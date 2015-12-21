#ifndef TARGET_WINDOWS
#include <sys/syscall.h>
#endif
#include "pin.H"
#include "common.h"
#include "CachedDict.h"
#include "ShadowCpu.h"

#ifdef TARGET_WINDOWS
ADDRINT SYS_ReadFile;
#define SYSCALL_ARG_COUNT 8
#else
ADDRINT SYS_ReadFIle;
#endif

CachedDict<ADDRINT, UINT8> shadow_taint_memory;

ShadowCpu * global_contexts[1024];
int  global_icount = 0;
PIN_RWMUTEX mutex;
bool global_taint_enable;
struct InputSyscallRecord
{
	ADDRINT syscall_num;
	ADDRINT args[SYSCALL_ARG_COUNT];
};
struct InstRegRecord
{
	int numberOfReadRegs;
	int numberOfWriteRegs;
	REG readRegs[8];
	REG writeRegs[8];
};
InputSyscallRecord global_syscall_record[1024];

CachedDict<ADDRINT, InstRegRecord *> global_inst_reg_record;

VOID doTaint(ADDRINT addr, ADDRINT size, UINT8 tag)
{
	PIN_RWMutexWriteLock(&mutex);
	for (ADDRINT i = 0; i != size; i++)
	{
		shadow_taint_memory[addr+i] |= tag;
	}
	MSG("[0x%" FORMAT_ADDR_X ":0x%" FORMAT_ADDR_X "] source tainted", addr, addr+size);
	MSG("xx %04s", (char *)addr);
    global_taint_enable = true;
	PIN_RWMutexUnlock(&mutex);
}
VOID BeforeSyscall(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *)
{
	if (threadIndex >= sizeof(global_contexts) / sizeof(CONTEXT *))
		ERROR("thread_id %d is larger than size of global_contexts", threadIndex);	
	global_syscall_record[threadIndex].syscall_num = PIN_GetSyscallNumber(ctxt, std);
	for (int i = 0; i < SYSCALL_ARG_COUNT; i ++)
	{
		global_syscall_record[threadIndex].args[i] = PIN_GetSyscallArgument(ctxt, std, i);
	}
}
VOID AfterSyscall(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *)
{
	if (threadIndex >= sizeof(global_contexts) / sizeof(CONTEXT *))
		ERROR("thread_id %d is larger than size of global_contexts", threadIndex);	
	const InputSyscallRecord &record = global_syscall_record[threadIndex];
	ADDRINT retv = PIN_GetSyscallReturn(ctxt, std);
#ifdef TARGET_MAC
	if ((record.syscall_num >> 24) != 0x2) return;//non unix syscall
	ADDRINT syscall_num = record.syscall_num & 0xffffff;
#else
	ADDRINT syscall_num = record.syscall_num;
#endif
#ifndef TARGET_WINDOWS //Linux or Mac
	if (retv == (ADDRINT)-1) return;
	if (syscall_num == SYS_recvfrom)
		doTaint(record.args[1], retv, 1);
#ifdef TARGET_LINUX
	else if (syscall_num == SYS_read)
#else 
	else if (syscall_num == SYS_read || syscall_num == SYS_read_nocancel)
#endif
		doTaint(record.args[1], retv, 1);
#else    //Windows
	if (retv < 0) return;
	MSG("%x is called bak", syscall_num);
	if (syscall_num == SYS_ReadFile)
	{
		doTaint(record.args[5], record.args[6], 1);
	}
#endif
}
VOID BeforeEachTraserInstrucion(THREADID thread_id, ADDRINT inst_addr, PIN_MULTI_MEM_ACCESS_INFO* muliti_mem_access_info, const InstRegRecord * instRegRecord)
{
	global_icount += 1;
	if (!global_taint_enable) return;
	if (thread_id >= sizeof(global_contexts) / sizeof(CONTEXT *))
		ERROR("thread_id %d is larger than size of global_contexts", thread_id);
	ShadowCpu * context = global_contexts[thread_id];
	if (!context) context = new ShadowCpu;
	if (!context) ERROR("malloc new context for thread %d fail", thread_id);

	global_contexts[thread_id] = context;
	TAG_t taint[16];
	memset(&taint, 0, sizeof(taint));
	REG reg;
	for (int i = 0; i != instRegRecord->numberOfReadRegs; i++)
	{
		reg = instRegRecord->readRegs[i];
		TAG_t * readTag = context->getTagPointerOfReg(reg);
		for (UINT32 j = 0; j < REG_Size(reg); j++)
		{
			//MSG("[%" FORMAT_ADDR_X "]" "read %s", inst_addr, REG_StringShort(reg).c_str());
			taint[j] |= readTag[j];
		}
	}
	bool tainted = false;
	for (ADDRINT i = 0; i < 16; i++)
	{
		if (taint[i]) 
		{
			tainted = true;
			break;
		}
	}
	//if (tainted) MSG("Source reg tainted at inst 0x%" FORMAT_ADDR_X,inst_addr);
	PIN_RWMutexWriteLock(&mutex);
	if (muliti_mem_access_info)
	{
		for (UINT32 i = 0; i != muliti_mem_access_info->numberOfMemops; i++)
		{
			const PIN_MEM_ACCESS_INFO &info = muliti_mem_access_info->memop[i];
			if (info.memopType == PIN_MEMOP_LOAD)
			{
				for (ADDRINT index = 0; index != info.bytesAccessed; index++)
				{
					taint[index] |= shadow_taint_memory[info.memoryAddress+index];
				}
			}
		}
	}
	//bool tainted = false;
	for (ADDRINT i = 0; i < 16; i++)
	{
		if (taint[i]) 
		{
			tainted = true;
			break;
		}
	}
	bool memSink = false;
	if (muliti_mem_access_info)
	{
		for (UINT32 i = 0; i != muliti_mem_access_info->numberOfMemops; i++)
		{
			const PIN_MEM_ACCESS_INFO &info = muliti_mem_access_info->memop[i];
			if (info.memopType == PIN_MEMOP_STORE)
			{
				memSink = true;
				if (tainted && memSink)
				{
					MSG("TAINTED mem[0x%" FORMAT_ADDR_X ":0x%" FORMAT_ADDR_X "] at inst 0x%" FORMAT_ADDR_X,
						info.memoryAddress,
						info.memoryAddress + info.bytesAccessed,
						inst_addr);
					
				}
				for (ADDRINT index=0; index != info.bytesAccessed; index++)
					shadow_taint_memory[info.memoryAddress+index] = taint[index];
			}
		}
	}
	//if (tainted) MSG("Source reg tainted at inst 0x%" FORMAT_ADDR_X,inst_addr);
	PIN_RWMutexUnlock(&mutex);

	for (int i = 0; i != instRegRecord->numberOfWriteRegs; i++)
	{
		reg = instRegRecord->writeRegs[i];
		//if (reg>=REG_MACHINE_LAST || reg == REG_X87) continue;
		TAG_t * writeTag = context->getTagPointerOfReg(reg);
		memset(writeTag, 0, REG_Size(reg) * sizeof(TAG_t));
		if ((!tainted) || memSink || (instRegRecord->numberOfWriteRegs > 1 && reg == REG_STACK_PTR))
		{
			continue;
		}
		MSG("TAINTED %s at inst 0x%" FORMAT_ADDR_X,REG_StringShort(reg).c_str(), inst_addr);
		memcpy(writeTag, &taint[0], REG_Size(reg) * sizeof(TAG_t));
		
	}
}
VOID InstrunctionInstrument(INS ins, VOID *)
{
	bool hasRead = (INS_RegR(ins, 0) != REG_INVALID_) || (INS_IsMemoryRead(ins));
	bool hasWrite = (INS_RegW(ins, 0) != REG_INVALID_) || (INS_IsMemoryWrite(ins));
	bool hasMem = (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)); 
	//if ((INS_Address(ins)&0xffffffff) != INS_Address(ins)) return;
	if (hasRead && hasWrite)
	{
		//MSG("%d %d", INS_RegR(ins, 0), REG_INVALID_);
		//MSG("Insert TrasferInstrucion Handle for %016" FORMAT_ADDR_X ":%x:%s", INS_Address(ins), ins.q(), INS_Disassemble(ins).c_str());
		if (!global_inst_reg_record[INS_Address(ins)])
			if (!(global_inst_reg_record[INS_Address(ins)] = new InstRegRecord)) ERROR("malloc new InstRegRecord failed");
		InstRegRecord * instRegRecord = global_inst_reg_record[INS_Address(ins)];
		instRegRecord->numberOfReadRegs = 0;
		instRegRecord->numberOfWriteRegs = 0;
		REG reg;
		for (int i = 0; (reg=INS_RegR(ins, i)) != REG_INVALID_; i++)
		{
			if (reg>REG_MACHINE_LAST || reg == REG_X87 || reg == REG_EIP 
#if BITS == 32
				|| reg == REG_EIP
#elif BITS == 64
				|| reg == REG_RIP
#else
#error("macro BITS undefined!")
#endif
					|| REG_is_flags_any_size_type(reg) 
					|| REG_is_status_flags_type(reg)
					|| REG_is_df_flag_type(reg)) 
				continue;
			instRegRecord->readRegs[(instRegRecord->numberOfReadRegs)++] = reg;
		}
		for (int i = 0; (reg=INS_RegW(ins, i)) != REG_INVALID_; i++)
		{
			if (reg>REG_MACHINE_LAST || reg == REG_X87 
#if BITS == 32
				|| reg == REG_EIP 
#elif BITS == 64
				|| reg == REG_RIP
#else
#error("macro BITS undefined!")
#endif
				) continue;
			//MSG("%s", REG_StringShort(reg).c_str());
			instRegRecord->writeRegs[(instRegRecord->numberOfWriteRegs)++] = reg;
		}

		if (hasMem)
			INS_InsertPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR) BeforeEachTraserInstrucion,
					IARG_THREAD_ID ,
					IARG_INST_PTR ,
					IARG_MULTI_MEMORYACCESS_EA, 
					IARG_PTR, instRegRecord,
					IARG_END);
		else
			INS_InsertPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR) BeforeEachTraserInstrucion,
					IARG_THREAD_ID ,
					IARG_INST_PTR ,
					IARG_PTR, NULL,
					IARG_PTR, instRegRecord,
					IARG_END);

	}
	return;
}
int Usage()
{
	MSG("Usage");
	return -1;
}
int main(int argc, char *argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	//PIN_RWMutexInit(&mutex);
#ifdef TARGET_WINDOWS 
#if BITS==32
	if (1 == 2);
	//else if (IsWindows10OrGreater()) {SYS_ReadFIle = 0x10000000;}
	//else if  (IsWindows8Point1OrGreater()) {SYS_ReadFile = 0x008a;}
	//else if  (IsWindows8OrGreater()) {SYS_ReadFile = 0x0087;}
	//else if  (IsWindows7OrGreater()) {SYS_ReadFile = 0x0111;}
	//else if  (IsWindowsVistaOrGreater()) {SYS_ReadFile = 0x0102;}
	//else if  (IsWindowsXPOrGreater()) {SYS_ReadFile = 0x00adb7;}
	SYS_ReadFile = 0xffff;
#endif
#if BITS==64
	if (1 == 2);
	//else if (IsWindows10OrGreater()) {SYS_ReadFIle = 0x10000000;}
	//else if  (IsWindows8Point1OrGreater()) {SYS_ReadFile = 0x008a;}
	//else if  (IsWindows8OrGreater()) {SYS_ReadFile = 0x0087;}
	//else if  (IsWindows7OrGreater()) {SYS_ReadFile = 0x0111;}
	//else if  (IsWindowsVistaOrGreater()) {SYS_ReadFile = 0x0102;}
	//else if  (IsWindowsXPOrGreater()) {SYS_ReadFile = 0x00adb7;}
	SYS_ReadFile = 0x0003;
#endif
#endif
	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}
	//LEVEL_PINCLIENT::
	INS_AddInstrumentFunction ((INS_INSTRUMENT_CALLBACK) InstrunctionInstrument, NULL);
	PIN_AddSyscallEntryFunction((SYSCALL_ENTRY_CALLBACK) BeforeSyscall, NULL);
	PIN_AddSyscallExitFunction((SYSCALL_ENTRY_CALLBACK) AfterSyscall, NULL);
	PIN_StartProgram();

	return 0;
}
