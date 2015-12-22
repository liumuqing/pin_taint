#ifndef TARGET_WINDOWS
#include <sys/syscall.h>
#endif
#include "pin.H"
#include "common.h"
#include "CachedDict.h"
#include "ShadowCpu.h"
#include "ShadowMemory.h"
#include "utils.h"
#ifdef TARGET_WINDOWS
ADDRINT SYS_ReadFile;
#define SYSCALL_ARG_COUNT 12
#else
#define SYSCALL_ARG_COUNT 6
#endif

KNOB<string> KnobOutputFilePath(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for pin_taint output (default empty, stdout)");
KNOB<string> KnobTaintSourceSuffix(KNOB_MODE_WRITEONCE,  "pintool",
    "s", "", "specify a suffix of the taint souce's fullpath");
char taintSourceSuffix[2048];

TAG_t global_total_taint = 0;


ShadowMemory shadowMemory;
ShadowCpu * global_contexts[1024];
int  global_icount = 0;
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

bool check_fd_handle(ADDRINT fd)
{
	char path[0x10000];
#ifdef TARGET_WINDOWS
	get_fullpath_from_fd_handle((void*)fd, path);
#else
	get_fullpath_from_fd_handle((int)fd, path);
#endif
	MSG("from file:%s", path);
	return isStrEndWith(path, taintSourceSuffix);
}
VOID doTaint(ADDRINT addr, ADDRINT size, TAG_t tag)
{
	shadowMemory.lock();
	MSG("taged as 0x%" FORMAT_TAG_X ":0x%" FORMAT_TAG_X, global_total_taint+1, (TAG_t)(global_total_taint+size+1));
	for (ADDRINT i = 0; i != size; i++)
	{
		//shadowMemory[addr+i] |= tag;
		shadowMemory[addr+i] = (++global_total_taint);
	}
	MSG("[0x%" FORMAT_ADDR_X ":0x%" FORMAT_ADDR_X "] source tainted", addr, addr+size);
    global_taint_enable = true;
	shadowMemory.unlock();
}

VOID BeforeSyscall(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *)
{
	if (threadIndex >= sizeof(global_contexts) / sizeof(CONTEXT *))
		ERROR("thread_id %d is larger than size of global_contexts", threadIndex);	
	global_syscall_record[threadIndex].syscall_num = PIN_GetSyscallNumber(ctxt, std);
	//MSG("SYSCALL 0x%" FORMAT_ADDR_X " BeforeSyscall", global_syscall_record[threadIndex].syscall_num);
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
	//if (syscall_num == SYS_recvfrom)
	//	doTaint(record.args[1], retv, 1);
	#ifdef TARGET_LINUX
	else if (syscall_num == SYS_read)
	#else 
	else if (syscall_num == SYS_read || syscall_num == SYS_read_nocancel)
	#endif
	{
		if (check_fd_handle(record.args[0]))
		{
			doTaint(record.args[1], retv, 1);
		}
	}
	else if (syscall_num == SYS_mmap)
	{
		if (check_fd_handle(record.args[4]))
		{
			doTaint(retv, record.args[1], 1);
		}
	}
#else    //Windows
	if (retv < 0) return;
	/*
		NTSTATUS ZwReadFile(
		_In_     HANDLE           FileHandle,
		_In_opt_ HANDLE           Event,
		_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
		_In_opt_ PVOID            ApcContext,
		_Out_    PIO_STATUS_BLOCK IoStatusBlock,
		_Out_    PVOID            Buffer,
		_In_     ULONG            Length,
		_In_opt_ PLARGE_INTEGER   ByteOffset,
		_In_opt_ PULONG           Key
		);

		typedef struct _IO_STATUS_BLOCK {
			union {
				NTSTATUS Status;
				PVOID    Pointer;
			};
			ULONG_PTR Information;
		} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
	
		**Information**
			This is set to a request-dependent value. For example, on successful completion of a transfer request, 
			this is set to the number of bytes transferred. If a transfer request is completed with another 
			STATUS_XXX, this member is set to zero.
	*/
	if (syscall_num == SYS_ReadFile)
	{
		if (check_fd_handle(record.args[0]))
		{
			doTaint(record.args[5], ((ADDRINT *) record.args[4])[1], 1);
		}
	}
#endif
}
VOID BeforeEachTraserInstrucion(THREADID thread_id, ADDRINT inst_addr, PIN_MULTI_MEM_ACCESS_INFO* muliti_mem_access_info, const InstRegRecord * instRegRecord, ADDRINT gsp)
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
	bool mixed = false;
	for (int i = 0; i != instRegRecord->numberOfReadRegs; i++)
	{
		reg = instRegRecord->readRegs[i];
		TAG_t * readTag = context->getTagPointerOfReg(reg);
		for (UINT32 j = 0; j < REG_Size(reg); j++)
		{
			//MSG("[%" FORMAT_ADDR_X "]" "read %s", inst_addr, REG_StringShort(reg).c_str());
			if (taint[j] && readTag[j] && taint[j] != readTag[j]) mixed = true;
			if (readTag[j] == 0xffffffff) mixed = true;
			if (readTag[j] &&  readTag[j] != 0xffffffff) MSG("tag-reg-0x%" FORMAT_TAG_X " at inst 0x%" FORMAT_ADDR_X " and sp:0x%" FORMAT_ADDR_X " regname:%s", readTag[j], inst_addr, gsp, REG_StringShort(reg).c_str());
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
	shadowMemory.lock();
	if (muliti_mem_access_info)
	{
		for (UINT32 i = 0; i != muliti_mem_access_info->numberOfMemops; i++)
		{
			const PIN_MEM_ACCESS_INFO &info = muliti_mem_access_info->memop[i];
			if (info.memopType == PIN_MEMOP_LOAD)
			{
				for (ADDRINT index = 0; index != info.bytesAccessed; index++)
				{
					TAG_t t = shadowMemory[info.memoryAddress + index];
					if (t) MSG("SOURCE MEM taint %" FORMAT_ADDR_X, info.memoryAddress+index);
					if (t && t != 0xffffffff) MSG("tag-mem-0x%" FORMAT_TAG_X " at inst 0x%" FORMAT_ADDR_X " and sp:0x%" FORMAT_ADDR_X, t, inst_addr, gsp);
					if (taint[index] && t && taint[index] != t) mixed = true;
					if (t == 0xffffffff) mixed = true;
					taint[index] |= t;
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
	if (tainted && mixed) MSG("although tainted, but tag mixed, so fully tag it at 0x%" FORMAT_ADDR_X, inst_addr);
	if (muliti_mem_access_info)
	{
		for (UINT32 i = 0; i != muliti_mem_access_info->numberOfMemops; i++)
		{
			const PIN_MEM_ACCESS_INFO &info = muliti_mem_access_info->memop[i];
			if (info.memopType == PIN_MEMOP_STORE)
			{
				memSink = true;
				if (tainted && memSink && !mixed)
				{
					MSG("TAINTED mem[0x%" FORMAT_ADDR_X ":0x%" FORMAT_ADDR_X "] at inst 0x%" FORMAT_ADDR_X,
						info.memoryAddress,
						info.memoryAddress + info.bytesAccessed,
						inst_addr);

					for (ADDRINT index = 0; index != info.bytesAccessed; index++)
						shadowMemory[info.memoryAddress + index] = taint[index];
				}
				else if (tainted && memSink && mixed)
					for (ADDRINT index = 0; index != info.bytesAccessed; index++)
						shadowMemory[info.memoryAddress + index] = 0xffffffff;
				else
					for (ADDRINT index = 0; index != info.bytesAccessed; index++)
						shadowMemory[info.memoryAddress + index] = 0x0;
			}
		}
	}
	//if (tainted) MSG("Source reg tainted at inst 0x%" FORMAT_ADDR_X,inst_addr);
	shadowMemory.unlock();

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
		if (mixed)
			memset(writeTag, 0xff, REG_Size(reg) * sizeof(TAG_t));
		MSG("TAINTED %s at inst 0x%" FORMAT_ADDR_X,REG_StringShort(reg).c_str(), inst_addr);
		memcpy(writeTag, &taint[0], REG_Size(reg) * sizeof(TAG_t));
		
	}
}
VOID InstrunctionInstrument(INS ins, VOID *)
{
	bool hasRead = (INS_RegR(ins, 0) != REG_INVALID_) || (INS_IsMemoryRead(ins));
	bool hasWrite = (INS_RegW(ins, 0) != REG_INVALID_) || (INS_IsMemoryWrite(ins));
	bool hasMem = (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins) || INS_HasMemoryRead2(ins)); 
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
					IARG_REG_VALUE, REG_STACK_PTR,
					IARG_END);
		else
			INS_InsertPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR) BeforeEachTraserInstrucion,
					IARG_THREAD_ID ,
					IARG_INST_PTR ,
					IARG_PTR, NULL,
					IARG_PTR, instRegRecord,
					IARG_REG_VALUE, REG_STACK_PTR,
					IARG_END);

	}
	return;
}
int Usage()
{
	printf("Usage:\n");
    printf("%s\n", KNOB_BASE::StringKnobSummary().c_str());
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
	SYS_ReadFile = 0x0003;
#endif
#if BITS==64
	if (1 == 2);
	SYS_ReadFile = 0x0003;
#endif
#endif
	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}
	if (KnobOutputFilePath.Value() != "")
	{
		KnobOutputFile = fopen(KnobOutputFilePath.Value().c_str(), "w+");
		if (!KnobOutputFile) {printf("Open Log File %s fails!..", KnobOutputFilePath.Value().c_str()); fflush(stdout); exit(1);}
	}
	strcpy(taintSourceSuffix, KnobTaintSourceSuffix.Value().c_str());

	INS_AddInstrumentFunction ((INS_INSTRUMENT_CALLBACK) InstrunctionInstrument, NULL);
	PIN_AddSyscallEntryFunction((SYSCALL_ENTRY_CALLBACK) BeforeSyscall, NULL);
	PIN_AddSyscallExitFunction((SYSCALL_ENTRY_CALLBACK) AfterSyscall, NULL);
	PIN_StartProgram();

	return 0;
}
