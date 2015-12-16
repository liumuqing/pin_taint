#include <iostream>
#include <fstream>
#ifndef TARGET_WINDOWS
#include <sys/syscall.h>
#endif
#include "pin.H"
#include "common.h"
#include "CachedDict.h"

CachedDict<ADDRINT, UINT8> shadow_taint_memory;
CONTEXT * global_contexts[1024];
int  global_icount = 0;
PIN_RWMUTEX mutex;
bool global_taint_enable;
struct InputSyscallRecord
{
	ADDRINT syscall_num;
	ADDRINT args[4];
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
	for (int i = 0; i != size; i++)
	{
		shadow_taint_memory[addr+i] |= tag;
	}
	MSG("[0x%llx:0x%llx] source tainted", addr, addr+size);
    global_taint_enable = true;
	PIN_RWMutexUnlock(&mutex);
}
VOID BeforeSyscall(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *)
{
	if (threadIndex >= sizeof(global_contexts) / sizeof(CONTEXT *))
		ERROR("thread_is %d is larger than size of global_contexts", threadIndex);	
	global_syscall_record[threadIndex].syscall_num = PIN_GetSyscallNumber(ctxt, std);
	for (int i = 0; i < 4; i ++)
	{
		global_syscall_record[threadIndex].args[i] = PIN_GetSyscallArgument(ctxt, std, i);
	}
}
VOID AfterSyscall(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *)
{
	if (threadIndex >= sizeof(global_contexts) / sizeof(CONTEXT *))
		ERROR("thread_is %d is larger than size of global_contexts", threadIndex);	
	const InputSyscallRecord &record = global_syscall_record[threadIndex];
	ADDRINT retv = PIN_GetSyscallReturn(ctxt, std);
#ifdef TARGET_MAC
	if ((record.syscall_num >> 24) != 0x2) return;//non unix syscall
	ADDRINT syscall_num = record.syscall_num & 0xffffff;
#else
	ADDRINT syscall_num = record.syscall_num;
#endif
#ifndef TARGET_WINDOWS
	if (retv == -1) return;
	if (syscall_num == SYS_recvfrom)
		doTaint(record.args[1], retv, 1);
#ifdef TARGET_LINUX
	else if (syscall_num == SYS_read)
#else 
	else if (syscall_num == SYS_read || syscall_num == SYS_read_nocancel)
#endif
		doTaint(record.args[1], retv, 1);
#endif
}
VOID BeforeEachTraserInstrucion(THREADID thread_id, ADDRINT inst_addr, PIN_MULTI_MEM_ACCESS_INFO* muliti_mem_access_info, const InstRegRecord * instRegRecord)
{
	global_icount += 1;
	//if ((global_icount &0xffff) == 0) MSG("%x", global_icount);
    //if (!global_taint_enable) return;
	if (thread_id >= sizeof(global_contexts) / sizeof(CONTEXT *))
		ERROR("thread_is %d is larger than size of global_contexts", thread_id);
	CONTEXT * context = global_contexts[thread_id];
	if (!context) context = new CONTEXT;
	if (!context) ERROR("malloc new context for thread %d fail", thread_id);

	global_contexts[thread_id] = context;
	PIN_REGISTER taint;
	memset(&taint, 0, sizeof(taint));
	REG reg;
	//auto instRegRecord = global_inst_reg_record[inst_addr];
	for (int i = 0; i != instRegRecord->numberOfReadRegs; i++)
	{
		reg = instRegRecord->readRegs[i];
		PIN_REGISTER readReg;
		//if (reg>=REG_MACHINE_LAST || reg == REG_X87) continue;
		//PIN_GetContextRegval(context, reg, (UINT8 *)&readReg);
		for (UINT32 j = 0; j < REG_Size(reg); j++)
		{
			taint.byte[j] |= readReg.byte[j];
		}
	}

	PIN_RWMutexWriteLock(&mutex);
	if (muliti_mem_access_info)
	{
		for (UINT32 i = 0; i != muliti_mem_access_info->numberOfMemops; i++)
		{
			const PIN_MEM_ACCESS_INFO &info = muliti_mem_access_info->memop[i];
			if (info.memopType == PIN_MEMOP_LOAD)
			{
				for (int index = 0; index != info.bytesAccessed; index++)
				{
					taint.byte[index] |= shadow_taint_memory[info.memoryAddress+index];
				}
			}
		}
	}
	bool tainted = false;
	for (int i = 0; i < MAX_QWORDS_PER_PIN_REG; i++)
	{
		if (taint.qword[i]) 
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
				for (int index=0; index != info.bytesAccessed; index++)
					shadow_taint_memory[info.memoryAddress+index] = taint.byte[index];
			}
		}
	}
	PIN_RWMutexUnlock(&mutex);

	//if (tainted && memSink) MSG("TAINTED mem at inst %016llx",inst_addr);
	//if (tainted && !memSink && instRegRecord->numberOfWriteRegs) MSG("TAINTED reg at inst %016llx",inst_addr);
	for (int i = 0; i != instRegRecord->numberOfWriteRegs; i++)
	{
		reg = instRegRecord->writeRegs[i];
		//if (reg>=REG_MACHINE_LAST || reg == REG_X87) continue;
		PIN_REGISTER writeReg;
		memset(&writeReg, 0, sizeof(writeReg));
		if (memSink) return;
			memcpy(&writeReg, &taint, REG_Size(reg));
		//PIN_SetContextRegval(context, reg, (UINT8 *)&writeReg);
	}
}
VOID InstrunctionInstrument(INS ins, VOID *)
{
	bool hasRead = (INS_RegR(ins, 0) != REG_INVALID_) || (INS_IsMemoryRead(ins));
	bool hasWrite = (INS_RegW(ins, 0) != REG_INVALID_) || (INS_IsMemoryWrite(ins));
	bool hasMem = (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)); 
	if (hasRead && hasWrite)
	{
		//MSG("%d %d", INS_RegR(ins, 0), REG_INVALID_);
		//MSG("Insert TrasferInstrucion Handle for %016llx:%x:%s", INS_Address(ins), ins.q(), INS_Disassemble(ins).c_str());
		if (!global_inst_reg_record[INS_Address(ins)])
			if (!(global_inst_reg_record[INS_Address(ins)] = new InstRegRecord)) ERROR("malloc new InstRegRecord failed");
		InstRegRecord * instRegRecord = global_inst_reg_record[INS_Address(ins)];
		instRegRecord->numberOfReadRegs = 0;
		instRegRecord->numberOfWriteRegs = 0;
		REG reg;
		for (int i = 0; (reg=INS_RegR(ins, i)) != REG_INVALID_; i++)
		{
			if (reg>=REG_MACHINE_LAST || reg == REG_X87 || reg == REG_EIP 
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
			if (reg>=REG_MACHINE_LAST || reg == REG_X87 
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
	PIN_RWMutexInit(&mutex);
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
