* 污点传播逻
	* 用pin自带的API检测每条指令读取了那些寄存器以及哪些内存，ESP/RSP/EIP/RIP相关污点不传播
	* 似乎还算正常，注意如果一条指令会写内存，那么就不要传播污点到这条指令所写的寄存器上，这通常是EBP, ECX, 之类。。
		* 目前这种情况会直接清除写寄存器上的tag。。可能不太对。。
* syscall：
	* Win下抓NtReadFile，Linux/OSX抓read，recv
	* 目前有get_full_name_of_fd_handle(fd, path)用来获取一个handle或者fd对应的路径。。。待用。。
* pin_taint.cpp代码混乱。。。需要稍微拆一拆。。把功能拆分开。。。
* 是否加一个针对单线程程序的编译开关/pintool参数，在分析单线程时可以避免每条语句都取线程的shadow_cpu状态，而且这样也不需要对shadowMemory加锁。	
* <del>讲道理现在的污点传播还是传统的逻辑。。需要改成两个不同tag污点混合就不再传播的那种样子。。。</del>
* 不同tag混合的话，会混成和0xffffffff，然后这个污点的被引用不会输出到日志中，恩。。


