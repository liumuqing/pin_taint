#pragma once 
#include <string.h>
#include "pin.H"
#include "common.h"

class ShadowCpu
{
public:
	ShadowCpu();
private:
	static uint32_t _RegOffsetList[REG_MACHINE_LAST];
	static bool _isStaticInited;
	static void staticInit();
	TAG_t _tags[REG_MACHINE_LAST*16+16];
public:
	TAG_t * getTagPointerOfReg(REG reg);
};
