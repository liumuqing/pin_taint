#pragma once 
#include <string.h>
#include "pin.H"
#include "common.h"

class ShadowCpu
{
public:
	ShadowCpu();
private:
	static uint32_t _RegOffsetList[REG_APPLICATION_LAST+1];
	static bool _isStaticInited;
	static void staticInit();
	TAG_t _tags[REG_APPLICATION_LAST*64];
public:
	TAG_t * getTagPointerOfReg(REG reg);
};
