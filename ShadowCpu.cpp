#include "ShadowCpu.h"
bool ShadowCpu::_isStaticInited = false;
uint32_t ShadowCpu::_RegOffsetList[REG_MACHINE_LAST];
ShadowCpu::ShadowCpu()
{
	if (!_isStaticInited) staticInit();
	memset(_tags, 0, sizeof(_tags));
}
void ShadowCpu::staticInit()
{
	//memset(_RegOffsetList, 0, sizeof(_RegOffsetList));
	_RegOffsetList[REG_RAX] = 8;
	_RegOffsetList[REG_EAX] = 8;
	_RegOffsetList[REG_AX] = 8;
	_RegOffsetList[REG_AL] = 8;
	_RegOffsetList[REG_AH] = 8;

	_RegOffsetList[REG_RBX] = 16;
	_RegOffsetList[REG_EBX] = 16;
	_RegOffsetList[REG_BX] = 16;
	_RegOffsetList[REG_BL] = 16;
	_RegOffsetList[REG_BH] = 17;

	_RegOffsetList[REG_RCX] = 24;
	_RegOffsetList[REG_ECX] = 24;
	_RegOffsetList[REG_CX] = 24;
	_RegOffsetList[REG_CL] = 24;
	_RegOffsetList[REG_CH] = 25;

	_RegOffsetList[REG_RDX] = 32;
	_RegOffsetList[REG_EDX] = 32;
	_RegOffsetList[REG_DX] = 32;
	_RegOffsetList[REG_DL] = 32;
	_RegOffsetList[REG_DH] = 33;

	_RegOffsetList[REG_RDI] = 40;
	_RegOffsetList[REG_EDI] = 40;
	_RegOffsetList[REG_DI] = 40;
	_RegOffsetList[REG_DIL] = 40;

	_RegOffsetList[REG_RSI] = 48;
	_RegOffsetList[REG_ESI] = 48;
	_RegOffsetList[REG_SI] = 48;
	_RegOffsetList[REG_SIL] = 48;

	_RegOffsetList[REG_RSP] = 56;
	_RegOffsetList[REG_ESP] = 56;
	_RegOffsetList[REG_SPL] = 56;
	//_RegOffsetList[REG_SPH] = 57;

	_RegOffsetList[REG_RBP] = 64;
	_RegOffsetList[REG_EBP] = 64;
	_RegOffsetList[REG_BPL] = 64;
	//_RegOffsetList[REG_BPH] = 65;

	_RegOffsetList[REG_RIP] = 72;
	_RegOffsetList[REG_EIP] = 72;

	_RegOffsetList[REG_RFLAGS] = 80;
	_RegOffsetList[REG_EFLAGS] = 80;

	_RegOffsetList[REG_R8] = 0x58;
	_RegOffsetList[REG_R8D] = 0x58;
	_RegOffsetList[REG_R8W] = 0x58;
	_RegOffsetList[REG_R8B] = 0x58;
	_RegOffsetList[REG_R9] = 0x60;
	_RegOffsetList[REG_R9D] = 0x60;
	_RegOffsetList[REG_R9W] = 0x60;
	_RegOffsetList[REG_R9B] = 0x60;
	_RegOffsetList[REG_R10] = 0x68;
	_RegOffsetList[REG_R10D] = 0x68;
	_RegOffsetList[REG_R10W] = 0x68;
	_RegOffsetList[REG_R10B] = 0x68;
	_RegOffsetList[REG_R11] = 0x70;
	_RegOffsetList[REG_R11D] = 0x70;
	_RegOffsetList[REG_R11W] = 0x70;
	_RegOffsetList[REG_R11B] = 0x70;
	_RegOffsetList[REG_R12] = 0x78;
	_RegOffsetList[REG_R12D] = 0x78;
	_RegOffsetList[REG_R12W] = 0x78;
	_RegOffsetList[REG_R12B] = 0x78;
	_RegOffsetList[REG_R13] = 0x80;
	_RegOffsetList[REG_R13D] = 0x80;
	_RegOffsetList[REG_R13W] = 0x80;
	_RegOffsetList[REG_R13B] = 0x80;
	_RegOffsetList[REG_R14] = 0x88;
	_RegOffsetList[REG_R14D] = 0x88;
	_RegOffsetList[REG_R14W] = 0x88;
	_RegOffsetList[REG_R14B] = 0x88;
	_RegOffsetList[REG_R15] = 0x90;
	_RegOffsetList[REG_R15D] = 0x90;
	_RegOffsetList[REG_R15W] = 0x90;
	_RegOffsetList[REG_R15B] = 0x90;

	_RegOffsetList[REG_XMM0] = 0xa0;
	_RegOffsetList[REG_XMM1] = 0xb0;
	_RegOffsetList[REG_XMM2] = 0xc0;
	_RegOffsetList[REG_XMM3] = 0xd0;
	_RegOffsetList[REG_XMM4] = 0xe0;
	_RegOffsetList[REG_XMM5] = 0xf0;
	_RegOffsetList[REG_XMM6] = 0x100;
	_RegOffsetList[REG_XMM7] = 0x110;
	_RegOffsetList[REG_XMM8] = 0x120;
	_RegOffsetList[REG_XMM9] = 0x130;
	_RegOffsetList[REG_XMM10] = 0x140;
	_RegOffsetList[REG_XMM11] = 0x150;
	_RegOffsetList[REG_XMM12] = 0x160;
	_RegOffsetList[REG_XMM13] = 0x170;
	_RegOffsetList[REG_XMM14] = 0x180;
	_RegOffsetList[REG_XMM15] = 0x190;

	_RegOffsetList[REG_YMM0] = 0x1a0;
	_RegOffsetList[REG_YMM1] = 0x1b0;
	_RegOffsetList[REG_YMM2] = 0x1c0;
	_RegOffsetList[REG_YMM3] = 0x1d0;
	_RegOffsetList[REG_YMM4] = 0x1e0;
	_RegOffsetList[REG_YMM5] = 0x1f0;
	_RegOffsetList[REG_YMM6] = 0x200;
	_RegOffsetList[REG_YMM7] = 0x210;
	_RegOffsetList[REG_YMM8] = 0x220;
	_RegOffsetList[REG_YMM9] = 0x230;
	_RegOffsetList[REG_YMM10] = 0x240;
	_RegOffsetList[REG_YMM11] = 0x250;
	_RegOffsetList[REG_YMM12] = 0x260;
	_RegOffsetList[REG_YMM13] = 0x270;
	_RegOffsetList[REG_YMM14] = 0x280;
	_RegOffsetList[REG_YMM15] = 0x290;

	_RegOffsetList[REG_SEG_CS] = 0x298;
	_RegOffsetList[REG_SEG_SS] = 0x2a0;
	_RegOffsetList[REG_SEG_DS] = 0x2a8;
	_RegOffsetList[REG_SEG_ES] = 0x2b0;
	_RegOffsetList[REG_SEG_FS] = 0x2b8;
	_RegOffsetList[REG_SEG_GS] = 0x2c0;

	_isStaticInited = true;
}
TAG_t * ShadowCpu::getTagPointerOfReg(REG reg)
{
	if (_RegOffsetList[reg] != 0)
		return &_tags[_RegOffsetList[reg]];
	ERROR("RegOffsetList[%s] 0x%x not initialized!", REG_StringShort(reg).c_str(), reg);
}
