#include "ShadowMemory.h"
ShadowMemory::ShadowMemory()
{
	PIN_MutexInit(&_mutex);
}
ShadowMemory::~ShadowMemory()
{
	PIN_MutexFini(&_mutex);
}
void ShadowMemory::lock()
{
	PIN_MutexLock(&_mutex);
}
void ShadowMemory::unlock()
{
	PIN_MutexUnlock(&_mutex);
}
