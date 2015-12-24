#include "pin.H"
#include "common.h"
#include "CachedDict.h"
class ShadowMemory: public CachedDict<ADDRINT, TAG_t>
{
private:
	PIN_MUTEX _mutex;
public:
	ShadowMemory();
	~ShadowMemory();
	void lock();
	void unlock();
};
