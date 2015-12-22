#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "pin.H"
#ifdef TARGET_MAC
#include <map>
#else
#include <unordered_map>
#endif

template <class TypeKey, class TypeValue>
class CachedDict
{
private:
	struct CacheItem
	{
		TypeValue * page;
		TypeKey pageIndex;
		bool valid;
	} typedef CacheItem;
public:
	CachedDict()
	{
		for (int i = 0; i < 4096; i++)
			cache[i].valid = false;
	}
	virtual TypeValue& operator [](TypeKey addr)
	{
		TypeKey pageIndex = (addr >> 12);
		if (cache[pageIndex&0xfff].valid && cache[pageIndex&0xfff].pageIndex == pageIndex)
		{
			TypeValue &retv = cache[pageIndex&0xfff].page[addr&0xfff];
			return retv;
		}	
		auto iter = pageTable.find(pageIndex);
		if (iter == pageTable.end())
		{
			TypeValue * newpage = new TypeValue[1<<12];
			if (!newpage)
				ERROR("CachedDic malloc failed");
			auto retv = pageTable.insert(std::pair<TypeKey, TypeValue*>(pageIndex, newpage));
			if (!retv.second)
			{
				iter = pageTable.find(pageIndex);
				if (iter == pageTable.end())
					ERROR("another thread insert to pageTable, but can't find in current thread?");
			}
			else
			{	
				iter = retv.first;
			}
		}
		cache[pageIndex&0xfff].page = iter->second;
		cache[pageIndex&0xfff].pageIndex = pageIndex;
		cache[pageIndex&0xfff].valid = true;
		return iter->second[addr&0xfff];
	}
	~CachedDict()
	{
		for (auto iter = pageTable.begin(); iter != pageTable.end(); iter++)
		{
			if (iter->second) delete[] iter->second;
		}
	}
private:
#ifdef TARGET_MAC
	std::map<TypeKey, TypeValue *> pageTable;
#else
	std::unordered_map<TypeKey, TypeValue *> pageTable;
#endif
	CacheItem cache[4096];
	CachedDict(CachedDict&);
};
