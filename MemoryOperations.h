#ifndef __MEMORY_OPERATIONS_H__
#define __MEMORY_OPERATIONS_H__

extern LIST_ENTRY g_MemoryUsed;
extern BOOLEAN g_bInitializeMemoryUsed;

typedef struct _PROCESS_MEMORY_USED
{
	LIST_ENTRY NextBlock;
	ULONG ulAddress;
	ULONG ulUsedSize;
	ULONG ulProtect;
}PROCESS_MEMORY_USED,*PPROCESS_MEMORY_USED;

PVOID AllocateMemory(ULONG ulSize,ULONG ulProtect);
BOOLEAN FreeMemory(PVOID pFreeMemory,ULONG ulSize);

#endif