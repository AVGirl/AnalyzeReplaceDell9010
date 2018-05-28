#include "AnalyzeReplaceDell9010.h"
#include "ListEntryOperations.h"
#include "MemoryOperations.h"

LIST_ENTRY g_MemoryUsed;
BOOLEAN g_bInitializeMemoryUsed = FALSE;

PVOID AllocateMemory(ULONG ulSize,ULONG ulProtect)
{
	PVOID pAllocateAddress;
	PPROCESS_MEMORY_USED pMemoryUsed;

	if (!ulSize)
	{
		return NULL;
	}
	pMemoryUsed = NULL;
	pAllocateAddress = NULL;
	if (g_bInitializeMemoryUsed == FALSE)
	{
		InitializeListHead(&g_MemoryUsed);
	}
	pAllocateAddress = VirtualAlloc(NULL, \
		ulSize, \
		MEM_COMMIT | MEM_RESERVE, \
		ulProtect);
	if (NULL == pAllocateAddress)
	{
		return NULL;
	}
	pMemoryUsed = (PPROCESS_MEMORY_USED)VirtualAlloc(NULL, \
		sizeof(PROCESS_MEMORY_USED), \
		MEM_COMMIT | MEM_RESERVE, \
		PAGE_READWRITE);
	if (NULL == pMemoryUsed)
	{
		return pAllocateAddress;
	}
	pMemoryUsed->ulAddress = (ULONG_PTR)pAllocateAddress;
	pMemoryUsed->ulUsedSize = ulSize;
	pMemoryUsed->ulProtect = ulProtect;
	InitializeListHead(&pMemoryUsed->NextBlock);
	InsertTailList(&g_MemoryUsed,&pMemoryUsed->NextBlock);
	return pAllocateAddress;
}
BOOLEAN FreeMemory(PVOID pFreeMemory,ULONG ulSize)
{
	return VirtualFree(pFreeMemory,ulSize,MEM_COMMIT | MEM_RESERVE);
}