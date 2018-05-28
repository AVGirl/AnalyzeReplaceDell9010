#pragma once
#include "AnalyzeReplaceDell9010.h"
class CDELLAnalyze
{
public:
	CDELLAnalyze(void);
	~CDELLAnalyze(void);
	BOOLEAN GetZlibHeader(PCHAR pDat, ULONG ulDatSize);
private:
	ULONG ulZlibSize;
	PCHAR pZlibDat;
	PCHAR pUnCompressZlibDat;
	ULONG ulUnCompressSize;
	CHAR HdrPath[MAX_PATH];
	BOOLEAN WriteModule(PCHAR pFileName, PCHAR pWriteDat, ULONG ulWriteSize);
public:
	BOOLEAN WriteHdr(void);
	PCHAR GetHdrDat(void);
	ULONG GetHdrLength(void);
	BOOLEAN GetHdrHeader(PVOID pHdrDat, ULONG ulOffset, PCHAR pOutHdrHeader, ULONG ulHdrHeaderSize);
	ULONG MyFindNextVolume(PCHAR pBIOSDat, ULONG ulSize, ULONG ulOffset);
	ULONG GetBIOSBlock(PCHAR pBIOSDat, ULONG ulBIOSSize, PDELL_BIOS_OPTX_9010 pDellBIOSInfo);
	BOOLEAN AnalyzeBIOS(PCHAR pBIOSDat, ULONG ulBIOSSize, PREPLACE_UEFI_SECTION pUefiSection);
private:
	ULONG ulIndex;
public:
	void SetIndex(void);
	ULONG GetIndex(void);
	ULONG ulOldHdrOffset;
};

extern CDELLAnalyze *g_pDellAnalyze;

