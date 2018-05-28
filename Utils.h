#pragma once
#include "AnalyzeReplaceDell9010.h"

typedef ULONG (__stdcall *EFICOMPRESS)(PUCHAR pSrc,ULONG ulSrcSize,PUCHAR pDst,ULONG* ulDstSize);
typedef ULONG (__stdcall *EFIDECOMPRESS)(PUCHAR pSrc,ULONG ulSrcSize,PUCHAR pDst,ULONG ulDstSize,PCHAR pSrcAtch,ULONG ulSrcAtchSize);
typedef ULONG (__stdcall *TIANOCOMPRESS)(PUCHAR pSrc,ULONG ulSrcSize,PUCHAR pDst,ULONG* ulDstSize);
typedef ULONG (__stdcall *TIANODECOMPRESS)(PUCHAR pSrc,ULONG ulSrcSize,PUCHAR pDst,ULONG ulDstSize,PCHAR pSrcAtch,ULONG ulSrcAtchSize);
class CUtils
{
public:
	CUtils(void);
	~CUtils(void);
	ULONG Match(PCHAR pSrcDat, ULONG ulSrcSize, PCHAR pFindString, ULONG ulFindSize, ULONG ulOffset, ULONG ulBoundry);
	ULONG Find(PCHAR pDat, ULONG ulDatSize, PCHAR pFind, ULONG ulFindSize, ULONG ulOffset, ULONG ulBoundry);
	USHORT CheckSum16(PCHAR pDat, ULONG ulOffset, ULONG ulLength, BYTE bExtra);
	ULONG UnicodeToAnsi(PWCHAR pSrc,PCHAR pDst,ULONG ulSize);
	ULONG AnsiToUnicode(PCHAR pSrc,PWCHAR pDst,ULONG ulSize);
	PCHAR ConvertName(PCHAR pGuidDat);
	BYTE CheckSum8(PCHAR pDat, ULONG ulOffset, ULONG ulLength, BYTE bExtra);
	ULONG CheckSum32(PCHAR pDat, ULONG ulOffset, ULONG ulLength);
	ULONG DelFileForSize(PCHAR pDirectory,ULONG ulDelSize);
	ULONG CheckSignature(PCHAR pFileName, PCHAR pSignature, ULONG ulSize);
	EFICOMPRESS EfiCompress;
	EFIDECOMPRESS EfiDecompress;
	TIANOCOMPRESS TianoCompress;
	TIANODECOMPRESS TianoDecompress;
private:
	HMODULE hModuleEfiDc;
public:
	ULONG ULONG24ToULONG32(PCHAR pSize);
	PCHAR ULONG32ToULONG24(ULONG ulValue);
	BYTE XorCheckSum(PCHAR pDat, ULONG ulSize,BOOLEAN bFucked);
};

extern CUtils *g_pUtils;

