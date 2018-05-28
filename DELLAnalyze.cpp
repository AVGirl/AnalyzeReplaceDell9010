#include "zlib/zlib.h"
#include "Utils.h"
#include "EFIBIOSANALYZE.h"
#include "DELLAnalyze.h"

CDELLAnalyze *g_pDellAnalyze = NULL;
CDELLAnalyze::CDELLAnalyze(void)
	: ulZlibSize(0)
	, ulUnCompressSize(0)
	, ulIndex(0)
	, ulOldHdrOffset(0)
{
	RtlZeroMemory(HdrPath,sizeof(CHAR) * MAX_PATH);
	GetCurrentDirectory(MAX_PATH,HdrPath);
	StringCchCat(HdrPath,MAX_PATH,"\\Dell9010.Hdr");
	pZlibDat = NULL;
	pUnCompressZlibDat = NULL;
}


CDELLAnalyze::~CDELLAnalyze(void)
{
	if (pUnCompressZlibDat)
	{
		VirtualFree(pUnCompressZlibDat,ulZlibSize * 3,MEM_COMMIT | MEM_RESERVE);
		pUnCompressZlibDat = NULL;
	}
	if (pZlibDat)
	{
		VirtualFree(pZlibDat,ulZlibSize,MEM_COMMIT | MEM_RESERVE);
		pZlibDat = NULL;
	}
}


BOOLEAN CDELLAnalyze::GetZlibHeader(PCHAR pDat, ULONG ulDatSize)
{
	ULONG ulRet;
	int nRet;

	CHAR pFindString[] = {0x65,0xAA,0x65,0xEE, \
		0x65,0xAA,0x65,0x76, \
		0x65,0x1B,0x65,0xEC, \
		0x65,0xBB,0x65,0x20, \
		0x65,0xF1,0x65,0xE6, \
		0x65,0x51,0x78,0x78, \
		0x65,0x78,0x65,0x9C};
	ulRet = g_pUtils->Match(pDat,ulDatSize,pFindString,sizeof(pFindString),0,1);
	if (0 == ulRet)
	{
		return FALSE;
	}
	ulOldHdrOffset = ulRet - 0x04;
	ulZlibSize = *(ULONG*)((ULONG)pDat + (ulRet - 0x04));
	if (ulZlibSize)
	{
		do 
		{
			pZlibDat = (PCHAR)VirtualAlloc(NULL,ulZlibSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
		} while (NULL == pZlibDat);
		RtlZeroMemory(pZlibDat,ulZlibSize);
		RtlCopyMemory(pZlibDat,(PCHAR)((ULONG)pDat + ulRet + 12),ulZlibSize);
		
		ulUnCompressSize = ulZlibSize * 3;
		do 
		{
			pUnCompressZlibDat = (PCHAR)VirtualAlloc(NULL,ulUnCompressSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
		} while (NULL == pUnCompressZlibDat);
		RtlZeroMemory(pUnCompressZlibDat,ulUnCompressSize);
		nRet = uncompress((Bytef*)pUnCompressZlibDat,&ulUnCompressSize,(Bytef*)pZlibDat,ulZlibSize);
		if (nRet != Z_OK)
		{
			if (pUnCompressZlibDat)
			{
				VirtualFree(pUnCompressZlibDat,ulUnCompressSize,MEM_COMMIT | MEM_RESERVE);
				pUnCompressZlibDat = NULL;
			}
			if (pZlibDat)
			{
				VirtualFree(pZlibDat,ulZlibSize,MEM_COMMIT | MEM_RESERVE);
				pZlibDat = NULL;
			}
			return FALSE;
		}
	}
	return TRUE;
}


BOOLEAN CDELLAnalyze::WriteModule(PCHAR pFileName, PCHAR pWriteDat, ULONG ulWriteSize)
{
	HANDLE hFile;
	BOOLEAN bRet;
	ULONG ulRetBytes;

	hFile = INVALID_HANDLE_VALUE;
	bRet = FALSE;
	ulRetBytes = 0;

	do 
	{
		hFile = CreateFile(pFileName, \
			FILE_ALL_ACCESS, \
			FILE_SHARE_READ | FILE_SHARE_WRITE, \
			NULL, \
			OPEN_ALWAYS, \
			FILE_ATTRIBUTE_NORMAL, \
			NULL);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			break;
		}
		bRet = WriteFile(hFile,pWriteDat,ulWriteSize,&ulRetBytes,NULL);
		if (FALSE == bRet || \
			ulRetBytes < ulWriteSize)
		{
			break;
		}
	} while (0);
	if (hFile)
	{
		CloseHandle(hFile);
	}
	return bRet;
}


BOOLEAN CDELLAnalyze::WriteHdr(void)
{
	return WriteModule(HdrPath,pUnCompressZlibDat,ulUnCompressSize);
}


PCHAR CDELLAnalyze::GetHdrDat(void)
{
	return pUnCompressZlibDat;
}


ULONG CDELLAnalyze::GetHdrLength(void)
{
	return ulUnCompressSize;
}


BOOLEAN CDELLAnalyze::GetHdrHeader(PVOID pHdrDat, ULONG ulOffset, PCHAR pOutHdrHeader, ULONG ulHdrHeaderSize)
{
	BOOLEAN bRet;

	bRet = FALSE;

	if (NULL == pHdrDat)
	{
		return bRet;
	}
	RtlCopyMemory(pOutHdrHeader,(PCHAR)((ULONG)pHdrDat + ulOffset),ulHdrHeaderSize);
	bRet = TRUE;
	return bRet;
}


ULONG CDELLAnalyze::MyFindNextVolume(PCHAR pBIOSDat, ULONG ulSize, ULONG ulOffset)
{
	ULONG ulIndex;

	ulIndex = g_pUtils->Find(pBIOSDat,ulSize,EFI_FV_SIGNATURE,strlen(EFI_FV_SIGNATURE),ulOffset,0);
	if (ulIndex < EFI_FV_SIGNATURE_OFFSET)
	{
		return -1;
	}
	return (ulIndex - EFI_FV_SIGNATURE_OFFSET);
}


ULONG CDELLAnalyze::GetBIOSBlock(PCHAR pBIOSDat, ULONG ulBIOSSize, PDELL_BIOS_OPTX_9010 pDellBIOSInfo)
{
	ULONG ulCount;
	ULONG ulIndex;
	ULONG ulOffset;
	PEFI_FIRMWARE_VOLUME_HEADER pEfiFirmWareVolumeHeader;

	ulIndex = 0;
	ulCount = 0;
	ulOffset = 0;
	pEfiFirmWareVolumeHeader = NULL;
	ulOffset = MyFindNextVolume(pBIOSDat,ulBIOSSize,ulOffset);
	while (TRUE)
	{
		ulIndex = MyFindNextVolume(pBIOSDat,ulBIOSSize,ulOffset);
		if (ulIndex < ulBIOSSize && ulIndex != 0)
		{
			pEfiFirmWareVolumeHeader = (PEFI_FIRMWARE_VOLUME_HEADER)((ULONG)pBIOSDat + ulIndex);
			ulOffset += pEfiFirmWareVolumeHeader->FvLength;
			if (ulOffset >= ulBIOSSize)
			{
				break;
			}
			pDellBIOSInfo->HdrInfo.pDellBlock[ulCount].ullBlockStart = ulIndex;
			pDellBIOSInfo->HdrInfo.pDellBlock[ulCount].ullBlockEnd = ulIndex + pEfiFirmWareVolumeHeader->FvLength;
			pDellBIOSInfo->HdrInfo.pDellBlock[ulCount].ullBlockSize = pEfiFirmWareVolumeHeader->FvLength;
#ifdef _DEBUG
			printf("BlockScan  Offset : %08x Length : %08x\r\n\n",ulIndex,pEfiFirmWareVolumeHeader->FvLength);
#endif
			RtlCopyMemory(&pDellBIOSInfo->HdrInfo.pDellBlock[ulCount].EfiFirmWareVolumeHeader,pEfiFirmWareVolumeHeader,sizeof(EFI_FIRMWARE_VOLUME_HEADER));
			pDellBIOSInfo->HdrInfo.ullBlockCount++;
			ulCount++;
		}
		else
		{
			break;
		}
	}
	return ulCount;
}


BOOLEAN CDELLAnalyze::AnalyzeBIOS(PCHAR pBIOSDat, ULONG ulBIOSSize, PREPLACE_UEFI_SECTION pUefiSection)
{
	ULONG ulVolumeOffset,ulPreVolumeOffset;
	ULONG ulVolumeSize,ulPreVolumeSize,ulNextVolumeSize;
	ULONG ulCalcVolumeSize;
	PEFI_FIRMWARE_VOLUME_HEADER pEfiFirmWareVolumeHeader;

	ulVolumeOffset = 0;
	ulVolumeSize = 0;
	ulPreVolumeOffset = 0;
	ulPreVolumeSize = 0;
	ulCalcVolumeSize = 0;
	ulNextVolumeSize = 0;
	pEfiFirmWareVolumeHeader = NULL;

	ulPreVolumeOffset = MyFindNextVolume(pBIOSDat,ulBIOSSize,0);
	ulVolumeOffset = ulPreVolumeOffset;
	if (ulVolumeOffset == -1)
	{
		return FALSE;
	}
	while (TRUE)
	{
		if (ulVolumeOffset > ulPreVolumeOffset + ulPreVolumeSize)
		{
			return FALSE;
		}
		if (g_pEfiBIOSAnalyze->GetVolumeSize(pBIOSDat,ulBIOSSize,ulVolumeOffset,&ulVolumeSize,&ulCalcVolumeSize) == FALSE)
		{
			return FALSE;
		}
		if (ulVolumeSize > ulBIOSSize || ulVolumeOffset + ulVolumeSize > ulBIOSSize)
		{
			return FALSE;
		}
		pEfiFirmWareVolumeHeader = (PEFI_FIRMWARE_VOLUME_HEADER)((ULONG)pBIOSDat + ulVolumeOffset);
		if (pEfiFirmWareVolumeHeader->Revision == 1)
		{
		}
		else if (pEfiFirmWareVolumeHeader->Revision == 2)
		{
		}
		else
		{

		}
		if (g_pEfiBIOSAnalyze->AnalyzeVolume(pBIOSDat,ulVolumeOffset,ulVolumeSize,GetIndex(),pUefiSection) == FALSE)
		{
			printf("\n");
		}
		ulVolumeOffset += ulVolumeSize;
		ulPreVolumeSize = MyFindNextVolume(pBIOSDat,ulBIOSSize - ulVolumeOffset,ulVolumeOffset);
		if (0 == ulPreVolumeSize)
		{
			printf("FindNextVolume Failed\n");
			break;
		}
		SetIndex();
	}
	return TRUE;
}


void CDELLAnalyze::SetIndex(void)
{
	ulIndex++;
}


ULONG CDELLAnalyze::GetIndex(void)
{
	return ulIndex;
}
