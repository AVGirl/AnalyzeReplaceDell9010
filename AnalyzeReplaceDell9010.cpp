#include "AnalyzeReplaceDell9010.h"
#include "DELLAnalyze.h"
#include "AnalyzeCmdLine.h"
#include "MemoryOperations.h"
#include "Utils.h"
#include "EFIBIOSANALYZE.h"
#include "FileOperations.h"
#include "zlib/zlib.h"
#include "Crc32.h"


PDELL_BIOS_OPTX_9010 g_pDellBIOSInfo = NULL;
LIST_ENTRY g_ReplaceUefiImage;

void SetBlackGreen()
{
	HANDLE hOut;
	hOut = GetStdHandle(STD_OUTPUT_HANDLE);  
	SetConsoleTextAttribute(hOut,FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	return;
}
BOOLEAN CheckGenerateHdr(PCHAR pHdrFileName)
{
	HANDLE hFile;
	CHAR ReadName[MAX_PATH];
	ULONG ulRetBytesRead;
	BOOLEAN bRet;
	ULONG ulSize;
	PCHAR pReadDat;

	hFile = INVALID_HANDLE_VALUE;
	ulRetBytesRead = 0;
	bRet = FALSE;
	ulSize = 0;
	pReadDat = NULL;
	RtlZeroMemory(ReadName,sizeof(CHAR) * MAX_PATH);

	do 
	{
		GetCurrentDirectory(MAX_PATH,ReadName);
		StringCchCatA(ReadName,MAX_PATH,"\\");
		StringCchCatA(ReadName,MAX_PATH,pHdrFileName);

		hFile = CreateFile(ReadName, \
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
		ulSize = ::GetFileSize(hFile,NULL);
		do 
		{
			pReadDat = (PCHAR)::VirtualAlloc(NULL,ulSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
		} while (NULL == pReadDat);
		RtlZeroMemory(pReadDat,ulSize);
		bRet = ReadFile(hFile,pReadDat,ulSize,&ulRetBytesRead,NULL);
		if (FALSE == bRet)
		{
			break;
		}
		g_pDellAnalyze->AnalyzeBIOS(pReadDat,ulSize,NULL);
	} while (0);
	if (hFile)
	{
		CloseHandle(hFile);
	}
	return bRet;
}
BOOLEAN FixedInstall(PCHAR pHdrFileName,PCHAR pInstallName)
{
	HANDLE hHdrFile;
	HANDLE hInstallFile;
	ULONG ulHdrFileSize;
	CHAR HdrPath[MAX_PATH];
	CHAR InstallPath[MAX_PATH];
	BOOLEAN bRet;
	PVOID pHdrDat;
	PVOID pExecuteDat;
	ULONG ulRetBytesRead;
	ULONG ulNeedSize;
	PCHAR pCompressedNewHdr;
	ULONG ulRetCompressedSize;
	ULONG ulExecuteSize;
	ULONG ulNeedExecuteSize;
	PCHAR pNewExecuteDat;
	ULONG ulBIOSCrc32CheckSum;
	

	hHdrFile = INVALID_HANDLE_VALUE;
	hInstallFile = INVALID_HANDLE_VALUE;
	ulHdrFileSize = 0;
	RtlZeroMemory(HdrPath,MAX_PATH);
	RtlZeroMemory(InstallPath,MAX_PATH);
	bRet = FALSE;
	pHdrDat = NULL;
	ulRetBytesRead = 0;
	pCompressedNewHdr = NULL;
	ulRetCompressedSize = 0;
	ulExecuteSize = 0;
	pExecuteDat = NULL;
	ulNeedExecuteSize = 0;
	pNewExecuteDat = NULL;
	ulBIOSCrc32CheckSum = 0;

	do 
	{
		GetCurrentDirectory(MAX_PATH,HdrPath);
		StringCchCatA(HdrPath,MAX_PATH,"\\");
		StringCchCatA(HdrPath,MAX_PATH,pHdrFileName);

		GetCurrentDirectory(MAX_PATH,InstallPath);
		StringCchCatA(InstallPath,MAX_PATH,"\\");
		StringCchCatA(InstallPath,MAX_PATH,pInstallName);

		hHdrFile = CreateFile(pHdrFileName, \
			FILE_ALL_ACCESS, \
			FILE_SHARE_READ | FILE_SHARE_WRITE, \
			NULL, \
			OPEN_ALWAYS, \
			FILE_ATTRIBUTE_NORMAL, \
			NULL);
		if (INVALID_HANDLE_VALUE == hHdrFile)
		{
			break;
		}
		ulHdrFileSize = ::GetFileSize(hHdrFile,NULL);

		hInstallFile = CreateFile(InstallPath, \
			FILE_ALL_ACCESS, \
			FILE_SHARE_READ | FILE_SHARE_WRITE, \
			NULL, \
			OPEN_ALWAYS, \
			FILE_ATTRIBUTE_NORMAL, \
			NULL);
		if (INVALID_HANDLE_VALUE == hInstallFile)
		{
			break;
		}
		ulExecuteSize = ::GetFileSize(hInstallFile,NULL);

		do 
		{
			pHdrDat = (PCHAR)::VirtualAlloc(NULL,ulHdrFileSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
		} while (NULL == pHdrDat);
		RtlZeroMemory(pHdrDat,ulHdrFileSize);
		bRet = ReadFile(hHdrFile,pHdrDat,ulHdrFileSize,&ulRetBytesRead,NULL);
		if (FALSE == bRet)
		{
			break;
		}

		do 
		{
			pExecuteDat = (PCHAR)::VirtualAlloc(NULL,ulExecuteSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
		} while (NULL == pExecuteDat);
		RtlZeroMemory(pExecuteDat,ulExecuteSize);
		bRet = ReadFile(hInstallFile,pExecuteDat,ulExecuteSize,&ulRetBytesRead,NULL);
		if (FALSE == bRet)
		{
			break;
		}

		ulBIOSCrc32CheckSum = MyCrc32(0,(PCHAR)((ULONG)pHdrDat + 0x58),0x600000);
		*(ULONG*)((ULONG)pHdrDat + 0x50) = 0xFFFFFFFF - ulBIOSCrc32CheckSum;

		ulNeedSize = compressBound(ulHdrFileSize) + 0x04 + 0x0C;
		do 
		{
			pCompressedNewHdr = (PCHAR)::VirtualAlloc(NULL,ulNeedSize,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
		} while (NULL == pCompressedNewHdr);
		RtlZeroMemory(pCompressedNewHdr,ulNeedSize);

		ulRetCompressedSize = ulNeedSize - 0x04 - 0x0C;
		if (compress((Bytef*)((ULONG)pCompressedNewHdr + 0x04 + 0x0C),&ulRetCompressedSize,(Bytef*)pHdrDat,ulHdrFileSize) != Z_OK)
		{
			printf("compressed New Hdr failed\n");
		}
		RtlCopyMemory(pCompressedNewHdr,&ulRetCompressedSize,sizeof(ULONG));
		RtlCopyMemory((PCHAR)((ULONG)pCompressedNewHdr + sizeof(ULONG)),bFindHdrSignature,0x0C);
		ulNeedExecuteSize = ulExecuteSize - \
			(*(ULONG*)((ULONG)pExecuteDat + g_pDellAnalyze->ulOldHdrOffset)) + \
			ulRetCompressedSize;

		do 
		{
			pNewExecuteDat = (PCHAR)::VirtualAlloc(NULL,ulNeedExecuteSize,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
		} while (NULL == pNewExecuteDat);
		RtlZeroMemory(pNewExecuteDat,ulNeedExecuteSize);


		RtlCopyMemory(pNewExecuteDat,pExecuteDat,g_pDellAnalyze->ulOldHdrOffset);

		*(PCHAR)((ULONG)pCompressedNewHdr + 0x0F) = 0x00;

		*(PCHAR)((ULONG)pCompressedNewHdr + 0x0F) = g_pUtils->XorCheckSum(pCompressedNewHdr,0x10,TRUE);

		RtlCopyMemory((PCHAR)((ULONG)pNewExecuteDat + g_pDellAnalyze->ulOldHdrOffset), \
			pCompressedNewHdr,ulRetCompressedSize + 0x04 + 0x0C);

		RtlCopyMemory((PCHAR)((ULONG)pNewExecuteDat + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x04 + 0x0C), \
			&ulRetCompressedSize,sizeof(ULONG));

		RtlCopyMemory((PCHAR)((ULONG)pNewExecuteDat + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x04 + 0x0C + sizeof(ULONG)), \
			(PCHAR)((ULONG)pExecuteDat + g_pDellAnalyze->ulOldHdrOffset + 4 + 0x0C + *(ULONG*)((ULONG)pExecuteDat + g_pDellAnalyze->ulOldHdrOffset) + sizeof(ULONG)), \
			ulExecuteSize - 0x04 - 0x0C - g_pDellAnalyze->ulOldHdrOffset - *(ULONG*)((ULONG)pExecuteDat + g_pDellAnalyze->ulOldHdrOffset) - sizeof(ULONG));

		*(PCHAR)((ULONG)pNewExecuteDat + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x10 + 0x0F) = 0x00;

		*(PCHAR)((ULONG)pNewExecuteDat + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x10 + 0x0F) = \
			g_pUtils->XorCheckSum((PCHAR)((ULONG)pNewExecuteDat + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x10),0x10,TRUE);

		g_pEfiBIOSAnalyze->WriteModule("Out.Exe",pNewExecuteDat,ulNeedExecuteSize);

	} while (0);
	if (hHdrFile)
	{
		CloseHandle(hHdrFile);
	}
	if (hInstallFile)
	{
		CloseHandle(hInstallFile);
	}
	return bRet;
}
int main(int argc, char* argv[])
{
	BOOLEAN bRet;
	PCHAR pGenHdrDat;
	ULONG ulOffset;
	SYSTEMTIME SystemTime;
	CHAR OutName[MAX_PATH];
	ULONG ulNeedSize;
	PCHAR pCompressedNewHdr;
	ULONG ulRetCompressedSize;
	PCHAR pNewExecuteFile;
	ULONG ulNewExecuteFileSize;
	ULONG ulBIOSCrc32CheckSum;
	int nRet;

	bRet = FALSE;
	pGenHdrDat = NULL;
	ulOffset = 0;
	ulNeedSize = 0;
	pCompressedNewHdr = 0;
	ulRetCompressedSize = 0;
	nRet = 0;
	ulNewExecuteFileSize = 0;
	pNewExecuteFile = NULL;
	ulBIOSCrc32CheckSum = 0;
	SetBlackGreen();

	if (argc < 2)
	{
		return 0;
	}
	do 
	{
		g_pDellBIOSInfo = (PDELL_BIOS_OPTX_9010)AllocateMemory(sizeof(DELL_BIOS_OPTX_9010),PAGE_READWRITE);
	} while (NULL == g_pDellBIOSInfo);
	RtlZeroMemory(g_pDellBIOSInfo,sizeof(DELL_BIOS_OPTX_9010));

	g_pDellBIOSInfo->ulExecuteFileSize = GetAnalyzeFileSize(argv[1]);
	if (0 == g_pDellBIOSInfo->ulExecuteFileSize)
	{
		return 0;
	}
	g_pDellBIOSInfo->pExecuteDat = (PVOID)AllocateMemory(g_pDellBIOSInfo->ulExecuteFileSize,PAGE_READWRITE);
	if (NULL == g_pDellBIOSInfo->pExecuteDat)
	{
		return 0;
	}
	RtlZeroMemory(g_pDellBIOSInfo->pExecuteDat,g_pDellBIOSInfo->ulExecuteFileSize);
	bRet = GetAnalyzeFileDat(argv[1],(PCHAR)g_pDellBIOSInfo->pExecuteDat,g_pDellBIOSInfo->ulExecuteFileSize);
	if (FALSE == bRet)
	{
		return 0;
	}
	g_pUtils = new CUtils;
	g_pDellAnalyze = new CDELLAnalyze;
	g_pEfiBIOSAnalyze = new CEFIBIOSANALYZE;
	g_pDellAnalyze->GetZlibHeader((PCHAR)g_pDellBIOSInfo->pExecuteDat,g_pDellBIOSInfo->ulExecuteFileSize);
	g_pDellAnalyze->WriteHdr();
	g_pDellBIOSInfo->HdrInfo.pHdrFileDat = g_pDellAnalyze->GetHdrDat();
	g_pDellBIOSInfo->HdrInfo.ullHdrFileSize = g_pDellAnalyze->GetHdrLength();
	g_pDellAnalyze->GetHdrHeader(g_pDellBIOSInfo->HdrInfo.pHdrFileDat, \
		0, \
		(PCHAR)g_pDellBIOSInfo->HdrInfo.HdrHeaderCode, \
		HDR_HEADER_LENGTH);

	g_pDellAnalyze->GetBIOSBlock((PCHAR)g_pDellBIOSInfo->HdrInfo.pHdrFileDat,g_pDellBIOSInfo->HdrInfo.ullHdrFileSize,g_pDellBIOSInfo);
	InitializeListHead(&g_ReplaceUefiImage);

	do 
	{
		pGenHdrDat = (PCHAR)::VirtualAlloc(NULL,g_pDellBIOSInfo->HdrInfo.ullHdrFileSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
	} while (NULL == pGenHdrDat);
	RtlZeroMemory(pGenHdrDat,g_pDellBIOSInfo->HdrInfo.ullHdrFileSize);

	RtlCopyMemory(pGenHdrDat,g_pDellBIOSInfo->HdrInfo.pHdrFileDat,HDR_HEADER_LENGTH);

	ulOffset = HDR_HEADER_LENGTH;
	//g_pDellAnalyze->AnalyzeBIOS((PCHAR)g_pDellBIOSInfo->HdrInfo.pHdrFileDat,g_pDellBIOSInfo->HdrInfo.ullHdrFileSize,NULL);
	for (ULONG uli = 0;uli < g_pDellBIOSInfo->HdrInfo.ullBlockCount;uli++)
	{
		if (uli == 3)
		{
			g_pEfiBIOSAnalyze->AnalyzeVolume2((PCHAR)((ULONG)g_pDellBIOSInfo->HdrInfo.pHdrFileDat +  g_pDellBIOSInfo->HdrInfo.pDellBlock[uli].ullBlockStart), \
				g_pDellBIOSInfo->HdrInfo.pDellBlock[uli].ullBlockSize,TRUE);
			RtlCopyMemory((PCHAR)((ULONG)pGenHdrDat + ulOffset), \
				(PCHAR)g_pEfiBIOSAnalyze->pReplaceBigBlock, \
				g_pDellBIOSInfo->HdrInfo.pDellBlock[uli].ullBlockSize);
			ulOffset += g_pDellBIOSInfo->HdrInfo.pDellBlock[uli].ullBlockSize;
		}
		else
		{
			g_pEfiBIOSAnalyze->AnalyzeVolume2((PCHAR)((ULONG)g_pDellBIOSInfo->HdrInfo.pHdrFileDat +  g_pDellBIOSInfo->HdrInfo.pDellBlock[uli].ullBlockStart), \
				g_pDellBIOSInfo->HdrInfo.pDellBlock[uli].ullBlockSize,FALSE);
			RtlCopyMemory((PCHAR)((ULONG)pGenHdrDat + ulOffset), \
				(PCHAR)((ULONG)g_pDellBIOSInfo->HdrInfo.pHdrFileDat + g_pDellBIOSInfo->HdrInfo.pDellBlock[uli].ullBlockStart), \
				g_pDellBIOSInfo->HdrInfo.pDellBlock[uli].ullBlockSize);
			ulOffset += g_pDellBIOSInfo->HdrInfo.pDellBlock[uli].ullBlockSize;
		}
	}
	RtlCopyMemory((PCHAR)((ULONG)pGenHdrDat + ulOffset), \
		(PCHAR)((ULONG)g_pDellBIOSInfo->HdrInfo.pHdrFileDat + ulOffset), \
		g_pDellBIOSInfo->HdrInfo.ullHdrFileSize - ulOffset);
	GetLocalTime(&SystemTime);

	RtlZeroMemory(OutName,sizeof(CHAR) * MAX_PATH);
	StringCchPrintf(OutName,MAX_PATH,"Bin\\%4d_%02d_%02d_%02d_%02d_%02d.Hdr", \
		SystemTime.wYear,SystemTime.wMonth,SystemTime.wDay,SystemTime.wHour,SystemTime.wMinute,SystemTime.wSecond);
	g_pEfiBIOSAnalyze->WriteModule(OutName,pGenHdrDat,g_pDellBIOSInfo->HdrInfo.ullHdrFileSize);

	//CheckGenerateHdr(OutName);

	ulNeedSize = compressBound(g_pDellBIOSInfo->HdrInfo.ullHdrFileSize) + 0x04 + 0x0C;
	do 
	{
		pCompressedNewHdr = (PCHAR)::VirtualAlloc(NULL,ulNeedSize,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
	} while (NULL == pCompressedNewHdr);
	RtlZeroMemory(pCompressedNewHdr,ulNeedSize);
	ulRetCompressedSize = ulNeedSize - 0x04 - 0x0C;

	ulBIOSCrc32CheckSum = MyCrc32(0,(PCHAR)((ULONG)pGenHdrDat + 0x58),0x600000);
	*(ULONG*)((ULONG)pGenHdrDat + 0x50) = 0xFFFFFFFF - ulBIOSCrc32CheckSum;
	nRet = compress((Bytef*)((ULONG)pCompressedNewHdr + 0x04 + 0x0C),&ulRetCompressedSize,(Bytef*)pGenHdrDat,g_pDellBIOSInfo->HdrInfo.ullHdrFileSize);
	if (nRet != Z_OK)
	{
		printf("compressed New Hdr failed\n");
	}
	RtlCopyMemory(pCompressedNewHdr,&ulRetCompressedSize,sizeof(ULONG));
	RtlCopyMemory((PCHAR)((ULONG)pCompressedNewHdr + sizeof(ULONG)),bFindHdrSignature,0x0C);

	ulNewExecuteFileSize = g_pDellBIOSInfo->ulExecuteFileSize - \
		(*(ULONG*)((ULONG)g_pDellBIOSInfo->pExecuteDat + g_pDellAnalyze->ulOldHdrOffset)) + \
		ulRetCompressedSize;
	do 
	{
		pNewExecuteFile = (PCHAR)::VirtualAlloc(NULL,ulNewExecuteFileSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
	} while (NULL == pNewExecuteFile);
	RtlZeroMemory(pNewExecuteFile,ulNewExecuteFileSize);

	RtlCopyMemory(pNewExecuteFile,g_pDellBIOSInfo->pExecuteDat,g_pDellAnalyze->ulOldHdrOffset);

	*(PCHAR)((ULONG)pCompressedNewHdr + 0x0F) = 0x00;

	*(PCHAR)((ULONG)pCompressedNewHdr + 0x0F) = g_pUtils->XorCheckSum(pCompressedNewHdr,0x10,TRUE);

	RtlCopyMemory((PCHAR)((ULONG)pNewExecuteFile + g_pDellAnalyze->ulOldHdrOffset), \
		pCompressedNewHdr,ulRetCompressedSize + 0x04 + 0x0C);

	RtlCopyMemory((PCHAR)((ULONG)pNewExecuteFile + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x04 + 0x0C), \
		&ulRetCompressedSize,sizeof(ULONG));

	RtlCopyMemory((PCHAR)((ULONG)pNewExecuteFile + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x04 + 0x0C + sizeof(ULONG)), \
		(PCHAR)((ULONG)g_pDellBIOSInfo->pExecuteDat + g_pDellAnalyze->ulOldHdrOffset + 4 + 0x0C + *(ULONG*)((ULONG)g_pDellBIOSInfo->pExecuteDat + g_pDellAnalyze->ulOldHdrOffset) + sizeof(ULONG)), \
		g_pDellBIOSInfo->ulExecuteFileSize - 0x04 - 0x0C - g_pDellAnalyze->ulOldHdrOffset - *(ULONG*)((ULONG)g_pDellBIOSInfo->pExecuteDat + g_pDellAnalyze->ulOldHdrOffset) - sizeof(ULONG));

	*(PCHAR)((ULONG)pNewExecuteFile + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x10 + 0x0F) = 0x00;

	*(PCHAR)((ULONG)pNewExecuteFile + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x10 + 0x0F) = \
		g_pUtils->XorCheckSum((PCHAR)((ULONG)pNewExecuteFile + g_pDellAnalyze->ulOldHdrOffset + ulRetCompressedSize + 0x10),0x10,TRUE);
	
	GetLocalTime(&SystemTime);

	RtlZeroMemory(OutName,sizeof(CHAR) * MAX_PATH);
	StringCchPrintf(OutName,MAX_PATH,"Bin\\%4d_%02d_%02d_%02d_%02d_%02d.exe", \
		SystemTime.wYear,SystemTime.wMonth,SystemTime.wDay,SystemTime.wHour,SystemTime.wMinute,SystemTime.wSecond);
	g_pEfiBIOSAnalyze->WriteModule(OutName,pNewExecuteFile,ulNewExecuteFileSize);

	FixedInstall("xxxxx.hdr.rom","2016_10_15_22_17_47.exe");
	
	system("pause");

}

