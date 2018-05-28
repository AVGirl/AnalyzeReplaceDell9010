#include "Utils.h"
#include "Crc32.h"

CUtils *g_pUtils = NULL;

CUtils::CUtils(void)
{
	EfiCompress = NULL;
	EfiDecompress = NULL;
	TianoCompress = NULL;
	TianoDecompress = NULL;
	hModuleEfiDc = NULL;

	hModuleEfiDc = LoadLibrary("EFIDC.dll");
	if (NULL == hModuleEfiDc)
	{
		printf("Initialize EFIDC.dll Failed\r\n");
	}
	EfiCompress = (EFICOMPRESS)GetProcAddress(hModuleEfiDc,"EfiCompress");
	EfiDecompress = (EFIDECOMPRESS)GetProcAddress(hModuleEfiDc,"EfiDecompress");
	TianoCompress = (TIANOCOMPRESS)GetProcAddress(hModuleEfiDc,"TianoCompress");
	TianoDecompress = (TIANODECOMPRESS)GetProcAddress(hModuleEfiDc,"TianoDecompress");
	if (NULL == EfiCompress || NULL == EfiDecompress || \
		NULL == TianoCompress || NULL == TianoDecompress)
	{
		printf("Get Efi or Tiano De Compress functions failed\r\n");
	}
}


CUtils::~CUtils(void)
{
	if (hModuleEfiDc)
	{
		FreeLibrary(hModuleEfiDc);
		hModuleEfiDc = NULL;
	}
}


ULONG CUtils::Match(PCHAR pSrcDat, ULONG ulSrcSize, PCHAR pFindString, ULONG ulFindSize, ULONG ulOffset, ULONG ulBoundry)
{
	ULONG uli;
	ULONG ulFindLength;
	ULONG ulGlobalCount;
	ULONG ulCount;
	ULONG ulRet;

	ulRet = 0;
	ulGlobalCount = 0;
	ulFindLength = ulFindSize/2;
	do 
	{
		ulCount = 0;
		for (uli = 0;uli <= ulFindLength - 1;uli++)
		{
			if (pFindString[ulCount] != 0x65)
			{
				if (pFindString[ulCount] == 0x78)
				{
					ulCount += 1;
				}
			}
			else
			{
				ulCount += 1;
				if (pSrcDat[ulGlobalCount + uli] != pFindString[ulCount])
				{
					break;
				}
			}
			ulCount += 1;
		}
		ulGlobalCount += ulBoundry;
	} while (uli != ulFindLength && ulGlobalCount <= ((ulSrcSize - ulFindLength - ulBoundry) + 2));
	if (uli == ulFindLength)
	{
		ulRet = ulGlobalCount - ulBoundry; 
	}
	return ulRet;
}


ULONG CUtils::Find(PCHAR pDat, ULONG ulDatSize, PCHAR pFind, ULONG ulFindSize, ULONG ulOffset, ULONG ulBoundry)
{
	ULONG uli,ulj;
	ULONG ulCount;
	ULONG ulRet;

	ulRet = 0;
	ulCount = 0;
	uli = ulj = 0;
	if (ulFindSize + ulOffset > ulDatSize)
	{
		return 0;
	}
	else
	{
		if (ulFindSize > 0)
		{
			if (ulBoundry >= 0)
			{
				for (uli = ulBoundry;uli < ulDatSize;uli++)
				{
					if (uli + ulOffset >= ulDatSize)
					{
						break;
					}
					for (ulj = 0;ulj < ulFindSize;ulj++)
					{
						if (uli + ulOffset + ulj > ulDatSize)
						{
							break;
						}
						if (uli + ulOffset + ulj > ulDatSize - (ulFindSize - 1) && ulCount != 1)
						{
							break;
						}
						if (pDat[uli + ulOffset + ulj] == pFind[ulj])
						{
							ulCount++;
						}
						else
						{
							ulCount = 0;
							break;
						}
					}
					if (ulCount == ulFindSize)
					{
						ulRet = uli + ulOffset;
						break;
					}
				}
			}
		}
	}
	return ulRet;
}


USHORT CUtils::CheckSum16(PCHAR pDat, ULONG ulOffset, ULONG ulLength, BYTE bExtra)
{
	USHORT uCheckSum;

	uCheckSum = 0;

	for (ULONG uli = 0;uli < ulLength;uli += 2)
	{
		uCheckSum += *(USHORT*)((ULONG)pDat + ulOffset + uli);
	}
	uCheckSum += (USHORT)bExtra;
	return (0x10000 - uCheckSum);
}
ULONG CUtils::UnicodeToAnsi(PWCHAR pSrc,PCHAR pDst,ULONG ulSize)
{
	ULONG ulNeedSize;

	ulNeedSize = 0;
	if (ulSize)
	{
		ulNeedSize = WideCharToMultiByte(CP_ACP, \
			NULL, \
			pSrc, \
			-1, \
			pDst, \
			ulSize, \
			NULL, \
			FALSE);
	}
	else
	{
		ulNeedSize = WideCharToMultiByte(CP_ACP, \
			NULL, \
			pSrc, \
			-1, \
			NULL, \
			0, \
			NULL, \
			FALSE);
	}
	return ulNeedSize;
}
ULONG CUtils::AnsiToUnicode(PCHAR pSrc,PWCHAR pDst,ULONG ulSize)
{
	ULONG ulNeedSize;

	ulNeedSize = 0;
	if (ulSize)
	{
		ulNeedSize = MultiByteToWideChar(CP_ACP, \
			NULL, \
			pSrc, \
			-1, \
			pDst, \
			ulSize);
	}
	else
	{
		ulNeedSize = MultiByteToWideChar(CP_ACP, \
			NULL, \
			pSrc, \
			-1, \
			NULL, \
			0);
	}
	return ulNeedSize;
}


PCHAR CUtils::ConvertName(PCHAR pGuidDat)
{
	PCHAR pGuid;

	if (NULL == pGuidDat)
	{
		return NULL;
	}
	pGuid = NULL;
	do 
	{
		pGuid = (PCHAR)malloc(MAX_PATH);
	} while (NULL == pGuid);
	RtlZeroMemory(pGuid,MAX_PATH);
	StringCchPrintf(pGuid,MAX_PATH,"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",*(BYTE*)((ULONG)pGuidDat + 3), \
		*(BYTE*)((ULONG)pGuidDat + 2), \
		*(BYTE*)((ULONG)pGuidDat + 1), \
		*(BYTE*)((ULONG)pGuidDat + 0), \
		*(BYTE*)((ULONG)pGuidDat + 5), \
		*(BYTE*)((ULONG)pGuidDat + 4), \
		*(BYTE*)((ULONG)pGuidDat + 7), \
		*(BYTE*)((ULONG)pGuidDat + 6), \
		*(BYTE*)((ULONG)pGuidDat + 8), \
		*(BYTE*)((ULONG)pGuidDat + 9), \
		*(BYTE*)((ULONG)pGuidDat + 0x0A), \
		*(BYTE*)((ULONG)pGuidDat + 0x0B), \
		*(BYTE*)((ULONG)pGuidDat + 0x0C), \
		*(BYTE*)((ULONG)pGuidDat + 0x0D), \
		*(BYTE*)((ULONG)pGuidDat + 0x0E), \
		*(BYTE*)((ULONG)pGuidDat + 0x0F));
	strupr(pGuid);
	return pGuid;
}


BYTE CUtils::CheckSum8(PCHAR pDat, ULONG ulOffset, ULONG ulLength, BYTE bExtra)
{
	BYTE bCheckSum;
	ULONG uli;

	bCheckSum = 0;

	for (uli = 0;uli < ulLength;uli++)
	{
		bCheckSum += *(BYTE*)((ULONG)pDat + ulOffset + uli);
	}
	bCheckSum += bExtra;
	return (0x100 - bCheckSum);
}


ULONG CUtils::CheckSum32(PCHAR pDat, ULONG ulOffset, ULONG ulLength)
{
	unsigned int ulCrc32;

	ulCrc32 = 0;

	crc32Init(&ulCrc32);
	crc32Update(&ulCrc32,(char*)((long)pDat + ulOffset),ulLength);
	crc32Finish(&ulCrc32);

	return ulCrc32;
}


ULONG CUtils::DelFileForSize(PCHAR pDirectory,ULONG ulDelSize)
{
	WIN32_FIND_DATA Win32FindDat;
	HANDLE hFind;
	BOOLEAN bRet;
	CHAR wEnumPath[MAX_PATH];
	CHAR wDeletePath[MAX_PATH];
	ULONG ulCount;
	CHAR wSaveBin[MAX_PATH];
	CHAR pSignature[3] = {0x55,0xAA,0x00};

	ulCount = 0;
	bRet = FALSE;
	RtlZeroMemory(wEnumPath,sizeof(CHAR) * MAX_PATH);
	RtlZeroMemory(wDeletePath,sizeof(CHAR) * MAX_PATH);
	RtlZeroMemory(wSaveBin,sizeof(CHAR) * MAX_PATH);
	StringCchCopy(wEnumPath,MAX_PATH,pDirectory);
	if (::PathFileExists(wEnumPath))
	{
		StringCchCat(wEnumPath,MAX_PATH,"\\*.*");
		hFind = ::FindFirstFile(wEnumPath,&Win32FindDat);
		if (INVALID_HANDLE_VALUE == hFind)
		{
			return ulCount;
		}
		while (TRUE)
		{
			if (Win32FindDat.cFileName[0] != '\.')
			{
				if (Win32FindDat.dwFileAttributes &= FILE_ATTRIBUTE_DIRECTORY)
				{
					printf("%ws",wDeletePath);
				}
				else
				{
					StringCchPrintf(wDeletePath,MAX_PATH,"%s\\%s",pDirectory,Win32FindDat.cFileName);
					if (Win32FindDat.nFileSizeLow < ulDelSize)
					{
						DeleteFile(wDeletePath);
						ulCount++;
					}
					else
					{
						if (CheckSignature(wDeletePath,pSignature,strlen(pSignature)))
						{
							printf("File: %s\r\n",wDeletePath);
							StringCchPrintf(wSaveBin,MAX_PATH,"%s\\%s","C:\\PassPKit\\FindExecuteBinPCI",Win32FindDat.cFileName);
							CopyFile(wDeletePath,wSaveBin,FALSE);
						}
					}
				}
			}
			bRet = ::FindNextFile(hFind,&Win32FindDat);
			if (FALSE == bRet)
			{
				break;
			}
		}
		::FindClose(hFind);
	}
	return ulCount;
}


ULONG CUtils::CheckSignature(PCHAR pFileName, PCHAR pSignature, ULONG ulSize)
{
	HANDLE hFile;
	BOOLEAN bRet;
	ULONG ulRetReadSize;
	PCHAR pReadDat;
	ULONG uli;
	ULONG ulCount;

	hFile = INVALID_HANDLE_VALUE;
	bRet = FALSE;
	ulRetReadSize = 0;
	pReadDat = NULL;
	ulCount = 0;

	do 
	{
		pReadDat = (PCHAR)malloc(ulSize);
	} while (NULL == pReadDat);
	RtlZeroMemory(pReadDat,ulSize);
	do 
	{
		hFile = CreateFile(pFileName, \
			FILE_ALL_ACCESS, \
			FILE_SHARE_READ, \
			NULL, \
			OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, \
			NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			break;
		}
		bRet = ReadFile(hFile, \
			pReadDat, \
			ulSize, \
			&ulRetReadSize, \
			NULL);
		if (FALSE == bRet)
		{
			break;
		}
		for (uli = 0;uli < ulSize;uli++)
		{
			if (pReadDat[uli] == pSignature[uli])
			{
				ulCount++;
			}
			else
			{
				ulCount = 0;
			}
			if (ulCount == ulSize)
			{
				break;
			}
		}
	} while (0);
	if (pReadDat)
	{
		free(pReadDat);
	}
	if (hFile)
	{
		CloseHandle(hFile);
	}
	return ulCount;
}


ULONG CUtils::ULONG24ToULONG32(PCHAR pSize)
{
	return (ULONG)(pSize[2] << 16) + (ULONG)(pSize[1] << 8) + (ULONG)pSize[0];
}


PCHAR CUtils::ULONG32ToULONG24(ULONG ulValue)
{
	PCHAR pHex;

	pHex = NULL;

	do 
	{
		pHex = (PCHAR)malloc(3);
	} while (NULL == pHex);
	RtlZeroMemory(pHex,3);
	pHex[0] = *(CHAR *)&ulValue;
	pHex[1] = *(CHAR *)((ULONG)&ulValue + 1);
	pHex[2] = *(CHAR *)((ULONG)&ulValue + 2);
	return pHex;
}


BYTE CUtils::XorCheckSum(PCHAR pDat, ULONG ulSize,BOOLEAN bFucked)
{
	BYTE bXorValue;
	BYTE bFuckXorValue;
	BYTE bRetValue;
	ULONG ulCount;

	bXorValue = 0;
	ulCount = 0;
	bRetValue = 0;
	bFuckXorValue = 0;

	if (bFucked)
	{
		bXorValue = *(BYTE*)pDat;
		for (int i = 1;i < ulSize;i++)
		{
			bXorValue = bXorValue ^ *(BYTE*)((ULONG)pDat + i);
		}
		return 0 ^ bXorValue;
	}
	else
	{
		while (ulCount < ulSize)
		{
			bXorValue = *(BYTE*)((ULONG)pDat + ulCount + 2);
			bRetValue = bXorValue ^ *(BYTE*)((ULONG)pDat + ulCount + 3);
			ulCount += 4;
			bRetValue = bRetValue ^ *(BYTE*)((ULONG)pDat + ulCount + 1);
			bRetValue = bRetValue ^ *(BYTE*)((ULONG)pDat + ulCount);
			bFuckXorValue = bFuckXorValue ^ bRetValue;
		}
		return bFuckXorValue;
	}
	return 0;
}
