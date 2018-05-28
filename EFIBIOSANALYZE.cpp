#include "EFIBIOSANALYZE.h"
#include "Utils.h"
#include "DELLAnalyze.h"
#include "LZMA/UefiLzma.h"
#include "LZMA/LzmaCompress.h"
#include "LZMA/LzmaDecompress.h"
#include "Tiano/EfiTianoDecompress.h"
#include "peimage.h"
#include <math.h>

CEFIBIOSANALYZE *g_pEfiBIOSAnalyze = NULL;

CEFIBIOSANALYZE::CEFIBIOSANALYZE(void)
	: ulFindCount(0)
	, ulReplaceSubPos(0)
	, ulBootkitLength(0)
{
	pReplaceBigBlock = NULL;
	pBootkitDat = NULL;
	pReplaceSubModule = NULL;
	ulReplaceBigBlockPos = 0;
}


CEFIBIOSANALYZE::~CEFIBIOSANALYZE(void)
{
}

PCHAR CEFIBIOSANALYZE::GetGUIDName(PCHAR pGuid)
{
	PCHAR pRetGuid;

	if (NULL == pGuid)
	{
		return NULL;
	}
	pRetGuid = NULL;

	do 
	{
		pRetGuid = (PCHAR)malloc(MAX_PATH);
	} while (NULL == pRetGuid);
	RtlZeroMemory(pRetGuid,MAX_PATH);
	if (strnicmp(pGuid,"3B6686BD-0D76-4030-B70E-B5519E2fC5A0",strlen("3B6686BD-0D76-4030-B70E-B5519E2fC5A0")) == 0)
	{
		RtlCopyMemory(pRetGuid,"EFI 封装",strlen("EFI 封装"));
	}
	if (strnicmp(pGuid,"7A9354D9-0468-444A-81CE-0BF617D890DF",strlen("7A9354D9-0468-444A-81CE-0BF617D890DF")) == 0)
	{
		RtlCopyMemory(pRetGuid,"EFI 固件文件系统",strlen("EFI 固件文件系统"));
	}
	if (strnicmp(pGuid,"8C8CE578-8A3D-4F1C-9935-896185C32DD3",strlen("8C8CE578-8A3D-4F1C-9935-896185C32DD3")) == 0)
	{
		RtlCopyMemory(pRetGuid,"EFI 固件文件系统",strlen("EFI 固件文件系统"));
	}
	if (strnicmp(pGuid,"5473C07A-3DCB-4DCA-BD6F-1E9689E7349A",strlen("5473C07A-3DCB-4DCA-BD6F-1E9689E7349A")) == 0)
	{
		RtlCopyMemory(pRetGuid,"EFI 固件文件系统",strlen("EFI 固件文件系统"));
	}
	if (strnicmp(pGuid,"DE28BC59-6228-41BD-BDF6-A3B9ADB58DA1",strlen("DE28BC59-6228-41BD-BDF6-A3B9ADB58DA1")) == 0)
	{
		RtlCopyMemory(pRetGuid,"固件块协议",strlen("固件块协议"));
	}
	if (strnicmp(pGuid,"1BA0062E-C779-4582-8566-336AE8F78F09",strlen("1BA0062E-C779-4582-8566-336AE8F78F09")) == 0)
	{
		RtlCopyMemory(pRetGuid,"EFI 固件文件系统卷首文件",strlen("EFI 固件文件系统卷首文件"));
	}
	return pRetGuid;
}
ULONG CEFIBIOSANALYZE::MyLzmaCompress(PUCHAR pDestDat, ULONG *ulDestSize, PUCHAR pSrcDat, ULONG ulSrcSize)
{
	ULONG ulRet = 0;

	ulRet = LzmaCompress(pSrcDat,ulSrcSize,pDestDat,(UINT32*)ulDestSize);
	return ulRet;
}


ULONG CEFIBIOSANALYZE::MyLzmaUnCompress(PUCHAR pDestDat,PUCHAR pSrcDat,ULONG ulSrcSize)
{
	ULONG ulRet = 0;

	ulRet = LzmaDecompress(pSrcDat,ulSrcSize,pDestDat);
	return ulRet;
}
BOOLEAN CEFIBIOSANALYZE::IsValidEFIFVH(PCHAR pBIOSRom, ULONG ulRomSize, ULONG ulOffset, BOOLEAN bVerbose)
{
	BOOLEAN bRet;
	PEFI_FIRMWARE_VOLUME_HEADER pEfiFirmWareVolumeHeader;

	bRet = TRUE;
	pEfiFirmWareVolumeHeader = NULL;

	if (NULL == pBIOSRom || \
		ulOffset > ulRomSize)
	{
		return FALSE;
	}
	pEfiFirmWareVolumeHeader = (PEFI_FIRMWARE_VOLUME_HEADER)((ULONG)pBIOSRom + ulOffset);
	if (strnicmp((PCHAR)&pEfiFirmWareVolumeHeader->Signature,EFI_FV_SIGNATURE,strlen(EFI_FV_SIGNATURE)) == 0)
	{
		if (!((ulOffset + pEfiFirmWareVolumeHeader->HeaderLength >= ulRomSize) | (pEfiFirmWareVolumeHeader->HeaderLength < 0x38)))
		{
			if (g_pUtils->CheckSum16(pBIOSRom,ulOffset,pEfiFirmWareVolumeHeader->HeaderLength,0) != 0)
			{
				bRet = FALSE;
			}
			if (pEfiFirmWareVolumeHeader->HeaderLength < 0x400)
			{
				bRet = TRUE;
			}
			if (ulOffset + pEfiFirmWareVolumeHeader->FvLength > ulRomSize || \
				pEfiFirmWareVolumeHeader->FvLength == 0)
			{
				if (bRet == FALSE)
				{
					if (bVerbose)
					{
						printf("无效的固件卷头\r\n");
					}
				}
			}
		}
	}
	return bRet;
}
BOOLEAN CEFIBIOSANALYZE::IsValidHeaderEFI(PCHAR pEfiDat, ULONG ulEfiLength, ULONG ulOffset, BOOLEAN bVerbose)
{
	BOOLEAN bRet;
	BYTE bNewCheckSumCrc8,bOldCheckSumCrc8;
	USHORT uCheckSum;
	BOOLEAN bFlag;
	PEFI_FFS_FILE_HEADER pEfiFfsFileHeader;
	ULONG ulLength;

	bRet = FALSE;
	bNewCheckSumCrc8 = 0;
	bOldCheckSumCrc8 = 0;
	uCheckSum = 0;
	bFlag = FALSE;
	pEfiFfsFileHeader = NULL;
	ulLength = 0;

	if (NULL == pEfiDat && \
		ulEfiLength < 0x18)
	{
		return bRet;
	}
	ulLength = (ULONG)pEfiFfsFileHeader->Size;
	pEfiFfsFileHeader = (PEFI_FFS_FILE_HEADER)((ULONG)pEfiDat + ulOffset);
	if (ulOffset +  ulLength > ulEfiLength || ulLength < 0x18)
	{
		if (bVerbose)
		{
			printf("无效的头部\r\n");
		}
	}
	else
	{
		bOldCheckSumCrc8 = *(BYTE*)((ULONG)pEfiDat + ulOffset + 0x11);
		*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x11) = 0;
		bNewCheckSumCrc8 = g_pUtils->CheckSum8(pEfiDat,ulOffset,0x17,0);
		*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x11) = bOldCheckSumCrc8;
		if (bNewCheckSumCrc8 != 0)
		{
			if (bVerbose)
			{
				printf("头部校验和无效\r\n");
			}
		}
		else
		{
			bFlag = TRUE;
			if ((*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x13) & 0x01) == 0x01)
			{
				ulLength = ulLength - 0x02;
			}
			if ((*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x13) & 0x40) == 0x40)
			{
				if (g_pUtils->CheckSum8(pEfiDat,ulOffset + 0x18,ulLength - 0x18,0) != bOldCheckSumCrc8)
				{
					bFlag = FALSE;
				}
			}
			else
			{
				if (*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x11) != 0x5A & \
					*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x11) != 0xAA)
				{
					bFlag = FALSE;
				}
			}
			if (!bFlag & (*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x17) != 0xF8 | \
				*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x12) > 0x0F | \
				(*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x13) | 0x41) != 0x41))
			{
				if (bVerbose)
				{
					printf("无效的头部\r\n");
				}
			}
			else
			{
				if ((*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x13) & 0x01) == 0x01 && \
					(*(BYTE*)((ULONG)pEfiDat + ulOffset + 0x12) & 0x02) == 0x02)
				{
					uCheckSum = ~(*(USHORT*)((ULONG)pEfiDat + ulOffset + 0x10) & 0xFFFF);
					if (uCheckSum != *(USHORT*)((ULONG)pEfiDat + ulLength))
					{
						if (bVerbose)
						{
							printf("尾部校验和无效\r\n");
							return bRet;
						}
					}
				}
				bRet = TRUE;
			}
		}
	}
	return bRet;
}

BOOLEAN CEFIBIOSANALYZE::GetVolumeSize(PCHAR pRomDat, ULONG ulRomSize, ULONG ulOffset, ULONG* ulVolumeSize, ULONG* ulCalcVolumeSize)
{
	BOOLEAN bRet;
	PEFI_FIRMWARE_VOLUME_HEADER pEfiFirmWareVolumeHeader;
	PEFI_FV_BLOCK_MAP_ENTRY pEfiFvBlockMapEntry;

	bRet = FALSE;
	pEfiFirmWareVolumeHeader = NULL;
	pEfiFvBlockMapEntry = NULL;
	*ulCalcVolumeSize = 0;

	if (ulRomSize < ulOffset + sizeof(EFI_FIRMWARE_VOLUME_HEADER) + 2 * sizeof(EFI_FV_BLOCK_MAP_ENTRY))
	{
		return bRet;
	}
	pEfiFirmWareVolumeHeader = (PEFI_FIRMWARE_VOLUME_HEADER)((ULONG)pRomDat + ulOffset);
	if (strnicmp((PCHAR)&pEfiFirmWareVolumeHeader->Signature,EFI_FV_SIGNATURE,strlen(EFI_FV_SIGNATURE)) != 0)
	{
		return bRet;
	}
	pEfiFvBlockMapEntry = (PEFI_FV_BLOCK_MAP_ENTRY)((ULONG)pRomDat + ulOffset + sizeof(EFI_FIRMWARE_VOLUME_HEADER));
	while (pEfiFvBlockMapEntry->NumBlocks != 0 && pEfiFvBlockMapEntry->Length != 0)
	{
		if ((ULONG)pEfiFvBlockMapEntry > ((ULONG)pRomDat + ulRomSize))
		{
			return bRet;
		}
		*ulCalcVolumeSize += pEfiFvBlockMapEntry->Length * pEfiFvBlockMapEntry->NumBlocks;
		pEfiFvBlockMapEntry = (PEFI_FV_BLOCK_MAP_ENTRY)((ULONG)pEfiFvBlockMapEntry + sizeof(EFI_FV_BLOCK_MAP_ENTRY));
	}
	*ulVolumeSize = pEfiFirmWareVolumeHeader->FvLength;
	if (*ulCalcVolumeSize)
	{
		bRet = TRUE;
	}
	return bRet;
}


BOOLEAN CEFIBIOSANALYZE::AnalyzeVolume(PCHAR pVolumeDat, ULONG ulOffset, ULONG ulVolumeSize, ULONG ulParentIndex, PREPLACE_UEFI_SECTION pUefiSection)
{
	BOOLEAN bRet;
	ULONG ulHeaderSize;
	PEFI_FIRMWARE_VOLUME_HEADER pEfiFirmWareVolumeHeader;
	PEFI_FIRMWARE_VOLUME_EXT_HEADER pEfiFirmWareVolumeExtHeader;
	PEFI_FFS_FILE_HEADER pEfiFfsFileHeader;
	BYTE bAttribute;
	BOOLEAN bIsVolumeUnknow;
	ULONG ulLocalVolumeSize;
	ULONG ulCalcVolumeSize;
	BOOLEAN bIsInvalidCheckSum;
	BOOLEAN bVolumeHasZVCRC;
	BOOLEAN bVolumeHasZVFSO;
	PCHAR pGuidName;
	ULONG ulFileOffset;
	ULONG ulFileSize;
	PCHAR pFileBody;
	ULONG ulFileDatSize;
	ULONG ulCrc32FromZeroVector;
	ULONG ulFreeSpaceOffsetFromZeroVector;
	ULONG ulCrc32CheckSum;
	CHAR ShowInfo[MAX_PATH];
	ULONG ulIndex;
	PCHAR pLocalVolumeDat;
	PREPLACE_UEFI_IMAGE pLocalUefiImage;
	PREPLACE_UEFI_FILE pUefiFile;
	PCHAR pFileGuidName;


	bRet = FALSE;
	ulHeaderSize = 0;
	pEfiFirmWareVolumeHeader = NULL;
	pEfiFirmWareVolumeExtHeader = NULL;
	bIsVolumeUnknow = TRUE;
	bAttribute = 0;
	ulCalcVolumeSize = 0;
	ulLocalVolumeSize = 0;
	bIsInvalidCheckSum = FALSE;
	pGuidName = NULL;
	pFileBody = NULL;
	ulFileSize = 0;
	pEfiFfsFileHeader = NULL;
	ulFileDatSize = 0;
	ulCrc32FromZeroVector = 0;
	ulFreeSpaceOffsetFromZeroVector = 0;
	bVolumeHasZVCRC = FALSE;
	bVolumeHasZVFSO = FALSE;
	ulCrc32CheckSum = 0;
	ulIndex = 0;
	pLocalUefiImage = NULL;
	pUefiFile = NULL;
	pFileGuidName = NULL;
	pLocalVolumeDat = (PCHAR)((ULONG)pVolumeDat + ulOffset);
	RtlZeroMemory(ShowInfo,MAX_PATH);

	if (NULL == pLocalVolumeDat || \
		ulVolumeSize < sizeof(EFI_FIRMWARE_VOLUME_HEADER))
	{
		return bRet;
	}
	pEfiFirmWareVolumeHeader = (PEFI_FIRMWARE_VOLUME_HEADER)pLocalVolumeDat;
	if (ALIGN8(pEfiFirmWareVolumeHeader->HeaderLength) > ulVolumeSize)
	{
		return bRet;
	}
	if (pEfiFirmWareVolumeHeader->ExtHeaderOffset > 0 && \
		ulVolumeSize < ALIGN8(pEfiFirmWareVolumeHeader->ExtHeaderOffset + sizeof(EFI_FIRMWARE_VOLUME_EXT_HEADER)))
	{
		return bRet;
	}
	if (pEfiFirmWareVolumeHeader->Revision > 1 && pEfiFirmWareVolumeHeader->ExtHeaderOffset)
	{
		pEfiFirmWareVolumeExtHeader = (PEFI_FIRMWARE_VOLUME_EXT_HEADER)((ULONG)pLocalVolumeDat + pEfiFirmWareVolumeHeader->ExtHeaderOffset);
		ulHeaderSize = pEfiFirmWareVolumeHeader->ExtHeaderOffset + pEfiFirmWareVolumeExtHeader->ExtHeaderSize;
	}
	else
	{
		ulHeaderSize = pEfiFirmWareVolumeHeader->HeaderLength;
	}
	ulHeaderSize = ALIGN8(ulHeaderSize);
	bAttribute = pEfiFirmWareVolumeHeader->Attributes & EFI_FVB_ERASE_POLARITY ? '\xFF' : '\x00';
	if (GetVolumeSize(pLocalVolumeDat,ulVolumeSize,0,&ulLocalVolumeSize,&ulCalcVolumeSize) == FALSE)
	{
		return bRet;
	}
	ulCrc32FromZeroVector = *(ULONG*)((ULONG)pLocalVolumeDat + 8);
	ulFreeSpaceOffsetFromZeroVector = *(ULONG*)((ULONG)pLocalVolumeDat + 12);
	if (ulCrc32FromZeroVector != 0)
	{
		ulCrc32CheckSum = g_pUtils->CheckSum32(pLocalVolumeDat,pEfiFirmWareVolumeHeader->HeaderLength,ulVolumeSize - pEfiFirmWareVolumeHeader->HeaderLength);
		if (ulCrc32CheckSum == ulCrc32FromZeroVector)
		{
			bVolumeHasZVCRC = TRUE;
		}
		if (ulFreeSpaceOffsetFromZeroVector != 0)
		{
			bVolumeHasZVFSO = TRUE;
		}
	}
	if (g_pUtils->CheckSum16((PCHAR)pEfiFirmWareVolumeHeader,0,pEfiFirmWareVolumeHeader->HeaderLength,0))
	{
		bIsInvalidCheckSum = TRUE;
	}
	pGuidName = g_pUtils->ConvertName((PCHAR)pEfiFirmWareVolumeHeader->FileSystemGuid.Data);
	StringCchPrintfA(ShowInfo,MAX_PATH,"%d %d %s Full Size:%d(%x) Header Size:%d(%x) Body Size:%d(%x) Revision:%d Attribute:%08x\n\n", \
		ulParentIndex,ulIndex,pGuidName,ulVolumeSize,ulVolumeSize,pEfiFirmWareVolumeHeader->HeaderLength,pEfiFirmWareVolumeHeader->HeaderLength, \
		ulVolumeSize - pEfiFirmWareVolumeHeader->HeaderLength,ulVolumeSize - pEfiFirmWareVolumeHeader->HeaderLength, \
		pEfiFirmWareVolumeHeader->Revision,pEfiFirmWareVolumeHeader->Attributes);
	printf(ShowInfo);
	if (pEfiFirmWareVolumeHeader->Revision > 1 && pEfiFirmWareVolumeHeader->ExtHeaderOffset)
	{
		pEfiFirmWareVolumeExtHeader = (PEFI_FIRMWARE_VOLUME_EXT_HEADER)((ULONG)pLocalVolumeDat + pEfiFirmWareVolumeHeader->ExtHeaderOffset);
	}
	pFileBody = (PCHAR)((ULONG)pLocalVolumeDat + pEfiFirmWareVolumeHeader->HeaderLength);
	ulFileOffset = ulHeaderSize;

	while (ulFileOffset < ulVolumeSize)
	{
		if (ulVolumeSize - ulFileOffset < sizeof(EFI_FFS_FILE_HEADER))
		{
			break;
		}
		if (ulFileOffset != ulVolumeSize)
		{
			while (*(BYTE*)((ULONG)pLocalVolumeDat + ulFileOffset) == 0xFF)
			{
				ulFileOffset++;
			}
		}
		ulFileSize = GetFileSize(pLocalVolumeDat,ulVolumeSize,ulFileOffset);
		if (ulFileSize <= 0 || ulFileSize > ulVolumeSize)
		{
			return bRet;
		}
		if (ulFileSize < sizeof(EFI_FFS_FILE_HEADER))
		{
			return bRet;
		}
		pFileBody = (PCHAR)((ULONG)pLocalVolumeDat + ulFileOffset);
		//ulFileDatSize = ulVolumeSize - ulFileOffset;
		pEfiFfsFileHeader = (PEFI_FFS_FILE_HEADER)pFileBody;
		pFileGuidName = g_pUtils->ConvertName((PCHAR)pEfiFfsFileHeader->Name.Data);
		printf("%s\n",pFileGuidName);
		//AnalyzeFile(pFileBody,ulFileSize,bAttribute == '\xFF' ? ERASE_POLARITY_TRUE : ERASE_POLARITY_FALSE,ulParentIndex,ulIndex,0,ulOffset + ulFileOffset,NULL);
		ulFileOffset += ulFileSize;
		ulFileOffset = ALIGN8(ulFileOffset);
		ulIndex++;
	}
	return TRUE;
}

BOOLEAN CEFIBIOSANALYZE::AnalyzeVolume2(PCHAR pVolumeDat, ULONG ulVolumeSize, BOOLEAN bIsReplace)
{
	BOOLEAN bRet;
	ULONG ulHeaderSize;
	PEFI_FIRMWARE_VOLUME_HEADER pEfiFirmWareVolumeHeader;
	PEFI_FIRMWARE_VOLUME_EXT_HEADER pEfiFirmWareVolumeExtHeader;
	PEFI_FFS_FILE_HEADER pEfiFfsFileHeader;
	PEFI_COMPRESSION_SECTION pCompressionSection;
	BYTE bAttribute;
	BOOLEAN bIsVolumeUnknow;
	ULONG ulLocalVolumeSize;
	ULONG ulCalcVolumeSize;
	BOOLEAN bIsInvalidCheckSum;
	BOOLEAN bVolumeHasZVCRC;
	BOOLEAN bVolumeHasZVFSO;
	PCHAR pGuidName,pFfsGuidName;
	ULONG ulFileOffset;
	ULONG ulFileSize;
	ULONG ulGenSize;
	ULONG ulGenOffset;
	PCHAR pFileBody;
	ULONG ulFileDatSize;
	ULONG ulCrc32FromZeroVector;
	ULONG ulFreeSpaceOffsetFromZeroVector;
	ULONG ulCrc32CheckSum;
	CHAR ShowInfo[MAX_PATH];
	ULONG ulIndex;
	PCHAR pLocalVolumeDat;
	ULONG ulDatCheckSum;
	ULONG ulHeaderCheckSum;
	ULONG ulBufferSize;
	ULONG ulFillOffset;
	BOOLEAN bIsEndOfBlock;
	ULONG ulAlignment;
	ULONG ulAlignmentPower;


	bRet = FALSE;
	ulHeaderSize = 0;
	pEfiFirmWareVolumeHeader = NULL;
	pEfiFirmWareVolumeExtHeader = NULL;
	bIsVolumeUnknow = TRUE;
	bAttribute = 0;
	ulCalcVolumeSize = 0;
	ulLocalVolumeSize = 0;
	bIsInvalidCheckSum = FALSE;
	pGuidName = NULL;
	pFileBody = NULL;
	ulFileSize = 0;
	pEfiFfsFileHeader = NULL;
	ulFileDatSize = 0;
	ulCrc32FromZeroVector = 0;
	ulFreeSpaceOffsetFromZeroVector = 0;
	bVolumeHasZVCRC = FALSE;
	bVolumeHasZVFSO = FALSE;
	ulCrc32CheckSum = 0;
	ulIndex = 0;
	ulDatCheckSum = 0;
	ulHeaderCheckSum = 0;
	ulBufferSize = 0;
	pLocalVolumeDat = pVolumeDat;
	pFfsGuidName = NULL;
	pCompressionSection = NULL;
	ulGenSize = 0;
	ulGenOffset = 0;
	ulFillOffset = 0;
	bIsEndOfBlock = FALSE;
	ulAlignment = 0;
	ulAlignmentPower = 0;
	
	RtlZeroMemory(ShowInfo,MAX_PATH);

	if (NULL == pLocalVolumeDat || \
		ulVolumeSize < sizeof(EFI_FIRMWARE_VOLUME_HEADER))
	{
		return bRet;
	}
	pEfiFirmWareVolumeHeader = (PEFI_FIRMWARE_VOLUME_HEADER)pLocalVolumeDat;
	if (ALIGN8(pEfiFirmWareVolumeHeader->HeaderLength) > ulVolumeSize)
	{
		return bRet;
	}
	if (pEfiFirmWareVolumeHeader->ExtHeaderOffset > 0 && \
		ulVolumeSize < ALIGN8(pEfiFirmWareVolumeHeader->ExtHeaderOffset + sizeof(EFI_FIRMWARE_VOLUME_EXT_HEADER)))
	{
		return bRet;
	}
	if (pEfiFirmWareVolumeHeader->Revision > 1 && pEfiFirmWareVolumeHeader->ExtHeaderOffset)
	{
		pEfiFirmWareVolumeExtHeader = (PEFI_FIRMWARE_VOLUME_EXT_HEADER)((ULONG)pLocalVolumeDat + pEfiFirmWareVolumeHeader->ExtHeaderOffset);
		ulHeaderSize = pEfiFirmWareVolumeHeader->ExtHeaderOffset + pEfiFirmWareVolumeExtHeader->ExtHeaderSize;
	}
	else
	{
		ulHeaderSize = pEfiFirmWareVolumeHeader->HeaderLength;
	}
	ulHeaderSize = ALIGN8(ulHeaderSize);
	bAttribute = pEfiFirmWareVolumeHeader->Attributes & EFI_FVB_ERASE_POLARITY ? '\xFF' : '\x00';
	if (GetVolumeSize(pLocalVolumeDat,ulVolumeSize,0,&ulLocalVolumeSize,&ulCalcVolumeSize) == FALSE)
	{
		return bRet;
	}
	ulCrc32FromZeroVector = *(ULONG*)((ULONG)pLocalVolumeDat + 8);
	ulFreeSpaceOffsetFromZeroVector = *(ULONG*)((ULONG)pLocalVolumeDat + 12);
	if (ulCrc32FromZeroVector != 0)
	{
		ulCrc32CheckSum = g_pUtils->CheckSum32(pLocalVolumeDat,pEfiFirmWareVolumeHeader->HeaderLength,ulVolumeSize - pEfiFirmWareVolumeHeader->HeaderLength);
		if (ulCrc32CheckSum == ulCrc32FromZeroVector)
		{
			bVolumeHasZVCRC = TRUE;
		}
		if (ulFreeSpaceOffsetFromZeroVector != 0)
		{
			bVolumeHasZVFSO = TRUE;
		}
	}
	if (g_pUtils->CheckSum16((PCHAR)pEfiFirmWareVolumeHeader,0,pEfiFirmWareVolumeHeader->HeaderLength,0))
	{
		bIsInvalidCheckSum = TRUE;
	}
	pGuidName = g_pUtils->ConvertName((PCHAR)pEfiFirmWareVolumeHeader->FileSystemGuid.Data);
	StringCchPrintfA(ShowInfo,MAX_PATH,"%d %s Full Size:%d(%x) Header Size:%d(%x) Body Size:%d(%x) Revision:%d Attribute:%08x\n\n", \
		ulIndex,pGuidName,ulVolumeSize,ulVolumeSize,pEfiFirmWareVolumeHeader->HeaderLength,pEfiFirmWareVolumeHeader->HeaderLength, \
		ulVolumeSize - pEfiFirmWareVolumeHeader->HeaderLength,ulVolumeSize - pEfiFirmWareVolumeHeader->HeaderLength, \
		pEfiFirmWareVolumeHeader->Revision,pEfiFirmWareVolumeHeader->Attributes);
	printf(ShowInfo);

	if (bIsReplace)
	{
		pReplaceBigBlock = NULL;
		ulReplaceBigBlockSize = 0;
		pEfiFvBlockMapEntry = (PEFI_FV_BLOCK_MAP_ENTRY)((ULONG)pVolumeDat + sizeof(EFI_FIRMWARE_VOLUME_HEADER));
		ulFvBlockSize = sizeof(EFI_FV_BLOCK_MAP_ENTRY);
		while (pEfiFvBlockMapEntry->Length != 0 && pEfiFvBlockMapEntry->NumBlocks != 0)
		{
			ulFvBlockSize += sizeof(EFI_FV_BLOCK_MAP_ENTRY);
			pEfiFvBlockMapEntry = (PEFI_FV_BLOCK_MAP_ENTRY)((ULONG)pEfiFvBlockMapEntry + sizeof(EFI_FV_BLOCK_MAP_ENTRY));
		}
		do 
		{
			pReplaceBigBlock = ::VirtualAlloc(NULL,ulVolumeSize,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
		} while (NULL == pReplaceBigBlock);
		RtlZeroMemory(pReplaceBigBlock,ulVolumeSize);

		ulReplaceBigBlockPos = sizeof(EFI_FIRMWARE_VOLUME_HEADER);
		RtlCopyMemory((PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos),(PCHAR)((ULONG)pVolumeDat + ulReplaceBigBlockPos),ulFvBlockSize);

		ulReplaceBigBlockPos += ulFvBlockSize;
	}
	//pGenEfiFirmWareVolumeHeader = GenerateVolumeHeader(&pEfiFirmWareVolumeHeader->FileSystemGuid,)
	if (pEfiFirmWareVolumeHeader->Revision > 1 && pEfiFirmWareVolumeHeader->ExtHeaderOffset)
	{
		pEfiFirmWareVolumeExtHeader = (PEFI_FIRMWARE_VOLUME_EXT_HEADER)((ULONG)pLocalVolumeDat + pEfiFirmWareVolumeHeader->ExtHeaderOffset);
	}
	pFileBody = (PCHAR)((ULONG)pLocalVolumeDat + pEfiFirmWareVolumeHeader->HeaderLength);
	ulFileOffset = ulHeaderSize;

	while (ulFileOffset < ulVolumeSize)
	{
		if (ulVolumeSize - ulFileOffset < sizeof(EFI_FFS_FILE_HEADER))
		{
			break;
		}
		if (ulFileOffset != ulVolumeSize)
		{
			while (*(BYTE*)((ULONG)pLocalVolumeDat + ulFileOffset) == 0xFF)
			{
				ulFileOffset++;
			}
		}
		if (ulVolumeSize - ulFileOffset < sizeof(EFI_FFS_FILE_HEADER))
		{
			while (ulReplaceBigBlockPos < ulFileOffset)
			{
				*(PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos) = 0xFF;
				ulReplaceBigBlockPos++;
			}
			break;
		}
		ulFileSize = GetFileSize(pLocalVolumeDat,ulVolumeSize,ulFileOffset);
		if (ulFileSize <= 0 || ulFileSize > ulVolumeSize)
		{
			return bRet;
		}
		if (ulFileSize < sizeof(EFI_FFS_FILE_HEADER))
		{
			return bRet;
		}
		pFileBody = (PCHAR)((ULONG)pLocalVolumeDat + ulFileOffset);
		//ulFileDatSize = ulVolumeSize - ulFileOffset;
		pEfiFfsFileHeader = (PEFI_FFS_FILE_HEADER)pFileBody;
		pCompressionSection = (PEFI_COMPRESSION_SECTION)((ULONG)pEfiFfsFileHeader + sizeof(EFI_FFS_FILE_HEADER));
		pFfsGuidName = g_pUtils->ConvertName((PCHAR)pEfiFfsFileHeader->Name.Data);
		AnalyzeFile2(pFileBody,ulFileSize,bIsReplace);

		if (bIsReplace)
		{
			if (NULL != pReplaceSubModule && ulReplaceSubPos != 0 && \
				strnicmp(pGuidName,"7A9354D9-0468-444A-81CE-0BF617D890DF",sizeof(EFI_GUID)) == 0 && \
				strnicmp(pFfsGuidName,"AE717C2F-1A42-4F2B-8861-78B79CA07E07",sizeof(EFI_GUID)) == 0)
			{
				pGenBigBlockFfsFileHeader = GenerateFfsFileHeader(&pEfiFfsFileHeader->Name, \
					g_pUtils->ULONG32ToULONG24(ulCompressionReplaceSubModuleSize + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMPRESSION_SECTION)),
					//(PCHAR)pEfiFfsFileHeader->Size,
					pEfiFfsFileHeader->Type,pEfiFfsFileHeader->Attributes,pEfiFfsFileHeader->State);
				RtlCopyMemory((PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos),pGenBigBlockFfsFileHeader,sizeof(EFI_FFS_FILE_HEADER));
				RtlCopyMemory((PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos + sizeof(EFI_FFS_FILE_HEADER)),pGenEfiCompressionSection,sizeof(EFI_COMPRESSION_SECTION));
				RtlCopyMemory((PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMPRESSION_SECTION)), \
					pCompressionReplaceSubModule,ulCompressionReplaceSubModuleSize);
				if (sizeof(EFI_COMPRESSION_SECTION) + ulCompressionReplaceSubModuleSize < ulFileSize)
				{
					//for (ULONG uli = sizeof(EFI_COMPRESSION_SECTION) + ulCompressionReplaceSubModuleSize;uli < ulFileSize;uli++)
					//{
					//	*(PCHAR)((ULONG)pReplaceBigBlock + uli) = 0xFF;
					//}
					ulGenSize = ulCompressionReplaceSubModuleSize + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMPRESSION_SECTION);
				}
				if (pEfiFfsFileHeader->Attributes & FFS_ATTRIB_CHECKSUM)
				{
					ulBufferSize = ulCompressionReplaceSubModuleSize + sizeof(EFI_COMPRESSION_SECTION);
					//ulBufferSize = g_pUtils->ULONG24ToULONG32((PCHAR)pCompressionSection->Size);
					if (pGenBigBlockFfsFileHeader->Attributes & FFS_ATTRIB_TAIL_PRESENT)
					{
						ulBufferSize -= sizeof(UINT16);
					}
					ulDatCheckSum = g_pUtils->CheckSum8((PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos + sizeof(EFI_FFS_FILE_HEADER)),0,ulBufferSize,0);
					if (pGenBigBlockFfsFileHeader->IntegrityCheck.Checksum.File != ulDatCheckSum)
					{
						//pGenBigBlockFfsFileHeader->IntegrityCheck.Checksum.File = ulDatCheckSum;
						//RtlCopyMemory((PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos),pGenBigBlockFfsFileHeader,sizeof(EFI_FFS_FILE_HEADER));
						ulDatCheckSum = g_pUtils->CheckSum8((PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos + sizeof(EFI_FFS_FILE_HEADER)),0,ulBufferSize,0);
						//if (g_pUtils->CheckSum8((PCHAR)((ULONG)pReplaceBigBlock + ulFileOffset + sizeof(EFI_FFS_FILE_HEADER)),0,ulBufferSize,0))
						//{
						//	pGenBigBlockFfsFileHeader->IntegrityCheck.Checksum.File = ulCheckSum;
						//}
					}
				}
				ulHeaderCheckSum = g_pUtils->CheckSum8((PCHAR)pGenBigBlockFfsFileHeader,0,sizeof(EFI_FFS_FILE_HEADER) - 1,0);
				if (ulHeaderCheckSum != pGenBigBlockFfsFileHeader->IntegrityCheck.Checksum.Header)
				{
					pGenBigBlockFfsFileHeader->IntegrityCheck.Checksum.File = 0;
					if (g_pUtils->CheckSum8((PCHAR)pGenBigBlockFfsFileHeader,0,sizeof(EFI_FFS_FILE_HEADER) - 1,0) != 0)
					{
						pGenBigBlockFfsFileHeader->IntegrityCheck.Checksum.Header = ulHeaderCheckSum;
						pGenBigBlockFfsFileHeader->IntegrityCheck.Checksum.File = ulDatCheckSum;
					}
				}
				RtlCopyMemory((PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos),pGenBigBlockFfsFileHeader,sizeof(EFI_FFS_FILE_HEADER));
				//ulFileSize = sizeof(EFI_FFS_FILE_HEADER)  + sizeof(EFI_COMPRESSION_SECTION) + ulCompressionReplaceSubModuleSize;
			}
			else
			{
				RtlCopyMemory((PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos),(PCHAR)((ULONG)pVolumeDat + ulFileOffset),ulFileSize);
			}
		}
		ulFileOffset += ulFileSize;
		ulFillOffset = ulFileOffset;
		ulFileOffset = ALIGN8(ulFileOffset);
		if (ulFileOffset < ulVolumeSize)
		{
			printf("FileOffset:%x FileSize:%x\n",ulFileOffset,ulFileSize);
		}
		if (ulFileOffset == 0x2ff3a0)
		{
			printf("Finder\n");
		}
		if (ulGenSize)
		{
			ulReplaceBigBlockPos += ulGenSize;
			ulFillOffset = ulReplaceBigBlockPos;
			ulReplaceBigBlockPos = ALIGN8(ulReplaceBigBlockPos);
			while (ulFillOffset < ulReplaceBigBlockPos)
			{
				*(PCHAR)((ULONG)pReplaceBigBlock + ulFillOffset) = 0xFF;
				ulFillOffset++;
			}
			//while (ulReplaceBigBlockPos < ulFileOffset)
			//{
			//	*(PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos) = 0xFF;
			//	ulReplaceBigBlockPos++;
			//}
			ulGenSize = 0;
		}
		else
		{
			ulReplaceBigBlockPos += ulFileSize;
			ulFillOffset = ulReplaceBigBlockPos;
			ulReplaceBigBlockPos = ALIGN8(ulReplaceBigBlockPos);
			while (ulFillOffset < ulReplaceBigBlockPos)
			{
				*(PCHAR)((ULONG)pReplaceBigBlock + ulFillOffset) = 0xFF;
				ulFillOffset++;
			}
		}
		ulAlignmentPower = bFfsAlignmentTable[(pEfiFfsFileHeader->Attributes & FFS_ATTRIB_DATA_ALIGNMENT) >> 3];
		ulAlignment = pow(2.0,(int)ulAlignmentPower);
		printf("AlignmentPower: %x Alignment: %x",ulAlignmentPower,ulAlignment);

		//if ((ulReplaceBigBlockPos + sizeof(EFI_FFS_FILE_HEADER)) % ulAlignment)
		//{
		//	msgUnalignedFile = true;
		//}
		//if (ulAlignment > 1)
		//{
		//	printf("> 1\n");
		//}
		//while (ulReplaceBigBlockPos % ulAlignment)
		//{
		//	*(PCHAR)((ULONG)pReplaceBigBlock + ulReplaceBigBlockPos) = 0xFF;
		//	ulReplaceBigBlockPos++;
		//}
		ulIndex++;
	}
	if (NULL != pReplaceSubModule && ulReplaceSubPos != 0 && bIsReplace == TRUE)
	{
		pGenEfiFirmWareVolumeHeader = GenerateVolumeHeader(&pEfiFirmWareVolumeHeader->FileSystemGuid, \
			pEfiFirmWareVolumeHeader->FvLength,
			//ulReplaceSubPos - 0x04,
			pEfiFirmWareVolumeHeader->Attributes, \
			pEfiFirmWareVolumeHeader->HeaderLength, \
			0, \
			pEfiFirmWareVolumeHeader->ExtHeaderOffset, \
			pEfiFirmWareVolumeHeader->Revision);
		RtlCopyMemory(pReplaceBigBlock,pGenEfiFirmWareVolumeHeader,sizeof(EFI_FIRMWARE_VOLUME_HEADER));

		pGenEfiFirmWareVolumeHeader->Checksum = g_pUtils->CheckSum16((PCHAR)pReplaceBigBlock,0,pGenEfiFirmWareVolumeHeader->HeaderLength,0);
		if (g_pUtils->CheckSum16((PCHAR)pReplaceBigBlock,0,pGenEfiFirmWareVolumeHeader->HeaderLength,0) != 0)
		{
			//pEfiFirmWareVolumeHeader->Checksum = g_pUtils->CheckSum16((PCHAR)pGenEfiFirmWareVolumeHeader,0,pGenEfiFirmWareVolumeHeader->HeaderLength,0);
			((PEFI_FIRMWARE_VOLUME_HEADER)pReplaceBigBlock)->Checksum = pGenEfiFirmWareVolumeHeader->Checksum;
		}
		WriteModule("7A9354D9-0468-444A-81CE-0BF617D890DF_All.Bin",pReplaceBigBlock,ulVolumeSize);
		
	}
	return TRUE;
}

ULONG CEFIBIOSANALYZE::GetFileSize(PCHAR pVolumeDat, ULONG ulVolumeSize, ULONG ulOffset)
{
	PEFI_FFS_FILE_HEADER pEfiFfsFileHeader;

	pEfiFfsFileHeader = NULL;

	if (NULL == pVolumeDat || ulVolumeSize < sizeof(EFI_FFS_FILE_HEADER))
	{
		return 0;
	}
	pEfiFfsFileHeader = (PEFI_FFS_FILE_HEADER)((ULONG)pVolumeDat + ulOffset);
	return (*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF);
}


BOOLEAN CEFIBIOSANALYZE::AnalyzeFile(PCHAR pFileDat, ULONG ulFileSize, BOOLEAN bErasePolarity, ULONG ulParentIndex, \
									 ULONG ulIndex,BOOLEAN bMode,ULONG ulBaseOffset,PREPLACE_UEFI_FILE pUefiFile)
{
	BOOLEAN bRet;
	EFI_FFS_FILE_HEADER CalcCheckSumEfiFfsHeader;
	PEFI_FFS_FILE_HEADER pEfiFfsFileHeader;
	BYTE bAttribute;
	ULONG ulCheckSum;
	BOOLEAN bIsInvalidHeaderChecksum;
	BOOLEAN bIsInvalidDataChecksum;
	BOOLEAN bIsInvalidTailValue;
	BOOLEAN bIsMsgInvalidType;
	BOOLEAN bIsParseCurrentFile;
	BOOLEAN bIsParseAsBios;
	ULONG ulBufferSize;
	PCHAR pFileBody;
	PCHAR pGuidName;
	USHORT uTailValue;
	ULONG ulSectionOffset;
	ULONG ulSectionSize;
	ULONG ulBodySize;
	CHAR ShowInfo[MAX_PATH];
	PREPLACE_UEFI_SECTION pUefiSection;

	bRet = FALSE;
	pEfiFfsFileHeader = NULL;
	ulCheckSum = 0;
	bIsInvalidHeaderChecksum = FALSE;
	bIsInvalidDataChecksum = FALSE;
	bIsInvalidTailValue = FALSE;
	ulBufferSize = 0;
	pFileBody = NULL;
	uTailValue = 0;
	bIsParseCurrentFile = TRUE;
	bIsParseAsBios = FALSE;
	bIsMsgInvalidType = FALSE;
	pGuidName = NULL;
	pUefiSection = NULL;

	RtlZeroMemory(&CalcCheckSumEfiFfsHeader,sizeof(EFI_FFS_FILE_HEADER));
	RtlZeroMemory(ShowInfo,MAX_PATH);

	if (NULL == pFileDat || ulFileSize <= 0)
	{
		return FALSE;
	}
	pEfiFfsFileHeader = (PEFI_FFS_FILE_HEADER)pFileDat;
	bAttribute = bErasePolarity ? '\xFF' : '\x00';
	RtlCopyMemory(&CalcCheckSumEfiFfsHeader,pFileDat,sizeof(EFI_FFS_FILE_HEADER));
	CalcCheckSumEfiFfsHeader.IntegrityCheck.Checksum.File = 0;
	CalcCheckSumEfiFfsHeader.IntegrityCheck.Checksum.Header = 0;

	ulCheckSum = g_pUtils->CheckSum8((PCHAR)&CalcCheckSumEfiFfsHeader,0,sizeof(EFI_FFS_FILE_HEADER),0);
	if (ulCheckSum != pEfiFfsFileHeader->IntegrityCheck.Checksum.Header)
	{
		bIsInvalidHeaderChecksum = TRUE;
	}

	if (pEfiFfsFileHeader->Attributes & FFS_ATTRIB_CHECKSUM)
	{
		ulBufferSize = ulFileSize - sizeof(EFI_FFS_FILE_HEADER);
		if (pEfiFfsFileHeader->Attributes & FFS_ATTRIB_TAIL_PRESENT)
		{
			ulBufferSize -= sizeof(UINT16);
		}
		ulCheckSum = g_pUtils->CheckSum8((PCHAR)((ULONG)pFileDat + sizeof(EFI_FFS_FILE_HEADER)),0,ulBufferSize,0);
		if (pEfiFfsFileHeader->IntegrityCheck.Checksum.File != ulCheckSum)
		{
			bIsInvalidDataChecksum = TRUE;
		}
	}
	else if (pEfiFfsFileHeader->IntegrityCheck.Checksum.File != FFS_FIXED_CHECKSUM && \
		pEfiFfsFileHeader->IntegrityCheck.Checksum.File != FFS_FIXED_CHECKSUM2)
	{
		bIsInvalidDataChecksum = TRUE;
	}
	pFileBody = (PCHAR)((ULONG)pFileDat + /*ulFileSize - */sizeof(EFI_FFS_FILE_HEADER));
	if (pEfiFfsFileHeader->Attributes & FFS_ATTRIB_TAIL_PRESENT)
	{
		uTailValue = *(USHORT*)((ULONG)pFileDat + sizeof(EFI_FFS_FILE_HEADER) + (*(ULONG*)((ULONG)pEfiFfsFileHeader->Size) & 0x00FFFFFF) - sizeof(USHORT));
		//uTailValue = *(USHORT*)((ULONG)pFileBody - sizeof(USHORT));
		if (pEfiFfsFileHeader->IntegrityCheck.TailReference != (USHORT)~uTailValue)
		{
			bIsInvalidTailValue = TRUE;
		}
	}
	switch (pEfiFfsFileHeader->Type)
	{
	case EFI_FV_FILETYPE_ALL:
		bIsParseAsBios = TRUE;
		break;
	case EFI_FV_FILETYPE_RAW:
		bIsParseAsBios = TRUE;
		break;
	case EFI_FV_FILETYPE_FREEFORM:
		break;
	case EFI_FV_FILETYPE_SECURITY_CORE:
		break;
	case EFI_FV_FILETYPE_PEI_CORE:
		break;
	case EFI_FV_FILETYPE_DXE_CORE:
		break;
	case EFI_FV_FILETYPE_PEIM:
		break;
	case EFI_FV_FILETYPE_DRIVER:
		break;
	case EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER:
		break;
	case EFI_FV_FILETYPE_APPLICATION:
		break;
	case EFI_FV_FILETYPE_SMM:
		break;
	case EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE:
		break;
	case EFI_FV_FILETYPE_COMBINED_SMM_DXE:
		break;
	case EFI_FV_FILETYPE_SMM_CORE:
		break;
	case EFI_FV_FILETYPE_PAD:
		break;
	default:
		bIsMsgInvalidType = TRUE;
		bIsParseCurrentFile = FALSE;
	}
	pGuidName = g_pUtils->ConvertName((PCHAR)pEfiFfsFileHeader->Name.Data);
	StringCchPrintfA(ShowInfo,MAX_PATH,"%x %x %s Type:%d Attribute:%d FullSize: %d(%x) HeaderSize:%d(%x) BodySize: %d(%x) State:%d\n\n", \
		ulParentIndex,ulIndex,pGuidName,pEfiFfsFileHeader->Type,pEfiFfsFileHeader->Attributes, \
		*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF, \
		sizeof(EFI_FFS_FILE_HEADER),sizeof(EFI_FFS_FILE_HEADER), \
		(*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF) - sizeof(EFI_FFS_FILE_HEADER),(*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF) - sizeof(EFI_FFS_FILE_HEADER), \
		pEfiFfsFileHeader->State);
	printf(ShowInfo);
	if (ulIndex == 0x29)
	{
		printf("\n");
	}
	if (bIsParseAsBios)
	{
		bRet = g_pDellAnalyze->AnalyzeBIOS(pFileBody,*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF,NULL);
		if (FALSE == bRet)
		{
			printf("\n");
			return bRet;
		}
		else
		{
			return bRet;
		}
	}
	else
	{
		ulSectionOffset = 0;
		ulSectionSize = 0;
		ulBodySize = (*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF) - sizeof(EFI_FFS_FILE_HEADER);

		while (TRUE)
		{
			ulSectionSize = GetSectionSize(pFileBody,ulBodySize - ulSectionOffset,ulSectionOffset);
			if (ulSectionSize == -1)
			{
				return bRet;
			}
			if (ulSectionSize == 0)
			{
				break;
			}
			bRet = AnalyzeSection((PCHAR)((ULONG)pFileBody + ulSectionOffset),ulSectionSize,ulParentIndex,ulIndex,pGuidName);
			if (bRet == FALSE)
			{
				return bRet;
			}
		}
	}
	return TRUE;
}

BOOLEAN CEFIBIOSANALYZE::AnalyzeFile2(PCHAR pFileDat, ULONG ulFileSize,BOOLEAN bIsReplace)
{
	BOOLEAN bRet;
	ULONG ulRet;
	EFI_FFS_FILE_HEADER CalcCheckSumEfiFfsHeader;
	PEFI_FFS_FILE_HEADER pEfiFfsFileHeader;
	PREPLACE_UEFI_SECTION pUefiSection;
	PEFI_COMMON_SECTION_HEADER pEfiCommonSectionHeader;
	PEFI_COMMON_SECTION_HEADER pFindEfiCommonSectionHeader;
	PEFI_COMPRESSION_SECTION pEfiCompressedSectionHeader;
	PEFI_COMPRESSION_SECTION pGenCompressionHeader;
	ULONG ulCheckSum;
	BOOLEAN bIsInvalidHeaderChecksum;
	BOOLEAN bIsInvalidDataChecksum;
	BOOLEAN bIsInvalidTailValue;
	BOOLEAN bIsMsgInvalidType;
	BOOLEAN bIsParseCurrentFile;
	BOOLEAN bIsParseAsBios;
	ULONG ulBufferSize;
	PCHAR pFileBody;
	PCHAR pGuidName;
	USHORT uTailValue;
	ULONG ulSectionOffset;
	ULONG ulSectionSize;
	ULONG ulBodySize;
	CHAR ShowInfo[MAX_PATH];
	PCHAR pSectionTypeDesc;
	PCHAR pDeCompressed;
	PCHAR pBody;
	BYTE bAlgorithm;
	ULONG ulOutDeCompressedDatSize;
	ULONG ulCrc32;
	BOOLEAN bIsParseCurrentSection;

	bRet = FALSE;
	bIsParseCurrentSection = FALSE;
	pEfiCommonSectionHeader = NULL;
	pSectionTypeDesc = NULL;
	pDeCompressed = NULL;
	pBody = NULL;
	ulOutDeCompressedDatSize = 0;
	pEfiFfsFileHeader = NULL;
	ulCheckSum = 0;
	bIsInvalidHeaderChecksum = FALSE;
	bIsInvalidDataChecksum = FALSE;
	bIsInvalidTailValue = FALSE;
	ulBufferSize = 0;
	pFileBody = NULL;
	uTailValue = 0;
	bIsParseCurrentFile = TRUE;
	bIsParseAsBios = FALSE;
	bIsMsgInvalidType = FALSE;
	pGuidName = NULL;
	pUefiSection = NULL;
	pFindEfiCommonSectionHeader = NULL;
	pCompressionReplaceSubModule = NULL;
	ulCompressionReplaceSubModuleSize = 0;
	pGenCompressionHeader = NULL;
	ulRet = 0;

	RtlZeroMemory(&CalcCheckSumEfiFfsHeader,sizeof(EFI_FFS_FILE_HEADER));
	RtlZeroMemory(ShowInfo,MAX_PATH);

	if (NULL == pFileDat || ulFileSize <= 0)
	{
		return FALSE;
	}
	pEfiFfsFileHeader = (PEFI_FFS_FILE_HEADER)pFileDat;
	RtlCopyMemory(&CalcCheckSumEfiFfsHeader,pFileDat,sizeof(EFI_FFS_FILE_HEADER));
	CalcCheckSumEfiFfsHeader.IntegrityCheck.Checksum.File = 0;
	CalcCheckSumEfiFfsHeader.IntegrityCheck.Checksum.Header = 0;

	ulCheckSum = g_pUtils->CheckSum8((PCHAR)&CalcCheckSumEfiFfsHeader,0,sizeof(EFI_FFS_FILE_HEADER) - 1,0);
	if (ulCheckSum != pEfiFfsFileHeader->IntegrityCheck.Checksum.Header)
	{
		bIsInvalidHeaderChecksum = TRUE;
	}

	if (pEfiFfsFileHeader->Attributes & FFS_ATTRIB_CHECKSUM)
	{
		ulBufferSize = ulFileSize - sizeof(EFI_FFS_FILE_HEADER);
		if (pEfiFfsFileHeader->Attributes & FFS_ATTRIB_TAIL_PRESENT)
		{
			ulBufferSize -= sizeof(UINT16);
		}
		ulCheckSum = g_pUtils->CheckSum8((PCHAR)((ULONG)pFileDat + sizeof(EFI_FFS_FILE_HEADER)),0,ulBufferSize,0);
		if (pEfiFfsFileHeader->IntegrityCheck.Checksum.File != ulCheckSum)
		{
			bIsInvalidDataChecksum = TRUE;
		}
	}
	else if (pEfiFfsFileHeader->IntegrityCheck.Checksum.File != FFS_FIXED_CHECKSUM && \
		pEfiFfsFileHeader->IntegrityCheck.Checksum.File != FFS_FIXED_CHECKSUM2)
	{
		bIsInvalidDataChecksum = TRUE;
	}
	if (pEfiFfsFileHeader->Attributes & FFS_ATTRIB_TAIL_PRESENT)
	{
		uTailValue = *(USHORT*)((ULONG)pFileDat + sizeof(EFI_FFS_FILE_HEADER) + (*(ULONG*)((ULONG)pEfiFfsFileHeader->Size) & 0x00FFFFFF) - sizeof(USHORT));
		if (pEfiFfsFileHeader->IntegrityCheck.TailReference != (USHORT)~uTailValue)
		{
			bIsInvalidTailValue = TRUE;
		}
	}
	switch (pEfiFfsFileHeader->Type)
	{
	case EFI_FV_FILETYPE_ALL:
		bIsParseAsBios = TRUE;
		break;
	case EFI_FV_FILETYPE_RAW:
		bIsParseAsBios = TRUE;
		break;
	case EFI_FV_FILETYPE_FREEFORM:
		break;
	case EFI_FV_FILETYPE_SECURITY_CORE:
		break;
	case EFI_FV_FILETYPE_PEI_CORE:
		break;
	case EFI_FV_FILETYPE_DXE_CORE:
		break;
	case EFI_FV_FILETYPE_PEIM:
		break;
	case EFI_FV_FILETYPE_DRIVER:
		break;
	case EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER:
		break;
	case EFI_FV_FILETYPE_APPLICATION:
		break;
	case EFI_FV_FILETYPE_SMM:
		break;
	case EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE:
		break;
	case EFI_FV_FILETYPE_COMBINED_SMM_DXE:
		break;
	case EFI_FV_FILETYPE_SMM_CORE:
		break;
	case EFI_FV_FILETYPE_PAD:
		break;
	default:
		bIsMsgInvalidType = TRUE;
		bIsParseCurrentFile = FALSE;
	}
	pGuidName = g_pUtils->ConvertName((PCHAR)pEfiFfsFileHeader->Name.Data);
	StringCchPrintfA(ShowInfo,MAX_PATH," %s Type:%d Attribute:%d FullSize: %d(%x) HeaderSize:%d(%x) BodySize: %d(%x) State:%d\n\n", \
		pGuidName,pEfiFfsFileHeader->Type,pEfiFfsFileHeader->Attributes, \
		*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF, \
		sizeof(EFI_FFS_FILE_HEADER),sizeof(EFI_FFS_FILE_HEADER), \
		(*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF) - sizeof(EFI_FFS_FILE_HEADER),(*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF) - sizeof(EFI_FFS_FILE_HEADER), \
		pEfiFfsFileHeader->State);
	printf(ShowInfo);
	if (bIsParseAsBios)
	{
		pFileBody = (PCHAR)((ULONG)pFileDat + /*ulFileSize - */sizeof(EFI_FFS_FILE_HEADER));
		bRet = g_pDellAnalyze->AnalyzeBIOS(pFileBody,*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF,NULL);
		if (FALSE == bRet)
		{
			printf("\n");
			return bRet;
		}
		else
		{
			return bRet;
		}
	}
	else
	{
		ulSectionOffset = 0;
		ulSectionSize = 0;
		pFileBody = (PCHAR)((ULONG)pFileDat + /*ulFileSize - */sizeof(EFI_FFS_FILE_HEADER));
		ulBodySize = (*(ULONG*)pEfiFfsFileHeader->Size & 0x00FFFFFF) - sizeof(EFI_FFS_FILE_HEADER);
		if (bIsReplace)
		{
			if (strnicmp(pGuidName,"AE717C2F-1A42-4F2B-8861-78B79CA07E07",sizeof(EFI_GUID)) == 0)
			{
				printf("Replace File Guid %s\n",pGuidName);
				WriteModule("AE717C2F-1A42-4F2B-8861-78B79CA07E07_Efi_Ffs_File.Bin",pFileDat,ulFileSize);
				WriteModule("AE717C2F-1A42-4F2B-8861-78B79CA07E07_Efi_Ffs_Body.Bin",pFileBody,ulBodySize);

				pEfiCommonSectionHeader = (PEFI_COMMON_SECTION_HEADER)pFileBody;
				pSectionTypeDesc = GetSectionType(pEfiCommonSectionHeader->Type);
				pEfiCompressedSectionHeader = (PEFI_COMPRESSION_SECTION)pEfiCommonSectionHeader;
				pBody = (PCHAR)((ULONG)pFileBody + sizeof(EFI_COMPRESSION_SECTION));
				bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
				bIsParseCurrentSection = DeCompress(pBody,*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF, \
					pEfiCompressedSectionHeader->CompressionType,&pDeCompressed,&ulOutDeCompressedDatSize,&bAlgorithm);
				WriteModule("AE717C2F-1A42-4F2B-8861-78B79CA07E07_DeCompress.Bin",pDeCompressed,ulOutDeCompressedDatSize);
				StringCchPrintfA(ShowInfo,MAX_PATH,"%s: Type : %d FullSize : %d(%x) HeaderSize : %d(%x) BodySize : %d(%x) CompressionType : %s DecompressedSize : %d", \
					pSectionTypeDesc,pEfiCompressedSectionHeader->CompressionType, \
					*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF, \
					sizeof(EFI_COMPRESSION_SECTION),sizeof(EFI_COMPRESSION_SECTION), \
					(*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_COMPRESSION_SECTION), \
					(*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_COMPRESSION_SECTION), \
					CompressionTypeToPCHAR(bAlgorithm),pEfiCompressedSectionHeader->UncompressedLength);
				printf(ShowInfo);
				if (bIsParseCurrentSection)
				{
					pFindEfiCommonSectionHeader = (PEFI_COMMON_SECTION_HEADER)pDeCompressed;
					ulBodySize = (*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_COMMON_SECTION_HEADER);
					StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type : %d FullSize : %d(%x) HeaderSize : %d(%x) BodySize : %d(%x)\n", \
						pSectionTypeDesc,pEfiCommonSectionHeader->Type, \
						*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF, \
						sizeof(EFI_COMMON_SECTION_HEADER),sizeof(EFI_COMMON_SECTION_HEADER), \
						ulBodySize,ulBodySize);
					printf(ShowInfo);
					while (TRUE)
					{
						ulSectionSize = GetSectionSize(pDeCompressed,ulBodySize - ulSectionOffset,ulSectionOffset);
						if (ulSectionSize == -1)
						{
							break;
						}
						if (ulSectionSize == 0)
						{
							break;
						}
						pSectionTypeDesc = GetSectionType(pFindEfiCommonSectionHeader->Type);
						if (pFindEfiCommonSectionHeader->Type == EFI_SECTION_FIRMWARE_VOLUME_IMAGE)
						{
							ulBodySize = (*(ULONG*)pFindEfiCommonSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_COMMON_SECTION_HEADER);
							pBody = (PCHAR)((ULONG)pDeCompressed + ulSectionOffset + sizeof(EFI_COMMON_SECTION_HEADER));
							StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type : %d FullSize : %d(%x) HeaderSize : %d(%x) BodySize : %d(%x)\n", \
								pSectionTypeDesc,pFindEfiCommonSectionHeader->Type, \
								*(ULONG*)pFindEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pFindEfiCommonSectionHeader->Size & 0x00FFFFFF, \
								sizeof(EFI_COMMON_SECTION_HEADER),sizeof(EFI_COMMON_SECTION_HEADER), \
								ulBodySize,ulBodySize);
							printf(ShowInfo);
							do 
							{
								pReplaceSubModule = (PCHAR)VirtualAlloc(NULL,ulOutDeCompressedDatSize + 0x1000,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
							} while (NULL == pReplaceSubModule);
							RtlZeroMemory(pReplaceSubModule,ulOutDeCompressedDatSize + 0x1000);
							RtlCopyMemory(pReplaceSubModule,pDeCompressed,sizeof(EFI_COMMON_SECTION_HEADER));
							ulReplaceSubPos += sizeof(EFI_COMMON_SECTION_HEADER);
							AnalyzeReplaceModule(pBody,ulBodySize);
							if (pReplaceSubModule && ulReplaceSubPos)
							{
								//pReplaceSubModule = (PCHAR)((ULONG)pReplaceSubModule - sizeof(EFI_COMMON_SECTION_HEADER));
								//ulReplaceSubPos += 4;
								ulCompressionReplaceSubModuleSize = (*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF) + 0x600000/* + 0x69eb60*/;
								do 
								{
									pCompressionReplaceSubModule = (PCHAR)VirtualAlloc(NULL,ulCompressionReplaceSubModuleSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
								} while (NULL == pCompressionReplaceSubModule);
								RtlZeroMemory(pCompressionReplaceSubModule,ulCompressionReplaceSubModuleSize);
								RtlCopyMemory(pReplaceSubModule,g_pUtils->ULONG32ToULONG24(ulReplaceSubPos - 0x24),3);
								WriteModule("AE717C2F-1A42-4F2B-8861-78B79CA07E07_VolumeHeader.Bin",pReplaceSubModule,ulReplaceSubPos);
								ulRet = LzmaCompress((UINT8*)pReplaceSubModule,ulReplaceSubPos, \
									(UINT8*)pCompressionReplaceSubModule,(UINT32*)&ulCompressionReplaceSubModuleSize);
								if (ulRet == EFI_SUCCESS)
								{
									pGenEfiCompressionSection = GenerateCompressionHeader(/*(PCHAR)pEfiCompressedSectionHeader->Size,*/ \
										g_pUtils->ULONG32ToULONG24(ulCompressionReplaceSubModuleSize + sizeof(EFI_COMPRESSION_SECTION)), \
										pEfiCompressedSectionHeader->Type, \
										ulReplaceSubPos, \
										pEfiCompressedSectionHeader->CompressionType);
								}
							}
						}
						ulSectionOffset += ulSectionSize;
						ulSectionOffset = ALIGN4(ulSectionOffset);
						if (ulSectionOffset >= ulOutDeCompressedDatSize - 0x24)
						{
							break;
						}
					}
				}
				ulFindCount++;
			}
			//else if (strnicmp(pGuidName,"60EBDAA4-1565-4D9A-99C8-88DFA65549A5",sizeof(EFI_GUID)) == 0)
			//{

			//}
		}
		//while (TRUE)
		//{
		//	ulSectionSize = GetSectionSize(pFileBody,ulBodySize - ulSectionOffset,ulSectionOffset);
		//	if (ulSectionSize == -1)
		//	{
		//		return bRet;
		//	}
		//	if (ulSectionSize == 0)
		//	{
		//		break;
		//	}
		//	bRet = AnalyzeSection2((PCHAR)((ULONG)pFileBody + ulSectionOffset),ulSectionSize,pGuidName);
		//	if (bRet == FALSE)
		//	{
		//		return bRet;
		//	}
		//}
	}
	return TRUE;
}

BOOLEAN CEFIBIOSANALYZE::AnalyzeSections(PCHAR pBodySection, ULONG ulBodySectionSize, ULONG ulParentIndex, ULONG ulIndex, PCHAR pParentGuid)
{
	BOOLEAN bRet;
	ULONG ulSectionOffset;
	ULONG ulSectionSize;
	ULONG ulLocalIndex;
	ULONG ulBodySize;

	bRet = FALSE;
	ulSectionOffset = 0;
	ulSectionSize = 0;
	ulBodySize = ulBodySectionSize;

	while (TRUE)
	{
		ulSectionSize = GetSectionSize(pBodySection,ulBodySize - ulSectionOffset,ulSectionOffset);
		if (ulSectionSize == -1)
		{
			return bRet;
		}
		if (ulSectionSize == 0)
		{
			break;
		}
		bRet = AnalyzeSection((PCHAR)((ULONG)pBodySection + ulSectionOffset),ulSectionSize,ulParentIndex,ulIndex,pParentGuid);
		if (bRet == FALSE)
		{
			return bRet;
		}
		ulSectionOffset += ulSectionSize;
		ulSectionOffset = ALIGN4(ulSectionOffset);
		if (ulSectionOffset >= ulBodySectionSize)
		{
			break;
		}
	}
	return TRUE;
}

BOOLEAN CEFIBIOSANALYZE::AnalyzeSections2(PCHAR pBodySection, ULONG ulBodySectionSize, PCHAR pParentGuid)
{
	BOOLEAN bRet;
	ULONG ulSectionOffset;
	ULONG ulSectionSize;
	ULONG ulLocalIndex;
	ULONG ulBodySize;

	bRet = FALSE;
	ulSectionOffset = 0;
	ulSectionSize = 0;
	ulBodySize = ulBodySectionSize;

	while (TRUE)
	{
		ulSectionSize = GetSectionSize(pBodySection,ulBodySize - ulSectionOffset,ulSectionOffset);
		if (ulSectionSize == -1)
		{
			return bRet;
		}
		if (ulSectionSize == 0)
		{
			break;
		}
		bRet = AnalyzeSection2((PCHAR)((ULONG)pBodySection + ulSectionOffset),ulSectionSize,pParentGuid);
		if (bRet == FALSE)
		{
			return bRet;
		}
		ulSectionOffset += ulSectionSize;
		ulSectionOffset = ALIGN4(ulSectionOffset);
		if (ulSectionOffset >= ulBodySectionSize)
		{
			break;
		}
	}
	return TRUE;
}

ULONG CEFIBIOSANALYZE::GetSectionSize(PCHAR pBody, ULONG ulBodySize, ULONG ulSectionOffset)
{
	PEFI_COMMON_SECTION_HEADER pEfiCommonSectionHeader;

	pEfiCommonSectionHeader = NULL;

	if (ulBodySize < ulSectionOffset + sizeof(EFI_COMMON_SECTION_HEADER))
	{
		return -1;
	}
	pEfiCommonSectionHeader = (PEFI_COMMON_SECTION_HEADER)((ULONG)pBody + ulSectionOffset);
	return (*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF);
}


BOOLEAN CEFIBIOSANALYZE::AnalyzeSection(PCHAR pSection, ULONG ulSectionSize, ULONG ulParentIndex, ULONG ulIndex, PCHAR pParentGuid)
{
	BOOLEAN bRet;
	PEFI_COMMON_SECTION_HEADER pEfiCommonSectionHeader;
	PCHAR pSectionTypeDesc;
	BOOLEAN bIsParseCurrentSection;
	PCHAR pDeCompressed;
	PCHAR pBody;
	PCHAR pHeader;
	ULONG ulBodySize;
	ULONG ulHeaderSize;
	PCHAR pGuidName;
	BYTE bAlgorithm;
	ULONG ulOutDeCompressedDatSize;
	ULONG ulCrc32;
	CHAR ShowInfo[MAX_PATH];

	bRet = FALSE;
	pEfiCommonSectionHeader = NULL;
	pSectionTypeDesc = NULL;
	bIsParseCurrentSection = TRUE;
	pDeCompressed = NULL;
	pBody = NULL;
	ulOutDeCompressedDatSize = 0;
	pGuidName = NULL;
	ulCrc32 = 0;
	ulBodySize = 0;
	pHeader = NULL;
	RtlZeroMemory(ShowInfo,MAX_PATH);

	pEfiCommonSectionHeader = (PEFI_COMMON_SECTION_HEADER)pSection;
	pSectionTypeDesc = GetSectionType(pEfiCommonSectionHeader->Type);
	switch (pEfiCommonSectionHeader->Type)
	{
	case EFI_SECTION_COMPRESSION:
		{
			PEFI_COMPRESSION_SECTION pEfiCompressedSectionHeader;

			pEfiCompressedSectionHeader = (PEFI_COMPRESSION_SECTION)pEfiCommonSectionHeader;
			pBody = (PCHAR)((ULONG)pSection + sizeof(EFI_COMPRESSION_SECTION));
			bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
			bIsParseCurrentSection = DeCompress(pBody,ulSectionSize - sizeof(EFI_COMPRESSION_SECTION), \
				pEfiCompressedSectionHeader->CompressionType,&pDeCompressed,&ulOutDeCompressedDatSize,&bAlgorithm);
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s: Type : %d FullSize : %d(%x) HeaderSize : %d(%x) BodySize : %d(%x) CompressionType : %s DecompressedSize : %d", \
				pSectionTypeDesc,pEfiCompressedSectionHeader->CompressionType, \
				*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF, \
				sizeof(EFI_COMPRESSION_SECTION),sizeof(EFI_COMPRESSION_SECTION), \
				(*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_COMPRESSION_SECTION), \
				(*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_COMPRESSION_SECTION), \
				CompressionTypeToPCHAR(bAlgorithm),pEfiCompressedSectionHeader->UncompressedLength);
			printf(ShowInfo);
			if (bIsParseCurrentSection)
			{
				if (AnalyzeSections(pDeCompressed,ulOutDeCompressedDatSize,ulParentIndex,ulIndex,pParentGuid) == FALSE)
				{
					return FALSE;
				}
			}
		}
		break;
	case EFI_SECTION_GUID_DEFINED:
		{
			PEFI_GUID_DEFINED_SECTION pEfiGuidDefinedSection;

			pEfiGuidDefinedSection = (PEFI_GUID_DEFINED_SECTION)pSection;
			pEfiGuidDefinedSection = (PEFI_GUID_DEFINED_SECTION)((ULONG)pSection + pEfiGuidDefinedSection->DataOffset);
			pBody = (PCHAR)((ULONG)pSection + pEfiGuidDefinedSection->DataOffset);
			
			pGuidName = g_pUtils->ConvertName((PCHAR)pEfiGuidDefinedSection->SectionDefinitionGuid.Data);
			StringCchPrintfA(ShowInfo,MAX_PATH, \
				"%s SectionGUID: %s Type: %d FullSize: %d(%x) HeaderSize: %d(%x) BodySize: %d(%x) DataOffset: %d(%x) Attribute:%d", \
				pSectionTypeDesc,pGuidName,pEfiGuidDefinedSection->Type,ulSectionSize,ulSectionSize,sizeof(EFI_GUID_DEFINED_SECTION),sizeof(EFI_GUID_DEFINED_SECTION), \
				(*(ULONG*)pEfiGuidDefinedSection->Size & 0x00FFFFFF) - sizeof(EFI_GUID_DEFINED_SECTION), \
				(*(ULONG*)pEfiGuidDefinedSection->Size & 0x00FFFFFF) - sizeof(EFI_GUID_DEFINED_SECTION), \
				pEfiGuidDefinedSection->DataOffset,pEfiGuidDefinedSection->DataOffset,pEfiGuidDefinedSection->Attributes);
			printf(ShowInfo);
			bAlgorithm = COMPRESSION_ALGORITHM_NONE;
			if (pEfiGuidDefinedSection->Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED)
			{
				if (strnicmp(pGuidName,EFI_GUIDED_SECTION_TIANO,strlen(EFI_GUIDED_SECTION_TIANO)) == 0)
				{
					bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
				}
				if (DeCompress(pBody,EFI_STANDARD_COMPRESSION,ulSectionSize - sizeof(EFI_GUID_DEFINED_SECTION),&pDeCompressed,&ulOutDeCompressedDatSize,&bAlgorithm) == FALSE)
				{
					bIsParseCurrentSection = FALSE;
				}
				if (bAlgorithm == COMPRESSION_ALGORITHM_TIANO)
				{
					printf("CompressionType: Tiano DecompressedSize: %d(%x)\n",ulOutDeCompressedDatSize,ulOutDeCompressedDatSize);
				}
				else if (bAlgorithm == COMPRESSION_ALGORITHM_EFI11)
				{
					printf("CompressionType: EFI11 DecompressedSize: %d(%x)\n",ulOutDeCompressedDatSize,ulOutDeCompressedDatSize);
				}
				else
				{
					printf("CompressionType: Unknow\n");
				}
			}
			else if (strnicmp(pGuidName,EFI_GUIDED_SECTION_LZMA,strlen(EFI_GUIDED_SECTION_LZMA)) == 0)
			{
				bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
				if (DeCompress(pBody,ulSectionSize - sizeof(EFI_GUID_DEFINED_SECTION),EFI_CUSTOMIZED_COMPRESSION,&pDeCompressed,&ulOutDeCompressedDatSize,&bAlgorithm) == FALSE)
				{
					bIsParseCurrentSection = FALSE;
				}
				if (bAlgorithm == COMPRESSION_ALGORITHM_LZMA)
				{
					printf("CompressionType: LZMA DecompressedSize: %d(%x)\n",ulOutDeCompressedDatSize,ulOutDeCompressedDatSize);
				}
				else
				{
					printf("CompressionType: Unknow\n");
				}
			}
			else if (strnicmp(pGuidName,EFI_FIRMWARE_CONTENTS_SIGNED_GUID,strlen(EFI_FIRMWARE_CONTENTS_SIGNED_GUID)) == 0)
			{
				PWIN_CERTIFICATE pCertificateHeader;
				PWIN_CERTIFICATE_UEFI_GUID pWinCertificateUefiGuid;

				pCertificateHeader = (PWIN_CERTIFICATE)pBody;
				if (ulSectionSize - sizeof(EFI_GUID_DEFINED_SECTION) < sizeof(WIN_CERTIFICATE))
				{
					bIsParseCurrentSection = FALSE;
					printf("Signature type: invalid, wrong length\n");
				}
				else if (pCertificateHeader->CertificateType == WIN_CERT_TYPE_EFI_GUID)
				{
					printf("Signature type: UEFI\n");
					pWinCertificateUefiGuid = (PWIN_CERTIFICATE_UEFI_GUID)pCertificateHeader;
					if (strnicmp(g_pUtils->ConvertName((PCHAR)pWinCertificateUefiGuid->CertType.Data), \
						EFI_CERT_TYPE_RSA2048_SHA256_GUID, \
						strlen(EFI_CERT_TYPE_RSA2048_SHA256_GUID)) == 0)
					{
						printf("Signature subtype: RSA2048/SHA256\n");
					}
					else if (strnicmp(g_pUtils->ConvertName((PCHAR)pWinCertificateUefiGuid->CertType.Data), \
						EFI_CERT_TYPE_PKCS7_GUID, \
						strlen(EFI_CERT_TYPE_PKCS7_GUID)))
					{
						printf("Signature subtype: PCKS7\n");
					}
					else
					{
						printf("Signature subtype: unknown");
					}
				}
				else if (pCertificateHeader->CertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA)
				{
					printf("Signature type: PCKS7\n");
				}
				else
				{
					printf("Signature type: Unknown\n");
				}
				if (ulSectionSize - sizeof(EFI_GUID_DEFINED_SECTION) < pCertificateHeader->Length)
				{
					printf("Signature type: invalid, wrong length\n");
					bIsParseCurrentSection = FALSE;
				}
				else
				{
					pEfiCommonSectionHeader = (PEFI_COMMON_SECTION_HEADER)((ULONG)pBody + pCertificateHeader->Length);
					pDeCompressed = (PCHAR)((ULONG)pBody + pCertificateHeader->Length);
				}
			}
			else if (pEfiGuidDefinedSection->Attributes & EFI_GUIDED_SECTION_AUTH_STATUS_VALID)
			{
				if (strnicmp(g_pUtils->ConvertName((PCHAR)pEfiGuidDefinedSection->SectionDefinitionGuid.Data),EFI_GUIDED_SECTION_CRC32,strlen(EFI_GUIDED_SECTION_CRC32)) == 0)
				{
					printf("Checksum type: CRC32\n");
					ulBodySize = ulSectionSize - sizeof(EFI_COMMON_SECTION_HEADER);
					ulCrc32 = g_pUtils->CheckSum32(pBody,0,ulBodySize);
					if (ulCrc32 == *(ULONG*)((ULONG)pBody + sizeof(EFI_GUID_DEFINED_SECTION)))
					{
						printf("Checksum Valid\n");
					}
					else
					{
						printf("Checksum invalid\n");
					}
				}
				else
				{

				}
			}
			if (bIsParseCurrentSection == FALSE)
			{
				printf("parseSection: GUID defined section can not be processed %d\n",ulIndex);
			}
			else
			{
				if (AnalyzeSections(pDeCompressed,ulBodySize,ulParentIndex,ulIndex,pGuidName) == FALSE)
				{
					return FALSE;
				}
			}
		}
		break;
	case EFI_SECTION_DISPOSABLE:
		{
			pHeader = pSection;
			pBody = (PCHAR)((ULONG)pSection + sizeof(EFI_DISPOSABLE_SECTION));
			ulBodySize = *(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF;
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type : %d FullSize: %d(%x) HeaderSize: %d(%x) BodySize: %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type,ulSectionSize,ulSectionSize,sizeof(EFI_DISPOSABLE_SECTION),sizeof(EFI_DISPOSABLE_SECTION), \
				ulBodySize,ulBodySize);
			printf(ShowInfo);
			if (AnalyzeSections(pBody,ulBodySize,ulParentIndex,ulIndex,pParentGuid) == FALSE)
			{
				return FALSE;
			}
		}
		break;
	case EFI_SECTION_DXE_DEPEX:
	case EFI_SECTION_PEI_DEPEX:
	case EFI_SECTION_SMM_DEPEX:
		{
			PCHAR pShowDesc;
			BOOLEAN bIsMsgDepexParseFailed;

			pShowDesc = NULL;
			bIsMsgDepexParseFailed = FALSE;

			ulHeaderSize = SizeOfSectionHeader(pEfiCommonSectionHeader);
			ulBodySize = ulSectionSize - ulHeaderSize;
			pHeader = pSection;
			pBody = (PCHAR)((ULONG)pSection + ulHeaderSize);
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type: %d FullSize: %d(%x) HeaderSize: %d(%x) BodySize: %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type,ulSectionSize,ulSectionSize,ulHeaderSize,ulHeaderSize, \
				*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF);
			printf(ShowInfo);
			if (AnalyzeDepexSection(pBody,ulBodySize,&pShowDesc) == FALSE)
			{
				bIsMsgDepexParseFailed = TRUE;
			}
			else
			{
				printf("Parsed expression: %s\n",pShowDesc);
			}
		}
		break;
	case EFI_SECTION_TE:
		{
			BOOLEAN bIsMsgInvalidSignature;
			PEFI_IMAGE_TE_HEADER pEfiImageTeHeader;
			ULONG ulTeFixup;

			bIsMsgInvalidSignature = FALSE;
			pEfiImageTeHeader = NULL;

			ulHeaderSize = SizeOfSectionHeader(pEfiCommonSectionHeader);
			pHeader = (PCHAR)pSection;
			pBody = (PCHAR)((ULONG)pSection + ulHeaderSize);
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type: %d FullSize: %d(%x) HeaderSize: %d(%x) BodySize: %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type,ulSectionSize,ulSectionSize,ulHeaderSize,ulHeaderSize, \
				*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF);
			printf(ShowInfo);
			pEfiImageTeHeader = (PEFI_IMAGE_TE_HEADER)pBody;
			ulTeFixup = pEfiImageTeHeader->StrippedSize - sizeof(EFI_IMAGE_TE_HEADER);
			if (pEfiImageTeHeader->Signature != EFI_IMAGE_TE_SIGNATURE)
			{
				bIsMsgInvalidSignature = TRUE;
				printf("Signature: %s invalid\n",pEfiImageTeHeader->Signature);
			}
			else
			{
				StringCchPrintfA(ShowInfo,MAX_PATH, \
					"Signature: %s MachhineType:%s NumberOfSection:%d StrippedSize:%d(%x) BaseOfCode:%x RelativeEntryPoint:%08x ImageBase:%x EntryPoint:%x\n", \
					pEfiImageTeHeader->Signature,pEfiImageTeHeader->Machine,pEfiImageTeHeader->NumberOfSections,pEfiImageTeHeader->StrippedSize,pEfiImageTeHeader->StrippedSize, \
					pEfiImageTeHeader->BaseOfCode,pEfiImageTeHeader->AddressOfEntryPoint,pEfiImageTeHeader->ImageBase,pEfiImageTeHeader->ImageBase + pEfiImageTeHeader->AddressOfEntryPoint - \
					ulTeFixup);
				printf(ShowInfo);
			}
		}
		break;
	case EFI_SECTION_PE32:
	case EFI_SECTION_PIC:
		{

		}
		break;
	case EFI_SECTION_COMPATIBILITY16:
		{

		}
		break;
	case EFI_SECTION_FREEFORM_SUBTYPE_GUID:
		{

		}
		break;
	case EFI_SECTION_VERSION:
		{

		}
		break;
	case EFI_SECTION_USER_INTERFACE:
		{

		}
		break;
	case EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
		{
			pHeader = pSection;
			ulBodySize = (*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_FIRMWARE_VOLUME_IMAGE_SECTION);
			pBody = (PCHAR)((ULONG)pSection + sizeof(EFI_FIRMWARE_VOLUME_IMAGE_SECTION));
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type : %d FullSize : %d(%x) HeaderSize : %d(%x) BodySize : %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type, \
				*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF, \
				sizeof(EFI_FIRMWARE_VOLUME_IMAGE_SECTION),sizeof(EFI_FIRMWARE_VOLUME_IMAGE_SECTION), \
				ulBodySize,ulBodySize);
			printf(ShowInfo);
			if (g_pDellAnalyze->AnalyzeBIOS(pBody,ulBodySize,NULL) == FALSE)
			{
				return FALSE;
			}
		}
		break;
	case EFI_SECTION_RAW:
		{
			BOOLEAN bIsParsed;
			PCHAR pUnionGuid;
			ULONG ulOutCount;

			bIsParsed = FALSE;
			pUnionGuid = NULL;
			ulOutCount = 0;

			pHeader = pSection;
			pBody = (PCHAR)((ULONG)pSection + sizeof(EFI_RAW_SECTION));
			ulBodySize = (*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_RAW_SECTION);
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type : %d FullSize : %d(%x) HeaderSize : %d(%x) BodySize : %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type, \
				*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF, \
				sizeof(EFI_RAW_SECTION),sizeof(EFI_RAW_SECTION), \
				ulBodySize,ulBodySize);
			printf(ShowInfo);
			if (strnicmp(pParentGuid,EFI_PEI_APRIORI_FILE_GUID,strlen(EFI_PEI_APRIORI_FILE_GUID)) == 0)
			{
				bIsParsed = TRUE;
				pUnionGuid = AnalyzeAprioriRawSection(pBody,ulBodySize,&ulOutCount);
				printf("Count:%d %s\n",ulOutCount,pUnionGuid);
			}
			else if (strnicmp(pParentGuid,EFI_DXE_APRIORI_FILE_GUID,strlen(EFI_DXE_APRIORI_FILE_GUID)) == 0)
			{
				bIsParsed = TRUE;
				pUnionGuid = AnalyzeAprioriRawSection(pBody,ulBodySize,&ulOutCount);
				printf("Count:%d %s\n",ulOutCount,pUnionGuid);
			}
			if (bIsParsed == FALSE)
			{
				if (g_pDellAnalyze->AnalyzeBIOS(pBody,ulBodySize,NULL) == FALSE)
				{
					return FALSE;
				}
			}
		}
		break;
	case SCT_SECTION_POSTCODE:
	case INSYDE_SECTION_POSTCODE:
		{

		}
		break;
	default:
		break;
	}
	return TRUE;
}

BOOLEAN CEFIBIOSANALYZE::AnalyzeSection2(PCHAR pSection, ULONG ulSectionSize, PCHAR pParentGuid)
{
	BOOLEAN bRet;
	PEFI_COMMON_SECTION_HEADER pEfiCommonSectionHeader;
	PCHAR pSectionTypeDesc;
	BOOLEAN bIsParseCurrentSection;
	PCHAR pDeCompressed;
	PCHAR pBody;
	PCHAR pHeader;
	ULONG ulBodySize;
	ULONG ulHeaderSize;
	PCHAR pGuidName;
	BYTE bAlgorithm;
	ULONG ulOutDeCompressedDatSize;
	ULONG ulCrc32;
	CHAR ShowInfo[MAX_PATH];

	bRet = FALSE;
	pEfiCommonSectionHeader = NULL;
	pSectionTypeDesc = NULL;
	bIsParseCurrentSection = TRUE;
	pDeCompressed = NULL;
	pBody = NULL;
	ulOutDeCompressedDatSize = 0;
	pGuidName = NULL;
	ulCrc32 = 0;
	ulBodySize = 0;
	pHeader = NULL;
	RtlZeroMemory(ShowInfo,MAX_PATH);

	pEfiCommonSectionHeader = (PEFI_COMMON_SECTION_HEADER)pSection;
	pSectionTypeDesc = GetSectionType(pEfiCommonSectionHeader->Type);
	switch (pEfiCommonSectionHeader->Type)
	{
	case EFI_SECTION_COMPRESSION:
		{
			PEFI_COMPRESSION_SECTION pEfiCompressedSectionHeader;

			pEfiCompressedSectionHeader = (PEFI_COMPRESSION_SECTION)pEfiCommonSectionHeader;
			pBody = (PCHAR)((ULONG)pSection + sizeof(EFI_COMPRESSION_SECTION));
			bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
			bIsParseCurrentSection = DeCompress(pBody,ulSectionSize - sizeof(EFI_COMPRESSION_SECTION), \
				pEfiCompressedSectionHeader->CompressionType,&pDeCompressed,&ulOutDeCompressedDatSize,&bAlgorithm);
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s: Type : %d FullSize : %d(%x) HeaderSize : %d(%x) BodySize : %d(%x) CompressionType : %s DecompressedSize : %d", \
				pSectionTypeDesc,pEfiCompressedSectionHeader->CompressionType, \
				*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF, \
				sizeof(EFI_COMPRESSION_SECTION),sizeof(EFI_COMPRESSION_SECTION), \
				(*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_COMPRESSION_SECTION), \
				(*(ULONG*)pEfiCompressedSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_COMPRESSION_SECTION), \
				CompressionTypeToPCHAR(bAlgorithm),pEfiCompressedSectionHeader->UncompressedLength);
			printf(ShowInfo);
			if (bIsParseCurrentSection)
			{
				if (AnalyzeSections2(pDeCompressed,ulOutDeCompressedDatSize,pParentGuid) == FALSE)
				{
					return FALSE;
				}
			}
		}
		break;
	case EFI_SECTION_GUID_DEFINED:
		{
			PEFI_GUID_DEFINED_SECTION pEfiGuidDefinedSection;

			pEfiGuidDefinedSection = (PEFI_GUID_DEFINED_SECTION)pSection;
			pEfiGuidDefinedSection = (PEFI_GUID_DEFINED_SECTION)((ULONG)pSection + pEfiGuidDefinedSection->DataOffset);
			pBody = (PCHAR)((ULONG)pSection + pEfiGuidDefinedSection->DataOffset);

			pGuidName = g_pUtils->ConvertName((PCHAR)pEfiGuidDefinedSection->SectionDefinitionGuid.Data);
			StringCchPrintfA(ShowInfo,MAX_PATH, \
				"%s SectionGUID: %s Type: %d FullSize: %d(%x) HeaderSize: %d(%x) BodySize: %d(%x) DataOffset: %d(%x) Attribute:%d", \
				pSectionTypeDesc,pGuidName,pEfiGuidDefinedSection->Type,ulSectionSize,ulSectionSize,sizeof(EFI_GUID_DEFINED_SECTION),sizeof(EFI_GUID_DEFINED_SECTION), \
				(*(ULONG*)pEfiGuidDefinedSection->Size & 0x00FFFFFF) - sizeof(EFI_GUID_DEFINED_SECTION), \
				(*(ULONG*)pEfiGuidDefinedSection->Size & 0x00FFFFFF) - sizeof(EFI_GUID_DEFINED_SECTION), \
				pEfiGuidDefinedSection->DataOffset,pEfiGuidDefinedSection->DataOffset,pEfiGuidDefinedSection->Attributes);
			printf(ShowInfo);
			bAlgorithm = COMPRESSION_ALGORITHM_NONE;
			if (pEfiGuidDefinedSection->Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED)
			{
				if (strnicmp(pGuidName,EFI_GUIDED_SECTION_TIANO,strlen(EFI_GUIDED_SECTION_TIANO)) == 0)
				{
					bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
				}
				if (DeCompress(pBody,EFI_STANDARD_COMPRESSION,ulSectionSize - sizeof(EFI_GUID_DEFINED_SECTION),&pDeCompressed,&ulOutDeCompressedDatSize,&bAlgorithm) == FALSE)
				{
					bIsParseCurrentSection = FALSE;
				}
				if (bAlgorithm == COMPRESSION_ALGORITHM_TIANO)
				{
					printf("CompressionType: Tiano DecompressedSize: %d(%x)\n",ulOutDeCompressedDatSize,ulOutDeCompressedDatSize);
				}
				else if (bAlgorithm == COMPRESSION_ALGORITHM_EFI11)
				{
					printf("CompressionType: EFI11 DecompressedSize: %d(%x)\n",ulOutDeCompressedDatSize,ulOutDeCompressedDatSize);
				}
				else
				{
					printf("CompressionType: Unknow\n");
				}
			}
			else if (strnicmp(pGuidName,EFI_GUIDED_SECTION_LZMA,strlen(EFI_GUIDED_SECTION_LZMA)) == 0)
			{
				bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
				if (DeCompress(pBody,ulSectionSize - sizeof(EFI_GUID_DEFINED_SECTION),EFI_CUSTOMIZED_COMPRESSION,&pDeCompressed,&ulOutDeCompressedDatSize,&bAlgorithm) == FALSE)
				{
					bIsParseCurrentSection = FALSE;
				}
				if (bAlgorithm == COMPRESSION_ALGORITHM_LZMA)
				{
					printf("CompressionType: LZMA DecompressedSize: %d(%x)\n",ulOutDeCompressedDatSize,ulOutDeCompressedDatSize);
				}
				else
				{
					printf("CompressionType: Unknow\n");
				}
			}
			else if (strnicmp(pGuidName,EFI_FIRMWARE_CONTENTS_SIGNED_GUID,strlen(EFI_FIRMWARE_CONTENTS_SIGNED_GUID)) == 0)
			{
				PWIN_CERTIFICATE pCertificateHeader;
				PWIN_CERTIFICATE_UEFI_GUID pWinCertificateUefiGuid;

				pCertificateHeader = (PWIN_CERTIFICATE)pBody;
				if (ulSectionSize - sizeof(EFI_GUID_DEFINED_SECTION) < sizeof(WIN_CERTIFICATE))
				{
					bIsParseCurrentSection = FALSE;
					printf("Signature type: invalid, wrong length\n");
				}
				else if (pCertificateHeader->CertificateType == WIN_CERT_TYPE_EFI_GUID)
				{
					printf("Signature type: UEFI\n");
					pWinCertificateUefiGuid = (PWIN_CERTIFICATE_UEFI_GUID)pCertificateHeader;
					if (strnicmp(g_pUtils->ConvertName((PCHAR)pWinCertificateUefiGuid->CertType.Data), \
						EFI_CERT_TYPE_RSA2048_SHA256_GUID, \
						strlen(EFI_CERT_TYPE_RSA2048_SHA256_GUID)) == 0)
					{
						printf("Signature subtype: RSA2048/SHA256\n");
					}
					else if (strnicmp(g_pUtils->ConvertName((PCHAR)pWinCertificateUefiGuid->CertType.Data), \
						EFI_CERT_TYPE_PKCS7_GUID, \
						strlen(EFI_CERT_TYPE_PKCS7_GUID)))
					{
						printf("Signature subtype: PCKS7\n");
					}
					else
					{
						printf("Signature subtype: unknown");
					}
				}
				else if (pCertificateHeader->CertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA)
				{
					printf("Signature type: PCKS7\n");
				}
				else
				{
					printf("Signature type: Unknown\n");
				}
				if (ulSectionSize - sizeof(EFI_GUID_DEFINED_SECTION) < pCertificateHeader->Length)
				{
					printf("Signature type: invalid, wrong length\n");
					bIsParseCurrentSection = FALSE;
				}
				else
				{
					pEfiCommonSectionHeader = (PEFI_COMMON_SECTION_HEADER)((ULONG)pBody + pCertificateHeader->Length);
					pDeCompressed = (PCHAR)((ULONG)pBody + pCertificateHeader->Length);
				}
			}
			else if (pEfiGuidDefinedSection->Attributes & EFI_GUIDED_SECTION_AUTH_STATUS_VALID)
			{
				if (strnicmp(g_pUtils->ConvertName((PCHAR)pEfiGuidDefinedSection->SectionDefinitionGuid.Data),EFI_GUIDED_SECTION_CRC32,strlen(EFI_GUIDED_SECTION_CRC32)) == 0)
				{
					printf("Checksum type: CRC32\n");
					ulBodySize = ulSectionSize - sizeof(EFI_COMMON_SECTION_HEADER);
					ulCrc32 = g_pUtils->CheckSum32(pBody,0,ulBodySize);
					if (ulCrc32 == *(ULONG*)((ULONG)pBody + sizeof(EFI_GUID_DEFINED_SECTION)))
					{
						printf("Checksum Valid\n");
					}
					else
					{
						printf("Checksum invalid\n");
					}
				}
				else
				{

				}
			}
			if (bIsParseCurrentSection == FALSE)
			{
				printf("parseSection: GUID defined section can not be processed\n");
			}
			else
			{
				if (AnalyzeSections2(pDeCompressed,ulBodySize,pGuidName) == FALSE)
				{
					return FALSE;
				}
			}
		}
		break;
	case EFI_SECTION_DISPOSABLE:
		{
			pHeader = pSection;
			pBody = (PCHAR)((ULONG)pSection + sizeof(EFI_DISPOSABLE_SECTION));
			ulBodySize = *(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF;
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type : %d FullSize: %d(%x) HeaderSize: %d(%x) BodySize: %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type,ulSectionSize,ulSectionSize,sizeof(EFI_DISPOSABLE_SECTION),sizeof(EFI_DISPOSABLE_SECTION), \
				ulBodySize,ulBodySize);
			printf(ShowInfo);
			if (AnalyzeSections2(pBody,ulBodySize,pParentGuid) == FALSE)
			{
				return FALSE;
			}
		}
		break;
	case EFI_SECTION_DXE_DEPEX:
	case EFI_SECTION_PEI_DEPEX:
	case EFI_SECTION_SMM_DEPEX:
		{
			PCHAR pShowDesc;
			BOOLEAN bIsMsgDepexParseFailed;

			pShowDesc = NULL;
			bIsMsgDepexParseFailed = FALSE;

			ulHeaderSize = SizeOfSectionHeader(pEfiCommonSectionHeader);
			ulBodySize = ulSectionSize - ulHeaderSize;
			pHeader = pSection;
			pBody = (PCHAR)((ULONG)pSection + ulHeaderSize);
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type: %d FullSize: %d(%x) HeaderSize: %d(%x) BodySize: %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type,ulSectionSize,ulSectionSize,ulHeaderSize,ulHeaderSize, \
				*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF);
			printf(ShowInfo);
			if (AnalyzeDepexSection(pBody,ulBodySize,&pShowDesc) == FALSE)
			{
				bIsMsgDepexParseFailed = TRUE;
			}
			else
			{
				printf("Parsed expression: %s\n",pShowDesc);
			}
		}
		break;
	case EFI_SECTION_TE:
		{
			BOOLEAN bIsMsgInvalidSignature;
			PEFI_IMAGE_TE_HEADER pEfiImageTeHeader;
			ULONG ulTeFixup;

			bIsMsgInvalidSignature = FALSE;
			pEfiImageTeHeader = NULL;

			ulHeaderSize = SizeOfSectionHeader(pEfiCommonSectionHeader);
			pHeader = (PCHAR)pSection;
			pBody = (PCHAR)((ULONG)pSection + ulHeaderSize);
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type: %d FullSize: %d(%x) HeaderSize: %d(%x) BodySize: %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type,ulSectionSize,ulSectionSize,ulHeaderSize,ulHeaderSize, \
				*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF);
			printf(ShowInfo);
			pEfiImageTeHeader = (PEFI_IMAGE_TE_HEADER)pBody;
			ulTeFixup = pEfiImageTeHeader->StrippedSize - sizeof(EFI_IMAGE_TE_HEADER);
			if (pEfiImageTeHeader->Signature != EFI_IMAGE_TE_SIGNATURE)
			{
				bIsMsgInvalidSignature = TRUE;
				printf("Signature: %s invalid\n",pEfiImageTeHeader->Signature);
			}
			else
			{
				StringCchPrintfA(ShowInfo,MAX_PATH, \
					"Signature: %s MachhineType:%s NumberOfSection:%d StrippedSize:%d(%x) BaseOfCode:%x RelativeEntryPoint:%08x ImageBase:%x EntryPoint:%x\n", \
					pEfiImageTeHeader->Signature,pEfiImageTeHeader->Machine,pEfiImageTeHeader->NumberOfSections,pEfiImageTeHeader->StrippedSize,pEfiImageTeHeader->StrippedSize, \
					pEfiImageTeHeader->BaseOfCode,pEfiImageTeHeader->AddressOfEntryPoint,pEfiImageTeHeader->ImageBase,pEfiImageTeHeader->ImageBase + pEfiImageTeHeader->AddressOfEntryPoint - \
					ulTeFixup);
				printf(ShowInfo);
			}
		}
		break;
	case EFI_SECTION_PE32:
	case EFI_SECTION_PIC:
		{

		}
		break;
	case EFI_SECTION_COMPATIBILITY16:
		{

		}
		break;
	case EFI_SECTION_FREEFORM_SUBTYPE_GUID:
		{

		}
		break;
	case EFI_SECTION_VERSION:
		{

		}
		break;
	case EFI_SECTION_USER_INTERFACE:
		{

		}
		break;
	case EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
		{
			pHeader = pSection;
			ulBodySize = (*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_COMMON_SECTION_HEADER);
			pBody = (PCHAR)((ULONG)pSection + sizeof(EFI_COMMON_SECTION_HEADER));
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type : %d FullSize : %d(%x) HeaderSize : %d(%x) BodySize : %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type, \
				*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF, \
				sizeof(EFI_COMMON_SECTION_HEADER),sizeof(EFI_COMMON_SECTION_HEADER), \
				ulBodySize,ulBodySize);
			printf(ShowInfo);
			//if (g_pDellAnalyze->AnalyzeBIOS(pBody,ulBodySize,NULL) == FALSE)
			//{
			//	return FALSE;
			//}
			AnalyzeReplaceModule(pBody,ulBodySize);
		}
		break;
	case EFI_SECTION_RAW:
		{
			BOOLEAN bIsParsed;
			PCHAR pUnionGuid;
			ULONG ulOutCount;

			bIsParsed = FALSE;
			pUnionGuid = NULL;
			ulOutCount = 0;

			pHeader = pSection;
			pBody = (PCHAR)((ULONG)pSection + sizeof(EFI_RAW_SECTION));
			ulBodySize = (*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF) - sizeof(EFI_RAW_SECTION);
			StringCchPrintfA(ShowInfo,MAX_PATH,"%s Type : %d FullSize : %d(%x) HeaderSize : %d(%x) BodySize : %d(%x)\n", \
				pSectionTypeDesc,pEfiCommonSectionHeader->Type, \
				*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF,*(ULONG*)pEfiCommonSectionHeader->Size & 0x00FFFFFF, \
				sizeof(EFI_RAW_SECTION),sizeof(EFI_RAW_SECTION), \
				ulBodySize,ulBodySize);
			printf(ShowInfo);
			if (strnicmp(pParentGuid,EFI_PEI_APRIORI_FILE_GUID,strlen(EFI_PEI_APRIORI_FILE_GUID)) == 0)
			{
				bIsParsed = TRUE;
				pUnionGuid = AnalyzeAprioriRawSection(pBody,ulBodySize,&ulOutCount);
				printf("Count:%d %s\n",ulOutCount,pUnionGuid);
			}
			else if (strnicmp(pParentGuid,EFI_DXE_APRIORI_FILE_GUID,strlen(EFI_DXE_APRIORI_FILE_GUID)) == 0)
			{
				bIsParsed = TRUE;
				pUnionGuid = AnalyzeAprioriRawSection(pBody,ulBodySize,&ulOutCount);
				printf("Count:%d %s\n",ulOutCount,pUnionGuid);
			}
			if (bIsParsed == FALSE)
			{
				if (g_pDellAnalyze->AnalyzeBIOS(pBody,ulBodySize,NULL) == FALSE)
				{
					return FALSE;
				}
			}
		}
		break;
	case SCT_SECTION_POSTCODE:
	case INSYDE_SECTION_POSTCODE:
		{

		}
		break;
	default:
		break;
	}
	return TRUE;
}
ULONG CEFIBIOSANALYZE::MyFindNextVolume(PCHAR pBIOSDat, ULONG ulSize, ULONG ulOffset)
{
	ULONG ulIndex;

	ulIndex = g_pUtils->Find(pBIOSDat,ulSize,EFI_FV_SIGNATURE,strlen(EFI_FV_SIGNATURE),ulOffset,0);
	if (ulIndex < EFI_FV_SIGNATURE_OFFSET)
	{
		return -1;
	}
	return (ulIndex - EFI_FV_SIGNATURE_OFFSET);
}
BOOLEAN CEFIBIOSANALYZE::AnalyzeReplaceModule(PCHAR pBIOSDat, ULONG ulBIOSSize)
{
	ULONG ulVolumeOffset,ulPreVolumeOffset;
	ULONG ulVolumeSize,ulPreVolumeSize,ulNextVolumeSize;
	ULONG ulCalcVolumeSize;
	PEFI_FIRMWARE_VOLUME_HEADER pEfiFirmWareVolumeHeader;
	ULONG ulHeaderSize;
	PEFI_FIRMWARE_VOLUME_EXT_HEADER pEfiFirmWareVolumeExtHeader;
	PEFI_FFS_FILE_HEADER pEfiFfsFileHeader;
	BYTE bAttribute;
	BOOLEAN bIsVolumeUnknow;
	ULONG ulLocalVolumeSize;
	BOOLEAN bIsInvalidCheckSum;
	BOOLEAN bVolumeHasZVCRC;
	BOOLEAN bVolumeHasZVFSO;
	PCHAR pGuidName,pFileGuidName;
	ULONG ulCrc32FromZeroVector;
	ULONG ulFreeSpaceOffsetFromZeroVector;
	ULONG ulCrc32CheckSum;
	CHAR ShowInfo[MAX_PATH];
	ULONG ulFileOffset;
	ULONG ulFileSize;
	ULONG ulFillOffset;
	PCHAR pFileBody;
	BOOLEAN bIsBlink;
	PEFI_FFS_FILE_HEADER pGenEfiFfsFileHeader;
	PEFI_FFS_FILE_HEADER pCheckSumFfsFileHeader;
	PEFI_COMMON_SECTION_HEADER pEfiCommonSectionHeader;
	PEFI_COMMON_SECTION_HEADER pGenCommonSectionHeader;
	PEFI_COMPRESSION_SECTION pCompressionHeader;
	PEFI_COMPRESSION_SECTION pGenCompressionHeader;
	PEFI_FIRMWARE_VOLUME_HEADER pGenVolumeHeader;
	ULONG ulDatCheckSum;
	ULONG ulHeaderCheckSum;
	ULONG ulBufferSize;

	ulHeaderSize = 0;
	pEfiFirmWareVolumeExtHeader = NULL;
	bIsVolumeUnknow = TRUE;
	bAttribute = 0;
	ulCalcVolumeSize = 0;
	ulLocalVolumeSize = 0;
	bIsInvalidCheckSum = FALSE;
	ulVolumeOffset = 0;
	ulVolumeSize = 0;
	ulPreVolumeOffset = 0;
	ulPreVolumeSize = 0;
	ulCalcVolumeSize = 0;
	ulNextVolumeSize = 0;
	ulFileOffset = 0;
	pGuidName = NULL;
	ulCrc32FromZeroVector = 0;
	ulFreeSpaceOffsetFromZeroVector = 0;
	bVolumeHasZVCRC = FALSE;
	bVolumeHasZVFSO = FALSE;
	ulCrc32CheckSum = 0;
	pFileGuidName = NULL;
	pEfiFirmWareVolumeHeader = NULL;
	bIsBlink = FALSE;
	pGenEfiFfsFileHeader = NULL;
	pGenCommonSectionHeader = NULL;
	pEfiCommonSectionHeader = NULL;
	pCompressionHeader = NULL;
	pGenCompressionHeader = NULL;
	pGenVolumeHeader = NULL;
	ulDatCheckSum = 0;
	ulHeaderCheckSum = 0;
	ulBufferSize = 0;
	pCheckSumFfsFileHeader = 0;
	ulFillOffset = 0;
	RtlZeroMemory(ShowInfo,MAX_PATH);

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

		if (ALIGN8(pEfiFirmWareVolumeHeader->HeaderLength) > ulVolumeSize)
		{
			return FALSE;
		}
		if (pEfiFirmWareVolumeHeader->ExtHeaderOffset > 0 && \
			ulVolumeSize < ALIGN8(pEfiFirmWareVolumeHeader->ExtHeaderOffset + sizeof(EFI_FIRMWARE_VOLUME_EXT_HEADER)))
		{
			return FALSE;
		}
		if (pEfiFirmWareVolumeHeader->Revision > 1 && pEfiFirmWareVolumeHeader->ExtHeaderOffset)
		{
			pEfiFirmWareVolumeExtHeader = (PEFI_FIRMWARE_VOLUME_EXT_HEADER)((ULONG)pBIOSDat + ulVolumeOffset + pEfiFirmWareVolumeHeader->ExtHeaderOffset);
			ulHeaderSize = pEfiFirmWareVolumeHeader->ExtHeaderOffset + pEfiFirmWareVolumeExtHeader->ExtHeaderSize;
		}
		else
		{
			ulHeaderSize = pEfiFirmWareVolumeHeader->HeaderLength;
		}
		ulHeaderSize = ALIGN8(ulHeaderSize);
		bAttribute = pEfiFirmWareVolumeHeader->Attributes & EFI_FVB_ERASE_POLARITY ? '\xFF' : '\x00';
		if (GetVolumeSize((PCHAR)((ULONG)pBIOSDat + ulVolumeOffset),ulVolumeSize,0,&ulLocalVolumeSize,&ulCalcVolumeSize) == FALSE)
		{
			return FALSE;
		}
		ulCrc32FromZeroVector = *(ULONG*)(((ULONG)pBIOSDat + ulVolumeOffset) + 8);
		ulFreeSpaceOffsetFromZeroVector = *(ULONG*)(((ULONG)pBIOSDat + ulVolumeOffset) + 12);
		if (ulCrc32FromZeroVector != 0)
		{
			ulCrc32CheckSum = g_pUtils->CheckSum32((PCHAR)((ULONG)pBIOSDat + ulVolumeOffset),pEfiFirmWareVolumeHeader->HeaderLength,ulVolumeSize - pEfiFirmWareVolumeHeader->HeaderLength);
			if (ulCrc32CheckSum == ulCrc32FromZeroVector)
			{
				bVolumeHasZVCRC = TRUE;
			}
			if (ulFreeSpaceOffsetFromZeroVector != 0)
			{
				bVolumeHasZVFSO = TRUE;
			}
		}
		if (g_pUtils->CheckSum16((PCHAR)pEfiFirmWareVolumeHeader,0,pEfiFirmWareVolumeHeader->HeaderLength,0))
		{
			bIsInvalidCheckSum = TRUE;
		}
		pGuidName = g_pUtils->ConvertName((PCHAR)pEfiFirmWareVolumeHeader->FileSystemGuid.Data);
		StringCchPrintfA(ShowInfo,MAX_PATH,"%s Full Size:%d(%x) Header Size:%d(%x) Body Size:%d(%x) Revision:%d Attribute:%08x\n\n", \
			pGuidName,ulVolumeSize,ulVolumeSize,pEfiFirmWareVolumeHeader->HeaderLength,pEfiFirmWareVolumeHeader->HeaderLength, \
			ulVolumeSize - pEfiFirmWareVolumeHeader->HeaderLength,ulVolumeSize - pEfiFirmWareVolumeHeader->HeaderLength, \
			pEfiFirmWareVolumeHeader->Revision,pEfiFirmWareVolumeHeader->Attributes);
		printf(ShowInfo);
		if (pEfiFirmWareVolumeHeader->Revision > 1 && pEfiFirmWareVolumeHeader->ExtHeaderOffset)
		{
			pEfiFirmWareVolumeExtHeader = (PEFI_FIRMWARE_VOLUME_EXT_HEADER)((ULONG)pBIOSDat + ulVolumeOffset + pEfiFirmWareVolumeHeader->ExtHeaderOffset);
		}
		pFileBody = (PCHAR)((ULONG)pBIOSDat + ulVolumeOffset + pEfiFirmWareVolumeHeader->HeaderLength);
		ulFileOffset = ulHeaderSize;
		if (NULL != pReplaceSubModule && ulReplaceSubPos)
		{
			ulBootkitLength = GetReplaceModuleLength("BootLoader.Bin");
			do 
			{
				pBootkitDat = (PCHAR)malloc(ulBootkitLength);
			} while (NULL == pBootkitDat);
			RtlZeroMemory(pBootkitDat,ulBootkitLength);
			GetReplaceModuleDat("BootLoader.Bin",pBootkitDat,ulBootkitLength);

			pGenVolumeHeader = GenerateVolumeHeader(&pEfiFirmWareVolumeHeader->FileSystemGuid, \
				pEfiFirmWareVolumeHeader->FvLength, \
				pEfiFirmWareVolumeHeader->Attributes, \
				pEfiFirmWareVolumeHeader->HeaderLength, \
				0, \
				pEfiFirmWareVolumeHeader->ExtHeaderOffset, \
				pEfiFirmWareVolumeHeader->Revision);
			//pGenVolumeHeader->Checksum = g_pUtils->CheckSum16((PCHAR)pGenVolumeHeader,0,pGenVolumeHeader->HeaderLength,0);

			//ulReplaceSubPos = 0;
			RtlCopyMemory((PCHAR)((ULONG)pReplaceSubModule + ulReplaceSubPos),pGenVolumeHeader,sizeof(EFI_FIRMWARE_VOLUME_HEADER));
			//RtlCopyMemory((PCHAR)((ULONG)pReplaceSubModule + ulReplaceSubPos),(PCHAR)((ULONG)pBIOSDat + ulVolumeOffset),ulFileOffset);
			ulReplaceSubPos += sizeof(EFI_FIRMWARE_VOLUME_HEADER);

			pEfiFvBlockMapEntry = (PEFI_FV_BLOCK_MAP_ENTRY)((ULONG)pEfiFirmWareVolumeHeader + sizeof(EFI_FIRMWARE_VOLUME_HEADER));
			ulFvBlockSize = sizeof(EFI_FV_BLOCK_MAP_ENTRY);
			while (pEfiFvBlockMapEntry->Length != 0 && pEfiFvBlockMapEntry->NumBlocks != 0)
			{
				ulFvBlockSize += sizeof(EFI_FV_BLOCK_MAP_ENTRY);
				pEfiFvBlockMapEntry = (PEFI_FV_BLOCK_MAP_ENTRY)((ULONG)pEfiFvBlockMapEntry + sizeof(EFI_FV_BLOCK_MAP_ENTRY));
			}
			RtlCopyMemory((PCHAR)((ULONG)pReplaceSubModule + ulReplaceSubPos), \
				(PCHAR)((ULONG)pEfiFirmWareVolumeHeader + sizeof(EFI_FIRMWARE_VOLUME_HEADER)), \
				ulFvBlockSize);
			ulReplaceSubPos += ulFvBlockSize;
			//pReplaceSubModule = (PCHAR)((ULONG)pReplaceSubModule + sizeof(EFI_COMMON_SECTION_HEADER));
		}
		ulReplaceSubPos -= 4;
		pReplaceSubModule = (PCHAR)((ULONG)pReplaceSubModule + 4);
		while (ulFileOffset < ulVolumeSize)
		{
			if (ulVolumeSize - ulFileOffset < sizeof(EFI_FFS_FILE_HEADER))
			{
				break;
			}
			if (ulFileOffset != ulVolumeSize)
			{
				while (*(BYTE*)((ULONG)pBIOSDat + ulVolumeOffset + ulFileOffset) == 0xFF)
				{
					ulFileOffset++;
					pReplaceSubModule[ulReplaceSubPos] = 0xFF;
					ulReplaceSubPos++;
				}
			}
			ulFileSize = GetFileSize((PCHAR)((ULONG)pBIOSDat + ulVolumeOffset),ulVolumeSize,ulFileOffset);
			if (ulFileSize <= 0 || ulFileSize > ulVolumeSize)
			{
				return FALSE;
			}
			if (ulFileSize < sizeof(EFI_FFS_FILE_HEADER))
			{
				return FALSE;
			}
			pFileBody = (PCHAR)((ULONG)pBIOSDat + ulVolumeOffset + ulFileOffset);
			//ulFileDatSize = ulVolumeSize - ulFileOffset;
			pEfiFfsFileHeader = (PEFI_FFS_FILE_HEADER)pFileBody;

			pFileGuidName = g_pUtils->ConvertName((PCHAR)pEfiFfsFileHeader->Name.Data);
			printf("%s\n",pFileGuidName);
			if (strnicmp(pFileGuidName,"82FBE26B-53D4-448F-924C-7BE0126ECA4F",sizeof(EFI_GUID)) == 0 && \
				pEfiFfsFileHeader->Type == EFI_FV_FILETYPE_FREEFORM)
			{
				printf("Find 82FBE26B-53D4-448F-924C-7BE0126ECA4F\n");

				do 
				{
					pGenSubModule = (PCHAR)malloc(ulBootkitLength + 0x1000);
				} while (NULL == pGenSubModule);
				RtlZeroMemory(pGenSubModule,ulBootkitLength + 0x1000);

				pEfiCommonSectionHeader = (PEFI_COMMON_SECTION_HEADER)((ULONG)pFileBody + sizeof(EFI_FFS_FILE_HEADER));
				pCompressionHeader = (PEFI_COMPRESSION_SECTION)((ULONG)pFileBody + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMMON_SECTION_HEADER));
				WriteModule("82FBE26B-53D4-448F-924C-7BE0126ECA4F_FfsFileHeader.Bin",pFileBody,ulFileSize);
				
				WriteModule("82FBE26B-53D4-448F-924C-7BE0126ECA4F_CommonSection.Bin",(PCHAR)((ULONG)pFileBody + sizeof(EFI_FFS_FILE_HEADER)),ulFileSize - sizeof(EFI_FFS_FILE_HEADER));

				WriteModule("82FBE26B-53D4-448F-924C-7BE0126ECA4F_Compress.Bin", \
					(PCHAR)((ULONG)pFileBody + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMMON_SECTION_HEADER)), \
					ulFileSize - sizeof(EFI_FFS_FILE_HEADER) - sizeof(EFI_COMMON_SECTION_HEADER));

				WriteModule("82FBE26B-53D4-448F-924C-7BE0126ECA4F_Rom.Bin", \
					(PCHAR)((ULONG)pFileBody + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMPRESSION_SECTION) + sizeof(EFI_COMMON_SECTION_HEADER)), \
					ulFileSize - sizeof(EFI_FFS_FILE_HEADER) - sizeof(EFI_COMPRESSION_SECTION) - sizeof(EFI_COMMON_SECTION_HEADER));

				pGenEfiFfsFileHeader = GenerateFfsFileHeader(&pEfiFfsFileHeader->Name, \
					(PCHAR)g_pUtils->ULONG32ToULONG24(ulBootkitLength + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMPRESSION_SECTION) + sizeof(EFI_COMMON_SECTION_HEADER)), \
					pEfiFfsFileHeader->Type, \
					pEfiFfsFileHeader->Attributes, \
					pEfiFfsFileHeader->State);
				RtlCopyMemory(pGenSubModule, \
					pGenEfiFfsFileHeader, \
					sizeof(EFI_FFS_FILE_HEADER));

				pGenCommonSectionHeader = GenerateCommonSectionHeader((PCHAR)g_pUtils->ULONG32ToULONG24(ulBootkitLength + \
					sizeof(EFI_COMMON_SECTION_HEADER) + sizeof(EFI_COMPRESSION_SECTION)), \
					pEfiCommonSectionHeader->Type);
				RtlCopyMemory((PCHAR)((ULONG)pGenSubModule + sizeof(EFI_FFS_FILE_HEADER)), \
					pGenCommonSectionHeader,sizeof(EFI_COMMON_SECTION_HEADER));

				pGenCompressionHeader = GenerateCompressionHeader(g_pUtils->ULONG32ToULONG24(ulBootkitLength + sizeof(EFI_COMMON_SECTION_HEADER)), \
					pCompressionHeader->Type, \
					((ulBootkitLength + sizeof(EFI_COMMON_SECTION_HEADER)) << 8), \
					pCompressionHeader->CompressionType);
				RtlCopyMemory((PCHAR)((ULONG)pGenSubModule + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMMON_SECTION_HEADER)) \
					,pGenCompressionHeader,sizeof(EFI_COMPRESSION_SECTION));

				RtlCopyMemory((PCHAR)((ULONG)pGenSubModule + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMMON_SECTION_HEADER) + \
					sizeof(EFI_COMPRESSION_SECTION)), \
					pBootkitDat,ulBootkitLength);

				pCheckSumFfsFileHeader = (PEFI_FFS_FILE_HEADER)pGenSubModule;
				if (pCheckSumFfsFileHeader->Attributes & FFS_ATTRIB_CHECKSUM)
				{
					ulBufferSize = ulBootkitLength + sizeof(EFI_FFS_FILE_HEADER) + sizeof(EFI_COMMON_SECTION_HEADER) + sizeof(EFI_COMPRESSION_SECTION);
					ulBufferSize -= sizeof(EFI_FFS_FILE_HEADER);
					if (pCheckSumFfsFileHeader->Attributes & FFS_ATTRIB_TAIL_PRESENT)
					{
						ulBufferSize -= sizeof(UINT16);
					}
					ulDatCheckSum = g_pUtils->CheckSum8((PCHAR)((ULONG)pGenSubModule + sizeof(EFI_FFS_FILE_HEADER)),0,ulBufferSize,0);
					if (pCheckSumFfsFileHeader->IntegrityCheck.Checksum.File != ulDatCheckSum)
					{
						//pCheckSumFfsFileHeader->IntegrityCheck.Checksum.File = ulCheckSum;
					}
				}
				ulHeaderCheckSum = g_pUtils->CheckSum8((PCHAR)pCheckSumFfsFileHeader,0,sizeof(EFI_FFS_FILE_HEADER) - 1,0);
				if (g_pUtils->CheckSum8((PCHAR)pCheckSumFfsFileHeader,0,sizeof(EFI_FFS_FILE_HEADER),0) != 0)
				{
					pCheckSumFfsFileHeader->IntegrityCheck.Checksum.File = ulDatCheckSum;
					pCheckSumFfsFileHeader->IntegrityCheck.Checksum.Header = ulHeaderCheckSum;
				}
				if (bIsBlink == FALSE)
				{
					if (NULL != pReplaceSubModule && ulReplaceSubPos)
					{
						RtlCopyMemory((PCHAR)((ULONG)pReplaceSubModule + ulReplaceSubPos),pGenSubModule,ulBufferSize + sizeof(EFI_FFS_FILE_HEADER));
						//for (ULONG uli = (ulBufferSize + sizeof(EFI_FFS_FILE_HEADER));uli < ulFileSize;uli++)
						//{
						//	pReplaceSubModule[ulReplaceSubPos + uli] = 0xFF;
						//}
						//ulReplaceSubPos += ulFileSize;
						//ulReplaceSubPos = ALIGN8(ulReplaceSubPos);
						ulFileSize = ulBufferSize + sizeof(EFI_FFS_FILE_HEADER);
						bIsBlink = TRUE;
					}
				}
				//AnalyzeFile(pFileBody,ulFileSize,bAttribute == '\xFF' ? ERASE_POLARITY_TRUE : ERASE_POLARITY_FALSE,0,0,0,ulFileOffset,NULL);
			}
			else
			{
				if (ulReplaceSubPos + ulFileSize > ulBIOSSize)
				{
					break;
				}
				if (NULL != pReplaceSubModule && ulReplaceSubPos)
				{
					RtlCopyMemory((PCHAR)((ULONG)pReplaceSubModule + ulReplaceSubPos),(PCHAR)((ULONG)pBIOSDat + ulVolumeOffset + ulFileOffset),ulFileSize);
					//ulReplaceSubPos += ulFileSize;
					//ulReplaceSubPos = ALIGN8(ulReplaceSubPos);
				}
			}
			ulFileOffset += ulFileSize;
			ulFillOffset = ulFileOffset;
			ulFileOffset = ALIGN8(ulFileOffset);

			//ulReplaceSubPos += ulFileSize;
			//ulFillOffset = ulReplaceSubPos;
			ulReplaceSubPos = ulFileOffset;
			while (ulFillOffset < ulFileOffset)
			{
				pReplaceSubModule[ulFillOffset] = 0xFF;
				ulFillOffset++;
			}

			//ulIndex++;
		}
		ulReplaceSubPos += 4;
		pReplaceSubModule = (PCHAR)((ULONG)pReplaceSubModule - 4);
		if (bIsBlink)
		{
			RtlCopyMemory((PCHAR)((ULONG)pReplaceSubModule + ulReplaceSubPos),(PCHAR)((ULONG)pBIOSDat + ulVolumeOffset + ulFileOffset),0x24);
			ulReplaceSubPos += 0x24;

			pGenVolumeHeader->FvLength = ulReplaceSubPos - 0x04 - 0x24;

			((PEFI_FIRMWARE_VOLUME_HEADER)((ULONG)pReplaceSubModule + sizeof(EFI_COMMON_SECTION_HEADER)))->Checksum = 0;
			if (g_pUtils->CheckSum16((PCHAR)((ULONG)pReplaceSubModule + sizeof(EFI_COMMON_SECTION_HEADER)),0,pGenVolumeHeader->HeaderLength,0))
			{
				//pGenVolumeHeader->Checksum = g_pUtils->CheckSum16((PCHAR)pGenVolumeHeader,0,pGenVolumeHeader->HeaderLength,0);
				((PEFI_FIRMWARE_VOLUME_HEADER)((ULONG)pReplaceSubModule + sizeof(EFI_COMMON_SECTION_HEADER)))->Checksum = \
					g_pUtils->CheckSum16((PCHAR)((ULONG)pReplaceSubModule + sizeof(EFI_COMMON_SECTION_HEADER)),0,pGenVolumeHeader->HeaderLength,0);
			}
			//RtlCopyMemory((PCHAR)((ULONG)pReplaceSubModule + 4),pGenVolumeHeader,sizeof(EFI_FIRMWARE_VOLUME_HEADER));
			WriteModule("AE717C2F-1A42-4F2B-8861-78B79CA07E07_UnCompress.Bin", \
				(PCHAR)((ULONG)pReplaceSubModule/* - sizeof(EFI_COMMON_SECTION_HEADER)*/),ulReplaceSubPos/* + sizeof(EFI_COMMON_SECTION_HEADER)*/);
		}
		ulVolumeOffset += ulVolumeSize;
		ulPreVolumeSize = MyFindNextVolume(pBIOSDat,ulBIOSSize - ulVolumeOffset,ulVolumeOffset);
		if (-1 == ulPreVolumeSize)
		{
			printf("FindNextVolume Failed\n");
			break;
		}
	}
	return TRUE;
}

PCHAR CEFIBIOSANALYZE::GetSectionType(ULONG ulType)
{
	PCHAR pRetDescription;

	pRetDescription = NULL;

	do 
	{
		pRetDescription = (PCHAR)malloc(MAX_PATH);
	} while (NULL == pRetDescription);
	RtlZeroMemory(pRetDescription,MAX_PATH);
	switch (ulType)
	{
	case EFI_SECTION_COMPRESSION:
		StringCchCopyA(pRetDescription,MAX_PATH,"压缩段");
		break;
	case EFI_SECTION_GUID_DEFINED:
		StringCchCopyA(pRetDescription,MAX_PATH,"GUID 定义段");
		break;
	case EFI_SECTION_DISPOSABLE:
		StringCchCopyA(pRetDescription,MAX_PATH,"Disposable");
		break;
	case EFI_SECTION_PE32:
		StringCchCopyA(pRetDescription,MAX_PATH,"PE32+ 映像段");
		break;
	case EFI_SECTION_PIC:
		StringCchCopyA(pRetDescription,MAX_PATH,"PIC 映像段");
		break;
	case EFI_SECTION_TE:
		StringCchCopyA(pRetDescription,MAX_PATH,"(TE) 映像段");
		break;
	case EFI_SECTION_DXE_DEPEX:
		StringCchCopyA(pRetDescription,MAX_PATH,"DXE Dependency");
		break;
	case EFI_SECTION_VERSION:
		StringCchCopyA(pRetDescription,MAX_PATH,"版本段");
		break;
	case EFI_SECTION_USER_INTERFACE:
		StringCchCopyA(pRetDescription,MAX_PATH,"用户接口");
		break;
	case EFI_SECTION_COMPATIBILITY16:
		StringCchCopyA(pRetDescription,MAX_PATH,"16位 映像段");
		break;
	case EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
		StringCchCopyA(pRetDescription,MAX_PATH,"固件卷映像段");
		break;
	case EFI_SECTION_FREEFORM_SUBTYPE_GUID:
		StringCchCopyA(pRetDescription,MAX_PATH,"任意形态子类型 GUID 段");
		break;
	case EFI_SECTION_RAW:
		StringCchCopyA(pRetDescription,MAX_PATH,"Raw 段");
		break;
	case EFI_SECTION_PEI_DEPEX:
		StringCchCopyA(pRetDescription,MAX_PATH,"PEI Dependency");
		break;
	case EFI_SECTION_SMM_DEPEX:
		StringCchCopyA(pRetDescription,MAX_PATH,"SMM Dependency");
		break;
	case INSYDE_SECTION_POSTCODE:
		StringCchCopyA(pRetDescription,MAX_PATH,"Insyde PostCode");
		break;
	case SCT_SECTION_POSTCODE:
		StringCchCopyA(pRetDescription,MAX_PATH,"SCT PostCode");
		break;
	default:
		StringCchCopyA(pRetDescription,MAX_PATH,"未知段");
		break;
	}
	return pRetDescription;
}

BOOLEAN CEFIBIOSANALYZE::DeCompress(PCHAR pCompressedDat, ULONG ulCompressedDatSize, BYTE bCompressionType, PCHAR* pOutDecompressedDat, ULONG* ulOutDecompressSize, BYTE* bAlgorithm)
{
	PCHAR pScratch;
	ULONG ulScratchSize;
	PCHAR pDat;
	ULONG ulDatSize;
	PEFI_TIANO_HEADER pEfiTianoHeader;

	pScratch = NULL;
	ulScratchSize = 0;
	pEfiTianoHeader = NULL;
	pDat = NULL;
	ulDatSize = 0;

	switch (bCompressionType)
	{
	case EFI_NOT_COMPRESSED:
		{
			do 
			{
				*pOutDecompressedDat = (PCHAR)malloc(ulCompressedDatSize);
			} while (NULL == *pOutDecompressedDat);
			RtlZeroMemory(*pOutDecompressedDat,ulCompressedDatSize);
			*ulOutDecompressSize = ulCompressedDatSize;
			RtlCopyMemory(*pOutDecompressedDat,pCompressedDat,ulCompressedDatSize);
			if (bAlgorithm)
			{
				*bAlgorithm = COMPRESSION_ALGORITHM_NONE;
			}
			return TRUE;
		}
		break;
	case EFI_STANDARD_COMPRESSION:
		{
			pEfiTianoHeader = (PEFI_TIANO_HEADER)pCompressedDat;
			if (pEfiTianoHeader->CompSize + sizeof(EFI_TIANO_HEADER) != ulCompressedDatSize)
			{
				return FALSE;
			}
			if (ERR_SUCCESS != EfiTianoGetInfo(pCompressedDat,ulCompressedDatSize,(UINT32*)ulOutDecompressSize,(UINT32*)&ulScratchSize))
			{
				return FALSE;
			}
			do 
			{
				*pOutDecompressedDat = (PCHAR)malloc(*ulOutDecompressSize);
			} while (NULL == *pOutDecompressedDat);
			RtlZeroMemory(*pOutDecompressedDat,*ulOutDecompressSize);
			do 
			{
				pScratch = (PCHAR)malloc(ulScratchSize);
			} while (NULL == pScratch);
			RtlZeroMemory(pScratch,ulScratchSize);
			if (ERR_SUCCESS != TianoDecompress(pCompressedDat,ulCompressedDatSize,*pOutDecompressedDat,*ulOutDecompressSize,pScratch,ulScratchSize))
			{
				if (ERR_SUCCESS != EfiDecompress(pCompressedDat,ulCompressedDatSize,*pOutDecompressedDat,*ulOutDecompressSize,pScratch,ulScratchSize))
				{
					if (bAlgorithm)
					{
						*bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
					}
					if (pScratch)
					{
						free(pScratch);
						pScratch = NULL;
						ulScratchSize = 0;
					}
					if (*pOutDecompressedDat)
					{
						free(*pOutDecompressedDat);
						*pOutDecompressedDat = NULL;
						*ulOutDecompressSize = 0;
					}
					return FALSE;
				}
				else
				{
					if (bAlgorithm)
					{
						*bAlgorithm = COMPRESSION_ALGORITHM_EFI11;
					}
				}
			}
			else
			{
				if (bAlgorithm)
				{
					*bAlgorithm = COMPRESSION_ALGORITHM_TIANO;
				}
			}
			return TRUE;
		}
		break;
	case EFI_CUSTOMIZED_COMPRESSION:
		{
			PEFI_COMMON_SECTION_HEADER pShittySectionHeader;
			ULONG ulShittySectionSize;

			pDat = pCompressedDat;
			ulDatSize = ulCompressedDatSize;
			if (ERR_SUCCESS != LzmaGetInfo(pDat,ulDatSize,(UINT32*)ulOutDecompressSize))
			{
				return FALSE;
			}
			do 
			{
				*pOutDecompressedDat = (PCHAR)malloc(*ulOutDecompressSize);
			} while (NULL == *pOutDecompressedDat);
			RtlZeroMemory(*pOutDecompressedDat,*ulOutDecompressSize);
			if (ERR_SUCCESS != LzmaDecompress(pDat,ulDatSize,*pOutDecompressedDat))
			{
				pShittySectionHeader = (PEFI_COMMON_SECTION_HEADER)pCompressedDat;
				ulShittySectionSize = SizeOfSectionHeader(pShittySectionHeader);
				pDat = (PCHAR)((ULONG)pDat + ulShittySectionSize);
				if (ERR_SUCCESS != LzmaGetInfo(pDat,ulDatSize,(UINT32*)ulOutDecompressSize))
				{
					if (*pOutDecompressedDat)
					{
						free(*pOutDecompressedDat);
						*pOutDecompressedDat = NULL;
					}
					return FALSE;
				}
				if (ERR_SUCCESS != LzmaDecompress(pDat,ulDatSize,*pOutDecompressedDat))
				{
					if (bAlgorithm)
					{
						*bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
					}
					if (*pOutDecompressedDat)
					{
						free(*pOutDecompressedDat);
						*pOutDecompressedDat = NULL;
					}
					return FALSE;
				}
				else
				{
					if (bAlgorithm)
					{
						*bAlgorithm = COMPRESSION_ALGORITHM_IMLZMA;
					}
				}
			}
			else
			{
				if (bAlgorithm)
				{
					*bAlgorithm = COMPRESSION_ALGORITHM_IMLZMA;
				}
			}
			return TRUE;
		}
		break;
	default:
		if (bAlgorithm)
		{
			*bAlgorithm = COMPRESSION_ALGORITHM_UNKNOWN;
		}
		break;
	}
	return FALSE;
}


ULONG CEFIBIOSANALYZE::SizeOfSectionHeader(PEFI_COMMON_SECTION_HEADER pSectionHeader)
{
	BOOLEAN bExtended;
	PEFI_GUID_DEFINED_SECTION pEfiGuidDefinedSection;
	PEFI_GUID_DEFINED_SECTION2 pEfiGuidDefinedSection2;
	PCHAR pGuidName;
	PWIN_CERTIFICATE pCertificateHeader;

	bExtended = FALSE;
	pEfiGuidDefinedSection = NULL;
	pEfiGuidDefinedSection2 = NULL;
	pGuidName = NULL;
	pCertificateHeader = NULL;

	if (NULL == pSectionHeader)
	{
		return 0;
	}
	switch (pSectionHeader->Type)
	{
	case EFI_SECTION_GUID_DEFINED:
		{
			if (FALSE == bExtended)
			{
				pEfiGuidDefinedSection = (PEFI_GUID_DEFINED_SECTION)pSectionHeader;
				pGuidName = g_pUtils->ConvertName((PCHAR)pEfiGuidDefinedSection->SectionDefinitionGuid.Data);
				if (strnicmp(pGuidName,EFI_FIRMWARE_CONTENTS_SIGNED_GUID,strlen(EFI_FIRMWARE_CONTENTS_SIGNED_GUID)) == 0)
				{
					pCertificateHeader = (PWIN_CERTIFICATE)((ULONG)pEfiGuidDefinedSection + sizeof(WIN_CERTIFICATE));
					return pEfiGuidDefinedSection->DataOffset + pCertificateHeader->Length;
				}
				return pEfiGuidDefinedSection->DataOffset;
			}
			else
			{
				pEfiGuidDefinedSection2 = (PEFI_GUID_DEFINED_SECTION2)pSectionHeader;
				pGuidName = g_pUtils->ConvertName((PCHAR)pEfiGuidDefinedSection2->SectionDefinitionGuid.Data);
				if (strnicmp(pGuidName,EFI_FIRMWARE_CONTENTS_SIGNED_GUID,strlen(EFI_FIRMWARE_CONTENTS_SIGNED_GUID)) == 0)
				{
					pCertificateHeader = (PWIN_CERTIFICATE)((ULONG)pEfiGuidDefinedSection2 + sizeof(WIN_CERTIFICATE));
					return pEfiGuidDefinedSection2->DataOffset + pCertificateHeader->Length;
				}
				return pEfiGuidDefinedSection2->DataOffset;
			}
		}
	case EFI_SECTION_COMPRESSION:
		{
			return bExtended ? sizeof(EFI_COMPRESSION_SECTION2) : sizeof(EFI_COMPRESSION_SECTION);
		}
	case EFI_SECTION_DISPOSABLE:
		{
			return bExtended ? sizeof(EFI_DISPOSABLE_SECTION2) : sizeof(EFI_DISPOSABLE_SECTION);
		}
	case EFI_SECTION_PE32:
		{
			return bExtended ? sizeof(EFI_PE32_SECTION2) : sizeof(EFI_PE32_SECTION);
		}
	case EFI_SECTION_PIC:
		{
		return bExtended ? sizeof(EFI_PIC_SECTION2) : sizeof(EFI_PIC_SECTION);
		}
	case EFI_SECTION_TE:
		{
			return bExtended ? sizeof(EFI_TE_SECTION2) : sizeof(EFI_TE_SECTION);
		}
		
	case EFI_SECTION_DXE_DEPEX:
		{
			return bExtended ? sizeof(EFI_DXE_DEPEX_SECTION2) : sizeof(EFI_DXE_DEPEX_SECTION);
		}
	case EFI_SECTION_VERSION:
		{
			return bExtended ? sizeof(EFI_VERSION_SECTION2) : sizeof(EFI_VERSION_SECTION);
		}
	case EFI_SECTION_USER_INTERFACE:
		{
			return bExtended ? sizeof(EFI_USER_INTERFACE_SECTION2) : sizeof(EFI_USER_INTERFACE_SECTION);
		}
	case EFI_SECTION_COMPATIBILITY16:
		{
			return bExtended ? sizeof(EFI_COMPATIBILITY16_SECTION2) : sizeof(EFI_COMPATIBILITY16_SECTION);
		}
	case EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
		{
			return bExtended ? sizeof(EFI_FIRMWARE_VOLUME_IMAGE_SECTION2) : sizeof(EFI_FIRMWARE_VOLUME_IMAGE_SECTION);
		}
	case EFI_SECTION_FREEFORM_SUBTYPE_GUID:
		{
			return bExtended ? sizeof(EFI_FREEFORM_SUBTYPE_GUID_SECTION2) : sizeof(EFI_FREEFORM_SUBTYPE_GUID_SECTION);
		}
	case EFI_SECTION_RAW:
		{
			return bExtended ? sizeof(EFI_RAW_SECTION2) : sizeof(EFI_RAW_SECTION);
		}
	case EFI_SECTION_PEI_DEPEX:
		{
			return bExtended ? sizeof(EFI_PEI_DEPEX_SECTION2) : sizeof(EFI_PEI_DEPEX_SECTION);
		}
	case EFI_SECTION_SMM_DEPEX:
		{
			return bExtended ? sizeof(EFI_SMM_DEPEX_SECTION2) : sizeof(EFI_SMM_DEPEX_SECTION);
		}
	case INSYDE_SECTION_POSTCODE:
		{
			return bExtended ? sizeof(POSTCODE_SECTION2) : sizeof(POSTCODE_SECTION);
		}
	case SCT_SECTION_POSTCODE:
		{
			return bExtended ? sizeof(POSTCODE_SECTION2) : sizeof(POSTCODE_SECTION);
		}
	default:
		{
			return bExtended ? sizeof(EFI_COMMON_SECTION_HEADER2) : sizeof(EFI_COMMON_SECTION_HEADER);
		}
	}
	return 0;
}


PCHAR CEFIBIOSANALYZE::CompressionTypeToPCHAR(BYTE bAlgorithm)
{
	PCHAR pRetDescription;

	pRetDescription = NULL;

	do 
	{
		pRetDescription = (PCHAR)malloc(MAX_PATH);
	} while (NULL == pRetDescription);
	RtlZeroMemory(pRetDescription,MAX_PATH);
	switch (bAlgorithm)
	{
	case COMPRESSION_ALGORITHM_NONE:
		StringCchCopyA(pRetDescription,MAX_PATH,"None");
		break;
	case COMPRESSION_ALGORITHM_EFI11:
		StringCchCopyA(pRetDescription,MAX_PATH,"EFI 1.1");
		break;
	case COMPRESSION_ALGORITHM_TIANO:
		StringCchCopyA(pRetDescription,MAX_PATH,"Tiano");
		break;
	case COMPRESSION_ALGORITHM_LZMA:
		StringCchCopyA(pRetDescription,MAX_PATH,"LZMA");
		break;
	case COMPRESSION_ALGORITHM_IMLZMA:
		StringCchCopyA(pRetDescription,MAX_PATH,"Intel modified LZMA");
		break;
	default:
		StringCchCopyA(pRetDescription,MAX_PATH,"Unknown");
		break;
	}
	return pRetDescription;
}


BOOLEAN CEFIBIOSANALYZE::AnalyzeDepexSection(PCHAR pSectionBody, ULONG ulSectionBodySize, PCHAR* pStrDesc)
{
	PEFI_GUID pEfiGuid;
	PBYTE pCurrent;
	PCHAR pGuidName;
	ULONG ulBodySize;
	CHAR TmpShowInfo[MAX_PATH];

	pEfiGuid = NULL;
	pCurrent = NULL;
	pGuidName = NULL;

	RtlZeroMemory(TmpShowInfo,MAX_PATH);
	if (NULL == pSectionBody || 0 >= ulSectionBodySize)
	{
		return FALSE;
	}
	do 
	{
		*pStrDesc = (PCHAR)malloc(MAX_PATH);
	} while (NULL == *pStrDesc);
	RtlZeroMemory(*pStrDesc,MAX_PATH);
	pCurrent = (PBYTE)pSectionBody;
	switch (*pCurrent)
	{
	case EFI_DEP_BEFORE:
		{
			if (ulSectionBodySize != 2 * EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID))
			{
				return FALSE;
			}
			pEfiGuid = (PEFI_GUID)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
			pGuidName = g_pUtils->ConvertName((PCHAR)pEfiGuid->Data);
			StringCchPrintfA(TmpShowInfo,MAX_PATH,"BEFORE %s\n",pGuidName);
			pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID));
			if (*pCurrent != EFI_DEP_END)
			{
				return FALSE;
			}
			return TRUE;
		}
		break;
	case EFI_DEP_AFTER:
		{
			if (ulSectionBodySize != 2 * EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID))
			{
				return FALSE;
			}
			pEfiGuid = (PEFI_GUID)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
			StringCchPrintfA(TmpShowInfo,MAX_PATH,"AFTER %s\n",pGuidName);
			pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID));
			if (*pCurrent != EFI_DEP_END)
			{
				return FALSE;
			}
			return TRUE;
		}
		break;
	case EFI_DEP_SOR:
		{
			if (ulSectionBodySize != 2 * EFI_DEP_OPCODE_SIZE)
			{
				return FALSE;
			}
			StringCchPrintfA(TmpShowInfo,MAX_PATH,"SOR\n");
			pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
		}
		break;
	default:
		break;
	}
	while ((ULONG)pCurrent - (ULONG)pSectionBody < ulSectionBodySize)
	{
		switch (*pCurrent)
		{
		case EFI_DEP_BEFORE:
		case EFI_DEP_AFTER:
		case EFI_DEP_SOR:
			{
				return FALSE;
			}
		case EFI_DEP_PUSH:
			{
				if (ulSectionBodySize - ((ULONG)pCurrent - (ULONG)pSectionBody) <= EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID))
				{
					return FALSE;
				}
				pEfiGuid = (PEFI_GUID)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
				pGuidName = g_pUtils->ConvertName((PCHAR)pEfiGuid->Data);
				StringCchCatA(TmpShowInfo,MAX_PATH,"\nPUSH:");
				StringCchCatA(TmpShowInfo,MAX_PATH,pGuidName);
				StringCchCatA(TmpShowInfo,MAX_PATH,"\n");
				pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID));
			}
			break;
		case EFI_DEP_AND:
			{

				StringCchCatA(TmpShowInfo,MAX_PATH,"AND\n");
				pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
			}
			break;
		case EFI_DEP_OR:
			{
				StringCchCatA(TmpShowInfo,MAX_PATH,"OR\n");
				pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
			}
			break;
		case EFI_DEP_NOT:
			{
				StringCchCatA(TmpShowInfo,MAX_PATH,"NOT\n");
				pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
			}
			break;
		case EFI_DEP_TRUE:
			{
				StringCchCatA(TmpShowInfo,MAX_PATH,"TRUE\n");
				pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
			}
			break;
		case EFI_DEP_FALSE:
			{
				StringCchCatA(TmpShowInfo,MAX_PATH,"FALSE\n");
				pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
			}
			break;
		case EFI_DEP_END:
			{
				StringCchCatA(TmpShowInfo,MAX_PATH,"END\n");
				pCurrent = (PBYTE)((ULONG)pCurrent + EFI_DEP_OPCODE_SIZE);
				if ((ULONG)pCurrent - (ULONG)pSectionBody < ulSectionBodySize)
				{
					return FALSE;
				}
			}
			break;
		default:
			return FALSE;
			break;
		}
	}
	StringCchCopyA(*pStrDesc,MAX_PATH,TmpShowInfo);
	return TRUE;
}


PCHAR CEFIBIOSANALYZE::AnalyzeAprioriRawSection(PCHAR pRawSectionBody, ULONG ulRawSectionSize, ULONG *ulOutCount)
{
	ULONG ulCount;
	PCHAR pRetStr;
	ULONG uli;
	PEFI_GUID pEfiGuid;
	PCHAR pGuidName;

	ulCount = 0;
	pRetStr = NULL;
	pGuidName = NULL;

	ulCount = ulRawSectionSize / sizeof(EFI_GUID);
	do 
	{
		pRetStr = (PCHAR)malloc(ulCount * sizeof(EFI_GUID));
	} while (NULL == pRetStr);
	RtlZeroMemory(pRetStr,ulCount * sizeof(EFI_GUID));
	
	if (ulCount > 0)
	{
		for (uli = 0;uli < ulCount;uli++)
		{
			pEfiGuid = (PEFI_GUID)((ULONG)pRawSectionBody + uli * sizeof(EFI_GUID));
			pGuidName = g_pUtils->ConvertName((PCHAR)pEfiGuid->Data);
			StringCchCatA(pRetStr,ulCount * sizeof(EFI_GUID),pGuidName);
		}
	}
	*ulOutCount = uli;
	return pRetStr;
}


BOOLEAN CEFIBIOSANALYZE::ReplaceModule(PCHAR pGuidName, PCHAR pReplaceGuidName, PVOID pReplaceModule, ULONG ulReplaceSize)
{
	if (strnicmp(pGuidName,pReplaceGuidName,sizeof(EFI_GUID)) == 0)
	{
		printf("Find Replace Module\n");
		return TRUE;
	}
	return FALSE;
}


BOOLEAN CEFIBIOSANALYZE::WriteModule(PCHAR pFileName, PVOID pWriteDat, ULONG ulWriteSize)
{
	HANDLE hFile;
	CHAR WriteName[MAX_PATH];
	ULONG ulRetBytesWrite;
	BOOLEAN bRet;

	hFile = INVALID_HANDLE_VALUE;
	ulRetBytesWrite = 0;
	bRet = FALSE;
	RtlZeroMemory(WriteName,sizeof(CHAR) * MAX_PATH);

	do 
	{
		GetCurrentDirectory(MAX_PATH,WriteName);
		StringCchCatA(WriteName,MAX_PATH,"\\");
		StringCchCatA(WriteName,MAX_PATH,pFileName);

		hFile = CreateFile(WriteName, \
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
		bRet = WriteFile(hFile,pWriteDat,ulWriteSize,&ulRetBytesWrite,NULL);
		if (FALSE == bRet)
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


PEFI_FFS_FILE_HEADER CEFIBIOSANALYZE::GenerateFfsFileHeader(PEFI_GUID pFfsGuid, PCHAR pSize, BYTE bType, BYTE bAttributes,BYTE bState)
{
	PEFI_FFS_FILE_HEADER pEfiFfsFileHeader;

	pEfiFfsFileHeader = NULL;

	do 
	{
		pEfiFfsFileHeader = (PEFI_FFS_FILE_HEADER)malloc(sizeof(EFI_FFS_FILE_HEADER));
	} while (NULL == pEfiFfsFileHeader);
	RtlZeroMemory(pEfiFfsFileHeader,sizeof(EFI_FFS_FILE_HEADER));
	RtlCopyMemory(&pEfiFfsFileHeader->Name,pFfsGuid,sizeof(EFI_GUID));
	pEfiFfsFileHeader->Size[2] = pSize[2];
	pEfiFfsFileHeader->Size[1] = pSize[1];
	pEfiFfsFileHeader->Size[0] = pSize[0];
	pEfiFfsFileHeader->Type = bType;
	pEfiFfsFileHeader->Attributes = bAttributes;
	pEfiFfsFileHeader->State = bState;
	return pEfiFfsFileHeader;
}


PEFI_COMMON_SECTION_HEADER CEFIBIOSANALYZE::GenerateCommonSectionHeader(PCHAR pSize, BYTE bType)
{
	PEFI_COMMON_SECTION_HEADER pEfiCommonSectionHeader;

	pEfiCommonSectionHeader = NULL;

	do 
	{
		pEfiCommonSectionHeader = (PEFI_COMMON_SECTION_HEADER)malloc(sizeof(EFI_COMMON_SECTION_HEADER));
	} while (NULL == pEfiCommonSectionHeader);
	RtlZeroMemory(pEfiCommonSectionHeader,sizeof(EFI_COMMON_SECTION_HEADER));
	pEfiCommonSectionHeader->Size[2] = pSize[2];
	pEfiCommonSectionHeader->Size[1] = pSize[1];
	pEfiCommonSectionHeader->Size[0] = pSize[0];
	pEfiCommonSectionHeader->Type = bType;
	return pEfiCommonSectionHeader;
}


PEFI_COMPRESSION_SECTION CEFIBIOSANALYZE::GenerateCompressionHeader(PCHAR pSize, BYTE bType, ULONG ulUncompressedLength,BYTE bCompressionType)
{
	PEFI_COMPRESSION_SECTION pEfiCompressionSection;

	pEfiCompressionSection = NULL;

	do 
	{
		pEfiCompressionSection = (PEFI_COMPRESSION_SECTION)malloc(sizeof(EFI_COMPRESSION_SECTION));
	} while (NULL == pEfiCompressionSection);
	RtlZeroMemory(pEfiCompressionSection,sizeof(EFI_COMPRESSION_SECTION));
	pEfiCompressionSection->Size[2] = pSize[2];
	pEfiCompressionSection->Size[1] = pSize[1];
	pEfiCompressionSection->Size[0] = pSize[0];
	pEfiCompressionSection->Type = bType;
	pEfiCompressionSection->UncompressedLength = ulUncompressedLength;
	pEfiCompressionSection->CompressionType = bCompressionType;
	return pEfiCompressionSection;
}


ULONG CEFIBIOSANALYZE::GetReplaceModuleLength(PCHAR pFileName)
{
	HANDLE hFile;
	ULONG ulFileSize;

	ulFileSize = 0;
	hFile = INVALID_HANDLE_VALUE;

	do 
	{
		hFile = CreateFile(pFileName, \
			FILE_ALL_ACCESS, \
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, \
			NULL, \
			OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, \
			NULL);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			break;
		}
		ulFileSize = ::GetFileSize(hFile,NULL);
		if (INVALID_FILE_SIZE == ulFileSize)
		{
			break;
		}
	} while (0);
	if (hFile)
	{
		CloseHandle(hFile);
	}
	return ulFileSize;
}


BOOLEAN CEFIBIOSANALYZE::GetReplaceModuleDat(PCHAR pFileName, PCHAR pReplaceDat, ULONG ulSize)
{
	BOOLEAN bRet;
	HANDLE hFile;
	ULONG ulRetBytesSize;

	bRet = FALSE;
	ulRetBytesSize = 0;
	hFile = INVALID_HANDLE_VALUE;

	do 
	{
		hFile = CreateFile(pFileName, \
			FILE_ALL_ACCESS, \
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, \
			NULL, \
			OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, \
			NULL);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			break;
		}
		bRet = ReadFile(hFile,pReplaceDat,ulSize,&ulRetBytesSize,NULL);
		if (FALSE == bRet)
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


PEFI_FIRMWARE_VOLUME_HEADER CEFIBIOSANALYZE::GenerateVolumeHeader(PEFI_GUID pEfiGuid,ULONG64 ulFvLength,ULONG ulAttributes,USHORT uHeaderLength, \
																  USHORT uChecksum,USHORT uExtHeaderOffset,BYTE bRevision)
{
	PEFI_FIRMWARE_VOLUME_HEADER pEfiFirmwareVolumeHeader;

	pEfiFirmwareVolumeHeader = NULL;

	do 
	{
		pEfiFirmwareVolumeHeader = (PEFI_FIRMWARE_VOLUME_HEADER)malloc(sizeof(EFI_FIRMWARE_VOLUME_HEADER));
	} while (NULL == pEfiFirmwareVolumeHeader);
	RtlZeroMemory(pEfiFirmwareVolumeHeader,sizeof(EFI_FIRMWARE_VOLUME_HEADER));
	RtlCopyMemory(&pEfiFirmwareVolumeHeader->FileSystemGuid,pEfiGuid,sizeof(EFI_GUID));
	pEfiFirmwareVolumeHeader->FvLength = ulFvLength;
	pEfiFirmwareVolumeHeader->Attributes = ulAttributes;
	pEfiFirmwareVolumeHeader->HeaderLength = uHeaderLength;
	pEfiFirmwareVolumeHeader->Checksum = uChecksum;
	pEfiFirmwareVolumeHeader->ExtHeaderOffset = uExtHeaderOffset;
	//pEfiFirmwareVolumeHeader->Signature = (ULONG)EFI_FV_SIGNATURE;
	RtlCopyMemory(&pEfiFirmwareVolumeHeader->Signature,EFI_FV_SIGNATURE,sizeof(ULONG));
	pEfiFirmwareVolumeHeader->Revision = bRevision;
	return pEfiFirmwareVolumeHeader;
}