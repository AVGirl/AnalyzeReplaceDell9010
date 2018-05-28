#pragma once
#include "AnalyzeReplaceDell9010.h"
class CEFIBIOSANALYZE
{
public:
	CEFIBIOSANALYZE(void);
	~CEFIBIOSANALYZE(void);
	ULONG MyLzmaCompress(PUCHAR pDestDat, ULONG *ulDestSize, PUCHAR pSrcDat, ULONG ulSrcSize);
	ULONG MyLzmaUnCompress(PUCHAR pDestDat,PUCHAR pSrcDat,ULONG ulSrcSize);
	BOOLEAN IsValidEFIFVH(PCHAR pBIOSRom, ULONG ulRomSize, ULONG ulOffset, BOOLEAN bVerbose);
	BOOLEAN IsValidHeaderEFI(PCHAR pEfiDat, ULONG ulEfiLength, ULONG ulOffset, BOOLEAN bVerbose);
	BOOLEAN GetVolumeSize(PCHAR pRomDat, ULONG ulRomSize, ULONG ulOffset, ULONG* ulVolumeSize, ULONG* ulCalcVolumeSize);
	BOOLEAN AnalyzeVolume(PCHAR pVolumeDat, ULONG ulOffset, ULONG ulVolumeSize, ULONG ulParentIndex, PREPLACE_UEFI_SECTION pUefiSection);
	BOOLEAN AnalyzeVolume2(PCHAR pVolumeDat, ULONG ulVolumeSize, BOOLEAN bIsReplace);
	ULONG GetFileSize(PCHAR pVolumeDat, ULONG ulVolumeSize, ULONG ulOffset);
	BOOLEAN AnalyzeFile(PCHAR pFileDat, ULONG ulFileSize, BOOLEAN bErasePolarity, ULONG ulParentIndex,ULONG ulIndex,BOOLEAN bMode,ULONG ulBaseOffset,PREPLACE_UEFI_FILE pUefiFile);
	BOOLEAN AnalyzeFile2(PCHAR pFileDat, ULONG ulFileSize,BOOLEAN bIsReplace);
	PCHAR GetGUIDName(PCHAR pGuid);
	BOOLEAN AnalyzeSections(PCHAR pBodySection, ULONG ulBodySectionSize, ULONG ulParentIndex, ULONG ulIndex, PCHAR pParentGuid);
	ULONG GetSectionSize(PCHAR pBody, ULONG ulBodySize, ULONG ulSectionOffset);
	BOOLEAN AnalyzeSection(PCHAR pSection, ULONG ulSectionSize, ULONG ulParentIndex, ULONG ulIndex, PCHAR pParentGuid);
	BOOLEAN AnalyzeSections2(PCHAR pBodySection, ULONG ulBodySectionSize, PCHAR pParentGuid);
	BOOLEAN AnalyzeSection2(PCHAR pSection, ULONG ulSectionSize, PCHAR pParentGuid);
	PCHAR GetSectionType(ULONG ulType);
	BOOLEAN DeCompress(PCHAR pCompressedDat, ULONG ulCompressedDatSize, BYTE bCompressionType, PCHAR* pOutDecompressedDat, ULONG* ulOutDecompressSize, BYTE* bAlgorithm);
	ULONG SizeOfSectionHeader(PEFI_COMMON_SECTION_HEADER pSectionHeader);
	PCHAR CompressionTypeToPCHAR(BYTE bAlgorithm);
	BOOLEAN AnalyzeDepexSection(PCHAR pSectionBody, ULONG ulSectionBodySize, PCHAR* pStrDesc);
	PCHAR AnalyzeAprioriRawSection(PCHAR pRawSectionBody, ULONG ulRawSectionSize, ULONG *ulOutCount);
	BOOLEAN ReplaceModule(PCHAR pGuidName, PCHAR pReplaceGuidName, PVOID pReplaceModule, ULONG ulReplaceSize);
	BOOLEAN WriteModule(PCHAR pFileName, PVOID pWriteDat, ULONG ulWriteSize);
	ULONG MyFindNextVolume(PCHAR pBIOSDat, ULONG ulSize, ULONG ulOffset);
	BOOLEAN AnalyzeReplaceModule(PCHAR pBIOSDat, ULONG ulBIOSSize);
	PEFI_FFS_FILE_HEADER GenerateFfsFileHeader(PEFI_GUID pFfsGuid, PCHAR pSize, BYTE bType, BYTE bAttributes,BYTE bState);
	PEFI_COMMON_SECTION_HEADER GenerateCommonSectionHeader(PCHAR pSize, BYTE bType);
	PEFI_COMPRESSION_SECTION GenerateCompressionHeader(PCHAR pSize, BYTE bType, ULONG ulUncompressedLength,BYTE bCompressionType);
	ULONG GetReplaceModuleLength(PCHAR pFileName);
	BOOLEAN GetReplaceModuleDat(PCHAR pFileName, PCHAR pReplaceDat, ULONG ulSize);
	PEFI_FIRMWARE_VOLUME_HEADER GenerateVolumeHeader(PEFI_GUID pEfiGuid,ULONG64 ulFvLength,ULONG ulAttributes,USHORT uHeaderLength, \
		USHORT uChecksum,USHORT uExtHeaderOffset,BYTE bRevision);
	ULONG ulBootkitLength;
	PCHAR pBootkitDat;
	PCHAR pGenSubModule;
	PCHAR pCompressionReplaceSubModule;
	ULONG ulCompressionReplaceSubModuleSize;
	PEFI_FFS_FILE_HEADER pGenBigBlockFfsFileHeader;
	PEFI_COMPRESSION_SECTION pGenEfiCompressionSection;
	PEFI_FV_BLOCK_MAP_ENTRY pEfiFvBlockMapEntry;
	PEFI_FIRMWARE_VOLUME_HEADER pGenEfiFirmWareVolumeHeader;
	PVOID pReplaceBigBlock;
	ULONG ulReplaceBigBlockPos;
	ULONG ulReplaceBigBlockSize;
	ULONG ulFvBlockSize;
	ULONG ulFindCount;
	PCHAR pReplaceSubModule;
	ULONG ulReplaceSubPos;
};

extern CEFIBIOSANALYZE *g_pEfiBIOSAnalyze;

