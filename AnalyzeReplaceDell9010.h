#ifndef __ANALYZE_REPLACE_DELL9010_H__
#define __ANALYZE_REPLACE_DELL9010_H__
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include <windows.h>
#include <Shlwapi.h>
#include "ListEntryOperations.h"
#pragma comment(lib,"Shlwapi.lib")

#define HDR_HEADER_LENGTH 0x58
#define MAX_BLOCK	128

#define EFI_FV_SIGNATURE "_FVH"
#define EFI_FV_SIGNATURE_OFFSET 0x28

const BYTE bFfsAlignmentTable[] = { 0, 4, 7, 9, 10, 12, 15, 16 };
//aa ee aa 76 1b ec bb 20 f1 e6 51 0a 78 9c ec d7
const BYTE bFindHdrSignature[] = {0xAA,0xEE,0xAA,0x76,0x1B,0xEC,0xBB,0x20,0xF1,0xE6,0x51,0x0A};
// Make sure we use right packing rules
#pragma pack(push,1)
// EFI GUID
typedef struct _EFI_GUID
{
	UINT8 Data[16];
} EFI_GUID,*PEFI_GUID;
//*****************************************************************************
// EFI Capsule
//*****************************************************************************
// Standard EFI Capsule header
typedef struct _EFI_CAPSULE_HEADER
{
    EFI_GUID  CapsuleGuid;
    UINT32    HeaderSize;
    UINT32    Flags;
    UINT32    CapsuleImageSize;
} EFI_CAPSULE_HEADER;

// Capsule flags
#define EFI_CAPSULE_HEADER_FLAG_SETUP                   0x00000001
#define EFI_CAPSULE_HEADER_FLAG_PERSIST_ACROSS_RESET    0x00010000
#define EFI_CAPSULE_HEADER_FLAG_POPULATE_SYSTEM_TABLE   0x00020000


//*****************************************************************************
// EFI Firmware Volume
//*****************************************************************************
// Firmware block map entry
// FvBlockMap ends with an entry {0x00000000, 0x00000000}
typedef struct _EFI_FV_BLOCK_MAP_ENTRY
{
    UINT32  NumBlocks;
    UINT32  Length;
} EFI_FV_BLOCK_MAP_ENTRY,*PEFI_FV_BLOCK_MAP_ENTRY;

// Volume header
typedef struct _EFI_FIRMWARE_VOLUME_HEADER
{
    UINT8                  ZeroVector[16];
    EFI_GUID               FileSystemGuid;
    UINT64                 FvLength;
    UINT32                 Signature;
    UINT32                 Attributes;
    UINT16                 HeaderLength;
    UINT16                 Checksum;
    UINT16                 ExtHeaderOffset;  //Reserved in Revision 1
    UINT8                  Reserved;
    UINT8                  Revision;
    //EFI_FV_BLOCK_MAP_ENTRY FvBlockMap[2];
} EFI_FIRMWARE_VOLUME_HEADER,*PEFI_FIRMWARE_VOLUME_HEADER;

// Firmware volume attributes
// Revision 1
#define EFI_FVB_READ_DISABLED_CAP  0x00000001
#define EFI_FVB_READ_ENABLED_CAP   0x00000002
#define EFI_FVB_READ_STATUS        0x00000004
#define EFI_FVB_WRITE_DISABLED_CAP 0x00000008
#define EFI_FVB_WRITE_ENABLED_CAP  0x00000010
#define EFI_FVB_WRITE_STATUS       0x00000020
#define EFI_FVB_LOCK_CAP           0x00000040
#define EFI_FVB_LOCK_STATUS        0x00000080
#define EFI_FVB_STICKY_WRITE       0x00000200
#define EFI_FVB_MEMORY_MAPPED      0x00000400
#define EFI_FVB_ERASE_POLARITY     0x00000800
#define EFI_FVB_ALIGNMENT_CAP       0x00008000
#define EFI_FVB_ALIGNMENT_2         0x00010000
#define EFI_FVB_ALIGNMENT_4         0x00020000
#define EFI_FVB_ALIGNMENT_8         0x00040000
#define EFI_FVB_ALIGNMENT_16        0x00080000
#define EFI_FVB_ALIGNMENT_32        0x00100000
#define EFI_FVB_ALIGNMENT_64        0x00200000
#define EFI_FVB_ALIGNMENT_128       0x00400000
#define EFI_FVB_ALIGNMENT_256       0x00800000
#define EFI_FVB_ALIGNMENT_512       0x01000000
#define EFI_FVB_ALIGNMENT_1K        0x02000000
#define EFI_FVB_ALIGNMENT_2K        0x04000000
#define EFI_FVB_ALIGNMENT_4K        0x08000000
#define EFI_FVB_ALIGNMENT_8K        0x10000000
#define EFI_FVB_ALIGNMENT_16K       0x20000000
#define EFI_FVB_ALIGNMENT_32K       0x40000000
#define EFI_FVB_ALIGNMENT_64K       0x80000000
// Revision 2
#define EFI_FVB2_READ_DISABLED_CAP  0x00000001
#define EFI_FVB2_READ_ENABLED_CAP   0x00000002
#define EFI_FVB2_READ_STATUS        0x00000004
#define EFI_FVB2_WRITE_DISABLED_CAP 0x00000008
#define EFI_FVB2_WRITE_ENABLED_CAP  0x00000010
#define EFI_FVB2_WRITE_STATUS       0x00000020
#define EFI_FVB2_LOCK_CAP           0x00000040
#define EFI_FVB2_LOCK_STATUS        0x00000080
#define EFI_FVB2_STICKY_WRITE       0x00000200
#define EFI_FVB2_MEMORY_MAPPED      0x00000400
#define EFI_FVB2_ERASE_POLARITY     0x00000800
#define EFI_FVB2_READ_LOCK_CAP      0x00001000
#define EFI_FVB2_READ_LOCK_STATUS   0x00002000
#define EFI_FVB2_WRITE_LOCK_CAP     0x00004000
#define EFI_FVB2_WRITE_LOCK_STATUS  0x00008000
#define EFI_FVB2_ALIGNMENT          0x001F0000
#define EFI_FVB2_ALIGNMENT_1        0x00000000
#define EFI_FVB2_ALIGNMENT_2        0x00010000
#define EFI_FVB2_ALIGNMENT_4        0x00020000
#define EFI_FVB2_ALIGNMENT_8        0x00030000
#define EFI_FVB2_ALIGNMENT_16       0x00040000
#define EFI_FVB2_ALIGNMENT_32       0x00050000
#define EFI_FVB2_ALIGNMENT_64       0x00060000
#define EFI_FVB2_ALIGNMENT_128      0x00070000
#define EFI_FVB2_ALIGNMENT_256      0x00080000
#define EFI_FVB2_ALIGNMENT_512      0x00090000
#define EFI_FVB2_ALIGNMENT_1K       0x000A0000
#define EFI_FVB2_ALIGNMENT_2K       0x000B0000
#define EFI_FVB2_ALIGNMENT_4K       0x000C0000
#define EFI_FVB2_ALIGNMENT_8K       0x000D0000
#define EFI_FVB2_ALIGNMENT_16K      0x000E0000
#define EFI_FVB2_ALIGNMENT_32K      0x000F0000
#define EFI_FVB2_ALIGNMENT_64K      0x00100000
#define EFI_FVB2_ALIGNMENT_128K     0x00110000
#define EFI_FVB2_ALIGNMENT_256K     0x00120000
#define EFI_FVB2_ALIGNMENT_512K     0x00130000
#define EFI_FVB2_ALIGNMENT_1M       0x00140000
#define EFI_FVB2_ALIGNMENT_2M       0x00150000
#define EFI_FVB2_ALIGNMENT_4M       0x00160000
#define EFI_FVB2_ALIGNMENT_8M       0x00170000
#define EFI_FVB2_ALIGNMENT_16M      0x00180000
#define EFI_FVB2_ALIGNMENT_32M      0x00190000
#define EFI_FVB2_ALIGNMENT_64M      0x001A0000
#define EFI_FVB2_ALIGNMENT_128M     0x001B0000
#define EFI_FVB2_ALIGNMENT_256M     0x001C0000
#define EFI_FVB2_ALIGNMENT_512M     0x001D0000
#define EFI_FVB2_ALIGNMENT_1G       0x001E0000
#define EFI_FVB2_ALIGNMENT_2G       0x001F0000
#define EFI_FVB2_WEAK_ALIGNMENT     0x80000000

// Extended firmware volume header
typedef struct _EFI_FIRMWARE_VOLUME_EXT_HEADER
{
    EFI_GUID FvName;
    UINT32 ExtHeaderSize;
} EFI_FIRMWARE_VOLUME_EXT_HEADER,*PEFI_FIRMWARE_VOLUME_EXT_HEADER;

// Extended header entry
// The extended header entries follow each other and are
// terminated by ExtHeaderType EFI_FV_EXT_TYPE_END
#define EFI_FV_EXT_TYPE_END        0x0000
typedef struct _EFI_FIRMWARE_VOLUME_EXT_ENTRY
{
    UINT16 ExtEntrySize;
    UINT16 ExtEntryType;
} EFI_FIRMWARE_VOLUME_EXT_ENTRY,*PEFI_FIRMWARE_VOLUME_EXT_ENTRY;

// GUID that maps OEM file types to GUIDs
#define EFI_FV_EXT_TYPE_OEM_TYPE   0x0001
typedef struct _EFI_FIRMWARE_VOLUME_EXT_HEADER_OEM_TYPE
{
    EFI_FIRMWARE_VOLUME_EXT_ENTRY Header;
    UINT32 TypeMask;
    //EFI_GUID                         Types[1];
} EFI_FIRMWARE_VOLUME_EXT_HEADER_OEM_TYPE,*PEFI_FIRMWARE_VOLUME_EXT_HEADER_OEM_TYPE;

#define EFI_FV_EXT_TYPE_GUID_TYPE  0x0002
typedef struct _EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE
{
    EFI_FIRMWARE_VOLUME_EXT_ENTRY Header;
    EFI_GUID FormatType;
    //UINT8 Data[];
} EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE,*PEFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE;

//*****************************************************************************
// EFI FFS File
//*****************************************************************************
// Integrity check
typedef union
{
    struct
	{
        UINT8   Header;
        UINT8   File;
    } Checksum;
    UINT16 TailReference;   // Revision 1
    UINT16 Checksum16;      // Revision 2
} EFI_FFS_INTEGRITY_CHECK,*PEFI_FFS_INTEGRITY_CHECK;
// File header
typedef struct _EFI_FFS_FILE_HEADER
{
    EFI_GUID                Name;
    EFI_FFS_INTEGRITY_CHECK IntegrityCheck;
    UINT8                   Type;
    UINT8                   Attributes;
    UINT8                   Size[3];
    UINT8                   State;
} EFI_FFS_FILE_HEADER,*PEFI_FFS_FILE_HEADER;

// Large file header
typedef struct _EFI_FFS_FILE_HEADER2
{
	EFI_GUID                Name;
	EFI_FFS_INTEGRITY_CHECK IntegrityCheck;
	UINT8                   Type;
	UINT8                   Attributes;
	UINT8                   Size[3]; // Set to 0xFFFFFF
	UINT8                   State;
	UINT32                  ExtendedSize;
} EFI_FFS_FILE_HEADER2,*PEFI_FFS_FILE_HEADER2;

// Compression section
typedef struct _EFI_COMPRESSION_SECTION
{
	UINT8    Size[3];
	UINT8    Type;
	UINT32   UncompressedLength;
	UINT8    CompressionType;
	//UINT8    Reserved;
} EFI_COMPRESSION_SECTION,*PEFI_COMPRESSION_SECTION;

typedef struct _EFI_COMPRESSION_SECTION2
{
	UINT8    Size[3];
	UINT8    Type;
	UINT32   ExtendedSize;
	UINT32   UncompressedLength;
	UINT8    CompressionType;
} EFI_COMPRESSION_SECTION2,*PEFI_COMPRESSION_SECTION2;
// Compression types
#define EFI_NOT_COMPRESSED          0x00
#define EFI_STANDARD_COMPRESSION    0x01
#define EFI_CUSTOMIZED_COMPRESSION  0x02

// Standard data checksum, used if FFS_ATTRIB_CHECKSUM is clear
#define FFS_FIXED_CHECKSUM   0x5A
#define FFS_FIXED_CHECKSUM2  0xAA

// File types
#define EFI_FV_FILETYPE_ALL                     0x00
#define EFI_FV_FILETYPE_RAW                     0x01
#define EFI_FV_FILETYPE_FREEFORM                0x02
#define EFI_FV_FILETYPE_SECURITY_CORE           0x03
#define EFI_FV_FILETYPE_PEI_CORE                0x04
#define EFI_FV_FILETYPE_DXE_CORE                0x05
#define EFI_FV_FILETYPE_PEIM                    0x06
#define EFI_FV_FILETYPE_DRIVER                  0x07
#define EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER    0x08
#define EFI_FV_FILETYPE_APPLICATION             0x09
#define EFI_FV_FILETYPE_SMM                     0x0A
#define EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE   0x0B
#define EFI_FV_FILETYPE_COMBINED_SMM_DXE        0x0C
#define EFI_FV_FILETYPE_SMM_CORE                0x0D
#define EFI_FV_FILETYPE_OEM_MIN                 0xC0
#define EFI_FV_FILETYPE_OEM_MAX                 0xDF
#define EFI_FV_FILETYPE_DEBUG_MIN               0xE0
#define EFI_FV_FILETYPE_DEBUG_MAX               0xEF
#define EFI_FV_FILETYPE_PAD                     0xF0
#define EFI_FV_FILETYPE_FFS_MIN                 0xF0
#define EFI_FV_FILETYPE_FFS_MAX                 0xFF

// File attributes
#define FFS_ATTRIB_TAIL_PRESENT       0x01 // Valid only for revision 1 volumes
#define FFS_ATTRIB_RECOVERY           0x02 // Valid only for revision 1 volumes
#define FFS_ATTRIB_LARGE_FILE         0x01 // Valid only for FFSv3 volumes
#define FFS_ATTRIB_FIXED              0x04
#define FFS_ATTRIB_DATA_ALIGNMENT     0x38
#define FFS_ATTRIB_CHECKSUM           0x40

// File states
#define EFI_FILE_HEADER_CONSTRUCTION    0x01
#define EFI_FILE_HEADER_VALID           0x02
#define EFI_FILE_DATA_VALID             0x04
#define EFI_FILE_MARKED_FOR_UPDATE      0x08
#define EFI_FILE_DELETED                0x10
#define EFI_FILE_HEADER_INVALID         0x20

//*****************************************************************************
// EFI FFS File Section
//*****************************************************************************
// Common section header
typedef struct _EFI_COMMON_SECTION_HEADER
{
    UINT8 Size[3];
    UINT8 Type;
} EFI_COMMON_SECTION_HEADER,*PEFI_COMMON_SECTION_HEADER;

// Large file common section header
typedef struct _EFI_COMMON_SECTION_HEADER2
{
    UINT8 Size[3];    //Must be 0xFFFFFF for this header to be used
    UINT8 Type;
    UINT32 ExtendedSize;
} EFI_COMMON_SECTION_HEADER2,*PEFI_COMMON_SECTION_HEADER2;

// Section2 usage indicator
#define EFI_SECTION2_IS_USED 0xFFFFFF

// File section types
#define EFI_SECTION_ALL 0x00 // Impossible attribute for file in the FS

// Encapsulation section types
#define EFI_SECTION_COMPRESSION     0x01
#define EFI_SECTION_GUID_DEFINED    0x02
#define EFI_SECTION_DISPOSABLE      0x03

// Leaf section types
#define EFI_SECTION_PE32                    0x10
#define EFI_SECTION_PIC                     0x11
#define EFI_SECTION_TE                      0x12
#define EFI_SECTION_DXE_DEPEX               0x13
#define EFI_SECTION_VERSION                 0x14
#define EFI_SECTION_USER_INTERFACE          0x15
#define EFI_SECTION_COMPATIBILITY16         0x16
#define EFI_SECTION_FIRMWARE_VOLUME_IMAGE   0x17
#define EFI_SECTION_FREEFORM_SUBTYPE_GUID   0x18
#define EFI_SECTION_RAW                     0x19
#define EFI_SECTION_PEI_DEPEX               0x1B
#define EFI_SECTION_SMM_DEPEX               0x1C
#define SCT_SECTION_POSTCODE                0xF0 // Specific to Phoenix SCT images
#define INSYDE_SECTION_POSTCODE             0x20 // Specific to Insyde images



//GUID defined section
typedef struct _EFI_GUID_DEFINED_SECTION
{
    UINT8    Size[3];
    UINT8    Type;
    EFI_GUID SectionDefinitionGuid;
    UINT16   DataOffset;
    UINT16   Attributes;
} EFI_GUID_DEFINED_SECTION,*PEFI_GUID_DEFINED_SECTION;

typedef struct _EFI_GUID_DEFINED_SECTION2
{
    UINT8    Size[3];
    UINT8    Type;
    UINT32   ExtendedSize;
    EFI_GUID SectionDefinitionGuid;
    UINT16   DataOffset;
    UINT16   Attributes;
} EFI_GUID_DEFINED_SECTION2,*PEFI_GUID_DEFINED_SECTION2;

// Attributes for GUID defined section
#define EFI_GUIDED_SECTION_PROCESSING_REQUIRED  0x01
#define EFI_GUIDED_SECTION_AUTH_STATUS_VALID    0x02
// GUIDs of GUID-defined sections
#define EFI_GUIDED_SECTION_CRC32 "FC1BCDB0-7D31-49AA-936A-A4600D9DD083"

#define EFI_GUIDED_SECTION_TIANO "A31280AD-481E-41B6-95E8-127F4C984779"

#define EFI_GUIDED_SECTION_LZMA "EE4E5898-3914-4259-9D6E-DC7BD79403CF"

#define EFI_FIRMWARE_CONTENTS_SIGNED_GUID "0F9D89E8-9259-4F76-A5AF-0C89E34023DF"

// WIN_CERTIFICATE_UEFI_GUID.CertType
#define EFI_CERT_TYPE_RSA2048_SHA256_GUID "A7717414-C616-4977-9420-844712A735BF"
#define EFI_CERT_TYPE_PKCS7_GUID "4AAFD29D-68DF-49EE-8AA9-347D375665A7"

// PEI apriori file
#define EFI_PEI_APRIORI_FILE_GUID "0ACC451B-6A15-8A42-AF62-49864DA0E6E6"

// DXE apriori file
#define EFI_DXE_APRIORI_FILE_GUID "E70E51FC-DCFF-D411-BD41-0080C73C8881"

// Volume top file
#define EFI_FFS_VOLUME_TOP_FILE_GUID = "2E06A01B-79C7-8245-8566-336AE8F78F09"

// Pad file GUID
#define EFI_FFS_PAD_FILE_GUID = "856553E4-0979-604A-B5C6-ECDEA6EBFB54"
// Version section
typedef struct _EFI_VERSION_SECTION
{
    UINT8    Size[3];
    UINT8    Type;
    UINT16   BuildNumber;
} EFI_VERSION_SECTION,*PEFI_VERSION_SECTION;

typedef struct _EFI_VERSION_SECTION2
{
    UINT8    Size[3];
    UINT8    Type;
    UINT32   ExtendedSize;
    UINT16   BuildNumber;
} EFI_VERSION_SECTION2,*PEFI_VERSION_SECTION2;

// Freeform subtype GUID section
typedef struct _EFI_FREEFORM_SUBTYPE_GUID_SECTION
{
    UINT8    Size[3];
    UINT8    Type;
    EFI_GUID SubTypeGuid;
} EFI_FREEFORM_SUBTYPE_GUID_SECTION,*PEFI_FREEFORM_SUBTYPE_GUID_SECTION;

typedef struct _EFI_FREEFORM_SUBTYPE_GUID_SECTION2
{
    UINT8    Size[3];
    UINT8    Type;
    UINT32   ExtendedSize;
    EFI_GUID SubTypeGuid;
} EFI_FREEFORM_SUBTYPE_GUID_SECTION2,*PEFI_FREEFORM_SUBTYPE_GUID_SECTION2;

// Phoenix SCT and HP postcode section
typedef struct _POSTCODE_SECTION
{
    UINT8    Size[3];
    UINT8    Type;
    UINT32   Postcode;
} POSTCODE_SECTION,*PPOSTCODE_SECTION;

typedef struct _POSTCODE_SECTION2
{
    UINT8    Size[3];
    UINT8    Type;
    UINT32   ExtendedSize;
    UINT32   Postcode;
} POSTCODE_SECTION2,*PPOSTCODE_SECTION2;

// Other sections
typedef EFI_COMMON_SECTION_HEADER  EFI_DISPOSABLE_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_DISPOSABLE_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_RAW_SECTION;
typedef PEFI_COMMON_SECTION_HEADER PEFI_RAW_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_RAW_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_DXE_DEPEX_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_DXE_DEPEX_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_PEI_DEPEX_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_PEI_DEPEX_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_SMM_DEPEX_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_SMM_DEPEX_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_PE32_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_PE32_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_PIC_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_PIC_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_TE_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_TE_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_COMPATIBILITY16_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_COMPATIBILITY16_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_FIRMWARE_VOLUME_IMAGE_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_FIRMWARE_VOLUME_IMAGE_SECTION2;
typedef EFI_COMMON_SECTION_HEADER  EFI_USER_INTERFACE_SECTION;
typedef EFI_COMMON_SECTION_HEADER2 EFI_USER_INTERFACE_SECTION2;

//*****************************************************************************
// EFI Dependency Expression
//*****************************************************************************

#define EFI_DEP_OPCODE_SIZE   1

///
/// If present, this must be the first and only opcode,
/// EFI_DEP_BEFORE is only used by DXE driver.
///
#define EFI_DEP_BEFORE        0x00

///
/// If present, this must be the first and only opcode,
/// EFI_DEP_AFTER is only used by DXE driver.
///
#define EFI_DEP_AFTER         0x01

#define EFI_DEP_PUSH          0x02
#define EFI_DEP_AND           0x03
#define EFI_DEP_OR            0x04
#define EFI_DEP_NOT           0x05
#define EFI_DEP_TRUE          0x06
#define EFI_DEP_FALSE         0x07
#define EFI_DEP_END           0x08


///
/// If present, this must be the first opcode,
/// EFI_DEP_SOR is only used by DXE driver.
///
#define EFI_DEP_SOR           0x09

//*****************************************************************************
// UEFI Crypto-signed Stuff
//*****************************************************************************

#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#define WIN_CERT_TYPE_EFI_GUID         0x0EF1

typedef struct _WIN_CERTIFICATE
{
    UINT32  Length;
    UINT16  Revision;
    UINT16  CertificateType;
    //UINT8 CertData[];
} WIN_CERTIFICATE,*PWIN_CERTIFICATE;

typedef struct _WIN_CERTIFICATE_UEFI_GUID
{
    WIN_CERTIFICATE   Header;     // Standard WIN_CERTIFICATE
    EFI_GUID          CertType;   // Determines format of CertData
    // UINT8          CertData[]; // Certificate data follows
} WIN_CERTIFICATE_UEFI_GUID,*PWIN_CERTIFICATE_UEFI_GUID;
// WIN_CERTIFICATE_UEFI_GUID.CertData
typedef struct _EFI_CERT_BLOCK_RSA_2048_SHA256
{
    UINT32  HashType;
    UINT8   PublicKey[256];
    UINT8   Signature[256];
} EFI_CERT_BLOCK_RSA_2048_SHA256,*PEFI_CERT_BLOCK_RSA_2048_SHA256;

typedef struct _DELL_BIOS_BLOCK_
{
	ULONG ullBlockStart;
	ULONG ullBlockEnd;
	ULONG ullBlockSize;
	EFI_FIRMWARE_VOLUME_HEADER EfiFirmWareVolumeHeader;
} DELL_BIOS_BLOCK,*PDELL_BIOS_BLOCK;

typedef struct _DELL_BIOS_HDR_INFO_
{
	BYTE HdrHeaderCode[HDR_HEADER_LENGTH];

	DELL_BIOS_BLOCK pDellBlock[MAX_BLOCK];
	ULONG ullBlockCount;

	PVOID pHdrFileDat;
	ULONG ullHdrFileSize;

} DELL_BIOS_HDR_INFO,*PDELL_BIOS_HDR_INFO;

typedef struct _DELL_BIOS_OPTX_9010
{
	PVOID pExecuteDat;
	ULONG ulExecuteFileSize;

	DELL_BIOS_HDR_INFO HdrInfo;

} DELL_BIOS_OPTX_9010,*PDELL_BIOS_OPTX_9010;


typedef struct _REPLACE_RAW_SECTION
{
	ULONG ulRawSectionOffset;
	ULONG ulRawSectionSize;
	PEFI_RAW_SECTION pEfiRawSection;
	PVOID pRawSectionDat;
	ULONG ulPaddingSize;
} REPLACE_RAW_SECTION,*PREPLACE_RAW_SECTION;

typedef struct _REPLACE_EFI_COMPRESSION_SECTION
{
	ULONG ulCompressionSectionOffset;
	ULONG ulCompressionSize;
	PEFI_COMPRESSION_SECTION pEfiCompressionSection;
	PVOID pCompressionDat;
	ULONG ulPaddingSize;
} REPLACE_EFI_COMPRESSION_SECTION,*PREPLACE_EFI_COMPRESSION_SECTION;

typedef struct _REPLACE_EFI_COMMON_SECTION_HEADER
{
	ULONG ulCommonSectionOffset;
	ULONG ulSectionSize;
	PEFI_COMMON_SECTION_HEADER pEfiCommonSectionHeader;
	PVOID pCommonSectionDat;
	ULONG ulPaddingSize;
} REPLACE_EFI_COMMON_SECTION_HEADER,*PREPLACE_EFI_COMMON_SECTION_HEADER;

typedef struct _REPLACE_UEFI_FILE
{
	LIST_ENTRY NextFile;
	ULONG ulIndex;
	ULONG ulFileOffset;
	ULONG ulFileSize;
	PEFI_FFS_FILE_HEADER pEfiFfsFileHeader;
	LIST_ENTRY SectionList;
	ULONG ulPaddingSize;
	PVOID pFileDat;
} REPLACE_UEFI_FILE,*PREPLACE_UEFI_FILE;

typedef struct _REPLACE_UEFI_IMAGE 
{
	LIST_ENTRY NextVolume;
	ULONG ulIndex;
	ULONG ulVolumeOffset;
	ULONG ulVolumeSize;
	PEFI_FIRMWARE_VOLUME_HEADER pEfiFirmWareVolumeHeader;
	ULONG ulPaddingSize;
	PVOID pVolumeDat;
} REPLACE_UEFI_IMAGE,*PREPLACE_UEFI_IMAGE;

typedef union _REPLACE_SECTION
{
	PREPLACE_RAW_SECTION pReplaceRawSection;
	PREPLACE_EFI_COMPRESSION_SECTION pReplaceCompressionSection;
	PREPLACE_EFI_COMMON_SECTION_HEADER pReplaceCommonSectionHeader;
	PREPLACE_UEFI_FILE pReplaceFile;
	PREPLACE_UEFI_IMAGE pReplaceImage;
} REPLACE_SECTION,*PREPLACE_SECTION;

typedef struct _REPLACE_UEFI_SECTION
{
	LIST_ENTRY NextSection;
	ULONG ulSectionOffset;
	ULONG ulSectionSize;
	REPLACE_SECTION ReplaceUefiSection;
	PVOID pSectionDat;
	ULONG ulPaddingSize;
} REPLACE_UEFI_SECTION,*PREPLACE_UEFI_SECTION;
// Restore previous packing rules
#pragma pack(pop)

#define ALIGN4(Value) (((Value)+3) & ~3)
#define ALIGN8(Value) (((Value)+7) & ~7)

extern LIST_ENTRY g_ReplaceUefiImage;
extern PDELL_BIOS_OPTX_9010 g_pDellBIOSInfo;

#endif