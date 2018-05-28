#include "AnalyzeReplaceDell9010.h"
#include "FileOperations.h"

ULONG GetAnalyzeFileSize(PCHAR pFileName)
{
	HANDLE hFile;
	ULONG ulFileSize;

	hFile = NULL;
	ulFileSize = 0;

	do 
	{
		hFile = CreateFile(pFileName, \
			FILE_READ_ATTRIBUTES, \
			FILE_SHARE_READ, \
			NULL, \
			OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL, \
			NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			break;
		}
		ulFileSize = GetFileSize(hFile,NULL);
		if (ulFileSize == INVALID_FILE_SIZE)
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
BOOLEAN GetAnalyzeFileDat(PCHAR pFileName,PCHAR pFileDat,ULONG ulFileSize)
{
	HANDLE hFile;
	BOOLEAN bRet;
	ULONG ulRetByteSize;

	hFile = NULL;
	bRet = FALSE;
	ulRetByteSize = 0;

	do 
	{
		hFile = CreateFile(pFileName, \
			FILE_READ_DATA | FILE_READ_ATTRIBUTES, \
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
			pFileDat, \
			ulFileSize, \
			&ulRetByteSize, \
			NULL);
		if (FALSE == bRet || \
			ulRetByteSize < ulFileSize)
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