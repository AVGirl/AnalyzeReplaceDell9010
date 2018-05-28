#include "AnalyzeReplaceDell9010.h"
#include "AnalyzeCmdLine.h"

ULONG GetCmdLineAndCountA(ULONG ulGetArgvIndex,PCHAR *pIndexCmdLine)
{
	ULONG ulCmdLineCount;
	PCHAR pCmdLine;
	PCHAR *pListCmdLine;

	ulCmdLineCount = 0;
	pCmdLine = NULL;
	pListCmdLine = NULL;

	if (ulGetArgvIndex <= 0)
	{
		return 0;
	}
	do 
	{
		pCmdLine = GetCommandLine();
		if (NULL == pCmdLine)
		{
			break;
		}
		*pIndexCmdLine = pIndexCmdLine[ulGetArgvIndex - 1];
	} while (0);
	return ulGetArgvIndex;
}