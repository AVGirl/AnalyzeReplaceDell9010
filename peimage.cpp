/* peimage.cpp

Copyright (c) 2015, Nikolaj Schlej. All rights reserved.
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#include "AnalyzeReplaceDell9010.h"
#include "peimage.h"

PCHAR MachineTypeToString(USHORT uMachineType)
{
	PCHAR pRetStr;

	pRetStr = NULL;

	do 
	{
		pRetStr = (PCHAR)malloc(MAX_PATH);
	} while (NULL == pRetStr);
	RtlZeroMemory(pRetStr,MAX_PATH);
    switch (uMachineType)
	{
    case IMAGE_FILE_MACHINE_AMD64:
		StringCchCopyA(pRetStr,MAX_PATH,"x86-64");
		return pRetStr;
    case IMAGE_FILE_MACHINE_ARM:
		StringCchCopyA(pRetStr,MAX_PATH,"ARM");
		return pRetStr;
    case IMAGE_FILE_MACHINE_ARMV7:
		StringCchCopyA(pRetStr,MAX_PATH,"ARMv7");
		return pRetStr;
    case IMAGE_FILE_MACHINE_EBC:
		StringCchCopyA(pRetStr,MAX_PATH,"EBC");
		return pRetStr;
    case IMAGE_FILE_MACHINE_I386:
		StringCchCopyA(pRetStr,MAX_PATH,"x86");
		return pRetStr;
    case IMAGE_FILE_MACHINE_IA64:
		StringCchCopyA(pRetStr,MAX_PATH,"IA64");
		return pRetStr;
    case IMAGE_FILE_MACHINE_THUMB:
		StringCchCopyA(pRetStr,MAX_PATH,"Thumb");
		return pRetStr;
    default:
		StringCchCopyA(pRetStr,MAX_PATH,"Unknown MachineType");
		return pRetStr;
    }
	if (pRetStr)
	{
		free(pRetStr);
	}
	return NULL;
}