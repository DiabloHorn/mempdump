/*
Process Memory Viewer
Made By: DiabloHorn (Proud Member Of KD-TEAM)
Thanks to all those great sites and offcourse google that helped me out.
Special thx to MSDN for the nice info they have there.
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <tlhelp32.h>
#include "psapi.h"

void PrintProcessNameAndID(DWORD);
void ListP();
void ExtraInf();
void DumpMem();
void Usage();

void main(int argc, char *argv[])
{
	if(argc==1)
	{
		Usage();
	}
	//ListP();
	for(int i=1;i<argc;i++)
	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1])
			{
				case '?':
							Usage();
							break;
				case 'L':
				case 'l':
							ListP();
							break;
				case 'S':
				case 's':
							ExtraInf();
							break;
				case 'D':
				case 'd':
							DumpMem();
							break;
				default:
							Usage();
							break;
			}
		}
		else
		{
			Usage();
		}
	}
}

void Usage()
{
	printf("\tProcess Memory Dumper\n");
	printf("\tMade By: DiabloHorn (Proud Member of: KD-Team)\n");
	printf("\t\tUse as: memdump.exe -<options>\n");
	printf("\t\tOptions:\n");
	printf("\t\t\t-? = Show this help\n");
	printf("\t\t\t-l = List all running processes\n");
	printf("\t\t\t-s = show info on Process like Path\n");
	printf("\t\t\t-d = Dump Memory of process\n");
}
void ListP()
{

    DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses,sizeof(aProcesses),&cbNeeded))
        return;

    cProcesses = cbNeeded / sizeof(DWORD);

    for ( i = 0; i < cProcesses; i++ )
	{
        PrintProcessNameAndID(aProcesses[i]);
	}
}
void PrintProcessNameAndID( DWORD processID )
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE, processID );

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if ( EnumProcessModules(hProcess, &hMod, sizeof(hMod),
             &cbNeeded) )
        {
            GetModuleBaseName( hProcess, hMod, szProcessName,
                               sizeof(szProcessName)/sizeof(TCHAR) );
        }
    }
    _tprintf( TEXT("%s\t(PID: %u)\tHex: %xh\n"), szProcessName, processID,processID );

    CloseHandle( hProcess );
}

void ExtraInf()
{
	HANDLE hSnapshot;
	MODULEENTRY32 me;
	DWORD pId=0;

	printf("Enter Process Id: ");
	scanf("%d",&pId);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pId);
	if(hSnapshot == NULL)
	{
		printf("Module Snapshot Failed\n");
	}
	else
	{
		printf("Module Snapshot succeeded\n");
	}
	if (!Module32First(hSnapshot, &me))
	{
		printf("Gathering Module information failed\n");
	}

	printf("Module ID: %u\n", me.th32ModuleID);
	printf("Global usage count: %u\n", me.GlblcntUsage);
	printf("Module usage count: %u\n", me.ProccntUsage);
	printf("Base address: 0x%Xh\n", me.modBaseAddr);
	printf("Base size: %u\n", me.modBaseSize);
	printf("Full path: %s\n", me.szExePath);

	CloseHandle(hSnapshot);
}

void DumpMem()
{
	char buf[24000];
	DWORD bufsize = sizeof(buf);
	DWORD hPID=0;
	HANDLE hReadp;

	printf("Enter Process Id: ");
	scanf("%d",&hPID);

	hReadp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE, hPID);

	if(NULL != hReadp)
	{
		int ret = ReadProcessMemory(hReadp,(LPCVOID)0x400000, &buf, bufsize,NULL);

		if(ret<=0)

		{
			printf("failed %d\n",GetLastError());
		}

			if(ret>0)
			{
				for(int e=0;e<=sizeof(buf);e++)
				printf("%c",buf[e]);
			}
	}

	CloseHandle(hReadp);
}

