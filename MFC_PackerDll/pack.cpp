#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include"pack.h"
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
//�ϲ�֮��data�εĿ�д���Խ��ᱻȥ������Ҫ�ٴθ���
#pragma comment(linker,"/section:.text,RWE")

void packStart();
PACKINFO g_PackInfo = {(DWORD)packStart};


typedef HANDLE(WINAPI* MyCreateThread)(
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ __drv_aliasesMem LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	);


typedef HMODULE (WINAPI* MyLoadLibraryExA)(
	LPCSTR lpLibFileName,
	HANDLE hFile,
	DWORD dwFlags
);

typedef FARPROC (WINAPI* MYGetProcAddress)(
	HMODULE hModule,
    LPCSTR lpProcName
);
typedef HMODULE(WINAPI* MyGetModuleHandleA)(
	LPCSTR lpModuleName
);

typedef BOOL(WINAPI* MyVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
	);

typedef int(WINAPI* MyMessageBoxA)(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT uType
	);

typedef HANDLE(WINAPI* MyCreateFileA)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
	);





MyLoadLibraryExA g_MyLoadLibraryExA=NULL;
MYGetProcAddress g_MYGetProcAddress = NULL;
MyGetModuleHandleA g_MyGetModuleHandleA = NULL;
MyVirtualProtect g_MyVirtualProtect = NULL;
MyMessageBoxA g_MyMessageBoxA = NULL;
MyCreateThread g_MyCreateThread = NULL;
MyCreateFileA g_MyCreateFileA = NULL;


#define ProcessDebugObjectHandle 0x1e
typedef NTSTATUS(NTAPI* MyNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

MyNtQueryInformationProcess g_MyNtQueryInformationProcess = NULL;



typedef HANDLE(WINAPI* MyGetCurrentProcess)(
	VOID
	);
MyGetCurrentProcess g_MyGetCurrentProcess = NULL;



typedef int(WINAPI* MyExitProcess)(
	_In_ UINT uExitCode
	);

MyExitProcess g_MyExitProcess = NULL;






DWORD GetImportantModule()
{
	DWORD dwBase = 0;
	_asm
	{
		mov eax, dword ptr fs : [0x30]//�̻߳�����TEBλ��
		mov eax, dword ptr[eax+0xC]//���̻�����PEBλ��
		mov eax, dword ptr[eax + 0x1C]//ģ���б�LDR���ĵ�ַ
		mov eax, [eax]//��ȡ�� LDR ��ͷָ��
		mov eax,dword ptr[eax+0x8]// LDR �ṹ���ҵ��˵�һ��ģ��ĵ�ַ
		mov dwBase,eax//��һ��ģ�����kernel32Ҳ�п�����kernelbase
	}

	return dwBase;//����kernel32
}

DWORD MyGetProcAddress(DWORD hModule,LPCSTR funName)
{
	//��ȡDOSͷNtͷ
	PIMAGE_DOS_HEADER pDosHeader= (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)hModule);
	//��ȡ������
	DWORD exportTableVa = pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(exportTableVa + hModule);
	//�ҵ��������Ʊ���ű���ַ��
	DWORD* nameTable = (DWORD*)(exportTable->AddressOfNames + hModule);
	DWORD* funTable= (DWORD*)(exportTable->AddressOfFunctions+ hModule);
	WORD* numberTable= (WORD*)(exportTable->AddressOfNameOrdinals+ hModule);
	//��ʼ����������
	for (int i = 0; i < (int)(exportTable->NumberOfNames); i++) {
		//��ȡ��������
		char* name = (char*)(nameTable[i] + hModule);
		if (!strcmp(name,funName)) {
			return funTable[numberTable[i]] + hModule;
		}
	}
	return 0;
}
void GetFunctions()//������ʼ��һЩ�����ĵ�ַ
{
	//��ȡkerner32����kernelbaseģ���ַ
	DWORD pkernelBase = GetImportantModule();
	//��ȡloadLibraryEx
	g_MyLoadLibraryExA=(MyLoadLibraryExA)MyGetProcAddress(pkernelBase, "LoadLibraryExA");
	//��ȡkerner32��ַ������ǰ�治ȷ��������kerner32����kernerbase
	HMODULE kernel32base = g_MyLoadLibraryExA("kernel32.dll",0,0);
	HMODULE user32base = g_MyLoadLibraryExA("user32.dll", 0, 0);
	g_MYGetProcAddress =(MYGetProcAddress)MyGetProcAddress((DWORD)kernel32base,"GetProcAddress");
	g_MyGetModuleHandleA= (MyGetModuleHandleA)g_MYGetProcAddress(kernel32base, "GetModuleHandleA");
	g_MyVirtualProtect = (MyVirtualProtect)g_MYGetProcAddress(kernel32base, "VirtualProtect");
	g_MyCreateThread = (MyCreateThread)g_MYGetProcAddress(kernel32base, "CreateThread");
	g_MyCreateFileA = (MyCreateFileA)g_MYGetProcAddress(kernel32base, "CreateFileA");
	g_MyMessageBoxA = (MyMessageBoxA)g_MYGetProcAddress(user32base, "MessageBoxA");
	g_MyGetCurrentProcess=(MyGetCurrentProcess)g_MYGetProcAddress(kernel32base, "GetCurrentProcess");
	g_MyExitProcess = (MyExitProcess)g_MYGetProcAddress(kernel32base, "ExitProcess");
	HMODULE hNtdll = g_MyGetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL) {
		return;//ntdll����Ӵ�����
	}
	g_MyNtQueryInformationProcess = (MyNtQueryInformationProcess)g_MYGetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!g_MyNtQueryInformationProcess) {
		//FreeLibrary(hNtDll);//�������
		return;
	}
}
#include"sm4.h"

//����
BOOL DecodeSections()
{
	int key = 0x51;
	//GetModuleHandleA(NULL);����ֱ�ӵ������API
	HMODULE hModule = g_MyGetModuleHandleA(0);//0��ʾ��ȡ��ǰ���̵�ģ�����ַ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders= (PIMAGE_NT_HEADERS)((DWORD)hModule+pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER firstSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);//�궨�庯��
	char* sectionBuff = (char*)(firstSectionHeader->VirtualAddress + (DWORD)hModule);
	//�޸��ڴ�����Ϊ��д
	DWORD oldProtect = 0;//����ԭ�����Է��㸴ԭ
	g_MyVirtualProtect(sectionBuff, firstSectionHeader->SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProtect);


	uint8_t keys[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x61, 0x16, 0x88, 0x3b, 0xf2, 0x03 };
	uint8_t paddedData[32] = { 0 };
	memcpy(paddedData, sectionBuff, firstSectionHeader->SizeOfRawData);
	size_t paddedSize = 0;
	pkcs7_padding(paddedData, firstSectionHeader->SizeOfRawData, 16, &paddedSize);
	// ��ʼ��SM4������
	SM4_CTX ctx;
	sm4_setkey(&ctx, keys);
	uint8_t encryptedData[32] = { 0 };
	sm4_crypt_ecb(&ctx, SM4_ENCRYPT, paddedSize, paddedData, encryptedData);
	for (int i = 0; i < firstSectionHeader->SizeOfRawData; i++)
	{
		sectionBuff[i] = sectionBuff[i] ^ key;
	}
	g_MyVirtualProtect(sectionBuff, firstSectionHeader->SizeOfRawData, oldProtect, &oldProtect);//��ԭ�ڴ�����
	return TRUE;
}

DWORD WINAPI ThreadFunc(LPVOID lpParam) {
	HANDLE hDebugObject;
	NTSTATUS status;
	//ѭ��������������g_MyExitProcess
	while (true) {

		if (g_MyNtQueryInformationProcess!=NULL) {//��һ�ζ���Ҫ��̬��ȡ
			NTSTATUS status = g_MyNtQueryInformationProcess(g_MyGetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugObjectHandle, &hDebugObject, sizeof(hDebugObject), NULL);
			if (hDebugObject) {
				//g_MyMessageBoxA(0, "��⵽������2", "tis", MB_OK);
				g_MyExitProcess(0);//�������� c�⺯������ʱ��֪�Ƿ���Ҫ��̬��λ��
			}
		}

		DWORD isDebug = 0;
		_asm
		{
			mov eax, dword ptr fs : [0x30]
			mov eax, [eax + 0x68]
			mov isDebug, eax
		}
		if (isDebug == 0x70) {
			//g_MyMessageBoxA(0, "��⵽������1", "tis", MB_OK);
			//exit(0);//�������� c�⺯������ʱ��֪�Ƿ���Ҫ��̬��λ��
			g_MyExitProcess(0);
		}
	}

	return 0;//����kernel32
}

BOOL checkdebug() {
	DWORD isDebug = 0;
	_asm
	{
		mov eax, dword ptr fs : [0x30]
		mov eax, [eax + 0x68]
		mov isDebug, eax
	}
	if (isDebug == 0x70) {
		g_MyMessageBoxA(0, "��⵽������", "SM444", MB_OK);
		g_MyExitProcess(0);
		return;//��⵽������ֱ���˳�
	}
}

//ע������ĺ�������Ҫ��̬���
void Ringzero() {
	HANDLE hDevice = g_MyCreateFileA("\\\\.\\MyDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		g_MyMessageBoxA(0, "�ں˱���ͨ��ʧ�ܣ��볢�Լ����ں˱������ٴ�����", "tis", NULL);
		exit(0);//��������
		return;
	}
	//�õ���PID��֪�ں˱�������

}

_declspec(naked) void packStart()
{
	//����Ĵ�������
	_asm pushad
	//�Ǵ����߼�
	GetImportantModule();
	GetFunctions();//�˴������쳣
	//g_MyMessageBoxA(0, "�Ǵ���ִ��", "��ʾ", MB_OK);
	//�˴��������ں˲����ͨ��
	//Ringzero();
	g_MyCreateThread(NULL, 0, ThreadFunc, NULL, 0, NULL);//checkdebug thread  ��Ϊ������������������̱Ƚ϶̵Ļ�������ִ����
	//checkdebug();
	DecodeSections();
	//�ָ��Ĵ�������������ԭʼOEP ��Ҫ˼��ԭʼOEP��ֵ�Ƕ���
	_asm popad
	_asm jmp g_PackInfo.oldOEP 
}