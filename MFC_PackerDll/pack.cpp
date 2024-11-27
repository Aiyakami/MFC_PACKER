#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include"pack.h"
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
//合并之后data段的可写属性将会被去除，需要再次给出
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
		mov eax, dword ptr fs : [0x30]//线程环境块TEB位置
		mov eax, dword ptr[eax+0xC]//进程环境块PEB位置
		mov eax, dword ptr[eax + 0x1C]//模块列表（LDR）的地址
		mov eax, [eax]//获取了 LDR 的头指针
		mov eax,dword ptr[eax+0x8]// LDR 结构中找到了第一个模块的地址
		mov dwBase,eax//第一个模块就是kernel32也有可能是kernelbase
	}

	return dwBase;//返回kernel32
}

DWORD MyGetProcAddress(DWORD hModule,LPCSTR funName)
{
	//获取DOS头Nt头
	PIMAGE_DOS_HEADER pDosHeader= (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)hModule);
	//获取导出表
	DWORD exportTableVa = pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(exportTableVa + hModule);
	//找到导出名称表，序号表，地址表
	DWORD* nameTable = (DWORD*)(exportTable->AddressOfNames + hModule);
	DWORD* funTable= (DWORD*)(exportTable->AddressOfFunctions+ hModule);
	WORD* numberTable= (WORD*)(exportTable->AddressOfNameOrdinals+ hModule);
	//开始遍历找名字
	for (int i = 0; i < (int)(exportTable->NumberOfNames); i++) {
		//获取函数名字
		char* name = (char*)(nameTable[i] + hModule);
		if (!strcmp(name,funName)) {
			return funTable[numberTable[i]] + hModule;
		}
	}
	return 0;
}
void GetFunctions()//用来初始化一些函数的地址
{
	//获取kerner32或者kernelbase模块基址
	DWORD pkernelBase = GetImportantModule();
	//获取loadLibraryEx
	g_MyLoadLibraryExA=(MyLoadLibraryExA)MyGetProcAddress(pkernelBase, "LoadLibraryExA");
	//获取kerner32地址，由于前面不确定到底是kerner32还是kernerbase
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
		return;//ntdll必须加错误处理
	}
	g_MyNtQueryInformationProcess = (MyNtQueryInformationProcess)g_MYGetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!g_MyNtQueryInformationProcess) {
		//FreeLibrary(hNtDll);//这里错误
		return;
	}
}
#include"sm4.h"

//解密
BOOL DecodeSections()
{
	int key = 0x51;
	//GetModuleHandleA(NULL);不能直接调用这个API
	HMODULE hModule = g_MyGetModuleHandleA(0);//0表示获取当前进程的模块基地址
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders= (PIMAGE_NT_HEADERS)((DWORD)hModule+pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER firstSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);//宏定义函数
	char* sectionBuff = (char*)(firstSectionHeader->VirtualAddress + (DWORD)hModule);
	//修改内存属性为可写
	DWORD oldProtect = 0;//保存原有属性方便复原
	g_MyVirtualProtect(sectionBuff, firstSectionHeader->SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProtect);


	uint8_t keys[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x61, 0x16, 0x88, 0x3b, 0xf2, 0x03 };
	uint8_t paddedData[32] = { 0 };
	memcpy(paddedData, sectionBuff, firstSectionHeader->SizeOfRawData);
	size_t paddedSize = 0;
	pkcs7_padding(paddedData, firstSectionHeader->SizeOfRawData, 16, &paddedSize);
	// 初始化SM4上下文
	SM4_CTX ctx;
	sm4_setkey(&ctx, keys);
	uint8_t encryptedData[32] = { 0 };
	sm4_crypt_ecb(&ctx, SM4_ENCRYPT, paddedSize, paddedData, encryptedData);
	for (int i = 0; i < firstSectionHeader->SizeOfRawData; i++)
	{
		sectionBuff[i] = sectionBuff[i] ^ key;
	}
	g_MyVirtualProtect(sectionBuff, firstSectionHeader->SizeOfRawData, oldProtect, &oldProtect);//还原内存属性
	return TRUE;
}

DWORD WINAPI ThreadFunc(LPVOID lpParam) {
	HANDLE hDebugObject;
	NTSTATUS status;
	//循环检测调试器对象g_MyExitProcess
	while (true) {

		if (g_MyNtQueryInformationProcess!=NULL) {//这一段都需要动态获取
			NTSTATUS status = g_MyNtQueryInformationProcess(g_MyGetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugObjectHandle, &hDebugObject, sizeof(hDebugObject), NULL);
			if (hDebugObject) {
				//g_MyMessageBoxA(0, "检测到调试器2", "tis", MB_OK);
				g_MyExitProcess(0);//结束进程 c库函数，暂时不知是否需要动态定位到
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
			//g_MyMessageBoxA(0, "检测到调试器1", "tis", MB_OK);
			//exit(0);//结束进程 c库函数，暂时不知是否需要动态定位到
			g_MyExitProcess(0);
		}
	}

	return 0;//返回kernel32
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
		g_MyMessageBoxA(0, "检测到调试器", "SM444", MB_OK);
		g_MyExitProcess(0);
		return;//检测到调试器直接退出
	}
}

//注意这里的函数还需要动态获得
void Ringzero() {
	HANDLE hDevice = g_MyCreateFileA("\\\\.\\MyDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		g_MyMessageBoxA(0, "内核保护通信失败，请尝试加载内核保护后再次运行", "tis", NULL);
		exit(0);//结束进程
		return;
	}
	//拿到后将PID告知内核保护程序

}

_declspec(naked) void packStart()
{
	//保存寄存器环境
	_asm pushad
	//壳代码逻辑
	GetImportantModule();
	GetFunctions();//此处触发异常
	//g_MyMessageBoxA(0, "壳代码执行", "提示", MB_OK);
	//此处尝试与内核层进行通信
	//Ringzero();
	g_MyCreateThread(NULL, 0, ThreadFunc, NULL, 0, NULL);//checkdebug thread  因为并发性所以如何主进程比较短的话还是能执行完
	//checkdebug();
	DecodeSections();
	//恢复寄存器环境，跳回原始OEP 需要思考原始OEP的值是多少
	_asm popad
	_asm jmp g_PackInfo.oldOEP 
}