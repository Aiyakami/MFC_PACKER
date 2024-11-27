#include "pch.h"
#include "packer.h"

PeUtils::PeUtils()
{

	//初始化变量
	fileBuff = NULL;
	pDosHeader = NULL;
	pNtHeader = NULL;
	pOptionHeader = NULL;
	pFileHeader = NULL;
	filesize = 0;
}

PeUtils::~PeUtils()
{
	if (fileBuff)
	{
		delete[] fileBuff;
	}
}
#include<stdio.h>
BOOL PeUtils::LoadFile(const char* path)
{
	//打开原PE文件
	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD dwError = GetLastError();
		// 处理错误，比如输出错误信息
		printf("CreateFileA failed with error code: %lu\n", dwError);
	}
	//获取文件大小
	filesize = GetFileSize(hFile, 0);
	fileBuff = new char[filesize] {};
	//存入缓冲区文件指针
	DWORD realsize = 0;
	BOOL ifSucess = ReadFile(hFile, fileBuff, filesize, &realsize, NULL);
	if (ifSucess == FALSE)
	{
		MessageBoxA(0, "文件打开失败！", "提示", MB_OK);
		return FALSE;
	}
	InitFileInfo();
	BOOL is32Bit = (pNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
	if (!is32Bit) {
		MessageBoxA(0, "当前仅支持32位程序，该程序不受支持", "提示", MB_OK);
		return FALSE;
	}
	return TRUE;
}

BOOL PeUtils::InitFileInfo()
{
	pDosHeader = (PIMAGE_DOS_HEADER)fileBuff;
	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + fileBuff);//起始地址+偏移
	pFileHeader = &pNtHeader->FileHeader;
	pOptionHeader = &pNtHeader->OptionalHeader;
	return TRUE;
}

DWORD PeUtils::GetAlignSize(DWORD realSize, DWORD alignSize)
{
	if (realSize % alignSize == 0)
	{
		return realSize;
	}
	return (realSize / alignSize + 1) * alignSize;
}

PIMAGE_SECTION_HEADER PeUtils::GetLastSectionHeader()
{
	PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(pNtHeader);


	return firstSection + (pFileHeader->NumberOfSections - 1);//返回最后一个区段的首地址
}

BOOL PeUtils::SaveFile(const char* path)
{
	HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD realWrite = 0;
	BOOL ifSucess = WriteFile(hFile, fileBuff, filesize, &realWrite, NULL);
	CloseHandle(hFile);
	return TRUE;
}

#include"sm4test.h"
BOOL PeUtils::EncodeSections()
{
	//VS默认第一个区段是代码段，如果是其他编译器还需再考虑
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	int keys = 0x51;
	char* pData = (DWORD)(pSectionHeader->PointerToRawData) + fileBuff;
	uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x61, 0x16, 0x88, 0x3b, 0xf2, 0x03 };
	uint8_t paddedData[32] = { 0 };
	memcpy(paddedData, pData, pSectionHeader->SizeOfRawData);
	size_t paddedSize = 0;
	pkcs7_padding(paddedData, pSectionHeader->SizeOfRawData, 16, &paddedSize);

	// 初始化SM4上下文
	SM4_CTX ctx;
	sm4_setkey(&ctx, key);
	uint8_t encryptedData[32] = { 0 };
	sm4_crypt_ecb(&ctx, SM4_ENCRYPT, paddedSize, paddedData, encryptedData);

	for (int i = 0; i < pSectionHeader->SizeOfRawData; i++)
	{
		
		pData[i] ^= keys;
	}
	return TRUE;
}

DWORD PeUtils::GetJmpVA()
{
	DWORD jmpva = pOptionHeader->AddressOfEntryPoint + pOptionHeader->ImageBase;
	return jmpva;
}

BOOL PeUtils::SetOep(DWORD oepRva)
{
	pOptionHeader->AddressOfEntryPoint = GetLastSectionHeader()->VirtualAddress + oepRva;
	return TRUE;
}

//修复重定位表
BOOL PeUtils::RepairRelco(DWORD imageBase)
{

	PIMAGE_DOS_HEADER pDllDosHeadr = (PIMAGE_DOS_HEADER)imageBase;
	//pDllDosHeader->e_lfanew 是一个指向PE文件的NT头（PE头）的偏移量的字段
	PIMAGE_NT_HEADERS pDllNtHeadr = (PIMAGE_NT_HEADERS)(pDllDosHeadr->e_lfanew + imageBase);
	PIMAGE_OPTIONAL_HEADER pDllOprionHeadr = &pDllNtHeadr->OptionalHeader;
	//拿到重定位表位置
	IMAGE_DATA_DIRECTORY dataDirctory = pDllOprionHeadr->DataDirectory[5];
	PIMAGE_BASE_RELOCATION  pDllRelocation =
		(PIMAGE_BASE_RELOCATION)(dataDirctory.VirtualAddress + imageBase);
	PIMAGE_SECTION_HEADER dllFirstSectionHead = IMAGE_FIRST_SECTION(pDllNtHeadr);
	while (pDllRelocation->SizeOfBlock != 0)
	{
		//小偏移表数量
		DWORD reNumber = (pDllRelocation->SizeOfBlock - 8) / 2;
		char* beginAddr = (char*)pDllRelocation;
		beginAddr += 8;
		//遍历小偏移表
		for (int i = 0; i < reNumber; i++) {
			WORD* prelocRva = (WORD*)beginAddr;
			if ((*prelocRva & 0x3000))//判断是否有效
			{
				//取word前12位+大偏移=rva
				WORD repairRva = (*prelocRva & 0x0FFF) + pDllRelocation->VirtualAddress;
				//获取需要重定位变量的地址
				DWORD* relRepairAddr = (DWORD*)(imageBase + repairRva);
				//计算其在被加壳程序中的偏移
				DWORD newFileSection = (DWORD)(GetLastSectionHeader()->PointerToRawData + fileBuff);

				DWORD newSectionAddr = GetLastSectionHeader()->VirtualAddress + pOptionHeader->ImageBase;
				//获取变量在被加壳程序新添加区段中的位置
				DWORD destAddr = (DWORD)relRepairAddr - (dllFirstSectionHead->VirtualAddress + imageBase) + newFileSection;
				//计算变量rva在filebuff中的
				*(DWORD*)destAddr = (*(DWORD*)destAddr - imageBase) - dllFirstSectionHead->VirtualAddress + newSectionAddr;

			}
			beginAddr += 2;
		}
		pDllRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pDllRelocation + pDllRelocation->SizeOfBlock);
	}
	return 0;
}

BOOL PeUtils::FixedImagebase()
{

	pOptionHeader->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	return 0;
}

BOOL PeUtils::InserSection(const char* sectionName, DWORD codesize, char* codebuff, DWORD attribute)
{

	//获取文件对齐后的缓冲区大小，用于存放新程序
	DWORD newFileSize = GetAlignSize(filesize + codesize, pOptionHeader->FileAlignment);
	char* newFileBuff = new char[newFileSize] {};
	memcpy_s(newFileBuff, newFileSize, fileBuff, filesize);
	filesize = newFileSize;
	delete[] fileBuff;
	fileBuff = newFileBuff;
	InitFileInfo();
	//添加区段头
	PIMAGE_SECTION_HEADER plastSectionHeader = GetLastSectionHeader();
	plastSectionHeader++;
	//设置区段头属性
	//设置内存大小
	plastSectionHeader->Misc.VirtualSize = GetAlignSize(codesize, pOptionHeader->SectionAlignment);
	//设置区段名称
	strcpy_s((char*)plastSectionHeader->Name, 8, sectionName);
	//文件大小
	plastSectionHeader->SizeOfRawData = GetAlignSize(codesize, pOptionHeader->FileAlignment);
	//设置virtualAddress
	PIMAGE_SECTION_HEADER plastSectionHeader2 = GetLastSectionHeader();//获取前一个区段头，要用到这个区段头才能计算出相关信息
	plastSectionHeader->VirtualAddress = plastSectionHeader2->VirtualAddress + GetAlignSize(plastSectionHeader2->Misc.VirtualSize, pOptionHeader->SectionAlignment);
	//设置文件中的偏移
	plastSectionHeader->PointerToRawData = plastSectionHeader2->PointerToRawData + plastSectionHeader2->SizeOfRawData;
	plastSectionHeader->Characteristics = attribute;//区段属性，是否可执行
	//修改文件头中numberOfSections
	pFileHeader->NumberOfSections++;
	//修改sizeOfImage  文件镜像大小
	pOptionHeader->SizeOfImage += GetAlignSize(codesize, pOptionHeader->SectionAlignment);//第一个值是加入的代码大小，第二个值是对齐值
	//将壳代码放入新的区段中
	char* sectionAddr = GetLastSectionHeader()->PointerToRawData + fileBuff;
	memcpy(sectionAddr, codebuff, codesize);
	return TRUE;
}


