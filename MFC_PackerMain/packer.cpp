#include "pch.h"
#include "packer.h"

PeUtils::PeUtils()
{

	//��ʼ������
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
	//��ԭPE�ļ�
	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD dwError = GetLastError();
		// ������󣬱������������Ϣ
		printf("CreateFileA failed with error code: %lu\n", dwError);
	}
	//��ȡ�ļ���С
	filesize = GetFileSize(hFile, 0);
	fileBuff = new char[filesize] {};
	//���뻺�����ļ�ָ��
	DWORD realsize = 0;
	BOOL ifSucess = ReadFile(hFile, fileBuff, filesize, &realsize, NULL);
	if (ifSucess == FALSE)
	{
		MessageBoxA(0, "�ļ���ʧ�ܣ�", "��ʾ", MB_OK);
		return FALSE;
	}
	InitFileInfo();
	BOOL is32Bit = (pNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
	if (!is32Bit) {
		MessageBoxA(0, "��ǰ��֧��32λ���򣬸ó�����֧��", "��ʾ", MB_OK);
		return FALSE;
	}
	return TRUE;
}

BOOL PeUtils::InitFileInfo()
{
	pDosHeader = (PIMAGE_DOS_HEADER)fileBuff;
	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + fileBuff);//��ʼ��ַ+ƫ��
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


	return firstSection + (pFileHeader->NumberOfSections - 1);//�������һ�����ε��׵�ַ
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
	//VSĬ�ϵ�һ�������Ǵ���Σ���������������������ٿ���
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	int keys = 0x51;
	char* pData = (DWORD)(pSectionHeader->PointerToRawData) + fileBuff;
	uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x61, 0x16, 0x88, 0x3b, 0xf2, 0x03 };
	uint8_t paddedData[32] = { 0 };
	memcpy(paddedData, pData, pSectionHeader->SizeOfRawData);
	size_t paddedSize = 0;
	pkcs7_padding(paddedData, pSectionHeader->SizeOfRawData, 16, &paddedSize);

	// ��ʼ��SM4������
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

//�޸��ض�λ��
BOOL PeUtils::RepairRelco(DWORD imageBase)
{

	PIMAGE_DOS_HEADER pDllDosHeadr = (PIMAGE_DOS_HEADER)imageBase;
	//pDllDosHeader->e_lfanew ��һ��ָ��PE�ļ���NTͷ��PEͷ����ƫ�������ֶ�
	PIMAGE_NT_HEADERS pDllNtHeadr = (PIMAGE_NT_HEADERS)(pDllDosHeadr->e_lfanew + imageBase);
	PIMAGE_OPTIONAL_HEADER pDllOprionHeadr = &pDllNtHeadr->OptionalHeader;
	//�õ��ض�λ��λ��
	IMAGE_DATA_DIRECTORY dataDirctory = pDllOprionHeadr->DataDirectory[5];
	PIMAGE_BASE_RELOCATION  pDllRelocation =
		(PIMAGE_BASE_RELOCATION)(dataDirctory.VirtualAddress + imageBase);
	PIMAGE_SECTION_HEADER dllFirstSectionHead = IMAGE_FIRST_SECTION(pDllNtHeadr);
	while (pDllRelocation->SizeOfBlock != 0)
	{
		//Сƫ�Ʊ�����
		DWORD reNumber = (pDllRelocation->SizeOfBlock - 8) / 2;
		char* beginAddr = (char*)pDllRelocation;
		beginAddr += 8;
		//����Сƫ�Ʊ�
		for (int i = 0; i < reNumber; i++) {
			WORD* prelocRva = (WORD*)beginAddr;
			if ((*prelocRva & 0x3000))//�ж��Ƿ���Ч
			{
				//ȡwordǰ12λ+��ƫ��=rva
				WORD repairRva = (*prelocRva & 0x0FFF) + pDllRelocation->VirtualAddress;
				//��ȡ��Ҫ�ض�λ�����ĵ�ַ
				DWORD* relRepairAddr = (DWORD*)(imageBase + repairRva);
				//�������ڱ��ӿǳ����е�ƫ��
				DWORD newFileSection = (DWORD)(GetLastSectionHeader()->PointerToRawData + fileBuff);

				DWORD newSectionAddr = GetLastSectionHeader()->VirtualAddress + pOptionHeader->ImageBase;
				//��ȡ�����ڱ��ӿǳ�������������е�λ��
				DWORD destAddr = (DWORD)relRepairAddr - (dllFirstSectionHead->VirtualAddress + imageBase) + newFileSection;
				//�������rva��filebuff�е�
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

	//��ȡ�ļ������Ļ�������С�����ڴ���³���
	DWORD newFileSize = GetAlignSize(filesize + codesize, pOptionHeader->FileAlignment);
	char* newFileBuff = new char[newFileSize] {};
	memcpy_s(newFileBuff, newFileSize, fileBuff, filesize);
	filesize = newFileSize;
	delete[] fileBuff;
	fileBuff = newFileBuff;
	InitFileInfo();
	//�������ͷ
	PIMAGE_SECTION_HEADER plastSectionHeader = GetLastSectionHeader();
	plastSectionHeader++;
	//��������ͷ����
	//�����ڴ��С
	plastSectionHeader->Misc.VirtualSize = GetAlignSize(codesize, pOptionHeader->SectionAlignment);
	//������������
	strcpy_s((char*)plastSectionHeader->Name, 8, sectionName);
	//�ļ���С
	plastSectionHeader->SizeOfRawData = GetAlignSize(codesize, pOptionHeader->FileAlignment);
	//����virtualAddress
	PIMAGE_SECTION_HEADER plastSectionHeader2 = GetLastSectionHeader();//��ȡǰһ������ͷ��Ҫ�õ��������ͷ���ܼ���������Ϣ
	plastSectionHeader->VirtualAddress = plastSectionHeader2->VirtualAddress + GetAlignSize(plastSectionHeader2->Misc.VirtualSize, pOptionHeader->SectionAlignment);
	//�����ļ��е�ƫ��
	plastSectionHeader->PointerToRawData = plastSectionHeader2->PointerToRawData + plastSectionHeader2->SizeOfRawData;
	plastSectionHeader->Characteristics = attribute;//�������ԣ��Ƿ��ִ��
	//�޸��ļ�ͷ��numberOfSections
	pFileHeader->NumberOfSections++;
	//�޸�sizeOfImage  �ļ������С
	pOptionHeader->SizeOfImage += GetAlignSize(codesize, pOptionHeader->SectionAlignment);//��һ��ֵ�Ǽ���Ĵ����С���ڶ���ֵ�Ƕ���ֵ
	//���Ǵ�������µ�������
	char* sectionAddr = GetLastSectionHeader()->PointerToRawData + fileBuff;
	memcpy(sectionAddr, codebuff, codesize);
	return TRUE;
}


