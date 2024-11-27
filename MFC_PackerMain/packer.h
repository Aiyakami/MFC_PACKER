#pragma once
#pragma once
#include<Windows.h>

class PeUtils
{
private:
	char* fileBuff;//������
	PIMAGE_DOS_HEADER pDosHeader;//DOSͷ
	PIMAGE_NT_HEADERS pNtHeader;//NTͷ
	PIMAGE_OPTIONAL_HEADER pOptionHeader;//PE��ѡͷ
	PIMAGE_FILE_HEADER pFileHeader;//�ļ�ͷ
	DWORD filesize;

public:
	PeUtils();
	~PeUtils();
	BOOL LoadFile(const char* path);
	BOOL InitFileInfo();
	BOOL InserSection(const char* sectionName, DWORD codesize, char* codebuff, DWORD attribute);//�������� �����С ��������ָ�� ��������
	DWORD GetAlignSize(DWORD realSize, DWORD alignSize);
	PIMAGE_SECTION_HEADER GetLastSectionHeader();
	BOOL SaveFile(const char* path);
	BOOL EncodeSections();
	DWORD GetJmpVA();
	BOOL SetOep(DWORD oepRva);
	BOOL RepairRelco(DWORD imageBase);//�޸�DLL�ļ����ض�λ��
	BOOL FixedImagebase();
};