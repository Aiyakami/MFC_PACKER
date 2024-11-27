#pragma once
#pragma once
#include<Windows.h>

class PeUtils
{
private:
	char* fileBuff;//输入流
	PIMAGE_DOS_HEADER pDosHeader;//DOS头
	PIMAGE_NT_HEADERS pNtHeader;//NT头
	PIMAGE_OPTIONAL_HEADER pOptionHeader;//PE可选头
	PIMAGE_FILE_HEADER pFileHeader;//文件头
	DWORD filesize;

public:
	PeUtils();
	~PeUtils();
	BOOL LoadFile(const char* path);
	BOOL InitFileInfo();
	BOOL InserSection(const char* sectionName, DWORD codesize, char* codebuff, DWORD attribute);//区段名称 代码大小 代码内容指针 区段属性
	DWORD GetAlignSize(DWORD realSize, DWORD alignSize);
	PIMAGE_SECTION_HEADER GetLastSectionHeader();
	BOOL SaveFile(const char* path);
	BOOL EncodeSections();
	DWORD GetJmpVA();
	BOOL SetOep(DWORD oepRva);
	BOOL RepairRelco(DWORD imageBase);//修复DLL文件的重定位表
	BOOL FixedImagebase();
};