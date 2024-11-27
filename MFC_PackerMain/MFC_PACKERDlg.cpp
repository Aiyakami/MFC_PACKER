
// MFC_PACKERDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MFC_PACKER.h"
#include "MFC_PACKERDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCPACKERDlg 对话框



CMFCPACKERDlg::CMFCPACKERDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFC_PACKER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCPACKERDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMFCPACKERDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCPACKERDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON4, &CMFCPACKERDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCPACKERDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CMFCPACKERDlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CMFCPACKERDlg 消息处理程序

BOOL CMFCPACKERDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	CMFCPACKERDlg::OnBnClickedButton2();
	CMFCPACKERDlg::OnBnClickedButton3();
	((CButton*)GetDlgItem(IDC_CHECK1))->SetCheck(BST_CHECKED);
	((CButton*)GetDlgItem(IDC_CHECK2))->SetCheck(BST_CHECKED);
	((CButton*)GetDlgItem(IDC_CHECK3))->SetCheck(BST_CHECKED);
	((CButton*)GetDlgItem(IDC_CHECK4))->SetCheck(BST_CHECKED);
	((CButton*)GetDlgItem(IDC_CHECK5))->SetCheck(BST_CHECKED);
	((CButton*)GetDlgItem(IDC_CHECK6))->SetCheck(BST_CHECKED);
	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMFCPACKERDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCPACKERDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMFCPACKERDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//选择需要加壳的文件路径
void CMFCPACKERDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	CString selectedFile;
	// 构造文件对话框对象
	CFileDialog fileDlg(TRUE);
	// 设置对话框的标题和过滤器
	fileDlg.m_ofn.lpstrTitle = _T("选择文件");
	fileDlg.m_ofn.lpstrFilter = _T("所有文件 (*.*)|*.*||");

	// 显示文件对话框，让用户选择文件
	if (fileDlg.DoModal() == IDOK) {
		selectedFile = fileDlg.GetPathName(); // 获取用户选择的文件路径
		//写入控件中
		SetDlgItemText(IDC_EDIT2, selectedFile);
	}
}



#include<Windows.h>
#include"packer.h"

typedef struct _PACKINFO
{
	DWORD newOEP;
	DWORD oldOEP;
}PACKINFO, * PPACKINFO;


PCHAR CMFCPACKERDlg::GetInputFilePath()
{
	CString Content;
	GetDlgItemText(IDC_EDIT2, Content); // IDC_YOUR_EDIT_CONTROL 是编辑框的ID
	LPWSTR lpwstr = Content.GetBuffer(Content.GetLength());
	// 第一步：计算所需的缓冲区大小
	int bufferSize = WideCharToMultiByte(CP_ACP, 0, lpwstr, -1, NULL, 0, NULL, NULL);//ANSI编码（CP_ACP）和UTF-8编码（CP_UTF8）
	if (bufferSize == 0) {
		return NULL;
	}
	// 第二步：分配缓冲区
	char* utf8Str = new char[bufferSize];
	// 第三步：执行转换
	int result = WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, utf8Str, bufferSize, NULL, NULL);
	if (result == 0) {
		delete[] utf8Str; // 清理分配的内存
		return NULL;
	};
	return utf8Str;
}


PCHAR CMFCPACKERDlg::GetSectionName()
{
	CString Content;
	GetDlgItemText(IDC_EDIT4, Content); // IDC_YOUR_EDIT_CONTROL 是编辑框的ID
	LPWSTR lpwstr = Content.GetBuffer(Content.GetLength());
	// 第一步：计算所需的缓冲区大小
	int bufferSize = WideCharToMultiByte(CP_ACP, 0, lpwstr, -1, NULL, 0, NULL, NULL);//ANSI编码（CP_ACP）和UTF-8编码（CP_UTF8）
	if (bufferSize == 0) {
		return NULL;
	}
	// 第二步：分配缓冲区
	char* utf8Str = new char[bufferSize];
	// 第三步：执行转换
	int result = WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, utf8Str, bufferSize, NULL, NULL);
	if (result == 0) {
		delete[] utf8Str; // 清理分配的内存
		return NULL;
	};
	return utf8Str;
}

PCHAR CMFCPACKERDlg::GetOutputFilePath(CString output)
{

	LPWSTR lpwstr = output.GetBuffer(output.GetLength());
	// 第一步：计算所需的缓冲区大小
	int bufferSize = WideCharToMultiByte(CP_ACP, 0, lpwstr, -1, NULL, 0, NULL, NULL);//ANSI编码（CP_ACP）和UTF-8编码（CP_UTF8）
	if (bufferSize == 0) {
		return NULL;
	}
	// 第二步：分配缓冲区
	char* utf8Str = new char[bufferSize];
	// 第三步：执行转换
	int result = WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, utf8Str, bufferSize, NULL, NULL);
	if (result == 0) {
		delete[] utf8Str; // 清理分配的内存
		return NULL;
	};
	return utf8Str;
}

void CMFCPACKERDlg::OnBnClickedButton4()
{



	PeUtils peutils;
	//peutils.LoadFile(GetInputFilePath());
	if (!peutils.LoadFile(GetInputFilePath())) {
		return;
	}

	peutils.FixedImagebase();
	peutils.EncodeSections();
	HMODULE hModule = LoadLibraryA("pack.dll");//这一步错误
	if (hModule == NULL) {
		return;
	}
	PPACKINFO ppackinfo = (PPACKINFO)GetProcAddress(hModule, "g_PackInfo");
	ppackinfo->oldOEP = peutils.GetJmpVA();
	PIMAGE_DOS_HEADER dllDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS dllNtHeader = (PIMAGE_NT_HEADERS)(dllDosHeader->e_lfanew + (DWORD)hModule);
	PIMAGE_SECTION_HEADER dllFirstSectionHeader = IMAGE_FIRST_SECTION(dllNtHeader);
	char* sectionBuff = (char*)(dllFirstSectionHeader->VirtualAddress + (DWORD)hModule);
	peutils.InserSection(GetSectionName(), dllFirstSectionHeader->Misc.VirtualSize, sectionBuff, 0xE00000E0);
	//修复重定位表 存放全局变量的
	peutils.RepairRelco((DWORD)hModule);
	DWORD oepRva = ppackinfo->newOEP - (DWORD)hModule;
	DWORD offsets = oepRva - dllFirstSectionHeader->VirtualAddress;
	peutils.SetOep(offsets);

	// TODO: 在此添加控件通知处理程序代码
	CString fileName;

	CString defaultFileName = _T("VTPACKER.exe"); // 默认的保存文件名
	CString defaultDir = _T("C:\\Users\\At\\Desktop\\packer"); // 默认的保存路径

	// 构造文件对话框对象
	CFileDialog fileDlg(FALSE, NULL, defaultFileName, OFN_OVERWRITEPROMPT, _T("文本文件 (*.txt)|*.txt||"), this);

	// 设置默认的保存路径
	fileDlg.m_ofn.lpstrInitialDir = defaultDir;

	// 设置对话框的标题和过滤器
	fileDlg.m_ofn.lpstrTitle = _T("保存文件");

	// 显示文件对话框，让用户指定保存路径
	if (fileDlg.DoModal() == IDOK) {
		fileName = fileDlg.GetPathName(); // 获取用户指定的保存路径
		peutils.SaveFile(GetOutputFilePath(fileName));
	}
}

#include <iostream>
void CMFCPACKERDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const int length = 16;

	CString result;

	srand(static_cast<unsigned int>(time(nullptr)));

	for (int i = 0; i < length; ++i)
	{
		int randomIndex = rand() % characters.length();
		char randomChar = characters[randomIndex];
		result += randomChar;
	}
	SetDlgItemText(IDC_EDIT3, result);
}


void CMFCPACKERDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	// TODO: 在此添加控件通知处理程序代码
	const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const int length = 6;

	CString result;

	srand(static_cast<unsigned int>(time(nullptr)));

	for (int i = 0; i < length; ++i)
	{
		int randomIndex = rand() % characters.length();
		char randomChar = characters[randomIndex];
		result += randomChar;
	}
	SetDlgItemText(IDC_EDIT4, result);
}
