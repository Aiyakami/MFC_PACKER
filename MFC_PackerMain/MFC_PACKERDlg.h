
// MFC_PACKERDlg.h: 头文件
//

#pragma once


// CMFCPACKERDlg 对话框
class CMFCPACKERDlg : public CDialogEx
{
// 构造
public:
	CMFCPACKERDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFC_PACKER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton4();
	afx_msg PCHAR GetInputFilePath();
	afx_msg PCHAR CMFCPACKERDlg::GetSectionName();
	afx_msg PCHAR GetOutputFilePath(CString output);
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
};
