// AdjTime.cpp : implementation file
//

#include "stdafx.h"
#include "kx509mfc.h"
#include "AdjTime.h"

#ifdef _DEBUG
//#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CAdjTime dialog


CAdjTime::CAdjTime(CWnd* pParent /*=NULL*/)
	: CDialog(CAdjTime::IDD, pParent)
{
	//{{AFX_DATA_INIT(CAdjTime)
	m_newRate = 0;
	//}}AFX_DATA_INIT
}


void CAdjTime::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAdjTime)
	DDX_Text(pDX, IDC_ADJ_TIME, m_newRate);
	DDV_MinMaxUInt(pDX, m_newRate, 0, 86400);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CAdjTime, CDialog)
	//{{AFX_MSG_MAP(CAdjTime)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CAdjTime message handlers
