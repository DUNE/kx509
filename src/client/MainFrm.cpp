// MainFrm.cpp : implementation of the CMainFrame class
//

#include "stdafx.h"
#include "kx509mfc.h"
#include "kx509.h"
#include "MainFrm.h"
#include "AdjTime.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


extern "C" void		log_printf(char *, ...);

extern	volatile LONG cAppInstances;
extern "C" void clean_cert_store(char *realm);
extern "C"			kx509_main(int argc, char **argv);
extern "C"	DWORD	GetSilentSelectFlag();
extern "C"	DWORD	SetSilentSelectFlag(BOOL bNewValue);
extern	int			kx509_argc;
extern	char		*kx509_argv[];
extern "C" char		*get_cert_subj(char *realm);
extern 	void		get_cert_time_left(char *realm, CTimeSpan *ptimeLeft);
extern "C" char		szCertRealm[];
extern "C" BOOL 	bPwdPrompt;  
extern "C" BOOL   bkx509busy;
extern "C" BOOL 	bSilentSelect;  
extern "C" char		*szStatusMsg;
extern "C" char		gszHardErrorMsg[];
extern CKx509mfcApp theApp;
extern CAdjTime		adjTime;
extern CMainFrame	*pMainFrame;

// Defined for MESSAGE_MAP directly below
#define	IDS_EXIT_APP_MSG		130
#define IDS_SILENT_SELECT       131

// Message to be registered as the one to generate when there's SysTray events
#define WM_MYSYSTRAY_MESSAGE		(WM_USER+1000)

/////////////////////////////////////////////////////////////////////////////
// CMainFrame

IMPLEMENT_DYNCREATE(CMainFrame, CFrameWnd)

BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
	//{{AFX_MSG_MAP(CMainFrame)

	// Routine to call when OnCreate-registered Message is generated
	ON_MESSAGE(WM_MYSYSTRAY_MESSAGE, OnSysTrayMessage)

	ON_WM_CREATE()
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
	ON_COMMAND(IDS_ADJ_RATE, OnAdjRate)
	ON_COMMAND(IDS_EXIT_APP_MSG, OnExitApp)		// Actually handled by SysTrayMenu
	ON_COMMAND(IDS_SILENT_SELECT, OnExitApp)	// Actually handled by SysTrayMenu
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CMainFrame construction/destruction

CMainFrame::CMainFrame()
{
	// TODO: add member initialization code here
	m_sampleRate = 0;
}

CMainFrame::~CMainFrame()
{
	m_trayIcon.DelSysTrayIcon();
}

int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CFrameWnd::OnCreate(lpCreateStruct) == -1)
		return -1;

	m_trayIcon.AddSysTrayIcon(this,IDI_UNAUTH);

	// Register with Shell the WM_MESSAGE to send when there's a SysTray "event"
	m_trayIcon.SetSysTrayCallback(WM_MYSYSTRAY_MESSAGE);

	return 0;
}

BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs)
{
	if( !CFrameWnd::PreCreateWindow(cs) )
		return FALSE;

	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CMainFrame diagnostics

#ifdef _DEBUG
void CMainFrame::AssertValid() const
{
	CFrameWnd::AssertValid();
}

void CMainFrame::Dump(CDumpContext& dc) const
{
	CFrameWnd::Dump(dc);
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CMainFrame message handlers

// CMainFrame::SysTrayMenu - This will handle the popup menu for our system
//                           tray icon.
//

DWORD CMainFrame::SysTrayMenu() {
	CMenu			cmenu;
	CPoint			mouse;
	CString			cstr;
	DWORD			nMenuItem		= -1;
	int				rc				= -1;
	MENUITEMINFO	mi				= {0};
	ULONG			iData[200]		= {0};
	WCHAR			tData[200]		= {0};
	BOOL			bChecked		= FALSE;
	int				bSilentSelect	= GetSilentSelectFlag();

	cmenu.CreatePopupMenu();

	// Menu Item 0 -- Exit App
	cstr.LoadString(IDS_EXIT_APP_NOW);
	cmenu.InsertMenu(0, MF_BYPOSITION | MF_STRING | MF_ENABLED,
						IDS_EXIT_APP_MSG, 
						cstr.GetBuffer(64));
	cstr.ReleaseBuffer();

	// Menu Item 1 -- Silent Cert Select (first check if IE supports this)
	if (bSilentSelect == -1)
	{
		// IE doesn't support Silent Select (version prior to 5.5)
		cstr.LoadString(IDS_NO_IE_SILENT_SELECT);
		cmenu.InsertMenu(-1, MF_BYPOSITION | MF_STRING | MF_ENABLED,
							 IDS_SILENT_SELECT, 
							 cstr.GetBuffer(64));
		cstr.ReleaseBuffer();
	}
	else
	{
		// IE does support -- use check to indicate if it's currently enabled
		cstr.LoadString(IDS_HAVE_SILENT_SELECT);
		bChecked = (bSilentSelect == TRUE) ? MF_CHECKED : MF_UNCHECKED;
		cmenu.InsertMenu(-1, MF_BYPOSITION | MF_STRING | MF_ENABLED | bChecked,
							 IDS_SILENT_SELECT, 
							 cstr.GetBuffer(64));
		cstr.ReleaseBuffer();
	}

	// Default to "Exit App"
	::SetMenuDefaultItem(cmenu.m_hMenu, 0, TRUE);

	GetCursorPos(&mouse);
	this->SetForegroundWindow();
	nMenuItem = cmenu.TrackPopupMenu(TPM_RETURNCMD | TPM_RIGHTALIGN | TPM_RIGHTBUTTON,
					mouse.x, mouse.y, this);

	cmenu.DestroyMenu();
	return nMenuItem;
}


// CMainFrame::OnSysTrayMessage - Respond to events from our system tray icon.
//

LONG CMainFrame::OnSysTrayMessage(
	WPARAM			uID, 
	LPARAM			lEvent
) 
{
	DWORD			nMenuItem	= -1;
	CTimeSpan		timeLeft	= 0;


	if (uID != IDI_UNAUTH) {
		return(0);
	}
	// You can select which way the Shell should behave by calling Shell_NotifyIcon with dwMessage set to NIM_SETVERSION. 
	// Set the uVersion member of the NOTIFYICONDATA structure to indicate whether you want version 5.0 or pre-version 5.0 behavior.

	switch (lEvent) {
		case (WM_CONTEXTMENU) :			// 
		case (WM_RBUTTONUP) : {
			// Do SysTray Menu stuff
			switch (this->SysTrayMenu())
			{
				case IDS_EXIT_APP:
					PostQuitMessage(0);
					return(1);
				case IDS_SILENT_SELECT:
					SetSilentSelectFlag((bSilentSelect==FALSE) ? TRUE : FALSE);
					break;
				default:
					break;
			}
		}
		case (WM_LBUTTONDBLCLK) : {
			// FORCE RE-FETCH OF CERT (USEFUL IF CHANGED KERB-IDENTITY PRIOR TO CERT EXPIRE)
			char	**argv = NULL;
			int		argc = 0;

			bPwdPrompt = TRUE;
			if (bkx509busy == FALSE) {
				bkx509busy = TRUE;
			    kx509_main(kx509_argc, kx509_argv);
				bkx509busy= FALSE;
			}
			bPwdPrompt = FALSE;

			return(1);
			break;
		}
		case (WM_MOUSEMOVE) : {
			// Show Current User Identity
			CString		sTimeLeft;
			char		*szTimeLeft = NULL;
			char		*szSubj		= NULL;
			char		tip[128]	= {0};
			char		*krbv		= KX509_CLIENT_KRB;


#ifdef USE_KRB5
#  ifdef USE_MSK5
			sprintf(tip, "%s %s: <Lock-Unlock screen or Double-Click Icon to get Certificate>\n\n", krbv, KX509_CLIENT_VERSION);
#  else // !USE_MSK5
			sprintf(tip, "%s %s: <Double-Click Icon to acquire tickets to get Certificate>\n\n", krbv, KX509_CLIENT_VERSION);
#  endif // !USE_MSK5
#else // !USE_KRB5
			sprintf(tip, "%s %s: <Double-Click Icon to acquire tickets to get Certificate>\n\n", krbv, KX509_CLIENT_VERSION);
#endif // !USE_KRB5

			if (strlen(gszHardErrorMsg))
			{
				sprintf(tip, "%s %s: ", krbv, KX509_CLIENT_VERSION);
				strncat(tip, gszHardErrorMsg, 63);
				strcat(tip, "\n\n");
			}
			else if (szStatusMsg)
			{
				sprintf(tip, "%s %s: ", krbv, KX509_CLIENT_VERSION);
				strncat(tip, szStatusMsg, 63);
				strcat(tip, "\n\n");
			}
			else
			{
				szSubj		= get_cert_subj(szCertRealm);
				if (szSubj)
				{
			log_printf("CMainFrame::OnSysTrayMessage: before get_cert_time_left.\n");
					get_cert_time_left(szCertRealm, &timeLeft);
					sTimeLeft	= timeLeft.Format(" %H hours, %M minutes");
					if (szTimeLeft = (char *)malloc(256))
					{
						if (strlen(szSubj) > 30)
							szSubj = szCertRealm;

						strcpy(szTimeLeft, sTimeLeft.GetBuffer(64));

						if (timeLeft.GetTotalMinutes() < 0)
							sprintf(tip, "%s %s: Cert for %s: EXPIRED\n\n", krbv, KX509_CLIENT_VERSION, szSubj);
						else
							sprintf(tip, "%s %s: Cert for %s: %s\n\n", krbv, KX509_CLIENT_VERSION, szSubj, szTimeLeft);
						free(szTimeLeft);
						szTimeLeft = NULL;
					}
			log_printf("CMainFrame::OnSysTrayMessage: before free.\n");
					free(szSubj);
					szSubj = NULL;
				}
			}
		log_printf("CMainFrame::OnSysTrayMessage: before ChangeSysTrayTip.\n");
			m_trayIcon.ChangeSysTrayTip(tip);

			// No "return(1)"  Let the system finish up for us.
			break;
		}
	}
	return(0);
}


LONG CMainFrame::OnExitApp(WPARAM uID, LPARAM lEvent) 
{
	log_printf("CMainFrame::OnExitApp: SHOULD BE UNUSED -- see CKx509mfcApp::ExistInstance.\n");

	if (pMainFrame)
		delete(pMainFrame);

	// Delete cert if ever acquired one
	if (szCertRealm[0])
		clean_cert_store(szCertRealm);

	// Decrement Windows Socket reference count
	WSACleanup( );

	// Decrement count of running instances
	InterlockedExchangeAdd((PLONG)&cAppInstances, -1);

//	return CWinApp::ExitInstance();
	exit(1);
}


LONG CMainFrame::OnAdjRate(WPARAM uID, LPARAM lEvent) 
{
	if (adjTime.DoModal() == IDOK)
	{
		m_sampleRate = adjTime.m_newRate;
	}

	return(0);
}

void CMainFrame::OnTimer
(
	UINT		nIDEvent
) 
{
	CTimeSpan	timeLeft	= 0;
	LONG		minLeft		= 0;
	LONG		secLeft		= 0;
	CMainFrame	*hWnd		= NULL;
	char		*szSubj		= NULL;

	log_printf("CMainFrame::OnTimer: entered.\n");

//#if 0 ///////////////////////////////////////////////////////
	hWnd		= (CMainFrame *)theApp.m_pMainWnd;
	get_cert_time_left(szCertRealm, &timeLeft);	// returns 0 if no realm or cert
	minLeft		= timeLeft.GetTotalMinutes();


	// Set TrayIcon to reflect status of cert (if any)
	if (minLeft >= CERT_DYING)
		hWnd->m_trayIcon.ChangeSysTrayIcon(IDI_AUTH);
	else 
	{
		if (minLeft < CERT_DYING)
		{
			szSubj		= get_cert_subj(szCertRealm);

			// If null Subject, then no cert exists so change to Un-authenticated Icon
			if (!szSubj)
				hWnd->m_trayIcon.ChangeSysTrayIcon(IDI_UNAUTH);
			else
			{
				// Alternate TrayIcons 'tween DEAD & DYING
				secLeft = (int)timeLeft.GetTotalSeconds();
				if ((secLeft % 2))
					hWnd->m_trayIcon.ChangeSysTrayIcon(IDI_DEAD);
				else
					hWnd->m_trayIcon.ChangeSysTrayIcon(IDI_AUTH);
				free(szSubj);
			}
		}
		else
			hWnd->m_trayIcon.ChangeSysTrayIcon(IDI_DEAD);
		log_printf("CMainFrame::OnTimer: gszHardErrorMsg=%s.\n", gszHardErrorMsg);
		if (bkx509busy == FALSE) 
		{
			bkx509busy = TRUE;
			kx509_main(kx509_argc, kx509_argv);
			bkx509busy = FALSE;
		}
	}
//#endif // 0 //////////////////////////////////////////////////////////////////


	// Do above check every 5 seconds
	(void)SetTimer(ID_SAMPLE_RATE, 5*1000, NULL);

	CFrameWnd::OnTimer(nIDEvent);
}
