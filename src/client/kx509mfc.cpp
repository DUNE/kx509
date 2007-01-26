// kx509mfc.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "kx509mfc.h"
#include "MainFrm.h"
#include "AdjTime.h"

#ifdef _DEBUG
# undef THIS_FILE
  static char THIS_FILE[] = __FILE__;
#endif /* _DEBUG */

extern "C" void res_init_startup();
extern "C" kx509_main(int argc, char **argv);
extern "C" void clean_cert_store(char *realm);
//extern CTimeSpan get_cert_time_left(char *realm);
extern "C" char szCertRealm[];
extern "C" void log_printf(char *, ...);
#ifdef WIN32
extern	"C" BOOL 	bSilent;  
extern "C" volatile BOOL bkx509busy;
extern "C" char gszHardErrorMsg[];
#endif /* WIN32 */
extern "C" BOOL WINAPI Load_DLLs();
extern "C" char err_buf[];

/////////////////////////////////////////////////////////////////////////////
// CKx509mfcApp

BEGIN_MESSAGE_MAP(CKx509mfcApp, CWinApp)
	//{{AFX_MSG_MAP(CKx509mfcApp)
	   // NOTE - the ClassWizard will add and remove mapping macros here.
	   //    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CKx509mfcApp construction

CKx509mfcApp::CKx509mfcApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CKx509mfcApp object

CKx509mfcApp theApp;
CMainFrame	*pMainFrame	= NULL;
CAdjTime	adjTime;

extern "C" BOOL 	bPwdPrompt;  
extern "C" HINSTANCE myhInstance;
extern "C" HWND      myhMainWindow;

char		*kx509_argv[100]	= {NULL};
int			kx509_argc			= 0;
WSADATA		wsaData;

/////////////////////////////////////////////////////////////////////////////
// Count of Instances already running (to ensure that no more than one is)
#pragma data_seg("Shared")
volatile LONG cAppInstances = 0;
#pragma data_seg()

#pragma comment(linker, "/SECTION:Shared,RWS")


/////////////////////////////////////////////////////////////////////////////
// CKx509mfcApp initialization


BOOL CKx509mfcApp::InitInstance()
{
	char		szCmdLine[1024];	// Chopped copy of command line for argv[] to ref
	LPVOID		lpvData		= NULL;
	char		*p			= NULL;
	DWORD		dwTlsIndex	= 0;
	WORD		wVersionRequested;
	int			err;


	// Make sure WinSock supports version 2.2
	wVersionRequested = MAKEWORD( 2, 2 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 )
		goto EXIT_RTN;
 
	res_init_startup(); /* make sure we load the iphelper DEE */

	/* Confirm that the WinSock DLL supports 2.2.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.2 in addition to 2.2, it will still return */
	/* 2.2 in wVersion since that is the version we      */
	/* requested.                                        */
 
	if ( LOBYTE( wsaData.wVersion ) != 2 ||
			HIBYTE( wsaData.wVersion ) != 2 ) 
	{
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		goto EXIT_RTN;
	}

	// Ensure only one instance keeps running
	InterlockedExchangeAdd((PLONG)&cAppInstances, 1);
	if (cAppInstances > 1)
		goto EXIT_RTN;

	// Ensure that TLS memory is allocated for this thread

	// Allocate a TLS index. 
 
   if ((dwTlsIndex = TlsAlloc()) == -1) 
      goto EXIT_RTN; 

	if ((lpvData = TlsGetValue(dwTlsIndex)) == NULL)
		if ((lpvData = (LPVOID)LocalAlloc(LPTR, 256)) != NULL)
			TlsSetValue(dwTlsIndex, lpvData);

	szCertRealm[0] = '\0';		// Null to start

	AfxEnableControlContainer();

	Enable3dControls();	  	// Call this when using MFC in a shared DLL

	kx509_argv[kx509_argc++] = (char *)m_pszAppName;	// Add app-name to start of argv[]

	strcpy(szCmdLine, m_lpCmdLine);	// Copy command line so OK to chop it up
	strcat(szCmdLine, " ");		// ensure all args are whitespace terminated

	// Find start of arg, add to argv, null-terminate it, repeat ... 
	for (p = &szCmdLine[0]; ; )
	{
		// skim to start of arg (or end-of-string)
		while (*p && strchr(" \t", *p))
			p++;

		// done if end-of-string
		if (!*p)
			break;

		// found an arg, add to argv & bump argc
		kx509_argv[kx509_argc++] = p;

		// skim to end of arg (has to have due to strcat'd blank)
		while (!strchr(" \t", *p))
			p++;

		// terminate this argv[] element
		*p++ = '\0';
	}
	kx509_argv[kx509_argc] = NULL;	// always null-terminate argv[]
	
	// Turn off all message boxes (for both errors and success) -- look at Tray Icon for success/failure
	bSilent = TRUE;

	// Prompt for password if (and only if) the name of this application is kx509 (otherwise silently wait for tickets)
	//   (NOTE: this has *NO* effect for KX509 using Microsoft Cred Cache since there's no way for an already
	//			logged on user to subsequently acquire tickets -- must be done by GINA at logon time)
	//DEE not true, using SSPI AcquireCredHandle AuthIdenity you can.
	//    But we only want to pompt if the user DBL clicks.
	//   (NOTE: For most users, this is balanced by screen locks/unlocks auto-fetching fresh kerberos tickets
	//			which kx509 will quickly notice and (for expired/dying certs) silently fetch a fresh cert)
#ifdef USE_MSK5
	bPwdPrompt = FALSE;
#else
	bPwdPrompt = (strcmp((char *)m_pszAppName, "kx509") == 0);
#endif

	Load_DLLs();
	if (strlen(gszHardErrorMsg))
		strcpy(gszHardErrorMsg, "Need to install MIT's Kerberos V (KfW)");

	pMainFrame = new CMainFrame;
	if (!pMainFrame->LoadFrame(IDR_MAINFRAME)) {
		return (FALSE);
	}
	adjTime.m_newRate = 15*1000;	// sample every 15 seconds

#if 1 //////////////////////// BILLDO ###########################
	// Check if need to adjust Tray Icon every second
	if (!pMainFrame->SetTimer(ID_SAMPLE_RATE, 1000, NULL))
		goto EXIT_RTN;
#else
	if (bkx509busy == FALSE) {
	  bkx509busy = TRUE;
	  kx509_main(kx509_argc, kx509_argv);
	  bkx509busy = FALSE;
	}
#endif // 0 ////////////////// BILLDO ############################

	pMainFrame->SetIcon(theApp.LoadIcon(IDR_MAINFRAME), TRUE);

	// The one and only window has been initialized, so *hide* and update it.
	pMainFrame->ShowWindow(SW_HIDE);
	pMainFrame->UpdateWindow();

	m_pMainWnd = pMainFrame;
	myhMainWindow = pMainFrame->m_hWnd; 
	myhInstance = theApp.m_hInstance;

EXIT_RTN:
	return TRUE;
}


BOOL CKx509mfcApp::OnIdle(LONG lCount)
{
	return CWinApp::OnIdle(lCount);
}

int CKx509mfcApp::ExitInstance() 
{
	if (pMainFrame) {
		 delete pMainFrame;
	}

	// Delete cert if ever acquired one
	if (szCertRealm[0])
		clean_cert_store(szCertRealm);

	// Decrement Windows Socket reference count
	WSACleanup( );

	// Decrement count of running instances
	InterlockedExchangeAdd((PLONG)&cAppInstances, -1);

	return CWinApp::ExitInstance();
}
