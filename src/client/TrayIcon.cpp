// TrayIcon.cpp - Routines to handle a system tray icon.
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "TrayIcon.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

TrayIcon::TrayIcon() {
	ZeroMemory(&m_nid,sizeof(m_nid));
	m_nid.cbSize = sizeof(NOTIFYICONDATA);
}

TrayIcon::~TrayIcon() {	
}

// TrayIcon::AddSysTrayIcon - Associate the icon with a window and put it
//                            in the system tray.
//

BOOL TrayIcon::AddSysTrayIcon(CWnd* pcwnd, UINT uID) {
	if (m_nid.uID != 0) {
		return(FALSE);
	}

	m_nid.hWnd   = pcwnd->GetSafeHwnd();
	m_nid.uID    = uID;
	m_nid.hIcon  = AfxGetApp()->LoadIcon(uID);
	m_nid.uFlags = NIF_ICON;

	return(Shell_NotifyIcon(NIM_ADD,&m_nid));
}

// TrayIcon::ChangeSysTrayIcon - Replace the current icon with a new one.
//

BOOL TrayIcon::ChangeSysTrayIcon
(
	UINT	uID
) 
{
	BOOL	bResult		= FALSE;
	HICON	hIcon		= NULL;
	static  UINT prev_uID	= -1;


	if (m_nid.uID == 0) 
	{
		return(FALSE);
	}

	if (prev_uID == uID)
		return(TRUE);
	prev_uID = uID;

	hIcon = m_nid.hIcon;
	m_nid.hIcon  = AfxGetApp()->LoadIcon(uID);
	m_nid.uFlags = NIF_ICON;
		
	bResult = Shell_NotifyIcon(NIM_MODIFY,&m_nid);

	if (hIcon) 
	{
		DestroyIcon(hIcon);
	}

	return(bResult);
}

// TrayIcon::ChangeSysTrayIcon - Change the icon, but also attach tip text to it.
//

BOOL TrayIcon::ChangeSysTrayIcon(UINT uID, PTSTR pszTip) {
	if (!ChangeSysTrayIcon(uID)) 
	{
		return(FALSE);
	}

	return(ChangeSysTrayTip(pszTip));
}

// TrayIcon::ChangeSysTrayTip - Change the icon tip text.
//

BOOL TrayIcon::ChangeSysTrayTip(PTSTR pszTip) {
	BOOL	bChanged	= FALSE;


	if (m_nid.uID == 0) 
		return(FALSE);

	if (pszTip == NULL) 
	{
		if (m_nid.szTip[0] != '\0')
		{
			ZeroMemory(m_nid.szTip,sizeof(m_nid.szTip));
			bChanged = TRUE;
		}
	} 
	else 
	{
		if (strcmp(m_nid.szTip, pszTip))
		{
			_tcsncpy(m_nid.szTip,pszTip,sizeof(m_nid.szTip));
			bChanged = TRUE;
		}
	}

	if (!bChanged)
		return FALSE;

	m_nid.uFlags = NIF_TIP;

	return(Shell_NotifyIcon(NIM_MODIFY,&m_nid));
}

// TrayIcon::SetSysTrayCallback - Give the icon a message ID to flag its messages to
//                                to the owner window.
//

BOOL TrayIcon::SetSysTrayCallback(UINT uCBID) {
	BOOL bResult;

	if (m_nid.uID == 0) {
		return(FALSE);
	}

	m_nid.uCallbackMessage = uCBID;
	m_nid.uFlags = NIF_MESSAGE;

	bResult = Shell_NotifyIcon(NIM_MODIFY,&m_nid);

	m_nid.uCallbackMessage = 0;

	return(bResult);
}

BOOL TrayIcon::DelSysTrayIcon()
{
	BOOL bResult;

	if (m_nid.uID == 0) {
		return(FALSE);
	}

	bResult = Shell_NotifyIcon(NIM_DELETE,&m_nid);
	m_nid.uID = 0;

	return(bResult);
}
