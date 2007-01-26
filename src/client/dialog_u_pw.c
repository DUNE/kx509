/*
 * Copyright  ©  2007
 * The Regents of the University of Michigan
 * ALL RIGHTS RESERVED
 *
 * permission is granted to use, copy, create derivative works 
 * and redistribute this software and such derivative works 
 * for any purpose, so long as the name of the university of 
 * michigan is not used in any advertising or publicity 
 * pertaining to the use or distribution of this software 
 * without specific, written prior authorization.  if the 
 * above copyright notice or any other identification of the 
 * university of michigan is included in any copy of any 
 * portion of this software, then the disclaimer below must 
 * also be included.
 *
 * this software is provided as is, without representation 
 * from the university of michigan as to its fitness for any 
 * purpose, and without warranty by the university of 
 * michigan of any kind, either express or implied, including 
 * without limitation the implied warranties of 
 * merchantability and fitness for a particular purpose. the 
 * regents of the university of michigan shall not be liable 
 * for any damages, including special, indirect, incidental, or 
 * consequential damages, with respect to any claim arising 
 * out of or in connection with the use of the software, even 
 * if it has been or is hereafter advised of the possibility of 
 * such damages.
 */

/*
 * Self contained routine to open a dialog box and prompt for 
 * user cell and password 
 */
#include <windows.h>
#include <winuser.h>
#include <stdio.h>
#include <malloc.h>
#include "debug.h"
#include "dialog_u_pw.h" 

/* need to check this */
#ifdef UNICODE
#undef UNICODE
#endif

// #define ID_D_U_PW_DIALOG	 2910
#define ID_D_U_PW_USER_P	 2911
#define ID_D_U_PW_USER		 2912
#define ID_D_U_PW_PASSWORD_P 2913
#define ID_D_U_PW_PASSWORD	 2914

/******************************************************************/
static
int CALLBACK
dialog_u_pw_dlgproc(HWND hdlg,
					UINT msg,
					WPARAM wParam,
					LPARAM lParam)
{
	dialog_u_pw_params *dp;
	
	switch(msg) {
		case WM_INITDIALOG:
			dp = (dialog_u_pw_params*)lParam;
			SetWindowLong(hdlg, DWL_USER, lParam);
			SetDlgItemText(hdlg, ID_D_U_PW_USER, dp->user);
			SetDlgItemText(hdlg, ID_D_U_PW_PASSWORD, "");
			return TRUE;
		case WM_COMMAND:
			dp = (dialog_u_pw_params*)GetWindowLong(hdlg, DWL_USER);
			switch(wParam) {
				case IDOK:
					GetDlgItemText(hdlg,ID_D_U_PW_USER, 
										dp->user, dp->userlen);
					GetDlgItemText(hdlg,ID_D_U_PW_PASSWORD, 
										dp->password, dp->passwordlen);
					if (dp->user[0] && dp->password[0]) {
						EndDialog(hdlg, TRUE);
					}else {
						MessageBox(hdlg, "Both fields must be provided",
							dp->caption, MB_OK | MB_ICONERROR);
					}
					break;
				case IDCANCEL:
					memset(dp->password,0,dp->passwordlen);
					EndDialog(hdlg, FALSE);
					break;
			} 
			return TRUE;

		default:
			return FALSE;
	}
}

/******************************************************************/
static
void
dialog_u_pw_additems(WORD** ppw, DWORD dwStyle,
					SHORT x, SHORT y,
					SHORT cx, SHORT cy,
					WORD id,
					WORD class,
					LPTSTR strTitle)
{
	/* must be DWORD aligned */
	DLGITEMTEMPLATE* p = (DLGITEMTEMPLATE*)(((((ULONG)(*ppw))+3)>>2)<<2);
	int mbsize;

log_printf("item      %p\n", p);
	p->style = dwStyle | WS_CHILD | WS_VISIBLE;
	p->dwExtendedStyle = 0;
	p->x    = x;
	p->y    = y;
	p->cx   = cx;
	p->cy   = cy;
	p->id   = id;

	*ppw = (WORD*)(++p);
	if (class) {
		*((*ppw)++) = 0xffff;
		*((*ppw)++) = class;
	} 

	mbsize = MultiByteToWideChar( CP_ACP, 0, strTitle, -1, *ppw, 512);
	*ppw = *ppw +  mbsize;
//	*((*ppw)++) = L'\0';
	(*ppw)++;
}

/******************************************************************/
static
DLGTEMPLATE * dialog_u_pw_build_template(dialog_u_pw_params * dupwp)
{
	DLGTEMPLATE * pDlgTemplate = NULL;
	DLGTEMPLATE * pdt;
	WORD * pw;
	int size;
	int mbsize;
	int items = 6;   // 2 buttons, 2 prompts, 2 editboxs

	size = sizeof(DLGTEMPLATE) + 4*512 + 
			items * (sizeof(DLGITEMTEMPLATE) + 4*512 + 2);

	if ((pDlgTemplate = (DLGTEMPLATE *)malloc(size)) == NULL)
		return NULL;

	memset(pDlgTemplate, 0, size);


	pdt = pDlgTemplate;
log_printf("pdt       %p\n", pdt);
	pdt->style = DS_MODALFRAME  | DS_NOIDLEMSG | DS_SETFOREGROUND |
				 DS_3DLOOK | DS_CENTER | WS_POPUP |
				 WS_VISIBLE | WS_CAPTION | WS_SYSMENU | DS_SETFONT;

	pdt->dwExtendedStyle=0;
	pdt->cdit = items;
	pdt->x = 0;
	pdt->y = 0;
	pdt->cx = 186;
	pdt->cy = 102;
	/* add the four extra items */
	pw = (WORD*)(pdt + 1);
	*pw++ = L'\0';  /* no memory array */
	*pw++ = L'\0';  /* no class array */
	
    mbsize = MultiByteToWideChar( CP_ACP, 0, dupwp->caption, -1, pw, 512); 
	pw = pw + mbsize;
//	*pw++ = L'\0';

	*pw++ = 8;   /*  font size*/
	mbsize = MultiByteToWideChar( CP_ACP, 0,TEXT("Arial"), -1, pw, 512);
	pw = pw + mbsize;
//	*pw++ = L'\0';

log_printf("items     %p\n", pw);

	/* now add the 6 items */

	dialog_u_pw_additems(&pw, ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
							5, 23, 174, 12, 
							ID_D_U_PW_USER, 0x0081, "");

	dialog_u_pw_additems(&pw, ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP 
							   | ES_PASSWORD, 
							5,55, 174, 12,
							ID_D_U_PW_PASSWORD, 0x0081, "");

	dialog_u_pw_additems(&pw, BS_DEFPUSHBUTTON | WS_TABSTOP,
							27, 81, 50, 14, 
							IDOK,  0x0080, "OK");

	dialog_u_pw_additems(&pw, BS_PUSHBUTTON | WS_TABSTOP,
							106, 81, 50, 14,
							IDCANCEL, 0x0080, "CANCEL");

	dialog_u_pw_additems(&pw, 0, 
							5, 12, 174, 10, 
							ID_D_U_PW_USER_P, 0x0082, dupwp->promptuser);
	
	dialog_u_pw_additems(&pw, 0,
							5,44,174,10,
							ID_D_U_PW_PASSWORD_P, 0x0082, dupwp->promptpassword);

log_printf("end       %p\n",pw);
 
  return pDlgTemplate;
}

/*****************************************************************/
     	
int
read_user_password_dialog(HINSTANCE hInstance, 
						  HWND hwndParent,
						  dialog_u_pw_params * dupwp)
{
	
	
	DLGPROC dlgproc = NULL;
	DLGTEMPLATE * dlgtemplate = NULL;

	dlgproc = dialog_u_pw_dlgproc;
	dupwp->rc = -1;

	dlgtemplate = dialog_u_pw_build_template(dupwp);

	log_hexdump("dlgtmplate", dlgtemplate, 1000);

	dupwp->rc = DialogBoxIndirectParam(hInstance, 
								dlgtemplate, 
								hwndParent,
								dlgproc,
								(LPARAM) dupwp);

	free(dlgtemplate);
	return dupwp->rc;
}
