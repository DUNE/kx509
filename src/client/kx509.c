/*
 * Copyright  �  2000,2007
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

#include <stdio.h> 
#include <errno.h> 
#include <string.h> 
#include <fcntl.h> 
#ifndef macintosh
# include <sys/types.h> 
#endif /* !macintosh */

#define VERSION "2.1"

#ifdef WIN32
# define __WINCRYPT_H__       // PREVENT windows.h from including wincrypt.h
                             // since wincrypt.h and openssl namepsaces collide
                             //  ex. X509_NAME is #define'd and typedef'd ...
# include <windows.h> 
# define main	kx509_main	// for WIN32, "main" in kx509mfc.cpp calls this main
#endif /* WIN32 */

#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#ifndef WIN32
# if !defined(linux)
#  define DES_DEFS
# endif /* !linux */
# ifdef macintosh
#  include <KClient.h>
#  include <sioux.h>
# else /* !macintosh */
#  include "des-openssl-hack.h"
# endif /* !macintosh */
#endif /* !WIN32 */

#include "kx509.h"
#include "debug.h" 

/* Include keylength define */
#include "keylength.h"

 
#if SSLEAY_VERSION_NUMBER > 0x0090601eL
#if SSLEAY_VERSION_NUMBER > 0x0090700eL
# define ADD_ALL_ALGORITHMS		OPENSSL_add_all_algorithms_noconf
#else /* ! > 0.9.7 */
# define ADD_ALL_ALGORITHMS		OpenSSL_add_all_algorithms
#endif /* 0.9.7 */
#else
# define ADD_ALL_ALGORITHMS		SSLeay_add_all_algorithms
#endif

/* "#define" macros that were dropped as-of OpenSSL-0.9.6 -- billdo 2000.1205 */

#if SSLEAY_VERSION_NUMBER > 0x0090600e
# define	Malloc		OPENSSL_malloc
# define	Realloc		OPENSSL_realloc
# define	Free(addr)	OPENSSL_free(addr)
#endif

#if defined(KX509_LIB)
int getcert(char *myserver, RSA **rsa, X509 **, char *, int, char *realm, char *tkt_cache_name);
#else
int getcert(char *myserver, RSA **rsa, X509 **, char *, int, char *realm);
#endif

#ifdef WIN32
int store_key(BYTE *b, DWORD cbPk); 
int store_cert(BYTE *cert, DWORD len); 
void clean_cert_store(char *realm);
void display_cert_and_key(); 
int rsa_to_keyblob(int keybits, RSA *key, BYTE	**ppk, DWORD *pcbPk);
void ADD_ALL_ALGORITHMS();
#endif /* WIN32 */
 
#define MAX_UNIQNAME_LEN	8 
#define	BUF_LEN	2048 

#ifdef WIN32
/*# define DEFBITS	1024 */
#endif /* WIN32 */
 
BIO 	*bio_err	= NULL; 
int 	debugPrint 	= 0;		/* Don't print debug by default */
								/* Defined as extern in debug.c */
extern int quietPrint = 0;		/* Don't print at all */
extern char *output_file_flag = NULL;	/* Output file if -o specified */

char 	err_buf[512];

char	szCertRealm[100] = {0};

#ifdef drh
 
/* 
 * load "random" seed based on contents of 
 *	supplied colon-separated <list> of filenames 
 */ 
 
static void gr_load_rand(char *name) 
{ 
	char file[256]; 
	int last=0; 
	char *p; 
 
	for (; name && !last; name=p+1) 
	{ 
		/* move p to "end" of current filename */ 
		for (p=name; ((*p != '\0') && (*p != ':')); p++) 
			; 
 
		/* copy current filename to "file" and null terminate */ 
		strncpy(file, name, p-name); 
		file[p-name] = '\0'; 
 
		/* shouldn't happen, but all-done if null-length filename */ 
		if (!strlen(file)) 
			break; 
 
		/* add contents of <file> to entropy of RAND functions */ 
		(void)RAND_load_file( file, 1024L*1024L ); 
 
		last = (*p == '\0'); 
	} 
 
	return; 
} 
 
#endif /* drh */


#ifdef WIN32
BOOL 	bSilent 	= TRUE;		// Re-purpose -S to mean "remain silent and don't prompt for TGT if none" (for dial-in users)
BOOL	bPwdPrompt	= TRUE;		// True only at startup (iff App name is "kx509) and Dbl-Clk of Tray Icon
BOOL	bSilentSelect = FALSE;	// Dangerous to default TRUE (but can default each run to keeping it as is so that once changed it stays changed)
HINSTANCE myhInstance = 0;
HWND      myhMainWindow = 0;

char	gszHardErrorMsg[200] = {0};
char	*szStatusMsg= NULL;

#define	KX509_REG_KEY	"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3"
#define	KX509_REG_VALUE	"1A04"

static HKEY		kx509_hkey	= NULL;


DWORD GetSilentSelectFlag()
{
	DWORD dwSize;
	DWORD iValue;


	// Attempt to open key that IE uses to determine whether to prompt for cert selection
	//		(if there are zero or none to select from)
	if (RegOpenKeyEx(HKEY_CURRENT_USER, KX509_REG_KEY, 0, 
					  KEY_QUERY_VALUE | KEY_SET_VALUE, &kx509_hkey)
		!= ERROR_SUCCESS)
	{
		bSilentSelect = -1;		// Early versions of Windows/IE didn't know about or support this flag (doesn't exist)
		goto GSSF_EXIT;
	}

	// Query that key for its present value (0=Enabled, 3=Disabled)
	dwSize = sizeof(DWORD);
	if (RegQueryValueEx(kx509_hkey, KX509_REG_VALUE, NULL, NULL, (PBYTE)&iValue, &dwSize)
			!= ERROR_SUCCESS) 
	{
		bSilentSelect = -1;		// this should NOT happen...
		goto GSSF_EXIT;
	}

	switch(iValue)
	{
		case URLPOLICY_ALLOW:
			bSilentSelect = TRUE;
			break;
		case URLPOLICY_DISALLOW:
			bSilentSelect = FALSE;
			break;
		default:
			bSilentSelect = -1;
	}

GSSF_EXIT:
	if (kx509_hkey != NULL) 
	{
		RegCloseKey(kx509_hkey);
		kx509_hkey = NULL;
	}

	return bSilentSelect;
}


DWORD SetSilentSelectFlag
(
	BOOL	bNewValue
)
{
	DWORD	iValue;


	// Attempt to open key that IE uses to determine whether to prompt for cert selection
	//		(if there are zero or one certs to select from)
	if (RegOpenKeyEx(HKEY_CURRENT_USER, KX509_REG_KEY, 0, 
					  KEY_QUERY_VALUE | KEY_SET_VALUE, &kx509_hkey)
		!= ERROR_SUCCESS)
	{
		bSilentSelect = -1;		// Early versions of Windows/IE didn't know about or support this flag (doesn't exist)
		goto SSSF_EXIT;
	}

	// translate bNewValue to actual value to update registry key to
	iValue = bNewValue ? URLPOLICY_ALLOW : URLPOLICY_DISALLOW;

	// Set that key to its new value (0=Enabled, 3=Disabled)
	if (RegSetValueEx(kx509_hkey, KX509_REG_VALUE, 0, REG_DWORD, (PBYTE)&iValue, sizeof(DWORD))
			!= ERROR_SUCCESS) 
	{
		bSilentSelect = -2;		// this should NOT happen...
	}

SSSF_EXIT:
	if (kx509_hkey != NULL) 
	{
		RegCloseKey(kx509_hkey);
		kx509_hkey = NULL;
	}

	return bSilentSelect;
}


int kx509AnnounceResults(
	char	*text
)
{
	HWND	hwndYell;
	HDC		hDC;
	RECT	rect;
	DWORD   lastError;
	int		width;
	int		height;
	int		textwidth;
	int		vertCenter;
	int		horizCenter;


	/* Obtain display width and height, so window can be centered on screen */
	int displayWidth = GetSystemMetrics(SM_CXSCREEN);
	int displayHeight = GetSystemMetrics(SM_CYSCREEN);

	if (bSilent)
		return 0;

	width = 500;
	height = 200;
	textwidth = strlen(text) * 5;
	vertCenter = (height-40)/2;		/* height, minus size of line, div two */
	horizCenter = (width-textwidth)/2;	/* width, minus width of text, div two */

	/* Create a centered window to display the results message */
	hwndYell = CreateWindow("STATIC", "Kx509 Results", WS_POPUP,
				(displayWidth-width)/2, (displayHeight-height)/2,
				width, height,	NULL, NULL, NULL, NULL);
	if (NULL == hwndYell) 
	{
		lastError = GetLastError();
		fprintf(stderr, "CreateWindow failed with 0x%08x -- %s\n", lastError, GetLastErrorText());
		return lastError;
	}

	if (NULL == (hDC = GetDC(hwndYell)))
	{
		lastError = GetLastError();
		fprintf(stderr, "GetDC failed with 0x%08x -- %s\n", lastError, GetLastErrorText());
		return lastError;
	}


	ShowWindow(hwndYell, SW_SHOWNORMAL);
	UpdateWindow(hwndYell);

	/*
	 * Get the client area of our window, draw a couple of
	 * nice border rectangles, and then draw the text
	 */
	if (GetClientRect(hwndYell, &rect))
	{
		RECT clientRect = {rect.left, rect.top, rect.right, rect.bottom};
		RECT textRect = {clientRect.left+horizCenter, clientRect.top+vertCenter,
					 clientRect.right-horizCenter, clientRect.bottom};
		HPEN hPenInner, hPenOuter;
		int outerPenSize = 5;

		FillRect(hDC, &clientRect, (HBRUSH) (COLOR_WINDOW+1));
		
		hPenInner = CreatePen(PS_INSIDEFRAME, outerPenSize, RGB(180, 0, 0));	/* Red */
		hPenOuter = CreatePen(PS_INSIDEFRAME, outerPenSize*2, RGB(0, 0, 180));	/* Blue */

		SelectObject(hDC, hPenOuter);
		Rectangle(hDC, clientRect.left,  clientRect.top,
			       clientRect.right, clientRect.bottom);

		SelectObject(hDC, hPenInner);
		Rectangle(hDC, clientRect.left+outerPenSize, clientRect.top+outerPenSize,
				clientRect.right-outerPenSize, clientRect.bottom-outerPenSize);

		DrawText(hDC, text, -1,  &textRect, DT_WORDBREAK);

		DeleteObject(hPenInner);
		DeleteObject(hPenOuter);
	}

	UpdateWindow(hwndYell);

	ReleaseDC(hwndYell, hDC);

	/* Leave the window up for 3 seconds */
	Sleep(3000);

	DestroyWindow(hwndYell);

	return 0;
}

#endif	/* WIN32 */

RSA *client_genkey(int keybits) 
{ 
	RSA *rsa=NULL; 
#ifdef drh
	char *inrand=NULL; 
	char *outfile=NULL; 
#endif /* drh */
	DWORD f4=RSA_F4; 
    static bOpenSSLinited = 0;

 
#ifdef drh
	/* assign constants to needed filenames ... for now */ 
 
	inrand		= "/var/adm/messages"; 
	outfile		= "/tmp/t.key"; 
#endif /* drh */
 
	/* SET-UP HOUSE */ 
 
	if (!bOpenSSLinited)
	{
		CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON); 
		ADD_ALL_ALGORITHMS(); 
		bOpenSSLinited = 1;
	}
 
	if ((bio_err=BIO_new(BIO_s_file())) != NULL) 
		BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT); 
 
#ifdef drh 
	gr_load_rand(inrand); 
#endif /* drh */
 
	/* GENERATE KEY-PAIR */ 
 
	rsa=RSA_generate_key(keybits,f4,NULL,NULL); 
		 
	return rsa; 
} 
 
#if defined(KX509_LIB)
int do_kx509
#else
int main 
#endif
(
	int			argc, 
	char		**argv
) 
{ 
	RSA			*rsa				= NULL; 
#ifndef macintosh
	BYTE		*pk					= NULL; 
#endif /* macintosh */
	DWORD		cbPk				= 0; 
	DWORD 		certlen				= BUF_LEN; 
	char		realm[50]			= {0};
	char		buffer[BUF_LEN]		= {0};
	BYTE		*certp				= (BYTE *)(&buffer[0]);
	X509		*cert				= NULL; 
#ifdef darwin
	char		privkeybuffer[BUF_LEN];
	char		pubkeybuffer[BUF_LEN];
	BYTE		*privkeyp;
	BYTE		*pubkeyp;
	long		privkeylen			= BUF_LEN;
	long		pubkeylen			= BUF_LEN;
#endif /* darwin */
	char		*err_msg			= NULL; 
	int			err_code			= 0;
#if defined(KX509_LIB)
	char		*tkt_cache_name		= NULL;
        char            *cert_file = NULL;
        char            *key_file = NULL;
        char            *certkey_file = NULL;
#endif
	char		*myserver = NULL;
#ifdef DEBUG
	char		**hvector			= NULL;
	char		**hvp				= NULL;
#endif
	char		*argp				= NULL;
 

#ifdef WIN32
	GetSilentSelectFlag();
#endif /* WIN32 */

#ifdef macintosh
	/* Configure SIOUX */
	SIOUXSettings.asktosaveonclose = false;
# ifdef DEBUG
	SIOUXSettings.columns = 80;
	SIOUXSettings.rows = 40;
# else /* !DEBUG */
	SIOUXSettings.columns = 40;
	SIOUXSettings.rows = 10;
# endif /* DEBUG */
	InstallConsole(0);	/* ugly, evil hack, but necessary */
#endif /* macintosh */

	/* PROCESS COMMAND-LINE OPTIONS */

	err_code = KX509_STATUS_GOOD;
	
	while (--argc > 0) if (*(argp = *++argv) == '-')
	if (argp[1]) while (*++argp) switch(*argp)
	{
#if defined(KX509_LIB)
	case 'c':
		--argc;
		tkt_cache_name = (char *)Malloc(strlen(*++argv)+1);
		strcpy(tkt_cache_name, *argv);
		break;
        case 't':
                --argc;
                cert_file = (char *)malloc(strlen(*++argv)+1);
                strcpy(cert_file, *argv);
                break;
        case 'k':
                --argc;
                key_file = (char *)malloc(strlen(*++argv)+1);
                strcpy(key_file, *argv);
                break;
        case 'b':
                --argc;
                certkey_file = (char *)malloc(strlen(*++argv)+1);
                strcpy(certkey_file, *argv);
                break;
#endif
	case 's':
		--argc;
		myserver = (char *)Malloc(strlen(*++argv)+1);
		strcpy(myserver, *argv);
		break;

	case 'd':
		debugPrint++;
		quietPrint = 0;			/* -d overrides -q */
		break;

	case 'q':
		if (debugPrint)
			{
			quietPrint = 0;		/* -d overrides -q */
			}
		else
			{
			quietPrint++;
			}
		break;

#ifdef WRITE_CERT
	case 'o':
		if (argc < 1) goto Usage;	/* -o must have argument */
		--argc;
		output_file_flag = *++argv;
		break;
#endif	/* WRITE_CERT */

	case '-':
		break;

	case 'h':
		fprintf(stdout,"FNAL kx509 version %s\n", VERSION);
		goto Usage;

	default:
		fprintf(stderr,"Can't understand switch <%s>\n", argp);
	Usage:
		err_msg = "Usage: kx509 [-d (turn on debug output)]\n"
"\t[-s server (specify KCA server name)]\n"
#ifdef WRITE_CERT
"\t[-o file (specify cert output file)]\n"
#endif
"\t[-q (no printout)] [-h (This help screen)]"

#ifdef WIN32
" [-S]"
#endif /* WIN32 */
#ifdef DEBUG
# ifdef USE_KRB5
" [-k caservice]"
# else /* !USE_KRB5 */
" [-k princ.inst]"
# endif /* !USE_KRB5 */
#endif /* DEBUG */
			"\n";
		err_code=KX509_STATUS_CLNT_FIX;
		goto THE_END;
	}
	else {
		fprintf(stderr,"Sorry, don't know what to do with just -\n");
		goto Usage;
	} else {
		fprintf(stderr,"Sorry, don't know what to do with <%s>\n", argp);
		goto Usage;
	}

	/* USE K4 AUTHENT + RSA PUB-KEY TO GET CERT FROM CA SERVER  */

	if (err_code = getcert(myserver,&rsa, &cert, err_buf, sizeof err_buf, realm
#if defined(KX509_LIB)
                                                                          , tkt_cache_name
#endif
																						   ))
	{
		err_msg = err_buf;
		goto THE_END; 
	}
 
	/* GOT INTERNAL CERT, WANT DER-ENCODED (ASN)  */

	certp = (BYTE *)(&buffer[0]);
	certlen = i2d_X509(cert, &certp);			/* NB: updates certp */
	certp = (BYTE *)(&buffer[0]);
 
#ifdef WIN32
	/* SINCE GOT CERT, PUT KEY-PAIR and CERT INTO "MY" KEY-STORE & CERT-STORE  */
 
	if (!rsa_to_keyblob(DEFBITS, rsa, &pk, &cbPk)) 
	{ 
		err_msg="Try running once more.  Response is garbled (hopefully in transit).";
		err_code=KX509_STATUS_CLNT_TMP;
		goto THE_END; 
	} 
 
	if (!store_key(pk, cbPk)) 
	{ 
		err_msg="Very strange.  Unable to store your private key in the Registry.";
		err_code=KX509_STATUS_CLNT_BAD;
		goto THE_END; 
	} 
 
	clean_cert_store(realm);			// garbage collect before adding
	store_cert(certp, certlen);
#else	/* WIN32 */
#ifdef darwin

	/* get the DER-encoded public key */
	if ((pubkeylen = i2d_RSAPublicKey(rsa, NULL)) > BUF_LEN)
	{
		err_msg="Buffer too small for RSAPublicKey";
		err_code=KX509_STATUS_CLNT_BAD;
		goto THE_END;
	}
	pubkeyp = (BYTE *)(&pubkeybuffer[0]);
	pubkeylen = i2d_RSAPublicKey(rsa, &pubkeyp);	/* NB: updates pubkeyp */
	pubkeyp = (BYTE *)(&pubkeybuffer[0]);

	/* get the DER-encoded private key */
	privkeyp = (BYTE *)(&privkeybuffer[0]);
	privkeylen = i2d_RSAPrivateKey(rsa, &privkeyp);	/* NB: updates privkeyp */
	privkeyp = (BYTE *)(&privkeybuffer[0]);

	/* store in Keychain */
/*	err_code = store_in_keychain(privkeyp, privkeylen, pubkeyp,
			pubkeylen, certp, certlen);
*/

	/* what about err_code??? */
	/* for now, do both _keychain and _cc */

#endif /* darwin */
#if defined(USE_KRB5)

	/* Store the key-pair and certificate into the K5 credentials cache as a mock ticket */
	err_code = store_in_cc(rsa, certp, certlen, realm,
#if defined(KX509_LIB)
			X509_get_notBefore(cert), X509_get_notAfter(cert),
			tkt_cache_name, &err_msg);
#else
			X509_get_notBefore(cert), X509_get_notAfter(cert), &err_msg);
#endif

#else	/* USE_KRB5 */

	/* SINCE GOT CERT, MUNGE KEY-PAIR and CERT INTO K4 TKT FILE AS MOCK TICKET */
	err_code = store_tkt(rsa, certp, certlen, realm, &err_msg);

#endif	/* USE_KRB5 */
#endif /* WIN32 */

#if defined(KX509_LIB)
        if(cert_file) {
          BIO *ofile = BIO_new(BIO_s_file());
          if(ofile == NULL) {
            perror("bio_new failed");
            return -1;
          }
          if(BIO_write_filename(ofile, cert_file) <= 0) {
            perror(cert_file);
            return -1;
          }
          if(chmod(cert_file, 0600) != 0) {
            perror(cert_file);
            return -1;
          }
          PEM_write_bio_X509(ofile, cert);
          BIO_free_all(ofile);
        }
                                                                                
        if(key_file) {
          BIO *ofile = BIO_new(BIO_s_file());
          if(ofile == NULL) {
            perror("bio_new failed");
            return -1;
          }
          if(BIO_write_filename(ofile, key_file) <= 0) {
            perror(key_file);
            return -1;
          }
          if(chmod(key_file, 0600) != 0) {
            perror(key_file);
            return -1;
          }
          PEM_write_bio_RSAPrivateKey(ofile, rsa, NULL, NULL, 0, NULL, NULL);
          BIO_free_all(ofile);
        }
       if(certkey_file) {
          BIO *ofile = BIO_new(BIO_s_file());
          if(ofile == NULL) {
            perror("bio_new failed");
            return -1;
          }
          if(BIO_write_filename(ofile, certkey_file) <= 0) {
            perror(certkey_file);
            return -1;
          }
          if(chmod(certkey_file, 0600) != 0) {
            perror(certkey_file);
            return -1;
          }
          PEM_write_bio_X509(ofile, cert);
          PEM_write_bio_RSAPrivateKey(ofile, rsa, NULL, NULL, 0, NULL, NULL);
          BIO_free_all(ofile);
        }
#endif
 
 
THE_END:
	if (cert)
	{
		X509_free(cert);
		cert = NULL;
	}
	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
	if (pk)
	{
		Free(pk);
		pk = NULL;
	}
#ifdef DEBUG
	if (hvector)
	{
		Free(hvector);
		hvector = NULL;
	}
#endif
#if defined(KX509_LIB)
	if (tkt_cache_name)
	{
		Free(tkt_cache_name);
		tkt_cache_name = NULL;
	}
#endif

	if (err_code)
#ifdef WIN32
	{
//		if (err_code != KX509_STATUS_CLNT_TMP)
			if (bSilent)
				szStatusMsg = err_msg;
			else
				MessageBox(0, err_msg, "KX509: Error!", MB_OK|MB_ICONERROR);
	}
#else /* !WIN32 */
		msg_printf("%s\n", err_msg);
#endif /* !WIN32 */
	else
	{
		strcpy(szCertRealm, realm);
#ifdef macintosh
		msg_printf("Success\n");
#endif /* macintosh */
#ifdef WIN32
		szStatusMsg = NULL;
#endif /* WIN32 */
	}

#ifdef WIN32
	// All further attempts/refreshes are to be silent
	bSilent = TRUE;
#endif /* WIN32 */


	return(err_code);
} 
