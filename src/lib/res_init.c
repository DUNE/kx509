// WIN32 ONLY FILE	--	billdo 2001.0522

/*
 * @doc RESOLVE
 *
 * @module res_init.c |
 *
 * Contains the implementation for res_init, res_getopts, res_setopts 
 * and supplementary internal functions. If you are adding support for a 
 * new TCP/IP stack of resolver configuration information this is where 
 * it will go.
 * @xref <f res_init> <f res_setopts> <f res_getopts> <f WhichOS> <f getRegKey>
 *
 * WSHelper DNS/Hesiod Library for WINSOCK
 *
 */

/*-
 * Copyright (c) 1985, 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)res_init.c  6.15 (Berkeley) 2/24/91";
#endif /* LIBC_SCCS and not lint */

#include <windows.h>
#include <winsock.h>

#define __DECLDLL__H
#undef  EXPORT
#undef  EXPORT32
#define EXPORT
#define EXPORT32

#include <arpa/nameser.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <wownt16.h>
#endif

#include "u-compat.h"


#include <shellapi.h>
#ifndef _WIN32
#include <toolhelp.h>
#endif

#include <mitwhich.h>
                    

// IDS_* defines are STOLEN FROM MIT WSHELP's "resource.h"  (billdo 2001.0522)

#define IDS_DEF_HES_RHS                 1
#define IDS_DEF_HES_LHS                 2
#define IDS_DEF_HES_CONFIG_FILE         3
#define IDS_DEF_RESCONF_PATH            4
#define IDS_DEF_DNS1                    5
#define IDS_DEF_DNS2                    6
#define IDS_DEF_DNS3                    7
#define IDS_TCPIP_PATH_NT               8
#define IDS_TCPIP_PATH_95               9
#define IDS_NT_DOMAIN_KEY               10
#define IDS_NT_NS_KEY                   11
#define IDS_W95_DOMAIN_KEY              12
#define IDS_W95_NS_KEY                  13
#define IDS_TCPIP_PATH_NT_TRANSIENT     14

char debstr[80];

#define index strchr

#ifndef MAKELONG
#define MAKELONG(a, b)      ((LONG)(((WORD)(a)) | ((DWORD)((WORD)(b))) << 16))
#endif

#define TCPIP_PATH "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define HKEY_MIT_PRIVATE HKEY_CLASSES_ROOT
#define WSH_MIT_PRIVATE_DOMAIN_SUBKEY TCPIP_PATH"\\Domain"
#define WSH_MIT_PRIVATE_NAMESERVER_SUBKEY TCPIP_PATH"\\NameServer"

EXPORT32 DWORD EXPORT WhichOS( DWORD *check);

static WORD WhichRegistry();
static int set_nameservers_using_registry( DWORD which_reg );
static int set_searchlist_using_registry( DWORD which_reg );
static int set_nameservers_using_iphlp();
static FILE *find_config_file( LPSTR config_path );
static int const getRegKey(const HKEY key, const char *subkey, const char *value, char *buf);

int WINAPI wsh_getdomainname(char* name, int size);

static HMODULE this_module();

#ifndef _WIN32

#ifndef KEY_QUERY_VALUE
#define KEY_QUERY_VALUE         (0x0001)
#endif

#ifndef KEY_ENUMERATE_SUB_KEYS
#define KEY_ENUMERATE_SUB_KEYS  (0x0008)
#endif

#ifndef HKEY_LOCAL_MACHINE
#define HKEY_LOCAL_MACHINE      ((HKEY) 0x80000002 )
#endif

#ifndef REG_EXPAND_SZ
#define REG_EXPAND_SZ           (2)
#endif

LONG RegOpenKeyEx(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    LONG samDesired,
    PHKEY phkResult
    );

LONG RegQueryValueEx(
    HKEY hKey, 
    LPCSTR lpszValueName, 
    LPDWORD lpdwReserved, 
    LPDWORD lpdwType, 
    LPBYTE lpbData, 
    LPDWORD lpcbData
    );

#endif /* !_WIN32 */


/*
 * Resolver state default settings
 */
// @struct _res | a structure of this type holds the state information for the 
// resolver options
struct state _res = {
    RES_TIMEOUT,                    /* @field retransmition time interval */
    4,                              /* @field number of times to retransmit */
    RES_DEFAULT,                    /* @field options flags */
    1,                              /* @field number of name servers */
};

/*
 * Set up default settings.  If the configuration file exist, the values
 * there will have precedence.  Otherwise, the server address is set to
 * INADDR_ANY and the default domain name comes from the gethostname().
 *
 * The configuration file should only be used if you want to redefine your
 * domain or run without a server on your machine.
 *
 * Return 0 if completes successfully, -1 on error
 */


#ifndef _MSC_VER

#define _upcase(c) (((c) <= 'Z' && (c) >= 'A') ? (c) + 'a' - 'A' : (c))
#define _chricmp(a, b) (_upcase(a) - _upcase(b))

int
#ifdef __cplusplus
inline
#endif
_strnicmp( register const char *a, register const char *b, register size_t n)
{
    register int cmp = 0; /* equal */
    while( n-- && !(cmp = _chricmp(*a, *b)) && (a++, *b++) /* *a == *b anyways */ );
    return cmp;
};

#endif


/*

@func EXPORT32 int EXPORT WINAPI | res_init |

This function reads the resolver configuration files and retrieves 
the default domain name, search order and name server address(es).  If 
no server is given, the local host is tried.  If no domain is given, 
that associated with the local host is used.  It can be overriden with 
the environment variable LOCALDOMAIN.  This function is normally executed 
by the first call to one of the other resolver functions.

@rdesc	The return value is 0 if the operation was successful.  
        Otherwise the value -1 is returned.



*/



EXPORT32 int
#ifdef _WINDLL
EXPORT WINAPI
#endif
res_init()
{
    register char *cp, **pp;
/*  LONG cb;                il 8/17/95 */
#if defined (_WINDLL) || defined (_WIN32)
#if 0
    UINT i, wnServs;
    char wnDomain[MAXDNAME], wnTmp[8];
#endif
    char wnServAddr[16];
#endif
    register int n;
    char buf[BUFSIZ];
    WORD which_reg = 0;
    int nserv = 0;      /* number of nameserver records read from file or registry -- il 8/1/95 */
    int haveenv = 0;	/* have an environment variable for local domain */
    int havedomain = 0; /* 0 or 1 do we have a value for the domain */
    int havesearch = 0; /* have we found components of local domain that might be searched */
    int havens = 0;    /* 0 or 1 do we have name servers ? */
#ifndef _WIN32
    FILE *fp;
    char nettcppath[_MAX_PATH];
#endif
    LONG result1 = -1995;

#define WSH_SPACES " \t,;="

    _res.nsaddr.sin_addr.s_addr = INADDR_ANY;
    _res.nsaddr.sin_family = AF_INET;
    _res.nsaddr.sin_port = htons(NAMESERVER_PORT);
    _res.nscount = 1;

    which_reg = WhichRegistry();

    /* Allow user to override the local domain definition */
    if ((cp = getenv("LOCALDOMAIN")) != NULL) {
        strncpy(_res.defdname, cp, sizeof(_res.defdname));
        haveenv++;
        havedomain++;
    };

    if (!havedomain) {
        if (!wsh_getdomainname(_res.defdname, sizeof(_res.defdname)))
            havedomain++;
    }

    if ( !havens ) {
        /* try to get nameservers from IP Helper API */
        if ( set_nameservers_using_iphlp() ) {
            havens++;
            nserv = _res.nscount;
        }
    }

    if( which_reg ){
        /* try to get nameservers from the registry */ /* il 8/1/95 */
        if( !havens &&
            set_nameservers_using_registry( which_reg ) )
        {
            havens++;
            nserv = _res.nscount;
        }

        if ( set_searchlist_using_registry( which_reg ) )
        {
            havesearch++;
        }
    }

    if( 0 != havedomain && 0 != nserv ){
        // return early, we've done our job
        /* find components of local domain that might be searched */
        if (havesearch == 0) {
            pp = _res.dnsrch;
            *pp++ = _res.defdname;
            for (cp = _res.defdname, n = 0; *cp; cp++)
                if (*cp == '.')
                    n++;
            cp = _res.defdname;
            for (; n >= LOCALDOMAINPARTS && pp < _res.dnsrch + MAXDFLSRCH;
                 n--) {
                cp = index(cp, '.');
                *pp++ = ++cp;
            }
            *pp++ = 0;
        };
        _res.options |= RES_INIT;
        return(0);
    }

#ifndef _WIN32
    // Now comes th ugly work of supporting Win16 or non MS TCP stacks.    
    if( fp = find_config_file( nettcppath ) ){
        char *tp;

        /* try to guess the path */
#define WSH_IS_FIELD(field) (!_strnicmp(buf, field, sizeof(field) - 1) && \
               strchr(WSH_SPACES, buf[sizeof(field) - 1]) && \
               ((cp = buf + sizeof(field) - 1), 1 /* to be optimized out */))
               /* il 8/24/95 -- multi-nameserver fields */

        /* open was sucessfull.  read the config file */
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            /* read default domain name */
            if (WSH_IS_FIELD("domain") ||
                WSH_IS_FIELD("domainname") /* for Core */
                ) {
                if (haveenv)        /* skip if have from environ */
                    continue;
              /* cp = buf + sizeof("domain") - 1; */ /* moved to WSH_IS_FIELD */
                while (strchr( WSH_SPACES"."/* for Tropic */, *cp )) /* ! assumed \0 is impossible */
                    cp++;
                if ((*cp == '\0') || (*cp == '\n'))
                    continue;
                (void)strncpy(_res.defdname, cp, sizeof(_res.defdname) - 1);
                if ((cp = index(_res.defdname, '\n')) != NULL)
                    *cp = '\0';
                havesearch = 0;
                continue;
            }
            /* set search list */
            /* will need to be rewritten like domains if multi-entry search
               filed is present in any TCP/IP stack -- il */
            if (WSH_IS_FIELD("search")) {
                if (haveenv)        /* skip if have from environ */
                    continue;
                /* cp = buf + sizeof("search") - 1; */ /* moved to WSH_IS_FIELD */
                while (strchr( WSH_SPACES"."/* for Tropic */, *cp )) /* ! assumed \0 is impossible */
                    cp++;
                if ((*cp == '\0') || (*cp == '\n'))
                    continue;
                (void)strncpy(_res.defdname, cp, sizeof(_res.defdname) - 1);
                if ((cp = index(_res.defdname, '\n')) != NULL)
                    *cp = '\0';
                /*
                 * Set search list to be blank-separated strings
                 * on rest of line.
                 */
                cp = _res.defdname;
                pp = _res.dnsrch;
                *pp++ = cp;
                for (n = 0; *cp && pp < _res.dnsrch + MAXDNSRCH; cp++) {
                    if (*cp == ' ' || *cp == '\t') {
                        *cp = 0;
                        n = 1;
                    } else if (n) {
                        *pp++ = cp;
                        n = 0;
                    }
                }
                /* null terminate last domain if there are excess */
                while (*cp != '\0' && *cp != ' ' && *cp != '\t')
                    cp++;
                *cp = '\0';
                *pp++ = 0;
                havesearch = 1;
                continue;
            }
            /* read nameservers to query */
            if (nserv < MAXNS &&
                (WSH_IS_FIELD("nameserver") ||
                 WSH_IS_FIELD("dns") ||  /* il 8/24/95 -- for Trumpet */
                 WSH_IS_FIELD("nameservers"))) { /* il 8/24/95 -- for Core */

                /* Some WinSocks don't like \n's in their inet_addr() calls */
                if ((tp = strchr(cp, '\n')) != NULL)
                    *tp= '\0';

                /* break into tokens and fill the nameserver spots */
                /* il 8/24/95 -- multi-dns field for Trumpet */
                for (cp = strtok(cp,WSH_SPACES"="); cp && nserv < MAXNS; cp = strtok(NULL,WSH_SPACES"="))
                    if ((_res.nsaddr_list[nserv].sin_addr.s_addr = inet_addr(cp)) == (unsigned)-1)
                        _res.nsaddr_list[nserv].sin_addr.s_addr = INADDR_ANY;
                    else{
                        _res.nsaddr_list[nserv].sin_family = AF_INET;
                        _res.nsaddr_list[nserv].sin_port = htons(NAMESERVER_PORT);
                        nserv++;
                        /*havens++;*/
                    }
            }
        }
        if (nserv >= 1)
            _res.nscount = nserv;
        (void) fclose(fp);
    }
#endif /* !_WIN32 */
    
    /* no reliable source or local domain or name servers */
    if (_res.defdname[0] == 0 || /*!havens ||*/ !nserv ){

        // We output this to any attached debugger.
        // You can get a free debug message viewer from www.sysinternals.com

        OutputDebugString(
            "wshelper error:\n"
            "\tNo reliable info about the local domain or the "
            "name servers found.\n"
            "\tPerhaps the network is not properly setup "
            "(or down if using DHCP).\n"
            "\tUsing built-in defaults.\n"
            );

        // Let's use those hard coded defaults
        // Note: these must match the DEF file entries

        if(LoadString(this_module(), IDS_DEF_DNS1, 
                      wnServAddr, sizeof(wnServAddr) )){

            if ((_res.nsaddr_list[0].sin_addr.s_addr = inet_addr(wnServAddr)) == (unsigned)-1)
                _res.nsaddr_list[0].sin_addr.s_addr = INADDR_ANY;
            else{
                _res.nsaddr_list[0].sin_family = AF_INET;
                _res.nsaddr_list[0].sin_port = htons(NAMESERVER_PORT);
                nserv++;
                /*havens++;*/
            }
        }
        if(LoadString(this_module(), IDS_DEF_DNS2, 
                      wnServAddr, sizeof(wnServAddr) )){

            if ((_res.nsaddr_list[1].sin_addr.s_addr = inet_addr(wnServAddr)) == (unsigned)-1)
                _res.nsaddr_list[1].sin_addr.s_addr = INADDR_ANY;
            else{
                _res.nsaddr_list[1].sin_family = AF_INET;
                _res.nsaddr_list[1].sin_port = htons(NAMESERVER_PORT);
                nserv++;
                /*havens++;*/
            }

        }
        if(LoadString(this_module(), IDS_DEF_DNS3, 
                      wnServAddr, sizeof(wnServAddr) )){

            if ((_res.nsaddr_list[2].sin_addr.s_addr = inet_addr(wnServAddr)) == (unsigned)-1)
                _res.nsaddr_list[2].sin_addr.s_addr = INADDR_ANY;
            else{
                _res.nsaddr_list[2].sin_family = AF_INET;
                _res.nsaddr_list[2].sin_port = htons(NAMESERVER_PORT);
                nserv++;
                /*havens++;*/
            }
        }
    }

    if (_res.defdname[0] == 0) {
        if (gethostname(buf, sizeof(_res.defdname)) == 0 &&
            (cp = /*index*/ strrchr (buf, '.')))
            (void)strcpy(_res.defdname, cp + 1);
    };
          
    /* find components of local domain that might be searched */
    if (havesearch == 0) {
        pp = _res.dnsrch;
        *pp++ = _res.defdname;
        for (cp = _res.defdname, n = 0; *cp; cp++)
            if (*cp == '.')
                n++;
        cp = _res.defdname;
        for (; n >= LOCALDOMAINPARTS && pp < _res.dnsrch + MAXDFLSRCH;
            n--) {
            cp = index(cp, '.');
            *pp++ = ++cp;
        }
        *pp++ = 0;
    };
    _res.options |= RES_INIT;
    return (0);
}


/* 

  @func EXPORT32 void EXPORT WINAPI | res_setopts |
  
Global information that is used by the resolver routines is kept 
in the variable _res.  Most of the values have reasonable defaults and can be 
ignored. Options are a simple bit mask and are OR'ed in to enable.
Options stored in _res.options are defined in <lt> resolv.h <gt> and are as 
follows.

@parm long | opts | the resolver option flags

  @flag RES_INIT      | True if the initial name server  address and  default
                        domain name are initialized (that is, res_init() has 
                        been called).

  @flag RES_DEBUG     | Print debugging messages.

  @flag RES_AAONLY    | Accept authoritative answers only. res_send() will
                        continue until it finds an authoritative answer or
                        finds an error.  Currently this is not implemented.

  @flag RES_USEVC     | Use TCP connections for queries  instead of UDP.

  @flag RES_PRIMARY   | Query primary server only.

  @flag RES_IGNTC     | Unused currently (ignore truncation errors, that is, do
                        not retry with TCP).

  @flag RES_RECURSE   | Set the recursion desired bit in queries.  This is the
                        default. res_send() does not do iterative queries
                        and expects the name server to handle recursion.

  @flag RES_DEFNAMES  | Append the default domain name to single label queries.
                        This is the default.

  @flag RES_STAYOPEN  | Used with RES_USEVC to keep the TCP connection open
                        between queries.  This is useful only in programs
                        that regularly do many queries.  UDP should be the
                        normal mode used.

  @flag RES_DNSRCH    | Search up local domain tree.

*/

EXPORT32 void
#ifdef _WINDLL
EXPORT WINAPI
#endif
res_setopts(long opts)
/* Set resolver options */
{
    _res.options = opts;
}



/* 

  @func EXPORT32 long EXPORT WINAPI | res_getopts |
  
Global information that is used by the resolver routines is kept 
in the variable _res.  Most of the values have reasonable defaults and can be
ignored. Options are a simple bit mask and are OR'ed in to enable. Options
stored in _res.options are defined in <lt> resolv.h <gt> and are as follows.

@rdesc returns a long which is the resolver option flags

  @flag RES_INIT      | True if the initial name server  address and  default
                        domain name are initialized (that is, res_init() has 
                        been called).

  @flag RES_DEBUG     | Print debugging messages.

  @flag RES_AAONLY    | Accept authoritative answers only. res_send() will
                        continue until it finds an authoritative answer or
                        finds an error.  Currently this is not implemented.

  @flag RES_USEVC     | Use TCP connections for queries  instead of UDP.

  @flag RES_PRIMARY   | Query primary server only.

  @flag RES_IGNTC     | Unused currently (ignore truncation errors, that is, do
                        not retry with TCP).

  @flag RES_RECURSE   | Set the recursion desired bit in queries.  This is the
                        default. res_send() does not do iterative queries
                        and expects the name server to handle recursion.

  @flag RES_DEFNAMES  | Append the default domain name to single label queries.
                        This is the default.

  @flag RES_STAYOPEN  | Used with RES_USEVC to keep the TCP connection open
                        between queries.  This is useful only in programs
                        that regularly do many queries.  UDP should be the
                        normal mode used.

  @flag RES_DNSRCH    | Search up local domain tree.

*/

EXPORT32 long
#ifdef _WINDLL
EXPORT WINAPI
#endif
res_getopts()
/* Get resolver options */
{
    return (_res.options);
}

/* --------------------------------------------------------------------------*/
/* Excerpt from IPTYPES.H */
#define MAX_HOSTNAME_LEN                128 // arb.
#define MAX_DOMAIN_NAME_LEN             128 // arb.
#define MAX_SCOPE_ID_LEN                256 // arb.

//
// IP_ADDRESS_STRING - store an IP address as a dotted decimal string
//

typedef struct {
    char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;

//
// IP_ADDR_STRING - store an IP address with its corresponding subnet mask,
// both as dotted decimal strings
//

typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;

// FIXED_INFO - the set of IP-related information which does not depend on DHCP
//
typedef struct {
    char HostName[MAX_HOSTNAME_LEN + 4] ;
    char DomainName[MAX_DOMAIN_NAME_LEN + 4];
    PIP_ADDR_STRING CurrentDnsServer;
    IP_ADDR_STRING DnsServerList;
    UINT NodeType;
    char ScopeId[MAX_SCOPE_ID_LEN + 4];
    UINT EnableRouting;
    UINT EnableProxy;
    UINT EnableDns;
} FIXED_INFO, *PFIXED_INFO;

/* End of Except from iptypes.h */
/* --------------------------------------------------------------------------*/

static HINSTANCE hIPHLPAPI = NULL;
static DWORD (__stdcall * pGetNetworkParams)
    (PFIXED_INFO pFixedInfo, PULONG pOutBufLen) = NULL;
static PFIXED_INFO ipinfo = NULL;

static int
load_iphelper()
{
    if (ipinfo != NULL)
        return(1);

    if (hIPHLPAPI == NULL)
        return 0;

    (FARPROC) pGetNetworkParams = GetProcAddress(hIPHLPAPI, 
                                                 "GetNetworkParams");
    if (pGetNetworkParams)
    {
        DWORD dwBuf = 0;
        DWORD rc = pGetNetworkParams(ipinfo, &dwBuf);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            ipinfo = (PFIXED_INFO) malloc(dwBuf);
            if ( ipinfo == NULL )
                return(0);
            if (pGetNetworkParams(ipinfo, &dwBuf) == ERROR_SUCCESS)
                return(1);
            free(ipinfo);
            ipinfo = NULL;
        }
    }
    return(0);
}

static int
set_nameservers_using_iphlp()
{
    if ( !load_iphelper() )
        return(0);

    if ( ipinfo->DnsServerList.IpAddress.String[0] ) {
        int nserv = 0;
        PIP_ADDR_STRING AddrList = &(ipinfo->DnsServerList);

        do {
            if ((_res.nsaddr_list[nserv].sin_addr.s_addr = 
                  inet_addr(AddrList->IpAddress.String)) == (unsigned)-1) 
            {
                _res.nsaddr_list[nserv].sin_addr.s_addr = INADDR_ANY;
            } else {
                _res.nsaddr_list[nserv].sin_family = AF_INET;
                _res.nsaddr_list[nserv].sin_port = htons(NAMESERVER_PORT);
                nserv++;
            }

            AddrList = AddrList->Next;
        } while (AddrList && nserv < MAXNS);

        if (nserv >= 1){
            _res.nscount = nserv;
            return( nserv );
        }
    }

    // if we got here we didn't get the nameservers so return 0
    return(0);
}

static
WORD
WhichRegistry(
    )
{
    static WORD result = (WORD)-1;

    if (result != (WORD)-1)
        return result;

#define TCPIP_PARAMS_ALA_WIN95  1
#define TCPIP_PARAMS_ALA_NT4    2
#define TCPIP_PARAMS_ALA_NT5    3

/*
What we really want to figure out is the access method.

- Registry ala Win95
- Registry ala WinNT4
- Registry ala WinNT5

- none of the above...

*/

#ifdef _WIN32
    // This is a 32-bit DLL.
    {
        OSVERSIONINFO osvi = { 0 };
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if (!GetVersionEx(&osvi)) {
            // houston, we have a problem....
            exit(1);
        }

        switch(osvi.dwPlatformId) {
        case VER_PLATFORM_WIN32s:
            return (result = 0);
        case VER_PLATFORM_WIN32_WINDOWS:
            return (result = TCPIP_PARAMS_ALA_WIN95);
        case VER_PLATFORM_WIN32_NT:
            if (osvi.dwMajorVersion > 4)
                return (result =  TCPIP_PARAMS_ALA_NT5);
            else
                return (result = TCPIP_PARAMS_ALA_NT4);
        default:
            return (result = 0);
        }

    }
#else // !_WIN32
    // This is a 16-bit DLL.
    {
        DWORD dwVersion = GetVersion();
        DWORD dwFlags = GetWinFlags();

        if( _res.options & RES_DEBUG ){
            wsprintf( debstr, "dwFlags = %x ", dwFlags );
            OutputDebugString( debstr );
            wsprintf( debstr, "dwVersion = %8lx ", dwVersion );
            OutputDebugString( debstr );
        }

#define __WF_WOW 0x4000

        if (dwFlags & __WF_WOW) {
            // We are some kind of NT
            if (HIBYTE(LOWORD(dwVersion)) == 95)
                // We are beyond NT4
                return (result = TCPIP_PARAMS_ALA_NT5);
            else
                // We are NT4 or lower
                return (result = TCPIP_PARAMS_ALA_NT4);
        } else {
            if (HIBYTE(LOWORD(dwVersion)) == 95)
                return (result = TCPIP_PARAMS_ALA_WIN95);
            else
                return (result = 0);
        }
    }
#endif // !_WIN32
}

 
/*

  @doc MISC
  
  @func EXPORT32 DWORD EXPORT | WhichOS | This function will attempt to 
  determine which Operating System and subsystem is being used by the
  application. It should function under Win16, Windows NT amd Windows
  95 at least.  It does call WSAStartup() and WSACleanup(). This
  function does have side effects on some global variables.  See the
  comments below.
  
  @parm DWORD *| check | a pointer to a DWORD, a value indicating
  which operating system and/or subsystem is being used will be stored
  in this parameter upon return.

  @rdesc a NULL will indicate that we could not determine what OS is
  being used. The high word contains:


  @flag MS_OS_WIN     (1) | The application is running under Windows or WFWG
  @flag	MS_OS_95      (2) | The application is running under Windows 95
  @flag	MS_OS_NT      (3) | The application is running under Windows NT
  @flag	MS_OS_UNKNOWN (0) | It looks like Windows but not any version that 
                            we know of.

  <nl>these are defined in mitwhich.h<nl>

The low word contains one of the following, which is derived from the winsock implementation: <nl>

  @flag MS_NT_32 (1) | The MS 32 bit Winsock stack for NT is being used
  @flag MS_NT_16 (2) | The MS 16 bit Winsock stack under NT is being used
  @flag	MS_95_32 (3) | The MS 32 bit Winsock stack under 95 is being used
  @flag	MS_95_16 (4) | The MS 16 bit Winsock stack under 95 is being used
  @flag	NOVELL_LWP_16       (5)  | The Novell 16 Winsock stack is being used
  @flag UNKNOWN_16_UNDER_32 (-2) | We don't know the stack.
  @flag UNKNOWN_16_UNDER_16 (-3) | We don't know the stack.
  @flag UNKNOWN_32_UNDER_32 (-4) | We don't know the stack.
  @flag UNKNOWN_32_UNDER_16 (-5) | We don't know the stack.
	
*/
EXPORT32
DWORD
EXPORT
WhichOS(
    DWORD *check
    )
{
    WORD wVersionRequested;
    WSADATA wsaData; // should be a global?
    int err;

    int checkStack = 0;
    int checkOS = 0;

    // first get the information from WSAStartup because it may give
    // more consistent information than Microsoft APIs.

    wVersionRequested = 0x0101;                  

    err = WSAStartup( wVersionRequested, &wsaData );

    if( err != 0 ){
        MessageBox( NULL, 
                    "It looks like a useable winsock.dll\n"
                    "could not be located by the wshelp*.dll\n"
                    "Please check your system configuration.",
                    "Problem in wshelper.dll", MB_OK );
        check = 0;
        return(0);
    }                         

    WSACleanup();

    if( _res.options & RES_DEBUG ){
        wsprintf( debstr, wsaData.szDescription );
        OutputDebugString( debstr );
    }

    if( (0 == checkStack) && (0 == stricmp( wsaData.szDescription, NT_32 ))){
        // OK we appear to be running under NT in the 32 bit subsystem
        // so we must be a 32 bit application.
        // This also implies that we can get the TCPIP parameters out
        // of the NT registry.
        checkStack = MS_NT_32;
    }

    if( (0 == checkStack) && (0 == stricmp( wsaData.szDescription, NT_16 ))){
        // this implies we're running under NT in the 16 bit subsystem
        // so we must be a 16 bit application
        // This means we have to go through some strange gyrations to read the
        // TCPIP parameters out of the NT 32 bit registry.
        checkStack = MS_NT_16;
        checkOS = MS_OS_NT;	
    }	

    if( (0 == checkStack) && (0 == stricmp( wsaData.szDescription, W95_32 ))){
    	// get the TCPIP parameters out of the Win95 registry
        checkStack = MS_95_32;
        checkOS = MS_OS_95; // ??
    }

    if( (0 == checkStack) && (0 == stricmp( wsaData.szDescription, W95_16 ))){
        // go through the pain of getting the TCPIP parameters out of the Win95
        // 32 bit registry
        checkStack = MS_95_16;                         
        checkOS = MS_OS_95;
    }

    if( (0 == checkStack) && (0 == stricmp( wsaData.szDescription, LWP_16 ))){
        // get the information out of the %NDIR%\TCP\RESOLV.CFG file
        checkStack = NOVELL_LWP_16;
        checkOS = MS_OS_WIN;
    }

    if( 0 == checkStack ){
        // at this time we don't easily know how to support this stack
        checkStack = STACK_UNKNOWN;
    }

#if !defined(_WIN32)
    // Note, if this is the 32 bit DLL we can't use the following
    // functions to determine the OS because they are
    // obsolete. However, we should be able to use them in the 16 bit
    // DLL.
    { 
        DWORD dwVersion = 0;
        DWORD dwFlags = 0;

        dwFlags = GetWinFlags();
        if( _res.options & RES_DEBUG ){
            wsprintf( debstr, "dwFlags = %x ", dwFlags );
            OutputDebugString( debstr );
        }	

        dwVersion = GetVersion();

        if( _res.options & RES_DEBUG ){
            wsprintf( debstr, "dwVersion = %8lx ", dwVersion );
            OutputDebugString( debstr );
        }	
		
        if( 95 == (DWORD)(HIBYTE(LOWORD(dwVersion))) ){
            // OK, we're a 16 bit app running on 95?
            checkOS = MS_OS_95;
        }

        if( dwFlags & 0x4000 ){
            // This means that this is a 16 bit application running
            // under WOW layer on NT.

            // So, we're going to get the TCPIP parameters out of the
            // 32 bit registry, but we don't know which set of
            // registry entries yet.
            
            // Since we see these version numbers and we're under WOW
            // we must be under NT 4.0 but we don't necessarily know
            // the stack
            checkOS = MS_OS_NT;
        }    
	 	 	    
	 	 	                                                     
        if( checkOS == 0 ){	 	
            // We are a 16 bit application running on a 16 bit operating system
            checkOS = MS_OS_WIN; // assumption, but we're not under 95 and not under NT, it looks like
            if( checkStack == STACK_UNKNOWN ){
                checkStack = UNKNOWN_16_UNDER_16;
            }
        }    
    }	
#endif // !_WIN32

#if defined(_WIN32)
    // This must be a 32 bit application so we are either under NT,
    // Win95, or WIN32s
    {
        OSVERSIONINFO osvi;

        memset( &osvi, 0, sizeof(OSVERSIONINFO));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx( &osvi );

        if( osvi.dwPlatformId == VER_PLATFORM_WIN32s ){
            if( checkStack == STACK_UNKNOWN ){
                checkStack = UNKNOWN_16_UNDER_16;
            }
            checkOS = MS_OS_WIN;
            wsprintf( debstr, "Microsoft Win32s %d.%d (Build %d)\n",
                      osvi.dwMajorVersion,
                      osvi.dwMinorVersion,
                      osvi.dwBuildNumber & 0xFFFF );
        }             

        if( osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS ){
            if( checkStack == STACK_UNKNOWN ){
                checkStack = UNKNOWN_32_UNDER_32;
            }
            checkOS = MS_OS_95;
            wsprintf( debstr, "Microsoft Windows 95 %d.%d (Build %d)\n",
                      osvi.dwMajorVersion,
                      osvi.dwMinorVersion,
                      osvi.dwBuildNumber & 0xFFFF );
        }

        if( osvi.dwPlatformId == VER_PLATFORM_WIN32_NT ){
            if( checkStack == STACK_UNKNOWN ){
                checkStack = UNKNOWN_32_UNDER_32;
            }
            checkOS = MS_OS_NT;
            wsprintf( debstr, "Microsoft Windows NT %d.%d (Build %d)\n",
                      osvi.dwMajorVersion,
                      osvi.dwMinorVersion,
                      osvi.dwBuildNumber & 0xFFFF );
        }

        if( _res.options & RES_DEBUG ){
            OutputDebugString( debstr );
        }	
    }

#endif // _WIN32

    // At this point we should know the OS.
    // We should also know the subsystem but not always the stack.

    *check = MAKELONG(checkOS, checkStack);
    return( *check );
}


static
BOOL
get_nt5_adapter_param(
    char* param,
    WORD skip,
    char* buf
    )
{
    static char linkage[BUFSIZ];
    char* p;
    char* q;
    HKEY hAdapters;

    char* DEVICE_STR = "\\Device\\";
    int DEVICE_LEN = strlen(DEVICE_STR);

#define TCPIP_PATH_ADAPTERS "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"
#define TCPIP_PATH_LINKAGE "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Linkage"

    if (!getRegKey(HKEY_LOCAL_MACHINE, TCPIP_PATH_LINKAGE, "Bind", linkage))
        return FALSE;

    p = linkage;

    RegOpenKeyEx(HKEY_LOCAL_MACHINE, TCPIP_PATH_ADAPTERS, 0, 
                 KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, 
                 &hAdapters);

    while (*p) {
        q = strstr(p, DEVICE_STR);
        if (!q) return FALSE; // assert?
        q += DEVICE_LEN;
        p = q;
        while (*p) p++;
        p++;
        if (getRegKey(hAdapters, q, param, buf)) {
            if (!skip) {
                RegCloseKey(hAdapters);
                return TRUE;
            }
            else
                skip--;
        }
    }
    RegCloseKey(hAdapters);

    // Bottom out by looking at default parameters
    {
        char Tcpip_path[_MAX_PATH];

        if(!LoadString(this_module(), IDS_TCPIP_PATH_NT, 
                       Tcpip_path, sizeof(Tcpip_path)))
            strcpy(Tcpip_path, NT_TCP_PATH);
        return getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, param, buf);
    }
    return FALSE;
}

static
BOOL
_getsearchlist(
    char *searchlist,
    int size,
    DWORD which_reg
    )
{
    char buf[BUFSIZ];
    char Tcpip_path[_MAX_PATH];
    char* param = "SearchList";
    BOOL ok = FALSE;
    char* rbuf = (searchlist && size && (size >= BUFSIZ))?searchlist:buf;

    if (!searchlist || (size <= 0)) return FALSE;

    switch(which_reg) {
    case TCPIP_PARAMS_ALA_NT4:
        if(!LoadString(this_module(), IDS_TCPIP_PATH_NT, 
                       Tcpip_path, sizeof(Tcpip_path)))
            strcpy(Tcpip_path, NT_TCP_PATH);
        ok = getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, param, rbuf);
        break;
    case TCPIP_PARAMS_ALA_WIN95:
        if(!LoadString(this_module(), IDS_TCPIP_PATH_95,
                       Tcpip_path, sizeof(Tcpip_path))){
            strcpy(Tcpip_path, W95_TCP_PATH);
        }
        ok = getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, param, rbuf);
        break;
    case TCPIP_PARAMS_ALA_NT5:
        ok = get_nt5_adapter_param(param, 0, rbuf);
        break;
    }

    if (ok) {
        if (size < (lstrlen(rbuf) + 1))
            return FALSE;
        if (rbuf != searchlist)
            strncpy(searchlist, rbuf, size);
        return TRUE;
    } else {
        return FALSE;
    }    
}

static
int
set_searchlist_using_registry(
    DWORD which_reg
    )
{
    static char buf[BUFSIZ];
    if (!_getsearchlist(buf, sizeof(buf), which_reg))
        return 0;

    if (buf[0]) {
        char *cp, **pp;
        int n;

        _res.dnsrch[0] = buf;
        cp = _res.dnsrch[0];
        pp = _res.dnsrch;
        pp++;
        for (n = 0; *cp && pp < _res.dnsrch + MAXDNSRCH; cp++) {
            if (*cp == ' ' || *cp == '\t' || *cp == ',') {
                *cp = 0;
                n = 1;
            } else if (n) {
                *pp++ = cp;
                n = 0;
            }
        }
        /* null terminate last domain if there are excess */
        while (*cp != '\0' && *cp != ' ' && *cp != '\t')
            cp++;
        *cp = '\0';
        *pp++ = 0;
        return 1;
    }
    return 0;
}

static
BOOL
_getdomainname(
    char* name, 
    int size, 
    WORD which_reg
    )
{
    char buf[BUFSIZ];
    char Tcpip_path[_MAX_PATH];
    char* dhcp_param = "DhcpDomain";
    char* param = "Domain";
    BOOL ok = FALSE;
    char* rbuf = (name && size && (size >= BUFSIZ))?name:buf;

    if (!name || (size <= 0)) return FALSE;

    switch(which_reg) {
    case TCPIP_PARAMS_ALA_NT4:
        if(!LoadString(this_module(), IDS_TCPIP_PATH_NT, 
                       Tcpip_path, sizeof(Tcpip_path)))
            strcpy(Tcpip_path, NT_TCP_PATH);
        ok = getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, dhcp_param, rbuf);
        if (!ok || !rbuf[0])
            ok = getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, param, rbuf);
        break;
    case TCPIP_PARAMS_ALA_WIN95:
        if(!LoadString(this_module(), IDS_TCPIP_PATH_95,
                       Tcpip_path, sizeof(Tcpip_path))){
            strcpy(Tcpip_path, W95_TCP_PATH);
        }
        ok = getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, param, rbuf);
        break;
    case TCPIP_PARAMS_ALA_NT5:
        ok = get_nt5_adapter_param(dhcp_param, 0, rbuf);
        if (!ok || !rbuf[0])
            ok = get_nt5_adapter_param(param, 0, rbuf);
        break;
    }

    if (ok && rbuf[0]) {
        if (size < (lstrlen(rbuf) + 1))
            return FALSE;
        if (rbuf != name)
            strncpy(name, rbuf, size);
        return TRUE;
    } else {
        return FALSE;
    }    
}

/*

  @doc MISC
  
  @func int | wsh_gethostname | Gets the base part of the hostname
  
  @parm char* | name | buffer into which to put name (must be large
                       enough to hold NULL-terminated host name)
  @parm int   | size | buffer size

  @rdesc 0 indicates success.  -1 on error.

*/
int WINAPI
wsh_gethostname(char* name, int size)
{
    if (!name || gethostname(name, size))
        return -1;
    while (*name && (*name != '.')) name++;
    if (*name == '.') *name = 0;
    return 0;
}

/*

  @doc MISC
  
  @func int | wsh_getdomainname | Gets the machine's domain name
  
  @parm char* | name | buffer into which to put domain name (must be large
                       enough to hold NULL-terminated domain name)
  @parm int   | size | buffer size

  @rdesc 0 indicates success.  -1 on error.

*/
int WINAPI
wsh_getdomainname(char* name, int size)
{
    // First, regardless of the operating system type we will use a
    // call to gethostbyname() to determine the domain name.  Only
    // if that fails will we look at the registry.
    struct hostent * host = NULL;
    if (!name) return -1;
    host = gethostbyname(NULL);
    if (host) {
        char * cp;
        cp = index(host->h_name, '.');
        if (!cp)
        {
            /* we have a hostent structure which contains IP addresses */
            /* let use them to determine the domain of the first.      */
            host = gethostbyaddr((char *)host->h_addr, 4, PF_INET);
            if (host)
                cp = index(host->h_name, '.');
        }
        if (cp)
        {
            cp++;
            strncpy(name, cp, size);
            name[size-1] = '\0';
            return(0);
        }
    }

    /* try to get local domain from IP Helper API */ 
    if (load_iphelper() && ipinfo->DomainName[0])
    {
        strncpy(name, ipinfo->DomainName, size);
        return 0;
    }

    /* try to get local domain from the registry */
    if (_getdomainname(name, size, WhichRegistry()))
        return 0;
    else
        return -1;
}

static
int
get_w95_dhcp_nameservers()
{
    unsigned char buf[BUFSIZ];
    unsigned char *cp;
    int nserv = 0;
    BOOL ok = FALSE;

    HKEY hkDHCP;
    HKEY hkDHCPInfo;
    DWORD dwIndex;
    DWORD dwSize;
    DWORD dwType;
    FILETIME filetime;

    if (RegOpenKey(HKEY_LOCAL_MACHINE,
                   "SYSTEM\\CurrentControlSet\\Services\\VxD\\DHCP", 
                   &hkDHCP) == ERROR_SUCCESS) {
        dwIndex = 0;
        dwSize = BUFSIZ;
        while ( nserv < MAXNS && 
                RegEnumKeyEx(hkDHCP, dwIndex, buf, &dwSize, NULL, NULL, NULL, &filetime)
                == ERROR_SUCCESS ) {
            if ( RegOpenKey(hkDHCP, buf, &hkDHCPInfo) == ERROR_SUCCESS ) {
                dwSize = BUFSIZ;
                if ( RegQueryValueEx( hkDHCPInfo, "OptionInfo", NULL, &dwType,
                                      buf, &dwSize) == ERROR_SUCCESS ) {
                    // the OptionInfo data field is a tagged set of length specified fields
                    // 03 - Route
                    // 06 - List of Name Servers (4bytes per IP address)
                    // 0F - Domain Name
                    // 2C - IP Address of WINS
                    // FF - end of list
                    for (cp = buf ; *cp != 0xFF ; ) {
                        switch ( *cp++ ) {
                        case 0x06: {    /* List of Name Servers */
                            int n = *cp++ / 4 ;
                            for ( ; n > 0 ; n-- ) {
                                if ( nserv < MAXNS ) {
                                    char ipaddr[16];
                                    sprintf(ipaddr,"%d.%d.%d.%d",
                                             cp[0],cp[1],cp[2],cp[3]);
                                    if ((_res.nsaddr_list[nserv].sin_addr.s_addr = 
                                          inet_addr(ipaddr)) == (unsigned)-1) 
                                    {
                                        _res.nsaddr_list[nserv].sin_addr.s_addr = INADDR_ANY;
                                    } else {
                                        _res.nsaddr_list[nserv].sin_family = AF_INET;
                                        _res.nsaddr_list[nserv].sin_port = htons(NAMESERVER_PORT);
                                        nserv++;
                                    }
                                }
                                cp += 4;
                            }
                            break;
                        }
                        case 0x03:      /* Route */
                        case 0x0F:      /* Domain Name */
                        case 0x2C:      /* IP Address of WINS */
                        default:
                            cp += *cp + 1;
                        }
                    }
                }
                RegCloseKey(hkDHCPInfo);
            }
            dwIndex++;
            dwSize = BUFSIZ;
        }
        RegCloseKey(hkDHCP);
    }

    if (RegOpenKey(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Services\\VxD\\DHCPOptions", 
                    &hkDHCP) == ERROR_SUCCESS) {
        dwIndex = 0;
        dwSize = BUFSIZ;
        while ( nserv < MAXNS && 
                RegEnumKeyEx(hkDHCP, dwIndex, buf, &dwSize, NULL, NULL, NULL, &filetime)
                == ERROR_SUCCESS ) {
            if ( RegOpenKey(hkDHCP, buf, &hkDHCPInfo) == ERROR_SUCCESS ) {
                dwSize = BUFSIZ;
                if ( RegQueryValueEx( hkDHCPInfo, "OptionInfo", NULL, &dwType,
                                      buf, &dwSize) == ERROR_SUCCESS ) {
                    int n;
                    // the OptionInfo data field is an ordered set of length specified fields
                    // Mask
                    // Route
                    // Name Servers
                    // Domain
                    // WINS
                    // Unknown 1
                    // Unknown 2
                    // Unknown 3
                    // Unknown 4
                    // Unknown 5

                    cp = buf;
                    cp += *cp + 1;  // Mask
                    cp += *cp + 1;  // Route

                    n = *cp++ / 4 ; // Domain
                    for ( ;n>0;n-- ) {
                        if ( nserv < MAXNS ) {
                            char ipaddr[16];
                            sprintf(ipaddr,"%d.%d.%d.%d",
                                     cp[0],cp[1],cp[2],cp[3]);
                            if ((_res.nsaddr_list[nserv].sin_addr.s_addr = 
                                  inet_addr(ipaddr)) == (unsigned)-1) 
                            {
                                _res.nsaddr_list[nserv].sin_addr.s_addr = INADDR_ANY;
                            } else {
                                _res.nsaddr_list[nserv].sin_family = AF_INET;
                                _res.nsaddr_list[nserv].sin_port = htons(NAMESERVER_PORT);
                                nserv++;
                            }
                        }
                        cp += 4;
                    }
                    // ignore the rest
                }
                RegCloseKey(hkDHCPInfo);
            }
            dwIndex++;
            dwSize = BUFSIZ;
        }
        RegCloseKey(hkDHCP);
    }

    if (nserv >= 1){
        _res.nscount = nserv;
        return( nserv );
    }

    // if we got here we didn't get the nameservers so return 0
    return(0);
}

static
int
set_nameservers_using_registry(
    DWORD which_reg
    )
{
    char buf[BUFSIZ];
    char *cp;
    int nserv = 0;
    char Tcpip_path[_MAX_PATH];
    char* dhcp_param = "DhcpNameServer";
    char* param = "NameServer";
    BOOL ok = FALSE;

    switch(which_reg) {
    case TCPIP_PARAMS_ALA_NT4:
        /* NT4 stores DNS information in three different places depending
           on where the information came from.  First, in the 
           TCPIP_PATH_NT_TRANSIENT key under subkey "NameServer".  This is
           set by dialup networking when connecting to an ISP.
           Second is TCPIP_PATH_NT under subkey "NameServer" and finally
           under the TCPIP_PATH_NT under subkey "DhcpNameServer".

           We must check all three.
         */
           
        if(!LoadString(this_module(), IDS_TCPIP_PATH_NT_TRANSIENT, 
                       Tcpip_path, sizeof(Tcpip_path)))
            strcpy(Tcpip_path, NT_TCP_PATH_TRANS);
        ok = getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, param, buf);

        if ( !ok || !buf[0] ) {
            if(!LoadString(this_module(), IDS_TCPIP_PATH_NT,
                           Tcpip_path, sizeof(Tcpip_path)))
                strcpy(Tcpip_path, NT_TCP_PATH);
            ok = getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, dhcp_param, buf);

            if ( !ok || !buf[0] ) {
                ok = getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, param, buf);
            }
        }
        break;
    case TCPIP_PARAMS_ALA_WIN95:
        /* W9X stores DNS information in two different places depending
           on where the information came from.

           If the information is placed into the Registry from the
           Network Control Panel DNS page then it goes into the 
           "NameServer" key.

           However, if the information is placed there via the DHCP or
           PPP drivers then it gets placed in binary records in the
           VxD\DHCP and VxD\DHCPOptions keys.  It is not possible for
           us to easily determine which is the active one so we will
           gather as many Name Servers as we can and place them into
           the list.
         */
        if(!LoadString(this_module(), IDS_TCPIP_PATH_95,
                       Tcpip_path, sizeof(Tcpip_path))){
            strcpy(Tcpip_path, W95_TCP_PATH);
        }
        ok = getRegKey(HKEY_LOCAL_MACHINE, Tcpip_path, param, buf);
        if ( !ok || !buf[0] ) {
            return(get_w95_dhcp_nameservers());
        }
        break;
    case TCPIP_PARAMS_ALA_NT5:
        ok = get_nt5_adapter_param(dhcp_param, 0, buf);
        if (!ok || !buf[0])
            ok = get_nt5_adapter_param(param, 0, buf);
        break;
    }

    if (ok) {
        /* break into tokens and fill the nameserver spots */
        for (cp=strtok(buf,WSH_SPACES); cp && nserv < MAXNS; cp=strtok(NULL,WSH_SPACES)){

            if ((_res.nsaddr_list[nserv].sin_addr.s_addr = inet_addr(cp)) == (unsigned)-1){
                _res.nsaddr_list[nserv].sin_addr.s_addr = INADDR_ANY;
	    } else {
                _res.nsaddr_list[nserv].sin_family = AF_INET;
                _res.nsaddr_list[nserv].sin_port = htons(NAMESERVER_PORT);
                nserv++;
            }
        }
 
        if (nserv >= 1){
            _res.nscount = nserv;
            return( nserv );
        }
    }

    // if we got here we didn't get the nameservers so return 0
    return(0);
}


#ifndef _WIN32

static
FILE *
find_config_file(
    LPSTR config_path
    )
{
    char *cp;
    FILE *fp;
    char buf[BUFSIZ];
    char DefConfigFile[_MAX_PATH];

/* il 8/1/95 -- added more search paths */
#define WSH_TRY(env_str, form_str) \
    ((cp = getenv(env_str)) && \
     (fp = fopen((wsprintf(config_path, (form_str), cp), config_path),\
		 "r")))

/* il 8/23/95 -- added path search (for Trumpet) */
#define WSH_SEARCH_TRY(fname) \
    ((OpenFile(fname, (LPOFSTRUCT)buf, OF_EXIST) != HFILE_ERROR) && \
     (fp = fopen(strcpy(config_path, ((LPOFSTRUCT)buf)->szPathName), "r")))
    
    if(!LoadString( this_module(), IDS_DEF_RESCONF_PATH, 
                    DefConfigFile, sizeof(DefConfigFile) )){
        strcpy( DefConfigFile, _PATH_RESCONF);
    }

    /* try to guess the path */
    if (WSH_TRY("ETC", "%s\\resolv.cfg") || /* il 8/1/95 -- added more search paths */
        WSH_TRY("EXCELAN", "%s\\TCP\\resolv.cfg") ||
        WSH_TRY("NDIR", "%s\\ETC\\resolv.cfg") ||
        WSH_TRY("NDIR", "%s\\TCP\\resolv.cfg") ||
        WSH_TRY("PCTCP", "%s") ||
	(fp = fopen(strcpy(config_path, DefConfigFile), "r")) ||
        WSH_SEARCH_TRY("resolv.cfg") || /* il 8/23/95 -- patch for */
        WSH_SEARCH_TRY("TRUMPWSK.INI") || /* il 8/23/95 -- patch for Trumpet */
        WSH_SEARCH_TRY("CORE.INI") || /* il 8/23/95 -- patch for Coreworks */
        WSH_SEARCH_TRY("PCTCP.INI")
        ) {
        return(fp);
    }

    return(0); // we didn't find it
}


// All of this section is thunking support to allow the 16 bit DLL wshelper to
// access the registry when running under NT or WIndows 95.


DWORD (WINAPI *ExpandEnvironmentStringsW)(
    LPSTR lpSrc,  // pointer to string with environment variables 
    LPSTR lpDst,  // pointer to string with expanded environment variables  
    DWORD nSize   // maximum characters in expanded string 
    );

HMODULE hKernel;                        

LONG RegQueryValueEx(
    HKEY hKey,
    LPCSTR lpszValueName,
    LPDWORD lpdwReserved,
    LPDWORD lpdwType,
    LPBYTE lpbData,
    LPDWORD lpcbData
    )
{
    DWORD pFn;
    DWORD dwResult = ERROR_ACCESS_DENIED;
    DWORD hAdvApi32; 

#define CPEX_DEST_STDCALL   0x00000000L

    hAdvApi32 = LoadLibraryEx32W( "ADVAPI32.DLL", NULL, 0);

    if( (DWORD) 0 != hAdvApi32 ){

        // call ANSI version
        pFn = GetProcAddress32W(hAdvApi32, "RegQueryValueExA");
        if((DWORD) 0 != pFn) {
            dwResult=CallProcEx32W(
                CPEX_DEST_STDCALL | 6,  // standard function call with
                                        // six parameters
                0x3e,                   // Identify what parameters
                                        // (addresses) must be translated
                pFn,                    // function pointer
                hKey,	                // open key
                lpszValueName,          // value to query
                lpdwReserved,           // reserved for future use
                lpdwType,               // value type
                lpbData,                // value data
                lpcbData                // value data length
                );
        }
    }
    if (hAdvApi32){
        FreeLibrary32W(hAdvApi32);
    }
    return(dwResult);
}


// This is for the 16 bit build running under a 32 bit OS

LONG RegOpenKeyEx(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    LONG samDesired,
    PHKEY phkResult
){
    DWORD pFn;
    DWORD dwResult = ERROR_ACCESS_DENIED;
    DWORD hAdvApi32;

    hAdvApi32 = LoadLibraryEx32W( "ADVAPI32.DLL", NULL, 0);

    if( (DWORD) 0 != hAdvApi32 ){
        // call ANSI version
        pFn = GetProcAddress32W(hAdvApi32, "RegOpenKeyExA");
        if((DWORD) 0 != pFn) {  
            dwResult=CallProcEx32W(
                CPEX_DEST_STDCALL | 5,	// standard function call with
                                        // five parameters
                0x1e,                   // Identify what parameters
                                        // (addresses) must be translated
                pFn,                    // function pointer
                hKey,                   // handle of open key
                lpSubKey,               // address of name of subkey to open
                ulOptions,              // reserved
                samDesired,             // security access mask
                phkResult               // address of handle of open key
                );
        }
    }
    if (hAdvApi32){
        FreeLibrary32W(hAdvApi32);
    }
    return(dwResult);
}

     
     
DWORD ExpandEnvironmentStrings(
    LPCSTR lpSrc, // pointer to string with environment variables 
    LPSTR lpDst,  // pointer to string with expanded environment variables  
    DWORD nSize   // maximum characters in expanded string 
){
    DWORD pFn;
    DWORD dwResult = ERROR_ACCESS_DENIED;
    DWORD hAdvApi32; 

    hAdvApi32 = LoadLibraryEx32W( "ADVAPI32.DLL", NULL, 0);

    if( (DWORD) 0 != hAdvApi32 ){
        // call ANSI version
        pFn = GetProcAddress32W(hAdvApi32, "RegOpenKeyExA");
        if((DWORD) 0 != pFn) {
            dwResult=CallProcEx32W(
                CPEX_DEST_STDCALL | 3,	// standard function call with
                                        // three parameters
                0x3e,                   // Identify what parameters
                                        // (addresses) must be translated
                pFn,                    // function pointer
                lpSrc,                  // string w/environment variables 
                lpDst,                  // string w/expanded environment variables  
                nSize                   // max characters in expanded string 
                );
        }

    }

    if (hAdvApi32){
        FreeLibrary32W(hAdvApi32);
    }

    return(dwResult);
}

     
     
		            
#endif // !_WIN32		                        



// @func int | getRegKey | This function is only used when the library is 
//                         running under a known 32-bit Microsoft Operating 
//                         system

// @parm const HKEY | key | Specifies a a currently open key or any
//  of the following predefined reserved handle values:
//	HKEY_CLASSES_ROOT
//	KEY_CURRENT_USER
//	HKEY_LOCAL_MACHINE
//	HKEY_USERS
//
// @parm const char * | subkey | Specifies a pointer to a null-terminated
//  string containing the name of the subkey to open. If this parameter is NULL
//  or a pointer to an empty string, the function will open a new handle
//  of the key identified by the key parameter.
//
// @parm const char * | value | Specifiea a pointer to a null-terminated
//  string containing the name of the value to be queried.
//
// @parm char * | buf | Specifies a pointer to a buffer that recieves the
//  key's data. This parameter can be NULL if the data is not required.
//
// @rdesc Returns an int  that can mean:
//
// FALSE - if the subkey cannot be queried or possibly opened.
// TRUE  - if the subkey can be queried but it is not of type: REG_EXPAND_SZ
// If the subkey can be queried, and its type is REG_EXPAND_SZ, and it can
// be expanded the return value is the number of characters stored in the
// buf parameter. If the number of characters is greater than the size of the
// of the destination buffer, the return value should be the size of the
// buffer required to hold the value.

static
int const 
getRegKey(
    const HKEY key, 
    const char *subkey, 
    const char *value, 
    char *buf
    )
{
    HKEY hkTcpipParameters;
    LONG err;
    DWORD type, cb;
    char *env_buf;

//  if (RegOpenKeyEx(key, subkey, 0, KEY_QUERY_VALUE, &hkTcpipParameters) == ERROR_SUCCESS) {

    if (RegOpenKey(key, subkey, &hkTcpipParameters) == ERROR_SUCCESS) {
        cb = BUFSIZ;
        err = RegQueryValueEx(hkTcpipParameters, value, 0, &type, buf, &cb);
        RegCloseKey(hkTcpipParameters);
        if( err == ERROR_SUCCESS ){
            if( type == REG_EXPAND_SZ ){
                if( env_buf = malloc( cb ) ){
                    err = ExpandEnvironmentStrings( strcpy( env_buf, buf ), buf, BUFSIZ );
                    free( env_buf );
                    return err;
                } else {
                    return FALSE;
                }
            }
            return TRUE; // subkey could be queried but it was not of type REG_EXPAND_SZ
        } else {
            return FALSE; // subkey exists but could not be queried
        }
    }
    else
  
// #endif // WIN32

        return FALSE; // subkey could not be opened
}

#ifdef __cplusplus
inline
#endif
int const getNoNameRegKey(const HKEY key, const char *subkey, char *buf)
{
    LONG cb;
    cb = BUFSIZ;
    return RegQueryValue(key, subkey, buf, &cb) == ERROR_SUCCESS;
}

void res_init_startup();
void res_init_cleanup();

static
HMODULE
this_module()
{
    static HMODULE hModWSHelp = 0;
    if (!hModWSHelp)
    {
        // Note: these must match the DEF file entries
#if defined (_WIN32)
        hModWSHelp = GetModuleHandle("WSHELP32");
#else
        hModWSHelp = GetModuleHandle("WSHELPER");
#endif
    }
    return hModWSHelp;
}

static
int
try_registry(
    HKEY  hBaseKey,
    const char * name,
    DWORD * value
    )
{
    HKEY hKey;
    LONG err;
    DWORD size;

    err = RegOpenKeyEx(hBaseKey,
                       "Software\\MIT\\WsHelper",
                       0,
                       KEY_QUERY_VALUE,
                       &hKey);
    if (err)
        return 0;
    size = sizeof(value);
    err = RegQueryValueEx(hKey, name, 0, 0, (u_char *)value, &size);
    RegCloseKey(hKey);
    return !err;
}

void
res_init_startup()
{
    DWORD debug_on = 0;

    hIPHLPAPI = LoadLibrary("IPHLPAPI");

    if (try_registry(HKEY_CURRENT_USER, "DebugOn", &debug_on) ||
        try_registry(HKEY_LOCAL_MACHINE, "DebugOn", &debug_on))
    {
        if (debug_on)
            _res.options |= RES_DEBUG;
    }
}

void
res_init_cleanup()
{
    if (ipinfo)
        free(ipinfo);
    if (hIPHLPAPI)
    {
        FreeLibrary(hIPHLPAPI);
        hIPHLPAPI = 0;
    }
}
