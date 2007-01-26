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

/* REALLY, TRULY GROSS HACKS, ALL TO MAKE KX509 WORK ACROSS MULTIPLE OS' */
/*    AS WELL AS VERSIONS PRIOR TO KfW-2.5 -- MOSTLY DUE TO RE-DEFINING */
/*    TO BE TRUE FN CALLS SOME WHICH ACTUALLY WERE MACROS WHICH  ...   */

#ifdef WIN32
#include <windows.h>
#include <NTSecAPI.h>
#include <loadfuncs-lsa.h>
#include <loadfuncs.h>
#include <loadfuncs-krb5.h>

// REALLY GROSS -- CLIPPED FROM K5-INT.H ...

struct _krb5_ccache {
    krb5_magic magic;
    const struct _krb5_cc_ops *ops;
    krb5_pointer data;
};

struct _krb5_cc_ops {
    krb5_magic magic;
    char *prefix;
    const char * (KRB5_CALLCONV *get_name) (krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *resolve) (krb5_context, krb5_ccache *,
					    const char *);
    krb5_error_code (KRB5_CALLCONV *gen_new) (krb5_context, krb5_ccache *);
    krb5_error_code (KRB5_CALLCONV *init) (krb5_context, krb5_ccache,
					    krb5_principal);
    krb5_error_code (KRB5_CALLCONV *destroy) (krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *close) (krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *store) (krb5_context, krb5_ccache,
					    krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *retrieve) (krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds *,
					    krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *get_princ) (krb5_context, krb5_ccache,
					    krb5_principal *);
    krb5_error_code (KRB5_CALLCONV *get_first) (krb5_context, krb5_ccache,
					    krb5_cc_cursor *);
    krb5_error_code (KRB5_CALLCONV *get_next) (krb5_context, krb5_ccache,
					    krb5_cc_cursor *, krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *end_get) (krb5_context, krb5_ccache,
					    krb5_cc_cursor *);
    krb5_error_code (KRB5_CALLCONV *remove_cred) (krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *set_flags) (krb5_context, krb5_ccache,
					    krb5_flags);
};

typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_free_default_realm)
	(krb5_context, const char *);

HINSTANCE hKrb5 = 0;
HINSTANCE hComErr32 = 0;
HINSTANCE hSecur32 = 0;
HINSTANCE hAdvAPI32 = 0;

// krb5 functions
DECL_FUNC_PTR(krb5_build_principal_ext);
DECL_FUNC_PTR(krb5_cc_close);
DECL_FUNC_PTR(krb5_cc_default);
DECL_FUNC_PTR(krb5_cc_get_principal);
DECL_FUNC_PTR(krb5_cc_resolve);
DECL_FUNC_PTR(krb5_cc_retrieve_cred);
DECL_FUNC_PTR(krb5_free_context);
DECL_FUNC_PTR(krb5_free_cred_contents);
/**/DECL_FUNC_PTR(krb5_free_creds);
/**/DECL_FUNC_PTR(krb5_free_default_realm);
/**/DECL_FUNC_PTR(krb5_free_host_realm);
DECL_FUNC_PTR(krb5_free_principal);
DECL_FUNC_PTR(krb5_get_default_realm);
/**/DECL_FUNC_PTR(krb5_get_host_realm);
DECL_FUNC_PTR(krb5_init_context);
DECL_FUNC_PTR(krb5_mk_req);
DECL_FUNC_PTR(krb5_parse_name);

FUNC_INFO k5_fi[];

#define COMERR32_DLL      "comerr32.dll"

typedef char * (KRB5_CALLCONV *FP_error_message)
		(krb5_error_code);

DECL_FUNC_PTR(error_message);

FUNC_INFO ce_fi[] = {
    MAKE_FUNC_INFO(error_message),
    END_FUNC_INFO
};

#ifdef USE_MSK5
TYPEDEF_FUNC(
    NTSTATUS,
    NTAPI,
    LsaDeregisterLogonProcess,
    (HANDLE)
    );

DECL_FUNC_PTR(LsaConnectUntrusted);
DECL_FUNC_PTR(LsaLookupAuthenticationPackage);
DECL_FUNC_PTR(LsaCallAuthenticationPackage);
DECL_FUNC_PTR(LsaFreeReturnBuffer);
DECL_FUNC_PTR(LsaDeregisterLogonProcess);

FUNC_INFO lsa_fi[] = {
    MAKE_FUNC_INFO(LsaConnectUntrusted),
    MAKE_FUNC_INFO(LsaLookupAuthenticationPackage),
    MAKE_FUNC_INFO(LsaCallAuthenticationPackage),
    MAKE_FUNC_INFO(LsaFreeReturnBuffer),
    MAKE_FUNC_INFO(LsaDeregisterLogonProcess),
    END_FUNC_INFO
};

DECL_FUNC_PTR(LsaNtStatusToWinError);

FUNC_INFO advapi_fi[] = {
    MAKE_FUNC_INFO(LsaNtStatusToWinError),
    END_FUNC_INFO
};
#endif // USE_MSK5

int
MyLoadFuncs(
    const char* dll_name, 
    FUNC_INFO fi[], 
    HINSTANCE* ph,  // [out, optional] - DLL handle
    int* pindex,    // [out, optional] - index of last func loaded (-1 if none)
	void **(fe)(),	// [in] - NULL unless there are exceptional Fn's in the fi table handled by fe() rtn
    int cleanup,    // cleanup function pointers and unload on error
    int go_on,      // continue loading even if some functions cannot be loaded
    int silent      // do not pop-up a system dialog if DLL cannot be loaded
    );

void **ExceptionalFuncs(
	char		*fn
	)
{
	void	**fp = NULL;

	if (!strcmp(fn, "krb5_cc_get_principal"))
		fp = (void **)1;
	else if (!strcmp(fn, "krb5_cc_retrieve_cred"))
		fp = (void **)1;
	else if (!strcmp(fn, "krb5_cc_close"))
		fp = (void **)1;

	return fp;
}

BOOL WINAPI
Load_DLLs(
    )
{
    return (MyLoadFuncs(KRB5_DLL, k5_fi, &hKrb5, 0, ExceptionalFuncs, 1, 0, 0) 
			&& MyLoadFuncs(COMERR32_DLL, ce_fi, &hComErr32, 0, NULL, 1, 1, 1)
#ifdef USE_MSK5
			&& MyLoadFuncs(SECUR32_DLL, lsa_fi, &hSecur32, 0, NULL, 1, 1, 1)
			&& MyLoadFuncs(ADVAPI32_DLL, advapi_fi, &hAdvAPI32, 0, NULL, 1, 1, 1)
#endif // USE_MSK5
			);
}

        
BOOL WINAPI
Unload_DLLs(
    )
{
    if (hKrb5)
        FreeLibrary(hKrb5);
    if (hSecur32)
        FreeLibrary(hSecur32);
    if (hAdvAPI32)
        FreeLibrary(hSecur32);

    return TRUE;
}





#else /* !WIN32 */






/* Does this help any? */

#include <krb5.h>
#include <com_err.h>

#ifdef HAVE_HEIMDAL
#define KRB5_CALLCONV
#define krb5_magic int
#endif

#if 1
struct _krb5_ccache {
    krb5_magic magic;
    const struct _krb5_cc_ops *ops;
    krb5_pointer data;
};

struct _krb5_cc_ops {
    krb5_magic magic;
    char *prefix;
    const char * (KRB5_CALLCONV *get_name) (krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *resolve) (krb5_context, krb5_ccache *,
					    const char *);
    krb5_error_code (KRB5_CALLCONV *gen_new) (krb5_context, krb5_ccache *);
    krb5_error_code (KRB5_CALLCONV *init) (krb5_context, krb5_ccache,
					    krb5_principal);
    krb5_error_code (KRB5_CALLCONV *destroy) (krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *close) (krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *store) (krb5_context, krb5_ccache,
					    krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *retrieve) (krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds *,
					    krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *get_princ) (krb5_context, krb5_ccache,
					    krb5_principal *);
    krb5_error_code (KRB5_CALLCONV *get_first) (krb5_context, krb5_ccache,
					    krb5_cc_cursor *);
    krb5_error_code (KRB5_CALLCONV *get_next) (krb5_context, krb5_ccache,
					    krb5_cc_cursor *, krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *end_get) (krb5_context, krb5_ccache,
					    krb5_cc_cursor *);
    krb5_error_code (KRB5_CALLCONV *remove_cred) (krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *set_flags) (krb5_context, krb5_ccache,
					    krb5_flags);
};

#endif

typedef struct _FUNC_INFO {
    void** func_ptr_var;
    char* func_name;
} FUNC_INFO;

#define MAKE_FUNC_INFO(x) { (void**) &p##x, #x }
#define END_FUNC_INFO { 0, 0 }

#define DECL_FUNC_PTR(fn)	void *p##fn = (void *)fn

DECL_FUNC_PTR(krb5_build_principal_ext);

/* If the *source* version has a *MACRO* defined, we need to FixUp later */
#ifdef krb5_cc_close
void *pkrb5_cc_close = (void *)1;
#else
DECL_FUNC_PTR(krb5_cc_close);
#endif /* !defined krb_cc_close */

DECL_FUNC_PTR(krb5_cc_default);

/* If the *source* version has a *MACRO* defined, we need to FixUp later */
#ifdef krb5_cc_get_principal
void *pkrb5_cc_get_principal = (void *)1;
#else
DECL_FUNC_PTR(krb5_cc_get_principal);
#endif /* !defined krb5_cc_get_principal */

DECL_FUNC_PTR(krb5_cc_resolve);

/* If the *source* version has a *MACRO* defined, we need to FixUp later */
#ifdef krb5_cc_retrieve_cred
void *pkrb5_cc_retrieve_cred = (void *)1;
#else
DECL_FUNC_PTR(krb5_cc_retrieve_cred);
#endif /* !defined krb5_cc_retrieve_cred */

DECL_FUNC_PTR(krb5_free_context);
DECL_FUNC_PTR(krb5_free_cred_contents);
DECL_FUNC_PTR(krb5_free_creds);
#ifndef HAVE_HEIMDAL
DECL_FUNC_PTR(krb5_free_default_realm);
#endif
DECL_FUNC_PTR(krb5_free_host_realm);
DECL_FUNC_PTR(krb5_free_principal);
DECL_FUNC_PTR(krb5_get_default_realm);
DECL_FUNC_PTR(krb5_get_host_realm);
DECL_FUNC_PTR(krb5_init_context);
DECL_FUNC_PTR(krb5_mk_req);
DECL_FUNC_PTR(krb5_parse_name);
DECL_FUNC_PTR(error_message);
#endif /* !WIN32 */

FUNC_INFO k5_fi[] = {
    MAKE_FUNC_INFO(krb5_build_principal_ext),
    MAKE_FUNC_INFO(krb5_cc_close),
    MAKE_FUNC_INFO(krb5_cc_default),
    MAKE_FUNC_INFO(krb5_cc_get_principal),
    MAKE_FUNC_INFO(krb5_cc_resolve),
    MAKE_FUNC_INFO(krb5_cc_retrieve_cred),
    MAKE_FUNC_INFO(krb5_free_context),
    MAKE_FUNC_INFO(krb5_free_cred_contents),
    MAKE_FUNC_INFO(krb5_free_creds),
//    { (void**)&pkrb5_free_default_realm, "_krb5_free_default_realm@8" },
#ifndef HAVE_HEIMDAL
    MAKE_FUNC_INFO(krb5_free_default_realm),
#endif
    MAKE_FUNC_INFO(krb5_free_host_realm),
    MAKE_FUNC_INFO(krb5_free_principal),
    MAKE_FUNC_INFO(krb5_init_context),
    MAKE_FUNC_INFO(krb5_get_default_realm),
    MAKE_FUNC_INFO(krb5_get_host_realm),
    MAKE_FUNC_INFO(krb5_mk_req),
    MAKE_FUNC_INFO(krb5_parse_name),
    END_FUNC_INFO
};

/* Handle fn's that prior to KfW 2.2 were actually "defined" as macros */
void FixupExceptionalFuncs(
	krb5_ccache	cc
	)
{
	int	n;


	/* Ensure that cc->ops ptrs aren't NULL */
	if ((cc == NULL) || (cc->ops == NULL)
	    || (cc->ops->get_princ == NULL)
	    || (cc->ops->retrieve == NULL)
	    || (cc->ops->close == NULL))
		return;

	/*  For all fn ptr == 1, set fn ptr to corresponding cc->ops val */
	for (n = 0; k5_fi[n].func_ptr_var; n++)
		if (!strcmp(k5_fi[n].func_name, "krb5_cc_get_principal")
		    && (*k5_fi[n].func_ptr_var == (void **)1))
			*(k5_fi[n].func_ptr_var) = (void **)cc->ops->get_princ;
		else if (!strcmp(k5_fi[n].func_name, "krb5_cc_retrieve_cred")
		    && (*k5_fi[n].func_ptr_var == (void **)1))
			*(k5_fi[n].func_ptr_var) = (void **)cc->ops->retrieve;
		else if (!strcmp(k5_fi[n].func_name, "krb5_cc_close")
		    && (*k5_fi[n].func_ptr_var == (void **)1))
			*(k5_fi[n].func_ptr_var) = (void **)cc->ops->close;
}
