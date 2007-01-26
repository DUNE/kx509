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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "loadfuncs.h"
extern char gszHardErrorMsg[];

//
// UnloadFuncs:
//
// This function will reset all the function pointers of a function loaded
// by LaodFuncs and will free the DLL instance provided.
//

void
UnloadFuncs(
    FUNC_INFO fi[], 
    HINSTANCE h
    )
{
    int n;
    if (fi)
        for (n = 0; fi[n].func_ptr_var; n++)
            *(fi[n].func_ptr_var) = 0;
    if (h) FreeLibrary(h);
}


//
// LoadFuncs:
//
// This function try to load the functions for a DLL.  It returns 0 on failure
// and non-zero on success.  The parameters are descibed below.
//

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

    )
{
    HINSTANCE	h;
    int			i, n, last_i;
    int			error			= 0;
    UINT		em;

    if (ph) 
		*ph = 0;
    if (pindex) 
		*pindex = -1;

    for (n = 0; fi[n].func_ptr_var; n++)
		*(fi[n].func_ptr_var) = 0;

    if (silent)
		em = SetErrorMode(SEM_FAILCRITICALERRORS);
    h = LoadLibrary(dll_name);
    if (silent)
        SetErrorMode(em);

    if (!h)
	{
		sprintf(gszHardErrorMsg, "LoadFuncs failed to LoadLibrary %s", dll_name);
        return 0;
	}

    last_i = -1;
    for (i = 0; (go_on || !error) && (i < n); i++)
    {
		void* p = (void*)GetProcAddress(h, fi[i].func_name);

		// Handle "old-style" name from earlier KfW's
		if ((p == NULL) && !strcmp(fi[i].func_name, "krb5_free_default_realm"))
			p = (void*)GetProcAddress(h, "_krb5_free_default_realm@8");

		if (!p && fe)
			p = (*fe)(fi[i].func_name);
		if (!p)
		{
			sprintf(gszHardErrorMsg, "LoadFuncs failed to GetProcAddress for %s", fi[i].func_name);
			error = 1;
		}
		else
		{
			last_i = i;
			*(fi[i].func_ptr_var) = p;
		}
    }
    if (pindex) 
		*pindex = last_i;
    if (error && cleanup && !go_on) 
	{
		for (i = 0; i < n; i++) 
			*(fi[i].func_ptr_var) = 0;
		FreeLibrary(h);
		return 0;
    }
    if (ph) 
		*ph = h;
    if (error) 
		return 0;
    return 1;
}
