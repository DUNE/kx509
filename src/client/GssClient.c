/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef USE_MSK5

#include <stdio.h>

#define UNICODE
#define _UNICODE

#include <windows.h>
#undef FAR

#include <stdio.h>      
#include <stdlib.h>
#include <conio.h>
#include <time.h>
#include <sys/timeb.h>
#include <string.h>
#define SECURITY_WIN32
#include <security.h> 
#include <ntsecapi.h>
#include "gssapi.h"


//#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>

#include "debug.h"
extern CredHandle cred_handle;


static unsigned char	tok_buf[10240];


/*
 * Function: client_establish_context
 *
 * Purpose: establishes a GSS-API context with a specified service and
 * returns the context handle
 *
 * Arguments:
 *
 *      s               (r) an established TCP connection to the service
 *      service_name    (r) the ASCII service name of the service
 *      context         (w) the established GSS-API context
 *      ret_flags       (w) the returned flags from init_sec_context
 *
 * Returns: 0 on success, NTSTATUS if not
 *
 * Effects:
 *
 * service_name is imported as a GSS-API name and a GSS-API context is
 * established with the corresponding service; the service should be
 * listening on the TCP connection s.  The default GSS-API mechanism
 * is used, and mutual authentication and replay detection are
 * requested.
 *
 * If successful, the context handle is returned in context.  If
 * unsuccessful, the GSS-API error messages are displayed on stderr
 * and -1 is returned.
 */
SECURITY_STATUS
client_establish_context(wide_service, tok)
   wchar_t			*wide_service;
   SecBuffer		*tok;
//   char				*service_name;
{
   OM_uint32		deleg_flag = 0;
   OM_uint32		ret_flags;
   CtxtHandle		gss_context;
   SecBuffer		recv_tok, send_tok;
   SecBufferDesc	input_desc, output_desc;
   SECURITY_STATUS		maj_stat;
   TimeStamp		expiry;
   PCtxtHandle		context_handle = NULL;

//   wchar_t			wide_service[100];

   
//   mbstowcs(wide_service, service_name, sizeof(wide_service) / sizeof(wchar_t));

   input_desc.cBuffers = 1;
   input_desc.pBuffers = &recv_tok;
   input_desc.ulVersion = SECBUFFER_VERSION;

   recv_tok.BufferType = SECBUFFER_TOKEN;
   recv_tok.cbBuffer = 0;
   recv_tok.pvBuffer = NULL;

   output_desc.cBuffers = 1;
   output_desc.pBuffers = &send_tok;
   output_desc.ulVersion = SECBUFFER_VERSION;

   send_tok.BufferType = SECBUFFER_TOKEN;
   send_tok.cbBuffer = 10240;
   send_tok.pvBuffer = &tok_buf[0];

   tok->BufferType = SECBUFFER_TOKEN;
   tok->cbBuffer = 0;
   tok->pvBuffer = NULL;


   /*
    * Perform the context-establishement loop.
    */

   gss_context.dwLower = 0;
   gss_context.dwUpper = 0;

   do
   {
      maj_stat =
      InitializeSecurityContext(
                               &cred_handle,
                               context_handle,
                               wide_service,	//service_name,
                               deleg_flag,
                               0,          // reserved
                               SECURITY_NATIVE_DREP,
                               &input_desc,
                               0,          // reserved
                               &gss_context,
                               &output_desc,
                               &ret_flags,
                               &expiry
                               );

      if (recv_tok.pvBuffer)
      {
         free(recv_tok.pvBuffer);
         recv_tok.pvBuffer = NULL;
         recv_tok.cbBuffer = 0;
      }

      context_handle = &gss_context;

      if (maj_stat!=SEC_E_OK && maj_stat!=SEC_I_CONTINUE_NEEDED)
      {
//         display_status("initializing context", maj_stat, 0);
		      return maj_stat;
      }

	  // SEND & RCV TOKEN CODE DELETED

   } while (maj_stat == SEC_I_CONTINUE_NEEDED);

	// RETURN SEND_TOK TO CALLER VIA TOK
   tok->BufferType = send_tok.BufferType;
   tok->cbBuffer = send_tok.cbBuffer;
   tok->pvBuffer = send_tok.pvBuffer;

   return 0;
}



SECURITY_STATUS
MSK5_Generate_Authenticator(wide_service, pubAuthent, pdwAuthentLen)
	wchar_t							*wide_service;
	BYTE							*pubAuthent;
	DWORD							*pdwAuthentLen;
{
	SecBuffer		tok;
	BYTE			*p = NULL;
#define HDR_LEN		17
	SECURITY_STATUS				rc = 0;


	*pdwAuthentLen	= 0;
	*pubAuthent		= 0;

	rc = client_establish_context(wide_service, &tok);
	if (rc != 0)
    	return rc;

	/* The SSPI token has the fixed GSSAPI header + a KRB5 AP-REQ */ 
    p = (BYTE *)tok.pvBuffer;
    *pdwAuthentLen = tok.cbBuffer - HDR_LEN;
    memcpy(pubAuthent, p + HDR_LEN,	*pdwAuthentLen);
    rc = 0;
  log_hexdump("AP-REQ", pubAuthent, *pdwAuthentLen);

	return rc;
}

#endif // USE_MSK5
