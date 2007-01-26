/*
 * Copyright  ©  2000,2007
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>

#if defined(USE_KRB4)
#ifndef DES_DEFS
# define DES_DEFS 1
#endif /* DES_DEFS */
#include "../lib/des-openssl-hack.h"
#include <krb.h>
extern int krb_ap_req_debug;
#endif	/* USE_KRB4 */

#if defined(USE_KRB5)
#include <krb5.h>
#if defined(HAVE_HEIMDAL)
#define KRB5_PVNO 5
#endif
#else
#define KRB5_PVNO 5
#endif	/* USE_KRB5 */

 /*
  * Stole this from k5-int.h so I can determine
  * if the request is a K4 or K5 request
  */
#define krb5_is_ap_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6e ||\
				    (dat)->data[0] == 0x4e))


#include "kx509_asn.h"
#include "msg.h"
#include "kx509.h"
#include "server.h"


typedef struct  sockaddr_in SOCKADDR;

int	single_process = 1;
char    *pn;			/* program name */

char version_2_0_string[4] = {0,0,2,0};

/* yuck.  DER encoded public keys don't have a keytype. */

sniff_at_key_type(unsigned char *inp, int maxlen)
{
	/* public key.  RSA: sequence bigint(n) smallint(e)
	 * DSA: either sequence bigint(pubkey) bigint(p) bigint(q) bigint(g) (with params)
	 *	or bigint(pubkey)
	 */
#define MAXN 5
	long l[MAXN];
	int t[MAXN];
	int x[MAXN];
	int j[MAXN];
	int i, n;
	unsigned char *p, *endp;
	int length;
	int type;

	p = inp;
	endp = p+maxlen;
	for (n=0;n<MAXN;++n)
	{
	    length = endp-p;
	    if (!length) break;
	    j[n] = ASN1_get_object(&p,&l[n],&t[n],&x[n],length);
	    if (j[n] == 0x80)
	    {
		    break;
	    }
	    if (n)
	    {
		if (t[n] != V_ASN1_INTEGER)
		    break;
		p += l[n];
	    } else if (t[0] == V_ASN1_INTEGER)
	    {
		++n;
		break;
	    }
	}
#if 0
	printf("n=%d\n", n);
	for (i = 0; i < n; ++i)
	printf (" %d: j=%d l=%d t=%d x=%d\n",
		i, j[i], l[i], t[i], x[i]);
#endif
	if (n == 3)
	    type = EVP_PKEY_RSA;
	else
	    type = EVP_PKEY_DSA;
#if 0
	printf (" final type=%d\n", type);
#endif
	return type;
}

int
decode_version_2(struct request *r, KX_MSG *clnt_msg)
{
	unsigned char *p;
	int length;
	int type;

	p = clnt_msg->m_data + 4;
	length = clnt_msg->m_curlen - 4;
	if (!(r->v2.request = d2i_KX509_REQUEST(NULL, &p, length)))
	{
		r->err_msg = "Unable to d2i_KX509_REQUEST";
		elcprintf("%s\n", r->err_msg);
		return r->err_code = KX509_STATUS_SRVR_TMP;
	}
#ifdef KX509_CLIENT_VERSION_IN_REQUEST
	if (r->v2.request->client_version)
		lcprintf("CLIENT version is: <%s>\n",
			 r->v2.request->client_version->data);
	else
		lcprintf("CLIENT did not supply version\n");
#endif

	/*
	 * Determine whether this is a KRB4 or KRB5 request
	 * and set krb_prot_version appropriately.
	 */

	/* Is it a K4 request? */
	if (4 == (*(char *)(r->v2.request->authenticator->data)))
	{
		r->krb_prot_version = 4;
	}
	else
	/* Is it a K5 rd_req ? */
	if (krb5_is_ap_req(r->v2.request->authenticator))
	{
		r->krb_prot_version = KRB5_PVNO;
	}
	else
	{
		elcprintf("Client is using Kerberos version %d?\n",
			r->krb_prot_version);
		r->err_msg = "Ill-formed request?  Cannot determine your Kerberos version, or your Kerberos version is not supported by the server.";
		return r->err_code = KX509_STATUS_SRVR_TMP;
	}

#if defined(USE_KRB5)
	if (KRB5_PVNO == r->krb_prot_version)
	{
		r->k5_authent.length = r->v2.request->authenticator->length;
		if (!(r->k5_authent.data = malloc(r->k5_authent.length)))
		{
			r->err_msg = "Unable to allocate memory for request authenticator";
			return r->err_code  = KX509_STATUS_SRVR_TMP;
		}
		memcpy(r->k5_authent.data, r->v2.request->authenticator->data,
			r->k5_authent.length);
	}
#if defined(USE_KRB4)
	else
#endif
#endif	/* USE_KRB5 */
#if defined(USE_KRB4)
	if (4 == r->krb_prot_version)
	{
		r->authent.length = r->v2.request->authenticator->length;
		if (r->authent.length > sizeof r->authent.dat)
		{
			r->err_msg = "Oversize ap_req";;
			return r->err_code = KX509_STATUS_SRVR_TMP;
		}
		memcpy(r->authent.dat, r->v2.request->authenticator->data,
			r->authent.length);
	}
#endif	/* USE_KRB4 */
	else
	{
		elcprintf("The server does not support Kerberos version %d\n",
			r->krb_prot_version);
		r->err_msg = "The server does not support your Kerberos version";
		return r->err_code = KX509_STATUS_SRVR_TMP;
	}

	type = sniff_at_key_type (r->v2.request->pkey->data,
		r->v2.request->pkey->length);
	p = r->v2.request->pkey->data;
	length = r->v2.request->pkey->length;
	if (!(r->pubkey = d2i_PublicKey(type,NULL,&p,length)))
	{
		r->err_msg =
		((type == EVP_PKEY_RSA) ?
		    "Unable to d2i_PublicKey RSAkey" :
		    "Unable to d2i_PublicKey DSAkey");
		elcprintf("%s\n", r->err_msg);
#if DEBUG
		printf ("decoded %d bytes\n", p-r->v2.request->pkey->data);
		bin_dump(r->v2.request->pkey->data, length);
		PEM_write(stdout, "RSA PRIVATE KEY", "", r->v2.request->pkey->data, length);
#endif
		return r->err_code = KX509_STATUS_SRVR_TMP;
	}
	return 0;
}

int
validate_version_2(struct request *r, KX_MSG *clnt_msg)
{
	ASN1_OCTET_STRING *hash;
	int result = 0;

	hash = ASN1_OCTET_STRING_new();
#if defined(USE_KRB5)
	if (KRB5_PVNO == r->krb_prot_version)
	{
	    KX509_REQUEST_compute_checksum(clnt_msg->m_data,
			r->v2.request,
			hash,
#if defined(HAVE_HEIMDAL)
			(char *)r->k5_ticket->ticket.key.keyvalue.data,
			r->k5_ticket->ticket.key.keyvalue.length);
#else
			(char *)r->k5_ticket->enc_part2->session->contents,
			r->k5_ticket->enc_part2->session->length);
#endif
	}
#if defined(USE_KRB4)
	else
#endif
#endif	/* USE_KRB5 */
#if defined(USE_KRB4)
	if (4 == r->krb_prot_version)
	{
	    KX509_REQUEST_compute_checksum(clnt_msg->m_data,
			r->v2.request,
			hash,
			(char *)r->ad.session,
			sizeof(C_Block));
	}
#endif
	if (hash->length != r->v2.request->hash->length ||
		memcmp(hash->data, r->v2.request->hash->data, hash->length))
	{
	    r->err_msg = "Integrity problem; hash does not match";
	    elcprintf("%s\n", r->err_msg);
	    result = r->err_code = KX509_STATUS_CLNT_TMP;
	}
	ASN1_OCTET_STRING_free(hash);
	return result;
}

int
encode_version_2(struct request *r, KX_MSG *srvr_msg)
{
	unsigned char *p;
	int length;
	int cert_len;
	unsigned char *cert_ptr;
	KX509_RESPONSE *response;

	cert_len = i2d_X509(r->cert, 0);
	/*
	 * Fix problem on AIX where a failure because of
	 * expired tickets or whatever, fails to return a
	 * packet back to the user because a malloc for
	 * length of zero does not return a pointer.
	 * KWC 06/21/2000
	 */
	if (cert_len)
	{
	    if (!(cert_ptr = Malloc(cert_len)))
	    {
		elcprintf("Cannot allocate v2 cert storage\n");
		return 1;
	    }
	    p = cert_ptr;
	    i2d_X509(r->cert, &p);
	}

	response = KX509_RESPONSE_new();
	if ((response->status = r->err_code) || !r->ad_is_valid)
	{
	    if (!response->status) response->status = KX509_STATUS_SRVR_BAD;
	    response->error_message = ASN1_VISIBLESTRING_new();
	    if (!r->err_msg) r->err_msg = "Unknown server problem";
	    fill_in_octet_string(response->error_message,
		r->err_msg,
		strlen(r->err_msg));
	} else {
	    response->certificate = ASN1_OCTET_STRING_new();
	    if (response->certificate->data)
		Free(response->certificate->data);
	    response->certificate->data = cert_ptr;
	    response->certificate->length = cert_len;
	}

	if (r->ad_is_valid)
	{
	    response->hash = ASN1_OCTET_STRING_new();
#if defined(USE_KRB5)
	    if (KRB5_PVNO == r->krb_prot_version)
	    {
		KX509_RESPONSE_compute_checksum((BYTE *)version_2_0_string,
			response, response->hash,
#if defined(HAVE_HEIMDAL)
			(char *)r->k5_ticket->ticket.key.keyvalue.data,
			r->k5_ticket->ticket.key.keyvalue.length);
#else
			(char *)r->k5_ticket->enc_part2->session->contents,
			r->k5_ticket->enc_part2->session->length);
#endif
	    }
#if defined(USE_KRB4)
	    else
#endif
#endif	/* USE_KRB5 */
#if defined(USE_KRB4)
	    if (4 == r->krb_prot_version)
	    {
	    KX509_RESPONSE_compute_checksum((BYTE *)version_2_0_string,
		response, response->hash,
		(char *)r->ad.session, sizeof(C_Block));
	    }
#endif	/* USE_KRB4 */
	}
	length = i2d_KX509_RESPONSE(response, 0);
	if (length > srvr_msg->m_maxlen-4)
	{
	    elcprintf("Oversize v2 result packet: cannot send\n");
	    return 1;
	}
	memcpy(srvr_msg->m_data, version_2_0_string, 4);
	p = srvr_msg->m_data+4;
	i2d_KX509_RESPONSE(response, &p);
	srvr_msg->m_curlen = p - srvr_msg->m_data;
	KX509_RESPONSE_free(response);
	return 0;
}

#if defined(USE_KRB5)

/*
 * Verify the client's authentication request and determine
 * the client's name if the authentication is successful.
 */
int authenticate_client_via_k5(struct request *r, char *realm)
{
	krb5_error_code	k5_rc;
	krb5_flags	k5_req_flags;

	if (k5_rc = krb5_auth_con_init(k5_context, &r->k5_auth_context))
	{
		r->err_msg = "Try re-authenticating.  KCA internal error initializing auth context";
		r->err_code = KX509_STATUS_CLNT_TMP;
		return -1;
	}

	if (k5_rc = krb5_rd_req(k5_context, &r->k5_auth_context, &r->k5_authent, NULL,
		k5_keytab, &k5_req_flags, &r->k5_ticket))
	{
		lcprintf("Received request %s\n", r->caller_name);
		elcprintf("krb5_rd_req failed using keytab '%s' with error code %d\n",
		    keytab_string, k5_rc);
		r->err_msg = "Try re-authenticating.  Your K5 credentials may be too old or for the wrong REALM";
		r->err_code = KX509_STATUS_CLNT_TMP;
		return -1;
	}
	if (k5_rc = krb5_unparse_name(k5_context, 
#if defined(HAVE_HEIMDAL)
				      r->k5_ticket->client,
#else
				      r->k5_ticket->enc_part2->client,
#endif
				      &r->k5_client_string))
	{
		lcprintf("Received request %s\n", r->caller_name);
		elcprintf("krb5_unparse_name failed with error code %d\n", k5_rc);
		r->err_msg = "Try re-authenticating.  KCA internal error calling krb5_unparse_name";
		r->err_code = KX509_STATUS_CLNT_TMP;
		return -1;
	}

#if defined(HAVE_HEIMDAL)
	strcpy(realm, r->k5_ticket->ticket.crealm);
#else
	strncpy(realm,
		krb5_princ_realm(k5_context, r->k5_ticket->enc_part2->client)->data,
		krb5_princ_realm(k5_context, r->k5_ticket->enc_part2->client)->length);
	realm[krb5_princ_realm(k5_context, r->k5_ticket->enc_part2->client)->length] = '\0';
#endif
	return 0;
}

/*
 * Perform more validation of the client.  Check that
 * their principal name (uniqname) is the correct
 * length.  Also verify that their principal name
 * does not have any instance components.
 */
int validate_client_via_k5(struct request *r)
{
#if defined(HAVE_HEIMDAL)
	int name_len;
#endif
	int component_count;
	
#if defined(HAVE_HEIMDAL)
	component_count = r->k5_ticket->client->name.name_string.len;
#else
	component_count = krb5_princ_size(k5_context, r->k5_ticket->enc_part2->client);
#endif
	if ( component_count > 1)
	{
		elcprintf("will NOT accept instances for authentication\n");
		r->err_msg = "This service does not accept instances for authentication";
		r->err_code = KX509_STATUS_CLNT_FIX;
		return -1;
	}

#if defined(HAVE_HEIMDAL)
	name_len = strlen(*r->k5_ticket->client->name.name_string.val);
	if ( (name_len < 3) || (name_len > 8) )
	{
		elcprintf("received uniqname of invalid length (%0d): %s\n",
			name_len, r->k5_ticket->client->name.name_string.val);
#else
	r->k5_client = krb5_princ_component(k5_context,
					r->k5_ticket->enc_part2->client, 0);
	if ( (r->k5_client->length < 3) || (r->k5_client->length > 8) )
	{
		elcprintf("received uniqname of invalid length (%0d): %s\n",
			r->k5_client->length, r->k5_client_string);
#endif
		r->err_msg = "Invalid uniqname used -- must be three to eight characters in length";
		r->err_code = KX509_STATUS_CLNT_FIX;
		return -1;
	}
	return 0;
}

#endif	/* USE_KRB5 */

void
server_request(int sock)
{
	KX_MSG		clnt_msg;
	KX_MSG		srvr_msg;
	SOCKADDR	peeraddr;
	size_t		peerlen;
	int		from_addr;
	char		uniqname[9];
	char		realm[200];
	char		lifetime_flags[8+1+1];	/* No #define available... */
	char		fullname[200];
	long		rcv_len;
	int		rc;			/* Universal return code */
	int		i;
	struct request	r[1];
	char		*callerp;
	int		sent_something = 0;
	BIGNUM		*bnSerial;
	char 		*szSerial;

	memset((char*)r, 0, sizeof *r);
	r->version = KX509_VERSION_2_0;

	if (MSG_ALLOC(&clnt_msg, MAX_KCP_LEN))
	{
	    elcprintf("Unable to malloc space for return message!!\n");
	    /* YOWCH!!  Can't malloc, so skip reply message */
	    r->err_code = KX509_STATUS_SRVR_TMP;
	    goto exit_rtn2;
	}

	if (MSG_ALLOC(&srvr_msg, MAX_KSP_LEN))
	{
	    elcprintf("Unable to malloc space for recv'd packets!!\n");
	    r->err_msg = "Try again.  (Hopefully) temporary server-side memory problem";
	    r->err_code = KX509_STATUS_SRVR_TMP;
	    goto exit_rtn2;
	}

	rcv_len = udp_nb_recvfrom(sock, &clnt_msg, (void *)&peeraddr, &peerlen);
	if (rcv_len == -1)
	{
	    elcprintf("Error during udp_nb_recvfrom on socket: %s\n",
		    strerror(errno));
	    r->err_msg = "Failed to receive packet from \"kx509\"";
	    r->err_code = KX509_STATUS_SRVR_TMP;
	    goto exit_rtn2;
	}

	/* Make note of requestor's IP address (for krb_rd_req) */
	from_addr = ntohl(peeraddr.sin_addr.s_addr);

	{
	char ipstore[20];
	sprintf(r->caller_name, "from %s:%d",
		iptos(ntohl(peeraddr.sin_addr.s_addr),
			ipstore),
		(unsigned short)ntohs(peeraddr.sin_port));
	}
	callerp = r->caller_name + strlen(r->caller_name);

	if (rcv_len < 4)
		goto exit_rtn2;
	r->version = ntohl(*(long*)(clnt_msg.m_data)) & 0xffff;

	switch(r->version)
	{
	case KX509_VERSION_2_0:
		if (decode_version_2(&r[0], &clnt_msg)) {
			elcprintf("%s - failed to decode request\n", r->caller_name);
			goto exit_rtn;
		}
		break;
	default:
	    sprintf (r->err_msg = r->err_buf,
			"Incompatible kca_version: gave %0d.%02d, want %0d.%02d",
			(r->version)>>8, (r->version) & 0xFF,
			(KX509_VERSION_2_0)>>8, KX509_VERSION_2_0 & 0xFF);
	    lcprintf("Received request %s\n", r->caller_name);
	    elcprintf("%s\n", r->err_msg);
	    r->version = KX509_VERSION_2_0;
	    r->err_code = KX509_STATUS_CLNT_BAD;
	    goto exit_rtn;
	}
	sprintf(callerp, " v%d.%d", r->version>>8, r->version&255);
	callerp += strlen(callerp);

#if defined(USE_KRB5)
	if (KRB5_PVNO == r->krb_prot_version)
	{
	    if (authenticate_client_via_k5(r, realm))
	    {
		goto exit_rtn;
	    }

	    sprintf(callerp, " K5 %s", r->k5_client_string);
	    lcprintf("Received request %s\n", r->caller_name);

	    dprintf(DF('u'), "server_request: K5 realm='%s'\n", realm);

	}
#if defined(USE_KRB4)
	else
#endif
#endif	/* USE_KRB5 */
#if defined(USE_KRB4)
	if (4 == r->krb_prot_version)
	{
	    /*
	    ** DO A "krb_rd_req" TO AUTHENTICATE CLIENT
	    */

	    /*
	    ** Check for UMICH.EDU authentication
	    */
	    krb_ap_req_debug=1;
	    krb_ignore_ip_address = 1;		/* Tell the library to ignore ip address! */

	    if (rc = krb_rd_req(&r->authent, kca_princ, kca_inst, from_addr, &r->ad, srvtab))
	    {
#if defined(HAVE_UMID_LOOKUP)
		int umich_rc;
		umich_rc = rc;
		/* XXX this is silly.  One srvtab can hold multiple realms, the ap_req
		 * holds the realm, & krb_rd_req will look for the service key in the
		 * appropriate realm automatically.
		 */
		/*
		** Not UMICH.EDU auth so check for ENGIN.UMICH.EDU authentication
		*/
		elcprintf("%s.%s via %s krb_rd_req failed %d=(%s), trying ENGIN\n",
			kca_princ, kca_inst, srvtab,
			umich_rc, krb_err_txt[umich_rc]);
		if (rc = krb_rd_req(&r->authent, kca_princ, kca_inst, from_addr, &r->ad, srvtab_engin))
		{
		    lcprintf("Received request %s\n", r->caller_name);
		    elcprintf("%s.%s via %s krb_rd_req failed: %s\n",
			kca_princ, kca_inst, srvtab_engin,
			krb_err_txt[rc]);
		    r->err_msg = "Try re-authenticating.  Your ticket is either too old or for the wrong REALM";
		    r->err_code = KX509_STATUS_CLNT_TMP;
		    goto exit_rtn;
		}
		sprintf(callerp, " %s.%s@%s",
			r->ad.pname,
			r->ad.pinst,
			r->ad.prealm);
		lcprintf("Received request %s\n", r->caller_name);

		/*
		** Only allow ENGIN.UMICH.EDU authentication when the "caen" lifetime
		** for the requesting uniqname allows CAEN to reset the UMICH password
		** (which should be true for all ENGIN folks)
		*/
		if (rc = uniqtolifetime(r->ad.pname, "caen", lifetime_flags))
		{
		    elcprintf("uniqtolifetime for %s's \"caen\" lifetime failed: %d %s\n",
			 r->ad.pname,
			rc, error_message(rc));
		    r->err_msg = "Try using UMICH tickets.  ENGIN tickets can only be used for "
				"uniqnames that are setup to allow CAEN to reset their UMICH password";
		    r->err_code = KX509_STATUS_CLNT_FIX;
		    goto exit_rtn;
		}
		elcprintf("%s's \"caen\" lifetime is \"%s\"\n", r->ad.pname, lifetime_flags);
		if (!index(lifetime_flags, 'P'))
		{
		    elcprintf("%s's \"caen\" lifetime of \"%s\" lacks Password reset flag\n",
			 r->ad.pname, lifetime_flags);
		    r->err_msg = "Try using UMICH tickets.  ENGIN tickets can only be used for "
				"uniqname that are setup to allow CAEN to reset their UMICH password";
		    r->err_code = KX509_STATUS_CLNT_FIX;
		    goto exit_rtn;
		}
#else	/* HAVE_UMID_LOOKUP */
		elcprintf("%s.%s via %s krb_rd_req failed %d=(%s)\n",
			kca_princ, kca_inst, srvtab,
			rc, krb_err_txt[rc]);
		dprintf(1, "server_request: initial rd_req failed with %d (from_addr 0x%08x)\n",
			rc, from_addr);
		r->err_msg = "Try re-authenticating.  Your ticket could not be used for the request";
		r->err_code = KX509_STATUS_CLNT_TMP;
		goto exit_rtn;

#endif	/* HAVE_UMID_LOOKUP */
	    } else {
		sprintf(callerp, " K4 %s.%s@%s",
			r->ad.pname,
			r->ad.pinst,
			r->ad.prealm);
		lcprintf("Received request %s\n", r->caller_name);
	    }
	    strcpy(realm, r->ad.prealm);
	    dprintf(DF('u'), "server_request: K4 realm='%s'\n", realm);
	}
#endif	/* USE_KRB4 */
	else
	{
		r->err_msg = "Try re-authenticating.  You may be using a version of Kerberos that I can't handle?";
		r->err_code = KX509_STATUS_CLNT_TMP;
		goto exit_rtn;
	}

	r->ad_is_valid = 1;
	switch(r->version)
	{
	case KX509_VERSION_2_0:
		if (validate_version_2(r, &clnt_msg))
			goto exit_rtn;
		break;
	default:
		;
	}

#if defined(USE_KRB5)
	if (KRB5_PVNO == r->krb_prot_version)
	{
	    if (validate_client_via_k5(r))
	    {
		goto exit_rtn;
	    }
#if defined(HAVE_HEIMDAL)
	    strcpy(uniqname, *r->k5_ticket->client->name.name_string.val);
#else
	    strncpy(uniqname, r->k5_client->data, r->k5_client->length);
	    uniqname[r->k5_client->length] = '\0';
#endif

	    dprintf(DF('u'), "authenticated uniqname ('%s') on socket\n",
			r->k5_client_string);

#if defined(HAVE_HEIMDAL)
	    free(r->k5_client_string);
#else
	    krb5_free_unparsed_name(k5_context, r->k5_client_string);
#endif
	}
#if defined(USE_KRB4)
	else
#endif
#endif	/* USE_KRB5 */
#if defined(USE_KRB4)
	if (4 == r->krb_prot_version)
	{
	    if ((strlen(r->ad.pname) < 3) || (strlen(r->ad.pname) > 8))
	    {
		elcprintf("received uniqname of invalid length (%0d): %s\n",
		    strlen(r->ad.pname), r->ad.pname);
		r->err_msg = "Invalid uniqname used -- must be three to eight characters in length";
		r->err_code = KX509_STATUS_CLNT_FIX;
		goto exit_rtn;
	    }
	    strcpy(uniqname, r->ad.pname);

	    if (strlen(r->ad.pinst))
	    {
		elcprintf("will NOT accept instances for authentication: '%s'\n",
		    r->ad.pinst);
		r->err_msg = "This service does not accept instances for authentication";
		r->err_code = KX509_STATUS_CLNT_FIX;
		goto exit_rtn;
	    }

	    dprintf(DF('u'), "authenticated uniqname ('%s@%s') on socket\n",
			uniqname, r->ad.prealm);
	}
#endif	/* USE_KRB4 */
	else
	{
	    elcprintf("The client is using a version of Kerberos (%d) that I do not understand!\n",
		    r->krb_prot_version);
	    r->err_msg = "You are using a version of kerberos that the KCA does not understand";
	    r->err_code = KX509_STATUS_CLNT_FIX;
	    goto exit_rtn;
	}

	/*
	** get PEM-encoded Public Key
	*/

	dprintf(DF('u'), "recv'd Public Key\n");

	/*
	** use it to make and sign an X.509 certificate
	*/
	if (r->err_code = do_CA(r, uniqname, realm))
	{
		elcprintf("do_CA failed: err_code=%0d, err_msg='%s'\n",
			r->err_code, r->err_msg);
		/* r->err_msg is set by do_CA() above */
		goto exit_rtn;
	}

	dprintf(DF('u'),"will send cert\n");

	bnSerial = ASN1_INTEGER_to_BN(X509_get_serialNumber(r->cert), NULL);
	if (bnSerial == NULL)
		elcprintf("Could not convert serial number to BIGNUM for printing\n");
	else
	{
		szSerial = BN_bn2hex(bnSerial);
		lcprintf("Issuing serial number %s for request %s\n",
			 szSerial, r->caller_name);
		OPENSSL_free(szSerial);
		BN_free(bnSerial);
	}
exit_rtn:

	switch(r->version)
	{
	case KX509_VERSION_2_0:
		if (encode_version_2(r, &srvr_msg))
			goto exit_rtn2;
		break;
	default:
		goto exit_rtn2;
	}

	i = udp_nb_sendto(sock, &srvr_msg, &peeraddr);
	sent_something = 1;
exit_rtn2:
	if (!sent_something)
		lcprintf("result -1 nothing sent.\n");
	if (r->err_code)
		lcprintf("result %d %s%s\n",
				r->err_code,
				r->ad_is_valid ? "" : "unauthentic ",
				r->err_msg ? r->err_msg : "Missing error message");
	else
		lcprintf("result 0 sent cert\n");
	if (clnt_msg.m_data)
		MSG_FREE(&clnt_msg);
	if (srvr_msg.m_data)
		MSG_FREE(&srvr_msg);
	if (r->v2.request)
		KX509_REQUEST_free(r->v2.request);
	if (r->pubkey)
		EVP_PKEY_free(r->pubkey);
	if (r->cert)
		X509_free(r->cert);
#if defined(USE_KRB5)
	if ( KRB5_PVNO == r->krb_prot_version ) {
		if (r->k5_authent.data != NULL )
			free(r->k5_authent.data);
		if (r->k5_ticket != NULL)
			krb5_free_ticket(k5_context, r->k5_ticket);
		if (r->k5_auth_context != NULL )
			krb5_auth_con_free(k5_context, r->k5_auth_context);
	}
#endif
}


int
main(int argc, char **argv)
{
	fd_set	socket_set;
	int	socket_set_size;


	pn = argv[0];

	process_args(argc, argv);

	if (server_init(&socket_set, &socket_set_size, KRBCHK_PORT))
	{
		exit (1);
	}

	server_main(&socket_set, &socket_set_size, &server_request);
}
