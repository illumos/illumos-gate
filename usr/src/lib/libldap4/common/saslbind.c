/*
 *
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * Comments:   
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"
#include "sec.h"
#include <strings.h>

BerElement * ldap_build_sasl_bind_req( LDAP *ld, char *dn, char *mechanism, struct berval *creds, LDAPControl ** serverctrls)
{
	BerElement *ber = NULL;
	int err;
	
	/* Create a Bind Request for SASL authentication.
	 * It look like this :
	 * BindRequest := [APPLICATION 0] SEQUENCE {
	 *		version		INTEGER,
	 *		name		LDAPDN,
	 *		authentication	CHOICE {
	 *			sasl		[3] SEQUENCE {
	 *				mechanism	LDAPString,
	 *				credential	OCTET STRING OPTIONAL
	 * 			}
	 *		}
	 *	}
	 * all wrapped up in an LDAPMessage sequence.
	 */
	
	if (dn == NULL || *dn == '\0'){
		ld->ld_errno = LDAP_PARAM_ERROR;
		return (NULLBER);
	}
	
	
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		return (NULLBER);
	}
	if ( ber_printf( ber, "{it{ist{s", ++ld->ld_msgid, LDAP_REQ_BIND, ld->ld_version, dn, LDAP_AUTH_SASL, mechanism) == -1){
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free(ber, 1);
		return (NULLBER);
	}
	if (creds != NULL && creds->bv_val != NULL) {
		if (ber_printf(ber, "o", creds->bv_val, creds->bv_len) == -1){
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free(ber, 1);
			return (NULLBER);
		}
	}
	if (ber_printf(ber, "}}") == -1){
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}
	/* LDAPv3 */
	/* Code controls if any */
	if (serverctrls && serverctrls[0]) {
		if (ldap_controls_code(ber, serverctrls) != LDAP_SUCCESS){
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( NULLBER );
		}
	} else if (ld->ld_srvctrls && ld->ld_srvctrls[0]) {
		/* Otherwise, is there any global server ctrls ? */
		if (ldap_controls_code(ber, ld->ld_srvctrls) != LDAP_SUCCESS){
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( NULLBER );
		}
	}

	if ( ber_printf( ber, "}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}
	
	return (ber);
}

/* 
 * ldap_sasl_bind - bind to the ldap server (and X.500).
 * dn, mechanism, cred, serverctrls, and clientctrls are supplied. 
 * the message id of the request is returned in msgid
 * Returns LDAP_SUCCESS or an error code.
 */

int ldap_sasl_bind(
	LDAP *ld,
	char *dn,
	char *mechanism,
	struct berval *cred,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls,
	int *msgidp)
{
	int theErr = LDAP_SUCCESS;
	int rv;
	BerElement *ber = NULL;
	
	Debug ( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 1288, "ldap_sasl_bind\n"), 0,0,0);

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	if (strcasecmp(mechanism, LDAP_SASL_SIMPLE) == 0){
		/* Simple bind */
		if ( (ber = ldap_build_simple_bind_req(ld, dn, cred->bv_val, serverctrls)) == NULLBER){
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &theErr);
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif	
			return (theErr);
		}
	}

	if (strcasecmp(mechanism, LDAP_SASL_CRAM_MD5) == 0){
		if (( ber = ldap_build_sasl_bind_req(ld, dn, LDAP_SASL_CRAM_MD5, cred, serverctrls)) == NULLBER) {
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &theErr);
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif	
			return (theErr);
		}
	}

	if (strcasecmp(mechanism, LDAP_SASL_EXTERNAL) == 0){
		if (( ber = ldap_build_sasl_bind_req(ld, dn, LDAP_SASL_EXTERNAL, cred, serverctrls)) == NULLBER) {
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &theErr);
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif	
			return (theErr);
		}
	}

	if (strcasecmp(mechanism, LDAP_SASL_X511_PROTECTED) == 0){
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (LDAP_NOT_SUPPORTED);
/* 
 *		if (( ber = ldap_build_sasl_bind_req(ld, dn, LDAP_SASL_X511_PROTECTED, cred, serverctrls)) == NULLBER) {
 *			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &theErr);
 *#ifdef _REENTRANT
 *			UNLOCK_LDAP(ld);
 *#endif	
 *			return (theErr);
 *		}
 */		
	}
	if (strcasecmp(mechanism, LDAP_SASL_X511_STRONG) == 0){
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (LDAP_NOT_SUPPORTED);
/* 
 *		if (( ber = ldap_build_sasl_bind_req(ld, dn, LDAP_SASL_X511_PROTECTED, cred, serverctrls)) == NULLBER) {
 *			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &theErr);
 *#ifdef _REENTRANT
 *			UNLOCK_LDAP(ld);
 *#endif	
 *			return (theErr);
 *		}
 */		
	}
	if (strcasecmp(mechanism, LDAP_SASL_KERBEROS_V4) == 0){
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (LDAP_NOT_SUPPORTED);
/* 
 *		if (( ber = ldap_build_sasl_bind_req(ld, dn, LDAP_SASL_X511_PROTECTED, cred, serverctrls)) == NULLBER) {
 *			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &theErr);
 *#ifdef _REENTRANT
 *			UNLOCK_LDAP(ld);
 *#endif	
 *			return (theErr);
 *		}
 */		
	}
	if (strcasecmp(mechanism, LDAP_SASL_GSSAPI) == 0){
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (LDAP_NOT_SUPPORTED);
/* 
 *		if (( ber = ldap_build_sasl_bind_req(ld, dn, LDAP_SASL_X511_PROTECTED, cred, serverctrls)) == NULLBER) {
 *			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &theErr);
 *#ifdef _REENTRANT
 *			UNLOCK_LDAP(ld);
 *#endif	
 *			return (theErr);
 *		}
 */		
	}
	if (strcasecmp(mechanism, LDAP_SASL_SKEY) == 0){
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (LDAP_NOT_SUPPORTED);
/* 
 *		if (( ber = ldap_build_sasl_bind_req(ld, dn, LDAP_SASL_X511_PROTECTED, cred, serverctrls)) == NULLBER) {
 *			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &theErr);
 *#ifdef _REENTRANT
 *			UNLOCK_LDAP(ld);
 *#endif	
 *			return (theErr);
 *		}
 */		
	}
	if (ber == NULL){
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (LDAP_PARAM_ERROR);
	}

#ifndef NO_CACHE
	if ( ld->ld_cache != NULL ) {
		ldap_flush_cache( ld );
	}
#endif /* !NO_CACHE */
	
	/* send the message */
	rv = send_initial_request( ld, LDAP_REQ_BIND, dn, ber );
	if (rv == -1){
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS){
			rv = LDAP_OTHER;
		}
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return (rv);
	}
	*msgidp = rv;
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return ( LDAP_SUCCESS );
}

/* 
 * ldap_sasl_bind_s - bind to the ldap server (and X.500).
 * dn, mechanism, cred, serverctrls, and clientctrls are supplied. 
 * the message id of the request is returned in msgid
 * Returns LDAP_SUCCESS or an error code.
 */

int ldap_sasl_bind_s(	
	LDAP *ld,
	char *dn,
	char *mechanism,
	struct berval *cred,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls,
	struct berval **servercredp)
{
	int msgid;
	int retcode;
	LDAPMessage *res;
	
	Debug ( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 1288, "ldap_sasl_bind\n"), 0,0,0);

	if ((retcode = ldap_sasl_bind(ld, dn, mechanism, cred, serverctrls, clientctrls, &msgid)) != LDAP_SUCCESS)
		return (retcode);
	if (ldap_result(ld, msgid, 1, (struct timeval *)NULL, &res ) == -1)
		return (ld->ld_errno );

	return (ldap_parse_sasl_bind_result(ld, res, servercredp, 1));
}

int ldap_sasl_cram_md5_bind_s(
	LDAP *ld,
	char *dn,
	struct berval *cred,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls ) 
{
	int res;
	struct berval *challenge = NULL;
	struct berval resp;
	unsigned char digest[16];
	char *theHDigest;
	
	if (dn == NULL){
		return (LDAP_PARAM_ERROR);
	}

	bzero(digest, sizeof (digest));
	
	if ((res = ldap_sasl_bind_s(ld, dn, LDAP_SASL_CRAM_MD5, NULL, serverctrls, clientctrls, &challenge))
		!= LDAP_SASL_BIND_INPROGRESS){
		return (res);
	}
	if (challenge == NULL){
		return (LDAP_PARAM_ERROR);
	}
	
	Debug (LDAP_DEBUG_TRACE, "SASL challenge: %s\n", challenge->bv_val, 0, 0);
	
	hmac_md5((unsigned char *)challenge->bv_val, challenge->bv_len, 
					 (unsigned char *)cred->bv_val, cred->bv_len,  digest);
	ber_bvfree(challenge);
	challenge = NULL;
	
	theHDigest = hexa_print(digest, 16);
	if (theHDigest == NULL){
		return (LDAP_NO_MEMORY);
	}

	resp.bv_len = (strlen(dn) + 32 + 1);
	if ((resp.bv_val = (char *)malloc(resp.bv_len+1)) == NULL) {
		return(LDAP_NO_MEMORY);
	}
	
	sprintf(resp.bv_val, "%s %s", dn, theHDigest);
	free(theHDigest);

	Debug (LDAP_DEBUG_TRACE, "SASL response: %s\n", resp.bv_val, 0, 0);
	res = ldap_sasl_bind_s(ld, dn, LDAP_SASL_CRAM_MD5, &resp, serverctrls, clientctrls, &challenge);

	free(resp.bv_val);
	return (res);
}
