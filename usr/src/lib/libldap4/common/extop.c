/*
 *
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * Comments:   
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>

#ifdef MACOS
#include "macos.h"
#endif /* MACOS */

#if !defined( MACOS ) && !defined( DOS )
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

BerElement * ldap_build_extended_operation_req(LDAP *ld, char *exoid, struct berval *exdata, LDAPControl ** serverctrls)
{
	BerElement *ber;
	int rv;
	
	/* an extended operation request looks like this: 
	 * ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
	 *		requestName		[0] LDAPOID,
	 *		requestValue	[1] OCTECT STRING OPTIONAL
	 * }
	 */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( NULLBER );
	}

	if ( ber_printf( ber, "{it{ts", ++ld->ld_msgid, LDAP_REQ_EXTENDED, LDAP_TAG_EXT_NAME, exoid ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}

	if (exdata && (ber_printf(ber, "to", LDAP_TAG_EXT_VAL, exdata->bv_val, exdata->bv_len) == -1 )) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}
	
	if ( ber_printf( ber, "}" ) == -1 ) {
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

/* ldap_extended_operation - initiate an ldap extended operation.
 * Parameters :
 *   ld : LDAP descriptor.
 *   exoid : OID of the request.
 *   exdata : Arbitrary data required by the operation.
 *   serverctrls : List of server controls.
 *   clientctrls : List of client controls.
 *   msgidp : msg id returned if operation succeeded.
 * Returns LDAP_SUCCESS or error code.
 */

int ldap_extended_operation(LDAP *ld, char *exoid, struct berval *exdata,
							LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp)
{
	BerElement	*ber;
	int rv;
	
#ifdef _REENTRANT
        LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 242, "ldap_extended_operation\n"), 0, 0, 0 );

	if (( ber = ldap_build_extended_operation_req( ld, exoid, exdata, serverctrls)) == NULLBER ) {
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS)
			rv = LDAP_OTHER;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return( rv);
	}

	/* send the message */
	rv = send_initial_request( ld, LDAP_REQ_EXTENDED, NULL, ber );
	if (rv == -1) {
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
#if _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return ( LDAP_SUCCESS );
}


int ldap_extended_operation_s(LDAP *ld, char *exoid, struct berval *exdata,
							  LDAPControl **serverctrls, LDAPControl **clientctrls, 
							  char **retoidp, struct berval **retdatap) 
{
	int msgid;
	int retcode;
	LDAPMessage *res = NULL;
	
	if ((retcode = ldap_extended_operation(ld, exoid, exdata, serverctrls, clientctrls, &msgid)) != LDAP_SUCCESS)
		return (retcode);
	if (ldap_result(ld, msgid, 1, (struct timeval *)NULL, &res ) == -1)
		return (ld->ld_errno );

	return (ldap_parse_extended_result(ld, res, retoidp, retdatap, 1));
}
