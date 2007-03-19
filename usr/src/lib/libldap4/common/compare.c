/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  compare.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

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

BerElement * ldap_build_compare_req(LDAP *ld, char *dn, char *attr, 
									struct berval *bvalue, LDAPControl **serverctrls)
{
	BerElement *ber;
	int rc, rv;

	/* The compare request looks like this:
	 *	CompareRequest ::= SEQUENCE {
	 *		entry	DistinguishedName,
	 *		ava	SEQUENCE {
	 *			type	AttributeType,
	 *			value	AttributeValue
	 *		}
	 *	}
	 * and must be wrapped in an LDAPMessage.
	 */
	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( NULLBER );
	}

	if ( ber_printf( ber, "{it{s{so}}", ++ld->ld_msgid, LDAP_REQ_COMPARE,
	    dn, attr, bvalue->bv_val, bvalue->bv_len ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}

	/* LDAPv3 */
	/* Code controls if any */
	if (serverctrls && serverctrls[0]) {
		if (ldap_controls_code(ber, serverctrls) != LDAP_SUCCESS){
			ld->ld_errno = LDAP_ENCODING_ERROR;
			return( NULLBER );
		}
	} else if (ld->ld_srvctrls && ld->ld_srvctrls[0]) {
		/* Otherwise, is there any global server ctrls ? */
		if (ldap_controls_code(ber, ld->ld_srvctrls) != LDAP_SUCCESS){
			ld->ld_errno = LDAP_ENCODING_ERROR;
			return( NULLBER );
		}
	}
	if (ber_printf(ber, "}") == -1) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free(ber, 1);
		return (NULLBER);
	}
	
	return (ber);
}

/*
 * ldap_compare - perform an ldap (and X.500) compare operation.  The dn
 * of the entry to compare to and the attribute and value to compare (in
 * attr and value) are supplied.  The msgid of the response is returned.
 *
 * Example:
 *	ldap_compare( ld, "c=us@cn=bob", "userPassword", "secret" )
 */
int
ldap_compare( LDAP *ld, char *dn, char *attr, char *value )
{
	BerElement	*ber;
	struct berval bv;
	int rv;
	
	/* The compare request looks like this:
	 *	CompareRequest ::= SEQUENCE {
	 *		entry	DistinguishedName,
	 *		ava	SEQUENCE {
	 *			type	AttributeType,
	 *			value	AttributeValue
	 *		}
	 *	}
	 * and must be wrapped in an LDAPMessage.
	 */

#ifdef _REENTRANT
        LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 128, "ldap_compare\n"), 0, 0, 0 );

	bv.bv_val = value;
	bv.bv_len = strlen(value);
	
	if ((ber = ldap_build_compare_req(ld, dn, attr, &bv, NULL)) == NULLBER) {
#ifdef _REENTRANT
        UNLOCK_LDAP(ld);
#endif
		return (-1);
	}
	
#ifndef NO_CACHE
	if ( ld->ld_cache != NULL ) {
		if ( check_cache( ld, LDAP_REQ_COMPARE, ber ) == 0 ) {
			ber_free( ber, 1 );
			ld->ld_errno = LDAP_SUCCESS;
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return( ld->ld_msgid );
		}
		add_request_to_cache( ld, LDAP_REQ_COMPARE, ber );
	}
#endif /* NO_CACHE */

	/* send the message */
	rv = send_initial_request( ld, LDAP_REQ_COMPARE, dn, ber );
#ifdef _REENTRANT
        UNLOCK_LDAP(ld);
#endif
	return (rv);
}

int
ldap_compare_s( LDAP *ld, char *dn, char *attr, char *value )
{
	int		msgid;
	LDAPMessage	*res;

	if ( (msgid = ldap_compare( ld, dn, attr, value )) == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, res, 1 ) );
}

/* LDAPv3 API extensions */
int ldap_compare_ext(LDAP *ld, char *dn, char *attr, struct berval *bvalue,
					 LDAPControl ** serverctrls, LDAPControl **clientctrls, int *msgidp)
{
	BerElement	*ber;
	struct berval bv;
	int rv;
	
	/* The compare request looks like this:
	 *	CompareRequest ::= SEQUENCE {
	 *		entry	DistinguishedName,
	 *		ava	SEQUENCE {
	 *			type	AttributeType,
	 *			value	AttributeValue
	 *		}
	 *	}
	 * and must be wrapped in an LDAPMessage.
	 */

#ifdef _REENTRANT
        LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 128, "ldap_compare\n"), 0, 0, 0 );

	if ((ber = ldap_build_compare_req(ld, dn, attr, bvalue, NULL)) == NULLBER) {
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS)
			rv = LDAP_OTHER;
#ifdef _REENTRANT
        UNLOCK_LDAP(ld);
#endif
		return (rv);
	}
	
#ifndef NO_CACHE
	if ( ld->ld_cache != NULL ) {
		if ( check_cache( ld, LDAP_REQ_COMPARE, ber ) == 0 ) {
			ber_free( ber, 1 );
			ld->ld_errno = LDAP_SUCCESS;
			*msgidp = ld->ld_msgid;
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return( LDAP_SUCCESS );
		}
		add_request_to_cache( ld, LDAP_REQ_COMPARE, ber );
	}
#endif /* NO_CACHE */

	/* send the message */
	rv = send_initial_request( ld, LDAP_REQ_COMPARE, dn, ber );
	if (rv == -1) {
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS){
			rv = LDAP_OTHER;
		}
#ifdef  _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (rv);
	}
	
	*msgidp = rv;
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (LDAP_SUCCESS);
}

int ldap_compare_ext_s(LDAP *ld, char *dn, char *attr, struct berval *bvalue,
					   LDAPControl ** serverctrls, LDAPControl **clientctrls)
{
	int		msgid, retcode = LDAP_SUCCESS;
	LDAPMessage	*res;

	if ( (retcode = ldap_compare_ext( ld, dn, attr, bvalue, serverctrls, clientctrls, &msgid )) != LDAP_SUCCESS )
		return( retcode );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	retcode = ldap_parse_result( ld, res,  &ld->ld_errno, &ld->ld_matched, &ld->ld_error,
								 &ld->ld_referrals, &ld->ld_ret_ctrls, 1);
	if (retcode == LDAP_SUCCESS)
		retcode = ld->ld_errno;
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (retcode);
}

