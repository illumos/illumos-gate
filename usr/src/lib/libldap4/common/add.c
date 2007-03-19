/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  add.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>

#ifdef MACOS
#include "macos.h"
#endif /* MACOS */

#if defined( DOS ) || defined( _WIN32 )
#include <malloc.h>
#include "msdos.h"
#endif /* DOS */

#if !defined( MACOS ) && !defined( DOS )
#include <sys/types.h>
#include <sys/socket.h>
#endif /* !MACOS && !DOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"


BerElement * ldap_build_add_req(LDAP *ld, char *dn, LDAPMod **attrs, 
								LDAPControl ** serverctrls)
{
	BerElement * ber;
	int rc, i;
	
	/*
	 * An add request looks like this:
	 *	AddRequest ::= [APPLICATION 8] SEQUENCE {
	 *		entry	DistinguishedName,
	 *		attrs	SEQUENCE OF SEQUENCE {
	 *			type	AttributeType,
	 *			values	SET OF AttributeValue
	 *		}
	 *	}
	 */

	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( NULLBER );
	}

	if ( ber_printf( ber, "{it{s{", ++ld->ld_msgid, LDAP_REQ_ADD, dn )
	    == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}

	/* for each attribute in the entry... */
	for ( i = 0; attrs[i] != NULL; i++ ) {
		if ( ( attrs[i]->mod_op & LDAP_MOD_BVALUES) != 0 ) {
			rc = ber_printf( ber, "{s[V]}", attrs[i]->mod_type,
			    attrs[i]->mod_values );
		} else {
			rc = ber_printf( ber, "{s[v]}", attrs[i]->mod_type,
			    attrs[i]->mod_values );
		}
		if ( rc == -1 ) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return(NULLBER);
		}
	}

	if ( ber_printf( ber, "}}" ) == -1 ) {
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
 * ldap_add - initiate an ldap (and X.500) add operation.  Parameters:
 *
 *	ld		LDAP descriptor
 *	dn		DN of the entry to add
 *	mods		List of attributes for the entry.  This is a null-
 *			terminated array of pointers to LDAPMod structures.
 *			only the type and values in the structures need be
 *			filled in.
 *
 * Example:
 *	LDAPMod	*attrs[] = { 
 *			{ 0, "cn", { "babs jensen", "babs", 0 } },
 *			{ 0, "sn", { "jensen", 0 } },
 *			{ 0, "objectClass", { "person", 0 } },
 *			0
 *		}
 *	msgid = ldap_add( ld, dn, attrs );
 */
int ldap_add( LDAP *ld, char *dn, LDAPMod **attrs )
{
	BerElement	*ber;
	int rv;

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 87, "ldap_add\n"), 0, 0, 0 );

	if ((ber = ldap_build_add_req(ld, dn, attrs, NULL)) == NULLBER){
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (-1);
	}
	
	/* send the message */
	rv = send_initial_request( ld, LDAP_REQ_ADD, dn, ber );
#ifdef  _REENTRANT
	UNLOCK_LDAP(ld);
#endif	
	return (rv);
}

int
ldap_add_s( LDAP *ld, char *dn, LDAPMod **attrs )
{
	int		msgid;
	LDAPMessage	*res;

	if ( (msgid = ldap_add( ld, dn, attrs )) == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, res, 1 ) );
}


/* ldapv3 API extensions */
/*
 * ldap_add_ext - initiate an ldap (and X.500) add operation.  Parameters:
 *
 *	ld		LDAP descriptor
 *	dn		DN of the entry to add
 *	attrs	List of attributes for the entry.  This is a null-
 *			terminated array of pointers to LDAPMod structures.
 *			only the type and values in the structures need be
 *			filled in.
 *  serverctrls	List of server controls. This is a null-terminated
 *			array of pointers to LDAPControl structures.
 *  clientctrls	List of client controls.
 *
 * Example:
 *	LDAPMod	*attrs[] = { 
 *			{ 0, "cn", { "babs jensen", "babs", 0 } },
 *			{ 0, "sn", { "jensen", 0 } },
 *			{ 0, "objectClass", { "person", 0 } },
 *			0
 *		}
 *
 *	retcode = ldap_add_ext( ld, dn, attrs, srvctrls, cltctrls, &msgid );
 */

int ldap_add_ext(LDAP *ld, char *dn, LDAPMod **attrs, 
				 LDAPControl ** serverctrls, LDAPControl **clientctrls, int *msgidp)
{
	BerElement	*ber;
	int		i, rc;
	int rv;

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 87, "ldap_add\n"), 0, 0, 0 );

	if ((ber = ldap_build_add_req(ld, dn, attrs, serverctrls)) == NULLBER){
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS)
			rv = LDAP_OTHER;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (rv);
	}
	
	/* send the message */
	rv = send_initial_request( ld, LDAP_REQ_ADD, dn, ber );
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
#ifdef  _REENTRANT
	UNLOCK_LDAP(ld);
#endif	
	return (LDAP_SUCCESS);
}

int ldap_add_ext_s(LDAP *ld, char *dn, LDAPMod **attrs, 
				   LDAPControl ** serverctrls, LDAPControl **clientctrls)
{
	int msgid;
	int retcode = LDAP_SUCCESS;
	LDAPMessage *res;
	
	if ((retcode = ldap_add_ext(ld, dn, attrs, serverctrls, clientctrls, &msgid)) != LDAP_SUCCESS)
		return (retcode);
	if (ldap_result(ld, msgid, 1, (struct timeval *)NULL, &res ) == -1)
		return (ld->ld_errno );

#ifdef  _REENTRANT
	LOCK_LDAP(ld);
#endif	
	retcode = ldap_parse_result(ld, res, &ld->ld_errno, &ld->ld_matched, &ld->ld_error,
								&ld->ld_referrals, &ld->ld_ret_ctrls, 1);
	if (retcode == LDAP_SUCCESS)
		retcode = ld->ld_errno;
#ifdef  _REENTRANT
	UNLOCK_LDAP(ld);
#endif	
	return (retcode);
}
