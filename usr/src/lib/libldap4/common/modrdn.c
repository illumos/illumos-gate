/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  modrdn.c
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

/*
 * ldap_modrdn - initiate an ldap (and X.500) modifyRDN operation. Parameters:
 *
 *	ld		LDAP descriptor
 *	dn		DN of the object to modify
 *	newrdn		RDN to give the object
 *	deleteoldrdn	nonzero means to delete old rdn values from the entry
 *
 * Example:
 *	msgid = ldap_modrdn( ld, dn, newrdn );
 */
int
ldap_modrdn( LDAP *ld, char *dn, char *newrdn, int deleteoldrdn )
{
	BerElement	*ber;
	int rv;

	/*
	 * A modify rdn request looks like this:
	 *	ModifyRDNRequest ::= SEQUENCE {
	 *		entry		DistinguishedName,
	 *		newrdn		RelativeDistinguishedName,
	 *		deleteoldrdn	BOOLEAN
	 *	}
	 */

#ifdef _REENTRANT
        LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 193, "ldap_modrdn\n"), 0, 0, 0 );

	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

	if ( ber_printf( ber, "{it{ssb}}", ++ld->ld_msgid, LDAP_REQ_MODRDN, dn,
	    newrdn, deleteoldrdn ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

	/* send the message */
	rv = send_initial_request( ld, LDAP_REQ_MODRDN, dn, ber );
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return ( rv );
}

int
ldap_modrdn0( LDAP *ld, char *dn, char *newrdn )
{
	return( ldap_modrdn( ld, dn, newrdn, 1 ) );
}

int
ldap_modrdn_s( LDAP *ld, char *dn, char *newrdn, int deleteoldrdn )
{
	int		msgid;
	LDAPMessage	*res;

	if ( (msgid = ldap_modrdn( ld, dn, newrdn, deleteoldrdn )) == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, res, 1 ) );
}

int
ldap_modrdn0_s( LDAP *ld, char *dn, char *newrdn )
{
	return( ldap_modrdn_s( ld, dn, newrdn, 1 ) );
}
