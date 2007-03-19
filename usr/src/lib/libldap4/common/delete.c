/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  delete.c
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
#include "msdos.h"
#endif /* DOS */

#if !defined( MACOS ) && !defined( DOS )
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

BerElement * ldap_build_delete_req(LDAP *ld, char *dn, LDAPControl **serverctrls)
{
	BerElement	*ber;
	int rv;

	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return(NULLBER );
	}

	if ( ber_printf( ber, "{its", ++ld->ld_msgid, LDAP_REQ_DELETE, dn ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return(NULLBER );
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
 * ldap_delete - initiate an ldap (and X.500) delete operation. Parameters:
 *
 *	ld		LDAP descriptor
 *	dn		DN of the object to delete
 *
 * Example:
 *	msgid = ldap_delete( ld, dn );
 */
int
ldap_delete( LDAP *ld, char *dn )
{
	BerElement	*ber;
	int rv;

	/*
	 * A delete request looks like this:
	 *	DelRequet ::= DistinguishedName,
	 */

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 129, "ldap_delete\n"), 0, 0, 0 );

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	
	if (( ber = ldap_build_delete_req(ld, dn, NULL)) == NULLBER) {
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (-1);
	}
		
	/* send the message */
	rv = send_initial_request( ld, LDAP_REQ_DELETE, dn, ber );
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return ( rv );
}


int
ldap_delete_s( LDAP *ld, char *dn )
{
	int		msgid;
	LDAPMessage	*res;

	if ( (msgid = ldap_delete( ld, dn )) == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, res, 1 ) );
}

/* ldapv3 API extensions */

int ldap_delete_ext(LDAP *ld, char *dn, LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp)
{
	BerElement	*ber;
	int rv;

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif	

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 192, "ldap_modify\n"), 0, 0, 0 );

	if ((ber = ldap_build_delete_req(ld, dn, serverctrls)) == NULLBER){
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS)
			rv = LDAP_OTHER;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (rv);
	}

	/* send the message */
	rv =  send_initial_request( ld, LDAP_REQ_DELETE, dn, ber );
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

int ldap_delete_ext_s(LDAP *ld, char *dn, LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	int msgid;
	int retcode = LDAP_SUCCESS;
	LDAPMessage *res;
	
	if ((retcode = ldap_delete_ext(ld, dn, serverctrls, clientctrls, &msgid)) != LDAP_SUCCESS)
		return (retcode);
	if (ldap_result(ld, msgid, 1, (struct timeval *)NULL, &res ) == -1)
		return (ld->ld_errno );

#ifdef  _REENTRANT
	LOCK_LDAP(ld);
#endif	
	retcode = ldap_parse_result( ld, res,  &ld->ld_errno, &ld->ld_matched, &ld->ld_error,
								 &ld->ld_referrals, &ld->ld_ret_ctrls, 1);
	if (retcode == LDAP_SUCCESS)
		retcode = ld->ld_errno;
#ifdef  _REENTRANT
	UNLOCK_LDAP(ld);
#endif	
	return (retcode);
}
