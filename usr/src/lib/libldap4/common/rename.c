/*
 *
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
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

BerElement * ldap_build_rename_req ( LDAP *ld, char *dn, char *newrdn, char *newparent,
									 int deleteoldrdn, LDAPControl **serverctrls)
{
	BerElement *ber;
	int rc;
	
	/*
	 * A modify rdn request looks like this:
	 *	ModifyRDNRequest ::= SEQUENCE {
	 *		entry		LDAPDN,
	 *		newrdn		RelativeLDAPDN,
	 *		deleteoldrdn	BOOLEAN
	 *		newSuperior	[0]	LDAPDN OPTIONAL
	 *	}
	 */

	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		return( NULLBER );
	}

	if ( ber_printf( ber, "{it{ssb", ++ld->ld_msgid, LDAP_REQ_MODRDN, dn,
	    newrdn, deleteoldrdn ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}

	if (newparent) {
		if ( ber_printf( ber, "ts}", LDAP_TAG_NEWPARENT, newparent) == -1){
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( NULLBER );
		}
		
	} else if ( ber_printf( ber, "}" ) == -1 ) {
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

/* ldap_rename - Modify the name of an entry.
 * Parameters :
 *     ld : LDAP descriptor.
 *     dn : DN of the object to rename.
 *     newrdn : New RDN to give to the entry.
 *     newparent : the parent or superior entry. If NULL only RDN is changed.
 *                 "" means the root DN.
 *     deleteoldrdn : Boolean to indicate wether or not to remove the old RDN value.
 *     serverctrls : List of Server controls.
 *     clientctrls : List of client controls.
 *     msgidp : the msg id return if renamed succeded.
 */

int ldap_rename(LDAP *ld, char *dn, char *newrdn, char *newparent, int deleteoldrdn,
				LDAPControl ** serverctrls, LDAPControl **clientctrls, int *msgidp)
{
	BerElement	*ber;
	int rv;

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 87, "ldap_rename\n"), 0, 0, 0 );

	if ((ber = ldap_build_rename_req(ld, dn, newrdn, newparent, deleteoldrdn, serverctrls)) == NULLBER){
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS)
			rv = LDAP_OTHER;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (rv);
	}
	
	/* send the message */
	rv = send_initial_request( ld, LDAP_REQ_MODRDN, dn, ber );
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


int ldap_rename_s(LDAP *ld, char *dn, char *newrdn, char *newparent, int deleteoldrdn,
				  LDAPControl ** serverctrls, LDAPControl **clientctrls)
{
	int msgid;
	int retcode = LDAP_SUCCESS;
	LDAPMessage *res;
	
	if ((retcode = ldap_rename(ld, dn, newrdn, newparent, deleteoldrdn, serverctrls, clientctrls, &msgid)) != LDAP_SUCCESS)
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
