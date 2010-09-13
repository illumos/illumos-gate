/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  modify.c
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

BerElement * ldap_build_modify_req(LDAP *ld, char *dn, LDAPMod ** mods, LDAPControl **serverctrls)
{
	BerElement	*ber;
	int		i, rc;

	/*
	 * A modify request looks like this:
	 *	ModifyRequest ::= SEQUENCE {
	 *		object		DistinguishedName,
	 *		modifications	SEQUENCE OF SEQUENCE {
	 *			operation	ENUMERATED {
	 *				add	(0),
	 *				delete	(1),
	 *				replace	(2)
	 *			},
	 *			modification	SEQUENCE {
	 *				type	AttributeType,
	 *				values	SET OF AttributeValue
	 *			}
	 *		}
	 *	}
	 */
	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		return( NULLBER );
	}
	if ( ber_printf( ber, "{it{s{", ++ld->ld_msgid, LDAP_REQ_MODIFY, dn )
	    == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}

	/* for each modification to be performed... */
	for ( i = 0; mods[i] != NULL; i++ ) {
		if (( mods[i]->mod_op & LDAP_MOD_BVALUES) != 0 ) {
			rc = ber_printf( ber, "{e{s[V]}}",
			    mods[i]->mod_op & ~LDAP_MOD_BVALUES,
			    mods[i]->mod_type, mods[i]->mod_bvalues );
		} else {
			rc = ber_printf( ber, "{e{s[v]}}", mods[i]->mod_op,
			    mods[i]->mod_type, mods[i]->mod_values );
		}

		if ( rc == -1 ) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( NULLBER );
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
 * ldap_modify - initiate an ldap (and X.500) modify operation.  Parameters:
 *
 *	ld		LDAP descriptor
 *	dn		DN of the object to modify
 *	mods		List of modifications to make.  This is null-terminated
 *			array of struct ldapmod's, specifying the modifications
 *			to perform.
 *
 * Example:
 *	LDAPMod	*mods[] = { 
 *			{ LDAP_MOD_ADD, "cn", { "babs jensen", "babs", 0 } },
 *			{ LDAP_MOD_REPLACE, "sn", { "jensen", 0 } },
 *			0
 *		}
 *	msgid = ldap_modify( ld, dn, mods );
 */
int
ldap_modify( LDAP *ld, char *dn, LDAPMod **mods )
{
	BerElement	*ber;
	int rv;

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif	

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 192, "ldap_modify\n"), 0, 0, 0 );

	if ((ber = ldap_build_modify_req(ld, dn, mods, NULL)) == NULLBER){
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (-1);
	}

	/* send the message */
	rv =  send_initial_request( ld, LDAP_REQ_MODIFY, dn, ber );
#ifdef _REENTRANT
        UNLOCK_LDAP(ld);
#endif
	return ( rv );
}

int
ldap_modify_s( LDAP *ld, char *dn, LDAPMod **mods )
{
	int		msgid;
	LDAPMessage	*res;

	if ( (msgid = ldap_modify( ld, dn, mods )) == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, res, 1 ) );
}

/* ldapv3 API extensions */

int ldap_modify_ext(LDAP *ld, char *dn, LDAPMod **mods, 
					LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp)
{
	BerElement	*ber;
	int		i, rc;
	int rv;

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif	

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 192, "ldap_modify\n"), 0, 0, 0 );

	if ((ber = ldap_build_modify_req(ld, dn, mods, serverctrls)) == NULLBER){
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS)
			rv = LDAP_OTHER;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif	
		return (rv);
	}

	/* send the message */
	rv =  send_initial_request( ld, LDAP_REQ_MODIFY, dn, ber );
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


int ldap_modify_ext_s(LDAP *ld, char *dn, LDAPMod **mods, 
					  LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	int msgid;
	int retcode = LDAP_SUCCESS;
	LDAPMessage *res;
	
	if ((retcode = ldap_modify_ext(ld, dn, mods, serverctrls, clientctrls, &msgid)) != LDAP_SUCCESS)
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

