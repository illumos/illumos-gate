
/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  abandon.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>

#if !defined( MACOS ) && !defined( DOS )
#include <sys/types.h>
#include <sys/socket.h>
#endif

#if defined( DOS ) || defined( _WIN32 )
#include <malloc.h>
#include "msdos.h"
#endif /* DOS */

#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

#ifdef NEEDPROTOS
static int do_abandon( LDAP *ld, int origid, int msgid, LDAPControl **serverctrls );
#else /* NEEDPROTOS */
static int do_abandon();
#endif /* NEEDPROTOS */

BerElement * ldap_build_abandon_req( LDAP *ld, int msgid, LDAPControl ** serverctrls)
{
	BerElement *ber;
	int rc;
	
	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		rc = -1;
		ld->ld_errno = LDAP_NO_MEMORY;
		return (NULLBER);
	}
#ifdef CLDAP
	if ( ld->ld_sb.sb_naddr > 0 ) {
		rc = ber_printf( ber, "{isti",
						  ++ld->ld_msgid, ld->ld_cldapdn,
						  LDAP_REQ_ABANDON, msgid );
	} else {
#endif /* CLDAP */
		rc = ber_printf( ber, "{iti", ++ld->ld_msgid,
						  LDAP_REQ_ABANDON, msgid );
#ifdef CLDAP
	}
#endif /* CLDAP */

	if ( rc == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return (NULLBER);
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
	
	if ( ber_printf( ber, "}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}
	return (ber);
}


/*
 * ldap_abandon - perform an ldap (and X.500) abandon operation. Parameters:
 *
 *	ld		LDAP descriptor
 *	msgid		The message id of the operation to abandon
 *
 * ldap_abandon returns 0 if everything went ok, -1 otherwise.
 *
 * Example:
 *	ldap_abandon( ld, msgid );
 */
int
ldap_abandon( LDAP *ld, int msgid )
{
	int rv;
	
#ifdef _REENTRANT
	LOCK_LDAP( ld );
#endif	

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 85, "ldap_abandon %d\n"), msgid, 0, 0 );

	rv =  do_abandon( ld, msgid, msgid , NULL);
#ifdef _REENTRANT
	UNLOCK_LDAP( ld );
#endif
	return (rv);
}

/* ldapv3 API extensions */

int ldap_abandon_ext(LDAP *ld, int msgid, LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	int rv;
	
#ifdef _REENTRANT
	LOCK_LDAP( ld );
#endif	

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 85, "ldap_abandon %d\n"), msgid, 0, 0 );

	rv =  do_abandon( ld, msgid, msgid , NULL);
	if (rv == -1) {
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS)
			rv = LDAP_OTHER;
#ifdef _REENTRANT
		UNLOCK_LDAP( ld );
#endif
		return (rv);
	}
#ifdef _REENTRANT
	UNLOCK_LDAP( ld );
#endif
	return (LDAP_SUCCESS);
}


static int
do_abandon( LDAP *ld, int origid, int msgid , LDAPControl **serverctrls)
{
	BerElement	*ber;
	int		i, err, sendabandon;
	Sockbuf		*sb;
#ifdef LDAP_REFERRALS
	LDAPRequest	*lr;
#endif /* LDAP_REFERRALS */

	/*
	 * An abandon request looks like this:
	 *	AbandonRequest ::= MessageID
	 */

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 86, "do_abandon origid %1$d, msgid %2$d\n"),
		origid, msgid, 0 );

	sendabandon = 1;

#ifdef LDAP_REFERRALS
	/* find the request that we are abandoning */
	for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
		if ( lr->lr_msgid == msgid ) {	/* this message */
			break;
		}
		if ( lr->lr_origid == msgid ) {	/* child:  abandon it */
			do_abandon( ld, msgid, lr->lr_msgid , serverctrls);
		}
	}

	if ( lr != NULL ) {
		if ( origid == msgid && lr->lr_parent != NULL ) {
			/* don't let caller abandon child requests! */
			ld->ld_errno = LDAP_PARAM_ERROR;
			return( -1 );
		}
		if ( lr->lr_status != LDAP_REQST_INPROGRESS ) {
			/* no need to send abandon message */
			sendabandon = 0;
		}
	}
#endif /* LDAP_REFERRALS */

	if ( ldap_msgdelete( ld, msgid ) == 0 ) {
		ld->ld_errno = LDAP_SUCCESS;
		return( 0 );
	}

	err = 0;
	if ( sendabandon ) {
		if ((ber = ldap_build_abandon_req(ld, msgid, serverctrls)) == NULLBER){
			return (-1);
		}

#ifdef LDAP_REFERRALS
		if ( lr != NULL ) {
			sb = lr->lr_conn->lconn_sb;
		} else {
			sb = &ld->ld_sb;
		}
#else /* LDAP_REFERRALS */
		sb = &ld->ld_sb;
#endif /* LDAP_REFERRALS */
		if ( ber_flush( sb, ber, 1 ) != 0 ) {
			ld->ld_errno = LDAP_SERVER_DOWN;
			err = -1;
		} else {
			err = 0;
		}
	}
#ifdef LDAP_REFERRALS
	if ( lr != NULL ) {
		if ( sendabandon ) {
			free_connection( ld, lr->lr_conn, 0, 1 );
		}
		if ( origid == msgid ) {
			free_request( ld, lr );
		}
	}
#endif /* LDAP_REFERRALS */


	if ( ld->ld_abandoned == NULL ) {
		if ( (ld->ld_abandoned = (int *) malloc( 2 * sizeof(int) ))
		    == NULL ) {
			ld->ld_errno = LDAP_NO_MEMORY;
			return( -1 );
		}
		i = 0;
	} else {
		for ( i = 0; ld->ld_abandoned[i] != -1; i++ )
			;	/* NULL */
		if ( (ld->ld_abandoned = (int *) realloc( (char *)
		    ld->ld_abandoned, (i + 2) * sizeof(int) )) == NULL ) {
			ld->ld_errno = LDAP_NO_MEMORY;
			return( -1 );
		}
	}
	ld->ld_abandoned[i] = msgid;
	ld->ld_abandoned[i + 1] = -1;

	if ( err != -1 ) {
		ld->ld_errno = LDAP_SUCCESS;
	}
	return( err );
}

