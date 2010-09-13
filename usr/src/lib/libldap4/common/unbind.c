/*
 *
 * Portions Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  unbind.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#else /* MACOS */
#if defined( DOS ) || defined( _WIN32 )
#include "msdos.h"
#ifdef NCSA
#include "externs.h"
#endif /* NCSA */
#else /* DOS */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#endif /* DOS */
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"


int
ldap_unbind( LDAP *ld )
{
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 259, "ldap_unbind\n"), 0, 0, 0 );

	return( ldap_ld_free( ld, 1 ));
}


int
ldap_ld_free( LDAP *ld, int close )
{
	LDAPMessage	*lm, *next;
	int		err = LDAP_SUCCESS;
	LDAPRequest	*lr, *nextlr;

#ifdef _REENTRANT
        LOCK_LDAP(ld);
#endif
	if ( ld->ld_sb.sb_naddr == 0 ) {
		/* free LDAP structure and outstanding requests/responses */
		for ( lr = ld->ld_requests; lr != NULL; lr = nextlr ) {
			nextlr = lr->lr_next;
			free_request( ld, lr );
		}

		/* free and unbind from all open connections */
		while ( ld->ld_conns != NULL ) {
			free_connection( ld, ld->ld_conns, 1, close );
		}
	} else {
		int	i;

		for ( i = 0; i < ld->ld_sb.sb_naddr; ++i ) {
			free( ld->ld_sb.sb_addrs[ i ] );
		}
		free( ld->ld_sb.sb_addrs );
		free( ld->ld_sb.sb_fromaddr );
#ifdef LDAP_SSL
		if (ld->ld_sb.sb_ssl){
			SSL_delete(ld->ld_sb.sb_ssl);
		}
			ld->ld_sb.sb_ssl = NULL;
			ld->ld_sb.sb_ssl_tls = 0;
#endif
	}

	if (ld->ld_sb.sb_ber.ber_buf) {
		free(ld->ld_sb.sb_ber.ber_buf);
		ld->ld_sb.sb_ber.ber_buf = NULL;
	}

#ifdef _REENTRANT
	LOCK_RESPONSE(ld);
#endif
	for ( lm = ld->ld_responses; lm != NULL; lm = next ) {
		next = lm->lm_next;
		ldap_msgfree( lm );
	}

#ifdef _REENTRANT 
	UNLOCK_RESPONSE(ld);
#endif

#ifndef NO_CACHE
	if ( ld->ld_cache != NULL )
		ldap_destroy_cache( ld );
#endif /* !NO_CACHE */
	if ( ld->ld_error != NULL )
		free( ld->ld_error );
	if ( ld->ld_matched != NULL )
		free( ld->ld_matched );
	if ( ld->ld_host != NULL )
		free( ld->ld_host );
	if ( ld->ld_ufnprefix != NULL )
		free( ld->ld_ufnprefix );
	if ( ld->ld_filtd != NULL )
		ldap_getfilter_free( ld->ld_filtd );
	if ( ld->ld_abandoned != NULL )
		free( ld->ld_abandoned );

	if ( ld->ld_selectinfo != NULL )
		free_select_info( ld->ld_selectinfo );

	if ( ld->ld_defhost != NULL )
		free( ld->ld_defhost );

#ifdef LDAP_SSL
	if (ld->ld_ssl_key != NULL)
		free(ld->ld_ssl_key);
#endif

#undef ld_attrbuffer
	{
		/* free thread-specific attr buffers */
		int i;

		for (i = 0; i < MAX_THREAD_ID; i++)
			if (ld->ld_attrbuffer[i] != NULL) {
				free(ld->ld_attrbuffer[i]);
				ld->ld_attrbuffer[i] = NULL;
			}
	}
/* free ldapv3 stuff */
	if (ld->ld_srvctrls != NULL)
		ldap_controls_free(ld->ld_srvctrls);
	if (ld->ld_cltctrls != NULL)
		ldap_controls_free(ld->ld_cltctrls);
	
#ifdef _REENTRANT
        UNLOCK_LDAP(ld);

	if (ld->ld_lockcount != 0)
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 260, "Mutex problem: ld_lockcount not equal to zero when freeing context\n"), 0, 0, 0 );
#endif

	free( (char *) ld );

	return( err );
}

int
ldap_unbind_s( LDAP *ld )
{
	return( ldap_ld_free( ld, 1 ));
}


int
send_unbind( LDAP *ld, Sockbuf *sb )
{
	BerElement	*ber;

#if defined( SUN ) && defined( _REENTRANT )
        LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 261, "send_unbind\n"), 0, 0, 0 );

	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( ld->ld_errno );
	}

	/* fill it in */
	if ( ber_printf( ber, "{itn}", ++ld->ld_msgid,
	    LDAP_REQ_UNBIND ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( ld->ld_errno );
	}

	/* send the message */
	if ( ber_flush( sb, ber, 1 ) == -1 ) {
		ld->ld_errno = LDAP_SERVER_DOWN;
		ber_free( ber, 1 );
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( ld->ld_errno );
	}

#if defined( SUN ) && defined( _REENTRANT )
        UNLOCK_LDAP(ld);
#endif
	return( LDAP_SUCCESS );
}
