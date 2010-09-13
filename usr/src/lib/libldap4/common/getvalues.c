/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getvalues.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h> /* free() for Solaris */
#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#else /* MACOS */
#if defined( DOS ) || defined( _WIN32 )
#include <malloc.h>
#include "msdos.h"
#else /* DOS */
#include <sys/types.h>
#include <sys/socket.h>
#endif /* DOS */
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

char **
ldap_get_values( LDAP *ld, LDAPMessage *entry, char *target )
{
	BerElement	ber;
	char		attr[LDAP_MAX_ATTR_LEN];
	int		found = 0;
	int		len;
	char		**vals;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 184, "ldap_get_values\n"), 0, 0, 0 );

	ber = *entry->lm_ber;

	/* skip sequence, dn, sequence of, and snag the first attr */
	len = sizeof(attr);
	if ( ber_scanf( &ber, "{x{{s", attr, &len ) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( NULL );
	}

	if ( strcasecmp( target, attr ) == 0 )
		found = 1;

	/* break out on success, return out on error */
	while ( ! found ) {
		len = sizeof(attr);
		if ( ber_scanf( &ber, "x}{s", attr, &len ) == LBER_ERROR ) {
			ld->ld_errno = LDAP_DECODING_ERROR;
			return( NULL );
		}

		if ( strcasecmp( target, attr ) == 0 )
			break;
	}

	/* 
	 * if we get this far, we've found the attribute and are sitting
	 * just before the set of values.
	 */

	if ( ber_scanf( &ber, "[v]", &vals ) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( NULL );
	}

	return( vals );
}

struct berval **
ldap_get_values_len( LDAP *ld, LDAPMessage *entry, char *target )
{
	BerElement	ber;
	char		attr[LDAP_MAX_ATTR_LEN];
	int		found = 0;
	int		len;
	struct berval	**vals;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 185, "ldap_get_values_len\n"), 0, 0, 0 );

	ber = *entry->lm_ber;

	/* skip sequence, dn, sequence of, and snag the first attr */
	len = sizeof(attr);
	if ( ber_scanf( &ber, "{x{{s", attr, &len ) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( NULL );
	}

	if ( strcasecmp( target, attr ) == 0 )
		found = 1;

	/* break out on success, return out on error */
	while ( ! found ) {
		len = sizeof(attr);
		if ( ber_scanf( &ber, "x}{s", attr, &len ) == LBER_ERROR ) {
			ld->ld_errno = LDAP_DECODING_ERROR;
			return( NULL );
		}

		if ( strcasecmp( target, attr ) == 0 )
			break;
	}

	/* 
	 * if we get this far, we've found the attribute and are sitting
	 * just before the set of values.
	 */

	if ( ber_scanf( &ber, "[V]", &vals ) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( NULL );
	}

	return( vals );
}

int
ldap_count_values( char **vals )
{
	int	i;

	if ( vals == NULL )
		return( 0 );

	for ( i = 0; vals[i] != NULL; i++ )
		;	/* NULL */

	return( i );
}

int
ldap_count_values_len( struct berval **vals )
{
	return( ldap_count_values( (char **) vals ) );
}

void
ldap_value_free( char **vals )
{
	int	i;

	if ( vals == NULL )
		return;
	for ( i = 0; vals[i] != NULL; i++ )
		free( vals[i] );
	free( (char *) vals );
}

void
ldap_value_free_len( struct berval **vals )
{
	int	i;

	if ( vals == NULL )
		return;
	for ( i = 0; vals[i] != NULL; i++ ) {
		free( vals[i]->bv_val );
		free( vals[i] );
	}
	free( (char *) vals );
}
