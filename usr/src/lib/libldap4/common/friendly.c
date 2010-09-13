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
 *  friendly.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1993 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h> /* malloc(),  free() for Solaris */
#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#endif /* MACOS */

#if defined( DOS ) || defined( _WIN32 )
#include <malloc.h>
#include "msdos.h"
#endif /* DOS */

#if !defined( MACOS ) && !defined( DOS )
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

char *
ldap_friendly_name( char *filename, char *uname, FriendlyMap **map )
{
	int	i, entries;
	FILE	*fp;
	char	*s;
	char	buf[BUFSIZ];

	if ( map == NULL ) {
#if !defined( MACOS ) && !defined( DOS )
		errno = EINVAL;
#endif
		return( uname );
	}

	if ( *map == NULL ) {
		if ( (fp = fopen( filename, "r" )) == NULL )
			return( uname );

		entries = 0;
		while ( fgets( buf, sizeof(buf), fp ) != NULL ) {
			if ( buf[0] != '#' )
				entries++;
		}
		rewind( fp );

		if ( (*map = (FriendlyMap *) malloc( (entries + 1) *
		    sizeof(FriendlyMap) )) == NULL ) {
			(void) fclose( fp );
			return( uname );
		}

		i = 0;
		while ( fgets( buf, sizeof(buf), fp ) != NULL && i < entries ) {
			if ( buf[0] == '#' )
				continue;

			if ( (s = strchr( buf, '\n' )) != NULL )
				*s = '\0';

			if ( (s = strchr( buf, '\t' )) == NULL )
				continue;
			*s++ = '\0';

			if ( *s == '"' ) {
				int	esc = 0, found = 0;

				for ( ++s; *s && !found; s++ ) {
					switch ( *s ) {
					case '\\':
						esc = 1;
						break;
					case '"':
						if ( !esc )
							found = 1;
						/* FALL */
					default:
						esc = 0;
						break;
					}
				}
			}

			(*map)[i].f_unfriendly = strdup( buf );
			(*map)[i].f_friendly = strdup( s );
			i++;
		}

		(void) fclose( fp );
		(*map)[i].f_unfriendly = NULL;
	}

	for ( i = 0; (*map)[i].f_unfriendly != NULL; i++ ) {
		if ( strcasecmp( uname, (*map)[i].f_unfriendly ) == 0 )
			return( (*map)[i].f_friendly );
	}
	return( uname );
}


void
ldap_free_friendlymap( FriendlyMap **map )
{
	struct friendly* pF = *map;

	if ( pF == NULL )
		return;

	while ( pF->f_unfriendly )
	{
		free( pF->f_unfriendly );
		free( pF->f_friendly );
		pF++;
	}
	free( *map );
	*map = NULL;
}
