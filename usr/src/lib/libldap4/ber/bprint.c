/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "lber.h"

/*
 * Print arbitrary stuff, for debugging.
 */

#ifdef LDAP_DEBUG

#ifndef NO_USERINTERFACE
#define BPLEN	48

void
lber_bprint( char *data, int len )
{
    static char	hexdig[] = "0123456789abcdef";
    char	out[ BPLEN ];
    int		i = 0;

    (void) memset( out, 0, BPLEN );
    for ( ;; ) {
	if ( len < 1 ) {
	    (void) fprintf( stderr, "\t%s\n", ( i == 0 ) ? catgets(slapdcat, 1, 72, "(end)") : out );
	    break;
	}

#ifndef HEX
	if ( isgraph( (unsigned char)*data )) {
	    out[ i ] = ' ';
	    out[ i+1 ] = *data;
	} else {
#endif
	    out[ i ] = hexdig[ ( *data & 0xf0 ) >> 4 ];
	    out[ i+1 ] = hexdig[ *data & 0x0f ];
#ifndef HEX
	}
#endif
	i += 2;
	len--;
	data++;

	if ( i > BPLEN - 2 ) {
	    (void) fprintf( stderr, "\t%s\n", out );
	    (void) memset( out, 0, BPLEN );
	    i = 0;
	    continue;
	}
	out[ i++ ] = ' ';
    }
}
#else /* NO_USERINTERFACE */
void
lber_bprint( char *data, int len )
{
}
#endif /* NO_USERINTERFACE */

#endif
