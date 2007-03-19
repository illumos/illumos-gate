/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* dtest.c - lber decoding test program */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include <stdio.h>
#include <string.h>
#ifdef MACOS
#include <stdlib.h>
#include <console.h>
#else /* MACOS */
#include <sys/types.h>
#include <sys/socket.h>
#endif /* MACOS */
#include "lber.h"

static usage( char *name )
{
	fprintf( stderr, "usage: %s fmt\n", name );
}

main( int argc, char **argv )
{
	long		i, i2, num;
	unsigned long	len;
	int		tag;
	char		*str, *s1, *s2;
	BerElement	ber;
	Sockbuf		sb;
	extern char	*optarg;

#ifdef MACOS
	ccommand( &argv );
	cshow( stdout );
#endif /* MACOS */

	bzero( &sb, sizeof(sb) );
	sb.sb_sd = 0;
	sb.sb_ber.ber_buf = NULL;
	if ( (tag = ber_get_next( &sb, &len, &ber )) == -1 ) {
		perror( "ber_get_next" );
		exit( 1 );
	}
	printf( "message has tag 0x%x and length %ld\n", tag, len );

	if ( ber_scanf( &ber, "i", &i ) == -1 ) {
		fprintf( stderr, "ber_scanf returns -1\n" );
		exit( 1 );
	}
	printf( "got int %d\n", i );

	return( 0 );
}
