/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* idtest.c - ber decoding test program using isode libraries */
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
#include <psap.h>
#include <quipu/attr.h>

static usage( char *name )
{
	fprintf( stderr, "usage: %s\n", name );
}

main( int argc, char **argv )
{
	PE	pe;
	PS	psin, psout, pserr;

	/* read the pe from standard in */
	if ( (psin = ps_alloc( std_open )) == NULLPS ) {
		perror( "ps_alloc" );
		exit( 1 );
	}
	if ( std_setup( psin, stdin ) == NOTOK ) {
		perror( "std_setup" );
		exit( 1 );
	}
	/* write the pe to standard out */
	if ( (psout = ps_alloc( std_open )) == NULLPS ) {
		perror( "ps_alloc" );
		exit( 1 );
	}
	if ( std_setup( psout, stdout ) == NOTOK ) {
		perror( "std_setup" );
		exit( 1 );
	}
	/* pretty print it to standard error */
	if ( (pserr = ps_alloc( std_open )) == NULLPS ) {
		perror( "ps_alloc" );
		exit( 1 );
	}
	if ( std_setup( pserr, stderr ) == NOTOK ) {
		perror( "std_setup" );
		exit( 1 );
	}

	while ( (pe = ps2pe( psin )) != NULLPE ) {
		pe2pl( pserr, pe );
		pe2ps( psout, pe );
	}

	exit( 0 );
}
