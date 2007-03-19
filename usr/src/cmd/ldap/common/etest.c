/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* test.c - lber encoding test program */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#ifdef MACOS
#include <stdlib.h>
#include <unix.h>
#include <fcntl.h>
#include <console.h>
#else /* MACOS */
#include <sys/types.h>
#include <sys/socket.h>
#endif /* MACOS */
#include "lber.h"

static usage( char *name )
{
	fprintf( stderr, "usage: %s fmtstring\n", name );
}

main( int argc, char **argv )
{
	int		i, num, len;
	char		*s, *p;
	Seqorset	*sos = NULLSEQORSET;
	BerElement	*ber;
	Sockbuf		sb;
	extern char	*optarg;

	if ( argc < 2 ) {
		usage( argv[0] );
		exit( 1 );
	}

	bzero( &sb, sizeof(sb) );
	sb.sb_sd = 1;
	sb.sb_ber.ber_buf = NULL;

#ifdef MACOS
	ccommand( &argv );
	cshow( stdout );

       if (( sb.sb_sd = open( "lber-test", O_WRONLY|O_CREAT|O_TRUNC|O_BINARY ))
		< 0 ) {
	    perror( "open" );
	    exit( 1 );
	}
#endif /* MACOS */

	if ( (ber = ber_alloc()) == NULLBER ) {
		perror( "ber_alloc" );
		exit( 1 );
	}

	num = 7;
	if ( ber_printf( ber, "{ti}", 0x1f44, num ) == -1 ) {
		fprintf( stderr, "ber_printf returns -1" );
		exit( 1 );
	}

	if ( ber_flush( &sb, ber, 1 ) == -1 ) {
		perror( "ber_flush" );
		exit( 1 );
	}
#ifdef notdef
	for ( s = argv[1]; *s; s++ ) {
		if ( fgets( buf, sizeof(buf), stdin ) == NULL )
			break;
		if ( (p = strchr( buf, '\n' )) != NULL )
			*p = '\0';

		switch ( *s ) {
		case 'i':	/* int */
		case 'b':	/* boolean */
			i = atoi( buf );
			if ( ber_printf( ber, "i", i ) == -1 ) {
				fprintf( stderr, "ber_printf i\n" );
				exit( 1 );
			}
			break;

		case 'e':	/* enumeration */
			i = va_arg( ap, int );
			rc = ber_put_enum( ber, i, (char)ber->ber_tag );
			break;

		case 'n':	/* null */
			rc = ber_put_null( ber, (char)ber->ber_tag );
			break;

		case 'o':	/* octet string (non-null terminated) */
			s = va_arg( ap, char * );
			len = va_arg( ap, int );
			rc = ber_put_ostring( ber, s, len, (char)ber->ber_tag );
			break;

		case 's':	/* string */
			s = va_arg( ap, char * );
			rc = ber_put_string( ber, s, (char)ber->ber_tag );
			break;

		case 'B':	/* bit string */
			s = va_arg( ap, char * );
			len = va_arg( ap, int );	/* in bits */
			rc = ber_put_bitstring( ber, s, len, (char)ber->ber_tag );
			break;

		case 't':	/* tag for the next element */
			ber->ber_tag = va_arg( ap, int );
			ber->ber_usertag = 1;
			break;

		case 'v':	/* vector of strings */
			if ( (ss = va_arg( ap, char ** )) == NULL )
				break;
			for ( i = 0; ss[i] != NULL; i++ ) {
				if ( (rc = ber_put_string( ber, ss[i],
				    (char)ber->ber_tag )) == -1 )
					break;
			}
			break;

		case 'V':	/* sequences of strings + lengths */
			if ( (bv = va_arg( ap, struct berval ** )) == NULL )
				break;
			for ( i = 0; bv[i] != NULL; i++ ) {
				if ( (rc = ber_put_ostring( ber, bv[i]->bv_val,
				    bv[i]->bv_len, (char)ber->ber_tag )) == -1 )
					break;
			}
			break;

		case '{':	/* begin sequence */
			rc = ber_start_seq( ber, (char)ber->ber_tag );
			break;

		case '}':	/* end sequence */
			rc = ber_put_seqorset( ber );
			break;

		case '[':	/* begin set */
			rc = ber_start_set( ber, (char)ber->ber_tag );
			break;

		case ']':	/* end set */
			rc = ber_put_seqorset( ber );
			break;

		default:
#ifndef NO_USERINTERFACE
			fprintf( stderr, "unknown fmt %c\n", *fmt );
#endif /* NO_USERINTERFACE */
			rc = -1;
			break;
		}
		}
	}

#endif

	return( 0 );
}
