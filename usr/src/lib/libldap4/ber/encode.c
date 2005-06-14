/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* encode.c - ber output encoding routines */
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
#ifdef MACOS
#include <stdlib.h>
#include <stdarg.h>
#include "macos.h"
#else /* MACOS */
#if defined(NeXT) || defined(VMS)
#include <stdlib.h>
#else /* next || vms */
#include <malloc.h>
#endif /* next || vms */
#if defined( BC31 ) || defined( _WIN32 ) || defined(__sun)
#include <stdarg.h>
#else /* BC31 || _WIN32 */
#include <varargs.h>
#endif /* BC31 || _WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef PCNFS
#include <tklib.h>
#endif /* PCNFS */
#endif /* MACOS */
#ifndef VMS
#include <memory.h>
#endif
#include <string.h>
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

#if defined( DOS ) || defined( _WIN32 )
#include "msdos.h"
#endif /* DOS */

#ifdef NEEDPROTOS
static int ber_put_len( BerElement *ber, unsigned int len, int nosos );
static int ber_start_seqorset( BerElement *ber, unsigned int tag );
static int ber_put_seqorset( BerElement *ber );
static int ber_put_int_or_enum( BerElement *ber, int num, unsigned int tag );
#endif /* NEEDPROTOS */

extern int ber_realloc(BerElement *ber, unsigned int len);

static int
ber_calc_taglen( unsigned int tag )
{
	int	i;
	int	mask;

	/* find the first non-all-zero byte in the tag */
	for ( i = sizeof(int) - 1; i > 0; i-- ) {
		mask = (0xffL << (i * 8));
		/* not all zero */
		if ( tag & mask )
			break;
	}

	return( i + 1 );
}

static int
ber_put_tag( BerElement	*ber, unsigned int tag, int nosos )
{
	int		taglen;
	unsigned int	ntag;

	taglen = ber_calc_taglen( tag );

	ntag = LBER_HTONL( tag );

	return( ber_write( ber, ((char *) &ntag) + sizeof(int) - taglen,
	    taglen, nosos ) );
}

static int
ber_calc_lenlen( unsigned int len )
{
	/*
	 * short len if it's less than 128 - one byte giving the len,
	 * with bit 8 0.
	 */

	if ( len <= 0x7F )
		return( 1 );

	/*
	 * int len otherwise - one byte with bit 8 set, giving the
	 * length of the length, followed by the length itself.
	 */

	if ( len <= 0xFF )
		return( 2 );
	if ( len <= 0xFFFF )
		return( 3 );
	if ( len <= 0xFFFFFF )
		return( 4 );

	return( 5 );
}

static int
ber_put_len( BerElement *ber, unsigned int len, int nosos )
{
	int		i;
	char		lenlen;
	int		mask;
	unsigned int	netlen;

	/*
	 * short len if it's less than 128 - one byte giving the len,
	 * with bit 8 0.
	 */

	if ( len <= 127 ) {
		netlen = LBER_HTONL( len );
		return( ber_write( ber, (char *) &netlen + sizeof(int) - 1,
		    1, nosos ) );
	}

	/*
	 * int len otherwise - one byte with bit 8 set, giving the
	 * length of the length, followed by the length itself.
	 */

	/* find the first non-all-zero byte */
	for ( i = sizeof(int) - 1; i > 0; i-- ) {
		mask = (0xff << (i * 8));
		/* not all zero */
		if ( len & mask )
			break;
	}
	lenlen = ++i;
	if ( lenlen > 4 )
		return( -1 );
	lenlen |= 0x80;

	/* write the length of the length */
	if ( ber_write( ber, &lenlen, 1, nosos ) != 1 )
		return( -1 );

	/* write the length itself */
	netlen = LBER_HTONL( len );
	if ( ber_write( ber, (char *) &netlen + (sizeof(int) - i), i, nosos )
	    != i )
		return( -1 );

	return( i + 1 );
}

static int
ber_put_int_or_enum( BerElement *ber, int num, unsigned int tag )
{
	int	i, sign, taglen;
	int	len, lenlen;
	int	netnum, mask;

	sign = (num < 0);

	/*
	 * high bit is set - look for first non-all-one byte
	 * high bit is clear - look for first non-all-zero byte
	 */
	for ( i = sizeof(int) - 1; i > 0; i-- ) {
		mask = (0xff << (i * 8));

		if ( sign ) {
			/* not all ones */
			if ( (num & mask) != mask )
				break;
		} else {
			/* not all zero */
			if ( num & mask )
				break;
		}
	}

	/*
	 * we now have the "leading byte".  if the high bit on this
	 * byte matches the sign bit, we need to "back up" a byte.
	 */
	mask = (num & (0x80 << (i * 8)));
	if ( (mask && !sign) || (sign && !mask) )
		i++;

	len = i + 1;

	if ( (taglen = ber_put_tag( ber, tag, 0 )) == -1 )
		return( -1 );

	if ( (lenlen = ber_put_len( ber, len, 0 )) == -1 )
		return( -1 );
	i++;
	netnum = LBER_HTONL( num );
	if ( ber_write( ber, (char *) &netnum + (sizeof(int) - i), i, 0 )
	   != i )
		return( -1 );

	/* length of tag + length + contents */
	return( taglen + lenlen + i );
}

int
ber_put_enum( BerElement *ber, int num, unsigned int tag )
{
	if ( tag == LBER_DEFAULT )
		tag = LBER_ENUMERATED;

	return( ber_put_int_or_enum( ber, num, tag ) );
}

int
ber_put_int( BerElement *ber, int num, unsigned int tag )
{
	if ( tag == LBER_DEFAULT )
		tag = LBER_INTEGER;

	return( ber_put_int_or_enum( ber, num, tag ) );
}

int
ber_put_ostring( BerElement *ber, char *str, unsigned int len,
	unsigned int tag )
{
	int	taglen, lenlen, rc;
#ifdef STR_TRANSLATION
	int	free_str;
#endif /* STR_TRANSLATION */

	if ( tag == LBER_DEFAULT )
		tag = LBER_OCTETSTRING;

	if ( (taglen = ber_put_tag( ber, tag, 0 )) == -1 )
		return( -1 );

#ifdef STR_TRANSLATION
	if ( len > 0 && ( ber->ber_options & LBER_TRANSLATE_STRINGS ) != 0 &&
	    ber->ber_encode_translate_proc != NULL ) {
		if ( (*(ber->ber_encode_translate_proc))( &str, &len, 0 )
		    != 0 ) {
			return( -1 );
		}
		free_str = 1;
	} else {
		free_str = 0;
	}
#endif /* STR_TRANSLATION */

	if ( (lenlen = ber_put_len( ber, len, 0 )) == -1 ||
		ber_write( ber, str, len, 0 ) != len ) {
		rc = -1;
	} else {
		/* return length of tag + length + contents */
		rc = taglen + lenlen + len;
	}

#ifdef STR_TRANSLATION
	if ( free_str ) {
		free( str );
	}
#endif /* STR_TRANSLATION */

	return( rc );
}

int
ber_put_string( BerElement *ber, char *str, unsigned int tag )
{
	return( ber_put_ostring( ber, str, (unsigned int)strlen( str ), tag ));
}

int
ber_put_bitstring( BerElement *ber, char *str,
	unsigned int blen /* in bits */, unsigned int tag )
{
	int		taglen, lenlen, len;
	unsigned char	unusedbits;

	if ( tag == LBER_DEFAULT )
		tag = LBER_BITSTRING;

	if ( (taglen = ber_put_tag( ber, tag, 0 )) == -1 )
		return( -1 );

	len = ( blen + 7 ) / 8;
	unusedbits = len * 8 - blen;
	if ( (lenlen = ber_put_len( ber, len + 1, 0 )) == -1 )
		return( -1 );

	if ( ber_write( ber, (char *)&unusedbits, 1, 0 ) != 1 )
		return( -1 );

	if ( ber_write( ber, str, len, 0 ) != len )
		return( -1 );

	/* return length of tag + length + unused bit count + contents */
	return( taglen + 1 + lenlen + len );
}

int
ber_put_null( BerElement *ber, unsigned int tag )
{
	int	taglen;

	if ( tag == LBER_DEFAULT )
		tag = LBER_NULL;

	if ( (taglen = ber_put_tag( ber, tag, 0 )) == -1 )
		return( -1 );

	if ( ber_put_len( ber, 0, 0 ) != 1 )
		return( -1 );

	return( taglen + 1 );
}

int
ber_put_boolean( BerElement *ber, int boolval, unsigned int tag )
{
	int		taglen;
	unsigned char	trueval = 0xff;
	unsigned char	falseval = 0x00;

	if ( tag == LBER_DEFAULT )
		tag = LBER_BOOLEAN;

	if ( (taglen = ber_put_tag( ber, tag, 0 )) == -1 )
		return( -1 );

	if ( ber_put_len( ber, 1, 0 ) != 1 )
		return( -1 );

	if ( ber_write( ber, (char *)(boolval ? &trueval : &falseval), 1, 0 )
	    != 1 )
		return( -1 );

	return( taglen + 2 );
}

#define FOUR_BYTE_LEN	5

static int
ber_start_seqorset( BerElement *ber, unsigned int tag )
{
	Seqorset	*new;

	if ( (new = (Seqorset *) calloc( sizeof(Seqorset), 1 ))
	    == NULLSEQORSET )
		return( -1 );
	new->sos_ber = ber;
	if ( ber->ber_sos == NULLSEQORSET )
		new->sos_first = ber->ber_ptr;
	else
		new->sos_first = ber->ber_sos->sos_ptr;

	/* Set aside room for a 4 byte length field */
	new->sos_ptr = new->sos_first + ber_calc_taglen( tag ) + FOUR_BYTE_LEN;
	new->sos_tag = tag;

	new->sos_next = ber->ber_sos;
	ber->ber_sos = new;
	if (ber->ber_sos->sos_ptr > ber->ber_end)
		ber_realloc(ber, ber->ber_sos->sos_ptr - ber->ber_end);

	return( 0 );
}

int
ber_start_seq( BerElement *ber, unsigned int tag )
{
	if ( tag == LBER_DEFAULT )
		tag = LBER_SEQUENCE;

	return( ber_start_seqorset( ber, tag ) );
}

int
ber_start_set( BerElement *ber, unsigned int tag )
{
	if ( tag == LBER_DEFAULT )
		tag = LBER_SET;

	return( ber_start_seqorset( ber, tag ) );
}

static int
ber_put_seqorset( BerElement *ber )
{
	unsigned int	len, netlen;
	int		taglen, lenlen;
	unsigned char	ltag = 0x80 + FOUR_BYTE_LEN - 1;
	Seqorset	*next;
	Seqorset	**sos = &ber->ber_sos;

	/*
	 * If this is the toplevel sequence or set, we need to actually
	 * write the stuff out.  Otherwise, it's already been put in
	 * the appropriate buffer and will be written when the toplevel
	 * one is written.  In this case all we need to do is update the
	 * length and tag.
	 */

	len = (*sos)->sos_clen;
	netlen = LBER_HTONL( len );
	/* CONSTCOND */
	if ( sizeof(int) > 4 && len > 0xFFFFFFFF )
		return( -1 );

	if ( ber->ber_options & LBER_USE_DER ) {
		lenlen = ber_calc_lenlen( len );
	} else {
		lenlen = FOUR_BYTE_LEN;
	}

	if ( (next = (*sos)->sos_next) == NULLSEQORSET ) {
		/* write the tag */
		if ( (taglen = ber_put_tag( ber, (*sos)->sos_tag, 1 )) == -1 )
			return( -1 );

		if ( ber->ber_options & LBER_USE_DER ) {
			/* Write the length in the minimum # of octets */
			if ( ber_put_len( ber, len, 1 ) == -1 )
				return( -1 );

			if (lenlen != FOUR_BYTE_LEN) {
				/*
				 * We set aside FOUR_BYTE_LEN bytes for
				 * the length field.  Move the data if
				 * we don't actually need that much
				 */
				(void) SAFEMEMCPY( (*sos)->sos_first + taglen +
				    lenlen, (*sos)->sos_first + taglen +
				    FOUR_BYTE_LEN, len );
			}
		} else {
			/* Fill FOUR_BYTE_LEN bytes for length field */
			/* one byte of length length */
			if ( ber_write( ber, (char *)&ltag, 1, 1 ) != 1 )
				return( -1 );

			/* the length itself */
			if ( ber_write( ber, (char *) &netlen + sizeof(int)
			    - (FOUR_BYTE_LEN - 1), FOUR_BYTE_LEN - 1, 1 )
			    != FOUR_BYTE_LEN - 1 )
				return( -1 );
		}
		/* The ber_ptr is at the set/seq start - move it to the end */
		(*sos)->sos_ber->ber_ptr += len;
	} else {
		unsigned int	ntag;

		/* the tag */
		taglen = ber_calc_taglen( (*sos)->sos_tag );
		ntag = LBER_HTONL( (*sos)->sos_tag );
		(void) SAFEMEMCPY( (*sos)->sos_first, (char *) &ntag +
		    sizeof(int) - taglen, taglen );

		if ( ber->ber_options & LBER_USE_DER ) {
			ltag = (lenlen == 1) ? len : 0x80 + (lenlen - 1);
		}

		/* one byte of length length */
		(void) SAFEMEMCPY( (*sos)->sos_first + 1, &ltag, 1 );

		if ( ber->ber_options & LBER_USE_DER ) {
			if (lenlen > 1) {
				/* Write the length itself */
				(void) SAFEMEMCPY( (*sos)->sos_first + 2,
				    (char *)&netlen + sizeof(unsigned int) -
				    (lenlen - 1),
				    lenlen - 1 );
			}
			if (lenlen != FOUR_BYTE_LEN) {
				/*
				 * We set aside FOUR_BYTE_LEN bytes for
				 * the length field.  Move the data if
				 * we don't actually need that much
				 */
				(void) SAFEMEMCPY( (*sos)->sos_first + taglen +
				    lenlen, (*sos)->sos_first + taglen +
				    FOUR_BYTE_LEN, len );
			}
		} else {
			/* the length itself */
			(void) SAFEMEMCPY( (*sos)->sos_first + taglen + 1,
			    (char *) &netlen + sizeof(int) -
			    (FOUR_BYTE_LEN - 1), FOUR_BYTE_LEN - 1 );
		}

		next->sos_clen += (taglen + lenlen + len);
		next->sos_ptr += (taglen + lenlen + len);
	}

	/* we're done with this seqorset, so free it up */
	free( (char *) (*sos) );
	*sos = next;

	return( taglen + lenlen + len );
}

int
ber_put_seq( BerElement *ber )
{
	return( ber_put_seqorset( ber ) );
}

int
ber_put_set( BerElement *ber )
{
	return( ber_put_seqorset( ber ) );
}

/* VARARGS */
int
ber_printf(
#if defined(MACOS) || defined(_WIN32) || defined(BC31) || defined(__sun)
	BerElement *ber, char *fmt, ... )
#else /* MACOS || _WIN32 || BC31 */
	va_alist )
va_dcl
#endif /* MACOS || _WIN32 || BC31 */
{
	va_list		ap;
#if !defined(MACOS) && !defined(_WIN32) && !defined(BC31) && !defined(__sun)
	BerElement	*ber;
	char		*fmt;
#endif /* !MACOS && !_WIN32 && !BC31 */
	char		*s, **ss;
	struct berval	**bv;
	int		rc, i;
	unsigned int	len;

#if defined(MACOS) || defined(_WIN32) || defined(BC31) || defined(__sun)
	va_start( ap, fmt );
#else /* MACOS || _WIN32 || BC31 */
	va_start( ap );
	ber = va_arg( ap, BerElement * );
	fmt = va_arg( ap, char * );
#endif /* MACOS || _WIN32 || BC31 */

	for ( rc = 0; *fmt && rc != -1; fmt++ ) {
		switch ( *fmt ) {
		case 'b':	/* boolean */
			i = va_arg( ap, int );
			rc = ber_put_boolean( ber, i, ber->ber_tag );
			break;

		case 'i':	/* int */
			i = va_arg( ap, int );
			rc = ber_put_int( ber, i, ber->ber_tag );
			break;

		case 'e':	/* enumeration */
			i = va_arg( ap, int );
			rc = ber_put_enum( ber, i, ber->ber_tag );
			break;

		case 'n':	/* null */
			rc = ber_put_null( ber, ber->ber_tag );
			break;

		case 'o':	/* octet string (non-null terminated) */
			s = va_arg( ap, char * );
			len = va_arg( ap, int );
			rc = ber_put_ostring( ber, s, len, ber->ber_tag );
			break;

		case 's':	/* string */
			s = va_arg( ap, char * );
			rc = ber_put_string( ber, s, ber->ber_tag );
			break;

		case 'B':	/* bit string */
			s = va_arg( ap, char * );
			len = va_arg( ap, int );	/* in bits */
			rc = ber_put_bitstring( ber, s, len, ber->ber_tag );
			break;

		case 't':	/* tag for the next element */
			ber->ber_tag = va_arg( ap, unsigned int );
			ber->ber_usertag = 1;
			break;

		case 'v':	/* vector of strings */
			if ( (ss = va_arg( ap, char ** )) == NULL )
				break;
			for ( i = 0; ss[i] != NULL; i++ ) {
				if ( (rc = ber_put_string( ber, ss[i],
				    ber->ber_tag )) == -1 )
					break;
			}
			break;

		case 'V':	/* sequences of strings + lengths */
			if ( (bv = va_arg( ap, struct berval ** )) == NULL )
				break;
			for ( i = 0; bv[i] != NULL; i++ ) {
				if ( (rc = ber_put_ostring( ber, bv[i]->bv_val,
				    bv[i]->bv_len, ber->ber_tag )) == -1 )
					break;
			}
			break;

		case '{':	/* begin sequence */
			rc = ber_start_seq( ber, ber->ber_tag );
			break;

		case '}':	/* end sequence */
			rc = ber_put_seqorset( ber );
			break;

		case '[':	/* begin set */
			rc = ber_start_set( ber, ber->ber_tag );
			break;

		case ']':	/* end set */
			rc = ber_put_seqorset( ber );
			break;

		default:
#ifndef NO_USERINTERFACE
			(void) fprintf( stderr, catgets(slapdcat, 1, 74, "unknown fmt %c\n"), *fmt );
#endif /* NO_USERINTERFACE */
			rc = -1;
			break;
		}

		if ( ber->ber_usertag == 0 )
			ber->ber_tag = LBER_DEFAULT;
		else
			ber->ber_usertag = 0;
	}

	va_end( ap );

	return( rc );
}
