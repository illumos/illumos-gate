/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* io.c - ber general i/o routines */
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
#include <ctype.h>
#include <unistd.h>
#include <poll.h>

#if defined( DOS ) || defined( _WIN32 )
#include "msdos.h"
#endif /* DOS || _WIN32 */

#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#else /* MACOS */
#if defined(NeXT) || defined(VMS)
#include <stdlib.h>
#else /* next || vms */
#include <malloc.h>
#endif /* next || vms */
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef PCNFS
#include <tklib.h>
#endif /* PCNFS */
#endif /* MACOS */

#ifdef SUN
#include <unistd.h>
#endif

#ifndef VMS
#include <memory.h>
#endif
#include <string.h>
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

#ifdef _WIN32
#include <winsock.h>
#include <io.h>
#endif /* _WIN32 */

#ifdef NEEDPROTOS
int ber_realloc(BerElement *ber, unsigned int len);
static int ber_filbuf(Sockbuf *sb, int len);
static int BerRead(Sockbuf *sb, char *buf, int len);
#ifdef PCNFS
static int BerWrite( Sockbuf *sb, char *buf, int len );
#endif /* PCNFS */
#else
int ber_filbuf();
int BerRead();
int ber_realloc();
#endif /* NEEDPROTOS */

#define bergetc( sb, len )    ( sb->sb_ber.ber_end > sb->sb_ber.ber_ptr ? \
			  (unsigned char)*sb->sb_ber.ber_ptr++ : \
			  ber_filbuf( sb, len ))

#ifdef MACOS
/*
 * MacTCP/OpenTransport
 */
#define read( s, b, l ) tcpread( s, 0, (unsigned char *)b, l, NULL )
#define MAX_WRITE	65535
#define BerWrite( sb, b, l )   tcpwrite( sb->sb_sd, (unsigned char *)(b), (l<MAX_WRITE)? l : MAX_WRITE )
#else /* MACOS */
#ifdef DOS
#ifdef PCNFS
/*
 * PCNFS (under DOS)
 */
#define read( s, b, l ) recv( s, b, l, 0 )
#define BerWrite( s, b, l ) send( s->sb_sd, b, (int) l, 0 )
#endif /* PCNFS */
#ifdef NCSA
/*
 * NCSA Telnet TCP/IP stack (under DOS)
 */
#define read( s, b, l ) nread( s, b, l )
#define BerWrite( s, b, l ) netwrite( s->sb_sd, b, l )
#endif /* NCSA */
#ifdef WINSOCK
/*
 * Windows Socket API (under DOS/Windows 3.x)
 */
#define read( s, b, l ) recv( s, b, l, 0 )
#define BerWrite( s, b, l ) send( s->sb_sd, b, l, 0 )
#endif /* WINSOCK */
#else /* DOS */
#ifdef _WIN32
/*
 * 32-bit Windows Socket API (under Windows NT or Windows 95)
 */
#define read( s, b, l )		recv( s, b, l, 0 )
#define BerWrite( s, b, l )	send( s->sb_sd, b, l, 0 )
#else /* _WIN32 */
#ifdef VMS
/*
 * VMS -- each write must be 64K or smaller
 */
#define MAX_WRITE 65535
#define BerWrite( sb, b, l ) write( sb->sb_sd, b, (l<MAX_WRITE)? l : MAX_WRITE)
#else /* VMS */
/*
 * everything else (Unix/BSD 4.3 socket API)
 */
#define BerWrite( sb, b, l )	write( sb->sb_sd, b, l )
#endif /* VMS */
#define udp_read( sb, b, l, al ) recvfrom(sb->sb_sd, (char *)b, l, 0, \
		(struct sockaddr *)sb->sb_fromaddr, \
		(al = sizeof(struct sockaddr), &al))
#define udp_write( sb, b, l ) sendto(sb->sb_sd, (char *)(b), l, 0, \
		(struct sockaddr *)sb->sb_useaddr, sizeof(struct sockaddr))
#endif /* _WIN32 */
#endif /* DOS */
#endif /* MACOS */

#ifndef udp_read
#define udp_read( sb, b, l, al )	CLDAP NOT SUPPORTED
#define udp_write( sb, b, l )		CLDAP NOT SUPPORTED
#endif /* udp_read */

#define EXBUFSIZ	1024

int
ber_filbuf( Sockbuf *sb, int len )
{
	ssize_t	rc;
#ifdef CLDAP
	int	addrlen;
#endif /* CLDAP */

	if ( sb->sb_ber.ber_buf == NULL ) {
		if ( (sb->sb_ber.ber_buf = (char *) malloc( READBUFSIZ )) ==
		    NULL )
			return( -1 );
		sb->sb_ber.ber_ptr = sb->sb_ber.ber_buf;
		sb->sb_ber.ber_end = sb->sb_ber.ber_buf;
	}

	if ( sb->sb_naddr > 0 ) {
#ifdef CLDAP
		rc = udp_read(sb, sb->sb_ber.ber_buf, READBUFSIZ, addrlen );
#ifdef LDAP_DEBUG
		if ( lber_debug ) {
			(void) fprintf( stderr, catgets(slapdcat, 1, 75, "ber_filbuf udp_read %d bytes\n"),
				(int)rc );
			if ( lber_debug > 1 && rc > 0 )
				lber_bprint( sb->sb_ber.ber_buf, (int)rc );
		}
#endif /* LDAP_DEBUG */
#else /* CLDAP */
		rc = -1;
#endif /* CLDAP */
#ifdef LDAP_SSL
	} else if ( sb->sb_ssl != NULL ) {
		rc = SSL_read(sb->sb_ssl,(u_char *)sb->sb_ber.ber_buf,
			     ((sb->sb_options & LBER_NO_READ_AHEAD) &&
			      (len < READBUFSIZ)) ?
			      len : READBUFSIZ  );
#endif /* LDAP_SSL */
	} else {
		int loop=2;
		while (loop>0) {
			--loop;
			rc = read( sb->sb_sd, sb->sb_ber.ber_buf,
					   ((sb->sb_options & LBER_NO_READ_AHEAD) &&
						(len < READBUFSIZ)) ?
					   len : READBUFSIZ );
			/*
			 * if packet not here yet, wait 10 seconds to let it arrive 
			 */
			if ( rc <= 0 && (errno==EWOULDBLOCK || errno==EAGAIN) ) {
				struct pollfd poll_tab[1];
				poll_tab[0].fd = sb->sb_sd;
				poll_tab[0].events = POLLIN;
				poll_tab[0].revents = 0;
				if ( poll(poll_tab, 1, 10000) <= 0) {
					/* nothing received or error, just abandon the read */
					break;
				} /* end if */
			} else {
				break;
			} /* end if */
		} /* end while */
	}

	if ( rc > 0 ) {
		sb->sb_ber.ber_ptr = sb->sb_ber.ber_buf + 1;
		sb->sb_ber.ber_end = sb->sb_ber.ber_buf + rc;
		return( (unsigned char)*sb->sb_ber.ber_buf );
	}

	return( -1 );
}


int
BerRead( Sockbuf *sb, char *buf, int len )
{
	int	c;
	int	nread = 0;

	while ( len > 0 ) {
		if ( (c = bergetc( sb, len )) < 0 ) {
			if ( nread > 0 )
				break;
			return( c );
		}
		*buf++ = (char)c;
		nread++;
		len--;
	}

	return( nread );
}


int
ber_read( BerElement *ber, char *buf, unsigned int len )
{
	unsigned int	actuallen, nleft;

	nleft = (int)(ber->ber_end - ber->ber_ptr);
	actuallen = nleft < len ? nleft : len;

	SAFEMEMCPY( buf, ber->ber_ptr, (size_t)actuallen );

	ber->ber_ptr += actuallen;

	return( (int)actuallen );
}

int
ber_write( BerElement *ber, char *buf, unsigned int len, int nosos )
{
	if ( nosos || ber->ber_sos == NULL ) {
		if ( ber->ber_ptr + len > ber->ber_end ) {
			if ( ber_realloc( ber, len ) != 0 )
				return( -1 );
		}
		(void) SAFEMEMCPY( ber->ber_ptr, buf, (size_t)len );
		ber->ber_ptr += len;
		return( len );
	} else {
		if ( ber->ber_sos->sos_ptr + len > ber->ber_end ) {
			if ( ber_realloc( ber, len ) != 0 )
				return( -1 );
		}
		(void) SAFEMEMCPY( ber->ber_sos->sos_ptr, buf, (size_t)len );
		ber->ber_sos->sos_ptr += len;
		ber->ber_sos->sos_clen += len;
		return( len );
	}
}

int
ber_realloc(BerElement *ber, unsigned int len)
{
	size_t need, have, total;
	Seqorset	*s;
	ssize_t		off;
	char		*oldbuf;

	have = (ber->ber_end - ber->ber_buf) / EXBUFSIZ;
	need = (len < EXBUFSIZ ? 1 : (len + (EXBUFSIZ - 1)) / EXBUFSIZ);
	total = have * EXBUFSIZ + need * EXBUFSIZ;

	oldbuf = ber->ber_buf;

	if ( ber->ber_buf == NULL ) {
		if ( (ber->ber_buf = (char *) malloc( (size_t)total )) == NULL )
			return( -1 );
	} else if ( (ber->ber_buf = (char *) realloc( ber->ber_buf,
	    (size_t)total )) == NULL )
		return( -1 );

	ber->ber_end = ber->ber_buf + total;

	/*
	 * If the stinking thing was moved, we need to go through and
	 * reset all the sos and ber pointers.  Offsets would've been
	 * a better idea... oh well.
	 */

	if ( ber->ber_buf != oldbuf ) {
		ber->ber_ptr = ber->ber_buf + (ber->ber_ptr - oldbuf);

		for ( s = ber->ber_sos; s != NULLSEQORSET; s = s->sos_next ) {
			off = s->sos_first - oldbuf;
			s->sos_first = ber->ber_buf + off;

			off = s->sos_ptr - oldbuf;
			s->sos_ptr = ber->ber_buf + off;
		}
	}

	return( 0 );
}

void
ber_free(BerElement *ber, int freebuf)
{
	if (NULL != ber) {
		if (freebuf && ber->ber_buf != NULL)
			free(ber->ber_buf);
		free((char *)ber);
	}
}

int
ber_flush( Sockbuf *sb, BerElement *ber, int freeit )
{
	ssize_t	nwritten, towrite, rc;

	if ( ber->ber_rwptr == NULL ) {
		ber->ber_rwptr = ber->ber_buf;
	}
	towrite = ber->ber_ptr - ber->ber_rwptr;

#ifdef LDAP_DEBUG
	if ( lber_debug ) {
		(void) fprintf( stderr, catgets(slapdcat, 1, 76, "ber_flush: %1$ld bytes to sd %2$ld%s\n"), towrite,
		    sb->sb_sd, ber->ber_rwptr != ber->ber_buf ? " (re-flush)"
		    : "" );
		if ( lber_debug > 1 )
			lber_bprint( ber->ber_rwptr, towrite );
	}
#endif
#if !defined(MACOS) && !defined(DOS)
	if ( sb->sb_options & (LBER_TO_FILE | LBER_TO_FILE_ONLY) ) {
#ifdef LDAP_SSL
		if (sb->sb_ssl) {
			rc = SSL_write( sb->sb_ssl, (u_char *)ber->ber_buf, towrite );
			if ( rc < 0 ) {
				fprintf( stderr, SSL_strerr(SSL_errno(sb->sb_ssl)));
			}
		} else {
#endif /* LDAP_SSL */
			rc = write( sb->sb_fd, ber->ber_buf, towrite );
			if ( sb->sb_options & LBER_TO_FILE_ONLY ) {
				return( (int)rc );
			}
#ifdef LDAP_SSL
		}
#endif /* LDAP_SSL */
	}
#endif

	nwritten = 0;
	do {
		if (sb->sb_naddr > 0) {
#ifdef CLDAP
			rc = udp_write( sb, ber->ber_buf + nwritten,
			    (size_t)towrite );
#else /* CLDAP */
			rc = -1;
#endif /* CLDAP */
			if ( rc <= 0 )
				return( -1 );
			/* fake error if write was not atomic */
			if (rc < towrite) {
#if !defined( MACOS ) && !defined( DOS )
			    errno = EMSGSIZE;
#endif
			    return( -1 );
			}
		} else {
#ifdef LDAP_SSL
			if (sb->sb_ssl) {
				if ( (rc = SSL_write( sb->sb_ssl, (u_char *)ber->ber_rwptr,
						     (size_t) towrite )) <= 0 ) {
					return( -1 );
				}
			} else
#endif /* LDAP_SSL */
				if ( (rc = BerWrite( sb, ber->ber_rwptr,
						     (size_t) towrite )) <= 0 ) {
					return( -1 );
				}
		}
		towrite -= rc;
		nwritten += rc;
		ber->ber_rwptr += rc;
	} while ( towrite > 0 );

	if ( freeit )
		ber_free( ber, 1 );

	return( 0 );
}

BerElement *
ber_alloc_t( int options )
{
	BerElement	*ber;

	if ( (ber = (BerElement *) calloc( (size_t) 1, sizeof(BerElement) )) == NULLBER )
		return( NULLBER );
	ber->ber_tag = LBER_DEFAULT;
	ber->ber_options = (char) options;

	return( ber );
}

BerElement *
ber_alloc()
{
	return( ber_alloc_t( 0 ) );
}

BerElement *
der_alloc()
{
	return( ber_alloc_t( LBER_USE_DER ) );
}

BerElement *
ber_dup( BerElement *ber )
{
	BerElement	*new;

	if ( (new = ber_alloc()) == NULLBER )
		return( NULLBER );

	*new = *ber;

	return( new );
}

BerElement *ber_init(struct berval *bv) 
{
	BerElement *new;

	if (bv == NULL)
		return (NULLBER);
	
	if ((new = ber_alloc()) == NULLBER)
		return (NULLBER);
	if ((new->ber_buf = (char *)malloc(bv->bv_len + 1)) == NULL){
		free(new);
		return (NULLBER);
	}
	SAFEMEMCPY(new->ber_buf, bv->bv_val, bv->bv_len);
	new->ber_end = new->ber_buf + bv->bv_len;
	new->ber_ptr = new->ber_buf;
	new->ber_len = bv->bv_len;
	return (new);
}

void
ber_zero_init( BerElement *ber, int options )
{
	(void) memset( (char *)ber, '\0', sizeof( BerElement ));
	ber->ber_tag = LBER_DEFAULT;
	ber->ber_options = options;
}


void
ber_reset( BerElement *ber, int was_writing )
{
	if ( was_writing ) {
		ber->ber_end = ber->ber_ptr;
		ber->ber_ptr = ber->ber_buf;
	} else {
		ber->ber_ptr = ber->ber_end;
	}

	ber->ber_rwptr = NULL;
}


#ifdef LDAP_DEBUG

void
ber_dump( BerElement *ber, int inout )
{
	(void) fprintf( stderr, catgets(slapdcat, 1, 77, "ber_dump: buf 0x%1$lx, ptr 0x%2$lx, end 0x%3$lx\n"),
	    ber->ber_buf, ber->ber_ptr, ber->ber_end );
	if ( inout == 1 ) {
		(void) fprintf( stderr, catgets(slapdcat, 1, 78, "          current len %ld, contents:\n"),
		    ber->ber_end - ber->ber_ptr );
		lber_bprint( ber->ber_ptr, ber->ber_end - ber->ber_ptr );
	} else {
		(void) fprintf( stderr, catgets(slapdcat, 1, 78, "          current len %ld, contents:\n"),
		    ber->ber_ptr - ber->ber_buf );
		lber_bprint( ber->ber_buf, ber->ber_ptr - ber->ber_buf );
	}
}

void
ber_sos_dump( Seqorset *sos )
{
	(void) fprintf( stderr, catgets(slapdcat, 1, 79, "*** sos dump ***\n") );
	while ( sos != NULLSEQORSET ) {
		(void) fprintf( stderr, catgets(slapdcat, 1, 80, "ber_sos_dump: clen %1$ld first 0x%2$lx ptr 0x%3$lx\n"),
		    sos->sos_clen, sos->sos_first, sos->sos_ptr );
		(void) fprintf( stderr, catgets(slapdcat, 1, 81, "              current len %ld contents:\n"),
		    sos->sos_ptr - sos->sos_first );
		lber_bprint( sos->sos_first, sos->sos_ptr - sos->sos_first );

		sos = sos->sos_next;
	}
	(void) fprintf( stderr, catgets(slapdcat, 1, 82, "*** end dump ***\n") );
}

#endif

/* return the tag - LBER_DEFAULT returned means trouble */
static unsigned int
get_tag( Sockbuf *sb )
{
	unsigned char	xbyte;
	unsigned int	tag;
	char		*tagp;
	int		i;

	if ( BerRead( sb, (char *) &xbyte, 1 ) != 1 )
		return( LBER_DEFAULT );

	if ( (xbyte & LBER_BIG_TAG_MASK) != LBER_BIG_TAG_MASK )
		return( (unsigned int) xbyte );

	tagp = (char *) &tag;
	tagp[0] = xbyte;
	for ( i = 1; i < sizeof(int); i++ ) {
		if ( BerRead( sb, (char *) &xbyte, 1 ) != 1 )
			return( LBER_DEFAULT );

		tagp[i] = xbyte;

		if ( ! (xbyte & LBER_MORE_TAG_MASK) )
			break;
	}

	/* tag too big! */
	if ( i == sizeof(int) )
		return( LBER_DEFAULT );

	/* want leading, not trailing 0's */
	return( tag >> (sizeof(int) - i - 1) );
}

unsigned int
ber_get_next( Sockbuf *sb, unsigned int *len, BerElement *ber )
{
	unsigned int	tag, netlen, toread;
	unsigned char	lc;
	int		rc;
	int		noctets, diff;

#ifdef LDAP_DEBUG
	if ( lber_debug )
		(void) fprintf( stderr, catgets(slapdcat, 1, 83, "ber_get_next\n") );
#endif

	/*
	 * Any ber element looks like this: tag length contents.
	 * Assuming everything's ok, we return the tag byte (we
	 * can assume a single byte), return the length in len,
	 * and the rest of the undecoded element in buf.
	 *
	 * Assumptions:
	 *	1) small tags (less than 128)
	 *	2) definite lengths
	 *	3) primitive encodings used whenever possible
	 */

	/*
	 * first time through - malloc the buffer, set up ptrs, and
	 * read the tag and the length and as much of the rest as we can
	 */

	if ( ber->ber_rwptr == NULL ) {
		/*
		 * First, we read the tag.
		 */

		if ( (tag = get_tag( sb )) == LBER_DEFAULT ) {
			return( LBER_DEFAULT );
		}
		ber->ber_tag = tag;

		/*
		 * Next, read the length.  The first byte contains the length
		 * of the length.  If bit 8 is set, the length is the int
		 * form, otherwise it's the short form.  We don't allow a
		 * length that's greater than what we can hold in an unsigned
		 * int.
		 */

		*len = netlen = 0;
		if ( BerRead( sb, (char *) &lc, 1 ) != 1 ) {
			return( LBER_DEFAULT );
		}
		if ( lc & 0x80 ) {
			noctets = (lc & 0x7f);
			if ( noctets > sizeof(unsigned int) )
				return( LBER_DEFAULT );
			diff = sizeof(unsigned int) - noctets;
			if ( BerRead( sb, (char *) &netlen + diff, noctets ) !=
			    noctets ) {
				return( LBER_DEFAULT );
			}
			*len = LBER_NTOHL( netlen );
		} else {
			*len = lc;
		}
		ber->ber_len = *len;

		/*
		 * Finally, malloc a buffer for the contents and read it in.
		 * It's this buffer that's passed to all the other ber decoding
		 * routines.
		 */

#if defined( DOS ) && !defined( _WIN32 )
		if ( *len > 65535 ) {	/* DOS can't allocate > 64K */
		    return( LBER_DEFAULT );
		}
#endif /* DOS && !_WIN32 */

		if ( ( sb->sb_options & LBER_MAX_INCOMING_SIZE ) &&
		    *len > sb->sb_max_incoming ) {
			return( LBER_DEFAULT );
		}

		if ( (ber->ber_buf = (char *) malloc( (size_t)*len )) == NULL ) {
			return( LBER_DEFAULT );
		}
		ber->ber_ptr = ber->ber_buf;
		ber->ber_end = ber->ber_buf + *len;
		ber->ber_rwptr = ber->ber_buf;
	}

	toread = (uintptr_t)ber->ber_end - (uintptr_t)ber->ber_rwptr;
	do {
		if ( (rc = BerRead( sb, ber->ber_rwptr, (int)toread )) <= 0 ) {
			return( LBER_DEFAULT );
		}

		toread -= rc;
		ber->ber_rwptr += rc;
	} while ( toread != 0 ); /* DF SUN for LINT */

#ifdef LDAP_DEBUG
	if ( lber_debug ) {
		(void) fprintf( stderr, catgets(slapdcat, 1, 84, "ber_get_next: tag 0x%1$lx len %2$ld contents:\n"),
		    tag, ber->ber_len );
		if ( lber_debug > 1 )
			ber_dump( ber, 1 );
	}
#endif

	*len = ber->ber_len;
	ber->ber_rwptr = NULL;
	return( ber->ber_tag );
}
