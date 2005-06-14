/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * xdr_rec_subr.c
 */

#include	<rpc/rpc.h>
#include	"rac_private.h"
#include	<sys/param.h>
#include	<sys/syslog.h>
#include	<sys/stropts.h>
#include	<sys/time.h>
#include	<assert.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<errno.h>
#ifndef	NDEBUG
#include	<stdio.h>
#endif
#include	<malloc.h>
#include	<tiuser.h>

/*
 *	This file supports the reading of packets for multiple recipients on a
 *	single virtual circuit.  Demultiplexing is done at a higher level based
 *	on RPC XIDs.  All packets are assumed to be in RPC record marking
 *	format (see the ``RECORD MARKING STANDARD'' in RFC 1057).
 *
 *	We export three functions:
 *
 *		pkt_vc_poll():	assemble a packet by fetching each fragment
 *				header, then the data associated with the
 *				fragment.  Returns (void *)0 when the packet
 *				is not yet complete, and an opaque handle for
 *				use by pkt_vc_read() when a complete packet
 *				has been collected.
 *
 *		pkt_vc_read():	read from a packet (whose representation is
 *				described below) constructed by pkt_vc_poll().
 *
 *		free_pkt():	free a packet constructed by pkt_vc_poll().
 */

#define	FRAGHEADER_SIZE		(sizeof (int))	/* size of XDR frag header */
#define	FH_LASTFRAG		(((uint_t)1) << 31)

/*
 *	A packet consists of one or more RPC record marking fragments.
 *	We represent this structure with a packet header and one or more
 *	fragment headers.
 *
 *	Buffer headers are allocated on each t_rcv() and contain information
 *	about that t_rcv() (such as the amount and location of the data).
 *	They in turn point to buffers, which are shared and reference-counted.
 *
 *				...			...
 *				    ^			^
 *				    |  fh_next		|  bh_next
 *				    |			|
 *				frag header	-->  buf header	-->	buffer
 *				    ^			^
 *				    |  fh_next		|  bh_next
 *				    |			|
 *	packet header	-->	frag header	-->  buf header	-->	buffer
 *		pkt_fragp		fh_bhp		bh_bufp
 *
 */
struct pkthdr {
	struct fraghdr	*pkt_fragp;	/* first fragment in this packet */
	struct pkthdr	*pkt_next;	/* next packet */
};

struct fraghdr {
	bool_t		fh_eof;		/* did EOF occur reading this frag? */
	bool_t		fh_error;
	/* did an error occur reading this frag? */
	int		fh_terrno;	/* copy of t_errno from read error */
	bool_t		fh_morefrags;	/* set from XDR record frag header */
	uint_t		fh_fragsize;	/* set from XDR record frag header */
	uint_t		fh_nbytes;	/* # bytes currently in this frag */
	struct fraghdr	*fh_next;	/* next frag in chain */
	struct bufhdr	*fh_bhp;	/* first buffer in this frag */
};

struct bufhdr {
	uint_t		bh_nbytes;	/* # bytes currently in this buffer */
	char		*bh_begin;	/* first byte of buffer */
	char		*bh_end;	/* next read position */
	struct buf	*bh_bufp;	/* pointer to buffer itself */
	struct bufhdr	*bh_next;	/* next bufhdr in this chain */
};

struct buf {
	uint_t		buf_refcnt;	/* # bufhdrs referencing this buffer */
	uint_t		buf_size;	/* size of this buffer */
	uint_t		buf_bytesused;	/* current number of bytes in use */
	uint_t		buf_bytesfree;	/* current number of bytes available */
	char		*buf_buf;	/* pointer to the actual data area */
};

enum recv_state { BEGINNING_OF_FRAG, NORMAL };
struct readinfo {
	struct pollinfo	*ri_pip;	/* pollinfo pointer for free() */
	struct pkthdr	*ri_php;	/* packet we're currently reading */
	struct fraghdr	*ri_fhp;	/* fragment within packet */
	struct bufhdr	*ri_bhp;	/* buffer header within fragment */
};
struct pollinfo {
	enum recv_state	pi_rs;		/* our receive state */
	struct pkthdr	*pi_curphdr;	/* the packet we're collecting */
	struct fraghdr	*pi_curfhdr;	/* ... its current fragment */
	struct bufhdr	*pi_curbhdr;	/* ... results of last read */
	struct buf	*pi_curbuf;	/* ... and the shared buffer area */
	struct readinfo	pi_ri;		/* information for pkt_vc_read() */
};

static struct pollinfo	*alloc_pollinfo(void);
static struct pkthdr	*alloc_pkthdr(void);
static void		free_pkthdr(struct pkthdr *);
static struct fraghdr	*alloc_fraghdr(void);
static void		free_fraghdr(struct fraghdr *);
static struct bufhdr	*alloc_bufhdr(void);
static void		free_bufhdr(struct bufhdr *);
static struct buf	*alloc_buf(uint_t);
static void		free_buf(struct buf *);
#ifdef	PRINTFS
static void		print_pkt(struct pkthdr *phdr);
#endif

void *
pkt_vc_poll(int fildes, void **pollinfop)
{
	register int	nread;
	register struct bufhdr	*bhdr;
	register struct pollinfo	*pi;
	struct pollfd readfd;
	int	flags;
	uint_t	nreadable;
	uint_t	fragheader;
	static uint_t	bufsiz;
	static uint_t	min_bytesfree;
	static bool_t	firstcall = TRUE;
	int selerr;

	if (firstcall == TRUE) {
		bufsiz = sysconf(_SC_PAGESIZE);	/* a convenient buffer size */
		min_bytesfree = bufsiz / 8;
		/* minimum usable buffer space */
		assert(min_bytesfree != 0);
		firstcall = FALSE;
	}

	if (*pollinfop == (void *)0) {
		pi = alloc_pollinfo();
		if (pi == (struct pollinfo *)0)
			return ((void *)0);
		else
			*pollinfop = (void *)pi;
		pi->pi_rs = BEGINNING_OF_FRAG;
	} else
		pi = (struct pollinfo *)*pollinfop;


	readfd.fd = fildes;
	readfd.events = POLLRDNORM;
	readfd.revents = 0;
	while ((selerr = poll(&readfd, 1, INFTIM)) > 0) {
	if (!(readfd.revents & POLLRDNORM)) {
		errno = EBADF;
		selerr = -1;
		break;
	}
#ifdef	PRINTFS
printf("pkt_vc_poll:  poll returned > 0\n");
#endif
		switch ((int)pi->pi_rs) {
		/*
		 *	Either we've never read a fragment or we've finished
		 *	reading an entire one and are ready to start the
		 *	next one.  We stay in this state until we know we've
		 *	gotten an entire XDR record header.
		 */
		case (int)BEGINNING_OF_FRAG:
			/*
			 *	If there's no packet present (then why did
			 *	select() return positive status?), or if
			 *	the amount of data doesn't exceed the size
			 *	of the XDR record header size, try again later.
			 */
			if (ioctl(fildes, I_NREAD, (size_t)&nreadable) <= 0)
				return ((void *)0);
			if (nreadable < FRAGHEADER_SIZE)
				return ((void *)0);

			/*
			 *	Enough data have arrived to read a fragment
			 *	header.  If this is the first fragment, we
			 *	have to allocate a packet header.
			 */
			if (!pi->pi_curphdr) {
				pi->pi_curphdr = alloc_pkthdr();
				if (!pi->pi_curphdr)
					return ((void *)0);
			}
			/*
			 *	Allocate a fragment header.  If this is not the
			 *	first fragment in this packet, add it on the
			 *	end of the fragment chain.
			 */
			if (!pi->pi_curfhdr) {
#ifdef	PRINTFS
printf("pkt_vc_poll (before alloc_fraghdr):  pi->pi_curphdr 0x%p\n",
	pi->pi_curphdr);
#endif
				pi->pi_curfhdr = alloc_fraghdr();
#ifdef	PRINTFS
printf("pkt_vc_poll (after alloc_fraghdr):  pi->pi_curphdr 0x%p\n",
	pi->pi_curphdr);
fflush(stdout);
#endif
				if (pi->pi_curfhdr)
					pi->pi_curphdr->pkt_fragp =
						pi->pi_curfhdr;
				else
					return ((void *)0);
			} else {
				register struct fraghdr	*fhp;

				assert(pi->pi_curfhdr->fh_fragsize ==
					pi->pi_curfhdr->fh_nbytes);
				assert(pi->pi_curfhdr->fh_morefrags == TRUE);

				fhp = alloc_fraghdr();
				if (fhp) {
					pi->pi_curfhdr->fh_next = fhp;
					pi->pi_curfhdr = fhp;
				} else
					return ((void *)0);
			}

			/*
			 *	We allocate a new buffer when there's less than
			 *	min_bytesfree bytes of data left in the current
			 *	buffer (or, of course, if there is no buffer at
			 *	all).
			 */
			if (!pi->pi_curbuf ||
				(pi->pi_curbuf->buf_bytesfree <
				min_bytesfree)) {
				struct buf	*buf;

				buf = alloc_buf(bufsiz);
				if (buf)
					pi->pi_curbuf = buf;
				else
					return ((void *)0);
			}

			/*
			 *	A buffer header is allocated for each t_rcv()
			 *	we do.
			 */
			bhdr = alloc_bufhdr();
			if (!bhdr)
				return ((void *)0);
			if (pi->pi_curfhdr->fh_bhp == (struct bufhdr *)0)
				pi->pi_curfhdr->fh_bhp = bhdr;
			if (pi->pi_curbhdr) {
				pi->pi_curbhdr->bh_next = bhdr;
				bhdr->bh_begin = bhdr->bh_end =
					pi->pi_curbhdr->bh_end;
			} else {
	/* XXX why are these asserts commented out? */
/*
 *				assert(pi->pi_curbuf->buf_refcnt == 0);
 *				assert(pi->pi_curbuf->buf_bytesused == 0);
 */
				bhdr->bh_begin = bhdr->bh_end =
					pi->pi_curbuf->buf_buf +
					pi->pi_curbuf->buf_bytesused;
			}
			pi->pi_curbhdr = bhdr;
			pi->pi_curbuf->buf_refcnt++;
			bhdr->bh_bufp = pi->pi_curbuf;	/* XXX - unneeded? */

			/*
			 *	We read the fragment into a temporary because
			 *	we want to access it as a longword and data in
			 *	the buffer aren't guaranteed to be properly
			 *	aligned.  Later we'll copy it from the temp to
			 *	the buffer.
			 */
			nread = t_rcv(fildes, (char *)&fragheader,
					FRAGHEADER_SIZE, &flags);
#ifdef	PRINTFS
printf("pkt_vc_poll:  case BEGINNING_OF_FRAG:  t_rcv returned %d\n", nread);
#endif

			fragheader = (int)ntohl(fragheader);

			/*
			 *	Deal with short reads or errors.
			 */
			if (nread == 0) {
				struct pkthdr	*phdr = pi->pi_curphdr;

				pi->pi_curfhdr->fh_eof = TRUE;
				pi->pi_curphdr = (struct pkthdr *)0;
				pi->pi_curfhdr = (struct fraghdr *)0;
				pi->pi_curbhdr = (struct bufhdr *)0;
				pi->pi_curbuf = (struct buf *)0;
				pi->pi_ri.ri_pip = pi;
				pi->pi_ri.ri_php = phdr;
				pi->pi_ri.ri_fhp = (struct fraghdr *)0;
				*pollinfop = (void *)0;
				return ((void *)&pi->pi_ri);
			}
			if (nread == -1) {
				struct pkthdr	*phdr = pi->pi_curphdr;

				if (t_errno == TLOOK)
					switch (t_look(fildes)) {
					case T_DISCONNECT:
						(void) t_rcvdis(fildes, NULL);
						(void) t_snddis(fildes, NULL);
						break;
					case T_ORDREL:
				/* Received orderly release indication */
						(void) t_rcvrel(fildes);
				/* Send orderly release indicator */
						(void) t_sndrel(fildes);
						break;
					default:
						break;
					}
				pi->pi_curfhdr->fh_error = TRUE;
				pi->pi_curfhdr->fh_terrno = t_errno;
				pi->pi_curphdr = (struct pkthdr *)0;
				pi->pi_curfhdr = (struct fraghdr *)0;
				pi->pi_curbhdr = (struct bufhdr *)0;
				pi->pi_curbuf = (struct buf *)0;
				pi->pi_ri.ri_pip = pi;
				pi->pi_ri.ri_php = phdr;
				pi->pi_ri.ri_fhp = (struct fraghdr *)0;
				*pollinfop = (void *)0;
				return ((void *)&pi->pi_ri);
			}
			assert(nread == FRAGHEADER_SIZE);

			pi->pi_curfhdr->fh_eof = 0;
			if (fragheader & FH_LASTFRAG)
				pi->pi_curfhdr->fh_morefrags = FALSE;
			else
				pi->pi_curfhdr->fh_morefrags = TRUE;

			/*
			 *	A fragment header's size doesn't include the
			 *	header itself, so we must manually adjust the
			 *	true size.
			 */
			pi->pi_curfhdr->fh_fragsize =
				(fragheader & ~FH_LASTFRAG) + FRAGHEADER_SIZE;

#ifdef	PRINTFS
printf("pkt_vc_poll:  morefrags %d, frag size %d\n",
	pi->pi_curfhdr->fh_morefrags, pi->pi_curfhdr->fh_fragsize);
#endif

			(void) memcpy(bhdr->bh_begin, (char *)&fragheader,
				FRAGHEADER_SIZE);
			pi->pi_curbuf->buf_bytesused += nread;
			pi->pi_curbuf->buf_bytesfree -= nread;
			bhdr->bh_nbytes += nread;
			bhdr->bh_end += nread;
			pi->pi_curfhdr->fh_nbytes += nread;

			pi->pi_rs = NORMAL;
			break;

		/*
		 *	We've received a complete RPC record header, and now
		 *	know how much more data to expect from this fragment.
		 */
		case (int)NORMAL:
			assert(pi->pi_curphdr);
			assert(pi->pi_curfhdr);
			assert(pi->pi_curfhdr->fh_bhp);
			assert(pi->pi_curbhdr);
			assert(pi->pi_curbuf);

			bhdr = alloc_bufhdr();
			if (!bhdr)
				return ((void *)0);
			pi->pi_curbhdr->bh_next = bhdr;

			if (pi->pi_curbuf->buf_bytesfree < min_bytesfree) {
				struct buf	*buf;

				buf = alloc_buf(bufsiz);
				if (!buf)
					return ((void *)0);
				pi->pi_curbuf = buf;
				bhdr->bh_begin = bhdr->bh_end = buf->buf_buf;
			} else
				bhdr->bh_begin = bhdr->bh_end =
					pi->pi_curbhdr->bh_end;
			pi->pi_curbhdr = bhdr;
			pi->pi_curbuf->buf_refcnt++;
			bhdr->bh_bufp = pi->pi_curbuf;

#ifdef	PRINTFS
printf("pkt_vc_poll:  case NORMAL:  t_rcv(%d, 0x%p, %d, &flags)",
	fildes, bhdr->bh_begin,
	MIN(pi->pi_curfhdr->fh_fragsize - pi->pi_curfhdr->fh_nbytes,
		pi->pi_curbuf->buf_bytesfree));
#endif
			nread = t_rcv(fildes, bhdr->bh_begin,
				MIN(pi->pi_curfhdr->fh_fragsize -
				pi->pi_curfhdr->fh_nbytes,
				pi->pi_curbuf->buf_bytesfree), &flags);
#ifdef	PRINTFS
printf(" returned %d (flags %#x)\n", nread, flags);
#endif
			/*
			 *	Deal with short reads or errors.
			 */
			if (nread == 0) {
				struct pkthdr	*phdr = pi->pi_curphdr;

				pi->pi_curfhdr->fh_eof = TRUE;
				free_bufhdr(bhdr);
				pi->pi_curbuf->buf_refcnt--;
				pi->pi_curphdr = (struct pkthdr *)0;
				pi->pi_curfhdr = (struct fraghdr *)0;
				pi->pi_curbhdr = (struct bufhdr *)0;
				pi->pi_curbuf = (struct buf *)0;
				pi->pi_ri.ri_pip = pi;
				pi->pi_ri.ri_php = phdr;
				pi->pi_ri.ri_fhp = (struct fraghdr *)0;
				*pollinfop = (void *)0;
				return ((void *)&pi->pi_ri);
			}
			if (nread == -1) {
				free_bufhdr(bhdr);
				pi->pi_curbuf->buf_refcnt--;
				return ((void *)0);
			}

			pi->pi_curbuf->buf_bytesused += nread;
			pi->pi_curbuf->buf_bytesfree -= nread;
			bhdr->bh_nbytes += nread;
			bhdr->bh_end += nread;
			pi->pi_curfhdr->fh_nbytes += nread;

			/*
			 *	Got an entire fragment.  See whether we've got
			 *	the entire packet.
			 */
#ifdef	PRINTFS
printf("pkt_vc_poll:  fragsize %u, fh_nbytes %u\n",
	pi->pi_curfhdr->fh_fragsize, pi->pi_curfhdr->fh_nbytes);
#endif
			if (pi->pi_curfhdr->fh_fragsize ==
				pi->pi_curfhdr->fh_nbytes) {
				pi->pi_curbhdr = (struct bufhdr *)0;
				pi->pi_rs = BEGINNING_OF_FRAG;
				if (pi->pi_curfhdr->fh_morefrags == FALSE) {
					struct pkthdr	*phdr = pi->pi_curphdr;

					pi->pi_curphdr = (struct pkthdr *)0;
					pi->pi_curfhdr = (struct fraghdr *)0;
					pi->pi_curbhdr = (struct bufhdr *)0;
					pi->pi_curbuf = (struct buf *)0;
					pi->pi_ri.ri_pip = pi;
					pi->pi_ri.ri_php = phdr;
					pi->pi_ri.ri_fhp = (struct fraghdr *)0;
#ifdef	PRINTFS
print_pkt(phdr);
#endif
					*pollinfop = (void *)0;
					return ((void *)&pi->pi_ri);
				}
			}

			break;
		}
	}
#ifdef	PRINTFS
	if (selerr == -1)
		printf("pkt_vc_poll:  poll returned -1 (errno %d)\n", errno);
	else
		printf("pkt_vc_poll:  poll returned %d\n", selerr);
#endif

	return ((void *)0);
}

int
pkt_vc_read(void **ripp, char *buf, int len)
{
	register int	bytes_read, xferbytes;
	register struct readinfo *rip = *((struct readinfo **)ripp);
	register struct pkthdr *php = rip->ri_php;
	register struct fraghdr	*fhp, *lastfhp;
	register struct bufhdr *bhp;

#ifdef	PRINTFS
printf("pkt_vc_read(pkthdr 0x%p, 0x%p, %d)\n", php, buf, len);
#endif
	if (rip->ri_fhp) {
		fhp = rip->ri_fhp;
		bhp = rip->ri_bhp;
	} else {
		fhp = php->pkt_fragp;
		if (fhp == (struct fraghdr *)0) {
#ifdef	PRINTFS
printf("pkt_vc_read:  no fragments;  returning 0\n");
printf("pkt_vc_read:  ci_readinfo <- 0\n");
#endif
			free_pkt((void *)rip);
			*ripp = (void *)0;
			return (0);
		}
		bhp = (struct bufhdr *)0;
	}
	if (bhp == (struct bufhdr *)0) {
		bhp = fhp->fh_bhp;
		if (bhp == (struct bufhdr *)0) {
#ifdef	PRINTFS
printf("pkt_vc_read:  no buf headers;  returning 0\n");
printf("pkt_vc_read:  ci_readinfo <- 0\n");
#endif
			free_pkt((void *)rip);
			*ripp = (void *)0;
			return (0);
		}
	}

	for (bytes_read = 0; fhp && len;
		fhp = fhp->fh_next,
		bhp = fhp ?  fhp->fh_bhp : (struct bufhdr *)0) {
/*		lastfhp = fhp; */
		rip->ri_fhp = fhp;
		for (; bhp && len; bhp = bhp->bh_next) {
			rip->ri_bhp = bhp;
			if (bhp->bh_nbytes) {
				xferbytes = MIN(len, bhp->bh_nbytes);
#ifdef	PRINTFS
printf("pkt_vc_read:  transferring %d bytes from bhdr 0x%p\n", xferbytes, bhp);
#endif
				(void) memcpy(buf, bhp->bh_begin, xferbytes);
				bhp->bh_nbytes -= xferbytes;
				bhp->bh_begin += xferbytes;
				assert(bhp->bh_begin <= bhp->bh_end);
				bytes_read += xferbytes;
				buf += xferbytes;
				len -= xferbytes;
			}
#ifdef	PRINTFS
			else
	printf("pkt_vc_read:  bhp 0x%p:  bh_nbytes == 0\n", bhp);
#endif
		}
	}
#ifdef	PRINTFS
printf("pkt_vc_read:  bytes_read:  %d, len:  %d\n", bytes_read, len);
#endif

	lastfhp = rip->ri_fhp;
	assert((len == 0) || ((fhp == (struct fraghdr *)0) &&
		(bhp == (struct bufhdr *)0)) || lastfhp->fh_eof ||
		(lastfhp->fh_error == TRUE));
	if (len > 0 && (lastfhp->fh_error == TRUE)) {
#ifdef	PRINTFS
printf("pkt_vc_read:  lastfhp 0x%p, lastfhp->fh_error TRUE,"
	" lastfhp->fh_terrno %d\n", lastfhp, lastfhp->fh_terrno);
#endif
		t_errno = lastfhp->fh_terrno;
#ifdef	PRINTFS
printf("pkt_vc_read:  ci_readinfo <- 0\n");
#endif
		free_pkt((void *)rip);
		*ripp = (void *)0;
		return (-1);
	}

	if (len > 0) {
#ifdef	PRINTFS
printf("pkt_vc_read:  ci_readinfo <- 0\n");
#endif
		free_pkt((void *)rip);
		*ripp = (void *)0;
	}
	return (bytes_read);
}

uint32_t
ri_to_xid(void *ri)
{
	struct pkthdr	*php;
	struct fraghdr	*fhp;
	struct bufhdr	*bhp;
	register uint32_t	xid;

	if (ri) {
		if (((struct readinfo *)ri)->ri_php) {
			php = ((struct readinfo *)ri)->ri_php;
			if (php->pkt_fragp) {
				fhp = php->pkt_fragp;
				if (fhp->fh_bhp) {
					bhp = fhp->fh_bhp;
					assert(((((intptr_t)bhp->bh_begin)
					& (sizeof (uint_t) - 1))) == 0);
					xid = (uint32_t)ntohl (*((uint32_t *)
						(bhp->bh_begin +
						FRAGHEADER_SIZE)));
					return (xid);
				}
			}
		}
	}
	return (0);
}

void
free_pkt(void *rip)
{
	struct pkthdr	*phdr = ((struct readinfo *)rip)->ri_php;
	register struct fraghdr	*fhp, *nextfhp;
	register struct bufhdr	*bhp, *nextbhp;
	register struct buf	*bp;

	assert(phdr != NULL);
	for (fhp = phdr->pkt_fragp; fhp; fhp = nextfhp) {
		nextfhp = fhp->fh_next;		/* save before freeing fhp */
		for (bhp = fhp->fh_bhp; bhp; bhp = nextbhp) {
			nextbhp = bhp->bh_next;	/* save before freeing bhp */
			bp = bhp->bh_bufp;
			if (bp != (struct buf *)0) {
				if (--bp->buf_refcnt == 0) {
					free_buf(bp);
				}
			}
			free_bufhdr(bhp);
		}
		free_fraghdr(fhp);
	}

	assert(((struct readinfo *)rip)->ri_pip != (struct pollinfo *)0);
	free_pollinfo(((struct readinfo *)rip)->ri_pip);

	free_pkthdr(phdr);
}

static struct pollinfo	*
alloc_pollinfo()
{
	return ((struct pollinfo *)calloc(1, sizeof (struct pollinfo)));
}

void
free_pollinfo(void *pi)
{
	(void) memset((char *)pi, 0, sizeof (struct pollinfo));
	(void) free((char *)pi);
}

static struct pkthdr *
alloc_pkthdr()
{
	return ((struct pkthdr *)calloc(1, sizeof (struct pkthdr)));
}

static void
free_pkthdr(struct pkthdr *phdr)
{
	(void) memset((char *)phdr, 0, sizeof (struct pkthdr));
	(void) free((char *)phdr);
}

#ifdef	PRINTFS
static void
print_pkt(struct pkthdr *phdr)
{
	register struct fraghdr	*fhp;
	register struct bufhdr	*bhp;


	printf("phdr:  0x%p", phdr);
	for (fhp = phdr->pkt_fragp; fhp; fhp = fhp->fh_next) {
		printf("\tfhdr:  0x%p\tbhdr:", fhp);
		for (bhp = fhp->fh_bhp; bhp; bhp = bhp->bh_next) {
			printf("\t0x%p (nbytes %d)", bhp, bhp->bh_nbytes);
		}
		printf("\tNULL\n");
	}
}
#endif

static struct fraghdr *
alloc_fraghdr()
{
	return ((struct fraghdr *)calloc(1, sizeof (struct fraghdr)));
}

static void
free_fraghdr(struct fraghdr *fhp)
{
	(void) memset((char *)fhp, 0, sizeof (struct fraghdr));
	(void) free((char *)fhp);
}

static struct bufhdr *
alloc_bufhdr()
{
	return ((struct bufhdr *)calloc(1, sizeof (struct bufhdr)));
}

static void
free_bufhdr(struct bufhdr *bhp)
{
	(void) memset((char *)bhp, 0, sizeof (struct bufhdr));
	(void) free((char *)bhp);
}

static struct buf *
alloc_buf(uint_t size)
{
	register struct buf	*bp;

	bp = (struct buf *)malloc(sizeof (struct buf) + size);
	if (bp) {
		bp->buf_refcnt = 0;
		bp->buf_bytesfree = bp->buf_size = size;
		bp->buf_bytesused = 0;
		bp->buf_buf = ((char *)bp) + sizeof (struct buf);
	}

	return (bp);
}

static void
free_buf(struct buf *bp)
{
	int	size = bp->buf_size;
	(void) memset((char *)bp, 0, sizeof (struct buf) + size);
	(void) free((char *)bp);
}
