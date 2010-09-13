/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Because this code is derived from the 4.3BSD compress source:
 *
 * Copyright (c) 1985, 1986 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * James A. Woods, derived from original work by Spencer Thomas
 * and Joseph Orost.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This version is for use with STREAMS in Solaris 2
 *
 * $Id: bsd-comp.c,v 1.20 1996/08/28 06:31:57 paulus Exp $
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <net/ppp_defs.h>

/* Defined for platform-neutral include file */
#define	PACKETPTR		mblk_t *
#include <net/ppp-comp.h>

#ifndef _BIG_ENDIAN
#define	BSD_LITTLE_ENDIAN
#endif

#if DO_BSD_COMPRESS

/*
 * PPP "BSD compress" compression
 *
 *  The differences between this compression and the classic BSD LZW
 *  source are obvious from the requirement that the classic code worked
 *  with files while this handles arbitrarily long streams that
 *  are broken into packets.  They are:
 *
 *	When the code size expands, a block of junk is not emitted by
 *	    the compressor and not expected by the decompressor.
 *
 *	New codes are not necessarily assigned every time an old
 *	    code is output by the compressor.  This is because a packet
 *	    end forces a code to be emitted, but does not imply that a
 *	    new sequence has been seen.
 *
 *	The compression ratio is checked at the first end of a packet
 *	    after the appropriate gap.	Besides simplifying and speeding
 *	    things up, this makes it more likely that the transmitter
 *	    and receiver will agree when the dictionary is cleared when
 *	    compression is not going well.
 */

/*
 * A dictionary for doing BSD compress.
 */
struct bsd_db {
	int		totlen;		/* length of this structure */
	uint_t		hsize;		/* size of the hash table */
	uint32_t	unit;
	uchar_t		hshift;		/* used in hash function */
	uchar_t		n_bits;		/* current bits/code */
	uchar_t		maxbits;
	uchar_t		flags;
	ushort_t	seqno;		/* sequence number of next packet */
	ushort_t	mru;
	uint_t		hdrlen;		/* header length to preallocate */
	uint_t		maxmaxcode;	/* largest valid code */
	uint_t		max_ent;	/* largest code in use */
	uint_t		in_count;	/* uncompressed bytes, aged */
	uint_t		bytes_out;	/* compressed bytes, aged */
	uint_t		ratio;		/* recent compression ratio */
	uint_t		checkpoint;	/* when to next check the ratio */
	uint_t		clear_count;	/* times dictionary cleared */
	uint_t		incomp_count;	/* incompressible packets */
	uint_t		incomp_bytes;	/* incompressible bytes */
	uint_t		uncomp_count;	/* uncompressed packets */
	uint_t		uncomp_bytes;	/* uncompressed bytes */
	uint_t		comp_count;	/* compressed packets */
	uint_t		comp_bytes;	/* compressed bytes */
	ushort_t	*lens;		/* array of lengths of codes */
	struct bsd_dict {
	union {				/* hash value */
		uint32_t	fcode;
		struct {
#ifdef BSD_LITTLE_ENDIAN
			ushort_t	prefix;	/* preceding code */
			uchar_t		suffix;	/* last character of new code */
			uchar_t		pad;
#else
			uchar_t		pad;
			uchar_t		suffix;	/* last character of new code */
			ushort_t	prefix;	/* preceding code */
#endif
		} hs;
	} f;
		ushort_t	codem1;		/* output of hash table -1 */
		ushort_t	cptr;		/* map code to hash entry */
	} dict[1];
};

#define	BSD_OVHD	2		/* BSD compress overhead/packet */
#define	BSD_INIT_BITS	BSD_MIN_BITS

/* db->flags values */
#define	DS_DEBUG	0x01
#define	DS_TESTIN	0x02
#define	DS_TESTOUT	0x04
#define	DS_INITDONE	0x08

static void	*bsd_comp_alloc(uchar_t *options, int opt_len);
static void	*bsd_decomp_alloc(uchar_t *options, int opt_len);
static void	bsd_free(void *state);
static int	bsd_comp_init(void *state, uchar_t *options, int opt_len,
				int unit, int hdrlen, int debug);
static int	bsd_decomp_init(void *state, uchar_t *options, int opt_len,
				int unit, int hdrlen, int mru, int debug);
static int	bsd_compress(void *state, mblk_t **mret,
				mblk_t *mp, int slen, int maxolen);
static int	bsd_incomp(void *state, mblk_t *dmsg);
static int	bsd_decompress(void *state, mblk_t **dmpp);
static void	bsd_reset(void *state);
static void	bsd_comp_stats(void *state, struct compstat *stats);
static int	bsd_set_effort(void *xarg, void *rarg, int effortlevel);

/*
 * Procedures exported to ppp_comp.c.
 */
struct compressor ppp_bsd_compress = {
	CI_BSD_COMPRESS,		/* compress_proto */
	bsd_comp_alloc,			/* comp_alloc */
	bsd_free,			/* comp_free */
	bsd_comp_init,			/* comp_init */
	bsd_reset,			/* comp_reset */
	bsd_compress,			/* compress */
	bsd_comp_stats,			/* comp_stat */
	bsd_decomp_alloc,		/* decomp_alloc */
	bsd_free,			/* decomp_free */
	bsd_decomp_init,		/* decomp_init */
	bsd_reset,			/* decomp_reset */
	bsd_decompress,			/* decompress */
	bsd_incomp,			/* incomp */
	bsd_comp_stats,			/* decomp_stat */
	bsd_set_effort,			/* set_effort */
};

/*
 * the next two codes should not be changed lightly, as they must not
 * lie within the contiguous general code space.
 */
#define	CLEAR		256		/* table clear output code */
#define	FIRST		257		/* first free entry */
#define	LAST		255

#define	MAXCODE(b)	((1 << (b)) - 1)
#define	BADCODEM1	MAXCODE(BSD_MAX_BITS)

#define	BSD_HASH(prefix, suffix, hshift)	\
	((((uint32_t)(suffix)) << (hshift)) ^ (uint32_t)(prefix))

#define	BSD_KEY(prefix, suffix)		\
	((((uint32_t)(suffix)) << 16) + (uint32_t)(prefix))

#define	CHECK_GAP	10000		/* Ratio check interval */

#define	RATIO_SCALE_LOG	8
#define	RATIO_SCALE	(1 << RATIO_SCALE_LOG)
#define	RATIO_MAX	(0x7fffffff >> RATIO_SCALE_LOG)

#define	DECOMP_CHUNK	256

/*
 * bsd_clear()
 *
 * clear the dictionary
 */
static void
bsd_clear(struct bsd_db *db)
{
	db->clear_count++;
	db->max_ent = FIRST-1;
	db->n_bits = BSD_INIT_BITS;
	db->ratio = 0;
	db->bytes_out = 0;
	db->in_count = 0;
	db->checkpoint = CHECK_GAP;
}

/*
 * bsd_check()
 *
 * If the dictionary is full, then see if it is time to reset it.
 *
 * Compute the compression ratio using fixed-point arithmetic
 * with 8 fractional bits.
 *
 * Since we have an infinite stream instead of a single file,
 * watch only the local compression ratio.
 *
 * Since both peers must reset the dictionary at the same time even in
 * the absence of CLEAR codes (while packets are incompressible), they
 * must compute the same ratio.
 */
static int				/* 1=output CLEAR */
bsd_check(struct bsd_db *db)
{
	uint_t	new_ratio;

	if (db->in_count >= db->checkpoint) {

		/*
		 * age the ratio by limiting the size of the counts
		 */
		if (db->in_count >= RATIO_MAX || db->bytes_out >= RATIO_MAX) {
			db->in_count -= db->in_count/4;
			db->bytes_out -= db->bytes_out/4;
		}

		db->checkpoint = db->in_count + CHECK_GAP;

		if (db->max_ent >= db->maxmaxcode) {

			/*
			 * Reset the dictionary only if the ratio is worse,
			 * or if it looks as if it has been poisoned
			 * by incompressible data.
			 *
			 * This does not overflow, because
			 * db->in_count <= RATIO_MAX.
			 */
			new_ratio = db->in_count << RATIO_SCALE_LOG;

			if (db->bytes_out != 0) {
				new_ratio /= db->bytes_out;
			}

			if (new_ratio < db->ratio ||
			    new_ratio < 1 * RATIO_SCALE) {
				bsd_clear(db);
				return (1);
			}

			db->ratio = new_ratio;
		}
	}

	return (0);
}

/*
 * bsd_comp_stats()
 *
 * Return statistics.
 */
static void
bsd_comp_stats(void *state, struct compstat *stats)
{
	struct bsd_db	*db = (struct bsd_db *)state;
	uint_t		out;

	stats->unc_bytes = db->uncomp_bytes;
	stats->unc_packets = db->uncomp_count;
	stats->comp_bytes = db->comp_bytes;
	stats->comp_packets = db->comp_count;
	stats->inc_bytes = db->incomp_bytes;
	stats->inc_packets = db->incomp_count;
	stats->ratio = db->in_count;

	out = db->bytes_out;

	if (stats->ratio <= 0x7fffff) {
		stats->ratio <<= 8;
	} else {
		out >>= 8;
	}

	if (out != 0) {
		stats->ratio /= out;
	}
}

/*
 * bsd_reset()
 *
 * Reset state, as on a CCP ResetReq.
 */
static void
bsd_reset(void *state)
{
	struct bsd_db	*db = (struct bsd_db *)state;

	if (db->hsize != 0) {
		db->seqno = 0;

		bsd_clear(db);

		db->clear_count = 0;
	}
}

/*
 * bsd_alloc()
 *
 * Allocate space for a (de) compressor.
 */
static void *
bsd_alloc(uchar_t *options, int opt_len, int decomp)
{
	int		bits;
	uint_t		newlen;
	uint_t		hsize;
	uint_t		hshift;
	uint_t		maxmaxcode;
	uint_t		ilen;
	struct bsd_db	*db;

	if (opt_len != 3 ||
	    options[0] != CI_BSD_COMPRESS ||
	    options[1] != 3 ||
	    BSD_VERSION(options[2]) != BSD_CURRENT_VERSION) {

		return (NULL);
	}

	bits = BSD_NBITS(options[2]);

	switch (bits) {

	case 9:				/* needs 82152 for both directions */
	case 10:			/* needs 84144 */
	case 11:			/* needs 88240 */
	case 12:			/* needs 96432 */

		hsize = 5003;
		hshift = 4;

		break;

	case 13:			/* needs 176784 */

		hsize = 9001;
		hshift = 5;

		break;

	case 14:			/* needs 353744 */

		hsize = 18013;
		hshift = 6;

		break;

	case 15:			/* needs 691440 */

		hsize = 35023;
		hshift = 7;

		break;

	/* XXX: this falls thru - it was originally commented */
	case 16:			/* needs 1366160--far too much, */
		/* hsize = 69001; */	/* and 69001 is too big for cptr */
		/* hshift = 8; */	/* in struct bsd_db */
		/* break; */

	default:

		return (NULL);
	}

	maxmaxcode = MAXCODE(bits);
	ilen = newlen = sizeof (*db) + (hsize-1) * sizeof (db->dict[0]);
	if (decomp)
		newlen += (maxmaxcode+1) * sizeof (db->lens[0]);
	db = (struct bsd_db *)kmem_alloc(newlen, KM_NOSLEEP);
	if (!db) {
		return (NULL);
	}

	bzero(db, sizeof (*db) - sizeof (db->dict));

	if (!decomp) {
		db->lens = NULL;
	} else {
		db->lens = (ushort_t *)((caddr_t)db + ilen);
	}

	db->totlen = newlen;
	db->hsize = hsize;
	db->hshift = (uchar_t)hshift;
	db->maxmaxcode = maxmaxcode;
	db->maxbits = (uchar_t)bits;

	return ((void *)db);
}

/*
 * bsd_free()
 */
static void
bsd_free(void *state)
{
	struct bsd_db	*db = (struct bsd_db *)state;

	if (db->hsize != 0) {
		/* XXX feeble attempt to catch bad references. */
		db->hsize = 0;

		kmem_free(db, db->totlen);
	}
}

/*
 * bsd_comp_alloc()
 */
static void *
bsd_comp_alloc(uchar_t *options, int opt_len)
{
	return (bsd_alloc(options, opt_len, 0));
}

/*
 * bsd_decomp_alloc()
 */
static void *
bsd_decomp_alloc(uchar_t *options, int opt_len)
{
	return (bsd_alloc(options, opt_len, 1));
}

/*
 * bsd_init()
 *
 * Initialize the database.
 */
static int
bsd_init(struct bsd_db *db, uchar_t *options, int opt_len, int unit,
	int hdrlen, int mru, int debug, int decomp)
{
	int	i;

	if (db->hsize == 0 || opt_len < CILEN_BSD_COMPRESS ||
	    options[0] != CI_BSD_COMPRESS ||
	    options[1] != CILEN_BSD_COMPRESS ||
	    BSD_VERSION(options[2]) != BSD_CURRENT_VERSION ||
	    BSD_NBITS(options[2]) != db->maxbits ||
	    decomp && db->lens == NULL) {

		return (0);
	}

	if (decomp) {
		i = LAST + 1;

		while (i != 0) {
			db->lens[--i] = 1;
		}
	}

	i = db->hsize;

	while (i != 0) {
		db->dict[--i].codem1 = BADCODEM1;
		db->dict[i].cptr = 0;
	}

	db->unit = unit;
	db->hdrlen = hdrlen;
	db->mru = (ushort_t)mru;

	if (debug) {
		db->flags |= DS_DEBUG;
	}

	bsd_reset(db);

	db->flags |= DS_INITDONE;

	return (1);
}

/*
 * bsd_comp_init()
 */
static int
bsd_comp_init(void *state, uchar_t *options, int opt_len, int unit, int hdrlen,
	int debug)
{
	return (bsd_init((struct bsd_db *)state, options, opt_len,
	    unit, hdrlen, 0, debug, 0));
}

/*
 * bsd_decomp_init()
 */
static int
bsd_decomp_init(void *state, uchar_t *options, int opt_len, int unit,
	int hdrlen, int mru, int debug)
{
	return (bsd_init((struct bsd_db *)state, options, opt_len,
	    unit, hdrlen, mru, debug, 1));
}


/*
 * bsd_compress()
 *
 * compress a packet
 *	One change from the BSD compress command is that when the
 *	code size expands, we do not output a bunch of padding.
 *
 * N.B. at present, we ignore the hdrlen specified in the comp_init call.
 */
static int			/* new slen */
bsd_compress(void *state, mblk_t **mretp, mblk_t *mp, int slen,	int maxolen)
{
	struct bsd_db	*db = (struct bsd_db *)state;
	int		hshift = db->hshift;
	uint_t		max_ent = db->max_ent;
	uint_t		n_bits = db->n_bits;
	uint_t		bitno = 32;
	uint32_t	accm = 0;
	uint32_t	fcode;
	struct bsd_dict	*dictp;
	uchar_t		c;
	int		hval;
	int		disp;
	int		ent;
	int		ilen = slen - (PPP_HDRLEN-1);
	mblk_t		*mret;
	uchar_t		*rptr, *rmax;
	uchar_t		*wptr;
	uchar_t		*cp_end;
	int		olen;
	mblk_t		*m;
	mblk_t		**mnp;
#if defined(lint) || defined(_lint)
	uchar_t		hdlcaddr, hdlcctl;
#else
	int		hdlcaddr, hdlcctl;
#endif

	ASSERT(db->flags & DS_INITDONE);

#define	PUTBYTE(v) {						\
	if (wptr) {						\
		*wptr++ = (v);					\
		if (wptr >= cp_end) {				\
			m->b_wptr = wptr;			\
			m = m->b_cont;				\
			if (m) {				\
				wptr = m->b_wptr;		\
				cp_end = m->b_datap->db_lim;	\
			} else {				\
				wptr = NULL;			\
			}					\
		}						\
	}							\
	++olen;							\
}

#define	OUTPUT(ent) {						\
	bitno -= n_bits;					\
	accm |= ((ent) << bitno);				\
	do {							\
		PUTBYTE(accm >> 24);				\
		accm <<= 8;					\
		bitno += 8;					\
	} while (bitno <= 24);					\
}

#define	ADJRPTR() {						\
	if (rptr != NULL) {					\
		while (rptr >= rmax) {				\
			if ((mp = mp->b_cont) == NULL) {	\
				rptr = NULL;			\
				break;				\
			}					\
			rptr = mp->b_rptr;			\
			rmax = mp->b_wptr;			\
		}						\
	}							\
}

#define	GETBYTE(v) {						\
	if (rptr != NULL) {					\
		(v) = *rptr++;					\
	}							\
}

	if (db->hsize == 0)
		return (-1);

	/*
	 * First get the protocol and check that we're
	 * interested in this packet.
	 */
	*mretp = NULL;
	rptr = mp->b_rptr;
	rmax = mp->b_wptr;

	/* We CANNOT do a pullup here; it's not our buffer to toy with. */
	ADJRPTR();
	GETBYTE(hdlcaddr);
	ADJRPTR();
	GETBYTE(hdlcctl);
	ADJRPTR();
	GETBYTE(ent);
	ADJRPTR();

	/*
	 * Per RFC 1977, the protocol field must be compressed using a
	 * PFC-like procedure.  Also, all protocols between 0000-3FFF
	 * except the two compression protocols must be LZ compressed.
	 */
	if (ent == 0) {
		GETBYTE(ent);
		if (rptr == NULL || ent == PPP_COMP || ent == PPP_COMPFRAG)
			return (0);
	} else {
		if (ent > 0x3F)
			return (0);
		ilen++;
	}

	/*
	 * Don't generate compressed packets that are larger than the
	 * source (uncompressed) packet.
	 */
	if (maxolen > slen) {
		maxolen = slen;
	}
	if (maxolen < 6)
		maxolen = 6;

	/*
	 * Allocate enough message blocks to give maxolen total space
	 */
	mnp = &mret;
	for (olen = maxolen; olen > 0; ) {

		m = allocb((olen < 4096? olen: 4096), BPRI_MED);

		*mnp = m;
		if (m == NULL) {
			if (mnp == &mret)
				return (0);
			/* We allocated some; hope for the best. */
			break;
		}

		mnp = &m->b_cont;
		olen -= m->b_datap->db_lim - m->b_wptr;
	}

	*mnp = NULL;

	m = mret;
	wptr = m->b_wptr;
	cp_end = m->b_datap->db_lim;

	olen = 0;

	/*
	 * Copy the PPP header over, changing the protocol,
	 * and install the 2-byte sequence number
	 */
	*wptr++ = hdlcaddr;
	*wptr++ = hdlcctl;
	*wptr++ = PPP_COMP>>8;		/* change the protocol */
	*wptr++ = PPP_COMP;
	*wptr++ = db->seqno >> 8;
	*wptr++ = db->seqno;

#ifdef DEBUG
	/*
	 * If testing output, just garbling the sequence here does the
	 * trick.
	 */
	if ((db->flags & DS_TESTOUT) && (db->seqno % 100) == 50)
		wptr[-1] ^= 0xAA;
#endif

	++db->seqno;

	for (;;) {
		ADJRPTR();
		if (rptr == NULL)
			break;

		GETBYTE(c);

		fcode = BSD_KEY(ent, c);
		hval = BSD_HASH(ent, c, hshift);

		dictp = &db->dict[hval];

		/*
		 * Validate and then check the entry
		 */
		if (dictp->codem1 >= max_ent) {
			goto nomatch;
		}

		if (dictp->f.fcode == fcode) {
			ent = dictp->codem1+1;

			/*
			 * found (prefix,suffix)
			 */
			continue;
		}

		/*
		 * continue probing until a match or invalid entry
		 */
		disp = (hval == 0) ? 1 : hval;

		do {
			hval += disp;
			if (hval >= db->hsize) {
				hval -= db->hsize;
				if (hval >= db->hsize) {
					if (db->flags & DS_DEBUG) {
						cmn_err(CE_CONT,
						    "bsd_comp%d: internal "
						    "error\n",
						    db->unit);
					}
					/* Caller will free it all */
					return (-1);
				}
			}

			dictp = &db->dict[hval];

			if (dictp->codem1 >= max_ent) {
				goto nomatch;
			}
		} while (dictp->f.fcode != fcode);

		/*
		 * finally found (prefix,suffix)
		 */
		ent = dictp->codem1 + 1;

		continue;

nomatch:
		/*
		 * output the prefix
		 */
		OUTPUT(ent);

		/*
		 * code -> hashtable
		 */
		if (max_ent < db->maxmaxcode) {
			struct bsd_dict *dictp2;

			/*
			 * expand code size if needed
			 */
			if (max_ent >= MAXCODE(n_bits)) {
				db->n_bits = ++n_bits;
			}

			/*
			 * Invalidate old hash table entry using
			 * this code, and then take it over.
			 */
			dictp2 = &db->dict[max_ent+1];

			if (db->dict[dictp2->cptr].codem1 == max_ent) {
				db->dict[dictp2->cptr].codem1 = BADCODEM1;
			}

			dictp2->cptr = (ushort_t)hval;
			dictp->codem1 = max_ent;
			dictp->f.fcode = fcode;

			db->max_ent = ++max_ent;
		}

		ent = c;
	}

	/*
	 * output the last code
	 */
	OUTPUT(ent);

	olen += (32-bitno+7)/8;	/* count complete bytes */

	db->bytes_out += olen;
	db->in_count += ilen;

	if (bsd_check(db)) {
		OUTPUT(CLEAR);		/* do not count the CLEAR */
	}

	/*
	 * Pad dribble bits of last code with ones.
	 * Do not emit a completely useless byte of ones.
	 */
	if (bitno != 32) {
		PUTBYTE((accm | (0xff << (bitno - 8))) >> 24);
	}

	/*
	 * Increase code size if we would have without the packet
	 * boundary and as the decompressor will.
	 */
	if (max_ent >= MAXCODE(n_bits) && max_ent < db->maxmaxcode) {
		db->n_bits++;
	}

	db->uncomp_bytes += ilen;
	++db->uncomp_count;

	if (wptr == NULL || olen + PPP_HDRLEN + BSD_OVHD >= maxolen) {
		/*
		 * throw away the compressed stuff if it is longer
		 * than uncompressed
		 */
		freemsg(mret);

		mret = NULL;

		++db->incomp_count;
		db->incomp_bytes += ilen;

	} else {

		m->b_wptr = wptr;
		if (m->b_cont) {
			freemsg(m->b_cont);
			m->b_cont = NULL;
		}

		++db->comp_count;
		db->comp_bytes += olen + BSD_OVHD;
	}

	*mretp = mret;

	return (olen + PPP_HDRLEN + BSD_OVHD);
#undef OUTPUT
#undef PUTBYTE
}


/*
 * bsd_incomp()
 *
 * Update the "BSD Compress" dictionary on the receiver for
 * incompressible data by pretending to compress the incoming data.
 */
static int
bsd_incomp(void *state, mblk_t *mp)
{
	struct bsd_db	*db = (struct bsd_db *)state;
	uint_t		hshift = db->hshift;
	uint_t		max_ent = db->max_ent;
	uint_t		n_bits = db->n_bits;
	struct bsd_dict	*dictp;
	uint32_t	fcode;
	uchar_t		c;
	long		hval;
	long		disp;
	int		slen;
	int		ilen;
	uint_t		bitno = 7;
	uchar_t		*rptr, *rmax;
	uint_t		ent;

	ASSERT(db->flags & DS_INITDONE);

	if (db->hsize == 0)
		return (-1);

	rptr = mp->b_rptr;
	rmax = mp->b_wptr;
	ADJRPTR();
	GETBYTE(ent);	/* address */
	ADJRPTR();
	GETBYTE(ent);	/* control */
	ADJRPTR();
	GETBYTE(ent);	/* protocol high */
	ADJRPTR();

	/*
	 * Per RFC 1977, the protocol field must be compressed using a
	 * PFC-like procedure.  Also, all protocols between 0000-3FFF
	 * except the two compression protocols must be LZ compressed.
	 */
	ilen = 1;			/* count the protocol as 1 byte */
	if (ent == 0) {
		GETBYTE(ent);
		if (rptr == NULL || ent == PPP_COMP || ent == PPP_COMPFRAG)
			return (0);
	} else {
		if (ent > 0x3F)
			return (0);
		ilen++;
	}

	db->seqno++;

	for (;;) {

		slen = mp->b_wptr - rptr;
		if (slen <= 0) {
			mp = mp->b_cont;
			if (!mp) {
				break;
			}

			rptr = mp->b_rptr;
			continue;	/* skip zero-length buffers */
		}

		ilen += slen;

		do {
			c = *rptr++;

			fcode = BSD_KEY(ent, c);
			hval = BSD_HASH(ent, c, hshift);

			dictp = &db->dict[hval];

			/*
			 * validate and then check the entry
			 */
			if (dictp->codem1 >= max_ent) {
				goto nomatch;
			}

			if (dictp->f.fcode == fcode) {
				ent = dictp->codem1 + 1;
				continue;   /* found (prefix,suffix) */
			}

			/*
			 * continue probing until a match or invalid entry
			 */
			disp = (hval == 0) ? 1 : hval;
			do {
				hval += disp;
				if (hval >= db->hsize) {
					hval -= db->hsize;
					if (hval >= db->hsize) {
						if (db->flags & DS_DEBUG) {
							cmn_err(CE_CONT,
							    "bsd_incomp%d: "
							    "internal error\n",
							    db->unit);
						}
						return (-1);
					}
				}

				dictp = &db->dict[hval];
				if (dictp->codem1 >= max_ent) {
					goto nomatch;
				}
			} while (dictp->f.fcode != fcode);

			ent = dictp->codem1+1;
			continue;	/* finally found (prefix,suffix) */

nomatch:				/* output (count) the prefix */
			bitno += n_bits;

			/*
			 * code -> hashtable
			 */
			if (max_ent < db->maxmaxcode) {
				struct bsd_dict *dictp2;

				/*
				 * expand code size if needed
				 */
				if (max_ent >= MAXCODE(n_bits)) {
					db->n_bits = ++n_bits;
				}

				/*
				 * Invalidate previous hash table entry
				 * assigned this code, and then take it over.
				 */
				dictp2 = &db->dict[max_ent+1];
				if (db->dict[dictp2->cptr].codem1 == max_ent) {
					db->dict[dictp2->cptr].codem1 =
					    BADCODEM1;
				}

				dictp2->cptr = (ushort_t)hval;
				dictp->codem1 = max_ent;
				dictp->f.fcode = fcode;

				db->max_ent = ++max_ent;
				db->lens[max_ent] = db->lens[ent]+1;
			}

			ent = c;
		} while (--slen != 0);
	}

	bitno += n_bits;		/* output (count) the last code */

	db->bytes_out += bitno/8;
	db->in_count += ilen;

	(void) bsd_check(db);

	++db->incomp_count;
	db->incomp_bytes += ilen;
	++db->uncomp_count;
	db->uncomp_bytes += ilen;

	/*
	 * Increase code size if we would have without the packet
	 * boundary and as the decompressor will.
	 */
	if (max_ent >= MAXCODE(n_bits) && max_ent < db->maxmaxcode) {
		db->n_bits++;
	}
	return (0);
#undef ADJRPTR
}


/*
 * bsd_decompress()
 *
 * Decompress "BSD Compress"
 *
 * Because of patent problems, we return DECOMP_ERROR for errors
 * found by inspecting the input data and for system problems, but
 * DECOMP_FATALERROR for any errors which could possibly be said to
 * be being detected "after" decompression.  For DECOMP_ERROR,
 * we can issue a CCP reset-request; for DECOMP_FATALERROR, we may be
 * infringing a patent of Motorola's if we do, so we take CCP down
 * instead.
 *
 * Given that the frame has the correct sequence number and a good FCS,
 * errors such as invalid codes in the input most likely indicate a
 * bug, so we return DECOMP_FATALERROR for them in order to turn off
 * compression, even though they are detected by inspecting the input.
 */
static int
bsd_decompress(void *state, mblk_t **dmpp)
{
	mblk_t		*cmsg = *dmpp, *mnext;
	struct bsd_db	*db = (struct bsd_db *)state;
	uint_t		max_ent = db->max_ent;
	uint32_t	accm = 0;
	uint_t		bitno = 32;		/* 1st valid bit in accm */
	uint_t		n_bits = db->n_bits;
	uint_t		tgtbitno = 32 - n_bits;	/* bitno when we have a code */
	struct bsd_dict	*dictp;
	int		explen;
	int		seq;
	uint_t		incode;
	uint_t		oldcode;
	uint_t		finchar = 0, ofinchar;
	uchar_t		*p;
	uchar_t		*rptr, *rmax;
	uchar_t		*wptr, *prepos;
	mblk_t		*dmsg;
	mblk_t		*mret;
	int		ilen;
	int		dlen;
	int		codelen;
	int		extra;
	int		decode_proto;
	int		blockctr;
	int		outlen;
#if defined(lint) || defined(_lint)
	uchar_t		adrs, ctrl;
#else
	int		adrs, ctrl;
#endif

	ASSERT(db->flags & DS_INITDONE);

	/* Note: spppcomp already did a pullup to fix the first buffer. */
	*dmpp = NULL;
	rptr = cmsg->b_rptr;
	rmax = cmsg->b_wptr;
	ilen = 0;

	/*
	 * Note that we free as we go.  If we fail to decompress,
	 * there's nothing good that the caller can do.
	 */
#define	ADJRPTR()					\
	while (rptr >= rmax) {				\
		mnext = cmsg->b_cont;			\
		freeb(cmsg);				\
		if ((cmsg = mnext) == NULL) {		\
			rptr = NULL;			\
			break;				\
		}					\
		rptr = cmsg->b_rptr;			\
		rmax = cmsg->b_wptr;			\
		ilen += rmax-rptr;			\
	}

	/*
	 * Save the address/control from the PPP header
	 * and then get the sequence number.
	 */
	adrs = rptr[0];
	ctrl = rptr[1];
	rptr += 4;
	ADJRPTR();
	seq = rptr == NULL ? 0 : (*rptr++ << 8);
	ADJRPTR();
	if (rptr == NULL) {
		if (db->flags & DS_DEBUG) {
			cmn_err(CE_CONT, "bsd_decomp%d: bad buffer\n",
			    db->unit);
		}
		return (DECOMP_ERROR);
	}
	seq |= *rptr++;

#ifdef DEBUG
	/*
	 * If testing input, just pretending the sequence is bad here
	 * does the trick.
	 */
	if ((db->flags & DS_TESTIN) && (db->seqno % 300) == 101)
		seq ^= 0x55;
#endif

	/*
	 * Check the sequence number and give up if it is not what we expect.
	 */
	if (db->hsize == 0 || seq != db->seqno++) {
		freemsg(cmsg);
		if (db->flags & DS_DEBUG) {
			cmn_err(CE_CONT, "bsd_decomp%d: bad sequence # %d, "
			    "expected %d\n", db->unit, seq, db->seqno - 1);
		}

		return (DECOMP_ERROR);
	}

	/*
	 * Allocate one message block to start with.
	 */
	if ((dmsg = allocb(DECOMP_CHUNK + db->hdrlen, BPRI_MED)) == NULL) {
		freemsg(cmsg);
		if (db->flags & DS_DEBUG) {
			cmn_err(CE_CONT,
			    "bsd_decomp%d: can't allocate first buffer\n",
			    db->unit);
		}
		return (DECOMP_ERROR);
	}

	/*
	 * Avoid an error that might cause us to allocate all available memory.
	 * Enforce a maximum number of blocks to allocate for message. We add
	 * a fudge factor of 5 extra blocks, in order to avoid unnecessary
	 * DECOMP_ERROR when the code size is small (9).
	 */
	blockctr = ((db->mru + 32 + DECOMP_CHUNK - 1) / DECOMP_CHUNK) + 5;

	mret = dmsg;
	dmsg->b_wptr += db->hdrlen;
	dmsg->b_rptr = wptr = dmsg->b_wptr;

	/*
	 * Insert PPP header.  This shouldn't be needed!
	 */
	*wptr++ = adrs;
	*wptr++ = ctrl;
	prepos = wptr;
	*wptr++ = 0;
	dmsg->b_wptr = wptr;

	explen = dmsg->b_datap->db_lim - wptr;
	oldcode = CLEAR;
	ilen = rmax-rptr;

	outlen = 0;
	decode_proto = 1;
	for (;;) {
		ADJRPTR();
		if (rptr == NULL)
			break;

		/*
		 * Accumulate bytes until we have a complete code.
		 * Then get the next code, relying on the 32-bit,
		 * unsigned accm to mask the result.
		 */
		bitno -= 8;

		accm |= *rptr++ << bitno;

		if (tgtbitno < bitno) {
			continue;
		}

		incode = accm >> tgtbitno;
		accm <<= n_bits;
		bitno += n_bits;

		if (incode == CLEAR) {

			/*
			 * The dictionary must only be cleared at
			 * the end of a packet.  But there could be an
			 * empty message block at the end.
			 */
			ADJRPTR();
			if (rptr != NULL) {
				freemsg(mret);
				freemsg(cmsg);
				if (db->flags & DS_DEBUG) {
					cmn_err(CE_CONT,
					    "bsd_decomp%d: bad CLEAR\n",
					    db->unit);
				}

				return (DECOMP_FATALERROR);
			}

			bsd_clear(db);
			/* Have to keep cleared state variables! */
			outlen += wptr-dmsg->b_wptr;
			dmsg->b_wptr = wptr;
			db->comp_bytes += ilen;
			ilen = 0;
			break;
		}

		/*
		 * Special case for KwKwK string
		 */
		ofinchar = finchar;
		if (incode > max_ent) {
			if (incode > max_ent + 2 ||
			    incode > db->maxmaxcode ||
			    oldcode == CLEAR) {
				freemsg(cmsg);
				freemsg(mret);

				/* probably a bug if we get here */
				if (db->flags & DS_DEBUG) {
					cmn_err(CE_CONT,
					    "bsd_decomp%d: bad code 0x%x "
					    "oldcode=0x%x ", db->unit, incode,
					    oldcode);
				}

				return (DECOMP_FATALERROR);
			}
			finchar = oldcode;
			extra = 1;
		} else {
			finchar = incode;
			extra = 0;
		}
		codelen = db->lens[finchar];

		/*
		 * Decode this code and install it in the decompressed buffer
		 */
		explen -= codelen + extra;
		if (explen < 0) {
			/*
			 * Allocate another message block
			 */
			dlen = wptr - dmsg->b_wptr;
			outlen += dlen;
			db->in_count += dlen;
			dmsg->b_wptr = wptr;
			dlen = codelen + extra;

			if (dlen < DECOMP_CHUNK) {
				dlen = DECOMP_CHUNK;
			}

			if ((--blockctr < 0) ||
			    (dmsg->b_cont = allocb(dlen, BPRI_MED)) == NULL) {
				freemsg(cmsg);
				freemsg(mret);
				if (db->flags & DS_DEBUG) {
					cmn_err(CE_CONT,
					    "bsd_decomp%d: %s output "
					    "buffers; outlen %d+%d\n",
					    db->unit,
					    (blockctr < 0 ? "too many" :
					    "can't allocate"),
					    outlen, dlen);
				}
				return (DECOMP_ERROR);
			}

			dmsg = dmsg->b_cont;
			wptr = dmsg->b_wptr;
			explen = dmsg->b_datap->db_lim - wptr - codelen -
			    extra;
		}

		p = (wptr += codelen);

		while (finchar > LAST) {
			dictp = &db->dict[db->dict[finchar].cptr];
			*--p = dictp->f.hs.suffix;
			finchar = dictp->f.hs.prefix;
		}

		*--p = finchar;

		if (decode_proto) {
			decode_proto = 0;
			/* Wow, is *this* ugly! */
			if (!(finchar & 1)) {
				if (p == prepos+1) {
					bcopy(p, prepos, wptr-p);
					wptr--;
					explen++;
					db->in_count++;
				} else {
					/* This is safe, but doesn't look it */
					*prepos = *p++;
					dmsg->b_rptr = p;
				}
			}
		}

		if (extra) {	/* the KwKwK case again */
			*wptr++ = ofinchar;
		}

		/*
		 * If not first code in a packet, and
		 * if not out of code space, then allocate a new code.
		 *
		 * Keep the hash table correct so it can be used
		 * with uncompressed packets.
		 */
		if (oldcode != CLEAR && max_ent < db->maxmaxcode) {
			struct bsd_dict	*dictp2;
			uint32_t	fcode;
			int		hval;
			int		disp;

			fcode = BSD_KEY(oldcode, finchar);
			hval = BSD_HASH(oldcode, finchar, db->hshift);

			dictp = &db->dict[hval];

			/*
			 * look for a free hash table entry
			 */
			if (dictp->codem1 < max_ent) {
				disp = (hval == 0) ? 1 : hval;

				do {
					hval += disp;

					if (hval >= db->hsize) {
						hval -= db->hsize;
						if (hval >= db->hsize) {
							freemsg(cmsg);
							freemsg(mret);
							if (db->flags &
							    DS_DEBUG) {
			cmn_err(CE_CONT, "bsd_decomp%d: internal error\n",
			    db->unit);
							}
							return
							    (DECOMP_FATALERROR);
						}
					}

					dictp = &db->dict[hval];

				} while (dictp->codem1 < max_ent);
			}

			/*
			 * Invalidate previous hash table entry
			 * assigned this code, and then take it over
			 */
			dictp2 = &db->dict[max_ent+1];

			if (db->dict[dictp2->cptr].codem1 == max_ent) {
				db->dict[dictp2->cptr].codem1 = BADCODEM1;
			}

			dictp2->cptr = (ushort_t)hval;
			dictp->codem1 = max_ent;
			dictp->f.fcode = fcode;

			db->max_ent = ++max_ent;
			db->lens[max_ent] = db->lens[oldcode]+1;

			/*
			 * Expand code size if needed
			 */
			if (max_ent >= MAXCODE(n_bits) &&
			    max_ent < db->maxmaxcode) {

				db->n_bits = ++n_bits;
				tgtbitno = 32-n_bits;
			}
		}

		oldcode = incode;
	}

	dlen = wptr-dmsg->b_wptr;
	outlen += dlen;
	db->in_count += dlen;
	dmsg->b_wptr = wptr;
	db->bytes_out += ilen;

	/*
	 * Keep the checkpoint right so that incompressible packets
	 * clear the dictionary at the right times.
	 */
	if (bsd_check(db) && (db->flags & DS_DEBUG)) {
		cmn_err(CE_CONT,
		    "bsd_decomp%d: peer should have cleared dictionary\n",
		    db->unit);
	}

	++db->comp_count;
	db->comp_bytes += ilen + BSD_OVHD;
	++db->uncomp_count;
	db->uncomp_bytes += outlen;

	*dmpp = mret;

	return (DECOMP_OK);
}

/* ARGSUSED */
static int
bsd_set_effort(void *xarg, void *rarg, int effortlevel)
{
#ifdef DEBUG
	struct bsd_db *xdb = (struct bsd_db *)xarg;
	struct bsd_db *rdb = (struct bsd_db *)rarg;

	if (effortlevel == 42 || effortlevel == 2112) {
		/* corrupt received data. */
		if (rdb != NULL) {
			rdb->flags |= DS_TESTIN;
			cmn_err(CE_CONT, "bsd-comp: enabled input testing.");
		}
		if (effortlevel != 2112)
			return (0);
	}
	if (effortlevel == 2001 || effortlevel == 2112) {
		/* corrupt transmitted data. */
		if (xdb != NULL) {
			xdb->flags |= DS_TESTOUT;
			cmn_err(CE_CONT, "bsd-comp: enabled output testing.");
		}
		return (0);
	}
#endif
	return (0);
}
#endif /* DO_BSD_COMPRESS */
