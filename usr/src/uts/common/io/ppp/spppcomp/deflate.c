/*
 * deflate.c - interface the zlib procedures for Deflate compression
 * and decompression (as used by gzip) to the PPP code.
 *
 * This version is for use with STREAMS in Solaris 2
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * $Id: deflate.c,v 1.9 1999/01/19 23:58:35 paulus Exp $
 */

#define	NO_DUMMY_DECL

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <net/ppp_defs.h>

/* Defined for platform-neutral include file */
#define	PACKETPTR	mblk_t *
#include <net/ppp-comp.h>
#include "s_common.h"
#include "zlib.h"

#if DO_DEFLATE

/*
 * State for a Deflate (de)compressor.
 */
struct deflate_state {
	int		seqno;
	int		w_size;
	int		unit;
	int		hdrlen;
	int		mru;
	int		flags;
	z_stream	strm;
	struct compstat	stats;
};

#define	DEFLATE_OVHD	2		/* Deflate overhead/packet */

#define	DS_DEBUG	0x0001
#define	DS_TESTIN	0x0002
#define	DS_TESTOUT	0x0004

static void	*z_alloc(void *, uint_t items, uint_t size);
static void	z_free(void *, void *ptr);
static void	*z_comp_alloc(uchar_t *options, int opt_len);
static void	*z_decomp_alloc(uchar_t *options, int opt_len);
static void	z_comp_free(void *state);
static void	z_decomp_free(void *state);
static int	z_comp_init(void *state, uchar_t *options, int opt_len,
			int unit, int hdrlen, int debug);
static int	z_decomp_init(void *state, uchar_t *options, int opt_len,
			int unit, int hdrlen, int mru, int debug);
static int	z_compress(void *state, mblk_t **mret,
			mblk_t *mp, int slen, int maxolen);
static int	z_incomp(void *state, mblk_t *dmsg);
static int	z_decompress(void *state, mblk_t **dmpp);
static void	z_comp_reset(void *state);
static void	z_decomp_reset(void *state);
static void	z_comp_stats(void *state, struct compstat *stats);
static int	z_set_effort(void *xstate, void *rstate, int effortlevel);

/*
 * Procedures exported to ppp_comp.c.
 */
struct compressor ppp_deflate = {
	CI_DEFLATE,		/* compress_proto */
	z_comp_alloc,		/* comp_alloc */
	z_comp_free,		/* comp_free */
	z_comp_init,		/* comp_init */
	z_comp_reset,		/* comp_reset */
	z_compress,		/* compress */
	z_comp_stats,		/* comp_stat */
	z_decomp_alloc,		/* decomp_alloc */
	z_decomp_free,		/* decomp_free */
	z_decomp_init,		/* decomp_init */
	z_decomp_reset,		/* decomp_reset */
	z_decompress,		/* decompress */
	z_incomp,		/* incomp */
	z_comp_stats,		/* decomp_stat */
	z_set_effort,		/* set_effort */
};

struct compressor ppp_deflate_draft = {
	CI_DEFLATE_DRAFT,	/* compress_proto */
	z_comp_alloc,		/* comp_alloc */
	z_comp_free,		/* comp_free */
	z_comp_init,		/* comp_init */
	z_comp_reset,		/* comp_reset */
	z_compress,		/* compress */
	z_comp_stats,		/* comp_stat */
	z_decomp_alloc,		/* decomp_alloc */
	z_decomp_free,		/* decomp_free */
	z_decomp_init,		/* decomp_init */
	z_decomp_reset,		/* decomp_reset */
	z_decompress,		/* decompress */
	z_incomp,		/* incomp */
	z_comp_stats,		/* decomp_stat */
	z_set_effort,		/* set_effort */
};

#define	DECOMP_CHUNK	512

/*
 * Space allocation and freeing routines for use by zlib routines.
 */
struct zchunk {
	uint_t		size;
	uint_t		guard;
};

#define	GUARD_MAGIC	0x77a6011a

/*
 * z_alloc()
 */
/* ARGSUSED */
static void *
z_alloc(void *notused, uint_t items, uint_t size)
{
	struct zchunk	*z;

	size = items * size + sizeof (struct zchunk);

	z = (struct zchunk *)kmem_alloc(size, KM_NOSLEEP);
	if (z == NULL)
		return (NULL);

	z->size = size;
	z->guard = GUARD_MAGIC;

	return ((void *)(z + 1));
}

/*
 * z_free()
 */
/* ARGSUSED */
static void
z_free(void *notused, void *ptr)
{
	struct zchunk	*z = ((struct zchunk *)ptr) - 1;

	if (ptr == NULL)
		return;

	if (z->guard != GUARD_MAGIC) {
		cmn_err(CE_CONT,
		    "deflate: z_free of corrupted chunk at 0x%p (%x, %x)\n",
		    (void *)z, z->size, z->guard);

		return;
	}

	kmem_free(z, z->size);
}

/*
 * Allocate space for a compressor.
 */
static void *
z_comp_alloc(uchar_t *options, int opt_len)
{
	struct deflate_state	*state;
	int			w_size;

	if (opt_len != CILEN_DEFLATE ||
		(options[0] != CI_DEFLATE && options[0] != CI_DEFLATE_DRAFT) ||
		options[1] != CILEN_DEFLATE ||
		DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL ||
		options[3] != DEFLATE_CHK_SEQUENCE) {

		return (NULL);
	}

	w_size = DEFLATE_SIZE(options[2]);
	/*
	 * Check <= minimum size to avoid unfixable zlib bug -- window size
	 * 256 (w_size 8) is not supported.
	 */
	if (w_size <= DEFLATE_MIN_SIZE || w_size > DEFLATE_MAX_SIZE) {
		return (NULL);
	}

	state = (struct deflate_state *)kmem_zalloc(sizeof (*state), KM_SLEEP);
	ASSERT(state != NULL);

	state->strm.zalloc = (alloc_func)z_alloc;
	state->strm.zfree = (free_func)z_free;

	if (deflateInit2(&state->strm, Z_DEFAULT_COMPRESSION,
		DEFLATE_METHOD_VAL, -w_size, 8, Z_DEFAULT_STRATEGY) != Z_OK) {

		kmem_free(state, sizeof (*state));

		return (NULL);
	}

	state->w_size = w_size;

	bzero(&state->stats, sizeof (state->stats));

	return ((void *)state);
}

/*
 * z_comp_free()
 */
static void
z_comp_free(void *arg)
{
	struct deflate_state	*state = (struct deflate_state *)arg;

	(void) deflateEnd(&state->strm);

	kmem_free(state, sizeof (*state));
}

/*
 * z_comp_init()
 */
static int
z_comp_init(void *arg, uchar_t *options, int opt_len, int unit, int hdrlen,
	int debug)
{
	struct deflate_state *state = (struct deflate_state *)arg;

	if (opt_len < CILEN_DEFLATE ||
		(options[0] != CI_DEFLATE && options[0] != CI_DEFLATE_DRAFT) ||
		options[1] != CILEN_DEFLATE ||
		DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL ||
		DEFLATE_SIZE(options[2]) != state->w_size ||
		options[3] != DEFLATE_CHK_SEQUENCE) {

		return (0);
	}

	state->seqno = 0;
	state->unit = unit;
	state->hdrlen = hdrlen;
	if (debug)
		state->flags |= DS_DEBUG;
	else
		state->flags &= ~DS_DEBUG;

	(void) deflateReset(&state->strm);

	return (1);
}

/*
 * z_comp_reset()
 */
static void
z_comp_reset(void *arg)
{
	struct deflate_state	*state = (struct deflate_state *)arg;

	state->seqno = 0;

	(void) deflateReset(&state->strm);
}

/*
 * z_compress()
 */
static int
z_compress(void *arg, mblk_t **mret, mblk_t *mp, int orig_len, int maxolen)
{
	struct deflate_state	*state = (struct deflate_state *)arg;
	uchar_t			*rptr, *rmax;
	uchar_t			*wptr;
	int			olen;
	int			wspace;
	int			r;
	int			flush;
	mblk_t			*m;
#if defined(lint) || defined(_lint)
	uchar_t			hdlcaddr, hdlcctrl;
#else
	int			hdlcaddr, hdlcctrl;
#endif

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

	/*
	 * Check that the protocol is one we handle.  Pullup is *NOT*
	 * possible here.
	 */
	*mret = NULL;
	rptr = mp->b_rptr;
	rmax = mp->b_wptr;
	ADJRPTR();
	GETBYTE(hdlcaddr);
	ADJRPTR();
	GETBYTE(hdlcctrl);
	ADJRPTR();

	/*
	 * Per RFC 1979, the protocol field must be compressed using a
	 * PFC-like procedure.  Also, all protocols between 0000-3FFF
	 * except the two compression protocols must be LZ compressed.
	 */
	if (rptr == NULL)
		return (orig_len);
	r = *rptr;
	if (r == 0) {
		rptr++;
		ADJRPTR();
		if (rptr == NULL || *rptr == PPP_COMP || *rptr == PPP_COMPFRAG)
			return (orig_len);
	} else {
		if (r > 0x3F)
			return (orig_len);
	}

	/*
	 * Allocate one mblk initially
	 */
	if (maxolen > orig_len) {
		maxolen = orig_len;
	}

	if (maxolen <= PPP_HDRLEN + 2) {
		wspace = 0;
		m = NULL;
	} else {
		wspace = maxolen + state->hdrlen;
		if (wspace > 4096) {
			wspace = 4096;
		}

		m = allocb(wspace, BPRI_MED);
	}

	if (m != NULL) {

		wspace = m->b_datap->db_lim - m->b_wptr;

		*mret = m;

		if (state->hdrlen + PPP_HDRLEN + 2 < wspace) {
			m->b_rptr += state->hdrlen;
			m->b_wptr = m->b_rptr;
			wspace -= state->hdrlen;
		}

		wptr = m->b_wptr;

		/*
		 * Copy over the PPP header and store the 2-byte
		 * sequence number
		 */
		wptr[0] = hdlcaddr;
		wptr[1] = hdlcctrl;
		wptr[2] = PPP_COMP >> 8;
		wptr[3] = PPP_COMP;

		wptr += PPP_HDRLEN;

		wptr[0] = state->seqno >> 8;
		wptr[1] = state->seqno;
		wptr += 2;

#ifdef DEBUG
		/*
		 * If testing output, just garbling the sequence here
		 * does the trick.
		 */
		if ((state->flags & DS_TESTOUT) && (state->seqno % 100) == 50)
			wptr[-1] ^= 0xAA;
#endif

		state->strm.next_out = wptr;
		state->strm.avail_out = wspace - (PPP_HDRLEN + 2);
	} else {
		state->strm.next_out = NULL;
		state->strm.avail_out = 1000000;
	}

	++state->seqno;

	state->strm.next_in = rptr;
	state->strm.avail_in = mp->b_wptr - rptr;

	olen = 0;

	for (;;) {
		flush = (mp == NULL || mp->b_cont == NULL) ? Z_PACKET_FLUSH :
		    Z_NO_FLUSH;
		r = deflate(&state->strm, flush);

		if (r != Z_OK) {
			cmn_err(CE_CONT,
			    "z_compress%d: deflate returned %d (%s)\n",
			    state->unit, r,
			    (state->strm.msg? state->strm.msg: ""));

			break;
		}

		if (state->strm.avail_in == 0) {
			if (mp != NULL)
				mp = mp->b_cont;
			if (mp == NULL) {
				if (state->strm.avail_out != 0)
					break;	/* all done */
			} else {
				state->strm.next_in = mp->b_rptr;
				state->strm.avail_in = mp->b_wptr - mp->b_rptr;
			}
		}

		if (state->strm.avail_out == 0) {
			if (m != NULL) {
				m->b_wptr += wspace;
				olen += wspace;
				wspace = maxolen - olen;

				if (wspace <= 0) {
					wspace = 0;
					m->b_cont = NULL;
				} else {
					if (wspace < 32) {
						wspace = 32;
					} else if (wspace > 4096) {
						wspace = 4096;
					}

					m->b_cont = allocb(wspace, BPRI_MED);
				}

				m = m->b_cont;

				if (m != NULL) {
					state->strm.next_out = m->b_wptr;
					wspace = m->b_datap->db_lim -
					    m->b_wptr;
					state->strm.avail_out = wspace;
				}
			}

			if (m == NULL) {
				state->strm.next_out = NULL;
				state->strm.avail_out = 1000000;
			}
		}
	}

	if (m != NULL) {
		m->b_wptr += wspace - state->strm.avail_out;
		olen += wspace - state->strm.avail_out;
	}

	/*
	 * See if we managed to reduce the size of the packet.
	 */
	if (olen < orig_len && m != NULL) {
		state->stats.comp_bytes += olen;
		state->stats.comp_packets++;
	} else {
		if (*mret != NULL) {
			freemsg(*mret);
			*mret = NULL;
		}

		state->stats.inc_bytes += orig_len;
		state->stats.inc_packets++;

		olen = orig_len;
	}

	state->stats.unc_bytes += orig_len;
	state->stats.unc_packets++;

	return (olen);
}

/*
 * z_incomp()
 *
 * Incompressible data has arrived - add it to the history.
 */
static int
z_incomp(void *arg, mblk_t *mp)
{
	struct deflate_state	*state = (struct deflate_state *)arg;
	uchar_t			*rptr, *rmax;
	int			rlen;
	int			r;

	/*
	 * Check that the protocol is one we handle.  Pullup is *NOT*
	 * possible here.
	 */
	rptr = mp->b_rptr;
	rmax = mp->b_wptr;
	ADJRPTR();
	rptr++;		/* skip address */
	ADJRPTR();
	rptr++;		/* skip control */
	ADJRPTR();

	/*
	 * Per RFC 1979, the protocol field must be compressed using a
	 * PFC-like procedure.  Also, all protocols between 0000-3FFF
	 * except the two compression protocols must be LZ compressed.
	 */
	if (rptr == NULL)
		return (0);
	r = *rptr;
	if (r == 0) {
		rptr++;
		ADJRPTR();
		if (rptr == NULL || *rptr == PPP_COMP || *rptr == PPP_COMPFRAG)
			return (0);
	} else {
		if (r > 0x3F)
			return (0);
	}

	++state->seqno;

	/*
	 * Iterate through the message blocks, adding the characters
	 * in them to the decompressor's history.
	 */
	rlen = mp->b_wptr - rptr;

	state->strm.next_in = rptr;
	state->strm.avail_in = rlen;

	for (;;) {
		r = inflateIncomp(&state->strm);

		if (r != Z_OK) {	/* gak! */
			if (state->flags & DS_DEBUG) {
				cmn_err(CE_CONT,
				    "z_incomp%d: inflateIncomp returned "
				    "%d (%s)\n", state->unit, r,
				    (state->strm.msg? state->strm.msg: ""));
			}

			return (-1);
		}

		mp = mp->b_cont;
		if (mp == NULL) {
			break;
		}

		state->strm.next_in = mp->b_rptr;
		state->strm.avail_in = mp->b_wptr - mp->b_rptr;

		rlen += state->strm.avail_in;
	}

	/*
	 * Update stats
	 */
	state->stats.inc_bytes += rlen;
	state->stats.inc_packets++;
	state->stats.unc_bytes += rlen;
	state->stats.unc_packets++;
	return (0);
#undef ADJRPTR
}

/*
 * z_comp_stats()
 */
static void
z_comp_stats(void *arg, struct compstat *stats)
{
	struct deflate_state	*state = (struct deflate_state *)arg;
	uint_t			out;

	*stats = state->stats;
	stats->ratio = stats->unc_bytes;
	out = stats->comp_bytes + stats->unc_bytes;

	if (stats->ratio <= 0x7ffffff) {
		stats->ratio <<= 8;
	} else {
		out >>= 8;
	}

	if (out != 0) {
		stats->ratio /= out;
	}
}

/*
 * z_decomp_alloc()
 *
 * Allocate space for a decompressor.
 */
static void *
z_decomp_alloc(uchar_t *options, int opt_len)
{
	struct deflate_state	*state;
	int			w_size;

	if (opt_len != CILEN_DEFLATE ||
		(options[0] != CI_DEFLATE && options[0] != CI_DEFLATE_DRAFT) ||
		options[1] != CILEN_DEFLATE ||
		DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL ||
		options[3] != DEFLATE_CHK_SEQUENCE) {

		return (NULL);
	}

	w_size = DEFLATE_SIZE(options[2]);
	/*
	 * Check <= minimum size to avoid unfixable zlib bug -- window size
	 * 256 (w_size 8) is not supported.
	 */
	if (w_size <= DEFLATE_MIN_SIZE || w_size > DEFLATE_MAX_SIZE) {
		return (NULL);
	}

	state = (struct deflate_state *)kmem_zalloc(sizeof (*state), KM_SLEEP);
	ASSERT(state != NULL);

	state->strm.zalloc = (alloc_func)z_alloc;
	state->strm.zfree = (free_func)z_free;

	if (inflateInit2(&state->strm, -w_size) != Z_OK) {
		kmem_free(state, sizeof (*state));
		return (NULL);
	}

	state->w_size = w_size;

	bzero(&state->stats, sizeof (state->stats));

	return ((void *)state);
}

/*
 * z_decomp_free()
 */
static void
z_decomp_free(void *arg)
{
	struct deflate_state	*state = (struct deflate_state *)arg;

	(void) inflateEnd(&state->strm);

	kmem_free(state, sizeof (*state));
}

/*
 * z_decomp_init()
 */
static int
z_decomp_init(void *arg, uchar_t *options, int opt_len, int unit, int hdrlen,
	int mru, int debug)
{
	struct deflate_state *state = (struct deflate_state *)arg;

	if (opt_len < CILEN_DEFLATE ||
		(options[0] != CI_DEFLATE && options[0] != CI_DEFLATE_DRAFT) ||
		options[1] != CILEN_DEFLATE ||
		DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL ||
		DEFLATE_SIZE(options[2]) != state->w_size ||
		options[3] != DEFLATE_CHK_SEQUENCE) {

		return (0);
	}

	state->seqno = 0;
	state->unit = unit;
	state->hdrlen = hdrlen;
	if (debug)
		state->flags |= DS_DEBUG;
	else
		state->flags &= ~DS_DEBUG;
	state->mru = mru;

	(void) inflateReset(&state->strm);

	return (1);
}

/*
 * z_decomp_reset()
 */
static void
z_decomp_reset(void *arg)
{
	struct deflate_state	*state = (struct deflate_state *)arg;

	state->seqno = 0;

	(void) inflateReset(&state->strm);
}

/*
 * z_decompress()
 *
 * Decompress a Deflate-compressed packet.
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
z_decompress(void *arg, mblk_t **mop)
{
	struct deflate_state	*state = (struct deflate_state *)arg;
	mblk_t			*mi = *mop, *mnext;
	mblk_t			*mo;
	mblk_t			*mo_head;
	uchar_t			*rptr, *rmax;
	uchar_t			*wptr;
	int			rlen;
	int			olen;
	int			ospace;
	int			seq;
	int			flush;
	int			r;
	int			decode_proto;
#if defined(lint) || defined(_lint)
	uchar_t			hdlcaddr, hdlcctrl;
#else
	int			hdlcaddr, hdlcctrl;
#endif

	/* Note: spppcomp already did a pullup to fix the first buffer. */
	*mop = NULL;
	rptr = mi->b_rptr + PPP_HDRLEN;
	rmax = mi->b_wptr;
	if (rptr > rmax) {
		if (state->flags & DS_DEBUG) {
			cmn_err(CE_CONT, "z_decompress%d: bad buffer\n",
			    state->unit);
		}
		freemsg(mi);
		return (DECOMP_ERROR);
	}

	hdlcaddr = rptr[-PPP_HDRLEN];
	hdlcctrl = rptr[-PPP_HDRLEN+1];

	/*
	 * Note that we free as we go.  If we fail to decompress,
	 * there's nothing good that the caller can do.
	 */
#define	ADJRPTR() {						\
	if (rptr != NULL) {					\
		while (rptr >= rmax) {				\
			mnext = mi->b_cont;			\
			freeb(mi);				\
			if ((mi = mnext) == NULL) {		\
				rptr = NULL;			\
				break;				\
			}					\
			rptr = mi->b_rptr;			\
			rmax = mi->b_wptr;			\
		}						\
	}							\
}

	/*
	 * Check the sequence number
	 */
	ADJRPTR();
	seq = rptr == NULL ? 0 : (*rptr++ << 8);
	ADJRPTR();
	if (rptr == NULL) {
		if (state->flags & DS_DEBUG) {
			cmn_err(CE_CONT, "z_decompress%d: bad buffer\n",
			    state->unit);
		}
		return (DECOMP_ERROR);
	}

	seq |= *rptr++;

#ifdef DEBUG
	/*
	 * If testing input, just pretending the sequence is bad here
	 * does the trick.
	 */
	if ((state->flags & DS_TESTIN) && (state->seqno % 300) == 101)
		seq ^= 0x55;
#endif
	if (seq != state->seqno++) {
		freemsg(mi);
		if (state->flags & DS_DEBUG) {
			cmn_err(CE_CONT,
				"z_decompress%d: bad seq # %d, expected %d\n",
				state->unit, seq, state->seqno - 1);
		}
		return (DECOMP_ERROR);
	}

	/*
	 * Allocate an output message block
	 */
	mo = allocb(DECOMP_CHUNK + state->hdrlen, BPRI_MED);
	if (mo == NULL) {
		freemsg(mi);
		return (DECOMP_ERROR);
	}

	mo_head = mo;
	mo->b_cont = NULL;
	mo->b_rptr += state->hdrlen;
	mo->b_wptr = wptr = mo->b_rptr;

	ospace = DECOMP_CHUNK;
	olen = 0;

	/*
	 * Fill in the first part of the PPP header.  The protocol field
	 * comes from the decompressed data.
	 */
	*wptr++ = hdlcaddr;
	*wptr++ = hdlcctrl;
	*wptr++ = 0;

	/*
	 * Set up to call inflate.  We set avail_out to 1 initially so we can
	 * look at the first byte of the output and decide whether we have
	 * a 1-byte or 2-byte protocol field.
	 */
	state->strm.next_in = rptr;
	state->strm.avail_in = mi->b_wptr - rptr;

	rlen = state->strm.avail_in + PPP_HDRLEN + DEFLATE_OVHD;

	state->strm.next_out = wptr;
	state->strm.avail_out = 1;

	decode_proto = 1;

	/*
	 * Call inflate, supplying more input or output as needed.
	 */
	for (;;) {

		flush = (mi == NULL || mi->b_cont == NULL) ?
		    Z_PACKET_FLUSH : Z_NO_FLUSH;
		r = inflate(&state->strm, flush);

		if (r != Z_OK) {

			if (state->flags & DS_DEBUG) {
				cmn_err(CE_CONT,
				    "z_decompress%d: inflate returned %d "
				    "(%s)\n", state->unit, r,
				    (state->strm.msg? state->strm.msg: ""));
			}

			if (mi != NULL)
				freemsg(mi);
			freemsg(mo_head);

			return (DECOMP_FATALERROR);
		}

		if (state->strm.avail_in == 0) {
			if (mi != NULL) {
				mnext = mi->b_cont;
				freeb(mi);
				mi = mnext;
			}
			if (mi == NULL) {
				if (state->strm.avail_out != 0)
					break;	/* all done */
			} else {
				state->strm.next_in = mi->b_rptr;
				state->strm.avail_in = mi->b_wptr - mi->b_rptr;

				rlen += state->strm.avail_in;
			}
		}

		if (state->strm.avail_out == 0) {
			if (decode_proto) {
				state->strm.avail_out = ospace - PPP_HDRLEN;

				if ((wptr[0] & 1) == 0) {
					/*
					 * 2-byte protocol field
					 */
					wptr[-1] = wptr[0];

					--state->strm.next_out;
					++state->strm.avail_out;
				}

				decode_proto = 0;
			} else {
				mo->b_wptr += ospace;
				olen += ospace;

				mo->b_cont = allocb(DECOMP_CHUNK, BPRI_MED);

				mo = mo->b_cont;
				if (mo == NULL) {
					if (mi != NULL)
						freemsg(mi);
					freemsg(mo_head);
					return (DECOMP_ERROR);
				}

				state->strm.next_out = mo->b_rptr;
				state->strm.avail_out = ospace = DECOMP_CHUNK;
			}
		}
	}

	if (decode_proto) {
		freemsg(mo_head);
		return (DECOMP_ERROR);
	}

	mo->b_wptr += ospace - state->strm.avail_out;
	olen += ospace - state->strm.avail_out;

	if ((olen > state->mru + PPP_HDRLEN) && (state->flags & DS_DEBUG)) {
		cmn_err(CE_CONT, "z_decompress%d: exceeded mru (%d > %d)\n",
		    state->unit, olen, state->mru + PPP_HDRLEN);
	}

	state->stats.unc_bytes += olen;
	state->stats.unc_packets++;
	state->stats.comp_bytes += rlen;
	state->stats.comp_packets++;

	*mop = mo_head;

	return (DECOMP_OK);
}

/* ARGSUSED */
static int
z_set_effort(void *xarg, void *rarg, int effortlevel)
{
	struct deflate_state *xstate = (struct deflate_state *)xarg;
#ifdef DEBUG
	struct deflate_state *rstate = (struct deflate_state *)rarg;
#endif
	int retv;

#ifdef DEBUG
	if (effortlevel == 42 || effortlevel == 2112) {
		/* corrupt received data. */
		if (rstate != NULL) {
			rstate->flags |= DS_TESTIN;
			cmn_err(CE_CONT, "deflate: enabled input testing.");
		}
		if (effortlevel != 2112)
			return (0);
	}
	if (effortlevel == 2001 || effortlevel == 2112) {
		/* corrupt transmitted data. */
		if (xstate != NULL) {
			xstate->flags |= DS_TESTOUT;
			cmn_err(CE_CONT, "deflate: enabled output testing.");
		}
		return (0);
	}
#endif
	if (effortlevel < -1 || effortlevel > 9)
		return (EINVAL);
	if (xstate == NULL)
		return (0);
	retv = deflateParams(&xstate->strm, effortlevel, Z_DEFAULT_STRATEGY);
	return (retv == Z_OK ? 0 : EINVAL);
}

#endif /* DO_DEFLATE */
