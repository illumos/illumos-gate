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

#include <sys/note.h>
#include "dh_gssapi.h"

/*
 * This module implements the interfaces for replay and out-of-sequence
 * detection.
 */

#define	WBITS_DEF 8 * sizeof (seq_word_t) /*  Bits in a seq_word_t */
static const int WBITS = WBITS_DEF; /* Stored in a static int for debuging */
static const int NBITS =  SSIZE * WBITS_DEF; /* Total bits in the sequence */

/*
 * The following routines are for debuging:
 *	__context_debug_set_next_seqno
 *	__context_debug_get_next_seqno
 *	__context_debug_set_last_seqno
 *	__context_debug_get_last_seqno
 *	__context_debug_print_seq_hist
 *      __context_debug_get_hist_size
 *	__context_debug
 *
 * These routines are declared static and there addresses placed into a table.
 * There is one publicly declare routine __context_debug_entry that is used
 * to fetch these entries. This way other routines can be added with out
 * changing the map-version file. This is being done for use with a libgss
 * test driver. In particular this technique is being used to implement
 * a pseudo libgss entry point gss_context_cntrl. Its declaration is
 * OM_uint32
 * gss_context_cntl(OM_uint32 *minor, gss_ctx_id_t ctx, int cmd, void *argp);
 *
 * Hence the declaratin of the debug routines below.
 */

/* Set the next sequence number to be sent */
static OM_uint32
__context_debug_set_next_seqno(OM_uint32 *minor, gss_ctx_id_t cntx, void *argp)
{
	dh_gss_context_t ctx = (dh_gss_context_t)cntx;
	OM_uint32 seqno = (OM_uint32)(intptr_t)argp;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;
	/*
	 * If context, set the sequence number.
	 * Locking should not be necessary since OM_uint32 should be atomic
	 * size.
	 */
	if (ctx) {
		mutex_lock(&ctx->seqno_lock);
		ctx->next_seqno = seqno;
		mutex_unlock(&ctx->seqno_lock);
	}
	return (GSS_S_COMPLETE);
}

/* Get the next sequence number to be sent */
static OM_uint32
__context_debug_get_next_seqno(OM_uint32 *minor, gss_ctx_id_t cntx, void *argp)
{
	dh_gss_context_t ctx = (dh_gss_context_t)cntx;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (argp == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;
	/* Grap the next sequence number */
	*(OM_uint32 *)argp = ctx->next_seqno;

	return (GSS_S_COMPLETE);
}

/* Set the last sequence number to was seen */
static OM_uint32
__context_debug_set_last_seqno(OM_uint32 *minor, gss_ctx_id_t cntx, void *argp)
{
	dh_gss_context_t ctx = (dh_gss_context_t)cntx;
	OM_uint32 seqno = (OM_uint32)(intptr_t)argp;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;

	/*
	 * If context, set the sequence number.
	 * Locking should not be necessary since OM_uint32 should be atomic
	 * size.
	 */
	if (ctx) {
		mutex_lock(&ctx->hist.seq_arr_lock);
		ctx->hist.seqno = seqno;
		mutex_unlock(&ctx->hist.seq_arr_lock);
	}
	return (GSS_S_COMPLETE);
}

/* Get the last sequence number seen */
static OM_uint32
__context_debug_get_last_seqno(OM_uint32 *minor, gss_ctx_id_t cntx, void *argp)
{
	dh_gss_context_t ctx = (dh_gss_context_t)cntx;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (argp == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;
	/* Grap the next sequence number */
	*(OM_uint32 *)argp = ctx->hist.seqno;

	return (GSS_S_COMPLETE);
}

static seq_word_t
rev(seq_word_t r)
{
	int i;
	seq_word_t t = 0;

	for (i = 0; i < WBITS; i++)
		if (r & ((seq_word_t)1 << i))
			t |= ((seq_word_t)1 << (WBITS - 1 - i));

	return (t);
}

/* Print out the sequence history to stderr */
static OM_uint32
__context_debug_print_seq_hist(OM_uint32 *minor, gss_ctx_id_t cntx, void *argp)
{
_NOTE(ARGUNUSED(argp))
	dh_gss_context_t ctx = (dh_gss_context_t)cntx;
	int i;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;

	/* Print out the sequence history */
	fprintf(stderr, "%u: ", ctx->hist.seqno);

	for (i = 0; i < SSIZE; i++)
		fprintf(stderr, "%016.16llx", rev(ctx->hist.arr[i]));
	fprintf(stderr, "\n");

	return (GSS_S_COMPLETE);
}

/* Fetch the size of the history */
static OM_uint32
__context_debug_get_hist_size(OM_uint32 *minor, gss_ctx_id_t cntx, void *argp)
{
_NOTE(ARGUNUSED(cntx))

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	if (argp == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;
	*(OM_uint32 *)argp = NBITS;

	return (GSS_S_COMPLETE);
}

/* Set the debug flag on the context */
static OM_uint32
__context_debug(OM_uint32 *minor, gss_ctx_id_t cntx, void *argp)
{
	dh_gss_context_t ctx = (dh_gss_context_t)cntx;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor = DH_SUCCESS;
	ctx->debug = (OM_uint32)(intptr_t)argp;

	return (GSS_S_COMPLETE);
}

/* Type to descript debug routines */
typedef OM_uint32 (*fptr)(OM_uint32 *, gss_ctx_id_t, void *);

/* Array of debug entries defined above */
static fptr __context_debug_entry_array[] = {
	__context_debug,
	__context_debug_set_next_seqno,
	__context_debug_get_next_seqno,
	__context_debug_print_seq_hist,
	__context_debug_get_hist_size,
	__context_debug_set_last_seqno,
	__context_debug_get_last_seqno
};

/* Structure to hold the debug entries */
static struct {
	int no_entries;
	fptr  *entrys;
} __context_debug_entry_points = {
	sizeof (__context_debug_entry_array)/sizeof (fptr),
	__context_debug_entry_array
};

/*
 * Exported entry point for debug routines. A call to this routine will
 * return a pointer to the above structure.
 */

void*
__context_debug_entry()
{
	return (&__context_debug_entry_points);
}

/* *************** End of Debug Section ***************** */

/* Clear all the bits in a sequence array */
static void
clear_all_bits(seq_array_t sa)
{
	unsigned int i;

	for (i = 0; i < SSIZE; i++)
		sa->arr[i] = (seq_word_t)0;
}

/* Check that a bit is set in a sequence array */
static unsigned int
check_bit(seq_array_t sa, unsigned int bit)
{
	if (bit >=  NBITS)
		return (0);

	return (sa->arr[bit/WBITS] & ((seq_word_t)1 << (bit % WBITS)) ? 1 : 0);
}

/* Set a bit in a sequence array */
void
set_bit(seq_array_t sa, unsigned int bit)
{
	if (bit < NBITS)
		sa->arr[bit/WBITS] |= ((seq_word_t)1 << (bit % WBITS));
}

/* Clear a bit in a sequence array */
/*
 * This function is not used, but is here as a comment for completeness.
 * Lint will complain if it is not commented out.
 * static void
 * clear_bit(seq_array_t sa, unsigned int bit)
 * {
 *	if (bit < NBITS)
 *		sa->arr[bit/WBITS] &= ~((seq_word_t)1 << (bit % WBITS));
 * }
 */

/*
 * Sift the bits in a sequence array by n
 *
 * The seqeunece arrays are logically arranged least significant bit to
 * most significant bit, where the LSB represents that last sequence
 * number seen. Thus this routine shifts the entire array to the left by
 * n.
 *
 *  0                                                             NBITS-1
 * +---------------------------------------------------------------+
 * |                                                               |
 * +---------------------------------------------------------------+
 *  ^
 *  This bit corresponds to the last sequence number seen sa->seqno.
 */
static void
shift_bits(seq_array_t sa, unsigned int n)
{
	int i, m;
	seq_word_t in = 0, out;

	/* How many words to shift */
	m = n / WBITS;

	/* Do we need to shift by words */
	if (m) {
		for (i = SSIZE - 1; i >= m; i--)
			sa->arr[i] = sa->arr[i - m];
		for (; i >= 0; i--)
			sa->arr[i] = (seq_word_t)0;
	}

	if (m >= SSIZE)
		return;

	/* The bits we need to shift */
	n %= WBITS;
	if (n == 0)
		return;


	for (i = m; i < SSIZE; i++) {
		/* The out going bits */
		out = (sa->arr[i] >> (WBITS - n));
		/*
		 * shift this part of the bit array and "add in"
		 * the most significant bits shifted out of the previous
		 * previous word.
		 */
		sa->arr[i] = (sa->arr[i] << n) |  in;
		/* The output of this word is the input to the next */
		in = out;
	}
}


/*
 * See if the given sequence number is out of sequence or is a replay
 * on the given context. If the context is not interested in either
 * just return GSS_S_COMPLETE
 */
OM_uint32
__dh_seq_detection(dh_gss_context_t ctx, OM_uint32 seqno)
{
	OM_uint32 n;
	OM_uint32 stat = GSS_S_COMPLETE;
	OM_uint32 minor;

	/*
	 * See if there is anything to do. If not return with no bits set.
	 */

	if (((ctx->flags & GSS_C_REPLAY_FLAG) == 0) &&
	    ((ctx->flags & GSS_C_SEQUENCE_FLAG) == 0))
		return (stat);

	/* lock the history why we check */
	mutex_lock(&ctx->hist.seq_arr_lock);

	/* If debugging print out the current history */
	if (ctx->debug)
		__context_debug_print_seq_hist(&minor, (gss_ctx_id_t)ctx, 0);

	n = seqno - ctx->hist.seqno;
	/* See if n is zero or that the high order bit is set or n = 0 */
	if ((n & ~((~((OM_uint32)0)) >> 1)) || n == 0) {
		/* sequence number is in the past */

		/*
		 * We want the small piece of the pie, so take the
		 * 2s complement (-n).
		 */
		n =  ~n + 1;

		/* the sequence number is ancient history */
		if (n > NBITS - 1)
			stat = GSS_S_OLD_TOKEN;
		/* See if it has been seen before */
		else if (check_bit(&ctx->hist, n))
			stat = GSS_S_DUPLICATE_TOKEN;
		else {
			/* Otherwise we've seen it now, so recored the fact */
			set_bit(&ctx->hist, n);

			/* If we care, report that we're out of sequence */
			if (ctx->flags & GSS_C_SEQUENCE_FLAG)
				stat = GSS_S_UNSEQ_TOKEN;
		}
	} else {
		/* sequence number is in the future so shift */
		shift_bits(&ctx->hist, n);

		/* The sequence number is the most recent now */
		ctx->hist.seqno = seqno;

		/* So set the most recent bit */
		set_bit(&ctx->hist, 0);

		/* if n > 1 and we care report a gap in the sequence */
		if (n > 1 && (ctx->flags & GSS_C_SEQUENCE_FLAG))
			stat = GSS_S_GAP_TOKEN;
	}

	/* If we're debugging print out the new state */
	if (ctx->debug)
		__context_debug_print_seq_hist(&minor, (gss_ctx_id_t)ctx, 0);

	/* Let other threads in */
	mutex_unlock(&ctx->hist.seq_arr_lock);

	/* return the status */
	return (stat);
}

/*
 * Set the next sequence number to use on this context.
 * Return that sequence number.
 */
OM_uint32
__dh_next_seqno(dh_gss_context_t ctx)
{
	OM_uint32 t;

	mutex_lock(&ctx->seqno_lock);
	t = ctx->next_seqno++;
	mutex_unlock(&ctx->seqno_lock);

	return (t);
}


/*
 * Initialize sequence history on a new context
 */
void
__dh_init_seq_hist(dh_gss_context_t ctx)
{
	mutex_init(&ctx->seqno_lock, USYNC_THREAD, 0);
	ctx->next_seqno = 1;
	mutex_init(&ctx->hist.seq_arr_lock, USYNC_THREAD, 0);
	ctx->hist.seqno = 0;
	clear_all_bits(&ctx->hist);
}

/*
 * Destroy sequence history on a context.
 */
void
__dh_destroy_seq_hist(dh_gss_context_t ctx)
{
	if (ctx) {
		mutex_destroy(&ctx->seqno_lock);
		mutex_destroy(&ctx->hist.seq_arr_lock);
	}
}
