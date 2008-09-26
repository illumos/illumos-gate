/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1988, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 *
 *	@(#)radix.c	8.5 (Berkeley) 5/19/95
 * $FreeBSD: /repoman/r/ncvs/src/sys/net/radix.c,v 1.36.2.1 2005/01/31 23:26:23
 * imp Exp $
 */


/*
 * Routines to build and maintain radix trees for routing lookups.
 */
#include <sys/types.h>

#ifndef _RADIX_H_
#include <sys/param.h>
#ifdef	_KERNEL
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#else
#include <assert.h>
#define	ASSERT assert
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <strings.h>
#endif	/* _KERNEL */
#include <net/radix.h>
#endif

#ifndef	_KERNEL
void
panic(const char *str)
{
	fprintf(stderr, "Panic - %s\n", str);
	abort();
}
#endif	/* _KERNEL */

static int	rn_walktree(struct radix_node_head *, walktree_f_t *, void *);
static int	rn_walktree_mt(struct radix_node_head *, walktree_f_t *,
    void *, lockf_t, lockf_t);
static struct radix_node
	*rn_insert(void *, struct radix_node_head *, int *,
	    struct radix_node [2]),
	*rn_newpair(void *, int, struct radix_node[2]),
	*rn_search(void *, struct radix_node *),
	*rn_search_m(void *, struct radix_node *, void *),
	*rn_lookup(void *, void *, struct radix_node_head *),
	*rn_match(void *, struct radix_node_head *),
	*rn_match_args(void *, struct radix_node_head *, match_leaf_t *,
	    void *),
	*rn_addmask(void *, int, int),
	*rn_addroute(void *, void *, struct radix_node_head *,
	    struct radix_node [2]),
	*rn_delete(void *, void *, struct radix_node_head *);
static	boolean_t rn_refines(void *, void *);

/*
 * IPF also uses PATRICIA tree to manage ippools. IPF stores its own structure
 * addrfamily_t. sizeof (addrfamily_t) == 24.
 */
#define	MAX_KEYLEN	24
static int	max_keylen = MAX_KEYLEN;

#ifdef	_KERNEL
static struct kmem_cache *radix_mask_cache; /* for rn_mkfreelist */
static struct kmem_cache *radix_node_cache;
#else
static char *radix_mask_cache, *radix_node_cache; /* dummy vars. never inited */
#endif	/* _KERNEL */

static struct radix_mask *rn_mkfreelist;
static struct radix_node_head *mask_rnhead;
/*
 * Work area -- the following point to 2 buffers of size max_keylen,
 * allocated in this order in a block of memory malloc'ed by rn_init.
 * A third buffer of size MAX_KEYLEN is allocated from the stack.
 */
static char *rn_zeros, *rn_ones;

#define	MKGet(m)  R_Malloc(m, radix_mask_cache, sizeof (struct radix_mask))
#define	MKFree(m) Free(m, radix_mask_cache)
#define	rn_masktop (mask_rnhead->rnh_treetop)

static boolean_t	rn_lexobetter(void *m_arg, void *n_arg);
static struct radix_mask *
		rn_new_radix_mask(struct radix_node *tt,
		    struct radix_mask *next);
static boolean_t
		rn_satisfies_leaf(char *trial, struct radix_node *leaf,
		    int skip, match_leaf_t *rn_leaf_fn, void *rn_leaf_arg);

#define	RN_MATCHF(rn, f, arg)	(f == NULL || (*f)((rn), arg))

/*
 * The data structure for the keys is a radix tree with one way
 * branching removed.  The index rn_bit at an internal node n represents a bit
 * position to be tested.  The tree is arranged so that all descendants
 * of a node n have keys whose bits all agree up to position rn_bit - 1.
 * (We say the index of n is rn_bit.)
 *
 * There is at least one descendant which has a one bit at position rn_bit,
 * and at least one with a zero there.
 *
 * A route is determined by a pair of key and mask.  We require that the
 * bit-wise logical and of the key and mask to be the key.
 * We define the index of a route associated with the mask to be
 * the first bit number in the mask where 0 occurs (with bit number 0
 * representing the highest order bit).
 *
 * We say a mask is normal if every bit is 0, past the index of the mask.
 * If a node n has a descendant (k, m) with index(m) == index(n) == rn_bit,
 * and m is a normal mask, then the route applies to every descendant of n.
 * If the index(m) < rn_bit, this implies the trailing last few bits of k
 * before bit b are all 0, (and hence consequently true of every descendant
 * of n), so the route applies to all descendants of the node as well.
 *
 * Similar logic shows that a non-normal mask m such that
 * index(m) <= index(n) could potentially apply to many children of n.
 * Thus, for each non-host route, we attach its mask to a list at an internal
 * node as high in the tree as we can go.
 *
 * The present version of the code makes use of normal routes in short-
 * circuiting an explict mask and compare operation when testing whether
 * a key satisfies a normal route, and also in remembering the unique leaf
 * that governs a subtree.
 */

/*
 * Most of the functions in this code assume that the key/mask arguments
 * are sockaddr-like structures, where the first byte is an uchar_t
 * indicating the size of the entire structure.
 *
 * To make the assumption more explicit, we use the LEN() macro to access
 * this field. It is safe to pass an expression with side effects
 * to LEN() as the argument is evaluated only once.
 */
#define	LEN(x) (*(const uchar_t *)(x))


/*
 * Search a node in the tree matching the key.
 */
static struct radix_node *
rn_search(v_arg, head)
	void *v_arg;
	struct radix_node *head;
{
	struct radix_node *x;
	caddr_t v;

	for (x = head, v = v_arg; x->rn_bit >= 0; ) {
		if (x->rn_bmask & v[x->rn_offset])
			x = x->rn_right;
		else
			x = x->rn_left;
	}
	return (x);
}

/*
 * Same as above, but with an additional mask.
 */
static struct radix_node *
rn_search_m(v_arg, head, m_arg)
	struct radix_node *head;
	void *v_arg, *m_arg;
{
	struct radix_node *x;
	caddr_t v = v_arg, m = m_arg;

	for (x = head; x->rn_bit >= 0; ) {
		if ((x->rn_bmask & m[x->rn_offset]) &&
		    (x->rn_bmask & v[x->rn_offset]))
			x = x->rn_right;
		else
			x = x->rn_left;
	}
	return (x);
}

/*
 * Returns true if there are no bits set in n_arg that are zero in
 * m_arg and the masks aren't equal.  In other words, it returns true
 * when m_arg is a finer-granularity netmask -- it represents a subset
 * of the destinations implied by n_arg.
 */
static boolean_t
rn_refines(m_arg, n_arg)
	void *m_arg, *n_arg;
{
	caddr_t m = m_arg, n = n_arg;
	caddr_t lim = n + LEN(n), lim2 = lim;
	int longer = LEN(n++) - (int)LEN(m++);
	boolean_t masks_are_equal = B_TRUE;

	if (longer > 0)
		lim -= longer;
	while (n < lim) {
		if (*n & ~(*m))
			return (0);
		if (*n++ != *m++)
			masks_are_equal = B_FALSE;
	}
	while (n < lim2)
		if (*n++)
			return (B_FALSE);
	if (masks_are_equal && (longer < 0))
		for (lim2 = m - longer; m < lim2; )
			if (*m++)
				return (B_TRUE);
	return (!masks_are_equal);
}

static struct radix_node *
rn_lookup(v_arg, m_arg, head)
	void *v_arg, *m_arg;
	struct radix_node_head *head;
{
	struct radix_node *x;
	caddr_t netmask = NULL;

	if (m_arg) {
		x = rn_addmask(m_arg, 1, head->rnh_treetop->rn_offset);
		if (x == NULL)
			return (NULL);
		netmask = x->rn_key;
	}
	x = rn_match(v_arg, head);
	if (x && netmask) {
		while (x && x->rn_mask != netmask)
			x = x->rn_dupedkey;
	}
	return (x);
}

/*
 * Returns true if address 'trial' has no bits differing from the
 * leaf's key when compared under the leaf's mask.  In other words,
 * returns true when 'trial' matches leaf.
 * In addition, if a rn_leaf_fn is passed in, that is used to find
 * a match on conditions defined by the caller of rn_match.  This is
 * used by the kernel ftable to match on IRE_MATCH_* conditions.
 */
static boolean_t
rn_satisfies_leaf(trial, leaf, skip, rn_leaf_fn, rn_leaf_arg)
	caddr_t trial;
	struct radix_node *leaf;
	int skip;
	match_leaf_t *rn_leaf_fn;
	void *rn_leaf_arg;
{
	char *cp = trial, *cp2 = leaf->rn_key, *cp3 = leaf->rn_mask;
	char *cplim;
	int length = min(LEN(cp), LEN(cp2));

	if (cp3 == 0)
		cp3 = rn_ones;
	else
		length = min(length, LEN(cp3));
	cplim = cp + length;
	cp3 += skip;
	cp2 += skip;

	for (cp += skip; cp < cplim; cp++, cp2++, cp3++)
		if ((*cp ^ *cp2) & *cp3)
			return (B_FALSE);

	return (RN_MATCHF(leaf, rn_leaf_fn, rn_leaf_arg));
}

static struct radix_node *
rn_match(v_arg, head)
	void *v_arg;
	struct radix_node_head *head;
{
	return (rn_match_args(v_arg, head, NULL, NULL));
}

static struct radix_node *
rn_match_args(v_arg, head, rn_leaf_fn, rn_leaf_arg)
	void *v_arg;
	struct radix_node_head *head;
	match_leaf_t *rn_leaf_fn;
	void *rn_leaf_arg;
{
	caddr_t v = v_arg;
	struct radix_node *t = head->rnh_treetop, *x;
	caddr_t cp = v, cp2;
	caddr_t cplim;
	struct radix_node *saved_t, *top = t;
	int off = t->rn_offset, vlen = LEN(cp), matched_off;
	int test, b, rn_bit;

	/*
	 * Open code rn_search(v, top) to avoid overhead of extra
	 * subroutine call.
	 */
	for (; t->rn_bit >= 0; ) {
		if (t->rn_bmask & cp[t->rn_offset])
			t = t->rn_right;
		else
			t = t->rn_left;
	}
	/*
	 * See if we match exactly as a host destination
	 * or at least learn how many bits match, for normal mask finesse.
	 *
	 * It doesn't hurt us to limit how many bytes to check
	 * to the length of the mask, since if it matches we had a genuine
	 * match and the leaf we have is the most specific one anyway;
	 * if it didn't match with a shorter length it would fail
	 * with a long one.  This wins big for class B&C netmasks which
	 * are probably the most common case...
	 */
	if (t->rn_mask)
		vlen = LEN(t->rn_mask);
	cp += off; cp2 = t->rn_key + off; cplim = v + vlen;
	for (; cp < cplim; cp++, cp2++)
		if (*cp != *cp2)
			goto keydiff;
	/*
	 * This extra grot is in case we are explicitly asked
	 * to look up the default.  Ugh!
	 *
	 * Never return the root node itself, it seems to cause a
	 * lot of confusion.
	 */
	if (t->rn_flags & RNF_ROOT)
		t = t->rn_dupedkey;
	if (t == NULL || RN_MATCHF(t, rn_leaf_fn, rn_leaf_arg)) {
		return (t);
	} else {
		/*
		 * Although we found an exact match on the key, rn_leaf_fn
		 * is looking for some other criteria as well. Continue
		 * looking as if the exact match failed.
		 */
		if (t->rn_parent->rn_flags & RNF_ROOT) {
			/* hit the top. have to give up */
			return (NULL);
		}
		b = 0;
		goto keeplooking;

	}
keydiff:
	test = (*cp ^ *cp2) & 0xff; /* find first bit that differs */
	for (b = 7; (test >>= 1) > 0; )
		b--;
keeplooking:
	matched_off = cp - v;
	b += matched_off << 3;
	rn_bit = -1 - b;

	/*
	 * If there is a host route in a duped-key chain, it will be first.
	 */
	if ((saved_t = t)->rn_mask == 0)
		t = t->rn_dupedkey;
	for (; t != NULL; t = t->rn_dupedkey) {
		/*
		 * Even if we don't match exactly as a host,
		 * we may match if the leaf we wound up at is
		 * a route to a net.
		 */

		if (t->rn_flags & RNF_NORMAL) {
			if ((rn_bit <= t->rn_bit) &&
			    RN_MATCHF(t, rn_leaf_fn, rn_leaf_arg)) {
				return (t);
			}
		} else if (rn_satisfies_leaf(v, t, matched_off, rn_leaf_fn,
		    rn_leaf_arg)) {
			return (t);
		}
	}
	t = saved_t;
	/* start searching up the tree */
	do {
		struct radix_mask *m;

		t = t->rn_parent;
		m = t->rn_mklist;
		/*
		 * If non-contiguous masks ever become important
		 * we can restore the masking and open coding of
		 * the search and satisfaction test and put the
		 * calculation of "off" back before the "do".
		 */
		while (m) {
			if (m->rm_flags & RNF_NORMAL) {
				if ((rn_bit <= m->rm_bit) &&
				    RN_MATCHF(m->rm_leaf, rn_leaf_fn,
				    rn_leaf_arg)) {
					return (m->rm_leaf);
				}
			} else {
				off = min(t->rn_offset, matched_off);
				x = rn_search_m(v, t, m->rm_mask);
				while (x != NULL && x->rn_mask != m->rm_mask)
					x = x->rn_dupedkey;
				if (x && rn_satisfies_leaf(v, x, off,
				    rn_leaf_fn, rn_leaf_arg)) {
					return (x);
				}
			}
			m = m->rm_mklist;
		}
	} while (t != top);
	return (0);
}

/*
 * Whenever we add a new leaf to the tree, we also add a parent node,
 * so we allocate them as an array of two elements: the first one must be
 * the leaf (see RNTORT() in route.c), the second one is the parent.
 * This routine initializes the relevant fields of the nodes, so that
 * the leaf is the left child of the parent node, and both nodes have
 * (almost) all all fields filled as appropriate.
 * The function returns a pointer to the parent node.
 */

static struct radix_node *
rn_newpair(v, b, nodes)
	void *v;
	int b;
	struct radix_node nodes[2];
{
	struct radix_node *tt = nodes, *t = tt + 1;

	t->rn_bit = b;
	t->rn_bmask = 0x80 >> (b & 7);
	t->rn_left = tt;
	t->rn_offset = b >> 3;

	/*
	 * t->rn_parent, r->rn_right, tt->rn_mask, tt->rn_dupedkey
	 * and tt->rn_bmask must have been zeroed by caller.
	 */
	tt->rn_bit = -1;
	tt->rn_key = v;
	tt->rn_parent = t;
	tt->rn_flags = t->rn_flags = RNF_ACTIVE;
	tt->rn_mklist = t->rn_mklist = 0;
	return (t);
}

static struct radix_node *
rn_insert(v_arg, head, dupentry, nodes)
	void *v_arg;
	struct radix_node_head *head;
	int *dupentry;
	struct radix_node nodes[2];
{
	caddr_t v = v_arg;
	struct radix_node *top = head->rnh_treetop;
	int head_off = top->rn_offset, vlen = (int)LEN(v);
	struct radix_node *t = rn_search(v_arg, top);
	caddr_t cp = v + head_off;
	int b;
	struct radix_node *tt;

	/*
	 * Find first bit at which v and t->rn_key differ
	 */
	{
		caddr_t cp2 = t->rn_key + head_off;
		int cmp_res;
		caddr_t cplim = v + vlen;

		while (cp < cplim)
			if (*cp2++ != *cp++)
				goto on1;
		*dupentry = 1;
		return (t);
on1:
		*dupentry = 0;
		cmp_res = (cp[-1] ^ cp2[-1]) & 0xff;
		for (b = (cp - v) << 3; cmp_res; b--)
			cmp_res >>= 1;
	}
	{
		struct radix_node *p, *x = top;
		cp = v;
		do {
			p = x;
			if (cp[x->rn_offset] & x->rn_bmask)
				x = x->rn_right;
			else
				x = x->rn_left;
		} while (b > (unsigned)x->rn_bit);
				/* x->rn_bit < b && x->rn_bit >= 0 */
		t = rn_newpair(v_arg, b, nodes);
		tt = t->rn_left;
		if ((cp[p->rn_offset] & p->rn_bmask) == 0)
			p->rn_left = t;
		else
			p->rn_right = t;
		x->rn_parent = t;
		t->rn_parent = p;
		if ((cp[t->rn_offset] & t->rn_bmask) == 0) {
			t->rn_right = x;
		} else {
			t->rn_right = tt;
			t->rn_left = x;
		}
	}
	return (tt);
}

static struct radix_node *
rn_addmask(n_arg, search, skip)
	int search, skip;
	void *n_arg;
{
	caddr_t netmask = (caddr_t)n_arg;
	struct radix_node *x;
	caddr_t cp, cplim;
	int b = 0, mlen, j;
	int maskduplicated, m0, isnormal;
	struct radix_node *saved_x;
	int last_zeroed = 0;
	char addmask_key[MAX_KEYLEN];

	if ((mlen = LEN(netmask)) > max_keylen)
		mlen = max_keylen;
	if (skip == 0)
		skip = 1;
	if (mlen <= skip)
		return (mask_rnhead->rnh_nodes);
	if (skip > 1)
		bcopy(rn_ones + 1, addmask_key + 1, skip - 1);
	if ((m0 = mlen) > skip)
		bcopy(netmask + skip, addmask_key + skip, mlen - skip);
	/*
	 * Trim trailing zeroes.
	 */
	for (cp = addmask_key + mlen; (cp > addmask_key) && cp[-1] == 0; )
		cp--;
	mlen = cp - addmask_key;
	if (mlen <= skip) {
		if (m0 >= last_zeroed)
			last_zeroed = mlen;
		return (mask_rnhead->rnh_nodes);
	}
	if (m0 < last_zeroed)
		bzero(addmask_key + m0, last_zeroed - m0);
	*addmask_key = last_zeroed = mlen;
	x = rn_search(addmask_key, rn_masktop);
	if (bcmp(addmask_key, x->rn_key, mlen) != 0)
		x = 0;
	if (x || search)
		return (x);
	R_Zalloc(x, radix_node_cache, max_keylen + 2 * sizeof (*x));

	if ((saved_x = x) == 0)
		return (0);
	netmask = cp = (caddr_t)(x + 2);
	bcopy(addmask_key, cp, mlen);
	x = rn_insert(cp, mask_rnhead, &maskduplicated, x);
	if (maskduplicated) {
#ifdef	_KERNEL
		cmn_err(CE_WARN, "rn_addmask: mask impossibly already in tree");
#else
		syslog(LOG_ERR, "rn_addmask: mask impossibly already in tree");
#endif	/* _KERNEL */
		Free(saved_x, radix_node_cache);
		return (x);
	}
	/*
	 * Calculate index of mask, and check for normalcy.
	 * First find the first byte with a 0 bit, then if there are
	 * more bits left (remember we already trimmed the trailing 0's),
	 * the pattern must be one of those in normal_chars[], or we have
	 * a non-contiguous mask.
	 */
	cplim = netmask + mlen;
	isnormal = 1;
	for (cp = netmask + skip; (cp < cplim) && *(uchar_t *)cp == 0xff; )
		cp++;
	if (cp != cplim) {
		static uint8_t normal_chars[] = {
			0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};

		for (j = 0x80; (j & *cp) != 0; j >>= 1)
			b++;
		if (*cp != normal_chars[b] || cp != (cplim - 1))
			isnormal = 0;
	}
	b += (cp - netmask) << 3;
	x->rn_bit = -1 - b;
	if (isnormal)
		x->rn_flags |= RNF_NORMAL;
	return (x);
}

/* arbitrary ordering for non-contiguous masks */
static boolean_t
rn_lexobetter(m_arg, n_arg)
	void *m_arg, *n_arg;
{
	uchar_t *mp = m_arg, *np = n_arg, *lim;

	if (LEN(mp) > LEN(np))
		/* not really, but need to check longer one first */
		return (B_TRUE);
	if (LEN(mp) == LEN(np))
		for (lim = mp + LEN(mp); mp < lim; )
			if (*mp++ > *np++)
				return (B_TRUE);
	return (B_FALSE);
}

static struct radix_mask *
rn_new_radix_mask(tt, next)
	struct radix_node *tt;
	struct radix_mask *next;
{
	struct radix_mask *m;

	MKGet(m);
	if (m == 0) {
#ifndef	_KERNEL
		syslog(LOG_ERR, "Mask for route not entered\n");
#endif	/* _KERNEL */
		return (0);
	}
	bzero(m, sizeof (*m));
	m->rm_bit = tt->rn_bit;
	m->rm_flags = tt->rn_flags;
	if (tt->rn_flags & RNF_NORMAL)
		m->rm_leaf = tt;
	else
		m->rm_mask = tt->rn_mask;
	m->rm_mklist = next;
	tt->rn_mklist = m;
	return (m);
}

static struct radix_node *
rn_addroute(v_arg, n_arg, head, treenodes)
	void *v_arg, *n_arg;
	struct radix_node_head *head;
	struct radix_node treenodes[2];
{
	caddr_t v = (caddr_t)v_arg, netmask = (caddr_t)n_arg;
	struct radix_node *t, *x = 0, *tt;
	struct radix_node *saved_tt, *top = head->rnh_treetop;
	short b = 0, b_leaf = 0;
	int keyduplicated;
	caddr_t mmask;
	struct radix_mask *m, **mp;

	/*
	 * In dealing with non-contiguous masks, there may be
	 * many different routes which have the same mask.
	 * We will find it useful to have a unique pointer to
	 * the mask to speed avoiding duplicate references at
	 * nodes and possibly save time in calculating indices.
	 */
	if (netmask)  {
		if ((x = rn_addmask(netmask, 0, top->rn_offset)) == 0)
			return (0);
		b_leaf = x->rn_bit;
		b = -1 - x->rn_bit;
		netmask = x->rn_key;
	}
	/*
	 * Deal with duplicated keys: attach node to previous instance
	 */
	saved_tt = tt = rn_insert(v, head, &keyduplicated, treenodes);
	if (keyduplicated) {
		for (t = tt; tt; t = tt, tt = tt->rn_dupedkey) {
			if (tt->rn_mask == netmask)
				return (0);
			if (netmask == 0 ||
			    (tt->rn_mask &&
			    /* index (netmask) > node */
			    ((b_leaf < tt->rn_bit) ||
			    rn_refines(netmask, tt->rn_mask) ||
			    rn_lexobetter(netmask, tt->rn_mask))))
				break;
		}
		/*
		 * If the mask is not duplicated, we wouldn't
		 * find it among possible duplicate key entries
		 * anyway, so the above test doesn't hurt.
		 *
		 * We sort the masks for a duplicated key the same way as
		 * in a masklist -- most specific to least specific.
		 * This may require the unfortunate nuisance of relocating
		 * the head of the list.
		 *
		 * We also reverse, or doubly link the list through the
		 * parent pointer.
		 */
		if (tt == saved_tt) {
			struct	radix_node *xx = x;
			/* link in at head of list */
			(tt = treenodes)->rn_dupedkey = t;
			tt->rn_flags = t->rn_flags;
			tt->rn_parent = x = t->rn_parent;
			t->rn_parent = tt; /* parent */
			if (x->rn_left == t)
				x->rn_left = tt;
			else
				x->rn_right = tt;
			saved_tt = tt; x = xx;
		} else {
			(tt = treenodes)->rn_dupedkey = t->rn_dupedkey;
			t->rn_dupedkey = tt;
			/* Set rn_parent value for tt and tt->rn_dupedkey */
			tt->rn_parent = t;
			if (tt->rn_dupedkey)
				tt->rn_dupedkey->rn_parent = tt;
		}
		tt->rn_key = v;
		tt->rn_bit = -1;
		tt->rn_flags = RNF_ACTIVE;
	}
	/*
	 * Put mask in tree.
	 */
	if (netmask) {
		tt->rn_mask = netmask;
		tt->rn_bit = x->rn_bit;
		tt->rn_flags |= x->rn_flags & RNF_NORMAL;
	}
	t = saved_tt->rn_parent;
	if (keyduplicated)
		goto key_exists;
	b_leaf = -1 - t->rn_bit;
	if (t->rn_right == saved_tt)
		x = t->rn_left;
	else
		x = t->rn_right;
	/* Promote general routes from below */
	if (x->rn_bit < 0) {
	    for (mp = &t->rn_mklist; x; x = x->rn_dupedkey)
		if (x->rn_mask && (x->rn_bit >= b_leaf) && x->rn_mklist == 0) {
			*mp = m = rn_new_radix_mask(x, 0);
			if (m)
				mp = &m->rm_mklist;
		}
	} else if (x->rn_mklist) {
		/*
		 * Skip over masks whose index is > that of new node
		 */
		for (mp = &x->rn_mklist; (m = *mp) != NULL; mp = &m->rm_mklist)
			if (m->rm_bit >= b_leaf)
				break;
		t->rn_mklist = m; *mp = 0;
	}
key_exists:
	/* Add new route to highest possible ancestor's list */
	if ((netmask == 0) || (b > t->rn_bit))
		return (tt); /* can't lift at all */
	b_leaf = tt->rn_bit;
	do {
		x = t;
		t = t->rn_parent;
	} while (b <= t->rn_bit && x != top);
	/*
	 * Search through routes associated with node to
	 * insert new route according to index.
	 * Need same criteria as when sorting dupedkeys to avoid
	 * double loop on deletion.
	 */
	for (mp = &x->rn_mklist; (m = *mp) != NULL; mp = &m->rm_mklist) {
		if (m->rm_bit < b_leaf)
			continue;
		if (m->rm_bit > b_leaf)
			break;
		if (m->rm_flags & RNF_NORMAL) {
			mmask = m->rm_leaf->rn_mask;
			if (tt->rn_flags & RNF_NORMAL) {
#ifdef	_KERNEL
				cmn_err(CE_WARN, "Non-unique normal route, "
				    "mask not entered\n");
#else
				syslog(LOG_ERR, "Non-unique normal route, "
				    "mask not entered\n");
#endif	/* _KERNEL */
				return (tt);
			}
		} else
			mmask = m->rm_mask;
		if (mmask == netmask) {
			m->rm_refs++;
			tt->rn_mklist = m;
			return (tt);
		}
		if (rn_refines(netmask, mmask) ||
		    rn_lexobetter(netmask, mmask))
			break;
	}
	*mp = rn_new_radix_mask(tt, *mp);
	return (tt);
}

static struct radix_node *
rn_delete(v_arg, netmask_arg, head)
	void *v_arg, *netmask_arg;
	struct radix_node_head *head;
{
	struct radix_node *t, *p, *x, *tt;
	struct radix_mask *m, *saved_m, **mp;
	struct radix_node *dupedkey, *saved_tt, *top;
	caddr_t v, netmask;
	int b, head_off, vlen;

	v = v_arg;
	netmask = netmask_arg;
	x = head->rnh_treetop;
	tt = rn_search(v, x);
	head_off = x->rn_offset;
	vlen =  LEN(v);
	saved_tt = tt;
	top = x;
	if (tt == 0 ||
	    bcmp(v + head_off, tt->rn_key + head_off, vlen - head_off))
		return (0);
	/*
	 * Delete our route from mask lists.
	 */
	if (netmask) {
		if ((x = rn_addmask(netmask, 1, head_off)) == 0)
			return (0);
		netmask = x->rn_key;
		while (tt->rn_mask != netmask)
			if ((tt = tt->rn_dupedkey) == 0)
				return (0);
	}
	if (tt->rn_mask == 0 || (saved_m = m = tt->rn_mklist) == 0)
		goto on1;
	if (tt->rn_flags & RNF_NORMAL) {
		if (m->rm_leaf != tt || m->rm_refs > 0) {
#ifdef	_KERNEL
			cmn_err(CE_WARN,
			    "rn_delete: inconsistent annotation\n");
#else
			syslog(LOG_ERR, "rn_delete: inconsistent annotation\n");
#endif	/* _KERNEL */
			return (0);  /* dangling ref could cause disaster */
		}
	} else {
		if (m->rm_mask != tt->rn_mask) {
#ifdef	_KERNEL
			cmn_err(CE_WARN,
			    "rn_delete: inconsistent annotation 2\n");
#else
			syslog(LOG_ERR,
			    "rn_delete: inconsistent annotation 2\n");
#endif	/* _KERNEL */
			goto on1;
		}
		if (--m->rm_refs >= 0)
			goto on1;
	}
	b = -1 - tt->rn_bit;
	t = saved_tt->rn_parent;
	if (b > t->rn_bit)
		goto on1; /* Wasn't lifted at all */
	do {
		x = t;
		t = t->rn_parent;
	} while (b <= t->rn_bit && x != top);
	for (mp = &x->rn_mklist; (m = *mp) != NULL; mp = &m->rm_mklist)
		if (m == saved_m) {
			*mp = m->rm_mklist;
			MKFree(m);
			break;
		}
	if (m == 0) {
#ifdef	_KERNEL
		cmn_err(CE_WARN, "rn_delete: couldn't find our annotation\n");
#else
		syslog(LOG_ERR, "rn_delete: couldn't find our annotation\n");
#endif	/* _KERNEL */
		if (tt->rn_flags & RNF_NORMAL)
			return (0); /* Dangling ref to us */
	}
on1:
	/*
	 * Eliminate us from tree
	 */
	if (tt->rn_flags & RNF_ROOT)
		return (0);
	t = tt->rn_parent;
	dupedkey = saved_tt->rn_dupedkey;
	if (dupedkey) {
		/*
		 * Here, tt is the deletion target and
		 * saved_tt is the head of the dupekey chain.
		 */
		if (tt == saved_tt) {
			/* remove from head of chain */
			x = dupedkey; x->rn_parent = t;
			if (t->rn_left == tt)
				t->rn_left = x;
			else
				t->rn_right = x;
		} else {
			/* find node in front of tt on the chain */
			for (x = p = saved_tt; p && p->rn_dupedkey != tt; )
				p = p->rn_dupedkey;
			if (p) {
				p->rn_dupedkey = tt->rn_dupedkey;
				if (tt->rn_dupedkey)		/* parent */
					tt->rn_dupedkey->rn_parent = p;
								/* parent */
			} else
#ifdef	_KERNEL
				cmn_err(CE_WARN,
				    "rn_delete: couldn't find us\n");
#else
				syslog(LOG_ERR,
				    "rn_delete: couldn't find us\n");
#endif	/* _KERNEL */
		}
		t = tt + 1;
		if (t->rn_flags & RNF_ACTIVE) {
			*++x = *t;
			p = t->rn_parent;
			if (p->rn_left == t)
				p->rn_left = x;
			else
				p->rn_right = x;
			x->rn_left->rn_parent = x;
			x->rn_right->rn_parent = x;
		}
		goto out;
	}
	if (t->rn_left == tt)
		x = t->rn_right;
	else
		x = t->rn_left;
	p = t->rn_parent;
	if (p->rn_right == t)
		p->rn_right = x;
	else
		p->rn_left = x;
	x->rn_parent = p;
	/*
	 * Demote routes attached to us.
	 */
	if (t->rn_mklist) {
		if (x->rn_bit >= 0) {
			for (mp = &x->rn_mklist; (m = *mp) != NULL; )
				mp = &m->rm_mklist;
			*mp = t->rn_mklist;
		} else {
			/*
			 * If there are any key,mask pairs in a sibling
			 * duped-key chain, some subset will appear sorted
			 * in the same order attached to our mklist
			 */
			for (m = t->rn_mklist; m && x; x = x->rn_dupedkey)
				if (m == x->rn_mklist) {
					struct radix_mask *mm = m->rm_mklist;
					x->rn_mklist = 0;
					if (--(m->rm_refs) < 0)
						MKFree(m);
					m = mm;
				}
			if (m)
#ifdef	_KERNEL
				cmn_err(CE_WARN,
				    "rn_delete: Orphaned Mask %p at %p\n",
				    (void *)m, (void *)x);
#else
				syslog(LOG_ERR,
				    "rn_delete: Orphaned Mask %p at %p\n",
				    (void *)m, (void *)x);
#endif	/* _KERNEL */
		}
	}
	/*
	 * We may be holding an active internal node in the tree.
	 */
	x = tt + 1;
	if (t != x) {
		*t = *x;
		t->rn_left->rn_parent = t;
		t->rn_right->rn_parent = t;
		p = x->rn_parent;
		if (p->rn_left == x)
			p->rn_left = t;
		else
			p->rn_right = t;
	}
out:
	tt->rn_flags &= ~RNF_ACTIVE;
	tt[1].rn_flags &= ~RNF_ACTIVE;
	return (tt);
}

/*
 * Walk the radix tree; For the kernel routing table, we hold additional
 * refs on the ire_bucket to ensure that the walk function f() does not
 * run into trashed memory. The kernel routing table is identified by
 * a rnh_treetop that has RNF_SUNW_FT set in the rn_flags.
 * Note that all refs takein in rn_walktree are released before it returns,
 * so that f() will need to take any additional references on memory
 * to be passed back to the caller of rn_walktree.
 */
static int
rn_walktree(h, f, w)
	struct radix_node_head *h;
	walktree_f_t *f;
	void *w;
{
	return (rn_walktree_mt(h, f, w, NULL, NULL));
}
static int
rn_walktree_mt(h, f, w, lockf, unlockf)
	struct radix_node_head *h;
	walktree_f_t *f;
	void *w;
	lockf_t lockf, unlockf;
{
	int error;
	struct radix_node *base, *next;
	struct radix_node *rn = h->rnh_treetop;
	boolean_t is_mt = B_FALSE;

	if (lockf != NULL) {
		ASSERT(unlockf != NULL);
		is_mt = B_TRUE;
	}
	/*
	 * This gets complicated because we may delete the node
	 * while applying the function f to it, so we need to calculate
	 * the successor node in advance.
	 */
	RADIX_NODE_HEAD_RLOCK(h);
	/* First time through node, go left */
	while (rn->rn_bit >= 0) {
		rn = rn->rn_left;
	}

	if (is_mt)
		(*lockf)(rn);

	for (;;) {
		base = rn;
		/* If at right child go back up, otherwise, go right */
		while (rn->rn_parent->rn_right == rn &&
		    (rn->rn_flags & RNF_ROOT) == 0) {
			rn = rn->rn_parent;
		}
		/* Find the next *leaf* since next node might vanish, too */
		for (rn = rn->rn_parent->rn_right; rn->rn_bit >= 0; ) {
			rn = rn->rn_left;
		}
		next = rn;

		if (is_mt && next != NULL)
			(*lockf)(next);

		/* Process leaves */
		while ((rn = base) != NULL) {
			base = rn->rn_dupedkey;

			if (is_mt && base != NULL)
				(*lockf)(base);

			RADIX_NODE_HEAD_UNLOCK(h);
			if (!(rn->rn_flags & RNF_ROOT) &&
			    (error = (*f)(rn, w))) {
				if (is_mt) {
					(*unlockf)(rn);
					if (base != NULL)
						(*unlockf)(base);
					if (next != NULL)
						(*unlockf)(next);
				}
				return (error);
			}
			if (is_mt)
				(*unlockf)(rn);
			RADIX_NODE_HEAD_RLOCK(h);
		}
		rn = next;
		if (rn->rn_flags & RNF_ROOT) {
			RADIX_NODE_HEAD_UNLOCK(h);
			/*
			 * no ref to release, since we never take a ref
			 * on the root node- it can't be deleted.
			 */
			return (0);
		}
	}
	/* NOTREACHED */
}

/*
 * Allocate and initialize an empty tree. This has 3 nodes, which are
 * part of the radix_node_head (in the order <left,root,right>) and are
 * marked RNF_ROOT so they cannot be freed.
 * The leaves have all-zero and all-one keys, with significant
 * bits starting at 'off'.
 * Return 1 on success, 0 on error.
 */
int
rn_inithead(head, off)
	void **head;
	int off;
{
	struct radix_node_head *rnh;
	struct radix_node *t, *tt, *ttt;
	if (*head)
		return (1);
	R_ZallocSleep(rnh, struct radix_node_head *, sizeof (*rnh));
	if (rnh == 0)
		return (0);
#ifdef _KERNEL
	RADIX_NODE_HEAD_LOCK_INIT(rnh);
#endif
	*head = rnh;
	t = rn_newpair(rn_zeros, off, rnh->rnh_nodes);
	ttt = rnh->rnh_nodes + 2;
	t->rn_right = ttt;
	t->rn_parent = t;
	tt = t->rn_left;	/* ... which in turn is rnh->rnh_nodes */
	tt->rn_flags = t->rn_flags = RNF_ROOT | RNF_ACTIVE;
	tt->rn_bit = -1 - off;
	*ttt = *tt;
	ttt->rn_key = rn_ones;
	rnh->rnh_addaddr = rn_addroute;
	rnh->rnh_deladdr = rn_delete;
	rnh->rnh_matchaddr = rn_match;
	rnh->rnh_matchaddr_args = rn_match_args;
	rnh->rnh_lookup = rn_lookup;
	rnh->rnh_walktree = rn_walktree;
	rnh->rnh_walktree_mt = rn_walktree_mt;
	rnh->rnh_walktree_from = NULL;  /* not implemented */
	rnh->rnh_treetop = t;
	return (1);
}

void
rn_init()
{
	char *cp, *cplim;

#ifdef	_KERNEL
	radix_mask_cache = kmem_cache_create("radix_mask",
	    sizeof (struct radix_mask), 0, NULL, NULL, NULL, NULL, NULL, 0);
	radix_node_cache = kmem_cache_create("radix_node",
	    max_keylen + 2 * sizeof (struct radix_node),
	    0, NULL, NULL, NULL, NULL, NULL, 0);
#endif /* _KERNEL */
	R_ZallocSleep(rn_zeros, char *, 2 * max_keylen);

	ASSERT(rn_zeros != NULL);
	bzero(rn_zeros, 2 * max_keylen);
	rn_ones = cp = rn_zeros + max_keylen;
	cplim = rn_ones + max_keylen;
	while (cp < cplim)
		*cp++ = -1;
	if (rn_inithead((void **)(void *)&mask_rnhead, 0) == 0)
		panic("rn_init: could not init mask_rnhead ");
}

int
rn_freenode(n, p)
	struct radix_node *n;
	void *p;
{
	struct	radix_node_head *rnh = p;
	struct	radix_node *d;

	d = rnh->rnh_deladdr(n->rn_key, NULL, rnh);
	if (d != NULL) {
		Free(d, radix_node_cache);
	}
	return (0);
}


void
rn_freehead(rnh)
	struct radix_node_head *rnh;
{
	(void) rn_walktree(rnh, rn_freenode, rnh);

	rnh->rnh_addaddr = NULL;
	rnh->rnh_deladdr = NULL;
	rnh->rnh_matchaddr = NULL;
	rnh->rnh_lookup = NULL;
	rnh->rnh_walktree = NULL;

#ifdef	_KERNEL
	RADIX_NODE_HEAD_DESTROY(rnh);
	FreeHead(rnh, sizeof (*rnh));
#else
	Free(rnh, NULL);
#endif	/* _KERNEL */
}

void
rn_fini()
{
	struct radix_mask *m;

	if (rn_zeros != NULL) {
#ifdef _KERNEL
		FreeHead(rn_zeros, 2 * max_keylen);
#else
		Free(rn_zeros, NULL);
#endif
		rn_zeros = NULL;
	}


	if (mask_rnhead != NULL) {
		rn_freehead(mask_rnhead);
		mask_rnhead = NULL;
	}

	while ((m = rn_mkfreelist) != NULL) {
		rn_mkfreelist = m->rm_mklist;
		Free(m, NULL);
	}
}
