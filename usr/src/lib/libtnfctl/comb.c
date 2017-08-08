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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

/*
 * Functions that know how to create and decode combinations that are
 * used for connecting probe functions.
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <assert.h>
#include <sys/types.h>

#include "tnfctl_int.h"
#include "dbg.h"


/*
 * Typedefs
 */

typedef struct comb_callinfo {
	unsigned	offset;
	unsigned	shift;	/* shift right <n> bits */
	unsigned	mask;

} comb_callinfo_t;

typedef struct comb_calltmpl {
	uintptr_t	entry;
	uintptr_t	down;
	uintptr_t	next;
	uintptr_t	end;

} comb_calltmpl_t;

typedef struct comb_key {
	comb_op_t	op;
	uintptr_t	down;
	uintptr_t	next;
	uintptr_t	comb;
} comb_key_t;

typedef struct decode_key {
	uintptr_t	addr;
	char		**name_ptrs;
	uintptr_t	*func_addrs;
} decode_key_t;


/*
 * Global - defined in assembler file
 */
extern comb_callinfo_t prb_callinfo;

extern void	 prb_chain_entry(void);
extern void	 prb_chain_down(void);
extern void	 prb_chain_next(void);
extern void	 prb_chain_end(void);

static comb_calltmpl_t calltmpl[PRB_COMB_COUNT] = {
{
		(uintptr_t)prb_chain_entry,
		(uintptr_t)prb_chain_down,
		(uintptr_t)prb_chain_next,
		(uintptr_t)prb_chain_end}
};

/*
 * Declarations
 */

static tnfctl_errcode_t decode(tnfctl_handle_t *hndl, uintptr_t addr,
	char ***func_names, uintptr_t **func_addrs);
static boolean_t find(tnfctl_handle_t *hndl, comb_op_t op, uintptr_t down,
	uintptr_t next, uintptr_t *comb_p);
static tnfctl_errcode_t build(tnfctl_handle_t *hndl, comb_op_t op,
	uintptr_t down, uintptr_t next, uintptr_t *comb_p);
static tnfctl_errcode_t add(tnfctl_handle_t *hndl, comb_op_t op, uintptr_t down,
	uintptr_t next, uintptr_t comb);
static int comb_compare(const void *a, const void *b);
static int decode_compare(const void *v0p, const void *v1p);
static tnfctl_errcode_t iscomb(tnfctl_handle_t *hndl, uintptr_t addr,
	uintptr_t *down_p, uintptr_t *next_p, boolean_t *ret_val);
static tnfctl_errcode_t findname(tnfctl_handle_t *hndl, uintptr_t addr,
	char **ret_name);


/* ---------------------------------------------------------------- */
/* ----------------------- Public Functions ----------------------- */
/* ---------------------------------------------------------------- */

/*
 * _tnfctl_comb_build() - finds (or builds) a combination satisfing the op,
 * down and next constraints of the caller.
 */
tnfctl_errcode_t
_tnfctl_comb_build(tnfctl_handle_t *hndl, comb_op_t op,
    uintptr_t down, uintptr_t next, uintptr_t *comb_p)
{
	tnfctl_errcode_t	prexstat;

	*comb_p = NULL;

	DBG_TNF_PROBE_0(_tnfctl_comb_build_start, "libtnfctl",
	    "start _tnfctl_comb_build; sunw%verbosity 1");

	if (find(hndl, op, down, next, comb_p)) {

		DBG_TNF_PROBE_1(_tnfctl_comb_build_end, "libtnfctl",
		    "end _tnfctl_comb_build; sunw%verbosity 1",
		    tnf_opaque, found_comb_at, *comb_p);

		return (TNFCTL_ERR_NONE);
	}
	prexstat = build(hndl, op, down, next, comb_p);

	DBG_TNF_PROBE_1(_tnfctl_comb_build_end, "libtnfctl",
	    "end _tnfctl_comb_build; sunw%verbosity 1",
	    tnf_opaque, built_comb_at, *comb_p);

	return (prexstat);
}


/*
 * _tnfctl_comb_decode() - returns a string describing the probe functions
 * NOTE - the string is for reference purposes ONLY, it should not be freed
 * by the client.
 */
tnfctl_errcode_t
_tnfctl_comb_decode(tnfctl_handle_t *hndl, uintptr_t addr, char ***func_names,
    uintptr_t **func_addrs)
{
	tnfctl_errcode_t prexstat;

	DBG_TNF_PROBE_0(_tnfctl_comb_decode_start, "libtnfctl",
	    "start _tnfctl_comb_decode; sunw%verbosity 2");

	prexstat = decode(hndl, addr, func_names, func_addrs);

	DBG_TNF_PROBE_0(_tnfctl_comb_decode_end, "libtnfctl",
	    "end _tnfctl_comb_decode; sunw%verbosity 2");

	return (prexstat);
}


/* ---------------------------------------------------------------- */
/* ----------------------- Private Functions ---------------------- */
/* ---------------------------------------------------------------- */

/*
 * if combination has been decoded, return decoded info., else
 * decode combination and cache information
 */
static tnfctl_errcode_t
decode(tnfctl_handle_t *hndl, uintptr_t addr, char ***func_names,
    uintptr_t **func_addrs)
{
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	decode_key_t	key;
	decode_key_t	*new_p = NULL;
	decode_key_t	**find_pp;
	uintptr_t	down;
	uintptr_t	next;
	char 		*thisname = NULL;
	boolean_t	is_combination;

	/* see if we can find the previously decoded answer */
	key.addr = addr;
	find_pp = (decode_key_t **)tfind(&key, &hndl->decoderoot,
	    decode_compare);
	if (find_pp) {
		DBG_TNF_PROBE_0(decode_1, "libtnfctl",
		    "sunw%verbosity 2; sunw%debug 'found existing'");
		*func_names = (*find_pp)->name_ptrs;
		*func_addrs = (*find_pp)->func_addrs;
		return (TNFCTL_ERR_NONE);
	}

	new_p = calloc(1, sizeof (decode_key_t));
	if (!new_p)
		return (TNFCTL_ERR_ALLOCFAIL);
	new_p->addr = addr;

	prexstat = iscomb(hndl, addr, &down, &next, &is_combination);
	if (prexstat)
		goto Error;

	if (is_combination) {
		char **nextnames;
		uintptr_t *nextaddrs;
		char **name_pp;
		uintptr_t *addr_p;
		int count, j;

		DBG_TNF_PROBE_2(decode_2, "libtnfctl", "sunw%verbosity 2;",
		    tnf_opaque, down, down, tnf_opaque, next, next);

		prexstat = findname(hndl, down, &thisname);
		if (prexstat == TNFCTL_ERR_USR1) {
			/*
			 * should never happen - combination should not
			 * point at the end function
			 */
			prexstat = TNFCTL_ERR_INTERNAL;
			goto Error;
		} else if (prexstat)
			goto Error;

		prexstat = decode(hndl, next, &nextnames, &nextaddrs);
		if (prexstat)
			goto Error;

		/* count number of elements - caution: empty 'for' loop */
		for (count = 0; nextnames[count]; count++)
			;
		count++;	/* since it was 0 based */

		/* allocate one more for new function name */
		new_p->name_ptrs = malloc((count + 1) *
		    sizeof (new_p->name_ptrs[0]));
		if (new_p->name_ptrs == NULL) {
			prexstat = TNFCTL_ERR_ALLOCFAIL;
			goto Error;
		}
		new_p->func_addrs = malloc((count + 1) *
		    sizeof (new_p->func_addrs[0]));
		if (new_p->func_addrs == NULL) {
			prexstat = TNFCTL_ERR_ALLOCFAIL;
			goto Error;
		}
		name_pp = new_p->name_ptrs;
		addr_p = new_p->func_addrs;
		addr_p[0] = down;
		name_pp[0] = thisname;
		for (j = 0; j < count; j++) {
			name_pp[j + 1] = nextnames[j];
			addr_p[j + 1] = nextaddrs[j];
		}
	} else {
		prexstat = findname(hndl, addr, &thisname);
		if (prexstat != TNFCTL_ERR_USR1) {
			/*
			 * base case - end function is the only function
			 * that can be pointed at directly
			 */
			if (prexstat == TNFCTL_ERR_NONE)
				prexstat = TNFCTL_ERR_NONE;
			goto Error;
		}
		new_p->name_ptrs = malloc(sizeof (new_p->name_ptrs[0]));
		if (new_p->name_ptrs == NULL) {
			prexstat = TNFCTL_ERR_ALLOCFAIL;
			goto Error;
		}
		new_p->func_addrs = malloc(sizeof (new_p->func_addrs[0]));
		if (new_p->func_addrs == NULL) {
			prexstat = TNFCTL_ERR_ALLOCFAIL;
			goto Error;
		}
		new_p->name_ptrs[0] = NULL;
		new_p->func_addrs[0] = NULL;
	}

	DBG_TNF_PROBE_1(decode_3, "libtnfctl",
	    "sunw%verbosity 2; sunw%debug 'decode built'",
	    tnf_string, func_name, (thisname) ? (thisname) : "end_func");

	find_pp = (decode_key_t **)tsearch(new_p, &hndl->decoderoot,
	    decode_compare);
	assert(*find_pp == new_p);
	*func_names = new_p->name_ptrs;
	*func_addrs = new_p->func_addrs;
	return (TNFCTL_ERR_NONE);

Error:
	if (new_p) {
		if (new_p->name_ptrs)
			free(new_p->name_ptrs);
		if (new_p->func_addrs)
			free(new_p->func_addrs);
		free(new_p);
	}
	return (prexstat);
}


/*
 * iscomb() - determine whether the pointed to function is a combination.  If
 * it is, return the down and next pointers
 */
static tnfctl_errcode_t
iscomb(tnfctl_handle_t *hndl, uintptr_t addr, uintptr_t *down_p,
    uintptr_t *next_p, boolean_t *ret_val)
{
	int		type;
	boolean_t	matched = B_FALSE;

	for (type = 0; type < PRB_COMB_COUNT; type++) {
		size_t		size;
		int		miscstat;
		char		*targ_p;
		char		*ptr;
		char		*tptr;
		uintptr_t	downaddr;
		uintptr_t	nextaddr;
		int		num_bits = 0;
		int		tmp_bits = prb_callinfo.mask;

		/* allocate room to copy the target code */
		size = (size_t)(calltmpl[type].end - calltmpl[type].entry);
		targ_p = malloc(size);
		if (!targ_p)
			return (TNFCTL_ERR_ALLOCFAIL);

		/* copy code from target */
		miscstat = hndl->p_read(hndl->proc_p, addr, targ_p, size);
		if (miscstat) {
			free(targ_p);
			return (TNFCTL_ERR_INTERNAL);
		}

		/* find the number of bits before the highest bit in mask */
		while (tmp_bits > 0) {
			num_bits++;
			tmp_bits <<= 1;
		}

		/* loop over all the words */
		tptr = (char *)calltmpl[type].entry;
		for (ptr = targ_p; ptr < (targ_p + size); ptr++, tptr++) {
			int			 downbits;
			int			 nextbits;
		/* LINTED pointer cast may result in improper alignment */
			int			*uptr = (int *)ptr;

			/*
			 * If we are pointing at one of the words that we
			 * patch, * (down or next displ) then read that value
			 * in. * Otherwise make sure the words match.
			 */
			if ((uintptr_t)tptr == calltmpl[type].down +
			    prb_callinfo.offset) {
				downbits = *uptr;
				downbits &= prb_callinfo.mask;
				/* sign extend */
				downbits  = (downbits << num_bits) >> num_bits;
				downbits <<= prb_callinfo.shift;
				downaddr = addr + (ptr - targ_p) + downbits;
#if defined(i386)
				downaddr += 4;
				/* intel is relative to *next* instruction */
#endif

				ptr += 3;
				tptr += 3;
			} else if ((uintptr_t)tptr == calltmpl[type].next +
			    prb_callinfo.offset) {
				nextbits = *uptr;
				nextbits &= prb_callinfo.mask;
				/* sign extend */
				nextbits  = (nextbits << num_bits) >> num_bits;
				nextbits <<= prb_callinfo.shift;
				nextaddr = addr + (ptr - targ_p) + nextbits;
#if defined(i386)
				nextaddr += 4;
				/* intel is relative to *next* instruction */
#endif

				ptr += 3;
				tptr += 3;
			} else {
				/* the byte better match or we bail */
				if (*ptr != *tptr)
					goto NextComb;
			}
		}

		/* YOWSA! - its a match */
		matched = B_TRUE;

NextComb:
		/* free allocated memory */
		if (targ_p)
			free(targ_p);

		if (matched) {
			*down_p = downaddr;
			*next_p = nextaddr;
			*ret_val = B_TRUE;
			return (TNFCTL_ERR_NONE);
		}
	}

	*ret_val = B_FALSE;
	return (TNFCTL_ERR_NONE);
}


#define	FUNC_BUF_SIZE	32
/*
 * findname() - find a name for a function given its address.
 */
static tnfctl_errcode_t
findname(tnfctl_handle_t *hndl, uintptr_t addr, char **ret_name)
{
	char		*symname;
	tnfctl_errcode_t prexstat;

	symname = NULL;
	prexstat = _tnfctl_sym_findname(hndl, addr, &symname);
	if ((prexstat == TNFCTL_ERR_NONE) && (symname != NULL)) {
		/* found a name */

		/*
		 * SPECIAL CASE
		 * If we find "tnf_trace_end" then we should not report it
		 * as this is the "end-cap" function and should be hidden
		 * from the user.  Return a null string instead ...
		 */
		if (strcmp(symname, TRACE_END_FUNC) == 0) {
			return (TNFCTL_ERR_USR1);
		} else {
			*ret_name = symname;
			return (TNFCTL_ERR_NONE);
		}
	} else {
		char *buffer;

		buffer = malloc(FUNC_BUF_SIZE);
		if (buffer == NULL)
			return (TNFCTL_ERR_ALLOCFAIL);

		/* no name found, use the address */
		(void) sprintf(buffer, "func@0x%p", addr);
		*ret_name = buffer;
		return (TNFCTL_ERR_NONE);
	}
}


/*
 * find() - try to find an existing combination that satisfies ...
 */
static boolean_t
find(tnfctl_handle_t *hndl, comb_op_t op, uintptr_t down, uintptr_t next,
    uintptr_t *comb_p)
{
	comb_key_t	key;
	comb_key_t	**find_pp;

	key.op = op;
	key.down = down;
	key.next = next;
	key.comb = NULL;

	find_pp = (comb_key_t **)tfind(&key, &hndl->buildroot, comb_compare);
	if (find_pp) {
		*comb_p = (*find_pp)->comb;
		return (B_TRUE);
	} else
		return (B_FALSE);
}


/*
 * add() - adds a combination to combination cache
 */
static tnfctl_errcode_t
add(tnfctl_handle_t *hndl, comb_op_t op, uintptr_t down, uintptr_t next,
    uintptr_t comb)
{
	comb_key_t	 *new_p;
	/* LINTED set but not used in function */
	comb_key_t	**ret_pp __unused;

	new_p = malloc(sizeof (comb_key_t));
	if (!new_p)
		return (TNFCTL_ERR_ALLOCFAIL);

	new_p->op = op;
	new_p->down = down;
	new_p->next = next;
	new_p->comb = comb;

	ret_pp = (comb_key_t **)tsearch(new_p, &hndl->buildroot,
	    comb_compare);
	assert(*ret_pp == new_p);
	return (TNFCTL_ERR_NONE);
}


/*
 * decode_compare() - comparison function used for tree search for
 * combinations
 */
static int
decode_compare(const void *v0p, const void *v1p)
{
	const decode_key_t   *k0p = v0p;
	const decode_key_t   *k1p = v1p;

	return (int)((uintptr_t)k1p->addr - (uintptr_t)k0p->addr);
}				/* end decode_compare */


/*
 * comb_compare() - comparison function used for tree search for combinations
 */
static int
comb_compare(const void *v0p, const void *v1p)
{
	const comb_key_t *k0p = v0p;
	const comb_key_t *k1p = v1p;

	if (k0p->op != k1p->op)
		return ((k0p->op < k1p->op) ? -1 : 1);

	if (k0p->down != k1p->down)
		return ((k0p->down < k1p->down) ? -1 : 1);

	if (k0p->next != k1p->next)
		return ((k0p->next < k1p->next) ? -1 : 1);

	return (0);

}				/* end comb_compare */

/*
 * build() - build a composition
 */
static tnfctl_errcode_t
build(tnfctl_handle_t *hndl, comb_op_t op, uintptr_t down, uintptr_t next,
    uintptr_t *comb_p)
{
	size_t		size;
	uintptr_t	addr;
	char		*buffer_p = NULL;
	uintptr_t	offset;
	uintptr_t	contents;
	unsigned	*word_p;
	int		miscstat;
	tnfctl_errcode_t	prexstat;

	*comb_p = NULL;
	size = calltmpl[op].end - calltmpl[op].entry;

	/* allocate memory in the target process */
	prexstat = _tnfctl_targmem_alloc(hndl, size, &addr);
	if (prexstat) {
		DBG((void) fprintf(stderr,
		    "build: trouble allocating target memory:\n"));
		goto Error;
	}

	/* allocate a scratch buffer, copy the template into it */
	buffer_p = malloc(size);
	if (!buffer_p) {
		DBG((void) fprintf(stderr, "build: alloc failed\n"));
		prexstat = TNFCTL_ERR_ALLOCFAIL;
		goto Error;
	}
	(void) memcpy(buffer_p, (void *) calltmpl[op].entry, size);

	/* poke the down address */
	offset = calltmpl[op].down - calltmpl[op].entry;
	/*LINTED pointer cast may result in improper alignment*/
	word_p = (unsigned *)(buffer_p + offset + prb_callinfo.offset);
	contents = down - (addr + offset);
#if defined(i386)
	contents -= 5;		/* intel offset is relative to *next* instr */
#endif

	DBG_TNF_PROBE_4(build_1, "libtnfctl", "sunw%verbosity 3",
	    tnf_opaque, down, down, tnf_opaque, contents, contents,
	    tnf_opaque, word_p, word_p, tnf_long, offset, offset);

	*word_p &= ~prb_callinfo.mask;	/* clear the relevant field */
	*word_p |= ((contents >> prb_callinfo.shift) & prb_callinfo.mask);

	/* poke the next address */
	offset = calltmpl[op].next - calltmpl[op].entry;
	/*LINTED pointer cast may result in improper alignment*/
	word_p = (unsigned *)(buffer_p + offset + prb_callinfo.offset);
	contents = next - (addr + offset);
#if defined(i386)
	contents -= 5;		/* intel offset is relative to *next* instr */
#endif

	DBG_TNF_PROBE_4(build_2, "libtnfctl", "sunw%verbosity 3",
	    tnf_opaque, next, next, tnf_opaque, contents, contents,
	    tnf_opaque, word_p, word_p, tnf_long, offset, offset);

	*word_p &= ~prb_callinfo.mask;	/* clear the relevant field */
	*word_p |= ((contents >> prb_callinfo.shift) & prb_callinfo.mask);

	/* copy the combination template into target memory */
	miscstat = hndl->p_write(hndl->proc_p, addr, buffer_p, size);
	if (miscstat) {
		DBG((void) fprintf(stderr,
		    "build: trouble writing combination: \n"));
		prexstat = TNFCTL_ERR_INTERNAL;
		goto Error;
	}
	*comb_p = addr;
	prexstat = add(hndl, op, down, next, addr);

Error:
	if (buffer_p)
		free(buffer_p);
	return (prexstat);
}
