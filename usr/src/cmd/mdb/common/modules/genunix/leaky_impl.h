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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LEAKY_IMPL_H
#define	_LEAKY_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	LK_NUM_TYPES	8		/* arbitrary */

#ifdef _KERNEL
typedef pc_t leak_pc_t;
#else
typedef uintptr_t leak_pc_t;
#endif

typedef struct leak_mtab {
	uintptr_t lkm_base;
	uintptr_t lkm_limit;
	uintptr_t lkm_bufctl;			/* target-defined */
} leak_mtab_t;

typedef struct leak_bufctl {
	struct leak_bufctl *lkb_hash_next;	/* internal use only */
	struct leak_bufctl *lkb_next;
	uintptr_t lkb_addr;			/* should be unique */
	uintptr_t lkb_bufaddr;
	uintptr_t lkb_data;
	uintptr_t lkb_cid;
	hrtime_t lkb_timestamp;
	int lkb_dups;
	uint8_t lkb_type;
	uint8_t lkb_depth;
	leak_pc_t lkb_stack[1];		/* actually lkb_depth */
} leak_bufctl_t;
#define	LEAK_BUFCTL_SIZE(d)	(OFFSETOF(leak_bufctl_t, lkb_stack[(d)]))

/*
 * callbacks for target to use
 */
extern void leaky_grep(uintptr_t, size_t);	/* grep a vaddr range */
extern void leaky_grep_ptr(uintptr_t);		/* grep a pointer */
extern void leaky_mark_ptr(uintptr_t);		/* mark a pointer */
extern int leaky_lookup_marked(uintptr_t, uintptr_t *, size_t *);

extern void leaky_add_leak(int, uintptr_t, uintptr_t, hrtime_t,
    leak_pc_t *, uint_t, uintptr_t, uintptr_t);

/*
 * ::findleaks target interface
 *
 * int leaky_subr_estimate(estp)
 *	Validate that any debugging options ::findleaks needs are active,
 *	and store an upper bound on the number of buffers in the system into
 *	estp.
 *
 *	Returns DCMD_OK to proceed, DCMD_ERR to abort ::findleaks.
 *
 * int leaky_subr_fill(mtpp)
 *	Passes a pointer to an mtab pointer, which points to the beginning
 *	of the mtab array.  Target should add an entry for each buffer in
 *	the system to the array, and update the pointer to point at the end
 *	of the table (i.e. one mtab beyond the last valid entry).
 *
 *	The lkm_bufctl entry in each mtab is target-defined.
 *
 *	Returns DCMD_OK to proceed, DCMD_ERR to abort ::findleaks.
 *
 * int leaky_subr_run(void)
 *	Target should invoke leaky_grep() or one of its variants on the
 *	root portions of the virtual address space.  Any pointers which
 *	are not reachable from those roots will be reported as leaks.
 *
 *	Returns DCMD_OK to proceed, DCMD_ERR to abort ::findleaks.
 *
 * void leaky_subr_add_leak(mtp)
 *	Invoked once for each leak.  Target should call leaky_add_leak()
 *	with the full details of the leak, which will be copied into a
 *	leak_bufctl_t.  That will be used in subsequent target invocations
 *	to identify the buffer.
 *
 *	leaky_add_leak() takes the following arguments:
 *		type	target-defined, 0 <= type < LK_NUM_TYPES.  Leaks are
 *			grouped by type.
 *
 *		addr	Address of the control structure for this leak.
 *			Should be unique across all types -- ::walk leak and
 *			::walk leakbuf use this field to identify leaks.
 *
 *		bufaddr	Address of the beginning of the buffer -- reported by
 *			::walk leakbuf.
 *
 *		timestamp
 *			High-resolution timestamp, usually of the time of
 *			allocation.  Coalesced leaks are represented by
 *			the leak with the earliest timestamp.
 *
 *		stack, depth
 *			The stack trace for this leak.  Leaks with
 *			identical stack traces will be coalesced.
 *
 *		cid	coalesce identifier -- leaks with differing
 *			cids will not be coalesced.
 *
 *		data	target-defined data
 *
 * int leaky_subr_bufctl_cmp(lhs, rhs)
 *	Target-defined display order for two leaks.  Both leaks will have
 *	the same lkb_type -- full display order is type (lowest-to-highest),
 *	then whatever order this function defines.
 *
 * void leaky_subr_dump_start(type)
 * void leaky_subr_dump(lkb, verbose)
 * void leaky_subr_dump_end(type)
 *	Used to dump the table of discovered leaks.  invoked as:
 *
 *		for i in 0 .. LK_NUM_TYPES
 *			leaky_subr_dump_start(i)
 *			for lkb in (possibly a subset of) the type i leaks
 *				leaky_subr_dump(lkb, 0)
 *			leaky_subr_dump_end(i)
 *
 *		if (-d was passed to ::findleaks)
 *			for i in 0 .. LK_NUM_TYPES
 *				for lkb of type i, same subset/order as above
 *					leaky_subr_dump(lkb, 1)
 *
 *	leaky_subr_dump_start()/end() are always invoked for each type, even
 *	if there are no leaks of that type.  leaky_subr_dump() can use the
 *	leaks chained off of lkb_next to access coalesced leaks.  lkb_dups
 *	is the length of the dup list.
 *
 * int leaky_subr_invoke_callback(lkb, cb, cbarg)
 *	Underlying implementation of '::walk leak' walker -- target should
 *	invoke cb for the passed in leak_bufctl_t.
 */
extern int leaky_subr_estimate(size_t *);
extern int leaky_subr_fill(leak_mtab_t **);

extern int leaky_subr_run(void);

extern void leaky_subr_add_leak(leak_mtab_t *);

extern int leaky_subr_bufctl_cmp(const leak_bufctl_t *, const leak_bufctl_t *);

extern void leaky_subr_dump_start(int);
extern void leaky_subr_dump(const leak_bufctl_t *, int verbose);
extern void leaky_subr_dump_end(int);

extern int leaky_subr_invoke_callback(const leak_bufctl_t *, mdb_walk_cb_t,
    void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LEAKY_IMPL_H */
