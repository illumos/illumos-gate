/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDB_WHATIS_H
#define	_MDB_WHATIS_H

#ifdef	__cplusplus
extern "C" {
#endif

struct mdb_whatis;
typedef struct mdb_whatis mdb_whatis_t;

/*
 * int mdb_whatis_overlaps(mdb_whatis_t *w, uintptr_t base, size_t size):
 *
 * Returns non-zero if and only if a call to
 *
 *	mdb_whatis_match(w, base, size, ...)
 *
 * will succeed;  that is, there is an address of interest in the
 * range [base, base+size).
 */
extern int mdb_whatis_overlaps(mdb_whatis_t *, uintptr_t, size_t);

/*
 * int mdb_whatis_match(mdb_whatis_t *w, uintptr_t base, size_t size,
 *	uintptr_t *out)
 *
 * Perform an iterative search for an address of interest in [base, base+size).
 * Each call returning a non-zero value returns the next interesting address
 * in the range.  This must be called repeatedly until it returns a zero
 * value, indicating that the search is complete.
 *
 * For example:
 *	uintptr_t cur;
 *
 *	while (mdb_whatis_match(w, base, size, &cur))
 *		mdb_whatis_report_object(w, cur, base, "allocated from ...");
 */
extern int mdb_whatis_match(mdb_whatis_t *, uintptr_t, size_t, uintptr_t *);

/*
 * void mdb_whatis_report_address(mdb_whatis_t *w, uintptr_t addr,
 *	uintptr_t base, const char *format, ...)
 *
 * Reports addr (an address from mdb_whatis_match()).  If addr is inside
 * a symbol, that will be reported. (format, ...) is an mdb_printf()
 * format string and associated arguments, and will follow a string like
 * "addr is ".  For example, it could be "in libfoo's text segment\n":
 *
 *	addr is in libfoo's text segment
 *
 * The caller should make sure to output a newline, either in format or in a
 * separate mdb_printf() call.
 */
extern void mdb_whatis_report_address(mdb_whatis_t *, uintptr_t,
    const char *, ...);

/*
 * void mdb_whatis_report_object(mdb_whatis_t *w, uintptr_t addr,
 *	uintptr_t base, const char *format, ...)
 *
 * Reports addr (an address from mdb_whatis_match()) as being part of an
 * object beginning at base.  (format, ...) is an mdb_printf() format
 * string and associated arguments, and will follow a string like
 * "addr is base+offset, ".  For example, it could be "allocated from foo\n":
 *
 *	addr is base+offset, allocated from foo
 *
 * The caller should make sure to output a newline, either in format or in a
 * separate mdb_printf() call.
 */
extern void mdb_whatis_report_object(mdb_whatis_t *, uintptr_t, uintptr_t,
    const char *, ...);

/*
 * uint_t mdb_whatis_flags(mdb_whatis_t *w)
 *
 * Reports which flags were passed to ::whatis.  See the flag definitions
 * for more details.
 */
extern uint_t mdb_whatis_flags(mdb_whatis_t *);

#define	WHATIS_BUFCTL	0x1	/* -b, the caller requested bufctls */
#define	WHATIS_IDSPACE 	0x2	/* -i, only search identifiers */
#define	WHATIS_QUIET	0x4	/* -q, single-line reports only */
#define	WHATIS_VERBOSE	0x8	/* -v, report information about the search */

/*
 * uint_t mdb_whatis_done(mdb_whatis_t *w)
 *
 * Returns non-zero if and only if all addresses have been reported, and it
 * is time to get out of the callback as quickly as possible.
 */
extern uint_t mdb_whatis_done(mdb_whatis_t *);

/* Macro for returning from a walker callback */
#define	WHATIS_WALKRET(w)	(mdb_whatis_done(w) ? WALK_DONE : WALK_NEXT)

typedef int mdb_whatis_cb_f(mdb_whatis_t *, void *);

/*
 * void mdb_whatis_register(const char *name, mdb_whatis_cb_f *cb, void *arg,
 *	uint_t prio, uint_t flags)
 *
 * May only be called from _mdb_init() for a module.
 *
 * Registers a whatis callback named "name" (which must be an MDB identifier),
 * with a callback function cb and argument arg.  prio determines when the
 * callback will be invoked, compared to other registered ones, and flags
 * determines when the callback will be invoked (see below).
 *
 * Callbacks with the same priority registered by the same module will be
 * executed in the order they were added.  The callbacks will be invoked as:
 *
 *	int ret = (*cb)(w, arg)
 *
 * Where w is an opaque mdb_whatis_t pointer which is to be passed to the API
 * routines, above.  The function should return 0 unless an error occurs.
 */
extern void mdb_whatis_register(const char *,
    mdb_whatis_cb_f *, void *, uint_t, uint_t);

#define	WHATIS_PRIO_EARLY	10	/* execute before allocator callbacks */
#define	WHATIS_PRIO_ALLOCATOR	20
#define	WHATIS_PRIO_LATE	30	/* execute after allocator callbacks */

#define	WHATIS_REG_ID_ONLY	0x1	/* only invoke for '-i' */
#define	WHATIS_REG_NO_ID	0x2	/* don't invoke for '-i' */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_WHATIS_H */
