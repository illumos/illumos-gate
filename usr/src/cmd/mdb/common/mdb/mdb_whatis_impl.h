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

#ifndef	_MDB_WHATIS_IMPL_H
#define	_MDB_WHATIS_IMPL_H

#include <mdb/mdb_module.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	WHATIS_MS(c, s) (((uint64_t)(c)) << (s))

#define	WHATIS_MAGIC 	/* whatis 0x2009 */ \
	(WHATIS_MS('w', 56) | WHATIS_MS('h', 48) | WHATIS_MS('a', 40) | \
	    WHATIS_MS('t', 32) | WHATIS_MS('i', 24) | WHATIS_MS('s', 16) | \
	    WHATIS_MS(0x2009, 0))

struct mdb_whatis {
	uint64_t w_magic;	/* just for sanity */
	uintptr_t *w_addrs;	/* w_naddr sorted addresses */
	char *w_addrfound;	/* array of w_naddr "found" flags */
	size_t w_naddrs;
	size_t w_match_next;	/* next match offset, or 0 if no active match */
	uintptr_t w_match_base;	/* base of current match */
	size_t w_match_size;	/* size of current match */
	size_t w_found;		/* count of set entries in w_addrfound */
	uint_t w_flags;		/* see WHATIS_* for details */
	uint8_t w_done;		/* set when no more processing is needed */
};

#define	WHATIS_PUBLIC		0x0ffff

/* flags which aren't part of the public interface */
#define	WHATIS_ALL		0x10000	/* -a, report all matches */

#define	WHATIS_PRIO_MIN		99

extern int cmd_whatis(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void whatis_help(void);

/* built-in callbacks */
extern int whatis_run_mappings(struct mdb_whatis *, void *);

/* callback at module unload time */
extern void mdb_whatis_unregister_module(mdb_module_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_WHATIS_IMPL_H */
