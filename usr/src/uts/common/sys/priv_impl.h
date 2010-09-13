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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PRIV_IMPL_H
#define	_SYS_PRIV_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/priv_const.h>
#include <sys/priv.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL) || defined(_KMEMUSER)
/*
 * priv_set_t is a structure holding a set of privileges
 */

struct priv_set {
	priv_chunk_t pbits[PRIV_SETSIZE];
};

typedef struct cred_priv_s {
	priv_set_t	crprivs[PRIV_NSET];	/* Priv sets */
	uint_t		crpriv_flags;		/* Privilege flags */
} cred_priv_t;

#endif

#ifdef _KERNEL

extern priv_set_t *priv_basic;
extern priv_set_t priv_unsafe;
extern priv_set_t priv_fullset;
extern void priv_init(void);

/* The CR_PRIVS macro is defined in <sys/cred_impl.h> */
#define	CR_EPRIV(c)	(CR_PRIVS(c)->crprivs[PRIV_EFFECTIVE])
#define	CR_IPRIV(c)	(CR_PRIVS(c)->crprivs[PRIV_INHERITABLE])
#define	CR_PPRIV(c)	(CR_PRIVS(c)->crprivs[PRIV_PERMITTED])
#define	CR_LPRIV(c)	(CR_PRIVS(c)->crprivs[PRIV_LIMIT])

#define	CR_FLAGS(c)	(CR_PRIVS(c)->crpriv_flags)

#define	PRIV_SETBYTES	(PRIV_NSET * PRIV_SETSIZE * sizeof (priv_chunk_t))

#define	PRIV_EISAWARE(c) ((CR_FLAGS(c) & PRIV_AWARE) || (c)->cr_uid != 0)
#define	PRIV_PISAWARE(c) ((CR_FLAGS(c) & PRIV_AWARE) || \
				((c)->cr_uid != 0 && (c)->cr_suid != 0 && \
				(c)->cr_ruid != 0))

#define	CR_OEPRIV(c)	(*(PRIV_EISAWARE(c) ? &CR_EPRIV(c) : &CR_LPRIV(c)))
#define	CR_OPPRIV(c)	(*(PRIV_PISAWARE(c) ? &CR_PPRIV(c) : &CR_LPRIV(c)))

#define	PRIV_VALIDSET(s)	((s) >= 0 && (s) < PRIV_NSET)
#define	PRIV_VALIDOP(op)	((op) >= PRIV_ON && (op) <= PRIV_SET)

#define	PRIV_FULLSET		&priv_fullset	/* Require full set */

/*
 * Privilege macros bits manipulation macros; DEBUG kernels will
 * ASSERT() that privileges are not out of range.
 */
#ifndef	NBBY
#define	NBBY		8
#endif

#define	__NBWRD		(NBBY * sizeof (priv_chunk_t))

#define	privmask(n)	(1U << ((__NBWRD - 1) - ((n) % __NBWRD)))
#define	privword(n)	((n)/__NBWRD)

/*
 * PRIV_ASSERT(a, b) sets privilege "b" in privilege set "a".
 * PRIV_CLEAR(a,b) clears privilege "b" in privilege set "a".
 * PRIV_ISASSERT tests if privilege 'b' is asserted in privilege set 'a'.
 */

#define	__PRIV_ASSERT(a, b)	((a)->pbits[privword(b)] |= privmask(b))
#define	__PRIV_CLEAR(a, b)	((a)->pbits[privword(b)] &= ~privmask(b))
#define	__PRIV_ISASSERT(a, b)	((a)->pbits[privword(b)] & privmask(b))

#ifdef DEBUG
#define	PRIV_CLEAR(a, b)	priv_delset((a), (b))
#define	PRIV_ASSERT(a, b)	priv_addset((a), (b))
#define	PRIV_ISASSERT(a, b)	priv_ismember((a), (b))
#else
#define	PRIV_CLEAR(a, b)	__PRIV_CLEAR((a), (b))
#define	PRIV_ASSERT(a, b)	__PRIV_ASSERT((a), (b))
#define	PRIV_ISASSERT(a, b)	__PRIV_ISASSERT((a), (b))
#endif

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PRIV_IMPL_H */
