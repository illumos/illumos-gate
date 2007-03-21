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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PRIV_PRIVATE_H
#define	_PRIV_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/priv.h>
#include <limits.h>

/*
 * Libc private privilege data.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	LOADPRIVDATA(d)		d = __priv_getdata()
#define	GETPRIVDATA()		__priv_getdata()
#define	LOCKPRIVDATA()		{ \
					/* Data already allocated */ \
					(void) lock_data(); \
					(void) refresh_data(); \
				}
#define	UNLOCKPRIVDATA()	unlock_data()
#define	WITHPRIVLOCKED(t, b, x)	{ \
					t __result; \
					if (lock_data() != 0) \
						return (b); \
					__result = (x); \
					if (__result == (b) && refresh_data()) \
						__result = (x); \
					unlock_data(); \
					return (__result); \
				}

/*
 * Privilege mask macros.
 */
#define	__NBWRD		(CHAR_BIT * sizeof (priv_chunk_t))
#define	privmask(n)	(1 << ((__NBWRD - 1) - ((n) % __NBWRD)))
#define	privword(n)	((n)/__NBWRD)

/*
 * Same as the functions, but for numeric privileges.
 */
#define	PRIV_ADDSET(a, p)	((priv_chunk_t *)(a))[privword(p)] |= \
							privmask(p)
#define	PRIV_DELSET(a, p)	((priv_chunk_t *)(a))[privword(p)] &= \
							~privmask(p)
#define	PRIV_ISMEMBER(a, p)	((((priv_chunk_t *)(a))[privword(p)] & \
							privmask(p)) != 0)

/*
 * The structure is static except for the setsort, privnames and nprivs
 * field.  The pinfo structure initially has sufficient room and the kernel
 * guarantees no offset changes so we can copy a new structure on top of it.
 * The locking stratgegy is this: we lock it when we need to reference any
 * of the volatile fields.
 */
typedef struct priv_data {
	size_t			pd_setsize;		/* In bytes */
	int			pd_nsets, pd_nprivs;
	uint32_t		pd_ucredsize;
	char  			**pd_setnames;
	char			**pd_privnames;
	int			*pd_setsort;
	priv_impl_info_t 	*pd_pinfo;
	priv_set_t		*pd_basicset;
	priv_set_t		*pd_zoneset;
} priv_data_t;

extern priv_data_t *__priv_getdata(void);
extern priv_data_t *__priv_parse_info(priv_impl_info_t *);
extern void __priv_free_info(priv_data_t *);
extern priv_data_t *privdata;

extern int lock_data(void);
extern boolean_t refresh_data(void);
extern void unlock_data(void);

extern boolean_t __priv_isemptyset(priv_data_t *, const priv_set_t *);
extern boolean_t __priv_isfullset(priv_data_t *, const priv_set_t *);
extern boolean_t __priv_issubset(priv_data_t *, const priv_set_t *,
				const priv_set_t *);
extern const char *__priv_getbynum(const priv_data_t *, int);

extern int getprivinfo(priv_impl_info_t *, size_t);

extern priv_set_t *priv_basic(void);

#ifdef __cplusplus
}
#endif

#endif /* _PRIV_PRIVATE_H */
