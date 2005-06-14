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

#ifndef	_SYS_DEVPOLICY_H
#define	_SYS_DEVPOLICY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/priv.h>
#include <sys/param.h>
#include <sys/vnode.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Device policy system call interface data structure.
 *
 * Inside the kernel we only make the structure definition available when the
 * privilege set definition is complete, i.e., something included
 * <sys/priv_const.h> before including this file.
 */

typedef struct devplcysys devplcysys_t;

#if defined(__PRIV_CONST_IMPL) || !defined(_KERNEL)

struct devplcysys {
	major_t		dps_maj;	/* major number */
	minor_t		dps_lomin;	/* low minor number, if known */
	minor_t		dps_himin;	/* high minor number, if known */
	char		dps_minornm[MAXNAMELEN]; /* minor name/pattern */
	boolean_t	dps_isblock;	/* expanded device is a block dev */
#ifdef _KERNEL
	priv_set_t	dps_rdp;	/* privileges required for reading */
	priv_set_t	dps_wrp;	/* privileges required for writing */
#else
	priv_chunk_t	dps_sets[1];	/* read/write privilege sets */
#endif
};

#ifdef _KERNEL
/*
 * The actual device policy structure.  This is returned on table
 * lookups.
 */
struct devplcy {
	uint32_t	dp_ref;		/* Reference count */
	uint32_t	dp_gen;		/* Generation count */
	priv_set_t	dp_rdp;		/* Privileges required for reading */
	priv_set_t	dp_wrp;		/* Privileges required for writing */
};
#endif /* _KERNEL */

#endif /* __PRIV_CONST_IMPL || !_KERNEL */

#ifdef _KERNEL

typedef struct devplcy devplcy_t;

extern devplcy_t *nullpolicy;		/* The null policy */

extern volatile uint32_t devplcy_gen;	/* The current generation count */

extern devplcy_t *dpget(void);
extern void dphold(devplcy_t *);
extern void dpfree(devplcy_t *);
extern devplcy_t *devpolicy_find(vnode_t *);

extern void devpolicy_init(void);
extern int devpolicy_load(int, size_t, devplcysys_t *);
extern int devpolicy_get(int *, size_t, devplcysys_t *);
extern int devpolicy_getbyname(size_t, devplcysys_t *, char *);

extern devplcy_t *devpolicy_priv_by_name(const char *, const char *);

#else /* _KERNEL */
#define	DEVPLCYSYS_SZ(ip)	(sizeof (devplcysys_t) + \
				((ip)->priv_setsize * 2 - 1) * \
				sizeof (priv_chunk_t))
#define	DEVPLCYSYS_RDP(dp, ip)	((priv_set_t *)(&(dp)->dps_sets[0]))
#define	DEVPLCYSYS_WRP(dp, ip)	\
			((priv_set_t *)(&(dp)->dps_sets[(ip)->priv_setsize]))

#define	DEVPLCY_TKN_RDP		"read_priv_set"
#define	DEVPLCY_TKN_WRP		"write_priv_set"

#endif /* _KERNEL */

#define	MAXDEVPOLICY		1000
#define	DEVPOLICY_DFLT_MAJ	((major_t)~0)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEVPOLICY_H */
