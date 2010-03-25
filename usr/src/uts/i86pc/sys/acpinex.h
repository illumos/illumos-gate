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
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_ACPI_NEXUS_H
#define	_ACPI_NEXUS_H
#include <sys/types.h>
#include <sys/dditypes.h>	/* needed for definition of dev_info_t */
#include <sys/mutex.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#define	ACPINEX_INSTANCE_MAX		(1 << 10)
#define	ACPINEX_INSTANCE_MASK		(ACPINEX_INSTANCE_MAX - 1)
#define	ACPINEX_INSTANCE_SHIFT		8
#define	ACPINEX_MINOR_TYPE_MASK		((1 << ACPINEX_INSTANCE_SHIFT) - 1)
#define	ACPINEX_DEVCTL_MINOR		((1 << ACPINEX_INSTANCE_SHIFT) - 1)

#define	ACPINEX_MAKE_DEVCTL_MINOR(instance) \
	(((instance) << ACPINEX_INSTANCE_SHIFT) | ACPINEX_DEVCTL_MINOR)
#define	ACPINEX_IS_DEVCTL(minor)	\
	(((minor) & ACPINEX_MINOR_TYPE_MASK) == ACPINEX_DEVCTL_MINOR)

#define	ACPINEX_GET_INSTANCE(minor)	((minor) >> ACPINEX_INSTANCE_SHIFT)

extern int	acpinex_debug;
#define	ACPINEX_DEBUG(lvl, ...)		\
	if (acpinex_debug) cmn_err((lvl), __VA_ARGS__)

/* Softstate structure for acpinex instance. */
typedef struct {
	dev_info_t			*ans_dip;
	ACPI_HANDLE			ans_hdl;
	int				ans_fm_cap;
	ddi_iblock_cookie_t		ans_fm_ibc;
	kmutex_t			ans_lock;
	char				ans_path[MAXPATHLEN];
} acpinex_softstate_t;

extern void acpinex_event_init(void);
extern void acpinex_event_fini(void);
extern int acpinex_event_scan(acpinex_softstate_t *, boolean_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _ACPI_NEXUS_H */
