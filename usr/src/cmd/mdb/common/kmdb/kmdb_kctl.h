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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KMDB_KCTL_H
#define	_KMDB_KCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interfaces used by the driver and mdb to interact with kmdb, and vice versa
 */

#include <sys/types.h>
#include <sys/kdi.h>

#include <kmdb/kmdb_auxv.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Interfaces used by mdb to control kmdb
 */
#define	KMDB_IOC		(0xDB << 16)
#define	KMDB_IOC_START		(KMDB_IOC|1)
#define	KMDB_IOC_STOP		(KMDB_IOC|2)

#define	KMDB_ACT_F_BOOT		0x1		/* activated during boot */

extern int kmdb_init(const char *, kmdb_auxv_t *);

/*
 * This function should only be defined for sun4v. However the mdb build
 * uses a custom tool (hdr2map) to generate mapfile from header files but
 * this tool does not take care of preprocessor directives and functions
 * are included into the mapfile whatever the architecture is and even
 * if there is an #ifdef sun4v. So we always declare this function but it
 * has a fake definition for all architecture but sun4v.
 */
extern void kmdb_init_promif(char *, kmdb_auxv_t *);

extern void kmdb_activate(kdi_debugvec_t **, uint_t);
extern void kmdb_deactivate(void);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_KCTL_H */
