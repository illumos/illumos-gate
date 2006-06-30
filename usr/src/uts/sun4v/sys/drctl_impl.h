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

#ifndef _SYS_DRCTL_IMPL_H
#define	_SYS_DRCTL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DRCTL_IOC_IMPL	('I' << 8)

/*
 * The communication with the backend should be decoupled from the
 * rest of the drctl module.  Currently, the backend lives in
 * userland and this module communicates with it via a door upcall.
 * In the future the backend may be kernel resident.  For this
 * reason the interface is placed in a separate "impl" source
 * module and can be easily replaced.
 */
#define	DRCTL_IOCTL_CONNECT_SERVER (DRCTL_IOC_IMPL | 1)

typedef struct drctl_setup {
	uint_t did;
} drctl_setup_t;

extern void i_drctl_init(void);
extern void i_drctl_fini(void);
extern int i_drctl_ioctl(int, intptr_t);
extern int i_drctl_send(void *, size_t, void **, size_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DRCTL_IMPL_H */
