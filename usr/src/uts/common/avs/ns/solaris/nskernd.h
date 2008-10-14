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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NSKERND_H
#define	_NSKERND_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/nsctl/nsc_ioctl.h>	/* for struct nskernd */

enum {
	NSKERND_START,		/* Start of daemon processing */
	NSKERND_STOP,		/* Stop daemon */
	NSKERND_WAIT,		/* Wait for next command */
	NSKERND_BSIZE,		/* Get size in blocks of device */
	NSKERND_NEWLWP,		/* Create a new lwp */
	NSKERND_LOCK,		/* Obtain an inter-node lock */
	NSKERND_IIBITMAP	/* mark an II bitmap as failed */
};

/*
 * The following #define is used by the ii kernel to write any
 * flags information into the dscfg file when the bitmap volume
 * fails.
 */
#define	NSKERN_II_BMP_OPTION "flags"

#ifdef _KERNEL

extern void *proc_nskernd;
extern int nskernd_iscluster;

extern void nskernd_init(void);
extern void nskernd_deinit(void);
extern void nskernd_stop(void);
extern int nskernd_get(struct nskernd *);

extern void nsc_lockchild(uint64_t, uint64_t);
extern void nsc_runlwp(uint64_t);

#endif

#ifdef	__cplusplus
}
#endif

#endif /* _NSKERND_H */
