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

#ifndef _NSC_POWER_H
#define	_NSC_POWER_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Power ioctl definitions for Storage Device.
 * This layout is common between 32 and 64 bits kernels.
 */

typedef struct nsc_power_ctl_s {
	int msg;	/* power ioctl sub-opcode */
	int arg1;	/* argument for the sub-opcode */
} nsc_power_ctl_t;

#ifdef _KERNEL
extern int _nsc_init_power(void);
extern int _nsc_deinit_power(void);
extern int _nsc_power(blind_t, int *);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _NSC_POWER_H */
