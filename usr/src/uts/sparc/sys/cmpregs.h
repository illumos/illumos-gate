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

#ifndef	_CMPREGS_H
#define	_CMPREGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	ASI_CMP_SHARED		0x41	/* shared CMP registers */
#define	ASI_CMP_PER_CORE	0x63	/* core-local CMP registers */

/*
 * Core ID Register
 *
 *   |-----------------------|
 *   |MAX_CORE_ID|---|CORE_ID|
 *   |-----------------------|
 *    21       16     5     0
 */
#define	ASI_CORE_ID		0x10	/* ASI 0x63, VA 0x10 */
#define	COREID_MASK		0x3f


/*
 * Error Steering Register
 *
 *   |-------|
 *   |CORE_ID|
 *   |-------|
 *    5     0
 */
#define	ASI_CMP_ERROR_STEERING	0x40	/* ASI 0x41, VA 0x40 */

/*
 * Core Running
 *
 *   |------------------------------|
 *   |       |core running (status) |
 *   |------------------------------|
 *            1                    0
 */
#define	ASI_CORE_RUNNING_RW	0x50	/* ASI 0x41, VA 0x50 */
#define	ASI_CORE_RUNNING_STATUS	0x58	/* ASI 0x41, VA 0x58 */
#define	ASI_CORE_RUNNING_W1S	0x60	/* ASI 0x41, VA 0x60 */
#define	ASI_CORE_RUNNING_W1C	0x68	/* ASI 0x41, VA 0x68 */

#ifdef	__cplusplus
}
#endif

#endif /* _CMPREGS_H */
