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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>

/*
 * getfauditflags() - combines system event flag mask with user event
 *	flag masks.
 *
 * input: usremasks->as_success - always audit on success
 *	  usremasks->as_failure - always audit on failure
 *	  usrdmasks->as_success - never audit on success
 *	  usrdmasks->as_failure - never audit on failure
 *
 * output: lastmasks->as_success - audit on success
 *	   lastmasks->as_failure - audit on failure
 *
 * returns:	 0 - ok
 * 		-1 - error (cannot get attributable mask)
 */
int
getfauditflags(au_mask_t *usremasks, au_mask_t *usrdmasks, au_mask_t *lastmasks)
{
	au_mask_t masks;

	/* get system audit mask and convert to bit mask */
	if (auditon(A_GETAMASK, (caddr_t)&masks, sizeof (masks)) == -1) {
		return (-1);
	}

	/* combine system and user event masks */
	lastmasks->as_success = masks.as_success;
	lastmasks->as_failure = masks.as_failure;

	lastmasks->as_success |= usremasks->as_success;
	lastmasks->as_failure |= usremasks->as_failure;

	lastmasks->as_success &= ~(usrdmasks->as_success);
	lastmasks->as_failure &= ~(usrdmasks->as_failure);

	return (0);
}
