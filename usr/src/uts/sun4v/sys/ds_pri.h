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

#ifndef	_SYS_DS_PRI_H_
#define	_SYS_DS_PRI_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ioctl info for ds_pri device
 */

#define	DSPRIIOC	('d' << 24 | 's' << 16 | 'p' << 8)

#define	DSPRI_GETINFO	(DSPRIIOC | 1)   /* Get PRI size */
#define	DSPRI_WAIT	(DSPRIIOC | 2)   /* Wait for PRI change */


/*
 * DSPRI_GETINFO
 * Datamodel invariant.
 */
struct dspri_info {
	uint64_t size;
	uint64_t token;
};


#ifdef __cplusplus
}
#endif

#endif /* _SYS_DS_PRI_H_ */
