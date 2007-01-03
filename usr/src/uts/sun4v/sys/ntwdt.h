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

#ifndef _SYS_NTWDT_H
#define	_SYS_NTWDT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ioccom.h>

/* ioctls for application watchdog */
#define	LOMIOCDOGSTATE	_IOR('a', 6, lom_dogstate_t)
#define	LOMIOCDOGCTL	_IOW('a', 7, lom_dogctl_t)
#define	LOMIOCDOGTIME	_IOW('a', 8, uint_t)
#define	LOMIOCDOGPAT	_IO('a', 9)

typedef
struct {
	int reset_enable;
	int dog_enable;
} lom_dogctl_t;

typedef
struct {
	int reset_enable;
	int dog_enable;
	uint_t dog_timeout;
} lom_dogstate_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NTWDT_H */
