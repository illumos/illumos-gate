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

#ifndef _RTSCHED_H
#define	_RTSCHED_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/priocntl.h>

/*
 * This definition is private to libc but is used in more than one subsystem.
 */
struct pcclass {
	short		pcc_state;
	pri_t		pcc_primin;
	pri_t		pcc_primax;
	pcinfo_t	pcc_info;
};

#endif	/* _RTSCHED_H */
