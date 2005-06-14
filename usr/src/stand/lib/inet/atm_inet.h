/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999, Sun Microsystems, Inc.
 *
 * ATM implementation-specific definitions
 */

#ifndef _ATM_INET_H
#define	_ATM_INET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	ATMSIZE			(4500)	/* Default ATM MTU size */
#define	ATM_ARP_TIMEOUT		(300000)	/* in milliseconds */
#define	ATM_IN_TIMEOUT		(4)	/* milliseconds wait for IP input */

#ifdef	__cplusplus
}
#endif

#endif /* _ATM_INET_H */
