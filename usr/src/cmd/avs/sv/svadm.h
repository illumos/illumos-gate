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

#ifndef	_SVADM_H
#define	_SVADM_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Functions exported from svadm.o for the use of fwcadm.o
 */

static void compare_one_sv(char *);
static void compare_sv(char *);
static int disable_one_sv(char *);
static int disable_sv(char *);
static int enable_one_sv(char *);
static int enable_sv(char *);
static void print_sv(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SVADM_H */
