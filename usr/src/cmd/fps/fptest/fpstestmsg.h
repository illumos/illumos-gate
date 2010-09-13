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

#ifndef _FPSTESTMSG_H
#define	_FPSTESTMSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	FPSM_01	"\nFPU System (Reliability) Test for CPU=%d Stress Level=%d"
#define	FPSM_02	"\nLapack %s precision test. CPU=%d"
#define	FPSM_03 "\n%s on architecture = %s"
#define	FPSM_04 "\nPASS limit (modulo): Low=%d Med=%d High=%d"
#define	FPSM_05 "\nLapack Stress Level=%d"

#ifdef __cplusplus
}
#endif

#endif /* _FPSTESTMSG_H */
