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

#ifndef _FPST_DEFINES_H
#define	_FPST_DEFINES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fpst-defines
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	BIND_FLAGS	EVCH_CREAT | EVCH_HOLD_PEND
#define	CHANNEL		"com.sun:sysevent-fpscrubber:channel-fps"
#define	CLASS "FPScrubber"
#define	SUBSCRIBE_FLAGS	EC_ALL
#define	SUBSCRIBE_ID	"FPS_FMD_MOD"
#define	FPS_MOD_DESC "Solaris FP-Scrubber"
#define	FPS_MOD_VER "1.0"
#define	FAIL_MSG_MAX 100

#define	USIII	"ultraSPARC-III"
#define	USIIIi	"ultraSPARC-IIIi"
#define	USIIIP	"ultraSPARC-IIIplus"
#define	USIV	"ultraSPARC-IV"
#define	USIVP	"ultraSPARC-IVplus"

#ifdef __cplusplus
}
#endif


#endif /* _FPST_DEFINES_H */
