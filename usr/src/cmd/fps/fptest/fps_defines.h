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

#ifndef _FPS_DEFINES_H
#define	_FPS_DEFINES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* defines for fps_ereport_mod.c sysevent channel */
#define	SUBCLASS	"FPU_Miscompare"
#define	VENDOR		"SUNW"
#define	PUBLISHER	"FPScrubber"
#define	BIND_FLAGS	EVCH_CREAT | EVCH_HOLD_PEND

/* defines for fps_ereport_mod.c nvlist names */
#define	NAME_FPS_VERSION	"fps-version"
#define	NAME_FPS_CPU		"cpu"
#define	NAME_FPS_TEST_ID	"test-id"
#define	NAME_FPS_EXPECTED_VALUE	"expected-value"
#define	NAME_FPS_OBSERVED_VALUE	"observed-value"
#define	NAME_FPS_RESOURCE	"resource"
#define	NAME_FPS_DETECTOR	"detector"
#define	NAME_FPS_ENA		"ena"
#define	NAME_FPS_CLASS		"class"
#define	NAME_FPS_STRING_DATA	"info"
#define	FPS_VERSION			0x1


/* defines for CPU names */
#define	USIII_KSTAT	"UltraSPARC-III"
#define	USIIIi_KSTAT	"UltraSPARC-IIIi"
#define	USIIIP_KSTAT	"UltraSPARC-III+"
#define	USIV_KSTAT	"UltraSPARC-IV"
#define	USIVP_KSTAT	"UltraSPARC-IV+"

#ifdef __cplusplus
}
#endif

#endif /* _FPS_DEFINES_H */
