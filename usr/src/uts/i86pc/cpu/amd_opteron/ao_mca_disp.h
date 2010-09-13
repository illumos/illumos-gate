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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _AO_MCA_DISP_H
#define	_AO_MCA_DISP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/mca_amd.h>
#include <sys/fm/cpu/AMD.h>

#include <ao.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	AO_MCA_PP_BIT_SRC	0x1
#define	AO_MCA_PP_BIT_RES	0x2
#define	AO_MCA_PP_BIT_OBS	0x4
#define	AO_MCA_PP_BIT_GEN	0x8

#define	AO_MCA_II_BIT_MEM	0x1
#define	AO_MCA_II_BIT_IO	0x2
#define	AO_MCA_II_BIT_GEN	0x4

#define	AO_MCA_R4_BIT_ERR	0x001
#define	AO_MCA_R4_BIT_RD	0x002
#define	AO_MCA_R4_BIT_WR	0x004
#define	AO_MCA_R4_BIT_DRD	0x008
#define	AO_MCA_R4_BIT_DWD	0x010
#define	AO_MCA_R4_BIT_DWR	0x020
#define	AO_MCA_R4_BIT_IRD	0x040
#define	AO_MCA_R4_BIT_PREFETCH	0x080
#define	AO_MCA_R4_BIT_EVICT	0x100
#define	AO_MCA_R4_BIT_SNOOP	0x200

extern const ao_error_disp_t *ao_error_disp[];

#ifdef __cplusplus
}
#endif

#endif /* _AO_MCA_DISP_H */
