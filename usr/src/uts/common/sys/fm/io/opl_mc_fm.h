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

#ifndef _SYS_FM_IO_OPL_MC_FM_H
#define	_SYS_FM_IO_OPL_MC_FM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* mc-opl ereport components */
#define	MC_OPL_ERROR_CLASS	"asic.mac"
#define	MC_OPL_PTRL_SUBCLASS	"ptrl"
#define	MC_OPL_MI_SUBCLASS	"mi"

/*
 * ereport definition
 */
#define	MC_OPL_UE	"ue"
#define	MC_OPL_CE	"ce"
#define	MC_OPL_ICE	"ice"
#define	MC_OPL_CMPE	"cmpe"
#define	MC_OPL_MUE	"mue"
#define	MC_OPL_SUE	"sue"

/* mc-opl payload name fields */
#define	MC_OPL_BOARD		"board"
#define	MC_OPL_BANK		"bank"
#define	MC_OPL_STATUS		"status"
#define	MC_OPL_ERR_ADD		"err-add"
#define	MC_OPL_ERR_LOG		"err-log"
#define	MC_OPL_ERR_SYND		"syndrome"
#define	MC_OPL_ERR_DIMMSLOT	"dimm-slot"
#define	MC_OPL_ERR_DRAM		"dram-place"
#define	MC_OPL_PA		"pa"
#define	MC_OPL_FLT_TYPE		"flt-type"

#define	MC_OPL_RESOURCE		"resource"

#define	MC_OPL_NO_UNUM		""

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_FM_IO_OPL_MC_FM_H */
