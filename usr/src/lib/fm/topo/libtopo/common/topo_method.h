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

#ifndef _TOPO_METHOD_H
#define	_TOPO_METHOD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * FMRI methods
 */
#define	TOPO_METH_ASRU_COMPUTE		"topo_asru_compute"
#define	TOPO_METH_FRU_COMPUTE		"topo_fru_compute"
#define	TOPO_METH_FMRI			"topo_fmri"
#define	TOPO_METH_NVL2STR		"topo_nvl2str"
#define	TOPO_METH_STR2NVL		"topo_str2nvl"
#define	TOPO_METH_CONTAINS		"topo_contains"
#define	TOPO_METH_COMPARE		"topo_compare"

#define	TOPO_METH_FMRI_VERSION			0
#define	TOPO_METH_FRU_COMPUTE_VERSION		0
#define	TOPO_METH_ASRU_COMPUTE_VERSION		0
#define	TOPO_METH_NVL2STR_VERSION		0
#define	TOPO_METH_STR2NVL_VERSION		0
#define	TOPO_METH_CONTAINS_VERSION		0
#define	TOPO_METH_COMPARE_VERSION		0

#define	TOPO_METH_ASRU_COMPUTE_DESC		"Dynamic ASRU constructor"
#define	TOPO_METH_FRU_COMPUTE_DESC		"Dynamic FRU constructor"
#define	TOPO_METH_FMRI_DESC			"Dynamic FMRI constructor"
#define	TOPO_METH_NVL2STR_DESC			"FMRI to string"
#define	TOPO_METH_STR2NVL_DESC			"string to FMRI"
#define	TOPO_METH_CONTAINS_DESC			"FMRI contains sub-FMRI"
#define	TOPO_METH_COMPARE_DESC			"compare two FMRIs"

#define	TOPO_METH_FMRI_ARG_NAME		"child-name"
#define	TOPO_METH_FMRI_ARG_INST		"child-inst"
#define	TOPO_METH_FMRI_ARG_NVL		"args"
#define	TOPO_METH_FMRI_ARG_PARENT	"parent-fmri"
#define	TOPO_METH_FMRI_ARG_AUTH		"auth"
#define	TOPO_METH_FMRI_ARG_PART		"part"
#define	TOPO_METH_FMRI_ARG_REV		"rev"
#define	TOPO_METH_FMRI_ARG_SER		"serial"
#define	TOPO_METH_FMRI_ARG_HCS		"hc-specific"

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_METHOD_H */
