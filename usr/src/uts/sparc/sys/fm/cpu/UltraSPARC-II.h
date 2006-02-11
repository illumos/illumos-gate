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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FM_ULTRASPARC_II_H
#define	_SYS_FM_ULTRASPARC_II_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Ereport class subcategories for UltraSPARC I, and II families */
#define	FM_EREPORT_CPU_USI		"ultraSPARC-I"
#define	FM_EREPORT_CPU_USII		"ultraSPARC-II"
#define	FM_EREPORT_CPU_USIIe		"ultraSPARC-IIe"
#define	FM_EREPORT_CPU_USIIi		"ultraSPARC-IIi"
#define	FM_EREPORT_CPU_UNSUPPORTED	"unsupported"

/*
 * FM Ereport definitions.
 */
#define	FM_EREPORT_CPU_USII_ISAP		"isap"
#define	FM_EREPORT_CPU_USII_ETP			"etp"
#define	FM_EREPORT_CPU_USII_IVUE		"ivue"
#define	FM_EREPORT_CPU_USII_TO			"to"
#define	FM_EREPORT_CPU_USII_BERR		"berr"
#define	FM_EREPORT_CPU_USII_LDP			"ldp"
#define	FM_EREPORT_CPU_USII_CP			"cp"
#define	FM_EREPORT_CPU_USII_WP			"wp"
#define	FM_EREPORT_CPU_USII_EDP			"edp"
#define	FM_EREPORT_CPU_USII_UE			"ue"
#define	FM_EREPORT_CPU_USII_CE			"ce"
#define	FM_EREPORT_CPU_USII_ESCRUB_TAG		"escrub-etp"
#define	FM_EREPORT_CPU_USII_ESCRUB_DATA		"escrub-edp"
#define	FM_EREPORT_CPU_USII_UNKNOWN		"unknown"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FM_ULTRASPARC_II_H */
