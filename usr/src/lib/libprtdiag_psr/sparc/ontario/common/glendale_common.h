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

/*
 * Sun4v Platform header file.
 *
 * 	called when :
 *      machine_type ==  Glendale
 *
 */

#ifndef _GLENDALE_COMMON_H
#define	_GLENDALE_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file is created so that ontario.c does not have
 * to include glendale.h, which separate out the Glendale
 * specific definitions.
 */

#define	GLENDALE_PLATFORM		"SUNW,Sun-Blade-T6320"

/*
 * Function Headers
 */
int glendale_pci_callback(picl_nodehdl_t pcih, void *args);
int glendale_hw_rev_callback(picl_nodehdl_t pcih, void *args);

#ifdef __cplusplus
}
#endif

#endif /* _GLENDALE_COMMON_H */
