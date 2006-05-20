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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SFX4500_PROPS_H
#define	_SFX4500_PROPS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	SUN_FIRE_X4500_PROPERTIES	"sfx4500-properties"
#define	SFX4500_FRU_UPDATE_ACTION	"fru-update-action"
#define	SFX4500_OVERTEMP_ACTION		"overtemp-action"
#define	SFX4500_ST_FAIL_ACTION		"selftest-fail-action"

extern struct sata_machine_specific_properties SFX4500_machprops;

#ifdef __cplusplus
}
#endif

#endif /* _SFX4500_PROPS_H */
