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


#ifndef	_TZMON_H
#define	_TZMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	TZ_DEFAULT_PERIOD	30

#define	TZ_NUM_LEVELS		10

typedef struct thermal_zone {
	struct thermal_zone	*next;
	kmutex_t		lock;
	ACPI_HANDLE		obj;
	ddi_taskq_t		*taskq;
	void			*zone_name;

	int			ac[TZ_NUM_LEVELS];
	ACPI_BUFFER		al[TZ_NUM_LEVELS];
	int			crt;
	int			hot;
	ACPI_BUFFER		psl;
	int			psv;
	int			tc1;
	int			tc2;
	int			tsp;
	int			tzp;

	int			polling_period;
	int			current_level;
} thermal_zone_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _TZMON_H */
