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

#ifndef	_SYS_VUID_WHEEL_H
#define	_SYS_VUID_WHEEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/vuid_event.h>	/* for VUIOC definition */

#ifdef	__cplusplus
extern "C" {
#endif

#define	VUID_WHEEL_MAX_COUNT	256
#define	VUIDGWHEELCOUNT		(VUIOC|15)
#define	VUIDGWHEELINFO		(VUIOC|16)
#define	VUIDGWHEELSTATE		(VUIOC|17)
#define	VUIDSWHEELSTATE		(VUIOC|18)

typedef struct {
	int	vers;		/* set to VUID_WHEEL_INFO_VERS */
	int	id;
	int	format;
} wheel_info;

#define	VUID_WHEEL_INFO_VERS		1

#define	VUID_WHEEL_FORMAT_UNKNOWN	0
#define	VUID_WHEEL_FORMAT_HORIZONTAL	1
#define	VUID_WHEEL_FORMAT_VERTICAL	2

typedef struct {
	int		vers;		/* set to VUID_WHEEL_STATE_VERS */
	int		id;
	uint32_t	stateflags;
} wheel_state;

#define	VUID_WHEEL_STATE_VERS		1
#define	VUID_WHEEL_STATE_ENABLED	(1 << 0) /* Can get & set */
#define	VUID_WHEEL_DELTAMASK		0x000000FF

#define	VUID_WHEEL_GETDELTA(event_value)	\
		((signed char) ((event_value) & VUID_WHEEL_DELTAMASK))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VUID_WHEEL_H */
