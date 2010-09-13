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

#ifndef	_SYS_SRN_H
#define	_SYS_SRN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	The following ioctl commands and structures may not exist
 *	or may have a different interpretation in a future release.
 */


#define	SRN_STANDBY_REQ		0xa01
#define	SRN_SUSPEND_REQ		0xa02
#define	SRN_NORMAL_RESUME	0xa03
#define	SRN_CRIT_RESUME		0xa04
#define	SRN_BATTERY_LOW		0xa05
#define	SRN_POWER_CHANGE	0xa06
#define	SRN_UPDATE_TIME		0xa07
#define	SRN_CRIT_SUSPEND_REQ	0xa08
#define	SRN_USER_STANDBY_REQ	0xa09
#define	SRN_USER_SUSPEND_REQ	0xa0a
#define	SRN_SYS_STANDBY_RESUME	0xa0b
#define	SRN_IOC_NEXTEVENT	0xa0c
#define	SRN_IOC_RESUME		0xa0d
#define	SRN_IOC_SUSPEND		0xa0e
#define	SRN_IOC_STANDBY		0xa0f
#define	SRN_IOC_AUTOSX		0xa10	/* change behavior of driver */

typedef struct srn_event_info
{
	int	ae_type;

} srn_event_info_t;

#ifdef	_KERNEL

#define	SRN_MAX_CLONE		8	/* only two consumer known */

#define	SRN_TYPE_APM		1
#define	SRN_TYPE_AUTOSX		2

#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SRN_H */
