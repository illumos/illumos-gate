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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This is an internal header file. Not to be shipped.
 */

#ifndef	_AUTH_LIST_H
#define	_AUTH_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Names of authorizations currently in use in the system
 */

#define	CDRW_AUTH		"solaris.device.cdrw"
#define	CRONADMIN_AUTH		"solaris.jobs.admin"
#define	CRONUSER_AUTH		"solaris.jobs.user"
#define	DEFAULT_DEV_ALLOC_AUTH	"solaris.device.allocate"
#define	DEVICE_REVOKE_AUTH	"solaris.device.revoke"
#define	MAILQ_AUTH		"solaris.mail.mailq"
#define	SET_DATE_AUTH		"solaris.system.date"
#define	WIFI_CONFIG_AUTH	"solaris.network.wifi.config"
#define	WIFI_WEP_AUTH		"solaris.network.wifi.wep"

#ifdef	__cplusplus
}
#endif

#endif	/* _AUTH_LIST_H */
