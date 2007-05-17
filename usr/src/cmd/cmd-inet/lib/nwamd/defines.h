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

#ifndef _DEFINES_H
#define	_DEFINES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/time.h>

#define	PKILL		"/usr/bin/pkill"
#define	ZENITY		"/usr/bin/zenity"
#define	SVCADM		"/usr/sbin/svcadm"
#define	IFCONFIG	"/sbin/ifconfig"
#define	NET_SVC_METHOD	"/lib/svc/method/net-svc"
#define	NET_SVC_FMRI	"svc:/network/service:default"
#define	DEV_LOCAL_SVC_FMRI "svc:/system/device/local:default"
#define	PFEXEC		"/usr/bin/pfexec"

#define	ULP_DIR		"/etc/nwam/ulp"
#define	LLPDIR		"/etc/nwam"
#define	LLPFILE		LLPDIR"/llp"
#define	KNOWN_WIFI_NETS	LLPDIR"/known_wifi_nets"

#define	BOOLEAN_TO_STRING(x) ((x) ? "TRUE" : "FALSE")
#define	STRING(s) (((s) == NULL) ? "NULL" : (s))

/* IPC listening port */
#define	NP_LISTEN_PORT		12340

#define	NWAM_DEFAULT_DHCP_WAIT_TIME	60	/* 1 minute */
#define	NWAM_IF_WAIT_DELTA_MAX		300	/* 5 minutes poll rate max */

#define	TIMER_INFINITY		0xffffffff	/* we use uint32s for timers */
#define	NSEC_TO_SEC(nsec)	(nsec) / NANOSEC

#endif /* _DEFINES_H */
