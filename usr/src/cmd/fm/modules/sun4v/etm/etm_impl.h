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
 * etm_impl.h	FMA ETM and Transport shared implementation header
 *		for sun4v/Ontario
 *
 * const/type defns shared between the event transport module (ETM)
 * and the ETM-to-Transport API
 */

#ifndef _ETM_IMPL_H
#define	_ETM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ------------------------------ includes -----------------------------------
 */

#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>

#include "etm_xport_api.h"

/*
 * ------------------------------- macros ------------------------------------
 */

/* define common macros here vs #include to ease Solaris-Linux portability */

#ifndef MIN
#define	MIN(x, y)	((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define	MAX(x, y)	((x) > (y) ? (x) : (y))
#endif
#ifndef ABS
#define	ABS(x)		((x) < (0) ? (-(x)) : (x))
#endif

/* ETM I/O operations: read, write, peek */

#define	ETM_IO_OP_RD	(1)
#define	ETM_IO_OP_WR	(2)
#define	ETM_IO_OP_PK	(3)

/* ETM sleep times */

#define	ETM_SLEEP_VERY_QUIK	(0)
#define	ETM_SLEEP_QUIK		(1)
#define	ETM_SLEEP_SLOW		(16)
#define	ETM_SLEEP_VERY_SLOW	(16 * 16)

/*
 * ----------------------------- property names ------------------------------
 */

#define	ETM_PROP_NM_XPORT_ADDRS		"etm_xport_addrs"

#define	ETM_PROP_NM_DEBUG_LVL		"etm_debug_lvl"
#define	ETM_PROP_NM_DEBUG_MAX_EV_CNT	"etm_debug_max_ev_cnt"

#define	ETM_PROP_NM_CONSOLE		"etm_alert_console"
#define	ETM_PROP_NM_SYSLOGD		"etm_alert_syslog"
#define	ETM_PROP_NM_FACILITY		"etm_alert_facility"

#define	ETM_PROP_NM_MAX_RESP_Q_LEN	"etm_resp_q_max_len"

/*
 * --------------------------------- prolog ----------------------------------
 */

#ifdef __cplusplus
}
#endif

#endif /* _ETM_IMPL_H */
