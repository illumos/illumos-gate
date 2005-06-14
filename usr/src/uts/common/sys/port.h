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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PORT_H
#define	_SYS_PORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/* port sources */
#define	PORT_SOURCE_AIO		1
#define	PORT_SOURCE_TIMER	2
#define	PORT_SOURCE_USER	3
#define	PORT_SOURCE_FD		4
#define	PORT_SOURCE_ALERT	5

typedef struct port_event {
	int		portev_events;	/* event data is source specific */
	ushort_t	portev_source;	/* event source */
	ushort_t	portev_pad;	/* port internal use */
	uintptr_t	portev_object;	/* source specific object */
	void		*portev_user;	/* user cookie */
} port_event_t;

typedef	struct	port_notify {
	int		portnfy_port;	/* bind request(s) to port */
	void		*portnfy_user;	/* user defined */
} port_notify_t;


#if defined(_SYSCALL32)

typedef struct port_event32 {
	int		portev_events;	/* events detected */
	ushort_t	portev_source;	/* user, timer, aio, etc */
	ushort_t	portev_pad;	/* reserved */
	caddr32_t	portev_object;	/* fd, timerid, ... */
	caddr32_t	portev_user;	/* user cookie */
} port_event32_t;

typedef	struct	port_notify32 {
	int		portnfy_port;	/* bind request(s) to port */
	caddr32_t 	portnfy_user;	/* user defined */
} port_notify32_t;

#endif /* _SYSCALL32 */

/* port_alert() flags */
#define	PORT_ALERT_SET		0x01
#define	PORT_ALERT_UPDATE	0x02
#define	PORT_ALERT_INVALID	(PORT_ALERT_SET | PORT_ALERT_UPDATE)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PORT_H */
