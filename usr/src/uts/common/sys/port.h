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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#ifndef	_SYS_PORT_H
#define	_SYS_PORT_H

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
#define	PORT_SOURCE_MQ		6
#define	PORT_SOURCE_FILE	7

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


typedef struct file_obj {
	timestruc_t	fo_atime;	/* Access time from stat(2) */
	timestruc_t	fo_mtime;	/* Modification time from stat(2) */
	timestruc_t	fo_ctime;	/* Change time from stat(2) */
	uintptr_t	fo_pad[3];	/* For future expansion */
	char		*fo_name;	/* Null terminated file name */
} file_obj_t;

#if defined(_SYSCALL32)

typedef struct file_obj32 {
	timestruc32_t	fo_atime;	/* Access time got from stat(2) */
	timestruc32_t	fo_mtime;	/* Modification time from stat(2) */
	timestruc32_t	fo_ctime;	/* Change time from stat(2) */
	caddr32_t	fo_pad[3];	/* For future expansion */
	caddr32_t	fo_name;	/* Null terminated file name */
} file_obj32_t;

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

/*
 * PORT_SOURCE_FILE - events
 */

/*
 * User watchable file events
 */
#define	FILE_ACCESS		0x00000001
#define	FILE_MODIFIED		0x00000002
#define	FILE_ATTRIB		0x00000004
#define	FILE_TRUNC		0x00100000
#define	FILE_NOFOLLOW		0x10000000

/*
 * exception file events
 */

/*
 * The watched file..
 */
#define	FILE_DELETE		0x00000010
#define	FILE_RENAME_TO		0x00000020
#define	FILE_RENAME_FROM	0x00000040
/*
 * The filesystem on which the watched file resides got
 * unmounted.
 */
#define	UNMOUNTED		0x20000000
/*
 * Some other file/filesystem got mounted over the
 * watched file/directory.
 */
#define	MOUNTEDOVER		0x40000000

/*
 * Helper type
 */
#define	FILE_EXCEPTION		(UNMOUNTED|FILE_DELETE|FILE_RENAME_TO \
				|FILE_RENAME_FROM|MOUNTEDOVER)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PORT_H */
