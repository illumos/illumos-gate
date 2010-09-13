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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VTDAEMON_H
#define	_SYS_VTDAEMON_H

#ifdef __cplusplus
extern "C" {
#endif

#define	VT_DAEMON_DOOR_FILE	"/var/run/vt/vtdaemon_door"

#define	VT_EV_X_EXIT	0	/* <vt_num> */
#define	VT_EV_HOTKEYS	1	/* <vt_num> */

/*
 * The structure of a request to vtdaemon.
 */
typedef struct vt_cmd_arg {
	uchar_t		vt_ev;
	uint32_t	vt_num;
} vt_cmd_arg_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_VTDAEMON_H */
