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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_VT_H
#define	_SYS_VT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Public IOCTLs supported by the VT, which are shared with
 * other operating systems.
 */
#define	VTIOC		('V'<<8)
#define	VT_OPENQRY	(VTIOC|1)	/* inquires if this vt already open */
#define	VT_SETMODE	(VTIOC|2)	/* set vt into auto or process mode */

#define	VT_GETMODE	(VTIOC|3)	/* returns mode vt is currently in */
#define	VT_RELDISP	(VTIOC|4)	/* tells vt when display released */
#define	VT_ACTIVATE	(VTIOC|5)	/* activates specified vt */
#define	VT_WAITACTIVE	(VTIOC|6)	/* wait for vt to be activated */
#define	VT_GETSTATE	(VTIOC|100)	/* returns active and open vts */

/*
 * Solaris specific public IOCTL.
 * Inquires if the vt functionality is available.
 */
#define	VT_ENABLED	(VTIOC|101)

/* get/set the target of /dev/vt/console_user symbol link */
#define	VT_GET_CONSUSER	(VTIOC|108)
#define	VT_SET_CONSUSER	(VTIOC|109)

struct vt_mode {
	char	mode;	/* mode to set vt into, VT_AUTO or VT_PROCESS */
	char	waitv;	/* if != 0, vt hangs on writes when not active */
	short	relsig;	/* signal to use for release request */
	short	acqsig;	/* signal to use for display acquired */
	short	frsig;	/* signal to use for forced release */
};

/* vt switching mode */
enum {
	VT_AUTO	= 0,	/* this vt switching is automatic */
	VT_PROCESS	/* this vt switching controlled by process */
};

#define	VT_ACKACQ	2	/* ack from v86 acquire routine */

/*
 * structure used by VT_GETSTATE ioctl
 */

struct vt_stat {
	unsigned short	v_active;
	unsigned short	v_signal;
	unsigned short	v_state;
};

/* project private IOCTLs */
#define	VT_CONFIG	(VTIOC|102)	/* config virtual console number */
#define	VT_SETDISPINFO	(VTIOC|103)	/* set display number */
#define	VT_SETDISPLOGIN	(VTIOC|104)	/* set display login */
#define	VT_GETDISPINFO	(VTIOC|105)	/* get display info */

/*
 * setting target console is only used by vtdaemon
 * to set target console while vtdaemon is authenticating
 * for it, which is returned in VT_GETSTATE. At that
 * time, the real active console is the vtdaemon special console,
 * but VT_GETSTATE should not be aware of it. Instead, VT_GETACTIVE
 * is used to get the real active console for vtdaemon.
 */
#define	VT_SET_TARGET	(VTIOC|106)
#define	VT_GETACTIVE	(VTIOC|107)

/*
 * Used by cn to convert a VT_SET_CONSUSER to a internal interface
 * so that /dev/console and /dev/vt/0 could be differentiated.
 */
#define	VT_RESET_CONSUSER	(VTIOC|110)

/*
 * structure used by VT_GETDISPINFO
 */
struct vt_dispinfo {
	pid_t	v_pid;		/* -1 if no display info (auto mode) */
	int	v_dispnum;	/* display number associated with vt */
	int	v_login;	/* if the user logged in the display */
};

#ifdef __cplusplus
}
#endif

#endif /* _SYS_VT_H */
