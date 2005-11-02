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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_SYS_MOUSE_H
#define	_SYS_MOUSE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	BUTCHNGMASK	0x38
#define	MOVEMENT	0x40

#define	BUTSTATMASK	7
#define	BUT3STAT	1
#define	BUT2STAT	2
#define	BUT1STAT	4
#define	BUT3CHNG	8
#define	BUT2CHNG	0x10
#define	BUT1CHNG	0x20

struct mse_event {
	uchar_t	type;		/* event type (see below) */
	uchar_t	code;		/* when type is XQ_MOTION or XQ_BUTTON, => */
				/*	bit 0 clear if right button pushed; */
				/*	bit 1 clear if middle button pushed; */
				/*	bit 2 clear if left button pushed; */
	char	x;		/* delta x movement (mouse motion only) */
	char	y;		/* delta y movement (mouse motion only) */
};

#define	MSE_BUTTON	0
#define	MSE_MOTION	1

struct mouseinfo {
	unsigned char	status;
	char	xmotion, ymotion;
};

/* Ioctl Command definitions */

#define	MOUSEIOC	('M'<<8)
#define	MOUSEIOCREAD    (MOUSEIOC|60)
#define	MOUSEISOPEN	(MOUSEIOC|66)
#define	MOUSE320    	(MOUSEIOC|67)
#define	MSEBUTTONS	(MOUSEIOC|68)
#define	TS_CALIB	(MOUSEIOC|70)	/* Touch screen: set the calibration */
#define	TS_RECALIB	(MOUSEIOC|71)	/* Touch screen: disable calibration */
#define	TS_CURPOS	(MOUSEIOC|72)	/* Touch screen: set cursor position */
#define	MOUSEIOCDELAY	(MOUSEIOC|80)
#define	MOUSEIOCNDELAY	(MOUSEIOC|81)
#define	MOUSEIOCCONFIG	(MOUSEIOC|100)
#define	MOUSEIOCMON	(MOUSEIOC|101)

#define	VPC_MOUSE_READ  MOUSEIOCREAD

#define	UPPERLIM	127
#define	LOWERLIM	-128
#define	ONEBYTE(x)	((x) > UPPERLIM ? UPPERLIM : \
				(x) < LOWERLIM ? LOWERLIM : (x))

/* 320 mouse command/query structure */

struct cmd_320 {
	int	cmd;
	int	arg1;
	int	arg2;
	int	arg3;
};

/*
 * AT&T 320 (PS/2 style) Mouse Commands
 */
#define	MSERESET	0xff	/* reset mouse */
#define	MSERESEND	0xfe	/* resend last data stream */
#define	MSESETDEF	0xf6	/* set default status */
#define	MSEOFF		0xf5	/* disable mouse */
#define	MSEON		0xf4	/* enable mouse */
#define	MSECHGMOD	0xf3	/* set sampling rate and/or button mode */
#define	MSEGETDEV	0xf2	/* read device type */
#define	MSESPROMPT	0xf0	/* set prompt mode (resets stream mode) */
#define	MSEECHON	0xee	/* set echo mode */
#define	MSEECHOFF	0xec	/* reset echo mode */
#define	MSEREPORT	0xeb	/* read mouse report */
#define	MSESTREAM	0xea	/* set Incremental Stream Mode */
#define	MSESTATREQ	0xe9	/* status request */
#define	MSESETRES	0xe8	/* set counts per mm. resolution */
#define	MSESCALE2	0xe7	/* set 2:1 scaling */
#define	MSESCALE1	0xe6	/* set 1:1 scaling */

/*
 * 320 mouse 8042 controller commands and flags
 */
#define	MSE_ROP		0xD0	/* read output port command */
#define	MSE_RIP		0xC0	/* read input port command */
#define	MSE_WOP		0xD3	/* write to loopback command */
#define	MSE_WAD		0xD4	/* write to device command */
#define	MSE_RCB		0x20	/* read command byte command */
#define	MSE_WCB		0x60	/* write command byte command */
#define	MSE_INBF	0x03	/* input/output buffer full flag */
#define	MSE_OUTBF	0x21	/* output buffer full flag */
#define	MSE_ENAB	0xA8	/* enable 8042 interface */
#define	MSE_DISAB	0xA7	/* disable 8042 interface */
#define	MSE_ACK		0xFA	/* Acknowledgement byte from 8042 */

typedef struct mouseinfo MOUSEINFO;

/*
 * Begin Carrol touch screen-specific definitions.
 */

/*
 * Calibration data structure.	Used with TS_CALIB ioctl to register the upper
 * left opto-coordinate that corresponds to the upper left corner of the active
 * video area, and the lower right opto-coordinate that corresponds to the
 * lower right corner of the active video area.
 */

struct ts_calib {
	int	c_ulx,	/* upper left X opto-coordinate of active video area */
		c_uly,	/* upper left Y opto-coordinate of active video area */
		c_lrx,	/* lower right X opto-coordinate of active video area */
		c_lry;	/* lower right Y opto-coordinate of active video area */
};

/*
 * Position cursor at the given "pixel" coordinate.
 */

struct ts_curpos {
	int	p_xpos, /* X cursor coordinate */
		p_ypos;	/* Y cursor coordinate */
};

/*
 * End Carrol touch screen-specific definitions.
 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MOUSE_H */
