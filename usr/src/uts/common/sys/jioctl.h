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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_JIOCTL_H
#define	_SYS_JIOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 11.5	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * jioctl.h
 *
 * Low level control codes for communication between the host and a
 * windowing terminal. See windows.h for additional messages used by
 * libwindows.
 *
 * In case you are wondering what the "j" in jioctl stands for,
 * the "j" stands for jerq which was the first windowing terminal.
 * The jerq became the Blit which begot the 5620 DMD which begot
 * the 615, the 620 and the 630 MTG.
 */


/*
 * Ioctl requests sent to the xt driver. The types JMPX, JWINSIZE,
 * and JTRUN are processed locally by xt. The others involve sending
 * a control message to the terminal on channel 0 (the control
 * channel). In the control message, the lower bytes of these defines
 * are used as the first byte of the control message.
 *
 * Note that packets sent from the host to the terminal on channels
 * other than 0 are implicitly data packets.
 */

#define	JTYPE		('j'<<8)
#define	JBOOT		(JTYPE|1)  /* start a download in a window */
#define	JTERM		(JTYPE|2)  /* return to default terminal emulator */
#define	JMPX		(JTYPE|3)  /* currently running layers? */

/*
 * Timeout in seconds. Not supported by streams xt, but reserve
 * this number to avoid confusion.
 * #define	JTIMO		(JTYPE|4)
 */

#define	JWINSIZE	(JTYPE|5)  /* inquire window size */
#define	JTIMOM		(JTYPE|6)  /* timeouts in millisecs */
#define	JZOMBOOT	(JTYPE|7)  /* JBOOT but wait for debugger to run */
#define	JAGENT		(JTYPE|9)  /* control for both directions */
#define	JTRUN		(JTYPE|10) /* send runlayer command to layers cmd */
#define	JXTPROTO	(JTYPE|11) /* set xt protocol type */

/*
 * jwinsize structure used by JWINSIZE message.
 */

struct jwinsize
{
	char	bytesx, bytesy;	/* Window size in characters */
	short	bitsx, bitsy;	/* Window size in bits */
};

/*
 * Channel 0 control message format.
 */

struct jerqmesg
{
	char	cmd;		/* A control code above */
	char	chan;		/* Channel it refers to */
};

/*
 * The first byte of every xt packet from the terminal to the host
 * is one of these control codes. Data packets start with either
 * C_SENDCHAR or C_SENDNCHARS.
 *
 * The usual format is: [command][data]
 */

#define	C_SENDCHAR	1	/* Send character to layer process */
#define	C_NEW		2	/* Create a new layer */
#define	C_UNBLK		3	/* Unblock layer process */
#define	C_DELETE	4	/* Delete layer process group */
#define	C_EXIT		5	/* Exit layers */
#define	C_DEFUNCT	6	/* Send terminate signal to proc. group */
#define	C_SENDNCHARS	7	/* Send several characters to layer proc. */
#define	C_RESHAPE	8	/* Layer has been reshaped */
#define	C_RUN		9	/* Run command in layer (local to xt/layers) */
#define	C_NOFLOW	10	/* Disable network xt flow control */
#define	C_YESFLOW	11	/* Enable network xt flow control */

/*
 * Format of JAGENT packets.
 */

struct bagent {
	int size;	/* size of src string going in and dest string out */
	char * src;	/* address of the source byte string */
	char * dest;	/* address of the destination byte string */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_JIOCTL_H */
