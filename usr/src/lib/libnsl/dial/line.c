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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * This is a new line.c, which consists of line.c and culine.c
 * merged together.
 */

#include "mt.h"
#include "uucp.h"

static const struct sg_spds {
	int sp_val;
	int sp_name;
} spds[] = {
	{ 50,		B50 },
	{ 75,		B75 },
	{ 110,		B110 },
	{ 134,		B134 },
	{ 150,		B150 },
	{ 200,		B200 },
	{ 300,		B300 },
	{ 600,		B600 },
	{ 1200,		B1200 },
	{ 1800,		B1800 },
	{ 2400,		B2400 },
	{ 4800,		B4800 },
	{ 9600,		B9600 },
	{ 19200,	B19200 },
	{ 38400,	B38400 },
	{ 57600,	B57600 },
	{ 76800,	B76800 },
	{ 115200,	B115200 },
	{ 153600,	B153600 },
	{ 230400,	B230400 },
	{ 307200,	B307200 },
	{ 460800,	B460800 },
	{ 921600,	B921600 },
	{ 1000000,	B1000000 },
	{ 1152000,	B1152000 },
	{ 1500000,	B1500000 },
	{ 2000000,	B2000000 },
	{ 2500000,	B2500000 },
	{ 3000000,	B3000000 },
	{ 3500000,	B3500000 },
	{ 4000000,	B4000000 },
	{ 0,		0}
};

#define	HEADERSIZE	6

static int Saved_line;		/* was savline() successful?	*/
static int Saved_termios;	/* was termios saved?	*/
static int
	Oddflag,	/* Default is no parity */
	Evenflag,	/* Default is no parity */
	Duplex = 1,	/* Default is full duplex */
	Terminal,	/* Default is no terminal */
	line_8bit = -1;	/* Default is same as terminal */

static const char P_PARITY[] = "Parity option error\r\n";

static struct termio Savettyb;
static struct termios Savettybs;
/*
 * set speed/echo/mode...
 *	tty 	-> terminal name
 *	spwant 	-> speed
 *	type	-> type
 *
 *	if spwant == 0, speed is untouched
 *	type is unused, but needed for compatibility
 *
 * return:
 *	none
 */
/*ARGSUSED*/
static void
fixline(int tty, int spwant, int type)
{
	register const struct sg_spds	*ps;
	struct termio		ttbuf;
	struct termios		ttbufs;
	int			speed = -1;
	int			i, istermios, ospeed;

	DEBUG(6, "fixline(%d, ", tty);
	DEBUG(6, "%d)\n", spwant);
	if ((istermios = (*Ioctl)(tty, TCGETS, &ttbufs)) < 0) {
		if ((*Ioctl)(tty, TCGETA, &ttbuf) != 0)
			return;
		ttbufs.c_lflag = ttbuf.c_lflag;
		ttbufs.c_oflag = ttbuf.c_oflag;
		ttbufs.c_iflag = ttbuf.c_iflag;
		ttbufs.c_cflag = ttbuf.c_cflag;
		for (i = 0; i < NCC; i++)
			ttbufs.c_cc[i] = ttbuf.c_cc[i];
	}
	if (spwant > 0) {
		for (ps = spds; ps->sp_val != 0; ps++)
			if (ps->sp_val == spwant) {
				speed = ps->sp_name;
				break;
			}
		if (speed < 0) {
			/*EMPTY*/
			DEBUG(5, "speed (%d) not supported\n", spwant);
		}
		ASSERT(speed >= 0, "BAD SPEED", "", spwant);
		ttbufs.c_cflag &= 0xffff0000;
		(void) cfsetospeed(&ttbufs, speed);
	} else { /* determine the current speed setting */
		ospeed = cfgetospeed(&ttbufs);
		ttbufs.c_cflag &= 0xffff0000;
		(void) cfsetospeed(&ttbufs, ospeed);
		for (ps = spds; ps->sp_val != 0; ps++)
			if (ps->sp_name == ospeed) {
				spwant = ps->sp_val;
				break;
			}
	}
	ttbufs.c_iflag &= 0xffff0000;
	ttbufs.c_oflag &= 0xffff0000;
	ttbufs.c_lflag &= 0xffff0000;

	ttbufs.c_cflag &= ~CLOCAL;

	if (EQUALS(Progname, "cu")) {

		/* set attributes associated with -h, -t, -e, and -o options */

		ttbufs.c_iflag = (IGNPAR | IGNBRK | IXON | IXOFF);
		if (line_8bit) {
			ttbufs.c_cflag |= CS8;
			ttbufs.c_iflag &= ~ISTRIP;
		} else {
			ttbufs.c_cflag |= CS7;
			ttbufs.c_iflag |= ISTRIP;
		}

		ttbufs.c_cc[VEOF] = '\1';
		ttbufs.c_cflag |= (CREAD | (speed ? HUPCL : 0));

		if (Evenflag) {				/* even parity -e */
			if (ttbufs.c_cflag & PARENB) {
				VERBOSE(P_PARITY, 0);
				exit(1);
			}
			ttbufs.c_cflag |= PARENB;
		} else if (Oddflag) {			/* odd parity -o */
			if (ttbufs.c_cflag & PARENB) {
				VERBOSE(P_PARITY, 0);
				exit(1);
			}
			ttbufs.c_cflag |= PARODD;
			ttbufs.c_cflag |= PARENB;
		}

		if (!Duplex)				/* half duplex -h */
			ttbufs.c_iflag &= ~(IXON | IXOFF);
		if (Terminal)				/* -t */
			ttbufs.c_oflag |= (OPOST | ONLCR);

	} else { /* non-cu */
		ttbufs.c_cflag |= (CS8 | CREAD | (speed ? HUPCL : 0));
		ttbufs.c_cc[VMIN] = HEADERSIZE;
		ttbufs.c_cc[VTIME] = 1;
	}

	if (istermios < 0) {
		ttbuf.c_lflag = ttbufs.c_lflag;
		ttbuf.c_oflag = ttbufs.c_oflag;
		ttbuf.c_iflag = ttbufs.c_iflag;
		ttbuf.c_cflag = ttbufs.c_cflag;
		for (i = 0; i < NCC; i++)
			ttbuf.c_cc[i] = ttbufs.c_cc[i];
		ASSERT((*Ioctl)(tty, TCSETAW, &ttbuf) >= 0,
		    "RETURN FROM fixline ioctl", "", errno);
	} else {
		ASSERT((*Ioctl)(tty, TCSETSW, &ttbufs) >= 0,
		    "RETURN FROM fixline ioctl", "", errno);
	}
}

static void
sethup(int dcf)
{
	struct termio ttbuf;

	if ((*Ioctl)(dcf, TCGETA, &ttbuf) != 0)
		return;
	if (!(ttbuf.c_cflag & HUPCL)) {
		ttbuf.c_cflag |= HUPCL;
		(void) (*Ioctl)(dcf, TCSETAW, &ttbuf);
	}
}

static void
ttygenbrk(int fn)
{
	if (isatty(fn))
		(void) (*Ioctl)(fn, TCSBRK, 0);
}

static int
savline(void)
{
	if ((Saved_termios = (*Ioctl)(0, TCGETS, &Savettybs)) < 0) {
		if ((*Ioctl)(0, TCGETA, &Savettyb) != 0) {
			Saved_line = FALSE;
		} else {
			Saved_line = TRUE;
			Savettyb.c_cflag = (Savettyb.c_cflag & ~CS8) | CS7;
			Savettyb.c_oflag |= OPOST;
			Savettyb.c_lflag |= (ISIG|ICANON|ECHO);
		}
	} else {
		Saved_line = TRUE;
		Savettybs.c_cflag = (Savettybs.c_cflag & ~CS8) | CS7;
		Savettybs.c_oflag |= OPOST;
		Savettybs.c_lflag |= (ISIG|ICANON|ECHO);
	}
	return (0);
}

static int
restline(void)
{
	if (Saved_line == TRUE) {
		if (Saved_termios < 0)
			return ((*Ioctl)(0, TCSETAW, &Savettyb));
		else
			return ((*Ioctl)(0, TCSETSW, &Savettybs));
	}
	return (0);
}
