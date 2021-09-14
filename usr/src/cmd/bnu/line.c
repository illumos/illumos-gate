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

#include "uucp.h"

static struct sg_spds {
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

#define	PACKSIZE	64
#define	HEADERSIZE	6

GLOBAL int
	packsize = PACKSIZE,
	xpacksize = PACKSIZE;

#define	SNDFILE	'S'
#define	RCVFILE 'R'
#define	RESET	'X'

#ifdef PKSPEEDUP
GLOBAL int linebaudrate;	/* for speedup hook in pk1.c */
#endif /*  PKSPEEDUP  */
static int Saved_line;		/* was savline() successful?	*/
static int Saved_termios;	/* was termios saved?	*/
GLOBAL int
	Oddflag = 0,	/* Default is no parity */
	Evenflag = 0,	/* Default is no parity */
	Duplex = 1,	/* Default is full duplex */
	Terminal = 0,	/* Default is no terminal */
	term_8bit = -1,	/* Default to terminal setting or 8 bit */
	line_8bit = -1;	/* Default is same as terminal */

static char *P_PARITY  = "Parity option error\r\n";

#ifdef ATTSVTTY

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
GLOBAL void
fixline(tty, spwant, type)
int	tty, spwant, type;
{
	register struct sg_spds	*ps;
	struct termio		ttbuf;
	struct termios		ttbufs;
	int			speed = -1;
	int			i, istermios, ospeed;

	DEBUG(6, "fixline(%d, ", tty);
	DEBUG(6, "%d)\n", spwant);
	if ((istermios = (*Ioctl)(tty, TCGETS, &ttbufs)) < 0) {
		if ((*Ioctl)(tty, TCGETA, &ttbuf) != 0) {
			return;
		} else {
			ttbufs.c_lflag = ttbuf.c_lflag;
			ttbufs.c_oflag = ttbuf.c_oflag;
			ttbufs.c_iflag = ttbuf.c_iflag;
			ttbufs.c_cflag = ttbuf.c_cflag;
			for (i = 0; i < NCC; i++)
				ttbufs.c_cc[i] = ttbuf.c_cc[i];
		}
	}
	if (spwant > 0) {
		for (ps = spds; ps->sp_val; ps++)
			if (ps->sp_val == spwant) {
				speed = ps->sp_name;
				break;
			}
		if (speed < 0)
			DEBUG(5, "speed (%d) not supported\n", spwant);
		ASSERT(speed >= 0, "BAD SPEED", "", spwant);
		ttbufs.c_cflag &= 0xffff0000;
		cfsetospeed(&ttbufs, speed);
	} else { /* determine the current speed setting */
		ospeed = cfgetospeed(&ttbufs);
		ttbufs.c_cflag &= 0xffff0000;
		cfsetospeed(&ttbufs, ospeed);
		for (ps = spds; ps->sp_val; ps++)
			if (ps->sp_name == ospeed) {
				spwant = ps->sp_val;
				break;
			}
	}
	/*
	 * In order to prevent attempts at split speed, all baud rate
	 * bitfields should be cleared. Thus cfsetispeed is used to
	 * set the speed to zero.
	 */
	(void) cfsetispeed(&ttbufs, 0);
	ttbufs.c_iflag &= 0xffff0000;
	ttbufs.c_oflag &= 0xffff0000;
	ttbufs.c_lflag &= 0xffff0000;
#ifdef PKSPEEDUP
	linebaudrate = spwant;
#endif /*  PKSPEEDUP  */

#ifdef NO_MODEM_CTRL
	/*   CLOCAL may cause problems on pdp11s with DHs */
	if (type == D_DIRECT) {
		DEBUG(4, "fixline - direct\n%s", "");
		ttbufs.c_cflag |= CLOCAL;
	} else
#endif /* NO_MODEM_CTRL */
		ttbufs.c_cflag &= ~CLOCAL;

	if (!EQUALS(Progname, "uucico")) {

		/* set attributes associated with -h, -t, -e, and -o options */

		ttbufs.c_iflag = (IGNPAR | IGNBRK | IXON | IXOFF);
		ttbufs.c_cc[VEOF] = '\1';
		ttbufs.c_cflag |= (CREAD | (speed ? HUPCL : 0));

		if (line_8bit) {
			ttbufs.c_cflag |= CS8;
			ttbufs.c_iflag &= ~ISTRIP;
		} else {
			if (Evenflag) {			/* even parity -e */
				ttbufs.c_cflag &= ~PARODD;
			} else if (Oddflag) {		/* odd parity -o */
				ttbufs.c_cflag |= PARODD;
			}
			ttbufs.c_cflag |= CS7|PARENB;
			ttbufs.c_iflag |= ISTRIP;
		}

		if (!Duplex)				/* half duplex -h */
			ttbufs.c_iflag &= ~(IXON | IXOFF);
		if (Terminal)				/* -t */
			ttbufs.c_oflag |= (OPOST | ONLCR);

	} else { /* non-uucico */
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

GLOBAL void
sethup(dcf)
int	dcf;
{
	struct termio ttbuf;

	if ((*Ioctl)(dcf, TCGETA, &ttbuf) != 0)
		return;
	if (!(ttbuf.c_cflag & HUPCL)) {
		ttbuf.c_cflag |= HUPCL;
		(void) (*Ioctl)(dcf, TCSETAW, &ttbuf);
	}
}

GLOBAL void
ttygenbrk(fn)
register int	fn;
{
	if (isatty(fn))
		(void) (*Ioctl)(fn, TCSBRK, 0);
}


/*
 * optimize line setting for sending or receiving files
 * return:
 *	none
 */
GLOBAL void
setline(type)
register char	type;
{
	static struct termio tbuf;
	static struct termios tbufs;
	int i, vtime, istermios, ospeed;

	DEBUG(2, "setline - %c\n", type);

	if ((istermios = (*Ioctl)(Ifn, TCGETS, &tbufs)) < 0) {
		if ((*Ioctl)(Ifn, TCGETA, &tbuf) != 0) {
			return;
		} else {
			tbufs.c_lflag = tbuf.c_lflag;
			tbufs.c_oflag = tbuf.c_oflag;
			tbufs.c_iflag = tbuf.c_iflag;
			tbufs.c_cflag = tbuf.c_cflag;
			for (i = 0; i < NCC; i++)
				tbufs.c_cc[i] = tbuf.c_cc[i];
		}
	}
	switch (type) {
	case RCVFILE:
		ospeed = cfgetospeed(&tbufs);
		switch (ospeed) {
#ifdef B19200
		case B19200:
#else
#ifdef EXTA
		case EXTA:
#endif
#endif
#ifdef B38400
		case B38400:
#endif
		case B57600:
		case B76800:
		case B115200:
		case B153600:
		case B230400:
		case B307200:
		case B460800:
		case B921600:
		case B9600:
			vtime = 1;
			break;
		case B4800:
			vtime = 4;
			break;
		default:
			vtime = 8;
			break;
		}
		if (tbufs.c_cc[VMIN] != packsize ||
		    tbufs.c_cc[VTIME] != vtime) {
		    tbufs.c_cc[VMIN] = packsize;
		    tbufs.c_cc[VTIME] = vtime;
		    if (istermios < 0) {
			tbuf.c_lflag = tbufs.c_lflag;
			tbuf.c_oflag = tbufs.c_oflag;
			tbuf.c_iflag = tbufs.c_iflag;
			tbuf.c_cflag = tbufs.c_cflag;
			for (i = 0; i < NCC; i++)
				tbuf.c_cc[i] = tbufs.c_cc[i];
			if ((*Ioctl)(Ifn, TCSETAW, &tbuf) != 0)
				DEBUG(4, "setline Ioctl failed errno=%d\n",
				    errno);
			} else {
				if ((*Ioctl)(Ifn, TCSETSW, &tbufs) != 0)
					DEBUG(4,
					    "setline Ioctl failed errno=%d\n",
					    errno);
			}
		}
		break;

	case SNDFILE:
	case RESET:
		if (tbufs.c_cc[VMIN] != HEADERSIZE) {
			tbufs.c_cc[VMIN] = HEADERSIZE;
			if (istermios < 0) {
				tbuf.c_lflag = tbufs.c_lflag;
				tbuf.c_oflag = tbufs.c_oflag;
				tbuf.c_iflag = tbufs.c_iflag;
				tbuf.c_cflag = tbufs.c_cflag;
				for (i = 0; i < NCC; i++)
					tbuf.c_cc[i] = tbufs.c_cc[i];
				if ((*Ioctl)(Ifn, TCSETAW, &tbuf) != 0)
					DEBUG(4,
					    "setline Ioctl failed errno=%d\n",
					    errno);
			} else {
				if ((*Ioctl)(Ifn, TCSETSW, &tbufs) != 0)
					DEBUG(4,
					    "setline Ioctl failed errno=%d\n",
					    errno);
			}
		}
		break;
	}
}

GLOBAL int
savline()
{
	if ((Saved_termios = (*Ioctl)(0, TCGETS, &Savettybs)) < 0) {
		if ((*Ioctl)(0, TCGETA, &Savettyb) != 0) {
			Saved_line = FALSE;
		} else {
			Saved_line = TRUE;
			Savettyb.c_cflag =
			    (Savettyb.c_cflag & ~CS8) | CS7 | PARENB;
			Savettyb.c_oflag |= OPOST;
			Savettyb.c_lflag |= (ISIG|ICANON|ECHO);
		}
	} else {
		Saved_line = TRUE;
		Savettybs.c_cflag = (Savettybs.c_cflag & ~CS8) | CS7 | PARENB;
		Savettybs.c_oflag |= OPOST;
		Savettybs.c_lflag |= (ISIG|ICANON|ECHO);
	}
	return (0);
}

#ifdef SYTEK

/*
 *	sytfixline(tty, spwant)	set speed/echo/mode...
 *	int tty, spwant;
 *
 *	return codes:  none
 */

GLOBAL void
sytfixline(tty, spwant)
int tty, spwant;
{
	struct termio ttbuf;
	struct termios ttbufs;
	struct sg_spds *ps;
	int speed = -1;
	int i, ret, istermios;

	if ((istermios = (*Ioctl)(tty, TCGETS, &ttbufs)) < 0) {
		if ((*Ioctl)(tty, TCGETA, &ttbuf) != 0) {
			return;
		} else {
			ttbufs.c_lflag = ttbuf.c_lflag;
			ttbufs.c_oflag = ttbuf.c_oflag;
			ttbufs.c_iflag = ttbuf.c_iflag;
			ttbufs.c_cflag = ttbuf.c_cflag;
			for (i = 0; i < NCC; i++)
				ttbufs.c_cc[i] = ttbuf.c_cc[i];
		}
	}
	for (ps = spds; ps->sp_val >= 0; ps++)
		if (ps->sp_val == spwant)
			speed = ps->sp_name;
	DEBUG(4, "sytfixline - speed= %d\n", speed);
	ASSERT(speed >= 0, "BAD SPEED", "", spwant);
	ttbufs.c_iflag &= 0xffff0000;
	ttbufs.c_oflag &= 0xffff0000;
	ttbufs.c_lflag &= 0xffff0000;
	ttbufs.c_cflag &= 0xffff0000;
	cfsetospeed(&ttbufs, speed);
	ttbufs.c_cflag |= (CS8|CLOCAL);
	ttbufs.c_cc[VMIN] = 6;
	ttbufs.c_cc[VTIME] = 1;
	if (istermios < 0) {
		ttbuf.c_lflag = ttbufs.c_lflag;
		ttbuf.c_oflag = ttbufs.c_oflag;
		ttbuf.c_iflag = ttbufs.c_iflag;
		ttbuf.c_cflag = ttbufs.c_cflag;
		for (i = 0; i < NCC; i++)
			ttbuf.c_cc[i] = ttbufs.c_cc[i];
		ret = (*Ioctl)(tty, TCSETAW, &ttbuf);
	} else
		ret = (*Ioctl)(tty, TCSETAWS &ttbufs);
	ASSERT(ret >= 0, "RETURN FROM sytfixline", "", ret);
}

GLOBAL void
sytfix2line(tty)
int tty;
{
	struct termio ttbuf;
	int ret;

	if ((*Ioctl)(tty, TCGETA, &ttbuf) != 0)
		return;
	ttbuf.c_cflag &= ~CLOCAL;
	ttbuf.c_cflag |= CREAD|HUPCL;
	ret = (*Ioctl)(tty, TCSETAW, &ttbuf);
	ASSERT(ret >= 0, "RETURN FROM sytfix2line", "", ret);
}

#endif /* SYTEK */

GLOBAL int
restline()
{
	if (Saved_line == TRUE) {
		if (Saved_termios < 0)
			return ((*Ioctl)(0, TCSETAW, &Savettyb));
		else
			return ((*Ioctl)(0, TCSETSW, &Savettybs));
	}
	return (0);
}

#else /* !ATTSVTTY */

static struct sgttyb Savettyb;

/*
 *	fixline(tty, spwant, type)	set speed/echo/mode...
 *	int tty, spwant;
 *
 *	if spwant == 0, speed is untouched
 *	type is unused, but needed for compatibility
 *
 *	return codes:  none
 */

/*ARGSUSED*/
GLOBAL void
fixline(tty, spwant, type)
int tty, spwant, type;
{
	struct sgttyb	ttbuf;
	struct sg_spds	*ps;
	int		 speed = -1;

	DEBUG(6, "fixline(%d, ", tty);
	DEBUG(6, "%d)\n", spwant);

	if ((*Ioctl)(tty, TIOCGETP, &ttbuf) != 0)
		return;
	if (spwant > 0) {
		for (ps = spds; ps->sp_val; ps++)
			if (ps->sp_val == spwant) {
				speed = ps->sp_name;
				break;
			}
		ASSERT(speed >= 0, "BAD SPEED", "", spwant);
		ttbuf.sg_ispeed = ttbuf.sg_ospeed = speed;
	} else {
		for (ps = spds; ps->sp_val; ps++)
			if (ps->sp_name == ttbuf.sg_ispeed) {
				spwant = ps->sp_val;
				break;
			}
		ASSERT(spwant >= 0, "BAD SPEED", "", ttbuf.sg_ispeed);
	}
	ttbuf.sg_flags = (ANYP | RAW);
#ifdef PKSPEEDUP
	linebaudrate = spwant;
#endif /*  PKSPEEDUP  */
	(void) (*Ioctl)(tty, TIOCSETP, &ttbuf);
	(void) (*Ioctl)(tty, TIOCHPCL, STBNULL);
	(void) (*Ioctl)(tty, TIOCEXCL, STBNULL);
}

GLOBAL void
sethup(dcf)
int	dcf;
{
	if (isatty(dcf))
		(void) (*Ioctl)(dcf, TIOCHPCL, STBNULL);
}

/*
 *	genbrk		send a break
 *
 *	return codes;  none
 */

GLOBAL void
ttygenbrk(fn)
{
	if (isatty(fn)) {
		(void) (*Ioctl)(fn, TIOCSBRK, 0);
#ifndef V8
		nap(HZ/10);				/* 0.1 second break */
		(void) (*Ioctl)(fn, TIOCCBRK, 0);
#endif
	}
}

/*
 * V7 and RT aren't smart enough for this -- linebaudrate is the best
 * they can do.
 */
/*ARGSUSED*/
GLOBAL void
setline(dummy) { }

GLOBAL int
savline()
{
	if ((*Ioctl)(0, TIOCGETP, &Savettyb) != 0)
		Saved_line = FALSE;
	else {
		Saved_line = TRUE;
		Savettyb.sg_flags |= ECHO;
		Savettyb.sg_flags &= ~RAW;
	}
	return (0);
}

GLOBAL int
restline()
{
	if (Saved_line == TRUE)
		return ((*Ioctl)(0, TIOCSETP, &Savettyb));
	return (0);
}
#endif
