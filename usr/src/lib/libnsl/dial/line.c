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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

/* This is a new line.c, which consists of line.c and culine.c
 * merged together.
 */

#include "uucp.h"
#include <rpc/trace.h> 

static const struct sg_spds {
	int	sp_val,
		sp_name;
} spds[] = {
	{  50,   B50},
	{  75,   B75},
	{ 110,  B110},
	{ 134,  B134},
	{ 150,  B150},
	{ 200,  B200},
	{ 300,  B300},
	{ 600,  B600},
	{1200, B1200},
	{1800, B1800},
	{2400, B2400},
	{4800, B4800},
	{9600, B9600},
#ifdef EXTA
	{19200,	EXTA},
#endif
#ifdef B19200
	{19200,	B19200},
#endif
#ifdef B38400
	{38400,	B38400},
#endif
	{57600, B57600},
	{76800, B76800},
	{115200, B115200},
	{153600, B153600},
	{230400, B230400},
	{307200, B307200},
	{460800, B460800},
	{0,    0}
};

#define PACKSIZE	64
#define HEADERSIZE	6

GLOBAL int
     packsize = PACKSIZE,
    xpacksize = PACKSIZE;

#define SNDFILE	'S'
#define RCVFILE 'R'
#define RESET	'X'

GLOBAL int donap;	/* for speedup hook in pk1.c */
static int Saved_line;		/* was savline() successful?	*/
static int Saved_termios;	/* was termios saved?	*/
GLOBAL int
	Oddflag,	/* Default is no parity */
	Evenflag,	/* Default is no parity */
	Duplex = 1,	/* Default is full duplex */
	Terminal,	/* Default is no terminal */
	term_8bit = -1,	/* Default to terminal setting or 8 bit */
	line_8bit = -1;	/* Default is same as terminal */

static const char P_PARITY[] = "Parity option error\r\n";

#ifdef ATTSV

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
	register const struct sg_spds	*ps;
	struct termio		ttbuf;
	struct termios		ttbufs;
	int			speed = -1;
	int			i, istermios, ospeed;

	trace4(TR_fixline, 0, tty, spwant, type);
	DEBUG(6, "fixline(%d, ", tty);
	DEBUG(6, "%d)\n", spwant);
	if ((istermios = (*Ioctl)(tty, TCGETS, &ttbufs)) < 0) {
	    if ((*Ioctl)(tty, TCGETA, &ttbuf) != 0) {
		trace1(TR_fixline, 1);
		return;
	    } else {
		ttbufs.c_lflag = ttbuf.c_lflag;
		ttbufs.c_oflag = ttbuf.c_oflag;
		ttbufs.c_iflag = ttbuf.c_iflag;
		ttbufs.c_cflag = ttbuf.c_cflag;
		for(i = 0; i < NCC; i++)
			ttbufs.c_cc[i] = ttbuf.c_cc[i];
	    }
	}
	if (spwant > 0) {
		for (ps = spds; ps->sp_val; ps++)
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
	ttbufs.c_iflag &= 0xffff0000;
	ttbufs.c_oflag &= 0xffff0000;
	ttbufs.c_lflag &= 0xffff0000;

#ifdef NO_MODEM_CTRL
	/*   CLOCAL may cause problems on pdp11s with DHs */
	if (type == D_DIRECT) {
		DEBUG(4, "fixline - direct\n%s", "");
		ttbufs.c_cflag |= CLOCAL;
	} else
#endif /* NO_MODEM_CTRL */
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

		if (Evenflag) {				/*even parity -e */
		    if (ttbufs.c_cflag & PARENB) {
				VERBOSE(P_PARITY, 0);
				trace1(TR_fixline, 1);
				exit (1);
		    } else 
				ttbufs.c_cflag |= PARENB;
		} else if (Oddflag) {			/*odd parity -o */
		    if (ttbufs.c_cflag & PARENB) {
				VERBOSE(P_PARITY, 0);
				trace1(TR_fixline, 1);
				exit (1);
		    } else {
				ttbufs.c_cflag |= PARODD;
				ttbufs.c_cflag |= PARENB;
		    }
		}

		if (!Duplex)				/*half duplex -h */
		    ttbufs.c_iflag &= ~(IXON | IXOFF);
		if (Terminal)				/* -t */
		    ttbufs.c_oflag |= (OPOST | ONLCR);

	} else { /* non-cu */
		ttbufs.c_cflag |= (CS8 | CREAD | (speed ? HUPCL : 0));
		ttbufs.c_cc[VMIN] = HEADERSIZE;
		ttbufs.c_cc[VTIME] = 1;
	}

	donap = (spwant > 0 && spwant < 4800);

	if (istermios < 0) {
		ttbuf.c_lflag = ttbufs.c_lflag;
		ttbuf.c_oflag = ttbufs.c_oflag;
		ttbuf.c_iflag = ttbufs.c_iflag;
		ttbuf.c_cflag = ttbufs.c_cflag;
		for(i = 0; i < NCC; i++)
			ttbuf.c_cc[i] = ttbufs.c_cc[i];
		ASSERT((*Ioctl)(tty, TCSETAW, &ttbuf) >= 0,
			"RETURN FROM fixline ioctl", "", errno);
	} else {
		ASSERT((*Ioctl)(tty, TCSETSW, &ttbufs) >= 0,
			"RETURN FROM fixline ioctl", "", errno);
	}
	trace1(TR_fixline, 1);
	return;
}

GLOBAL void
sethup(dcf)
int	dcf;
{
	struct termio ttbuf;

	trace2(TR_sethup, 0, dcf);
	if ((*Ioctl)(dcf, TCGETA, &ttbuf) != 0) {
		trace1(TR_sethup, 1);
		return;
	}
	if (!(ttbuf.c_cflag & HUPCL)) {
		ttbuf.c_cflag |= HUPCL;
		(void) (*Ioctl)(dcf, TCSETAW, &ttbuf);
	}
	trace1(TR_sethup, 1);
	return;
}

GLOBAL void
ttygenbrk(fn)
register int	fn;
{
	trace2(TR_ttygenbrk, 0, fn);
	if (isatty(fn)) 
		(void) (*Ioctl)(fn, TCSBRK, 0);
	trace1(TR_ttygenbrk, 1);
	return;
}


#ifndef DIAL
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
	
	trace1(TR_setline, 0);
	DEBUG(2, "setline - %c\n", type);
	if ((istermios = (*Ioctl)(Ifn, TCGETS, &tbufs)) < 0) {
		if ((*Ioctl)(Ifn, TCGETA, &tbuf) != 0) {
			trace1(TR_setline, 1);
			return;
		} else {
			tbufs.c_lflag = tbuf.c_lflag;
			tbufs.c_oflag = tbuf.c_oflag;
			tbufs.c_iflag = tbuf.c_iflag;
			tbufs.c_cflag = tbuf.c_cflag;
			for(i = 0; i < NCC; i++)
				tbufs.c_cc[i] = tbuf.c_cc[i];
		}
	}
	switch (type) {
	case RCVFILE:
		ospeed = cfgetospeed(&tbufs);
		switch (ospeed) {
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
			for(i = 0; i < NCC; i++)
				tbuf.c_cc[i] = tbufs.c_cc[i];
			if ((*Ioctl)(Ifn, TCSETAW, &tbuf) != 0)
				DEBUG(4, "setline Ioctl failed errno=%d\n", errno);
		    } else {
			if ((*Ioctl)(Ifn, TCSETSW, &tbufs) != 0)
				DEBUG(4, "setline Ioctl failed errno=%d\n", errno);
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
			for(i = 0; i < NCC; i++)
				tbuf.c_cc[i] = tbufs.c_cc[i];
			if ((*Ioctl)(Ifn, TCSETAW, &tbuf) != 0)
				DEBUG(4, "setline Ioctl failed errno=%d\n", errno);
		    } else {
			if ((*Ioctl)(Ifn, TCSETSW, &tbufs) != 0)
				DEBUG(4, "setline Ioctl failed errno=%d\n", errno);
		    }
		}
		break;
	}
	trace1(TR_setline, 1);
	return;
}
#endif

GLOBAL int
savline()
{
	trace1(TR_savline, 0);
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
	trace1(TR_savline, 1);
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
	const struct sg_spds *ps;
	int speed = -1;
	int i, ret, istermios;

	trace3(TR_sytfixline, 0, tty, spwant);
	if ((istermios = (*Ioctl)(tty, TCGETS, &ttbufs)) < 0) {
		if ((*Ioctl)(tty, TCGETA, &ttbuf) != 0) {
			trace1(TR_sytfixline, 1);
			return;
		} else {
			ttbufs.c_lflag = ttbuf.c_lflag;
			ttbufs.c_oflag = ttbuf.c_oflag;
			ttbufs.c_iflag = ttbuf.c_iflag;
			ttbufs.c_cflag = ttbuf.c_cflag;
			for(i = 0; i < NCC; i++)
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
		for(i = 0; i < NCC; i++)
			ttbuf.c_cc[i] = ttbufs.c_cc[i];
		ret = (*Ioctl)(tty, TCSETAW, &ttbuf);
	} else
		ret = (*Ioctl)(tty, TCSETSW, &ttbufs);

	ASSERT(ret >= 0, "RETURN FROM sytfixline", "", ret);
	trace1(TR_sytfixline, 1);
	return;
}

GLOBAL void
sytfix2line(tty)
int tty;
{
	struct termio ttbuf;
	int ret;

	trace2(TR_sytfix2line, 0, tty);
	if ((*Ioctl)(tty, TCGETA, &ttbuf) != 0) {
		trace1(TR_sytfix2line, 1);
		return;
	}
	ttbuf.c_cflag &= ~CLOCAL;
	ttbuf.c_cflag |= CREAD|HUPCL;
	ret = (*Ioctl)(tty, TCSETAW, &ttbuf);
	ASSERT(ret >= 0, "RETURN FROM sytfix2line", "", ret);
	trace1(TR_sytfix2line, 1);
	return;
}

#endif /* SYTEK */

GLOBAL int
restline()
{
	trace1(TR_restline, 0);
	if (Saved_line == TRUE) {
		trace1(TR_restline, 1);
		if (Saved_termios < 0)
			return ((*Ioctl)(0, TCSETAW, &Savettyb));
		else
			return ((*Ioctl)(0, TCSETSW, &Savettybs));
	}
	trace1(TR_restline, 1);
	return (0);
}

#else /* !ATTSV */

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

	trace4(TR_fixline, 0, tty, spwant, type);
	DEBUG(6, "fixline(%d, ", tty);
	DEBUG(6, "%d)\n", spwant);

	if ((*Ioctl)(tty, TIOCGETP, &ttbuf) != 0) {
		trace1(TR_fixline, 1);
		return;
	}
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
	(void) (*Ioctl)(tty, TIOCSETP, &ttbuf);
	(void) (*Ioctl)(tty, TIOCHPCL, STBNULL);
	(void) (*Ioctl)(tty, TIOCEXCL, STBNULL);
	donap = (spwant > 0 && spwant < 4800);
	trace1(TR_fixline, 1);
	return;
}

GLOBAL void
sethup(dcf)
int	dcf;
{
	trace2(TR_sethup, 0, dcf);
	if (isatty(dcf)) 
		(void) (*Ioctl)(dcf, TIOCHPCL, STBNULL);
	trace1(TR_sethup, 1);
	return;
}

/*
 *	genbrk		send a break
 *
 *	return codes;  none
 */

GLOBAL void
ttygenbrk(fn)
{
	trace1(TR_ttygenbrk, 0);
	if (isatty(fn)) {
		(void) (*Ioctl)(fn, TIOCSBRK, 0);
#ifndef V8
		nap(HZ/10);				/* 0.1 second break */
		(void) (*Ioctl)(fn, TIOCCBRK, 0);
#endif
	}
	trace1(TR_ttygenbrk, 1);
	return;
}

#ifndef DIAL
/*
 * V7 and RT aren't smart enough for this -- linebaudrate is the best
 * they can do.
 */
/*ARGSUSED*/
GLOBAL void
setline(dummy) 
{ 
	trace1(TR_setline, 0);
	trace1(TR_setline, 1);
}
#endif

GLOBAL int
savline()
{
	trace1(TR_savline, 0);
	if ((*Ioctl)(0, TIOCGETP, &Savettyb) != 0) {
		Saved_line = FALSE;
	else {
		Saved_line = TRUE;
		Savettyb.sg_flags |= ECHO;
		Savettyb.sg_flags &= ~RAW;
	}
	trace1(TR_savline, 1);
	return (0);
}

GLOBAL int
restline()
{
	trace1(TR_restline, 0);
	if (Saved_line == TRUE) {
		trace1(TR_restline, 1);
		return ((*Ioctl)(0, TIOCSETP, &Savettyb));
	}
	trace1(TR_restline, 1);
	return (0);
}
#endif
