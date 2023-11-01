/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * The following routines try to encapsulate what is system dependent
 * (at least between 4.x and dos) which is used in telnet.c.
 */


#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <signal.h>
#include <errno.h>
#include <arpa/telnet.h>

#include "ring.h"

#include "defines.h"
#include "externs.h"
#include "types.h"

#define	SIG_FUNC_RET	void

int tout;			/* Output file descriptor */
static int tin;			/* Input file descriptor */
int net = -1;


#ifndef	USE_TERMIO
struct	tchars otc = { 0 }, ntc = { 0 };
struct	ltchars oltc = { 0 }, nltc = { 0 };
struct	sgttyb ottyb = { 0 }, nttyb = { 0 };
int	olmode = 0;
#define	cfgetispeed(ptr)	(ptr)->sg_ispeed
#define	cfgetospeed(ptr)	(ptr)->sg_ospeed
#define	old_tc ottyb

#else	/* USE_TERMIO */
static struct	termio old_tc = { 0 };
extern struct termio new_tc;
#endif	/* USE_TERMIO */

static fd_set ibits, obits, xbits;

static SIG_FUNC_RET susp(int);
void fatal_tty_error(char *doing_what);


void
init_sys()
{
	tout = fileno(stdout);
	tin = fileno(stdin);
	FD_ZERO(&ibits);
	FD_ZERO(&obits);
	FD_ZERO(&xbits);

	errno = 0;
}


int
TerminalWrite(buf, n)
	char *buf;
	int  n;
{
	return (write(tout, buf, n));
}

static int
TerminalRead(buf, n)
	char *buf;
	int  n;
{
	return (read(tin, buf, n));
}

#ifdef	KLUDGELINEMODE
extern int kludgelinemode;
#endif
/*
 * TerminalSpecialChars()
 *
 * Look at an input character to see if it is a special character
 * and decide what to do.
 *
 * Output:
 *
 *	0	Don't add this character.
 *	1	Do add this character
 */
int
TerminalSpecialChars(c)
	int	c;
{
	/*
	 * Don't check for signal characters here.  If MODE_TRAPSIG is on,
	 * then the various signal handlers will catch the characters.  If
	 * the character in question gets here, then it must have been LNEXTed
	 */
	if (c == termQuitChar) {
#ifdef	KLUDGELINEMODE
		if (kludgelinemode) {
			if (sendbrk() == -1) {
				/* This won't return. */
				fatal_tty_error("write");
			}
			return (0);
		}
#endif
	} else if (c == termFlushChar) {
		/* Transmit Abort Output */
		if (xmitAO() == -1) {
			/* This won't return. */
			fatal_tty_error("write");
		}
		return (0);
	} else if (!MODE_LOCAL_CHARS(globalmode)) {
		if (c == termKillChar) {
			xmitEL();
			return (0);
		} else if (c == termEraseChar) {
			xmitEC();	/* Transmit Erase Character */
			return (0);
		}
	}
	return (1);
}


/*
 * Flush output to the terminal
 */

void
TerminalFlushOutput()
{
	if (isatty(fileno(stdout))) {
		(void) ioctl(fileno(stdout), TIOCFLUSH, NULL);
	}
}

void
TerminalSaveState()
{
#ifndef	USE_TERMIO
	(void) ioctl(0, TIOCGETP, &ottyb);
	(void) ioctl(0, TIOCGETC, &otc);
	(void) ioctl(0, TIOCGLTC, &oltc);
	(void) ioctl(0, TIOCLGET, &olmode);

	ntc = otc;
	nltc = oltc;
	nttyb = ottyb;

#else	/* USE_TERMIO */
	(void) tcgetattr(0, &old_tc);

	new_tc = old_tc;
	termAytChar = CONTROL('T');
#endif	/* USE_TERMIO */
}

cc_t *
tcval(func)
	register int func;
{
	switch (func) {
	case SLC_IP:	return (&termIntChar);
	case SLC_ABORT:	return (&termQuitChar);
	case SLC_EOF:	return (&termEofChar);
	case SLC_EC:	return (&termEraseChar);
	case SLC_EL:	return (&termKillChar);
	case SLC_XON:	return (&termStartChar);
	case SLC_XOFF:	return (&termStopChar);
	case SLC_FORW1:	return (&termForw1Char);
#ifdef	USE_TERMIO
	case SLC_FORW2:	return (&termForw2Char);
	case SLC_AO:	return (&termFlushChar);
	case SLC_SUSP:	return (&termSuspChar);
	case SLC_EW:	return (&termWerasChar);
	case SLC_RP:	return (&termRprntChar);
	case SLC_LNEXT:	return (&termLiteralNextChar);
#endif

	case SLC_SYNCH:
	case SLC_BRK:
	case SLC_EOR:
	default:
		return ((cc_t *)0);
	}
}

void
TerminalDefaultChars()
{
#ifndef	USE_TERMIO
	ntc = otc;
	nltc = oltc;
	nttyb.sg_kill = ottyb.sg_kill;
	nttyb.sg_erase = ottyb.sg_erase;
#else	/* USE_TERMIO */
	(void) memcpy(new_tc.c_cc, old_tc.c_cc, sizeof (old_tc.c_cc));
	termAytChar = CONTROL('T');
#endif	/* USE_TERMIO */
}

/*
 * TerminalNewMode - set up terminal to a specific mode.
 *	MODE_ECHO: do local terminal echo
 *	MODE_FLOW: do local flow control
 *	MODE_TRAPSIG: do local mapping to TELNET IAC sequences
 *	MODE_EDIT: do local line editing
 *
 *	Command mode:
 *		MODE_ECHO|MODE_EDIT|MODE_FLOW|MODE_TRAPSIG
 *		local echo
 *		local editing
 *		local xon/xoff
 *		local signal mapping
 *
 *	Linemode:
 *		local/no editing
 *	Both Linemode and Single Character mode:
 *		local/remote echo
 *		local/no xon/xoff
 *		local/no signal mapping
 */


void
TerminalNewMode(f)
	register int f;
{
	static int prevmode = -2;	/* guaranteed unique */
#ifndef	USE_TERMIO
	struct tchars tc;
	struct ltchars ltc;
	struct sgttyb sb;
	int lmode;
#else	/* USE_TERMIO */
	struct termio tmp_tc;
#endif	/* USE_TERMIO */
	int onoff;
	int old;
	cc_t esc;
	sigset_t nset;

	globalmode = f&~MODE_FORCE;
	if (prevmode == f)
		return;

	/*
	 * Write any outstanding data before switching modes
	 * ttyflush() returns 0 only when there was no data
	 * to write out; it returns -1 if it couldn't do
	 * anything at all, returns -2 if there was a write
	 * error (other than EWOULDBLOCK), and otherwise it
	 * returns 1 + the number of characters left to write.
	 */
#ifndef	USE_TERMIO
	/*
	 * We would really like ask the kernel to wait for the output
	 * to drain, like we can do with the TCSADRAIN, but we don't have
	 * that option.  The only ioctl that waits for the output to
	 * drain, TIOCSETP, also flushes the input queue, which is NOT
	 * what we want(TIOCSETP is like TCSADFLUSH).
	 */
#endif
	old = ttyflush(SYNCHing|flushout);
	if (old == -1 || old > 1) {
#ifdef	USE_TERMIO
		(void) tcgetattr(tin, &tmp_tc);
#endif	/* USE_TERMIO */
		do {
			/*
			 * Wait for data to drain, then flush again.
			 */
#ifdef	USE_TERMIO
			(void) tcsetattr(tin, TCSADRAIN, &tmp_tc);
#endif	/* USE_TERMIO */
			old = ttyflush(SYNCHing|flushout);
		} while (old == -1 || old > 1);
	}

	old = prevmode;
	prevmode = f&~MODE_FORCE;
#ifndef	USE_TERMIO
	sb = nttyb;
	tc = ntc;
	ltc = nltc;
	lmode = olmode;
#else
	tmp_tc = new_tc;
#endif

	if (f&MODE_ECHO) {
#ifndef	USE_TERMIO
		sb.sg_flags |= ECHO;
#else
		tmp_tc.c_lflag |= ECHO;
		tmp_tc.c_oflag |= ONLCR;
		if (crlf)
			tmp_tc.c_iflag |= ICRNL;
#endif
	} else {
#ifndef	USE_TERMIO
		sb.sg_flags &= ~ECHO;
#else
		tmp_tc.c_lflag &= ~ECHO;
		tmp_tc.c_oflag &= ~ONLCR;
#ifdef notdef
		if (crlf)
			tmp_tc.c_iflag &= ~ICRNL;
#endif
#endif
	}

	if ((f&MODE_FLOW) == 0) {
#ifndef	USE_TERMIO
		tc.t_startc = _POSIX_VDISABLE;
		tc.t_stopc = _POSIX_VDISABLE;
#else
		tmp_tc.c_iflag &= ~(IXOFF|IXON); /* Leave the IXANY bit alone */
	} else {
		if (restartany < 0) {
			/* Leave the IXANY bit alone */
			tmp_tc.c_iflag |= IXOFF|IXON;
		} else if (restartany > 0) {
			tmp_tc.c_iflag |= IXOFF|IXON|IXANY;
		} else {
			tmp_tc.c_iflag |= IXOFF|IXON;
			tmp_tc.c_iflag &= ~IXANY;
		}
#endif
	}

	if ((f&MODE_TRAPSIG) == 0) {
#ifndef	USE_TERMIO
		tc.t_intrc = _POSIX_VDISABLE;
		tc.t_quitc = _POSIX_VDISABLE;
		tc.t_eofc = _POSIX_VDISABLE;
		ltc.t_suspc = _POSIX_VDISABLE;
		ltc.t_dsuspc = _POSIX_VDISABLE;
#else
		tmp_tc.c_lflag &= ~ISIG;
#endif
		localchars = 0;
	} else {
#ifdef	USE_TERMIO
		tmp_tc.c_lflag |= ISIG;
#endif
		localchars = 1;
	}

	if (f&MODE_EDIT) {
#ifndef	USE_TERMIO
		sb.sg_flags &= ~CBREAK;
		sb.sg_flags |= CRMOD;
#else
		tmp_tc.c_lflag |= ICANON;
#endif
	} else {
#ifndef	USE_TERMIO
		sb.sg_flags |= CBREAK;
		if (f&MODE_ECHO)
			sb.sg_flags |= CRMOD;
		else
			sb.sg_flags &= ~CRMOD;
#else
		tmp_tc.c_lflag &= ~ICANON;
		tmp_tc.c_iflag &= ~ICRNL;
		tmp_tc.c_cc[VMIN] = 1;
		tmp_tc.c_cc[VTIME] = 0;
#endif
	}

	if ((f&(MODE_EDIT|MODE_TRAPSIG)) == 0) {
#ifndef	USE_TERMIO
		ltc.t_lnextc = _POSIX_VDISABLE;
#else
		tmp_tc.c_cc[VLNEXT] = (cc_t)(_POSIX_VDISABLE);
#endif
	}

	if (f&MODE_SOFT_TAB) {
#ifndef USE_TERMIO
		sb.sg_flags |= XTABS;
#else
		tmp_tc.c_oflag &= ~TABDLY;
		tmp_tc.c_oflag |= TAB3;
#endif
	} else {
#ifndef USE_TERMIO
		sb.sg_flags &= ~XTABS;
#else
		tmp_tc.c_oflag &= ~TABDLY;
#endif
	}

	if (f&MODE_LIT_ECHO) {
#ifndef USE_TERMIO
		lmode &= ~LCTLECH;
#else
		tmp_tc.c_lflag &= ~ECHOCTL;
#endif
	} else {
#ifndef USE_TERMIO
		lmode |= LCTLECH;
#else
		tmp_tc.c_lflag |= ECHOCTL;
#endif
	}

	if (f == -1) {
		onoff = 0;
	} else {
#ifndef	USE_TERMIO
		if (f & MODE_OUTBIN)
			lmode |= LLITOUT;
		else
			lmode &= ~LLITOUT;
#else
		if (f & MODE_OUTBIN) {
			tmp_tc.c_cflag &= ~(CSIZE|PARENB);
			tmp_tc.c_cflag |= CS8;
			tmp_tc.c_oflag &= ~OPOST;
		} else {
			tmp_tc.c_cflag &= ~(CSIZE|PARENB);
			tmp_tc.c_cflag |= old_tc.c_cflag & (CSIZE|PARENB);
			tmp_tc.c_oflag |= OPOST;
		}
#endif
		onoff = 1;
	}

	if (f != -1) {

		(void) signal(SIGTSTP, susp);

#if	defined(USE_TERMIO) && defined(NOKERNINFO)
		tmp_tc.c_lflag |= NOKERNINFO;
#endif
		/*
		 * We don't want to process ^Y here.  It's just another
		 * character that we'll pass on to the back end.  It has
		 * to process it because it will be processed when the
		 * user attempts to read it, not when we send it.
		 */
#ifndef	USE_TERMIO
		ltc.t_dsuspc = _POSIX_VDISABLE;
#else
		tmp_tc.c_cc[VDSUSP] = (cc_t)(_POSIX_VDISABLE);
#endif
#ifdef	USE_TERMIO
		/*
		 * If the VEOL character is already set, then use VEOL2,
		 * otherwise use VEOL.
		 */
		esc = (rlogin != _POSIX_VDISABLE) ? rlogin : escape;
		if ((tmp_tc.c_cc[VEOL] != esc)
		    /* XXX */ &&
		    (tmp_tc.c_cc[VEOL2] != esc)
		    /* XXX */) {
			if (tmp_tc.c_cc[VEOL] == (cc_t)(_POSIX_VDISABLE))
				tmp_tc.c_cc[VEOL] = esc;
			else if (tmp_tc.c_cc[VEOL2] == (cc_t)(_POSIX_VDISABLE))
				tmp_tc.c_cc[VEOL2] = esc;
		}
#else
		if (tc.t_brkc == (cc_t)(_POSIX_VDISABLE))
			tc.t_brkc = esc;
#endif
	} else {
		(void) signal(SIGTSTP, SIG_DFL);
		(void) sigemptyset(&nset);
		(void) sigaddset(&nset, SIGTSTP);
		(void) sigprocmask(SIG_UNBLOCK, &nset, 0);
#ifndef USE_TERMIO
		ltc = oltc;
		tc = otc;
		sb = ottyb;
		lmode = olmode;
#else
		tmp_tc = old_tc;
#endif
	}
	if (isatty(tin)) {
#ifndef USE_TERMIO
		(void) ioctl(tin, TIOCLSET, &lmode);
		(void) ioctl(tin, TIOCSLTC, &ltc);
		(void) ioctl(tin, TIOCSETC, &tc);
		(void) ioctl(tin, TIOCSETN, &sb);
#else
		if (tcsetattr(tin, TCSADRAIN, &tmp_tc) < 0)
			(void) tcsetattr(tin, TCSANOW, &tmp_tc);
#endif
		(void) ioctl(tin, FIONBIO, &onoff);
		(void) ioctl(tout, FIONBIO, &onoff);
	}

}

/*
 * This code assumes that the values B0, B50, B75...
 * are in ascending order.  They do not have to be
 * contiguous.
 */
static struct termspeeds {
	int speed;
	int value;
} termspeeds[] = {
	{ 0, B0 },		{ 50, B50 },		{ 75, B75 },
	{ 110, B110 },		{ 134, B134 },		{ 150, B150 },
	{ 200, B200 },		{ 300, B300 },		{ 600, B600 },
	{ 1200, B1200 },	{ 1800, B1800 },	{ 2400, B2400 },
	{ 4800, B4800 },	{ 9600, B9600 },	{ 19200, B19200 },
	{ 38400, B38400 },	{ 57600, B57600 },	{ 76800, B76800 },
	{ 115200, B115200 },	{ 153600, B153600 },	{ 230400, B230400 },
	{ 307200, B307200 },	{ 460800, B460800 },	{ 921600, B921600 },
	{ 1000000, B1000000 },	{ 1152000, B1152000 },	{ 1500000, B1500000 },
	{ 2000000, B2000000 },	{ 2500000, B2500000 },	{ 3000000, B3000000 },
	{ 3500000, B3500000 },	{ 4000000, B4000000 },	{ -1, B0 }
};

void
TerminalSpeeds(ispeed, ospeed)
	int *ispeed;
	int *ospeed;
{
	register struct termspeeds *tp;
	register int in, out;

	out = cfgetospeed(&old_tc);
	in = cfgetispeed(&old_tc);
	if (in == 0)
		in = out;

	tp = termspeeds;
	while ((tp->speed != -1) && (tp->value < in)) {
		tp++;
	}
	if (tp->speed == -1)
		tp--;			/* back up to fastest defined speed */
	*ispeed = tp->speed;

	tp = termspeeds;
	while ((tp->speed != -1) && (tp->value < out)) {
		tp++;
	}
	if (tp->speed == -1)
		tp--;
	*ospeed = tp->speed;
}

int
TerminalWindowSize(rows, cols)
	unsigned short *rows, *cols;
{
	struct winsize ws;

	if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) >= 0) {
		*rows = ws.ws_row;
		*cols = ws.ws_col;
		return (1);
	}
	return (0);
}

static void
NetNonblockingIO(fd, onoff)
	int fd;
	int onoff;
{
	(void) ioctl(fd, FIONBIO, &onoff);
}

/*
 * Various signal handling routines.
 */

/* ARGSUSED */
static SIG_FUNC_RET
deadpeer(sig)
	int sig;
{
	/*
	 * Once is all we should catch SIGPIPE.  If we get it again,
	 * it means we tried to put still more data out to a pipe
	 * which has disappeared.  In that case, telnet will exit.
	 */
	(void) signal(SIGPIPE, SIG_IGN);
	flushout = 1;
	setcommandmode();
	longjmp(peerdied, -1);
}

boolean_t intr_happened	= B_FALSE;
boolean_t intr_waiting	= B_FALSE;

/* ARGSUSED */
static SIG_FUNC_RET
intr(sig)
	int sig;
{
	if (intr_waiting) {
		intr_happened = 1;
		return;
	}
	(void) signal(SIGINT, intr);
	if (localchars) {
		intp();
		return;
	}
	setcommandmode();
	longjmp(toplevel, -1);
}

/* ARGSUSED */
static SIG_FUNC_RET
intr2(sig)
	int sig;
{
	(void) signal(SIGQUIT, intr2);
	if (localchars) {
		/*
		 * Ignore return to the next two function calls
		 * since we're doing SIGQUIT
		 */
#ifdef	KLUDGELINEMODE
		if (kludgelinemode) {
			(void) sendbrk();
		}
		else
#endif
			sendabort();
		return;
	}
}

/* ARGSUSED */
static SIG_FUNC_RET
susp(sig)
	int sig;
{
	(void) signal(SIGTSTP, susp);
	if ((rlogin != _POSIX_VDISABLE) && rlogin_susp())
		return;
	if (localchars)
		sendsusp();
}

/* ARGSUSED */
static SIG_FUNC_RET
sendwin(sig)
	int sig;
{
	(void) signal(SIGWINCH, sendwin);
	if (connected) {
		sendnaws();
	}
}

void
sys_telnet_init()
{
	(void) signal(SIGINT, intr);
	(void) signal(SIGQUIT, intr2);
	(void) signal(SIGPIPE, deadpeer);
	(void) signal(SIGWINCH, sendwin);
	(void) signal(SIGTSTP, susp);

	setconnmode(0);

	NetNonblockingIO(net, 1);

	if (SetSockOpt(net, SOL_SOCKET, SO_OOBINLINE, 1) == -1) {
		perror("SetSockOpt");
	}
}


/*
 * fatal_tty_error -
 *	Handle case where there is an unrecoverable error on the tty
 *      connections.  Print an error, reset the terminal settings
 *	and get out as painlessly as possible.
 */
void
fatal_tty_error(char *doing_what)
{
	TerminalNewMode(-1);
	(void) fprintf(stderr, "Error processing %s:  %s\n", doing_what,
	    strerror(errno));
	exit(1);
}


/*
 * Process rings -
 *
 *	This routine tries to fill up/empty our various rings.
 *
 *	The parameter specifies whether this is a poll operation,
 *	or a block-until-something-happens operation.
 *
 *	The return value is 1 if something happened, 0 if not.
 *	If poll == 0, then block until something to do.
 */
int
process_rings(int netin, int netout, int netex, int ttyin, int ttyout, int poll)
{
	int c;
	/*
	 * One wants to be a bit careful about setting returnValue
	 * to one, since a one implies we did some useful work,
	 * and therefore probably won't be called to block next
	 * time (TN3270 mode only).
	 */
	int returnValue = 0;
	static struct timeval TimeValue = { 0 };
	int i;

	if (netout) {
		FD_SET(net, &obits);
	}
	if (ttyout) {
		FD_SET(tout, &obits);
	}
	if (ttyin) {
		FD_SET(tin, &ibits);
	}
	if (netin) {
		FD_SET(net, &ibits);
	}
	if (netex) {
		FD_SET(net, &xbits);
	}
	if ((c = select(16, &ibits, &obits, &xbits,
			(poll == 0) ? NULL : &TimeValue)) < 0) {
		if (c == -1) {
			/*
			 * we can get EINTR if we are in line mode,
			 * and the user does an escape (TSTP), or
			 * some other signal generator.
			 */
			if (errno == EINTR) {
				return (0);
			}
			/* I don't like this, does it ever happen? */
			(void) printf("sleep(5) from telnet, after select\r\n");
			(void) sleep(5);
		}
		return (0);
	}

	/*
	 * Any urgent data?
	 */
	if (FD_ISSET(net, &xbits)) {
		FD_CLR(net, &xbits);
		SYNCHing = 1;

		/* flush any data that is already enqueued */
		i = ttyflush(1);
		if (i == -2) {
			/* This will not return. */
			fatal_tty_error("write");
		}
	}

	/*
	 * Something to read from the network...
	 */
	if (FD_ISSET(net, &ibits)) {
		int canread;

		FD_CLR(net, &ibits);
		canread = ring_empty_consecutive(&netiring);
		c = recv(net, netiring.supply, canread, 0);
		if (c < 0 && errno == EWOULDBLOCK) {
			c = 0;
		} else if (c <= 0) {
			return (-1);
		}
		if (netdata) {
			Dump('<', netiring.supply, c);
		}
		if (c)
			ring_supplied(&netiring, c);
		returnValue = 1;
	}

	/*
	 * Something to read from the tty...
	 */
	if (FD_ISSET(tin, &ibits)) {
		FD_CLR(tin, &ibits);
		c = TerminalRead((char *)ttyiring.supply,
		    ring_empty_consecutive(&ttyiring));
		if (c < 0) {
			if (errno != EWOULDBLOCK) {
				/* This will not return. */
				fatal_tty_error("read");
			}
			c = 0;
		} else {
			/* EOF detection for line mode!!!! */
			if ((c == 0) && MODE_LOCAL_CHARS(globalmode) &&
			    isatty(tin)) {
				/* must be an EOF... */
				eof_pending = 1;
				return (1);
			}
			if (c <= 0) {
				returnValue = -1;
				goto next;
			}
			if (termdata) {
				Dump('<', ttyiring.supply, c);
			}
			ring_supplied(&ttyiring, c);
		}
		returnValue = 1;		/* did something useful */
	}

next:
	if (FD_ISSET(net, &obits)) {
		FD_CLR(net, &obits);
		returnValue |= netflush();
	}
	if (FD_ISSET(tout, &obits)) {
		FD_CLR(tout, &obits);
		i = ttyflush(SYNCHing|flushout);
		if (i == -2) {
			/* This will not return. */
			fatal_tty_error("write");
		}
		returnValue |= (i > 0);
	}

	return (returnValue);
}
