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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <termio.h>
#include <sys/stermio.h>
#include <sys/termiox.h>
#include "stty.h"

extern char *getenv();
extern void exit();
extern void perror();

static char *STTY = "stty: ";
static char *USAGE = "usage: stty [-agh] [modes]\n";
static int	pitt = 0;
static struct termios cb;
static struct termio ocb; /* for non-streams devices */
static struct stio stio;
static struct termiox termiox;
static struct winsize winsize, owinsize;
static int term;

void prmodes(int);
void pramodes(int);
void prachars(void);
void pcol(int, int);
void pit(unsigned char, char *, char *);
void delay(int, char *s);
void prspeed(char *, int);
void prencode(void);

#define	ioctl_desc	1
#define	output		stderr

int
main(int argc, char *argv[])
{

	int i;
	char	*s_arg, *sttyparse();	/* s_arg: ptr to mode to be set */
	extern const struct	speeds	speeds[];

	if (argc == 2) {
		/*
		 * "stty size", "stty speed" and "stty -g" are intended for
		 * use within backquotes; thus, they do the "fetch" "ioctl"
		 * from "/dev/tty" and always print their result on the
		 * standard output.
		 * Since their standard output is likely to be a pipe, they
		 * should not try to read the modes from the standard output.
		 */
		if (strcmp(argv[1], "size") == 0) {
			if ((i = open("/dev/tty", 0)) < 0) {
				perror("stty: Cannot open /dev/tty");
				exit(2);
			}
			if (ioctl(i, TIOCGWINSZ, &winsize) < 0) {
				perror("stty: TIOCGWINSZ");
				exit(2);
			}
			(void) printf("%d %d\n",
			    winsize.ws_row, winsize.ws_col);
			exit(0);
		} else if (strcmp(argv[1], "speed") == 0) {
			if ((i = open("/dev/tty", 0)) < 0) {
				perror("stty: Cannot open /dev/tty");
				exit(2);
			}
			if ((term = get_ttymode(i,
			    &ocb, &cb, &stio, &termiox, &winsize)) < 0) {
				perror(STTY);
				exit(2);
			}
			if (term & TERMIOS) {
				for (i = 0; speeds[i].string; i++)
					if (cfgetospeed(&cb) ==
					    speeds[i].speed) {
						(void) printf("%s\n",
						    speeds[i].string);
						exit(0);
					}
			} else {
				for (i = 0; speeds[i].string; i++)
					if ((cb.c_cflag&CBAUD) ==
					    speeds[i].speed) {
						(void) printf("%s\n",
						    speeds[i].string);
						exit(0);
					}
			}
			(void) printf("unknown\n");
			exit(1);
		} else if (strcmp(argv[1], "-g") == 0) {
			if ((i = open("/dev/tty", 0)) < 0) {
				perror("stty: Cannot open /dev/tty");
				exit(2);
			}
			if ((term = get_ttymode(i,
			    &ocb, &cb, &stio, &termiox, &winsize)) < 0) {
				perror(STTY);
				exit(2);
			}
			prencode();
			exit(0);
		}
	}

	if ((term = get_ttymode(ioctl_desc,
	    &ocb, &cb, &stio, &termiox, &winsize)) < 0) {
		perror(STTY);
		exit(2);
	}
	owinsize = winsize;
	if (argc == 1) {
		prmodes(0);
		exit(0);
	}
	if ((argc == 2) && strcmp(argv[1], "all") == 0) {
		prmodes(1);
		exit(0);
	}
	if ((argc == 2) && strcmp(argv[1], "everything") == 0) {
		pramodes(1);
		exit(0);
	}
	if ((argc == 2) && (argv[1][0] == '-') && (argv[1][2] == '\0'))
		switch (argv[1][1]) {
		case 'a':
			pramodes(0);
			exit(0);
		case 'h':
			pramodes(1);
			exit(0);
		default:
			(void) fprintf(stderr, "%s", USAGE);
			exit(2);
		}
	if (s_arg = sttyparse(argc, argv,
	    term, &ocb, &cb, &termiox, &winsize)) {
		(void) fprintf(stderr, "unknown mode: %s\n", s_arg);
		exit(2);
	}

	if (set_ttymode(ioctl_desc,
	    term, &ocb, &cb, &stio, &termiox, &winsize, &owinsize) == -1) {
		perror(STTY);
		exit(2);
	}
	return (0);	/*NOTREACHED*/
}

void
prmodes(int moremodes)
/* print modes, no options, argc is 1 */
{
	int m;

	if (!(term & ASYNC)) {
		m = stio.imode;
		if (m & IUCLC)
			(void) fprintf(output, "iuclc ");
		else
			(void) fprintf(output, "-iuclc ");
		m = stio.omode;
		if (m & OLCUC)
			(void) fprintf(output, "olcuc ");
		else
			(void) fprintf(output, "-olcuc ");
		if (m & TAB3)
			(void) fprintf(output, "tab3 ");
		m = stio.lmode;
		if (m & XCASE)
			(void) fprintf(output, "xcase ");
		else
			(void) fprintf(output, "-xcase ");
		if (m & STFLUSH)
			(void) fprintf(output, "stflush ");
		else
			(void) fprintf(output, "-stflush ");
		if (m & STWRAP)
			(void) fprintf(output, "stwrap ");
		else
			(void) fprintf(output, "-stwrap ");
		if (m & STAPPL)
			(void) fprintf(output, "stappl ");
		else
			(void) fprintf(output, "-stappl ");
		(void) fprintf(output, "\n");
	}
	if (term & ASYNC) {
		m = cb.c_cflag;
		if ((term & TERMIOS) && cfgetispeed(&cb) != 0 &&
		    cfgetispeed(&cb) != cfgetospeed(&cb)) {
			prspeed("ispeed ", cfgetispeed(&cb));
			prspeed("ospeed ", cfgetospeed(&cb));
		} else
			prspeed("speed ", cfgetospeed(&cb));
		if (m & PARENB) {
			if ((m & PAREXT) && (term & TERMIOS)) {
				if (m & PARODD)
					(void) fprintf(output, "markp ");
				else
					(void) fprintf(output, "spacep ");
			} else {
				if (m & PARODD)
					(void) fprintf(output, "oddp ");
				else
					(void) fprintf(output, "evenp ");
			}
		} else
			(void) fprintf(output, "-parity ");
		if (((m & PARENB) && !(m & CS7)) ||
		    (!(m & PARENB) && !(m & CS8)))
			(void) fprintf(output, "cs%c ", '5' + (m & CSIZE)/CS6);
		if (m & CSTOPB)
			(void) fprintf(output, "cstopb ");
		if (m & HUPCL)
			(void) fprintf(output, "hupcl ");
		if (!(m & CREAD))
			(void) fprintf(output, "-cread ");
		if (m & CLOCAL)
			(void) fprintf(output, "clocal ");
		if (m & LOBLK)
			(void) fprintf(output, "loblk ");
		(void) fprintf(output, "\n");
		if (ocb.c_line != 0)
			(void) fprintf(output, "line = %d; ", ocb.c_line);
		if (term & WINDOW) {
			(void) fprintf(output, "rows = %d; columns = %d;",
			    winsize.ws_row, winsize.ws_col);
			(void) fprintf(output, " ypixels = %d; xpixels = %d;\n",
			    winsize.ws_ypixel, winsize.ws_xpixel);
		}
		if ((cb.c_lflag & ICANON) == 0)
			(void) fprintf(output, "min = %d; time = %d;\n",
			    cb.c_cc[VMIN], cb.c_cc[VTIME]);
		if (!moremodes) {
			if (cb.c_cc[VINTR] != CINTR)
				pit(cb.c_cc[VINTR], "intr", "; ");
			if (cb.c_cc[VQUIT] != CQUIT)
				pit(cb.c_cc[VQUIT], "quit", "; ");
			if (cb.c_cc[VERASE] != CERASE)
				pit(cb.c_cc[VERASE], "erase", "; ");
			if (cb.c_cc[VKILL] != CKILL)
				pit(cb.c_cc[VKILL], "kill", "; ");
			if (cb.c_cc[VEOF] != CEOF)
				pit(cb.c_cc[VEOF], "eof", "; ");
			if (cb.c_cc[VEOL] != CNUL)
				pit(cb.c_cc[VEOL], "eol", "; ");
			if (cb.c_cc[VEOL2] != CNUL)
				pit(cb.c_cc[VEOL2], "eol2", "; ");
			if (cb.c_cc[VSWTCH] != CSWTCH)
				pit(cb.c_cc[VSWTCH], "swtch", "; ");
			if (term & TERMIOS) {
				if (cb.c_cc[VSTART] != CSTART)
					pit(cb.c_cc[VSTART], "start", "; ");
				if (cb.c_cc[VSTOP] != CSTOP)
					pit(cb.c_cc[VSTOP], "stop", "; ");
				if (cb.c_cc[VSUSP] != CSUSP)
					pit(cb.c_cc[VSUSP], "susp", "; ");
				if (cb.c_cc[VDSUSP] != CDSUSP)
					pit(cb.c_cc[VDSUSP], "dsusp", "; ");
				if (cb.c_cc[VREPRINT] != CRPRNT)
					pit(cb.c_cc[VREPRINT], "rprnt", "; ");
				if (cb.c_cc[VDISCARD] != CFLUSH)
					pit(cb.c_cc[VDISCARD], "flush", "; ");
				if (cb.c_cc[VWERASE] != CWERASE)
					pit(cb.c_cc[VWERASE], "werase", "; ");
				if (cb.c_cc[VLNEXT] != CLNEXT)
					pit(cb.c_cc[VLNEXT], "lnext", "; ");
			}
		}
		if (pitt)
			(void) fprintf(output, "\n");
		m = cb.c_iflag;
		if (m & IGNBRK)
			(void) fprintf(output, "ignbrk ");
		else if (!(m & BRKINT))
			(void) fprintf(output, "-brkint ");
		if (!(m & INPCK))
			(void) fprintf(output, "-inpck ");
		else if (!(m & IGNPAR))
			(void) fprintf(output, "-ignpar ");
		if (m & PARMRK)
			(void) fprintf(output, "parmrk ");
		if (!(m & ISTRIP))
			(void) fprintf(output, "-istrip ");
		if (m & INLCR)
			(void) fprintf(output, "inlcr ");
		if (m & IGNCR)
			(void) fprintf(output, "igncr ");
		if (!(m & ICRNL))
			(void) fprintf(output, "-icrnl ");
		if (m & IUCLC)
			(void) fprintf(output, "iuclc ");
		if (!(m & IXON))
			(void) fprintf(output, "-ixon ");
		else if (m & IXANY)
			(void) fprintf(output, "ixany ");
		if (m & IXOFF)
			(void) fprintf(output, "ixoff ");
		if ((term & TERMIOS) && (m & IMAXBEL))
			(void) fprintf(output, "imaxbel ");
		m = cb.c_oflag;
		if (!(m & OPOST))
			(void) fprintf(output, "-opost ");
		else {
			if (m & OLCUC)
				(void) fprintf(output, "olcuc ");
			if (!(m & ONLCR))
				(void) fprintf(output, "-onlcr ");
			if (m & OCRNL)
				(void) fprintf(output, "ocrnl ");
			if (m & ONOCR)
				(void) fprintf(output, "onocr ");
			if (m & ONLRET)
				(void) fprintf(output, "onlret ");
			if (m & OFILL)
				if (m & OFDEL)
					(void) fprintf(output, "del-fill ");
				else
					(void) fprintf(output, "nul-fill ");
			delay((m & CRDLY)/CR1, "cr");
			delay((m & NLDLY)/NL1, "nl");
			if ((m & TABDLY) == XTABS)
				(void) fprintf(output, "-tabs ");
			else
				delay((m & TABDLY)/TAB1, "tab");
			delay((m & BSDLY)/BS1, "bs");
			delay((m & VTDLY)/VT1, "vt");
			delay((m & FFDLY)/FF1, "ff");
		}
		(void) fprintf(output, "\n");
		m = cb.c_lflag;
		if (!(m & ISIG))
			(void) fprintf(output, "-isig ");
		if (!(m & ICANON))
			(void) fprintf(output, "-icanon ");
		if (m & XCASE)
			(void) fprintf(output, "xcase ");
		if (!(m & ECHO))
			(void) fprintf(output, "-echo ");
		if (m & ECHOE) {
			if (m & ECHOKE)
				(void) fprintf(output, "crt ");
			else
				(void) fprintf(output, "echoe -echoke ");
		} else {
			if (!(m & ECHOPRT))
				(void) fprintf(output, "-echoprt ");
		}
		if (!(m & ECHOK))
			(void) fprintf(output, "-echok ");
		if (m & ECHONL)
			(void) fprintf(output, "echonl ");
		if (m & NOFLSH)
			(void) fprintf(output, "noflsh ");
		if (m & TOSTOP)
			(void) fprintf(output, "tostop ");
		if (!(m & ECHOCTL))
			(void) fprintf(output, "-echoctl ");
		if (m & DEFECHO)
			(void) fprintf(output, "defecho ");
		if (m & FLUSHO)
			(void) fprintf(output, "flusho ");
		if (m & PENDIN)
			(void) fprintf(output, "pendin ");
		if (m & IEXTEN)
			(void) fprintf(output, "iexten ");
		(void) fprintf(output, "\n");
	}
	if (term & FLOW) {
		m = termiox.x_hflag;
		if (m & RTSXOFF)
			(void) fprintf(output, "rtsxoff ");
		if (m & CTSXON)
			(void) fprintf(output, "ctsxon ");
		if (m & DTRXOFF)
			(void) fprintf(output, "dterxoff ");
		if (m & CDXON)
			(void) fprintf(output, "rlsdxon ");
		if (m & ISXOFF)
			(void) fprintf(output, "isxoff ");
		m = termiox.x_cflag;
		switch (m & XMTCLK) {
		case XCIBRG:
			(void) fprintf(output, "xcibrg ");
			break;
		case XCTSET:
			(void) fprintf(output, "xctset ");
			break;
		case XCRSET:
			(void) fprintf(output, "xcrset ");
			break;
		}

		switch (m & RCVCLK) {
		case RCIBRG:
			(void) fprintf(output, "rcibrg ");
			break;
		case RCTSET:
			(void) fprintf(output, "rctset ");
			break;
		case RCRSET:
			(void) fprintf(output, "rcrset ");
			break;
		}

		switch (m & TSETCLK) {
		case TSETCOFF:
			(void) fprintf(output, "tsetcoff ");
			break;
		case TSETCRBRG:
			(void) fprintf(output, "tsetcrc ");
			break;
		case TSETCTBRG:
			(void) fprintf(output, "tsetcxc ");
			break;
		}

		switch (m & RSETCLK) {
		case RSETCOFF:
			(void) fprintf(output, "rsetcoff ");
			break;
		case RSETCRBRG:
			(void) fprintf(output, "rsetcrc ");
			break;
		case RSETCTBRG:
			(void) fprintf(output, "rsetcxc ");
		}
		(void) fprintf(output, "\n");
	}
	if (moremodes)
		prachars();
}

void
pramodes(int tabform)
/* print all modes, -a option */
{
	int m;

	m = cb.c_cflag;
	if (term & ASYNC) {
		if ((term & TERMIOS) && cfgetispeed(&cb) != 0 &&
		    cfgetispeed(&cb) != cfgetospeed(&cb)) {
			prspeed("ispeed ", cfgetispeed(&cb));
			prspeed("ospeed ", cfgetospeed(&cb));
		} else
			prspeed("speed ", cfgetospeed(&cb));
		if (!(term & TERMIOS))
			(void) fprintf(output, "line = %d; ", ocb.c_line);
		(void) fprintf(output, "\n");
		if (term & WINDOW) {
			(void) fprintf(output, "rows = %d columns = %d; ",
			    winsize.ws_row, winsize.ws_col);
			(void) fprintf(output, "ypixels = %d xpixels = %d\n",
			    winsize.ws_ypixel, winsize.ws_xpixel);
		}
		if ((cb.c_lflag & ICANON) == 0)
			(void) fprintf(output, "min = %d; time = %d;\n",
			    cb.c_cc[VMIN], cb.c_cc[VTIME]);
		if (!tabform) {
			pit(cb.c_cc[VINTR], "intr", "; ");
			pit(cb.c_cc[VQUIT], "quit", "; ");
			pit(cb.c_cc[VERASE], "erase", "; ");
			pit(cb.c_cc[VKILL], "kill", ";\n");
			pit(cb.c_cc[VEOF], "eof", "; ");
			pit(cb.c_cc[VEOL], "eol", "; ");
			pit(cb.c_cc[VEOL2], "eol2", "; ");
			pit(cb.c_cc[VSWTCH], "swtch", ";\n");
			if (term & TERMIOS) {
				pit(cb.c_cc[VSTART], "start", "; ");
				pit(cb.c_cc[VSTOP], "stop", "; ");
				pit(cb.c_cc[VSUSP], "susp", "; ");
				pit(cb.c_cc[VDSUSP], "dsusp", ";\n");
				pit(cb.c_cc[VREPRINT], "rprnt", "; ");
				pit(cb.c_cc[VDISCARD], "flush", "; ");
				pit(cb.c_cc[VWERASE], "werase", "; ");
				pit(cb.c_cc[VLNEXT], "lnext", ";\n");
			}
		}
	} else
		pit((unsigned)stio.tab, "ctab", "\n");
	m = cb.c_cflag;
	(void) fprintf(output, "-parenb " + ((m & PARENB) != 0));
	(void) fprintf(output, "-parodd " + ((m & PARODD) != 0));
	(void) fprintf(output, "cs%c ", '5'+ (m & CSIZE)/CS6);
	(void) fprintf(output, "-cstopb " + ((m & CSTOPB) != 0));
	(void) fprintf(output, "-hupcl " + ((m & HUPCL) != 0));
	(void) fprintf(output, "-cread " + ((m & CREAD) != 0));
	(void) fprintf(output, "-clocal " + ((m & CLOCAL) != 0));

	(void) fprintf(output, "-loblk " + ((m & LOBLK) != 0));
	if (term & TERMIOS)
		(void) fprintf(output, "-parext " + ((m & PAREXT) != 0));

	(void) fprintf(output, "\n");
	m = cb.c_iflag;
	(void) fprintf(output, "-ignbrk " + ((m & IGNBRK) != 0));
	(void) fprintf(output, "-brkint " + ((m & BRKINT) != 0));
	(void) fprintf(output, "-ignpar " + ((m & IGNPAR) != 0));
	(void) fprintf(output, "-parmrk " + ((m & PARMRK) != 0));
	(void) fprintf(output, "-inpck " + ((m & INPCK) != 0));
	(void) fprintf(output, "-istrip " + ((m & ISTRIP) != 0));
	(void) fprintf(output, "-inlcr " + ((m & INLCR) != 0));
	(void) fprintf(output, "-igncr " + ((m & IGNCR) != 0));
	(void) fprintf(output, "-icrnl " + ((m & ICRNL) != 0));
	(void) fprintf(output, "-iuclc " + ((m & IUCLC) != 0));
	(void) fprintf(output, "\n");
	(void) fprintf(output, "-ixon " + ((m & IXON) != 0));
	(void) fprintf(output, "-ixany " + ((m & IXANY) != 0));
	(void) fprintf(output, "-ixoff " + ((m & IXOFF) != 0));
	if (term & TERMIOS)
		(void) fprintf(output, "-imaxbel " + ((m & IMAXBEL) != 0));
	(void) fprintf(output, "\n");
	m = cb.c_lflag;
	(void) fprintf(output, "-isig " + ((m & ISIG) != 0));
	(void) fprintf(output, "-icanon " + ((m & ICANON) != 0));
	(void) fprintf(output, "-xcase " + ((m & XCASE) != 0));
	(void) fprintf(output, "-echo " + ((m & ECHO) != 0));
	(void) fprintf(output, "-echoe " + ((m & ECHOE) != 0));
	(void) fprintf(output, "-echok " + ((m & ECHOK) != 0));
	(void) fprintf(output, "-echonl " + ((m & ECHONL) != 0));
	(void) fprintf(output, "-noflsh " + ((m & NOFLSH) != 0));
	if (term & TERMIOS) {
		(void) fprintf(output, "\n");
		(void) fprintf(output, "-tostop " + ((m & TOSTOP) != 0));
		(void) fprintf(output, "-echoctl " + ((m & ECHOCTL) != 0));
		(void) fprintf(output, "-echoprt " + ((m & ECHOPRT) != 0));
		(void) fprintf(output, "-echoke " + ((m & ECHOKE) != 0));
		(void) fprintf(output, "-defecho " + ((m & DEFECHO) != 0));
		(void) fprintf(output, "-flusho " + ((m & FLUSHO) != 0));
		(void) fprintf(output, "-pendin " + ((m & PENDIN) != 0));
		(void) fprintf(output, "-iexten " + ((m & IEXTEN) != 0));
	}
	if (!(term & ASYNC)) {
		(void) fprintf(output, "-stflush " + ((m & STFLUSH) != 0));
		(void) fprintf(output, "-stwrap " + ((m & STWRAP) != 0));
		(void) fprintf(output, "-stappl " + ((m & STAPPL) != 0));
	}
	(void) fprintf(output, "\n");
	m = cb.c_oflag;
	(void) fprintf(output, "-opost " + ((m & OPOST) != 0));
	(void) fprintf(output, "-olcuc " + ((m & OLCUC) != 0));
	(void) fprintf(output, "-onlcr " + ((m & ONLCR) != 0));
	(void) fprintf(output, "-ocrnl " + ((m & OCRNL) != 0));
	(void) fprintf(output, "-onocr " + ((m & ONOCR) != 0));
	(void) fprintf(output, "-onlret " + ((m & ONLRET) != 0));
	(void) fprintf(output, "-ofill " + ((m & OFILL) != 0));
	(void) fprintf(output, "-ofdel " + ((m & OFDEL) != 0));
	delay((m & CRDLY)/CR1, "cr");
	delay((m & NLDLY)/NL1, "nl");
	if ((m & TABDLY) == XTABS)
		(void) fprintf(output, "-tabs ");
	else
		delay((m & TABDLY)/TAB1, "tab");
	delay((m & BSDLY)/BS1, "bs");
	delay((m & VTDLY)/VT1, "vt");
	delay((m & FFDLY)/FF1, "ff");
	(void) fprintf(output, "\n");
	if (term & FLOW) {
		m = termiox.x_hflag;
		(void) fprintf(output, "-rtsxoff " + ((m & RTSXOFF) != 0));
		(void) fprintf(output, "-ctsxon " + ((m & CTSXON) != 0));
		(void) fprintf(output, "-dterxoff " + ((m & DTRXOFF) != 0));
		(void) fprintf(output, "-rlsdxon " + ((m & CDXON) != 0));
		(void) fprintf(output, "-isxoff " + ((m & ISXOFF) != 0));
		m = termiox.x_cflag;
		switch (m & XMTCLK) {
		case XCIBRG:
			(void) fprintf(output, "xcibrg ");
			break;
		case XCTSET:
			(void) fprintf(output, "xctset ");
			break;
		case XCRSET:
			(void) fprintf(output, "xcrset ");
			break;
		}

		switch (m & RCVCLK) {
		case RCIBRG:
			(void) fprintf(output, "rcibrg ");
			break;
		case RCTSET:
			(void) fprintf(output, "rctset ");
			break;
		case RCRSET:
			(void) fprintf(output, "rcrset ");
			break;
		}

		switch (m & TSETCLK) {
		case TSETCOFF:
			(void) fprintf(output, "tsetcoff ");
			break;
		case TSETCRBRG:
			(void) fprintf(output, "tsetcrc ");
			break;
		case TSETCTBRG:
			(void) fprintf(output, "tsetcxc ");
			break;
		}

		switch (m & RSETCLK) {
		case RSETCOFF:
			(void) fprintf(output, "rsetcoff ");
			break;
		case RSETCRBRG:
			(void) fprintf(output, "rsetcrc ");
			break;
		case RSETCTBRG:
			(void) fprintf(output, "rsetcxc ");
			break;
		}
		(void) fprintf(output, "\n");
	}
	if (tabform)
		prachars();
}

void
prachars(void)
{
	if ((cb.c_lflag & ICANON) == 0)
		(void) fprintf(output, "min %d, time %d\n", cb.c_cc[VMIN],
		    cb.c_cc[VTIME]);
	(void) fprintf(output, "\
erase  kill   werase rprnt  flush  lnext  susp   intr   quit   stop   eof\
\n");
	pcol(cb.c_cc[VERASE], 0);
	pcol(cb.c_cc[VKILL], 0);
	pcol(cb.c_cc[VWERASE], 0);
	pcol(cb.c_cc[VREPRINT], 0);
	pcol(cb.c_cc[VDISCARD], 0);
	pcol(cb.c_cc[VLNEXT], 0);
	pcol(cb.c_cc[VSUSP], cb.c_cc[VDSUSP]);
	pcol(cb.c_cc[VINTR], 0);
	pcol(cb.c_cc[VQUIT], 0);
	pcol(cb.c_cc[VSTOP], cb.c_cc[VSTART]);
	if (cb.c_lflag&ICANON)
		pcol(cb.c_cc[VEOF], cb.c_cc[VEOL]);
	(void) fprintf(output, "\n");
	if (cb.c_cc[VEOL2] != 0 || cb.c_cc[VSWTCH] != 0) {
		(void) fprintf(output, "\
eol2  swtch\
\n");
		pcol(cb.c_cc[VEOL2], 0);
		pcol(cb.c_cc[VSWTCH], 0);
		(void) fprintf(output, "\n");
	}
}

void
pcol(int ch1, int ch2)
{
	int nout = 0;

	ch1 &= 0377;
	ch2 &= 0377;
	if (ch1 == ch2)
		ch2 = 0;
	for (; ch1 != 0 || ch2 != 0; ch1 = ch2, ch2 = 0) {
		if (ch1 == 0)
			continue;
		if (ch1 & 0200 && !isprint(ch1)) {
			(void) fprintf(output, "M-");
			nout += 2;
			ch1 &= ~ 0200;
		}
		if (ch1 == 0177) {
			(void) fprintf(output, "^");
			nout++;
			ch1 = '?';
		} else if (ch1 < ' ') {
			(void) fprintf(output, "^");
			nout++;
			ch1 += '@';
		}
		(void) fprintf(output, "%c", ch1);
		nout++;
		if (ch2 != 0) {
			(void) fprintf(output, "/");
			nout++;
		}
	}
	while (nout < 7) {
		(void) fprintf(output, " ");
		nout++;
	}
}

void
pit(unsigned char what, char *itsname, char *sep)
/* print function for prmodes() and pramodes() */
{

	pitt++;
	(void) fprintf(output, "%s", itsname);
	if ((term & TERMIOS) && what == _POSIX_VDISABLE ||
	    !(term & TERMIOS) && what == 0200) {
		(void) fprintf(output, " = <undef>%s", sep);
		return;
	}
	(void) fprintf(output, " = ");
	if (what & 0200 && !isprint(what)) {
		(void) fprintf(output, "-");
		what &= ~ 0200;
	}
	if (what == 0177) {
		(void) fprintf(output, "^?%s", sep);
		return;
	} else if (what < ' ') {
		(void) fprintf(output, "^");
		what += '`';
	}
	(void) fprintf(output, "%c%s", what, sep);
}

void
delay(int m, char *s)
{
	if (m)
		(void) fprintf(output, "%s%d ", s, m);
}

long	speed[] = {
	0, 50, 75, 110, 134, 150, 200, 300,
	600, 1200, 1800, 2400, 4800, 9600, 19200, 38400,
	57600, 76800, 115200, 153600, 230400, 307200, 460800, 921600
};

void
prspeed(char *c, int s)
{
	(void) fprintf(output, "%s%d baud; ", c, speed[s]);
}

/*
 * print current settings for use with
 * another stty cmd, used for -g option
 */
void
prencode(void)
{
	int i, last;

	/* Since the -g option is mostly used for redirecting to a file */
	/* We must print to stdout here, not stderr */

	(void) printf("%x:%x:%x:%x:", cb.c_iflag, cb.c_oflag,
	    cb.c_cflag, cb.c_lflag);

	if (term & TERMIOS)
	/* last control slot is unused */
		last = NCCS - 2;
	else
		last = NCC - 1;
	for (i = 0; i < last; i++)
		(void) printf("%x:", cb.c_cc[i]);
	(void) printf("%x\n", cb.c_cc[last]);
}
