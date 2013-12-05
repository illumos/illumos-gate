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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <locale.h>
#include <sys/types.h>
#include <termio.h>
#include <sys/stermio.h>
#include <sys/termiox.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#ifdef EUC
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/eucioctl.h>
#include <sys/csiioctl.h>
#include <sys/stream.h>
#include <sys/termios.h>
#include <sys/ldterm.h>
#include <getwidth.h>
#endif /* EUC */
#include "stty.h"

extern const char *not_supported[];

extern char *getenv();
extern void exit();
extern void perror();
extern int get_ttymode();
extern int set_ttymode();

static char *STTY = "stty: ";
static int pitt = 0;
static struct termios cb;
static struct termio ocb; /* for non-streams devices */
static struct stio stio;
static struct termiox termiox;
static struct winsize winsize, owinsize;
static int term;
#ifdef EUC
static struct eucioc kwp;
static eucwidth_t wp;
static ldterm_cs_data_user_t cswp;	/* User side codeset width data */
static ldterm_cs_data_user_t kcswp;	/* Kernel side codeset width data */
static int invalid_ldterm_dat_file;
#endif /* EUC */

static void prmodes();
static void pramodes();
static void pit(unsigned char what, char *itsname, char *sep);
static void delay(int m, char *s);
static void prspeed(char *c, int s);
static void prencode();

int
main(int argc, char *argv[])
{
	int i;
	int fd;
	char *s_arg, *sttyparse();	/* s_arg: ptr to mode to be set */
#ifdef	EUC
	char *lc;
	char tmps[PATH_MAX];
#endif	/* EUC */

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

#ifdef EUC
	lc = setlocale(LC_CTYPE, (const char *)NULL);
	if (lc) {
		sprintf(tmps, _LDTERM_DAT_PATH, lc);

		fd = open(tmps, O_RDONLY, 0);
		if (fd != -1) {
			if (read(fd, (void *)&cswp, sizeof (cswp)) <
			    sizeof (cswp)) {
				(void) fprintf(stderr, gettext(
				    "cannot read entire %s file\n"), tmps);
				exit(2);
			}

			(void) close(fd);

			/*
			 * If the ldterm.dat contains invalid data or
			 * the current locale name is too long, we clear
			 * the 'cswp' and flag the invalid ldterm.dat since
			 * we are not going to use the data.
			 */
			if (cswp.version > LDTERM_DATA_VERSION ||
			    cswp.codeset_type < LDTERM_CS_TYPE_MIN ||
			    cswp.codeset_type > LDTERM_CS_TYPE_MAX ||
			    strlen(lc) >= MAXNAMELEN ||
			    (cswp.codeset_type == LDTERM_CS_TYPE_EUC &&
			    cswp.csinfo_num > LDTERM_CS_TYPE_EUC_MAX_SUBCS) ||
			    (cswp.codeset_type == LDTERM_CS_TYPE_PCCS &&
			    (cswp.csinfo_num < LDTERM_CS_TYPE_PCCS_MIN_SUBCS ||
			    cswp.csinfo_num > LDTERM_CS_TYPE_PCCS_MAX_SUBCS))) {
				(void) memset((void *)&cswp, 0, sizeof (cswp));
				invalid_ldterm_dat_file = 1;
			} else {
				(void) strcpy(cswp.locale_name, lc);
			}
		}
	}

	getwidth(&wp);
#endif /* EUC */

	if ((term = get_ttymode(0, &ocb, &cb, &stio, &termiox, &winsize
#ifdef EUC
	    /* */, &kwp, &kcswp
#endif /* EUC */
	    /* */)) < 0) {
		perror(STTY);
		exit(2);
	}
	owinsize = winsize;
	if (argc == 1) {
		prmodes();
		exit(0);
	}
	if ((argc == 2) && (argv[1][0] == '-') && (argv[1][2] == '\0'))
	switch (argv[1][1]) {
		case 'a':
			pramodes();
			return (0);
		case 'g':
			prencode();
			return (0);
		case '-':
			prmodes(); /* stty -- */
			return (0);
		default:
			(void) fprintf(stderr, gettext(
			    "usage: stty [-a| -g]\n"));
			(void) fprintf(stderr, gettext(
			    "       stty [modes]\n"));
			return (2);
	}

	if ((argc == 3) && (argv[1][0] == '-') && (argv[1][2] == '\0') &&
	    (argv[2][0] == '-') && (argv[2][1] == '-') && (argv[2][2] == '\0'))
	switch (argv[1][1]) {
	case 'a':
		pramodes();
		return (0);
	case 'g':
		prencode();
		return (0);
	default:
		(void) fprintf(stderr, gettext(
		    "usage: stty [-a| -g]\n"));
		(void) fprintf(stderr, gettext(
		    "       stty [modes]\n"));
		return (2);
	}
	if ((argc >= 3) && (argv[1][0] == '-') && (argv[1][1] == '-') &&
	    (argv[1][2] == '\0')) {
		/* ignore -- */
		--argc;
		++argv;
	}
	if (s_arg = sttyparse(argc, argv, term, &ocb, &cb, &termiox, &winsize
#ifdef EUC
	    /* */, &wp, &kwp, &cswp, &kcswp
#endif /* EUC */
	    /* */)) {
		char *s = s_arg;
		if (*s == '-') s++;
		for (i = 0; not_supported[i]; i++) {
			if (strcmp(not_supported[i], s) == 0) {
				(void) fprintf(stderr,
				    gettext(
				    "mode not supported on this device: %s\n"),
				    s_arg);
				exit(2);
			}
		}
		(void) fprintf(stderr, gettext("unknown mode: %s\n"), s_arg);
		return (2);
	}

	if (set_ttymode(0, term, &ocb, &cb, &stio, &termiox, &winsize, &owinsize
#ifdef EUC
	    /* */, &kwp, &kcswp, invalid_ldterm_dat_file
#endif /* EUC */
	    /* */) == -1) {
		perror(STTY);
		return (2);
	}
	return (0);
}

void
prmodes(void)				/* print modes, no options, argc is 1 */
{
	int m;

	if (!(term & ASYNC)) {
		m = stio.imode;
		if (m & IUCLC)
			(void) printf("iuclc ");
		else
			(void) printf("-iuclc ");
		m = stio.omode;
		if (m & OLCUC)
			(void) printf("olcuc ");
		else
			(void) printf("-olcuc ");
		if (m & TAB3)
			(void) printf("tab3 ");
		m = stio.lmode;
		if (m & XCASE)
			(void) printf("xcase ");
		else
			(void) printf("-xcase ");
		if (m & STFLUSH)
			(void) printf("stflush ");
		else
			(void) printf("-stflush ");
		if (m & STWRAP)
			(void) printf("stwrap ");
		else
			(void) printf("-stwrap ");
		if (m & STAPPL)
			(void) printf("stappl ");
		else
			(void) printf("-stappl ");
		(void) printf("\n");
	}
	if (term & ASYNC) {
		m = cb.c_cflag;
		if ((term & TERMIOS) && cfgetispeed(&cb) != 0 &&
		    cfgetispeed(&cb) != cfgetospeed(&cb)) {
			prspeed("ispeed ", cfgetispeed(&cb));
			prspeed("ospeed ", cfgetospeed(&cb));
		} else
			prspeed("speed ", cfgetospeed(&cb));
		if (m&PARENB) {
			if ((m&PAREXT) && (term & TERMIOS)) {
				if (m&PARODD)
					(void) printf("markp ");
				else
					(void) printf("spacep ");
			} else {
				if (m&PARODD)
					(void) printf("oddp ");
				else
					(void) printf("evenp ");
			}
		} else
			(void) printf("-parity ");
		if (((m&PARENB) && !(m&CS7)) || (!(m&PARENB) && !(m&CS8)))
			(void) printf("cs%c ", '5'+(m&CSIZE)/CS6);
		if (m&CSTOPB)
			(void) printf("cstopb ");
		if (m&HUPCL)
			(void) printf("hupcl ");
		if (!(m&CREAD))
			(void) printf("-cread ");
		if (m&CLOCAL)
			(void) printf("clocal ");
		if (m&LOBLK)
			(void) printf("loblk ");
		(void) printf("\n");
		if (ocb.c_line != 0)
			(void) printf(gettext("line = %d; "), ocb.c_line);
		if (term & WINDOW) {
			(void) printf(gettext("rows = %d; columns = %d;"),
			    winsize.ws_row, winsize.ws_col);
			(void) printf(gettext(
			    " ypixels = %d; xpixels = %d;\n"),
			    winsize.ws_ypixel, winsize.ws_xpixel);
		}
		if ((cb.c_lflag&ICANON) == 0)
			(void) printf(gettext("min = %d; time = %d;\n"),
			    cb.c_cc[VMIN], cb.c_cc[VTIME]);
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
			if (cb.c_cc[VSTATUS] != CSTATUS)
				pit(cb.c_cc[VSTATUS], "status", "; ");
		}
		if (pitt) (void) printf("\n");
		m = cb.c_iflag;
		if (m&IGNBRK)
			(void) printf("ignbrk ");
		else if (m&BRKINT)
			(void) printf("brkint ");
		if (!(m&INPCK))
			(void) printf("-inpck ");
		else if (m&IGNPAR)
			(void) printf("ignpar ");
		if (m&PARMRK)
			(void) printf("parmrk ");
		if (!(m&ISTRIP))
			(void) printf("-istrip ");
		if (m&INLCR)
			(void) printf("inlcr ");
		if (m&IGNCR)
			(void) printf("igncr ");
		if (m&ICRNL)
			(void) printf("icrnl ");
		if (m&IUCLC)
			(void) printf("iuclc ");
		if (!(m&IXON))
			(void) printf("-ixon ");
		else if (!(m&IXANY))
			(void) printf("-ixany ");
		if (m&IXOFF)
			(void) printf("ixoff ");
		if ((term & TERMIOS) && (m&IMAXBEL))
			(void) printf("imaxbel ");
		m = cb.c_oflag;
		if (!(m&OPOST))
			(void) printf("-opost ");
		else {
			if (m&OLCUC)
				(void) printf("olcuc ");
			if (m&ONLCR)
				(void) printf("onlcr ");
			if (m&OCRNL)
				(void) printf("ocrnl ");
			if (m&ONOCR)
				(void) printf("onocr ");
			if (m&ONLRET)
				(void) printf("onlret ");
			if (m&OFILL)
				if (m&OFDEL)
					(void) printf("del-fill ");
				else
					(void) printf("nul-fill ");
			delay((m&CRDLY)/CR1, "cr");
			delay((m&NLDLY)/NL1, "nl");
			delay((m&TABDLY)/TAB1, "tab");
			delay((m&BSDLY)/BS1, "bs");
			delay((m&VTDLY)/VT1, "vt");
			delay((m&FFDLY)/FF1, "ff");
		}
		(void) printf("\n");
		m = cb.c_lflag;
		if (!(m&ISIG))
			(void) printf("-isig ");
		if (!(m&ICANON))
			(void) printf("-icanon ");
		if (m&XCASE)
			(void) printf("xcase ");
		(void) printf("-echo "+((m&ECHO) != 0));
		(void) printf("-echoe "+((m&ECHOE) != 0));
		(void) printf("-echok "+((m&ECHOK) != 0));
		if (m&ECHONL)
			(void) printf("echonl ");
		if (m&NOFLSH)
			(void) printf("noflsh ");
		if (m&TOSTOP)
			(void) printf("tostop ");
		if (m&ECHOCTL)
			(void) printf("echoctl ");
		if (m&ECHOPRT)
			(void) printf("echoprt ");
		if (m&ECHOKE)
			(void) printf("echoke ");
		if (m&DEFECHO)
			(void) printf("defecho ");
		if (m&FLUSHO)
			(void) printf("flusho ");
		if (m&PENDIN)
			(void) printf("pendin ");
		if (m&IEXTEN)
			(void) printf("iexten ");
		(void) printf("\n");
	}
	if (term & FLOW) {
		m = termiox.x_hflag;
		if (m & RTSXOFF)
			(void) printf("rtsxoff ");
		if (m & CTSXON)
			(void) printf("ctsxon ");
		if (m & DTRXOFF)
			(void) printf("dtrxoff ");
		if (m & CDXON)
			(void) printf("cdxon ");
		if (m & ISXOFF)
			(void) printf("isxoff ");
		m = termiox.x_cflag;
		switch (m & XMTCLK) {
			case XCIBRG: (void)printf("xcibrg ");
					break;
			case XCTSET: (void)printf("xctset ");
					break;
			case XCRSET: (void)printf("xcrset ");
		}

		switch (m & RCVCLK) {
			case RCIBRG: (void)printf("rcibrg ");
					break;
			case RCTSET: (void)printf("rctset ");
					break;
			case RCRSET: (void)printf("rcrset ");
		}

		switch (m & TSETCLK) {
			case TSETCOFF: (void)printf("tsetcoff ");
					break;
			case TSETCRBRG: (void)printf("tsetcrbrg ");
					break;
			case TSETCTBRG: (void)printf("tsetctbrg ");
					break;
			case TSETCTSET: (void)printf("tsetctset ");
					break;
			case TSETCRSET: (void)printf("tsetcrset ");
		}

		switch (m & RSETCLK) {
			case RSETCOFF: (void)printf("rsetcoff ");
					break;
			case RSETCRBRG: (void)printf("rsetcrbrg ");
					break;
			case RSETCTBRG: (void)printf("rsetctbrg ");
					break;
			case RSETCTSET: (void)printf("rsetctset ");
					break;
			case RSETCRSET: (void)printf("rsetcrset ");
		}
		(void) printf("\n");
	}
}

void
pramodes(void)				/* print all modes, -a option */
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
			(void) printf(gettext("line = %d; "), ocb.c_line);
		(void) printf("\n");
		if (term & WINDOW) {
			(void) printf(gettext("rows = %d; columns = %d;"),
			    winsize.ws_row, winsize.ws_col);
			(void) printf(gettext(
			    " ypixels = %d; xpixels = %d;\n"),
			    winsize.ws_ypixel, winsize.ws_xpixel);
		}
#ifdef EUC
		if ((term & CSIW) && kcswp.locale_name[0]) {
			(void) printf("csdata %s\n", kcswp.locale_name);
		} else {
			(void) printf("csdata ?\n");
		}
		/*
		 * If kwp.eucw[0] is zero, it means the current codeset type
		 * in the ldterm is not EUC.
		 */
		if ((term & EUCW) && kwp.eucw[0]) {
			(void) printf("eucw %d:%d:%d:%d, ", kwp.eucw[0],
			    kwp.eucw[1], kwp.eucw[2], kwp.eucw[3]);
			(void) printf("scrw %d:%d:%d:%d\n", kwp.scrw[0],
			    kwp.scrw[1], kwp.scrw[2], kwp.scrw[3]);
		} else
			(void) printf("eucw ?, scrw ?\n");
#endif /* EUC */
		if ((cb.c_lflag&ICANON) == 0)
			(void) printf(gettext("min = %d; time = %d;\n"),
			    cb.c_cc[VMIN], cb.c_cc[VTIME]);
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
			pit(cb.c_cc[VSTATUS], "status", ";\n");
		}
	} else
		pit((unsigned)stio.tab, "ctab", "\n");
	m = cb.c_cflag;
	(void) printf("-parenb "+((m&PARENB) != 0));
	(void) printf("-parodd "+((m&PARODD) != 0));
	(void) printf("cs%c ", '5'+(m&CSIZE)/CS6);
	(void) printf("-cstopb "+((m&CSTOPB) != 0));
	(void) printf("-hupcl "+((m&HUPCL) != 0));
	(void) printf("-cread "+((m&CREAD) != 0));
	(void) printf("-clocal "+((m&CLOCAL) != 0));

	(void) printf("-loblk "+((m&LOBLK) != 0));
	(void) printf("-crtscts "+((m&CRTSCTS) != 0));
	(void) printf("-crtsxoff "+((m&CRTSXOFF) != 0));
	if (term & TERMIOS)
		(void) printf("-parext "+((m&PAREXT) != 0));

	(void) printf("\n");
	m = cb.c_iflag;
	(void) printf("-ignbrk "+((m&IGNBRK) != 0));
	(void) printf("-brkint "+((m&BRKINT) != 0));
	(void) printf("-ignpar "+((m&IGNPAR) != 0));
	(void) printf("-parmrk "+((m&PARMRK) != 0));
	(void) printf("-inpck "+((m&INPCK) != 0));
	(void) printf("-istrip "+((m&ISTRIP) != 0));
	(void) printf("-inlcr "+((m&INLCR) != 0));
	(void) printf("-igncr "+((m&IGNCR) != 0));
	(void) printf("-icrnl "+((m&ICRNL) != 0));
	(void) printf("-iuclc "+((m&IUCLC) != 0));
	(void) printf("\n");
	(void) printf("-ixon "+((m&IXON) != 0));
	(void) printf("-ixany "+((m&IXANY) != 0));
	(void) printf("-ixoff "+((m&IXOFF) != 0));
	if (term & TERMIOS)
		(void) printf("-imaxbel "+((m&IMAXBEL) != 0));
	(void) printf("\n");
	m = cb.c_lflag;
	(void) printf("-isig "+((m&ISIG) != 0));
	(void) printf("-icanon "+((m&ICANON) != 0));
	(void) printf("-xcase "+((m&XCASE) != 0));
	(void) printf("-echo "+((m&ECHO) != 0));
	(void) printf("-echoe "+((m&ECHOE) != 0));
	(void) printf("-echok "+((m&ECHOK) != 0));
	(void) printf("-echonl "+((m&ECHONL) != 0));
	(void) printf("-noflsh "+((m&NOFLSH) != 0));
	if (term & TERMIOS) {
		(void) printf("\n");
		(void) printf("-tostop "+((m&TOSTOP) != 0));
		(void) printf("-echoctl "+((m&ECHOCTL) != 0));
		(void) printf("-echoprt "+((m&ECHOPRT) != 0));
		(void) printf("-echoke "+((m&ECHOKE) != 0));
		(void) printf("-defecho "+((m&DEFECHO) != 0));
		(void) printf("-flusho "+((m&FLUSHO) != 0));
		(void) printf("-pendin "+((m&PENDIN) != 0));
		(void) printf("-iexten "+((m&IEXTEN) != 0));
	}
	if (!(term & ASYNC)) {
		(void) printf("-stflush "+((m&STFLUSH) != 0));
		(void) printf("-stwrap "+((m&STWRAP) != 0));
		(void) printf("-stappl "+((m&STAPPL) != 0));
	}
	(void) printf("\n");
	m = cb.c_oflag;
	(void) printf("-opost "+((m&OPOST) != 0));
	(void) printf("-olcuc "+((m&OLCUC) != 0));
	(void) printf("-onlcr "+((m&ONLCR) != 0));
	(void) printf("-ocrnl "+((m&OCRNL) != 0));
	(void) printf("-onocr "+((m&ONOCR) != 0));
	(void) printf("-onlret "+((m&ONLRET) != 0));
	(void) printf("-ofill "+((m&OFILL) != 0));
	(void) printf("-ofdel "+((m&OFDEL) != 0));
	delay((m&CRDLY)/CR1, "cr");
	delay((m&NLDLY)/NL1, "nl");
	delay((m&TABDLY)/TAB1, "tab");
	delay((m&BSDLY)/BS1, "bs");
	delay((m&VTDLY)/VT1, "vt");
	delay((m&FFDLY)/FF1, "ff");
	(void) printf("\n");
	if (term & FLOW) {
		m = termiox.x_hflag;
		(void) printf("-rtsxoff "+((m&RTSXOFF) != 0));
		(void) printf("-ctsxon "+((m&CTSXON) != 0));
		(void) printf("-dtrxoff "+((m&DTRXOFF) != 0));
		(void) printf("-cdxon "+((m&CDXON) != 0));
		(void) printf("-isxoff "+((m&ISXOFF) != 0));
		m = termiox.x_cflag;
		switch (m & XMTCLK) {
			case XCIBRG: (void)printf("xcibrg ");
					break;
			case XCTSET: (void)printf("xctset ");
					break;
			case XCRSET: (void)printf("xcrset ");
		}

		switch (m & RCVCLK) {
			case RCIBRG: (void)printf("rcibrg ");
					break;
			case RCTSET: (void)printf("rctset ");
					break;
			case RCRSET: (void)printf("rcrset ");
		}

		switch (m & TSETCLK) {
			case TSETCOFF: (void)printf("tsetcoff ");
					break;
			case TSETCRBRG: (void)printf("tsetcrbrg ");
					break;
			case TSETCTBRG: (void)printf("tsetctbrg ");
					break;
			case TSETCTSET: (void)printf("tsetctset ");
					break;
			case TSETCRSET: (void)printf("tsetcrset ");
		}

		switch (m & RSETCLK) {
			case RSETCOFF: (void)printf("rsetcoff ");
					break;
			case RSETCRBRG: (void)printf("rsetcrbrg ");
					break;
			case RSETCTBRG: (void)printf("rsetctbrg ");
					break;
			case RSETCTSET: (void)printf("rsetctset ");
					break;
			case RSETCRSET: (void)printf("rsetcrset ");
		}
		(void) printf("\n");
	}
}

/* print function for prmodes() and pramodes() */
void
pit(unsigned char what, char *itsname, char *sep)
{

	pitt++;
	(void) printf("%s", itsname);
	if ((term & TERMIOS) && what == _POSIX_VDISABLE ||
	    !(term & TERMIOS) && what == 0200) {
		(void) printf(" = <undef>%s", sep);
		return;
	}
	(void) printf(" = ");
	if (what & 0200 && !isprint(what)) {
		(void) printf("-");
		what &= ~ 0200;
	}
	if (what == 0177) {
		(void) printf("^?%s", sep);
		return;
	} else if (what < ' ') {
		(void) printf("^");
		what += '`';
		if (what > 'z')
			what -= 'a' -'A';
	}
	(void) printf("%c%s", what, sep);
}

void
delay(int m, char *s)
{
	if (m)
		(void) printf("%s%d ", s, m);
}

void
prspeed(char *c, int scode)
{
	int sval = -1;
	int i;

	for (i = 0; speeds[i].string; i++) {
		if (speeds[i].code == scode) {
			sval = speeds[i].value;
			break;
		}
	}

	(void) printf("%s%d baud; ", c, sval);
}

/* print current settings for use with  */
void
prencode(void)		/* another stty cmd, used for -g option */
{
	int i, last;

	/*
	 * Although there are only 16 control chars defined as of April 1995,
	 * prencode() and encode() will not have to be changed if up to MAX_CC
	 * control chars are defined in the future.  A maximum of MAX_CC rather
	 * than NCCS control chars are printed because the last control slot
	 * is unused.  "stty -g" prints out a total of NUM_FIELDS fields
	 * (NUM_MODES modes + MAX_CC control chars).  First print the input,
	 * output, control, and line discipline modes.
	 */
	(void) printf("%x:%x:%x:%x", cb.c_iflag, cb.c_oflag, cb.c_cflag,
	    cb.c_lflag);

	/* Print the control character fields. */
	if (term & TERMIOS)
		last = MAX_CC;
	else
		last = NCC;
#ifdef EUC
	if (term & CSIW) {
		for (i = 0; i < MAX_CC; i++)
			(void) printf(":%x", (i >= last) ? 0 : cb.c_cc[i]);
		/*
		 * Print out ldterm_cs_data_user_t data fields for
		 * PSARC/1999/140 TCR2. This change introduces additional
		 * 44 fields that come from the ldterm_cs_data_user_t data
		 * structure.
		 */
		(void) printf(":%x:%x:%x:", kcswp.version, kcswp.codeset_type,
		    kcswp.csinfo_num);
		if (*kcswp.locale_name == '\0') {
			(void) printf("00");
		} else {
			for (i = 0; kcswp.locale_name[i] && i < MAXNAMELEN; i++)
				(void) printf("%02x", kcswp.locale_name[i]);
		}
		for (i = 0; i < LDTERM_CS_MAX_CODESETS; i++)
			(void) printf(":%x:%x:%x:%x",
			    kcswp.eucpc_data[i].byte_length,
			    kcswp.eucpc_data[i].screen_width,
			    kcswp.eucpc_data[i].msb_start,
			    kcswp.eucpc_data[i].msb_end);
	} else {
#endif /* EUC */
		for (i = 0; i < last; i++)
			(void) printf(":%x", cb.c_cc[i]);
#ifdef EUC
	}
#endif /* EUC */
	(void) printf("\n");
}
