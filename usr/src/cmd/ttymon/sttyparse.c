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
#include <unistd.h>
#include <stdlib.h>
#include <libintl.h>
#include <sys/types.h>
#include <ctype.h>
#include <termio.h>
#include <sys/stermio.h>
#include <sys/termiox.h>
#ifdef EUC
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
#include <locale.h>
#include <string.h>

static char	*s_arg;			/* s_arg: ptr to mode to be set */
static int	match;
#ifdef EUC
static int parse_encoded(struct termios *, ldterm_cs_data_user_t *, int);
#else
static int parse_encoded(struct termios *);
#endif /* EUC */
static int eq(const char *string);
static int gct(char *cp, int term);

/* set terminal modes for supplied options */
char *
sttyparse(int argc, char *argv[], int term, struct termio *ocb,
	struct termios *cb, struct termiox *termiox, struct winsize *winsize
#ifdef EUC
	/* */, eucwidth_t *wp, struct eucioc *kwp, ldterm_cs_data_user_t *cswp,
	ldterm_cs_data_user_t *kcswp
#endif /* EUC */
	/* */)
{
	int i;

	while (--argc > 0) {
		s_arg = *++argv;
		match = 0;
		if (term & ASYNC) {
			if (eq("erase") && --argc)
				cb->c_cc[VERASE] = gct(*++argv, term);
			else if (eq("intr") && --argc)
				cb->c_cc[VINTR] = gct(*++argv, term);
			else if (eq("quit") && --argc)
				cb->c_cc[VQUIT] = gct(*++argv, term);
			else if (eq("eof") && --argc)
				cb->c_cc[VEOF] = gct(*++argv, term);
			else if (eq("min") && --argc) {
				if (isdigit((unsigned char)argv[1][0]))
					cb->c_cc[VMIN] = atoi(*++argv);
				else
					cb->c_cc[VMIN] = gct(*++argv, term);
			} else if (eq("eol") && --argc)
				cb->c_cc[VEOL] = gct(*++argv, term);
			else if (eq("eol2") && --argc)
				cb->c_cc[VEOL2] = gct(*++argv, term);
			else if (eq("time") && --argc) {
				if (isdigit((unsigned char)argv[1][0]))
					cb->c_cc[VTIME] = atoi(*++argv);
				else
					cb->c_cc[VTIME] = gct(*++argv, term);
			} else if (eq("kill") && --argc)
				cb->c_cc[VKILL] = gct(*++argv, term);
			else if (eq("swtch") && --argc)
				cb->c_cc[VSWTCH] = gct(*++argv, term);
			if (match)
				continue;
			if (term & TERMIOS) {
				if (eq("start") && --argc)
					cb->c_cc[VSTART] = gct(*++argv, term);
				else if (eq("stop") && --argc)
					cb->c_cc[VSTOP] = gct(*++argv, term);
				else if (eq("susp") && --argc)
					cb->c_cc[VSUSP] = gct(*++argv, term);
				else if (eq("dsusp") && --argc)
					cb->c_cc[VDSUSP] = gct(*++argv, term);
				else if (eq("rprnt") && --argc)
					cb->c_cc[VREPRINT] = gct(*++argv, term);
				else if (eq("reprint") && --argc)
					cb->c_cc[VREPRINT] = gct(*++argv, term);
				else if (eq("discard") && --argc)
					cb->c_cc[VDISCARD] = gct(*++argv, term);
				else if (eq("flush") && --argc)
					cb->c_cc[VDISCARD] = gct(*++argv, term);
				else if (eq("werase") && --argc)
					cb->c_cc[VWERASE] = gct(*++argv, term);
				else if (eq("lnext") && --argc)
					cb->c_cc[VLNEXT] = gct(*++argv, term);
				else if (eq("status") && --argc)
					cb->c_cc[VSTATUS] = gct(*++argv, term);
				else if (eq("erase2") && --argc)
					cb->c_cc[VERASE2] = gct(*++argv, term);
			}
			if (match)
				continue;
			if (eq("ek")) {
				cb->c_cc[VERASE] = CERASE;
				if (term & TERMIOS)
					cb->c_cc[VERASE2] = CERASE2;
				cb->c_cc[VKILL] = CKILL;
			} else if (eq("line") &&
			    !(term & TERMIOS) && --argc) {
				ocb->c_line = atoi(*++argv);
				continue;
			} else if (eq("raw")) {
				cb->c_cc[VMIN] = 1;
				cb->c_cc[VTIME] = 0;
			} else if (eq("-raw") | eq("cooked")) {
				cb->c_cc[VEOF] = CEOF;
				cb->c_cc[VEOL] = CNUL;
			} else if (eq("sane")) {
				cb->c_cc[VERASE] = CERASE;
				if (term & TERMIOS)
					cb->c_cc[VERASE2] = CERASE2;
				cb->c_cc[VKILL] = CKILL;
				cb->c_cc[VQUIT] = CQUIT;
				cb->c_cc[VINTR] = CINTR;
				cb->c_cc[VEOF] = CEOF;
				cb->c_cc[VEOL] = CNUL;
				cb->c_cc[VSTATUS] = CSTATUS;
				/* SWTCH purposely not set */
#ifdef EUC
			} else if (eq("defeucw")) {
				kwp->eucw[0] = '\001';
				kwp->eucw[1] =
				    (unsigned char)(wp->_eucw1 & 0177);
				kwp->eucw[2] =
				    (unsigned char)(wp->_eucw2 & 0177);
				kwp->eucw[3] =
				    (unsigned char)(wp->_eucw3 & 0177);

				kwp->scrw[0] = '\001';
				kwp->scrw[1] =
				    (unsigned char)(wp->_scrw1 & 0177);
				kwp->scrw[2] =
				    (unsigned char)(wp->_scrw2 & 0177);
				kwp->scrw[3] =
				    (unsigned char)(wp->_scrw3 & 0177);

				(void) memcpy((void *)kcswp, (const void *)cswp,
				    sizeof (ldterm_cs_data_user_t));
#endif /* EUC */
			} else if ((term & TERMIOS) && eq("ospeed") && --argc) {
				s_arg = *++argv;
				for (match = 0, i = 0; speeds[i].string; i++) {
					if (eq(speeds[i].string)) {
						(void) cfsetospeed(cb,
						    speeds[i].code);
						break;
					}
				}
				if (!match)
					return (s_arg);
				continue;

			} else if ((term & TERMIOS) && eq("ispeed") && --argc) {
				s_arg = *++argv;
				for (match = 0, i = 0; speeds[i].string; i++) {
					if (eq(speeds[i].string)) {
						(void) cfsetispeed(cb,
						    speeds[i].code);
						break;
					}
				}
				if (!match)
					return (s_arg);
				continue;

			} else {
				for (match = 0, i = 0; speeds[i].string; i++) {
					if (eq(speeds[i].string)) {
						(void) cfsetospeed(cb,
						    speeds[i].code);
						(void) cfsetispeed(cb,
						    speeds[i].code);
						break;
					}
				}
			}
		}
		if (!(term & ASYNC) && eq("ctab") && --argc) {
			cb->c_cc[7] = gct(*++argv, term);
			continue;
		}

		for (i = 0; imodes[i].string; i++)
			if (eq(imodes[i].string)) {
				cb->c_iflag &= ~imodes[i].reset;
				cb->c_iflag |= imodes[i].set;
#ifdef EUC
				if (wp->_multibyte &&
				    (eq("-raw") || eq("cooked") || eq("sane")))
					cb->c_iflag &= ~ISTRIP;
#endif /* EUC */
			}
		if (term & TERMIOS) {
			for (i = 0; nimodes[i].string; i++)
				if (eq(nimodes[i].string)) {
					cb->c_iflag &= ~nimodes[i].reset;
					cb->c_iflag |= nimodes[i].set;
				}
		}

		for (i = 0; omodes[i].string; i++)
			if (eq(omodes[i].string)) {
				cb->c_oflag &= ~omodes[i].reset;
				cb->c_oflag |= omodes[i].set;
			}
		if (!(term & ASYNC) && eq("sane")) {
			cb->c_oflag |= TAB3;
			continue;
		}
		for (i = 0; cmodes[i].string; i++)
			if (eq(cmodes[i].string)) {
				cb->c_cflag &= ~cmodes[i].reset;
				cb->c_cflag |= cmodes[i].set;
#ifdef EUC
				if (wp->_multibyte &&
				    (eq("-raw") || eq("cooked") ||
				    eq("sane"))) {
					cb->c_cflag &= ~(CS7|PARENB);
					cb->c_cflag |= CS8;
				}
#endif /* EUC */
			}
		if (term & TERMIOS)
			for (i = 0; ncmodes[i].string; i++)
				if (eq(ncmodes[i].string)) {
					cb->c_cflag &= ~ncmodes[i].reset;
					cb->c_cflag |= ncmodes[i].set;
				}
		for (i = 0; lmodes[i].string; i++)
			if (eq(lmodes[i].string)) {
				cb->c_lflag &= ~lmodes[i].reset;
				cb->c_lflag |= lmodes[i].set;
			}
		if (term & TERMIOS)
			for (i = 0; nlmodes[i].string; i++)
				if (eq(nlmodes[i].string)) {
					cb->c_lflag &= ~nlmodes[i].reset;
					cb->c_lflag |= nlmodes[i].set;
				}
		if (term & FLOW) {
			for (i = 0; hmodes[i].string; i++)
				if (eq(hmodes[i].string)) {
					termiox->x_hflag &= ~hmodes[i].reset;
					termiox->x_hflag |= hmodes[i].set;
				}
			for (i = 0; clkmodes[i].string; i++)
				if (eq(clkmodes[i].string)) {
					termiox->x_cflag &= ~clkmodes[i].reset;
					termiox->x_cflag |= clkmodes[i].set;
				}

		}

		if (eq("rows") && --argc)
			winsize->ws_row = atoi(*++argv);
		else if ((eq("columns") || eq("cols")) && --argc)
			winsize->ws_col = atoi(*++argv);
		else if (eq("xpixels") && --argc)
			winsize->ws_xpixel = atoi(*++argv);
		else if (eq("ypixels") && --argc)
			winsize->ws_ypixel = atoi(*++argv);

		if (!match) {
#ifdef EUC
			if (!parse_encoded(cb, kcswp, term)) {
#else
			if (!parse_encoded(cb)) {
#endif /* EUC */
				return (s_arg); /* parsing failed */
			}
		}
	}
	return ((char *)0);
}

static int
eq(const char *string)
{
	int i;

	if (!s_arg)
		return (0);
	i = 0;
loop:
	if (s_arg[i] != string[i])
		return (0);
	if (s_arg[i++] != '\0')
		goto loop;
	match++;
	return (1);
}

/* get pseudo control characters from terminal  */
/* and convert to internal representation	*/
static int
gct(char *cp, int term)
{
	int c;

	c = *cp;
	if (c == '^') {
		c = *++cp;
		if (c == '?')
			c = 0177;		/* map '^?' to 0177 */
		else if (c == '-') {
			/* map '^-' to undefined */
			c = (term & TERMIOS) ? _POSIX_VDISABLE : 0200;
		} else
			c &= 037;
	} else if (strcmp(cp, "undef") == 0) {
		/* map "undef" to undefined */
		c = (term & TERMIOS) ? _POSIX_VDISABLE : 0200;
	}
	return (c);
}

/* get modes of tty device and fill in applicable structures */
int
get_ttymode(int fd, struct termio *termio, struct termios *termios,
	struct stio *stermio, struct termiox *termiox, struct winsize *winsize
#ifdef EUC
	/* */, struct eucioc *kwp, ldterm_cs_data_user_t *kcswp
#endif /* EUC */
	/* */)
{
	int i;
	int term = 0;
#ifdef EUC
	struct strioctl cmd;
#endif /* EUC */
	if (ioctl(fd, STGET, stermio) == -1) {
		term |= ASYNC;
		if (ioctl(fd, TCGETS, termios) == -1) {
			if (ioctl(fd, TCGETA, termio) == -1)
				return (-1);
			termios->c_lflag = termio->c_lflag;
			termios->c_oflag = termio->c_oflag;
			termios->c_iflag = termio->c_iflag;
			termios->c_cflag = termio->c_cflag;
			for (i = 0; i < NCC; i++)
				termios->c_cc[i] = termio->c_cc[i];
		} else
			term |= TERMIOS;
	} else {
		termios->c_cc[7] = (unsigned)stermio->tab;
		termios->c_lflag = stermio->lmode;
		termios->c_oflag = stermio->omode;
		termios->c_iflag = stermio->imode;
	}

	if (ioctl(fd, TCGETX, termiox) == 0)
		term |= FLOW;

	if (ioctl(fd, TIOCGWINSZ, winsize) == 0)
		term |= WINDOW;
#ifdef EUC
	cmd.ic_cmd = EUC_WGET;
	cmd.ic_timout = 0;
	cmd.ic_len = sizeof (struct eucioc);
	cmd.ic_dp = (char *)kwp;

	if (ioctl(fd, I_STR, &cmd) == 0)
		term |= EUCW;

	cmd.ic_cmd = CSDATA_GET;
	cmd.ic_timout = 0;
	cmd.ic_len = sizeof (ldterm_cs_data_user_t);
	cmd.ic_dp = (char *)kcswp;

	if (ioctl(fd, I_STR, &cmd) == 0)
		term |= CSIW;
	else
		(void) memset((void *)kcswp, 0, sizeof (ldterm_cs_data_user_t));
#endif /* EUC */
	return (term);
}

/* set tty modes */
int
set_ttymode(int fd, int term, struct termio *termio, struct termios *termios,
	struct stio *stermio, struct termiox *termiox, struct winsize *winsize,
	struct winsize *owinsize
#ifdef EUC
	/* */, struct eucioc *kwp, ldterm_cs_data_user_t *kcswp,
	int invalid_ldterm_dat_file
#endif /* EUC */
	/* */)
{
	int i;
#ifdef EUC
	struct strioctl cmd;
#endif /* EUC */

	if (term & ASYNC) {
		if (term & TERMIOS) {
			if (ioctl(fd, TCSETSW, termios) == -1)
				return (-1);
		} else {
			termio->c_lflag = termios->c_lflag;
			termio->c_oflag = termios->c_oflag;
			termio->c_iflag = termios->c_iflag;
			termio->c_cflag = termios->c_cflag;
			for (i = 0; i < NCC; i++)
				termio->c_cc[i] = termios->c_cc[i];
			if (ioctl(fd, TCSETAW, termio) == -1)
				return (-1);
		}

	} else {
		stermio->imode = termios->c_iflag;
		stermio->omode = termios->c_oflag;
		stermio->lmode = termios->c_lflag;
		stermio->tab = termios->c_cc[7];
		if (ioctl(fd, STSET, stermio) == -1)
			return (-1);
	}
	if (term & FLOW) {
		if (ioctl(fd, TCSETXW, termiox) == -1)
			return (-1);
	}
	if ((owinsize->ws_col != winsize->ws_col ||
	    owinsize->ws_row != winsize->ws_row ||
	    owinsize->ws_xpixel != winsize->ws_xpixel ||
	    owinsize->ws_ypixel != winsize->ws_ypixel) &&
	    ioctl(0, TIOCSWINSZ, winsize) != 0)
		return (-1);
#ifdef EUC
	/*
	 * If the ldterm.dat file contains valid, non-EUC codeset info,
	 * send downstream CSDATA_SET. Otherwise, try EUC_WSET.
	 */
	if (invalid_ldterm_dat_file) {
		(void) fprintf(stderr, gettext(
		"stty: can't set codeset width due to invalid ldterm.dat.\n"));
		return (-1);
	} else if ((term & CSIW) && kcswp->version) {
		cmd.ic_cmd = CSDATA_SET;
		cmd.ic_timout = 0;
		cmd.ic_len = sizeof (ldterm_cs_data_user_t);
		cmd.ic_dp = (char *)kcswp;
		if (ioctl(fd, I_STR, &cmd) != 0) {
			(void) fprintf(stderr, gettext(
			    "stty: can't set codeset width.\n"));
			return (-1);
		}
	} else if (term & EUCW) {
		cmd.ic_cmd = EUC_WSET;
		cmd.ic_timout = 0;
		cmd.ic_len = sizeof (struct eucioc);
		cmd.ic_dp = (char *)kwp;
		if (ioctl(fd, I_STR, &cmd) != 0) {
			(void) fprintf(stderr, gettext(
			    "stty: can't set EUC codeset width.\n"));
			return (-1);
		}
	}
#endif /* EUC */
	return (0);
}

static int
parse_encoded(struct termios *cb
#ifdef EUC
	/* */, ldterm_cs_data_user_t *kcswp, int term
#endif /* EUC */
	/* */)
{
	unsigned long grab[NUM_FIELDS];
	int last, i;
#ifdef EUC
	long l;
	char s[3];
	char *t;
	char *r;
	uchar_t *g;
	ldterm_cs_data_user_t ecswp;
#endif /* EUC */

	/*
	 * Although there are only 16 control chars defined as of April 1995,
	 * parse_encoded() and prencode()  will not have to be changed if up to
	 * MAX_CC control chars are defined in the future.
	 * Scan the fields of "stty -g" output into the grab array.
	 * Set a total of NUM_FIELDS fields (NUM_MODES modes + MAX_CC
	 * control chars).
	 */
	i = sscanf(s_arg, "%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx:"
	    "%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx",
	    &grab[0], &grab[1], &grab[2], &grab[3], &grab[4], &grab[5],
	    &grab[6], &grab[7], &grab[8], &grab[9], &grab[10], &grab[11],
	    &grab[12], &grab[13], &grab[14], &grab[15],	&grab[16], &grab[17],
	    &grab[18], &grab[19], &grab[20], &grab[21]);

	if (i < 12)
		return (0);
	cb->c_iflag = grab[0];
	cb->c_oflag = grab[1];
	cb->c_cflag = grab[2];
	cb->c_lflag = grab[3];

	last = i - NUM_MODES;
	for (i = 0; i < last; i++)
		cb->c_cc[i] = (unsigned char) grab[i+NUM_MODES];

#ifdef EUC
	/* This is to fulfill PSARC/1999/140 TCR2. */
	if (term & CSIW) {
		r = strdup(s_arg);
		if (r == (char *)NULL) {
			(void) fprintf(stderr, gettext(
			    "no more memory - try again later\n"));
			return (0);
		}
		t = strtok(r, ":");
		for (i = 0; t != NULL && i < 22; i++) {
			t = strtok(NULL, ":");
		}

		if (t == NULL) {
			free((void *)r);
			return (0);
		}
		ecswp.version = (uchar_t)strtol(t, (char **)NULL, 16);
		if (ecswp.version > LDTERM_DATA_VERSION ||
		    ecswp.version == 0) {
			free((void *)r);
			return (0);
		}

		if ((t = strtok(NULL, ":")) == NULL) {
			free((void *)r);
			return (0);
		}
		ecswp.codeset_type = (uchar_t)strtol(t, (char **)NULL, 16);
		if (ecswp.codeset_type < LDTERM_CS_TYPE_MIN ||
		    ecswp.codeset_type > LDTERM_CS_TYPE_MAX) {
			free((void *)r);
			return (0);
		}

		if ((t = strtok(NULL, ":")) == NULL) {
			free((void *)r);
			return (0);
		}
		ecswp.csinfo_num = (uchar_t)strtol(t, (char **)NULL, 16);
		if ((ecswp.codeset_type == LDTERM_CS_TYPE_EUC &&
		    ecswp.csinfo_num > 3) ||
		    (ecswp.codeset_type == LDTERM_CS_TYPE_PCCS &&
		    (ecswp.csinfo_num < 1 || ecswp.csinfo_num > 10))) {
			free((void *)r);
			return (0);
		}

		if ((t = strtok(NULL, ":")) == NULL) {
			free((void *)r);
			return (0);
		}
		s[2] = '\0';
		for (i = 0; *t != 0 && i < MAXNAMELEN; i++) {
			if (*(t + 1) == (char)NULL) {
				free((void *)r);
				return (0);
			}
			s[0] = *t++;
			s[1] = *t++;
			ecswp.locale_name[i] = (char)strtol(s, (char **)NULL,
			    16);
		}
		if (i >= MAXNAMELEN) {
			free((void *)r);
			return (0);
		}
		ecswp.locale_name[i] = '\0';

		g = (uchar_t *)ecswp.eucpc_data;
		for (i = 0; i < (LDTERM_CS_MAX_CODESETS * 4); i++) {
			if ((t = strtok(NULL, ":")) == NULL) {
				free((void *)r);
				return (0);
			}
			l = strtol(t, (char **)NULL, 16);
			if (l < 0 || l > 255) {
				free((void *)r);
				return (0);
			}
			*g++ = (uchar_t)l;
		}

		/* We got the 'ecswp' all filled up now; let's copy. */
		(void) memcpy((void *)kcswp, (const void *)&ecswp,
		    sizeof (ldterm_cs_data_user_t));
	}
#endif /* EUC */

	return (1);
}
