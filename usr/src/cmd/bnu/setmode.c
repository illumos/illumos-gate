/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Stolen from ucb/lpr/printjob.c
 */

#include <string.h>
#include "uucp.h"

static struct termios termios_set;
static struct termios termios_clear;

static int parse_modes(char *modes);
static void setty(int);

int
setmode(modes, fd)
	char *modes;
	int fd;
{
	if (parse_modes(modes))
		setty(fd);
	return (0);
}

struct mds {
	char	*string;
	unsigned long	set;
	unsigned long	reset;
};
						/* Control Modes */
static struct mds cmodes[] = {
	"-parity", CS8, PARENB|CSIZE,
	"-evenp", CS8, PARENB|CSIZE,
	"-oddp", CS8, PARENB|PARODD|CSIZE,
	"parity", PARENB|CS7, PARODD|CSIZE,
	"evenp", PARENB|CS7, PARODD|CSIZE,
	"oddp", PARENB|PARODD|CS7, CSIZE,
	"parenb", PARENB, 0,
	"-parenb", 0, PARENB,
	"parodd", PARODD, 0,
	"-parodd", 0, PARODD,
	"cs8", CS8, CSIZE,
	"cs7", CS7, CSIZE,
	"cs6", CS6, CSIZE,
	"cs5", CS5, CSIZE,
	"cstopb", CSTOPB, 0,
	"-cstopb", 0, CSTOPB,
	"stopb", CSTOPB, 0,
	"-stopb", 0, CSTOPB,
	"hupcl", HUPCL, 0,
	"hup", HUPCL, 0,
	"-hupcl", 0, HUPCL,
	"-hup", 0, HUPCL,
	"clocal", CLOCAL, 0,
	"-clocal", 0, CLOCAL,
	"nohang", CLOCAL, 0,
	"-nohang", 0, CLOCAL,
#if 0		/* this bit isn't supported */
	"loblk", LOBLK, 0,
	"-loblk", 0, LOBLK,
#endif
	"cread", CREAD, 0,
	"-cread", 0, CREAD,
#ifndef CRTSCTS
#define	CRTSCTS	0x80000000
#endif
	"crtscts", CRTSCTS, 0,
	"-crtscts", 0, CRTSCTS,
#ifndef CRTSXOFF
#define	CRTSXOFF 0x40000000
#endif
	"crtsxoff", CRTSXOFF, 0,
	"-crtsxoff", 0, CRTSXOFF,
	"litout", CS8, (CSIZE|PARENB),
	"-litout", (CS7|PARENB), CSIZE,
	"pass8", CS8, (CSIZE|PARENB),
	"-pass8", (CS7|PARENB), CSIZE,
	"raw", CS8, (CSIZE|PARENB),
	"-raw", (CS7|PARENB), CSIZE,
	"cooked", (CS7|PARENB), CSIZE,
	"sane", (CS7|PARENB|CREAD), (CSIZE|PARODD|CLOCAL),
	0
};
						/* Input Modes */
static struct mds imodes[] = {
	"ignbrk", IGNBRK, 0,
	"-ignbrk", 0, IGNBRK,
	"brkint", BRKINT, 0,
	"-brkint", 0, BRKINT,
	"ignpar", IGNPAR, 0,
	"-ignpar", 0, IGNPAR,
	"parmrk", PARMRK, 0,
	"-parmrk", 0, PARMRK,
	"inpck", INPCK, 0,
	"-inpck", 0, INPCK,
	"istrip", ISTRIP, 0,
	"-istrip", 0, ISTRIP,
	"inlcr", INLCR, 0,
	"-inlcr", 0, INLCR,
	"igncr", IGNCR, 0,
	"-igncr", 0, IGNCR,
	"icrnl", ICRNL, 0,
	"-icrnl", 0, ICRNL,
	"-nl", ICRNL, (INLCR|IGNCR),
	"nl", 0, ICRNL,
	"iuclc", IUCLC, 0,
	"-iuclc", 0, IUCLC,
	"lcase", IUCLC, 0,
	"-lcase", 0, IUCLC,
	"LCASE", IUCLC, 0,
	"-LCASE", 0, IUCLC,
	"ixon", IXON, 0,
	"-ixon", 0, IXON,
	"ixany", IXANY, 0,
	"-ixany", 0, IXANY,
	"decctlq", 0, IXANY,
	"-decctlq", IXANY, 0,
	"ixoff", IXOFF, 0,
	"-ixoff", 0, IXOFF,
	"tandem", IXOFF, 0,
	"-tandem", 0, IXOFF,
	"imaxbel", IMAXBEL, 0,
	"-imaxbel", 0, IMAXBEL,
	"pass8", 0, ISTRIP,
	"-pass8", ISTRIP, 0,
	"raw", 0, (unsigned long)-1,
	"-raw", (BRKINT|IGNPAR|ISTRIP|ICRNL|IXON|IMAXBEL), 0,
	"cooked", (BRKINT|IGNPAR|ISTRIP|ICRNL|IXON), 0,
	"sane", (BRKINT|IGNPAR|ISTRIP|ICRNL|IXON|IMAXBEL),
		(IGNBRK|PARMRK|INPCK|INLCR|IGNCR|IUCLC|IXOFF),
	0
};
						/* Local Modes */
static struct mds lmodes[] = {
	"isig", ISIG, 0,
	"-isig", 0, ISIG,
	"noisig", 0, ISIG,
	"-noisig", ISIG, 0,
	"iexten", IEXTEN, 0,
	"-iexten", 0, IEXTEN,
	"icanon", ICANON, 0,
	"-icanon", 0, ICANON,
	"cbreak", 0, ICANON,
	"-cbreak", ICANON, 0,
	"xcase", XCASE, 0,
	"-xcase", 0, XCASE,
	"lcase", XCASE, 0,
	"-lcase", 0, XCASE,
	"LCASE", XCASE, 0,
	"-LCASE", 0, XCASE,
	"echo", ECHO, 0,
	"-echo", 0, ECHO,
	"echoe", ECHOE, 0,
	"-echoe", 0, ECHOE,
	"crterase", ECHOE, 0,
	"-crterase", 0, ECHOE,
	"echok", ECHOK, 0,
	"-echok", 0, ECHOK,
	"lfkc", ECHOK, 0,
	"-lfkc", 0, ECHOK,
	"echonl", ECHONL, 0,
	"-echonl", 0, ECHONL,
	"noflsh", NOFLSH, 0,
	"-noflsh", 0, NOFLSH,
	"tostop", TOSTOP, 0,
	"-tostop", 0, TOSTOP,
	"echoctl", ECHOCTL, 0,
	"-echoctl", 0, ECHOCTL,
	"ctlecho", ECHOCTL, 0,
	"-ctlecho", 0, ECHOCTL,
	"echoprt", ECHOPRT, 0,
	"-echoprt", 0, ECHOPRT,
	"prterase", ECHOPRT, 0,
	"-prterase", 0, ECHOPRT,
	"echoke", ECHOKE, 0,
	"-echoke", 0, ECHOKE,
	"crtkill", ECHOKE, 0,
	"-crtkill", 0, ECHOKE,
#if 0		/* this bit isn't supported yet */
	"defecho", DEFECHO, 0,
	"-defecho", 0, DEFECHO,
#endif
	"raw", 0, (ISIG|ICANON|XCASE|IEXTEN),
	"-raw", (ISIG|ICANON|IEXTEN), 0,
	"cooked", (ISIG|ICANON), 0,
	"sane", (ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE),
		(XCASE|ECHOPRT|ECHONL|NOFLSH),
	0,
};
						/* Output Modes */
static struct mds omodes[] = {
	"opost", OPOST, 0,
	"-opost", 0, OPOST,
	"nopost", 0, OPOST,
	"-nopost", OPOST, 0,
	"olcuc", OLCUC, 0,
	"-olcuc", 0, OLCUC,
	"lcase", OLCUC, 0,
	"-lcase", 0, OLCUC,
	"LCASE", OLCUC, 0,
	"-LCASE", 0, OLCUC,
	"onlcr", ONLCR, 0,
	"-onlcr", 0, ONLCR,
	"-nl", ONLCR, (OCRNL|ONLRET),
	"nl", 0, ONLCR,
	"ocrnl", OCRNL, 0,
	"-ocrnl", 0, OCRNL,
	"onocr", ONOCR, 0,
	"-onocr", 0, ONOCR,
	"onlret", ONLRET, 0,
	"-onlret", 0, ONLRET,
	"fill", OFILL, OFDEL,
	"-fill", 0, OFILL|OFDEL,
	"nul-fill", OFILL, OFDEL,
	"del-fill", OFILL|OFDEL, 0,
	"ofill", OFILL, 0,
	"-ofill", 0, OFILL,
	"ofdel", OFDEL, 0,
	"-ofdel", 0, OFDEL,
	"cr0", CR0, CRDLY,
	"cr1", CR1, CRDLY,
	"cr2", CR2, CRDLY,
	"cr3", CR3, CRDLY,
	"tab0", TAB0, TABDLY,
	"tabs", TAB0, TABDLY,
	"tab1", TAB1, TABDLY,
	"tab2", TAB2, TABDLY,
	"-tabs", XTABS, TABDLY,
	"tab3", XTABS, TABDLY,
	"nl0", NL0, NLDLY,
	"nl1", NL1, NLDLY,
	"ff0", FF0, FFDLY,
	"ff1", FF1, FFDLY,
	"vt0", VT0, VTDLY,
	"vt1", VT1, VTDLY,
	"bs0", BS0, BSDLY,
	"bs1", BS1, BSDLY,
#if 0		/* these bits aren't supported yet */
	"pageout", PAGEOUT, 0,
	"-pageout", 0, PAGEOUT,
	"wrap", WRAP, 0,
	"-wrap", 0, WRAP,
#endif
	"litout", 0, OPOST,
	"-litout", OPOST, 0,
	"raw", 0, OPOST,
	"-raw", OPOST, 0,
	"cooked", OPOST, 0,
	"33", CR1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"tty33", CR1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"tn", CR1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"tn300", CR1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"ti", CR2, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"ti700", CR2, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"05", NL1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"vt05", NL1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"tek", FF1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"37", (FF1|VT1|CR2|TAB1|NL1), (NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY),
	"tty37", (FF1|VT1|CR2|TAB1|NL1), (NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY),
	"sane", (OPOST|ONLCR), (OLCUC|OCRNL|ONOCR|ONLRET|OFILL|OFDEL|
			NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY),
	0,
};

/*
 * Parse a set of modes.
 */
static int
parse_modes(modes)
	char *modes;
{
	char *curtoken;
	int match;
	int i;

	termios_clear.c_iflag = 0;
	termios_clear.c_oflag = 0;
	termios_clear.c_cflag = 0;
	termios_clear.c_lflag = 0;
	termios_set.c_iflag = 0;
	termios_set.c_oflag = 0;
	termios_set.c_cflag = 0;
	termios_set.c_lflag = 0;

	curtoken = strtok(modes, ",");
	while (curtoken != NULL) {
		match = 0;
		for (i = 0; imodes[i].string != NULL; i++) {
			if (strcmp(curtoken, imodes[i].string) == 0) {
				match++;
				termios_clear.c_iflag |= imodes[i].reset;
				termios_set.c_iflag |= imodes[i].set;
			}
		}
		for (i = 0; omodes[i].string != NULL; i++) {
			if (strcmp(curtoken, omodes[i].string) == 0) {
				match++;
				termios_clear.c_oflag |= omodes[i].reset;
				termios_set.c_oflag |= omodes[i].set;
			}
		}
		for (i = 0; cmodes[i].string != NULL; i++) {
			if (strcmp(curtoken, cmodes[i].string) == 0) {
				match++;
				termios_clear.c_cflag |= cmodes[i].reset;
				termios_set.c_cflag |= cmodes[i].set;
			}
		}
		for (i = 0; lmodes[i].string != NULL; i++) {
			if (strcmp(curtoken, lmodes[i].string) == 0) {
				match++;
				termios_clear.c_lflag |= lmodes[i].reset;
				termios_set.c_lflag |= lmodes[i].set;
			}
		}
		if (!match) {
			CDEBUG(5, "unknown mode %s in STTY= string", curtoken);
			return (0);
		}
		curtoken = strtok((char *)NULL, ",");
	}
	return (1);
}

/*
 * setup tty lines.
 */
static void
setty(int fd)
{
	struct termios termios;

	if ((*Ioctl)(fd, TCGETS, &termios) < 0) {
		CDEBUG(5, "ioctl(TCGETS): %d", errno);
		return;
	}

	termios.c_iflag &= ~termios_clear.c_iflag;
	termios.c_iflag |= termios_set.c_iflag;
	termios.c_oflag &= ~termios_clear.c_oflag;
	termios.c_oflag |= termios_set.c_oflag;
	termios.c_cflag &= ~termios_clear.c_cflag;
	termios.c_cflag |= termios_set.c_cflag;
	termios.c_lflag &= ~termios_clear.c_lflag;
	termios.c_lflag |= termios_set.c_lflag;

	if ((*Ioctl)(fd, TCSETSF, &termios) < 0) {
		CDEBUG(5, "ioctl(TCSETSF): %d", errno);
		return;
	}
}
