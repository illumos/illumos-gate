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

/*
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <termio.h>
#include <sys/stermio.h>
#include <sys/termiox.h>
#include "stty.h"

const struct speeds speeds[] = {
	"0",		B0,		0,
	"50",		B50,		50,
	"75",		B75,		75,
	"110",		B110,		110,
	"134",		B134,		134,
	"134.5", 	B134,		134,
	"150",		B150,		150,
	"200",		B200,		200,
	"300",		B300,		300,
	"600",		B600,		600,
	"1200",		B1200,		1200,
	"1800",		B1800,		1800,
	"2400",		B2400,		2400,
	"4800",		B4800,		4800,
	"9600",		B9600,		9600,
	"19200",	B19200,		19200,
	"19.2",		B19200,		19200,
	"38400",	B38400,		38400,
	"38.4",		B38400,		38400,
	"57600",	B57600,		57600,
	"57.6",		B57600,		57600,
	"76800",	B76800,		76800,
	"76.8",		B76800,		76800,
	"115200",	B115200,	115200,
	"115.2",	B115200,	115200,
	"153600",	B153600,	153600,
	"153.6",	B153600,	153600,
	"230400",	B230400,	230400,
	"230.4",	B230400,	230400,
	"307200",	B307200,	307200,
	"307.2",	B307200,	307200,
	"460800",	B460800,	460800,
	"460.8",	B460800,	460800,
	"921600",	B921600,	921600,
	"921.6",	B921600,	921600,
	"1000000",	B1000000,	1000000,
	"1152000",	B1152000,	1152000,
	"1500000",	B1500000,	1500000,
	"2000000",	B2000000,	2000000,
	"2500000",	B2500000,	2500000,
	"3000000",	B3000000,	3000000,
	"3500000",	B3500000,	3500000,
	"4000000",	B4000000,	4000000,
	0,
};

const struct mds cmodes[] = {
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
	"hupcl", HUPCL, 0,
	"hup", HUPCL, 0,
	"-hupcl", 0, HUPCL,
	"-hup", 0, HUPCL,
	"clocal", CLOCAL, 0,
	"-clocal", 0, CLOCAL,
	"loblk", LOBLK, 0,
	"-loblk", 0, LOBLK,
	"cread", CREAD, 0,
	"-cread", 0, CREAD,
	"crtscts", (long)CRTSCTS, 0,
	"-crtscts", 0, (long)CRTSCTS,
	"crtsxoff", CRTSXOFF, 0,
	"-crtsxoff", 0, CRTSXOFF,
	"raw", CS8, (CSIZE|PARENB),
	"-raw", (CS7|PARENB), CSIZE,
	"cooked", (CS7|PARENB), CSIZE,
	"sane", (CS7|PARENB|CREAD), (CSIZE|PARODD|CLOCAL),
	0
};

const struct mds ncmodes[] = {
	"parext", PAREXT, 0,
	"-parext", 0, PAREXT,
	"markp", (PARENB|PARODD|CS7|PAREXT), CSIZE,
	"-markp", CS8, (PARENB|PARODD|CSIZE|PAREXT),
	"spacep", (PARENB|CS7|PAREXT), PARODD|CSIZE,
	"-spacep", CS8, (PARENB|CSIZE|PAREXT),
	0
};

const struct mds imodes[] = {
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
#ifdef XPG4
	"-nl", 0, (ICRNL|INLCR|IGNCR),
	"nl", ICRNL, 0,
#else
	"-nl", ICRNL, (INLCR|IGNCR),
	"nl", 0, ICRNL,
#endif
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
	"ixoff", IXOFF, 0,
	"-ixoff", 0, IXOFF,
	"raw", 0, -1,
	"-raw", (BRKINT|IGNPAR|ISTRIP|ICRNL|IXON), 0,
	"cooked", (BRKINT|IGNPAR|ISTRIP|ICRNL|IXON), 0,
	"sane", (BRKINT|IGNPAR|ISTRIP|ICRNL|IXON|IMAXBEL),
		(IGNBRK|PARMRK|INPCK|INLCR|IGNCR|IUCLC|IXOFF|IXANY),
	0
};


const struct mds nimodes[] = {
	"imaxbel", IMAXBEL, 0,
	"-imaxbel", 0, IMAXBEL,
	0
};

const struct mds lmodes[] = {
	"isig", ISIG, 0,
	"-isig", 0, ISIG,
	"icanon", ICANON, 0,
	"-icanon", 0, ICANON,
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
	"echok", ECHOK, 0,
	"-echok", 0, ECHOK,
	"lfkc", ECHOK, 0,
	"-lfkc", 0, ECHOK,
	"echonl", ECHONL, 0,
	"-echonl", 0, ECHONL,
	"noflsh", NOFLSH, 0,
	"-noflsh", 0, NOFLSH,
	"raw", 0, (ISIG|ICANON|XCASE),
	"-raw", (ISIG|ICANON), 0,
	"cooked", (ISIG|ICANON), 0,
	"sane", (ISIG|ICANON|IEXTEN|ECHO|ECHOK|ECHOE|ECHOKE|ECHOCTL),
		(XCASE|ECHONL|NOFLSH|STFLUSH|STWRAP|STAPPL),
	"stflush", STFLUSH, 0,
	"-stflush", 0, STFLUSH,
	"stwrap", STWRAP, 0,
	"-stwrap", 0, STWRAP,
	"stappl", STAPPL, 0,
	"-stappl", 0, STAPPL,
	0,
};

const struct mds nlmodes[] = {
	"tostop", TOSTOP, 0,
	"-tostop", 0, TOSTOP,
	"echoctl", ECHOCTL, 0,
	"-echoctl", 0, ECHOCTL,
	"echoprt", ECHOPRT, 0,
	"-echoprt", 0, ECHOPRT,
	"echoke", ECHOKE, 0,
	"-echoke", 0, ECHOKE,
	"defecho", DEFECHO, 0,
	"-defecho", 0, DEFECHO,
	"flusho", FLUSHO, 0,
	"-flusho", 0, FLUSHO,
	"pendin", PENDIN, 0,
	"-pendin", 0, PENDIN,
	"iexten", IEXTEN, 0,
	"-iexten", 0, IEXTEN,
	0
};

const struct mds omodes[] = {
	"opost", OPOST, 0,
	"-opost", 0, OPOST,
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
	"tab3", TAB3, TABDLY,
	"-tabs", TAB3, TABDLY,
	"tab8", TAB3, TABDLY,
	"nl0", NL0, NLDLY,
	"nl1", NL1, NLDLY,
	"ff0", FF0, FFDLY,
	"ff1", FF1, FFDLY,
	"vt0", VT0, VTDLY,
	"vt1", VT1, VTDLY,
	"bs0", BS0, BSDLY,
	"bs1", BS1, BSDLY,
	"raw", 0, OPOST,
	"-raw", OPOST, 0,
	"cooked", OPOST, 0,
	"tty33", CR1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"tn300", CR1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"ti700", CR2, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"vt05", NL1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"tek", FF1, (CRDLY|TABDLY|NLDLY|FFDLY|VTDLY|BSDLY),
	"tty37", (FF1|VT1|CR2|TAB1|NL1), (NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY),
	"sane", (OPOST|ONLCR), (OLCUC|OCRNL|ONOCR|ONLRET|OFILL|OFDEL|
			NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY),
	0,
};

const struct mds hmodes[] = {
	"-rtsxoff", 0, RTSXOFF,
	"rtsxoff", RTSXOFF, 0,
	"-ctsxon", 0, CTSXON,
	"ctsxon", CTSXON, 0,
	"-dtrxoff", 0, DTRXOFF,
	"dtrxoff", DTRXOFF, 0,
	"-cdxon", 0, CDXON,
	"cdxon", CDXON, 0,
	"-isxoff", 0, ISXOFF,
	"isxoff", ISXOFF, 0,
	0,
};

const struct mds clkmodes[] = {
	"xcibrg", XCIBRG, XMTCLK,
	"xctset", XCTSET, XMTCLK,
	"xcrset", XCRSET, XMTCLK,
	"rcibrg", RCIBRG, RCVCLK,
	"rctset", RCTSET, RCVCLK,
	"rcrset", RCRSET, RCVCLK,
	"tsetcoff", TSETCOFF, TSETCLK,
	"tsetcrbrg", TSETCRBRG, TSETCLK,
	"tsetctbrg", TSETCTBRG, TSETCLK,
	"tsetctset", TSETCTSET, TSETCLK,
	"tsetcrset", TSETCRSET, TSETCLK,
	"rsetcoff", RSETCOFF, RSETCLK,
	"rsetcrbrg", RSETCRBRG, RSETCLK,
	"rsetctbrg", RSETCTBRG, RSETCLK,
	"rsetctset", RSETCTSET, RSETCLK,
	"rsetcrset", RSETCRSET, RSETCLK,
	"async", XCIBRG|RCIBRG|TSETCOFF|RSETCOFF, XMTCLK|RCVCLK|TSETCLK|RSETCLK,
	0,
};

const char *not_supported[] =  {
	"rtsxoff",
	"ctsxon",
	"dtrxoff",
	"cdxon",
	"isxoff",
	"xcibrg",
	"xctset",
	"scrset",
	"rcibrg",
	"rctset",
	"rcrset",
	"tsetcoff",
	"tsetcrbrg",
	"rsetcbrg",
	"rsetctbrg",
	"rsetctset",
	"rsetcrset",
	0,
};
