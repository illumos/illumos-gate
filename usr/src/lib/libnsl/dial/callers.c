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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include "uucp.h"

static void alarmtr(int);
static jmp_buf Sjbuf;
static char *fdig(char *);
#ifndef SMALL
static char *strecpy(char *, char *, char *);
#endif
static int interface(const char *);
static int fd_mklock(int);
static int getdialline(char *, int);
static int chat(int, char *[], int, char *, char *);
static void fixline(), fd_rmlock();
static void translate(char *, char *);
static int gdial(char *, char *[], int);
static int	Modemctrl;
static unsigned connecttime;
static int (*Setup)();

/*
 *	to add a new caller:
 *	declare the function that knows how to call on the device,
 *	add a line to the callers table giving the name of the device
 *	(from Devices file) and the name of the function
 *	add the function to the end of this file
 */

#ifdef TLI
static int	tlicall(char *[], char *[]);
#endif /* TLI */

static struct caller Caller[] = {

#ifdef TLI
	{"TLI",		tlicall},	/* AT&T Transport Layer Interface */
#ifdef TLIS
	{"TLIS",	tlicall},	/* AT&T Transport Layer Interface */
#endif /*  TLIS  */
#endif /* TLI */

	{NULL,		NULL}		/* this line must be last */
};

/*
 *	exphone - expand phone number for given prefix and number
 *
 *	return code - none
 */

static void
exphone(char *in, char *out)
{
	FILE *fn;
	char pre[MAXPH], npart[MAXPH], tpre[MAXPH], p[MAXPH];
	char buf[BUFSIZ];
	char *s1;

	if (!isalpha(*in)) {
		(void) strcpy(out, in);
		return;
	}

	s1 = pre;
	while (isalpha(*in))
		*s1++ = *in++;
	*s1 = NULLCHAR;
	s1 = npart;
	while (*in != NULLCHAR)
		*s1++ = *in++;
	*s1 = NULLCHAR;

	tpre[0] = NULLCHAR;
	fn = fopen(DIALCODES, "rF");
	if (fn != NULL) {
		while (fgets(buf, BUFSIZ, fn)) {
			if (sscanf(buf, "%60s%60s", p, tpre) < 1)
				continue;
			if (EQUALS(p, pre))
				break;
			tpre[0] = NULLCHAR;
		}
		(void) fclose(fn);
	}

	(void) strcpy(out, tpre);
	(void) strcat(out, npart);
}

/*
 * repphone - Replace \D and \T sequences in arg with phone
 * expanding and translating as appropriate.
 */
static char *
repphone(char *arg, char *phone, char *trstr)
{
	static char *pbuf;	/* dynamically allocated below */
	char *fp, *tp;

	if (pbuf == NULL) {
		pbuf = malloc(2*(MAXPH+2));
		if (pbuf == NULL)
			return (arg);
	}
	for (tp = pbuf; *arg; arg++) {
		if (*arg != '\\') {
			*tp++ = *arg;
			continue;
		} else {
			switch (*(arg+1)) {
			case 'T':
				exphone(phone, tp);
				translate(trstr, tp);
				for (; *tp; tp++)
					;
				arg++;
				break;
			case 'D':
				for (fp = phone; *tp = *fp++; tp++)
					;
				arg++;
				break;
			default:
				*tp++ = *arg;
				break;
			}
		}
	}
	*tp = '\0';
	return (pbuf);
}

static uint_t saved_mode;
static char saved_dcname[20];

/*
 * processdev - Process a line from the Devices file
 *
 * return codes:
 *	file descriptor  -  succeeded
 *	FAIL  -  failed
 */
static int
processdev(char *flds[], char *dev[])
{
	int dcf = -1;
	struct caller	*ca;
	char *args[D_MAX+1], dcname[20];
	char **sdev;
	static int pop_push(int);
	static void setdevcfg(char *, char *);
	int nullfd;
	char *phonecl;			/* clear phone string */
	char phoneex[2*(MAXPH+2)];	/* expanded phone string */
	static void ttygenbrk(int);
	struct termio tty_orig;
	int ret_orig = -1;

	sdev = dev;
	/*	set up default "break" routine	*/
	genbrk = ttygenbrk;

	/*	initialize Devconfig info	*/
	DEBUG(5, "processdev: calling setdevcfg(%s, ", Progname);
	DEBUG(5, "%s)\n", flds[F_TYPE]);
	setdevcfg(Progname, flds[F_TYPE]);

	for (ca = Caller; ca->CA_type != NULL; ca++) {
		/* This will find built-in caller functions */
		if (EQUALS(ca->CA_type, dev[D_CALLER])) {
			DEBUG(5, "Internal caller type %s\n", dev[D_CALLER]);
			if (dev[D_ARG] == NULL) {
				/* if NULL - assume translate */
				/* needed for for loop later to mark the end */
				dev[D_ARG+1] = NULL;
				dev[D_ARG] = "\\T";
			}
			dev[D_ARG] = repphone(dev[D_ARG], flds[F_PHONE], "");
			if ((dcf = (*(ca->CA_caller))(flds, dev)) < 0)
				return (dcf);
			if (interface(ca->CA_type)) {
				DEBUG(5, "interface(%s) failed", ca->CA_type);
				Uerror = SS_DEVICE_FAILED;
				/*	restore vanilla unix interface	*/
				(void) interface("UNIX");
				return (FAIL);
			}
			dev += 2; /* Skip to next CALLER and ARG */
			break;
		}
	}
	if (dcf == -1) {
		/* Here if not a built-in caller function */

		/* We do locking (file and advisory) after open	*/

		/*
		 * Open the line
		 */
		if (*dev[D_LINE] != '/') {
			(void) snprintf(dcname, sizeof (dcname),
							"/dev/%s", dev[D_LINE]);
		} else {
			(void) strcpy(dcname, dev[D_LINE]);
		}
		/* take care of the possible partial open fd */
		(void) close(nullfd = open("/", O_RDONLY));
		if (setjmp(Sjbuf)) {
			(void) close(nullfd);
			DEBUG(1, "generic open timeout\n%s", "");
			logent("generic open", "TIMEOUT");
			Uerror = SS_CANT_ACCESS_DEVICE;
			goto bad;
		}
		(void) signal(SIGALRM, alarmtr);
		(void) alarm(10);
		if (Modemctrl) {
			DEBUG(7, "opening with O_NDELAY set\n%s", "");
			dcf = open(dcname, (O_RDWR | O_NDELAY));
			saved_mode = O_RDWR | O_NDELAY;
		} else {
			dcf = open(dcname, O_RDWR);
			saved_mode = O_RDWR;
		}
		(void) strcpy(saved_dcname, dcname);
		(void) alarm(0);
		if (dcf < 0) {
			DEBUG(1, "generic open failed, errno = %d\n", errno);
			(void) close(nullfd);
			logent("generic open", "FAILED");
			Uerror = SS_CANT_ACCESS_DEVICE;
			goto bad;
		}

		/* check locks BEFORE modifying the stream */

		if (fd_mklock(dcf) != SUCCESS) {
			DEBUG(1, "failed to lock device %s\n", dcname);
			Uerror = SS_LOCKED_DEVICE;
			goto bad;
		}

		if (Modemctrl) {
			DEBUG(7, "clear O_NDELAY\n%s", "");
			if (fcntl(dcf, F_SETFL,
			    (fcntl(dcf, F_GETFL, 0) & ~O_NDELAY)) < 0) {
				DEBUG(7, "clear O_NDELAY failed, errno %d\n",
								errno);
				Uerror = SS_DEVICE_FAILED;
				goto bad;
			}
		}
	}

	if ((*Setup)(MASTER, &dcf, &dcf)) {
		/*	any device|system lock files we should remove?	*/
		DEBUG(5, "MASTER Setup failed%s", "");
		Uerror = SS_DEVICE_FAILED;
		goto bad;
	}

	/* configure any requested streams modules */
	if (!pop_push(dcf)) {
		DEBUG(5, "STREAMS module configuration failed%s\n", "");
		Uerror = SS_DEVICE_FAILED;
		goto bad;
	}

	/* save initial state of line in case script fails */
	ret_orig = ioctl(dcf, TCGETA, &tty_orig);

	/* use sdev[] since dev[] is incremented for internal callers */
	fixline(dcf, atoi(fdig(sdev[D_CLASS])), D_DIRECT);

	/*
	 * Now loop through the remaining callers and chat
	 * according to scripts in dialers file.
	 */
	for (; dev[D_CALLER] != NULL; dev += 2) {
		int w;
		/*
		 * Scan Dialers file to find an entry
		 */
		if ((w = gdial(dev[D_CALLER], args, D_MAX)) < 1) {
			logent("generic call to gdial", "FAILED");
			Uerror = SS_CANT_ACCESS_DEVICE;
			goto bad;
		}
		if (w <= 2)	/* do nothing - no chat */
			break;
		/*
		 * Translate the phone number
		 */
		if (dev[D_ARG] == NULL) {
			/* if NULL - assume no translation */
			/* needed for for loop to mark the end */
			dev[D_ARG+1] = NULL;
			dev[D_ARG] = "\\D";
		}

		phonecl = repphone(dev[D_ARG], flds[F_PHONE], args[1]);
		exphone(phonecl, phoneex);
		translate(args[1], phoneex);
		/*
		 * Chat
		 */
		if (chat(w-2, &args[2], dcf, phonecl, phoneex) != SUCCESS) {
			CDEBUG(5, "\nCHAT gdial(%s) FAILED\n", dev[D_CALLER]);
			Uerror = SS_CHAT_FAILED;
			goto bad;
		}
	}
	/*
	 * Success at last!
	 */
	(void) strcpy(Dc, sdev[D_LINE]);
	return (dcf);
bad:
	if (dcf >= 0) {
		/* reset line settings if we got them in the beginning */
		if (ret_orig == 0)
			(void) ioctl(dcf, TCSETAW, &tty_orig);
		fd_rmlock(dcf);
		(void) close(dcf);
	}
	/*	restore vanilla unix interface	*/
	(void) interface("UNIX");
	return (FAIL);
}

/*
 * clear_hup()	clear the hangup state of the given device
 */
static int
clear_hup(int dcf)
{
	int ndcf;
	if ((ndcf = open(saved_dcname, saved_mode)) < 0) {
		return (FAIL);
	}
	if (ndcf != dcf) {
		(void) close(ndcf);
	}
	return (SUCCESS);
}


/*
 * translate the pairs of characters present in the first
 * string whenever the first of the pair appears in the second
 * string.
 */
static void
translate(char *ttab, char *str)
{
	char *s;

	for (; *ttab && *(ttab+1); ttab += 2)
		for (s = str; *s; s++)
			if (*ttab == *s)
				*s = *(ttab+1);
}

#define	MAXLINE	512
/*
 * Get the information about the dialer.
 * gdial(type, arps, narps)
 *	type	-> type of dialer (e.g., penril)
 *	arps	-> array of pointers returned by gdial
 *	narps	-> number of elements in array returned by gdial
 * Return value:
 *	-1	-> Can't open DIALERFILE
 *	0	-> requested type not found
 *	>0	-> success - number of fields filled in
 */
static int
gdial(char *type, char *arps[], int narps)
{
	static char *info;	/* dynamically allocated MAXLINE */
	int na;
	static void dialreset(void);
#ifndef SMALL
	static char *currdial(void);
#endif

	DEBUG(2, "gdial(%s) called\n", type);
	if (info == NULL) {
		info = malloc(MAXLINE);
		if (info == NULL) {
			DEBUG(1, "malloc failed for info in gdial\n", 0);
			return (0);
		}
	}
	while (getdialline(info, MAXLINE)) {
		if ((info[0] == '#') || (info[0] == ' ') ||
		    (info[0] == '\t') || (info[0] == '\n'))
			continue;
		if ((na = getargs(info, arps, narps)) == 0)
			continue;
		if (EQUALS(arps[0], type)) {
		    DEBUG(5, "Trying caller script '%s'", type);
		    DEBUG(5, " from '%s'.\n", currdial());
		    dialreset();
		    bsfix(arps);
		    return (na);
		}
	}
	DEBUG(1, "%s not found in Dialers file\n", type);
	dialreset();
	return (0);
}

#ifdef TLI
/*
 *
 * AT&T Transport Layer Interface
 *
 * expected in Devices
 *	TLI line1 - - TLI
 * or
 *	TLIS line1 - - TLIS
 *
 */

#include <tiuser.h>

static void tfaillog(int fd, const char *s);

#define	CONNECT_ATTEMPTS	3
#define	TFREE(p, type)	if ((p)) (void) t_free((char *)(p), (type))

/*
 * returns fd to remote uucp daemon
 */
/*ARGSUSED*/
static int
tlicall(char *flds[], char *dev[])
{
	char		addrbuf[ BUFSIZ ];
	char		devname[MAXNAMESIZE];
	int		fd;
	int		i, j;
	struct t_bind	*bind_ret = 0;
	struct t_info	tinfo;
	struct t_call	*sndcall = 0, *rcvcall = 0;

	static struct netbuf	*stoa(char *, struct netbuf *);

	if (dev[D_LINE][0] != '/') {
		/*	dev holds device name relative to /dev	*/
		(void) snprintf(devname, sizeof (devname),
							"/dev/%s", dev[D_LINE]);
	} else {
		/*	dev holds full path name of device	*/
		(void) strcpy(devname, dev[D_LINE]);
	}
	/* gimme local transport endpoint */
	errno = t_errno = 0;
	if (setjmp(Sjbuf)) {
		DEBUG(1, "t_open timeout\n%s", "");
		logent("t_open", "TIMEOUT");
		Uerror = SS_NO_DEVICE;
		return (FAIL);
	}
	(void) signal(SIGALRM, alarmtr);
	(void) alarm(5);
	fd = t_open(devname, O_RDWR, &tinfo);
	(void) alarm(0);
	if (fd < 0) {
		tfaillog(fd, "t_open");
		Uerror = SS_NO_DEVICE;
		return (FAIL);
	}
	if (fd_mklock(fd) != SUCCESS) {
		(void) t_close(fd);
		DEBUG(1, "tlicall: failed to lock device %s\n", devname);
		Uerror = SS_LOCKED_DEVICE;
		return (FAIL);
	}

	/* allocate tli structures	*/
	errno = t_errno = 0;
	/* LINTED pointer cast */
	if ((bind_ret = (struct t_bind *)t_alloc(fd, T_BIND, T_ALL)) == NULL ||
	    /* LINTED pointer cast */
	    (sndcall = (struct t_call *)t_alloc(fd, T_CALL, T_ALL)) == NULL ||
	    /* LINTED pointer cast */
	    (rcvcall = (struct t_call *)t_alloc(fd, T_CALL, T_ALL)) == NULL) {
		tfaillog(fd, "t_alloc");
		TFREE(bind_ret, T_BIND);
		TFREE(sndcall, T_CALL);
		TFREE(rcvcall, T_CALL);
		Uerror = SS_NO_DEVICE;
		return (FAIL);
	}

	/* bind */
	errno = t_errno = 0;
	if (t_bind(fd, (struct t_bind *)0, bind_ret) < 0) {
		tfaillog(fd, "t_bind");
		TFREE(bind_ret, T_BIND);
		TFREE(sndcall, T_CALL);
		TFREE(rcvcall, T_CALL);
		Uerror = SS_NO_DEVICE;
		fd_rmlock(fd);
		(void) t_close(fd);
		return (FAIL);
	}
	DEBUG(5, "tlicall: bound to %s\n", bind_ret->addr.buf);

	/*
	 * Prepare to connect.
	 *
	 * If address begins with "\x", "\X", "\o", or "\O",
	 * assume is hexadecimal or octal address and use stoa()
	 * to convert it.
	 *
	 * Else is usual uucico address -- only \N's left to process.
	 * Walk thru connection address, changing \N's to NULLCHARs.
	 * Note:  If a NULLCHAR must be part of the connection address,
	 * it must be overtly included in the address.  One recommended
	 * way is to do it in the Devices file, thusly:
	 *		Netname /dev/netport - - TLI \D\000
	 * bsfix() turns \000 into \N and then the loop below makes it a
	 * real, included-in-the-length null-byte.
	 *
	 * The DEBUG must print the strecpy'd address (so that
	 * non-printables will have been replaced with C escapes).
	 */

	DEBUG(5, "t_connect to addr \"%s\"\n",
		strecpy(addrbuf, dev[D_ARG], "\\"));

	if (dev[D_ARG][0] == '\\' && (dev[D_ARG][1] == 'x' ||
			dev[D_ARG][1] == 'X' || dev[D_ARG][1] == 'o' ||
			dev[D_ARG][1] == 'O')) {
		if (stoa(dev[D_ARG], &(sndcall->addr)) == NULL) {
			DEBUG(5, "tlicall: stoa failed\n%s", "");
			logent("tlicall", "string-to-address failed");
			TFREE(bind_ret, T_BIND);
			TFREE(sndcall, T_CALL);
			TFREE(rcvcall, T_CALL);
			Uerror = SS_NO_DEVICE;
			fd_rmlock(fd);
			(void) t_close(fd);
			return (FAIL);
		}
	} else {
		for (i = j = 0; i < BUFSIZ && dev[D_ARG][i] != NULLCHAR;
								++i, ++j) {
			if (dev[D_ARG][i] == '\\' && dev[D_ARG][i+1] == 'N') {
				addrbuf[j] = NULLCHAR;
				++i;
			} else {
				addrbuf[j] = dev[D_ARG][i];
			}
		}
		sndcall->addr.buf = addrbuf;
		sndcall->addr.len = j;
	}

	if (setjmp(Sjbuf)) {
		DEBUG(4, "timeout tlicall\n%s", "");
		logent("tlicall", "TIMEOUT");
		TFREE(bind_ret, T_BIND);
		TFREE(sndcall, T_CALL);
		TFREE(rcvcall, T_CALL);
		Uerror = SS_NO_DEVICE;
		fd_rmlock(fd);
		(void) t_close(fd);
		return (FAIL);
	}
	(void) signal(SIGALRM, alarmtr);
	(void) alarm(connecttime);

	/* connect to the service -- some listeners can't handle */
	/* multiple connect requests, so try it a few times */
	errno = t_errno = 0;
	for (i = 0; i < CONNECT_ATTEMPTS; ++i) {
		if (t_connect(fd, sndcall, rcvcall) == 0)
			break;
		if ((t_errno == TLOOK) && (t_look(fd) == T_DISCONNECT)) {
			(void) t_rcvdis(fd, NULL);
			(void) alarm(0);
		} else {
			(void) alarm(0);
			tfaillog(fd, "t_connect");
			TFREE(bind_ret, T_BIND);
			TFREE(sndcall, T_CALL);
			TFREE(rcvcall, T_CALL);
			Uerror = SS_DIAL_FAILED;
			fd_rmlock(fd);
			(void) t_close(fd);
			return (FAIL);
		}
	}
	(void) alarm(0);
	TFREE(bind_ret, T_BIND);
	TFREE(sndcall, T_CALL);
	TFREE(rcvcall, T_CALL);
	if (i == CONNECT_ATTEMPTS) {
		tfaillog(fd, "t_connect");
		Uerror = SS_DIAL_FAILED;
		fd_rmlock(fd);
		(void) t_close(fd);
		return (FAIL);
	}
	errno = t_errno = 0;
	(void) strcpy(Dc, dev[D_CALLER]);
	return (fd);
}
#endif /* TLI */
