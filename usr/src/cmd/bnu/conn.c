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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "uucp.h"

GLOBAL char _Protocol[40] = "";	/* working protocol string */
static char _ProtoSys[40] = "";	/* protocol string from Systems file entry */
static char _ProtoDev[40] = "";	/* protocol string from Devices file entry */
EXTERN char _ProtoCfg[];	/* protocol string from Config  file entry */

EXTERN jmp_buf Sjbuf;
EXTERN unsigned expecttime;

GLOBAL int	Modemctrl;

/* Parity control during login procedure */
#define	P_ZERO	0
#define	P_ONE	1
#define	P_EVEN	2
#define	P_ODD	3

static char	par_tab[128];

EXTERN void alarmtr();
static void addProto(), mergeProto(), removeProto();
static void bld_partab();
static char *nextProto();
EXTERN char *findProto();
static void getProto();
EXTERN int getto();		/* make this static when ct uses altconn() */
EXTERN int chat(), rddev(), expect(), wrstr(), wrchr();
EXTERN int processdev(), getdevline(), getsysline(), sysaccess();
EXTERN int clear_hup();
EXTERN char *currsys(), *currdev();
static int finds();
static int wait_for_hangup(), expect_str();

EXTERN void sendthem(), nap();
static int notin(), ifdate(), checkdate(), checktime(), classmatch();

GLOBAL char *Myline = CNULL;	/* to force which line will be used */
GLOBAL char *Mytype = CNULL;	/* to force selection of specific device type */
EXTERN int Dologin;		/* to force login chat sequence */

/*
 * conn - place a telephone call to system and login, etc.
 *
 * return codes:
 *	FAIL - connection failed
 *	>0  - file no.  -  connect ok
 * When a failure occurs, Uerror is set.
 */

GLOBAL int
conn(system)
char *system;
{
	int nf, fn;
	char *flds[F_MAX+1];
	EXTERN void sysreset();

	CDEBUG(4, "conn(%s)\n", system);
	Uerror = 0;
	while ((nf = finds(system, flds, F_MAX)) > 0) {
		fn = getto(flds);
		CDEBUG(4, "getto ret %d\n", fn);
		if (fn < 0)
		    continue;

#ifdef TIOCSPGRP
		{
#ifdef ATTSV
		int pgrp = getpgrp();
#else
		int pgrp = getpgrp(0);
#endif
		ioctl(fn, TIOCSPGRP, &pgrp);
		}
#endif
		if (Dologin || EQUALS(Progname, "uucico")) {
		    if (chat(nf - F_LOGIN, flds + F_LOGIN, fn,"","") == SUCCESS) {
			sysreset();
			return(fn); /* successful return */
		    }

		    /* login failed */
		    DEBUG(6, "close caller (%d)\n", fn);
		    fd_rmlock(fn);
		    close(fn);
		    if (Dc[0] != NULLCHAR) {
			DEBUG(6, "delock line (%s)\n", Dc);
		    }
		} else {
		    sysreset();
		    return(fn);
		}
	}

	/* finds or getto failed */
	sysreset();
	CDEBUG(1, "Call Failed: %s\n", UERRORTEXT);
	return(FAIL);
}

/*
 * getto - connect to remote machine
 *
 * return codes:
 *	>0  -  file number - ok
 *	FAIL  -  failed
 */

GLOBAL int
getto(flds)
char *flds[];
{
	char *dev[D_MAX+2], devbuf[BUFSIZ];
	int status;
	int dcf = -1;
	int reread = 0;
	int tries = 0;	/* count of call attempts - for limit purposes */
	EXTERN void devreset();

	CDEBUG(1, "Device Type %s wanted\n", flds[F_TYPE]);
	Uerror = 0;
	while (tries < TRYCALLS) {
		if ((status=rddev(flds[F_TYPE], dev, devbuf, D_MAX)) == FAIL) {
			if (tries == 0 || ++reread >= TRYCALLS)
				break;
			devreset();
			continue;
		}
		/* check class, check (and possibly set) speed */
		if (classmatch(flds, dev) != SUCCESS) {
		    DEBUG(7, "Skipping entry in '%s'", currdev());
		    DEBUG(7, " - class (%s) not wanted.\n", dev[D_CLASS]);
		    continue;
		}
                DEBUG(5, "Trying device entry '%s' ", dev[D_LINE]);
		DEBUG(5, "from '%s'.\n", currdev());
		if ((dcf = processdev(flds, dev)) >= 0)
			break;

		switch(Uerror) {
		case SS_CANT_ACCESS_DEVICE:
		case SS_DEVICE_FAILED:
		case SS_LOCKED_DEVICE:
		case SS_CHAT_FAILED:
			break;
		default:
			tries++;
			break;
		}
	}
	devreset();	/* reset devices file(s) */
	if (status == FAIL && !Uerror) {
	    CDEBUG(1, "Requested Device Type Not Found\n%s", "");
	    Uerror = SS_NO_DEVICE;
	}
	return(dcf);
}

/*
 * classmatch - process 'Any' in Devices and Systems and
 * 	determine the correct speed, or match for ==
 */

static int
classmatch(flds, dev)
char *flds[], *dev[];
{
	/* check class, check (and possibly set) speed */
	if (EQUALS(flds[F_CLASS], "Any")
	   && EQUALS(dev[D_CLASS], "Any")) {
		dev[D_CLASS] = DEFAULT_BAUDRATE;
		return(SUCCESS);
	} else if (EQUALS(dev[D_CLASS], "Any")) {
		dev[D_CLASS] = flds[F_CLASS];
		return(SUCCESS);
	} else if (EQUALS(flds[F_CLASS], "Any") ||
	EQUALS(flds[F_CLASS], dev[D_CLASS]))
		return(SUCCESS);
	else
		return(FAIL);
}


/*
 *	rddev - find and unpack a line from device file for this caller type
 *	lines starting with whitespace of '#' are comments
 *
 *	return codes:
 *		>0  -  number of arguments in vector - succeeded
 *		FAIL - EOF
 */

GLOBAL int
rddev(char *type, char *dev[], char *buf, int devcount)
{
	char *commap, d_type[BUFSIZ];
	int na;

	while (getdevline(buf, BUFSIZ)) {
		if (buf[0] == ' ' || buf[0] == '\t'
		    ||  buf[0] == '\n' || buf[0] == '\0' || buf[0] == '#')
			continue;
		na = getargs(buf, dev, devcount);
		ASSERT(na >= D_CALLER, "BAD LINE", buf, na);

		if ( strncmp(dev[D_LINE],"/dev/",5) == 0 ) {
			/* since cu (altconn()) strips off leading */
			/* "/dev/",  do the same here.  */
			strcpy(dev[D_LINE], &(dev[D_LINE][5]) );
		}

		/* may have ",M" subfield in D_LINE */
		Modemctrl = FALSE;
		if ( (commap = strchr(dev[D_LINE], ',')) != (char *)NULL ) {
			if ( strcmp( commap, ",M") == SAME )
				Modemctrl = TRUE;
			*commap = '\0';
		}

		/*
		 * D_TYPE field may have protocol subfield, which
		 * must be pulled off before comparing to desired type.
		 */
		(void)strcpy(d_type, dev[D_TYPE]);
		if ((commap = strchr(d_type, ',')) != (char *)NULL )
			*commap = '\0';

		/* to force the requested device type to be used. */
		if ((Mytype != NULL) && (!EQUALS(Mytype, d_type)) )
		    continue;
		/* to force the requested line to be used */
		if ((Myline != NULL) && (!EQUALS(Myline, dev[D_LINE])) )
		    continue;

		bsfix(dev);	/* replace \X fields */

		if (EQUALS(d_type, type)) {
			getProto( _ProtoDev, dev[D_TYPE] );
			return(na);
		}
	}
	return(FAIL);
}


/*
 * finds	- set system attribute vector
 *
 * input:
 *	fsys - open Systems file descriptor
 *	sysnam - system name to find
 * output:
 *	flds - attibute vector from Systems file
 *	fldcount - number of fields in flds
 * return codes:
 *	>0  -  number of arguments in vector - succeeded
 *	FAIL - failed
 * Uerror set:
 *	0 - found a line in Systems file
 *	SS_BADSYSTEM - no line found in Systems file
 *	SS_TIME_WRONG - wrong time to call
 */

static int
finds(char *sysnam, char *flds[], int fldcount)
{
	static char info[BUFSIZ];
	int na;

	/* format of fields
	 *	0 name;
	 *	1 time
	 *	2 acu/hardwired
	 *	3 speed
	 *	etc
	 */
	if (sysnam == 0 || *sysnam == 0 ) {
		Uerror = SS_BADSYSTEM;
		return(FAIL);
	}

	while (getsysline(info, sizeof(info))) {
		na = getargs(info, flds, fldcount);
		bsfix(flds);	/* replace \X fields */
		if ( !EQUALSN(sysnam, flds[F_NAME], MAXBASENAME))
			continue;
		/* check if requested Mytype device type */
		if ((Mytype != CNULL) &&
		    (na <= F_TYPE ||
			!EQUALSN(flds[F_TYPE], Mytype, strlen(Mytype)))) {
		    DEBUG(7, "Skipping entry in '%s'", currsys());
		    DEBUG(7, " - type (%s) not wanted.\n", na > F_TYPE ?
			flds[F_TYPE] : "Missing type entry");
		    continue;
		} else {
		    DEBUG(5, "Trying entry from '%s'", currsys());
		    DEBUG(5, " - device type %s.\n", na > F_TYPE ?
			flds[F_TYPE] : "<Missing type entry>");
		}
		/* OK if not uucico (ie. ct or cu) or the time is right */
		if (!EQUALS(Progname, "uucico") ||
		    (na > F_TIME && ifdate(flds[F_TIME]))) {
			/*  found a good entry  */
			if (na > F_TYPE) {
				getProto(_ProtoSys, flds[F_TYPE]);
				Uerror = 0;
				return(na);	/* FOUND OK LINE */
			}
			DEBUG(5, "Trying entry from '%s'", currsys());
			DEBUG(5, " - Missing type entry for <%s>.\n",
				flds[F_NAME]);
		} else {
			CDEBUG(1, "Wrong Time To Call: %s\n", na > F_TIME ?
			    flds[F_TIME] : "<Missing time entry>");
			if (!Uerror)
				Uerror = SS_TIME_WRONG;
		}
	}
	if (!Uerror)
		Uerror = SS_BADSYSTEM;
	return(FAIL);
}

/*
 * getProto - get the protocol letters from the input string.
 * input:
 *	str - string from Systems/Devices/Config file,
 *		a ',' delimits the protocol string
 *		e.g. ACU,g or DK,d
 * output:
 *	str - the , (if present) will be replaced with NULLCHAR
 *
 * return:  none
 */

static void
getProto(save, str)
char *save;
char *str;
{
	char *p;

	*save = NULLCHAR;
	if ( (p=strchr(str, ',')) != NULL) {
		*p = NULLCHAR;
		(void) strcpy(save, p+1);
		DEBUG(7, "Protocol = %s\n", save);
	}
	return;
}

/*
 * check for a specified protocol selection string
 * return:
 *	protocol string pointer
 *	NULL if none specified for LOGNAME
 */
GLOBAL char *
protoString(valid)
char *valid;
{
	char *save;

	save =strdup(valid);
	_Protocol[0] = '\0';

	if ( _ProtoSys[0] != '\0' )
	    addProto(_ProtoSys, valid);
	if ( _ProtoDev[0] != '\0' )
	    addProto(_ProtoDev, valid);
	if ( _ProtoCfg[0] != '\0' )
	    addProto(_ProtoCfg, valid);

	if ( _Protocol[0] == '\0' ) {
	    (void) strcpy(valid, save);
	    (void) strcpy(_Protocol, save);
	}

	return(_Protocol[0] == NULLCHAR ? NULL : _Protocol);
}

/*
 * addProto
 *
 * Verify that the desired protocols from the Systems and Devices file
 * have been compiled into this application.
 *
 * 	desired -	list of desired protocols
 *	valid -		list of protocols that are compiled in.
 */

static void
addProto (desired, valid)
char *desired;
char *valid;
{
	char *protoPtr;
	char *wantPtr;

	if ( *desired == '\0' )
	    return;

	if ( *(protoPtr = _Protocol) != NULLCHAR ) {
	    while ( *(protoPtr = nextProto(protoPtr)) != NULLCHAR ) {
		if ( *(wantPtr = findProto(desired, *protoPtr)) == NULLCHAR ) {
		    removeProto(valid, *protoPtr);
		    removeProto(protoPtr, *protoPtr);
		} else {
		    mergeProto(protoPtr, wantPtr);
		    protoPtr++;
		}
	    }
	} else {
	    wantPtr = desired;
	    while ( *(wantPtr = nextProto(wantPtr)) != NULLCHAR ) {
		if ( *(findProto(valid, *wantPtr)) != NULLCHAR ) {
		    mergeProto(protoPtr, wantPtr);
		}
		wantPtr++;
	    }
	}
	if ( *(protoPtr = _Protocol) != NULLCHAR ) {
	    while ( *(protoPtr = nextProto(protoPtr)) != NULLCHAR )
		*(valid++) = *(protoPtr++);
	    *valid = NULLCHAR;
	}
	return;
}

/*
 * mergeProto
 *
 * input
 * 	char *tostring, *fromstring;
 */
static void
mergeProto(tostring, fromstring)
char *tostring, *fromstring;
{
	char buffer[BUFSIZ];
	int length;

	while ( *(tostring = nextProto(tostring)) != NULLCHAR ) {
	    if ( *tostring == *fromstring )
		break;
	    else
		tostring++;
	}

	if ( *tostring == NULLCHAR ) {
	    length = nextProto(fromstring + 1) - fromstring;
	    (void) strncpy(tostring, fromstring, length);
	    *(tostring + length) = NULLCHAR;
	} else {
	    tostring++;
	    fromstring++;
	    if ( (*tostring !=  '(') && (*fromstring == '(') ) {
		(void) strcpy(buffer, tostring);
		length = nextProto(fromstring) - fromstring;
	        (void) strncpy(tostring, fromstring, length);
		(void) strcpy(tostring+length, buffer);
	    }
	}
	return;
}

/*
 * removeProto
 *
 * char *old
 * char letter
 *
 * return
 *	none
 */
static void
removeProto(string, letter)
char *string, letter;
{
	while ( *(string = nextProto(string)) != NULLCHAR ) {
	    if ( *string == letter )
		(void) strcpy(string, nextProto(string+1));
	    else
		string++;
	}
}

/*
 * nextProto
 *	char *string;
 * return
 *	char * to next non-parameter letter
 */
static char *
nextProto(string)
char *string;
{
	if ( *string == '(' )
	    while ( *string != NULLCHAR )
		if ( *(string++) == ')' )
		    break;
	return(string);
}

/*
 * findProto
 *	char *desired,
 *	char protoPtr;
 * return
 *	char *pointer to found or string terminating NULLCHAR
 */
GLOBAL char *
findProto(string, letter)
char *string;
char letter;
{
	while ( *(string = nextProto(string)) != NULLCHAR )
	    if ( *string == letter )
		break;
	    else
		string++;
	return(string);
}

/*
 * chat -	do conversation
 * input:
 *	nf - number of fields in flds array
 *	flds - fields from Systems file
 *	fn - write file number
 *	phstr1 - phone number to replace \D
 *	phstr2 - phone number to replace \T
 *
 *	return codes:  0  |  FAIL
 */

GLOBAL int
chat(nf, flds, fn, phstr1, phstr2)
char *flds[], *phstr1, *phstr2;
int nf, fn;
{
	char *want, *altern;
	int k, ok;

	for (k = 0; k < nf; k += 2) {
		want = flds[k];
		ok = FAIL;
		while (ok != 0) {
			altern = index(want, '-');
			if (altern != NULL)
				*altern++ = NULLCHAR;
			ok = expect(want, fn);
			if (ok == 0)
				break;
			if (altern == NULL) {
				Uerror = SS_LOGIN_FAILED;
				logent(UERRORTEXT, "FAILED");
				return(FAIL);
			}
			want = index(altern, '-');
			if (want != NULL)
				*want++ = NULLCHAR;
			sendthem(altern, fn, phstr1, phstr2);
		}
		sleep(2);
		if (flds[k+1])
		    sendthem(flds[k+1], fn, phstr1, phstr2);
	}
	return(0);
}

#define MR 1000

/*
 *	expect(str, fn)	look for expected string w/ possible special chars
 *
 *	return codes:
 *		0  -  found
 *		FAIL  -  too many characters read
 *		some character  -  timed out
 */

GLOBAL int
expect(str, fn)
char *str;
int fn;
{
	char *bptr, *sptr;
	char    buf[BUFSIZ];

	bptr = buf;

	for (sptr = str; *sptr; sptr++) {
		if (*sptr == '\\') {
			switch (*++sptr) {
			case 'H':
				*bptr++ = '\0';
				if (expect_str(buf, fn) == FAIL) {
					return (FAIL);
				}
				if (wait_for_hangup(fn) == FAIL) {
					return (FAIL);
				}
				bptr = buf;
				continue;
			case '\\':
				*bptr++ = '\\';
				continue;
			default:
				*bptr++ = '\\';
				*bptr++ = *sptr;
				continue;
			}
		} else
			*bptr++ = *sptr;
	}
	*bptr = '\0';
	if (expect_str(buf, fn) == FAIL) {
		return (FAIL);
	}
	return (0);
}

/*
 *	expect_str(str, fn)	look for expected string, w/ no special chars
 *
 *	return codes:
 *		0  -  found
 *		FAIL  -  too many characters read
 *		some character  -  timed out
 */

GLOBAL int
expect_str(str, fn)
char *str;
int fn;
{
	static char rdvec[MR];
	char *rp = rdvec;
	int kr, c;
	char nextch;

	*rp = 0;

	CDEBUG(4, "expect: (%s", "");
	for (c=0; (kr=str[c]) != 0 ; c++)
		if (kr < 040) {
			CDEBUG(4, "^%c", kr | 0100);
		} else
			CDEBUG(4, "%c", kr);
	CDEBUG(4, ")\n%s", "");

	if (EQUALS(str, "\"\"")) {
		CDEBUG(4, "got it\n%s", "");
		return(0);
	}
	if (*str== '\0') {
		return(0);
	}
	if (setjmp(Sjbuf)) {
		return (FAIL);
	}
	(void) signal(SIGALRM, alarmtr);
	alarm(expecttime);
	while (notin(str, rdvec)) {
		errno = 0;
		kr = (*Read)(fn, &nextch, 1);
		if (kr <= 0) {
			alarm(0);
			CDEBUG(4, "lost line errno - %d\n", errno);
			logent("LOGIN", "LOST LINE");
			return(FAIL);
		}
		c = nextch & 0177;
		CDEBUG(4, "%s", c < 040 ? "^" : "");
		CDEBUG(4, "%c", c < 040 ? c | 0100 : c);
		if ((*rp = nextch & 0177) != NULLCHAR)
			rp++;
		if (rp >= rdvec + MR) {
			CDEBUG(4, "enough already\n%s", "");
			alarm(0);
			return(FAIL);
		}
		*rp = NULLCHAR;
	}
	alarm(0);
	CDEBUG(4, "got it\n%s", "");
	return(0);
}
/*
 *	alarmtr()  -  catch alarm routine for "expect".
 */
/*ARGSUSED*/
GLOBAL void
alarmtr(sig)
int sig;
{
	CDEBUG(6, "timed out\n%s", "");
	longjmp(Sjbuf, 1);
}

/*
 *	wait_for_hangup() - wait for a hangup to occur on the given device
 */
int
wait_for_hangup(dcf)
	int dcf;
{
	int rval;
	char buff[BUFSIZ];

	CDEBUG(4, "Waiting for hangup\n%s", "");
	while((rval = read(dcf, buff, BUFSIZ)) > 0);

	if (rval < 0) {
		return (FAIL);
	}
	CDEBUG(4, "Received hangup\n%s", "");

	if (clear_hup(dcf) != SUCCESS) {
	    CDEBUG(4, "Unable to clear hup on device\n%s", "");
	    return (FAIL);
	}
	return (SUCCESS);
}

/*
 *	sendthem(str, fn, phstr1, phstr2)	send line of chat sequence
 *	char *str, *phstr;
 *
 *	return codes:  none
 */

#define FLUSH() {\
	if ((bptr - buf) > 0)\
		if (wrstr(fn, buf, bptr - buf, echocheck) != SUCCESS)\
			goto err;\
	bptr = buf;\
}

GLOBAL void
sendthem(str, fn, phstr1, phstr2)
char *str, *phstr1, *phstr2;
int fn;
{
	int sendcr = 1, echocheck = 0;
	char	*sptr, *bptr;
	char	buf[BUFSIZ];
	struct termio	ttybuf;
	static int p_init = 0;

	if (!p_init) {
		p_init++;
		bld_partab(P_EVEN);
	}

	/* should be EQUALS, but previous versions had BREAK n for integer n */
	if (PREFIX("BREAK", str)) {
		/* send break */
		CDEBUG(5, "BREAK\n%s", "");
		(*genbrk)(fn);
		return;
	}

	if (PREFIX("STTY=", str)) {
		CDEBUG(5, "STTY %s\n", str+5);
		setmode(str+5, fn);
		return;
	}

	if (EQUALS(str, "EOT")) {
		CDEBUG(5, "EOT\n%s", "");
		bptr = buf;
		for (sptr = EOTMSG; *sptr; sptr++)
			*bptr++ = par_tab[*sptr&0177];
		(void) (*Write)(fn, buf, bptr - buf);
		return;
	}

	/* Set parity as needed */
	if (EQUALS(str, "P_ZERO")) {
		bld_partab(P_ZERO);
		return;
	}
	if (EQUALS(str, "P_ONE")) {
		bld_partab(P_ONE);
		return;
	}
	if (EQUALS(str, "P_EVEN")) {
		bld_partab(P_EVEN);
		return;
	}
	if (EQUALS(str, "P_ODD")) {
		bld_partab(P_ODD);
		return;
	}

	if (EQUALS(str, "\"\"")) {
		CDEBUG(5, "\"\"\n%s", "");
		str += 2;
	}

	bptr = buf;
	CDEBUG(5, "sendthem (%s", "");
	for (sptr = str; *sptr; sptr++) {
		if (*sptr == '\\') {
			switch(*++sptr) {

			/* adjust switches */
			case 'c':	/* no CR after string */
				FLUSH();
				if (sptr[1] == NULLCHAR) {
					CDEBUG(5, "<NO CR>%s", "");
					sendcr = 0;
				} else
					CDEBUG(5, "<NO CR IGNORED>\n%s", "");
				continue;

			/* stash in buf and continue */
			case 'D':	/* raw phnum */
				strcpy(bptr, phstr1);
				bptr += strlen(bptr);
				continue;
			case 'T':	/* translated phnum */
				strcpy(bptr, phstr2);
				bptr += strlen(bptr);
				continue;
			case 'N':	/* null */
				*bptr++ = 0;
				continue;
			case 's':	/* space */
				*bptr++ = ' ';
				continue;
			case '\\':	/* backslash escapes itself */
				*bptr++ = *sptr;
				continue;
			default:	/* send the backslash */
				*bptr++ = '\\';
				*bptr++ = *sptr;
				continue;

			/* flush buf, perform action, and continue */
			case 'E':	/* echo check on */
				FLUSH();
				CDEBUG(5, "ECHO CHECK ON\n%s", "");
				echocheck = 1;
				continue;
			case 'e':	/* echo check off */
				FLUSH();
				CDEBUG(5, "ECHO CHECK OFF\n%s", "");
				echocheck = 0;
				continue;
			case 'd':	/* sleep briefly */
				FLUSH();
				CDEBUG(5, "DELAY\n%s", "");
				sleep(2);
				continue;
			case 'p':	/* pause momentarily */
				FLUSH();
				CDEBUG(5, "PAUSE\n%s", "");
				nap(HZ/4);	/* approximately 1/4 second */
				continue;
			case 'K':	/* inline break */
				FLUSH();
				CDEBUG(5, "BREAK\n%s", "");
				(*genbrk)(fn);
				continue;
			case 'M':	/* modem control - set CLOCAL */
			case 'm':	/* no modem control - clear CLOCAL */
				FLUSH();
				CDEBUG(5, ")\n%s CLOCAL ",
					(*sptr == 'M' ? "set" : "clear"));
#ifdef ATTSVTTY
				if ( (*Ioctl)(fn, TCGETA, &ttybuf) != 0  ) {
				    CDEBUG(5, "ignored. TCGETA failed, errno %d", errno);
				} else {
				    if (*sptr == 'M')
					ttybuf.c_cflag |= CLOCAL;
				    else
					ttybuf.c_cflag &= ~CLOCAL;
				    if ( (*Ioctl)(fn, TCSETAW, &ttybuf) != 0 )
					CDEBUG(5, "failed. TCSETAW failed, errno %d", errno);
				}
#endif
				CDEBUG(5, "\n%s", "");
				continue;
			}
		} else
			*bptr++ = *sptr;
	}
	if (sendcr)
		*bptr++ = '\r';
	if ( (bptr - buf) > 0 )
		(void) wrstr(fn, buf, bptr - buf, echocheck);

err:
	CDEBUG(5, ")\n%s", "");
	return;
}

/*
 * generate parity table for use by sendthem.
 */
static void
bld_partab(type)
int type;
{
	int i, j, n;

	for (i = 0; i < 128; i++) {
		n = 0;
		for (j = i&0177; j; j = (j-1)&j)
			n++;
		par_tab[i] = i;
		if (type == P_ONE
		 || (type == P_EVEN && (n&01) != 0)
		 || (type == P_ODD && (n&01) == 0))
			par_tab[i] |= 0200;
	}
}

#undef FLUSH

GLOBAL int
wrstr(int fn, char *buf, int len, int echocheck)
{
	int 	i;
	char dbuf[BUFSIZ], *dbptr = dbuf;

	if (echocheck)
		return(wrchr(fn, buf, len));

	if (Debug >= 5) {
		if (sysaccess(ACCESS_SYSTEMS) == 0) { /* Systems file access ok */
			for (i = 0; i < len; i++) {
				*dbptr = buf[i];
				if (*dbptr < 040) {
					*dbptr++ = '^';
					*dbptr = buf[i] | 0100;
				}
				dbptr++;
			}
			*dbptr = 0;
		} else
			strcpy(dbuf, "????????");
		CDEBUG(5, "%s", dbuf);
	}
	dbptr = dbuf;
	for (i = 0; i < len; i++)
		*dbptr++ = par_tab[buf[i]&0177];
	if ((*Write)(fn, dbuf, len) != len)
		return(FAIL);
	return(SUCCESS);
}

GLOBAL int
wrchr(int fn, char *buf, int len)
{
	int 	i, saccess;
	char	cin, cout;

	saccess = (sysaccess(ACCESS_SYSTEMS) == 0); /* protect Systems file */
	if (setjmp(Sjbuf))
		return(FAIL);
	(void) signal(SIGALRM, alarmtr);

	for (i = 0; i < len; i++) {
		cout = buf[i]&0177;
		if (saccess) {
			CDEBUG(5, "%s", cout < 040 ? "^" : "");
			CDEBUG(5, "%c", cout < 040 ? cout | 0100 : cout);
		} else
			CDEBUG(5, "?%s", "");
		if (((*Write)(fn, &par_tab[cout], 1)) != 1)
			return(FAIL);
		do {
			(void) alarm(expecttime);
			if ((*Read)(fn, &cin, 1) != 1)
				return(FAIL);
			(void) alarm(0);
			cin &= 0177;
			if (saccess) {
				CDEBUG(5, "%s", cin < 040 ? "^" : "");
				CDEBUG(5, "%c", cin < 040 ? cin | 0100 : cin);
			} else
				CDEBUG(5, "?%s", "");
		} while (cout != cin);
	}
	return(SUCCESS);
}


/*
 *	notin(sh, lg)	check for occurrence of substring "sh"
 *	char *sh, *lg;
 *
 *	return codes:
 *		0  -  found the string
 *		1  -  not in the string
 */

static int
notin(sh, lg)
char *sh, *lg;
{
	while (*lg != NULLCHAR) {
		if (PREFIX(sh, lg))
			return(0);
		else
			lg++;
	}
	return(1);
}


/*
 *	ifdate(s)
 *	char *s;
 *
 *	ifdate  -  this routine will check a string (s)
 *	like "MoTu0800-1730" to see if the present
 *	time is within the given limits.
 *
 *	SIDE EFFECT - Retrytime is set to number following ";"
 *	SIDE EFFECT - MaxGrade is set to character following "/"
 *
 *	if a grade is specified, iswrk() is consulted, so that we don't
 *	place calls when there's only low priority work.  this will appear
 *	as a "wrong time to call" in the status file.  sorry.
 *
 *	String alternatives:
 *		Wk - Mo thru Fr
 *		zero or one time means all day
 *		Any - any day
 *
 *	return codes:
 *		0  -  not within limits, or grade too low
 *		1  -  within limits
 */

static int
ifdate(s)
char *s;
{
	char	*r;
#ifdef MAXGRADE
	char	*m, grade;
#endif
	struct tm	*tp;
	time_t	clock;
	int	t__now;

	time(&clock);
	tp = localtime(&clock);
	t__now = tp->tm_hour * 100 + tp->tm_min;	/* "navy" time */

	/*
	 *	pick up retry time for failures and max grade
	 *	global variables Retrytime and MaxGrade are set here
	 */
	r = strrchr(s, ';');

	/* set retry time */
	if (r != NULL) {
	    if (isdigit(r[1])) {
		if (sscanf(r+1, "%ld", &Retrytime) < 1)
			Retrytime = 5;	/* 5 minutes is error default */
		DEBUG(5, "Retry time set to %d minutes\n", Retrytime);
		Retrytime *= 60;	/* convert to seconds */
		*r = NULLCHAR;		/* blow away retry time field */
	    }
	} else
	    Retrytime = 0;	/* use exponential backoff */

#ifdef MAXGRADE
	/* set grade */
	MaxGrade = NULLCHAR;			/* default */
	m = strrchr(s, '/');
	if (m != NULL) {
	    if (isalnum(m[1]))
		MaxGrade = m[1];	/* you asked for it! */
	    *m = NULLCHAR;		/* blow away max grade field */
	    DEBUG(5, "Max Grade set to %c\n", MaxGrade);
	}

	/* test grade */
	if (MaxGrade != NULLCHAR) {
	    grade = iswrk(CNULL);
	    if (grade == NULLCHAR || MaxGrade < grade) {
		DEBUG(4, "No work of grade %c -- no call\n", MaxGrade);
		return(0);
	    }
	}
#endif /* MAXGRADE */


	while (checkdate(s, tp, t__now) == 0) {
		s = strchr(s, ',');
		if (s == CNULL)
			return(0);
		s++;
	}
	return(1);
}

/* worker function for ifdate() */
static int
checkdate(s, tp, t__now)
char *s;
struct tm	*tp;
int	t__now;
{
	static char *days[] = {
		"Su", "Mo", "Tu", "We", "Th", "Fr", "Sa", 0
	};
	int	i;

	/*
	 * check day of week
	 */

	while (isalpha(*s)) {
		if (PREFIX("Any", s))
			return(checktime(s, t__now));

		if (PREFIX("Wk", s) && tp->tm_wday >= 1 && tp->tm_wday <= 5)
			return(checktime(s, t__now));

		for (i = 0; days[i]; i++)
			if (PREFIX(days[i], s) && tp->tm_wday == i)
				return(checktime(s, t__now));
		s++;
	}

	return(0);	/* day match failed */
}

/* day match ok -- check time */
static int
checktime(s, t__now)
char *s;
int	t__now;
{
	int	t__low, t__high;

	while (isalpha(*s))	/* flush day stuff */
		s++;

	if ((sscanf(s, "%d-%d", &t__low, &t__high) < 2))
		return(1);	/* time match ok (default) */

	if (t__low == t__high)
		return(1);

	/* 0000 crossover? */
	if (t__low < t__high) {
		if (t__low <= t__now && t__now <= t__high)
			return(1);
	} else {
		if (t__low <= t__now || t__now <= t__high)
			return(1);
	}

	return(0);
}

/*
 *	char *
 *	fdig(cp)	find first digit in string
 *
 *	return - pointer to first digit in string or end of string
 */

GLOBAL char *
fdig(cp)
char *cp;
{
	char *c;

	for (c = cp; *c; c++)
		if (*c >= '0' && *c <= '9')
			break;
	return(c);
}


#ifdef FASTTIMER
/*	Sleep in increments of 60ths of second.	*/
GLOBAL void
nap (time)
int time;
{
	static int fd;

	if (fd == 0)
		fd = open (FASTTIMER, 0);

	(void) (*Read)(fd, 0, time);
	return;
}

#endif /* FASTTIMER */

#if defined(BSD4_2) || defined(ATTSVR4)

	/* nap(n) -- sleep for 'n' ticks of 1/60th sec each. */
	/* This version uses the select system call */


GLOBAL void
nap(n)
unsigned n;
{
	struct timeval tv;

	if (n==0)
		return;
	tv.tv_sec = n/60;
	tv.tv_usec = ((n%60)*1000000L)/60;
	(void) select(32, 0, 0, 0, &tv);
	return;
}

#endif /* BSD4_2 || ATTSVR4 */

#ifdef NONAP

/*	nap(n) where n is ticks
 *
 *	loop using n/HZ part of a second
 *	if n represents more than 1 second, then
 *	use sleep(time) where time is the equivalent
 *	seconds rounded off to full seconds
 *	NOTE - this is a rough approximation and chews up
 *	processor resource!
 */

GLOBAL void
nap(n)
unsigned n;
{
	struct tms	tbuf;
	long endtime;
	int i;

	if (n > HZ) {
		/* > second, use sleep, rounding time */
		sleep( (int) (((n)+HZ/2)/HZ) );
		return;
	}

	/* use timing loop for < 1 second */
	endtime = times(&tbuf) + 3*n/4;	/* use 3/4 because of scheduler! */
	while (times(&tbuf) < endtime) {
	    for (i=0; i<1000; i++, (void) (i*i))
		;
	}
	return;
}

#endif /* NONAP */

/*

 * altconn - place a telephone call to system
 * from cu when telephone number or direct line used
 *
 * return codes:
 *	FAIL - connection failed
 *	>0  - file no.  -  connect ok
 * When a failure occurs, Uerror is set.
 */
GLOBAL int
altconn(call)
struct call *call;
{
	int fn = FAIL;
	char *alt[7];
	EXTERN char *Myline;

	alt[F_NAME] = "dummy";	/* to replace the Systems file fields  */
	alt[F_TIME] = "Any";	/* needed for getto(); [F_TYPE] and    */
	alt[F_TYPE] = "";	/* [F_PHONE] assignment below          */
	alt[F_CLASS] = call->speed;
	alt[F_PHONE] = "";
	alt[F_LOGIN] = "";
	alt[6] = NULL;

	CDEBUG(4,"altconn called\r\n%s", "");

	/* cu -l dev ...					*/
	/* if is "/dev/device", strip off "/dev/" because must	*/
	/* exactly match entries in Devices file, which usually	*/
	/* omit the "/dev/".  if doesn't begin with "/dev/",	*/
	/* either they've omitted the "/dev/" or it's a non-	*/
	/* standard path name.  in either case, leave it as is	*/

	if(call->line != NULL ) {
		if ( strncmp(call->line, "/dev/", 5) == 0 ) {
			Myline = (call->line + 5);
		} else {
			Myline = call->line;
		}
	}

	/* cu  ... telno */
	if(call->telno != NULL) {
		alt[F_PHONE] = call->telno;
		alt[F_TYPE] = "ACU";
	} else {
	/* cu direct line */
		alt[F_TYPE] = "Direct";
	}
	if (call->type != NULL)
		alt[F_TYPE] = call->type;
	fn = getto(alt);
	CDEBUG(4, "getto ret %d\n", fn);

	return(fn);

}
