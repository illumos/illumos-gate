/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include "tip.h"

extern acu_t	acutable[];

static acu_t *acu = NOACU;
static int conflag;
static void acuabort(int);
static acu_t *acutype(char *);
static sigjmp_buf jmpbuf;

/*
 * Establish connection for tip
 *
 * If DU is true, we should dial an ACU whose type is AT.
 * The phone numbers are in PN, and the call unit is in CU.
 *
 * If the PN is an '@', then we consult the PHONES file for
 *   the phone numbers.  This file is /etc/phones, unless overriden
 *   by an exported shell variable.
 *
 * The data base files must be in the format:
 *	host-name[ \t]*phone-number
 *   with the possibility of multiple phone numbers
 *   for a single host acting as a rotary (in the order
 *   found in the file).
 */
char *
connect(void)
{
	char *cp = PN;
	char *phnum, string[256];
	int tried = 0;

	if (!DU)
		return (NOSTR);
	/*
	 * @ =>'s use data base in PHONES environment variable
	 *	  otherwise, use /etc/phones
	 */
	if (sigsetjmp(jmpbuf, 1)) {
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);
		(void) printf("\ncall aborted\n");
		logent(value(HOST), "", "", "call aborted");
		if (acu != NOACU) {
			boolean(value(VERBOSE)) = FALSE;
			if (conflag)
				disconnect(NOSTR);
			else
				(*acu->acu_abort)();
		}
		myperm();
		delock(uucplock);
		exit(1);
	}
	(void) signal(SIGINT, acuabort);
	(void) signal(SIGQUIT, acuabort);
	if ((acu = acutype(AT)) == NOACU)
		return ("unknown ACU type");
	if (*cp != '@') {
		while (*cp) {
			for (phnum = cp; *cp && *cp != '|'; cp++)
				;
			if (*cp)
				*cp++ = '\0';

			if (conflag = (*acu->acu_dialer)(phnum, CU)) {
				logent(value(HOST), phnum, acu->acu_name,
				    "call completed");
				return (NOSTR);
			} else
				logent(value(HOST), phnum, acu->acu_name,
				    "call failed");
			tried++;
		}
	} else {
		if (phfd == NOFILE) {
			(void) printf("%s: ", PH);
			return ("can't open phone number file");
		}
		rewind(phfd);
		while (fgets(string, sizeof (string), phfd) != NOSTR) {
			if (string[0] == '#')
				continue;
			for (cp = string; !any(*cp, " \t\n"); cp++)
				;
			if (*cp == '\n')
				return ("unrecognizable host name");
			*cp++ = '\0';
			if (!equal(string, value(HOST)))
				continue;
			while (any(*cp, " \t"))
				cp++;
			if (*cp == '\n')
				return ("missing phone number");
			for (phnum = cp; *cp && *cp != '|' && *cp != '\n'; cp++)
				;
			*cp = '\0';

			if (conflag = (*acu->acu_dialer)(phnum, CU)) {
				logent(value(HOST), phnum, acu->acu_name,
				    "call completed");
				return (NOSTR);
			} else
				logent(value(HOST), phnum, acu->acu_name,
				    "call failed");
			tried++;
		}
	}
	if (!tried)
		logent(value(HOST), "", acu->acu_name, "missing phone number");
	else
		(*acu->acu_abort)();
	return (tried ? "call failed" : "missing phone number");
}

void
disconnect(char *reason)
{
	if (!conflag)
		return;
	if (reason == NOSTR) {
		logent(value(HOST), "", acu->acu_name, "call terminated");
		if (boolean(value(VERBOSE)))
			(void) printf("\r\ndisconnecting...");
	} else
		logent(value(HOST), "", acu->acu_name, reason);
	(*acu->acu_disconnect)();
}

static void
acuabort(int s)
{
	(void) signal(s, SIG_IGN);
	siglongjmp(jmpbuf, 1);
}

static acu_t *
acutype(char *s)
{
	acu_t *p;

	if (s != NOSTR)
		for (p = acutable; p->acu_name != NULL; p++)
			if (equal(s, p->acu_name))
				return (p);
	return (NOACU);
}
