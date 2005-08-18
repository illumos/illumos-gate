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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mail.h"

#define	MAXHDRSIZE	100	/* Maximum length of header line */
#define	MAXUNAME	20	/* Maximum length of user name */

/*
 *	display headers, indicating current and status
 *
 *	current is the displacement into the mailfile of the
 *	current letter
 *
 *	all indicates how many headers should be shown.
 *		0	->	show window +/-6 around current
 *		1	->	show all messages
 *		2	->	show deleted messages
 *
 *	Only 100 characters of the From (first) header line will
 *	be read in.  This line is assumed to be in the following
 *	format:
 *		From <sender address> <date>
 *	where
 *		<sender address> is either a UUCP-style (sysa!sysb!user)
 *		or domain-style address (user@host).
 *
 *	If the sender address contains a UUCP-style address, then
 *	the user name displayed is made up of the characters following
 *	the final '!' in the sender address, otherwise the sender
 *	address is considered to be the user name.
 *
 *	The maximum number of characters of a user name displayed
 *	is 19.
 *
 */
int
gethead(int current, int all)
{

	int	displayed = 0;
	FILE	*file;
	char	*hold;
	char	holdval[MAXHDRSIZE];
	char	*wline;
	char	wlineval[MAXHDRSIZE];
	int	ln;
	char	mark;
	int	rc, size, start, stop, ix;
	char	userval[MAXUNAME];
	char	*uucpptr;
	int	uucpstart;
	int	unamechars = MAXUNAME - 1;
	int	sender_size;

	hold = holdval;
	wline = wlineval;

	printf("%d letters found in %s, %d scheduled for deletion, "
	    "%d newly arrived\n", nlet, mailfile, changed, nlet - onlet);

	if (all == 2 && !changed)
		return (0);

	file = doopen(lettmp, "r", E_TMP);
	if (!flgr) {
		stop = current - 6;
		if (stop < -1) stop = -1;
		start = current + 5;
		if (start > nlet - 1) start = nlet - 1;
		if (all) {
			start = nlet -1;
			stop = -1;
		}
	} else {
		stop = current + 6;
		if (stop > nlet) stop = nlet;
		start = current - 5;
		if (start < 0) start = 0;
		if (all) {
			start = 0;
			stop = nlet;
		}
	}
	for (ln = start; ln != stop; ln = flgr ? ln + 1 : ln - 1) {
		size = let[ln+1].adr - let[ln].adr;
		if ((rc = fseek(file, let[ln].adr, 0)) != 0) {
			errmsg(E_FILE, "Cannot seek header");
			fclose(file);
			return (1);
		}
		if (fgets(wline, MAXHDRSIZE, file) == NULL) {
			errmsg(E_FILE, "Cannot read header");
			fclose(file);
			return (1);
		}
		if ((rc = strncmp(wline, header[H_FROM].tag, 5)) != SAME) {
			errmsg(E_FILE, "Invalid header encountered");
			fclose(file);
			return (1);
		}

		/* skip past trailing white space after header tag */
		for (rc = 5; wline[rc] == ' ' || wline[rc] == '\t'; ++rc);
		(void) strlcpy(hold, wline + rc, MAXHDRSIZE);
		fgets(wline, MAXHDRSIZE, file);

		while (((rc = strncmp(wline,
		    header[H_FROM1].tag, 6)) == SAME) &&
		    (substr(wline, "remote from ") != -1)) {
			(void) strlcpy(hold, wline + 6, MAXHDRSIZE);
			fgets(wline, MAXHDRSIZE, file);
		}


		/*
		 * If UUCP-style sender address, then read past
		 * last "!" to get the start of the user name.
		 */
		sender_size = strcspn(hold, " \t");
		uucpstart = 0;
		if ((uucpptr = strrchr(hold, '!')) != NULL) {
			uucpstart = uucpptr - hold + 1;
			if (uucpstart > sender_size) {
				uucpstart = 0;
			}
		}

		/* Get the user name out of the sender address. */
		for (ix = 0, rc = uucpstart; ix < unamechars &&
		    hold[rc] != ' ' && hold[rc] != '\t' &&
		    rc < sender_size; ++rc) {
			userval[ix++] = hold[rc];
		}
		if ((ix > 0) && (userval[ix - 1] == '\n')) {
			userval[ix - 1] = '\0';
		} else {
			userval[ix] = '\0';
		}

		/*
		 * Skip past the rest of the sender address, and
		 * delimiting white space.
		 */
		for (; hold[rc] != '\0' && hold[rc] != ' ' &&
		    hold[rc] != '\t'; ++rc);
		for (; hold[rc] == ' ' || hold[rc] == '\t'; ++rc);

		/* Get the date information. */
		(void) strlcpy(wline, hold + rc, MAXHDRSIZE);
		for (rc = 0; wline[rc] != '\0' && wline[rc] != '\n'; ++rc);
		wline[rc] = '\0';

		if (!flgh && current == ln) mark = '>';
		else mark = ' ';

		if (all == 2) {
			if (displayed >= changed) {
				fclose(file);
				return (0);
			}
			if (let[ln].change == ' ') continue;
		}

		printf("%c %3d  %c  %-5d  %-10s  %s\n", mark, ln + 1,
		    let[ln].change, size, userval, wline);
		displayed++;
	}
	fclose(file);
	return (0);
}

void
tmperr(void)
{
	fclose(tmpf);
	errmsg(E_TMP, "");
}

/*
 *	Write a string out to tmp file, with error checking.
 *	Return 1 on success, else 0
 */
int
wtmpf(char *str, int length)
{
	if (fwrite(str, 1, length, tmpf) != length) {
		tmperr();
		return (0);
	}
	return (1);
}

/*
 *	Read a line from stdin, assign it to line and
 *	return number of bytes in length
 */
int
getline(char *ptr2line, int max, FILE *f)
{
	int	i, ch;
	for (i = 0; i < max-1 && (ch = getc(f)) != EOF; )
		if ((ptr2line[i++] = ch) == '\n') break;
	ptr2line[i] = '\0';
	return (i);
}

/*
 *	Make temporary file for letter
 */
void
mktmp(void)
{
	static char tmpl[] = "/var/tmp/mailXXXXXX";
	int fd = mkstemp(lettmp = tmpl);

	if (fd < 0 || (tmpf = fdopen(fd, "w+")) == NULL) {
	    fprintf(stderr,
		    "%s: Can't open '%s', type: w+\n", program, lettmp);
	    done(0);
	}
}

/*
 * Get a number from user's reply,
 * return its value or zero if none present, -1 on error
 */
int
getnumbr(char *s)
{
	int	k = 0;

	while (*s == ' ' || *s == '\t') s++;

	if (*s != '\0') {
		if ((k = atoi(s)) != 0)
			if (!validmsg(k))
				return (-1);

		for (; *s >= '0' && *s <= '9'; ) s++;
		if (*s != '\0' && *s != '\n') {
			printf("Illegal numeric\n");
			return (-1);
		}
		return (k);
	}
	return (0);
}

/*
 *	If valid msgnum return 1,
 *		else print message and return 0
 */
int
validmsg(int i)
{
	if ((i < 0) || (i > nlet)) {
		printf("No such message\n");
		return (0);
	}
	return (1);
}

/*
 *	Set letter to passed status, and adjust changed as necessary
 */
void
setletr(int letter, int status)
{
	if (status == ' ') {
		if (let[letter].change != ' ')
			if (changed) changed--;
	} else {
		if (let[letter].change == ' ') changed++;
	}
	let[letter].change = status;
}
