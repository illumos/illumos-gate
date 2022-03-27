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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include	<unistd.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<ctype.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<termio.h>
#include	<sys/stermio.h>
#include	<sys/termiox.h>
#include	"ttymon.h"
#include	"tmstruct.h"
#include	"tmextern.h"
#include	"stty.h"

static	void	insert_def(struct Gdef *);
static	void	zero(char *, int);

/*
 *	read_ttydefs	- read in the /etc/ttydefs and store in Gdef array
 *			- if id is not NULL, only get entry with that id
 *			- if check is TRUE, print out the entries
 */
void
read_ttydefs(const char *id, int check)
{
	FILE	*fp;
	static	struct Gdef def;
	struct	Gdef *gptr;
	static	char	line[BUFSIZ];
	static	char	dbuf[BUFSIZ];
	char	*ptr;
	int	len;
	int	input, state, size, rawc, field;
	char	oldc;
	static	char	d_id[MAXID+1],
	    d_nextid[MAXID+1],
	    d_autobaud[MAXID+1],
	    d_if[BUFSIZ],
	    d_ff[BUFSIZ];
	static	char *states[] = {
	    "", "tty label", "Initial flags", "Final flags", "Autobaud",
	    "Next label"
	};

	if ((fp = fopen(TTYDEFS, "r")) == NULL) {
		log("can't open \"%s\".\n", TTYDEFS);
		return;
	}

	if (check) {
		for (len = 0; len < (size_t)(BUFSIZ - 1); len++)
			dbuf[len] = '-';
		dbuf[len] = '\0';
	}

	/* Start searching for the line with the proper "id". */
	input = ACTIVE;
	field = FAILURE;
	do {
		line[0] = '\0';
		for (ptr = line, oldc = '\0'; ptr < &line[sizeof (line) - 1] &&
		    (rawc = getc(fp)) != '\n' && rawc != EOF;
		    ptr++, oldc = (char)rawc) {
			if ((rawc == '#') && (oldc != '\\'))
				break;
			*ptr = (char)rawc;
		}
		*ptr = '\0';

		/* skip rest of the line */
		if (rawc != EOF && rawc != '\n') {
			if (check && rawc != '#')
				log("Entry too long.");
			while ((rawc = getc(fp)) != EOF && rawc != '\n')
				;
		}

		if (rawc == EOF) {
			if (ptr == line)
				break;
			else
				input = FINISHED;
		}

		/* if empty line, skip */
		for (ptr = line; *ptr != '\0' && isspace(*ptr); ptr++)
			;
		if (*ptr == '\0')
			continue;

		/* Now we have the complete line */

		/* Initialize "def" and "gptr". */
		gptr = &def;
		zero((char *)gptr, sizeof (struct Gdef));

		ptr = line;
		state = T_TTYLABEL;
		(void) strncpy(d_id, getword(ptr, &size, 0), MAXID);
		gptr->g_id = d_id;
		ptr += size;
		if (*ptr != ':') {
			field = state;
			state = FAILURE;
		} else {
			ptr++;	/* Skip the ':' */
			state++;
		}

		/* If "id" != NULL, and it does not match, go to next entry */
		if ((id != NULL) && (strcmp(id, gptr->g_id) != 0))
			continue;

		if (check) {
			len = strlen(line);
			dbuf[len] = '\0';
			log("\n%s", dbuf);
			log("%s", line);
			log("%s\n", dbuf);
			dbuf[len] = '-';
		}


		for (; state != FAILURE && state != SUCCESS; ) {
			switch (state) {

			case T_IFLAGS:
				(void) strncpy(d_if, getword(ptr, &size, 1),
				    BUFSIZ);
				gptr->g_iflags = d_if;
				ptr += size;
				if ((*ptr != ':') || (check_flags(d_if) != 0)) {
					field = state;
					state = FAILURE;
				} else {
					ptr++;
					state++;
				}
				break;

			case T_FFLAGS:
				(void) strncpy(d_ff, getword(ptr, &size, 1),
				    BUFSIZ);
				gptr->g_fflags = d_ff;
				ptr += size;
				if ((*ptr != ':') || (check_flags(d_ff) != 0)) {
					field = state;
					state = FAILURE;
				} else {
					ptr++;
					state++;
				}
				break;

			case T_AUTOBAUD:
				(void) strncpy(d_autobaud,
				    getword(ptr, &size, 0), MAXID);
				if (size > 1) {
					ptr += size;
					field = state;
					state = FAILURE;
					break;
				}
				if (size == 1) {
					if (*d_autobaud == 'A') {
						gptr->g_autobaud |= A_FLAG;
					} else {
						ptr += size;
						field = state;
						state = FAILURE;
						break;
					}
				}
				ptr += size;
				if (*ptr != ':') {
					field = state;
					state = FAILURE;
				} else {
					ptr++;	/* Skip the ':' */
					state++;
				}
				break;

			case T_NEXTLABEL:
				(void) strncpy(d_nextid,
				    getword(ptr, &size, 0), MAXID);
				gptr->g_nextid = d_nextid;
				ptr += size;
				if (*ptr != '\0') {
					field = state;
					state = FAILURE;
				} else {
					state = SUCCESS;
				}
				break;

			} /* end switch */
		} /* end for loop */

		if (state == SUCCESS) {

			if (check) {
				log("ttylabel:\t%s", gptr->g_id);
				log("initial flags:\t%s", gptr->g_iflags);
				log("final flags:\t%s", gptr->g_fflags);
				if (gptr->g_autobaud & A_FLAG)
					log("autobaud:\tyes");
				else
					log("autobaud:\tno");
				log("nextlabel:\t%s", gptr->g_nextid);
			}
			if (Ndefs < MAXDEFS) {
				insert_def(gptr);
			} else {
				log("can't add more entries to ttydefs table, "
				    " Maximum entries = %d", MAXDEFS);
				(void) fclose(fp);
				return;
			}
			if (id != NULL) {
				return;
			}
		} else {
			*++ptr = '\0';
			log("Parsing failure in the \"%s\" field\n"
			    "%s<--error detected here\n", states[field], line);
		}
	} while (input == ACTIVE);
	(void) fclose(fp);
}

/*
 *	zero	- zero out the buffer
 */
static void
zero(char *adr, int size)
{
	if (adr != NULL) {
		while (size--)
			*adr++ = '\0';
	}
}

/*
 * find_def(ttylabel)
 *	- scan Gdef table for an entry with requested "ttylabel".
 *	- return a Gdef ptr if entry with "ttylabel" is found
 *	- return NULL if no entry with matching "ttylabel"
 */

struct Gdef *
find_def(char *ttylabel)
{
	int	i;
	struct	Gdef	*tp;

	tp = &Gdef[0];
	for (i = 0; i < Ndefs; i++, tp++) {
		if (strcmp(ttylabel, tp->g_id) == 0) {
			return (tp);
		}
	}
	return (NULL);
}

/*
 *	check_flags	- check to see if the flags contains options that are
 *			  recognizable by stty
 *			- return 0 if no error. Otherwise return -1
 */
int
check_flags(char *flags)
{
	struct	 termio termio;
	struct	 termios termios;
	struct	 termiox termiox;
	struct	 winsize winsize;
	int	 term;
	int	 cnt = 1;
	char	 *argvp[MAXARGS];	/* stty args */
	static   char	 *binstty = "/usr/bin/stty";
	static	 char	buf[BUFSIZ];
	char	*s_arg;		/* this will point to invalid option */

	/* put flags into buf, because strtok will break up buffer */
	(void) strcpy(buf, flags);
	argvp[0] = binstty;	/* just a place holder */
	mkargv(buf, &argvp[1], &cnt, MAXARGS - 1);
	argvp[cnt] = NULL;

	/*
	 * because we don't know what type of terminal we have now,
	 * just set term = everything, so all possible stty options
	 * are accepted
	 */
	term = ASYNC|TERMIOS|FLOW;
	if ((s_arg = sttyparse(cnt, argvp, term, &termio, &termios,
	    &termiox, &winsize)) != NULL) {
		log("invalid mode: %s", s_arg);
		return (-1);
	}
	return (0);
}

/*
 *	insert_def	- insert one entry into Gdef table
 */
static void
insert_def(struct Gdef *gptr)
{
	struct	Gdef	*tp;

	if (find_def(gptr->g_id) != NULL) {
		log("Warning -- duplicate entry <%s>, ignored", gptr->g_id);
		return;
	}
	tp = &Gdef[Ndefs];
	tp->g_id = strsave(gptr->g_id);
	tp->g_iflags = strsave(gptr->g_iflags);
	tp->g_fflags = strsave(gptr->g_fflags);
	tp->g_autobaud = gptr->g_autobaud;
	tp->g_nextid = strsave(gptr->g_nextid);
	Ndefs++;
}

/*
 *	mkargv	- parse the string into args, starting from args[cnt]
 */

void
mkargv(char *string, char **args, int *cnt, int maxargs)
{
	char *ptrin, *ptrout;
	int i;
	int qsize;

	for (i = 0; i < maxargs; i++)
		args[i] = NULL;

	ptrin = ptrout = string;
	for (i = 0; *ptrin != '\0' && i < maxargs; i++) {
		/* Skip excess white spaces between arguments. */
		while (*ptrin == ' ' || *ptrin == '\t') {
			ptrin++;
			ptrout++;
		}
		/* Save the address of argument if there is something there. */
		if (*ptrin == '\0')
			break;
		else
			args[i] = ptrout;

/* Span the argument itself.  The '\' character causes quoting */
/* of the next character to take place (except for '\0'). */
		while (*ptrin != '\0') {
			if (*ptrin == '\\') {
				*ptrout++ = quoted(ptrin, &qsize);
				ptrin += qsize;

/* Is this the end of the argument?  If so quit loop. */
			} else if (*ptrin == ' ' || *ptrin == '\t') {
				ptrin++;
				break;

/* If this is a normal letter of the argument, save it, advancing */
/* the pointers at the same time. */
			} else *ptrout++ = *ptrin++;
		}
		/* Null terminate the string. */
		*ptrout++ = '\0';
	}
	(*cnt) += i;
}

#ifdef	DEBUG
/*
 *	dump_ttydefs	- dump Gdef table to log file
 */
void
dump_ttydefs(void)
{
	int	i;
	struct	Gdef	*gptr;

	gptr = &Gdef[0];
	log("********** dumping ttydefs table **********");
	log("Ndefs = %d", Ndefs);
	log(" ");
	for (i = 0; i < Ndefs; i++, gptr++) {
		log("----------------------------------------");
		log("ttylabel:\t%s", gptr->g_id);
		log("initial flags:\t%s", gptr->g_iflags);
		log("final flags:\t%s", gptr->g_fflags);
		if (gptr->g_autobaud & A_FLAG)
			log("autobaud:\tyes");
		else
			log("Autobaud:\tno");
		log("nextlabel:\t%s", gptr->g_nextid);
		log(" ");
	}
	log("********** end dumping ttydefs table **********");
}
#endif


/*
 * this is copies from uucp/strsave.c
 * and is modified that if malloc fails, it will exit
 */
char *
strsave(char *str)
{
	char *rval;

	if (str == NULL) {
		if ((rval = malloc(1)) == NULL) {
			log("strsave: malloc failed");
			exit(1);
		}
		*rval = '\0';
	} else {
		if ((rval = malloc(strlen(str) + 1)) == NULL) {
			log("strsave: malloc failed");
			exit(1);
		}
		(void) strcpy(rval, str);
	}
	return (rval);
}
