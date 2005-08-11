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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "misc.h"
#include "msgs.h"
#include <sac.h>
#include "structs.h"
#include <sys/types.h>
#include <unistd.h>
#include "extern.h"


/*
 * read_table - read in SAC's administrative file and build internal
 *		data structures
 *
 *	args:	startflag - flag to indicate if port monitor's should be
 *			    started as a side effect of reading
 */

void
read_table(startflag)
int startflag;
{
	FILE *fp;		/* scratch file pointer */
	int ret;		/* return code from check_version */
	struct sactab *sp;	/* working pointer to move through PM info */

# ifdef DEBUG
	debug("in read_table");
# endif

/*
 * make sure _sactab is ok
 */

	Nentries = 0;
	if ((ret = check_version(VERSION, SACTAB)) == 1)
		error(E_BADVER, EXIT);
	else if (ret == 2)
		error(E_SACOPEN, EXIT);
	else if (ret == 3)
		error(E_BADFILE, EXIT);
	fp = fopen(SACTAB, "r");
	if (fp == NULL)
		error(E_SACOPEN, EXIT);

/*
 * mark all entries as invalid
 */

	for (sp = Sactab; sp; sp = sp->sc_next)
		sp->sc_valid = 0;

/*
 * build internal structures
 */

	while (sp = read_entry(fp))
		insert(sp, startflag);
	purge();
	(void) fclose(fp);
}


/*
 * read_entry - read an entry from _sactab
 *
 *	args:	fp - file pointer referencing _sactab
 */

struct sactab *
read_entry(fp)
FILE *fp;
{
	register struct sactab *sp;	/* working pointer */
	register char *p;		/* scratch pointer */
	char buf[SIZE];			/* scratch buffer */

/*
 * retrieve a line from the file
 */

	do {
		if (fgets(buf, SIZE, fp) == NULL)
			return(NULL);
		p = trim(buf);
	} while (*p == '\0');

/*
 * allocate a list element for it and then parse the line, parsed
 * info goes into list element
 */

	sp = (struct sactab *) calloc(1, sizeof(struct sactab));
	if (sp == NULL)
		error(E_MALLOC, EXIT);
	sp->sc_sstate = sp->sc_lstate = sp->sc_pstate = NOTRUNNING;
	(void) memset(sp->sc_utid, '\0', IDLEN);
	parse(p, sp);
	return(sp);
}


/*
 * insert - insert a sactab entry into the linked list
 *
 *	args:	sp - entry to be inserted
 *		startflag - flag to indicate if port monitor's should be
 *			    started as a side effect of reading
 */

void
insert(sp, startflag)
register struct sactab *sp;
int startflag;
{
	register struct sactab *tsp, *savtsp;	/* scratch pointers */
	int ret;				/* strcmp return value */

# ifdef DEBUG
	debug("in insert");
# endif
	savtsp = tsp = Sactab;

/*
 * find the correct place to insert this element
 */

	while (tsp) {
		ret = strcmp(sp->sc_tag, tsp->sc_tag);
# ifdef DEBUG
		(void) sprintf(Scratch, "sp->sc_tag <%s> tsp->sc_tag <%s>, ret is %d", sp->sc_tag, tsp->sc_tag, ret);
		debug(Scratch);
# endif
		if (ret > 0) {
			/* keep on looking */
			savtsp = tsp;
			tsp = tsp->sc_next;
			continue;
		}
		else if (ret == 0) {

/*
 * found an entry for it in the list, either a duplicate or we're
 * rereading the file.
 */

			if (tsp->sc_valid) {
				/* this is a duplicate entry, ignore it */
				(void) sprintf(Scratch, "Ignoring duplicate entry for <%s>", tsp->sc_tag);
				log(Scratch);
			}
			else {
				/* found a valid match, replace flags & restart max only */
				tsp->sc_rsmax = sp->sc_rsmax;
				tsp->sc_flags = sp->sc_flags;
# ifdef DEBUG
				(void) sprintf(Scratch, "replacing <%s>", sp->sc_tag);
				debug(Scratch);
# endif
				/* this entry is "current" */
				tsp->sc_valid = 1;
				Nentries++;
			}
			free(sp->sc_cmd);
			free(sp);
			return;
		}
		else {
			/* insert it here */
			if (tsp == Sactab) {
				sp->sc_next = Sactab;
				Sactab = sp;
			}
			else {
				sp->sc_next = savtsp->sc_next;
				savtsp->sc_next = sp;
			}
# ifdef DEBUG
			(void) sprintf(Scratch, "adding <%s>", sp->sc_tag);
			debug(Scratch);
# endif
			Nentries++;
			/* this entry is "current" */
			sp->sc_valid = 1;
			if (startflag && !(sp->sc_flags & X_FLAG))
				(void) startpm(sp);
			return;
		}
	}

/*
 * either an empty list or should put element at end of list
 */

	sp->sc_next = NULL;
	if (Sactab == NULL)
		Sactab = sp;
	else
		savtsp->sc_next = sp;
# ifdef DEBUG
	(void) sprintf(Scratch, "adding <%s>", sp->sc_tag);
	debug(Scratch);
# endif
	++Nentries;
	/* this entry is "current" */
	sp->sc_valid = 1;
	if (startflag && !(sp->sc_flags & X_FLAG))
		(void) startpm(sp);
}



/*
 * purge - purge linked list of "old" entries
 */


void
purge()
{
	register struct sactab *sp;		/* working pointer */
	register struct sactab *savesp, *tsp;	/* scratch pointers */
	sigset_t cset;				/* for signal handling */
	sigset_t tset;				/* for signal handling */

# ifdef DEBUG
	debug("in purge");
# endif
	/* get current signal mask */
	(void) sigprocmask(SIG_SETMASK, NULL, &cset);
	sp = savesp = Sactab;
	while (sp) {
		if (sp->sc_valid) {
			savesp = sp;
			sp = sp->sc_next;
			continue;
		}

		/* element should be removed */
		switch (sp->sc_sstate) {
		case UNKNOWN:
		case ENABLED:
		case DISABLED:
		case STARTING:
			/* need to kill it */
			tset = cset;
			(void) sigaddset(&tset, SIGALRM);
			(void) sigaddset(&tset, SIGCLD);
			(void) sigprocmask(SIG_SETMASK, &tset, NULL);
			if (sendsig(sp, SIGTERM))
				(void) sprintf(Scratch, "could not send SIGTERM to <%s>", sp->sc_tag);
			else
				(void) sprintf(Scratch, "terminating <%s>", sp->sc_tag);
			log(Scratch);
			(void) sigdelset(&tset, SIGALRM);
			(void) sigprocmask(SIG_SETMASK, &tset, NULL);
			/* fall thru */
		case STOPPING:
			(void) close(sp->sc_fd);
			/* fall thru */
		case NOTRUNNING:
		case FAILED:
			cleanutx(sp);
			tsp = sp;
			if (tsp == Sactab) {
				Sactab = sp->sc_next;
				savesp = Sactab;
			}
			else
				savesp->sc_next = sp->sc_next;
# ifdef DEBUG
			(void) sprintf(Scratch, "purging <%s>", sp->sc_tag);
			debug(Scratch);
# endif
			sp = sp->sc_next;
			free(tsp->sc_cmd);
			free(tsp->sc_comment);
			free(tsp);

/*
 * all done cleaning up, restore signal mask
 */

			(void) sigprocmask(SIG_SETMASK, &cset, NULL);
			break;
		}
	}
}


/*
 * dump_table - dump the internal SAC table, used to satisfy sacadm -l
 */


char **
dump_table()
{
	register struct sactab *sp;	/* working pointer */
	register char *p;		/* scratch pointer */
	register int size;		/* size of "dumped" table */
	char **info, **savinfo;		/* scratch pointers */

# ifdef DEBUG
	(void) sprintf(Scratch, "about to 'info' malloc %d entries", Nentries);
	debug(Scratch);
# endif

/*
 * get space for number of entries we have
 */

	if (Nentries == 0)
		return(NULL);
	if ((info = (char **) malloc(Nentries * sizeof(char *))) == NULL) {
		error(E_MALLOC, CONT);
		return(NULL);
	}
	savinfo = info;

/*
 * traverse the list allocating space for entries and formatting them
 */

	for (sp = Sactab; sp; sp = sp->sc_next) {
		size = strlen(sp->sc_tag) + strlen(sp->sc_type) + strlen(sp->sc_cmd) + strlen(sp->sc_comment) + SLOP;
		if ((p = malloc((unsigned) size)) == NULL) {
			error(E_MALLOC, CONT);
			return(NULL);
		}
		(void) sprintf(p, "%s:%s:%d:%d:%d:%s:%s\n", sp->sc_tag, sp->sc_type,
			sp->sc_flags, sp->sc_rsmax, sp->sc_pstate, sp->sc_cmd, sp->sc_comment);
		*info++ = p;
# ifdef DEBUG
		debug(*(info - 1));
# endif
	}
	return(savinfo);
}
