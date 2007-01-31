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
 * Copyright (c) 1995 Sun Microsystems, Inc.  All Rights Reserved
 *
 * module:
 *	rules.c
 *
 * purpose:
 *	to read and write the rules file and manage rules lists
 *
 * contents:
 *	reading rules file
 *		read_rules
 *		(static) read_command
 *	writing rules file
 *		write_rules
 *		(static) rw_header, rw_base
 *	adding rules
 *		add_ignore, add_include
 *		(static) add_rule
 *	adding/checking restrictions
 *		add_restr, check_restr
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "filesync.h"
#include "database.h"
#include "messages.h"
#include "debug.h"

/*
 * routines:
 */
static errmask_t rw_base(FILE *file, struct base *bp);
static errmask_t rw_header(FILE *file);
static errmask_t add_rule(struct base *, int, const char *);
static char *read_cmd(char *);

/*
 * globals
 */
static int rules_added;
static int restr_added;

/*
 * locals
 */
#define	RULE_MAJOR	1		/* rules file format major rev	*/
#define	RULE_MINOR	1		/* rules file format minor rev	*/
#define	RULE_TAG	"PACKINGRULES"	/* magic string for rules files	*/

/*
 * routine:
 *	read_rules
 *
 * purpose:
 *	to read in the rules file
 *
 * parameters:
 *	name of rules file
 *
 * returns:
 *	error mask
 *
 * notes:
 *	later when I implement a proper (comment preserving) update
 *	function I'm going to wish I had figured out how to build the
 *	input functions for this function in a way that would make
 *	the more usable for that too.
 */
errmask_t
read_rules(char *name)
{	FILE *file;
	errmask_t errs = 0;
	int flags;
	int major, minor;
	char *s, *s1, *s2;
	struct base *bp;
	char *errstr = "???";

	file = fopen(name, "r");
	if (file == NULL) {
		fprintf(stderr, gettext(ERR_open), gettext(TXT_rules),
			name);
		return (ERR_FILES);
	}

	lex_linenum = 0;

	if (opt_debug & DBG_FILES)
		fprintf(stderr, "FILE: READ RULES %s\n", name);

	bp = &omnibase;		/* default base before any others	*/

	while (!feof(file)) {
		/* find the first token on the line	*/
		s = lex(file);

		/* skip blank lines and comments	*/
		if (s == 0 || *s == 0 || *s == '#' || *s == '*')
			continue;

		/* see if the first token is a known keyword	*/
		if (strcmp(s, "BASE") == 0) {

			/* get the source & destination tokens	*/
			errstr = gettext(TXT_srcdst);
			s1 = lex(0);
			if (s1 == 0)
				goto bad;
			s1 = strdup(s1);

			s2 = lex(0);
			if (s2 == 0)
				goto bad;
			s2 = strdup(s2);

			/* creat the new base pair		*/
			bp = add_base(s1, s2);
			bp->b_flags |= F_LISTED;

			free(s1);
			free(s2);
			continue;
		}

		if (strcmp(s, "LIST") == 0) {

			/* make sure we are associated with a real base */
			if (bp == &omnibase) {
				errstr = gettext(TXT_nobase);
				goto bad;
			}

			/* skip to the next token */
			s = lex(0);
			errstr = gettext(TXT_noargs);
			if (s == 0)
				goto bad;

			/* see if it is a program or a name */
			if (*s == '!') {
				errs |= add_rule(bp, R_PROGRAM,
						read_cmd(&s[1]));
			} else {
				do {
					flags = wildcards(s) ? R_WILD : 0;
					errs |= add_rule(bp, flags, s);
					s = lex(0);
				} while (s != 0);
			}
			continue;
		}

		if (strcmp(s, "IGNORE") == 0) {

			/* skip to the next token */
			s = lex(0);
			errstr = gettext(TXT_noargs);
			if (s == 0)
				goto bad;

			flags = R_IGNORE;

			/* see if it is a program or a name */
			if (*s == '!') {
				errs |= add_rule(bp, R_PROGRAM|flags,
						read_cmd(&s[1]));
			} else {
				do {
					if (wildcards(s))
						flags |= R_WILD;
					errs |= add_rule(bp, flags, s);
					s = lex(0);
				} while (s != 0);
			}
			continue;
		}

		if (strcmp(s, "VERSION") == 0 || strcmp(s, RULE_TAG) == 0) {
			s = lex(0);
			errstr = gettext(TXT_noargs);
			if (s == 0)
				goto bad;

			major = strtol(s, &s1, 10);
			errstr = gettext(TXT_badver);
			if (*s1 != '.')
				goto bad;
			minor = strtol(&s1[1], 0, 10);

			if (major != RULE_MAJOR || minor > RULE_MINOR) {
				fprintf(stderr, gettext(ERR_badver),
					major, minor, gettext(TXT_rules), name);
				errs |= ERR_FILES;
			}
			continue;
		}

	bad:	/* log the error and continue processing to find others	*/
		fprintf(stderr, gettext(ERR_badinput),
			lex_linenum, errstr, name);
		errs |= ERR_FILES;
	}


	(void) fclose(file);
	return (errs);
}

/*
 * routine:
 *	read_cmd
 *
 * purpose:
 *	to lex a runnable command (! lines) into a buffer
 *
 * parameters:
 *	first token
 *
 * returns:
 *	pointer to a command line in a static buffer
 *	(it is assumed the caller will copy it promptly)
 *
 * notes:
 *	this is necessary because lex has already choped off
 *	the first token for us
 */
static char *read_cmd(char * s)
{
	static char cmdbuf[ MAX_LINE ];

	cmdbuf[0] = 0;

	do {
		if (*s) {
			strcat(cmdbuf, s);
			strcat(cmdbuf, " ");
		}
	} while ((s = lex(0)) != 0);

	return (cmdbuf);
}

/*
 * routine:
 *	write_rules
 *
 * purpose:
 *	to rewrite the rules file, appending the new rules
 *
 * parameters:
 *	name of output file
 *
 * returns:
 *	error mask
 *
 */
errmask_t
write_rules(char *name)
{	FILE *newfile;
	errmask_t errs = 0;
	struct base *bp;
	char tmpname[ MAX_PATH ];

	/* if no-touch is specified, we don't update files	*/
	if (opt_notouch || rules_added == 0)
		return (0);

	/* create a temporary output file			*/
	sprintf(tmpname, "%s-TMP", name);

	/* create our output file	*/
	newfile = fopen(tmpname, "w+");
	if (newfile == NULL) {
		fprintf(stderr, gettext(ERR_creat), gettext(TXT_rules),
			name);
		return (ERR_FILES);
	}

	if (opt_debug & DBG_FILES)
		fprintf(stderr, "FILE: UPDATE RULES %s\n", name);

	errs |= rw_header(newfile);
	errs |= rw_base(newfile, &omnibase);
	for (bp = bases; bp; bp = bp->b_next)
		errs |= rw_base(newfile, bp);

	if (ferror(newfile)) {
		fprintf(stderr, gettext(ERR_write), gettext(TXT_rules),
			tmpname);
		errs |= ERR_FILES;
	}

	if (fclose(newfile)) {
		fprintf(stderr, gettext(ERR_fclose), gettext(TXT_rules),
			tmpname);
		errs |= ERR_FILES;
	}

	/* now switch the new file for the old one	*/
	if (errs == 0)
		if (rename(tmpname, name) != 0) {
			fprintf(stderr, gettext(ERR_rename),
				gettext(TXT_rules), tmpname, name);
			errs |= ERR_FILES;
		}

	return (errs);
}

/*
 * routine:
 *	rw_header
 *
 * purpose:
 *	to write out a rules header
 *
 * parameters:
 *	FILE* for the output file
 *
 * returns:
 *	error mask
 *
 * notes:
 */
static errmask_t rw_header(FILE *file)
{
	time_t now;
	struct tm *local;

	/* figure out what time it is	*/
	(void) time(&now);
	local = localtime(&now);

	fprintf(file, "%s %d.%d\n", RULE_TAG, RULE_MAJOR, RULE_MINOR);
	fprintf(file, "#\n");
	fprintf(file, "# filesync rules, last written by %s, %s",
		cuserid((char *) 0), asctime(local));
	fprintf(file, "#\n");

	return (0);
}

/*
 * routine:
 *	rw_base
 *
 * purpose:
 *	to write out the summary for one base-pair
 *
 * parameters:
 *	FILE * for the output file
 *
 * returns:
 *	error mask
 *
 * notes:
 */
static errmask_t rw_base(FILE *file, struct base *bp)
{	struct rule *rp;

	fprintf(file, "\n");

	/* global rules don't appear within a base */
	if (bp->b_ident)
		fprintf(file, "BASE %s %s\n", noblanks(bp->b_src_spec),
				noblanks(bp->b_dst_spec));

	for (rp = bp->b_includes; rp; rp = rp->r_next)
		if (rp->r_flags & R_PROGRAM)
			fprintf(file, "LIST !%s\n", rp->r_file);
		else
			fprintf(file, "LIST %s\n", noblanks(rp->r_file));

	for (rp = bp->b_excludes; rp; rp = rp->r_next)
		if (rp->r_flags & R_PROGRAM)
			fprintf(file, "IGNORE !%s\n", rp->r_file);
		else
			fprintf(file, "IGNORE %s\n", noblanks(rp->r_file));

	return (0);
}

/*
 * routine:
 *	add_rule
 *
 * purpose:
 *	to add a new rule
 *
 * parameters:
 *	pointer to list base
 *	rule flags
 *	associated name/arguments
 *
 * returns:
 *	error flags
 *
 * notes:
 *	we always copy the argument string because most of them
 *	were read from a file and are just in a transient buffer
 */
static errmask_t add_rule(struct base *bp, int flags, const char *args)
{	struct rule *rp;
	struct rule **list;

	rp = malloc(sizeof (struct rule));
	if (rp == 0)
		nomem("rule struture");

	/* initialize the new base			*/
	memset((void *) rp, 0, sizeof (struct rule));
	rp->r_flags = flags;
	rp->r_file = strdup(args);

	/* figure out which list to put it on		*/
	if (flags&R_IGNORE)
		list = &bp->b_excludes;
	else if (flags&R_RESTRICT)
		list = &bp->b_restrictions;
	else
		list = &bp->b_includes;

	while (*list)
		list = &((*list)->r_next);
	*list = rp;

	if (flags & R_NEW)
		rules_added++;

	if (opt_debug & DBG_RULE) {
		fprintf(stderr, "RULE: base=%d, ", bp->b_ident);
		fprintf(stderr, "flags=%s, ",
			showflags(rflags, rp->r_flags));
		fprintf(stderr, "arg=%s\n", rp->r_file);
	}

	return (0);
}

/*
 * routine:
 *	add_ignore, add_include
 *
 * purpose:
 *	wrappers for add_rule that permit outsiders (like main.c)
 *	not to know what is inside of a base, file, or list entry
 *
 * parameters:
 *	base under which rules should be added
 *	argument associated with rule
 *
 * returns:
 *	error flags
 *
 * notes:
 *	basically these routines figure out what the right
 *	flags are for a rule, and what list to put it on,
 *	and then call a common handler.
 */
errmask_t
add_ignore(struct base *bp, char *name)
{	int flags = R_IGNORE | R_NEW;

	if (bp == 0)
		bp = &omnibase;

	if (wildcards(name))
		flags |= R_WILD;

	return (add_rule(bp, flags, name));
}

errmask_t
add_include(struct base *bp, char *name)
{	int flags = R_NEW;

	if (bp == 0)
		bp = &omnibase;

	if (wildcards(name))
		flags |= R_WILD;

	bp->b_flags |= F_LISTED;

	return (add_rule(bp, flags, name));
}

/*
 * routine:
 *	add_restr
 *
 * purpose:
 *	to add a restriction to a base
 *
 * parameters:
 *	address of base
 *	restriction string
 *
 * returns:
 * 	error mask
 *
 * notes:
 *	a restriction is specified on the command line and
 *	tells us to limit our analysis/reconcilation to
 *	specified files and/or directories.  We deal with
 *	these by adding a restriction rule to any base that
 *	looks like it might fit the restriction.  We need to
 *	treat this as a rule because the restriction string
 *	may extend beyond the base directory and part-way into
 *	its tree ... meaning that individual file names under
 *	the base will have to be checked against the restriction.
 */
errmask_t
add_restr(char *restr)
{	const char *s;
	errmask_t errs = 0;
	struct base *bp;

	for (bp = bases; bp; bp = bp->b_next) {
		/*
		 * see if this restriction could apply to this base.
		 * It could match either the source or destination
		 * directory name for this base.  If it matches neither
		 * then the restriction does not apply to this base.
		 */
		s = prefix(restr, bp->b_src_name);
		if (s == 0)
			s = prefix(restr, bp->b_dst_name);
		if (s == 0)
			continue;

		/*
		 * if there is more restriction string after the
		 * base, we will need to note the remainder of the
		 * string so that we can match individual files
		 * against it.
		 */
		if (*s == '/')
			s++;

		errs |= add_rule(bp, R_RESTRICT, s);
		restr_added++;
	}

	return (errs);
}

/*
 * routine:
 *	check_restr
 *
 * purpose:
 *	to see if an argument falls within restrictions
 *
 * parameters:
 *	pointer to relevant base
 *	file name
 *
 * returns:
 *	TRUE	name is within restrictions
 *	FALSE	name is outside of restrictions
 *	MAYBE	name is on the path to a restriction
 *
 * notes:
 *	if no restrictions have been specified, we evaluate
 *	everything.  If any restrictions have been specified,
 *	we process only files that match one of the restrictions.
 *
 *	add_restr has ensured that if the restriction includes
 *	a portion that must be matched by individual files under
 *	the base, that the restriction rule will contain that
 *	portion of the restriction which must be matched against
 *	individual file names.
 */
bool_t
check_restr(struct base *bp, const char *name)
{	struct rule *rp;

	/* if there are no restrictions, everything is OK	*/
	if (restr_added == 0)
		return (TRUE);

	/* now we have to run through the list			*/
	for (rp = bp->b_restrictions; rp; rp = rp->r_next) {
		/* see if current path is under the restriction	*/
		if (prefix(name, rp->r_file))
			return (TRUE);

		/* see if current path is on the way to restr	*/
		if (prefix(rp->r_file, name))
			/*
			 * this is kinky, but walker really needs
			 * to know the difference between a directory
			 * that we are unreservedly scanning, and one
			 * that we are scanning only to find something
			 * beneath it.
			 */
			return (MAYBE);
	}

	/*
	 * there are restrictions in effect and this file doesn't seem
	 * to meet any of them
	 */
	if (opt_debug & DBG_RULE)
		fprintf(stderr, "RULE: FAIL RESTRICTION base=%d, file=%s\n",
			bp->b_ident, name);

	return (FALSE);
}
