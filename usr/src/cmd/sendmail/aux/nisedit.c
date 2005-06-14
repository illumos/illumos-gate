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
 * Copyright 1991-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nisplus.h"

#include <pwd.h>
#include <search.h>

/*
 * These are pointers to trees built from the "old" and "new" versions
 * of the alias database when we run in edit mode.
 */

static void *oroot = NULL;  /* pointer to the search table built from nis */
static void *nroot = NULL;  /* pointer to the table built from the editor */

static int	get_mailias();
static void	*mailias_parse_file(FILE *fp, nis_name map, nis_name domain);

/*
 * mailias_cmp returns 0 if the the ALIAS_COL ONLY of
 * an nis alias table entry are the same.  Otherwise it
 * it returns -1 if obj1 is lexicographically less than obj2
 * it returns 1 if obj1 is  lexicographically greater than obj2
 * N.B. This needs to be a function instead of a macro because it's
 * passed to the tsearch and tfind family of routines.
 */
static int
mailias_cmp(obj1, obj2)
	const void *obj1, *obj2;
{
	char *s1, *s2;
/* basically strcmp inlined for performance */
	s1 = ALIAS(((nis_object *) obj1));
	s2 = ALIAS(((nis_object *) obj2));

	while (*s1 == *s2++)
		if (*s1++ == '\0')
			return (0);
	return (*s1 - *--s2);
}

/*
 * mailias_eq returns 1 if ALL columns of two alias objects are
 * the same. Otherwise it returns 0.
 */
static int
mailias_eq(obj1, obj2)
	nis_object *obj1, *obj2;
{
	char *s1, *s2;

	/* check ALIAS column */
	s1 = ALIAS(obj1);
	s2 = ALIAS(obj2);
	if ((s1 != NULL) && (s2 != NULL)) {
		if (strcmp(s1, s2) != 0)
			return (FALSE);
	} else
		if (!((s1 == NULL) && (s2 == NULL)))
			return (FALSE);

	/* check EXPN column */
	s1 = EXPN(obj1);
	s2 = EXPN(obj2);
	if ((s1 != NULL) && (s2 != NULL)) {
		if (strcmp(s1, s2) != 0)
			return (FALSE);
	} else
		if (!((s1 == NULL) && (s2 == NULL)))
			return (FALSE);

	/* check COMMENTS column */
	s1 = COMMENTS(obj1);
	s2 = COMMENTS(obj2);
	if ((s1 != NULL) && (s2 != NULL)) {
		if (strcmp(s1, s2) != 0)
			return (FALSE);
	} else
		if (!((s1 == NULL) && (s2 == NULL)))
			return (FALSE);

	/* check OPTIONS column */
	s1 = OPTIONS(obj1);
	s2 = OPTIONS(obj2);
	if ((s1 != NULL) && (s2 != NULL)) {
		if (strcmp(s1, s2) != 0)
			return (FALSE);
	} else
		if (!((s1 == NULL) && (s2 == NULL)))
			return (FALSE);

	/* Done */
	return (TRUE);
}

/*
 * nis_mailias_list(fp, map, domain)
 *   prints the nis alias map contained in "map" in the domain "domain"
 *   to the file pointed to by	"fp" in format which is human readable.
 *   The format is "alias: value #options#comments
 *   Note that unless the -n flag was specified (which turns off the
 *   print_comments flag) this format will NOT be compatible with the
 *   /etc/mail/aliases file.
 */

void
nis_mailias_list(fp, map, domain)
	FILE *fp;
	nis_name map;
	nis_name domain;
{
	nis_result *res;
	int i;
	char qmap[NIS_MAXNAMELEN];  /* fully qualified map name */

	(void) snprintf(qmap, sizeof (qmap), "%s.%s", map, domain);

	res = nis_list(qmap, ALL_RESULTS|FOLLOW_PATH, NULL, NULL);
	if (res->status	 == NIS_SUCCESS) {
		qsort((void *) res->objects.objects_val,
			(unsigned)res->objects.objects_len,
			sizeof (nis_object),
			mailias_cmp);
		for (i = 0; i < res->objects.objects_len; i++) {
			mailias_print(fp, &res->objects.objects_val[i]);
		}
	}
}

/*
 * check_for_deletes(obj, order, level)
 *
 * when we walk the tree containing the original version of the aliases
 * we call this routine.  If obj is in the New aliases database we do
 * nothing.  If obj is NOT found in the new aliases database we
 * delete that alias from the nis aliases database.
 */

/* ARGSUSED2 */
static void
check_for_deletes(obj, order, level)
	const void *obj;
	VISIT order;
	int level;
{
	nis_mailias a;
	nis_object *old;

	/*
	 * need to check objects only once otherwise we might try and delete
	 * a deleted object
	 */
	if (order != preorder && order != leaf)
		return;

	old = *((nis_object **)obj);

	/* N.B. obj is really a (nis_object) ** */
	if (tfind((void *)old, &nroot, mailias_cmp) != NULL)
		return;
	/* fall through and delete the object */
	a.name = ALIAS(old);
	a.expn = EXPN(old);
	a.comments = COMMENTS(old);
	a.options = OPTIONS(old);
#ifdef DEBUG
	fprintf(stderr, "deleting ");
	mailias_print(stderr, old);
#endif
	nis_mailias_delete(a, old->zo_name, old->zo_domain);
}

/*
 * check_for_changes(obj, order, level)
 *
 * when we walk the tree containing the version of the aliases the user created
 * we call this routine.  If obj is the same as in the old aliases database
 * we do  nothing.  If obj is NOT found in the old aliases database we
 * add that alias to the nis aliases database.	If the obj is found in the
 * old database but has been changed we change (using the nis_change
 * operations) that alias in the database
 */

/* ARGSUSED2 */
static void
check_for_changes(obj, order, level)
	const void *obj;
	VISIT order;
	int level;
{
	nis_object *old, *new;
	nis_object **result;
	nis_mailias a;

	/*
	 * need to check objects only once otherwise we might try and change
	 * or add an object that has already been changed or added.
	 */
	if (order != preorder && order != leaf)
		return;

	new = *((nis_object **)obj);
	/* N.B. obj is really a (nis_object) ** */
	result = (nis_object **) tfind((void *)new, &oroot, mailias_cmp);
	old = (result ? *result : NULL);

	if (old == NULL) {
		a.name = ALIAS(new);
		a.expn = EXPN(new);
		a.comments = COMMENTS(new);
		a.options = OPTIONS(new);
#ifdef DEBUG
		fprintf(stderr, "adding ");
		mailias_print(stderr, new);
#endif
		nis_mailias_add(a, new->zo_name, new->zo_domain);
		return;
	}
	if (mailias_eq(old, new)) {
		/* alias entry was not changed */
#ifdef DEBUG
		fprintf(stderr, "unchanged ");
		mailias_print(stderr, new);
#endif
		return;
	}
	/* i.e. the alias entry has changed */
	a.name = ALIAS(new);
	a.expn = EXPN(new);
	a.comments = COMMENTS(new);
	a.options = OPTIONS(new);
#ifdef DEBUG
	fprintf(stderr, "changing ");
	mailias_print(stderr, new);
#endif
	nis_mailias_change(a, new->zo_name, new->zo_domain);
}

/*
 * nis_mailias_edit(FILE *fp, nis_name map, nis_man domain)
 *
 *   Edit's the alias map "map" in domain "domain".  If fp is non-NULL
 *   The file pointed to by fp contains the new alias map and no
 *   editor is invoked.
 *   The method used is to build two search trees and compare them.
 *   The first tree pointed to by oroot contains the original alias map.
 *   the second tree pointed to by nroot contains the desired aliases map.
 *   The old tree is walked first, if any of the aliases in the old tree are
 *   missing in the new tree those aliases are deleted.	 The new tree is
 *   then walked.  If the aliases are added or changed the apropriate
 *   mailias_function is called.
 */

void
nis_mailias_edit(fp, map, domain)
	FILE *fp;
	nis_name map;
	nis_name domain;
{
	nis_result *res;
	char qmap[NIS_MAXNAMELEN];  /* fully qualified map name */
	int i;
	char *editor, *cmd, *tmpfname;
	size_t cmdsize;

	void *key;

	if (!check_table(map, domain)) {
		fprintf(stderr, "Alias table %s.%s does not exist\n",
			map, domain);
		exit(-1);
	}

	(void) snprintf(qmap, sizeof (qmap), "%s.%s", map, domain);
	res = nis_list(qmap, ALL_RESULTS|FOLLOW_PATH, NULL, NULL);
	if (res->status	 == NIS_SUCCESS) {
		qsort((void *) res->objects.objects_val,
			(unsigned)res->objects.objects_len,
			sizeof (nis_object),
			mailias_cmp);
	}
	if (fp == NULL) {
		tmpfname = tmpnam(NULL);
		fp = fopen(tmpfname, "w");
		/* print the aliases into a temporary file */
		if (res -> status == NIS_SUCCESS) {
			for (i = 0; i < res->objects.objects_len; i++) {
				mailias_print(fp, &res->objects.objects_val[i]);
			}
		}
		fclose(fp);
		/* invoke the users editor on that file */
		editor = getenv("VISUAL");
		if (editor == NULL)
			editor = getenv("EDITOR");
		if (editor == NULL)
			editor = "/usr/bin/vi";
		cmdsize = strlen(editor) + strlen(tmpfname) + 2;
		cmd = (char *)malloc(cmdsize);
		if (cmd == NULL) {
			perror(NULL);
			exit(-1);
		}
		(void) snprintf(cmd, cmdsize, "%s %s", editor, tmpfname);
		system(cmd);
		fp = fopen(tmpfname, "r");
		nroot = mailias_parse_file(fp, map, domain);
		fclose(fp);
		unlink(tmpfname);
	} else {
		/* they used the -f command option to read from a file */
		nroot = mailias_parse_file(fp, map, domain);
	}

	/* If there were entries in the existing map */
	if (res -> status == NIS_SUCCESS) {
		for (i = 0; i < res->objects.objects_len; i++) {
			key = (void *) &(res->objects.objects_val[i]);
			(void) tsearch(key, &oroot, mailias_cmp);
		}
		twalk(oroot, check_for_deletes);
	}
	twalk(nroot, check_for_changes);
}

/*
 * mailias_parse_file(fp, map, domain)
 *
 * Returns a pointer to a tsearch(3) style tree which contains nis mail
 * alias objects.
 */

extern void *
mailias_parse_file(fp, map, domain)
	FILE *fp;
	nis_name map;
	nis_name domain;
{
	char lbuf[4*NIS_MAXNAMELEN + MAXLINE];
	int skipping = FALSE;
	int next_char;
	char *lp = NULL;		/* pointer to an alias line */
	char *p;
	nis_mailias a;
	nis_object *obj;
	void *root = NULL;


	while (fgets(lbuf, sizeof (lbuf), fp) != NULL) {
		/* This used to be a strchr but was inlined for performance */
		for (p = lbuf; *p != '\n' && *p != '\0'; p++)
			;
		*p = '\0';		/* get rid of \n in the string */
		switch (lbuf[0]) {
		case '#':
		case '\0':
			skipping = FALSE;
			continue;

		case ' ':
		case '\t':
			if (!skipping)
				fprintf(stderr,
				"Non-continuation line starts with space\n");
			skipping = TRUE;
			continue;
		}
		skipping = FALSE;

		/*
		 * Find and Read Any lines that start with whitespace
		 * (continuation lines)
		 */
		lp = strdup(lbuf);
		while ((next_char = getc(fp)) != EOF) {
			if (next_char == '\t' || next_char == ' ') {
				size_t lpsize = strlen(p) + strlen(lbuf);
				/* Read a Continuation line */
				ungetc(next_char, fp);
				(void) fgets(lbuf, sizeof (lbuf), fp);
				p = lp;
				lp = (char *)malloc(lpsize);
				if (p != NULL) {
					(void) strlcpy(lp, p, lpsize);
					free(p);
				}

				/*
				 * used to be a strchr,
				 * inlined for performance
				 */
				for (p = lbuf; *p != '\n' && *p != '\0'; p++)
					;
				*p = '\0';
				(void) strlcat(lp, lbuf, lpsize);
			} else {
				ungetc(next_char, fp);
				break;
			}
		}

		/* Find The Alias Name */
		a.name = "";
		a.expn = "";
		a.comments = "";
		a.options = "";

		(void) get_mailias(&a, lp);
		if (lp != NULL)
			free(lp);


		if (strcmp(a.name, "") != 0) {
			obj = mailias_make_entry(a, map, domain);
			(void) tsearch((void *) obj, &root, mailias_cmp);
		}
	}
	return (root);
}

/*
 *  get_mailias(a, lbuf)
 *
 *  put's the mail alias from lbuf into the alias structure a.
 *  Note that this ISN'T the same format as the /etc/alias file.
 *  In /etc/aliases #'s (which are used here to separate fields)
 *  are perfectly legal on the right hand side of an alias (although
 *  sendmail won't handle that sort of alias)
 */
static int
get_mailias(a, lbuf)
	nis_mailias *a;
	char *lbuf;
{
	char *ap;		/* pointer to the end of the alias field */
	char *ep;		/* pointer to the end of the expansion field */
	char *cp;		/* pointer to the end of the comment field   */
	int  cdepth = 0;	/* if > 0 we're in a user name comment */
				/* (in parens) */

	/* Find the ":", all aliases should be of the form alias: value */
	/* There used to be a strchr here that was inlined for performance */
	for (ap = lbuf; *ap != ':' && *ap != '\0'; ap++)
		;
	if (ap == '\0') {
		fprintf(stderr, "Warning, missing colon in alias\n");
		return (FALSE);
	}

	/* Allocate space and copy the alias into a->name */
	a->name = (char *)malloc((ap - lbuf) + 1);
	if (a->name == NULL) {
		perror(NULL);
		return (FALSE);
	}
	strncpy(a->name, lbuf, ap - lbuf);
	a->name[ap - lbuf] = '\0';  /* terminate the string with NUL */

	/* Read the alias value */
	for (ep = ap; (*ep != '#' || cdepth > 0) && *ep != '\0'; ep++) {
		if (*ep == '(')
			cdepth++;
		if (*ep == ')' && (cdepth > 0))
			cdepth--;
	}
	a->expn = (char *)malloc((ep - ap) + 1);
	if (a->expn == NULL) {
		perror(NULL);
		return (FALSE);
	}
	strncpy(a->expn, ap + 1, ep - (ap + 1));   /* this eliminates the : */
	a->expn[ep - (ap + 1)] = '\0';

	/* i.e. there are no comments or options */
	if (*ep == '\0')
		return (TRUE);

	/* Read the comments field value */
	cdepth = 0;
	for (cp = ep + 1; (*cp != '#' || cdepth > 0) && *cp != '\0'; cp++) {
		/*
		 * Note that notion of comments in parens inside a comment
		 * field is a bit strange.  It's really just a way to
		 * embed "#"'s in your comments
		 */
		if (*cp == '(')
			cdepth++;
		if (*cp == ')' && (cdepth > 0))
			cdepth--;
	}
	a->comments = (char *)malloc(cp - ep);
	if (a->comments == NULL) {
		perror(NULL);
		return (FALSE);
	}

	/* this eliminates the # */
	strncpy(a->comments, ep + 1, cp - (ep + 1));
	a->comments[cp - (ep + 1)] = '\0';

	/* i.e. there are no options */
	if (*cp == '\0')
		return (TRUE);

	a->options = strdup(cp + 1);  /* make sure to skip the # */
	return (TRUE);
}
