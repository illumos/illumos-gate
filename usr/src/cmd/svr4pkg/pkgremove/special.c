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
 * Copyright 2017 Gary Mills
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * special.c
 *
 * This module contains code required to remove special contents from
 * the contents file when a pkgrm is done on a system upgraded to use
 * the new database.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pkgstrct.h>
#include "pkglib.h"
#include <libintl.h>

/* This specifies the maximum length of a contents file line read in. */
#define	LINESZ	8192

#define	SPECIAL_MALLOC	"unable to maintain package contents text due to "\
			"insufficient memory."
#define	SPECIAL_ACCESS	"unable to maintain package contents text due to "\
			"an access failure."
#define	SPECIAL_INPUT	"unable to maintain package contents text: alternate "\
			"root path too long"

/*
 * strcompare
 *
 * This function is used by qsort to sort an array of special contents
 * rule strings.  This array must be sorted to facilitate efficient
 * rule processing.  See qsort(3c) regarding qsort compare functions.
 */
static int
strcompare(const void *pv1, const void *pv2)
{
	char **ppc1 = (char **) pv1;
	char **ppc2 = (char **) pv2;
	int i = strcmp(*ppc1, *ppc2);
	if (i < 0)
		return (-1);
	if (i > 0)
		return (1);
	return (0);
}

/*
 * match
 *
 * This function determines whether a file name (pc) matches a rule
 * from the special contents file (pcrule).  We assume that neither
 * string is ever NULL.
 *
 * Return: 1 on match, 0 on no match.
 * Side effects: none.
 */
static int
match(const char *pc, char *pcrule)
{
	int n = strlen(pcrule);
	int wild = 0;
	if (pcrule[n - 1] == '*') {
		wild = 1;
		pcrule[n - 1] = '\0';
	}

	if (!wild) {
		if (fnmatch(pc, pcrule, FNM_PATHNAME) == 0 ||
		    fnmatch(pc, pcrule, 0) == 0)
		return (1);
	} else {
		int j;
		j = strncmp(pc, pcrule, n - 1);
		pcrule[n - 1] = '*';
		if (j == 0)
			return (1);
	}
	return (0);
}

/*
 * search_special_contents
 *
 * This function assumes that a series of calls will be made requesting
 * whether a given path matches the special contents rules or not.  We
 * assume that
 *
 *   a) the special_contents array is sorted
 *   b) the calls will be made with paths in a sorted order
 *
 * Given that, we can keep track of where the last search ended and
 * begin the new search at that point.  This reduces the cost of a
 * special contents matching search to O(n) from O(n^2).
 *
 *   ppcSC  A pointer to an array of special contents obtained via
 *	  get_special_contents().
 *   path   A path: determine whether it matches the special
 *	  contents rules or not.
 *   piX    The position in the special_contents array we have already
 *	  arrived at through searching.  This must be initialized to
 *	  zero before initiating a series of search_special_contents
 *	  operations.
 *
 * Example:
 * {
 *	int i = 0, j, max;
 *	char **ppSC = NULL;
 *	if (get_special_contents(NULL, &ppcSC, &max) != 0) exit(1);
 *	for (j = 0; paths != NULL && paths[j] != NULL; j++) {
 *		if (search_special_contents(ppcSC, path[j], &i)) {
 *			do_something_with_special_path(path[j]);
 *		}
 *	}
 * }
 *
 * Return: 1 if there is a match, 0 otherwise.
 * Side effects: The value of *piX will be set between calls to this
 *    function.  To make this function thread safe, use search arrays.
 *    Also:  Nonmatching entries are eliminated, set to NULL.
 */
static int
search_special_contents(char **ppcSC, const char *pcpath, int *piX, int max)
{
	int wild;
	if (ppcSC == NULL || *piX == max)
		return (0);

	while (*piX < max) {

		int j, k;
		if (ppcSC[*piX] == NULL) {
			(*piX)++;
			continue;
		}

		j = strlen(ppcSC[*piX]);
		k = strcmp(pcpath, ppcSC[*piX]);
		wild = (ppcSC[*piX][j - 1] == '*');

		/*
		 * Depending on whether the path string compared with the
		 * rule, we take different actions.  If the path is less
		 * than the rule, we keep the rule.  If the path equals
		 * the rule, we advance the rule (as long as the rule is
		 * not a wild card).  If the path is greater than the rule,
		 * we have to advance the rule list until we are less or equal
		 * again.  This way we only have to make one pass through the
		 * rules, as we make one pass through the path strings.  We
		 * assume that the rules and the path strings are sorted.
		 */
		if (k < 0) {

			if (wild == 0)
				return (0);

			if (match(pcpath, ppcSC[*piX]))
				return (1);
			break;

		} else if (k == 0) {

			int x = match(pcpath, ppcSC[*piX]);
			if (wild == 0) (*piX)++;
			return (x);

		} else {
			/* One last try. */
			if (match(pcpath, ppcSC[*piX]))
				return (1);

			/*
			 * As pcpath > ppcSC[*piX] we have passed up this
			 * rule - it cannot apply.  Therefore, we do not
			 * need to retain it.  Removing the rule will make
			 * subsequent searching more efficient.
			 */
			free(ppcSC[*piX]);
			ppcSC[*piX] = NULL;

			(*piX)++;
		}
	}
	return (0);
}

/*
 * get_special_contents
 *
 * Retrieves the special contents file entries, if they exist.  These
 * are sorted.  We do not assume the special_contents file is in sorted
 * order.
 *
 *   pcroot   The root of the install database.  If NULL assume '/'.
 *   pppcSC   A pointer to a char **.  This pointer will be set to
 *		point at NULL if there is no special_contents file or
 *		to a sorted array of strings, NULL terminated, otherwise.
 *   piMax    The # of entries in the special contents result.
 *
 * Returns:  0 on no error, nonzero on error.
 * Side effects:  the pppcSC pointer is set to point at a newly
 *   allocated array of pointers to strings..  The caller must
 *   free this buffer.  The value of *piMax is set to the # of
 *   entries in ppcSC.
 */
static int
get_special_contents(const char *pcroot, char ***pppcSC, int *piMax)
{
	int e, i;
	FILE *fp;
	char line[2048];
	char **ppc;
	char *pc = "var/sadm/install/special_contents";
	char path[PATH_MAX];
	struct stat s;

	/* Initialize the return values. */
	*piMax = 0;
	*pppcSC = NULL;

	if (pcroot == NULL) {
		pcroot = "/";
	}

	if (pcroot[strlen(pcroot) - 1] == '/') {
		if (snprintf(path, PATH_MAX, "%s%s", pcroot, pc) >= PATH_MAX) {
			progerr(gettext(SPECIAL_INPUT));
			return (1);
		}
	} else {
		if (snprintf(path, PATH_MAX, "%s/%s", pcroot, pc)
		    >= PATH_MAX) {
			progerr(gettext(SPECIAL_INPUT));
			return (1);
		}
	}

	errno = 0;
	e = stat(path, &s);
	if (e != 0 && errno == ENOENT)
		return (0); /* No special contents file.  Do nothing. */

	if (access(path, R_OK) != 0 || (fp = fopen(path, "r")) == NULL) {
		/* Could not open special contents which exists */
		progerr(gettext(SPECIAL_ACCESS));
		return (1);
	}

	for (i = 0; fgets(line, 2048, fp) != NULL; i++);
	rewind(fp);
	if ((ppc = (char **) calloc(i + 1, sizeof (char *))) == NULL) {
		progerr(gettext(SPECIAL_MALLOC));
		return (1);
	}

	for (i = 0; fgets(line, 2048, fp) != NULL; ) {
		int n;
		if (line[0] == '#' || line[0] == ' ' || line[0] == '\n' ||
		    line[0] == '\t' || line[0] == '\r')
			continue;
		n = strlen(line);
		if (line[n - 1] == '\n')
			line[n - 1] = '\0';
		ppc[i++] = strdup(line);
	}

	qsort(ppc, i, sizeof (char *), strcompare);

	*pppcSC = ppc;
	*piMax = i;
	return (0);
}

/*
 * free_special_contents
 *
 * This function frees special_contents which have been allocated using
 * get_special_contents.
 *
 *   pppcSC    A pointer to a buffer allocated using get_special_contents.
 *   max       The number of entries allocated.
 *
 * Result: None.
 * Side effects: Frees memory allocated using get_special_contents and
 *    sets the pointer passed in to NULL.
 */
static void
free_special_contents(char ***pppcSC, int max)
{
	int i;
	char **ppc = NULL;
	if (*pppcSC == NULL)
		return;

	ppc = *pppcSC;
	for (i = 0; ppc != NULL && i < max; i++)
		if (ppc[i] == NULL)
			free(ppc[i]);

	if (ppc != NULL)
		free(ppc);

	*pppcSC = NULL;
}

/*
 * get_path
 *
 * Return the first field of a string delimited by a space.
 *
 *   pcline	A line from the contents file.
 *
 * Return: NULL if an error.  Otherwise a string allocated by this
 *   function.  The caller must free the string.
 * Side effects: none.
 */
static char *
get_path(const char *pcline)
{
	int i = strcspn(pcline, " ");
	char *pc = NULL;
	if (i <= 1 || (pc = (char *) calloc(i + 1, 1)) == NULL)
		return (NULL);
	(void) memcpy(pc, pcline, i);
	return (pc);
}

/*
 * generate_special_contents_rules
 *
 * This procedure will generate an array of integers which will be a mask
 * to apply to the ppcfextra array.  If set to 1, then the content must be
 * added to the contents file.  Otherwise it will not be:  The old contents
 * file will be used for this path value, if one even exists.
 *
 *    ient	The number of ppcfextra contents installed.
 *    ppcfent	The contents installed.
 *    ppcSC	The rules (special contents)
 *    max	The number of special contents rules.
 *    ppiIndex	The array of integer values, determining whether
 *		individual ppcfextra items match special contents rules.
 *		This array will be created and set in this function and
 *		returned.
 *
 * Return: 0 success, nonzero failure
 * Side effects: allocates an array of integers that the caller must free.
 */
static int
generate_special_contents_rules(int ient, struct cfent **ppcfent,
    char **ppcSC, int max, int **ppiIndex)
{
	int i, j;
	int *pi = (int *) calloc(ient, sizeof (int));
	if (pi == NULL) {
		progerr(gettext(SPECIAL_MALLOC));
		return (1);
	}

	/*
	 * For each entry in ppcfextra, check if it matches a rule.
	 * If it does not, set the entry in the index to -1.
	 */
	for (i = 0, j = 0; i < ient && j < max; i++) {
		if (search_special_contents(ppcSC, ppcfent[i]->path,
		    &j, max) == 1) {
			pi[i] = 1;

		} else {
			pi[i] = 0;
		}
	}

	/*
	 * In case we ran out of rules before contents, we will not use
	 * those contents.  Make sure these contents are set to 0 and
	 * will not be copied from the ppcfent array into the contents
	 * file.
	 */
	for (i = i; i < ient; i++)
		pi[i] = 0;

	*ppiIndex = pi;
	return (0);
}


/*
 * pathcmp
 *
 * Compare a path to a cfent.  It will match either if the path is
 * equal to the cfent path, or if the cfent is a symbolic or link
 * and *that* matches.
 *
 *    path	a path
 *    pent      a contents entry
 *
 * Returns: as per strcmp
 * Side effects: none.
 */
static int
pathcmp(const char *pc, const struct cfent *pent)
{
	int i;
	if ((pent->ftype == 's' || pent->ftype == 'l') &&
	    pent->ainfo.local) {
		char *p, *q;
		if ((p = strstr(pc, "=")) == NULL) {

			i = strcmp(pc, pent->path);

			/* A path without additional chars strcmp's to less */
			if (i == 0)
				i = -1;

		} else {
			/* Break the link path into two pieces. */
			*p = '\0';

			/* Compare the first piece. */
			i = strcmp(pc, pent->path);

			/* If equal we must compare the second piece. */
			if (i == 0) {
				q = p + 1;
				i = strcmp(q, pent->ainfo.local);
			}

			/* Restore the link path. */
			*p = '=';
		}
	} else {
		i = strcmp(pc, pent->path);
	}

	return (i);
}

/*
 * -----------------------------------------------------------------------
 * Externally visible function.
 */

/*
 * special_contents_remove
 *
 * Given a set of entries to remove and an alternate root, this function
 * will do everything required to ensure that the entries are removed
 * from the contents file if they are listed in the special_contents
 * file.  The contents file will get changed only in the case that the
 * entire operation has succeeded.
 *
 *  ient	The number of entries.
 *  ppcfent	The entries to remove.
 *  pcroot	The alternate install root.  Could be NULL.  In this
 *		case, assume root is '/'
 *
 * Result: 0 on success, nonzero on failure.  If an error occurs, an
 *    error string will get output to standard error alerting the user.
 * Side effects: The contents file may change as a result of this call,
 *    such that lines in the in the file will be changed or removed.
 *    If the call fails, a t.contents file may be left behind.  This
 *    temporary file should be removed subsequently.
 */
int
special_contents_remove(int ient, struct cfent **ppcfent, const char *pcroot)
{
	int result = 0;		/* Assume we will succeed.  Return result. */
	char **ppcSC = NULL;	/* The special contents rules, sorted. */
	int i;			/* Index into contents & special contents */
	FILE *fpi = NULL,	/* Input of contents file */
	    *fpo = NULL;	/* Output to temp contents file */
	char cpath[PATH_MAX],	/* Contents file path */
	    tcpath[PATH_MAX];	/* Temp contents file path */
	const char *pccontents = "var/sadm/install/contents";
	const char *pctcontents = "var/sadm/install/t.contents";
	char line[LINESZ];	/* Reads in and writes out contents lines. */
	time_t t;		/* Used to create a timestamp comment. */
	int max;		/* Max number of special contents entries. */
	int *piIndex;		/* An index to ppcfents to remove from cfile */

	cpath[0] = tcpath[0] = '\0';

	if (ient == 0 || ppcfent == NULL || ppcfent[0] == NULL) {
		goto remove_done;
	}

	if ((get_special_contents(pcroot, &ppcSC, &max)) != 0) {
		result = 1;
		goto remove_done;
	}

	/* Check if there are no special contents actions to take. */
	if (ppcSC == NULL) {
		goto remove_done;
	}

	if (pcroot == NULL) pcroot = "/";
	if (pcroot[strlen(pcroot) - 1] == '/') {
		if (snprintf(cpath, PATH_MAX, "%s%s", pcroot, pccontents)
		    >= PATH_MAX ||
		    snprintf(tcpath, PATH_MAX, "%s%s", pcroot, pctcontents)
		    >= PATH_MAX) {
			progerr(gettext(SPECIAL_INPUT));
			result = -1;
			goto remove_done;
		}
	} else {
		if (snprintf(cpath, PATH_MAX, "%s/%s", pcroot, pccontents)
		    >= PATH_MAX ||
		    snprintf(tcpath, PATH_MAX, "%s/%s", pcroot, pctcontents)
		    >= PATH_MAX) {
			progerr(gettext(SPECIAL_INPUT));
			result = -1;
			goto remove_done;
		}
	}

	/* Open the temporary contents file to write, contents to read. */
	if (access(cpath, F_OK | R_OK) != 0) {
		/*
		 * This is not a problem since no contents means nothing
		 * to remove due to special contents rules.
		 */
		result = 0;
		cpath[0] = '\0'; /* This signals omission of 'rename cleanup' */
		goto remove_done;
	}

	if (access(cpath, W_OK) != 0) {
		/* can't write contents file, something is wrong. */
		progerr(gettext(SPECIAL_ACCESS));
		result = 1;
		goto remove_done;

	}

	if ((fpi = fopen(cpath, "r")) == NULL) {
		/* Given the access test above, this should not happen. */
		progerr(gettext(SPECIAL_ACCESS));
		result = 1;
		goto remove_done;
	}

	if ((fpo = fopen(tcpath, "w")) == NULL) {
		/* open t.contents failed */
		progerr(gettext(SPECIAL_ACCESS));
		result = 1;
		goto remove_done;
	}

	if (generate_special_contents_rules(ient, ppcfent, ppcSC, max, &piIndex)
	    != 0) {
		result = 1;
		goto remove_done;
	}

	/*
	 * Copy contents to t.contents unless there is an entry in
	 * the ppcfent array which corresponds to an index set to 1.
	 *
	 * These items are the removed package contents which matche an
	 * entry in ppcSC (the special_contents rules).
	 *
	 * Since both the contents and rules are sorted, we can
	 * make a single efficient pass.
	 */
	(void) memset(line, 0, LINESZ);

	for (i = 0; fgets(line, LINESZ, fpi) != NULL; ) {

		char *pcpath = NULL;

		/*
		 * Note:  This could be done better:  We should figure out
		 * which are the last 2 lines and only trim those off.
		 * This will suffice to do this and will only be done as
		 * part of special_contents handling.
		 */
		if (line[0] == '#')
			continue; /* Do not copy the final 2 comment lines */

		pcpath = get_path(line);

		if (pcpath != NULL && i < ient) {
			int k;
			while (piIndex[i] == 0)
				i++;

			if (i < ient)
				k = pathcmp(pcpath, ppcfent[i]);

			if (k < 0 || i >= ient) {
				/* Just copy contents -> t.contents */
				/*EMPTY*/
			} else if (k == 0) {
				/* We have a match.  Do not copy the content. */
				i++;
				free(pcpath);
				(void) memset(line, 0, LINESZ);
				continue;
			} else while (i < ient) {

				/*
				 * This is a complex case:  The content
				 * entry is further along alphabetically
				 * than the rule.  Skip over all rules which
				 * apply until we come to a rule which is
				 * greater than the current entry, or equal
				 * to it.  If equal, do not copy, otherwise
				 * do copy the entry.
				 */
				if (piIndex[i] == 0) {
					i++;
					continue;
				} else if ((k = pathcmp(pcpath, ppcfent[i]))
				    >= 0) {
					i++;
					if (k == 0) {
						free(pcpath);
						(void) memset(line, 0, LINESZ);
						break;
					}
				} else {
					/* path < rule, end special case */
					break;
				}
			}

			/*
			 * Avoid copying the old content when path == rule
			 * This occurs when the complex case ends on a match.
			 */
			if (k == 0)
				continue;
		}

		if (fprintf(fpo, "%s", line) < 0) {
			/* Failing to write output would be catastrophic. */
			progerr(gettext(SPECIAL_ACCESS));
			result = 1;
			break;
		}
		(void) memset(line, 0, LINESZ);
	}

	t = time(NULL);
	(void) fprintf(fpo, "# Last modified by pkgremove\n");
	(void) fprintf(fpo, "# %s", ctime(&t));

remove_done:
	free_special_contents(&ppcSC, max);

	if (fpi != NULL)
		(void) fclose(fpi);

	if (fpo != NULL)
		(void) fclose(fpo);

	if (result == 0) {
		if (tcpath[0] != '\0' && cpath[0] != '\0' &&
		    rename(tcpath, cpath) != 0) {
			progerr(gettext(SPECIAL_ACCESS));
			result = 1;
		}
	} else {
		if (tcpath[0] != '\0' && remove(tcpath) != 0) {
			/*
			 * Do not output a diagnostic message.  This condition
			 * occurs only when we are unable to clean up after
			 * a failure.  A temporary file will linger.
			 */
			result = 1;
		}
	}

	return (result);
}
