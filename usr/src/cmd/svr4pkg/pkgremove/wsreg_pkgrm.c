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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * wsreg_pkgrm.c
 *
 * Background information:
 *
 * In the past, pkgrm did not check whether a package was needed by
 * products in the product registry.  The only check that pkgrm does
 * is whether any packages depend on the package to be removed.  This
 * meant that it was trivial to use pkgrm correctly and damage products
 * (installed by webstart wizards) - without even receiving a warning.
 *
 * This enhancement to pkgrm will determine if the package to remove is
 * needed by any registered products.  If not, a '0' is returned and the
 * pkgrm can proceed.  If there is a conflict, nonzero is returned and
 * a list of all products which will be effected.  Note that removing
 * one package may damage several products.  This is because some
 * packages are used by several products, and some components are shared
 * by several products.
 *
 * The list returned is a string, which the caller must free by calling
 * free().
 *
 * The purpose of the list is to inform the user, exactly as is done with
 * the 'depends' information.  The user must be presented with the list
 * as a warning and be able to either abort the operation or proceed -
 * well advised of the consequences.
 *
 * How this works
 *
 * Installed products are associated with 'components' in a product
 * registry database.  Components in the product registry are often
 * associated with packages.  Packages are the mechanism in which
 * software is actually installed, on Solaris.  For example, when a
 * webstart wizard install occurs, one or more packages are added.
 * These are associated with 'components' (install metadata containers)
 * in the product registry.  The product registry interface acts as
 * though these packages *really are* installed.
 *
 * In order to ensure that this remains the case, the product registry
 * is examined for instances of a package before that package is removed.
 *
 * See libwsreg(3LIB) for general information about the product
 * registry library used to determine if removing a package is OK.
 *
 * See prodreg(1M) for information about a tool which can be used
 * to inspect the product registry.  Any component which has an
 * attribute 'pkgs' will list those packages which cannot be removed
 * safely.  For example: 'pkgs= SUNWfoo SUNWbar' would imply that
 * neither SUNWfoo or SUNWbar can be removed.
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>

#include "wsreg_pkgrm.h"

struct dstrp {
	char **ppc;
	int    len;
	int    max;
};

static int append_dstrp(struct dstrp *pd, const char *str);
static int in_list(const char *pcList, const char *pcItem);
static void get_all_dependents_r(struct dstrp *, struct dstrp *,
    Wsreg_component *, int *, const char *);
static char *get_locale();

/*
 * wsreg_pkgrm_check
 *
 * This routine determines if removing a particular package will
 * 'damage' a product.
 *
 *    pcRoot      IN:  The alternate root directory.  If this parameter
 *                     is NULL - then the root "/" is assumed.
 *
 *    pcPKG       IN:  The name of the package to remove (a normal NULL-
 *                     terminated string.)
 *                     This parameter must not be NULL.
 *
 *    pppcID     OUT:  The location of a char ** pointer is passed in.
 *                     This parameter must not be NULL.  The result
 *                     will be a NULL terminated array of ID strings.
 *                     The caller must free both the array of strings
 *                     and each individual string.  Example:
 *
 *                     char ** ppcID;
 *                     int i;
 *
 *                     if (wsreg_pkgrm_check(NULL, "SUNWblah", &ppcID, ..)
 *                         > 0) {
 *
 *                         for (i = 0; ppcID[i]; i++) {
 *                             do_something(ppcID[i]);
 *                             free(ppcID[i]);
 *                         }
 *                         free(ppcID);
 *                     }
 *
 *    pppcName   OUT:  As pppcID, except this contains the human readable
 *                     localized name of the component.  The index of the
 *                     name array coincides with that of the ID array, so
 *                     there will be the same number of items in both and
 *                     the component whose name is *pppcName[0] has the
 *                     id *pppcID[0].
 *
 * Returns: 0 if there is no problem.  pkgrm my proceed.
 *          positive - there is a conflict.  pppcID & pppcName return strings.
 *          negative - there was a problem running this function.
 *                     Error conditions include: (errno will be set)
 *                      ENOENT	The pcRoot directory was not valid.
 *			ENOMEM	The string to return could not be allocated.
 *			EACCES	The registry database could not be read.
 *
 * Side effects: The pppcID and pppcName parameters may be changed and set
 *     to the value of arrays of strings which the caller must free.
 */
int
wsreg_pkgrm_check(const char *pcRoot, const char *pcPKG,
    char ***pppcID, char ***pppcName)
{
	Wsreg_component **ppws;
	struct dstrp id = { NULL, 0, 0}, nm = {NULL, 0, 0};
	int i, r;
	char *locale = get_locale();
	if (locale == NULL)
		locale = "en";

	if (locale == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	assert(pcPKG != NULL && pppcName != NULL && pppcID != NULL);

	*pppcID = NULL;
	*pppcName = NULL;

	errno = 0;
	r = 0; /* A return value 0 indicates nothing was found. */

	if (pcRoot == NULL)
		pcRoot = "/";

	if (wsreg_initialize(WSREG_INIT_NORMAL, pcRoot) != WSREG_SUCCESS ||
		wsreg_can_access_registry(O_RDONLY) == 0) {
		errno = EACCES;
		return (-1);
	}

	ppws = wsreg_get_all();

	for (i = 0; ((ppws != NULL) && (ppws[i] != NULL)); i++) {
		char *pcpkgs = wsreg_get_data(ppws[i], "pkgs");
		if (pcpkgs != NULL && in_list(pcpkgs, pcPKG)) {
			char *pcID = wsreg_get_id(ppws[i]);
			char *pcName = wsreg_get_display_name(ppws[i],
			    locale);
			int depth;

			depth = 0;
			r = 1;

			if (append_dstrp(&id, pcID) ||
			    append_dstrp(&nm, pcName)) {
				errno = ENOMEM;
				r = -1;
				break;
			}

			if (pcID) free(pcID);
			if (pcName) free(pcName);
			get_all_dependents_r(&id, &nm, ppws[i], &depth, locale);
		}
	}

	if (r > 0) {
		*pppcID = id.ppc;
		*pppcName = nm.ppc;
	}

	free(locale);

	if (ppws != NULL)
		wsreg_free_component_array(ppws);

	return (r);
}

/*
 * in_list
 *
 *   pcList   A white space delimited list of words (non-white characters)
 *   pcItem   A word (not NULL, an empty string or containing white space)
 *
 * Returns 0 if pcItem is not in pcList.  nonzero if pcItem is in pcList
 * Side effects: None
 */
static int
in_list(const char *pcList, const char *pcItem)
{

	int i = 0, j = 0, k = 0;

	assert(pcItem);
	k = strlen(pcItem);

	if (pcList == NULL || k == 0)
		return (0);

	while (pcList[i] != '\0') {

		if (isspace(pcList[i])) {
			if (i == j) {
				i++;
				j++;
			} else {

				if ((i - j) == k &&
				    strncmp(&pcList[j], pcItem, i - j) == 0) {
					return (1);
				} else {
					j = i;
				}

			}
		} else {
			i++;
		}

		/* last element in the list case */
		if (pcList[i] == '\0' && j < i &&
		    strncmp(&pcList[j], pcItem, i - j) == 0)
			return (1);
	}

	return (0);
}

#define	APPEND_INCR	20

/*
 * append_dstrp
 *
 * This routine manages a dynamic array of strings in a very minimal way.
 * It assumes it has been passed a cleared struct dstrp = { NULL, 0, 0 }
 * It will add the appended string to the end of the array.  When needed,
 * the array of strings is grown to the next APPEND_INCR in size.
 *
 * Note this routine is different than append_dstr since that accumulates
 * char, this accumulates char *.
 *
 *   pd  The dynamic string.  Must be initialized to {NULL,0,0}.  Must not
 *       be NULL.
 *
 *   str The string to add.  May be of 0 length.  If NULL, a string of 0
 *       length will be added (NOT a NULL).
 *
 * Returns: 0 if OK, -1 if malloc failed.
 * Side effects: The value of pd->ppc[pd->len] changes, taking strdup(str)
 *     The final entry in the array will be NULL.  There will be pd->len
 *     entries.  To free this, free each string in the array and the array
 *     itself.   The caller must free the allocated memory.
 */
static int
append_dstrp(struct dstrp *pd, const char *str)
{
	if (str == NULL) str = "";

	if (pd->max == 0) {

		/* Initialize if necessary */
		pd->len = 0;
		pd->max = APPEND_INCR;
		pd->ppc = (char **)calloc(APPEND_INCR * sizeof (char *), 1);
		if (pd->ppc == NULL)
			return (-1);

	} else if ((pd->len + 2) == pd->max) {

		/*
		 * Grow the array.
		 * Always leave room for a single NULL end item:  That is
		 * why we grow when +2 equals the max, not +1.
		 */
		size_t s = (pd->max + APPEND_INCR) * sizeof (char *);
		pd->ppc = realloc(pd->ppc, s);
		if (pd->ppc == NULL) {
			return (-1);
		} else {
			memset(pd->ppc + pd->max, '\0',
				APPEND_INCR * sizeof (char *));
		}

		pd->max += APPEND_INCR;
	}

	if (str == NULL) {
		pd->ppc[pd->len] = NULL;
		pd->len++;
	} else {
		pd->ppc[pd->len] = (char *)strdup(str);
		if (pd->ppc[pd->len] == NULL)
			return (-1);
		pd->len++;
	}

	return (0);
}

#define	DEPTH_MAX	100

/*
 * get_all_dependents_r
 *
 *   This routine accumulates the id and name of all components which
 *   depend (directly or indirectly) on a component which has a pkg which
 *   may be removed.  By calling this routine recursively, the entire list
 *   of existing dependencies can be accumulated.
 *
 *   id        The dynamic accumulation of all ids of dependent components.
 *   nm        The dynamic accumulation of all names of dep. components.
 *   pws       The component to check for dependencies, record their
 *             ids and names, then call check these components for redun-
 *             dancy also.
 *   pdepth    The depth of the recursion.  This must be set to 0 upon the
 *             first call to this function.  Only DEPTH_MAX calls will be
 *             attempted.
 *   locale    The locale to use for querying for display names.
 *
 * Return value: None.
 * Side effects.  strings will be added to id and nm.  The depth counter
 *    will increase.
 */
static void
get_all_dependents_r(struct dstrp *id, struct dstrp *nm, Wsreg_component *pws,
    int *pdepth, const char *locale)
{
	int i;

	/* Get the list of dependent components. */
	Wsreg_component **ppws = wsreg_get_dependent_components(pws);
	if (ppws == NULL)
		return;

	if (locale == NULL)
		locale = "en";
	if (locale == NULL)
		return;

	/*
	 * Prevent infinite loops in the case where there is a cycle
	 * in the dependency graph.  Such a cycle should never happen,
	 * but a clueless user of the libwsreg API could construct such
	 * a failure case.  This is defensive programming.
	 */
	if (*pdepth > DEPTH_MAX)
		return;

	(*pdepth)++;

	for (i = 0; ppws[i]; i++) {
		char *pcID = wsreg_get_id(ppws[i]);
		char *pcName = wsreg_get_display_name(ppws[i], locale);
		if (append_dstrp(id, pcID) ||
		    append_dstrp(nm, pcName))
			/*
			 * Errors in append_dstrp happen only due to malloc
			 * failing on small allocations.  If we fail here
			 * this is the least of the user's problems.  We
			 * can just stop accumulating new info at this point.
			 */
			return;
		get_all_dependents_r(id, nm, ppws[i], pdepth, locale);
	}

	wsreg_free_component_array(ppws);
}

/*
 * init_locale
 *
 * Set locale and textdomain for localization.  Note that the return value
 * of setlocale is the locale string.  It is in the form
 *
 *   "/" LC_CTYPE "/" LC_COLLATE "/" LC_CTIME "/" LC_NUMERIC "/"
 *      LC_MONETARY "/ LC_MESSAGES
 *
 *  This routine parses this result line to determine the value of
 *  the LC_MESSAGES field.  If it is "C", the default language "en"
 *  is selected.  If not, the string is disected to get only the
 *  ISO 639 two letter tag:  "en_US.ISO8859-1" becomes "en".
 *
 * Returns: Returns a newly allocated language tag string.
 *          Returns NULL if setlocale() returns a null pointer.
 * Side effects:
 * (1) setlocale changes behavior of the application.
 */
static char *
get_locale()
{
	int i = 0, c, n;
	char lang[32];
	char *pc = setlocale(LC_ALL, "");
	char *tag = NULL;

	if (pc == NULL) {
		return (NULL);
	}

	(void *) memset(lang, 0, 32);
	if (pc[0] == '/') {

		/* Skip to the 6th field, which is 'LC_MESSAGES.' */
		c = 0;
		for (i = 0; (pc[i] != NULL) && (c < 6); i++) {
			if (pc[i] == '/') c++;
		}

		/* Strip off any dialect tag and character encoding. */
		n = 0;
		while ((pc[i] != NULL) && (pc[i] != '_') &&
		    (n < 32) && (pc[i] != '.')) {
			lang[n++] = pc[i++];
		}
	}

	if (i > 2) {
		if (strcmp(lang, "C") == 0) {
			tag = strdup("en");
		} else {
			tag = strdup(lang);
		}
	} else {
		tag = strdup("en");
	}

	return (tag);
}
