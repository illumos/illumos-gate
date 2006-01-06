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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>
#include <string.h>
#include <rpcsvc/nis.h>
#include <ctype.h>
#include <malloc.h>
#include "nis_local.h"

#ifdef ORGDIR
static void append_orgdir(nis_name nname);
#endif
static void check_dup_dnames(nis_name *namelist, int count);

/* Counts and returns the number of dots in the given string.  */
static int
dots_in_name(char *name)
{
	int i, ndots;
	size_t len = strlen(name);

#ifdef QUOTES
	int in_quotes = 0;
/* Commented out the quoted quotes stuff for 1202807 */
#endif

	for (ndots = i = 0; i < len; i++) {

#ifdef QUOTES
/* Commented out the quoted quotes stuff for 1202807 */

		/* Entering a quotation? */
		if (name[i] == '"') {

			if (name[i+1] == '"') {
				/* No.  This is "", i.e. a quoted quote */

				i++;	/* skip the next quote, else will */
				continue;  /* think it's only one quote */

			} else {

				/* Entering quotes.  Ignore all dots in here. */

				in_quotes = (in_quotes ? 0 : 1);
			}
		}

		/* If not in quotes, then increment counter */
		if ((!in_quotes) && (name[i] == '.'))
#endif

		/* Increment counter */
		if (name[i] == '.')
			++ndots;
	}
	return (ndots);
}


/*
 * parse_default()
 *
 * This function takes the default domain and creates a possible set of
 * candidate names from it. (similar to the DNS server)
 */
static int
parse_default(
	nis_name	name,		/* name given by user	*/
	nis_name	local,		/* nis_local_dir()	*/
	nis_name	*result,	/* array of pointers 	*/
	int		rmax)		/* max array value	*/
{
	char	buf[NIS_MAXSRCHLEN];	/* working name buffer	*/
	char	tmpbuf[NIS_MAXSRCHLEN];	/* temp name buffer	*/
	nis_name top;			/* ptr to free memory	*/
	nis_name dom, tmpdom;	/* temp domain names	*/
	nis_name tmpnam;	/* temp domain names	*/
	nis_name mkr = NULL;		/* name in domain flag	*/
	int comps = 0;		/* # of new components	*/

	/* There is a trailing dot, we're done */
	if (name[strlen(name)-1] == '.') {
		char *temp = strdup(name);	/* very temporary */
		if (!temp)
			return (0);	/* out-of-memory or something */
		result[comps++] = temp;
		return (comps);	/* return how many we made */
	}

	top = dom = strdup(local);	/* local is never NULL */
	if (!dom)
		return (0);		/* out-of-memory or something */

	result[0] = NULL; /* clear result list	*/
	buf[0] = '\0';	/* clear name buffer	*/
	tmpnam = name;	/* set tmpnam = name	*/
	tmpdom = dom;	/* set tmpdom = dom	*/

	/*
	 * The main reason for the following if statement is to make an
	 * intelligent "guess" as to what the user/application intended
	 * as the fully-qualified (FQ) object pathname, given a partially-
	 * qualified (PQ) one.  If there is a successful search found, a
	 * single entry, result[0], is initialized with that object name
	 * before proceeding with the normal method of creating names by
	 * continuously stripping off parts of the domain name until we've
	 * exhausted all possibilities.  If there is no resulting "guess,"
	 * the program proceeds as normal.
	 *
	 * If 'name' is not a substring of domain, then keep stripping off
	 * the labels to check for substrings of the domain.  If we've
	 * reached the end with no matches, that's okay, we just proceed
	 * as normal down below, otherwise, if there is a match, then make
	 * the assign to the first result what we think the user intended
	 * as the valid object.  Proceed as normal below.
	 *
	 * Examples:	PQ OBJ (dynam)	DOMAIN NAME (static)	ACTION
	 *		--------------	--------------------	------
	 *	1)	org_dir.foo	foo.bar.sun.com.	(continue)
	 *		foo			"		(done)
	 *		    (name is a substring of domainname, so
	 *		    guess is org_dir.foo.bar.sun.com.)
	 *
	 *	2)	x.foo.eng	foo.bar.sun.com.	(continue)
	 *		foo.eng		"		(done)
	 *		    (guess is x.foo.bar.sun.com.)
	 *
	 *	3)	hosts		foo.bar.sun.com.	(continue)
	 *					"		(done)
	 *		    (reached end of name, no guess)
	 */
	if (!(mkr = strstr(dom, name))) {

		/*
		 * Don't go past end of 'name'!  The rest of this
		 * routine incrementally takes labels from 'name'
		 * and stores them in a buffer until what remains
		 * of name is a substring of the domain name.
		 *
		 * 'tmpnam' is the temporary name pointer, and the
		 * condition in the while statement checks whether
		 * the address has passed the end of 'name'.
		 */
		while (tmpnam < (name + strlen(name))) {

			/* save first label */
			(void) nis_leaf_of_r(tmpnam, tmpbuf, NIS_MAXSRCHLEN);
			if (strlcat(buf, tmpbuf, sizeof (buf)) >=
					sizeof (buf)) {
				free(top);
				return (0);
			}
			if (strlcat(buf, ".", sizeof (buf)) >= sizeof (buf)) {
				free(top);
				return (0);
			}

			/* strip first label from rest of name */
			if (!(tmpnam = (nis_name) __nis_nextsep_of(tmpnam)))
				break;

			/* if there's a '.' skip past it for next label */
			if (*tmpnam == '.')
				tmpnam++;

			/* reached end without a dot, i.e. "hosts" */
			if (*tmpnam == '\0')
				break;

			/*
			 * If remainder is a substring of domain, break out.
			 * Move the domain pointer up to just past where the
			 * match from 'name' ends, and copy all of what
			 * matches into 'name'.
			 *
			 * Example: (see example 1 in comments above)
			 *
			 *	buf    =   org_dir
			 *	tmpnam =   foo ('org_dir' stripped off to buf)
			 *	tmpdom =   foo.bar.sun.com.
			 *			^
			 *			mkr
			 *
			 *	We check to make sure that 'mkr' points to a
			 *	'.', otherwise, the match isn't correct, i.e.
			 *	"foo" is not a label of "foo500" though
			 *	it's a substring, hence not-a-match here.
			 */
			if ((mkr = strstr(tmpdom, tmpnam)) != 0 &&
			    *(mkr+strlen(tmpnam)) == '.') {
				char *temp;	/* very temporary */

				tmpdom = mkr + strlen(tmpnam);

				/* add label:  buf = buf + tmpnam */
				if (strlcat(buf, tmpnam, sizeof (buf)) >=
						sizeof (buf)) {
					free(top);
					return (0);
				}

				/* replace name:  name = buf */
				(void) strcpy(name, buf);

				/* add domain:  buf = name + tmpdom */
				if (snprintf(buf, sizeof (buf), "%s%s", name,
						tmpdom) >= sizeof (buf)) {
					free(top);
					return (0);
				}

				/* write guess:  result[0] = buf */
				temp = strdup(buf);
				if (!temp) {
					free(top);
					return (0);	/* out-of-memory */
				}
				result[comps++] = temp;
				break;
			}
		}
	} else {

		/*
		 * If 'name' is a proper substring of the current domain name,
		 * chop off the entire name from the domain name up to the point
		 * where they do not match.  Store the item as the first result.
		 *
		 * Ex:	PQ OBJ (static)	DOMAIN NAME (dynamic)	ACTION
		 *	---------------	---------------------	------
		 *	foo.bar.sun	foo.bar.sun.com.	(continue)
		 *			com.			(done)
		 *	    (guess is foo.bar.sun.com.)
		 */
		if (*(tmpnam = mkr + strlen(name)) == '.')
			tmpdom = tmpnam;

		/*
		 * Assign this one only if we've actually moved up the tmpdom
		 * past the match *and* that the tail part of name was really
		 * a label, i.e. "eng", instead of a substring, "en".  If it
		 * was really a label, then the next character would be a '.'.
		 */
		if (*tmpdom == '.') {
		    char *temp;		/* very temporary */
		    if (snprintf(buf, sizeof (buf), "%s%s", name, tmpdom) >=
				sizeof (buf)) {
			free(top);
			return (0);
		    }
		    temp = strdup(buf);
		    if (!temp) {
			free(top);
			return (0);	/* out-of-memory or something */
		    }
		    result[comps++] = temp;
		}
	}

	/* build the list */
	for (; *dom && (comps < rmax); comps++) {

		/* bail if domain name has less than 2 labels */
		if (dots_in_name(dom) < 2)
			break;

		/* put (name + '.' + domain name) together */
		if (snprintf(buf, sizeof (buf), "%s.%s", name, dom) >=
				sizeof (buf)) {
			free(top);
			return (0);
		}

		/* bail if total name has less than 3 labels */
		if (dots_in_name(buf) < 3)
			break;

		/* assign slot if it doesn't match the first elmt */
		if ((result[0]) && (strcmp(result[0], buf) == 0)) {
			comps--;
		} else {
			char *temp = strdup(buf);	/* very temporary */
			if (!temp) {
				free(top);
				return (0);	/* out-of-memory or something */
			}
			result[comps] = temp;
		}

		/* out of memory or something */
		if (!result[comps])
			break;

		/* truncate prefix domain, return rest with '.' in front */
		dom = (nis_name) __nis_nextsep_of(dom);

		/* skip past the "." in the new domain name */
		if (*dom == '.')
			dom++;
	}
	free(top);	/* free locally-allocated domain string */
	return (comps);	/* return how many we made */
}


/*
 * __nis_parse_path()
 *
 * This function consumes "path" and parses it into a list of
 * names. Pointers to those names are stored in the array of nis_names
 * passed as 'list'. 'max' is the length of the array 'list'.
 *
 * It malloc's no memory, it only uses the array passed and the string
 * in path.
 */
int
__nis_parse_path(char *path, nis_name *list, int max)
{
	char	*s;
	int		cur;

	/* parse a colon separated list into individual table names */
	for (s = path, cur = 0; (*s != '\0') && (cur < max); cur++) {
		list[cur] = s;
		/* walk through s until EOS or ':' */
		while ((*s != ':') && (*s != '\0')) {
			s++;
#ifdef QUOTES
/* Commented out the quoted quotes stuff for 1202807 */
			if (*s == '"') {
				if (*(s+1) == '"') { /* escaped quote */
					s += 2;
				} else {
					/* skip quoted string */
					s++;
					while (1) {
						if (*s == '\0')
							break;
						/* embedded quote quote */
						if ((*s == '"') &&
						    (*(s+1) == '"')) {
							s = s+2;
							continue;
						}
						if (*s == '"')
							break;
						s++;
					}
					if (*s == '"')
						s++;
				}
			} else
				s++;
#endif
		}
		if (*s == ':') {
			*s = '\0';
			s++;
		}
	}
	return (cur);
}


/*
 * parse_path()
 *
 * This function returns the number of names it parsed out
 * of the string.
 */
static int
parse_path(const nis_name name, const char *path, const nis_name local,
    nis_name *result, int rmax)
{
	int		i, comps, cur;
	size_t		len, len1;
	nis_name	list[NIS_MAXPATHDEPTH];
	char		buf[NIS_MAXSRCHLEN], pbuf[NIS_MAXPATHLEN];

	/* parse a colon separated list into individual path names */
	(void) strncpy(pbuf, path, NIS_MAXPATHLEN); /* local copy of path */
	comps = __nis_parse_path(pbuf, list, NIS_MAXPATHDEPTH);

	/* expand "special" names in the path based on $ and + */
	for (i = 0, cur = 0; (i < comps) && (cur < rmax); i++) {

		/* if path element is just '$' by itself... */
		if ((*(list[i]) == '$') && (*(list[i]+1) == '\0')) {
			cur += parse_default(name, local, &result[cur],
				rmax - cur);
			if (cur > 0 && (!result[cur-1]))
				break; /* finish early */

		/* otherwise it's something like org_dir.$ or groups_dir.$ */
		} else {
			len = strlen((char *)(list[i]));
			/* is last character a $? */
			if (*(list[i] + (len - 1)) == '$') {
				*(list[i] + (len - 1)) = '\0';
				len1 = snprintf(buf, sizeof (buf), "%s.%s%s",
				    name, list[i], local);
			} else
				len1 = snprintf(buf, sizeof (buf), "%s.%s",
				    name, list[i]);

			/* force ending dot */
			if (buf[len1 - 1] != '.') {
			    if (len1 < sizeof (buf) - 1)
				(void) strcat(buf, ".");
			    else
				break;	/* finish early */
			} else if (len1 >= sizeof (buf))
				break;	/* finish early */

			result[cur++] = (nis_name) strdup(buf);
			if (!result[cur-1])
				break; /* finish early */
		}
	}
	return (cur);
}


#ifdef ORGDIR
/*
 *	This function will append "org_dir" to the standard tables
 *	if already not present ie standard table name is not preceded
 *	by ANY directory name.
 */
static void
append_orgdir(nis_name nname)
{
char	*p1 = nname;
int	append = 0;

	if (strchr(nname, '.'))
		return;

	switch (*p1) {

	/* auto_* tables */
	case 'a':
		p1++;

		if (strcmp(p1, "uto_") == 0)
				append = 1;
		break;

	/* bootparams */
	case 'b':
		p1++;
		if (strcmp(p1, "ootparams") == 0)
			append = 1;
		break;

	/* cred */
	case 'c':
		p1++;
		if (strcmp(p1, "red") == 0)
			append = 1;
		break;

	/* ethers */
	case 'e':
		p1++;
		if (strcmp(p1, "thers") == 0)
			append = 1;
		break;

	/* group */
	case 'g':
		p1++;
		if (strcmp(p1, "roup") == 0)
			append = 1;
		break;

	/* hosts */
	case 'h':
		p1++;
		if (strcmp(p1, "osts") == 0)
			append = 1;
		break;

	case 'm':
		p1++;
		if (strcmp(p1, "ail_aliases") == 0)
			append = 1;
		break;

	/* netgroup, netmasks, networks */
	case 'n':
		p1++;
		if (strcmp(p1, "et") == 0) {
			p1 = p1 + 2;
			switch (*p1) {
			case 'g':
				p1++;
				if (strcmp(p1, "roup") == 0)
					append = 1;
				break;

			case 'm':
				p1++;
				if (strcmp(p1, "asks") == 0)
					append = 1;
				break;

			case 'w':
				p1++;
				if (strcmp(p1, "orks") == 0)
					append = 1;
				break;
			}
		}
		break;

	/* passwd, protocols */
	case 'p':
		p1++;
		switch (*p1) {
		case 'a':
			p1++;
			if (strcmp(p1, "sswd") == 0)
				append = 1;
			break;

		case 'r':
			p1++;
			if (strcmp(p1, "otocols") == 0)
				append = 1;
			break;
		}
		break;

	/* rpc */
	case 'r':
		p1++;
		if (strcmp(p1, "pc") == 0)
			append = 1;
		break;

	/* services */
	case 's':
		p1++;
		if (strcmp(p1, "ervices") == 0)
			append = 1;
		break;

	/* timezone */
	case 't':
		p1++;
		if (strcmp(p1, "imezone") == 0)
			append = 1;
		break;

	}

	if (append)
		(void) strlcat(nname, ".org_dir", NIS_MAXSRCHLEN);
}
#endif


/*
 *	This function is called only when the NIS_PATH is set.
 *	It checks for org_dir.org_dir in the pathname. If "org_dir.org_dir"
 *	is present it either removes that entry from the name list(
 *	because if count > 1 there will be a  duplicate entry)
 *	otherwise substitute org_dir in place of org_dir.org_dir.
 *	In case the count is 1 we cannot remove the entry, rather
 *	use substitution. This would happen if NIS_PATH = org_dir.$.
 */
static void
check_dup_dnames(nis_name *namelist, int count)
{
	char	*p1, *p2;
	int	i;

	for (i = 0; i < count; i++) {
		if (p1 = strstr(namelist[i], "org_dir.org_dir")) {
			for (; i < count; i++) {
				if (count > 1) {
					namelist[i] = namelist[i+1];
				} else {
					p2 = strchr(p1, '.');
					p2++;
					while (*p1++ = *p2++);
					*p2 = 0;
				}
			}
		}
	}
}

/*
 * __nis_getnames(nis_name name, nis_error *nis_err)
 *
 * This function extends the functionality as nis_getnames() to
 * return the appropriate error in the case of failure. nis_err
 * is undefined when a non-NULL value is returned.
 */
nis_name *
__nis_getnames(nis_name name, nis_error *nis_err)
{
	int			i = 0;
	nis_name		*result;
	char			*local = NULL,   /* The local directory */
				*path = NULL,	 /* The search path */
				*tmp_path = NULL; /* The search path */
	char			buf[NIS_MAXSRCHLEN];

	if (!name) {
		*nis_err = NIS_BADNAME;
		return (NULL);
	}

	if (name[strlen(name)-1] != '.') {
		result = malloc(NIS_MAXPATHDEPTH * sizeof (nis_name));
		if (result == NULL) {
			*nis_err = NIS_NOMEMORY;
			return (NULL);
		}

		tmp_path = path = (char *)getenv("NIS_PATH");

		if (strlcpy(buf, name, sizeof (buf)) >= sizeof (buf)) {
			*nis_err = NIS_BADNAME;
			return (NULL);
		}
#ifdef ORGDIR
		append_orgdir(buf);
#endif

		if (!path)
			path = "$"; /* default path */

		/* if can't get local_dir, no need to continue */
		if (!(local = nis_local_directory())) {
			*nis_err = NIS_NOMEMORY;
			return (NULL);
		}

		/* parse the path into segments */
		i = parse_path(buf, path, local, result, NIS_MAXPATHDEPTH);

		/* check case were name is "near" the root. */
		if (i == 0) {
			if (strlcat(buf, ".", sizeof (buf)) >= sizeof (buf)) {
				*nis_err = NIS_BADNAME;
				return (NULL);
			}
			if (strlcat(buf, local, sizeof (buf)) >= sizeof (buf)) {
				*nis_err = NIS_BADNAME;
				return (NULL);
			}
			result[i++] = (nis_name) strdup(buf);
		}
		result[i] = NULL;

		/* only if NIS_PATH is set */
		if (tmp_path)
			check_dup_dnames(result, i);

	} else {
		/* the simple case for a fully-qualified path */
		result = malloc(2 * sizeof (nis_name));
		if (!result) {
			*nis_err = NIS_NOMEMORY;
			return (NULL);
		}
		result[0] = (nis_name) strdup((char *)(name));
		result[1] = NULL;
	}

	*nis_err = NIS_SUCCESS;
	return (result);
}


/*
 * nis_getnames(name, nis_error *nis_err)
 *
 * This function returns a list of candidate NIS+ names given an
 * non fully qualified NIS name. Note it is HOST RFC compliant
 * in that it stops generating names when the resulting name would
 * have 2 or fewer dots in it. This helps avoid banging on the root
 * name servers.
 */
nis_name *
nis_getnames(nis_name name)
{
	nis_error nis_err;

	return (__nis_getnames(name, &nis_err));
}


/* free an entire list, one at a time */
void
nis_freenames(nis_name *namelist)
{
	int i = 0;

	while (namelist[i])
		free(namelist[i++]);
	free(namelist);
}
