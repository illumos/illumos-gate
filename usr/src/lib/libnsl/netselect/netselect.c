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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include "mt.h"
#include "../rpc/rpc_mt.h"		/* for MT declarations only */
#include <rpc/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netconfig.h>
#include <malloc.h>
#include <libintl.h>
#include <syslog.h>
#include <zone.h>
#include "netcspace.h"

#define	FAILURE  (unsigned)(-1)

/*
 *	Local routines used by the library procedures
 */

static int blank(char *);
static int comment(char *);
static struct netconfig *fgetnetconfig(FILE *, char *);
static void netconfig_free(struct netconfig *);
static unsigned int getflag(char *);
static char **getlookups(char *);
static struct netconfig **getnetlist(void);
static unsigned int getnlookups(char *);
static char *gettoken(char *, int);
static unsigned int getvalue(char *, struct nc_data nc_data[]);
static void shift1left(char *);
static void netlist_free(struct netconfig ***);
static void free_entry(void *);
static struct netconfig *netconfig_dup(struct netconfig *);

extern const char __nsl_dom[];

/*
 *	Static global variables used by the library procedures:
 *
 *	netpp - points to the beginning of the list of netconfig
 *		entries used by setnetconfig() and setnetpath().
 *		Once netpp is initialized, that memory is *never*
 *		released.  This was necessary to improve performance.
 *
 *	linenum - the current line number of the /etc/netconfig
 *		  file (used for debugging and for nc_perror()).
 *
 *	fieldnum - the current field number of the current line
 *		   of /etc/netconfig (used for debugging and for
 *		   nc_perror()).
 *
 *	nc_error - the error condition encountered.
 */

static struct netconfig **netpp = NULL;
mutex_t netpp_mutex = DEFAULTMUTEX;
/*
 * The following two variables are used by the /etc/netconfig parsing
 * routines, which will always be executed once, and within the netpp_mutex.
 * They are global to allow the nc_sperror routine to provide better
 * information to the user about /etc/netconfig file problems.
 */
static int linenum = 0;			/* "owned" by getnetlist() */
static int fieldnum = 0;		/* "owned" by fgetnetconfig() */


static int *
__nc_error(void)
{
	static pthread_key_t nc_error_key = PTHREAD_ONCE_KEY_NP;
	static int nc_error = NC_NOERROR;
	int *ret;

	if (thr_main())
		return (&nc_error);
	ret = thr_get_storage(&nc_error_key, sizeof (int), free);
	/* if thr_get_storage fails we return the address of nc_error */
	return (ret ? ret : &nc_error);
}
#define	nc_error	(*(__nc_error()))

/*
 *	setnetconfig() has the effect of "initializing" the
 *	network configuration database.   It reads in the
 *	netcf entries (if not already read in).
 */

void *
setnetconfig(void)
{
	NCONF_HANDLE *retp;

	(void) mutex_lock(&netpp_mutex);
	if ((netpp == NULL) && ((netpp = getnetlist()) == NULL)) {
		(void) mutex_unlock(&netpp_mutex);
		return (NULL);
	}
	(void) mutex_unlock(&netpp_mutex);
	if ((retp = malloc(sizeof (NCONF_HANDLE))) == NULL) {
		nc_error = NC_NOMEM;
		return (NULL);
	}
	nc_error = NC_NOERROR;
	retp->nc_head = retp->nc_curr = netpp;
	return ((void *)retp);
}

/*
 *	endnetconfig() frees up all data allocated by setnetconfig()
 */

int
endnetconfig(void *vdata)
{
	NCONF_HANDLE *nconf_handlep = (NCONF_HANDLE *)vdata;

	(void) mutex_lock(&netpp_mutex);
	if (netpp == NULL || nconf_handlep == NULL) {
		nc_error = NC_NOSET;
		(void) mutex_unlock(&netpp_mutex);
		return (-1);
	}
	(void) mutex_unlock(&netpp_mutex);

	nc_error = NC_NOERROR;
	free(nconf_handlep);
	return (0);
}

/*
 *	getnetconfig() returns the current entry in the list
 *	of netconfig structures.  It uses the nconf_handlep argument
 *	to determine the current entry. If setnetconfig() was not
 *	called previously to set up the list, return failure.
 *      It also check if ipv6 interface is present(ipv6_present) and
 *	skips udp6 & tcp6 entries if ipv6 is not supported.
 */

struct netconfig *
getnetconfig(void *vdata)
{
	NCONF_HANDLE *nconf_handlep = (NCONF_HANDLE *)vdata;
	struct netconfig *retp;  /* holds the return value */
	int ipv6_present = -1;

	(void) mutex_lock(&netpp_mutex);
	if ((netpp == NULL) || (nconf_handlep == NULL)) {
		nc_error = NC_NOSET;
		(void) mutex_unlock(&netpp_mutex);
		return (NULL);
	}
	(void) mutex_unlock(&netpp_mutex);
	for (;;) {
		retp = *(nconf_handlep->nc_curr);
		if (retp && (strcmp(retp->nc_netid, "udp6") == 0 ||
		    strcmp(retp->nc_netid, "tcp6") == 0)) {
			if (ipv6_present == -1)
				ipv6_present = __can_use_af(AF_INET6);
			if (!ipv6_present) {
				++(nconf_handlep->nc_curr);
				continue;
			}
		}
		break;
	}
	if (retp != NULL) {
		++(nconf_handlep->nc_curr);
		nc_error = NC_NOERROR;
	} else {
		nc_error = NC_NOMOREENTRIES;
	}
	return (retp);
}

/*
 *	getnetconfig() searches the netconfig database for a
 *	given network id.  Returns a pointer to the netconfig
 *	structure or a NULL if not found.
 *      It also check if ipv6 interface is present(ipv6_present) and
 *	skips udp6 & tcp6 entries if ipv6 is not supported.
 */

struct netconfig *
getnetconfigent(const char *netid)
{
	struct netconfig **tpp;
	int ipv6_present;

	(void) mutex_lock(&netpp_mutex);
	if ((netpp == NULL) && ((netpp = getnetlist()) == NULL)) {
		(void) mutex_unlock(&netpp_mutex);
		return (NULL);
	}
	(void) mutex_unlock(&netpp_mutex);
	for (tpp = netpp; *tpp; tpp++) {
		if (strcmp((*tpp)->nc_netid, netid) == 0) {
			if (*tpp && (strcmp((*tpp)->nc_netid, "udp6") == 0 ||
			    strcmp((*tpp)->nc_netid, "tcp6") == 0)) {
				ipv6_present = __can_use_af(AF_INET6);
				if (!ipv6_present) {
					nc_error = NC_NOTFOUND;
					return (NULL);
				}
			}
			return (netconfig_dup(*tpp));
		}
	}
	nc_error = NC_NOTFOUND;
	return (NULL);
}

/*
 *	freenetconfigent frees the data allocated by getnetconfigent()
 */

void
freenetconfigent(struct netconfig *netp)
{
	netconfig_free(netp);
}

/*
 *	getnetlist() reads the netconfig file and creates a
 *	NULL-terminated list of entries.
 *	Returns the pointer to the head of the list or a NULL
 *	on failure.
 */

static struct netconfig **
getnetlist(void)
{
	FILE *fp = NULL;	/* file stream for NETCONFIG */
	struct netconfig **listpp; /* the beginning of the netconfig list */
	struct netconfig **tpp;	/* used to traverse the netconfig list */
	int count;		/* the number of entries in file */
	char nc_path[MAXPATHLEN];
	const char *zroot = zone_get_nroot();
	char line[BUFSIZ];	/* holds each line of NETCONFIG */

	/*
	 * If we are running in a branded zone, ensure we use the "/native"
	 * prefix when opening the netconfig file:
	 */
	(void) snprintf(nc_path, sizeof (nc_path), "%s%s", zroot != NULL ?
	    zroot : "", NETCONFIG);

	if ((fp = fopen(nc_path, "rF")) == NULL) {
		nc_error = NC_OPENFAIL;
		return (NULL);
	}

	count = 0;
	while (fgets(line, BUFSIZ, fp)) {
		if (!(blank(line) || comment(line))) {
			++count;
		}
	}
	rewind(fp);

	if (count == 0) {
		nc_error = NC_NOTFOUND;
		if (fp != NULL)
			(void) fclose(fp);
		return (NULL);
	}

	if ((listpp = malloc((count + 1) *
	    sizeof (struct netconfig *))) == NULL) {
		nc_error = NC_NOMEM;
		if (fp != NULL)
			(void) fclose(fp);
		return (NULL);
	}

	/*
	 *	The following loop fills in the list (loops until
	 *	fgetnetconfig() returns a NULL) and counts the
	 *	number of entries placed in the list.  Note that
	 *	when the loop is completed, the last entry in the
	 *	list will contain a NULL (signifying the end of
	 *	the list).
	 */
	linenum = 0;
	for (tpp = listpp; *tpp = fgetnetconfig(fp, NULL); tpp++)
		;
	(void) fclose(fp);

	if (nc_error != NC_NOMOREENTRIES) /* Something is screwed up */
		netlist_free(&listpp);

	return (listpp);
}

/*
 *	fgetnetconfig() parses a line of the netconfig file into
 *	a netconfig structure.  It returns a pointer to the
 *	structure of success and a NULL on failure or EOF.
 */

static struct netconfig *
fgetnetconfig(FILE *fp, char *netid)
{
	char linep[BUFSIZ];	/* pointer to a line in the file */
	struct netconfig *netconfigp; /* holds the new netconfig structure */
	char  *tok1, *tok2, *tok3; /* holds a token from the line */
	char  *retvalp;		/* the return value of fgets() */
	char *entnetid;		/* netid for the current entry */

	/* skip past blank lines and comments. */
	while (retvalp = fgets(linep, BUFSIZ, fp)) {
		linenum++;
		if (!(blank(linep) || comment(linep))) {
			break;
		}
		retvalp = NULL;
	}
	if (retvalp == NULL) {
		nc_error = NC_NOMOREENTRIES;
		return (NULL);
	}
	fieldnum = 0;
	if ((entnetid = gettoken(linep, FALSE)) == NULL) {
		nc_error = NC_BADLINE;
		return (NULL);
	}
	if (netid && (strcmp(netid, entnetid) != 0)) {
		free(entnetid);
		nc_error = NC_NOTFOUND;
		return (NULL);
	}
	if ((netconfigp = calloc(1, sizeof (struct netconfig))) == NULL) {
		free(entnetid);
		nc_error = NC_NOMEM;
		return (NULL);
	}

	tok1 = tok2 = tok3 = NULL;
	netconfigp->nc_netid = entnetid;
	if (((tok1 = gettoken(NULL, FALSE)) == NULL) ||
	    ((netconfigp->nc_semantics =
		getvalue(tok1, nc_semantics)) == FAILURE) ||
	    ((tok2 = gettoken(NULL, FALSE)) == NULL) ||
	    ((netconfigp->nc_flag = getflag(tok2)) == FAILURE) ||
	    ((netconfigp->nc_protofmly = gettoken(NULL, FALSE)) == NULL) ||
	    ((netconfigp->nc_proto = gettoken(NULL, FALSE)) == NULL) ||
	    ((netconfigp->nc_device = gettoken(NULL, FALSE)) == NULL) ||
	    ((tok3 = gettoken(NULL, TRUE)) == NULL) ||
	    (((netconfigp->nc_nlookups = getnlookups(tok3)) != 0) &&
		((netconfigp->nc_lookups = getlookups(tok3)) == NULL))) {
		netconfig_free(netconfigp);
		nc_error = NC_BADLINE;
		netconfigp = NULL;
	}
	free(tok1);
	free(tok2);
	free(tok3);
	return (netconfigp);
}

/*
 *	setnetpath() has the effect of "initializing" the
 *	NETPATH variable.  It reads in the netcf entries (if not
 *	already read in), creates a list corresponding to the entries
 *	in the NETPATH variable (or the "visible" entries og netconfig
 *	if NETPATH is not set).
 */

void *
setnetpath(void)
{
	int count;		    /* the number of entries in NETPATH	    */
	char valid_netpath[BUFSIZ]; /* holds the valid entries if NETPATH   */
	char templine[BUFSIZ];	    /* has value of NETPATH when scanning   */
	struct netconfig **curr_pp; /* scans the list from NETPATH	    */
	struct netconfig **tpp;	    /* scans the list from netconfig file   */
	struct netconfig **rnetpp;  /* the list of entries from NETPATH	    */
	char *netpath;		    /* value of NETPATH from environment    */
	char *netid;		    /* holds a component of NETPATH	    */
	char *tp;		    /* used to scan NETPATH string	    */
	NCONF_HANDLE *retp;	    /* the return value			    */

	/*
	 *	Read in the netconfig database if not already read in
	 */
	(void) mutex_lock(&netpp_mutex);
	if ((netpp == NULL) && ((netpp = getnetlist()) == NULL)) {
		(void) mutex_unlock(&netpp_mutex);
		return (NULL);
	}
	(void) mutex_unlock(&netpp_mutex);

	if ((retp = malloc(sizeof (NCONF_HANDLE))) == NULL) {
		nc_error = NC_NOMEM;
		return (NULL);
	}

	/*
	 *	Get the valid entries of the NETPATH variable (and
	 *	count the number of entries while doing it).
	 *
	 *	This is done every time the procedure is called just
	 *	in case NETPATH has changed from call to call.
	 *
	 * 	If NETPATH is too long, we ignore it altogether as
	 *	it can only be a buffer overflow attack.
	 *	Since we add one colon for each entry, but colons only
	 *	need to exist between entries, we have to subtract one.
	 */
	count = 0;
	valid_netpath[0] = '\0';
	if ((netpath = getenv(NETPATH)) == NULL ||
	    strlen(netpath) >= sizeof (templine) - 1) {
		/*
		 *	If NETPATH variable is not set or invalid,
		 *	the valid NETPATH consist of all "visible"
		 *	netids from the netconfig database.
		 */

		for (tpp = netpp; *tpp; tpp++) {
			if ((*tpp)->nc_flag & NC_VISIBLE) {
				(void) strcat(valid_netpath, (*tpp)->nc_netid);
				(void) strcat(valid_netpath, ":");
				count++;
			}
		}
	} else {

		/*
		 *	Copy the value of NETPATH (since '\0's will be
		 *	put into the string) and create the valid NETPATH
		 *	(by throwing away all netids not in the database).
		 *	If an entry appears more than one, it *will* be
		 *	listed twice in the list of valid netpath entries.
		 */

		(void) strcpy(templine, netpath);
		tp = templine;

		while (*tp) {
			/* Skip all leading ':'s */
			while (*tp && *tp == ':')
				tp++;
			if (*tp == NULL)
				break;  /* last one */
			netid = tp;
			while (*tp && *tp != ':')
				tp++;
			if (*tp)
				*tp++ = '\0'; /* isolate netid */

			for (tpp = netpp; *tpp; tpp++) {
				if (strcmp(netid, (*tpp)->nc_netid) == 0) {
					(void) strcat(valid_netpath,
						(*tpp)->nc_netid);
					(void) strcat(valid_netpath, ":");
					count++;
					break;
				}
			}
		}
	}

	/* Get space to hold the valid list (+1 for the NULL) */

	if ((rnetpp = malloc((count + 1) *
			sizeof (struct netconfig *))) == NULL) {
		free(retp);
		nc_error = NC_NOMEM;
		return (NULL);
	}

	/*
	 *	Populate the NETPATH list, ending it with a NULL.
	 *	Each entry in the list points to the structure in the
	 *	"netpp" list (the entry must exist in the list, otherwise
	 *	it wouldn't appear in valid_netpath[]).
	 */

	curr_pp = rnetpp;
	netid = tp = valid_netpath;
	while (*tp) {
		netid = tp;
		while (*tp && *tp != ':')
			tp++;
		if (*tp)
			*tp++ = '\0';
		for (tpp = netpp; *tpp; tpp++) {
			if (strcmp(netid, (*tpp)->nc_netid) == 0) {
				*curr_pp++ = *tpp;
				break;
			}
		}
	}
	*curr_pp = NULL;

	retp->nc_curr = retp->nc_head = rnetpp;
	return ((void *)retp);
}

/*
 *	endnetpath() frees up all of the memory allocated by setnetpath().
 *	It returns -1 (error) if setnetpath was never called.
 */

int
endnetpath(void *vdata)
{
	/* The argument is really a NCONF_HANDLE;  cast it here */
	NCONF_HANDLE *nconf_handlep = (NCONF_HANDLE *)vdata;

	(void) mutex_lock(&netpp_mutex);
	if (netpp == NULL || nconf_handlep == NULL) {
		nc_error = NC_NOSET;
		(void) mutex_unlock(&netpp_mutex);
		return (-1);
	}
	(void) mutex_unlock(&netpp_mutex);

	free(nconf_handlep->nc_head);
	free(nconf_handlep);
	return (0);
}

/*
 *	getnetpath() returns the current entry in the list
 *	from the NETPATH variable.  If setnetpath() was not called
 *	previously to set up the list, return NULL.
 */

struct netconfig *
getnetpath(void *vdata)
{
	/* The argument is really a NCONF_HANDLE;  cast it here */
	NCONF_HANDLE *nconf_handlep = (NCONF_HANDLE *)vdata;
	struct netconfig *retp;  /* holds the return value */
	int ipv6_present = -1;

	(void) mutex_lock(&netpp_mutex);
	if (netpp == NULL) {
		nc_error = NC_NOSET;
		(void) mutex_unlock(&netpp_mutex);
		return (NULL);
	}
	(void) mutex_unlock(&netpp_mutex);
	for (;;) {
		retp = *(nconf_handlep->nc_curr);
		if (retp && (strcmp(retp->nc_netid, "udp6") == 0 ||
		    strcmp(retp->nc_netid, "tcp6") == 0)) {
			if (ipv6_present == -1)
				ipv6_present = __can_use_af(AF_INET6);
			if (!ipv6_present) {
				++(nconf_handlep->nc_curr);
				continue;
			}
		}
		break;
	}
	if (retp) {
		++(nconf_handlep->nc_curr);
		nc_error = NC_NOERROR;
	} else {
		nc_error = NC_NOMOREENTRIES;
	}

	return (retp);
}

/*
 *	blank() returns true if the line is a blank line, 0 otherwise
 */

static int
blank(char *cp)
{
	while (*cp && isspace(*cp)) {
		cp++;
	}
	return (*cp == '\0');
}

/*
 *	comment() returns true if the line is a comment, 0 otherwise.
 */

static int
comment(char *cp)
{
	while (*cp && isspace(*cp)) {
		cp++;
	}
	return (*cp == '#');
}

/*
 *	getvalue() searches for the given string in the given array,
 *	and return the integer value associated with the string.
 */

static unsigned int
getvalue(char *cp, struct nc_data nc_data[])
{
	int i;	/* used to index through the given struct nc_data array */

	for (i = 0; nc_data[i].string; i++) {
		if (strcmp(nc_data[i].string, cp) == 0) {
			break;
		}
	}
	return (nc_data[i].value);
}

/*
 *	getflag() creates a bitmap of the one-character flags in
 *	the given string.  It uses nc_flags array to get the values.
 */

static unsigned int
getflag(char *cp)
{
	int i;			/* indexs through the nc_flag array */
	unsigned int mask = 0; /* holds bitmask of flags */

	while (*cp) {
		for (i = 0; nc_flag[i].string; i++) {
			if (*nc_flag[i].string == *cp) {
				mask |= nc_flag[i].value;
				break;
			}
		}
		cp++;
	}
	return (mask);
}

/*
 *	getlookups() creates and returns an array of string representing
 *	the directory lookup libraries, given as a comma-seperated list
 *	in the argument "cp".
 */

static char **
getlookups(char *cp)
{
	unsigned int num;	/* holds the number of entries in the list   */
	char **listpp;		/* the beginning of the list of dir routines */
	char **tpp;		/* traverses the list, populating it */
	char *start;

	num = getnlookups(cp);
	if (num == 0)
		return (NULL);
	if ((listpp = malloc((num + 1) * sizeof (char *))) == NULL)
		return (NULL);

	tpp = listpp;
	while (num--) {
		start  = cp;

		/*
		 *	Traverse the string looking for the next entry
		 *	of the list (i.e, where the ',' or end of the
		 *	string appears).  If a "\" is found, shift the
		 *	token over 1 to the left (taking the next char
		 *	literally).
		 */

		while (*cp && *cp != ',') {
			if (*cp == '\\' && *(cp + 1)) {
				shift1left(cp);
			}
			cp++;
		}
		if (*cp)
			*cp++ = '\0';
		if ((*tpp++ = strdup(start)) == NULL) {
			for (tpp = listpp; *tpp; tpp++)
				free(*tpp);
			free(listpp);
			return (NULL);
		}
	}
	*tpp = NULL;
	return (listpp);
}

/*
 *	getnlookups() returns the number of entries in a comma-separated
 *	string of tokens.  A "-" means no strings are present.
 */

static unsigned int
getnlookups(char *cp)
{
	unsigned int count;	/* the number of tokens in the string */

	if (strcmp(cp, "-") == 0)
		return (0);

	count = 1;
	while (*cp) {
		if (*cp == ',') {
			count++;
		}

		/*
		 *	If a "\" is in the string, take the next character
		 *	literally.  Onlly skip the character if "\" is
		 *	not the last character of the token.
		 */
		if (*cp == '\\' && *(cp + 1)) {
			cp++;
		}
		cp++;
	}
	return (count);
}

/*
 *	gettoken() behaves much like strtok(), except that
 *	it knows about escaped space characters (i.e., space characters
 *	preceeded by a '\' are taken literally).
 */

static char *
gettoken(char *cp, int skip)
{
	static char	*savep;	/* the place where we left off    */
	char	*p;		/* the beginning of the new token */
	char	*retp;		/* the token to be returned	  */

	fieldnum++;

	/* Determine if first or subsequent call  */
	p = (cp == NULL)? savep: cp;

	/* Return if no tokens remain.  */
	if (p == 0)
		return (NULL);

	while (isspace(*p))
		p++;

	if (*p == '\0')
		return (NULL);

	/*
	 *	Save the location of the token and then skip past it
	 */

	retp = p;
	while (*p) {
		if (isspace(*p))
			if (skip == TRUE) {
				shift1left(p);
				continue;
			} else
				break;
		/*
		 *	Only process the escape of the space seperator;
		 *	since the token may contain other separators,
		 *	let the other routines handle the escape of
		 *	specific characters in the token.
		 */

		if (*p == '\\' && *(p + 1) != '\n' && isspace(*(p + 1))) {
			shift1left(p);
		}
		p++;
	}
	if (*p == '\0') {
		savep = 0;	/* indicate this is last token */
	} else {
		*p = '\0';
		savep = ++p;
	}
	return (strdup(retp));
}

/*
 *	shift1left() moves all characters in the string over 1 to
 *	the left.
 */

static void
shift1left(char *p)
{
	for (; *p; p++)
		*p = *(p + 1);
}

char *
nc_sperror(void)
{
	static char buf_main[BUFSIZ];
	static pthread_key_t perror_key = PTHREAD_ONCE_KEY_NP;
	char *retstr = thr_main()?
		buf_main :
		thr_get_storage(&perror_key, BUFSIZ, free);

	if (retstr == NULL) {
		syslog(LOG_WARNING,
		"nc_sperror: malloc failed when trying to create buffer\n");
		return (NULL);
	}

	switch (nc_error) {
	case NC_NOERROR:
		(void) strlcpy(retstr, dgettext(__nsl_dom, "no error"), BUFSIZ);
		break;
	case NC_NOMEM:
		(void) strlcpy(retstr, dgettext(__nsl_dom, "out of memory"),
		    BUFSIZ);
		break;
	case NC_NOSET:
		(void) strlcpy(retstr, dgettext(__nsl_dom,
		    "routine called before calling \
		    setnetpath() or setnetconfig()"), BUFSIZ);
		break;
	case NC_OPENFAIL:
		(void) strlcpy(retstr,
			dgettext(__nsl_dom, "cannot open /etc/netconfig"),
			BUFSIZ);
		break;
	case NC_BADLINE:
		(void) snprintf(retstr, BUFSIZ, dgettext(__nsl_dom,
			"error in /etc/netconfig: field %d of line %d\n"),
				fieldnum, linenum);
		break;
	case NC_NOTFOUND:
		(void) snprintf(retstr, BUFSIZ,
			dgettext(__nsl_dom,
				"netid not found in /etc/netconfig"));
		break;
	case NC_NOMOREENTRIES:
		(void) snprintf(retstr, BUFSIZ,
			dgettext(__nsl_dom,
				"no more entries in /etc/netconfig"));
		break;
	default:
		(void) strlcpy(retstr, dgettext(__nsl_dom, "unknown error"),
		    BUFSIZ);
		break;
	}
	return (retstr);
}

void
nc_perror(const char *string)
{
	if (string)
		(void) fprintf(stderr, "%s: %s\n", string, nc_sperror());
	else
		(void) fprintf(stderr, "%s\n", nc_sperror());
}

static void
netlist_free(struct netconfig ***netppp)
{
	struct netconfig **tpp;

	for (tpp = *netppp; *tpp; tpp++) {
		netconfig_free(*tpp);
	}
	free(*netppp);
	*netppp = NULL;
}

static void
netconfig_free(struct netconfig *netconfigp)
{
	int i;

	if (netconfigp == NULL)
		return;
	free_entry(netconfigp->nc_netid);
	free_entry(netconfigp->nc_protofmly);
	free_entry(netconfigp->nc_proto);
	free_entry(netconfigp->nc_device);
	if (netconfigp->nc_lookups)
		for (i = 0; i < netconfigp->nc_nlookups; i++)
			free_entry(netconfigp->nc_lookups[i]);
	free_entry(netconfigp->nc_lookups);
	free(netconfigp);
}

static struct netconfig *
netconfig_dup(struct netconfig *netconfigp)
{
	struct netconfig *nconf;
	int i;

	nconf = calloc(1, sizeof (struct netconfig));
	if (nconf == NULL) {
		nc_error = NC_NOMEM;
		return (NULL);
	}
	nconf->nc_netid = strdup(netconfigp->nc_netid);
	nconf->nc_protofmly = strdup(netconfigp->nc_protofmly);
	nconf->nc_proto = strdup(netconfigp->nc_proto);
	nconf->nc_device = strdup(netconfigp->nc_device);
	nconf->nc_lookups = malloc((netconfigp->nc_nlookups + 1)
					* sizeof (char *));
	if (!(nconf->nc_lookups && nconf->nc_netid &&
		nconf->nc_protofmly && nconf->nc_proto &&
		nconf->nc_device)) {
		nc_error = NC_NOMEM;
		netconfig_free(nconf);
		return (NULL);
	}

	for (i = 0; i < netconfigp->nc_nlookups; i++) {
		nconf->nc_lookups[i] = strdup(netconfigp->nc_lookups[i]);
		if (nconf->nc_lookups[i] == NULL) {
			nconf->nc_nlookups = i;
			netconfig_free(nconf);
			nc_error = NC_NOMEM;
			return (NULL);
		}
	}
	nconf->nc_lookups[i] = NULL;
	nconf->nc_nlookups = netconfigp->nc_nlookups;
	nconf->nc_flag = netconfigp->nc_flag;
	nconf->nc_semantics = netconfigp->nc_semantics;
	return (nconf);
}

static void
free_entry(void *foo)
{
	if (foo)
		free(foo);
}
