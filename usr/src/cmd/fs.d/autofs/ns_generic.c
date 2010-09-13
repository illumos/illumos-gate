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
 *	ns_generic.c
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <nsswitch.h>
#include <sys/param.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs_prot.h>
#include "automount.h"

/*
 * Each name service is represented by a ns_info structure.
 */
struct ns_info {
	char	*ns_name;		/* service name */
	void	(*ns_init)();		/* initialization routine */
	int	(*ns_getmapent)();	/* get map entry given key */
	int	(*ns_loadmaster)();	/* load master map */
	int	(*ns_loaddirect)();	/* load direct map */
	int	(*ns_getmapkeys)();	/* readdir */
};

static struct ns_info ns_info[] = {

	"files",   init_files,  getmapent_files,
	loadmaster_files, loaddirect_files,
	getmapkeys_files,

	"ldap",   init_ldap,  getmapent_ldap,
	loadmaster_ldap, loaddirect_ldap,
	getmapkeys_ldap,

	"nis",	   init_nis,	getmapent_nis,
	loadmaster_nis,   loaddirect_nis,
	getmapkeys_nis,

	NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static struct ns_info *get_next_ns(struct __nsw_lookup **, int);

void
ns_setup(char **stack, char ***stkptr)
{
	struct ns_info *nsp;

	for (nsp = ns_info; nsp->ns_name; nsp++) {
		nsp->ns_init(stack, stkptr);
	}
}

static struct ns_info *
get_next_ns(curr_ns, curr_nserr)
	struct __nsw_lookup **curr_ns;
	int curr_nserr;
{
	static struct __nsw_switchconfig *conf = NULL;
	enum __nsw_parse_err pserr;
	struct __nsw_lookup *lkp;
	struct ns_info *nsp;

	if (conf == NULL) {
		/* __nsw_getconfig() is protected by a lock */
		conf = __nsw_getconfig("automount", &pserr);
		if (conf == NULL) {
			return (NULL);
		}
	}

	if (*curr_ns == NULL)
		/* first time */
		lkp = conf->lookups;
	else {
		lkp = *curr_ns;
		/* __NSW_ACTION is MT-Safe */
		if (__NSW_ACTION(lkp, curr_nserr) == __NSW_RETURN)
			return (NULL);
		lkp = lkp->next;
	}

	for (; lkp; lkp = lkp->next) {
		for (nsp = ns_info; nsp->ns_name; nsp++) {
			if (strcmp(lkp->service_name, nsp->ns_name) == 0) {
				*curr_ns = lkp;
				return (nsp);
			}
		}
		/*
		 * Note: if we get here then we've found
		 * an unsupported name service.
		 */
	}

	return (NULL);
}

int
getmapent(key, mapname, ml, stack, stkptr, iswildcard, isrestricted)
	char *key, *mapname;
	struct mapline *ml;
	char **stack, ***stkptr;
	bool_t *iswildcard;
	bool_t isrestricted;
{
	struct __nsw_lookup *curr_ns = NULL;
	int ns_err = __NSW_SUCCESS;
	struct ns_info *nsp;

	if (strcmp(mapname, "-hosts") == 0) {
		(void) strcpy(ml->linebuf, "-hosts");
		return (__NSW_SUCCESS);
	}

	if (*mapname == '/') 		/* must be a file */
		return (getmapent_files(key, mapname, ml, stack, stkptr,
					iswildcard, isrestricted));

	while ((nsp = get_next_ns(&curr_ns, ns_err)) != NULL) {
		ns_err = nsp->ns_getmapent(key, mapname, ml, stack, stkptr,
						iswildcard, isrestricted);
		if (ns_err == __NSW_SUCCESS)
			return (__NSW_SUCCESS);
	}

	return (__NSW_UNAVAIL);
}

int
loadmaster_map(mapname, defopts, stack, stkptr)
	char *mapname, *defopts;
	char **stack, ***stkptr;
{
	struct __nsw_lookup *curr_ns = NULL;
	int ns_err = __NSW_SUCCESS;
	struct ns_info *nsp;

	if (*mapname == '/')		/* must be a file */
		return (loadmaster_files(mapname, defopts, stack, stkptr));

	while ((nsp = get_next_ns(&curr_ns, ns_err)) != NULL) {
		ns_err = nsp->ns_loadmaster(mapname, defopts, stack, stkptr);
		if (ns_err == __NSW_SUCCESS)
			return (__NSW_SUCCESS);
	}

	return (__NSW_UNAVAIL);
}

int
loaddirect_map(mapname, localmap, defopts, stack, stkptr)
	char *mapname, *localmap, *defopts;
	char **stack, ***stkptr;
{
	struct __nsw_lookup *curr_ns = NULL;
	int ns_err = __NSW_SUCCESS;
	struct ns_info *nsp;

	if (*mapname == '/')		/* must be a file */
		return (loaddirect_files(mapname, localmap, defopts,
				stack, stkptr));

	while ((nsp = get_next_ns(&curr_ns, ns_err)) != NULL) {
		ns_err = nsp->ns_loaddirect(mapname, localmap, defopts, stack,
					stkptr);
		if (ns_err == __NSW_SUCCESS)
			return (__NSW_SUCCESS);
	}

	return (__NSW_UNAVAIL);
}

int
gethostkeys(mapname, list, error, cache_time)
	char *mapname;
	struct dir_entry **list;
	int *error;
	int *cache_time;
{
	char *buffer, **p;
	int bufferlen = 1000;
	struct dir_entry *last = NULL;
	struct hostent ent;

#ifdef lint
	mapname = mapname;
#endif

	*cache_time = RDDIR_CACHE_TIME * 2;
	*error = 0;
	if (trace  > 1)
		trace_prt(1, "gethostkeys called\n");

	if (sethostent(1)) {
		syslog(LOG_ERR, "gethostkeys: sethostent failed");
		*error = EIO;
		return (__NSW_UNAVAIL);
	}

	buffer = (char *)malloc(bufferlen);
	if (buffer == NULL) {
		syslog(LOG_ERR, "gethostkeys: malloc of buffer failed");
		*error = ENOMEM;
		return (__NSW_UNAVAIL);
	}

	while (gethostent_r(&ent, buffer, bufferlen, error)) {
		/*
		 * add canonical name
		 */
		if (add_dir_entry(ent.h_name, list, &last)) {
			*error = ENOMEM;
			goto done;
		}
		if (ent.h_aliases == NULL)
			goto done;	/* no aliases */
		for (p = ent.h_aliases; *p != 0; p++) {
			if (strcmp(*p, ent.h_name) != 0) {
				/*
				 * add alias only if different
				 * from canonical name
				 */
				if (add_dir_entry(*p, list, &last)) {
					*error = ENOMEM;
					goto done;
				}
			}
		}
		assert(last != NULL);
	}
done:	if (*list != NULL) {
		/*
		 * list of entries found
		 */
		*error = 0;
	}
	endhostent();

	return (__NSW_SUCCESS);
}

/*
 * enumerate all entries in the map in the various name services.
 */
int
getmapkeys(mapname, list, error, cache_time, stack, stkptr, uid)
	char *mapname;
	struct dir_entry **list;
	int *error;
	int *cache_time;
	char **stack, ***stkptr;
	uid_t uid;

{
	struct __nsw_lookup *curr_ns = NULL;
	int ns_err = __NSW_SUCCESS;
	int success = 0;
	struct ns_info *nsp;

	if (*mapname == '/') 		/* must be a file */
		return (getmapkeys_files(mapname, list, error, cache_time,
				stack, stkptr));
	if (strcmp(mapname, "-hosts") == 0) {
		return (gethostkeys(mapname, list, error, cache_time));
	}

	while ((nsp = get_next_ns(&curr_ns, ns_err)) != NULL) {
		ns_err = nsp->ns_getmapkeys(mapname, list, error,
				cache_time, stack, stkptr);
		if (*error == 0) {
			/*
			 * return success if listing was successful
			 * for at least one name service
			 */
			success++;
		}

		/*
		 * XXX force next name service
		 */
		if (ns_err != __NSW_UNAVAIL)
			ns_err = __NSW_NOTFOUND;
	}
	if (success) {
		/*
		 * if succeeded at least once, return error=0
		 */
		*error = 0;
	};

	return (success ? __NSW_SUCCESS : __NSW_NOTFOUND);
}
