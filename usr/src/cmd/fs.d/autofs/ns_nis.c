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
 *	ns_nis.c
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <nsswitch.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systeminfo.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs_prot.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>
#include <sys/errno.h>
#include "automount.h"

#define	KEY		0
#define	CONTENTS	1

static int replace_undscr_by_dot(char *);
static int nis_err(int);

static char nis_mydomain[YPMAXDOMAIN];

struct dir_cbdata {
	struct dir_entry **list;
	struct dir_entry *last;
	int error;
};

static int readdir_callback(int, char *, int, const char *,
				int, struct dir_cbdata *);

void
init_nis(char **stack, char ***stkptr)
{
#ifdef lint
	stack = stack;
	stkptr = stkptr;
#endif /* lint */

	(void) sysinfo(SI_SRPC_DOMAIN, nis_mydomain, sizeof (nis_mydomain));
}

/*ARGSUSED*/
int
getmapent_nis(key, map, ml, stack, stkptr, iswildcard, isrestricted)
	char *key, *map;
	struct mapline *ml;
	char **stack;
	char ***stkptr;
	bool_t *iswildcard;
	bool_t isrestricted;
{
	char *nisline = NULL;
	char *my_map = NULL;
	char *lp, *lq;
	int nislen, len;
	int nserr;

	if (iswildcard)
		*iswildcard = FALSE;
	nserr = yp_match(nis_mydomain, map, key, strlen(key),
						&nisline, &nislen);
	if (nserr == YPERR_MAP) {
		my_map = strdup(map);
		if (my_map == NULL) {
			syslog(LOG_ERR,
				"getmapent_nis: memory alloc failed: %m");
			return (__NSW_UNAVAIL);
		}
		if (replace_undscr_by_dot(my_map))
			nserr = yp_match(nis_mydomain, my_map, key,
					strlen(key), &nisline, &nislen);
	}

	if (nserr) {
		if (nserr == YPERR_KEY) {
			/*
			 * Try the default entry "*"
			 */
			if (my_map == NULL)
				nserr = yp_match(nis_mydomain, map, "*", 1,
						&nisline, &nislen);
			else
				nserr = yp_match(nis_mydomain, my_map, "*", 1,
						&nisline, &nislen);
			if (!nserr && iswildcard)
				*iswildcard = TRUE;
		} else {
			if (verbose)
				syslog(LOG_ERR, "%s: %s",
					map, yperr_string(nserr));
			nserr = 1;
		}
	}
	if (my_map != NULL)
		free(my_map);

	nserr = nis_err(nserr);
	if (nserr)
		goto done;

	/*
	 * at this point we are sure that yp_match succeeded
	 * so massage the entry by
	 * 1. ignoring # and beyond
	 * 2. trim the trailing whitespace
	 */
	if (lp = strchr(nisline, '#'))
		*lp = '\0';
	len = strlen(nisline);
	if (len == 0) {
		nserr = __NSW_NOTFOUND;
		goto done;
	}
	lp = &nisline[len - 1];
	while (lp > nisline && isspace(*lp))
		*lp-- = '\0';
	if (lp == nisline) {
		nserr = __NSW_NOTFOUND;
		goto done;
	}
	(void) strcpy(ml->linebuf, nisline);
	lp = ml->linebuf;
	lq = ml->lineqbuf;
	unquote(lp, lq);
	/* now we have the correct line */

	nserr = __NSW_SUCCESS;
done:
	if (nisline)
		free((char *)nisline);
	return (nserr);

}

int
loadmaster_nis(mapname, defopts, stack, stkptr)
	char *mapname, *defopts;
	char **stack;
	char ***stkptr;
{
	int first, err;
	char *key, *nkey, *val;
	int kl, nkl, vl;
	char dir[256], map[256], qbuff[256];
	char *pmap, *opts, *my_mapname;
	int count = 0;

	first = 1;
	key  = NULL; kl  = 0;
	nkey = NULL; nkl = 0;
	val  = NULL; vl  = 0;

	/*
	 * need a private copy of mapname, because we may change
	 * the underscores by dots. We however do not want the
	 * orignal to be changed, as we may want to use the
	 * original name in some other name service
	 */
	my_mapname = strdup(mapname);
	if (my_mapname == NULL) {
		syslog(LOG_ERR, "loadmaster_yp: memory alloc failed: %m");
		/* not the name svc's fault but ... */
		return (__NSW_UNAVAIL);
	}
	for (;;) {
		if (first) {
			first = 0;
			err = yp_first(nis_mydomain, my_mapname,
				&nkey, &nkl, &val, &vl);

			if ((err == YPERR_MAP) &&
			    (replace_undscr_by_dot(my_mapname)))
				err = yp_first(nis_mydomain, my_mapname,
					&nkey, &nkl, &val, &vl);

			if ((err == YPERR_DOMAIN) || (err == YPERR_YPBIND)) {
				syslog(LOG_ERR,
					"can't read nis map %s: %s - retrying",
					my_mapname, yperr_string(err));
				while ((err == YPERR_DOMAIN) ||
					(err == YPERR_YPBIND)) {
					(void) sleep(20);
					err = yp_first(nis_mydomain, my_mapname,
						&nkey, &nkl, &val, &vl);
				}
				syslog(LOG_ERR,
					"nis map %s: read OK.", my_mapname);
			}
		} else {
			err = yp_next(nis_mydomain, my_mapname, key, kl,
				&nkey, &nkl, &val, &vl);
		}
		if (err) {
			if (err != YPERR_NOMORE && err != YPERR_MAP)
				if (verbose)
					syslog(LOG_ERR, "%s: %s",
					my_mapname, yperr_string(err));
			break;
		}
		if (key)
			free(key);
		key = nkey;
		kl = nkl;


		if (kl >= 256 || vl >= 256)
			break;
		if (kl < 2 || vl < 1)
			break;
		if (isspace(*key) || *key == '#')
			break;
		(void) strncpy(dir, key, kl);
		dir[kl] = '\0';
		if (macro_expand("", dir, qbuff, sizeof (dir))) {
			syslog(LOG_ERR,
			    "%s in NIS map %s: entry too long (max %d chars)",
			    dir, my_mapname, sizeof (dir) - 1);
			break;
		}
		(void) strncpy(map, val, vl);
		map[vl] = '\0';
		if (macro_expand(dir, map, qbuff, sizeof (map))) {
			syslog(LOG_ERR,
			    "%s in NIS map %s: entry too long (max %d chars)",
			    map, my_mapname, sizeof (map) - 1);
			break;
		}
		pmap = map;
		while (*pmap && isspace(*pmap))
			pmap++;		/* skip blanks in front of map */
		opts = pmap;
		while (*opts && !isspace(*opts))
			opts++;
		if (*opts) {
			*opts++ = '\0';
			while (*opts && isspace(*opts))
				opts++;
			if (*opts == '-')
				opts++;
			else
				opts = defopts;
		}
		free(val);

		/*
		 * Check for no embedded blanks.
		 */
		if (strcspn(opts, " 	") == strlen(opts)) {
			dirinit(dir, pmap, opts, 0, stack, stkptr);
			count++;
		} else {
pr_msg("Warning: invalid entry for %s in NIS map %s ignored.\n", dir, mapname);
		}

	}
	if (my_mapname)
		free(my_mapname);

	/*
	 * In the context of a master map, if no entry is
	 * found, it is like NOTFOUND
	 */
	if (count > 0 && err == YPERR_NOMORE)
		return (__NSW_SUCCESS);
	else {
		if (err)
			return (nis_err(err));
		else
			/*
			 * This case will happen if map is empty
			 *  or none of the entries is valid
			 */
			return (__NSW_NOTFOUND);
	}
}

int
loaddirect_nis(nismap, localmap, opts, stack, stkptr)
	char *nismap, *localmap, *opts;
	char **stack;
	char ***stkptr;
{
	int first, err, count;
	char *key, *nkey, *val, *my_nismap;
	int kl, nkl, vl;
	char dir[100];

	first = 1;
	key  = NULL; kl  = 0;
	nkey = NULL; nkl = 0;
	val  = NULL; vl  = 0;
	count = 0;
	my_nismap = NULL;

	my_nismap = strdup(nismap);
	if (my_nismap == NULL) {
		syslog(LOG_ERR, "loadmaster_yp: memory alloc failed: %m");
		return (__NSW_UNAVAIL);
	}
	for (;;) {
		if (first) {
			first = 0;
			err = yp_first(nis_mydomain, my_nismap, &nkey, &nkl,
					&val, &vl);

			if ((err == YPERR_MAP) &&
			    (replace_undscr_by_dot(my_nismap)))
				err = yp_first(nis_mydomain, my_nismap,
						&nkey, &nkl, &val, &vl);

			if ((err == YPERR_DOMAIN) || (err == YPERR_YPBIND)) {
				syslog(LOG_ERR,
					"can't read nis map %s: %s - retrying",
					my_nismap, yperr_string(err));
				while ((err == YPERR_DOMAIN) ||
					(err == YPERR_YPBIND)) {
					(void) sleep(20);
					err = yp_first(nis_mydomain, my_nismap,
						&nkey, &nkl, &val, &vl);
				}
				syslog(LOG_ERR,
					"nis map %s: read OK.", my_nismap);
			}
		} else {
			err = yp_next(nis_mydomain, my_nismap, key, kl,
					&nkey, &nkl, &val, &vl);
		}
		if (err) {
			if (err != YPERR_NOMORE && err != YPERR_MAP)
				syslog(LOG_ERR, "%s: %s",
					my_nismap, yperr_string(err));
			break;
		}
		if (key)
			free(key);
		key = nkey;
		kl = nkl;

		if (kl < 2 || kl >= 100)
			continue;
		if (isspace(*key) || *key == '#')
			continue;
		(void) strncpy(dir, key, kl);
		dir[kl] = '\0';

		dirinit(dir, localmap, opts, 1, stack, stkptr);
		count++;
		free(val);
	}

	if (my_nismap)
		free(my_nismap);

	if (count > 0 && err == YPERR_NOMORE)
			return (__NSW_SUCCESS);
	else
		return (nis_err(err));

}

static int
replace_undscr_by_dot(map)
	char *map;
{
	int ret_val = 0;

	while (*map) {
		if (*map == '_') {
			ret_val = 1;
			*map = '.';
		}
		map++;
	}
	return (ret_val);
}

static int
nis_err(err)
	int err;
{
	switch (err) {
	case 0:
		return (__NSW_SUCCESS);
	case YPERR_KEY:
		return (__NSW_NOTFOUND);
	case YPERR_MAP:
		return (__NSW_UNAVAIL);
	default:
		return (__NSW_UNAVAIL);
	}
}

int
getmapkeys_nis(nsmap, list, error, cache_time, stack, stkptr)
	char *nsmap;
	struct dir_entry **list;
	int *error;
	int *cache_time;
	char **stack;
	char ***stkptr;
{
	int nserr;
	struct dir_cbdata readdir_cbdata;
	struct ypall_callback cback;
	char *my_map = NULL;

	char *key = NULL, *val = NULL;
	int nkl, vl;

#ifdef lint
	stack = stack;
	stkptr = stkptr;
#endif /* lint */

	*cache_time = RDDIR_CACHE_TIME;

	/*
	 * XXX Hack to determine if we need to replace '_' with '.'
	 * Have to use yp_first() since yp_all() simply fails if
	 * the map is not present
	 */
	my_map = strdup(nsmap);
	if (my_map == NULL) {
		syslog(LOG_ERR,
			"getmapkeys_nis: memory alloc failed: %m");
		*error = ENOMEM;
		return (__NSW_UNAVAIL);
	}
	nserr = yp_first(nis_mydomain, my_map, &key, &nkl, &val, &vl);
	if (nserr == YPERR_MAP) {
		if (replace_undscr_by_dot(my_map)) {
			nserr = yp_first(nis_mydomain, my_map,
					&key, &nkl, &val, &vl);
		}
		if (nserr == YPERR_MAP) {
			/*
			 * map not found
			 */
			*error = 0;	/* return an empty list */
			if (verbose) {
				syslog(LOG_ERR, "%s: %s",
					nsmap, yperr_string(nserr));
			}
			free(my_map);
			return (nis_err(nserr));
		}
	}
	if (key)
		free(key);
	if (val)
		free(val);

	readdir_cbdata.list = list;
	readdir_cbdata.last = NULL;
	readdir_cbdata.error = 0;

	cback.foreach = readdir_callback;
	cback.data = (char *)&readdir_cbdata;

	/*
	 * after all this song and dance we finally
	 * ask for the list of entries
	 */
	nserr = yp_all(nis_mydomain, my_map, &cback);

	free(my_map);
	*error = readdir_cbdata.error;
	if (nserr) {
		if (verbose)
			syslog(LOG_ERR, "%s: %s", nsmap, yperr_string(nserr));
		nserr = 1;
		if (*error == 0)
			*error = ENOENT;

		return (nis_err(nserr));
	}

	return (__NSW_SUCCESS);
}

static int
readdir_callback(instatus, inkey, inkeylen, inval, invallen, indata)
	int instatus;
	char *inkey;
	int inkeylen;
	const char *inval;
	int invallen;
	struct dir_cbdata *indata;
{
	struct dir_entry **list = indata->list;
	struct dir_entry *last = indata->last;
	char key[MAXPATHLEN];

#ifdef lint
	inval = inval;
	invallen = invallen;
#endif

	if (instatus != YP_TRUE)
		return (0);	/* next entry. yp_all may decide otherwise... */

	if (inkeylen == 0 || isspace(*inkey) || *inkey == '#')
		return (0);

	/*
	 * yp_all allocates inkey with two extra bytes which contain
	 * NEWLINE and null but these two bytes are not reflected in
	 * inkeylen.
	 */
	strncpy(key, inkey, inkeylen);
	key[inkeylen] = '\0';

	/*
	 * Wildcard entry should be ignored - following entries should continue
	 * to be read to corroborate with the way we search for entries in yp,
	 * i.e., first for an exact key match and then a wildcard, if there's
	 * no exact key match.
	 */
	if (key[0] == '*' && key[1] == '\0')
		return (0);

	if (add_dir_entry(key, list, &last)) {
		indata->error = ENOMEM;
		return (1);	/* get no more entries */
	}

	indata->last = last;
	indata->error = 0;

	return (0);
}
