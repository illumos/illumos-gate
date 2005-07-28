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
 *	ns_nisplus.c
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <nsswitch.h>
#include <sys/param.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs_prot.h>
#include <rpcsvc/nis.h>
#include <sys/errno.h>
#include "automount.h"

#define	KEY		0
#define	CONTENTS	1

/*
 * The following macro is for making the values returned
 * from name services switch compatible. Earlier when a
 * name service returned 0 it meant it could not find
 * the requested stuff and a ret val of > 0 implied
 * success. This is opposite of what switch expects
 */
nis_result *__nis_list_localcb(nis_name, ulong_t,
		int (*)(nis_name, nis_object *, void *), void *);

static int mastermap_callback(char *, nis_object *, void *);
static int directmap_callback(char *, nis_object *, void *);
static int nisplus_err(int);
static int nisplus_match(char *, char *, char *, char **, int *);
static int readdir_callback(char *, nis_object *, void *);

static char *nisplus_subdomain = NULL;

struct loadmaster_cbdata {
	char *ptr1;
	char **ptr2;
	char ***ptr3;
};

struct loaddirect_cbdata {
	char *ptr1;
	char *ptr2;
	char **ptr3;
	char ***ptr4;
};

struct dir_cbdata {
	struct dir_entry **list;
	struct dir_entry *last;
	int error;
};

void
init_nisplus(char **stack, char ***stkptr)
{

#ifdef lint
	stack = stack;
	stkptr = stkptr;
#endif /* lint */

	nisplus_subdomain = "org_dir";
}

/*ARGSUSED*/
int
getmapent_nisplus(key, map, ml, stack, stkptr, iswildcard, isrestricted)
	char *key;
	char *map;
	struct mapline *ml;
	char **stack;
	char ***stkptr;
	bool_t *iswildcard;
	bool_t isrestricted;
{
	char *nis_line = NULL;
	char *lp;
	int nis_len, len;
	int nserr;

	if (iswildcard)
		*iswildcard = FALSE;
	nserr = nisplus_match(map, "key", key, &nis_line, &nis_len);
	if (nserr) {
		if (nserr == __NSW_NOTFOUND) {
			/* Try the default entry "*" */
			if ((nserr = nisplus_match(map, "key", "*", &nis_line,
						    &nis_len)))
				goto done;
			else {
				if (iswildcard)
					*iswildcard = TRUE;
			}
		} else
			goto done;
	}

	/*
	 * at this point we are sure that nisplus_match
	 * succeeded so massage the entry by
	 * 1. ignoring # and beyond
	 * 2. trim the trailing whitespace
	 */
	if (lp = strchr(nis_line, '#'))
		*lp = '\0';
	len = strlen(nis_line);
	if (len == 0) {
		nserr = __NSW_NOTFOUND;
		goto done;
	}
	lp = &nis_line[len - 1];
	while (lp > nis_line && isspace(*lp))
		*lp-- = '\0';
	if (lp == nis_line) {
		nserr = __NSW_NOTFOUND;
		goto done;
	}
	(void) strcpy(ml->linebuf, nis_line);
	unquote(ml->linebuf, ml->lineqbuf);
	nserr = __NSW_SUCCESS;
done:
	if (nis_line)
		free((char *)nis_line);

	return (nserr);
}

int
loadmaster_nisplus(mapname, defopts, stack, stkptr)
	char *mapname;
	char *defopts;
	char **stack;
	char ***stkptr;
{
	char indexedname[NIS_MAXNAMELEN];
	nis_result *res = NULL;
	int err;
	struct loadmaster_cbdata master_cbdata;

	if (nisplus_subdomain == NULL)
		return (__NSW_UNAVAIL);

	(void) strcpy(indexedname, mapname);
	if (strchr(mapname, '.') == NULL) {
		(void) strcat(indexedname, ".");
		(void) strcat(indexedname, nisplus_subdomain);
	}

	master_cbdata.ptr1 = defopts;
	master_cbdata.ptr2 = stack;
	master_cbdata.ptr3 = stkptr;

	res = __nis_list_localcb(indexedname,
			EXPAND_NAME | FOLLOW_LINKS | FOLLOW_PATH |
			HARD_LOOKUP | ALL_RESULTS,
			mastermap_callback, (void *) &master_cbdata);
	if (res == NULL)
		return (__NSW_UNAVAIL);

	if (res->status != NIS_CBRESULTS) {
		if (verbose)
			syslog(LOG_ERR, "nisplus can't list map, %s: %s",
				mapname, nis_sperror(res->status,
						    "nis_list failed"));
		err = res->status;
		nis_freeresult(res);

		return (nisplus_err(err));
	}

	nis_freeresult(res);
	return (__NSW_SUCCESS);
}

int
loaddirect_nisplus(nsmap, localmap, opts, stack, stkptr)
	char *nsmap, *localmap, *opts;
	char **stack;
	char ***stkptr;
{
	char indexedname[NIS_MAXNAMELEN];
	struct loaddirect_cbdata direct_cbdata;
	nis_result *res = NULL;
	int err;

	if (nisplus_subdomain == NULL)
		return (__NSW_UNAVAIL);

	(void) strcpy(indexedname, nsmap);
	if (strchr(nsmap, '.') == NULL) {
		(void) strcat(indexedname, ".");
		(void) strcat(indexedname, nisplus_subdomain);
	}
	direct_cbdata.ptr1 = opts;
	direct_cbdata.ptr2 = localmap;
	direct_cbdata.ptr3 = stack;
	direct_cbdata.ptr4 = stkptr;

	res = __nis_list_localcb(indexedname,
			EXPAND_NAME | FOLLOW_LINKS | FOLLOW_PATH |
			HARD_LOOKUP | ALL_RESULTS,
			directmap_callback, (void *)&direct_cbdata);
	if (res == NULL)
		return (__NSW_UNAVAIL);

	if (res->status != NIS_CBRESULTS) {
		if (verbose)
			syslog(LOG_ERR, "nisplus can't list map, %s: %s",
				nsmap, nis_sperror(res->status,
						"nis_list failed"));
		err = res->status;
		nis_freeresult(res);

		return (nisplus_err(err));
	}

	nis_freeresult(res);
	return (__NSW_SUCCESS);
}

static int
nisplus_err(err)
	int err;
{
	switch (err) {

	case NIS_SUCCESS:
	case NIS_S_SUCCESS:
		return (__NSW_SUCCESS);

	case NIS_NOTFOUND:
	case NIS_S_NOTFOUND:
		return (__NSW_NOTFOUND);

	case NIS_TRYAGAIN:
		return (__NSW_TRYAGAIN);

	default:
		return (__NSW_UNAVAIL);
	}
}


/*
 * The first param is not used, but it is reqd
 * because this function is called by nisplus
 * library functions
 */
/* ARGSUSED */
static int
mastermap_callback(tab, ent, udata)
	char *tab;
	nis_object *ent;
	void *udata;
{
	char *key, *contents, *pmap, *opts;
	char dir[256], map[256], qbuff[256];
	int  key_len, contents_len;
	register entry_col *ec = ent->EN_data.en_cols.en_cols_val;
	struct loadmaster_cbdata *temp = (struct loadmaster_cbdata *)udata;
	char *defopts = temp->ptr1;
	char **stack = temp->ptr2;
	char ***stkptr = temp->ptr3;
	int i;

	key_len = ec[KEY].ec_value.ec_value_len;
	contents_len = ec[CONTENTS].ec_value.ec_value_len;

	if (key_len >= 256 || contents_len >= 256)
		return (0);
	if (key_len < 2 || contents_len < 2)
		return (0);

	key = ec[KEY].ec_value.ec_value_val;
	contents = ec[CONTENTS].ec_value.ec_value_val;
	while (isspace(*contents))
		contents++;
	if (contents == NULL)
		return (0);
	if (isspace(*key) || *key == '#')
		return (0);
	(void) strncpy(dir, key, key_len);
	dir[key_len] = '\0';
	for (i = 0; i < 256; i++)
		qbuff[i] = ' ';
	if (macro_expand("", dir, qbuff, sizeof (dir))) {
		syslog(LOG_ERR,
		    "%s in nisplus master map: entry too long (max %d chars)",
		    dir, sizeof (dir) - 1);
		return (0);
	}
	(void) strncpy(map, contents, contents_len);
	map[contents_len] = '\0';
	for (i = 0; i < 256; i++)
		qbuff[i] = ' ';
	if (macro_expand("", map, qbuff, sizeof (map))) {
		syslog(LOG_ERR,
		    "%s in nisplus master map: entry too long (max %d chars)",
		    map, sizeof (map) - 1);
		return (0);
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
	/*
	 * Check for no embedded blanks.
	 */
	if (strcspn(opts, " 	") == strlen(opts)) {
		dirinit(dir, pmap, opts, 0, stack, stkptr);
	} else
pr_msg("Warning: invalid entry for %s in nisplus map %s ignored.\n",
		    dir, ent->zo_name);
	return (0);
}

/*
 * The first param is not used, but it is reqd
 * because this function is called by nisplus
 * library functions
 */
/* ARGSUSED */
static int
directmap_callback(tab, ent, udata)
	char *tab;
	nis_object *ent;
	void *udata;
{
	char *key;
	char dir[256];
	int  key_len;
	struct loaddirect_cbdata *temp = (struct loaddirect_cbdata *)udata;
	char *opts = temp->ptr1;
	char *localmap = temp->ptr2;
	char **stack = temp->ptr3;
	char ***stkptr = temp->ptr4;

	register entry_col *ec = ent->EN_data.en_cols.en_cols_val;

	key_len = ec[KEY].ec_value.ec_value_len;
	if (key_len >= 100 || key_len < 2)
		return (0);

	key = ec[KEY].ec_value.ec_value_val;
	if (isspace(*key) || *key == '#')
		return (0);
	(void) strncpy(dir, key, key_len);
	dir[key_len] = '\0';

	dirinit(dir, localmap, opts, 1, stack, stkptr);

	return (0);
}

static int
nisplus_match(map, colm_name, key, nis_line, nis_len)
	char *map, *colm_name, *key;
	char **nis_line;
	int  *nis_len;
{
	nis_result *res = NULL;
	int err;
	entry_col *ent;
	char indexedname[NIS_MAXNAMELEN];

	if (nisplus_subdomain == NULL)
		return (__NSW_UNAVAIL);

	if (*map != '[')
		(void) sprintf(indexedname, "[%s=%s],%s",
				colm_name, key, map);
	else
		(void) strcpy(indexedname, map);

	if (strchr(map, '.') == NULL) {
		(void) strcat(indexedname, ".");
		(void) strcat(indexedname, nisplus_subdomain);
	}

	if (trace > 1)
		trace_prt(1, "  nisplus_match: Requesting list for %s\n",
				indexedname);

	res = nis_list(indexedname,
			USE_DGRAM | EXPAND_NAME | FOLLOW_LINKS |
			FOLLOW_PATH | ALL_RESULTS,
			NULL, NULL);

	if (trace > 1) {
		if ((res == NULL) ||
			((res->status != NIS_SUCCESS) &&
			(res->status != NIS_S_SUCCESS)))
			trace_prt(1, "  nisplus_match: nis_list FAILED\n");
		else
			trace_prt(1, "  nisplus_match: nis_list OK\n");
	}

	if (res == NULL)
		return (__NSW_UNAVAIL);

	if (res->status != NIS_SUCCESS && res->status != NIS_S_SUCCESS) {
		if (verbose && res->status != NIS_NOTFOUND)
			syslog(LOG_ERR, "nisplus can't list map, %s: %s", map,
				nis_sperror(res->status, "nis_list failed"));
		err = res->status;
		nis_freeresult(res);

		return (nisplus_err(err));
	}

	ent = res->objects.objects_val->EN_data.en_cols.en_cols_val;

	if (ent == NULL ||
	    ent[KEY].ec_value.ec_value_val == NULL ||
	    strcmp(ent[KEY].ec_value.ec_value_val, key) != 0) {
		nis_freeresult(res);
		return (__NSW_NOTFOUND);
	}

	if (ent[CONTENTS].ec_value.ec_value_len == 0 ||
	    ent[CONTENTS].ec_value.ec_value_val == NULL) {
		if (verbose)
			syslog(LOG_ERR,
		    "nisplus map %s, entry for %s has NULL value field",
			    map, key);
		nis_freeresult(res);
		return (__NSW_UNAVAIL);
	}

	*nis_len = ent[CONTENTS].ec_value.ec_value_len +
		ent[KEY].ec_value.ec_value_len;
	/*
	 * so check for the length; it should be less than LINESZ
	 */
	if ((*nis_len + 2) > LINESZ) {
		syslog(LOG_ERR, "nisplus map %s, entry for %s"
			" is too long %d chars (max %d)",
		    map, key, (*nis_len + 2), LINESZ);
		nis_freeresult(res);
		return (__NSW_UNAVAIL);
	}
	*nis_line = (char *)malloc(*nis_len + 2);
	if (*nis_line == NULL) {
		syslog(LOG_ERR, "nisplus_match: malloc failed");
		nis_freeresult(res);
		return (__NSW_UNAVAIL);
	}

	(void) sprintf(*nis_line, "%s", ent[CONTENTS].ec_value.ec_value_val);
	nis_freeresult(res);

	return (__NSW_SUCCESS);
}


int
getmapkeys_nisplus(nsmap, list, error, cache_time, stack, stkptr)
	char *nsmap;
	struct dir_entry **list;
	int *error;
	int *cache_time;
	char **stack;
	char ***stkptr;
{
	char indexedname[NIS_MAXNAMELEN];
	struct dir_cbdata readdir_cbdata;
	nis_result *res = NULL;
	int err;

#ifdef lint
	stack = stack;
	stkptr = stkptr;
#endif /* lint */

	if (trace > 1)
		trace_prt(1, "getmapkeys_nisplus called\n");

	*cache_time = RDDIR_CACHE_TIME;
	*error = 0;
	if (nisplus_subdomain == NULL)
		return (__NSW_UNAVAIL);

	(void) strcpy(indexedname, nsmap);
	if (strchr(nsmap, '.') == NULL) {
		(void) strcat(indexedname, ".");
		(void) strcat(indexedname, nisplus_subdomain);
	}
	readdir_cbdata.list = list;
	readdir_cbdata.last = NULL;
	res = __nis_list_localcb(indexedname,
			EXPAND_NAME | FOLLOW_LINKS | FOLLOW_PATH | HARD_LOOKUP,
			readdir_callback, (void *)&readdir_cbdata);
	if (res == NULL)
		return (__NSW_UNAVAIL);

	if (readdir_cbdata.error)
		*error = readdir_cbdata.error;
	if (res->status != NIS_CBRESULTS) {
		printf("nisplus can't list map, %s: %s",
				nsmap, nis_sperror(res->status,
				"nis_list failed"));
		err = res->status;
		nis_freeresult(res);

		if (*error == 0)
			*error = ECOMM;
		return (nisplus_err(err));
	}

	nis_freeresult(res);

	return (__NSW_SUCCESS);
}

/*
 * The first param is not used, but it is reqd
 * because this function is called by nisplus
 * library functions
 */
/* ARGSUSED */
static int
readdir_callback(tab, ent, udata)
	char *tab;
	nis_object *ent;
	void *udata;
{
	char *key;
	int  key_len;
	struct dir_cbdata *temp = (struct dir_cbdata *)udata;
	struct dir_entry **list = temp->list;
	struct dir_entry *last = temp->last;
	register entry_col *ec = ent->EN_data.en_cols.en_cols_val;

	key_len = ec[KEY].ec_value.ec_value_len;
	if (key_len >= 100 || key_len < 2)
		return (0);

	key = ec[KEY].ec_value.ec_value_val;
	if (isspace(*key) || *key == '#')
		return (0);

	/*
	 * Wildcard entry should be ignored - following entries should continue
	 * to be read to corroborate with the way we search for entries in
	 * NIS+, i.e., first for an exact key match and then a wildcard
	 * if there's no exact key match.
	 */
	if (key[0] == '*' && key[1] == '\0')
		return (0);

	if (add_dir_entry(key, list, &last)) {
		temp->error = ENOMEM;
		return (1);
	}

	temp->last = last;
	temp->error = 0;

	return (0);
}
