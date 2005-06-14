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
 *	makelocalcred.c
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * makelocalcred.c
 *
 * Make a "local" credential. The local credential is used to map from
 * a UID in the nis_local_directory() to a principal name in some other
 * NIS+ directory. Needless to say the principal name is required and
 * this function must be run as the NIS+ administrator.
 */

#include <stdio.h>
#include <pwd.h>
#include <limits.h>
#include <rpcsvc/nis.h>
#include "nisaddcred.h"

/*
 * _getgroupsbymember(uname, gid_array, maxgids, numgids):
 *	This function can be found in libc/port/gen/getgrnam_r.c.
 *	It's a private interface mainly for initgroups().  It returns the
 *	group ids of groups of which the specified user is a member.
 */
extern int _getgroupsbymember(const char *, gid_t[], int, int);

#define	EVAL(e, c) (ENTRY_LEN(e, c) > 0 ? ENTRY_VAL(e, c) : "")

struct cback_info {
    char *username;
    int gidcnt;
    int maxgids;
    gid_t *gidlist;
};

static
int
add_gidval(info, gid)
	struct cback_info *info;
	gid_t gid;
{
	int i;

	for (i = 0; i < info->gidcnt; i++) {
		if (info->gidlist[i] == gid)
			return (1);    /* don't insert dup, but not error */
	}
	if (info->gidcnt >= info->maxgids)
		return (0);    /* no room */

	info->gidlist[info->gidcnt] = gid;
	info->gidcnt++;

	return (1);
}

int
cback(table, entry, udata)
	nis_name table;
	nis_object *entry;
	void *udata;
{
	struct cback_info *info = (struct cback_info *)udata;
	char *username = info->username;
	int len;
	char *p;
	char *members;
	char *gid;
	char *gname;
	int gidval;

	len = strlen(username);

	members = EVAL(entry, 3);
	while (*members) {
		while (*members && isspace(*members))
			members++;
		if (*members == '\0')
			break;

		p = members;
		while (*members && *members != ',')
			members++;

		if (members - p == len && strncmp(p, username, len) == 0) {
			gid = EVAL(entry, 2);
			if (isdigit(gid[0])) {
				gidval = atoi(gid);
				if (! add_gidval(info, gidval))
					return (1);   /* no more room */
			}
		}

		if (*members == ',')
			members++;
	}

	return (0);
}

/*
 *  Get groups from an NIS+ domain.  If that doesn't yield any
 *  groups and the domain was not specified on the command line,
 *  then we try the local routines for getting group ids.
 */
static
int
__getnisgroupsbymember(domain, uid, username, basegid, maxgids, gidlist)
	char *domain;
	uid_t uid;
	char *username;
	gid_t basegid;
	int maxgids;
	gid_t *gidlist;
{
	struct cback_info info;
	nis_result *res;
	char name[1024];
	u_long flags = EXPAND_NAME|MASTER_ONLY|FOLLOW_PATH|FOLLOW_LINKS;

	info.username = username;
	info.gidcnt = 0;
	info.maxgids = NGROUPS_MAX;
	info.gidlist = gidlist;

	add_gidval(&info, basegid);

	sprintf(name, "group.org_dir.%s", domain);
	res = nis_list(name, flags, cback, (void *)&info);
	nis_freeresult(res);

#ifdef USE_LOCAL_INFO
	/*
	 * If no domain was specified on the command line and we didn't get
	 * any extra gids from NIS+, then try getting them locally.
	 */
	if (! explicit_domain && info.gidcnt == 1) {
		if (uid == my_uid)
			info.gidcnt = getgroups(info.maxgids, info.gidlist);
		else
			info.gidcnt = _getgroupsbymember(username, info.gidlist,
						    info.maxgids, 1);

		/* if getgroups failed, put basegid back in list */
		if (info.gidcnt <= 0) {
			info.gidcnt = 0;
			add_gidval(&info, basegid);
		}
	}
#endif /* USE_LOCAL_INFO */

	return (info.gidcnt);
}

int
make_local_cred(nisprinc, uidstr, domain, flavor)
	char	*nisprinc;
	char	*uidstr;
	char	*domain;
	char	*flavor; /* Ignored. */
{
	nis_object	*obj = init_entry();
	nis_error	err;
	int		i, gidlen;
	uid_t		uid;
	gid_t		gidlist[NGROUPS_MAX];
	struct passwd	*pw;
	char		nisname[NIS_MAXNAMELEN+1],
			pdata[NIS_MAXATTRVAL+1],
			gidstr[MAXIPRINT+1];
	int		status, addition;
	struct passwd	*domain_getpwuid();

	if (!isdigit(*uidstr)) {
		fprintf(stderr,
			"%s: invalid local principal '%s' (must be number)\n",
			program_name, uidstr);
		return (0);
	}

	uid = (uid_t)atoi(uidstr);
	if (uid == 0) {
		fprintf(stderr, "%s: need not add LOCAL entry for root\n",
			program_name);
		return (0);
	}

	pw = domain_getpwuid(domain, uid);
	if (!pw)
		return (0);

	if (nisprinc == 0)
		sprintf(nisname, "%s.%s", pw->pw_name, domain);
	else
		strcpy(nisname, nisprinc);

	/* Another principal owns same credentials? (exits if that happens) */
	(void) auth_exists(nisname, uidstr, "LOCAL", domain);

	addition = (cred_exists(nisname, "LOCAL", domain) == NIS_NOTFOUND);

	/* build up list of group ids */
	if ((gidlen = __getnisgroupsbymember(domain, uid,
			pw->pw_name, pw->pw_gid, NGROUPS_MAX, gidlist)) <= 0) {
		fprintf(stderr,
		"Failed to get group information for user %s\n", pw->pw_name);
		return (0);
	}
	pdata[0] = '\0';
	for (i = 0; i < gidlen; i++) {
		if ((i + 1) < gidlen)
			sprintf(gidstr, "%d,", gidlist[i]);
		else
			sprintf(gidstr, "%d", gidlist[i]);
		strcat(pdata, gidstr);
	}

	ENTRY_VAL(obj, 0) = nisname;
	ENTRY_LEN(obj, 0) = strlen(nisname) + 1;

	ENTRY_VAL(obj, 1) = "LOCAL";
	ENTRY_LEN(obj, 1) = 6;

	ENTRY_VAL(obj, 2) = uidstr;
	ENTRY_LEN(obj, 2) = strlen(uidstr)+1;

	ENTRY_VAL(obj, 3) = pdata;
	ENTRY_LEN(obj, 3) = strlen(pdata) + 1;

	ENTRY_VAL(obj, 4) = "";
	ENTRY_LEN(obj, 4) = 0;

	if (addition) {
		obj->zo_owner = my_nisname;
		obj->zo_group = my_group;
		obj->zo_domain = domain;
		/* owner: rmcd, group: rmcd */
		obj->zo_access = ((NIS_READ_ACC|NIS_MODIFY_ACC|
				NIS_CREATE_ACC|NIS_DESTROY_ACC)<<8) |
				((NIS_READ_ACC|NIS_MODIFY_ACC|
				NIS_CREATE_ACC|NIS_DESTROY_ACC)<<16);
		status = add_cred_obj(obj, domain);
	} else {
		/* columns that could have changed */
		obj->EN_data.en_cols.en_cols_val[2].ec_flags |= EN_MODIFIED;
		obj->EN_data.en_cols.en_cols_val[3].ec_flags |= EN_MODIFIED;

		status = modify_cred_obj(obj, domain);
	}
	return (status);
}




/*
 * Return a string representation of the "LOCAL" authentication name.
 * In this case it is easy, its our uid.
 */
char *
get_local_cred(domain, flavor)
	char *domain;   /* ignored  for local case */
	char *flavor;	/* ignored */
{
	static char 	myname[MAXIPRINT];

	sprintf(myname, "%d", my_uid);
	return (myname);
}
