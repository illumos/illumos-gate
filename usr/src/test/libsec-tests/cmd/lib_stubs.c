/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 RackTop Systems, Inc.
 */

/*
 * Stubs to replace libidmap and libc calls for these test programs.
 * See -Wl,-zinterpose in Makefile
 */


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <pwd.h>
#include <grp.h>
#include "idmap.h"

struct mapping {
	uid_t pid;
	int is_user;
	char *sid;	/* may be NULL */
	char *name;
	char *domain;	/* may be NULL */
};

struct mapping mappings[] = {
	/* User and group with no SID, no domain */
	{
		.pid = 501,
		.is_user = 1,
		.sid = NULL,
		.name = "user501",
		.domain = NULL
	},
	{
		.pid = 502,
		.is_user = 0,
		.sid = NULL,
		.name = "group502",
		.domain = NULL
	},
	/* Users and groups with SID, names, domains of various length. */
	{
		.pid = 0x80000001,
		.is_user = 1,
		.sid = "S-1-5-21-1813420391-1960978090-3893453001-1001",
		.name = "user1001",
		.domain = "test-domain-name"
	},
	{
		.pid = 0x80000002,
		.is_user = 0,
		.sid = "S-1-5-21-1813420391-1960978090-3893453001-1002",
		.name = "group1002",
		.domain = "test-domain-name"
	},
	{
		.pid = 0x80000003,
		.is_user = 0,
		.sid = "S-1-5-21-1813420391-1960978090-3893453001-1003",
		.name = "group1003-name-really-crazy-long-long"
			"-long-long-long-long-long-long-long",
		.domain = "test-domain-name"
	},
	{
		.pid = 0x80000004,
		.is_user = 0,
		.sid = "S-1-5-21-1813420391-1960978090-3893453002-2002",
		.name = "group2002",
		.domain = "test-domain-name-somewhat-longer"
	},
	{
		.pid = 0x80000005,
		.is_user = 0,
		.sid = "S-1-5-21-1813420391-1960978090-3893453003-3003",
		.name = "group3003",
		.domain = "test-domain-name-really-crazy-long"
			"-long-long-long-long-long-long-long-long"
	},
	{
		.pid = 0
	}
};


idmap_get_handle_t *stub_idmh = (idmap_get_handle_t *)0x40;

idmap_stat
idmap_get_create(idmap_get_handle_t **gh)
{
	*gh = stub_idmh;
	return (0);
}

void
idmap_get_destroy(idmap_get_handle_t *gh)
{
}

idmap_stat
idmap_get_mappings(idmap_get_handle_t *gh)
{
	if (gh != stub_idmh)
		return (IDMAP_ERR_ARG);
	return (0);
}


/*
 * Get winname given pid
 */
idmap_stat
idmap_getwinnamebypid(uid_t pid, int is_user, int flag, char **name,
    char **domain)
{
	struct mapping	*mp;

	if (name == NULL)
		return (IDMAP_ERR_ARG);

	/* Get mapping */
	for (mp = mappings; mp->pid != 0; mp++) {
		if (mp->is_user != is_user)
			continue;
		if (mp->pid == pid)
			break;
	}
	if (mp->pid == 0 || mp->name == NULL || mp->domain == NULL)
		return (IDMAP_ERR_NORESULT);

	if (domain != NULL) {
		*name = strdup(mp->name);
		*domain = strdup(mp->domain);
	} else {
		(void) asprintf(name, "%s@%s", mp->name, mp->domain);
	}

	return (0);
}

idmap_stat
idmap_getwinnamebyuid(uid_t uid, int flag, char **name, char **domain)
{
	return (idmap_getwinnamebypid(uid, 1, flag, name, domain));
}

idmap_stat
idmap_getwinnamebygid(gid_t gid, int flag, char **name, char **domain)
{
	return (idmap_getwinnamebypid(gid, 0, flag, name, domain));
}

idmap_stat
idmap_getpidbywinname(const char *name, const char *domain, int flag,
    uid_t *uid, int is_user)
{
	struct mapping	*mp;

	/* Get mapping */
	for (mp = mappings; mp->pid != 0; mp++) {
		if (mp->is_user != is_user)
			continue;
		if (mp->domain == NULL)
			continue;
		if (strcmp(mp->domain, domain) == 0 &&
		    strcmp(mp->name, name) == 0)
			break;
	}
	if (mp->pid == 0)
		return (IDMAP_ERR_NORESULT);

	*uid = mp->pid;
	return (0);
}


idmap_stat
idmap_getuidbywinname(const char *name, const char *domain, int flag,
    uid_t *uid)
{
	return (idmap_getpidbywinname(name, domain, flag, uid, 1));
}

idmap_stat
idmap_getgidbywinname(const char *name, const char *domain, int flag,
    gid_t *gid)
{
	return (idmap_getpidbywinname(name, domain, flag, gid, 0));
}


idmap_stat
idmap_get_sidbypid(idmap_get_handle_t *gh, uid_t pid, int flag,
    char **sidprefix, idmap_rid_t *rid, idmap_stat *stat, int is_user)
{
	struct mapping	*mp;
	char *p;
	int len;

	/* Get mapping */
	for (mp = mappings; mp->pid != 0; mp++) {
		if (mp->is_user != is_user)
			continue;
		if (mp->pid == pid)
			break;
	}
	if (mp->pid == 0 || mp->sid == NULL)
		goto errout;

	p = strrchr(mp->sid, '-');
	if (p == NULL)
		goto errout;
	len = p - mp->sid;
	*sidprefix = malloc(len + 1);
	if (*sidprefix == NULL)
		goto errout;
	(void) strlcpy(*sidprefix, mp->sid, len + 1);

	*rid = strtol(p + 1, NULL, 10);
	*stat = 0;
	return (0);

errout:
	*stat = IDMAP_ERR_NORESULT;
	return (0);
}

idmap_stat
idmap_get_sidbyuid(idmap_get_handle_t *gh, uid_t uid, int flag,
    char **sidprefix, idmap_rid_t *rid, idmap_stat *stat)
{
	return (idmap_get_sidbypid(gh, uid, flag,
	    sidprefix, rid, stat, 1));
}

idmap_stat
idmap_get_sidbygid(idmap_get_handle_t *gh, gid_t gid, int flag,
    char **sidprefix, idmap_rid_t *rid, idmap_stat *stat)
{
	return (idmap_get_sidbypid(gh, gid, flag,
	    sidprefix, rid, stat, 0));
}

idmap_stat
idmap_get_pidbysid(idmap_get_handle_t *gh, char *sidprefix, idmap_rid_t rid,
    int flag, uid_t *pid, int *is_user, idmap_stat *stat)
{
	char tmpsid[80];
	struct mapping	*mp;

	(void) snprintf(tmpsid, sizeof (tmpsid), "%s-%u", sidprefix, rid);

	/* Get mapping */
	for (mp = mappings; mp->pid != 0; mp++) {
		if (mp->sid != NULL &&
		    strcmp(mp->sid, tmpsid) == 0)
			break;
	}
	if (mp->pid == 0)
		return (IDMAP_ERR_NORESULT);

	*pid = mp->pid;
	*is_user = mp->is_user;
	*stat = 0;

	return (0);
}

idmap_stat
idmap_get_uidbysid(idmap_get_handle_t *gh, char *sidprefix, idmap_rid_t rid,
    int flag, uid_t *uid, idmap_stat *stat)
{
	idmap_stat rc;
	uid_t pid;
	int is_user;

	rc = idmap_get_pidbysid(gh, sidprefix, rid, flag, &pid, &is_user, stat);
	if (rc == 0) {
		if (is_user != 1) {
			*stat = IDMAP_ERR_NOTUSER;
			return (0);
		}
		*uid = pid;
	}

	return (rc);
}

idmap_stat
idmap_get_gidbysid(idmap_get_handle_t *gh, char *sidprefix, idmap_rid_t rid,
    int flag, gid_t *gid, idmap_stat *stat)
{
	idmap_stat rc;
	uid_t pid;
	int is_user;

	rc = idmap_get_pidbysid(gh, sidprefix, rid, flag, &pid, &is_user, stat);
	if (rc == 0) {
		if (is_user != 0) {
			*stat = IDMAP_ERR_NOTGROUP;
			return (rc);
		}
		*gid = pid;
	}

	return (rc);
}

struct passwd *
getpwnam(const char *nam)
{
	static char pwname[128];
	static struct passwd pw;
	struct mapping	*mp;
	char *p;

	/* Allow lookup with or without domain part */
	if ((p = strchr(nam, '@')) != NULL) {
		int len = p - nam;
		if (len >= sizeof (pwname))
			return (NULL);
		(void) strlcpy(pwname, nam, len + 1);
		pwname[len] = '\0';
	} else {
		(void) strlcpy(pwname, nam, sizeof (pwname));
	}

	/* Get mapping */
	for (mp = mappings; mp->pid != 0; mp++) {
		if (mp->is_user != 1)
			continue;
		if (strcmp(mp->name, pwname) == 0)
			break;
	}
	if (mp->pid == 0)
		return (NULL);

	if (mp->domain != NULL)
		(void) snprintf(pwname, sizeof (pwname),
		    "%s@%s", mp->name, mp->domain);
	else
		(void) strlcpy(pwname, mp->name, sizeof (pwname));

	pw.pw_name = pwname;
	pw.pw_uid = mp->pid;
	return (&pw);
}

struct passwd *
getpwuid(uid_t uid)
{
	static char pwname[128];
	static struct passwd pw;
	struct mapping	*mp;

	/* Get mapping */
	for (mp = mappings; mp->pid != 0; mp++) {
		if (mp->is_user != 1)
			continue;
		if (mp->pid == uid)
			break;
	}
	if (mp->pid == 0)
		return (NULL);

	if (mp->domain != NULL)
		(void) snprintf(pwname, sizeof (pwname),
		    "%s@%s", mp->name, mp->domain);
	else
		(void) strlcpy(pwname, mp->name, sizeof (pwname));

	pw.pw_name = pwname;
	pw.pw_uid = uid;
	return (&pw);
}

struct group *
getgrnam(const char *nam)
{
	static char grname[128];
	static struct group gr;
	struct mapping	*mp;
	char *p;

	/* Allow lookup with or without domain part */
	if ((p = strchr(nam, '@')) != NULL) {
		int len = p - nam;
		if (len >= sizeof (grname))
			return (NULL);
		(void) strlcpy(grname, nam, len + 1);
		grname[len] = '\0';
	} else {
		(void) strlcpy(grname, nam, sizeof (grname));
	}

	/* Get mapping */
	for (mp = mappings; mp->pid != 0; mp++) {
		if (mp->is_user != 0)
			continue;
		if (strcmp(mp->name, grname) == 0)
			break;
	}
	if (mp->pid == 0)
		return (NULL);

	if (mp->domain != NULL)
		(void) snprintf(grname, sizeof (grname),
		    "%s@%s", mp->name, mp->domain);
	else
		(void) strlcpy(grname, mp->name, sizeof (grname));

	gr.gr_name = grname;
	gr.gr_gid = mp->pid;
	return (&gr);
}

struct group *
getgrgid(gid_t gid)
{
	static char grname[128];
	static struct group gr;
	struct mapping	*mp;

	/* Get mapping */
	for (mp = mappings; mp->pid != 0; mp++) {
		if (mp->is_user != 0)
			continue;
		if (mp->pid == gid)
			break;
	}
	if (mp->pid == 0)
		return (NULL);

	if (mp->domain != NULL)
		(void) snprintf(grname, sizeof (grname),
		    "%s@%s", mp->name, mp->domain);
	else
		(void) strlcpy(grname, mp->name, sizeof (grname));

	gr.gr_name = grname;
	gr.gr_gid = gid;
	return (&gr);
}
