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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <user_attr.h>
#include <pwd.h>
#include <grp.h>
#include <userdefs.h>
#include <project.h>
#include <memory.h>
#include <nss_dbdefs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/mman.h>

#pragma weak setprojent = _setprojent
#pragma weak endprojent = _endprojent
#pragma weak getprojent = _getprojent
#pragma weak fgetprojent = _fgetprojent
#pragma weak getprojbyid = _getprojbyid
#pragma weak getprojbyname = _getprojbyname
#pragma weak getdefaultproj = _getdefaultproj
#pragma weak inproj = _inproj
#pragma weak getprojidbyname = _getprojidbyname

#define	DEFAULT_PROJECT	1
#define	NORMAL_PROJECT	0

static int ismember(struct project *, const char *, gid_t, int);
static int str2project(const char *, int, void *, char *, int);

static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

void
_nss_initf_project(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_PROJECT;
	p->default_config = NSS_DEFCONF_PROJECT;
}

void
_setprojent(void)
{
	nss_setent(&db_root, _nss_initf_project, &context);
}

void
_endprojent(void)
{
	nss_endent(&db_root, _nss_initf_project, &context);
	nss_delete(&db_root);
}

struct project *
_getprojent(struct project *result, void *buffer, size_t buflen)
{
	nss_XbyY_args_t arg;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2project);
	(void) nss_getent(&db_root, _nss_initf_project, &context, &arg);
	return ((struct project *)NSS_XbyY_FINI(&arg));
}

struct project *
_fgetprojent(FILE *f, struct project *result, void *buffer, size_t buflen)
{
	extern void _nss_XbyY_fgets(FILE *, nss_XbyY_args_t *);
	nss_XbyY_args_t arg;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2project);
	_nss_XbyY_fgets(f, &arg);
	return ((struct project *)NSS_XbyY_FINI(&arg));
}

struct project *
_getprojbyid(projid_t projid, struct project *result,
    void *buffer, size_t buflen)
{
	nss_XbyY_args_t arg;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2project);
	arg.key.projid = projid;
	(void) nss_search(&db_root, _nss_initf_project,
	    NSS_DBOP_PROJECT_BYID, &arg);
	return ((struct project *)NSS_XbyY_FINI(&arg));
}

struct project *
_getprojbyname(const char *name, struct project *result,
    void *buffer, size_t buflen)
{
	nss_XbyY_args_t arg;
	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2project);
	arg.key.name = name;
	(void) nss_search(&db_root, _nss_initf_project,
	    NSS_DBOP_PROJECT_BYNAME, &arg);
	return ((struct project *)NSS_XbyY_FINI(&arg));
}

/*
 * The following routine checks if user specified by the second argument
 * is allowed to join the project specified as project structure in first
 * argument.  Information about user's default group and whether or not
 * the project specified in the first argument is user's default project
 * (i.e., user_attr, "default", "user.username", or "group.groupname"
 * should also be provided.  If is_default is set to DEFAULT_PROJECT,
 * then this function returns 1 (true), unless specified user explicitly
 * excluded with "!user", or "!group" wildcards.
 */
static int
ismember(struct project *proj, const char *user, gid_t gid, int is_default)
{
	char grbuf[NSS_BUFLEN_GROUP];
	char groupname[MAXGLEN + 1];
	int res = is_default;
	struct group grp;
	int group_ok = 0;
	char **u, **g;
	char *member;

	if (getgrgid_r(gid, &grp, grbuf, NSS_BUFLEN_GROUP) != NULL) {
		group_ok = 1;
		(void) snprintf(groupname, MAXGLEN, grp.gr_name);
	}

	/*
	 * Scan project's user list.
	 */
	for (u = proj->pj_users; *u; u++) {
		member = *u;
		if (member[0] == '!' &&
		    (strcmp(member + 1, user) == 0 ||
		    strcmp(member + 1, "*") == 0))
			return (0);
		if (strcmp(member, "*") == 0 || strcmp(member, user) == 0)
			res = 1;
	}

	/*
	 * Scan project's group list.
	 */
	for (g = proj->pj_groups; *g; g++) {
		member = *g;
		/*
		 * Check if user's default group is included here.
		 */
		if (group_ok) {
			if (member[0] == '!' &&
			    (strcmp(member + 1, groupname) == 0 ||
			    strcmp(member + 1, "*") == 0))
				return (0);
			if (strcmp(member, "*") == 0 ||
			    strcmp(member, groupname) == 0)
				res = 1;
		}
		/*
		 * Check if user is a member of one of project's groups.
		 */
		if (getgrnam_r(member, &grp, grbuf, NSS_BUFLEN_GROUP) != NULL) {
			for (u = grp.gr_mem; *u; u++)
				if (strcmp(*u, user) == 0)
					res = 1;
		}
	}
	return (res);
}

struct project *
_getdefaultproj(const char *user, struct project *result,
    void *buffer, size_t buflen)
{
	char projname[PROJNAME_MAX + 1];
	nss_XbyY_args_t arg;
	userattr_t *uattr;
	struct passwd p;
	struct group g;
	char *attrproj;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2project);

	/*
	 * Need user's default group ID for ismember() calls later
	 */
	if (getpwnam_r(user, &p, buffer, buflen) == NULL)
		return (NULL);

	/*
	 * Check user_attr database first
	 */
	if ((uattr = getusernam(user)) != NULL) {
		if ((attrproj = kva_match(uattr->attr, "project")) != NULL) {
			arg.key.name = attrproj;
			(void) nss_search(&db_root, _nss_initf_project,
			    NSS_DBOP_PROJECT_BYNAME, &arg);
			if ((result = NSS_XbyY_FINI(&arg)) != NULL) {
				free_userattr(uattr);
				return (result);
			}
		}
		free_userattr(uattr);
	}

	/*
	 * Check user.{username} and group.{groupname} projects
	 */
	(void) snprintf(projname, PROJNAME_MAX, "user.%s", user);
	arg.key.name = projname;
	(void) nss_search(&db_root, _nss_initf_project,
	    NSS_DBOP_PROJECT_BYNAME, &arg);
	if ((result = NSS_XbyY_FINI(&arg)) != NULL &&
	    ismember(result, user, p.pw_gid, DEFAULT_PROJECT))
		return (result);
	if (getgrgid_r(p.pw_gid, &g, buffer, buflen) != NULL) {
		(void) snprintf(projname, PROJNAME_MAX, "group.%s", g.gr_name);
		arg.key.name = projname;
		(void) nss_search(&db_root, _nss_initf_project,
		    NSS_DBOP_PROJECT_BYNAME, &arg);
		if ((result = NSS_XbyY_FINI(&arg)) != NULL &&
		    ismember(result, user, p.pw_gid, DEFAULT_PROJECT))
			return (result);
	}
	arg.key.name = "default";
	(void) nss_search(&db_root, _nss_initf_project,
	    NSS_DBOP_PROJECT_BYNAME, &arg);
	if ((result = NSS_XbyY_FINI(&arg)) != NULL &&
	    ismember(result, user, p.pw_gid, DEFAULT_PROJECT))
		return (result);
	return (NULL);
}

int
_inproj(const char *user, const char *name, void *buffer, size_t buflen)
{
	char projname[PROJNAME_MAX + 1];
	char grbuf[NSS_BUFLEN_GROUP];
	nss_XbyY_args_t arg;
	struct project proj;
	struct passwd pwd;
	userattr_t *uattr;
	struct group grp;
	char *attrproj;
	gid_t gid;

	NSS_XbyY_INIT(&arg, &proj, buffer, buflen, str2project);

	/*
	 * 0. Sanity checks.
	 */
	if (getpwnam_r(user, &pwd, buffer, buflen) == NULL)
		return (0);		/* user does not exist */
	gid = pwd.pw_gid;
	if (getprojbyname(name, &proj, buffer, buflen) == NULL)
		return (0);		/* project does not exist */

	/*
	 * 1. Check for special "default" project.
	 */
	if (strcmp("default", name) == 0)
		return (ismember(&proj, user, gid, DEFAULT_PROJECT));

	/*
	 * 2. Check user_attr database.
	 */
	if ((uattr = getusernam(user)) != NULL) {
		if ((attrproj = kva_match(uattr->attr, "project")) != NULL) {
			if (strcmp(attrproj, name) == 0) {
				free_userattr(uattr);
				return (ismember(&proj, user, gid,
				    DEFAULT_PROJECT));
			}
		}
		free_userattr(uattr);
	}

	/*
	 * 3. Check if this is a special "user.username" project.
	 *
	 * User "username" is considered to be a member of project
	 * "user.username" even if project's user lists do not
	 * include "username".
	 */
	(void) snprintf(projname, PROJNAME_MAX, "user.%s", user);
	if (strcmp(projname, name) == 0)
		return (ismember(&proj, user, gid, DEFAULT_PROJECT));

	/*
	 * 4. Check if this is a special "group.groupname" project.
	 *
	 * User "username" with default group "groupname" is considered
	 * to be a member of project "group.groupname" even if project's
	 * group list does not include "groupname".
	 */
	if (getgrgid_r(gid, &grp, grbuf, NSS_LINELEN_GROUP) != NULL) {
		(void) snprintf(projname, PROJNAME_MAX,
		    "group.%s", grp.gr_name);
		if (strcmp(projname, name) == 0)
			return (ismember(&proj, user, gid, DEFAULT_PROJECT));
	}

	/*
	 * 5. Handle all other (non-default) projects.
	 */
	return (ismember(&proj, user, gid, NORMAL_PROJECT));
}

/*
 * Just a quick wrapper around getprojbyname so that the caller does not
 * need to allocate the buffer.
 */
projid_t
_getprojidbyname(const char *name)
{
	struct project proj;
	char buf[PROJECT_BUFSZ];

	if (getprojbyname(name, &proj, &buf, PROJECT_BUFSZ) != NULL)
		return (proj.pj_projid);
	else
		return ((projid_t)-1);
}

static char *
gettok(char **nextpp, char sep)
{
	char *p = *nextpp;
	char *q = p;
	char c;

	if (p == NULL)
		return (NULL);
	while ((c = *q) != '\0' && c != sep)
		q++;
	if (c == '\0')
		*nextpp = 0;
	else {
		*q++ = '\0';
		*nextpp = q;
	}
	return (p);
}


/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas.
 */
static int
str2project(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	struct project *project = ent;
	char *p, *next;
	char *users, *groups;
	char **uglist;
	char **limit;

	if (lenstr + 1 > buflen)
		return (NSS_STR_PARSE_ERANGE);
	/*
	 * We copy the input string into the output buffer and
	 * operate on it in place.
	 */
	(void) memcpy(buffer, instr, lenstr);
	buffer[lenstr] = '\0';
	next = buffer;

	limit = (char **)ROUND_DOWN(buffer + buflen, sizeof (char *));

	/*
	 * Parsers for passwd and group have always been pretty rigid;
	 * we wouldn't want to buck a Unix tradition
	 */
	p = gettok(&next, ':');
	if (p == NULL || *p == '\0' || strlen(p) > PROJNAME_MAX) {
		/*
		 * empty or very long project names are not allowed
		 */
		return (NSS_STR_PARSE_ERANGE);
	}
	project->pj_name = p;

	p = gettok(&next, ':');
	if (p == NULL || *p == '\0') {
		/*
		 * projid field shouldn't be empty
		 */
		return (NSS_STR_PARSE_PARSE);
	}
	project->pj_projid = (projid_t)strtol(p, NULL, 10);
	if (project->pj_projid < 0) {
		/*
		 * projids should be positive number
		 */
		project->pj_projid = 0;
		return (NSS_STR_PARSE_PARSE);
	}

	p = gettok(&next, ':');
	if (p == NULL) {
		/*
		 * comment field can be empty but should not be last field
		 */
		return (NSS_STR_PARSE_PARSE);
	}
	project->pj_comment = p;

	if ((users = gettok(&next, ':')) == NULL) {
		/*
		 * users field should not be last field
		 */
		return (NSS_STR_PARSE_PARSE);
	}

	if ((groups = gettok(&next, ':')) == NULL) {
		/*
		 * groups field should not be last field
		 */
		return (NSS_STR_PARSE_PARSE);
	}

	if (next == NULL) {
		/*
		 * attributes field should be last
		 */
		return (NSS_STR_PARSE_PARSE);
	}

	project->pj_attr = next;

	uglist = (char **)ROUND_UP(buffer + lenstr + 1, sizeof (char *));
	*uglist = NULL;
	project->pj_users = uglist;
	while (uglist < limit) {
		p = gettok(&users, ',');
		if (p == NULL || *p == '\0') {
			*uglist = 0;
			break;
		}
		*uglist++ = p;
	}
	if (uglist >= limit)
		return (NSS_STR_PARSE_ERANGE);

	uglist++;
	*uglist = NULL;
	project->pj_groups = uglist;
	while (uglist < limit) {
		p = gettok(&groups, ',');
		if (p == NULL || *p == '\0') {
			*uglist = 0;
			break;
		}
		*uglist++ = p;
	}
	if (uglist >= limit)
		return (NSS_STR_PARSE_ERANGE);

	return (NSS_STR_PARSE_SUCCESS);
}
