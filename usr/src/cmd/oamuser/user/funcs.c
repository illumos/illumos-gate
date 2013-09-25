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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 RackTop Systems.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <auth_attr.h>
#include <prof_attr.h>
#include <user_attr.h>
#include <project.h>
#include <secdb.h>
#include <pwd.h>
#include <unistd.h>
#include <priv.h>
#include <errno.h>
#include <ctype.h>
#include <nss.h>
#include <bsm/libbsm.h>
#include <tsol/label.h>
#include "funcs.h"
#include "messages.h"
#undef	GROUP
#include "userdefs.h"

typedef struct ua_key {
	const char	*key;
	const char	*(*check)(const char *);
	const char	*errstr;
	char		*newvalue;
} ua_key_t;

static const char role[] = "role name";
static const char prof[] = "profile name";
static const char proj[] = "project name";
static const char priv[] = "privilege set";
static const char auth[] = "authorization";
static const char type[] = "user type";
static const char lock[] = "lock_after_retries value";
static const char label[] = "label";
static const char idlecmd[] = "idlecmd value";
static const char idletime[] = "idletime value";
static const char auditflags[] = "audit mask";
static char	  auditerr[256];


static const char *check_auth(const char *);
static const char *check_prof(const char *);
static const char *check_role(const char *);
static const char *check_proj(const char *);
static const char *check_privset(const char *);
static const char *check_type(const char *);
static const char *check_lock_after_retries(const char *);
static const char *check_label(const char *);
static const char *check_idlecmd(const char *);
static const char *check_idletime(const char *);
static const char *check_auditflags(const char *);

int nkeys;

static ua_key_t keys[] = {
	/* First entry is always set correctly in main() */
	{ USERATTR_TYPE_KW,	check_type,	type },
	{ USERATTR_AUTHS_KW,	check_auth,	auth },
	{ USERATTR_PROFILES_KW,	check_prof,	prof },
	{ USERATTR_ROLES_KW,	check_role,	role },
	{ USERATTR_DEFAULTPROJ_KW,	check_proj,	proj },
	{ USERATTR_LIMPRIV_KW,	check_privset,	priv },
	{ USERATTR_DFLTPRIV_KW,	check_privset,	priv },
	{ USERATTR_LOCK_AFTER_RETRIES_KW, check_lock_after_retries,  lock },
	{ USERATTR_CLEARANCE,	check_label,	label },
	{ USERATTR_MINLABEL,	check_label,	label },
	{ USERATTR_IDLECMD_KW,	check_idlecmd,	idlecmd },
	{ USERATTR_IDLETIME_KW,	check_idletime,	idletime },
	{ USERATTR_AUDIT_FLAGS_KW, check_auditflags, auditflags },
};

#define	NKEYS	(sizeof (keys)/sizeof (ua_key_t))

/*
 * Change a key, there are three different call sequences:
 *
 *		key, value	- key with option letter, value.
 *		NULL, value	- -K key=value option.
 */

void
change_key(const char *key, char *value)
{
	int i;
	const char *res;

	if (key == NULL) {
		key = value;
		value = strchr(value, '=');
		/* Bad value */
		if (value == NULL) {
			errmsg(M_INVALID_VALUE);
			exit(EX_BADARG);
		}
		*value++ = '\0';
	}

	for (i = 0; i < NKEYS; i++) {
		if (strcmp(key, keys[i].key) == 0) {
			if (keys[i].newvalue != NULL) {
				/* Can't set a value twice */
				errmsg(M_REDEFINED_KEY, key);
				exit(EX_BADARG);
			}

			if (keys[i].check != NULL &&
			    (res = keys[i].check(value)) != NULL) {
				errmsg(M_INVALID, res, keys[i].errstr);
				exit(EX_BADARG);
			}
			keys[i].newvalue = value;
			nkeys++;
			return;
		}
	}
	errmsg(M_INVALID_KEY, key);
	exit(EX_BADARG);
}

/*
 * Add the keys to the argument vector.
 */
void
addkey_args(char **argv, int *index)
{
	int i;

	for (i = 0; i < NKEYS; i++) {
		const char *key = keys[i].key;
		char *val = keys[i].newvalue;
		size_t len;
		char *arg;

		if (val == NULL)
			continue;

		len = strlen(key) + strlen(val) + 2;
		arg = malloc(len);

		(void) snprintf(arg, len, "%s=%s", key, val);
		argv[(*index)++] = "-K";
		argv[(*index)++] = arg;
	}
}

/*
 * Propose a default value for a key and get the actual value back.
 * If the proposed default value is NULL, return the actual value set.
 * The key argument is the user_attr key.
 */
char *
getsetdefval(const char *key, char *dflt)
{
	int i;

	for (i = 0; i < NKEYS; i++)
		if (strcmp(keys[i].key, key) == 0) {
			if (keys[i].newvalue != NULL)
				return (keys[i].newvalue);
			else
				return (keys[i].newvalue = dflt);
		}
	return (NULL);
}

char *
getusertype(char *cmdname)
{
	static char usertype[MAX_TYPE_LENGTH];
	char *cmd;

	if ((cmd = strrchr(cmdname, '/')))
		++cmd;
	else
		cmd = cmdname;

	/* get user type based on the program name */
	if (strncmp(cmd, CMD_PREFIX_USER,
	    strlen(CMD_PREFIX_USER)) == 0)
		strcpy(usertype, USERATTR_TYPE_NORMAL_KW);
	else
		strcpy(usertype, USERATTR_TYPE_NONADMIN_KW);

	return (usertype);
}

int
is_role(char *usertype)
{
	if (strcmp(usertype, USERATTR_TYPE_NONADMIN_KW) == 0)
		return (1);
	/* not a role */
	return (0);
}

/*
 * Verifies the provided list of authorizations are all valid.
 *
 * Returns NULL if all authorization names are valid.
 * Otherwise, returns the invalid authorization name
 *
 */
static const char *
check_auth(const char *auths)
{
	char *authname;
	authattr_t *result;
	char *tmp;
	struct passwd   *pw;
	int have_grant = 0;

	tmp = strdup(auths);
	if (tmp == NULL) {
		errmsg(M_NOSPACE);
		exit(EX_FAILURE);
	}

	authname = strtok(tmp, AUTH_SEP);
	pw = getpwuid(getuid());
	if (pw == NULL) {
		return (authname);
	}

	while (authname != NULL) {
		char *suffix;
		char *authtoks;

		/* Check if user has been granted this authorization */
		if (!chkauthattr(authname, pw->pw_name))
			return (authname);

		/* Remove named object after slash */
		if ((suffix = index(authname, KV_OBJECTCHAR)) != NULL)
			*suffix = '\0';

		/* Find the suffix */
		if ((suffix = rindex(authname, '.')) == NULL)
			return (authname);

		/* Check for existence in auth_attr */
		suffix++;
		if (strcmp(suffix, KV_WILDCARD)) { /* Not a wildcard */
			result = getauthnam(authname);
			if (result == NULL) {
			/* can't find the auth */
				free_authattr(result);
				return (authname);
			}
			free_authattr(result);
		}

		/* Check if user can delegate this authorization */
		if (strcmp(suffix, "grant")) { /* Not a grant option */
			authtoks = malloc(strlen(authname) + sizeof ("grant"));
			strcpy(authtoks, authname);
			have_grant = 0;
			while ((suffix = rindex(authtoks, '.')) &&
			    !have_grant) {
				strcpy(suffix, ".grant");
				if (chkauthattr(authtoks, pw->pw_name))
					have_grant = 1;
				else
					*suffix = '\0';
			}
			if (!have_grant)
				return (authname);
		}
		authname = strtok(NULL, AUTH_SEP);
	}
	free(tmp);
	return (NULL);
}

/*
 * Verifies the provided list of profile names are valid.
 *
 * Returns NULL if all profile names are valid.
 * Otherwise, returns the invalid profile name
 *
 */
static const char *
check_prof(const char *profs)
{
	char *profname;
	profattr_t *result;
	char *tmp;

	tmp = strdup(profs);
	if (tmp == NULL) {
		errmsg(M_NOSPACE);
		exit(EX_FAILURE);
	}

	profname = strtok(tmp, PROF_SEP);
	while (profname != NULL) {
		result = getprofnam(profname);
		if (result == NULL) {
		/* can't find the profile */
			return (profname);
		}
		free_profattr(result);
		profname = strtok(NULL, PROF_SEP);
	}
	free(tmp);
	return (NULL);
}


/*
 * Verifies the provided list of role names are valid.
 *
 * Returns NULL if all role names are valid.
 * Otherwise, returns the invalid role name
 *
 */
static const char *
check_role(const char *roles)
{
	char *rolename;
	userattr_t *result;
	char *utype;
	char *tmp;

	tmp = strdup(roles);
	if (tmp == NULL) {
		errmsg(M_NOSPACE);
		exit(EX_FAILURE);
	}

	rolename = strtok(tmp, ROLE_SEP);
	while (rolename != NULL) {
		result = getusernam(rolename);
		if (result == NULL) {
		/* can't find the rolename */
			return (rolename);
		}
		/* Now, make sure it is a role */
		utype = kva_match(result->attr, USERATTR_TYPE_KW);
		if (utype == NULL) {
			/* no user type defined. not a role */
			free_userattr(result);
			return (rolename);
		}
		if (strcmp(utype, USERATTR_TYPE_NONADMIN_KW) != 0) {
			free_userattr(result);
			return (rolename);
		}
		free_userattr(result);
		rolename = strtok(NULL, ROLE_SEP);
	}
	free(tmp);
	return (NULL);
}

static const char *
check_proj(const char *proj)
{
	if (getprojidbyname(proj) < 0) {
		return (proj);
	} else {
		return (NULL);
	}
}

static const char *
check_privset(const char *pset)
{
	priv_set_t *tmp;
	const char *res;

	tmp = priv_str_to_set(pset, ",", &res);

	if (tmp != NULL) {
		res = NULL;
		priv_freeset(tmp);
	} else if (res == NULL)
		res = strerror(errno);

	return (res);
}

static const char *
check_type(const char *type)
{
	if (strcmp(type, USERATTR_TYPE_NONADMIN_KW) != 0 &&
	    strcmp(type, USERATTR_TYPE_NORMAL_KW) != 0)
		return (type);

	return (NULL);
}

static const char *
check_lock_after_retries(const char *keyval)
{
	if (keyval != NULL) {
		if ((strcasecmp(keyval, "no") != 0) &&
		    (strcasecmp(keyval, "yes") != 0) &&
		    (*keyval != '\0'))   {
			return (keyval);
		}
	}
	return (NULL);
}

static const char *
check_label(const char *labelstr)
{
	int	err;
	m_label_t *lbl = NULL;

	if (!is_system_labeled())
		return (NULL);

	err = str_to_label(labelstr, &lbl, MAC_LABEL, L_NO_CORRECTION, NULL);
	m_label_free(lbl);

	if (err == -1)
		return (labelstr);

	return (NULL);
}

static const char *
check_idlecmd(const char *cmd)
{
	if ((strcmp(cmd, USERATTR_IDLECMD_LOCK_KW) != 0) &&
	    (strcmp(cmd, USERATTR_IDLECMD_LOGOUT_KW) != 0)) {
		return (cmd);
	}

	return (NULL);
}

static const char *
check_idletime(const char *time)
{
	int		c;
	unsigned char	*up = (unsigned char *)time;

	c = *up;
	while (c != '\0') {
		if (!isdigit(c))
			return (time);
		c = *++up;
	}

	return (NULL);
}

static const char *
check_auditflags(const char *auditflags)
{
	au_mask_t mask;
	char	*flags;
	char	*last = NULL;
	char	*err = "NULL";

	/* if deleting audit_flags */
	if (*auditflags == '\0') {
		return (NULL);
	}

	if ((flags = _strdup_null((char *)auditflags)) == NULL) {
		errmsg(M_NOSPACE);
		exit(EX_FAILURE);
	}

	if (!__chkflags(_strtok_escape(flags, KV_AUDIT_DELIMIT, &last), &mask,
	    B_FALSE, &err)) {
		(void) snprintf(auditerr, sizeof (auditerr),
		    "always mask \"%s\"", err);
		free(flags);
		return (auditerr);
	}
	if (!__chkflags(_strtok_escape(NULL, KV_AUDIT_DELIMIT, &last), &mask,
	    B_FALSE, &err)) {
		(void) snprintf(auditerr, sizeof (auditerr),
		    "never mask \"%s\"", err);
		free(flags);
		return (auditerr);
	}
	if (last != NULL) {
		(void) snprintf(auditerr, sizeof (auditerr), "\"%s\"",
		    auditflags);
		free(flags);
		return (auditerr);
	}
	free(flags);

	return (NULL);
}
