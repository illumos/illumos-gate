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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <syslog.h>
#include <pwd.h>
#include <unistd.h>
#include <strings.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <libintl.h>

static int parse_allow_name(char *, char *);

/*
 * pam_sm_acct_mgmt	main account managment routine.
 *			XXX: The routine just prints out a warning message.
 *			     It may need to force the user to change their
 *			     passwd.
 */

int
pam_sm_acct_mgmt(
	pam_handle_t *pamh,
	int	flags,
	int	argc,
	const char **argv)
{
	char	*user;
	char	*pg;
	int	i;
	/*LINTED - set but not used. Would be used in a real module. */
	int	debug __unused = 0;
	/*LINTED - set but not used. Would be used in a real module. */
	int	nowarn __unused = 0;
	int	error = 0;

	if (argc == 0)
		return (PAM_SUCCESS);

	if (pam_get_item(pamh, PAM_USER, (void **)&user) != PAM_SUCCESS)
		return (PAM_SERVICE_ERR);

	if (pam_get_item(pamh, PAM_SERVICE, (void **)&pg) != PAM_SUCCESS)
		return (PAM_SERVICE_ERR);

	/*
	 * kludge alert. su needs to be handled specially for allow policy.
	 * we want to use the policy of the current user not the "destination"
	 * user. This will enable us to prevent su to root but not to rlogin,
	 * telnet, rsh, ftp to root.
	 *
	 * description of problem: user name is the "destination" name. not
	 * the current name. The allow policy needs to be applied to the
	 * current name in the case of su. user is "root" in this case and
	 * we will be getting the root policy instead of the user policy.
	 */
	if (strcmp(pg, "su") == 0) {
		struct passwd *pw;
		uid_t uid;
		uid = getuid();
		pw = getpwuid(uid);
		if (pw == NULL)
			return (PAM_SYSTEM_ERR);
		user = pw->pw_name;
	}

	if (user == 0 || *user == '\0' || (strcmp(user, "root") == 0))
		return (PAM_SUCCESS);

	for (i = 0; i < argc; i++) {
		if (strcasecmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcasecmp(argv[i], "nowarn") == 0) {
			nowarn = 1;
			flags = flags | PAM_SILENT;
		} else if (strncmp(argv[i], "allow=", 6) == 0)
			error |= parse_allow_name(user, (char *)(argv[i]+6));
		else
			syslog(LOG_DEBUG, "illegal option %s", argv[i]);
	}
	return (error?PAM_SUCCESS:PAM_AUTH_ERR);
}

static char *getname();

static int
parse_allow_name(char *who, char *cp)
{
	char name[256];

	/* catch "allow=" */
	if (*cp == '\0')
		return (0);
	while (cp) {
		cp = getname(cp, name);
		/* catch things such as =, and ,, */
		if (*name == '\0')
			continue;
		if (strcmp(who, name) == 0)
			return (1);
	}
	return (0);
}

static char *
getname(char *cp, char *name)
{
	/* force name to be initially null string */
	*name = '\0';

	/* end of string? */
	if (*cp == '\0')
		return ((char *)0);
	while (*cp) {
		/* end of name? */
		if (*cp == ',' || *cp == '\0')
			break;
		*name++ = *cp++;
	}
	/* make name into string */
	*name++ = '\0';
	return ((*cp == '\0')? (char *)0 : ++cp);
}
