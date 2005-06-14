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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Turning DEBUG on for this library opens a potential security hole.  If
 * the library is compiled with DEBUG, it should only be done for internal
 * testing.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>


#ifdef DEBUG
#define	OPT_INT		1
#define	OPT_STRING	2
#define	OPT_FILE	3

int	__ldap_debug_file = 2;
int	__ldap_debug_api;
int	__ldap_debug_ldap;
int	__ldap_debug_servers;

struct option {
	char	*name;
	int	type;
	void	*address;
};

static struct option options[] = {
	{ "debug_file", OPT_FILE, &__ldap_debug_file },
	{ "debug_api", OPT_INT, &__ldap_debug_api },
	{ "debug_ldap", OPT_INT, &__ldap_debug_servers },
	{ 0, 0, 0 },
};

#ifdef NS_NO_STDIO
extern int __ns_ldap_raise_fd(int);
#endif

static void
set_option(char *name, char *val)
{
	struct option *opt;
	int		n;
	char		*p;
	int		fd;

	for (opt = options; opt->name; opt++) {
		if (strcasecmp(name, opt->name) == 0) {
			switch (opt->type) {
			    case OPT_STRING:
				p = strdup(val);
				*((char **)opt->address) = p;
				break;
			    case OPT_INT:
				if (val && *val == '\0')
					n = 1;
				else
					n = atoi(val);
				*((int *)opt->address) = n;
				break;
			    case OPT_FILE:
				/* this is a potential security risk    */
				/* as setuid programs will create files */
				/* owned by root.  This is only to be   */
				/* used for internal debugging.		*/
				fd = open(val, O_WRONLY | O_CREAT, 0644);
#ifdef NS_NO_STDIO
				fd = __ns_ldap_raise_fd(fd);
#endif
				*((int *)opt->address) = fd;
				break;
			}
			break;
		}
	}
}
#endif

void
get_environment()
{
#ifdef DEBUG
	char	*p;
	char	*base;
	char	optname[100];
	char	optval[100];

	p = getenv("LDAP_OPTIONS");
	if (p == NULL)
		return;

	while (*p) {
		while (isspace(*p))
			p++;
		if (*p == '\0')
			break;
		base = p;
		while (*p && *p != '=' && !isspace(*p))
			p++;
		(void) strncpy(optname, base, p - base);
		optname[p - base] = '\0';
		if (*p == '=') {
			p++;
			base = p;
			while (*p && !isspace(*p))
				p++;
			(void) strncpy(optval, base, p - base);
			optval[p - base] = '\0';
		} else {
			optval[0] = '\0';
		}
		set_option(optname, optval);
	}

	(void) fprintf(stderr, "debug_api: %d\n", __ldap_debug_api);
	(void) fprintf(stderr, "debug_ldap: %d\n", __ldap_debug_ldap);
	(void) fprintf(stderr, "debug_servers: %d\n", __ldap_debug_servers);
#endif
}

/*ARGSUSED*/
void
__s_api_debug_pause(int priority, int st, const char *mesg)
{
	if (mesg)
		syslog(priority, "libsldap: Status: %d  Mesg: %s", st, mesg);
}
