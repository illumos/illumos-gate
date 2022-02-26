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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <arpa/inet.h> /* inet_addr() */
#include <ctype.h>
#include <libscf.h>
#include <netdb.h> /* hostent */
#include <netinet/in.h> /* ip_addr_t */
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/varargs.h>
#include <zone.h>
#include "ksslcfg.h"

/*
 * ksslcfg(8)
 *
 * ksslcfg manages smf(7) instances for the Kernel SSL proxy module.
 * It makes use of kssladm(8) which does the grunt work.
 */

/*
 * This version number is rather meaningless. In any case,
 * version 2.0 adds support for IPv6 addresses.
 */
#define	KSSLCFG_VERSION "Version 2.0"

boolean_t verbose = B_FALSE;
const char *SERVICE_NAME = "network/ssl/proxy";

void
KSSL_DEBUG(const char *format, ...)
{
	va_list ap;

	if (verbose) {
		va_start(ap, format);
		(void) vprintf(format, ap);
		va_end(ap);
	}
}

/*
 * Convert string to port number and check for errors. Return 0 on error,
 * 1 on success.
 */
int
get_portnum(const char *s, ushort_t *rport)
{
	long long tmp_port;
	char *ep;

	errno = 0;
	tmp_port = strtoll(s, &ep, 10);
	if (s == ep || *ep != '\0' || errno != 0)
		return (0);
	if (tmp_port < 1 || tmp_port > 65535)
		return (0);

	if (rport != NULL)
		*rport = (ushort_t)tmp_port;

	return (1);
}

#define	ANY_ADDR	"INADDR_ANY"

/*
 * An instance name is formed using either the host name in the fully
 * qualified domain name form (FQDN) which should map to a specific IP address
 * or using INADDR_ANY which means all IP addresses.
 *
 * We do a lookup or reverse lookup to get the host name. It is assumed that
 * the returned name is in the FQDN form. i.e. DNS is used.
 */
char *
create_instance_name(const char *arg, char **inaddr_any_name,
    boolean_t is_create)
{
	int len;
	uint16_t port;
	char *cname;
	char *instance_name;
	const char *prefix = "kssl-";
	char *first_space;

	first_space = strchr(arg, ' ');
	if (first_space == NULL) {	/* No host name. Use INADDR_ANY. */
		if (get_portnum(arg, &port) == 0) {
			(void) fprintf(stderr,
			    gettext("Error: Invalid port value -- %s\n"),
			    arg);
			return (NULL);
		}
		KSSL_DEBUG("port=%d\n", port);
		if ((cname = strdup(ANY_ADDR)) == NULL)
			return (NULL);
	} else {
		char *temp_str;
		char *ptr;
		struct hostent *hp;
		boolean_t do_warn;
		int error_num;
		in_addr_t v4addr;
		in6_addr_t v6addr;

		if (get_portnum(first_space + 1, &port) == 0) {
			(void) fprintf(stderr,
			    gettext("Error: Invalid port value -- %s\n"),
			    first_space + 1);
			return (NULL);
		}
		KSSL_DEBUG("port=%d\n", port);

		if ((temp_str = strdup(arg)) == NULL)
			return (NULL);
		*(strchr(temp_str, ' ')) = '\0';

		if (inet_pton(AF_INET6, temp_str, &v6addr) == 1) {
			/* Do a reverse lookup for the IPv6 address */
			hp = getipnodebyaddr(&v6addr, sizeof (v6addr),
			    AF_INET6, &error_num);
		} else if (inet_pton(AF_INET, temp_str, &v4addr) == 1) {
			/* Do a reverse lookup for the IPv4 address */
			hp = getipnodebyaddr(&v4addr, sizeof (v4addr),
			    AF_INET, &error_num);
		} else {
			/* Do a lookup for the host name */
			hp = getipnodebyname(temp_str, AF_INET6, AI_DEFAULT,
			    &error_num);
		}

		if (hp == NULL) {
			(void) fprintf(stderr,
			    gettext("Error: Unknown host -- %s\n"), temp_str);
			free(temp_str);
			return (NULL);
		}

		if ((ptr = cname = strdup(hp->h_name)) == NULL) {
			freehostent(hp);
			free(temp_str);
			return (NULL);
		}

		freehostent(hp);

		do_warn = B_TRUE;
		/* "s/./-/g" */
		while ((ptr = strchr(ptr, '.')) != NULL) {
			if (do_warn)
				do_warn = B_FALSE;
			*ptr = '-';
			ptr++;
		}

		if (do_warn && is_create) {
			(void) fprintf(stderr,
			    gettext("Warning: %s does not appear to have a"
			    " registered DNS name.\n"), temp_str);
		}

		free(temp_str);
	}

	KSSL_DEBUG("Cannonical host name =%s\n", cname);

	len = strlen(prefix) + strlen(cname) + 10;
	if ((instance_name = malloc(len)) == NULL) {
		(void) fprintf(stderr,
		    gettext("Error: memory allocation failure.\n"));
		return (NULL);
	}
	(void) snprintf(instance_name, len, "%s%s-%d", prefix, cname, port);

	if (is_create) {
		len = strlen(prefix) + strlen(ANY_ADDR) + 10;
		if ((*inaddr_any_name = malloc(len)) == NULL) {
			(void) fprintf(stderr,
			    gettext("Error: memory allocation failure.\n"));
			free(instance_name);
			free(cname);
			return (NULL);
		}

		(void) snprintf(*inaddr_any_name, len,
		    "%s%s-%d", prefix, ANY_ADDR, port);
	}

	free(cname);
	KSSL_DEBUG("instance_name=%s\n", instance_name);
	return (instance_name);
}

static void
usage_all(void)
{
	(void) fprintf(stderr, gettext("Usage:\n"));
	usage_create(B_FALSE);
	usage_delete(B_FALSE);
	(void) fprintf(stderr, "ksslcfg -V\n");
	(void) fprintf(stderr, "ksslcfg -?\n");
}


int
main(int argc, char **argv)
{
	int rv = SUCCESS;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* Running from within a non-global zone is not supported yet. */
	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr,
		    gettext("Error: Configuring KSSL from within a non-global "
		    "zone is not supported.\nPlease run the command from "
		    "the global zone.\n"));
		return (ERROR_USAGE);
	}

	if (argc < 2) {
		usage_all();
		return (ERROR_USAGE);
	}

	if (strcmp(argv[1], "create") == 0) {
		rv = do_create(argc, argv);
	} else if (strcmp(argv[1], "delete") == 0) {
		rv = do_delete(argc, argv);
	} else if (strcmp(argv[1], "-V") == 0) {
		(void) printf("%s\n", KSSLCFG_VERSION);
	} else if (strcmp(argv[1], "-?") == 0) {
		usage_all();
	} else {
		(void) fprintf(stderr,
		    gettext("Error: Unknown subcommand -- %s\n"), argv[1]);
		usage_all();
		rv = ERROR_USAGE;
	}

	return (rv);
}
