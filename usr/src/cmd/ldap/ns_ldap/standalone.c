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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Helper functions for standalone functionality
 */

#include <assert.h>
#include <libintl.h>
#include <strings.h>
#include "ns_sldap.h"
#include "ns_internal.h"

ns_standalone_conf_t standaloneDefaults =
	    { {NULL,		/* A directory server's IP/name. No default. */
	    0,			/* A directory server's port. No default. */
	    NULL,		/* A domain name. */
				/* libsldap uses its own default. */
	    "default",		/* A DUAProfile's name. */
	    NULL,		/* Authentication information used. */
				/* If not specified by the user, */
				/* libsldap will use its own data */
	    NULL,		/* A credential level to be used */
				/* along with the authentication info. */
				/* See the previous comment. */
	    NSLDAPDIRECTORY,	/* The default path to */
				/* the certificate database. */
	    NULL,		/* A bind DN to be used during */
				/* subsequent LDAP Bind requests */
	    NULL},		/* A bind password to be used during */
				/* subsequent LDAP Bind requests */
	    NS_CACHEMGR};	/* If the -H option is not given, libsldap */
				/* will obtain all the configuration */
				/* information from ldap_cachemgr. */

int
separatePort(char *peer, char **name, uint16_t *port)
{
	char	*chr, *portStr = NULL;

	chr = strchr(peer, '[');
	if (chr != NULL) {
		/* An IPv6 address */
		*name = chr + 1;

		chr = strchr(peer, ']');
		if (chr == NULL) {
			(void) fprintf(stderr,
			    gettext("Server address is wrong: "
			    "unbalanced [\n"));
			return (1);
		}

		*chr++ = '\0';

		chr = strchr(chr, ':');
		if (chr != NULL && *(chr + 1) != '\0') {
			portStr = chr + 1;
		}
	} else {
		/* An IPv4 address */
		chr = strchr(peer, ']');
		if (chr != NULL) {
			(void) fprintf(stderr,
			    gettext("Server address is wrong: "
			    "unbalanced ]\n"));
			return (1);
		}

		chr = strchr(peer, ':');
		if (chr != NULL && *(chr + 1) != '\0') {
			*chr++ = '\0';
			portStr = chr;
		}

		*name = peer;
	}

	if ((*name)[0] == '\0') {
		(void) fprintf(stderr,
		    gettext("Server address or name must be"
		    " specified.\n"));
		return (1);
	}

	if (portStr && sscanf(portStr, "%hu", port) != 1) {
		(void) fprintf(stderr,
		    gettext("Server port is wrong. "
		    "The default port 389/636 "
		    "will be used.\n"));
	}
	return (0);
}

char *
readPwd(char *pwd_file)
{
	FILE	*f;
	char	*pwd;
	char	passwdBuf[BUFSIZE];

	if ((f = fopen(pwd_file, "r")) == NULL) {
		(void) fprintf(stderr,
		    gettext("Unable to open '%s' file\n"), pwd_file);
		return (NULL);
	}
	if (fgets(passwdBuf, BUFSIZE, f) == NULL) {
		(void) fprintf(stderr,
		    gettext("Unable to read '%s' file\n"), pwd_file);
		(void) fclose(f);
		return (NULL);
	}

	(void) fclose(f);

	if (passwdBuf[strlen(passwdBuf) - 1] == '\n') {
		passwdBuf[strlen(passwdBuf) - 1] = '\0';
	}
	if ((pwd = strdup(passwdBuf)) == NULL) {
		(void) fprintf(stderr,
		    gettext("Memory allocation error\n"));
		return (NULL);
	}

	return (pwd);
}
