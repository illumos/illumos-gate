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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netdb.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>

/*ARGSUSED*/
int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	FILE	*fd;
	const char	*allowdeny_filename = PF_PATH;
	char	buf[BUFSIZ];
	char	hostname[MAXHOSTNAMELEN];
	char	*username = NULL;
	char	*bufp;
	char	*rhost;
	char 	*limit;
	int	userok = 0;
	int	hostok = 0;
	int	i;
	int	allow_deny_test = 0;
	boolean_t	debug = B_FALSE;
	boolean_t	plus_check = B_TRUE;
	boolean_t	allow = B_FALSE;
	boolean_t	matched = B_FALSE;
	boolean_t	check_user = B_TRUE;
	boolean_t	check_host = B_FALSE;
	boolean_t	check_exact = B_FALSE;

	for (i = 0; i < argc; ++i) {
		if (strncasecmp(argv[i], "debug", sizeof ("debug")) == 0) {
			debug = B_TRUE;
		} else if (strncasecmp(argv[i], "user", sizeof ("user")) == 0) {
			check_user = B_TRUE;
		} else if (strncasecmp(argv[i], "nouser",
		    sizeof ("nouser")) == 0) {
			check_user = B_FALSE;
		} else if (strncasecmp(argv[i], "host", sizeof ("host")) == 0) {
			check_host = B_TRUE;
		} else if (strncasecmp(argv[i], "nohost",
		    sizeof ("nohost")) == 0) {
			check_host = B_FALSE;
		} else if (strncasecmp(argv[i], "user_host_exact",
		    sizeof ("user_host_exact")) == 0) {
			check_exact = B_TRUE;
		} else if (strncasecmp(argv[i], "allow=",
		    sizeof ("allow=") - 1) == 0) {
			allowdeny_filename = argv[i] + sizeof ("allow=") - 1;
			allow = B_TRUE;
			plus_check = B_FALSE;
			allow_deny_test++;
		} else if (strncasecmp(argv[i], "deny=",
		    sizeof ("deny=") - 1) == 0) {
			allowdeny_filename = argv[i] + sizeof ("deny=") - 1;
			allow = B_FALSE;
			plus_check = B_FALSE;
			allow_deny_test++;
		} else {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "pam_list: illegal option %s", argv[i]);
			return (PAM_SERVICE_ERR);
		}
	}

	if (((check_user || check_host || check_exact) == B_FALSE) ||
	    (allow_deny_test > 1)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_list: illegal combination of options");
		return (PAM_SERVICE_ERR);
	}

	if (debug) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_list: check_user = %d, check_host = %d,"
		    "check_exact = %d\n",
		    check_user, check_host, check_exact);

		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_list: auth_file: %s, %s\n", allowdeny_filename,
		    allow ? "allow file" : "deny file");
	}

	(void) pam_get_item(pamh, PAM_USER, (void**)&username);

	if ((check_user || check_exact) && ((username == NULL) ||
	    (*username == '\0'))) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_list: username not supplied, critical error");
		return (PAM_USER_UNKNOWN);
	}

	(void) pam_get_item(pamh, PAM_RHOST, (void**)&rhost);

	if ((check_host || check_exact) && ((rhost == NULL) ||
	    (*rhost == '\0'))) {
		if (gethostname(hostname, MAXHOSTNAMELEN) == 0) {
			rhost = hostname;
		} else {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "pam_list: error by gethostname - %m");
			return (PAM_SERVICE_ERR);
		}
	}

	if (debug) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_list:pam_sm_acct_mgmt for (%s,%s,)\n",
		    (rhost != NULL) ? rhost : "", username);
	}

	if ((fd = fopen(allowdeny_filename, "rF")) == NULL) {
		return (PAM_SERVICE_ERR);
	}

	while (fgets(buf, BUFSIZ, fd) != NULL) {
		/* lines longer than BUFSIZ-1 */
		if ((strlen(buf) == (BUFSIZ - 1)) &&
		    (buf[BUFSIZ - 2] != '\n')) {
			while ((fgetc(fd) != '\n') && (!feof(fd))) {
				continue;
			}
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "pam_list: long line in file,"
			    "more than %d chars, the rest ignored", BUFSIZ - 1);
		}

		/* remove unneeded colons if necessary */
		if ((limit = strpbrk(buf, ":\n")) != NULL) {
			*limit = '\0';
		}

		/* ignore free values */
		if (buf[0] == '\0') {
			continue;
		}


		bufp = buf;
		/* test for interesting lines = +/- in /etc/passwd */
		if (plus_check) {
			if (((buf[0] != '+') && (buf[0] != '-')) ||
			    (buf[1] == '\0')) {
				continue;
			}

			if (buf[0] == '+') {
				allow = B_TRUE;
			} else {
				allow = B_FALSE;
			}
			bufp++;
		}

		/*
		 * if -> netgroup line
		 * else -> user line
		 */
		if ((bufp[0] == '@') && (bufp[1] != '\0')) {
			bufp++;

			if (check_exact) {
				if (innetgr(bufp, rhost, username,
				    NULL) == 1) {
					matched = B_TRUE;
					break;
				}
			} else {
				if (check_user) {
					userok = innetgr(bufp, NULL, username,
					    NULL);
				} else {
					userok = 1;
				}
				if (check_host) {
					hostok = innetgr(bufp, rhost, NULL,
					    NULL);
				} else {
					hostok = 1;
				}
				if (userok && hostok) {
					matched = B_TRUE;
					break;
				}
			}
		} else {
			if (check_user) {
				if (strcmp(bufp, username) == 0) {
					matched = B_TRUE;
					break;
				}
			}
		}
	}
	(void) fclose(fd);
	if (matched) {
		return (allow ? PAM_SUCCESS : PAM_PERM_DENIED);
	}
	/* for compatibility with passwd_compat mode */
	if (plus_check) {
		return (PAM_IGNORE);
	}
	return (allow ? PAM_PERM_DENIED : PAM_SUCCESS);
}
