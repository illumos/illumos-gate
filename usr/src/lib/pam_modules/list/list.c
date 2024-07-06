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
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netdb.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>

#define	ILLEGAL_COMBINATION "pam_list: illegal combination of options"

typedef enum {
	LIST_EXTERNAL_FILE,
	LIST_PLUS_CHECK,
	LIST_COMPAT_MODE
} pam_list_mode_t;

static const char *
string_mode_type(pam_list_mode_t op_mode, boolean_t allow)
{
	return ((op_mode == LIST_COMPAT_MODE) ? "compat" :
	    (allow ? "allow" : "deny"));
}

static void
log_illegal_combination(const char *s1, const char *s2)
{
	__pam_log(LOG_AUTH | LOG_ERR, ILLEGAL_COMBINATION
	    " %s and %s", s1, s2);
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	FILE *fd;
	const char *allowdeny_filename = PF_PATH;
	char buf[BUFSIZ];
	char hostname[MAXHOSTNAMELEN];
	const char *username = NULL;
	char *grbuf = NULL;
	char *bufp;
	const char *rhost;
	char *limit;
	int userok = 0;
	int hostok = 0;
	int i;
	int allow_deny_test = 0;
	long grbuflen = 0;
	boolean_t debug = B_FALSE;
	boolean_t allow = B_FALSE;
	boolean_t matched = B_FALSE;
	boolean_t check_user = B_TRUE;
	boolean_t check_group = B_FALSE;
	boolean_t check_host = B_FALSE;
	boolean_t check_exact = B_FALSE;
	pam_list_mode_t	op_mode = LIST_PLUS_CHECK;

	// group reentrant interfaces limits
	if ((grbuflen = sysconf(_SC_GETGR_R_SIZE_MAX)) <= 0)
		return (PAM_BUF_ERR);

	for (i = 0; i < argc; ++i) {
		if (strncasecmp(argv[i], "debug", sizeof ("debug")) == 0) {
			debug = B_TRUE;
		} else if (strncasecmp(argv[i], "group",
		    sizeof ("group")) == 0) {
			check_group = B_TRUE;
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
		} else if (strcasecmp(argv[i], "compat") == 0) {
			if (op_mode == LIST_PLUS_CHECK) {
				op_mode = LIST_COMPAT_MODE;
			} else {
				log_illegal_combination("compat",
				    string_mode_type(op_mode, allow));
				return (PAM_SERVICE_ERR);
			}
		} else if (strncasecmp(argv[i], "allow=",
		    sizeof ("allow=") - 1) == 0) {
			if (op_mode == LIST_PLUS_CHECK) {
				allowdeny_filename = argv[i] +
				    sizeof ("allow=") - 1;
				allow = B_TRUE;
				op_mode = LIST_EXTERNAL_FILE;
				allow_deny_test++;
			} else {
				log_illegal_combination("allow",
				    string_mode_type(op_mode, allow));
				return (PAM_SERVICE_ERR);
			}
		} else if (strncasecmp(argv[i], "deny=",
		    sizeof ("deny=") - 1) == 0) {
			if (op_mode == LIST_PLUS_CHECK) {
				allowdeny_filename = argv[i] +
				    sizeof ("deny=") - 1;
				allow = B_FALSE;
				op_mode = LIST_EXTERNAL_FILE;
				allow_deny_test++;
			} else {
				log_illegal_combination("deny",
				    string_mode_type(op_mode, allow));
				return (PAM_SERVICE_ERR);
			}
		} else {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "pam_list: illegal option %s", argv[i]);
			return (PAM_SERVICE_ERR);
		}
	}

	if (((check_user || check_group || check_host ||
	    check_exact) == B_FALSE) || (allow_deny_test > 1)) {
		__pam_log(LOG_AUTH | LOG_ERR, ILLEGAL_COMBINATION);
		return (PAM_SERVICE_ERR);
	}

	if ((op_mode == LIST_COMPAT_MODE) && (check_user == B_FALSE)) {
		log_illegal_combination("compat", "nouser");
		return (PAM_SERVICE_ERR);
	}

	if ((op_mode == LIST_COMPAT_MODE) && (check_group == B_TRUE)) {
		log_illegal_combination("compat", "group");
		return (PAM_SERVICE_ERR);
	}

	if (debug) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_list: check_user = %d, check_host = %d,"
		    "check_exact = %d\n",
		    check_user, check_host, check_exact);

		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_list: auth_file: %s, %s\n", allowdeny_filename,
		    (op_mode == LIST_COMPAT_MODE) ? "compat mode" :
		    (allow ? "allow file" : "deny file"));
	}

	(void) pam_get_item(pamh, PAM_USER, (const void **)&username);

	if ((check_user || check_group || check_exact) && ((username == NULL) ||
	    (*username == '\0'))) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_list: username not supplied, critical error");
		return (PAM_USER_UNKNOWN);
	}

	(void) pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);

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
		    "pam_list: pam_sm_acct_mgmt for (%s,%s,)",
		    (rhost != NULL) ? rhost : "", username);
	}

	if (strlen(allowdeny_filename) == 0) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_list: file name not specified");
		return (PAM_SERVICE_ERR);
	}

	if ((fd = fopen(allowdeny_filename, "rF")) == NULL) {
		__pam_log(LOG_AUTH | LOG_ERR, "pam_list: fopen of %s: %s",
		    allowdeny_filename, strerror(errno));
		return (PAM_SERVICE_ERR);
	}

	if (check_group && ((grbuf = calloc(1, grbuflen)) == NULL)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_list: could not allocate memory for group");
		return (PAM_BUF_ERR);
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
		if (op_mode == LIST_COMPAT_MODE) {
			/* simple + matches all */
			if ((buf[0] == '+') && (buf[1] == '\0')) {
				matched = B_TRUE;
				allow = B_TRUE;
				break;
			}

			/* simple - is not defined */
			if ((buf[0] == '-') && (buf[1] == '\0')) {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "pam_list: simple minus unknown, "
				    "illegal line in " PF_PATH);
				(void) fclose(fd);
				free(grbuf);
				return (PAM_SERVICE_ERR);
			}

			/* @ is not allowed on the first position */
			if (buf[0] == '@') {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "pam_list: @ is not allowed on the first "
				    "position in " PF_PATH);
				(void) fclose(fd);
				free(grbuf);
				return (PAM_SERVICE_ERR);
			}

			/* -user or -@netgroup */
			if (buf[0] == '-') {
				allow = B_FALSE;
				bufp++;
			/* +user or +@netgroup */
			} else if (buf[0] == '+') {
				allow = B_TRUE;
				bufp++;
			/* user */
			} else {
				allow = B_TRUE;
			}
		} else if (op_mode == LIST_PLUS_CHECK) {
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
		 * else if -> group line
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
		} else if ((bufp[0] == '%') && (bufp[1] != '\0')) {
			char	**member;
			struct	group grp;

			if (check_group == B_FALSE)
				continue;

			bufp++;

			if (getgrnam_r(bufp, &grp, grbuf, grbuflen) != NULL) {
				for (member = grp.gr_mem; *member != NULL;
				    member++) {
					if (strcmp(*member, username) == 0) {
						matched = B_TRUE;
						break;
					}
				}
			} else {
				__pam_log(LOG_AUTH | LOG_ERR,
				    "pam_list: %s is not a known group",
				    bufp);
			}
		} else {
			if (check_user) {
				if (strcmp(bufp, username) == 0) {
					matched = B_TRUE;
					break;
				}
			}
		}

		/*
		 * No match found in /etc/passwd yet.  For compat mode
		 * a failure to match should result in a return of
		 * PAM_PERM_DENIED which is achieved below if 'matched'
		 * is false and 'allow' is true.
		 */
		if (op_mode == LIST_COMPAT_MODE) {
			allow = B_TRUE;
		}
	}
	(void) fclose(fd);
	free(grbuf);

	if (debug) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_list: %s for %s", matched ? "matched" : "no match",
		    allow ? "allow" : "deny");
	}

	if (matched) {
		return (allow ? PAM_SUCCESS : PAM_PERM_DENIED);
	}
	/*
	 * For compatibility with passwd_compat mode to prevent root access
	 * denied.
	 */
	if (op_mode == LIST_PLUS_CHECK) {
		return (PAM_IGNORE);
	}
	return (allow ? PAM_PERM_DENIED : PAM_SUCCESS);
}
