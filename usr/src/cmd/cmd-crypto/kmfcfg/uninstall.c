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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <libgen.h>
#include <libintl.h>
#include <errno.h>
#include <kmfapiP.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <cryptoutil.h>
#include "util.h"

static int err; /* To store errno which may be overwritten by gettext() */

int
kc_uninstall(int argc, char *argv[])
{
	int 		rv = KC_OK;
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char 		*keystore_name = NULL;
	conf_entry_t	*entry = NULL;
	FILE		*pfile = NULL;
	FILE		*pfile_tmp = NULL;
	char		tmpfile_name[MAXPATHLEN];
	char		buffer[MAXPATHLEN];
	char		buffer2[MAXPATHLEN];
	boolean_t 	found;
	boolean_t	in_package;

	while ((opt = getopt_av(argc, argv, "k:(keystore)")) != EOF) {
		switch (opt) {
		case 'k':
			if (keystore_name != NULL)
				rv = KC_ERR_USAGE;
			else {
				keystore_name = get_string(optarg_av, &rv);
				if (keystore_name == NULL) {
					(void) fprintf(stderr, gettext(
					    "Error keystore input.\n"));
				}
			}
			break;
		default:
			(void) fprintf(stderr,
			    gettext("Error input option.\n"));
			rv = KC_ERR_USAGE;
			break;
		}
		if (rv != KC_OK)
			goto out;
	}

	/* No additional args allowed. */
	argc -= optind_av;
	if (argc) {
		(void) fprintf(stderr,
		    gettext("Error input option\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	if (keystore_name == NULL) {
		(void) fprintf(stderr,
		    gettext("Error input option\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	if (strcasecmp(keystore_name, "nss") == 0 ||
	    strcasecmp(keystore_name, "pkcs11") == 0 ||
	    strcasecmp(keystore_name, "file") == 0) {
		(void) fprintf(stderr,
		    gettext("Can not uninstall the built-in keystore %s\n"),
		    keystore_name);
		rv = KC_ERR_UNINSTALL;
		goto out;
	}

	entry = get_keystore_entry(keystore_name);
	if (entry == NULL) {
		(void) fprintf(stderr, gettext("%s does not exist.\n"),
		    keystore_name);
		rv = KC_ERR_USAGE;
		goto out;
	}

	if ((pfile = fopen(_PATH_KMF_CONF, "r+")) == NULL) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("failed to update the configuration - %s\n"),
		    strerror(err));
		rv = KC_ERR_ACCESS;
		goto out;
	}

	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("failed to lock the configuration - %s\n"),
		    strerror(err));
		rv = KC_ERR_UNINSTALL;
		goto out;
	}

	/*
	 * Create a temporary file in the /etc/crypto directory.
	 */
	(void) strlcpy(tmpfile_name, CONF_TEMPFILE, sizeof (tmpfile_name));
	if (mkstemp(tmpfile_name) == -1) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("failed to create a temporary file - %s\n"),
		    strerror(err));
		rv = KC_ERR_UNINSTALL;
		goto out;
	}

	if ((pfile_tmp = fopen(tmpfile_name, "w")) == NULL) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("failed to open a temporary file - %s\n"),
		    strerror(err));
		rv = KC_ERR_UNINSTALL;
		goto out;
	}

	/*
	 * Loop thru the config file. If the plugin to be uninstalled is in
	 * a package, then just comment it off.
	 */
	in_package = B_FALSE;
	while (fgets(buffer, MAXPATHLEN, pfile) != NULL) {
		found = B_FALSE;
		if (buffer[0] != ' ' && buffer[0] != '\n' &&
		    buffer[0] != '\t') {
			if (strstr(buffer, " Start ") != NULL) {
				in_package = B_TRUE;
			} else if (strstr(buffer, " End ") != NULL) {
				in_package = B_FALSE;
			} else if (buffer[0] != '#') {
				char *name;
				int len;

				/*
				 * make a copy of the original buffer to
				 * buffer2.  Also get rid of the trailing
				 * '\n' from buffer2.
				 */
				(void) strlcpy(buffer2, buffer, MAXPATHLEN);
				/* get rid of trailing '\n' */
				len = strlen(buffer2);
				if (buffer2[len-1] == '\n') {
					len--;
				}
				buffer2[len] = '\0';

				if ((name = strtok(buffer2, SEP_COLON)) ==
				    NULL) {
					rv = KC_ERR_UNINSTALL;
					goto out;
				}

				if (strcmp(keystore_name, name) == 0)
					found = B_TRUE;
			}
		}

		if (found) {
			/*
			 * If found and not in_package, then don't write
			 * this line to the result file.
			 */
			if (in_package) {
				(void) snprintf(buffer2, sizeof (buffer2),
				    "%s%s", "#", buffer);

				if (fputs(buffer2, pfile_tmp) == EOF) {
					rv = KC_ERR_UNINSTALL;
					goto out;
				}
			}
		} else {
			if (fputs(buffer, pfile_tmp) == EOF) {
				rv = KC_ERR_UNINSTALL;
				goto out;
			}
		}
	}

out:
	if (pfile != NULL)
		(void) fclose(pfile);

	if (rv != KC_OK && pfile_tmp != NULL)
		(void) unlink(tmpfile_name);

	if (pfile_tmp != NULL)
		(void) fclose(pfile_tmp);

	if (rv == KC_OK) {
		if (rename(tmpfile_name, _PATH_KMF_CONF) == -1) {
			err = errno;
			(void) fprintf(stderr, gettext(
			    "failed to update the configuration - %s"),
			    strerror(err));
			return (KC_ERR_UNINSTALL);
		}

		if (chmod(_PATH_KMF_CONF,
		    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
			err = errno;
			(void) fprintf(stderr, gettext(
			    "failed to update the configuration - %s\n"),
			    strerror(err));
			return (KC_ERR_UNINSTALL);
		}
	}

	return (rv);
}
