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
kc_install(int argc, char *argv[])
{
	int 		rv = KC_OK;
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char 		*keystore_name = NULL;
	char 		*modulepath = NULL;
	char		*option_str = NULL;
	conf_entry_t	*entry = NULL;
	char		realpath[MAXPATHLEN];
	struct stat 	statbuf;
	FILE		*pfile = NULL;
	FILE		*pfile_tmp = NULL;
	char		tmpfile_name[MAXPATHLEN];
	int		found_count = 0;
	char		buffer[BUFSIZ];
	char		*ptr;
	boolean_t 	found;

	while ((opt = getopt_av(argc, argv, "k:(keystore)m:(modulepath)"
	    "o:(option)")) != EOF) {
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
		case 'm':
			if (modulepath != NULL)
				rv = KC_ERR_USAGE;
			else {
				modulepath = get_string(optarg_av, &rv);
				if (modulepath == NULL) {
					(void) fprintf(stderr,
					    gettext("Error modulepath.\n"));
				}
			}
			break;
		case 'o':
			if (option_str != NULL) {
				rv = KC_ERR_USAGE;
			} else {
				option_str = get_string(optarg_av, &rv);
				if (option_str == NULL) {
					(void) fprintf(stderr,
					    gettext("Error option input.\n"));
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

	if (keystore_name == NULL || modulepath == NULL) {
		(void) fprintf(stderr, gettext("Error input option\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	if (strcasecmp(keystore_name, "nss") == 0 ||
	    strcasecmp(keystore_name, "pkcs11") == 0 ||
	    strcasecmp(keystore_name, "file") == 0) {
		(void) fprintf(stderr,
		    gettext("Can not use the built-in keystore name %s\n"),
		    keystore_name);
		rv = KC_ERR_USAGE;
		goto out;
	}

	entry = get_keystore_entry(keystore_name);
	if (entry != NULL) {
		(void) fprintf(stderr, gettext("%s exists already.\n"),
		    keystore_name);
		rv = KC_ERR_USAGE;
		goto out;
	}

	/*
	 * Find the absolute path of the module and check if it exists in
	 * the system.  If $ISA is in the path, will check the 32bit version
	 * only.
	 */
	if (strncmp(modulepath, "/", 1) != 0) {
		/*
		 * Only contain the base name; prepand it with
		 * KMF_PLUGIN_PATH
		 */
		(void) snprintf(realpath, MAXPATHLEN, "%s%s",
		    KMF_PLUGIN_PATH, modulepath);
	} else {
		char *buf = modulepath;
		char *isa;

		if ((isa = strstr(buf, PKCS11_ISA)) != NULL) {
			(void) strncpy(realpath, buf, isa - buf);
			isa += strlen(PKCS11_ISA) - 1;
			(void) strlcat(realpath, isa, MAXPATHLEN);
		} else {
			(void) strlcpy(realpath, modulepath, MAXPATHLEN);
		}
	}

	if (stat(realpath, &statbuf) != 0) {
		(void) fprintf(stderr, gettext("%s not found.\n"),
		    realpath);
		rv = KC_ERR_ACCESS;
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
		rv = KC_ERR_INSTALL;
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
		rv = KC_ERR_INSTALL;
		goto out;
	}

	if ((pfile_tmp = fopen(tmpfile_name, "w")) == NULL) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("failed to open %s - %s\n"),
		    tmpfile_name, strerror(err));
		rv = KC_ERR_INSTALL;
		goto out;
	}

	/*
	 * Loop thru the config file. If the file was reserved within a
	 * package bracket, just uncomment it.  Other wise, append it at
	 * the end.  The resulting file will be saved in the temp file first.
	 */
	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		found = B_FALSE;
		if (buffer[0] == '#') {
			ptr = buffer;
			ptr++;
			while (*ptr == '#' || *ptr == ' ')
				ptr++;
			if (strncmp(keystore_name, ptr, strlen(keystore_name))
			    == 0) {
				found = B_TRUE;
				found_count++;
			}
		}

		if (found == B_FALSE) {
			if (fputs(buffer, pfile_tmp) == EOF) {
				rv = KC_ERR_INSTALL;
				goto out;
			}
		} else {
			if (found_count == 1) {
				if (fputs(ptr, pfile_tmp) == EOF) {
					rv = KC_ERR_INSTALL;
					goto out;
				}
			} else {
				/*
				 * Found a second entry with #keystore_name.
				 * This should not happen. The kmf.conf file
				 * is corrupted. Give a warning and skip
				 * this entry.
				 */
				(void) fprintf(stderr, gettext(
				    "(Warning) Found an additional reserved "
				    "entry for %s.\n"), keystore_name);
			}
		}
	}

	if (found_count == 0) {
		char buf[MAXPATHLEN];
		/*
		 * This entry was not in package before, append it to the
		 * end of the temp file.
		 */
		if (option_str == NULL)
			(void) snprintf(buf, MAXPATHLEN, "%s:%s%s\n",
			    keystore_name, CONF_MODULEPATH, modulepath);
		else
			(void) snprintf(buf, MAXPATHLEN, "%s:%s%s;%s%s\n",
			    keystore_name, CONF_MODULEPATH, modulepath,
			    CONF_OPTION, option_str);

		if (fputs(buf, pfile_tmp) == EOF) {
			err = errno;
			(void) fprintf(stderr, gettext(
			    "failed to write to %s: %s\n"), tmpfile_name,
			    strerror(err));
			rv = KC_ERR_INSTALL;
			goto out;
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
			return (KC_ERR_INSTALL);
		}

		if (chmod(_PATH_KMF_CONF,
		    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
			err = errno;
			(void) fprintf(stderr, gettext(
			    "failed to update the configuration - %s\n"),
			    strerror(err));
			return (KC_ERR_INSTALL);
		}
	}

	return (rv);
}
