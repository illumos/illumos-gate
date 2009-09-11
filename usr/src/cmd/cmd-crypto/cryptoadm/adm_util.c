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
 */

#include <ctype.h>
#include <strings.h>
#include <libintl.h>
#include <stdio.h>
#include <sys/stat.h>
#include "cryptoadm.h"
#include <cryptoutil.h>

/*
 * Create one item of type mechlist_t with the mechanism name.  A null is
 * returned to indicate that the storage space available is insufficient.
 */
mechlist_t *
create_mech(char *name)
{
	mechlist_t *pres = NULL;
	char *first, *last;

	if (name == NULL) {
		return (NULL);
	}

	pres = malloc(sizeof (mechlist_t));
	if (pres == NULL) {
		cryptodebug("out of memory.");
		return (NULL);
	}

	first = name;
	while (isspace(*first)) /* nuke leading whitespace */
		first++;
	(void) strlcpy(pres->name, first, sizeof (pres->name));

	last = strrchr(pres->name, '\0');
	last--;
	while (isspace(*last))  /* nuke trailing whitespace */
		*last-- = '\0';

	pres->next = NULL;

	return (pres);
}



void
free_mechlist(mechlist_t *plist)
{
	mechlist_t *pnext;

	while (plist != NULL) {
		pnext = plist->next;
		free(plist);
		plist = pnext;
	}
}



/*
 * Check if the mechanism is in the mechanism list.
 */
boolean_t
is_in_list(char *mechname, mechlist_t *plist)
{
	boolean_t found = B_FALSE;

	if (mechname == NULL) {
		return (B_FALSE);
	}

	while (plist != NULL) {
		if (strcmp(plist->name, mechname) == 0) {
			found = B_TRUE;
			break;
		}
		plist = plist->next;
	}

	return (found);
}

int
update_conf(char *conf_file, char *entry)
{

	boolean_t	found;
	FILE	*pfile;
	FILE	*pfile_tmp;
	char	tmpfile_name[MAXPATHLEN];
	char	*ptr;
	char	*name;
	char	buffer[BUFSIZ];
	char	buffer2[BUFSIZ];
	int		found_count;
	int		rc = SUCCESS;
	int		err;

	if ((pfile = fopen(conf_file, "r+")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to open %s for write.", conf_file);
		return (FAILURE);
	}

	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to lock the configuration - %s"),
		    strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}

	/*
	 * Create a temporary file in the /etc/crypto directory.
	 */
	(void) strlcpy(tmpfile_name, TMPFILE_TEMPLATE, sizeof (tmpfile_name));
	if (mkstemp(tmpfile_name) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to create a temporary file - %s"),
		    strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}

	if ((pfile_tmp = fopen(tmpfile_name, "w")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s - %s"),
		    tmpfile_name, strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}


	/*
	 * Loop thru the config file. If the provider was reserved within a
	 * package bracket, just uncomment it.  Otherwise, append it at
	 * the end.  The resulting file will be saved in the temp file first.
	 */
	found_count = 0;
	rc = SUCCESS;

	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		found = B_FALSE;
		if (strcmp(conf_file, _PATH_PKCS11_CONF) == 0) {
			if (buffer[0] == '#') {
				ptr = buffer;
				ptr++;
				if (strcmp(entry, ptr) == 0) {
					found = B_TRUE;
					found_count++;
				}
			}
		} else { /* _PATH_KCF_CONF */
			if (buffer[0] == '#') {
				(void) strlcpy(buffer2, buffer, BUFSIZ);
				ptr = buffer2;
				ptr++; /* skip # */
				if ((name = strtok(ptr, SEP_COLON)) == NULL) {
					rc = FAILURE;
					break;
				} else if (strcmp(FIPS_KEYWORD, name) == 0) {
					found = B_TRUE;
					found_count++;
				}
			} else {
				(void) strlcpy(buffer2, buffer, BUFSIZ);
				ptr = buffer2;
				if ((name = strtok(ptr, SEP_COLON)) == NULL) {
					rc = FAILURE;
					break;
				} else if (strcmp(FIPS_KEYWORD, name) == 0) {
					found = B_TRUE;
					found_count++;
				}
			}
		}

		if (found == B_FALSE) {
			if (fputs(buffer, pfile_tmp) == EOF) {
				rc = FAILURE;
			}
		} else {
			if (found_count == 1) {
				if (strcmp(conf_file, _PATH_PKCS11_CONF) == 0) {
					if (fputs(ptr, pfile_tmp) == EOF) {
						rc = FAILURE;
					}
				} else {
					if (fputs(entry, pfile_tmp) == EOF) {
						rc = FAILURE;
					}
				}
			} else {
				/*
				 * Found a second entry with same tag name.
				 * Should not happen. The config file
				 * is corrupted. Give a warning and skip
				 * this entry.
				 */
				cryptoerror(LOG_STDERR, gettext(
				    "(Warning) Found an additional reserved "
				    "entry for %s."), entry);
			}
		}

		if (rc == FAILURE) {
			break;
		}
	}

	(void) fclose(pfile);

	if (rc == FAILURE) {
		cryptoerror(LOG_STDERR, gettext("write error."));
		(void) fclose(pfile_tmp);
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"), tmpfile_name,
			    strerror(err));
		}
		return (FAILURE);
	}

	if (found_count == 0) {
		/*
		 * The entry was not in config file before, append it to the
		 * end of the temp file.
		 */
		if (fputs(entry, pfile_tmp) == EOF) {
			cryptoerror(LOG_STDERR, gettext(
			    "failed to write to %s: %s"), tmpfile_name,
			    strerror(errno));
			(void) fclose(pfile_tmp);
			if (unlink(tmpfile_name) != 0) {
				err = errno;
				cryptoerror(LOG_STDERR, gettext(
				    "(Warning) failed to remove %s: %s"),
				    tmpfile_name, strerror(err));
			}
			return (FAILURE);
		}
	}

	if (fclose(pfile_tmp) != 0) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to close %s: %s"), tmpfile_name,
		    strerror(err));
		return (FAILURE);
	}

	if (rename(tmpfile_name, conf_file) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to rename %s to %s: %s", tmpfile_name,
		    conf_file, strerror(err));
		rc = FAILURE;
	} else if (chmod(conf_file,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to chmod to %s: %s", conf_file,
		    strerror(err));
		rc = FAILURE;
	} else {
		rc = SUCCESS;
	}

	if (rc == FAILURE) {
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"),
			    tmpfile_name, strerror(err));
		}
	}

	return (rc);

}
