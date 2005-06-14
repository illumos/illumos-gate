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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains functions used for reading and writing the index file.
 * setzoneent() opens the file.  getzoneent() parses the file, doing the usual
 * skipping of comment lines, etc., and using gettok() to deal with the ":"
 * delimiters.  endzoneent() closes the file.  putzoneent() updates the file,
 * adding, deleting or modifying lines, locking and unlocking appropriately.
 */

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <libzonecfg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include "zonecfg_impl.h"


#define	_PATH_TMPFILE	ZONE_CONFIG_ROOT "/zonecfg.XXXXXX"

/*
 * gettok() is a helper function for parsing the index file, used to split
 * the lines by their ":" delimiters.  Note that an entry may contain a ":"
 * inside double quotes; this should only affect the zonepath, as zone names
 * do not allow such characters, and zone states do not have them either.
 * Same with double-quotes themselves: they are not allowed in zone names,
 * and do not occur in zone states, and in theory should never occur in a
 * zonepath since zonecfg does not support a method for escaping them.
 */

static char *
gettok(char **cpp)
{
	char *cp = *cpp, *retv;
	boolean_t quoted = B_FALSE;

	if (cp == NULL)
		return ("");
	if (*cp == '"') {
		quoted = B_TRUE;
		cp++;
	}
	retv = cp;
	if (quoted) {
		while (*cp != '\0' && *cp != '"')
			cp++;
		if (*cp == '"')
			*cp++ = '\0';
	}
	while (*cp != '\0' && *cp != ':')
		cp++;
	if (*cp == '\0') {
		*cpp = NULL;
	} else {
		*cp++ = '\0';
		*cpp = cp;
	}
	return (retv);
}

char *
getzoneent(FILE *cookie)
{
	struct zoneent *ze;
	char *name;

	if ((ze = getzoneent_private(cookie)) == NULL)
		return (NULL);
	name = strdup(ze->zone_name);
	free(ze);
	return (name);
}

struct zoneent *
getzoneent_private(FILE *cookie)
{
	char *cp, buf[MAX_INDEX_LEN], *p;
	struct zoneent *ze;

	if (cookie == NULL)
		return (NULL);

	if ((ze = malloc(sizeof (struct zoneent))) == NULL)
		return (NULL);

	for (;;) {
		if (fgets(buf, sizeof (buf), cookie) == NULL) {
			free(ze);
			return (NULL);
		}
		if ((cp = strpbrk(buf, "\r\n")) == NULL) {
			/* this represents a line that's too long */
			continue;
		}
		*cp = '\0';
		cp = buf;
		if (*cp == '#') {
			/* skip comment lines */
			continue;
		}
		p = gettok(&cp);
		if (p == NULL || *p == '\0' || strlen(p) > ZONENAME_MAX) {
			/*
			 * empty or very long zone names are not allowed
			 */
			continue;
		}
		(void) strlcpy(ze->zone_name, p, ZONENAME_MAX);

		p = gettok(&cp);
		if (p == NULL || *p == '\0') {
			/* state field should not be empty */
			continue;
		}
		errno = 0;
		if (strcmp(p, ZONE_STATE_STR_CONFIGURED) == 0) {
			ze->zone_state = ZONE_STATE_CONFIGURED;
		} else if (strcmp(p, ZONE_STATE_STR_INCOMPLETE) == 0) {
			ze->zone_state = ZONE_STATE_INCOMPLETE;
		} else if (strcmp(p, ZONE_STATE_STR_INSTALLED) == 0) {
			ze->zone_state = ZONE_STATE_INSTALLED;
		} else
			continue;

		p = gettok(&cp);
		if (strlen(p) > MAXPATHLEN) {
			/* very long paths are not allowed */
			continue;
		}
		if (p == NULL) {
			/* empty paths accepted for backwards compatibility */
			p = "";
		}
		(void) strlcpy(ze->zone_path, p, MAXPATHLEN);

		break;
	}

	return (ze);
}

FILE *
setzoneent(void)
{
	return (fopen(ZONE_INDEX_FILE, "r"));
}

void
endzoneent(FILE *cookie)
{
	if (cookie != NULL)
		(void) fclose(cookie);
}

static int
lock_index_file(int *lock_fd)
{
	struct flock lock;

	if ((mkdir(ZONE_SNAPSHOT_ROOT, S_IRWXU) == -1) && errno != EEXIST)
		return (Z_LOCKING_FILE);
	*lock_fd = open(ZONE_INDEX_LOCK_FILE, O_CREAT|O_RDWR, 0644);
	if (*lock_fd < 0)
		return (Z_LOCKING_FILE);

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(*lock_fd, F_SETLKW, &lock) == -1)
		return (Z_LOCKING_FILE);

	return (Z_OK);
}

static int
unlock_index_file(int lock_fd)
{
	struct flock lock;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLK, &lock) == -1)
		return (Z_UNLOCKING_FILE);

	if (close(lock_fd) == -1)
		return (Z_UNLOCKING_FILE);

	return (Z_OK);
}

/*
 * This function adds or removes a zone name et al. to the index file.
 *
 * If ze->zone_state is < 0, it means leave the
 * existing value unchanged; this is only meaningful when operation ==
 * PZE_MODIFY (i.e., it's bad on PZE_ADD and a no-op on PZE_DELETE).
 *
 * Likewise, a zero-length ze->zone_path means leave the existing value
 * unchanged; this is only meaningful when operation == PZE_MODIFY
 * (i.e., it's bad on PZE_ADD and a no-op on PZE_DELETE).
 *
 * Locking and unlocking is done via the functions above.
 * The file itself is not modified in place; rather, a copy is made which
 * is modified, then the copy is atomically renamed back to the main file.
 */

int
putzoneent(struct zoneent *ze, zoneent_op_t operation)
{
	FILE *index_file, *tmp_file;
	char *tmp_file_name, buf[MAX_INDEX_LEN], orig_buf[MAX_INDEX_LEN];
	char zone[ZONENAME_MAX + 1];		/* name plus newline */
	char line[MAX_INDEX_LEN];
	int tmp_file_desc, lock_fd, err;
	boolean_t exists = B_FALSE, need_quotes;
	char *cp, *p;

	assert(ze != NULL);
	if (operation == PZE_ADD &&
	    (ze->zone_state < 0 || strlen(ze->zone_path) == 0))
		return (Z_INVAL);
	if ((err = lock_index_file(&lock_fd)) != Z_OK)
		return (err);
	tmp_file_name = strdup(_PATH_TMPFILE);
	if (tmp_file_name == NULL) {
		(void) unlock_index_file(lock_fd);
		return (Z_NOMEM);
	}
	tmp_file_desc = mkstemp(tmp_file_name);
	if (tmp_file_desc == -1) {
		(void) unlink(tmp_file_name);
		free(tmp_file_name);
		(void) unlock_index_file(lock_fd);
		return (Z_TEMP_FILE);
	}
	if ((tmp_file = fdopen(tmp_file_desc, "w")) == NULL) {
		(void) close(tmp_file_desc);
		(void) unlink(tmp_file_name);
		free(tmp_file_name);
		(void) unlock_index_file(lock_fd);
		return (Z_MISC_FS);
	}
	if ((index_file = fopen(ZONE_INDEX_FILE, "r")) == NULL) {
		(void) fclose(tmp_file);
		(void) unlink(tmp_file_name);
		free(tmp_file_name);
		(void) unlock_index_file(lock_fd);
		return (Z_MISC_FS);
	}

	/*
	 * We need to quote a path which contains a ":"; this should only
	 * affect the zonepath, as zone names do not allow such characters,
	 * and zone states do not have them either.  Same with double-quotes
	 * themselves: they are not allowed in zone names, and do not occur
	 * in zone states, and in theory should never occur in a zonepath
	 * since zonecfg does not support a method for escaping them.
	 */
	need_quotes = (strchr(ze->zone_path, ':') != NULL);

	(void) snprintf(line, sizeof (line), "%s:%s:%s%s%s\n", ze->zone_name,
	    zone_state_str(ze->zone_state), need_quotes ? "\"" : "",
	    ze->zone_path, need_quotes ? "\"" : "");
	for (;;) {
		if (fgets(buf, sizeof (buf), index_file) == NULL) {
			if (operation == PZE_ADD && !exists)
				(void) fputs(line, tmp_file);
			break;
		}
		(void) strlcpy(orig_buf, buf, sizeof (orig_buf));

		if ((cp = strpbrk(buf, "\r\n")) == NULL) {
			/* this represents a line that's too long */
			continue;
		}
		*cp = '\0';
		cp = buf;
		if (*cp == '#') {
			/* skip comment lines */
			(void) fputs(orig_buf, tmp_file);
			continue;
		}
		p = gettok(&cp);
		if (p == NULL || *p == '\0' || strlen(p) > ZONENAME_MAX) {
			/*
			 * empty or very long zone names are not allowed
			 */
			continue;
		}
		(void) strlcpy(zone, p, ZONENAME_MAX);

		if (strcmp(zone, ze->zone_name) == 0) {
			exists = B_TRUE;		/* already there */
			if (operation == PZE_ADD) {
				/* can't add same zone */
				goto error;
			} else if (operation == PZE_MODIFY) {
				char tmp_state[ZONE_STATE_MAXSTRLEN + 1];

				if (ze->zone_state >= 0 &&
				    strlen(ze->zone_path) > 0) {
					/* use specified values */
					(void) fputs(line, tmp_file);
					continue;
				}
				/* use existing value for state */
				p = gettok(&cp);
				if (p == NULL || *p == '\0') {
					/* state field should not be empty */
					goto error;
				}
				(void) strlcpy(tmp_state,
				    (ze->zone_state < 0) ? p :
				    zone_state_str(ze->zone_state),
				    sizeof (tmp_state));

				p = gettok(&cp);

				(void) fprintf(tmp_file, "%s:%s:%s%s%s\n",
				    ze->zone_name, tmp_state,
				    need_quotes ? "\"" : "",
				    (strlen(ze->zone_path) == 0) ? p :
				    ze->zone_path, need_quotes ? "\"" : "");
			}
		} else {
			(void) fputs(orig_buf, tmp_file);
		}
	}

	(void) fclose(index_file);
	if (fclose(tmp_file) != 0) {
		(void) unlink(tmp_file_name);
		free(tmp_file_name);
		(void) unlock_index_file(lock_fd);
		return (Z_MISC_FS);
	}
	(void) chmod(tmp_file_name, 0644);
	if (rename(tmp_file_name, ZONE_INDEX_FILE) == -1) {
		(void) unlink(tmp_file_name);
		free(tmp_file_name);
		(void) unlock_index_file(lock_fd);
		if (errno == EACCES)
			return (Z_ACCES);
		return (Z_MISC_FS);
	}
	free(tmp_file_name);
	if (unlock_index_file(lock_fd) != Z_OK)
		return (Z_UNLOCKING_FILE);
	return (Z_OK);
error:
	(void) fclose(index_file);
	(void) fclose(tmp_file);
	(void) unlink(tmp_file_name);
	free(tmp_file_name);
	if (unlock_index_file(lock_fd) != Z_OK)
		return (Z_UNLOCKING_FILE);
	return (Z_UPDATING_INDEX);
}
