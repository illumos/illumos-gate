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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
#include <string.h>
#include <errno.h>
#include <libzonecfg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include <uuid/uuid.h>
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
 *
 * It never returns NULL.
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
		if (*p == '\0' || strlen(p) >= ZONENAME_MAX) {
			/*
			 * empty or very long zone names are not allowed
			 */
			continue;
		}
		(void) strlcpy(ze->zone_name, p, ZONENAME_MAX);

		p = gettok(&cp);
		if (*p == '\0') {
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
		} else {
			continue;
		}

		p = gettok(&cp);
		if (strlen(p) >= MAXPATHLEN) {
			/* very long paths are not allowed */
			continue;
		}
		(void) strlcpy(ze->zone_path, p, MAXPATHLEN);

		p = gettok(&cp);
		if (uuid_parse(p, ze->zone_uuid) == -1)
			uuid_clear(ze->zone_uuid);

		break;
	}

	return (ze);
}

static boolean_t
get_index_path(char *path)
{
	return (snprintf(path, MAXPATHLEN, "%s%s", zonecfg_root,
	    ZONE_INDEX_FILE) < MAXPATHLEN);
}

FILE *
setzoneent(void)
{
	char path[MAXPATHLEN];

	if (!get_index_path(path)) {
		errno = EINVAL;
		return (NULL);
	}
	return (fopen(path, "r"));
}

void
endzoneent(FILE *cookie)
{
	if (cookie != NULL)
		(void) fclose(cookie);
}

static int
lock_index_file(void)
{
	int lock_fd;
	struct flock lock;
	char path[MAXPATHLEN];

	if (snprintf(path, sizeof (path), "%s%s", zonecfg_root,
	    ZONE_INDEX_LOCK_DIR) >= sizeof (path))
		return (-1);
	if ((mkdir(path, S_IRWXU) == -1) && errno != EEXIST)
		return (-1);
	if (strlcat(path, ZONE_INDEX_LOCK_FILE, sizeof (path)) >=
	    sizeof (path))
		return (-1);
	lock_fd = open(path, O_CREAT|O_RDWR, 0644);
	if (lock_fd == -1)
		return (-1);

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLKW, &lock) == -1) {
		(void) close(lock_fd);
		return (-1);
	}

	return (lock_fd);
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
 * PZE_MODIFY (i.e., it's bad on PZE_ADD and a no-op on PZE_REMOVE).
 *
 * A zero-length ze->zone_path means leave the existing value
 * unchanged; this is only meaningful when operation == PZE_MODIFY
 * (i.e., it's bad on PZE_ADD and a no-op on PZE_REMOVE).
 *
 * A zero-length ze->zone_newname means leave the existing name
 * unchanged; otherwise the zone is renamed to zone_newname.  This is
 * only meaningful when operation == PZE_MODIFY.
 *
 * Locking and unlocking is done via the functions above.
 * The file itself is not modified in place; rather, a copy is made which
 * is modified, then the copy is atomically renamed back to the main file.
 */
int
putzoneent(struct zoneent *ze, zoneent_op_t operation)
{
	FILE *index_file, *tmp_file;
	char *tmp_file_name, buf[MAX_INDEX_LEN];
	int tmp_file_desc, lock_fd, err;
	boolean_t exist, need_quotes;
	char *cp;
	char path[MAXPATHLEN];
	char uuidstr[UUID_PRINTABLE_STRING_LENGTH];
	size_t tlen, namelen;
	const char *zone_name, *zone_state, *zone_path, *zone_uuid;

	assert(ze != NULL);
	if (operation == PZE_ADD &&
	    (ze->zone_state < 0 || strlen(ze->zone_path) == 0))
		return (Z_INVAL);

	if (operation != PZE_MODIFY && strlen(ze->zone_newname) != 0)
		return (Z_INVAL);

	if ((lock_fd = lock_index_file()) == -1)
		return (Z_LOCKING_FILE);

	/* using sizeof gives us room for the terminating NUL byte as well */
	tlen = sizeof (_PATH_TMPFILE) + strlen(zonecfg_root);
	tmp_file_name = malloc(tlen);
	if (tmp_file_name == NULL) {
		(void) unlock_index_file(lock_fd);
		return (Z_NOMEM);
	}
	(void) snprintf(tmp_file_name, tlen, "%s%s", zonecfg_root,
	    _PATH_TMPFILE);

	tmp_file_desc = mkstemp(tmp_file_name);
	if (tmp_file_desc == -1) {
		(void) unlink(tmp_file_name);
		free(tmp_file_name);
		(void) unlock_index_file(lock_fd);
		return (Z_TEMP_FILE);
	}
	(void) fchmod(tmp_file_desc, ZONE_INDEX_MODE);
	(void) fchown(tmp_file_desc, ZONE_INDEX_UID, ZONE_INDEX_GID);
	if ((tmp_file = fdopen(tmp_file_desc, "w")) == NULL) {
		(void) close(tmp_file_desc);
		err = Z_MISC_FS;
		goto error;
	}
	if (!get_index_path(path)) {
		err = Z_MISC_FS;
		goto error;
	}
	if ((index_file = fopen(path, "r")) == NULL) {
		err = Z_MISC_FS;
		goto error;
	}

	exist = B_FALSE;
	zone_name = ze->zone_name;
	namelen = strlen(zone_name);
	for (;;) {
		if (fgets(buf, sizeof (buf), index_file) == NULL) {
			if (operation == PZE_ADD && !exist) {
				zone_state = zone_state_str(ze->zone_state);
				zone_path = ze->zone_path;
				zone_uuid = "";
				goto add_entry;
			}
			/*
			 * It's not considered an error to delete something
			 * that doesn't exist, but we can't modify a missing
			 * record.
			 */
			if (operation == PZE_MODIFY && !exist) {
				err = Z_UPDATING_INDEX;
				goto error;
			}
			break;
		}

		if (buf[0] == '#') {
			/* skip and preserve comment lines */
			(void) fputs(buf, tmp_file);
			continue;
		}

		if (strncmp(buf, zone_name, namelen) != 0 ||
		    buf[namelen] != ':') {
			/* skip and preserve non-target lines */
			(void) fputs(buf, tmp_file);
			continue;
		}

		if ((cp = strpbrk(buf, "\r\n")) == NULL) {
			/* this represents a line that's too long; delete */
			continue;
		}
		*cp = '\0';

		/*
		 * Skip over the zone name.  Because we've already matched the
		 * target zone (above), we know for certain here that the zone
		 * name is present and correctly formed.  No need to check.
		 */
		cp = strchr(buf, ':') + 1;

		zone_state = gettok(&cp);
		if (*zone_state == '\0') {
			/* state field should not be empty */
			err = Z_UPDATING_INDEX;
			goto error;
		}
		zone_path = gettok(&cp);
		zone_uuid = gettok(&cp);

		switch (operation) {
		case PZE_ADD:
			/* can't add same zone */
			err = Z_UPDATING_INDEX;
			goto error;

		case PZE_MODIFY:
			/*
			 * If the caller specified a new state for the zone,
			 * then use that.  Otherwise, use the current state.
			 */
			if (ze->zone_state >= 0) {
				zone_state = zone_state_str(ze->zone_state);

				/*
				 * If the caller is uninstalling this zone,
				 * then wipe out the uuid.  The zone's contents
				 * are no longer known.
				 */
				if (ze->zone_state < ZONE_STATE_INSTALLED)
					zone_uuid = "";
			}

			/* If a new name is supplied, use it. */
			if (ze->zone_newname[0] != '\0')
				zone_name = ze->zone_newname;

			if (ze->zone_path[0] != '\0')
				zone_path = ze->zone_path;
			break;

		case PZE_REMOVE:
		default:
			continue;
		}

	add_entry:
		/*
		 * If the entry in the file is in greater than configured
		 * state, then we must have a UUID.  Make sure that we do.
		 * (Note that the file entry is only tokenized, not fully
		 * parsed, so we need to do a string comparison here.)
		 */
		if (strcmp(zone_state, ZONE_STATE_STR_CONFIGURED) != 0 &&
		    *zone_uuid == '\0') {
			if (uuid_is_null(ze->zone_uuid))
				uuid_generate(ze->zone_uuid);
			uuid_unparse(ze->zone_uuid, uuidstr);
			zone_uuid = uuidstr;
		}
		/*
		 * We need to quote a path that contains a ":"; this should
		 * only affect the zonepath, as zone names do not allow such
		 * characters, and zone states do not have them either.  Same
		 * with double-quotes themselves: they are not allowed in zone
		 * names, and do not occur in zone states, and in theory should
		 * never occur in a zonepath since zonecfg does not support a
		 * method for escaping them.
		 */
		need_quotes = (strchr(zone_path, ':') != NULL);
		(void) fprintf(tmp_file, "%s:%s:%s%s%s:%s\n", zone_name,
		    zone_state, need_quotes ? "\"" : "", zone_path,
		    need_quotes ? "\"" : "", zone_uuid);
		exist = B_TRUE;
	}

	(void) fclose(index_file);
	index_file = NULL;
	if (fclose(tmp_file) != 0) {
		tmp_file = NULL;
		err = Z_MISC_FS;
		goto error;
	}
	tmp_file = NULL;
	if (rename(tmp_file_name, path) == -1) {
		err = errno == EACCES ? Z_ACCES : Z_MISC_FS;
		goto error;
	}
	free(tmp_file_name);
	if (unlock_index_file(lock_fd) != Z_OK)
		return (Z_UNLOCKING_FILE);
	return (Z_OK);

error:
	if (index_file != NULL)
		(void) fclose(index_file);
	if (tmp_file != NULL)
		(void) fclose(tmp_file);
	(void) unlink(tmp_file_name);
	free(tmp_file_name);
	(void) unlock_index_file(lock_fd);
	return (err);
}
