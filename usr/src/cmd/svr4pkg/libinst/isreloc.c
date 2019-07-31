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



#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pkglib.h>
#include <libintl.h>
#include <libinst.h>
#include <install.h>

#define	ERR_NOPKGMAP	"Cannot open pkgmap file."

#define	ENTRY_MAX (PATH_MAX + 38)
#define	IGNORE_START	":#!"
#define	IGNORE_TYPE	"i"

static int	has_rel_path(char *entry);
static int	is_relative(char *entry);

/*
 * This routine attempts to determine with certainty whether or not
 * the package is relocatable or not. It first attempts to determine if
 * there is a reloc directory by scanning pkginstdir. If that fails to
 * provide a definite result (pkg is coming from a stream device and
 * the directories aren't in place) it inspects the pkgmap in pkginstdir
 * in order to determine if the package has relocatable elements. If
 * there is a single relative pathname or $BASEDIR/... construct,
 * this returns 1. If no relative pathnames are found it returns 0
 * meaning absolute package and all the things that implies.
 *
 * This does not determine the validity of the pkgmap file. If the pkgmap
 * is corrupted, this returns 0.
 */
int
isreloc(char *pkginstdir)
{
	FILE	*pkg_fp;
	struct	dirent *drp;
	DIR	*dirfp;
	int	retcode = 0;

	/* First look in the directory */
	if ((dirfp = opendir(pkginstdir)) != NULL) {
		while ((drp = readdir(dirfp)) != NULL) {
			if (drp->d_name[0] == '.')
				continue;
			if (strlen(drp->d_name) < (size_t)5)
				continue;
			if (strncmp(drp->d_name, "reloc", 5) == 0) {
				retcode = 1;
				break;
			}
		}
		(void) closedir(dirfp);
	}

	/*
	 * If retcode == 0, meaning we didn't find a reloc directory then we
	 * probably don't have a complete directory structure available to
	 * us. We'll have to determine what type of package it is by scanning
	 * the pkgmap file.
	 */
	if (retcode == 0) {
		char	path_buffer[ENTRY_MAX];

		(void) snprintf(path_buffer, sizeof (path_buffer),
						"%s/pkgmap", pkginstdir);

		canonize(path_buffer);

		if ((pkg_fp = fopen(path_buffer, "r")) != NULL) {
			while (fgets(path_buffer, sizeof (path_buffer), pkg_fp))
				if (has_rel_path(path_buffer)) {
					retcode = 1;
					break;
				}
			(void) fclose(pkg_fp);
		} else {
			progerr(gettext(ERR_NOPKGMAP));
			quit(99);
		}
	}

	return (retcode);
}

/*
 * Test the string for the presence of a relative path. If found, return
 * 1 otherwise return 0. If we get past the IGNORE_TYPE test, we're working
 * with a line of the form :
 *
 *	dpart type classname pathname ...
 *
 * It's pathname we're going to test here.
 *
 * Yes, yes, I know about sscanf(); but, I don't need to reserve 4K of
 * space and parse the whole string, I just need to get to two tokens.
 * We're in a hurry.
 */
static int
has_rel_path(char *entry)
{
	register int entry_pos = 1;

	/* If the line is a comment or special directive, return 0 */
	if (*entry == '\0' || strchr(IGNORE_START, *entry) != NULL)
		return (0);

	/* Skip past this data entry if it is volume number. */
	if (isdigit(*entry)) {
		while (*entry && !isspace(*entry)) {
			entry++;
		}
	}

	/* Skip past this white space */
	while (*entry && isspace(*entry)) {
		entry++;
	}

	/*
	 * Now we're either pointing at the type or we're pointing at
	 * the termination of a degenerate entry. If the line is degenerate
	 * or the type indicates this line should be ignored, we return
	 * as though not relative.
	 */
	if (*entry == '\0' || strchr(IGNORE_TYPE, *entry))
		return (0);

	/* The pathname is in the third position */
	do {
		/* Skip past this data entry */
		while (*entry && !isspace(*entry)) {
			entry++;
		}

		/* Skip past this white space and call this the next entry */
		while (*entry && isspace(*entry)) {
			entry++;
		}
	} while (++entry_pos < 3 && *entry != '\0');

	/*
	 * Now we're pointing at the first character of the pathname.
	 * If the file is corrupted, we're pointing at NULL. is_relative()
	 * will return FALSE for NULL which will yield the correct return
	 * value.
	 */
	return (is_relative(entry));
}

/*
 * If the path doesn't begin with a variable, the first character in the
 * path is tested for '/' to determine if it is absolute or not. If the
 * path begins with a '$', that variable is resolved if possible. If it
 * isn't defined yet, we exit with error code 1.
 */
static int
is_relative(char *entry)
{
	register char *eopath = entry;	/* end of full pathname pointer */
	register char **lasts = &entry;

	/* If there is a path, test it */
	if (entry && *entry) {
		if (*entry == '$') {	/* it's an environment parameter */
			entry++;	/* skip the '$' */

			while (*eopath && !isspace(*eopath))
				eopath++;

			*eopath = '\0';	/* terminate the pathname */

			/* isolate the variable */
			entry = strtok_r(entry, "/", lasts);

			/*
			 * Some packages call out $BASEDIR for relative
			 * paths in the pkgmap even though that is
			 * redundant. This special case is actually
			 * an indication that this is a relative
			 * path.
			 */
			if (strcmp(entry, "BASEDIR") == 0)
				return (1);
			/*
			 * Since entry is pointing to a now-expendable PATH_MAX
			 * size buffer, we can expand the path variable into it
			 * here.
			 */
			entry = getenv(entry);
		}

		/*
		 * Return type of path. If pathname was unresolvable
		 * variable, assume relative. This looks like a strange
		 * assumption since the resolved path may end up
		 * absolute and pkgadd may prompt the user for a basedir
		 * incorrectly because of this assumption. Unfortunately,
		 * the request script MUST have a final BASEDIR in the
		 * environment before it executes.
		 */
		if (entry && *entry)
			return (RELATIVE(entry));
		else
			return (1);
	} else		/* no path, so we skip it */
		return (0);
}
