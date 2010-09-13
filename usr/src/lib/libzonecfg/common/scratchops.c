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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains functions used for reading and writing the scratch zone
 * translation files.  These files are used by Live Upgrade to keep track of
 * mappings between actual kernel zone names and the zones in an alternate boot
 * environment.
 *
 * The functions are MT-safe.
 *
 * The file format looks like this:
 *
 *	<zonename>	<kernel-zonename>	<alt-root>
 *
 * The expected usage model is:
 *
 *	fp = zonecfg_open_scratch("", B_TRUE);
 *	zonecfg_lock_scratch(fp);
 *	if (zonecfg_find_scratch(fp, zonename, altroot, NULL, 0) == 0) {
 *		handle error; zone already mounted
 *	}
 *	mount zone here
 *	zonecfg_add_scratch(fp, zonename, kernname, altroot);
 *	zonecfg_close_scratch(fp);
 *	fp = zonecfg_open_scratch(zoneroot, B_TRUE);
 *	ftruncate(fileno(fp), 0);
 *	zonecfg_add_scratch(fp, zonename, kernname, "/");
 *	zonecfg_close_scratch(fp);
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <libzonecfg.h>

#define	PATH_MAPFILE	"tmp/.alt.lu-zone-map"

static int
lock_op(int fd, int type)
{
	struct flock lock;

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	return (fcntl(fd, F_SETLKW, &lock));
}

FILE *
zonecfg_open_scratch(const char *rootpath, boolean_t createfile)
{
	mode_t oldmask = umask(0);
	struct stat lbuf, fbuf;
	int fd, flags;
	FILE *fp;
	char mapfile[MAXPATHLEN];

	(void) snprintf(mapfile, sizeof (mapfile), "%s/" PATH_MAPFILE,
	    rootpath);

	flags = O_RDWR | O_NOFOLLOW | O_NOLINKS;
	if (createfile)
		flags |= O_EXCL | O_CREAT;
	if ((fd = open(mapfile, flags, 0644)) == -1) {
		if (!createfile) {
			errno = ENOENT;
			goto failure;
		}
		if (lstat(mapfile, &lbuf) == -1)
			goto failure;
		if (!S_ISREG(lbuf.st_mode) || lbuf.st_nlink != 1 ||
		    lbuf.st_uid != 0) {
			errno = EINVAL;
			goto failure;
		}
		fd = open(mapfile, O_RDWR);
		if (fd == -1)
			goto failure;
		if (fstat(fd, &fbuf) == -1)
			goto failure;
		if (lbuf.st_ino != fbuf.st_ino || lbuf.st_dev != fbuf.st_dev) {
			errno = EINVAL;
			goto failure;
		}
	}
	if (lock_op(fd, F_RDLCK) == -1)
		goto failure;
	(void) umask(oldmask);
	if ((fp = fdopen(fd, "r+")) == NULL)
		(void) close(fd);
	return (fp);

failure:
	if (fd != -1)
		(void) close(fd);
	(void) umask(oldmask);
	return (NULL);
}

int
zonecfg_lock_scratch(FILE *fp)
{
	if (fflush(fp) != 0)
		return (-1);
	return (lock_op(fileno(fp), F_WRLCK));
}

void
zonecfg_close_scratch(FILE *fp)
{
	(void) fclose(fp);
}

int
zonecfg_get_scratch(FILE *fp, char *zonename, size_t namelen, char *kernname,
    size_t kernlen, char *altroot, size_t altlen)
{
	char line[2 * ZONENAME_MAX + MAXPATHLEN + 2];
	char *cp, *cp2;

	/* We always hold at least a read lock on the file */
	for (;;) {
		if (fgets(line, sizeof (line), fp) == NULL)
			return (-1);
		if ((cp = strchr(line, '\n')) == NULL)
			return (-1);
		*cp = '\0';
		if ((cp = strchr(line, ' ')) == NULL)
			cp = line + strlen(line);
		else
			*cp++ = '\0';
		if (zonename != NULL &&
		    strlcpy(zonename, line, namelen) >= namelen)
			continue;
		if ((cp2 = strchr(cp, ' ')) == NULL)
			cp2 = cp + strlen(cp);
		else
			*cp2++ = '\0';
		if (kernname != NULL &&
		    strlcpy(kernname, cp, kernlen) >= kernlen)
			continue;
		if (altroot != NULL && strlcpy(altroot, cp2, altlen) >= altlen)
			continue;
		break;
	}
	return (0);
}

int
zonecfg_find_scratch(FILE *fp, const char *zonename, const char *altroot,
    char *kernzone, size_t kernlen)
{
	char zone[ZONENAME_MAX];
	char aroot[MAXPATHLEN];

	rewind(fp);
	while (zonecfg_get_scratch(fp, zone, sizeof (zone), kernzone, kernlen,
	    aroot, sizeof (aroot)) == 0) {
		if (strcmp(zone, zonename) == 0 && strcmp(altroot, aroot) == 0)
			return (0);
	}
	return (-1);
}

int
zonecfg_reverse_scratch(FILE *fp, const char *kernzone, char *zonename,
    size_t namelen, char *altroot, size_t altlen)
{
	char kzone[ZONENAME_MAX];

	rewind(fp);
	while (zonecfg_get_scratch(fp, zonename, namelen, kzone,
	    sizeof (kzone), altroot, altlen) == 0) {
		if (strcmp(kzone, kernzone) == 0)
			return (0);
	}
	return (-1);
}

int
zonecfg_add_scratch(FILE *fp, const char *zonename, const char *kernzone,
    const char *altroot)
{
	if (fseek(fp, 0, SEEK_END) == -1)
		return (-1);
	if (fprintf(fp, "%s %s %s\n", zonename, kernzone, altroot) == EOF)
		return (-1);
	if (fflush(fp) != 0)
		return (-1);
	return (0);
}

int
zonecfg_delete_scratch(FILE *fp, const char *kernzone)
{
	char zone[ZONENAME_MAX];
	char kzone[ZONENAME_MAX];
	char aroot[MAXPATHLEN];
	long roffs, woffs;

	/*
	 * The implementation here is intentionally quite simple.  We could
	 * allocate a buffer that's big enough to hold the data up to
	 * stat.st_size and then write back out the part we need to, but there
	 * seems to be little point.
	 */
	rewind(fp);
	roffs = 0;
	do {
		woffs = roffs;
		if (zonecfg_get_scratch(fp, NULL, 0, kzone, sizeof (kzone),
		    NULL, 0) != 0)
			return (-1);
		roffs = ftell(fp);
	} while (strcmp(kzone, kernzone) != 0);
	while (zonecfg_get_scratch(fp, zone, sizeof (zone), kzone,
	    sizeof (kzone), aroot, sizeof aroot) == 0) {
		roffs = ftell(fp);
		if (fseek(fp, woffs, SEEK_SET) == -1)
			break;
		if (fprintf(fp, "%s %s %s\n", zone, kzone, aroot) == EOF)
			break;
		woffs = ftell(fp);
		if (fseek(fp, roffs, SEEK_SET) == -1)
			break;
	}
	(void) ftruncate(fileno(fp), woffs);
	return (0);
}

boolean_t
zonecfg_is_scratch(const char *kernzone)
{
	return (strncmp(kernzone, "SUNWlu", 6) == 0);
}
