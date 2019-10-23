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
/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sun_sas.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <libdevinfo.h>

/*
 * structure for di_devlink_walk
 */
typedef struct walk_devlink {
	char *path;
	size_t len;
	char **linkpp;
} walk_devlink_t;

/*
 * callback funtion for di_devlink_walk
 * Find matching /dev link for the given path argument.
 * devlink element and callback function argument.
 * The input path is expected to not have "/devices".
 */
static int
get_devlink(di_devlink_t devlink, void *arg)
{
	const char ROUTINE[] = "get_devlink";
	walk_devlink_t *warg = (walk_devlink_t *)arg;

	/*
	 * When path is specified, it doesn't have minor
	 * name. Therefore, the ../.. prefixes needs to be stripped.
	 */
	if (warg->path) {
		char *content = (char *)di_devlink_content(devlink);
		char *start = strstr(content, "/devices");

		if (start == NULL ||
		    strncmp(start, warg->path, warg->len) != 0 ||
		    /* make it sure the device path has minor name */
		    start[warg->len] != ':') {
			return (DI_WALK_CONTINUE);
		}
	}

	*(warg->linkpp) = strdup(di_devlink_path(devlink));
	log(LOG_DEBUG, ROUTINE, "Walk terminate");
	return (DI_WALK_TERMINATE);
}

/*
 * Convert /devices paths to /dev sym-link paths.
 * The mapping buffer OSDeviceName paths will be
 * converted to short names.
 * mappings The target mappings data to convert to short names
 *
 * If no link is found, the long path is left as is.
 * Note: The NumberOfEntries field MUST not be greater than the size
 * of the array passed in.
 */
void
convertDevpathToDevlink(PSMHBA_TARGETMAPPING mappings)
{
	const char ROUTINE[] = "convertDevpathToLink";
	di_devlink_handle_t hdl;
	walk_devlink_t	    warg;
	int		    j;
	char		    *minor_path, *devlinkp;

	if ((hdl = di_devlink_init(NULL, 0)) == NULL) {
		log(LOG_DEBUG, ROUTINE, "di_devlink failed: errno:%d",
		    strerror(errno));
		return;
	}

	for (j = 0; j < mappings->NumberOfEntries; j++) {
		if (strchr(mappings->entry[j].ScsiId.OSDeviceName, ':')) {
			/* search link for minor node */
			minor_path = mappings->entry[j].ScsiId.OSDeviceName;
			if (strstr(minor_path, "/devices") != NULL) {
				minor_path = mappings->entry[j].ScsiId.
				    OSDeviceName + strlen("/devices");
			}
			warg.path = NULL;
		} else {
			minor_path = NULL;
			if (strstr(mappings->entry[j].ScsiId.OSDeviceName,
			    "/devices") != NULL) {
				warg.len = strlen(mappings->entry[j].ScsiId.
				    OSDeviceName) - strlen("/devices");
				warg.path = mappings->entry[j].
				    ScsiId.OSDeviceName + strlen("/devices");
			} else {
				warg.len = strlen(mappings->entry[j].ScsiId.
				    OSDeviceName);
				warg.path = mappings->entry[j].ScsiId.
				    OSDeviceName;
			}
		}

		devlinkp = NULL;
		warg.linkpp = &devlinkp;
		(void) di_devlink_walk(hdl, NULL, minor_path, DI_PRIMARY_LINK,
		    (void *)&warg, get_devlink);

		if (devlinkp != NULL) {
			(void) snprintf(mappings->entry[j].ScsiId.OSDeviceName,
			    sizeof (mappings->entry[j].ScsiId.OSDeviceName),
			    "%s", devlinkp);
			free(devlinkp);
		}

	}

	(void) di_devlink_fini(&hdl);
}

/*
 * Finds controller path for a give device path.
 *
 * Return value: /dev link for dir and minor name.
 */
static HBA_STATUS
lookupLink(char *path, char *link, const char *dir, const char *mname)
{
	const char ROUTINE[] = "lookupLink";
	DIR    *dp;
	char    buf[MAXPATHLEN];
	char    node[MAXPATHLEN];
	char	*charptr;
	struct dirent *newdirp, *dirp;
	ssize_t	count;
	int	dirplen;
	char	*subpath;
	char	tmpPath[MAXPATHLEN];

	if ((dp = opendir(dir)) == NULL) {
		log(LOG_DEBUG, ROUTINE,
		"Unable to open %s to find controller number.", dir);
		return (HBA_STATUS_ERROR);
	}

	if (link == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "Invalid argument for storing the link.");
		return (HBA_STATUS_ERROR);
	}

	/*
	 * dirplen is large enough to fit the largest path-
	 * struct dirent includes one byte (the terminator)
	 * so we don't add 1 to the calculation here.
	 */
	dirplen = pathconf(dir, _PC_NAME_MAX);
	dirplen = ((dirplen <= 0) ? MAXNAMELEN : dirplen) +
	    sizeof (struct dirent);
	dirp = (struct dirent *)malloc(dirplen);
	if (dirp == NULL) {
		OUT_OF_MEMORY(ROUTINE);
		return (HBA_STATUS_ERROR);
	}

	while ((readdir_r(dp, dirp, &newdirp)) == 0 && newdirp != NULL) {
		if (strcmp(dirp->d_name, ".") == 0 ||
		    strcmp(dirp->d_name, "..") == 0) {
			continue;
		}
		/*
		 * set to another pointer since dirp->d_name length is 1
		 * that will store only the first char 'c' from the name.
		 */
		charptr = dirp->d_name;
		(void) snprintf(node, strlen(charptr) + strlen(dir) + 2,
		    "%s/%s", dir, charptr);
		if ((count = readlink(node, buf, sizeof (buf))) > 0) {
			subpath = NULL;
			subpath = strstr(buf, path);
			buf[count] = '\0';
			if (subpath != NULL) {
				(void) strlcpy(tmpPath, path, MAXPATHLEN);
				(void) strlcat(tmpPath, mname, MAXPATHLEN);
				/*
				 * if device path has substring of path
				 * and exactally matching with :scsi suffix
				 */
				if (strcmp(subpath, tmpPath) == 0) {
					(void) strlcpy(link, node, MAXPATHLEN);
					(void) closedir(dp);
					S_FREE(dirp);
					return (HBA_STATUS_OK);
				}
			}
		}
	}

	(void) closedir(dp);
	S_FREE(dirp);
	return (HBA_STATUS_ERROR);
}

/*
 * Finds controller path for a give device path.
 *
 * Return vale:i smp devlink.
 */
HBA_STATUS
lookupControllerLink(char *path, char *link)
{
	const char dir[] = "/dev/cfg";
	const char mname[] = ":scsi";
	return (lookupLink(path, link, dir, mname));
}

/*
 * Finds smp devlink  for a give smp path.
 *
 * Return vale: smp devlink.
 */
HBA_STATUS
lookupSMPLink(char *path, char *link)
{
	const char dir[] = "/dev/smp";
	const char mname[] = ":smp";
	return (lookupLink(path, link, dir, mname));
}
