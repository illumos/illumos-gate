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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/corectl.h>
#include "mms_cores.h"
#include <mms_strapp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <syslog.h>

int
mms_set_core(char *dir, char *proc)
{
	int		 val;
	char		*pattern;
	char		 cpath[PATH_MAX];
	int		 len;

	if (proc == NULL) { /* filename and pid */
		pattern = mms_strapp(NULL, "core.%s.%s", "%f", "%p");
	} else { /* filename, process name and pid */
		pattern = mms_strapp(NULL, "core.%s.%s.%s", "%f", proc, "%p");
	}

	if (dir == NULL) {
		(void) strcpy(cpath, MMS_CORES_DIR);
	} else {
		(void) strcpy(cpath, dir);
	}

	len = strlen(cpath);
	(void) snprintf(&cpath[len], PATH_MAX - len, "/%s", pattern);

	/*
	 * Allow per process core file with executable file name and pid
	 * file name extension.
	 */
	if ((val = core_get_options()) == -1) {
		free(pattern);
		return (-1);
	}
	if (core_set_options(val | CC_PROCESS_PATH | CC_PROCESS_SETID) == -1) {
		free(pattern);
		return (-1);
	}
	if (core_set_process_path(cpath, strlen(cpath) + 1, getpid())) {
		free(pattern);
		return (-1);
	}
	free(pattern);
	return (0);
}

int
corecmp(const void *c1, const void *c2)
{
	corestat_t *t1 = (corestat_t *)c1;
	corestat_t *t2 = (corestat_t *)c2;
	return ((int)t1->time - (int)t2->time);
}

/*
 * Function name mms_man_cores
 *
 *
 * Parameters:
 *	- dir : pointer to cores directory
 *	- proc : the core file name
 *
 * Description: Rotates the core file if necessary.
 *
 *
 * Return code: 0 on success
 *	       -1 on failure
 *
 */
int
mms_man_cores(char *dir, char *proc)
{
	DIR		*dp;
	struct dirent	*dirp;
	struct stat	stp;
	int		corecount = 0;
	int		coreamt = MMS_CORE_AMT;
	int		coretot = 20;
	size_t		bufsize = sizeof (corestat_t) * coretot;
	corestat_t	*buf2 = (corestat_t *)malloc(bufsize);
	corestat_t	*tmpbuf;
	int		i;

	if ((dp = opendir(dir)) == NULL) {
		syslog(LOG_ERR, "mms_man_cores: opendir failed");
		return (-1);
	} else {
		while ((dirp = readdir(dp)) != NULL) {
			if (strcmp(dirp->d_name, ".") == 0 ||
			    strcmp(dirp->d_name, "..") == 0)
				continue;
			else {
				if (corecount > coretot) {
					bufsize = bufsize * 2;
					coretot = coretot *2;
					tmpbuf = (corestat_t *)
					    realloc(buf2, bufsize);
					if (tmpbuf != NULL)
						buf2 = tmpbuf;
					else {
						syslog(LOG_ERR,
						    "mms_man_cores: reallocr");
					}
				}
				if (strncmp(dirp->d_name, proc,
				    strlen(proc)) == 0) {
					buf2[corecount].name = mms_strapp(NULL,
					    "%s/%s", dir, dirp->d_name);
					if (stat(buf2[corecount].name,
					    &stp) != 0) {
						syslog(LOG_ERR,
						    "mms_man_cores: opendir");
					} else {
						buf2[corecount].time =
						    stp.st_mtime;
						corecount++;
					}
				}
			}
		}
		/* Remove old core files if needed */
		if (corecount > coreamt) {
			qsort(buf2, corecount, sizeof (corestat_t), corecmp);
			/* Remove the oldest core files */
			for (i = 0; i < (corecount - coreamt); i++) {
				(void) remove(buf2[i].name);
			}
		}
	}

	/* Free up all the core names */
	for (i = 0; i < corecount; i++)
		free(buf2[i].name);
	free(buf2);
	return (0);
}
