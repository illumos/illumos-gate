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
 * misc.c - miscellaneous and utility functions
 */

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include "startd.h"

void
startd_close(int fd)
{
	if (close(fd) == 0)
		return;

	log_error(LOG_WARNING, "close(%d) failed: %s\n", fd, strerror(errno));
	abort();
}

void
startd_fclose(FILE *fp)
{
	if (fclose(fp) == 0)
		return;

	log_error(LOG_WARNING, "fclose() failed\n");
	abort();
}

/*
 * Canonify fmri.  On success, sets *retp to a string which should be freed
 * with startd_free( , max_scf_fmri_size) and returns 0.  On failure returns
 * EINVAL.
 *
 * If 'isinstance' is non-zero, then return EINVAL if the FMRI specificies
 * anything other than an instance.
 */
int
fmri_canonify(const char *fmri, char **retp, boolean_t isinstance)
{
	char *cf;

	cf = startd_alloc(max_scf_fmri_size);

	if (isinstance) {
		const char *instance, *pg;

		/*
		 * Verify that this fmri specifies an instance, using
		 * scf_parse_svc_fmri().
		 */
		if (strlcpy(cf, fmri, max_scf_fmri_size) >= max_scf_fmri_size ||
		    scf_parse_svc_fmri(cf, NULL, NULL, &instance, &pg,
		    NULL) != 0) {
			startd_free(cf, max_scf_fmri_size);
			return (EINVAL);
		}

		if (instance == NULL || pg != NULL) {
			startd_free(cf, max_scf_fmri_size);
			return (EINVAL);
		}
	}

	if (scf_canonify_fmri(fmri, cf, max_scf_fmri_size) < 0) {
		startd_free(cf, max_scf_fmri_size);
		return (EINVAL);
	}

	*retp = cf;
	return (0);
}

/*
 * int fs_is_read_only(char *, ulong_t *)
 *   Returns 1 if the given path is that of a filesystem with the ST_RDONLY flag
 *   set.  0 if ST_RDONLY is unset.  -1 if the statvfs(2) call failed.  If the
 *   second parameter is non-NULL, the fsid for the requested filesystem is
 *   written to the given address on success.
 */
int
fs_is_read_only(char *path, ulong_t *fsidp)
{
	int err;
	struct statvfs sfb;

	do {
		err = statvfs(path, &sfb);
	} while (err == -1 && errno == EINTR);

	if (err)
		return (-1);

	if (fsidp != NULL)
		*fsidp = sfb.f_fsid;

	if (sfb.f_flag & ST_RDONLY)
		return (1);

	return (0);
}

/*
 * int fs_remount(char *)
 *   Attempt to remount the given filesystem read-write, so that we can unlock
 *   the repository (or handle other similar failures).
 *
 *   Returns 0 on success, -1 on failure.
 */
int
fs_remount(char *path)
{
	if (fork_mount(path, "remount,rw"))
		return (-1);

	return (0);
}

/*
 * void xstr_sanitize(char *s)
 *   In-place transform any non-alphanumeric characters (or '_') to '_'
 *   characters.
 */
void
xstr_sanitize(char *s)
{
	for (; *s != '\0'; s++)
		if (!isalnum(*s) && *s != '_')
			*s = '_';
}
