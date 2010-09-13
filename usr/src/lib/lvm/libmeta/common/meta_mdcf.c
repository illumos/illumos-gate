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
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * patch md.cf file
 */

#include <meta.h>

/*
 * save metadevice configuration in md.cf
 */
int
meta_update_md_cf(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	char		*name = METACONF;
	char		*tname = METACONFTMP;
	FILE		*tfp = NULL;
	FILE		*mfp = NULL;
	mdprtopts_t	options = PRINT_SHORT | PRINT_FAST;
	struct stat	sbuf;
	char		line[1000];

	/* If this is not the local set, no need to do anything */
	if (!metaislocalset(sp))
		return (0);

	/* open temp file */
	if ((tfp = fopen(tname, "w")) == NULL)
		return (mdsyserror(ep, errno, tname));
	if (stat(name, &sbuf) == 0) {
		(void) fchmod(fileno(tfp), (sbuf.st_mode & 0777));
		(void) fchown(fileno(tfp), sbuf.st_uid, sbuf.st_gid);
	}

	/* dump header */
	if (fputs(dgettext(TEXT_DOMAIN,
	    "# metadevice configuration file\n"
	    "# do not hand edit\n"), tfp) == EOF) {
		(void) mdsyserror(ep, errno, tname);
		goto errout;
	}

	/* dump device configuration */
	if (meta_print_all(sp, tname, NULL, tfp, options, NULL, ep) != 0)
		goto errout;

	/* close and rename file */
	if (fclose(tfp) != 0) {
		(void) mdsyserror(ep, errno, tname);
		goto errout;
	}
	tfp = NULL;

	/*
	 * Renames don't work in the miniroot since tmpfiles are
	 * created in /var/tmp. Hence we copy the data out.
	 */

	if (rename(tname, name) != 0) {
		if (errno == EROFS) {
			if ((tfp = fopen(tname, "r")) == NULL) {
				goto errout;
			}
			if ((mfp = fopen(METACONF, "w+")) == NULL) {
				goto errout;
			}
			while (fgets(line, 1000, tfp) != NULL) {
				if (fputs(line, mfp) == NULL) {
					(void) mdsyserror(ep, errno, METACONF);
					goto errout;
				}
			}
			if (fclose(tfp) != 0) {
				tfp = NULL;
				goto errout;
			}
			tfp = NULL;
			/* delete the tempfile */
			(void) unlink(tname);
			if (fflush(mfp) != 0) {
				goto errout;
			}
			if (fsync(fileno(mfp)) != 0) {
				goto errout;
			}
			if (fclose(mfp) != 0) {
				mfp = NULL;
				goto errout;
			}
			mfp = NULL;
		} else {
			(void) mdsyserror(ep, errno, name);
			goto errout;
		}
	}

	/* success */
	return (0);

	/* cleanup, return error */
errout:
	if (tfp != NULL) {
		(void) fclose(tfp);
		(void) unlink(tname);
	}
	if (mfp != NULL) {
		(void) fclose(mfp);
	}
	return (-1);
}
