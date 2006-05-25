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
 * patch /etc/system file for the root device
 */

#include <dlfcn.h>
#include <meta.h>


/*
 * set root device name in md.conf and vfstab, patch in mddb locations
 */
int
meta_patch_rootdev(
	mdname_t	*rootnp,	/* root device */
	char		*sname,		/* system file name */
	char		*vname,		/* vfstab file name */
	char		*cname,		/* mddb.cf file name */
	char		*dbname,	/* md.conf file name */
	int		doit,		/* really patch files */
	int		verbose,	/* show what we're doing */
	md_error_t	*ep		/* returned error */
)
{
	mdsetname_t	*sp;
	int		ismeta = metaismeta(rootnp);
	char		*tsname = NULL;
	FILE		*tsfp = NULL;
	char		*dbtname = NULL;
	FILE		*dbtfp = NULL;
	char		*tvname = NULL;
	int		rval = -1;

	/* check names */
	if (sname == NULL)
		sname = "/etc/system";
	if (vname == NULL)
		vname = "/etc/vfstab";
	if (cname == NULL)
		cname = META_DBCONF;
	if (dbname == NULL)
		dbname = "/kernel/drv/md.conf";

	/* make sure we have a local name */
	if ((sp = metagetset(rootnp, TRUE, ep)) == NULL)
		return (-1);

	if (! metaislocalset(sp)) {
		return (mddeverror(ep, MDE_NOT_LOCAL, rootnp->dev,
		    rootnp->cname));
	}

	/* replace forceload and rootdev lines in system */
	if (meta_systemfile_copy(sname, 1, 0, doit, verbose, &tsname, &tsfp,
	    ep) != 0) {
		goto out;
	}
	if (meta_systemfile_append_mdroot(rootnp, sname,
	    tsname, tsfp, ismeta, doit, verbose, ep) != 0) {
		goto out;
	}

	/* replace bootlist lines in /kernel/drv/md.conf */
	if (meta_systemfile_copy(dbname, 0, 1, doit, verbose, &dbtname,
	    &dbtfp, ep) != 0) {
		goto out;
	}
	if (meta_systemfile_append_mddb(cname, dbname, dbtname, dbtfp, doit,
	    verbose, 1, ep) != 0) {
		goto out;
	}

	/* force the file contents out to disk */
	if (doit) {
		if ((fflush(tsfp) != 0) ||
		    (fsync(fileno(tsfp)) != 0) ||
		    (fclose(tsfp) != 0)) {
			(void) mdsyserror(ep, errno, tsname);
			goto out;
		}
		tsfp = NULL;
		if ((fflush(dbtfp) != 0) ||
		    (fsync(fileno(dbtfp)) != 0) ||
		    (fclose(dbtfp) != 0)) {
			(void) mdsyserror(ep, errno, dbtname);
			goto out;
		}
		dbtfp = NULL;
	}

	/* replace lines in vfstab */
	if (meta_patch_vfstab("/", rootnp, vname, NULL, doit, verbose, &tvname,
	    ep) != 0) {
		goto out;
	}

	/* rename files, better hope both work */
	if (doit) {
		if (rename(tsname, sname) != 0) {
			(void) mdsyserror(ep, errno, sname);
			goto out;
		}
		Free(tsname);
		tsname = NULL;
		if (rename(dbtname, dbname) != 0) {
			(void) mdsyserror(ep, errno, dbname);
			goto out;
		}
		Free(dbtname);
		dbtname = NULL;
		if (rename(tvname, vname) != 0) {
			(void) mdsyserror(ep, errno, vname);
			goto out;
		}
		Free(tvname);
		tvname = NULL;
	}
	rval = 0;

	/* cleanup, return error */
out:
	if (tsfp != NULL)
		(void) fclose(tsfp);
	if (tsname != NULL) {
		if (doit)
			(void) unlink(tsname);
		Free(tsname);
	}
	if (tvname != NULL) {
		if (doit)
			(void) unlink(tvname);
		Free(tvname);
	}

	/* free the temporary files for md.conf */
	if (dbtfp != NULL)
		(void) fclose(dbtfp);
	if (dbtname != NULL) {
		if (doit)
			(void) unlink(dbtname);
		Free(dbtname);
	}
	return (rval);
}
