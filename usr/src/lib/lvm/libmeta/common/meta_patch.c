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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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
 * patch /etc/vfstab file
 */
#include <meta.h>
#include <string.h>

/*
 * patch filesystem lines into vfstab file, return tempfilename
 */
int
meta_patch_vfstab(
	char		*cmpname,	/* filesystem mount point or */
					/* "swap" if updating swap partition */
	mdname_t	*fsnp,		/* filesystem device name */
	char		*vname,		/* vfstab file name */
	char		*old_bdevname,	/* old name of block device, needed */
					/* for deciding which of multiple   */
					/* swap file entries to change	    */
					/* if NULL then not changing swap   */
	int		doit,		/* really patch file */
	int		verbose,	/* show what we're doing */
	char		**tname,	/* returned temp file name */
	md_error_t	*ep		/* returned error */
)
{
	char		*chrname = fsnp->rname;
	char		*blkname = fsnp->bname;
	FILE		*fp = NULL;
	FILE		*tfp = NULL;
	struct stat	sbuf;
	char		buf[512];
	char		cdev[512];
	char		bdev[512];
	char		mntpt[512];
	char		fstype[512];
	char		fsckpass[512];
	char		mntboot[512];
	char		mntopt[512];
	int		gotfs = 0;
	char		*cmpstr = &mntpt[0]; /* compare against mntpnt if fs, */
						/* or fstype if swap */
	char		*char_device = chrname;

	/* check names */
	assert(vname != NULL);
	assert(tname != NULL);

	/* get temp names */
	*tname = NULL;
	*tname = Malloc(strlen(vname) + strlen(".tmp") + 1);
	(void) strcpy(*tname, vname);
	(void) strcat(*tname, ".tmp");

	/* check if going to update swap entry in file */
	/* if so then compare against file system type */
	if ((old_bdevname != NULL) && (strcmp("swap", cmpname) == 0)) {
	    cmpstr = &fstype[0];
	    char_device = &cdev[0];
	}

	/* copy vfstab file, replace filesystem line */
	if ((fp = fopen(vname, "r")) == NULL) {
		(void) mdsyserror(ep, errno, vname);
		goto out;
	}
	if (fstat(fileno(fp), &sbuf) != 0) {
		(void) mdsyserror(ep, errno, vname);
		goto out;
	}
	if (doit) {
		if ((tfp = fopen(*tname, "w")) == NULL) {
			(void) mdsyserror(ep, errno, *tname);
			goto out;
		}
		if (fchmod(fileno(tfp), (sbuf.st_mode & 0777)) != 0) {
			(void) mdsyserror(ep, errno, *tname);
			goto out;
		}
		if (fchown(fileno(tfp), sbuf.st_uid, sbuf.st_gid) != 0) {
			(void) mdsyserror(ep, errno, *tname);
			goto out;
		}
	}
	while (fgets(buf, sizeof (buf), fp) != NULL) {

	    /* check that have all required params from vfstab file  */
	    /* or that the line isnt a comment	*/
	    /* or that the fstype/mntpoint match what was passed in  */
	    /* or that the block device matches if changing swap */
	    /* the last check is needed since there may be multiple  */
	    /* entries of swap in the file, and so the fstype is not */
	    /* a sufficient check */
		if ((sscanf(buf, "%512s %512s %512s %512s %512s %512s %512s",
		    bdev, cdev, mntpt, fstype, fsckpass,
		    mntboot, mntopt) != 7) ||
		    (bdev[0] == '#') || (strcmp(cmpstr, cmpname) != 0) ||
		    ((old_bdevname != NULL) &&
		    (strstr(bdev, old_bdevname) == NULL))) {
			if (doit) {
			    if (fputs(buf, tfp) == EOF) {
				(void) mdsyserror(ep, errno, *tname);
				goto out;
			    }
			}
			continue;
		}

		if (verbose) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "Delete the following line from %s:\n\n"),
			    vname);
			(void) printf("%s\n", buf);
			(void) printf(
			    dgettext(TEXT_DOMAIN,
			    "Add the following line to %s:\n\n"),
			    vname);
			(void) printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n\n",
				blkname, char_device, mntpt, fstype, fsckpass,
				mntboot, mntopt);
		}
		if (doit) {
		    if (fprintf(tfp, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			blkname, char_device, mntpt, fstype, fsckpass,
			mntboot, mntopt) == EOF) {
			(void) mdsyserror(ep, errno, *tname);
			goto out;
		    }
		}


		gotfs = 1;
	}
	if (! feof(fp)) {
		(void) mdsyserror(ep, errno, vname);
		goto out;
	}
	if (! gotfs) {
		(void) mderror(ep, MDE_VFSTAB_FILE, vname);
		goto out;
	}
	if (fclose(fp) != 0) {
		(void) mdsyserror(ep, errno, vname);
		goto out;
	}
	fp = NULL;
	if (doit) {
		if ((fflush(tfp) != 0) ||
		    (fsync(fileno(tfp)) != 0) ||
		    (fclose(tfp) != 0)) {
			(void) mdsyserror(ep, errno, *tname);
			goto out;
		}
		tfp = NULL;
	}

	/* return success */
	return (0);

	/* cleanup, return error */
out:
	if (fp != NULL)
		(void) fclose(fp);
	if (tfp != NULL)
		(void) fclose(tfp);
	if (*tname != NULL) {
		(void) unlink(*tname);
		Free(*tname);
	}
	return (-1);
}


/*
 * set filesystem device name in vfstab
 */
int
meta_patch_fsdev(
	char		*fsname,	/* filesystem mount point */
	mdname_t	*fsnp,		/* filesystem device */
	char		*vname,		/* vfstab file name */
	md_error_t	*ep		/* returned error */
)
{
	int		doit = 1;
	int		verbose = 0;
	char		*tvname = NULL;
	int		rval = -1;

	/* check names */
	assert(fsname != NULL);
	if (vname == NULL)
		vname = "/etc/vfstab";

	/* replace lines in vfstab */
	if (meta_patch_vfstab(fsname, fsnp, vname, NULL, doit, verbose, &tvname,
	    ep) != 0) {
		goto out;
	}

	/* rename temp file on top of real one */
	if (rename(tvname, vname) != 0) {
		(void) mdsyserror(ep, errno, vname);
		goto out;
	}
	Free(tvname);
	tvname = NULL;
	rval = 0;

	/* cleanup, return error */
out:
	if (tvname != NULL) {
		if (doit)
			(void) unlink(tvname);
		Free(tvname);
	}
	return (rval);
}


/*
 * set filesystem device name in vfstab
 */
int
meta_patch_swapdev(
	mdname_t	*fsnp,		 /* filesystem device */
	char		*vname,		 /* vfstab file name */
	char		*old_bdevname,	 /* block device name to change */
	md_error_t	*ep		 /* returned error */
)
{
	int		doit = 1;
	int		verbose = 0;
	char		*tvname = NULL;
	int		rval = -1;

	/* check names */
	if (vname == NULL)
		vname = "/etc/vfstab";

	/* replace lines in vfstab */
	if (meta_patch_vfstab("swap", fsnp, vname, old_bdevname, doit,
	    verbose, &tvname, ep) != 0) {
		goto out;
	}

	/* rename temp file on top of real one */
	if (rename(tvname, vname) != 0) {
		(void) mdsyserror(ep, errno, vname);
		goto out;
	}
	Free(tvname);
	tvname = NULL;
	rval = 0;

	/* cleanup, return error */
out:
	if (tvname != NULL) {
		if (doit)
			(void) unlink(tvname);
		Free(tvname);
	}
	return (rval);
}
