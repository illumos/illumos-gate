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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <stddef.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <libzonecfg.h>

#include "zoneadm.h"

extern int errno;

/* ARGSUSED */
static int
pkg_entry_compare(const void *l_arg, const void *r_arg, void *private)
{
	zone_pkg_entry_t *l = (zone_pkg_entry_t *)l_arg;
	zone_pkg_entry_t *r = (zone_pkg_entry_t *)r_arg;

	return (strcmp(l->zpe_name, r->zpe_name));
}

static boolean_t
valid_num(char *n)
{
	for (; isdigit(*n); n++)
		;

	if (*n != NULL)
		return (B_FALSE);
	return (B_TRUE);
}

/*
 * Take an input field, which must look like a positive int, and return the
 * numeric value of the field.  Return -1 if the input field does not look
 * like something we can convert.
 */
static int
fld2num(char *fld, char **nfld)
{
	char *ppoint;
	long n;

	if ((ppoint = strchr(fld, '.')) != NULL) {
		*ppoint = '\0';
		*nfld = ppoint + 1;
	} else {
		*nfld = NULL;
	}

	if (!valid_num(fld))
		return (-1);

	errno = 0;
	n = strtol(fld, (char **)NULL, 10);
	if (errno != 0)
		return (-1);

	return ((int)n);
}

/*
 * Step through two version strings that look like postive ints delimited by
 * decimals and compare them.  Example input can look like 2, 010.3, 75.02.09,
 * etc.  If the input does not look like this then we do a simple lexical
 * comparison of the two strings.  The string can be modified on exit of
 * this function.
 */
static int
fld_cmp(char *v1, char *v2)
{
	char *nxtfld1, *nxtfld2;
	int n1, n2;

	for (;;) {
		n1 = fld2num(v1, &nxtfld1);
		n2 = fld2num(v2, &nxtfld2);

		/*
		 * If either field is not a postive int, just compare them
		 * lexically.
		 */
		if (n1 < 0 || n2 < 0)
			return (strcmp(v1, v2));

		if (n1 > n2)
			return (1);

		if (n1 < n2)
			return (-1);

		/* They're equal */

		/* No more fields */
		if (nxtfld1 == NULL && nxtfld2 == NULL)
			return (0);

		/* Field 2 still has data so it is greater than field 1 */
		if (nxtfld1 == NULL)
			return (-1);

		/* Field 1 still has data so it is greater than field 2 */
		if (nxtfld2 == NULL)
			return (1);

		/* Both fields still have data, keep going. */
		v1 = nxtfld1;
		v2 = nxtfld2;
	}
}

/*
 * The result of the comparison is returned in the cmp parameter:
 *	 0 if both versions are equal.
 *	<0 if version1 is less than version 2.
 *	>0 if version1 is greater than version 2.
 * The function returns B_TRUE if there was an ENOMEM error, B_FALSE otherwise.
 *
 * This function handles the various version strings we can get from the
 * dependent pkg versions.  They usually look like:
 *	"1.21,REV=2005.01.17.23.31"
 *	"2.6.0,REV=10.0.3.2004.12.16.18.02"
 *
 * We can't do a simple lexical comparison since:
 *      2.6.0 would be greater than 2.20.0
 *	12 would be greater than 110
 *
 * If the input strings do not look like decimal delimted version strings
 * then we fall back to doing a simple lexical comparison.
 */
static boolean_t
pkg_vers_cmp(char *vers1, char *vers2, int *cmp)
{
	char *v1, *v2;
	char *rev1, *rev2;
	int res;

	/* We need to modify the input strings so we dup them. */
	if ((v1 = strdup(vers1)) == NULL)
		return (B_TRUE);
	if ((v2 = strdup(vers2)) == NULL) {
		free(v1);
		return (B_TRUE);
	}

	/* Strip off a revision delimited by a comma. */
	if ((rev1 = strchr(v1, ',')) != NULL)
		*rev1++ = '\0';
	if ((rev2 = strchr(v2, ',')) != NULL)
		*rev2++ = '\0';

	res = fld_cmp(v1, v2);
	/* If the primary versions are not equal, return the result */
	if (res != 0) {
		*cmp = res;
		goto done;
	}

	/*
	 * All of the fields in the primary version strings are equal, check
	 * the rev, if it exists.
	 */

	/* No revs */
	if (rev1 == NULL && rev2 == NULL) {
		*cmp = 0;
		goto done;
	}

	/* Field 2 has a rev so it is greater than field 1 */
	if (rev1 == NULL) {
		*cmp = -1;
		goto done;
	}

	/* Field 1 has a rev so it is greater than field 2 */
	if (rev2 == NULL) {
		*cmp = 1;
		goto done;
	}

	/* If no recognized REV data then just lexically compare them */
	if (strncmp(rev1, "REV=", 4) != 0 || strncmp(rev2, "REV=", 4) != 0) {
		*cmp = strcmp(rev1, rev2);
		goto done;
	}

	/* Both fields have revs, check them. */
	*cmp = fld_cmp(rev1 + 4, rev2 + 4);

done:
	free(v1);
	free(v2);

	return (B_FALSE);
}

static void
pkg_avl_delete(uu_avl_t *pavl)
{
	zone_pkg_entry_t *p;
	void *cookie = NULL;

	if (pavl == NULL)
		return;

	while ((p = uu_avl_teardown(pavl, &cookie)) != NULL) {
		free(p->zpe_name);
		free(p->zpe_vers);
		pkg_avl_delete(p->zpe_patches_avl);
		free(p);
	}

	uu_avl_destroy(pavl);
}

/*
 * Walk all of the patches on the pkg, looking to see if the specified patch
 * has been obsoleted by one of those patches.
 */
static boolean_t
is_obsolete(zone_pkg_entry_t *pkg, zone_pkg_entry_t *patchid)
{
	uu_avl_walk_t	*patch_walk;
	zone_pkg_entry_t *patch;
	boolean_t res;

	if (pkg->zpe_patches_avl == NULL)
		return (B_FALSE);

	patch_walk = uu_avl_walk_start(pkg->zpe_patches_avl, UU_WALK_ROBUST);
	if (patch_walk == NULL)
		return (B_FALSE);

	res = B_FALSE;
	while ((patch = uu_avl_walk_next(patch_walk)) != NULL) {
		uu_avl_index_t where;

		if (patch->zpe_patches_avl == NULL)
			continue;

		/* Check the obsolete list on the patch. */
		if (uu_avl_find(patch->zpe_patches_avl, patchid, NULL, &where)
		    != NULL) {
			res = B_TRUE;
			break;
		}
	}

	uu_avl_walk_end(patch_walk);
	return (res);
}

/*
 * Build a list of unique patches from the input pkg_patches list.
 * If the pkg parameter is not null then we will check the patches on that
 * pkg to see if any of the pkg_patches have been obsoleted.  We don't
 * add those obsoleted patches to the unique list.
 * Returns B_FALSE if an error occurs.
 */
static boolean_t
add_patch(uu_avl_t *pkg_patches, uu_avl_t *unique, zone_pkg_entry_t *pkg,
    uu_avl_pool_t *pkg_pool)
{
	uu_avl_walk_t	*walk;
	zone_pkg_entry_t *pkg_patch;

	if (pkg_patches == NULL)
		return (B_TRUE);

	walk = uu_avl_walk_start(pkg_patches, UU_WALK_ROBUST);
	if (walk == NULL)
		return (B_FALSE);

	while ((pkg_patch = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_index_t where;
		zone_pkg_entry_t *patch;

		/* Skip adding it if we already have it. */
		if (uu_avl_find(unique, pkg_patch, NULL, &where) != NULL)
			continue;

		/* Likewise, skip adding it if it has been obsoleted. */
		if (pkg != NULL && is_obsolete(pkg, pkg_patch))
			continue;

		/* We need to add it so make a duplicate. */
		if ((patch = (zone_pkg_entry_t *)
		    malloc(sizeof (zone_pkg_entry_t))) == NULL) {
			uu_avl_walk_end(walk);
			return (B_FALSE);
		}

		if ((patch->zpe_name = strdup(pkg_patch->zpe_name)) == NULL) {
			free(patch);
			uu_avl_walk_end(walk);
			return (B_FALSE);
		}
		if ((patch->zpe_vers = strdup(pkg_patch->zpe_vers)) == NULL) {
			free(patch->zpe_name);
			free(patch);
			uu_avl_walk_end(walk);
			return (B_FALSE);
		}
		patch->zpe_patches_avl = NULL;

		/* Insert patch into the unique patch AVL tree. */
		uu_avl_node_init(patch, &patch->zpe_entry, pkg_pool);
		uu_avl_insert(unique, patch, where);
	}
	uu_avl_walk_end(walk);

	return (B_TRUE);
}

/*
 * Common code for sw_cmp which will check flags, update res and print the
 * section header.  Return true if we should be silent.
 */
static boolean_t
prt_header(int *res, uint_t flag, boolean_t *do_header, char *hdr)
{
	*res = Z_ERR;
	if (flag & SW_CMP_SILENT)
		return (B_TRUE);

	if (*do_header) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr, hdr);
		*do_header = B_FALSE;
	}
	return (B_FALSE);
}

/*
 * Compare the software on the local global zone and source system global
 * zone.  Used when we are trying to attach a zone during migration or
 * when checking if a ZFS snapshot is still usable for a ZFS clone.
 * l_handle is for the local system and s_handle is for the source system.
 * These have a snapshot of the appropriate packages and patches in the global
 * zone for the two machines.
 * The functions called here can print any messages that are needed to
 * inform the user about package or patch problems.
 * The flag parameter controls how the messages are printed.  If the
 * SW_CMP_SILENT bit is set in the flag then no messages will be printed
 * but we still compare the sw and return an error if there is a mismatch.
 */
int
sw_cmp(zone_dochandle_t l_handle, zone_dochandle_t s_handle, uint_t flag)
{
	char		*hdr;
	int		res;
	int		err;
	boolean_t	do_header;
	uu_avl_pool_t	*pkg_pool = NULL;
	uu_avl_t	*src_pkgs = NULL;
	uu_avl_t	*dst_pkgs = NULL;
	uu_avl_t	*src_patches = NULL;
	uu_avl_t	*dst_patches = NULL;
	zone_pkg_entry_t *src_pkg;
	zone_pkg_entry_t *dst_pkg;
	zone_pkg_entry_t *src_patch;
	zone_pkg_entry_t *dst_patch;
	uu_avl_walk_t	*walk;

	/* Set res to cover any of these memory allocation errors. */
	res = Z_NOMEM;
	if ((pkg_pool = uu_avl_pool_create("pkgs_pool",
	    sizeof (zone_pkg_entry_t), offsetof(zone_pkg_entry_t, zpe_entry),
	    pkg_entry_compare, UU_DEFAULT)) == NULL)
		goto done;

	if ((src_pkgs = uu_avl_create(pkg_pool, NULL, UU_DEFAULT)) == NULL)
		goto done;

	if ((dst_pkgs = uu_avl_create(pkg_pool, NULL, UU_DEFAULT)) == NULL)
		goto done;

	if ((src_patches = uu_avl_create(pkg_pool, NULL, UU_DEFAULT)) == NULL)
		goto done;

	if ((dst_patches = uu_avl_create(pkg_pool, NULL, UU_DEFAULT)) == NULL)
		goto done;

	res = Z_OK;
	if ((err = zonecfg_getpkgdata(s_handle, pkg_pool, src_pkgs)) != Z_OK) {
		res = errno = err;
		zperror(gettext("could not get package data for detached zone"),
		    B_TRUE);
		goto done;
	}
	if ((err = zonecfg_getpkgdata(l_handle, pkg_pool, dst_pkgs)) != Z_OK) {
		res = errno = err;
		zperror(gettext("could not get package data for global zone"),
		    B_TRUE);
		goto done;
	}

	/*
	 * Check the source host for pkgs (and versions) that are not on the
	 * local host.
	 */
	hdr = gettext("These packages installed on the source system "
	    "are inconsistent with this system:\n");
	do_header = B_TRUE;

	if ((walk = uu_avl_walk_start(src_pkgs, UU_WALK_ROBUST)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}
	while ((src_pkg = uu_avl_walk_next(walk)) != NULL) {
		int cmp;
		uu_avl_index_t where;

		dst_pkg = uu_avl_find(dst_pkgs, src_pkg, NULL, &where);

		/*
		 * Build up a list of unique patches for the src system but
		 * don't track patches that are obsoleted on the dst system
		 * since they don't matter.
		 */
		if (!add_patch(src_pkg->zpe_patches_avl, src_patches, dst_pkg,
		    pkg_pool)) {
			res = Z_NOMEM;
			goto done;
		}

		if (dst_pkg == NULL) {
			/* src pkg is not installed on dst */
			if (prt_header(&res, flag, &do_header, hdr))
				break;

			(void) fprintf(stderr,
			    gettext("\t%s: not installed\n\t\t(%s)\n"),
			    src_pkg->zpe_name, src_pkg->zpe_vers);
			continue;
		}

		/* Check pkg version */
		if (pkg_vers_cmp(src_pkg->zpe_vers, dst_pkg->zpe_vers, &cmp)) {
			res = Z_NOMEM;
			goto done;
		}

		if (cmp != 0) {
			if (prt_header(&res, flag, &do_header, hdr))
				break;

			(void) fprintf(stderr, gettext(
			    "\t%s: version mismatch\n\t\t(%s)\n\t\t(%s)\n"),
			    src_pkg->zpe_name, src_pkg->zpe_vers,
			    dst_pkg->zpe_vers);
		}
	}
	uu_avl_walk_end(walk);

	/*
	 * Now check the local host for pkgs that were not on the source host.
	 * We already handled version mismatches in the loop above.
	 */
	hdr = gettext("These packages installed on this system were "
	    "not installed on the source system:\n");
	do_header = B_TRUE;

	if ((walk = uu_avl_walk_start(dst_pkgs, UU_WALK_ROBUST)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}
	while ((dst_pkg = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_index_t where;

		/*
		 * Build up a list of unique patches for the dst system.  We
		 * don't worry about tracking obsolete patches that were on the
		 * src since we only want to report the results of moving to
		 * the dst system.
		 */
		if (!add_patch(dst_pkg->zpe_patches_avl, dst_patches, NULL,
		    pkg_pool)) {
			res = Z_NOMEM;
			goto done;
		}

		src_pkg = uu_avl_find(src_pkgs, dst_pkg, NULL, &where);
		if (src_pkg == NULL) {
			/* dst pkg is not installed on src */
			if (prt_header(&res, flag, &do_header, hdr))
				break;

			(void) fprintf(stderr, gettext("\t%s (%s)\n"),
			    dst_pkg->zpe_name, dst_pkg->zpe_vers);
		}
	}
	uu_avl_walk_end(walk);

	/*
	 * Check the source host for patches that are not on the local host.
	 */
	hdr = gettext("These patches installed on the source system "
	    "are inconsistent with this system:\n");
	do_header = B_TRUE;

	if ((walk = uu_avl_walk_start(src_patches, UU_WALK_ROBUST)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}
	while ((src_patch = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_index_t where;

		dst_patch = uu_avl_find(dst_patches, src_patch, NULL, &where);
		if (dst_patch == NULL) {
			/* src patch is not installed on dst */
			if (prt_header(&res, flag, &do_header, hdr))
				break;

			(void) fprintf(stderr,
			    gettext("\t%s-%s: not installed\n"),
			    src_patch->zpe_name, src_patch->zpe_vers);
			continue;
		}

		/*
		 * Check patch version.  We assume the patch versions are
		 * properly structured with a leading 0 if necessary (e.g. 01).
		 */
		assert(strlen(src_patch->zpe_vers) ==
		    strlen(dst_patch->zpe_vers));
		if (strcmp(src_patch->zpe_vers, dst_patch->zpe_vers) != 0) {
			if (prt_header(&res, flag, &do_header, hdr))
				break;

			(void) fprintf(stderr,
			    gettext("\t%s: version mismatch\n\t\t(%s) (%s)\n"),
			    src_patch->zpe_name, src_patch->zpe_vers,
			    dst_patch->zpe_vers);
		}
	}
	uu_avl_walk_end(walk);

	/*
	 * Check the local host for patches that were not on the source host.
	 * We already handled version mismatches in the loop above.
	 */
	hdr = gettext("These patches installed on this system were "
	    "not installed on the source system:\n");
	do_header = B_TRUE;

	if ((walk = uu_avl_walk_start(dst_patches, UU_WALK_ROBUST)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}
	while ((dst_patch = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_index_t where;

		src_patch = uu_avl_find(src_patches, dst_patch, NULL, &where);
		if (src_patch == NULL) {
			/* dst patch is not installed on src */
			if (prt_header(&res, flag, &do_header, hdr))
				break;

			(void) fprintf(stderr, gettext("\t%s-%s\n"),
			    dst_patch->zpe_name, dst_patch->zpe_vers);
		}
	}
	uu_avl_walk_end(walk);

done:
	if (res == Z_NOMEM)
		zerror(gettext("Out of memory"));

	/* free avl structs */
	pkg_avl_delete(src_pkgs);
	pkg_avl_delete(dst_pkgs);
	pkg_avl_delete(src_patches);
	pkg_avl_delete(dst_patches);
	if (pkg_pool != NULL)
		uu_avl_pool_destroy(pkg_pool);

	return (res);
}

/*
 * Compare the software on the local global zone and source system global
 * zone.  Used to determine if/how we have to update the zone during attach.
 * We generate the data files needed by the update process in this case.
 * l_handle is for the local system and s_handle is for the source system.
 * These have a snapshot of the appropriate packages and patches in the global
 * zone for the two machines.
 *
 * The algorithm we use to compare the pkgs is as follows:
 * 1) pkg on src but not on dst
 *	remove src pkg (allowed in order to handle obsolete pkgs - note that
 *	this only applies to dependent pkgs, not generic pkgs installed into
 *	the zone by the zone admin)
 * 2) pkg on dst but not on src
 *	add pkg
 * 3) pkg on src with higher rev than on dst
 *	fail (downgrade)
 * 4) pkg on dst with higher rev than on src
 *	remove src pkg & add new
 * 5) pkg version is the same
 *	a) patch on src but not on dst
 *		fail (downgrade, unless obsoleted)
 *	b) patch on dst but not on src
 *		remove src pkg & add new
 *	c) patch on src with higher rev than on dst
 *		fail (downgrade, unless obsoleted)
 *	d) patch on dst with higher rev than on src
 *		remove src pkg & add new
 *
 * We run this algorithm in 2 passes, first looking at the pkgs from the src
 * system and then looking at the pkgs from the dst system.
 *
 * As with the sw_cmp function, we return Z_OK if there is no work to be
 * done (the attach can just happen) or Z_ERR if we have to update the pkgs
 * within the zone.  We can also return Z_FATAL if we had a real error during
 * this process.
 */
int
sw_up_to_date(zone_dochandle_t l_handle, zone_dochandle_t s_handle,
    char *zonepath)
{
	int		res = Z_OK;
	int		err;
	int		cmp;
	FILE		*fp_add = NULL, *fp_rm = NULL;
	uu_avl_pool_t	*pkg_pool = NULL;
	uu_avl_t	*src_pkgs = NULL;
	uu_avl_t	*dst_pkgs = NULL;
	uu_avl_walk_t	*walk;
	zone_pkg_entry_t *src_pkg;
	zone_pkg_entry_t *dst_pkg;
	char		fname[MAXPATHLEN];

	(void) snprintf(fname, sizeof (fname), "%s/pkg_add", zonepath);
	if ((fp_add = fopen(fname, "w")) == NULL) {
		zperror(gettext("could not save list of packages to add"),
		    B_FALSE);
		goto fatal;
	}

	(void) snprintf(fname, sizeof (fname), "%s/pkg_rm", zonepath);
	if ((fp_rm = fopen(fname, "w")) == NULL) {
		zperror(gettext("could not save list of packages to remove"),
		    B_FALSE);
		goto fatal;
	}

	if ((pkg_pool = uu_avl_pool_create("pkgs_pool",
	    sizeof (zone_pkg_entry_t), offsetof(zone_pkg_entry_t, zpe_entry),
	    pkg_entry_compare, UU_DEFAULT)) == NULL)
		goto fatal;

	if ((src_pkgs = uu_avl_create(pkg_pool, NULL, UU_DEFAULT)) == NULL)
		goto fatal;

	if ((dst_pkgs = uu_avl_create(pkg_pool, NULL, UU_DEFAULT)) == NULL)
		goto fatal;

	if ((err = zonecfg_getpkgdata(s_handle, pkg_pool, src_pkgs)) != Z_OK) {
		errno = err;
		zperror(gettext("could not get package data for detached zone"),
		    B_TRUE);
		goto fatal;
	}
	if ((err = zonecfg_getpkgdata(l_handle, pkg_pool, dst_pkgs)) != Z_OK) {
		errno = err;
		zperror(gettext("could not get package data for global zone"),
		    B_TRUE);
		goto fatal;
	}

	/*
	 * First Pass
	 *
	 * Start by checking each pkg from the src system.  We need to handle
	 * the following:
	 *	1) pkg on src but not on dst
	 *		rm old pkg (allowed in order to handle obsolete pkgs)
	 *	3) pkg on src with higher rev than on dst
	 *		fail (downgrade)
	 *	5) pkg ver same
	 *		a) patch on src but not on dst
	 *			fail (downgrade)
	 *		c) patch on src with higher rev than on dst
	 *			fail (downgrade)
	 */
	if ((walk = uu_avl_walk_start(src_pkgs, UU_WALK_ROBUST)) == NULL) {
		zerror(gettext("Out of memory"));
		goto fatal;
	}

	while ((src_pkg = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_index_t where;
		uu_avl_walk_t	*patch_walk;
		zone_pkg_entry_t *src_patch;

		dst_pkg = uu_avl_find(dst_pkgs, src_pkg, NULL, &where);

		if (dst_pkg == NULL) {
			/* src pkg is not installed on dst */
			if (fprintf(fp_rm, "%s\n", src_pkg->zpe_name) < 0) {
				zperror(gettext("could not save list of "
				    "packages to remove"), B_FALSE);
				goto fatal;
			}
			res = Z_ERR;
			continue;
		}

		/* Check pkg version to determine how to proceed. */
		if (pkg_vers_cmp(src_pkg->zpe_vers, dst_pkg->zpe_vers, &cmp)) {
			zerror(gettext("Out of memory"));
			goto fatal;
		}

		if (cmp > 0) {
			/* src pkg has higher vers than dst pkg */
			zerror(gettext("ERROR: attempt to downgrade package "
			    "%s %s to version %s"), src_pkg->zpe_name,
			    src_pkg->zpe_vers, dst_pkg->zpe_vers);
			goto fatal;
		}

		/*
		 * src pkg has lower vers than dst pkg, we'll handle
		 * this in the loop where we process the dst pkgs.
		 */
		if (cmp < 0)
			continue;

		/* src and dst pkgs have the same version. */

		/*
		 * If src pkg has no patches, then we're done with this pkg.
		 * Any patches on the dst pkg are handled in the 2nd pass.
		 */
		if (src_pkg->zpe_patches_avl == NULL)
			continue;

		if (dst_pkg->zpe_patches_avl == NULL) {
			/*
			 * We have the same pkg on the src and dst but the src
			 * pkg has patches and the dst pkg does not, so this
			 * would be a downgrade!  Disallow this.
			 */
			zerror(gettext("ERROR: attempt to downgrade package "
			    "%s, the source had patches but this system does "
			    "not\n"), src_pkg->zpe_name);
			goto fatal;
		}

		patch_walk = uu_avl_walk_start(src_pkg->zpe_patches_avl,
		    UU_WALK_ROBUST);
		if (patch_walk == NULL) {
			zerror(gettext("Out of memory"));
			goto fatal;
		}

		while ((src_patch = uu_avl_walk_next(patch_walk)) != NULL) {
			zone_pkg_entry_t *dst_patch;

			dst_patch = uu_avl_find(dst_pkg->zpe_patches_avl,
			    src_patch, NULL, &where);

			if (dst_patch == NULL) {
				/*
				 * We have the same pkg on the src and dst but
				 * the src pkg has a patch that the dst pkg
				 * does not, so this would be a downgrade!  We
				 * need to disallow this but first double check
				 * that this patch has not been obsoleted by
				 * some other patch that is installed on the
				 * dst.  If the patch is obsolete, the pkg will
				 * be handled in the 2nd pass.
				 */
				if (is_obsolete(dst_pkg, src_patch))
					continue;

				zerror(gettext("ERROR: attempt to downgrade "
				    "package %s, the source had patch %s-%s "
				    "which is not installed on this system\n"),
				    src_pkg->zpe_name, src_patch->zpe_name,
				    src_patch->zpe_vers);

				goto fatal;
			}

			/* Check if the src patch is newer than the dst patch */
			if (strcmp(src_patch->zpe_vers, dst_patch->zpe_vers)
			    > 0) {
				/*
				 * We have a patch on the src with higher rev
				 * than the patch on the dst so this would be a
				 * downgrade!  We need to disallow this but
				 * first double check that this patch has not
				 * been obsoleted by some other patch that is
				 * installed on the dst.  If the patch is
				 * obsolete, the pkg will be handled in the 2nd
				 * pass.
				 */
				if (is_obsolete(dst_pkg, src_patch))
					continue;

				zerror(gettext("ERROR: attempt to downgrade "
				    "package %s, the source had patch %s-%s "
				    "but this system only has %s-%s\n"),
				    src_pkg->zpe_name, src_patch->zpe_name,
				    src_patch->zpe_vers, dst_patch->zpe_name,
				    dst_patch->zpe_vers);
				goto fatal;
			}

			/*
			 * If the src patch is the same rev or older than the
			 * dst patch we'll handle that in the second pass.
			 */
		}

		uu_avl_walk_end(patch_walk);
	}

	uu_avl_walk_end(walk);

	/*
	 * Second Pass
	 *
	 * Now check each pkg from the dst system.  We need to handle
	 * the following:
	 *	2) pkg on dst but not on src
	 *		add pkg
	 *	4) pkg on dst with higher rev than on src
	 *		remove old pkg & add current
	 *	5) pkg ver same
	 *		b) patch on dst but not on src
	 *			remove old pkg & add
	 *		d) patch on dst with higher rev than on src
	 *			remove old pkg & add
	 */
	if ((walk = uu_avl_walk_start(dst_pkgs, UU_WALK_ROBUST)) == NULL) {
		zerror(gettext("Out of memory"));
		goto fatal;
	}

	while ((dst_pkg = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_index_t where;
		uu_avl_walk_t	*patch_walk;
		zone_pkg_entry_t *dst_patch;

		src_pkg = uu_avl_find(src_pkgs, dst_pkg, NULL, &where);

		if (src_pkg == NULL) {
			/* dst pkg was not installed on src */
			if (fprintf(fp_add, "%s\n", dst_pkg->zpe_name) < 0) {
				zperror(gettext("could not save list of "
				    "packages to add"), B_FALSE);
				goto fatal;
			}
			res = Z_ERR;
			continue;
		}

		/* Check pkg version to determine how to proceed. */
		if (pkg_vers_cmp(dst_pkg->zpe_vers, src_pkg->zpe_vers, &cmp)) {
			zerror(gettext("Out of memory"));
			goto fatal;
		}

		if (cmp > 0) {
			/* dst pkg has higher vers than src pkg */
			if (fprintf(fp_rm, "%s\n", dst_pkg->zpe_name) < 0) {
				zperror(gettext("could not save list of "
				    "packages to remove"), B_FALSE);
				goto fatal;
			}
			if (fprintf(fp_add, "%s\n", dst_pkg->zpe_name) < 0) {
				zperror(gettext("could not save list of "
				    "packages to add"), B_FALSE);
				goto fatal;
			}
			res = Z_ERR;
			continue;
		}

		/*
		 * cmp < 0 was handled in the first loop.  This would
		 * be a downgrade so we should have already failed.
		 */
		assert(cmp >= 0);

		/* src and dst pkgs have the same version. */

		/* If dst pkg has no patches, then we're done with this pkg. */
		if (dst_pkg->zpe_patches_avl == NULL)
			continue;

		if (src_pkg->zpe_patches_avl == NULL) {
			/*
			 * We have the same pkg on the src and dst
			 * but the dst pkg has patches and the src
			 * pkg does not.   Just replace the pkg.
			 */
			if (fprintf(fp_rm, "%s\n", dst_pkg->zpe_name) < 0) {
				zperror(gettext("could not save list of "
				    "packages to remove"), B_FALSE);
				goto fatal;
			}
			if (fprintf(fp_add, "%s\n", dst_pkg->zpe_name) < 0) {
				zperror(gettext("could not save list of "
				    "packages to add"), B_FALSE);
				goto fatal;
			}
			res = Z_ERR;
			continue;
		}

		patch_walk = uu_avl_walk_start(dst_pkg->zpe_patches_avl,
		    UU_WALK_ROBUST);
		if (patch_walk == NULL) {
			zerror(gettext("Out of memory"));
			goto fatal;
		}

		while ((dst_patch = uu_avl_walk_next(patch_walk)) != NULL) {
			zone_pkg_entry_t *src_patch;

			src_patch = uu_avl_find(src_pkg->zpe_patches_avl,
			    dst_patch, NULL, &where);

			if (src_patch == NULL) {
				/*
				 * We have the same pkg on the src and dst but
				 * the dst pkg has a patch that the src pkg
				 * does not.  Just replace the pkg.
				 */
				if (fprintf(fp_rm, "%s\n", dst_pkg->zpe_name)
				    < 0) {
					zperror(gettext("could not save list "
					    "of packages to remove"), B_FALSE);
					goto fatal;
				}
				if (fprintf(fp_add, "%s\n", dst_pkg->zpe_name)
				    < 0) {
					zperror(gettext("could not save list "
					    "of packages to add"), B_FALSE);
					goto fatal;
				}
				res = Z_ERR;
				continue;
			}

			/* Check if the dst patch is newer than the src patch */
			if (strcmp(dst_patch->zpe_vers, src_patch->zpe_vers)
			    > 0) {
				/*
				 * We have a patch on the dst with higher rev
				 * than the patch on the src.  Just replace the
				 * pkg.
				 */
				if (fprintf(fp_rm, "%s\n", dst_pkg->zpe_name)
				    < 0) {
					zperror(gettext("could not save list "
					    "of packages to remove"), B_FALSE);
					goto fatal;
				}
				if (fprintf(fp_add, "%s\n", dst_pkg->zpe_name)
				    < 0) {
					zperror(gettext("could not save list "
					    "of packages to add"), B_FALSE);
					goto fatal;
				}
				res = Z_ERR;
				continue;
			}

			/*
			 * If the dst patch is the same rev then we can ignore
			 * this pkg.  If it is older than the src patch we
			 * handled that in the first pass and we should have
			 * already failed.
			 */
			assert(strcmp(dst_patch->zpe_vers, src_patch->zpe_vers)
			    >= 0);
		}

		uu_avl_walk_end(patch_walk);
	}

	uu_avl_walk_end(walk);

	if (fclose(fp_add) != 0) {
		zperror(gettext("could not save list of packages to add"),
		    B_FALSE);
		goto fatal;
	}
	fp_add = NULL;
	if (fclose(fp_rm) != 0) {
		zperror(gettext("could not save list of packages to remove"),
		    B_FALSE);
		goto fatal;
	}

	/* free avl structs */
	pkg_avl_delete(src_pkgs);
	pkg_avl_delete(dst_pkgs);
	uu_avl_pool_destroy(pkg_pool);

	return (res);

fatal:
	/* free avl structs */
	pkg_avl_delete(src_pkgs);
	pkg_avl_delete(dst_pkgs);
	if (pkg_pool != NULL)
		uu_avl_pool_destroy(pkg_pool);

	if (fp_add != NULL)
		(void) fclose(fp_add);
	if (fp_rm != NULL)
		(void) fclose(fp_rm);

	/* clean up data files left behind */
	(void) snprintf(fname, sizeof (fname), "%s/pkg_add", zonepath);
	(void) unlink(fname);
	(void) snprintf(fname, sizeof (fname), "%s/pkg_rm", zonepath);
	(void) unlink(fname);

	return (Z_FATAL);
}
