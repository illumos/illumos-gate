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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <libzonecfg.h>

#include "zoneadm.h"

/*
 * Find the specified package in the sw inventory on the handle and check
 * if the version matches what is passed in.
 * Return 0 if the packages match
 *        1 if the package is found but we have a version mismatch
 *        -1 if the package is not found
 */
static int
pkg_cmp(zone_dochandle_t handle, char *pkg_name, char *pkg_vers,
    char *return_vers, int vers_size)
{
	int res = -1;
	struct zone_pkgtab pkgtab;

	if (zonecfg_setpkgent(handle) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate packages\n"));
		return (Z_ERR);
	}

	while (zonecfg_getpkgent(handle, &pkgtab) == Z_OK) {
		if (strcmp(pkg_name, pkgtab.zone_pkg_name) != 0)
			continue;

		if (strcmp(pkg_vers, pkgtab.zone_pkg_version) == 0) {
			res = 0;
			break;
		}

		(void) strlcpy(return_vers, pkgtab.zone_pkg_version, vers_size);
		res = 1;
		break;
	}

	(void) zonecfg_endpkgent(handle);
	return (res);
}

/*
 * Used in software comparisons to check the packages between the two zone
 * handles.  The packages have to match or we print a message telling the
 * user what is out of sync.  If flag has SW_CMP_SRC this tells us the first
 * handle is the source machine global zone.  This is used to enable the
 * right messages to be printed and also to enable extra version checking
 * that is not needed for the opposite comparison.
 */
static int
pkg_check(char *header, zone_dochandle_t handle1, zone_dochandle_t handle2,
    uint_t flag)
{
	int			err;
	int			res = Z_OK;
	boolean_t		do_header = B_TRUE;
	char			other_vers[ZONE_PKG_VERSMAX];
	struct zone_pkgtab	pkgtab;

	if (zonecfg_setpkgent(handle1) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate packages\n"));
		return (Z_ERR);
	}

	while (zonecfg_getpkgent(handle1, &pkgtab) == Z_OK) {
		if ((err = pkg_cmp(handle2, pkgtab.zone_pkg_name,
		    pkgtab.zone_pkg_version, other_vers, sizeof (other_vers)))
		    != 0) {
			res = Z_ERR;
			if (flag & SW_CMP_SILENT)
				break;

			if (do_header && (err < 0 || flag & SW_CMP_SRC)) {
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr, header);
				do_header = B_FALSE;
			}
			if (err < 0)
				(void) fprintf(stderr,
				    (flag & SW_CMP_SRC) ?
				    gettext("\t%s: not installed\n\t\t(%s)\n") :
				    gettext("\t%s (%s)\n"),
				    pkgtab.zone_pkg_name,
				    pkgtab.zone_pkg_version);
			else if (flag & SW_CMP_SRC)
				(void) fprintf(stderr, gettext(
				    "\t%s: version mismatch\n\t\t(%s)"
				    "\n\t\t(%s)\n"),
				    pkgtab.zone_pkg_name,
				    pkgtab.zone_pkg_version, other_vers);
		}
	}

	(void) zonecfg_endpkgent(handle1);

	return (res);
}

/*
 * Find the specified patch in the sw inventory on the handle and check
 * if the version matches what is passed in.
 * Return 0 if the patches match
 *        1 if the patches is found but we have a version mismatch
 *        -1 if the patches is not found
 */
static int
patch_cmp(zone_dochandle_t handle, char *patch_id, char *patch_vers,
    char *return_vers, int vers_size)
{
	int			res = -1;
	struct zone_patchtab	patchtab;

	if (zonecfg_setpatchent(handle) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate patches\n"));
		return (Z_ERR);
	}

	while (zonecfg_getpatchent(handle, &patchtab) == Z_OK) {
		char *p;

		if ((p = strchr(patchtab.zone_patch_id, '-')) != NULL)
			*p++ = '\0';
		else
			p = "";

		if (strcmp(patch_id, patchtab.zone_patch_id) != 0)
			continue;

		if (strcmp(patch_vers, p) == 0) {
			res = 0;
			break;
		}

		(void) strlcpy(return_vers, p, vers_size);
		/*
		 * Keep checking.  This handles the case where multiple
		 * versions of the same patch is installed.
		 */
		res = 1;
	}

	(void) zonecfg_endpatchent(handle);
	return (res);
}

/*
 * Used in software comparisons to check the patches between the two zone
 * handles.  The patches have to match or we print a message telling the
 * user what is out of sync.  If flag has SW_CMP_SRC this tells us the first
 * handle is the source machine global zone.  This is used to enable the
 * right messages to be printed.  For patches we do need to compare the
 * versions both ways and print the right header and error message.  This
 * is because it is possible to have multiple versions of a patch installed
 * and we need to detect the case where the target has a newer version of
 * a patch in addition to the version that was installed on the source.
 */
static int
patch_check(char *header, zone_dochandle_t handle1, zone_dochandle_t handle2,
    uint_t flag)
{
	int			err;
	int			res = Z_OK;
	boolean_t		do_header = B_TRUE;
	char			other_vers[MAXNAMELEN];
	struct zone_patchtab	patchtab;

	if (zonecfg_setpatchent(handle1) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate patches\n"));
		return (Z_ERR);
	}

	while (zonecfg_getpatchent(handle1, &patchtab) == Z_OK) {
		char *patch_vers;

		if ((patch_vers = strchr(patchtab.zone_patch_id, '-')) != NULL)
			*patch_vers++ = '\0';
		else
			patch_vers = "";

		if ((err = patch_cmp(handle2, patchtab.zone_patch_id,
		    patch_vers, other_vers, sizeof (other_vers))) != 0) {
			res = Z_ERR;
			if (flag & SW_CMP_SILENT)
				break;

			if (do_header) {
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr, header);
				do_header = B_FALSE;
			}
			if (err < 0)
				(void) fprintf(stderr,
				    (flag & SW_CMP_SRC) ?
				    gettext("\t%s: not installed\n") :
				    gettext("\t%s\n"),
				    patchtab.zone_patch_id);
			else
				(void) fprintf(stderr,
				    gettext("\t%s: version mismatch\n\t\t(%s) "
				    "(%s)\n"), patchtab.zone_patch_id,
				    patch_vers, other_vers);
		}
	}

	(void) zonecfg_endpatchent(handle1);

	return (res);
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
	int		res = Z_OK;

	/*
	 * Check the source host for pkgs (and versions) that are not on the
	 * local host.
	 */
	if (!(flag & SW_CMP_SILENT))
		hdr = gettext("These packages installed on the source system "
		    "are inconsistent with this system:\n");
	if (pkg_check(hdr, s_handle, l_handle, flag | SW_CMP_SRC) != Z_OK)
		res = Z_ERR;

	/*
	 * Now check the local host for pkgs that were not on the source host.
	 * We already handled version mismatches in the loop above.
	 */
	if (!(flag & SW_CMP_SILENT))
		hdr = gettext("These packages installed on this system were "
		    "not installed on the source system:\n");
	if (pkg_check(hdr, l_handle, s_handle, flag | SW_CMP_NONE) != Z_OK)
		res = Z_ERR;

	/*
	 * Check the source host for patches that are not on the local host.
	 */
	if (!(flag & SW_CMP_SILENT))
		hdr = gettext("These patches installed on the source system "
		    "are inconsistent with this system:\n");
	if (patch_check(hdr, s_handle, l_handle, flag | SW_CMP_SRC) != Z_OK)
		res = Z_ERR;

	/*
	 * Check the local host for patches that were not on the source host.
	 * We already handled version mismatches in the loop above.
	 */
	if (!(flag & SW_CMP_SILENT))
		hdr = gettext("These patches installed on this system were "
		    "not installed on the source system:\n");
	if (patch_check(hdr, l_handle, s_handle, flag | SW_CMP_NONE) != Z_OK)
		res = Z_ERR;

	return (res);
}
