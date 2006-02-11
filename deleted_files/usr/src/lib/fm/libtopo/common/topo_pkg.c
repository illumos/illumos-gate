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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/modctl.h>
#include <sys/fm/protocol.h>
#include <alloca.h>
#include <libtopo.h>
#include "topo_impl.h"

/*
 * mod_filename_bindpath --
 *
 * Determine that path to a particular mod_filename.  The path is determined
 * using the module load path hierarchy for the machine obtained from the
 * kernel via MODGETPATH modctl and kernel run mode information obtained from
 * MODGETPATHSUFFIX - and searching for the module on this path.  A match
 * corresponds to the same path the kernel would use to load the module.
 *
 * This function returns a pointer to a malloced path. The caller
 * must free this to avoid leaks.
 *
 * NOTE: this function is typically called for an unbound path
 * (unloaded module, so MODINFO_MODPATH failed). We may however call
 * this for a bound path (loaded module) if MODINFO_MODPATH returned
 * path does not start with '/'.  This situation may occur with
 * primary modules loaded by OBP, like krtld.
 */
#define	MOD_SEP	" :"

static char *Moddirsave;
static char *Suffixdir;

static char *
mod_filename_bindpath(const char *mod_filename)
{
	char		*moddir;
	char		path[MAXPATHLEN];
	char		*dir = NULL;
	char		*ls;
	struct stat	st;
	int		len;

	/*
	 * On first call, initialize the string that describes the
	 * directories searched by the kernel to locate a module.
	 */
	if (Moddirsave == NULL) {
		if (modctl(MODGETPATHLEN, NULL, &len) != 0)
			goto out;
		Moddirsave = topo_zalloc(len + 1);
		if (modctl(MODGETPATH, NULL, Moddirsave) != 0) {
			topo_free(Moddirsave);
			Moddirsave = topo_strdup("");
			goto out;
		}
		topo_out(TOPO_DEBUG, "%s\n", Moddirsave);
	}

	/*
	 * On first call, initialize architecture specific directory suffix.
	 */
	if (Suffixdir == NULL) {
		char *tmpbuf = alloca(MAXPATHLEN);
		char *sufbuf = alloca(MAXPATHLEN);

		(void) sysinfo(SI_ARCHITECTURE_K, tmpbuf, MAXPATHLEN);
		if (strcmp(tmpbuf, "i386") == 0) {
			Suffixdir = topo_strdup("drv");
		} else {
			(void) snprintf(sufbuf, MAXPATHLEN, "drv/%s", tmpbuf);
			Suffixdir = topo_strdup(sufbuf);
		}
	}

	/* find the last '/' in mod_filename */
	ls = strrchr(mod_filename, '/');

	/* initialize for module path string breakup */
	moddir = topo_strdup(Moddirsave);
	dir = strtok(moddir, MOD_SEP);

	/* loop over the directories searched to locate a module */
	while (dir != NULL) {
		/*
		 * break out of loop if we find the file.
		 * try the Suffixdir (e.g, "sparcv9") specific path first
		 */
		if (ls) {
			/*
			 * split mod_filename into a path piece and a
			 * file piece, then interject our suffix
			 * between the pieces.
			 *
			 * i.e, if path comes in as drv/fish
			 * and Suffixdir is determined to be sparcv9,
			 * we end up with .../drv/sparcv9/fish.
			 */
			*ls = 0;
			(void) snprintf(path, sizeof (path), "%s/%s/%s/%s",
			    dir, mod_filename, Suffixdir, &ls[1]);
			*ls = '/';
			if ((stat(path, &st) == 0) &&
			    ((st.st_mode & S_IFMT) == S_IFREG))
				break;
		} else {
			/* we don't have a '/' in path, Suffixdir goes first */
			(void) snprintf(path, sizeof (path),
			    "%s/%s/%s", dir, Suffixdir, mod_filename);
			if ((stat(path, &st) == 0) &&
			    ((st.st_mode & S_IFMT) == S_IFREG))
				break;
		}

		/* try straight mod_filename. */
		(void) snprintf(path, sizeof (path), "%s/%s",
		    dir, mod_filename);
		if ((stat(path, &st) == 0) &&
		    ((st.st_mode & S_IFMT) == S_IFREG))
			break;

		dir = strtok((char *)NULL, MOD_SEP);
	}

	topo_free(moddir);

out:	if (dir == NULL)
		return (NULL);

	return (topo_strdup(path));
}

static int
read_thru(FILE *fp, const char *substr)
{
	char *tmpbuf = alloca(2 * MAXPATHLEN);
	int notfound = 1;

	while (fgets(tmpbuf, 2 * MAXPATHLEN, fp) != NULL) {
		if (substr == NULL)
			topo_out(TOPO_DEBUG, "%s", tmpbuf);
		else if (strstr(tmpbuf, substr) != NULL) {
			notfound = 0;
			break;
		}
	}
	return (notfound);
}

static nvlist_t *
construct_asru_fmri(struct modinfo *mi, nvlist_t *fru)
{
	nvlist_t *a = NULL;
	int e;

	errno = nvlist_xalloc(&a, NV_UNIQUE_NAME, &Topo_nv_alloc_hdl);
	if (errno != 0) {
		topo_out(TOPO_ERR, "alloc of mod nvl failed:");
		goto fmrialeave;
	}

	mi->mi_name[MODMAXNAMELEN - 1] = '\0';
	mi->mi_msinfo[0].msi_linkinfo[MODMAXNAMELEN - 1] = '\0';

	e = nvlist_add_string(a, FM_FMRI_SCHEME, FM_FMRI_SCHEME_MOD);
	e |= nvlist_add_uint8(a, FM_VERSION, FM_MOD_SCHEME_VERSION);
	e |= nvlist_add_nvlist(a, FM_FMRI_MOD_PKG, fru);
	e |= nvlist_add_string(a, FM_FMRI_MOD_NAME, mi->mi_name);
	e |= nvlist_add_int32(a, FM_FMRI_MOD_ID, mi->mi_id);
	e |= nvlist_add_string(a, FM_FMRI_MOD_DESC,
	    mi->mi_msinfo[0].msi_linkinfo);
	if (e != 0) {
		topo_out(TOPO_ERR, "construct of mod nvl failed:");
		goto fmrialeave;
	}

	return (a);

fmrialeave:
	if (a != NULL)
		nvlist_free(a);
	return (NULL);
}

static nvlist_t *
construct_fru_fmri(const char *pkgname, FILE *fp)
{
	nvlist_t *f = NULL;
	char *tmpbuf = alloca(2 * MAXPATHLEN);
	char *pkgdir = NULL;
	char *pkgver = NULL;
	char *token;
	int e;

	if (pkgname == NULL)
		return (NULL);

	while (fgets(tmpbuf, 2 * MAXPATHLEN, fp) != NULL) {
		if (strstr(tmpbuf, "VERSION:") != NULL) {
			token = strtok(tmpbuf, ":");
			token = strtok(NULL, ": \t\n");
			pkgver = topo_strdup(token);
		} else if (strstr(tmpbuf, "BASEDIR:") != NULL) {
			token = strtok(tmpbuf, ":");
			token = strtok(NULL, ": \t\n");
			pkgdir = topo_strdup(token);
		}
	}

	if (pkgdir == NULL || pkgver == NULL)
		goto fmrileave;

	errno = nvlist_xalloc(&f, NV_UNIQUE_NAME, &Topo_nv_alloc_hdl);
	if (errno != 0) {
		topo_out(TOPO_ERR, "alloc of pkg nvl failed:");
		goto fmrileave;
	}
	e = nvlist_add_string(f, FM_FMRI_SCHEME, FM_FMRI_SCHEME_PKG);
	e |= nvlist_add_uint8(f, FM_VERSION, FM_PKG_SCHEME_VERSION);
	e |= nvlist_add_string(f, FM_FMRI_PKG_BASEDIR, pkgdir);
	e |= nvlist_add_string(f, FM_FMRI_PKG_INST, pkgname);
	e |= nvlist_add_string(f, FM_FMRI_PKG_VERSION, pkgver);
	if (e == 0)
		goto fmrileave;

	topo_out(TOPO_ERR, "construct of pkg nvl failed:");
	nvlist_free(f);
	f = NULL;

fmrileave:
	if (pkgdir != NULL)
		topo_free(pkgdir);
	if (pkgver != NULL)
		topo_free(pkgver);

	return (f);
}

#define	PKGINFO_CMD	"LC_MESSAGES= /usr/bin/pkginfo -l %s 2>/dev/null"
#define	PKGCHK_CMD	"LC_MESSAGES= /usr/sbin/pkgchk -lp %s 2>/dev/null"
#define	PKG_KEYPHRASE	"Referenced by the following packages:"

/*
 * topo_driver_fru -- Given a driver name, find the path that module,
 *	and then look up the package delivering that module to the
 *	system.  Then construct a 'pkg' scheme FMRI that describes the
 *	package.
 */
static nvlist_t *
topo_driver_fru(const char *drvrname)
{
	nvlist_t *f = NULL;
	FILE *pcout;
	char *tmpbuf = alloca(2 * MAXPATHLEN);
	char *findpkgname;
	char *pkgname = NULL;
	char *path;

	if ((path = mod_filename_bindpath(drvrname)) != NULL) {
		(void) snprintf(tmpbuf, 2 * MAXPATHLEN, PKGCHK_CMD, path);
		topo_out(TOPO_DEBUG, "popen of %s\n", tmpbuf);
		pcout = popen(tmpbuf, "r");
		if (read_thru(pcout, PKG_KEYPHRASE)) {
			(void) pclose(pcout);
			goto drvfrufail;
		}
		(void) fgets(tmpbuf, 2 * MAXPATHLEN, pcout);
		(void) pclose(pcout);
		topo_out(TOPO_DEBUG, "%s", tmpbuf);

		if ((findpkgname = strtok(tmpbuf, " 	\n")) == NULL)
			goto drvfrufail;
		pkgname = topo_strdup(findpkgname);
		(void) snprintf(tmpbuf, 2 * MAXPATHLEN, PKGINFO_CMD, pkgname);
		topo_out(TOPO_DEBUG, "popen of %s\n", tmpbuf);
		pcout = popen(tmpbuf, "r");
		f = construct_fru_fmri(pkgname, pcout);
		(void) pclose(pcout);
	}

drvfrufail:
	if (pkgname != NULL)
		topo_free(pkgname);
	if (path != NULL)
		topo_free(path);
	return (f);
}

/*
 * topo_driver_asru -- Given a driver name, first create its FRU fmri
 *	and if that goes well, get the rest of the module information
 *	and put it in a 'mod' scheme FMRI describing the driver as an
 *	ASRU.
 */
nvlist_t *
topo_driver_asru(const char *drvrname, nvlist_t **frup)
{
	struct modinfo mi;
	nvlist_t *a = NULL;
	nvlist_t *f = NULL;
	int true = 1;
	int id = -1;	/* get info for all loaded modules */

	if ((f = topo_driver_fru(drvrname)) == NULL)
		goto drvasrufail;

	mi.mi_id = mi.mi_nextid = id;
	mi.mi_info = MI_INFO_ALL | MI_INFO_NOBASE;
	do {
		if (modctl(MODINFO, id, &mi) < 0)
			break;
		if (strncmp(mi.mi_name, drvrname, MODMAXNAMELEN) == 0) {
			if ((a = construct_asru_fmri(&mi, f)) == NULL)
				goto drvasrufail;
			break;
		}
		id = mi.mi_id;
	} while (true);

	if (f != NULL && frup != NULL)
		*frup = f;
	return (a);

drvasrufail:
	if (f != NULL)
		nvlist_free(f);
	return (NULL);
}

void
topo_driver_fini(void)
{
	if (Moddirsave != NULL) {
		topo_free(Moddirsave);
		Moddirsave = NULL;
	}
	if (Suffixdir != NULL) {
		topo_free(Suffixdir);
		Suffixdir = NULL;
	}
}
