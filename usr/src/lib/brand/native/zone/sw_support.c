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

/*
 * sw_support does install, detach and attach processing for svr4 pkgs.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <wait.h>
#include <zone.h>
#include <locale.h>
#include <libintl.h>
#include <libzonecfg.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <dirent.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <fcntl.h>
#include <door.h>
#include <macros.h>
#include <libgen.h>
#include <fnmatch.h>
#include <strings.h>

#include <libzonecfg.h>

#define	ZONE_SUBPROC_OK			0
#define	ZONE_SUBPROC_USAGE		253
#define	ZONE_SUBPROC_NOTCOMPLETE	254
#define	ZONE_SUBPROC_FATAL		255

#define	Z_ERR		1
#define	Z_USAGE		2
#define	Z_FATAL		3

#define	SW_CMP_NONE	0x0
#define	SW_CMP_SRC	0x01
#define	SW_CMP_SILENT	0x02

#define	DETACHED	"SUNWdetached.xml"
#define	ATTACH_FORCED	"SUNWattached.xml"
#define	PKG_PATH	"/var/sadm/pkg"
#define	CONTENTS_FILE	"/var/sadm/install/contents"
#define	SUNW_PKG_ALL_ZONES	"SUNW_PKG_ALLZONES=true\n"
#define	SUNW_PKG_THIS_ZONE	"SUNW_PKG_THISZONE=true\n"
#define	VERSION		"VERSION="
#define	PATCHLIST	"PATCHLIST="
#define	PATCHINFO	"PATCH_INFO_"
#define	PKGINFO_RD_LEN	128
#define	MY_BRAND_NAME	"native"

#define	EXEC_PREFIX	"exec "
#define	EXEC_LEN	(strlen(EXEC_PREFIX))
#define	RMCOMMAND	"/usr/bin/rm -rf"

/* 0755 is the default directory mode. */
#define	DEFAULT_DIR_MODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

enum zn_ipd_fs {ZONE_IPD, ZONE_FS};

struct zone_pkginfo {
	boolean_t	zpi_all_zones;
	boolean_t	zpi_this_zone;
	int		zpi_patch_cnt;
	char		*zpi_version;
	char		**zpi_patchinfo;
};

typedef struct {
	uu_avl_node_t	patch_node;
	char		*patch_num;
	char		*patch_vers;
	uu_list_t	*obs_patches;
} patch_node_t;

typedef struct {
	uu_list_node_t	link;
	char		*patch_num;
} obs_patch_node_t;

typedef struct {
	uu_avl_t	*obs_patches_avl;
	zone_dochandle_t handle;
	int		res;
} patch_parms_t;

static char *locale;
static char *zonename;
static char *zonepath;

/* used in attach_func() and signal handler */
static volatile boolean_t attach_interupted;

void
zperror(const char *str, boolean_t zonecfg_error)
{
	(void) fprintf(stderr, "%s: %s\n", str,
	    zonecfg_error ? zonecfg_strerror(errno) : strerror(errno));
}

static int sw_cmp(zone_dochandle_t, zone_dochandle_t, uint_t);

/* PRINTFLIKE1 */
void
zerror(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);
	(void) fprintf(stderr, "zone '%s': ", zonename);
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

static int
do_subproc(char *cmdbuf)
{
	void (*saveint)(int);
	void (*saveterm)(int);
	void (*savequit)(int);
	void (*savehup)(int);
	int pid, child, status;

	/*
	 * do_subproc() links stdin to /dev/null, which would break any
	 * interactive subprocess we try to launch here.
	 */
	if ((child = vfork()) == 0) {
		(void) execl("/bin/sh", "sh", "-c", cmdbuf, (char *)NULL);
	}

	if (child == -1)
		return (-1);

	saveint = sigset(SIGINT, SIG_IGN);
	saveterm = sigset(SIGTERM, SIG_IGN);
	savequit = sigset(SIGQUIT, SIG_IGN);
	savehup = sigset(SIGHUP, SIG_IGN);

	while ((pid = waitpid(child, &status, 0)) != child && pid != -1)
		;

	(void) sigset(SIGINT, saveint);
	(void) sigset(SIGTERM, saveterm);
	(void) sigset(SIGQUIT, savequit);
	(void) sigset(SIGHUP, savehup);

	return (pid == -1 ? -1 : status);
}

static int
subproc_status(const char *cmd, int status, boolean_t verbose_failure)
{
	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);

		if ((verbose_failure) && (exit_code != ZONE_SUBPROC_OK))
			zerror(gettext("'%s' failed with exit code %d."), cmd,
			    exit_code);

		return (exit_code);
	} else if (WIFSIGNALED(status)) {
		int signal = WTERMSIG(status);
		char sigstr[SIG2STR_MAX];

		if (sig2str(signal, sigstr) == 0) {
			zerror(gettext("'%s' terminated by signal SIG%s."), cmd,
			    sigstr);
		} else {
			zerror(gettext("'%s' terminated by an unknown signal."),
			    cmd);
		}
	} else {
		zerror(gettext("'%s' failed for unknown reasons."), cmd);
	}

	/*
	 * Assume a subprocess that died due to a signal or an unknown error
	 * should be considered an exit code of ZONE_SUBPROC_FATAL, as the
	 * user will likely need to do some manual cleanup.
	 */
	return (ZONE_SUBPROC_FATAL);
}

/*
 * Maintain a space separated list of unique pkg names.  PATH_MAX is used in
 * the pkg code as the maximum size for a pkg name.
 */
static int
add_pkg_to_str(char **str, char *pkg)
{
	int len, newlen;
	char tstr[PATH_MAX + 3];
	char *tmp;

	len = strlen(pkg);
	if (*str == NULL) {
		/* space for str + 2 spaces + NULL */
		if ((*str = (char *)malloc(len + 3)) == NULL)
			return (Z_NOMEM);
		(void) snprintf(*str, len + 3, " %s ", pkg);
		return (Z_OK);
	}

	(void) snprintf(tstr, sizeof (tstr), " %s ", pkg);
	if (strstr(*str, tstr) != NULL)
		return (Z_OK);

	/* space for str + 1 space + NULL */
	newlen = strlen(*str) + len + 2;
	if ((tmp = (char *)realloc(*str, newlen)) == NULL)
		return (Z_NOMEM);
	*str = tmp;
	(void) strlcat(*str, pkg, newlen);
	(void) strlcat(*str, " ", newlen);
	return (Z_OK);
}

/*
 * Process a list of pkgs from an entry in the contents file, adding each pkg
 * name to the list of pkgs.
 *
 * It is possible for the pkg name to be preceeded by a special character
 * which indicates some bookkeeping information for pkging.  Check if the
 * first char is not an Alpha char.  If so, skip over it.
 */
static int
add_pkg_list(char *lastp, char ***plist, int *pcnt, char **pkg_warn)
{
	char	*p;
	int	pkg_cnt = *pcnt;
	char	**pkgs = *plist;
	int	res = Z_OK;

	while ((p = strtok_r(NULL, " ", &lastp)) != NULL) {
		char	**tmpp;
		int	i;

		/* skip over any special pkg bookkeeping char */
		if (!isalpha(*p)) {
			p++;
			if ((res = add_pkg_to_str(pkg_warn, p)) != Z_OK)
				break;
		}

		/* Check if the pkg is already in the list */
		for (i = 0; i < pkg_cnt; i++) {
			if (strcmp(p, pkgs[i]) == 0)
				break;
		}

		if (i < pkg_cnt)
			continue;

		/* The pkg is not in the list; add it. */
		if ((tmpp = (char **)realloc(pkgs,
		    sizeof (char *) * (pkg_cnt + 1))) == NULL) {
			res = Z_NOMEM;
			break;
		}
		pkgs = tmpp;

		if ((pkgs[pkg_cnt] = strdup(p)) == NULL) {
			res = Z_NOMEM;
			break;
		}
		pkg_cnt++;
	}

	*plist = pkgs;
	*pcnt = pkg_cnt;

	return (res);
}

/*
 * Process an entry from the contents file (type "directory").  If the
 * directory path is in the list of ipds and is not under a lofs mount within
 * the ipd then add the associated list of pkgs to the pkg list.  The input
 * parameter "entry" will be broken up by the parser within this function so
 * its value will be modified when this function exits.
 *
 * The entries we are looking for will look something like:
 *	/usr d none 0755 root sys SUNWctpls SUNWidnl SUNWlibCf ....
 */
static int
get_path_pkgs(char *entry, char **ipds, char **fss, char ***pkgs, int *pkg_cnt,
    char **pkg_warn)
{
	char	*f1;
	char	*f2;
	char	*lastp;
	int	i;
	char	*nlp;

	if ((f1 = strtok_r(entry, " ", &lastp)) == NULL ||
	    (f2 = strtok_r(NULL, " ", &lastp)) == NULL || strcmp(f2, "d") != 0)
		return (Z_OK);

	/* Check if this directory entry is in the list of ipds. */
	for (i = 0; ipds[i] != NULL; i++) {
		char wildcard[MAXPATHLEN];

		/*
		 * We want to match on the path and any other directory
		 * entries under this path.  When we use FNM_PATHNAME then
		 * that means '/' will not be matched by a wildcard (*) so
		 * we omit FNM_PATHNAME on the call with the wildcard matching.
		 */
		(void) snprintf(wildcard, sizeof (wildcard), "%s/*", ipds[i]);
		if (fnmatch(ipds[i], f1, FNM_PATHNAME) == 0 ||
		    fnmatch(wildcard, f1, 0) == 0) {
			/* It looks like we do want the pkgs for this path. */
			break;
		}
	}

	/* This entry did not match any of the ipds. */
	if (ipds[i] == NULL)
		return (Z_OK);

	/*
	 * Check if there is a fs mounted under the ipd.  If so, ignore this
	 * entry.
	 */
	for (i = 0; fss[i] != NULL; i++) {
		char wildcard[MAXPATHLEN];

		(void) snprintf(wildcard, sizeof (wildcard), "%s/*", fss[i]);
		if (fnmatch(fss[i], f1, FNM_PATHNAME) == 0 ||
		    fnmatch(wildcard, f1, 0) == 0) {
			/* We should ignore this path. */
			break;
		}
	}

	/* If not null, then we matched an fs mount point so ignore entry. */
	if (fss[i] != NULL)
		return (Z_OK);

	/*
	 * We do want the pkgs for this entry.  First, skip over the next 4
	 * fields in the entry so that we call add_pkg_list starting with the
	 * pkg names.
	 */
	for (i = 0; i < 4 && strtok_r(NULL, " ", &lastp) != NULL; i++)
		;
	/* If there are < 4 fields this entry is corrupt, just skip it. */
	if (i < 4)
		return (Z_OK);

	/* strip newline from the line */
	nlp = (lastp + strlen(lastp) - 1);
	if (*nlp == '\n')
		*nlp = '\0';

	return (add_pkg_list(lastp, pkgs, pkg_cnt, pkg_warn));
}

/*
 * Read an entry from a pkginfo or contents file.  Some of these lines can
 * either be arbitrarily long or be continued by a backslash at the end of
 * the line.  This function coalesces lines that are longer than the read
 * buffer, and lines that are continued, into one buffer which is returned.
 * The caller must free this memory.  NULL is returned when we hit EOF or
 * if we run out of memory (errno is set to ENOMEM).
 */
static char *
read_pkg_data(FILE *fp)
{
	char *start;
	char *inp;
	char *p;
	int char_cnt = 0;

	errno = 0;
	if ((start = (char *)malloc(PKGINFO_RD_LEN)) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	inp = start;
	while ((p = fgets(inp, PKGINFO_RD_LEN, fp)) != NULL) {
		int len;

		len = strlen(inp);
		if (inp[len - 1] == '\n' &&
		    (len == 1 || inp[len - 2] != '\\')) {
			char_cnt = len;
			break;
		}

		if (inp[len - 2] == '\\')
			char_cnt += len - 2;
		else
			char_cnt += PKGINFO_RD_LEN - 1;

		if ((p = realloc(start, char_cnt + PKGINFO_RD_LEN)) == NULL) {
			errno = ENOMEM;
			break;
		}

		start = p;
		inp = start + char_cnt;
	}

	if (errno == ENOMEM || (p == NULL && char_cnt == 0)) {
		free(start);
		start = NULL;
	}

	return (start);
}

static void
free_ipd_pkgs(char **pkgs, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++)
		free(pkgs[i]);
	free(pkgs);
}

/*
 * Get a list of the inherited pkg dirs or fs entries configured for the
 * zone.  The type parameter will be either ZONE_IPD or ZONE_FS.
 */
static int
get_ipd_fs_list(zone_dochandle_t handle, enum zn_ipd_fs type, char ***list)
{
	int	res;
	struct zone_fstab fstab;
	int	cnt = 0;
	char	**entries = NULL;
	int	i;
	int	(*fp)(zone_dochandle_t, struct zone_fstab *);

	if (type == ZONE_IPD) {
		fp = zonecfg_getipdent;
		res = zonecfg_setipdent(handle);
	} else {
		fp = zonecfg_getfsent;
		res = zonecfg_setfsent(handle);
	}

	if (res != Z_OK)
		return (res);

	while (fp(handle, &fstab) == Z_OK) {
		char	**p;

		if ((p = (char **)realloc(entries,
		    sizeof (char *) * (cnt + 1))) == NULL) {
			res = Z_NOMEM;
			break;
		}
		entries = p;

		if ((entries[cnt] = strdup(fstab.zone_fs_dir)) == NULL) {
			res = Z_NOMEM;
			break;
		}

		cnt++;
	}

	if (type == ZONE_IPD)
		(void) zonecfg_endipdent(handle);
	else
		(void) zonecfg_endfsent(handle);

	/* Add a NULL terminating element. */
	if (res == Z_OK) {
		char	**p;

		if ((p = (char **)realloc(entries,
		    sizeof (char *) * (cnt + 1))) == NULL) {
			res = Z_NOMEM;
		} else {
			entries = p;
			entries[cnt] = NULL;
		}
	}

	if (res != Z_OK) {
		if (entries != NULL) {
			for (i = 0; i < cnt; i++)
				free(entries[i]);
			free(entries);
		}
		return (res);
	}

	*list = entries;
	return (Z_OK);
}

/*
 * Get the list of inherited-pkg-dirs (ipd) for the zone and then get the
 * list of pkgs that deliver into those dirs.
 */
static int
get_ipd_pkgs(zone_dochandle_t handle, char ***pkg_list, int *cnt)
{
	int	res;
	char	**ipds;
	char	**fss;
	int	pkg_cnt = 0;
	char	**pkgs = NULL;
	int	i;

	if ((res = get_ipd_fs_list(handle, ZONE_IPD, &ipds)) != Z_OK)
		return (res);

	if ((res = get_ipd_fs_list(handle, ZONE_FS, &fss)) != Z_OK) {
		for (i = 0; ipds[i] != NULL; i++)
			free(ipds[i]);
		free(ipds);
		return (res);
	}

	/* We only have to process the contents file if we have ipds. */
	if (ipds != NULL) {
		FILE	*fp;

		if ((fp = fopen(CONTENTS_FILE, "r")) != NULL) {
			char	*buf;
			char	*pkg_warn = NULL;

			while ((buf = read_pkg_data(fp)) != NULL) {
				res = get_path_pkgs(buf, ipds, fss, &pkgs,
				    &pkg_cnt, &pkg_warn);
				free(buf);
				if (res != Z_OK)
					break;
			}

			(void) fclose(fp);

			if (pkg_warn != NULL) {
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "WARNING: package operation in progress "
				    "on the following packages:\n   %s\n"),
				    pkg_warn);
				free(pkg_warn);
			}
		}
	}

	for (i = 0; ipds[i] != NULL; i++)
		free(ipds[i]);
	free(ipds);

	for (i = 0; fss[i] != NULL; i++)
		free(fss[i]);
	free(fss);

	if (res != Z_OK) {
		free_ipd_pkgs(pkgs, pkg_cnt);
	} else {
		*pkg_list = pkgs;
		*cnt = pkg_cnt;
	}

	return (res);
}

/*
 * Return true if pkg_name is in the list of pkgs that deliver into an
 * inherited pkg directory for the zone.
 */
static boolean_t
dir_pkg(char *pkg_name, char **pkg_list, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++) {
		if (strcmp(pkg_name, pkg_list[i]) == 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Keep track of obsoleted patches for this specific patch.  We don't need to
 * keep track of the patch version since once a patch is obsoleted, all prior
 * versions are also obsolete and there won't be any new versions.
 */
static int
add_obs_patch(patch_node_t *patch, char *num, uu_list_pool_t *patches_pool)
{
	obs_patch_node_t *obs;

	if (patch->obs_patches == NULL) {
		if ((patch->obs_patches = uu_list_create(patches_pool, NULL,
		    0)) == NULL)
			return (Z_NOMEM);
	}

	if ((obs = (obs_patch_node_t *)malloc(sizeof (obs_patch_node_t)))
	    == NULL)
		return (Z_NOMEM);

	if ((obs->patch_num = strdup(num)) == NULL) {
		free(obs);
		return (Z_NOMEM);
	}

	uu_list_node_init(obs, &obs->link, patches_pool);
	(void) uu_list_insert_before(patch->obs_patches, NULL, obs);

	return (Z_OK);
}

/*
 * Keep track of obsoleted patches.  We don't need to keep track of the patch
 * version since once a patch is obsoleted, all prior versions are also
 * obsolete and there won't be any new versions.
 */
static int
save_obs_patch(char *num, uu_avl_pool_t *patches_pool, uu_avl_t *obs_patches)
{
	patch_node_t	*patch;
	uu_avl_index_t where;

	if ((patch = (patch_node_t *)malloc(sizeof (patch_node_t))) == NULL)
		return (Z_NOMEM);

	if ((patch->patch_num = strdup(num)) == NULL) {
		free(patch);
		return (Z_NOMEM);
	}

	patch->patch_vers = NULL;
	patch->obs_patches = NULL;

	uu_avl_node_init(patch, &patch->patch_node, patches_pool);

	if (uu_avl_find(obs_patches, patch, NULL, &where) != NULL) {
		free(patch->patch_num);
		free(patch);
		return (Z_OK);
	}

	uu_avl_insert(obs_patches, patch, where);
	return (Z_OK);
}

/*
 * Keep a list of patches for a pkg.  If we see a newer version of a patch,
 * we only keep track of the newer version.
 */
static boolean_t
save_patch(patch_node_t *patch, uu_avl_t *patches_avl)
{
	patch_node_t *existing;
	uu_avl_index_t where;

	/*
	 * Check if this is a newer version of a patch we already have.
	 * If it is an older version of a patch we already have, ignore it.
	 */
	if ((existing = (patch_node_t *)uu_avl_find(patches_avl, patch, NULL,
	    &where)) != NULL) {
		char *endptr;
		ulong_t pvers, evers;

		pvers = strtoul(patch->patch_vers, &endptr, 10);
		evers = strtoul(existing->patch_vers, &endptr, 10);

		if (pvers <= evers)
			return (B_FALSE);

		/*
		 * Remove the lower version patch from the tree so we can
		 * insert the new higher version one.  We also discard the
		 * obsolete patch list from the old version since the new
		 * version will have its own, likely different, list.
		 */
		uu_avl_remove(patches_avl, existing);
		free(existing->patch_num);
		free(existing->patch_vers);
		if (existing->obs_patches != NULL) {
			obs_patch_node_t *op;
			void *cookie2 = NULL;

			while ((op = uu_list_teardown(existing->obs_patches,
			    &cookie2)) != NULL) {
				free(op->patch_num);
				free(op);
			}
			uu_list_destroy(existing->obs_patches);
		}
		free(existing);

		/*
		 * Now that the old one is gone, find the new location
		 * in the tree.
		 */
		(void) uu_avl_find(patches_avl, patch, NULL, &where);
	}

	uu_avl_insert(patches_avl, patch, where);
	return (B_TRUE);
}

/*
 * Check if a patch is on the list of obsoleted patches.  We don't need to
 * check the patch version since once a patch is obsoleted, all prior versions
 * are also obsolete and there won't be any new versions.
 */
static boolean_t
obsolete_patch(patch_node_t *patch, uu_avl_t *obs_patches)
{
	uu_avl_index_t	where;

	if (uu_avl_find(obs_patches, patch, NULL, &where) != NULL)
		return (B_TRUE);

	return (B_FALSE);
}

/* ARGSUSED */
static int
patch_node_compare(const void *l_arg, const void *r_arg, void *private)
{
	patch_node_t *l = (patch_node_t *)l_arg;
	patch_node_t *r = (patch_node_t *)r_arg;
	char *endptr;
	ulong_t lnum, rnum;

	lnum = strtoul(l->patch_num, &endptr, 10);
	rnum = strtoul(r->patch_num, &endptr, 10);

	if (lnum > rnum)
		return (1);
	if (lnum < rnum)
		return (-1);
	return (0);
}

/*
 * Parse the patchinfo string for the patch.
 *
 * We are parsing entries of the form:
 * PATCH_INFO_121454-02=Installed: Wed Dec  7 07:13:51 PST 2005 From: mum \
 *	Obsoletes: 120777-03 121087-02 119108-07 Requires: 119575-02 \
 *	119255-06 Incompatibles:
 *
 * A backed out patch will have "backed out\n" as the status.  We should
 * skip these patches.  We also ignore any entries that seem to be
 * corrupted.  Obsolete patches are saved in the obs_patches parameter
 * AVL list.
 */
static int
parse_info(char *patchinfo, uu_avl_pool_t *patches_pool, uu_avl_t *patches_avl,
    uu_avl_t *obs_patches, uu_list_pool_t *list_pool)
{
	char		*p;
	char		*lastp;
	char		*ep;
	char		*pvers;
	boolean_t	add_info = B_FALSE;
	patch_node_t	*patch;

	if (strlen(patchinfo) < (sizeof (PATCHINFO) - 1))
		return (Z_OK);

	/* Skip over "PATCH_INFO_" to get the patch id. */
	p = patchinfo + sizeof (PATCHINFO) - 1;
	if ((ep = strchr(p, '=')) == NULL)
		return (Z_OK);

	*ep++ = '\0';

	/* Ignore all but installed patches. */
	if (strncmp(ep, "Installed:", 10) != 0)
		return (Z_OK);

	/* remove newline */
	lastp = (ep + strlen(ep) - 1);
	if (*lastp == '\n')
		*lastp = '\0';

	if ((patch = (patch_node_t *)malloc(sizeof (patch_node_t))) == NULL)
		return (Z_NOMEM);

	if ((pvers = strchr(p, '-')) != NULL)
		*pvers++ = '\0';
	else
		pvers = "";

	if ((patch->patch_num = strdup(p)) == NULL) {
		free(patch);
		return (Z_NOMEM);
	}
	if ((patch->patch_vers = strdup(pvers)) == NULL) {
		free(patch->patch_num);
		free(patch);
		return (Z_NOMEM);
	}
	patch->obs_patches = NULL;

	uu_avl_node_init(patch, &patch->patch_node, patches_pool);
	if (!save_patch(patch, patches_avl)) {
		free(patch->patch_num);
		free(patch->patch_vers);
		assert(patch->obs_patches == NULL);
		free(patch);
		return (Z_OK);
	}

	/*
	 * Start with the first token.  This will probably be "Installed:".
	 * If we can't tokenize this entry, just return.
	 */
	if ((p = strtok_r(ep, " ", &lastp)) == NULL)
		return (Z_OK);

	do {
		if (strcmp(p, "Installed:") == 0 ||
		    strcmp(p, "Requires:") == 0 ||
		    strcmp(p, "From:") == 0 ||
		    strcmp(p, "Incompatibles:") == 0) {
			add_info = B_FALSE;
			continue;
		} else if (strcmp(p, "Obsoletes:") == 0) {
			add_info = B_TRUE;
			continue;
		}

		if (!add_info)
			continue;

		if ((pvers = strchr(p, '-')) != NULL)
			*pvers = '\0';

		/*
		 * We save all of the obsolete patches in one big list in the
		 * obs_patches AVL tree so that we know not to output those as
		 * part of the sw dependencies.  However, we also need to save
		 * the obsolete patch information for this sepcific patch so
		 * so that we can do the cross manifest patch checking
		 * correctly.
		 */
		if (save_obs_patch(p, patches_pool, obs_patches) != Z_OK)
			return (Z_NOMEM);
		if (add_obs_patch(patch, p, list_pool) != Z_OK)
			return (Z_NOMEM);
	} while ((p = strtok_r(NULL, " ", &lastp)) != NULL);

	return (Z_OK);
}

/*
 * AVL walker callback used to add patch to XML manifest.
 *
 * PATH_MAX is used in the pkg/patch code as the maximum size for the patch
 * number/version string.
 */
static int
avl_add_patch(void *e, void *p)
{
	xmlNodePtr	node;
	char		id[PATH_MAX];
	patch_node_t	*patch;
	patch_parms_t	*args;

	patch = e;
	args = p;

	/* skip this patch if it has been obsoleted */
	if (obsolete_patch(patch, args->obs_patches_avl))
		return (UU_WALK_NEXT);

	if (patch->patch_vers[0] == '\0')
		(void) snprintf(id, sizeof (id), "%s", patch->patch_num);
	else
		(void) snprintf(id, sizeof (id), "%s-%s", patch->patch_num,
		    patch->patch_vers);

	if ((args->res = zonecfg_add_patch(args->handle, id, (void **)&node))
	    != Z_OK)
		return (UU_WALK_DONE);

	if (patch->obs_patches != NULL) {
		obs_patch_node_t *op;

		for (op = uu_list_first(patch->obs_patches); op != NULL;
		    op = uu_list_next(patch->obs_patches, op)) {
			(void) snprintf(id, sizeof (id), "%s", op->patch_num);
			if ((args->res = zonecfg_add_patch_obs(id, node))
			    != Z_OK)
				return (UU_WALK_DONE);
		}
	}

	return (UU_WALK_NEXT);
}

static void
patch_avl_delete(uu_avl_t *patches_avl)
{
	if (patches_avl != NULL) {
		patch_node_t *p;
		void *cookie = NULL;

		while ((p = (patch_node_t *)uu_avl_teardown(patches_avl,
		    &cookie)) != NULL) {
			free(p->patch_num);
			free(p->patch_vers);

			if (p->obs_patches != NULL) {
				obs_patch_node_t *op;
				void *cookie2 = NULL;

				while ((op = uu_list_teardown(p->obs_patches,
				    &cookie2)) != NULL) {
					free(op->patch_num);
					free(op);
				}
				uu_list_destroy(p->obs_patches);
			}

			free(p);
		}

		uu_avl_destroy(patches_avl);
	}
}

/*
 * Add the unique, highest version patches that are associated with this pkg
 * to the sw inventory on the handle.
 */
static int
add_patches(zone_dochandle_t handle, struct zone_pkginfo *infop,
    uu_avl_pool_t *patches_pool, uu_avl_t *obs_patches,
    uu_list_pool_t *list_pool)
{
	int		i;
	int		res;
	uu_avl_t 	*patches_avl;
	patch_parms_t	args;

	if ((patches_avl = uu_avl_create(patches_pool, NULL, UU_DEFAULT))
	    == NULL)
		return (Z_NOMEM);

	for (i = 0; i < infop->zpi_patch_cnt; i++) {
		if ((res = parse_info(infop->zpi_patchinfo[i], patches_pool,
		    patches_avl, obs_patches, list_pool)) != Z_OK) {
			patch_avl_delete(patches_avl);
			return (res);
		}
	}

	args.obs_patches_avl = obs_patches;
	args.handle = handle;
	args.res = Z_OK;

	(void) uu_avl_walk(patches_avl, avl_add_patch, &args, 0);

	patch_avl_delete(patches_avl);
	return (args.res);
}

/*
 * Keep track of the pkgs we have already processed so that we can quickly
 * skip those pkgs while recursively doing dependents.
 */
static boolean_t
pkg_in_manifest(uu_avl_t *saw_pkgs, char *pname, uu_avl_pool_t *pkgs_pool)
{
	uu_avl_index_t where;

	if (uu_avl_find(saw_pkgs, pname, NULL, &where) == NULL) {
		zone_pkg_entry_t *pkg;

		/*
		 * We need to add it.  If we don't have memory we just skip
		 * this pkg since this routine improves performance but the
		 * algorithm is still correct without it.
		 */
		if ((pkg = (zone_pkg_entry_t *)
		    malloc(sizeof (zone_pkg_entry_t))) == NULL)
			return (B_FALSE);

		if ((pkg->zpe_name = strdup(pname)) == NULL) {
			free(pkg);
			return (B_FALSE);
		}

		pkg->zpe_vers = NULL;
		pkg->zpe_patches_avl = NULL;

		/* Insert pkg into the AVL tree. */
		uu_avl_node_init(pkg, &pkg->zpe_entry, pkgs_pool);
		uu_avl_insert(saw_pkgs, pkg, where);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
free_pkginfo(struct zone_pkginfo *infop)
{
	free(infop->zpi_version);
	if (infop->zpi_patch_cnt > 0) {
		int i;

		for (i = 0; i < infop->zpi_patch_cnt; i++)
			free(infop->zpi_patchinfo[i]);
		free(infop->zpi_patchinfo);
	}
}

/*
 * Read the pkginfo file and populate the structure with the data we need
 * from this pkg for a sw inventory.
 */
static int
get_pkginfo(char *pkginfo, struct zone_pkginfo *infop)
{
	FILE	*fp;
	char	*buf;
	int	err = 0;

	infop->zpi_all_zones = B_FALSE;
	infop->zpi_this_zone = B_FALSE;
	infop->zpi_version = NULL;
	infop->zpi_patch_cnt = 0;
	infop->zpi_patchinfo = NULL;

	if ((fp = fopen(pkginfo, "r")) == NULL)
		return (errno);

	while ((buf = read_pkg_data(fp)) != NULL) {
		if (strncmp(buf, VERSION, sizeof (VERSION) - 1) == 0) {
			int len;

			if ((infop->zpi_version =
			    strdup(buf + sizeof (VERSION) - 1)) == NULL) {
				err = ENOMEM;
				break;
			}

			/* remove trailing newline */
			len = strlen(infop->zpi_version);
			*(infop->zpi_version + len - 1) = 0;

		} else if (strcmp(buf, SUNW_PKG_ALL_ZONES) == 0) {
			infop->zpi_all_zones = B_TRUE;

		} else if (strcmp(buf, SUNW_PKG_THIS_ZONE) == 0) {
			infop->zpi_this_zone = B_TRUE;

		} else if (strncmp(buf, PATCHINFO, sizeof (PATCHINFO) - 1)
		    == 0) {
			char **p;

			if ((p = (char **)realloc(infop->zpi_patchinfo,
			    sizeof (char *) * (infop->zpi_patch_cnt + 1)))
			    == NULL) {
				err = ENOMEM;
				break;
			}
			infop->zpi_patchinfo = p;

			if ((infop->zpi_patchinfo[infop->zpi_patch_cnt] =
			    strdup(buf)) == NULL) {
				err = ENOMEM;
				break;
			}
			infop->zpi_patch_cnt++;
		}

		free(buf);
	}

	free(buf);

	if (errno == ENOMEM) {
		err = ENOMEM;
		/* Clean up anything we did manage to allocate. */
		free_pkginfo(infop);
	}

	(void) fclose(fp);

	return (err);
}

/*
 * Add any dependent pkgs to the list.  The pkg depend file lists pkg
 * dependencies, one per line with an entry that looks like:
 *	P SUNWcar       Core Architecture, (Root)
 * See the depend(4) man page.
 */
static int
add_dependents(zone_dochandle_t handle, char *pname,
    uu_avl_pool_t *patches_pool, uu_avl_t *obs_patches,
    uu_list_pool_t *list_pool, uu_avl_t *saw_pkgs, uu_avl_pool_t *pkgs_pool)
{
	int		res = Z_OK;
	FILE		*fp;
	char		depend[MAXPATHLEN];
	char		*buf;
	struct stat	sbuf;

	(void) snprintf(depend, sizeof (depend), "%s/%s/install/depend",
	    PKG_PATH, pname);

	if (stat(depend, &sbuf) == -1 || !S_ISREG(sbuf.st_mode))
		return (Z_OK);

	if ((fp = fopen(depend, "r")) == NULL)
		return (Z_OK);

	while ((buf = read_pkg_data(fp)) != NULL) {
		char *deppkg;
		char *delims = " \t";
		char pkginfo[MAXPATHLEN];
		struct zone_pkginfo info;

		if (*buf != 'P') {
			free(buf);
			continue;
		}

		/* Skip past the leading 'P '. */
		if ((deppkg = strtok(buf + 2, delims)) == NULL) {
			free(buf);
			continue;
		}

		/* If the pkg is already in the manifest don't add it again. */
		if (pkg_in_manifest(saw_pkgs, deppkg, pkgs_pool)) {
			free(buf);
			continue;
		}

		(void) snprintf(pkginfo, sizeof (pkginfo), "%s/%s/pkginfo",
		    PKG_PATH, deppkg);

		if (stat(pkginfo, &sbuf) == -1 || !S_ISREG(sbuf.st_mode)) {
			free(buf);
			continue;
		}

		if (get_pkginfo(pkginfo, &info) != 0) {
			res = Z_NOMEM;
			free(buf);
			break;
		}

		if ((res = add_dependents(handle, deppkg, patches_pool,
		    obs_patches, list_pool, saw_pkgs, pkgs_pool)) == Z_OK &&
		    (res = zonecfg_add_pkg(handle, deppkg, info.zpi_version))
		    == Z_OK) {
			if (info.zpi_patch_cnt > 0)
				res = add_patches(handle, &info, patches_pool,
				    obs_patches, list_pool);
		}

		free(buf);
		free_pkginfo(&info);

		if (res != Z_OK)
			break;
	}

	(void) fclose(fp);
	return (res);
}

/* ARGSUSED */
static int
pkg_entry_nm_compare(const void *l_arg, const void *r_arg, void *private)
{
	zone_pkg_entry_t *pkg = (zone_pkg_entry_t *)l_arg;
	char *name = (char *)r_arg;

	return (strcmp(pkg->zpe_name, name));
}

/* ARGSUSED */
static int
pkg_entry_compare(const void *l_arg, const void *r_arg, void *private)
{
	zone_pkg_entry_t *l = (zone_pkg_entry_t *)l_arg;
	zone_pkg_entry_t *r = (zone_pkg_entry_t *)r_arg;

	return (strcmp(l->zpe_name, r->zpe_name));
}

static void
pkg_avl_delete(uu_avl_t *pavl)
{
	if (pavl != NULL) {
		zone_pkg_entry_t *p;
		void *cookie = NULL;

		while ((p = uu_avl_teardown(pavl, &cookie)) != NULL) {
			free(p->zpe_name);
			free(p);
		}

		uu_avl_destroy(pavl);
	}
}

/*
 * Take a software inventory of the global zone.  We need to get the set of
 * packages and patches that are on the global zone that the specified
 * non-global zone depends on.  The packages we need in the inventory are:
 *
 * - skip the package if SUNW_PKG_THISZONE is 'true'
 * otherwise,
 * - add the package if
 * a) SUNW_PKG_ALLZONES is 'true',
 * or
 * b) any file delivered by the package is in a file system that is inherited
 * from the global zone.
 * If the zone does not inherit any file systems (whole root)
 * then (b) will be skipped.
 *
 * For each of the packages that is being added to the inventory, we will also
 * add its dependent packages to the inventory.
 *
 * For each of the packages that is being added to the inventory, we will also
 * add all of the associated, unique patches to the inventory.
 *
 * See the comment for zonecfg_getpkgdata() for compatability restrictions on
 * how we must save the XML representation of the software inventory.
 */
static int
sw_inventory(zone_dochandle_t handle)
{
	char		pkginfo[MAXPATHLEN];
	int		res;
	struct dirent	*dp;
	DIR		*dirp;
	struct stat	buf;
	struct zone_pkginfo	info;
	int		pkg_cnt = 0;
	char		**pkgs = NULL;
	uu_avl_pool_t 	*pkgs_pool = NULL;
	uu_avl_pool_t 	*patches_pool = NULL;
	uu_list_pool_t 	*list_pool = NULL;
	uu_avl_t	*saw_pkgs = NULL;
	uu_avl_t 	*obs_patches = NULL;

	if ((pkgs_pool = uu_avl_pool_create("pkgs_pool",
	    sizeof (zone_pkg_entry_t), offsetof(zone_pkg_entry_t, zpe_entry),
	    pkg_entry_nm_compare, UU_DEFAULT)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	if ((saw_pkgs = uu_avl_create(pkgs_pool, NULL, UU_DEFAULT)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	if ((patches_pool = uu_avl_pool_create("patches_pool",
	    sizeof (patch_node_t), offsetof(patch_node_t, patch_node),
	    patch_node_compare, UU_DEFAULT)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	if ((list_pool = uu_list_pool_create("list_pool",
	    sizeof (obs_patch_node_t), offsetof(obs_patch_node_t, link), NULL,
	    UU_DEFAULT)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	/*
	 * The obs_patches AVL tree saves all of the obsolete patches so
	 * that we know not to output those as part of the sw dependencies.
	 */
	if ((obs_patches = uu_avl_create(patches_pool, NULL, UU_DEFAULT))
	    == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	if ((res = get_ipd_pkgs(handle, &pkgs, &pkg_cnt)) != Z_OK) {
		res = Z_NOMEM;
		goto done;
	}

	if ((dirp = opendir(PKG_PATH)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	while ((dp = readdir(dirp)) != (struct dirent *)0) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		(void) snprintf(pkginfo, sizeof (pkginfo), "%s/%s/pkginfo",
		    PKG_PATH, dp->d_name);

		if (stat(pkginfo, &buf) == -1 || !S_ISREG(buf.st_mode))
			continue;

		if (get_pkginfo(pkginfo, &info) != 0) {
			res = Z_NOMEM;
			break;
		}

		if (!info.zpi_this_zone &&
		    (info.zpi_all_zones ||
		    dir_pkg(dp->d_name, pkgs, pkg_cnt)) &&
		    !pkg_in_manifest(saw_pkgs, dp->d_name, pkgs_pool)) {
			/*
			 * Add dependents first so any patches will get
			 * associated with the right pkg in the xml file.
			 */
			if ((res = add_dependents(handle, dp->d_name,
			    patches_pool, obs_patches, list_pool, saw_pkgs,
			    pkgs_pool)) == Z_OK &&
			    (res = zonecfg_add_pkg(handle, dp->d_name,
			    info.zpi_version)) == Z_OK) {
				if (info.zpi_patch_cnt > 0)
					res = add_patches(handle, &info,
					    patches_pool, obs_patches,
					    list_pool);
			}
		}

		free_pkginfo(&info);

		if (res != Z_OK)
			break;
	}

	(void) closedir(dirp);

done:
	pkg_avl_delete(saw_pkgs);
	patch_avl_delete(obs_patches);
	if (pkgs_pool != NULL)
		uu_avl_pool_destroy(pkgs_pool);
	if (patches_pool != NULL)
		uu_avl_pool_destroy(patches_pool);
	if (list_pool != NULL)
		uu_list_pool_destroy(list_pool);
	free_ipd_pkgs(pkgs, pkg_cnt);

	if (res == Z_OK)
		zonecfg_set_swinv(handle);

	return (res);
}

/*
 * Get the information required to support detaching a zone.  This is
 * called on the source system when detaching (the detaching parameter should
 * be set to true) and on the destination system before attaching (the
 * detaching parameter should be false).
 *
 * For native Solaris zones, the detach/attach process involves validating
 * that the software on the global zone can support the zone when we attach.
 * To do this we take a software inventory of the global zone.  We also
 * have to keep track of the device configuration so that we can properly
 * recreate it on the destination.
 */
static int
get_detach_info(zone_dochandle_t handle, boolean_t detaching)
{
	int		res;

	if ((res = sw_inventory(handle)) != Z_OK)
		return (res);

	if (detaching)
		res = zonecfg_dev_manifest(handle);

	return (res);
}

/* ARGSUSED */
static int
zfm_print(const char *p, void *r) {
	(void) fprintf(stderr, "  %s\n", p);
	return (0);
}

static int
detach_func(int argc, char *argv[])
{
	int err, arg;
	zone_dochandle_t handle;
	boolean_t execute = B_TRUE;

	opterr = 0;
	optind = 0;
	if ((arg = getopt(argc, argv, "?n")) != EOF) {
		switch (arg) {
		case '?':
			if (optopt != '?') {
				(void) fprintf(stderr, gettext("%s brand: "
				    "invalid option: %c\n"), MY_BRAND_NAME,
				    optopt);
			}
			(void) fprintf(stderr, gettext("usage:\t%s brand "
			    "options: none\n"), MY_BRAND_NAME);
			return (optopt == '?' ? Z_OK : ZONE_SUBPROC_USAGE);
		case 'n':
			execute = B_FALSE;
			break;
		default:
			(void) fprintf(stderr, gettext("%s brand: invalid "
			    "option: %c\n"), MY_BRAND_NAME, arg);
			return (ZONE_SUBPROC_USAGE);
		}
	}

	/* Don't detach the zone if anything is still mounted there */
	if (execute && zonecfg_find_mounts(zonepath, NULL, NULL)) {
		(void) fprintf(stderr, gettext("These file systems are "
		    "mounted on subdirectories of %s.\n"), zonepath);
		(void) zonecfg_find_mounts(zonepath, zfm_print, NULL);
		return (ZONE_SUBPROC_NOTCOMPLETE);
	}

	if ((handle = zonecfg_init_handle()) == NULL) {
		(void) fprintf(stderr, gettext("brand detach program error: "
		    "%s\n"), strerror(errno));
		return (ZONE_SUBPROC_NOTCOMPLETE);
	}

	if ((err = zonecfg_get_handle(zonename, handle)) != Z_OK) {
		(void) fprintf(stderr, gettext("brand detach program error: "
		    "%s\n"), zonecfg_strerror(err));
		zonecfg_fini_handle(handle);
		return (ZONE_SUBPROC_NOTCOMPLETE);
	}

	if ((err = get_detach_info(handle, B_TRUE)) != Z_OK) {
		(void) fprintf(stderr, gettext("brand detach program error: "
		    "%s\n"), zonecfg_strerror(err));
		goto done;
	}

	if ((err = zonecfg_detach_save(handle, (execute ? 0 : ZONE_DRY_RUN)))
	    != Z_OK) {
		(void) fprintf(stderr, gettext("saving the detach manifest "
		    "failed: %s\n"), zonecfg_strerror(err));
		goto done;
	}

done:
	zonecfg_fini_handle(handle);

	return ((err == Z_OK) ? ZONE_SUBPROC_OK : ZONE_SUBPROC_FATAL);
}

/*
 * Validate attaching a zone but don't actually do the work.  The zone
 * does not have to exist, so there is some complexity getting a new zone
 * configuration set up so that we can perform the validation.  This is
 * handled within zonecfg_attach_manifest() which returns two handles; one
 * for the the full configuration to validate (rem_handle) and the other
 * (local_handle) containing only the zone configuration derived from the
 * manifest.
 */
static int
dryrun_attach(char *manifest_path)
{
	int fd;
	int err;
	int res;
	char atbrand[MAXNAMELEN];
	zone_dochandle_t local_handle;
	zone_dochandle_t rem_handle = NULL;

	if ((fd = open(manifest_path, O_RDONLY)) < 0) {
		(void) fprintf(stderr, gettext("could not open manifest path: "
		    "%s\n"), strerror(errno));
		return (ZONE_SUBPROC_NOTCOMPLETE);
	}

	if ((local_handle = zonecfg_init_handle()) == NULL) {
		(void) fprintf(stderr, gettext("brand attach program error: "
		    "%s\n"), strerror(errno));
		res = ZONE_SUBPROC_NOTCOMPLETE;
		goto done;
	}

	if ((rem_handle = zonecfg_init_handle()) == NULL) {
		(void) fprintf(stderr, gettext("brand attach program error: "
		    "%s\n"), strerror(errno));
		res = ZONE_SUBPROC_NOTCOMPLETE;
		goto done;
	}

	if ((err = zonecfg_attach_manifest(fd, local_handle, rem_handle))
	    != Z_OK) {
		res = ZONE_SUBPROC_NOTCOMPLETE;

		if (err == Z_INVALID_DOCUMENT) {
			char buf[6];

			bzero(buf, sizeof (buf));
			(void) lseek(fd, 0L, SEEK_SET);
			if (read(fd, buf, sizeof (buf) - 1) < 0 ||
			    strncmp(buf, "<?xml", 5) != 0)
				(void) fprintf(stderr, gettext("%s is not an "
				    "XML file\n"), manifest_path);
			else
				(void) fprintf(stderr, gettext("Cannot attach "
				    "to an earlier release of the operating "
				    "system\n"));
		} else {
			(void) fprintf(stderr, gettext("brand attach program "
			    "error: %s\n"), zonecfg_strerror(err));
		}
		goto done;
	}

	/*
	 * Retrieve remote handle brand type and determine whether it is
	 * native or not.
	 */
	if (zonecfg_get_brand(rem_handle, atbrand, sizeof (atbrand)) != Z_OK) {
		(void) fprintf(stderr, gettext("missing or invalid brand\n"));
		exit(ZONE_SUBPROC_FATAL);
	}

	if (strcmp(atbrand, MY_BRAND_NAME) != 0) {
		err = Z_ERR;
		(void) fprintf(stderr, gettext("Trying to attach a '%s' zone "
		    "to a '%s' configuration.\n"), atbrand, MY_BRAND_NAME);
		exit(ZONE_SUBPROC_FATAL);
	}

	/* Get the detach information for the locally defined zone. */
	res = Z_OK;
	if ((err = get_detach_info(local_handle, B_FALSE)) != Z_OK) {
		(void) fprintf(stderr, gettext("getting the attach information "
		    "failed: %s\n"), zonecfg_strerror(err));
		res = ZONE_SUBPROC_FATAL;
	} else {
		/* sw_cmp prints error msgs as necessary */
		if (sw_cmp(local_handle, rem_handle, SW_CMP_NONE) != Z_OK)
			res = ZONE_SUBPROC_FATAL;
	}

done:
	(void) close(fd);

	zonecfg_fini_handle(local_handle);
	zonecfg_fini_handle(rem_handle);

	return ((res == Z_OK) ? Z_OK : ZONE_SUBPROC_FATAL);
}

static int
mount_func(boolean_t force)
{
	zone_cmd_arg_t zarg;

	zarg.cmd = force ? Z_FORCEMOUNT : Z_MOUNT;
	zarg.bootbuf[0] = '\0';
	if (zonecfg_call_zoneadmd(zonename, &zarg, locale, B_FALSE) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		return (Z_ERR);
	}
	return (Z_OK);
}

static int
unmount_func()
{
	zone_cmd_arg_t zarg;

	zarg.cmd = Z_UNMOUNT;
	if (zonecfg_call_zoneadmd(zonename, &zarg, locale, B_FALSE) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		return (Z_ERR);
	}
	return (Z_OK);
}

/*
 * Attempt to generate the information we need to make the zone look like
 * it was properly detached by using the pkg information contained within
 * the zone itself.
 *
 * We will perform a dry-run detach within the zone to generate the xml file.
 * To do this we need to be able to get a handle on the zone so we can see
 * how it is configured.  In order to get a handle, we need a copy of the
 * zone configuration within the zone.  Since the zone's configuration is
 * not available within the zone itself, we need to temporarily copy it into
 * the zone.
 *
 * The sequence of actions we are doing is this:
 *	[set zone state to installed]
 *	[mount zone]
 *	zlogin {zone} </etc/zones/{zone}.xml 'cat >/etc/zones/{zone}.xml'
 *	zlogin {zone} 'zoneadm -z {zone} detach -n' >{zonepath}/SUNWdetached.xml
 *	zlogin {zone} 'rm -f /etc/zones/{zone}.xml'
 *	[unmount zone]
 *	[set zone state to configured]
 *
 * The successful result of this function is that we will have a
 * SUNWdetached.xml file in the zonepath and we can use that to attach the zone.
 */
static boolean_t
gen_detach_info()
{
	int		status;
	boolean_t	mounted = B_FALSE;
	boolean_t	res = B_FALSE;
	char		cmdbuf[2 * MAXPATHLEN];

	/*
	 * The zone has to be installed to mount and zlogin.  Temporarily set
	 * the state to 'installed'.
	 */
	if (zone_set_state(zonename, ZONE_STATE_INSTALLED) != Z_OK)
		return (B_FALSE);

	/* Mount the zone so we can zlogin. */
	if (mount_func(B_FALSE) != Z_OK)
		goto cleanup;
	mounted = B_TRUE;

	/*
	 * We need to copy the zones xml configuration file into the
	 * zone so we can get a handle for the zone while running inside
	 * the zone.
	 */
	if (snprintf(cmdbuf, sizeof (cmdbuf), "/usr/sbin/zlogin -S %s "
	    "</etc/zones/%s.xml '/usr/bin/cat >/etc/zones/%s.xml'",
	    zonename, zonename, zonename) >= sizeof (cmdbuf))
		goto cleanup;

	status = do_subproc(cmdbuf);
	if (subproc_status("copy", status, B_TRUE) != ZONE_SUBPROC_OK)
		goto cleanup;

	/* Now run the detach command within the mounted zone. */
	if (snprintf(cmdbuf, sizeof (cmdbuf), "/usr/sbin/zlogin -S %s "
	    "'/usr/sbin/zoneadm -z %s detach -n' >%s/SUNWdetached.xml",
	    zonename, zonename, zonepath) >= sizeof (cmdbuf))
		goto cleanup;

	status = do_subproc(cmdbuf);
	if (subproc_status("detach", status, B_TRUE) != ZONE_SUBPROC_OK)
		goto cleanup;

	res = B_TRUE;

cleanup:
	/* Cleanup from the previous actions. */
	if (mounted) {
		if (snprintf(cmdbuf, sizeof (cmdbuf),
		    "/usr/sbin/zlogin -S %s '/usr/bin/rm -f /etc/zones/%s.xml'",
		    zonename, zonename) >= sizeof (cmdbuf)) {
			res = B_FALSE;
		} else {
			status = do_subproc(cmdbuf);
			if (subproc_status("rm", status, B_TRUE)
			    != ZONE_SUBPROC_OK)
				res = B_FALSE;
		}

		if (unmount_func() != Z_OK)
			res =  B_FALSE;
	}

	if (zone_set_state(zonename, ZONE_STATE_CONFIGURED) != Z_OK)
		res = B_FALSE;

	return (res);
}

/*
 * The zone needs to be updated so set it up for the update and initiate the
 * update within the scratch zone.  First set the state to incomplete so we can
 * force-mount the zone for the update operation.  We pass the -U option to the
 * mount so that the scratch zone is mounted without the zone's /etc and /var
 * being lofs mounted back into the scratch zone root.  This is done by
 * overloading the bootbuf string in the zone_cmd_arg_t to pass -U as an option
 * to the mount cmd.
 */
static int
attach_update(zone_dochandle_t handle)
{
	int err;
	int update_res;
	int status;
	zone_cmd_arg_t zarg;
	FILE *fp;
	struct zone_fstab fstab;
	char cmdbuf[(4 * MAXPATHLEN) + 20];

	if ((err = zone_set_state(zonename, ZONE_STATE_INCOMPLETE))
	    != Z_OK) {
		(void) fprintf(stderr, gettext("could not set state: %s\n"),
		    zonecfg_strerror(err));
		return (Z_FATAL);
	}

	zarg.cmd = Z_FORCEMOUNT;
	(void) strlcpy(zarg.bootbuf, "-U",  sizeof (zarg.bootbuf));
	if (zonecfg_call_zoneadmd(zonename, &zarg, locale, B_FALSE) != 0) {
		(void) fprintf(stderr, gettext("could not mount zone\n"));

		/* We reset the state since the zone wasn't modified yet. */
		if ((err = zone_set_state(zonename, ZONE_STATE_CONFIGURED))
		    != Z_OK) {
			(void) fprintf(stderr, gettext("could not reset state: "
			    "%s\n"), zonecfg_strerror(err));
		}
		return (Z_FATAL);
	}

	/*
	 * Move data files generated by sw_up_to_date() into the scratch
	 * zone's /tmp.
	 */
	(void) snprintf(cmdbuf, sizeof (cmdbuf), "exec /usr/bin/mv "
	    "%s/pkg_add %s/pkg_rm %s/lu/tmp",
	    zonepath, zonepath, zonepath);

	status = do_subproc(cmdbuf);
	if (subproc_status("mv", status, B_TRUE) != ZONE_SUBPROC_OK) {
		(void) fprintf(stderr, gettext("could not mv data files: %s\n"),
		    strerror(errno));
		goto fail;
	}

	/*
	 * Save list of inherit-pkg-dirs into zone.  Since the file is in
	 * /tmp we don't have to worry about deleting it.
	 */
	(void) snprintf(cmdbuf, sizeof (cmdbuf), "%s/lu/tmp/inherited",
	    zonepath);
	if ((fp = fopen(cmdbuf, "w")) == NULL) {
		(void) fprintf(stderr, gettext("could not save "
		    "inherit-pkg-dirs: %s\n"), strerror(errno));
		goto fail;
	}
	if (zonecfg_setipdent(handle) != Z_OK) {
		(void) fprintf(stderr, gettext("could not enumerate "
		    "inherit-pkg-dirs: %s\n"), zonecfg_strerror(err));
		goto fail;
	}
	while (zonecfg_getipdent(handle, &fstab) == Z_OK) {
		if (fprintf(fp, "%s\n", fstab.zone_fs_dir) < 0) {
			(void) fprintf(stderr, gettext("could not save "
			    "inherit-pkg-dirs: %s\n"), strerror(errno));
			(void) fclose(fp);
			goto fail;
		}
	}
	(void) zonecfg_endipdent(handle);
	if (fclose(fp) != 0) {
		(void) fprintf(stderr, gettext("could not save "
		    "inherit-pkg-dirs: %s\n"), strerror(errno));
		goto fail;
	}

	/* run the updater inside the scratch zone */
	(void) snprintf(cmdbuf, sizeof (cmdbuf),
	    "exec /usr/sbin/zlogin -S %s "
	    "/usr/lib/brand/native/attach_update %s", zonename, zonename);

	update_res = Z_OK;
	status = do_subproc(cmdbuf);
	if (subproc_status("attach_update", status, B_TRUE)
	    != ZONE_SUBPROC_OK) {
		(void) fprintf(stderr, gettext("could not update zone\n"));
		update_res = Z_ERR;
	}

	zarg.cmd = Z_UNMOUNT;
	if (zonecfg_call_zoneadmd(zonename, &zarg, locale, B_FALSE) != 0) {
		(void) fprintf(stderr, gettext("could not unmount zone\n"));
		return (Z_ERR);
	}

	/*
	 * If the update script within the scratch zone failed for some reason
	 * we will now leave the zone in the incomplete state since we no
	 * longer know the state of the files within the zonepath.
	 */
	if (update_res == Z_ERR)
		return (Z_ERR);

	zonecfg_rm_detached(handle, B_FALSE);

	if ((err = zone_set_state(zonename, ZONE_STATE_INSTALLED)) != Z_OK) {
		errno = err;
		(void) fprintf(stderr, gettext("could not set state: %s\n"),
		    zonecfg_strerror(err));
		return (Z_ERR);
	}

	return (Z_OK);

fail:
	zarg.cmd = Z_UNMOUNT;
	if (zonecfg_call_zoneadmd(zonename, &zarg, locale, B_FALSE) != 0)
		(void) fprintf(stderr, gettext("could not unmount zone\n"));

	/* We reset the state since the zone wasn't modified yet. */
	if ((err = zone_set_state(zonename, ZONE_STATE_CONFIGURED))
	    != Z_OK) {
		errno = err;
		(void) fprintf(stderr, gettext("could not reset state: %s\n"),
		    zonecfg_strerror(err));
	}

	return (Z_ERR);
}

/* ARGSUSED */
static void
sigcleanup(int sig)
{
	attach_interupted = B_TRUE;
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
static int
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
static int
sw_up_to_date(zone_dochandle_t l_handle, zone_dochandle_t s_handle)
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

/*
 * During attach we go through and fix up the /dev entries for the zone
 * we are attaching.  In order to regenerate /dev with the correct devices,
 * the old /dev will be removed, the zone readied (which generates a new
 * /dev) then halted, then we use the info from the manifest to update
 * the modes, owners, etc. on the new /dev.
 */
static int
dev_fix(char *zonename, zone_dochandle_t handle)
{
	int			err;
	int			status;
	struct zone_devpermtab	devtab;
	zone_cmd_arg_t		zarg;
	char			devpath[MAXPATHLEN];
				/* 6: "exec " and " " */
	char			cmdbuf[sizeof (RMCOMMAND) + MAXPATHLEN + 6];

	if (snprintf(devpath, sizeof (devpath), "%s/dev", zonepath)
	    >= sizeof (devpath))
		return (Z_TOO_BIG);

	/*
	 * "exec" the command so that the returned status is that of
	 * RMCOMMAND and not the shell.
	 */
	(void) snprintf(cmdbuf, sizeof (cmdbuf), EXEC_PREFIX RMCOMMAND " %s",
	    devpath);
	status = do_subproc(cmdbuf);
	if ((err = subproc_status(RMCOMMAND, status, B_TRUE)) !=
	    ZONE_SUBPROC_OK) {
		(void) fprintf(stderr,
		    gettext("could not remove existing /dev\n"));
		return (Z_ERR);
	}

	/* In order to ready the zone, it must be in the installed state */
	if ((err = zone_set_state(zonename, ZONE_STATE_INSTALLED)) != Z_OK) {
		errno = err;
		zperror(gettext("could not reset state"), B_TRUE);
		return (Z_ERR);
	}

	/* We have to ready the zone to regen the dev tree */
	zarg.cmd = Z_READY;
	if (zonecfg_call_zoneadmd(zonename, &zarg, locale, B_FALSE) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		/* attempt to restore zone to configured state */
		(void) zone_set_state(zonename, ZONE_STATE_CONFIGURED);
		return (Z_ERR);
	}

	zarg.cmd = Z_HALT;
	if (zonecfg_call_zoneadmd(zonename, &zarg, locale, B_FALSE) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		/* attempt to restore zone to configured state */
		(void) zone_set_state(zonename, ZONE_STATE_CONFIGURED);
		return (Z_ERR);
	}

	/* attempt to restore zone to configured state */
	(void) zone_set_state(zonename, ZONE_STATE_CONFIGURED);

	if (zonecfg_setdevperment(handle) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate device entries\n"));
		return (Z_ERR);
	}

	while (zonecfg_getdevperment(handle, &devtab) == Z_OK) {
		int err;

		if ((err = zonecfg_devperms_apply(handle,
		    devtab.zone_devperm_name, devtab.zone_devperm_uid,
		    devtab.zone_devperm_gid, devtab.zone_devperm_mode,
		    devtab.zone_devperm_acl)) != Z_OK && err != Z_INVAL)
			(void) fprintf(stderr, gettext("error updating device "
			    "%s: %s\n"), devtab.zone_devperm_name,
			    zonecfg_strerror(err));

		free(devtab.zone_devperm_acl);
	}

	(void) zonecfg_enddevperment(handle);

	return (Z_OK);
}

static int
attach_func(int argc, char *argv[])
{
	int err, arg;
	zone_dochandle_t handle;
	zone_dochandle_t athandle = NULL;
	char brand[MAXNAMELEN], atbrand[MAXNAMELEN];
	boolean_t execute = B_TRUE;
	boolean_t retried = B_FALSE;
	boolean_t update = B_FALSE;
	char *manifest_path;

	opterr = 0;
	optind = 0;
	if ((arg = getopt(argc, argv, "?Fn:u")) != EOF) {
		switch (arg) {
		case '?':
			if (optopt != '?') {
				(void) fprintf(stderr, gettext("%s brand: "
				    "invalid option: %c\n"), MY_BRAND_NAME,
				    optopt);
			}
			(void) fprintf(stderr, gettext("usage:\t%s brand "
			    "options: [-u]\n"), MY_BRAND_NAME);
			(void) fprintf(stderr, gettext("\tSpecify "
			    "-u to update the zone to the current "
			    "system software.\n"));
			return (optopt == '?' ? Z_OK : ZONE_SUBPROC_USAGE);
		case 'n':
			execute = B_FALSE;
			manifest_path = optarg;
			break;
		case 'u':
			update = B_TRUE;
			break;
		default:
			(void) fprintf(stderr, gettext("%s brand: invalid "
			    "option: %c\n"), MY_BRAND_NAME, optopt);
			return (ZONE_SUBPROC_USAGE);
		}
	}

	/* dry-run and update flags are mutually exclusive */
	if (!execute && update) {
		(void) fprintf(stderr, gettext("-n and -u flags are mutually "
		    "exclusive\n"));
		return (ZONE_SUBPROC_USAGE);
	}

	/*
	 * If the no-execute option was specified, we need to branch down
	 * a completely different path since there is no zone required to be
	 * configured for this option.
	 */
	if (!execute)
		return (dryrun_attach(manifest_path));

	if ((handle = zonecfg_init_handle()) == NULL) {
		(void) fprintf(stderr, gettext("brand attach program error: "
		    "%s\n"), strerror(errno));
		return (ZONE_SUBPROC_NOTCOMPLETE);
	}

	if ((err = zonecfg_get_handle(zonename, handle)) != Z_OK) {
		(void) fprintf(stderr, gettext("brand attach program error: "
		    "%s\n"), zonecfg_strerror(err));
		zonecfg_fini_handle(handle);
		return (ZONE_SUBPROC_NOTCOMPLETE);
	}

	if ((athandle = zonecfg_init_handle()) == NULL) {
		(void) fprintf(stderr, gettext("brand attach program error: "
		    "%s\n"), strerror(errno));
		goto done;
	}

retry:
	if ((err = zonecfg_get_attach_handle(zonepath, zonename, B_TRUE,
	    athandle)) != Z_OK) {
		if (err == Z_NO_ZONE) {
			/*
			 * Zone was not detached.  Try to fall back to getting
			 * the needed information from within the zone.
			 */
			if (!retried) {
				(void) fprintf(stderr, gettext("The zone was "
				    "not properly detached.\n\tAttempting to "
				    "attach anyway.\n"));
				if (gen_detach_info()) {
					retried = B_TRUE;
					goto retry;
				}
			}
			(void) fprintf(stderr, gettext("Cannot generate the "
			    "information needed to attach this zone.\n"));
		} else if (err == Z_INVALID_DOCUMENT) {
			(void) fprintf(stderr, gettext("Cannot attach to an "
			    "earlier release of the operating system\n"));
		} else {
			(void) fprintf(stderr, gettext("brand attach program "
			    "error: %s\n"), zonecfg_strerror(err));
		}
		goto done;
	}

	/* Get the detach information for the locally defined zone. */
	if ((err = get_detach_info(handle, B_FALSE)) != Z_OK) {
		(void) fprintf(stderr, gettext("getting the attach information "
		    "failed: %s\n"), zonecfg_strerror(err));
		goto done;
	}

	/*
	 * Ensure that the detached and locally defined zones are both of
	 * the same brand.
	 */
	if ((zonecfg_get_brand(handle, brand, sizeof (brand)) != 0) ||
	    (zonecfg_get_brand(athandle, atbrand, sizeof (atbrand)) != 0)) {
		err = Z_ERR;
		(void) fprintf(stderr, gettext("missing or invalid brand\n"));
		goto done;
	}

	if (strcmp(atbrand, brand) != 0) {
		err = Z_ERR;
		(void) fprintf(stderr, gettext("Trying to attach a '%s' zone "
		    "to a '%s' configuration.\n"), atbrand, brand);
		goto done;
	}

	/*
	 * If we're doing an update on attach, and the zone does need to be
	 * updated, then run the update.
	 */
	if (update) {
		char fname[MAXPATHLEN];

		(void) sigset(SIGINT, sigcleanup);

		if ((err = sw_up_to_date(handle, athandle)) != Z_OK) {
			if (err != Z_FATAL && !attach_interupted) {
				err = Z_FATAL;
				err = attach_update(handle);
			}
			if (!attach_interupted || err == Z_OK)
				goto done;
		}

		(void) sigset(SIGINT, SIG_DFL);

		/* clean up data files left behind by sw_up_to_date() */
		(void) snprintf(fname, sizeof (fname), "%s/pkg_add", zonepath);
		(void) unlink(fname);
		(void) snprintf(fname, sizeof (fname), "%s/pkg_rm", zonepath);
		(void) unlink(fname);

		if (attach_interupted) {
			err = Z_FATAL;
			goto done;
		}

	} else {
		/* sw_cmp prints error msgs as necessary */
		if ((err = sw_cmp(handle, athandle, SW_CMP_NONE)) != Z_OK)
			goto done;

		if ((err = dev_fix(zonename, athandle)) != Z_OK)
			goto done;
	}

	if ((err = zone_set_state(zonename, ZONE_STATE_INSTALLED)) != Z_OK) {
		(void) fprintf(stderr, gettext("could not reset state: %s\n"),
		    zonecfg_strerror(err));
	}

done:
	zonecfg_fini_handle(handle);
	if (athandle != NULL)
		zonecfg_fini_handle(athandle);

	return ((err == Z_OK) ? Z_OK : ZONE_SUBPROC_FATAL);
}

static int
install_func(int argc, char *argv[])
{
	char cmdbuf[MAXPATHLEN];
	int arg;
	int status;

	opterr = 0;
	optind = 0;
	while ((arg = getopt(argc, argv, "?x:")) != EOF) {
		switch (arg) {
		case '?':
			if (optopt != '?') {
				(void) fprintf(stderr, gettext("%s brand: "
				    "invalid option: %c\n"), MY_BRAND_NAME,
				    optopt);
			}
			(void) fprintf(stderr, gettext("usage:\t%s brand "
			    "options: none\n"), MY_BRAND_NAME);
			return (optopt == '?' ? Z_OK : ZONE_SUBPROC_USAGE);
		case 'x':
			if (strcmp(optarg, "nodataset") != 0) {
				(void) fprintf(stderr, gettext("%s brand: "
				    "invalid option: %c\n"), MY_BRAND_NAME,
				    arg);
				return (ZONE_SUBPROC_USAGE);
			}
			/* Ignore option, handled in zoneadm. */
			break;
		default:
			(void) fprintf(stderr, gettext("%s brand: invalid "
			    "option: %c\n"), MY_BRAND_NAME, optopt);
			return (ZONE_SUBPROC_USAGE);
		}
	}

	if (snprintf(cmdbuf, sizeof (cmdbuf), "/usr/lib/lu/lucreatezone -z %s",
	    zonename) >= sizeof (cmdbuf))
		return (Z_ERR);

	/*
	 * According to the Application Packaging Developer's Guide, a
	 * "checkinstall" script when included in a package is executed as
	 * the user "install", if such a user exists, or by the user
	 * "nobody".  In order to support this dubious behavior, the path
	 * to the zone being constructed is opened up during the life of
	 * the command laying down the zone's root file system.  Once this
	 * has completed, regardless of whether it was successful, the
	 * path to the zone is again restricted.
	 */
	if (chmod(zonepath, DEFAULT_DIR_MODE) != 0) {
		zperror(zonepath, B_FALSE);
		return (Z_ERR);
	}

	status = do_subproc(cmdbuf);

	if (chmod(zonepath, S_IRWXU) != 0) {
		zperror(zonepath, B_FALSE);
		return (Z_ERR);
	}

	if (subproc_status("install", status, B_FALSE) != ZONE_SUBPROC_OK)
		return (Z_ERR);

	return (Z_OK);
}

/* ARGSUSED */
static int
postclone_func(int argc, char *argv[])
{
	int		status;
	boolean_t	res = B_TRUE;
	struct stat	sbuf;
	char		cmdbuf[2 * MAXPATHLEN];

	/* Ignore any arguments. */

	/*
	 * Trusted Extensions requires that cloned zones use the same sysid
	 * configuration, so it is not appropriate to perform any
	 * post-clone reconfiguration.
	 */
	if (is_system_labeled())
		return (ZONE_SUBPROC_OK);

	/* If the zone is already sys-unconfiged, then we're done. */
	if (snprintf(cmdbuf, sizeof (cmdbuf), "%s/root/etc/.UNCONFIGURED",
	    zonepath) >= sizeof (cmdbuf))
		return (ZONE_SUBPROC_FATAL);

	if (stat(cmdbuf, &sbuf) == 0 && S_ISREG(sbuf.st_mode))
		return (ZONE_SUBPROC_OK);

	/*
	 * Mount the zone.  The zone is still in the INCOMPLETE state, so we
	 * have to force mount it.
	 */
	if (mount_func(B_TRUE) != Z_OK)
		return (ZONE_SUBPROC_FATAL);

	/* sys-unconfig the zone */
	if (snprintf(cmdbuf, sizeof (cmdbuf), "/usr/sbin/zlogin -S %s "
	    "'/usr/sbin/sys-unconfig -R /a'", zonename) >= sizeof (cmdbuf)) {
		res = B_FALSE;
	} else {
		status = do_subproc(cmdbuf);
		if (subproc_status("sys-unconfig failed", status, B_TRUE)
		    != ZONE_SUBPROC_OK)
			res = B_FALSE;
	}

	if (unmount_func() != Z_OK)
		res =  B_FALSE;

	return (res ? ZONE_SUBPROC_OK : ZONE_SUBPROC_FATAL);
}

/*
 * Perform any necessary housekeeping tasks we need to do before we take
 * a ZFS snapshot of the zone.  What this really entails is that we are
 * taking a sw inventory of the source zone, like we do when we detach,
 * so that there is the XML manifest in the snapshot.  We use that to
 * validate the snapshot if it is the source of a clone at some later time.
 */
static int
presnap_func(int argc, char *argv[])
{
	int err;
	zone_dochandle_t handle;

	opterr = 0;
	optind = 0;
	if (getopt(argc, argv, "") != EOF)
		return (ZONE_SUBPROC_USAGE);

	if ((handle = zonecfg_init_handle()) == NULL) {
		(void) fprintf(stderr, gettext("brand pre-snapshot program "
		    "error: %s\n"), strerror(errno));
		return (Z_ERR);
	}

	if ((err = zonecfg_get_handle(zonename, handle)) != Z_OK) {
		(void) fprintf(stderr, gettext("brand pre-snapshot program "
		    "error: %s\n"), zonecfg_strerror(err));
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	if ((err = get_detach_info(handle, B_TRUE)) != Z_OK) {
		(void) fprintf(stderr, gettext("brand pre-snapshot program "
		    "error: %s\n"), zonecfg_strerror(err));
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	if ((err = zonecfg_detach_save(handle, 0)) != Z_OK) {
		(void) fprintf(stderr, gettext("saving the detach manifest "
		    "failed: %s\n"), zonecfg_strerror(err));
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	zonecfg_fini_handle(handle);

	return (Z_OK);
}

/*
 * Perform any necessary housekeeping tasks we need to do after we take
 * a ZFS snapshot of the zone.  What this really entails is removing the
 * sw inventory XML file from the zone.  It is still in the snapshot where
 * we want it, but we don't want it in the source zone itself.
 */
static int
postsnap_func(int argc, char *argv[])
{
	int err;
	zone_dochandle_t handle;

	opterr = 0;
	optind = 0;
	if (getopt(argc, argv, "") != EOF)
		return (ZONE_SUBPROC_USAGE);

	if ((handle = zonecfg_init_handle()) == NULL) {
		(void) fprintf(stderr, gettext("brand post-snapshot program "
		    "error: %s\n"), strerror(errno));
		return (Z_ERR);
	}

	if ((err = zonecfg_get_handle(zonename, handle)) != Z_OK) {
		(void) fprintf(stderr, gettext("brand post-snapshot program "
		    "error: %s\n"), zonecfg_strerror(err));
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	zonecfg_rm_detached(handle, B_FALSE);
	zonecfg_fini_handle(handle);

	return (Z_OK);
}

/*
 * We are using an explicit snapshot from some earlier point in time so
 * we need to validate it.  This involves checking the sw inventory that
 * we took when we made the snapshot to verify that the current sw config
 * on the host is still valid to run a zone made from this snapshot.
 */
static int
validatesnap_func(int argc, char *argv[])
{
	int err;
	zone_dochandle_t handle;
	zone_dochandle_t athandle = NULL;
	char *snapshot_name;
	char *snap_path;

	opterr = 0;
	optind = 0;
	if (getopt(argc, argv, "") != EOF)
		return (ZONE_SUBPROC_USAGE);

	if (argc < 2)
		return (ZONE_SUBPROC_USAGE);

	snapshot_name = argv[0];
	snap_path = argv[1];

	if ((handle = zonecfg_init_handle()) == NULL) {
		(void) fprintf(stderr, gettext("brand validate-snapshot "
		    "program error: %s\n"), strerror(errno));
		return (Z_ERR);
	}

	if ((err = zonecfg_get_handle(zonename, handle)) != Z_OK) {
		(void) fprintf(stderr, gettext("brand validate-snapshot "
		    "program error: %s\n"), zonecfg_strerror(err));
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	if ((athandle = zonecfg_init_handle()) == NULL) {
		(void) fprintf(stderr, gettext("brand validate-snapshot "
		    "program error: %s\n"), strerror(errno));
		goto done;
	}

	if ((err = zonecfg_get_attach_handle(snap_path, zonename, B_TRUE,
	    athandle)) != Z_OK) {
		if (err == Z_NO_ZONE)
			(void) fprintf(stderr, gettext("snapshot %s was not "
			    "taken\n\tby a 'zoneadm clone' command.  It can "
			    "not be used to clone zones.\n"), snapshot_name);
		else
			(void) fprintf(stderr, gettext("snapshot %s is "
			    "out-dated\n\tIt can no longer be used to clone "
			    "zones on this system.\n"), snapshot_name);
		goto done;
	}

	/* Get the detach information for the locally defined zone. */
	if ((err = get_detach_info(handle, B_FALSE)) != Z_OK) {
		errno = err;
		zperror(gettext("getting the attach information failed"),
		    B_TRUE);
		goto done;
	}

	if ((err = sw_cmp(handle, athandle, SW_CMP_SILENT)) != Z_OK)
		(void) fprintf(stderr, gettext("snapshot %s is out-dated\n\t"
		    "It can no longer be used to clone zones on this "
		    "system.\n"), snapshot_name);

done:
	zonecfg_fini_handle(handle);
	if (athandle != NULL)
		zonecfg_fini_handle(athandle);

	return ((err == Z_OK) ? Z_OK : ZONE_SUBPROC_FATAL);
}

static void
usage()
{
	(void) fprintf(stderr, gettext("sw_support invalid arguments\n"));
	exit(253);
}

int
main(int argc, char **argv)
{
	int err = ZONE_SUBPROC_FATAL;
	char *cmd = NULL;

	if ((locale = setlocale(LC_ALL, "")) == NULL)
		locale = "C";
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 4)
		usage();

	cmd = argv[1];
	zonename = argv[2];
	zonepath = argv[3];

	argc -= 4;
	argv = &argv[4];

	if (strcmp(cmd, "attach") == 0)
		err = attach_func(argc, argv);
	else if (strcmp(cmd, "detach") == 0)
		err = detach_func(argc, argv);
	else if (strcmp(cmd, "install") == 0)
		err = install_func(argc, argv);
	else if (strcmp(cmd, "postclone") == 0)
		err = postclone_func(argc, argv);
	else if (strcmp(cmd, "presnap") == 0)
		err = presnap_func(argc, argv);
	else if (strcmp(cmd, "postsnap") == 0)
		err = postsnap_func(argc, argv);
	else if (strcmp(cmd, "validatesnap") == 0)
		err = validatesnap_func(argc, argv);

	return (err);
}
