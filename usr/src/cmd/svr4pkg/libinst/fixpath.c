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
 * This module contains all the code necessary to establish the key base
 * directories to which the actual components of the package will be
 * installed or removed. -- JST
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>	/* mkdir() declaration */
#include <libintl.h>
#include <pkglib.h>
#include <install.h>
#include <libadm.h>
#include <libinst.h>

static char *install_root = NULL;
static int install_root_exists = 0;	/* An install root was specified */
static int install_root_len;		/* strlen(install_root) */
static char *orig_basedir = NULL;	/* The unadjusted basedir */
static char *basedir = NULL;		/* basedir (cmb w/ inst rt if req) */
static int basedir_exists = 0;		/* There are relocatable paths */
static char *client_basedir = NULL;
static int client_basedir_exists = 0;	/* Installing from a host */
static char *env_cl_bdir = NULL;	/* CLIENT_BASEDIR from environment */
static int ir_accessed = 0;		/* install_root has been used */
static int relocatable;			/* set_basedir() assumed this */
static int partial_inst = 0; /* Installing pkg from partial spool directory */
static boolean_t depend_pkginfo_DB = B_FALSE; /* Only update depend/pkginfoDB */
static int partial_spool_create = 0; /* Create partial spool dir */

static int	ask_basedir(char *path, int nointeract);
static char	*expand_path(char *path);
static int	set_client_basedir(void);
static char 	*fixpath_dup(char *path);
static int	orig_offset_rel;

/*
 * base_sepr and rel_fmt support construction of absolute paths from
 * relative paths.
 */
static int	base_sepr = 1;	/* separator length btwn basedir & path */
static char	*rel_fmt[] = { "%s%s", "%s/%s" };

static int	eval_valid = 0;	/* everything set up to do an eval_path() */

/* libpkg/gpkgmap.c */
extern int	getmapmode();

#define	MSG_IR_REPL	"Replacing current install root with %s."
#define	ERR_IRSET	"Install_root has already been set to <%s> and used."
#define	ERR_IRNOTABS	"Install_root (-R option) requires an absolute " \
			"pathname: <%s>"
#define	ERR_ALLOCFAILED	"insufficient memory in %s"
#define	ERR_ADMIN_INVAL	"Invalid basedir entry in admin file."
#define	ERR_PATHNAME 	"Path name is invalid"
#define	ERR_RELINABS	"Relative path <%s> found in absolute package."
#define	ERR_CL_MIS	"Constructed CLIENT_BASEDIR <%s> and " \
			"environment CLIENT_BASEDIR <%s> do not match."
#define	ERR_ASKBD	"%s is already installed at %s. Cannot create a " \
			    "duplicate installation at %s."
#define	ERR_NO_CL_BD	"Cannot resolve CLIENT_BASEDIR conflicts."
#define	ERR_AMBDIRS	"Cannot evaluate path due to ambiguous " \
			"base directories."
#define	ERR_NODELETE	"unable to delete <%s>."
#define	ERR_MKBASE	"unable to make directory <%s>."
#define	MSG_REQBASEDIR	"Installation of this package requires a base " \
			"directory."

#define	MSG_MUSTEXIST	"\\nThe selected base directory <%s> must exist " \
			"before installation is attempted."
#define	MSG_YORNPRMPT	"Do you want this directory created now"

#define	MSG_ISAFILE	"\\nThe selected base directory <%s> must exist " \
			"before installation is attempted, but a file " \
			"already exists in it's place."
#define	MSG_YORNFILE	"Do you want the file deleted and the directory " \
			"created now"

#define	MSG_PROMPT	"Enter path to package base directory"

#define	MSG_HELP	"Installation of this package requires that a UNIX " \
			"directory be available for installation of " \
			"appropriate software.  This directory may be part " \
			"of any mounted filesystem, or may itself be a " \
			"mount point.  In general, it is unwise to select a " \
			"base directory which already contains other files " \
			"and/or directories."

/*
 * Set the install root (-R option).
 */

int
set_inst_root(char *path)
{
	static	char	tmp_path[PATH_MAX];

	/*
	 * If we've already set the install_root but no one has used it
	 * yet, we'll complain and allow the change. If it's been used
	 * then we'll deny the switch & return failed.
	 */
	if (install_root_exists)
		/* If the two install_roots are different - problem */
		if (strcmp(install_root, path))
			/* We are trying to *change* the install_root */
			if (ir_accessed) {
				ptext(stderr, gettext(ERR_IRSET), path);
				return (0);
			} else { /* !ir_accessed */
				ptext(stderr, gettext(MSG_IR_REPL), path);
				install_root_exists = 0;	/* reset */
				install_root = NULL;
			}

	if (path && *path) {
		if (*path != '/') {
			ptext(stderr, gettext(ERR_IRNOTABS), path);
			return (0);
		}

		(void) strlcpy(tmp_path, path, sizeof (tmp_path));

		canonize(tmp_path);

		install_root = tmp_path;

		install_root_exists = 1;

		install_root_len = strlen(install_root);

		/* If install_root is '/' then it's trivial. */
		if (install_root_len == 1)
			install_root_len = 0;
		else
			z_set_zone_root(install_root);
	} else
		install_root_exists = 0;

	return (1);
}

/*
 * This routine returns a path with the correct install_root prepended.
 * if the install_root has been set. NOTE : this allocates memory
 * which will need to be freed at some point.
 */
char *
fixpath(char *path)
{
	register char *npath_ptr, *ir_ptr;
	char *npath = NULL;

	if (path && *path) {
		if (install_root_exists) {
			if ((npath =
			    calloc(1, strlen(path) + install_root_len +
			    1)) == NULL) {
				progerr(gettext(ERR_ALLOCFAILED), "fixpath()");
				quit(99);
			}

			npath_ptr = npath;
			ir_ptr = get_inst_root();

			while (*ir_ptr)	/* for every char in install_root */
				*npath_ptr++ = *ir_ptr++;	/* copy it */

			/*
			 * If install_root == "/", a concatenation will
			 * result in a return value of "//...", same goes
			 * for an install_root ending in '/'. So we back
			 * over a trailing '/' if it's there.
			 */
			if (*(npath_ptr - 1) == '/')
				npath_ptr--;

			if (strcmp(path, "/"))
				(void) strcpy(npath_ptr, path);
		} else
			/*
			 * If there's no install root & no client_basedir,
			 * then return the path
			 */
			npath = strdup(path);
	} else
		/*
		 * If there's no path specified, return the install root
		 * since no matter what happens, this is where the
		 * path will have to start.
		 */
		if (install_root_exists)
			npath = strdup(get_inst_root());

	return (npath);
}

/*
 * This routine does what fixpath() does except it's for high-volume
 * stuff restricted to the instvol() function. By using
 * pathdup() and pathalloc() memory fragmentation is reduced. Also, the
 * memory allocated by pathdup() and pathalloc() gets freed at the end
 * of each volume installed.
 */
char *
fixpath_dup(char *path)
{
	register char *npath_ptr, *ir_ptr;
	char *npath = NULL;

	if (path && *path) {
		if (install_root_exists) {
			npath = pathalloc(strlen(path) + install_root_len + 1);

			npath_ptr = npath;
			ir_ptr = get_inst_root();

			while (*ir_ptr)	/* for every char in install_root */
				*npath_ptr++ = *ir_ptr++;	/* copy it */

			/*
			 * If install_root == "/", a concatenation will
			 * result in a return value of "//...", same goes
			 * for an install_root ending in '/'. So we back
			 * over a trailing '/' if it's there.
			 */
			if (*(npath_ptr - 1) == '/')
				npath_ptr--;

			if (strcmp(path, "/"))
				(void) strcpy(npath_ptr, path);
		} else
			/*
			 * If there's no install root & no client_basedir,
			 * then return the path
			 */
			npath = pathdup(path);
	} else
		/*
		 * If there's no path specified, return the install root
		 * since no matter what happens, this is where the
		 * path will have to start.
		 */
		if (install_root_exists)
			npath = pathdup(get_inst_root());

	return (npath);
}

/*
 * This returns a pointer to a static name. This could be abused.
 * -- JST (1993-07-21)
 */
char *
get_inst_root(void)
{
	ir_accessed = 1;	/* we can't change it now */
	return (install_root);
}

/*
 * This routine takes path and removes install_root from the path
 * if it has already been prepended. If install_root is not prepended to
 * path or install_root is '/' or path == NULL then path is returned
 * as is. If the resulting path is somehow relative, a corrupt
 * package name error is raised and the program quits. NOTE : This
 * function usually returns a pointer into the original path
 * argument. It doesn't allocate new memory. This is possible,
 * of course, because the path being returned is guaranteed to
 * be a subset of the original argument unless basedir = '/' in
 * which case a pointer to a static "/" is returned. See
 * orig_path() below if you want to be handed a new copy of the
 * return value.
 */
char *
orig_path_ptr(char *path)
{
	char *retv = NULL;

	if (path && *path) {	/* as long as we got an argument */
		if (!install_root_exists)	/* if no install_root */
			retv = path;		/*   path unchanged */

		/*
		 * Otherwise, if install_root is really prepended to the path
		 * then remove it dealing appropriately with special cases.
		 */
		else if (strncmp(path, install_root, install_root_len) == 0) {
			retv = path + install_root_len;
			if (*retv == '\0')
				retv = "/";

			/*
			 * The result will be relative if install_root = '/'.
			 * If the basedir path was built legally, then moving
			 * the pointer back one character will make it
			 * absolute. If that fails then the path we got was
			 * incorrectly constructed in the first place.
			 */
			else if (*retv != '/') {
				retv--;
				if (*retv != '/') {
					progerr(gettext(ERR_PATHNAME));
					quit(99);
				}
			}
		} else
			retv = path;	/* All else failing, return path. */

		canonize(retv);
	}

	return (retv);
}

/*
 * This function does the same as orig_path_ptr() except that it mallocs
 * new space and provides a new copy of the original basedir path which
 * needs to be free()'d one way or another later.
 */
char *
orig_path(char *path)
{
	char *retv;

	retv = orig_path_ptr(path);

	return ((retv == NULL) ? retv : strdup(retv));
}

/*
 * This function lets us hold onto the environment's version of
 * CLIENT_BASEDIR for later review by set_client_basedir().
 */
void
set_env_cbdir()
{
	register char *cb_ptr;

	cb_ptr = getenv("CLIENT_BASEDIR");

	if (cb_ptr && *cb_ptr) {
		env_cl_bdir = strdup(cb_ptr);
		canonize(env_cl_bdir);
	}
}

/* ask for the basedir */
static int
ask_basedir(char *path, int nointeract)
{
	int n;

	if (nointeract) {
		progerr(gettext(MSG_REQBASEDIR));
		return (5);
	} else {
		path[0] = '\0';
		if (n = ckpath(path, P_ABSOLUTE|P_DIR|P_WRITE,
		    basedir, NULL, gettext(MSG_HELP),
		    gettext(MSG_PROMPT)))
			return (n);	/* FAIL */
		orig_basedir =
		    expand_path(path);
	}
	return (0);
}

/*
 * Set the basedir and client_basedir based on install root and config
 * files. It returns 0 if all OK otherwise returns the error code base
 * appropriate to the problem.
 */
int
set_basedirs(int reloc, char *adm_basedir, char *pkginst, int nointeract)
{
	char	path[PATH_MAX];
	int	n;

	relocatable = reloc;

	/*
	 * If there are no relocatable files basedir is probably meaningless
	 * so we skip ahead to the simple tests. Otherwise we do the twisted
	 * stuff below. The BASEDIR is set based on the following heirarchy :
	 *	1. The entry in the admin file
	 *	2. The entry in the pkginfo file delivered on the medium
	 *	3. The entry in the already installed pkginfo file
	 *	4. ask
	 * If it's not a relocatable package, we go with whatever seems
	 * reasonable; if it's relocatable and we've exhausted our
	 * options, we ask.
	 */
	if (reloc) {
		int is_adm_basedir = (adm_basedir && *adm_basedir);
		int is_update = 0;
		int is_ask = 0;

		if (is_adm_basedir) {
			if (strcmp(adm_basedir, "update") == 0) {
				is_update = 1;
				is_ask = 1;
			} else if (strcmp(adm_basedir, "ask") == 0)
				is_ask = 1;
		}

		/*
		 * If there's a BASEDIR in the admin file & it's a valid
		 * absolute pathname, use it.
		 */
		if (is_adm_basedir && strchr("/$", *adm_basedir))
			orig_basedir = expand_path(adm_basedir);

		/* If admin says 'ask regardless', ask and continue */
		else if (is_adm_basedir && is_ask) {
			if (n = ask_basedir(path, nointeract))
				return (n);
			if (is_update &&
			    strcmp(orig_basedir,
			    (basedir = getenv("BASEDIR"))) != 0) {
				progerr(gettext(ERR_ASKBD),
				    getenv("PKG"), basedir, orig_basedir);
				quit(4);
			}
		}
		/*
		 * If it isn't the only other valid option,
		 * namely 'default', quit FAIL.
		 */
		else if (is_adm_basedir &&
		    strcmp(adm_basedir, "default") != 0) {
			progerr(gettext(ERR_ADMIN_INVAL));
			return (1);

		/*
		 * OK, the admin file has no preference, so we go to the
		 * other sources.
		 */
		} else {
			/*
			 * Check to see if BASEDIR is set in the environment
			 * (probably from the pkginfo file on the installation
			 * medium).
			 */
			basedir = getenv("BASEDIR");
			if (basedir && *basedir)
				orig_basedir = expand_path(basedir);
			else {
				/*
				 * Check to see if the package BASEDIR was
				 * already defined during a previous
				 * installation of this package instance. The
				 * function below looks for an installed
				 * pkginfo file and scans it.
				 */
				basedir = pkgparam(pkginst, "BASEDIR");
				if (basedir && *basedir)
					orig_basedir = expand_path(basedir);
				else if (n = ask_basedir(path, nointeract))
					return (n);
			}
		}
	} else {	/* not relocatable */
		/*
		 * Since all paths are absolute the only reason to have a
		 * basedir is if there's an install root meaning there's
		 * really a basedir relative to this host or this package is
		 * absolute only because it's sparse in which case we're
		 * interested in the prior basedir. So we next check for a
		 * prior basedir and then an install root.
		 */
		basedir = pkgparam(pkginst, "BASEDIR");
		if (basedir && *basedir)
			orig_basedir = expand_path(basedir);

		else if (install_root_exists)
			/*
			 * If we have a basedir *only because*
			 * we have an install_root, we need to
			 * set orig_basedir to '/' to simplify
			 * later attempts to force
			 * client_basedir.
			 */
			orig_basedir = "/";
		else {
			eval_valid++;	/* we can run eval_path() now */
			return (0);	/* fixpath below unnecessary */
		}
	}

	basedir_exists = 1;

	basedir = fixpath(orig_basedir);

	/*
	 * If basedir == "/" then there's no need for a "/" between
	 * it and the rest of the path.
	 */
	if (strcmp(basedir, "/") == 0)
		base_sepr = 0;

	if (set_client_basedir() == 0) {
		progerr(gettext(ERR_NO_CL_BD));
		return (1);
	}

	eval_valid++;	/* we've confirmed the validity of everything */

	return (0);
}

/*
 * Make a directory from a path and all necessary directories above it as
 * needed.
 */
int
mkpath(char *p)
{
	char	*pt;

	/* if entire path exists, return o.k. */

	if (access(p, F_OK) == 0) {
		return (0);
	}

	/* entire path not there - check components and create */

	pt = (*p == '/') ? p+1 : p;
	do {
		if (pt = strchr(pt, '/')) {
			*pt = '\0';
		}
		if ((access(p, F_OK) != 0) && (mkdir(p, 0755) != 0)) {
			return (-1);
		}
		if (pt) {
			*pt++ = '/';
		}
	} while (pt);

	return (0);
}

/* This makes the required base directory if necessary */
void
mkbasedir(int flag, char *basedir)
{
	char	ans[MAX_INPUT];
	int	n;

	/*
	 * If a base directory is called for but there's no such directory on
	 * the system, deal with that issue.
	 */
	if (is_a_basedir() && isdir(basedir)) {
		if (flag) {	/* Interaction is OK. */
			/*
			 * If there's a non-directory object in the way, ask.
			 */
			if (access(basedir, F_OK) == 0) {
				ptext(stderr, gettext(MSG_ISAFILE), basedir);

				if (n = ckyorn(ans, NULL, NULL, NULL,
				    gettext(MSG_YORNFILE)))
					quit(n);
				if (strchr("yY", *ans) == NULL)
					quit(3);

				/*
				 * It isn't a directory, so we'll just unlink
				 * it.
				 */
				if (unlink(basedir) == -1) {
					progerr(gettext(ERR_NODELETE),
					    basedir);
					quit(99);
				}

			} else {
				ptext(stderr, gettext(MSG_MUSTEXIST), basedir);

				if (n = ckyorn(ans, NULL, NULL, NULL,
				    gettext(MSG_YORNPRMPT)))
					quit(n);
				if (strchr("yY", *ans) == NULL)
					quit(3);
			}
		}

		if (access(basedir, F_OK) == 0 || mkpath(basedir)) {
			progerr(gettext(ERR_MKBASE), basedir);
			quit(99);
		}
	}
}

/*
 * Create a client_basedir if it is appropriate. If all goes well, resulting
 * in either a valid client_basedir or a valid lack thereof, it returns 1.
 * If there is an irreconcileable conflict, it returns 0.
 */
static int
set_client_basedir(void)
{
	if (install_root_exists) {
		if (basedir_exists)
			client_basedir = strdup(orig_basedir);
		else
			client_basedir = "/";
		client_basedir_exists = 1;
	}

	/*
	 * In response to an agreement associated with bug report #1133956,
	 * CLIENT_BASEDIR will be defined in all cases where BASEDIR is
	 * defined until the on1094 release. For on1094 delete the else if
	 * and associated expressions below. -- JST (6/25/1993)
	 */
	else if (basedir_exists) {
		client_basedir = strdup(basedir);
		client_basedir_exists = 1;
	}

	/*
	 * At this point we may or may not have a client_basedir defined. Now
	 * we need to check for one in the environment & make sure it syncs
	 * up with prior findings. If there's no other client_basedir defined,
	 * the environment defines it.
	 */
	if (env_cl_bdir && *env_cl_bdir) {
		if (client_basedir_exists) {
			/* If the two client basedirs mismatch, return fail */
			if (strcmp(client_basedir, env_cl_bdir)) {
				ptext(stderr, gettext(ERR_CL_MIS),
				    client_basedir, env_cl_bdir);
				return (0);
			}
		} else {
			client_basedir = env_cl_bdir;
			client_basedir_exists = 1;
		}
	}

	return (1);
}

static char *
expand_path(char *path)
{
	char	path_buf[PATH_MAX];

	if (!path || !*path)
		return (path);

	(void) strlcpy(path_buf, path, sizeof (path_buf));
	mappath(getmapmode(), path_buf);
	canonize(path_buf);

	return (qstrdup(path_buf));
}

char *
get_basedir(void)
{
	return (basedir);
}

char *
get_client_basedir(void)
{
	return (client_basedir);
}

/*
 * This function returns the basedir that is appropriate for this package's
 * pkginfo file.
 */
char *
get_info_basedir(void)
{
	if (install_root_exists)
		return (client_basedir);
	else if (basedir_exists)
		return (basedir);
	else
		return (NULL);
}

int
is_an_inst_root(void)
{
	return (install_root_exists);
}

int
is_a_basedir(void)
{
	return (basedir_exists);
}

int
is_relocatable(void)
{
	return (relocatable);
}

int
is_a_cl_basedir(void)
{
	return (client_basedir_exists);
}

/*
 * Since calls to putparam() become valid long after much of the above
 * code has run, this routine allows the insertion of these key
 * environment variables without passing a bunch of pointers.
 */
void
put_path_params(void)
{
	if (install_root_exists)
		putparam("PKG_INSTALL_ROOT", get_inst_root());

	if (basedir_exists)
		putparam("BASEDIR", basedir);

	if (client_basedir_exists)
		putparam("CLIENT_BASEDIR", client_basedir);
}

/*
 * This fills three pointers and a buffer which contains the longest
 * possible path (with install_root and basedir prepended. The pointers
 * are to the subpaths within the string. This was added so that the
 * eptlist could be produced with all relevant paths defined without
 * repeated calls and string scans. For example, given a path of
 * haberdasher/crute we may return
 *
 *	server_ptr -----> /export/root/client1/opt/SUNWhab/haberdasher/crute
 *                                            |            |
 *	client_ptr ---------------------------             |
 *	map_ptr -------------------------------------------
 *
 * We construct the new path based upon the established environment
 * and the type of path that was passed. Here are the possibilities:
 *
 *   |					| relative path	| absolute path	|
 *   |	--------------------------------|---------------|---------------|
 *   |	is_an_inst_root			|	1	|	2	|
 *   V	! an_inst_root && is_a_basedir	|	1	|	3	|
 *	! an_inst_root && ! a_basedir	|	X	|	3	|
 *
 * METHOD
 * 1. Prepend the basedir to the path (the basedir is guaranteed to exist
 *	whenever there's an install_root).
 *
 * 2. Prepend the install_root (not the basedir) to the path
 *
 * 3. Return the path as unchanged.
 *
 * X. THIS CAN'T HAPPEN
 */
int
eval_path(char **server_ptr, char **client_ptr, char **map_ptr, char *path)
{
	static int client_offset;
	static int offsets_valid, retcode;
	int path_size;

	if (!offsets_valid) {
		/*
		 * This is the offset from the beginning of the evaluated
		 * path to the start of the relative path. Note that we
		 * are accounting for the '/' inserted between the
		 * basedir and the path with the '+ 1'. If there is a
		 * relative path, then there is always a basedir. The
		 * only way this will come up '0' is if this is an
		 * absolute package.
		 */
		orig_offset_rel = (is_a_basedir()) ? (strlen(basedir) +
		    base_sepr) : 0;

		/*
		 * This is the position of the client-relative path
		 * in that it points to the '/' beginning the base
		 * directory or the absolute path. Once the basedir has
		 * been afixed, the path is absolute. For that reason,
		 * the client path is the same thing as the original path
		 * if it were absolute.
		 */
		client_offset = (is_an_inst_root()) ? install_root_len : 0;

		offsets_valid = 1;
	}

	/*
	 * If we've evaluated the base directory and come up trumps,
	 * then we can procede with this operation, otherwise, the
	 * available data is too ambiguous to resolve the issue.
	 */
	if (eval_valid) {
		if (RELATIVE(path)) {
			if (relocatable) {
				/*
				 * Figure out how long our buffer will
				 * have to be.
				 */
				path_size = orig_offset_rel + strlen(path);

				(*server_ptr) = pathalloc(path_size);

				*client_ptr = *server_ptr + client_offset;

				if (map_ptr)
					*map_ptr = *server_ptr +
					    orig_offset_rel;

				/* LINTED warning: variable format specifier */
				(void) snprintf(*server_ptr, path_size+1,
					rel_fmt[base_sepr], basedir, path);
			} else {
				ptext(stderr, gettext(ERR_RELINABS), path);
				retcode = 0;
			}
		} else {	/* NOT RELATIVE */
			*server_ptr = fixpath_dup(path);

			if ((*client_ptr = *server_ptr + client_offset) == NULL)
				*client_ptr = "/";

			if (map_ptr)
				*map_ptr = *client_ptr;
		}

		retcode = 1;
	} else {
		ptext(stderr, gettext(ERR_AMBDIRS));
		retcode = 0;
	}

	return (retcode);
}

void
export_client_env(char *root_path)
{
	char	*inst_release_path;
	char	*key;
	char	*value;
	FILE	*inst_fp;
	size_t	len;

	/*
	 * Put the variables found in a clients INST_RELEASE file into the
	 * package environment so procedure scripts can know what
	 * release/version/revision a client is running. Also this function
	 * doesn't return state since the INST_RELEASE file may not exist in
	 * some package installation environments
	 */

	len = strlen(root_path) + strlen(INST_RELEASE) + 2;

	inst_release_path = (char *)malloc(len);

	key = (char *)malloc(PATH_MAX);

	(void) snprintf(inst_release_path, len, "%s/%s", root_path,
				INST_RELEASE);

	if ((inst_fp = fopen(inst_release_path, "r")) != NULL) {
		while (value = fpkgparam(inst_fp, key)) {
			if (strcmp(key, "OS") == 0) {
				putparam("PKG_CLIENT_OS", value);
			} else if (strcmp(key, "VERSION") == 0) {
				putparam("PKG_CLIENT_VERSION", value);
			} else if (strcmp(key, "REV") == 0) {
				putparam("PKG_CLIENT_REVISION", value);
			}
			*key = '\0';
		}
		(void) fclose(inst_fp);
	}
	free(inst_release_path);
	free(key);
}

/*
 * Increment variable indicating the installation is from a partially spooled
 * package.
 */
void
set_partial_inst(void)
{
	partial_inst++;
}

/*
 * Return variable indicating that the installation is from a partially spooled
 * package.
 * Returns:  !0 for true
 *           0 for false
 */
int
is_partial_inst(void)
{
	return (partial_inst);
}

/*
 * Increment variable indicating that only the depend and pkginfo DB's are to be
 * updated
 */

void
set_depend_pkginfo_DB(boolean_t a_setting)
{
	depend_pkginfo_DB = a_setting;
}

/*
 * Return variable indicating that the installation only updates the depend
 * and pkginfo DB's.
 * Returns:  !0 for true
 *           0 for false
 */

boolean_t
is_depend_pkginfo_DB(void)
{
	return (depend_pkginfo_DB);
}

/*
 * Increment variable indicating that packages should not be spooled in
 * var/sadm/pkg/<pkgabbrev>/save/pspool/
 */
void
disable_spool_create(void)
{
	partial_spool_create++;
}

/*
 * Return variable indicating whether or not the partial spool directory
 * should be created.
 * Returns:  1 for true
 *           0 for false
 */
int
is_spool_create(void)
{
	return (partial_spool_create);
}
