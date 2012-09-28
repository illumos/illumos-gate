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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 */

/*
 * Library processing
 */
#include	<stdio.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<string.h>
#include	<limits.h>
#include	<errno.h>
#include	<debug.h>
#include	<sys/sysmacros.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Define a list index for "-L" processing.  By default, "-L" search paths are
 * inserted at the beginning of the associated search list.  However, should a
 * ";" be discovered in a LD_LIBRARY_PATH listing, then any new "-L" search
 * paths are inserted following the ";".
 */
static Aliste	Lidx = 0;

/*
 * Function to handle -YL and -YU substitutions in LIBPATH.  It's probably
 * very unlikely that the link-editor will ever see this, as any use of these
 * options is normally processed by the compiler driver first and the finished
 * -YP string is sent to us.  The fact that these two options are not even
 * documented anymore makes it even more unlikely this processing will occur.
 */
static char *
compat_YL_YU(Ofl_desc *ofl, char *path, int index)
{
	if (index == YLDIR) {
		if (Llibdir) {
			/*
			 * User supplied "-YL,libdir", this is the pathname that
			 * corresponds for compatibility to -YL (as defined in
			 * sgs/include/paths.h)
			 */
			DBG_CALL(Dbg_libs_ylu(ofl->ofl_lml, Llibdir,
			    path, index));
			return (Llibdir);
		}
	} else if (index == YUDIR) {
		if (Ulibdir) {
			/*
			 * User supplied "-YU,libdir", this is the pathname that
			 * corresponds for compatibility to -YU (as defined in
			 * sgs/include/paths.h)
			 */
			DBG_CALL(Dbg_libs_ylu(ofl->ofl_lml, Ulibdir,
			    path, index));
			return (Ulibdir);
		}
	}
	return (path);
}

static char *
process_lib_path(Ofl_desc *ofl, APlist **apl, char *path, Boolean subsflag)
{
	int	i;
	char	*cp;
	Boolean	seenflg = FALSE;
	char	*dot = (char *)MSG_ORIG(MSG_STR_DOT);

	for (i = YLDIR; i; i++) {
		cp = strpbrk(path, MSG_ORIG(MSG_STR_PATHTOK));
		if (cp == NULL) {
			if (*path == '\0') {
				if (seenflg)
					if (aplist_append(apl, (subsflag ?
					    compat_YL_YU(ofl, dot, i) : dot),
					    AL_CNT_OFL_LIBDIRS) == NULL)
						return ((char *)S_ERROR);

			} else if (aplist_append(apl, (subsflag ?
			    compat_YL_YU(ofl, path, i) : path),
			    AL_CNT_OFL_LIBDIRS) == NULL) {
				return ((char *)S_ERROR);
			}
			return (cp);
		}

		if (*cp == ':') {
			*cp = '\0';
			if (cp == path) {
				if (aplist_append(apl, (subsflag ?
				    compat_YL_YU(ofl, dot, i) : dot),
				    AL_CNT_OFL_LIBDIRS) == NULL)
					return ((char *)S_ERROR);

			} else if (aplist_append(apl, (subsflag ?
			    compat_YL_YU(ofl, path, i) : path),
			    AL_CNT_OFL_LIBDIRS) == NULL) {
				return ((char *)S_ERROR);
			}
			path = cp + 1;
			seenflg = TRUE;
			continue;
		}

		/* case ";" */

		if (cp != path) {
			if (aplist_append(apl, (subsflag ?
			    compat_YL_YU(ofl, path, i) : path),
			    AL_CNT_OFL_LIBDIRS) == NULL)
				return ((char *)S_ERROR);
		} else {
			if (seenflg)
				if (aplist_append(apl, (subsflag ?
				    compat_YL_YU(ofl, dot, i) : dot),
				    AL_CNT_OFL_LIBDIRS) == NULL)
					return ((char *)S_ERROR);
		}
		return (cp);
	}
	/* NOTREACHED */
	return (NULL);	/* keep gcc happy */
}

/*
 * adds the indicated path to those to be searched for libraries.
 */
uintptr_t
ld_add_libdir(Ofl_desc *ofl, const char *path)
{
	if (aplist_insert(&ofl->ofl_ulibdirs, path,
	    AL_CNT_OFL_LIBDIRS, Lidx++) == NULL)
		return (S_ERROR);

	/*
	 * As -l and -L options can be interspersed, print the library
	 * search paths each time a new path is added.
	 */
	DBG_CALL(Dbg_libs_update(ofl->ofl_lml, ofl->ofl_ulibdirs,
	    ofl->ofl_dlibdirs));
	return (1);
}

/*
 * Process a required library.  Combine the directory and filename, and then
 * append either a `.so' or `.a' suffix and try opening the associated pathname.
 */
static uintptr_t
find_lib_name(const char *dir, const char *file, Ofl_desc *ofl, Rej_desc *rej,
    ofl_flag_t flags)
{
	int		fd;
	size_t		dlen;
	char		*_path, path[PATH_MAX + 2];
	const char	*_dir = dir;
	uintptr_t	open_ret;

	/*
	 * Determine the size of the directory.  The directory and filename are
	 * concatenated into the local buffer which is purposely larger than
	 * PATH_MAX.  Should a pathname be created that exceeds the system
	 * limit, the open() will catch it, and a suitable rejection message is
	 * saved.
	 */
	if ((dlen = strlen(dir)) == 0) {
		_dir = (char *)MSG_ORIG(MSG_STR_DOT);
		dlen = 1;
	}
	dlen++;

	/*
	 * If we are in dynamic mode try and open the associated shared object.
	 */
	if (ofl->ofl_flags & FLG_OF_DYNLIBS) {
		(void) snprintf(path, (PATH_MAX + 2), MSG_ORIG(MSG_STR_LIB_SO),
		    _dir, file);
		DBG_CALL(Dbg_libs_l(ofl->ofl_lml, file, path));
		if ((fd = open(path, O_RDONLY)) != -1) {

			if ((_path = libld_malloc(strlen(path) + 1)) == NULL)
				return (S_ERROR);
			(void) strcpy(_path, path);

			open_ret = ld_process_open(_path, &_path[dlen], &fd,
			    ofl, FLG_IF_NEEDED, rej, NULL);
			if (fd != -1)
				(void) close(fd);
			if (open_ret != 0 && (flags & FLG_OF_ADEFLIB))
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_ARG_ASSDEFLIB_FOUND), dir,
				    file);
			return (open_ret);

		} else if (errno != ENOENT) {
			/*
			 * If the open() failed for anything other than the
			 * file not existing, record the error condition.
			 */
			rej->rej_type = SGS_REJ_STR;
			rej->rej_str = strerror(errno);
			rej->rej_name = strdup(path);
		}
	}

	/*
	 * If we are not in dynamic mode, or a shared object could not be
	 * located, try and open the associated archive.
	 */
	(void) snprintf(path, (PATH_MAX + 2), MSG_ORIG(MSG_STR_LIB_A),
	    _dir, file);
	DBG_CALL(Dbg_libs_l(ofl->ofl_lml, file, path));
	if ((fd = open(path, O_RDONLY)) != -1) {

		if ((_path = libld_malloc(strlen(path) + 1)) == NULL)
			return (S_ERROR);
		(void) strcpy(_path, path);

		open_ret = ld_process_open(_path, &_path[dlen], &fd, ofl,
		    FLG_IF_NEEDED, rej, NULL);
		if (fd != -1)
			(void) close(fd);
		return (open_ret);

	} else if (errno != ENOENT) {
		/*
		 * If the open() failed for anything other than the
		 * file not existing, record the error condition.
		 */
		rej->rej_type = SGS_REJ_STR;
		rej->rej_str = strerror(errno);
		rej->rej_name = strdup(path);
	}

	return (0);
}

/*
 * Take the abbreviated name of a library file (from -lfoo) and searches for the
 * library.  The search path rules are:
 *
 *	o	use any user supplied paths, i.e. LD_LIBRARY_PATH and -L, then
 *
 *	o	use the default directories, i.e. LIBPATH or -YP.
 *
 * If we are in dynamic mode and -Bstatic is not in effect, first look for a
 * shared object with full name: path/libfoo.so; then [or else] look for an
 * archive with name: path/libfoo.a.  If no file is found, it's a fatal error,
 * otherwise process the file appropriately depending on its type.
 *
 * If we end up using the default directories and -z assert-deflib has been
 * turned on, then we pass that information down into find_lib_name which will
 * warn appropriately if we find a shared object.
 */
uintptr_t
ld_find_library(const char *name, Ofl_desc *ofl)
{
	Aliste		idx;
	char		*path;
	uintptr_t	open_ret;
	Rej_desc	rej = { 0 };
	ofl_flag_t	flags = 0;

	/*
	 * Search for this file in any user defined directories.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_ulibdirs, idx, path)) {
		Rej_desc	_rej = { 0 };

		if ((open_ret = find_lib_name(path, name, ofl, &_rej,
		    flags)) == 0) {
			if (_rej.rej_type && (rej.rej_type == 0))
				rej = _rej;
			continue;
		}
		return (open_ret);
	}

	if (ofl->ofl_flags & FLG_OF_ADEFLIB) {
		flags |= FLG_OF_ADEFLIB;
		for (APLIST_TRAVERSE(ofl->ofl_assdeflib, idx, path)) {
			if (strncmp(name, path + MSG_STR_LIB_SIZE,
			    MAX(strlen(path + MSG_STR_LIB_SIZE) -
			    MSG_STR_SOEXT_SIZE, strlen(name))) == 0) {
				flags &= ~FLG_OF_ADEFLIB;
				break;
			}
		}
	}

	/*
	 * Finally try the default library search directories.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_dlibdirs, idx, path)) {
		Rej_desc	_rej = { 0 };

		if ((open_ret = find_lib_name(path, name, ofl, &_rej,
		    flags)) == 0) {
			if (_rej.rej_type && (rej.rej_type == 0))
				rej = _rej;
			continue;
		}

		return (open_ret);
	}

	/*
	 * If we've got this far we haven't found a shared object or archive.
	 * If an object was found, but was rejected for some reason, print a
	 * diagnostic to that effect, otherwise generate a generic "not found"
	 * diagnostic.
	 */
	if (rej.rej_type) {
		Conv_reject_desc_buf_t rej_buf;

		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(reject[rej.rej_type]),
		    rej.rej_name ? rej.rej_name : MSG_INTL(MSG_STR_UNKNOWN),
		    conv_reject_desc(&rej, &rej_buf, ld_targ.t_m.m_mach));
	} else {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_LIB_NOTFOUND), name);
	}

	return (0);
}

/*
 * Inspect the LD_LIBRARY_PATH variable (if the -i options has not been
 * specified), and set up the directory list from which to search for
 * libraries.  From the man page:
 *
 *	LD_LIBRARY_PATH=dirlist1;dirlist2
 * and
 *	ld ... -Lpath1 ... -Lpathn ...
 *
 * results in a search order of:
 *
 *	dirlist1 path1 ... pathn dirlist2 LIBPATH
 *
 * If LD_LIBRARY_PATH has no `;' specified, the pathname(s) supplied are
 * all taken as dirlist2.
 */
uintptr_t
ld_lib_setup(Ofl_desc *ofl)
{
	char	*path, *cp = NULL;

	/*
	 * Determine whether an LD_LIBRARY_PATH setting is in effect.
	 */
	if (!(ofl->ofl_flags & FLG_OF_IGNENV)) {
#if	defined(_ELF64)
		if ((cp = getenv(MSG_ORIG(MSG_LD_LIBPATH_64))) == NULL)
#else
		if ((cp = getenv(MSG_ORIG(MSG_LD_LIBPATH_32))) == NULL)
#endif
			cp  = getenv(MSG_ORIG(MSG_LD_LIBPATH));
	}

	if (cp && cp[0]) {
		if ((path = libld_malloc(strlen(cp) + 1)) == NULL)
			return (S_ERROR);
		(void) strcpy(path, cp);
		DBG_CALL(Dbg_libs_path(ofl->ofl_lml, path, LA_SER_DEFAULT, 0));

		/*
		 * Process the first path string (anything up to a null or
		 * a `;');
		 */
		path = process_lib_path(ofl, &ofl->ofl_ulibdirs, path, FALSE);


		/*
		 * By default, -L paths are prepended to the library search
		 * path list, because Lidx == 0.  If a ';' is seen within an
		 * LD_LIBRARY_PATH string, change the insert index so that -L
		 * paths are added following the ';'.
		 */
		if (path) {
			Lidx = aplist_nitems(ofl->ofl_ulibdirs);
			*path = '\0';
			++path;
			cp = process_lib_path(ofl, &ofl->ofl_ulibdirs, path,
			    FALSE);
			if (cp == (char *)S_ERROR)
				return (S_ERROR);
			else if (cp)
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_LIB_MALFORM));
		}
	}

	/*
	 * Add the default LIBPATH or any -YP supplied path.
	 */
	DBG_CALL(Dbg_libs_yp(ofl->ofl_lml, Plibpath));
	cp = process_lib_path(ofl, &ofl->ofl_dlibdirs, Plibpath, TRUE);
	if (cp == (char *)S_ERROR)
		return (S_ERROR);
	else if (cp) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_LIB_BADYP));
		return (S_ERROR);
	}
	DBG_CALL(Dbg_libs_init(ofl->ofl_lml, ofl->ofl_ulibdirs,
	    ofl->ofl_dlibdirs));
	return (1);
}
