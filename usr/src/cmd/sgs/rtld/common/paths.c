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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PATH setup and search directory functions.
 */
#include	"_synonyms.h"

#include	<stdio.h>
#include	<limits.h>
#include	<fcntl.h>
#include	<string.h>
#include	<sys/systeminfo.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"msg.h"

/*
 * Given a search rule type, return a list of directories to search according
 * to the specified rule.
 */
static Pnode *
get_dir_list(uchar_t rules, Rt_map *lmp, uint_t flags)
{
	Pnode *		dirlist = (Pnode *)0;
	Lm_list *	lml = LIST(lmp);
	int		search;

	/*
	 * Determine whether ldd -s is in effect - ignore when we're searching
	 * for audit libraries as these will be added to their own link-map.
	 */
	if ((lml->lm_flags & LML_FLG_TRC_SEARCH) &&
	    ((FLAGS1(lmp) & FL1_RT_LDDSTUB) == 0) &&
	    ((flags & FLG_RT_AUDIT) == 0))
		search = 1;
	else
		search = 0;

	switch (rules) {
	case RPLENV:
		/*
		 * Initialize the replaceable environment variable
		 * (LD_LIBRARY_PATH) search path list.  Note, we always call
		 * Dbg_libs_path() so that every library lookup diagnostic can
		 * be preceded with the appropriate search path information.
		 */
		if (rpl_libpath) {
			uint_t	mode = (LA_SER_LIBPATH | PN_FLG_UNIQUE);

			/*
			 * Note, this path may have originated from the users
			 * environment or from a configuration file.
			 */
			if (env_info & ENV_INF_PATHCFG)
				mode |= LA_SER_CONFIG;

			DBG_CALL(Dbg_libs_path(lml, rpl_libpath, mode,
			    config->c_name));

			/*
			 * For ldd(1) -s, indicate the search paths that'll
			 * be used.  If this is a secure program then some
			 * search paths may be ignored, therefore reset the
			 * rpl_libdirs pointer each time so that the
			 * diagnostics related to these unsecure directories
			 * will be output for each image loaded.
			 */
			if (search) {
				const char	*fmt;

				if (env_info & ENV_INF_PATHCFG)
					fmt = MSG_INTL(MSG_LDD_PTH_LIBPATHC);
				else
					fmt = MSG_INTL(MSG_LDD_PTH_LIBPATH);

				(void) printf(fmt, rpl_libpath, config->c_name);
			}
			if (rpl_libdirs && (rtld_flags & RT_FL_SECURE) &&
			    (search || DBG_ENABLED)) {
				free(rpl_libdirs);
				rpl_libdirs = 0;
			}
			if (!rpl_libdirs) {
				/*
				 * If this is a secure application we need to
				 * be selective over what directories we use.
				 */
				rpl_libdirs = expand_paths(lmp, rpl_libpath,
				    mode, PN_TKN_HWCAP);
			}
			dirlist = rpl_libdirs;
		}
		break;
	case PRMENV:
		/*
		 * Initialize the permanent (LD_LIBRARY_PATH) search path list.
		 * This can only originate from a configuration file.  To be
		 * consistent with the debugging display of DEFENV (above),
		 * always call Dbg_libs_path().
		 */
		if (prm_libpath) {
			uint_t	mode =
			    (LA_SER_LIBPATH | LA_SER_CONFIG | PN_FLG_UNIQUE);

			DBG_CALL(Dbg_libs_path(lml, prm_libpath, mode,
			    config->c_name));

			/*
			 * For ldd(1) -s, indicate the search paths that'll
			 * be used.  If this is a secure program then some
			 * search paths may be ignored, therefore reset the
			 * prm_libdirs pointer each time so that the
			 * diagnostics related to these unsecure directories
			 * will be output for each image loaded.
			 */
			if (search)
				(void) printf(MSG_INTL(MSG_LDD_PTH_LIBPATHC),
				    prm_libpath, config->c_name);
			if (prm_libdirs && (rtld_flags & RT_FL_SECURE) &&
			    (search || DBG_ENABLED)) {
				free(prm_libdirs);
				prm_libdirs = 0;
			}
			if (!prm_libdirs) {
				/*
				 * If this is a secure application we need to
				 * be selective over what directories we use.
				 */
				prm_libdirs = expand_paths(lmp, prm_libpath,
				    mode, PN_TKN_HWCAP);
			}
			dirlist = prm_libdirs;
		}
		break;
	case RUNPATH:
		/*
		 * Initialize the runpath search path list.  To be consistent
		 * with the debugging display of DEFENV (above), always call
		 * Dbg_libs_path().
		 */
		if (RPATH(lmp)) {
			DBG_CALL(Dbg_libs_path(lml, RPATH(lmp), LA_SER_RUNPATH,
			    NAME(lmp)));

			/*
			 * For ldd(1) -s, indicate the search paths that'll
			 * be used.  If this is a secure program then some
			 * search paths may be ignored, therefore reset the
			 * runlist pointer each time so that the diagnostics
			 * related to these unsecure directories will be
			 * output for each image loaded.
			 */
			if (search)
				(void) printf(MSG_INTL(MSG_LDD_PTH_RUNPATH),
				    RPATH(lmp), NAME(lmp));
			if (RLIST(lmp) && (rtld_flags & RT_FL_SECURE) &&
			    (search || DBG_ENABLED)) {
				free(RLIST(lmp));
				RLIST(lmp) = 0;
			}
			if (!(RLIST(lmp)))
				/*
				 * If this is a secure application we need to
				 * be selective over what directories we use.
				 */
				RLIST(lmp) = expand_paths(lmp, RPATH(lmp),
				    LA_SER_RUNPATH, PN_TKN_HWCAP);
			dirlist = RLIST(lmp);
		}
		break;
	case DEFAULT:
		if ((FLAGS1(lmp) & FL1_RT_NODEFLIB) == 0) {
			if ((rtld_flags & RT_FL_SECURE) &&
			    (flags & (FLG_RT_PRELOAD | FLG_RT_AUDIT)))
				dirlist = LM_SECURE_DIRS(lmp);
			else
				dirlist = LM_DFLT_DIRS(lmp);
		}

		/*
		 * For ldd(1) -s, indicate the default paths that'll be used.
		 */
		if (dirlist && (search || DBG_ENABLED)) {
			Pnode *	pnp = dirlist;
			int	num = 0;

			if (search)
				(void) printf(MSG_INTL(MSG_LDD_PTH_BGNDFL));
			for (; pnp && pnp->p_name; pnp = pnp->p_next, num++) {
				if (search) {
					const char	*fmt;

					if (num) {
						fmt =
						    MSG_ORIG(MSG_LDD_FMT_PATHN);
					} else {
						fmt =
						    MSG_ORIG(MSG_LDD_FMT_PATH1);
					}
					(void) printf(fmt, pnp->p_name);
				} else
					DBG_CALL(Dbg_libs_path(lml, pnp->p_name,
					    pnp->p_orig, config->c_name));
			}
			/* BEGIN CSTYLED */
			if (search) {
				if (dirlist->p_orig & LA_SER_CONFIG)
				    (void) printf(MSG_INTL(MSG_LDD_PTH_ENDDFLC),
					config->c_name);
				else
				    (void) printf(MSG_INTL(MSG_LDD_PTH_ENDDFL));
			}
			/* END CSTYLED */
		}
		break;
	default:
		break;
	}
	return (dirlist);
}

/*
 * Get the next dir in the search rules path.
 */
Pnode *
get_next_dir(Pnode ** dirlist, Rt_map * lmp, uint_t flags)
{
	static unsigned char	*rules = NULL;

	/*
	 * Search rules consist of one or more directories names. If this is a
	 * new search, then start at the beginning of the search rules.
	 * Otherwise traverse the list of directories that make up the rule.
	 */
	if (!*dirlist) {
		rules = search_rules;
	} else {
		if ((*dirlist = (*dirlist)->p_next) != 0)
			return (*dirlist);
		else
			rules++;
	}

	while (*rules) {
		if ((*dirlist = get_dir_list(*rules, lmp, flags)) != 0)
			return (*dirlist);
		else
			rules++;
	}

	/*
	 * If we got here, no more directories to search, return NULL.
	 */
	return (NULL);
}

/*
 * Process a directory (runpath) or filename (needed or filter) string looking
 * for tokens to expand.  Allocate a new buffer for the string.
 */
uint_t
expand(char **name, size_t *len, char **list, uint_t orig, uint_t omit,
    Rt_map *lmp)
{
	char	_name[PATH_MAX];
	char	*token = 0, *oname, *optr, *_optr, *nptr, * _list;
	size_t	olen = 0, nlen = 0, _len;
	int	isaflag = 0;
	uint_t	flags = 0;
	Lm_list	*lml = LIST(lmp);

	optr = _optr = oname = *name;
	nptr = _name;

	while ((olen < *len) && (nlen < PATH_MAX)) {
		uint_t	_flags;

		if ((*optr != '$') || ((olen - *len) == 1)) {
			/*
			 * When expanding paths while a configuration file
			 * exists that contains directory information, determine
			 * whether the path contains "./".  If so, we'll resolve
			 * the path later to remove these relative entries.
			 */
			if ((rtld_flags & RT_FL_DIRCFG) &&
			    (orig & LA_SER_MASK) && (*optr == '/') &&
			    (optr != oname) && (*(optr - 1) == '.'))
				flags |= TKN_DOTSLASH;

			olen++, optr++;
			continue;
		}

		/*
		 * Copy any string we've presently passed over to the new
		 * buffer.
		 */
		if ((_len = (optr - _optr)) != 0) {
			if ((nlen += _len) < PATH_MAX) {
				(void) strncpy(nptr, _optr, _len);
				nptr = nptr + _len;
			} else {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_ERR_EXPAND1), NAME(lmp),
				    oname);
				return (0);
			}
		}

		/*
		 * Skip the token delimiter and determine if a reserved token
		 * match is found.
		 */
		olen++, optr++;
		_flags = 0;
		token = 0;

		if (strncmp(optr, MSG_ORIG(MSG_TKN_ORIGIN),
		    MSG_TKN_ORIGIN_SIZE) == 0) {
			token = (char *)MSG_ORIG(MSG_TKN_ORIGIN);

			/*
			 * $ORIGIN expansion is required.  Determine this
			 * objects basename.  Expansion of $ORIGIN is allowed
			 * for secure applications but must be checked by the
			 * caller to insure the expanded path matches a
			 * registered secure name.
			 */
			if (((omit & PN_TKN_ORIGIN) == 0) &&
			    (((_len = DIRSZ(lmp)) != 0) ||
			    ((_len = fullpath(lmp, 0)) != 0))) {
				if ((nlen += _len) < PATH_MAX) {
					(void) strncpy(nptr,
					    ORIGNAME(lmp), _len);
					nptr = nptr +_len;
					olen += MSG_TKN_ORIGIN_SIZE;
					optr += MSG_TKN_ORIGIN_SIZE;
					_flags |= PN_TKN_ORIGIN;
				} else {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_ERR_EXPAND1),
					    NAME(lmp), oname);
					return (0);
				}
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_TKN_PLATFORM),
		    MSG_TKN_PLATFORM_SIZE) == 0) {
			token = (char *)MSG_ORIG(MSG_TKN_PLATFORM);

			/*
			 * $PLATFORM expansion required.  This would have been
			 * established from the AT_SUN_PLATFORM aux vector, but
			 * if not attempt to get it from sysconf().
			 */
			if (((omit & PN_TKN_PLATFORM) == 0) &&
			    ((platform == 0) && (platform_sz == 0))) {
				char	_info[SYS_NMLN];
				long	_size;

				_size = sysinfo(SI_PLATFORM, _info, SYS_NMLN);
				if ((_size != -1) &&
				    ((platform = malloc((size_t)_size)) != 0)) {
					(void) strcpy(platform, _info);
					platform_sz = (size_t)_size - 1;
				}
			}
			if (((omit & PN_TKN_PLATFORM) == 0) &&
			    (platform != 0)) {
				if ((nlen += platform_sz) < PATH_MAX) {
					(void) strncpy(nptr, platform,
					    platform_sz);
					nptr = nptr + platform_sz;
					olen += MSG_TKN_PLATFORM_SIZE;
					optr += MSG_TKN_PLATFORM_SIZE;
					_flags |= PN_TKN_PLATFORM;
				} else {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_ERR_EXPAND1),
					    NAME(lmp), oname);
					return (0);
				}
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_TKN_OSNAME),
		    MSG_TKN_OSNAME_SIZE) == 0) {
			token = (char *)MSG_ORIG(MSG_TKN_OSNAME);

			/*
			 * $OSNAME expansion required.  This is established
			 * from the sysname[] returned by uname(2).
			 */
			if (((omit & PN_TKN_OSNAME) == 0) && (uts == 0))
				uts = conv_uts();

			if (((omit & PN_TKN_OSNAME) == 0) &&
			    (uts && uts->uts_osnamesz)) {
				if ((nlen += uts->uts_osnamesz) < PATH_MAX) {
					(void) strncpy(nptr, uts->uts_osname,
					    uts->uts_osnamesz);
					nptr = nptr + uts->uts_osnamesz;
					olen += MSG_TKN_OSNAME_SIZE;
					optr += MSG_TKN_OSNAME_SIZE;
					_flags |= PN_TKN_OSNAME;
				} else {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_ERR_EXPAND1),
					    NAME(lmp), oname);
					return (0);
				}
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_TKN_OSREL),
		    MSG_TKN_OSREL_SIZE) == 0) {
			token = (char *)MSG_ORIG(MSG_TKN_OSREL);

			/*
			 * $OSREL expansion required.  This is established
			 * from the release[] returned by uname(2).
			 */
			if (((omit & PN_TKN_OSREL) == 0) && (uts == 0))
				uts = conv_uts();

			if (((omit & PN_TKN_OSREL) == 0) &&
			    (uts && uts->uts_osrelsz)) {
				if ((nlen += uts->uts_osrelsz) < PATH_MAX) {
					(void) strncpy(nptr, uts->uts_osrel,
					    uts->uts_osrelsz);
					nptr = nptr + uts->uts_osrelsz;
					olen += MSG_TKN_OSREL_SIZE;
					optr += MSG_TKN_OSREL_SIZE;
					_flags |= PN_TKN_OSREL;
				} else {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_ERR_EXPAND1),
					    NAME(lmp), oname);
					return (0);
				}
			}

		} else if ((strncmp(optr, MSG_ORIG(MSG_TKN_ISALIST),
		    MSG_TKN_ISALIST_SIZE) == 0)) {
			int	ok;
			token = (char *)MSG_ORIG(MSG_TKN_ISALIST);

			/*
			 * $ISALIST expansion required.  When accompanied with
			 * a list pointer, this routine updates that pointer
			 * with the new list of potential candidates.  Without
			 * this list pointer, only the first expansion is
			 * provided.  NOTE, that two $ISLIST expansions within
			 * the same path aren't supported.
			 */
			if ((omit & PN_TKN_ISALIST) || isaflag++)
				ok = 0;
			else
				ok = 1;

			if (ok && (isa == 0))
				isa = conv_isalist();

			if (ok && isa && isa->isa_listsz) {
				size_t	no, mlen, tlen, hlen = olen - 1;
				char	*lptr;
				Isa_opt *opt = isa->isa_opt;

				if ((nlen += opt->isa_namesz) < PATH_MAX) {
					(void) strncpy(nptr,  opt->isa_name,
					    opt->isa_namesz);
					nptr = nptr + opt->isa_namesz;
					olen += MSG_TKN_ISALIST_SIZE;
					optr += MSG_TKN_ISALIST_SIZE;
					_flags |= PN_TKN_ISALIST;
				} else {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_ERR_EXPAND1),
					    NAME(lmp), oname);
					return (0);
				}

				if (list) {
					tlen = *len - olen;
					mlen = ((hlen + tlen) *
					    (isa->isa_optno - 1)) +
					    isa->isa_listsz - opt->isa_namesz +
					    strlen(*list);
					if ((_list = lptr = malloc(mlen)) == 0)
						return (0);

					for (no = 1, opt++; no < isa->isa_optno;
					    no++, opt++) {
						(void) strncpy(lptr, *name,
						    hlen);
						lptr = lptr + hlen;
						(void) strncpy(lptr,
						    opt->isa_name,
						    opt->isa_namesz);
						lptr = lptr + opt->isa_namesz;
						(void) strncpy(lptr, optr,
						    tlen);
						lptr = lptr + tlen;
						*lptr++ = ':';
					}
					if (**list)
						(void) strcpy(lptr, *list);
					else
						*--lptr = '\0';
				}
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_TKN_HWCAP),
		    MSG_TKN_HWCAP_SIZE) == 0) {
			char	*bptr = nptr - 1;
			char	*eptr = optr + MSG_TKN_HWCAP_SIZE;
			token = (char *)MSG_ORIG(MSG_TKN_HWCAP);

			/*
			 * $HWCAP expansion required.  For compatibility with
			 * older environments, only expand this token when hard-
			 * ware capability information is available.   This
			 * expansion is only allowed for non-simple pathnames
			 * (must contain a '/'), with the token itself being the
			 * last element of the path.  Therefore, all we need do
			 * is test the existence of the string "/$HWCAP\0".
			 */
			if (((omit & PN_TKN_HWCAP) == 0) &&
			    (rtld_flags2 & RT_FL2_HWCAP) &&
			    ((bptr > _name) && (*bptr == '/') &&
			    ((*eptr == '\0') || (*eptr == ':')))) {
				/*
				 * Decrement the present pointer so that the
				 * directories trailing "/" gets nuked later.
				 */
				nptr--, nlen--;
				olen += MSG_TKN_HWCAP_SIZE;
				optr += MSG_TKN_HWCAP_SIZE;
				_flags |= PN_TKN_HWCAP;
			}

		} else {
			/*
			 * If reserved token was not found, copy the
			 * character.
			 */
			*nptr++ = '$';
			nlen++;
		}

		/*
		 * If reserved token was found, and could not be expanded,
		 * diagnose the error condition.
		 */
		if (token) {
			if (_flags)
				flags |= _flags;
			else {
				char	buf[PATH_MAX], *str;

				/*
				 * Note, the original string we're expanding
				 * might contain a number of ':' separated
				 * paths.  Isolate the path we're processing to
				 * provide a more precise error diagnostic.
				 */
				if (str = strchr(oname, ':')) {
					size_t	slen = str - oname;

					(void) strncpy(buf, oname, slen);
					buf[slen] = '\0';
					str = buf;
				} else
					str = oname;

				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_ERR_EXPAND2), NAME(lmp),
				    str, token);
				return (0);
			}
		}
		_optr = optr;
	}

	/*
	 * First make sure the current length is shorter than PATH_MAX.  We may
	 * arrive here if the given path contains '$' characters which are not
	 * the lead of a reserved token.
	 */
	if (nlen >= PATH_MAX) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ERR_EXPAND1), NAME(lmp),
		    oname);
		return (0);
	}

	/*
	 * If any ISALIST processing has occurred not only do we return the
	 * expanded node we're presently working on, but we can also update the
	 * remaining list so that it is effectively prepended with this node
	 * expanded to all remaining ISALIST options.  Note that we can only
	 * handle one ISALIST per node.  For more than one ISALIST to be
	 * processed we'd need a better algorithm than above to replace the
	 * newly generated list.  Whether we want to encourage the number of
	 * pathname permutations this would provide is another question. So, for
	 * now if more than one ISALIST is encountered we return the original
	 * node untouched.
	 */
	if (isa && isaflag) {
		if (isaflag == 1) {
			if (list)
				*list = _list;
		} else {
			flags &= ~PN_TKN_ISALIST;

			if ((nptr = calloc(1, (*len + 1))) == 0)
				return (0);
			(void) strncpy(nptr, *name, *len);
			*name = nptr;

			return (TKN_NONE);
		}
	}

	/*
	 * Copy any remaining string. Terminate the new string with a null as
	 * this string can be displayed via debugging diagnostics.
	 */
	if ((_len = (optr - _optr)) != 0) {
		if ((nlen += _len) < PATH_MAX) {
			(void) strncpy(nptr, _optr, _len);
			nptr = nptr + _len;
		} else {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ERR_EXPAND1),
			    NAME(lmp), oname);
			return (0);
		}
	}
	*nptr = '\0';

	/*
	 * A path that has been expanded, is typically used to create full
	 * pathnames for objects that will be opened.  The final pathname is
	 * resolved to simplify it, and set the stage for possible $ORIGIN
	 * processing.  Therefore, it's usually unnecessary to resolve the path
	 * at this point.  However, if a configuration file, containing
	 * directory information is in use, then we might need to lookup this
	 * path in the configuration file.  To keep the number of pathname
	 * resolutions to a minimum, only resolve paths that contain "./".  The
	 * use of "$ORIGIN/../lib" will probably only match a configuration file
	 * entry after resolution.
	 */
	if (list && ((rtld_flags & (RT_FL_DIRCFG | RT_FL_EXECNAME)) ==
	    (RT_FL_DIRCFG | RT_FL_EXECNAME)) && (flags & TKN_DOTSLASH)) {
		int	len;

		if ((len = resolvepath(_name, _name, (PATH_MAX - 1))) >= 0) {
			nlen = (size_t)len;
			_name[nlen] = '\0';
		}
	}

	/*
	 * Allocate permanent storage for the new string and return to the user.
	 */
	if ((nptr = malloc(nlen + 1)) == 0)
		return (0);
	(void) strcpy(nptr, _name);
	*name = nptr;
	*len = nlen;

	/*
	 * Return an indication of any token expansion that may have occurred.
	 * Under security, any pathname expanded with the $ORIGIN token must be
	 * validated against any registered secure directories.
	 */
	return (flags ? flags : TKN_NONE);
}

/*
 * Determine whether a pathname is secure.
 */
static int
is_path_secure(char *opath, Rt_map *clmp, uint_t info, uint_t flags)
{
	Pnode	*sdir = LM_SECURE_DIRS(LIST(clmp)->lm_head);
	char	buffer[PATH_MAX], *npath;
	Lm_list	*lml;

	/*
	 * If a pathname originates from a configuration file, use it.  The use
	 * of a configuration file is already validated for secure applications,
	 * so if we're using a configuration file, we must be able to use all
	 * that it defines.
	 */
	if (info & LA_SER_CONFIG)
		return (1);

	if ((info & LA_SER_MASK) == 0) {
		char	*str;

		/*
		 * If the pathname specifies a file (rather than a directory),
		 * peel off the file before making the comparison.
		 */
		str = strrchr(opath, '/');

		/*
		 * A simple filename (one containing no "/") is fine, as this
		 * will be combined with search paths to determine the complete
		 * path.  Other paths are checked:
		 *
		 *   .	a full path (one starting with "/") is fine, provided
		 *	it isn't a preload/audit path.
		 *   .  any $ORIGIN expansion
		 *   .	any relative path
		 */
		if (((str == 0) || ((*opath == '/') && (str != opath) &&
		    ((info & PN_FLG_EXTLOAD) == 0))) &&
		    ((flags & PN_TKN_ORIGIN) == 0))
			return (1);

		if (str == opath)
			npath = (char *)MSG_ORIG(MSG_STR_SLASH);
		else {
			size_t	size;

			if ((size = str - opath) >= PATH_MAX)
				return (0);

			(void) strncpy(buffer, opath, size);
			buffer[size] = '\0';
			npath = buffer;
		}
	} else {
		/*
		 * A search path, i.e., RPATH, configuration file path, etc. is
		 * used as is.  Exceptions to this are:
		 *
		 *   .	LD_LIBRARY_PATH
		 *   .	any $ORIGIN expansion
		 *   .	any relative path
		 */
		if (((info & LA_SER_LIBPATH) == 0) && (*opath == '/') &&
		    ((flags & PN_TKN_ORIGIN) == 0))
			return (1);

		npath = (char *)opath;
	}

	while (sdir) {
		if (strcmp(npath, sdir->p_name) == 0)
			return (1);
		sdir = sdir->p_next;
	}

	lml = LIST(clmp);

	/*
	 * The path is insecure, so depending on the caller, provide a
	 * diagnostic.  Preloaded, or audit libraries generate a warning, as
	 * the process will run without them.
	 */
	if (info & PN_FLG_EXTLOAD) {
		if (lml->lm_flags & LML_FLG_TRC_ENABLE) {
			if ((FLAGS1(clmp) & FL1_RT_LDDSTUB) == 0)
				(void) printf(MSG_INTL(MSG_LDD_FIL_ILLEGAL),
				    opath);
		} else
			eprintf(lml, ERR_WARNING, MSG_INTL(MSG_SEC_ILLEGAL),
			    opath);

		return (0);
	}

	/*
	 * Explicit file references are fatal.
	 */
	if ((info & LA_SER_MASK) == 0) {
		if (lml->lm_flags & LML_FLG_TRC_ENABLE) {
			/* BEGIN CSTYLED */
			if ((FLAGS1(clmp) & FL1_RT_LDDSTUB) == 0) {
			    if (lml->lm_flags &
				(LML_FLG_TRC_VERBOSE | LML_FLG_TRC_SEARCH))
				    (void) printf(MSG_INTL(MSG_LDD_FIL_FIND),
					opath, NAME(clmp));

			    if (((rtld_flags & RT_FL_SILENCERR) == 0) ||
				(lml->lm_flags & LML_FLG_TRC_VERBOSE))
				    (void) printf(MSG_INTL(MSG_LDD_FIL_ILLEGAL),
					opath);
			}
			/* END CSTYLED */
		} else
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), opath,
			    strerror(EACCES));
	} else {
		/*
		 * Search paths.
		 */
		DBG_CALL(Dbg_libs_ignore(lml, opath));
		if ((lml->lm_flags & LML_FLG_TRC_SEARCH) &&
		    ((FLAGS1(clmp) & FL1_RT_LDDSTUB) == 0))
			(void) printf(MSG_INTL(MSG_LDD_PTH_IGNORE), opath);
	}
	return (0);
}

/*
 * Determine whether a path already exists within the callers Pnode list.
 */
inline static uint_t
is_path_unique(Pnode *pnp, const char *path)
{
	for (; pnp; pnp = pnp->p_next) {
		if (pnp->p_len && (strcmp(pnp->p_name, path) == 0))
			return (PN_FLG_DUPLICAT);
	}
	return (0);
}

/*
 * Expand one or more pathnames.  This routine is called for all path strings,
 * i.e., NEEDED, rpaths, default search paths, configuration file search paths,
 * filtees, etc.  The path may be a single pathname, or a colon separated list
 * of pathnames.  Each individual pathname is processed for possible reserved
 * token expansion.  All string nodes are maintained in allocated memory
 * (regardless of whether they are constant (":"), or token expanded) to
 * simplify pnode removal.
 *
 * The info argument passes in auxiliary information regarding the callers
 * intended use of the pathnames.  This information may be maintained in the
 * pnode element produced to describe the pathname (i.e., LA_SER_LIBPATH etc.),
 * or may be used to determine additional security or diagnostic processing.
 */
Pnode *
expand_paths(Rt_map *clmp, const char *list, uint_t orig, uint_t omit)
{
	char	*str, *olist = 0, *nlist = (char *)list;
	Pnode	*pnp, *npnp, *opnp;
	int	fnull = FALSE;	/* TRUE if empty final path segment seen */
	uint_t	unique = 0;

	for (pnp = opnp = 0, str = nlist; *nlist || fnull; str = nlist) {
		char	*ostr;
		size_t	len, olen;
		uint_t	tkns = 0;

		if (*nlist == ';')
			++nlist, ++str;
		if ((*nlist == ':') || fnull) {
			/* If not a final null segment, check following one */
			fnull = !(fnull || *(nlist + 1));

			if (*nlist)
				nlist++;

			/*
			 * When the shell sees a null PATH segment, it
			 * treats it as if it were the cwd (.). We mimic
			 * this behavior for LD_LIBRARY_PATH and runpaths
			 * (mainly for backwards compatibility with previous
			 * behavior). For other paths, this makes no sense,
			 * so we simply ignore the segment.
			 */
			if (!(orig & (LA_SER_LIBPATH | LA_SER_RUNPATH)))
				continue; /* Process next segment */

			if ((str = strdup(MSG_ORIG(MSG_FMT_CWD))) == NULL)
				return (NULL);
			len = MSG_FMT_CWD_SIZE;

		} else {
			char	*elist;

			len = 0;
			while (*nlist && (*nlist != ':') && (*nlist != ';')) {
				nlist++, len++;
			}

			/* Check for a following final null segment */
			fnull = (*nlist == ':') && !*(nlist + 1);

			if (*nlist)
				nlist++;

			/*
			 * Expand the captured string.  Besides expanding the
			 * present path/file entry, we may have a new list to
			 * deal with (ISALIST expands to multiple new entries).
			 */
			elist = nlist;
			ostr = str;
			olen = len;
			if ((tkns = expand(&str, &len, &elist, orig, omit,
			    clmp)) == 0)
				continue;

			if (elist != nlist) {
				if (olist)
					free(olist);
				nlist = olist = elist;
			}
		}

		/*
		 * If this a secure application, validation of the expanded
		 * pathname may be necessary.
		 */
		if (rtld_flags & RT_FL_SECURE) {
			if (is_path_secure(str, clmp, orig, tkns) == 0) {
				free(str);
				continue;
			}
		}

		/*
		 * If required, ensure that the string is unique.  For search
		 * paths such as LD_LIBRARY_PATH, users often inherit multiple
		 * paths which result in unnecessary duplication.  Note, if
		 * we're debugging, any duplicate entry is retained and flagged
		 * so that the entry can be diagnosed later as part of unused
		 * processing.
		 */
		if (orig & PN_FLG_UNIQUE) {
			Word	tracing;

			tracing = LIST(clmp)->lm_flags &
			    (LML_FLG_TRC_UNREF | LML_FLG_TRC_UNUSED);
			unique = is_path_unique(pnp, str);

			/*
			 * Note, use the debug strings rpl_debug and prm_debug
			 * as an indicator that debugging has been requested,
			 * rather than DBG_ENABLE(), as the initial use of
			 * LD_LIBRARY_PATH occurs in preparation for loading
			 * our debugging library.
			 */
			if ((unique == PN_FLG_DUPLICAT) && (tracing == 0) &&
			    (rpl_debug == 0) && (prm_debug == 0)) {
				free(str);
				continue;
			}
		}

		/*
		 * Allocate a new Pnode for this string.
		 */
		if ((npnp = calloc(1, sizeof (Pnode))) == 0) {
			free(str);
			return (NULL);
		}
		if (opnp == 0)
			pnp = npnp;
		else
			opnp->p_next = npnp;

		if (tkns & PN_TKN_MASK) {
			char	*oname;

			/*
			 * If this is a pathname, and any token expansion
			 * occurred, maintain the original string for possible
			 * diagnostic use.
			 */
			if ((oname = malloc(olen + 1)) == 0) {
				free(str);
				return (NULL);
			}
			(void) strncpy(oname, ostr, olen);
			oname[olen] = '\0';
			npnp->p_oname = oname;
		}
		npnp->p_name = str;
		npnp->p_len = len;
		npnp->p_orig = (orig & LA_SER_MASK) | unique |
		    (tkns & PN_TKN_MASK);

		opnp = npnp;
	}

	if (olist)
		free(olist);

	return (pnp);
}
