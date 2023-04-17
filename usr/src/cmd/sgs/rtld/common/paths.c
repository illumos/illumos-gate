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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */
/*
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 */

/*
 * PATH setup and search directory functions.
 */

#include	<stdio.h>
#include	<unistd.h>
#include	<limits.h>
#include	<fcntl.h>
#include	<string.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"msg.h"

/*
 * Default and secure dependency search path initialization.
 */
void
set_dirs(Alist **alpp, Spath_defn *sdp, uint_t flags)
{
	while (sdp->sd_name) {
		Pdesc	*pdp;

		if ((pdp = alist_append(alpp, NULL, sizeof (Pdesc),
		    AL_CNT_SPATH)) == NULL)
			return;

		pdp->pd_pname = (char *)sdp->sd_name;
		pdp->pd_plen = sdp->sd_len;
		pdp->pd_flags = flags;
		sdp++;
	}
}

static void
print_default_dirs(Lm_list *lml, Alist *alp, int search)
{
	uint_t	flags = 0;
	int	num = 0;
	Aliste	idx;
	Pdesc	*pdp;

	if (search)
		(void) printf(MSG_INTL(MSG_LDD_PTH_BGNDFL));

	for (ALIST_TRAVERSE(alp, idx, pdp)) {
		flags = pdp->pd_flags;

		if (search) {
			const char	*fmt;

			if (num++)
				fmt = MSG_ORIG(MSG_LDD_FMT_PATHN);
			else
				fmt = MSG_ORIG(MSG_LDD_FMT_PATH1);

			(void) printf(fmt, pdp->pd_pname);
		} else
			DBG_CALL(Dbg_libs_path(lml, pdp->pd_pname,
			    pdp->pd_flags, config->c_name));
	}

	if (search) {
		if (flags & LA_SER_CONFIG)
			(void) printf(MSG_INTL(MSG_LDD_PTH_ENDDFLC),
			    config->c_name);
		else
			(void) printf(MSG_INTL(MSG_LDD_PTH_ENDDFL));
	}
}

/*
 * Given a search rule type, return a list of directories to search according
 * to the specified rule.
 */
static Alist **
get_dir_list(uchar_t rules, Rt_map *lmp, uint_t flags)
{
	Alist	**dalpp = NULL;
	Lm_list *lml = LIST(lmp);
	int	search;

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
			uint_t	mode = (LA_SER_LIBPATH | PD_FLG_UNIQUE);

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
			 * be used.  If this is a secure application then some
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
			    (search || DBG_ENABLED))
				remove_alist(&rpl_libdirs, 1);

			if (rpl_libdirs == NULL) {
				/*
				 * If this is a secure application we need to
				 * be selective over what directories we use.
				 */
				(void) expand_paths(lmp, rpl_libpath,
				    &rpl_libdirs, AL_CNT_SEARCH, mode,
				    PD_TKN_CAP);
			}
			dalpp = &rpl_libdirs;
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
			    (LA_SER_LIBPATH | LA_SER_CONFIG | PD_FLG_UNIQUE);

			DBG_CALL(Dbg_libs_path(lml, prm_libpath, mode,
			    config->c_name));

			/*
			 * For ldd(1) -s, indicate the search paths that'll
			 * be used.  If this is a secure application then some
			 * search paths may be ignored, therefore reset the
			 * prm_libdirs pointer each time so that the
			 * diagnostics related to these unsecure directories
			 * will be output for each image loaded.
			 */
			if (search)
				(void) printf(MSG_INTL(MSG_LDD_PTH_LIBPATHC),
				    prm_libpath, config->c_name);
			if (prm_libdirs && (rtld_flags & RT_FL_SECURE) &&
			    (search || DBG_ENABLED))
				remove_alist(&prm_libdirs, 1);

			if (prm_libdirs == NULL) {
				/*
				 * If this is a secure application we need to
				 * be selective over what directories we use.
				 */
				(void) expand_paths(lmp, prm_libpath,
				    &prm_libdirs, AL_CNT_SEARCH, mode,
				    PD_TKN_CAP);
			}
			dalpp = &prm_libdirs;
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
			 * be used.  If this is a secure application then some
			 * search paths may be ignored, therefore reset the
			 * runlist pointer each time so that the diagnostics
			 * related to these unsecure directories will be
			 * output for each image loaded.
			 */
			if (search)
				(void) printf(MSG_INTL(MSG_LDD_PTH_RUNPATH),
				    RPATH(lmp), NAME(lmp));
			if (RLIST(lmp) && (rtld_flags & RT_FL_SECURE) &&
			    (search || DBG_ENABLED))
				remove_alist(&RLIST(lmp), 1);

			if (RLIST(lmp) == NULL) {
				/*
				 * If this is a secure application we need to
				 * be selective over what directories we use.
				 */
				(void) expand_paths(lmp, RPATH(lmp),
				    &RLIST(lmp), AL_CNT_SEARCH, LA_SER_RUNPATH,
				    PD_TKN_CAP);
			}
			dalpp = &RLIST(lmp);
		}
		break;
	case DEFAULT:
		/*
		 * If we have been requested to load an audit library through a
		 * DT_DEPAUDIT entry, then we treat this the same way that we
		 * handle a library that has been specified via a DT_NEEDED
		 * entry -- we check the default directories and not the
		 * secure directories.
		 */
		if ((FLAGS1(lmp) & FL1_RT_NODEFLIB) == 0) {
			if ((rtld_flags & RT_FL_SECURE) &&
			    ((flags & FLG_RT_PRELOAD) ||
			    ((flags & FLG_RT_AUDIT) && !(FLAGS1(lmp) &
			    FL1_RT_DEPAUD))))
				dalpp = LM_SECURE_DIRS(lmp)();
			else
				dalpp = LM_DEFAULT_DIRS(lmp)();
		}

		/*
		 * For ldd(1) -s, indicate the default paths that'll be used.
		 */
		if (dalpp && (search || DBG_ENABLED))
			print_default_dirs(lml, *dalpp, search);
		break;
	default:
		break;
	}
	return (dalpp);
}

/*
 * Get the next directory in the search rules path.  The search path "cookie"
 * provided by the caller (sdp) maintains the state of a search in progress.
 *
 * Typically, a search consists of a series of rules that govern the order of
 * a search (ie. LD_LIBRARY_PATH, followed by RPATHS, followed by defaults).
 * Each rule can establish a corresponding series of path names, which are
 * maintained as an Alist.  The index within this Alist determines the present
 * search directory.
 */
Pdesc *
get_next_dir(Spath_desc *sdp, Rt_map *lmp, uint_t flags)
{
	/*
	 * Make sure there are still rules to process.
	 */
	while (*sdp->sp_rule) {
		Alist	*alp;

		/*
		 * If an Alist for this rule already exists, use if, otherwise
		 * obtain an Alist for this rule.  Providing the Alist has
		 * content, and the present Alist index is less than the number
		 * of Alist members, return the associated path name descriptor.
		 */
		if ((sdp->sp_dalpp || ((sdp->sp_dalpp =
		    get_dir_list(*sdp->sp_rule, lmp, flags)) != NULL)) &&
		    ((alp = *sdp->sp_dalpp) != NULL) &&
		    (alist_nitems(alp) > sdp->sp_idx)) {
			return (alist_item(alp, sdp->sp_idx++));
		}

		/*
		 * If no Alist for this rule exists, or if this is the last
		 * element of this Alist, reset the Alist pointer and index,
		 * and prepare for the next rule.
		 */
		sdp->sp_rule++;
		sdp->sp_dalpp = NULL;
		sdp->sp_idx = 0;
	}

	/*
	 * All rules and search paths have been exhausted.
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
	char	*token = NULL, *oname, *ename, *optr, *_optr, *nptr, *_list;
	size_t	olen = 0, nlen = 0, _len;
	int	isaflag = 0;
	uint_t	flags = 0;
	Lm_list	*lml = LIST(lmp);

	optr = _optr = oname = ename = *name;
	ename += *len;
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
			if (((omit & PD_TKN_ORIGIN) == 0) &&
			    (((_len = DIRSZ(lmp)) != 0) ||
			    ((_len = fullpath(lmp, 0)) != 0))) {
				if ((nlen += _len) < PATH_MAX) {
					(void) strncpy(nptr,
					    ORIGNAME(lmp), _len);
					nptr = nptr +_len;
					olen += MSG_TKN_ORIGIN_SIZE;
					optr += MSG_TKN_ORIGIN_SIZE;
					_flags |= PD_TKN_ORIGIN;
				} else {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_ERR_EXPAND1),
					    NAME(lmp), oname);
					return (0);
				}
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_TKN_PLATFORM),
		    MSG_TKN_PLATFORM_SIZE) == 0) {
			Syscapset	*scapset;

			if (FLAGS1(lmp) & FL1_RT_ALTCAP)
				scapset = alt_scapset;
			else
				scapset = org_scapset;

			token = (char *)MSG_ORIG(MSG_TKN_PLATFORM);

			/*
			 * $PLATFORM expansion required.
			 */
			if (((omit & PD_TKN_PLATFORM) == 0) &&
			    ((scapset->sc_plat == NULL) &&
			    (scapset->sc_platsz == 0)))
				platform_name(scapset);

			if (((omit & PD_TKN_PLATFORM) == 0) &&
			    scapset->sc_plat) {
				nlen += scapset->sc_platsz;
				if (nlen < PATH_MAX) {
					(void) strncpy(nptr, scapset->sc_plat,
					    scapset->sc_platsz);
					nptr = nptr + scapset->sc_platsz;
					olen += MSG_TKN_PLATFORM_SIZE;
					optr += MSG_TKN_PLATFORM_SIZE;
					_flags |= PD_TKN_PLATFORM;
				} else {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_ERR_EXPAND1),
					    NAME(lmp), oname);
					return (0);
				}
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_TKN_MACHINE),
		    MSG_TKN_MACHINE_SIZE) == 0) {
			Syscapset	*scapset;

			if (FLAGS1(lmp) & FL1_RT_ALTCAP)
				scapset = alt_scapset;
			else
				scapset = org_scapset;

			token = (char *)MSG_ORIG(MSG_TKN_MACHINE);

			/*
			 * $MACHINE expansion required.
			 */
			if (((omit & PD_TKN_MACHINE) == 0) &&
			    ((scapset->sc_mach == NULL) &&
			    (scapset->sc_machsz == 0)))
				machine_name(scapset);

			if (((omit & PD_TKN_MACHINE) == 0) &&
			    scapset->sc_mach) {
				nlen += scapset->sc_machsz;
				if (nlen < PATH_MAX) {
					(void) strncpy(nptr, scapset->sc_mach,
					    scapset->sc_machsz);
					nptr = nptr + scapset->sc_machsz;
					olen += MSG_TKN_MACHINE_SIZE;
					optr += MSG_TKN_MACHINE_SIZE;
					_flags |= PD_TKN_MACHINE;
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
			if (((omit & PD_TKN_OSNAME) == 0) && (uts == NULL))
				uts = conv_uts();

			if (((omit & PD_TKN_OSNAME) == 0) &&
			    (uts && uts->uts_osnamesz)) {
				if ((nlen += uts->uts_osnamesz) < PATH_MAX) {
					(void) strncpy(nptr, uts->uts_osname,
					    uts->uts_osnamesz);
					nptr = nptr + uts->uts_osnamesz;
					olen += MSG_TKN_OSNAME_SIZE;
					optr += MSG_TKN_OSNAME_SIZE;
					_flags |= PD_TKN_OSNAME;
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
			if (((omit & PD_TKN_OSREL) == 0) && (uts == 0))
				uts = conv_uts();

			if (((omit & PD_TKN_OSREL) == 0) &&
			    (uts && uts->uts_osrelsz)) {
				if ((nlen += uts->uts_osrelsz) < PATH_MAX) {
					(void) strncpy(nptr, uts->uts_osrel,
					    uts->uts_osrelsz);
					nptr = nptr + uts->uts_osrelsz;
					olen += MSG_TKN_OSREL_SIZE;
					optr += MSG_TKN_OSREL_SIZE;
					_flags |= PD_TKN_OSREL;
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
			if ((omit & PD_TKN_ISALIST) || isaflag++)
				ok = 0;
			else
				ok = 1;

			if (ok && (isa == NULL))
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
					_flags |= PD_TKN_ISALIST;
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
					if ((_list = lptr =
					    malloc(mlen)) == NULL)
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

		} else if (strncmp(optr, MSG_ORIG(MSG_TKN_CAPABILITY),
		    MSG_TKN_CAPABILITY_SIZE) == 0) {
			char	*bptr = nptr - 1;
			char	*eptr = optr + MSG_TKN_CAPABILITY_SIZE;
			token = (char *)MSG_ORIG(MSG_TKN_CAPABILITY);

			/*
			 * $CAPABILITY expansion required.  Expansion is only
			 * allowed for non-simple path names (must contain a
			 * '/'), with the token itself being the last element
			 * of the path.  Therefore, all we need do is test the
			 * existence of the string "/$CAPABILITY\0".
			 */
			if (((omit & PD_TKN_CAP) == 0) &&
			    ((bptr > _name) && (*bptr == '/') &&
			    ((*eptr == '\0') || (*eptr == ':')))) {
				/*
				 * Decrement the present pointer so that the
				 * directories trailing "/" gets nuked later.
				 */
				nptr--, nlen--;
				olen += MSG_TKN_CAPABILITY_SIZE;
				optr += MSG_TKN_CAPABILITY_SIZE;
				_flags |= PD_TKN_CAP;
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_TKN_HWCAP),
		    MSG_TKN_HWCAP_SIZE) == 0) {
			char	*bptr = nptr - 1;
			char	*eptr = optr + MSG_TKN_HWCAP_SIZE;
			token = (char *)MSG_ORIG(MSG_TKN_HWCAP);

			/*
			 * $HWCAP expansion required.  This token has been
			 * superseeded by $CAPABILITY.  For compatibility with
			 * older environments, only expand this token when hard-
			 * ware capability information is available.   This
			 * expansion is only allowed for non-simple path names
			 * (must contain a '/'), with the token itself being the
			 * last element of the path.  Therefore, all we need do
			 * is test the existence of the string "/$HWCAP\0".
			 */
			if (((omit & PD_TKN_CAP) == 0) &&
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
				_flags |= PD_TKN_CAP;
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
		 * If a reserved token was found, and could not be expanded,
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
				str = strchr(oname, ':');
				if (str != NULL) {
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
	 * path name permutations this would provide is another question.  So,
	 * for now if more than one ISALIST is encountered we return the
	 * original node untouched.
	 */
	if (isa && isaflag) {
		if (isaflag == 1) {
			if (list)
				*list = _list;
		} else {
			flags &= ~PD_TKN_ISALIST;
			if ((nptr = (char *)stravl_insert(*name, 0,
			    (*len + 1), 1)) == NULL)
				return (0);
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
	 * A path that has been expanded is typically used to create full
	 * path names for objects that will be opened.  The final path name is
	 * resolved to simplify it, and set the stage for possible $ORIGIN
	 * processing.  Therefore, it's usually unnecessary to resolve the path
	 * at this point.  However, if a configuration file, containing
	 * directory information is in use, then we might need to lookup this
	 * path in the configuration file.  To keep the number of path name
	 * resolutions to a minimum, only resolve paths that contain "./".  The
	 * use of "$ORIGIN/../lib" will probably only match a configuration file
	 * entry after resolution.
	 */
	if (list && (rtld_flags & RT_FL_DIRCFG) && (flags & TKN_DOTSLASH)) {
		int	len;

		if ((len = resolvepath(_name, _name, (PATH_MAX - 1))) >= 0) {
			nlen = (size_t)len;
			_name[nlen] = '\0';
			flags |= PD_TKN_RESOLVED;
		}
	}

	/*
	 * Allocate a new string if necessary.
	 *
	 * If any form of token expansion, or string resolution has occurred,
	 * the storage must be allocated for the new string.
	 *
	 * If we're processing a substring, for example, any string besides the
	 * last string within a search path "A:B:C", then this substring needs
	 * to be isolated with a null terminator.  However, if this search path
	 * was created from a previous ISALIST expansion, then all strings must
	 * be allocated, as the isalist expansion will be freed after expansion
	 * processing.
	 */
	if ((nptr = (char *)stravl_insert(_name, 0, (nlen + 1), 1)) == NULL)
		return (0);
	*name = nptr;
	*len = nlen;
	return (flags ? flags : TKN_NONE);
}

/*
 * Determine whether a path name is secure.
 */
int
is_path_secure(char *opath, Rt_map *clmp, uint_t info, uint_t flags)
{
	Alist		**salpp;
	Aliste		idx;
	char		buffer[PATH_MAX], *npath = NULL;
	Lm_list		*lml = LIST(clmp);
	Pdesc		*pdp;

	/*
	 * If a path name originates from a configuration file, use it.  The use
	 * of a configuration file is already validated for secure applications,
	 * so if we're using a configuration file, we must be able to use all
	 * that it defines.
	 */
	if (info & LA_SER_CONFIG)
		return (1);

	if ((info & LA_SER_MASK) == 0) {
		char	*str;

		/*
		 * If the path name specifies a file (rather than a directory),
		 * peel off the file before making the comparison.
		 */
		str = strrchr(opath, '/');

		/*
		 * Carry out some initial security checks.
		 *
		 *   .	a simple file name (one containing no "/") is fine, as
		 *	this file name will be combined with search paths to
		 *	determine the complete path.  Note, a secure application
		 *	may provide a configuration file, and this can only be
		 *	a full path name (PN_FLG_FULLPATH).
		 *   .	a full path (one starting with "/") is fine, provided
		 *	this path name isn't a preload/audit path.
		 *   .	provided $ORIGIN expansion has not been employed, the
		 *	above categories of path are deemed secure.
		 */
		if ((((str == 0) && ((info & PD_FLG_FULLPATH) == 0)) ||
		    ((*opath == '/') && (str != opath) &&
		    ((info & PD_FLG_EXTLOAD) == 0))) &&
		    ((flags & PD_TKN_ORIGIN) == 0))
			return (1);

		/*
		 * Determine the directory name of the present path.
		 */
		if (str) {
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

			/*
			 * If $ORIGIN processing has been employed, then allow
			 * any directory that has already been used to satisfy
			 * other dependencies, to be used.
			 */
			if ((flags & PD_TKN_ORIGIN) &&
			    pnavl_recorded(&spavl, npath, 0, NULL)) {
				DBG_CALL(Dbg_libs_insecure(lml, npath, 1));
				return (1);
			}
		}
	} else {
		/*
		 * A search path, i.e., RPATH, configuration file path, etc. is
		 * used as is.  Exceptions to this are:
		 *
		 *   .	LD_LIBRARY_PATH.
		 *   .	any $ORIGIN expansion, unless used by a setuid ld.so.1
		 *	to find its own dependencies, or the path name has
		 *	already been used to find other dependencies.
		 *   .	any relative path.
		 */
		if (((info & LA_SER_LIBPATH) == 0) && (*opath == '/') &&
		    ((flags & PD_TKN_ORIGIN) == 0))
			return (1);

		/*
		 * If $ORIGIN processing is requested, allow a setuid ld.so.1
		 * to use this path for its own dependencies.  Allow the
		 * application to use this path name only if the path name has
		 * already been used to locate other dependencies.
		 */
		if (flags & PD_TKN_ORIGIN) {
			if ((lml->lm_flags & LML_FLG_RTLDLM) &&
			    is_rtld_setuid())
				return (1);
			else if (pnavl_recorded(&spavl, opath, 0, NULL)) {
				DBG_CALL(Dbg_libs_insecure(lml, opath, 1));
				return (1);
			}
		}
		npath = (char *)opath;
	}

	/*
	 * Determine whether the present directory is trusted.
	 */
	if (npath) {
		salpp = LM_SECURE_DIRS(LIST(clmp)->lm_head)();
		for (ALIST_TRAVERSE(*salpp, idx, pdp)) {
			if (strcmp(npath, pdp->pd_pname) == 0)
				return (1);
		}
	}

	/*
	 * The path is insecure, so depending on the caller, provide a
	 * diagnostic.  Preloaded, or audit libraries generate a warning, as
	 * the process will run without them.
	 */
	if (info & PD_FLG_EXTLOAD) {
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
					(void) printf(
					    MSG_INTL(MSG_LDD_FIL_FIND),
					    opath, NAME(clmp));

				if (((rtld_flags & RT_FL_SILENCERR) == 0) ||
				    (lml->lm_flags & LML_FLG_TRC_VERBOSE))
					(void) printf(
					    MSG_INTL(MSG_LDD_FIL_ILLEGAL),
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
		DBG_CALL(Dbg_libs_insecure(lml, opath, 0));
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
is_path_unique(Alist *alp, const char *path)
{
	Aliste	idx;
	Pdesc	*pdp;

	for (ALIST_TRAVERSE(alp, idx, pdp)) {
		if (pdp->pd_plen && (strcmp(pdp->pd_pname, path) == 0))
			return (PD_FLG_DUPLICAT);
	}
	return (0);
}

/*
 * Expand one or more path names.  This routine is called for all path strings,
 * i.e., NEEDED, rpaths, default search paths, configuration file search paths,
 * filtees, etc.  The path may be a single path name, or a colon separated list
 * of path names.  Each individual path name is processed for possible reserved
 * token expansion.  All string nodes are maintained in allocated memory
 * (regardless of whether they are constant (":"), or token expanded) to
 * simplify path name descriptor removal.
 *
 * The info argument passes in auxiliary information regarding the callers
 * intended use of the path names.  This information may be maintained in the
 * path name descriptor element produced to describe the path name (i.e.,
 * LA_SER_LIBPATH etc.), or may be used to determine additional security or
 * diagnostic processing.
 */
int
expand_paths(Rt_map *clmp, const char *list, Alist **alpp, Aliste alni,
    uint_t orig, uint_t omit)
{
	char	*str, *olist = 0, *nlist = (char *)list;
	int	fnull = FALSE;	/* TRUE if empty final path segment seen */
	Pdesc	*pdp = NULL;

	for (str = nlist; *nlist || fnull; str = nlist) {
		char	*ostr;
		char	*elist = NULL;
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

			str = (char *)MSG_ORIG(MSG_FMT_CWD);
			len = MSG_FMT_CWD_SIZE;

		} else {
			uint_t	_tkns;

			len = 0;
			while (*nlist && (*nlist != ':') && (*nlist != ';')) {
				if (*nlist == '/')
					tkns |= PD_FLG_PNSLASH;
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
			if ((_tkns = expand(&str, &len, &elist, orig, omit,
			    clmp)) == 0)
				continue;
			tkns |= _tkns;
		}

		/*
		 * If this a secure application, validation of the expanded
		 * path name may be necessary.
		 */
		if ((rtld_flags & RT_FL_SECURE) &&
		    (is_path_secure(str, clmp, orig, tkns) == 0))
			continue;

		/*
		 * If required, ensure that the string is unique.  For search
		 * paths such as LD_LIBRARY_PATH, users often inherit multiple
		 * paths which result in unnecessary duplication.  Note, if
		 * we're debugging, any duplicate entry is retained and flagged
		 * so that the entry can be diagnosed later as part of unused
		 * processing.
		 */
		if (orig & PD_FLG_UNIQUE) {
			Word	tracing;

			tracing = LIST(clmp)->lm_flags &
			    (LML_FLG_TRC_UNREF | LML_FLG_TRC_UNUSED);
			tkns |= is_path_unique(*alpp, str);

			/*
			 * Note, use the debug strings rpl_debug and prm_debug
			 * as an indicator that debugging has been requested,
			 * rather than DBG_ENABLE(), as the initial use of
			 * LD_LIBRARY_PATH occurs in preparation for loading
			 * our debugging library.
			 */
			if ((tkns & PD_FLG_DUPLICAT) && (tracing == 0) &&
			    (rpl_debug == 0) && (prm_debug == 0))
				continue;
		}

		/*
		 * Create a new pathname descriptor.
		 */
		if ((pdp = alist_append(alpp, NULL, sizeof (Pdesc),
		    alni)) == NULL)
			return (0);

		pdp->pd_pname = str;
		pdp->pd_plen = len;
		pdp->pd_flags = (orig & LA_SER_MASK) | (tkns & PD_MSK_INHERIT);

		/*
		 * If token expansion occurred, maintain the original string.
		 * This string can be used to provide a more informative error
		 * diagnostic for a file that fails to load, or for displaying
		 * unused search paths.
		 */
		if ((tkns & PD_MSK_EXPAND) && ((pdp->pd_oname =
		    stravl_insert(ostr, 0, (olen + 1), 1)) == NULL))
			return (0);

		/*
		 * Now that any duplication of the original string has occurred,
		 * release any previous old listing.
		 */
		if (elist && (elist != nlist)) {
			if (olist)
				free(olist);
			nlist = olist = elist;
		}
	}

	if (olist)
		free(olist);

	/*
	 * If no paths could be determined (perhaps because of security), then
	 * indicate a failure.
	 */
	return (pdp != NULL);
}

/*
 * Establish an objects fully resolved path.
 *
 * When $ORIGIN was first introduced, the expansion of a relative path name was
 * deferred until it was required.  However now we insure a full path name is
 * always created - things like the analyzer wish to rely on librtld_db
 * returning a full path.  The overhead of this is perceived to be low,
 * providing the associated libc version of getcwd is available (see 4336878).
 * This getcwd() was ported back to Solaris 8.1.
 */
size_t
fullpath(Rt_map *lmp, Fdesc *fdp)
{
	const char	*name;

	/*
	 * Determine whether this path name is already resolved.
	 */
	if (fdp && (fdp->fd_flags & FLG_FD_RESOLVED)) {
		/*
		 * If the resolved path differed from the original name, the
		 * resolved path would have been recorded as the fd_pname.
		 * Steal this path name from the file descriptor.  Otherwise,
		 * the path name is the same as the name of this object.
		 */
		if (fdp->fd_pname)
			PATHNAME(lmp) = fdp->fd_pname;
		else
			PATHNAME(lmp) = NAME(lmp);
	} else {
		/*
		 * If this path name has not yet been resolved, resolve the
		 * current name.
		 */
		char		_path[PATH_MAX];
		const char	*path;
		int		size, rsize;

		if (fdp && fdp->fd_pname)
			PATHNAME(lmp) = fdp->fd_pname;
		else
			PATHNAME(lmp) = NAME(lmp);

		name = path = PATHNAME(lmp);
		size = strlen(name);

		if (path[0] != '/') {
			/*
			 * If we can't determine the current directory (possible
			 * if too many files are open - EMFILE), or if the
			 * created path is too big, simply revert back to the
			 * initial path name.
			 */
			if (getcwd(_path, (PATH_MAX - 2 - size)) != NULL) {
				(void) strcat(_path, MSG_ORIG(MSG_STR_SLASH));
				(void) strcat(_path, name);
				path = _path;
				size = strlen(path);
			}
		}

		/*
		 * See if the path name can be reduced further.
		 */
		if ((rsize = resolvepath(path, _path, (PATH_MAX - 1))) > 0) {
			_path[rsize] = '\0';
			path = _path;
			size = rsize;
		}

		/*
		 * If the path name is different from the original, duplicate it
		 * so that it is available in a core file.  If the duplication
		 * fails simply leave the original path name alone.
		 */
		if ((PATHNAME(lmp) =
		    stravl_insert(path, 0, (size + 1), 0)) == NULL)
			PATHNAME(lmp) = name;
	}

	name = ORIGNAME(lmp) = PATHNAME(lmp);

	/*
	 * Establish the directory name size - this also acts as a flag that the
	 * directory name has been computed.
	 */
	DIRSZ(lmp) = strrchr(name, '/') - name;
	return (DIRSZ(lmp));
}
