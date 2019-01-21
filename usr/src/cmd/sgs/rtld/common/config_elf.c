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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<sys/mman.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<limits.h>
#include	<stdio.h>
#include	<string.h>
#include	<rtc.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"msg.h"

static Config	_config = { 0 };
Config		*config = &_config;

/*
 * Validate a configuration file.
 */
static void
elf_config_validate(Addr addr, Rtc_head *head, Rt_map *lmp)
{
	Lm_list		*lml = LIST(lmp);
	const char	*str, *strtbl = config->c_strtbl;
	Rtc_obj		*obj;
	Rtc_dir		*dirtbl;
	Rtc_file	*filetbl;
	rtld_stat_t	status;
	int		err;

	/*
	 * If this configuration file is for a specific application make sure
	 * we've been invoked by the application.  Note that we only check the
	 * basename component of the application as the original application
	 * and its cached equivalent are never going to have the same pathnames.
	 * Also, we use PATHNAME() and not NAME() - this catches things like vi
	 * that exec shells using execv(/usr/bin/ksh, sh ...).
	 */
	if (head->ch_app) {
		char		*_str, *_cname, *cname;
		const char	*aname = PATHNAME(lmp);

		obj = (Rtc_obj *)(head->ch_app + addr);
		cname = _cname = (char *)(strtbl + obj->co_name);

		if ((_str = strrchr(aname, '/')) != NULL)
			aname = ++_str;
		if ((_str = strrchr(cname, '/')) != NULL)
			cname = ++_str;

		if (strcmp(aname, cname)) {
			/*
			 * It's possible a user is trying to ldd(1) an alternate
			 * shared object and point to a configuration file that
			 * the shared object is part of.  In this case ignore
			 * any mismatch name warnings.
			 */
			if ((lml->lm_flags & LML_FLG_TRC_ENABLE) &&
			    ((FLAGS1(lmp) & FL1_RT_LDDSTUB) == 0)) {
				eprintf(lml, ERR_WARNING,
				    MSG_INTL(MSG_CONF_APP), config->c_name,
				    _cname);
				return;
			}
		}

		/*
		 * If we have a valid alternative application reset its original
		 * name for possible $ORIGIN processing.
		 */
		if ((FLAGS1(lmp) & FL1_RT_LDDSTUB) == 0) {
			ORIGNAME(lmp) = _cname;
			DIRSZ(lmp) = cname - _cname - 1;
		}
	}

	/*
	 * If alternative objects are specified traverse the directories
	 * specified in the configuration file, if any directory is newer than
	 * the time it was recorded in the cache then continue to inspect its
	 * files.  Any file determined newer than its configuration recording
	 * questions the the use of any alternative objects.  The intent here
	 * is to make sure no-one abuses a configuration as a means of static
	 * linking.
	 */
	for (dirtbl = (Rtc_dir *)(head->ch_dir + addr);
	    dirtbl->cd_obj; dirtbl++) {
		/*
		 * Skip directories that provide no files - this also catches
		 * RTC_OBJ_NOEXIST directories.
		 */
		filetbl = (Rtc_file *)(dirtbl->cd_file + addr);
		if (filetbl->cf_obj == 0)
			continue;

		/*
		 * Skip directories that haven't provided real, dumped files.
		 */
		obj = (Rtc_obj *)(dirtbl->cd_obj + addr);
		if ((obj->co_flags & (RTC_OBJ_DUMP | RTC_OBJ_REALPTH)) !=
		    (RTC_OBJ_DUMP | RTC_OBJ_REALPTH))
			continue;

		str = strtbl + obj->co_name;

		if (rtld_stat(str, &status) != 0) {
			err = errno;
			eprintf(lml, ERR_WARNING, MSG_INTL(MSG_CONF_DSTAT),
			    config->c_name, str, strerror(err));
			continue;
		}

		if (status.st_mtime == obj->co_info)
			continue;

		/*
		 * The system directory is newer than the configuration files
		 * entry, start checking any dumped files.
		 */
		for (; filetbl->cf_obj; filetbl++) {
			obj = (Rtc_obj *)(filetbl->cf_obj + addr);
			str = strtbl + obj->co_name;

			/*
			 * Skip any files that aren't real, dumped files.
			 */
			if ((obj->co_flags &
			    (RTC_OBJ_DUMP | RTC_OBJ_REALPTH)) !=
			    (RTC_OBJ_DUMP | RTC_OBJ_REALPTH))
				continue;

			if (rtld_stat(str, &status) != 0) {
				err = errno;
				eprintf(lml, ERR_WARNING,
				    MSG_INTL(MSG_CONF_FSTAT), config->c_name,
				    str, strerror(err));
				continue;
			}

			/*
			 * If the files size is different somethings been
			 * changed.
			 */
			if (status.st_size != obj->co_info) {
				eprintf(lml, ERR_WARNING,
				    MSG_INTL(MSG_CONF_FCMP), config->c_name,
				    str);
			}
		}
	}
}

/*
 * Process a configuration file.
 *
 * A configuration file can be specified using the LD_CONFIG environment
 * variable, from a DT_CONFIG string recorded in the executable (see ld(1) -c),
 * or in the case of a crle() dumped image, the file is "fabricated" to a
 * configuration file that may have been associated with the dumped image.  In
 * the absence of any of these techniques, a default configuration file is used.
 *
 * The LD_CONFIG variable take precedence, unless the application is secure, in
 * which case the environment variable is ignored (see ld_generic_env()).
 *
 * A DT_CONFIG string is honored, even if the application is secure.  However,
 * the path name follows the same rules as RUNPATH's, which must be a full path
 * name with no use of $ORIGIN.
 */
int
elf_config(Rt_map *lmp, int aout)
{
	Rtc_id		*id;
	Rtc_head	*head;
	int		fd, features = 0;
	rtld_stat_t	status;
	Addr		addr;
	const char	*str;
	char		path[PATH_MAX];

	/*
	 * If we're dealing with an alternative application, fabricate the need
	 * for a $ORIGIN/ld.config.app-name configuration file.
	 */
	if (rtld_flags & RT_FL_CONFAPP) {
		if ((str = strrchr(PATHNAME(lmp), '/')) != NULL)
			str++;
		else
			str = PATHNAME(lmp);

		(void) snprintf(path, PATH_MAX, MSG_ORIG(MSG_ORG_CONFIG), str);
		str = path;
	} else
		str = config->c_name;

	/*
	 * If a configuration file name is known, expand and verify the name.
	 */
	if (str) {
		size_t	size = strlen(str);
		char	*estr = (char *)str;
		uint_t	tkns;

		/*
		 * Expand any configuration string.
		 */
		if ((tkns = expand(&estr, &size, 0, 0,
		    (PD_TKN_ISALIST | PD_TKN_CAP), lmp)) == 0)
			return (0);

		/*
		 * If this is a secure application, validate the configuration
		 * file path name.  Ignore any untrustworthy path name, and
		 * fall through to pick up the defaults.
		 */
		if ((rtld_flags & RT_FL_SECURE) &&
		    (is_path_secure(estr, lmp, PD_FLG_FULLPATH, tkns) == 0))
			str = NULL;
		else
			str = (const char *)estr;
	}

	/*
	 * If a configuration file has not been specified try opening up the
	 * default.
	 */
	if (str == NULL) {
#if	defined(_ELF64)
		str = MSG_ORIG(MSG_PTH_CONFIG_64);
#else
		str = MSG_ORIG(MSG_PTH_CONFIG);
#endif
	}
	config->c_name = str;

	/*
	 * If we can't open the configuration file return silently.
	 */
	if ((fd = open(str, O_RDONLY, 0)) == -1)
		return (DBG_CONF_PRCFAIL);

	/*
	 * Determine the configuration file size and map the file.
	 */
	(void) rtld_fstat(fd, &status);
	if (status.st_size < sizeof (Rtc_head)) {
		(void) close(fd);
		return (DBG_CONF_CORRUPT);
	}
	if ((addr = (Addr)mmap(0, status.st_size, PROT_READ, MAP_SHARED,
	    fd, 0)) == (Addr)MAP_FAILED) {
		(void) close(fd);
		return (DBG_CONF_PRCFAIL);
	}
	(void) close(fd);

	/*
	 * If we have an Rtc_id block at the beginning, then validate it
	 * and advance the address to the Rtc_head. If not, then trust
	 * that the file is compatible with us and move ahead (there is
	 * some error checking for Rtc_head below as well).
	 */
	id = (Rtc_id *) addr;
	if (RTC_ID_TEST(id)) {
		addr += sizeof (*id);
		status.st_size -= sizeof (*id);
		if (status.st_size < sizeof (Rtc_head))
			return (DBG_CONF_CORRUPT);
		if ((id->id_class != M_CLASS) || (id->id_data != M_DATA) ||
		    (id->id_machine != M_MACH))
			return (DBG_CONF_ABIMISMATCH);
	}

	config->c_bgn = addr;
	config->c_end = addr + status.st_size;

	head = (Rtc_head *)addr;

	/*
	 * Make sure we can handle this version of the configuration file.
	 */
	if (head->ch_version > RTC_VER_CURRENT)
		return (DBG_CONF_VERSION);

	/*
	 * When crle(1) creates a temporary configuration file the
	 * RTC_HDR_IGNORE flag is set.  Thus the mapping of the configuration
	 * file is taken into account but not its content.
	 */
	if (head->ch_cnflags & RTC_HDR_IGNORE)
		return (DBG_CONF_IGNORE);

	/*
	 * Apply any new default library pathname.
	 */
	if (head->ch_edlibpath) {
		str = (const char *)(head->ch_edlibpath + addr);
#ifndef	SGS_PRE_UNIFIED_PROCESS
		if ((head->ch_cnflags & RTC_HDR_UPM) == 0) {
#if	defined(_ELF64)
			str = conv_config_upm(str, MSG_ORIG(MSG_PTH_USRLIB_64),
			    MSG_ORIG(MSG_PTH_LIB_64), MSG_PTH_LIB_64_SIZE);
#else
			str = conv_config_upm(str, MSG_ORIG(MSG_PTH_USRLIB),
			    MSG_ORIG(MSG_PTH_LIB), MSG_PTH_LIB_SIZE);
#endif
		}
#endif
		if (expand_paths(lmp, str, &elf_def_dirs, AL_CNT_SEARCH,
		    (LA_SER_DEFAULT | LA_SER_CONFIG), PD_TKN_CAP) != 0)
			features |= CONF_EDLIBPATH;
	}
	if (head->ch_eslibpath) {
		str = (const char *)(head->ch_eslibpath + addr);
#ifndef	SGS_PRE_UNIFIED_PROCESS
		if ((head->ch_cnflags & RTC_HDR_UPM) == 0) {
#if	defined(_ELF64)
			str = conv_config_upm(str,
			    MSG_ORIG(MSG_PTH_USRLIBSE_64),
			    MSG_ORIG(MSG_PTH_LIBSE_64), MSG_PTH_LIBSE_64_SIZE);
#else
			str = conv_config_upm(str, MSG_ORIG(MSG_PTH_USRLIBSE),
			    MSG_ORIG(MSG_PTH_LIBSE), MSG_PTH_LIBSE_SIZE);
#endif
		}
#endif
		if (expand_paths(lmp, str, &elf_sec_dirs, AL_CNT_SEARCH,
		    (LA_SER_SECURE | LA_SER_CONFIG), PD_TKN_CAP) != 0)
			features |= CONF_ESLIBPATH;
	}
#if	defined(__sparc) && !defined(_ELF64)
	if (head->ch_adlibpath) {
		str = (const char *)(head->ch_adlibpath + addr);
		if (expand_paths(lmp, str, &aout_def_dirs, AL_CNT_SEARCH,
		    (LA_SER_DEFAULT | LA_SER_CONFIG), PD_TKN_CAP) != 0)
			features |= CONF_ADLIBPATH;
	}
	if (head->ch_aslibpath) {
		str = (const char *)(head->ch_aslibpath + addr);
		if (expand_paths(lmp, str, &aout_sec_dirs, AL_CNT_SEARCH,
		    (LA_SER_SECURE | LA_SER_CONFIG), PD_TKN_CAP) != 0)
			features |= CONF_ASLIBPATH;
	}
#endif
	/*
	 * Apply any environment variables.  This attribute was added with
	 * RTC_VER_THREE.
	 */
	if ((head->ch_version >= RTC_VER_THREE) && head->ch_env &&
	    (!(rtld_flags & RT_FL_NOENVCFG))) {
		if (readenv_config((Rtc_env *)(head->ch_env + addr),
		    addr, aout) != 0)
			return (-1);
		features |= CONF_ENVS;
	}

	/*
	 * Determine whether filter/filtee associations are available.
	 */
	if ((head->ch_version >= RTC_VER_FOUR) && head->ch_fltr &&
	    (!(rtld_flags2 & RT_FL2_NOFLTCFG))) {
		rtld_flags2 |= RT_FL2_FLTCFG;
		config->c_fltr = (Rtc_fltr *)(head->ch_fltr + addr);
		config->c_flte = (Rtc_flte *)(head->ch_flte + addr);
		features |= CONF_FLTR;
	}

	/*
	 * Determine whether directory configuration is available.
	 */
	if ((!(rtld_flags & RT_FL_NODIRCFG)) && head->ch_hash) {
		config->c_hashtbl = (Word *)(head->ch_hash + addr);
		config->c_hashchain = &config->c_hashtbl[2 +
		    config->c_hashtbl[0]];
		config->c_objtbl = (Rtc_obj *)(head->ch_obj + addr);
		config->c_strtbl = (const char *)(head->ch_str + addr);

		rtld_flags |= RT_FL_DIRCFG;
		features |= CONF_DIRCFG;
	}

	/*
	 * Determine whether alternative objects are specified or an object
	 * reservation area is required.  If the reservation can't be completed
	 * (either because the configuration information is out-of-date, or the
	 * the reservation can't be allocated), then alternative objects are
	 * ignored.
	 */
	if ((!(rtld_flags & (RT_FL_NODIRCFG | RT_FL_NOOBJALT))) &&
	    (head->ch_cnflags & RTC_HDR_ALTER)) {
		rtld_flags |= RT_FL_OBJALT;
		features |= CONF_OBJALT;

		elf_config_validate(addr, head, lmp);

		if (head->ch_resbgn) {

			if (((config->c_bgn <= head->ch_resbgn) &&
			    (config->c_bgn >= head->ch_resend)) ||
			    (nu_map(LIST(lmp),
			    (caddr_t)(uintptr_t)head->ch_resbgn,
			    (head->ch_resend - head->ch_resbgn), PROT_NONE,
			    MAP_FIXED | MAP_PRIVATE) == MAP_FAILED))
				return (-1);

			rtld_flags |= RT_FL_MEMRESV;
			features |= CONF_MEMRESV;
		}
	}

	return (features);
}

/*
 * Determine whether the given file exists in the configuration file.
 */
Rtc_obj *
elf_config_ent(const char *name, Word hash, int id, const char **alternate)
{
	Word		bkt, ndx;
	const char	*str;
	Rtc_obj		*obj;

	bkt = hash % config->c_hashtbl[0];
	ndx = config->c_hashtbl[2 + bkt];

	while (ndx) {
		obj = config->c_objtbl + ndx;
		str = config->c_strtbl + obj->co_name;

		if ((obj->co_hash != hash) || (strcmp(name, str) != 0) ||
		    (id && (id != obj->co_id))) {
			ndx = config->c_hashchain[ndx];
			continue;
		}

		if ((obj->co_flags & RTC_OBJ_ALTER) && alternate)
			*alternate = config->c_strtbl + obj->co_alter;

		return (obj);
	}
	return (0);
}

/*
 * Determine whether a filter and filtee string pair exists in the configuration
 * file.  If so, return the cached filtees that are associated with this pair as
 * an Alist.
 */
void
elf_config_flt(Lm_list *lml, const char *filter, const char *string,
    Alist **alpp, Aliste alni)
{
	Rtc_fltr	*fltrtbl;

	for (fltrtbl = (Rtc_fltr *)config->c_fltr; fltrtbl->fr_filter;
	    fltrtbl++) {
		Rtc_flte	*fltetbl;
		const char	*fltr, *str;

		fltr = config->c_strtbl + fltrtbl->fr_filter;
		str = config->c_strtbl + fltrtbl->fr_string;
		if (strcmp(filter, fltr) || strcmp(string, str))
			continue;

		/*
		 * Create a path descriptor for each filtee associated with this
		 * filter/filtee string pair.  Note, no expansion of filtee
		 * entries is called for, as any original expansion would have
		 * been carried out before they were recorded in the
		 * configuration file.
		 */
		/* LINTED */
		for (fltetbl = (Rtc_flte *)((char *)config->c_flte +
		    fltrtbl->fr_filtee); fltetbl->fe_filtee; fltetbl++) {
			const char	*flte;
			Pdesc		*pdp;

			flte = config->c_strtbl + fltetbl->fe_filtee;

			if ((pdp = alist_append(alpp, NULL, sizeof (Pdesc),
			    alni)) == NULL)
				return;

			pdp->pd_pname = (char *)flte;
			pdp->pd_plen = strlen(flte) + 1;
			pdp->pd_flags = LA_SER_CONFIG;

			DBG_CALL(Dbg_file_filter(lml, fltr, flte, 1));
		}
	}
}
