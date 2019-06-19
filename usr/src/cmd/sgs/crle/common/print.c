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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mman.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>
#include	<limits.h>
#include	"sgs.h"
#include	"rtc.h"
#include	"conv.h"
#include	"_crle.h"
#include	"msg.h"


/*
 * Display the command line required to regenerate the configuration file.
 *
 * Under normal mode the command is printed on one line to make it more
 * available for grep(1) use.  Under verbose mode the command is separated
 * into each argument (a little more readable perhaps when the arguments are
 * numerous of have long pathnames).
 *
 * Note that for version 1 configuration files we never used to generate any
 * command-line information, and as the attempt to do so is only a best effort
 * don't bother printing anything.
 */
static void
printcmd(Crle_desc *crle, Rtc_head * head, APlist *cmdline)
{
	Aliste		idx, lidx;
	const char	*fmto, *fmtb, *fmtm, *fmte;
	char		*cmd;
	int		output = 0;

	if (crle->c_flags & CRLE_VERBOSE) {
		fmto = MSG_INTL(MSG_DMP_CMD_ONE_V);
		fmtb = MSG_INTL(MSG_DMP_CMD_BGN_V);
		fmtm = MSG_INTL(MSG_DMP_CMD_MID_V);
		fmte = MSG_INTL(MSG_DMP_CMD_END_V);

	} else if (head->ch_version > RTC_VER_ONE) {
		fmto = MSG_INTL(MSG_DMP_CMD_ONE);
		fmtb = MSG_INTL(MSG_DMP_CMD_BGN);
		fmtm = MSG_INTL(MSG_DMP_CMD_MID);
		fmte = MSG_INTL(MSG_DMP_CMD_END);

	} else {
		(void) printf(MSG_ORIG(MSG_STR_NL));
		return;
	}

	(void) printf(MSG_INTL(MSG_DMP_CMD_TITLE));

	lidx = aplist_nitems(cmdline) - 1;
	for (APLIST_TRAVERSE(cmdline, idx, cmd)) {
		if (output++ == 0) {
			if (idx < lidx)
				(void) printf(fmtb, cmd);
			else
				(void) printf(fmto, cmd);
		} else {
			if (idx < lidx)
				(void) printf(fmtm, cmd);
			else
				(void) printf(fmte, cmd);
		}
	}
}

/*
 * Establish the argument required to generate the associated object.
 */
static const char *
getformat(Half flags)
{
	if (flags & RTC_OBJ_ALTER) {
		if (flags & RTC_OBJ_DUMP) {
			if (flags & RTC_OBJ_GROUP)
				return (MSG_ORIG(MSG_CMD_DUMPGRP));
			else
				return (MSG_ORIG(MSG_CMD_DUMPIND));
		} else {
			if (flags & RTC_OBJ_OPTINAL)
				return (MSG_ORIG(MSG_CMD_OPTIONAL));
			else
				return (MSG_ORIG(MSG_CMD_ALTER));
		}
	} else {
		if (flags & RTC_OBJ_GROUP)
			return (MSG_ORIG(MSG_CMD_GRP));
		else
			return (MSG_ORIG(MSG_CMD_IND));
	}
}

/*
 * Fabricate a system default search path.  If an update is requested, and
 * new search paths are specified while no configuration file exists, or if a
 * configuration file does exist but doesn't specify this particular search
 * path, create any system defaults.  The intent is to allow
 * "crle -u -l/usr/local/lib" and have this append the search path to the
 * system default, rather than have the user have to determine and specify
 * this default themselves.
 */
static int
fablib(Crle_desc * crle, int flag)
{
	const char	*path;
	char		**list;

	switch (flag) {
	case CRLE_EDLIB:
#if M_CLASS == ELFCLASS64
#ifndef	SGS_PRE_UNIFIED_PROCESS
		path = MSG_ORIG(MSG_PTH_NEWDLP_64);
#else
		path = MSG_ORIG(MSG_PTH_OLDDLP_64);
#endif
#else
#ifndef	SGS_PRE_UNIFIED_PROCESS
		path = MSG_ORIG(MSG_PTH_NEWDLP);
#else
		path = MSG_ORIG(MSG_PTH_OLDDLP);
#endif
#endif
		list = &crle->c_edlibpath;
		break;

	case CRLE_ESLIB:
#if M_CLASS == ELFCLASS64
#ifndef	SGS_PRE_UNIFIED_PROCESS
		path = MSG_ORIG(MSG_PTH_NEWTD_64);
#else
		path = MSG_ORIG(MSG_PTH_OLDTD_64);
#endif
#else
#ifndef	SGS_PRE_UNIFIED_PROCESS
		path = MSG_ORIG(MSG_PTH_NEWTD);
#else
		path = MSG_ORIG(MSG_PTH_OLDTD);
#endif
#endif
		list = &crle->c_eslibpath;
		break;

	case CRLE_ADLIB:
		path = MSG_ORIG(MSG_PTH_AOUTDLP);
		list = &crle->c_adlibpath;
		break;

	case CRLE_ASLIB:
#ifndef	SGS_PRE_UNIFIED_PROCESS
		path = MSG_ORIG(MSG_PTH_NEWTD);
#else
		path = MSG_ORIG(MSG_PTH_OLDTD);
#endif
		list = &crle->c_aslibpath;
		break;

	default:
		return (1);
	}

	return (addlib(crle, list, path));
}

/*
 * Establish the flags required to generate the associated object.  Actually
 * the flags are already part of the object being inspected from the present
 * configuration file, but instead of using them all, which can cause some
 * unsuspected propagation down the inspect() family, only use those flags that
 * would have been contributed from crle()'s calls to inspect.
 */
static Half
getflags(Half flags)
{
	flags &=
	    (RTC_OBJ_ALTER | RTC_OBJ_DUMP | RTC_OBJ_GROUP | RTC_OBJ_OPTINAL);
	return (flags | RTC_OBJ_CMDLINE);
}

/*
 * Dump a configuration files information.  This routine is very close to the
 * scanconfig() in libcrle.
 */
/*ARGSUSED2*/
static INSCFG_RET
scanconfig(Crle_desc * crle, Addr addr, int c_class)
{
	Conv_inv_buf_t		inv_buf1, inv_buf2, inv_buf3, inv_buf4;
	Conv_dl_flag_buf_t	dl_flag_buf;
	Rtc_id		*id;
	Rtc_head	*head;
	Rtc_dir		*dirtbl;
	Rtc_file	*filetbl;
	Rtc_obj		*objtbl, *obj;
	Word		*hash, *chain;
	const char	*strtbl;
	int		ndx, bkts;
	APlist		*cmdline = NULL;
	char		_cmd[PATH_MAX], *cmd;
	char		_objdir[PATH_MAX], *objdir = NULL;

	/*
	 * If there is an Rtc_id present, the Rtc_head follows it.
	 * Otherwise, it is at the top.
	 */
	if (RTC_ID_TEST(addr)) {
		id = (Rtc_id *) addr;
		addr += sizeof (*id);	/* Rtc_head follows */
	} else {
		id = NULL;
		/*
		 * When updating an existing config file that is lacking
		 * the Rtc_id block, don't put one into the resulting file.
		 */
		crle->c_flags &= ~CRLE_ADDID;
	}
	head = (Rtc_head *) addr;


	/*
	 * The rest of the configuration file can only be examined by
	 * a program of the same ELFCLASS, byte order, and hardware
	 * architecture as the one that created it.
	 */
#ifdef _ELF64
	/* 64-bit program with an existing 32-bit file? Abort. */
	if (!(head->ch_cnflags & RTC_HDR_64)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ARG_CLASS),
		    crle->c_name, crle->c_confil);
		return (INSCFG_RET_FAIL);
	}
#else
	/* 32-bit program with an existing 64-bit file? Restart. */
	if (head->ch_cnflags & RTC_HDR_64)
		return (INSCFG_RET_NEED64);

	/*
	 * 32-bit program with an existing 32-bit file, but the
	 * user specified the -64 option? Abort
	 */
	if (c_class != ELFCLASS32) {
		(void) fprintf(stderr, MSG_INTL(MSG_ARG_CLASS),
		    crle->c_name, crle->c_confil);
		return (INSCFG_RET_FAIL);
	}
#endif
	/*
	 * Now that the ELFCLASS has been settled, ensure that the
	 * byte order and hardware match. Unlike ELFCLASS, where restarting
	 * the other version is an option, we cannot work around a mismatch
	 * of these attributes.
	 */
	if (id) {		/* Rtc_id is present */
		/*
		 * Was the file produced by compatible hardware?
		 * ELFCLASS doesn't matter here, because we can
		 * adjust for that, but byte order and machine type do.
		 */
		if ((id->id_data != M_DATA) || (id->id_machine != M_MACH)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ARG_WRONGARCH),
			    crle->c_name, crle->c_confil,
			    conv_ehdr_data(id->id_data, CONV_FMT_ALT_FILE,
			    &inv_buf1),
			    conv_ehdr_mach(id->id_machine, CONV_FMT_ALT_FILE,
			    &inv_buf2),
			    conv_ehdr_data(M_DATA, CONV_FMT_ALT_FILE,
			    &inv_buf3),
			    conv_ehdr_mach(M_MACH, CONV_FMT_ALT_FILE,
			    &inv_buf4));
			return (INSCFG_RET_FAIL);
		}
	}


	/* LINTED */
	objtbl = (Rtc_obj *)(CAST_PTRINT(char *, head->ch_obj) + addr);
	strtbl = (const char *)(CAST_PTRINT(char *, head->ch_str) + addr);

	/*
	 * If the configuration file has a version higher than we
	 * recognise, we face two issues:
	 *	(1) Updates are not possible because we have no
	 *		way to recognise or propagate the new features.
	 *		This has to be a fatal error.
	 *	(2) Printing has the risk that we may have been
	 *		handed something other than a real config file, as
	 *		well as the fact that we can't display the information
	 *		for the new features. So, we print a warning, but
	 *		continue on to do the best we can with it.
	 */
	if (head->ch_version > RTC_VER_CURRENT) {
		if (crle->c_flags & CRLE_UPDATE) {
			(void) fprintf(stderr, MSG_INTL(MSG_ARG_UPDATEVER),
			    crle->c_name, crle->c_confil,
			    (int)head->ch_version, RTC_VER_CURRENT);
			return (INSCFG_RET_FAIL);
		} else {
			(void) fprintf(stderr, MSG_INTL(MSG_ARG_PRINTVER),
			    crle->c_name, crle->c_confil,
			    (int)head->ch_version, RTC_VER_CURRENT);
		}
	}

	/*
	 * If this is a version 1 configuration file we can't generate accurate
	 * update information, or the command-line used to create the file.
	 */
	if (head->ch_version == RTC_VER_ONE) {
		(void) printf(MSG_INTL(MSG_ARG_UPDATE), crle->c_name,
		    crle->c_confil, (int)head->ch_version);
	}


	if (!(crle->c_flags & CRLE_UPDATE) && (head->ch_cnflags & RTC_HDR_64)) {
		/*
		 * Construct the original command line argument.
		 */
		cmd = strdupa(MSG_ORIG(MSG_CMD_64));
		if (aplist_append(&cmdline, cmd, AL_CNT_CRLE) == NULL)
			return (INSCFG_RET_FAIL);
	}


	/*
	 * Start analyzing the configuration files header information.
	 */
	if ((crle->c_flags & CRLE_UPDATE) == 0) {
		const char	*fmt;

		if (head->ch_dlflags)
			fmt = conv_dl_flag(head->ch_dlflags, 0, &dl_flag_buf);
		else
			fmt = MSG_ORIG(MSG_STR_EMPTY);

		(void) printf(MSG_INTL(MSG_DMP_HEAD), (int)head->ch_version,
		    crle->c_confil, fmt);

		/*
		 * If the file has an id block, show the information
		 */
		if (id)
			(void) printf(MSG_INTL(MSG_DMP_PLATFORM),
			    conv_ehdr_class(id->id_class, CONV_FMT_ALT_FILE,
			    &inv_buf1),
			    conv_ehdr_data(id->id_data, CONV_FMT_ALT_FILE,
			    &inv_buf2),
			    conv_ehdr_mach(id->id_machine, CONV_FMT_ALT_FILE,
			    &inv_buf3));

		/*
		 * Construct the original command line argument.
		 */
		(void) snprintf(_cmd, PATH_MAX, MSG_ORIG(MSG_CMD_CONF),
		    crle->c_confil);
		cmd = strdupa(_cmd);
		if (aplist_append(&cmdline, cmd, AL_CNT_CRLE) == NULL)
			return (INSCFG_RET_FAIL);

		/*
		 * Construct any -f usage.
		 */
		if (head->ch_dlflags &&
		    (head->ch_dlflags != RTLD_REL_RELATIVE)) {
			(void) snprintf(_cmd, PATH_MAX, MSG_ORIG(MSG_CMD_FLAGS),
			    conv_dl_flag(head->ch_dlflags, CONV_FMT_ALT_CRLE,
			    &dl_flag_buf));
			cmd = strdupa(_cmd);
			if (aplist_append(&cmdline, cmd, AL_CNT_CRLE) == NULL)
				return (INSCFG_RET_FAIL);
		}
	} else {
		/*
		 * Establish any -f usage.
		 */
		if (head->ch_dlflags &&
		    (head->ch_dlflags != RTLD_REL_RELATIVE))
			crle->c_dlflags = head->ch_dlflags;
	}


	/*
	 * Determine if this configuration file is only applicable to a specific
	 * application.
	 */
	if (head->ch_app) {
		char	*alter;

		obj = (Rtc_obj *)(head->ch_app + addr);

		/*
		 * Determine the output directory for the files
		 * alternative name.
		 */
		alter = (char *)(strtbl + obj->co_alter);
		(void) strcpy(_objdir, alter);
		alter = strrchr(_objdir, '/');
		*alter = '\0';

		crle->c_objdir = objdir = _objdir;

		if (crle->c_flags & CRLE_UPDATE) {
			if (inspect(crle, (strtbl + obj->co_name),
			    (RTC_OBJ_DUMP | RTC_OBJ_ALTER |
			    RTC_OBJ_GROUP | RTC_OBJ_CMDLINE)) != 0)
				return (INSCFG_RET_FAIL);
		} else {
			(void) printf(MSG_INTL(MSG_DMP_APP),
			    (strtbl + obj->co_alter), (strtbl + obj->co_name));

			/*
			 * Construct the original command line arguments.
			 */
			(void) snprintf(_cmd, PATH_MAX,
			    MSG_ORIG(MSG_CMD_OUTPUT), crle->c_objdir);
			cmd = strdupa(_cmd);
			if (aplist_append(&cmdline, cmd, AL_CNT_CRLE) == NULL)
				return (INSCFG_RET_FAIL);

			(void) snprintf(_cmd, PATH_MAX,
			    MSG_ORIG(MSG_CMD_DUMPGRP), (strtbl + obj->co_name));
			cmd = strdupa(_cmd);
			if (aplist_append(&cmdline, cmd, AL_CNT_CRLE) == NULL)
				return (INSCFG_RET_FAIL);
		}
	}

	/*
	 * Analyze any alternative library path and trusted directory entries.
	 */
	if (head->ch_edlibpath) {
		const char	*str;

		str = (const char *)(head->ch_edlibpath + addr);

		if (crle->c_flags & CRLE_UPDATE) {
			crle->c_flags &= ~CRLE_AOUT;

#ifndef	SGS_PRE_UNIFIED_PROCESS
			if ((head->ch_cnflags & RTC_HDR_UPM) == 0) {
				if (head->ch_cnflags & RTC_HDR_64)
					str = conv_config_upm(str,
					    MSG_ORIG(MSG_PTH_OLDDLP_64),
					    MSG_ORIG(MSG_PTH_UPDLP_64),
					    MSG_PTH_UPDLP_64_SIZE);
				else
					str = conv_config_upm(str,
					    MSG_ORIG(MSG_PTH_OLDDLP),
					    MSG_ORIG(MSG_PTH_UPDLP),
					    MSG_PTH_UPDLP_SIZE);
			}
#endif
			if (addlib(crle, &crle->c_edlibpath, str) != 0)
				return (INSCFG_RET_FAIL);
		} else {
			(void) printf(MSG_INTL(MSG_DMP_DLIBPTH),
			    MSG_ORIG(MSG_STR_ELF), str);

			(void) snprintf(_cmd, PATH_MAX,
			    MSG_ORIG(MSG_CMD_EDLIB), str);
			cmd = strdupa(_cmd);
			if (aplist_append(&cmdline, cmd, AL_CNT_CRLE) == NULL)
				return (INSCFG_RET_FAIL);
		}
	} else {
		if (crle->c_flags & CRLE_UPDATE) {
			if (crle->c_flags & CRLE_EDLIB) {
				/*
				 * If we've been asked to update a configuration
				 * file, and no existing default ELF search
				 * path exists, but the user is going to add new
				 * entries, fabricate the system defaults so
				 * that the users get added to them.
				 */
				if (fablib(crle, CRLE_EDLIB) != 0)
					return (INSCFG_RET_FAIL);
			}
		} else {
			/*
			 * Indicate any system default.
			 */
#if M_CLASS == ELFCLASS64
#ifndef	SGS_PRE_UNIFIED_PROCESS
			(void) printf(MSG_INTL(MSG_DEF_NEWDLP_64));
#else
			(void) printf(MSG_INTL(MSG_DEF_OLDDLP_64));
#endif
#else
#ifndef	SGS_PRE_UNIFIED_PROCESS
			(void) printf(MSG_INTL(MSG_DEF_NEWDLP));
#else
			(void) printf(MSG_INTL(MSG_DEF_OLDDLP));
#endif
#endif
		}
	}

	if (head->ch_eslibpath) {
		const char	*str;

		str = (const char *)(head->ch_eslibpath + addr);

		if (crle->c_flags & CRLE_UPDATE) {
			crle->c_flags &= ~CRLE_AOUT;

#ifndef	SGS_PRE_UNIFIED_PROCESS
			if ((head->ch_cnflags & RTC_HDR_UPM) == 0) {
				if (head->ch_cnflags & RTC_HDR_64)
					str = conv_config_upm(str,
					    MSG_ORIG(MSG_PTH_OLDTD_64),
					    MSG_ORIG(MSG_PTH_UPTD_64),
					    MSG_PTH_UPTD_64_SIZE);
				else
					str = conv_config_upm(str,
					    MSG_ORIG(MSG_PTH_OLDTD),
					    MSG_ORIG(MSG_PTH_UPTD),
					    MSG_PTH_UPTD_SIZE);
			}
#endif
			if (addlib(crle, &crle->c_eslibpath, str) != 0)
				return (INSCFG_RET_FAIL);
		} else {
			(void) printf(MSG_INTL(MSG_DMP_TLIBPTH),
			    MSG_ORIG(MSG_STR_ELF), str);

			(void) snprintf(_cmd, PATH_MAX,
			    MSG_ORIG(MSG_CMD_ESLIB), str);
			cmd = strdupa(_cmd);
			if (aplist_append(&cmdline, cmd, AL_CNT_CRLE) == NULL)
				return (INSCFG_RET_FAIL);
		}
	} else {
		if (crle->c_flags & CRLE_UPDATE) {
			if (crle->c_flags & CRLE_ESLIB) {
				/*
				 * If we've been asked to update a configuration
				 * file, and no existing default ELF secure
				 * path exists, but the user is going to add new
				 * entries, fabricate the system defaults so
				 * that the users get added to them.
				 */
				if (fablib(crle, CRLE_ESLIB) != 0)
					return (INSCFG_RET_FAIL);
			}
		} else {
			/*
			 * Indicate any system default.
			 */
#if M_CLASS == ELFCLASS64
#ifndef	SGS_PRE_UNIFIED_PROCESS
			(void) printf(MSG_INTL(MSG_DEF_NEWTD_64));
#else
			(void) printf(MSG_INTL(MSG_DEF_OLDTD_64));
#endif
#else
#ifndef	SGS_PRE_UNIFIED_PROCESS
			(void) printf(MSG_INTL(MSG_DEF_NEWTD));
#else
			(void) printf(MSG_INTL(MSG_DEF_OLDTD));
#endif
#endif
		}
	}

	if (head->ch_adlibpath) {
		const char	*str;

		str = (const char *)(head->ch_adlibpath + addr);

		if (crle->c_flags & CRLE_UPDATE) {
			crle->c_flags |= CRLE_AOUT;
			if (addlib(crle, &crle->c_adlibpath, str) != 0)
				return (INSCFG_RET_FAIL);
		} else {
			(void) printf(MSG_INTL(MSG_DMP_DLIBPTH),
			    MSG_ORIG(MSG_STR_AOUT), str);

			(void) snprintf(_cmd, PATH_MAX,
			    MSG_ORIG(MSG_CMD_ADLIB), str);
			cmd = strdupa(_cmd);
			if (aplist_append(&cmdline, cmd, AL_CNT_CRLE) == NULL)
				return (INSCFG_RET_FAIL);
		}
	} else {
		if (crle->c_flags & CRLE_UPDATE) {
			if (crle->c_flags & CRLE_ADLIB) {
				/*
				 * If we've been asked to update a configuration
				 * file, and no existing default AOUT search
				 * path exists, but the user is going to add new
				 * entries, fabricate the system defaults so
				 * that the users get added to them.
				 */
				if (fablib(crle, CRLE_ADLIB) != 0)
					return (INSCFG_RET_FAIL);
			}
		} else if (crle->c_flags & CRLE_AOUT) {
			/*
			 * Indicate any system default.
			 */
			(void) printf(MSG_INTL(MSG_DEF_AOUTDLP));
		}
	}

	if (head->ch_aslibpath) {
		const char	*str;

		str = (const char *)(head->ch_aslibpath + addr);

		if (crle->c_flags & CRLE_UPDATE) {
			crle->c_flags |= CRLE_AOUT;
			if (addlib(crle, &crle->c_aslibpath, str) != 0)
				return (INSCFG_RET_FAIL);
		} else {
			(void) printf(MSG_INTL(MSG_DMP_TLIBPTH),
			    MSG_ORIG(MSG_STR_AOUT), str);

			(void) snprintf(_cmd, PATH_MAX,
			    MSG_ORIG(MSG_CMD_ASLIB), str);
			cmd = strdupa(_cmd);
			if (aplist_append(&cmdline, cmd, AL_CNT_CRLE) == NULL)
				return (INSCFG_RET_FAIL);
		}
	} else {
		if (crle->c_flags & CRLE_UPDATE) {
			if (crle->c_flags & CRLE_ASLIB) {
				/*
				 * If we've been asked to update a configuration
				 * file, and no existing default AOUT secure
				 * path exists, but the user is going to add new
				 * entries, fabricate the system defaults so
				 * that the users get added to them.
				 */
				if (fablib(crle, CRLE_ASLIB) != 0)
					return (INSCFG_RET_FAIL);
			}
		} else if (crle->c_flags & CRLE_AOUT) {
			/*
			 * Indicate any system default.
			 */
#ifndef	SGS_PRE_UNIFIED_PROCESS
			(void) printf(MSG_INTL(MSG_DEF_AOUTNEWTD));
#else
			(void) printf(MSG_INTL(MSG_DEF_AOUTOLDTD));
#endif
		}
	}

	/*
	 * Display any environment variables.
	 */
	if ((head->ch_version >= RTC_VER_THREE) && head->ch_env) {
		Rtc_env	*envtbl;

		if ((crle->c_flags & CRLE_UPDATE) == 0)
			(void) printf(MSG_INTL(MSG_ENV_TITLE));

		for (envtbl = (Rtc_env *)(head->ch_env + addr);
		    envtbl->env_str; envtbl++) {
			const char	*str;

			str = (const char *)(envtbl->env_str + addr);

			if (crle->c_flags & CRLE_UPDATE) {
				if (addenv(crle, str,
				    (envtbl->env_flags | RTC_ENV_CONFIG)) == 0)
					return (INSCFG_RET_FAIL);
			} else {
				const char	*pfmt, *sfmt;

				if (envtbl->env_flags & RTC_ENV_PERMANT) {
					pfmt = MSG_INTL(MSG_ENV_PRM);
					sfmt = MSG_ORIG(MSG_CMD_PRMENV);
				} else {
					pfmt = MSG_INTL(MSG_ENV_RPL);
					sfmt = MSG_ORIG(MSG_CMD_RPLENV);
				}
				(void) printf(pfmt, str);
				(void) snprintf(_cmd, PATH_MAX, sfmt, str);
				cmd = strdupa(_cmd);
				if (aplist_append(&cmdline, cmd,
				    AL_CNT_CRLE) == NULL)
					return (INSCFG_RET_FAIL);
			}
		}
	}

	/*
	 * Display any filter/filtee associations.
	 */
	if ((head->ch_version >= RTC_VER_FOUR) && head->ch_fltr) {
		if ((crle->c_flags & CRLE_UPDATE) == 0) {
			Rtc_fltr	*fltrtbl;
			Rtc_flte	*fltetbl;

			/* LINTED */
			fltrtbl = (Rtc_fltr *)
			    (CAST_PTRINT(char *, head->ch_fltr) + addr);
			/* LINTED */
			fltetbl = (Rtc_flte *)
			    (CAST_PTRINT(char *, head->ch_flte) + addr);

			(void) printf(MSG_INTL(MSG_FLT_TITLE));

			while (fltrtbl->fr_filter) {
				Rtc_flte	*_fltetbl;

				/*
				 * Print the filter and filtee string pair.
				 */
				(void) printf(MSG_INTL(MSG_FLT_FILTER),
				    (strtbl + fltrtbl->fr_filter),
				    (strtbl + fltrtbl->fr_string));

				/*
				 * Print each filtee.
				 */
				/* LINTED */
				for (_fltetbl = (Rtc_flte *)((char *)fltetbl +
				    fltrtbl->fr_filtee); _fltetbl->fe_filtee;
				    _fltetbl++) {
					(void) printf(MSG_INTL(MSG_FLT_FILTEE),
					    (strtbl + _fltetbl->fe_filtee));
				}
				fltrtbl++;
			}
		}
	}

	/*
	 * Display any memory reservations required for any alternative
	 * objects.
	 */
	if (head->ch_resbgn && ((crle->c_flags & CRLE_UPDATE) == 0))
		(void) printf(MSG_INTL(MSG_DMP_RESV),
		    (u_longlong_t)head->ch_resbgn,
		    (u_longlong_t)head->ch_resend,
		    (u_longlong_t)(head->ch_resend - head->ch_resbgn));

	/*
	 * If there's no hash table there's nothing else to process.
	 */
	if (head->ch_hash == 0) {
		if ((crle->c_flags & CRLE_UPDATE) == 0)
			printcmd(crle, head, cmdline);
		return (INSCFG_RET_OK);
	}

	/*
	 * Traverse the directory and filename arrays.
	 */
	for (dirtbl = (Rtc_dir *)(head->ch_dir + addr);
	    dirtbl->cd_obj; dirtbl++) {
		struct stat	status;
		Rtc_obj		*dobj;
		const char	*str;

		dobj = (Rtc_obj *)(dirtbl->cd_obj + addr);
		filetbl = (Rtc_file *)(dirtbl->cd_file + addr);
		str = strtbl + dobj->co_name;

		/*
		 * Simplify recreation by using any command-line directories.
		 * If we're dealing with a version 1 configuration file use
		 * every directory.
		 */
		if ((dobj->co_flags & RTC_OBJ_CMDLINE) ||
		    (head->ch_version == RTC_VER_ONE)) {
			if (crle->c_flags & CRLE_UPDATE) {
				if (inspect(crle, str,
				    getflags(dobj->co_flags)) != 0)
					return (INSCFG_RET_FAIL);
				if ((dobj->co_flags &
				    (RTC_OBJ_NOEXIST | RTC_OBJ_ALTER)) ==
				    RTC_OBJ_NOEXIST)
					continue;
			} else {
				/* LINTED */
				(void) snprintf(_cmd, PATH_MAX,
				    getformat(dobj->co_flags), str);
				cmd = strdupa(_cmd);
				if (aplist_append(&cmdline, cmd,
				    AL_CNT_CRLE) == NULL)
					return (INSCFG_RET_FAIL);
			}
		}

		/*
		 * If this isn't an update print the directory name.  If the
		 * directory has no entries (possible if the directory is a
		 * symlink to another directory, in which case we record the
		 * real path also), don't bother printing it unless we're in
		 * verbose mode.
		 */
		if ((crle->c_flags & CRLE_UPDATE) == 0) {
			if ((dobj->co_flags &
			    (RTC_OBJ_NOEXIST | RTC_OBJ_ALTER)) ==
			    RTC_OBJ_NOEXIST) {
				(void) printf(MSG_INTL(MSG_DMP_DIR_2), str);
				continue;
			} else if (filetbl->cf_obj ||
			    (crle->c_flags & CRLE_VERBOSE))
				(void) printf(MSG_INTL(MSG_DMP_DIR_1), str);
		}

		/*
		 * Under verbose mode validate any real directory entry - the
		 * same test will be carried out by ld.so.1.
		 */
		if (((crle->c_flags & CRLE_UPDATE) == 0) &&
		    (crle->c_flags & CRLE_VERBOSE) &&
		    (dobj->co_flags & RTC_OBJ_REALPTH)) {
			if (stat(str, &status) != 0) {
				int err = errno;
				(void) printf(MSG_INTL(MSG_DMP_STAT), str,
				    strerror(err));
			} else if (status.st_mtime != dobj->co_info) {
				(void) printf(MSG_INTL(MSG_DMP_DCMP), str);
			}
		}

		for (; filetbl->cf_obj; filetbl++) {
			Rtc_obj	*fobj;
			Half	flags;

			fobj = (Rtc_obj *)(filetbl->cf_obj + addr);
			str = strtbl + fobj->co_name;
			flags = fobj->co_flags;

			/*
			 * Only update individual files that were originally
			 * specified on the command-line.  Or, if this is a
			 * version 1 configuration file use every file that
			 * isn't part of an all-entries directory.
			 */
			if (((flags & RTC_OBJ_CMDLINE) &&
			    ((fobj->co_flags & RTC_OBJ_APP) == 0)) ||
			    ((head->ch_version == RTC_VER_ONE) &&
			    ((dobj->co_flags & RTC_OBJ_ALLENTS) == 0))) {
				char	*alter = NULL, altdir[PATH_MAX];

				/*
				 * Determine whether this file requires an
				 * alternative, and if so, and we haven't
				 * already an alternative in affect, create one.
				 */
				if (fobj->co_flags & RTC_OBJ_ALTER) {
					alter = (char *)(strtbl +
					    fobj->co_alter);
					(void) strcpy(altdir, alter);
					alter = strrchr(altdir, '/');
					*alter = '\0';

					if ((objdir == NULL) ||
					    (strcmp(objdir, altdir) != 0)) {
						(void) strcpy(_objdir, altdir);
						crle->c_objdir = alter =
						    objdir = _objdir;
					} else
						alter = NULL;
				}

				if (crle->c_flags & CRLE_UPDATE) {
					if (inspect(crle, str,
					    getflags(flags)) != 0)
						return (INSCFG_RET_FAIL);
					continue;
				}

				if (alter) {
					(void) snprintf(_cmd, PATH_MAX,
					    MSG_ORIG(MSG_CMD_OUTPUT),
					    crle->c_objdir);
					cmd = strdupa(_cmd);
					if (aplist_append(&cmdline, cmd,
					    AL_CNT_CRLE) == NULL)
						return (INSCFG_RET_FAIL);
				}

				/* LINTED */
				(void) snprintf(_cmd, PATH_MAX,
				    getformat(flags), str);
				cmd = strdupa(_cmd);
				if (aplist_append(&cmdline, cmd,
				    AL_CNT_CRLE) == NULL)
					return (INSCFG_RET_FAIL);
			}

			if (crle->c_flags & CRLE_UPDATE)
				continue;

			/*
			 * Although we record both full pathnames and their
			 * simple filenames (basename), only print the simple
			 * names unless we're under verbose mode.
			 */
			if ((strchr(str, '/') == 0) ||
			    (crle->c_flags & CRLE_VERBOSE)) {
				if (fobj->co_flags & RTC_OBJ_ALTER)
					(void) printf(MSG_INTL(MSG_DMP_FILE_2),
					    str, (strtbl + fobj->co_alter));
				else
					(void) printf(MSG_INTL(MSG_DMP_FILE_1),
					    str);
			}

			/*
			 * Under verbose mode validate any real file entry - the
			 * same test will be carried out by ld.so.1.
			 */
			if ((crle->c_flags & CRLE_VERBOSE) &&
			    (fobj->co_flags & RTC_OBJ_REALPTH)) {
				if (stat(str, &status) != 0) {
					int err = errno;
					(void) printf(MSG_INTL(MSG_DMP_STAT),
					    str, strerror(err));
				} else if (status.st_size != fobj->co_info) {
					(void) printf(MSG_INTL(MSG_DMP_FCMP),
					    str);
				}
			}
		}
	}

	if ((crle->c_flags & CRLE_UPDATE) == 0)
		printcmd(crle, head, cmdline);

	if ((crle->c_flags & CRLE_VERBOSE) == 0)
		return (INSCFG_RET_OK);

	/*
	 * If we've in verbose mode scan the hash list.
	 */
	/* LINTED */
	hash = (Word *)(CAST_PTRINT(char *, head->ch_hash) + addr);
	bkts = hash[0];
	chain = &hash[2 + bkts];
	hash += 2;

	(void) printf(MSG_INTL(MSG_DMP_HASH));

	/*
	 * Scan the hash buckets looking for valid entries.
	 */
	for (ndx = 0; ndx < bkts; ndx++, hash++) {
		Conv_config_obj_buf_t	config_obj_buf;
		Rtc_obj			*obj;
		const char		*str;
		Word			_ndx;

		if (*hash == 0)
			continue;

		obj = objtbl + *hash;
		str = strtbl + obj->co_name;

		(void) printf(MSG_INTL(MSG_DMP_HASHENT_1), obj->co_id, ndx,
		    str, conv_config_obj(obj->co_flags, &config_obj_buf));

		/*
		 * Determine whether there are other objects chained to this
		 * bucket.
		 */
		for (_ndx = chain[*hash]; _ndx; _ndx = chain[_ndx]) {
			obj = objtbl + _ndx;
			str = strtbl + obj->co_name;

			(void) printf(MSG_INTL(MSG_DMP_HASHENT_2), obj->co_id,
			    str, conv_config_obj(obj->co_flags,
			    &config_obj_buf));
		}
	}
	(void) printf(MSG_ORIG(MSG_STR_NL));

	return (INSCFG_RET_OK);
}


INSCFG_RET
inspectconfig(Crle_desc * crle, int c_class)
{
	INSCFG_RET	error;
	int		fd;
	Addr		addr;
	struct stat	status;
	const char	*caller = crle->c_name, *file = crle->c_confil;
	Conv_inv_buf_t	inv_buf1, inv_buf2, inv_buf3;

	/*
	 * Open the configuration file, determine its size and map it in.
	 */
	if ((fd = open(file, O_RDONLY, 0)) == -1) {
		int	err = errno;

		if (err == ENOENT) {
#ifndef _ELF64
			/* Must restart if user requested a 64-bit file */
			if (c_class == ELFCLASS64)
				return (INSCFG_RET_NEED64);
#endif

			/*
			 * To allow an update (-u) from scratch, fabricate any
			 * default search and secure paths that the user
			 * intends to add to.
			 */
			if (crle->c_flags & CRLE_UPDATE) {
				if (crle->c_flags & CRLE_EDLIB) {
					if (fablib(crle, CRLE_EDLIB))
						return (INSCFG_RET_FAIL);
				}
				if (crle->c_flags & CRLE_ESLIB) {
					if (fablib(crle, CRLE_ESLIB))
						return (INSCFG_RET_FAIL);
				}
				if (crle->c_flags & CRLE_ADLIB) {
					if (fablib(crle, CRLE_ADLIB))
						return (INSCFG_RET_FAIL);
				}
				if (crle->c_flags & CRLE_ASLIB) {
					if (fablib(crle, CRLE_ASLIB))
						return (INSCFG_RET_FAIL);
				}
				return (INSCFG_RET_OK);

			} else if (crle->c_flags & CRLE_CONFDEF) {
				const char	*fmt1, *fmt2;

				/*
				 * Otherwise if the user is inspecting a default
				 * configuration file that doesn't exist inform
				 * them and display the ELF defaults.
				 */
				(void) printf(MSG_INTL(MSG_DEF_NOCONF), file);
				(void) printf(MSG_INTL(MSG_DMP_PLATFORM),
				    conv_ehdr_class(M_CLASS,
				    CONV_FMT_ALT_FILE, &inv_buf1),
				    conv_ehdr_data(M_DATA,
				    CONV_FMT_ALT_FILE, &inv_buf2),
				    conv_ehdr_mach(M_MACH,
				    CONV_FMT_ALT_FILE, &inv_buf3));


				if (crle->c_flags & CRLE_AOUT) {
					fmt1 = MSG_INTL(MSG_DEF_AOUTDLP);
#ifndef SGS_PRE_UNIFIED_PROCESS
					fmt2 = MSG_INTL(MSG_DEF_AOUTNEWTD);
#else
					fmt2 = MSG_INTL(MSG_DEF_AOUTOLDTD);
#endif
				} else {
#if M_CLASS == ELFCLASS64
#ifndef	SGS_PRE_UNIFIED_PROCESS
					fmt1 = MSG_INTL(MSG_DEF_NEWDLP_64);
					fmt2 = MSG_INTL(MSG_DEF_NEWTD_64);
#else
					fmt1 = MSG_INTL(MSG_DEF_OLDDLP_64);
					fmt2 = MSG_INTL(MSG_DEF_OLDTD_64);
#endif
#else
#ifndef	SGS_PRE_UNIFIED_PROCESS
					fmt1 = MSG_INTL(MSG_DEF_NEWDLP);
					fmt2 = MSG_INTL(MSG_DEF_NEWTD);
#else
					fmt1 = MSG_INTL(MSG_DEF_OLDDLP);
					fmt2 = MSG_INTL(MSG_DEF_OLDTD);
#endif
#endif
				}
				(void) printf(fmt1);
				(void) printf(fmt2);

				return (INSCFG_RET_OK);
			}
		}

		/*
		 * Otherwise there's an error condition in accessing the file.
		 */
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN), caller, file,
		    strerror(err));

		return (INSCFG_RET_FAIL);
	}

	(void) fstat(fd, &status);
	if (status.st_size < sizeof (Rtc_head)) {
		(void) close(fd);
		(void) fprintf(stderr, MSG_INTL(MSG_COR_TRUNC), caller, file);
		return (INSCFG_RET_FAIL);
	}
	if ((addr = (Addr)mmap(0, status.st_size, PROT_READ, MAP_SHARED,
	    fd, 0)) == (Addr)MAP_FAILED) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_MMAP), caller, file,
		    strerror(err));
		(void) close(fd);
		return (INSCFG_RET_FAIL);
	}
	(void) close(fd);

	/*
	 * Print the contents of the configuration file.
	 */
	error = scanconfig(crle, addr, c_class);

	(void) munmap((void *)addr, status.st_size);
	return (error);
}
