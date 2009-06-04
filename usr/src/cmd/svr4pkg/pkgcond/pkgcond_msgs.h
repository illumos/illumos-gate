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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PKGCOND_MSGS_H
#define	_PKGCOND_MSGS_H


#include <libintl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	lint
#define	gettext(x)	x
#endif

/* generic messages */

#define	MSG_USAGE						gettext(\
"%s; usage is:\n" \
"\t%s [-nv] <condition> [ <option(s)> ]\n" \
"\n" \
"command options:\n" \
"\t-n - negate results of condition test\n" \
"\t-v - verbose output of condition testing\n" \
"\n" \
"<condition> may be any one of:\n" \
"%s\n" \
"<option(s)> are specific to the condition used\n" \
"\n" \
"pkgcond -?\n" \
"\t- Shows this help message\n")

#define	MSG_NO_PKG_ENV_DATA_PRESENT				gettext(\
"no data available from package tools: zone information may be incomplete")

#define	MSG_NO_ARGUMENTS_SPECIFIED				gettext(\
"no condition to check specified")

#define	MSG_INVALID_OPTION_SPECIFIED				gettext(\
"option <%c> not recognized")

#define	MSG_IS_INVALID_OPTION					gettext(\
"option <%c> not recognized by condition <%s>")

#define	MSG_UNRECOGNIZED_CONDITION_SPECIFIED			gettext(\
"condition not recognized")

#define	MSG_IS_WHAT_RESULT					gettext(\
"%s=%d")

/* debugging messages */

#define	DBG_NO_RECURSION					gettext(\
"nonrecursive call to <%s>")

#define	DBG_RECURSION						gettext(\
"recursive call to <%s> count <%d> ignored")

#define	DBG_TESTPATH_OK						gettext(\
"path <%s> matches all criteria")

#define	DBG_ADDV_PATH_IS_SYMLINK				gettext(\
"cannot add driver to path <%s>: <%s> does not exist or exists but " \
"is a symbolic link")

#define	DBG_ADDV_YES						gettext(\
"root path <%s> can have a driver added")

#define	DBG_UPDV_PATH_IS_SYMLINK				gettext(\
"cannot update driver to path <%s>: <%s> does not exist or exists but " \
"is a symbolic link")

#define	DBG_UPDV_YES						gettext(\
"root path <%s> can have a driver updated")

#define	DBG_RMDV_PATH_IS_SYMLINK				gettext(\
"cannot remove driver to path <%s>: <%s> does not exist or exists but " \
"is a symbolic link")

#define	DBG_RMDV_YES						gettext(\
"root path <%s> can have a driver removed")

#define	DBG_ROOTPATH_IS						gettext(\
"root path is <%s>")

#define	DBG_CANNOT_ACCESS_PATH_BUT_SHOULD			gettext(\
"test_path: path <%s> must exist and does not: %s")

#define	DBG_CANNOT_ACCESS_PATH_OK				gettext(\
"test_path: path <%s> must not (and does not) exist")

#define	DBG_PATH_DOES_NOT_EXIST					gettext(\
"test_path: path <%s> does not exist: %s")

#define	DBG_CANNOT_LSTAT_PATH					gettext(\
"test_path: cannot lstat path <%s>: %s")

#define	DBG_IS_A_DIRECTORY					gettext(\
"test_path: path <%s> is a directory but is not supposed to be")

#define	DBG_IS_NOT_A_DIRECTORY					gettext(\
"test_path: path <%s> is not a directory but is supposed to be")

#define	DBG_DIRECTORY_NOT					gettext(\
"test_path: path <%s> is not a directory")

#define	DBG_DIRECTORY_IS					gettext(\
"test_path: path <%s> is a directory")

#define	DBG_IS_A_FILE						gettext(\
"test_path: path <%s> is a file but is not supposed to be")

#define	DBG_IS_NOT_A_FILE					gettext(\
"test_path: path <%s> is not a file but is supposed to be")

#define	DBG_TOKEN__EXISTS					gettext(\
"test_path: token <%s> exists in path <%s>")

#define	DBG_FILE_NOT						gettext(\
"test_path: path <%s> is not a file")

#define	DBG_FILE_IS						gettext(\
"test_path: path <%s> is a file")

#define	DBG_IS_A_SYMLINK					gettext(\
"test_path: path <%s> is a symlink but is not supposed to be")

#define	DBG_IS_NOT_A_SYMLINK					gettext(\
"test_path: path <%s> is not a symlink but is supposed to be")

#define	DBG_SORTEDINS_SKIPPED					gettext(\
"duplicate entry <%d> : <%s> (<%s> vs <%s>, <%s> vs <%s>): merged options")

#define	DBG_SYMLINK_NOT						gettext(\
"test_path: path <%s> is not a symlink")

#define	DBG_SYMLINK_IS						gettext(\
"test_path: path <%s> is a symlink")

#define	DBG_SET_NEGATE_RESULTS					gettext(\
"set_negate_results: current setting <%d> new setting <%d>")

#define	DBG_ADJUST_RESULTS					gettext(\
"adjust_results: result <%d> negate <%d> returned result <%d>")

#define	DBG_PARSE_GLOBAL					gettext(\
"parsing global data <%s>")

#define	DBG_NO_DEFAULT_ROOT_PATH_SET				gettext(\
"no default root path set")

#define	DBG_DEFAULT_ROOT_PATH_SET				gettext(\
"default root path <%s> set from environment variable <%s>")

#define	DBG_RESULTS						gettext(\
"returning results <%d>")

#define	DBG_SET_ROOT_PATH_TO					gettext(\
"setting root path to <%s>")

#define	DBG_TEST_PATH						gettext(\
"test path <%s> flags <0x%08lx>")

#define	DBG_TEST_PATH_NO_RESOLVE				gettext(\
"cannot resolve path <%s>")

#define	DBG_TEST_PATH_RESOLVE					gettext(\
"test resolved path <%s>")

#define	DBG_TEST_EXISTS_SHOULD_NOT				gettext(\
"path <%s> exists but should not")

#define	DBG_PARSED_ENVIRONMENT					gettext(\
"global data parsed from environment variable <%s>")

#define	DBG_DUMP_GLOBAL_LINE					gettext(\
"inherited file system <%d> is <%s>")

#define	DBG_DUMP_GLOBAL_ENTRY					gettext(\
"global data settings")

#define	DBG_DUMP_GLOBAL_PARENT_ZONE				gettext(\
"parentzone zoneName <%s> zoneType <%s>")

#define	DBG_DUMP_GLOBAL_CURRENT_ZONE				gettext(\
"currentzone zoneName <%s> zoneType <%s>")

#define	DBG_IDLC_INITIAL_INSTALL				gettext(\
"path <%s> is not a diskless client: initial installation in progress")

#define	DBG_IDLC_ZONE_INSTALL					gettext(\
"path <%s> is not a diskless client: initial zone installation in progress")

#define	DBG_IDLC_PKG_NOT_INSTALLED				gettext(\
"path <%s> is not a diskless client: package <%s> is not installed in <%s>")

#define	DBG_IDLC_ROOTPATH_BAD					gettext(\
"path <%s> is not a diskless client: root path cannot be <%s>")

#define	DBG_IDLC_ZONE_BAD					gettext(\
"path <%s> is not a diskless client: current zone must be <%s>")

#define	DBG_IDLC_PATH_MISSING					gettext(\
"path <%s> is not a diskless client: <%s> does not exist")

#define	DBG_IDLC_USR_IS_NOT_EMPTY				gettext(\
"path <%s> is not a diskless client: </usr> is not empty")

#define	DBG_IDLC_NO_TEMPLATES_PATH				gettext(\
"path <%s> is not a diskless client: <%s/%s> does not exist")

#define	DBG_IDLC_PATH_IS_DISKLESS_CLIENT			gettext(\
"path <%s> is a diskless client")

#define	DBG_ISGZ_INITIAL_INSTALL				gettext(\
"path <%s> is not a global zone: initial installation in progress")

#define	DBG_ISGZ_NGZ_ZONE_INSTALL				gettext(\
"path <%s> is not a global zone: initial non-global zone " \
"installation in progress")

#define	DBG_ISGZ_PATH_IS_GLOBAL_ZONE				gettext(\
"path <%s> is a global zone")

#define	DBG_ISGZ_PATH_ISNT_DIRECTORY				gettext(\
"path <%s> is not a global zone: directory <%s> does not exist")

#define	DBG_ISGZ_PATH_EXISTS					gettext(\
"path <%s> is not a global zone: <%s> exists")

#define	DBG_ISGZ_ZONENAME_ISNT_GLOBAL				gettext(\
"path <%s> is not a global zone: zone name <%s> is not <global>")

#define	DBG_ISGZ_PATH_IS_SYMLINK				gettext(\
"path <%s> is not a global zone: <%s> does not exist or exists but " \
"is a symbolic link")

#define	DBG_INIM_INITIAL_INSTALL				gettext(\
"path <%s> is not a netinstall image: initial installation in progress")

#define	DBG_INIM_ZONE_INSTALL					gettext(\
"path <%s> is not a netinstall image: initial zone installation in progress")

#define	DBG_INIM_PATH_IS_NETINSTALL_IMAGE			gettext(\
"path <%s> is a netinstall image")

#define	DBG_INIM_BAD_CURRENT_ZONE				gettext(\
"path <%s> is not a netinstall image: current zone is not <%s>")

#define	DBG_INIM_PATH_ISNT_SYMLINK				gettext(\
"path <%s> is not a netinstall image: <%s> does not exist or exists " \
"but is not a symbolic link")

#define	DBG_INIM_PATH_ISNT_DIRECTORY				gettext(\
"path <%s> is not a netinstall image: <%s> does not exist or " \
"is not a directory")

#define	DBG_IMRT_INITIAL_INSTALL				gettext(\
"path <%s> is not a mounted miniroot image: initial installation in progress")

#define	DBG_IMRT_ZONE_INSTALL					gettext(\
"path <%s> is not a mounted miniroot image: initial zone " \
"installation in progress")

#define	DBG_IMRT_PATH_IS_MOUNTED_MINIROOT			gettext(\
"path <%s> is a mounted miniroot")

#define	DBG_IMRT_BAD_CURRENT_ZONE				gettext(\
"path <%s> is not a mounted miniroot image: current zone is not <%s>")

#define	DBG_IMRT_ROOTDIR_BAD					gettext(\
"path <%s> is not a mounted miniroot image: root directory is not <%s>")

#define	DBG_IMRT_PATH_ISNT_SYMLINK				gettext(\
"path <%s> is not a mounted miniroot image: <%s> does not exist or is " \
" not a symbolic link")

#define	DBG_IMRT_PATH_ISNT_DIRECTORY				gettext(\
"path <%s> is not a netinstall image: <%s> does not exist or is not " \
" a directory")

#define	DBG_NGZN_INITIAL_INSTALL				gettext(\
"path <%s> is not a non-global zone: initial installation in progress")

#define	DBG_NGZN_GLOBAL_ZONE_INSTALL				gettext(\
"path <%s> is not a non-global zone: initial global zone " \
"installation in progress")

#define	DBG_NGZN_IN_GZ_IS_NONGLOBAL_ZONE			gettext(\
"path <%s> is a non-global zone: running in global zone")

#define	DBG_NGZN_PARENT_CHILD_SAMEZONE				gettext(\
"path <%s> is a non-global zone: parent/child are same zone name <%s>")

#define	DBG_NGZN_IS_NONGLOBAL_ZONE				gettext(\
"path <%s> is a non-global zone")

#define	DBG_NGZN_ZONENAME_ISNT_NGZ				gettext(\
"path <%s> is not a non-global zone: zone name is <%s>")

#define	DBG_NGZN_INSTALL_ZONENAME_IS_NGZ			gettext(\
"path <%s> is a non-global zone: installation of non-global zone name is <%s>")

#define	DBG_NGZN_ZONENAME_IS_NGZ				gettext(\
"path <%s> is a non-global zone: zone name is <%s>")

#define	DBG_NGZN_PATH_EXISTS					gettext(\
"path <%s> is not a non-global zone: <%s> exists")

#define	DBG_NGZN_BAD_PARENT_ZONETYPE				gettext(\
"path <%s> is not a non-global zone: parent zone type is <%s>")

#define	DBG_NGZN_BAD_CURRENT_ZONETYPE				gettext(\
"path <%s> is not a non-global zone: current zone type is <%s>")

#define	DBG_NGZN_PATH_DOES_NOT_EXIST				gettext(\
"path <%s> is not a non-global zone: <%s> does not exist or exists but " \
"is a symbolic link")

#define	DBG_IRST_INITIAL_INSTALL				gettext(\
"path <%s> is not the current running system: initial installation in progress")

#define	DBG_IRST_ZONE_INSTALL					gettext(\
"path <%s> is not the current running system: initial zone installation " \
"in progress")

#define	DBG_IRST_PATH_IS_RUNNING_SYSTEM				gettext(\
"path <%s> is a running system")

#define	DBG_IRST_ZONE_BAD					gettext(\
"path <%s> is not the current running system: the current zone name " \
" is not <%s>")

#define	DBG_IRST_ROOTPATH_BAD					gettext(\
"path <%s> is not the current running system: root path is not <%s>")

#define	DBG_IALR_INITIAL_INSTALL				gettext(\
"path <%s> is an alternative root: initial installation in progress")

#define	DBG_IALR_ZONE_INSTALL					gettext(\
"path <%s> is not an alternative root: initial zone installation in progress")

#define	DBG_IALR_PATH_DOES_NOT_EXIST				gettext(\
"path <%s> is not an alternative root: <%s> does not exist or exists but " \
"is a symbolic link")

#define	DBG_IALR_BAD_ROOTPATH					gettext(\
"path <%s> is not an alternative root: root directory is <%s>")

#define	DBG_IALR_IS						gettext(\
"root path <%s> is an alternative root")

#define	DBG_WRNG_IS						gettext(\
"root path <%s> is a whole root non-global zone")

#define	DBG_WRNG_IS_NOT						gettext(\
"root path <%s> is not a whole root non-global zones: " \
"file systems are inherited")

#define	DBG_SRNG_IS_NOT						gettext(\
"root path <%s> is not a sparse root non-global zones: " \
"file systems are not inherited")

#define	DBG_SRNG_IS						gettext(\
"root path <%s> is a sparse root non-global zone")

#define	DBG_BENV_INITIAL_INSTALL				gettext(\
"path <%s> is not an alternative boot environment: initial " \
"installation in progress")

#define	DBG_BENV_ZONE_INSTALL					gettext(\
"path <%s> is not an alternative boot environment: initial zone " \
"installation in progress")

#define	DBG_BENV_IS						gettext(\
"path <%s> is an alternative boot environment")

#define	DBG_BENV_NO_ETCLU					gettext(\
"path <%s> is not an alternative boot environment: <%s> does " \
"not exist or is not a directory")

#define	DBG_BENV_NO_ETCLUTAB					gettext(\
"path <%s> is not an alternative boot environment: <%s> does not exist")

#define	DBG_BENV_BAD_ZONE					gettext(\
"path <%s> is not an alternative boot environment: " \
"the current zone name is not <%s>")

#define	DBG_BENV_BAD_ROOTPATH					gettext(\
"path <%s> is not an alternative boot environment: root directory is <%s>")

#define	DBG_PWRT_INHERITED					gettext(\
"root path <%s> is not writeable: is inherited with <%s>")

#define	DBG_PWRT_READONLY					gettext(\
"root path <%s> is not writeable: is read only <%s>")

#define	DBG_PWRT_IS						gettext(\
"root path <%s> is writeable")

#define	DBG_PWRT_INFO						gettext(\
"root path <%s> is mount point <%s> fstype <%s> options <%s>")

#define	DBG_NO_GLOBAL_DATA_AVAILABLE				gettext(\
"no global data available in environment variable <%s>")

#define	DBG_CKSR_FSREADONLY					gettext(\
"file system <%s> type <%s> is read-only")

#define	DBG_CALCSCFG_ENTRY					gettext(\
"analyzing inherited and mounted file systems")

#define	DBG_CALCSCFG_INHERITED					gettext(\
"analyzing inherited file systems")

#define	DBG_CALCSCFG_MOUNTED					gettext(\
"analyzing mounted file systems")

#define	DBG_SINS_ENTRY						gettext(\
"inserting mount point <%s> type <%s> options <%s>")

#define	DBG_NGZN_PATH_EXISTS					gettext(\
"path <%s> is not a non-global zone: <%s> exists")

#define	DBG_CMDLINE_PATH					gettext(\
"command line path to check set to: <%s>")

/* warnings */

#define	WRN_PARSED_DATA_MISSING					gettext(\
"available global data missing <%s>")

/* errors */

#define	MSG_FATAL						gettext(\
	"Fatal Error")

#define	ERR_REQUIRED_ROOTPATH_MISSING				gettext(\
"the <%s> condition requires a root path to be specified")

#define	ERR_CANNOT_GET_ZONENAME					gettext(\
"could not determine zone name")

#define	ERR_CANNOT_CALC_FS_CONFIG				gettext(\
"cannot calculate file system config")

#define	ERR_CANNOT_PARSE_GLOBAL_DATA				gettext(\
"cannot parse global data SML: <%s>")

#define	ERR_UNRECOGNIZED_OPTION					gettext(\
"unrecognized option <%s>")

#define	ERR_DEFAULT_ROOT_INVALID				gettext(\
"cannot set root path to <%s>: %s")

#define	ERR_DEFAULT_ROOT_NOT_DIR				gettext(\
"cannot set root path to <%s>: not a directory")

#define	ERR_CANNOT_SET_ROOT_PATH				gettext(\
"cannot set root path from environment variable <%s>")

#define	ERR_CANNOT_USE_GLOBAL_DATA				gettext(\
"global data from environment variable <%s> cannot be used to determine " \
"conditions and capabilities")

#define	ERR_BAD_SUB						gettext(\
	"\"%s\" is not a valid condition")

#ifdef	__cplusplus
}
#endif

#endif /* _PKGCOND_MSGS_H */
