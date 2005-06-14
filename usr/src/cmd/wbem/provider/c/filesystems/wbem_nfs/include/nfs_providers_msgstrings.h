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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NFS_PROVIDERS_MSGSTRINGS_H
#define	_NFS_PROVIDERS_MSGSTRINGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * dgettext is normally defined by including libintl.h.  However, the file
 * /usr/sadm/lib/wbem/include/cimapi.h erroneously defines gettext so that
 * they can play games with L10N in the CIM functions.  If we try to undef
 * gettext before we include libintl.h we get a complaint from hdrchk.  So,
 * just declare the extern here to work around this mess.
 */
extern char *dgettext(const char *, const char *);

/*
 * This include file defines all messages that are used for error reporting
 * in the nfs providers.  Other messages about CIM specific failures are
 * defined in $(SRC)/cmd/wbem/provider/c/include/messageStrings.h
 */

/*
 * CIM failures - These should be moved to
 * $(SRC)/cmd/wbem/provider/c/include/messageStrings.h
 */
#define	ADD_PROP_TO_PROPLIST_FAILURE \
	util_routineFailureMessage("cim_addPropertyToPropertyList")
#define	ADD_PROP_TO_OBJPATH_FAILURE \
	util_routineFailureMessage("cim_addPropertyListToObjectPath")
#define	CIMOM_ENUM_INST_FAILURE \
	util_routineFailureMessage("cimom_enumerateInstances")
#define	CIMOM_ENUM_INSTNAMES_FAILURE \
	util_routineFailureMessage("cimom_enumerateInstanceNames")
#define	CIMOM_GET_INST_FAILURE \
	util_routineFailureMessage("cimom_getInstance")
#define	CREATE_EMPTY_OBJPATH_FAILURE \
	util_routineFailureMessage("cim_createEmptyObjectPath")
#define	CREATE_PROPLIST_FAILURE \
	util_routineFailureMessage("cim_createPropertyList")
#define	ENCODE_STRING_ARRAY_FAILURE \
	util_routineFailureMessage("cim_encodeStringArray")
#define	GET_PROPERTY_FAILURE \
	util_routineFailureMessage("cim_getProperty")
#define	PREPEND_INSTANCE_FAILURE \
	util_routineFailureMessage("cim_prependInstance")
#define	PROPLIST_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("cim_addPropertyListToInstance")

/*
 * NFS provider failures
 */
#define	CMD_EXEC_RETR_STR_FAILURE \
	util_routineFailureMessage("cmd_execute_command_and_retrieve_string")
#define	CMDGEN_GEN_CMD_FAILURE \
	util_routineFailureMessage("cmdgen_generate_command")
#define	CREATE_NFSMOUNT_ASSOC_FAILURE \
	util_routineFailureMessage("create_nfsMount_associations")
#define	DEL_DUPLICATE_PATHS_FAILURE \
	util_routineFailureMessage("del_all_with_duplicate_path")
#define	FS_ADD_DFSTAB_ENT_FAILURE \
	util_routineFailureMessage("fs_add_DFStab_ent")
#define	FS_CHECK_DUP_PATHS \
	util_routineFailureMessage("fs_check_for_duplicate_DFStab_paths")
#define	FS_DEL_MNT_DEFAULT_FAILURE \
	util_routineFailureMessage("fs_del_mount_default_ent")
#define	FS_DEL_DFSTAB_ENT_FAILURE \
	util_routineFailureMessage("fs_del_DFStab_ent")
#define	FS_EDIT_DFSTAB_ENT_FAILURE \
	util_routineFailureMessage("fs_edit_DFStab_ent")
#define	FS_GET_DFSTAB_ENT_FAILURE \
	util_routineFailureMessage("fs_get_DFStab_ents")
#define	FS_GET_DFSTAB_ENT_NUM_FAILURE \
	util_routineFailureMessage("fs_get_DFStab_ent_num")
#define	FS_GET_FILTERED_MNTDEFAULTS_FAILURE \
	util_routineFailureMessage("fs_get_filtered_mount_defaults")
#define	FS_GET_MAXFILENMLEN_FAILURE \
	util_routineFailureMessage("fs_get_maxfilenamelen")
#define	FS_GET_SHARE_FAILURE \
	util_routineFailureMessage("fs_get_share_list")
#define	FS_PARSE_OPTS_FOR_SEC_MODES_FAILURE \
	util_routineFailureMessage("fs_parse_opts_for_sec_modes")
#define	FS_PARSE_OPTLIST_FAILURE \
	util_routineFailureMessage("fs_parse_optlist_for_option")
#define	GET_DEFAULT_SECMODE_FAILURE \
	util_routineFailureMessage("nfssec_get_default_secmode")
#define	GET_DEVID_FAILURE \
	util_routineFailureMessage("get_devid")
#define	GET_HOSTNAME_FAILURE \
	util_routineFailureMessage("sys_get_hostname")
#define	GET_NETID_LIST_FAILURE \
	util_routineFailureMessage("netcfg_get_networkid_list")
#define	GET_RESOURCE_FAILURE \
	util_routineFailureMessage("get_resource")
#define	GET_SECMODE_LIST_FAILURE \
	util_routineFailureMessage("nfssec_get_nfs_secmode_list")
#define	NFS_GET_FILTERED_MOUNTS_FAILURE \
	util_routineFailureMessage("nfs_get_filtered_mount_list")
#define	NFS_GET_MNTLIST_FAILURE \
	util_routineFailureMessage("nfs_get_mount_list")
#define	NFS_GET_MNTS_BY_MNTOPT_FAILURE \
	util_routineFailureMessage("nfs_get_mounts_by_mntopt")

/*
 * NFS provider messages
 */
#define	NFSD_START_FAILURE \
	util_routineStartDaemonMessage("nfsd")
#define	NO_SHARES_ON_SYSTEM \
	dgettext(TEXT_DOMAIN, \
	"/etc/dfs/sharetab does not exist. No shares on system")
#define	MOUNTD_START_FAILURE \
	util_routineStartDaemonMessage("mountd")

#ifdef __cplusplus
}
#endif

#endif /* _NFS_PROVIDERS_MSGSTRINGS_H */
