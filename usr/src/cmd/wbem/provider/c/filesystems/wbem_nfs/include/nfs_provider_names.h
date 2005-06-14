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

#ifndef _NFS_PROVIDER_NAMES_H
#define	_NFS_PROVIDER_NAMES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NFS provider classes.
 */
#define	SOLARIS_HOSTEDSHARE "Solaris_HostedShare"
#define	SOLARIS_NFS "Solaris_NFS"
#define	SOLARIS_NFSMOUNT "Solaris_NFSMount"
#define	SOLARIS_NFSSHARE "Solaris_NFSShare"
#define	SOLARIS_NFSSHAREENT "Solaris_NFSShareEntry"
#define	SOLARIS_NFSSHAREDEFSECMODES "Solaris_NFSShareDefSecurityModes"
#define	SOLARIS_NFSSHARESEC "Solaris_NFSShareSecurity"
#define	SOLARIS_NFSSHARESECMODES "Solaris_NFSShareSecurityModes"
#define	SOLARIS_NFSSHARESECURITY "Solaris_NFSShareSecurity"
#define	SOLARIS_PERSISTSHARE "Solaris_PersistentShare"
#define	SOLARIS_SHAREDFS "Solaris_SharedFileSystem"
#define	SOLARIS_SHARESERV "Solaris_ShareService"
#define	SOLARIS_SYSPERSISTSHARE "Solaris_PersistentShareForSystem"

/*
 * Other referenced Solaris classes
 */
#define	SOLARIS_CS "Solaris_ComputerSystem"
#define	SOLARIS_DIR "Solaris_Directory"

/*
 * These are nfs providers specific functions.
 */
#define		ADD_PROP_TO_INST	"add_property_to_instance"
#define		ADD_PROP_TO_LIST	"add_property_to_list"
#define		COMMAND_GEN		"cmdgen_generate_command"
#define		CREATE_HOSTEDSHARE_ASSOC	\
	"create_hostedShare_associations"
#define		CREATE_OUT_PARAMS	"create_outParams_list"
#define		CREATE_PSFORSYS_ASSOC	"create_persistShareForSys_associations"
#define		CREATE_SHAREDFS_ASSOC	"create_sharedFS_associations"
#define		DELETE_DUP_PATHS	"del_all_with_duplicate_path"
#define		DELETE_VFSTAB_ENT	"delete_vfstab_entry"
#define		ENUM_MOUNTS		"enumerate_mounts"
#define		EXEC_CMD		"exec_command"
#define		GET_ANT			"get_Antecedent"
#define		GET_ASSOC_DIR		"get_associated_directory"
#define		GET_ASSOC_INST		"get_associated_instances"
#define		GET_ASSOC_NFSMNTS	"get_associated_nfs_mntlist"
#define		GET_ASSOC_SEC_INSTLIST	"get_associated_nfsShareSec_instList"
#define		GET_ASSOC_SEC_OPLIST	"get_associated_nfsShareSec_OPList"
#define		GET_ASSOC_SEC_PROPLIST	"get_associated_nfsShareSec_propList"
#define		GET_ASSOC_SP_INSTLIST	"get_associated_sharePersist_instList"
#define		GET_ASSOC_SP_OPLIST	"get_associated_sharePersist_OPList"
#define		GET_ASSOC_SP_PROPLIST	"get_associated_sharePersist_propList"
#define		GET_DEF_SECMODE		"get_default_secmode"
#define		GET_DEP			"get_Dependent"
#define		GET_NETCFG_LIST		"get_netconfig_list"
#define		GET_NFSSEC_LIST		"get_nfssec_list"
#define		GET_NFSSHARESEC_INST	"get_Solaris_NFSShareSecurity_Inst"
#define		GET_NFSSHARE_0P		"get_Solaris_NFSShare_OP"
#define		GET_PROP_FROM_OPTS	"get_property_from_opt_string"
#define		GET_SHAREPERSIST_INST	"get_Solaris_PersistentShare_Inst"
#define		MOUNTALL_INVOKE_METH	"mountall"
#define		POPULATE_PROPLIST	"populate_property_list"
#define		SHAREALL_INVOKE_METH	"shareall"
#define		SHARE_EXISTS		"does_share_exist"
#define		SHOW_EXPORTS		"show_exports"
#define		UNMOUNTALL_INVOKE_METH	"unmountall"
#define		UNSHAREALL_INVOKE_METH	"unshareall"
#ifdef __cplusplus
}
#endif

#endif /* _NFS_PROVIDER_NAMES_H */
