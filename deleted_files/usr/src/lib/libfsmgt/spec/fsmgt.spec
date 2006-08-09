#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libfsmgt/spec/fsmgt.spec

function        cmd_execute_command
include         <libfsmgt.h>
declaration     int cmd_execute_command(char *cmd, int *output_filedes, \
		int *error_filedes)
version         SUNWprivate_1.1
end

function        cmd_execute_command_and_retrieve_string
include         <libfsmgt.h>
declaration     char *cmd_execute_command_and_retrieve_string(char *cmd, \
		int *errp)
version         SUNWprivate_1.1
end

function        cmd_retrieve_string
include         <libfsmgt.h>
declaration     char    *cmd_retrieve_string(int filedes, int *errp)
version         SUNWprivate_1.1
end

function	fileutil_add_string_to_array
include		<libfsmgt.h>
declaration	boolean_t fileutil_add_string_to_array(char ***, char *, \
		int *, int *)
version		SUNWprivate_1.1
end

function	fileutil_free_string_array
include		<libfsmgt.h>
declaration	void fileutil_free_string_array(char **, int)
version		SUNWprivate_1.1
end

function	fileutil_get_cmd_from_string
include		<libfsmgt.h>
declaration	char *fileutil_get_cmd_from_string(char *input_stringp)
version		SUNWprivate_1.1
end

function	fileutil_get_first_column_data
include		<libfsmgt.h>
declaration	char **fileutil_get_first_column_data(FILE *, int *, int *)
version		SUNWprivate_1.1
end

function	fileutil_getfs
include		<libfsmgt.h>
declaration	char *fileutil_getfs(FILE *)
version		SUNWprivate_1.1
end

function	fileutil_getline
include		<libfsmgt.h>
declaration	char *fileutil_getline(FILE *, char *, int)
version		SUNWprivate_1.1
end

function	fs_add_mount_default
include		<libfsmgt.h>
declaration	fs_mntdefaults_t *fs_add_mount_default(fs_mntdefaults_t *, \
		int *)
version		SUNWprivate_1.1
end

function	fs_del_mount_default_ent
include		<libfsmgt.h>
declaration	fs_mntdefaults_t *fs_del_mount_default_ent(fs_mntdefaults_t *, \
		int *)
version		SUNWprivate_1.1
end

function	fs_edit_mount_defaults
include		<libfsmgt.h>
declaration	fs_mntdefaults_t *fs_edit_mount_defaults(fs_mntdefaults_t *, \
		fs_mntdefaults_t *, int *)
version		SUNWprivate_1.1
end

function	fs_free_mntdefaults_list
include		<libfsmgt.h>
declaration	void fs_free_mntdefaults_list(fs_mntdefaults_t *headp);
version		SUNWprivate_1.1
end

function	fs_get_filtered_mount_defaults
include		<libfsmgt.h>
declaration	fs_mntdefaults_t *fs_get_filtered_mount_defaults(\
		fs_mntdefaults_t *filter, int *errp)
version		SUNWprivate_1.1
end

function	fs_get_mount_defaults
include		<libfsmgt.h>
declaration	fs_mntdefaults_t *fs_get_mount_defaults(int *errp)
version		SUNWprivate_1.1
end

function	fs_free_mount_list
include		<libfsmgt.h>
declaration	void fs_free_mount_list(fs_mntlist_t *mnt_list)
version		SUNWprivate_1.1
end

function	fs_get_availablesize
include		<libfsmgt.h>
declaration	unsigned long long fs_get_availablesize(char *mntpnt, int *errp)
version		SUNWprivate_1.1
end

function	fs_get_avail_for_nonsuperuser_size
include		<libfsmgt.h>
delcaration	unsigned long long fs_get_avail_for_nonsuperuser_size(\
		char *mntpnt, int *errp)
version		SUNWprivate_1.1
end

function	fs_get_blocksize
include		<libfsmgt.h>
declaration	unsigned long long fs_get_blocksize(char *mntpnt, int *errp)
version		SUNWprivate_1.1
end

function	fs_get_filtered_mount_list
include		<libfsmgt.h>
declaration	fs_mntlist_t *fs_get_filtered_mount_list(char *resource, \
		char *mountp, char *fstype, char *mntopts, char *time, \
		boolean_t find_overlays, int *errp)
version		SUNWprivate_1.1
end

function	fs_get_fragsize
include		<libfsmgt.h>
declaration	unsigned long fs_get_fragsize(char *mntpnt, int *errp)
version		SUNWprivate_1.1
end

function	fs_get_maxfilenamelen
include		<libfsmgt.h>
declaration	unsigned long fs_get_maxfilenamelen(char *mntpnt, int *errp)
version		SUNWprivate_1.1
end

function	fs_get_mounts_by_mntopt
include		<libfsmgt.h>
declaration	fs_mntlist_t *fs_get_mounts_by_mntopt(char *mntopt, \
		boolean_t find_overlays, int *errp)
version		SUNWprivate_1.1
end

function	fs_get_mount_list
include		<libfsmgt.h>
declaration	fs_mntlist_t *fs_get_mount_list(boolean_t find_overlays, \
		int *errp)
version		SUNWprivate_1.1
end

function	fs_get_totalsize
include		<libfsmgt.h>
declaration	unsigned long long fs_get_totalsize(char *mntpnt, int *errp)
version		SUNWprivate_1.1
end

function	fs_get_usedsize
include		<libfsmgt.h>
declaration	unsigned long long fs_get_usedsize(char *mntpnt, int *errp)
version		SUNWprivate_1.1
end

function	fs_is_readonly
include		<libfsmgt.h>
declaration	boolean_t fs_is_readonly(char *mntpnt, int *errp)
version		SUNWprivate_1.1
end

function	fs_parse_optlist_for_option
include		<libfsmgt.h>
declaration	char *fs_parse_optlist_for_option(char *optlist, char *opt, \
		int *errp)
version		SUNWprivate_1.1
end

function	fs_parse_opts_for_sec_modes
include		<libfsmgt.h>
declaration	char **fs_parse_opts_for_sec_modes(char *cmd, int *count, \
		int *error)
version		SUNWprivate_1.1
end

function	fs_free_share_list
include		<libfsmgt.h>
declaration	void fs_free_share_list(fs_sharelist_t *share_list)
version		SUNWprivate_1.1
end

function	fs_get_share_list
include		<libfsmgt.h>
declaration	fs_sharelist_t  *fs_get_share_list(int *errp)
version		SUNWprivate_1.1
end

function	fs_create_array_from_accesslist
include		<libfsmgt.h>
declaration	char **fs_create_array_from_accesslist(char *access_list, \
		int *count, int *err)
version		SUNWprivate_1.1
end

function	fs_check_for_duplicate_DFStab_paths
include		<libfsmgt.h>
declaration	int fs_check_for_duplicate_DFStab_paths(char *path, int *err)
include		<libfsmgt.h>
version		SUNWprivate_1.1
end

function	fs_add_DFStab_ent
declaration	fs_dfstab_entry_t fs_add_DFStab_ent(char *, int *)
include		<libfsmgt.h>
version		SUNWprivate_1.1
end

function	fs_del_All_DFStab_ents_with_Path
include		<libfsmgt.h>
declaration	fs_dfstab_entry_t fs_del_All_DFStab_ents_with_Path(char *path, \
		int *err)
version		SUNWprivate_1.1
end

function	fs_del_DFStab_ent
include		<libfsmgt.h>
declaration	fs_dfstab_entry_t fs_del_DFStab_ent(char *, int *)
version		SUNWprivate_1.1
end

function	fs_edit_DFStab_ent
include		<libfsmgt.h>
declaration	fs_dfstab_entry_t fs_edit_DFStab_ent(char *, char *, int *)
version		SUNWprivate_1.1
end

function	fs_free_DFStab_ents
include		<libfsmgt.h>
declaration	void fs_free_DFStab_ents(fs_dfstab_entry_t)
version		SUNWprivate_1.1
end

function	fs_get_DFStab_ents
include		<libfsmgt.h>
declaration	fs_dfstab_entry_t fs_get_DFStab_ents(int *err)
version		SUNWprivate_1.1
end

function	fs_get_DFStab_ent_Desc
include		<libfsmgt.h>
declaration	char *fs_get_DFStab_ent_Desc(fs_dfstab_entry_t)
version		SUNWprivate_1.1
end

function	fs_get_DFStab_ent_Fstype
include		<libfsmgt.h>
declaration	char *fs_get_DFStab_ent_Fstype(fs_dfstab_entry_t)
version		SUNWprivate_1.1
end

function	fs_get_DFStab_ent_Next
include		<libfsmgt.h>
declaration	fs_dfstab_entry_t fs_get_DFStab_ent_Next(fs_dfstab_entry_t)
version		SUNWprivate_1.1
end

function	fs_get_DFStab_ent_Options
include		<libfsmgt.h>
declaration	char *fs_get_DFStab_ent_Options(fs_dfstab_entry_t)
version		SUNWprivate_1.1
end

function	fs_get_DFStab_ent_Path
include		<libfsmgt.h>
declaration	char *fs_get_DFStab_ent_Path(fs_dfstab_entry_t)
version		SUNWprivate_1.1
end

function	fs_get_DFStab_ent_Res
include		<libfsmgt.h>
declaration	char *fs_get_DFStab_ent_Res(fs_dfstab_entry_t)
version		SUNWprivate_1.1
end

function	fs_get_Dfstab_share_cmd
include		<libfsmgt.h>
declaration	char *fs_get_Dfstab_share_cmd(fs_dfstab_entry_t, int *)
version		SUNWprivate_1.1
end

function	fs_set_DFStab_ent
include		<libfsmgt.h>
declaration	fs_dfstab_entry_t fs_set_DFStab_ent(char *, char *, char *, \
		char *, int *)
version		SUNWprivate_1.1
end

function	fs_print_dfstab_entries
include		<libfsmgt.h>
declaration	void fs_print_dfstab_entries(fs_dfstab_entry_t)
version		SUNWprivate_1.1
end

function	nfs_free_mntinfo_list
include		<libfsmgt.h>
declaration	void nfs_free_mntinfo_list(nfs_mntlist_t *)
version		SUNWprivate_1.1
end

function	nfs_get_filtered_mount_list
include		<libfsmgt.h>
declaration	nfs_mntlist_t *nfs_get_filtered_mount_list(char *resource, \
		char *mountp, char *mntopts, char *time, \
		boolean_t find_overlays, int *errp)
version		SUNWprivate_1.1
end

function	nfs_get_mounts_by_mntopt
include		<libfsmgt.h>
declaration	nfs_mntlist_t *nfs_get_mounts_by_mntopt(char *mntopt, \
		boolean_t find_overlays, int *errp)
version		SUNWprivate_1.1
end

function	nfs_get_mount_list
include		<libfsmgt.h>
declaration	nfs_mntlist_t *nfs_get_mount_list(int *)
version		SUNWprivate_1.1
end

function	netcfg_free_networkid_list
include		<libfsmgt.h>
declaration	void netcfg_free_networkid_list(char **netlist, \
		int num_elements)
version		SUNWprivate_1.1
end

function	netcfg_get_networkid_list
include		<libfsmgt.h>
declaration	char **netcfg_get_networkid_list(int *num_elements, int *errp)
version		SUNWprivate_1.1
end

function	nfssec_free_secmode_list
include		<libfsmgt.h>
declaration	void nfssec_free_secmode_list(char **seclist, int num_elements)
version		SUNWprivate_1.1
end

function	nfssec_get_default_secmode
include		<libfsmgt.h>
declaration	char *nfssec_get_default_secmode(int *errp)
version		SUNWprivate_1.1
end

function	nfssec_get_nfs_secmode_list
include		<libfsmgt.h>
declaration	char **nfssec_get_nfs_secmode_list(int *num_elements, int *errp)
version		SUNWprivate_1.1
end

function	sys_get_hostname
include		<libfsmgt.h>
declaration	char *sys_get_hostname(int *errp)
version		SUNWprivate_1.1
end
