#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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

#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libzonecfg/spec/libzonecfg.spec
#

function	zonecfg_set_root
include		<libzonecfg.h>
declaration	void zonecfg_set_root(const char *)
version		SUNWprivate_1.1
end

function	zonecfg_get_root
include		<libzonecfg.h>
declaration	const char *zonecfg_get_root(void)
version		SUNWprivate_1.1
end

function	zonecfg_in_alt_root
include		<libzonecfg.h>
declaration	boolean_t zonecfg_in_alt_root(void)
version		SUNWprivate_1.1
end

function	zonecfg_init_handle
include		<libzonecfg.h>
declaration	zone_dochandle_t zonecfg_init_handle(void)
version		SUNWprivate_1.1
end		

function	zonecfg_get_handle
include		<libzonecfg.h>
declaration	int zonecfg_get_handle(const char *, zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_get_attach_handle
include		<libzonecfg.h>
declaration	int zonecfg_get_attach_handle(const char *, const char *, boolean_t, zone_dochandle_t)
version		SUNWprivate_1.1
end

function	zonecfg_get_snapshot_handle
include		<libzonecfg.h>
declaration	int zonecfg_get_snapshot_handle(const char *, zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_get_template_handle
include		<libzonecfg.h>
declaration	int zonecfg_get_template_handle(const char *, const char *, \
			zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_attach_manifest
include		<libzonecfg.h>
declaration	int zonecfg_attach_manifest(int, zone_dochandle_t, \
			zone_dochandle_t)
version		SUNWprivate_1.1
end

function	zonecfg_check_handle
include		<libzonecfg.h>
declaration	int zonecfg_check_handle(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_fini_handle
include		<libzonecfg.h>
declaration	void zonecfg_fini_handle(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_get_name
include		<libzonecfg.h>
declaration	int zonecfg_get_name(zone_dochandle_t, char *, size_t)
version		SUNWprivate_1.1
end		

function	zonecfg_set_name
include		<libzonecfg.h>
declaration	int zonecfg_set_name(zone_dochandle_t, char *)
version		SUNWprivate_1.1
end		

function	zonecfg_validate_zonename
include		<libzonecfg.h>
declaration	int zonecfg_validate_zonename(char *)
version		SUNWprivate_1.1
end

function	zonecfg_get_zonepath
include		<libzonecfg.h>
declaration	int zonecfg_get_zonepath(zone_dochandle_t, char *, size_t)
version		SUNWprivate_1.1
end		

function	zonecfg_set_zonepath
include		<libzonecfg.h>
declaration	int zonecfg_set_zonepath(zone_dochandle_t, char *)
version		SUNWprivate_1.1
end		

function	zonecfg_get_autoboot
include		<libzonecfg.h>
declaration	int zonecfg_get_autoboot(zone_dochandle_t, boolean_t *);
version		SUNWprivate_1.1
end		

function	zonecfg_set_autoboot
include		<libzonecfg.h>
declaration	int zonecfg_set_autoboot(zone_dochandle_t, boolean_t)
version		SUNWprivate_1.1
end		

function	zonecfg_get_pool
include		<libzonecfg.h>
declaration	int zonecfg_get_pool(zone_dochandle_t, char *, size_t)
version		SUNWprivate_1.1
end		

function	zonecfg_set_pool
include		<libzonecfg.h>
declaration	int zonecfg_set_pool(zone_dochandle_t, char *)
version		SUNWprivate_1.1
end		

function	zonecfg_get_limitpriv
include		<libzonecfg.h>
declaration	int zonecfg_get_limitpriv(zone_dochandle_t, char **)
version		SUNWprivate_1.1
end		

function	zonecfg_set_limitpriv
include		<libzonecfg.h>
declaration	int zonecfg_set_limitpriv(zone_dochandle_t, char *)
version		SUNWprivate_1.1
end		

function	zonecfg_get_bootargs
include		<libzonecfg.h>
declaration	int zonecfg_get_bootargs(zone_dochandle_t, char *, size_t)
version		SUNWprivate_1.1
end		

function	zonecfg_set_bootargs
include		<libzonecfg.h>
declaration	int zonecfg_set_bootargs(zone_dochandle_t, char *)
version		SUNWprivate_1.1
end		

function	zonecfg_add_fs_option
include		<libzonecfg.h>
declaration	int zonecfg_add_fs_option(struct zone_fstab *, char *)
version		SUNWprivate_1.1
end		

function	zonecfg_remove_fs_option
include		<libzonecfg.h>
declaration	int zonecfg_remove_fs_option(struct zone_fstab *, char *)
version		SUNWprivate_1.1
end		

function	zonecfg_free_fs_option_list
include		<libzonecfg.h>
declaration	void zonecfg_free_fs_option_list(zone_fsopt_t *)
version		SUNWprivate_1.1
end		

function	zonecfg_add_filesystem
include		<libzonecfg.h>
declaration	int zonecfg_add_filesystem(zone_dochandle_t, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_delete_filesystem
include		<libzonecfg.h>
declaration	int zonecfg_delete_filesystem(zone_dochandle_t, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_modify_filesystem
include		<libzonecfg.h>
declaration	int zonecfg_modify_filesystem(zone_dochandle_t, struct zone_fstab *, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_lookup_filesystem
include		<libzonecfg.h>
declaration	int zonecfg_lookup_filesystem(zone_dochandle_t, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_add_ipd
include		<libzonecfg.h>
declaration	int zonecfg_add_ipd(zone_dochandle_t, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_delete_ipd
include		<libzonecfg.h>
declaration	int zonecfg_delete_ipd(zone_dochandle_t, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_modify_ipd
include		<libzonecfg.h>
declaration	int zonecfg_modify_ipd(zone_dochandle_t, struct zone_fstab *, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_lookup_ipd
include		<libzonecfg.h>
declaration	int zonecfg_lookup_ipd(zone_dochandle_t, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function        zonecfg_add_nwif
include         <libzonecfg.h>
declaration     int zonecfg_add_nwif(zone_dochandle_t, struct zone_nwiftab *)
version         SUNWprivate_1.1
end             

function        zonecfg_delete_nwif
include         <libzonecfg.h>
declaration     int zonecfg_delete_nwif(zone_dochandle_t, struct zone_nwiftab *)
version         SUNWprivate_1.1
end             

function        zonecfg_modify_nwif
include         <libzonecfg.h>
declaration     int zonecfg_modify_nwif(zone_dochandle_t, struct zone_nwiftab *, struct zone_nwiftab *)
version         SUNWprivate_1.1
end             

function        zonecfg_lookup_nwif
include         <libzonecfg.h>
declaration     int zonecfg_lookup_nwif(zone_dochandle_t, struct zone_nwiftab *)
version         SUNWprivate_1.1
end             

function	zonecfg_lookup_dev
include		<libzonecfg.h>
declaration	int zonecfg_lookup_dev(zone_dochandle_t, struct zone_devtab *)
version		SUNWprivate_1.1
end		

function	zonecfg_add_dev
include		<libzonecfg.h>
declaration	int zonecfg_add_dev(zone_dochandle_t, struct zone_devtab *)
version		SUNWprivate_1.1
end		

function	zonecfg_delete_dev
include		<libzonecfg.h>
declaration	int zonecfg_delete_dev(zone_dochandle_t, struct zone_devtab *)
version		SUNWprivate_1.1
end		

function	zonecfg_modify_dev
include		<libzonecfg.h>
declaration	int zonecfg_modify_dev(zone_dochandle_t, struct zone_devtab *, struct zone_devtab *)
version		SUNWprivate_1.1
end		

function	zonecfg_match_dev
include		<libzonecfg.h>
declaration	int zonecfg_match_dev(zone_dochandle_t, char *, struct zone_devtab *)
version		SUNWprivate_1.1
end		

function        zonecfg_add_attr
include         <libzonecfg.h>
declaration     int zonecfg_add_attr(zone_dochandle_t, struct zone_attrtab *)
version         SUNWprivate_1.1
end             

function        zonecfg_delete_attr
include         <libzonecfg.h>
declaration     int zonecfg_delete_attr(zone_dochandle_t, struct zone_attrtab *)
version         SUNWprivate_1.1
end             

function        zonecfg_modify_attr
include         <libzonecfg.h>
declaration     int zonecfg_modify_attr(zone_dochandle_t, struct zone_attrtab *, struct zone_attrtab *)
version         SUNWprivate_1.1
end             

function        zonecfg_lookup_attr
include         <libzonecfg.h>
declaration     int zonecfg_lookup_attr(zone_dochandle_t, struct zone_attrtab *)
version         SUNWprivate_1.1
end             

function	zonecfg_add_ds
include		<libzonecfg.h>
declaration	int zonecfg_add_ds(zone_dochandle_t, struct zone_dstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_delete_ds
include		<libzonecfg.h>
declaration	int zonecfg_delete_ds(zone_dochandle_t, struct zone_dstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_modify_ds
include		<libzonecfg.h>
declaration	int zonecfg_modify_ds(zone_dochandle_t, struct zone_dstab *, struct zone_dstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_lookup_ds
include		<libzonecfg.h>
declaration	int zonecfg_lookup_ds(zone_dochandle_t, struct zone_dstab *)
version		SUNWprivate_1.1
end		

function        zonecfg_get_attr_boolean
include         <libzonecfg.h>
declaration     int zonecfg_get_attr_boolean(const struct zone_attrtab *, boolean_t *)
version         SUNWprivate_1.1
end             

function        zonecfg_get_attr_int
include         <libzonecfg.h>
declaration     int zonecfg_get_attr_int(const struct zone_attrtab *, int64_t *)
version         SUNWprivate_1.1
end             

function        zonecfg_get_attr_string
include         <libzonecfg.h>
declaration     int zonecfg_get_attr_string(const struct zone_attrtab *, char *, size_t)
version         SUNWprivate_1.1
end             

function        zonecfg_get_attr_uint
include         <libzonecfg.h>
declaration     int zonecfg_get_attr_uint(const struct zone_attrtab *, uint64_t *)
version         SUNWprivate_1.1
end             

function        zonecfg_add_rctl
include         <libzonecfg.h>
declaration     int zonecfg_add_rctl(zone_dochandle_t, struct zone_rctltab *)
version         SUNWprivate_1.1
end             

function        zonecfg_delete_rctl
include         <libzonecfg.h>
declaration     int zonecfg_delete_rctl(zone_dochandle_t, struct zone_rctltab *)
version         SUNWprivate_1.1
end             

function        zonecfg_modify_rctl
include         <libzonecfg.h>
declaration     int zonecfg_modify_rctl(zone_dochandle_t, struct zone_rctltab *, struct zone_rctltab *)
version         SUNWprivate_1.1
end             

function        zonecfg_lookup_rctl
include         <libzonecfg.h>
declaration     int zonecfg_lookup_rctl(zone_dochandle_t, struct zone_rctltab *)
version         SUNWprivate_1.1
end             

function        zonecfg_add_rctl_value
include         <libzonecfg.h>
declaration     int zonecfg_add_rctl_value(struct zone_rctltab *, struct zone_rctlvaltab *)
version         SUNWprivate_1.1
end             

function        zonecfg_remove_rctl_value
include         <libzonecfg.h>
declaration     int zonecfg_remove_rctl_value(struct zone_rctltab *, struct zone_rctlvaltab *)
version         SUNWprivate_1.1
end             

function	zonecfg_free_rctl_value_list
include		<libzonecfg.h>
declaration	void zonecfg_free_rctl_value_list(struct zone_rctlvaltab *)
version		SUNWprivate_1.1
end

function	zonecfg_strerror
include		<libzonecfg.h>
declaration	char *zonecfg_strerror(int)
version		SUNWprivate_1.1
end		

function	zonecfg_setfsent
include		<libzonecfg.h>
declaration	int zonecfg_setfsent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_getfsent
include		<libzonecfg.h>
declaration	int zonecfg_getfsent(zone_dochandle_t, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_endfsent
include		<libzonecfg.h>
declaration	int zonecfg_endfsent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_setipdent
include		<libzonecfg.h>
declaration	int zonecfg_setipdent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_getipdent
include		<libzonecfg.h>
declaration	int zonecfg_getipdent(zone_dochandle_t, struct zone_fstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_endipdent
include		<libzonecfg.h>
declaration	int zonecfg_endipdent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_setnwifent
include		<libzonecfg.h>
declaration	int zonecfg_setnwifent(zone_dochandle_t);
version		SUNWprivate_1.1
end		

function	zonecfg_getnwifent
include		<libzonecfg.h>
declaration	int zonecfg_getnwifent(zone_dochandle_t, struct zone_nwiftab *)
version		SUNWprivate_1.1
end		

function	zonecfg_endnwifent
include		<libzonecfg.h>
declaration	int zonecfg_endnwifent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_setdevent
include		<libzonecfg.h>
declaration	int zonecfg_setdevent(zone_dochandle_t);
version		SUNWprivate_1.1
end		

function	zonecfg_getdevent
include		<libzonecfg.h>
declaration	int zonecfg_getdevent(zone_dochandle_t, struct zone_devtab *)
version		SUNWprivate_1.1
end		

function	zonecfg_enddevent
include		<libzonecfg.h>
declaration	int zonecfg_enddevent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_setattrent
include		<libzonecfg.h>
declaration	int zonecfg_setattrent(zone_dochandle_t);
version		SUNWprivate_1.1
end		

function	zonecfg_getattrent
include		<libzonecfg.h>
declaration	int zonecfg_getattrent(zone_dochandle_t, struct zone_attrtab *)
version		SUNWprivate_1.1
end		

function	zonecfg_endattrent
include		<libzonecfg.h>
declaration	int zonecfg_endattrent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_setrctlent
include		<libzonecfg.h>
declaration	int zonecfg_setrctlent(zone_dochandle_t);
version		SUNWprivate_1.1
end		

function	zonecfg_getrctlent
include		<libzonecfg.h>
declaration	int zonecfg_getrctlent(zone_dochandle_t, struct zone_rctltab *)
version		SUNWprivate_1.1
end		

function	zonecfg_endrctlent
include		<libzonecfg.h>
declaration	int zonecfg_endrctlent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_setdsent
include		<libzonecfg.h>
declaration	int zonecfg_setdsent(zone_dochandle_t);
version		SUNWprivate_1.1
end		

function	zonecfg_getdsent
include		<libzonecfg.h>
declaration	int zonecfg_getdsent(zone_dochandle_t, struct zone_dstab *)
version		SUNWprivate_1.1
end		

function	zonecfg_enddsent
include		<libzonecfg.h>
declaration	int zonecfg_enddsent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_setpkgent
include		<libzonecfg.h>
declaration	int zonecfg_setpkgent(zone_dochandle_t);
version		SUNWprivate_1.1
end		

function	zonecfg_getpkgent
include		<libzonecfg.h>
declaration	int zonecfg_getpkgent(zone_dochandle_t, struct zone_pkgtab *)
version		SUNWprivate_1.1
end		

function	zonecfg_endpkgent
include		<libzonecfg.h>
declaration	int zonecfg_endpkgent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_setpatchent
include		<libzonecfg.h>
declaration	int zonecfg_setpatchent(zone_dochandle_t);
version		SUNWprivate_1.1
end		

function	zonecfg_getpatchent
include		<libzonecfg.h>
declaration	int zonecfg_getpatchent(zone_dochandle_t, struct zone_patchtab *)
version		SUNWprivate_1.1
end		

function	zonecfg_endpatchent
include		<libzonecfg.h>
declaration	int zonecfg_endpatchent(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_setdevperment
include		<libzonecfg.h>
declaration	int zonecfg_setdevperment(zone_dochandle_t);
version		SUNWprivate_1.1
end		

function	zonecfg_getdevperment
include		<libzonecfg.h>
declaration	int zonecfg_getdevperment(zone_dochandle_t, struct zone_devpermtab *)
version		SUNWprivate_1.1
end		

function	zonecfg_enddevperment
include		<libzonecfg.h>
declaration	int zonecfg_enddevperment(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_destroy
include		<libzonecfg.h>
declaration	int zonecfg_destroy(const char *, boolean_t)
version		SUNWprivate_1.1
end		

function	zonecfg_create_snapshot
include		<libzonecfg.h>
declaration	int zonecfg_create_snapshot(const char *)
version		SUNWprivate_1.1
end		

function	zonecfg_destroy_snapshot
include		<libzonecfg.h>
declaration	int zonecfg_destroy_snapshot(const char *)
version		SUNWprivate_1.1
end		

function	zonecfg_save
include		<libzonecfg.h>
declaration	int zonecfg_save(zone_dochandle_t)
version		SUNWprivate_1.1
end		

function	zonecfg_detach_save
include		<libzonecfg.h>
declaration	int zonecfg_detach_save(zone_dochandle_t, uint_t)
version		SUNWprivate_1.1
end		

function	zonecfg_get_detach_info
include		<libzonecfg.h>
declaration	int zonecfg_get_detach_info(zone_dochandle_t, boolean_t)
version		SUNWprivate_1.1
end

function	zonecfg_detached
include		<libzonecfg.h>
declaration	boolean_t zonecfg_detached(const char *)
version		SUNWprivate_1.1
end		

function	zonecfg_rm_detached
include		<libzonecfg.h>
declaration	void zonecfg_rm_sw_inventory(zone_dochandle_t, boolean_t)
version		SUNWprivate_1.1
end		

function	zonecfg_devwalk
include		<libzonecfg.h>
declaration	int zonecfg_devwalk(zone_dochandle_t, int (*cb)(const char *, uid_t, gid_t, mode_t, const char *, void *), void *data)
version		SUNWprivate_1.1
end

function	zonecfg_devperms_apply
include		<libzonecfg.h>
declaration	int zonecfg_devperms_apply(zone_dochandle_t, const char *, uid_t, gid_t, mode_t, const char *)
version		SUNWprivate_1.1
end

function	zonecfg_access
include		<libzonecfg.h>
declaration	int zonecfg_access(const char *, int)
version		SUNWprivate_1.1
end		

function	zonecfg_default_privset
include		<libzonecfg.h>
declaration	int zonecfg_default_privset(struct priv_set *)
version		SUNWprivate_1.1
end

function	zonecfg_get_privset
include		<libzonecfg.h>
declaration	int zonecfg_get_privset(zone_dochandle_t, priv_set_t *, \
		    char **)
version		SUNWprivate_1.1
end

function	getzoneent
include		<libzonecfg.h>
declaration	char *getzoneent(FILE *);
version		SUNWprivate_1.1
exception	$return == 0
end

function	getzoneent_private
include		<libzonecfg.h>
declaration	struct zoneent *getzoneent_private(FILE *);
version		SUNWprivate_1.1
end

function	setzoneent
include		<libzonecfg.h>
declaration	FILE *setzoneent(void);
version		SUNWprivate_1.1
end

function	endzoneent
include		<libzonecfg.h>
declaration	void endzoneent(FILE *);
version		SUNWprivate_1.1
end

function	putzoneent
include		<libzonecfg.h>
declaration	void putzoneent(struct zoneent *, int)
version		SUNWprivate_1.1
end

function	zone_get_id
include		<libzonecfg.h>
declaration	int zone_get_id(const char *, zoneid_t *);
version		SUNWprivate_1.1
end

function	zone_get_rootpath
include		<libzonecfg.h>
declaration	int zone_get_rootpath(char *, char *, size_t);
version		SUNWprivate_1.1
end		

function	zone_get_zonepath
include		<libzonecfg.h>
declaration	int zone_get_zonepath(char *, char *, size_t);
version		SUNWprivate_1.1
end		

function	zone_get_state
include		<libzonecfg.h>
declaration	int zone_get_state(char *, zone_state_t *);
version		SUNWprivate_1.1
end		

function	zone_set_state
include		<libzonecfg.h>
declaration	int zone_set_state(char *, zone_state_t)
version		SUNWprivate_1.1
end		

function	zone_state_str
include		<libzonecfg.h>
declaration	char *zone_state_str(zone_state_t);
version		SUNWprivate_1.1
end		

function	zonecfg_get_name_by_uuid
include		<libzonecfg.h>
declaration	int zonecfg_get_name_by_uuid(const uuid_t, char *, size_t)
version		SUNWprivate_1.1
end

function	zonecfg_get_uuid
include		<libzonecfg.h>
declaration	int zonecfg_get_uuid(const char *, uuid_t)
version		SUNWprivate_1.1
end

function	zonecfg_same_net_address
include		<libzonecfg.h>
declaration	boolean_t zonecfg_same_net_address(char *, char *);
version		SUNWprivate_1.1
end		

function	zonecfg_valid_net_address
include		<libzonecfg.h>
declaration	int zonecfg_valid_net_address(char *, struct lifreq *);
version		SUNWprivate_1.1
end		

function	zonecfg_is_rctl
include		<libzonecfg.h>
declaration	boolean_t zonecfg_is_rctl(const char *);
version		SUNWprivate_1.1
end

function	zonecfg_valid_fs_type
include		<libzonecfg.h>
declaration	boolean_t zonecfg_valid_fs_type(const char *);
version		SUNWprivate_1.1
end

function	zonecfg_valid_rctlname
include		<libzonecfg.h>
declaration	boolean_t zonecfg_valid_rctlname(const char *);
version		SUNWprivate_1.1
end

function	zonecfg_valid_rctlblk
include		<libzonecfg.h>
declaration	boolean_t zonecfg_valid_rctlblk(const rctlblk_t *);
version		SUNWprivate_1.1
end

function	zonecfg_valid_rctl
include		<libzonecfg.h>
declaration	boolean_t zonecfg_valid_rctl(const char *, const rctlblk_t *);
version		SUNWprivate_1.1
end

function	zonecfg_construct_rctlblk
include		<libzonecfg.h>
declaration	int zonecfg_construct_rctlblk(const struct zone_rctlvaltab *, rctlblk_t *);
version		SUNWprivate_1.1
end

function	zonecfg_notify_bind
include		<libzonecfg.h>
declaration 	void * zonecfg_notify_bind(int(*)(const char *, zoneid_t zid, const char *, const char *, void *), void *)
version		SUNWprivate_1.1
end

function	zonecfg_notify_unbind		
include		<libzonecfg.h>
delcaration	void zonecfg_notify_unbind(void *)
version		SUNWprivate_1.1
end

function	 zonecfg_notify_critical_enter
include		<libzonecfg.h>
declaration	void zonecfg_notify_critical_enter(void *);
version		SUNWprivate_1.1
end

function 	zonecfg_notify_critical_abort
include		<libzonecfg.h>
declaration	void zonecfg_notify_critical_abort(void *);
version		SUNWprivate_1.1
end

function 	zonecfg_notify_critical_exit
include		<libzonecfg.h>
declaration	int zonecfg_notify_critical_exit(void *);
version		SUNWprivate_1.1
end

function	zonecfg_open_scratch
include		<libzonecfg.h>
declaration	FILE *zonecfg_open_scratch(const char *, boolean_t)
version		SUNWprivate_1.1
end

function	zonecfg_lock_scratch
include		<libzonecfg.h>
declaration	int zonecfg_lock_scratch(FILE *)
version		SUNWprivate_1.1
end

function	zonecfg_close_scratch
include		<libzonecfg.h>
declaration	void zonecfg_close_scratch(FILE *)
version		SUNWprivate_1.1
end

function	zonecfg_get_scratch
include		<libzonecfg.h>
declaration	int zonecfg_get_scratch(FILE *, char *, size_t, char *, \
			size_t, char *, size_t)
version		SUNWprivate_1.1
end

function	zonecfg_find_scratch
include		<libzonecfg.h>
declaration	int zonecfg_find_scratch(FILE *, const char *, const char *, \
			char *, size_t)
version		SUNWprivate_1.1
end

function	zonecfg_reverse_scratch
include		<libzonecfg.h>
declaration	int zonecfg_reverse_scratch(FILE *, const char *, char *, \
			size_t, char *, size_t)
version		SUNWprivate_1.1
end

function	zonecfg_add_scratch
include		<libzonecfg.h>
declaration	int zonecfg_add_scratch(FILE *, const char *, const char *, \
			const char *)
version		SUNWprivate_1.1
end

function	zonecfg_delete_scratch
include		<libzonecfg.h>
declaration	int zonecfg_delete_scratch(FILE *, const char *)
version		SUNWprivate_1.1
end

function	zonecfg_is_scratch
include		<libzonecfg.h>
declaration	boolean_t zonecfg_is_scratch(const char *)
version		SUNWprivate_1.1
end

function	zonecfg_find_mounts
include		<libzonecfg.h>
declaration	int zonecfg_find_mounts(char * , int (*)(char *, void*), void*);
version		SUNWprivate_1.1
end

