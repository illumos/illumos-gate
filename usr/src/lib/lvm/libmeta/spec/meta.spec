#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/lvm/libmeta/spec/meta.spec

function	meta_smf_enable
version		SUNWprivate_1.1
end

function	meta_smf_disable
version		SUNWprivate_1.1
end

function	meta_smf_getmask
version		SUNWprivate_1.1
end

function	meta_smf_isonline
version		SUNWprivate_1.1
end

function	meta_svm_sysevent
version		SUNWprivate_1.1
end

function	close_admin
version		SUNWprivate_1.1
end

function	meta_dev_ismeta
version		SUNWprivate_1.1
end

function	meta_get_nunits
version		SUNWprivate_1.1
end

function	metamakedev
version		SUNWprivate_1.1
end

function	meta_get_tstate
version		SUNWprivate_1.1
end

function	meta_expldev
version		SUNWprivate_1.1
end

function	meta_cmpldev
version		SUNWprivate_1.1
end

function	meta_getmajor
version		SUNWprivate_1.1
end

function	meta_getminor
version		SUNWprivate_1.1
end

function	open_admin
version		SUNWprivate_1.1
end

function	meta_concat_generic
version		SUNWprivate_1.1
end

function	meta_concat_parent
version		SUNWprivate_1.1
end

function	meta_check_driveinset
version		SUNWprivate_1.1
end

function	meta_check_drivemounted
version		SUNWprivate_1.1
end

function	meta_check_driveswapped
version		SUNWprivate_1.1
end

function	meta_check_inmeta
version		SUNWprivate_1.1
end

function	meta_check_inset
version		SUNWprivate_1.1
end

function	meta_check_root
version		SUNWprivate_1.1
end

function	meta_check_inuse
version		SUNWprivate_1.1
end

function	meta_imp_drvused
version		SUNWprivate_1.1
end

function	meta_check_overlap
version		SUNWprivate_1.1
end

function	meta_check_samedrive
version		SUNWprivate_1.1
end

function	meta_check_inreplica
version		SUNWprivate_1.1
end

function	meta_check_replica
version		SUNWprivate_1.1
end

function	meta_db_addsidenms
version		SUNWprivate_1.1
end

function	meta_db_attach
version		SUNWprivate_1.1
end

function	meta_db_delsidenm
version		SUNWprivate_1.1
end

function	meta_db_detach
version		SUNWprivate_1.1
end

function	meta_db_minreplica
version		SUNWprivate_1.1
end

function	meta_db_patch
version		SUNWprivate_1.1
end

function	meta_get_replica_names
version		SUNWprivate_1.1
end

function	meta_setup_db_locations
version		SUNWprivate_1.1
end

function	meta_sync_db_locations
version		SUNWprivate_1.1
end

function	meta_getdidminorbykey
version		SUNWprivate_1.1
end

function	meta_getdidbykey
version		SUNWprivate_1.1
end

function	meta_setdid
version		SUNWprivate_1.1
end

function	metafreereplicalist
version		SUNWprivate_1.1
end

function	metareplicalist
version		SUNWprivate_1.1
end

function	meta_db_balance
version		SUNWprivate_1.1
end

function	meta_create_non_dup_list
version		SUNWprivate_1.1
end

function	sdssc_add_hosts
version		SUNWprivate_1.1
end

function	sdssc_bind_library
version		SUNWprivate_1.1
end

function	sdssc_bindclusterdevs
version		SUNWprivate_1.1
end

function	sdssc_binddevs
version		SUNWprivate_1.1
end

function	sdssc_clnt_bind_devs
version		SUNWprivate_1.1
end

function	sdssc_clnt_proxy_cmd
version		SUNWprivate_1.1
end

function	sdssc_cm_nid2nm
version		SUNWprivate_1.1
end

function	sdssc_cm_nm2nid
version		SUNWprivate_1.1
end

function	sdssc_cm_sr_nid2nm
version		SUNWprivate_1.1
end

function	sdssc_cm_sr_nm2nid
version		SUNWprivate_1.1
end

function	sdssc_cmd_proxy
version		SUNWprivate_1.1
end

function	sdssc_convert_cluster_path
version		SUNWprivate_1.1
end

function	sdssc_convert_ctd_path
version		SUNWprivate_1.1
end

function	sdssc_convert_path_free
version		SUNWprivate_1.1
end

function	sdssc_create_begin
version		SUNWprivate_1.1
end

function	sdssc_mo_create_begin
version		SUNWprivate_1.1
end

function	sdssc_create_end
version		SUNWprivate_1.1
end

function	sdssc_delete_begin
version		SUNWprivate_1.1
end

function	sdssc_delete_end
version		SUNWprivate_1.1
end

function	sdssc_delete_hosts
version		SUNWprivate_1.1
end

function	sdssc_free_mdcerr_list
version		SUNWprivate_1.1
end

function	sdssc_freenodelist
version		SUNWprivate_1.1
end

function	sdssc_get_index
version		SUNWprivate_1.1
end

function	sdssc_get_primary_host
version		SUNWprivate_1.1
end

function	sdssc_get_priv_ipaddr
version		SUNWprivate_1.1
end

function	sdssc_get_services
version		SUNWprivate_1.1
end

function	sdssc_get_services_free
version		SUNWprivate_1.1
end

function	sdssc_getnodelist
version		SUNWprivate_1.1
end

function	sdssc_gettransportbynode
version		SUNWprivate_1.1
end

function	sdssc_notify_service
version		SUNWprivate_1.1
end

function	sdssc_property_get
version		SUNWprivate_1.1
end

function	sdssc_property_set
version		SUNWprivate_1.1
end

function	sdssc_suspend
version		SUNWprivate_1.1
end

function	sdssc_version
version		SUNWprivate_1.1
end

function	getdevstamp
version		SUNWprivate_1.1
end

function	setdevstamp
version		SUNWprivate_1.1
end

function	md_eprintf
version		SUNWprivate_1.1
end

function	meta_mc_log
version		SUNWprivate_1.1
end

function	md_logpfx
version		SUNWprivate_1.1
end

function	md_perror
version		SUNWprivate_1.1
end

function	mdclrerror
version		SUNWprivate_1.1
end

function	mdcomperror
version		SUNWprivate_1.1
end

function	mddeverror
version		SUNWprivate_1.1
end

function	mddserror
version		SUNWprivate_1.1
end

function	mde_perror
version		SUNWprivate_1.1
end

function	mde_sperror
version		SUNWprivate_1.1
end

function	mderror
version		SUNWprivate_1.1
end

function	mderrorextra
version		SUNWprivate_1.1
end

function	mdhserror
version		SUNWprivate_1.1
end

function	mdhsperror
version		SUNWprivate_1.1
end

function	mdmddberror
version		SUNWprivate_1.1
end

function	mdmderror
version		SUNWprivate_1.1
end

function	mdrpccreateerror
version		SUNWprivate_1.1
end

function	mdrpcerror
version		SUNWprivate_1.1
end

function	mdstealerror
version		SUNWprivate_1.1
end

function	mdsyserror
version		SUNWprivate_1.1
end

function	mduseerror
version		SUNWprivate_1.1
end

function	metaioctl
version		SUNWprivate_1.1
end

function	meta_getalldevs
version		SUNWprivate_1.1
end

function	meta_getdevs
version		SUNWprivate_1.1
end

function	meta_getvtoc
version		SUNWprivate_1.1
end

function	meta_setvtoc
version		SUNWprivate_1.1
end

function	hs_state_to_name
version		SUNWprivate_1.1
end

function	meta_check_hotspare
version		SUNWprivate_1.1
end

function	meta_check_hsp
version		SUNWprivate_1.1
end

function	meta_check_inhsp
version		SUNWprivate_1.1
end

function	meta_create_hsp
version		SUNWprivate_1.1
end

function	meta_free_hsp
version		SUNWprivate_1.1
end

function	meta_get_hsp
version		SUNWprivate_1.1
end

function	meta_gethspnmentbyid
version		SUNWprivate_1.1
end

function	meta_get_hsp_common
version		SUNWprivate_1.1
end

function	meta_get_hsp_names
version		SUNWprivate_1.1
end

function	meta_hs_add
version		SUNWprivate_1.1
end

function	meta_hs_delete
version		SUNWprivate_1.1
end

function	meta_hs_enable
version		SUNWprivate_1.1
end

function	meta_hs_replace
version		SUNWprivate_1.1
end

function	meta_hsp_print
version		SUNWprivate_1.1
end

function	meta_hsp_reset
version		SUNWprivate_1.1
end

function	meta_init_hsp
version		SUNWprivate_1.1
end

function	meta_invalidate_hsp
version		SUNWprivate_1.1
end

function	metachkhsp
version		SUNWprivate_1.1
end

function	meta_adjust_geom
version		SUNWprivate_1.1
end

function	meta_cook_syntax
version		SUNWprivate_1.1
end

function	meta_init_name
version		SUNWprivate_1.1
end

function	meta_init_make_device
version		SUNWprivate_1.1
end

function	meta_setup_geom
version		SUNWprivate_1.1
end

function	parse_interlace
version		SUNWprivate_1.1
end

function	close_mnttab
version		SUNWprivate_1.1
end

function	open_mnttab
version		SUNWprivate_1.1
end

function	meta_update_md_cf
version		SUNWprivate_1.1
end

function	med_errnum_to_str
version		SUNWprivate_1.1
end

function	Calloc
version		SUNWprivate_1.1
end

function	Free
version		SUNWprivate_1.1
end

function	Malloc
version		SUNWprivate_1.1
end

function	Realloc
version		SUNWprivate_1.1
end

function	Strdup
version		SUNWprivate_1.1
end

function	Zalloc
version		SUNWprivate_1.1
end

function	cl_get_setkey
version		SUNWprivate_1.1
end

function	cl_set_setkey
version		SUNWprivate_1.1
end

function	clnt_add_drv_sidenms
version		SUNWprivate_1.1
end

function	clnt_adddrvs
version		SUNWprivate_1.1
end

function	clnt_addhosts
version		SUNWprivate_1.1
end

function	clnt_createset
version		SUNWprivate_1.1
end

function	clnt_del_drv_sidenms
version		SUNWprivate_1.1
end

function	clnt_deldrvs
version		SUNWprivate_1.1
end

function	clnt_delhosts
version		SUNWprivate_1.1
end

function	clnt_delset
version		SUNWprivate_1.1
end

function	clnt_devinfo
version		SUNWprivate_1.1
end

function	clnt_drvused
version		SUNWprivate_1.1
end

function	clnt_devinfo_by_devid
version		SUNWprivate_1.1
end

function	clnt_getset
version		SUNWprivate_1.1
end

function	clnt_mngetset
version		SUNWprivate_1.1
end

function	clnt_gtimeout
version		SUNWprivate_1.1
end

function	clnt_hostname
version		SUNWprivate_1.1
end

function	clnt_lock_set
version		SUNWprivate_1.1
end

function	clnt_nullproc
version		SUNWprivate_1.1
end

function	clnt_ownset
version		SUNWprivate_1.1
end

function	clnt_setnameok
version		SUNWprivate_1.1
end

function	clnt_setnumbusy
version		SUNWprivate_1.1
end

function	clnt_stimeout
version		SUNWprivate_1.1
end

function	clnt_unlock_set
version		SUNWprivate_1.1
end

function	clnt_upd_dr_dbinfo
version		SUNWprivate_1.1
end

function	clnt_upd_dr_flags
version		SUNWprivate_1.1
end

function	clnt_upd_sr_flags
version		SUNWprivate_1.1
end

function	clnt_upd_nr_flags
version		SUNWprivate_1.1
end

function	clnt_updmeds
version		SUNWprivate_1.1
end

function	meta_conv_drvdesc_new2old
version		SUNWprivate_1.1
end

function	meta_conv_drvdesc_old2new
version		SUNWprivate_1.1
end

function	meta_conv_drvname_new2old
version		SUNWprivate_1.1
end

function	meta_conv_drvname_old2new
version		SUNWprivate_1.1
end

function	alloc_olddrvdesc
version		SUNWprivate_1.1
end

function	alloc_newdrvdesc
version		SUNWprivate_1.1
end

function	free_olddrvdesc
version		SUNWprivate_1.1
end

function	free_newdrvdesc
version		SUNWprivate_1.1
end

function	meta_get_devid
version		SUNWprivate_1.1
end

function	meta_print_devid
version		SUNWprivate_1.1
end

function	clnt_mncreateset
version		SUNWprivate_1.1
end

function	clnt_joinset
version		SUNWprivate_1.1
end

function	clnt_mnsetmaster
version		SUNWprivate_1.1
end

function	clnt_mn_mirror_resync_all
version		SUNWprivate_1.1
end

function	clnt_mn_sp_update_abr
version		SUNWprivate_1.1
end

function	free_sr
version		SUNWprivate_1.1
end

function	short_circuit_getset
version		SUNWprivate_1.1
end

function	commitset
version		SUNWprivate_1.1
end

function	dr_cache_add
version		SUNWprivate_1.1
end

function	dr_cache_del
version		SUNWprivate_1.1
end

function	mnnr_cache_add
version		SUNWprivate_1.1
end

function	mnnr_cache_del
version		SUNWprivate_1.1
end

function	drdup
version		SUNWprivate_1.1
end

function	get_db_rec
version		SUNWprivate_1.1
end

function	get_ur_rec
version		SUNWprivate_1.1
end

function	metad_getsetbyname
version		SUNWprivate_1.1
end

function	metad_getsetbynum
version		SUNWprivate_1.1
end

function	resnarf_set
version		SUNWprivate_1.1
end

function	metad_isautotakebyname
version		SUNWprivate_1.1
end

function	metad_isautotakebynum
version		SUNWprivate_1.1
end

function	s_delrec
version		SUNWprivate_1.1
end

function	s_delset
version		SUNWprivate_1.1
end

function	s_ownset
version		SUNWprivate_1.1
end

function	set_snarf
version		SUNWprivate_1.1
end

function	setdup
version		SUNWprivate_1.1
end

function	mnsetdup
version		SUNWprivate_1.1
end

function	sr_cache_add
version		SUNWprivate_1.1
end

function	sr_cache_del
version		SUNWprivate_1.1
end

function	sr_cache_flush
version		SUNWprivate_1.1
end

function	sr_cache_flush_setno
version		SUNWprivate_1.1
end

function	sr_validate
version		SUNWprivate_1.1
end

function	sr_del_drv
version		SUNWprivate_1.1
end

function	clnt_med_get_data
version		SUNWprivate_1.1
end

function	clnt_med_get_rec
version		SUNWprivate_1.1
end

function	clnt_med_hostname
version		SUNWprivate_1.1
end

function	clnt_med_null
version		SUNWprivate_1.1
end

function	clnt_med_upd_data
version		SUNWprivate_1.1
end

function	clnt_med_upd_rec
version		SUNWprivate_1.1
end

function	meddstealerror
version		SUNWprivate_1.1
end

function	meta_h2hi
version		SUNWprivate_1.1
end

function	meta_hi2h
version		SUNWprivate_1.1
end

function	meta_med_hnm2ip
version		SUNWprivate_1.1
end

function	setup_med_cfg
version		SUNWprivate_1.1
end

function	defmhiargs
version		SUNWprivate_1.1
end

function	meta_drive_to_disk_status_list
version		SUNWprivate_1.1
end

function	meta_free_disk_status_list
version		SUNWprivate_1.1
end

function	meta_free_drive_info_list
version		SUNWprivate_1.1
end

function	meta_free_im_set_desc
version		SUNWprivate_1.1
end

function	meta_get_drive_names
version		SUNWprivate_1.1
end

function	meta_list_disks
version		SUNWprivate_1.1
end

function	meta_imp_set
version		SUNWprivate_1.1
end

function	meta_list_drives
version		SUNWprivate_1.1
end

function	meta_get_and_report_set_info
version		SUNWprivate_1.1
end

function	meta_prune_cnames
version		SUNWprivate_1.1
end

function	print_concise_entry
version		SUNWprivate_1.1
end

function	meta_get_raid_col_state
version		SUNWprivate_1.1
end

function	meta_get_stripe_state
version		SUNWprivate_1.1
end

function	meta_get_hs_state
version		SUNWprivate_1.1
end

function	meta_rel_own
version		SUNWprivate_1.1
end

function	meta_replica_quorum
version		SUNWprivate_1.1
end

function	meta_status_own
version		SUNWprivate_1.1
end

function	meta_take_own
version		SUNWprivate_1.1
end

function	mhstealerror
version		SUNWprivate_1.1
end

function	rel_own_bydd
version		SUNWprivate_1.1
end

function	tk_own_bydd
version		SUNWprivate_1.1
end

function	meta_check_inmirror
version		SUNWprivate_1.1
end

function	meta_check_mirror
version		SUNWprivate_1.1
end

function	meta_check_submirror
version		SUNWprivate_1.1
end

function	meta_create_mirror
version		SUNWprivate_1.1
end

function	meta_free_mirror
version		SUNWprivate_1.1
end

function	meta_get_mirror
version		SUNWprivate_1.1
end

function	meta_get_mirror_names
version		SUNWprivate_1.1
end

function	meta_init_mirror
version		SUNWprivate_1.1
end

function	meta_mirror_anycomp_is_err
version		SUNWprivate_1.1
end

function	meta_mirror_attach
version		SUNWprivate_1.1
end

function	meta_mirror_detach
version		SUNWprivate_1.1
end

function	meta_mirror_enable
version		SUNWprivate_1.1
end

function	meta_mirror_get_params
version		SUNWprivate_1.1
end

function	meta_mirror_offline
version		SUNWprivate_1.1
end

function	meta_mirror_online
version		SUNWprivate_1.1
end

function	meta_mirror_print
version		SUNWprivate_1.1
end

function	meta_mirror_replace
version		SUNWprivate_1.1
end

function	meta_mirror_reset
version		SUNWprivate_1.1
end

function	meta_mirror_set_params
version		SUNWprivate_1.1
end

function	meta_print_mirror_options
version		SUNWprivate_1.1
end

function	name_to_pass_num
version		SUNWprivate_1.1
end

function	name_to_rd_opt
version		SUNWprivate_1.1
end

function	name_to_wr_opt
version		SUNWprivate_1.1
end

function	rd_opt_to_name
version		SUNWprivate_1.1
end

function	sm_state_to_action
version		SUNWprivate_1.1
end

function	sm_state_to_name
version		SUNWprivate_1.1
end

function	wr_opt_to_name
version		SUNWprivate_1.1
end

function	meta_mirror_resync
version		SUNWprivate_1.1
end

function	meta_mirror_resync_all
version		SUNWprivate_1.1
end

function	meta_mn_mirror_resync_all
version		SUNWprivate_1.1
end

function	meta_mirror_resync_kill_all
version		SUNWprivate_1.1
end

function	meta_mirror_resync_block_all
version		SUNWprivate_1.1
end

function	meta_mirror_resync_unblock_all
version		SUNWprivate_1.1
end

function	meta_mirror_resync_unblock
version		SUNWprivate_1.1
end

function	meta_mirror_resync_kill
version		SUNWprivate_1.1
end

function	meta_get_mountp
version		SUNWprivate_1.1
end

function	blkname
version		SUNWprivate_1.1
end

function	get_devname
version		SUNWprivate_1.1
end

function	get_hspname
version		SUNWprivate_1.1
end

function	get_mdname
version		SUNWprivate_1.1
end

function	meta_is_all
version		SUNWprivate_1.1
end

function	meta_is_none
version		SUNWprivate_1.1
end

function	is_hspname
version		SUNWprivate_1.1
end

function	sr2setdesc
version		SUNWprivate_1.1
end

function	is_existing_metadevice
version		SUNWprivate_1.1
end

function	is_existing_hsp
version		SUNWprivate_1.1
end

function	is_metaname
version		SUNWprivate_1.1
end

function	meta_canonicalize
version		SUNWprivate_1.1
end

function	meta_get_hotspare_names
version		SUNWprivate_1.1
end

function	meta_getdev
version		SUNWprivate_1.1
end

function	metachkcomp
version		SUNWprivate_1.1
end

function	metachkdisk
version		SUNWprivate_1.1
end

function	metachkmeta
version		SUNWprivate_1.1
end

function	metadevname
version		SUNWprivate_1.1
end

function	metadiskname
version		SUNWprivate_1.1
end

function	metadrivename
version		SUNWprivate_1.1
end

function	metadrivenamelist
version		SUNWprivate_1.1
end

function	metadrivenamelist_append
version		SUNWprivate_1.1
end

function	meta_drivenamelist_append_wrapper
version		SUNWprivate_1.1
end

function	metafakesetname
version		SUNWprivate_1.1
end

function	metaflushmetanames
version		SUNWprivate_1.1
end

function	metaflushnames
version		SUNWprivate_1.1
end

function	metaflushsetname
version		SUNWprivate_1.1
end

function	metaflushsidenames
version		SUNWprivate_1.1
end

function	metaflushdrivenames
version		SUNWprivate_1.1
end

function	metafreedrivename
version		SUNWprivate_1.1
end

function	metafreedrivenamelist
version		SUNWprivate_1.1
end

function	metafreehspnamelist
version		SUNWprivate_1.1
end

function	metafreenamelist
version		SUNWprivate_1.1
end

function	metaget_setdesc
version		SUNWprivate_1.1
end

function	metahsphspname
version		SUNWprivate_1.1
end

function	metahspname
version		SUNWprivate_1.1
end

function	metahspnamelist
version		SUNWprivate_1.1
end

function	metahspnamelist_append
version		SUNWprivate_1.1
end

function	metaislocalset
version		SUNWprivate_1.1
end

function	metaismeta
version		SUNWprivate_1.1
end

function	metaissameset
version		SUNWprivate_1.1
end

function	metakeyname
version		SUNWprivate_1.1
end

function	metamnumname
version		SUNWprivate_1.1
end

function	meta_name_getname
version		SUNWprivate_1.1
end

function	metaname
version		SUNWprivate_1.1
end

function	metaname_fast
version		SUNWprivate_1.1
end

function	metanamelist
version		SUNWprivate_1.1
end

function	metanamelist_append
version		SUNWprivate_1.1
end

function	metasetname
version		SUNWprivate_1.1
end

function	metasetnosetname
version		SUNWprivate_1.1
end

function	metaslicename
version		SUNWprivate_1.1
end

function	ctlr_cache_add
version		SUNWprivate_1.1
end

function	ctlr_cache_look
version		SUNWprivate_1.1
end

function	getdrvnode
version		SUNWprivate_1.1
end

function	meta_free_unit
version		SUNWprivate_1.1
end

function	meta_get_mdunit
version		SUNWprivate_1.1
end

function	meta_get_unit
version		SUNWprivate_1.1
end

function	meta_invalidate_name
version		SUNWprivate_1.1
end

function	meta_isopen
version		SUNWprivate_1.1
end

function	meta_match_enclosure
version		SUNWprivate_1.1
end

function	metaflushctlrcache
version		SUNWprivate_1.1
end

function	metafreevtoc
version		SUNWprivate_1.1
end

function	metagetcinfo
version		SUNWprivate_1.1
end

function	metagetdevicesname
version		SUNWprivate_1.1
end

function	metagetgeom
version		SUNWprivate_1.1
end

function	metagetlabel
version		SUNWprivate_1.1
end

function	metagetmiscname
version		SUNWprivate_1.1
end

function	metagetpartno
version		SUNWprivate_1.1
end

function	metagetset
version		SUNWprivate_1.1
end

function	metagetsize
version		SUNWprivate_1.1
end

function	metagetstart
version		SUNWprivate_1.1
end

function	metagetvtoc
version		SUNWprivate_1.1
end

function	metahasmddb
version		SUNWprivate_1.1
end

function	metasetvtoc
version		SUNWprivate_1.1
end

function	add_key_name
version		SUNWprivate_1.1
end

function	add_name
version		SUNWprivate_1.1
end

function	del_key_name
version		SUNWprivate_1.1
end

function	del_key_names
version		SUNWprivate_1.1
end

function	del_name
version		SUNWprivate_1.1
end

function	meta_getnmbykey
version		SUNWprivate_1.1
end

function	meta_getnmentbydev
version		SUNWprivate_1.1
end

function	meta_getnmentbykey
version		SUNWprivate_1.1
end

function	evdrv2evlib_typetab
version		SUNWprivate_1.1
end

function	meta_notify_createq
version		SUNWprivate_1.1
end

function	meta_notify_deleteq
version		SUNWprivate_1.1
end

function	meta_notify_doputev
version		SUNWprivate_1.1
end

function	meta_notify_flushq
version		SUNWprivate_1.1
end

function	meta_notify_freeevlist
version		SUNWprivate_1.1
end

function	meta_notify_getev
version		SUNWprivate_1.1
end

function	meta_notify_getevlist
version		SUNWprivate_1.1
end

function	meta_notify_listq
version		SUNWprivate_1.1
end

function	meta_notify_putev
version		SUNWprivate_1.1
end

function	meta_notify_putevlist
version		SUNWprivate_1.1
end

function	meta_notify_sendev
version		SUNWprivate_1.1
end

function	meta_notify_validq
version		SUNWprivate_1.1
end

function	tag2obj_typetab
version		SUNWprivate_1.1
end

function	meta_patch_fsdev
version		SUNWprivate_1.1
end

function	meta_patch_swapdev
version		SUNWprivate_1.1
end

function	meta_patch_vfstab
version		SUNWprivate_1.1
end

function	meta_patch_rootdev
version		SUNWprivate_1.1
end

function	meta_prbits
version		SUNWprivate_1.1
end

function	meta_print_all
version		SUNWprivate_1.1
end

function	meta_print_name
version		SUNWprivate_1.1
end

function	meta_print_time
version		SUNWprivate_1.1
end

function	meta_print_hrtime
version		SUNWprivate_1.1
end

function	meta_check_column
version		SUNWprivate_1.1
end

function	meta_check_inraid
version		SUNWprivate_1.1
end

function	meta_check_raid
version		SUNWprivate_1.1
end

function	meta_create_raid
version		SUNWprivate_1.1
end

function	meta_default_raid_interlace
version		SUNWprivate_1.1
end

function	meta_free_raid
version		SUNWprivate_1.1
end

function	meta_get_raid_common
version		SUNWprivate_1.1
end

function	meta_get_raid
version		SUNWprivate_1.1
end

function	meta_get_raid_names
version		SUNWprivate_1.1
end

function	meta_init_raid
version		SUNWprivate_1.1
end

function	meta_print_raid_options
version		SUNWprivate_1.1
end

function	meta_raid_anycomp_is_err
version		SUNWprivate_1.1
end

function	meta_raid_attach
version		SUNWprivate_1.1
end

function	meta_raid_check_interlace
version		SUNWprivate_1.1
end

function	meta_raid_enable
version		SUNWprivate_1.1
end

function	meta_raid_get_params
version		SUNWprivate_1.1
end

function	meta_raid_print
version		SUNWprivate_1.1
end

function	meta_raid_regen_byname
version		SUNWprivate_1.1
end

function	meta_raid_replace
version		SUNWprivate_1.1
end

function	meta_raid_reset
version		SUNWprivate_1.1
end

function	meta_raid_set_params
version		SUNWprivate_1.1
end

function	meta_raid_state_cnt
version		SUNWprivate_1.1
end

function	meta_raid_valid
version		SUNWprivate_1.1
end

function	raid_col_state_to_name
version		SUNWprivate_1.1
end

function	raid_state_to_action
version		SUNWprivate_1.1
end

function	raid_state_to_name
version		SUNWprivate_1.1
end

function	meta_raid_resync
version		SUNWprivate_1.1
end

function	meta_raid_resync_all
version		SUNWprivate_1.1
end

function	meta_exchange
version		SUNWprivate_1.1
end

function	meta_rename
version		SUNWprivate_1.1
end

function	meta_enable_byname
version		SUNWprivate_1.1
end

function	meta_replace_byname
version		SUNWprivate_1.1
end

function	meta_reset
version		SUNWprivate_1.1
end

function	meta_reset_all
version		SUNWprivate_1.1
end

function	meta_reset_by_name
version		SUNWprivate_1.1
end

function	meta_resync_all
version		SUNWprivate_1.1
end

function	meta_resync_byname
version		SUNWprivate_1.1
end

function	do_owner_ioctls
version		SUNWprivate_1.1
end

function	commd_get_verbosity
version		SUNWprivate_1.1
end

function	commd_get_outfile
version		SUNWprivate_1.1
end

function	get_max_meds
version		SUNWprivate_1.1
end

function	get_max_sets
version		SUNWprivate_1.1
end

function	getmyside
version		SUNWprivate_1.1
end

function	getsetbyname
version		SUNWprivate_1.1
end

function	getsetbynum
version		SUNWprivate_1.1
end

function	meta_check_drive_inuse
version		SUNWprivate_1.1
end

function	meta_check_ownership
version		SUNWprivate_1.1
end

function	meta_check_ownership_on_host
version		SUNWprivate_1.1
end

function	meta_get_reserved_names
version		SUNWprivate_1.1
end

function	meta_getnextside_devinfo
version		SUNWprivate_1.1
end

function	meta_is_drive_in_anyset
version		SUNWprivate_1.1
end

function	meta_is_drive_in_thisset
version		SUNWprivate_1.1
end

function	meta_is_devid_in_anyset
version		SUNWprivate_1.1
end

function	meta_is_devid_in_thisset
version		SUNWprivate_1.1
end

function	meta_set_balance
version		SUNWprivate_1.1
end

function	meta_set_destroy
version		SUNWprivate_1.1
end

function	meta_set_purge
version		SUNWprivate_1.1
end

function	meta_set_query
version		SUNWprivate_1.1
end

function	metadrivename_withdrkey
version		SUNWprivate_1.1
end

function	metafreedrivedesc
version		SUNWprivate_1.1
end

function	metaget_drivedesc
version		SUNWprivate_1.1
end

function	metaget_drivedesc_fromnamelist
version		SUNWprivate_1.1
end

function	metaget_drivedesc_sideno
version		SUNWprivate_1.1
end

function	metaget_setownership
version		SUNWprivate_1.1
end

function	mynode
version		SUNWprivate_1.1
end

function	strinlst
version		SUNWprivate_1.1
end

function	meta_set_adddrives
version		SUNWprivate_1.1
end

function	meta_set_deletedrives
version		SUNWprivate_1.1
end

function	meta_set_checkname
version		SUNWprivate_1.1
end

function	meta_set_addhosts
version		SUNWprivate_1.1
end

function	meta_set_deletehosts
version		SUNWprivate_1.1
end

function	meta_set_addmeds
version		SUNWprivate_1.1
end

function	meta_set_deletemeds
version		SUNWprivate_1.1
end

function	meta_set_auto_take
version		SUNWprivate_1.1
end

function	checkdrive_onnode
version		SUNWprivate_1.1
end

function	getnodeside
version		SUNWprivate_1.1
end

function	halt_set
version		SUNWprivate_1.1
end

function	metadrivedesc_append
version		SUNWprivate_1.1
end

function	nodehasset
version		SUNWprivate_1.1
end

function	nodesuniq
version		SUNWprivate_1.1
end

function	own_set
version		SUNWprivate_1.1
end

function	resync_genid
version		SUNWprivate_1.1
end

function	setup_db_bydd
version		SUNWprivate_1.1
end

function	snarf_set
version		SUNWprivate_1.1
end

function	meta_set_release
version		SUNWprivate_1.1
end

function	meta_set_take
version		SUNWprivate_1.1
end

function	meta_set_join
version		SUNWprivate_1.1
end

function	meta_set_withdraw
version		SUNWprivate_1.1
end

function	meta_update_mb
version		SUNWprivate_1.1
end

function	allsigs
version		SUNWprivate_1.1
end

function	md_daemonize
version		SUNWprivate_1.1
end

function	md_exit
version		SUNWprivate_1.1
end

function	md_got_sig
version		SUNWprivate_1.1
end

function	setup_mc_log
version		SUNWprivate_1.1
end

function	md_init
version		SUNWprivate_1.1
end

function	md_init_nosig
version		SUNWprivate_1.1
end

function	md_init_daemon
version		SUNWprivate_1.1
end

function	md_post_sig
version		SUNWprivate_1.1
end

function	md_rb_sig_handling_off
version		SUNWprivate_1.1
end

function	md_rb_sig_handling_on
version		SUNWprivate_1.1
end

function	md_which_sig
version		SUNWprivate_1.1
end

function	meta_lock
version		SUNWprivate_1.1
end

function	meta_lock_name
version		SUNWprivate_1.1
end

function	meta_lock_nowait
version		SUNWprivate_1.1
end

function	meta_lock_status
version		SUNWprivate_1.1
end

function	meta_unlock
version		SUNWprivate_1.1
end

function	metalogfp
version		SUNWprivate_1.1
end

function	metasyslog
version		SUNWprivate_1.1
end

function	verbosity
version		SUNWprivate_1.1
end

function	start_time
version		SUNWprivate_1.1
end

function	myname
version		SUNWprivate_1.1
end

function	procsigs
version		SUNWprivate_1.1
end

function	rb_test
version		SUNWprivate_1.1
end

function	meta_stat
version		SUNWprivate_1.1
end

function	metaflushstatcache
version		SUNWprivate_1.1
end

function	comp_state_to_name
version		SUNWprivate_1.1
end

function	meta_check_component
version		SUNWprivate_1.1
end

function	meta_check_instripe
version		SUNWprivate_1.1
end

function	meta_check_stripe
version		SUNWprivate_1.1
end

function	meta_create_stripe
version		SUNWprivate_1.1
end

function	meta_default_stripe_interlace
version		SUNWprivate_1.1
end

function	meta_find_erred_comp
version		SUNWprivate_1.1
end

function	meta_free_stripe
version		SUNWprivate_1.1
end

function	meta_get_stripe_common
version		SUNWprivate_1.1
end

function	meta_get_stripe
version		SUNWprivate_1.1
end

function	meta_get_stripe_names
version		SUNWprivate_1.1
end

function	meta_init_stripe
version		SUNWprivate_1.1
end

function	meta_print_stripe_options
version		SUNWprivate_1.1
end

function	meta_recover_sp
version		SUNWprivate_1.1
end

function	meta_sp_issp
version		SUNWprivate_1.1
end

function	meta_sp_reset_component
version		SUNWprivate_1.1
end

function	meta_sp_attach
version		SUNWprivate_1.1
end

function	meta_sp_update_abr
version		SUNWprivate_1.1
end

function	meta_mn_sp_update_abr
version		SUNWprivate_1.1
end

function	meta_get_sp_common
version		SUNWprivate_1.1
end

function	meta_get_sp
version		SUNWprivate_1.1
end

function	meta_free_sp
version		SUNWprivate_1.1
end

function	meta_get_sp_names
version		SUNWprivate_1.1
end

function	meta_sp_can_create_sps
version		SUNWprivate_1.1
end

function	meta_sp_can_create_sps_on_drive
version		SUNWprivate_1.1
end

function	meta_sp_get_free_space
version		SUNWprivate_1.1
end

function	meta_sp_get_free_space_on_drive
version		SUNWprivate_1.1
end

function	meta_sp_get_number_of_possible_sps
version		SUNWprivate_1.1
end

function	meta_sp_get_number_of_possible_sps_on_drive
version		SUNWprivate_1.1
end

function	meta_sp_get_possible_sp_size
version		SUNWprivate_1.1
end

function	meta_sp_get_possible_sp_size_on_drive
version		SUNWprivate_1.1
end

function	meta_sp_parsesize
version		SUNWprivate_1.1
end

function	meta_stripe_anycomp_is_err
version		SUNWprivate_1.1
end

function	meta_stripe_attach
version		SUNWprivate_1.1
end

function	meta_stripe_check_interlace
version		SUNWprivate_1.1
end

function	meta_stripe_get_params
version		SUNWprivate_1.1
end

function	meta_stripe_print
version		SUNWprivate_1.1
end

function	meta_stripe_replace
version		SUNWprivate_1.1
end

function	meta_stripe_reset
version		SUNWprivate_1.1
end

function	meta_stripe_set_params
version		SUNWprivate_1.1
end

function	meta_systemfile_append_mddb
version		SUNWprivate_1.1
end

function	meta_systemfile_append_mdroot
version		SUNWprivate_1.1
end

function	meta_systemfile_copy
version		SUNWprivate_1.1
end

function	meta_tab_find
version		SUNWprivate_1.1
end

function	meta_tab_free
version		SUNWprivate_1.1
end

function	meta_tab_parse
version		SUNWprivate_1.1
end

function	meta_check_intrans
version		SUNWprivate_1.1
end

function	meta_check_log
version		SUNWprivate_1.1
end

function	meta_check_master
version		SUNWprivate_1.1
end

function	meta_free_trans
version		SUNWprivate_1.1
end

function	meta_get_trans
version		SUNWprivate_1.1
end

function	meta_get_trans_common
version		SUNWprivate_1.1
end

function	meta_get_trans_names
version		SUNWprivate_1.1
end

function	meta_logs_print
version		SUNWprivate_1.1
end

function	meta_trans_detach
version		SUNWprivate_1.1
end

function	meta_trans_print
version		SUNWprivate_1.1
end

function	meta_trans_replace
version		SUNWprivate_1.1
end

function	meta_trans_reset
version		SUNWprivate_1.1
end

function	mt_flags_to_action
version		SUNWprivate_1.1
end

function	mt_flags_to_name
version		SUNWprivate_1.1
end

function	mt_l_error_to_action
version		SUNWprivate_1.1
end

function	mt_l_error_to_name
version		SUNWprivate_1.1
end

function	transstats
version		SUNWprivate_1.1
end

function	meta_getuserflags
version		SUNWprivate_1.1
end

function	meta_setuserflags
version		SUNWprivate_1.1
end

function	metarpcclose
version		SUNWprivate_1.1
end

function	metarpccloseall
version		SUNWprivate_1.1
end

function	metarpcopen
version		SUNWprivate_1.1
end

function	splicename
version		SUNWprivate_1.1
end

function	splitname
version		SUNWprivate_1.1
end

function	crcfreetab
version		SUNWprivate_1.1
end

function	crcfunc
version		SUNWprivate_1.1
end

function	mdnullerror
version		SUNWprivate_1.1
end

function	xdr_comp_state_t
version		SUNWprivate_1.1
end

function	xdr_comp_t
version		SUNWprivate_1.1
end

function	xdr_diskaddr_t
version		SUNWprivate_1.1
end

function	xdr_hotspare_states_t
version		SUNWprivate_1.1
end

function	xdr_hs_t
version		SUNWprivate_1.1
end

function	xdr_hsp_t
version		SUNWprivate_1.1
end

function	xdr_md_common_t
version		SUNWprivate_1.1
end

function	xdr_md_comp_errno_t
version		SUNWprivate_1.1
end

function	xdr_md_comp_error_t
version		SUNWprivate_1.1
end

function	xdr_md_comp_t
version		SUNWprivate_1.1
end

function	xdr_md_dev_errno_t
version		SUNWprivate_1.1
end

function	xdr_md_dev_error_t
version		SUNWprivate_1.1
end

function	xdr_md_drive_desc
version		SUNWprivate_1.1
end

function	xdr_md_drive_record
version		SUNWprivate_1.1
end

function	xdr_md_ds_errno_t
version		SUNWprivate_1.1
end

function	xdr_md_ds_error_t
version		SUNWprivate_1.1
end

function	xdr_md_errclass_t
version		SUNWprivate_1.1
end

function	xdr_md_error_info_t
version		SUNWprivate_1.1
end

function	xdr_md_error_t
version		SUNWprivate_1.1
end

function	xdr_md_hs_errno_t
version		SUNWprivate_1.1
end

function	xdr_md_hs_error_t
version		SUNWprivate_1.1
end

function	xdr_md_hs_t
version		SUNWprivate_1.1
end

function	xdr_md_hsp_errno_t
version		SUNWprivate_1.1
end

function	xdr_md_hsp_error_t
version		SUNWprivate_1.1
end

function	xdr_md_hsp_t
version		SUNWprivate_1.1
end

function	xdr_md_md_errno_t
version		SUNWprivate_1.1
end

function	xdr_md_md_error_t
version		SUNWprivate_1.1
end

function	xdr_md_mddb_errno_t
version		SUNWprivate_1.1
end

function	xdr_md_mddb_error_t
version		SUNWprivate_1.1
end

function	xdr_md_mirror_t
version		SUNWprivate_1.1
end

function	xdr_md_name_prefix
version		SUNWprivate_1.1
end

function	xdr_md_name_suffix
version		SUNWprivate_1.1
end

function	xdr_md_parent_t
version		SUNWprivate_1.1
end

function	xdr_md_raid_t
version		SUNWprivate_1.1
end

function	xdr_md_raidcol_t
version		SUNWprivate_1.1
end

function	xdr_md_replica_t
version		SUNWprivate_1.1
end

function	xdr_md_replica_recerr_t
version		SUNWprivate_1.1
end

function	xdr_md_replicalist_t
version		SUNWprivate_1.1
end

function	xdr_md_riflags_t
version		SUNWprivate_1.1
end

function	xdr_md_row_t
version		SUNWprivate_1.1
end

function	xdr_md_rpc_error_t
version		SUNWprivate_1.1
end

function	xdr_md_set_desc
version		SUNWprivate_1.1
end

function	xdr_md_set_record
version		SUNWprivate_1.1
end

function	xdr_md_setkey_t
version		SUNWprivate_1.1
end

function	xdr_md_shared_t
version		SUNWprivate_1.1
end

function	xdr_md_splitname
version		SUNWprivate_1.1
end

function	xdr_md_stackcap_t
version		SUNWprivate_1.1
end

function	xdr_md_status_t
version		SUNWprivate_1.1
end

function	xdr_md_stripe_t
version		SUNWprivate_1.1
end

function	xdr_md_submirror_t
version		SUNWprivate_1.1
end

function	xdr_md_sys_error_t
version		SUNWprivate_1.1
end

function	xdr_md_trans_t
version		SUNWprivate_1.1
end

function	xdr_md_types_t
version		SUNWprivate_1.1
end

function	xdr_md_ur_get_cmd_t
version		SUNWprivate_1.1
end

function	xdr_md_use_errno_t
version		SUNWprivate_1.1
end

function	xdr_md_use_error_t
version		SUNWprivate_1.1
end

function	xdr_md_void_errno_t
version		SUNWprivate_1.1
end

function	xdr_md_void_error_t
version		SUNWprivate_1.1
end

function	xdr_mdcinfo_t
version		SUNWprivate_1.1
end

function	xdr_mddb_cfgcmd_t
version		SUNWprivate_1.1
end

function	xdr_mddb_recstatus_t
version		SUNWprivate_1.1
end

function	xdr_mddb_type_t
version		SUNWprivate_1.1
end

function	xdr_mddb_usercmd_t
version		SUNWprivate_1.1
end

function	xdr_mddb_userrec_t
version		SUNWprivate_1.1
end

function	xdr_mddrivename_t
version		SUNWprivate_1.1
end

function	xdr_mddrivenamelist_t
version		SUNWprivate_1.1
end

function	xdr_mdgeom_t
version		SUNWprivate_1.1
end

function	xdr_mdhspname_t
version		SUNWprivate_1.1
end

function	xdr_mdhspnamelist_t
version		SUNWprivate_1.1
end

function	xdr_mdname_t
version		SUNWprivate_1.1
end

function	xdr_mdnamelist_t
version		SUNWprivate_1.1
end

function	xdr_mdnmtype_t
version		SUNWprivate_1.1
end

function	xdr_mdpart_t
version		SUNWprivate_1.1
end

function	xdr_mdsetname_t
version		SUNWprivate_1.1
end

function	xdr_mdsetnamelist_t
version		SUNWprivate_1.1
end

function	xdr_mdsidenames_t
version		SUNWprivate_1.1
end

function	xdr_mdvtoc_t
version		SUNWprivate_1.1
end

function	xdr_minor_or_hsp_t
version		SUNWprivate_1.1
end

function	xdr_mm_params_t
version		SUNWprivate_1.1
end

function	xdr_mm_pass_num_t
version		SUNWprivate_1.1
end

function	xdr_mm_rd_opt_t
version		SUNWprivate_1.1
end

function	xdr_mm_wr_opt_t
version		SUNWprivate_1.1
end

function	xdr_mr_params_t
version		SUNWprivate_1.1
end

function	xdr_ms_params_t
version		SUNWprivate_1.1
end

function	xdr_mt_debug_t
version		SUNWprivate_1.1
end

function	xdr_mt_flags_t
version		SUNWprivate_1.1
end

function	xdr_mt_l_error_t
version		SUNWprivate_1.1
end

function	xdr_rcs_flags_t
version		SUNWprivate_1.1
end

function	xdr_rcs_state_t
version		SUNWprivate_1.1
end

function	xdr_replica_flags_t
version		SUNWprivate_1.1
end

function	xdr_rus_state_t
version		SUNWprivate_1.1
end

function	xdr_sm_flags_t
version		SUNWprivate_1.1
end

function	xdr_sm_state_t
version		SUNWprivate_1.1
end

function	xdr_unit_t
version		SUNWprivate_1.1
end

function	xdr_clnt_stat
version		SUNWprivate_1.1
end

function	xdr_md_timeval32_t
version		SUNWprivate_1.1
end

function	xdr_daddr_t
version		SUNWprivate_1.1
end

function	xdr_md_dev64_t
version		SUNWprivate_1.1
end

function	xdr_dev_t
version		SUNWprivate_1.1
end

function	xdr_md_alias_ip_t
version		SUNWprivate_1.1
end

function	xdr_md_alias_nm_t
version		SUNWprivate_1.1
end

function	xdr_md_h_arr_t
version		SUNWprivate_1.1
end

function	xdr_md_h_t
version		SUNWprivate_1.1
end

function	xdr_md_hi_arr_t
version		SUNWprivate_1.1
end

function	xdr_md_hi_t
version		SUNWprivate_1.1
end

function	xdr_md_node_nm_arr_t
version		SUNWprivate_1.1
end

function	xdr_md_node_nm_t
version		SUNWprivate_1.1
end

function	xdr_md_set_nm_t
version		SUNWprivate_1.1
end

function	xdr_mddb_recid_t
version		SUNWprivate_1.1
end

function	xdr_mdkey_t
version		SUNWprivate_1.1
end

function	xdr_minor_t
version		SUNWprivate_1.1
end

function	xdr_off_t
version		SUNWprivate_1.1
end

function	xdr_set_t
version		SUNWprivate_1.1
end

function	xdr_side_t
version		SUNWprivate_1.1
end

function	xdr_size_t
version		SUNWprivate_1.1
end

function	xdr_timeval
version		SUNWprivate_1.1
end

function	md_in_daemon
version		SUNWprivate_1.1
end

function	mdrpc_add_drv_sidenms_1
version		SUNWprivate_1.1
end

function	mdrpc_adddrvs_1
version		SUNWprivate_1.1
end

function	mdrpc_addhosts_1
version		SUNWprivate_1.1
end

function	mdrpc_createset_1
version		SUNWprivate_1.1
end

function	mdrpc_del_drv_sidenms_1
version		SUNWprivate_1.1
end

function	mdrpc_deldrvs_1
version		SUNWprivate_1.1
end

function	mdrpc_delhosts_1
version		SUNWprivate_1.1
end

function	mdrpc_delset_1
version		SUNWprivate_1.1
end

function	mdrpc_drvused_1
version		SUNWprivate_1.1
end

function	mdrpc_flush_internal_1
version		SUNWprivate_1.1
end

function	mdrpc_getset_1
version		SUNWprivate_1.1
end

function	mdrpc_gtimeout_1
version		SUNWprivate_1.1
end

function	mdrpc_hostname_1
version		SUNWprivate_1.1
end

function	mdrpc_lock_set_1
version		SUNWprivate_1.1
end

function	mdrpc_nullproc_1
version		SUNWprivate_1.1
end

function	mdrpc_ownset_1
version		SUNWprivate_1.1
end

function	mdrpc_setnameok_1
version		SUNWprivate_1.1
end

function	mdrpc_setnumbusy_1
version		SUNWprivate_1.1
end

function	mdrpc_stimeout_1
version		SUNWprivate_1.1
end

function	mdrpc_unlock_set_1
version		SUNWprivate_1.1
end

function	mdrpc_upd_dr_dbinfo_1
version		SUNWprivate_1.1
end

function	mdrpc_upd_dr_flags_1
version		SUNWprivate_1.1
end

function	mdrpc_upd_sr_flags_1
version		SUNWprivate_1.1
end

function	mdrpc_updmeds_1
version		SUNWprivate_1.1
end

function	mdrpc_add_drv_sidenms_2
version		SUNWprivate_1.1
end

function	mdrpc_adddrvs_2
version		SUNWprivate_1.1
end

function	mdrpc_addhosts_2
version		SUNWprivate_1.1
end

function	mdrpc_createset_2
version		SUNWprivate_1.1
end

function	mdrpc_del_drv_sidenms_2
version		SUNWprivate_1.1
end

function	mdrpc_deldrvs_2
version		SUNWprivate_1.1
end

function	mdrpc_delhosts_2
version		SUNWprivate_1.1
end

function	mdrpc_delset_2
version		SUNWprivate_1.1
end

function	mdrpc_devinfo_2
version		SUNWprivate_1.1
end

function	mdrpc_drvused_2
version		SUNWprivate_1.1
end

function	mdrpc_flush_internal_2
version		SUNWprivate_1.1
end

function	mdrpc_getset_2
version		SUNWprivate_1.1
end

function	mdrpc_mngetset_2
version		SUNWprivate_1.1
end

function	mdrpc_gtimeout_2
version		SUNWprivate_1.1
end

function	mdrpc_hostname_2
version		SUNWprivate_1.1
end

function	mdrpc_lock_set_2
version		SUNWprivate_1.1
end

function	mdrpc_nullproc_2
version		SUNWprivate_1.1
end

function	mdrpc_ownset_2
version		SUNWprivate_1.1
end

function	mdrpc_setnameok_2
version		SUNWprivate_1.1
end

function	mdrpc_setnumbusy_2
version		SUNWprivate_1.1
end

function	mdrpc_stimeout_2
version		SUNWprivate_1.1
end

function	mdrpc_unlock_set_2
version		SUNWprivate_1.1
end

function	mdrpc_upd_dr_dbinfo_2
version		SUNWprivate_1.1
end

function	mdrpc_upd_dr_flags_2
version		SUNWprivate_1.1
end

function	mdrpc_upd_sr_flags_2
version		SUNWprivate_1.1
end

function	mdrpc_upd_nr_flags_2
version		SUNWprivate_1.1
end

function	mdrpc_updmeds_2
version		SUNWprivate_1.1
end

function	mdrpc_mncreateset_2
version		SUNWprivate_1.1
end

function	mdrpc_mnsetmaster_2
version		SUNWprivate_1.1
end

function	mdrpc_mn_mirror_resync_all_2
version		SUNWprivate_1.1
end

function	mdrpc_mn_sp_update_abr_2
version		SUNWprivate_1.1
end

function	xdr_mdrpc_bool_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_createset_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_createset_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_mncreateset_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_devinfo_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_devidstr_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_devid_name_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_devinfo_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_devinfo_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_devinfo_2_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_devid_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_devid_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_devid_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_drives_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_drives_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_drv_sidenm_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_drv_sidenm_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_drvused_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_drvused_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_generic_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_getset_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_getset_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_getset_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_mngetset_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_gtimeout_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_host_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_host_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_hostname_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_null_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_setlock_res
version		SUNWprivate_1.1
end

function	xdr_mdrpc_setno_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_setno_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_sp_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_sp_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_stimeout_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_stimeout_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_upd_dr_flags_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_upd_dr_flags_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_upd_sr_flags_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_upd_sr_flags_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_upd_nr_flags_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_updmeds_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_updmeds_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_mnsetmaster_2_args
version		SUNWprivate_1.1
end

function	xdr_stringarray
version		SUNWprivate_1.1
end

function	med_get_data_1
version		SUNWprivate_1.1
end

function	med_get_rec_1
version		SUNWprivate_1.1
end

function	med_hostname_1
version		SUNWprivate_1.1
end

function	med_null_1
version		SUNWprivate_1.1
end

function	med_upd_data_1
version		SUNWprivate_1.1
end

function	med_upd_rec_1
version		SUNWprivate_1.1
end

function	md_med_def_timeout
version		SUNWprivate_1.1
end

function	md_med_pmap_timeout
version		SUNWprivate_1.1
end

function	med_null_err
version		SUNWprivate_1.1
end

function	xdr_md_med_errno_t
version		SUNWprivate_1.1
end

function	xdr_med_args_t
version		SUNWprivate_1.1
end

function	xdr_med_data_t
version		SUNWprivate_1.1
end

function	xdr_med_err_t
version		SUNWprivate_1.1
end

function	xdr_med_get_data_res_t
version		SUNWprivate_1.1
end

function	xdr_med_get_rec_res_t
version		SUNWprivate_1.1
end

function	xdr_med_hnm_res_t
version		SUNWprivate_1.1
end

function	xdr_med_med_t
version		SUNWprivate_1.1
end

function	xdr_med_rec_t
version		SUNWprivate_1.1
end

function	xdr_med_res_t
version		SUNWprivate_1.1
end

function	xdr_med_upd_data_args_t
version		SUNWprivate_1.1
end

function	xdr_med_upd_rec_args_t
version		SUNWprivate_1.1
end

function	mhd_list_1
version		SUNWprivate_1.1
end

function	mhd_relown_1
version		SUNWprivate_1.1
end

function	mhd_status_1
version		SUNWprivate_1.1
end

function	mhd_tkown_1
version		SUNWprivate_1.1
end

function	mhd_null_error
version		SUNWprivate_1.1
end

function	xdr_mhd_drive_status_t
version		SUNWprivate_1.1
end

function	xdr_mhd_drivename_t
version		SUNWprivate_1.1
end

function	xdr_mhd_error_t
version		SUNWprivate_1.1
end

function	xdr_mhd_ff_mode_t
version		SUNWprivate_1.1
end

function	xdr_mhd_list_args_t
version		SUNWprivate_1.1
end

function	xdr_mhd_list_res_t
version		SUNWprivate_1.1
end

function	xdr_mhd_opts_t
version		SUNWprivate_1.1
end

function	xdr_mhd_relown_args_t
version		SUNWprivate_1.1
end

function	xdr_mhd_set_t
version		SUNWprivate_1.1
end

function	xdr_mhd_status_args_t
version		SUNWprivate_1.1
end

function	xdr_mhd_status_res_t
version		SUNWprivate_1.1
end

function	xdr_mhd_tkown_args_t
version		SUNWprivate_1.1
end

function	xdr_mhd_cinfo_t
version		SUNWprivate_1.1
end

function	xdr_mhd_ctlrtype_t
version		SUNWprivate_1.1
end

function	xdr_mhd_did_flags_t
version		SUNWprivate_1.1
end

function	xdr_mhd_drive_id_t
version		SUNWprivate_1.1
end

function	xdr_mhd_drive_info_list_t
version		SUNWprivate_1.1
end

function	xdr_mhd_drive_info_t
version		SUNWprivate_1.1
end

function	xdr_mhd_mhiargs_t
version		SUNWprivate_1.1
end

function	xdr_mhd_serial_t
version		SUNWprivate_1.1
end

function	xdr_mhd_mhioctkown_t
version		SUNWprivate_1.1
end

function	xdr_md_mn_msg_t
version		SUNWprivate_1.1
end

function	xdr_md_mn_nodeid_t
version		SUNWprivate_1.1
end

function	meta_get_current_root
version		SUNWprivate_1.1
end

function	meta_get_current_root_dev
version		SUNWprivate_1.1
end

function	meta_gettimeofday
version		SUNWprivate_1.1
end

function	meta_replicaslice
version		SUNWprivate_1.1
end

function	meta_get_tstate
version		SUNWprivate_1.1
end

function	meta_setmdvtoc
version		SUNWprivate_1.1
end

function	meta_check_devicesize
version		SUNWprivate_1.1
end

function	clnt_devid
version		SUNWprivate_1.1
end

function	meta_number_to_string
version		SUNWprivate_1.1
end

function	meta_repartition_drive
version		SUNWprivate_1.1
end

function	mdmn_send_message
version		SUNWprivate_1.1
end

function	copy_result
version		SUNWprivate_1.1
end

function	free_result
version		SUNWprivate_1.1
end

function	copy_msg
version		SUNWprivate_1.1
end

function	copy_msg_1
version		SUNWprivate_1.1
end

function	free_msg
version		SUNWprivate_1.1
end

function	mdmn_get_handler
version		SUNWprivate_1.1
end

function	mdmn_get_submessage_generator
version		SUNWprivate_1.1
end

function	mdmn_get_message_class
version		SUNWprivate_1.1
end

function	mdmn_get_timeout
version		SUNWprivate_1.1
end

function	meta_read_nodelist
version		SUNWprivate_1.1
end

function	meta_write_nodelist
version		SUNWprivate_1.1
end

function	meta_free_nodelist
version		SUNWprivate_1.1
end

function	meta_is_mn_set
version		SUNWprivate_1.1
end

function	meta_ping_mnset
version		SUNWprivate_1.1
end

function	meta_mn_send_command
version		SUNWprivate_1.1
end

function	meta_mn_send_suspend_writes
version		SUNWprivate_1.1
end

function	meta_mn_send_setsync
version		SUNWprivate_1.1
end

function	meta_mn_send_metaclear_command
version		SUNWprivate_1.1
end

function	meta_mn_send_resync_starting
version		SUNWprivate_1.1
end

function	meta_mn_change_owner
version		SUNWprivate_1.1
end

function	meta_is_mn_name
version		SUNWprivate_1.1
end

function	meta_reconfig_choose_master
version		SUNWprivate_1.1
end

function	meta_mnsync_user_records
version		SUNWprivate_1.1
end

function	meta_mnsync_diskset_mddbs
version		SUNWprivate_1.1
end

function	meta_mnjoin_all
version		SUNWprivate_1.1
end

function	mdmn_create_msgid
version		SUNWprivate_1.1
end

function	mdmn_suspend
version		SUNWprivate_1.1
end

function	mdmn_resume
version		SUNWprivate_1.1
end

function	mdmn_reinit_set
version		SUNWprivate_1.1
end

function	mdmn_msgtype_lock
version		SUNWprivate_1.1
end

function	mdmn_abort
version		SUNWprivate_1.1
end

function	mdmn_send_1
version		SUNWprivate_1.1
end

function	mdmn_work_1
version		SUNWprivate_1.1
end

function	mdmn_wakeup_initiator_1
version		SUNWprivate_1.1
end

function	mdmn_wakeup_master_1
version		SUNWprivate_1.1
end

function	mdmn_comm_lock_1
version		SUNWprivate_1.1
end

function	mdmn_comm_unlock_1
version		SUNWprivate_1.1
end

function	mdmn_comm_suspend_1
version		SUNWprivate_1.1
end

function	mdmn_comm_resume_1
version		SUNWprivate_1.1
end

function	mdmn_comm_reinit_set_1
version		SUNWprivate_1.1
end

function	mdmn_comm_msglock_1
version		SUNWprivate_1.1
end

function	clnt_mdcommdctl
version		SUNWprivate_1.1
end

function	mdrpc_mdcommdctl_2
version		SUNWprivate_1.1
end

function	clnt_mn_is_stale
version		SUNWprivate_1.1
end

function	mdrpc_mn_is_stale_2
version		SUNWprivate_1.1
end

function	clnt_clr_mnsetlock
version		SUNWprivate_1.1
end

function	mdrpc_clr_mnsetlock_2
version		SUNWprivate_1.1
end

function	xdr_mdrpc_sp_flags_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_sp_flags_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_mdcommdctl_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_mdcommdctl_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_getdrivedesc_res
version		SUNWprivate_1.1
end

function	dd_list_dup
version		SUNWprivate_1.1
end

function	mdmn_allocate_changelog
version		SUNWprivate_1.1
end

function	mdmn_reset_changelog
version		SUNWprivate_1.1
end

function	mdmn_log_msg
version		SUNWprivate_1.1
end

function	mdmn_unlog_msg
version		SUNWprivate_1.1
end

function	mdmn_snarf_changelog
version		SUNWprivate_1.1
end

function	mdmn_get_changelogrec
version		SUNWprivate_1.1
end

function	clnt_reset_mirror_owner
version		SUNWprivate_1.1
end

function	mdrpc_reset_mirror_owner_2
version		SUNWprivate_1.1
end

function	clnt_mn_susp_res_io
version		SUNWprivate_1.1
end

function	mdrpc_mn_susp_res_io_2
version		SUNWprivate_1.1
end

function	xdr_mdrpc_mn_susp_res_io_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_mn_susp_res_io_2_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_nodeid_args
version		SUNWprivate_1.1
end

function	xdr_mdrpc_nodeid_2_args
version		SUNWprivate_1.1
end

function	clnt_imp_adddrvs
version		SUNWprivate_1.1
end

function	mdrpc_imp_adddrvs_2
version		SUNWprivate_1.1
end

function	meta_is_member
version		SUNWprivate_1.1
end

function	meta_mn_singlenode
version		SUNWprivate_1.1
end

function	meta_sp_setstatus
version		SUNWprivate_1.1
end

function	xdr_mp_unit_t
version		SUNWprivate_1.1
end

function	xdr_md_set_params_t
version		SUNWprivate_1.1
end

function	meta_fixdevid
version		SUNWprivate_1.1
end

function	meta_upd_ctdnames	
version		SUNWprivate_1.1
end

function	pathname_reload
version		SUNWprivate_1.1
end

function	meta_deviceid_to_nmlist
version		SUNWprivate_1.1
end

function	meta_mn_send_get_tstate
version		SUNWprivate_1.1
end

function	meta_client_create_retry
version		SUNWprivate_1.1
end

function	meta_client_create
version		SUNWprivate_1.1
end

function	read_master_block
version		SUNWprivate_1.1
end

function	pick_good_disk
version		SUNWprivate_1.1
end

function	add_self_name
version		SUNWprivate_1.1
end

function	del_self_name
version		SUNWprivate_1.1
end
