#pragma ident	"%Z%%M%	%I%	%E% SMI"
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
#
# lib/libnsl/spec/private.spec

function	cbc_crypt
version		SUNWprivate_1.1
end	

function	ecb_crypt
version		SUNWprivate_1.1
end	

function	__npd_cbc_crypt
version		SUNWprivate_1.1
end	

function	__npd_ecb_crypt
version		SUNWprivate_1.1
end	

function	xencrypt
version		SUNWprivate_1.1
end	

function	xdecrypt
version		SUNWprivate_1.1
end	

function	_check_daemon_lock
version		SUNWprivate_1.4
end

function	_check_services
version		SUNWprivate_1.4
end

function	_enter_daemon_lock
version		SUNWprivate_1.4
end

function	_herrno2nss
version		SUNWprivate_1.1
end	

function	_create_daemon_lock
version		SUNWprivate_1.4
end

function	_switch_getipnodebyaddr_r
version		SUNWprivate_1.2
end

function	_switch_getipnodebyname_r
version		SUNWprivate_1.2
end

function	_uncached_getipnodebyaddr
version		SUNWprivate_1.2
end

function	_uncached_getipnodebyname
version		SUNWprivate_1.2
end

function	__authenticate
version		SUNWprivate_1.1
end	

function	__break_name
version		SUNWprivate_1.1
end	

function	__clear_directory_ptr
version		SUNWprivate_1.1
end	

function	__clnt_create_loopback
version		SUNWprivate_1.1
end	

function	__cvt2attr
version		SUNWprivate_1.1
end	

function	__do_ismember
version		SUNWprivate_1.1
end	

function	__endhostent6
version		SUNWprivate_1.2
end

function	__gen_dhkeys
version		SUNWprivate_1.1
end	

function	__gethostent6
version		SUNWprivate_1.2
end

function	__getnetnamebyuid
version		SUNWprivate_1.1
end	

function	__key_decryptsession_pk_LOCAL
version		SUNWprivate_1.1
end	

function	__key_encryptsession_pk_LOCAL
version		SUNWprivate_1.1
end	

function	__key_gendes_LOCAL
version		SUNWprivate_1.1
end	

function	__name_distance
version		SUNWprivate_1.1
end	

function	__nderror
version		SUNWprivate_1.1
end	

function	__nis_CacheBind
version		SUNWprivate_1.1
end	

function	__nis_CacheInit
version		SUNWprivate_1.1
end	

function	__nis_CachePrint
version		SUNWprivate_1.1
end	

function	__nis_CacheAddEntry
version		SUNWprivate_1.1
end	

function	__nis_CacheRemoveEntry
version		SUNWprivate_1.1
end	

function	__nis_CacheRestart
version		SUNWprivate_1.1
end	

function	__nis_CacheSearch
version		SUNWprivate_1.1
end	

function	__nis_auth2princ
version		SUNWprivate_1.1
end	

function	__nis_bad_auth_server
version		SUNWprivate_1.1
end	

function	__nis_cast_proc
version		SUNWprivate_1.1
end	

function	__nis_ck_perms
version		SUNWprivate_1.1
end	

function	__nis_clnt_create
version		SUNWprivate_1.1
end

function	__nis_creategroup_obj
version		SUNWprivate_1.1
end	

function	__nis_core_lookup
version		SUNWprivate_1.1
end	

function	__nis_debuglevel
version		SUNWprivate_1.1
end	

function	__nis_destroy_callback
version		SUNWprivate_1.1
end	

function	__nis_flush_group_exp_name
version		SUNWprivate_1.1
end	

function	__nis_get_netconfig
version		SUNWprivate_1.1
end	

function	__nis_get_server
version		SUNWprivate_1.1
end	

function	__nis_group_cache_stats
version		SUNWprivate_1.1
end	

function	__nis_host2nis_server
version		SUNWprivate_1.1
end	

function	__nis_init_callback
version		SUNWprivate_1.1
end	

function	__nis_isadmin
version		SUNWprivate_1.1
end	

function	__nis_ismaster
version		SUNWprivate_1.1
end	

function	__nis_list_localcb
version		SUNWprivate_1.1
end	

function	__nis_local_root
version		SUNWprivate_1.1
end	

function	__nis_map_group_r
version		SUNWprivate_1.1
end	

function	__nis_netconfig2ep
version		SUNWprivate_1.2
end

function	__nis_netconfig_matches_ep
version		SUNWprivate_1.2
end

function	__nis_parse_path
version		SUNWprivate_1.1
end	

function	__nis_pingproc
version		SUNWprivate_1.1
end	

function	__nis_principal
version		SUNWprivate_1.1
end	

function	__nis_release_server
version		SUNWprivate_1.1
end	

function	__nis_reset_state
version		SUNWprivate_1.1
end	

function	__nis_rpc_domain
version		SUNWprivate_1.1
end	

function	__nis_run_callback
version		SUNWprivate_1.1
end	

function	__nis_ss_used
version		SUNWprivate_1.1
end	

function	__nsl_dom
version		SUNWprivate_1.1
end	

function	__free_nis_server
version		SUNWprivate_1.1
end	

function	__nss2herrno
version		SUNWprivate_1.1
end	

function	__rpc_bindresvport
version		SUNWprivate_1.1
end	

function	__rpc_bindresvport_ipv6
version		SUNWprivate_1.2
end

function	__rpc_control
version		SUNWprivate_1.1
end	

function	__rpc_dtbsize
version		SUNWprivate_1.1
end	

function	__rpc_endconf
version		SUNWprivate_1.1
end	

function	__rpc_get_a_size
version		SUNWprivate_1.1
end	

function	__rpc_get_default_domain
version		SUNWprivate_1.1
end	

function	__rpc_get_local_uid
version		SUNWprivate_1.1
end	

function	__rpc_get_t_size
version		SUNWprivate_1.1
end	

function	__rpc_getconf
version		SUNWprivate_1.1
end	

function	__rpc_getconfip
version		SUNWprivate_1.1
end	

function	__rpc_matchserv
version		SUNWprivate_1.1
end	

function	__rpc_negotiate_uid
version		SUNWprivate_1.1
end	

function	__rpc_select_to_poll
version		SUNWprivate_1.1
end	

function	__rpc_setconf
version		SUNWprivate_1.1
end	

function	__rpc_timeval_to_msec
version		SUNWprivate_1.1
end	

function	__rpc_tli_set_options
declaration	int __rpc_tli_set_options(int fd, int optlevel, int optname,\
						int optval)
version		SUNWprivate_1.1
end

function	__rpcbind_is_up
version		SUNWprivate_1.1
end	

function	__rpcfd_to_nconf
version		SUNWprivate_1.1
end	

function	__seterr_reply
version		SUNWprivate_1.1
end	

function	__sethostent6
version		SUNWprivate_1.2
end

function	__svc_get_svcauth
version		SUNWprivate_1.1
end	

function	__svc_nisplus_fdcleanup_hack
version		SUNWprivate_1.1
end	

function	__svc_set_proc_cleanup_cb
version		SUNWprivate_1.1
end	

function	__svc_vc_dup
version		SUNWprivate_1.1
end	

function	__svc_vc_dupcache_init
version		SUNWprivate_1.1
end	

function	__svc_vc_dupdone
version		SUNWprivate_1.1
end	

function	__svcauth_des
version		SUNWprivate_1.1
end	

function	__start_clock
version		SUNWprivate_1.1
end	

function	__stop_clock
version		SUNWprivate_1.1
end	

function	__yp_dobind
version		SUNWprivate_1.1
end	

function	__yp_master_rsvdport
version		SUNWprivate_1.1
end	

function	__yp_all_rsvdport
version		SUNWprivate_1.1
end	

function	__yp_clnt_create_rsvdport
version		SUNWprivate_1.1
end	

function	__yp_rel_binding
version		SUNWprivate_1.1
end	

function	__yp_add_binding
version		SUNWprivate_1.1
end	

function	__empty_yp_cache
version		SUNWprivate_1.1
end	

function	_get_hostserv_inetnetdir_byaddr
version		SUNWprivate_1.1
end	

function	_get_hostserv_inetnetdir_byname
version		SUNWprivate_1.1
end	

function	_rawcombuf
version		SUNWprivate_1.1
end	

function	_switch_gethostbyaddr_r
version		SUNWprivate_1.1
end	

function	_switch_gethostbyname_r
version		SUNWprivate_1.1
end	

function	_svc_getreqset_proc
version		SUNWprivate_1.1
end	

function	_uncached_gethostbyaddr_r
version		SUNWprivate_1.1
end	

function	_uncached_gethostbyname_r
version		SUNWprivate_1.1
end	

function	bitno
version		SUNWprivate_1.1
end	

function	blkno
version		SUNWprivate_1.1
end	

function	calchash
version		SUNWprivate_1.1
end	

function	check_version
version		SUNWprivate_1.1
end	

function	dbrdonly
version		SUNWprivate_1.1
end	

function	dirbuf
version		SUNWprivate_1.1
end	

function	dirf
version		SUNWprivate_1.1
end	

function	firsthash
version		SUNWprivate_1.1
end	

function	getdomainname
version		SUNWprivate_1.1
end	

function	hashinc
version		SUNWprivate_1.1
end	

function	hmask
version		SUNWprivate_1.1
end	

function	key_call
version		SUNWprivate_1.1
end	

function	key_call_ruid
version		SUNWprivate_1.3
end	

function	key_decryptsession_pk
version		SUNWprivate_1.1
end	

function	key_encryptsession_pk
version		SUNWprivate_1.1
end	

function	key_get_conv
version		SUNWprivate_1.1
end	

function	key_setnet
version		SUNWprivate_1.1
end	

function	key_setnet_ruid
version		SUNWprivate_1.3
end	

function	makdatum
version		SUNWprivate_1.1
end	

function	nis_flushgroups
version		SUNWprivate_1.1
end	

function	nis_old_data
version		SUNWprivate_1.1
end	

function	nis_pop_item
version		SUNWprivate_1.1
end	

function	pagbuf
version		SUNWprivate_1.1
end	

function	pagf
version		SUNWprivate_1.1
end	

function	passwd2des
version		SUNWprivate_1.1
end	

function	rpcb_taddr2uaddr
version		SUNWprivate_1.1
end	

function	rpcb_uaddr2taddr
version		SUNWprivate_1.1
end	

function	rtime_tli
version		SUNWprivate_1.1
end	

function	setdomainname
version		SUNWprivate_1.1
end	

function	str2servent
version		SUNWprivate_1.1
end	

function	str2hostent
version		SUNWprivate_1.1
end	

function	str2hostent6
version		SUNWprivate_1.4
end	

function	svc_xprt_alloc
version		SUNWprivate_1.1
end	

function	svc_xprt_free
version		SUNWprivate_1.1
end	

function	t_errlist
version		SUNWprivate_1.1
end	

function	tiusr_statetbl
version		SUNWprivate_1.1
end	

function	usingypmap
version		SUNWprivate_1.1
end	

function	writeColdStartFile
version		SUNWprivate_1.1
end	

function	xdr_authdes_cred
version		SUNWprivate_1.1
end	

function	xdr_authdes_verf
version		SUNWprivate_1.1
end	

function	xdr_cback_data
version		SUNWprivate_1.1
end	

function	xdr_cp_result
version		SUNWprivate_1.1
end	

function	xdr_cryptkeyarg2
version		SUNWprivate_1.1
end	

function	xdr_cryptkeyarg
version		SUNWprivate_1.1
end	

function	xdr_cryptkeyres
version		SUNWprivate_1.1
end	

function	xdr_datum
version		SUNWprivate_1.1
end	

function	xdr_des_block
version		SUNWprivate_1.1
end	

function	xdr_directory_obj
version		SUNWprivate_1.1
end	

function	xdr_dump_args
version		SUNWprivate_1.1
end	

function	xdr_entry_obj
version		SUNWprivate_1.1
end	

function	xdr_fd_args
version		SUNWprivate_1.1
end	

function	xdr_fd_result
version		SUNWprivate_1.1
end	

function	xdr_getcredres
version		SUNWprivate_1.1
end	

function	xdr_gid_t
version		SUNWprivate_1.1
end	

function	xdr_uid_t
version		SUNWprivate_1.1
end	

function	xdr_ib_request
version		SUNWprivate_1.1
end	

function	xdr_log_entry
version		SUNWprivate_1.1
end	

function	xdr_log_result
version		SUNWprivate_1.1
end	

function	xdr_key_netstarg
version		SUNWprivate_1.1
end	

function	xdr_key_netstres
version		SUNWprivate_1.1
end	

function	xdr_keybuf
version		SUNWprivate_1.1
end	

function	xdr_keystatus
version		SUNWprivate_1.1
end	

function	xdr_netbuf
version		SUNWprivate_1.1
end	

function	xdr_netnamestr
version		SUNWprivate_1.1
end	

function	xdr_netobj
version		SUNWprivate_1.1
end	

function	xdr_nis_attr
version		SUNWprivate_1.1
end	

function	xdr_nis_error
version		SUNWprivate_1.1
end	

function	xdr_nis_name
version		SUNWprivate_1.1
end	

function	xdr_nis_object
version		SUNWprivate_1.1
end	

function	xdr_nis_oid
version		SUNWprivate_1.1
end	

function	xdr_nis_result
version		SUNWprivate_1.1
end	

function	xdr_nis_server
version		SUNWprivate_1.1
end	

function	xdr_nis_taglist
version		SUNWprivate_1.1
end	

function	xdr_ns_request
version		SUNWprivate_1.1
end	

function	xdr_obj_p
version		SUNWprivate_1.1
end	

function	xdr_objdata
version		SUNWprivate_1.1
end	

function	xdr_ping_args
version		SUNWprivate_1.1
end	

function	xdr_pmap
version		SUNWprivate_1.1
end	

function	xdr_pmaplist
version		SUNWprivate_1.1
end	

function	xdr_pmaplist_ptr
version		SUNWprivate_1.1
end	

function	xdr_rmtcallargs
version		SUNWprivate_1.1
end	

function	xdr_rmtcallres
version		SUNWprivate_1.1
end	

function	xdr_rpcb
version		SUNWprivate_1.1
end	

function	xdr_rpcb_entry
version		SUNWprivate_1.1
end	

function	xdr_rpcb_entry_list_ptr
version		SUNWprivate_1.1
end	

function	xdr_rpcb_rmtcallargs
version		SUNWprivate_1.1
end	

function	xdr_rpcb_rmtcallres
version		SUNWprivate_1.1
end	

function	xdr_rpcb_stat
version		SUNWprivate_1.1
end	

function	xdr_rpcb_stat_byvers
version		SUNWprivate_1.1
end	

function	xdr_rpcblist
version		SUNWprivate_1.1
end	

function	xdr_rpcblist_ptr
version		SUNWprivate_1.1
end	

function	xdr_rpcbs_addrlist
version		SUNWprivate_1.1
end	

function	xdr_rpcbs_addrlist_ptr
version		SUNWprivate_1.1
end	

function	xdr_rpcbs_proc
version		SUNWprivate_1.1
end	

function	xdr_rpcbs_rmtcalllist
version		SUNWprivate_1.1
end	

function	xdr_rpcbs_rmtcalllist_ptr
version		SUNWprivate_1.1
end	

function	xdr_table_obj
version		SUNWprivate_1.1
end	

function	xdr_ulonglong_t
version		SUNWprivate_1.1
end	

function	xdr_unixcred
version		SUNWprivate_1.1
end	

function	xdr_yp_buf
version		SUNWprivate_1.1
end	

function	xdr_ypall
version		SUNWprivate_1.1
end	

function	xdr_ypbind_domain
version		SUNWprivate_1.1
end	

function	xdr_ypbind_resp
version		SUNWprivate_1.1
end	

function	xdr_ypbind_resptype
version		SUNWprivate_1.1
end	

function	xdr_ypbind_setdom
version		SUNWprivate_1.1
end	

function	xdr_ypdelete_args
version		SUNWprivate_1.1
end	

function	xdr_ypdomain_wrap_string
version		SUNWprivate_1.1
end	

function	xdr_ypmap_parms
version		SUNWprivate_1.1
end	

function	xdr_ypmap_wrap_string
version		SUNWprivate_1.1
end	

function	xdr_ypowner_wrap_string
version		SUNWprivate_1.1
end	

function	xdr_yppasswd
version		SUNWprivate_1.1
end	

function	xdr_yppushresp_xfr
version		SUNWprivate_1.1
end	

function	xdr_ypreq_key
version		SUNWprivate_1.1
end	

function	xdr_ypreq_newxfr
version		SUNWprivate_1.1
end	

function	xdr_ypreq_nokey
version		SUNWprivate_1.1
end	

function	xdr_ypreq_xfr
version		SUNWprivate_1.1
end	

function	xdr_ypresp_key_val
version		SUNWprivate_1.1
end	

function	xdr_ypresp_maplist
version		SUNWprivate_1.1
end	

function	xdr_ypresp_master
version		SUNWprivate_1.1
end	

function	xdr_ypresp_order
version		SUNWprivate_1.1
end	

function	xdr_ypresp_val
version		SUNWprivate_1.1
end	

function	xdr_ypupdate_args
version		SUNWprivate_1.1
end	

function	yp_match_rsvdport
version		SUNWprivate_1.1
end	

function	ypbindproc_domain_3
version		SUNWprivate_1.1
end	

function	__nis_host_is_server
version		SUNWprivate_1.1
end	

function	__nis_remote_lookup
version		SUNWprivate_1.1
end	

function	__nis_finddirectory_remote
version		SUNWprivate_1.1
end	

function	__nis_finddirectory
version		SUNWprivate_1.1
end	

function	nis_bind_dir
version		SUNWprivate_1.1
end	

function	nis_free_binding
version		SUNWprivate_1.1
end	

function	__nis_CacheLocalInit
version		SUNWprivate_1.1
end	

function	__nis_CacheLocalLoadPref
version		SUNWprivate_1.1
end	

function	__nis_serverRefreshCache
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrBindMaster
version		SUNWprivate_1.1
end	

function	__inet_address_count
version		SUNWprivate_1.1
end	

function	xdr_nis_bound_directory
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrRefreshAddress
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrRefreshCallback
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrRefreshBinding
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrTimers
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrRefreshCache
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrInit
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrInit_discard
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrBindReplica
version		SUNWprivate_1.1
end	

function	__inet_get_uaddr
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrCleanup
version		SUNWprivate_1.1
end	

function	__inet_get_networka
version		SUNWprivate_1.1
end	

function	xdr_endpoint
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrBindServer
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrUpdateUaddr
version		SUNWprivate_1.1
end	

function	__inet_uaddr_is_local
version		SUNWprivate_1.1
end	

function	__nis_CacheMgrMarkUp
version		SUNWprivate_1.1
end	

function	xdr_nis_bound_endpoint
version		SUNWprivate_1.1
end	

function	__nis_path
version		SUNWprivate_1.1
end	

function	__nis_path_free
version		SUNWprivate_1.1
end	

function	__nis_print_result
version		SUNWprivate_1.1
end	

function	__nis_send_msg
version		SUNWprivate_1.1
end	

function	__inet_get_local_interfaces
version		SUNWprivate_1.1
end	

function	__inet_get_addr
version		SUNWprivate_1.1
end	

function	__inet_free_local_interfaces
version		SUNWprivate_1.1
end	

function	__getpublickey_cached
version		SUNWprivate_1.1
end	

function	__getpublickey_flush
version		SUNWprivate_1.1
end	

function	__nis_freelogresult
version		SUNWprivate_1.1
end	

function	__svc_nisplus_purge_since
version		SUNWprivate_1.1
end	

function	__svc_nisplus_enable_timestamps
version		SUNWprivate_1.1
end	

function	__nis_force_hard_lookups
version		SUNWprivate_1.1
end	

function	__readColdStartFile
version		SUNWprivate_1.1
end	

function	xdr_setkeyarg3
version		SUNWprivate_1.1
end	

function	xdr_key_netstarg3
version		SUNWprivate_1.1
end	

function	xdr_key_netstres3
version		SUNWprivate_1.1
end	

function	xdr_keybuf3
version		SUNWprivate_1.1
end	

function	xdr_keynum_t
version		SUNWprivate_1.1
end	

function	xdr_mechtype
version		SUNWprivate_1.1
end	

function	xdr_getcredres3
version		SUNWprivate_1.1
end	

function	xdr_cryptkeyarg3
version		SUNWprivate_1.1
end	

function	xdr_cryptkeyres3
version		SUNWprivate_1.1
end	

function	xdr_deskeyarg3
version		SUNWprivate_1.1
end	

function	xdr_deskeyarray
version		SUNWprivate_1.1
end	

function	__nis_host2nis_server_g
version		SUNWprivate_1.1
end	

function	nis_make_rpchandle_gss_svc
version		SUNWprivate_1.1
end	

function	nis_make_rpchandle_gss_svc_ruid
version		SUNWprivate_1.4
end	

function	__nis_gssprin2netname
version		SUNWprivate_1.1
end	

function	__nis_auth2princ_rpcgss
version		SUNWprivate_1.1
end	

function	__nis_dhext_extract_pkey
version		SUNWprivate_1.1
end	

function	__cbc_triple_crypt
version		SUNWprivate_1.1
end	

function	xencrypt_g
version		SUNWprivate_1.1
end	

function	xdecrypt_g
version		SUNWprivate_1.1
end	

function	__nis_authtype2mechalias
version		SUNWprivate_1.1
end	

function	__nis_get_mechanisms
version		SUNWprivate_1.1
end	

function	__nis_get_mechanism_library
version		SUNWprivate_1.1
end	

function	__nis_get_mechanism_symbol
version		SUNWprivate_1.1
end	

function	__nis_mechalias2authtype
version		SUNWprivate_1.1
end	

function	__nis_mechname2alias
version		SUNWprivate_1.1
end	

function	__nis_translate_mechanism
version		SUNWprivate_1.1
end	

function	__nis_release_mechanisms
version		SUNWprivate_1.1
end	

function	__nis_keyalg2authtype
version		SUNWprivate_1.1
end	

function	__nis_keyalg2mechalias
version		SUNWprivate_1.1
end	

function	__gen_dhkeys_g
version		SUNWprivate_1.1
end	

function	__gen_common_dhkeys_g
version		SUNWprivate_1.1
end	

function	passwd2des_g
version		SUNWprivate_1.1
end	

function	des_setparity_g
version		SUNWprivate_1.1
end	

function	getpublickey_g
version		SUNWprivate_1.1
end	

function	__getpublickey_cached_g
version		SUNWprivate_1.1
end	

function	__getpublickey_flush_g
version		SUNWprivate_1.1
end	

function	getsecretkey_g
version		SUNWprivate_1.1
end	

function	key_secretkey_is_set_g
version		SUNWprivate_1.1
end	

function	key_secretkey_is_set_g_ruid
version		SUNWprivate_1.3
end	

function	key_removesecret_g
version		SUNWprivate_1.1
end	

function	key_removesecret_g_ruid
version		SUNWprivate_1.3
end	

function	key_gendes_g
version		SUNWprivate_1.1
end	

function	key_encryptsession_g
version		SUNWprivate_1.1
end	

function	key_decryptsession_g
version		SUNWprivate_1.1
end	

function	key_setsecret_g
version		SUNWprivate_1.1
end	

function	key_decryptsession_pk_g
version		SUNWprivate_1.1
end	

function	key_encryptsession_pk_g
version		SUNWprivate_1.1
end	

function	key_get_conv_g
version		SUNWprivate_1.1
end	

function	key_setnet_g
version		SUNWprivate_1.1
end	

function	key_setnet_g_ruid
version		SUNWprivate_1.3
end	

function	__netdir_getbyaddr_nosrv
version		SUNWprivate_1.1
end	

function	nss_ioctl
version		SUNWprivate_1.1
end

function	order_haddrlist_af
version		SUNWprivate_1.1
end

function	__des_crypt
version		SUNWprivate_1.1
end	

# PSARC 1997/332; User Attr databases START

function	_getusernam
version		SUNWprivate_1.2
end

function	_getuserattr
version		SUNWprivate_1.2
end

function	_fgetuserattr
version		SUNWprivate_1.2
end

function	_setuserattr
version		SUNWprivate_1.2
end

function	_enduserattr
version		SUNWprivate_1.2
end

function	_getauthnam
version		SUNWprivate_1.2
end

function	_getauthattr
version		SUNWprivate_1.2
end

function	_setauthattr
version		SUNWprivate_1.2
end

function	_endauthattr
version		SUNWprivate_1.2
end

function	_getprofnam
version		SUNWprivate_1.2
end

function	_getprofattr
version		SUNWprivate_1.2
end

function	_setprofattr
version		SUNWprivate_1.2
end

function	_endprofattr
version		SUNWprivate_1.2
end

function	_getexecattr
version		SUNWprivate_1.2
end

function	_getexecprof
version		SUNWprivate_1.2
end

function	_setexecattr
version		SUNWprivate_1.2
end

function	_endexecattr
version		SUNWprivate_1.2
end

function	_exec_wild_id
version		SUNWprivate_1.2
end

function	_doexeclist
version		SUNWprivate_1.2
end

function	_dup_execstr
version		SUNWprivate_1.2
end

function	_free_execstr
version		SUNWprivate_1.2
end

function	_exec_cleanup
version		SUNWprivate_1.2
end

function	_getauusernam
version		SUNWprivate_1.2
end

function	_getauuserent
version		SUNWprivate_1.2
end

function	_setauuser
version		SUNWprivate_1.2
end

function	_endauuser
version		SUNWprivate_1.2
end

function	_readbufline
version		SUNWprivate_1.2
end

function	_escape
version		SUNWprivate_1.2
end

function	_unescape
version		SUNWprivate_1.2
end

function	_strtok_escape
version		SUNWprivate_1.2
end

function	_strpbrk_escape
version		SUNWprivate_1.2
end

function	_strdup_null
version		SUNWprivate_1.2
end

# PSARC 1997/332; RFE 4182580; User Attr databases END

# PSARC/1998/452; Bug 4181371; NSS Lookup Control START

function	__yp_match_cflookup
declaration	int __yp_match_cflookup(char *, char *, char *, int, char **,\
					int *, int *);
version		SUNWprivate_1.2
end	

function	__yp_match_rsvdport_cflookup
declaration	int __yp_match_rsvdport_cflookup(char *, char *, char *,\
					int, char **, int *, int *);
version		SUNWprivate_1.2
end	

function	__yp_first_cflookup
declaration	int __yp_first_cflookup(char *, char *, char **, int *,\
					char **, int *, int);
version		SUNWprivate_1.2
end	

function	__yp_next_cflookup
declaration	int __yp_next_cflookup(char *, char *, char *, int, char **,\
					int *, char **, int  *, int);
version		SUNWprivate_1.2
end	

# PSARC/1998/452; Bug 4181371; NSS Lookup Control END

function	__yp_all_cflookup
#declaration	int __yp_all_cflookup(char *, char *, \
#					struct ypall_callback *, int);
version		SUNWprivate_1.4
end	
