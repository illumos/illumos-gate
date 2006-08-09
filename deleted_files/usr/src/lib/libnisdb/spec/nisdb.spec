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
# lib/libnisdb/spec/nisdb.spec

function	free_entry
version		SUNWprivate_2.1
end		

function	db_add_entry
version		SUNWprivate_2.1
end		

function	__db_add_entry_nolog
version		SUNWprivate_2.1
end		

function	__db_add_entry_nosync
version		SUNWprivate_2.1
end		

function	db_checkpoint
version		SUNWprivate_2.1
end		

function	db_create_table
version		SUNWprivate_2.1
end		

function	db_destroy_table
version		SUNWprivate_2.1
end		

function	db_first_entry
version		SUNWprivate_2.1
end		

function	db_initialize
version		SUNWprivate_2.1
end		

function	db_list_entries
version		SUNWprivate_2.1
end		

function	db_massage_dict
version		SUNWprivate_2.1
end		

function	db_next_entry
version		SUNWprivate_2.1
end		

function	db_remove_entry
version		SUNWprivate_2.1
end		

function	__db_remove_entry_nosync
version		SUNWprivate_2.1
end		

function	db_reset_next_entry
version		SUNWprivate_2.1
end		

function	db_standby
version		SUNWprivate_2.1
end		

function	db_table_exists
version		SUNWprivate_2.1
end		

function	db_unload_table
version		SUNWprivate_2.1
end		

function	db_perror
version		SUNWprivate_2.1
end		

function	db_abort_merge_dict
version		SUNWprivate_2.1
end		

function	db_end_merge_dict
version		SUNWprivate_2.1
end		

function	db_begin_merge_dict
version		SUNWprivate_2.1
end		

function	db_copy_file
version		SUNWprivate_2.1
end		

function	db_in_dict_file
version		SUNWprivate_2.1
end		

function	db_extract_dict_entries
version		SUNWprivate_2.1
end		

function	db_sync_log
version		SUNWprivate_2.1
end

function	__db_defer
version		SUNWprivate_2.1
end

function	__db_commit
version		SUNWprivate_2.1
end

function	__db_rollback
version		SUNWprivate_2.1
end

function	__db_configure
version		SUNWprivate_2.1
end

function	__db_list_entries
version		SUNWprivate_2.1
end

function	__nis_lock_hash_table
version		SUNWprivate_2.1
end

function	__nisdb_wulock
version		SUNWprivate_2.1
end

function	__nis_pop_item_mt
version		SUNWprivate_2.1
end

function	__nis_item_access
version		SUNWprivate_2.1
end

function	__nis_scan_table_mt
version		SUNWprivate_2.1
end

function	__nis_release_item
version		SUNWprivate_2.1
end

function	__nisdb_rulock
version		SUNWprivate_2.1
end

function	__nis_init_hash_table
version		SUNWprivate_2.1
end

function	__nisdb_rlock
version		SUNWprivate_2.1
end

function	__nis_ulock_hash_table
version		SUNWprivate_2.1
end

function	__nis_insert_name_mt
version		SUNWprivate_2.1
end

function	__nisdb_wlock
version		SUNWprivate_2.1
end

function	__nisdb_wlock_trylock
version		SUNWprivate_2.1
end

function	__nis_remove_item_mt
version		SUNWprivate_2.1
end

function	__nis_find_item_mt
version		SUNWprivate_2.1
end

function	__nis_insert_item_mt
version		SUNWprivate_2.1
end

function	freeRuleValue
version		SUNWprivate_2.1
end

function	freeQuery
version		SUNWprivate_2.1
end

function	printObjAttr
version		SUNWprivate_2.1
end

function	printbuf
version		SUNWprivate_2.1
end

function	createQuery
version		SUNWprivate_2.1
end

function	printQuery
version		SUNWprivate_2.1
end

function	mapFromLDAP
version		SUNWprivate_2.1
end

function	parseConfig
version		SUNWprivate_2.1
end

function	p2buf
version		SUNWprivate_2.1
end

function	printTableMapping
version		SUNWprivate_2.1
end

function	mapToLDAP
version		SUNWprivate_2.1
end

function	ldapMappingList
version		SUNWprivate_2.1
end

function	fullObjName
version		SUNWprivate_2.1
end

function	objFromLDAP
version		SUNWprivate_2.1
end

function	objToLDAP
version		SUNWprivate_2.1
end

function	deleteLDAPobj
version		SUNWprivate_2.1
end

function	freeObjAttr
version		SUNWprivate_2.1
end

function	numMisaligned
version		SUNWprivate_2.1
end

function	verbose
version		SUNWprivate_2.1
end

function	justTesting
version		SUNWprivate_2.1
end

function	cons
version		SUNWprivate_2.1
end

function	internal_table_name
version		SUNWprivate_2.1
end

function	__make_legal
version		SUNWprivate_2.1
end

function	relative_name
version		SUNWprivate_2.1
end

function	logmsg
version		SUNWprivate_2.1
end

function	ldapConfig
version		SUNWprivate_2.1
end

function	__nis_retry_sleep
version		SUNWprivate_2.1
end

function	setColumnsDuringConfig
version		SUNWprivate_2.1
end

function	socket
version		SUNWprivate_2.1
end

function	xdr_nis_name_abbrev
version		SUNWprivate_2.1
end

function	xdr_nis_fetus_object
version		SUNWprivate_2.1
end

function	__nisdb_get_tsd
version		SUNWprivate_2.1
end

function	ldapDBTableMapping
version		SUNWprivate_2.1
end

function	sfree
version		SUNWprivate_2.1
end

function	nis_server_control
version		SUNWprivate_2.1
end

function	nis_isserving
version		SUNWprivate_2.1
end

function	bp2buf
version		SUNWprivate_2.1
end

function	update_root_object
version		SUNWprivate_2.1
end

function	get_root_object
version		SUNWprivate_2.1
end

function	remove_root_object
version		SUNWprivate_2.1
end

function	beginTransaction
version		SUNWprivate_2.1
end

function	abort_transaction
version		SUNWprivate_2.1
end

function	endTransaction
version		SUNWprivate_2.1
end

function	addUpdate
version		SUNWprivate_2.1
end

function	__db_disallowLDAP
version		SUNWprivate_2.1
end

function	__db_allowLDAP
version		SUNWprivate_2.1
end

function	sc2buf
version		SUNWprivate_2.1
end

function	freeEntryObjArray
version		SUNWprivate_2.1
end

function	internalTableName
version		SUNWprivate_2.1
end

function	dbCreateFromLDAP
version		SUNWprivate_2.1
end

function	tbl_prototype
version		SUNWprivate_2.1
end

function	getObjMapping
version		SUNWprivate_2.1
end

function	loadAllLDAP
version		SUNWprivate_2.1
end

function	assertExclusive
version		SUNWprivate_2.1
end

function	lockTransLog
version		SUNWprivate_2.1
end

function	unlockTransLog
version		SUNWprivate_2.1
end

function	__nis_lock_db_table
version		SUNWprivate_2.1
end

function	__nis_ulock_db_table
version		SUNWprivate_2.1
end

function	__nisdb_lock_report
version		SUNWprivate_2.1
end

# YPTOL stuff

function	init_lock_system
version		SUNWprivate_2.1
end

function	shim_dbm_close
version		SUNWprivate_2.1
end

function	shim_dbm_delete
version		SUNWprivate_2.1
end

function	shim_dbm_fetch
version		SUNWprivate_2.1
end

function	shim_dbm_fetch_noupdate
version		SUNWprivate_2.1
end

function	shim_dbm_firstkey
version		SUNWprivate_2.1
end

function	shim_dbm_nextkey
version		SUNWprivate_2.1
end

function	shim_dbm_do_nextkey
version		SUNWprivate_2.1
end

function	shim_dbm_open
version		SUNWprivate_2.1
end

function	shim_dbm_store
version		SUNWprivate_2.1
end

function	ypmkfilename
version		SUNWprivate_2.1
end

function	shim_exit
version		SUNWprivate_2.1
end

function	dump_dit_to_maps
version		SUNWprivate_2.1
end

function	get_map_name
version		SUNWprivate_2.1
end

function	dump_maps_to_dit
version		SUNWprivate_2.1
end

function	yptol_mode
version		SUNWprivate_2.1
end

function	yptol_newlock
version		SUNWprivate_2.1
end

# If these weak functions are not made external then then they get resolved at
# library link time. Result when the library calls them it always sees it's 
# own version rather that the version provided by an external program.

function	init_lock_map
version		SUNWprivate_2.1
end

function	lock_core
version		SUNWprivate_2.1
end

function	unlock_core
version		SUNWprivate_2.1
end

function	lock_map
version		SUNWprivate_2.1
end

function	unlock_map
version		SUNWprivate_2.1
end

function	init_lock_map
version		SUNWprivate_2.1
end

function	hash
version		SUNWprivate_2.1
end

function	rename_map
version		SUNWprivate_2.1
end

function	delete_map
version		SUNWprivate_2.1
end

function	single
version		SUNWprivate_2.1
end

function	nogecos
version		SUNWprivate_2.1
end

function	noshell
version		SUNWprivate_2.1
end

function	nopw
version		SUNWprivate_2.1
end

function	mflag
version		SUNWprivate_2.1
end

function	validloginshell
version		SUNWprivate_2.1
end

function	validstr
version		SUNWprivate_2.1
end

function	init_yptol_flag
version		SUNWprivate_2.1
end

function	get_list_max
version		SUNWprivate_2.1
end

function	ypcheck_domain_yptol
version		SUNWprivate_2.1
end

function	ypcheck_map_existence_yptol
version		SUNWprivate_2.1
end

# N2L yppasswdd stuff
function	shim_changepasswd
version		SUNWprivate_2.1
end
