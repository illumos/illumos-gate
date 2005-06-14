#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/kdb/spec/kdb.spec
#
# Interface definition for libkdb.so.1
#

function	destroy_file_suffix
include		"kdb_hdr.h"
declaration	krb5_error_code destroy_file_suffix(char *dbname, char *suffix)
version		SUNWprivate_1.1
end


function	krb5_db_close_database
declaration	krb5_error_code krb5_db_close_database(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_db_create
declaration	krb5_error_code krb5_db_create(krb5_context context, char *db_name)
version		SUNWprivate_1.1
end

function	krb5_db_destroy
declaration	krb5_error_code krb5_db_destroy(krb5_context context, char *db_name)
version		SUNWprivate_1.1
end

function	krb5_db_delete_principal
declaration	krb5_error_code krb5_db_delete_principal(krb5_context context, krb5_principal searchfor, int * nentries)
version		SUNWprivate_1.1
end

function	krb5_db_fetch_mkey
declaration	krb5_error_code krb5_db_fetch_mkey(krb5_context context, krb5_principal mname, krb5_encrypt_block * eblock, krb5_boolean fromkeyboard, krb5_boolean twice, char *keyfile, krb5_data * salt, krb5_keyblock * key)
version		SUNWprivate_1.1
end

function	krb5_db_free_principal
declaration	void krb5_db_free_principal(krb5_context context, krb5_db_entry * krbtgt_entry, int one)
version		SUNWprivate_1.1
end

function	krb5_db_get_age
declaration	krb5_error_code krb5_db_get_age(krb5_context context, char *db_name, time_t *age)
version		SUNWprivate_1.1
end

function	krb5_db_get_principal
declaration	krb5_error_code krb5_db_get_principal(krb5_context context, krb5_principal searchfor, krb5_db_entry *entries, int *nentries, krb5_boolean *more)
version		SUNWprivate_1.1
end

function	krb5_db_init
declaration	krb5_error_code krb5_db_init(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_db_iterate
declaration	krb5_error_code krb5_db_iterate( krb5_context context, krb5_error_code *func, krb5_pointer func_arg)
version		SUNWprivate_1.1
end

function	krb5_db_lock
declarationi	krb5_error_code krb5_db_lock(krb5_context context, krb5_int32 lockmode)
version		SUNWprivate_1.1
end

function	krb5_db_open_database
declaration	krb5_error_code krb5_db_open_database(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_db_put_principal
declaration	krb5_error_code krb5_db_put_principal(krb5_context context, krb5_db_entry *entries, register int *nentries)
version		SUNWprivate_1.1
end

function	krb5_db_rename
declaration	krb5_error_code krb5_db_rename(krb5_context context, char *from, char *to)
version		SUNWprivate_1.1
end

function	krb5_db_set_lockmode
declaration	krb5_boolean krb5_db_set_lockmode(krb5_context context, krb5_boolean mode)
version		SUNWprivate_1.1
end

function	krb5_db_set_name
declaration	krb5_error_code krb5_db_set_name(krb5_context context, char *name)
version		SUNWprivate_1.1
end

function	krb5_db_setup_mkey_name
declaration	krb5_error_code krb5_db_setup_mkey_name(krb5_context context, const char *keyname, const char *realm, char **fullname, krb5_principal *principal)
version		SUNWprivate_1.1
end

function	krb5_db_store_mkey
declaration	krb5_error_code krb5_db_store_mkey(krb5_context context, char *keyfile, krb5_principal mname, krb5_keyblock *key)
version		SUNWprivate_1.1
end

function	krb5_db_set_mkey
declaration	krb5_error_code krb5_db_set_mkey(krb5_context context, krb5_keyblock *key)
version		SUNWprivate_1.1
end

function	krb5_db_unlock
declaration	krb5_error_code krb5_db_unlock(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_db_verify_master_key
declaration	krb5_error_code krb5_db_verify_master_key(krb5_context context, krb5_principal mprinc, krb5_keyblock *mkey, krb5_encrypt_block *eblock)
version		SUNWprivate_1.1
end

function	krb5_db_fini
declaration	krb5_error_code krb5_db_fini(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_dbe_apw
declaration	krb5_error_code krb5_dbe_apw(krb5_context context, krb5_encrypt_block * master_eblock, krb5_key_salt_tuple * ks_tuple, int ks_tuple_count, char * passwd, krb5_db_entry * db_entry)
version		SUNWprivate_1.1
end

function	krb5_dbe_ark
declaration	krb5_error_code krb5_dbe_ark(krb5_context context, krb5_encrypt_block * master_eblock, krb5_key_salt_tuple * ks_tuple, int ks_tuple_count, krb5_db_entry * db_entry)
version		SUNWprivate_1.1
end

function	krb5_dbe_cpw
declaration	krb5_error_code krb5_dbe_cpw(krb5_context context, krb5_encrypt_block * master_eblock, krb5_key_salt_tuple * ks_tuple, int ks_tuple_count, char * passwd, int new_kvno, krb5_db_entry * db_entry)
version		SUNWprivate_1.1
end

function	krb5_dbe_create_key_data
declaration	krb5_error_code krb5_dbe_create_key_data(krb5_context context, krb5_db_entry * entry)
version		SUNWprivate_1.1
end

function	krb5_dbe_crk
declaration	krb5_error_code krb5_dbe_crk(krb5_context context, krb5_encrypt_block  * master_eblock, krb5_key_salt_tuple * ks_tuple, int ks_tuple_count, krb5_db_entry * db_entry)
version		SUNWprivate_1.1
end

function	krb5_dbe_find_enctype
declaration	krb5_error_code krb5_dbe_find_enctype(krb5_context kcontext, krb5_db_entry *dbentp, krb5_int32 ktype, krb5_int32 stype, krb5_int32 kvno, krb5_key_data **kdatap)
version		SUNWprivate_1.1
end

function	krb5_dbe_free_contents
declaration	void krb5_dbe_free_contents(krb5_context context, krb5_db_entry * entry)
version		SUNWprivate_1.1
end

function	krb5_dbe_lookup_last_pwd_change
declaration	krb5_error_code krb5_dbe_lookup_last_pwd_change(krb5_context context, krb5_db_entry * entry, krb5_timestamp * stamp)
version		SUNWprivate_1.1
end

function	krb5_dbe_lookup_mod_princ_data
declaration	krb5_error_code krb5_dbe_lookup_mod_princ_data(krb5_context context, krb5_db_entry * entry, krb5_timestamp * mod_time, krb5_principal * mod_princ)
version		SUNWprivate_1.1
end

function	krb5_dbe_lookup_tl_data
declaration	krb5_error_code krb5_dbe_lookup_tl_data(krb5_context context, krb5_db_entry * entry, krb5_tl_data * ret_tl_data)
version		SUNWprivate_1.1
end

function	krb5_dbe_search_enctype
declaration	krb5_error_code krb5_dbe_search_enctype(krb5_context kcontext, krb5_db_entry *dbentp, krb5_int32 *start, krb5_int32 ktype, krb5_int32 stype, krb5_int32 kvno, krb5_key_data **kdatap)
version		SUNWprivate_1.1
end

function	krb5_dbe_update_last_pwd_change
declaration	krb5_error_code krb5_dbe_update_last_pwd_change(krb5_context context, krb5_db_entry * entry, krb5_timestamp stamp)
version		SUNWprivate_1.1
end

function	krb5_dbe_update_mod_princ_data
declaration	krb5_error_code krb5_dbe_update_mod_princ_data(krb5_context context, krb5_db_entry * entry, krb5_timestamp mod_date, krb5_principal mod_princ)
version		SUNWprivate_1.1
end

function	krb5_dbe_update_tl_data
declaration	krb5_error_code krb5_dbe_update_tl_data(krb5_context context, krb5_db_entry * entry, krb5_tl_data * new_tl_data)
version		SUNWprivate_1.1
end

function	krb5_dbekd_decrypt_key_data
declaration	krb5_error_code krb5_dbekd_decrypt_key_data(krb5_context context, krb5_encrypt_block * eblock, const krb5_key_data * key_data, krb5_keyblock * keyblock, krb5_keysalt * keysalt)
version		SUNWprivate_1.1
end

function	krb5_dbekd_encrypt_key_data
declaration	krb5_error_code krb5_dbekd_encrypt_key_data(krb5_context context, krb5_encrypt_block * eblock, const krb5_keyblock * keyblock, const krb5_keysalt * keysalt, int keyver, krb5_key_data * key_data)
version		SUNWprivate_1.1
end

function	krb5_decode_princ_contents
declaration	krb5_error_code krb5_decode_princ_contents(krb5_context context, datum * content, krb5_db_entry * entry)
version		SUNWprivate_1.1
end

function	krb5_encode_princ_contents
declaration	krb5_error_code krb5_encode_princ_contents(krb5_context context, datum * content, krb5_db_entry * entry)
version		SUNWprivate_1.1
end

function	krb5_free_princ_contents
declaration	void krb5_free_princ_contents(krb5_context context, datum *contents)
version		SUNWprivate_1.1
end

data		krb5_kt_kdb_ops
declaration	krb5_kt_ops krb5_kt_kdb_ops
version		SUNWprivate_1.1
end

function	krb5_ktkdb_close
declaration	krb5_error_code krb5_ktkdb_close(krb5_context context, krb5_keytab kt)
version		SUNWprivate_1.1
end

function	krb5_ktkdb_get_entry
declaration	krb5_error_code krb5_ktkdb_get_entry(krb5_context context, krb5_keytab id, krb5_principal principal, krb5_kvno kvno, krb5_enctype enctype, krb5_keytab_entry * entry)
version		SUNWprivate_1.1
end

function	krb5_ktkdb_resolve
declaration	krb5_error_code krb5_ktkdb_resolve(krb5_context context, krb5_db_context * kdb, krb5_keytab * id)
version		SUNWprivate_1.1
end

data		krb5_mkey_pwd_prompt1
declaration	char *krb5_mkey_pwd_prompt1
version		SUNWprivate_1.1
end

data		krb5_mkey_pwd_prompt2
declaration	char *krb5_mkey_pwd_prompt2
version		SUNWprivate_1.1
end

function	krb5_ser_db_context_init
declaration	krb5_error_code krb5_ser_db_context_init(krb5_context kcontext)
version		SUNWprivate_1.1
end

function	ulog_free_entries
declaration	void ulog_free_entries(kdb_incr_update_t *updates, int no_of_updates)
version		SUNWprivate_1.1
end

function	ulog_get_entries
declaration	krb5_error_code ulog_get_entries(krb5_context context, kdb_last_t last, kdb_incr_result_t *ulog_handle);
version		SUNWprivate_1.1
end

function	ulog_map
declaration	krb5_error_code ulog_map(krb5_context context, kadm5_config_params *params, int caller)
version		SUNWprivate_1.1
end

function	ulog_replay
include		"iprop.h"
declaration	krb5_error_code ulog_replay(krb5_context context, kdb_incr_result_t *incr_ret)
version		SUNWprivate_1.1
end

function	ulog_set_role
include		"iprop.h"
declaration	krb5_error_code ulog_set_role(krb5_context context, krb5_context *ctx)
version		SUNWprivate_1.1
end
