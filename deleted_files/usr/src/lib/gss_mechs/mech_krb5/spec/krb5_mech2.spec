#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_mech2.spec
#

function	krb5_find_serializer
include		<k5-int.h>
declaration	krb5_ser_handle krb5_find_serializer \
			(krb5_context kcontext, krb5_magic odtype)
version		SUNWprivate_1.1
end

function	krb5_free_address
include		<krb5.h>
declaration	void krb5_free_address \
			(krb5_context context, krb5_address *val)
version		SUNWprivate_1.1
end

function	krb5_free_addresses
include		<krb5.h>
declaration	void krb5_free_addresses ( \
			krb5_context context, \
			krb5_address **val)
version		SUNWprivate_1.1
end

function	krb5_free_ap_rep
include		<krb5.h>
declaration	void krb5_free_ap_rep \
			(krb5_context context, register krb5_ap_rep *val)
version		SUNWprivate_1.1
end

function	krb5_free_ap_rep_enc_part
include		<krb5.h>
declaration	void krb5_free_ap_rep_enc_part \
			(krb5_context context, krb5_ap_rep_enc_part *val)
version		SUNWprivate_1.1
end

function	krb5_free_ap_req
include		<krb5.h>
declaration	void krb5_free_ap_req \
			(krb5_context context, register krb5_ap_req *val)
version		SUNWprivate_1.1
end

function	krb5_free_authdata
include		<krb5.h>
declaration	void krb5_free_authdata \
			(krb5_context context, krb5_authdata **val)
version		SUNWprivate_1.1
end

function	krb5_free_authenticator
include		<krb5.h>
declaration	void krb5_free_authenticator \
			(krb5_context context, krb5_authenticator *val)
version		SUNWprivate_1.1
end

function	krb5_free_authenticator_contents
include		<krb5.h>
declaration	void krb5_free_authenticator_contents \
			(krb5_context context, krb5_authenticator *val)
version		SUNWprivate_1.1
end

function	krb5_free_checksum
include		<krb5.h>
declaration	void krb5_free_checksum \
			(krb5_context context, register krb5_checksum *val)
version		SUNWprivate_1.1
end

function	krb5_free_checksum_contents
include		<krb5.h>
declaration	void krb5_free_checksum_contents \
			(krb5_context context, register krb5_checksum *val)
version		SUNWprivate_1.1
end

function	krb5_free_cksumtypes
include		<k5-int.h>, <etypes.h>, <cksumtypes.h>
declaration	void krb5_free_cksumtypes( \
			krb5_context context, \
			krb5_cksumtype * val)
version		SUNWprivate_1.1
end

function	krb5_free_context
include		<krb5.h>
declaration	void krb5_free_context (krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_free_cred
include		<krb5.h>
declaration	void krb5_free_cred \
			(krb5_context context, register krb5_cred *val)
version		SUNWprivate_1.1
end

function	krb5_free_cred_contents
include		<krb5.h>
declaration	void krb5_free_cred_contents \
			(krb5_context context, krb5_creds *val)
version		SUNWprivate_1.1
end

function	krb5_free_cred_enc_part
include		<krb5.h>
declaration	void krb5_free_cred_enc_part (krb5_context, \
			krb5_cred_enc_part *)
version		SUNWprivate_1.1
end

function	krb5_free_creds
include		<krb5.h>
declaration	void krb5_free_creds \
			(krb5_context context, krb5_creds *val)
version		SUNWprivate_1.1
end

function	krb5_free_data
include		<krb5.h>
declaration	void krb5_free_data \
			(krb5_context context, krb5_data *val)
version		SUNWprivate_1.1
end

function	krb5_free_data_contents
include		<krb5.h>
declaration	void krb5_free_data_contents \
			(krb5_context context, krb5_data *val)
version		SUNWprivate_1.1
end

function	krb5_free_enc_kdc_rep_part
include		<krb5.h>
declaration	void krb5_free_enc_kdc_rep_part \
			(krb5_context context, \
			register krb5_enc_kdc_rep_part *val)
version		SUNWprivate_1.1
end

function	krb5_free_enc_sam_response_enc
include		<krb5.h>
declaration	void krb5_free_enc_sam_response_enc \
			(krb5_context context, krb5_enc_sam_response_enc *esre)
version		SUNWprivate_1.1
end

function	krb5_free_enc_sam_response_enc_contents
include		<krb5.h>
declaration	void krb5_free_enc_sam_response_enc_contents \
			(krb5_context context, krb5_enc_sam_response_enc *esre)
version		SUNWprivate_1.1
end

function	krb5_free_enc_tkt_part
include		<krb5.h>
declaration	void krb5_free_enc_tkt_part \
			(krb5_context context, krb5_enc_tkt_part *val)
version		SUNWprivate_1.1
end

function	krb5_free_error
include		<krb5.h>
declaration	void krb5_free_error \
			(krb5_context context, krb5_error *val)
version		SUNWprivate_1.1
end

function	krb5_free_etype_info
include		<k5-int.h>
declaration	void krb5_free_etype_info \
			(krb5_context context, krb5_etype_info info)
version		SUNWprivate_1.1
end

function	krb5_free_host_realm
include		<krb5.h>
declaration	krb5_error_code krb5_free_host_realm \
			(krb5_context context, char * const * realmlist)
version		SUNWprivate_1.1
end

function	krb5_free_kdc_rep
include		<krb5.h>
declaration	void krb5_free_kdc_rep \
			(krb5_context context, krb5_kdc_rep *val)
version		SUNWprivate_1.1
end

function	krb5_free_kdc_req
include		<krb5.h>
declaration	void krb5_free_kdc_req (krb5_context context, \
			krb5_kdc_req *val)
version		SUNWprivate_1.1
end

function	krb5_free_keyblock
include		<krb5.h>
declaration	void krb5_free_keyblock \
			(krb5_context context, \
			register krb5_keyblock *val)
version		SUNWprivate_1.1
end

function	krb5_free_keyblock_contents
include		<krb5.h>
declaration	void krb5_free_keyblock_contents \
			(krb5_context context, register krb5_keyblock *val)
version		SUNWprivate_1.1
end

function	krb5_free_krbhst
include		<krb5.h>
declaration	krb5_error_code krb5_free_krbhst \
			(krb5_context context, char * const *hotlist)
version		SUNWprivate_1.1
end

function	krb5_free_last_req
include		<krb5.h>
declaration	void krb5_free_last_req \
			(krb5_context context, krb5_last_req_entry **val)
version		SUNWprivate_1.1
end

function	krb5_free_pa_data
include		<krb5.h>
declaration	void krb5_free_pa_data \
			(krb5_context context, krb5_pa_data **val)
version		SUNWprivate_1.1
end

function	krb5_free_pa_enc_ts
include		<krb5.h>
declaration	void krb5_free_pa_enc_ts \
			(krb5_context context, krb5_pa_enc_ts *pa_enc_ts)
version		SUNWprivate_1.1
end

function	krb5_free_predicted_sam_response
include		<krb5.h>
declaration	void krb5_free_predicted_sam_response \
			(krb5_context context, krb5_predicted_sam_response *psr)
version		SUNWprivate_1.1
end

function	krb5_free_predicted_sam_response_contents
include		<krb5.h>
declaration	void krb5_free_predicted_sam_response_contents \
			(krb5_context context, krb5_predicted_sam_response *psr)
version		SUNWprivate_1.1
end

function	krb5_free_principal
include		<krb5.h>
declaration	void krb5_free_principal \
			(krb5_context context, krb5_principal val)
version		SUNWprivate_1.1
end

function	krb5_free_priv
declaration	void krb5_free_priv (krb5_context context, krb5_priv *val)
version		SUNWprivate_1.1
end

function	krb5_free_priv_enc_part
include		<krb5.h>
declaration	void krb5_free_priv_enc_part \
			(krb5_context context, krb5_priv_enc_part *val)
version		SUNWprivate_1.1
end

function	krb5_free_pwd_data
include		<krb5.h>
declaration	void krb5_free_pwd_data \
			(krb5_context context, krb5_pwd_data *val)
version		SUNWprivate_1.1
end

function	krb5_free_pwd_sequences
include		<krb5.h>
declaration	void krb5_free_pwd_sequences \
			(krb5_context context, passwd_phrase_element **val)
version		SUNWprivate_1.1
end

function	krb5_free_realm_tree
include		<krb5.h>
declaration	void krb5_free_realm_tree \
			(krb5_context context, krb5_principal *realms)
version		SUNWprivate_1.1
end

function	krb5_free_safe
include		<krb5.h>
declaration	void krb5_free_safe \
			(krb5_context context, register krb5_safe *val)
version		SUNWprivate_1.1
end

function	krb5_free_sam_challenge
include		<krb5.h>
declaration	void krb5_free_sam_challenge \
			(krb5_context context, krb5_sam_challenge *sc)
version		SUNWprivate_1.1
end

function	krb5_free_sam_challenge_contents
include		<krb5.h>
declaration	void krb5_free_sam_challenge_contents\
			(krb5_context context, krb5_sam_challenge *sc)
version		SUNWprivate_1.1
end

function	krb5_free_sam_response
include		<krb5.h>
declaration	void krb5_free_sam_response\
			(krb5_context context, krb5_sam_response *sr)
version		SUNWprivate_1.1
end

function	krb5_free_sam_response_contents
include		<krb5.h>
declaration	void krb5_free_sam_response_contents\
			(krb5_context context, krb5_sam_response *sr)
version		SUNWprivate_1.1
end

function	krb5_free_tgt_creds
include		<krb5.h>
declaration	void krb5_free_tgt_creds \
			(krb5_context context, krb5_creds **tgts)
version		SUNWprivate_1.1
end

function	krb5_free_ticket
include		<krb5.h>
declaration	void krb5_free_ticket (krb5_context context, \
			krb5_ticket *val)
version		SUNWprivate_1.1
end

function	krb5_free_tickets
include		<krb5.h>
declaration	void krb5_free_tickets \
			(krb5_context context, krb5_ticket **val)
version		SUNWprivate_1.1
end

function	krb5_free_tkt_authent
include		<krb5.h>
declaration	void krb5_free_tkt_authent \
			(krb5_context context, krb5_tkt_authent *val)
version		SUNWprivate_1.1
end

# spec2trace RFE
function	krb5_free_uio
version		SUNWprivate_1.1
end

function	krb5_free_unparsed_name
include		<krb5.h>
declaration	void krb5_free_unparsed_name \
			(krb5_context context, char *val)
version		SUNWprivate_1.1
end

function	krb5_fwd_tgt_creds
include		<krb5.h>
declaration	krb5_error_code krb5_fwd_tgt_creds \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			char *rhost, krb5_principal client, \
			krb5_principal server, krb5_ccache cc, \
			int forwardable, krb5_data *outbuf)
version		SUNWprivate_1.1
end

function	krb5_gen_portaddr
include		<krb5.h>
declaration	krb5_error_code krb5_gen_portaddr \
			(krb5_context context, \
			const krb5_address *addr, \
			krb5_const_pointer ptr, \
			krb5_address **outaddr)
version		SUNWprivate_1.1
end

function	krb5_gen_replay_name
include		<k5-int.h>
declaration	krb5_error_code krb5_gen_replay_name \
			(krb5_context context, \
			const krb5_address *address, \
			const char *uniq, char **string)
version		SUNWprivate_1.1
end

function	krb5_generate_seq_number
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_generate_seq_number ( \
			krb5_context context, \
			const krb5_keyblock *key, \
			krb5_int32 *seqno)
version		SUNWprivate_1.1
end

function	krb5_generate_subkey
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_generate_subkey ( \
			krb5_context context, \
			const krb5_keyblock *key, \
			krb5_keyblock **subkey)
version		SUNWprivate_1.1
end

function	krb5_get_cred_from_kdc
include		<krb5.h>
declaration	krb5_error_code krb5_get_cred_from_kdc \
			(krb5_context context, krb5_ccache cache, \
			krb5_creds *in_cred, krb5_creds **out_cred, \
			krb5_creds ***tgts)
version		SUNWprivate_1.1
end

function	krb5_get_cred_from_kdc_renew
include		<krb5.h>
declaration	krb5_error_code krb5_get_cred_from_kdc_renew \
			(krb5_context context, krb5_ccache cache, \
			krb5_creds *in_cred, krb5_creds **out_creds, \
			krb5_creds ***tgts)
version		SUNWprivate_1.1
end

function	krb5_get_cred_from_kdc_validate
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_cred_from_kdc_validate ( \
			krb5_context context, \
			krb5_ccache ccache, \
			krb5_creds  *in_cred, \
			krb5_creds  **out_cred, \
			krb5_creds  ***tgts)
version		SUNWprivate_1.1
end

function	krb5_get_cred_via_tkt
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_cred_via_tkt ( \
			krb5_context context, \
			krb5_creds * tkt, \
			const krb5_flags kdcoptions, \
			krb5_address *const * address, \
			krb5_creds * in_cred, \
			krb5_creds ** out_cred)
version		SUNWprivate_1.1
end

function	krb5_get_credentials
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_credentials ( \
			krb5_context context, \
			const krb5_flags options, \
			krb5_ccache ccache, \
			krb5_creds *in_creds, \
			krb5_creds **out_creds)
version		SUNWprivate_1.1
end

function	krb5_get_credentials_renew
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_credentials_renew ( \
			krb5_context context, \
			const krb5_flags options, \
			krb5_ccache ccache, \
			krb5_creds *in_creds, \
			krb5_creds **out_creds)
version		SUNWprivate_1.1
end

function	krb5_get_credentials_validate
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_credentials_validate ( \
			krb5_context context, \
			const krb5_flags options, \
			krb5_ccache ccache, \
			krb5_creds *in_creds, \
			krb5_creds **out_creds)
version		SUNWprivate_1.1
end

function	krb5_get_default_in_tkt_ktypes
include		<krb5.h>
declaration	krb5_error_code krb5_get_default_in_tkt_ktypes \
			(krb5_context context, krb5_enctype **ktypes)
version		SUNWprivate_1.1
end

function	krb5_get_default_realm
include		<krb5.h>
declaration	krb5_error_code krb5_get_default_realm \
			(krb5_context context, char **lrealm)
version		SUNWprivate_1.1
end

function	krb5_get_host_realm
include		<krb5.h>
declaration	krb5_error_code krb5_get_host_realm \
			(krb5_context context, const char *host, \
			char ***realmsp)
version		SUNWprivate_1.1
end

function	krb5_get_krbhst
include		<k5-int.h>
declaration	krb5_error_code krb5_get_krbhst ( \
			krb5_context context, \
			const krb5_data *realm, char ***host)
version		SUNWprivate_1.1
end

function	krb5_get_realm_domain
include		<krb5.h>
declaration	krb5_error_code krb5_get_realm_domain \
			(krb5_context context, const char *realm, \
			char **domain)
version		SUNWprivate_1.1
end

function	krb5_get_tgs_ktypes
include		<krb5.h>
declaration	krb5_error_code krb5_get_tgs_ktypes \
			(krb5_context context, \
			krb5_const_principal princ, krb5_enctype **ktypes)
version		SUNWprivate_1.1
end

function	krb5_get_time_offsets
include		<krb5.h>
declaration	krb5_error_code krb5_get_time_offsets \
			(krb5_context context, krb5_int32 *seconds, \
			krb5_int32 *microseconds)
version		SUNWprivate_1.1
end

function	krb5_getenv
declaration	char * krb5_getenv (const char *name)
version		SUNWprivate_1.1
end

function	krb5_hmac
declaration	krb5_error_code krb5_hmac( \
			krb5_context context, \
			const struct krb5_hash_provider *hash, \
			const krb5_keyblock *key, \
			const unsigned int icount, \
			const krb5_data *input, \
			krb5_data *output)
version		SUNWprivate_1.1
end

function	krb5_init_context
include		<krb5.h>
declaration	krb5_error_code krb5_init_context ( \
			krb5_context *context)
version		SUNWprivate_1.1
end

function	krb5_init_ef_handle
include		<krb5.h>
declaration	krb5_error_code krb5_init_ef_handle(krb5_context)
version		SUNWprivate_1.1
end

function	krb5_free_ef_handle
include		<krb5.h>
declaration	krb5_error_code krb5_free_ef_handle(krb5_context)
version		SUNWprivate_1.1
end

function	krb5_internalize_opaque
include		<k5-int.h>
declaration	krb5_error_code krb5_internalize_opaque \
			(krb5_context kcontext, krb5_magic odtype, \
			krb5_pointer *argp, krb5_octet **bufpp, \
			size_t *sizep)
version		SUNWprivate_1.1
end

function	krb5_kdc_rep_decrypt_proc
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_kdc_rep_decrypt_proc ( \
			krb5_context context, \
			const krb5_keyblock * key, \
			krb5_const_pointer decryptarg, \
			krb5_kdc_rep * dec_rep)
version		SUNWprivate_1.1
end
