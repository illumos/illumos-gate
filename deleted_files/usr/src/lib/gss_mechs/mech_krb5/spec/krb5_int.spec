#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_int.spec
#

function	com_err
version		SUNWprivate_1.1
end

function	com_err_va
version		SUNWprivate_1.1
end

function	daemon
declaration	int daemon (int nochdir, int noclose)
version		SUNWprivate_1.1
end

function	decode_krb5_alt_method
declaration	krb5_error_code decode_krb5_alt_method \
			(const krb5_data *code, krb5_alt_method **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_ap_rep
declaration	krb5_error_code decode_krb5_ap_rep \
			(const krb5_data *code, krb5_ap_rep **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_ap_rep_enc_part
declaration	krb5_error_code decode_krb5_ap_rep_enc_part \
			(const krb5_data *code, krb5_ap_rep_enc_part **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_ap_req
declaration	krb5_error_code decode_krb5_ap_req \
			(const krb5_data *code, krb5_ap_req **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_as_rep
declaration	krb5_error_code decode_krb5_as_rep \
			(const krb5_data *code, krb5_kdc_rep **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_as_req
declaration	krb5_error_code decode_krb5_as_req \
			(const krb5_data *code, krb5_kdc_req **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_authdata
declaration	krb5_error_code decode_krb5_authdata \
			(const krb5_data *code, krb5_authdata ***rep)
version		SUNWprivate_1.1
end

function	decode_krb5_authenticator
declaration	krb5_error_code decode_krb5_authenticator \
			(const krb5_data *code, krb5_authenticator **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_cred
declaration	krb5_error_code decode_krb5_cred \
			(const krb5_data *code, krb5_cred **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_enc_cred_part
declaration	krb5_error_code decode_krb5_enc_cred_part \
			(const krb5_data *code, krb5_cred_enc_part **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_enc_data
declaration	krb5_error_code decode_krb5_enc_data \
			(const krb5_data *code, krb5_enc_data **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_enc_kdc_rep_part
declaration	krb5_error_code decode_krb5_enc_kdc_rep_part \
			(const krb5_data *code, krb5_enc_kdc_rep_part **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_enc_priv_part
declaration	krb5_error_code decode_krb5_enc_priv_part \
			(const krb5_data *code, krb5_priv_enc_part **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_enc_sam_key
declaration	krb5_error_code decode_krb5_enc_sam_key \
			(const krb5_data *code, krb5_sam_key **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_enc_sam_response_enc
declaration	krb5_error_code decode_krb5_enc_sam_response_enc \
			(const krb5_data *code, krb5_enc_sam_response_enc **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_enc_tkt_part
declaration	krb5_error_code decode_krb5_enc_tkt_part \
			(const krb5_data *code, krb5_enc_tkt_part **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_encryption_key
declaration	krb5_error_code decode_krb5_encryption_key \
			(const krb5_data *code, krb5_keyblock **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_error
declaration	krb5_error_code decode_krb5_error \
			(const krb5_data *code, krb5_error **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_etype_info
declaration	krb5_error_code decode_krb5_etype_info \
			(const krb5_data *code, krb5_etype_info_entry ***rep)
version		SUNWprivate_1.1
end

function	decode_krb5_kdc_req_body
declaration	krb5_error_code decode_krb5_kdc_req_body \
			(const krb5_data *code, krb5_kdc_req **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_pa_enc_ts
declaration	krb5_error_code decode_krb5_pa_enc_ts \
			(const krb5_data *code, krb5_pa_enc_ts **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_padata_sequence
declaration	krb5_error_code decode_krb5_padata_sequence \
			(const krb5_data *code, krb5_pa_data ***rep)
version		SUNWprivate_1.1
end

function	decode_krb5_predicted_sam_response
declaration	krb5_error_code decode_krb5_predicted_sam_response \
			(const krb5_data *code, krb5_predicted_sam_response **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_priv
declaration	krb5_error_code decode_krb5_priv \
			(const krb5_data *code, krb5_priv **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_pwd_data
declaration	krb5_error_code decode_krb5_pwd_data \
			(const krb5_data *code, krb5_pwd_data **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_pwd_sequence
declaration	krb5_error_code decode_krb5_pwd_sequence \
			(const krb5_data *code, passwd_phrase_element **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_safe
declaration	krb5_error_code decode_krb5_safe \
			(const krb5_data *code, krb5_safe **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_sam_challenge
declaration	krb5_error_code decode_krb5_sam_challenge \
			(const krb5_data *code, krb5_sam_challenge **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_sam_response
declaration	krb5_error_code decode_krb5_sam_response \
			(const krb5_data *code, krb5_sam_response **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_tgs_rep
declaration	krb5_error_code decode_krb5_tgs_rep \
			(const krb5_data *code, krb5_kdc_rep **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_tgs_req
declaration	krb5_error_code decode_krb5_tgs_req \
			(const krb5_data *code, krb5_kdc_req **rep)
version		SUNWprivate_1.1
end

function	decode_krb5_ticket
declaration	krb5_error_code decode_krb5_ticket \
			(const krb5_data *code, krb5_ticket **rep)
version		SUNWprivate_1.1
end

function	display_unknown
include		<gssapi_krb5.h>
declaration	int display_unknown (const char *kind, \
			OM_uint32 value, gss_buffer_t buffer)
version		SUNWprivate_1.1
end

function	encode_krb5_alt_method
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_alt_method \
			(const krb5_alt_method *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_ap_rep
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_ap_rep \
			(const krb5_ap_rep *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_ap_rep_enc_part
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_ap_rep_enc_part \
			(const krb5_ap_rep_enc_part *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_ap_req
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_ap_req \
			(const krb5_ap_req *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_as_rep
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_as_rep \
			(const krb5_kdc_rep *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_as_req
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_as_req \
			(const krb5_kdc_req *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_authdata
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_authdata \
			(const krb5_authdata **rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_authenticator
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_authenticator \
			(const krb5_authenticator *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_cred
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_cred \
			(const krb5_cred *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_enc_cred_part
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_enc_cred_part \
			(const krb5_cred_enc_part *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_enc_data
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_enc_data \
			(const krb5_enc_data *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_enc_kdc_rep_part
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_enc_kdc_rep_part \
			(const krb5_enc_kdc_rep_part *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_enc_priv_part
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_enc_priv_part \
			(const krb5_priv_enc_part *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_enc_sam_response_enc
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_enc_sam_response_enc \
			(const krb5_enc_sam_response_enc *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_enc_tkt_part
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_enc_tkt_part \
			(const krb5_enc_tkt_part *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_encryption_key
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_encryption_key \
			(const krb5_keyblock *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_error
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_error \
			(const krb5_error *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_etype_info
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_etype_info \
			(const krb5_etype_info_entry **rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_etype_info2
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_etype_info2 \
			(const krb5_etype_info_entry **rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_kdc_req_body
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_kdc_req_body \
			(const krb5_kdc_req *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_pa_enc_ts
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_pa_enc_ts \
			(const krb5_pa_enc_ts *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_padata_sequence
declaration	krb5_error_code encode_krb5_padata_sequence \
			(const krb5_pa_data **rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_predicted_sam_response
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_predicted_sam_response \
			(const krb5_predicted_sam_response *rep, \
			krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_priv
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_priv \
			(const krb5_priv *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_pwd_data
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_pwd_data \
			(const krb5_pwd_data *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_pwd_sequence
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_pwd_sequence \
			(const passwd_phrase_element *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_safe
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_safe \
			(const krb5_safe *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_sam_challenge
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_sam_challenge \
			(const krb5_sam_challenge *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_sam_key
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_sam_key \
			(const krb5_sam_key *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_sam_response
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_sam_response \
			(const krb5_sam_response *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_tgs_rep
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_tgs_rep \
			(const krb5_kdc_rep *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_tgs_req
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_tgs_req \
			(const krb5_kdc_req *rep, krb5_data **code)
version		SUNWprivate_1.1
end

function	encode_krb5_ticket
include		<k5-int.h>
declaration	krb5_error_code encode_krb5_ticket \
			(const krb5_ticket *rep, krb5_data **code)
version		SUNWprivate_1.1
end
