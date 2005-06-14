#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_asn1.spec
#

function	asn12krb5_buf
include		<asn1buf.h>
declaration	asn1_error_code asn12krb5_buf \
			(const asn1buf *buf, krb5_data **code)
version		SUNWprivate_1.1
end

function	asn1_decode_addrtype
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_addrtype \
			(asn1buf *buf, krb5_addrtype *val)
version		SUNWprivate_1.1
end

function	asn1_decode_ap_options
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_ap_options \
			(asn1buf *buf, krb5_flags *val)
version		SUNWprivate_1.1
end

function	asn1_decode_authdata_elt
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_authdata_elt \
			(asn1buf *buf, krb5_authdata *val)
version		SUNWprivate_1.1
end

function	asn1_decode_authdatatype
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_authdatatype \
			(asn1buf *buf, krb5_authdatatype *val)
version		SUNWprivate_1.1
end

function	asn1_decode_authorization_data
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_authorization_data \
			(asn1buf *buf, krb5_authdata ***val)
version		SUNWprivate_1.1
end

function	asn1_decode_charstring
include		<asn1_decode.h>
declaration	asn1_error_code asn1_decode_charstring \
			(asn1buf *buf, unsigned int *retlen, char **val)
version		SUNWprivate_1.1
end

function	asn1_decode_checksum
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_checksum \
			(asn1buf *buf, krb5_checksum *val)
version		SUNWprivate_1.1
end

function	asn1_decode_cksumtype
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_cksumtype \
			(asn1buf *buf, krb5_cksumtype *val)
version		SUNWprivate_1.1
end

function	asn1_decode_enc_kdc_rep_part
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_enc_kdc_rep_part \
			(asn1buf *buf, krb5_enc_kdc_rep_part *val)
version		SUNWprivate_1.1
end

function	asn1_decode_enc_sam_key
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_enc_sam_key \
			(asn1buf *buf, krb5_sam_key *val)
version		SUNWprivate_1.1
end

function	asn1_decode_enc_sam_response_enc
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_enc_sam_response_enc \
			(asn1buf *buf, krb5_enc_sam_response_enc *val)
version		SUNWprivate_1.1
end

function	asn1_decode_encrypted_data
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_encrypted_data \
			(asn1buf *buf, krb5_enc_data *val)
version		SUNWprivate_1.1
end

function	asn1_decode_encryption_key
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_encryption_key \
			(asn1buf *buf, krb5_keyblock *val)
version		SUNWprivate_1.1
end

function	asn1_decode_enctype
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_enctype \
			(asn1buf *buf, krb5_enctype *val)
version		SUNWprivate_1.1
end

function	asn1_decode_etype_info
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_etype_info \
			(asn1buf *buf, krb5_etype_info_entry ***val)
version		SUNWprivate_1.1
end

function	asn1_decode_generalstring
include		<asn1_decode.h>
declaration	asn1_error_code asn1_decode_generalstring \
			(asn1buf *buf, unsigned int *retlen, char **val)
version		SUNWprivate_1.1
end

function	asn1_decode_generaltime
include		<asn1_decode.h>
declaration	asn1_error_code asn1_decode_generaltime \
			(asn1buf *buf, time_t *val)
version		SUNWprivate_1.1
end

function	asn1_decode_host_address
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_host_address \
			(asn1buf *buf, krb5_address *val)
version		SUNWprivate_1.1
end

function	asn1_decode_host_addresses
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_host_addresses \
			(asn1buf *buf, krb5_address ***val)
version		SUNWprivate_1.1
end

function	asn1_decode_ia5string
include		<asn1_decode.h>
declaration	asn1_error_code asn1_decode_ia5string \
			(asn1buf *buf, int *retlen, char **val)
version		SUNWprivate_1.1
end

function	asn1_decode_int
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_int \
			(asn1buf *buf, int *val)
version		SUNWprivate_1.1
end

function	asn1_decode_int32
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_int32 \
			(asn1buf *buf, krb5_int32 *val)
version		SUNWprivate_1.1
end

function	asn1_decode_integer
include		<asn1_decode.h>
declaration	asn1_error_code asn1_decode_integer \
			(asn1buf *buf, long *val)
version		SUNWprivate_1.1
end

function	asn1_decode_kdc_options
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_kdc_options \
			(asn1buf *buf, krb5_flags *val)
version		SUNWprivate_1.1
end

function	asn1_decode_kdc_rep
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_kdc_rep \
			(asn1buf *buf, krb5_kdc_rep *val)
version		SUNWprivate_1.1
end

function	asn1_decode_kdc_req
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_kdc_req \
			(asn1buf *buf, krb5_kdc_req *val)
version		SUNWprivate_1.1
end

function	asn1_decode_kdc_req_body
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_kdc_req_body \
			(asn1buf *buf, krb5_kdc_req *val)
version		SUNWprivate_1.1
end

function	asn1_decode_kerberos_time
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_kerberos_time \
			(asn1buf *buf, krb5_timestamp *val)
version		SUNWprivate_1.1
end

function	asn1_decode_krb5_flags
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_krb5_flags \
			(asn1buf *buf, krb5_flags *val)
version		SUNWprivate_1.1
end

function	asn1_decode_krb_cred_info
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_krb_cred_info \
			(asn1buf *buf, krb5_cred_info *val)
version		SUNWprivate_1.1
end

function	asn1_decode_krb_safe_body
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_krb_safe_body \
			(asn1buf *buf, krb5_safe *val)
version		SUNWprivate_1.1
end

function	asn1_decode_kvno
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_kvno \
			(asn1buf *buf, krb5_kvno *val)
version		SUNWprivate_1.1
end

function	asn1_decode_last_req
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_last_req \
			(asn1buf *buf, krb5_last_req_entry ***val)
version		SUNWprivate_1.1
end

function	asn1_decode_last_req_entry
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_last_req_entry \
			(asn1buf *buf, krb5_last_req_entry *val)
version		SUNWprivate_1.1
end

function	asn1_decode_msgtype
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_msgtype \
			(asn1buf *buf, krb5_msgtype *val)
version		SUNWprivate_1.1
end

function	asn1_decode_null
include		<asn1_decode.h>
declaration	asn1_error_code asn1_decode_null(asn1buf *buf)
version		SUNWprivate_1.1
end

function	asn1_decode_octet
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_octet \
			(asn1buf *buf, krb5_octet *val)
version		SUNWprivate_1.1
end

function	asn1_decode_octetstring
include		<asn1_decode.h>
declaration	asn1_error_code asn1_decode_octetstring \
			(asn1buf *buf, unsigned int *retlen, asn1_octet **val)
version		SUNWprivate_1.1
end

function	asn1_decode_pa_data
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_pa_data \
			(asn1buf *buf, krb5_pa_data *val)
version		SUNWprivate_1.1
end

function	asn1_decode_passwdsequence
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_passwdsequence \
			(asn1buf *buf, passwd_phrase_element *val)
version		SUNWprivate_1.1
end

function	asn1_decode_predicted_sam_response
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_predicted_sam_response \
			(asn1buf *buf, krb5_predicted_sam_response *val)
version		SUNWprivate_1.1
end

function	asn1_decode_principal_name
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_principal_name \
			(asn1buf *buf, krb5_principal *val)
version		SUNWprivate_1.1
end

function	asn1_decode_printablestring
include		<asn1_decode.h>
declaration	asn1_error_code asn1_decode_printablestring \
			(asn1buf *buf, int *retlen, char **val)
version		SUNWprivate_1.1
end

function	asn1_decode_realm
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_realm \
			(asn1buf *buf, krb5_principal *val)
version		SUNWprivate_1.1
end

function	asn1_decode_sam_challenge
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_sam_challenge \
			(asn1buf *buf, krb5_sam_challenge *val)
version		SUNWprivate_1.1
end

function	asn1_decode_sam_flags
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_sam_flags \
			(asn1buf *buf, krb5_flags *val)
version		SUNWprivate_1.1
end

function	asn1_decode_sam_response
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_sam_response \
			(asn1buf *buf, krb5_sam_response *val)
version		SUNWprivate_1.1
end

function	asn1_decode_sequence_of_enctype
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_sequence_of_enctype \
			(asn1buf *buf, int *num, krb5_enctype **val)
version		SUNWprivate_1.1
end

function	asn1_decode_sequence_of_krb_cred_info
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_sequence_of_krb_cred_info \
			(asn1buf *buf, krb5_cred_info ***val)
version		SUNWprivate_1.1
end

function	asn1_decode_sequence_of_pa_data
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_sequence_of_pa_data \
			(asn1buf *buf, krb5_pa_data ***val)
version		SUNWprivate_1.1
end

function	asn1_decode_sequence_of_passwdsequence
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_sequence_of_passwdsequence \
			(asn1buf *buf, passwd_phrase_element ***val)
version		SUNWprivate_1.1
end

function	asn1_decode_sequence_of_ticket
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_sequence_of_ticket \
			(asn1buf *buf, krb5_ticket ***val)
version		SUNWprivate_1.1
end

function	asn1_decode_ticket
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_ticket \
			(asn1buf *buf, krb5_ticket *val)
version		SUNWprivate_1.1
end

function	asn1_decode_ticket_flags
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_ticket_flags \
			(asn1buf *buf, krb5_flags *val)
version		SUNWprivate_1.1
end

function	asn1_decode_transited_encoding
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_transited_encoding \
			(asn1buf *buf, krb5_transited *val)
version		SUNWprivate_1.1
end

function	asn1_decode_ui_2
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_ui_2 \
			(asn1buf *buf, krb5_ui_2 *val)
version		SUNWprivate_1.1
end

function	asn1_decode_ui_4
include		<asn1_k_decode.h>
declaration	asn1_error_code asn1_decode_ui_4 \
			(asn1buf *buf, krb5_ui_4 *val)
version		SUNWprivate_1.1
end

function	asn1_decode_unsigned_integer
include		<asn1_decode.h>
declaration	asn1_error_code asn1_decode_unsigned_integer \
			(asn1buf *buf, unsigned long *val)
version		SUNWprivate_1.1
end

function	asn1_encode_ap_options
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_ap_options \
			(asn1buf *buf, const krb5_flags val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_authorization_data
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_authorization_data \
			(asn1buf *buf, const krb5_authdata **val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_charstring
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_charstring (asn1buf *buf, \
			const unsigned int len, const char *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_checksum
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_checksum (asn1buf *buf, \
			const krb5_checksum *val, unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_enc_kdc_rep_part
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_enc_kdc_rep_part (asn1buf *buf, \
			const krb5_enc_kdc_rep_part *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_enc_sam_response_enc
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_enc_sam_response_enc (asn1buf *buf, \
			const krb5_enc_sam_response_enc *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_encrypted_data
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_encrypted_data \
			(asn1buf *buf, const krb5_enc_data *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_encryption_key
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_encryption_key \
			(asn1buf *buf, const krb5_keyblock *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_etype_info
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_etype_info (asn1buf *buf, \
			const krb5_etype_info_entry **val, \
			unsigned int *retlen, int etype_info2)
version		SUNWprivate_1.1
end

function	asn1_encode_etype_info_entry
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_etype_info_entry (asn1buf *buf, \
			const krb5_etype_info_entry *val, \
			unsigned int *retlen, int etype_info2)
version		SUNWprivate_1.1
end

function	asn1_encode_generalstring
include		<asn1_encode.h>
declaration	asn1_error_code asn1_encode_generalstring (asn1buf *buf, \
			const unsigned int len, const char *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_generaltime
include		<asn1_encode.h>
declaration	asn1_error_code asn1_encode_generaltime \
			(asn1buf *buf, const time_t val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_host_address
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_host_address (asn1buf *buf, \
			const krb5_address *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_host_addresses
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_host_addresses (asn1buf *buf, \
			const krb5_address **val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_ia5string
include		<asn1_encode.h>
declaration	asn1_error_code asn1_encode_ia5string (asn1buf *buf, \
			const unsigned int len, const char *val, \
			int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_integer
include		<asn1_encode.h>
declaration	asn1_error_code asn1_encode_integer \
			(asn1buf *buf, const long val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_kdc_options
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_kdc_options \
			(asn1buf *buf, const krb5_flags val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_kdc_rep
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_kdc_rep (int msg_type, \
			asn1buf *buf, const krb5_kdc_rep *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_kdc_req
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_kdc_req (int msg_type, \
			asn1buf *buf, const krb5_kdc_req *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_kdc_req_body
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_kdc_req_body \
			(asn1buf *buf, const krb5_kdc_req *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_kerberos_time
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_kerberos_time \
			(asn1buf *buf, const krb5_timestamp val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_krb5_authdata_elt
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_krb5_authdata_elt \
			(asn1buf *buf, const krb5_authdata *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_krb5_flags
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_krb5_flags \
			(asn1buf *buf, const krb5_flags val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_krb_cred_info
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_krb_cred_info \
			(asn1buf *buf, const krb5_cred_info *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_krb_safe_body
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_krb_safe_body \
			(asn1buf *buf, const krb5_safe *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_last_req
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_last_req (asn1buf *buf, \
			const krb5_last_req_entry **val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_last_req_entry
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_last_req_entry (asn1buf *buf, \
			const krb5_last_req_entry *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_null
include		<asn1_encode.h>
declaration	asn1_error_code asn1_encode_null (asn1buf *buf, int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_octetstring
include		<asn1_encode.h>
declaration	asn1_error_code asn1_encode_octetstring (asn1buf *buf, \
			const unsigned int len, const asn1_octet *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_pa_data
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_pa_data \
			(asn1buf *buf, const krb5_pa_data *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_passwdsequence
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_passwdsequence (asn1buf *buf, \
			const passwd_phrase_element *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_predicted_sam_response
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_predicted_sam_response (asn1buf *buf, \
			const krb5_predicted_sam_response *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_principal_name
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_principal_name \
			(asn1buf *buf, const krb5_principal val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_printablestring
include		<asn1_encode.h>
declaration	asn1_error_code asn1_encode_printablestring (asn1buf *buf, \
			const unsigned int len, const char *val, \
			int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_realm
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_realm \
			(asn1buf *buf, const krb5_principal val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_sam_challenge
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_sam_challenge (asn1buf *buf, \
			const krb5_sam_challenge * val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_sam_flags
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_sam_flags \
			(asn1buf * buf, const krb5_flags val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_sam_key
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_sam_key \
			(asn1buf *buf, const krb5_sam_key *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_sam_response
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_sam_response (asn1buf *buf, \
			const krb5_sam_response *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_sequence_of_enctype
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_sequence_of_enctype (asn1buf *buf, \
			const int len, const krb5_enctype *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_sequence_of_krb_cred_info
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_sequence_of_krb_cred_info \
			(asn1buf *buf, const krb5_cred_info **val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_sequence_of_pa_data
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_sequence_of_pa_data \
			(asn1buf *buf, const krb5_pa_data **val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_sequence_of_passwdsequence
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_sequence_of_passwdsequence \
			(asn1buf *buf, const passwd_phrase_element **val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_sequence_of_ticket
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_sequence_of_ticket \
			(asn1buf *buf, const krb5_ticket **val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_ticket
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_ticket \
			(asn1buf *buf, const krb5_ticket *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_ticket_flags
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_ticket_flags \
			(asn1buf *buf, const krb5_flags val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_transited_encoding
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_transited_encoding \
			(asn1buf *buf, const krb5_transited *val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_ui_4
include		<asn1_k_encode.h>
declaration	asn1_error_code asn1_encode_ui_4 (asn1buf *buf, \
				const krb5_ui_4 val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_encode_unsigned_integer
include		<asn1_encode.h>
declaration	asn1_error_code asn1_encode_unsigned_integer \
			(asn1buf *buf, const unsigned long val, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_get_sequence
include		<asn1_get.h>
declaration	asn1_error_code asn1_get_sequence \
			(asn1buf *buf, unsigned int *retlen, \
			int *indef)
version		SUNWprivate_1.1
end

function	asn1_get_tag_2
include		<asn1_get.h>
declaration	asn1_error_code asn1_get_tag_2 (asn1buf *buf, taginfo *tinfo)
version		SUNWprivate_1.1
end

function	asn1_krb5_realm_copy
include		<asn1_misc.h>
declaration	asn1_error_code asn1_krb5_realm_copy \
			(krb5_principal target, krb5_principal source)
version		SUNWprivate_1.1
end

function	asn1_make_etag
include		<asn1_make.h>
declaration	asn1_error_code asn1_make_etag (asn1buf *buf, \
			const asn1_class class, \
			const asn1_tagnum tagnum, \
			const unsigned int in_len, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_make_id
include		<asn1_make.h>
declaration	asn1_error_code asn1_make_id (asn1buf *buf, const asn1_class class, \
			const asn1_construction construction, const asn1_tagnum tagnum, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_make_length
include		<asn1_make.h>
declaration	asn1_error_code asn1_make_length \
			(asn1buf *buf, const unsigned int in_len, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_make_sequence
include		<asn1_make.h>
declaration	asn1_error_code asn1_make_sequence \
			(asn1buf *buf, const unsigned int seq_len, \
			unsigned int *len)
version		SUNWprivate_1.1
end

function	asn1_make_set
include		<asn1_make.h>
declaration	asn1_error_code asn1_make_set \
			(asn1buf *buf, const unsigned int set_len, \
			unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1_make_string
include		<asn1_make.h>
declaration	asn1_error_code asn1_make_string (asn1buf *buf, \
			const unsigned int len, const char *string, \
			int *retlen)
version		SUNWprivate_1.1
end

function	asn1_make_tag
include		<asn1_make.h>
declaration	asn1_error_code asn1_make_tag \
			(asn1buf *buf, const asn1_class class, \
			const asn1_construction construction, \
			const asn1_tagnum tagnum, \
			const unsigned int in_len, unsigned int *retlen)
version		SUNWprivate_1.1
end

function	asn1buf_create
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_create (asn1buf **buf)
version		SUNWprivate_1.1
end

function	asn1buf_destroy
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_destroy (asn1buf **buf)
version		SUNWprivate_1.1
end

function	asn1buf_ensure_space
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_ensure_space \
			(asn1buf *buf, const unsigned int amount)
version		SUNWprivate_1.1
end

function	asn1buf_expand
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_expand \
			(asn1buf *buf, unsigned int inc)
version		SUNWprivate_1.1
end

function	asn1buf_free
include		<asn1buf.h>
declaration	int asn1buf_free (const asn1buf *buf)
version		SUNWprivate_1.1
end

function	asn1buf_hex_unparse
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_hex_unparse \
			(const asn1buf *buf, char **s)
version		SUNWprivate_1.1
end

function	asn1buf_imbed
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_imbed \
			(asn1buf *subbuf, const asn1buf *buf, \
			const unsigned int length,\
			const int indef)
version		SUNWprivate_1.1
end

function	asn1buf_insert_charstring
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_insert_charstring \
			(asn1buf *buf, const unsigned int len, const char *s)
version		SUNWprivate_1.1
end

function	asn1buf_insert_octet
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_insert_octet \
			(asn1buf *buf, const int o)
version		SUNWprivate_1.1
end

function	asn1buf_insert_octetstring
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_insert_octetstring \
			(asn1buf *buf, const unsigned int len, \
			const asn1_octet *s)
version		SUNWprivate_1.1
end

function	asn1buf_len
include		<asn1buf.h>
declaration	int asn1buf_len (const asn1buf *buf)
version		SUNWprivate_1.1
end

function	asn1buf_remains
include		<asn1buf.h>
declaration	int asn1buf_remains (asn1buf *buf, int indef)
version		SUNWprivate_1.1
end

function	asn1buf_remove_charstring
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_remove_charstring \
			(asn1buf *buf, const unsigned int len, char **s)
version		SUNWprivate_1.1
end

function	asn1buf_remove_octet
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_remove_octet \
			(asn1buf *buf, asn1_octet *o)
version		SUNWprivate_1.1
end

function	asn1buf_remove_octetstring
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_remove_octetstring \
			(asn1buf *buf, const unsigned int len, asn1_octet **s)
version		SUNWprivate_1.1
end

function	asn1buf_size
include		<asn1buf.h>
declaration	int asn1buf_size (const asn1buf *buf)
version		SUNWprivate_1.1
end

function	asn1buf_skiptail
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_skiptail \
			(asn1buf *buf, const unsigned int length, const int indef)
version		SUNWprivate_1.1
end

function	asn1buf_sync
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_sync (asn1buf *buf, asn1buf *subbuf, \
			const asn1_class class, const asn1_tagnum lasttag, \
			const unsigned int length, const int indef, \
			const int seqindef)
version		SUNWprivate_1.1
end

function	asn1buf_unparse
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_unparse \
			(const asn1buf *buf, char **s)
version		SUNWprivate_1.1
end

function	asn1buf_wrap_data
include		<asn1buf.h>
declaration	asn1_error_code asn1buf_wrap_data \
			(asn1buf *buf, const krb5_data *code)
version		SUNWprivate_1.1
end
