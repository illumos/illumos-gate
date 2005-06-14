#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_crypto.spec
#

function	krb5_c_is_coll_proof_cksum
include		<k5-int.h>, <cksumtypes.h>
declaration	krb5_boolean krb5_c_is_coll_proof_cksum( \
			krb5_cksumtype ctype)
version		SUNWprivate_1.1
end

function	krb5_c_is_keyed_cksum
include		<k5-int.h>, <cksumtypes.h>
declaration	krb5_boolean krb5_c_is_keyed_cksum( \
			krb5_cksumtype ctype)
version		SUNWprivate_1.1
end

function	krb5_c_block_size
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_c_block_size( \
			krb5_context context, \
			krb5_enctype enctype, \
			size_t *blocksize)
version		SUNWprivate_1.1
end

function	krb5_c_init_state
include		<krb5.h>
declaration	krb5_error_code krb5_c_init_state( \
			krb5_context, const krb5_keyblock *, \
			krb5_keyusage, krb5_data *)
version		SUNWprivate_1.1
end

function	krb5_c_free_state
include		<k5-int.h>
declaration	krb5_error_code krb5_c_free_state( \
			krb5_context, const krb5_keyblock *, \
			krb5_data *)
version		SUNWprivate_1.1
end

function	krb5_c_checksum_length
include		<k5-int.h>, <cksumtypes.h>
declaration	krb5_error_code krb5_c_checksum_length( \
			krb5_context context, \
			krb5_cksumtype cksumtype, \
			size_t *length)
version		SUNWprivate_1.1
end

function	krb5_c_decrypt
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_c_decrypt( \
			krb5_context context, \
			const krb5_keyblock *key, \
			krb5_keyusage usage, \
			const krb5_data *ivec, \
			const krb5_enc_data *input, \
			krb5_data *output)
version		SUNWprivate_1.1
end

function	krb5_c_encrypt
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_c_encrypt( \
			krb5_context context, \
			const krb5_keyblock *key, \
			krb5_keyusage usage, \
			const krb5_data *ivec, \
			const krb5_data *input, \
			krb5_enc_data *output)
version		SUNWprivate_1.1
end

function	krb5_c_encrypt_length
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_c_encrypt_length( \
			krb5_context context, \
			krb5_enctype enctype, \
			size_t inputlen, \
			size_t *length)
version		SUNWprivate_1.1
end

function	krb5_c_enctype_compare
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_c_enctype_compare( \
			krb5_context context, \
			krb5_enctype e1, \
			krb5_enctype e2, \
			krb5_boolean *similar)
version		SUNWprivate_1.1
end

function	krb5_c_keyed_checksum_types
include		<k5-int.h>, <etypes.h>, <cksumtypes.h>
declaration	krb5_error_code krb5_c_keyed_checksum_types( \
			krb5_context context, \
			krb5_enctype enctype, \
			unsigned int *count, \
			krb5_cksumtype **cksumtypes)
version		SUNWprivate_1.1
end

function	krb5_c_make_checksum	
include		<k5-int.h>, <cksumtypes.h>, <etypes.h>
declaration	krb5_error_code krb5_c_make_checksum ( \
			krb5_context context, \
			krb5_cksumtype cksumtype, \
			const krb5_keyblock *key, \
			krb5_keyusage usage, \
			const krb5_data *input, \
			krb5_checksum *cksum)
version		SUNWprivate_1.1
end

function	krb5_c_verify_checksum	
include		<k5-int.h>, <cksumtypes.h>
declaration	krb5_error_code krb5_c_verify_checksum ( \
                        krb5_context context, \
                        const krb5_keyblock *key, \
                        krb5_keyusage usage, \
                        const krb5_data *data, \
                        const krb5_checksum *cksum, \
                        krb5_boolean *valid)

version		SUNWprivate_1.1
end

function	krb5_c_make_random_key	
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_c_make_random_key( \
			krb5_context context, \
			krb5_enctype enctype, \
			krb5_keyblock *random_key)
version		SUNWprivate_1.1
end

function	krb5_c_random_make_octets	
include		<k5-int.h>, <enc_provider.h>
declaration	krb5_error_code krb5_c_random_make_octets( \
			krb5_context context, krb5_data *data)
version		SUNWprivate_1.1
end

function	krb5_c_random_seed	
include		<k5-int.h>, <enc_provider.h>
declaration	krb5_error_code krb5_c_random_seed( \
			krb5_context context, krb5_data *data)
version		SUNWprivate_1.1
end

function	krb5_c_string_to_key
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_c_string_to_key( \
			krb5_context context, \
			krb5_enctype enctype, \
			const krb5_data *string, \
			const krb5_data *salt, \
			krb5_keyblock *key)
version		SUNWprivate_1.1
end

function	krb5_c_string_to_key_with_params
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_c_string_to_key_with_params( \
			krb5_context context, \
			krb5_enctype enctype, \
			const krb5_data *string, \
			const krb5_data *salt, \
			const krb5_data *params, \
			krb5_keyblock *key)
version		SUNWprivate_1.1
end

function	krb5_cksumtype_to_string
include		<k5-int.h>, <cksumtypes.h>
declaration	krb5_error_code krb5_cksumtype_to_string( \
			krb5_cksumtype cksumtype, \
			char * buffer, \
			size_t buflen)
version		SUNWprivate_1.1
end

function	krb5_enctype_to_string
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_enctype_to_string( \
			krb5_enctype enctype, \
			char * buffer, \
			size_t buflen)
version		SUNWprivate_1.1
end

function	krb5_old_decrypt
include		<k5-int.h>
declaration	krb5_error_code krb5_old_decrypt ( \
			krb5_context context, \
			const struct krb5_enc_provider *enc, \
			const struct krb5_hash_provider *hash, \
			const krb5_keyblock *key, krb5_keyusage usage,\
			const krb5_data *ivec, \
			const krb5_data *input, \
			krb5_data *arg_output)
version		SUNWprivate_1.1
end

function	krb5_old_encrypt
include		<k5-int.h>
declaration	void krb5_old_encrypt ( \
			krb5_context context, \
			const struct krb5_enc_provider *enc, \
			const struct krb5_hash_provider *hash, \
			const krb5_keyblock *key, krb5_keyusage usage, \
			const krb5_data *ivec, const krb5_data *input, \
			krb5_data *output)
version		SUNWprivate_1.1
end

function	krb5_old_encrypt_length
include		<k5-int.h>
declaration	void krb5_old_encrypt_length ( \
			const struct krb5_enc_provider *enc, \
			const struct krb5_hash_provider *hash, \
			size_t input, size_t *length)
version		SUNWprivate_1.1
end

function	krb5_raw_decrypt
include		<k5-int.h>, <raw.h>
declaration	krb5_error_code krb5_raw_decrypt ( \
			krb5_context context, \
			const struct krb5_enc_provider *enc, \
			const struct krb5_hash_provider *hash, \
			const krb5_keyblock *key, \
			krb5_keyusage usage, \
			const krb5_data *ivec, \
			const krb5_data *input, \
			krb5_data *output)
version		SUNWprivate_1.1
end

function	krb5_raw_encrypt
include		<k5-int.h>, <raw.h>
declaration	krb5_error_code krb5_raw_encrypt( \
			krb5_context context, \
			const struct krb5_enc_provider *enc, \
			const struct krb5_hash_provider *hash, \
			const krb5_keyblock *key, \
			krb5_keyusage usage, \
			const krb5_data *ivec, \
			const krb5_data *input, \
			krb5_data *output)
version		SUNWprivate_1.1
end

function	krb5_raw_encrypt_length
include		<k5-int.h>, <raw.h>
declaration	void krb5_raw_encrypt_length ( \
			const struct krb5_enc_provider *enc, \
			const struct krb5_hash_provider *hash, \
			size_t inputlen, \
			size_t *length)
version		SUNWprivate_1.1
end

function	mit_des_check_key_parity
include		<krb5.h>, <des_int.h>
declaration	int mit_des_check_key_parity (mit_des_cblock key)
version		SUNWprivate_1.1
end

function	mit_des_fixup_key_parity
include		<krb5.h>, <des_int.h>
declaration	void mit_des_fixup_key_parity (mit_des_cblock key)
version		SUNWprivate_1.1
end

function	mit_des_is_weak_key
include		<des_int.h>
declaration	int mit_des_is_weak_key (mit_des_cblock key)
version		SUNWprivate_1.1
end

function	krb5_string_to_cksumtype
include		<k5-int.h>, <cksumtypes.h>
declaration	krb5_error_code krb5_string_to_cksumtype( \
			char * string, krb5_cksumtype * cksumtypep)
version		SUNWprivate_1.1
end

function	krb5_string_to_enctype
include		<k5-int.h>, <etypes.h>
declaration	krb5_error_code krb5_string_to_enctype( \
			char * string, krb5_enctype * enctypep)
version		SUNWprivate_1.1
end

function	krb5_c_valid_cksumtype
include		<k5-int.h>, <cksumtypes.h>
declaration	krb5_boolean krb5_c_valid_cksumtype( \
			krb5_cksumtype ctype)
version		SUNWprivate_1.1
end

function	krb5_c_valid_enctype
include		<k5-int.h>, <etypes.h>
declaration	krb5_boolean krb5_c_valid_enctype( \
			krb5_enctype etype)
version		SUNWprivate_1.1
end

function	k5_ef_hash
include		<k5-int.h>, <security/pkcs11.h>
declaration	krb5_error_code k5_ef_hash(krb5_context context, \
			CK_MECHANISM *mechanism, \
			unsigned int icount, \
			const krb5_data *input, \
			krb5_data *output)
version		SUNWprivate_1.1
end

function	k5_ef_mac
include		<k5-int.h>, <security/pkcs11.h>
declaration	krb5_error_code k5_ef_mac(krb5_context context, \
			krb5_keyblock *key, \
			krb5_data *ivec, \
			const krb5_data *input, \
			krb5_data *output)
version		SUNWprivate_1.1
end


function	krb5int_aes_encrypt
include		<k5-int.h>, <security/pkcs11.h>
declaration	krb5_error_code \
		krb5int_aes_encrypt(krb5_context context, \
		const krb5_keyblock *key, const krb5_data *ivec,\
		const krb5_data *input, krb5_data *output)
version		SUNWprivate_1.1
end

function	krb5int_pbkdf2_hmac_sha1
include		<k5-int.h>, <security/pkcs11.h>
declaration	krb5_error_code krb5int_pbkdf2_hmac_sha1 ( \
			krb5_context context, \
			const krb5_data *out, unsigned long count, \
			krb5_enctype enctype, \
			const krb5_data *pass, const krb5_data *salt)
version		SUNWprivate_1.1
end


