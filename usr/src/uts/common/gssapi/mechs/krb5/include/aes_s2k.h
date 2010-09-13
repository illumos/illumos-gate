extern krb5_error_code
krb5int_aes_string_to_key (krb5_context context, const struct krb5_enc_provider *,
			   const krb5_data *, const krb5_data *,
			   const krb5_data *, krb5_keyblock *key);
