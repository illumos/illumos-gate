/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef ARCFOUR_H
#define ARCFOUR_H

#define CONFOUNDERLENGTH 8

extern void
krb5_arcfour_encrypt_length(const struct krb5_enc_provider *,
			const struct krb5_hash_provider *,
			size_t,
			size_t *);

extern 
krb5_error_code krb5_arcfour_encrypt(krb5_context,
			const struct krb5_enc_provider *,
			const struct krb5_hash_provider *,
			const krb5_keyblock *,
			krb5_keyusage,
			const krb5_data *,
     			const krb5_data *,
			krb5_data *);

extern 
krb5_error_code krb5_arcfour_decrypt(krb5_context,
			const struct krb5_enc_provider *,
			const struct krb5_hash_provider *,
			const krb5_keyblock *,
			krb5_keyusage,
			const krb5_data *,
			const krb5_data *,
			krb5_data *);

#ifndef _KERNEL
extern krb5_error_code krb5int_arcfour_string_to_key(
	krb5_context,
     const struct krb5_enc_provider *,
     const krb5_data *,
     const krb5_data *,
     const krb5_data *,
     krb5_keyblock *);
#endif /* _KERNEL */

extern const struct krb5_enc_provider krb5int_enc_arcfour;

krb5_keyusage krb5int_arcfour_translate_usage(krb5_keyusage usage);

#endif /* ARCFOUR_H */
