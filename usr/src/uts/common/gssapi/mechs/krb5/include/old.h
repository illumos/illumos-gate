/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"

void krb5_old_encrypt_length
(const struct krb5_enc_provider *enc,
		const struct krb5_hash_provider *hash,
		size_t input, size_t *length);

krb5_error_code krb5_old_encrypt
(krb5_context context,
		const struct krb5_enc_provider *enc,
		const struct krb5_hash_provider *hash,
		const krb5_keyblock *key, krb5_keyusage usage,
		const krb5_data *ivec, const krb5_data *input,
		krb5_data *output);

krb5_error_code krb5_old_decrypt
(krb5_context context,
		const struct krb5_enc_provider *enc,
		const struct krb5_hash_provider *hash,
		const krb5_keyblock *key, krb5_keyusage usage,
		const krb5_data *ivec, const krb5_data *input,
		krb5_data *arg_output);

#ifndef	_KERNEL
krb5_error_code krb5int_des_string_to_key
(krb5_context context,
		const struct krb5_enc_provider *enc,
		const krb5_data *string, const krb5_data *salt,
		const krb5_data *params,
		krb5_keyblock *key);
#endif	/* _KERNEL */
