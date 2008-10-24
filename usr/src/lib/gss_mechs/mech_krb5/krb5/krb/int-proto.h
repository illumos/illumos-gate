/*
 * lib/krb5/krb/int-proto.h
 *
 * Copyright 1990,1991 the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Function prototypes for Kerberos V5 library internal functions.
 */


#ifndef KRB5_INT_FUNC_PROTO__
#define KRB5_INT_FUNC_PROTO__

krb5_error_code krb5_tgtname
    	(krb5_context context,
	           const krb5_data *,
	           const krb5_data *,
	           krb5_principal *);

krb5_error_code krb5_libdefault_boolean
        (krb5_context, const krb5_data *, const char *,
			int *);

krb5_error_code krb5_ser_authdata_init (krb5_context);
krb5_error_code krb5_ser_address_init (krb5_context);
krb5_error_code krb5_ser_authenticator_init (krb5_context);
krb5_error_code krb5_ser_checksum_init (krb5_context);
krb5_error_code krb5_ser_keyblock_init (krb5_context);
krb5_error_code krb5_ser_principal_init (krb5_context);

krb5_error_code
krb5_preauth_supply_preauth_data(krb5_context context,
				 krb5_gic_opt_ext *opte,
				 const char *attr,
				 const char *value);

#endif /* KRB5_INT_FUNC_PROTO__ */

