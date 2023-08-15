/*
 * lib/krb5/os/os-proto.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * LIBOS internal function prototypes.
 */

#ifndef KRB5_LIBOS_INT_PROTO__
#define KRB5_LIBOS_INT_PROTO__

struct addrlist;
krb5_error_code krb5_locate_kdc
    (krb5_context, const krb5_data *, struct addrlist *, int, int, int);

/* Solaris Kerberos */
krb5_error_code krb5_get_servername
	(krb5_context,
	const krb5_data *,
	const char *, const char *,
	char *,
	unsigned short *);


#ifdef HAVE_NETINET_IN_H
krb5_error_code krb5_unpack_full_ipaddr
	      (krb5_context,
	       const krb5_address *,
	       krb5_int32 *,
	       krb5_int16 *);

krb5_error_code krb5_make_full_ipaddr
              (krb5_context,
	       krb5_int32,
	       int,			/* unsigned short promotes to signed
					   int */
	       krb5_address **);

#endif /* HAVE_NETINET_IN_H */

krb5_error_code krb5_try_realm_txt_rr(const char *, const char *,
				      char **realm);

/* Obsolete interface - leave prototype here until code removed */
krb5_error_code krb5_secure_config_files(krb5_context ctx);

void krb5int_debug_fprint (const char *fmt, ...);

int _krb5_use_dns_realm (krb5_context);
int _krb5_use_dns_kdc (krb5_context);
int _krb5_conf_boolean (const char *);

#include "k5-thread.h"
extern k5_mutex_t krb5int_us_time_mutex;

extern unsigned int krb5_max_skdc_timeout;
extern unsigned int krb5_skdc_timeout_shift;
extern unsigned int krb5_skdc_timeout_1;
extern unsigned int krb5_max_dgram_size;


#endif /* KRB5_LIBOS_INT_PROTO__ */
