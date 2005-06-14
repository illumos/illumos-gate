/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
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

#ifdef SOCK_DGRAM			/* XXX hack... */
krb5_error_code krb5_locate_kdc
    PROTOTYPE((krb5_context,
	       const krb5_data *,
	       struct addrlist *,
	       int ,
	       int ,
	       int));

krb5_error_code krb5_get_servername
    PROTOTYPE((krb5_context,
		const krb5_data *,
		const char *, const char *,
	    	char *,
		unsigned short *));
#endif

#ifdef HAVE_NETINET_IN_H
krb5_error_code krb5_unpack_full_ipaddr
    PROTOTYPE((krb5_context,
	       const krb5_address *,
	       krb5_int32 *,
	       krb5_int16 *));

krb5_error_code krb5_make_full_ipaddr
    PROTOTYPE((krb5_context,
	       krb5_int32,
	       int,			/* unsigned short promotes to signed
					   int */
	       krb5_address **));

#endif /* HAVE_NETINET_IN_H */

krb5_error_code krb5_try_realm_txt_rr(const char *, const char *, 
				      char **realm);

extern unsigned int krb5_max_dgram_size;

#endif /* KRB5_LIBOS_INT_PROTO__ */
