/*
 * lib/krb5/os/full_ipadr.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * Take an IP addr & port and generate a full IP address.
 */

#include "k5-int.h"

#ifdef HAVE_NETINET_IN_H

#include "os-proto.h"
#if !defined(_WINSOCKAPI_)

#include <netinet/in.h>
#endif

/*ARGSUSED*/
krb5_error_code
krb5_make_fulladdr(krb5_context context, krb5_address *kaddr, krb5_address *kport, krb5_address *raddr)
{
    register krb5_octet * marshal;
    krb5_int32 tmp32;
    krb5_int16 tmp16;

    if ((kport == NULL) || (kport == NULL))
	return EINVAL;

    raddr->length = kaddr->length + kport->length + (4 * sizeof(krb5_int32));
    if (!(raddr->contents = (krb5_octet *)malloc(raddr->length)))
	return ENOMEM;

    raddr->addrtype = ADDRTYPE_ADDRPORT;
    marshal = raddr->contents;

    tmp16 = kaddr->addrtype;
    *marshal++ = 0x00;
    *marshal++ = 0x00;
    *marshal++ = (krb5_octet) (tmp16 & 0xff);
    *marshal++ = (krb5_octet) ((tmp16 >> 8) & 0xff);

    tmp32 = kaddr->length;
    *marshal++ = (krb5_octet) (tmp32 & 0xff);
    *marshal++ = (krb5_octet) ((tmp32 >> 8) & 0xff);
    *marshal++ = (krb5_octet) ((tmp32 >> 16) & 0xff);
    *marshal++ = (krb5_octet) ((tmp32 >> 24) & 0xff);

    (void) memcpy((char *)marshal, (char *)(kaddr->contents), kaddr->length);
    marshal += kaddr->length;

    tmp16 = kport->addrtype;
    *marshal++ = 0x00;
    *marshal++ = 0x00;
    *marshal++ = (krb5_octet) (tmp16 & 0xff);
    *marshal++ = (krb5_octet) ((tmp16 >> 8) & 0xff);

    tmp32 = kport->length;
    *marshal++ = (krb5_octet) (tmp32 & 0xff);
    *marshal++ = (krb5_octet) ((tmp32 >> 8) & 0xff);
    *marshal++ = (krb5_octet) ((tmp32 >> 16) & 0xff);
    *marshal++ = (krb5_octet) ((tmp32 >> 24) & 0xff);

    (void) memcpy((char *)marshal, (char *)(kport->contents), kport->length);
    marshal += kport->length;
    return 0;
}
#endif
