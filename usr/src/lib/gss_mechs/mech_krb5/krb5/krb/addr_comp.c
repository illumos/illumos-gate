#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/krb/addr_comp.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * krb5_address_compare()
 */

#include <k5-int.h>

#ifdef KRB5_DEBUG
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/*
 * If the two addresses are the same, return TRUE, else return FALSE
 */
/*ARGSUSED*/
krb5_boolean KRB5_CALLCONV
krb5_address_compare(krb5_context context, krb5_const krb5_address *addr1,
	krb5_const krb5_address *addr2)
{
    KRB5_LOG0(KRB5_INFO, "krb5_address_compare() start");

#ifdef KRB5_DEBUG
{
    char buf[256];
    sa_family_t addr_fam;

    switch (addr1->addrtype) {
	case ADDRTYPE_INET:
	    addr_fam = AF_INET;
	    break;
	case ADDRTYPE_INET6:
	    addr_fam = AF_INET6;
	    break;
    }
    inet_ntop(addr_fam, addr1->contents, buf, sizeof(buf));
    KRB5_LOG(KRB5_INFO, "krb5_address_compare() addr1=%s", buf);
    KRB5_LOG(KRB5_INFO, "krb5_address_compare() addr1 type=%d", 
	    addr1->addrtype);
    KRB5_LOG(KRB5_INFO, "krb5_address_compare() addr1 length=%d", 
	    addr1->length);

    switch (addr2->addrtype) {
	case ADDRTYPE_INET:
	    addr_fam = AF_INET;
	    break;
	case ADDRTYPE_INET6:
	    addr_fam = AF_INET6;
	    break;
    }
    inet_ntop(addr_fam, addr2->contents, buf, sizeof(buf));
    KRB5_LOG(KRB5_INFO, "krb5_address_compare() addr2=%s", buf);
    KRB5_LOG(KRB5_INFO, "krb5_address_compare() addr2 type=%d", 
	    addr2->addrtype);
    KRB5_LOG(KRB5_INFO, "krb5_address_compare() addr2 length=%d", 
	    addr2->length);
}
#endif /* KRB5_DEBUG */

    if (addr1->addrtype != addr2->addrtype){
	KRB5_LOG0(KRB5_INFO, "krb5_address_compare() end FALSE"
		" (addrtype mismatch)");
	return(FALSE);
    }

    if (addr1->length != addr2->length){
	KRB5_LOG0(KRB5_INFO, "krb5_address_compare() end FALSE"
		" (length mismatch)");
	return(FALSE);
    }
    if (memcmp((char *)addr1->contents, (char *)addr2->contents,
	       addr1->length)){
	KRB5_LOG0(KRB5_INFO, "krb5_address_compare() end FALSE"
		" (contents mismatch)");
	return FALSE;
    }
    else {
	KRB5_LOG0(KRB5_INFO, "krb5_address_compare() end TRUE");
	return TRUE;
    }
}
