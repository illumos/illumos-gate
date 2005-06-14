#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc_write.c
 *
 * Copyright 1990,1991,1992,1993,1994 by the Massachusetts Institute
 * of Technology. 
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_fcc_write_<type>.
 */


#include <errno.h>
#include "fcc.h"

#define CHECK(ret) if (ret != KRB5_OK) return ret;

/*
 * Requires:
 * id is open
 *
 * Effects:
 * Writes len bytes from buf into the file cred cache id.
 *
 * Errors:
 * system errors
 */
krb5_error_code
krb5_fcc_write(context, id, buf, len)
   krb5_context context;
   krb5_ccache id;
   krb5_pointer buf;
   int len;
{
     int ret;

     ret = write(((krb5_fcc_data *)id->data)->fd, (char *) buf, len);
     if (ret < 0)
	  return krb5_fcc_interpret(context, errno);
     if (ret != len)
	 return KRB5_CC_WRITE;
     return KRB5_OK;
}

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 * 
 * Requires:
 * ((krb5_fcc_data *) id->data)->fd is open and at the right position.
 * 
 * Effects:
 * Stores an encoded version of the second argument in the
 * cache file.
 *
 * Errors:
 * system errors
 */

krb5_error_code
krb5_fcc_store_principal(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal princ;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code ret;
    krb5_int32 i, length, tmp, type;

    type = krb5_princ_type(context, princ);
    tmp = length = krb5_princ_size(context, princ);

    if (data->version == KRB5_FCC_FVNO_1) {
	/*
	 * DCE-compatible format means that the length count
	 * includes the realm.  (It also doesn't include the
	 * principal type information.)
	 */
	tmp++;
    } else {
	ret = krb5_fcc_store_int32(context, id, type);
	CHECK(ret);
    }
    
    ret = krb5_fcc_store_int32(context, id, tmp);
    CHECK(ret);

    ret = krb5_fcc_store_data(context, id, krb5_princ_realm(context, princ));
    CHECK(ret);

    for (i=0; i < length; i++) {
	ret = krb5_fcc_store_data(context, id, krb5_princ_component(context, princ, i));
	CHECK(ret);
    }

    return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_addrs(context, id, addrs)
   krb5_context context;
   krb5_ccache id;
   krb5_address ** addrs;
{
     krb5_error_code ret;
     krb5_address **temp;
     krb5_int32 i, length = 0;

     /* Count the number of components */
     if (addrs) {
	     temp = addrs;
	     while (*temp++)
		     length += 1;
     }

     ret = krb5_fcc_store_int32(context, id, length);
     CHECK(ret);
     for (i=0; i < length; i++) {
	  ret = krb5_fcc_store_addr(context, id, addrs[i]);
	  CHECK(ret);
     }

     return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_keyblock(context, id, keyblock)
   krb5_context context;
   krb5_ccache id;
   krb5_keyblock *keyblock;
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code ret;

     ret = krb5_fcc_store_ui_2(context, id, keyblock->enctype);
     CHECK(ret);
     if (data->version == KRB5_FCC_FVNO_3) {
	 ret = krb5_fcc_store_ui_2(context, id, keyblock->enctype);
	 CHECK(ret);
     }
     ret = krb5_fcc_store_int32(context, id, keyblock->length);
     CHECK(ret);
     return krb5_fcc_write(context, id, (char *) keyblock->contents, keyblock->length);
}

krb5_error_code
krb5_fcc_store_addr(context, id, addr)
   krb5_context context;
   krb5_ccache id;
   krb5_address *addr;
{
     krb5_error_code ret;

     ret = krb5_fcc_store_ui_2(context, id, addr->addrtype);
     CHECK(ret);
     ret = krb5_fcc_store_int32(context, id, addr->length);
     CHECK(ret);
     return krb5_fcc_write(context, id, (char *) addr->contents, addr->length);
}


krb5_error_code
krb5_fcc_store_data(context, id, data)
   krb5_context context;
   krb5_ccache id;
   krb5_data *data;
{
     krb5_error_code ret;

     ret = krb5_fcc_store_int32(context, id, data->length);
     CHECK(ret);
     return krb5_fcc_write(context, id, data->data, data->length);
}

krb5_error_code
krb5_fcc_store_int32(context, id, i)
   krb5_context context;
   krb5_ccache id;
   krb5_int32 i;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    unsigned char buf[4];

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2)) 
	return krb5_fcc_write(context, id, (char *) &i, sizeof(krb5_int32));
    else {
	buf[3] = (unsigned char) (i & 0xFF);
	i >>= 8;
	buf[2] = (unsigned char) (i & 0xFF);
	i >>= 8;
	buf[1] = (unsigned char) (i & 0xFF);
	i >>= 8;
	buf[0] = (unsigned char) (i & 0xFF);
	
	return krb5_fcc_write(context, id, buf, 4);
    }
}

krb5_error_code
krb5_fcc_store_ui_2(context, id, i)
   krb5_context context;
    krb5_ccache id;
    krb5_int32 i;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_ui_2 ibuf;
    unsigned char buf[2];
    
    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2)) {
	ibuf = (krb5_ui_2) i;
	return krb5_fcc_write(context, id, (char *) &ibuf, sizeof(krb5_ui_2));
    } else {
	buf[1] = (unsigned char) (i & 0xFF);
	i >>= 8;
	buf[0] = (unsigned char) (i & 0xFF);
	
	return krb5_fcc_write(context, id, buf, 2);
    }
}
   
krb5_error_code
krb5_fcc_store_octet(context, id, i)
   krb5_context context;
    krb5_ccache id;
    krb5_int32 i;
{
    krb5_octet ibuf;

    ibuf = (krb5_octet) i;
    return krb5_fcc_write(context, id, (char *) &ibuf, 1);
}
   
krb5_error_code
krb5_fcc_store_times(context, id, t)
   krb5_context context;
   krb5_ccache id;
   krb5_ticket_times *t;
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code retval;

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_write(context, id, (char *) t, sizeof(krb5_ticket_times));
    else {
	retval = krb5_fcc_store_int32(context, id, t->authtime);
	CHECK(retval);
	retval = krb5_fcc_store_int32(context, id, t->starttime);
	CHECK(retval);
	retval = krb5_fcc_store_int32(context, id, t->endtime);
	CHECK(retval);
	retval = krb5_fcc_store_int32(context, id, t->renew_till);
	CHECK(retval);
	return 0;
    }
}
   
krb5_error_code
krb5_fcc_store_authdata(context, id, a)
   krb5_context context;
    krb5_ccache id;
    krb5_authdata **a;
{
    krb5_error_code ret;
    krb5_authdata **temp;
    krb5_int32 i, length=0;

    if (a != NULL) {
	for (temp=a; *temp; temp++)
	    length++;
    }

    ret = krb5_fcc_store_int32(context, id, length);
    CHECK(ret);
    for (i=0; i<length; i++) {
	ret = krb5_fcc_store_authdatum (context, id, a[i]);
	CHECK(ret);
    }
    return KRB5_OK;
}

krb5_error_code
krb5_fcc_store_authdatum (context, id, a)
   krb5_context context;
    krb5_ccache id;
    krb5_authdata *a;
{
    krb5_error_code ret;
    ret = krb5_fcc_store_ui_2(context, id, a->ad_type);
    CHECK(ret);
    ret = krb5_fcc_store_int32(context, id, a->length);
    CHECK(ret);
    return krb5_fcc_write(context, id, (krb5_pointer) a->contents, a->length);
}
