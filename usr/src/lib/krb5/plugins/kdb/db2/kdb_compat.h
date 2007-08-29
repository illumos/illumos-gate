/*
 * Copyright 1997-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KRB5_KDB_KDB_COMPAT_H
#define	_KRB5_KDB_KDB_COMPAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * lib/kdb/kdb_compat.h
 *
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
 * KDC Database interface definitions.
 */


typedef struct _old_krb5_encrypted_keyblock {
    krb5_enctype enctype;
    int length;
    krb5_octet *contents;
} old_krb5_encrypted_keyblock;

typedef struct old_krb5_principal_data {
    krb5_magic magic;
    krb5_data realm;
    krb5_data *data;		/* An array of strings */
    krb5_int32 length;
    krb5_int32 type;
} old_krb5_principal_data;

typedef	old_krb5_principal_data *old_krb5_principal;


/*
 * Note --- this structure cannot be modified without changing the
 * database version number in libkdb.a
 */
typedef struct _old_krb5_db_entry {
    old_krb5_principal principal;
    old_krb5_encrypted_keyblock key;
    krb5_kvno kvno;
    krb5_deltat	max_life;
    krb5_deltat	max_renewable_life;
    krb5_kvno mkvno;			/* master encryption key vno */
    
    krb5_timestamp expiration;		/* This is when the client expires */
    krb5_timestamp pw_expiration; 	/* This is when its password does */
    krb5_timestamp last_pwd_change; 	/* Last time of password change  */
    krb5_timestamp last_success;	/* Last successful password */
    
    krb5_timestamp last_failed;		/* Last failed password attempt */
    krb5_kvno fail_auth_count; 		/* # of failed password attempts */
    
    old_krb5_principal mod_name;
    krb5_timestamp mod_date;
    krb5_flags attributes;
    krb5_int32 salt_type:8,
 	       salt_length:24;
    krb5_octet *salt;
    old_krb5_encrypted_keyblock alt_key;
    krb5_int32 alt_salt_type:8,
 	       alt_salt_length:24;
    krb5_octet *alt_salt;
    
    krb5_int32 expansion[8];
} old_krb5_db_entry;


#ifdef	__cplusplus
}
#endif

#endif	/* !_KRB5_KDB_KDB_COMPAT_H */
