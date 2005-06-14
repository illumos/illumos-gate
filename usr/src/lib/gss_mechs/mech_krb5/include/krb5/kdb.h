#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * include/krb5/kdb.h
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
 * KDC Database interface definitions.
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

#ifndef KRB5_KDB5__
#define KRB5_KDB5__

/* Salt types */
#define KRB5_KDB_SALTTYPE_NORMAL	0
#define KRB5_KDB_SALTTYPE_V4		1
#define KRB5_KDB_SALTTYPE_NOREALM	2
#define KRB5_KDB_SALTTYPE_ONLYREALM	3
#define KRB5_KDB_SALTTYPE_SPECIAL	4
#define KRB5_KDB_SALTTYPE_AFS3		5

/* Attributes */
#define	KRB5_KDB_DISALLOW_POSTDATED	0x00000001
#define	KRB5_KDB_DISALLOW_FORWARDABLE	0x00000002
#define	KRB5_KDB_DISALLOW_TGT_BASED	0x00000004
#define	KRB5_KDB_DISALLOW_RENEWABLE	0x00000008
#define	KRB5_KDB_DISALLOW_PROXIABLE	0x00000010
#define	KRB5_KDB_DISALLOW_DUP_SKEY	0x00000020
#define	KRB5_KDB_DISALLOW_ALL_TIX	0x00000040
#define	KRB5_KDB_REQUIRES_PRE_AUTH	0x00000080
#define KRB5_KDB_REQUIRES_HW_AUTH	0x00000100
#define	KRB5_KDB_REQUIRES_PWCHANGE	0x00000200
#define KRB5_KDB_DISALLOW_SVR		0x00001000
#define KRB5_KDB_PWCHANGE_SERVICE	0x00002000
#define KRB5_KDB_SUPPORT_DESMD5         0x00004000
#define	KRB5_KDB_NEW_PRINC		0x00008000

/* Creation flags */
#define KRB5_KDB_CREATE_BTREE		0x00000001
#define KRB5_KDB_CREATE_HASH		0x00000002

#if !defined(macintosh) && !defined(_MSDOS) && !defined(_WIN32)

/*
 * Note --- these structures cannot be modified without changing the
 * database version number in libkdb.a, but should be expandable by
 * adding new tl_data types.
 */
typedef struct _krb5_tl_data {
    struct _krb5_tl_data* tl_data_next;		/* NOT saved */
    krb5_int16 		  tl_data_type;		
    krb5_int16		  tl_data_length;	
    krb5_octet 	        * tl_data_contents;	
} krb5_tl_data;

/* 
 * If this ever changes up the version number and make the arrays be as
 * big as necessary.
 *
 * Currently the first type is the enctype and the second is the salt type.
 */
typedef struct _krb5_key_data {
    krb5_int16 		  key_data_ver;		/* Version */
    krb5_int16		  key_data_kvno;	/* Key Version */
    krb5_int16		  key_data_type[2];	/* Array of types */
    krb5_int16		  key_data_length[2];	/* Array of lengths */
    krb5_octet 	        * key_data_contents[2];	/* Array of pointers */
} krb5_key_data;

#define KRB5_KDB_V1_KEY_DATA_ARRAY	2	/* # of array elements */

typedef struct _krb5_keysalt {
    krb5_int16		  type;	
    krb5_data		  data;			/* Length, data */
} krb5_keysalt;

typedef struct _krb5_db_entry_new {
    krb5_magic 		  magic;		/* NOT saved */
    krb5_int16		  len;			
    krb5_flags 		  attributes;
    krb5_deltat		  max_life;
    krb5_deltat		  max_renewable_life;
    krb5_timestamp 	  expiration;	  	/* When the client expires */
    krb5_timestamp 	  pw_expiration;  	/* When its passwd expires */
    krb5_timestamp 	  last_success;		/* Last successful passwd */
    krb5_timestamp 	  last_failed;		/* Last failed passwd attempt */
    krb5_kvno 	 	  fail_auth_count; 	/* # of failed passwd attempt */
    krb5_int16 		  n_tl_data;
    krb5_int16 		  n_key_data;
    krb5_int16		  e_length;		/* Length of extra data */
    krb5_octet		* e_data;		/* Extra data to be saved */

    krb5_principal 	  princ;		/* Length, data */	
    krb5_tl_data	* tl_data;		/* Linked list */
    krb5_key_data       * key_data;		/* Array */
} krb5_db_entry;

#define	KRB5_KDB_MAGIC_NUMBER		0xdbdbdbdb
#define KRB5_KDB_V1_BASE_LENGTH		38
  
#define KRB5_TL_LAST_PWD_CHANGE		0x0001
#define KRB5_TL_MOD_PRINC		0x0002
#define KRB5_TL_KADM_DATA		0x0003
#define KRB5_TL_KADM5_E_DATA		0x0004
#define KRB5_TL_RB1_CHALLENGE		0x0005
#ifdef SECURID
#define KRB5_TL_SECURID_STATE           0x0006
#endif /* SECURID */
    
/*
 * Determines the number of failed KDC requests before DISALLOW_ALL_TIX is set
 * on the principal.
 */
#define KRB5_MAX_FAIL_COUNT		5

/* XXX depends on knowledge of krb5_parse_name() formats */
#define KRB5_KDB_M_NAME		"K/M"	/* Kerberos/Master */

/* prompts used by default when reading the KDC password from the keyboard. */
#define KRB5_KDC_MKEY_1	"Enter KDC database master key:"
#define KRB5_KDC_MKEY_2	"Re-enter KDC database master key to verify:"

extern char *krb5_mkey_pwd_prompt1;
extern char *krb5_mkey_pwd_prompt2;

/*
 * These macros specify the encoding of data within the database.
 *
 * Data encoding is little-endian.
 */
#define	krb5_kdb_decode_int16(cp, i16)	\
	*((krb5_int16 *) &(i16)) = (((krb5_int16) ((unsigned char) (cp)[0]))| \
			      ((krb5_int16) ((unsigned char) (cp)[1]) << 8))
#define	krb5_kdb_decode_int32(cp, i32)	\
	*((krb5_int32 *) &(i32)) = (((krb5_int32) ((unsigned char) (cp)[0]))| \
			      ((krb5_int32) ((unsigned char) (cp)[1]) << 8) | \
			      ((krb5_int32) ((unsigned char) (cp)[2]) << 16)| \
			      ((krb5_int32) ((unsigned char) (cp)[3]) << 24))
#define	krb5_kdb_encode_int16(i16, cp)	\
	{							\
	    (cp)[0] = (unsigned char) ((i16) & 0xff);		\
	    (cp)[1] = (unsigned char) (((i16) >> 8) & 0xff);	\
	}
#define	krb5_kdb_encode_int32(i32, cp)	\
	{							\
	    (cp)[0] = (unsigned char) ((i32) & 0xff);		\
	    (cp)[1] = (unsigned char) (((i32) >> 8) & 0xff);	\
	    (cp)[2] = (unsigned char) (((i32) >> 16) & 0xff);	\
	    (cp)[3] = (unsigned char) (((i32) >> 24) & 0xff);	\
	}

/* libkdb.spec */
krb5_error_code krb5_db_set_name
	KRB5_PROTOTYPE((krb5_context,
		   char * ));
krb5_error_code krb5_db_init
	KRB5_PROTOTYPE((krb5_context));
krb5_error_code krb5_db_fini
	KRB5_PROTOTYPE((krb5_context));
krb5_error_code krb5_db_get_age
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   time_t * ));
krb5_error_code krb5_db_create
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   krb5_int32 ));
krb5_error_code krb5_db_rename
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   char * ));
krb5_error_code krb5_db_get_principal
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal ,
		   krb5_db_entry *,
		   int *,
		   krb5_boolean * ));
void krb5_db_free_principal
	KRB5_PROTOTYPE((krb5_context,
		   krb5_db_entry *,
		   int  ));
krb5_error_code krb5_db_put_principal
	KRB5_PROTOTYPE((krb5_context,
		   krb5_db_entry *,
		   int * ));
krb5_error_code krb5_db_delete_principal
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   int * ));
krb5_error_code krb5_db_iterate
	KRB5_PROTOTYPE((krb5_context,
		   krb5_error_code (* ) KRB5_PROTOTYPE((krb5_pointer,
						   krb5_db_entry *)),
		   krb5_pointer ));
krb5_error_code krb5_db_verify_master_key
	KRB5_PROTOTYPE((krb5_context,
		   krb5_principal, 
		   krb5_keyblock *));
krb5_error_code krb5_db_store_mkey 
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   krb5_principal,
		   krb5_keyblock *));

krb5_error_code krb5_db_setup_mkey_name
	KRB5_PROTOTYPE((krb5_context,
		   const char *, 
		   const char *, 
		   char **, 
		   krb5_principal *));

krb5_error_code krb5_db_set_mkey
        KRB5_PROTOTYPE((krb5_context, krb5_keyblock *));

krb5_error_code krb5_db_get_mkey
        KRB5_PROTOTYPE((krb5_context, krb5_keyblock **));
krb5_error_code krb5_db_destroy 
	KRB5_PROTOTYPE((krb5_context,
		   char * ));
krb5_error_code krb5_db_lock
	KRB5_PROTOTYPE((krb5_context,
		   int ));
krb5_error_code krb5_db_unlock
	KRB5_PROTOTYPE((krb5_context));
krb5_error_code krb5_db_set_nonblocking
	KRB5_PROTOTYPE((krb5_context,
		   krb5_boolean,
		   krb5_boolean * ));
krb5_boolean krb5_db_set_lockmode
	KRB5_PROTOTYPE((krb5_context,
		   krb5_boolean));
krb5_error_code	krb5_db_fetch_mkey
	KRB5_PROTOTYPE((krb5_context,
		   krb5_principal, 
		   krb5_enctype, 
		   krb5_boolean,
		   krb5_boolean, 
		   char *,
		   krb5_data *, 
		   krb5_keyblock * ));

krb5_error_code krb5_db_open_database
	KRB5_PROTOTYPE((krb5_context));
krb5_error_code krb5_db_close_database
	KRB5_PROTOTYPE((krb5_context));

krb5_error_code krb5_dbekd_encrypt_key_data
	KRB5_PROTOTYPE((krb5_context,
		   const krb5_keyblock *,
		   const krb5_keyblock *,
		   const krb5_keysalt *,
		   int,
		   krb5_key_data *));
krb5_error_code krb5_dbekd_decrypt_key_data
	KRB5_PROTOTYPE((krb5_context,
		   const krb5_keyblock *,
		   const krb5_key_data *,
		   krb5_keyblock *,
		   krb5_keysalt *));
krb5_error_code krb5_dbe_create_key_data
	KRB5_PROTOTYPE((krb5_context,
			krb5_db_entry *));
krb5_error_code krb5_dbe_update_tl_data
	KRB5_PROTOTYPE((krb5_context,
			krb5_db_entry *,
			krb5_tl_data *));
krb5_error_code krb5_dbe_lookup_tl_data
	KRB5_PROTOTYPE((krb5_context,
			krb5_db_entry *,
			krb5_tl_data *));
krb5_error_code krb5_dbe_update_last_pwd_change
	KRB5_PROTOTYPE((krb5_context,
			krb5_db_entry *,
			krb5_timestamp));
krb5_error_code krb5_dbe_lookup_last_pwd_change
	KRB5_PROTOTYPE((krb5_context,
			krb5_db_entry *,
			krb5_timestamp *));
krb5_error_code krb5_dbe_update_mod_princ_data
	KRB5_PROTOTYPE((krb5_context,
			krb5_db_entry *,
			krb5_timestamp,
			krb5_const_principal));
krb5_error_code krb5_dbe_lookup_mod_princ_data
	KRB5_PROTOTYPE((krb5_context,
			krb5_db_entry *,
			krb5_timestamp *,
			krb5_principal *));
int krb5_encode_princ_dbkey
	KRB5_PROTOTYPE((krb5_context,
    		   krb5_data  *,
    		   krb5_const_principal));
void krb5_free_princ_dbkey
	KRB5_PROTOTYPE((krb5_context,
		   krb5_data *));
krb5_error_code krb5_encode_princ_contents
	KRB5_PROTOTYPE((krb5_context,
    		   krb5_data  *,
    		   krb5_db_entry *));
void krb5_free_princ_contents
	KRB5_PROTOTYPE((krb5_context,
		   krb5_data  *));
krb5_error_code krb5_decode_princ_contents
	KRB5_PROTOTYPE((krb5_context,
    		   krb5_data  *,
    		   krb5_db_entry *));
void krb5_dbe_free_contents
	KRB5_PROTOTYPE((krb5_context,
    		   krb5_db_entry *));

krb5_error_code krb5_dbe_find_enctype
	KRB5_PROTOTYPE((krb5_context,
			krb5_db_entry *,
			krb5_int32,
			krb5_int32,
			krb5_int32,
			krb5_key_data **));

krb5_error_code krb5_dbe_search_enctype
	KRB5_PROTOTYPE((krb5_context,
			krb5_db_entry *,
			krb5_int32 *,
			krb5_int32,
			krb5_int32,
			krb5_int32,
			krb5_key_data **));

struct __krb5_key_salt_tuple;

krb5_error_code krb5_dbe_cpw
        KRB5_PROTOTYPE((krb5_context,
			krb5_keyblock  *,
			struct __krb5_key_salt_tuple *,
			int,
			char *,
			int,
			krb5_boolean,
			krb5_db_entry *));
krb5_error_code krb5_dbe_apw
        KRB5_PROTOTYPE((krb5_context,
                   krb5_keyblock  *,
                   struct __krb5_key_salt_tuple *,
                   int,
                   char *,
                   krb5_db_entry *));
krb5_error_code krb5_dbe_crk
        KRB5_PROTOTYPE((krb5_context,
                   krb5_keyblock  *,
                   struct __krb5_key_salt_tuple *,
                   int,
		   krb5_boolean,
                   krb5_db_entry *));
krb5_error_code krb5_dbe_ark
        KRB5_PROTOTYPE((krb5_context,
                   krb5_keyblock  *,
                   struct __krb5_key_salt_tuple *,
                   int,
                   krb5_db_entry *));

krb5_error_code krb5_ser_db_context_init KRB5_PROTOTYPE((krb5_context));
 
#define KRB5_KDB_DEF_FLAGS	0

#ifdef KRB5_OLD_AND_KRUFTY
/* this is the same structure as krb5_keyblock, but with a different name to
   enable compile-time catching of programmer confusion between encrypted &
   decrypted keys in the database */

typedef struct _krb5_encrypted_keyblock {
    krb5_magic magic;
    short enctype;			/* XXX this is SO ugly --- proven */
    int length;
    krb5_octet *contents;
} krb5_encrypted_keyblock;

typedef struct _krb5_db_entry {
    krb5_magic magic;
    krb5_principal principal;
    krb5_encrypted_keyblock key;
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
    
    krb5_principal mod_name;
    krb5_timestamp mod_date;
    krb5_flags attributes;
    krb5_int32 salt_type:8,
 	       salt_length:24;
    krb5_octet *salt;
    krb5_encrypted_keyblock alt_key;
    krb5_int32 alt_salt_type:8,
 	       alt_salt_length:24;
    krb5_octet *alt_salt;
    
    krb5_int32 expansion[8];
} krb5_db_entry_OLD;

#endif	/* OLD_AND_KRUFTY */

/* This is now a structure that is private to the database backend. */
#ifdef notdef
#ifdef	KDB5_DISPATCH
/*
 * Database operation dispatch table.  This table determines the procedures
 * to be used to access the KDC database.  Replacement of this structure is
 * not supported.
 */
typedef struct _kdb5_dispatch_table {
    char *	kdb5_db_mech_name;
    char *	kdb5_db_index_ext;
    char *	kdb5_db_data_ext;
    char *	kdb5_db_lock_ext;
    DBM *	(*kdb5_dbm_open) KRB5_NPROTOTYPE((const char *, int, int));
    void	(*kdb5_dbm_close) KRB5_NPROTOTYPE((DBM *));
    datum	(*kdb5_dbm_fetch) KRB5_NPROTOTYPE((DBM *, datum));
    datum	(*kdb5_dbm_firstkey) KRB5_NPROTOTYPE((DBM *));
    datum	(*kdb5_dbm_nextkey) KRB5_NPROTOTYPE((DBM *));
    int		(*kdb5_dbm_delete) KRB5_NPROTOTYPE((DBM *, datum));
    int		(*kdb5_dbm_store) KRB5_NPROTOTYPE((DBM *, datum, datum, int));
    int		(*kdb5_dbm_dirfno) KRB5_NPROTOTYPE((DBM *));
    int		(*kdb5_dbm_pagfno) KRB5_NPROTOTYPE((DBM *));
} kdb5_dispatch_table;

krb5_error_code kdb5_db_set_dbops KRB5_PROTOTYPE((krb5_context,
						  kdb5_dispatch_table *));
#else
typedef	struct _kdb5_dispatch_table kdb5_dispatch_table;
#endif	/* KDB5_DISPATCH */
#endif /* notdef */
#endif /* !defined(macintosh) && !defined(_MSDOS) &&!defined(_WIN32) */
#endif /* KRB5_KDB5__ */
