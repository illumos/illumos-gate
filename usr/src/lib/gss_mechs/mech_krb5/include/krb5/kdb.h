/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#if !defined(_WIN32)

/*
 * Note --- these structures cannot be modified without changing the
 * database version number in libkdb.a, but should be expandable by
 * adding new tl_data types.
 */
typedef struct _krb5_tl_data {
    struct _krb5_tl_data* tl_data_next;		/* NOT saved */
    krb5_int16 		  tl_data_type;		
    krb5_ui_2		  tl_data_length;	
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
#if 0 
     /*
      * SUNW14resync (mech)
      * This has changed in the mech so we change it here also
      * prior to the admin resync.
      */
     krb5_ui_2      key_data_length[2];  Array of lengths
#endif
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
    krb5_ui_2		  len;			
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
    krb5_ui_2		  e_length;		/* Length of extra data */
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
#define KRB5_KDC_MKEY_1	"Enter KDC database master key"
#define KRB5_KDC_MKEY_2	"Re-enter KDC database master key to verify"

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
krb5_error_code krb5_db_set_name (krb5_context, char * );
krb5_error_code krb5_db_init (krb5_context);
krb5_error_code krb5_db_fini (krb5_context);
krb5_error_code krb5_db_get_age (krb5_context, char *, time_t * );
krb5_error_code krb5_db_create (krb5_context, char *, krb5_int32 );
krb5_error_code krb5_db_rename (krb5_context, char *, char * );
krb5_error_code krb5_db_get_principal (krb5_context, krb5_const_principal ,
				       krb5_db_entry *, int *,
				       krb5_boolean * );
void krb5_db_free_principal (krb5_context, krb5_db_entry *, int  );
krb5_error_code krb5_db_put_principal (krb5_context, krb5_db_entry *, int * );
krb5_error_code krb5_db_delete_principal (krb5_context, krb5_const_principal,
					  int * );
krb5_error_code krb5_db_iterate (krb5_context,
				 krb5_error_code (* ) (krb5_pointer,
						       krb5_db_entry *),
				 krb5_pointer);
krb5_error_code krb5_db_iterate_ext (krb5_context,
				     krb5_error_code (* ) (krb5_pointer,
					  	           krb5_db_entry *),
				     krb5_pointer, int, int);
krb5_error_code krb5_db_verify_master_key (krb5_context, krb5_principal, 
					   krb5_keyblock *);
krb5_error_code krb5_db_store_mkey (krb5_context, char *, krb5_principal,
				    krb5_keyblock *);

krb5_error_code krb5_db_setup_mkey_name (krb5_context, const char *, 
					 const char *, char **,
					 krb5_principal *);

krb5_error_code krb5_db_set_mkey (krb5_context, krb5_keyblock *);

krb5_error_code krb5_db_get_mkey (krb5_context, krb5_keyblock **);
krb5_error_code krb5_db_destroy (krb5_context, char * );
krb5_error_code krb5_db_lock (krb5_context, int );
krb5_error_code krb5_db_unlock (krb5_context);
krb5_error_code krb5_db_set_nonblocking (krb5_context, krb5_boolean,
					 krb5_boolean * );
krb5_boolean krb5_db_set_lockmode (krb5_context, krb5_boolean);
krb5_error_code	krb5_db_fetch_mkey (krb5_context, krb5_principal, krb5_enctype,
				    krb5_boolean, krb5_boolean, char *,
				    krb5_data *, 
				    krb5_keyblock * );

krb5_error_code krb5_db_open_database (krb5_context);
krb5_error_code krb5_db_close_database (krb5_context);

krb5_error_code krb5_dbekd_encrypt_key_data (krb5_context,
					     const krb5_keyblock *,
					     const krb5_keyblock *,
					     const krb5_keysalt *,
					     int,
					     krb5_key_data *);
krb5_error_code krb5_dbekd_decrypt_key_data (krb5_context,
					     const krb5_keyblock *,
					     const krb5_key_data *,
					     krb5_keyblock *,
					     krb5_keysalt *);
krb5_error_code krb5_dbe_create_key_data (krb5_context,
					  krb5_db_entry *);
krb5_error_code krb5_dbe_update_tl_data (krb5_context,
					 krb5_db_entry *,
					 krb5_tl_data *);
krb5_error_code krb5_dbe_lookup_tl_data (krb5_context,
					 krb5_db_entry *,
					 krb5_tl_data *);
krb5_error_code krb5_dbe_update_last_pwd_change (krb5_context,
						 krb5_db_entry *,
						 krb5_timestamp);
krb5_error_code krb5_dbe_lookup_last_pwd_change (krb5_context,
						 krb5_db_entry *,
						 krb5_timestamp *);
krb5_error_code krb5_dbe_update_mod_princ_data (krb5_context,
						krb5_db_entry *,
						krb5_timestamp,
						krb5_const_principal);
krb5_error_code krb5_dbe_lookup_mod_princ_data (krb5_context,
						krb5_db_entry *,
						krb5_timestamp *,
						krb5_principal *);
int krb5_encode_princ_dbkey (krb5_context, krb5_data  *, krb5_const_principal);
void krb5_free_princ_dbkey (krb5_context, krb5_data *);
krb5_error_code krb5_encode_princ_contents (krb5_context, krb5_data *,
					    krb5_db_entry *);
void krb5_free_princ_contents (krb5_context, krb5_data  *);
krb5_error_code krb5_decode_princ_contents (krb5_context, krb5_data  *,
					    krb5_db_entry *);
void krb5_dbe_free_contents (krb5_context, krb5_db_entry *);

krb5_error_code krb5_dbe_find_enctype (krb5_context, krb5_db_entry *,
				       krb5_int32,
				       krb5_int32,
				       krb5_int32,
				       krb5_key_data **);

krb5_error_code krb5_dbe_search_enctype (krb5_context,
					 krb5_db_entry *,
					 krb5_int32 *,
					 krb5_int32,
					 krb5_int32,
					 krb5_int32,
					 krb5_key_data **);

struct __krb5_key_salt_tuple;

krb5_error_code krb5_dbe_cpw (krb5_context,
			      krb5_keyblock  *,
			      struct __krb5_key_salt_tuple *,
			      int,
			      char *,
			      int,
			      krb5_boolean,
			      krb5_db_entry *);
krb5_error_code krb5_dbe_apw (krb5_context,
			      krb5_keyblock  *,
			      struct __krb5_key_salt_tuple *,
			      int,
			      char *,
			      krb5_db_entry *);
krb5_error_code krb5_dbe_crk (krb5_context,
			      krb5_keyblock  *,
			      struct __krb5_key_salt_tuple *,
			      int,
			      krb5_boolean,
			      krb5_db_entry *);
krb5_error_code krb5_dbe_ark (krb5_context,
			      krb5_keyblock  *,
			      struct __krb5_key_salt_tuple *,
			      int,
			      krb5_db_entry *);

krb5_error_code krb5_ser_db_context_init (krb5_context);
 
#define KRB5_KDB_DEF_FLAGS	0

#endif /* !defined(_WIN32) */
#endif /* KRB5_KDB5__ */
