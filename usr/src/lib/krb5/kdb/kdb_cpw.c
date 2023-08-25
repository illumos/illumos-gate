/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/kdb/kdb_cpw.c
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
#include "kdb.h"
#include <stdio.h>
#include <errno.h>

static int
get_key_data_kvno(context, count, data)
    krb5_context	  context;
    int			  count;
    krb5_key_data	* data;
{
    int i, kvno;
    /* Find last key version number */
    for (kvno = i = 0; i < count; i++) {
	if (kvno < data[i].key_data_kvno) {
	    kvno = data[i].key_data_kvno;
	}
    }
    return(kvno);
}

static void
cleanup_key_data(context, count, data)
    krb5_context	  context;
    int			  count;
    krb5_key_data	* data;
{
    int i, j;

    /* If data is NULL, count is always 0 */
    if (data == NULL) return;

    for (i = 0; i < count; i++) {
	for (j = 0; j < data[i].key_data_ver; j++) {
	    if (data[i].key_data_length[j]) {
	    	krb5_db_free(context, data[i].key_data_contents[j]);
	    }
	}
    }
    krb5_db_free(context, data);
}

static krb5_error_code
add_key_rnd(context, master_key, ks_tuple, ks_tuple_count, db_entry, kvno)
    krb5_context	  context;
    krb5_keyblock       * master_key;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    krb5_db_entry	* db_entry;
    int			  kvno;
{
    krb5_principal	  krbtgt_princ;
    krb5_keyblock	  key;
    krb5_db_entry	  krbtgt_entry;
    krb5_boolean	  more;
    int			  max_kvno, one, i, j, k;
    krb5_error_code	  retval;
    krb5_key_data         tmp_key_data;
    krb5_key_data        *tptr;

    memset( &tmp_key_data, 0, sizeof(tmp_key_data));


    retval = krb5_build_principal_ext(context, &krbtgt_princ,
				      db_entry->princ->realm.length,
				      db_entry->princ->realm.data,
				      KRB5_TGS_NAME_SIZE,
				      KRB5_TGS_NAME,
				      db_entry->princ->realm.length,
				      db_entry->princ->realm.data,
				      0);
    if (retval)
	return retval;

    /* Get tgt from database */
    retval = krb5_db_get_principal(context, krbtgt_princ, &krbtgt_entry,
				   &one, &more);
    krb5_free_principal(context, krbtgt_princ); /* don't need it anymore */
    if (retval)
	return(retval);
    if ((one > 1) || (more)) {
	krb5_db_free_principal(context, &krbtgt_entry, one);
	return KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
    }
    if (!one)
	return KRB5_KDB_NOENTRY;

    /* Get max kvno */
    for (max_kvno = j = 0; j < krbtgt_entry.n_key_data; j++) {
	 if (max_kvno < krbtgt_entry.key_data[j].key_data_kvno) {
	     max_kvno = krbtgt_entry.key_data[j].key_data_kvno;
	}
    }

    for (i = 0; i < ks_tuple_count; i++) {
	krb5_boolean similar;

	similar = 0;

	/*
	 * We could use krb5_keysalt_iterate to replace this loop, or use
	 * krb5_keysalt_is_present for the loop below, but we want to avoid
	 * circular library dependencies.
	 */
	for (j = 0; j < i; j++) {
	    if ((retval = krb5_c_enctype_compare(context,
						 ks_tuple[i].ks_enctype,
						 ks_tuple[j].ks_enctype,
						 &similar)))
		return(retval);

	    if (similar)
		break;
	}

	if (similar)
	    continue;

        if ((retval = krb5_dbe_create_key_data(context, db_entry)))
	    goto add_key_rnd_err;

	/* there used to be code here to extract the old key, and derive
	   a new key from it.  Now that there's a unified prng, that isn't
	   necessary. */

	/* make new key */
	if ((retval = krb5_c_make_random_key(context, ks_tuple[i].ks_enctype,
					     &key)))
	    goto add_key_rnd_err;


	/* db library will free this. Since, its a so, it could actually be using different memory management
	   function. So, its better if the memory is allocated by the db's malloc. So, a temporary memory is used
	   here which will later be copied to the db_entry */
    	retval = krb5_dbekd_encrypt_key_data(context, master_key,
					     &key, NULL, kvno,
					     &tmp_key_data);

	krb5_free_keyblock_contents(context, &key);
	if( retval )
	    goto add_key_rnd_err;

	tptr = &db_entry->key_data[db_entry->n_key_data-1];

	tptr->key_data_ver = tmp_key_data.key_data_ver;
	tptr->key_data_kvno = tmp_key_data.key_data_kvno;

	for( k = 0; k < tmp_key_data.key_data_ver; k++ )
	{
	    tptr->key_data_type[k] = tmp_key_data.key_data_type[k];
	    tptr->key_data_length[k] = tmp_key_data.key_data_length[k];
	    if( tmp_key_data.key_data_contents[k] )
	    {
		tptr->key_data_contents[k] = krb5_db_alloc(context, NULL, tmp_key_data.key_data_length[k]);
		if( tptr->key_data_contents[k] == NULL )
		{
		    cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
		    db_entry->key_data = NULL;
		    db_entry->n_key_data = 0;
		    retval = ENOMEM;
		    goto add_key_rnd_err;
		}
		memcpy( tptr->key_data_contents[k], tmp_key_data.key_data_contents[k], tmp_key_data.key_data_length[k]);

		memset( tmp_key_data.key_data_contents[k], 0, tmp_key_data.key_data_length[k]);
		free( tmp_key_data.key_data_contents[k] );
		tmp_key_data.key_data_contents[k] = NULL;
	    }
	}

    }

add_key_rnd_err:
    krb5_db_free_principal(context, &krbtgt_entry, one);

    for( i = 0; i < tmp_key_data.key_data_ver; i++ )
    {
	if( tmp_key_data.key_data_contents[i] )
	{
	    memset( tmp_key_data.key_data_contents[i], 0, tmp_key_data.key_data_length[i]);
	    free( tmp_key_data.key_data_contents[i] );
	}
    }
    return(retval);
}

/*
 * Change random key for a krb5_db_entry
 * Assumes the max kvno
 *
 * As a side effect all old keys are nuked if keepold is false.
 */
krb5_error_code
krb5_dbe_crk(context, master_key, ks_tuple, ks_tuple_count, keepold, db_entry)
    krb5_context	  context;
    krb5_keyblock       * master_key;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    krb5_boolean	  keepold;
    krb5_db_entry	* db_entry;
{
    int 		  key_data_count;
    int			  n_new_key_data;
    krb5_key_data 	* key_data;
    krb5_error_code	  retval;
    int			  kvno;
    int			  i;

    /* First save the old keydata */
    kvno = get_key_data_kvno(context, db_entry->n_key_data, db_entry->key_data);
    key_data_count = db_entry->n_key_data;
    key_data = db_entry->key_data;
    db_entry->key_data = NULL;
    db_entry->n_key_data = 0;

    /* increment the kvno */
    kvno++;

    retval = add_key_rnd(context, master_key, ks_tuple,
			 ks_tuple_count, db_entry, kvno);
    if (retval) {
	cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
	db_entry->n_key_data = key_data_count;
	db_entry->key_data = key_data;
    } else if (keepold) {
	n_new_key_data = db_entry->n_key_data;
	for (i = 0; i < key_data_count; i++) {
	    retval = krb5_dbe_create_key_data(context, db_entry);
	    if (retval) {
		cleanup_key_data(context, db_entry->n_key_data,
				 db_entry->key_data);
		break;
	    }
	    db_entry->key_data[i+n_new_key_data] = key_data[i];
	    memset(&key_data[i], 0, sizeof(krb5_key_data));
	}
	krb5_db_free(context, key_data); /* we moved the cotents to new memory. But, the original block which contained the data */
    } else {
	cleanup_key_data(context, key_data_count, key_data);
    }
    return(retval);
}

/*
 * Add random key for a krb5_db_entry
 * Assumes the max kvno
 *
 * As a side effect all old keys older than the max kvno are nuked.
 */
krb5_error_code
krb5_dbe_ark(context, master_key, ks_tuple, ks_tuple_count, db_entry)
    krb5_context	  context;
    krb5_keyblock       * master_key;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    krb5_db_entry	* db_entry;
{
    int 		  key_data_count;
    krb5_key_data 	* key_data;
    krb5_error_code	  retval;
    int			  kvno;
    int			  i;

    /* First save the old keydata */
    kvno = get_key_data_kvno(context, db_entry->n_key_data, db_entry->key_data);
    key_data_count = db_entry->n_key_data;
    key_data = db_entry->key_data;
    db_entry->key_data = NULL;
    db_entry->n_key_data = 0;

    /* increment the kvno */
    kvno++;

    if ((retval = add_key_rnd(context, master_key, ks_tuple,
			     ks_tuple_count, db_entry, kvno))) {
	cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
	db_entry->n_key_data = key_data_count;
	db_entry->key_data = key_data;
    } else {
	/* Copy keys with key_data_kvno == kvno - 1 ( = old kvno ) */
	for (i = 0; i < key_data_count; i++) {
	    if (key_data[i].key_data_kvno == (kvno - 1)) {
		if ((retval = krb5_dbe_create_key_data(context, db_entry))) {
		    cleanup_key_data(context, db_entry->n_key_data,
				     db_entry->key_data);
		    break;
		}
		/* We should decrypt/re-encrypt the data to use the same mkvno*/
		db_entry->key_data[db_entry->n_key_data - 1] = key_data[i];
		memset(&key_data[i], 0, sizeof(krb5_key_data));
	    }
	}
	cleanup_key_data(context, key_data_count, key_data);
    }
    return(retval);
}

/*
 * Add key_data for a krb5_db_entry
 * If passwd is NULL the assumes that the caller wants a random password.
 */
static krb5_error_code
add_key_pwd(context, master_key, ks_tuple, ks_tuple_count, passwd,
	    db_entry, kvno)
    krb5_context	  context;
    krb5_keyblock       * master_key;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    char 		* passwd;
    krb5_db_entry	* db_entry;
    int			  kvno;
{
    krb5_error_code	  retval;
    krb5_keysalt	  key_salt;
    krb5_keyblock	  key;
    krb5_data	  	  pwd;
    int			  i, j, k;
    krb5_key_data         tmp_key_data;
    krb5_key_data        *tptr;

    memset( &tmp_key_data, 0, sizeof(tmp_key_data));

    retval = 0;

    for (i = 0; i < ks_tuple_count; i++) {
	krb5_boolean similar;

	similar = 0;

	/*
	 * We could use krb5_keysalt_iterate to replace this loop, or use
	 * krb5_keysalt_is_present for the loop below, but we want to avoid
	 * circular library dependencies.
	 */
	for (j = 0; j < i; j++) {
	    if ((retval = krb5_c_enctype_compare(context,
						 ks_tuple[i].ks_enctype,
						 ks_tuple[j].ks_enctype,
						 &similar)))
		return(retval);

	    if (similar &&
		(ks_tuple[j].ks_salttype == ks_tuple[i].ks_salttype))
		break;
	}

	if (j < i)
	    continue;

	if ((retval = krb5_dbe_create_key_data(context, db_entry)))
	    return(retval);

	/* Convert password string to key using appropriate salt */
	switch (key_salt.type = ks_tuple[i].ks_salttype) {
    	case KRB5_KDB_SALTTYPE_ONLYREALM: {
            krb5_data * saltdata;
            if ((retval = krb5_copy_data(context, krb5_princ_realm(context,
					      db_entry->princ), &saltdata)))
	 	return(retval);

	    key_salt.data = *saltdata;
	    krb5_xfree(saltdata);
	}
		break;
    	case KRB5_KDB_SALTTYPE_NOREALM:
            if ((retval=krb5_principal2salt_norealm(context, db_entry->princ,
						    &key_salt.data)))
		return(retval);
            break;
	case KRB5_KDB_SALTTYPE_NORMAL:
            if ((retval = krb5_principal2salt(context, db_entry->princ,
					      &key_salt.data)))
		return(retval);
            break;
    	case KRB5_KDB_SALTTYPE_V4:
            key_salt.data.length = 0;
            key_salt.data.data = 0;
            break;
    	case KRB5_KDB_SALTTYPE_AFS3: {
#if 0
            krb5_data * saltdata;
            if (retval = krb5_copy_data(context, krb5_princ_realm(context,
					db_entry->princ), &saltdata))
	 	return(retval);

	    key_salt.data = *saltdata;
	    key_salt.data.length = SALT_TYPE_AFS_LENGTH; /*length actually used below...*/
	    krb5_xfree(saltdata);
#else
	    /* Why do we do this? Well, the afs_mit_string_to_key needs to
	       use strlen, and the realm is not NULL terminated.... */
	    unsigned int slen =
		(*krb5_princ_realm(context,db_entry->princ)).length;
	    if(!(key_salt.data.data = (char *) malloc(slen+1)))
	        return ENOMEM;
	    key_salt.data.data[slen] = 0;
	    memcpy((char *)key_salt.data.data,
		   (char *)(*krb5_princ_realm(context,db_entry->princ)).data,
		   slen);
	    key_salt.data.length = SALT_TYPE_AFS_LENGTH; /*length actually used below...*/
#endif

	}
		break;
	default:
	    return(KRB5_KDB_BAD_SALTTYPE);
	}

    	pwd.data = passwd;
    	pwd.length = strlen(passwd);

	/* Solaris Kerberos */
	memset(&key, 0, sizeof (krb5_keyblock));

	/* AFS string to key will happen here */
	if ((retval = krb5_c_string_to_key(context, ks_tuple[i].ks_enctype,
					   &pwd, &key_salt.data, &key))) {
	     if (key_salt.data.data)
		  free(key_salt.data.data);
	     return(retval);
	}

	if (key_salt.data.length == SALT_TYPE_AFS_LENGTH)
	    key_salt.data.length =
	      krb5_princ_realm(context, db_entry->princ)->length;

	/* memory allocation to be done by db. So, use temporary block and later copy
	   it to the memory allocated by db */
	retval = krb5_dbekd_encrypt_key_data(context, master_key, &key,
					     (const krb5_keysalt *)&key_salt,
					     kvno, &tmp_key_data);
	if (key_salt.data.data)
	    free(key_salt.data.data);

	/* Solaris Kerberos */
	krb5_free_keyblock_contents(context, &key);

	if( retval )
	    return retval;

	tptr = &db_entry->key_data[db_entry->n_key_data-1];

	tptr->key_data_ver = tmp_key_data.key_data_ver;
	tptr->key_data_kvno = tmp_key_data.key_data_kvno;

	for( k = 0; k < tmp_key_data.key_data_ver; k++ )
	{
	    tptr->key_data_type[k] = tmp_key_data.key_data_type[k];
	    tptr->key_data_length[k] = tmp_key_data.key_data_length[k];
	    if( tmp_key_data.key_data_contents[k] )
	    {
		tptr->key_data_contents[k] = krb5_db_alloc(context, NULL, tmp_key_data.key_data_length[k]);
		if( tptr->key_data_contents[k] == NULL )
		{
		    cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
		    db_entry->key_data = NULL;
		    db_entry->n_key_data = 0;
		    retval = ENOMEM;
		    goto add_key_pwd_err;
		}
		memcpy( tptr->key_data_contents[k], tmp_key_data.key_data_contents[k], tmp_key_data.key_data_length[k]);

		memset( tmp_key_data.key_data_contents[k], 0, tmp_key_data.key_data_length[k]);
		free( tmp_key_data.key_data_contents[k] );
		tmp_key_data.key_data_contents[k] = NULL;
	    }
	}
    }
 add_key_pwd_err:
    for( i = 0; i < tmp_key_data.key_data_ver; i++ )
    {
	if( tmp_key_data.key_data_contents[i] )
	{
	    memset( tmp_key_data.key_data_contents[i], 0, tmp_key_data.key_data_length[i]);
	    free( tmp_key_data.key_data_contents[i] );
	}
    }

    return(retval);
}

/*
 * Change password for a krb5_db_entry
 * Assumes the max kvno
 *
 * As a side effect all old keys are nuked if keepold is false.
 */
krb5_error_code
krb5_dbe_def_cpw(context, master_key, ks_tuple, ks_tuple_count, passwd,
	     new_kvno, keepold, db_entry)
    krb5_context	  context;
    krb5_keyblock       * master_key;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    char 		* passwd;
    int			  new_kvno;
    krb5_boolean	  keepold;
    krb5_db_entry	* db_entry;
{
    int 		  key_data_count;
    int			  n_new_key_data;
    krb5_key_data 	* key_data;
    krb5_error_code	  retval;
    int			  old_kvno;
    int			  i;

    /* First save the old keydata */
    old_kvno = get_key_data_kvno(context, db_entry->n_key_data,
				 db_entry->key_data);
    key_data_count = db_entry->n_key_data;
    key_data = db_entry->key_data;
    db_entry->key_data = NULL;
    db_entry->n_key_data = 0;

    /* increment the kvno.  if the requested kvno is too small,
       increment the old kvno */
    if (new_kvno < old_kvno+1)
       new_kvno = old_kvno+1;

    retval = add_key_pwd(context, master_key, ks_tuple, ks_tuple_count,
			 passwd, db_entry, new_kvno);
    if (retval) {
	cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
	db_entry->n_key_data = key_data_count;
	db_entry->key_data = key_data;
    } else if (keepold) {
	n_new_key_data = db_entry->n_key_data;
	for (i = 0; i < key_data_count; i++) {
	    retval = krb5_dbe_create_key_data(context, db_entry);
	    if (retval) {
		cleanup_key_data(context, db_entry->n_key_data,
				 db_entry->key_data);
		break;
	    }
	    db_entry->key_data[i+n_new_key_data] = key_data[i];
	    memset(&key_data[i], 0, sizeof(krb5_key_data));
	}
	krb5_db_free( context, key_data );
    } else {
	cleanup_key_data(context, key_data_count, key_data);
    }
    return(retval);
}

/*
 * Add password for a krb5_db_entry
 * Assumes the max kvno
 *
 * As a side effect all old keys older than the max kvno are nuked.
 */
krb5_error_code
krb5_dbe_apw(context, master_key, ks_tuple, ks_tuple_count, passwd, db_entry)
    krb5_context	  context;
    krb5_keyblock       * master_key;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    char 		* passwd;
    krb5_db_entry	* db_entry;
{
    int 		  key_data_count;
    krb5_key_data 	* key_data;
    krb5_error_code	  retval;
    int			  old_kvno, new_kvno;
    int			  i;

    /* First save the old keydata */
    old_kvno = get_key_data_kvno(context, db_entry->n_key_data,
				 db_entry->key_data);
    key_data_count = db_entry->n_key_data;
    key_data = db_entry->key_data;
    db_entry->key_data = NULL;
    db_entry->n_key_data = 0;

    /* increment the kvno */
    new_kvno = old_kvno+1;

    if ((retval = add_key_pwd(context, master_key, ks_tuple, ks_tuple_count,
			     passwd, db_entry, new_kvno))) {
	cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
	db_entry->n_key_data = key_data_count;
	db_entry->key_data = key_data;
    } else {
	/* Copy keys with key_data_kvno == old_kvno */
	for (i = 0; i < key_data_count; i++) {
	    if (key_data[i].key_data_kvno == old_kvno) {
		if ((retval = krb5_dbe_create_key_data(context, db_entry))) {
		    cleanup_key_data(context, db_entry->n_key_data,
				     db_entry->key_data);
		    break;
		}
		/* We should decrypt/re-encrypt the data to use the same mkvno*/
		db_entry->key_data[db_entry->n_key_data - 1] = key_data[i];
		memset(&key_data[i], 0, sizeof(krb5_key_data));
	    }
	}
	cleanup_key_data(context, key_data_count, key_data);
    }
    return(retval);
}


