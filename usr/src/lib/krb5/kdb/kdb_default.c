/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/kdb_helper.c
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

#include "k5-int.h"
#include "kdb.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <libintl.h>


/*
 * Given a particular enctype and optional salttype and kvno, find the
 * most appropriate krb5_key_data entry of the database entry.
 *
 * If stype or kvno is negative, it is ignored.
 * If kvno is 0 get the key which is maxkvno for the princ and matches
 * the other attributes.
 */
krb5_error_code
krb5_dbe_def_search_enctype(kcontext, dbentp, start, ktype, stype, kvno, kdatap)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_int32		*start;
    krb5_int32		ktype;
    krb5_int32		stype;
    krb5_int32		kvno;
    krb5_key_data	**kdatap;
{
    int			i, idx;
    int			maxkvno;
    krb5_key_data	*datap;
    krb5_error_code	ret;

    ret = 0;
    if (kvno == -1 && stype == -1 && ktype == -1)
	kvno = 0;

    if (kvno == 0) { 
	/* Get the max key version */
	for (i = 0; i < dbentp->n_key_data; i++) {
	    if (kvno < dbentp->key_data[i].key_data_kvno) { 
		kvno = dbentp->key_data[i].key_data_kvno;
	    }
	}
    }

    maxkvno = -1;
    datap = (krb5_key_data *) NULL;
    for (i = *start; i < dbentp->n_key_data; i++) {
        krb5_boolean    similar;
        krb5_int32      db_stype;

	ret = 0;
	if (dbentp->key_data[i].key_data_ver > 1) {
	    db_stype = dbentp->key_data[i].key_data_type[1];
	} else {
	    db_stype = KRB5_KDB_SALTTYPE_NORMAL;
	}

	/*
	 * Filter out non-permitted enctypes.
	 */
	if (!krb5_is_permitted_enctype(kcontext,
				       dbentp->key_data[i].key_data_type[0])) {
	    ret = KRB5_KDB_NO_PERMITTED_KEY;
	    continue;
	}
	

	if (ktype > 0) {
	    if ((ret = krb5_c_enctype_compare(kcontext, (krb5_enctype) ktype,
					      dbentp->key_data[i].key_data_type[0],
					      &similar)))

		return(ret);
	}

	if (((ktype <= 0) || similar) &&
	    ((db_stype == stype) || (stype < 0))) {
	    if (kvno >= 0) {
		if (kvno == dbentp->key_data[i].key_data_kvno) {
		    datap = &dbentp->key_data[i];
		    idx = i;
		    maxkvno = kvno;
		    break;
		}
	    } else {
		if (dbentp->key_data[i].key_data_kvno > maxkvno) {
		    maxkvno = dbentp->key_data[i].key_data_kvno;
		    datap = &dbentp->key_data[i];
		    idx = i;
		}
	    }
	}
    }
    if (maxkvno < 0)
	return ret ? ret : KRB5_KDB_NO_MATCHING_KEY;
    *kdatap = datap;
    *start = idx+1;
    return 0;
}
    
/*
 *  kdb default functions. Ideally, some other file should have this functions. For now, TBD.
 */
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

krb5_error_code
krb5_def_store_mkey(context, keyfile, mname, key, master_pwd)
    krb5_context context;
    char *keyfile;
    krb5_principal mname;
    krb5_keyblock *key;
    char *master_pwd;
{
    FILE *kf;
    krb5_error_code retval = 0;
    krb5_ui_2 enctype;
    char defkeyfile[MAXPATHLEN+1];
    krb5_data *realm = krb5_princ_realm(context, mname);
#if HAVE_UMASK
    mode_t oumask;
#endif

    if (!keyfile) {
	(void) strcpy(defkeyfile, DEFAULT_KEYFILE_STUB);
	(void) strncat(defkeyfile, realm->data,
		       min(sizeof(defkeyfile)-sizeof(DEFAULT_KEYFILE_STUB)-1,
			   realm->length));
	defkeyfile[sizeof(defkeyfile) - 1] = '\0';
	keyfile = defkeyfile;
    }

#if HAVE_UMASK
    oumask = umask(077);
#endif
#ifdef ANSI_STDIO
    /* Solaris Kerberos: using F to deal with 256 open file limit */
    if (!(kf = fopen(keyfile, "wbF")))
#else
    if (!(kf = fopen(keyfile, "wF")))
#endif
    {
	int e = errno;
#if HAVE_UMASK
	(void) umask(oumask);
#endif
	krb5_set_error_message (context, e,
				gettext("%s accessing file '%s'"),
				error_message (e), keyfile);
	return e;
    }
    enctype = key->enctype;
    if ((fwrite((krb5_pointer) &enctype,
		2, 1, kf) != 1) ||
	(fwrite((krb5_pointer) &key->length,
		sizeof(key->length), 1, kf) != 1) ||
	(fwrite((krb5_pointer) key->contents,
		sizeof(key->contents[0]), (unsigned) key->length, 
		kf) != key->length)) {
	retval = errno;
	(void) fclose(kf);
    }
    if (fclose(kf) == EOF)
	retval = errno;
#if HAVE_UMASK
    (void) umask(oumask);
#endif
    return retval;
}


krb5_error_code
krb5_db_def_fetch_mkey( krb5_context   context,
			krb5_principal mname,
			krb5_keyblock *key,
			int           *kvno,
			char          *db_args)
{
    krb5_error_code retval;
    krb5_ui_2 enctype;
    char defkeyfile[MAXPATHLEN+1];
    krb5_data *realm = krb5_princ_realm(context, mname);
    FILE *kf = NULL;

    retval = 0;
    key->magic = KV5M_KEYBLOCK;
    (void) strcpy(defkeyfile, DEFAULT_KEYFILE_STUB);
    (void) strncat(defkeyfile, realm->data,
		   min(sizeof(defkeyfile)-sizeof(DEFAULT_KEYFILE_STUB)-1,
		       realm->length));
    defkeyfile[sizeof(defkeyfile) - 1] = '\0';
	
#ifdef ANSI_STDIO
    /* Solaris Kerberos: using F to deal with 256 open file limit */
    if (!(kf = fopen((db_args) ? db_args : defkeyfile, "rbF")))
#else
    if (!(kf = fopen((db_args) ? db_args : defkeyfile, "rF")))
#endif
	return KRB5_KDB_CANTREAD_STORED;

    if (fread((krb5_pointer) &enctype, 2, 1, kf) != 1) {
	retval = KRB5_KDB_CANTREAD_STORED;
	goto errout;
    }

    if (key->enctype == ENCTYPE_UNKNOWN)
	key->enctype = enctype;
    else if (enctype != key->enctype) {
	retval = KRB5_KDB_BADSTORED_MKEY;
	goto errout;
    }

    if (fread((krb5_pointer) &key->length,
	      sizeof(key->length), 1, kf) != 1) {
	retval = KRB5_KDB_CANTREAD_STORED;
	goto errout;
    }

    if (!key->length || ((int) key->length) < 0) {
	retval = KRB5_KDB_BADSTORED_MKEY;
	goto errout;
    }
	
    if (!(key->contents = (krb5_octet *)malloc(key->length))) {
	retval = ENOMEM;
	goto errout;
    }

    if (fread((krb5_pointer) key->contents,
	      sizeof(key->contents[0]), key->length, kf) 
	!= key->length) {
	retval = KRB5_KDB_CANTREAD_STORED;
	memset(key->contents, 0,  key->length);
	free(key->contents);
	key->contents = 0;
    } else
	retval = 0;

    *kvno = 0;

 errout:
    (void) fclose(kf);
    return retval;

}


krb5_error_code
krb5_def_verify_master_key(context, mprinc, mkey)
    krb5_context context;
    krb5_principal mprinc;
    krb5_keyblock *mkey;
{
    krb5_error_code retval;
    krb5_db_entry master_entry;
    int nprinc;
    krb5_boolean more;
    krb5_keyblock tempkey;

    nprinc = 1;
    if ((retval = krb5_db_get_principal(context, mprinc,
					&master_entry, &nprinc, &more)))
	return(retval);
	
    if (nprinc != 1) {
	if (nprinc)
	    krb5_db_free_principal(context, &master_entry, nprinc);
	return(KRB5_KDB_NOMASTERKEY);
    } else if (more) {
	krb5_db_free_principal(context, &master_entry, nprinc);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    }	

    if ((retval = krb5_dbekd_decrypt_key_data(context, mkey, 
					      &master_entry.key_data[0],
					      &tempkey, NULL))) {
	krb5_db_free_principal(context, &master_entry, nprinc);
	return retval;
    }

    if (mkey->length != tempkey.length ||
	memcmp((char *)mkey->contents,
	       (char *)tempkey.contents,mkey->length)) {
	retval = KRB5_KDB_BADMASTERKEY;
    }

    memset((char *)tempkey.contents, 0, tempkey.length);
    krb5_xfree(tempkey.contents);
    krb5_db_free_principal(context, &master_entry, nprinc);
    
    return retval;
}


krb5_error_code kdb_def_set_mkey ( krb5_context kcontext,
				   char *pwd,
				   krb5_keyblock *key )
{
    /* printf("default set master key\n"); */
    return 0;
}

krb5_error_code kdb_def_get_mkey ( krb5_context kcontext,
				   krb5_keyblock **key )
{
    /* printf("default get master key\n"); */
    return 0;
}

krb5_error_code krb5_def_promote_db (krb5_context kcontext,
				     char *s, char **args)
{
    /* printf("default promote_db\n"); */
    return KRB5_PLUGIN_OP_NOTSUPP;
}
