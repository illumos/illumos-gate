#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/kdb_xdr.c
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
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define safe_realloc(p,n) ((p)?(realloc(p,n)):(malloc(n)))

krb5_error_code
krb5_dbe_create_key_data(context, entry) 
    krb5_context	  context;
    krb5_db_entry	* entry;
{
    if ((entry->key_data =
	 (krb5_key_data *) safe_realloc(entry->key_data,
					(sizeof(krb5_key_data)*
					 (entry->n_key_data + 1)))) == NULL)
	return(ENOMEM);
	

    memset(entry->key_data + entry->n_key_data, 0, sizeof(krb5_key_data));
    entry->n_key_data++;

    return 0;
}

krb5_error_code
krb5_dbe_update_tl_data(context, entry, new_tl_data)
    krb5_context          context;
    krb5_db_entry       * entry;
    krb5_tl_data	* new_tl_data;
{
    krb5_tl_data        * tl_data;
    krb5_octet          * tmp;

    /* copy the new data first, so we can fail cleanly if malloc()
       fails */

    if ((tmp = (krb5_octet *) malloc(new_tl_data->tl_data_length)) == NULL)
	return(ENOMEM);

    /* Find an existing entry of the specified type and point at
       it, or NULL if not found */

    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next)
	if (tl_data->tl_data_type == new_tl_data->tl_data_type)
	    break;

    /* if necessary, chain a new record in the beginning and point at it */

    if (!tl_data) {
	if ((tl_data = (krb5_tl_data *) calloc(1, sizeof(krb5_tl_data)))
	    == NULL) {
	    free(tmp);
	    return(ENOMEM);
	}
	tl_data->tl_data_next = entry->tl_data;
	entry->tl_data = tl_data;
	entry->n_tl_data++;
    }

    /* fill in the record */

    if (tl_data->tl_data_contents)
	free(tl_data->tl_data_contents);

    tl_data->tl_data_type = new_tl_data->tl_data_type;
    tl_data->tl_data_length = new_tl_data->tl_data_length;
    tl_data->tl_data_contents = tmp;
    memcpy(tmp, new_tl_data->tl_data_contents, tl_data->tl_data_length);

    return(0);
}

krb5_error_code
krb5_dbe_lookup_tl_data(context, entry, ret_tl_data)
    krb5_context          context;
    krb5_db_entry       * entry;
    krb5_tl_data        * ret_tl_data;
{
    krb5_tl_data *tl_data;

    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next) {
        if (tl_data->tl_data_type == ret_tl_data->tl_data_type) {
	    *ret_tl_data = *tl_data;
	    return(0);
	}
    }

    /* if the requested record isn't found, return zero bytes.
       if it ever means something to have a zero-length tl_data,
       this code and its callers will have to be changed */

    ret_tl_data->tl_data_length = 0;
    ret_tl_data->tl_data_contents = NULL;
    return(0);
}

krb5_error_code
krb5_dbe_update_last_pwd_change(context, entry, stamp)
    krb5_context          context;
    krb5_db_entry       * entry;
    krb5_timestamp	  stamp;
{
    krb5_tl_data        tl_data;
    krb5_octet          buf[4]; /* this is the encoded size of an int32 */

    tl_data.tl_data_type = KRB5_TL_LAST_PWD_CHANGE;
    tl_data.tl_data_length = sizeof(buf); 
    krb5_kdb_encode_int32((krb5_int32) stamp, buf);
    tl_data.tl_data_contents = buf;

    return(krb5_dbe_update_tl_data(context, entry, &tl_data));
}

krb5_error_code
krb5_dbe_lookup_last_pwd_change(context, entry, stamp)
    krb5_context          context;
    krb5_db_entry       * entry;
    krb5_timestamp	* stamp;
{
    krb5_tl_data        tl_data;
    krb5_error_code	code;
    krb5_int32		tmp;

    tl_data.tl_data_type = KRB5_TL_LAST_PWD_CHANGE;

    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
	return(code);
    
    if (tl_data.tl_data_length != 4) {
	*stamp = 0;
	return(0);
    }

    krb5_kdb_decode_int32(tl_data.tl_data_contents, tmp);

    *stamp = (krb5_timestamp) tmp;

    return(0);
}

/* it seems odd that there's no function to remove a tl_data, but if
   I need one, I'll add one */

krb5_error_code
krb5_dbe_update_mod_princ_data(context, entry, mod_date, mod_princ)
    krb5_context	  context;
    krb5_db_entry	* entry;
    krb5_timestamp	  mod_date;
    krb5_const_principal  mod_princ;
{
    krb5_tl_data          tl_data;

    krb5_error_code 	  retval = 0;
    krb5_octet		* nextloc = 0;
    char		* unparse_mod_princ = 0;
    unsigned int	unparse_mod_princ_size;

    if ((retval = krb5_unparse_name(context, mod_princ, 
				    &unparse_mod_princ)))
	return(retval);

    unparse_mod_princ_size = strlen(unparse_mod_princ) + 1;

    if ((nextloc = (krb5_octet *) malloc(unparse_mod_princ_size + 4))
	== NULL) {
	free(unparse_mod_princ);
	return(ENOMEM);
    }

    tl_data.tl_data_type = KRB5_TL_MOD_PRINC;
    tl_data.tl_data_length = unparse_mod_princ_size + 4;
    tl_data.tl_data_contents = nextloc;

    /* Mod Date */
    krb5_kdb_encode_int32(mod_date, nextloc);

    /* Mod Princ */
    memcpy(nextloc+4, unparse_mod_princ, unparse_mod_princ_size);

    retval = krb5_dbe_update_tl_data(context, entry, &tl_data);

    free(unparse_mod_princ);
    free(nextloc);

    return(retval);
}

krb5_error_code
krb5_dbe_lookup_mod_princ_data(context, entry, mod_time, mod_princ)
    krb5_context	  context;
    krb5_db_entry	* entry;
    krb5_timestamp	* mod_time;
    krb5_principal	* mod_princ;
{
    krb5_tl_data        tl_data;
    krb5_error_code	code;

    tl_data.tl_data_type = KRB5_TL_MOD_PRINC;

    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
	return(code);
    
    if ((tl_data.tl_data_length < 5) ||
	(tl_data.tl_data_contents[tl_data.tl_data_length-1] != '\0'))
	return(KRB5_KDB_TRUNCATED_RECORD);

    /* Mod Date */
    krb5_kdb_decode_int32(tl_data.tl_data_contents, *mod_time);

    /* Mod Princ */
    if ((code = krb5_parse_name(context,
				(const char *) (tl_data.tl_data_contents+4),
				mod_princ)))
	return(code);

    return(0);
}

krb5_error_code
krb5_encode_princ_dbkey(context, key, principal)
    krb5_context context;
    krb5_data  *key;
    krb5_const_principal principal;
{
    char *princ_name;
    krb5_error_code retval;

    if (!(retval = krb5_unparse_name(context, principal, &princ_name))) {
        /* need to store the NULL for decoding */
        key->length = strlen(princ_name)+1;	
        key->data = princ_name;
    }
    return(retval);
}

void
krb5_free_princ_dbkey(context, key)
    krb5_context context;
    krb5_data  *key;
{
    (void) krb5_free_data_contents(context, key);
}

krb5_error_code
krb5_encode_princ_contents(context, content, entry)
    krb5_context 	  context;
    krb5_data  		* content;
    krb5_db_entry 	* entry;
{
    int 		  i, j;
    unsigned int	  unparse_princ_size;
    char 		* unparse_princ;
    char		* nextloc;
    krb5_tl_data	* tl_data;
    krb5_error_code 	  retval;
    krb5_int16		  psize16;

    /*
     * Generate one lump of data from the krb5_db_entry.
     * This data must be independent of byte order of the machine,
     * compact and extensible.
     */

    /* 
     * First allocate enough space for all the data. 
     * Need  2 bytes for the length of the base structure
     * then 36 [ 8 * 4 + 2 * 2] bytes for the base information
     *         [ attributes, max_life, max_renewable_life, expiration,
     *	  	 pw_expiration, last_success, last_failed, fail_auth_count ]
     *         [ n_key_data, n_tl_data ]
     * then XX bytes [ e_length ] for the extra data [ e_data ]
     * then XX bytes [ 2 for length + length for string ] for the principal,
     * then (4 [type + length] + tl_data_length) bytes per tl_data
     * then (4 + (4 + key_data_length) per key_data_contents) bytes per key_data
     */
    content->length = entry->len + entry->e_length;

    if ((retval = krb5_unparse_name(context, entry->princ, &unparse_princ)))
	return(retval);

    unparse_princ_size = strlen(unparse_princ) + 1;
    content->length += unparse_princ_size;
    content->length += 2;		

    i = 0;
    /* tl_data is a linked list */
    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next) {
	content->length += tl_data->tl_data_length;
	content->length += 4; /* type, length */
	i++;
    }

    if (i != entry->n_tl_data) {
	retval = KRB5_KDB_TRUNCATED_RECORD;
	goto epc_error;
    }

    /* key_data is an array */
    for (i = 0; i < entry->n_key_data; i++) {
	content->length += 4; /* Version, KVNO */
	for (j = 0; j < entry->key_data[i].key_data_ver; j++) {
	    content->length += entry->key_data[i].key_data_length[j];
	    content->length += 4; /* type + length */
	}
    }
	
    if ((content->data = malloc(content->length)) == NULL) {
	retval = ENOMEM;
	goto epc_error;
    }

    /* 
     * Now we go through entry again, this time copying data 
     * These first entries are always saved regardless of version
     */
    nextloc = content->data;

	/* Base Length */
    krb5_kdb_encode_int16(entry->len, nextloc);
    nextloc += 2;

	/* Attributes */
    krb5_kdb_encode_int32(entry->attributes, nextloc);
    nextloc += 4;
  
	/* Max Life */
    krb5_kdb_encode_int32(entry->max_life, nextloc);
    nextloc += 4;
  
	/* Max Renewable Life */
    krb5_kdb_encode_int32(entry->max_renewable_life, nextloc);
    nextloc += 4;
  
	/* When the client expires */
    krb5_kdb_encode_int32(entry->expiration, nextloc);
    nextloc += 4;
  
	/* When its passwd expires */
    krb5_kdb_encode_int32(entry->pw_expiration, nextloc);
    nextloc += 4;
  
	/* Last successful passwd */
    krb5_kdb_encode_int32(entry->last_success, nextloc);
    nextloc += 4;
  
	/* Last failed passwd attempt */
    krb5_kdb_encode_int32(entry->last_failed, nextloc);
    nextloc += 4;
  
	/* # of failed passwd attempt */
    krb5_kdb_encode_int32(entry->fail_auth_count, nextloc);
    nextloc += 4;

	/* # tl_data strutures */
    krb5_kdb_encode_int16(entry->n_tl_data, nextloc);
    nextloc += 2;
  
	/* # key_data strutures */
    krb5_kdb_encode_int16(entry->n_key_data, nextloc);
    nextloc += 2;
  
    	/* Put extended fields here */
    if (entry->len != KRB5_KDB_V1_BASE_LENGTH)
	abort();

	/* Any extra data that this version doesn't understand. */
    if (entry->e_length) {
	memcpy(nextloc, entry->e_data, entry->e_length);
	nextloc += entry->e_length;
    }
  
	/* 
	 * Now we get to the principal.
	 * To squeze a few extra bytes out it is always assumed to come
	 * after the base type.
	 */
    psize16 = (krb5_int16) unparse_princ_size;
    krb5_kdb_encode_int16(psize16, nextloc);
    nextloc += 2;
    (void) memcpy(nextloc, unparse_princ, unparse_princ_size);
    nextloc += unparse_princ_size;

    	/* tl_data is a linked list, of type, legth, contents */
    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next) {
	krb5_kdb_encode_int16(tl_data->tl_data_type, nextloc);
	nextloc += 2;
	krb5_kdb_encode_int16(tl_data->tl_data_length, nextloc);
	nextloc += 2;

	memcpy(nextloc, tl_data->tl_data_contents, tl_data->tl_data_length);
	nextloc += tl_data->tl_data_length;
    }

    	/* key_data is an array */
    for (i = 0; i < entry->n_key_data; i++) {
	krb5_kdb_encode_int16(entry->key_data[i].key_data_ver, nextloc);
	nextloc += 2;
	krb5_kdb_encode_int16(entry->key_data[i].key_data_kvno, nextloc);
	nextloc += 2;

	for (j = 0; j < entry->key_data[i].key_data_ver; j++) {
	    krb5_int16 type = entry->key_data[i].key_data_type[j];
	    krb5_ui_2  length = entry->key_data[i].key_data_length[j];

    	    krb5_kdb_encode_int16(type, nextloc);
	    nextloc += 2;
    	    krb5_kdb_encode_int16(length, nextloc);
	    nextloc += 2;

	    if (length) {
	        memcpy(nextloc, entry->key_data[i].key_data_contents[j],length);
	        nextloc += length;
	    }
	}
    }
	
epc_error:;
    free(unparse_princ);
    return retval;
}

void
krb5_free_princ_contents(context, contents)
    krb5_context 	  context;
    krb5_data *contents;
{
    krb5_free_data_contents(context, contents);
    return;
}

krb5_error_code
krb5_decode_princ_contents(context, content, entry)
    krb5_context 	  context;
    krb5_data  		* content;
    krb5_db_entry 	* entry;
{
    int			  sizeleft, i;
    char 		* nextloc;
    krb5_tl_data       ** tl_data;
    krb5_int16		  i16;

    krb5_error_code retval;

    /* Zero out entry and NULL pointers */
    memset(entry, 0, sizeof(krb5_db_entry));

    /*
     * undo the effects of encode_princ_contents.
     *
     * The first part is decoding the base type. If the base type is
     * bigger than the original base type then the additional fields
     * need to be filled in. If the base type is larger than any
     * known base type the additional data goes in e_data.
     */

    /* First do the easy stuff */
    nextloc = content->data;
    sizeleft = content->length;
    if ((sizeleft -= KRB5_KDB_V1_BASE_LENGTH) < 0) 
	return KRB5_KDB_TRUNCATED_RECORD;

	/* Base Length */
    krb5_kdb_decode_int16(nextloc, entry->len);
    nextloc += 2;

	/* Attributes */
    krb5_kdb_decode_int32(nextloc, entry->attributes);
    nextloc += 4;

	/* Max Life */
    krb5_kdb_decode_int32(nextloc, entry->max_life);
    nextloc += 4;

	/* Max Renewable Life */
    krb5_kdb_decode_int32(nextloc, entry->max_renewable_life);
    nextloc += 4;

	/* When the client expires */
    krb5_kdb_decode_int32(nextloc, entry->expiration);
    nextloc += 4;

	/* When its passwd expires */
    krb5_kdb_decode_int32(nextloc, entry->pw_expiration);
    nextloc += 4;

	/* Last successful passwd */
    krb5_kdb_decode_int32(nextloc, entry->last_success);
    nextloc += 4;

	/* Last failed passwd attempt */
    krb5_kdb_decode_int32(nextloc, entry->last_failed);
    nextloc += 4;

	/* # of failed passwd attempt */
    krb5_kdb_decode_int32(nextloc, entry->fail_auth_count);
    nextloc += 4;

	/* # tl_data strutures */
    krb5_kdb_decode_int16(nextloc, entry->n_tl_data);
    nextloc += 2;

    if (entry->n_tl_data < 0)
	return KRB5_KDB_TRUNCATED_RECORD;

	/* # key_data strutures */
    krb5_kdb_decode_int16(nextloc, entry->n_key_data);
    nextloc += 2;

    if (entry->n_key_data < 0)
	return KRB5_KDB_TRUNCATED_RECORD;

	/* Check for extra data */
    if (entry->len > KRB5_KDB_V1_BASE_LENGTH) {
	entry->e_length = entry->len - KRB5_KDB_V1_BASE_LENGTH;
	if ((entry->e_data = (krb5_octet *)malloc(entry->e_length))) {
	    memcpy(entry->e_data, nextloc, entry->e_length);
	    nextloc += entry->e_length;
	} else {
	    return ENOMEM;
	}
    }

    /*
     * Get the principal name for the entry 
     * (stored as a string which gets unparsed.)
     */
    if ((sizeleft -= 2) < 0) {
	retval = KRB5_KDB_TRUNCATED_RECORD;
	goto error_out;
    }

    i = 0;
    krb5_kdb_decode_int16(nextloc, i16);
    i = (int) i16;
    nextloc += 2;

    if ((retval = krb5_parse_name(context, nextloc, &(entry->princ))))
	goto error_out;
    if (((size_t) i != (strlen(nextloc) + 1)) || (sizeleft < i)) {
	retval = KRB5_KDB_TRUNCATED_RECORD;
	goto error_out;
    }
    sizeleft -= i;
    nextloc += i;

    	/* tl_data is a linked list */
    tl_data = &entry->tl_data;
    for (i = 0; i < entry->n_tl_data; i++) {
    	if ((sizeleft -= 4) < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	if ((*tl_data = (krb5_tl_data *)
	  malloc(sizeof(krb5_tl_data))) == NULL) {
	    retval = ENOMEM;
	    goto error_out;
	}
	(*tl_data)->tl_data_next = NULL;
	(*tl_data)->tl_data_contents = NULL;
	krb5_kdb_decode_int16(nextloc, (*tl_data)->tl_data_type);
	nextloc += 2;
	krb5_kdb_decode_int16(nextloc, (*tl_data)->tl_data_length);
	nextloc += 2;

    	if ((sizeleft -= (*tl_data)->tl_data_length) < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	if (((*tl_data)->tl_data_contents = (krb5_octet *)
	  malloc((*tl_data)->tl_data_length)) == NULL) {
	    retval = ENOMEM;
	    goto error_out;
	}
	memcpy((*tl_data)->tl_data_contents,nextloc,(*tl_data)->tl_data_length);
	nextloc += (*tl_data)->tl_data_length;
	tl_data = &((*tl_data)->tl_data_next);
    }

    	/* key_data is an array */
    if (entry->n_key_data && ((entry->key_data = (krb5_key_data *)
      malloc(sizeof(krb5_key_data) * entry->n_key_data)) == NULL)) {
        retval = ENOMEM;
	goto error_out;
    }
    for (i = 0; i < entry->n_key_data; i++) {
	krb5_key_data * key_data;
        int j;

    	if ((sizeleft -= 4) < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	key_data = entry->key_data + i;
	memset(key_data, 0, sizeof(krb5_key_data));
	krb5_kdb_decode_int16(nextloc, key_data->key_data_ver);
	nextloc += 2;
	krb5_kdb_decode_int16(nextloc, key_data->key_data_kvno);
	nextloc += 2;

	/* key_data_ver determins number of elements and how to unparse them. */
	if (key_data->key_data_ver <= KRB5_KDB_V1_KEY_DATA_ARRAY) {
	    for (j = 0; j < key_data->key_data_ver; j++) {
    	        if ((sizeleft -= 4) < 0) {
	            retval = KRB5_KDB_TRUNCATED_RECORD;
	            goto error_out;
	        }
		krb5_kdb_decode_int16(nextloc, key_data->key_data_type[j]);
		nextloc += 2;
		krb5_kdb_decode_int16(nextloc, key_data->key_data_length[j]);
		nextloc += 2;

    	        if ((sizeleft -= key_data->key_data_length[j]) < 0) {
	            retval = KRB5_KDB_TRUNCATED_RECORD;
	            goto error_out;
	        }
	        if (key_data->key_data_length[j]) {
	    	    if ((key_data->key_data_contents[j] = (krb5_octet *)
	    	      malloc(key_data->key_data_length[j])) == NULL) {
	                retval = ENOMEM;
	                goto error_out;
	            }
	            memcpy(key_data->key_data_contents[j], nextloc, 
		           key_data->key_data_length[j]);
	            nextloc += key_data->key_data_length[j];
		}
	    }
	} else {
	    /* This isn't right. I'll fix it later */
	    abort();
	}
    }
    return 0;

error_out:;
    krb5_dbe_free_contents(context, entry);
    return retval;
}
	    
void
krb5_dbe_free_contents(context, entry)
     krb5_context 	  context; 
     krb5_db_entry 	* entry;
{
    krb5_tl_data 	* tl_data_next;
    krb5_tl_data 	* tl_data;
    int i, j;

    if (entry->e_data)
	free(entry->e_data);
    if (entry->princ)
	krb5_free_principal(context, entry->princ);
    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data_next) {
	tl_data_next = tl_data->tl_data_next;
	if (tl_data->tl_data_contents)
	    free(tl_data->tl_data_contents);
	free(tl_data);
    }
    if (entry->key_data) {
    	for (i = 0; i < entry->n_key_data; i++) {
	    for (j = 0; j < entry->key_data[i].key_data_ver; j++) {
	    	if (entry->key_data[i].key_data_length[j]) {
		    if (entry->key_data[i].key_data_contents[j]) {
		        memset(entry->key_data[i].key_data_contents[j], 
			       0, 
			       (unsigned) entry->key_data[i].key_data_length[j]);
		    	free (entry->key_data[i].key_data_contents[j]);
		    }
		}
		entry->key_data[i].key_data_contents[j] = NULL;
		entry->key_data[i].key_data_length[j] = 0;
		entry->key_data[i].key_data_type[j] = 0;
	    }
	}
	free(entry->key_data);
    }
    memset(entry, 0, sizeof(*entry));
    return;
}

/*
 * Given a particular enctype and optional salttype and kvno, find the
 * most appropriate krb5_key_data entry of the database entry.
 *
 * If stype or kvno is negative, it is ignored.
 * If kvno is 0 get the key which is maxkvno for the princ and matches
 * the other attributes.
 */
krb5_error_code
krb5_dbe_search_enctype(kcontext, dbentp, start, ktype, stype, kvno, kdatap)
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

krb5_error_code
krb5_dbe_find_enctype(kcontext, dbentp, ktype, stype, kvno, kdatap)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_int32		ktype;
    krb5_int32		stype;
    krb5_int32		kvno;
    krb5_key_data	**kdatap;
{
    krb5_int32 start = 0;

    return krb5_dbe_search_enctype(kcontext, dbentp, &start, ktype, stype,
				   kvno, kdatap);
}

    
