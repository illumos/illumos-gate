/*
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING 
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 */

#include	<sys/types.h>
#include	<sys/time.h>
#include	<errno.h>
#include	"server_internal.h"
#include	<kadm5/admin.h>
#include	<kdb.h>
#include	<stdio.h>
#include	<string.h>
#include	<stdarg.h>
#include	<stdlib.h>
#include	<k5-int.h>
#include	<kadm5/server_internal.h>
#include	<kadm5/admin.h>
#ifdef USE_PASSWORD_SERVER
#include	<sys/wait.h>
#endif

extern	krb5_principal	    master_princ;
extern	krb5_principal	    hist_princ;
extern	krb5_keyblock	    hist_key;
extern	krb5_db_entry	    master_db;
extern	krb5_db_entry	    hist_db;
extern  krb5_kvno	    hist_kvno;

static int decrypt_key_data(krb5_context context,
			    krb5_keyblock *, int n_key_data, krb5_key_data *key_data,
			    krb5_keyblock **keyblocks, int *n_keys);

static krb5_error_code 
kadm5_copy_principal(krb5_context context, krb5_const_principal inprinc, krb5_principal *outprinc)
{
    register krb5_principal tempprinc;
    register int i, nelems;
                                                                                                                            
    tempprinc = (krb5_principal)krb5_db_alloc(context, NULL, sizeof(krb5_principal_data));
                                                                                                                            
    if (tempprinc == 0)
        return ENOMEM;
                                                                                                                            
    memcpy(tempprinc, inprinc, sizeof(krb5_principal_data));
                                                                                                                            
    nelems = (int) krb5_princ_size(context, inprinc);
    tempprinc->data = krb5_db_alloc(context, NULL, nelems * sizeof(krb5_data));
                                                                                                                            
    if (tempprinc->data == 0) {
	krb5_db_free(context, (char *)tempprinc);
        return ENOMEM;
    }
                                                                                                                            
    for (i = 0; i < nelems; i++) {
        unsigned int len = krb5_princ_component(context, inprinc, i)->length;
        krb5_princ_component(context, tempprinc, i)->length = len;
        if (((krb5_princ_component(context, tempprinc, i)->data =
              krb5_db_alloc(context, NULL, len)) == 0) && len) {
            while (--i >= 0)
                krb5_db_free(context, krb5_princ_component(context, tempprinc, i)->data);
            krb5_db_free (context, tempprinc->data);
            krb5_db_free (context, tempprinc);
            return ENOMEM;
        }
        if (len)
            memcpy(krb5_princ_component(context, tempprinc, i)->data,
                   krb5_princ_component(context, inprinc, i)->data, len);
    }
                                                                                                                            
    tempprinc->realm.data =
	krb5_db_alloc(context, NULL, tempprinc->realm.length = inprinc->realm.length);
    if (!tempprinc->realm.data && tempprinc->realm.length) {
            for (i = 0; i < nelems; i++)
		krb5_db_free(context, krb5_princ_component(context, tempprinc, i)->data);
            krb5_db_free(context, tempprinc->data);
            krb5_db_free(context, tempprinc);
            return ENOMEM;
    }
    if (tempprinc->realm.length)
        memcpy(tempprinc->realm.data, inprinc->realm.data,
               inprinc->realm.length);
                                                                                                                            
    *outprinc = tempprinc;
    return 0;
}
                                                                                                                            
static void
kadm5_free_principal(krb5_context context, krb5_principal val)
{
    register krb5_int32 i;
                                                                                                                            
    if (!val)
        return;
                                                                                                                            
    if (val->data) {
        i = krb5_princ_size(context, val);
        while(--i >= 0)
            krb5_db_free(context, krb5_princ_component(context, val, i)->data);
        krb5_db_free(context, val->data);
    }
    if (val->realm.data)
        krb5_db_free(context, val->realm.data);
    krb5_db_free(context, val);
}

/*
 * XXX Functions that ought to be in libkrb5.a, but aren't.
 */
kadm5_ret_t krb5_copy_key_data_contents(context, from, to)
   krb5_context context;
   krb5_key_data *from, *to;
{
     int i, idx;
     
     *to = *from;

     idx = (from->key_data_ver == 1 ? 1 : 2);

     for (i = 0; i < idx; i++) {
       if ( from->key_data_length[i] ) {
	 to->key_data_contents[i] = malloc(from->key_data_length[i]);
	 if (to->key_data_contents[i] == NULL) {
	   for (i = 0; i < idx; i++) {
	     if (to->key_data_contents[i]) {
	       memset(to->key_data_contents[i], 0,
		      to->key_data_length[i]);
	       free(to->key_data_contents[i]);
	     }
	   }
	   return ENOMEM;
	 }
	 memcpy(to->key_data_contents[i], from->key_data_contents[i],
		from->key_data_length[i]);
       }
     }
     return 0;
}

static krb5_tl_data *dup_tl_data(krb5_tl_data *tl)
{
     krb5_tl_data *n;

     n = (krb5_tl_data *) malloc(sizeof(krb5_tl_data));
     if (n == NULL)
	  return NULL;
     n->tl_data_contents = malloc(tl->tl_data_length);
     if (n->tl_data_contents == NULL) {
	  free(n);
	  return NULL;
     }
     memcpy(n->tl_data_contents, tl->tl_data_contents, tl->tl_data_length);
     n->tl_data_type = tl->tl_data_type;
     n->tl_data_length = tl->tl_data_length;
     n->tl_data_next = NULL;
     return n;
}

/* This is in lib/kdb/kdb_cpw.c, but is static */
static void cleanup_key_data(context, count, data)
   krb5_context	  context;
   int			  count;
   krb5_key_data	* data;
{
     int i, j;
     
     for (i = 0; i < count; i++)
	  for (j = 0; j < data[i].key_data_ver; j++)
	       if (data[i].key_data_length[j])
		   krb5_db_free(context, data[i].key_data_contents[j]);
     krb5_db_free(context, data);
}

kadm5_ret_t
kadm5_create_principal(void *server_handle,
			    kadm5_principal_ent_t entry, long mask,
			    char *password)
{
    return
	kadm5_create_principal_3(server_handle, entry, mask,
				 0, NULL, password);
}
kadm5_ret_t
kadm5_create_principal_3(void *server_handle,
			 kadm5_principal_ent_t entry, long mask,
			 int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
			 char *password)
{
    krb5_db_entry		kdb;
    osa_princ_ent_rec		adb;
    kadm5_policy_ent_rec	polent;
    krb5_int32			now;
    krb5_tl_data		*tl_data_tail;
    unsigned int		ret;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    /*
     * Argument sanity checking, and opening up the DB
     */
    if(!(mask & KADM5_PRINCIPAL) || (mask & KADM5_MOD_NAME) ||
       (mask & KADM5_MOD_TIME) || (mask & KADM5_LAST_PWD_CHANGE) ||
       (mask & KADM5_MKVNO) || (mask & KADM5_POLICY_CLR) ||
       (mask & KADM5_AUX_ATTRIBUTES) || (mask & KADM5_KEY_DATA) ||
       (mask & KADM5_LAST_SUCCESS) || (mask & KADM5_LAST_FAILED) ||
       (mask & KADM5_FAIL_AUTH_COUNT))
	return KADM5_BAD_MASK;
    if((mask & ~ALL_PRINC_MASK))
	return KADM5_BAD_MASK;
    if (entry == (kadm5_principal_ent_t) NULL || password == NULL)
	return EINVAL;

    /*
     * Check to see if the principal exists
     */
    ret = kdb_get_entry(handle, entry->principal, &kdb, &adb);

    switch(ret) {
    case KADM5_UNK_PRINC:
	/* Solaris Kerberos */
	memset(&kdb, 0, sizeof(krb5_db_entry));
	memset(&adb, 0, sizeof(osa_princ_ent_rec));
	break;
    case 0:
	/*
	 * Solaris Kerberos: this allows an addprinc to be done on a mix-in
	 * princ which has no keys initially.
	 */
	if (kdb.n_key_data != 0) {
		/* have a princ with keys, return dupe princ error */
		kdb_free_entry(handle, &kdb, &adb);
		return KADM5_DUP;
	} else {
		/*
		 * have a princ with no keys, let's replace it.  Note, want to
		 * keep the existing kdb tl_data (specifically the LDAP plugin
		 * adds the DN to the tl_data which is needed to locate the dir.
		 * entry).
		 */
		kdb_free_entry(handle, NULL, &adb);
		memset(&adb, 0, sizeof(osa_princ_ent_rec));
	}
	break;
    default:
	return ret;
    }

    /*
     * If a policy was specified, load it.
     * If we can not find the one specified return an error
     */
    if ((mask & KADM5_POLICY)) {
	 if ((ret = kadm5_get_policy(handle->lhandle, entry->policy,
				     &polent)) != KADM5_OK) {
	    if(ret == EINVAL) 
		return KADM5_BAD_POLICY;
	    else
		return ret;
	}
    }
    if ((ret = passwd_check(handle, password, (mask & KADM5_POLICY),
			    &polent, entry->principal))) {
	if (mask & KADM5_POLICY)
	     (void) kadm5_free_policy_ent(handle->lhandle, &polent);
	return ret;
    }
    /*
     * Start populating the various DB fields, using the
     * "defaults" for fields that were not specified by the
     * mask.
     */
    if ((ret = krb5_timeofday(handle->context, &now))) {
	 if (mask & KADM5_POLICY)
	      (void) kadm5_free_policy_ent(handle->lhandle, &polent);
	 return ret;
    }

    kdb.magic = KRB5_KDB_MAGIC_NUMBER;
    kdb.len = KRB5_KDB_V1_BASE_LENGTH; /* gag me with a chainsaw */

    /*
     * Solaris Kerberos:
     * If KADM5_ATTRIBUTES is set, we want to rope in not only
     * entry->attributes, but also the generic params.flags
     * obtained previously via kadm5_get_config_params.
     */
    if ((mask & KADM5_ATTRIBUTES)) {
	kdb.attributes = handle->params.flags;
	kdb.attributes |= entry->attributes;
    } else {
	kdb.attributes = handle->params.flags;
    }

    if ((mask & KADM5_MAX_LIFE))
	kdb.max_life = entry->max_life; 
    else 
	kdb.max_life = handle->params.max_life;

    if (mask & KADM5_MAX_RLIFE)
	 kdb.max_renewable_life = entry->max_renewable_life;
    else
	 kdb.max_renewable_life = handle->params.max_rlife;

    if ((mask & KADM5_PRINC_EXPIRE_TIME))
	kdb.expiration = entry->princ_expire_time;
    else
	kdb.expiration = handle->params.expiration;

    kdb.pw_expiration = 0;
    if ((mask & KADM5_POLICY)) {
	if(polent.pw_max_life)
	    kdb.pw_expiration = now + polent.pw_max_life;
	else
	    kdb.pw_expiration = 0;
    }
    if ((mask & KADM5_PW_EXPIRATION))
	 kdb.pw_expiration = entry->pw_expiration;
    
    kdb.last_success = 0;
    kdb.last_failed = 0;
    kdb.fail_auth_count = 0;

    /* this is kind of gross, but in order to free the tl data, I need
       to free the entire kdb entry, and that will try to free the
       principal. */

    if ((ret = kadm5_copy_principal(handle->context,
				    entry->principal, &(kdb.princ)))) {
	if (mask & KADM5_POLICY)
	     (void) kadm5_free_policy_ent(handle->lhandle, &polent);
	return(ret);
    }

    if ((ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now))) {
         krb5_db_free_principal(handle->context, &kdb, 1);
	 if (mask & KADM5_POLICY)
	     (void) kadm5_free_policy_ent(handle->lhandle, &polent);
	 return(ret);
    }

    if (mask & KADM5_TL_DATA) {
	/* splice entry->tl_data onto the front of kdb.tl_data */
	for (tl_data_tail = entry->tl_data; tl_data_tail;
	     tl_data_tail = tl_data_tail->tl_data_next)
	{
	    ret = krb5_dbe_update_tl_data(handle->context, &kdb, tl_data_tail);
	    if( ret )
	    {
		krb5_db_free_principal(handle->context, &kdb, 1);
		if (mask & KADM5_POLICY)
		    (void) kadm5_free_policy_ent(handle->lhandle, &polent);
		return ret;
	    }
	}
    }

    /* initialize the keys */

    if ((ret = krb5_dbe_cpw(handle->context, &handle->master_keyblock,
			    n_ks_tuple?ks_tuple:handle->params.keysalts,
			    n_ks_tuple?n_ks_tuple:handle->params.num_keysalts,
			    password,
			    (mask & KADM5_KVNO)?entry->kvno:1,
			    FALSE, &kdb))) {
	krb5_db_free_principal(handle->context, &kdb, 1);
	if (mask & KADM5_POLICY)
	     (void) kadm5_free_policy_ent(handle->lhandle, &polent);
	return(ret);
    }

    /* populate the admin-server-specific fields.  In the OV server,
       this used to be in a separate database.  Since there's already
       marshalling code for the admin fields, to keep things simple,
       I'm going to keep it, and make all the admin stuff occupy a
       single tl_data record, */

    adb.admin_history_kvno = hist_kvno;
    if ((mask & KADM5_POLICY)) {
	adb.aux_attributes = KADM5_POLICY;

	/* this does *not* need to be strdup'ed, because adb is xdr */
	/* encoded in osa_adb_create_princ, and not ever freed */

	adb.policy = entry->policy;
    }

    /* increment the policy ref count, if any */

    if ((mask & KADM5_POLICY)) {
	polent.policy_refcnt++;
	if ((ret = kadm5_modify_policy_internal(handle->lhandle, &polent,
						    KADM5_REF_COUNT))
	    != KADM5_OK) {
	    krb5_db_free_principal(handle->context, &kdb, 1);
	    if (mask & KADM5_POLICY)
		 (void) kadm5_free_policy_ent(handle->lhandle, &polent);
	    return(ret);
	}
    }

    /* In all cases key and the principal data is set, let the database provider know */
    kdb.mask = mask | KADM5_KEY_DATA | KADM5_PRINCIPAL ;

    /* store the new db entry */
    ret = kdb_put_entry(handle, &kdb, &adb);

    krb5_db_free_principal(handle->context, &kdb, 1);

    if (ret) {
	if ((mask & KADM5_POLICY)) {
	    /* decrement the policy ref count */

	    polent.policy_refcnt--;
	    /*
	     * if this fails, there's nothing we can do anyway.  the
	     * policy refcount wil be too high.
	     */
	    (void) kadm5_modify_policy_internal(handle->lhandle, &polent,
						     KADM5_REF_COUNT);
	}

	if (mask & KADM5_POLICY)
	     (void) kadm5_free_policy_ent(handle->lhandle, &polent);
	return(ret);
    }

    if (mask & KADM5_POLICY)
	 (void) kadm5_free_policy_ent(handle->lhandle, &polent);

    return KADM5_OK;
}

	
kadm5_ret_t
kadm5_delete_principal(void *server_handle, krb5_principal principal)
{
    unsigned int		ret;
    kadm5_policy_ent_rec	polent;
    krb5_db_entry		kdb;
    osa_princ_ent_rec		adb;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (principal == NULL)
	return EINVAL;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
	return(ret);

    if ((adb.aux_attributes & KADM5_POLICY)) {
	if ((ret = kadm5_get_policy(handle->lhandle,
				    adb.policy, &polent))
	    == KADM5_OK) {
	    polent.policy_refcnt--;
	    if ((ret = kadm5_modify_policy_internal(handle->lhandle, &polent,
							 KADM5_REF_COUNT))
		!= KADM5_OK) {
		(void) kadm5_free_policy_ent(handle->lhandle, &polent);
		kdb_free_entry(handle, &kdb, &adb);
		return(ret);
	    }
	}
	if ((ret = kadm5_free_policy_ent(handle->lhandle, &polent))) {
	     kdb_free_entry(handle, &kdb, &adb);
	     return ret;
	}
    }

    ret = kdb_delete_entry(handle, principal);

    kdb_free_entry(handle, &kdb, &adb);

    return ret;
}

kadm5_ret_t
kadm5_modify_principal(void *server_handle,
			    kadm5_principal_ent_t entry, long mask)
{
    int			    ret, ret2, i;
    kadm5_policy_ent_rec    npol, opol;
    int			    have_npol = 0, have_opol = 0;
    krb5_db_entry	    kdb;
    krb5_tl_data	    *tl_data_orig;
    osa_princ_ent_rec	    adb;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if((mask & KADM5_PRINCIPAL) || (mask & KADM5_LAST_PWD_CHANGE) ||
       (mask & KADM5_MOD_TIME) || (mask & KADM5_MOD_NAME) ||
       (mask & KADM5_MKVNO) || (mask & KADM5_AUX_ATTRIBUTES) ||
       (mask & KADM5_KEY_DATA) || (mask & KADM5_LAST_SUCCESS) ||
       (mask & KADM5_LAST_FAILED))
	return KADM5_BAD_MASK;
    if((mask & ~ALL_PRINC_MASK))
	return KADM5_BAD_MASK;
    if((mask & KADM5_POLICY) && (mask & KADM5_POLICY_CLR))
	return KADM5_BAD_MASK;
    if(entry == (kadm5_principal_ent_t) NULL)
	return EINVAL;
    if (mask & KADM5_TL_DATA) {
	 tl_data_orig = entry->tl_data;
	 while (tl_data_orig) {
	      if (tl_data_orig->tl_data_type < 256)
		   return KADM5_BAD_TL_TYPE;
	      tl_data_orig = tl_data_orig->tl_data_next;
	 }
    }

    ret = kdb_get_entry(handle, entry->principal, &kdb, &adb);
    if (ret)
	return(ret);

    /*
     * This is pretty much the same as create ...
     */

    if ((mask & KADM5_POLICY)) {
	 /* get the new policy */
	 ret = kadm5_get_policy(handle->lhandle, entry->policy, &npol);
	 if (ret) {
	      switch (ret) {
	      case EINVAL:
		   ret = KADM5_BAD_POLICY;
		   break;
	      case KADM5_UNK_POLICY:
	      case KADM5_BAD_POLICY:
		   ret =  KADM5_UNK_POLICY;
		   break;
	      }
	      goto done;
	 }
	 have_npol = 1;

	 /* if we already have a policy, get it to decrement the refcnt */
	 if(adb.aux_attributes & KADM5_POLICY) {
	      /* ... but not if the old and new are the same */
	      if(strcmp(adb.policy, entry->policy)) {
		   ret = kadm5_get_policy(handle->lhandle,
					  adb.policy, &opol);
		   switch(ret) {
		   case EINVAL:
		   case KADM5_BAD_POLICY:
		   case KADM5_UNK_POLICY:
			break;
		   case KADM5_OK:
			have_opol = 1;
			opol.policy_refcnt--;
			break;
		   default:
			goto done;
			break;
		   }
		   npol.policy_refcnt++;
	      }
	 } else npol.policy_refcnt++;

	 /* set us up to use the new policy */
	 adb.aux_attributes |= KADM5_POLICY;
	 if (adb.policy)
	      free(adb.policy);
	 adb.policy = strdup(entry->policy);

	 /* set pw_max_life based on new policy */
	 if (npol.pw_max_life) {
	     ret = krb5_dbe_lookup_last_pwd_change(handle->context, &kdb,
						   &(kdb.pw_expiration));
	     if (ret)
		 goto done;
	     kdb.pw_expiration += npol.pw_max_life;
	 } else {
	     kdb.pw_expiration = 0;
	 }
    }

    if ((mask & KADM5_POLICY_CLR) &&
	(adb.aux_attributes & KADM5_POLICY)) {
	 ret = kadm5_get_policy(handle->lhandle, adb.policy, &opol);
	 switch(ret) {
	 case EINVAL:
	 case KADM5_BAD_POLICY:
	 case KADM5_UNK_POLICY:
	      ret = KADM5_BAD_DB;
	      goto done;
	      break;
	 case KADM5_OK:
	      have_opol = 1;
	      if (adb.policy)
		   free(adb.policy);
	      adb.policy = NULL;
	      adb.aux_attributes &= ~KADM5_POLICY;
	      kdb.pw_expiration = 0;
	      opol.policy_refcnt--;
	      break;
	 default:
	      goto done;
	      break;
	 }
    }

    if (((mask & KADM5_POLICY) || (mask & KADM5_POLICY_CLR)) &&
	(((have_opol) &&
	  (ret =
	   kadm5_modify_policy_internal(handle->lhandle, &opol,
					     KADM5_REF_COUNT))) ||
	 ((have_npol) &&
	  (ret =
	   kadm5_modify_policy_internal(handle->lhandle, &npol,
					     KADM5_REF_COUNT)))))
	goto done;

    if ((mask & KADM5_ATTRIBUTES)) 
	kdb.attributes = entry->attributes;
    if ((mask & KADM5_MAX_LIFE))
	kdb.max_life = entry->max_life;
    if ((mask & KADM5_PRINC_EXPIRE_TIME))
	kdb.expiration = entry->princ_expire_time;
    if (mask & KADM5_PW_EXPIRATION)
	 kdb.pw_expiration = entry->pw_expiration;
    if (mask & KADM5_MAX_RLIFE)
	 kdb.max_renewable_life = entry->max_renewable_life;
    if (mask & KADM5_FAIL_AUTH_COUNT)
	 kdb.fail_auth_count = entry->fail_auth_count;
    
    if((mask & KADM5_KVNO)) {
	 for (i = 0; i < kdb.n_key_data; i++)
	      kdb.key_data[i].key_data_kvno = entry->kvno;
    }

    if (mask & KADM5_TL_DATA) {
	 krb5_tl_data *tl;

	 /* may have to change the version number of the API. Updates the list with the given tl_data rather than over-writting */

	 for (tl = entry->tl_data; tl;
	      tl = tl->tl_data_next)
	 {
	     ret = krb5_dbe_update_tl_data(handle->context, &kdb, tl);
	     if( ret )
	     {
		 goto done;
	     }
	 }
    }

    /* let the mask propagate to the database provider */
    kdb.mask = mask;

    ret = kdb_put_entry(handle, &kdb, &adb);
    if (ret) goto done;

    ret = KADM5_OK;
done:
    if (have_opol) {
	 ret2 = kadm5_free_policy_ent(handle->lhandle, &opol);
	 ret = ret ? ret : ret2;
    }
    if (have_npol) {
	 ret2 = kadm5_free_policy_ent(handle->lhandle, &npol);
	 ret = ret ? ret : ret2;
    }
    kdb_free_entry(handle, &kdb, &adb);
    return ret;
}
    
kadm5_ret_t
kadm5_rename_principal(void *server_handle,
			    krb5_principal source, krb5_principal target)
{
    krb5_db_entry	kdb;
    osa_princ_ent_rec	adb;
    int			ret, i;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (source == NULL || target == NULL)
	return EINVAL;

    if ((ret = kdb_get_entry(handle, target, &kdb, &adb)) == 0) {
	kdb_free_entry(handle, &kdb, &adb);
	return(KADM5_DUP);
    }

    if ((ret = kdb_get_entry(handle, source, &kdb, &adb)))
	return ret;

    /* this is kinda gross, but unavoidable */

    for (i=0; i<kdb.n_key_data; i++) {
	if ((kdb.key_data[i].key_data_ver == 1) ||
	    (kdb.key_data[i].key_data_type[1] == KRB5_KDB_SALTTYPE_NORMAL)) {
	    ret = KADM5_NO_RENAME_SALT;
	    goto done;
	}
    }

    kadm5_free_principal(handle->context, kdb.princ);
    ret = kadm5_copy_principal(handle->context, target, &kdb.princ);
    if (ret) {
	kdb.princ = NULL; /* so freeing the dbe doesn't lose */
	goto done;
    }

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
	goto done;

    ret = kdb_delete_entry(handle, source);

done:
    kdb_free_entry(handle, &kdb, &adb);
    return ret;
}

kadm5_ret_t
kadm5_get_principal(void *server_handle, krb5_principal principal,
		    kadm5_principal_ent_t entry,
		    long in_mask)
{
    krb5_db_entry		kdb;
    osa_princ_ent_rec		adb;
    krb5_error_code		ret = 0;
    long			mask;
    int i;
    kadm5_server_handle_t handle = server_handle;
    kadm5_principal_ent_rec	entry_local, *entry_orig;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    /*
     * In version 1, all the defined fields are always returned.
     * entry is a pointer to a kadm5_principal_ent_t_v1 that should be
     * filled with allocated memory.
     */
    if (handle->api_version == KADM5_API_VERSION_1) {
	 mask = KADM5_PRINCIPAL_NORMAL_MASK;
	 entry_orig = entry;
	 entry = &entry_local;
    } else {
	 mask = in_mask;
    }

    memset((char *) entry, 0, sizeof(*entry));

    if (principal == NULL)
	return EINVAL;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
	return ret;

    if ((mask & KADM5_POLICY) &&
	adb.policy && (adb.aux_attributes & KADM5_POLICY)) {
	if ((entry->policy = (char *) malloc(strlen(adb.policy) + 1)) == NULL) {
	    ret = ENOMEM;
	    goto done;
	}
	strcpy(entry->policy, adb.policy);
    }

    if (mask & KADM5_AUX_ATTRIBUTES)
	 entry->aux_attributes = adb.aux_attributes;

    if ((mask & KADM5_PRINCIPAL) &&
	(ret = krb5_copy_principal(handle->context, principal,
				   &entry->principal))) { 
	goto done;
    }

    if (mask & KADM5_PRINC_EXPIRE_TIME)
	 entry->princ_expire_time = kdb.expiration;

    if ((mask & KADM5_LAST_PWD_CHANGE) &&
	(ret = krb5_dbe_lookup_last_pwd_change(handle->context, &kdb,
					       &(entry->last_pwd_change)))) {
	goto done;
    }

    if (mask & KADM5_PW_EXPIRATION)
	 entry->pw_expiration = kdb.pw_expiration;
    if (mask & KADM5_MAX_LIFE)
	 entry->max_life = kdb.max_life;

    /* this is a little non-sensical because the function returns two */
    /* values that must be checked separately against the mask */
    if ((mask & KADM5_MOD_NAME) || (mask & KADM5_MOD_TIME)) {
	ret = krb5_dbe_lookup_mod_princ_data(handle->context, &kdb,
					     &(entry->mod_date), 
					     &(entry->mod_name));
	if (ret) {
	    goto done;
	}
	
	if (! (mask & KADM5_MOD_TIME))
	    entry->mod_date = 0;
	if (! (mask & KADM5_MOD_NAME)) {
	    krb5_free_principal(handle->context, entry->principal);
	    entry->principal = NULL;
	}
    }

    if (mask & KADM5_ATTRIBUTES)
	 entry->attributes = kdb.attributes;

    if (mask & KADM5_KVNO)
	 for (entry->kvno = 0, i=0; i<kdb.n_key_data; i++)
	      if (kdb.key_data[i].key_data_kvno > entry->kvno)
		   entry->kvno = kdb.key_data[i].key_data_kvno;
    
    if (handle->api_version == KADM5_API_VERSION_2)
	 entry->mkvno = 0;
    else {
	 /* XXX I'll be damned if I know how to deal with this one --marc */
	 entry->mkvno = 1;
    }

    /*
     * The new fields that only exist in version 2 start here
     */
    if (handle->api_version == KADM5_API_VERSION_2) {
	 if (mask & KADM5_MAX_RLIFE)
	      entry->max_renewable_life = kdb.max_renewable_life;
	 if (mask & KADM5_LAST_SUCCESS)
	      entry->last_success = kdb.last_success;
	 if (mask & KADM5_LAST_FAILED)
	      entry->last_failed = kdb.last_failed;
	 if (mask & KADM5_FAIL_AUTH_COUNT)
	      entry->fail_auth_count = kdb.fail_auth_count;
	 if (mask & KADM5_TL_DATA) {
	      krb5_tl_data *tl, *tl2;

	      entry->tl_data = NULL;
	      
	      tl = kdb.tl_data;
	      while (tl) {
		   if (tl->tl_data_type > 255) {
			if ((tl2 = dup_tl_data(tl)) == NULL) {
			     ret = ENOMEM;
			     goto done;
			}
			tl2->tl_data_next = entry->tl_data;
			entry->tl_data = tl2;
			entry->n_tl_data++;
		   }
			
		   tl = tl->tl_data_next;
	      }
	 }
	 if (mask & KADM5_KEY_DATA) {
	      entry->n_key_data = kdb.n_key_data;
	      if(entry->n_key_data) {
		      entry->key_data = (krb5_key_data *)
			      malloc(entry->n_key_data*sizeof(krb5_key_data));
		      if (entry->key_data == NULL) {
			      ret = ENOMEM;
			      goto done;
		      }
	      } else 
		      entry->key_data = NULL;

	      for (i = 0; i < entry->n_key_data; i++)
		  ret = krb5_copy_key_data_contents(handle->context,
						    &kdb.key_data[i],
						    &entry->key_data[i]);
		   if (ret)
			goto done;
	 }
    }

    /*
     * If KADM5_API_VERSION_1, we return an allocated structure, and
     * we need to convert the new structure back into the format the
     * caller is expecting.
     */
    if (handle->api_version == KADM5_API_VERSION_1) {
	 kadm5_principal_ent_t_v1 newv1;

	 newv1 = ((kadm5_principal_ent_t_v1) calloc(1, sizeof(*newv1)));
	 if (newv1 == NULL) {
	      ret = ENOMEM;
	      goto done;
	 }
	 
	 newv1->principal = entry->principal;
	 newv1->princ_expire_time = entry->princ_expire_time;
	 newv1->last_pwd_change = entry->last_pwd_change;
	 newv1->pw_expiration = entry->pw_expiration;
	 newv1->max_life = entry->max_life;
	 newv1->mod_name = entry->mod_name;
	 newv1->mod_date = entry->mod_date;
	 newv1->attributes = entry->attributes;
	 newv1->kvno = entry->kvno;
	 newv1->mkvno = entry->mkvno;
	 newv1->policy = entry->policy;
	 newv1->aux_attributes = entry->aux_attributes;

	 *((kadm5_principal_ent_t_v1 *) entry_orig) = newv1;
    }

    ret = KADM5_OK;

done:
    if (ret && entry->principal)
	 krb5_free_principal(handle->context, entry->principal);
    kdb_free_entry(handle, &kdb, &adb);

    return ret;
}

/*
 * Function: check_pw_reuse
 *
 * Purpose: Check if a key appears in a list of keys, in order to
 * enforce password history.
 *
 * Arguments:
 *
 *	context			(r) the krb5 context
 *	hist_keyblock		(r) the key that hist_key_data is
 *				encrypted in
 *	n_new_key_data		(r) length of new_key_data
 *	new_key_data		(r) keys to check against
 *				pw_hist_data, encrypted in hist_keyblock
 *	n_pw_hist_data		(r) length of pw_hist_data
 *	pw_hist_data		(r) passwords to check new_key_data against
 *
 * Effects:
 * For each new_key in new_key_data:
 * 	decrypt new_key with the master_keyblock
 * 	for each password in pw_hist_data:
 *		for each hist_key in password:
 *			decrypt hist_key with hist_keyblock
 *			compare the new_key and hist_key
 *
 * Returns krb5 errors, KADM5_PASS_RESUSE if a key in
 * new_key_data is the same as a key in pw_hist_data, or 0.
 */
static kadm5_ret_t
check_pw_reuse(krb5_context context,
	       krb5_keyblock *master_keyblock,
	       krb5_keyblock *hist_keyblock,
	       int n_new_key_data, krb5_key_data *new_key_data,
	       unsigned int n_pw_hist_data, osa_pw_hist_ent *pw_hist_data)
{
    int x, y, z;
    krb5_keyblock newkey, histkey;
    krb5_error_code ret;

    for (x = 0; x < n_new_key_data; x++) {
	ret = krb5_dbekd_decrypt_key_data(context,
					  master_keyblock,
					  &(new_key_data[x]),
					  &newkey, NULL);
	if (ret)
	    return(ret);
	for (y = 0; y < n_pw_hist_data; y++) {
	     for (z = 0; z < pw_hist_data[y].n_key_data; z++) {
		 ret = krb5_dbekd_decrypt_key_data(context,
						   hist_keyblock,
						   &pw_hist_data[y].key_data[z],
						   &histkey, NULL);
		 if (ret)
		     return(ret);		
		 
		 if ((newkey.length == histkey.length) &&
		     (newkey.enctype == histkey.enctype) &&
		     (memcmp(newkey.contents, histkey.contents,
			     histkey.length) == 0)) {
		     krb5_free_keyblock_contents(context, &histkey);
		     krb5_free_keyblock_contents(context, &newkey);
		     
		     return(KADM5_PASS_REUSE);
		 }
		 krb5_free_keyblock_contents(context, &histkey);
	     }
	}
	krb5_free_keyblock_contents(context, &newkey);
    }

    return(0);
}

/*
 * Function: create_history_entry
 *
 * Purpose: Creates a password history entry from an array of
 * key_data.
 *
 * Arguments:
 *
 *	context		(r) krb5_context to use
 *      master_keyblcok (r) master key block
 *	n_key_data	(r) number of elements in key_data
 *	key_data	(r) keys to add to the history entry
 *	hist		(w) history entry to fill in
 *
 * Effects:
 *
 * hist->key_data is allocated to store n_key_data key_datas.  Each
 * element of key_data is decrypted with master_keyblock, re-encrypted
 * in hist_key, and added to hist->key_data.  hist->n_key_data is
 * set to n_key_data.
 */
static
int create_history_entry(krb5_context context, 
	krb5_keyblock *master_keyblock,	int n_key_data,
	krb5_key_data *key_data, osa_pw_hist_ent *hist)
{
     int i, ret;
     krb5_keyblock key;
     krb5_keysalt salt;
     
     hist->key_data = (krb5_key_data*)malloc(n_key_data*sizeof(krb5_key_data));
     if (hist->key_data == NULL)
	  return ENOMEM;
     memset(hist->key_data, 0, n_key_data*sizeof(krb5_key_data));

     for (i = 0; i < n_key_data; i++) {
	 ret = krb5_dbekd_decrypt_key_data(context,
					   master_keyblock,
					   &key_data[i],
					   &key, &salt);
	 if (ret)
	     return ret;

	 ret = krb5_dbekd_encrypt_key_data(context, &hist_key,
					   &key, &salt,
					   key_data[i].key_data_kvno,
					   &hist->key_data[i]);
	 if (ret)
	     return ret;
	 
	 krb5_free_keyblock_contents(context, &key);
	 /* krb5_free_keysalt(context, &salt); */
     }

     hist->n_key_data = n_key_data;
     return 0;
}

static
void free_history_entry(krb5_context context, osa_pw_hist_ent *hist)
{
     int i;

     for (i = 0; i < hist->n_key_data; i++)
	  krb5_free_key_data_contents(context, &hist->key_data[i]);
     free(hist->key_data);
}

/*
 * Function: add_to_history
 *
 * Purpose: Adds a password to a principal's password history.
 *
 * Arguments:
 *
 *	context		(r) krb5_context to use
 *	adb		(r/w) admin principal entry to add keys to
 *	pol		(r) adb's policy
 *	pw		(r) keys for the password to add to adb's key history
 *
 * Effects:
 *
 * add_to_history adds a single password to adb's password history.
 * pw contains n_key_data keys in its key_data, in storage should be
 * allocated but not freed by the caller (XXX blech!).
 *
 * This function maintains adb->old_keys as a circular queue.  It
 * starts empty, and grows each time this function is called until it
 * is pol->pw_history_num items long.  adb->old_key_len holds the
 * number of allocated entries in the array, and must therefore be [0,
 * pol->pw_history_num).  adb->old_key_next is the index into the
 * array where the next element should be written, and must be [0,
 * adb->old_key_len).
 */
#define	KADM_MOD(x)	(x + adb->old_key_next) % adb->old_key_len
static kadm5_ret_t add_to_history(krb5_context context,
				  osa_princ_ent_t adb,
				  kadm5_policy_ent_t pol,
				  osa_pw_hist_ent *pw)
{
     osa_pw_hist_ent *histp;
     uint32_t nhist;
     unsigned int i, knext, nkeys;

     nhist = pol->pw_history_num;
     /* A history of 1 means just check the current password */
     if (nhist <= 1)
	  return 0;

     nkeys = adb->old_key_len;
     knext = adb->old_key_next;
     /* resize the adb->old_keys array if necessary */
     if (nkeys + 1 < nhist) {
	  if (adb->old_keys == NULL) {
	       adb->old_keys = (osa_pw_hist_ent *)
		    malloc((nkeys + 1) * sizeof (osa_pw_hist_ent));
	  } else {
	       adb->old_keys = (osa_pw_hist_ent *)
		    realloc(adb->old_keys,
			    (nkeys + 1) * sizeof (osa_pw_hist_ent));
	  }
	  if (adb->old_keys == NULL)
	       return(ENOMEM);
	  
	  memset(&adb->old_keys[nkeys], 0, sizeof(osa_pw_hist_ent));
     	  nkeys = ++adb->old_key_len;
	  /*
	   * To avoid losing old keys, shift forward each entry after
	   * knext.
	   */
	  for (i = nkeys - 1; i > knext; i--) {
	      adb->old_keys[i] = adb->old_keys[i - 1];
	  }
	  memset(&adb->old_keys[knext], 0, sizeof(osa_pw_hist_ent));
     } else if (nkeys + 1 > nhist) {
	 /*
	  * The policy must have changed!  Shrink the array.
	  * Can't simply realloc() down, since it might be wrapped.
	  * To understand the arithmetic below, note that we are
	  * copying into new positions 0 .. N-1 from old positions
	  * old_key_next-N .. old_key_next-1, modulo old_key_len,
	  * where N = pw_history_num - 1 is the length of the
	  * shortened list.        Matt Crawford, FNAL
	  */
	 /*
	  * M = adb->old_key_len, N = pol->pw_history_num - 1
	  *
	  * tmp[0] .. tmp[N-1] = old[(knext-N)%M] .. old[(knext-1)%M]
	  */
	 int j;
	 osa_pw_hist_t tmp;

	 tmp = (osa_pw_hist_ent *)
	     malloc((nhist - 1) * sizeof (osa_pw_hist_ent));
	 if (tmp == NULL)
	     return ENOMEM;
	 for (i = 0; i < nhist - 1; i++) {
	     /*
	      * Add nkeys once before taking remainder to avoid
	      * negative values.
	      */
	     j = (i + nkeys + knext - (nhist - 1)) % nkeys;
	     tmp[i] = adb->old_keys[j];
	 }
	 /* Now free the ones we don't keep (the oldest ones) */
	 for (i = 0; i < nkeys - (nhist - 1); i++) {
	     j = (i + nkeys + knext) % nkeys;
	     histp = &adb->old_keys[j];
	     for (j = 0; j < histp->n_key_data; j++) {
		 krb5_free_key_data_contents(context, &histp->key_data[j]);
	     }
	     free(histp->key_data);
	 }
	 free((void *)adb->old_keys);
	 adb->old_keys = tmp;
	 nkeys = adb->old_key_len = nhist - 1;
	 knext = adb->old_key_next = 0;
     }

     /*
      * If nhist decreased since the last password change, and nkeys+1
      * is less than the previous nhist, it is possible for knext to
      * index into unallocated space.  This condition would not be
      * caught by the resizing code above.
      */
     if (knext + 1 > nkeys)
	 knext = adb->old_key_next = 0;
     /* free the old pw history entry if it contains data */
     histp = &adb->old_keys[knext];
     for (i = 0; i < histp->n_key_data; i++)
	  krb5_free_key_data_contents(context, &histp->key_data[i]);
     free(histp->key_data);

     /* store the new entry */
     adb->old_keys[knext] = *pw;

     /* update the next pointer */
     if (++adb->old_key_next == nhist - 1)
	 adb->old_key_next = 0;

     return(0);
}
#undef KADM_MOD

#ifdef USE_PASSWORD_SERVER
/* FIXME: don't use global variable for this */
krb5_boolean use_password_server = 0;

static krb5_boolean
kadm5_use_password_server (void)
{
    return use_password_server;
}

void
kadm5_set_use_password_server (void)
{
    use_password_server = 1;
}
#endif

#ifdef USE_PASSWORD_SERVER

/*
 * kadm5_launch_task () runs a program (task_path) to synchronize the 
 * Apple password server with the Kerberos database.  Password server
 * programs can receive arguments on the command line (task_argv)
 * and a block of data via stdin (data_buffer).
 *
 * Because a failure to communicate with the tool results in the
 * password server falling out of sync with the database,
 * kadm5_launch_task() always fails if it can't talk to the tool.
 */

static kadm5_ret_t
kadm5_launch_task (krb5_context context,
                   const char *task_path, char * const task_argv[],
                   const char *data_buffer) 
{
    kadm5_ret_t ret = 0;
    int data_pipe[2];
    
    if (data_buffer != NULL) {
        ret = pipe (data_pipe);
        if (ret) { ret = errno; }
    }

    if (!ret) {
        pid_t pid = fork ();
        if (pid == -1) {
            ret = errno;
        } else if (pid == 0) {
            /* The child: */
            
            if (data_buffer != NULL) {
                if (dup2 (data_pipe[0], STDIN_FILENO) == -1) {
                    _exit (1);
                }
            } else {
                close (data_pipe[0]);
            }

            close (data_pipe[1]);
            
            execv (task_path, task_argv);
            
            _exit (1); /* Fail if execv fails */
        } else {
            /* The parent: */
            int status;
                       
            if (data_buffer != NULL) {
                /* Write out the buffer to the child */
                if (krb5_net_write (context, data_pipe[1],
                                    data_buffer, strlen (data_buffer)) < 0) {
                    /* kill the child to make sure waitpid() won't hang later */
                    ret = errno;
                    kill (pid, SIGKILL);
                }
            }

            close (data_buffer[0]);
            close (data_buffer[1]);

            waitpid (pid, &status, 0);

            if (!ret) {
                if (WIFEXITED (status)) {
                    /* child read password and exited.  Check the return value. */
                    if ((WEXITSTATUS (status) != 0) && (WEXITSTATUS (status) != 252)) {
                       ret = KRB5KDC_ERR_POLICY; /* password change rejected */
                    }
                } else {
                    /* child read password but crashed or was killed */
                    ret = KRB5KRB_ERR_GENERIC; /* FIXME: better error */
                }
            }
        }
    }

    return ret;
}

#endif

kadm5_ret_t
kadm5_chpass_principal(void *server_handle,
			    krb5_principal principal, char *password)
{
    return
	kadm5_chpass_principal_3(server_handle, principal, FALSE,
				 0, NULL, password);
}

kadm5_ret_t
kadm5_chpass_principal_3(void *server_handle,
			 krb5_principal principal, krb5_boolean keepold,
			 int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
			 char *password)
{
    krb5_int32			now;
    kadm5_policy_ent_rec	pol;
    osa_princ_ent_rec		adb;
    krb5_db_entry		kdb, kdb_save;
    int				ret, ret2, last_pwd, hist_added;
    int				have_pol = 0;
    kadm5_server_handle_t	handle = server_handle;
    osa_pw_hist_ent		hist;

    CHECK_HANDLE(server_handle);

    /* Solaris Kerberos - kadm5_check_min_life checks for null principal. */
    ret = kadm5_check_min_life(server_handle,principal,NULL,0);
    if (ret)
	return (ret);
    krb5_clear_error_message(handle->context);

    hist_added = 0;
    memset(&hist, 0, sizeof(hist));

    if (principal == NULL || password == NULL)
	return EINVAL;
    if ((krb5_principal_compare(handle->context,
				principal, hist_princ)) == TRUE)
	return KADM5_PROTECT_PRINCIPAL;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
       return(ret);

    /* we are going to need the current keys after the new keys are set */
    if ((ret = kdb_get_entry(handle, principal, &kdb_save, NULL))) {
	 kdb_free_entry(handle, &kdb, &adb);
	 return(ret);
    }
    
    if ((adb.aux_attributes & KADM5_POLICY)) {
	if ((ret = kadm5_get_policy(handle->lhandle, adb.policy, &pol)))
	     goto done;
	have_pol = 1;
    }

    if ((ret = passwd_check(handle, password, adb.aux_attributes &
			    KADM5_POLICY, &pol, principal)))
	 goto done;

    ret = krb5_dbe_cpw(handle->context, &handle->master_keyblock,
		       n_ks_tuple?ks_tuple:handle->params.keysalts,
		       n_ks_tuple?n_ks_tuple:handle->params.num_keysalts,
		       password, 0 /* increment kvno */,
		       keepold, &kdb);
    if (ret)
	goto done;

    kdb.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;

    ret = krb5_timeofday(handle->context, &now);
    if (ret)
	 goto done;
    
    if ((adb.aux_attributes & KADM5_POLICY)) {
       /* the policy was loaded before */

	ret = krb5_dbe_lookup_last_pwd_change(handle->context,
					      &kdb, &last_pwd);
	if (ret)
	    goto done;

#if 0
	 /*
	  * The spec says this check is overridden if the caller has
	  * modify privilege.  The admin server therefore makes this
	  * check itself (in chpass_principal_wrapper, misc.c). A
	  * local caller implicitly has all authorization bits.
	  */
	if ((now - last_pwd) < pol.pw_min_life &&
	    !(kdb.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
	     ret = KADM5_PASS_TOOSOON;
	     goto done;
	}
#endif

	ret = create_history_entry(handle->context,
				   &handle->master_keyblock, kdb_save.n_key_data,
				   kdb_save.key_data, &hist);
	if (ret)
	    goto done;

	ret = check_pw_reuse(handle->context,
			     &handle->master_keyblock,
			     &hist_key,
			     kdb.n_key_data, kdb.key_data,
			     1, &hist);
	if (ret)
	    goto done;
	 
	if (pol.pw_history_num > 1) {
	    if (adb.admin_history_kvno != hist_kvno) {
		ret = KADM5_BAD_HIST_KEY;
		goto done;
	    }

	    ret = check_pw_reuse(handle->context,
				&handle->master_keyblock,
				     &hist_key,
				 kdb.n_key_data, kdb.key_data,
				 adb.old_key_len, adb.old_keys);
	    if (ret)
		goto done;

	    ret = add_to_history(handle->context, &adb, &pol, &hist);
	    if (ret)
		goto done;
	    hist_added = 1;
       }

	if (pol.pw_max_life)
	   kdb.pw_expiration = now + pol.pw_max_life;
	else
	   kdb.pw_expiration = 0;
    } else {
	kdb.pw_expiration = 0;
    }

#ifdef USE_PASSWORD_SERVER
    if (kadm5_use_password_server () &&
        (krb5_princ_size (handle->context, principal) == 1)) {
        krb5_data *princ = krb5_princ_component (handle->context, principal, 0);
        const char *path = "/usr/sbin/mkpassdb";
        char *argv[] = { "mkpassdb", "-setpassword", NULL, NULL };
        char *pstring = NULL;
        char pwbuf[256];
        int pwlen = strlen (password);

        if (pwlen > 254) pwlen = 254;
        strncpy (pwbuf, password, pwlen);
        pwbuf[pwlen] = '\n';
        pwbuf[pwlen + 1] = '\0';

        if (!ret) {
            pstring = malloc ((princ->length + 1) * sizeof (char));
            if (pstring == NULL) { ret = errno; }
        }

        if (!ret) {
            memcpy (pstring, princ->data, princ->length);
            pstring [princ->length] = '\0';
            argv[2] = pstring;

            ret = kadm5_launch_task (handle->context, path, argv, pwbuf);
        }
        
        if (pstring != NULL)
            free (pstring);
        
        if (ret)
            goto done;
    }
#endif

    ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now);
    if (ret)
	goto done;

    /* key data and attributes changed, let the database provider know */
    /* Solaris Kerberos: adding support for key history in LDAP KDB */
    if (hist_added == 1)
	kdb.mask = KADM5_KEY_DATA | KADM5_ATTRIBUTES | KADM5_KEY_HIST
	    /* | KADM5_CPW_FUNCTION */;
    else
	kdb.mask = KADM5_KEY_DATA | KADM5_ATTRIBUTES /* | KADM5_CPW_FUNCTION */;

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
	goto done;

    ret = KADM5_OK;
done:
    if (!hist_added && hist.key_data)
	 free_history_entry(handle->context, &hist);
    kdb_free_entry(handle, &kdb, &adb);
    kdb_free_entry(handle, &kdb_save, NULL);
    krb5_db_free_principal(handle->context, &kdb, 1);

    if (have_pol && (ret2 = kadm5_free_policy_ent(handle->lhandle, &pol))
	&& !ret) 
	 ret = ret2;

    return ret;
}

kadm5_ret_t
kadm5_randkey_principal(void *server_handle,
			krb5_principal principal,
			krb5_keyblock **keyblocks,
			int *n_keys)
{
	 /* Solaris Kerberos: */
	krb5_key_salt_tuple keysalts[2];

	/*
	 * Anyone calling this routine is forced to use only DES
	 * enctypes to be compatible with earlier releases that
	 * did not support stronger crypto.
	 *
	 * S10 (and later) kadmin clients will not use this API,
	 * so we can assume the request is from an older version.
	 */
	keysalts[0].ks_enctype = ENCTYPE_DES_CBC_MD5;
	keysalts[0].ks_salttype = KRB5_KDB_SALTTYPE_NORMAL;
	keysalts[1].ks_enctype = ENCTYPE_DES_CBC_CRC;
	keysalts[1].ks_salttype = KRB5_KDB_SALTTYPE_NORMAL;

	return (kadm5_randkey_principal_3(server_handle, principal,
			FALSE, 2, keysalts, keyblocks, n_keys));
}
kadm5_ret_t
kadm5_randkey_principal_3(void *server_handle,
			krb5_principal principal,
			krb5_boolean keepold,
			int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
			krb5_keyblock **keyblocks,
			int *n_keys)
{
    krb5_db_entry		kdb;
    osa_princ_ent_rec		adb;
    krb5_int32			now;
    kadm5_policy_ent_rec	pol;
    krb5_key_data		*key_data;
    int				ret, last_pwd, have_pol = 0;
    kadm5_server_handle_t	handle = server_handle;

    if (keyblocks)
	 *keyblocks = NULL;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (principal == NULL)
	return EINVAL;
    if (hist_princ && /* this will be NULL when initializing the databse */
	((krb5_principal_compare(handle->context,
				 principal, hist_princ)) == TRUE))
	return KADM5_PROTECT_PRINCIPAL;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
       return(ret);

    ret = krb5_dbe_crk(handle->context, &handle->master_keyblock,
		       n_ks_tuple?ks_tuple:handle->params.keysalts,
		       n_ks_tuple?n_ks_tuple:handle->params.num_keysalts,
		       keepold,
		       &kdb);
    if (ret)
	goto done;

    kdb.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;

    ret = krb5_timeofday(handle->context, &now);
    if (ret)
	goto done;

    if ((adb.aux_attributes & KADM5_POLICY)) {
	if ((ret = kadm5_get_policy(handle->lhandle, adb.policy,
				    &pol)) != KADM5_OK) 
	   goto done;
	have_pol = 1;

	ret = krb5_dbe_lookup_last_pwd_change(handle->context,
					      &kdb, &last_pwd);
	if (ret)
	     goto done;

#if 0
	 /*
	  * The spec says this check is overridden if the caller has
	  * modify privilege.  The admin server therefore makes this
	  * check itself (in chpass_principal_wrapper, misc.c).  A
	  * local caller implicitly has all authorization bits.
	  */
	if((now - last_pwd) < pol.pw_min_life &&
	   !(kdb.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
	     ret = KADM5_PASS_TOOSOON;
	     goto done;
	}
#endif

	if(pol.pw_history_num > 1) {
	    if(adb.admin_history_kvno != hist_kvno) {
		ret = KADM5_BAD_HIST_KEY;
		goto done;
	    }

	    ret = check_pw_reuse(handle->context,
				 &handle->master_keyblock,
				 &hist_key,
				 kdb.n_key_data, kdb.key_data,
				 adb.old_key_len, adb.old_keys);
	    if (ret)
		goto done;
	}
	if (pol.pw_max_life)
	   kdb.pw_expiration = now + pol.pw_max_life;
	else
	   kdb.pw_expiration = 0;
    } else {
	kdb.pw_expiration = 0;
    }

    ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now);
    if (ret)
	 goto done;

    if (keyblocks) {
	 if (handle->api_version == KADM5_API_VERSION_1) {
	      /* Version 1 clients will expect to see a DES_CRC enctype. */
	     ret = krb5_dbe_find_enctype(handle->context, &kdb,
					 ENCTYPE_DES_CBC_CRC,
					 -1, -1, &key_data);
	     if (ret)
		 goto done;
	     
	     ret = decrypt_key_data(handle->context,
				&handle->master_keyblock, 1, key_data,
				     keyblocks, NULL);
	     if (ret)
		 goto done;
	 } else {
	     ret = decrypt_key_data(handle->context,
				     &handle->master_keyblock,
				     kdb.n_key_data, kdb.key_data,
				     keyblocks, n_keys);
	     if (ret)
		 goto done;
	 }
    }	 
    
    /* key data changed, let the database provider know */
    kdb.mask = KADM5_KEY_DATA /* | KADM5_RANDKEY_USED */;

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
	goto done;

    ret = KADM5_OK;
done:
    kdb_free_entry(handle, &kdb, &adb);
    if (have_pol)
	 kadm5_free_policy_ent(handle->lhandle, &pol);

    return ret;
}

#if 0 /* Solaris Kerberos */
/*
 * kadm5_setv4key_principal:
 *
 * Set only ONE key of the principal, removing all others.  This key
 * must have the DES_CBC_CRC enctype and is entered as having the
 * krb4 salttype.  This is to enable things like kadmind4 to work.
 */
kadm5_ret_t
kadm5_setv4key_principal(void *server_handle,
		       krb5_principal principal,
		       krb5_keyblock *keyblock)
{
    krb5_db_entry		kdb;
    osa_princ_ent_rec		adb;
    krb5_int32			now;
    kadm5_policy_ent_rec	pol;
    krb5_keysalt		keysalt;
    int				i, k, kvno, ret, have_pol = 0;
#if 0
    int                         last_pwd;
#endif
    kadm5_server_handle_t	handle = server_handle;
    krb5_key_data               tmp_key_data;

    memset( &tmp_key_data, 0, sizeof(tmp_key_data));

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (principal == NULL || keyblock == NULL)
	return EINVAL;
    if (hist_princ && /* this will be NULL when initializing the databse */
	((krb5_principal_compare(handle->context,
				 principal, hist_princ)) == TRUE))
	return KADM5_PROTECT_PRINCIPAL;

    if (keyblock->enctype != ENCTYPE_DES_CBC_CRC)
	return KADM5_SETV4KEY_INVAL_ENCTYPE;
    
    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
       return(ret);

    for (kvno = 0, i=0; i<kdb.n_key_data; i++)
	 if (kdb.key_data[i].key_data_kvno > kvno)
	      kvno = kdb.key_data[i].key_data_kvno;

    if (kdb.key_data != NULL)
	 cleanup_key_data(handle->context, kdb.n_key_data, kdb.key_data);
    
    kdb.key_data = (krb5_key_data*)krb5_db_alloc(handle->context, NULL, sizeof(krb5_key_data));
    if (kdb.key_data == NULL)
	 return ENOMEM;
    memset(kdb.key_data, 0, sizeof(krb5_key_data));
    kdb.n_key_data = 1;
    keysalt.type = KRB5_KDB_SALTTYPE_V4;
    /* XXX data.magic? */
    keysalt.data.length = 0;
    keysalt.data.data = NULL;

    /* use tmp_key_data as temporary location and reallocate later */
    ret = krb5_dbekd_encrypt_key_data(handle->context, &master_keyblock,
				      keyblock, &keysalt, kvno + 1,
				      &tmp_key_data);
    if (ret) {
	goto done;
    }

    for (k = 0; k < tmp_key_data.key_data_ver; k++) {
	kdb.key_data->key_data_type[k] = tmp_key_data.key_data_type[k];
	kdb.key_data->key_data_length[k] = tmp_key_data.key_data_length[k];
	if (tmp_key_data.key_data_contents[k]) {
	    kdb.key_data->key_data_contents[k] = krb5_db_alloc(handle->context, NULL, tmp_key_data.key_data_length[k]);
	    if (kdb.key_data->key_data_contents[k] == NULL) {
		cleanup_key_data(handle->context, kdb.n_key_data, kdb.key_data);
		kdb.key_data = NULL;
		kdb.n_key_data = 0;
		ret = ENOMEM;
		goto done;
	    }
	    memcpy (kdb.key_data->key_data_contents[k], tmp_key_data.key_data_contents[k], tmp_key_data.key_data_length[k]);

	    memset (tmp_key_data.key_data_contents[k], 0, tmp_key_data.key_data_length[k]);
	    free (tmp_key_data.key_data_contents[k]);
	    tmp_key_data.key_data_contents[k] = NULL;
	}
    }



    kdb.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;

    ret = krb5_timeofday(handle->context, &now);
    if (ret)
	goto done;

    if ((adb.aux_attributes & KADM5_POLICY)) {
	if ((ret = kadm5_get_policy(handle->lhandle, adb.policy,
				    &pol)) != KADM5_OK) 
	   goto done;
	have_pol = 1;

#if 0
	/*
	  * The spec says this check is overridden if the caller has
	  * modify privilege.  The admin server therefore makes this
	  * check itself (in chpass_principal_wrapper, misc.c).  A
	  * local caller implicitly has all authorization bits.
	  */
	if (ret = krb5_dbe_lookup_last_pwd_change(handle->context,
						  &kdb, &last_pwd))
	     goto done;
	if((now - last_pwd) < pol.pw_min_life &&
	   !(kdb.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
	     ret = KADM5_PASS_TOOSOON;
	     goto done;
	}
#endif
#if 0
	/*
	 * Should we be checking/updating pw history here?
	 */
	if(pol.pw_history_num > 1) {
	    if(adb.admin_history_kvno != hist_kvno) {
		ret = KADM5_BAD_HIST_KEY;
		goto done;
	    }

	    if (ret = check_pw_reuse(handle->context,
				     &hist_key,
				     kdb.n_key_data, kdb.key_data,
				     adb.old_key_len, adb.old_keys))
		goto done;
	}
#endif
	
	if (pol.pw_max_life)
	   kdb.pw_expiration = now + pol.pw_max_life;
	else
	   kdb.pw_expiration = 0;
    } else {
	kdb.pw_expiration = 0;
    }

    ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now);
    if (ret)
	 goto done;

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
	goto done;

    ret = KADM5_OK;
done:
    for (i = 0; i < tmp_key_data.key_data_ver; i++) {
	if (tmp_key_data.key_data_contents[i]) {
	    memset (tmp_key_data.key_data_contents[i], 0, tmp_key_data.key_data_length[i]);
	    free (tmp_key_data.key_data_contents[i]);
	}
    }

    kdb_free_entry(handle, &kdb, &adb);
    if (have_pol)
	 kadm5_free_policy_ent(handle->lhandle, &pol);

    return ret;
}
#endif

kadm5_ret_t
kadm5_setkey_principal(void *server_handle,
		       krb5_principal principal,
		       krb5_keyblock *keyblocks,
		       int n_keys)
{
    return
	kadm5_setkey_principal_3(server_handle, principal,
				 FALSE, 0, NULL,
				 keyblocks, n_keys);
}

kadm5_ret_t
kadm5_setkey_principal_3(void *server_handle,
			 krb5_principal principal,
			 krb5_boolean keepold,
			 int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
			 krb5_keyblock *keyblocks,
			 int n_keys)
{
    krb5_db_entry		kdb;
    osa_princ_ent_rec		adb;
    krb5_int32			now;
    kadm5_policy_ent_rec	pol;
    krb5_key_data		*old_key_data;
    int				n_old_keys;
    int				i, j, k, kvno, ret, have_pol = 0;
#if 0
    int                         last_pwd;
#endif
    kadm5_server_handle_t	handle = server_handle;
    krb5_boolean		similar;
    krb5_keysalt		keysalt;
    krb5_key_data         tmp_key_data;
    krb5_key_data        *tptr;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (principal == NULL || keyblocks == NULL)
	return EINVAL;
    if (hist_princ && /* this will be NULL when initializing the databse */
	((krb5_principal_compare(handle->context,
				 principal, hist_princ)) == TRUE))
	return KADM5_PROTECT_PRINCIPAL;

    for (i = 0; i < n_keys; i++) {
	for (j = i+1; j < n_keys; j++) {
	    if ((ret = krb5_c_enctype_compare(handle->context,
					      keyblocks[i].enctype,
					      keyblocks[j].enctype,
					      &similar)))
		return(ret);
	    if (similar) {
		if (n_ks_tuple) {
		    if (ks_tuple[i].ks_salttype == ks_tuple[j].ks_salttype)
			return KADM5_SETKEY_DUP_ENCTYPES;
		} else
		    return KADM5_SETKEY_DUP_ENCTYPES;
	    }
	}
    }

    if (n_ks_tuple && n_ks_tuple != n_keys)
	return KADM5_SETKEY3_ETYPE_MISMATCH;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
       return(ret);
    
    for (kvno = 0, i=0; i<kdb.n_key_data; i++)
	 if (kdb.key_data[i].key_data_kvno > kvno)
	      kvno = kdb.key_data[i].key_data_kvno;

    if (keepold) {
	old_key_data = kdb.key_data;
	n_old_keys = kdb.n_key_data;
    } else {
	if (kdb.key_data != NULL)
	    cleanup_key_data(handle->context, kdb.n_key_data, kdb.key_data);
	n_old_keys = 0;
	old_key_data = NULL;
    }
    
    kdb.key_data = (krb5_key_data*)krb5_db_alloc(handle->context, NULL, (n_keys+n_old_keys)
						 *sizeof(krb5_key_data));
    if (kdb.key_data == NULL) {
	ret = ENOMEM;
	goto done;
    }

    memset(kdb.key_data, 0, (n_keys+n_old_keys)*sizeof(krb5_key_data));
    kdb.n_key_data = 0;

    for (i = 0; i < n_keys; i++) {
	if (n_ks_tuple) {
	    keysalt.type = ks_tuple[i].ks_salttype;
	    keysalt.data.length = 0;
	    keysalt.data.data = NULL;
	    if (ks_tuple[i].ks_enctype != keyblocks[i].enctype) {
		ret = KADM5_SETKEY3_ETYPE_MISMATCH;
		goto done;
	    }
	}
	memset (&tmp_key_data, 0, sizeof(tmp_key_data));

	ret = krb5_dbekd_encrypt_key_data(handle->context,
					  &handle->master_keyblock,
					  &keyblocks[i],
					  n_ks_tuple ? &keysalt : NULL,
					  kvno + 1,
					  &tmp_key_data);
	if (ret) {
	    goto done;
	}
	tptr = &kdb.key_data[i];
	for (k = 0; k < tmp_key_data.key_data_ver; k++) {
	    tptr->key_data_type[k] = tmp_key_data.key_data_type[k];
	    tptr->key_data_length[k] = tmp_key_data.key_data_length[k];
	    if (tmp_key_data.key_data_contents[k]) {
		tptr->key_data_contents[k] = krb5_db_alloc(handle->context, NULL, tmp_key_data.key_data_length[k]);
		if (tptr->key_data_contents[k] == NULL) {
		    int i1;
		    for (i1 = k; i1 < tmp_key_data.key_data_ver; i1++) {
			if (tmp_key_data.key_data_contents[i1]) {
			    memset (tmp_key_data.key_data_contents[i1], 0, tmp_key_data.key_data_length[i1]);
			    free (tmp_key_data.key_data_contents[i1]);
			}
		    }

		    ret =  ENOMEM;
		    goto done;
		}
		memcpy (tptr->key_data_contents[k], tmp_key_data.key_data_contents[k], tmp_key_data.key_data_length[k]);

		memset (tmp_key_data.key_data_contents[k], 0, tmp_key_data.key_data_length[k]);
		free (tmp_key_data.key_data_contents[k]);
		tmp_key_data.key_data_contents[k] = NULL;
	    }
	}
	kdb.n_key_data++;
    }

    /* copy old key data if necessary */
    for (i = 0; i < n_old_keys; i++) {
	kdb.key_data[i+n_keys] = old_key_data[i];
	memset(&old_key_data[i], 0, sizeof (krb5_key_data));
	kdb.n_key_data++;
    }

    if (old_key_data)
	krb5_db_free(handle->context, old_key_data);

    /* assert(kdb.n_key_data == n_keys + n_old_keys) */
    kdb.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;

    if ((ret = krb5_timeofday(handle->context, &now)))
	goto done;

    if ((adb.aux_attributes & KADM5_POLICY)) {
	if ((ret = kadm5_get_policy(handle->lhandle, adb.policy,
				    &pol)) != KADM5_OK) 
	   goto done;
	have_pol = 1;

#if 0
	/*
	  * The spec says this check is overridden if the caller has
	  * modify privilege.  The admin server therefore makes this
	  * check itself (in chpass_principal_wrapper, misc.c).  A
	  * local caller implicitly has all authorization bits.
	  */
	if (ret = krb5_dbe_lookup_last_pwd_change(handle->context,
						  &kdb, &last_pwd))
	     goto done;
	if((now - last_pwd) < pol.pw_min_life &&
	   !(kdb.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
	     ret = KADM5_PASS_TOOSOON;
	     goto done;
	}
#endif
#if 0
	/*
	 * Should we be checking/updating pw history here?
	 */
	if (pol.pw_history_num > 1) {
	    if(adb.admin_history_kvno != hist_kvno) {
		ret = KADM5_BAD_HIST_KEY;
		goto done;
	    }

	    if (ret = check_pw_reuse(handle->context,
				&handle->master_keyblock,
				     &hist_key,
				     kdb.n_key_data, kdb.key_data,
				     adb.old_key_len, adb.old_keys))
		goto done;
	}
#endif
	
	if (pol.pw_max_life)
	   kdb.pw_expiration = now + pol.pw_max_life;
	else
	   kdb.pw_expiration = 0;
    } else {
	kdb.pw_expiration = 0;
    }

    if ((ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now)))
        goto done;

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
	goto done;

    ret = KADM5_OK;
done:
    kdb_free_entry(handle, &kdb, &adb);
    if (have_pol)
	 kadm5_free_policy_ent(handle->lhandle, &pol);

    return ret;
}

/*
 * Allocate an array of n_key_data krb5_keyblocks, fill in each
 * element with the results of decrypting the nth key in key_data with
 * master_keyblock, and if n_keys is not NULL fill it in with the
 * number of keys decrypted.
 */
static int decrypt_key_data(krb5_context context,
			    krb5_keyblock *master_keyblock,
			    int n_key_data, krb5_key_data *key_data,
			    krb5_keyblock **keyblocks, int *n_keys)
{
     krb5_keyblock *keys;
     int ret, i;

     keys = (krb5_keyblock *) malloc(n_key_data*sizeof(krb5_keyblock));
     if (keys == NULL)
	  return ENOMEM;
     memset((char *) keys, 0, n_key_data*sizeof(krb5_keyblock));

     for (i = 0; i < n_key_data; i++) {
          ret = krb5_dbekd_decrypt_key_data(context,
					    master_keyblock,
					    &key_data[i], 
					    &keys[i], NULL);
	  if (ret) {
	       for (; i >= 0; i--) {
		   if (keys[i].contents) {
		       memset (keys[i].contents, 0, keys[i].length);
		       free( keys[i].contents );
		   }
	       }

	       memset((char *) keys, 0, n_key_data*sizeof(krb5_keyblock));
	       free(keys);
	       return ret;
	  }
     }

     *keyblocks = keys;
     if (n_keys)
	  *n_keys = n_key_data;

     return 0;
}

/*
 * Function: kadm5_decrypt_key
 *
 * Purpose: Retrieves and decrypts a principal key.
 *
 * Arguments:
 *
 *	server_handle	(r) kadm5 handle
 *	entry		(r) principal retrieved with kadm5_get_principal
 *	ktype		(r) enctype to search for, or -1 to ignore
 *	stype		(r) salt type to search for, or -1 to ignore
 *	kvno		(r) kvno to search for, -1 for max, 0 for max
 *			only if it also matches ktype and stype
 *	keyblock	(w) keyblock to fill in
 *	keysalt		(w) keysalt to fill in, or NULL
 *	kvnop		(w) kvno to fill in, or NULL
 *
 * Effects: Searches the key_data array of entry, which must have been
 * retrived with kadm5_get_principal with the KADM5_KEY_DATA mask, to
 * find a key with a specified enctype, salt type, and kvno in a
 * principal entry.  If not found, return ENOENT.  Otherwise, decrypt
 * it with the master key, and return the key in keyblock, the salt
 * in salttype, and the key version number in kvno.
 *
 * If ktype or stype is -1, it is ignored for the search.  If kvno is
 * -1, ktype and stype are ignored and the key with the max kvno is
 * returned.  If kvno is 0, only the key with the max kvno is returned
 * and only if it matches the ktype and stype; otherwise, ENOENT is
 * returned.
 */
kadm5_ret_t kadm5_decrypt_key(void *server_handle,
			      kadm5_principal_ent_t entry, krb5_int32
			      ktype, krb5_int32 stype, krb5_int32
			      kvno, krb5_keyblock *keyblock,
			      krb5_keysalt *keysalt, int *kvnop)
{
    kadm5_server_handle_t handle = server_handle;
    krb5_db_entry dbent;
    krb5_key_data *key_data;
    int ret;

    CHECK_HANDLE(server_handle);

    if (entry->n_key_data == 0 || entry->key_data == NULL)
	 return EINVAL;

    /* find_enctype only uses these two fields */
    dbent.n_key_data = entry->n_key_data;
    dbent.key_data = entry->key_data;
    if ((ret = krb5_dbe_find_enctype(handle->context, &dbent, ktype,
				    stype, kvno, &key_data)))
	 return ret;

    if ((ret = krb5_dbekd_decrypt_key_data(handle->context,
					   &handle->master_keyblock, key_data,
					   keyblock, keysalt)))
	 return ret;

    /*
     * Coerce the enctype of the output keyblock in case we got an
     * inexact match on the enctype; this behavior will go away when
     * the key storage architecture gets redesigned for 1.3.
     */
    keyblock->enctype = ktype;

    if (kvnop)
	 *kvnop = key_data->key_data_kvno;

    return KADM5_OK;
}

/* Solaris Kerberos */
kadm5_ret_t
kadm5_check_min_life(void *server_handle, krb5_principal principal,
	       char *msg_ret, unsigned int msg_len)
{
    krb5_int32			now;
    kadm5_ret_t			ret;
    kadm5_policy_ent_rec	pol;
    kadm5_principal_ent_rec	princ;
    kadm5_server_handle_t	handle = server_handle;

    if (msg_ret != NULL)
	*msg_ret = '\0';

    ret = krb5_timeofday(handle->context, &now);
    if (ret)
	return ret;

    ret = kadm5_get_principal(handle->lhandle, principal, 
			      &princ, KADM5_PRINCIPAL_NORMAL_MASK);
    if(ret) 
	 return ret;
    if(princ.aux_attributes & KADM5_POLICY) {
	if((ret=kadm5_get_policy(handle->lhandle,
				 princ.policy, &pol)) != KADM5_OK) {
	    (void) kadm5_free_principal_ent(handle->lhandle, &princ);
	    return ret;
	}
	if((now - princ.last_pwd_change) < pol.pw_min_life &&
	   !(princ.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
	    if (msg_ret != NULL) {
		time_t until;
		char *time_string, *ptr, *errstr;

		until = princ.last_pwd_change + pol.pw_min_life;

		time_string = ctime(&until);
		errstr = (char *)error_message(CHPASS_UTIL_PASSWORD_TOO_SOON);

		if (strlen(errstr) + strlen(time_string) >= msg_len) {
		    *errstr = '\0';
		} else {
		    if (*(ptr = &time_string[strlen(time_string)-1]) == '\n')
			*ptr = '\0';
		    sprintf(msg_ret, errstr, time_string);
		}
	    }

	    (void) kadm5_free_policy_ent(handle->lhandle, &pol);
	    (void) kadm5_free_principal_ent(handle->lhandle, &princ);
	    return KADM5_PASS_TOOSOON;
	}

	ret = kadm5_free_policy_ent(handle->lhandle, &pol);
	if (ret) {
	    (void) kadm5_free_principal_ent(handle->lhandle, &princ);
	    return ret;
        }
    }

    return kadm5_free_principal_ent(handle->lhandle, &princ);
}
