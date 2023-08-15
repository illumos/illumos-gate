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
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include	"server_internal.h"
#include	<sys/types.h>
#include	<kadm5/admin.h>
#include	<stdlib.h>
#include	<errno.h>

#define MAX_PW_HISTORY	10
#define MIN_PW_HISTORY	1
#define	MIN_PW_CLASSES	1
#define MAX_PW_CLASSES	5
#define	MIN_PW_LENGTH	1

/*
 * Function: kadm5_create_policy
 *
 * Purpose: Create Policies in the policy DB.
 *
 * Arguments:
 *	entry	(input) The policy entry to be written out to the DB.
 *	mask	(input)	Specifies which fields in entry are to ge written out
 *			and which get default values.
 *	<return value> 0 if successful otherwise an error code is returned.
 *
 * Requires:
 *	Entry must be a valid principal entry, and mask have a valid value.
 *
 * Effects:
 *	Verifies that mask does not specify that the refcount should
 *	be set as part of the creation, and calls
 *	kadm5_create_policy_internal.  If the refcount *is*
 *	specified, returns KADM5_BAD_MASK.
 */

kadm5_ret_t
kadm5_create_policy(void *server_handle,
			 kadm5_policy_ent_t entry, long mask)
{
    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(((kadm5_server_handle_t)server_handle)->context);

    if (mask & KADM5_REF_COUNT)
	return KADM5_BAD_MASK;
    else
	return kadm5_create_policy_internal(server_handle, entry, mask);
}

/*
 * Function: kadm5_create_policy_internal
 *
 * Purpose: Create Policies in the policy DB.
 *
 * Arguments:
 *	entry	(input) The policy entry to be written out to the DB.
 *	mask	(input)	Specifies which fields in entry are to ge written out
 *			and which get default values.
 *	<return value> 0 if successful otherwise an error code is returned.
 *
 * Requires:
 *	Entry must be a valid principal entry, and mask have a valid value.
 *
 * Effects:
 *	Writes the data to the database, and does a database sync if
 *	successful.
 *
 */

kadm5_ret_t
kadm5_create_policy_internal(void *server_handle,
				  kadm5_policy_ent_t entry, long mask)
{
    kadm5_server_handle_t handle = server_handle;
    osa_policy_ent_rec	pent;
    int			ret;
    char		*p;

    CHECK_HANDLE(server_handle);

    if ((entry == (kadm5_policy_ent_t) NULL) || (entry->policy == NULL))
	return EINVAL;
    if(strlen(entry->policy) == 0)
	return KADM5_BAD_POLICY;
    if (!(mask & KADM5_POLICY))
	return KADM5_BAD_MASK;

    pent.name = entry->policy;
    p = entry->policy;
    while(*p != '\0') {
	if(*p < ' ' || *p > '~')
	    return KADM5_BAD_POLICY;
	else
	    p++;
    }
    if (!(mask & KADM5_PW_MAX_LIFE))
	pent.pw_max_life = 0;
    else
	pent.pw_max_life = entry->pw_max_life;
    if (!(mask & KADM5_PW_MIN_LIFE))
	pent.pw_min_life = 0;
    else {
	if((mask & KADM5_PW_MAX_LIFE)) {
	    if(entry->pw_min_life > entry->pw_max_life && entry->pw_max_life != 0)
		return KADM5_BAD_MIN_PASS_LIFE;
	}
	pent.pw_min_life = entry->pw_min_life;
    }
    if (!(mask & KADM5_PW_MIN_LENGTH))
	pent.pw_min_length = MIN_PW_LENGTH;
    else {
	if(entry->pw_min_length < MIN_PW_LENGTH)
	    return KADM5_BAD_LENGTH;
	pent.pw_min_length = entry->pw_min_length;
    }
    if (!(mask & KADM5_PW_MIN_CLASSES))
	pent.pw_min_classes = MIN_PW_CLASSES;
    else {
	if(entry->pw_min_classes > MAX_PW_CLASSES || entry->pw_min_classes < MIN_PW_CLASSES)
	    return KADM5_BAD_CLASS;
	pent.pw_min_classes = entry->pw_min_classes;
    }
    if (!(mask & KADM5_PW_HISTORY_NUM))
	pent.pw_history_num = MIN_PW_HISTORY;
    else {
	if(entry->pw_history_num < MIN_PW_HISTORY ||
	   entry->pw_history_num > MAX_PW_HISTORY)
	    return KADM5_BAD_HISTORY;
	else
	    pent.pw_history_num = entry->pw_history_num;
    }
    if (!(mask & KADM5_REF_COUNT))
	pent.policy_refcnt = 0;
    else
	pent.policy_refcnt = entry->policy_refcnt;
    if ((ret = krb5_db_create_policy(handle->context, &pent)))
	return ret;
    else
	return KADM5_OK;
}

kadm5_ret_t
kadm5_delete_policy(void *server_handle, kadm5_policy_t name)
{
    kadm5_server_handle_t handle = server_handle;
    osa_policy_ent_t		entry;
    int				ret;
    int                         cnt=1;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if(name == (kadm5_policy_t) NULL)
	return EINVAL;
    if(strlen(name) == 0)
	return KADM5_BAD_POLICY;
    if((ret = krb5_db_get_policy(handle->context, name, &entry,&cnt)))
	return ret;
    if( cnt != 1 )
	return KADM5_UNK_POLICY;

    if(entry->policy_refcnt != 0) {
	krb5_db_free_policy(handle->context, entry);
	return KADM5_POLICY_REF;
    }
    krb5_db_free_policy(handle->context, entry);
    if ((ret = krb5_db_delete_policy(handle->context, name)))
	return ret;
    else
	return KADM5_OK;
}

kadm5_ret_t
kadm5_modify_policy(void *server_handle,
			 kadm5_policy_ent_t entry, long mask)
{
    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(((kadm5_server_handle_t)server_handle)->context);

    if (mask & KADM5_REF_COUNT)
	return KADM5_BAD_MASK;
    else
	return kadm5_modify_policy_internal(server_handle, entry, mask);
}

kadm5_ret_t
kadm5_modify_policy_internal(void *server_handle,
				  kadm5_policy_ent_t entry, long mask)
{
    kadm5_server_handle_t handle = server_handle;
    osa_policy_ent_t	p;
    int			ret;
    int                 cnt=1;

    CHECK_HANDLE(server_handle);

    if((entry == (kadm5_policy_ent_t) NULL) || (entry->policy == NULL))
	return EINVAL;
    if(strlen(entry->policy) == 0)
	return KADM5_BAD_POLICY;
    if((mask & KADM5_POLICY))
	return KADM5_BAD_MASK;

    if ((ret = krb5_db_get_policy(handle->context, entry->policy, &p, &cnt)))
	return ret;
    if (cnt != 1)
	return KADM5_UNK_POLICY;

    if ((mask & KADM5_PW_MAX_LIFE))
	p->pw_max_life = entry->pw_max_life;
    if ((mask & KADM5_PW_MIN_LIFE)) {
	if(entry->pw_min_life > p->pw_max_life && p->pw_max_life != 0)	{
	     krb5_db_free_policy(handle->context, p);
	     return KADM5_BAD_MIN_PASS_LIFE;
	}
	p->pw_min_life = entry->pw_min_life;
    }
    if ((mask & KADM5_PW_MIN_LENGTH)) {
	if(entry->pw_min_length < MIN_PW_LENGTH) {
	      krb5_db_free_policy(handle->context, p);
	      return KADM5_BAD_LENGTH;
	 }
	p->pw_min_length = entry->pw_min_length;
    }
    if ((mask & KADM5_PW_MIN_CLASSES)) {
	if(entry->pw_min_classes > MAX_PW_CLASSES ||
	   entry->pw_min_classes < MIN_PW_CLASSES) {
	     krb5_db_free_policy(handle->context, p);
	     return KADM5_BAD_CLASS;
	}
	p->pw_min_classes = entry->pw_min_classes;
    }
    if ((mask & KADM5_PW_HISTORY_NUM)) {
	if(entry->pw_history_num < MIN_PW_HISTORY ||
	   entry->pw_history_num > MAX_PW_HISTORY) {
	     krb5_db_free_policy(handle->context, p);
	     return KADM5_BAD_HISTORY;
	}
	p->pw_history_num = entry->pw_history_num;
    }
    if ((mask & KADM5_REF_COUNT))
	p->policy_refcnt = entry->policy_refcnt;
    ret = krb5_db_put_policy(handle->context, p);
    krb5_db_free_policy(handle->context, p);
    return ret;
}

kadm5_ret_t
kadm5_get_policy(void *server_handle, kadm5_policy_t name,
		 kadm5_policy_ent_t entry)
{
    osa_policy_ent_t		t;
    kadm5_policy_ent_rec	entry_local, **entry_orig, *new;
    int				ret;
    kadm5_server_handle_t handle = server_handle;
    int                         cnt=1;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    /*
     * In version 1, entry is a pointer to a kadm5_policy_ent_t that
     * should be filled with allocated memory.
     */
    if (handle->api_version == KADM5_API_VERSION_1) {
	 entry_orig = (kadm5_policy_ent_rec **) entry;
	 *entry_orig = NULL;
	 entry = &entry_local;
    }

    if (name == (kadm5_policy_t) NULL)
	return EINVAL;
    if(strlen(name) == 0)
	return KADM5_BAD_POLICY;
    if((ret = krb5_db_get_policy(handle->context, name, &t, &cnt)))
	return ret;

    if( cnt != 1 )
	return KADM5_UNK_POLICY;

    if ((entry->policy = (char *) malloc(strlen(t->name) + 1)) == NULL) {
	 krb5_db_free_policy(handle->context, t);
	 return ENOMEM;
    }
    strcpy(entry->policy, t->name);
    entry->pw_min_life = t->pw_min_life;
    entry->pw_max_life = t->pw_max_life;
    entry->pw_min_length = t->pw_min_length;
    entry->pw_min_classes = t->pw_min_classes;
    entry->pw_history_num = t->pw_history_num;
    entry->policy_refcnt = t->policy_refcnt;
    krb5_db_free_policy(handle->context, t);

    if (handle->api_version == KADM5_API_VERSION_1) {
	 new = (kadm5_policy_ent_t) malloc(sizeof(kadm5_policy_ent_rec));
	 if (new == NULL) {
	      free(entry->policy);
	      krb5_db_free_policy(handle->context, t);
	      return ENOMEM;
	 }
	 *new = *entry;
	 *entry_orig = new;
    }

    return KADM5_OK;
}
