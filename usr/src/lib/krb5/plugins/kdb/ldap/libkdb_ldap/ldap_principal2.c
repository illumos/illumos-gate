#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/kdb_ldap/ldap_principal2.c
 *
 * Copyright (c) 2004-2005, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <time.h>
#include "ldap_main.h"
#include "kdb_ldap.h"
#include "ldap_principal.h"
#include "princ_xdr.h"
#include "ldap_tkt_policy.h"
#include "ldap_pwd_policy.h"
#include "ldap_err.h"
#include <kadm5/admin.h>
#include <libintl.h>

extern char* principal_attributes[];
extern char* max_pwd_life_attr[];

static char *
getstringtime(krb5_timestamp);

krb5_error_code
berval2tl_data(struct berval *in, krb5_tl_data **out)
{
    *out = (krb5_tl_data *) malloc (sizeof (krb5_tl_data));
    if (*out == NULL)
	return ENOMEM;

    (*out)->tl_data_length = in->bv_len - 2;
    (*out)->tl_data_contents =  (krb5_octet *) malloc
	((*out)->tl_data_length * sizeof (krb5_octet));
    if ((*out)->tl_data_contents == NULL) {
	free (*out);
	return ENOMEM;
    }

    /* Solaris Kerberos: need cast */
    UNSTORE16_INT ((unsigned char *)in->bv_val, (*out)->tl_data_type);
    memcpy ((*out)->tl_data_contents, in->bv_val + 2, (*out)->tl_data_length);

    return 0;
}

/*
 * look up a principal in the directory.
 */

krb5_error_code
krb5_ldap_get_principal(context, searchfor, entries, nentries, more)
    krb5_context context;
    krb5_const_principal searchfor;
    krb5_db_entry *entries;	/* filled in */
    int *nentries;		/* how much room/how many found */
    krb5_boolean *more;		/* are there more? */
{
    char                        *user=NULL, *filter=NULL, **subtree=NULL;
    unsigned int                tree=0, ntrees=1, princlen=0;
    krb5_error_code	        tempst=0, st=0;
    char                        **values=NULL;
    LDAP	                *ld=NULL;
    LDAPMessage	                *result=NULL, *ent=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* set initial values */
    *nentries = 0;
    *more = 0;
    memset(entries, 0, sizeof(*entries));

    if (searchfor == NULL)
	return EINVAL;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;

    CHECK_LDAP_HANDLE(ldap_context);

    if (is_principal_in_realm(ldap_context, searchfor) != 0) {
	*more = 0;
	krb5_set_error_message (context, st, gettext("Principal does not belong to realm"));
	goto cleanup;
    }

    if ((st=krb5_unparse_name(context, searchfor, &user)) != 0)
	goto cleanup;

    if ((st=krb5_ldap_unparse_principal_name(user)) != 0)
	goto cleanup;

    princlen = strlen(FILTER) + strlen(user) + 2 + 1;      /* 2 for closing brackets */
    if ((filter = malloc(princlen)) == NULL) {
	st = ENOMEM;
	goto cleanup;
    }
    snprintf(filter, princlen, FILTER"%s))", user);

    if ((st = krb5_get_subtree_info(ldap_context, &subtree, &ntrees)) != 0)
	goto cleanup;

    GET_HANDLE();
    for (tree=0; tree < ntrees && *nentries == 0; ++tree) {

	LDAP_SEARCH(subtree[tree], ldap_context->lrparams->search_scope, filter, principal_attributes);
	for (ent=ldap_first_entry(ld, result); ent != NULL && *nentries == 0; ent=ldap_next_entry(ld, ent)) {

	    /* get the associated directory user information */
	    if ((values=ldap_get_values(ld, ent, "krbprincipalname")) != NULL) {
		int i;

		/* a wild-card in a principal name can return a list of kerberos principals.
		 * Make sure that the correct principal is returned.
		 * NOTE: a principalname k* in ldap server will return all the principals starting with a k
		 */
		for (i=0; values[i] != NULL; ++i) {
		    if (strcasecmp(values[i], user) == 0) {
			*nentries = 1;
			break;
		    }
		}
		ldap_value_free(values);

		if (*nentries == 0) /* no matching principal found */
		    continue;
	    }

	    if ((st = populate_krb5_db_entry(context, ldap_context, ld, ent, searchfor,
			entries)) != 0)
		goto cleanup;
	}
	ldap_msgfree(result);
	result = NULL;
    } /* for (tree=0 ... */

    /* once done, put back the ldap handle */
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    ldap_server_handle = NULL;

cleanup:
    ldap_msgfree(result);

    if (*nentries == 0 || st != 0)
	krb5_dbe_free_contents(context, entries);

    if (filter)
	free (filter);

    if (subtree) {
	for (; ntrees; --ntrees)
	    if (subtree[ntrees-1])
		free (subtree[ntrees-1]);
	free (subtree);
    }

    if (ldap_server_handle)
	krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);

    if (user)
	free(user);

    return st;
}

typedef enum{ ADD_PRINCIPAL, MODIFY_PRINCIPAL } OPERATION;
/*
 * ptype is creating confusions. Additionally the logic
 * surronding ptype is redundunt and can be achevied
 * with the help of dn and containerdn members.
 * so dropping the ptype member
 */

typedef struct _xargs_t {
    char           *dn;
    char           *linkdn;
    krb5_boolean   dn_from_kbd;
    char           *containerdn;
    char           *tktpolicydn;
}xargs_t;

static void
free_xargs(xargs)
    xargs_t xargs;
{
    if (xargs.dn)
	free (xargs.dn);
    if (xargs.linkdn)
	free(xargs.linkdn);
    if (xargs.containerdn)
	free (xargs.containerdn);
    if (xargs.tktpolicydn)
	free (xargs.tktpolicydn);
}

static krb5_error_code
process_db_args(context, db_args, xargs, optype)
    krb5_context   context;
    char           **db_args;
    xargs_t        *xargs;
    OPERATION      optype;
{
    int                   i=0;
    krb5_error_code       st=0;
    char                  errbuf[1024];
    char                  *arg=NULL, *arg_val=NULL;
    char                  **dptr=NULL;
    unsigned int          arg_val_len=0;

    if (db_args) {
	for (i=0; db_args[i]; ++i) {
	    arg = strtok_r(db_args[i], "=", &arg_val);
	    if (strcmp(arg, TKTPOLICY_ARG) == 0) {
		dptr = &xargs->tktpolicydn;
	    } else {
		if (strcmp(arg, USERDN_ARG) == 0) {
		    if (optype == MODIFY_PRINCIPAL || 
			xargs->dn != NULL || xargs->containerdn != NULL || 
			xargs->linkdn != NULL) {
			st = EINVAL;
			snprintf(errbuf, sizeof(errbuf), 
				 gettext("%s option not supported"), arg);
			krb5_set_error_message(context, st, "%s", errbuf);
			goto cleanup;
		    }
		    dptr = &xargs->dn;
		} else if (strcmp(arg, CONTAINERDN_ARG) == 0) {
		    if (optype == MODIFY_PRINCIPAL ||
			xargs->dn != NULL || xargs->containerdn != NULL) {
			st = EINVAL;
			snprintf(errbuf, sizeof(errbuf), 
				 gettext("%s option not supported"), arg);
			krb5_set_error_message(context, st, "%s", errbuf);
			goto cleanup;
		    }
		    dptr = &xargs->containerdn;
		} else if (strcmp(arg, LINKDN_ARG) == 0) {
		    if (xargs->dn != NULL || xargs->linkdn != NULL) {
			st = EINVAL;
			snprintf(errbuf, sizeof(errbuf), 
				 gettext("%s option not supported"), arg);
			krb5_set_error_message(context, st, "%s", errbuf);
			goto cleanup;
		    }
		    dptr = &xargs->linkdn;
		} else {
		    st = EINVAL;
		    snprintf(errbuf, sizeof(errbuf), gettext("unknown option: %s"), arg);
		    krb5_set_error_message(context, st, "%s", errbuf);
		    goto cleanup;
		}
		
		xargs->dn_from_kbd = TRUE;
		if (arg_val == NULL || strlen(arg_val) == 0) {
		    st = EINVAL;
		    snprintf(errbuf, sizeof(errbuf), 
			     gettext("%s option value missing"), arg);
		    krb5_set_error_message(context, st, "%s", errbuf);
		    goto cleanup;
		}
	    }

	    if (arg_val == NULL) {
		st = EINVAL;
		snprintf(errbuf, sizeof(errbuf), 
			 gettext("%s option value missing"), arg);
		krb5_set_error_message(context, st, "%s", errbuf);
		goto cleanup;
	    }
	    arg_val_len = strlen(arg_val) + 1;

	    if (strcmp(arg, TKTPOLICY_ARG) == 0) {
		if ((st = krb5_ldap_name_to_policydn (context, 
						      arg_val, 
						      dptr)) != 0)
		    goto cleanup;
	    } else {
		*dptr = calloc (1, arg_val_len);
		if (*dptr == NULL) {
		    st = ENOMEM;
		    goto cleanup;
		}
		memcpy(*dptr, arg_val, arg_val_len);
	    }
	}
    }

cleanup:
    return st;
}

krb5int_access accessor;
extern int kldap_ensure_initialized (void);

static krb5_error_code
asn1_encode_sequence_of_keys (krb5_key_data *key_data, krb5_int16 n_key_data,
			      krb5_int32 mkvno, krb5_data **code)
{
    krb5_error_code err;

    /*
     * This should be pushed back into other library initialization
     * code.
     */
    err = kldap_ensure_initialized ();
    if (err)
	return err;

    return accessor.asn1_ldap_encode_sequence_of_keys(key_data, n_key_data,
						      mkvno, code);
}

static krb5_error_code
asn1_decode_sequence_of_keys (krb5_data *in, krb5_key_data **out,
			      krb5_int16 *n_key_data, int *mkvno)
{
    krb5_error_code err;

    /*
     * This should be pushed back into other library initialization
     * code.
     */
    err = kldap_ensure_initialized ();
    if (err)
	return err;

    return accessor.asn1_ldap_decode_sequence_of_keys(in, out, n_key_data,
						      mkvno);
}


/* Decoding ASN.1 encoded key */
static struct berval **
krb5_encode_krbsecretkey(krb5_key_data *key_data, int n_key_data) {
    struct berval **ret = NULL;
    int currkvno;
    int num_versions = 1;
    int i, j, last;
    krb5_error_code err = 0;

    if (n_key_data <= 0)
	return NULL;

    /* Find the number of key versions */
    for (i = 0; i < n_key_data - 1; i++)
	if (key_data[i].key_data_kvno != key_data[i + 1].key_data_kvno)
	    num_versions++;

    ret = (struct berval **) calloc (num_versions + 1, sizeof (struct berval *));
    if (ret == NULL) {
	err = ENOMEM;
	goto cleanup;
    }
    for (i = 0, last = 0, j = 0, currkvno = key_data[0].key_data_kvno; i < n_key_data; i++) {
	krb5_data *code;
	if (i == n_key_data - 1 || key_data[i + 1].key_data_kvno != currkvno) {
	    code = NULL;
	    asn1_encode_sequence_of_keys (key_data+last,
					  (krb5_int16) i - last + 1,
					  0, /* For now, mkvno == 0*/
					  &code);
	    if (code == NULL) {
		err = ENOMEM;
		goto cleanup;
	    }
	    ret[j] = malloc (sizeof (struct berval));
	    if (ret[j] == NULL) {
		err = ENOMEM;
		goto cleanup;
	    }
	    /*CHECK_NULL(ret[j]); */
	    ret[j]->bv_len = code->length;
	    ret[j]->bv_val = code->data;
	    j++;
	    last = i + 1;

	    currkvno = key_data[i].key_data_kvno;
	    /* Solaris Kerberos: fix memleak */
	    free(code);
	}
    }
    ret[num_versions] = NULL;

cleanup:

    if (err != 0) {
	if (ret != NULL) {
	    for (i = 0; i <= num_versions; i++)
		if (ret[i] != NULL)
		    free (ret[i]);
	    free (ret);
	    ret = NULL;
	}
    }

    return ret;
}

static krb5_error_code tl_data2berval (krb5_tl_data *in, struct berval **out) {
    *out = (struct berval *) malloc (sizeof (struct berval));
    if (*out == NULL)
	return ENOMEM;

    (*out)->bv_len = in->tl_data_length + 2;
    (*out)->bv_val =  (char *) malloc ((*out)->bv_len);
    if ((*out)->bv_val == NULL) {
	free (*out);
	return ENOMEM;
    }

    /* Solaris Kerberos: need cast */
    STORE16_INT((unsigned char *)(*out)->bv_val, in->tl_data_type);
    memcpy ((*out)->bv_val + 2, in->tl_data_contents, in->tl_data_length);

    return 0;
}

krb5_error_code
krb5_ldap_put_principal(context, entries, nentries, db_args)
    krb5_context               context;
    krb5_db_entry              *entries;
    register int               *nentries;         /* number of entry structs to update */
    char                       **db_args;
{
    int 		        i=0, l=0, kerberos_principal_object_type=0;
    krb5_error_code 	        st=0, tempst=0;
    LDAP  		        *ld=NULL;
    LDAPMessage                 *result=NULL, *ent=NULL;
    char                        *user=NULL, *subtree=NULL, *principal_dn=NULL;
    char                        **values=NULL, *strval[10]={NULL}, errbuf[1024];
    struct berval	        **bersecretkey=NULL;
    LDAPMod 		        **mods=NULL;
    krb5_boolean                create_standalone_prinicipal=FALSE;
    krb5_boolean                krb_identity_exists=FALSE, establish_links=FALSE;
    char                        *standalone_principal_dn=NULL;
    krb5_tl_data                *tl_data=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
    osa_princ_ent_rec 	        princ_ent;
    xargs_t                     xargs = {0};
    char                        *polname = NULL;
    OPERATION optype;
    krb5_boolean     		found_entry = FALSE;
    struct berval **ber_tl_data = NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    SETUP_CONTEXT();
    if (ldap_context->lrparams == NULL || ldap_context->krbcontainer == NULL)
	return EINVAL;

    /* get ldap handle */
    GET_HANDLE();

    for (i=0; i < *nentries; ++i, ++entries) {
	if (is_principal_in_realm(ldap_context, entries->princ) != 0) {
	    st = EINVAL;
	    krb5_set_error_message(context, st, gettext("Principal does not belong to the default realm"));
	    goto cleanup;
	}

	/* get the principal information to act on */
	if (entries->princ) {
	    if (((st=krb5_unparse_name(context, entries->princ, &user)) != 0) ||
		((st=krb5_ldap_unparse_principal_name(user)) != 0))
		goto cleanup;
	}

	/* Identity the type of operation, it can be
	 * add principal or modify principal.
	 * hack if the entries->mask has KRB_PRINCIPAL flag set
	 * then it is a add operation
	 */
	if (entries->mask & KADM5_PRINCIPAL)
	    optype = ADD_PRINCIPAL;
	else
	    optype = MODIFY_PRINCIPAL;

	if (((st=krb5_get_princ_type(context, entries, &kerberos_principal_object_type)) != 0) ||
	    ((st=krb5_get_userdn(context, entries, &principal_dn)) != 0))
	    goto cleanup;

	if ((st=process_db_args(context, db_args, &xargs, optype)) != 0)
	    goto cleanup;

	if (entries->mask & KADM5_LOAD) {
	    int              tree = 0, princlen = 0, numlentries = 0;
	    unsigned int     ntrees = 0;
	    char             **subtreelist = NULL, *filter = NULL;

	    /*  A load operation is special, will do a mix-in (add krbprinc
	     *  attrs to a non-krb object entry) if an object exists with a
	     *  matching krbprincipalname attribute so try to find existing
	     *  object and set principal_dn.  This assumes that the
	     *  krbprincipalname attribute is unique (only one object entry has
	     *  a particular krbprincipalname attribute).
	     */
	    if (user == NULL) {
		/* must have principal name for search */
		st = EINVAL;
		krb5_set_error_message(context, st, gettext("operation can not continue, principal name not found"));
		goto cleanup;
	    }
	    princlen = strlen(FILTER) + strlen(user) + 2 + 1;      /* 2 for closing brackets */
	    if ((filter = malloc(princlen)) == NULL) {
		st = ENOMEM;
		goto cleanup;
	    }
	    snprintf(filter, princlen, FILTER"%s))", user);

	    /* get the current subtree list */
	    if ((st = krb5_get_subtree_info(ldap_context, &subtreelist, &ntrees)) != 0)
		goto cleanup;

	    found_entry = FALSE;
	    /* search for entry with matching krbprincipalname attribute */
	    for (tree = 0; found_entry == FALSE && tree < ntrees; ++tree) {
		result = NULL;
		if (principal_dn == NULL) {
		    LDAP_SEARCH_1(subtreelist[tree], ldap_context->lrparams->search_scope, filter, principal_attributes, IGNORE_STATUS);
		} else {
		    /* just look for entry with principal_dn */
		    LDAP_SEARCH_1(principal_dn, LDAP_SCOPE_BASE, filter, principal_attributes, IGNORE_STATUS);
		}
		if (st == LDAP_SUCCESS) {
		    numlentries = ldap_count_entries(ld, result);
		    if (numlentries > 1) {
			ldap_msgfree(result);
			free(filter);
			st = EINVAL;
			krb5_set_error_message(context, st,
			    gettext("operation can not continue, more than one entry with principal name \"%s\" found"),
			    user);
			goto cleanup;
		    } else if (numlentries == 1) {
			found_entry = TRUE;
			if (principal_dn == NULL) {
			    ent = ldap_first_entry(ld, result);
			    if (ent != NULL) {
				/* setting principal_dn will cause that entry to be modified further down */
				if ((principal_dn = ldap_get_dn(ld, ent)) == NULL) {
				    ldap_get_option (ld, LDAP_OPT_RESULT_CODE, &st);
				    st = set_ldap_error (context, st, 0);
				    ldap_msgfree(result);
				    free(filter);
				    goto cleanup;
				}
			    }
			}
		    }
		    if (result)
			ldap_msgfree(result);
		} else if (st != LDAP_NO_SUCH_OBJECT) {
		    /* could not perform search, return with failure */
		    st = set_ldap_error (context, st, 0);
		    free(filter);
		    goto cleanup;
		}
		/* 
		 * If it isn't found then assume a standalone princ entry is to
		 * be created.
		 */
	    } /* end for (tree = 0; principal_dn == ... */

	    free(filter);

	    if (found_entry == FALSE && principal_dn != NULL) {
		/* 
		 * if principal_dn is null then there is code further down to
		 * deal with setting standalone_principal_dn.  Also note that
		 * this will set create_standalone_prinicipal true for
		 * non-mix-in entries which is okay if loading from a dump.
		 */
		create_standalone_prinicipal = TRUE;
		standalone_principal_dn = strdup(principal_dn);
		CHECK_NULL(standalone_principal_dn);
	    }
	} /* end if (entries->mask & KADM5_LOAD */

	/* time to generate the DN information with the help of
	 * containerdn, principalcontainerreference or
	 * realmcontainerdn information
	 */
	if (principal_dn == NULL && xargs.dn == NULL) { /* creation of standalone principal */
	    /* get the subtree information */
	    if (entries->princ->length == 2 && entries->princ->data[0].length == strlen("krbtgt") &&
		strncmp(entries->princ->data[0].data, "krbtgt", entries->princ->data[0].length) == 0) {
		/* if the principal is a inter-realm principal, always created in the realm container */
		subtree = strdup(ldap_context->lrparams->realmdn);
	    } else if (xargs.containerdn) {
		if ((st=checkattributevalue(ld, xargs.containerdn, NULL, NULL, NULL)) != 0) {
		    if (st == KRB5_KDB_NOENTRY || st == KRB5_KDB_CONSTRAINT_VIOLATION) {
			int ost = st;
			st = EINVAL;
			snprintf(errbuf, sizeof(errbuf), gettext("'%s' not found: "), xargs.containerdn);
			prepend_err_str(context, errbuf, st, ost);
		    }
		    goto cleanup;
		}
		subtree = strdup(xargs.containerdn);
	    } else if (ldap_context->lrparams->containerref && strlen(ldap_context->lrparams->containerref) != 0) {
		/*
		 * Here the subtree should be changed with
		 * principalcontainerreference attribute value
		 */
		subtree = strdup(ldap_context->lrparams->containerref);
	    } else {
		subtree = strdup(ldap_context->lrparams->realmdn);
	    }
	    CHECK_NULL(subtree);

	    standalone_principal_dn = malloc(strlen("krbprincipalname=") + strlen(user) + strlen(",") +
					     strlen(subtree) + 1);
	    CHECK_NULL(standalone_principal_dn);
	    /*LINTED*/
	    sprintf(standalone_principal_dn, "krbprincipalname=%s,%s", user, subtree);
	    /*
	     * free subtree when you are done using the subtree
	     * set the boolean create_standalone_prinicipal to TRUE
	     */
	    create_standalone_prinicipal = TRUE;
	    free(subtree);
	    subtree = NULL;
	}

	/*
	 * If the DN information is presented by the user, time to
	 * validate the input to ensure that the DN falls under
	 * any of the subtrees
	 */
	if (xargs.dn_from_kbd == TRUE) {
	    /* make sure the DN falls in the subtree */
	    int              tre=0, dnlen=0, subtreelen=0;
	    unsigned int     ntrees = 0;
	    char             **subtreelist=NULL;
	    char             *dn=NULL;
	    krb5_boolean     outofsubtree=TRUE;

	    if (xargs.dn != NULL) {
		dn = xargs.dn;
	    } else if (xargs.linkdn != NULL) {
		dn = xargs.linkdn;
	    } else if (standalone_principal_dn != NULL) {
		/*
		 * Even though the standalone_principal_dn is constructed
		 * within this function, there is the containerdn input
		 * from the user that can become part of the it.
		 */
		dn = standalone_principal_dn;
	    }

	    /* get the current subtree list */
	    if ((st = krb5_get_subtree_info(ldap_context, &subtreelist, &ntrees)) != 0)
		goto cleanup;

	    for (tre=0; tre<ntrees; ++tre) {
		if (subtreelist[tre] == NULL || strlen(subtreelist[tre]) == 0) {
		    outofsubtree = FALSE;
		    break;
		} else {
		    dnlen = strlen (dn);
		    subtreelen = strlen(subtreelist[tre]);
		    if ((dnlen >= subtreelen) && (strcasecmp((dn + dnlen - subtreelen), subtreelist[tre]) == 0)) {
			outofsubtree = FALSE;
			break;
		    }
		}
	    }

	    for (tre=0; tre < ntrees; ++tre) {
		free(subtreelist[tre]);
	    }

	    if (outofsubtree == TRUE) {
		st = EINVAL;
		krb5_set_error_message(context, st, gettext("DN is out of the realm subtree"));
		goto cleanup;
	    }

	    /*
	     * dn value will be set either by dn, linkdn or the standalone_principal_dn
	     * In the first 2 cases, the dn should be existing and in the last case we
	     * are supposed to create the ldap object. so the below should not be
	     * executed for the last case.
	     */

	    if (standalone_principal_dn == NULL) {
		/*
		 * If the ldap object is missing, this results in an error.
		 */

		/*
		 * Search for krbprincipalname attribute here.
		 * This is to find if a kerberos identity is already present
		 * on the ldap object, in which case adding a kerberos identity
		 * on the ldap object should result in an error.
		 */
		char  *attributes[]={"krbticketpolicyreference", "krbprincipalname", NULL};

		LDAP_SEARCH_1(dn, LDAP_SCOPE_BASE, 0, attributes, IGNORE_STATUS);
		if (st == LDAP_SUCCESS) {
		    ent = ldap_first_entry(ld, result);
		    if (ent != NULL) {
			if ((values=ldap_get_values(ld, ent, "krbticketpolicyreference")) != NULL) {
			    ldap_value_free(values);
			}

			if ((values=ldap_get_values(ld, ent, "krbprincipalname")) != NULL) {
			    krb_identity_exists = TRUE;
			    ldap_value_free(values);
			}
		    }
		    ldap_msgfree(result);
		} else {
		    st = set_ldap_error(context, st, OP_SEARCH);
		    goto cleanup;
		}
	    }
	}

	/*
	 * If xargs.dn is set then the request is to add a
	 * kerberos principal on a ldap object, but if
	 * there is one already on the ldap object this
	 * should result in an error.
	 */

	if (xargs.dn != NULL && krb_identity_exists == TRUE) {
	    st = EINVAL;
	    snprintf(errbuf, sizeof(errbuf), gettext("ldap object is already kerberized"));
	    krb5_set_error_message(context, st, "%s", errbuf);
	    goto cleanup;
	}

	if (xargs.linkdn != NULL) {
	    /*
	     * link information can be changed using modprinc.
	     * However, link information can be changed only on the
	     * standalone kerberos principal objects. A standalone
	     * kerberos principal object is of type krbprincipal
	     * structural objectclass.
	     *
	     * NOTE: kerberos principals on an ldap object can't be
	     * linked to other ldap objects.
	     */
	    if (optype == MODIFY_PRINCIPAL &&
		kerberos_principal_object_type != KDB_STANDALONE_PRINCIPAL_OBJECT) {
		st = EINVAL;
		snprintf(errbuf, sizeof(errbuf),
		    gettext("link information can not be set/updated as the kerberos principal belongs to an ldap object"));
		krb5_set_error_message(context, st, "%s", errbuf);
		goto cleanup;
	    }
            /*
             * Check the link information. If there is already a link
             * existing then this operation is not allowed.
             */
            {
                char **linkdns=NULL;
                int  j=0;

                if ((st=krb5_get_linkdn(context, entries, &linkdns)) != 0) {
                    snprintf(errbuf, sizeof(errbuf),
                             gettext("Failed getting object references"));
                    krb5_set_error_message(context, st, "%s", errbuf);
                    goto cleanup;
                }
                if (linkdns != NULL) {
                    st = EINVAL;
                    snprintf(errbuf, sizeof(errbuf),
                             gettext("kerberos principal is already linked "
                             "to a ldap object"));
                    krb5_set_error_message(context, st, "%s", errbuf);
                    for (j=0; linkdns[j] != NULL; ++j)
                        free (linkdns[j]);
                    free (linkdns);
                    goto cleanup;
                }
            }

	    establish_links = TRUE;
	}

	if ((entries->last_success)!=0) {
	    memset(strval, 0, sizeof(strval));
	    if ((strval[0]=getstringtime(entries->last_success)) == NULL)
		goto cleanup;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbLastSuccessfulAuth", LDAP_MOD_REPLACE, strval)) != 0) {
		free (strval[0]);
		goto cleanup;
	    }
	    free (strval[0]);
	}

	if (entries->last_failed!=0) {
	    memset(strval, 0, sizeof(strval));
	    if ((strval[0]=getstringtime(entries->last_failed)) == NULL)
		goto cleanup;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbLastFailedAuth", LDAP_MOD_REPLACE, strval)) != 0) {
		free (strval[0]);
		goto cleanup;
	    }
	    free(strval[0]);
	}

	if (entries->fail_auth_count!=0) {
	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbLoginFailedCount", LDAP_MOD_REPLACE, entries->fail_auth_count)) !=0)
		goto cleanup;
	}

	if (entries->mask & KADM5_MAX_LIFE) {
	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbmaxticketlife", LDAP_MOD_REPLACE, entries->max_life)) != 0)
		goto cleanup;
	}

	if (entries->mask & KADM5_MAX_RLIFE) {
	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbmaxrenewableage", LDAP_MOD_REPLACE,
					      entries->max_renewable_life)) != 0)
		goto cleanup;
	}

	if (entries->mask & KADM5_ATTRIBUTES) {
	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbticketflags", LDAP_MOD_REPLACE,
					      entries->attributes)) != 0)
		goto cleanup;
	}

	if (entries->mask & KADM5_PRINCIPAL) {
	    memset(strval, 0, sizeof(strval));
	    strval[0] = user;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbprincipalname", LDAP_MOD_REPLACE, strval)) != 0)
		goto cleanup;
	}

	/*
	 * Solaris Kerberos: this logic was not working properly when
	 * default_principal_expiration set.
	 */
	if (entries->mask & KADM5_PRINC_EXPIRE_TIME || entries->expiration != 0) {
	    memset(strval, 0, sizeof(strval));
	    if ((strval[0]=getstringtime(entries->expiration)) == NULL)
		goto cleanup;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbprincipalexpiration", LDAP_MOD_REPLACE, strval)) != 0) {
		free (strval[0]);
		goto cleanup;
	    }
	    free (strval[0]);
	}

	/*
	 * Solaris Kerberos: in case KADM5_PW_EXPIRATION isn't set, check
	 * pw_expiration
	 */
	if (entries->mask & KADM5_PW_EXPIRATION || entries->pw_expiration != 0) {
	    memset(strval, 0, sizeof(strval));
	    if ((strval[0]=getstringtime(entries->pw_expiration)) == NULL)
		goto cleanup;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpasswordexpiration",
					      LDAP_MOD_REPLACE,
					      strval)) != 0) {
		free (strval[0]);
		goto cleanup;
	    }
	    free (strval[0]);
	}

	if (entries->mask & KADM5_POLICY) {
	    memset(&princ_ent, 0, sizeof(princ_ent));
	    for (tl_data=entries->tl_data; tl_data; tl_data=tl_data->tl_data_next) {
		if (tl_data->tl_data_type == KRB5_TL_KADM_DATA) {
		    /* FIX ME: I guess the princ_ent should be freed after this call */
		    if ((st = krb5_lookup_tl_kadm_data(tl_data, &princ_ent)) != 0) {
			goto cleanup;
		    }
		}
	    }

	    if (princ_ent.aux_attributes & KADM5_POLICY) {
		memset(strval, 0, sizeof(strval));
		if ((st = krb5_ldap_name_to_policydn (context, princ_ent.policy, &polname)) != 0)
		    goto cleanup;
		strval[0] = polname;
		/* Solaris Kerberos: fix memleak */
		free(princ_ent.policy);
		if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpwdpolicyreference", LDAP_MOD_REPLACE, strval)) != 0)
		    goto cleanup;
	    } else {
		st = EINVAL;
		krb5_set_error_message(context, st, gettext("Password policy value null"));
		goto cleanup;
	    }
	} else if (entries->mask & KADM5_LOAD && found_entry == TRUE) {
	    /* 
	     * a load is special in that existing entries must have attrs that
	     * removed.
	     */

	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpwdpolicyreference", LDAP_MOD_REPLACE, NULL)) != 0)
		goto cleanup;
	}

	if (entries->mask & KADM5_POLICY_CLR) {
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpwdpolicyreference", LDAP_MOD_DELETE, NULL)) != 0)
		goto cleanup;
	}

	if (entries->mask & KADM5_KEY_DATA || entries->mask & KADM5_KVNO) {
	    bersecretkey = krb5_encode_krbsecretkey (entries->key_data,
						     entries->n_key_data);

	    if ((st=krb5_add_ber_mem_ldap_mod(&mods, "krbprincipalkey",
					      LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, bersecretkey)) != 0)
		goto cleanup;

	    if (!(entries->mask & KADM5_PRINCIPAL)) {
		memset(strval, 0, sizeof(strval));
		if ((strval[0]=getstringtime(entries->pw_expiration)) == NULL)
		    goto cleanup;
		if ((st=krb5_add_str_mem_ldap_mod(&mods,
						  "krbpasswordexpiration",
						  LDAP_MOD_REPLACE, strval)) != 0) {
		    free (strval[0]);
		    goto cleanup;
		}
		free (strval[0]);
	    }

	    /* Update last password change whenever a new key is set */
	    {
		krb5_timestamp last_pw_changed;
		if ((st=krb5_dbe_lookup_last_pwd_change(context, entries,
							&last_pw_changed)) != 0)
		    goto cleanup;

		memset(strval, 0, sizeof(strval));
		if ((strval[0] = getstringtime(last_pw_changed)) == NULL)
		    goto cleanup;

		if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbLastPwdChange",
						  LDAP_MOD_REPLACE, strval)) != 0) {
		    free (strval[0]);
		    goto cleanup;
		}
		free (strval[0]);
	    }

	} /* Modify Key data ends here */

	/* Set tl_data */
	if (entries->tl_data != NULL) {
	    int count = 0;
	    /* struct berval **ber_tl_data = NULL; */
	    krb5_tl_data *ptr;
	    for (ptr = entries->tl_data; ptr != NULL; ptr = ptr->tl_data_next) {
		if (ptr->tl_data_type == KRB5_TL_LAST_PWD_CHANGE
#ifdef SECURID
		    || ptr->tl_data_type == KRB5_TL_DB_ARGS
#endif
		    || ptr->tl_data_type == KDB_TL_USER_INFO)
		    continue;

		/* Solaris Kerberos: fix key history issue */
		if (ptr->tl_data_type == KRB5_TL_KADM_DATA && ! entries->mask & KADM5_KEY_HIST)
		    continue;
		    
		count++;
	    }
	    if (count != 0) {
		int j;
		ber_tl_data = (struct berval **) calloc (count + 1,
							 sizeof (struct berval*));
		if (ber_tl_data == NULL) {
		    st = ENOMEM;
		    goto cleanup;
		}
		for (j = 0, ptr = entries->tl_data; ptr != NULL; ptr = ptr->tl_data_next) {
		    /* Ignore tl_data that are stored in separate directory
		     * attributes */
		    if (ptr->tl_data_type == KRB5_TL_LAST_PWD_CHANGE
#ifdef SECURID
			|| ptr->tl_data_type == KRB5_TL_DB_ARGS
#endif
			|| ptr->tl_data_type == KDB_TL_USER_INFO)
			continue;

		    /*
		     * Solaris Kerberos: key history needs to be stored (it's in
		     * the KRB5_TL_KADM_DATA).
		     */
		    if (ptr->tl_data_type == KRB5_TL_KADM_DATA && ! entries->mask & KADM5_KEY_HIST)
			continue;

		    if ((st = tl_data2berval (ptr, &ber_tl_data[j])) != 0)
			break;
		    j++;
		}
		if (st != 0) {
		    /* Solaris Kerberos: don't free here, do it at cleanup */
		    goto cleanup;
		}
		ber_tl_data[count] = NULL;
		if ((st=krb5_add_ber_mem_ldap_mod(&mods, "krbExtraData",
						  LDAP_MOD_REPLACE | LDAP_MOD_BVALUES,
						  ber_tl_data)) != 0)
		    goto cleanup;
	    }
	}

	/* Directory specific attribute */
	if (xargs.tktpolicydn != NULL) {
	    int tmask=0;

	    if (strlen(xargs.tktpolicydn) != 0) {
		st = checkattributevalue(ld, xargs.tktpolicydn, "objectclass", policyclass, &tmask);
		CHECK_CLASS_VALIDITY(st, tmask, "ticket policy object value: ");

		strval[0] = xargs.tktpolicydn;
		strval[1] = NULL;
		if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbticketpolicyreference", LDAP_MOD_REPLACE, strval)) != 0)
		    goto cleanup;

	    } else {
		/* if xargs.tktpolicydn is a empty string, then delete
		 * already existing krbticketpolicyreference attr */
		if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbticketpolicyreference", LDAP_MOD_DELETE, NULL)) != 0)
		    goto cleanup;
	    }

	}

	if (establish_links == TRUE) {
	    memset(strval, 0, sizeof(strval));
	    strval[0] = xargs.linkdn;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbObjectReferences", LDAP_MOD_REPLACE, strval)) != 0)
		goto cleanup;
	}

	/*
	 * in case mods is NULL then return
	 * not sure but can happen in a modprinc
	 * so no need to return an error
	 * addprinc will at least have the principal name
	 * and the keys passed in
	 */
	if (mods == NULL)
	    goto cleanup;

	if (create_standalone_prinicipal == TRUE) {
	    memset(strval, 0, sizeof(strval));
	    strval[0] = "krbprincipal";
	    strval[1] = "krbprincipalaux";
	    strval[2] = "krbTicketPolicyAux";

	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
		goto cleanup;

	    st = ldap_add_ext_s(ld, standalone_principal_dn, mods, NULL, NULL);
	    if (st == LDAP_ALREADY_EXISTS && entries->mask & KADM5_LOAD) {
		/* a load operation must replace an existing entry */
		st = ldap_delete_ext_s(ld, standalone_principal_dn, NULL, NULL);
		if (st != LDAP_SUCCESS) {
		    snprintf(errbuf, sizeof (errbuf), gettext("Principal delete failed (trying to replace entry): %s"),
			ldap_err2string(st));
		    st = translate_ldap_error (st, OP_ADD);
		    krb5_set_error_message(context, st, "%s", errbuf);
		    goto cleanup;
		} else {
		    st = ldap_add_ext_s(ld, standalone_principal_dn, mods, NULL, NULL);
		}
	    }
	    if (st != LDAP_SUCCESS) {
		snprintf(errbuf, sizeof (errbuf), gettext("Principal add failed: %s"), ldap_err2string(st));
		st = translate_ldap_error (st, OP_ADD);
		krb5_set_error_message(context, st, "%s", errbuf);
		goto cleanup;
	    }
	} else {
	    /*
	     * Here existing ldap object is modified and can be related
	     * to any attribute, so always ensure that the ldap
	     * object is extended with all the kerberos related
	     * objectclasses so that there are no constraint
	     * violations.
	     */
	    {
		char *attrvalues[] = {"krbprincipalaux", "krbTicketPolicyAux", NULL};
		int p, q, r=0, amask=0;

		if ((st=checkattributevalue(ld, (xargs.dn) ? xargs.dn : principal_dn,
					    "objectclass", attrvalues, &amask)) != 0)
		    goto cleanup;

		memset(strval, 0, sizeof(strval));
		for (p=1, q=0; p<=2; p<<=1, ++q) {
		    if ((p & amask) == 0)
			strval[r++] = attrvalues[q];
		}
		if (r != 0) {
		    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
			goto cleanup;
		}
	    }
	    if (xargs.dn != NULL)
		st=ldap_modify_ext_s(ld, xargs.dn, mods, NULL, NULL);
	    else
		st = ldap_modify_ext_s(ld, principal_dn, mods, NULL, NULL);

	    if (st != LDAP_SUCCESS) {
		snprintf(errbuf, sizeof (errbuf), gettext("User modification failed: %s"), ldap_err2string(st));
		st = translate_ldap_error (st, OP_MOD);
		krb5_set_error_message(context, st, "%s", errbuf);
		goto cleanup;
	    }
	}
    }

cleanup:
    if (user)
	free(user);

    free_xargs(xargs);

    if (standalone_principal_dn)
	free(standalone_principal_dn);

    if (principal_dn)
	free (principal_dn);

    /* Solaris Kerberos: fix memleak */
    if (ber_tl_data) {
	int j;

	for (j = 0; ber_tl_data[j] != NULL; j++) {
	    free (ber_tl_data[j]->bv_val);
	    free (ber_tl_data[j]);
	}
	free(ber_tl_data);
    }

    if (polname != NULL)
	free(polname);

    if (subtree)
	free (subtree);

    if (bersecretkey) {
	for (l=0; bersecretkey[l]; ++l) {
	    if (bersecretkey[l]->bv_val)
		free (bersecretkey[l]->bv_val);
	    free (bersecretkey[l]);
	}
	free (bersecretkey);
    }

    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    *nentries = i;
    return(st);
}

krb5_error_code
krb5_read_tkt_policy (context, ldap_context, entries, policy)
    krb5_context                context;
    krb5_ldap_context           *ldap_context;
    krb5_db_entry               *entries;
    char                        *policy;
{
    krb5_error_code             st=0;
    unsigned int                mask=0, omask=0;
    int                         tkt_mask=(KDB_MAX_LIFE_ATTR | KDB_MAX_RLIFE_ATTR | KDB_TKT_FLAGS_ATTR);
    krb5_ldap_policy_params     *tktpoldnparam=NULL;

    if ((st=krb5_get_attributes_mask(context, entries, &mask)) != 0)
	goto cleanup;

    if ((mask & tkt_mask) == tkt_mask)
	goto cleanup;

    if (policy != NULL) {
	st = krb5_ldap_read_policy(context, policy, &tktpoldnparam, &omask);
	if (st && st != KRB5_KDB_NOENTRY) {
	    prepend_err_str(context, gettext("Error reading ticket policy. "), st, st);
	    goto cleanup;
	}

	st = 0; /* reset the return status */
    }

    if ((mask & KDB_MAX_LIFE_ATTR) == 0) {
	if ((omask & KDB_MAX_LIFE_ATTR) ==  KDB_MAX_LIFE_ATTR)
	    entries->max_life = tktpoldnparam->maxtktlife;
	else if (ldap_context->lrparams->max_life)
	    entries->max_life = ldap_context->lrparams->max_life;
    }

    if ((mask & KDB_MAX_RLIFE_ATTR) == 0) {
	if ((omask & KDB_MAX_RLIFE_ATTR) == KDB_MAX_RLIFE_ATTR)
	    entries->max_renewable_life = tktpoldnparam->maxrenewlife;
	else if (ldap_context->lrparams->max_renewable_life)
	    entries->max_renewable_life = ldap_context->lrparams->max_renewable_life;
    }

    if ((mask & KDB_TKT_FLAGS_ATTR) == 0) {
	if ((omask & KDB_TKT_FLAGS_ATTR) == KDB_TKT_FLAGS_ATTR)
	    entries->attributes = tktpoldnparam->tktflags;
	else if (ldap_context->lrparams->tktflags)
	    entries->attributes |= ldap_context->lrparams->tktflags;
    }
    krb5_ldap_free_policy(context, tktpoldnparam);

cleanup:
    return st;
}

krb5_error_code
krb5_decode_krbsecretkey(context, entries, bvalues)
    krb5_context                context;
    krb5_db_entry               *entries;
    struct berval               **bvalues;
{
    char                        *user=NULL;
    int                         i=0, j=0, noofkeys=0;
    krb5_key_data               *key_data=NULL, *tmp;
    krb5_error_code             st=0;

    if ((st=krb5_unparse_name(context, entries->princ, &user)) != 0)
	goto cleanup;

    for (i=0; bvalues[i] != NULL; ++i) {
	int mkvno; /* Not used currently */
	krb5_int16 n_kd;
	krb5_key_data *kd;
	krb5_data in;

	if (bvalues[i]->bv_len == 0)
	    continue;
	in.length = bvalues[i]->bv_len;
	in.data = bvalues[i]->bv_val;

	st = asn1_decode_sequence_of_keys (&in,
					   &kd,
					   &n_kd,
					   &mkvno);

	if (st != 0) {
	    const char *msg = error_message(st);
	    st = -1; /* Something more appropriate ? */
	    krb5_set_error_message (context, st,
				    gettext("unable to decode stored principal key data (%s)"), msg);
	    goto cleanup;
	}
	noofkeys += n_kd;
	tmp = key_data;
	key_data = realloc (key_data, noofkeys * sizeof (krb5_key_data));
	if (key_data == NULL) {
	    key_data = tmp;
	    st = ENOMEM;
	    goto cleanup;
	}
	for (j = 0; j < n_kd; j++)
	    key_data[noofkeys - n_kd + j] = kd[j];
	free (kd);
    }

    entries->n_key_data = noofkeys;
    entries->key_data = key_data;

cleanup:
    ldap_value_free_len(bvalues);
    free (user);
    return st;
}

static char *
getstringtime(epochtime)
    krb5_timestamp    epochtime;
{
    struct tm           tme;
    char                *strtime=NULL;
    time_t		posixtime = epochtime;

    strtime = calloc (50, 1);
    if (strtime == NULL)
	return NULL;

    if (gmtime_r(&posixtime, &tme) == NULL)
	return NULL;

    strftime(strtime, 50, DATE_FORMAT, &tme);
    return strtime;
}

