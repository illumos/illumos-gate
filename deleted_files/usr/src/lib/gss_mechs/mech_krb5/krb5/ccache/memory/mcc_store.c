#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/ccache/memory/mcc_store.c
 *
 * Copyright 1995 Locus Computing Corporation
 *
 * This file contains the source code for krb5_mcc_store.
 */


#include <errno.h>
#include "mcc.h"

#define CHECK(ret) if (ret != KRB5_OK) return ret;

/*
 * Modifies:
 * the memory cache
 *
 * Effects:
 * stores creds in the memory cred cache
 *
 * Errors:
 * system errors
 * storage failure errors
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_store(context, id, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_creds *creds;
{
     krb5_error_code ret;
     krb5_mcc_cursor mcursor;

     mcursor = (krb5_mcc_cursor)malloc(sizeof(krb5_mcc_link));
     if (mcursor == NULL)
	return KRB5_CC_NOMEM;
     ret = krb5_copy_creds(context, creds, &mcursor->creds);
     if (ret == KRB5_OK) {
	mcursor->next = ((krb5_mcc_data *)id->data)->link;
	((krb5_mcc_data *)id->data)->link = mcursor;
	krb5_change_cache();
     }
     return ret;
}

