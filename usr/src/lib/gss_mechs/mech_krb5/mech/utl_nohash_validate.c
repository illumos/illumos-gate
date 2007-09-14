#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright 1990,1994 by the Massachusetts Institute of Technology.
 *  All Rights Reserved.
 * 
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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
 * stub functions for those without the hash library.
 */

#include "gssapiP_generic.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

/* functions for each type */

/* save */

int g_save_name(vdb, name)
     void **vdb;
     gss_name_t *name;
{
	return 1;
}
int g_save_cred_id(vdb, cred)
     void **vdb;
     gss_cred_id_t *cred;
{
	return 1;
}
int g_save_ctx_id(vdb, ctx)
     void **vdb;
     gss_ctx_id_t *ctx;
{
	return 1;
}
int g_save_lucidctx_id(vdb, lctx)
     void **vdb;
     void *lctx;
{
	return 1;
}

/* validate */

int g_validate_name(vdb, name)
     void **vdb;
     gss_name_t *name;
{
	return 1;
}
int g_validate_cred_id(vdb, cred)
     void **vdb;
     gss_cred_id_t *cred;
{
	return 1;
}
int g_validate_ctx_id(vdb, ctx)
     void **vdb;
     gss_ctx_id_t *ctx;
{
	return 1;
}
int g_validate_lucidctx_id(vdb, lctx)
     void **vdb;
     void *lctx;
{
	return 1;
}

/* delete */

int g_delete_name(vdb, name)
     void **vdb;
     gss_name_t *name;
{
	return 1;
}
int g_delete_cred_id(vdb, cred)
     void **vdb;
     gss_cred_id_t *cred;
{
	return 1;
}
int g_delete_ctx_id(vdb, ctx)
     void **vdb;
     gss_ctx_id_t *ctx;
{
	return 1;
}
int g_delete_lucidctx_id(vdb, lctx)
     void **vdb;
     void *lctx;
{
	return 1;
}

