/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Copyright 2006 by the Massachusetts Institute of Technology.
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
 */

/**********************************************************************
*
*	C %name:		db2_exp.c %
*	Instance:		idc_sec_2
*	Description:
*	%created_by:	spradeep %
*	%date_created:	Tue Apr  5 11:44:00 2005 %
*
**********************************************************************/
#ifndef lint
static char *_csrc = "@(#) %filespec: db2_exp.c~5 %  (%full_filespec: db2_exp.c~5:csrc:idc_sec#2 %)";
#endif

#include "k5-int.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <db.h>
#include <stdio.h>
#include <errno.h>
#include <utime.h>
#include <kdb/kdb5.h>
#include "kdb_db2.h"
#include "kdb_xdr.h"
#include "policy_db.h"

/* Quick and dirty wrapper functions to provide for thread safety
   within the plugin, instead of making the kdb5 library do it.  Eventually
   these should be integrated into the real functions.

   Some of the functions wrapped here are also called directly from
   within this library (e.g., create calls open), so simply dropping
   locking code into the top and bottom of each referenced function
   won't do.  (We aren't doing recursive locks, currently.)  */

static k5_mutex_t *krb5_db2_mutex;

#define WRAP(NAME,TYPE,ARGLIST,ARGNAMES,ERROR_RESULT)	\
	static TYPE wrap_##NAME ARGLIST			\
	{						\
	    TYPE result;				\
	    int code = k5_mutex_lock (krb5_db2_mutex);	\
	    if (code) { return ERROR_RESULT; }		\
	    result = NAME ARGNAMES;			\
	    k5_mutex_unlock (krb5_db2_mutex);		\
	    return result;				\
	}						\
	/* hack: decl to allow a following ";" */	\
	static TYPE wrap_##NAME ()

/* Two special cases: void (can't assign result), and krb5_error_code
   (return error from locking code).  */

#define WRAP_VOID(NAME,ARGLIST,ARGNAMES)		\
	static void wrap_##NAME ARGLIST			\
	{						\
	    int code = k5_mutex_lock (krb5_db2_mutex);	\
	    if (code) { return; }			\
	    NAME ARGNAMES;				\
	    k5_mutex_unlock (krb5_db2_mutex);		\
	}						\
	/* hack: decl to allow a following ";" */	\
	static void wrap_##NAME ()

#define WRAP_K(NAME,ARGLIST,ARGNAMES)			\
	WRAP(NAME,krb5_error_code,ARGLIST,ARGNAMES,code)

WRAP_K (krb5_db2_open,
	( krb5_context kcontext,
	  char *conf_section,
	  char **db_args,
	  int mode ),
	(kcontext, conf_section, db_args, mode));
WRAP_K (krb5_db2_db_fini, (krb5_context ctx), (ctx));
WRAP_K (krb5_db2_create,
	( krb5_context kcontext, char *conf_section, char **db_args ),
	(kcontext, conf_section, db_args));
WRAP_K (krb5_db2_destroy,
	( krb5_context kcontext, char *conf_section, char **db_args ),
	(kcontext, conf_section, db_args));
WRAP_K (krb5_db2_db_get_age,
	(krb5_context ctx,
		   char *s,
	 time_t *t),
	(ctx, s, t));
WRAP_K (krb5_db2_db_set_option,
	( krb5_context kcontext,
	  int option,
	  void *value ),
	(kcontext, option, value));

WRAP_K (krb5_db2_db_lock,
	( krb5_context 	  context,
	  int 	 	  in_mode),
	(context, in_mode));
WRAP_K (krb5_db2_db_unlock, (krb5_context ctx), (ctx));

WRAP_K (krb5_db2_db_get_principal,
	(krb5_context ctx,
		   krb5_const_principal p,
		   krb5_db_entry *d,
		   int * i,
	 krb5_boolean *b),
	(ctx, p, d, i, b));
WRAP_K (krb5_db2_db_free_principal,
	(krb5_context ctx,
		   krb5_db_entry *d,
	 int i),
	(ctx, d, i));
WRAP_K (krb5_db2_db_put_principal,
	(krb5_context ctx,
	 krb5_db_entry *d,
	 int *i,
	 char **db_args),
	(ctx, d, i, db_args));
WRAP_K (krb5_db2_db_delete_principal,
	(krb5_context context,
	 krb5_const_principal searchfor,
	 int *nentries),
	(context, searchfor, nentries));

/* Solaris Kerberos: adding support for db_args */
WRAP_K (krb5_db2_db_iterate,
	(krb5_context ctx, char *s,
	 krb5_error_code (*f) (krb5_pointer,
			      krb5_db_entry *),
	 krb5_pointer p,
	 char **db_args),
	(ctx, s, f, p, db_args));

WRAP_K (krb5_db2_create_policy,
	(krb5_context context, osa_policy_ent_t entry),
	(context, entry));
WRAP_K (krb5_db2_get_policy,
	( krb5_context kcontext,
	  char *name,
	  osa_policy_ent_t *policy,
	  int *cnt),
	(kcontext, name, policy, cnt));
WRAP_K (krb5_db2_put_policy,
	( krb5_context kcontext, osa_policy_ent_t policy ),
	(kcontext, policy));
WRAP_K (krb5_db2_iter_policy,
	( krb5_context kcontext,
	  char *match_entry,
	  osa_adb_iter_policy_func func,
	  void *data ),
	(kcontext, match_entry, func, data));
WRAP_K (krb5_db2_delete_policy,
	( krb5_context kcontext, char *policy ),
	(kcontext, policy));
WRAP_VOID (krb5_db2_free_policy,
	   ( krb5_context kcontext, osa_policy_ent_t entry ),
	   (kcontext, entry));

WRAP (krb5_db2_alloc, void *,
      ( krb5_context kcontext,
	void *ptr,
	size_t size ),
      (kcontext, ptr, size), NULL);
WRAP_VOID (krb5_db2_free,
	   ( krb5_context kcontext, void *ptr ),
	   (kcontext, ptr));

WRAP_K (krb5_db2_set_master_key_ext,
	( krb5_context kcontext, char *pwd, krb5_keyblock *key),
	(kcontext, pwd, key));
WRAP_K (krb5_db2_db_get_mkey,
	( krb5_context context, krb5_keyblock **key),
	(context, key));
WRAP_K (krb5_db2_promote_db,
	( krb5_context kcontext, char *conf_section, char **db_args ),
	(kcontext, conf_section, db_args));

static krb5_error_code
hack_init ()
{
    krb5_error_code c;
    c = krb5int_mutex_alloc (&krb5_db2_mutex);
    if (c)
	return c;
    return krb5_db2_lib_init ();
}

static krb5_error_code
hack_cleanup (void)
{
    krb5int_mutex_free (krb5_db2_mutex);
    krb5_db2_mutex = NULL;
    return krb5_db2_lib_cleanup();
}


/*
 *      Exposed API
 */

kdb_vftabl kdb_function_table = {
  /* major version number 1 */		       1,
  /* minor version number 0 */		       0,
  /* Solaris Kerberos: iprop support */
  /* iprop_supported, yes for db2 */	       1,
  /* init_library */			       hack_init,
  /* fini_library */			       hack_cleanup,
  /* init_module */			       wrap_krb5_db2_open,
  /* fini_module */			       wrap_krb5_db2_db_fini,
  /* db_create */			       wrap_krb5_db2_create,
  /* db_destroy */			       wrap_krb5_db2_destroy,
  /* db_get_age */                             wrap_krb5_db2_db_get_age,
  /* db_set_option */			       wrap_krb5_db2_db_set_option,
  /* db_lock */				       wrap_krb5_db2_db_lock,
  /* db_unlock */			       wrap_krb5_db2_db_unlock,
  /* db_get_principal */		       wrap_krb5_db2_db_get_principal,
  /* Solaris Kerberos: need a nolock for iprop */
  /* db_get_principal_nolock */		       krb5_db2_db_get_principal,
  /* db_free_principal */		       wrap_krb5_db2_db_free_principal,
  /* db_put_principal */		       wrap_krb5_db2_db_put_principal,
  /* db_delete_principal */		       wrap_krb5_db2_db_delete_principal,
  /* db_iterate */			       wrap_krb5_db2_db_iterate,
  /* db_create_policy */                       wrap_krb5_db2_create_policy,
  /* db_get_policy */                          wrap_krb5_db2_get_policy,
  /* db_put_policy */                          wrap_krb5_db2_put_policy,
  /* db_iter_policy */                         wrap_krb5_db2_iter_policy,
  /* db_delete_policy */                       wrap_krb5_db2_delete_policy,
  /* db_free_policy */                         wrap_krb5_db2_free_policy,
  /* db_supported_realms */		       NULL,
  /* db_free_supported_realms */	       NULL,
  /* errcode_2_string */                       krb5_db2_errcode_2_string,
  /* release_errcode_string */		       krb5_db2_release_errcode_string,
  /* db_alloc */                               wrap_krb5_db2_alloc,
  /* db_free */                                wrap_krb5_db2_free,
  /* set_master_key */			       wrap_krb5_db2_set_master_key_ext,
  /* get_master_key */			       wrap_krb5_db2_db_get_mkey,
  /* blah blah blah */ 0,0,0,0,0,0,
  /* promote_db */			       wrap_krb5_db2_promote_db,
};
