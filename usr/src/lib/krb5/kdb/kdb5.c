/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
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

/*
 * This code was based on code donated to MIT by Novell for
 * distribution under the MIT license.
 */

/* 
 * Include files
 */

#include <stdio.h>
#include <string.h>
#include <k5-int.h>
#include <osconf.h>
#include "kdb5.h"
#include <assert.h>
#include "k5-platform.h"
#include <libintl.h>

/* Currently DB2 policy related errors are exported from DAL.  But
   other databases should set_err function to return string.  */
#include "adb_err.h"

/*
 * Type definitions
 */
#define KRB5_TL_DB_ARGS                 0x7fff

/*
 * internal static variable
 */

static k5_mutex_t db_lock = K5_MUTEX_PARTIAL_INITIALIZER;

#ifdef _KDB5_STATIC_LINK
#undef _KDB5_DYNAMIC_LINK
#else
#undef _KDB5_DYNAMIC_LINK
/* to avoid redefinition problem */
#define _KDB5_DYNAMIC_LINK
#endif

static db_library lib_list;

/*
 * Helper Functions
 */

MAKE_INIT_FUNCTION(kdb_init_lock_list);
MAKE_FINI_FUNCTION(kdb_fini_lock_list);

int
kdb_init_lock_list(void)
{
    return k5_mutex_finish_init(&db_lock);
}

static int
kdb_lock_list()
{
    int err;
    err = CALL_INIT_FUNCTION (kdb_init_lock_list);
    if (err)
	return err;
    return k5_mutex_lock(&db_lock);
}

void
kdb_fini_lock_list(void)
{
    if (INITIALIZER_RAN(kdb_init_lock_list))
	k5_mutex_destroy(&db_lock);
}

static int
kdb_unlock_list()
{
    return k5_mutex_unlock(&db_lock);
}

#define kdb_init_lib_lock(a) 0
#define kdb_destroy_lib_lock(a) (void)0
#define kdb_lock_lib_lock(a, b) 0
#define kdb_unlock_lib_lock(a, b) (void)0

/* Caller must free result*/

static char *
kdb_get_conf_section(krb5_context kcontext)
{
    krb5_error_code status = 0;
    char   *result = NULL;
    char   *value = NULL;

    if (kcontext->default_realm == NULL)
	return NULL;
    /* The profile has to have been initialized.  If the profile was
       not initialized, expect nothing less than a crash.  */
    status = profile_get_string(kcontext->profile,
				/* realms */
				KDB_REALM_SECTION,
				kcontext->default_realm,
				/* under the realm name, database_module */
				KDB_MODULE_POINTER,
				/* default value is the realm name itself */
				kcontext->default_realm,
				&value);

    if (status) {
	/* some problem */
	result = strdup(kcontext->default_realm);
	/* let NULL be handled by the caller */
    } else {
	result = strdup(value);
	/* free profile string */
	profile_release_string(value);
    }

    return result;
}

static char *
kdb_get_library_name(krb5_context kcontext)
{
    krb5_error_code status = 0;
    char   *result = NULL;
    char   *value = NULL;
    char   *lib = NULL;

    status = profile_get_string(kcontext->profile,
				/* realms */
				KDB_REALM_SECTION,
				kcontext->default_realm,
				/* under the realm name, database_module */
				KDB_MODULE_POINTER,
				/* default value is the realm name itself */
				kcontext->default_realm,
				&value);
    if (status) {
	goto clean_n_exit;
    }

#define DB2_NAME "db2"
    /* we got the module section. Get the library name from the module */
    status = profile_get_string(kcontext->profile, KDB_MODULE_SECTION, value,
				KDB_LIB_POINTER,
				/* default to db2 */
				DB2_NAME,
				&lib);

    if (status) {
	goto clean_n_exit;
    }

    result = strdup(lib);
  clean_n_exit:
    if (value) {
	/* free profile string */
	profile_release_string(value);
    }

    if (lib) {
	/* free profile string */
	profile_release_string(lib);
    }
    return result;
}

static void
kdb_setup_opt_functions(db_library lib)
{
    if (lib->vftabl.set_master_key == NULL) {
	lib->vftabl.set_master_key = kdb_def_set_mkey;
    }

    if (lib->vftabl.get_master_key == NULL) {
	lib->vftabl.get_master_key = kdb_def_get_mkey;
    }

    if (lib->vftabl.fetch_master_key == NULL) {
	lib->vftabl.fetch_master_key = krb5_db_def_fetch_mkey;
    }

    if (lib->vftabl.verify_master_key == NULL) {
	lib->vftabl.verify_master_key = krb5_def_verify_master_key;
    }

    if (lib->vftabl.dbe_search_enctype == NULL) {
	lib->vftabl.dbe_search_enctype = krb5_dbe_def_search_enctype;
    }

    if (lib->vftabl.db_change_pwd == NULL) {
	lib->vftabl.db_change_pwd = krb5_dbe_def_cpw;
    }

    if (lib->vftabl.store_master_key == NULL) {
	lib->vftabl.store_master_key = krb5_def_store_mkey;
    }

    if (lib->vftabl.promote_db == NULL) {
	lib->vftabl.promote_db = krb5_def_promote_db;
    }
}

static int kdb_db2_pol_err_loaded = 0;
#ifdef _KDB5_STATIC_LINK
#define DEF_SYMBOL(a) extern kdb_vftabl krb5_db_vftabl_ ## a
#define GET_SYMBOL(a) (krb5_db_vftabl_ ## a)
static krb5_error_code
kdb_load_library(krb5_context kcontext, char *lib_name, db_library * lib)
{
    krb5_error_code status;
    void   *vftabl_addr = NULL;
    char    buf[KRB5_MAX_ERR_STR];

    if (!strcmp("kdb_db2", lib_name) && (kdb_db2_pol_err_loaded == 0)) {
	initialize_adb_error_table();
	kdb_db2_pol_err_loaded = 1;
    }

    *lib = calloc((size_t) 1, sizeof(**lib));
    if (*lib == NULL) {
	status = ENOMEM;
	goto clean_n_exit;
    }

    status = kdb_init_lib_lock(*lib);
    if (status) {
	goto clean_n_exit;
    }

    strcpy((*lib)->name, lib_name);

#if !defined(KDB5_USE_LIB_KDB_DB2) && !defined(KDB5_USE_LIB_TEST)
#error No database module defined
#endif

#ifdef KDB5_USE_LIB_KDB_DB2
    if (strcmp(lib_name, "kdb_db2") == 0) {
	DEF_SYMBOL(kdb_db2);
	vftabl_addr = (void *) &GET_SYMBOL(kdb_db2);
    } else
#endif
#ifdef KDB5_USE_LIB_TEST
    if (strcmp(lib_name, "test") == 0) {
	DEF_SYMBOL(test);
	vftabl_addr = (void *) &GET_SYMBOL(test);
    } else
#endif
    {
	snprintf(buf, sizeof(buf), gettext("Program not built to support %s database type\n"),
		lib_name);
	status = KRB5_KDB_DBTYPE_NOSUP;
	krb5_db_set_err(kcontext, krb5_err_have_str, status, buf);
	goto clean_n_exit;
    }

    memcpy(&(*lib)->vftabl, vftabl_addr, sizeof(kdb_vftabl));

    kdb_setup_opt_functions(*lib);

    if ((status = (*lib)->vftabl.init_library())) {
	/* ERROR. library not initialized cleanly */
	snprintf(buf, sizeof(buf), gettext("%s library initialization failed, error code %ld\n"),
		lib_name, status);
	status = KRB5_KDB_DBTYPE_INIT;
	krb5_db_set_err(kcontext, krb5_err_have_str, status, buf);
	goto clean_n_exit;
    }

  clean_n_exit:
    if (status) {
	free(*lib), *lib = NULL;
    }
    return status;
}

#else /* KDB5_STATIC_LINK*/

static char *db_dl_location[] = DEFAULT_KDB_LIB_PATH;
#define db_dl_n_locations (sizeof(db_dl_location) / sizeof(db_dl_location[0]))

static krb5_error_code
kdb_load_library(krb5_context kcontext, char *lib_name, db_library * lib)
{
    krb5_error_code status = 0;
    int     ndx;
    void  **vftabl_addrs = NULL;
    /* N.B.: If this is "const" but not "static", the Solaris 10
       native compiler has trouble building the library because of
       absolute relocations needed in read-only section ".rodata".
       When it's static, it goes into ".picdata", which is
       read-write.  */
    static const char *const dbpath_names[] = {
	KDB_MODULE_SECTION, "db_module_dir", NULL,
    };
    const char *filebases[2];
    char **profpath = NULL;
    char **path = NULL;

    filebases[0] = lib_name;
    filebases[1] = NULL;

    if (!strcmp(DB2_NAME, lib_name) && (kdb_db2_pol_err_loaded == 0)) {
	initialize_adb_error_table();
	kdb_db2_pol_err_loaded = 1;
    }

    *lib = calloc((size_t) 1, sizeof(**lib));
    if (*lib == NULL) {
	status = ENOMEM;
	goto clean_n_exit;
    }

    status = kdb_init_lib_lock(*lib);
    if (status) {
	goto clean_n_exit;
    }

    strcpy((*lib)->name, lib_name);

    /* Fetch the list of directories specified in the config
       file(s) first.  */
    status = profile_get_values(kcontext->profile, dbpath_names, &profpath);
    if (status != 0 && status != PROF_NO_RELATION)
	goto clean_n_exit;
    ndx = 0;
    if (profpath)
	while (profpath[ndx] != NULL)
	    ndx++;

    path = calloc(ndx + db_dl_n_locations, sizeof (char *));
    if (path == NULL) {
	status = errno;
	goto clean_n_exit;
    }
    if (ndx)
	memcpy(path, profpath, ndx * sizeof(profpath[0]));
    memcpy(path + ndx, db_dl_location, db_dl_n_locations * sizeof(char *));
    status = 0;
    
    if ((status = krb5int_open_plugin_dirs ((const char **) path, 
                                            filebases, 
                                            &(*lib)->dl_dir_handle, &kcontext->err))) {
        const char *err_str = krb5_get_error_message(kcontext, status);
	status = KRB5_KDB_DBTYPE_NOTFOUND;
	krb5_set_error_message (kcontext, status,
				gettext("Unable to find requested database type: %s"), err_str);
	krb5_free_error_message (kcontext, err_str);
	goto clean_n_exit;
    }

    if ((status = krb5int_get_plugin_dir_data (&(*lib)->dl_dir_handle, "kdb_function_table",
                                               &vftabl_addrs, &kcontext->err))) {
        const char *err_str = krb5_get_error_message(kcontext, status);
        status = KRB5_KDB_DBTYPE_INIT;
        krb5_set_error_message (kcontext, status,
                                gettext("plugin symbol 'kdb_function_table' lookup failed: %s"), err_str);
        krb5_free_error_message (kcontext, err_str);
	goto clean_n_exit;
    }

    if (vftabl_addrs[0] == NULL) {
	/* No plugins! */
	status = KRB5_KDB_DBTYPE_NOTFOUND;
	krb5_set_error_message (kcontext, status,
				gettext("Unable to load requested database module '%s': plugin symbol 'kdb_function_table' not found"),
				lib_name);
	goto clean_n_exit;
    }

    memcpy(&(*lib)->vftabl, vftabl_addrs[0], sizeof(kdb_vftabl));
    kdb_setup_opt_functions(*lib);
    
    if ((status = (*lib)->vftabl.init_library())) {
        /* ERROR. library not initialized cleanly */
        goto clean_n_exit;
    }    
    
clean_n_exit:
    if (vftabl_addrs != NULL) { krb5int_free_plugin_dir_data (vftabl_addrs); }
    /* Both of these DTRT with NULL.  */
    profile_free_list(profpath);
    free(path);
    if (status) {
        if (*lib) {
	    kdb_destroy_lib_lock(*lib);
            if (PLUGIN_DIR_OPEN((&(*lib)->dl_dir_handle))) {
                krb5int_close_plugin_dirs (&(*lib)->dl_dir_handle);
            }
	    free(*lib);
	    *lib = NULL;
	}
    }
    return status;
}

#endif /* end of _KDB5_STATIC_LINK */

static krb5_error_code
kdb_find_library(krb5_context kcontext, char *lib_name, db_library * lib)
{
    /* lock here so that no two threads try to do the same at the same time */
    krb5_error_code status = 0;
    int     locked = 0;
    db_library curr_elt, prev_elt = NULL;

    if ((status = kdb_lock_list()) != 0) {
	goto clean_n_exit;
    }
    locked = 1;

    curr_elt = lib_list;
    while (curr_elt != NULL) {
	if (strcmp(lib_name, curr_elt->name) == 0) {
	    *lib = curr_elt;
	    goto clean_n_exit;
	}
	prev_elt = curr_elt;
	curr_elt = curr_elt->next;
    }

    /* module not found. create and add to list */
    status = kdb_load_library(kcontext, lib_name, lib);
    if (status) {
	goto clean_n_exit;
    }

    if (prev_elt) {
	/* prev_elt points to the last element in the list */
	prev_elt->next = *lib;
	(*lib)->prev = prev_elt;
    } else {
	lib_list = *lib;
    }

  clean_n_exit:
    if (*lib) {
	(*lib)->reference_cnt++;
    }

    if (locked) {
	(void)kdb_unlock_list();
    }

    return status;
}

static krb5_error_code
kdb_free_library(db_library lib)
{
    krb5_error_code status = 0;
    int     locked = 0;

    if ((status = kdb_lock_list()) != 0) {
	goto clean_n_exit;
    }
    locked = 1;

    lib->reference_cnt--;

    if (lib->reference_cnt == 0) {
	status = lib->vftabl.fini_library();
	if (status) {
	    goto clean_n_exit;
	}

	/* close the library */
        if (PLUGIN_DIR_OPEN((&lib->dl_dir_handle))) {
            krb5int_close_plugin_dirs (&lib->dl_dir_handle);
        }
        
	kdb_destroy_lib_lock(lib);

	if (lib->prev == NULL) {
	    /* first element in the list */
	    lib_list = lib->next;
	} else {
	    lib->prev->next = lib->next;
	}

	if (lib->next) {
	    lib->next->prev = lib->prev;
	}
	free(lib);
    }

  clean_n_exit:
    if (locked) {
	(void)kdb_unlock_list();
    }

    return status;
}

static krb5_error_code
kdb_setup_lib_handle(krb5_context kcontext)
{
    char   *library = NULL;
    krb5_error_code status = 0;
    db_library lib = NULL;
    kdb5_dal_handle *dal_handle = NULL;

    dal_handle = calloc((size_t) 1, sizeof(kdb5_dal_handle));
    if (dal_handle == NULL) {
	status = ENOMEM;
	goto clean_n_exit;
    }

    library = kdb_get_library_name(kcontext);
    if (library == NULL) {
	status = KRB5_KDB_DBTYPE_NOTFOUND;
	goto clean_n_exit;
    }

    status = kdb_find_library(kcontext, library, &lib);
    if (status) {
	goto clean_n_exit;
    }

    dal_handle->lib_handle = lib;
    kcontext->db_context = (void *) dal_handle;

  clean_n_exit:
    free(library);

    if (status) {
	free(dal_handle);
	if (lib) {
	    (void)kdb_free_library(lib);
	}
    }

    return status;
}

static krb5_error_code
kdb_free_lib_handle(krb5_context kcontext)
{
    krb5_error_code status = 0;

    status =
	kdb_free_library(((kdb5_dal_handle *) kcontext->db_context)->
			 lib_handle);
    if (status) {
	goto clean_n_exit;
    }

    free(kcontext->db_context);
    kcontext->db_context = NULL;

  clean_n_exit:
    return status;
}

static void
get_errmsg (krb5_context kcontext, krb5_error_code err_code)
{
    kdb5_dal_handle *dal_handle;
    const char *e;
    if (err_code == 0)
	return;
    assert(kcontext != NULL);
    /* Must be called with dal_handle->lib_handle locked!  */
    assert(kcontext->db_context != NULL);
    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    if (dal_handle->lib_handle->vftabl.errcode_2_string == NULL)
	return;
    e = dal_handle->lib_handle->vftabl.errcode_2_string(kcontext, err_code);
    assert (e != NULL);
    krb5_set_error_message(kcontext, err_code, "%s", e);
    if (dal_handle->lib_handle->vftabl.release_errcode_string)
	dal_handle->lib_handle->vftabl.release_errcode_string(kcontext, e);
}

/*
 *      External functions... DAL API
 */
krb5_error_code
krb5_db_open(krb5_context kcontext, char **db_args, int mode)
{
    krb5_error_code status = 0;
    char   *section = NULL;
    kdb5_dal_handle *dal_handle;

    section = kdb_get_conf_section(kcontext);
    if (section == NULL) {
	status = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (kcontext, status,
		gettext("unable to determine configuration section for realm %s\n"),
		kcontext->default_realm ? kcontext->default_realm : "[UNSET]");
	goto clean_n_exit;
    }

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	/* Solaris Kerberos */
	kdb_free_lib_handle(kcontext);
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.init_module(kcontext, section, db_args,
						   mode);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

    /* Solaris Kerberos */
    if (status)
	kdb_free_lib_handle(kcontext);

  clean_n_exit:
    if (section)
	free(section);
    return status;
}

krb5_error_code
krb5_db_inited(krb5_context kcontext)
{
    return !(kcontext && kcontext->db_context &&
	     ((kdb5_dal_handle *) kcontext->db_context)->db_context);
}

krb5_error_code
krb5_db_create(krb5_context kcontext, char **db_args)
{
    krb5_error_code status = 0;
    char   *section = NULL;
    kdb5_dal_handle *dal_handle;

    section = kdb_get_conf_section(kcontext);
    if (section == NULL) {
	status = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (kcontext, status,
		gettext("unable to determine configuration section for realm %s\n"),
		kcontext->default_realm);
	goto clean_n_exit;
    }

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_create(kcontext, section, db_args);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    if (section)
	free(section);
    return status;
}

krb5_error_code
krb5_db_fini(krb5_context kcontext)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	/* module not loaded. So nothing to be done */
	goto clean_n_exit;
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.fini_module(kcontext);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

    if (status) {
	goto clean_n_exit;
    }

    status = kdb_free_lib_handle(kcontext);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_destroy(krb5_context kcontext, char **db_args)
{
    krb5_error_code status = 0;
    char   *section = NULL;
    kdb5_dal_handle *dal_handle;

    section = kdb_get_conf_section(kcontext);
    if (section == NULL) {
	status = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (kcontext, status,
		gettext("unable to determine configuration section for realm %s\n"),
		kcontext->default_realm);
	goto clean_n_exit;
    }

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_destroy(kcontext, section, db_args);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    if (section)
	free(section);
    return status;
}

krb5_error_code
krb5_db_get_age(krb5_context kcontext, char *db_name, time_t * t)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_get_age(kcontext, db_name, t);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_set_option(krb5_context kcontext, int option, void *value)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_set_option(kcontext, option, value);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_lock(krb5_context kcontext, int lock_mode)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    /* acquire an exclusive lock, ensures no other thread uses this context */
    status = kdb_lock_lib_lock(dal_handle->lib_handle, TRUE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_lock(kcontext, lock_mode);
    get_errmsg(kcontext, status);

    /* exclusive lock is still held, so no other thread could use this context */
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_unlock(krb5_context kcontext)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    /* normal lock acquired and exclusive lock released */
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_unlock(kcontext);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, TRUE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_get_principal(krb5_context kcontext,
		      krb5_const_principal search_for,
		      krb5_db_entry * entries,
		      int *nentries, krb5_boolean * more)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_get_principal(kcontext, search_for,
							entries, nentries,
							more);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_get_principal_nolock(krb5_context kcontext,
		      krb5_const_principal search_for,
		      krb5_db_entry * entries,
		      int *nentries, krb5_boolean * more)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_get_principal_nolock(kcontext,
							search_for,
							entries, nentries,
							more);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_free_principal(krb5_context kcontext, krb5_db_entry * entry, int count)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_free_principal(kcontext, entry,
							 count);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_put_principal(krb5_context kcontext,
		      krb5_db_entry * entries, int *nentries)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;
    char  **db_args = NULL;
    krb5_tl_data *prev, *curr, *next;
    int     db_args_size = 0;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    /* Giving db_args as part of tl data causes, db2 to store the
       tl_data as such.  To prevent this, tl_data is collated and
       passed as a sepearte argument. Currently supports only one
       principal.  but passing it as a seperate argument makes it
       difficult for kadmin remote to pass arguments to server.  */
    prev = NULL, curr = entries->tl_data;
    while (curr) {
	if (curr->tl_data_type == KRB5_TL_DB_ARGS) {
	    char  **t;
	    /* Since this is expected to be NULL terminated string and
	       this could come from any client, do a check before
	       passing it to db.  */
	    if (((char *) curr->tl_data_contents)[curr->tl_data_length - 1] !=
		'\0') {
		/* not null terminated. Dangerous input */
		status = EINVAL;
		goto clean_n_exit;
	    }

	    db_args_size++;
	    t = realloc(db_args, sizeof(char *) * (db_args_size + 1));	/* 1 for NULL */
	    if (t == NULL) {
		status = ENOMEM;
		goto clean_n_exit;
	    }

	    db_args = t;
	    db_args[db_args_size - 1] = (char *) curr->tl_data_contents;
	    db_args[db_args_size] = NULL;

	    next = curr->tl_data_next;
	    if (prev == NULL) {
		/* current node is the first in the linked list. remove it */
		entries->tl_data = curr->tl_data_next;
	    } else {
		prev->tl_data_next = curr->tl_data_next;
	    }
	    entries->n_tl_data--;
	    krb5_db_free(kcontext, curr);

	    /* previous does not change */
	    curr = next;
	} else {
	    prev = curr;
	    curr = curr->tl_data_next;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_put_principal(kcontext, entries,
							     nentries,
							     db_args);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    while (db_args_size) {
	if (db_args[db_args_size - 1])
	    krb5_db_free(kcontext, db_args[db_args_size - 1]);

	db_args_size--;
    }

    if (db_args)
	free(db_args);

    return status;
}

krb5_error_code
krb5_db_delete_principal(krb5_context kcontext,
			 krb5_principal search_for, int *nentries)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_delete_principal(kcontext,
							   search_for,
							   nentries);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_iterate(krb5_context kcontext,
		char *match_entry,
		int (*func) (krb5_pointer, krb5_db_entry *),
		krb5_pointer func_arg,
		/* Solaris Kerberos: adding support for db_args */
		char **db_args)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    /* Solaris Kerberos: adding support for db_args */
    status = dal_handle->lib_handle->vftabl.db_iterate(kcontext,
						       match_entry,
						       func, func_arg,
						       db_args);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_supported_realms(krb5_context kcontext, char **realms)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_supported_realms(kcontext, realms);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_free_supported_realms(krb5_context kcontext, char **realms)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_free_supported_realms(kcontext,
								realms);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_set_master_key_ext(krb5_context kcontext,
			   char *pwd, krb5_keyblock * key)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.set_master_key(kcontext, pwd, key);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_set_mkey(krb5_context context, krb5_keyblock * key)
{
    return krb5_db_set_master_key_ext(context, NULL, key);
}

krb5_error_code
krb5_db_get_mkey(krb5_context kcontext, krb5_keyblock ** key)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    /* Lets use temp key and copy it later to avoid memory problems
       when freed by the caller.  */
    status = dal_handle->lib_handle->vftabl.get_master_key(kcontext, key);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_store_master_key(krb5_context kcontext,
			 char *db_arg,
			 krb5_principal mname,
			 krb5_keyblock * key, char *master_pwd)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.store_master_key(kcontext,
							     db_arg,
							     mname,
							     key, master_pwd);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

char   *krb5_mkey_pwd_prompt1 = KRB5_KDC_MKEY_1;
char   *krb5_mkey_pwd_prompt2 = KRB5_KDC_MKEY_2;

krb5_error_code
krb5_db_fetch_mkey(krb5_context context,
		   krb5_principal mname,
		   krb5_enctype etype,
		   krb5_boolean fromkeyboard,
		   krb5_boolean twice,
		   char *db_args, krb5_data * salt, krb5_keyblock * key)
{
    krb5_error_code retval;
    char    password[BUFSIZ];
    krb5_data pwd;
    unsigned int size = sizeof(password);
    int     kvno;
    krb5_keyblock tmp_key;

    memset(&tmp_key, 0, sizeof(tmp_key));

    if (fromkeyboard) {
	krb5_data scratch;

	if ((retval = krb5_read_password(context, krb5_mkey_pwd_prompt1,
					 twice ? krb5_mkey_pwd_prompt2 : 0,
					 password, &size))) {
	    goto clean_n_exit;
	}

	pwd.data = password;
	pwd.length = size;
	if (!salt) {
	    retval = krb5_principal2salt(context, mname, &scratch);
	    if (retval)
		goto clean_n_exit;
	}
	retval =
	    krb5_c_string_to_key(context, etype, &pwd, salt ? salt : &scratch,
				 key);

	if (!salt)
	    krb5_xfree(scratch.data);
	memset(password, 0, sizeof(password));	/* erase it */

    } else {
	kdb5_dal_handle *dal_handle;

	if (context->db_context == NULL) {
	    retval = kdb_setup_lib_handle(context);
	    if (retval) {
		goto clean_n_exit;
	    }
	}

	dal_handle = (kdb5_dal_handle *) context->db_context;
	retval = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
	if (retval) {
	    goto clean_n_exit;
	}
#if 0 /************** Begin IFDEF'ed OUT *******************************/
	/* Orig MIT */
	tmp_key.enctype = key->enctype;
#else
	/* Solaris Kerberos: need to use etype */
	tmp_key.enctype = etype;
#endif /**************** END IFDEF'ed OUT *******************************/
	retval = dal_handle->lib_handle->vftabl.fetch_master_key(context,
								 mname,
								 &tmp_key,
								 &kvno,
								 db_args);
	get_errmsg(context, retval);
	kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

	if (retval) {
	    goto clean_n_exit;
	}

	key->contents = malloc(tmp_key.length);
	if (key->contents == NULL) {
	    retval = ENOMEM;
	    goto clean_n_exit;
	}

	key->magic = tmp_key.magic;
	key->enctype = tmp_key.enctype;
	key->length = tmp_key.length;
	memcpy(key->contents, tmp_key.contents, tmp_key.length);
    }

  clean_n_exit:
    if (tmp_key.contents) {
	memset(tmp_key.contents, 0, tmp_key.length);
	krb5_db_free(context, tmp_key.contents);
    }
    return retval;
}

krb5_error_code
krb5_db_verify_master_key(krb5_context kcontext,
			  krb5_principal mprinc, krb5_keyblock * mkey)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.verify_master_key(kcontext,
							      mprinc, mkey);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

void   *
krb5_db_alloc(krb5_context kcontext, void *ptr, size_t size)
{
    krb5_error_code status;
    kdb5_dal_handle *dal_handle;
    void   *new_ptr = NULL;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;

    new_ptr = dal_handle->lib_handle->vftabl.db_alloc(kcontext, ptr, size);

  clean_n_exit:
    return new_ptr;
}

void
krb5_db_free(krb5_context kcontext, void *ptr)
{
    krb5_error_code status;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;

    dal_handle->lib_handle->vftabl.db_free(kcontext, ptr);

  clean_n_exit:
    return;
}

/* has to be modified */

krb5_error_code
krb5_dbe_find_enctype(krb5_context kcontext,
		      krb5_db_entry * dbentp,
		      krb5_int32 ktype,
		      krb5_int32 stype,
		      krb5_int32 kvno, krb5_key_data ** kdatap)
{
    krb5_int32 start = 0;
    return krb5_dbe_search_enctype(kcontext, dbentp, &start, ktype, stype,
				   kvno, kdatap);
}

krb5_error_code
krb5_dbe_search_enctype(krb5_context kcontext,
			krb5_db_entry * dbentp,
			krb5_int32 * start,
			krb5_int32 ktype,
			krb5_int32 stype,
			krb5_int32 kvno, krb5_key_data ** kdatap)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.dbe_search_enctype(kcontext,
							       dbentp,
							       start,
							       ktype,
							       stype,
							       kvno, kdatap);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

#define	REALM_SEP_STRING	"@"

krb5_error_code
krb5_db_setup_mkey_name(krb5_context context,
			const char *keyname,
			const char *realm,
			char **fullname, krb5_principal * principal)
{
    krb5_error_code retval;
    size_t  keylen;
    size_t  rlen = strlen(realm);
    char   *fname;

    if (!keyname)
	keyname = KRB5_KDB_M_NAME;	/* XXX external? */

    keylen = strlen(keyname);

    fname = malloc(keylen + rlen + strlen(REALM_SEP_STRING) + 1);
    if (!fname)
	return ENOMEM;

    strcpy(fname, keyname);
    (void)strcat(fname, REALM_SEP_STRING);
    (void)strcat(fname, realm);

    if ((retval = krb5_parse_name(context, fname, principal)))
	return retval;
    if (fullname)
	*fullname = fname;
    else
	free(fname);
    return 0;
}

krb5_error_code
krb5_dbe_lookup_last_pwd_change(context, entry, stamp)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_timestamp *stamp;
{
    krb5_tl_data tl_data;
    krb5_error_code code;
    krb5_int32 tmp;

    tl_data.tl_data_type = KRB5_TL_LAST_PWD_CHANGE;

    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
	return (code);

    if (tl_data.tl_data_length != 4) {
	*stamp = 0;
	return (0);
    }

    krb5_kdb_decode_int32(tl_data.tl_data_contents, tmp);

    *stamp = (krb5_timestamp) tmp;

    return (0);
}

/*ARGSUSED*/
krb5_error_code
krb5_dbe_lookup_tl_data(context, entry, ret_tl_data)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_tl_data *ret_tl_data;
{
    krb5_tl_data *tl_data;

    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next) {
	if (tl_data->tl_data_type == ret_tl_data->tl_data_type) {
	    *ret_tl_data = *tl_data;
	    return (0);
	}
    }

    /* if the requested record isn't found, return zero bytes.
     * if it ever means something to have a zero-length tl_data,
     * this code and its callers will have to be changed */

    ret_tl_data->tl_data_length = 0;
    ret_tl_data->tl_data_contents = NULL;
    return (0);
}

krb5_error_code
krb5_dbe_create_key_data(context, entry)
    krb5_context context;
    krb5_db_entry *entry;
{
    if ((entry->key_data =
	 (krb5_key_data *) krb5_db_alloc(context, entry->key_data,
					 (sizeof(krb5_key_data) *
					  (entry->n_key_data + 1)))) == NULL)
	return (ENOMEM);

    memset(entry->key_data + entry->n_key_data, 0, sizeof(krb5_key_data));
    entry->n_key_data++;

    return 0;
}

krb5_error_code
krb5_dbe_update_mod_princ_data(context, entry, mod_date, mod_princ)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_timestamp mod_date;
    krb5_const_principal mod_princ;
{
    krb5_tl_data tl_data;

    krb5_error_code retval = 0;
    krb5_octet *nextloc = 0;
    char   *unparse_mod_princ = 0;
    unsigned int unparse_mod_princ_size;

    if ((retval = krb5_unparse_name(context, mod_princ, &unparse_mod_princ)))
	return (retval);

    unparse_mod_princ_size = strlen(unparse_mod_princ) + 1;

    if ((nextloc = (krb5_octet *) malloc(unparse_mod_princ_size + 4))
	== NULL) {
	free(unparse_mod_princ);
	return (ENOMEM);
    }

    tl_data.tl_data_type = KRB5_TL_MOD_PRINC;
    tl_data.tl_data_length = unparse_mod_princ_size + 4;
    tl_data.tl_data_contents = nextloc;

    /* Mod Date */
    krb5_kdb_encode_int32(mod_date, nextloc);

    /* Mod Princ */
    memcpy(nextloc + 4, unparse_mod_princ, unparse_mod_princ_size);

    retval = krb5_dbe_update_tl_data(context, entry, &tl_data);

    free(unparse_mod_princ);
    free(nextloc);

    return (retval);
}

krb5_error_code
krb5_dbe_lookup_mod_princ_data(context, entry, mod_time, mod_princ)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_timestamp *mod_time;
    krb5_principal *mod_princ;
{
    krb5_tl_data tl_data;
    krb5_error_code code;

    tl_data.tl_data_type = KRB5_TL_MOD_PRINC;

    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
	return (code);

    if ((tl_data.tl_data_length < 5) ||
	(tl_data.tl_data_contents[tl_data.tl_data_length - 1] != '\0'))
	return (KRB5_KDB_TRUNCATED_RECORD);

    /* Mod Date */
    krb5_kdb_decode_int32(tl_data.tl_data_contents, *mod_time);

    /* Mod Princ */
    if ((code = krb5_parse_name(context,
				(const char *) (tl_data.tl_data_contents + 4),
				mod_princ)))
	return (code);

    return (0);
}

krb5_error_code
krb5_dbe_update_last_pwd_change(context, entry, stamp)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_timestamp stamp;
{
    krb5_tl_data tl_data;
    krb5_octet buf[4];		/* this is the encoded size of an int32 */

    tl_data.tl_data_type = KRB5_TL_LAST_PWD_CHANGE;
    tl_data.tl_data_length = sizeof(buf);
    krb5_kdb_encode_int32((krb5_int32) stamp, buf);
    tl_data.tl_data_contents = buf;

    return (krb5_dbe_update_tl_data(context, entry, &tl_data));
}

krb5_error_code
krb5_dbe_update_tl_data(context, entry, new_tl_data)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_tl_data *new_tl_data;
{
    krb5_tl_data *tl_data = NULL;
    krb5_octet *tmp;

    /* copy the new data first, so we can fail cleanly if malloc()
     * fails */
    if ((tmp =
	 (krb5_octet *) krb5_db_alloc(context, NULL,
				      new_tl_data->tl_data_length)) == NULL)
	return (ENOMEM);

    /* Find an existing entry of the specified type and point at
     * it, or NULL if not found */

    if (new_tl_data->tl_data_type != KRB5_TL_DB_ARGS) {	/* db_args can be multiple */
	for (tl_data = entry->tl_data; tl_data;
	     tl_data = tl_data->tl_data_next)
	    if (tl_data->tl_data_type == new_tl_data->tl_data_type)
		break;
    }

    /* if necessary, chain a new record in the beginning and point at it */

    if (!tl_data) {
	if ((tl_data =
	     (krb5_tl_data *) krb5_db_alloc(context, NULL,
					    sizeof(krb5_tl_data)))
	    == NULL) {
	    free(tmp);
	    return (ENOMEM);
	}
	memset(tl_data, 0, sizeof(krb5_tl_data));
	tl_data->tl_data_next = entry->tl_data;
	entry->tl_data = tl_data;
	entry->n_tl_data++;
    }

    /* fill in the record */

    if (tl_data->tl_data_contents)
	krb5_db_free(context, tl_data->tl_data_contents);

    tl_data->tl_data_type = new_tl_data->tl_data_type;
    tl_data->tl_data_length = new_tl_data->tl_data_length;
    tl_data->tl_data_contents = tmp;
    memcpy(tmp, new_tl_data->tl_data_contents, tl_data->tl_data_length);

    return (0);
}

/* change password functions */
krb5_error_code
krb5_dbe_cpw(krb5_context kcontext,
	     krb5_keyblock * master_key,
	     krb5_key_salt_tuple * ks_tuple,
	     int ks_tuple_count,
	     char *passwd,
	     int new_kvno, krb5_boolean keepold, krb5_db_entry * db_entry)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_change_pwd(kcontext,
							  master_key,
							  ks_tuple,
							  ks_tuple_count,
							  passwd,
							  new_kvno,
							  keepold, db_entry);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

/* policy management functions */
krb5_error_code
krb5_db_create_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_create_policy(kcontext, policy);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_get_policy(krb5_context kcontext, char *name,
		   osa_policy_ent_t * policy, int *cnt)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_get_policy(kcontext, name, policy,
						     cnt);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_put_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_put_policy(kcontext, policy);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_iter_policy(krb5_context kcontext, char *match_entry,
		    osa_adb_iter_policy_func func, void *data)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_iter_policy(kcontext, match_entry,
						      func, data);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_delete_policy(krb5_context kcontext, char *policy)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_delete_policy(kcontext, policy);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

void
krb5_db_free_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    dal_handle->lib_handle->vftabl.db_free_policy(kcontext, policy);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return;
}

krb5_error_code
krb5_db_promote(krb5_context kcontext, char **db_args)
{
    krb5_error_code status = 0;
    char   *section = NULL;
    kdb5_dal_handle *dal_handle;

    section = kdb_get_conf_section(kcontext);
    if (section == NULL) {
	status = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (kcontext, status,
		gettext("unable to determine configuration section for realm %s\n"),
		kcontext->default_realm);
	goto clean_n_exit;
    }

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.promote_db(kcontext, section, db_args);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    if (section)
	free(section);
    return status;
}

/* 
 * Solaris Kerberos: support for iprop
 *
 * Not all KDB plugins support iprop.
 *
 * sets iprop_supported to 1 if iprop supportd, 0 otherwise.
 */
krb5_error_code
krb5_db_supports_iprop(krb5_context kcontext, int *iprop_supported)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->db_context == NULL) {
	status = kdb_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = (kdb5_dal_handle *) kcontext->db_context;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    *iprop_supported = dal_handle->lib_handle->vftabl.iprop_supported;
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}
