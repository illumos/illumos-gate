#ifndef _KRB5_KDB5_H_
#define _KRB5_KDB5_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <utime.h>
#include <utime.h>
#include <k5-int.h>
#include "kdb.h"

#define KDB_MAX_DB_NAME 128
#define KDB_REALM_SECTION  "realms"
#define KDB_MODULE_POINTER "database_module"
#define KDB_MODULE_DEF_SECTION "dbdefaults"
#define KDB_MODULE_SECTION "dbmodules"
#define KDB_LIB_POINTER    "db_library"
#define KDB_DATABASE_CONF_FILE  DEFAULT_SECURE_PROFILE_PATH
#define KDB_DATABASE_ENV_PROF KDC_PROFILE_ENV

#define KRB5_DB_GET_DB_CONTEXT(kcontext) (((kdb5_dal_handle*) (kcontext)->db_context)->db_context)
#define KRB5_DB_GET_PROFILE(kcontext)  ((kcontext)->profile)
#define KRB5_DB_GET_REALM(kcontext)    ((kcontext)->default_realm)

typedef struct _kdb_vftabl{
    short int maj_ver;
    short int min_ver;
    int       iprop_supported;

    krb5_error_code (*init_library)();
    krb5_error_code (*fini_library)();
    krb5_error_code (*init_module) (krb5_context kcontext,
				    char * conf_section,
				    char ** db_args,
				    int mode);

    krb5_error_code (*fini_module) (krb5_context kcontext);

    krb5_error_code (*db_create) (krb5_context kcontext,
				  char * conf_section,
				  char ** db_args);

    krb5_error_code (*db_destroy) (krb5_context kcontext,
				   char *conf_section,
				   char ** db_args);

    krb5_error_code (*db_get_age) (krb5_context kcontext,
				   char *db_name,
				   time_t *age);

    krb5_error_code (*db_set_option) (krb5_context kcontext,
				      int option,
				      void *value);

    krb5_error_code (*db_lock) (krb5_context kcontext,
				int mode);

    krb5_error_code (*db_unlock) (krb5_context kcontext);

    krb5_error_code (*db_get_principal) (krb5_context kcontext,
					 krb5_const_principal search_for,
					 krb5_db_entry *entries,
					 int *nentries,
					 krb5_boolean *more);

    krb5_error_code (*db_get_principal_nolock) (krb5_context kcontext,
					 krb5_const_principal search_for,
					 krb5_db_entry *entries,
					 int *nentries,
					 krb5_boolean *more);

    krb5_error_code (*db_free_principal) (krb5_context kcontext,
					  krb5_db_entry *entry,
					  int count);

    krb5_error_code (*db_put_principal) (krb5_context kcontext,
					 krb5_db_entry *entries,
					 int *nentries,
					 char **db_args);

    krb5_error_code (*db_delete_principal) (krb5_context kcontext,
					    krb5_const_principal search_for,
					    int *nentries);

    /* Solaris Kerberos: adding support for db_args */
    krb5_error_code (*db_iterate) (krb5_context kcontext,
				   char *match_entry,
				   int (*func) (krb5_pointer, krb5_db_entry *),
				   krb5_pointer func_arg,
				   char **db_args);

    krb5_error_code (*db_create_policy) (krb5_context kcontext,
					 osa_policy_ent_t policy);

    krb5_error_code (*db_get_policy) (krb5_context kcontext,
				      char *name,
				      osa_policy_ent_t *policy,
				      int *cnt);

    krb5_error_code (*db_put_policy) (krb5_context kcontext,
				      osa_policy_ent_t policy);

    krb5_error_code (*db_iter_policy) (krb5_context kcontext,
				       char *match_entry,
				       osa_adb_iter_policy_func func,
				       void *data);


    krb5_error_code (*db_delete_policy) (krb5_context kcontext,
					 char *policy);

    void (*db_free_policy) (krb5_context kcontext,
			    osa_policy_ent_t val);

    krb5_error_code (*db_supported_realms) (krb5_context kcontext,
					    char **realms);

    krb5_error_code (*db_free_supported_realms) (krb5_context kcontext,
						 char **realms);


    const char * (*errcode_2_string) (krb5_context kcontext,
				      long err_code);
    void (*release_errcode_string) (krb5_context kcontext, const char *msg);

    void * (*db_alloc) (krb5_context kcontext, void *ptr, size_t size);
    void   (*db_free)  (krb5_context kcontext, void *ptr);



    /* optional functions */
    krb5_error_code (*set_master_key) (krb5_context kcontext,
				       char *pwd,
				       krb5_keyblock *key);

    krb5_error_code (*get_master_key) (krb5_context kcontext,
				       krb5_keyblock **key);


    krb5_error_code (*setup_master_key_name) (krb5_context kcontext,
					      char *keyname,
					      char *realm,
					      char **fullname,
					      krb5_principal  *principal);

    krb5_error_code (*store_master_key) (krb5_context kcontext,
					 char *db_arg,
					 krb5_principal mname,
					 krb5_keyblock *key,
					 char *master_pwd);

    krb5_error_code (*fetch_master_key) (krb5_context kcontext,
					 krb5_principal mname,
					 krb5_keyblock *key,
					 int *kvno,
					 char *db_args);

    krb5_error_code (*verify_master_key) (krb5_context kcontext,
					  krb5_principal mprinc,
					  krb5_keyblock *mkey);

    krb5_error_code (*dbe_search_enctype) (krb5_context kcontext,
					   krb5_db_entry *dbentp,
					   krb5_int32 *start,
					   krb5_int32 ktype,
					   krb5_int32 stype,
					   krb5_int32 kvno,
					   krb5_key_data **kdatap);


    krb5_error_code
    (*db_change_pwd) (krb5_context	  context,
		      krb5_keyblock     * master_key,
		      krb5_key_salt_tuple * ks_tuple,
		      int		  ks_tuple_count,
		      char 		* passwd,
		      int		  new_kvno,
		      krb5_boolean	  keepold,
		      krb5_db_entry	* db_entry);

    /* Promote a temporary database to be the live one.  */
    krb5_error_code (*promote_db) (krb5_context context,
				   char *conf_section,
				   char **db_args);

} kdb_vftabl;

typedef struct _db_library {
    char name[KDB_MAX_DB_NAME];
    int reference_cnt;
    struct plugin_dir_handle dl_dir_handle;
    kdb_vftabl vftabl;
    struct _db_library *next, *prev;
} *db_library;

typedef struct _kdb5_dal_handle
{
    /* Helps us to change db_library without affecting modules to some
       extent.  */
    void *db_context;
    db_library lib_handle;
} kdb5_dal_handle;

#endif  /* end of _KRB5_KDB5_H_ */
