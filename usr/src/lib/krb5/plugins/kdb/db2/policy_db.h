/*
 * Data Types for policy and principal information that
 * exists in the respective databases.
 *
 * $Header$
 *
 * This file was originally created with rpcgen.
 * It has been hacked up since then.
 */

#ifndef __ADB_H__
#define __ADB_H__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <errno.h>
#include <krb5.h>
#include <kdb.h>
/* Okay, this is a bit obscure.  The libdb2 configure script doesn't
   detect it, but on Tru64 5.1, netinet/in.h causes sys/bittypes.h to
   be included, and that has a typedef for u_int32_t.  Because the
   configure script doesn't detect it, it causes db-config.h to have a
   #define for u_int32_t, so including db.h and then netinet/in.h
   causes compilation to fail.

   Since gssrpc/types.h includes netinet/in.h, including that first
   will cause the typedef to be seen before the macro definition,
   which still isn't quite right, but is close enough for now.

   A better fix might be for db.h to include netinet/in.h if that's
   where we find u_int32_t.  */
/* Solaris Kerberos: gssrpc not supported */
#if 0 /************** Begin IFDEF'ed OUT *******************************/
#include <gssrpc/types.h>
#include <gssrpc/xdr.h>
#else
#include <rpc/types.h>
#include <rpc/xdr.h>
#endif /**************** END IFDEF'ed OUT *******************************/
#include <db.h>
#include <kdb/adb_err.h>
#include <com_err.h>

typedef	long		osa_adb_ret_t;

#define OSA_ADB_POLICY_DB_MAGIC	0x12345A00

#define OSA_ADB_POLICY_VERSION_MASK	0x12345D00
#define OSA_ADB_POLICY_VERSION_1	0x12345D01



typedef struct _osa_adb_db_lock_ent_t {
     FILE     *lockfile;
     char     *filename;
     int      refcnt, lockmode, lockcnt;
     krb5_context context;
} osa_adb_lock_ent, *osa_adb_lock_t;

typedef struct _osa_adb_db_ent_t {
     int        magic;
     DB         *db;
     HASHINFO   info;
     BTREEINFO  btinfo;
     char       *filename;
     osa_adb_lock_t lock;
     int        opencnt;
} osa_adb_db_ent, *osa_adb_db_t, *osa_adb_princ_t, *osa_adb_policy_t;

/*
 * Return Code (the rest are in adb_err.h)
 */
 
#define OSA_ADB_OK		0

/*
 * Functions
 */

krb5_error_code	osa_adb_create_db(char *filename, char *lockfile, int magic);
krb5_error_code	osa_adb_destroy_db(char *filename, char *lockfile, int magic);
krb5_error_code   osa_adb_rename_db(char *filefrom, char *lockfrom,
				  char *fileto, char *lockto, int magic);
krb5_error_code	osa_adb_init_db(osa_adb_db_t *dbp, char *filename,
				char *lockfile, int magic);
krb5_error_code	osa_adb_fini_db(osa_adb_db_t db, int magic);
krb5_error_code	osa_adb_get_lock(osa_adb_db_t db, int mode);
krb5_error_code	osa_adb_release_lock(osa_adb_db_t db);
krb5_error_code osa_adb_open_and_lock(osa_adb_princ_t db, int locktype);
krb5_error_code osa_adb_close_and_unlock(osa_adb_princ_t db);
krb5_error_code	osa_adb_close_policy(osa_adb_policy_t db);
krb5_error_code	osa_adb_create_policy(osa_adb_policy_t db,
				      osa_policy_ent_t entry);
krb5_error_code	osa_adb_destroy_policy(osa_adb_policy_t db,
				       char * name);
krb5_error_code	osa_adb_get_policy(osa_adb_policy_t db,
				   char * name,
				   osa_policy_ent_t *entry,
				   int *cnt);
krb5_error_code	osa_adb_put_policy(osa_adb_policy_t db,
				   osa_policy_ent_t entry);
krb5_error_code	osa_adb_iter_policy(osa_adb_policy_t db,
				    osa_adb_iter_policy_func func,
				    void * data);
void		osa_free_policy_ent(osa_policy_ent_t val);

bool_t  xdr_osa_policy_ent_rec(XDR *xdrs, osa_policy_ent_t objp);

#endif /* __ADB_H__ */
