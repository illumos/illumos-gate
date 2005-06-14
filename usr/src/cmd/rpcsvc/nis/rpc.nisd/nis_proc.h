/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NIS_PROC_H
#define	_NIS_PROC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <nis_servlist.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	nis_proc.h
 *
 * This module contains definitions used by the NIS service.
 *
 */

/*
 * Structure definitions used by the various functions
 */
struct nis_db_result {
	nis_error	status;	/* Status of the result		   */
	nis_object	*obj;	/* Pointer to the object returned  */
	unsigned long	ticks;	/* Number of clock ticks used	   */
};

typedef struct nis_db_result nis_db_result;

struct obj_list {
	u_char		r;	/* readable flag	*/
	nis_object	*o;	/* object		*/
};

typedef struct obj_list	obj_list;
struct nis_db_list_result {
	nis_error	status;	/* return status */
	obj_list	*objs;	/* Objects returned */
	int		numo;	/* Number of objects */
	unsigned long	ticks;	/* Database ticks */
};

typedef struct nis_db_list_result nis_db_list_result;

struct nis_fn_result {
	nis_error	status;	/* Return status */
	nis_object	*obj;	/* The object returned */
	netobj		cookie; /* The magic cookie (db state) */
	unsigned long	ticks;	/* the obligatory ticks value */
};

typedef struct nis_fn_result nis_fn_result;

struct limits {
	int	max_attrval;	/* Maximum length of 1 attribute */
	int	max_attr;	/* Maximum number of attributes  */
	int	max_columns;	/* Maximum number of columns	 */
};

struct ticks {
	u_long	aticks;
	u_long	dticks;
	u_long	zticks;
	u_long	cticks;
};

struct object_list {
	int		num;
	nis_object	*objs;
};

struct cleanup {
	void		(*func)();
	void		*data;
	char		*tag;
	int		id;
	struct cleanup *next;
};
typedef struct cleanup cleanup;

struct xdr_clean_data {
	bool_t		(*xdr_func)();
	char		*xdr_data;
};
typedef struct xdr_clean_data xdr_clean_data;


#define		INIT_UPD_LIST_TIME_INCR	120
#define		MAX_UPD_LIST_TIME_INCR	1920

/*
 * "nis_mt.h" needs some of the declarations above (notably nis_fn_result),
 * but also redefines some items below, so it needs to be included here.
 */
#include "nis_mt.h"
/*
 * We include <nisdb_ldap.h> and "nis_ldap.h" here as a convenience for
 * the rpc.nisd source files.
 */
#include <nisdb_ldap.h>
#include "nis_ldap.h"

struct ping_item {
	NIS_HASH_ITEM	item;	/* Item struct for hash functions  */
	u_long		mtime;	/* Time of the update		   */
	nis_object	*obj;	/* Directory object.		   */
	u_long		utime;	/* Time we will retry this entry   */
	u_long		delta;	/* Current value of time increment */
};

typedef struct ping_item ping_item;

struct sdata {
	void	*buf;	/* Memory allocation pointer */
	u_long	size;	/* Size of allocated data    */
};

/* operations statistics vector */
struct ops_stats {
	u_long	op;		/* Operation (procedure number)  */
	u_long	calls;		/* Times called			 */
	u_long	errors;		/* Error encountered in call	*/
	int	cursamp;	/* current sample index		 */
	u_long	tsamps[16];	/* last 16 time measurements	 */
};

/*
 * Used for caching table objects
 */
struct table_item {
	NIS_HASH_ITEM	ti_item;	/* Generic ITEM tag */
	nis_object	*ibobj;		/* Table object */
};

/*
 * Map callback pid/tid to an anonymous number
 */
typedef	pid_t			anonid_t;
struct callback_id {
	pthread_t		id;
	anonid_t		anonid;
	nis_name		pname;
	struct callback_id	*next;
};
typedef	struct callback_id	callback_id;

/*
 * Forward reference declarations for functions in the service and in
 * the nis library
 */

#ifdef __STDC__
/* in nis_db.c */
extern void		__make_legal(char *);
extern nis_db_result 	*db_add(nis_name, nis_object *, int);
extern nis_error 	__db_add(nis_name, nis_object *, int);
extern nis_db_result 	*db_remove(nis_name, nis_object *, u_long);
extern nis_error 	__db_remove(nis_name, nis_object *);
extern nis_db_result 	*db_lookup(nis_name);
extern nis_db_result	*db_lookup_deferred(nis_name, bool_t);
extern nis_db_list_result *db_list(nis_name, int, nis_attr *);
extern nis_db_list_result *db_list_flags(nis_name, int, nis_attr *, u_long);
extern void		free_db_list(nis_db_list_result *);
extern nis_db_result 	*db_addib(nis_name, int, nis_attr *, nis_object *,
								nis_object *);
extern nis_error 	__db_addib(nis_name, int, nis_attr *, nis_object *);
extern nis_error 	__db_addib_nolog(nis_name, int, nis_attr *,
								nis_object *);
extern nis_error 	__db_addib_nosync(nis_name, int, nis_attr *,
								nis_object *);
extern nis_db_result 	*db_remib(nis_name, int, nis_attr *, obj_list *, int,
							nis_object *, u_long);
extern nis_error 	__db_remib(nis_name, int, nis_attr *);
extern nis_error 	__db_remib_nosync(nis_name, int, nis_attr *);
extern nis_fn_result 	*db_firstib(nis_name, int, nis_attr *, int, char *);
extern nis_fn_result 	*db_nextib(nis_name, netobj *, int, char *);
extern nis_error	db_find_table(nis_name);
extern nis_error	db_create(nis_name, table_obj*);
extern nis_error	db_destroy(nis_name);
extern void		db_flush(nis_name, netobj *);
extern void		add_checkpoint(nis_name);
extern int		checkpoint_db();
extern nis_name		__table_name(nis_name);
extern char		*internal_table_name(nis_name, char *);
extern int		nis_db_sync_log(void);
extern nis_error	db_configure(char *);
extern int		loadLDAPdata(void);

/* in nis_subr_proc.c */
extern int		nis_strcasecmp(char *, char *);
extern int		nis_isserving(nis_object *);
extern nis_error	__directory_object(nis_name, struct ticks *, int,
								nis_object **);
extern nis_error	__directory_object_msg(nis_name, struct ticks *, int,
							nis_object **, int);
extern void		nis_getprincipal(char *, struct svc_req	*);
extern nis_error	get_object_safely(nis_name, u_long, nis_object **);
extern nis_result	*svc_lookup(nis_name, u_long);
extern int		__can_do(u_long, u_long, nis_object *, nis_name);
extern u_char		*__get_xdr_buf(int);
extern char		*__get_string_buf(int);
extern entry_col	*__get_entry_col(int);
extern table_col	*__get_table_col(int);
extern nis_attr		*__get_attrs(int);
extern int		nis_isstable(log_entry *, int);
extern void		flush_tablecache(nis_name);
extern u_long		nis_cptime(nis_server *, nis_name);
extern u_long		nis_cptime_msg(nis_server *, nis_name, bool_t, bool_t);
extern void		make_stamp(nis_name, u_long);
extern int		replica_update(ping_item *);
extern int		ping_replicas(ping_item *);
extern void		add_pingitem(nis_object *, u_long, NIS_HASH_TABLE *);
extern void		do_cleanup(cleanup *);
extern void		add_cleanup(void (*)(), void *, char *);
extern void		do_xdr_cleanup(xdr_clean_data *);
extern void		add_xdr_cleanup(bool_t (*)(), char *, char *);
extern nis_result	*__nis_local_lookup(ib_request *, u_long, int, void *,
						int (*)());

/* in nis_ib_proc.c */
extern nis_object	*nis_censor_object_attr(nis_object *, table_col *,
						nis_name, u_int, nis_attr *);
extern nis_object	*nis_censor_object(nis_object *, table_col *, nis_name);
extern endpoint		*__nis_alt_callback_server(endpoint *, u_int,
					struct netbuf *, char **, int);

/* in nis_log_svc.c */
extern u_long		last_update(nis_name);
extern int		apply_transaction(log_entry *);
extern int		checkpoint_log(void);
extern u_long		add_update(log_entry *);
extern u_long		add_update_nosync(log_entry *, void **);
extern int		abort_transaction(int);
extern void 		entries_since(nis_object *, u_long, log_result *);

/* in nis_log_common.c */
extern int		begin_transaction(nis_name);
extern int		end_transaction_x(int, int);
extern int		end_transaction(int);
extern int		lockTransLog(char *, int, int);
extern void		unlockTransLog(char *, int);
extern int		map_log(char *, int);
extern void		sync_log();

/* nis_opacc.c */
extern bool_t		nis_op_access(char *, char *, nis_name, char *,
					struct svc_req *);
extern void		nis_delete_callback_id(pthread_t);
extern pthread_t	nis_get_callback_id(anonid_t, nis_name, int);
extern anonid_t		nis_add_callback_id(pthread_t, nis_name);

#else

/* in nis_db.c */
extern void		__make_legal();
extern nis_db_result 	*db_add();
extern nis_error 	__db_add();
extern nis_db_result 	*db_remove();
extern nis_error 	__db_remove();
extern nis_db_result 	*db_lookup();
extern nis_db_result 	*db_lookup_deferred();
extern nis_db_list_result *db_list();
extern nis_db_list_result *db_list_flags();
extern void		free_db_list();
extern nis_db_result 	*db_addib();
extern nis_error 	*__db_addib();
extern nis_error 	*__db_addib_nolog();
extern nis_error 	*__db_addib_nosync();
extern nis_db_result 	*db_remib();
extern nis_error 	__db_remib();
extern nis_error 	__db_remib_nosync();
extern nis_fn_result 	*db_firstib();
extern nis_fn_result 	*db_nextib();
extern nis_error	db_find_table();
extern nis_error	db_create();
extern nis_error	db_destroy();
extern void		db_flush();
extern void		add_checkpoint();
extern int		checkpoint_db();
extern nis_name		__table_name();
extern int		nis_db_sync_log();
extern nis_error	db_configure();
extern int		loadLDAPdata();

/* in nis_subr_proc.c */
extern int		nis_strcasecmp();
extern int		nis_isserving();
extern nis_error	__directory_object();
extern nis_error	__directory_object_msg();
extern void		nis_getprincipal();
extern nis_error	get_object_safely();
extern nis_result	*svc_lookup();
extern int		__can_do();
extern u_char		*__get_xdr_buf();
extern char		*__get_string_buf();
extern entry_col	*__get_entry_col();
extern table_col	*__get_table_col();
extern nis_attr		*__get_attrs();
extern int		nis_isstable();
extern void		flush_tablecache();
extern u_long		nis_cptime();
extern void		make_stamp();
extern void		replica_update();
extern void		add_pingitem();
extern void		do_cleanup();
extern void		add_cleanup();
extern void		do_xdr_cleanup();
extern void		add_xdr_cleanup();
extern nis_result	*__nis_local_lookup();

/* in nis_ib_proc.c */
extern nis_object	*nis_censor_object_attr();
extern nis_object	*nis_censor_object();
extern endpoint		*__nis_alt_callback_server();


/* in nis_log_svc.c */
extern u_long		last_update();
extern int		apply_transaction();
extern int		checkpoint_log();
extern u_long		add_update();
extern u_long		add_update_nosync();
extern int		abort_transaction();
extern void		entries_since();

/* in nis_log_common.c */
extern int		begin_transaction();
extern int		end_transaction_x();
extern int		end_transaction();
extern int		lockTransLog();
extern void		unlockTransLog();
extern int		map_log();
extern void		sync_log();
extern int		__log_resync();
extern char		*__make_name();

/* nis_opacc.c */
extern bool_t		nis_op_access();
extern void		nis_delete_callback_id();
extern pid_t		nis_get_callback_id();
extern anonid_t		nis_add_callback_id();
#endif

/*
 * Declarations for global state used by the service.
 */
extern int root_server;		/* set by the -r switch 	*/
extern int verbose;		/* set by the -v switch 	*/
extern int static_root;		/* set by network partition 	*/
extern int secure_level;	/* set by the -S switch 	*/
extern NIS_HASH_TABLE upd_list;	/* added during a ping.	*/
extern NIS_HASH_TABLE ping_list; /* added during an update.	*/
extern NIS_HASH_TABLE checkpoint_list; /* added for a checkpoint. */
extern int checkpoint_all;
extern NIS_HASH_TABLE *table_cache; /* cache of table objects   */
extern int ping_pid, upd_pid;	/* Processes doing the work	*/

/*
 * MACRO definitions for the various source modules.
 */
#define	STATUS(r) r.status
#define	OBJECT(r) r.objects.objects_val
#define	NUMOBJ(r) r.objects.objects_len
#define	CBDATA(r) r.cookie
#define	COOKIE(r) r.cookie
#define	same_oid(o1, o2)	(((o1)->zo_oid.mtime == (o2)->zo_oid.mtime) &&\
				((o1)->zo_oid.ctime == (o2)->zo_oid.ctime))

#define	ROOT_OBJ	"root.object"
#define	PARENT_OBJ	"parent.object"

#define	ENVAL ec_value.ec_value_val
#define	ENLEN ec_value.ec_value_len
#define	ZAVAL zattr_val.zattr_val_val
#define	ZALEN zattr_val.zattr_val_len

#define	FN_NOMANGLE	0	/* don't mangle objects on first/next calls */
#define	FN_MANGLE	1	/* mangle objects on first/next calls */
#define	FN_NORAGS	2	/* don't put malloc data on the rag list    */
#define	FN_NOERROR	4	/* don't generate error on missing table    */

#define	ADD_OP		1
#define	REM_OP		2
#define	MOD_OP		3
#define	FIRST_OP 	4
#define	NEXT_OP 	5

#define	GETSERVER(o, n) (((o)->DI_data.do_servers.do_servers_val) + n)
#define	MAXSERVER(o)    (o)->DI_data.do_servers.do_servers_len
#define	MASTER(o) 	GETSERVER(o, 0)

#define	CHILDPROC	(getpid() != master_pid)

#define	DIR_IDLE_TIME	120

#define	NOANONID	(anonid_t)-1

/* Global variables defined in nis_log_common.c */
extern pid_t	master_pid;

/* Global variables defined in nis_main.c */
extern cleanup	*looseends;	  /* Data that needs to be freed	*/
extern cleanup	*free_rags;	  /* free cleanup structs that are available  */
extern int	children;	  /* Server load control		*/
extern int	max_children;	  /* Max number of forked children	*/
extern int	readonly;	  /* When true the service is read only	*/
extern int	need_checkpoint;  /* When true the log should be checkpointed */
extern int	force_checkpoint; /* When true the log WILL be checkpointed   */
extern int	auth_verbose; /* verbose authorization messages */
extern table_obj tbl_prototype; /* directory "table" format */

/*
 * A set of defines for tracking memory problems. A simple memory allocator
 * and checker is part of nis_malloc.c and when DEBUG is defined and this
 * file is linked in, we generate messages on allocs/frees and check for
 * freeing free memory, etc.
 */
#ifdef MEM_DEBUG
#define	XFREE		xfree
#define	XMALLOC 	xmalloc
#define	XCALLOC 	xcalloc
#define	XSTRDUP 	xstrdup
#ifdef __STDC__
extern void xfree(void *);
extern char *xstrdup(char *);
extern char *xmalloc(int);
extern char *xcalloc(int, int);
#else
extern void xfree();
extern char *xstrdup();
extern char *xmalloc();
extern char *xcalloc();
#endif /* __STDC__ */
#else
#define	XFREE 		free
#define	XMALLOC		malloc
#define	XCALLOC		calloc
#define	XSTRDUP		strdup
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NIS_PROC_H */
