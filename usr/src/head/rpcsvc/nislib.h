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
 * Copyright 1991-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * nislib.h
 *
 * This file contains the interfaces that are visible in the SunOS 5.x
 * implementation of NIS Plus. When using C++ the defined __cplusplus and
 * __STDC__ should both be true.
 */

#ifndef	_RPCSVC_NISLIB_H
#define	_RPCSVC_NISLIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __STDC__
extern void nis_freeresult(nis_result *);
extern nis_result *nis_lookup(nis_name, uint_t);
extern nis_result *nis_list(nis_name, uint_t,
	int (*)(nis_name, nis_object *, void *), void *);
extern nis_result *nis_add(nis_name, nis_object *);
extern nis_result *nis_remove(nis_name, nis_object *);
extern nis_result *nis_modify(nis_name, nis_object *);

extern nis_result *nis_add_entry(nis_name, nis_object *, uint_t);
extern nis_result *nis_remove_entry(nis_name, nis_object *, uint_t);
extern nis_result *nis_modify_entry(nis_name, nis_object *, uint_t);
extern nis_result *nis_first_entry(nis_name);
extern nis_result *nis_next_entry(nis_name, netobj *);

extern nis_error nis_mkdir(nis_name, nis_server *);
extern nis_error nis_rmdir(nis_name, nis_server *);
extern name_pos nis_dir_cmp(nis_name, nis_name);

extern nis_name *nis_getnames(nis_name);
extern void nis_freenames(nis_name *);
extern nis_name nis_domain_of(nis_name);
extern nis_name nis_leaf_of(nis_name);
extern nis_name nis_leaf_of_r(const nis_name, char *, size_t);
extern nis_name nis_name_of(nis_name);
extern nis_name nis_local_group(void);
extern nis_name nis_local_directory(void);
extern nis_name nis_local_principal(void);
extern nis_name nis_local_host(void);

extern void nis_destroy_object(nis_object *);
extern nis_object *nis_clone_object(nis_object *, nis_object *);
extern void nis_print_object(nis_object *o);

extern char *nis_sperrno(nis_error);
extern void nis_perror(nis_error, char *);
extern char *nis_sperror(nis_error, char *);
extern char *nis_sperror_r(nis_error, char *, char *, int len);
extern void nis_lerror(nis_error, char *);

extern void nis_print_group_entry(nis_name);
extern bool_t nis_ismember(nis_name, nis_name);
extern nis_error nis_creategroup(nis_name, uint_t);
extern nis_error nis_destroygroup(nis_name);
extern nis_error nis_addmember(nis_name, nis_name);
extern nis_error nis_removemember(nis_name, nis_name);
extern nis_error nis_verifygroup(nis_name);

extern void nis_freeservlist(nis_server **);
extern nis_server **nis_getservlist(nis_name);
extern nis_error nis_stats(nis_server *, nis_tag *, int, nis_tag **);
extern nis_error nis_servstate(nis_server *, nis_tag *, int, nis_tag **);
extern void nis_freetags(nis_tag *, int);

extern nis_result *nis_checkpoint(nis_name);
extern void nis_ping(nis_name, uint32_t, nis_object *);

/*
 * XXX: PLEASE NOTE THAT THE FOLLOWING FUNCTIONS ARE INTERNAL
 * TO NIS+ AND SHOULD NOT BE USED BY ANY APPLICATION PROGRAM.
 * THEIR SEMANTICS AND/OR SIGNATURE CAN CHANGE WITHOUT NOTICE.
 * SO, PLEASE DO NOT USE THEM.  YOU ARE WARNED!!!!
 */

extern char **__break_name(nis_name, int *);
extern int __name_distance(char **, char **);
extern nis_result *nis_make_error(nis_error, uint32_t, uint32_t, uint32_t,
    uint32_t);
extern nis_attr *__cvt2attr(int *, char **);
extern void nis_free_request(ib_request *);
extern nis_error nis_get_request(nis_name, nis_object *, netobj*, ib_request*);
extern nis_object *nis_read_obj(char *);
extern int nis_write_obj(char *, nis_object *);
extern int nis_in_table(nis_name, NIS_HASH_TABLE *, int *);
extern int nis_insert_item(NIS_HASH_ITEM *, NIS_HASH_TABLE *);
extern NIS_HASH_ITEM *nis_find_item(nis_name, NIS_HASH_TABLE *);
extern NIS_HASH_ITEM *nis_remove_item(nis_name, NIS_HASH_TABLE *);
extern void nis_insert_name(nis_name, NIS_HASH_TABLE *);
extern void nis_remove_name(nis_name, NIS_HASH_TABLE *);
extern CLIENT *nis_make_rpchandle(nis_server *, int, rpcprog_t, rpcvers_t,
    uint_t, int, int);
extern void *nis_get_static_storage(struct nis_sdata *, uint_t, uint_t);
extern char *nis_data(char *);
extern char *nis_old_data(char *);
extern void nis_print_rights(uint_t);
extern void nis_print_directory(directory_obj *);
extern void nis_print_group(group_obj *);
extern void nis_print_table(table_obj *);
extern void nis_print_link(link_obj *);
extern void nis_print_entry(entry_obj *);
extern nis_server *__nis_init_callback(CLIENT *,
    int (*)(nis_name, nis_object *, void *), void *);
extern int __nis_run_callback(netobj *, rpcproc_t, struct timeval *, CLIENT *);

extern log_result *nis_dumplog(nis_server *, nis_name, uint32_t);
extern log_result *nis_dump(nis_server *, nis_name,
    int (*)(nis_name, nis_object *, void *));
extern nis_name __nis_rpc_domain(void);

extern bool_t __do_ismember(nis_name, nis_object *,
    nis_result *(*)(nis_name, uint_t));
extern nis_name __nis_map_group(nis_name);
extern nis_name __nis_map_group_r(const nis_name, char *, size_t);

void __nis_CacheStart(void);
nis_error __nis_CacheBind(char *dname, directory_obj *dobj);
bool_t __nis_CacheRemoveEntry(directory_obj *dobj);
nis_error __nis_CacheSearch(char *dname, directory_obj *dobj);
void __nis_CacheRestart(void);
void __nis_CachePrint(void);
void __nis_CachePrintDir(char *);
bool_t __nis_CacheAddEntry(fd_result *, directory_obj *);
void __nis_CacheRefreshEntry(char *);
nis_error __nis_CacheBindDir(char *dname,
		nis_bound_directory **binding, int flags);
nis_error __nis_CacheBindMaster(char *dname, nis_bound_directory **binding);
nis_error __nis_CacheBindServer(nis_server *srv, int nsrv,
		nis_bound_directory **binding);
int __nis_CacheRefreshBinding(nis_bound_directory *binding);
int __nis_CacheRefreshAddress(nis_bound_endpoint *bep);
int __nis_CacheRefreshCallback(nis_bound_endpoint *bep);
nis_error __nis_CacheLocalInit(uint32_t *exp_time);
uint32_t __nis_CacheLocalLoadPref(void);
nis_error __nis_CacheMgrInit(void);
void __nis_CacheMgrCleanup(void);
void __nis_CacheMgrReadColdstart(void);
nis_error __nis_CacheMgrBindReplica(char *dname);
nis_error __nis_CacheMgrBindMaster(char *dname);
nis_error __nis_CacheMgrBindServer(nis_server *srv, int nsrv);
int __nis_CacheMgrRefreshBinding(nis_bound_directory *binding);
int __nis_CacheMgrRefreshAddress(nis_bound_endpoint *bep);
int __nis_CacheMgrRefreshCallback(nis_bound_endpoint *bep);
int __nis_CacheMgrUpdateUaddr(char *uaddr);
void __nis_CacheMgrMarkUp(void);
uint32_t __nis_CacheMgrTimers(void);
uint32_t __nis_CacheMgrRefreshCache(void);
uint32_t __nis_serverRefreshCache(void);

extern CLIENT *__get_ti_clnt(char *, CLIENT *, char **, pid_t *, dev_t *);
extern int __strcmp_case_insens(char *, char *);
extern int __strncmp_case_insens(char *, char *);

extern fd_result *nis_finddirectory(directory_obj *, nis_name);
extern int __start_clock(int);
extern uint32_t __stop_clock(int);

fd_result *__nis_finddirectory(nis_bound_directory **, char *dname);
int __dir_prefix(char **, char **);
void __free_break_name(char **, int);
void __broken_name_print(char **, int);
void __free_fdresult(fd_result *res);
nis_error __nis_ping_servers(nis_bound_directory *, int, int);
struct netconfig *__nis_get_netconfig(endpoint *ep);
int __dir_same(char **, char **);
void nis_free_binding(nis_bound_directory *);
char *__nis_xdr_dup(xdrproc_t, char *, char *);

CLIENT *__nis_clnt_create(int, struct netconfig *, char *, struct netbuf *,
			int, int, int, int, int);

#else

/* Non-prototype definitions (old fashioned C) */

extern void nis_freeresult();
extern nis_result *nis_lookup();
extern nis_result *nis_list();
extern nis_result *nis_add();
extern nis_result *nis_remove();
extern nis_result *nis_modify();

extern nis_result *nis_add_entry();
extern nis_result *nis_remove_entry();
extern nis_result *nis_modify_entry();
extern nis_result *nis_first_entry();
extern nis_result *nis_next_entry();

extern nis_error nis_mkdir();
extern nis_error nis_rmdir();
extern name_pos nis_dir_cmp();

extern nis_name *nis_getnames();
extern void nis_freenames();
extern nis_name nis_domain_of();
extern nis_name nis_leaf_of();
extern nis_name nis_leaf_of_r();
extern nis_name nis_name_of();
extern nis_name nis_local_group();
extern nis_name nis_local_directory();
extern nis_name nis_local_principal();
extern nis_name nis_local_host();

extern void nis_destroy_object();
extern nis_object *nis_clone_object();
extern void nis_print_object();

extern char *nis_sperrno();
extern void nis_perror();
extern char *nis_sperror();
extern char *nis_sperror_r();
extern void nis_lerror();

extern void nis_print_group_entry();
extern bool_t nis_ismember();
extern nis_error nis_creategroup();
extern nis_error nis_destroygroup();
extern nis_error nis_addmember();
extern nis_error nis_removemember();
extern nis_error nis_verifygroup();

extern void nis_freeservlist();
extern nis_server **nis_getservlist();
extern nis_error nis_stats();
extern nis_error nis_servstate();
extern void nis_freetags();

extern nis_result *nis_checkpoint();
extern void nis_ping();

/*
 * XXX: PLEASE NOTE THAT THE FOLLOWING FUNCTIONS ARE INTERNAL
 * TO NIS+ AND SHOULD NOT BE USED BY ANY APPLICATION PROGRAM.
 * THEIR SEMANTICS AND/OR SIGNATURE CAN CHANGE WITHOUT NOTICE.
 * SO, PLEASE DO NOT USE THEM.  YOU ARE WARNED!!!!
 */
extern char **__break_name();
extern int __name_distance();
extern nis_result *nis_make_error();
extern nis_attr *__cvt2attr();
extern void nis_free_request();
extern nis_error nis_get_request();
extern nis_object *nis_read_obj();
extern int nis_write_obj();
extern int nis_in_table();
extern int nis_insert_item();
extern NIS_HASH_ITEM *nis_find_item();
extern NIS_HASH_ITEM *nis_remove_item();
extern void nis_insert_name();
extern void nis_remove_name();
extern CLIENT *nis_make_rpchandle();
extern void *nis_get_static_storage();
extern char *nis_data();
extern char *nis_old_data();

extern void nis_print_rights();
extern void nis_print_directory();
extern void nis_print_group();
extern void nis_print_table();
extern void nis_print_link();
extern void nis_print_entry();

extern nis_server *__nis_init_callback();
extern int __nis_run_callback();

extern log_result *nis_dump();
extern log_result *nis_dumplog();
extern nis_name __nis_rpc_domain();

extern bool_t __do_ismember();
extern nis_name __nis_map_group();
extern nis_name __nis_map_group_r();

void __nis_CacheStart();
nis_error __nis_CacheBind();
bool_t __nis_CacheRemoveEntry();
nis_error __nis_CacheSearch();
void __nis_CacheRestart();
void __nis_CachePrint();
void __nis_CachePrintDir();
bool_t __nis_CacheAddEntry();
void __nis_CacheRefreshEntry();
nis_error __nis_CacheBindDir();
nis_error __nis_CacheBindMaster();
nis_error __nis_CacheBindServer();
int __nis_CacheRefreshBinding();
int __nis_CacheRefreshAddress();
int __nis_CacheRefreshCallback();
nis_error __nis_CacheLocalInit();
uint32_t __nis_CacheLocalLoadPref();
nis_error __nis_CacheMgrInit();
void __nis_CacheMgrCleanup();
void __nis_CacheMgrReadColdstart();
nis_error __nis_CacheMgrBindReplica();
nis_error __nis_CacheMgrBindMaster();
nis_error __nis_CacheMgrBindServer();
int __nis_CacheMgrRefreshBinding();
int __nis_CacheMgrRefreshAddress();
int __nis_CacheMgrRefreshCallback();
int __nis_CacheMgrUpdateUaddr();
void __nis_CacheMgrMarkUp();
uint32_t __nis_CacheMgrTimers();
uint32_t __nis_CacheMgrRefreshCache();
uint32_t __nis_serverRefreshCache();

extern CLIENT *__get_ti_clnt();
extern int __strcmp_case_insens();
extern int __strncmp_case_insens();

extern fd_result *nis_finddirectory();
extern int __start_clock();
extern uint32_t __stop_clock();

fd_result *__nis_finddirectory();
int __dir_prefix();
void __free_break_name();
void __broken_name_print();
void __free_fdresult();
nis_error __nis_ping_servers();
struct netconfig *__nis_get_netconfig();
int __dir_same();
void nis_free_binding();
char *__nis_xdr_dup();

CLIENT *__nis_clnt_create();

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _RPCSVC_NISLIB_H */
