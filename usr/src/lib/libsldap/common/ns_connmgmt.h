/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_NS_CONNMGMT_H
#define	_NS_CONNMGMT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <thread.h>
#include "ns_sldap.h"
#include "ns_internal.h"
#include "ns_cache_door.h"

struct ns_conn_user; /* connection user, forward definition */
struct ns_conn_mt;   /* multi-threaded (MT) connection, forward definition */
struct ns_conn_mgmt; /* connection management, forward definition */

#define	NS_CONN_MT_USER_NO_MAX	-1
#define	NS_CONN_MT_USER_MAX	NS_CONN_MT_USER_NO_MAX
#define	NS_LIST_TRY_MAX		3

/*
 * Structure for handling the waiter of a pending multi-threaded (MT) connection
 */
typedef struct ns_conn_waiter {
	cond_t			waitcv;
	uint8_t			signaled;
	struct ns_conn_user	*key;
	struct ns_conn_waiter	*next, *prev;
} ns_conn_waiter_t;

/*
 * type of a connection user
 */
typedef enum {
	NS_CONN_USER_SEARCH	= 1,
	NS_CONN_USER_WRITE	= 2,
	NS_CONN_USER_AUTH	= 3,
	NS_CONN_USER_GETENT	= 4
} ns_conn_user_type_t;

/*
 * state of a connection user
 */
typedef enum {
	NS_CONN_USER_UNINITED		= 0,
	NS_CONN_USER_ALLOCATED		= 1,
	NS_CONN_USER_FINDING		= 2, /* looking for an MT connection */
	NS_CONN_USER_WAITING		= 3, /* waiting for an MT connection */
	NS_CONN_USER_WOKEUP		= 4,
	NS_CONN_USER_CONNECT_ERROR	= 5,
	NS_CONN_USER_CONNECTED  	= 6,
	NS_CONN_USER_DISCONNECTED	= 7,
	NS_CONN_USER_FREED		= 8
} ns_conn_user_state_t;

/*
 * A connection user represents a request processed by libsldap. It
 * usually is a thread using the same connection from start to end.
 * Different connection users of the same type can share the same
 * connection opened for that type. But search and getent users can
 * share the same connection opened for either search or getent. AUTH
 * connection are not shareable.
 *
 * A getent user may have a longer lifespan and live outside of libsldap.
 * This is because the associated search cookie is passed back to the caller
 * via the firstEntry call and used in the subsequent nextEntry or endEntry
 * calls. Even though the firstEntry and the nextEntry/endEntry calls may
 * be running in a different thread, the connection being used will be the
 * same. It is the one assigend during the firstEntry call.
 */
struct ns_conn_user {
	ns_conn_user_type_t	type; /* search, write, auth, getent, ... */
	ns_conn_user_state_t	state;
	thread_t		tid;   /* id of the thread starts the request */
	struct ns_conn_user	*next; /* next conn_user in the linked list */
	struct ns_conn_mt	*conn_mt; /* the MT connection being used */
	struct ns_conn_mgmt	*conn_mgmt; /* ref counted conn management */
	void			*userinfo; /* private data of the request */
	ns_ldap_return_code	ns_rc; /* error return code */
	ns_ldap_error_t		*ns_error; /* error info */
	boolean_t		referral; /* using a referred server ? */
	boolean_t		retry; /* retry the request on certain error? */
	boolean_t		keep_conn; /* keep the conn for reuse ? */
	boolean_t		use_mt_conn; /* using/used an MT connection ? */
	boolean_t		bad_mt_conn; /* MT connection is not usable ? */
};

/*
 * state of an MT connection
 */
typedef enum {
	NS_CONN_MT_UNINITED		= 0,
	NS_CONN_MT_CONNECTING		= 1,
	NS_CONN_MT_CONNECT_ERROR	= 2,
	NS_CONN_MT_CONNECTED		= 3,
	NS_CONN_MT_CLOSING		= 4
} ns_conn_mt_state_t;

/*
 * An ns_conn_mt (or MT connection) represents an ldap connection
 * that can be shared among multiple threads. It also represents
 * the set of connection users using the ldap connection. It contains
 * a pointer to the Connection structure that has the physical info
 * of the connection (server name, address, ldap handle, etc). It
 * also contains a linked list of all the conn_user using the ldap
 * connection. The connection users can wait on an MT connection
 * to become available or be told to abort and clean up when one of
 * the connection user detects an error and knows that the connection
 * is no longer usable. The error info is then saved in the structure
 * for other users to consume.
 *
 * An MT connection is meant to be shared concurrently and persistent.
 * Even when there's no current user, it will be kept by the connection
 * management, waiting for the next user. It will be closed when
 * a connection error is detected, when a better server should be
 * used, when the Native LDAP configuration change, or when the libsldap
 * is being unloaded.
 */
typedef struct ns_conn_mt {
	mutex_t			lock;
	ns_conn_mt_state_t	state;
	pid_t			pid; /* process creates the connection */
	thread_t		tid; /* thread creates the connection */
	struct ns_conn_mt	*next; /* next conn_mt in the linked list */
	ns_conn_user_t		*cu_head; /* head of conn_user linked list */
	ns_conn_user_t		*cu_tail; /* tail of conn_user linked list */
	struct ns_conn_mgmt	*conn_mgmt; /* ref counted conn management */
	ns_conn_waiter_t	waiter; /* first of the connection waiters */
	uint_t			cu_cnt; /* number of the using conn_user */
	int32_t			cu_max; /* max. allowed number of conn_user */
	uint_t			waiter_cnt; /* number of waiters */
	ns_conn_user_type_t	opened_for; /* type of conn_user opened for */
	Connection		*conn; /* name, IP address, ldap handle, etc */
	time_t			create_time; /* time when connection created */
	time_t			access_time; /* time when last used */
	ns_ldap_return_code	ns_rc; /* saved error code */
	ns_ldap_error_t		*ns_error; /* saved error info */
	boolean_t		close_when_nouser;  /* close connection when */
						    /* last user is done ? */
	boolean_t		detached; /* no longer in connection pool? */
	boolean_t		referral; /* using a referred server ? */
} ns_conn_mt_t;

/*
 * state of a connection management
 * (a connection pool sharing the same native LDAP configuration)
 */
typedef enum {
	NS_CONN_MGMT_UNINITED	= 0,
	NS_CONN_MGMT_INACTIVE	= 1, /* conn sharing not yet requested */
	NS_CONN_MGMT_ACTIVE	= 2, /* connection sharing required/requested */
	NS_CONN_MGMT_DETACHED	= 3  /* on the way down, no new user allowed */
} ns_conn_mgmt_state_t;

/*
 * An ns_conn_mgmt (or connection management) represents the set of MT
 * connections using the same native LDAP configuration. It is a connection
 * pool that can adjust the MT connection status and usage based on the
 * change notifications it receives from the ldap_cachemgr daemon, OR When
 * the change is detected at config refresh time. When a server status
 * change (up or down) notification is received or detected, it will
 * close the MT connections using the server. Or mark them as to-be-closed
 * and close them when all users are done using them. When a config change
 * notice is received, it will detach itself and allow a new ns_conn_mgmt be
 * created for the new configuration. The old config would still be used
 * by the detached ns_conn_mgmt. Both will be destroyed when all existing
 * conn_user are done. Any conn_user and MT connection created after the
 * configuration switch will use the new configuration.
 *
 * Note that there's always just one current ns_conn_mgmt. Its usage is
 * reference counted. Any new conn_user or MT connection referencing
 * the ns_conn_mgmt adds 1 to the count, any release of the ns_conn_mgmt
 * decrement the count by 1. The ns_conn_mgmt can not be freed until
 * the reference count becomes zero.
 *
 * Each ns_conn_mgmt references a native LDAP configuration. The config
 * component of this library always maintains a global configuration. It is
 * referred to as the current global config. The current ns_conn_mgmt
 * uses that global config. When an ns_conn_mgmt is detached, or not
 * longer active/current, the config it uses is no longer the current global
 * one, which is referred as the per connection management config. When
 * the ns_conn_mgmt is freed, the config will also be destroyed.
 */

typedef struct ns_conn_mgmt {
	mutex_t		lock;
	ns_conn_mgmt_state_t state;
	pid_t		pid; /* process creates the conn_mgmt */
	thread_t	procchg_tid; /* id of the change monitor thread */
	ns_conn_mt_t	*cm_head; /* head of the conn_mt linked list */
	ns_conn_mt_t	*cm_tail; /* tail of the conn_mt linked list */
	mutex_t		cfg_lock; /* lock serializes access to config */
	ldap_get_chg_cookie_t cfg_cookie; /* used to detect if config changes */
	ns_config_t	*config; /* the native LDAP config being used */
	char		**pservers; /* preferred servers defined in config */
	uint_t		cm_cnt;  /* number of MT connection in the pool */
	uint_t		ref_cnt; /* number of reference by conn_MT/conn_user */
	boolean_t	is_nscd; /* running in a nscd ? */
	boolean_t	is_peruser_nscd; /* running in a per-user nscd ? */
	boolean_t	ldap_mt; /* libldap supports multi-threaded client ? */
	boolean_t	do_mt_conn;	/* need and able to do MT conn ? */
	boolean_t	shutting_down;  /* on the way down ? */
	boolean_t	cfg_reloaded;   /* config is not current ? */
	boolean_t	procchg_started; /* change monitor thread started ? */
	boolean_t	procchg_door_call; /* in door call and waiting ? */
	boolean_t	pservers_loaded; /* pservers array is set ? */
} ns_conn_mgmt_t;

/*
 * For a connection management and the conn_mt connections it manages, it is
 * very helpful to know exactly when the Native LDAP configuration changes
 * and when the status of the configured servers change. If the config
 * changes, new connection management will be created. If servers go up
 * or down, conn_mt connections being used need to be dropped or switched.
 * For processes other than the main nscd, the changes has to be detected
 * in a less efficient way by libsldap. For the main nscd (not including
 * peruser nscd), the connection management which has active conn_mt
 * connections can rely on the ldap_cachemgr daemon to report if there's any
 * change in servers' status or if the native LDAP configuration has changed.
 *
 * The mechanism for reporting of the changes is a door call sent from
 * libsldap to ldap_cachemgr. The call will not be returned until changes
 * detected by ldap_cachemgr. When the change info is passed back to
 * libsldap, the change monitor thread will wake up from the door call
 * and process the notification. For servers went from up to down, the
 * associated MT connections will be closed, and then all conn_users'
 * state will be marked as closing. When a conn_user notices it, the
 * operations represented by that conn_user will be ended with error
 * info. When a more preferred server is up, MT connections using
 * less preferred servers will be marked as closed-when-all-user-done,
 * so that new connection will be opened and using the preferred server.
 * A configuration change causes the current connection management and
 * the configuration it uses to become detached but continually being
 * used by the old MT connections. Any new MT connection opened will
 * be put in a new connection management and uses the new configuration
 * immediately.
 */
typedef enum {
	NS_SERVER_UP	= 1,
	NS_SERVER_DOWN	= 2
} ns_server_status_t;

typedef struct ns_server_status_change {
	int			num_server;
	boolean_t		config_changed;
	ns_server_status_t	*changes;	/* array of status change */
	char			**servers;	/* array of server */
} ns_server_status_change_t;

/*
 * connection management functions
 */
ns_conn_mgmt_t *__s_api_conn_mgmt_init();
int __s_api_setup_mt_ld(LDAP *ld);
int __s_api_check_mtckey();
void __s_api_use_prev_conn_mgmt(int, ns_config_t *);
ns_conn_user_t *__s_api_conn_user_init(int, void *, boolean_t);
void __s_api_conn_mt_return(ns_conn_user_t *);
void __s_api_conn_user_free(ns_conn_user_t *);
int __s_api_conn_mt_add(Connection *con, ns_conn_user_t *, ns_ldap_error_t **);
int __s_api_conn_mt_get(const char *, const int, const ns_cred_t *,
	Connection **, ns_ldap_error_t **, ns_conn_user_t *);
void __s_api_conn_mt_remove(ns_conn_user_t *, int, ns_ldap_error_t **);
int __s_api_check_libldap_MT_conn_support(ns_conn_user_t *, LDAP *ld,
	ns_ldap_error_t **);
void __s_api_conn_mt_close(ns_conn_user_t *, int, ns_ldap_error_t **);
void __s_api_reinit_conn_mgmt_new_config(ns_config_t *);
int __s_api_setup_retry_search(ns_conn_user_t **, ns_conn_user_type_t, int *,
	int *, ns_ldap_error_t **);
int __s_api_setup_getnext(ns_conn_user_t *, int *, ns_ldap_error_t **);
void __s_api_shutdown_conn_mgmt();

#ifdef __cplusplus
}
#endif

#endif /* _NS_CONNMGMT_H */
