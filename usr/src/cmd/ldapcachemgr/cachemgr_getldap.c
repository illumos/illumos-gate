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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <memory.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/door.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <synch.h>
#include <pthread.h>
#include <unistd.h>
#include <lber.h>
#include <ldap.h>
#include <ctype.h>	/* tolower */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ucred.h>
#include "cachemgr.h"
#include "solaris-priv.h"
#include "ns_connmgmt.h"

static rwlock_t	ldap_lock = DEFAULTRWLOCK;
static int	sighup_update = FALSE;
extern admin_t	current_admin;

extern int is_root_or_all_privs(char *dc_str, ucred_t **ucp);

/* variables used for SIGHUP wakeup on sleep */
static mutex_t			sighuplock;
static cond_t			cond;

/* refresh time statistics */
static time_t	prev_refresh_time = 0;

/* variables used for signaling parent process */
static mutex_t	sig_mutex;
static int	signal_done = FALSE;

/* TCP connection timeout (in milliseconds) */
static int tcptimeout = NS_DEFAULT_BIND_TIMEOUT * 1000;

#ifdef SLP
extern int	use_slp;
#endif /* SLP */

/* nis domain information */
#define	_NIS_FILTER		"objectclass=nisDomainObject"
#define	_NIS_DOMAIN		"nisdomain"

#define	CACHESLEEPTIME		600
/*
 * server list refresh delay when in "no server" mode
 * (1 second)
 */
#define	REFRESH_DELAY_WHEN_NO_SERVER	1

typedef enum {
	INFO_OP_CREATE		= 0,
	INFO_OP_DELETE		= 1,
	INFO_OP_REFRESH		= 2,
	INFO_OP_REFRESH_WAIT	= 3,
	INFO_OP_GETSERVER	= 4,
	INFO_OP_GETSTAT		= 5,
	INFO_OP_REMOVESERVER	= 6
} info_op_t;

typedef enum {
	INFO_RW_UNKNOWN		= 0,
	INFO_RW_READONLY	= 1,
	INFO_RW_WRITEABLE	= 2
} info_rw_t;

typedef enum {
	INFO_SERVER_JUST_INITED	= -1,
	INFO_SERVER_UNKNOWN	= 0,
	INFO_SERVER_CONNECTING	= 1,
	INFO_SERVER_UP		= 2,
	INFO_SERVER_ERROR 	= 3,
	INFO_SERVER_REMOVED	= 4
} info_server_t;

typedef enum {
	INFO_STATUS_UNKNOWN	= 0,
	INFO_STATUS_ERROR 	= 1,
	INFO_STATUS_NEW   	= 2,
	INFO_STATUS_OLD		= 3
} info_status_t;

typedef enum {
	CACHE_OP_CREATE		= 0,
	CACHE_OP_DELETE		= 1,
	CACHE_OP_FIND		= 2,
	CACHE_OP_ADD		= 3,
	CACHE_OP_GETSTAT	= 4
} cache_op_t;

typedef enum {
	CACHE_MAP_UNKNOWN	= 0,
	CACHE_MAP_DN2DOMAIN	= 1
} cache_type_t;

typedef struct server_info_ext {
	char			*addr;
	char			*hostname;
	char			*rootDSE_data;
	char			*errormsg;
	info_rw_t		type;
	info_server_t		server_status;
	info_server_t		prev_server_status;
	info_status_t 		info_status;
	ns_server_status_t	change;
} server_info_ext_t;

typedef struct server_info {
	struct server_info 	*next;
	mutex_t			mutex[2];	/* 0: current copy lock */
						/* 1: update copy lock */
	server_info_ext_t	sinfo[2]; /* 0: current, 1:  update copy */
} server_info_t;

typedef struct cache_hash {
	cache_type_t		type;
	char			*from;
	char			*to;
	struct cache_hash	*next;
} cache_hash_t;

/*
 * The status of a server to be removed. It can be up or down.
 */
typedef struct rm_svr {
	char	*addr;
	int	up; /* 1: up, 0: down */
} rm_svr_t;

static int getldap_destroy_serverInfo(server_info_t *head);
static void test_server_change(server_info_t *head);
static void remove_server(char *addr);
static ns_server_status_t set_server_status(char *input, server_info_t *head);
static void create_buf_and_notify(char *input, ns_server_status_t st);

/*
 * Load configuration
 * The code was in signal handler getldap_revalidate
 * It's moved out of the handler because it could cause deadlock
 * return: 1 SUCCESS
 *         0 FAIL
 */
static int
load_config() {
	ns_ldap_error_t *error;
	int		rc = 1;

	(void) __ns_ldap_setServer(TRUE);

	(void) rw_wrlock(&ldap_lock);
	if ((error = __ns_ldap_LoadConfiguration()) != NULL) {
		logit("Error: Unable to read '%s': %s\n",
			NSCONFIGFILE, error->message);
		__ns_ldap_freeError(&error);
		rc = 0; /* FAIL */
	} else
		sighup_update = TRUE;

	(void) rw_unlock(&ldap_lock);

	return (rc);
}

/*
 * Calculate a hash for a string
 * Based on elf_hash algorithm, hash is case insensitive
 * Uses tolower instead of _tolower because of I18N
 */

static unsigned long
getldap_hash(const char *str)
{
	unsigned int	hval = 0;

	while (*str) {
		unsigned int	g;

		hval = (hval << 4) + tolower(*str++);
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}
	return ((unsigned long)hval);
}

/*
 * Remove a hash table entry.
 * This function expects a lock in place when called.
 */

static cache_hash_t *
getldap_free_hash(cache_hash_t *p)
{
	cache_hash_t	*next;

	p->type = CACHE_MAP_UNKNOWN;
	if (p->from)
		free(p->from);
	if (p->to)
		free(p->to);
	next = p->next;
	p->next = NULL;
	free(p);
	return (next);
}

/*
 * Scan a hash table hit for a matching hash entry.
 * This function expects a lock in place when called.
 */
static cache_hash_t *
getldap_scan_hash(cache_type_t type, char *from,
		cache_hash_t *idx)
{
	while (idx) {
		if (idx->type == type &&
		    strcasecmp(from, idx->from) == 0) {
			return (idx);
		}
		idx = idx->next;
	}
	return ((cache_hash_t *)NULL);
}

/*
 * Format and return the cache data statistics
 */
static int
getldap_get_cacheData_stat(int max, int current, char **output)
{
#define	C_HEADER0	"Cache data information: "
#define	C_HEADER1	"  Maximum cache entries:   "
#define	C_HEADER2	"  Number of cache entries: "
	int		hdr0_len = strlen(gettext(C_HEADER0));
	int		hdr1_len = strlen(gettext(C_HEADER1));
	int		hdr2_len = strlen(gettext(C_HEADER2));
	int		len;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_get_cacheData_stat()...\n");
	}

	*output = NULL;

	len = hdr0_len + hdr1_len + hdr2_len +
	    3 * strlen(DOORLINESEP) + 21;
	*output = malloc(len);
	if (*output == NULL)
		return (-1);

	(void) snprintf(*output, len, "%s%s%s%10d%s%s%10d%s",
	    gettext(C_HEADER0), DOORLINESEP,
	    gettext(C_HEADER1), max, DOORLINESEP,
	    gettext(C_HEADER2), current, DOORLINESEP);

	return (NS_LDAP_SUCCESS);
}

static int
getldap_cache_op(cache_op_t op, cache_type_t type,
			char *from, char **to)
{
#define	CACHE_HASH_MAX		257
#define	CACHE_HASH_MAX_ENTRY	256
	static cache_hash_t	*hashTbl[CACHE_HASH_MAX];
	cache_hash_t		*next, *idx, *newp;
	unsigned long		hash;
	static rwlock_t 	cache_lock = DEFAULTRWLOCK;
	int 			i;
	static int		entry_num = 0;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_cache_op()...\n");
	}
	switch (op) {
	case CACHE_OP_CREATE:
		if (current_admin.debug_level >= DBG_ALL) {
			logit("operation is CACHE_OP_CREATE...\n");
		}
		(void) rw_wrlock(&cache_lock);

		for (i = 0; i < CACHE_HASH_MAX; i++) {
			hashTbl[i] = NULL;
		}
		entry_num = 0;

		(void) rw_unlock(&cache_lock);
		break;

	case CACHE_OP_DELETE:
		if (current_admin.debug_level >= DBG_ALL) {
			logit("operation is CACHE_OP_DELETE...\n");
		}
		(void) rw_wrlock(&cache_lock);

		for (i = 0; i < CACHE_HASH_MAX; i++) {
			next = hashTbl[i];
			while (next != NULL) {
				next = getldap_free_hash(next);
			}
			hashTbl[i] = NULL;
		}
		entry_num = 0;

		(void) rw_unlock(&cache_lock);
		break;

	case CACHE_OP_ADD:
		if (current_admin.debug_level >= DBG_ALL) {
			logit("operation is CACHE_OP_ADD...\n");
		}
		if (from == NULL || to == NULL || *to == NULL)
			return (-1);
		hash = getldap_hash(from) % CACHE_HASH_MAX;
		(void) rw_wrlock(&cache_lock);
		idx = hashTbl[hash];
		/*
		 * replace old "to" value with new one
		 * if an entry with same "from"
		 * already exists
		 */
		if (idx) {
			newp = getldap_scan_hash(type, from, idx);
			if (newp) {
				free(newp->to);
				newp->to = strdup(*to);
				(void) rw_unlock(&cache_lock);
				return (NS_LDAP_SUCCESS);
			}
		}

		if (entry_num > CACHE_HASH_MAX_ENTRY) {
			(void) rw_unlock(&cache_lock);
			return (-1);
		}

		newp = (cache_hash_t *)malloc(sizeof (cache_hash_t));
		if (newp == NULL) {
			(void) rw_unlock(&cache_lock);
			return (NS_LDAP_MEMORY);
		}
		newp->type = type;
		newp->from = strdup(from);
		newp->to = strdup(*to);
		newp->next = idx;
		hashTbl[hash] = newp;
		entry_num++;
		(void) rw_unlock(&cache_lock);
		break;

	case CACHE_OP_FIND:
		if (current_admin.debug_level >= DBG_ALL) {
			logit("operation is CACHE_OP_FIND...\n");
		}
		if (from == NULL || to == NULL)
			return (-1);
		*to = NULL;
		hash = getldap_hash(from) % CACHE_HASH_MAX;
		(void) rw_rdlock(&cache_lock);
		idx = hashTbl[hash];
		idx = getldap_scan_hash(type, from, idx);
		if (idx)
			*to = strdup(idx->to);
		(void) rw_unlock(&cache_lock);
		if (idx == NULL)
			return (-1);
		break;

	case CACHE_OP_GETSTAT:
		if (current_admin.debug_level >= DBG_ALL) {
			logit("operation is CACHE_OP_GETSTAT...\n");
		}
		if (to == NULL)
			return (-1);

		return (getldap_get_cacheData_stat(CACHE_HASH_MAX_ENTRY,
		    entry_num, to));
		break;

	default:
		logit("getldap_cache_op(): "
		    "invalid operation code (%d).\n", op);
		return (-1);
		break;
	}
	return (NS_LDAP_SUCCESS);
}
/*
 * Function: sync_current_with_update_copy
 *
 * This function syncs up the 2 sinfo copies in info.
 *
 * The 2 copies are identical most of time.
 * The update copy(sinfo[1]) could be different when
 * getldap_serverInfo_refresh thread is refreshing the server list
 * and calls getldap_get_rootDSE to update info.  getldap_get_rootDSE
 * calls sync_current_with_update_copy to sync up 2 copies before thr_exit.
 * The calling sequence is
 *  getldap_serverInfo_refresh->
 *  getldap_get_serverInfo_op(INFO_OP_CREATE,...)->
 *  getldap_set_serverInfo->
 *  getldap_get_rootDSE
 *
 * The original server_info_t has one copy of server info. When libsldap
 * makes door call GETLDAPSERVER to get the server info and getldap_get_rootDSE
 * is updating the server info, it would hit a unprotected window in
 * getldap_rootDSE. The door call  will not get server info and libsldap
 * fails at making ldap connection.
 *
 * The new server_info_t provides GETLDAPSERVER thread with a current
 * copy(sinfo[0]). getldap_get_rootDSE only works on the update copy(sinfo[1])
 * and syncs up 2 copies before thr_exit. This will close the window in
 * getldap_get_rootDSE.
 *
 */
static void
sync_current_with_update_copy(server_info_t *info)
{
	if (current_admin.debug_level >= DBG_ALL) {
		logit("sync_current_with_update_copy()...\n");
	}

	(void) mutex_lock(&info->mutex[1]);
	(void) mutex_lock(&info->mutex[0]);

	if (info->sinfo[1].server_status == INFO_SERVER_UP &&
	    info->sinfo[0].server_status != INFO_SERVER_UP)
		info->sinfo[1].change = NS_SERVER_UP;
	else if (info->sinfo[1].server_status != INFO_SERVER_UP &&
	    info->sinfo[0].server_status == INFO_SERVER_UP)
		info->sinfo[1].change = NS_SERVER_DOWN;
	else
		info->sinfo[1].change = 0;


	/* free memory in current copy first */
	if (info->sinfo[0].addr)
		free(info->sinfo[0].addr);
	info->sinfo[0].addr = NULL;

	if (info->sinfo[0].hostname)
		free(info->sinfo[0].hostname);
	info->sinfo[0].hostname = NULL;

	if (info->sinfo[0].rootDSE_data)
		free(info->sinfo[0].rootDSE_data);
	info->sinfo[0].rootDSE_data = NULL;

	if (info->sinfo[0].errormsg)
		free(info->sinfo[0].errormsg);
	info->sinfo[0].errormsg = NULL;

	/*
	 * make current and update copy identical
	 */
	info->sinfo[0] = info->sinfo[1];

	/*
	 * getldap_get_server_stat() reads the update copy sinfo[1]
	 * so it can't be freed or nullified yet at this point.
	 *
	 * The sinfo[0] and sinfo[1] have identical string pointers.
	 * strdup the strings to avoid the double free problem.
	 * The strings of sinfo[1] are freed in
	 * getldap_get_rootDSE() and the strings of sinfo[0]
	 * are freed earlier in this function. If the pointers are the
	 * same, they will be freed twice.
	 */
	if (info->sinfo[1].addr)
		info->sinfo[0].addr = strdup(info->sinfo[1].addr);
	if (info->sinfo[1].hostname)
		info->sinfo[0].hostname = strdup(info->sinfo[1].hostname);
	if (info->sinfo[1].rootDSE_data)
		info->sinfo[0].rootDSE_data =
		    strdup(info->sinfo[1].rootDSE_data);
	if (info->sinfo[1].errormsg)
		info->sinfo[0].errormsg = strdup(info->sinfo[1].errormsg);

	(void) mutex_unlock(&info->mutex[0]);
	(void) mutex_unlock(&info->mutex[1]);

}

static void *
getldap_get_rootDSE(void *arg)
{
	server_info_t	*serverInfo = (server_info_t *)arg;
	char		*rootDSE;
	int		exitrc = NS_LDAP_SUCCESS;
	pid_t		ppid;
	int		server_found = 0;
	char		errmsg[MAXERROR];
	ns_ldap_return_code	rc;
	ns_ldap_error_t *error = NULL;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_get_rootDSE()....\n");
	}

	/* initialize the server info element */
	(void) mutex_lock(&serverInfo->mutex[1]);
	serverInfo->sinfo[1].type	= INFO_RW_UNKNOWN;
	serverInfo->sinfo[1].info_status =
	    INFO_STATUS_UNKNOWN;
	/*
	 * When the sever list is refreshed over and over,
	 * this function is called each time it is refreshed.
	 * The previous server status of the update copy(sinfo[1])
	 * is the status of the current copy
	 */
	(void) mutex_lock(&serverInfo->mutex[0]);
	serverInfo->sinfo[1].prev_server_status =
	    serverInfo->sinfo[0].server_status;
	(void) mutex_unlock(&serverInfo->mutex[0]);

	serverInfo->sinfo[1].server_status =
	    INFO_SERVER_UNKNOWN;
	if (serverInfo->sinfo[1].rootDSE_data)
		free(serverInfo->sinfo[1].rootDSE_data);
	serverInfo->sinfo[1].rootDSE_data	= NULL;
	if (serverInfo->sinfo[1].errormsg)
		free(serverInfo->sinfo[1].errormsg);
	serverInfo->sinfo[1].errormsg 		= NULL;
	(void) mutex_unlock(&serverInfo->mutex[1]);

	(void) mutex_lock(&serverInfo->mutex[1]);
	serverInfo->sinfo[1].server_status = INFO_SERVER_CONNECTING;
	(void) mutex_unlock(&serverInfo->mutex[1]);

	/*
	 * WARNING: anon_fallback == 1 (last argument) means that when
	 * __ns_ldap_getRootDSE is unable to bind using the configured
	 * credentials, it will try to fall back to using anonymous, non-SSL
	 * mode of operation.
	 *
	 * This is for backward compatibility reasons - we might have machines
	 * in the field with broken configuration (invalid credentials) and we
	 * don't want them to be disturbed.
	 */
	if (rc = __ns_ldap_getRootDSE(serverInfo->sinfo[1].addr,
	    &rootDSE,
	    &error,
	    SA_ALLOW_FALLBACK) != NS_LDAP_SUCCESS) {
		(void) mutex_lock(&serverInfo->mutex[1]);
		serverInfo->sinfo[1].server_status = INFO_SERVER_ERROR;
		serverInfo->sinfo[1].info_status = INFO_STATUS_ERROR;
		if (error && error->message) {
			serverInfo->sinfo[1].errormsg = strdup(error->message);
		} else {
			(void) snprintf(errmsg, sizeof (errmsg), "%s %s "
			    "(rc = %d)", gettext("Can not get the root DSE from"
			    " server"), serverInfo->sinfo[1].addr, rc);
			serverInfo->sinfo[1].errormsg = strdup(errmsg);
		}

		if (error != NULL) {
			(void) __ns_ldap_freeError(&error);
		}

		if (current_admin.debug_level >= DBG_ALL) {
			logit("getldap_get_rootDSE: %s.\n",
			    serverInfo->sinfo[1].errormsg);
		}
		(void) mutex_unlock(&serverInfo->mutex[1]);
		/*
		 * sync sinfo copies in the serverInfo.
		 * protected by mutex
		 */
		sync_current_with_update_copy(serverInfo);
		thr_exit((void *) -1);
	}

	(void) mutex_lock(&serverInfo->mutex[1]);

	/* assume writeable, i.e., can do modify */
	serverInfo->sinfo[1].type		= INFO_RW_WRITEABLE;
	serverInfo->sinfo[1].server_status	= INFO_SERVER_UP;
	serverInfo->sinfo[1].info_status	= INFO_STATUS_NEW;
	/* remove the last DOORLINESEP */
	*(rootDSE+strlen(rootDSE)-1) = '\0';
	serverInfo->sinfo[1].rootDSE_data = rootDSE;

	server_found = 1;

	(void) mutex_unlock(&serverInfo->mutex[1]);

	/*
	 * sync sinfo copies in the serverInfo.
	 * protected by mutex
	 */
	sync_current_with_update_copy(serverInfo);
	/*
	 * signal that the ldap_cachemgr parent process
	 * should exit now, if it is still waiting
	 */
	(void) mutex_lock(&sig_mutex);
	if (signal_done == FALSE && server_found) {
		ppid = getppid();
		(void) kill(ppid, SIGUSR1);
		if (current_admin.debug_level >= DBG_ALL) {
			logit("getldap_get_rootDSE(): "
			    "SIGUSR1 signal sent to "
			    "parent process(%ld).\n", ppid);
		}
		signal_done = TRUE;
	}
	(void) mutex_unlock(&sig_mutex);

	thr_exit((void *) exitrc);

	return ((void *) NULL);
}

static int
getldap_init_serverInfo(server_info_t **head)
{
	char		**servers = NULL;
	int		rc = 0, i, exitrc = NS_LDAP_SUCCESS;
	ns_ldap_error_t *errorp = NULL;
	server_info_t	*info, *tail = NULL;

	*head = NULL;
	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_init_serverInfo()...\n");
	}
	rc = __s_api_getServers(&servers, &errorp);

	if (rc != NS_LDAP_SUCCESS) {
		logit("getldap_init_serverInfo: "
		    "__s_api_getServers failed.\n");
		if (errorp)
			__ns_ldap_freeError(&errorp);
		return (-1);
	}
	for (i = 0; servers[i] != NULL; i++) {
		info = (server_info_t *)calloc(1, sizeof (server_info_t));
		if (info == NULL) {
			logit("getldap_init_serverInfo: "
			    "not enough memory.\n");
			exitrc = NS_LDAP_MEMORY;
			break;
		}
		if (i == 0) {
			*head = info;
			tail  = info;
		} else {
			tail->next = info;
			tail  = info;
		}

		info->sinfo[0].addr		= strdup(servers[i]);
		if (info->sinfo[0].addr == NULL) {
			logit("getldap_init_serverInfo: "
			    "not enough memory.\n");
			exitrc = NS_LDAP_MEMORY;
			break;
		}
		info->sinfo[1].addr		= strdup(servers[i]);
		if (info->sinfo[1].addr == NULL) {
			logit("getldap_init_serverInfo: "
			    "not enough memory.\n");
			exitrc = NS_LDAP_MEMORY;
			break;
		}

		info->sinfo[0].type 		= INFO_RW_UNKNOWN;
		info->sinfo[1].type 		= INFO_RW_UNKNOWN;
		info->sinfo[0].info_status	= INFO_STATUS_UNKNOWN;
		info->sinfo[1].info_status	= INFO_STATUS_UNKNOWN;
		info->sinfo[0].server_status	= INFO_SERVER_UNKNOWN;
		info->sinfo[1].server_status	= INFO_SERVER_UNKNOWN;

		/*
		 * Assume at startup or after the configuration
		 * profile is refreshed, all servers are good.
		 */
		info->sinfo[0].prev_server_status =
		    INFO_SERVER_UP;
		info->sinfo[1].prev_server_status =
		    INFO_SERVER_UP;
		info->sinfo[0].hostname		= NULL;
		info->sinfo[1].hostname		= NULL;
		info->sinfo[0].rootDSE_data	= NULL;
		info->sinfo[1].rootDSE_data	= NULL;
		info->sinfo[0].errormsg 	= NULL;
		info->sinfo[1].errormsg 	= NULL;
		info->next 		= NULL;
	}
	__s_api_free2dArray(servers);
	if (exitrc != NS_LDAP_SUCCESS) {
		if (head && *head) {
			(void) getldap_destroy_serverInfo(*head);
			*head = NULL;
		}
	}
	return (exitrc);
}

static int
getldap_destroy_serverInfo(server_info_t *head)
{
	server_info_t	*info, *next;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_destroy_serverInfo()...\n");
	}

	if (head == NULL) {
		logit("getldap_destroy_serverInfo: "
		    "invalid serverInfo list.\n");
		return (-1);
	}

	for (info = head; info; info = next) {
		if (info->sinfo[0].addr)
			free(info->sinfo[0].addr);
		if (info->sinfo[1].addr)
			free(info->sinfo[1].addr);
		if (info->sinfo[0].hostname)
			free(info->sinfo[0].hostname);
		if (info->sinfo[1].hostname)
			free(info->sinfo[1].hostname);
		if (info->sinfo[0].rootDSE_data)
			free(info->sinfo[0].rootDSE_data);
		if (info->sinfo[1].rootDSE_data)
			free(info->sinfo[1].rootDSE_data);
		if (info->sinfo[0].errormsg)
			free(info->sinfo[0].errormsg);
		if (info->sinfo[1].errormsg)
			free(info->sinfo[1].errormsg);
		next = info->next;
		free(info);
	}
	return (NS_LDAP_SUCCESS);
}

static int
getldap_set_serverInfo(server_info_t *head, int reset_bindtime, info_op_t op)
{
	server_info_t	*info;
	int 		atleast1 = 0;
	thread_t	*tid;
	int 		num_threads = 0, i, j;
	void		*status;
	void		**paramVal = NULL;
	ns_ldap_error_t	*error = NULL;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_set_serverInfo()...\n");
	}

	if (head == NULL) {
		logit("getldap_set_serverInfo: "
		    "invalid serverInfo list.\n");
		return (-1);
	}

	/* Get the bind timeout value */
	if (reset_bindtime == 1) {
		tcptimeout = NS_DEFAULT_BIND_TIMEOUT * 1000;
		(void) __ns_ldap_getParam(NS_LDAP_BIND_TIME_P,
		    &paramVal, &error);
		if (paramVal != NULL && *paramVal != NULL) {
			/* convert to milliseconds */
			tcptimeout = **((int **)paramVal);
			tcptimeout *= 1000;
			(void) __ns_ldap_freeParam(&paramVal);
		}
		if (error)
			(void) __ns_ldap_freeError(&error);
	}

	for (info = head; info; info = info->next)
		num_threads++;

	if (num_threads == 0) {
		logit("getldap_set_serverInfo: "
		    "empty serverInfo list.\n");
		return (-1);
	}

	tid = (thread_t *) calloc(1, sizeof (thread_t) * num_threads);
	if (tid == NULL) {
		logit("getldap_set_serverInfo: "
		    "No memory to create thread ID list.\n");
		return (-1);
	}

	for (info = head, i = 0; info; info = info->next, i++) {
		if (thr_create(NULL, 0,
		    (void *(*)(void*))getldap_get_rootDSE,
		    (void *)info, 0, &tid[i])) {
			logit("getldap_set_serverInfo: "
			    "can not create thread %d.\n", i + 1);
			for (j = 0; j < i; j++)
				(void) thr_join(tid[j], NULL, NULL);
			free(tid);
			return (-1);
		}
	}

	for (i = 0; i < num_threads; i++) {
		if (thr_join(tid[i], NULL, &status) == 0) {
			if ((int)status == NS_LDAP_SUCCESS)
				atleast1 = 1;
		}
	}

	free(tid);

	if (op == INFO_OP_REFRESH)
		test_server_change(head);
	if (atleast1) {
		return (NS_LDAP_SUCCESS);
	} else
		return (-1);
}

/*
 * getldap_get_serverInfo processes the GETLDAPSERVER door request passed
 * to this function from getldap_serverInfo_op().
 * input:
 *   a buffer containing an empty string (e.g., input[0]='\0';) or a string
 *   as the "input" in printf(input, "%s%s%s%s", req, addrtype, DOORLINESEP,
 *   addr);
 *   where addr is the address of a server and
 *   req is one of the following:
 *   NS_CACHE_NEW:    send a new server address, addr is ignored.
 *   NS_CACHE_NORESP: send the next one, remove addr from list.
 *   NS_CACHE_NEXT:   send the next one, keep addr on list.
 *   NS_CACHE_WRITE:  send a non-replica server, if possible, if not, same
 *                    as NS_CACHE_NEXT.
 *   addrtype:
 *   NS_CACHE_ADDR_IP: return server address as is, this is default.
 *   NS_CACHE_ADDR_HOSTNAME: return both server address and its FQDN format,
 *			only self credential case requires such format.
 * output:
 *   a buffer containing server info in the following format:
 *   serveraddress DOORLINESEP [ serveraddress FQDN DOORLINESEP ]
 *   [ attr=value [DOORLINESEP attr=value ]...]
 *   For example: ( here | used as DOORLINESEP for visual purposes)
 *   1) simple bind and sasl/DIGEST-MD5 bind :
 *   1.2.3.4|supportedControl=1.1.1.1|supportedSASLmechanisms=EXTERNAL|
 *   supportedSASLmechanisms=GSSAPI
 *   2) sasl/GSSAPI bind (self credential):
 *   1.2.3.4|foo.sun.com|supportedControl=1.1.1.1|
 *   supportedSASLmechanisms=EXTERNAL|supportedSASLmechanisms=GSSAPI
 *   NOTE: caller should free this buffer when done using it
 */
static int
getldap_get_serverInfo(server_info_t *head, char *input,
		char **output, int *svr_removed)
{
	server_info_t	*info 	= NULL;
	server_info_t	*server	= NULL;
	char 		*addr	= NULL;
	char 		*req	= NULL;
	char 		req_new[] = NS_CACHE_NEW;
	char 		addr_type[] = NS_CACHE_ADDR_IP;
	int		matched = FALSE, len = 0, rc = 0;
	char		*ret_addr = NULL, *ret_addrFQDN = NULL;
	char		*new_addr = NULL;
	pid_t		pid;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_get_serverInfo()...\n");
	}

	if (input == NULL || output == NULL) {
		logit("getldap_get_serverInfo: "
		    "No input or output buffer.\n");
		return (-1);
	}

	*output = NULL;
	*svr_removed = FALSE;

	if (head == NULL) {
		logit("getldap_get_serverInfo: "
		    "invalid serverInfo list.\n");
		return (-1);
	}
	/*
	 * parse the input string to get req and addr,
	 * if input is empty, i.e., input[0] == '\0',
	 * treat it as an NS_CACHE_NEW request
	 */
	req = req_new;
	if (input[0] != '\0') {
		req = input;
		/* Save addr type flag */
		addr_type[0] = input[1];
		input[strlen(NS_CACHE_NEW)] = '\0';
		/* skip acion type flag, addr type flag and DOORLINESEP */
		addr = input + strlen(DOORLINESEP) + strlen(NS_CACHE_NEW)
		    + strlen(NS_CACHE_ADDR_IP);
	}
	/*
	 * if NS_CACHE_NEW,
	 * or the server info is new,
	 * starts from the
	 * beginning of the list
	 */
	if ((strcmp(req, NS_CACHE_NEW) == 0) ||
	    (head->sinfo[0].info_status == INFO_STATUS_NEW))
		matched = TRUE;
	for (info = head; info; info = info->next) {
		/*
		 * make sure the server info stays the same
		 * while the data is being processed
		 */

		/*
		 * This function is called to get server info list
		 * and pass it back to door call clients.
		 * Access the current copy (sinfo[0]) to get such
		 * information
		 */
		(void) mutex_lock(&info->mutex[0]);

		if (matched == FALSE &&
		    strcmp(info->sinfo[0].addr, addr) == 0) {
			matched = TRUE;
			if (strcmp(req, NS_CACHE_NORESP) == 0) {
				if (chg_is_called_from_nscd_or_peruser_nscd(
				    "REMOVE SERVER", &pid) == 0) {
					(void) mutex_unlock(&info->mutex[0]);
					if (current_admin.debug_level >=
					    DBG_ALL)
						logit("Only nscd can remove "
						    "servers. pid %ld", pid);
					continue;
				}

				/*
				 * if the information is new,
				 * give this server one more chance
				 */
				if (info->sinfo[0].info_status ==
				    INFO_STATUS_NEW &&
				    info->sinfo[0].server_status  ==
				    INFO_SERVER_UP) {
					server = info;
					break;
				} else {
					/*
					 * it is recommended that
					 * before removing the
					 * server from the list,
					 * the server should be
					 * contacted one more time
					 * to make sure that it is
					 * really unavailable.
					 * For now, just trust the client
					 * (i.e., the sldap library)
					 * that it knows what it is
					 * doing and would not try
					 * to mess up the server
					 * list.
					 */
					/*
					 * Make a copy of addr to contact
					 * it later. It's not doing it here
					 * to avoid long wait and possible
					 * recursion to contact an LDAP server.
					 */
					new_addr = strdup(info->sinfo[0].addr);
					if (new_addr)
						remove_server(new_addr);
					*svr_removed = TRUE;
					(void) mutex_unlock(&info->mutex[0]);
					break;
				}
			} else {
				/*
				 * req == NS_CACHE_NEXT or NS_CACHE_WRITE
				 */
				(void) mutex_unlock(&info->mutex[0]);
				continue;
			}
		}

		if (matched) {
			if (strcmp(req, NS_CACHE_WRITE) == 0) {
				if (info->sinfo[0].type ==
				    INFO_RW_WRITEABLE &&
				    info->sinfo[0].server_status  ==
				    INFO_SERVER_UP) {
					server = info;
					break;
				}
			} else if (info->sinfo[0].server_status ==
			    INFO_SERVER_UP) {
				server = info;
				break;
			}
		}

		(void) mutex_unlock(&info->mutex[0]);
	}

	if (server) {
		if (strcmp(addr_type, NS_CACHE_ADDR_HOSTNAME) == 0) {
			/*
			 * In SASL/GSSAPI case, a hostname is required for
			 * Kerberos's service principal.
			 * e.g.
			 * ldap/foo.sun.com@SUN.COM
			 */
			if (server->sinfo[0].hostname == NULL) {
				rc = __s_api_ip2hostname(server->sinfo[0].addr,
				    &server->sinfo[0].hostname);
				if (rc != NS_LDAP_SUCCESS) {
					(void) mutex_unlock(&info->mutex[0]);
					return (rc);
				}
				if (current_admin.debug_level >= DBG_ALL) {
					logit("getldap_get_serverInfo: "
					    "%s is converted to %s\n",
					    server->sinfo[0].addr,
					    server->sinfo[0].hostname);
				}
			}
			ret_addr = server->sinfo[0].addr;
			ret_addrFQDN = server->sinfo[0].hostname;

		} else
			ret_addr = server->sinfo[0].addr;


		len = strlen(ret_addr) +
		    strlen(server->sinfo[0].rootDSE_data) +
		    strlen(DOORLINESEP) + 1;
		if (ret_addrFQDN != NULL)
			len += strlen(ret_addrFQDN) + strlen(DOORLINESEP);
		*output = (char *)malloc(len);
		if (*output == NULL) {
			(void) mutex_unlock(&info->mutex[0]);
			return (NS_LDAP_MEMORY);
		}
		if (ret_addrFQDN == NULL)
			(void) snprintf(*output, len, "%s%s%s",
			    ret_addr, DOORLINESEP,
			    server->sinfo[0].rootDSE_data);
		else
			(void) snprintf(*output, len, "%s%s%s%s%s",
			    ret_addr, DOORLINESEP,
			    ret_addrFQDN, DOORLINESEP,
			    server->sinfo[0].rootDSE_data);
		server->sinfo[0].info_status = INFO_STATUS_OLD;
		(void) mutex_unlock(&info->mutex[0]);
		return (NS_LDAP_SUCCESS);
	}
	else
		return (-99);
}

/*
 * Format previous and next refresh time
 */
static int
getldap_format_refresh_time(char **output, time_t *prev, time_t *next)
{
#define	TIME_FORMAT	"%Y/%m/%d %H:%M:%S"
#define	TIME_HEADER1	"  Previous refresh time: "
#define	TIME_HEADER2	"  Next refresh time:     "
	int		hdr1_len = strlen(gettext(TIME_HEADER1));
	int		hdr2_len = strlen(gettext(TIME_HEADER2));
	struct	tm 	tm;
	char		nbuf[256];
	char		pbuf[256];
	int		len;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_format_refresh_time()...\n");
	}

	*output = NULL;

	/* format the time of previous refresh  */
	if (*prev != 0) {
		(void) localtime_r(prev, &tm);
		(void) strftime(pbuf, sizeof (pbuf) - 1, TIME_FORMAT, &tm);
	} else {
		(void) strcpy(pbuf, gettext("NOT DONE"));
	}

	/* format the time of next refresh  */
	if (*next != 0) {
		(void) localtime_r(next, &tm);
		(void) strftime(nbuf, sizeof (nbuf) - 1, TIME_FORMAT, &tm);
	} else {
		(void) strcpy(nbuf, gettext("NOT SET"));
	}

	len = hdr1_len + hdr2_len + strlen(nbuf) +
	    strlen(pbuf) + 2 * strlen(DOORLINESEP) + 1;

	*output = malloc(len);
	if (*output == NULL)
		return (-1);

	(void) snprintf(*output, len, "%s%s%s%s%s%s",
	    gettext(TIME_HEADER1), pbuf, DOORLINESEP,
	    gettext(TIME_HEADER2), nbuf, DOORLINESEP);

	return (NS_LDAP_SUCCESS);
}

/*
 * getldap_get_server_stat processes the GETSTAT request passed
 * to this function from getldap_serverInfo_op().
 * output:
 *   a buffer containing info for all the servers.
 *   For each server, the data is in the following format:
 *   server: server address or name, status: unknown|up|down|removed DOORLINESEP
 *   for example: ( here | used as DOORLINESEP for visual purposes)
 *   server: 1.2.3.4, status: down|server: 2.2.2.2, status: up|
 *   NOTE: caller should free this buffer when done using it
 */
static int
getldap_get_server_stat(server_info_t *head, char **output,
		time_t *prev, time_t *next)
{
#define	S_HEADER	"Server information: "
#define	S_FORMAT	"  server: %s, status: %s%s"
#define	S_ERROR		"    error message: %s%s"
	server_info_t	*info 	= NULL;
	int	header_len = strlen(gettext(S_HEADER));
	int	format_len = strlen(gettext(S_FORMAT));
	int	error_len = strlen(gettext(S_ERROR));
	int	len = header_len + strlen(DOORLINESEP);
	int	len1 = 0;
	char	*status, *output1 = NULL, *tmpptr;

	*output = NULL;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_get_server_stat()...\n");
	}

	if (head == NULL) {
		logit("getldap_get_server_stat: "
		    "invalid serverInfo list.\n");
		return (-1);
	}

	/* format previous and next refresh time */
	(void) getldap_format_refresh_time(&output1, prev, next);
	if (output1 == NULL)
		return (-1);
	len += strlen(output1);
	len1 = len + strlen(DOORLINESEP) + 1;

	*output = (char *)calloc(1, len1);
	if (*output == NULL) {
		free(output1);
		return (-1);
	}

	/* insert header string and refresh time info */
	(void) snprintf(*output, len1, "%s%s%s",
	    gettext(S_HEADER), DOORLINESEP, output1);

	for (info = head; info; info = info->next) {

		/*
		 * make sure the server info stays the same
		 * while the data is being processed
		 */
		(void) mutex_lock(&info->mutex[1]);

		/*
		 * When the updating process is under way(getldap_get_rootDSE)
		 * the update copy(sinfo[1] is the latest copy.
		 * When the updating process
		 * is done, the current copy (sinfo[0]) has the latest status,
		 * which is still identical to the update copy.
		 * So update copy has the latest status.
		 * Use the update copy(sinfo[1]) to show status
		 * (ldap_cachemgr -g).
		 *
		 */

		switch (info->sinfo[1].server_status) {
		case INFO_SERVER_UNKNOWN:
			status = gettext("UNKNOWN");
			break;
		case INFO_SERVER_CONNECTING:
			status = gettext("CONNECTING");
			break;
		case INFO_SERVER_UP:
			status = gettext("UP");
			break;
		case INFO_SERVER_ERROR:
			status = gettext("ERROR");
			break;
		case INFO_SERVER_REMOVED:
			status = gettext("REMOVED");
			break;
		}

		len += format_len + strlen(status) +
		    strlen(info->sinfo[1].addr) +
		    strlen(DOORLINESEP);
		if (info->sinfo[1].errormsg != NULL)
			len += error_len +
			    strlen(info->sinfo[1].errormsg) +
			    strlen(DOORLINESEP);

		tmpptr = (char *)realloc(*output, len);
		if (tmpptr == NULL) {
			free(output1);
			free(*output);
			*output = NULL;
			(void) mutex_unlock(&info->mutex[1]);
			return (-1);
		} else
			*output = tmpptr;

		/* insert server IP addr or name and status */
		len1 = len - strlen(*output);
		(void) snprintf(*output + strlen(*output), len1,
		    gettext(S_FORMAT), info->sinfo[1].addr,
		    status, DOORLINESEP);
		/* insert error message if any */
		len1 = len - strlen(*output);
		if (info->sinfo[1].errormsg != NULL)
			(void) snprintf(*output + strlen(*output), len1,
			    gettext(S_ERROR),
			    info->sinfo[1].errormsg,
			    DOORLINESEP);

		(void) mutex_unlock(&info->mutex[1]);

	}

	free(output1);
	return (NS_LDAP_SUCCESS);
}

/*
 * Format and return the refresh time statistics
 */
static int
getldap_get_refresh_stat(char **output)
{
#define	R_HEADER0	"Configuration refresh information: "
#define	R_HEADER1	"  Configured to NO REFRESH."
	int		hdr0_len = strlen(gettext(R_HEADER0));
	int		hdr1_len = strlen(gettext(R_HEADER1));
	int		cache_ttl = -1, len = 0;
	time_t 		expire = 0;
	void		**paramVal = NULL;
	ns_ldap_error_t	*errorp = NULL;
	char		*output1 = NULL;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_get_refresh_stat()...\n");
	}

	*output = NULL;

	/* get configured cache TTL */
	if ((__ns_ldap_getParam(NS_LDAP_CACHETTL_P,
	    &paramVal, &errorp) == NS_LDAP_SUCCESS) &&
	    paramVal != NULL &&
	    (char *)*paramVal != NULL) {
			cache_ttl = atol((char *)*paramVal);
	} else {
		if (errorp)
			__ns_ldap_freeError(&errorp);
	}
	(void) __ns_ldap_freeParam(&paramVal);

	/* cound not get cache TTL */
	if (cache_ttl == -1)
		return (-1);

	if (cache_ttl == 0) {
		len = hdr0_len + hdr1_len +
		    2 * strlen(DOORLINESEP) + 1;
		*output = malloc(len);
		if (*output == NULL)
			return (-1);
		(void) snprintf(*output, len, "%s%s%s%s",
		    gettext(R_HEADER0), DOORLINESEP,
		    gettext(R_HEADER1), DOORLINESEP);
	} else {

		/* get configuration expiration time */
		if ((__ns_ldap_getParam(NS_LDAP_EXP_P,
		    &paramVal, &errorp) == NS_LDAP_SUCCESS) &&
		    paramVal != NULL &&
		    (char *)*paramVal != NULL) {
				expire = (time_t)atol((char *)*paramVal);
		} else {
			if (errorp)
				__ns_ldap_freeError(&errorp);
		}

		(void) __ns_ldap_freeParam(&paramVal);

		/* cound not get expiration time */
		if (expire == -1)
			return (-1);

		/* format previous and next refresh time */
		(void) getldap_format_refresh_time(&output1,
		    &prev_refresh_time, &expire);
		if (output1 == NULL)
			return (-1);

		len = hdr0_len + strlen(output1) +
		    2 * strlen(DOORLINESEP) + 1;
		*output = malloc(len);
		if (*output == NULL) {
			free(output1);
			return (-1);
		}
		(void) snprintf(*output, len, "%s%s%s%s",
		    gettext(R_HEADER0), DOORLINESEP,
		    output1, DOORLINESEP);
		free(output1);
	}

	return (NS_LDAP_SUCCESS);
}

static int
getldap_get_cacheTTL()
{
	void		**paramVal = NULL;
	ns_ldap_error_t	*error;
	int		rc = 0, cachettl;


	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_get_cacheTTL()....\n");
	}

	if ((rc = __ns_ldap_getParam(NS_LDAP_CACHETTL_P,
	    &paramVal, &error)) != NS_LDAP_SUCCESS) {
		if (error != NULL && error->message != NULL)
			logit("Error: Unable to get configuration "
			    "refresh TTL: %s\n",
			    error->message);
		else {
			char *tmp;

			__ns_ldap_err2str(rc, &tmp);
			logit("Error: Unable to get configuration "
			    "refresh TTL: %s\n", tmp);
		}
		(void) __ns_ldap_freeParam(&paramVal);
		(void) __ns_ldap_freeError(&error);
		return (-1);
	}
	if (paramVal == NULL || (char *)*paramVal == NULL)
			return (-1);
	cachettl = atol((char *)*paramVal);
	(void) __ns_ldap_freeParam(&paramVal);
	return (cachettl);
}


/*
 * This function implements the adaptive server list refresh
 * algorithm used by ldap_cachemgr. The idea is to have the
 * refresh TTL adjust itself between maximum and minimum
 * values. If the server list has been walked three times
 * in a row without errors, the TTL will be doubled. This will
 * be done repeatedly until the maximum value is reached
 * or passed. If passed, the maximum value will be used.
 * If any time a server is found to be down/bad, either
 * after another server list walk or informed by libsldap via
 * the GETLDAPSERVER door calls, the TTL will be set to half
 * of its value, again repeatedly, but no less than the minimum
 * value. Also, at any time, if all the servers on the list
 * are found to be down/bad, the TTL will be set to minimum,
 * so that a "no-server" refresh loop should be entered to try
 * to find a good server as soon as possible. The caller
 * could check the no_gd_server flag for this situation.
 * The maximum and minimum values are initialized when the input
 * refresh_ttl is set to zero, this should occur during
 * ldap_cachemgr startup or every time the server list is
 * recreated after the configuration profile is refreshed
 * from an LDAP server. The maximum is set to the value of
 * the NS_LDAP_CACHETTL parameter (configuration profile
 * refresh TTL), but if it is zero (never refreshed) or can
 * not be retrieved, the maximum is set to the macro
 * REFRESHTTL_MAX (12 hours) defined below. The minimum is
 * set to REFRESHTTL_MIN, which is the TCP connection timeout
 * (tcptimeout) set via the LDAP API ldap_set_option()
 * with the new LDAP_X_OPT_CONNECT_TIMEOUT option plus 10 seconds.
 * This accounts for the maximum possible timeout value for an
 * LDAP TCP connect call.The first refresh TTL, initial value of
 * refresh_ttl, will be set to the smaller of the two,
 * REFRESHTTL_REGULAR (10 minutes) or (REFRESHTTL_MAX + REFRESHTTL_MIN)/2.
 * The idea is to have a low starting value and have the value
 * stay low if the network/server is unstable, but eventually
 * the value will move up to maximum and stay there if the
 * network/server is stable.
 */
static int
getldap_set_refresh_ttl(server_info_t *head, int *refresh_ttl,
		int *no_gd_server)
{
#define	REFRESHTTL_REGULAR	600
#define	REFRESHTTL_MAX		43200
/* tcptimeout is in milliseconds */
#define	REFRESHTTL_MIN		(tcptimeout/1000) + 10
#define	UP_REFRESH_TTL_NUM	2

	static mutex_t		refresh_mutex;
	static int		refresh_ttl_max = 0;
	static int		refresh_ttl_min = 0;
	static int		num_walked_ok = 0;
	int			num_servers = 0;
	int			num_good_servers = 0;
	int			num_prev_good_servers = 0;
	server_info_t		*info;

	/* allow one thread at a time */
	(void) mutex_lock(&refresh_mutex);

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_set_refresh_ttl()...\n");
	}

	if (!head || !refresh_ttl || !no_gd_server) {
		logit("getldap_set_refresh_ttl: head is "
		    "NULL or refresh_ttl is NULL or "
		    "no_gd_server is NULL");
		(void) mutex_unlock(&refresh_mutex);
		return (-1);
	}
	*no_gd_server = FALSE;

	/*
	 * init max. min. TTLs if first time through or a fresh one
	 */
	if (current_admin.debug_level >= DBG_SERVER_LIST_REFRESH) {
		logit("getldap_set_refresh_ttl:(1) refresh ttl is %d "
		    "seconds\n", *refresh_ttl);
	}
	if (*refresh_ttl == 0) {
		num_walked_ok = 0;
		/*
		 * init cache manager server list TTL:
		 *
		 * init the min. TTL to
		 * REFRESHTTL_MIN ( 2*(TCP MSL) + 10 seconds)
		 */
		refresh_ttl_min = REFRESHTTL_MIN;

		/*
		 * try to set the max. TTL to
		 * configuration refresh TTL (NS_LDAP_CACHETTL),
		 * if error (-1), or never refreshed (0),
		 * set it to REFRESHTTL_MAX (12 hours)
		 */
		refresh_ttl_max = getldap_get_cacheTTL();
		if (current_admin.debug_level >= DBG_SERVER_LIST_REFRESH) {
			logit("getldap_set_refresh_ttl:(2) refresh ttl is %d "
			    "seconds\n", *refresh_ttl);
			logit("getldap_set_refresh_ttl:(2) max ttl is %d, "
			    "min ttl is %d seconds\n",
			    refresh_ttl_max, refresh_ttl_min);
		}
		if (refresh_ttl_max <= 0)
			refresh_ttl_max = REFRESHTTL_MAX;
		else if (refresh_ttl_max < refresh_ttl_min)
			refresh_ttl_max = refresh_ttl_min;

		/*
		 * init the first TTL to the smaller of the two:
		 * REFRESHTTL_REGULAR ( 10 minutes),
		 * (refresh_ttl_max + refresh_ttl_min)/2
		 */
		*refresh_ttl = REFRESHTTL_REGULAR;
		if (*refresh_ttl > (refresh_ttl_max + refresh_ttl_min) / 2)
			*refresh_ttl = (refresh_ttl_max + refresh_ttl_min) / 2;
		if (current_admin.debug_level >= DBG_SERVER_LIST_REFRESH) {
			logit("getldap_set_refresh_ttl:(3) refresh ttl is %d "
			    "seconds\n", *refresh_ttl);
			logit("getldap_set_refresh_ttl:(3) max ttl is %d, "
			    "min ttl is %d seconds\n",
			    refresh_ttl_max, refresh_ttl_min);
		}
	}

	/*
	 * get the servers statistics:
	 * number of servers on list
	 * number of good servers on list
	 * number of pevious good servers on list
	 */
	for (info = head; info; info = info->next) {
		num_servers++;
		(void) mutex_lock(&info->mutex[0]);
		if (info->sinfo[0].server_status  == INFO_SERVER_UP)
			num_good_servers++;
		/*
		 * Server's previous status could be UNKNOWN
		 * only between the very first and second
		 * refresh. Treat that UNKNOWN status as up
		 */
		if (info->sinfo[0].prev_server_status
		    == INFO_SERVER_UP ||
		    info->sinfo[0].prev_server_status
		    == INFO_SERVER_UNKNOWN)
			num_prev_good_servers++;
		(void) mutex_unlock(&info->mutex[0]);
	}

	/*
	 * if the server list is walked three times in a row
	 * without problems, double the refresh TTL but no more
	 * than the max. refresh TTL
	 */
	if (num_good_servers == num_servers) {
		num_walked_ok++;
		if (num_walked_ok > UP_REFRESH_TTL_NUM)  {

			*refresh_ttl = *refresh_ttl * 2;
			if (*refresh_ttl > refresh_ttl_max)
				*refresh_ttl = refresh_ttl_max;

			num_walked_ok = 0;
		}
		if (current_admin.debug_level >= DBG_SERVER_LIST_REFRESH) {
			logit("getldap_set_refresh_ttl:(4) refresh ttl is %d "
			    "seconds\n", *refresh_ttl);
		}
	} else if (num_good_servers == 0) {
		/*
		 * if no good server found,
		 * set refresh TTL to miminum
		 */
		*refresh_ttl = refresh_ttl_min;
		*no_gd_server = TRUE;
		num_walked_ok = 0;
		if (current_admin.debug_level >= DBG_SERVER_LIST_REFRESH) {
			logit("getldap_set_refresh_ttl:(5) refresh ttl is %d "
			    "seconds\n", *refresh_ttl);
		}
	} else if (num_prev_good_servers > num_good_servers) {
		/*
		 * if more down/bad servers found,
		 * decrease the refresh TTL by half
		 * but no less than the min. refresh TTL
		 */
		*refresh_ttl = *refresh_ttl / 2;
		if (*refresh_ttl < refresh_ttl_min)
			*refresh_ttl = refresh_ttl_min;
		num_walked_ok = 0;
		logit("getldap_set_refresh_ttl:(6) refresh ttl is %d "
		    "seconds\n", *refresh_ttl);

	}

	if (current_admin.debug_level >= DBG_SERVER_LIST_REFRESH) {
		logit("getldap_set_refresh_ttl:(7) refresh ttl is %d seconds\n",
		    *refresh_ttl);
	}
	(void) mutex_unlock(&refresh_mutex);
	return (0);
}

static int
getldap_serverInfo_op(info_op_t op, char *input, char **output)
{

	static rwlock_t 	info_lock = DEFAULTRWLOCK;
	static rwlock_t 	info_lock_old = DEFAULTRWLOCK;
	static mutex_t		info_mutex;
	static cond_t		info_cond;
	static int		creating = FALSE;
	static int		refresh_ttl = 0;
	static int		sec_to_refresh = 0;
	static int		in_no_server_mode = FALSE;

	static server_info_t 	*serverInfo = NULL;
	static server_info_t 	*serverInfo_old = NULL;
	server_info_t 		*serverInfo_1;
	int 			is_creating;
	int 			err, no_server_good = FALSE;
	int			server_removed = FALSE;
	int			fall_thru = FALSE;
	static struct timespec	timeout;
	struct timespec		new_timeout;
	struct timeval		tp;
	static time_t		prev_refresh = 0, next_refresh = 0;
	ns_server_status_t		changed = 0;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_serverInfo_op()...\n");
	}
	switch (op) {
	case INFO_OP_CREATE:
		if (current_admin.debug_level >= DBG_ALL) {
			logit("operation is INFO_OP_CREATE...\n");
		}

		/*
		 * indicate that the server info is being
		 * (re)created, so that the refresh thread
		 * will not refresh the info list right
		 * after the list got (re)created
		 */
		(void) mutex_lock(&info_mutex);
		is_creating = creating;
		creating = TRUE;
		(void) mutex_unlock(&info_mutex);

		if (is_creating)
			break;
		/*
		 * create an empty info list
		 */
		(void) getldap_init_serverInfo(&serverInfo_1);
		/*
		 * exit if list not created
		 */
		if (serverInfo_1 == NULL) {
			(void) mutex_lock(&info_mutex);
			creating = FALSE;
			(void) mutex_unlock(&info_mutex);
			break;
		}
		/*
		 * make the new server info available:
		 * use writer lock here, so that the switch
		 * is done after all the reader locks have
		 * been released.
		 */
		(void) rw_wrlock(&info_lock);
		serverInfo = serverInfo_1;
		/*
		 * if this is the first time
		 * the server list is being created,
		 * (i.e., serverInfo_old is NULL)
		 * make the old list same as the new
		 * so the GETSERVER code can do its work
		 */
		if (serverInfo_old == NULL)
			serverInfo_old = serverInfo_1;
		(void) rw_unlock(&info_lock);

		/*
		 * fill the new info list
		 */
		(void) rw_rdlock(&info_lock);
		/* reset bind time (tcptimeout) */
		(void) getldap_set_serverInfo(serverInfo, 1, INFO_OP_CREATE);

		(void) mutex_lock(&info_mutex);
		/*
		 * set cache manager server list TTL,
		 * set refresh_ttl to zero to indicate a fresh one
		 */
		refresh_ttl = 0;
		(void) getldap_set_refresh_ttl(serverInfo,
		    &refresh_ttl, &no_server_good);
		sec_to_refresh = refresh_ttl;

		/* statistics: previous refresh time */
		if (gettimeofday(&tp, NULL) == 0)
			prev_refresh = tp.tv_sec;

		creating = FALSE;

		/*
		 * if no server found or available,
		 * tell the server info refresh thread
		 * to start the "no-server" refresh loop
		 * otherwise reset the in_no_server_mode flag
		 */
		if (no_server_good) {
			sec_to_refresh = 0;
			in_no_server_mode = TRUE;
		} else
			in_no_server_mode = FALSE;
		/*
		 * awake the sleeping refresh thread
		 */
		(void) cond_signal(&info_cond);

		(void) mutex_unlock(&info_mutex);
		(void) rw_unlock(&info_lock);

		/*
		 * delete the old server info
		 */
		(void) rw_wrlock(&info_lock_old);
		if (serverInfo_old != serverInfo)
			(void) getldap_destroy_serverInfo(serverInfo_old);
		/*
		 * serverInfo_old needs to be the same as
		 * serverinfo now.
		 * it will be used by GETSERVER processing.
		 */
		serverInfo_old = serverInfo;
		(void) rw_unlock(&info_lock_old);
		break;
	case INFO_OP_DELETE:
		if (current_admin.debug_level >= DBG_ALL) {
			logit("operation is INFO_OP_DELETE...\n");
		}
		/*
		 * use writer lock here, so that the delete would
		 * not start until all the reader locks have
		 * been released.
		 */
		(void) rw_wrlock(&info_lock);
		if (serverInfo)
			(void) getldap_destroy_serverInfo(serverInfo);
		serverInfo = NULL;
		(void) rw_unlock(&info_lock);
		break;
	case INFO_OP_REFRESH:
		if (current_admin.debug_level >= DBG_SERVER_LIST_REFRESH) {
			logit("operation is INFO_OP_REFRESH...\n");
		}
		/*
		 * if server info is currently being
		 * (re)created, do nothing
		 */
		(void) mutex_lock(&info_mutex);
		is_creating = creating;
		(void) mutex_unlock(&info_mutex);
		if (is_creating)
			break;

		(void) rw_rdlock(&info_lock);
		if (serverInfo) {
			/* do not reset bind time (tcptimeout) */
			(void) getldap_set_serverInfo(serverInfo, 0,
			    INFO_OP_REFRESH);

			(void) mutex_lock(&info_mutex);

			/* statistics: previous refresh time */
			if (gettimeofday(&tp, NULL) == 0)
				prev_refresh = tp.tv_sec;
			/*
			 * set cache manager server list TTL
			 */
			(void) getldap_set_refresh_ttl(serverInfo,
			    &refresh_ttl, &no_server_good);
			/*
			 * if no good server found,
			 * tell the server info refresh thread
			 * to start the "no-server" refresh loop
			 * otherwise reset the in_no_server_mode flag
			 */
			if (no_server_good) {
				in_no_server_mode = TRUE;
				sec_to_refresh = 0;
			} else {
				in_no_server_mode = FALSE;
				sec_to_refresh = refresh_ttl;
			}
			if (current_admin.debug_level >=
			    DBG_SERVER_LIST_REFRESH) {
				logit("getldap_serverInfo_op("
				    "INFO_OP_REFRESH):"
				    " seconds refresh: %d second(s)....\n",
				    sec_to_refresh);
			}
			(void) mutex_unlock(&info_mutex);
		}
		(void) rw_unlock(&info_lock);

		break;
	case INFO_OP_REFRESH_WAIT:
		if (current_admin.debug_level >= DBG_SERVER_LIST_REFRESH) {
			logit("operation is INFO_OP_REFRESH_WAIT...\n");
		}
		(void) cond_init(&info_cond, NULL, NULL);
		(void) mutex_lock(&info_mutex);
		err = 0;
		while (err != ETIME) {
			int sleeptime;
			/*
			 * if need to go into the "no-server" refresh
			 * loop, set timout value to
			 * REFRESH_DELAY_WHEN_NO_SERVER
			 */
			if (sec_to_refresh == 0) {
				sec_to_refresh = refresh_ttl;
				timeout.tv_sec = time(NULL) +
				    REFRESH_DELAY_WHEN_NO_SERVER;
				sleeptime = REFRESH_DELAY_WHEN_NO_SERVER;
				if (current_admin.debug_level >=
				    DBG_SERVER_LIST_REFRESH) {
					logit("getldap_serverInfo_op("
					    "INFO_OP_REFRESH_WAIT):"
					    " entering no-server "
					    "refresh loop...\n");
				}
			} else {
				timeout.tv_sec = time(NULL) + sec_to_refresh;
				sleeptime = sec_to_refresh;
			}
			timeout.tv_nsec = 0;

			/* statistics: next refresh time */
			next_refresh = timeout.tv_sec;

			if (current_admin.debug_level >=
			    DBG_SERVER_LIST_REFRESH) {
				logit("getldap_serverInfo_op("
				    "INFO_OP_REFRESH_WAIT):"
				    " about to sleep for %d second(s)...\n",
				    sleeptime);
			}
			err = cond_timedwait(&info_cond,
			    &info_mutex, &timeout);
		}
		(void) cond_destroy(&info_cond);
		(void) mutex_unlock(&info_mutex);
		break;
	case INFO_OP_GETSERVER:
		if (current_admin.debug_level >= DBG_ALL) {
			logit("operation is INFO_OP_GETSERVER...\n");
		}
		*output = NULL;
		/*
		 * GETSERVER processing always use
		 * serverInfo_old to retrieve server infomation.
		 * serverInfo_old is equal to serverInfo
		 * most of the time, except when a new
		 * server list is being created.
		 * This is why the check for is_creating
		 * is needed below.
		 */
		(void) rw_rdlock(&info_lock_old);

		if (serverInfo_old == NULL) {
			(void) rw_unlock(&info_lock_old);
			break;
		} else
			(void) getldap_get_serverInfo(serverInfo_old,
			    input, output, &server_removed);
		(void) rw_unlock(&info_lock_old);

		/*
		 * Return here and let remove server thread do its job in
		 * another thread. It executes INFO_OP_REMOVESERVER code later.
		 */
		if (server_removed)
			break;

		fall_thru = TRUE;

		/* FALL THROUGH */

	case INFO_OP_REMOVESERVER:
		/*
		 * INFO_OP_GETSERVER and INFO_OP_REMOVESERVER share the
		 * following code except (!fall thru) part.
		 */

		/*
		 * if server info is currently being
		 * (re)created, do nothing
		 */

		(void) mutex_lock(&info_mutex);
		is_creating = creating;
		(void) mutex_unlock(&info_mutex);
		if (is_creating)
			break;

		if (!fall_thru) {
			if (current_admin.debug_level >= DBG_ALL)
				logit("operation is INFO_OP_REMOVESERVER...\n");
			(void) rw_rdlock(&info_lock_old);
			changed = set_server_status(input, serverInfo_old);
			(void) rw_unlock(&info_lock_old);
			if (changed)
				create_buf_and_notify(input, changed);
			else
				break;
		}

		/*
		 * set cache manager server list TTL if necessary
		 */
		if (*output == NULL || changed) {
			(void) rw_rdlock(&info_lock);
			(void) mutex_lock(&info_mutex);

			(void) getldap_set_refresh_ttl(serverInfo,
			    &refresh_ttl, &no_server_good);

			/*
			 * if no good server found, need to go into
			 * the "no-server" refresh loop
			 * to find a server as soon as possible
			 * otherwise reset the in_no_server_mode flag
			 */
			if (no_server_good) {
				/*
				 * if already in no-server mode,
				 * don't brother
				 */
				if (in_no_server_mode == FALSE) {
					sec_to_refresh = 0;
					in_no_server_mode = TRUE;
					(void) cond_signal(&info_cond);
				}
				(void) mutex_unlock(&info_mutex);
				(void) rw_unlock(&info_lock);
				break;
			} else {
				in_no_server_mode = FALSE;
				sec_to_refresh = refresh_ttl;
			}
			/*
			 * if the refresh thread will be timed out
			 * longer than refresh_ttl seconds,
			 * wake it up to make it wait on the new
			 * time out value
			 */
			new_timeout.tv_sec = time(NULL) + refresh_ttl;
			if (new_timeout.tv_sec < timeout.tv_sec)
				(void) cond_signal(&info_cond);

			(void) mutex_unlock(&info_mutex);
			(void) rw_unlock(&info_lock);
		}
		break;
	case INFO_OP_GETSTAT:
		if (current_admin.debug_level >= DBG_ALL) {
			logit("operation is INFO_OP_GETSTAT...\n");
		}
		*output = NULL;
		(void) rw_rdlock(&info_lock);
		if (serverInfo) {
			(void) getldap_get_server_stat(serverInfo,
			    output, &prev_refresh, &next_refresh);
		}
		(void) rw_unlock(&info_lock);
		break;
	default:
		logit("getldap_serverInfo_op(): "
		    "invalid operation code (%d).\n", op);
		return (-1);
		break;
	}
	return (NS_LDAP_SUCCESS);
}

void
getldap_serverInfo_refresh()
{
	int always = 1;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_serverInfo_refresh()...\n");
	}

	/* create the server info list */
	(void) getldap_serverInfo_op(INFO_OP_CREATE, NULL, NULL);

	while (always) {
		/*
		 * the operation INFO_OP_REFRESH_WAIT
		 * causes this thread to wait until
		 * it is time to do refresh,
		 * see getldap_serverInfo_op() for details
		 */
		(void) getldap_serverInfo_op(INFO_OP_REFRESH_WAIT, NULL, NULL);
		(void) getldap_serverInfo_op(INFO_OP_REFRESH, NULL, NULL);
	}
}

void
getldap_getserver(LineBuf *config_info, ldap_call_t *in)
{
	char 		req[] = "0";

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_getserver()...\n");
	}

	config_info->len = 0;

	/* make sure the request is valid */
	req[0] = (in->ldap_u.servername)[0];
	if ((req[0] != '\0') &&
	    (strcmp(req, NS_CACHE_NEW) != 0) &&
	    (strcmp(req, NS_CACHE_NORESP)  != 0) &&
	    (strcmp(req, NS_CACHE_NEXT)    != 0) &&
	    (strcmp(req, NS_CACHE_WRITE)   != 0)) {
		return;
	}

	(void) getldap_serverInfo_op(INFO_OP_GETSERVER,
	    in->ldap_u.domainname, &config_info->str);

	if (config_info->str == NULL)
		return;

	config_info->len = strlen(config_info->str) + 1;

	if (current_admin.debug_level >= DBG_PROFILE_REFRESH) {
		/* Log server IP */
		char	*ptr,
		    separator;
		ptr = strstr(config_info->str, DOORLINESEP);
		if (ptr) {
			separator = *ptr;
			*ptr = '\0';
			logit("getldap_getserver: got server %s\n",
			    config_info->str);
			*ptr = separator;
		} else
			logit("getldap_getserver: Missing %s."
			    " Internal error\n", DOORLINESEP);
	}
}

void
getldap_get_cacheData(LineBuf *config_info, ldap_call_t *in)
{
	char	*instr = NULL;
	int	datatype = CACHE_MAP_UNKNOWN;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_get_cacheData()...\n");
	}

	config_info->len = 0;
	config_info->str = NULL;

	/* make sure the request is valid */
	if (strncmp(in->ldap_u.servername,
	    NS_CACHE_DN2DOMAIN, strlen(NS_CACHE_DN2DOMAIN)) == 0)
		datatype = CACHE_MAP_DN2DOMAIN;

	if (datatype == CACHE_MAP_UNKNOWN)
		return;

	instr = strstr(in->ldap_u.servername, DOORLINESEP);
	if (instr == NULL)
		return;
	instr += strlen(DOORLINESEP);
	if (*instr == '\0')
		return;

	(void) getldap_cache_op(CACHE_OP_FIND, datatype,
	    instr, &config_info->str);

	if (config_info->str != NULL) {
		config_info->len = strlen(config_info->str) + 1;
	}
}

int
getldap_set_cacheData(ldap_call_t *in)
{
	char	*instr1 = NULL;
	char	*instr2 = NULL;
	int	datatype = CACHE_MAP_UNKNOWN;
	int	rc = 0;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_set_cacheData()...\n");
	}

	/* make sure the request is valid */
	if (strncmp(in->ldap_u.servername,
	    NS_CACHE_DN2DOMAIN, strlen(NS_CACHE_DN2DOMAIN)) == 0)
		datatype = CACHE_MAP_DN2DOMAIN;

	if (datatype == CACHE_MAP_UNKNOWN)
		return (-1);

	instr1 = strstr(in->ldap_u.servername, DOORLINESEP);
	if (instr1 == NULL)
		return (-1);
	*instr1 = '\0';
	instr1 += strlen(DOORLINESEP);
	if (*instr1 == '\0')
		return (-1);
	instr2 = strstr(instr1, DOORLINESEP);
	if (instr2 == NULL)
		return (-1);
	*instr2 = '\0';
	instr2 += strlen(DOORLINESEP);
	if (*instr2 == '\0')
		return (-1);

	rc = getldap_cache_op(CACHE_OP_ADD, datatype,
	    instr1, &instr2);
	if (rc != NS_LDAP_SUCCESS)
		return (-1);

	return (0);
}

void
getldap_get_cacheStat(LineBuf *stat_info)
{
	char	*foutstr = NULL;
	char	*soutstr = NULL;
	char	*coutstr = NULL;
	int	infoSize;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_get_cacheStat()...\n");
	}

	stat_info->str = NULL;
	stat_info->len = 0;

	/* get refersh statisitcs */
	(void) getldap_get_refresh_stat(&foutstr);
	if (foutstr == NULL)
		return;

	/* get server statisitcs */
	(void) getldap_serverInfo_op(INFO_OP_GETSTAT, NULL, &soutstr);
	if (soutstr == NULL) {
		free(foutstr);
		return;
	}
	/* get cache data statisitcs */
	(void) getldap_cache_op(CACHE_OP_GETSTAT, NULL, NULL, &coutstr);
	if (coutstr == NULL) {
		free(foutstr);
		free(soutstr);
		return;
	}

	infoSize = strlen(foutstr) + strlen(soutstr) + strlen(coutstr) + 3;
	stat_info->str = calloc(infoSize, sizeof (char));
	if (stat_info->str != NULL) {
		(void) strncpy(stat_info->str,
		    foutstr,
		    strlen(foutstr) + 1);
		(void) strncat(stat_info->str,
		    soutstr,
		    strlen(soutstr) + 1);
		(void) strncat(stat_info->str,
		    coutstr,
		    strlen(coutstr) + 1);
		stat_info->len = infoSize;
	}

	free(foutstr);
	free(soutstr);
	free(coutstr);
}

static int
checkupdate(int sighup)
{
	int	value;

	(void) rw_wrlock(&ldap_lock);
	value = sighup;
	(void) rw_unlock(&ldap_lock);

	return (value == TRUE);
}


static int
update_from_profile(int *change_status)
{
	ns_ldap_result_t *result = NULL;
	char		searchfilter[BUFSIZ];
	ns_ldap_error_t	*error;
	int		rc;
	void		**paramVal = NULL;
	ns_config_t	*ptr = NULL;
	char		*profile = NULL;
	char		errstr[MAXERROR];

	if (current_admin.debug_level >= DBG_ALL) {
		logit("update_from_profile....\n");
	}
	do {
		(void) rw_wrlock(&ldap_lock);
		sighup_update = FALSE;
		(void) rw_unlock(&ldap_lock);

		if ((rc = __ns_ldap_getParam(NS_LDAP_PROFILE_P,
		    &paramVal, &error)) != NS_LDAP_SUCCESS) {
			if (error != NULL && error->message != NULL)
				logit("Error: Unable to  profile name: %s\n",
				    error->message);
			else {
				char *tmp;

				__ns_ldap_err2str(rc, &tmp);
				logit("Error: Unable to  profile name: %s\n",
				    tmp);
			}
			(void) __ns_ldap_freeParam(&paramVal);
			(void) __ns_ldap_freeError(&error);
			return (-1);
		}

		if (paramVal && *paramVal)
			profile = strdup((char *)*paramVal);
		(void) __ns_ldap_freeParam(&paramVal);

		if (profile == NULL) {
			return (-1);
		}

		(void) snprintf(searchfilter, BUFSIZ, _PROFILE_FILTER,
		    _PROFILE1_OBJECTCLASS, _PROFILE2_OBJECTCLASS, profile);

		if ((rc = __ns_ldap_list(_PROFILE_CONTAINER,
		    (const char *)searchfilter, NULL,
		    NULL, NULL, 0,
		    &result, &error, NULL, NULL)) != NS_LDAP_SUCCESS) {

			/*
			 * Is profile name the DEFAULTCONFIGNAME?
			 * syslog Warning, otherwise syslog error.
			 */
			if (strcmp(profile, DEFAULTCONFIGNAME) == 0) {
				syslog(LOG_WARNING,
				    "Ignoring attempt to refresh nonexistent "
				    "default profile: %s.\n",
				    profile);
				logit("Ignoring attempt to refresh nonexistent "
				    "default profile: %s.\n",
				    profile);
			} else if ((error != NULL) &&
			    (error->message != NULL)) {
				syslog(LOG_ERR,
				    "Error: Unable to refresh profile:%s:"
				    " %s\n", profile, error->message);
				logit("Error: Unable to refresh profile:"
				    "%s:%s\n", profile, error->message);
			} else {
				syslog(LOG_ERR, "Error: Unable to refresh "
				    "from profile:%s. (error=%d)\n",
				    profile, rc);
				logit("Error: Unable to refresh from profile "
				    "%s (error=%d)\n", profile, rc);
			}

			(void) __ns_ldap_freeError(&error);
			(void) __ns_ldap_freeResult(&result);
			free(profile);
			return (-1);
		}
		free(profile);


	} while (checkupdate(sighup_update) == TRUE);

	(void) rw_wrlock(&ldap_lock);

	ptr = __ns_ldap_make_config(result);
	(void) __ns_ldap_freeResult(&result);

	if (ptr == NULL) {
		logit("Error: __ns_ldap_make_config failed.\n");
		(void) rw_unlock(&ldap_lock);
		return (-1);
	}

	/*
	 * cross check the config parameters
	 */
	if (__s_api_crosscheck(ptr, errstr, B_TRUE) == NS_SUCCESS) {
		/*
		 * reset the local profile TTL
		 */
		if (ptr->paramList[NS_LDAP_CACHETTL_P].ns_pc)
			current_admin.ldap_stat.ldap_ttl =
			    atol(ptr->paramList[NS_LDAP_CACHETTL_P].ns_pc);

		if (current_admin.debug_level >= DBG_PROFILE_REFRESH) {
			logit("update_from_profile: reset profile TTL to %d"
			    "  seconds\n",
			    current_admin.ldap_stat.ldap_ttl);
			logit("update_from_profile: expire time %ld "
			    "seconds\n",
			    ptr->paramList[NS_LDAP_EXP_P].ns_tm);
		}

		/* set ptr as current_config if the config is changed */
		chg_test_config_change(ptr, change_status);
		rc = 0;
	} else {
		__s_api_destroy_config(ptr);
		logit("Error: downloaded profile failed to pass "
		    "crosscheck (%s).\n", errstr);
		syslog(LOG_ERR, "ldap_cachemgr: %s", errstr);
		rc = -1;
	}
	(void) rw_unlock(&ldap_lock);

	return (rc);
}

int
getldap_init()
{
	ns_ldap_error_t	*error;
	struct timeval	tp;
	ldap_get_chg_cookie_t	cookie;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_init()...\n");
	}

	(void) __ns_ldap_setServer(TRUE);

	(void) rw_wrlock(&ldap_lock);
	if ((error = __ns_ldap_LoadConfiguration()) != NULL) {
		logit("Error: Unable to read '%s': %s\n",
		    NSCONFIGFILE, error->message);
		(void) fprintf(stderr,
		    gettext("\nError: Unable to read '%s': %s\n"),
		    NSCONFIGFILE, error->message);
		__ns_ldap_freeError(&error);
		(void) rw_unlock(&ldap_lock);
		return (-1);
	}
	(void) rw_unlock(&ldap_lock);

	if (gettimeofday(&tp, NULL) == 0) {
		/* statistics: previous refresh time */
		prev_refresh_time = tp.tv_sec;
	}

	/* initialize the data cache */
	(void) getldap_cache_op(CACHE_OP_CREATE,
	    0, NULL, NULL);

	cookie.mgr_pid = getpid();
	cookie.seq_num = 0;
	chg_config_cookie_set(&cookie);
	return (0);
}

static void
perform_update(void)
{
	ns_ldap_error_t	*error = NULL;
	struct timeval	tp;
	char		buf[20];
	int		rc, rc1;
	int		changed = 0;
	void		**paramVal = NULL;
	ns_ldap_self_gssapi_config_t	config;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("perform_update()...\n");
	}

	(void) __ns_ldap_setServer(TRUE);

	if (gettimeofday(&tp, NULL) != 0)
		return;

	rc = __ns_ldap_getParam(NS_LDAP_CACHETTL_P, &paramVal, &error);

	if (rc == NS_LDAP_SUCCESS && paramVal != NULL) {
		current_admin.ldap_stat.ldap_ttl = atol((char *)*paramVal);
	}

	if (error != NULL)
		(void) __ns_ldap_freeError(&error);

	if (paramVal != NULL)
		(void) __ns_ldap_freeParam(&paramVal);

	if (current_admin.debug_level >= DBG_PROFILE_REFRESH) {
		logit("perform_update: current profile TTL is %d seconds\n",
		    current_admin.ldap_stat.ldap_ttl);
	}

	if (current_admin.ldap_stat.ldap_ttl > 0) {
		/*
		 * set the profile TTL parameter, just
		 * in case that the downloading of
		 * the profile from server would fail
		 */

		/*
		 * NS_LDAP_EXP_P is a no op for __ns_ldap_setParam
		 * It depends on NS_LDAP_CACHETTL_P to set it's value
		 * Set NS_LDAP_CACHETTL_P here so NS_LDAP_EXP_P value
		 * can be set.
		 * NS_LDAP_CACHETTL_P value can be reset after the profile is
		 * downloaded from the server, so is NS_LDAP_EXP_P.
		 */
		buf[19] = '\0'; /* null terminated the buffer */
		if (__ns_ldap_setParam(NS_LDAP_CACHETTL_P,
		    lltostr((long long)current_admin.ldap_stat.ldap_ttl,
		    &buf[19]),
		    &error) != NS_LDAP_SUCCESS) {
			logit("Error: __ns_ldap_setParam failed, status: %d "
			    "message: %s\n", error->status, error->message);
			(void)  __ns_ldap_freeError(&error);
			return;
		}

		(void) rw_wrlock(&ldap_lock);
		sighup_update = FALSE;
		(void) rw_unlock(&ldap_lock);

		do {
			rc = update_from_profile(&changed);
			if (rc != 0) {
				logit("Error: Unable to update from profile\n");
			}
		} while (checkupdate(sighup_update) == TRUE);
	} else {
		rc = 0;
	}

	/*
	 * recreate the server info list
	 */
	if (rc == 0) {
		(void) getldap_serverInfo_op(INFO_OP_CREATE, NULL, NULL);

		/* flush the data cache */
		(void) getldap_cache_op(CACHE_OP_DELETE,
		    0, NULL, NULL);

		/* statistics: previous refresh time */
		prev_refresh_time = tp.tv_sec;
	}
	rc1 = __ns_ldap_self_gssapi_config(&config);
	if (rc1 == NS_LDAP_SUCCESS) {
		if (config != NS_LDAP_SELF_GSSAPI_CONFIG_NONE) {
			rc1 = __ns_ldap_check_all_preq(0, 0, 0, config, &error);
			(void)  __ns_ldap_freeError(&error);
			if (rc1 != NS_LDAP_SUCCESS) {
				logit("Error: Check on self credential "
				    "prerquesites failed: %d\n",
				    rc1);
				exit(rc1);
			}
		}
	} else {
		logit("Error: Failed to get self credential configuration %d\n",
		    rc1);
			exit(rc1);
	}

	if (!changed)
		return;

	(void) rw_rdlock(&ldap_lock);
	if (((error = __ns_ldap_DumpConfiguration(NSCONFIGREFRESH)) != NULL) ||
	    ((error = __ns_ldap_DumpConfiguration(NSCREDREFRESH)) != NULL)) {
		logit("Error: __ns_ldap_DumpConfiguration failed, "
		    "status: %d message: %s\n", error->status, error->message);
		__ns_ldap_freeError(&error);
		(void) rw_unlock(&ldap_lock);
		return;
	}
	if (rename(NSCONFIGREFRESH, NSCONFIGFILE) != 0) {
		logit("Error: unlink failed - errno: %s\n", strerror(errno));
		syslog(LOG_ERR, "Unable to refresh profile, LDAP configuration"
		    "files not written");
		(void) rw_unlock(&ldap_lock);
		return;
	}
	if (rename(NSCREDREFRESH, NSCREDFILE) != 0) {
		/*
		 * We probably have inconsistent configuration at this point.
		 * If we were to create a backup file and rename it here, that
		 * operation might also fail. Consequently there is no safe way
		 * to roll back.
		 */
		logit("Error: unlink failed - errno: %s\n", strerror(errno));
		syslog(LOG_ERR, "Unable to refresh profile consistently, "
		    "LDAP configuration files inconsistent");
		(void) rw_unlock(&ldap_lock);
		return;
	}

	(void) rw_unlock(&ldap_lock);
}

void
getldap_refresh()
{
	struct timespec	timeout;
	int		sleeptime;
	struct timeval	tp;
	long		expire = 0;
	void		**paramVal = NULL;
	ns_ldap_error_t	*errorp;
	int		always = 1, err;
	int		first_time = 1;
	int		sig_done = 0;
	int		dbg_level;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_refresh()...\n");
	}

	/*
	 * wait for an available server
	 */
	while (sig_done == 0) {
		(void) mutex_lock(&sig_mutex);
		sig_done = signal_done;
		(void) mutex_unlock(&sig_mutex);
	}

	(void) __ns_ldap_setServer(TRUE);
	while (always) {
		dbg_level = current_admin.debug_level;
		(void) rw_rdlock(&ldap_lock);
		sleeptime = current_admin.ldap_stat.ldap_ttl;
		if (dbg_level >= DBG_PROFILE_REFRESH) {
			logit("getldap_refresh: current profile TTL is %d "
			"seconds\n", current_admin.ldap_stat.ldap_ttl);
		}
		if (gettimeofday(&tp, NULL) == 0) {
			if ((__ns_ldap_getParam(NS_LDAP_EXP_P,
			    &paramVal, &errorp) == NS_LDAP_SUCCESS) &&
			    paramVal != NULL &&
			    (char *)*paramVal != NULL) {
				errno = 0;
				expire = atol((char *)*paramVal);
				(void) __ns_ldap_freeParam(&paramVal);
				if (errno == 0) {
					if (expire == 0) {
						first_time = 0;
						(void) rw_unlock(&ldap_lock);
						(void) cond_init(&cond,
						    NULL, NULL);
						(void) mutex_lock(&sighuplock);
						timeout.tv_sec =
						    CACHESLEEPTIME;
						timeout.tv_nsec = 0;
						if (dbg_level >=
						    DBG_PROFILE_REFRESH) {
							logit("getldap_refresh:"
							    "(1)about to sleep"
							    " for %d seconds\n",
							    CACHESLEEPTIME);
						}
						err = cond_reltimedwait(&cond,
						    &sighuplock, &timeout);
						(void) cond_destroy(&cond);
						(void) mutex_unlock(
						    &sighuplock);
						/*
						 * if woke up by
						 * getldap_revalidate(),
						 * do update right away
						 */
						if (err == ETIME)
							continue;
						else {
							/*
							 * if load
							 * configuration failed
							 * don't do update
							 */
							if (load_config())
								perform_update
								    ();
							continue;
						}
					}
					sleeptime = expire - tp.tv_sec;
					if (dbg_level >= DBG_PROFILE_REFRESH) {
						logit("getldap_refresh: expire "
						    "time = %ld\n", expire);
					}

				}
			}
		}

		(void) rw_unlock(&ldap_lock);

		/*
		 * if this is the first time downloading
		 * the profile or expire time already passed,
		 * do not wait, do update
		 */
		if (first_time == 0 && sleeptime > 0) {
			if (dbg_level >= DBG_PROFILE_REFRESH) {
				logit("getldap_refresh: (2)about to sleep "
				"for %d seconds\n", sleeptime);
			}
			(void) cond_init(&cond, NULL, NULL);
			(void) mutex_lock(&sighuplock);
			timeout.tv_sec = sleeptime;
			timeout.tv_nsec = 0;
			err = cond_reltimedwait(&cond,
			    &sighuplock, &timeout);
			(void) cond_destroy(&cond);
			(void) mutex_unlock(&sighuplock);
		}
		/*
		 * if load concfiguration failed
		 * don't do update
		 */
		if (load_config())
			perform_update();
		first_time = 0;
	}
}

void
getldap_revalidate()
{
	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_revalidate()...\n");
	}
	/* block signal SIGHUP */
	(void) sighold(SIGHUP);

	/* now awake the sleeping refresh thread */
	(void) cond_signal(&cond);

	/* release signal SIGHUP */
	(void) sigrelse(SIGHUP);

}

void
getldap_admincred(LineBuf *config_info, ldap_call_t *in)
{
	ns_ldap_error_t	*error;
	ldap_config_out_t *cout;
	ucred_t *uc = NULL;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_admincred()...\n");
	}
	/* check privileges */
	if (is_root_or_all_privs("GETADMINCRED", &uc) == 0) {
		logit("admin credential requested by a non-root and no ALL "
		    "privilege user not allowed");
		config_info->str = NULL;
		config_info->len = 0;
	} else {
		(void) rw_rdlock(&ldap_lock);
		if ((error = __ns_ldap_LoadDoorInfo(config_info,
		    in->ldap_u.domainname, NULL, 1)) != NULL) {
			if (error != NULL && error->message != NULL)
				logit("Error: ldap_lookup: %s\n",
				    error->message);
			(void) __ns_ldap_freeError(&error);

			config_info->str = NULL;
			config_info->len = 0;
		}
		/* set change cookie */
		cout = (ldap_config_out_t *)config_info->str;
		if (cout)
			cout->cookie = chg_config_cookie_get();
		(void) rw_unlock(&ldap_lock);
	}
}

void
getldap_lookup(LineBuf *config_info, ldap_call_t *in)
{
	ns_ldap_error_t	*error;
	ldap_config_out_t *cout;

	if (current_admin.debug_level >= DBG_ALL) {
		logit("getldap_lookup()...\n");
	}
	(void) rw_rdlock(&ldap_lock);
	if ((error = __ns_ldap_LoadDoorInfo(config_info,
	    in->ldap_u.domainname, NULL, 0)) != NULL) {
		if (error != NULL && error->message != NULL)
			logit("Error: ldap_lookup: %s\n", error->message);
		(void) __ns_ldap_freeError(&error);

		config_info->str = NULL;
		config_info->len = 0;
	}
	/* set change cookie */
	cout = (ldap_config_out_t *)config_info->str;
	if (cout)
		cout->cookie = chg_config_cookie_get();
	(void) rw_unlock(&ldap_lock);
}
/*
 * It creates the header and data stream to be door returned and notify
 * chg_get_statusChange() threads.
 * This is called after all getldap_get_rootDSE() threads are joined.
 */
void
test_server_change(server_info_t *head)
{
	server_info_t *info;
	int	len = 0, num = 0, ds_len = 0, new_len = 0, tlen = 0;
	char	*tmp_buf = NULL, *ptr = NULL, *status = NULL;
	ldap_get_change_out_t *cout;

	ds_len = strlen(DOORLINESEP);

	for (info = head; info; info = info->next) {
		(void) mutex_lock(&info->mutex[0]);
		if (info->sinfo[0].change != 0) {
			/* "9.9.9.9|NS_SERVER_CHANGE_UP|" */
			len += 2 * ds_len + strlen(info->sinfo[0].addr) +
			    strlen(NS_SERVER_CHANGE_UP);
			num++;
		}
		(void) mutex_unlock(&info->mutex[0]);
	}

	if (len == 0)
		return;

	len++; /* '\0' */

	tlen = sizeof (ldap_get_change_out_t) - sizeof (int) + len;
	if ((tmp_buf = malloc(tlen)) == NULL)
		return;

	cout = (ldap_get_change_out_t *)tmp_buf;
	cout->type = NS_STATUS_CHANGE_TYPE_SERVER;
	/* cout->cookie is set by chg_notify_statusChange */
	cout->server_count = num;
	cout->data_size = len;

	/* Create IP|UP or DOWN|IP|UP or DOWN| ... */
	ptr = cout->data;
	new_len = len;
	for (info = head; info; info = info->next) {
		(void) mutex_lock(&info->mutex[0]);
		if (info->sinfo[0].change == 0) {
			(void) mutex_unlock(&info->mutex[0]);
			continue;
		}

		if (info->sinfo[0].change == NS_SERVER_UP)
			status = NS_SERVER_CHANGE_UP;
		else if (info->sinfo[0].change == NS_SERVER_DOWN)
			status = NS_SERVER_CHANGE_DOWN;
		else {
			syslog(LOG_WARNING, gettext("Bad change value %d"),
			    info->sinfo[0].change);
			(void) mutex_unlock(&info->mutex[0]);
			free(tmp_buf);
			return;
		}

		if ((snprintf(ptr, new_len, "%s%s%s%s",
		    info->sinfo[0].addr, DOORLINESEP,
		    status, DOORLINESEP)) >= new_len) {
			(void) mutex_unlock(&info->mutex[0]);
			break;
		}
		new_len -= strlen(ptr);
		ptr += strlen(ptr);

		(void) mutex_unlock(&info->mutex[0]);
	}
	(void) chg_notify_statusChange(tmp_buf);
}
/*
 * It creates the header and data stream to be door returned and notify
 * chg_get_statusChange() threads.
 * This is called in removing server case.
 */
static void
create_buf_and_notify(char *input, ns_server_status_t st)
{
	rm_svr_t *rms = (rm_svr_t *)input;
	char	*tmp_buf, *ptr, *status;
	int	len, tlen;
	ldap_get_change_out_t *cout;

	/* IP|UP or DOWN| */
	len = 2 * strlen(DOORLINESEP) + strlen(rms->addr) +
	    strlen(NS_SERVER_CHANGE_UP) + 1;

	tlen = sizeof (ldap_get_change_out_t) - sizeof (int) + len;

	if ((tmp_buf = malloc(tlen)) == NULL)
		return;

	cout = (ldap_get_change_out_t *)tmp_buf;
	cout->type = NS_STATUS_CHANGE_TYPE_SERVER;
	/* cout->cookie is set by chg_notify_statusChange */
	cout->server_count = 1;
	cout->data_size = len;

	/* Create IP|DOWN| */
	ptr = cout->data;
	if (st == NS_SERVER_UP)
		status = NS_SERVER_CHANGE_UP;
	else if (st == NS_SERVER_DOWN)
		status = NS_SERVER_CHANGE_DOWN;

	(void) snprintf(ptr, len, "%s%s%s%s",
	    rms->addr, DOORLINESEP, status, DOORLINESEP);

	(void) chg_notify_statusChange(tmp_buf);

}

/*
 * Return: 0 server is down, 1 server is up
 */
static int
contact_server(char *addr)
{
	char		*rootDSE = NULL;
	ns_ldap_error_t	*error = NULL;
	int		rc;

	if (__ns_ldap_getRootDSE(addr, &rootDSE, &error,
	    SA_ALLOW_FALLBACK) != NS_LDAP_SUCCESS) {
		if (current_admin.debug_level >= DBG_ALL)
			logit("get rootDSE %s failed. %s", addr,
			    error->message ? error->message : "");
		rc = 0;
	} else
		rc = 1;

	if (rootDSE)
		free(rootDSE);
	if (error)
		(void) __ns_ldap_freeError(&error);

	return (rc);
}

/*
 * The thread is spawned to do contact_server() so it won't be blocking
 * getldap_serverInfo_op(INFO_OP_GETSERVER, ...) case.
 * After contact_server() is done, it calls
 * getldap_serverInfo_op(INFO_OP_REMOVESERVER, ...) to return to the remaining
 * program flow. It's meant to maintain the original program flow yet be
 * non-blocking when it's contacting server.
 */
static void *
remove_server_thread(void *arg)
{
	char *addr = (char *)arg, *out = NULL;
	int up;
	rm_svr_t rms;

	up = contact_server(addr);

	rms.addr = addr;
	rms.up = up;

	(void) getldap_serverInfo_op(INFO_OP_REMOVESERVER, (char *)&rms, &out);

	free(addr);

	thr_exit(NULL);
	return (NULL);
}
/*
 * addr is allocated and is freed by remove_server_thread
 * It starts a thread to contact server and remove server to avoid long wait
 * or recursion.
 */
static void
remove_server(char *addr)
{
	if (thr_create(NULL, 0, remove_server_thread,
	    (void *)addr, THR_BOUND|THR_DETACHED, NULL) != 0) {
		free(addr);
		syslog(LOG_ERR, "thr_create failed for remove_server_thread");
	}
}
/*
 * Compare the server_status and mark it up or down accordingly.
 * This is called in removing server case.
 */
static ns_server_status_t
set_server_status(char *input, server_info_t *head)
{
	rm_svr_t *rms = (rm_svr_t *)input;
	ns_server_status_t changed = 0;
	server_info_t *info;

	for (info = head; info != NULL; info = info->next) {
		(void) mutex_lock(&info->mutex[0]);
		if (strcmp(info->sinfo[0].addr, rms->addr) == 0) {
			if (info->sinfo[0].server_status == INFO_SERVER_UP &&
			    rms->up == FALSE) {
				info->sinfo[0].prev_server_status =
				    info->sinfo[0].server_status;
				info->sinfo[0].server_status =
				    INFO_SERVER_ERROR;
				info->sinfo[0].change = NS_SERVER_DOWN;
				changed = NS_SERVER_DOWN;

			} else if (info->sinfo[0].server_status ==
			    INFO_SERVER_ERROR && rms->up == TRUE) {
				/*
				 * It should be INFO_SERVER_UP, but check here
				 */
				info->sinfo[0].prev_server_status =
				    info->sinfo[0].server_status;
				info->sinfo[0].server_status =
				    INFO_SERVER_UP;
				info->sinfo[0].change = NS_SERVER_UP;
				changed = NS_SERVER_UP;
			}
			(void) mutex_unlock(&info->mutex[0]);
			break;
		}
		(void) mutex_unlock(&info->mutex[0]);
	}
	if (changed) {
		/* ldap_cachemgr -g option looks up [1] */
		(void) mutex_lock(&info->mutex[1]);
		info->sinfo[1].prev_server_status =
		    info->sinfo[1].server_status;
		if (changed == NS_SERVER_DOWN)
			info->sinfo[1].server_status = INFO_SERVER_ERROR;
		else if (changed == NS_SERVER_UP)
			info->sinfo[1].server_status = INFO_SERVER_UP;
		(void) mutex_unlock(&info->mutex[1]);
	}
	return (changed);
}
