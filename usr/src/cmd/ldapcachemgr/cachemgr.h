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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CACHEMGR_H
#define	_CACHEMGR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <thread.h>
#include <synch.h>
#include <unistd.h>
#include <procfs.h>
#include "ns_sldap.h"
#include "ns_internal.h"
#include "ns_cache_door.h"
#include "cachemgr_door.h"

#define	LOGFILE		"/var/ldap/cachemgr.log"
#define	KILLCACHEMGR	"/var/lib/ldap/ldap_cachemgr -K"
#define	MAXBITSIZE	30
#define	MAXDEBUG	DBG_ALL
#define	DEFAULTTTL	3600		/* 1 hour */

typedef	union {
	ldap_data_t	data;
	char		space[BUFFERSIZE];
} dataunion;

/*
 * In ldap_cachemgr, it return -99 for some case, start with -100 here
 */
typedef enum chg_error {
	CHG_SUCCESS  = 0,
	CHG_NO_MEMORY = -100,
	CHG_INVALID_PARAM = -101,
	CHG_NOT_FOUND_IN_WAITING_LIST = -102,
	CHG_EXCEED_MAX_THREADS = -103,
	CHG_NSCD_REPEATED_CALL = -104
} chg_error_t;

typedef struct waiting_list {
	pid_t			pid;		/* pid of the door client */
	thread_t		tid;		/* thread id of the server */
						/* thread */
	int			cleanup;	/* 1: the thread will be */
						/* cleaned up */
	struct waiting_list	*prev;		/* previous node in the */
						/* linked list */
	struct waiting_list	*next;		/* next node in the linked */
						/* list */
} waiting_list_t;

/*
 * This structure contains the buffer for the chang data and a wating list to
 * regester all the threads that handle GETSTATUSCHANGE START call and are
 * waiting for the change notification.
 * The notification threads save the data in the buffer then send broadcast
 * to wake up the GETSTATUSCHANGE START threads to copy data to the stack and
 * door_return().
 */
typedef struct chg_info {
	mutex_t		chg_lock;	/* mutex for this data structure */
	cond_t		chg_cv;		/* cond var for synchronization */
	int		chg_wakeup;	/* flag used with chg_cv for */
					/* synchronization */
	waiting_list_t	*chg_w_first;	/* the head of the linked list */
	waiting_list_t	*chg_w_last;	/* the tail of the linked list */
	char		*chg_data;	/* the buffer for the change data */
	int		chg_data_size;	/* the size of the change data */
} chg_info_t;

extern char *getcacheopt(char *s);
extern void logit(char *format, ...);
extern int load_admin_defaults(admin_t *ptr, int will_become_server);
extern int getldap_init(void);
extern void getldap_revalidate(int);
extern int getldap_uidkeepalive(int keep, int interval);
extern int getldap_invalidate(void);
extern void getldap_lookup(LineBuf *config_info, ldap_call_t *in);
extern void getldap_admincred(LineBuf *config_info, ldap_call_t *in);
extern void getldap_refresh(void);
extern int cachemgr_set_dl(admin_t *ptr, int value);
extern int cachemgr_set_ttl(ldap_stat_t *cache, char *name, int value);
extern int get_clearance(int callnumber);
extern int release_clearance(int callnumber);
#ifdef SLP
extern void discover();
#endif /* SLP */
extern void getldap_serverInfo_refresh(void);
extern void getldap_getserver(LineBuf *config_info, ldap_call_t *in);
extern void getldap_get_cacheData(LineBuf *config_info, ldap_call_t *in);
extern int getldap_set_cacheData(ldap_call_t *in);
extern void getldap_get_cacheStat(LineBuf *stat_info);
extern int is_called_from_nscd(pid_t pid); /* in cachemgr.c */
extern int chg_is_called_from_nscd_or_peruser_nscd(char *dc_str, pid_t *pidp);
extern void *chg_cleanup_waiting_threads(void *arg);
extern int chg_get_statusChange(LineBuf *config_info, ldap_call_t *in,
	pid_t nscd_pid);
extern int chg_notify_statusChange(char *str);
extern void chg_test_config_change(ns_config_t *new, int *change_status);
extern void chg_config_cookie_set(ldap_get_chg_cookie_t *cookie);
extern ldap_get_chg_cookie_t chg_config_cookie_get(void);
#ifdef __cplusplus
}
#endif

#endif /* _CACHEMGR_H */
