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
 */

#ifndef	_NS_CACHE_DOOR_H
#define	_NS_CACHE_DOOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for client side of doors-based ldap caching
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <grp.h>
#include <pwd.h>


/*
 *	statistics & control structure
 */

typedef struct ldap_stat {
	int	ldap_numbercalls;	/* number of times called */
	int	ldap_ttl;		/* time to live for positive entries */
} ldap_stat_t;


/*
 * Structure used to transfer arrays of strings.
 * Buffer format:
 *   count
 *   array of offsets from start of buffer
 *   array of characters of strings
 *        charp = buf + ldap_offsets[n];
 */

typedef struct ldap_strlist {
	int	ldap_count;		/* number of strings */
	int	ldap_offsets[1];	/* array of offsets */
} ldap_strlist_t;

/*
 * Structure used to request/inform config and server status changes.
 */

typedef struct ldap_get_chg_cookie {
	pid_t		mgr_pid;  /* current process id of ldap_cachemgr */
	uint32_t	seq_num;  /* current config sequence number */
} ldap_get_chg_cookie_t;

typedef struct ldap_get_change {
	uint32_t		op;	/* start or stop */
	ldap_get_chg_cookie_t	cookie;	/* get status change cookie */
} ldap_get_change_t;

typedef struct ldap_get_change_out {
	uint32_t	type;		 /* config change or server change */
	ldap_get_chg_cookie_t cookie;    /* get status change cookie */
	uint32_t	server_count;	 /* if server change: num of servers */
	uint32_t	data_size;	 /* if server change: size of data */
	char 		data[sizeof (int)]; /* real size is data_size */
} ldap_get_change_out_t;

typedef struct ldap_config_out {
	ldap_get_chg_cookie_t cookie;    /* get status change cookie */
	uint32_t	data_size;	 /* length of the config string */
	char 		config_str[sizeof (int)]; /* real size is data_size */
} ldap_config_out_t;

/*
 * structure returned by server for all calls
 */

#define	BUFFERSIZE	8192
#define	OFFSET		36

typedef struct {
	int 		ldap_bufferbytesused;
	int 		ldap_return_code;
	int 		ldap_errno;

	union {
		char		config[BUFFERSIZE - OFFSET]; /* V1 Config */
		ldap_stat_t 	stats;
		char 		buff[4];
		char 		ber[4];		/* BER/DER encoded packet */
		ldap_strlist_t	strlist;
		ldap_config_out_t config_str;
		ldap_get_change_out_t changes;
	} ldap_u;

} ldap_return_t;

/*
 * calls look like this
 */

typedef struct {
	int ldap_callnumber;
	union {
		uid_t uid;
		gid_t gid;
		char domainname[sizeof (int)]; 	/* size is indeterminate */
		struct {
			int  a_type;
			int  a_length;
			char a_data[sizeof (int)];
		} addr;
		char servername[sizeof (int)]; 	/* Format: server:port */
		ldap_strlist_t	strlist;
		ldap_get_change_t get_change;
	} ldap_u;
} ldap_call_t;
/*
 * how the client views the call process
 */

typedef union {
	ldap_call_t 		ldap_call;
	ldap_return_t 		ldap_ret;
	char 			ldap_buff[sizeof (int)];
} ldap_data_t;

/* Version 1 Cache Manager calls */
	/* Cache manager ping */
#define	NULLCALL	0
	/* NativeLDAP I Get Config */
#define	GETLDAPCONFIG	1
#define	GETLDAPCONFIGV1	1

/*
 * administrative calls
 */

#define	KILLSERVER	7
#define	GETADMIN	8
#define	SETADMIN	9

/*
 * debug levels
 */

#define	DBG_OFF		0
#define	DBG_CANT_FIND	1
#define	DBG_NETLOOKUPS	2
#define	DBG_SERVER_LIST_REFRESH	3	/* debug server list refresh */
#define	DBG_PROFILE_REFRESH	4	/* debug profile TTL/refresh */
#define	DBG_ALL		6

/* Version 2 Cache Manager calls */
	/* NativeLDAP II Get Server and RootDSE Info */
#define	GETLDAPSERVER	21
	/* NativeLDAP II Get cached data */
#define	GETCACHE	22
	/* NativeLDAP II Set cached data */
#define	SETCACHE	23
	/* NativeLDAP II get cache data statistics */
#define	GETCACHESTAT	24
	/* Configuration change or server status change notification */
#define	GETSTATUSCHANGE	25

/*
 * GETLDAPSERVER request flags
 */

#define	NS_CACHE_NEW	"0"
#define	NS_CACHE_NORESP	"1"
#define	NS_CACHE_NEXT	"2"
#define	NS_CACHE_WRITE	"3"
#define	NS_CACHE_ADDR_HOSTNAME	"H"
#define	NS_CACHE_ADDR_IP	"I"

/*
 * GETSTATUSCHANGE operation: start or stop
 */
#define	NS_STATUS_CHANGE_OP_START	1
#define	NS_STATUS_CHANGE_OP_STOP	2

/*
 * GETSTATUSCHANGE change type: config or server
 */
#define	NS_STATUS_CHANGE_TYPE_CONFIG	1
#define	NS_STATUS_CHANGE_TYPE_SERVER	2

/*
 * Server status change
 */
#define	NS_SERVER_CHANGE_UP	"0"	/* mapped to NS_SERVER_UP */
#define	NS_SERVER_CHANGE_DOWN	"1"	/* mapped to NS_SERVER_DOWN */
/*
 * GETCACHE/SETCACHE data flags
 */
#define	NS_CACHE_DN2DOMAIN	"DM"

/*
 * Max size name we allow to be passed to avoid
 * buffer overflow problems
 */
#define	LDAPMAXNAMELEN	255

/*
 * defines for client-server interaction
 */

#define	LDAP_CACHE_DOOR_VERSION 1
#define	LDAP_CACHE_DOOR "/var/run/ldap_cache_door"
#define	LDAP_CACHE_DOOR_COOKIE ((void*)(0xdeadbeef^LDAP_CACHE_DOOR_VERSION))
#define	UPDATE_DOOR_COOKIE ((void*)(0xdeadcafe)

#define	NS_CACHE_SUCCESS	0
#define	NS_CACHE_NOTFOUND  	-1
#define	NS_CACHE_CREDERROR 	-2
#define	NS_CACHE_SERVERERROR 	-3
#define	NS_CACHE_NOSERVER 	-4

int
__ns_ldap_trydoorcall(ldap_data_t **dptr, int *ndata, int *adata);
int
__ns_ldap_trydoorcall_getfd();
int
__ns_ldap_trydoorcall_send(ldap_data_t **dptr, int *ndata, int *adata);
void
__ns_ldap_doorfd_close();

#ifdef	__cplusplus
}
#endif


#endif	/* _NS_CACHE_DOOR_H */
