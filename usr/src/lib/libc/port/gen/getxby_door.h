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
 * Copyright 1994, 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GETXBY_DOOR_H
#define	_GETXBY_DOOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for client side of doors-based name service caching
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
#include <exec_attr.h>
#include <prof_attr.h>
#include <user_attr.h>

#ifdef	_LP64

/* NB uid_t and gid_t are the same size in 32 & 64 bit mode */

typedef	unsigned int	uptr32_t;	/* 32bit pointer type */

typedef	struct	passwd32 {
	uptr32_t	pw_name;
	uptr32_t	pw_passwd;
	uid_t		pw_uid;
	gid_t		pw_gid;
	uptr32_t	pw_age;
	uptr32_t	pw_comment;
	uptr32_t	pw_gecos;
	uptr32_t	pw_dir;
	uptr32_t	pw_shell;
} passwd32_t;

typedef	struct  group32 {
	uptr32_t	gr_name;
	uptr32_t	gr_passwd;
	gid_t   gr_gid;
	uptr32_t	gr_mem;
} group32_t;

/* NB int is the same size in 32 & 64 bit mode */

typedef	struct  hostent32 {
	uptr32_t	h_name;		/* official name of host */
	uptr32_t	h_aliases;	/* alias list */
	int		h_addrtype;	/* host address type */
	int		h_length;	/* length of address */
	uptr32_t	h_addr_list;	/* list of addresses from name server */
#define	h_addr	h_addr_list[0]  	/* address, for backward compatiblity */
} hostent32_t;

typedef struct execstr32_s {
	uptr32_t	name;
	uptr32_t	policy;
	uptr32_t	type;
	uptr32_t	res1;
	uptr32_t	res2;
	uptr32_t	id;
	uptr32_t	attr;
} execstr32_t;

typedef struct profstr32_s {
	uptr32_t	name;
	uptr32_t	res1;
	uptr32_t	res2;
	uptr32_t	desc;
	uptr32_t	attr;
} profstr32_t;

typedef struct userstr32_s {
	uptr32_t	name;
	uptr32_t	qualifier;
	uptr32_t	res1;
	uptr32_t	res2;
	uptr32_t	attr;
} userstr32_t;

#endif	/*	_LP64	*/

/*
 *	statistics & control structure
 */

typedef struct nsc_stat {
	int 	nsc_pos_cache_hits;	/* hits on real entries */
	int	nsc_neg_cache_hits;	/* hits on hegative entries */
	int	nsc_pos_cache_misses;	/* miss that results in real entry */
	int	nsc_neg_cache_misses;	/* miss that results in neg entry */
	int	nsc_entries;		/* count of cache entries */
	int	nsc_throttle_count;	/* count of load shedding */
	int	nsc_invalidate_count;	/* count for cache invalidation */
	int	nsc_suggestedsize;	/* suggested size */
	int	nsc_enabled;		/* if 0, always return NOSERVER */
	int	nsc_invalidate;		/* command to invalidate cache */
	int	nsc_pos_ttl;		/* time to live for positive entries */
	int	nsc_neg_ttl;		/* time to live for negative entries */
	short	nsc_keephot;		/* number of entries to keep hot */
	short	nsc_old_data_ok;	/* set if expired data is acceptable */
	short	nsc_check_files;	/* set if file time should be checked */
	short	nsc_secure_mode;	/* set if pw fields to be blanked for */
					/* those other than owners */
} nsc_stat_t;


/*
 * structure returned by server for all calls
 */

typedef struct {
	int 		nsc_bufferbytesused;
	int 		nsc_return_code;
	int 		nsc_errno;

	union {
/*
 * If we are 64bit mode explicitly use the 32 versions, otherwise we are in
 * 32bit mode and can use the original definitions. No need to worry about
 * padding since all the sizes are preserved
 */
#ifdef	_LP64
		passwd32_t 	pwd;
		group32_t  	grp;
		hostent32_t 	hst;
		execstr32_t	exec;
		profstr32_t	prof;
		userstr32_t	user;
#else
		struct passwd 	pwd;
		struct group  	grp;
		struct hostent 	hst;
		execstr_t	exec;
		profstr_t	prof;
		userstr_t	user;
#endif
		nsc_stat_t 	stats;
		char 		buff[4];
	} nsc_u;

} nsc_return_t;

/*
 * calls look like this
 */

typedef struct {
	int nsc_callnumber;
	union {
		uid_t uid;
		gid_t gid;
		char name[sizeof (int)]; 	/* size is indeterminate */
		struct {
			int  a_type;
			int  a_length;
			char a_data[sizeof (int)];
		} addr;
		struct {
			int af_family;
			int flags;
			char name[sizeof (int)]; /* size is indeterminate */
		} ipnode;
	} nsc_u;
} nsc_call_t;
/*
 * how the client views the call process
 */

typedef union {
	nsc_call_t 		nsc_call;
	nsc_return_t 		nsc_ret;
	char 			nsc_buff[sizeof (int)];
} nsc_data_t;

/*
 *  What each entry in the nameserver cache looks like.
 */

typedef struct {
	int		nsc_hits;	/* number of hits */
	int		nsc_status;	/* flag bits */
	time_t		nsc_timestamp;	/* last time entry validated */
	int 		nsc_refcount;	/* reference count 		*/
	nsc_return_t	nsc_data;	/* data returned to client	*/
} nsc_bucket_t;

typedef struct hash_entry {
	struct hash_entry *next_entry;
	struct hash_entry *right_entry;
	struct hash_entry *left_entry;
	char 	*key;
	char 	*data;
} hash_entry_t;

typedef struct hash {
	int 		size;
	hash_entry_t	**table;
	hash_entry_t	*start;
	enum hash_type {
		String_Key = 0, Integer_Key = 1
	} hash_type;
} hash_t;

typedef struct passwd_cache {
	hash_entry_t	passwd;
} passwd_cache_t;

typedef struct group_cache {
	hash_entry_t	group;
} group_cache_t;

typedef struct host_cache {
	hash_entry_t	host;
} host_cache_t;

/*
 *	structure to handle waiting for pending name service requests
 */

typedef struct waiter {
	cond_t		w_waitcv;
	char		**w_key;
	struct waiter	*w_next, *w_prev;
} waiter_t;

/*
 * OR'D in by server to call self for updates
 */

#define	UPDATEBIT	(1<<30)
#define	MASKUPDATEBIT(a) ((~UPDATEBIT)&(a))

#define	NULLCALL	0
#define	GETPWUID 	1
#define	GETPWNAM	2
#define	GETGRNAM	3
#define	GETGRGID	4
#define	GETHOSTBYNAME	5
#define	GETHOSTBYADDR	6
#define	GETIPNODEBYNAME	10
#define	GETIPNODEBYADDR	11
#define	GETEXECID	12	/* for exec_attr */
#define	GETPROFNAM	13	/* for prof_attr */
#define	GETUSERNAM	14	/* for user_attr */

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
#define	DBG_CANT_FIND	2
#define	DBG_NETLOOKUPS	4
#define	DBG_ALL		6

/*
 * Max size name we allow to be passed to avoid
 * buffer overflow problems
 */
#define	NSCDMAXNAMELEN	255

/*
 * flag bits
 */

#define	ST_UPDATE_PENDING	1


/*
 * defines for client-server interaction
 */

#define	NAME_SERVICE_DOOR_VERSION 1
#define	NAME_SERVICE_DOOR "/var/run/name_service_door"
#define	NAME_SERVICE_DOOR_COOKIE ((void*)(0xdeadbeef^NAME_SERVICE_DOOR_VERSION))
#define	UPDATE_DOOR_COOKIE ((void*)(0xdeadcafe)

#define	SUCCESS		0
#define	NOTFOUND  	-1
#define	CREDERROR 	-2
#define	SERVERERROR 	-3
#define	NOSERVER 	-4

int
_nsc_trydoorcall(nsc_data_t **dptr, int *ndata, int *adata);

struct passwd *
_uncached_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
	int buflen);

struct passwd *
_uncached_getpwnam_r(const char *name, struct passwd *result, char *buffer,
	int buflen);

struct group *
_uncached_getgrnam_r(const char *name, struct group *result, char *buffer,
    int buflen);

struct group *
_uncached_getgrgid_r(gid_t gid, struct group *result, char *buffer, int buflen);


#ifdef	__cplusplus
}
#endif


#endif	/* _GETXBY_DOOR_H */
