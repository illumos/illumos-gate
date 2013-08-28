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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#ifndef	_SM_STATD_H
#define	_SM_STATD_H

#ifdef __cplusplus
extern "C" {
#endif

/* Limit defines */
#define	SM_DIRECTORY_MODE 00755
#define	MAX_HASHSIZE 50
#define	SM_RPC_TIMEOUT	15
#define	PERCENT_MINJOIN 10
#define	MAX_FDS	256
#define	MAX_THR	25
#define	INC_DELAYTIME	30
#define	MAX_DELAYTIME	300
#define	SM_CLTS_TIMEOUT	15
/* max strlen of /statmon/state, /statmon/sm.bak, /statmon/sm */
#define	SM_MAXPATHLEN	17
/* Increment size for realloc of array host_name */
#define	HOST_NAME_INCR  5

/* supported address family names in /var/statmon symlinks */
#define	SM_ADDR_IPV4	"ipv4"
#define	SM_ADDR_IPV6	"ipv6"

/* Supported for readdir_r() */
#define	MAXDIRENT	(sizeof (struct dirent) +  _POSIX_PATH_MAX + 1)

/* Structure entry for monitor table (mon_table) */
struct mon_entry {
	mon id;				/* mon information: mon_name, my_id */
	struct mon_entry *prev;		/* Prev ptr to prev entry in hash */
	struct mon_entry *nxt;		/* Next ptr to next entry in hash */
};
typedef struct mon_entry mon_entry;

/* Structure entry for record (rec_table) and recovery (recov_q) tables */
struct name_entry {
	char *name;			/* name of host */
	int count;			/* count of entries */
	struct name_entry *prev;	/* Prev ptr to prev entry in hash */
	struct name_entry *nxt;		/* Next ptr to next entry in hash */
};
typedef struct name_entry name_entry;

/* Structure for passing arguments into thread send_notice */
typedef struct moninfo {
	mon id;				/* Monitor information */
	int state;			/* Current state */
} moninfo_t;

/* Structure entry for hash tables */
typedef struct sm_hash {
	union {
		struct mon_entry *mon_hdptr;	/* Head ptr for mon_table */
		name_entry *rec_hdptr;		/* Head ptr for rec_table */
		name_entry *recov_hdptr;	/* Head ptr for recov_q */
	} smhd_t;
	mutex_t	lock;			/* Lock to protect each list head */
} sm_hash_t;

#define	sm_monhdp	smhd_t.mon_hdptr
#define	sm_rechdp	smhd_t.rec_hdptr
#define	sm_recovhdp	smhd_t.recov_hdptr

/* Structure entry for address list in name-to-address entry */
typedef struct addr_entry {
	struct addr_entry *next;
	struct netobj ah;
	sa_family_t family;
} addr_entry_t;

/* Structure entry for name-to-address translation table */
typedef struct name_addr_entry {
	struct name_addr_entry *next;
	char *name;
	struct addr_entry *addresses;
} name_addr_entry_t;

/* Hash tables for each of the in-cache information */
extern sm_hash_t	mon_table[MAX_HASHSIZE];

/* Global variables */
extern mutex_t crash_lock;	/* lock for die and crash variables */
extern int die;			/* Flag to indicate that an SM_CRASH */
				/* request came in & to stop threads cleanly */
extern int in_crash;		/* Flag to single thread sm_crash requests. */
extern int regfiles_only;	/* Flag to indicate symlink use in statmon */
extern cond_t crash_finish;	/* Condition to wait until crash is finished */
extern mutex_t sm_trylock;	/* Lock to single thread sm_try */
/*
 * The only established lock precedence here is:
 *
 *	thr_rwlock > name_addrlock
 */
extern mutex_t name_addrlock;	/* Locks all entries of name-to-addr table */
extern rwlock_t thr_rwlock;	/* Reader/writer lock for requests coming in */
extern cond_t retrywait;	/* Condition to wait before starting retry */

extern char STATE[MAXPATHLEN], CURRENT[MAXPATHLEN];
extern char BACKUP[MAXPATHLEN];
extern int LOCAL_STATE;

/*
 * Hash functions for monitor and record hash tables.
 * Functions are hashed based on first 2 letters and last 2 letters of name.
 * If only 1 letter in name, then, hash only on 1 letter.
 */
#define	SMHASH(name, key) { \
	int l; \
	key = *name; \
	if ((l = strlen(name)) != 1) \
		key |= ((*(name+(l-1)) << 24) | (*(name+1) << 16) | \
			(*(name+(l-2)) << 8)); \
	key = key % MAX_HASHSIZE; \
}

extern int debug;		/* Prints out debug information if set. */

extern char hostname[MAXHOSTNAMELEN];

/*
 * These variables will be used to store all the
 * alias names for the host, as well as the -a
 * command line hostnames.
 */
extern char **host_name; /* store -a opts */
extern int	host_name_count;
extern int  addrix; /* # of -a entries */

/*
 * The following 2 variables are meaningful
 * only under a HA configuration.
 */
extern char **path_name; /* store -p opts */
extern int  pathix; /* # of -p entries */

/* Function prototypes used in program */
extern int	create_file(char *name);
extern void	delete_file(char *name);
extern void	record_name(char *name, int op);
extern void	sm_crash(void);
extern void	statd_init();
extern void	merge_hosts(void);
extern void	merge_ips(void);
extern CLIENT	*create_client(char *, int, int, char *, struct timeval *);
extern char	*xmalloc(unsigned);

/*
 * RPC service functions, slightly different here than the
 * generated ones in sm_inter.h
 */
extern void	nsmaddrproc1_reg(reg1args *, reg1res *);
extern void	sm_stat_svc(sm_name *namep, sm_stat_res *resp);
extern void	sm_mon_svc(mon *monp, sm_stat_res *resp);
extern void	sm_unmon_svc(mon_id *monidp, sm_stat *resp);
extern void	sm_unmon_all_svc(my_id *myidp, sm_stat *resp);
extern void	sm_simu_crash_svc(void *myidp);
extern void	sm_notify_svc(stat_chge *ntfp);

extern void	sm_inithash();
extern void	copydir_from_to(char *from_dir, char *to_dir);
extern int	str_cmp_unqual_hostname(char *, char *);
extern void	record_addr(char *name, sa_family_t family, struct netobj *ah);
extern int	is_symlink(char *file);
extern int	create_symlink(char *todir, char *rname, char *lname);
extern int	str_cmp_address_specifier(char *specifier1, char *specifier2);

#ifdef __cplusplus
}
#endif

#endif /* _SM_STATD_H */
