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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_IPC_IMPL_H
#define	_IPC_IMPL_H

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/mutex.h>
#include <sys/ipc_rctl.h>
#include <sys/project.h>
#include <sys/zone.h>
#include <sys/sysmacros.h>
#include <sys/avl.h>
#include <sys/id_space.h>
#include <sys/cred.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint64_t ipc_time_t;

/* For xxxctl64 */
#define	IPC_SET64	13	/* set options */
#define	IPC_STAT64	14	/* get options */

/*
 * There are two versions of the userland ipc_perm structure:
 *   ipc_perm     - the version used by user applications and by the kernel
 *		    when the user and kernel data models match (in ipc.h)
 *   ipc_perm32   - the 64-bit kernel's view of a 32-bit struct ipc_perm
 */
#if	defined(_SYSCALL32)
struct ipc_perm32 {
	uid32_t		uid;	/* owner's user id */
	gid32_t		gid;	/* owner's group id */
	uid32_t		cuid;	/* creator's user id */
	gid32_t		cgid;	/* creator's group id */
	mode32_t	mode;	/* access modes */
	uint32_t	seq;	/* slot usage sequence number */
	key32_t		key;	/* key */
	int32_t		pad[4];	/* reserve area */
};
#endif	/* _SYSCALL32 */

/*
 * This is the ipc_perm equivalent used in the xxxid_ds64 structures.
 * It, like the structures it is used in, is intended only for use in
 * communication between the kernel and user programs, and has the same
 * layout across all data models.
 *
 * The xxxid_ds64 structures rely on ipc_perm64 being a multiple of
 * 8 bytes so subsequent fields are 64-bit aligned on x86.
 */
typedef struct ipc_perm64 {
	uid_t	ipcx_uid;	/* owner's user id */
	gid_t	ipcx_gid;	/* owner's group id */
	uid_t	ipcx_cuid;	/* creator's user id */
	gid_t	ipcx_cgid;	/* creator's group id */
	mode_t	ipcx_mode;	/* access modes */
	key_t	ipcx_key;	/* key */
	projid_t ipcx_projid;	/* allocating project id */
	zoneid_t ipcx_zoneid;	/* creator's zone id */
} ipc_perm64_t;

/*
 * These are versions of xxxid_ds which are intended only for use in
 * communication between the kernel and user programs, and therefore
 * have the same layout across all data models.  Omitted are all
 * implementation-specific fields which would be of no use to user
 * programs.
 */
struct shmid_ds64 {
	ipc_perm64_t	shmx_perm;	/* operation permission struct */
	pid_t		shmx_lpid;	/* pid of last shmop */
	pid_t		shmx_cpid;	/* pid of creator */
	uint64_t	shmx_segsz;	/* size of segment in bytes */
	uint64_t	shmx_nattch;	/* # of attaches */
	uint64_t	shmx_cnattch;	/* # of ISM attaches */
	uint64_t	shmx_lkcnt;	/* lock count ??? */
	ipc_time_t	shmx_atime;	/* last shmat time */
	ipc_time_t	shmx_dtime;	/* last shmdt time */
	ipc_time_t	shmx_ctime;	/* last change time */
};

struct semid_ds64 {
	ipc_perm64_t	semx_perm;	/* operation permission struct */
	ushort_t	semx_nsems;	/* # of semaphores in set */
	ushort_t	_semx_pad[3];	/* pad to 8-byte multiple */
	ipc_time_t	semx_otime;	/* last semop time */
	ipc_time_t	semx_ctime;	/* last change time */
};

struct msqid_ds64 {
	ipc_perm64_t	msgx_perm;	/* operation permission struct */
	uint64_t	msgx_cbytes;	/* current # bytes on q */
	uint64_t	msgx_qnum;	/* # of messages on q */
	uint64_t	msgx_qbytes;	/* max # of bytes on q */
	pid_t		msgx_lspid;	/* pid of last msgsnd */
	pid_t		msgx_lrpid;	/* pid of last msgrcv */
	ipc_time_t	msgx_stime;	/* last msgsnd time */
	ipc_time_t	msgx_rtime;	/* last msgrcv time */
	ipc_time_t	msgx_ctime;	/* last change time */
};

#ifdef _KERNEL

/*
 * Implementation macros
 */
#define	IPC_FREE(x)	(((x)->ipc_mode & IPC_ALLOC) == 0)

#define	IPC_SEQ_BITS	7
#define	IPC_SEQ_MASK	((1 << IPC_SEQ_BITS) - 1)
#define	IPC_SEQ_SHIFT	(31 - IPC_SEQ_BITS)
#define	IPC_INDEX_MASK	((1 << IPC_SEQ_SHIFT) - 1)
#define	IPC_SEQ(x)	((unsigned int)(x) >> IPC_SEQ_SHIFT)
#define	IPC_INDEX(x)	((unsigned int)(x) & IPC_INDEX_MASK)

#define	IPC_IDS_MIN	(PAGESIZE / 64)		/* starting # of entries */
#define	IPC_IDS_MAX	(1 << IPC_SEQ_SHIFT)	/* maximum # of entries */
#define	IPC_ID_INVAL	UINT_MAX

#define	IPC_PROJ_USAGE(p, s) \
	(*(rctl_qty_t *)(((char *)&p->ipc_proj->kpj_data.kpd_ipc) + \
	s->ipcs_rctlofs))
#define	IPC_ZONE_USAGE(p, s) \
	(*(rctl_qty_t *)(((char *)&p->ipc_zone_ref.zref_zone->zone_ipc) + \
	s->ipcs_rctlofs))
#define	IPC_LOCKED(s, o) \
	MUTEX_HELD(&s->ipcs_table[IPC_INDEX(o->ipc_id)].ipct_lock)

/*
 * The kernel's ipc_perm structure.
 */
typedef struct kipc_perm {
	avl_node_t ipc_avl;	/* avl node if key is non-private */
	list_node_t ipc_list;	/* list node in list of all ids */
	uint_t	ipc_ref;	/* reference count		*/
	uid_t	ipc_uid;	/* owner's user id		*/
	gid_t	ipc_gid;	/* owner's group id		*/
	uid_t	ipc_cuid;	/* creator's user id		*/
	gid_t	ipc_cgid;	/* creator's group id		*/
	mode_t	ipc_mode;	/* access modes			*/
	key_t	ipc_key;	/* key				*/
	kproject_t *ipc_proj;	/* creator's project		*/
	uint_t	ipc_id;		/* id				*/
	zoneid_t ipc_zoneid;	/* creator's zone id		*/
	zone_ref_t ipc_zone_ref; /* reference to creator's zone */
} kipc_perm_t;

typedef struct ipc_slot {
	kmutex_t	ipct_lock;	/* bucket lock		*/
	kipc_perm_t	*ipct_data;	/* data			*/
	uint_t		ipct_seq;	/* sequence number	*/
	struct ipc_slot	*ipct_chain;	/* for stale arrays	*/
	char		ipct_pad[64 - sizeof (kmutex_t) - 3 * sizeof (void *)];
} ipc_slot_t;

typedef void(ipc_func_t)(kipc_perm_t *);

typedef struct ipc_service {
	kmutex_t	ipcs_lock;	/* lock for (de)allocation, keys */
	avl_tree_t	ipcs_keys;	/* objects sorted by key	*/
	ipc_slot_t	*ipcs_table;	/* table of objects		*/
	uint_t		ipcs_tabsz;	/* size of table		*/
	uint_t		ipcs_count;	/* # of objects allocated	*/
	rctl_hndl_t	ipcs_proj_rctl;	/* id limiting rctl handle	*/
	rctl_hndl_t	ipcs_zone_rctl;	/* id limiting rctl handle	*/
	size_t		ipcs_rctlofs;	/* offset in kproject_data_t	*/
	id_space_t	*ipcs_ids;	/* id space for objects		*/
	size_t		ipcs_ssize;	/* object size (for allocation)	*/
	ipc_func_t	*ipcs_dtor;	/* object destructor		*/
	ipc_func_t	*ipcs_rmid;	/* object removal		*/
	list_t		ipcs_usedids;	/* list of allocated ids	*/
	int		ipcs_atype;	/* audit type (see c2/audit.h)	*/
} ipc_service_t;

int ipcperm_access(kipc_perm_t *, int, cred_t *);
int ipcperm_set(ipc_service_t *, struct cred *, kipc_perm_t *,
    struct ipc_perm *, model_t);
void ipcperm_stat(struct ipc_perm *, kipc_perm_t *, model_t);
int ipcperm_set64(ipc_service_t *, struct cred *, kipc_perm_t *,
    ipc_perm64_t *);
void ipcperm_stat64(ipc_perm64_t *, kipc_perm_t *);

ipc_service_t *ipcs_create(const char *, rctl_hndl_t, rctl_hndl_t, size_t,
    ipc_func_t *, ipc_func_t *, int, size_t);
void ipcs_destroy(ipc_service_t *);
void ipcs_lock(ipc_service_t *);
void ipcs_unlock(ipc_service_t *);

kmutex_t *ipc_lock(ipc_service_t *, int);
kmutex_t *ipc_relock(ipc_service_t *, int, kmutex_t *);
kmutex_t *ipc_lookup(ipc_service_t *, int, kipc_perm_t **);

void ipc_hold(ipc_service_t *, kipc_perm_t *);
void ipc_rele(ipc_service_t *, kipc_perm_t *);
void ipc_rele_locked(ipc_service_t *, kipc_perm_t *);

int ipc_get(ipc_service_t *, key_t, int, kipc_perm_t **, kmutex_t **);
int ipc_commit_begin(ipc_service_t *, key_t, int, kipc_perm_t *);
kmutex_t *ipc_commit_end(ipc_service_t *, kipc_perm_t *);
void ipc_cleanup(ipc_service_t *, kipc_perm_t *);

int ipc_rmid(ipc_service_t *, int, cred_t *);
int ipc_ids(ipc_service_t *, int *, uint_t, uint_t *);

void ipc_remove_zone(ipc_service_t *, zoneid_t);

#else	/* _KERNEL */

int msgctl64(int, int, struct msqid_ds64 *);
int semctl64(int, int, int, ...);
int shmctl64(int, int, struct shmid_ds64 *);

#endif	/* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _IPC_IMPL_H */
