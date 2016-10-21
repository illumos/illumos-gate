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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2014 Igor Kozhukhov <ikozhukhov@gmail.com>.
 */

#ifndef _SYS_ZONE_H
#define	_SYS_ZONE_H

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/rctl.h>
#include <sys/ipc_rctl.h>
#include <sys/pset.h>
#include <sys/tsol/label.h>
#include <sys/cred.h>
#include <sys/netstack.h>
#include <sys/uadmin.h>
#include <sys/ksynch.h>
#include <sys/socket_impl.h>
#include <sys/secflags.h>
#include <netinet/in.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NOTE
 *
 * The contents of this file are private to the implementation of
 * Solaris and are subject to change at any time without notice.
 * Applications and drivers using these interfaces may fail to
 * run on future releases.
 */

/* Available both in kernel and for user space */

/* zone id restrictions and special ids */
#define	MAX_ZONEID	9999
#define	MIN_USERZONEID	1	/* lowest user-creatable zone ID */
#define	MIN_ZONEID	0	/* minimum zone ID on system */
#define	GLOBAL_ZONEID	0
#define	ZONEID_WIDTH	4	/* for printf */

/*
 * Special zoneid_t token to refer to all zones.
 */
#define	ALL_ZONES	(-1)

/* system call subcodes */
#define	ZONE_CREATE		0
#define	ZONE_DESTROY		1
#define	ZONE_GETATTR		2
#define	ZONE_ENTER		3
#define	ZONE_LIST		4
#define	ZONE_SHUTDOWN		5
#define	ZONE_LOOKUP		6
#define	ZONE_BOOT		7
#define	ZONE_VERSION		8
#define	ZONE_SETATTR		9
#define	ZONE_ADD_DATALINK	10
#define	ZONE_DEL_DATALINK	11
#define	ZONE_CHECK_DATALINK	12
#define	ZONE_LIST_DATALINK	13

/* zone attributes */
#define	ZONE_ATTR_ROOT		1
#define	ZONE_ATTR_NAME		2
#define	ZONE_ATTR_STATUS	3
#define	ZONE_ATTR_PRIVSET	4
#define	ZONE_ATTR_UNIQID	5
#define	ZONE_ATTR_POOLID	6
#define	ZONE_ATTR_INITPID	7
#define	ZONE_ATTR_SLBL		8
#define	ZONE_ATTR_INITNAME	9
#define	ZONE_ATTR_BOOTARGS	10
#define	ZONE_ATTR_BRAND		11
#define	ZONE_ATTR_PHYS_MCAP	12
#define	ZONE_ATTR_SCHED_CLASS	13
#define	ZONE_ATTR_FLAGS		14
#define	ZONE_ATTR_HOSTID	15
#define	ZONE_ATTR_FS_ALLOWED	16
#define	ZONE_ATTR_NETWORK	17
#define	ZONE_ATTR_INITNORESTART	20
#define	ZONE_ATTR_SECFLAGS	21

/* Start of the brand-specific attribute namespace */
#define	ZONE_ATTR_BRAND_ATTRS	32768

#define	ZONE_FS_ALLOWED_MAX	1024

#define	ZONE_EVENT_CHANNEL	"com.sun:zones:status"
#define	ZONE_EVENT_STATUS_CLASS	"status"
#define	ZONE_EVENT_STATUS_SUBCLASS	"change"

#define	ZONE_EVENT_UNINITIALIZED	"uninitialized"
#define	ZONE_EVENT_INITIALIZED		"initialized"
#define	ZONE_EVENT_READY		"ready"
#define	ZONE_EVENT_RUNNING		"running"
#define	ZONE_EVENT_SHUTTING_DOWN	"shutting_down"

#define	ZONE_CB_NAME		"zonename"
#define	ZONE_CB_NEWSTATE	"newstate"
#define	ZONE_CB_OLDSTATE	"oldstate"
#define	ZONE_CB_TIMESTAMP	"when"
#define	ZONE_CB_ZONEID		"zoneid"

/*
 * Exit values that may be returned by scripts or programs invoked by various
 * zone commands.
 *
 * These are defined as:
 *
 *	ZONE_SUBPROC_OK
 *	===============
 *	The subprocess completed successfully.
 *
 *	ZONE_SUBPROC_USAGE
 *	==================
 *	The subprocess failed with a usage message, or a usage message should
 *	be output in its behalf.
 *
 *	ZONE_SUBPROC_NOTCOMPLETE
 *	========================
 *	The subprocess did not complete, but the actions performed by the
 *	subprocess require no recovery actions by the user.
 *
 *	For example, if the subprocess were called by "zoneadm install," the
 *	installation of the zone did not succeed but the user need not perform
 *	a "zoneadm uninstall" before attempting another install.
 *
 *	ZONE_SUBPROC_FATAL
 *	==================
 *	The subprocess failed in a fatal manner, usually one that will require
 *	some type of recovery action by the user.
 *
 *	For example, if the subprocess were called by "zoneadm install," the
 *	installation of the zone did not succeed and the user will need to
 *	perform a "zoneadm uninstall" before another install attempt is
 *	possible.
 *
 *	The non-success exit values are large to avoid accidental collision
 *	with values used internally by some commands (e.g. "Z_ERR" and
 *	"Z_USAGE" as used by zoneadm.)
 */
#define	ZONE_SUBPROC_OK			0
#define	ZONE_SUBPROC_USAGE		253
#define	ZONE_SUBPROC_NOTCOMPLETE	254
#define	ZONE_SUBPROC_FATAL		255

#ifdef _SYSCALL32
typedef struct {
	caddr32_t zone_name;
	caddr32_t zone_root;
	caddr32_t zone_privs;
	size32_t zone_privssz;
	caddr32_t rctlbuf;
	size32_t rctlbufsz;
	caddr32_t extended_error;
	caddr32_t zfsbuf;
	size32_t  zfsbufsz;
	int match;			/* match level */
	uint32_t doi;			/* DOI for label */
	caddr32_t label;		/* label associated with zone */
	int flags;
} zone_def32;
#endif
typedef struct {
	const char *zone_name;
	const char *zone_root;
	const struct priv_set *zone_privs;
	size_t zone_privssz;
	const char *rctlbuf;
	size_t rctlbufsz;
	int *extended_error;
	const char *zfsbuf;
	size_t zfsbufsz;
	int match;			/* match level */
	uint32_t doi;			/* DOI for label */
	const bslabel_t *label;		/* label associated with zone */
	int flags;
} zone_def;

/* extended error information */
#define	ZE_UNKNOWN	0	/* No extended error info */
#define	ZE_CHROOTED	1	/* tried to zone_create from chroot */
#define	ZE_AREMOUNTS	2	/* there are mounts within the zone */
#define	ZE_LABELINUSE	3	/* label is already in use by some other zone */

/*
 * zone_status values
 *
 * You must modify zone_status_names in mdb(1M)'s genunix module
 * (genunix/zone.c) when you modify this enum.
 */
typedef enum {
	ZONE_IS_UNINITIALIZED = 0,
	ZONE_IS_INITIALIZED,
	ZONE_IS_READY,
	ZONE_IS_BOOTING,
	ZONE_IS_RUNNING,
	ZONE_IS_SHUTTING_DOWN,
	ZONE_IS_EMPTY,
	ZONE_IS_DOWN,
	ZONE_IS_DYING,
	ZONE_IS_DEAD
} zone_status_t;
#define	ZONE_MIN_STATE		ZONE_IS_UNINITIALIZED
#define	ZONE_MAX_STATE		ZONE_IS_DEAD

/*
 * Valid commands which may be issued by zoneadm to zoneadmd.  The kernel also
 * communicates with zoneadmd, but only uses Z_REBOOT and Z_HALT.
 */
typedef enum zone_cmd {
	Z_READY, Z_BOOT, Z_FORCEBOOT, Z_REBOOT, Z_HALT, Z_NOTE_UNINSTALLING,
	Z_MOUNT, Z_FORCEMOUNT, Z_UNMOUNT, Z_SHUTDOWN
} zone_cmd_t;

/*
 * The structure of a request to zoneadmd.
 */
typedef struct zone_cmd_arg {
	uint64_t	uniqid;		/* unique "generation number" */
	zone_cmd_t	cmd;		/* requested action */
	uint32_t	_pad;		/* need consistent 32/64 bit alignmt */
	char locale[MAXPATHLEN];	/* locale in which to render messages */
	char bootbuf[BOOTARGS_MAX];	/* arguments passed to zone_boot() */
} zone_cmd_arg_t;

/*
 * Structure of zoneadmd's response to a request.  A NULL return value means
 * the caller should attempt to restart zoneadmd and retry.
 */
typedef struct zone_cmd_rval {
	int rval;			/* return value of request */
	char errbuf[1];	/* variable-sized buffer containing error messages */
} zone_cmd_rval_t;

/*
 * The zone support infrastructure uses the zone name as a component
 * of unix domain (AF_UNIX) sockets, which are limited to 108 characters
 * in length, so ZONENAME_MAX is limited by that.
 */
#define	ZONENAME_MAX		64

#define	GLOBAL_ZONENAME		"global"

/*
 * Extended Regular expression (see regex(5)) which matches all valid zone
 * names.
 */
#define	ZONENAME_REGEXP		"[a-zA-Z0-9][-_.a-zA-Z0-9]{0,62}"

/*
 * Where the zones support infrastructure places temporary files.
 */
#define	ZONES_TMPDIR		"/var/run/zones"

/*
 * The path to the door used by clients to communicate with zoneadmd.
 */
#define	ZONE_DOOR_PATH		ZONES_TMPDIR "/%s.zoneadmd_door"


/* zone_flags */
/*
 * Threads that read or write the following flag must hold zone_lock.
 */
#define	ZF_REFCOUNTS_LOGGED	0x1	/* a thread logged the zone's refs */

/*
 * The following threads are set when the zone is created and never changed.
 * Threads that test for these flags don't have to hold zone_lock.
 */
#define	ZF_HASHED_LABEL		0x2	/* zone has a unique label */
#define	ZF_IS_SCRATCH		0x4	/* scratch zone */
#define	ZF_NET_EXCL		0x8	/* Zone has an exclusive IP stack */


/* zone_create flags */
#define	ZCF_NET_EXCL		0x1	/* Create a zone with exclusive IP */

/* zone network properties */
#define	ZONE_NETWORK_ADDRESS	1
#define	ZONE_NETWORK_DEFROUTER	2

#define	ZONE_NET_ADDRNAME	"address"
#define	ZONE_NET_RTRNAME	"route"

typedef struct zone_net_data {
	int zn_type;
	int zn_len;
	datalink_id_t zn_linkid;
	uint8_t zn_val[1];
} zone_net_data_t;


#ifdef _KERNEL

/*
 * We need to protect the definition of 'list_t' from userland applications and
 * libraries which may be defining ther own versions.
 */
#include <sys/list.h>
#include <sys/loadavg.h>

#define	GLOBAL_ZONEUNIQID	0	/* uniqid of the global zone */

struct pool;
struct brand;

/*
 * Each of these constants identifies a kernel subsystem that acquires and
 * releases zone references.  Each subsystem that invokes
 * zone_hold_ref() and zone_rele_ref() should specify the
 * zone_ref_subsys_t constant associated with the subsystem.  Tracked holds
 * help users and developers quickly identify subsystems that stall zone
 * shutdowns indefinitely.
 *
 * NOTE: You must modify zone_ref_subsys_names in usr/src/uts/common/os/zone.c
 * when you modify this enumeration.
 */
typedef enum zone_ref_subsys {
	ZONE_REF_NFS,			/* NFS */
	ZONE_REF_NFSV4,			/* NFSv4 */
	ZONE_REF_SMBFS,			/* SMBFS */
	ZONE_REF_MNTFS,			/* MNTFS */
	ZONE_REF_LOFI,			/* LOFI devices */
	ZONE_REF_VFS,			/* VFS infrastructure */
	ZONE_REF_IPC,			/* IPC infrastructure */
	ZONE_REF_NUM_SUBSYS		/* This must be the last entry. */
} zone_ref_subsys_t;

/*
 * zone_ref represents a general-purpose references to a zone.  Each zone's
 * references are linked into the zone's zone_t::zone_ref_list.  This allows
 * debuggers to walk zones' references.
 */
typedef struct zone_ref {
	struct zone	*zref_zone; /* the zone to which the reference refers */
	list_node_t	zref_linkage; /* linkage for zone_t::zone_ref_list */
} zone_ref_t;

/*
 * Structure to record list of ZFS datasets exported to a zone.
 */
typedef struct zone_dataset {
	char		*zd_dataset;
	list_node_t	zd_linkage;
} zone_dataset_t;

/*
 * structure for zone kstats
 */
typedef struct zone_kstat {
	kstat_named_t zk_zonename;
	kstat_named_t zk_usage;
	kstat_named_t zk_value;
} zone_kstat_t;

struct cpucap;

typedef struct {
	kstat_named_t	zm_zonename;
	kstat_named_t	zm_pgpgin;
	kstat_named_t	zm_anonpgin;
	kstat_named_t	zm_execpgin;
	kstat_named_t	zm_fspgin;
	kstat_named_t	zm_anon_alloc_fail;
} zone_mcap_kstat_t;

typedef struct {
	kstat_named_t	zm_zonename;	/* full name, kstat truncates name */
	kstat_named_t	zm_utime;
	kstat_named_t	zm_stime;
	kstat_named_t	zm_wtime;
	kstat_named_t	zm_avenrun1;
	kstat_named_t	zm_avenrun5;
	kstat_named_t	zm_avenrun15;
	kstat_named_t	zm_ffcap;
	kstat_named_t	zm_ffnoproc;
	kstat_named_t	zm_ffnomem;
	kstat_named_t	zm_ffmisc;
	kstat_named_t	zm_nested_intp;
	kstat_named_t	zm_init_pid;
	kstat_named_t	zm_boot_time;
} zone_misc_kstat_t;

typedef struct zone {
	/*
	 * zone_name is never modified once set.
	 */
	char		*zone_name;	/* zone's configuration name */
	/*
	 * zone_nodename and zone_domain are never freed once allocated.
	 */
	char		*zone_nodename;	/* utsname.nodename equivalent */
	char		*zone_domain;	/* srpc_domain equivalent */
	/*
	 * zone_hostid is used for per-zone hostid emulation.
	 * Currently it isn't modified after it's set (so no locks protect
	 * accesses), but that might have to change when we allow
	 * administrators to change running zones' properties.
	 *
	 * The global zone's zone_hostid must always be HW_INVALID_HOSTID so
	 * that zone_get_hostid() will function correctly.
	 */
	uint32_t	zone_hostid;	/* zone's hostid, HW_INVALID_HOSTID */
					/* if not emulated */
	/*
	 * zone_lock protects the following fields of a zone_t:
	 * 	zone_ref
	 * 	zone_cred_ref
	 * 	zone_subsys_ref
	 * 	zone_ref_list
	 * 	zone_ntasks
	 * 	zone_flags
	 * 	zone_zsd
	 *	zone_pfexecd
	 */
	kmutex_t	zone_lock;
	/*
	 * zone_linkage is the zone's linkage into the active or
	 * death-row list.  The field is protected by zonehash_lock.
	 */
	list_node_t	zone_linkage;
	zoneid_t	zone_id;	/* ID of zone */
	uint_t		zone_ref;	/* count of zone_hold()s on zone */
	uint_t		zone_cred_ref;	/* count of zone_hold_cred()s on zone */
	/*
	 * Fixed-sized array of subsystem-specific reference counts
	 * The sum of all of the counts must be less than or equal to zone_ref.
	 * The array is indexed by the counts' subsystems' zone_ref_subsys_t
	 * constants.
	 */
	uint_t		zone_subsys_ref[ZONE_REF_NUM_SUBSYS];
	list_t		zone_ref_list;	/* list of zone_ref_t structs */
	/*
	 * zone_rootvp and zone_rootpath can never be modified once set.
	 */
	struct vnode	*zone_rootvp;	/* zone's root vnode */
	char		*zone_rootpath;	/* Path to zone's root + '/' */
	ushort_t	zone_flags;	/* misc flags */
	zone_status_t	zone_status;	/* protected by zone_status_lock */
	uint_t		zone_ntasks;	/* number of tasks executing in zone */
	kmutex_t	zone_nlwps_lock; /* protects zone_nlwps, and *_nlwps */
					/* counters in projects and tasks */
					/* that are within the zone */
	rctl_qty_t	zone_nlwps;	/* number of lwps in zone */
	rctl_qty_t	zone_nlwps_ctl; /* protected by zone_rctls->rcs_lock */
	rctl_qty_t	zone_shmmax;	/* System V shared memory usage */
	ipc_rqty_t	zone_ipc;	/* System V IPC id resource usage */

	uint_t		zone_rootpathlen; /* strlen(zone_rootpath) + 1 */
	uint32_t	zone_shares;	/* FSS shares allocated to zone */
	rctl_set_t	*zone_rctls;	/* zone-wide (zone.*) rctls */
	kmutex_t	zone_mem_lock;	/* protects zone_locked_mem and */
					/* kpd_locked_mem for all */
					/* projects in zone. */
					/* Also protects zone_max_swap */
					/* grab after p_lock, before rcs_lock */
	rctl_qty_t	zone_locked_mem;	/* bytes of locked memory in */
						/* zone */
	rctl_qty_t	zone_locked_mem_ctl;	/* Current locked memory */
						/* limit.  Protected by */
						/* zone_rctls->rcs_lock */
	rctl_qty_t	zone_max_swap; /* bytes of swap reserved by zone */
	rctl_qty_t	zone_max_swap_ctl;	/* current swap limit. */
						/* Protected by */
						/* zone_rctls->rcs_lock */
	kmutex_t	zone_rctl_lock;	/* protects zone_max_lofi */
	rctl_qty_t	zone_max_lofi; /* lofi devs for zone */
	rctl_qty_t	zone_max_lofi_ctl;	/* current lofi limit. */
						/* Protected by */
						/* zone_rctls->rcs_lock */
	list_t		zone_zsd;	/* list of Zone-Specific Data values */
	kcondvar_t	zone_cv;	/* used to signal state changes */
	struct proc	*zone_zsched;	/* Dummy kernel "zsched" process */
	pid_t		zone_proc_initpid; /* pid of "init" for this zone */
	char		*zone_initname;	/* fs path to 'init' */
	int		zone_boot_err;  /* for zone_boot() if boot fails */
	char		*zone_bootargs;	/* arguments passed via zone_boot() */
	uint64_t	zone_phys_mcap;	/* physical memory cap */
	/*
	 * zone_kthreads is protected by zone_status_lock.
	 */
	kthread_t	*zone_kthreads;	/* kernel threads in zone */
	struct priv_set	*zone_privset;	/* limit set for zone */
	/*
	 * zone_vfslist is protected by vfs_list_lock().
	 */
	struct vfs	*zone_vfslist;	/* list of FS's mounted in zone */
	uint64_t	zone_uniqid;	/* unique zone generation number */
	struct cred	*zone_kcred;	/* kcred-like, zone-limited cred */
	/*
	 * zone_pool is protected by pool_lock().
	 */
	struct pool	*zone_pool;	/* pool the zone is bound to */
	hrtime_t	zone_pool_mod;	/* last pool bind modification time */
	/* zone_psetid is protected by cpu_lock */
	psetid_t	zone_psetid;	/* pset the zone is bound to */

	time_t		zone_boot_time;	/* Similar to boot_time */

	/*
	 * The following two can be read without holding any locks.  They are
	 * updated under cpu_lock.
	 */
	int		zone_ncpus;  /* zone's idea of ncpus */
	int		zone_ncpus_online; /* zone's idea of ncpus_online */
	/*
	 * List of ZFS datasets exported to this zone.
	 */
	list_t		zone_datasets;	/* list of datasets */

	ts_label_t	*zone_slabel;	/* zone sensitivity label */
	int		zone_match;	/* require label match for packets */
	tsol_mlp_list_t zone_mlps;	/* MLPs on zone-private addresses */

	boolean_t	zone_restart_init;	/* Restart init if it dies? */
	struct brand	*zone_brand;		/* zone's brand */
	void 		*zone_brand_data;	/* store brand specific data */
	id_t		zone_defaultcid;	/* dflt scheduling class id */
	kstat_t		*zone_swapresv_kstat;
	kstat_t		*zone_lockedmem_kstat;
	/*
	 * zone_dl_list is protected by zone_lock
	 */
	list_t		zone_dl_list;
	netstack_t	*zone_netstack;
	struct cpucap	*zone_cpucap;	/* CPU caps data */
	/*
	 * Solaris Auditing per-zone audit context
	 */
	struct au_kcontext	*zone_audit_kctxt;
	/*
	 * For private use by mntfs.
	 */
	struct mntelem	*zone_mntfs_db;
	krwlock_t	zone_mntfs_db_lock;

	struct klpd_reg		*zone_pfexecd;

	char		*zone_fs_allowed;
	rctl_qty_t	zone_nprocs;	/* number of processes in the zone */
	rctl_qty_t	zone_nprocs_ctl;	/* current limit protected by */
						/* zone_rctls->rcs_lock */
	kstat_t		*zone_nprocs_kstat;

	kmutex_t	zone_mcap_lock;	/* protects mcap statistics */
	kstat_t		*zone_mcap_ksp;
	zone_mcap_kstat_t *zone_mcap_stats;
	uint64_t	zone_pgpgin;		/* pages paged in */
	uint64_t	zone_anonpgin;		/* anon pages paged in */
	uint64_t	zone_execpgin;		/* exec pages paged in */
	uint64_t	zone_fspgin;		/* fs pages paged in */
	uint64_t	zone_anon_alloc_fail;	/* cnt of anon alloc fails */

	psecflags_t	zone_secflags; /* default zone security-flags */

	/*
	 * Misc. kstats and counters for zone cpu-usage aggregation.
	 * The zone_Xtime values are the sum of the micro-state accounting
	 * values for all threads that are running or have run in the zone.
	 * This is tracked in msacct.c as threads change state.
	 * The zone_stime is the sum of the LMS_SYSTEM times.
	 * The zone_utime is the sum of the LMS_USER times.
	 * The zone_wtime is the sum of the LMS_WAIT_CPU times.
	 * As with per-thread micro-state accounting values, these values are
	 * not scaled to nanosecs.  The scaling is done by the
	 * zone_misc_kstat_update function when kstats are requested.
	 */
	kmutex_t	zone_misc_lock;		/* protects misc statistics */
	kstat_t		*zone_misc_ksp;
	zone_misc_kstat_t *zone_misc_stats;
	uint64_t	zone_stime;		/* total system time */
	uint64_t	zone_utime;		/* total user time */
	uint64_t	zone_wtime;		/* total time waiting in runq */
	/* fork-fail kstat tracking */
	uint32_t	zone_ffcap;		/* hit an rctl cap */
	uint32_t	zone_ffnoproc;		/* get proc/lwp error */
	uint32_t	zone_ffnomem;		/* as_dup/memory error */
	uint32_t	zone_ffmisc;		/* misc. other error */

	uint32_t	zone_nested_intp;	/* nested interp. kstat */

	struct loadavg_s zone_loadavg;		/* loadavg for this zone */
	uint64_t	zone_hp_avenrun[3];	/* high-precision avenrun */
	int		zone_avenrun[3];	/* FSCALED avg. run queue len */

	/*
	 * FSS stats updated once per second by fss_decay_usage.
	 */
	uint32_t	zone_fss_gen;		/* FSS generation cntr */
	uint64_t	zone_run_ticks;		/* tot # of ticks running */

	/*
	 * DTrace-private per-zone state
	 */
	int		zone_dtrace_getf;	/* # of unprivileged getf()s */

	/*
	 * Synchronization primitives used to synchronize between mounts and
	 * zone creation/destruction.
	 */
	int		zone_mounts_in_progress;
	kcondvar_t	zone_mount_cv;
	kmutex_t	zone_mount_lock;
} zone_t;

/*
 * Special value of zone_psetid to indicate that pools are disabled.
 */
#define	ZONE_PS_INVAL	PS_MYID


extern zone_t zone0;
extern zone_t *global_zone;
extern uint_t maxzones;
extern rctl_hndl_t rc_zone_nlwps;
extern rctl_hndl_t rc_zone_nprocs;

extern long zone(int, void *, void *, void *, void *);
extern void zone_zsd_init(void);
extern void zone_init(void);
extern void zone_hold(zone_t *);
extern void zone_rele(zone_t *);
extern void zone_init_ref(zone_ref_t *);
extern void zone_hold_ref(zone_t *, zone_ref_t *, zone_ref_subsys_t);
extern void zone_rele_ref(zone_ref_t *, zone_ref_subsys_t);
extern void zone_cred_hold(zone_t *);
extern void zone_cred_rele(zone_t *);
extern void zone_task_hold(zone_t *);
extern void zone_task_rele(zone_t *);
extern zone_t *zone_find_by_id(zoneid_t);
extern zone_t *zone_find_by_label(const ts_label_t *);
extern zone_t *zone_find_by_name(char *);
extern zone_t *zone_find_by_any_path(const char *, boolean_t);
extern zone_t *zone_find_by_path(const char *);
extern zoneid_t getzoneid(void);
extern zone_t *zone_find_by_id_nolock(zoneid_t);
extern int zone_datalink_walk(zoneid_t, int (*)(datalink_id_t, void *), void *);
extern int zone_check_datalink(zoneid_t *, datalink_id_t);
extern void zone_loadavg_update();

/*
 * Zone-specific data (ZSD) APIs
 */
/*
 * The following is what code should be initializing its zone_key_t to if it
 * calls zone_getspecific() without necessarily knowing that zone_key_create()
 * has been called on the key.
 */
#define	ZONE_KEY_UNINITIALIZED	0

typedef uint_t zone_key_t;

extern void	zone_key_create(zone_key_t *, void *(*)(zoneid_t),
    void (*)(zoneid_t, void *), void (*)(zoneid_t, void *));
extern int 	zone_key_delete(zone_key_t);
extern void	*zone_getspecific(zone_key_t, zone_t *);
extern int	zone_setspecific(zone_key_t, zone_t *, const void *);

/*
 * The definition of a zsd_entry is truly private to zone.c and is only
 * placed here so it can be shared with mdb.
 *
 * State maintained for each zone times each registered key, which tracks
 * the state of the create, shutdown and destroy callbacks.
 *
 * zsd_flags is used to keep track of pending actions to avoid holding locks
 * when calling the create/shutdown/destroy callbacks, since doing so
 * could lead to deadlocks.
 */
struct zsd_entry {
	zone_key_t		zsd_key;	/* Key used to lookup value */
	void			*zsd_data;	/* Caller-managed value */
	/*
	 * Callbacks to be executed when a zone is created, shutdown, and
	 * destroyed, respectively.
	 */
	void			*(*zsd_create)(zoneid_t);
	void			(*zsd_shutdown)(zoneid_t, void *);
	void			(*zsd_destroy)(zoneid_t, void *);
	list_node_t		zsd_linkage;
	uint16_t 		zsd_flags;	/* See below */
	kcondvar_t		zsd_cv;
};

/*
 * zsd_flags
 */
#define	ZSD_CREATE_NEEDED	0x0001
#define	ZSD_CREATE_INPROGRESS	0x0002
#define	ZSD_CREATE_COMPLETED	0x0004
#define	ZSD_SHUTDOWN_NEEDED	0x0010
#define	ZSD_SHUTDOWN_INPROGRESS	0x0020
#define	ZSD_SHUTDOWN_COMPLETED	0x0040
#define	ZSD_DESTROY_NEEDED	0x0100
#define	ZSD_DESTROY_INPROGRESS	0x0200
#define	ZSD_DESTROY_COMPLETED	0x0400

#define	ZSD_CREATE_ALL	\
	(ZSD_CREATE_NEEDED|ZSD_CREATE_INPROGRESS|ZSD_CREATE_COMPLETED)
#define	ZSD_SHUTDOWN_ALL	\
	(ZSD_SHUTDOWN_NEEDED|ZSD_SHUTDOWN_INPROGRESS|ZSD_SHUTDOWN_COMPLETED)
#define	ZSD_DESTROY_ALL	\
	(ZSD_DESTROY_NEEDED|ZSD_DESTROY_INPROGRESS|ZSD_DESTROY_COMPLETED)

#define	ZSD_ALL_INPROGRESS \
	(ZSD_CREATE_INPROGRESS|ZSD_SHUTDOWN_INPROGRESS|ZSD_DESTROY_INPROGRESS)

/*
 * Macros to help with zone visibility restrictions.
 */

/*
 * Is process in the global zone?
 */
#define	INGLOBALZONE(p) \
	((p)->p_zone == global_zone)

/*
 * Can process view objects in given zone?
 */
#define	HASZONEACCESS(p, zoneid) \
	((p)->p_zone->zone_id == (zoneid) || INGLOBALZONE(p))

/*
 * Convenience macro to see if a resolved path is visible from within a
 * given zone.
 *
 * The basic idea is that the first (zone_rootpathlen - 1) bytes of the
 * two strings must be equal.  Since the rootpathlen has a trailing '/',
 * we want to skip everything in the path up to (but not including) the
 * trailing '/'.
 */
#define	ZONE_PATH_VISIBLE(path, zone) \
	(strncmp((path), (zone)->zone_rootpath,		\
	    (zone)->zone_rootpathlen - 1) == 0)

/*
 * Convenience macro to go from the global view of a path to that seen
 * from within said zone.  It is the responsibility of the caller to
 * ensure that the path is a resolved one (ie, no '..'s or '.'s), and is
 * in fact visible from within the zone.
 */
#define	ZONE_PATH_TRANSLATE(path, zone)	\
	(ASSERT(ZONE_PATH_VISIBLE(path, zone)),	\
	(path) + (zone)->zone_rootpathlen - 2)

/*
 * Special processes visible in all zones.
 */
#define	ZONE_SPECIALPID(x)	 ((x) == 0 || (x) == 1)

/*
 * Zone-safe version of thread_create() to be used when the caller wants to
 * create a kernel thread to run within the current zone's context.
 */
extern kthread_t *zthread_create(caddr_t, size_t, void (*)(), void *, size_t,
    pri_t);
extern void zthread_exit(void);

/*
 * Functions for an external observer to register interest in a zone's status
 * change.  Observers will be woken up when the zone status equals the status
 * argument passed in (in the case of zone_status_timedwait, the function may
 * also return because of a timeout; zone_status_wait_sig may return early due
 * to a signal being delivered; zone_status_timedwait_sig may return for any of
 * the above reasons).
 *
 * Otherwise these behave identically to cv_timedwait(), cv_wait(), and
 * cv_wait_sig() respectively.
 */
extern clock_t zone_status_timedwait(zone_t *, clock_t, zone_status_t);
extern clock_t zone_status_timedwait_sig(zone_t *, clock_t, zone_status_t);
extern void zone_status_wait(zone_t *, zone_status_t);
extern int zone_status_wait_sig(zone_t *, zone_status_t);

/*
 * Get the status  of the zone (at the time it was called).  The state may
 * have progressed by the time it is returned.
 */
extern zone_status_t zone_status_get(zone_t *);

/*
 * Safely get the hostid of the specified zone (defaults to machine's hostid
 * if the specified zone doesn't emulate a hostid).  Passing NULL retrieves
 * the global zone's (i.e., physical system's) hostid.
 */
extern uint32_t zone_get_hostid(zone_t *);

/*
 * Get the "kcred" credentials corresponding to the given zone.
 */
extern struct cred *zone_get_kcred(zoneid_t);

/*
 * Get/set the pool the zone is currently bound to.
 */
extern struct pool *zone_pool_get(zone_t *);
extern void zone_pool_set(zone_t *, struct pool *);

/*
 * Get/set the pset the zone is currently using.
 */
extern psetid_t zone_pset_get(zone_t *);
extern void zone_pset_set(zone_t *, psetid_t);

/*
 * Get the number of cpus/online-cpus visible from the given zone.
 */
extern int zone_ncpus_get(zone_t *);
extern int zone_ncpus_online_get(zone_t *);

/*
 * Returns true if the named pool/dataset is visible in the current zone.
 */
extern int zone_dataset_visible(const char *, int *);

/*
 * zone version of kadmin()
 */
extern int zone_kadmin(int, int, const char *, cred_t *);
extern void zone_shutdown_global(void);

extern void mount_in_progress(zone_t *);
extern void mount_completed(zone_t *);

extern int zone_walk(int (*)(zone_t *, void *), void *);

extern rctl_hndl_t rc_zone_locked_mem;
extern rctl_hndl_t rc_zone_max_swap;
extern rctl_hndl_t rc_zone_max_lofi;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZONE_H */
