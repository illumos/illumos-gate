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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_LX_PROC_H
#define	_LX_PROC_H

#ifdef _LXPROC_NATIVE_H
#error Attempted to include branded lx_proc.h after native lxproc.h
#endif

#define	_LXPROC_BRANDED_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * lxproc.h: declarations, data structures and macros for lxprocfs
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/policy.h>
#include <sys/debug.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/var.h>
#include <sys/user.h>
#include <sys/t_lock.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/priv.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/cmn_err.h>
#include <sys/zone.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/dnlc.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/nvpair.h>
#include <vm/as.h>
#include <vm/anon.h>

/*
 * Convert a vnode into an lxpr_mnt_t
 */
#define	VTOLXPM(vp)	((lxpr_mnt_t *)(vp)->v_vfsp->vfs_data)

/*
 * convert a vnode into an lxpr_node
 */
#define	VTOLXP(vp)	((lxpr_node_t *)(vp)->v_data)

/*
 * convert a lxprnode into a vnode
 */
#define	LXPTOV(lxpnp)	((lxpnp)->lxpr_vnode)

/*
 * convert a lxpr_node into zone for fs
 */
#define	LXPTOZ(lxpnp) \
	(((lxpr_mnt_t *)(lxpnp)->lxpr_vnode->v_vfsp->vfs_data)->lxprm_zone)

#define	LXPNSIZ		256	/* max size of lx /proc file name entries */

/*
 * Pretend that a directory entry takes 16 bytes
 */
#define	LXPR_SDSIZE	16

/*
 * Node/file types for lx /proc files
 * (directories and files contained therein).
 */
typedef enum lxpr_nodetype {
	LXPR_INVALID,		/* nodes start at 1	*/
	LXPR_PROCDIR,		/* /proc		*/
	LXPR_PIDDIR,		/* /proc/<pid>		*/
	LXPR_PID_AUXV,		/* /proc/<pid>/auxv	*/
	LXPR_PID_CGROUP,	/* /proc/<pid>/cgroup	*/
	LXPR_PID_CMDLINE,	/* /proc/<pid>/cmdline	*/
	LXPR_PID_COMM,		/* /proc/<pid>/comm	*/
	LXPR_PID_CPU,		/* /proc/<pid>/cpu	*/
	LXPR_PID_CURDIR,	/* /proc/<pid>/cwd	*/
	LXPR_PID_ENV,		/* /proc/<pid>/environ	*/
	LXPR_PID_EXE,		/* /proc/<pid>/exe	*/
	LXPR_PID_LIMITS,	/* /proc/<pid>/limits	*/
	LXPR_PID_LOGINUID,	/* /proc/<pid>/loginuid	*/
	LXPR_PID_MAPS,		/* /proc/<pid>/maps	*/
	LXPR_PID_MEM,		/* /proc/<pid>/mem	*/
	LXPR_PID_MOUNTINFO,	/* /proc/<pid>/mountinfo */
	LXPR_PID_MOUNTS,	/* /proc/<pid>/mounts	*/
	LXPR_PID_OOM_SCR_ADJ,	/* /proc/<pid>/oom_score_adj	*/
	LXPR_PID_PERSONALITY,	/* /proc/<pid>/personality	*/
	LXPR_PID_ROOTDIR,	/* /proc/<pid>/root	*/
	LXPR_PID_STAT,		/* /proc/<pid>/stat	*/
	LXPR_PID_STATM,		/* /proc/<pid>/statm	*/
	LXPR_PID_STATUS,	/* /proc/<pid>/status	*/
	LXPR_PID_TASKDIR,	/* /proc/<pid>/task	*/
	LXPR_PID_TASK_IDDIR,	/* /proc/<pid>/task/<tid>		*/
	LXPR_PID_FDDIR,		/* /proc/<pid>/fd	*/
	LXPR_PID_FD_FD,		/* /proc/<pid>/fd/nn	*/
	LXPR_PID_TID_AUXV,	/* /proc/<pid>/task/<tid>/auxv		*/
	LXPR_PID_TID_CGROUP,	/* /proc/<pid>/task/<tid>/cgroup	*/
	LXPR_PID_TID_CMDLINE,	/* /proc/<pid>/task/<tid>/cmdline	*/
	LXPR_PID_TID_COMM,	/* /proc/<pid>/task/<tid>/comm		*/
	LXPR_PID_TID_CPU,	/* /proc/<pid>/task/<tid>/cpu		*/
	LXPR_PID_TID_CURDIR,	/* /proc/<pid>/task/<tid>/cwd		*/
	LXPR_PID_TID_ENV,	/* /proc/<pid>/task/<tid>/environ	*/
	LXPR_PID_TID_EXE,	/* /proc/<pid>/task/<tid>/exe		*/
	LXPR_PID_TID_LIMITS,	/* /proc/<pid>/task/<tid>/limits	*/
	LXPR_PID_TID_LOGINUID,	/* /proc/<pid>/task/<tid>/loginuid	*/
	LXPR_PID_TID_MAPS,	/* /proc/<pid>/task/<tid>/maps		*/
	LXPR_PID_TID_MEM,	/* /proc/<pid>/task/<tid>/mem		*/
	LXPR_PID_TID_MOUNTINFO,	/* /proc/<pid>/task/<tid>/mountinfo	*/
	LXPR_PID_TID_OOM_SCR_ADJ, /* /proc/<pid>/task/<tid>/oom_score_adj */
	LXPR_PID_TID_PERSONALITY, /* /proc/<pid>/task/<tid>/personality */
	LXPR_PID_TID_ROOTDIR,	/* /proc/<pid>/task/<tid>/root		*/
	LXPR_PID_TID_STAT,	/* /proc/<pid>/task/<tid>/stat		*/
	LXPR_PID_TID_STATM,	/* /proc/<pid>/task/<tid>/statm		*/
	LXPR_PID_TID_STATUS,	/* /proc/<pid>/task/<tid>/status	*/
	LXPR_PID_TID_FDDIR,	/* /proc/<pid>/task/<tid>/fd		*/
	LXPR_PID_TID_FD_FD,	/* /proc/<pid>/task/<tid>/fd/nn		*/
	LXPR_CGROUPS,		/* /proc/cgroups	*/
	LXPR_CMDLINE,		/* /proc/cmdline	*/
	LXPR_CPUINFO,		/* /proc/cpuinfo	*/
	LXPR_DEVICES,		/* /proc/devices	*/
	LXPR_DISKSTATS,		/* /proc/diskstats	*/
	LXPR_DMA,		/* /proc/dma		*/
	LXPR_FILESYSTEMS,	/* /proc/filesystems	*/
	LXPR_INTERRUPTS,	/* /proc/interrupts	*/
	LXPR_IOPORTS,		/* /proc/ioports	*/
	LXPR_KCORE,		/* /proc/kcore		*/
	LXPR_KMSG,		/* /proc/kmsg		*/
	LXPR_LOADAVG,		/* /proc/loadavg	*/
	LXPR_MEMINFO,		/* /proc/meminfo	*/
	LXPR_MODULES,		/* /proc/modules	*/
	LXPR_MOUNTS,		/* /proc/mounts		*/
	LXPR_NETDIR,		/* /proc/net		*/
	LXPR_NET_ARP,		/* /proc/net/arp	*/
	LXPR_NET_DEV,		/* /proc/net/dev	*/
	LXPR_NET_DEV_MCAST,	/* /proc/net/dev_mcast	*/
	LXPR_NET_IF_INET6,	/* /proc/net/if_inet6	*/
	LXPR_NET_IGMP,		/* /proc/net/igmp	*/
	LXPR_NET_IP_MR_CACHE,	/* /proc/net/ip_mr_cache */
	LXPR_NET_IP_MR_VIF,	/* /proc/net/ip_mr_vif	*/
	LXPR_NET_IPV6_ROUTE,	/* /proc/net/ipv6_route	*/
	LXPR_NET_MCFILTER,	/* /proc/net/mcfilter	*/
	LXPR_NET_NETSTAT,	/* /proc/net/netstat	*/
	LXPR_NET_RAW,		/* /proc/net/raw	*/
	LXPR_NET_ROUTE,		/* /proc/net/route	*/
	LXPR_NET_RPC,		/* /proc/net/rpc	*/
	LXPR_NET_RT_CACHE,	/* /proc/net/rt_cache	*/
	LXPR_NET_SOCKSTAT,	/* /proc/net/sockstat	*/
	LXPR_NET_SNMP,		/* /proc/net/snmp	*/
	LXPR_NET_STAT,		/* /proc/net/stat	*/
	LXPR_NET_TCP,		/* /proc/net/tcp	*/
	LXPR_NET_TCP6,		/* /proc/net/tcp6	*/
	LXPR_NET_UDP,		/* /proc/net/udp	*/
	LXPR_NET_UDP6,		/* /proc/net/udp6	*/
	LXPR_NET_UNIX,		/* /proc/net/unix	*/
	LXPR_PARTITIONS,	/* /proc/partitions	*/
	LXPR_SELF,		/* /proc/self		*/
	LXPR_STAT,		/* /proc/stat		*/
	LXPR_SWAPS,		/* /proc/swaps		*/
	LXPR_SYSDIR,		/* /proc/sys/		*/
	LXPR_SYS_FSDIR,		/* /proc/sys/fs/	*/
	LXPR_SYS_FS_FILEMAX,	/* /proc/sys/fs/file-max */
	LXPR_SYS_FS_INOTIFYDIR,	/* /proc/sys/fs/inotify	*/
	LXPR_SYS_FS_INOTIFY_MAX_QUEUED_EVENTS,	/* inotify/max_queued_events */
	LXPR_SYS_FS_INOTIFY_MAX_USER_INSTANCES,	/* inotify/max_user_instances */
	LXPR_SYS_FS_INOTIFY_MAX_USER_WATCHES,	/* inotify/max_user_watches */
	LXPR_SYS_KERNELDIR,	/* /proc/sys/kernel/	*/
	LXPR_SYS_KERNEL_CAPLCAP,	/* /proc/sys/kernel/cap_last_cap */
	LXPR_SYS_KERNEL_COREPATT,	/* /proc/sys/kernel/core_pattern */
	LXPR_SYS_KERNEL_HOSTNAME,	/* /proc/sys/kernel/hostname */
	LXPR_SYS_KERNEL_MSGMNI,	/* /proc/sys/kernel/msgmni */
	LXPR_SYS_KERNEL_NGROUPS_MAX,	/* /proc/sys/kernel/ngroups_max */
	LXPR_SYS_KERNEL_OSREL,	/* /proc/sys/kernel/osrelease */
	LXPR_SYS_KERNEL_PID_MAX,	/* /proc/sys/kernel/pid_max */
	LXPR_SYS_KERNEL_RANDDIR,	/* /proc/sys/kernel/random */
	LXPR_SYS_KERNEL_RAND_BOOTID, /* /proc/sys/kernel/random/boot_id */
	LXPR_SYS_KERNEL_SEM,		/* /proc/sys/kernel/sem		*/
	LXPR_SYS_KERNEL_SHMALL,		/* /proc/sys/kernel/shmall	*/
	LXPR_SYS_KERNEL_SHMMAX,		/* /proc/sys/kernel/shmmax	*/
	LXPR_SYS_KERNEL_SHMMNI,		/* /proc/sys/kernel/shmmni	*/
	LXPR_SYS_KERNEL_THREADS_MAX,	/* /proc/sys/kernel/threads-max */
	LXPR_SYS_NETDIR,		/* /proc/sys/net		*/
	LXPR_SYS_NET_COREDIR,		/* /proc/sys/net/core		*/
	LXPR_SYS_NET_CORE_SOMAXCON,	/* /proc/sys/net/core/somaxconn	*/
	LXPR_SYS_NET_IPV4DIR,		/* /proc/sys/net/ipv4		*/
	LXPR_SYS_NET_IPV4_IP_LPORT_RANGE, /* .../net/ipv4/ip_local_port_range */
	LXPR_SYS_NET_IPV4_TCP_FIN_TO,	/* /proc/sys/net/ipv4/tcp_fin_timeout */
	LXPR_SYS_NET_IPV4_TCP_KA_INT,	/* .../net/ipv4/tcp_keepalive_intvl */
	LXPR_SYS_NET_IPV4_TCP_KA_TIM,	/* .../net/ipv4/tcp_keepalive_time */
	LXPR_SYS_NET_IPV4_TCP_MAX_SYN_BL, /* .../net/ipv4/tcp_max_syn_backlog */
	LXPR_SYS_NET_IPV4_TCP_RMEM,	/* /proc/sys/net/ipv4/tcp_rmem */
	LXPR_SYS_NET_IPV4_TCP_SACK,	/* /proc/sys/net/ipv4/tcp_sack */
	LXPR_SYS_NET_IPV4_TCP_WINSCALE,	/* .../net/ipv4/tcp_window_scaling */
	LXPR_SYS_NET_IPV4_TCP_WMEM,	/* /proc/sys/net/ipv4/tcp_wmem */
	LXPR_SYS_VMDIR,			/* /proc/sys/vm			*/
	LXPR_SYS_VM_MAX_MAP_CNT,	/* /proc/sys/vm/max_map_count	*/
	LXPR_SYS_VM_MINFR_KB,		/* /proc/sys/vm/min_free_kbytes	*/
	LXPR_SYS_VM_NHUGEP,		/* /proc/sys/vm/nr_hugepages	*/
	LXPR_SYS_VM_OVERCOMMIT_MEM,	/* /proc/sys/vm/overcommit_memory */
	LXPR_SYS_VM_SWAPPINESS,		/* /proc/sys/vm/swappiness	*/
	LXPR_UPTIME,		/* /proc/uptime		*/
	LXPR_VERSION,		/* /proc/version	*/
	LXPR_VMSTAT,		/* /proc/vmstat		*/
	LXPR_NFILES		/* number of lx /proc file types */
} lxpr_nodetype_t;


/*
 * Number of fds allowed for in the inode number calculation
 * per process (if a process has more fds then inode numbers
 * may be duplicated)
 */
#define	LXPR_FD_PERPROC 2000

/*
 * Linux sector size for /proc/diskstats
 */
#define	LXPR_SECTOR_SIZE	512

/*
 * external dirent characteristics
 */
typedef struct {
	lxpr_nodetype_t	d_type;
	char		*d_name;
} lxpr_dirent_t;

/*
 * This is the lxprocfs private data object
 * which is attached to v_data in the vnode structure
 */
typedef struct lxpr_node {
	lxpr_nodetype_t	lxpr_type;	/* type of this node 		*/
	vnode_t		*lxpr_vnode;	/* vnode for the node		*/
	vnode_t		*lxpr_parent;	/* parent directory		*/
	vnode_t		*lxpr_realvp;	/* real vnode, file in dirs	*/
	timestruc_t	lxpr_time;	/* creation etc time for file	*/
	mode_t		lxpr_mode;	/* file mode bits		*/
	uid_t		lxpr_uid;	/* file owner			*/
	gid_t		lxpr_gid;	/* file group owner		*/
	pid_t		lxpr_pid;	/* pid of proc referred to	*/
	uint_t		lxpr_desc;	/* addl. descriptor (fd or tid)	*/
	ino_t		lxpr_ino;	/* node id 			*/
} lxpr_node_t;

struct zone;    /* forward declaration */

/*
 * This is the lxprocfs private data object
 * which is attached to vfs_data in the vfs structure
 */
typedef struct lxpr_mnt {
	lxpr_node_t	*lxprm_node;	/* node at root of proc mount */
	struct zone	*lxprm_zone;	/* zone for this mount */
	ldi_ident_t	lxprm_li;	/* ident for ldi */
} lxpr_mnt_t;

extern vnodeops_t	*lxpr_vnodeops;
extern int		nproc_highbit;	/* highbit(v.v_nproc)		*/

typedef struct mounta	mounta_t;

extern void lxpr_initnodecache();
extern void lxpr_fininodecache();
extern void lxpr_initrootnode(lxpr_node_t **, vfs_t *);
extern ino_t lxpr_inode(lxpr_nodetype_t, pid_t, int);
extern ino_t lxpr_parentinode(lxpr_node_t *);
extern boolean_t lxpr_is_writable(lxpr_nodetype_t);
extern lxpr_node_t *lxpr_getnode(vnode_t *, lxpr_nodetype_t, proc_t *, int);
extern void lxpr_freenode(lxpr_node_t *);
extern vnode_t *lxpr_lookup_fdnode(vnode_t *, const char *);
extern int lxpr_readlink_fdnode(lxpr_node_t *, char *, size_t);

typedef struct lxpr_uiobuf {
	uio_t *uiop;
	char *buffer;
	uint32_t buffsize;
	char *pos;
	size_t beg;
	int error;
} lxpr_uiobuf_t;

extern lxpr_uiobuf_t *lxpr_uiobuf_new(uio_t *);
extern void lxpr_uiobuf_free(lxpr_uiobuf_t *);
extern int lxpr_uiobuf_flush(lxpr_uiobuf_t *);
extern void lxpr_uiobuf_seek(lxpr_uiobuf_t *, offset_t);
extern boolean_t lxpr_uiobuf_nonblock(lxpr_uiobuf_t *);
extern void lxpr_uiobuf_write(lxpr_uiobuf_t *, const char *, size_t);
extern void lxpr_uiobuf_printf(lxpr_uiobuf_t *, const char *, ...);
extern void lxpr_uiobuf_seterr(lxpr_uiobuf_t *, int);

extern int lxpr_core_path_l2s(const char *, char *, size_t);
extern int lxpr_core_path_s2l(const char *, char *, size_t);

typedef enum lxpr_zombok {
	NO_ZOMB = 0,
	ZOMB_OK
} zombok_t;

extern proc_t *lxpr_lock(lxpr_node_t *, zombok_t);
extern proc_t *lxpr_lock_pid(lxpr_node_t *, pid_t, zombok_t, kthread_t **);
extern void lxpr_unlock(proc_t *);
extern netstack_t *lxpr_netstack(lxpr_node_t *);
extern void lxpr_fixpid(zone_t *, proc_t *, pid_t *, pid_t *);

#ifdef	__cplusplus
}
#endif

#ifndef islower
#define	islower(x)	(((unsigned)(x) >= 'a') && ((unsigned)(x) <= 'z'))
#endif
#ifndef toupper
#define	toupper(x)	(islower(x) ? (x) - 'a' + 'A' : (x))
#endif

#endif /* _LX_PROC_H */
