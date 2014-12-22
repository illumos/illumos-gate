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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef	_LXPROC_H
#define	_LXPROC_H

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
	LXPR_PROCDIR,		/* /proc		*/
	LXPR_PIDDIR,		/* /proc/<pid>		*/
	LXPR_PID_CMDLINE,	/* /proc/<pid>/cmdline	*/
	LXPR_PID_CPU,		/* /proc/<pid>/cpu	*/
	LXPR_PID_CURDIR,	/* /proc/<pid>/cwd	*/
	LXPR_PID_ENV,		/* /proc/<pid>/environ	*/
	LXPR_PID_EXE,		/* /proc/<pid>/exe	*/
	LXPR_PID_LIMITS,	/* /proc/<pid>/limits	*/
	LXPR_PID_MAPS,		/* /proc/<pid>/maps	*/
	LXPR_PID_MEM,		/* /proc/<pid>/mem	*/
	LXPR_PID_MOUNTINFO,	/* /proc/<pid>/mountinfo */
	LXPR_PID_ROOTDIR,	/* /proc/<pid>/root	*/
	LXPR_PID_STAT,		/* /proc/<pid>/stat	*/
	LXPR_PID_STATM,		/* /proc/<pid>/statm	*/
	LXPR_PID_STATUS,	/* /proc/<pid>/status	*/
	LXPR_PID_FDDIR,		/* /proc/<pid>/fd	*/
	LXPR_PID_FD_FD,		/* /proc/<pid>/fd/nn	*/
	LXPR_CMDLINE,		/* /proc/cmdline	*/
	LXPR_CPUINFO,		/* /proc/cpuinfo	*/
	LXPR_DEVICES,		/* /proc/devices	*/
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
	LXPR_NET_UDP,		/* /proc/net/udp	*/
	LXPR_NET_UNIX,		/* /proc/net/unix	*/
	LXPR_PARTITIONS,	/* /proc/partitions	*/
	LXPR_SELF,		/* /proc/self		*/
	LXPR_STAT,		/* /proc/stat		*/
	LXPR_SWAPS,		/* /proc/swaps		*/
	LXPR_SYSDIR,		/* /proc/sys/		*/
	LXPR_SYS_FSDIR,		/* /proc/sys/fs/	*/
	LXPR_SYS_FS_INOTIFYDIR,	/* /proc/sys/fs/inotify	*/
	LXPR_SYS_FS_INOTIFY_MAX_QUEUED_EVENTS,	/* inotify/max_queued_events */
	LXPR_SYS_FS_INOTIFY_MAX_USER_INSTANCES,	/* inotify/max_user_instances */
	LXPR_SYS_FS_INOTIFY_MAX_USER_WATCHES,	/* inotify/max_user_watches */
	LXPR_SYS_KERNELDIR,	/* /proc/sys/kernel/	*/
	LXPR_SYS_KERNEL_HOSTNAME,	/* /proc/sys/kernel/hostname */
	LXPR_SYS_KERNEL_MSGMNI,	/* /proc/sys/kernel/msgmni */
	LXPR_SYS_KERNEL_NGROUPS_MAX,	/* /proc/sys/kernel/ngroups_max */
	LXPR_SYS_KERNEL_PID_MAX,	/* /proc/sys/kernel/pid_max */
	LXPR_SYS_KERNEL_SHMMAX,	/* /proc/sys/kernel/shmmax */
	LXPR_SYS_KERNEL_THREADS_MAX,	/* /proc/sys/kernel/threads-max */
	LXPR_UPTIME,		/* /proc/uptime		*/
	LXPR_VERSION,		/* /proc/version	*/
	LXPR_NFILES		/* number of lx /proc file types */
} lxpr_nodetype_t;


/*
 * Number of fds allowed for in the inode number calculation
 * per process (if a process has more fds then inode numbers
 * may be duplicated)
 */
#define	LXPR_FD_PERPROC 2000

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
	ino_t		lxpr_ino;	/* node id 			*/
	ldi_handle_t	lxpr_cons_ldih; /* ldi handle for console device */
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
extern lxpr_node_t *lxpr_getnode(vnode_t *, lxpr_nodetype_t, proc_t *, int);
extern void lxpr_freenode(lxpr_node_t *);

typedef struct lxpr_uiobuf lxpr_uiobuf_t;
extern lxpr_uiobuf_t *lxpr_uiobuf_new(uio_t *);
extern void lxpr_uiobuf_free(lxpr_uiobuf_t *);
extern int lxpr_uiobuf_flush(lxpr_uiobuf_t *);
extern void lxpr_uiobuf_seek(lxpr_uiobuf_t *, offset_t);
extern boolean_t lxpr_uiobuf_nonblock(lxpr_uiobuf_t *);
extern void lxpr_uiobuf_write(lxpr_uiobuf_t *, const char *, size_t);
extern void lxpr_uiobuf_printf(lxpr_uiobuf_t *, const char *, ...);
extern void lxpr_uiobuf_seterr(lxpr_uiobuf_t *, int);

proc_t *lxpr_lock(pid_t);
void lxpr_unlock(proc_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _LXPROC_H */
