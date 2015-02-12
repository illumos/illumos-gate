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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

/*
 * lxproc -- a loosely Linux-compatible /proc
 *
 * The aspiration here is to provide something that sufficiently approximates
 * the Linux /proc implementation for purposes of offering some compatibility
 * for simple Linux /proc readers (e.g., ps/top/htop).  However, it is not
 * intended to exactly mimic Linux semantics; when choosing between offering
 * compatibility and telling the truth, we emphatically pick the truth.  A
 * particular glaring example of this is the Linux notion of "tasks" (that is,
 * threads), which -- due to historical misadventures on Linux -- allocate their
 * identifiers from the process identifier space.  (That is, each thread has in
 * effect a pid.)  Some Linux /proc readers have come to depend on this
 * attribute, and become confused when threads appear with proper identifiers,
 * so we simply opt for the pre-2.6 behavior, and do not present the tasks
 * directory at all.  Similarly, when choosing between offering compatibility
 * and remaining consistent with our broader security model, we (obviously)
 * choose security over compatibility.  In short, this is meant to be a best
 * effort -- no more.
 */

#include <sys/cpupart.h>
#include <sys/cpuvar.h>
#include <sys/session.h>
#include <sys/vmparam.h>
#include <sys/mman.h>
#include <vm/rm.h>
#include <vm/seg_vn.h>
#include <sys/sdt.h>
#include <lx_signum.h>
#include <sys/strlog.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/lx_brand.h>
#include <sys/x86_archext.h>
#include <sys/archsystm.h>
#include <sys/fp.h>
#include <sys/pool_pset.h>
#include <sys/pset.h>
#include <sys/zone.h>
#include <sys/pghw.h>
#include <sys/vfs_opreg.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/rctl.h>
#include <sys/kstat.h>
#include <sys/lx_misc.h>
#include <sys/cred_impl.h>
#include <sys/tihdr.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <inet/tcp.h>
#include <inet/udp_impl.h>
#include <inet/ipclassifier.h>
#include <sys/socketvar.h>
#include <fs/sockfs/socktpi.h>

/* Dependent on procfs */
extern kthread_t *prchoose(proc_t *);
extern int prreadargv(proc_t *, char *, size_t, size_t *);

#include "lx_proc.h"

extern pgcnt_t swapfs_minfree;
extern time_t boot_time;

/*
 * Pointer to the vnode ops vector for this fs.
 * This is instantiated in lxprinit() in lxpr_vfsops.c
 */
vnodeops_t *lxpr_vnodeops;

static int lxpr_open(vnode_t **, int, cred_t *, caller_context_t *);
static int lxpr_close(vnode_t *, int, int, offset_t, cred_t *,
    caller_context_t *);
static int lxpr_read(vnode_t *, uio_t *, int, cred_t *, caller_context_t *);
static int lxpr_getattr(vnode_t *, vattr_t *, int, cred_t *,
    caller_context_t *);
static int lxpr_access(vnode_t *, int, int, cred_t *, caller_context_t *);
static int lxpr_lookup(vnode_t *, char *, vnode_t **,
    pathname_t *, int, vnode_t *, cred_t *, caller_context_t *, int *,
    pathname_t *);
static int lxpr_readdir(vnode_t *, uio_t *, cred_t *, int *,
    caller_context_t *, int);
static int lxpr_readlink(vnode_t *, uio_t *, cred_t *, caller_context_t *);
static int lxpr_readlink_pid_fd(lxpr_node_t *lxpnp, char *bp, size_t len);
static int lxpr_cmp(vnode_t *, vnode_t *, caller_context_t *);
static int lxpr_realvp(vnode_t *, vnode_t **, caller_context_t *);
static int lxpr_sync(void);
static void lxpr_inactive(vnode_t *, cred_t *, caller_context_t *);

static vnode_t *lxpr_lookup_procdir(vnode_t *, char *);
static vnode_t *lxpr_lookup_piddir(vnode_t *, char *);
static vnode_t *lxpr_lookup_not_a_dir(vnode_t *, char *);
static vnode_t *lxpr_lookup_fddir(vnode_t *, char *);
static vnode_t *lxpr_lookup_netdir(vnode_t *, char *);
static vnode_t *lxpr_lookup_sysdir(vnode_t *, char *);
static vnode_t *lxpr_lookup_sys_fsdir(vnode_t *, char *);
static vnode_t *lxpr_lookup_sys_fs_inotifydir(vnode_t *, char *);
static vnode_t *lxpr_lookup_sys_kerneldir(vnode_t *, char *);

static int lxpr_readdir_procdir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_piddir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_not_a_dir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_fddir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_netdir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_sysdir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_sys_fsdir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_sys_fs_inotifydir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_sys_kerneldir(lxpr_node_t *, uio_t *, int *);

static void lxpr_read_invalid(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_empty(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_cpuinfo(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_isdir(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_fd(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_kmsg(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_loadavg(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_meminfo(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_mounts(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_partitions(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_stat(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_swaps(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_uptime(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_version(lxpr_node_t *, lxpr_uiobuf_t *);

static void lxpr_read_pid_cmdline(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_limits(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_maps(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_mountinfo(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_stat(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_statm(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_status(lxpr_node_t *, lxpr_uiobuf_t *);

static void lxpr_read_net_arp(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_dev(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_dev_mcast(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_if_inet6(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_igmp(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_ip_mr_cache(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_ip_mr_vif(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_ipv6_route(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_mcfilter(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_netstat(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_raw(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_route(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_rpc(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_rt_cache(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_sockstat(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_snmp(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_stat(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_tcp(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_tcp6(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_udp(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_udp6(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_unix(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_sys_fs_inotify_max_queued_events(lxpr_node_t *,
    lxpr_uiobuf_t *);
static void lxpr_read_sys_fs_inotify_max_user_instances(lxpr_node_t *,
    lxpr_uiobuf_t *);
static void lxpr_read_sys_fs_inotify_max_user_watches(lxpr_node_t *,
    lxpr_uiobuf_t *);
static void lxpr_read_sys_kernel_hostname(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_sys_kernel_msgmni(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_sys_kernel_ngroups_max(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_sys_kernel_pid_max(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_sys_kernel_shmmax(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_sys_kernel_threads_max(lxpr_node_t *, lxpr_uiobuf_t *);

/*
 * Simple conversion
 */
#define	btok(x)	((x) >> 10)			/* bytes to kbytes */
#define	ptok(x)	((x) << (PAGESHIFT - 10))	/* pages to kbytes */

extern rctl_hndl_t rc_zone_msgmni;
extern rctl_hndl_t rc_zone_shmmax;
#define	FOURGB	4294967295

/*
 * The maximum length of the concatenation of argument vector strings we
 * will return to the user via the branded procfs:
 */
int lxpr_maxargvlen = 4096;

/*
 * The lx /proc vnode operations vector
 */
const fs_operation_def_t lxpr_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = lxpr_open },
	VOPNAME_CLOSE,		{ .vop_close = lxpr_close },
	VOPNAME_READ,		{ .vop_read = lxpr_read },
	VOPNAME_GETATTR,	{ .vop_getattr = lxpr_getattr },
	VOPNAME_ACCESS,		{ .vop_access = lxpr_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = lxpr_lookup },
	VOPNAME_READDIR,	{ .vop_readdir = lxpr_readdir },
	VOPNAME_READLINK,	{ .vop_readlink = lxpr_readlink },
	VOPNAME_FSYNC,		{ .error = lxpr_sync },
	VOPNAME_SEEK,		{ .error = lxpr_sync },
	VOPNAME_INACTIVE,	{ .vop_inactive = lxpr_inactive },
	VOPNAME_CMP,		{ .vop_cmp = lxpr_cmp },
	VOPNAME_REALVP,		{ .vop_realvp = lxpr_realvp },
	NULL,			NULL
};


/*
 * file contents of an lx /proc directory.
 */
static lxpr_dirent_t lx_procdir[] = {
	{ LXPR_CMDLINE,		"cmdline" },
	{ LXPR_CPUINFO,		"cpuinfo" },
	{ LXPR_DEVICES,		"devices" },
	{ LXPR_DMA,		"dma" },
	{ LXPR_FILESYSTEMS,	"filesystems" },
	{ LXPR_INTERRUPTS,	"interrupts" },
	{ LXPR_IOPORTS,		"ioports" },
	{ LXPR_KCORE,		"kcore" },
	{ LXPR_KMSG,		"kmsg" },
	{ LXPR_LOADAVG,		"loadavg" },
	{ LXPR_MEMINFO,		"meminfo" },
	{ LXPR_MODULES,		"modules" },
	{ LXPR_MOUNTS,		"mounts" },
	{ LXPR_NETDIR,		"net" },
	{ LXPR_PARTITIONS,	"partitions" },
	{ LXPR_SELF,		"self" },
	{ LXPR_STAT,		"stat" },
	{ LXPR_SWAPS,		"swaps" },
	{ LXPR_SYSDIR,		"sys" },
	{ LXPR_UPTIME,		"uptime" },
	{ LXPR_VERSION,		"version" }
};

#define	PROCDIRFILES	(sizeof (lx_procdir) / sizeof (lx_procdir[0]))

/*
 * Contents of an lx /proc/<pid> directory.
 */
static lxpr_dirent_t piddir[] = {
	{ LXPR_PID_CMDLINE,	"cmdline" },
	{ LXPR_PID_CPU,		"cpu" },
	{ LXPR_PID_CURDIR,	"cwd" },
	{ LXPR_PID_ENV,		"environ" },
	{ LXPR_PID_EXE,		"exe" },
	{ LXPR_PID_LIMITS,	"limits" },
	{ LXPR_PID_MAPS,	"maps" },
	{ LXPR_PID_MEM,		"mem" },
	{ LXPR_PID_MOUNTINFO,	"mountinfo" },
	{ LXPR_PID_ROOTDIR,	"root" },
	{ LXPR_PID_STAT,	"stat" },
	{ LXPR_PID_STATM,	"statm" },
	{ LXPR_PID_STATUS,	"status" },
	{ LXPR_PID_FDDIR,	"fd" }
};

#define	PIDDIRFILES	(sizeof (piddir) / sizeof (piddir[0]))

#define	LX_RLIM_INFINITY	0xFFFFFFFFFFFFFFFF

#define	RCTL_INFINITE(x) \
	((x->rcv_flagaction & RCTL_LOCAL_MAXIMAL) && \
	(x->rcv_flagaction & RCTL_GLOBAL_INFINITE))

typedef struct lxpr_rlimtab {
	char	*rlim_name;	/* limit name */
	char	*rlim_unit;	/* limit unit */
	char	*rlim_rctl;	/* rctl source */
} lxpr_rlimtab_t;

static lxpr_rlimtab_t lxpr_rlimtab[] = {
	{ "Max cpu time",	"seconds",	"process.max-cpu-time" },
	{ "Max file size",	"bytes",	"process.max-file-size" },
	{ "Max data size",	"bytes",	"process.max-data-size" },
	{ "Max stack size",	"bytes",	"process.max-stack-size" },
	{ "Max core file size",	"bytes",	"process.max-core-size" },
	{ "Max resident set",	"bytes",	"zone.max-physical-memory" },
	{ "Max processes",	"processes",	"zone.max-lwps" },
	{ "Max open files",	"files",	"process.max-file-descriptor" },
	{ "Max locked memory",	"bytes",	"zone.max-locked-memory" },
	{ "Max address space",	"bytes",	"process.max-address-space" },
	{ "Max file locks",	"locks",	NULL },
	{ "Max pending signals",	"signals",
		"process.max-sigqueue-size" },
	{ "Max msgqueue size",	"bytes",	"process.max-msg-messages" },
	{ NULL, NULL, NULL }
};


/*
 * contents of lx /proc/net directory
 */
static lxpr_dirent_t netdir[] = {
	{ LXPR_NET_ARP,		"arp" },
	{ LXPR_NET_DEV,		"dev" },
	{ LXPR_NET_DEV_MCAST,	"dev_mcast" },
	{ LXPR_NET_IF_INET6,	"if_inet6" },
	{ LXPR_NET_IGMP,	"igmp" },
	{ LXPR_NET_IP_MR_CACHE,	"ip_mr_cache" },
	{ LXPR_NET_IP_MR_VIF,	"ip_mr_vif" },
	{ LXPR_NET_IPV6_ROUTE,	"ipv6_route" },
	{ LXPR_NET_MCFILTER,	"mcfilter" },
	{ LXPR_NET_NETSTAT,	"netstat" },
	{ LXPR_NET_RAW,		"raw" },
	{ LXPR_NET_ROUTE,	"route" },
	{ LXPR_NET_RPC,		"rpc" },
	{ LXPR_NET_RT_CACHE,	"rt_cache" },
	{ LXPR_NET_SOCKSTAT,	"sockstat" },
	{ LXPR_NET_SNMP,	"snmp" },
	{ LXPR_NET_STAT,	"stat" },
	{ LXPR_NET_TCP,		"tcp" },
	{ LXPR_NET_TCP6,	"tcp6" },
	{ LXPR_NET_UDP,		"udp" },
	{ LXPR_NET_UDP6,	"udp6" },
	{ LXPR_NET_UNIX,	"unix" }
};

#define	NETDIRFILES	(sizeof (netdir) / sizeof (netdir[0]))

/*
 * contents of /proc/sys directory
 */
static lxpr_dirent_t sysdir[] = {
	{ LXPR_SYS_FSDIR,	"fs" },
	{ LXPR_SYS_KERNELDIR,	"kernel" },
};

#define	SYSDIRFILES	(sizeof (sysdir) / sizeof (sysdir[0]))

/*
 * contents of /proc/sys/fs directory
 */
static lxpr_dirent_t sys_fsdir[] = {
	{ LXPR_SYS_FS_INOTIFYDIR,	"inotify" },
};

#define	SYS_FSDIRFILES (sizeof (sys_fsdir) / sizeof (sys_fsdir[0]))

/*
 * contents of /proc/sys/fs/inotify directory
 */
static lxpr_dirent_t sys_fs_inotifydir[] = {
	{ LXPR_SYS_FS_INOTIFY_MAX_QUEUED_EVENTS,	"max_queued_events" },
	{ LXPR_SYS_FS_INOTIFY_MAX_USER_INSTANCES,	"max_user_instances" },
	{ LXPR_SYS_FS_INOTIFY_MAX_USER_WATCHES,		"max_user_watches" },
};

#define	SYS_FS_INOTIFYDIRFILES \
	(sizeof (sys_fs_inotifydir) / sizeof (sys_fs_inotifydir[0]))

/*
 * contents of /proc/sys/kernel directory
 */
static lxpr_dirent_t sys_kerneldir[] = {
	{ LXPR_SYS_KERNEL_HOSTNAME,	"hostname" },
	{ LXPR_SYS_KERNEL_MSGMNI,	"msgmni" },
	{ LXPR_SYS_KERNEL_NGROUPS_MAX,	"ngroups_max" },
	{ LXPR_SYS_KERNEL_PID_MAX,	"pid_max" },
	{ LXPR_SYS_KERNEL_SHMMAX,	"shmmax" },
	{ LXPR_SYS_KERNEL_THREADS_MAX,	"threads-max" },
};

#define	SYS_KERNELDIRFILES (sizeof (sys_kerneldir) / sizeof (sys_kerneldir[0]))

/*
 * lxpr_open(): Vnode operation for VOP_OPEN()
 */
static int
lxpr_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	vnode_t		*vp = *vpp;
	lxpr_node_t	*lxpnp = VTOLXP(vp);
	lxpr_nodetype_t	type = lxpnp->lxpr_type;
	vnode_t		*rvp;
	int		error = 0;

	/*
	 * We only allow reading in this file systrem
	 */
	if (flag & FWRITE)
		return (EROFS);

	/*
	 * If we are opening an underlying file only allow regular files,
	 * fifos or sockets; reject the open for anything else.
	 * Just do it if we are opening the current or root directory.
	 */
	if (lxpnp->lxpr_realvp != NULL) {
		rvp = lxpnp->lxpr_realvp;

		if (type == LXPR_PID_FD_FD && rvp->v_type != VREG &&
		    rvp->v_type != VFIFO && rvp->v_type != VSOCK) {
			error = EACCES;
		} else {
			if (type == LXPR_PID_FD_FD && rvp->v_type == VFIFO) {
				/*
				 * This flag lets the fifo open know that
				 * we're using proc/fd to open a fd which we
				 * already have open. Otherwise, the fifo might
				 * reject an open if the other end has closed.
				 */
				flag |= FKLYR;
			}
			/*
			 * Need to hold rvp since VOP_OPEN() may release it.
			 */
			VN_HOLD(rvp);
			error = VOP_OPEN(&rvp, flag, cr, ct);
			if (error) {
				VN_RELE(rvp);
			} else {
				*vpp = rvp;
				VN_RELE(vp);
			}
		}
	}

	return (error);
}


/*
 * lxpr_close(): Vnode operation for VOP_CLOSE()
 */
/* ARGSUSED */
static int
lxpr_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ct)
{
	lxpr_node_t	*lxpr = VTOLXP(vp);
	lxpr_nodetype_t	type = lxpr->lxpr_type;

	/*
	 * we should never get here because the close is done on the realvp
	 * for these nodes
	 */
	ASSERT(type != LXPR_PID_FD_FD &&
	    type != LXPR_PID_CURDIR &&
	    type != LXPR_PID_ROOTDIR &&
	    type != LXPR_PID_EXE);

	return (0);
}

static void (*lxpr_read_function[LXPR_NFILES])() = {
	lxpr_read_isdir,		/* /proc		*/
	lxpr_read_isdir,		/* /proc/<pid>		*/
	lxpr_read_pid_cmdline,		/* /proc/<pid>/cmdline	*/
	lxpr_read_empty,		/* /proc/<pid>/cpu	*/
	lxpr_read_invalid,		/* /proc/<pid>/cwd	*/
	lxpr_read_empty,		/* /proc/<pid>/environ	*/
	lxpr_read_invalid,		/* /proc/<pid>/exe	*/
	lxpr_read_pid_limits,		/* /proc/<pid>/limits	*/
	lxpr_read_pid_maps,		/* /proc/<pid>/maps	*/
	lxpr_read_empty,		/* /proc/<pid>/mem	*/
	lxpr_read_pid_mountinfo,	/* /proc/<pid>/mountinfo */
	lxpr_read_invalid,		/* /proc/<pid>/root	*/
	lxpr_read_pid_stat,		/* /proc/<pid>/stat	*/
	lxpr_read_pid_statm,		/* /proc/<pid>/statm	*/
	lxpr_read_pid_status,		/* /proc/<pid>/status	*/
	lxpr_read_isdir,		/* /proc/<pid>/fd	*/
	lxpr_read_fd,			/* /proc/<pid>/fd/nn	*/
	lxpr_read_empty,		/* /proc/cmdline	*/
	lxpr_read_cpuinfo,		/* /proc/cpuinfo	*/
	lxpr_read_empty,		/* /proc/devices	*/
	lxpr_read_empty,		/* /proc/dma		*/
	lxpr_read_empty,		/* /proc/filesystems	*/
	lxpr_read_empty,		/* /proc/interrupts	*/
	lxpr_read_empty,		/* /proc/ioports	*/
	lxpr_read_empty,		/* /proc/kcore		*/
	lxpr_read_kmsg,			/* /proc/kmsg		*/
	lxpr_read_loadavg,		/* /proc/loadavg	*/
	lxpr_read_meminfo,		/* /proc/meminfo	*/
	lxpr_read_empty,		/* /proc/modules	*/
	lxpr_read_mounts,		/* /proc/mounts		*/
	lxpr_read_isdir,		/* /proc/net		*/
	lxpr_read_net_arp,		/* /proc/net/arp	*/
	lxpr_read_net_dev,		/* /proc/net/dev	*/
	lxpr_read_net_dev_mcast,	/* /proc/net/dev_mcast	*/
	lxpr_read_net_if_inet6,		/* /proc/net/if_inet6	*/
	lxpr_read_net_igmp,		/* /proc/net/igmp	*/
	lxpr_read_net_ip_mr_cache,	/* /proc/net/ip_mr_cache */
	lxpr_read_net_ip_mr_vif,	/* /proc/net/ip_mr_vif	*/
	lxpr_read_net_ipv6_route,	/* /proc/net/ipv6_route	*/
	lxpr_read_net_mcfilter,		/* /proc/net/mcfilter	*/
	lxpr_read_net_netstat,		/* /proc/net/netstat	*/
	lxpr_read_net_raw,		/* /proc/net/raw	*/
	lxpr_read_net_route,		/* /proc/net/route	*/
	lxpr_read_net_rpc,		/* /proc/net/rpc	*/
	lxpr_read_net_rt_cache,		/* /proc/net/rt_cache	*/
	lxpr_read_net_sockstat,		/* /proc/net/sockstat	*/
	lxpr_read_net_snmp,		/* /proc/net/snmp	*/
	lxpr_read_net_stat,		/* /proc/net/stat	*/
	lxpr_read_net_tcp,		/* /proc/net/tcp	*/
	lxpr_read_net_tcp6,		/* /proc/net/tcp6	*/
	lxpr_read_net_udp,		/* /proc/net/udp	*/
	lxpr_read_net_udp6,		/* /proc/net/udp6	*/
	lxpr_read_net_unix,		/* /proc/net/unix	*/
	lxpr_read_partitions,		/* /proc/partitions	*/
	lxpr_read_invalid,		/* /proc/self		*/
	lxpr_read_stat,			/* /proc/stat		*/
	lxpr_read_swaps,		/* /proc/swaps		*/
	lxpr_read_invalid,		/* /proc/sys		*/
	lxpr_read_invalid,		/* /proc/sys/fs		*/
	lxpr_read_invalid,		/* /proc/sys/fs/inotify	*/
	lxpr_read_sys_fs_inotify_max_queued_events, /* max_queued_events */
	lxpr_read_sys_fs_inotify_max_user_instances, /* max_user_instances */
	lxpr_read_sys_fs_inotify_max_user_watches, /* max_user_watches */
	lxpr_read_invalid,		/* /proc/sys/kernel	*/
	lxpr_read_sys_kernel_hostname,	/* /proc/sys/kernel/hostname */
	lxpr_read_sys_kernel_msgmni,	/* /proc/sys/kernel/msgmni */
	lxpr_read_sys_kernel_ngroups_max, /* /proc/sys/kernel/ngroups_max */
	lxpr_read_sys_kernel_pid_max,	/* /proc/sys/kernel/pid_max */
	lxpr_read_sys_kernel_shmmax,	/* /proc/sys/kernel/shmmax */
	lxpr_read_sys_kernel_threads_max, /* /proc/sys/kernel/threads-max */
	lxpr_read_uptime,		/* /proc/uptime		*/
	lxpr_read_version,		/* /proc/version	*/
};

/*
 * Array of lookup functions, indexed by lx /proc file type.
 */
static vnode_t *(*lxpr_lookup_function[LXPR_NFILES])() = {
	lxpr_lookup_procdir,		/* /proc		*/
	lxpr_lookup_piddir,		/* /proc/<pid>		*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/cmdline	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/cpu	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/cwd	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/environ	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/exe	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/limits	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/maps	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/mem	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/mountinfo */
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/root	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/stat	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/statm	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/status	*/
	lxpr_lookup_fddir,		/* /proc/<pid>/fd	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/fd/nn	*/
	lxpr_lookup_not_a_dir,		/* /proc/cmdline	*/
	lxpr_lookup_not_a_dir,		/* /proc/cpuinfo	*/
	lxpr_lookup_not_a_dir,		/* /proc/devices	*/
	lxpr_lookup_not_a_dir,		/* /proc/dma		*/
	lxpr_lookup_not_a_dir,		/* /proc/filesystems	*/
	lxpr_lookup_not_a_dir,		/* /proc/interrupts	*/
	lxpr_lookup_not_a_dir,		/* /proc/ioports	*/
	lxpr_lookup_not_a_dir,		/* /proc/kcore		*/
	lxpr_lookup_not_a_dir,		/* /proc/kmsg		*/
	lxpr_lookup_not_a_dir,		/* /proc/loadavg	*/
	lxpr_lookup_not_a_dir,		/* /proc/meminfo	*/
	lxpr_lookup_not_a_dir,		/* /proc/modules	*/
	lxpr_lookup_not_a_dir,		/* /proc/mounts		*/
	lxpr_lookup_netdir,		/* /proc/net		*/
	lxpr_lookup_not_a_dir,		/* /proc/net/arp	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/dev	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/dev_mcast	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/if_inet6	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/igmp	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/ip_mr_cache */
	lxpr_lookup_not_a_dir,		/* /proc/net/ip_mr_vif	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/ipv6_route	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/mcfilter	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/netstat	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/raw	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/route	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/rpc	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/rt_cache	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/sockstat	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/snmp	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/stat	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/tcp	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/tcp6	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/udp	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/udp6	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/unix	*/
	lxpr_lookup_not_a_dir,		/* /proc/partitions	*/
	lxpr_lookup_not_a_dir,		/* /proc/self		*/
	lxpr_lookup_not_a_dir,		/* /proc/stat		*/
	lxpr_lookup_not_a_dir,		/* /proc/swaps		*/
	lxpr_lookup_sysdir,		/* /proc/sys		*/
	lxpr_lookup_sys_fsdir,		/* /proc/sys/fs		*/
	lxpr_lookup_sys_fs_inotifydir,	/* /proc/sys/fs/inotify	*/
	lxpr_lookup_not_a_dir,		/* .../inotify/max_queued_events */
	lxpr_lookup_not_a_dir,		/* .../inotify/max_user_instances */
	lxpr_lookup_not_a_dir,		/* .../inotify/max_user_watches */
	lxpr_lookup_sys_kerneldir,	/* /proc/sys/kernel	*/
	lxpr_lookup_not_a_dir,		/* /proc/sys/kernel/hostname */
	lxpr_lookup_not_a_dir,		/* /proc/sys/kernel/msgmni */
	lxpr_lookup_not_a_dir,		/* /proc/sys/kernel/ngroups_max */
	lxpr_lookup_not_a_dir,		/* /proc/sys/kernel/pid_max */
	lxpr_lookup_not_a_dir,		/* /proc/sys/kernel/shmmax */
	lxpr_lookup_not_a_dir,		/* /proc/sys/kernel/threads-max */
	lxpr_lookup_not_a_dir,		/* /proc/uptime		*/
	lxpr_lookup_not_a_dir,		/* /proc/version	*/
};

/*
 * Array of readdir functions, indexed by /proc file type.
 */
static int (*lxpr_readdir_function[LXPR_NFILES])() = {
	lxpr_readdir_procdir,		/* /proc		*/
	lxpr_readdir_piddir,		/* /proc/<pid>		*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/cmdline	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/cpu	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/cwd	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/environ	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/exe	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/limits	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/maps	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/mem	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/mountinfo */
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/root	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/stat	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/statm	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/status	*/
	lxpr_readdir_fddir,		/* /proc/<pid>/fd	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/fd/nn	*/
	lxpr_readdir_not_a_dir,		/* /proc/cmdline	*/
	lxpr_readdir_not_a_dir,		/* /proc/cpuinfo	*/
	lxpr_readdir_not_a_dir,		/* /proc/devices	*/
	lxpr_readdir_not_a_dir,		/* /proc/dma		*/
	lxpr_readdir_not_a_dir,		/* /proc/filesystems	*/
	lxpr_readdir_not_a_dir,		/* /proc/interrupts	*/
	lxpr_readdir_not_a_dir,		/* /proc/ioports	*/
	lxpr_readdir_not_a_dir,		/* /proc/kcore		*/
	lxpr_readdir_not_a_dir,		/* /proc/kmsg		*/
	lxpr_readdir_not_a_dir,		/* /proc/loadavg	*/
	lxpr_readdir_not_a_dir,		/* /proc/meminfo	*/
	lxpr_readdir_not_a_dir,		/* /proc/modules	*/
	lxpr_readdir_not_a_dir,		/* /proc/mounts		*/
	lxpr_readdir_netdir,		/* /proc/net		*/
	lxpr_readdir_not_a_dir,		/* /proc/net/arp	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/dev	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/dev_mcast	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/if_inet6	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/igmp	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/ip_mr_cache */
	lxpr_readdir_not_a_dir,		/* /proc/net/ip_mr_vif	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/ipv6_route	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/mcfilter	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/netstat	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/raw	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/route	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/rpc	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/rt_cache	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/sockstat	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/snmp	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/stat	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/tcp	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/tcp6	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/udp	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/udp6	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/unix	*/
	lxpr_readdir_not_a_dir,		/* /proc/partitions	*/
	lxpr_readdir_not_a_dir,		/* /proc/self		*/
	lxpr_readdir_not_a_dir,		/* /proc/stat		*/
	lxpr_readdir_not_a_dir,		/* /proc/swaps		*/
	lxpr_readdir_sysdir,		/* /proc/sys		*/
	lxpr_readdir_sys_fsdir,		/* /proc/sys/fs		*/
	lxpr_readdir_sys_fs_inotifydir,	/* /proc/sys/fs/inotify	*/
	lxpr_readdir_not_a_dir,		/* .../inotify/max_queued_events */
	lxpr_readdir_not_a_dir,		/* .../inotify/max_user_instances */
	lxpr_readdir_not_a_dir,		/* .../inotify/max_user_watches	*/
	lxpr_readdir_sys_kerneldir,	/* /proc/sys/kernel	*/
	lxpr_readdir_not_a_dir,		/* /proc/sys/kernel/hostname */
	lxpr_readdir_not_a_dir,		/* /proc/sys/kernel/msgmni */
	lxpr_readdir_not_a_dir,		/* /proc/sys/kernel/ngroups_max */
	lxpr_readdir_not_a_dir,		/* /proc/sys/kernel/pid_max */
	lxpr_readdir_not_a_dir,		/* /proc/sys/kernel/shmmax */
	lxpr_readdir_not_a_dir,		/* /proc/sys/kernel/threads-max */
	lxpr_readdir_not_a_dir,		/* /proc/uptime		*/
	lxpr_readdir_not_a_dir,		/* /proc/version	*/
};


/*
 * lxpr_read(): Vnode operation for VOP_READ()
 *
 * As the format of all the files that can be read in the lx procfs is human
 * readable and not binary structures there do not have to be different
 * read variants depending on whether the reading process model is 32 or 64 bits
 * (at least in general, and certainly the difference is unlikely to be enough
 * to justify have different routines for 32 and 64 bit reads
 */
/* ARGSUSED */
static int
lxpr_read(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	lxpr_node_t *lxpnp = VTOLXP(vp);
	lxpr_nodetype_t type = lxpnp->lxpr_type;
	lxpr_uiobuf_t *uiobuf = lxpr_uiobuf_new(uiop);
	int error;

	ASSERT(type < LXPR_NFILES);

	if (type == LXPR_KMSG) {
		ldi_ident_t	li = VTOLXPM(vp)->lxprm_li;
		struct strioctl	str;
		int		rv;

		/*
		 * Open the zone's console device using the layered driver
		 * interface.
		 */
		if ((error = ldi_open_by_name("/dev/log", FREAD, cr,
		    &lxpnp->lxpr_cons_ldih, li)) != 0)
			return (error);

		/*
		 * Send an ioctl to the underlying console device, letting it
		 * know we're interested in getting console messages.
		 */
		str.ic_cmd = I_CONSLOG;
		str.ic_timout = 0;
		str.ic_len = 0;
		str.ic_dp = NULL;
		if ((error = ldi_ioctl(lxpnp->lxpr_cons_ldih, I_STR,
		    (intptr_t)&str, FKIOCTL, cr, &rv)) != 0)
			return (error);
	}

	lxpr_read_function[type](lxpnp, uiobuf);

	if (type == LXPR_KMSG) {
		if ((error = ldi_close(lxpnp->lxpr_cons_ldih, FREAD, cr)) != 0)
			return (error);
	}

	error = lxpr_uiobuf_flush(uiobuf);
	lxpr_uiobuf_free(uiobuf);

	return (error);
}

/*
 * lxpr_read_invalid(), lxpr_read_isdir(), lxpr_read_empty()
 *
 * Various special case reads:
 * - trying to read a directory
 * - invalid file (used to mean a file that should be implemented,
 *   but isn't yet)
 * - empty file
 * - wait to be able to read a file that will never have anything to read
 */
/* ARGSUSED */
static void
lxpr_read_isdir(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_uiobuf_seterr(uiobuf, EISDIR);
}

/* ARGSUSED */
static void
lxpr_read_invalid(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_uiobuf_seterr(uiobuf, EINVAL);
}

/* ARGSUSED */
static void
lxpr_read_empty(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/*
 * lxpr_read_pid_cmdline(): read argument vector from process
 */
static void
lxpr_read_pid_cmdline(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	proc_t *p;
	char *buf;
	size_t asz = lxpr_maxargvlen, sz;

	ASSERT(lxpnp->lxpr_type == LXPR_PID_CMDLINE);

	buf = kmem_alloc(asz, KM_SLEEP);

	p = lxpr_lock(lxpnp->lxpr_pid);
	if (p == NULL) {
		lxpr_uiobuf_seterr(uiobuf, EINVAL);
		kmem_free(buf, asz);
		return;
	}

	if (prreadargv(p, buf, asz, &sz) != 0) {
		lxpr_uiobuf_seterr(uiobuf, EINVAL);
	} else {
		lxpr_uiobuf_write(uiobuf, buf, sz);
	}

	lxpr_unlock(p);
	kmem_free(buf, asz);
}

/*
 * lxpr_read_pid_limits(): ulimit file
 */
static void
lxpr_read_pid_limits(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	proc_t *p;
	rctl_qty_t cur, max;
	rctl_val_t *oval, *nval;
	rctl_hndl_t hndl;
	char *kname;
	int i;

	ASSERT(lxpnp->lxpr_type == LXPR_PID_LIMITS);

	nval = kmem_alloc(sizeof (rctl_val_t), KM_SLEEP);

	p = lxpr_lock(lxpnp->lxpr_pid);
	if (p == NULL) {
		kmem_free(nval, sizeof (rctl_val_t));
		lxpr_uiobuf_seterr(uiobuf, EINVAL);
		return;
	}

	lxpr_uiobuf_printf(uiobuf, "%-25s %-20s %-20s %-10s\n",
	    "Limit", "Soft Limit", "Hard Limit", "Units");
	for (i = 0; lxpr_rlimtab[i].rlim_name != NULL; i++) {
		kname = lxpr_rlimtab[i].rlim_rctl;
		/* default to unlimited for resources without an analog */
		cur = RLIM_INFINITY;
		max = RLIM_INFINITY;
		if (kname != NULL) {
			hndl = rctl_hndl_lookup(kname);
			oval = NULL;
			while ((hndl != -1) &&
			    rctl_local_get(hndl, oval, nval, p) == 0) {
				oval = nval;
				switch (nval->rcv_privilege) {
				case RCPRIV_BASIC:
					if (!RCTL_INFINITE(nval))
						cur = nval->rcv_value;
					break;
				case RCPRIV_PRIVILEGED:
					if (!RCTL_INFINITE(nval))
						max = nval->rcv_value;
					break;
				}
			}
		}

		lxpr_uiobuf_printf(uiobuf, "%-25s", lxpr_rlimtab[i].rlim_name);
		if (cur == RLIM_INFINITY || cur == LX_RLIM_INFINITY) {
			lxpr_uiobuf_printf(uiobuf, " %-20s", "unlimited");
		} else {
			lxpr_uiobuf_printf(uiobuf, " %-20lu", cur);
		}
		if (max == RLIM_INFINITY || max == LX_RLIM_INFINITY) {
			lxpr_uiobuf_printf(uiobuf, " %-20s", "unlimited");
		} else {
			lxpr_uiobuf_printf(uiobuf, " %-20lu", max);
		}
		lxpr_uiobuf_printf(uiobuf, " %-10s\n",
		    lxpr_rlimtab[i].rlim_unit);
	}

	lxpr_unlock(p);
	kmem_free(nval, sizeof (rctl_val_t));
}

/*
 * lxpr_read_pid_maps(): memory map file
 */
static void
lxpr_read_pid_maps(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	proc_t *p;
	struct as *as;
	struct seg *seg;
	char *buf;
	int buflen = MAXPATHLEN;
	struct print_data {
		uintptr_t saddr;
		uintptr_t eaddr;
		int type;
		char prot[5];
		uintptr_t offset;
		vnode_t *vp;
		struct print_data *next;
	} *print_head = NULL;
	struct print_data **print_tail = &print_head;
	struct print_data *pbuf;

	ASSERT(lxpnp->lxpr_type == LXPR_PID_MAPS);

	p = lxpr_lock(lxpnp->lxpr_pid);
	if (p == NULL) {
		lxpr_uiobuf_seterr(uiobuf, EINVAL);
		return;
	}

	as = p->p_as;

	if (as == &kas) {
		lxpr_unlock(p);
		return;
	}

	mutex_exit(&p->p_lock);

	/* Iterate over all segments in the address space */
	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	for (seg = AS_SEGFIRST(as); seg != NULL; seg = AS_SEGNEXT(as, seg)) {
		vnode_t *vp;
		uint_t protbits;

		pbuf = kmem_alloc(sizeof (*pbuf), KM_SLEEP);

		pbuf->saddr = (uintptr_t)seg->s_base;
		pbuf->eaddr = pbuf->saddr + seg->s_size;
		pbuf->type = SEGOP_GETTYPE(seg, seg->s_base);

		/*
		 * Cheat and only use the protection bits of the first page
		 * in the segment
		 */
		(void) strncpy(pbuf->prot, "----", sizeof (pbuf->prot));
		(void) SEGOP_GETPROT(seg, seg->s_base, 0, &protbits);

		if (protbits & PROT_READ)	   pbuf->prot[0] = 'r';
		if (protbits & PROT_WRITE)	   pbuf->prot[1] = 'w';
		if (protbits & PROT_EXEC)	   pbuf->prot[2] = 'x';
		if (pbuf->type & MAP_SHARED)	   pbuf->prot[3] = 's';
		else if (pbuf->type & MAP_PRIVATE) pbuf->prot[3] = 'p';

		if (seg->s_ops == &segvn_ops &&
		    SEGOP_GETVP(seg, seg->s_base, &vp) == 0 &&
		    vp != NULL && vp->v_type == VREG) {
			VN_HOLD(vp);
			pbuf->vp = vp;
		} else {
			pbuf->vp = NULL;
		}

		pbuf->offset = SEGOP_GETOFFSET(seg, (caddr_t)pbuf->saddr);

		pbuf->next = NULL;
		*print_tail = pbuf;
		print_tail = &pbuf->next;
	}
	AS_LOCK_EXIT(as, &as->a_lock);
	mutex_enter(&p->p_lock);
	lxpr_unlock(p);

	buf = kmem_alloc(buflen, KM_SLEEP);

	/* print the data we've extracted */
	pbuf = print_head;
	while (pbuf != NULL) {
		struct print_data *pbuf_next;
		vattr_t vattr;

		int maj = 0;
		int min = 0;
		ino_t inode = 0;

		*buf = '\0';
		if (pbuf->vp != NULL) {
			vattr.va_mask = AT_FSID | AT_NODEID;
			if (VOP_GETATTR(pbuf->vp, &vattr, 0, CRED(),
			    NULL) == 0) {
				maj = getmajor(vattr.va_fsid);
				min = getminor(vattr.va_fsid);
				inode = vattr.va_nodeid;
			}
			(void) vnodetopath(NULL, pbuf->vp, buf, buflen, CRED());
			VN_RELE(pbuf->vp);
		}

		if (p->p_model == DATAMODEL_LP64) {
			lxpr_uiobuf_printf(uiobuf,
			    "%08llx-%08llx %s %08llx %02x:%02x %llu%s%s\n",
			    pbuf->saddr, pbuf->eaddr, pbuf->prot, pbuf->offset,
			    maj, min, inode, *buf != '\0' ? " " : "", buf);
		} else {
			lxpr_uiobuf_printf(uiobuf,
			    "%08x-%08x %s %08x %02x:%02x %llu%s%s\n",
			    (uint32_t)pbuf->saddr, (uint32_t)pbuf->eaddr,
			    pbuf->prot, (uint32_t)pbuf->offset, maj, min,
			    inode, *buf != '\0' ? " " : "", buf);
		}

		pbuf_next = pbuf->next;
		kmem_free(pbuf, sizeof (*pbuf));
		pbuf = pbuf_next;
	}

	kmem_free(buf, buflen);
}

/*
 * lxpr_read_pid_mountinfo(): information about process mount points. e.g.:
 *    14 19 0:13 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
 * mntid parid devnums root mntpnt mntopts - fstype mntsrc superopts
 *
 * We have to make up several of these fields.
 */
static void
lxpr_read_pid_mountinfo(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	struct vfs *vfsp;
	struct vfs *vfslist;
	zone_t *zone = LXPTOZ(lxpnp);
	struct print_data {
		refstr_t *vfs_mntpt;
		refstr_t *vfs_resource;
		uint_t vfs_flag;
		int vfs_fstype;
		dev_t vfs_dev;
		struct print_data *next;
	} *print_head = NULL;
	struct print_data **print_tail = &print_head;
	struct print_data *printp;
	int root_id = 15;	/* use a made-up value */
	int mnt_id;

	ASSERT(lxpnp->lxpr_type == LXPR_PID_MOUNTINFO);

	vfs_list_read_lock();

	/* root is the top-level, it does not appear in this output */
	if (zone == global_zone) {
		vfsp = vfslist = rootvfs;
	} else {
		vfsp = vfslist = zone->zone_vfslist;
		/*
		 * If the zone has a root entry, it will be the first in
		 * the list.  If it doesn't, we conjure one up.
		 */
		if (vfslist == NULL || strcmp(refstr_value(vfsp->vfs_mntpt),
		    zone->zone_rootpath) != 0) {
			struct vfs *tvfsp;
			/*
			 * The root of the zone is not a mount point.  The vfs
			 * we want to report is that of the zone's root vnode.
			 */
			tvfsp = zone->zone_rootvp->v_vfsp;

			lxpr_uiobuf_printf(uiobuf,
			    "%d 1 %d:%d / / %s - %s / %s\n",
			    root_id,
			    major(tvfsp->vfs_dev), minor(vfsp->vfs_dev),
			    tvfsp->vfs_flag & VFS_RDONLY ? "ro" : "rw",
			    vfssw[tvfsp->vfs_fstype].vsw_name,
			    tvfsp->vfs_flag & VFS_RDONLY ? "ro" : "rw");

		}
		if (vfslist == NULL) {
			vfs_list_unlock();
			return;
		}
	}

	/*
	 * Later on we have to do a lookupname, which can end up causing
	 * another vfs_list_read_lock() to be called. Which can lead to a
	 * deadlock. To avoid this, we extract the data we need into a local
	 * list, then we can run this list without holding vfs_list_read_lock()
	 * We keep the list in the same order as the vfs_list
	 */
	do {
		/* Skip mounts we shouldn't show */
		if (vfsp->vfs_flag & VFS_NOMNTTAB) {
			goto nextfs;
		}

		printp = kmem_alloc(sizeof (*printp), KM_SLEEP);
		refstr_hold(vfsp->vfs_mntpt);
		printp->vfs_mntpt = vfsp->vfs_mntpt;
		refstr_hold(vfsp->vfs_resource);
		printp->vfs_resource = vfsp->vfs_resource;
		printp->vfs_flag = vfsp->vfs_flag;
		printp->vfs_fstype = vfsp->vfs_fstype;
		printp->vfs_dev = vfsp->vfs_dev;
		printp->next = NULL;

		*print_tail = printp;
		print_tail = &printp->next;

nextfs:
		vfsp = (zone == global_zone) ?
		    vfsp->vfs_next : vfsp->vfs_zone_next;

	} while (vfsp != vfslist);

	vfs_list_unlock();

	mnt_id = root_id + 1;

	/*
	 * now we can run through what we've extracted without holding
	 * vfs_list_read_lock()
	 */
	printp = print_head;
	while (printp != NULL) {
		struct print_data *printp_next;
		const char *resource;
		char *mntpt;
		struct vnode *vp;
		int error;

		mntpt = (char *)refstr_value(printp->vfs_mntpt);
		resource = refstr_value(printp->vfs_resource);

		if (mntpt != NULL && mntpt[0] != '\0')
			mntpt = ZONE_PATH_TRANSLATE(mntpt, zone);
		else
			mntpt = "-";

		error = lookupname(mntpt, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);

		if (error != 0)
			goto nextp;

		if (!(vp->v_flag & VROOT)) {
			VN_RELE(vp);
			goto nextp;
		}
		VN_RELE(vp);

		if (resource != NULL && resource[0] != '\0') {
			if (resource[0] == '/') {
				resource = ZONE_PATH_VISIBLE(resource, zone) ?
				    ZONE_PATH_TRANSLATE(resource, zone) : mntpt;
			}
		} else {
			resource = "none";
		}

		/*
		 * XXX parent ID is not tracked correctly here. Currently we
		 * always assume the parent ID is the root ID.
		 */
		lxpr_uiobuf_printf(uiobuf,
		    "%d %d %d:%d / %s %s - %s %s %s\n",
		    mnt_id, root_id,
		    major(printp->vfs_dev), minor(printp->vfs_dev),
		    mntpt,
		    printp->vfs_flag & VFS_RDONLY ? "ro" : "rw",
		    vfssw[printp->vfs_fstype].vsw_name,
		    resource,
		    printp->vfs_flag & VFS_RDONLY ? "ro" : "rw");

nextp:
		printp_next = printp->next;
		refstr_rele(printp->vfs_mntpt);
		refstr_rele(printp->vfs_resource);
		kmem_free(printp, sizeof (*printp));
		printp = printp_next;

		mnt_id++;
	}
}

/*
 * lxpr_read_pid_statm(): memory status file
 */
static void
lxpr_read_pid_statm(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	proc_t *p;
	struct as *as;
	size_t vsize;
	size_t rss;

	ASSERT(lxpnp->lxpr_type == LXPR_PID_STATM);

	p = lxpr_lock(lxpnp->lxpr_pid);
	if (p == NULL) {
		lxpr_uiobuf_seterr(uiobuf, EINVAL);
		return;
	}

	as = p->p_as;

	mutex_exit(&p->p_lock);

	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	vsize = btopr(as->a_resvsize);
	rss = rm_asrss(as);
	AS_LOCK_EXIT(as, &as->a_lock);

	mutex_enter(&p->p_lock);
	lxpr_unlock(p);

	lxpr_uiobuf_printf(uiobuf,
	    "%lu %lu %lu %lu %lu %lu %lu\n",
	    vsize, rss, 0l, rss, 0l, 0l, 0l);
}

/*
 * Derived from procfs prgetxmap32
 */
static size_t
get_locked(proc_t *p)
{
	struct as *as = p->p_as;
	struct seg *seg;
	uint_t nlocked = 0;

	ASSERT(as != &kas && AS_READ_HELD(as, &as->a_lock));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	do {
		char *parr;
		uint64_t npages;
		uint64_t pagenum;

		npages = ((uintptr_t)seg->s_size) >> PAGESHIFT;
		parr = kmem_zalloc(npages, KM_SLEEP);

		SEGOP_INCORE(seg, seg->s_base, seg->s_size, parr);

		for (pagenum = 0; pagenum < npages; pagenum++) {
			if (parr[pagenum] & SEG_PAGE_LOCKED)
				nlocked++;
		}
		kmem_free(parr, npages);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (nlocked);
}

/*
 * lxpr_read_pid_status(): status file
 */
static void
lxpr_read_pid_status(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	proc_t *p;
	kthread_t *t;
	user_t *up;
	cred_t *cr;
	const gid_t *groups;
	int    ngroups;
	struct as *as;
	char *status;
	pid_t pid, ppid;
	size_t vsize;
	size_t nlocked;
	size_t rss;
	k_sigset_t current, ignore, handle;
	int    i, lx_sig;

	ASSERT(lxpnp->lxpr_type == LXPR_PID_STATUS);

	p = lxpr_lock(lxpnp->lxpr_pid);
	if (p == NULL) {
		lxpr_uiobuf_seterr(uiobuf, EINVAL);
		return;
	}

	pid = p->p_pid;

	/*
	 * Convert pid to the Linux default of 1 if we're the zone's init
	 * process or if we're the zone's zsched the pid is 0.
	 */
	if (pid == curproc->p_zone->zone_proc_initpid) {
		pid = 1;
		ppid = 0;	/* parent pid for init is 0 */
	} else if (pid == curproc->p_zone->zone_zsched->p_pid) {
		pid = 0;	/* zsched is pid 0 */
		ppid = 0;	/* parent pid for zsched is itself */
	} else {
		/*
		 * Make sure not to reference parent PIDs that reside outside
		 * the zone
		 */
		ppid = ((p->p_flag & SZONETOP)
		    ? curproc->p_zone->zone_zsched->p_pid : p->p_ppid);

		/*
		 * Convert ppid to the Linux default of 1 if our parent is the
		 * zone's init process
		 */
		if (ppid == curproc->p_zone->zone_proc_initpid)
			ppid = 1;
	}

	t = prchoose(p);
	if (t != NULL) {
		switch (t->t_state) {
		case TS_SLEEP:
			status = "S (sleeping)";
			break;
		case TS_RUN:
		case TS_ONPROC:
			status = "R (running)";
			break;
		case TS_ZOMB:
			status = "Z (zombie)";
			break;
		case TS_STOPPED:
			status = "T (stopped)";
			break;
		default:
			status = "! (unknown)";
			break;
		}
		thread_unlock(t);
	} else {
		/*
		 * there is a hole in the exit code, where a proc can have
		 * no threads but it is yet to be flagged SZOMB. We will
		 * assume we are about to become a zombie
		 */
		status = "Z (zombie)";
	}

	up = PTOU(p);
	mutex_enter(&p->p_crlock);
	crhold(cr = p->p_cred);
	mutex_exit(&p->p_crlock);

	lxpr_uiobuf_printf(uiobuf,
	    "Name:\t%s\n"
	    "State:\t%s\n"
	    "Tgid:\t%d\n"
	    "Pid:\t%d\n"
	    "PPid:\t%d\n"
	    "TracerPid:\t%d\n"
	    "Uid:\t%u\t%u\t%u\t%u\n"
	    "Gid:\t%u\t%u\t%u\t%u\n"
	    "FDSize:\t%d\n"
	    "Groups:\t",
	    up->u_comm,
	    status,
	    pid, /* thread group id - same as pid */
	    pid,
	    ppid,
	    0,
	    crgetruid(cr), crgetuid(cr), crgetsuid(cr), crgetuid(cr),
	    crgetrgid(cr), crgetgid(cr), crgetsgid(cr), crgetgid(cr),
	    p->p_fno_ctl);

	ngroups = crgetngroups(cr);
	groups  = crgetgroups(cr);
	for (i = 0; i < ngroups; i++) {
		lxpr_uiobuf_printf(uiobuf,
		    "%u ",
		    groups[i]);
	}
	crfree(cr);

	as = p->p_as;
	if ((p->p_stat != SZOMB) && !(p->p_flag & SSYS) && (as != &kas)) {
		mutex_exit(&p->p_lock);
		AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
		vsize = as->a_resvsize;
		rss = rm_asrss(as);
		nlocked = get_locked(p);
		AS_LOCK_EXIT(as, &as->a_lock);
		mutex_enter(&p->p_lock);

		lxpr_uiobuf_printf(uiobuf,
		    "\n"
		    "VmSize:\t%8lu kB\n"
		    "VmLck:\t%8lu kB\n"
		    "VmRSS:\t%8lu kB\n"
		    "VmData:\t%8lu kB\n"
		    "VmStk:\t%8lu kB\n"
		    "VmExe:\t%8lu kB\n"
		    "VmLib:\t%8lu kB",
		    btok(vsize),
		    ptok(nlocked),
		    ptok(rss),
		    0l,
		    btok(p->p_stksize),
		    ptok(rss),
		    0l);
	}

	sigemptyset(&current);
	sigemptyset(&ignore);
	sigemptyset(&handle);

	for (i = 1; i < NSIG; i++) {
		lx_sig = stol_signo[i];

		if ((lx_sig > 0) && (lx_sig <= LX_NSIG)) {
			if (sigismember(&p->p_sig, i))
				sigaddset(&current, lx_sig);

			if (up->u_signal[i - 1] == SIG_IGN)
				sigaddset(&ignore, lx_sig);
			else if (up->u_signal[i - 1] != SIG_DFL)
				sigaddset(&handle, lx_sig);
		}
	}

	lxpr_uiobuf_printf(uiobuf,
	    "\n"
	    "SigPnd:\t%08x%08x\n"
	    "SigBlk:\t%08x%08x\n"
	    "SigIgn:\t%08x%08x\n"
	    "SigCgt:\t%08x%08x\n"
	    "CapInh:\t%016x\n"
	    "CapPrm:\t%016x\n"
	    "CapEff:\t%016x\n",
	    current.__sigbits[1], current.__sigbits[0],
	    0, 0, /* signals blocked on per thread basis */
	    ignore.__sigbits[1], ignore.__sigbits[0],
	    handle.__sigbits[1], handle.__sigbits[0],
	    /* Can't do anything with linux capabilities */
	    0,
	    0,
	    0);

	lxpr_unlock(p);
}


/*
 * lxpr_read_pid_stat(): pid stat file
 */
static void
lxpr_read_pid_stat(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	proc_t *p;
	kthread_t *t;
	struct as *as;
	char stat;
	pid_t pid, ppid, pgpid, spid;
	gid_t psgid;
	dev_t psdev;
	size_t rss, vsize;
	int nice, pri;
	caddr_t wchan;
	processorid_t cpu;

	ASSERT(lxpnp->lxpr_type == LXPR_PID_STAT);

	p = lxpr_lock(lxpnp->lxpr_pid);
	if (p == NULL) {
		lxpr_uiobuf_seterr(uiobuf, EINVAL);
		return;
	}

	pid = p->p_pid;

	/*
	 * Set Linux defaults if we're the zone's init process
	 */
	if (pid == curproc->p_zone->zone_proc_initpid) {
		pid = 1;		/* PID for init */
		ppid = 0;		/* parent PID for init is 0 */
		pgpid = 0;		/* process group for init is 0 */
		psgid = (gid_t)-1;	/* credential GID for init is -1 */
		spid = 0;		/* session id for init is 0 */
		psdev = 0;		/* session device for init is 0 */
	} else if (pid == curproc->p_zone->zone_zsched->p_pid) {
		pid = 0;		/* PID for zsched */
		ppid = 0;		/* parent PID for zsched is 0 */
		pgpid = 0;		/* process group for zsched is 0 */
		psgid = (gid_t)-1;	/* credential GID for zsched is -1 */
		spid = 0;		/* session id for zsched is 0 */
		psdev = 0;		/* session device for zsched is 0 */
	} else {
		/*
		 * Make sure not to reference parent PIDs that reside outside
		 * the zone
		 */
		ppid = ((p->p_flag & SZONETOP) ?
		    curproc->p_zone->zone_zsched->p_pid : p->p_ppid);

		/*
		 * Convert ppid to the Linux default of 1 if our parent is the
		 * zone's init process
		 */
		if (ppid == curproc->p_zone->zone_proc_initpid)
			ppid = 1;

		pgpid = p->p_pgrp;

		mutex_enter(&p->p_splock);
		mutex_enter(&p->p_sessp->s_lock);
		spid = p->p_sessp->s_sid;
		psdev = p->p_sessp->s_dev;
		if (p->p_sessp->s_cred)
			psgid = crgetgid(p->p_sessp->s_cred);
		else
			psgid = crgetgid(p->p_cred);

		mutex_exit(&p->p_sessp->s_lock);
		mutex_exit(&p->p_splock);
	}

	t = prchoose(p);
	if (t != NULL) {
		switch (t->t_state) {
		case TS_SLEEP:
			stat = 'S'; break;
		case TS_RUN:
		case TS_ONPROC:
			stat = 'R'; break;
		case TS_ZOMB:
			stat = 'Z'; break;
		case TS_STOPPED:
			stat = 'T'; break;
		default:
			stat = '!'; break;
		}

		if (CL_DONICE(t, NULL, 0, &nice) != 0)
			nice = 0;

		pri = t->t_pri;
		wchan = t->t_wchan;
		cpu = t->t_cpu->cpu_id;
		thread_unlock(t);
	} else {
		/* Only zombies have no threads */
		stat = 'Z';
		nice = 0;
		pri = 0;
		wchan = 0;
		cpu = 0;
	}
	as = p->p_as;
	mutex_exit(&p->p_lock);
	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	vsize = as->a_resvsize;
	rss = rm_asrss(as);
	AS_LOCK_EXIT(as, &as->a_lock);
	mutex_enter(&p->p_lock);

	lxpr_uiobuf_printf(uiobuf,
	    "%d (%s) %c %d %d %d %d %d "
	    "%lu %lu %lu %lu %lu "
	    "%lu %lu %ld %ld "
	    "%d %d %d "
	    "%lu "
	    "%lu "
	    "%lu %ld %llu "
	    "%lu %lu %u "
	    "%lu %lu "
	    "%lu %lu %lu %lu "
	    "%lu "
	    "%lu %lu "
	    "%d "
	    "%d"
	    "\n",
	    pid, PTOU(p)->u_comm, stat, ppid, pgpid, spid, psdev, psgid,
	    0l, 0l, 0l, 0l, 0l, /* flags, minflt, cminflt, majflt, cmajflt */
	    p->p_utime, p->p_stime, p->p_cutime, p->p_cstime,
	    pri, nice, p->p_lwpcnt,
	    0l, /* itrealvalue (time before next SIGALRM) */
	    PTOU(p)->u_ticks,
	    vsize, rss, p->p_vmem_ctl,
	    0l, 0l, USRSTACK, /* startcode, endcode, startstack */
	    0l, 0l, /* kstkesp, kstkeip */
	    0l, 0l, 0l, 0l, /* signal, blocked, sigignore, sigcatch */
	    wchan,
	    0l, 0l, /* nswap, cnswap */
	    0, /* exit_signal */
	    cpu);

	lxpr_unlock(p);
}

/* ARGSUSED */
static void
lxpr_read_net_arp(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

struct lxpr_ifstat {
	uint64_t rx_bytes;
	uint64_t rx_packets;
	uint64_t rx_errors;
	uint64_t rx_drop;
	uint64_t tx_bytes;
	uint64_t tx_packets;
	uint64_t tx_errors;
	uint64_t tx_drop;
	uint64_t collisions;
	uint64_t rx_multicast;
};

static void *
lxpr_kstat_read(kstat_t *kn, boolean_t byname, size_t *size, int *num)
{
	kstat_t *kp;
	int i, nrec = 0;
	size_t bufsize;
	void *buf = NULL;

	if (byname == B_TRUE)
		kp = kstat_hold_byname(kn->ks_module, kn->ks_instance,
		    kn->ks_name, getzoneid());
	else
		kp = kstat_hold_bykid(kn->ks_kid, getzoneid());
	if (kp == NULL)
		return (NULL);
	if (kp->ks_flags & KSTAT_FLAG_INVALID) {
		kstat_rele(kp);
		return (NULL);
	}

	bufsize = kp->ks_data_size + 1;
	kstat_rele(kp);

	/*
	 * The kstat in question is released so that kmem_alloc(KM_SLEEP) is
	 * performed without it held.  After the alloc, the kstat is reacquired
	 * and its size is checked again. If the buffer is no longer large
	 * enough, the alloc and check are repeated up to three times.
	 */
	for (i = 0; i < 2; i++) {
		buf = kmem_alloc(bufsize, KM_SLEEP);

		/* Check if bufsize still appropriate */
		if (byname == B_TRUE)
			kp = kstat_hold_byname(kn->ks_module, kn->ks_instance,
			    kn->ks_name, getzoneid());
		else
			kp = kstat_hold_bykid(kn->ks_kid, getzoneid());
		if (kp == NULL || kp->ks_flags & KSTAT_FLAG_INVALID) {
			if (kp != NULL)
				kstat_rele(kp);
			kmem_free(buf, bufsize);
			return (NULL);
		}
		KSTAT_ENTER(kp);
		(void) KSTAT_UPDATE(kp, KSTAT_READ);
		if (bufsize < kp->ks_data_size) {
			kmem_free(buf, bufsize);
			bufsize = kp->ks_data_size + 1;
			KSTAT_EXIT(kp);
			kstat_rele(kp);
			continue;
		} else {
			if (KSTAT_SNAPSHOT(kp, buf, KSTAT_READ) != 0) {
				kmem_free(buf, bufsize);
				buf = NULL;
			}
			nrec = kp->ks_ndata;
			KSTAT_EXIT(kp);
			kstat_rele(kp);
			break;
		}
	}

	if (buf != NULL) {
		*size = bufsize;
		*num = nrec;
	}
	return (buf);
}

static int
lxpr_kstat_ifstat(kstat_t *kn, struct lxpr_ifstat *ifs)
{
	kstat_named_t *kp;
	int i, num;
	size_t size;

	/*
	 * Search by name instead of by kid since there's a small window to
	 * race against kstats being added/removed.
	 */
	bzero(ifs, sizeof (*ifs));
	kp = (kstat_named_t *)lxpr_kstat_read(kn, B_TRUE, &size, &num);
	if (kp == NULL)
		return (-1);
	for (i = 0; i < num; i++) {
		if (strncmp(kp[i].name, "rbytes64", KSTAT_STRLEN) == 0)
			ifs->rx_bytes = kp[i].value.ui64;
		else if (strncmp(kp[i].name, "ipackets64", KSTAT_STRLEN) == 0)
			ifs->rx_packets = kp[i].value.ui64;
		else if (strncmp(kp[i].name, "ierrors", KSTAT_STRLEN) == 0)
			ifs->rx_errors = kp[i].value.ui32;
		else if (strncmp(kp[i].name, "norcvbuf", KSTAT_STRLEN) == 0)
			ifs->rx_drop = kp[i].value.ui32;
		else if (strncmp(kp[i].name, "multircv", KSTAT_STRLEN) == 0)
			ifs->rx_multicast = kp[i].value.ui32;
		else if (strncmp(kp[i].name, "obytes64", KSTAT_STRLEN) == 0)
			ifs->tx_bytes = kp[i].value.ui64;
		else if (strncmp(kp[i].name, "opackets64", KSTAT_STRLEN) == 0)
			ifs->tx_packets = kp[i].value.ui64;
		else if (strncmp(kp[i].name, "oerrors", KSTAT_STRLEN) == 0)
			ifs->tx_errors = kp[i].value.ui32;
		else if (strncmp(kp[i].name, "noxmtbuf", KSTAT_STRLEN) == 0)
			ifs->tx_drop = kp[i].value.ui32;
		else if (strncmp(kp[i].name, "collisions", KSTAT_STRLEN) == 0)
			ifs->collisions = kp[i].value.ui32;
	}
	kmem_free(kp, size);
	return (0);
}

/* ARGSUSED */
static void
lxpr_read_net_dev(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	kstat_t *ksr;
	kstat_t ks0;
	int i, nidx;
	size_t sidx;
	struct lxpr_ifstat ifs;

	lxpr_uiobuf_printf(uiobuf, "Inter-|   Receive                   "
	    "                             |  Transmit\n");
	lxpr_uiobuf_printf(uiobuf, " face |bytes    packets errs drop fifo"
	    " frame compressed multicast|bytes    packets errs drop fifo"
	    " colls carrier compressed\n");

	ks0.ks_kid = 0;
	ksr = (kstat_t *)lxpr_kstat_read(&ks0, B_FALSE, &sidx, &nidx);
	if (ksr == NULL)
		return;

	for (i = 1; i < nidx; i++) {
		if (strncmp(ksr[i].ks_module, "link", KSTAT_STRLEN) == 0 ||
		    strncmp(ksr[i].ks_module, "lo", KSTAT_STRLEN) == 0) {
			if (lxpr_kstat_ifstat(&ksr[i], &ifs) != 0)
				continue;

			/* Overwriting the name is ok in the local snapshot */
			lx_ifname_convert(ksr[i].ks_name, LX_IFNAME_FROMNATIVE);
			lxpr_uiobuf_printf(uiobuf, "%6s: %7llu %7llu %4lu "
			    "%4lu %4u %5u %10u %9lu %8llu %7llu %4lu %4lu %4u "
			    "%5lu %7u %10u\n",
			    ksr[i].ks_name,
			    ifs.rx_bytes, ifs.rx_packets,
			    ifs.rx_errors, ifs.rx_drop,
			    0, 0, 0, ifs.rx_multicast,
			    ifs.tx_bytes, ifs.tx_packets,
			    ifs.tx_errors, ifs.tx_drop,
			    0, ifs.collisions, 0, 0);
		}
	}

	kmem_free(ksr, sidx);
}

/* ARGSUSED */
static void
lxpr_read_net_dev_mcast(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

static void
lxpr_inet6_out(const in6_addr_t *addr, char buf[33])
{
	const uint8_t *ip = addr->s6_addr;
	char digits[] = "0123456789abcdef";
	int i;
	for (i = 0; i < 16; i++) {
		buf[2 * i] = digits[ip[i] >> 4];
		buf[2 * i + 1] = digits[ip[i] & 0xf];
	}
	buf[32] = '\0';
}

/* ARGSUSED */
static void
lxpr_read_net_if_inet6(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	netstack_t *ns;
	ip_stack_t *ipst;
	ill_t *ill;
	ipif_t *ipif;
	ill_walk_context_t	ctx;
	char ifname[LIFNAMSIZ], ip6out[33];

	ns = netstack_get_current();
	if (ns == NULL)
		return;
	ipst = ns->netstack_ip;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V6(&ctx, ipst);

	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			uint_t index = ill->ill_phyint->phyint_ifindex;
			int plen = ip_mask_to_plen_v6(&ipif->ipif_v6net_mask);
			in6addr_scope_t scope = ip_addr_scope_v6(
			    &ipif->ipif_v6lcl_addr);
			/* Always report PERMANENT flag */
			int flag = 0x80;

			ipif_get_name(ipif, ifname, sizeof (ifname));
			lx_ifname_convert(ifname, LX_IFNAME_FROMNATIVE);
			lxpr_inet6_out(&ipif->ipif_v6lcl_addr, ip6out);
			/* Scope output is shifted on Linux */
			scope = scope << 4;

			lxpr_uiobuf_printf(uiobuf, "%32s %02x %02x %02x %02x"
			    " %8s\n", ip6out, index, plen, scope, flag, ifname);
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);
	netstack_rele(ns);
}

/* ARGSUSED */
static void
lxpr_read_net_igmp(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_ip_mr_cache(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_ip_mr_vif(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

static void
lxpr_format_route_ipv6(ire_t *ire, lxpr_uiobuf_t *uiobuf)
{
	uint32_t flags;
	char name[IFNAMSIZ];
	char ipv6addr[33];

	lxpr_inet6_out(&ire->ire_addr_v6, ipv6addr);
	lxpr_uiobuf_printf(uiobuf, "%s %02x ", ipv6addr,
	    ip_mask_to_plen_v6(&ire->ire_mask_v6));

	/* punt on this for now */
	lxpr_uiobuf_printf(uiobuf, "%s %02x ",
	    "00000000000000000000000000000000", 0);

	lxpr_inet6_out(&ire->ire_gateway_addr_v6, ipv6addr);
	lxpr_uiobuf_printf(uiobuf, "%s", ipv6addr);

	flags = ire->ire_flags &
	    (RTF_UP|RTF_GATEWAY|RTF_HOST|RTF_DYNAMIC|RTF_MODIFIED);
	/* Linux's RTF_LOCAL equivalent */
	if (ire->ire_metrics.iulp_local)
		flags |= 0x80000000;

	if (ire->ire_ill != NULL) {
		ill_get_name(ire->ire_ill, name, sizeof (name));
		lx_ifname_convert(name, LX_IFNAME_FROMNATIVE);
	} else {
		name[0] = '\0';
	}

	lxpr_uiobuf_printf(uiobuf, " %08x %08x %08x %08x %8s\n",
	    0, /* metric */
	    ire->ire_refcnt,
	    0,
	    flags,
	    name);
}

/* ARGSUSED */
static void
lxpr_read_net_ipv6_route(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	netstack_t *ns;
	ip_stack_t *ipst;

	ns = netstack_get_current();
	if (ns == NULL)
		return;
	ipst = ns->netstack_ip;

	/*
	 * LX branded zones are expected to have exclusive IP stack, hence
	 * using ALL_ZONES as the zoneid filter.
	 */
	ire_walk_v6(&lxpr_format_route_ipv6, uiobuf, ALL_ZONES, ipst);

	netstack_rele(ns);
}

/* ARGSUSED */
static void
lxpr_read_net_mcfilter(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_netstat(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_raw(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

#define	LXPR_SKIP_ROUTE(type)	\
	(((IRE_IF_CLONE | IRE_BROADCAST | IRE_MULTICAST | \
	IRE_NOROUTE | IRE_LOOPBACK | IRE_LOCAL) & type) != 0)

static void
lxpr_format_route_ipv4(ire_t *ire, lxpr_uiobuf_t *uiobuf)
{
	uint32_t flags;
	char name[IFNAMSIZ];
	ill_t *ill;
	ire_t *nire;
	ipif_t *ipif;
	ipaddr_t gateway;

	if (LXPR_SKIP_ROUTE(ire->ire_type) || ire->ire_testhidden != 0)
		return;

	/* These route flags have direct Linux equivalents */
	flags = ire->ire_flags &
	    (RTF_UP|RTF_GATEWAY|RTF_HOST|RTF_DYNAMIC|RTF_MODIFIED);

	/*
	 * Search for a suitable IRE for naming purposes.
	 * On Linux, the default route is typically associated with the
	 * interface used to access gateway.  The default IRE on Illumos
	 * typically lacks an ill reference but its parent might have one.
	 */
	nire = ire;
	do {
		ill = nire->ire_ill;
		nire = nire->ire_dep_parent;
	} while (ill == NULL && nire != NULL);
	if (ill != NULL) {
		ill_get_name(ill, name, sizeof (name));
		lx_ifname_convert(name, LX_IFNAME_FROMNATIVE);
	} else {
		name[0] = '*';
		name[1] = '\0';
	}

	/*
	 * Linux suppresses the gateway address for directly connected
	 * interface networks.  To emulate this behavior, we walk all addresses
	 * of a given route interface.  If one matches the gateway, it is
	 * displayed as NULL.
	 */
	gateway = ire->ire_gateway_addr;
	if ((ill = ire->ire_ill) != NULL) {
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (ipif->ipif_lcl_addr == gateway) {
				gateway = 0;
				break;
			}
		}
	}

	lxpr_uiobuf_printf(uiobuf, "%s\t%08X\t%08X\t%04X\t%d\t%u\t"
	    "%d\t%08X\t%d\t%u\t%u\n",
	    name,
	    ire->ire_addr,
	    gateway,
	    flags, 0, 0,
	    0, /* priority */
	    ire->ire_mask,
	    0, 0, /* mss, window */
	    ire->ire_metrics.iulp_rtt);
}

/* ARGSUSED */
static void
lxpr_read_net_route(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	netstack_t *ns;
	ip_stack_t *ipst;

	lxpr_uiobuf_printf(uiobuf, "Iface\tDestination\tGateway \tFlags\t"
	    "RefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");

	ns = netstack_get_current();
	if (ns == NULL)
		return;
	ipst = ns->netstack_ip;

	/*
	 * LX branded zones are expected to have exclusive IP stack, hence
	 * using ALL_ZONES as the zoneid filter.
	 */
	ire_walk_v4(&lxpr_format_route_ipv4, uiobuf, ALL_ZONES, ipst);

	netstack_rele(ns);
}

/* ARGSUSED */
static void
lxpr_read_net_rpc(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_rt_cache(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_sockstat(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

typedef struct lxpr_snmp_table {
	const char *lst_proto;
	const char *lst_fields[];
} lxpr_snmp_table_t;

static lxpr_snmp_table_t lxpr_snmp_ip = { "ip",
	{
	"forwarding", "defaultTTL", "inReceives", "inHdrErrors",
	"inAddrErrors", "forwDatagrams", "inUnknownProtos", "inDiscards",
	"inDelivers", "outRequests", "outDiscards", "outNoRoutes",
	"reasmTimeout", "reasmReqds", "reasmOKs", "reasmFails", "fragOKs",
	"fragFails", "fragCreates",
	NULL
	}
};
static lxpr_snmp_table_t lxpr_snmp_icmp = { "icmp",
	{
	"inMsgs", "inErrors", "inCsumErrors", "inDestUnreachs", "inTimeExcds",
	"inParmProbs", "inSrcQuenchs", "inRedirects", "inEchos", "inEchoReps",
	"inTimestamps", "inTimestampReps", "inAddrMasks", "inAddrMaskReps",
	"outMsgs", "outErrors", "outDestUnreachs", "outTimeExcds",
	"outParmProbs", "outSrcQuenchs", "outRedirects", "outEchos",
	"outEchoReps", "outTimestamps", "outTimestampReps", "outAddrMasks",
	"outAddrMaskReps",
	NULL
	}
};
static lxpr_snmp_table_t lxpr_snmp_tcp = { "tcp",
	{
	"rtoAlgorithm", "rtoMin", "rtoMax", "maxConn", "activeOpens",
	"passiveOpens", "attemptFails", "estabResets", "currEstab", "inSegs",
	"outSegs", "retransSegs", "inErrs", "outRsts", "inCsumErrors",
	NULL
	}
};
static lxpr_snmp_table_t lxpr_snmp_udp = { "udp",
	{
	"inDatagrams", "noPorts", "inErrors", "outDatagrams", "rcvbufErrors",
	"sndbufErrors", "inCsumErrors",
	NULL
	}
};

static lxpr_snmp_table_t *lxpr_net_snmptab[] = {
	&lxpr_snmp_ip,
	&lxpr_snmp_icmp,
	&lxpr_snmp_tcp,
	&lxpr_snmp_udp,
	NULL
};

static void
lxpr_kstat_print_tab(lxpr_uiobuf_t *uiobuf, lxpr_snmp_table_t *table,
    kstat_t *kn)
{
	kstat_named_t *klist;
	char upname[KSTAT_STRLEN], upfield[KSTAT_STRLEN];
	int i, j, num;
	size_t size;

	klist = (kstat_named_t *)lxpr_kstat_read(kn, B_TRUE, &size, &num);
	if (klist == NULL)
		return;

	/* Print the header line, fields capitalized */
	(void) strncpy(upname, table->lst_proto, KSTAT_STRLEN);
	upname[0] = toupper(upname[0]);
	lxpr_uiobuf_printf(uiobuf, "%s:", upname);
	for (i = 0; table->lst_fields[i] != NULL; i++) {
		(void) strncpy(upfield, table->lst_fields[i], KSTAT_STRLEN);
		upfield[0] = toupper(upfield[0]);
		lxpr_uiobuf_printf(uiobuf, " %s", upfield);
	}
	lxpr_uiobuf_printf(uiobuf, "\n%s:", upname);

	/* Then loop back through to print the value line. */
	for (i = 0; table->lst_fields[i] != NULL; i++) {
		kstat_named_t *kpoint = NULL;
		for (j = 0; j < num; j++) {
			if (strncmp(klist[j].name, table->lst_fields[i],
			    KSTAT_STRLEN) == 0) {
				kpoint = &klist[j];
				break;
			}
		}
		if (kpoint == NULL) {
			/* Output 0 for unknown fields */
			lxpr_uiobuf_printf(uiobuf, " 0");
		} else {
			switch (kpoint->data_type) {
			case KSTAT_DATA_INT32:
				lxpr_uiobuf_printf(uiobuf, " %d",
				    kpoint->value.i32);
				break;
			case KSTAT_DATA_UINT32:
				lxpr_uiobuf_printf(uiobuf, " %u",
				    kpoint->value.ui32);
				break;
			case KSTAT_DATA_INT64:
				lxpr_uiobuf_printf(uiobuf, " %ld",
				    kpoint->value.l);
				break;
			case KSTAT_DATA_UINT64:
				lxpr_uiobuf_printf(uiobuf, " %lu",
				    kpoint->value.ul);
				break;
			}
		}
	}
	lxpr_uiobuf_printf(uiobuf, "\n");
	kmem_free(klist, size);
}

/* ARGSUSED */
static void
lxpr_read_net_snmp(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	kstat_t *ksr;
	kstat_t ks0;
	lxpr_snmp_table_t **table = lxpr_net_snmptab;
	int i, t, nidx;
	size_t sidx;

	ks0.ks_kid = 0;
	ksr = (kstat_t *)lxpr_kstat_read(&ks0, B_FALSE, &sidx, &nidx);
	if (ksr == NULL)
		return;

	for (t = 0; table[t] != NULL; t++) {
		for (i = 0; i < nidx; i++) {
			if (strncmp(ksr[i].ks_class, "mib2", KSTAT_STRLEN) != 0)
				continue;
			if (strncmp(ksr[i].ks_name, table[t]->lst_proto,
			    KSTAT_STRLEN) == 0) {
				lxpr_kstat_print_tab(uiobuf, table[t], &ksr[i]);
				break;
			}
		}
	}
	kmem_free(ksr, sidx);
}

/* ARGSUSED */
static void
lxpr_read_net_stat(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

static int
lxpr_convert_tcp_state(int st)
{
	/*
	 * Derived from the enum located in the Linux kernel sources:
	 * include/net/tcp_states.h
	 */
	switch (st) {
	case TCPS_ESTABLISHED:
		return (1);
	case TCPS_SYN_SENT:
		return (2);
	case TCPS_SYN_RCVD:
		return (3);
	case TCPS_FIN_WAIT_1:
		return (4);
	case TCPS_FIN_WAIT_2:
		return (5);
	case TCPS_TIME_WAIT:
		return (6);
	case TCPS_CLOSED:
		return (7);
	case TCPS_CLOSE_WAIT:
		return (8);
	case TCPS_LAST_ACK:
		return (9);
	case TCPS_LISTEN:
		return (10);
	case TCPS_CLOSING:
		return (11);
	default:
		/* No translation for TCPS_IDLE, TCPS_BOUND or anything else */
		return (0);
	}
}

static void
lxpr_format_tcp(lxpr_uiobuf_t *uiobuf, ushort_t ipver)
{
	int i, sl = 0;
	connf_t *connfp;
	conn_t *connp;
	netstack_t *ns;
	ip_stack_t *ipst;

	ASSERT(ipver == IPV4_VERSION || ipver == IPV6_VERSION);
	if (ipver == IPV4_VERSION) {
		lxpr_uiobuf_printf(uiobuf, "  sl  local_address rem_address   "
		    "st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout "
		    "inode\n");
	} else {
		lxpr_uiobuf_printf(uiobuf, "  sl  "
		    "local_address                         "
		    "remote_address                        "
		    "st tx_queue rx_queue tr tm->when retrnsmt   "
		    "uid  timeout inode\n");
	}
	/*
	 * Due to differences between the Linux and illumos TCP
	 * implementations, some data will be omitted from the output here.
	 *
	 * Valid fields:
	 *  - local_address
	 *  - remote_address
	 *  - st
	 *  - tx_queue
	 *  - rx_queue
	 *  - uid
	 *  - inode
	 *
	 * Omitted/invalid fields
	 *  - tr
	 *  - tm->when
	 *  - retrnsmt
	 *  - timeout
	 */

	ns = netstack_get_current();
	if (ns == NULL)
		return;
	ipst = ns->netstack_ip;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		connfp = &ipst->ips_ipcl_globalhash_fanout[i];
		connp = NULL;
		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCPCONN)) != NULL) {
			tcp_t *tcp;
			vattr_t attr;
			sonode_t *so = (sonode_t *)connp->conn_upper_handle;
			vnode_t *vp = (so != NULL) ? so->so_vnode : NULL;
			if (connp->conn_ipversion != ipver)
				continue;
			tcp = connp->conn_tcp;
			if (ipver == IPV4_VERSION) {
				lxpr_uiobuf_printf(uiobuf,
				    "%4d: %08X:%04X %08X:%04X ",
				    ++sl,
				    connp->conn_laddr_v4,
				    ntohs(connp->conn_lport),
				    connp->conn_faddr_v4,
				    ntohs(connp->conn_fport));
			} else {
				lxpr_uiobuf_printf(uiobuf, "%4d: "
				    "%08X%08X%08X%08X:%04X "
				    "%08X%08X%08X%08X:%04X ",
				    ++sl,
				    connp->conn_laddr_v6.s6_addr32[0],
				    connp->conn_laddr_v6.s6_addr32[1],
				    connp->conn_laddr_v6.s6_addr32[2],
				    connp->conn_laddr_v6.s6_addr32[3],
				    ntohs(connp->conn_lport),
				    connp->conn_faddr_v6.s6_addr32[0],
				    connp->conn_faddr_v6.s6_addr32[1],
				    connp->conn_faddr_v6.s6_addr32[2],
				    connp->conn_faddr_v6.s6_addr32[3],
				    ntohs(connp->conn_fport));
			}

			/* fetch the simulated inode for the socket */
			if (vp == NULL ||
			    VOP_GETATTR(vp, &attr, 0, CRED(), NULL) != 0)
				attr.va_nodeid = 0;

			lxpr_uiobuf_printf(uiobuf,
			    "%02X %08X:%08X %02X:%08X %08X "
			    "%5u %8d %lu %d %p %u %u %u %u %d\n",
			    lxpr_convert_tcp_state(tcp->tcp_state),
			    tcp->tcp_rcv_cnt, tcp->tcp_unsent, /* rx/tx queue */
			    0, 0, /* tr, when */
			    0, /* per-connection rexmits aren't tracked today */
			    connp->conn_cred->cr_uid,
			    0, /* timeout */
			    /* inode + more */
			    (ino_t)attr.va_nodeid, 0, NULL, 0, 0, 0, 0, 0);
		}
	}
	netstack_rele(ns);
}

/* ARGSUSED */
static void
lxpr_read_net_tcp(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_format_tcp(uiobuf, IPV4_VERSION);
}

/* ARGSUSED */
static void
lxpr_read_net_tcp6(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_format_tcp(uiobuf, IPV6_VERSION);
}

static void
lxpr_format_udp(lxpr_uiobuf_t *uiobuf, ushort_t ipver)
{
	int i, sl = 0;
	connf_t *connfp;
	conn_t *connp;
	netstack_t *ns;
	ip_stack_t *ipst;

	ASSERT(ipver == IPV4_VERSION || ipver == IPV6_VERSION);
	if (ipver == IPV4_VERSION) {
		lxpr_uiobuf_printf(uiobuf, "  sl  local_address rem_address"
		    "   st tx_queue rx_queue tr tm->when retrnsmt   uid"
		    "  timeout inode ref pointer drops\n");
	} else {
		lxpr_uiobuf_printf(uiobuf, "  sl  "
		    "local_address                         "
		    "remote_address                        "
		    "st tx_queue rx_queue tr tm->when retrnsmt   "
		    "uid  timeout inode ref pointer drops\n");
	}
	/*
	 * Due to differences between the Linux and illumos UDP
	 * implementations, some data will be omitted from the output here.
	 *
	 * Valid fields:
	 *  - local_address
	 *  - remote_address
	 *  - st: limited
	 *  - uid
	 *
	 * Omitted/invalid fields
	 *  - tx_queue
	 *  - rx_queue
	 *  - tr
	 *  - tm->when
	 *  - retrnsmt
	 *  - timeout
	 *  - inode
	 */

	ns = netstack_get_current();
	if (ns == NULL)
		return;
	ipst = ns->netstack_ip;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		connfp = &ipst->ips_ipcl_globalhash_fanout[i];
		connp = NULL;
		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_UDPCONN)) != NULL) {
			udp_t *udp;
			int state = 0;
			vattr_t attr;
			sonode_t *so = (sonode_t *)connp->conn_upper_handle;
			vnode_t *vp = (so != NULL) ? so->so_vnode : NULL;
			if (connp->conn_ipversion != ipver)
				continue;
			udp = connp->conn_udp;
			if (ipver == IPV4_VERSION) {
				lxpr_uiobuf_printf(uiobuf,
				    "%4d: %08X:%04X %08X:%04X ",
				    ++sl,
				    connp->conn_laddr_v4,
				    ntohs(connp->conn_lport),
				    connp->conn_faddr_v4,
				    ntohs(connp->conn_fport));
			} else {
				lxpr_uiobuf_printf(uiobuf, "%4d: "
				    "%08X%08X%08X%08X:%04X "
				    "%08X%08X%08X%08X:%04X ",
				    ++sl,
				    connp->conn_laddr_v6.s6_addr32[0],
				    connp->conn_laddr_v6.s6_addr32[1],
				    connp->conn_laddr_v6.s6_addr32[2],
				    connp->conn_laddr_v6.s6_addr32[3],
				    ntohs(connp->conn_lport),
				    connp->conn_faddr_v6.s6_addr32[0],
				    connp->conn_faddr_v6.s6_addr32[1],
				    connp->conn_faddr_v6.s6_addr32[2],
				    connp->conn_faddr_v6.s6_addr32[3],
				    ntohs(connp->conn_fport));
			}

			switch (udp->udp_state) {
			case TS_UNBND:
			case TS_IDLE:
				state = 7;
				break;
			case TS_DATA_XFER:
				state = 1;
				break;
			}

			/* fetch the simulated inode for the socket */
			if (vp == NULL ||
			    VOP_GETATTR(vp, &attr, 0, CRED(), NULL) != 0)
				attr.va_nodeid = 0;

			lxpr_uiobuf_printf(uiobuf,
			    "%02X %08X:%08X %02X:%08X %08X "
			    "%5u %8d %lu %d %p %d\n",
			    state,
			    0, 0, /* rx/tx queue */
			    0, 0, /* tr, when */
			    0, /* retrans */
			    connp->conn_cred->cr_uid,
			    0, /* timeout */
			    /* inode, ref, pointer, drops */
			    (ino_t)attr.va_nodeid, 0, NULL, 0);
		}
	}
	netstack_rele(ns);
}

/* ARGSUSED */
static void
lxpr_read_net_udp(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_format_udp(uiobuf, IPV4_VERSION);
}

/* ARGSUSED */
static void
lxpr_read_net_udp6(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_format_udp(uiobuf, IPV6_VERSION);
}

/* ARGSUSED */
static void
lxpr_read_net_unix(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	sonode_t *so;
	zoneid_t zoneid = getzoneid();

	lxpr_uiobuf_printf(uiobuf, "Num       RefCount Protocol Flags    Type "
	    "St Inode Path\n");

	mutex_enter(&socklist.sl_lock);
	for (so = socklist.sl_list; so != NULL;
	    so = _SOTOTPI(so)->sti_next_so) {
		vnode_t *vp = so->so_vnode;
		vattr_t attr;
		sotpi_info_t *sti;
		const char *name = NULL;
		int status = 0;
		int type = 0;
		int flags = 0;

		/* Only process active sonodes in this zone */
		if (so->so_count == 0 || so->so_zoneid != zoneid)
			continue;

		/*
		 * Grab the inode, if possible.
		 * This must be done before entering so_lock.
		 */
		if (vp == NULL ||
		    VOP_GETATTR(vp, &attr, 0, CRED(), NULL) != 0)
			attr.va_nodeid = 0;

		mutex_enter(&so->so_lock);
		sti = _SOTOTPI(so);

		if (sti->sti_laddr_sa != NULL)
			name = sti->sti_laddr_sa->sa_data;
		else if (sti->sti_faddr_sa != NULL)
			name = sti->sti_faddr_sa->sa_data;

		/*
		 * Derived from enum values in Linux kernel source:
		 * include/uapi/linux/net.h
		 */
		if ((so->so_state & SS_ISDISCONNECTING) != 0) {
			status = 4;
		} else if ((so->so_state & SS_ISCONNECTING) != 0) {
			status = 2;
		} else if ((so->so_state & SS_ISCONNECTED) != 0) {
			status = 3;
		} else {
			status = 1;
			/* Add ACC flag for stream-type server sockets */
			if (so->so_type != SOCK_DGRAM &&
			    sti->sti_laddr_sa != NULL)
				flags |= 0x10000;
		}

		/* Convert to Linux type */
		switch (so->so_type) {
		case SOCK_DGRAM:
			type = 2;
			break;
		case SOCK_SEQPACKET:
			type = 5;
			break;
		default:
			type = 1;
		}

		lxpr_uiobuf_printf(uiobuf, "%p: %08X %08X %08X %04X %02X %5llu",
		    so,
		    so->so_count,
		    0, /* proto, always 0 */
		    flags,
		    type,
		    status,
		    (ino_t)attr.va_nodeid);

		/*
		 * Due to shortcomings in the abstract socket emulation, they
		 * cannot be properly represented here (as @<path>).
		 *
		 * This will be the case until they are better implemented.
		 */
		if (name != NULL)
			lxpr_uiobuf_printf(uiobuf, " %s\n", name);
		else
			lxpr_uiobuf_printf(uiobuf, "\n");
		mutex_exit(&so->so_lock);
	}
	mutex_exit(&socklist.sl_lock);
}

/*
 * lxpr_read_kmsg(): read the contents of the kernel message queue. We
 * translate this into the reception of console messages for this zone; each
 * read copies out a single zone console message, or blocks until the next one
 * is produced, unless we're open non-blocking, in which case we return after
 * 1ms.
 */

#define	LX_KMSG_PRI	"<0>"

static void
lxpr_read_kmsg(lxpr_node_t *lxpnp, struct lxpr_uiobuf *uiobuf)
{
	ldi_handle_t	lh = lxpnp->lxpr_cons_ldih;
	mblk_t		*mp;
	timestruc_t	to;
	timestruc_t	*tp = NULL;

	ASSERT(lxpnp->lxpr_type == LXPR_KMSG);

	if (lxpr_uiobuf_nonblock(uiobuf)) {
		to.tv_sec = 0;
		to.tv_nsec = 1000000; /* 1msec */
		tp = &to;
	}

	if (ldi_getmsg(lh, &mp, tp) == 0) {
		/*
		 * lx procfs doesn't like successive reads to the same file
		 * descriptor unless we do an explicit rewind each time.
		 */
		lxpr_uiobuf_seek(uiobuf, 0);

		lxpr_uiobuf_printf(uiobuf, "%s%s", LX_KMSG_PRI,
		    mp->b_cont->b_rptr);

		freemsg(mp);
	}
}

/*
 * lxpr_read_loadavg(): read the contents of the "loadavg" file.  We do just
 * enough for uptime and other simple lxproc readers to work
 */
extern int nthread;

static void
lxpr_read_loadavg(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	ulong_t avenrun1;
	ulong_t avenrun5;
	ulong_t avenrun15;
	ulong_t avenrun1_cs;
	ulong_t avenrun5_cs;
	ulong_t avenrun15_cs;
	int loadavg[3];
	int *loadbuf;
	cpupart_t *cp;
	zone_t *zone = LXPTOZ(lxpnp);

	uint_t nrunnable = 0;
	rctl_qty_t nlwps;

	ASSERT(lxpnp->lxpr_type == LXPR_LOADAVG);

	mutex_enter(&cpu_lock);

	/*
	 * Need to add up values over all CPU partitions. If pools are active,
	 * only report the values of the zone's partition, which by definition
	 * includes the current CPU.
	 */
	if (pool_pset_enabled()) {
		psetid_t psetid = zone_pset_get(curproc->p_zone);

		ASSERT(curproc->p_zone != &zone0);
		cp = CPU->cpu_part;

		nrunnable = cp->cp_nrunning + cp->cp_nrunnable;
		(void) cpupart_get_loadavg(psetid, &loadavg[0], 3);
		loadbuf = &loadavg[0];
	} else {
		cp = cp_list_head;
		do {
			nrunnable += cp->cp_nrunning + cp->cp_nrunnable;
		} while ((cp = cp->cp_next) != cp_list_head);

		loadbuf = zone == global_zone ?
		    &avenrun[0] : zone->zone_avenrun;
	}

	/*
	 * If we're in the non-global zone, we'll report the total number of
	 * LWPs in the zone for the "nproc" parameter of /proc/loadavg,
	 * otherwise will just use nthread (which will include kernel threads,
	 * but should be good enough for lxproc).
	 */
	nlwps = zone == global_zone ? nthread : zone->zone_nlwps;

	mutex_exit(&cpu_lock);

	avenrun1 = loadbuf[0] >> FSHIFT;
	avenrun1_cs = ((loadbuf[0] & (FSCALE-1)) * 100) >> FSHIFT;
	avenrun5 = loadbuf[1] >> FSHIFT;
	avenrun5_cs = ((loadbuf[1] & (FSCALE-1)) * 100) >> FSHIFT;
	avenrun15 = loadbuf[2] >> FSHIFT;
	avenrun15_cs = ((loadbuf[2] & (FSCALE-1)) * 100) >> FSHIFT;

	lxpr_uiobuf_printf(uiobuf,
	    "%ld.%02d %ld.%02d %ld.%02d %d/%d %d\n",
	    avenrun1, avenrun1_cs,
	    avenrun5, avenrun5_cs,
	    avenrun15, avenrun15_cs,
	    nrunnable, nlwps, 0);
}

/*
 * lxpr_read_meminfo(): read the contents of the "meminfo" file.
 */
static void
lxpr_read_meminfo(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	zone_t *zone = LXPTOZ(lxpnp);
	int global = zone == global_zone;
	long total_mem, free_mem, total_swap, used_swap;

	ASSERT(lxpnp->lxpr_type == LXPR_MEMINFO);

	if (global || zone->zone_phys_mem_ctl == UINT64_MAX) {
		total_mem = physmem * PAGESIZE;
		free_mem = freemem * PAGESIZE;
	} else {
		total_mem = zone->zone_phys_mem_ctl;
		free_mem = zone->zone_phys_mem_ctl - zone->zone_phys_mem;
	}

	if (global || zone->zone_max_swap_ctl == UINT64_MAX) {
		total_swap = k_anoninfo.ani_max * PAGESIZE;
		used_swap = k_anoninfo.ani_phys_resv * PAGESIZE;
	} else {
		mutex_enter(&zone->zone_mem_lock);
		total_swap = zone->zone_max_swap_ctl;
		used_swap = zone->zone_max_swap;
		mutex_exit(&zone->zone_mem_lock);
	}

	lxpr_uiobuf_printf(uiobuf,
	    "MemTotal:  %8lu kB\n"
	    "MemFree:   %8lu kB\n"
	    "MemShared: %8u kB\n"
	    "Buffers:   %8u kB\n"
	    "Cached:    %8u kB\n"
	    "SwapCached:%8u kB\n"
	    "Active:    %8u kB\n"
	    "Inactive:  %8u kB\n"
	    "HighTotal: %8u kB\n"
	    "HighFree:  %8u kB\n"
	    "LowTotal:  %8u kB\n"
	    "LowFree:   %8u kB\n"
	    "SwapTotal: %8lu kB\n"
	    "SwapFree:  %8lu kB\n",
	    btok(total_mem),				/* MemTotal */
	    btok(free_mem),				/* MemFree */
	    0,						/* MemShared */
	    0,						/* Buffers */
	    0,						/* Cached */
	    0,						/* SwapCached */
	    0,						/* Active */
	    0,						/* Inactive */
	    0,						/* HighTotal */
	    0,						/* HighFree */
	    btok(total_mem),				/* LowTotal */
	    btok(free_mem),				/* LowFree */
	    btok(total_swap),				/* SwapTotal */
	    btok(total_swap - used_swap));		/* SwapFree */
}

/*
 * lxpr_read_mounts():
 */
/* ARGSUSED */
static void
lxpr_read_mounts(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	struct vfs *vfsp;
	struct vfs *vfslist;
	zone_t *zone = LXPTOZ(lxpnp);
	struct print_data {
		refstr_t *vfs_mntpt;
		refstr_t *vfs_resource;
		uint_t vfs_flag;
		int vfs_fstype;
		struct print_data *next;
	} *print_head = NULL;
	struct print_data **print_tail = &print_head;
	struct print_data *printp;

	vfs_list_read_lock();

	if (zone == global_zone) {
		vfsp = vfslist = rootvfs;
	} else {
		vfsp = vfslist = zone->zone_vfslist;
		/*
		 * If the zone has a root entry, it will be the first in
		 * the list.  If it doesn't, we conjure one up.
		 */
		if (vfslist == NULL || strcmp(refstr_value(vfsp->vfs_mntpt),
		    zone->zone_rootpath) != 0) {
			struct vfs *tvfsp;
			/*
			 * The root of the zone is not a mount point.  The vfs
			 * we want to report is that of the zone's root vnode.
			 */
			tvfsp = zone->zone_rootvp->v_vfsp;

			lxpr_uiobuf_printf(uiobuf,
			    "/ / %s %s 0 0\n",
			    vfssw[tvfsp->vfs_fstype].vsw_name,
			    tvfsp->vfs_flag & VFS_RDONLY ? "ro" : "rw");

		}
		if (vfslist == NULL) {
			vfs_list_unlock();
			return;
		}
	}

	/*
	 * Later on we have to do a lookupname, which can end up causing
	 * another vfs_list_read_lock() to be called. Which can lead to a
	 * deadlock. To avoid this, we extract the data we need into a local
	 * list, then we can run this list without holding vfs_list_read_lock()
	 * We keep the list in the same order as the vfs_list
	 */
	do {
		/* Skip mounts we shouldn't show */
		if (vfsp->vfs_flag & VFS_NOMNTTAB) {
			goto nextfs;
		}

		printp = kmem_alloc(sizeof (*printp), KM_SLEEP);
		refstr_hold(vfsp->vfs_mntpt);
		printp->vfs_mntpt = vfsp->vfs_mntpt;
		refstr_hold(vfsp->vfs_resource);
		printp->vfs_resource = vfsp->vfs_resource;
		printp->vfs_flag = vfsp->vfs_flag;
		printp->vfs_fstype = vfsp->vfs_fstype;
		printp->next = NULL;

		*print_tail = printp;
		print_tail = &printp->next;

nextfs:
		vfsp = (zone == global_zone) ?
		    vfsp->vfs_next : vfsp->vfs_zone_next;

	} while (vfsp != vfslist);

	vfs_list_unlock();

	/*
	 * now we can run through what we've extracted without holding
	 * vfs_list_read_lock()
	 */
	printp = print_head;
	while (printp != NULL) {
		struct print_data *printp_next;
		const char *resource;
		char *mntpt;
		struct vnode *vp;
		int error;

		mntpt = (char *)refstr_value(printp->vfs_mntpt);
		resource = refstr_value(printp->vfs_resource);

		if (mntpt != NULL && mntpt[0] != '\0')
			mntpt = ZONE_PATH_TRANSLATE(mntpt, zone);
		else
			mntpt = "-";

		error = lookupname(mntpt, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);

		if (error != 0)
			goto nextp;

		if (!(vp->v_flag & VROOT)) {
			VN_RELE(vp);
			goto nextp;
		}
		VN_RELE(vp);

		if (resource != NULL && resource[0] != '\0') {
			if (resource[0] == '/') {
				resource = ZONE_PATH_VISIBLE(resource, zone) ?
				    ZONE_PATH_TRANSLATE(resource, zone) :
				    mntpt;
			}
		} else {
			resource = "-";
		}

		lxpr_uiobuf_printf(uiobuf,
		    "%s %s %s %s 0 0\n",
		    resource, mntpt, vfssw[printp->vfs_fstype].vsw_name,
		    printp->vfs_flag & VFS_RDONLY ? "ro" : "rw");

nextp:
		printp_next = printp->next;
		refstr_rele(printp->vfs_mntpt);
		refstr_rele(printp->vfs_resource);
		kmem_free(printp, sizeof (*printp));
		printp = printp_next;

	}
}

/*
 * lxpr_read_partitions():
 *
 * We don't support partitions in a local zone because it requires access to
 * physical devices.  But we need to fake up enough of the file to show that we
 * have no partitions.
 */
/* ARGSUSED */
static void
lxpr_read_partitions(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_uiobuf_printf(uiobuf,
	    "major minor  #blocks  name     rio rmerge rsect ruse "
	    "wio wmerge wsect wuse running use aveq\n\n");
}

/*
 * lxpr_read_version(): read the contents of the "version" file.
 */
/* ARGSUSED */
static void
lxpr_read_version(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	char *vers;

	vers = lx_get_zone_kern_version(LXPTOZ(lxpnp));

	lxpr_uiobuf_printf(uiobuf,
	    "%s version %s (%s version %d.%d.%d) "
	    "#%s SMP %s\n",
	    LX_UNAME_SYSNAME, vers,
#if defined(__GNUC__)
	    "gcc",
	    __GNUC__,
	    __GNUC_MINOR__,
	    __GNUC_PATCHLEVEL__,
#else
	    "Sun C",
	    __SUNPRO_C / 0x100,
	    (__SUNPRO_C & 0xff) / 0x10,
	    __SUNPRO_C & 0xf,
#endif
	    LX_UNAME_VERSION,
	    "00:00:00 00/00/00");
}

/*
 * lxpr_read_stat(): read the contents of the "stat" file.
 *
 */
/* ARGSUSED */
static void
lxpr_read_stat(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	cpu_t *cp, *cpstart;
	int pools_enabled;
	ulong_t idle_cum = 0;
	ulong_t sys_cum  = 0;
	ulong_t user_cum = 0;
	ulong_t irq_cum = 0;
	ulong_t cpu_nrunnable_cum = 0;
	ulong_t w_io_cum = 0;

	ulong_t pgpgin_cum    = 0;
	ulong_t pgpgout_cum   = 0;
	ulong_t pgswapout_cum = 0;
	ulong_t pgswapin_cum  = 0;
	ulong_t intr_cum = 0;
	ulong_t pswitch_cum = 0;
	ulong_t forks_cum = 0;
	hrtime_t msnsecs[NCMSTATES];
	char *lx_kern_version = lx_get_zone_kern_version(LXPTOZ(lxpnp));
	/* temporary variable since scalehrtime modifies data in place */
	hrtime_t tmptime;

	ASSERT(lxpnp->lxpr_type == LXPR_STAT);

	mutex_enter(&cpu_lock);
	pools_enabled = pool_pset_enabled();

	/* Calculate cumulative stats */
	cp = cpstart = CPU->cpu_part->cp_cpulist;
	do {
		int i;

		/*
		 * Don't count CPUs that aren't even in the system
		 * or aren't up yet.
		 */
		if ((cp->cpu_flags & CPU_EXISTS) == 0) {
			continue;
		}

		get_cpu_mstate(cp, msnsecs);

		idle_cum += NSEC_TO_TICK(msnsecs[CMS_IDLE]);
		sys_cum  += NSEC_TO_TICK(msnsecs[CMS_SYSTEM]);
		user_cum += NSEC_TO_TICK(msnsecs[CMS_USER]);

		pgpgin_cum += CPU_STATS(cp, vm.pgpgin);
		pgpgout_cum += CPU_STATS(cp, vm.pgpgout);
		pgswapin_cum += CPU_STATS(cp, vm.pgswapin);
		pgswapout_cum += CPU_STATS(cp, vm.pgswapout);

		if (strncmp(lx_kern_version, "2.4", 3) != 0) {
			cpu_nrunnable_cum += cp->cpu_disp->disp_nrunnable;
			w_io_cum += CPU_STATS(cp, sys.iowait);
			for (i = 0; i < NCMSTATES; i++) {
				tmptime = cp->cpu_intracct[i];
				scalehrtime(&tmptime);
				irq_cum += NSEC_TO_TICK(tmptime);
			}
		}

		for (i = 0; i < PIL_MAX; i++)
			intr_cum += CPU_STATS(cp, sys.intr[i]);

		pswitch_cum += CPU_STATS(cp, sys.pswitch);
		forks_cum += CPU_STATS(cp, sys.sysfork);
		forks_cum += CPU_STATS(cp, sys.sysvfork);

		if (pools_enabled)
			cp = cp->cpu_next_part;
		else
			cp = cp->cpu_next;
	} while (cp != cpstart);

	if (strncmp(lx_kern_version, "2.4", 3) != 0) {
		lxpr_uiobuf_printf(uiobuf,
		    "cpu %lu %lu %lu %lu %lu %lu %lu\n",
		    user_cum, 0L, sys_cum, idle_cum, 0L, irq_cum, 0L);
	} else {
		lxpr_uiobuf_printf(uiobuf,
		    "cpu %lu %lu %lu %lu\n",
		    user_cum, 0L, sys_cum, idle_cum);
	}

	/* Do per processor stats */
	do {
		int i;

		ulong_t idle_ticks;
		ulong_t sys_ticks;
		ulong_t user_ticks;
		ulong_t irq_ticks = 0;

		/*
		 * Don't count CPUs that aren't even in the system
		 * or aren't up yet.
		 */
		if ((cp->cpu_flags & CPU_EXISTS) == 0) {
			continue;
		}

		get_cpu_mstate(cp, msnsecs);

		idle_ticks = NSEC_TO_TICK(msnsecs[CMS_IDLE]);
		sys_ticks  = NSEC_TO_TICK(msnsecs[CMS_SYSTEM]);
		user_ticks = NSEC_TO_TICK(msnsecs[CMS_USER]);

		for (i = 0; i < NCMSTATES; i++) {
			tmptime = cp->cpu_intracct[i];
			scalehrtime(&tmptime);
			irq_ticks += NSEC_TO_TICK(tmptime);
		}

		if (strncmp(lx_kern_version, "2.4", 3) != 0) {
			lxpr_uiobuf_printf(uiobuf,
			    "cpu%d %lu %lu %lu %lu %lu %lu %lu\n",
			    cp->cpu_id, user_ticks, 0L, sys_ticks, idle_ticks,
			    0L, irq_ticks, 0L);
		} else {
			lxpr_uiobuf_printf(uiobuf,
			    "cpu%d %lu %lu %lu %lu\n",
			    cp->cpu_id,
			    user_ticks, 0L, sys_ticks, idle_ticks);
		}

		if (pools_enabled)
			cp = cp->cpu_next_part;
		else
			cp = cp->cpu_next;
	} while (cp != cpstart);

	mutex_exit(&cpu_lock);

	if (strncmp(lx_kern_version, "2.4", 3) != 0) {
		lxpr_uiobuf_printf(uiobuf,
		    "page %lu %lu\n"
		    "swap %lu %lu\n"
		    "intr %lu\n"
		    "ctxt %lu\n"
		    "btime %lu\n"
		    "processes %lu\n"
		    "procs_running %lu\n"
		    "procs_blocked %lu\n",
		    pgpgin_cum, pgpgout_cum,
		    pgswapin_cum, pgswapout_cum,
		    intr_cum,
		    pswitch_cum,
		    boot_time,
		    forks_cum,
		    cpu_nrunnable_cum,
		    w_io_cum);
	} else {
		lxpr_uiobuf_printf(uiobuf,
		    "page %lu %lu\n"
		    "swap %lu %lu\n"
		    "intr %lu\n"
		    "ctxt %lu\n"
		    "btime %lu\n"
		    "processes %lu\n",
		    pgpgin_cum, pgpgout_cum,
		    pgswapin_cum, pgswapout_cum,
		    intr_cum,
		    pswitch_cum,
		    boot_time,
		    forks_cum);
	}
}

/*
 * lxpr_read_swaps():
 *
 * We don't support swap files or partitions, so just provide a dummy file with
 * the necessary header.
 */
/* ARGSUSED */
static void
lxpr_read_swaps(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_uiobuf_printf(uiobuf,
	    "Filename                                "
	    "Type            Size    Used    Priority\n");
}

/*
 * inotify tunables exported via /proc.
 */
extern int inotify_maxevents;
extern int inotify_maxinstances;
extern int inotify_maxwatches;

static void
lxpr_read_sys_fs_inotify_max_queued_events(lxpr_node_t *lxpnp,
    lxpr_uiobuf_t *uiobuf)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_FS_INOTIFY_MAX_QUEUED_EVENTS);
	lxpr_uiobuf_printf(uiobuf, "%d\n", inotify_maxevents);
}

static void
lxpr_read_sys_fs_inotify_max_user_instances(lxpr_node_t *lxpnp,
    lxpr_uiobuf_t *uiobuf)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_FS_INOTIFY_MAX_USER_INSTANCES);
	lxpr_uiobuf_printf(uiobuf, "%d\n", inotify_maxinstances);
}

static void
lxpr_read_sys_fs_inotify_max_user_watches(lxpr_node_t *lxpnp,
    lxpr_uiobuf_t *uiobuf)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_FS_INOTIFY_MAX_USER_WATCHES);
	lxpr_uiobuf_printf(uiobuf, "%d\n", inotify_maxwatches);
}

static void
lxpr_read_sys_kernel_hostname(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_KERNEL_HOSTNAME);
	lxpr_uiobuf_printf(uiobuf, "%s\n", uts_nodename());
}

static void
lxpr_read_sys_kernel_msgmni(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	rctl_qty_t val;

	ASSERT(lxpnp->lxpr_type == LXPR_SYS_KERNEL_MSGMNI);

	mutex_enter(&curproc->p_lock);
	val = rctl_enforced_value(rc_zone_msgmni,
	    curproc->p_zone->zone_rctls, curproc);
	mutex_exit(&curproc->p_lock);

	lxpr_uiobuf_printf(uiobuf, "%u\n", (uint_t)val);
}

static void
lxpr_read_sys_kernel_ngroups_max(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_KERNEL_NGROUPS_MAX);
	lxpr_uiobuf_printf(uiobuf, "%d\n", ngroups_max);
}

static void
lxpr_read_sys_kernel_pid_max(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_KERNEL_PID_MAX);
	lxpr_uiobuf_printf(uiobuf, "%d\n", maxpid);
}

static void
lxpr_read_sys_kernel_shmmax(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	rctl_qty_t val;

	ASSERT(lxpnp->lxpr_type == LXPR_SYS_KERNEL_SHMMAX);

	mutex_enter(&curproc->p_lock);
	val = rctl_enforced_value(rc_zone_shmmax,
	    curproc->p_zone->zone_rctls, curproc);
	mutex_exit(&curproc->p_lock);

	if (val > FOURGB)
		val = FOURGB;

	lxpr_uiobuf_printf(uiobuf, "%u\n", (uint_t)val);
}

static void
lxpr_read_sys_kernel_threads_max(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_KERNEL_THREADS_MAX);
	lxpr_uiobuf_printf(uiobuf, "%d\n", curproc->p_zone->zone_nlwps_ctl);
}

/*
 * lxpr_read_uptime(): read the contents of the "uptime" file.
 *
 * format is: "%.2lf, %.2lf",uptime_secs, idle_secs
 * Use fixed point arithmetic to get 2 decimal places
 */
/* ARGSUSED */
static void
lxpr_read_uptime(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	cpu_t *cp, *cpstart;
	int pools_enabled;
	ulong_t idle_cum = 0;
	ulong_t cpu_count = 0;
	ulong_t idle_s;
	ulong_t idle_cs;
	ulong_t up_s;
	ulong_t up_cs;
	hrtime_t birthtime;
	hrtime_t centi_sec = 10000000;  /* 10^7 */

	ASSERT(lxpnp->lxpr_type == LXPR_UPTIME);

	/* Calculate cumulative stats */
	mutex_enter(&cpu_lock);
	pools_enabled = pool_pset_enabled();

	cp = cpstart = CPU;
	do {
		/*
		 * Don't count CPUs that aren't even in the system
		 * or aren't up yet.
		 */
		if ((cp->cpu_flags & CPU_EXISTS) == 0) {
			continue;
		}

		idle_cum += CPU_STATS(cp, sys.cpu_ticks_idle);
		idle_cum += CPU_STATS(cp, sys.cpu_ticks_wait);
		cpu_count += 1;

		if (pools_enabled)
			cp = cp->cpu_next_part;
		else
			cp = cp->cpu_next;
	} while (cp != cpstart);
	mutex_exit(&cpu_lock);

	/* Getting the Zone zsched process startup time */
	birthtime = LXPTOZ(lxpnp)->zone_zsched->p_mstart;
	up_cs = (gethrtime() - birthtime) / centi_sec;
	up_s = up_cs / 100;
	up_cs %= 100;

	ASSERT(cpu_count > 0);
	idle_cum /= cpu_count;
	idle_s = idle_cum / hz;
	idle_cs = idle_cum % hz;
	idle_cs *= 100;
	idle_cs /= hz;

	lxpr_uiobuf_printf(uiobuf,
	    "%ld.%02d %ld.%02d\n", up_s, up_cs, idle_s, idle_cs);
}

static const char *amd_x_edx[] = {
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	"syscall",
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	"mp",
	"nx",	NULL,	"mmxext", NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	"lm",	"3dnowext", "3dnow"
};

static const char *amd_x_ecx[] = {
	"lahf_lm", NULL, "svm", NULL,
	"altmovcr8"
};

static const char *tm_x_edx[] = {
	"recovery", "longrun", NULL, "lrti"
};

/*
 * Intel calls no-execute "xd" in its docs, but Linux still reports it as "nx."
 */
static const char *intc_x_edx[] = {
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	"syscall",
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	"nx",	NULL,	NULL,   NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	"lm",   NULL,   NULL
};

static const char *intc_edx[] = {
	"fpu",	"vme",	"de",	"pse",
	"tsc",	"msr",	"pae",	"mce",
	"cx8",	"apic",	 NULL,	"sep",
	"mtrr",	"pge",	"mca",	"cmov",
	"pat",	"pse36", "pn",	"clflush",
	NULL,	"dts",	"acpi",	"mmx",
	"fxsr",	"sse",	"sse2",	"ss",
	"ht",	"tm",	"ia64",	"pbe"
};

/*
 * "sse3" on linux is called "pni" (Prescott New Instructions).
 */
static const char *intc_ecx[] = {
	"pni",	NULL,	NULL, "monitor",
	"ds_cpl", NULL,	NULL, "est",
	"tm2",	NULL,	"cid", NULL,
	NULL,	"cx16",	"xtpr"
};

static void
lxpr_read_cpuinfo(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	int i;
	uint32_t bits;
	cpu_t *cp, *cpstart;
	int pools_enabled;
	const char **fp;
	char brandstr[CPU_IDSTRLEN];
	struct cpuid_regs cpr;
	int maxeax;
	int std_ecx, std_edx, ext_ecx, ext_edx;

	ASSERT(lxpnp->lxpr_type == LXPR_CPUINFO);

	mutex_enter(&cpu_lock);
	pools_enabled = pool_pset_enabled();

	cp = cpstart = CPU;
	do {
		/*
		 * This returns the maximum eax value for standard cpuid
		 * functions in eax.
		 */
		cpr.cp_eax = 0;
		(void) cpuid_insn(cp, &cpr);
		maxeax = cpr.cp_eax;

		/*
		 * Get standard x86 feature flags.
		 */
		cpr.cp_eax = 1;
		(void) cpuid_insn(cp, &cpr);
		std_ecx = cpr.cp_ecx;
		std_edx = cpr.cp_edx;

		/*
		 * Now get extended feature flags.
		 */
		cpr.cp_eax = 0x80000001;
		(void) cpuid_insn(cp, &cpr);
		ext_ecx = cpr.cp_ecx;
		ext_edx = cpr.cp_edx;

		(void) cpuid_getbrandstr(cp, brandstr, CPU_IDSTRLEN);

		lxpr_uiobuf_printf(uiobuf,
		    "processor\t: %d\n"
		    "vendor_id\t: %s\n"
		    "cpu family\t: %d\n"
		    "model\t\t: %d\n"
		    "model name\t: %s\n"
		    "stepping\t: %d\n"
		    "cpu MHz\t\t: %u.%03u\n",
		    cp->cpu_id, cpuid_getvendorstr(cp), cpuid_getfamily(cp),
		    cpuid_getmodel(cp), brandstr, cpuid_getstep(cp),
		    (uint32_t)(cpu_freq_hz / 1000000),
		    ((uint32_t)(cpu_freq_hz / 1000)) % 1000);

		lxpr_uiobuf_printf(uiobuf, "cache size\t: %u KB\n",
		    getl2cacheinfo(cp, NULL, NULL, NULL) / 1024);

		if (is_x86_feature(x86_featureset, X86FSET_HTT)) {
			/*
			 * 'siblings' is used for HT-style threads
			 */
			lxpr_uiobuf_printf(uiobuf,
			    "physical id\t: %lu\n"
			    "siblings\t: %u\n",
			    pg_plat_hw_instance_id(cp, PGHW_CHIP),
			    cpuid_get_ncpu_per_chip(cp));
		}

		/*
		 * Since we're relatively picky about running on older hardware,
		 * we can be somewhat cavalier about the answers to these ones.
		 *
		 * In fact, given the hardware we support, we just say:
		 *
		 *	fdiv_bug	: no	(if we're on a 64-bit kernel)
		 *	hlt_bug		: no
		 *	f00f_bug	: no
		 *	coma_bug	: no
		 *	wp		: yes	(write protect in supervsr mode)
		 */
		lxpr_uiobuf_printf(uiobuf,
		    "fdiv_bug\t: %s\n"
		    "hlt_bug \t: no\n"
		    "f00f_bug\t: no\n"
		    "coma_bug\t: no\n"
		    "fpu\t\t: %s\n"
		    "fpu_exception\t: %s\n"
		    "cpuid level\t: %d\n"
		    "flags\t\t:",
#if defined(__i386)
		    fpu_pentium_fdivbug ? "yes" : "no",
#else
		    "no",
#endif /* __i386 */
		    fpu_exists ? "yes" : "no", fpu_exists ? "yes" : "no",
		    maxeax);

		for (bits = std_edx, fp = intc_edx, i = 0;
		    i < sizeof (intc_edx) / sizeof (intc_edx[0]); fp++, i++)
			if ((bits & (1 << i)) != 0 && *fp)
				lxpr_uiobuf_printf(uiobuf, " %s", *fp);

		/*
		 * name additional features where appropriate
		 */
		switch (x86_vendor) {
		case X86_VENDOR_Intel:
			for (bits = ext_edx, fp = intc_x_edx, i = 0;
			    i < sizeof (intc_x_edx) / sizeof (intc_x_edx[0]);
			    fp++, i++)
				if ((bits & (1 << i)) != 0 && *fp)
					lxpr_uiobuf_printf(uiobuf, " %s", *fp);
			break;

		case X86_VENDOR_AMD:
			for (bits = ext_edx, fp = amd_x_edx, i = 0;
			    i < sizeof (amd_x_edx) / sizeof (amd_x_edx[0]);
			    fp++, i++)
				if ((bits & (1 << i)) != 0 && *fp)
					lxpr_uiobuf_printf(uiobuf, " %s", *fp);

			for (bits = ext_ecx, fp = amd_x_ecx, i = 0;
			    i < sizeof (amd_x_ecx) / sizeof (amd_x_ecx[0]);
			    fp++, i++)
				if ((bits & (1 << i)) != 0 && *fp)
					lxpr_uiobuf_printf(uiobuf, " %s", *fp);
			break;

		case X86_VENDOR_TM:
			for (bits = ext_edx, fp = tm_x_edx, i = 0;
			    i < sizeof (tm_x_edx) / sizeof (tm_x_edx[0]);
			    fp++, i++)
				if ((bits & (1 << i)) != 0 && *fp)
					lxpr_uiobuf_printf(uiobuf, " %s", *fp);
			break;
		default:
			break;
		}

		for (bits = std_ecx, fp = intc_ecx, i = 0;
		    i < sizeof (intc_ecx) / sizeof (intc_ecx[0]); fp++, i++)
			if ((bits & (1 << i)) != 0 && *fp)
				lxpr_uiobuf_printf(uiobuf, " %s", *fp);

		lxpr_uiobuf_printf(uiobuf, "\n\n");

		if (pools_enabled)
			cp = cp->cpu_next_part;
		else
			cp = cp->cpu_next;
	} while (cp != cpstart);

	mutex_exit(&cpu_lock);
}

/* ARGSUSED */
static void
lxpr_read_fd(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	ASSERT(lxpnp->lxpr_type == LXPR_PID_FD_FD);
	lxpr_uiobuf_seterr(uiobuf, EFAULT);
}

/*
 * lxpr_getattr(): Vnode operation for VOP_GETATTR()
 */
static int
lxpr_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	register lxpr_node_t *lxpnp = VTOLXP(vp);
	lxpr_nodetype_t type = lxpnp->lxpr_type;
	extern uint_t nproc;
	int error;

	/*
	 * Return attributes of underlying vnode if ATTR_REAL
	 *
	 * but keep fd files with the symlink permissions
	 */
	if (lxpnp->lxpr_realvp != NULL && (flags & ATTR_REAL)) {
		vnode_t *rvp = lxpnp->lxpr_realvp;

		/*
		 * withold attribute information to owner or root
		 */
		if ((error = VOP_ACCESS(rvp, 0, 0, cr, ct)) != 0) {
			return (error);
		}

		/*
		 * now its attributes
		 */
		if ((error = VOP_GETATTR(rvp, vap, flags, cr, ct)) != 0) {
			return (error);
		}

		/*
		 * if it's a file in lx /proc/pid/fd/xx then set its
		 * mode and keep it looking like a symlink, fifo or socket
		 */
		if (type == LXPR_PID_FD_FD) {
			vap->va_mode = lxpnp->lxpr_mode;
			vap->va_type = lxpnp->lxpr_realvp->v_type;
			vap->va_size = 0;
			vap->va_nlink = 1;
		}
		return (0);
	}

	/* Default attributes, that may be overridden below */
	bzero(vap, sizeof (*vap));
	vap->va_atime = vap->va_mtime = vap->va_ctime = lxpnp->lxpr_time;
	vap->va_nlink = 1;
	vap->va_type = vp->v_type;
	vap->va_mode = lxpnp->lxpr_mode;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_blksize = DEV_BSIZE;
	vap->va_uid = lxpnp->lxpr_uid;
	vap->va_gid = lxpnp->lxpr_gid;
	vap->va_nodeid = lxpnp->lxpr_ino;

	switch (type) {
	case LXPR_PROCDIR:
		vap->va_nlink = nproc + 2 + PROCDIRFILES;
		vap->va_size = (nproc + 2 + PROCDIRFILES) * LXPR_SDSIZE;
		break;
	case LXPR_PIDDIR:
		vap->va_nlink = PIDDIRFILES;
		vap->va_size = PIDDIRFILES * LXPR_SDSIZE;
		break;
	case LXPR_SELF:
		vap->va_uid = crgetruid(curproc->p_cred);
		vap->va_gid = crgetrgid(curproc->p_cred);
		break;
	case LXPR_PID_FD_FD:
		/*
		 * Restore VLNK type for lstat-type activity.
		 * See lxpr_readlink for more details.
		 */
		if ((flags & FOLLOW) == 0)
			vap->va_type = VLNK;
	default:
		break;
	}

	vap->va_nblocks = (fsblkcnt64_t)btod(vap->va_size);
	return (0);
}

/*
 * lxpr_access(): Vnode operation for VOP_ACCESS()
 */
static int
lxpr_access(vnode_t *vp, int mode, int flags, cred_t *cr, caller_context_t *ct)
{
	lxpr_node_t *lxpnp = VTOLXP(vp);
	int shift = 0;
	proc_t *tp;

	/* lx /proc is a read only file system */
	if (mode & VWRITE)
		return (EROFS);

	/*
	 * If this is a restricted file, check access permissions.
	 */
	switch (lxpnp->lxpr_type) {
	case LXPR_PIDDIR:
		return (0);
	case LXPR_PID_CURDIR:
	case LXPR_PID_ENV:
	case LXPR_PID_EXE:
	case LXPR_PID_LIMITS:
	case LXPR_PID_MAPS:
	case LXPR_PID_MEM:
	case LXPR_PID_ROOTDIR:
	case LXPR_PID_FDDIR:
	case LXPR_PID_FD_FD:
		if ((tp = lxpr_lock(lxpnp->lxpr_pid)) == NULL)
			return (ENOENT);
		if (tp != curproc && secpolicy_proc_access(cr) != 0 &&
		    priv_proc_cred_perm(cr, tp, NULL, mode) != 0) {
			lxpr_unlock(tp);
			return (EACCES);
		}
		lxpr_unlock(tp);
	default:
		break;
	}

	if (lxpnp->lxpr_realvp != NULL) {
		/*
		 * For these we use the underlying vnode's accessibility.
		 */
		return (VOP_ACCESS(lxpnp->lxpr_realvp, mode, flags, cr, ct));
	}

	/* If user is root allow access regardless of permission bits */
	if (secpolicy_proc_access(cr) == 0)
		return (0);

	/*
	 * Access check is based on only one of owner, group, public.  If not
	 * owner, then check group.  If not a member of the group, then check
	 * public access.
	 */
	if (crgetuid(cr) != lxpnp->lxpr_uid) {
		shift += 3;
		if (!groupmember((uid_t)lxpnp->lxpr_gid, cr))
			shift += 3;
	}

	mode &= ~(lxpnp->lxpr_mode << shift);

	if (mode == 0)
		return (0);

	return (EACCES);
}

/* ARGSUSED */
static vnode_t *
lxpr_lookup_not_a_dir(vnode_t *dp, char *comp)
{
	return (NULL);
}

/*
 * lxpr_lookup(): Vnode operation for VOP_LOOKUP()
 */
/* ARGSUSED */
static int
lxpr_lookup(vnode_t *dp, char *comp, vnode_t **vpp, pathname_t *pathp,
	int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
	int *direntflags, pathname_t *realpnp)
{
	lxpr_node_t *lxpnp = VTOLXP(dp);
	lxpr_nodetype_t type = lxpnp->lxpr_type;
	int error;

	ASSERT(dp->v_type == VDIR);
	ASSERT(type < LXPR_NFILES);

	/*
	 * we should never get here because the lookup
	 * is done on the realvp for these nodes
	 */
	ASSERT(type != LXPR_PID_FD_FD &&
	    type != LXPR_PID_CURDIR &&
	    type != LXPR_PID_ROOTDIR);

	/*
	 * restrict lookup permission to owner or root
	 */
	if ((error = lxpr_access(dp, VEXEC, 0, cr, ct)) != 0) {
		return (error);
	}

	/*
	 * Just return the parent vnode if that's where we are trying to go.
	 */
	if (strcmp(comp, "..") == 0) {
		VN_HOLD(lxpnp->lxpr_parent);
		*vpp = lxpnp->lxpr_parent;
		return (0);
	}

	/*
	 * Special handling for directory searches.  Note: null component name
	 * denotes that the current directory is being searched.
	 */
	if ((dp->v_type == VDIR) && (*comp == '\0' || strcmp(comp, ".") == 0)) {
		VN_HOLD(dp);
		*vpp = dp;
		return (0);
	}

	*vpp = (lxpr_lookup_function[type](dp, comp));
	return ((*vpp == NULL) ? ENOENT : 0);
}

/*
 * Do a sequential search on the given directory table
 */
static vnode_t *
lxpr_lookup_common(vnode_t *dp, char *comp, proc_t *p,
    lxpr_dirent_t *dirtab, int dirtablen)
{
	lxpr_node_t *lxpnp;
	int count;

	for (count = 0; count < dirtablen; count++) {
		if (strcmp(dirtab[count].d_name, comp) == 0) {
			lxpnp = lxpr_getnode(dp, dirtab[count].d_type, p, 0);
			dp = LXPTOV(lxpnp);
			ASSERT(dp != NULL);
			return (dp);
		}
	}
	return (NULL);
}

static vnode_t *
lxpr_lookup_piddir(vnode_t *dp, char *comp)
{
	proc_t *p;

	ASSERT(VTOLXP(dp)->lxpr_type == LXPR_PIDDIR);

	p = lxpr_lock(VTOLXP(dp)->lxpr_pid);
	if (p == NULL)
		return (NULL);

	dp = lxpr_lookup_common(dp, comp, p, piddir, PIDDIRFILES);

	lxpr_unlock(p);

	return (dp);
}

/*
 * Lookup one of the process's open files.
 */
static vnode_t *
lxpr_lookup_fddir(vnode_t *dp, char *comp)
{
	lxpr_node_t *dlxpnp = VTOLXP(dp);
	lxpr_node_t *lxpnp;
	vnode_t *vp = NULL;
	proc_t *p;
	file_t *fp;
	uint_t fd;
	int c;
	uf_entry_t *ufp;
	uf_info_t *fip;

	ASSERT(dlxpnp->lxpr_type == LXPR_PID_FDDIR);

	/*
	 * convert the string rendition of the filename
	 * to a file descriptor
	 */
	fd = 0;
	while ((c = *comp++) != '\0') {
		int ofd;
		if (c < '0' || c > '9')
			return (NULL);

		ofd = fd;
		fd = 10*fd + c - '0';
		/* integer overflow */
		if (fd / 10 != ofd)
			return (NULL);
	}

	/*
	 * get the proc to work with and lock it
	 */
	p = lxpr_lock(dlxpnp->lxpr_pid);
	if ((p == NULL))
		return (NULL);

	/*
	 * If the process is a zombie or system process
	 * it can't have any open files.
	 */
	if ((p->p_stat == SZOMB) || (p->p_flag & SSYS) || (p->p_as == &kas)) {
		lxpr_unlock(p);
		return (NULL);
	}

	/*
	 * get us a fresh node/vnode
	 */
	lxpnp = lxpr_getnode(dp, LXPR_PID_FD_FD, p, fd);

	/*
	 * Drop p_lock, but keep the process P_PR_LOCK'd to prevent it from
	 * going away while we dereference into fi_list.
	 */
	mutex_exit(&p->p_lock);

	/*
	 * get open file info
	 */
	fip = (&(p)->p_user.u_finfo);
	mutex_enter(&fip->fi_lock);

	if (fd < fip->fi_nfiles) {
		UF_ENTER(ufp, fip, fd);
		/*
		 * ensure the fd is still kosher.
		 * it may have gone between the readdir and
		 * the lookup
		 */
		if (fip->fi_list[fd].uf_file == NULL) {
			mutex_exit(&fip->fi_lock);
			UF_EXIT(ufp);
			mutex_enter(&p->p_lock);
			lxpr_unlock(p);
			lxpr_freenode(lxpnp);
			return (NULL);
		}

		if ((fp = ufp->uf_file) != NULL)
			vp = fp->f_vnode;
		UF_EXIT(ufp);
	}
	mutex_exit(&fip->fi_lock);

	if (vp == NULL) {
		mutex_enter(&p->p_lock);
		lxpr_unlock(p);
		lxpr_freenode(lxpnp);
		return (NULL);
	} else {
		/*
		 * Fill in the lxpr_node so future references will be able to
		 * find the underlying vnode. The vnode is held on the realvp.
		 */
		lxpnp->lxpr_realvp = vp;
		VN_HOLD(lxpnp->lxpr_realvp);
		/*
		 * For certain entries (sockets, pipes, etc), Linux expects a
		 * bogus-named symlink.  If that's the case, report the type as
		 * VNON to bypass link-following elsewhere in the vfs system.
		 *
		 * See lxpr_readlink for more details.
		 */
		if (lxpr_readlink_pid_fd(lxpnp, NULL, 0) == 0)
			LXPTOV(lxpnp)->v_type = VNON;
	}

	mutex_enter(&p->p_lock);
	lxpr_unlock(p);
	dp = LXPTOV(lxpnp);
	ASSERT(dp != NULL);

	return (dp);
}

static vnode_t *
lxpr_lookup_netdir(vnode_t *dp, char *comp)
{
	ASSERT(VTOLXP(dp)->lxpr_type == LXPR_NETDIR);

	dp = lxpr_lookup_common(dp, comp, NULL, netdir, NETDIRFILES);

	return (dp);
}

static vnode_t *
lxpr_lookup_procdir(vnode_t *dp, char *comp)
{
	ASSERT(VTOLXP(dp)->lxpr_type == LXPR_PROCDIR);

	/*
	 * We know all the names of files & dirs in our file system structure
	 * except those that are pid names.  These change as pids are created/
	 * deleted etc., so we just look for a number as the first char to see
	 * if we are we doing pid lookups.
	 *
	 * Don't need to check for "self" as it is implemented as a symlink
	 */
	if (*comp >= '0' && *comp <= '9') {
		pid_t pid = 0;
		lxpr_node_t *lxpnp = NULL;
		proc_t *p;
		int c;

		while ((c = *comp++) != '\0')
			pid = 10 * pid + c - '0';

		/*
		 * Can't continue if the process is still loading or it doesn't
		 * really exist yet (or maybe it just died!)
		 */
		p = lxpr_lock(pid);
		if (p == NULL)
			return (NULL);

		if (secpolicy_basic_procinfo(CRED(), p, curproc) != 0) {
			lxpr_unlock(p);
			return (NULL);
		}

		/*
		 * allocate and fill in a new lx /proc node
		 */
		lxpnp = lxpr_getnode(dp, LXPR_PIDDIR, p, 0);

		lxpr_unlock(p);

		dp = LXPTOV(lxpnp);
		ASSERT(dp != NULL);

		return (dp);
	}

	/* Lookup fixed names */
	return (lxpr_lookup_common(dp, comp, NULL, lx_procdir, PROCDIRFILES));
}

static vnode_t *
lxpr_lookup_sysdir(vnode_t *dp, char *comp)
{
	ASSERT(VTOLXP(dp)->lxpr_type == LXPR_SYSDIR);
	return (lxpr_lookup_common(dp, comp, NULL, sysdir, SYSDIRFILES));
}

static vnode_t *
lxpr_lookup_sys_kerneldir(vnode_t *dp, char *comp)
{
	ASSERT(VTOLXP(dp)->lxpr_type == LXPR_SYS_KERNELDIR);
	return (lxpr_lookup_common(dp, comp, NULL, sys_kerneldir,
	    SYS_KERNELDIRFILES));
}

static vnode_t *
lxpr_lookup_sys_fsdir(vnode_t *dp, char *comp)
{
	ASSERT(VTOLXP(dp)->lxpr_type == LXPR_SYS_FSDIR);
	return (lxpr_lookup_common(dp, comp, NULL, sys_fsdir,
	    SYS_FSDIRFILES));
}

static vnode_t *
lxpr_lookup_sys_fs_inotifydir(vnode_t *dp, char *comp)
{
	ASSERT(VTOLXP(dp)->lxpr_type == LXPR_SYS_FS_INOTIFYDIR);
	return (lxpr_lookup_common(dp, comp, NULL, sys_fs_inotifydir,
	    SYS_FS_INOTIFYDIRFILES));
}

/*
 * lxpr_readdir(): Vnode operation for VOP_READDIR()
 */
/* ARGSUSED */
static int
lxpr_readdir(vnode_t *dp, uio_t *uiop, cred_t *cr, int *eofp,
	caller_context_t *ct, int flags)
{
	lxpr_node_t *lxpnp = VTOLXP(dp);
	lxpr_nodetype_t type = lxpnp->lxpr_type;
	ssize_t uresid;
	off_t uoffset;
	int error;

	ASSERT(dp->v_type == VDIR);
	ASSERT(type < LXPR_NFILES);

	/*
	 * we should never get here because the readdir
	 * is done on the realvp for these nodes
	 */
	ASSERT(type != LXPR_PID_FD_FD &&
	    type != LXPR_PID_CURDIR &&
	    type != LXPR_PID_ROOTDIR);

	/*
	 * restrict readdir permission to owner or root
	 */
	if ((error = lxpr_access(dp, VREAD, 0, cr, ct)) != 0)
		return (error);

	uoffset = uiop->uio_offset;
	uresid = uiop->uio_resid;

	/* can't do negative reads */
	if (uoffset < 0 || uresid <= 0)
		return (EINVAL);

	/* can't read directory entries that don't exist! */
	if (uoffset % LXPR_SDSIZE)
		return (ENOENT);

	return (lxpr_readdir_function[lxpnp->lxpr_type](lxpnp, uiop, eofp));
}

/* ARGSUSED */
static int
lxpr_readdir_not_a_dir(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp)
{
	return (ENOTDIR);
}

/*
 * This has the common logic for returning directory entries
 */
static int
lxpr_readdir_common(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp,
    lxpr_dirent_t *dirtab, int dirtablen)
{
	/* bp holds one dirent64 structure */
	longlong_t bp[DIRENT64_RECLEN(LXPNSIZ) / sizeof (longlong_t)];
	dirent64_t *dirent = (dirent64_t *)bp;
	ssize_t oresid;	/* save a copy for testing later */
	ssize_t uresid;

	oresid = uiop->uio_resid;

	/* clear out the dirent buffer */
	bzero(bp, sizeof (bp));

	/*
	 * Satisfy user request
	 */
	while ((uresid = uiop->uio_resid) > 0) {
		int dirindex;
		off_t uoffset;
		int reclen;
		int error;

		uoffset = uiop->uio_offset;
		dirindex  = (uoffset / LXPR_SDSIZE) - 2;

		if (uoffset == 0) {

			dirent->d_ino = lxpnp->lxpr_ino;
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '\0';
			reclen = DIRENT64_RECLEN(1);

		} else if (uoffset == LXPR_SDSIZE) {

			dirent->d_ino = lxpr_parentinode(lxpnp);
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '.';
			dirent->d_name[2] = '\0';
			reclen = DIRENT64_RECLEN(2);

		} else if (dirindex < dirtablen) {
			int slen = strlen(dirtab[dirindex].d_name);

			dirent->d_ino = lxpr_inode(dirtab[dirindex].d_type,
			    lxpnp->lxpr_pid, 0);

			ASSERT(slen < LXPNSIZ);
			(void) strcpy(dirent->d_name, dirtab[dirindex].d_name);
			reclen = DIRENT64_RECLEN(slen);

		} else {
			/* Run out of table entries */
			if (eofp) {
				*eofp = 1;
			}
			return (0);
		}

		dirent->d_off = (off64_t)(uoffset + LXPR_SDSIZE);
		dirent->d_reclen = (ushort_t)reclen;

		/*
		 * if the size of the data to transfer is greater
		 * that that requested then we can't do it this transfer.
		 */
		if (reclen > uresid) {
			/*
			 * Error if no entries have been returned yet.
			 */
			if (uresid == oresid) {
				return (EINVAL);
			}
			break;
		}

		/*
		 * uiomove() updates both uiop->uio_resid and uiop->uio_offset
		 * by the same amount.  But we want uiop->uio_offset to change
		 * in increments of LXPR_SDSIZE, which is different from the
		 * number of bytes being returned to the user.  So we set
		 * uiop->uio_offset separately, ignoring what uiomove() does.
		 */
		if ((error = uiomove((caddr_t)dirent, reclen, UIO_READ,
		    uiop)) != 0)
			return (error);

		uiop->uio_offset = uoffset + LXPR_SDSIZE;
	}

	/* Have run out of space, but could have just done last table entry */
	if (eofp) {
		*eofp =
		    (uiop->uio_offset >= ((dirtablen+2) * LXPR_SDSIZE)) ? 1 : 0;
	}
	return (0);
}


static int
lxpr_readdir_procdir(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp)
{
	/* bp holds one dirent64 structure */
	longlong_t bp[DIRENT64_RECLEN(LXPNSIZ) / sizeof (longlong_t)];
	dirent64_t *dirent = (dirent64_t *)bp;
	ssize_t oresid;	/* save a copy for testing later */
	ssize_t uresid;
	off_t uoffset;
	zoneid_t zoneid;
	pid_t pid;
	int error;
	int ceof;

	ASSERT(lxpnp->lxpr_type == LXPR_PROCDIR);

	oresid = uiop->uio_resid;
	zoneid = LXPTOZ(lxpnp)->zone_id;

	/*
	 * We return directory entries in the order: "." and ".." then the
	 * unique lxproc files, then the directories corresponding to the
	 * running processes.  We have defined this as the ordering because
	 * it allows us to more easily keep track of where we are betwen calls
	 * to getdents().  If the number of processes changes between calls
	 * then we can't lose track of where we are in the lxproc files.
	 */

	/* Do the fixed entries */
	error = lxpr_readdir_common(lxpnp, uiop, &ceof, lx_procdir,
	    PROCDIRFILES);

	/* Finished if we got an error or if we couldn't do all the table */
	if (error != 0 || ceof == 0)
		return (error);

	/* clear out the dirent buffer */
	bzero(bp, sizeof (bp));

	/* Do the process entries */
	while ((uresid = uiop->uio_resid) > 0) {
		proc_t *p;
		int len;
		int reclen;
		int i;

		uoffset = uiop->uio_offset;

		/*
		 * Stop when entire proc table has been examined.
		 */
		i = (uoffset / LXPR_SDSIZE) - 2 - PROCDIRFILES;
		if (i >= v.v_proc) {
			/* Run out of table entries */
			if (eofp) {
				*eofp = 1;
			}
			return (0);
		}
		mutex_enter(&pidlock);

		/*
		 * Skip indices for which there is no pid_entry, PIDs for
		 * which there is no corresponding process, a PID of 0,
		 * and anything the security policy doesn't allow
		 * us to look at.
		 */
		if ((p = pid_entry(i)) == NULL || p->p_stat == SIDL ||
		    p->p_pid == 0 ||
		    secpolicy_basic_procinfo(CRED(), p, curproc) != 0) {
			mutex_exit(&pidlock);
			goto next;
		}
		mutex_exit(&pidlock);

		/*
		 * Convert pid to the Linux default of 1 if we're the zone's
		 * init process, or 0 if zsched, otherwise use the value from
		 * the proc structure
		 */
		if (p->p_pid == curproc->p_zone->zone_proc_initpid) {
			pid = 1;
		} else if (p->p_pid == curproc->p_zone->zone_zsched->p_pid) {
			pid = 0;
		} else {
			pid = p->p_pid;
		}

		/*
		 * If this /proc was mounted in the global zone, view
		 * all procs; otherwise, only view zone member procs.
		 */
		if (zoneid != GLOBAL_ZONEID && p->p_zone->zone_id != zoneid) {
			goto next;
		}

		ASSERT(p->p_stat != 0);

		dirent->d_ino = lxpr_inode(LXPR_PIDDIR, pid, 0);
		len = snprintf(dirent->d_name, LXPNSIZ, "%d", pid);
		ASSERT(len < LXPNSIZ);
		reclen = DIRENT64_RECLEN(len);

		dirent->d_off = (off64_t)(uoffset + LXPR_SDSIZE);
		dirent->d_reclen = (ushort_t)reclen;

		/*
		 * if the size of the data to transfer is greater
		 * that that requested then we can't do it this transfer.
		 */
		if (reclen > uresid) {
			/*
			 * Error if no entries have been returned yet.
			 */
			if (uresid == oresid)
				return (EINVAL);
			break;
		}

		/*
		 * uiomove() updates both uiop->uio_resid and uiop->uio_offset
		 * by the same amount.  But we want uiop->uio_offset to change
		 * in increments of LXPR_SDSIZE, which is different from the
		 * number of bytes being returned to the user.  So we set
		 * uiop->uio_offset separately, in the increment of this for
		 * the loop, ignoring what uiomove() does.
		 */
		if ((error = uiomove((caddr_t)dirent, reclen, UIO_READ,
		    uiop)) != 0)
			return (error);
next:
		uiop->uio_offset = uoffset + LXPR_SDSIZE;
	}

	if (eofp != NULL) {
		*eofp = (uiop->uio_offset >=
		    ((v.v_proc + PROCDIRFILES + 2) * LXPR_SDSIZE)) ? 1 : 0;
	}

	return (0);
}

static int
lxpr_readdir_piddir(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp)
{
	proc_t *p;
	pid_t find_pid;

	ASSERT(lxpnp->lxpr_type == LXPR_PIDDIR);

	/* can't read its contents if it died */
	mutex_enter(&pidlock);

	if (lxpnp->lxpr_pid == 1) {
		find_pid = curproc->p_zone->zone_proc_initpid;
	} else if (lxpnp->lxpr_pid == 0) {
		find_pid = curproc->p_zone->zone_zsched->p_pid;
	} else {
		find_pid = lxpnp->lxpr_pid;
	}
	p = prfind(find_pid);

	if (p == NULL || p->p_stat == SIDL) {
		mutex_exit(&pidlock);
		return (ENOENT);
	}
	mutex_exit(&pidlock);

	return (lxpr_readdir_common(lxpnp, uiop, eofp, piddir, PIDDIRFILES));
}

static int
lxpr_readdir_netdir(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp)
{
	ASSERT(lxpnp->lxpr_type == LXPR_NETDIR);
	return (lxpr_readdir_common(lxpnp, uiop, eofp, netdir, NETDIRFILES));
}

static int
lxpr_readdir_fddir(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp)
{
	/* bp holds one dirent64 structure */
	longlong_t bp[DIRENT64_RECLEN(LXPNSIZ) / sizeof (longlong_t)];
	dirent64_t *dirent = (dirent64_t *)bp;
	ssize_t oresid;	/* save a copy for testing later */
	ssize_t uresid;
	off_t uoffset;
	int error;
	int ceof;
	proc_t *p;
	int fddirsize = -1;
	uf_info_t *fip;

	ASSERT(lxpnp->lxpr_type == LXPR_PID_FDDIR);

	oresid = uiop->uio_resid;

	/* can't read its contents if it died */
	p = lxpr_lock(lxpnp->lxpr_pid);
	if (p == NULL)
		return (ENOENT);

	if ((p->p_stat == SZOMB) || (p->p_flag & SSYS) || (p->p_as == &kas))
		fddirsize = 0;

	/*
	 * Drop p_lock, but keep the process P_PR_LOCK'd to prevent it from
	 * going away while we iterate over its fi_list.
	 */
	mutex_exit(&p->p_lock);

	/* Get open file info */
	fip = (&(p)->p_user.u_finfo);
	mutex_enter(&fip->fi_lock);

	if (fddirsize == -1)
		fddirsize = fip->fi_nfiles;

	/* Do the fixed entries (in this case just "." & "..") */
	error = lxpr_readdir_common(lxpnp, uiop, &ceof, 0, 0);

	/* Finished if we got an error or if we couldn't do all the table */
	if (error != 0 || ceof == 0)
		goto out;

	/* clear out the dirent buffer */
	bzero(bp, sizeof (bp));

	/*
	 * Loop until user's request is satisfied or until
	 * all file descriptors have been examined.
	 */
	for (; (uresid = uiop->uio_resid) > 0;
	    uiop->uio_offset = uoffset + LXPR_SDSIZE) {
		int reclen;
		int fd;
		int len;

		uoffset = uiop->uio_offset;

		/*
		 * Stop at the end of the fd list
		 */
		fd = (uoffset / LXPR_SDSIZE) - 2;
		if (fd >= fddirsize) {
			if (eofp) {
				*eofp = 1;
			}
			goto out;
		}

		if (fip->fi_list[fd].uf_file == NULL)
			continue;

		dirent->d_ino = lxpr_inode(LXPR_PID_FD_FD, lxpnp->lxpr_pid, fd);
		len = snprintf(dirent->d_name, LXPNSIZ, "%d", fd);
		ASSERT(len < LXPNSIZ);
		reclen = DIRENT64_RECLEN(len);

		dirent->d_off = (off64_t)(uoffset + LXPR_SDSIZE);
		dirent->d_reclen = (ushort_t)reclen;

		if (reclen > uresid) {
			/*
			 * Error if no entries have been returned yet.
			 */
			if (uresid == oresid)
				error = EINVAL;
			goto out;
		}

		if ((error = uiomove((caddr_t)dirent, reclen, UIO_READ,
		    uiop)) != 0)
			goto out;
	}

	if (eofp != NULL) {
		*eofp =
		    (uiop->uio_offset >= ((fddirsize+2) * LXPR_SDSIZE)) ? 1 : 0;
	}

out:
	mutex_exit(&fip->fi_lock);
	mutex_enter(&p->p_lock);
	lxpr_unlock(p);
	return (error);
}

static int
lxpr_readdir_sysdir(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYSDIR);
	return (lxpr_readdir_common(lxpnp, uiop, eofp, sysdir, SYSDIRFILES));
}

static int
lxpr_readdir_sys_fsdir(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_FSDIR);
	return (lxpr_readdir_common(lxpnp, uiop, eofp, sys_fsdir,
	    SYS_FSDIRFILES));
}

static int
lxpr_readdir_sys_fs_inotifydir(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_FS_INOTIFYDIR);
	return (lxpr_readdir_common(lxpnp, uiop, eofp, sys_fs_inotifydir,
	    SYS_FS_INOTIFYDIRFILES));
}

static int
lxpr_readdir_sys_kerneldir(lxpr_node_t *lxpnp, uio_t *uiop, int *eofp)
{
	ASSERT(lxpnp->lxpr_type == LXPR_SYS_KERNELDIR);
	return (lxpr_readdir_common(lxpnp, uiop, eofp, sys_kerneldir,
	    SYS_KERNELDIRFILES));
}

/*
 * lxpr_readlink(): Vnode operation for VOP_READLINK()
 */
/* ARGSUSED */
static int
lxpr_readlink(vnode_t *vp, uio_t *uiop, cred_t *cr, caller_context_t *ct)
{
	char bp[MAXPATHLEN + 1];
	size_t buflen = sizeof (bp);
	lxpr_node_t *lxpnp = VTOLXP(vp);
	vnode_t *rvp = lxpnp->lxpr_realvp;
	pid_t pid;
	int error = 0;

	/*
	 * Linux does something very "clever" for /proc/<pid>/fd/<num> entries.
	 * Open FDs are represented as symlinks, the link contents
	 * corresponding to the open resource.  For plain files or devices,
	 * this isn't absurd since one can dereference the symlink to query
	 * the underlying resource.  For sockets or pipes, it becomes ugly in a
	 * hurry.  To maintain this human-readable output, those FD symlinks
	 * point to bogus targets such as "socket:[<inodenum>]".  This requires
	 * circumventing vfs since the stat/lstat behavior on those FD entries
	 * will be unusual. (A stat must retrieve information about the open
	 * socket or pipe.  It cannot fail because the link contents point to
	 * an absent file.)
	 *
	 * To accomplish this, lxpr_getnode returns an vnode typed VNON for FD
	 * entries.  This bypasses code paths which would normally
	 * short-circuit on symlinks and allows us to emulate the vfs behavior
	 * expected by /proc consumers.
	 */
	if (vp->v_type != VLNK && lxpnp->lxpr_type != LXPR_PID_FD_FD)
		return (EINVAL);

	/* Try to produce a symlink name for anything that has a realvp */
	if (rvp != NULL) {
		if ((error = lxpr_access(vp, VREAD, 0, CRED(), ct)) != 0)
			return (error);
		if ((error = vnodetopath(NULL, rvp, bp, buflen, CRED())) != 0) {
			/*
			 * Special handling possible for /proc/<pid>/fd/<num>
			 * Generate <type>:[<inode>] links, if allowed.
			 */
			if (lxpnp->lxpr_type != LXPR_PID_FD_FD ||
			    lxpr_readlink_pid_fd(lxpnp, bp, buflen) != 0) {
				return (error);
			}
		}
	} else {
		switch (lxpnp->lxpr_type) {
		case LXPR_SELF:
			/*
			 * Convert pid to the Linux default of 1 if we're the
			 * zone's init process or 0 if zsched.
			 */
			if (curproc->p_pid ==
			    curproc->p_zone->zone_proc_initpid) {
				pid = 1;
			} else if (curproc->p_pid ==
			    curproc->p_zone->zone_zsched->p_pid) {
				pid = 0;
			} else {
				pid = curproc->p_pid;
			}

			/*
			 * Don't need to check result as every possible int
			 * will fit within MAXPATHLEN bytes.
			 */
			(void) snprintf(bp, buflen, "%d", pid);
			break;
		case LXPR_PID_CURDIR:
		case LXPR_PID_ROOTDIR:
		case LXPR_PID_EXE:
			return (EACCES);
		default:
			/*
			 * Need to return error so that nothing thinks
			 * that the symlink is empty and hence "."
			 */
			return (EINVAL);
		}
	}

	/* copy the link data to user space */
	return (uiomove(bp, strlen(bp), UIO_READ, uiop));
}

/*
 * Attempt to create Linux-proc-style fake symlinks contents for supported
 * /proc/<pid>/fd/<#> entries.
 */
static int
lxpr_readlink_pid_fd(lxpr_node_t *lxpnp, char *bp, size_t len)
{
	const char *format;
	vnode_t *rvp = lxpnp->lxpr_realvp;
	vattr_t attr;

	switch (rvp->v_type) {
	case VSOCK:
		format = "socket:[%lu]";
		break;
	case VFIFO:
		format = "pipe:[%lu]";
		break;
	default:
		return (-1);
	}

	/* Fetch the inode of the underlying vnode */
	if (VOP_GETATTR(rvp, &attr, 0, CRED(), NULL) != 0)
		return (-1);

	if (bp != NULL)
		(void) snprintf(bp, len, format, (ino_t)attr.va_nodeid);
	return (0);
}

/*
 * lxpr_inactive(): Vnode operation for VOP_INACTIVE()
 * Vnode is no longer referenced, deallocate the file
 * and all its resources.
 */
/* ARGSUSED */
static void
lxpr_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	lxpr_freenode(VTOLXP(vp));
}

/*
 * lxpr_sync(): Vnode operation for VOP_SYNC()
 */
static int
lxpr_sync()
{
	/*
	 * Nothing to sync but this function must never fail
	 */
	return (0);
}

/*
 * lxpr_cmp(): Vnode operation for VOP_CMP()
 */
static int
lxpr_cmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{
	vnode_t *rvp;

	while (vn_matchops(vp1, lxpr_vnodeops) &&
	    (rvp = VTOLXP(vp1)->lxpr_realvp) != NULL) {
		vp1 = rvp;
	}

	while (vn_matchops(vp2, lxpr_vnodeops) &&
	    (rvp = VTOLXP(vp2)->lxpr_realvp) != NULL) {
		vp2 = rvp;
	}

	if (vn_matchops(vp1, lxpr_vnodeops) || vn_matchops(vp2, lxpr_vnodeops))
		return (vp1 == vp2);
	return (VOP_CMP(vp1, vp2, ct));
}

/*
 * lxpr_realvp(): Vnode operation for VOP_REALVP()
 */
static int
lxpr_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	vnode_t *rvp;

	if ((rvp = VTOLXP(vp)->lxpr_realvp) != NULL) {
		vp = rvp;
		if (VOP_REALVP(vp, &rvp, ct) == 0)
			vp = rvp;
	}

	*vpp = vp;
	return (0);
}
