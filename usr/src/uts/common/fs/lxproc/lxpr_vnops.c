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
 */

/*
 * Copyright 2014 Joyent, Inc. All rights reserved.
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
#include <sys/strlog.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/x86_archext.h>
#include <sys/archsystm.h>
#include <sys/fp.h>
#include <sys/pool_pset.h>
#include <sys/pset.h>
#include <sys/zone.h>
#include <sys/pghw.h>
#include <sys/vfs_opreg.h>

/* Dependent on procfs */
extern kthread_t *prchoose(proc_t *);

#include "lxproc.h"

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
static int lxpr_cmp(vnode_t *, vnode_t *, caller_context_t *);
static int lxpr_realvp(vnode_t *, vnode_t **, caller_context_t *);
static int lxpr_sync(void);
static void lxpr_inactive(vnode_t *, cred_t *, caller_context_t *);

static vnode_t *lxpr_lookup_procdir(vnode_t *, char *);
static vnode_t *lxpr_lookup_piddir(vnode_t *, char *);
static vnode_t *lxpr_lookup_not_a_dir(vnode_t *, char *);
static vnode_t *lxpr_lookup_fddir(vnode_t *, char *);
static vnode_t *lxpr_lookup_netdir(vnode_t *, char *);

static int lxpr_readdir_procdir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_piddir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_not_a_dir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_fddir(lxpr_node_t *, uio_t *, int *);
static int lxpr_readdir_netdir(lxpr_node_t *, uio_t *, int *);

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
static void lxpr_read_uptime(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_version(lxpr_node_t *, lxpr_uiobuf_t *);

static void lxpr_read_pid_cmdline(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_maps(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_stat(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_statm(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_pid_status(lxpr_node_t *, lxpr_uiobuf_t *);

static void lxpr_read_net_arp(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_dev(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_dev_mcast(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_igmp(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_ip_mr_cache(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_ip_mr_vif(lxpr_node_t *, lxpr_uiobuf_t *);
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
static void lxpr_read_net_udp(lxpr_node_t *, lxpr_uiobuf_t *);
static void lxpr_read_net_unix(lxpr_node_t *, lxpr_uiobuf_t *);

/*
 * Simple conversion
 */
#define	btok(x)	((x) >> 10)			/* bytes to kbytes */
#define	ptok(x)	((x) << (PAGESHIFT - 10))	/* pages to kbytes */

/*
 * The lxproc vnode operations vector
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
 * file contents of an lxproc directory.
 */
static lxpr_dirent_t lxpr_dir[] = {
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
	{ LXPR_MOUNTS,		"mounts" },
	{ LXPR_NETDIR,		"net" },
	{ LXPR_PARTITIONS,	"partitions" },
	{ LXPR_SELF,		"self" },
	{ LXPR_STAT,		"stat" },
	{ LXPR_UPTIME,		"uptime" },
	{ LXPR_VERSION,		"version" }
};

#define	PROCDIRFILES	(sizeof (lxpr_dir) / sizeof (lxpr_dir[0]))

/*
 * Contents of an /lxproc/<pid> directory.
 */
static lxpr_dirent_t piddir[] = {
	{ LXPR_PID_CMDLINE,	"cmdline" },
	{ LXPR_PID_CPU,		"cpu" },
	{ LXPR_PID_CURDIR,	"cwd" },
	{ LXPR_PID_ENV,		"environ" },
	{ LXPR_PID_EXE,		"exe" },
	{ LXPR_PID_MAPS,	"maps" },
	{ LXPR_PID_MEM,		"mem" },
	{ LXPR_PID_ROOTDIR,	"root" },
	{ LXPR_PID_STAT,	"stat" },
	{ LXPR_PID_STATM,	"statm" },
	{ LXPR_PID_STATUS,	"status" },
	{ LXPR_PID_FDDIR,	"fd" }
};

#define	PIDDIRFILES	(sizeof (piddir) / sizeof (piddir[0]))

/*
 * contents of /lxproc/net directory
 */
static lxpr_dirent_t netdir[] = {
	{ LXPR_NET_ARP,		"arp" },
	{ LXPR_NET_DEV,		"dev" },
	{ LXPR_NET_DEV_MCAST,	"dev_mcast" },
	{ LXPR_NET_IGMP,	"igmp" },
	{ LXPR_NET_IP_MR_CACHE,	"ip_mr_cache" },
	{ LXPR_NET_IP_MR_VIF,	"ip_mr_vif" },
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
	{ LXPR_NET_UDP,		"udp" },
	{ LXPR_NET_UNIX,	"unix" }
};

#define	NETDIRFILES	(sizeof (netdir) / sizeof (netdir[0]))

/*
 * These are the major signal number differences between Linux and native:
 *
 * 	====================================
 * 	| Number | Linux      | Native     |
 * 	| ====== | =========  | ========== |
 *	|    7   | SIGBUS     | SIGEMT     |
 *	|   10   | SIGUSR1    | SIGBUS     |
 *	|   12   | SIGUSR2    | SIGSYS     |
 *	|   16   | SIGSTKFLT  | SIGUSR1    |
 *	|   17   | SIGCHLD    | SIGUSR2    |
 * 	|   18   | SIGCONT    | SIGCHLD    |
 *	|   19   | SIGSTOP    | SIGPWR     |
 * 	|   20   | SIGTSTP    | SIGWINCH   |
 * 	|   21   | SIGTTIN    | SIGURG     |
 * 	|   22   | SIGTTOU    | SIGPOLL    |
 *	|   23   | SIGURG     | SIGSTOP    |
 * 	|   24   | SIGXCPU    | SIGTSTP    |
 *	|   25   | SIGXFSZ    | SIGCONT    |
 *	|   26   | SIGVTALARM | SIGTTIN    |
 *	|   27   | SIGPROF    | SIGTTOU    |
 *	|   28   | SIGWINCH   | SIGVTALARM |
 *	|   29   | SIGPOLL    | SIGPROF    |
 *	|   30   | SIGPWR     | SIGXCPU    |
 *	|   31   | SIGSYS     | SIGXFSZ    |
 * 	====================================
 *
 * Not every Linux signal maps to a native signal, nor does every native
 * signal map to a Linux counterpart. However, when signals do map, the
 * mapping is unique.
 */
static int
lxpr_sigmap[NSIG] = {
	0,
	LX_SIGHUP,
	LX_SIGINT,
	LX_SIGQUIT,
	LX_SIGILL,
	LX_SIGTRAP,
	LX_SIGABRT,
	LX_SIGSTKFLT,
	LX_SIGFPE,
	LX_SIGKILL,
	LX_SIGBUS,
	LX_SIGSEGV,
	LX_SIGSYS,
	LX_SIGPIPE,
	LX_SIGALRM,
	LX_SIGTERM,
	LX_SIGUSR1,
	LX_SIGUSR2,
	LX_SIGCHLD,
	LX_SIGPWR,
	LX_SIGWINCH,
	LX_SIGURG,
	LX_SIGPOLL,
	LX_SIGSTOP,
	LX_SIGTSTP,
	LX_SIGCONT,
	LX_SIGTTIN,
	LX_SIGTTOU,
	LX_SIGVTALRM,
	LX_SIGPROF,
	LX_SIGXCPU,
	LX_SIGXFSZ,
	-1,			/* 32:  illumos SIGWAITING */
	-1,			/* 33:  illumos SIGLWP */
	-1,			/* 34:  illumos SIGFREEZE */
	-1,			/* 35:  illumos SIGTHAW */
	-1,			/* 36:  illumos SIGCANCEL */
	-1,			/* 37:  illumos SIGLOST */
	-1,			/* 38:  illumos SIGXRES */
	-1,			/* 39:  illumos SIGJVM1 */
	-1,			/* 40:  illumos SIGJVM2 */
	-1,			/* 41:  illumos SIGINFO */
	LX_SIGRTMIN,		/* 42:  illumos _SIGRTMIN */
	LX_SIGRTMIN + 1,
	LX_SIGRTMIN + 2,
	LX_SIGRTMIN + 3,
	LX_SIGRTMIN + 4,
	LX_SIGRTMIN + 5,
	LX_SIGRTMIN + 6,
	LX_SIGRTMIN + 7,
	LX_SIGRTMIN + 8,
	LX_SIGRTMIN + 9,
	LX_SIGRTMIN + 10,
	LX_SIGRTMIN + 11,
	LX_SIGRTMIN + 12,
	LX_SIGRTMIN + 13,
	LX_SIGRTMIN + 14,
	LX_SIGRTMIN + 15,
	LX_SIGRTMIN + 16,
	LX_SIGRTMIN + 17,
	LX_SIGRTMIN + 18,
	LX_SIGRTMIN + 19,
	LX_SIGRTMIN + 20,
	LX_SIGRTMIN + 21,
	LX_SIGRTMIN + 22,
	LX_SIGRTMIN + 23,
	LX_SIGRTMIN + 24,
	LX_SIGRTMIN + 25,
	LX_SIGRTMIN + 26,
	LX_SIGRTMIN + 27,
	LX_SIGRTMIN + 28,
	LX_SIGRTMIN + 29,
	LX_SIGRTMIN + 30,
	LX_SIGRTMAX
};

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
	 * If we are opening an underlying file only allow regular files
	 * reject the open for anything but a regular file.
	 * Just do it if we are opening the current or root directory.
	 */
	if (lxpnp->lxpr_realvp != NULL) {
		rvp = lxpnp->lxpr_realvp;

		if (type == LXPR_PID_FD_FD && rvp->v_type != VREG)
			error = EACCES;
		else {
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
	lxpr_read_pid_maps,		/* /proc/<pid>/maps	*/
	lxpr_read_empty,		/* /proc/<pid>/mem	*/
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
	lxpr_read_mounts,		/* /proc/mounts		*/
	lxpr_read_isdir,		/* /proc/net		*/
	lxpr_read_net_arp,		/* /proc/net/arp	*/
	lxpr_read_net_dev,		/* /proc/net/dev	*/
	lxpr_read_net_dev_mcast,	/* /proc/net/dev_mcast	*/
	lxpr_read_net_igmp,		/* /proc/net/igmp	*/
	lxpr_read_net_ip_mr_cache,	/* /proc/net/ip_mr_cache */
	lxpr_read_net_ip_mr_vif,	/* /proc/net/ip_mr_vif	*/
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
	lxpr_read_net_udp,		/* /proc/net/udp	*/
	lxpr_read_net_unix,		/* /proc/net/unix	*/
	lxpr_read_partitions,		/* /proc/partitions	*/
	lxpr_read_invalid,		/* /proc/self		*/
	lxpr_read_stat,			/* /proc/stat		*/
	lxpr_read_uptime,		/* /proc/uptime		*/
	lxpr_read_version,		/* /proc/version	*/
};

/*
 * Array of lookup functions, indexed by /lxproc file type.
 */
static vnode_t *(*lxpr_lookup_function[LXPR_NFILES])() = {
	lxpr_lookup_procdir,		/* /proc		*/
	lxpr_lookup_piddir,		/* /proc/<pid>		*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/cmdline	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/cpu	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/cwd	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/environ	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/exe	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/maps	*/
	lxpr_lookup_not_a_dir,		/* /proc/<pid>/mem	*/
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
	lxpr_lookup_not_a_dir,		/* /proc/mounts		*/
	lxpr_lookup_netdir,		/* /proc/net		*/
	lxpr_lookup_not_a_dir,		/* /proc/net/arp	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/dev	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/dev_mcast	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/igmp	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/ip_mr_cache */
	lxpr_lookup_not_a_dir,		/* /proc/net/ip_mr_vif	*/
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
	lxpr_lookup_not_a_dir,		/* /proc/net/udp	*/
	lxpr_lookup_not_a_dir,		/* /proc/net/unix	*/
	lxpr_lookup_not_a_dir,		/* /proc/partitions	*/
	lxpr_lookup_not_a_dir,		/* /proc/self		*/
	lxpr_lookup_not_a_dir,		/* /proc/stat		*/
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
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/maps	*/
	lxpr_readdir_not_a_dir,		/* /proc/<pid>/mem	*/
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
	lxpr_readdir_not_a_dir,		/* /proc/mounts		*/
	lxpr_readdir_netdir,		/* /proc/net		*/
	lxpr_readdir_not_a_dir,		/* /proc/net/arp	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/dev	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/dev_mcast	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/igmp	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/ip_mr_cache */
	lxpr_readdir_not_a_dir,		/* /proc/net/ip_mr_vif	*/
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
	lxpr_readdir_not_a_dir,		/* /proc/net/udp	*/
	lxpr_readdir_not_a_dir,		/* /proc/net/unix	*/
	lxpr_readdir_not_a_dir,		/* /proc/partitions	*/
	lxpr_readdir_not_a_dir,		/* /proc/self		*/
	lxpr_readdir_not_a_dir,		/* /proc/stat		*/
	lxpr_readdir_not_a_dir,		/* /proc/uptime		*/
	lxpr_readdir_not_a_dir,		/* /proc/version	*/
};


/*
 * lxpr_read(): Vnode operation for VOP_READ()
 *
 * As the format of all the files that can be read in lxproc is human readable
 * and not binary structures there do not have to be different read variants
 * depending on whether the reading process model is 32- or 64-bit.
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
 * lxpr_read_pid_cmdline():
 *
 * This is not precisely compatible with Linux: the Linux cmdline returns argv
 * with the correct separation using \0 between the arguments, but we cannot do
 * that without copying the real argv from the correct process context.  This
 * is too difficult to attempt so we pretend that the entire cmdline is just
 * argv[0]. This is good enough for ps and htop to display correctly, but might
 * cause some other things not to work correctly.
 */
static void
lxpr_read_pid_cmdline(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	proc_t *p;
	char *buf;

	ASSERT(lxpnp->lxpr_type == LXPR_PID_CMDLINE);

	p = lxpr_lock(lxpnp->lxpr_pid);
	if (p == NULL) {
		lxpr_uiobuf_seterr(uiobuf, EINVAL);
		return;
	}

	buf = PTOU(p)->u_argv != 0 ? PTOU(p)->u_psargs : PTOU(p)->u_comm;

	lxpr_uiobuf_write(uiobuf, buf, strlen(buf) + 1);
	lxpr_unlock(p);
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
		caddr_t saddr;
		caddr_t eaddr;
		int type;
		char prot[5];
		uint32_t offset;
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

		pbuf->saddr = seg->s_base;
		pbuf->eaddr = seg->s_base+seg->s_size;
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

		pbuf->offset = (uint32_t)SEGOP_GETOFFSET(seg, pbuf->saddr);

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
		u_longlong_t inode = 0;

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

		if (*buf != '\0') {
			lxpr_uiobuf_printf(uiobuf,
			    "%08x-%08x %s %08x %02d:%03d %lld %s\n",
			    pbuf->saddr, pbuf->eaddr, pbuf->prot, pbuf->offset,
			    maj, min, inode, buf);
		} else {
			lxpr_uiobuf_printf(uiobuf,
			    "%08x-%08x %s %08x %02d:%03d %lld\n",
			    pbuf->saddr, pbuf->eaddr, pbuf->prot, pbuf->offset,
			    maj, min, inode);
		}

		pbuf_next = pbuf->next;
		kmem_free(pbuf, sizeof (*pbuf));
		pbuf = pbuf_next;
	}

	kmem_free(buf, buflen);
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
	 * process
	 */
	if (pid == curproc->p_zone->zone_proc_initpid) {
		pid = 1;
		ppid = 0;	/* parent pid for init is 0 */
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
		    0l,
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
		lx_sig = lxpr_sigmap[i];

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

/* ARGSUSED */
static void
lxpr_read_net_dev(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_uiobuf_printf(uiobuf, "Inter-|   Receive                   "
	    "                             |  Transmit\n");
	lxpr_uiobuf_printf(uiobuf, " face |bytes    packets errs drop fifo"
	    " frame compressed multicast|bytes    packets errs drop fifo"
	    " colls carrier compressed\n");

	/*
	 * Data about each interface should go here, but that shouldn't be added
	 * unless there is an lxproc reader that actually makes use of it (and
	 * doesn't need anything else that we refuse to provide)...
	 */
}

/* ARGSUSED */
static void
lxpr_read_net_dev_mcast(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
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

/* ARGSUSED */
static void
lxpr_read_net_route(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
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

/* ARGSUSED */
static void
lxpr_read_net_snmp(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_stat(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_tcp(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_udp(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/* ARGSUSED */
static void
lxpr_read_net_unix(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
}

/*
 * lxpr_read_kmsg(): read the contents of the kernel message queue. We
 * translate this into the reception of console messages for this zone; each
 * read copies out a single zone console message, or blocks until the next one
 * is produced.
 */

#define	LX_KMSG_PRI	"<0>"

static void
lxpr_read_kmsg(lxpr_node_t *lxpnp, struct lxpr_uiobuf *uiobuf)
{
	ldi_handle_t	lh = lxpnp->lxpr_cons_ldih;
	mblk_t		*mp;

	ASSERT(lxpnp->lxpr_type == LXPR_KMSG);

	if (ldi_getmsg(lh, &mp, NULL) == 0) {
		/*
		 * lxproc doesn't like successive reads to the same file
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
	    "        total:     used:    free:  shared: buffers:  cached:\n"
	    "Mem:  %8lu %8lu %8lu %8u %8u %8u\n"
	    "Swap: %8lu %8lu %8lu\n"
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
	    total_mem, total_mem - free_mem, free_mem, 0, 0, 0,
	    total_swap, used_swap, total_swap - used_swap,
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
 * lxpr_read_version(): read the contents of the "version" file.  Note that
 * we don't lie here -- we don't pretend that we're Linux.  If lxproc is to
 * be used in a Linux-branded zone, there will need to be a mount option to
 * indicate that Linux should be more fully mimicked.
 */
/* ARGSUSED */
static void
lxpr_read_version(lxpr_node_t *lxpnp, lxpr_uiobuf_t *uiobuf)
{
	lxpr_uiobuf_printf(uiobuf,
	    "%s version %s (%s version %d.%d.%d) "
	    "#%s SMP %s\n",
	    utsname.sysname, utsname.release,
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
	    utsname.version,
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

		cpu_nrunnable_cum += cp->cpu_disp->disp_nrunnable;
		w_io_cum += CPU_STATS(cp, sys.iowait);
		for (i = 0; i < NCMSTATES; i++) {
			tmptime = cp->cpu_intracct[i];
			scalehrtime(&tmptime);
			irq_cum += NSEC_TO_TICK(tmptime);
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

	lxpr_uiobuf_printf(uiobuf, "cpu %lu %lu %lu %lu %lu %lu %lu\n",
	    user_cum, 0L, sys_cum, idle_cum, 0L, irq_cum, 0L);

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

		lxpr_uiobuf_printf(uiobuf,
		    "cpu%d %lu %lu %lu %lu %lu %lu %lu\n",
		    cp->cpu_id, user_ticks, 0L, sys_ticks, idle_ticks,
		    0L, irq_ticks, 0L);

		if (pools_enabled)
			cp = cp->cpu_next_part;
		else
			cp = cp->cpu_next;
	} while (cp != cpstart);

	mutex_exit(&cpu_lock);

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
		 * mode and keep it looking like a symlink
		 */
		if (type == LXPR_PID_FD_FD) {
			vap->va_mode = lxpnp->lxpr_mode;
			vap->va_type = vp->v_type;
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
		 * allocate and fill in a new lxpr node
		 */
		lxpnp = lxpr_getnode(dp, LXPR_PIDDIR, p, 0);

		lxpr_unlock(p);

		dp = LXPTOV(lxpnp);
		ASSERT(dp != NULL);

		return (dp);
	}

	/* Lookup fixed names */
	return (lxpr_lookup_common(dp, comp, NULL, lxpr_dir, PROCDIRFILES));
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
	error = lxpr_readdir_common(lxpnp, uiop, &ceof, lxpr_dir,
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
		 * init process, otherwise use the value from the proc
		 * structure
		 */
		pid = ((p->p_pid != curproc->p_zone->zone_proc_initpid) ?
		    p->p_pid : 1);

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

	ASSERT(lxpnp->lxpr_type == LXPR_PIDDIR);

	/* can't read its contents if it died */
	mutex_enter(&pidlock);

	p = prfind((lxpnp->lxpr_pid == 1) ?
	    curproc->p_zone->zone_proc_initpid : lxpnp->lxpr_pid);

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

	/* must be a symbolic link file */
	if (vp->v_type != VLNK)
		return (EINVAL);

	/* Try to produce a symlink name for anything that has a realvp */
	if (rvp != NULL) {
		if ((error = lxpr_access(vp, VREAD, 0, CRED(), ct)) != 0)
			return (error);
		if ((error = vnodetopath(NULL, rvp, bp, buflen, CRED())) != 0)
			return (error);
	} else {
		switch (lxpnp->lxpr_type) {
		case LXPR_SELF:
			/*
			 * Convert pid to the Linux default of 1 if we're the
			 * zone's init process
			 */
			pid = ((curproc->p_pid !=
			    curproc->p_zone->zone_proc_initpid)
			    ? curproc->p_pid : 1);

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
