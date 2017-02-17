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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/open.h>
#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/poll.h>
#include <sys/utsname.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/obpdefs.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <sys/kstat.h>
#include <sys/membar.h>
#include <sys/ivintr.h>
#include <sys/vm_machparam.h>
#include <sys/x_call.h>
#include <sys/cpuvar.h>
#include <sys/archsystm.h>
#include <sys/dmv.h>

#include <sys/idn.h>
#include <sys/idn_xf.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/cpu_sgn.h>

struct idn_gkstat	sg_kstat;

#define	MBXTBL_PART_REPORT	((caddr_t)1)
#define	MBXTBL_FULL_REPORT	((caddr_t)2)

idn_domain_t	idn_domain[MAX_DOMAINS];
idn_global_t	idn;
int		idn_debug;
int		idn_snoop;
int		idn_history;

typedef enum {
	IDN_GPROPS_OKAY,
	IDN_GPROPS_UNCHECKED,
	IDN_GPROPS_ERROR
} idn_gprops_t;

struct idn_history	idnhlog;

/*
 * IDN "tunables".
 */
int		idn_smr_size;
int		idn_nwr_size;
int		idn_lowat;
int		idn_hiwat;
int		idn_protocol_nservers;
int		idn_awolmsg_interval;
int		idn_smr_bufsize;
int		idn_slab_bufcount;
int		idn_slab_prealloc;
int		idn_slab_maxperdomain;
int		idn_slab_mintotal;
int		idn_window_max;
int		idn_window_incr;
int		idn_window_emax;
int		idn_reclaim_min;
int		idn_reclaim_max;
int		idn_mbox_per_net;
int		idn_max_nets;

int		idn_netsvr_spin_count;
int		idn_netsvr_wait_min;
int		idn_netsvr_wait_max;
int		idn_netsvr_wait_shift;

int		idn_checksum;

int		idn_msgwait_nego;
int		idn_msgwait_cfg;
int		idn_msgwait_con;
int		idn_msgwait_fin;
int		idn_msgwait_cmd;
int		idn_msgwait_data;

int		idn_retryfreq_nego;
int		idn_retryfreq_con;
int		idn_retryfreq_fin;

int		idn_window_emax;	/* calculated */
int		idn_slab_maxperdomain;	/* calculated */

/*
 * DMV interrupt support.
 */
int		idn_pil;
int		idn_dmv_pending_max;
idn_dmv_msg_t	*idn_iv_queue[NCPU];
int		idn_intr_index[NCPU];	/* idn_handler ONLY */
static idn_dmv_data_t	*idn_dmv_data;

int		idn_sigbpil;

idnparam_t	idn_param_arr[] = {
{ 0,		1,		0,		/* 0 */ "idn_modunloadable" },
};

/*
 * Parameters that are only accessible in a DEBUG driver.
 */
static char *idn_param_debug_only[] = {
#if 0
	"idn_checksum",
#endif /* 0 */
	0
};

/*
 * Parameters that are READ-ONLY.
 */
static char *idn_param_read_only[] = {
#if 0
	"idn_window_emax",
	"idn_slab_maxperdomain",
#endif /* 0 */
	0
};

static struct idn_global_props {
	int		p_min, p_max, p_def;
	char		*p_string;
	int		*p_var;
} idn_global_props[] = {
{ 0,	0,	0,	"idn_debug",		&idn_debug		},
{ 0,	1,	0,	"idn_history",		&idn_history		},
{ 0,	IDN_SMR_MAXSIZE,
		0,	"idn_smr_size",		&idn_smr_size		},
{ 0,	IDN_SMR_MAXSIZE,
		0,	"idn_nwr_size",		&idn_nwr_size		},
{ 1,	512*1024,
		1,	"idn_lowat",		&idn_lowat		},
{ 1*1024,
	1*1024*1024,
		256*1024,
			"idn_hiwat",		&idn_hiwat		},
{ IDN_SMR_BUFSIZE_MIN,
	IDN_SMR_BUFSIZE_MAX,
		IDN_SMR_BUFSIZE_DEF,
			"idn_smr_bufsize",	&idn_smr_bufsize	},
{ 4,	1024,	32,	"idn_slab_bufcount",	&idn_slab_bufcount	},
{ 0,	10,	0,	"idn_slab_prealloc",	&idn_slab_prealloc	},
{ 2,	MAX_DOMAINS,
		8,	"idn_slab_mintotal",	&idn_slab_mintotal	},
{ 8,	256,	64,	"idn_window_max",	&idn_window_max		},
{ 0,	32,	8,	"idn_window_incr",	&idn_window_incr	},
{ 1,	128,	5,	"idn_reclaim_min",	&idn_reclaim_min	},
{ 0,	128,	0,	"idn_reclaim_max",	&idn_reclaim_max	},
{ 1,	IDN_MAXMAX_NETS,
		8,	"idn_max_nets",		&idn_max_nets		},
{ 31,	511,	127,	"idn_mbox_per_net",	&idn_mbox_per_net	},
{ 0,	1,	1,	"idn_checksum",		&idn_checksum		},
{ 0,	10000,	500,	"idn_netsvr_spin_count",
						&idn_netsvr_spin_count	},
{ 0,	30*100,	40,	"idn_netsvr_wait_min",	&idn_netsvr_wait_min	},
{ 0,	60*100,	16*100,	"idn_netsvr_wait_max",	&idn_netsvr_wait_max	},
{ 1,	5,	1,	"idn_netsvr_wait_shift",
						&idn_netsvr_wait_shift	},
{ 1,	MAX_DOMAINS,
		IDN_PROTOCOL_NSERVERS,
			"idn_protocol_nservers",
						&idn_protocol_nservers	},
{ 0,	3600,	IDN_AWOLMSG_INTERVAL,
			"idn_awolmsg_interval",	&idn_awolmsg_interval	},
{ 10,	300,	IDN_MSGWAIT_NEGO,
			"idn_msgwait_nego",	&idn_msgwait_nego	},
{ 10,	300,	IDN_MSGWAIT_CFG,
			"idn_msgwait_cfg",	&idn_msgwait_cfg	},
{ 10,	300,	IDN_MSGWAIT_CON,
			"idn_msgwait_con",	&idn_msgwait_con	},
{ 10,	300,	IDN_MSGWAIT_FIN,
			"idn_msgwait_fin",	&idn_msgwait_fin	},
{ 10,	300,	IDN_MSGWAIT_CMD,
			"idn_msgwait_cmd",	&idn_msgwait_cmd	},
{ 10,	300,	IDN_MSGWAIT_DATA,
			"idn_msgwait_data",	&idn_msgwait_data	},
{ 1,	60,	IDN_RETRYFREQ_NEGO,
			"idn_retryfreq_nego",	&idn_retryfreq_nego	},
{ 1,	60,	IDN_RETRYFREQ_CON,
			"idn_retryfreq_con",	&idn_retryfreq_con	},
{ 1,	60,	IDN_RETRYFREQ_FIN,
			"idn_retryfreq_fin",	&idn_retryfreq_fin	},
{ 1,	9,	IDN_PIL,
			"idn_pil",		&idn_pil		},
{ 1,	9,	IDN_SIGBPIL,
			"idn_sigbpil",		&idn_sigbpil		},
{ 8,	512,	IDN_DMV_PENDING_MAX,
			"idn_dmv_pending_max",	&idn_dmv_pending_max	},
{ 0,	0,	0,	NULL,			NULL			}
};

struct idn	*idn_i2s_table[IDN_MAXMAX_NETS << 1];
clock_t		idn_msg_waittime[IDN_NUM_MSGTYPES];
clock_t		idn_msg_retrytime[(int)IDN_NUM_RETRYTYPES];

static caddr_t	idn_ndlist;	/* head of 'named dispatch' var list */

static int	idnattach(dev_info_t *, ddi_attach_cmd_t);
static int	idndetach(dev_info_t *, ddi_detach_cmd_t);
static int	idnopen(register queue_t *, dev_t *, int, int, cred_t *);
static int	idnclose(queue_t *, int, cred_t *);
static int	idnwput(queue_t *, mblk_t *);
static int	idnwsrv(queue_t *);
static int	idnrput(queue_t *, mblk_t *);
static void	idnioctl(queue_t *, mblk_t *);
static idn_gprops_t	idn_check_conf(dev_info_t *dip, processorid_t *cpuid);
static int	idn_size_check();
static void	idn_xmit_monitor_init();
static void	idn_xmit_monitor_deinit();
static void	idn_init_msg_waittime();
static void	idn_init_msg_retrytime();
static void	idn_sigb_setup(cpu_sgnblk_t *sigbp, void *arg);
static int	idn_init(dev_info_t *dip);
static int	idn_deinit();
static void	idn_sigbhandler_create();
static void	idn_sigbhandler_kill();
static uint_t	idn_sigbhandler_wakeup(caddr_t arg1, caddr_t arg2);
static void	idn_sigbhandler_thread(struct sigbintr **sbpp);
static void	idn_sigbhandler(processorid_t cpuid, cpu_sgnblk_t *sgnblkp);
static int	idn_info(idnsb_info_t *sfp);
static int	idn_init_smr();
static void	idn_deinit_smr();
static int	idn_prom_getsmr(uint_t *smrsz, uint64_t *paddrp,
				uint64_t *sizep);
static int	idn_init_handler();
static void	idn_deinit_handler();
static uint_t	idn_handler(caddr_t unused, caddr_t unused2);
/*
 * ioctl services
 */
static int	idnioc_link(idnop_t *idnop);
static int	idnioc_unlink(idnop_t *idnop);
static int	idn_rw_mem(idnop_t *idnop);
static int	idn_send_ping(idnop_t *idnop);

static void 	idn_domains_init(struct hwconfig *local_hw);
static void 	idn_domains_deinit();
static void	idn_retrytask_init();
static void	idn_retrytask_deinit();
static void	idn_gkstat_init();
static void	idn_gkstat_deinit();
static int	idn_gkstat_update();
static void	idn_timercache_init();
static void	idn_timercache_deinit();
static void	idn_dopers_init();
static void	idn_dopers_deinit();

static void	idn_param_cleanup();
static int	idn_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr);
static int	idn_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
					cred_t *cr);
static int	idn_param_register(register idnparam_t *idnpa, int count);
static int	idn_slabpool_report(queue_t *wq, mblk_t *mp, caddr_t cp,
					cred_t *cr);
static int	idn_buffer_report(queue_t *wq, mblk_t *mp, caddr_t cp,
					cred_t *cr);
static int	idn_mboxtbl_report(queue_t *wq, mblk_t *mp, caddr_t cp,
					cred_t *cr);
static int	idn_mainmbox_report(queue_t *wq, mblk_t *mp, caddr_t cp,
					cred_t *cr);
static void	idn_mainmbox_domain_report(queue_t *wq, mblk_t *mp, int domid,
					idn_mainmbox_t *mmp, char *mbxtype);
static int	idn_global_report(queue_t *wq, mblk_t *mp, caddr_t cp,
					cred_t *cr);
static int	idn_domain_report(queue_t *wq, mblk_t *mp, caddr_t cp,
					cred_t *cr);
static int	idn_get_net_binding(queue_t *wq, mblk_t *mp, caddr_t cp,
					cred_t *cr);
static int	idn_set_net_binding(queue_t *wq, mblk_t *mp, char *value,
					caddr_t cp, cred_t *cr);

/*
 * String definitions used for DEBUG and non-DEBUG.
 */
const char	*idnm_str[] = {
/*  0 */	"null",
/*  1 */	"nego",
/*  2 */	"con",
/*  3 */	"cfg",
/*  4 */	"fin",
/*  5 */	"cmd",
/*  6 */	"data",
};

const char	*idnds_str[] = {
/*  0 */	"CLOSED",
/*  1 */	"NEGO_PEND",
/*  2 */	"NEGO_SENT",
/*  3 */	"NEGO_RCVD",
/*  4 */	"CONFIG",
/*  5 */	"CON_PEND",
/*  6 */	"CON_SENT",
/*  7 */	"CON_RCVD",
/*  8 */	"CON_READY",
/*  9 */	"CONNECTED",
/* 10 */	"FIN_PEND",
/* 11 */	"FIN_SENT",
/* 12 */	"FIN_RCVD",
/* 13 */	"DMAP"
};

const char	*idnxs_str[] = {
/* 0 */		"PEND",
/* 1 */		"SENT",
/* 2 */		"RCVD",
/* 3 */		"FINAL",
/* 4 */		"NIL"
};

const char	*idngs_str[] = {
/*  0 */	"OFFLINE",
/*  1 */	"CONNECT",
/*  2 */	"ONLINE",
/*  3 */	"DISCONNECT",
/*  4 */	"RECONFIG",
/*  5 */	"unknown",
/*  6 */	"unknown",
/*  7 */	"unknown",
/*  8 */	"unknown",
/*  9 */	"unknown",
/* 10 */	"IGNORE"
};

const char	*idncmd_str[] = {
/*  0 */	"unknown",
/*  1 */	"SLABALLOC",
/*  2 */	"SLABFREE",
/*  3 */	"SLABREAP",
/*  4 */	"NODENAME"
};

const char	*idncon_str[] = {
/*  0 */	"OFF",
/*  1 */	"NORMAL",
/*  2 */	"QUERY"
};

const char	*idnfin_str[] = {
/*  0 */	"OFF",
/*  1 */	"NORMAL",
/*  2 */	"FORCE_SOFT",
/*  3 */	"FORCE_HARD",
/*  4 */	"QUERY"
};

const char	*idnfinopt_str[] = {
/*  0 */	"NONE",
/*  1 */	"UNLINK",
/*  2 */	"RELINK"
};

const char	*idnfinarg_str[] = {
/*  0 */	"NONE",
/*  1 */	"SMRBAD",
/*  2 */	"CPUCFG",
/*  3 */	"HWERR",
/*  4 */	"CFGERR_FATAL",
/*  5 */	"CFGERR_MTU",
/*  6 */	"CFGERR_BUF",
/*  7 */	"CFGERR_SLAB",
/*  8 */	"CFGERR_NWR",
/*  9 */	"CFGERR_NETS",
/* 10 */	"CFGERR_MBOX",
/* 11 */	"CFGERR_NMCADR",
/* 12 */	"CFGERR_MCADR",
/* 13 */	"CFGERR_CKSUM",
/* 14 */	"CFGERR_SMR",
};

const char	*idnsync_str[] = {
/*  0 */	"NIL",
/*  1 */	"CONNECT",
/*  2 */	"DISCONNECT"
};

const char	*idnreg_str[] = {
/*  0 */	"REG",
/*  1 */	"NEW",
/*  2 */	"QUERY"
};

const char	*idnnack_str[] = {
/*  0 */	"unknown",
/*  1 */	"NOCONN",
/*  2 */	"BADCHAN",
/*  3 */	"BADCFG",
/*  4 */	"BADCMD",
/*  5 */	"RETRY",
/*  6 */	"DUP",
/*  7 */	"EXIT",
/*  8 */	"--reserved1",
/*  9 */	"--reserved2",
/* 10 */	"--reserved3"
};

const char	*idnop_str[] = {
/*  0 */	"DISCONNECTED",
/*  1 */	"CONNECTED",
/*  2 */	"ERROR"
};

const char	*chanop_str[] = {
/*  0 */	"OPEN",
/*  1 */	"SOFT_CLOSE",
/*  2 */	"HARD_CLOSE",
/*  3 */	"OFFLINE",
/*  4 */	"ONLINE"
};

const char	*chanaction_str[] = {
/*  0 */	"DETACH",
/*  1 */	"STOP",
/*  2 */	"SUSPEND",
/*  3 */	"RESUME",
/*  4 */	"RESTART",
/*  5 */	"ATTACH"
};

const char	*timer_str[] = {
/* 0 */		"NIL",
/* 1 */		"MSG"
};

static struct module_info idnrinfo = {
	IDNIDNUM,		/* mi_idnum */
	IDNNAME,		/* mi_idname */
	IDNMINPSZ,		/* mi_minpsz */
	IDNMAXPSZ,		/* mi_maxpsz */
	0,			/* mi_hiwat - see IDN_HIWAT */
	0			/* mi_lowat - see IDN_LOWAT */
};

static struct module_info idnwinfo = {
	IDNIDNUM,		/* mi_idnum */
	IDNNAME,		/* mi_idname */
	IDNMINPSZ,		/* mi_minpsz */
	IDNMAXPSZ,		/* mi_maxpsz */
	0,			/* mi_hiwat - see IDN_HIWAT */
	0			/* mi_lowat - see IDN_LOWAT */
};

static struct qinit idnrinit = {
	idnrput,		/* qi_putp */
	NULL,			/* qi_srvp */
	idnopen,		/* qi_qopen */
	idnclose,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&idnrinfo,		/* qi_minfo */
	NULL,			/* qi_mstat */
	NULL,			/* qi_rwp */
	NULL,			/* qi_infop */
	STRUIOT_DONTCARE	/* qi_struiot */
};

static struct qinit idnwinit = {
	idnwput,		/* qi_putp */
	idnwsrv,		/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&idnwinfo,		/* qi_minfo */
	NULL,			/* qi_mstat */
	NULL,			/* qi_rwp */
	NULL,			/* qi_infop */
	STRUIOT_DONTCARE	/* qi_struiot */
};

struct streamtab idninfo = {
	&idnrinit,		/* st_rdinit */
	&idnwinit,		/* st_wrinit */
	NULL,			/* st_muxrinit */
	NULL,			/* st_muxwinit */
};

/*
 * Module linkage information (cb_ops & dev_ops) for the kernel.
 */

static struct cb_ops cb_idnops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&idninfo,		/* cb_stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops idnops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ddi_no_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	idnattach,		/* devo_attach */
	idndetach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_idnops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern cpuset_t	cpu_ready_set;

static struct modldrv modldrv = {
	&mod_driverops,		/* This module is a pseudo driver */
	IDNDESC " 1.58",
	&idnops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * --------------------------------------------------
 */
int
_init(void)
{
	idn.version = IDN_VERSION;

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * ----------------------------------------------
 */
static int
idnattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	int		doinit = 0;
	processorid_t	bcpuid;
	struct idn	*sip;
	struct idnstr	*stp;
	procname_t	proc = "idnattach";


#ifndef	lint
	ASSERT(sizeof (idnsb_t) == IDNSB_SIZE);
	ASSERT(offsetof(struct idnsb, id_hwchkpt[0]) == 0x40);
#endif	/* lint */

	switch (cmd) {
	case DDI_RESUME:
		sip = ddi_get_driver_private(dip);
		/*
		 * sip may have not yet been set if the
		 * OBP environment variable (idn-smr-size)
		 * was not set.
		 */
		if (sip == NULL)
			return (DDI_FAILURE);
		/*
		 * RESUME IDN services.
		 */
		IDN_GLOCK_SHARED();
		if (idn.state != IDNGS_OFFLINE) {
			cmn_err(CE_WARN,
			    "IDN: 101: not in expected OFFLINE state "
			    "for DDI_RESUME");
			ASSERT(0);
		}
		IDN_GUNLOCK();

		/*
		 * RESUME DLPI services.
		 */
		sip->si_flags &= ~IDNSUSPENDED;

		rw_enter(&idn.struprwlock, RW_READER);
		for (stp = idn.strup; stp; stp = stp->ss_nextp)
			if (stp->ss_sip == sip) {
				doinit = 1;
				break;
			}
		rw_exit(&idn.struprwlock);
		if (doinit)
			(void) idndl_init(sip);

		return (DDI_SUCCESS);

	case DDI_ATTACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	PR_DRV("%s: instance = %d\n", proc, instance);

	if (idn_check_conf(dip, &bcpuid) == IDN_GPROPS_ERROR)
		return (DDI_FAILURE);

	mutex_enter(&idn.siplock);

	if (ddi_create_minor_node(dip, IDNNAME, S_IFCHR, instance,
	    DDI_NT_NET, CLONE_DEV) == DDI_FAILURE) {
		mutex_exit(&idn.siplock);
		return (DDI_FAILURE);
	}

	if (idn.smr.ready == 0) {
		if (idn_init_smr() == 0) {
			idn.enabled = 1;
#ifdef DEBUG
			cmn_err(CE_NOTE, "!IDN: Driver enabled");
#endif /* DEBUG */
		} else {
			cmn_err(CE_NOTE,
			    "!IDN: 102: driver disabled "
			    "- check OBP environment "
			    "(idn-smr-size)");
			mutex_exit(&idn.siplock);
			return (DDI_SUCCESS);
		}
	}

	ASSERT(idn.smr.ready || idn.enabled);

	if (idn.dip == NULL) {
		doinit = 1;

		if (idn_size_check()) {
			idn_deinit_smr();
			ddi_remove_minor_node(dip, NULL);
			mutex_exit(&idn.siplock);
			return (DDI_FAILURE);
		}

		if (idn_init(dip)) {
			idn_deinit_smr();
			ddi_remove_minor_node(dip, NULL);
			mutex_exit(&idn.siplock);
			return (DDI_FAILURE);
		}
	}

	ASSERT(idn.dip);

	/*
	 * This must occur _after_ idn_init() since
	 * it assumes idn_chanservers_init() has been
	 * called.
	 */
	idn_chanserver_bind(ddi_get_instance(dip), bcpuid);

	/*
	 * DLPI supporting stuff.
	 */
	sip = GETSTRUCT(struct idn, 1);
	sip->si_dip = dip;
	ddi_set_driver_private(dip, sip);
	sip->si_nextp = idn.sip;
	idn.sip = sip;
	IDN_SET_INST2SIP(instance, sip);
	mutex_exit(&idn.siplock);

	if (doinit)
		idndl_dlpi_init();	/* initializes idninfoack */
	/*
	 * Get our local IDN ethernet address.
	 */
	idndl_localetheraddr(sip, &sip->si_ouraddr);
	idndl_statinit(sip);

	if (doinit) {
		idn_gkstat_init();
		/*
		 * Add our sigblock SSP interrupt handler.
		 */
		mutex_enter(&idn.sigbintr.sb_mutex);
		idn_sigbhandler_create();
		mutex_exit(&idn.sigbintr.sb_mutex);

		if (sgnblk_poll_register(idn_sigbhandler) == 0) {
			mutex_enter(&idn.sigbintr.sb_mutex);
			idn_sigbhandler_kill();
			idn.sigbintr.sb_cpuid = (uchar_t)-1;
			idn.sigbintr.sb_busy = IDNSIGB_INACTIVE;
			mutex_exit(&idn.sigbintr.sb_mutex);

			idn_gkstat_deinit();

			mutex_enter(&idn.siplock);
			(void) idn_deinit();
			IDN_SET_INST2SIP(instance, NULL);
			idn.sip = sip->si_nextp;
			mutex_exit(&idn.siplock);

			ddi_remove_minor_node(dip, NULL);

			return (DDI_FAILURE);
		}
		/*
		 * We require sigblkp[cpu0] to be mapped for hardware
		 * configuration determination and also auto-linking
		 * on bootup.
		 */
		if (sgnblk_poll_reference(idn_sigb_setup, NULL) != 0) {
			(void) sgnblk_poll_unregister(idn_sigbhandler);
			mutex_enter(&idn.sigbintr.sb_mutex);
			idn_sigbhandler_kill();
			idn.sigbintr.sb_cpuid = (uchar_t)-1;
			idn.sigbintr.sb_busy = IDNSIGB_INACTIVE;
			mutex_exit(&idn.sigbintr.sb_mutex);

			idn_gkstat_deinit();

			mutex_enter(&idn.siplock);
			(void) idn_deinit();
			IDN_SET_INST2SIP(instance, NULL);
			idn.sip = sip->si_nextp;
			mutex_exit(&idn.siplock);

			ddi_remove_minor_node(dip, NULL);

			cmn_err(CE_WARN,
			    "IDN: 103: unable to reference sigblock area");

			return (DDI_FAILURE);
		}

		idn_init_autolink();
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

/*
 * ----------------------------------------------
 */
static int
idndetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		err = 0;
	int		instance;
	struct idn	*sip, *hsip, *tsip;
	procname_t	proc = "idndetach";

	sip = ddi_get_driver_private(dip);
	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_SUSPEND:
		if (sip == NULL)
			return (DDI_FAILURE);
		/*
		 * SUSPEND IDN services.
		 * - Actually don't suspend anything, we just
		 *   make sure we're not connected per DR protocol.
		 *   If we really wanted to suspend it should
		 *   be done _after_ DLPI is suspended so that
		 *   we're not competing with that traffic.
		 */
		IDN_GLOCK_SHARED();

		if (idn.state != IDNGS_OFFLINE) {
			int	d;

			cmn_err(CE_WARN,
			    "IDN: 104: cannot suspend while active "
			    "(state = %s)",
			    idngs_str[idn.state]);

			for (d = 0; d < MAX_DOMAINS; d++) {
				idn_domain_t	*dp;

				dp = &idn_domain[d];
				if (dp->dcpu < 0)
					continue;

				cmn_err(CE_CONT,
				    "IDN: 121: domain %d (CPU %d, name "
				    "\"%s\", state %s)\n",
				    d, dp->dcpu, dp->dname,
				    idnds_str[dp->dstate]);
			}
			err = 1;
		}

		IDN_GUNLOCK();

		if (err)
			return (DDI_FAILURE);
		/*
		 * SUSPEND DLPI services.
		 */
		sip->si_flags |= IDNSUSPENDED;

		idndl_uninit(sip);

		return (DDI_FAILURE);

	case DDI_DETACH:
		if (idn.enabled == 0) {
			ddi_remove_minor_node(dip, NULL);
			ASSERT(idn.dip == NULL);
			return (DDI_SUCCESS);
		}
		if (!IDN_MODUNLOADABLE)
			return (DDI_FAILURE);
		break;

	default:
		return (DDI_FAILURE);
	}

	PR_DRV("%s: instance = %d\n", proc, instance);

	if (sip == NULL) {
		/*
		 * No resources allocated.
		 */
		return (DDI_SUCCESS);
	}

	mutex_enter(&idn.siplock);
	if (idn.sip && (idn.sip->si_nextp == NULL)) {
		/*
		 * This is our last stream connection
		 * going away.  Time to deinit and flag
		 * the SSP we're (IDN) DOWN.
		 */
		if (idn_deinit()) {
			/*
			 * Must still be active.
			 */
			mutex_exit(&idn.siplock);
			return (DDI_FAILURE);
		}
		idn_deinit_autolink();
		/*
		 * Remove our sigblock SSP interrupt handler.
		 */
		(void) sgnblk_poll_unregister(idn_sigbhandler);
		mutex_enter(&idn.sigbintr.sb_mutex);
		idn_sigbhandler_kill();
		idn.sigbintr.sb_cpuid = (uchar_t)-1;
		idn.sigbintr.sb_busy = IDNSIGB_NOTREADY;
		mutex_exit(&idn.sigbintr.sb_mutex);
		/*
		 * Remove our reference to the sigblock area.
		 */
		sgnblk_poll_unreference(idn_sigb_setup);
		idn_gkstat_deinit();
	}

	ddi_remove_minor_node(dip, NULL);

	/*
	 * Remove this instance from our linked list.
	 */
	IDN_SET_INST2SIP(instance, NULL);
	if ((hsip = tsip = idn.sip) == sip) {
		idn.sip = sip->si_nextp;
	} else {
		for (; hsip && (sip != hsip); tsip = hsip,
		    hsip = hsip->si_nextp)
			;
		if (hsip)
			tsip->si_nextp = hsip->si_nextp;
	}
	mutex_exit(&idn.siplock);
	if (sip->si_ksp)
		kstat_delete(sip->si_ksp);

	ddi_set_driver_private(dip, NULL);

	FREESTRUCT(sip, struct idn, 1);

	return (DDI_SUCCESS);
}

/*
 * ----------------------------------------------
 */
static idn_gprops_t
idn_check_conf(dev_info_t *dip, processorid_t *cpuid)
{
	static idn_gprops_t	global_props = IDN_GPROPS_UNCHECKED;

	if (global_props == IDN_GPROPS_UNCHECKED) {
		int		p;

		global_props = IDN_GPROPS_OKAY;

		for (p = 0; idn_global_props[p].p_string; p++) {
			char	*str;
			int	*var;
			int	val, v_min, v_max, v_def;

			str = idn_global_props[p].p_string;
			var = (int *)idn_global_props[p].p_var;
			v_min = idn_global_props[p].p_min;
			v_max = idn_global_props[p].p_max;
			v_def = idn_global_props[p].p_def;
			ASSERT(str && var);

			val = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS |
			    DDI_PROP_NOTPROM,
			    str, v_def);
			if ((v_min != v_max) &&
			    ((val < v_min) || (val > v_max))) {
				cmn_err(CE_WARN,
				    "IDN: 105: driver parameter "
				    "(%s) specified (%d) out of "
				    "range [%d - %d]",
				    str, val, v_min, v_max);
				global_props = IDN_GPROPS_ERROR;
			} else {
				*var = val;
			}
		}
	}

	*cpuid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "bind_cpu", -1);

	return (global_props);
}

static int
idn_size_check()
{
	int		i, cnt;
	int		rv = 0;
	ulong_t		mboxareasize;
	int		max_num_slabs;
	procname_t	proc = "idn_size_check";

	if (IDN_NWR_SIZE == 0)
		IDN_NWR_SIZE = IDN_SMR_SIZE;

	if (IDN_NWR_SIZE > IDN_SMR_SIZE) {
		cmn_err(CE_WARN,
		    "IDN: 106: idn_nwr_size(%d) > idn_smr_size(%d)"
		    " - Limiting to %d MB",
		    IDN_NWR_SIZE, IDN_SMR_SIZE, IDN_SMR_SIZE);
		IDN_NWR_SIZE = IDN_SMR_SIZE;
	}

	if (MB2B(IDN_NWR_SIZE) < IDN_SLAB_SIZE) {
		cmn_err(CE_WARN,
		    "IDN: 107: memory region(%lu) < slab size(%u)",
		    MB2B(IDN_NWR_SIZE), IDN_SLAB_SIZE);
		rv = -1;
	}

	if (IDN_LOWAT >= IDN_HIWAT) {
		cmn_err(CE_WARN,
		    "IDN: 108: idn_lowat(%d) >= idn_hiwat(%d)",
		    IDN_LOWAT, IDN_HIWAT);
		rv = -1;
	}

	mboxareasize = (ulong_t)(IDN_MBOXAREA_SIZE + (IDN_SMR_BUFSIZE - 1));
	mboxareasize &= ~((ulong_t)IDN_SMR_BUFSIZE - 1);
#ifdef DEBUG
	if ((ulong_t)IDN_SLAB_SIZE < mboxareasize) {
		PR_DRV("%s: slab size(%d) < mailbox area(%ld)",
		    proc, IDN_SLAB_SIZE, mboxareasize);
		/* not fatal */
	}
#endif /* DEBUG */

	if ((mboxareasize + (ulong_t)IDN_SLAB_SIZE) > MB2B(IDN_NWR_SIZE)) {
		cmn_err(CE_WARN,
		    "IDN: 109: mailbox area(%lu) + slab size(%u) "
		    "> nwr region(%lu)",
		    mboxareasize, IDN_SLAB_SIZE,
		    MB2B(IDN_NWR_SIZE));
		rv = -1;
	}

	max_num_slabs = (int)((MB2B(IDN_NWR_SIZE) - mboxareasize) /
	    (ulong_t)IDN_SLAB_SIZE);
	if (max_num_slabs < IDN_SLAB_MINTOTAL) {
		cmn_err(CE_WARN,
		    "IDN: 110: maximum number of slabs(%d) < "
		    "minimum required(%d)",
		    max_num_slabs, IDN_SLAB_MINTOTAL);
		rv = -1;
	} else {
		IDN_SLAB_MAXPERDOMAIN = max_num_slabs / IDN_SLAB_MINTOTAL;
	}

#if 0
	if ((IDN_MTU + sizeof (struct ether_header)) > IDN_DATA_SIZE) {
		cmn_err(CE_WARN,
		    "IDN: (IDN_MTU(%d) + ether_header(%d)) "
		    "> IDN_DATA_SIZE(%lu)",
		    IDN_MTU, sizeof (struct ether_header),
		    IDN_DATA_SIZE);
		rv = -1;
	}
#endif /* 0 */

	if (IDN_SMR_BUFSIZE & (IDN_ALIGNSIZE - 1)) {
		cmn_err(CE_WARN,
		    "IDN: 111: idn_smr_bufsize(%d) not on a "
		    "64 byte boundary", IDN_SMR_BUFSIZE);
		rv = -1;
	}

	for (i = cnt = 0;
	    (cnt <= 1) && (((ulong_t)1 << i) < MB2B(IDN_NWR_SIZE));
	    i++)
		if ((1 << i) & IDN_SMR_BUFSIZE)
			cnt++;
	if ((i > 0) && (!cnt || (cnt > 1))) {
		cmn_err(CE_WARN,
		    "IDN: 112: idn_smr_bufsize(%d) not a power of 2",
		    IDN_SMR_BUFSIZE);
		rv = -1;
	}

	if ((IDN_MBOX_PER_NET & 1) == 0) {
		cmn_err(CE_WARN,
		    "IDN: 113: idn_mbox_per_net(%d) must be an "
		    "odd number", IDN_MBOX_PER_NET);
		rv = -1;
	}

	if (idn.nchannels > 0)
		IDN_WINDOW_EMAX = IDN_WINDOW_MAX +
		    ((idn.nchannels - 1) * IDN_WINDOW_INCR);

	if (IDN_NETSVR_WAIT_MIN > IDN_NETSVR_WAIT_MAX) {
		cmn_err(CE_WARN,
		    "IDN: 115: idn_netsvr_wait_min(%d) cannot be "
		    "greater than idn_netsvr_wait_max(%d)",
		    IDN_NETSVR_WAIT_MIN,
		    IDN_NETSVR_WAIT_MAX);
		rv = -1;
	}

	return (rv);
}

static int
idn_init_smr()
{
	uint64_t	obp_paddr;
	uint64_t	obp_size;	/* in Bytes */
	uint_t		smr_size;	/* in MBytes */
	pgcnt_t		npages;
	procname_t	proc = "idn_init_smr";

	if (idn.smr.ready)
		return (0);

	if (idn_prom_getsmr(&smr_size, &obp_paddr, &obp_size) < 0)
		return (-1);

	PR_PROTO("%s: smr_size = %d, obp_paddr = 0x%lx, obp_size = 0x%lx\n",
	    proc, smr_size, obp_paddr, obp_size);

	if (IDN_SMR_SIZE)
		smr_size = MIN(smr_size, IDN_SMR_SIZE);

	npages = btopr(MB2B(smr_size));

	idn.smr.prom_paddr = obp_paddr;
	idn.smr.prom_size = obp_size;
	idn.smr.vaddr = vmem_alloc(heap_arena, ptob(npages), VM_SLEEP);
	ASSERT(((ulong_t)idn.smr.vaddr & MMU_PAGEOFFSET) == 0);
	idn.smr.locpfn = (pfn_t)(obp_paddr >> MMU_PAGESHIFT);
	idn.smr.rempfn = idn.smr.rempfnlim = PFN_INVALID;
	IDN_SMR_SIZE = smr_size;

	PR_PROTO("%s: smr vaddr = %p\n", proc, (void *)idn.smr.vaddr);

	smr_remap(&kas, idn.smr.vaddr, idn.smr.locpfn, IDN_SMR_SIZE);

	idn.localid = PADDR_TO_DOMAINID(obp_paddr);

	idn.smr.ready = 1;

	return (0);
}

static void
idn_deinit_smr()
{
	pgcnt_t		npages;

	if (idn.smr.ready == 0)
		return;

	smr_remap(&kas, idn.smr.vaddr, PFN_INVALID, IDN_SMR_SIZE);

	npages = btopr(MB2B(IDN_SMR_SIZE));

	vmem_free(heap_arena, idn.smr.vaddr, ptob(npages));

	idn.localid = IDN_NIL_DOMID;

	IDN_SMR_SIZE = 0;

	idn.smr.ready = 0;
}

/*ARGSUSED1*/
static void
idn_sigb_setup(cpu_sgnblk_t *sigbp, void *arg)
{
	procname_t	proc = "idn_sigb_setup";

	PR_PROTO("%s: Setting sigb to %p\n", proc, (void *)sigbp);

	mutex_enter(&idn.idnsb_mutex);
	if (sigbp == NULL) {
		idn.idnsb = NULL;
		idn.idnsb_eventp = NULL;
		mutex_exit(&idn.idnsb_mutex);
		return;
	}
	idn.idnsb_eventp = (idnsb_event_t *)sigbp->sigb_idn;
	idn.idnsb = (idnsb_t *)&idn.idnsb_eventp->idn_reserved1;
	mutex_exit(&idn.idnsb_mutex);
}

static int
idn_init(dev_info_t *dip)
{
	struct hwconfig	local_hw;
	procname_t	proc = "idn_init";


	ASSERT(MUTEX_HELD(&idn.siplock));

	if (!idn.enabled) {
		cmn_err(CE_WARN,
		    "IDN: 117: IDN not enabled");
		return (-1);
	}

	if (idn.dip != NULL) {
		PR_DRV("%s: already initialized (dip = 0x%p)\n",
		    proc, (void *)idn.dip);
		return (0);
	}

	/*
	 * Determine our local domain's hardware configuration.
	 */
	if (get_hw_config(&local_hw)) {
		cmn_err(CE_WARN,
		    "IDN: 118: hardware config not appropriate");
		return (-1);
	}

	PR_DRV("%s: locpfn = 0x%lx\n", proc, idn.smr.locpfn);
	PR_DRV("%s: rempfn = 0x%lx\n", proc, idn.smr.rempfn);
	PR_DRV("%s: smrsize = %d MB\n", proc, IDN_SMR_SIZE);

	rw_init(&idn.grwlock, NULL, RW_DEFAULT, NULL);
	rw_init(&idn.struprwlock, NULL, RW_DEFAULT, NULL);
	mutex_init(&idn.sync.sz_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&idn.sipwenlock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Calculate proper value for idn.bframe_shift.
	 * Kind of hokey as it assume knowledge of the format
	 * of the idnparam_t structure.
	 */
	{
		int		s;

		for (s = 0; (1 << s) < IDN_SMR_BUFSIZE_MIN; s++)
			;
		idn.bframe_shift = s;
		PR_DRV("%s: idn.bframe_shift = %d, minbuf = %d\n",
		    proc, idn.bframe_shift, IDN_SMR_BUFSIZE_MIN);

		ASSERT((uint_t)IDN_OFFSET2BFRAME(MB2B(idn_smr_size)) <
		    (1 << 24));
	}

	idn_xmit_monitor_init();

	/*
	 * Initialize the domain op (dopers) stuff.
	 */
	idn_dopers_init();

	/*
	 * Initialize the timer (kmem) cache used for timeout
	 * structures.
	 */
	idn_timercache_init();

	/*
	 * Initialize the slab waiting areas.
	 */
	(void) smr_slabwaiter_init();

	/*
	 * Initialize retryjob kmem cache.
	 */
	idn_retrytask_init();

	idn_init_msg_waittime();
	idn_init_msg_retrytime();

	/*
	 * Initialize idn_domains[] and local domains information
	 * include idn_global information.
	 */
	idn_domains_init(&local_hw);

	/*
	 * Start up IDN protocol servers.
	 */
	if (idn_protocol_init(idn_protocol_nservers) <= 0) {
		cmn_err(CE_WARN,
		    "IDN: 119: failed to initialize %d protocol servers",
		    idn_protocol_nservers);
		idn_domains_deinit();
		idn_retrytask_deinit();
		smr_slabwaiter_deinit();
		idn_timercache_deinit();
		idn_dopers_deinit();
		idn_xmit_monitor_deinit();
		mutex_destroy(&idn.sipwenlock);
		mutex_destroy(&idn.sync.sz_mutex);
		rw_destroy(&idn.grwlock);
		rw_destroy(&idn.struprwlock);
		return (-1);
	}

	/*
	 * Initialize chan_servers array.
	 */
	(void) idn_chanservers_init();

	/*
	 * Need to register the IDN handler with the DMV subsystem.
	 *
	 * Need to prevent the IDN driver from being unloaded
	 * once loaded since DMV's may come in at any time.
	 * If the driver is not loaded and the idn_dmv_handler
	 * has been registered with the DMV, system will crash.
	 */
	(void) idn_init_handler();

	idn.dip = dip;
	IDN_GLOCK_EXCL();
	IDN_GSTATE_TRANSITION(IDNGS_OFFLINE);
	IDN_GUNLOCK();

	return (0);
}

static int
idn_deinit()
{
	procname_t	proc = "idn_deinit";

	ASSERT(MUTEX_HELD(&idn.siplock));

	IDN_GLOCK_EXCL();

	if (idn.state != IDNGS_OFFLINE) {
		int	d;

		cmn_err(CE_WARN,
		    "IDN: 120: cannot deinit while active "
		    "(state = %s)", idngs_str[idn.state]);

		for (d = 0; d < MAX_DOMAINS; d++) {
			idn_domain_t	*dp;

			dp = &idn_domain[d];
			if (dp->dcpu < 0)
				continue;

			cmn_err(CE_CONT,
			    "IDN: 121: domain %d (CPU %d, "
			    "name \"%s\", state %s)\n",
			    d, dp->dcpu, dp->dname,
			    idnds_str[dp->dstate]);
		}
		IDN_GUNLOCK();
		return (-1);
	}

	if (idn.dip == NULL) {
		PR_DRV("%s: already deinitialized\n", proc);
		IDN_GUNLOCK();
		return (0);
	}

	IDN_GSTATE_TRANSITION(IDNGS_IGNORE);

	IDN_GUNLOCK();

	idn_xmit_monitor_deinit();

	idn_deinit_handler();

	idn_chanservers_deinit();

	idn.nchannels = 0;
	ASSERT(idn.chan_servers == NULL);

	smr_slabpool_deinit();

	idn_protocol_deinit();

	idn_domains_deinit();

	smr_slabwaiter_deinit();

	idn_retrytask_deinit();

	idn_timercache_deinit();

	idn_dopers_deinit();

	ASSERT(idn.localid == IDN_NIL_DOMID);

	IDN_SET_MASTERID(IDN_NIL_DOMID);

	idn_deinit_smr();

	mutex_destroy(&idn.sipwenlock);
	mutex_destroy(&idn.sync.sz_mutex);
	rw_destroy(&idn.grwlock);
	rw_destroy(&idn.struprwlock);

	idn.dip = NULL;

	return (0);
}

static void
idn_xmit_monitor_init()
{
	mutex_init(&idn.xmit_lock, NULL, MUTEX_DEFAULT, NULL);
	idn.xmit_tid = (timeout_id_t)NULL;
	CHANSET_ZERO(idn.xmit_chanset_wanted);
}

static void
idn_xmit_monitor_deinit()
{
	timeout_id_t	tid;

	mutex_enter(&idn.xmit_lock);
	CHANSET_ZERO(idn.xmit_chanset_wanted);
	if ((tid = idn.xmit_tid) != (timeout_id_t)NULL) {
		idn.xmit_tid = (timeout_id_t)NULL;
		mutex_exit(&idn.xmit_lock);
		(void) untimeout(tid);
	} else {
		mutex_exit(&idn.xmit_lock);
	}
	mutex_destroy(&idn.xmit_lock);
}

static void
idn_init_msg_waittime()
{
	idn_msg_waittime[IDNP_NULL] = -1;
	idn_msg_waittime[IDNP_NEGO] = idn_msgwait_nego * hz;
	idn_msg_waittime[IDNP_CFG]  = idn_msgwait_cfg * hz;
	idn_msg_waittime[IDNP_CON]  = idn_msgwait_con * hz;
	idn_msg_waittime[IDNP_FIN]  = idn_msgwait_fin * hz;
	idn_msg_waittime[IDNP_CMD]  = idn_msgwait_cmd * hz;
	idn_msg_waittime[IDNP_DATA] = idn_msgwait_data * hz;
}

static void
idn_init_msg_retrytime()
{
	idn_msg_retrytime[(int)IDNRETRY_NIL]	 = -1;
	idn_msg_retrytime[(int)IDNRETRY_NEGO]	 = idn_retryfreq_nego * hz;
	idn_msg_retrytime[(int)IDNRETRY_CON]	 = idn_retryfreq_con * hz;
	idn_msg_retrytime[(int)IDNRETRY_CONQ]	 = idn_retryfreq_con * hz;
	idn_msg_retrytime[(int)IDNRETRY_FIN]	 = idn_retryfreq_fin * hz;
	idn_msg_retrytime[(int)IDNRETRY_FINQ]	 = idn_retryfreq_fin * hz;
}

/*
 * ----------------------------------------------
 */
/*ARGSUSED*/
static int
idnopen(register queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	register int	err = 0;
	int		minordev;
	struct idnstr	*stp, **pstp;
	procname_t	proc = "idnopen";

	ASSERT(sflag != MODOPEN);

	IDN_GLOCK_EXCL();

	rw_enter(&idn.struprwlock, RW_WRITER);
	mutex_enter(&idn.sipwenlock);
	pstp = &idn.strup;

	if (idn.enabled == 0) {
		PR_DRV("%s: Driver disabled (check OBP:idn-smr-size)\n",
		    proc);
		mutex_exit(&idn.sipwenlock);
		rw_exit(&idn.struprwlock);
		IDN_GUNLOCK();
		return (EACCES);
	}

	if (!idn_ndlist &&
	    idn_param_register(idn_param_arr, A_CNT(idn_param_arr))) {
		PR_DRV("%s: failed to register ndd parameters\n", proc);
		mutex_exit(&idn.sipwenlock);
		rw_exit(&idn.struprwlock);
		IDN_GUNLOCK();
		return (ENOMEM);
	}
	IDN_GUNLOCK();

	if (sflag == CLONEOPEN) {
		minordev = 0;
		for (stp = *pstp; stp; pstp = &stp->ss_nextp, stp = *pstp) {
			if (minordev < stp->ss_minor)
				break;
			minordev++;
		}
		*devp = makedevice(getmajor(*devp), minordev);
	} else {
		minordev = getminor(*devp);
	}
	if (rq->q_ptr)
		goto done;

	stp = GETSTRUCT(struct idnstr, 1);
	stp->ss_rq = rq;
	stp->ss_minor = minordev;
	rw_init(&stp->ss_rwlock, NULL, RW_DEFAULT, NULL);
	/*
	 * DLPI stuff
	 */
	stp->ss_sip = NULL;
	stp->ss_state = DL_UNATTACHED;
	stp->ss_sap = 0;
	stp->ss_flags = 0;
	stp->ss_mccount = 0;
	stp->ss_mctab = NULL;

	/*
	 * Link new entry into list of actives.
	 */
	stp->ss_nextp = *pstp;
	*pstp = stp;

	WR(rq)->q_ptr = rq->q_ptr = (void *)stp;
	/*
	 * Disable automatic enabling of our write service
	 * procedure.  We control this explicitly.
	 */
	noenable(WR(rq));

	/*
	 * Set our STREAMs queue maximum packet size that
	 * we'll accept and our high/low water marks.
	 */
	(void) strqset(WR(rq), QMAXPSZ, 0, IDN_DATA_SIZE);
	(void) strqset(WR(rq), QLOWAT,  0, IDN_LOWAT);
	(void) strqset(WR(rq), QHIWAT,  0, IDN_HIWAT);
	(void) strqset(rq, QMAXPSZ, 0, IDN_DATA_SIZE);
	(void) strqset(rq, QLOWAT,  0, IDN_LOWAT);
	(void) strqset(rq, QHIWAT,  0, IDN_HIWAT);

done:
	mutex_exit(&idn.sipwenlock);
	rw_exit(&idn.struprwlock);

	(void) qassociate(rq, -1);
	qprocson(rq);

	return (err);
}

/*
 * ----------------------------------------------
 */
/*ARGSUSED1*/
static int
idnclose(queue_t *rq, int flag, cred_t *crp)
{
	struct idnstr	*stp, **pstp;

	ASSERT(rq->q_ptr);

	qprocsoff(rq);
	/*
	 * Guaranteed to be single threaded with respect
	 * to this stream at this point.
	 */

	stp = (struct idnstr *)rq->q_ptr;

	if (stp->ss_sip)
		idndl_dodetach(stp);

	rw_enter(&idn.struprwlock, RW_WRITER);
	mutex_enter(&idn.sipwenlock);
	pstp = &idn.strup;
	for (stp = *pstp; stp; pstp = &stp->ss_nextp, stp = *pstp)
		if (stp == (struct idnstr *)rq->q_ptr)
			break;
	ASSERT(stp);
	ASSERT(stp->ss_rq == rq);
	*pstp = stp->ss_nextp;

	rw_destroy(&stp->ss_rwlock);
	FREESTRUCT(stp, struct idnstr, 1);

	WR(rq)->q_ptr = rq->q_ptr = NULL;
	mutex_exit(&idn.sipwenlock);
	rw_exit(&idn.struprwlock);

	idn_param_cleanup();
	(void) qassociate(rq, -1);

	return (0);
}

/*
 * ----------------------------------------------
 */
static int
idnwput(register queue_t *wq, register mblk_t *mp)
{
	register struct idnstr	*stp;
	struct idn		*sip;
	procname_t	proc = "idnwput";

	stp = (struct idnstr *)wq->q_ptr;
	sip = stp->ss_sip;

	switch (DB_TYPE(mp)) {
	case M_IOCTL:
		idnioctl(wq, mp);
		break;

	case M_DATA:
		if (((stp->ss_flags & (IDNSFAST|IDNSRAW)) == 0) ||
		    (stp->ss_state != DL_IDLE) ||
		    (sip == NULL)) {
			PR_DLPI("%s: fl=0x%x, st=0x%x, ret(EPROTO)\n",
			    proc, stp->ss_flags, stp->ss_state);
			merror(wq, mp, EPROTO);

		} else if (wq->q_first) {
			if (putq(wq, mp) == 0)
				freemsg(mp);
			/*
			 * We're only holding the reader lock,
			 * but that's okay since this field
			 * is just a soft-flag.
			 */
			sip->si_wantw = 1;
			qenable(wq);

		} else if (sip->si_flags & IDNPROMISC) {
			if (putq(wq, mp) == 0) {
				PR_DLPI("%s: putq failed\n", proc);
				freemsg(mp);
			} else {
				PR_DLPI("%s: putq succeeded\n", proc);
			}
			qenable(wq);

		} else {
			PR_DLPI("%s: idndl_start(sip=0x%p)\n",
			    proc, (void *)sip);
			rw_enter(&stp->ss_rwlock, RW_READER);
			(void) idndl_start(wq, mp, sip);
			rw_exit(&stp->ss_rwlock);
		}
		break;

	case M_PROTO:
	case M_PCPROTO:
		/*
		 * Break the association between the current thread
		 * and the thread that calls idndl_proto() to resolve
		 * the problem of idn_chan_server() threads which
		 * loop back around to call idndl_proto and try to
		 * recursively acquire internal locks.
		 */
		if (putq(wq, mp) == 0)
			freemsg(mp);
		qenable(wq);
		break;

	case M_FLUSH:
		PR_STR("%s: M_FLUSH request (flush = %d)\n",
		    proc, (int)*mp->b_rptr);
		if (*mp->b_rptr & FLUSHW) {
			flushq(wq, FLUSHALL);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR)
			qreply(wq, mp);
		else
			freemsg(mp);
		break;

	default:
		PR_STR("%s: unexpected DB_TYPE 0x%x\n",
		    proc, DB_TYPE(mp));
		freemsg(mp);
		break;
	}

	return (0);
}

/*
 * ----------------------------------------------
 */
static int
idnwsrv(queue_t *wq)
{
	mblk_t		*mp;
	int		err = 0;
	struct idnstr	*stp;
	struct idn	*sip;
	procname_t	proc = "idnwsrv";

	stp = (struct idnstr *)wq->q_ptr;
	sip = stp->ss_sip;

	while (mp = getq(wq)) {
		switch (DB_TYPE(mp)) {
		case M_DATA:
			if (sip) {
				PR_DLPI("%s: idndl_start(sip=0x%p)\n",
				    proc, (void *)sip);
				rw_enter(&stp->ss_rwlock, RW_READER);
				err = idndl_start(wq, mp, sip);
				rw_exit(&stp->ss_rwlock);
				if (err)
					goto done;
			} else {
				PR_DLPI("%s: NO sip to start msg\n", proc);
				freemsg(mp);
			}
			break;

		case M_PROTO:
		case M_PCPROTO:
			idndl_proto(wq, mp);
			break;

		default:
			ASSERT(0);
			PR_STR("%s: unexpected db_type (%d)\n",
			    proc, DB_TYPE(mp));
			freemsg(mp);
			break;
		}
	}
done:
	return (0);
}

/*
 * ----------------------------------------------
 */
static int
idnrput(register queue_t *rq, register mblk_t *mp)
{
	register int	err = 0;
	procname_t	proc = "idnrput";

	switch (DB_TYPE(mp)) {
	case M_DATA:
		/*
		 * Should not reach here with data packets
		 * if running DLPI.
		 */
		cmn_err(CE_WARN,
		    "IDN: 123: unexpected M_DATA packets for "
		    "q_stream 0x%p", (void *)rq->q_stream);
		freemsg(mp);
		err = ENXIO;
		break;

	case M_FLUSH:
		PR_STR("%s: M_FLUSH request (flush = %d)\n",
		    proc, (int)*mp->b_rptr);
		if (*mp->b_rptr & FLUSHR)
			flushq(rq, FLUSHALL);
		(void) putnext(rq, mp);
		break;

	case M_ERROR:
		PR_STR("%s: M_ERROR (error = %d) coming through\n",
		    proc, (int)*mp->b_rptr);
		(void) putnext(rq, mp);
		break;
	default:
		PR_STR("%s: unexpected DB_TYPE 0x%x\n",
		    proc, DB_TYPE(mp));
		freemsg(mp);
		err = ENXIO;
		break;
	}

	return (err);
}

/*
 * ----------------------------------------------
 * Not allowed to enqueue messages!  Only M_DATA messages
 * can be enqueued on the write stream.
 * ----------------------------------------------
 */
static void
idnioctl(register queue_t *wq, register mblk_t *mp)
{
	register struct iocblk	*iocp;
	register int	cmd;
	idnop_t		*idnop = NULL;
	int		error = 0;
	int		argsize;
	procname_t	proc = "idnioctl";

	iocp = (struct iocblk *)mp->b_rptr;
	cmd  = iocp->ioc_cmd;

	/*
	 * Intercept DLPI ioctl's.
	 */
	if (VALID_DLPIOP(cmd)) {
		PR_STR("%s: DLPI ioctl(%d)\n", proc, cmd);
		error = idnioc_dlpi(wq, mp, &argsize);
		goto done;
	}

	/*
	 * Validate expected arguments.
	 */
	if (!VALID_IDNIOCTL(cmd)) {
		PR_STR("%s: invalid cmd (0x%x)\n", proc, cmd);
		error = EINVAL;
		goto done;

	} else if (!VALID_NDOP(cmd)) {
		error = miocpullup(mp, sizeof (idnop_t));
		if (error != 0) {
			PR_STR("%s: idnioc(cmd = 0x%x) miocpullup "
			    "failed (%d)\n", proc, cmd, error);
			goto done;
		}
	}

	argsize = mp->b_cont->b_wptr - mp->b_cont->b_rptr;
	idnop = (idnop_t *)mp->b_cont->b_rptr;

	switch (cmd) {
	case IDNIOC_LINK:
		error = idnioc_link(idnop);
		break;

	case IDNIOC_UNLINK:
		error = idnioc_unlink(idnop);
		break;

	case IDNIOC_MEM_RW:
		error = idn_rw_mem(idnop);
		break;

	case IDNIOC_PING:
		error = idn_send_ping(idnop);
		break;

	case ND_SET:
		IDN_GLOCK_EXCL();
		if (!nd_getset(wq, idn_ndlist, mp)) {
			IDN_GUNLOCK();
			error = ENOENT;
			break;
		}
		IDN_GUNLOCK();
		qreply(wq, mp);
		return;

	case ND_GET:
		IDN_GLOCK_SHARED();
		if (!nd_getset(wq, idn_ndlist, mp)) {
			IDN_GUNLOCK();
			error = ENOENT;
			break;
		}
		IDN_GUNLOCK();
		qreply(wq, mp);
		return;

	default:
		PR_STR("%s: invalid cmd 0x%x\n", proc, cmd);
		error = EINVAL;
		break;
	}

done:
	if (error == 0)
		miocack(wq, mp, argsize, 0);
	else
		miocnak(wq, mp, 0, error);
}

/*
 * This thread actually services the SSI_LINK/UNLINK calls
 * asynchronously that come via BBSRAM.  This is necessary
 * since we can't process them from within the context of
 * the interrupt handler in which idn_sigbhandler() is
 * called.
 */
static void
idn_sigbhandler_thread(struct sigbintr **sbpp)
{
	int		d, pri, rv;
	struct sigbintr	*sbp;
	sigbmbox_t	*mbp;
	idn_fin_t	fintype;
	idnsb_data_t	*sdp;
	idnsb_info_t	*sfp;
	idnsb_error_t	*sep;
	idn_domain_t	*dp;
	procname_t	proc = "idn_sigbhandler_thread";


	sbp = *sbpp;

	PR_PROTO("%s: KICKED OFF (sigbintr pointer = 0x%p)\n",
	    proc, (void *)sbp);

	ASSERT(sbp == &idn.sigbintr);

	mutex_enter(&idn.sigbintr.sb_mutex);

	while (sbp->sb_busy != IDNSIGB_DIE) {
		cpu_sgnblk_t	*sigbp;

		while ((sbp->sb_busy != IDNSIGB_ACTIVE) &&
		    (sbp->sb_busy != IDNSIGB_DIE)) {
			cv_wait(&sbp->sb_cv, &idn.sigbintr.sb_mutex);
			PR_PROTO("%s: AWAKENED (busy = %d)\n",
			    proc, (int)sbp->sb_busy);
		}
		if (sbp->sb_busy == IDNSIGB_DIE) {
			PR_PROTO("%s: DIE REQUESTED\n", proc);
			break;
		}

		if ((sigbp = cpu_sgnblkp[sbp->sb_cpuid]) == NULL) {
			cmn_err(CE_WARN,
			    "IDN: 124: sigblk for CPU ID %d "
			    "is NULL", sbp->sb_cpuid);
			sbp->sb_busy = IDNSIGB_INACTIVE;
			continue;
		}

		mbp = &sigbp->sigb_host_mbox;

		if (mbp->flag != SIGB_MBOX_BUSY) {
			PR_PROTO("%s: sigblk mbox flag (%d) != BUSY (%d)\n",
			    proc, mbp->flag, SIGB_MBOX_BUSY);
			sbp->sb_busy = IDNSIGB_INACTIVE;
			continue;
		}
		/*
		 * The sb_busy bit is set and the mailbox flag
		 * indicates BUSY also, so we effectively have things locked.
		 * So, we can drop the critical sb_mutex which we want to
		 * do since it pushes us to PIL 14 while we hold it and we
		 * don't want to run at PIL 14 across IDN code.
		 */
		mutex_exit(&idn.sigbintr.sb_mutex);

		sdp = (idnsb_data_t *)mbp->data;
		sep = (idnsb_error_t *)&sdp->ssb_error;
		INIT_IDNKERR(sep);

		if (mbp->len != sizeof (idnsb_data_t)) {
			PR_PROTO("%s: sigblk mbox length (%d) != "
			    "expected (%lu)\n", proc, mbp->len,
			    sizeof (idnsb_data_t));
			SET_IDNKERR_ERRNO(sep, EINVAL);
			SET_IDNKERR_IDNERR(sep, IDNKERR_DATA_LEN);
			SET_IDNKERR_PARAM0(sep, sizeof (idnsb_data_t));

			goto sberr;

		}
		if (idn.enabled == 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "IDN: 102: driver disabled "
			    "- check OBP environment "
			    "(idn-smr-size)");
#else /* DEBUG */
			cmn_err(CE_NOTE,
			    "!IDN: 102: driver disabled "
			    "- check OBP environment "
			    "(idn-smr-size)");
#endif /* DEBUG */
			SET_IDNKERR_ERRNO(sep, EACCES);
			SET_IDNKERR_IDNERR(sep, IDNKERR_DRV_DISABLED);

			goto sberr;

		}

		switch (mbp->cmd) {

		case SSI_LINK:
		{
			idnsb_link_t	slp;

			bcopy(&sdp->ssb_link, &slp, sizeof (slp));

			if (slp.master_pri < 0) {
				pri = IDNVOTE_MINPRI;
			} else if (slp.master_pri > 0) {
				/*
				 * If I'm already in a IDN network,
				 * then my vote priority is set to
				 * the max, otherwise it's one-less.
				 */
				pri = IDNVOTE_MAXPRI;
				IDN_GLOCK_SHARED();
				if (idn.ndomains <= 1)
					pri--;
				IDN_GUNLOCK();
			} else {
				pri = IDNVOTE_DEFPRI;
			}

			PR_PROTO("%s: SSI_LINK(cpuid = %d, domid = %d, "
			    "pri = %d (req = %d), t/o = %d)\n",
			    proc, slp.cpuid, slp.domid, pri,
			    slp.master_pri, slp.timeout);

			rv = idn_link(slp.domid, slp.cpuid, pri,
			    slp.timeout, sep);
			SET_IDNKERR_ERRNO(sep, rv);
			(void) idn_info(&sdp->ssb_info);
			break;
		}

		case SSI_UNLINK:
		{
			idnsb_unlink_t	sup;
			idn_domain_t	*xdp;
			domainset_t	domset;

			bcopy(&sdp->ssb_unlink, &sup, sizeof (sup));

			PR_PROTO("%s: SSI_UNLINK(c = %d, d = %d, bs = 0x%x, "
			    "f = %d, is = 0x%x, t/o = %d)\n",
			    proc, sup.cpuid, sup.domid, sup.boardset,
			    sup.force, sup.idnset, sup.timeout);

			domset = idn.domset.ds_trans_on |
			    idn.domset.ds_connected |
			    idn.domset.ds_trans_off |
			    idn.domset.ds_awol |
			    idn.domset.ds_relink;

			if (VALID_DOMAINID(sup.domid)) {
				dp = &idn_domain[sup.domid];
			} else if (VALID_CPUID(sup.cpuid)) {
				for (d = 0; d < MAX_DOMAINS; d++) {
					xdp = &idn_domain[d];

					if ((xdp->dcpu == IDN_NIL_DCPU) &&
					    !DOMAIN_IN_SET(domset, d))
						continue;

					if (CPU_IN_SET(xdp->dcpuset,
					    sup.cpuid))
						break;
				}
				dp = (d == MAX_DOMAINS) ? NULL : xdp;
			}
			if ((dp == NULL) && sup.boardset) {
				for (d = 0; d < MAX_DOMAINS; d++) {
					xdp = &idn_domain[d];

					if ((xdp->dcpu == IDN_NIL_DCPU) &&
					    !DOMAIN_IN_SET(domset, d))
						continue;

					if (xdp->dhw.dh_boardset &
					    sup.boardset)
						break;
				}
				dp = (d == MAX_DOMAINS) ? NULL : xdp;
			}
			if (dp == NULL) {
				SET_IDNKERR_ERRNO(sep, EINVAL);
				SET_IDNKERR_IDNERR(sep, IDNKERR_INVALID_DOMAIN);
				SET_IDNKERR_PARAM0(sep, sup.domid);
				SET_IDNKERR_PARAM1(sep, sup.cpuid);
				(void) idn_info(&sdp->ssb_info);
				goto sberr;
			} else {
				sup.domid = dp->domid;
			}

			switch (sup.force) {
			case SSIFORCE_OFF:
				fintype = IDNFIN_NORMAL;
				break;

			case SSIFORCE_SOFT:
				fintype = IDNFIN_FORCE_SOFT;
				break;

			case SSIFORCE_HARD:
				fintype = IDNFIN_FORCE_HARD;
				break;
			default:
				SET_IDNKERR_ERRNO(sep, EINVAL);
				SET_IDNKERR_IDNERR(sep, IDNKERR_INVALID_FORCE);
				SET_IDNKERR_PARAM0(sep, sup.force);
				(void) idn_info(&sdp->ssb_info);
				goto sberr;
			}

			rv = idn_unlink(sup.domid, sup.idnset, fintype,
			    IDNFIN_OPT_UNLINK, sup.timeout, sep);
			SET_IDNKERR_ERRNO(sep, rv);
			(void) idn_info(&sdp->ssb_info);
			break;
		}

		case SSI_INFO:
			sfp = &sdp->ssb_info;

			PR_PROTO("%s: SSI_INFO\n", proc);

			rv = idn_info(sfp);
			SET_IDNKERR_ERRNO(sep, rv);
			if (rv != 0) {
				SET_IDNKERR_IDNERR(sep, IDNKERR_INFO_FAILED);
			}
			break;

		default:
			ASSERT(0);
			SET_IDNKERR_ERRNO(sep, EINVAL);
			SET_IDNKERR_IDNERR(sep, IDNKERR_INVALID_CMD);
			SET_IDNKERR_PARAM0(sep, mbp->cmd);
			break;
		}

sberr:

		if (GET_IDNKERR_ERRNO(sep) != 0) {
			cmn_err(CE_WARN,
#ifdef DEBUG
			    "IDN: 125: op (%s) failed, returning "
			    "(%d/0x%x [%d, %d, %d])",
#else /* DEBUG */
			    "!IDN: 125: op (%s) failed, returning "
			    "(%d/0x%x [%d, %d, %d])",
#endif /* DEBUG */
			    (mbp->cmd == SSI_LINK) ? "LINK" :
			    (mbp->cmd == SSI_UNLINK) ? "UNLINK" :
			    (mbp->cmd == SSI_INFO) ?
			    "INFO" : "UNKNOWN",
			    GET_IDNKERR_ERRNO(sep),
			    GET_IDNKERR_IDNERR(sep),
			    GET_IDNKERR_PARAM0(sep),
			    GET_IDNKERR_PARAM1(sep),
			    GET_IDNKERR_PARAM2(sep));
		}

		PR_PROTO("%s: returning errno = %d, idnerr = %d, "
		    "params = [%d, %d, %d]\n",
		    proc, GET_IDNKERR_ERRNO(sep), GET_IDNKERR_IDNERR(sep),
		    GET_IDNKERR_PARAM0(sep), GET_IDNKERR_PARAM1(sep),
		    GET_IDNKERR_PARAM2(sep));

		mutex_enter(&idn.sigbintr.sb_mutex);
		ASSERT((sbp->sb_busy == IDNSIGB_ACTIVE) ||
		    (sbp->sb_busy == IDNSIGB_DIE));
		mbp->cmd |= SSI_ACK;
		if (sbp->sb_busy == IDNSIGB_ACTIVE)
			sbp->sb_busy = IDNSIGB_INACTIVE;
		/*
		 * Set flag which kicks off response to SSP.
		 */
		membar_stst_ldst();
		mbp->flag = HOST_TO_CBS;
	}

	/*
	 * Wake up the dude that killed us!
	 */
	idn.sigb_threadp = NULL;
	cv_signal(&sbp->sb_cv);
	mutex_exit(&idn.sigbintr.sb_mutex);
	thread_exit();
}

/*
 * Create the thread that will service sigb interrupts.
 */
static void
idn_sigbhandler_create()
{
	struct sigbintr	*sbp;

	if (idn.sigb_threadp) {
		cmn_err(CE_WARN,
		    "IDN: 126: sigbhandler thread already "
		    "exists (0x%p)", (void *)idn.sigb_threadp);
		return;
	}
	cv_init(&idn.sigbintr.sb_cv, NULL, CV_DEFAULT, NULL);
	sbp = &idn.sigbintr;
	sbp->sb_busy = IDNSIGB_INACTIVE;
	idn.sigb_threadp = thread_create(NULL, 0,
	    idn_sigbhandler_thread, &sbp, sizeof (sbp), &p0,
	    TS_RUN, minclsyspri);
	sbp->sb_inum = add_softintr((uint_t)idn_sigbpil,
	    idn_sigbhandler_wakeup, 0, SOFTINT_ST);
}

static void
idn_sigbhandler_kill()
{
	if (idn.sigb_threadp) {
		struct sigbintr	*sbp;

		sbp = &idn.sigbintr;
		if (sbp->sb_inum != 0)
			(void) rem_softintr(sbp->sb_inum);
		sbp->sb_inum = 0;
		sbp->sb_busy = IDNSIGB_DIE;
		cv_signal(&sbp->sb_cv);
		while (idn.sigb_threadp != NULL)
			cv_wait(&sbp->sb_cv, &idn.sigbintr.sb_mutex);
		sbp->sb_busy = IDNSIGB_INACTIVE;
		cv_destroy(&sbp->sb_cv);
	}
}

/*ARGSUSED0*/
static uint_t
idn_sigbhandler_wakeup(caddr_t arg1, caddr_t arg2)
{
	mutex_enter(&idn.sigbintr.sb_mutex);
	if (idn.sigbintr.sb_busy == IDNSIGB_STARTED) {
		idn.sigbintr.sb_busy = IDNSIGB_ACTIVE;
		cv_signal(&idn.sigbintr.sb_cv);
	}
	mutex_exit(&idn.sigbintr.sb_mutex);

	return (DDI_INTR_CLAIMED);
}

static void
idn_sigbhandler(processorid_t cpuid, cpu_sgnblk_t *sgnblkp)
{
	struct sigbintr	*sbp = &idn.sigbintr;
	sigbmbox_t	*mbp;
	idnsb_data_t	*sdp;
	idnsb_error_t	*sep;
	uint32_t	cmd;
	int		sigb_lock = 0;

	ASSERT(sgnblkp);

	mbp = &sgnblkp->sigb_host_mbox;
	sdp = (idnsb_data_t *)mbp->data;
	sep = &sdp->ssb_error;
	cmd = mbp->cmd;

	if ((mbp->flag != CBS_TO_HOST) || !VALID_IDNSIGBCMD(cmd)) {
		/*
		 * Not a valid IDN command.  Just bail out.
		 */
		return;
	}

	mbp->flag = SIGB_MBOX_BUSY;
	SET_IDNKERR_ERRNO(sep, 0);

	if (cmd & SSI_ACK) {
		/*
		 * Hmmm...weird, the ACK bit is set.
		 */
		SET_IDNKERR_ERRNO(sep, EPROTO);
		SET_IDNKERR_IDNERR(sep, IDNKERR_INVALID_CMD);
		SET_IDNKERR_PARAM0(sep, cmd);
		goto sigb_done;
	}

	if (!mutex_tryenter(&idn.sigbintr.sb_mutex)) {
		/*
		 * Couldn't get the lock.  Driver is either
		 * not quite all the way up or is shutting down
		 * for some reason.  Caller should spin again.
		 */
		cmd |= SSI_ACK;
		SET_IDNKERR_ERRNO(sep, EBUSY);
		SET_IDNKERR_IDNERR(sep, IDNKERR_SIGBINTR_LOCKED);
		goto sigb_done;
	}
	sigb_lock = 1;

	if ((idn.sigb_threadp == NULL) ||
	    (sbp->sb_busy == IDNSIGB_NOTREADY)) {
		cmd |= SSI_ACK;
		SET_IDNKERR_ERRNO(sep, EAGAIN);
		SET_IDNKERR_IDNERR(sep, IDNKERR_SIGBINTR_NOTRDY);
		goto sigb_done;
	}

	if (sbp->sb_busy != IDNSIGB_INACTIVE) {
		cmd |= SSI_ACK;
		SET_IDNKERR_ERRNO(sep, EBUSY);
		SET_IDNKERR_IDNERR(sep, IDNKERR_SIGBINTR_BUSY);
		goto sigb_done;
	}

	sbp->sb_cpuid = (uchar_t)cpuid & 0xff;
	membar_stst_ldst();
	sbp->sb_busy = IDNSIGB_STARTED;
	/*
	 * The sb_busy bit is set and the mailbox flag
	 * indicates BUSY also, so we effectively have things locked.
	 * So, we can drop the critical sb_mutex which we want to
	 * do since it pushes us to PIL 14 while we hold it and we
	 * don't want to run at PIL 14 across IDN code.
	 *
	 * Send interrupt to cause idn_sigbhandler_thread to wakeup.
	 * We cannot do wakeup (cv_signal) directly from here since
	 * we're executing from a high-level (14) interrupt.
	 */
	setsoftint(sbp->sb_inum);

sigb_done:

	if (GET_IDNKERR_ERRNO(sep) != 0) {
		mbp->len = sizeof (idnsb_data_t);
		mbp->cmd = cmd;
		membar_stst_ldst();
		mbp->flag = HOST_TO_CBS;
	}

	if (sigb_lock)
		mutex_exit(&idn.sigbintr.sb_mutex);
}

static int
idn_info(idnsb_info_t *sfp)
{
	int		count, d;
	idn_domain_t	*dp;
	idnsb_info_t	sinfo;
	int		local_id, master_id;
	procname_t	proc = "idn_info";

	bzero(&sinfo, sizeof (sinfo));
	sinfo.master_index = (uchar_t)-1;
	sinfo.master_cpuid = (uchar_t)-1;
	sinfo.local_index  = (uchar_t)-1;
	sinfo.local_cpuid  = (uchar_t)-1;

	IDN_GLOCK_SHARED();

	sinfo.idn_state = (uchar_t)idn.state;

	switch (idn.state) {
	case IDNGS_OFFLINE:
		sinfo.idn_active = SSISTATE_INACTIVE;
		PR_PROTO("%s: idn_state (%s) = INACTIVE\n",
		    proc, idngs_str[idn.state]);
		break;

	case IDNGS_IGNORE:
		PR_PROTO("%s: IGNORING IDN_INFO call...\n", proc);
		IDN_GUNLOCK();
		return (EIO);

	default:
		sinfo.idn_active = SSISTATE_ACTIVE;
		PR_PROTO("%s: idn_state (%s) = ACTIVE\n",
		    proc, idngs_str[idn.state]);
		break;
	}
	master_id = IDN_GET_MASTERID();
	local_id = idn.localid;

	/*
	 * Need to drop idn.grwlock before acquiring domain locks.
	 */
	IDN_GUNLOCK();

	IDN_SYNC_LOCK();

	sinfo.awol_domset = (ushort_t)idn.domset.ds_awol;
	sinfo.conn_domset = (ushort_t)(idn.domset.ds_connected &
	    ~idn.domset.ds_trans_on);
	DOMAINSET_ADD(sinfo.conn_domset, idn.localid);

	count = 0;
	for (d = 0; d < MAX_DOMAINS; d++) {
		dp = &idn_domain[d];

		if (dp->dcpu == IDN_NIL_DCPU)
			continue;

		IDN_DLOCK_SHARED(d);
		if ((dp->dcpu == IDN_NIL_DCPU) ||
		    (dp->dstate == IDNDS_CLOSED)) {
			IDN_DUNLOCK(d);
			continue;
		}

		count++;
		if (d == local_id) {
			sinfo.local_index = (uchar_t)d;
			sinfo.local_cpuid = (uchar_t)dp->dcpu;
			PR_PROTO("%s: domid %d is LOCAL (cpuid = %d)\n",
			    proc, d, dp->dcpu);
		}
		if (d == master_id) {
			sinfo.master_index = (uchar_t)d;
			sinfo.master_cpuid = (uchar_t)dp->dcpu;
			PR_PROTO("%s: domid %d is MASTER (cpuid = %d)\n",
			    proc, d, dp->dcpu);
		}

		sinfo.domain_boardset[d] = (ushort_t)dp->dhw.dh_boardset;

		IDN_DUNLOCK(d);
	}

	IDN_SYNC_UNLOCK();

	bcopy(&sinfo, sfp, sizeof (*sfp));

	PR_PROTO("%s: Found %d domains within IDNnet\n", proc, count);

	return (0);
}

/*
 * ----------------------------------------------
 * ndd param support routines.
 * - Borrowed from tcp.
 * ----------------------------------------------
 */
static void
idn_param_cleanup()
{
	IDN_GLOCK_EXCL();
	if (!idn.strup && idn_ndlist)
		nd_free(&idn_ndlist);
	IDN_GUNLOCK();
}

/*ARGSUSED*/
static int
idn_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	idnparam_t	*idnpa = (idnparam_t *)cp;

	/*
	 * lock grabbed before calling nd_getset.
	 */
	ASSERT(IDN_GLOCK_IS_HELD());

	(void) mi_mpprintf(mp, "%ld", idnpa->sp_val);

	return (0);
}

/*ARGSUSED*/
static int
idn_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *cr)
{
	char		*end;
	ulong_t		new_value;
	idnparam_t	*idnpa = (idnparam_t *)cp;

	/*
	 * lock grabbed before calling nd_getset.
	 */
	ASSERT(IDN_GLOCK_IS_EXCL());

	new_value = (ulong_t)mi_strtol(value, &end, 10);

	if ((end == value) ||
	    (new_value < idnpa->sp_min) ||
	    (new_value > idnpa->sp_max))
		return (EINVAL);

	if (idn.enabled == 0) {
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "IDN: 102: driver disabled "
		    "- check OBP environment "
		    "(idn-smr-size)");
#else /* DEBUG */
		cmn_err(CE_NOTE,
		    "!IDN: 102: driver disabled "
		    "- check OBP environment "
		    "(idn-smr-size)");
#endif /* DEBUG */
		return (EACCES);
	}

	idnpa->sp_val = new_value;

	return (0);
}

static int
idn_param_register(register idnparam_t *idnpa, int count)
{
	ASSERT(IDN_GLOCK_IS_EXCL());

	for (; count > 0; count--, idnpa++) {
		if (idnpa->sp_name && idnpa->sp_name[0]) {
			register int	i;
			ndsetf_t	set_func;
			char		*p;
			/*
			 * Don't advertise in non-DEBUG parameters.
			 */
			for (i = 0; idn_param_debug_only[i]; i++) {
				p = idn_param_debug_only[i];
				if (strcmp(idnpa->sp_name, p) == 0)
					break;
			}
			if (idn_param_debug_only[i])
				continue;

			/*
			 * Do not register a "set" function for
			 * read-only parameters.
			 */
			for (i = 0; idn_param_read_only[i]; i++) {
				p = idn_param_read_only[i];
				if (strcmp(idnpa->sp_name, p) == 0)
					break;
			}
			if (idn_param_read_only[i])
				set_func = NULL;
			else
				set_func = idn_param_set;

			if (!nd_load(&idn_ndlist, idnpa->sp_name,
			    idn_param_get, set_func,
			    (caddr_t)idnpa)) {
				nd_free(&idn_ndlist);
				return (-1);
			}
		}
	}
	if (!nd_load(&idn_ndlist, "idn_slabpool", idn_slabpool_report,
	    NULL, NULL)) {
		nd_free(&idn_ndlist);
		return (-1);
	}
	if (!nd_load(&idn_ndlist, "idn_buffers", idn_buffer_report,
	    NULL, NULL)) {
		nd_free(&idn_ndlist);
		return (-1);
	}
	if (!nd_load(&idn_ndlist, "idn_mboxtbl", idn_mboxtbl_report,
	    NULL, MBXTBL_PART_REPORT)) {
		nd_free(&idn_ndlist);
		return (-1);
	}
	if (!nd_load(&idn_ndlist, "idn_mboxtbl_all", idn_mboxtbl_report,
	    NULL, MBXTBL_FULL_REPORT)) {
		nd_free(&idn_ndlist);
		return (-1);
	}
	if (!nd_load(&idn_ndlist, "idn_mainmbox", idn_mainmbox_report,
	    NULL, NULL)) {
		nd_free(&idn_ndlist);
		return (-1);
	}
	if (!nd_load(&idn_ndlist, "idn_global", idn_global_report,
	    NULL, NULL)) {
		nd_free(&idn_ndlist);
		return (-1);
	}
	if (!nd_load(&idn_ndlist, "idn_domain", idn_domain_report,
	    NULL, (caddr_t)0)) {
		nd_free(&idn_ndlist);
		return (-1);
	}
	if (!nd_load(&idn_ndlist, "idn_domain_all", idn_domain_report,
	    NULL, (caddr_t)1)) {
		nd_free(&idn_ndlist);
		return (-1);
	}
	if (!nd_load(&idn_ndlist, "idn_bind_net", idn_get_net_binding,
	    idn_set_net_binding, NULL)) {
		nd_free(&idn_ndlist);
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static int
idn_set_net_binding(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *cr)
{
	char		*end, *cpup;
	long		net;
	processorid_t	cpuid;

	/*
	 * lock grabbed before calling nd_getset.
	 */
	ASSERT(IDN_GLOCK_IS_EXCL());

	if ((cpup = strchr(value, '=')) == NULL)
		return (EINVAL);

	*cpup++ = '\0';

	net = mi_strtol(value, &end, 10);
	if ((end == value) || (net < 0) || (net >= IDN_MAX_NETS) ||
	    !CHAN_IN_SET(idn.chanset, net))
		return (EINVAL);

	cpuid = (processorid_t)mi_strtol(cpup, &end, 10);
	if ((end == cpup) || ((cpuid != -1) &&
	    (!VALID_CPUID(cpuid) ||
	    !CPU_IN_SET(cpu_ready_set, cpuid))))
		return (EINVAL);

	idn_chanserver_bind(net, cpuid);

	return (0);
}

/*ARGSUSED*/
static int
idn_get_net_binding(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	int	c;

	/*
	 * lock grabbed before calling nd_getset.
	 */
	ASSERT(IDN_GLOCK_IS_HELD());

	(void) mi_mpprintf(mp,
	    "IDN network interfaces/channels active = %d",
	    idn.nchannels);

	if (idn.nchannels == 0)
		return (0);

	(void) mi_mpprintf(mp, "Net    Cpu");

	for (c = 0; c < IDN_MAX_NETS; c++) {
		int		bc;
		idn_chansvr_t	*csp;

		if (!CHAN_IN_SET(idn.chanset, c))
			continue;

		csp = &idn.chan_servers[c];

		if ((bc = csp->ch_bound_cpuid) == -1)
			bc = csp->ch_bound_cpuid_pending;

		if (c < 10)
			(void) mi_mpprintf(mp, " %d      %d", c, bc);
		else
			(void) mi_mpprintf(mp, " %d     %d", c, bc);
	}

	return (0);
}

static int
idnioc_link(idnop_t *idnop)
{
	int		rv;
	int		pri;
	idnsb_error_t	err;
	procname_t	proc = "idnioc_link";

	if (idnop->link.master < 0)
		pri = IDNVOTE_MINPRI;
	else if (idnop->link.master > 0)
		pri = IDNVOTE_MAXPRI;
	else
		pri = IDNVOTE_DEFPRI;

	PR_DRV("%s: domid = %d, cpuid = %d, pri = %d\n",
	    proc, idnop->link.domid, idnop->link.cpuid, pri);

	rv = idn_link(idnop->link.domid, idnop->link.cpuid,
	    pri, idnop->link.wait, &err);

	return (rv);
}

static int
idnioc_unlink(idnop_t *idnop)
{
	int		d, cpuid, domid, rv;
	boardset_t	idnset;
	idn_fin_t	fintype;
	idn_domain_t	*dp, *xdp;
	idnsb_error_t	err;
	procname_t	proc = "idnioc_unlink";

	PR_DRV("%s: domid = %d, cpuid = %d, force = %d\n",
	    proc, idnop->unlink.domid, idnop->unlink.cpuid,
	    idnop->unlink.force);

	idnset = BOARDSET_ALL;
	domid = idnop->unlink.domid;
	cpuid = idnop->unlink.cpuid;
	dp = NULL;

	if (domid == IDN_NIL_DOMID)
		domid = idn.localid;

	if (VALID_DOMAINID(domid)) {
		dp = &idn_domain[domid];
		if (VALID_CPUID(cpuid) && (dp->dcpu != IDN_NIL_DCPU) &&
		    !CPU_IN_SET(dp->dcpuset, cpuid)) {
			dp = NULL;
			PR_PROTO("%s: ERROR: invalid cpuid "
			    "(%d) for domain (%d) [cset = 0x%x.x%x]\n",
			    proc, cpuid, domid,
			    UPPER32_CPUMASK(dp->dcpuset),
			    LOWER32_CPUMASK(dp->dcpuset));
		}
	} else if (VALID_CPUID(cpuid)) {
		for (d = 0; d < MAX_DOMAINS; d++) {
			xdp = &idn_domain[d];

			if (xdp->dcpu == IDN_NIL_DCPU)
				continue;

			if (CPU_IN_SET(xdp->dcpuset, cpuid))
				break;
		}
		dp = (d == MAX_DOMAINS) ? NULL : xdp;
	}

	if ((dp == NULL) || (dp->dcpu == IDN_NIL_DCPU))
		return (0);

	domid = dp->domid;

	switch (idnop->unlink.force) {
	case SSIFORCE_OFF:
		fintype = IDNFIN_NORMAL;
		break;

	case SSIFORCE_SOFT:
		fintype = IDNFIN_FORCE_SOFT;
		break;

	case SSIFORCE_HARD:
		fintype = IDNFIN_FORCE_HARD;
		break;
	default:
		PR_PROTO("%s: invalid force parameter \"%d\"",
		    proc, idnop->unlink.force);
		return (EINVAL);
	}

	rv = idn_unlink(domid, idnset, fintype, IDNFIN_OPT_UNLINK,
	    idnop->unlink.wait, &err);

	return (rv);
}

static int
idn_send_ping(idnop_t *idnop)
{
	int		domid = idnop->ping.domid;
	int		cpuid = idnop->ping.cpuid;
	int		ocpuid;
	idn_domain_t	*dp;
	idn_msgtype_t	mt;
	procname_t	proc = "idn_send_ping";

	if ((domid == IDN_NIL_DOMID) && (cpuid == IDN_NIL_DCPU)) {
		cmn_err(CE_WARN,
		    "IDN: %s: no valid domain ID or CPU ID given",
		    proc);
		return (EINVAL);
	}
	if (domid == IDN_NIL_DOMID)
		domid = MAX_DOMAINS - 1;

	dp = &idn_domain[domid];
	IDN_DLOCK_EXCL(domid);
	if ((dp->dcpu == IDN_NIL_DCPU) && (cpuid == IDN_NIL_DCPU)) {
		cmn_err(CE_WARN,
		    "IDN: %s: no valid target CPU specified",
		    proc);
		IDN_DUNLOCK(domid);
		return (EINVAL);
	}
	if (cpuid == IDN_NIL_DCPU)
		cpuid = dp->dcpu;

	ocpuid = dp->dcpu;
	dp->dcpu = cpuid;

	/*
	 * XXX - Need a special PING IDN command.
	 */
	mt.mt_mtype = IDNP_DATA | IDNP_ACK;
	mt.mt_atype = 0;

	(void) IDNXDC(domid, &mt, 0x100, 0x200, 0x300, 0x400);

	dp->dcpu = ocpuid;
	IDN_DUNLOCK(domid);

	return (0);
}

/*
 * ----------------------------------------------
 */
static void
idn_dopers_init()
{
	int		i;
	dop_waitlist_t	*dwl;

	if (idn.dopers)
		return;

	idn.dopers = GETSTRUCT(struct dopers, 1);

	bzero(idn.dopers, sizeof (struct dopers));

	dwl = &idn.dopers->_dop_wcache[0];
	for (i = 0; i < (IDNOP_CACHE_SIZE-1); i++)
		dwl[i].dw_next = &dwl[i+1];
	dwl[i].dw_next = NULL;

	idn.dopers->dop_freelist = &idn.dopers->_dop_wcache[0];
	idn.dopers->dop_waitcount = 0;
	idn.dopers->dop_domset = 0;
	idn.dopers->dop_waitlist = NULL;

	cv_init(&idn.dopers->dop_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&idn.dopers->dop_mutex, NULL, MUTEX_DEFAULT, NULL);
}

static void
idn_dopers_deinit()
{
	dop_waitlist_t	*dwl, *next_dwl;


	if (idn.dopers == NULL)
		return;

	for (dwl = idn.dopers->dop_waitlist; dwl; dwl = next_dwl) {
		next_dwl = dwl->dw_next;
		if (!IDNOP_IN_CACHE(dwl))
			FREESTRUCT(dwl, dop_waitlist_t, 1);
	}

	cv_destroy(&idn.dopers->dop_cv);
	mutex_destroy(&idn.dopers->dop_mutex);

	FREESTRUCT(idn.dopers, struct dopers, 1);
	idn.dopers = NULL;
}

/*
 * Reset the dop_errset field in preparation for an
 * IDN operation attempt.  This is only called from
 * idn_link() and idn_unlink().
 */
void *
idn_init_op(idn_opflag_t opflag, domainset_t domset, idnsb_error_t *sep)
{
	dop_waitlist_t	*dwl;
	/*
	 * Clear any outstanding error ops in preparation
	 * for an IDN (link/unlink) operation.
	 */
	mutex_enter(&idn.dopers->dop_mutex);
	if ((dwl = idn.dopers->dop_freelist) == NULL) {
		dwl = GETSTRUCT(dop_waitlist_t, 1);
	} else {
		idn.dopers->dop_freelist = dwl->dw_next;
		bzero(dwl, sizeof (*dwl));
	}
	dwl->dw_op = opflag;
	dwl->dw_reqset = domset;
	dwl->dw_idnerr = sep;
	dwl->dw_next = idn.dopers->dop_waitlist;

	idn.dopers->dop_waitlist = dwl;
	idn.dopers->dop_waitcount++;
	idn.dopers->dop_domset |= domset;
	mutex_exit(&idn.dopers->dop_mutex);

	return (dwl);
}

/*
 * Anybody waiting on a opflag operation for any one
 * of the domains in domset, needs to be updated to
 * additionally wait for new domains in domset.
 * This is used, for example, when needing to connect
 * to more domains than known at the time of the
 * original request.
 */
void
idn_add_op(idn_opflag_t opflag, domainset_t domset)
{
	dop_waitlist_t	*dwl;

	mutex_enter(&idn.dopers->dop_mutex);
	if ((idn.dopers->dop_waitcount == 0) ||
	    ((idn.dopers->dop_domset & domset) == 0)) {
		mutex_exit(&idn.dopers->dop_mutex);
		return;
	}
	for (dwl = idn.dopers->dop_waitlist; dwl; dwl = dwl->dw_next)
		if ((dwl->dw_op == opflag) && (dwl->dw_reqset & domset))
			dwl->dw_reqset |= domset;
	mutex_exit(&idn.dopers->dop_mutex);
}

/*
 * Mechanism to wakeup any potential users which may be waiting
 * for a link/unlink operation to complete.  If an error occurred
 * don't update dop_errset unless there was no previous error.
 */
void
idn_update_op(idn_opflag_t opflag, domainset_t domset, idnsb_error_t *sep)
{
	int		do_wakeup = 0;
	dop_waitlist_t	*dw;
	procname_t	proc = "idn_update_op";

	mutex_enter(&idn.dopers->dop_mutex);
	/*
	 * If there are no waiters, or nobody is waiting for
	 * the particular domainset in question, then
	 * just bail.
	 */
	if ((idn.dopers->dop_waitcount == 0) ||
	    ((idn.dopers->dop_domset & domset) == 0)) {
		mutex_exit(&idn.dopers->dop_mutex);
		PR_PROTO("%s: NO waiters exist (domset=0x%x)\n",
		    proc, domset);
		return;
	}

	for (dw = idn.dopers->dop_waitlist; dw; dw = dw->dw_next) {
		int		d;
		domainset_t	dset, rset;

		if ((dset = dw->dw_reqset & domset) == 0)
			continue;

		if (opflag == IDNOP_ERROR) {
			dw->dw_errset |= dset;
			if (sep) {
				for (d = 0; d < MAX_DOMAINS; d++) {
					if (!DOMAIN_IN_SET(dset, d))
						continue;

					dw->dw_errors[d] =
					    (short)GET_IDNKERR_ERRNO(sep);
				}
				bcopy(sep, dw->dw_idnerr, sizeof (*sep));
			}
		} else if (opflag == dw->dw_op) {
			dw->dw_domset |= dset;
		}

		/*
		 * Check if all the domains are spoken for that
		 * a particular waiter may have been waiting for.
		 * If there's at least one, we'll need to broadcast.
		 */
		rset = (dw->dw_errset | dw->dw_domset) & dw->dw_reqset;
		if (rset == dw->dw_reqset)
			do_wakeup++;
	}

	PR_PROTO("%s: found %d waiters ready for wakeup\n", proc, do_wakeup);

	if (do_wakeup > 0)
		cv_broadcast(&idn.dopers->dop_cv);

	mutex_exit(&idn.dopers->dop_mutex);
}

void
idn_deinit_op(void *cookie)
{
	domainset_t	domset;
	dop_waitlist_t	*hw, *tw;
	dop_waitlist_t	*dwl = (dop_waitlist_t *)cookie;

	mutex_enter(&idn.dopers->dop_mutex);

	ASSERT(idn.dopers->dop_waitlist);

	if (dwl == idn.dopers->dop_waitlist) {
		idn.dopers->dop_waitlist = dwl->dw_next;
		if (IDNOP_IN_CACHE(dwl)) {
			dwl->dw_next = idn.dopers->dop_freelist;
			idn.dopers->dop_freelist = dwl;
		} else {
			FREESTRUCT(dwl, dop_waitlist_t, 1);
		}
	} else {
		for (tw = idn.dopers->dop_waitlist, hw = tw->dw_next;
		    hw;
		    tw = hw, hw = hw->dw_next) {
			if (dwl == hw)
				break;
		}
		ASSERT(hw);

		tw->dw_next = hw->dw_next;
	}

	/*
	 * Recompute domainset for which waiters might be waiting.
	 * It's possible there may be other waiters waiting for
	 * the same domainset that the current waiter that's leaving
	 * may have been waiting for, so we can't simply delete
	 * the leaving waiter's domainset from dop_domset.
	 */
	for (hw = idn.dopers->dop_waitlist, domset = 0; hw; hw = hw->dw_next)
		domset |= hw->dw_reqset;

	idn.dopers->dop_waitcount--;
	idn.dopers->dop_domset = domset;

	mutex_exit(&idn.dopers->dop_mutex);
}

/*
 * Wait until the specified operation succeeds or fails with
 * respect to the given domains.  Note the function terminates
 * if at least one error occurs.
 * This process is necessary since link/unlink operations occur
 * asynchronously and we need some way of waiting to find out
 * if it indeed completed.
 * Timeout value is received indirectly from the SSP and
 * represents seconds.
 */
int
idn_wait_op(void *cookie, domainset_t *domsetp, int wait_timeout)
{
	int	d, rv, err = 0;
	dop_waitlist_t	*dwl;


	dwl = (dop_waitlist_t *)cookie;

	ASSERT(wait_timeout > 0);
	ASSERT((dwl->dw_op == IDNOP_CONNECTED) ||
	    (dwl->dw_op == IDNOP_DISCONNECTED));

	mutex_enter(&idn.dopers->dop_mutex);

	while (((dwl->dw_domset | dwl->dw_errset) != dwl->dw_reqset) && !err) {
		rv = cv_reltimedwait_sig(&idn.dopers->dop_cv,
		    &idn.dopers->dop_mutex, (wait_timeout * hz), TR_CLOCK_TICK);

		if ((dwl->dw_domset | dwl->dw_errset) == dwl->dw_reqset)
			break;

		switch (rv) {
		case -1:
			/*
			 * timed out
			 */
			cmn_err(CE_WARN,
			    "!IDN: 129: %s operation timed out",
			    (dwl->dw_op == IDNOP_CONNECTED) ? "LINK" :
			    (dwl->dw_op == IDNOP_DISCONNECTED) ? "UNLINK" :
			    "UNKNOWN");
			/*FALLTHROUGH*/
		case 0:
			/*
			 * signal, e.g. kill(2)
			 */
			err = 1;
			break;

		default:
			break;
		}
	}

	if (dwl->dw_domset == dwl->dw_reqset) {
		rv = 0;
	} else {
		/*
		 * Op failed for some domains or we were awakened.
		 */
		for (d = rv = 0; (d < MAX_DOMAINS) && !rv; d++)
			rv = dwl->dw_errors[d];
	}
	*domsetp = dwl->dw_domset;

	mutex_exit(&idn.dopers->dop_mutex);

	idn_deinit_op(cookie);

	return (rv);
}

/*
 * --------------------------------------------------
 * Return any valid (& ready) cpuid for the given board based on
 * the given cpuset.
 * --------------------------------------------------
 */
int
board_to_ready_cpu(int board, cpuset_t cpuset)
{
	int	base_cpuid;
	int	ncpu_board = MAX_CPU_PER_BRD;

	board *= ncpu_board;
	for (base_cpuid = board;
	    base_cpuid < (board + ncpu_board);
	    base_cpuid++)
		if (CPU_IN_SET(cpuset, base_cpuid))
			return (base_cpuid);

	return (-1);
}

void
idn_domain_resetentry(idn_domain_t *dp)
{
	register int		i;
	procname_t	proc = "idn_domain_resetentry";

	ASSERT(dp);
	ASSERT(dp->dstate == IDNDS_CLOSED);
	ASSERT(IDN_DLOCK_IS_EXCL(dp->domid));
	ASSERT(IDN_GLOCK_IS_EXCL());

	ASSERT(dp->domid == (dp - &idn_domain[0]));

	IDN_FSTATE_TRANSITION(dp, IDNFIN_OFF);
	dp->dname[0]	= '\0';
	dp->dnetid	= (ushort_t)-1;
	dp->dmtu	= 0;
	dp->dbufsize	= 0;
	dp->dslabsize	= 0;
	dp->dnwrsize	= 0;
	dp->dncpus	= 0;
	dp->dcpuindex   = 0;
	CPUSET_ZERO(dp->dcpuset);
	dp->dcpu	= dp->dcpu_last = dp->dcpu_save = IDN_NIL_DCPU;
	dp->dvote.ticket = 0;
	dp->dslab	= NULL;
	dp->dslab_state = DSLAB_STATE_UNKNOWN;
	dp->dnslabs	= 0;
	dp->dio		= 0;
	dp->dioerr	= 0;
	lock_clear(&dp->diowanted);
	bzero(&dp->dhw, sizeof (dp->dhw));
	dp->dxp		= NULL;
	IDN_XSTATE_TRANSITION(dp, IDNXS_NIL);
	dp->dsync.s_cmd = IDNSYNC_NIL;
	dp->dfin_sync   = IDNFIN_SYNC_OFF;
	IDN_RESET_COOKIES(dp->domid);
	dp->dcookie_err = 0;
	bzero(&dp->dawol, sizeof (dp->dawol));
	dp->dtmp = -1;

	if (dp->dtimerq.tq_queue != NULL) {
		PR_PROTO("%s: WARNING: MSG timerq not empty (count = %d)\n",
		    proc, dp->dtimerq.tq_count);
		IDN_MSGTIMER_STOP(dp->domid, 0, 0);
	}

	for (i = 0; i < NCPU; i++)
		dp->dcpumap[i] = (uchar_t)-1;
}

int
idn_open_domain(int domid, int cpuid, uint_t ticket)
{
	int		c, new_cpuid;
	idn_domain_t	*dp, *ldp;
	procname_t	proc = "idn_open_domain";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	if (!VALID_DOMAINID(domid)) {
		PR_PROTO("%s: INVALID domainid (%d) "
		    "[cpuid = %d, ticket = 0x%x]\n",
		    proc, domid, cpuid, ticket);
		return (-1);
	}

	dp = &idn_domain[domid];
	ldp = &idn_domain[idn.localid];

	if (dp->dcpu >= 0) {
		PR_PROTO("%s:%d: domain already OPEN (state = %s)\n",
		    proc, domid, idnds_str[dp->dstate]);
		return (1);
	}

	if (DOMAIN_IN_SET(idn.domset.ds_relink, domid)) {
		if (dp->dcpu_save == IDN_NIL_DCPU)
			new_cpuid = cpuid;
		else
			new_cpuid = dp->dcpu_save;
	} else {
		new_cpuid = cpuid;
	}

	if (new_cpuid == IDN_NIL_DCPU) {
		PR_PROTO("%s:%d: WARNING: invalid cpuid (%d) specified\n",
		    proc, domid, new_cpuid);
		return (-1);
	}

	IDN_GLOCK_EXCL();

	idn_domain_resetentry(dp);

	PR_STATE("%s:%d: requested cpuid %d, assigning cpuid %d\n",
	    proc, domid, cpuid, new_cpuid);

	idn_assign_cookie(domid);

	dp->dcpu = dp->dcpu_save = new_cpuid;
	dp->dvote.ticket = ticket;
	CPUSET_ADD(dp->dcpuset, new_cpuid);
	dp->dncpus = 1;
	for (c = 0; c < NCPU; c++)
		dp->dcpumap[c] = (uchar_t)new_cpuid;
	dp->dhw.dh_nboards = 1;
	dp->dhw.dh_boardset = BOARDSET(CPUID_TO_BOARDID(new_cpuid));

	if (domid != idn.localid)
		IDN_DLOCK_EXCL(idn.localid);

	if (idn.ndomains == 1) {
		struct hwconfig	local_hw;

		/*
		 * We're attempting to connect to our first domain.
		 * Recheck our local hardware configuration before
		 * we go any further in case it changed due to a DR,
		 * and update any structs dependent on this.
		 * ASSUMPTION:
		 *	IDN is unlinked before performing any DRs.
		 */
		PR_PROTO("%s: RECHECKING local HW config.\n", proc);
		if (get_hw_config(&local_hw)) {
			dp->dcpu = IDN_NIL_DCPU;
			cmn_err(CE_WARN,
			    "IDN: 118: hardware config not appropriate");
			if (domid != idn.localid)
				IDN_DUNLOCK(idn.localid);
			IDN_GUNLOCK();
			return (-1);
		}
		(void) update_local_hw_config(ldp, &local_hw);
	}

	idn.ndomains++;

	if (domid != idn.localid)
		IDN_DUNLOCK(idn.localid);
	IDN_GUNLOCK();

	IDN_MBOX_LOCK(domid);
	dp->dmbox.m_tbl = NULL;

	if (domid != idn.localid) {
		dp->dmbox.m_send = idn_mainmbox_init(domid,
		    IDNMMBOX_TYPE_SEND);
		dp->dmbox.m_recv = idn_mainmbox_init(domid,
		    IDNMMBOX_TYPE_RECV);
	} else {
		/*
		 * The local domain does not need send/recv
		 * mailboxes in its idn_domain[] entry.
		 */
		dp->dmbox.m_send = NULL;
		dp->dmbox.m_recv = NULL;
	}
	IDN_MBOX_UNLOCK(domid);

	PR_PROTO("%s:%d: new domain (cpu = %d, vote = 0x%x)\n",
	    proc, domid, dp->dcpu, dp->dvote.ticket);

	return (0);
}

/*
 * The local domain never "closes" itself unless the driver
 * is doing a idndetach.  It will be reopened during idnattach
 * when idn_domains_init is called.
 */
void
idn_close_domain(int domid)
{
	uint_t		token;
	idn_domain_t	*dp;
	procname_t	proc = "idn_close_domain";

	ASSERT(IDN_SYNC_IS_LOCKED());
	ASSERT(IDN_DLOCK_IS_EXCL(domid));

	dp = &idn_domain[domid];

	ASSERT(dp->dstate == IDNDS_CLOSED);

	if (dp->dcpu == IDN_NIL_DCPU) {
		PR_PROTO("%s:%d: DOMAIN ALREADY CLOSED!\n",
		    proc, domid);
		return;
	}

	token = IDN_RETRY_TOKEN(domid, IDN_RETRY_TYPEALL);

	(void) idn_retry_terminate(token);

	DOMAINSET_DEL(idn.domset.ds_trans_on, domid);
	DOMAINSET_DEL(idn.domset.ds_ready_on, domid);
	DOMAINSET_DEL(idn.domset.ds_connected, domid);
	DOMAINSET_DEL(idn.domset.ds_trans_off, domid);
	DOMAINSET_DEL(idn.domset.ds_ready_off, domid);
	DOMAINSET_DEL(idn.domset.ds_hwlinked, domid);
	DOMAINSET_DEL(idn.domset.ds_flush, domid);

	idn_sync_exit(domid, IDNSYNC_CONNECT);
	idn_sync_exit(domid, IDNSYNC_DISCONNECT);

	IDN_GLOCK_EXCL();

	if (DOMAIN_IN_SET(idn.domset.ds_awol, domid))
		idn_clear_awol(domid);

	idn.ndomains--;

	IDN_GUNLOCK();

	IDN_MBOX_LOCK(domid);
	dp->dmbox.m_tbl = NULL;

	if (dp->dmbox.m_send)  {
		idn_mainmbox_deinit(domid, dp->dmbox.m_send);
		dp->dmbox.m_send = NULL;
	}

	if (dp->dmbox.m_recv) {
		idn_mainmbox_deinit(domid, dp->dmbox.m_recv);
		dp->dmbox.m_recv = NULL;
	}

	IDN_MBOX_UNLOCK(domid);

	cmn_err(CE_NOTE,
	    "!IDN: 142: link (domain %d, CPU %d) disconnected",
	    dp->domid, dp->dcpu);

	dp->dcpu = IDN_NIL_DCPU;	/* ultimate demise */

	IDN_RESET_COOKIES(domid);

	ASSERT(dp->dio <= 0);
	ASSERT(dp->dioerr == 0);
	ASSERT(dp->dslab == NULL);
	ASSERT(dp->dnslabs == 0);

	IDN_GKSTAT_GLOBAL_EVENT(gk_unlinks, gk_unlink_last);
}


/*
 * -----------------------------------------------------------------------
 */
static void
idn_domains_init(struct hwconfig *local_hw)
{
	register int		i, d;
	idn_domain_t		*ldp;
	uchar_t			*cpumap;

	ASSERT(local_hw != NULL);

	cpumap = GETSTRUCT(uchar_t, NCPU * MAX_DOMAINS);

	for (d = 0; d < MAX_DOMAINS; d++) {
		register idn_domain_t	*dp;

		dp = &idn_domain[d];

		dp->domid = d;

		rw_init(&dp->drwlock, NULL, RW_DEFAULT, NULL);

		IDN_TIMERQ_INIT(&dp->dtimerq);

		dp->dstate = IDNDS_CLOSED;

		mutex_init(&dp->dmbox.m_mutex, NULL, MUTEX_DEFAULT, NULL);

		dp->dcpumap = cpumap;

		rw_init(&dp->dslab_rwlock, NULL, RW_DEFAULT, NULL);

		IDN_DLOCK_EXCL(d);
		IDN_GLOCK_EXCL();

		idn_domain_resetentry(dp);

		IDN_GUNLOCK();

		IDNSB_DOMAIN_UPDATE(dp);

		IDN_DUNLOCK(d);

		cpumap += NCPU;
	}

	IDN_SYNC_LOCK();

	/*
	 * Update local domain information.
	 */
	ASSERT(idn.smr.locpfn);
	ASSERT(local_hw->dh_nboards && local_hw->dh_boardset);

	idn.ndomains = 0;	/* note that open_domain will get us to 1 */

	IDN_DLOCK_EXCL(idn.localid);
	d = idn_open_domain(idn.localid, (int)CPU->cpu_id, 0);
	ASSERT(d == 0);
	IDN_GLOCK_EXCL();
	IDN_SET_MASTERID(IDN_NIL_DOMID);
	IDN_SET_NEW_MASTERID(IDN_NIL_DOMID);

	ldp = &idn_domain[idn.localid];

	(void) strncpy(ldp->dname, utsname.nodename, MAXDNAME - 1);
	ldp->dname[MAXDNAME-1] = '\0';
	bcopy(local_hw, &ldp->dhw, sizeof (ldp->dhw));
	ASSERT(idn.ndomains == 1);
	ASSERT((ldp->dhw.dh_nboards > 0) &&
	    (ldp->dhw.dh_nboards <= MAX_BOARDS));
	ldp->dnetid	= IDN_DOMID2NETID(ldp->domid);
	ldp->dmtu	= IDN_MTU;
	ldp->dbufsize	= IDN_SMR_BUFSIZE;
	ldp->dslabsize	= (short)IDN_SLAB_BUFCOUNT;
	ldp->dnwrsize	= (short)IDN_NWR_SIZE;
	ldp->dcpuset	= cpu_ready_set;
	ldp->dncpus	= (short)ncpus;
	ldp->dvote.ticket	= IDNVOTE_INITIAL_TICKET;
	ldp->dvote.v.master	= 0;
	ldp->dvote.v.nmembrds	= ldp->dhw.dh_nmcadr - 1;
	ldp->dvote.v.ncpus	= (int)ldp->dncpus - 1;
	ldp->dvote.v.board	= CPUID_TO_BOARDID(ldp->dcpu);
	i = -1;
	for (d = 0; d < NCPU; d++) {
		BUMP_INDEX(ldp->dcpuset, i);
		ldp->dcpumap[d] = (uchar_t)i;
	}

	CPUSET_ZERO(idn.dc_cpuset);
	CPUSET_OR(idn.dc_cpuset, ldp->dcpuset);
	idn.dc_boardset = ldp->dhw.dh_boardset;

	/*
	 * Setting the state for ourselves is only relevant
	 * for loopback performance testing.  Anyway, it
	 * makes sense that we always have an established
	 * connection with ourself regardless of IDN :-o
	 */
	IDN_DSTATE_TRANSITION(ldp, IDNDS_CONNECTED);

	IDN_GUNLOCK();
	IDN_DUNLOCK(idn.localid);
	IDN_SYNC_UNLOCK();
}

static void
idn_domains_deinit()
{
	register int	d;

	IDN_SYNC_LOCK();
	IDN_DLOCK_EXCL(idn.localid);
	IDN_DSTATE_TRANSITION(&idn_domain[idn.localid], IDNDS_CLOSED);
	idn_close_domain(idn.localid);
	IDN_DUNLOCK(idn.localid);
	IDN_SYNC_UNLOCK();
	idn.localid = IDN_NIL_DOMID;

	FREESTRUCT(idn_domain[0].dcpumap, uchar_t, NCPU * MAX_DOMAINS);

	for (d = 0; d < MAX_DOMAINS; d++) {
		idn_domain_t	*dp;

		dp = &idn_domain[d];

		rw_destroy(&dp->dslab_rwlock);
		mutex_destroy(&dp->dmbox.m_mutex);
		rw_destroy(&dp->drwlock);
		IDN_TIMERQ_DEINIT(&dp->dtimerq);
		dp->dcpumap = NULL;
	}
}

/*
 * -----------------------------------------------------------------------
 */
static void
idn_retrytask_init()
{
	ASSERT(idn.retryqueue.rq_cache == NULL);

	mutex_init(&idn.retryqueue.rq_mutex, NULL, MUTEX_DEFAULT, NULL);
	idn.retryqueue.rq_cache = kmem_cache_create("idn_retryjob_cache",
	    sizeof (idn_retry_job_t),
	    0, NULL, NULL, NULL,
	    NULL, NULL, 0);
}

static void
idn_retrytask_deinit()
{
	if (idn.retryqueue.rq_cache == NULL)
		return;

	kmem_cache_destroy(idn.retryqueue.rq_cache);
	mutex_destroy(&idn.retryqueue.rq_mutex);

	bzero(&idn.retryqueue, sizeof (idn.retryqueue));
}

/*
 * -----------------------------------------------------------------------
 */
static void
idn_timercache_init()
{
	ASSERT(idn.timer_cache == NULL);

	idn.timer_cache = kmem_cache_create("idn_timer_cache",
	    sizeof (idn_timer_t),
	    0, NULL, NULL, NULL,
	    NULL, NULL, 0);
}

static void
idn_timercache_deinit()
{
	if (idn.timer_cache == NULL)
		return;

	kmem_cache_destroy(idn.timer_cache);
	idn.timer_cache = NULL;
}

idn_timer_t *
idn_timer_alloc()
{
	idn_timer_t	*tp;

	tp = kmem_cache_alloc(idn.timer_cache, KM_SLEEP);
	bzero(tp, sizeof (*tp));
	tp->t_forw = tp->t_back = tp;

	return (tp);
}

void
idn_timer_free(idn_timer_t *tp)
{
	if (tp == NULL)
		return;
	kmem_cache_free(idn.timer_cache, tp);
}

void
idn_timerq_init(idn_timerq_t *tq)
{
	mutex_init(&tq->tq_mutex, NULL, MUTEX_DEFAULT, NULL);
	tq->tq_count = 0;
	tq->tq_queue = NULL;
}

void
idn_timerq_deinit(idn_timerq_t *tq)
{
	ASSERT(tq->tq_queue == NULL);
	mutex_destroy(&tq->tq_mutex);
}

/*
 * Dequeue all the timers of the given subtype from the
 * given timerQ.  If subtype is 0, then dequeue all the
 * timers.
 */
idn_timer_t *
idn_timer_get(idn_timerq_t *tq, int type, ushort_t tcookie)
{
	register idn_timer_t	*tp, *tphead;

	ASSERT(IDN_TIMERQ_IS_LOCKED(tq));

	if ((tp = tq->tq_queue) == NULL)
		return (NULL);

	if (!type) {
		tq->tq_queue = NULL;
		tq->tq_count = 0;
		tphead = tp;
	} else {
		int		count;
		idn_timer_t	*tpnext;

		tphead = NULL;
		count = tq->tq_count;
		do {
			tpnext = tp->t_forw;
			if ((tp->t_type == type) &&
			    (!tcookie || (tp->t_cookie == tcookie))) {
				tp->t_forw->t_back = tp->t_back;
				tp->t_back->t_forw = tp->t_forw;
				if (tphead == NULL) {
					tp->t_forw = tp->t_back = tp;
				} else {
					tp->t_forw = tphead;
					tp->t_back = tphead->t_back;
					tp->t_back->t_forw = tp;
					tphead->t_back = tp;
				}
				tphead = tp;
				if (--(tq->tq_count) == 0)
					tq->tq_queue = NULL;
				else if (tq->tq_queue == tp)
					tq->tq_queue = tpnext;
			}
			tp = tpnext;
		} while (--count > 0);
	}

	if (tphead) {
		tphead->t_back->t_forw = NULL;

		for (tp = tphead; tp; tp = tp->t_forw)
			tp->t_onq = 0;
	}

	return (tphead);
}

ushort_t
idn_timer_start(idn_timerq_t *tq, idn_timer_t *tp, clock_t tval)
{
	idn_timer_t	*otp;
	ushort_t	tcookie;
	procname_t	proc = "idn_timer_start";
	STRING(str);

	ASSERT(tq && tp && (tval > 0));
	ASSERT((tp->t_forw == tp) && (tp->t_back == tp));
	ASSERT(tp->t_type != 0);

	IDN_TIMERQ_LOCK(tq);
	/*
	 * Assign a unique non-zero 8-bit cookie to this timer
	 * if the caller hasn't already preassigned one.
	 */
	while ((tcookie = tp->t_cookie) == 0) {
		tp->t_cookie = (tp->t_type & 0xf) |
		    ((++tq->tq_cookie & 0xf) << 4);
		/*
		 * Calculated cookie must never conflict
		 * with the public timer cookie.
		 */
		ASSERT(tp->t_cookie != IDN_TIMER_PUBLIC_COOKIE);
	}

	/*
	 * First have to remove old timers of the
	 * same type and cookie, and get rid of them.
	 */
	otp = idn_timer_get(tq, tp->t_type, tcookie);

	tq->tq_count++;

	if (tq->tq_queue == NULL) {
		tq->tq_queue = tp;
		ASSERT((tp->t_forw == tp) && (tp->t_back == tp));
	} else {
		/*
		 * Put me at the end of the list.
		 */
		tp->t_forw = tq->tq_queue;
		tp->t_back = tq->tq_queue->t_back;
		tp->t_back->t_forw = tp;
		tp->t_forw->t_back = tp;
	}

	tp->t_onq = 1;
	tp->t_q = tq;
	tp->t_id = timeout(idn_timer_expired, (caddr_t)tp, tval);


	INUM2STR(tp->t_type, str);
	PR_TIMER("%s: started %s timer (domain = %d, cookie = 0x%x)\n",
	    proc, str, tp->t_domid, tcookie);

	IDN_TIMERQ_UNLOCK(tq);

	if (otp)
		(void) idn_timer_stopall(otp);

	return (tcookie);
}

/*
 * Stop all timers of the given subtype.
 * If subtype is 0, then stop all timers
 * in this timerQ.
 */
void
idn_timer_stop(idn_timerq_t *tq, int type, ushort_t tcookie)
{
	idn_timer_t	*tphead;
	procname_t	proc = "idn_timer_stop";
	STRING(str);

	ASSERT(tq);

	INUM2STR(type, str);

	IDN_TIMERQ_LOCK(tq);

	if (tq->tq_count == 0) {
		PR_TIMER("%s: found no %s timers (count=0)\n", proc, str);
		IDN_TIMERQ_UNLOCK(tq);
		return;
	}
	tphead = idn_timer_get(tq, type, tcookie);
#ifdef DEBUG
	if (tphead == NULL)
		PR_TIMER("%s: found no %s (cookie = 0x%x) "
		    "timers (count=%d)!!\n",
		    proc, str, tcookie, tq->tq_count);
#endif /* DEBUG */
	IDN_TIMERQ_UNLOCK(tq);

	if (tphead)
		(void) idn_timer_stopall(tphead);
}

int
idn_timer_stopall(idn_timer_t *tp)
{
	int		count = 0;
	int		nonactive;
	uint_t		type;
	idn_timer_t	*ntp;
	procname_t	proc = "idn_timer_stopall";
	STRING(str);

	nonactive = 0;

	if (tp) {
		/*
		 * Circle should have been broken.
		 */
		ASSERT(tp->t_back->t_forw == NULL);
		type = tp->t_type;
		INUM2STR(type, str);
	}

	for (; tp; tp = ntp) {
		ntp = tp->t_forw;
		count++;
		ASSERT(tp->t_id != (timeout_id_t)0);
		if (untimeout(tp->t_id) < 0) {
			nonactive++;
			PR_TIMER("%s: bad %s untimeout (domain=%d)\n",
			    proc, str, tp->t_domid);
		} else {
			PR_TIMER("%s: good %s untimeout (domain=%d)\n",
			    proc, str, tp->t_domid);
		}
		/*
		 * There are two possible outcomes from
		 * the untimeout().  Each ultimately result
		 * in us having to free the timeout structure.
		 *
		 * 1. We successfully aborted a timeout call.
		 *
		 * 2. We failed to find the given timer.  It
		 *    probably just fired off.
		 */
		idn_timer_free(tp);
	}
	PR_TIMER("%s: stopped %d of %d %s timers\n",
	    proc, count - nonactive, count, str);

	return (count);
}

void
idn_timer_dequeue(idn_timerq_t *tq, idn_timer_t *tp)
{
	ASSERT(tq && tp);
	ASSERT(IDN_TIMERQ_IS_LOCKED(tq));

	ASSERT(tp->t_q == tq);

	if (tp->t_onq == 0) {
		/*
		 * We've already been dequeued.
		 */
		ASSERT(tp == tp->t_forw);
		ASSERT(tp == tp->t_back);
	} else {
		/*
		 * We're still in the queue, get out.
		 */
		if (tq->tq_queue == tp)
			tq->tq_queue = tp->t_forw;
		tp->t_forw->t_back = tp->t_back;
		tp->t_back->t_forw = tp->t_forw;
		tp->t_onq = 0;
		if (--(tq->tq_count) == 0) {
			ASSERT(tq->tq_queue == tp);
			tq->tq_queue = NULL;
		}
		tp->t_forw = tp->t_back = tp;
	}
}

/*
 * -----------------------------------------------------------------------
 */
/*ARGSUSED*/
static int
idn_slabpool_report(queue_t *wq, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	register int	p, nfree;
	char		dsetstr[128];

	ASSERT(IDN_GLOCK_IS_HELD());

	if (idn.slabpool == NULL) {
		(void) mi_mpprintf(mp,
		    "IDN slabpool not initialized (masterid = %d)",
		    IDN_GET_MASTERID());
		return (0);
	}

	for (p = nfree = 0; p < idn.slabpool->npools; p++)
		nfree += idn.slabpool->pool[p].nfree;

	(void) mi_mpprintf(mp,
	    "IDN slabpool (ntotal_slabs = %d, nalloc = %d, "
	    "npools = %d)",
	    idn.slabpool->ntotslabs,
	    idn.slabpool->ntotslabs - nfree,
	    idn.slabpool->npools);

	(void) mi_mpprintf(mp, "pool  nslabs  nfree domains");

	for (p = 0; p < idn.slabpool->npools; p++) {
		register int	d, s;
		uint_t		domset;

		domset = 0;
		for (s = 0; s < idn.slabpool->pool[p].nslabs; s++) {
			short	dd;

			dd = idn.slabpool->pool[p].sarray[s].sl_domid;
			if (dd != (short)IDN_NIL_DOMID)
				DOMAINSET_ADD(domset, dd);
		}
		dsetstr[0] = '\0';
		if (domset) {
			for (d = 0; d < MAX_DOMAINS; d++) {
				if (!DOMAIN_IN_SET(domset, d))
					continue;

				if (dsetstr[0] == '\0')
					(void) sprintf(dsetstr, "%d", d);
				else
					(void) sprintf(dsetstr, "%s %d",
					    dsetstr, d);
			}
		}

		if (p < 10)
			(void) mi_mpprintf(mp, "  %d     %d       %d    %s",
			    p, idn.slabpool->pool[p].nslabs,
			    idn.slabpool->pool[p].nfree,
			    dsetstr);
		else
			(void) mi_mpprintf(mp, " %d     %d       %d    %s",
			    p, idn.slabpool->pool[p].nslabs,
			    idn.slabpool->pool[p].nfree,
			    dsetstr);
	}
	return (0);
}

/*ARGSUSED*/
static int
idn_buffer_report(queue_t *wq, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	smr_slab_t	*sp;
	register int	d, cnt;
	int		bufcount[MAX_DOMAINS];
	int		spl;

	ASSERT(IDN_GLOCK_IS_HELD());

	if (idn.localid == IDN_NIL_DOMID) {
		(void) mi_mpprintf(mp, "IDN not initialized (localid = %d)",
		    idn.localid);
		return (0);
	}

	(void) mi_mpprintf(mp, "Local domain has %d slabs allocated.",
	    idn_domain[idn.localid].dnslabs);

	DSLAB_LOCK_SHARED(idn.localid);
	if ((sp = idn_domain[idn.localid].dslab) == NULL) {
		DSLAB_UNLOCK(idn.localid);
		return (0);
	}

	bzero(bufcount, sizeof (bufcount));
	cnt = 0;

	spl = splhi();
	for (; sp; sp = sp->sl_next) {
		smr_slabbuf_t	*bp;

		while (!lock_try(&sp->sl_lock))
			;
		for (bp = sp->sl_inuse; bp; bp = bp->sb_next) {
			bufcount[bp->sb_domid]++;
			cnt++;
		}
		lock_clear(&sp->sl_lock);
	}
	splx(spl);

	DSLAB_UNLOCK(idn.localid);

	(void) mi_mpprintf(mp, "Local domain has %d buffers outstanding.", cnt);
	if (cnt == 0)
		return (0);

	(void) mi_mpprintf(mp, "Domain  nbufs");
	for (d = 0; d < MAX_DOMAINS; d++)
		if (bufcount[d]) {
			if (d < 10)
				(void) mi_mpprintf(mp, "   %d      %d",
				    d, bufcount[d]);
			else
				(void) mi_mpprintf(mp, "  %d      %d",
				    d, bufcount[d]);
		}

	return (0);
}

static const char *
_get_spaces(int w, int s, int W)
{
	static const char *const _spaces[] = {
		"",			/* 0 */
		" ",			/* 1 */
		"  ", 			/* 2 */
		"   ", 			/* 3 */
		"    ", 		/* 4 */
		"     ", 		/* 5 */
		"      ", 		/* 6 */
		"       ", 		/* 7 */
		"        ", 		/* 8 */
		"         ", 		/* 9 */
		"          ", 		/* 10 */
		"           ", 		/* 11 */
		"            ", 	/* 12 */
		"             ", 	/* 13 */
		"              ", 	/* 14 */
		"               ", 	/* 15 */
		"                ", 	/* 16 */
		"                 ", 	/* 17 */
		"                  ", 	/* 18 */
		"                   ", 	/* 19 */
	};
	return (_spaces[w+s-W]);
}

#define	_SSS(X, W, w, s) \
	(((w) >= (W)) && (X)) ? _get_spaces((w), (s), (W))

static const char *
_hexspace(uint64_t v, int sz, int width, int padding)
{
	int	maxnbl = 16;
	int	diff;
	uchar_t	*np;

	diff = sizeof (uint64_t) - sz;
	np = (uchar_t *)&v + diff;
	maxnbl -= diff << 1;
	while (sz-- > 0) {
		if ((*np & 0xf0) && (width >= maxnbl))
			return (_get_spaces(width, padding, maxnbl));
		maxnbl--;
		if ((*np & 0x0f) && (width >= maxnbl))
			return (_get_spaces(width, padding, maxnbl));
		maxnbl--;
		np++;
	}
	return (_get_spaces(width, padding, 1));
}

#define	HEXSPACE(v, t, w, s)	_hexspace((uint64_t)(v), sizeof (t), (w), (s))

#define	DECSPACE(n, w, s) \
	(_SSS((uint_t)(n) >= 10000000, 8, (w), (s)) : \
	_SSS((uint_t)(n) >= 1000000, 7, (w), (s)) : \
	_SSS((uint_t)(n) >= 100000, 6, (w), (s)) : \
	_SSS((uint_t)(n) >= 10000, 5, (w), (s)) : \
	_SSS((uint_t)(n) >= 1000, 4, (w), (s)) : \
	_SSS((uint_t)(n) >= 100, 3, (w), (s)) : \
	_SSS((uint_t)(n) >= 10, 2, (w), (s)) : \
	_get_spaces((w), (s), 1))

#define	DECSPACE16(n, w, s) \
	(_SSS((n) >= 10000, 5, (w), (s)) : \
	_SSS((n) >= 1000, 4, (w), (s)) : \
	_SSS((n) >= 100, 3, (w), (s)) : \
	_SSS((n) >= 10, 2, (w), (s)) : \
	_get_spaces((w), (s), 1))

#define	MBXINFO(mtp) \
	(void *)&mtp->mt_header, \
		HEXSPACE(&mtp->mt_header, &mtp->mt_header, 16, 2), \
	mtp->mt_header.mh_svr_ready_ptr, \
		HEXSPACE(mtp->mt_header.mh_svr_ready_ptr, \
			mtp->mt_header.mh_svr_ready_ptr, 8, 1), \
	mtp->mt_header.mh_svr_active_ptr, \
		HEXSPACE(mtp->mt_header.mh_svr_active_ptr, \
			mtp->mt_header.mh_svr_active_ptr, 8, 2), \
	*(ushort_t *)(IDN_OFFSET2ADDR(mtp->mt_header.mh_svr_ready_ptr)), \
	DECSPACE16(*(ushort_t *) \
			(IDN_OFFSET2ADDR(mtp->mt_header.mh_svr_ready_ptr)), \
			1, 1), \
	*(ushort_t *)(IDN_OFFSET2ADDR(mtp->mt_header.mh_svr_active_ptr)), \
	DECSPACE16(*(ushort_t *) \
			(IDN_OFFSET2ADDR(mtp->mt_header.mh_svr_active_ptr)), \
			1, 5), \
	mtp->mt_header.mh_cookie, \
		HEXSPACE(mtp->mt_header.mh_cookie, \
			mtp->mt_header.mh_cookie, 8, 2), \
	(void *)&mtp->mt_queue[0], \
		HEXSPACE(&mtp->mt_queue[0], &mtp->mt_queue[0], 16, 2)

/*ARGSUSED*/
static int
idn_mboxtbl_report(queue_t *wq, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	register int		c, n, domid, subdomid;
	register idn_mboxtbl_t	*mtp;
	register idn_mboxmsg_t	*msp;
	idn_mboxtbl_t		*map, *mtbasep;


	ASSERT((cp == MBXTBL_PART_REPORT) || (cp == MBXTBL_FULL_REPORT));

	if (IDN_GLOCK_TRY_SHARED() == 0) {
		(void) mi_mpprintf(mp, "Local domain busy, try again.");
		return (0);
	}

	if ((map = idn.mboxarea) == NULL) {
		(void) mi_mpprintf(mp,
		    "WARNING: Local domain is not master, "
		    "ASSUMING idn.smr.vaddr.");
		map = (idn_mboxtbl_t *)idn.smr.vaddr;
	}

	if (map) {
		(void) mi_mpprintf(mp, "Mailbox Area starts @ 0x%p",
		    (void *)map);
	} else {
		(void) mi_mpprintf(mp, "Mailbox Area not found.");
		goto repdone;
	}

	if (!idn.nchannels) {
		(void) mi_mpprintf(mp, "No OPEN channels found");
		goto repdone;
	}

	for (c = 0; c < IDN_MAX_NETS; c++) {

		IDN_CHAN_LOCK_GLOBAL(&idn.chan_servers[c]);
		if (!IDN_CHANNEL_IS_ATTACHED(&idn.chan_servers[c])) {
			IDN_CHAN_UNLOCK_GLOBAL(&idn.chan_servers[c]);
			continue;
		}

		(void) mi_mpprintf(mp,
		    "Channel %d ---------------------------"
		    "--------------------------"
		    "-----------------------------", c);
		(void) mi_mpprintf(mp,
		    "  Domain   Header	    "
		    "Ready/Active Ptrs    "
		    "rdy/actv  cookie    Queue	     "
		    "busy");

		for (domid = 0; domid < MAX_DOMAINS; domid++) {
			register int	busy_count;

			if ((cp == MBXTBL_PART_REPORT) &&
			    (idn_domain[domid].dcpu == IDN_NIL_DCPU))
				continue;

			mtbasep = IDN_MBOXAREA_BASE(map, domid);

			for (subdomid = 0; subdomid < MAX_DOMAINS;
			    subdomid++) {
				mtp = IDN_MBOXTBL_PTR(mtbasep, subdomid);
				mtp = IDN_MBOXTBL_PTR_CHAN(mtp, c);

				if (subdomid == domid) {
					if (subdomid == 0)
						(void) mi_mpprintf(mp,
						    "   %x.%x-%d%s%s",
						    domid, subdomid, c,
							/*CONSTCOND*/
						    DECSPACE(c, 2, 2),
						    "-- unused --");
					else
						(void) mi_mpprintf(mp,
						    "    .%x-%d%s%s",
						    subdomid, c,
							/*CONSTCOND*/
						    DECSPACE(c, 2, 2),
						    "-- unused --");
					continue;
				}
				busy_count = 0;
				msp = &mtp->mt_queue[0];
				for (n = 0; n < IDN_MMBOX_NUMENTRIES; n++) {
					if (msp[n].ms_owner)
						busy_count++;
				}
				if (subdomid == 0) {
					(void) mi_mpprintf(mp,
					    "   %x.%x-%d%s%p%s%x%s/ %x%s"
					    "%d%s/ %d%s%x%s%p%s%d%s",
					    domid, subdomid, c,
						/*CONSTCOND*/
					    DECSPACE(c, 2, 2),
					    MBXINFO(mtp), busy_count,
					    busy_count ? " <<<<<":"");
				} else {
					(void) mi_mpprintf(mp,
					    "    .%x-%d%s%p%s%x%s/ %x%s"
					    "%d%s/ %d%s%x%s%p%s%d%s",
					    subdomid, c,
						/*CONSTCOND*/
					    DECSPACE(c, 2, 2),
					    MBXINFO(mtp), busy_count,
					    busy_count ? " <<<<<":"");
				}
			}
		}
		IDN_CHAN_UNLOCK_GLOBAL(&idn.chan_servers[c]);
	}

repdone:
	IDN_GUNLOCK();

	return (0);
}

/*ARGSUSED*/
static void
idn_mainmbox_domain_report(queue_t *wq, mblk_t *mp, int domid,
					idn_mainmbox_t *mmp, char *mbxtype)
{
	register int	c;

	if (mmp == NULL) {
		(void) mi_mpprintf(mp, " %x.%s  -- none --", domid, mbxtype);
		return;
	}

	for (c = 0; c < IDN_MAX_NETS; mmp++, c++) {
		int	mm_count;

		IDN_CHAN_LOCK_GLOBAL(&idn.chan_servers[c]);
		if (IDN_CHANNEL_IS_DETACHED(&idn.chan_servers[c])) {
			(void) mi_mpprintf(mp, " %x.%s  %u  -- not open --",
			    domid, mbxtype, (int)mmp->mm_channel);
			IDN_CHAN_UNLOCK_GLOBAL(&idn.chan_servers[c]);
			continue;
		}

		mm_count = ((mmp->mm_count < 0) ? 0 : mmp->mm_count) / 1000;

		(void) mi_mpprintf(mp, " %x.%s  %d%s%d%s%d%s%p%s%p%s%p%s%d/%d",
		    domid, mbxtype,
		    (int)mmp->mm_channel,
					/*CONSTCOND*/
		    DECSPACE((int)mmp->mm_channel, 5, 2),
		    mm_count, DECSPACE(mm_count, 8, 2),
		    mmp->mm_dropped,
		    DECSPACE(mmp->mm_dropped, 8, 2),
		    (void *)mmp->mm_smr_mboxp,
		    HEXSPACE(mmp->mm_smr_mboxp,
		    mmp->mm_smr_mboxp, 16, 2),
		    (void *)mmp->mm_smr_readyp,
		    HEXSPACE(mmp->mm_smr_readyp,
		    mmp->mm_smr_readyp, 16, 2),
		    (void *)mmp->mm_smr_activep,
		    HEXSPACE(mmp->mm_smr_activep,
		    mmp->mm_smr_activep, 16, 2),
		    mmp->mm_qiget, mmp->mm_qiput);
		IDN_CHAN_UNLOCK_GLOBAL(&idn.chan_servers[c]);
	}
}

/*ARGSUSED2*/
static int
idn_mainmbox_report(queue_t *wq, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	int	domid;
	int	header = 0;

	/*
	 * Domain 0 never has a send/recv mainmbox so
	 * don't bother printing it.
	 */
	for (domid = 1; domid < MAX_DOMAINS; domid++) {
		idn_domain_t	*dp;

		dp = &idn_domain[domid];

		if (dp->dcpu == IDN_NIL_DCPU)
			continue;
		IDN_DLOCK_SHARED(domid);
		if (dp->dcpu == IDN_NIL_DCPU) {
			IDN_DUNLOCK(domid);
			continue;
		}
		if (!header) {
			(void) mi_mpprintf(mp,
			    "Domain  Chan   PktCntK   "
			    "PktDrop   SMRMbox	   "
			    "ReadyPtr	  "
			    "ActvPtr	  Miget/Miput");
			header = 1;
		}

		mutex_enter(&dp->dmbox.m_mutex);
		idn_mainmbox_domain_report(wq, mp, domid,
		    idn_domain[domid].dmbox.m_send,
		    "snd");
		idn_mainmbox_domain_report(wq, mp, domid,
		    idn_domain[domid].dmbox.m_recv,
		    "rcv");
		mutex_exit(&dp->dmbox.m_mutex);

		IDN_DUNLOCK(domid);

		(void) mi_mpprintf(mp,
		    "  ---------------------------------------"
		    "------------------------"
		    "----------------------------");
	}

	if (!header)
		(void) mi_mpprintf(mp, "No ACTIVE domain connections exist");

	return (0);
}

/*ARGSUSED*/
static int
idn_global_report(queue_t *wq, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	int		i, nactive, masterid, nretry;
	uint_t		locpfn_upper, locpfn_lower,
	    rempfn_upper, rempfn_lower;
	uint_t		marea_upper, marea_lower,
	    iarea_upper, iarea_lower;
	char		alt_dbuffer[64];
	idn_retry_job_t	*rp;
	domainset_t	retryset;
	domainset_t	connected;
	idn_synczone_t	*zp;
	idn_syncop_t	*sp;
	idn_domain_t	*dp;
	char		*dbp, *dbuffer;

	if (IDN_SYNC_TRYLOCK() == 0) {
		(void) mi_mpprintf(mp, "Sync lock busy, try again.");
		return (0);
	}

	if (IDN_GLOCK_TRY_SHARED() == 0) {
		(void) mi_mpprintf(mp, "Local domain busy, try again.");
		IDN_SYNC_UNLOCK();
		return (0);
	}
	if ((dbp = dbuffer = ALLOC_DISPSTRING()) == NULL)
		dbp = alt_dbuffer;

	(void) mi_mpprintf(mp, "IDN\n    Global State = %s (%d)",
	    idngs_str[idn.state], idn.state);

	(void) mi_mpprintf(mp, "SMR");
	(void) mi_mpprintf(mp, "    vaddr                ");
	(void) mi_mpprintf(mp, "    0x%p", (void *)idn.smr.vaddr);

	(void) mi_mpprintf(mp, "    paddr-local     paddr-remote");
	masterid = IDN_GET_MASTERID();
	locpfn_upper = (uint_t)(idn.smr.locpfn >> (32 - PAGESHIFT));
	locpfn_lower = (uint_t)(idn.smr.locpfn << PAGESHIFT);
	if (idn.smr.rempfn == PFN_INVALID) {
		rempfn_upper = rempfn_lower = 0;
	} else {
		rempfn_upper = (uint_t)(idn.smr.rempfn >> (32 - PAGESHIFT));
		rempfn_lower = (uint_t)(idn.smr.rempfn << PAGESHIFT);
	}
	(void) mi_mpprintf(mp, "    0x%x.%x%s0x%x.%x",
	    locpfn_upper, locpfn_lower,
	    HEXSPACE(locpfn_lower, locpfn_lower, 8,
	    (locpfn_upper < 0x10) ? 4 : 3),
	    rempfn_upper, rempfn_lower);

	(void) mi_mpprintf(mp, "    SMR length  = %d MBytes", IDN_SMR_SIZE);
	(void) mi_mpprintf(mp, "    SMR bufsize = %d Bytes", IDN_SMR_BUFSIZE);
	(void) mi_mpprintf(mp, "    NWR length  = %d MBytes", IDN_NWR_SIZE);
	marea_upper = (uint_t)((uint64_t)IDN_MBOXAREA_SIZE >> 32);
	marea_lower = (uint_t)((uint64_t)IDN_MBOXAREA_SIZE & 0xffffffff);
	iarea_upper = (uint_t)((uint64_t)(MB2B(IDN_NWR_SIZE) -
	    (size_t)IDN_MBOXAREA_SIZE) >> 32);
	iarea_lower = (uint_t)((MB2B(IDN_NWR_SIZE) -
	    (size_t)IDN_MBOXAREA_SIZE) & 0xffffffff);
	(void) mi_mpprintf(mp,
	    "    [ mbox area = 0x%x.%x Bytes, "
	    "iobuf area = 0x%x.%x Bytes ]",
	    marea_upper, marea_lower, iarea_upper, iarea_lower);

	(void) mi_mpprintf(mp,
	    "\nIDNnet (local domain [id:%d] [name:%s] is %s)",
	    idn.localid,
	    idn_domain[idn.localid].dname,
	    (masterid == IDN_NIL_DOMID) ? "IDLE" :
	    (idn.localid == masterid) ? "MASTER" :
	    "SLAVE");
	nactive = 0;
	for (i = 0; i < IDN_MAX_NETS; i++) {
		IDN_CHAN_LOCK_GLOBAL(&idn.chan_servers[i]);
		if (IDN_CHANNEL_IS_ACTIVE(&idn.chan_servers[i]))
			nactive++;
		IDN_CHAN_UNLOCK_GLOBAL(&idn.chan_servers[i]);
	}
	(void) mi_mpprintf(mp, "    I/O Networks: (Open = %d, "
	    "Active = %d, Max = %d)",
	    idn.nchannels, nactive, IDN_MAX_NETS);
	(void) mi_mpprintf(mp, "    Number of Domains  = %d", idn.ndomains);
	(void) mi_mpprintf(mp, "    Number of AWOLs    = %d", idn.nawols);
	/*
	 * During connect domains can possibly be in ds_connected
	 * while still in ds_trans_on.  Only once they leave ds_trans_on
	 * are they really connected.
	 */
	connected = idn.domset.ds_connected & ~idn.domset.ds_trans_on;
	DOMAINSET_ADD(connected, idn.localid);
	boardset2str(connected, dbp);
	(void) mi_mpprintf(mp, "    Connected Domains      = %s", dbp);
	domainset2str(idn.domset.ds_trans_on, dbp);
	(void) mi_mpprintf(mp, "    Pending Domain Links   = %s",
	    idn.domset.ds_trans_on ? dbp : "<>");
	domainset2str(idn.domset.ds_trans_off, dbp);
	(void) mi_mpprintf(mp, "    Pending Domain Unlinks = %s",
	    idn.domset.ds_trans_off ? dbp : "<>");
	mutex_enter(&idn.retryqueue.rq_mutex);
	nretry = idn.retryqueue.rq_count;
	retryset = 0;
	for (i = 0, rp = idn.retryqueue.rq_jobs; i < nretry; i++,
	    rp = rp->rj_next) {
		int	domid;

		domid = IDN_RETRY_TOKEN2DOMID(rp->rj_token);
		if (VALID_DOMAINID(domid)) {
			DOMAINSET_ADD(retryset, domid);
		}
	}
	mutex_exit(&idn.retryqueue.rq_mutex);
	domainset2str(retryset, dbp);
	(void) mi_mpprintf(mp, "    Retry Jobs:Domains     = %d:%s",
	    nretry, retryset ? dbp : "<>");
	domainset2str(idn.domset.ds_hitlist, dbp);
	(void) mi_mpprintf(mp, "    Hitlist Domains        = %s",
	    idn.domset.ds_hitlist ? dbp : "<>");
	domainset2str(idn.domset.ds_relink, dbp);
	(void) mi_mpprintf(mp, "    Reconfig Domains       = %s",
	    idn.domset.ds_relink ? dbp : "<>");
	if (idn.domset.ds_relink)
		(void) mi_mpprintf(mp, "         new master id = %d",
		    IDN_GET_NEW_MASTERID());
	if (masterid == IDN_NIL_DOMID) {
		(void) mi_mpprintf(mp, "    Master Domain: no master");
	} else {
		idn_domain_t	*mdp;

		mdp = &idn_domain[masterid];

		(void) mi_mpprintf(mp,
		    "    Master Domain (id:name/brds - state):");

		if (strlen(mdp->dname) > 0)
			(void) strcpy(dbp, mdp->dname);
		else
			boardset2str(mdp->dhw.dh_boardset, dbp);
		if (masterid < 10)
			(void) mi_mpprintf(mp, "         %d: %s - %s",
			    masterid, dbp,
			    idnds_str[mdp->dstate]);
		else
			(void) mi_mpprintf(mp, "        %d: %s - %s",
			    masterid, dbp,
			    idnds_str[mdp->dstate]);
	}
	if (idn.ndomains <= 1) {
		(void) mi_mpprintf(mp, "    Slave Domains: none");
	} else {
		int	d;

		(void) mi_mpprintf(mp,
		    "    Slave Domains (id:name/brds - state):");
		for (d = 0; d < MAX_DOMAINS; d++) {
			dp = &idn_domain[d];

			if ((dp->dcpu == IDN_NIL_DCPU) || (d == masterid))
				continue;

			if (strlen(dp->dname) > 0)
				(void) strcpy(dbp, dp->dname);
			else
				boardset2str(dp->dhw.dh_boardset, dbp);
			if (d < 10)
				(void) mi_mpprintf(mp, "         %d: %s - %s",
				    d, dbp,
				    idnds_str[dp->dstate]);
			else
				(void) mi_mpprintf(mp, "        %d: %s - %s",
				    d, dbp,
				    idnds_str[dp->dstate]);
		}
	}

	if (idn.nawols == 0) {
		(void) mi_mpprintf(mp, "    AWOL Domains: none");
	} else {
		int	d;

		(void) mi_mpprintf(mp, "    AWOL Domains (id:name/brds):");
		for (d = 0; d < MAX_DOMAINS; d++) {
			dp = &idn_domain[d];

			if (!DOMAIN_IN_SET(idn.domset.ds_awol, d) ||
			    (dp->dcpu == IDN_NIL_DCPU))
				continue;

			if (strlen(dp->dname) > 0)
				(void) strcpy(dbp, dp->dname);
			else
				boardset2str(dp->dhw.dh_boardset, dbp);
			if (d < 10)
				(void) mi_mpprintf(mp, "         %d: %s",
				    d, dbp);
			else
				(void) mi_mpprintf(mp, "        %d: %s",
				    d, dbp);
		}
	}

	/*CONSTCOND*/
	i = IDN_SYNC_GETZONE(IDNSYNC_CONNECT);
	zp = &idn.sync.sz_zone[i];
	if (zp->sc_cnt == 0) {
		(void) mi_mpprintf(mp, "    Sync Zone (con): [empty]");
	} else {
		(void) mi_mpprintf(mp, "    Sync Zone (con): [%d domains]",
		    zp->sc_cnt);
		sp = zp->sc_op;
		for (i = 0; (i < zp->sc_cnt) && sp; i++) {
			(void) mi_mpprintf(mp,
			    "	             "
			    "%x: x_set =%s0x%x, r_set =%s0x%x",
			    sp->s_domid,
			    HEXSPACE(sp->s_set_exp,
			    sp->s_set_exp, 4, 1),
			    sp->s_set_exp,
			    HEXSPACE(sp->s_set_rdy,
			    sp->s_set_rdy, 4, 1),
			    sp->s_set_rdy);
			sp = sp->s_next;
		}
	}
	/*CONSTCOND*/
	i = IDN_SYNC_GETZONE(IDNSYNC_DISCONNECT);
	zp = &idn.sync.sz_zone[i];
	if (zp->sc_cnt == 0) {
		(void) mi_mpprintf(mp, "    Sync Zone (dis): [empty]");
	} else {
		(void) mi_mpprintf(mp, "    Sync Zone (dis): [%d domains]",
		    zp->sc_cnt);
		sp = zp->sc_op;
		for (i = 0; (i < zp->sc_cnt) && sp; i++) {
			(void) mi_mpprintf(mp,
			    "	             "
			    "%x: x_set =%s0x%x, r_set =%s0x%x",
			    sp->s_domid,
			    HEXSPACE(sp->s_set_exp,
			    sp->s_set_exp, 4, 1),
			    sp->s_set_exp,
			    HEXSPACE(sp->s_set_rdy,
			    sp->s_set_rdy, 4, 1),
			    sp->s_set_rdy);
			sp = sp->s_next;
		}
	}

	IDN_GUNLOCK();
	IDN_SYNC_UNLOCK();

	if (dbuffer) {
		FREE_DISPSTRING(dbuffer);
	}

	return (0);
}

/*ARGSUSED*/
static int
idn_domain_report(queue_t *wq, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	int		d, nchan;
	uint_t		domset;
	idn_chanset_t	chanset;
	idn_domain_t	*dp;
	uint_t		pset_upper, pset_lower;
	char		*dbuffer, *dbp;
	char		alt_dbuffer[64];


	if (IDN_SYNC_TRYLOCK() == 0) {
		(void) mi_mpprintf(mp, "Sync lock busy, try again.");
		return (0);
	}

	if (IDN_GLOCK_TRY_SHARED() == 0) {
		(void) mi_mpprintf(mp, "Local domain busy, try again.");
		IDN_SYNC_UNLOCK();
		return (0);
	}

	if ((dbp = dbuffer = ALLOC_DISPSTRING()) == NULL)
		dbp = alt_dbuffer;

	if (cp == NULL)
		domset = DOMAINSET(idn.localid);
	else
		domset = DOMAINSET_ALL;

	for (d = 0; d < MAX_DOMAINS; d++) {

		if (DOMAIN_IN_SET(domset, d) == 0)
			continue;

		dp = &idn_domain[d];

		if (dp->dcpu == IDN_NIL_DCPU)
			continue;

		if (IDN_DLOCK_TRY_SHARED(d) == 0) {
			if (d < 10)
				(void) mi_mpprintf(mp,
				    "Domain %d   (0x%p) busy...",
				    d, (void *)dp);
			else
				(void) mi_mpprintf(mp,
				    "Domain %d  (0x%p) busy...",
				    d, (void *)dp);
			continue;
		}
		if (dp->dcpu == IDN_NIL_DCPU) {
			IDN_DUNLOCK(d);
			continue;
		}
		if (d < 10)
			(void) mi_mpprintf(mp, "%sDomain %d   (0x%p)",
			    (d && (idn.ndomains > 1)) ? "\n" : "",
			    d, (void *)dp);
		else
			(void) mi_mpprintf(mp, "%sDomain %d  (0x%p)",
			    (d && (idn.ndomains > 1)) ? "\n" : "",
			    d, (void *)dp);

		if (d == idn.localid)
			(void) mi_mpprintf(mp, "  (local)  State = %s (%d)",
			    idnds_str[dp->dstate], dp->dstate);
		else
			(void) mi_mpprintf(mp, "           State = %s (%d)",
			    idnds_str[dp->dstate], dp->dstate);
		(void) mi_mpprintf(mp, "           Name = %s, Netid = %d",
		    (strlen(dp->dname) > 0) ? dp->dname : "<>",
		    (int)dp->dnetid);

		CHANSET_ZERO(chanset);
		nchan = idn_domain_is_registered(d, -1, &chanset);
		if (dbuffer)
			mask2str(chanset, dbp, 32);
		else
			(void) sprintf(dbp, "0x%x", chanset);
		(void) mi_mpprintf(mp, "           Nchans = %d, Chanset = %s",
		    nchan, nchan ? dbp : "<>");
		pset_upper = UPPER32_CPUMASK(dp->dcpuset);
		pset_lower = LOWER32_CPUMASK(dp->dcpuset);
		if (dbuffer)
			boardset2str(dp->dhw.dh_boardset, dbp);
		else
			(void) sprintf(dbp, "0x%x", dp->dhw.dh_boardset);

		(void) mi_mpprintf(mp, "           Nboards = %d, Brdset = %s",
		    dp->dhw.dh_nboards,
		    dp->dhw.dh_nboards ? dbp : "<>");
		(void) sprintf(dbp, "0x%x.%x", pset_upper, pset_lower);
		(void) mi_mpprintf(mp, "           Ncpus = %d, Cpuset = %s",
		    dp->dncpus, dp->dncpus ? dbp : "<>");
		(void) mi_mpprintf(mp, "           Nmcadr = %d",
		    dp->dhw.dh_nmcadr);
		(void) mi_mpprintf(mp,
		    "	   MsgTimer = %s  (cnt = %d)",
		    (dp->dtimerq.tq_count > 0)
		    ? "active" : "idle",
		    dp->dtimerq.tq_count);
		(void) mi_mpprintf(mp, "           Dcpu = %d  "
		    "(lastcpu = %d, cpuindex = %d)",
		    dp->dcpu, dp->dcpu_last, dp->dcpuindex);
		(void) mi_mpprintf(mp, "           Dio = %d  "
		    "(ioerr = %d, iochk = %d, iowanted = %d)",
		    dp->dio, dp->dioerr, dp->diocheck ? 1 : 0,
		    dp->diowanted ? 1 : 0);
		if (dp->dsync.s_cmd == IDNSYNC_NIL) {
			(void) mi_mpprintf(mp, "           Dsync = %s",
			    idnsync_str[IDNSYNC_NIL]);
		} else {
			(void) mi_mpprintf(mp,
			    "	   Dsync = %s "
			    "(x_set = 0x%x, r_set = 0x%x)",
			    idnsync_str[dp->dsync.s_cmd],
			    (uint_t)dp->dsync.s_set_exp,
			    (uint_t)dp->dsync.s_set_rdy);
		}
		(void) mi_mpprintf(mp, "           Dvote = 0x%x",
		    dp->dvote.ticket);
		(void) mi_mpprintf(mp, "           Dfin = %s (Sync = %s)",
		    idnfin_str[dp->dfin],
		    (dp->dfin_sync == IDNFIN_SYNC_OFF) ? "OFF" :
		    (dp->dfin_sync == IDNFIN_SYNC_YES) ? "YES" :
		    "NO");
		(void) mi_mpprintf(mp, "           Dcookie_err = %s (cnt = %d)",
		    dp->dcookie_err ? "YES" : "NO",
		    dp->dcookie_errcnt);
		IDN_DUNLOCK(d);
	}

	IDN_GUNLOCK();

	if (dbuffer) {
		FREE_DISPSTRING(dbuffer);
	}

	IDN_SYNC_UNLOCK();

	return (0);
}

#define	SNOOP_ENTRIES	2048	/* power of 2 */

struct snoop_buffer {
/*  0 */	char	io;
/*  1 */	char	board;
/*  2 */	char	trans[14];

/* 10 */	uint_t	xargs[4];
} *snoop_data, snoop_buffer[SNOOP_ENTRIES+1];


int		snoop_index;
kmutex_t	snoop_mutex;
static char	_bd2hexascii[] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

#define	SNOOP_IDN(in, tr, bd, arg1, arg2, arg3, arg4) \
{ \
	if (idn_snoop) { \
		mutex_enter(&snoop_mutex); \
		if (snoop_data == NULL) { \
			snoop_data = (struct snoop_buffer *) \
				(((uint_t)(uintptr_t)snoop_buffer + 0xf) & \
				    ~0xf);				\
		} \
		snoop_data[snoop_index].io = ((in) == 0) ? 'o' : 'i'; \
		snoop_data[snoop_index].board = \
				((bd) == -1) ? 'X' : _bd2hexascii[bd]; \
		(void) strncpy(snoop_data[snoop_index].trans, (tr), 14); \
		snoop_data[snoop_index].xargs[0] = (arg1); \
		snoop_data[snoop_index].xargs[1] = (arg2); \
		snoop_data[snoop_index].xargs[2] = (arg3); \
		snoop_data[snoop_index].xargs[3] = (arg4); \
		snoop_index++; \
		snoop_index &= SNOOP_ENTRIES - 1; \
		mutex_exit(&snoop_mutex); \
	} \
}

/*
 * Allocate the circular buffers to be used for
 * DMV interrupt processing.
 */
static int
idn_init_handler()
{
	int		i, c;
	size_t		len;
	idn_dmv_msg_t	*basep, *ivp;
	uint32_t	ivp_offset;
	procname_t	proc = "idn_init_handler";

	if (idn.intr.dmv_data != NULL) {
		cmn_err(CE_WARN,
		    "IDN: 130: IDN DMV handler already initialized");
		return (-1);
	}

	/*
	 * This memory will be touched by the low-level
	 * DMV trap handler for IDN.
	 */
	len = sizeof (idn_dmv_data_t);
	len = roundup(len, sizeof (uint64_t));
	len += NCPU * idn_dmv_pending_max * sizeof (idn_dmv_msg_t);
	len = roundup(len, PAGESIZE);

	PR_PROTO("%s: sizeof (idn_dmv_data_t) = %lu\n",
	    proc, sizeof (idn_dmv_data_t));
	PR_PROTO("%s: allocating %lu bytes for dmv data area\n", proc, len);

	idn.intr.dmv_data_len = len;
	idn.intr.dmv_data = kmem_zalloc(len, KM_SLEEP);

	PR_PROTO("%s: DMV data area = %p\n", proc, (void *)idn.intr.dmv_data);

	idn_dmv_data = (idn_dmv_data_t *)idn.intr.dmv_data;
	basep = (idn_dmv_msg_t *)roundup((size_t)idn.intr.dmv_data +
	    sizeof (idn_dmv_data_t),
	    sizeof (uint64_t));
	idn_dmv_data->idn_dmv_qbase = (uint64_t)basep;

	ivp = basep;
	ivp_offset = 0;
	/*
	 * The buffer queues are allocated per-cpu.
	 */
	for (c = 0, ivp = basep; c < NCPU; ivp++, c++) {
		idn_dmv_data->idn_dmv_cpu[c].idn_dmv_current = ivp_offset;
		idn_iv_queue[c] = ivp;
		ivp_offset += sizeof (idn_dmv_msg_t);
		for (i = 1; i < idn_dmv_pending_max; ivp++, i++) {
			ivp->iv_next = ivp_offset;
			ivp->iv_ready = 0;
			lock_set(&ivp->iv_ready);
			ivp_offset += sizeof (idn_dmv_msg_t);
		}
		ivp->iv_next = idn_dmv_data->idn_dmv_cpu[c].idn_dmv_current;
		ivp->iv_ready = 0;
		lock_set(&ivp->iv_ready);
	}

	idn.intr.dmv_inum = STARFIRE_DMV_IDN_BASE;
	idn.intr.soft_inum = add_softintr((uint_t)idn_pil, idn_handler, 0,
	    SOFTINT_ST);
	idn_dmv_data->idn_soft_inum = idn.intr.soft_inum;
	/*
	 * Make sure everything is out there before
	 * we effectively set it free for use.
	 */
	membar_stld_stst();

	if (dmv_add_intr(idn.intr.dmv_inum, idn_dmv_handler,
	    (caddr_t)idn_dmv_data)) {
		idn_deinit_handler();
		cmn_err(CE_WARN, "IDN: 132: failed to add IDN DMV handler");
		return (-1);
	}

	return (0);
}

static void
idn_deinit_handler()
{
	if (idn.intr.dmv_data == NULL)
		return;

	(void) dmv_rem_intr(idn.intr.dmv_inum);
	(void) rem_softintr(idn.intr.soft_inum);
	kmem_free(idn.intr.dmv_data, idn.intr.dmv_data_len);
	idn.intr.dmv_data = NULL;
}

/*
 * High-level (soft interrupt) handler for DMV interrupts
 */
/*ARGSUSED0*/
static uint_t
idn_handler(caddr_t unused, caddr_t unused2)
{
#ifdef DEBUG
	int		count = 0;
#endif /* DEBUG */
	int		cpuid = (int)CPU->cpu_id;
	ushort_t	mtype, atype;
	idn_dmv_msg_t	*xp, *xplimit;
	procname_t	proc = "idn_handler";

	ASSERT(getpil() >= idn_pil);
	flush_windows();

	/*
	 * Clear the synchronization flag to indicate that
	 * processing has started.  As long as idn_dmv_active
	 * is non-zero, idn_dmv_handler will queue work without
	 * initiating a soft interrupt.  Since we clear it
	 * first thing at most one pil-interrupt for IDN will
	 * queue up behind the currently active one.  We don't
	 * want to clear this flag at the end because it leaves
	 * a window where an interrupt could get lost (unless it's
	 * pushed by a subsequent interrupt).  The objective in
	 * doing this is to prevent exhausting a cpu's intr_vec
	 * structures with interrupts of the same pil level.
	 */
	lock_clear(&idn_dmv_data->idn_dmv_cpu[cpuid].idn_dmv_active);

	xp = idn_iv_queue[cpuid];
	xplimit = xp + idn_dmv_pending_max;
	xp += idn_intr_index[cpuid];
	/*
	 * As long as there's stuff that's READY in the
	 * queue, keep processing.
	 */
	while (lock_try(&xp->iv_ready)) {

		ASSERT(lock_try(&xp->iv_inuse) == 0);

		mtype = (ushort_t)xp->iv_mtype;
		mtype &= IDNP_MSGTYPE_MASK | IDNP_ACKNACK_MASK;
		atype = (ushort_t)xp->iv_atype;

		if (((int)xp->iv_ver == idn.version) && mtype) {
			idn_protojob_t	*jp;
#ifdef DEBUG
			STRING(mstr);
			STRING(astr);

			INUM2STR(mtype, mstr);
			if ((mtype & IDNP_MSGTYPE_MASK) == 0) {
				INUM2STR(atype, astr);
				(void) strcat(mstr, "/");
				(void) strcat(mstr, astr);
			}

			count++;

			PR_XDC("%s:%d:%d RECV: scpu = %d, msg = 0x%x(%s)\n",
			    proc, (int)xp->iv_domid, count,
			    (int)xp->iv_cpuid, mtype, mstr);
			PR_XDC("%s:%d:%d R-DATA: a0 = 0x%x, a1 = 0x%x\n",
			    proc, (int)xp->iv_domid, count,
			    xp->iv_xargs0, xp->iv_xargs1);
			PR_XDC("%s:%d:%d R-DATA: a2 = 0x%x, a3 = 0x%x\n",
			    proc, (int)xp->iv_domid, count,
			    xp->iv_xargs2, xp->iv_xargs3);
#endif /* DEBUG */

			if (mtype == IDNP_DATA) {
				jp = NULL;
				/*
				 * The only time we receive pure
				 * data messages at this level is
				 * to wake up the channel server.
				 * Since this is often an urgent
				 * request we'll do it from here
				 * instead of waiting for a proto
				 * server to do it.
				 */
				idn_signal_data_server((int)xp->iv_domid,
				    (ushort_t)xp->iv_xargs0);
			} else {
				jp = idn_protojob_alloc(KM_NOSLEEP);
				/*
				 * If the allocation fails, just drop
				 * the message and get on with life.
				 * If memory pressure is this great then
				 * dropping this message is probably
				 * the least of our worries!
				 */
				if (jp) {
					jp->j_msg.m_domid = (int)xp->iv_domid;
					jp->j_msg.m_cpuid = (int)xp->iv_cpuid;
					jp->j_msg.m_msgtype = mtype;
					jp->j_msg.m_acktype = atype;
					jp->j_msg.m_cookie = xp->iv_cookie;
					SET_XARGS(jp->j_msg.m_xargs,
					    xp->iv_xargs0, xp->iv_xargs1,
					    xp->iv_xargs2, xp->iv_xargs3);
				}

			}
			membar_ldst_stst();

			lock_clear(&xp->iv_inuse);

			if (jp)
				idn_protojob_submit(jp->j_msg.m_domid, jp);
		} else {
			membar_ldst_stst();
			IDN_GKSTAT_INC(gk_dropped_intrs);
			lock_clear(&xp->iv_inuse);
		}

		if (++xp == xplimit)
			xp = idn_iv_queue[cpuid];
	}

	idn_intr_index[cpuid] = xp - idn_iv_queue[cpuid];

	return (DDI_INTR_CLAIMED);
}

void
idn_awol_event_set(boardset_t boardset)
{
	idnsb_event_t	*sbp;
	procname_t	proc = "idn_awol_event_set";

	ASSERT(IDN_GLOCK_IS_EXCL());

	mutex_enter(&idn.idnsb_mutex);
	sbp = idn.idnsb_eventp;
	if (sbp == NULL) {
		cmn_err(CE_WARN, "IDN: 133: sigblock event area missing");
		cmn_err(CE_CONT,
		    "IDN: 134: unable to mark boardset (0x%x) AWOL\n",
		    boardset);
		mutex_exit(&idn.idnsb_mutex);
		return;
	}

	if (boardset == 0) {
		PR_PROTO("%s: AWOL BOARDSET is 0, NO EVENT <<<<<<<<<<<<<<<\n",
		    proc);
		mutex_exit(&idn.idnsb_mutex);
		return;
	} else {
		PR_PROTO("%s: MARKING BOARDSET (0x%x) AWOL\n", proc, boardset);
	}
	SSIEVENT_ADD(sbp, SSIEVENT_AWOL, boardset);
	mutex_exit(&idn.idnsb_mutex);
}

void
idn_awol_event_clear(boardset_t boardset)
{
	idnsb_event_t	*sbp;
	procname_t	proc = "idn_awol_event_clear";

	ASSERT(IDN_GLOCK_IS_EXCL());

	mutex_enter(&idn.idnsb_mutex);
	sbp = idn.idnsb_eventp;
	if (sbp == NULL) {
		cmn_err(CE_WARN, "IDN: 133: sigblock event area missing");
		cmn_err(CE_CONT,
		    "IDN: 134: unable to mark boardset (0x%x) AWOL\n",
		    boardset);
		mutex_exit(&idn.idnsb_mutex);
		return;
	}

	if (boardset == 0) {
		PR_PROTO("%s: AWOL BOARDSET is 0, NO EVENT <<<<<<<<<<<<<<<\n",
		    proc);
		mutex_exit(&idn.idnsb_mutex);
		return;
	} else {
		PR_PROTO("%s: CLEARING BOARDSET (0x%x) AWOL\n", proc, boardset);
	}
	SSIEVENT_DEL(sbp, SSIEVENT_AWOL, boardset);
	mutex_exit(&idn.idnsb_mutex);
}

static void
idn_gkstat_init()
{
	struct	kstat			*ksp;
	struct	idn_gkstat_named	*sgkp;

#ifdef	kstat
	if ((ksp = kstat_create(IDNNAME, ddi_get_instance(idn.dip),
	    IDNNAME, "net", KSTAT_TYPE_NAMED,
	    sizeof (struct idn_gkstat_named) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
#else
	if ((ksp = kstat_create(IDNNAME, ddi_get_instance(idn.dip),
	    IDNNAME, "net", KSTAT_TYPE_NAMED,
	    sizeof (struct idn_gkstat_named) /
	    sizeof (kstat_named_t), 0)) == NULL) {
#endif /* kstat */
		cmn_err(CE_CONT, "IDN: 135: %s: %s\n",
		    IDNNAME, "kstat_create failed");
		return;
	}

	idn.ksp = ksp;
	sgkp = (struct idn_gkstat_named *)(ksp->ks_data);
	kstat_named_init(&sgkp->sk_curtime,		"curtime",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_reconfigs,		"reconfigs",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_reconfig_last,	"reconfig_last",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_reaps,		"reaps",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_reap_last,		"reap_last",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_links,		"links",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_link_last,		"link_last",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_unlinks,		"unlinks",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_unlink_last,		"unlink_last",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_buffail,		"buf_fail",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_buffail_last,	"buf_fail_last",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_slabfail,		"slab_fail",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_slabfail_last,	"slab_fail_last",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_slabfail_last,	"slab_fail_last",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_reap_count,		"reap_count",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sgkp->sk_dropped_intrs,	"dropped_intrs",
	    KSTAT_DATA_ULONG);
	ksp->ks_update = idn_gkstat_update;
	ksp->ks_private = (void *)NULL;
	kstat_install(ksp);
}

static void
idn_gkstat_deinit()
{
	if (idn.ksp)
		kstat_delete(idn.ksp);
	idn.ksp = NULL;
}

static int
idn_gkstat_update(kstat_t *ksp, int rw)
{
	struct idn_gkstat_named	*sgkp;

	sgkp = (struct idn_gkstat_named *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {
		sg_kstat.gk_reconfigs	    = sgkp->sk_reconfigs.value.ul;
		sg_kstat.gk_reconfig_last   = sgkp->sk_reconfig_last.value.ul;
		sg_kstat.gk_reaps	    = sgkp->sk_reaps.value.ul;
		sg_kstat.gk_reap_last	    = sgkp->sk_reap_last.value.ul;
		sg_kstat.gk_links	    = sgkp->sk_links.value.ul;
		sg_kstat.gk_link_last	    = sgkp->sk_link_last.value.ul;
		sg_kstat.gk_unlinks	    = sgkp->sk_unlinks.value.ul;
		sg_kstat.gk_unlink_last	    = sgkp->sk_unlink_last.value.ul;
		sg_kstat.gk_buffail	    = sgkp->sk_buffail.value.ul;
		sg_kstat.gk_buffail_last    = sgkp->sk_buffail_last.value.ul;
		sg_kstat.gk_slabfail	    = sgkp->sk_slabfail.value.ul;
		sg_kstat.gk_slabfail_last   = sgkp->sk_slabfail_last.value.ul;
		sg_kstat.gk_reap_count	    = sgkp->sk_reap_count.value.ul;
		sg_kstat.gk_dropped_intrs   = sgkp->sk_dropped_intrs.value.ul;
	} else {
		sgkp->sk_curtime.value.ul	  = ddi_get_lbolt();
		sgkp->sk_reconfigs.value.ul	  = sg_kstat.gk_reconfigs;
		sgkp->sk_reconfig_last.value.ul	  = sg_kstat.gk_reconfig_last;
		sgkp->sk_reaps.value.ul		  = sg_kstat.gk_reaps;
		sgkp->sk_reap_last.value.ul	  = sg_kstat.gk_reap_last;
		sgkp->sk_links.value.ul		  = sg_kstat.gk_links;
		sgkp->sk_link_last.value.ul	  = sg_kstat.gk_link_last;
		sgkp->sk_unlinks.value.ul	  = sg_kstat.gk_unlinks;
		sgkp->sk_unlink_last.value.ul	  = sg_kstat.gk_unlink_last;
		sgkp->sk_buffail.value.ul	  = sg_kstat.gk_buffail;
		sgkp->sk_buffail_last.value.ul    = sg_kstat.gk_buffail_last;
		sgkp->sk_slabfail.value.ul	  = sg_kstat.gk_slabfail;
		sgkp->sk_slabfail_last.value.ul   = sg_kstat.gk_slabfail_last;
		sgkp->sk_reap_count.value.ul	  = sg_kstat.gk_reap_count;
		sgkp->sk_dropped_intrs.value.ul	  = sg_kstat.gk_dropped_intrs;
	}

	return (0);
}

#ifdef DEBUG
#define	RW_HISTORY	100
static uint_t	rw_history[NCPU][RW_HISTORY];
static int	rw_index[NCPU];
#endif /* DEBUG */

static int
idn_rw_mem(idnop_t *idnop)
{
	uint_t		lo_off, hi_off;
	int		rw, blksize, num;
	int		cpuid;
	register int	n, idx;
	char 		*ibuf, *obuf;
	char		*smraddr;
	struct seg	*segp;
	ulong_t		randx;
	kmutex_t	slock;
	kcondvar_t	scv;
	static int	orig_gstate = IDNGS_IGNORE;
	extern struct  seg	ktextseg;

#define	RANDOM_INIT()	(randx = ddi_get_lbolt())
#define	RANDOM(a, b)	\
	(((a) >= (b)) ? \
	(a) : (((randx = randx * 1103515245L + 12345) % ((b)-(a))) + (a)))

	RANDOM_INIT();

	lo_off  = idnop->rwmem.lo_off;
	hi_off  = idnop->rwmem.hi_off;
	blksize = idnop->rwmem.blksize;
	num	= idnop->rwmem.num;
	rw	= idnop->rwmem.rw;	/* 0 = rd, 1 = wr, 2 = rd/wr */

	if (((hi_off > (uint_t)MB2B(IDN_SMR_SIZE)) || (lo_off >= hi_off) ||
	    (blksize <= 0) || (blksize > (hi_off - lo_off)) || (num <= 0)) &&
	    (idnop->rwmem.goawol == -1)) {
		return (EINVAL);
	}

	if (idnop->rwmem.goawol && (orig_gstate == IDNGS_IGNORE)) {
		IDN_GLOCK_EXCL();
		cmn_err(CE_WARN, "IDN: Local domain going into IGNORE MODE!!");
		orig_gstate = idn.state;
		IDN_GSTATE_TRANSITION(IDNGS_IGNORE);
		IDN_GUNLOCK();

	} else if (!idnop->rwmem.goawol && (orig_gstate != IDNGS_IGNORE)) {
		IDN_GLOCK_EXCL();
		cmn_err(CE_WARN,
		    "IDN: Local domain restoring original state %s(%d)",
		    idngs_str[orig_gstate], (int)orig_gstate);
		IDN_GSTATE_TRANSITION(orig_gstate);
		orig_gstate = IDNGS_IGNORE;
		IDN_GUNLOCK();
	}
	/*
	 * Just requested AWOL.
	 */
	if (num == 0)
		return (0);
	/*
	 * Default READ only.
	 */
	ibuf = (char *)kmem_alloc(blksize, KM_SLEEP);
	if (rw == 1) {
		/*
		 * WRITE only.
		 */
		obuf = ibuf;
		ibuf = NULL;
	} else if (rw == 2) {
		/*
		 * READ/WRITE.
		 */
		obuf = (char *)kmem_alloc(blksize, KM_SLEEP);
		for (segp = &ktextseg; segp; segp = AS_SEGNEXT(&kas, segp)) {
			if (segp->s_size >= blksize)
				break;
		}
		if (segp == NULL) {
			cmn_err(CE_WARN,
			    "IDN: blksize (%d) too large", blksize);
			return (EINVAL);
		}
		bcopy(segp->s_base, obuf, blksize);
	}

	mutex_init(&slock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&scv, NULL, CV_DEFAULT, NULL);

	cmn_err(CE_NOTE,
	    "IDN: starting %s of %d blocks of %d bytes each...",
	    (rw == 1) ? "W-ONLY" : (rw == 2) ? "RW" : "R-ONLY",
	    num, blksize);

	for (n = 0; n < num; n++) {
		uint_t	rpos;

		if ((hi_off - lo_off) > blksize)
			rpos = RANDOM(lo_off, (hi_off - blksize));
		else
			rpos = lo_off;
		smraddr = IDN_OFFSET2ADDR(rpos);

		cpuid = (int)CPU->cpu_id;
#ifdef DEBUG
		idx = rw_index[cpuid]++ % RW_HISTORY;
		rw_history[cpuid][idx] = rpos;
#endif /* DEBUG */

		switch (rw) {
		case 0:
			bcopy(smraddr, ibuf, blksize);
			break;
		case 1:
			bcopy(obuf, smraddr, blksize);
			break;
		case 2:
			if (n & 1)
				bcopy(obuf, smraddr, blksize);
			else
				bcopy(smraddr, ibuf, blksize);
			break;
		default:
			break;
		}
		if (!(n % 1000)) {
			int	rv;

			mutex_enter(&slock);
			rv = cv_reltimedwait_sig(&scv, &slock, hz,
			    TR_CLOCK_TICK);
			mutex_exit(&slock);
			if (rv == 0)
				break;
		}
	}

	cv_destroy(&scv);
	mutex_destroy(&slock);

	if (ibuf)
		kmem_free(ibuf, blksize);
	if (obuf)
		kmem_free(obuf, blksize);

	return (0);
}

void
inum2str(uint_t inum, char str[])
{
	uint_t	acknack;

	str[0] = '\0';

	acknack = (inum & IDNP_ACKNACK_MASK);
	inum &= ~IDNP_ACKNACK_MASK;

	if (!inum && !acknack) {
		(void) strcpy(str, idnm_str[0]);
		return;
	}

	if (inum == 0) {
		(void) strcpy(str, (acknack & IDNP_ACK) ? "ack" : "nack");
	} else {
		if (inum < IDN_NUM_MSGTYPES)
			(void) strcpy(str, idnm_str[inum]);
		else
			(void) sprintf(str, "0x%x?", inum);
		if (acknack) {
			if (acknack & IDNP_ACK)
				(void) strcat(str, "+ack");
			else
				(void) strcat(str, "+nack");
		}
	}
}

boardset_t
cpuset2boardset(cpuset_t portset)
{
	register int		c;
	register boardset_t	bset;

	bset = 0;
	for (c = 0; c < NCPU; )
		if (CPU_IN_SET(portset, c)) {
			BOARDSET_ADD(bset, CPUID_TO_BOARDID(c));
			c = (c + 4) & ~3;
		} else {
			c++;
		}

	return (bset);
}

void
cpuset2str(cpuset_t cset, char buffer[])
{
	register int	c, n;

	buffer[0] = '\0';
	for (c = n = 0; c < NCPU; c++) {
		if (!CPU_IN_SET(cset, c))
			continue;
#ifdef DEBUG
		if (strlen(buffer) >= _DSTRLEN) {
			PR_PROTO("************* WARNING WARNING WARNING\n");
			PR_PROTO("cpuset2str(cpu = %d) buffer "
			    "OVERFLOW <<<<<<\n", c);
			PR_PROTO("*******************************\n");
			(void) sprintf(&buffer[_DSTRLEN-6], "*OVER");
			return;
		}
#endif /* DEBUG */
		if (n == 0)
			(void) sprintf(buffer, "%d", c);
		else
			(void) sprintf(buffer, "%s, %d", buffer, c);
		n++;
	}
}

void
domainset2str(domainset_t dset, char buffer[])
{
	/*
	 * Since domainset_t and boardset_t are the
	 * same (max = MAX_DOMAINS = MAX_BOARDS) we
	 * can just overload boardset2str().
	 */
	mask2str((uint_t)dset, buffer, MAX_DOMAINS);
}

void
boardset2str(boardset_t bset, char buffer[])
{
	mask2str((uint_t)bset, buffer, MAX_BOARDS);
}

void
mask2str(uint_t mask, char buffer[], int maxnum)
{
	int	n, i;

	buffer[0] = '\0';
	for (i = n = 0; i < maxnum; i++) {
		if ((mask & (1 << i)) == 0)
			continue;
		if (n == 0)
			(void) sprintf(buffer, "%d", i);
		else
			(void) sprintf(buffer, "%s, %d", buffer, i);
		n++;
	}
}

int
idnxdc(int domid, idn_msgtype_t *mtp,
	uint_t arg1, uint_t arg2,
	uint_t arg3, uint_t arg4)
{
	int		rv, cpuid, tcpuid;
	uint_t		cookie;
	uint64_t	pdata;
	uint64_t	dmv_word0, dmv_word1, dmv_word2;
	idn_domain_t	*dp = &idn_domain[domid];
	extern kmutex_t	xc_sys_mutex;
	extern int	xc_spl_enter[];
	procname_t	proc = "idnxdc";


	if (idn_snoop) {
		int	bd;
		STRING(str);
		STRING(mstr);
		STRING(astr);

		INUM2STR(mtp->mt_mtype, mstr);
		if ((mtp->mt_mtype & IDNP_MSGTYPE_MASK) == 0) {
			INUM2STR(arg1, astr);
			(void) sprintf(str, "%s/%s", mstr, astr);
		} else {
			(void) strcpy(str, mstr);
		}
		if (dp->dcpu == IDN_NIL_DCPU)
			bd = -1;
		else
			bd = CPUID_TO_BOARDID(dp->dcpu);
		SNOOP_IDN(0, str, bd, arg1, arg2, arg3, arg4);
	}

	/*
	 * For NEGO messages we send the remote domain the cookie we
	 * expect it to use in subsequent messages that it sends
	 * to us (dcookie_recv).
	 * For other messages, we must use the cookie that the
	 * remote domain assigned to us for sending (dcookie_send).
	 */
	if ((mtp->mt_mtype & IDNP_MSGTYPE_MASK) == IDNP_NEGO)
		cookie = IDN_MAKE_COOKIE(dp->dcookie_recv, mtp->mt_cookie);
	else
		cookie = IDN_MAKE_COOKIE(dp->dcookie_send, mtp->mt_cookie);

	pdata = IDN_MAKE_PDATA(mtp->mt_mtype, mtp->mt_atype, cookie);

	dmv_word0 = DMV_MAKE_DMV(idn.intr.dmv_inum, pdata);
	dmv_word1 = ((uint64_t)arg1 << 32) | (uint64_t)arg2;
	dmv_word2 = ((uint64_t)arg3 << 32) | (uint64_t)arg4;

	ASSERT((dp->dcpu != IDN_NIL_DCPU) ||
	    (dp->dcpu_last != IDN_NIL_DCPU));

	tcpuid = (dp->dcpu == IDN_NIL_DCPU) ?
	    dp->dcpu_last : dp->dcpu;

	if (tcpuid == IDN_NIL_DCPU) {
		PR_PROTO("%s:%d: cpu/cpu_last == NIL_DCPU\n",
		    proc, domid);
		return (-1);
	}

	mutex_enter(&xc_sys_mutex);
	cpuid = (int)CPU->cpu_id;
	xc_spl_enter[cpuid] = 1;

	idnxf_init_mondo(dmv_word0, dmv_word1, dmv_word2);

	rv = idnxf_send_mondo(STARFIRE_UPAID2HWMID(tcpuid));

	xc_spl_enter[cpuid] = 0;
	mutex_exit(&xc_sys_mutex);

	return (rv);
}

void
idnxdc_broadcast(domainset_t domset, idn_msgtype_t *mtp,
		uint_t arg1, uint_t arg2,
		uint_t arg3, uint_t arg4)
{
	int	d;

	for (d = 0; d < MAX_DOMAINS; d++) {
		idn_domain_t	*dp;

		if (!DOMAIN_IN_SET(domset, d))
			continue;

		dp = &idn_domain[d];
		if (dp->dcpu == IDN_NIL_DCPU)
			continue;

		(void) IDNXDC(d, mtp, arg1, arg2, arg3, arg4);
	}
}

#define	PROM_SMRSIZE	0x1
#define	PROM_SMRADDR	0x2
#define	PROM_SMRPROPS	(PROM_SMRSIZE | PROM_SMRADDR)
/*
 * Locate the idn-smr-size property to determine the size of the SMR
 * region for the SSI.  Value inherently enables/disables SSI capability.
 */
static int
idn_prom_getsmr(uint_t *smrsz, uint64_t *paddrp, uint64_t *sizep)
{
	pnode_t		nodeid;
	int		found = 0;
	int		len;
	uint_t		smrsize = 0;
	uint64_t	obpaddr, obpsize;
	struct smraddr {
		uint32_t	hi_addr;
		uint32_t	lo_addr;
		uint32_t	hi_size;
		uint32_t	lo_size;
	} smraddr;
	procname_t	proc = "idn_prom_getsmr";

	bzero(&smraddr, sizeof (smraddr));
	/*
	 * idn-smr-size is a property of the "memory" node and
	 * is defined in megabytes.
	 */
	nodeid = prom_finddevice("/memory");

	if (nodeid != OBP_NONODE) {
		len = prom_getproplen(nodeid, IDN_PROP_SMRSIZE);
		if (len == sizeof (smrsize)) {
			(void) prom_getprop(nodeid, IDN_PROP_SMRSIZE,
			    (caddr_t)&smrsize);
			found |= PROM_SMRSIZE;
		}
		len = prom_getproplen(nodeid, IDN_PROP_SMRADDR);
		if (len  == sizeof (smraddr)) {
			(void) prom_getprop(nodeid, IDN_PROP_SMRADDR,
			    (caddr_t)&smraddr);
			found |= PROM_SMRADDR;
		}
	}

	if (found != PROM_SMRPROPS) {
		if ((found & PROM_SMRSIZE) == 0)
			cmn_err(CE_WARN,
			    "IDN: 136: \"%s\" property not found, "
			    "disabling IDN",
			    IDN_PROP_SMRSIZE);
		if (smrsize && ((found & PROM_SMRADDR) == 0))
			cmn_err(CE_WARN,
			    "IDN: 136: \"%s\" property not found, "
			    "disabling IDN",
			    IDN_PROP_SMRADDR);
		return (-1);
	}

	if (smrsize == 0) {
		PR_SMR("%s: IDN DISABLED (idn_smr_size = 0)\n", proc);
		cmn_err(CE_NOTE, "!IDN: 137: SMR size is 0, disabling IDN");

	} else if (smrsize > IDN_SMR_MAXSIZE) {
		PR_SMR("%s: IDN DISABLED (idn_smr_size too big %d > %d MB)\n",
		    proc, smrsize, IDN_SMR_MAXSIZE);
		cmn_err(CE_WARN,
		    "!IDN: 138: SMR size (%dMB) is too big (max = %dMB), "
		    "disabling IDN",
		    smrsize, IDN_SMR_MAXSIZE);
		smrsize = 0;
	} else {
		*smrsz = smrsize;
		found &= ~PROM_SMRSIZE;
	}

	obpaddr = ((uint64_t)smraddr.hi_addr << 32) |
	    (uint64_t)smraddr.lo_addr;
	obpsize = ((uint64_t)smraddr.hi_size << 32) |
	    (uint64_t)smraddr.lo_size;

	if (obpsize == 0) {
		if (smrsize > 0) {
			cmn_err(CE_WARN, "!IDN: 139: OBP region for "
			    "SMR is 0 length");
		}
	} else if (obpsize < (uint64_t)MB2B(smrsize)) {
		cmn_err(CE_WARN,
		    "!IDN: 140: OBP region (%ld B) smaller "
		    "than requested size (%ld B)",
		    obpsize, MB2B(smrsize));
	} else if ((obpaddr & ((uint64_t)IDN_SMR_ALIGN - 1)) != 0) {
		cmn_err(CE_WARN,
		    "!IDN: 141: OBP region (0x%lx) not on (0x%x) "
		    "boundary", obpaddr, IDN_SMR_ALIGN);
	} else {
		*sizep = obpsize;
		*paddrp = obpaddr;
		found &= ~PROM_SMRADDR;
	}

	return (found ? -1 : 0);
}

void
idn_init_autolink()
{
	idnsb_event_t	*sbp;
	procname_t	proc = "idn_init_autolink";

	mutex_enter(&idn.idnsb_mutex);
	if ((sbp = idn.idnsb_eventp) == NULL) {
		PR_PROTO("%s: IDN private sigb (event) area is NULL\n", proc);
		mutex_exit(&idn.idnsb_mutex);
		return;
	}

	PR_PROTO("%s: marking domain IDN ready.\n", proc);

	bzero(sbp, sizeof (*sbp));

	sbp->idn_version = (uchar_t)idn.version;
	SSIEVENT_SET(sbp, SSIEVENT_BOOT, 0);
	(void) strncpy(sbp->idn_cookie_str, SSIEVENT_COOKIE,
	    SSIEVENT_COOKIE_LEN);
	mutex_exit(&idn.idnsb_mutex);
}

void
idn_deinit_autolink()
{
	idnsb_event_t	*sbp;
	procname_t	proc = "idn_deinit_autolink";

	mutex_enter(&idn.idnsb_mutex);
	if ((sbp = idn.idnsb_eventp) == NULL) {
		PR_PROTO("%s: IDN private sigb (event) area is NULL\n", proc);
		mutex_exit(&idn.idnsb_mutex);
		return;
	}

	PR_PROTO("%s: marking domain IDN unavailable.\n", proc);

	sbp->idn_version = (uchar_t)idn.version;
	SSIEVENT_CLEAR(sbp, SSIEVENT_BOOT, 0);
	(void) strncpy(sbp->idn_cookie_str, SSIEVENT_COOKIE,
	    SSIEVENT_COOKIE_LEN);
	mutex_exit(&idn.idnsb_mutex);
}

void
_make64cpumask(cpuset_t *csetp, uint_t upper, uint_t lower)
{
	int	c;

	CPUSET_ZERO(*csetp);

	for (c = 0; c < 32; c++) {
		if (lower & (1 << c)) {
			CPUSET_ADD(*csetp, c);
		}
		if (upper & (1 << (c + 32))) {
			CPUSET_ADD(*csetp, c + 32);
		}
	}
}

uint_t
_lower32cpumask(cpuset_t cset)
{
	int	c;
	uint_t	set = 0;

	for (c = 0; c < 32; c++)
		if (CPU_IN_SET(cset, c))
			set |= 1 << c;

	return (set);
}

uint_t
_upper32cpumask(cpuset_t cset)
{
	int	c;
	uint_t	set = 0;

	for (c = 32; c < NCPU; c++)
		if (CPU_IN_SET(cset, c))
			set |= 1 << (c - 32);

	return (set);
}

#ifdef DEBUG
int
debug_idnxdc(char *f, int domid, idn_msgtype_t *mtp,
		uint_t a1, uint_t a2, uint_t a3, uint_t a4)
{
	idn_domain_t	*dp = &idn_domain[domid];
	int		rv, cpuid, bd;
	static int	xx = 0;
	STRING(str);
	STRING(mstr);
	STRING(astr);

	xx++;
	INUM2STR(mtp->mt_mtype, mstr);
	if ((mtp->mt_mtype & IDNP_MSGTYPE_MASK) == 0) {
		INUM2STR(a1, astr);
		(void) sprintf(str, "%s/%s", mstr, astr);
	} else {
		(void) strcpy(str, mstr);
	}

	if ((cpuid = dp->dcpu) == IDN_NIL_DCPU)
		bd = -1;
	else
		bd = CPUID_TO_BOARDID(cpuid);

	SNOOP_IDN(0, str, bd, a1, a2, a3, a4);

	PR_XDC("%s:%d:%d SENT: scpu = %d, msg = 0x%x(%s)\n",
	    f, domid, xx, cpuid, mtp->mt_mtype, str);
	PR_XDC("%s:%d:%d S-DATA: a1 = 0x%x, a2 = 0x%x\n",
	    f, domid, xx, a1, a2);
	PR_XDC("%s:%d:%d S-DATA: a3 = 0x%x, a4 = 0x%x\n",
	    f, domid, xx, a3, a4);

	rv = idnxdc(domid, mtp, a1, a2, a3, a4);
	if (rv != 0) {
		PR_XDC("%s:%d:%d: WARNING: idnxdc(cpu %d) FAILED\n",
		    f, domid, xx, cpuid);
	}

	return (rv);
}

caddr_t
_idn_getstruct(char *structname, int size)
{
	caddr_t		ptr;
	procname_t	proc = "GETSTRUCT";

	ptr = kmem_zalloc(size, KM_SLEEP);

	PR_ALLOC("%s: ptr 0x%p, struct(%s), size = %d\n",
	    proc, (void *)ptr, structname, size);

	return (ptr);
}

void
_idn_freestruct(caddr_t ptr, char *structname, int size)
{
	procname_t	proc = "FREESTRUCT";

	PR_ALLOC("%s: ptr 0x%p, struct(%s), size = %d\n",
	    proc, (void *)ptr, structname, size);

	ASSERT(ptr != NULL);
	kmem_free(ptr, size);
}
#endif /* DEBUG */
