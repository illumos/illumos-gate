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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * safari system board DR module.
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>

#include <sys/autoconf.h>
#include <sys/cmn_err.h>

#include <sys/ddi_impldefs.h>
#include <sys/machsystm.h>
#include <sys/param.h>

#include <sys/sbdpriv.h>
#include <sys/sbd_io.h>

/* start sbd includes */

#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/x_call.h>
#include <sys/membar.h>
#include <vm/seg_kmem.h>

extern int nulldev();
extern int nodev();

typedef struct {		/* arg to sbd_get_handle */
	dev_t	dev;
	int	cmd;
	int	mode;
	sbd_ioctl_arg_t *ioargp;
} sbd_init_arg_t;


/*
 * sbd support operations.
 */
static void	sbd_exec_op(sbd_handle_t *hp);
static void	sbd_dev_configure(sbd_handle_t *hp);
static int	sbd_dev_release(sbd_handle_t *hp);
static int	sbd_dev_unconfigure(sbd_handle_t *hp);
static void	sbd_attach_cpu(sbd_handle_t *hp, sbderror_t *ep,
				dev_info_t *dip, int unit);
static void	sbd_detach_cpu(sbd_handle_t *hp, sbderror_t *ep,
				dev_info_t *dip, int unit);
static int	sbd_detach_mem(sbd_handle_t *hp, sbderror_t *ep, int unit);
static void	sbd_cancel(sbd_handle_t *hp);
void 	sbd_errno_decode(int err, sbderror_t *ep, dev_info_t *dip);
int		sbd_dealloc_instance(sbd_board_t *sbp, int max_boards);
int		sbd_errno2ecode(int error);
#pragma weak sbdp_cpu_get_impl

#ifdef DEBUG
uint_t	sbd_debug	=	(uint_t)0x0;

#ifdef SBD_DEBUG_ERRS
/* controls which errors are injected */
uint_t	sbd_err_debug	=	(uint_t)0x0;

/* controls printing about error injection */
uint_t	sbd_print_errs	=	(uint_t)0x0;

#endif /* SBD_DEBUG_ERRS */

#endif /* DEBUG */

char	*sbd_state_str[] = {
	"EMPTY", "OCCUPIED", "CONNECTED", "UNCONFIGURED",
	"PARTIAL", "CONFIGURED", "RELEASE", "UNREFERENCED",
	"FATAL"
};

/*	Note: this must be changed in tandem with sbd_ioctl.h	*/
char	*sbd_ct_str[] = {
	"NONE", "CPU", "MEM", "IO", "UNKNOWN"
};

/*	Note: this must also be changed in tandem with sbd_ioctl.h */
#define	SBD_CMD_STR(c) \
	(((c) == SBD_CMD_ASSIGN)	? "ASSIGN"	: \
	((c) == SBD_CMD_UNASSIGN)	? "UNASSIGN"	: \
	((c) == SBD_CMD_POWERON)	? "POWERON"	: \
	((c) == SBD_CMD_POWEROFF)	? "POWEROFF"	: \
	((c) == SBD_CMD_TEST)		? "TEST"	: \
	((c) == SBD_CMD_CONNECT)	? "CONNECT"	: \
	((c) == SBD_CMD_CONFIGURE)	? "CONFIGURE"	: \
	((c) == SBD_CMD_UNCONFIGURE)	? "UNCONFIGURE"	: \
	((c) == SBD_CMD_DISCONNECT)	? "DISCONNECT"	: \
	((c) == SBD_CMD_STATUS)		? "STATUS"	: \
	((c) == SBD_CMD_GETNCM)		? "GETNCM"	: \
	((c) == SBD_CMD_PASSTHRU)	? "PASSTHRU"	: "unknown")

/*
 * Defines and structures for device tree naming and mapping
 * to node types
 */

sbd_devattr_t *sbd_devattr;

/* defines to access the attribute struct */
#define	SBD_DEVNAME(i)		sbd_devattr[i].s_devname
#define	SBD_OTYPE(i)		sbd_devattr[(i)].s_obp_type
#define	SBD_COMP(i)		sbd_devattr[i].s_dnodetype

/*
 * State transition table.  States valid transitions for "board" state.
 * Recall that non-zero return value terminates operation, however
 * the herrno value is what really indicates an error , if any.
 */
static int
_cmd2index(int c)
{
	/*
	 * Translate DR CMD to index into sbd_state_transition.
	 */
	switch (c) {
	case SBD_CMD_CONNECT:		return (0);
	case SBD_CMD_DISCONNECT:	return (1);
	case SBD_CMD_CONFIGURE:		return (2);
	case SBD_CMD_UNCONFIGURE:	return (3);
	case SBD_CMD_POWEROFF:		return (4);
	case SBD_CMD_POWERON:		return (5);
	case SBD_CMD_UNASSIGN:		return (6);
	case SBD_CMD_ASSIGN:		return (7);
	case SBD_CMD_TEST:		return (8);
	default:			return (-1);
	}
}

#define	CMD2INDEX(c)	_cmd2index(c)

static struct sbd_state_trans {
	int	x_cmd;
	struct {
		int	x_rv;		/* return value of pre_op */
		int	x_err;		/* errno, if any */
	} x_op[SBD_NUM_STATES];
} sbd_state_transition[] = {
	{ SBD_CMD_CONNECT,
		{
			{ 0, 0 },	/* empty */
			{ 0, 0 },	/* occupied */
			{ 1, EIO },	/* connected */
			{ 1, EIO },	/* unconfigured */
			{ 1, EIO },	/* partial */
			{ 1, EIO },	/* configured */
			{ 1, EIO },	/* release */
			{ 1, EIO },	/* unreferenced */
			{ 1, EIO },	/* fatal */
		}
	},
	{ SBD_CMD_DISCONNECT,
		{
			{ 1, EIO },	/* empty */
			{ 0, 0 },	/* occupied */
			{ 0, 0 },	/* connected */
			{ 0, 0 },	/* unconfigured */
			{ 1, EIO },	/* partial */
			{ 1, EIO },	/* configured */
			{ 1, EIO },	/* release */
			{ 1, EIO },	/* unreferenced */
			{ 1, EIO },	/* fatal */
		}
	},
	{ SBD_CMD_CONFIGURE,
		{
			{ 1, EIO },	/* empty */
			{ 1, EIO },	/* occupied */
			{ 0, 0 },	/* connected */
			{ 0, 0 },	/* unconfigured */
			{ 0, 0 },	/* partial */
			{ 1, 0 },	/* configured */
			{ 0, 0 },	/* release */
			{ 0, 0 },	/* unreferenced */
			{ 1, EIO },	/* fatal */
		}
	},
	{ SBD_CMD_UNCONFIGURE,
		{
			{ 1, EIO },	/* empty */
			{ 1, EIO },	/* occupied */
			{ 1, EIO },	/* connected */
			{ 1, EIO },	/* unconfigured */
			{ 1, EIO },	/* partial */
			{ 0, 0 },	/* configured */
			{ 0, 0 },	/* release */
			{ 0, 0 },	/* unreferenced */
			{ 1, EIO },	/* fatal */
		}
	},
	{ SBD_CMD_POWEROFF,
		{
			{ 1, EIO },	/* empty */
			{ 0, 0 },	/* occupied */
			{ 1, EIO },	/* connected */
			{ 1, EIO },	/* unconfigured */
			{ 1, EIO },	/* partial */
			{ 1, EIO },	/* configured */
			{ 1, EIO },	/* release */
			{ 1, EIO },	/* unreferenced */
			{ 1, EIO },	/* fatal */
		}
	},
	{ SBD_CMD_POWERON,
		{
			{ 1, EIO },	/* empty */
			{ 0, 0 },	/* occupied */
			{ 1, EIO },	/* connected */
			{ 1, EIO },	/* unconfigured */
			{ 1, EIO },	/* partial */
			{ 1, EIO },	/* configured */
			{ 1, EIO },	/* release */
			{ 1, EIO },	/* unreferenced */
			{ 1, EIO },	/* fatal */
		}
	},
	{ SBD_CMD_UNASSIGN,
		{
			{ 1, EIO },	/* empty */
			{ 0, 0 },	/* occupied */
			{ 1, EIO },	/* connected */
			{ 1, EIO },	/* unconfigured */
			{ 1, EIO },	/* partial */
			{ 1, EIO },	/* configured */
			{ 1, EIO },	/* release */
			{ 1, EIO },	/* unreferenced */
			{ 1, EIO },	/* fatal */
		}
	},
	{ SBD_CMD_ASSIGN,
		{
			{ 1, EIO },	/* empty */
			{ 0, 0 },	/* occupied */
			{ 1, EIO },	/* connected */
			{ 1, EIO },	/* unconfigured */
			{ 1, EIO },	/* partial */
			{ 1, EIO },	/* configured */
			{ 1, EIO },	/* release */
			{ 1, EIO },	/* unreferenced */
			{ 1, EIO },	/* fatal */
		}
	},
	{ SBD_CMD_TEST,
		{
			{ 1, EIO },	/* empty */
			{ 0, 0 },	/* occupied */
			{ 1, EIO },	/* connected */
			{ 1, EIO },	/* unconfigured */
			{ 1, EIO },	/* partial */
			{ 1, EIO },	/* configured */
			{ 1, EIO },	/* release */
			{ 1, EIO },	/* unreferenced */
			{ 1, EIO },	/* fatal */
		}
	},
};

/*
 * Global R/W lock to synchronize access across
 * multiple boards.  Users wanting multi-board access
 * must grab WRITE lock, others must grab READ lock.
 */
krwlock_t	sbd_grwlock;

/*
 * Global to determine if an event needs to be sent
 */
char send_event = 0;

/*
 * Required/Expected functions.
 */

static sbd_handle_t	*sbd_get_handle(dev_t dev, sbd_softstate_t *softsp,
				intptr_t arg, sbd_init_arg_t *iap);
static void		sbd_release_handle(sbd_handle_t *hp);
static int		sbd_pre_op(sbd_handle_t *hp);
static void		sbd_post_op(sbd_handle_t *hp);
static int		sbd_probe_board(sbd_handle_t *hp);
static int		sbd_deprobe_board(sbd_handle_t *hp);
static void		sbd_connect(sbd_handle_t *hp);
static void		sbd_assign_board(sbd_handle_t *hp);
static void		sbd_unassign_board(sbd_handle_t *hp);
static void		sbd_poweron_board(sbd_handle_t *hp);
static void		sbd_poweroff_board(sbd_handle_t *hp);
static void		sbd_test_board(sbd_handle_t *hp);

static int		sbd_disconnect(sbd_handle_t *hp);
static sbd_devlist_t	*sbd_get_attach_devlist(sbd_handle_t *hp,
					int32_t *devnump, int32_t pass);
static int		sbd_pre_attach_devlist(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int32_t devnum);
static int		sbd_post_attach_devlist(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int32_t devnum);
static sbd_devlist_t	*sbd_get_release_devlist(sbd_handle_t *hp,
					int32_t *devnump, int32_t pass);
static int		sbd_pre_release_devlist(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int32_t devnum);
static int		sbd_post_release_devlist(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int32_t devnum);
static void		sbd_release_done(sbd_handle_t *hp,
					sbd_comp_type_t nodetype,
					dev_info_t *dip);
static sbd_devlist_t	*sbd_get_detach_devlist(sbd_handle_t *hp,
					int32_t *devnump, int32_t pass);
static int		sbd_pre_detach_devlist(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int32_t devnum);
static int		sbd_post_detach_devlist(sbd_handle_t *hp,
					sbd_devlist_t *devlist, int32_t devnum);
static void		sbd_status(sbd_handle_t *hp);
static void		sbd_get_ncm(sbd_handle_t *hp);


/*
 * Support functions.
 */
static sbd_devset_t	sbd_dev2devset(sbd_comp_id_t *cid);
static int		sbd_copyin_ioarg(sbd_handle_t *hp, int mode, int cmd,
				sbd_cmd_t *cmdp, sbd_ioctl_arg_t *iap);
static int		sbd_copyout_errs(int mode, sbd_ioctl_arg_t *iap,
					void *arg);
static int		sbd_copyout_ioarg(int mode, int cmd, sbd_cmd_t *scp,
				sbd_ioctl_arg_t *iap);
static int		sbd_check_transition(sbd_board_t *sbp,
					sbd_devset_t *devsetp,
					struct sbd_state_trans *transp);
static sbd_devlist_t	*sbd_get_devlist(sbd_handle_t *hp,
					sbd_board_t *sbp,
					sbd_comp_type_t nodetype,
					int max_units, uint_t uset,
					int *count, int present_only);
static int		sbd_mem_status(sbd_handle_t *hp, sbd_devset_t devset,
					sbd_dev_stat_t *dsp);

static int		sbd_init_devlists(sbd_board_t *sbp);
static int		sbd_name_to_idx(char *name);
static int		sbd_otype_to_idx(char *otpye);
static int		sbd_setup_devlists(dev_info_t *dip, void *arg);
static void		sbd_init_mem_devlists(sbd_board_t *sbp);
static void		sbd_init_cpu_unit(sbd_board_t *sbp, int unit);
static void		sbd_board_discovery(sbd_board_t *sbp);
static void		sbd_board_init(sbd_board_t *sbp,
				sbd_softstate_t *softsp,
				int bd, dev_info_t *dip, int wnode);
static void		sbd_board_destroy(sbd_board_t *sbp);
static int		sbd_check_unit_attached(sbd_board_t *sbp,
				dev_info_t *dip, int unit,
				sbd_comp_type_t nodetype, sbderror_t *ep);

static sbd_state_t 	rstate_cvt(sbd_istate_t state);

/*
 * Autoconfiguration data structures
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"System Board DR"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

static int sbd_instances = 0;

/*
 * dr Global data elements
 */
sbd_global sbd_g;

/*
 * We want to be able to unload the module when we wish to do so, but we don't
 * want anything else to unload it.  Unloading cannot occur until
 * sbd_teardown_instance is called by an explicit IOCTL into the parent node.
 * This support is for debugging purposes and should it be expected to work
 * on the field, it should be enhanced:
 * Currently, there is still a window where sbd_teardow_instance gets called,
 * sbd_prevent_unloading now = 0, the driver doesn't get unloaded, and
 * sbd_setup_instance gets called.  This may cause a panic.
 */
int sbd_prevent_unloading = 1;

/*
 * Driver entry points.
 */
int
_init(void)
{
	int	err;

	/*
	 * If you need to support multiple nodes (instances), then
	 * whatever the maximum number of supported nodes is would
	 * need to passed as the third parameter to ddi_soft_state_init().
	 * Alternative would be to dynamically fini and re-init the
	 * soft state structure each time a node is attached.
	 */
	err = ddi_soft_state_init((void **)&sbd_g.softsp,
		sizeof (sbd_softstate_t), SBD_MAX_INSTANCES);
	if (err)
		return (err);

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini((void **)&sbd_g.softsp);
		return (err);
	}

	/* Get the array of names from platform helper routine */
	sbd_devattr = sbdp_get_devattr();

	return (err);
}

int
_fini(void)
{
	int	err;

	if (sbd_prevent_unloading)
		return (DDI_FAILURE);

	ASSERT(sbd_instances == 0);

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	ddi_soft_state_fini((void **)&sbd_g.softsp);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
sbd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, char *event)
{
	int		rv = 0, instance;
	sbd_handle_t	*hp;
	sbd_softstate_t	*softsp;
	sbd_init_arg_t	init_arg;
	static fn_t	f = "sbd_ioctl";
	int		dr_avail;

	PR_BYP("sbd_ioctl cmd=%x, arg=%lx\n", cmd, arg);

	/* Note: this must also be changed in tandem with sbd_ioctl.h */
	switch (cmd) {
		case SBD_CMD_ASSIGN:
		case SBD_CMD_UNASSIGN:
		case SBD_CMD_POWERON:
		case SBD_CMD_POWEROFF:
		case SBD_CMD_TEST:
		case SBD_CMD_CONNECT:
		case SBD_CMD_CONFIGURE:
		case SBD_CMD_UNCONFIGURE:
		case SBD_CMD_DISCONNECT:
		case SBD_CMD_STATUS:
		case SBD_CMD_GETNCM:
		case SBD_CMD_PASSTHRU:
			break;
		default:
			return (ENOTTY);
	}

	instance = SBD_GET_MINOR2INST(getminor(dev));
	if ((softsp = (sbd_softstate_t *)GET_SOFTC(instance)) == NULL) {
		cmn_err(CE_WARN,
			"sbd:%s:%d: module not yet attached",
			f, instance);
		return (ENXIO);
	}

	init_arg.dev = dev;
	init_arg.cmd = cmd;
	init_arg.mode = mode;
	init_arg.ioargp = (sbd_ioctl_arg_t *)arg;

	hp = sbd_get_handle(dev, softsp, arg, &init_arg);
	/* Check to see if we support dr */
	dr_avail = sbdp_dr_avail();
	if (dr_avail != 1) {
		switch (hp->h_cmd) {
			case SBD_CMD_STATUS:
			case SBD_CMD_GETNCM:
			case SBD_CMD_PASSTHRU:
				break;
			default:
				sbd_release_handle(hp);
				return (ENOTSUP);
		}
	}

	switch (hp->h_cmd) {
	case SBD_CMD_STATUS:
	case SBD_CMD_GETNCM:
	case SBD_CMD_PASSTHRU:
		/* no locks needed for these commands */
		break;

	default:
		rw_enter(&sbd_grwlock, RW_WRITER);
		mutex_enter(&SBDH2BD(hp->h_sbd)->sb_mutex);

		/*
		 * If we're dealing with memory at all, then we have
		 * to keep the "exclusive" global lock held.  This is
		 * necessary since we will probably need to look at
		 * multiple board structs.  Otherwise, we only have
		 * to deal with the board in question and so can drop
		 * the global lock to "shared".
		 */
		/*
		 * XXX This is incorrect. The sh_devset has not
		 * been set at this point - it is 0.
		 */
		rv = DEVSET_IN_SET(HD2MACHHD(hp)->sh_devset,
		    SBD_COMP_MEM, DEVSET_ANYUNIT);
		if (rv == 0)
			rw_downgrade(&sbd_grwlock);
		break;
	}

	/*
	 * Before any operations happen, reset the event flag
	 */
	send_event = 0;

	if (sbd_pre_op(hp) == 0) {
		sbd_exec_op(hp);
		sbd_post_op(hp);
	}

	rv = SBD_GET_ERRNO(SBD_HD2ERR(hp));
	*event = send_event;

	/* undo locking, if any, done before sbd_pre_op */
	switch (hp->h_cmd) {
	case SBD_CMD_STATUS:
	case SBD_CMD_GETNCM:
	case SBD_CMD_PASSTHRU:
		break;
	default:
		mutex_exit(&SBDH2BD(hp->h_sbd)->sb_mutex);
		rw_exit(&sbd_grwlock);
	}

	sbd_release_handle(hp);

	return (rv);
}

int
sbd_setup_instance(int instance, dev_info_t *root, int max_boards, int wnode,
		caddr_t sbdp_arg)
{
	int 		b;
	sbd_softstate_t	*softsp;
	sbd_board_t	*sbd_boardlist;
	static fn_t	f = "sbd_setup_instance";

	sbd_instances++;

	if (sbdp_setup_instance(sbdp_arg) != DDI_SUCCESS) {
		sbd_instances--;
		return (DDI_FAILURE);
	}

	if (ALLOC_SOFTC(instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
			"sbd:%s:%d: failed to alloc soft-state",
			f, instance);
		(void) sbdp_teardown_instance(sbdp_arg);
		sbd_instances--;
		return (DDI_FAILURE);
	}

	softsp = (sbd_softstate_t *)GET_SOFTC(instance);

	if (softsp == NULL) {
		cmn_err(CE_WARN,
			"sbd:%s:%d: failed to get soft-state instance",
			f, instance);
		goto exit;
	}

	sbd_boardlist = GETSTRUCT(sbd_board_t, max_boards);
	if (sbd_boardlist == NULL) {
		cmn_err(CE_WARN,
			"sbd:%s: failed to alloc board list %d",
			f, instance);
		goto exit;
	}


	softsp->sbd_boardlist  = (void *)sbd_boardlist;
	softsp->max_boards  = max_boards;
	softsp->wnode  = wnode;


	for (b = 0; b < max_boards; b++) {
		sbd_board_init(sbd_boardlist++, softsp, b, root, wnode);
	}


	return (DDI_SUCCESS);
exit:
	(void) sbdp_teardown_instance(sbdp_arg);
	FREE_SOFTC(instance);
	sbd_instances--;
	return (DDI_FAILURE);
}

int
sbd_teardown_instance(int instance, caddr_t sbdp_arg)
{
	sbd_softstate_t	*softsp;

	if (sbdp_teardown_instance(sbdp_arg) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softsp = (sbd_softstate_t *)GET_SOFTC(instance);
	if (softsp == NULL) {
		return (DDI_FAILURE);
	}

	(void) sbd_dealloc_instance((sbd_board_t *)softsp->sbd_boardlist,
		softsp->max_boards);

	FREE_SOFTC(instance);
	sbd_instances--;
	sbd_prevent_unloading = 0;

	return (DDI_SUCCESS);
}

static void
sbd_exec_op(sbd_handle_t *hp)
{
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	static fn_t	f = "sbd_exec_op";

	switch (hp->h_cmd) {
		int	dev_canceled;

	case SBD_CMD_CONNECT:
		if (sbd_probe_board(hp))
			break;

		sbd_connect(hp);
		break;

	case SBD_CMD_CONFIGURE:
		sbd_dev_configure(hp);
		break;

	case SBD_CMD_UNCONFIGURE:
		if (((dev_canceled = sbd_dev_release(hp)) == 0) &&
		    (SBD_GET_ERRNO(SBD_HD2ERR(hp)) == 0 &&
		    SBD_GET_ERR(SBD_HD2ERR(hp)) == 0))
			dev_canceled = sbd_dev_unconfigure(hp);

		if (dev_canceled)
			sbd_cancel(hp);
		break;

	case SBD_CMD_DISCONNECT:
		mutex_enter(&sbp->sb_slock);
		if (sbd_disconnect(hp) == 0)
			(void) sbd_deprobe_board(hp);
		mutex_exit(&sbp->sb_slock);
		break;

	case SBD_CMD_STATUS:
		sbd_status(hp);
		break;

	case SBD_CMD_GETNCM:
		sbd_get_ncm(hp);
		break;

	case SBD_CMD_ASSIGN:
		sbd_assign_board(hp);
		break;

	case SBD_CMD_UNASSIGN:
		sbd_unassign_board(hp);
		break;

	case SBD_CMD_POWEROFF:
		sbd_poweroff_board(hp);
		break;

	case SBD_CMD_POWERON:
		sbd_poweron_board(hp);
		break;

	case SBD_CMD_TEST:
		sbd_test_board(hp);
		break;

	case SBD_CMD_PASSTHRU:
	{
		int			rv;
		sbdp_handle_t		*hdp;
		sbderror_t		*ep = SBD_HD2ERR(hp);
		sbdp_ioctl_arg_t	ia, *iap;

		iap = &ia;

		iap->h_dev = hp->h_dev;
		iap->h_cmd = hp->h_cmd;
		iap->h_iap = (intptr_t)hp->h_iap;
		iap->h_mode = hp->h_mode;

		hdp = sbd_get_sbdp_handle(sbp, hp);
		rv = sbdp_ioctl(hdp, iap);
		if (rv != 0) {
			SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
			ep->e_errno = rv;
		}
		sbd_release_sbdp_handle(hdp);
		break;
	}

	default:
		SBD_SET_ERRNO(SBD_HD2ERR(hp), ENOTTY);
		cmn_err(CE_WARN,
			"sbd:%s: unknown command (%d)",
			f, hp->h_cmd);
		break;

	}

	if (SBD_GET_ERR(SBD_HD2ERR(hp)))
		PR_BYP("XXX e_code=%d", SBD_GET_ERR(SBD_HD2ERR(hp)));
	if (SBD_GET_ERRNO(SBD_HD2ERR(hp)))
		PR_BYP("XXX errno=%d", SBD_GET_ERRNO(SBD_HD2ERR(hp)));
}

sbd_comp_type_t
sbd_get_devtype(sbd_handle_t *hp, dev_info_t *dip)
{
	sbd_board_t	*sbp = hp ? SBDH2BD(hp->h_sbd) : NULL;
	sbd_istate_t	bstate;
	dev_info_t	**devlist;
	int		i;
	char		device[OBP_MAXDRVNAME];
	int		devicelen;

	devicelen = sizeof (device);

	bstate = sbp ? SBD_BOARD_STATE(sbp) : SBD_STATE_EMPTY;
	/*
	 * if the board's connected or configured, search the
	 * devlists.  Otherwise check the device tree
	 */
	switch (bstate) {

	case SBD_STATE_CONNECTED:
	case SBD_STATE_CONFIGURED:
	case SBD_STATE_UNREFERENCED:
	case SBD_STATE_UNCONFIGURED:
		devlist = sbp->sb_devlist[NIX(SBD_COMP_MEM)];
		for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++)
			if (devlist[i] == dip)
				return (SBD_COMP_MEM);

		devlist = sbp->sb_devlist[NIX(SBD_COMP_CPU)];
		for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++)
			if (devlist[i] == dip)
				return (SBD_COMP_CPU);

		devlist = sbp->sb_devlist[NIX(SBD_COMP_IO)];
		for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++)
			if (devlist[i] == dip)
				return (SBD_COMP_IO);
		/*FALLTHROUGH*/

	default:
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    OBP_DEVICETYPE,  (caddr_t)device, &devicelen))
			break;

		for (i = 0; SBD_COMP(i) != SBD_COMP_UNKNOWN; i++) {
			if (strcmp(device, SBD_OTYPE(i)) != 0)
				continue;
			return (SBD_COMP(i));
		}

		break;
	}
	return (SBD_COMP_UNKNOWN);
}

static void
sbd_dev_configure(sbd_handle_t *hp)
{
	int		n, unit;
	int32_t		pass, devnum;
	dev_info_t	*dip;
	sbd_devlist_t	*devlist;
	sbdp_handle_t	*hdp;
	sbd_comp_type_t	nodetype;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);

	pass = 1;

	hdp = sbd_get_sbdp_handle(sbp, hp);
	while ((devlist = sbd_get_attach_devlist(hp, &devnum, pass)) != NULL) {
		int	err;

		err = sbd_pre_attach_devlist(hp, devlist, devnum);
		if (err < 0) {
			break;
		} else if (err > 0) {
			pass++;
			continue;
		}

		for (n = 0; n < devnum; n++) {
			sbderror_t	*ep;

			ep = &devlist[n].dv_error;
			SBD_SET_ERRNO(ep, 0);
			SBD_SET_ERR(ep, 0);
			dip = devlist[n].dv_dip;
			nodetype = sbd_get_devtype(hp, dip);

			unit = sbdp_get_unit_num(hdp, dip);
			if (unit < 0) {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}

			switch (nodetype) {
			case SBD_COMP_MEM:
				sbd_attach_mem(hp, ep);
				if (SBD_GET_ERR(ep) == ESBD_CPUONLINE) {
					FREESTRUCT(devlist, sbd_devlist_t,
						MAX_MEM_UNITS_PER_BOARD);
					sbd_release_sbdp_handle(hdp);
					return;
				}
				break;

			case SBD_COMP_CPU:
				sbd_attach_cpu(hp, ep, dip, unit);
				break;

			case SBD_COMP_IO:
				sbd_attach_io(hp, ep, dip, unit);
				break;

			default:
				SBD_SET_ERRNO(ep, ENOTTY);
				break;
			}

			if (sbd_set_err_in_hdl(hp, ep) == 0)
				continue;
		}

		err = sbd_post_attach_devlist(hp, devlist, devnum);
		if (err < 0)
			break;

		pass++;
	}
	sbd_release_sbdp_handle(hdp);
}

static int
sbd_dev_release(sbd_handle_t *hp)
{
	int		n, unit;
	int32_t		pass, devnum;
	dev_info_t	*dip;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbdp_handle_t	*hdp;
	sbd_devlist_t	*devlist;
	sbd_comp_type_t	nodetype;
	int		err = 0;
	int		dev_canceled;

	pass = 1;
	hdp = sbd_get_sbdp_handle(sbp, hp);

	sbp->sb_busy = 1;
	while ((devlist =
		sbd_get_release_devlist(hp, &devnum, pass)) != NULL) {

		err = sbd_pre_release_devlist(hp, devlist, devnum);
		if (err < 0) {
			dev_canceled = 1;
			break;
		} else if (err > 0) {
			pass++;
			continue;
		}

		dev_canceled = 0;
		for (n = 0; n < devnum; n++) {
			dip = devlist[n].dv_dip;
			nodetype = sbd_get_devtype(hp, dip);

			unit = sbdp_get_unit_num(hdp, dip);
			if (unit < 0) {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}

			if ((nodetype == SBD_COMP_MEM) &&
			    sbd_release_mem(hp, dip, unit)) {

				dev_canceled++;
			}

			sbd_release_done(hp, nodetype, dip);
		}

		err = sbd_post_release_devlist(hp, devlist, devnum);

		if (err < 0)
			break;

		if (dev_canceled)
			break;

		pass++;
	}
	sbp->sb_busy = 0;

	sbd_release_sbdp_handle(hdp);

	if (dev_canceled)
		return (dev_canceled);

	return (err);
}

static int
sbd_dev_unconfigure(sbd_handle_t *hp)
{
	int		n, unit;
	int32_t		pass, devnum;
	dev_info_t	*dip;
	sbd_devlist_t	*devlist;
	sbdp_handle_t	*hdp;
	sbd_comp_type_t	nodetype;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	int		dev_canceled = 0;
	static fn_t	f = "sbd_dev_unconfigure";

	PR_ALL("%s...\n", f);

	pass = 1;
	hdp = sbd_get_sbdp_handle(sbp, hp);

	while ((devlist = sbd_get_detach_devlist(hp, &devnum, pass)) != NULL) {
		int	err, detach_err = 0;

		err = sbd_pre_detach_devlist(hp, devlist, devnum);
		if (err) {
			/*
			 * Only cancel the operation for memory in
			 * case of failure.
			 */
			nodetype = sbd_get_devtype(hp, devlist->dv_dip);
			if (nodetype == SBD_COMP_MEM)
				dev_canceled = 1;
			(void) sbd_post_detach_devlist(hp, devlist, devnum);
			break;
		}

		for (n = 0; n < devnum; n++) {
			sbderror_t	*ep;

			ep = &devlist[n].dv_error;
			SBD_SET_ERRNO(ep, 0);
			SBD_SET_ERR(ep, 0);
			dip = devlist[n].dv_dip;
			nodetype = sbd_get_devtype(hp, dip);

			unit = sbdp_get_unit_num(hdp, dip);
			if (unit < 0) {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}

			switch (nodetype) {
			case SBD_COMP_MEM:
				dev_canceled = sbd_detach_mem(hp, ep, unit);
				break;

			case SBD_COMP_CPU:
				sbd_detach_cpu(hp, ep, dip, unit);
				break;

			case SBD_COMP_IO:
				sbd_detach_io(hp, ep, dip, unit);
				break;

			default:
				SBD_SET_ERRNO(ep, ENOTTY);
				break;
			}

			if (sbd_set_err_in_hdl(hp, ep) == 0) {
				detach_err = -1;
				break;
			}

		}
		err = sbd_post_detach_devlist(hp, devlist, devnum);
		if ((err < 0) || (detach_err < 0))
			break;

		pass++;
	}

	sbd_release_sbdp_handle(hdp);
	return (dev_canceled);
}

int
sbd_errno2ecode(int error)
{
	int	rv;

	switch (error) {
	case EBUSY:
		rv = ESBD_BUSY;
		break;
	case EINVAL:
		rv = ESBD_INVAL;
		break;
	case EALREADY:
		rv = ESBD_ALREADY;
		break;
	case ENODEV:
		rv = ESBD_NODEV;
		break;
	case ENOMEM:
		rv = ESBD_NOMEM;
		break;
	default:
		rv = ESBD_INVAL;
	}

	return (rv);
}

static void
sbd_attach_cpu(sbd_handle_t *hp, sbderror_t *ep, dev_info_t *dip, int unit)
{
	int rv = 0;
	processorid_t	cpuid;
	sbdp_handle_t	*hdp;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	static fn_t	f = "sbd_attach_cpu";
	char		*pathname;

	ASSERT(MUTEX_HELD(&cpu_lock));

	ASSERT(dip);

	/*
	 * With the introduction of CMP devices, the CPU nodes
	 * are no longer directly under the top node. Since
	 * there is no plan to support CPU attach in the near
	 * future, a branch configure operation is not required.
	 */

	hdp = sbd_get_sbdp_handle(sbp, hp);
	cpuid = sbdp_get_cpuid(hdp, dip);
	if (cpuid < 0) {
		rv = -1;
		SBD_GET_PERR(hdp->h_err, ep);
	} else if ((rv = cpu_configure(cpuid)) != 0) {
		cmn_err(CE_WARN,
			"sbd:%s: cpu_configure for cpuid %d failed",
			f, cpuid);
		SBD_SET_ERR(ep, sbd_errno2ecode(rv));
	}
	sbd_release_sbdp_handle(hdp);

	if (rv == 0) {
		ASSERT(sbp->sb_cpupath[unit] != NULL);
		pathname = sbp->sb_cpupath[unit];
		(void) ddi_pathname(dip, pathname);
	}
}

/*
 *	translate errno
 */
void
sbd_errno_decode(int err, sbderror_t *ep, dev_info_t *dip)
{
	ASSERT(err != 0);

	switch (err) {
	case ENOMEM:
		SBD_SET_ERR(ep, ESBD_NOMEM);
		break;

	case EBUSY:
		SBD_SET_ERR(ep, ESBD_BUSY);
		break;

	case EIO:
		SBD_SET_ERR(ep, ESBD_IO);
		break;

	case ENXIO:
		SBD_SET_ERR(ep, ESBD_NODEV);
		break;

	case EINVAL:
		SBD_SET_ERR(ep, ESBD_INVAL);
		break;

	case EFAULT:
	default:
		SBD_SET_ERR(ep, ESBD_FAULT);
		break;
	}

	(void) ddi_pathname(dip, SBD_GET_ERRSTR(ep));
}

static void
sbd_detach_cpu(sbd_handle_t *hp, sbderror_t *ep, dev_info_t *dip, int unit)
{
	processorid_t	cpuid;
	int		rv;
	sbdp_handle_t	*hdp;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbd_error_t	*spe;
	static fn_t	f = "sbd_detach_cpu";

	ASSERT(MUTEX_HELD(&cpu_lock));

	ASSERT(dip);
	hdp = sbd_get_sbdp_handle(sbp, hp);
	spe = hdp->h_err;
	cpuid = sbdp_get_cpuid(hdp, dip);
	if (cpuid < 0) {
		SBD_GET_PERR(spe, ep);
		sbd_release_sbdp_handle(hdp);
		return;
	}

	if ((rv = cpu_unconfigure(cpuid)) != 0) {
		SBD_SET_ERR(ep, sbd_errno2ecode(rv));
		SBD_SET_ERRSTR(ep, sbp->sb_cpupath[unit]);
		cmn_err(CE_WARN,
			"sbd:%s: cpu_unconfigure for cpu %d failed",
			f, cpuid);
		sbd_release_sbdp_handle(hdp);
		return;
	}
	sbd_release_sbdp_handle(hdp);

	/*
	 * Since CPU nodes are no longer configured in CPU
	 * attach, the corresponding branch unconfigure
	 * operation that would be performed here is also
	 * no longer required.
	 */
}


int
sbd_detach_mem(sbd_handle_t *hp, sbderror_t *ep, int unit)
{
	sbd_mem_unit_t	*mp;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	int		i, rv;
	static fn_t	f = "sbd_detach_mem";

	mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

	if (sbd_detach_memory(hp, ep, mp, unit)) {
		cmn_err(CE_WARN, "%s: detach fail", f);
		return (-1);
	}

	/*
	 * Now detach mem devinfo nodes with status lock held.
	 */
	for (i = 0; i < SBD_NUM_MC_PER_BOARD; i++) {
		dev_info_t	*fdip = NULL;

		if (mp->sbm_dip[i] == NULL)
			continue;
		ASSERT(e_ddi_branch_held(mp->sbm_dip[i]));
		mutex_enter(&sbp->sb_slock);
		rv = e_ddi_branch_unconfigure(mp->sbm_dip[i], &fdip,
		    DEVI_BRANCH_EVENT);
		mutex_exit(&sbp->sb_slock);
		if (rv) {
			/*
			 * If non-NULL, fdip is returned held and must be
			 * released.
			 */
			if (fdip != NULL) {
				sbd_errno_decode(rv, ep, fdip);
				ddi_release_devi(fdip);
			} else {
				sbd_errno_decode(rv, ep, mp->sbm_dip[i]);
			}
		}
	}

	return (0);
}

/* start beginning of sbd.c */

/*
 * MDR          memory support - somewhat disabled for now.
 * UNSAFE       unsafe driver code - I don't think we want this.
 *              need to check.
 * DEVNODE      This driver creates attachment points for individual
 *              components as well as boards.  We only need board
 *              support.
 * DEV2DEVSET   Put only present devices in devset.
 */


static sbd_state_t
rstate_cvt(sbd_istate_t state)
{
	sbd_state_t cs;

	switch (state) {
	case SBD_STATE_EMPTY:
		cs = SBD_STAT_EMPTY;
		break;
	case SBD_STATE_OCCUPIED:
	case SBD_STATE_FATAL:
		cs = SBD_STAT_DISCONNECTED;
		break;
	case SBD_STATE_CONFIGURED:
	case SBD_STATE_CONNECTED:
	case SBD_STATE_UNCONFIGURED:
	case SBD_STATE_PARTIAL:
	case SBD_STATE_RELEASE:
	case SBD_STATE_UNREFERENCED:
		cs = SBD_STAT_CONNECTED;
		break;
	default:
		cs = SBD_STAT_NONE;
		break;
	}

	return (cs);
}


sbd_state_t
ostate_cvt(sbd_istate_t state)
{
	sbd_state_t cs;

	switch (state) {
	case SBD_STATE_EMPTY:
	case SBD_STATE_OCCUPIED:
	case SBD_STATE_UNCONFIGURED:
	case SBD_STATE_CONNECTED:
	case SBD_STATE_FATAL:
		cs = SBD_STAT_UNCONFIGURED;
		break;
	case SBD_STATE_PARTIAL:
	case SBD_STATE_CONFIGURED:
	case SBD_STATE_RELEASE:
	case SBD_STATE_UNREFERENCED:
		cs = SBD_STAT_CONFIGURED;
		break;
	default:
		cs = SBD_STAT_NONE;
		break;
	}

	return (cs);
}

int
sbd_dealloc_instance(sbd_board_t *sbp, int max_boards)
{
	int		b;
	sbd_board_t    *list = sbp;
	static fn_t	f = "sbd_dealloc_instance";

	PR_ALL("%s...\n", f);

	if (sbp == NULL) {
		return (-1);
	}

	for (b = 0; b < max_boards; b++) {
		sbd_board_destroy(sbp++);
	}

	FREESTRUCT(list, sbd_board_t, max_boards);

	return (0);
}

static sbd_devset_t
sbd_dev2devset(sbd_comp_id_t *cid)
{
	static fn_t	f = "sbd_dev2devset";

	sbd_devset_t	devset;
	int		unit = cid->c_unit;

	switch (cid->c_type) {
		case SBD_COMP_NONE:
			devset =  DEVSET(SBD_COMP_CPU, DEVSET_ANYUNIT);
			devset |= DEVSET(SBD_COMP_MEM, DEVSET_ANYUNIT);
			devset |= DEVSET(SBD_COMP_IO,  DEVSET_ANYUNIT);
			break;

		case SBD_COMP_CPU:
			if ((unit > MAX_CPU_UNITS_PER_BOARD) || (unit < 0)) {
				PR_ALL("%s: invalid cpu unit# = %d",
					f, unit);
				devset = 0;
			} else
				/*
				 * Generate a devset that includes all the
				 * cores of a CMP device. If this is not a
				 * CMP, the extra cores will be eliminated
				 * later since they are not present. This is
				 * also true for CMP devices that do not have
				 * all cores active.
				 */
				devset = DEVSET(SBD_COMP_CMP, unit);

			break;

		case SBD_COMP_MEM:

			if ((unit > MAX_MEM_UNITS_PER_BOARD) || (unit < 0)) {
#ifdef XXX_jeffco
				PR_ALL("%s: invalid mem unit# = %d",
					f, unit);
				devset = 0;
#endif
				devset = DEVSET(cid->c_type, 0);
				PR_ALL("%s: adjusted MEM devset = 0x%x\n",
					f, devset);
			} else
				devset = DEVSET(cid->c_type, unit);
			break;

		case SBD_COMP_IO:
			if ((unit > MAX_IO_UNITS_PER_BOARD) || (unit < 0)) {
				PR_ALL("%s: invalid io unit# = %d",
					f, unit);
				devset = 0;
			} else
				devset = DEVSET(cid->c_type, unit);

			break;

		default:
		case SBD_COMP_UNKNOWN:
			devset = 0;
			break;
	}

	return (devset);
}

/*
 * Simple mutex for covering handle list ops as it is only
 * used "infrequently". No need to add another mutex to the sbd_board_t.
 */
static kmutex_t sbd_handle_list_mutex;

static sbd_handle_t *
sbd_get_handle(dev_t dev, sbd_softstate_t *softsp, intptr_t arg,
	sbd_init_arg_t *iap)
{
	sbd_handle_t		*hp;
	sbderror_t		*ep;
	sbd_priv_handle_t	*shp;
	sbd_board_t		*sbp = softsp->sbd_boardlist;
	int			board;

	board = SBDGETSLOT(dev);
	ASSERT(board < softsp->max_boards);
	sbp += board;

	/*
	 * Brand-new handle.
	 */
	shp = kmem_zalloc(sizeof (sbd_priv_handle_t), KM_SLEEP);
	shp->sh_arg = (void *)arg;

	hp = MACHHD2HD(shp);

	ep = &shp->sh_err;

	hp->h_err = ep;
	hp->h_sbd = (void *) sbp;
	hp->h_dev = iap->dev;
	hp->h_cmd = iap->cmd;
	hp->h_mode = iap->mode;
	sbd_init_err(ep);

	mutex_enter(&sbd_handle_list_mutex);
	shp->sh_next = sbp->sb_handle;
	sbp->sb_handle = shp;
	mutex_exit(&sbd_handle_list_mutex);

	return (hp);
}

void
sbd_init_err(sbderror_t *ep)
{
	ep->e_errno = 0;
	ep->e_code = 0;
	ep->e_rsc[0] = '\0';
}

int
sbd_set_err_in_hdl(sbd_handle_t *hp, sbderror_t *ep)
{
	sbderror_t	*hep = SBD_HD2ERR(hp);

	/*
	 * If there is an error logged already, don't rewrite it
	 */
	if (SBD_GET_ERR(hep) || SBD_GET_ERRNO(hep)) {
		return (0);
	}

	if (SBD_GET_ERR(ep) || SBD_GET_ERRNO(ep)) {
		SBD_SET_ERR(hep, SBD_GET_ERR(ep));
		SBD_SET_ERRNO(hep, SBD_GET_ERRNO(ep));
		SBD_SET_ERRSTR(hep, SBD_GET_ERRSTR(ep));
		return (0);
	}

	return (-1);
}

static void
sbd_release_handle(sbd_handle_t *hp)
{
	sbd_priv_handle_t	*shp, **shpp;
	sbd_board_t		*sbp;
	static fn_t		f = "sbd_release_handle";

	if (hp == NULL)
		return;

	sbp = SBDH2BD(hp->h_sbd);

	shp = HD2MACHHD(hp);

	mutex_enter(&sbd_handle_list_mutex);
	/*
	 * Locate the handle in the board's reference list.
	 */
	for (shpp = &sbp->sb_handle; (*shpp) && ((*shpp) != shp);
	    shpp = &((*shpp)->sh_next))
		/* empty */;

	if (*shpp == NULL) {
		cmn_err(CE_PANIC,
			"sbd:%s: handle not found in board %d",
			f, sbp->sb_num);
		/*NOTREACHED*/
	} else {
		*shpp = shp->sh_next;
	}
	mutex_exit(&sbd_handle_list_mutex);

	if (hp->h_opts.copts != NULL) {
		FREESTRUCT(hp->h_opts.copts, char, hp->h_opts.size);
	}

	FREESTRUCT(shp, sbd_priv_handle_t, 1);
}

sbdp_handle_t *
sbd_get_sbdp_handle(sbd_board_t *sbp, sbd_handle_t *hp)
{
	sbdp_handle_t		*hdp;

	hdp = kmem_zalloc(sizeof (sbdp_handle_t), KM_SLEEP);
	hdp->h_err = kmem_zalloc(sizeof (sbd_error_t), KM_SLEEP);
	if (sbp == NULL) {
		hdp->h_board = -1;
		hdp->h_wnode = -1;
	} else {
		hdp->h_board = sbp->sb_num;
		hdp->h_wnode = sbp->sb_wnode;
	}

	if (hp == NULL) {
		hdp->h_flags = 0;
		hdp->h_opts = NULL;
	} else {
		hdp->h_flags = SBD_2_SBDP_FLAGS(hp->h_flags);
		hdp->h_opts = &hp->h_opts;
	}

	return (hdp);
}

void
sbd_release_sbdp_handle(sbdp_handle_t *hdp)
{
	if (hdp == NULL)
		return;

	kmem_free(hdp->h_err, sizeof (sbd_error_t));
	kmem_free(hdp, sizeof (sbdp_handle_t));
}

void
sbd_reset_error_sbdph(sbdp_handle_t *hdp)
{
	if ((hdp != NULL) && (hdp->h_err != NULL)) {
		bzero(hdp->h_err, sizeof (sbd_error_t));
	}
}

static int
sbd_copyin_ioarg(sbd_handle_t *hp, int mode, int cmd, sbd_cmd_t *cmdp,
	sbd_ioctl_arg_t *iap)
{
	static fn_t	f = "sbd_copyin_ioarg";

	if (iap == NULL)
		return (EINVAL);

	bzero((caddr_t)cmdp, sizeof (sbd_cmd_t));

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		sbd_cmd32_t	scmd32;

		bzero((caddr_t)&scmd32, sizeof (sbd_cmd32_t));

		if (ddi_copyin((void *)iap, (void *)&scmd32,
				sizeof (sbd_cmd32_t), mode)) {
			cmn_err(CE_WARN,
				"sbd:%s: (32bit) failed to copyin "
					"sbdcmd-struct", f);
			return (EFAULT);
		}
		cmdp->cmd_cm.c_id.c_type = scmd32.cmd_cm.c_id.c_type;
		cmdp->cmd_cm.c_id.c_unit = scmd32.cmd_cm.c_id.c_unit;
		bcopy(&scmd32.cmd_cm.c_id.c_name[0],
			&cmdp->cmd_cm.c_id.c_name[0], OBP_MAXPROPNAME);
		cmdp->cmd_cm.c_flags = scmd32.cmd_cm.c_flags;
		cmdp->cmd_cm.c_len = scmd32.cmd_cm.c_len;
		cmdp->cmd_cm.c_opts = (caddr_t)(uintptr_t)scmd32.cmd_cm.c_opts;

		if (cmd == SBD_CMD_PASSTHRU) {
			PR_BYP("passthru copyin: iap=%p, sz=%ld", (void *)iap,
				sizeof (sbd_cmd32_t));
			PR_BYP("passthru copyin: c_opts=%x, c_len=%d",
				scmd32.cmd_cm.c_opts,
				scmd32.cmd_cm.c_len);
		}

		switch (cmd) {
		case SBD_CMD_STATUS:
			cmdp->cmd_stat.s_nbytes = scmd32.cmd_stat.s_nbytes;
			cmdp->cmd_stat.s_statp =
				(caddr_t)(uintptr_t)scmd32.cmd_stat.s_statp;
			break;
		default:
			break;

		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)iap, (void *)cmdp,
			sizeof (sbd_cmd_t), mode) != 0) {
		cmn_err(CE_WARN,
			"sbd:%s: failed to copyin sbd cmd_t struct", f);
		return (EFAULT);
	}
	/*
	 * A user may set platform specific options so we need to
	 * copy them in
	 */
	if ((cmd != SBD_CMD_STATUS) && ((hp->h_opts.size = cmdp->cmd_cm.c_len)
	    > 0)) {
		hp->h_opts.size += 1;	/* For null termination of string. */
		hp->h_opts.copts = GETSTRUCT(char, hp->h_opts.size);
		if (ddi_copyin((void *)cmdp->cmd_cm.c_opts,
		    (void *)hp->h_opts.copts,
		    cmdp->cmd_cm.c_len, hp->h_mode) != 0) {
			/* copts is freed in sbd_release_handle(). */
			cmn_err(CE_WARN,
			    "sbd:%s: failed to copyin options", f);
			return (EFAULT);
		}
	}

	return (0);
}

static int
sbd_copyout_ioarg(int mode, int cmd, sbd_cmd_t *scp, sbd_ioctl_arg_t *iap)
{
	static fn_t	f = "sbd_copyout_ioarg";

	if ((iap == NULL) || (scp == NULL))
		return (EINVAL);

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		sbd_cmd32_t	scmd32;

		scmd32.cmd_cm.c_id.c_type = scp->cmd_cm.c_id.c_type;
		scmd32.cmd_cm.c_id.c_unit = scp->cmd_cm.c_id.c_unit;
		bcopy(scp->cmd_cm.c_id.c_name,
			scmd32.cmd_cm.c_id.c_name, OBP_MAXPROPNAME);

		scmd32.cmd_cm.c_flags = scp->cmd_cm.c_flags;

		switch (cmd) {
		case SBD_CMD_GETNCM:
			scmd32.cmd_getncm.g_ncm = scp->cmd_getncm.g_ncm;
			break;
		default:
			break;
		}

		if (ddi_copyout((void *)&scmd32, (void *)iap,
				sizeof (sbd_cmd32_t), mode)) {
			cmn_err(CE_WARN,
				"sbd:%s: (32bit) failed to copyout "
					"sbdcmd struct", f);
			return (EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout((void *)scp, (void *)iap,
			sizeof (sbd_cmd_t), mode) != 0) {
		cmn_err(CE_WARN,
			"sbd:%s: failed to copyout sbdcmd struct", f);
		return (EFAULT);
	}

	return (0);
}

static int
sbd_copyout_errs(int mode, sbd_ioctl_arg_t *iap, void *arg)
{
	static fn_t	f = "sbd_copyout_errs";
	sbd_ioctl_arg_t	*uap;

	uap = (sbd_ioctl_arg_t *)arg;

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		sbd_error32_t err32;
		sbd_ioctl_arg32_t *uap32;

		uap32 = (sbd_ioctl_arg32_t *)arg;

		err32.e_code = iap->ie_code;
		(void) strcpy(err32.e_rsc, iap->ie_rsc);

		if (ddi_copyout((void *)&err32, (void *)&uap32->i_err,
				sizeof (sbd_error32_t), mode)) {
			cmn_err(CE_WARN,
				"sbd:%s: failed to copyout ioctl32 errs",
				f);
			return (EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout((void *)&iap->i_err, (void *)&uap->i_err,
			sizeof (sbd_error_t), mode) != 0) {
		cmn_err(CE_WARN,
			"sbd:%s: failed to copyout ioctl errs", f);
		return (EFAULT);
	}

	return (0);
}

/*
 * State transition policy is that if at least one
 * device cannot make the transition, then none of
 * the requested devices are allowed to transition.
 *
 * Returns the state that is in error, if any.
 */
static int
sbd_check_transition(sbd_board_t *sbp, sbd_devset_t *devsetp,
			struct sbd_state_trans *transp)
{
	int	s, ut;
	int	state_err = 0;
	sbd_devset_t	devset;
	static fn_t	f = "sbd_check_transition";

	devset = *devsetp;

	if (!devset) {
		/*
		 * Transition does not deal with any components.
		 * This is the case for addboard/deleteboard.
		 */
		PR_ALL("%s: no devs: requested devset = 0x%x,"
			" final devset = 0x%x\n",
			f, (uint_t)*devsetp, (uint_t)devset);

		return (0);
	}

	if (DEVSET_IN_SET(devset, SBD_COMP_MEM, DEVSET_ANYUNIT)) {
		for (ut = 0; ut < MAX_MEM_UNITS_PER_BOARD; ut++) {
			if (DEVSET_IN_SET(devset, SBD_COMP_MEM, ut) == 0)
				continue;
			s = (int)SBD_DEVICE_STATE(sbp, SBD_COMP_MEM, ut);
			if (transp->x_op[s].x_rv) {
				if (!state_err)
					state_err = s;
				DEVSET_DEL(devset, SBD_COMP_MEM, ut);
			}
		}
	}

	if (DEVSET_IN_SET(devset, SBD_COMP_CPU, DEVSET_ANYUNIT)) {
		for (ut = 0; ut < MAX_CPU_UNITS_PER_BOARD; ut++) {
			if (DEVSET_IN_SET(devset, SBD_COMP_CPU, ut) == 0)
				continue;
			s = (int)SBD_DEVICE_STATE(sbp, SBD_COMP_CPU, ut);
			if (transp->x_op[s].x_rv) {
				if (!state_err)
					state_err = s;
				DEVSET_DEL(devset, SBD_COMP_CPU, ut);
			}
		}
	}

	if (DEVSET_IN_SET(devset, SBD_COMP_IO, DEVSET_ANYUNIT)) {
		for (ut = 0; ut < MAX_IO_UNITS_PER_BOARD; ut++) {
			if (DEVSET_IN_SET(devset, SBD_COMP_IO, ut) == 0)
				continue;
			s = (int)SBD_DEVICE_STATE(sbp, SBD_COMP_IO, ut);
			if (transp->x_op[s].x_rv) {
				if (!state_err)
					state_err = s;
				DEVSET_DEL(devset, SBD_COMP_IO, ut);
			}
		}
	}

	PR_ALL("%s: requested devset = 0x%x, final devset = 0x%x\n",
		f, (uint_t)*devsetp, (uint_t)devset);

	*devsetp = devset;
	/*
	 * If there are some remaining components for which
	 * this state transition is valid, then allow them
	 * through, otherwise if none are left then return
	 * the state error.
	 */
	return (devset ? 0 : state_err);
}

/*
 * pre-op entry point must SET_ERRNO(), if needed.
 * Return value of non-zero indicates failure.
 */
static int
sbd_pre_op(sbd_handle_t *hp)
{
	int		rv = 0, t;
	int		cmd, serr = 0;
	sbd_devset_t	devset;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbd_priv_handle_t	*shp = HD2MACHHD(hp);
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbd_cmd_t	*cmdp;
	static fn_t	f = "sbd_pre_op";

	cmd = hp->h_cmd;
	devset = shp->sh_devset;

	switch (cmd) {
		case SBD_CMD_CONNECT:
		case SBD_CMD_DISCONNECT:
		case SBD_CMD_UNCONFIGURE:
		case SBD_CMD_CONFIGURE:
		case SBD_CMD_ASSIGN:
		case SBD_CMD_UNASSIGN:
		case SBD_CMD_POWERON:
		case SBD_CMD_POWEROFF:
		case SBD_CMD_TEST:
		/* ioctls allowed if caller has write permission */
		if (!(hp->h_mode & FWRITE)) {
			SBD_SET_ERRNO(ep, EPERM);
			return (-1);
		}

		default:
		break;
	}

	hp->h_iap = GETSTRUCT(sbd_ioctl_arg_t, 1);
	rv = sbd_copyin_ioarg(hp, hp->h_mode, cmd,
		(sbd_cmd_t *)hp->h_iap, shp->sh_arg);
	if (rv) {
		SBD_SET_ERRNO(ep, rv);
		FREESTRUCT(hp->h_iap, sbd_ioctl_arg_t, 1);
		hp->h_iap = NULL;
		cmn_err(CE_WARN, "%s: copyin fail", f);
		return (-1);
	} else {
		cmdp =  (sbd_cmd_t *)hp->h_iap;
		if (cmdp->cmd_cm.c_id.c_name[0] != '\0') {

			cmdp->cmd_cm.c_id.c_type = SBD_COMP(sbd_name_to_idx(
				cmdp->cmd_cm.c_id.c_name));
			if (cmdp->cmd_cm.c_id.c_type == SBD_COMP_MEM) {
				if (cmdp->cmd_cm.c_id.c_unit == -1)
					cmdp->cmd_cm.c_id.c_unit = 0;
			}
		}
		devset = shp->sh_orig_devset = shp->sh_devset =
		    sbd_dev2devset(&cmdp->cmd_cm.c_id);
		if (devset == 0) {
			SBD_SET_ERRNO(ep, EINVAL);
			FREESTRUCT(hp->h_iap, sbd_ioctl_arg_t, 1);
			hp->h_iap = NULL;
			return (-1);
		}
	}

	/*
	 * Always turn on these bits ala Sunfire DR.
	 */
	hp->h_flags |= SBD_FLAG_DEVI_FORCE;

	if (cmdp->cmd_cm.c_flags & SBD_FLAG_FORCE)
		hp->h_flags |= SBD_IOCTL_FLAG_FORCE;

	/*
	 * Check for valid state transitions.
	 */
	if (!serr && ((t = CMD2INDEX(cmd)) != -1)) {
		struct sbd_state_trans	*transp;
		int			state_err;

		transp = &sbd_state_transition[t];
		ASSERT(transp->x_cmd == cmd);

		state_err = sbd_check_transition(sbp, &devset, transp);

		if (state_err < 0) {
			/*
			 * Invalidate device.
			 */
			SBD_SET_ERRNO(ep, ENOTTY);
			serr = -1;
			PR_ALL("%s: invalid devset (0x%x)\n",
				f, (uint_t)devset);
		} else if (state_err != 0) {
			/*
			 * State transition is not a valid one.
			 */
			SBD_SET_ERRNO(ep, transp->x_op[state_err].x_err);
			serr = transp->x_op[state_err].x_rv;
			PR_ALL("%s: invalid state %s(%d) for cmd %s(%d)\n",
				f, sbd_state_str[state_err], state_err,
				SBD_CMD_STR(cmd), cmd);
		}
		if (serr && SBD_GET_ERRNO(ep) != 0) {
			/*
			 * A state transition error occurred.
			 */
			if (serr < 0) {
				SBD_SET_ERR(ep, ESBD_INVAL);
			} else {
				SBD_SET_ERR(ep, ESBD_STATE);
			}
			PR_ALL("%s: invalid state transition\n", f);
		} else {
			shp->sh_devset = devset;
		}
	}

	if (serr && !rv && hp->h_iap) {

		/*
		 * There was a state error.  We successfully copied
		 * in the ioctl argument, so let's fill in the
		 * error and copy it back out.
		 */

		if (SBD_GET_ERR(ep) && SBD_GET_ERRNO(ep) == 0)
			SBD_SET_ERRNO(ep, EIO);

		SBD_SET_IOCTL_ERR(&hp->h_iap->i_err,
			ep->e_code,
			ep->e_rsc);
		(void) sbd_copyout_errs(hp->h_mode, hp->h_iap, shp->sh_arg);
		FREESTRUCT(hp->h_iap, sbd_ioctl_arg_t, 1);
		hp->h_iap = NULL;
		rv = -1;
	}

	return (rv);
}

static void
sbd_post_op(sbd_handle_t *hp)
{
	int		cmd;
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbd_priv_handle_t	*shp = HD2MACHHD(hp);
	sbd_board_t    *sbp = SBDH2BD(hp->h_sbd);

	cmd = hp->h_cmd;

	switch (cmd) {
		case SBD_CMD_CONFIGURE:
		case SBD_CMD_UNCONFIGURE:
		case SBD_CMD_CONNECT:
		case SBD_CMD_DISCONNECT:
			sbp->sb_time = gethrestime_sec();
			break;

		default:
			break;
	}

	if (SBD_GET_ERR(ep) && SBD_GET_ERRNO(ep) == 0) {
		SBD_SET_ERRNO(ep, EIO);
	}

	if (shp->sh_arg != NULL) {

		if (SBD_GET_ERR(ep) != ESBD_NOERROR) {

			SBD_SET_IOCTL_ERR(&hp->h_iap->i_err,
				ep->e_code,
				ep->e_rsc);

			(void) sbd_copyout_errs(hp->h_mode, hp->h_iap,
					shp->sh_arg);
		}

		if (hp->h_iap != NULL) {
			FREESTRUCT(hp->h_iap, sbd_ioctl_arg_t, 1);
			hp->h_iap = NULL;
		}
	}
}

static int
sbd_probe_board(sbd_handle_t *hp)
{
	int		rv;
	sbd_board_t    *sbp;
	sbdp_handle_t	*hdp;
	static fn_t	f = "sbd_probe_board";

	sbp = SBDH2BD(hp->h_sbd);

	ASSERT(sbp != NULL);
	PR_ALL("%s for board %d", f, sbp->sb_num);


	hdp = sbd_get_sbdp_handle(sbp, hp);

	if ((rv = sbdp_connect_board(hdp)) != 0) {
		sbderror_t	*ep = SBD_HD2ERR(hp);

		SBD_GET_PERR(hdp->h_err, ep);
	}

	/*
	 * We need to force a recache after the connect.  The cached
	 * info may be incorrect
	 */
	mutex_enter(&sbp->sb_flags_mutex);
	sbp->sb_flags &= ~SBD_BOARD_STATUS_CACHED;
	mutex_exit(&sbp->sb_flags_mutex);

	SBD_INJECT_ERR(SBD_PROBE_BOARD_PSEUDO_ERR, hp->h_err, EIO,
		ESGT_PROBE, NULL);

	sbd_release_sbdp_handle(hdp);

	return (rv);
}

static int
sbd_deprobe_board(sbd_handle_t *hp)
{
	int		rv;
	sbdp_handle_t	*hdp;
	sbd_board_t	*sbp;
	static fn_t	f = "sbd_deprobe_board";

	PR_ALL("%s...\n", f);

	sbp = SBDH2BD(hp->h_sbd);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	if ((rv = sbdp_disconnect_board(hdp)) != 0) {
		sbderror_t	*ep = SBD_HD2ERR(hp);

		SBD_GET_PERR(hdp->h_err, ep);
	}

	mutex_enter(&sbp->sb_flags_mutex);
	sbp->sb_flags &= ~SBD_BOARD_STATUS_CACHED;
	mutex_exit(&sbp->sb_flags_mutex);

	SBD_INJECT_ERR(SBD_DEPROBE_BOARD_PSEUDO_ERR, hp->h_err, EIO,
		ESGT_DEPROBE, NULL);

	sbd_release_sbdp_handle(hdp);
	return (rv);
}

/*
 * Check if a CPU node is part of a CMP.
 */
int
sbd_is_cmp_child(dev_info_t *dip)
{
	dev_info_t *pdip;

	if (strcmp(ddi_node_name(dip), "cpu") != 0) {
		return (0);
	}

	pdip = ddi_get_parent(dip);

	ASSERT(pdip);

	if (strcmp(ddi_node_name(pdip), "cmp") == 0) {
		return (1);
	}

	return (0);
}

/*
 * Returns the nodetype if dip is a top dip on the board of
 * interest or SBD_COMP_UNKNOWN otherwise
 */
static sbd_comp_type_t
get_node_type(sbd_board_t *sbp, dev_info_t *dip, int *unitp)
{
	int		idx, unit;
	sbd_handle_t	*hp;
	sbdp_handle_t	*hdp;
	char		otype[OBP_MAXDRVNAME];
	int		otypelen;

	ASSERT(sbp);

	if (unitp)
		*unitp = -1;

	hp = MACHBD2HD(sbp);

	hdp = sbd_get_sbdp_handle(sbp, hp);
	if (sbdp_get_board_num(hdp, dip) != sbp->sb_num) {
		sbd_release_sbdp_handle(hdp);
		return (SBD_COMP_UNKNOWN);
	}

	/*
	 * sbdp_get_unit_num will return (-1) for cmp as there
	 * is no "device_type" property associated with cmp.
	 * Therefore we will just skip getting unit number for
	 * cmp.  Callers of this function need to check the
	 * value set in unitp before using it to dereference
	 * an array.
	 */
	if (strcmp(ddi_node_name(dip), "cmp") == 0) {
		sbd_release_sbdp_handle(hdp);
		return (SBD_COMP_CMP);
	}

	otypelen = sizeof (otype);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_DEVICETYPE,  (caddr_t)otype, &otypelen)) {
		sbd_release_sbdp_handle(hdp);
		return (SBD_COMP_UNKNOWN);
	}

	idx = sbd_otype_to_idx(otype);

	if (SBD_COMP(idx) == SBD_COMP_UNKNOWN) {
		sbd_release_sbdp_handle(hdp);
		return (SBD_COMP_UNKNOWN);
	}

	unit = sbdp_get_unit_num(hdp, dip);
	if (unit == -1) {
		cmn_err(CE_WARN,
			"get_node_type: %s unit fail %p", otype, (void *)dip);
		sbd_release_sbdp_handle(hdp);
		return (SBD_COMP_UNKNOWN);
	}

	sbd_release_sbdp_handle(hdp);

	if (unitp)
		*unitp = unit;

	return (SBD_COMP(idx));
}

typedef struct {
	sbd_board_t	*sbp;
	int		nmc;
	int		hold;
} walk_tree_t;

static int
sbd_setup_devlists(dev_info_t *dip, void *arg)
{
	walk_tree_t	*wp;
	dev_info_t	**devlist = NULL;
	char		*pathname = NULL;
	sbd_mem_unit_t	*mp;
	static fn_t	f = "sbd_setup_devlists";
	sbd_board_t	*sbp;
	int		unit;
	sbd_comp_type_t nodetype;

	ASSERT(dip);

	wp = (walk_tree_t *)arg;

	if (wp == NULL) {
		PR_ALL("%s:bad arg\n", f);
		return (DDI_WALK_TERMINATE);
	}

	sbp = wp->sbp;

	nodetype = get_node_type(sbp, dip, &unit);

	switch (nodetype) {

	case SBD_COMP_CPU:
		pathname = sbp->sb_cpupath[unit];
		break;

	case SBD_COMP_MEM:
		pathname = sbp->sb_mempath[unit];
		break;

	case SBD_COMP_IO:
		pathname = sbp->sb_iopath[unit];
		break;

	case SBD_COMP_CMP:
	case SBD_COMP_UNKNOWN:
		/*
		 * This dip is not of interest to us
		 */
		return (DDI_WALK_CONTINUE);

	default:
		ASSERT(0);
		return (DDI_WALK_CONTINUE);
	}

	/*
	 * dip's parent is being held busy by ddi_walk_devs(),
	 * so dip doesn't have to be held while calling ddi_pathname()
	 */
	if (pathname) {
		(void) ddi_pathname(dip, pathname);
	}

	devlist = sbp->sb_devlist[NIX(nodetype)];

	/*
	 * The branch rooted at dip should already be held,
	 * unless we are dealing with a core of a CMP.
	 */
	ASSERT(sbd_is_cmp_child(dip) || e_ddi_branch_held(dip));
	devlist[unit] = dip;

	/*
	 * This test is required if multiple devices are considered
	 * as one. This is the case for memory-controller nodes.
	 */
	if (!SBD_DEV_IS_PRESENT(sbp, nodetype, unit)) {
		sbp->sb_ndev++;
		SBD_DEV_SET_PRESENT(sbp, nodetype, unit);
	}

	if (nodetype == SBD_COMP_MEM) {
		mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);
		ASSERT(wp->nmc < SBD_NUM_MC_PER_BOARD);
		mp->sbm_dip[wp->nmc++] = dip;
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * This routine is used to construct the memory devlist.
 * In Starcat and Serengeti platforms, a system board can contain up to
 * four memory controllers (MC).  The MCs have been programmed by POST for
 * optimum memory interleaving amongst their peers on the same board.
 * This DR driver does not support deinterleaving.  Therefore, the smallest
 * unit of memory that can be manipulated by this driver is all of the
 * memory on a board.  Because of this restriction, a board's memory devlist
 * is populated with only one of the four (possible) MC dnodes on that board.
 * Care must be taken to ensure that the selected MC dnode represents the
 * lowest physical address to which memory on the board will respond to.
 * This is required in order to preserve the semantics of
 * sbdp_get_base_physaddr() when applied to a MC dnode stored in the
 * memory devlist.
 */
static void
sbd_init_mem_devlists(sbd_board_t *sbp)
{
	dev_info_t	**devlist;
	sbd_mem_unit_t	*mp;
	dev_info_t	*mc_dip;
	sbdp_handle_t	*hdp;
	uint64_t	mc_pa, lowest_pa;
	int		i;
	sbd_handle_t	*hp = MACHBD2HD(sbp);

	devlist = sbp->sb_devlist[NIX(SBD_COMP_MEM)];

	mp = SBD_GET_BOARD_MEMUNIT(sbp, 0);

	mc_dip = mp->sbm_dip[0];
	if (mc_dip == NULL)
		return;		/* No MC dips found for this board */

	hdp = sbd_get_sbdp_handle(sbp, hp);

	if (sbdphw_get_base_physaddr(hdp, mc_dip, &mc_pa)) {
		/* TODO: log complaint about dnode */

pretend_no_mem:
		/*
		 * We are here because sbdphw_get_base_physaddr() failed.
		 * Although it is very unlikely to happen, it did.  Lucky us.
		 * Since we can no longer examine _all_ of the MCs on this
		 * board to determine which one is programmed to the lowest
		 * physical address, we cannot involve any of the MCs on
		 * this board in DR operations.  To ensure this, we pretend
		 * that this board does not contain any memory.
		 *
		 * Paranoia: clear the dev_present mask.
		 */
		if (SBD_DEV_IS_PRESENT(sbp, SBD_COMP_MEM, 0)) {
			ASSERT(sbp->sb_ndev != 0);
			SBD_DEV_CLR_PRESENT(sbp, SBD_COMP_MEM, 0);
			sbp->sb_ndev--;
		}

		for (i = 0; i < SBD_NUM_MC_PER_BOARD; i++) {
			mp->sbm_dip[i] = NULL;
		}

		sbd_release_sbdp_handle(hdp);
		return;
	}

	/* assume this one will win. */
	devlist[0] = mc_dip;
	mp->sbm_cm.sbdev_dip = mc_dip;
	lowest_pa = mc_pa;

	/*
	 * We know the base physical address of one of the MC devices.  Now
	 * we will enumerate through all of the remaining MC devices on
	 * the board to find which of them is programmed to the lowest
	 * physical address.
	 */
	for (i = 1; i < SBD_NUM_MC_PER_BOARD; i++) {
		mc_dip = mp->sbm_dip[i];
		if (mc_dip == NULL) {
			break;
		}

		if (sbdphw_get_base_physaddr(hdp, mc_dip, &mc_pa)) {
			cmn_err(CE_NOTE, "No mem on board %d unit %d",
				sbp->sb_num, i);
			break;
		}
		if (mc_pa < lowest_pa) {
			mp->sbm_cm.sbdev_dip = mc_dip;
			devlist[0] = mc_dip;
			lowest_pa = mc_pa;
		}
	}

	sbd_release_sbdp_handle(hdp);
}

static int
sbd_name_to_idx(char *name)
{
	int idx;

	for (idx = 0; SBD_COMP(idx) != SBD_COMP_UNKNOWN; idx++) {
		if (strcmp(name, SBD_DEVNAME(idx)) == 0) {
			break;
		}
	}

	return (idx);
}

static int
sbd_otype_to_idx(char *otype)
{
	int idx;

	for (idx = 0; SBD_COMP(idx) != SBD_COMP_UNKNOWN; idx++) {

		if (strcmp(otype, SBD_OTYPE(idx)) == 0) {
			break;
		}
	}

	return (idx);
}

static int
sbd_init_devlists(sbd_board_t *sbp)
{
	int		i;
	sbd_dev_unit_t	*dp;
	sbd_mem_unit_t	*mp;
	walk_tree_t	*wp, walk = {0};
	dev_info_t	*pdip;
	static fn_t	f = "sbd_init_devlists";

	PR_ALL("%s (board = %d)...\n", f, sbp->sb_num);

	wp = &walk;

	SBD_DEVS_DISCONNECT(sbp, (uint_t)-1);

	/*
	 * Clear out old entries, if any.
	 */

	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		sbp->sb_devlist[NIX(SBD_COMP_MEM)][i] = NULL;
		dp = (sbd_dev_unit_t *)SBD_GET_BOARD_MEMUNIT(sbp, i);
		dp->u_common.sbdev_sbp = sbp;
		dp->u_common.sbdev_unum = i;
		dp->u_common.sbdev_type = SBD_COMP_MEM;
	}

	mp = SBD_GET_BOARD_MEMUNIT(sbp, 0);
	ASSERT(mp != NULL);
	for (i = 0; i < SBD_NUM_MC_PER_BOARD; i++) {
		mp->sbm_dip[i] = NULL;
	}

	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		sbp->sb_devlist[NIX(SBD_COMP_CPU)][i] = NULL;
		dp = (sbd_dev_unit_t *)SBD_GET_BOARD_CPUUNIT(sbp, i);
		dp->u_common.sbdev_sbp = sbp;
		dp->u_common.sbdev_unum = i;
		dp->u_common.sbdev_type = SBD_COMP_CPU;
	}
	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		sbp->sb_devlist[NIX(SBD_COMP_IO)][i] = NULL;
		dp = (sbd_dev_unit_t *)SBD_GET_BOARD_IOUNIT(sbp, i);
		dp->u_common.sbdev_sbp = sbp;
		dp->u_common.sbdev_unum = i;
		dp->u_common.sbdev_type = SBD_COMP_IO;
	}

	wp->sbp = sbp;
	wp->nmc = 0;
	sbp->sb_ndev = 0;

	/*
	 * ddi_walk_devs() requires that topdip's parent be held.
	 */
	pdip = ddi_get_parent(sbp->sb_topdip);
	if (pdip) {
		ndi_hold_devi(pdip);
		ndi_devi_enter(pdip);
	}
	ddi_walk_devs(sbp->sb_topdip, sbd_setup_devlists, (void *) wp);
	if (pdip) {
		ndi_devi_exit(pdip);
		ndi_rele_devi(pdip);
	}

	/*
	 * There is no point checking all the components if there
	 * are no devices.
	 */
	if (sbp->sb_ndev == 0) {
		sbp->sb_memaccess_ok = 0;
		return (sbp->sb_ndev);
	}

	/*
	 * Initialize cpu sections before calling sbd_init_mem_devlists
	 * which will access the mmus.
	 */
	sbp->sb_memaccess_ok = 1;
	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		if (SBD_DEV_IS_PRESENT(sbp, SBD_COMP_CPU, i)) {
			sbd_init_cpu_unit(sbp, i);
			if (sbd_connect_cpu(sbp, i)) {
				SBD_SET_ERR(HD2MACHERR(MACHBD2HD(sbp)),
					ESBD_CPUSTART);
			}

		}
	}

	if (sbp->sb_memaccess_ok) {
		sbd_init_mem_devlists(sbp);
	} else {
		cmn_err(CE_WARN, "unable to access memory on board %d",
		    sbp->sb_num);
	}

	return (sbp->sb_ndev);
}

static void
sbd_init_cpu_unit(sbd_board_t *sbp, int unit)
{
	sbd_istate_t	new_state;
	sbd_cpu_unit_t	*cp;
	int		cpuid;
	dev_info_t	*dip;
	sbdp_handle_t	*hdp;
	sbd_handle_t	*hp = MACHBD2HD(sbp);
	extern kmutex_t	cpu_lock;

	if (SBD_DEV_IS_ATTACHED(sbp, SBD_COMP_CPU, unit)) {
		new_state = SBD_STATE_CONFIGURED;
	} else if (SBD_DEV_IS_PRESENT(sbp, SBD_COMP_CPU, unit)) {
		new_state = SBD_STATE_CONNECTED;
	} else {
		new_state = SBD_STATE_EMPTY;
	}

	dip = sbp->sb_devlist[NIX(SBD_COMP_CPU)][unit];

	cp = SBD_GET_BOARD_CPUUNIT(sbp, unit);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	cpuid = sbdp_get_cpuid(hdp, dip);

	cp->sbc_cpu_id = cpuid;

	if (&sbdp_cpu_get_impl)
		cp->sbc_cpu_impl = sbdp_cpu_get_impl(hdp, dip);
	else
		cp->sbc_cpu_impl = -1;

	mutex_enter(&cpu_lock);
	if ((cpuid >= 0) && cpu[cpuid])
		cp->sbc_cpu_flags = cpu[cpuid]->cpu_flags;
	else
		cp->sbc_cpu_flags = CPU_OFFLINE | CPU_POWEROFF;
	mutex_exit(&cpu_lock);

	sbd_cpu_set_prop(cp, dip);

	cp->sbc_cm.sbdev_cond = sbd_get_comp_cond(dip);
	sbd_release_sbdp_handle(hdp);

	/*
	 * Any changes to the cpu should be performed above
	 * this call to ensure the cpu is fully initialized
	 * before transitioning to the new state.
	 */
	SBD_DEVICE_TRANSITION(sbp, SBD_COMP_CPU, unit, new_state);
}

/*
 * Only do work if called to operate on an entire board
 * which doesn't already have components present.
 */
static void
sbd_connect(sbd_handle_t *hp)
{
	sbd_board_t	*sbp;
	sbderror_t	*ep;
	static fn_t	f = "sbd_connect";

	sbp = SBDH2BD(hp->h_sbd);

	PR_ALL("%s board %d\n", f, sbp->sb_num);

	ep = HD2MACHERR(hp);

	if (SBD_DEVS_PRESENT(sbp)) {
		/*
		 * Board already has devices present.
		 */
		PR_ALL("%s: devices already present (0x%x)\n",
			f, SBD_DEVS_PRESENT(sbp));
		SBD_SET_ERRNO(ep, EINVAL);
		return;
	}

	if (sbd_init_devlists(sbp) == 0) {
		cmn_err(CE_WARN, "%s: no devices present on board %d",
			f, sbp->sb_num);
		SBD_SET_ERR(ep, ESBD_NODEV);
		return;
	} else {
		int	i;

		/*
		 * Initialize mem-unit section of board structure.
		 */
		for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++)
			if (SBD_DEV_IS_PRESENT(sbp, SBD_COMP_MEM, i))
				sbd_init_mem_unit(sbp, i, SBD_HD2ERR(hp));

		/*
		 * Initialize sb_io sections.
		 */
		for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++)
			if (SBD_DEV_IS_PRESENT(sbp, SBD_COMP_IO, i))
				sbd_init_io_unit(sbp, i);

		SBD_BOARD_TRANSITION(sbp, SBD_STATE_CONNECTED);
		sbp->sb_rstate = SBD_STAT_CONNECTED;
		sbp->sb_ostate = SBD_STAT_UNCONFIGURED;
		(void) drv_getparm(TIME, (void *)&sbp->sb_time);
		SBD_INJECT_ERR(SBD_CONNECT_BOARD_PSEUDO_ERR, hp->h_err, EIO,
			ESBD_INTERNAL, NULL);
	}
}

static int
sbd_disconnect(sbd_handle_t *hp)
{
	int		i;
	sbd_devset_t	devset;
	sbd_board_t	*sbp;
	static fn_t	f = "sbd_disconnect it";

	PR_ALL("%s ...\n", f);

	sbp = SBDH2BD(hp->h_sbd);

	/*
	 * Only devices which are present, but
	 * unattached can be disconnected.
	 */
	devset = HD2MACHHD(hp)->sh_devset & SBD_DEVS_PRESENT(sbp) &
			SBD_DEVS_UNATTACHED(sbp);

	ASSERT((SBD_DEVS_ATTACHED(sbp) & devset) == 0);

	/*
	 * Update per-device state transitions.
	 */

	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++)
		if (DEVSET_IN_SET(devset, SBD_COMP_MEM, i)) {
			if (sbd_disconnect_mem(hp, i) == 0) {
				SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM, i,
							SBD_STATE_EMPTY);
				SBD_DEV_CLR_PRESENT(sbp, SBD_COMP_MEM, i);
			}
		}

	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++)
		if (DEVSET_IN_SET(devset, SBD_COMP_CPU, i)) {
			if (sbd_disconnect_cpu(hp, i) == 0) {
				SBD_DEVICE_TRANSITION(sbp, SBD_COMP_CPU, i,
							SBD_STATE_EMPTY);
				SBD_DEV_CLR_PRESENT(sbp, SBD_COMP_CPU, i);
			}
		}

	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++)
		if (DEVSET_IN_SET(devset, SBD_COMP_IO, i)) {
			if (sbd_disconnect_io(hp, i) == 0) {
				SBD_DEVICE_TRANSITION(sbp, SBD_COMP_IO, i,
							SBD_STATE_EMPTY);
				SBD_DEV_CLR_PRESENT(sbp, SBD_COMP_IO, i);
			}
		}

	/*
	 * Once all the components on a board have been disconnect
	 * the board's state can transition to disconnected and
	 * we can allow the deprobe to take place.
	 */
	if (SBD_DEVS_PRESENT(sbp) == 0) {
		SBD_BOARD_TRANSITION(sbp, SBD_STATE_OCCUPIED);
		sbp->sb_rstate = SBD_STAT_DISCONNECTED;
		sbp->sb_ostate = SBD_STAT_UNCONFIGURED;
		(void) drv_getparm(TIME, (void *)&sbp->sb_time);
		SBD_INJECT_ERR(SBD_DISCONNECT_BOARD_PSEUDO_ERR, hp->h_err, EIO,
			ESBD_INTERNAL, NULL);
		return (0);
	} else {
		cmn_err(CE_WARN, "%s: could not disconnect devices on board %d",
			f, sbp->sb_num);
		return (-1);
	}
}

static void
sbd_test_board(sbd_handle_t *hp)
{
	sbd_board_t	*sbp;
	sbdp_handle_t	*hdp;

	sbp = SBDH2BD(hp->h_sbd);

	PR_ALL("sbd_test_board: board %d\n", sbp->sb_num);


	hdp = sbd_get_sbdp_handle(sbp, hp);

	if (sbdp_test_board(hdp, &hp->h_opts) != 0) {
		sbderror_t	*ep = SBD_HD2ERR(hp);

		SBD_GET_PERR(hdp->h_err, ep);
	}

	SBD_INJECT_ERR(SBD_TEST_BOARD_PSEUDO_ERR, hp->h_err, EIO,
		ESBD_INTERNAL, NULL);

	sbd_release_sbdp_handle(hdp);
}

static void
sbd_assign_board(sbd_handle_t *hp)
{
	sbd_board_t	*sbp;
	sbdp_handle_t	*hdp;

	sbp = SBDH2BD(hp->h_sbd);

	PR_ALL("sbd_assign_board: board %d\n", sbp->sb_num);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	if (sbdp_assign_board(hdp) != 0) {
		sbderror_t	*ep = SBD_HD2ERR(hp);

		SBD_GET_PERR(hdp->h_err, ep);
	}

	SBD_INJECT_ERR(SBD_ASSIGN_BOARD_PSEUDO_ERR, hp->h_err, EIO,
		ESBD_INTERNAL, NULL);

	sbd_release_sbdp_handle(hdp);
}

static void
sbd_unassign_board(sbd_handle_t *hp)
{
	sbd_board_t	*sbp;
	sbdp_handle_t	*hdp;

	sbp = SBDH2BD(hp->h_sbd);

	PR_ALL("sbd_unassign_board: board %d\n", sbp->sb_num);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	if (sbdp_unassign_board(hdp) != 0) {
		sbderror_t	*ep = SBD_HD2ERR(hp);

		SBD_GET_PERR(hdp->h_err, ep);
	}

	SBD_INJECT_ERR(SBD_ASSIGN_BOARD_PSEUDO_ERR, hp->h_err, EIO,
		ESBD_INTERNAL, NULL);

	sbd_release_sbdp_handle(hdp);
}

static void
sbd_poweron_board(sbd_handle_t *hp)
{
	sbd_board_t	*sbp;
	sbdp_handle_t	*hdp;

	sbp = SBDH2BD(hp->h_sbd);

	PR_ALL("sbd_poweron_board: %d\n", sbp->sb_num);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	if (sbdp_poweron_board(hdp) != 0) {
		sbderror_t	*ep = SBD_HD2ERR(hp);

		SBD_GET_PERR(hdp->h_err, ep);
	}

	SBD_INJECT_ERR(SBD_POWERON_BOARD_PSEUDO_ERR, hp->h_err, EIO,
		ESBD_INTERNAL, NULL);

	sbd_release_sbdp_handle(hdp);
}

static void
sbd_poweroff_board(sbd_handle_t *hp)
{
	sbd_board_t	*sbp;
	sbdp_handle_t	*hdp;

	sbp = SBDH2BD(hp->h_sbd);

	PR_ALL("sbd_poweroff_board: %d\n", sbp->sb_num);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	if (sbdp_poweroff_board(hdp) != 0) {
		sbderror_t	*ep = SBD_HD2ERR(hp);

		SBD_GET_PERR(hdp->h_err, ep);
	}

	SBD_INJECT_ERR(SBD_POWEROFF_BOARD_PSEUDO_ERR, hp->h_err, EIO,
		ESBD_INTERNAL, NULL);

	sbd_release_sbdp_handle(hdp);
}


/*
 * Return a list of the dip's of devices that are
 * either present and attached, or present only but
 * not yet attached for the given board.
 */
sbd_devlist_t *
sbd_get_devlist(sbd_handle_t *hp, sbd_board_t *sbp, sbd_comp_type_t nodetype,
		int max_units, uint_t uset, int *count, int present_only)
{
	int		i, ix;
	sbd_devlist_t	*ret_devlist;
	dev_info_t	**devlist;
	sbdp_handle_t	*hdp;

	*count = 0;
	ret_devlist = GETSTRUCT(sbd_devlist_t, max_units);
	devlist = sbp->sb_devlist[NIX(nodetype)];
	/*
	 * Turn into binary value since we're going
	 * to be using XOR for a comparison.
	 * if (present_only) then
	 *	dev must be PRESENT, but NOT ATTACHED.
	 * else
	 *	dev must be PRESENT AND ATTACHED.
	 * endif
	 */
	if (present_only)
		present_only = 1;

	hdp = sbd_get_sbdp_handle(sbp, hp);

	for (i = ix = 0; (i < max_units) && uset; i++) {
		int	ut, is_present, is_attached;
		dev_info_t *dip;
		sbderror_t *ep = SBD_HD2ERR(hp);
		int	nunits, distance, j;

		/*
		 * For CMPs, we would like to perform DR operation on
		 * all the cores before moving onto the next chip.
		 * Therefore, when constructing the devlist, we process
		 * all the cores together.
		 */
		if (nodetype == SBD_COMP_CPU) {
			/*
			 * Number of units to process in the inner loop
			 */
			nunits = MAX_CORES_PER_CMP;
			/*
			 * The distance between the units in the
			 * board's sb_devlist structure.
			 */
			distance = MAX_CMP_UNITS_PER_BOARD;
		} else {
			nunits = 1;
			distance = 0;
		}

		for (j = 0; j < nunits; j++) {
			if ((dip = devlist[i + j * distance]) == NULL)
				continue;

			ut = sbdp_get_unit_num(hdp, dip);

			if (ut == -1) {
				SBD_GET_PERR(hdp->h_err, ep);
				PR_ALL("sbd_get_devlist bad unit %d"
				    " code %d errno %d",
				    i, ep->e_code, ep->e_errno);
			}

			if ((uset & (1 << ut)) == 0)
				continue;
			uset &= ~(1 << ut);
			is_present = SBD_DEV_IS_PRESENT(sbp, nodetype, ut) ?
			    1 : 0;
			is_attached = SBD_DEV_IS_ATTACHED(sbp, nodetype, ut) ?
			    1 : 0;

			if (is_present && (present_only ^ is_attached)) {
				ret_devlist[ix].dv_dip = dip;
				sbd_init_err(&ret_devlist[ix].dv_error);
				ix++;
			}
		}
	}
	sbd_release_sbdp_handle(hdp);

	if ((*count = ix) == 0) {
		FREESTRUCT(ret_devlist, sbd_devlist_t, max_units);
		ret_devlist = NULL;
	}

	return (ret_devlist);
}

static sbd_devlist_t *
sbd_get_attach_devlist(sbd_handle_t *hp, int32_t *devnump, int32_t pass)
{
	sbd_board_t	*sbp;
	uint_t		uset;
	sbd_devset_t	devset;
	sbd_devlist_t	*attach_devlist;
	static int	next_pass = 1;
	static fn_t	f = "sbd_get_attach_devlist";

	PR_ALL("%s (pass = %d)...\n", f, pass);

	sbp = SBDH2BD(hp->h_sbd);
	devset = HD2MACHHD(hp)->sh_devset;

	*devnump = 0;
	attach_devlist = NULL;

	/*
	 * We switch on next_pass for the cases where a board
	 * does not contain a particular type of component.
	 * In these situations we don't want to return NULL
	 * prematurely.  We need to check other devices and
	 * we don't want to check the same type multiple times.
	 * For example, if there were no cpus, then on pass 1
	 * we would drop through and return the memory nodes.
	 * However, on pass 2 we would switch back to the memory
	 * nodes thereby returning them twice!  Using next_pass
	 * forces us down to the end (or next item).
	 */
	if (pass == 1)
		next_pass = 1;

	switch (next_pass) {
	case 1:
		if (DEVSET_IN_SET(devset, SBD_COMP_CPU, DEVSET_ANYUNIT)) {
			uset = DEVSET_GET_UNITSET(devset, SBD_COMP_CPU);

			attach_devlist = sbd_get_devlist(hp, sbp, SBD_COMP_CPU,
						MAX_CPU_UNITS_PER_BOARD,
						uset, devnump, 1);

			DEVSET_DEL(devset, SBD_COMP_CPU, DEVSET_ANYUNIT);
			if (!devset || attach_devlist) {
				next_pass = 2;
				return (attach_devlist);
			}
			/*
			 * If the caller is interested in the entire
			 * board, but there aren't any cpus, then just
			 * fall through to check for the next component.
			 */
		}
		/*FALLTHROUGH*/

	case 2:
		if (DEVSET_IN_SET(devset, SBD_COMP_MEM, DEVSET_ANYUNIT)) {
			uset = DEVSET_GET_UNITSET(devset, SBD_COMP_MEM);

			attach_devlist = sbd_get_devlist(hp, sbp, SBD_COMP_MEM,
						MAX_MEM_UNITS_PER_BOARD,
						uset, devnump, 1);

			DEVSET_DEL(devset, SBD_COMP_MEM, DEVSET_ANYUNIT);
			if (!devset || attach_devlist) {
				next_pass = 3;
				return (attach_devlist);
			}
			/*
			 * If the caller is interested in the entire
			 * board, but there isn't any memory, then
			 * just fall through to next component.
			 */
		}
		/*FALLTHROUGH*/


	case 3:
		next_pass = -1;
		if (DEVSET_IN_SET(devset, SBD_COMP_IO, DEVSET_ANYUNIT)) {
			uset = DEVSET_GET_UNITSET(devset, SBD_COMP_IO);

			attach_devlist = sbd_get_devlist(hp, sbp, SBD_COMP_IO,
						MAX_IO_UNITS_PER_BOARD,
						uset, devnump, 1);

			DEVSET_DEL(devset, SBD_COMP_IO, DEVSET_ANYUNIT);
			if (!devset || attach_devlist) {
				next_pass = 4;
				return (attach_devlist);
			}
		}
		/*FALLTHROUGH*/

	default:
		*devnump = 0;
		return (NULL);
	}
	/*NOTREACHED*/
}

static int
sbd_pre_attach_devlist(sbd_handle_t *hp, sbd_devlist_t *devlist,
	int32_t devnum)
{
	int		max_units = 0, rv = 0;
	sbd_comp_type_t	nodetype;
	static fn_t	f = "sbd_pre_attach_devlist";

	/*
	 * In this driver, all entries in a devlist[] are
	 * of the same nodetype.
	 */
	nodetype = sbd_get_devtype(hp, devlist->dv_dip);

	PR_ALL("%s (nt = %s(%d), num = %d)...\n",
		f, sbd_ct_str[(int)nodetype], (int)nodetype, devnum);

	switch (nodetype) {

	case SBD_COMP_MEM:
		max_units = MAX_MEM_UNITS_PER_BOARD;
		rv = sbd_pre_attach_mem(hp, devlist, devnum);
		break;

	case SBD_COMP_CPU:
		max_units = MAX_CPU_UNITS_PER_BOARD;
		rv = sbd_pre_attach_cpu(hp, devlist, devnum);
		break;

	case SBD_COMP_IO:
		max_units = MAX_IO_UNITS_PER_BOARD;
		break;

	default:
		rv = -1;
		break;
	}

	if (rv && max_units) {
		int	i;
		/*
		 * Need to clean up devlist
		 * if pre-op is going to fail.
		 */
		for (i = 0; i < max_units; i++) {
			if (SBD_GET_ERRSTR(&devlist[i].dv_error)) {
				SBD_FREE_ERR(&devlist[i].dv_error);
			} else {
				break;
			}
		}
		FREESTRUCT(devlist, sbd_devlist_t, max_units);
	}

	/*
	 * If an error occurred, return "continue"
	 * indication so that we can continue attaching
	 * as much as possible.
	 */
	return (rv ? -1 : 0);
}

static int
sbd_post_attach_devlist(sbd_handle_t *hp, sbd_devlist_t *devlist,
			int32_t devnum)
{
	int		i, max_units = 0, rv = 0;
	sbd_devset_t	devs_unattached, devs_present;
	sbd_comp_type_t	nodetype;
	sbd_board_t 	*sbp = SBDH2BD(hp->h_sbd);
	sbdp_handle_t	*hdp;
	static fn_t	f = "sbd_post_attach_devlist";

	sbp = SBDH2BD(hp->h_sbd);
	nodetype = sbd_get_devtype(hp, devlist->dv_dip);

	PR_ALL("%s (nt = %s(%d), num = %d)...\n",
		f, sbd_ct_str[(int)nodetype], (int)nodetype, devnum);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	/*
	 * Need to free up devlist[] created earlier in
	 * sbd_get_attach_devlist().
	 */
	switch (nodetype) {
	case SBD_COMP_CPU:
		max_units = MAX_CPU_UNITS_PER_BOARD;
		rv = sbd_post_attach_cpu(hp, devlist, devnum);
		break;


	case SBD_COMP_MEM:
		max_units = MAX_MEM_UNITS_PER_BOARD;

		rv = sbd_post_attach_mem(hp, devlist, devnum);
		break;

	case SBD_COMP_IO:
		max_units = MAX_IO_UNITS_PER_BOARD;
		break;

	default:
		rv = -1;
		break;
	}


	for (i = 0; i < devnum; i++) {
		int		unit;
		dev_info_t	*dip;
		sbderror_t	*ep;

		ep = &devlist[i].dv_error;

		if (sbd_set_err_in_hdl(hp, ep) == 0)
			continue;

		dip = devlist[i].dv_dip;
		nodetype = sbd_get_devtype(hp, dip);
		unit = sbdp_get_unit_num(hdp, dip);

		if (unit == -1) {
			SBD_GET_PERR(hdp->h_err, ep);
			continue;
		}

		unit = sbd_check_unit_attached(sbp, dip, unit, nodetype, ep);

		if (unit == -1) {
			PR_ALL("%s: ERROR (nt=%s, b=%d, u=%d) not attached\n",
				f, sbd_ct_str[(int)nodetype], sbp->sb_num, i);
			continue;
		}

		SBD_DEV_SET_ATTACHED(sbp, nodetype, unit);
		SBD_DEVICE_TRANSITION(sbp, nodetype, unit,
						SBD_STATE_CONFIGURED);
	}
	sbd_release_sbdp_handle(hdp);

	if (rv) {
		PR_ALL("%s: errno %d, ecode %d during attach\n",
			f, SBD_GET_ERRNO(SBD_HD2ERR(hp)),
			SBD_GET_ERR(HD2MACHERR(hp)));
	}

	devs_present = SBD_DEVS_PRESENT(sbp);
	devs_unattached = SBD_DEVS_UNATTACHED(sbp);

	switch (SBD_BOARD_STATE(sbp)) {
	case SBD_STATE_CONNECTED:
	case SBD_STATE_UNCONFIGURED:
		ASSERT(devs_present);

		if (devs_unattached == 0) {
			/*
			 * All devices finally attached.
			 */
			SBD_BOARD_TRANSITION(sbp, SBD_STATE_CONFIGURED);
			sbp->sb_rstate = SBD_STAT_CONNECTED;
			sbp->sb_ostate = SBD_STAT_CONFIGURED;
		} else if (devs_present != devs_unattached) {
			/*
			 * Only some devices are fully attached.
			 */
			SBD_BOARD_TRANSITION(sbp, SBD_STATE_PARTIAL);
			sbp->sb_rstate = SBD_STAT_CONNECTED;
			sbp->sb_ostate = SBD_STAT_UNCONFIGURED;
		}
		(void) drv_getparm(TIME, (void *)&sbp->sb_time);
		break;

	case SBD_STATE_PARTIAL:
		ASSERT(devs_present);
		/*
		 * All devices finally attached.
		 */
		if (devs_unattached == 0) {
			SBD_BOARD_TRANSITION(sbp, SBD_STATE_CONFIGURED);
			sbp->sb_rstate = SBD_STAT_CONNECTED;
			sbp->sb_ostate = SBD_STAT_CONFIGURED;
			(void) drv_getparm(TIME, (void *)&sbp->sb_time);
		}
		break;

	default:
		break;
	}

	if (max_units && devlist) {
		int	i;

		for (i = 0; i < max_units; i++) {
			if (SBD_GET_ERRSTR(&devlist[i].dv_error)) {
				SBD_FREE_ERR(&devlist[i].dv_error);
			} else {
				break;
			}
		}
		FREESTRUCT(devlist, sbd_devlist_t, max_units);
	}

	/*
	 * Our policy is to attach all components that are
	 * possible, thus we always return "success" on the
	 * pre and post operations.
	 */
	return (0);
}

/*
 * We only need to "release" cpu and memory devices.
 */
static sbd_devlist_t *
sbd_get_release_devlist(sbd_handle_t *hp, int32_t *devnump, int32_t pass)
{
	sbd_board_t	*sbp;
	uint_t		uset;
	sbd_devset_t	devset;
	sbd_devlist_t	*release_devlist;
	static int	next_pass = 1;
	static fn_t	f = "sbd_get_release_devlist";

	PR_ALL("%s (pass = %d)...\n", f, pass);

	sbp = SBDH2BD(hp->h_sbd);
	devset = HD2MACHHD(hp)->sh_devset;

	*devnump = 0;
	release_devlist = NULL;

	/*
	 * We switch on next_pass for the cases where a board
	 * does not contain a particular type of component.
	 * In these situations we don't want to return NULL
	 * prematurely.  We need to check other devices and
	 * we don't want to check the same type multiple times.
	 * For example, if there were no cpus, then on pass 1
	 * we would drop through and return the memory nodes.
	 * However, on pass 2 we would switch back to the memory
	 * nodes thereby returning them twice!  Using next_pass
	 * forces us down to the end (or next item).
	 */
	if (pass == 1)
		next_pass = 1;

	switch (next_pass) {
	case 1:
		if (DEVSET_IN_SET(devset, SBD_COMP_MEM, DEVSET_ANYUNIT)) {
			uset = DEVSET_GET_UNITSET(devset, SBD_COMP_MEM);

			release_devlist = sbd_get_devlist(hp, sbp,
						SBD_COMP_MEM,
						MAX_MEM_UNITS_PER_BOARD,
						uset, devnump, 0);

			DEVSET_DEL(devset, SBD_COMP_MEM, DEVSET_ANYUNIT);
			if (!devset || release_devlist) {
				next_pass = 2;
				return (release_devlist);
			}
			/*
			 * If the caller is interested in the entire
			 * board, but there isn't any memory, then
			 * just fall through to next component.
			 */
		}
		/*FALLTHROUGH*/


	case 2:
		if (DEVSET_IN_SET(devset, SBD_COMP_CPU, DEVSET_ANYUNIT)) {
			uset = DEVSET_GET_UNITSET(devset, SBD_COMP_CPU);

			release_devlist = sbd_get_devlist(hp, sbp,
						SBD_COMP_CPU,
						MAX_CPU_UNITS_PER_BOARD,
						uset, devnump, 0);

			DEVSET_DEL(devset, SBD_COMP_CPU, DEVSET_ANYUNIT);
			if (!devset || release_devlist) {
				next_pass = 3;
				return (release_devlist);
			}
			/*
			 * If the caller is interested in the entire
			 * board, but there aren't any cpus, then just
			 * fall through to check for the next component.
			 */
		}
		/*FALLTHROUGH*/


	case 3:
		next_pass = -1;
		if (DEVSET_IN_SET(devset, SBD_COMP_IO, DEVSET_ANYUNIT)) {
			uset = DEVSET_GET_UNITSET(devset, SBD_COMP_IO);

			release_devlist = sbd_get_devlist(hp, sbp,
						SBD_COMP_IO,
						MAX_IO_UNITS_PER_BOARD,
						uset, devnump, 0);

			DEVSET_DEL(devset, SBD_COMP_IO, DEVSET_ANYUNIT);
			if (!devset || release_devlist) {
				next_pass = 4;
				return (release_devlist);
			}
		}
		/*FALLTHROUGH*/

	default:
		*devnump = 0;
		return (NULL);
	}
	/*NOTREACHED*/
}

static int
sbd_pre_release_devlist(sbd_handle_t *hp, sbd_devlist_t *devlist,
			int32_t devnum)
{
	int		max_units = 0, rv = 0;
	sbd_comp_type_t	nodetype;
	static fn_t	f = "sbd_pre_release_devlist";

	nodetype = sbd_get_devtype(hp, devlist->dv_dip);

	PR_ALL("%s (nt = %s(%d), num = %d)...\n",
		f, sbd_ct_str[(int)nodetype], (int)nodetype, devnum);

	switch (nodetype) {
	case SBD_COMP_CPU: {
		int			i, mem_present = 0;
		sbd_board_t		*sbp = SBDH2BD(hp->h_sbd);
		sbd_devset_t		devset;
		sbd_priv_handle_t	*shp = HD2MACHHD(hp);

		max_units = MAX_CPU_UNITS_PER_BOARD;

		devset = shp->sh_orig_devset;

		for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
			/*
			 * if client also requested to unconfigure memory
			 * the we allow the operation. Therefore
			 * we need to warranty that memory gets unconfig
			 * before cpus
			 */

			if (DEVSET_IN_SET(devset, SBD_COMP_MEM, i)) {
				continue;
			}
			if (SBD_DEV_IS_ATTACHED(sbp, SBD_COMP_MEM, i)) {
				mem_present = 1;
				break;
			}
		}
		if (mem_present) {
			sbderror_t	*ep = SBD_HD2ERR(hp);
			SBD_SET_ERR(ep, ESBD_MEMONLINE);
			SBD_SET_ERRSTR(ep, sbp->sb_mempath[i]);
			rv = -1;
		} else {
			rv = sbd_pre_release_cpu(hp, devlist, devnum);
		}

		break;

	}
	case SBD_COMP_MEM:
		max_units = MAX_MEM_UNITS_PER_BOARD;
		rv = sbd_pre_release_mem(hp, devlist, devnum);
		break;


	case SBD_COMP_IO:
		max_units = MAX_IO_UNITS_PER_BOARD;
		rv = sbd_pre_release_io(hp, devlist, devnum);
		break;

	default:
		rv = -1;
		break;
	}

	if (rv && max_units) {
		int	i;

		/*
		 * the individual pre_release component routines should
		 * have set the error in the handle.  No need to set it
		 * here
		 *
		 * Need to clean up dynamically allocated devlist
		 * if pre-op is going to fail.
		 */
		for (i = 0; i < max_units; i++) {
			if (SBD_GET_ERRSTR(&devlist[i].dv_error)) {
				SBD_FREE_ERR(&devlist[i].dv_error);
			} else {
				break;
			}
		}
		FREESTRUCT(devlist, sbd_devlist_t, max_units);
	}

	return (rv ? -1 : 0);
}

static int
sbd_post_release_devlist(sbd_handle_t *hp, sbd_devlist_t *devlist,
			int32_t devnum)
{
	int		i, max_units = 0;
	sbd_comp_type_t	nodetype;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbdp_handle_t	*hdp;
	sbd_error_t	*spe;
	static fn_t	f = "sbd_post_release_devlist";

	nodetype = sbd_get_devtype(hp, devlist->dv_dip);
	ASSERT(nodetype >= SBD_COMP_CPU && nodetype <= SBD_COMP_IO);

	PR_ALL("%s (nt = %s(%d), num = %d)...\n",
		f, sbd_ct_str[(int)nodetype], (int)nodetype, devnum);

	/*
	 * Need to free up devlist[] created earlier in
	 * sbd_get_release_devlist().
	 */
	switch (nodetype) {
	case SBD_COMP_CPU:
		max_units = MAX_CPU_UNITS_PER_BOARD;
		break;

	case SBD_COMP_MEM:
		max_units = MAX_MEM_UNITS_PER_BOARD;
		break;

	case SBD_COMP_IO:
		/*
		 *  Need to check if specific I/O is referenced and
		 *  fail post-op.
		 */

		if (sbd_check_io_refs(hp, devlist, devnum) > 0) {
				PR_IO("%s: error - I/O devices ref'd\n", f);
		}

		max_units = MAX_IO_UNITS_PER_BOARD;
		break;

	default:
		{
			cmn_err(CE_WARN, "%s: invalid nodetype (%d)",
				f, (int)nodetype);
			SBD_SET_ERR(HD2MACHERR(hp), ESBD_INVAL);
		}
		break;
	}
	hdp = sbd_get_sbdp_handle(sbp, hp);
	spe = hdp->h_err;

	for (i = 0; i < devnum; i++) {
		int		unit;
		sbderror_t	*ep;

		ep = &devlist[i].dv_error;

		if (sbd_set_err_in_hdl(hp, ep) == 0) {
			continue;
		}

		unit = sbdp_get_unit_num(hdp, devlist[i].dv_dip);
		if (unit == -1) {
			SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
			PR_ALL("%s bad unit num: %d code %d",
			    f, unit, spe->e_code);
			continue;
		}
	}
	sbd_release_sbdp_handle(hdp);

	if (SBD_GET_ERRNO(SBD_HD2ERR(hp))) {
		PR_ALL("%s: errno %d, ecode %d during release\n",
			f, SBD_GET_ERRNO(SBD_HD2ERR(hp)),
			SBD_GET_ERR(SBD_HD2ERR(hp)));
	}

	if (max_units && devlist) {
		int	i;

		for (i = 0; i < max_units; i++) {
			if (SBD_GET_ERRSTR(&devlist[i].dv_error)) {
				SBD_FREE_ERR(&devlist[i].dv_error);
			} else {
				break;
			}
		}
		FREESTRUCT(devlist, sbd_devlist_t, max_units);
	}

	return (SBD_GET_ERRNO(SBD_HD2ERR(hp)) ? -1 : 0);
}

static void
sbd_release_dev_done(sbd_board_t *sbp, sbd_comp_type_t nodetype, int unit)
{
	SBD_DEV_SET_UNREFERENCED(sbp, nodetype, unit);
	SBD_DEVICE_TRANSITION(sbp, nodetype, unit, SBD_STATE_UNREFERENCED);
}

static void
sbd_release_done(sbd_handle_t *hp, sbd_comp_type_t nodetype, dev_info_t *dip)
{
	int		unit;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbderror_t	*ep;
	static fn_t	f = "sbd_release_done";
	sbdp_handle_t	*hdp;

	PR_ALL("%s...\n", f);

	hdp = sbd_get_sbdp_handle(sbp, hp);
	ep = SBD_HD2ERR(hp);

	if ((unit = sbdp_get_unit_num(hdp, dip)) < 0) {
		cmn_err(CE_WARN,
			"sbd:%s: unable to get unit for dip (0x%p)",
			f, (void *)dip);
		SBD_GET_PERR(hdp->h_err, ep);
		sbd_release_sbdp_handle(hdp);
		return;
	}
	sbd_release_sbdp_handle(hdp);

	/*
	 * Transfer the device which just completed its release
	 * to the UNREFERENCED state.
	 */
	switch (nodetype) {

	case SBD_COMP_MEM:
		sbd_release_mem_done((void *)hp, unit);
		break;

	default:
		sbd_release_dev_done(sbp, nodetype, unit);
		break;
	}

	/*
	 * If the entire board was released and all components
	 * unreferenced then transfer it to the UNREFERENCED state.
	 */
	if (SBD_DEVS_RELEASED(sbp) == SBD_DEVS_UNREFERENCED(sbp)) {
		SBD_BOARD_TRANSITION(sbp, SBD_STATE_UNREFERENCED);
		(void) drv_getparm(TIME, (void *)&sbp->sb_time);
	}
}

static sbd_devlist_t *
sbd_get_detach_devlist(sbd_handle_t *hp, int32_t *devnump, int32_t pass)
{
	sbd_board_t	*sbp;
	uint_t		uset;
	sbd_devset_t	devset;
	sbd_devlist_t	*detach_devlist;
	static int	next_pass = 1;
	static fn_t	f = "sbd_get_detach_devlist";

	PR_ALL("%s (pass = %d)...\n", f, pass);

	sbp = SBDH2BD(hp->h_sbd);
	devset = HD2MACHHD(hp)->sh_devset;

	*devnump = 0;
	detach_devlist = NULL;

	/*
	 * We switch on next_pass for the cases where a board
	 * does not contain a particular type of component.
	 * In these situations we don't want to return NULL
	 * prematurely.  We need to check other devices and
	 * we don't want to check the same type multiple times.
	 * For example, if there were no cpus, then on pass 1
	 * we would drop through and return the memory nodes.
	 * However, on pass 2 we would switch back to the memory
	 * nodes thereby returning them twice!  Using next_pass
	 * forces us down to the end (or next item).
	 */
	if (pass == 1)
		next_pass = 1;

	switch (next_pass) {
	case 1:
		if (DEVSET_IN_SET(devset, SBD_COMP_MEM, DEVSET_ANYUNIT)) {
			uset = DEVSET_GET_UNITSET(devset, SBD_COMP_MEM);

			detach_devlist = sbd_get_devlist(hp, sbp,
						SBD_COMP_MEM,
						MAX_MEM_UNITS_PER_BOARD,
						uset, devnump, 0);

			DEVSET_DEL(devset, SBD_COMP_MEM, DEVSET_ANYUNIT);
			if (!devset || detach_devlist) {
				next_pass = 2;
				return (detach_devlist);
			}
			/*
			 * If the caller is interested in the entire
			 * board, but there isn't any memory, then
			 * just fall through to next component.
			 */
		}
		/*FALLTHROUGH*/

	case 2:
		if (DEVSET_IN_SET(devset, SBD_COMP_CPU, DEVSET_ANYUNIT)) {
			uset = DEVSET_GET_UNITSET(devset, SBD_COMP_CPU);

			detach_devlist = sbd_get_devlist(hp, sbp,
						SBD_COMP_CPU,
						MAX_CPU_UNITS_PER_BOARD,
						uset, devnump, 0);

			DEVSET_DEL(devset, SBD_COMP_CPU, DEVSET_ANYUNIT);
			if (!devset || detach_devlist) {
				next_pass = 2;
				return (detach_devlist);
			}
			/*
			 * If the caller is interested in the entire
			 * board, but there aren't any cpus, then just
			 * fall through to check for the next component.
			 */
		}
		/*FALLTHROUGH*/

	case 3:
		next_pass = -1;
		if (DEVSET_IN_SET(devset, SBD_COMP_IO, DEVSET_ANYUNIT)) {
			uset = DEVSET_GET_UNITSET(devset, SBD_COMP_IO);

			detach_devlist = sbd_get_devlist(hp, sbp,
						SBD_COMP_IO,
						MAX_IO_UNITS_PER_BOARD,
						uset, devnump, 0);

			DEVSET_DEL(devset, SBD_COMP_IO, DEVSET_ANYUNIT);
			if (!devset || detach_devlist) {
				next_pass = 4;
				return (detach_devlist);
			}
		}
		/*FALLTHROUGH*/

	default:
		*devnump = 0;
		return (NULL);
	}
	/*NOTREACHED*/
}

static int
sbd_pre_detach_devlist(sbd_handle_t *hp, sbd_devlist_t *devlist,
	int32_t devnum)
{
	int		rv = 0;
	sbd_comp_type_t	nodetype;
	static fn_t	f = "sbd_pre_detach_devlist";

	nodetype = sbd_get_devtype(hp, devlist->dv_dip);

	PR_ALL("%s (nt = %s(%d), num = %d)...\n",
		f, sbd_ct_str[(int)nodetype], (int)nodetype, devnum);

	switch (nodetype) {
	case SBD_COMP_CPU:
		rv = sbd_pre_detach_cpu(hp, devlist, devnum);
		break;

	case SBD_COMP_MEM:
		rv = sbd_pre_detach_mem(hp, devlist, devnum);
		break;

	case SBD_COMP_IO:
		rv = sbd_pre_detach_io(hp, devlist, devnum);
		break;

	default:
		rv = -1;
		break;
	}

	/*
	 * We want to continue attempting to detach
	 * other components.
	 */
	return (rv);
}

static int
sbd_post_detach_devlist(sbd_handle_t *hp, sbd_devlist_t *devlist,
			int32_t devnum)
{
	int		i, max_units = 0, rv = 0;
	sbd_comp_type_t	nodetype;
	sbd_board_t	*sbp;
	sbd_istate_t	bstate;
	static fn_t	f = "sbd_post_detach_devlist";
	sbdp_handle_t	*hdp;

	sbp = SBDH2BD(hp->h_sbd);
	nodetype = sbd_get_devtype(hp, devlist->dv_dip);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	PR_ALL("%s (nt = %s(%d), num = %d)...\n",
		f, sbd_ct_str[(int)nodetype], (int)nodetype, devnum);

	/*
	 * Need to free up devlist[] created earlier in
	 * sbd_get_detach_devlist().
	 */
	switch (nodetype) {
	case SBD_COMP_CPU:
		max_units = MAX_CPU_UNITS_PER_BOARD;
		rv = sbd_post_detach_cpu(hp, devlist, devnum);
		break;

	case SBD_COMP_MEM:
		max_units = MAX_MEM_UNITS_PER_BOARD;
		rv = sbd_post_detach_mem(hp, devlist, devnum);
		break;

	case SBD_COMP_IO:
		max_units = MAX_IO_UNITS_PER_BOARD;
		rv = sbd_post_detach_io(hp, devlist, devnum);
		break;

	default:
		rv = -1;
		break;
	}


	for (i = 0; i < devnum; i++) {
		int		unit;
		sbderror_t	*ep;
		dev_info_t	*dip;

		ep = &devlist[i].dv_error;

		if (sbd_set_err_in_hdl(hp, ep) == 0)
			continue;

		dip = devlist[i].dv_dip;
		unit = sbdp_get_unit_num(hdp, dip);
		if (unit == -1) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE)
				continue;
			else {
				SBD_GET_PERR(hdp->h_err, ep);
				break;
			}
		}
		nodetype = sbd_get_devtype(hp, dip);

		if (sbd_check_unit_attached(sbp, dip, unit, nodetype,
		    ep) >= 0) {
			/*
			 * Device is still attached probably due
			 * to an error.  Need to keep track of it.
			 */
			PR_ALL("%s: ERROR (nt=%s, b=%d, u=%d) not detached\n",
				f, sbd_ct_str[(int)nodetype], sbp->sb_num,
				unit);
			continue;
		}

		SBD_DEV_CLR_ATTACHED(sbp, nodetype, unit);
		SBD_DEV_CLR_RELEASED(sbp, nodetype, unit);
		SBD_DEV_CLR_UNREFERENCED(sbp, nodetype, unit);
		SBD_DEVICE_TRANSITION(sbp, nodetype, unit,
						SBD_STATE_UNCONFIGURED);
	}
	sbd_release_sbdp_handle(hdp);

	bstate = SBD_BOARD_STATE(sbp);
	if (bstate != SBD_STATE_UNCONFIGURED) {
		if (SBD_DEVS_PRESENT(sbp) == SBD_DEVS_UNATTACHED(sbp)) {
			/*
			 * All devices are finally detached.
			 */
			SBD_BOARD_TRANSITION(sbp, SBD_STATE_UNCONFIGURED);
		} else if ((SBD_BOARD_STATE(sbp) != SBD_STATE_PARTIAL) &&
				SBD_DEVS_ATTACHED(sbp)) {
			/*
			 * Some devices remain attached.
			 */
			SBD_BOARD_TRANSITION(sbp, SBD_STATE_PARTIAL);
		}
	}

	if (rv) {
		PR_ALL("%s: errno %d, ecode %d during detach\n",
			f, SBD_GET_ERRNO(SBD_HD2ERR(hp)),
			SBD_GET_ERR(HD2MACHERR(hp)));
	}

	if (max_units && devlist) {
		int	i;

		for (i = 0; i < max_units; i++) {
			if (SBD_GET_ERRSTR(&devlist[i].dv_error)) {
				SBD_FREE_ERR(&devlist[i].dv_error);
			} else {
				break;
			}
		}
		FREESTRUCT(devlist, sbd_devlist_t, max_units);
	}

	return (SBD_GET_ERRNO(SBD_HD2ERR(hp)) ? -1 : 0);
}

/*
 * Return the unit number of the respective dip if
 * it's found to be attached.
 */
static int
sbd_check_unit_attached(sbd_board_t *sbp, dev_info_t *dip, int unit,
	sbd_comp_type_t nodetype, sbderror_t *ep)
{
	int		rv = -1;
	processorid_t	cpuid;
	uint64_t	basepa, endpa;
	struct memlist	*ml;
	extern struct memlist	*phys_install;
	sbdp_handle_t	*hdp;
	sbd_handle_t	*hp = MACHBD2HD(sbp);
	static fn_t	f = "sbd_check_unit_attached";

	hdp = sbd_get_sbdp_handle(sbp, hp);

	switch (nodetype) {

	case SBD_COMP_CPU:
		cpuid = sbdp_get_cpuid(hdp, dip);
		if (cpuid < 0) {
			break;
		}
		mutex_enter(&cpu_lock);
		if (cpu_get(cpuid) != NULL)
			rv = unit;
		mutex_exit(&cpu_lock);
		break;

	case SBD_COMP_MEM:
		if (sbdphw_get_base_physaddr(hdp, dip, &basepa)) {
			break;
		}
		if (sbdp_get_mem_alignment(hdp, dip, &endpa)) {
			cmn_err(CE_WARN, "%s sbdp_get_mem_alignment fail", f);
			break;
		}

		basepa &= ~(endpa - 1);
		endpa += basepa;
		/*
		 * Check if base address is in phys_install.
		 */
		memlist_read_lock();
		for (ml = phys_install; ml; ml = ml->ml_next)
			if ((endpa <= ml->ml_address) ||
			    (basepa >= (ml->ml_address + ml->ml_size)))
				continue;
			else
				break;
		memlist_read_unlock();
		if (ml != NULL)
			rv = unit;
		break;

	case SBD_COMP_IO:
	{
		dev_info_t	*tdip, *pdip;

		tdip = dip;

		/*
		 * ddi_walk_devs() requires that topdip's parent be held.
		 */
		pdip = ddi_get_parent(sbp->sb_topdip);
		if (pdip) {
			ndi_hold_devi(pdip);
			ndi_devi_enter(pdip);
		}
		ddi_walk_devs(sbp->sb_topdip, sbd_check_io_attached,
			(void *)&tdip);
		if (pdip) {
			ndi_devi_exit(pdip);
			ndi_rele_devi(pdip);
		}

		if (tdip == NULL)
			rv = unit;
		else
			rv = -1;
		break;
	}

	default:
		PR_ALL("%s: unexpected nodetype(%d) for dip 0x%p\n",
			f, nodetype, (void *)dip);
		rv = -1;
		break;
	}

	/*
	 * Save the error that sbdp sent us and report it
	 */
	if (rv == -1)
		SBD_GET_PERR(hdp->h_err, ep);

	sbd_release_sbdp_handle(hdp);

	return (rv);
}

/*
 * Return memhandle, if in fact, this memunit is the owner of
 * a scheduled memory delete.
 */
int
sbd_get_memhandle(sbd_handle_t *hp, dev_info_t *dip, memhandle_t *mhp)
{
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbd_mem_unit_t	*mp;
	sbdp_handle_t	*hdp;
	int		unit;
	static fn_t	f = "sbd_get_memhandle";

	PR_MEM("%s...\n", f);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	unit = sbdp_get_unit_num(hdp, dip);
	if (unit == -1) {
		SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
		sbd_release_sbdp_handle(hdp);
		return (-1);
	}
	sbd_release_sbdp_handle(hdp);

	mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

	if (mp->sbm_flags & SBD_MFLAG_RELOWNER) {
		*mhp = mp->sbm_memhandle;
		return (0);
	} else {
		SBD_SET_ERR(SBD_HD2ERR(hp), ESBD_INTERNAL);
		SBD_SET_ERRSTR(SBD_HD2ERR(hp), sbp->sb_mempath[unit]);
		return (-1);
	}
	/*NOTREACHED*/
}


static int
sbd_cpu_cnt(sbd_handle_t *hp, sbd_devset_t devset)
{
	int		c, cix;
	sbd_board_t	*sbp;

	sbp = SBDH2BD(hp->h_sbd);

	/*
	 * Only look for requested devices that are actually present.
	 */
	devset &= SBD_DEVS_PRESENT(sbp);

	for (c = cix = 0; c < MAX_CMP_UNITS_PER_BOARD; c++) {
		/*
		 * Index for core 1 , if exists.
		 * With the current implementation it is
		 * MAX_CMP_UNITS_PER_BOARD off from core 0.
		 * The calculation will need to change if
		 * the assumption is no longer true.
		 */
		int		c1 = c + MAX_CMP_UNITS_PER_BOARD;

		if (DEVSET_IN_SET(devset, SBD_COMP_CMP, c) == 0) {
			continue;
		}

		/*
		 * Check to see if the dip(s) exist for this chip
		 */
		if ((sbp->sb_devlist[NIX(SBD_COMP_CMP)][c] == NULL) &&
		    (sbp->sb_devlist[NIX(SBD_COMP_CMP)][c1] == NULL))
			continue;

		cix++;
	}

	return (cix);
}

static int
sbd_mem_cnt(sbd_handle_t *hp, sbd_devset_t devset)
{
	int		i, ix;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);

	/*
	 * Only look for requested devices that are actually present.
	 */
	devset &= SBD_DEVS_PRESENT(sbp);

	for (i = ix = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		dev_info_t	*dip;

		if (DEVSET_IN_SET(devset, SBD_COMP_MEM, i) == 0) {
			continue;
		}

		dip = sbp->sb_devlist[NIX(SBD_COMP_MEM)][i];
		if (dip == NULL)
			continue;

		ix++;
	}

	return (ix);
}

/*
 * NOTE: This routine is only partially smart about multiple
 *	 mem-units.  Need to make mem-status structure smart
 *	 about them also.
 */
static int
sbd_mem_status(sbd_handle_t *hp, sbd_devset_t devset, sbd_dev_stat_t *dsp)
{
	int		m, mix, rv;
	memdelstat_t	mdst;
	memquery_t	mq;
	sbd_board_t	*sbp;
	sbd_mem_unit_t	*mp;
	sbd_mem_stat_t	*msp;
	extern int	kcage_on;
	int		i;
	static fn_t	f = "sbd_mem_status";

	sbp = SBDH2BD(hp->h_sbd);

	/*
	 * Check the present devset and access the dip with
	 * status lock held to protect agains a concurrent
	 * unconfigure or disconnect thread.
	 */
	mutex_enter(&sbp->sb_slock);

	/*
	 * Only look for requested devices that are actually present.
	 */
	devset &= SBD_DEVS_PRESENT(sbp);

	for (m = mix = 0; m < MAX_MEM_UNITS_PER_BOARD; m++) {
		dev_info_t	*dip;


		if (DEVSET_IN_SET(devset, SBD_COMP_MEM, m) == 0)
			continue;

		/*
		 * Check to make sure the memory unit is in a state
		 * where its fully initialized.
		 */
		if (SBD_DEVICE_STATE(sbp, SBD_COMP_MEM, m) == SBD_STATE_EMPTY)
			continue;

		dip = sbp->sb_devlist[NIX(SBD_COMP_MEM)][m];
		if (dip == NULL)
			continue;

		mp = SBD_GET_BOARD_MEMUNIT(sbp, m);

		msp = &dsp->d_mem;

		bzero((caddr_t)msp, sizeof (*msp));
		msp->ms_type = SBD_COMP_MEM;

		/*
		 * The plugin expects -1 for the mem unit
		 */
		msp->ms_cm.c_id.c_unit = -1;

		/*
		 * Get the memory name from what sbdp gave us
		 */
		for (i = 0; SBD_COMP(i) != SBD_COMP_UNKNOWN; i++) {
			if (SBD_COMP(i) == SBD_COMP_MEM) {
				(void) strcpy(msp->ms_name, SBD_DEVNAME(i));
			}
		}
		msp->ms_cm.c_cond = mp->sbm_cm.sbdev_cond;
		msp->ms_cm.c_busy = mp->sbm_cm.sbdev_busy;
		msp->ms_cm.c_time = mp->sbm_cm.sbdev_time;

		/* XXX revisit this after memory conversion */
		msp->ms_ostate = ostate_cvt(SBD_DEVICE_STATE(
			sbp, SBD_COMP_MEM, m));

		msp->ms_basepfn = mp->sbm_basepfn;
		msp->ms_pageslost = mp->sbm_pageslost;
		msp->ms_cage_enabled = kcage_on;
		msp->ms_interleave = mp->sbm_interleave;

		if (mp->sbm_flags & SBD_MFLAG_RELOWNER)
			rv = kphysm_del_status(mp->sbm_memhandle, &mdst);
		else
			rv = KPHYSM_EHANDLE;	/* force 'if' to fail */

		if (rv == KPHYSM_OK) {
			msp->ms_totpages += mdst.phys_pages;

			/*
			 * Any pages above managed is "free",
			 * i.e. it's collected.
			 */
			msp->ms_detpages += (uint_t)(mdst.collected +
							mdst.phys_pages -
							mdst.managed);
		} else {
			msp->ms_totpages += (uint_t)mp->sbm_npages;

			/*
			 * If we're UNREFERENCED or UNCONFIGURED,
			 * then the number of detached pages is
			 * however many pages are on the board.
			 * I.e. detached = not in use by OS.
			 */
			switch (msp->ms_cm.c_ostate) {
			/*
			 * changed to use cfgadm states
			 *
			 * was:
			 *	case SFDR_STATE_UNREFERENCED:
			 *	case SFDR_STATE_UNCONFIGURED:
			 */
			case SBD_STAT_UNCONFIGURED:
				msp->ms_detpages = msp->ms_totpages;
				break;

			default:
				break;
			}
		}

		rv = kphysm_del_span_query(mp->sbm_basepfn,
						mp->sbm_npages, &mq);
		if (rv == KPHYSM_OK) {
			msp->ms_managed_pages = mq.managed;
			msp->ms_noreloc_pages = mq.nonrelocatable;
			msp->ms_noreloc_first = mq.first_nonrelocatable;
			msp->ms_noreloc_last = mq.last_nonrelocatable;
			msp->ms_cm.c_sflags = 0;
			if (mq.nonrelocatable) {
				SBD_SET_SUSPEND(SBD_CMD_UNCONFIGURE,
				    dsp->ds_suspend);
			}
		} else {
			PR_MEM("%s: kphysm_del_span_query() = %d\n", f, rv);
		}

		mix++;
		dsp++;
	}

	mutex_exit(&sbp->sb_slock);

	return (mix);
}

static void
sbd_cancel(sbd_handle_t *hp)
{
	int		i;
	sbd_devset_t	devset;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	static fn_t	f = "sbd_cancel";
	int		rv;

	PR_ALL("%s...\n", f);

	/*
	 * Only devices which have been "released" are
	 * subject to cancellation.
	 */
	devset = HD2MACHHD(hp)->sh_devset & SBD_DEVS_UNREFERENCED(sbp);

	/*
	 * Nothing to do for CPUs or IO other than change back
	 * their state.
	 */
	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		if (!DEVSET_IN_SET(devset, SBD_COMP_CPU, i))
			continue;
		if (sbd_cancel_cpu(hp, i) != SBD_CPUERR_FATAL) {
			SBD_DEVICE_TRANSITION(sbp, SBD_COMP_CPU, i,
						SBD_STATE_CONFIGURED);
		} else {
			SBD_DEVICE_TRANSITION(sbp, SBD_COMP_CPU, i,
						SBD_STATE_FATAL);
		}
	}

	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		if (!DEVSET_IN_SET(devset, SBD_COMP_IO, i))
			continue;
		SBD_DEVICE_TRANSITION(sbp, SBD_COMP_IO, i,
					SBD_STATE_CONFIGURED);
	}

	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		if (!DEVSET_IN_SET(devset, SBD_COMP_MEM, i))
			continue;
		if ((rv = sbd_cancel_mem(hp, i)) == 0) {
			SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM, i,
						SBD_STATE_CONFIGURED);
		} else if (rv == -1) {
			SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM, i,
						SBD_STATE_FATAL);
		}
	}

	PR_ALL("%s: unreleasing devset (0x%x)\n", f, (uint_t)devset);

	SBD_DEVS_CANCEL(sbp, devset);

	if (SBD_DEVS_UNREFERENCED(sbp) == 0) {
		sbd_istate_t	new_state;
		/*
		 * If the board no longer has any released devices
		 * than transfer it back to the CONFIG/PARTIAL state.
		 */
		if (SBD_DEVS_ATTACHED(sbp) == SBD_DEVS_PRESENT(sbp))
			new_state = SBD_STATE_CONFIGURED;
		else
			new_state = SBD_STATE_PARTIAL;
		if (SBD_BOARD_STATE(sbp) != new_state) {
			SBD_BOARD_TRANSITION(sbp, new_state);
		}
		sbp->sb_ostate = SBD_STAT_CONFIGURED;
		(void) drv_getparm(TIME, (void *)&sbp->sb_time);
	}
}

static void
sbd_get_ncm(sbd_handle_t *hp)
{
	sbd_devset_t devset;
	sbd_priv_handle_t	*shp = HD2MACHHD(hp);
	sbd_cmd_t		*cmdp =  (sbd_cmd_t *)hp->h_iap;
	int			error;

	/* pre_op restricted the devices to those selected by the ioctl */
	devset = shp->sh_devset;

	cmdp->cmd_getncm.g_ncm = sbd_cpu_cnt(hp, devset)
		+ sbd_io_cnt(hp, devset) + sbd_mem_cnt(hp, devset);

	error = sbd_copyout_ioarg(hp->h_mode, hp->h_cmd, cmdp,
		(sbd_ioctl_arg_t *)shp->sh_arg);

	if (error != 0)
		SBD_SET_ERRNO(SBD_HD2ERR(hp), error);
}

static void
sbd_status(sbd_handle_t *hp)
{
	int			nstat, mode, ncm, sz, cksz;
	sbd_priv_handle_t	*shp = HD2MACHHD(hp);
	sbd_devset_t		devset;
	sbd_board_t		*sbp = SBDH2BD(hp->h_sbd);
	sbd_stat_t		*dstatp;
	sbd_cmd_t		*cmdp =  (sbd_cmd_t *)hp->h_iap;
	sbdp_handle_t		*hdp;
	sbd_dev_stat_t		*devstatp;

#ifdef _MULTI_DATAMODEL
	int			sz32;
	sbd_stat32_t		*dstat32p;
#endif /* _MULTI_DATAMODEL */

	static fn_t	f = "sbd_status";

	mode = hp->h_mode;
	devset = shp->sh_devset;

	devset &= SBD_DEVS_PRESENT(sbp);

	if (cmdp->cmd_cm.c_id.c_type == SBD_COMP_NONE) {
		if (cmdp->cmd_cm.c_flags & SBD_FLAG_ALLCMP) {
			/*
			 * Get the number of components "ncm" on the board.
			 * Calculate size of buffer required to store one
			 * sbd_stat_t structure plus ncm-1 sbd_dev_stat_t
			 * structures. Note that sbd_stat_t already contains
			 * one sbd_dev_stat_t, so only an additional ncm-1
			 * sbd_dev_stat_t structures need to be accounted for
			 * in the calculation when more than one component
			 * is present.
			 */
			ncm = sbd_cpu_cnt(hp, devset) + sbd_io_cnt(hp, devset) +
			    sbd_mem_cnt(hp, devset);

		} else {
			/*
			 * In the case of c_type == SBD_COMP_NONE, and
			 * SBD_FLAG_ALLCMP not specified, only the board
			 * info is to be returned, no components.
			 */
			ncm = 0;
			devset = 0;
		}
	} else {
		/* Confirm that only one component is selected. */
		ncm = sbd_cpu_cnt(hp, devset) + sbd_io_cnt(hp, devset) +
		    sbd_mem_cnt(hp, devset);
		if (ncm != 1) {
			PR_ALL("%s: expected ncm of 1, got %d, devset 0x%x\n",
			    f, ncm, devset);
			SBD_SET_ERRNO(SBD_HD2ERR(hp), EINVAL);
			return;
		}
	}

	sz = sizeof (sbd_stat_t);
	if (ncm > 1)
		sz += sizeof (sbd_dev_stat_t) * (ncm - 1);

	cksz = sz;

	/*
	 * s_nbytes describes the size of the preallocated user
	 * buffer into which the application is executing to
	 * receive the sbd_stat_t and sbd_dev_stat_t structures.
	 * This buffer must be at least the required (sz) size.
	 */

#ifdef _MULTI_DATAMODEL

	/*
	 * More buffer space is required for the 64bit to 32bit
	 * conversion of data structures.
	 */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		sz32 = sizeof (sbd_stat32_t);
		if (ncm > 1)
			sz32  += sizeof (sbd_dev_stat32_t) * (ncm - 1);
		cksz = sz32;
	} else
		sz32 = 0;
#endif

	if ((int)cmdp->cmd_stat.s_nbytes < cksz) {
		PR_ALL("%s: ncm=%d s_nbytes = 0x%x\n", f, ncm,
		    cmdp->cmd_stat.s_nbytes);
		PR_ALL("%s: expected size of 0x%x\n", f, cksz);
		SBD_SET_ERRNO(SBD_HD2ERR(hp), EINVAL);
		return;
	}

	dstatp = kmem_zalloc(sz, KM_SLEEP);
	devstatp = &dstatp->s_stat[0];

#ifdef _MULTI_DATAMODEL
	if (sz32 != 0)
		dstat32p = kmem_zalloc(sz32, KM_SLEEP);
#endif

	/*
	 * if connected or better, provide cached status if available,
	 * otherwise call sbdp for status
	 */
	mutex_enter(&sbp->sb_flags_mutex);
	switch (sbp->sb_state) {

	case	SBD_STATE_CONNECTED:
	case	SBD_STATE_PARTIAL:
	case	SBD_STATE_CONFIGURED:
		if (sbp->sb_flags & SBD_BOARD_STATUS_CACHED) {
			bcopy(&sbp->sb_stat, dstatp, sizeof (sbd_stat_t));
			dstatp->s_rstate = rstate_cvt(sbp->sb_state);
			dstatp->s_ostate = ostate_cvt(sbp->sb_state);
			dstatp->s_busy = sbp->sb_busy;
			dstatp->s_time = sbp->sb_time;
			dstatp->s_cond = sbp->sb_cond;
			break;
		}
	/*FALLTHROUGH*/

	default:
		sbp->sb_flags &= ~SBD_BOARD_STATUS_CACHED;
		dstatp->s_board = sbp->sb_num;
		dstatp->s_ostate = ostate_cvt(sbp->sb_state);
		dstatp->s_time = sbp->sb_time;

		hdp = sbd_get_sbdp_handle(sbp, hp);

		if (sbdp_get_board_status(hdp, dstatp) != 0) {
			SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
			sbd_release_sbdp_handle(hdp);
#ifdef _MULTI_DATAMODEL
			if (sz32 != 0)
				kmem_free(dstat32p, sz32);
#endif
			kmem_free(dstatp, sz);
			mutex_exit(&sbp->sb_flags_mutex);
			return;
		}
		/*
		 * Do not cache status if the busy flag has
		 * been set by the call to sbdp_get_board_status().
		 */
		if (!dstatp->s_busy) {
			/* Can get board busy flag now */
			dstatp->s_busy = sbp->sb_busy;
			sbp->sb_cond = (sbd_cond_t)dstatp->s_cond;
			bcopy(dstatp, &sbp->sb_stat,
				sizeof (sbd_stat_t));
			sbp->sb_flags |= SBD_BOARD_STATUS_CACHED;
		}
		sbd_release_sbdp_handle(hdp);
		break;
	}
	mutex_exit(&sbp->sb_flags_mutex);

	if (DEVSET_IN_SET(devset, SBD_COMP_CPU, DEVSET_ANYUNIT))
		if ((nstat = sbd_cpu_flags(hp, devset, devstatp)) > 0) {
			dstatp->s_nstat += nstat;
			devstatp += nstat;
		}

	if (DEVSET_IN_SET(devset, SBD_COMP_MEM, DEVSET_ANYUNIT))
		if ((nstat = sbd_mem_status(hp, devset, devstatp)) > 0) {
			dstatp->s_nstat += nstat;
			devstatp += nstat;
		}

	if (DEVSET_IN_SET(devset, SBD_COMP_IO, DEVSET_ANYUNIT))
		if ((nstat = sbd_io_status(hp, devset, devstatp)) > 0) {
			dstatp->s_nstat += nstat;
			devstatp += nstat;
		}

	/* paranoia: detect buffer overrun */
	if ((caddr_t)devstatp > ((caddr_t)dstatp) + sz) {
		PR_ALL("%s: buffer overrun\n", f);
#ifdef _MULTI_DATAMODEL
		if (sz32 != 0)
			kmem_free(dstat32p, sz32);
#endif
		kmem_free(dstatp, sz);
		SBD_SET_ERRNO(SBD_HD2ERR(hp), EINVAL);
		return;
	}

/* if necessary, move data into intermediate device status buffer */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		int		i, j;

		ASSERT(sz32 != 0);
		/* paranoia: detect buffer overrun */
		if ((caddr_t)&dstat32p->s_stat[dstatp->s_nstat] >
		    ((caddr_t)dstat32p) + sz32) {
			cmn_err(CE_WARN,
				"sbd:%s: buffer32 overrun", f);
#ifdef _MULTI_DATAMODEL
			if (sz32 != 0)
				kmem_free(dstat32p, sz32);
#endif
			kmem_free(dstatp, sz);
			SBD_SET_ERRNO(SBD_HD2ERR(hp), EINVAL);
			return;
		}

		/*
		 * initialize 32 bit sbd board status structure
		 */
		dstat32p->s_board = (int32_t)dstatp->s_board;
		dstat32p->s_nstat = (int32_t)dstatp->s_nstat;
		dstat32p->s_rstate = dstatp->s_rstate;
		dstat32p->s_ostate = dstatp->s_ostate;
		dstat32p->s_cond = dstatp->s_cond;
		dstat32p->s_busy = dstatp->s_busy;
		dstat32p->s_time = dstatp->s_time;
		dstat32p->s_assigned = dstatp->s_assigned;
		dstat32p->s_power = dstatp->s_power;
		dstat32p->s_platopts = (int32_t)dstatp->s_platopts;
		(void) strcpy(dstat32p->s_type, dstatp->s_type);

		for (i = 0; i < dstatp->s_nstat; i++) {
			sbd_dev_stat_t	*dsp = &dstatp->s_stat[i];
			sbd_dev_stat32_t	*ds32p = &dstat32p->s_stat[i];

			/*
			 * copy common data for the device
			 */
			ds32p->d_cm.ci_type = (int32_t)dsp->d_cm.ci_type;
			ds32p->d_cm.ci_unit = (int32_t)dsp->d_cm.ci_unit;
			ds32p->d_cm.c_ostate = (int32_t)dsp->d_cm.c_ostate;
			ds32p->d_cm.c_cond = (int32_t)dsp->d_cm.c_cond;
			ds32p->d_cm.c_busy = (int32_t)dsp->d_cm.c_busy;
			ds32p->d_cm.c_time = (time32_t)dsp->d_cm.c_time;
			ds32p->d_cm.c_sflags = (int32_t)dsp->d_cm.c_sflags;
			(void) strcpy(ds32p->d_cm.ci_name, dsp->d_cm.ci_name);

			/* copy type specific data for the device */
			switch (dsp->d_cm.ci_type) {

			case SBD_COMP_CPU:
				ds32p->d_cpu.cs_isbootproc =
					(int32_t)dsp->d_cpu.cs_isbootproc;
				ds32p->d_cpu.cs_cpuid =
					(int32_t)dsp->d_cpu.cs_cpuid;
				ds32p->d_cpu.cs_speed =
					(int32_t)dsp->d_cpu.cs_speed;
				ds32p->d_cpu.cs_ecache =
					(int32_t)dsp->d_cpu.cs_ecache;
				break;

			case SBD_COMP_MEM:
				ds32p->d_mem.ms_type =
					(int32_t)dsp->d_mem.ms_type;
				ds32p->d_mem.ms_ostate =
					(int32_t)dsp->d_mem.ms_ostate;
				ds32p->d_mem.ms_cond =
					(int32_t)dsp->d_mem.ms_cond;
				ds32p->d_mem.ms_interleave =
					(uint32_t)dsp->d_mem.ms_interleave;
				ds32p->d_mem.ms_basepfn =
					(uint32_t)dsp->d_mem.ms_basepfn;
				ds32p->d_mem.ms_totpages =
					(uint32_t)dsp->d_mem.ms_totpages;
				ds32p->d_mem.ms_detpages =
					(uint32_t)dsp->d_mem.ms_detpages;
				ds32p->d_mem.ms_pageslost =
					(int32_t)dsp->d_mem.ms_pageslost;
				ds32p->d_mem.ms_managed_pages =
					(int32_t)dsp->d_mem.ms_managed_pages;
				ds32p->d_mem.ms_noreloc_pages =
					(int32_t)dsp->d_mem.ms_noreloc_pages;
				ds32p->d_mem.ms_noreloc_first =
					(int32_t)dsp->d_mem.ms_noreloc_first;
				ds32p->d_mem.ms_noreloc_last =
					(int32_t)dsp->d_mem.ms_noreloc_last;
				ds32p->d_mem.ms_cage_enabled =
					(int32_t)dsp->d_mem.ms_cage_enabled;
				ds32p->d_mem.ms_peer_is_target =
					(int32_t)dsp->d_mem.ms_peer_is_target;
				(void) strcpy(ds32p->d_mem.ms_peer_ap_id,
					dsp->d_mem.ms_peer_ap_id);
				break;


			case SBD_COMP_IO:

				ds32p->d_io.is_type =
					(int32_t)dsp->d_io.is_type;
				ds32p->d_io.is_unsafe_count =
					(int32_t)dsp->d_io.is_unsafe_count;
				ds32p->d_io.is_referenced =
					(int32_t)dsp->d_io.is_referenced;
				for (j = 0; j < SBD_MAX_UNSAFE; j++)
					ds32p->d_io.is_unsafe_list[j] =
					    (int32_t)
					    ds32p->d_io.is_unsafe_list[j];
				bcopy(dsp->d_io.is_pathname,
				    ds32p->d_io.is_pathname, MAXPATHLEN);
				break;

			case SBD_COMP_CMP:
				/* copy sbd_cmp_stat_t structure members */
				bcopy(&dsp->d_cmp.ps_cpuid[0],
					&ds32p->d_cmp.ps_cpuid[0],
					sizeof (ds32p->d_cmp.ps_cpuid));
				ds32p->d_cmp.ps_ncores =
					(int32_t)dsp->d_cmp.ps_ncores;
				ds32p->d_cmp.ps_speed =
					(int32_t)dsp->d_cmp.ps_speed;
				ds32p->d_cmp.ps_ecache =
					(int32_t)dsp->d_cmp.ps_ecache;
				break;

			default:
				cmn_err(CE_WARN,
				    "sbd:%s: unknown dev type (%d)", f,
				    (int)dsp->d_cm.c_id.c_type);
				break;
			}
		}

		if (ddi_copyout((void *)dstat32p,
		    cmdp->cmd_stat.s_statp, sz32, mode) != 0) {
			cmn_err(CE_WARN,
				"sbd:%s: failed to copyout status "
				"for board %d", f, sbp->sb_num);
			SBD_SET_ERRNO(SBD_HD2ERR(hp), EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout((void *)dstatp, cmdp->cmd_stat.s_statp,
	    sz, mode) != 0) {
		cmn_err(CE_WARN,
			"sbd:%s: failed to copyout status for board %d",
			f, sbp->sb_num);
		SBD_SET_ERRNO(SBD_HD2ERR(hp), EFAULT);
	}

#ifdef _MULTI_DATAMODEL
	if (sz32 != 0)
		kmem_free(dstat32p, sz32);
#endif
	kmem_free(dstatp, sz);
}

/*
 * Called at driver load time to determine the state and condition
 * of an existing board in the system.
 */
static void
sbd_board_discovery(sbd_board_t *sbp)
{
	int		i;
	dev_info_t	*dip;
	sbd_devset_t	devs_lost, devs_attached = 0;
	extern kmutex_t	cpu_lock;
	sbdp_handle_t	*hdp;
	static fn_t	f = "sbd_board_discovery";
	sbderror_t	error, *ep;
	sbd_handle_t	*hp = MACHBD2HD(sbp);

	if (SBD_DEVS_PRESENT(sbp) == 0) {
		PR_ALL("%s: board %d has no devices present\n",
			f, sbp->sb_num);
		return;
	}

	ep = &error;
	bzero(ep, sizeof (sbderror_t));

	/*
	 * Check for existence of cpus.
	 */

	hdp = sbd_get_sbdp_handle(sbp, hp);

	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		processorid_t	cpuid;

		if (!SBD_DEV_IS_PRESENT(sbp, SBD_COMP_CPU, i))
			continue;

		dip = sbp->sb_devlist[NIX(SBD_COMP_CPU)][i];

		if (dip != NULL) {
			cpuid = sbdp_get_cpuid(hdp, dip);

			if (cpuid < 0) {
				SBD_GET_PERR(hdp->h_err,
				    ep);
				continue;
			}

			mutex_enter(&cpu_lock);	/* needed to call cpu_get() */
			if (cpu_get(cpuid)) {
				SBD_DEV_SET_ATTACHED(sbp, SBD_COMP_CPU, i);
				DEVSET_ADD(devs_attached, SBD_COMP_CPU, i);
				PR_ALL("%s: board %d, cpuid %d - attached\n",
					f, sbp->sb_num, cpuid);
			}
			mutex_exit(&cpu_lock);
			sbd_init_cpu_unit(sbp, i);
		}
	}

	/*
	 * Check for existence of memory.
	 */
	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		uint64_t	basepa, endpa;
		struct memlist	*ml;
		extern struct memlist	*phys_install;

		if (!SBD_DEV_IS_PRESENT(sbp, SBD_COMP_MEM, i))
			continue;

		dip = sbp->sb_devlist[NIX(SBD_COMP_MEM)][i];
		if (dip == NULL)
			continue;

		if (sbdphw_get_base_physaddr(hdp, dip, &basepa)) {
			/* omit phantom memory controllers on I/O boards */
			if (SBD_DEV_IS_PRESENT(sbp, SBD_COMP_MEM, i)) {
				ASSERT(sbp->sb_ndev != 0);
				SBD_DEV_CLR_PRESENT(sbp, SBD_COMP_MEM, i);
				sbp->sb_ndev--;
			}
			sbp->sb_devlist[NIX(SBD_COMP_MEM)][i] = NULL;
			continue;
		}

		/*
		 * basepa may not be on a alignment boundary, make it so.
		 */
		if (sbdp_get_mem_alignment(hdp, dip, &endpa)) {
			cmn_err(CE_WARN, "%s sbdp_get_mem_alignment fail", f);
			continue;
		}

		basepa &= ~(endpa - 1);
		endpa += basepa;

		/*
		 * Check if base address is in phys_install.
		 */
		memlist_read_lock();
		for (ml = phys_install; ml; ml = ml->ml_next)
			if ((endpa <= ml->ml_address) ||
			    (basepa >= (ml->ml_address + ml->ml_size)))
				continue;
			else
				break;
		memlist_read_unlock();

		if (ml) {
			SBD_DEV_SET_ATTACHED(sbp, SBD_COMP_MEM, i);
			DEVSET_ADD(devs_attached, SBD_COMP_MEM, i);
			PR_ALL("%s: board %d, mem-unit %d - attached\n",
				f, sbp->sb_num, i);
		}
		sbd_init_mem_unit(sbp, i, ep);
	}
	sbd_release_sbdp_handle(hdp);

	/*
	 * If so far we have found an error, we just log it but continue
	 */
	if (SBD_GET_ERRNO(ep) != 0)
		cmn_err(CE_WARN, "%s errno has occurred: errno %d", f,
			SBD_GET_ERRNO(ep));

	/*
	 * Check for i/o state.
	 */
	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {

		if (!SBD_DEV_IS_PRESENT(sbp, SBD_COMP_IO, i))
			continue;

		dip = sbp->sb_devlist[NIX(SBD_COMP_IO)][i];
		if (dip == NULL)
			continue;

		ASSERT(e_ddi_branch_held(dip));

		/*
		 * XXX Is the devstate check needed ?
		 */
		if (i_ddi_devi_attached(dip) ||
		    ddi_get_devstate(dip) == DDI_DEVSTATE_UP) {

			/*
			 * Found it!
			 */
			SBD_DEV_SET_ATTACHED(sbp, SBD_COMP_IO, i);
			DEVSET_ADD(devs_attached, SBD_COMP_IO, i);
			PR_ALL("%s: board %d, io-unit %d - attached\n",
				f, sbp->sb_num, i);
		}
		sbd_init_io_unit(sbp, i);
	}

	SBD_DEVS_CONFIGURE(sbp, devs_attached);
	if (devs_attached && ((devs_lost = SBD_DEVS_UNATTACHED(sbp)) != 0)) {
		int		ut;
		/*
		 * A prior comment stated that a partially configured
		 * board was not permitted. The Serengeti architecture
		 * makes this possible, so the SB_DEVS_DISCONNECT
		 * at the end of this block has been removed.
		 */

		PR_ALL("%s: some devices not configured (0x%x)...\n",
			f, devs_lost);

		for (ut = 0; ut < MAX_CPU_UNITS_PER_BOARD; ut++)
			if (DEVSET_IN_SET(devs_lost, SBD_COMP_CPU, ut)) {
				SBD_DEVICE_TRANSITION(sbp, SBD_COMP_CPU,
					ut, SBD_STATE_UNCONFIGURED);
			}

		for (ut = 0; ut < MAX_MEM_UNITS_PER_BOARD; ut++)
			if (DEVSET_IN_SET(devs_lost, SBD_COMP_MEM, ut)) {
				SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM,
					ut, SBD_STATE_UNCONFIGURED);
			}

		for (ut = 0; ut < MAX_IO_UNITS_PER_BOARD; ut++)
			if (DEVSET_IN_SET(devs_lost, SBD_COMP_IO, ut)) {
				SBD_DEVICE_TRANSITION(sbp, SBD_COMP_IO,
					ut, SBD_STATE_UNCONFIGURED);
			}
	}
}

static int
hold_rele_branch(dev_info_t *rdip, void *arg)
{
	walk_tree_t	*wp = (walk_tree_t *)arg;

	ASSERT(wp && (wp->hold == 0 || wp->hold == 1));

	switch (get_node_type(wp->sbp, rdip, NULL)) {
		case SBD_COMP_CMP:
		case SBD_COMP_MEM:
		case SBD_COMP_IO:
			break;
		case SBD_COMP_CPU:

			/*
			 * All CPU nodes under CMP nodes should have
			 * gotten pruned when the CMP node was first
			 * encountered.
			 */
			ASSERT(!sbd_is_cmp_child(rdip));

			break;

		case SBD_COMP_UNKNOWN:
			/* Not of interest to us */
			return (DDI_WALK_CONTINUE);
		default:
			ASSERT(0);
			return (DDI_WALK_PRUNECHILD);
	}

	if (wp->hold) {
		ASSERT(!e_ddi_branch_held(rdip));
		e_ddi_branch_hold(rdip);
	} else {
		ASSERT(e_ddi_branch_held(rdip));
		e_ddi_branch_rele(rdip);
	}

	return (DDI_WALK_PRUNECHILD);
}

static void
sbd_board_init(sbd_board_t *sbp, sbd_softstate_t *softsp,
	int bd, dev_info_t *top_dip, int wnode)
{
	int		i;
	dev_info_t	*pdip;
	walk_tree_t	walk = {0};

	mutex_init(&sbp->sb_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sbp->sb_flags_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sbp->sb_slock, NULL, MUTEX_DRIVER, NULL);

	sbp->sb_ref = 0;
	sbp->sb_num = bd;
	sbp->sb_time = gethrestime_sec();
	/*
	 * For serengeti, top_dip doesn't need to be held because
	 * sbp i.e. sbd_board_t will be destroyed in sbd_teardown_instance()
	 * before top_dip detaches. For Daktari, top_dip is the
	 * root node which never has to be held.
	 */
	sbp->sb_topdip = top_dip;
	sbp->sb_cpuid = -1;
	sbp->sb_softsp = (void *) softsp;
	sbp->sb_cond = SBD_COND_UNKNOWN;
	sbp->sb_wnode = wnode;
	sbp->sb_memaccess_ok = 1;

	ASSERT(MAX_IO_UNITS_PER_BOARD <= SBD_MAX_UNITS_PER_BOARD);
	ASSERT(MAX_CPU_UNITS_PER_BOARD <= SBD_MAX_UNITS_PER_BOARD);
	ASSERT(MAX_MEM_UNITS_PER_BOARD <= SBD_MAX_UNITS_PER_BOARD);

	/*
	 * Allocate the devlist for cpus.
	 */
	sbp->sb_devlist[NIX(SBD_COMP_CPU)] = GETSTRUCT(dev_info_t *,
						MAX_CPU_UNITS_PER_BOARD);

	/*
	 * Allocate the devlist for mem.
	 */
	sbp->sb_devlist[NIX(SBD_COMP_MEM)] = GETSTRUCT(dev_info_t *,
						MAX_MEM_UNITS_PER_BOARD);

	/*
	 * Allocate the devlist for io.
	 */
	sbp->sb_devlist[NIX(SBD_COMP_IO)] = GETSTRUCT(dev_info_t *,
						MAX_IO_UNITS_PER_BOARD);


	sbp->sb_dev[NIX(SBD_COMP_CPU)] = GETSTRUCT(sbd_dev_unit_t,
						MAX_CPU_UNITS_PER_BOARD);

	sbp->sb_dev[NIX(SBD_COMP_MEM)] = GETSTRUCT(sbd_dev_unit_t,
						MAX_MEM_UNITS_PER_BOARD);

	sbp->sb_dev[NIX(SBD_COMP_IO)] = GETSTRUCT(sbd_dev_unit_t,
						MAX_IO_UNITS_PER_BOARD);

	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		sbp->sb_cpupath[i] = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	}

	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		sbp->sb_mempath[i] = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	}

	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		sbp->sb_iopath[i] = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	}

	/*
	 * Walk the device tree, find all top dips on this board and
	 * hold the branches rooted at them
	 */
	ASSERT(sbp->sb_topdip);
	pdip = ddi_get_parent(sbp->sb_topdip);
	if (pdip)
		ndi_devi_enter(pdip);
	walk.sbp = sbp;
	walk.hold = 1;
	ddi_walk_devs(sbp->sb_topdip, hold_rele_branch, (void *)&walk);
	if (pdip)
		ndi_devi_exit(pdip);

	/*
	 * Initialize the devlists
	 */
	if (sbd_init_devlists(sbp) == 0) {
		SBD_BOARD_TRANSITION(sbp, SBD_STATE_EMPTY);
	} else {
		/*
		 * Couldn't have made it down here without
		 * having found at least one device.
		 */
		ASSERT(SBD_DEVS_PRESENT(sbp) != 0);
		/*
		 * Check the state of any possible devices on the
		 * board.
		 */
		sbd_board_discovery(sbp);

		if (SBD_DEVS_UNATTACHED(sbp) == 0) {
			/*
			 * The board has no unattached devices, therefore
			 * by reason of insanity it must be configured!
			 */
			SBD_BOARD_TRANSITION(sbp, SBD_STATE_CONFIGURED);
			sbp->sb_cond = SBD_COND_OK;
		} else if (SBD_DEVS_ATTACHED(sbp)) {
			SBD_BOARD_TRANSITION(sbp, SBD_STATE_PARTIAL);
		} else {
			SBD_BOARD_TRANSITION(sbp, SBD_STATE_CONNECTED);
		}
	}
}

static void
sbd_board_destroy(sbd_board_t *sbp)
{
	int		i;
	dev_info_t	*pdip;
	walk_tree_t	walk = {0};

	SBD_BOARD_TRANSITION(sbp, SBD_STATE_EMPTY);

#ifdef DEBUG
	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		sbd_mem_unit_t *mp;

		mp = SBD_GET_BOARD_MEMUNIT(sbp, i);
		ASSERT(mp->sbm_mlist == NULL);
	}
#endif /* DEBUG */

	/*
	 * Free up MEM unit structs.
	 */
	FREESTRUCT(sbp->sb_dev[NIX(SBD_COMP_MEM)],
			sbd_dev_unit_t, MAX_MEM_UNITS_PER_BOARD);
	sbp->sb_dev[NIX(SBD_COMP_MEM)] = NULL;

	/*
	 * Free up CPU unit structs.
	 */
	FREESTRUCT(sbp->sb_dev[NIX(SBD_COMP_CPU)],
			sbd_dev_unit_t, MAX_CPU_UNITS_PER_BOARD);
	sbp->sb_dev[NIX(SBD_COMP_CPU)] = NULL;

	/*
	 * Free up IO unit structs.
	 */
	FREESTRUCT(sbp->sb_dev[NIX(SBD_COMP_IO)],
			sbd_dev_unit_t, MAX_IO_UNITS_PER_BOARD);
	sbp->sb_dev[NIX(SBD_COMP_IO)] = NULL;

	/*
	 * free up CPU devlists.
	 */

	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		kmem_free((caddr_t)sbp->sb_cpupath[i], MAXPATHLEN);
	}
	FREESTRUCT(sbp->sb_devlist[NIX(SBD_COMP_CPU)], dev_info_t *,
		MAX_CPU_UNITS_PER_BOARD);
	sbp->sb_devlist[NIX(SBD_COMP_CPU)] = NULL;

	/*
	 * free up MEM devlists.
	 */
	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		kmem_free((caddr_t)sbp->sb_mempath[i], MAXPATHLEN);
	}
	FREESTRUCT(sbp->sb_devlist[NIX(SBD_COMP_MEM)], dev_info_t *,
		MAX_MEM_UNITS_PER_BOARD);
	sbp->sb_devlist[NIX(SBD_COMP_MEM)] = NULL;

	/*
	 * free up IO devlists.
	 */
	for (i = 0; i <  MAX_IO_UNITS_PER_BOARD; i++) {
		kmem_free((caddr_t)sbp->sb_iopath[i], MAXPATHLEN);
	}
	FREESTRUCT(sbp->sb_devlist[NIX(SBD_COMP_IO)], dev_info_t *,
		MAX_IO_UNITS_PER_BOARD);
	sbp->sb_devlist[NIX(SBD_COMP_IO)] = NULL;

	/*
	 * Release all branches held earlier
	 */
	ASSERT(sbp->sb_topdip);
	pdip = ddi_get_parent(sbp->sb_topdip);
	if (pdip)
		ndi_devi_enter(pdip);
	walk.sbp = sbp;
	walk.hold = 0;
	ddi_walk_devs(sbp->sb_topdip, hold_rele_branch, (void *)&walk);
	if (pdip)
		ndi_devi_exit(pdip);

	mutex_destroy(&sbp->sb_slock);
	mutex_destroy(&sbp->sb_flags_mutex);
	mutex_destroy(&sbp->sb_mutex);
}

sbd_comp_type_t
sbd_cm_type(char *name)
{
	sbd_comp_type_t type = SBD_COMP_UNKNOWN;
	int i;

	/* look up type in table */
	for (i = 0; SBD_COMP(i) != SBD_COMP_UNKNOWN; i++) {
		if (strcmp(name, SBD_OTYPE(i)) == 0) {
			type = SBD_COMP(i);
			break;
		}
	}

	return (type);
}

/*
 * There are certain cases where obp marks components as failed
 * If the status is ok the node won't have any status property. It
 * is only there if the status is other than ok.
 *
 * The translation is as follows:
 * If there is no status prop, the the cond is SBD_COND_OK
 * If we find a status prop but can't get to it then cond is SBD_COND_UNKNOWN
 * if we find a stat and it is failed the cond is SBD_COND_FAILED
 * If the stat is disabled, the cond is SBD_COND_UNUSABLE
 * Otherwise we return con as SBD_COND_OK
 */
sbd_cond_t
sbd_get_comp_cond(dev_info_t *dip)
{
	int			len;
	char			*status_buf;
	static const char	*status = "status";
	static const char	*failed = "fail";
	static const char	*disabled = "disabled";

	if (dip == NULL) {
		PR_BYP("dip is NULL\n");
		return (SBD_COND_UNKNOWN);
	}

	/*
	 * If retired, return FAILED
	 */
	if (DEVI(dip)->devi_flags & DEVI_RETIRED) {
		PR_CPU("dip is retired\n");
		return (SBD_COND_FAILED);
	}

	if (ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    (char *)status, &len) != DDI_PROP_SUCCESS) {
		PR_CPU("status in sbd is ok\n");
		return (SBD_COND_OK);
	}

	status_buf = kmem_zalloc(sizeof (char) * OBP_MAXPROPNAME, KM_SLEEP);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    (char *)status, status_buf, &len) != DDI_PROP_SUCCESS) {
		PR_CPU("status in sbd is unknown\n");
		return (SBD_COND_UNKNOWN);
	}

	if (strncmp(status_buf, failed, strlen(failed)) == 0) {
		PR_CPU("status in sbd is failed\n");
		kmem_free(status_buf, sizeof (char) * OBP_MAXPROPNAME);
		return (SBD_COND_FAILED);
	}

	if (strcmp(status_buf, disabled) == 0) {
		PR_CPU("status in sbd is unusable\n");
		kmem_free(status_buf, sizeof (char) * OBP_MAXPROPNAME);
		return (SBD_COND_UNUSABLE);
	}

	kmem_free(status_buf, sizeof (char) * OBP_MAXPROPNAME);
	return (SBD_COND_OK);
}

#ifdef SBD_DEBUG_ERRS

/* function to simulate errors throughout the sbd code */
void
sbd_inject_err(int error, sbderror_t *ep, int Errno, int ecode,
	char *rsc)
{
	static fn_t	f = "sbd_inject_err";

	if (sbd_err_debug == 0)
		return;

	if (ep == NULL) {
		cmn_err(CE_WARN, "%s ep is NULL", f);
		return;
	}

	if (SBD_GET_ERRNO(ep) != 0) {
		cmn_err(CE_WARN, "%s errno already set to %d", f,
			SBD_GET_ERRNO(ep));
		return;
	}

	if (SBD_GET_ERR(ep) != 0) {
		cmn_err(CE_WARN, "%s code already set to %d", f,
			SBD_GET_ERR(ep));
		return;
	}

	if ((sbd_err_debug & (1 << error)) != 0) {
		ep->e_errno = Errno;
		ep->e_code = ecode;

		if (rsc != NULL)
			bcopy((caddr_t)rsc,
			(caddr_t)ep->e_rsc,
			sizeof (ep->e_rsc));

		if (Errno != 0)
			PR_ERR_ERRNO("%s set errno to %d", f, ep->e_errno);

		if (ecode != 0)
			PR_ERR_ECODE("%s set ecode to %d", f, ep->e_code);

		if (rsc != NULL)
			PR_ERR_RSC("%s set rsc to %s", f, ep->e_rsc);
	}
}
#endif
