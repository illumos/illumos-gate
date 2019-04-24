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
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

/*
 * PIM-DR layer of DR driver.  Provides interface between user
 * level applications and the PSM-DR layer.
 */

#include <sys/note.h>
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
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/mem_config.h>

#include <sys/autoconf.h>
#include <sys/cmn_err.h>

#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/machsystm.h>

#include <sys/dr.h>
#include <sys/drmach.h>
#include <sys/dr_util.h>

extern int		 nulldev();
extern int		 nodev();
extern struct memlist	*phys_install;

#ifdef DEBUG
uint_t	dr_debug = 0;			/* dr.h for bit values */
#endif /* DEBUG */

static int	dr_dev_type_to_nt(char *);

/*
 * NOTE: state_str, nt_str and SBD_CMD_STR are only used in a debug
 * kernel.  They are, however, referenced during both debug and non-debug
 * compiles.
 */

static char *state_str[] = {
	"EMPTY", "OCCUPIED", "CONNECTED", "UNCONFIGURED",
	"PARTIAL", "CONFIGURED", "RELEASE", "UNREFERENCED",
	"FATAL"
};

#define	SBD_CMD_STR(c) \
	(((c) == SBD_CMD_ASSIGN)	? "ASSIGN"	: \
	((c) == SBD_CMD_UNASSIGN)	? "UNASSIGN"	: \
	((c) == SBD_CMD_POWERON)	? "POWERON"	: \
	((c) == SBD_CMD_POWEROFF)	? "POWEROFF"	: \
	((c) == SBD_CMD_TEST)		? "TEST"	: \
	((c) == SBD_CMD_CONNECT)	? "CONNECT"	: \
	((c) == SBD_CMD_DISCONNECT)	? "DISCONNECT"	: \
	((c) == SBD_CMD_CONFIGURE)	? "CONFIGURE"	: \
	((c) == SBD_CMD_UNCONFIGURE)	? "UNCONFIGURE"	: \
	((c) == SBD_CMD_GETNCM)		? "GETNCM"	: \
	((c) == SBD_CMD_PASSTHRU)	? "PASSTHRU"	: \
	((c) == SBD_CMD_STATUS)		? "STATUS"	: "unknown")

#define	DR_GET_BOARD_DEVUNIT(sb, ut, un) (&((sb)->b_dev[DEVSET_NIX(ut)][un]))

#define	DR_MAKE_MINOR(i, b)	(((i) << 16) | (b))
#define	DR_MINOR2INST(m)	(((m) >> 16) & 0xffff)
#define	DR_MINOR2BNUM(m)	((m) & 0xffff)

/* for the DR*INTERNAL_ERROR macros.  see sys/dr.h. */
static char *dr_ie_fmt = "dr.c %d";

/* struct for drmach device name to sbd_comp_type_t mapping */
typedef	struct {
	char		*s_devtype;
	sbd_comp_type_t	s_nodetype;
} dr_devname_t;

/* struct to map starfire device attributes - name:sbd_comp_type_t */
static	dr_devname_t	dr_devattr[] = {
	{ DRMACH_DEVTYPE_MEM,	SBD_COMP_MEM },
	{ DRMACH_DEVTYPE_CPU,	SBD_COMP_CPU },
	{ DRMACH_DEVTYPE_PCI,	SBD_COMP_IO },
#if defined(DRMACH_DEVTYPE_SBUS)
	{ DRMACH_DEVTYPE_SBUS,	SBD_COMP_IO },
#endif
#if defined(DRMACH_DEVTYPE_WCI)
	{ DRMACH_DEVTYPE_WCI,	SBD_COMP_IO },
#endif
	/* last s_devtype must be NULL, s_nodetype must be SBD_COMP_UNKNOWN */
	{ NULL,			SBD_COMP_UNKNOWN }
};

/*
 * Per instance soft-state structure.
 */
typedef struct dr_softstate {
	dev_info_t	*dip;
	dr_board_t	*boards;
	kmutex_t	 i_lock;
	int		 dr_initialized;
} dr_softstate_t;

/*
 * dr Global data elements
 */
struct dr_global {
	dr_softstate_t	*softsp;	/* pointer to initialize soft state */
	kmutex_t	lock;
} dr_g;

dr_unsafe_devs_t	dr_unsafe_devs;

/*
 * Table of known passthru commands.
 */
struct {
	char	*pt_name;
	int	(*pt_func)(dr_handle_t *);
} pt_arr[] = {
	"quiesce",		dr_pt_test_suspend,
};

int dr_modunload_okay = 0;		/* set to non-zero to allow unload */

/*
 * State transition table.  States valid transitions for "board" state.
 * Recall that non-zero return value terminates operation, however
 * the herrno value is what really indicates an error , if any.
 */
static int
_cmd2index(int c)
{
	/*
	 * Translate DR CMD to index into dr_state_transition.
	 */
	switch (c) {
	case SBD_CMD_CONNECT:		return (0);
	case SBD_CMD_DISCONNECT:	return (1);
	case SBD_CMD_CONFIGURE:		return (2);
	case SBD_CMD_UNCONFIGURE:	return (3);
	case SBD_CMD_ASSIGN:		return (4);
	case SBD_CMD_UNASSIGN:		return (5);
	case SBD_CMD_POWERON:		return (6);
	case SBD_CMD_POWEROFF:		return (7);
	case SBD_CMD_TEST:		return (8);
	default:			return (-1);
	}
}

#define	CMD2INDEX(c)	_cmd2index(c)

static struct dr_state_trans {
	int	x_cmd;
	struct {
		int	x_rv;		/* return value of pre_op */
		int	x_err;		/* error, if any */
	} x_op[DR_STATE_MAX];
} dr_state_transition[] = {
	{ SBD_CMD_CONNECT,
		{
			{ 0, 0 },			/* empty */
			{ 0, 0 },			/* occupied */
			{ -1, ESBD_STATE },		/* connected */
			{ -1, ESBD_STATE },		/* unconfigured */
			{ -1, ESBD_STATE },		/* partial */
			{ -1, ESBD_STATE },		/* configured */
			{ -1, ESBD_STATE },		/* release */
			{ -1, ESBD_STATE },		/* unreferenced */
			{ -1, ESBD_FATAL_STATE },	/* fatal */
		}
	},
	{ SBD_CMD_DISCONNECT,
		{
			{ -1, ESBD_STATE },		/* empty */
			{ 0, 0 },			/* occupied */
			{ 0, 0 },			/* connected */
			{ 0, 0 },			/* unconfigured */
			{ -1, ESBD_STATE },		/* partial */
			{ -1, ESBD_STATE },		/* configured */
			{ -1, ESBD_STATE },		/* release */
			{ -1, ESBD_STATE },		/* unreferenced */
			{ -1, ESBD_FATAL_STATE },	/* fatal */
		}
	},
	{ SBD_CMD_CONFIGURE,
		{
			{ -1, ESBD_STATE },		/* empty */
			{ -1, ESBD_STATE },		/* occupied */
			{ 0, 0 },			/* connected */
			{ 0, 0 },			/* unconfigured */
			{ 0, 0 },			/* partial */
			{ 0, 0 },			/* configured */
			{ -1, ESBD_STATE },		/* release */
			{ -1, ESBD_STATE },		/* unreferenced */
			{ -1, ESBD_FATAL_STATE },	/* fatal */
		}
	},
	{ SBD_CMD_UNCONFIGURE,
		{
			{ -1, ESBD_STATE },		/* empty */
			{ -1, ESBD_STATE },		/* occupied */
			{ -1, ESBD_STATE },		/* connected */
			{ -1, ESBD_STATE },		/* unconfigured */
			{ 0, 0 },			/* partial */
			{ 0, 0 },			/* configured */
			{ 0, 0 },			/* release */
			{ 0, 0 },			/* unreferenced */
			{ -1, ESBD_FATAL_STATE },	/* fatal */
		}
	},
	{ SBD_CMD_ASSIGN,
		{
			{ 0, 0 },			/* empty */
			{ 0, 0 },			/* occupied */
			{ -1, ESBD_STATE },		/* connected */
			{ -1, ESBD_STATE },		/* unconfigured */
			{ -1, ESBD_STATE },		/* partial */
			{ -1, ESBD_STATE },		/* configured */
			{ -1, ESBD_STATE },		/* release */
			{ -1, ESBD_STATE },		/* unreferenced */
			{ -1, ESBD_FATAL_STATE },	/* fatal */
		}
	},
	{ SBD_CMD_UNASSIGN,
		{
			{ 0, 0 },			/* empty */
			{ 0, 0 },			/* occupied */
			{ -1, ESBD_STATE },		/* connected */
			{ -1, ESBD_STATE },		/* unconfigured */
			{ -1, ESBD_STATE },		/* partial */
			{ -1, ESBD_STATE },		/* configured */
			{ -1, ESBD_STATE },		/* release */
			{ -1, ESBD_STATE },		/* unreferenced */
			{ -1, ESBD_FATAL_STATE },	/* fatal */
		}
	},
	{ SBD_CMD_POWERON,
		{
			{ 0, 0 },			/* empty */
			{ 0, 0 },			/* occupied */
			{ -1, ESBD_STATE },		/* connected */
			{ -1, ESBD_STATE },		/* unconfigured */
			{ -1, ESBD_STATE },		/* partial */
			{ -1, ESBD_STATE },		/* configured */
			{ -1, ESBD_STATE },		/* release */
			{ -1, ESBD_STATE },		/* unreferenced */
			{ -1, ESBD_FATAL_STATE },	/* fatal */
		}
	},
	{ SBD_CMD_POWEROFF,
		{
			{ 0, 0 },			/* empty */
			{ 0, 0 },			/* occupied */
			{ -1, ESBD_STATE },		/* connected */
			{ -1, ESBD_STATE },		/* unconfigured */
			{ -1, ESBD_STATE },		/* partial */
			{ -1, ESBD_STATE },		/* configured */
			{ -1, ESBD_STATE },		/* release */
			{ -1, ESBD_STATE },		/* unreferenced */
			{ -1, ESBD_FATAL_STATE },	/* fatal */
		}
	},
	{ SBD_CMD_TEST,
		{
			{ 0, 0 },			/* empty */
			{ 0, 0 },			/* occupied */
			{ -1, ESBD_STATE },		/* connected */
			{ -1, ESBD_STATE },		/* unconfigured */
			{ -1, ESBD_STATE },		/* partial */
			{ -1, ESBD_STATE },		/* configured */
			{ -1, ESBD_STATE },		/* release */
			{ -1, ESBD_STATE },		/* unreferenced */
			{ -1, ESBD_FATAL_STATE },	/* fatal */
		}
	},
};

/*
 * Global R/W lock to synchronize access across
 * multiple boards.  Users wanting multi-board access
 * must grab WRITE lock, others must grab READ lock.
 */
krwlock_t	dr_grwlock;

/*
 * Head of the boardlist used as a reference point for
 * locating board structs.
 * TODO: eliminate dr_boardlist
 */
dr_board_t	*dr_boardlist;

/*
 * DR support functions.
 */
static dr_devset_t	dr_dev2devset(sbd_comp_id_t *cid);
static int		dr_check_transition(dr_board_t *bp,
					dr_devset_t *devsetp,
					struct dr_state_trans *transp,
					int cmd);
static int		dr_check_unit_attached(dr_common_unit_t *dp);
static sbd_error_t	*dr_init_devlists(dr_board_t *bp);
static void		dr_board_discovery(dr_board_t *bp);
static int		dr_board_init(dr_board_t *bp, dev_info_t *dip, int bd);
static void		dr_board_destroy(dr_board_t *bp);
static void		dr_board_transition(dr_board_t *bp, dr_state_t st);

/*
 * DR driver (DDI) entry points.
 */
static int	dr_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
				void *arg, void **result);
static int	dr_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	dr_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	dr_probe(dev_info_t *dip);
static int	dr_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
				cred_t *cred_p, int *rval_p);
static int	dr_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int	dr_open(dev_t *dev, int flag, int otyp, cred_t *cred_p);

/*
 * DR command processing operations.
 */
static int	dr_copyin_iocmd(dr_handle_t *hp);
static int	dr_copyout_iocmd(dr_handle_t *hp);
static int	dr_copyout_errs(dr_handle_t *hp);
static int	dr_pre_op(dr_handle_t *hp);
static int	dr_post_op(dr_handle_t *hp, int rv);
static int	dr_exec_op(dr_handle_t *hp);
static void	dr_assign_board(dr_handle_t *hp);
static void	dr_unassign_board(dr_handle_t *hp);
static void	dr_connect(dr_handle_t *hp);
static int	dr_disconnect(dr_handle_t *hp);
static void	dr_dev_configure(dr_handle_t *hp);
static void	dr_dev_release(dr_handle_t *hp);
static int	dr_dev_unconfigure(dr_handle_t *hp);
static void	dr_dev_cancel(dr_handle_t *hp);
static int	dr_dev_status(dr_handle_t *hp);
static int	dr_get_ncm(dr_handle_t *hp);
static int	dr_pt_ioctl(dr_handle_t *hp);
static void	dr_poweron_board(dr_handle_t *hp);
static void	dr_poweroff_board(dr_handle_t *hp);
static void	dr_test_board(dr_handle_t *hp);

/*
 * Autoconfiguration data structures
 */
struct cb_ops dr_cb_ops = {
	dr_open,	/* open */
	dr_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	dr_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* chpoll */
	ddi_prop_op,	/* cb_prop_op */
	NULL,		/* struct streamtab */
	D_NEW | D_MP | D_MTSAFE,	/* compatibility flags */
	CB_REV,		/* Rev */
	nodev,		/* cb_aread */
	nodev		/* cb_awrite */
};

struct dev_ops dr_dev_ops = {
	DEVO_REV,	/* build version */
	0,		/* dev ref count */
	dr_getinfo,	/* getinfo */
	nulldev,	/* identify */
	dr_probe,	/* probe */
	dr_attach,	/* attach */
	dr_detach,	/* detach */
	nodev,		/* reset */
	&dr_cb_ops,	/* cb_ops */
	(struct bus_ops *)NULL, /* bus ops */
	NULL,		/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"Dynamic Reconfiguration",
	&dr_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

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
	err = ddi_soft_state_init((void **)&dr_g.softsp,
	    sizeof (dr_softstate_t), 1);
	if (err)
		return (err);

	mutex_init(&dr_g.lock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&dr_grwlock, NULL, RW_DEFAULT, NULL);

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	mutex_destroy(&dr_g.lock);
	rw_destroy(&dr_grwlock);

	ddi_soft_state_fini((void **)&dr_g.softsp);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED1*/
static int
dr_open(dev_t *dev, int flag, int otyp, cred_t *cred_p)
{
	int		 instance;
	dr_softstate_t	*softsp;
	dr_board_t	*bp;

	/*
	 * Don't open unless we've attached.
	 */
	instance = DR_MINOR2INST(getminor(*dev));
	softsp = ddi_get_soft_state(dr_g.softsp, instance);
	if (softsp == NULL)
		return (ENXIO);

	mutex_enter(&softsp->i_lock);
	if (!softsp->dr_initialized) {
		int		 bd;
		int		 rv = 0;

		bp = softsp->boards;

		/* initialize each array element */
		for (bd = 0; bd < MAX_BOARDS; bd++, bp++) {
			rv = dr_board_init(bp, softsp->dip, bd);
			if (rv)
				break;
		}

		if (rv == 0) {
			softsp->dr_initialized = 1;
		} else {
			/* destroy elements initialized thus far */
			while (--bp >= softsp->boards)
				dr_board_destroy(bp);

			/* TODO: should this be another errno val ? */
			mutex_exit(&softsp->i_lock);
			return (ENXIO);
		}
	}
	mutex_exit(&softsp->i_lock);

	bp = &softsp->boards[DR_MINOR2BNUM(getminor(*dev))];

	/*
	 * prevent opening of a dyn-ap for a board
	 * that does not exist
	 */
	if (!bp->b_assigned) {
		if (drmach_board_lookup(bp->b_num, &bp->b_id) != 0)
			return (ENODEV);
	}

	return (0);
}

/*ARGSUSED*/
static int
dr_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	return (0);
}

/*
 * Enable/disable DR features.
 */
int dr_enable = 1;

/*ARGSUSED3*/
static int
dr_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p)
{
	int		rv = 0;
	int		instance;
	int		bd;
	dr_handle_t	*hp;
	dr_softstate_t	*softsp;
	static fn_t	f = "dr_ioctl";

	PR_ALL("%s...\n", f);

	instance = DR_MINOR2INST(getminor(dev));
	softsp = ddi_get_soft_state(dr_g.softsp, instance);
	if (softsp == NULL) {
		cmn_err(CE_WARN, "dr%d: module not yet attached", instance);
		return (ENXIO);
	}

	if (!dr_enable) {
		switch (cmd) {
			case SBD_CMD_STATUS:
			case SBD_CMD_GETNCM:
			case SBD_CMD_PASSTHRU:
				break;
			default:
				return (ENOTSUP);
		}
	}

	bd = DR_MINOR2BNUM(getminor(dev));
	if (bd >= MAX_BOARDS)
		return (ENXIO);

	/* get and initialize storage for new handle */
	hp = GETSTRUCT(dr_handle_t, 1);
	hp->h_bd = &softsp->boards[bd];
	hp->h_err = NULL;
	hp->h_dev = getminor(dev);
	hp->h_cmd = cmd;
	hp->h_mode = mode;
	hp->h_iap = (sbd_ioctl_arg_t *)arg;

	/* copy sbd command into handle */
	rv = dr_copyin_iocmd(hp);
	if (rv) {
		FREESTRUCT(hp, dr_handle_t, 1);
		return (EINVAL);
	}

	/* translate canonical name to component type */
	if (hp->h_sbdcmd.cmd_cm.c_id.c_name[0] != '\0') {
		hp->h_sbdcmd.cmd_cm.c_id.c_type =
		    dr_dev_type_to_nt(hp->h_sbdcmd.cmd_cm.c_id.c_name);

		PR_ALL("%s: c_name = %s, c_type = %d\n",
		    f,
		    hp->h_sbdcmd.cmd_cm.c_id.c_name,
		    hp->h_sbdcmd.cmd_cm.c_id.c_type);
	} else {
		/*EMPTY*/
		PR_ALL("%s: c_name is NULL\n", f);
	}

	/* determine scope of operation */
	hp->h_devset = dr_dev2devset(&hp->h_sbdcmd.cmd_cm.c_id);

	switch (hp->h_cmd) {
	case SBD_CMD_STATUS:
	case SBD_CMD_GETNCM:
		/* no locks needed for these commands */
		break;

	default:
		rw_enter(&dr_grwlock, RW_WRITER);
		mutex_enter(&hp->h_bd->b_lock);

		/*
		 * If we're dealing with memory at all, then we have
		 * to keep the "exclusive" global lock held.  This is
		 * necessary since we will probably need to look at
		 * multiple board structs.  Otherwise, we only have
		 * to deal with the board in question and so can drop
		 * the global lock to "shared".
		 */
		rv = DEVSET_IN_SET(hp->h_devset, SBD_COMP_MEM, DEVSET_ANYUNIT);
		if (rv == 0)
			rw_downgrade(&dr_grwlock);
		break;
	}
	rv = 0;

	if (rv == 0)
		rv = dr_pre_op(hp);
	if (rv == 0) {
		rv = dr_exec_op(hp);
		rv = dr_post_op(hp, rv);
	}

	if (rv == -1)
		rv = EIO;

	if (hp->h_err != NULL)
		if (!(rv = dr_copyout_errs(hp)))
			rv = EIO;

	/* undo locking, if any, done before dr_pre_op */
	switch (hp->h_cmd) {
	case SBD_CMD_STATUS:
	case SBD_CMD_GETNCM:
		break;

	case SBD_CMD_ASSIGN:
	case SBD_CMD_UNASSIGN:
	case SBD_CMD_POWERON:
	case SBD_CMD_POWEROFF:
	case SBD_CMD_CONNECT:
	case SBD_CMD_CONFIGURE:
	case SBD_CMD_UNCONFIGURE:
	case SBD_CMD_DISCONNECT:
		/* Board changed state. Log a sysevent. */
		if (rv == 0)
			(void) drmach_log_sysevent(hp->h_bd->b_num, "",
			    SE_SLEEP, 0);
		/* Fall through */

	default:
		mutex_exit(&hp->h_bd->b_lock);
		rw_exit(&dr_grwlock);
	}

	if (hp->h_opts.size != 0)
		FREESTRUCT(hp->h_opts.copts, char, hp->h_opts.size);

	FREESTRUCT(hp, dr_handle_t, 1);

	return (rv);
}

/*ARGSUSED*/
static int
dr_probe(dev_info_t *dip)
{
	return (DDI_PROBE_SUCCESS);
}

static int
dr_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		rv, rv2;
	int		bd;
	int		instance;
	sbd_error_t	*err;
	dr_softstate_t	*softsp;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		rw_enter(&dr_grwlock, RW_WRITER);

		rv = ddi_soft_state_zalloc(dr_g.softsp, instance);
		if (rv != DDI_SUCCESS) {
			cmn_err(CE_WARN, "dr%d: failed to alloc soft-state",
			    instance);
			return (DDI_FAILURE);
		}

		/* initialize softstate structure */
		softsp = ddi_get_soft_state(dr_g.softsp, instance);
		softsp->dip = dip;

		mutex_init(&softsp->i_lock, NULL, MUTEX_DRIVER, NULL);

		/* allocate board array (aka boardlist) */
		softsp->boards = GETSTRUCT(dr_board_t, MAX_BOARDS);

		/* TODO: eliminate dr_boardlist */
		dr_boardlist = softsp->boards;

		/* initialize each array element */
		rv = DDI_SUCCESS;
		for (bd = 0; bd < MAX_BOARDS; bd++) {
			dr_board_t	*bp = &softsp->boards[bd];
			char		*p, *name;
			int		 l, minor_num;

			/*
			 * initialized board attachment point path
			 * (relative to pseudo) in a form immediately
			 * reusable as an cfgadm command argument.
			 * TODO: clean this up
			 */
			p = bp->b_path;
			l = sizeof (bp->b_path);
			(void) snprintf(p, l, "dr@%d:", instance);
			while (*p != '\0') {
				l--;
				p++;
			}

			name = p;
			err = drmach_board_name(bd, p, l);
			if (err) {
				sbd_err_clear(&err);
				rv = DDI_FAILURE;
				break;
			}

			minor_num = DR_MAKE_MINOR(instance, bd);
			rv = ddi_create_minor_node(dip, name, S_IFCHR,
			    minor_num, DDI_NT_SBD_ATTACHMENT_POINT, 0);
			if (rv != DDI_SUCCESS)
				rv = DDI_FAILURE;
		}

		if (rv == DDI_SUCCESS) {
			/*
			 * Announce the node's presence.
			 */
			ddi_report_dev(dip);
		} else {
			ddi_remove_minor_node(dip, NULL);
		}
		/*
		 * Init registered unsafe devs.
		 */
		dr_unsafe_devs.devnames = NULL;
		rv2 = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    "unsupported-io-drivers", &dr_unsafe_devs.devnames,
		    &dr_unsafe_devs.ndevs);

		if (rv2 != DDI_PROP_SUCCESS)
			dr_unsafe_devs.ndevs = 0;

		rw_exit(&dr_grwlock);
		return (rv);

	default:
		return (DDI_FAILURE);
	}

	/*NOTREACHED*/
}

static int
dr_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	dr_softstate_t	*softsp;

	switch (cmd) {
	case DDI_DETACH:
		if (!dr_modunload_okay)
			return (DDI_FAILURE);

		rw_enter(&dr_grwlock, RW_WRITER);

		instance = ddi_get_instance(dip);
		softsp = ddi_get_soft_state(dr_g.softsp, instance);

		/* TODO: eliminate dr_boardlist */
		ASSERT(softsp->boards == dr_boardlist);

		/* remove all minor nodes */
		ddi_remove_minor_node(dip, NULL);

		if (softsp->dr_initialized) {
			int bd;

			for (bd = 0; bd < MAX_BOARDS; bd++)
				dr_board_destroy(&softsp->boards[bd]);
		}

		FREESTRUCT(softsp->boards, dr_board_t, MAX_BOARDS);
		mutex_destroy(&softsp->i_lock);
		ddi_soft_state_free(dr_g.softsp, instance);

		rw_exit(&dr_grwlock);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
	/*NOTREACHED*/
}

static int
dr_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip))

	dev_t		dev = (dev_t)arg;
	int		instance, error;
	dr_softstate_t	*softsp;

	*result = NULL;
	error = DDI_SUCCESS;
	instance = DR_MINOR2INST(getminor(dev));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		softsp = ddi_get_soft_state(dr_g.softsp, instance);
		if (softsp == NULL)
			return (DDI_FAILURE);
		*result = (void *)softsp->dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		break;

	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);
}

/*
 * DR operations.
 */

static int
dr_copyin_iocmd(dr_handle_t *hp)
{
	static fn_t	f = "dr_copyin_iocmd";
	sbd_cmd_t	*scp = &hp->h_sbdcmd;

	if (hp->h_iap == NULL)
		return (EINVAL);

	bzero((caddr_t)scp, sizeof (sbd_cmd_t));

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(hp->h_mode & FMODELS) == DDI_MODEL_ILP32) {
		sbd_cmd32_t	scmd32;

		bzero((caddr_t)&scmd32, sizeof (sbd_cmd32_t));

		if (ddi_copyin((void *)hp->h_iap, (void *)&scmd32,
		    sizeof (sbd_cmd32_t), hp->h_mode)) {
			cmn_err(CE_WARN,
			    "%s: (32bit) failed to copyin "
			    "sbdcmd-struct", f);
			return (EFAULT);
		}
		scp->cmd_cm.c_id.c_type = scmd32.cmd_cm.c_id.c_type;
		scp->cmd_cm.c_id.c_unit = scmd32.cmd_cm.c_id.c_unit;
		bcopy(&scmd32.cmd_cm.c_id.c_name[0],
		    &scp->cmd_cm.c_id.c_name[0], OBP_MAXPROPNAME);
		scp->cmd_cm.c_flags = scmd32.cmd_cm.c_flags;
		scp->cmd_cm.c_len = scmd32.cmd_cm.c_len;
		scp->cmd_cm.c_opts = (caddr_t)(uintptr_t)scmd32.cmd_cm.c_opts;

		switch (hp->h_cmd) {
		case SBD_CMD_STATUS:
			scp->cmd_stat.s_nbytes = scmd32.cmd_stat.s_nbytes;
			scp->cmd_stat.s_statp =
			    (caddr_t)(uintptr_t)scmd32.cmd_stat.s_statp;
			break;
		default:
			break;

		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)hp->h_iap, (void *)scp,
	    sizeof (sbd_cmd_t), hp->h_mode) != 0) {
		cmn_err(CE_WARN,
		    "%s: failed to copyin sbdcmd-struct", f);
		return (EFAULT);
	}

	if ((hp->h_opts.size = scp->cmd_cm.c_len) != 0) {
		hp->h_opts.copts = GETSTRUCT(char, scp->cmd_cm.c_len + 1);
		++hp->h_opts.size;
		if (ddi_copyin((void *)scp->cmd_cm.c_opts,
		    (void *)hp->h_opts.copts,
		    scp->cmd_cm.c_len, hp->h_mode) != 0) {
			cmn_err(CE_WARN, "%s: failed to copyin options", f);
			return (EFAULT);
		}
	}

	return (0);
}

static int
dr_copyout_iocmd(dr_handle_t *hp)
{
	static fn_t	f = "dr_copyout_iocmd";
	sbd_cmd_t	*scp = &hp->h_sbdcmd;

	if (hp->h_iap == NULL)
		return (EINVAL);

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(hp->h_mode & FMODELS) == DDI_MODEL_ILP32) {
		sbd_cmd32_t	scmd32;

		scmd32.cmd_cm.c_id.c_type = scp->cmd_cm.c_id.c_type;
		scmd32.cmd_cm.c_id.c_unit = scp->cmd_cm.c_id.c_unit;
		bcopy(&scp->cmd_cm.c_id.c_name[0],
		    &scmd32.cmd_cm.c_id.c_name[0], OBP_MAXPROPNAME);

		scmd32.cmd_cm.c_flags = scp->cmd_cm.c_flags;
		scmd32.cmd_cm.c_len = scp->cmd_cm.c_len;
		scmd32.cmd_cm.c_opts = (caddr32_t)(uintptr_t)scp->cmd_cm.c_opts;

		switch (hp->h_cmd) {
		case SBD_CMD_GETNCM:
			scmd32.cmd_getncm.g_ncm = scp->cmd_getncm.g_ncm;
			break;
		default:
			break;
		}

		if (ddi_copyout((void *)&scmd32, (void *)hp->h_iap,
		    sizeof (sbd_cmd32_t), hp->h_mode)) {
			cmn_err(CE_WARN,
			    "%s: (32bit) failed to copyout "
			    "sbdcmd-struct", f);
			return (EFAULT);
		}
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout((void *)scp, (void *)hp->h_iap,
	    sizeof (sbd_cmd_t), hp->h_mode) != 0) {
		cmn_err(CE_WARN,
		    "%s: failed to copyout sbdcmd-struct", f);
		return (EFAULT);
	}

	return (0);
}

static int
dr_copyout_errs(dr_handle_t *hp)
{
	static fn_t	f = "dr_copyout_errs";

	if (hp->h_err == NULL)
		return (0);

	if (hp->h_err->e_code) {
		PR_ALL("%s: error %d %s",
		    f, hp->h_err->e_code, hp->h_err->e_rsc);
	}

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(hp->h_mode & FMODELS) == DDI_MODEL_ILP32) {
		sbd_error32_t	*serr32p;

		serr32p = GETSTRUCT(sbd_error32_t, 1);

		serr32p->e_code = hp->h_err->e_code;
		bcopy(&hp->h_err->e_rsc[0], &serr32p->e_rsc[0],
		    MAXPATHLEN);
		if (ddi_copyout((void *)serr32p,
		    (void *)&((sbd_ioctl_arg32_t *)hp->h_iap)->i_err,
		    sizeof (sbd_error32_t), hp->h_mode)) {
			cmn_err(CE_WARN,
			    "%s: (32bit) failed to copyout", f);
			return (EFAULT);
		}
		FREESTRUCT(serr32p, sbd_error32_t, 1);
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyout((void *)hp->h_err,
	    (void *)&hp->h_iap->i_err,
	    sizeof (sbd_error_t), hp->h_mode)) {
		cmn_err(CE_WARN,
		    "%s: failed to copyout", f);
		return (EFAULT);
	}

	sbd_err_clear(&hp->h_err);

	return (0);

}

/*
 * pre-op entry point must sbd_err_set_c(), if needed.
 * Return value of non-zero indicates failure.
 */
static int
dr_pre_op(dr_handle_t *hp)
{
	int		rv = 0, t;
	int		cmd, serr = 0;
	dr_devset_t	devset;
	dr_board_t	*bp = hp->h_bd;
	dr_handle_t	*shp = hp;
	static fn_t	f = "dr_pre_op";

	cmd = hp->h_cmd;
	devset = shp->h_devset;

	PR_ALL("%s (cmd = %s)...\n", f, SBD_CMD_STR(cmd));

	devset = DEVSET_AND(devset, DR_DEVS_PRESENT(bp));
	hp->h_err = drmach_pre_op(cmd, bp->b_id, &hp->h_opts, &devset);
	if (hp->h_err != NULL) {
		PR_ALL("drmach_pre_op failed for cmd %s(%d)\n",
		    SBD_CMD_STR(cmd), cmd);
		return (-1);
	}

	/*
	 * Check for valid state transitions.
	 */
	if ((t = CMD2INDEX(cmd)) != -1) {
		struct dr_state_trans	*transp;
		int			state_err;

		transp = &dr_state_transition[t];
		ASSERT(transp->x_cmd == cmd);

		state_err = dr_check_transition(bp, &devset, transp, cmd);

		if (state_err < 0) {
			/*
			 * Invalidate device.
			 */
			dr_op_err(CE_IGNORE, hp, ESBD_INVAL, NULL);
			serr = -1;
			PR_ALL("%s: invalid devset (0x%x)\n",
			    f, (uint_t)devset);
		} else if (state_err != 0) {
			/*
			 * State transition is not a valid one.
			 */
			dr_op_err(CE_IGNORE, hp,
			    transp->x_op[state_err].x_err, NULL);

			serr = transp->x_op[state_err].x_rv;

			PR_ALL("%s: invalid state %s(%d) for cmd %s(%d)\n",
			    f, state_str[state_err], state_err,
			    SBD_CMD_STR(cmd), cmd);
		} else {
			shp->h_devset = devset;
		}
	}

	if (serr) {
		rv = -1;
	}

	return (rv);
}

static int
dr_post_op(dr_handle_t *hp, int rv)
{
	int		cmd;
	sbd_error_t	*err;
	dr_board_t	*bp = hp->h_bd;
	static fn_t	f = "dr_post_op";

	cmd = hp->h_cmd;

	PR_ALL("%s (cmd = %s)...\n", f, SBD_CMD_STR(cmd));

	err = drmach_post_op(cmd, bp->b_id, &hp->h_opts, rv);
	if (err != NULL) {
		PR_ALL("drmach_post_op failed for cmd %s(%d)\n",
		    SBD_CMD_STR(cmd), cmd);
		if (rv == 0) {
			ASSERT(hp->h_err == NULL);
			hp->h_err = err;
			rv = -1;
		} else if (hp->h_err == NULL) {
			hp->h_err = err;
		} else {
			sbd_err_clear(&err);
		}
	}

	return (rv);
}

static int
dr_exec_op(dr_handle_t *hp)
{
	int		rv = 0;
	static fn_t	f = "dr_exec_op";

	/* errors should have been caught by now */
	ASSERT(hp->h_err == NULL);

	switch (hp->h_cmd) {
	case SBD_CMD_ASSIGN:
		dr_assign_board(hp);
		break;

	case SBD_CMD_UNASSIGN:
		dr_unassign_board(hp);
		break;

	case SBD_CMD_POWEROFF:
		dr_poweroff_board(hp);
		break;

	case SBD_CMD_POWERON:
		dr_poweron_board(hp);
		break;

	case SBD_CMD_TEST:
		dr_test_board(hp);
		break;

	case SBD_CMD_CONNECT:
		dr_connect(hp);
		break;

	case SBD_CMD_CONFIGURE:
		dr_dev_configure(hp);
		break;

	case SBD_CMD_UNCONFIGURE:
		dr_dev_release(hp);
		if (hp->h_err == NULL)
			rv = dr_dev_unconfigure(hp);
		else
			dr_dev_cancel(hp);
		break;

	case SBD_CMD_DISCONNECT:
		rv = dr_disconnect(hp);
		break;

	case SBD_CMD_STATUS:
		rv = dr_dev_status(hp);
		break;

	case SBD_CMD_GETNCM:
		hp->h_sbdcmd.cmd_getncm.g_ncm = dr_get_ncm(hp);
		rv = dr_copyout_iocmd(hp);
		break;

	case SBD_CMD_PASSTHRU:
		rv = dr_pt_ioctl(hp);
		break;

	default:
		cmn_err(CE_WARN,
		    "%s: unknown command (%d)",
		    f, hp->h_cmd);
		break;
	}

	if (hp->h_err != NULL) {
		rv = -1;
	}

	return (rv);
}

static void
dr_assign_board(dr_handle_t *hp)
{
	dr_board_t *bp = hp->h_bd;

	hp->h_err = drmach_board_assign(bp->b_num, &bp->b_id);
	if (hp->h_err == NULL) {
		bp->b_assigned = 1;
	}
}

static void
dr_unassign_board(dr_handle_t *hp)
{
	dr_board_t *bp = hp->h_bd;

	/*
	 * Block out status during unassign.
	 * Not doing cv_wait_sig here as starfire SSP software
	 * ignores unassign failure and removes board from
	 * domain mask causing system panic.
	 * TODO: Change cv_wait to cv_wait_sig when SSP software
	 * handles unassign failure.
	 */
	dr_lock_status(bp);

	hp->h_err = drmach_board_unassign(bp->b_id);
	if (hp->h_err == NULL) {
		/*
		 * clear drmachid_t handle; not valid after board unassign
		 */
		bp->b_id = 0;
		bp->b_assigned = 0;
	}

	dr_unlock_status(bp);
}

static void
dr_poweron_board(dr_handle_t *hp)
{
	dr_board_t *bp = hp->h_bd;

	hp->h_err = drmach_board_poweron(bp->b_id);
}

static void
dr_poweroff_board(dr_handle_t *hp)
{
	dr_board_t *bp = hp->h_bd;

	hp->h_err = drmach_board_poweroff(bp->b_id);
}

static void
dr_test_board(dr_handle_t *hp)
{
	dr_board_t *bp = hp->h_bd;
	hp->h_err = drmach_board_test(bp->b_id, &hp->h_opts,
	    dr_cmd_flags(hp) & SBD_FLAG_FORCE);
}

/*
 * Create and populate the component nodes for a board.  Assumes that the
 * devlists for the board have been initialized.
 */
static void
dr_make_comp_nodes(dr_board_t *bp)
{
	int	i;

	/*
	 * Make nodes for the individual components on the board.
	 * First we need to initialize memory unit data structures of board
	 * structure.
	 */
	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		dr_mem_unit_t *mp;

		mp = dr_get_mem_unit(bp, i);
		dr_init_mem_unit(mp);
	}

	/*
	 * Initialize cpu unit data structures.
	 */
	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		dr_cpu_unit_t *cp;

		cp = dr_get_cpu_unit(bp, i);
		dr_init_cpu_unit(cp);
	}

	/*
	 * Initialize io unit data structures.
	 */
	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		dr_io_unit_t *ip;

		ip = dr_get_io_unit(bp, i);
		dr_init_io_unit(ip);
	}

	dr_board_transition(bp, DR_STATE_CONNECTED);

	bp->b_rstate = SBD_STAT_CONNECTED;
	bp->b_ostate = SBD_STAT_UNCONFIGURED;
	bp->b_cond = SBD_COND_OK;
	(void) drv_getparm(TIME, (void *)&bp->b_time);

}

/*
 * Only do work if called to operate on an entire board
 * which doesn't already have components present.
 */
static void
dr_connect(dr_handle_t *hp)
{
	dr_board_t	*bp = hp->h_bd;
	static fn_t	f = "dr_connect";

	PR_ALL("%s...\n", f);

	if (DR_DEVS_PRESENT(bp)) {
		/*
		 * Board already has devices present.
		 */
		PR_ALL("%s: devices already present (" DEVSET_FMT_STR ")\n",
		    f, DEVSET_FMT_ARG(DR_DEVS_PRESENT(bp)));
		return;
	}

	hp->h_err = drmach_board_connect(bp->b_id, &hp->h_opts);
	if (hp->h_err)
		return;

	hp->h_err = dr_init_devlists(bp);
	if (hp->h_err)
		return;
	else if (bp->b_ndev == 0) {
		dr_op_err(CE_WARN, hp, ESBD_EMPTY_BD, bp->b_path);
		return;
	} else {
		dr_make_comp_nodes(bp);
		return;
	}
	/*NOTREACHED*/
}

static int
dr_disconnect(dr_handle_t *hp)
{
	int		i;
	dr_devset_t	devset;
	dr_board_t	*bp = hp->h_bd;
	static fn_t	f = "dr_disconnect";

	PR_ALL("%s...\n", f);

	/*
	 * Only devices which are present, but
	 * unattached can be disconnected.
	 */
	devset = hp->h_devset & DR_DEVS_PRESENT(bp) &
	    DR_DEVS_UNATTACHED(bp);

	if ((devset == 0) && DR_DEVS_PRESENT(bp)) {
		dr_op_err(CE_IGNORE, hp, ESBD_EMPTY_BD, bp->b_path);
		return (0);
	}

	/*
	 * Block out status during disconnect.
	 */
	mutex_enter(&bp->b_slock);
	while (bp->b_sflags & DR_BSLOCK) {
		if (cv_wait_sig(&bp->b_scv, &bp->b_slock) == 0) {
			mutex_exit(&bp->b_slock);
			return (EINTR);
		}
	}
	bp->b_sflags |= DR_BSLOCK;
	mutex_exit(&bp->b_slock);

	hp->h_err = drmach_board_disconnect(bp->b_id, &hp->h_opts);
	if (hp->h_err && hp->h_err->e_code == EX86_WALK_DEPENDENCY) {
		/*
		 * Other boards have dependency on this board. No device nodes
		 * have been destroyed so keep current board status.
		 */
		goto disconnect_done;
	}

	DR_DEVS_DISCONNECT(bp, devset);

	ASSERT((DR_DEVS_ATTACHED(bp) & devset) == 0);

	/*
	 * Update per-device state transitions.
	 */
	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		dr_cpu_unit_t *cp;

		if (!DEVSET_IN_SET(devset, SBD_COMP_CPU, i))
			continue;

		cp = dr_get_cpu_unit(bp, i);
		if (dr_disconnect_cpu(cp) == 0)
			dr_device_transition(&cp->sbc_cm, DR_STATE_EMPTY);
		else if (cp->sbc_cm.sbdev_error != NULL)
			DRERR_SET_C(&hp->h_err, &cp->sbc_cm.sbdev_error);

		ASSERT(cp->sbc_cm.sbdev_error == NULL);
	}

	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		dr_mem_unit_t *mp;

		if (!DEVSET_IN_SET(devset, SBD_COMP_MEM, i))
			continue;

		mp = dr_get_mem_unit(bp, i);
		if (dr_disconnect_mem(mp) == 0)
			dr_device_transition(&mp->sbm_cm, DR_STATE_EMPTY);
		else if (mp->sbm_cm.sbdev_error != NULL)
			DRERR_SET_C(&hp->h_err, &mp->sbm_cm.sbdev_error);

		ASSERT(mp->sbm_cm.sbdev_error == NULL);
	}

	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		dr_io_unit_t *ip;

		if (!DEVSET_IN_SET(devset, SBD_COMP_IO, i))
			continue;

		ip = dr_get_io_unit(bp, i);
		if (dr_disconnect_io(ip) == 0)
			dr_device_transition(&ip->sbi_cm, DR_STATE_EMPTY);
		else if (ip->sbi_cm.sbdev_error != NULL)
			DRERR_SET_C(&hp->h_err, &ip->sbi_cm.sbdev_error);

		ASSERT(ip->sbi_cm.sbdev_error == NULL);
	}

	if (hp->h_err) {
		/*
		 * For certain errors, drmach_board_disconnect will mark
		 * the board as unusable; in these cases the devtree must
		 * be purged so that status calls will succeed.
		 * XXX
		 * This implementation checks for discrete error codes -
		 * someday, the i/f to drmach_board_disconnect should be
		 * changed to avoid the e_code testing.
		 */
		if (hp->h_err->e_code == EX86_DEPROBE) {
			bp->b_ostate = SBD_STAT_UNCONFIGURED;
			bp->b_busy = 0;
			(void) drv_getparm(TIME, (void *)&bp->b_time);

			if (drmach_board_deprobe(bp->b_id))
				goto disconnect_done;
			else
				bp->b_ndev = 0;
		}
	}

	/*
	 * Once all the components on a board have been disconnect
	 * the board's state can transition to disconnected and
	 * we can allow the deprobe to take place.
	 */
	if (hp->h_err == NULL && DR_DEVS_PRESENT(bp) == 0) {
		dr_board_transition(bp, DR_STATE_OCCUPIED);
		bp->b_rstate = SBD_STAT_DISCONNECTED;
		bp->b_ostate = SBD_STAT_UNCONFIGURED;
		bp->b_busy = 0;
		(void) drv_getparm(TIME, (void *)&bp->b_time);

		hp->h_err = drmach_board_deprobe(bp->b_id);

		if (hp->h_err == NULL) {
			bp->b_ndev = 0;
			dr_board_transition(bp, DR_STATE_EMPTY);
			bp->b_rstate = SBD_STAT_EMPTY;
			(void) drv_getparm(TIME, (void *)&bp->b_time);
		}
	}

disconnect_done:
	dr_unlock_status(bp);

	return (0);
}

/*
 * Check if a particular device is a valid target of the current
 * operation. Return 1 if it is a valid target, and 0 otherwise.
 */
static int
dr_dev_is_target(dr_dev_unit_t *dp, int present_only, uint_t uset)
{
	dr_common_unit_t *cp;
	int		 is_present;
	int		 is_attached;

	cp = &dp->du_common;

	/* check if the user requested this device */
	if ((uset & (1 << cp->sbdev_unum)) == 0) {
		return (0);
	}

	is_present = DR_DEV_IS_PRESENT(cp) ? 1 : 0;
	is_attached = DR_DEV_IS_ATTACHED(cp) ? 1 : 0;

	/*
	 * If the present_only flag is set, a valid target
	 * must be present but not attached. Otherwise, it
	 * must be both present and attached.
	 */
	if (is_present && (present_only ^ is_attached)) {
		/* sanity check */
		ASSERT(cp->sbdev_id != (drmachid_t)0);

		return (1);
	}

	return (0);
}

static void
dr_dev_make_list(dr_handle_t *hp, sbd_comp_type_t type, int present_only,
    dr_common_unit_t ***devlist, int *devnum)
{
	dr_board_t	*bp = hp->h_bd;
	int		 unum;
	int		 nunits;
	uint_t		 uset;
	int		 len;
	dr_common_unit_t **list, **wp;

	switch (type) {
	case SBD_COMP_CPU:
		nunits = MAX_CPU_UNITS_PER_BOARD;
		break;
	case SBD_COMP_MEM:
		nunits = MAX_MEM_UNITS_PER_BOARD;
		break;
	case SBD_COMP_IO:
		nunits = MAX_IO_UNITS_PER_BOARD;
		break;
	default:
		/* catch this in debug kernels */
		ASSERT(0);
		break;
	}

	/* allocate list storage. */
	len = sizeof (dr_common_unit_t *) * (nunits + 1);
	list = kmem_zalloc(len, KM_SLEEP);

	/* record length of storage in first element */
	*list++ = (dr_common_unit_t *)(uintptr_t)len;

	/* get bit array signifying which units are to be involved */
	uset = DEVSET_GET_UNITSET(hp->h_devset, type);

	/*
	 * Adjust the loop count for CPU devices since all cores
	 * in a CMP will be examined in a single iteration.
	 */
	if (type == SBD_COMP_CPU) {
		nunits = MAX_CMP_UNITS_PER_BOARD;
	}

	/* populate list */
	for (wp = list, unum = 0; unum < nunits; unum++) {
		dr_dev_unit_t	*dp;
		int		core;
		int		cunum;

		dp = DR_GET_BOARD_DEVUNIT(bp, type, unum);
		if (dr_dev_is_target(dp, present_only, uset)) {
			*wp++ = &dp->du_common;
		}

		/* further processing is only required for CPUs */
		if (type != SBD_COMP_CPU) {
			continue;
		}

		/*
		 * Add any additional cores from the current CPU
		 * device. This is to ensure that all the cores
		 * are grouped together in the device list, and
		 * consequently sequenced together during the actual
		 * operation.
		 */
		for (core = 1; core < MAX_CORES_PER_CMP; core++) {
			cunum = DR_CMP_CORE_UNUM(unum, core);
			dp = DR_GET_BOARD_DEVUNIT(bp, type, cunum);

			if (dr_dev_is_target(dp, present_only, uset)) {
				*wp++ = &dp->du_common;
			}
		}
	}

	/* calculate number of units in list, return result and list pointer */
	*devnum = wp - list;
	*devlist = list;
}

static void
dr_dev_clean_up(dr_handle_t *hp, dr_common_unit_t **list, int devnum)
{
	int len;
	int n = 0;
	dr_common_unit_t *cp, **rp = list;

	/*
	 * move first encountered unit error to handle if handle
	 * does not yet have a recorded error.
	 */
	if (hp->h_err == NULL) {
		while (n++ < devnum) {
			cp = *rp++;
			if (cp->sbdev_error != NULL) {
				hp->h_err = cp->sbdev_error;
				cp->sbdev_error = NULL;
				break;
			}
		}
	}

	/* free remaining unit errors */
	while (n++ < devnum) {
		cp = *rp++;
		if (cp->sbdev_error != NULL) {
			sbd_err_clear(&cp->sbdev_error);
			cp->sbdev_error = NULL;
		}
	}

	/* free list */
	list -= 1;
	len = (int)(uintptr_t)list[0];
	kmem_free(list, len);
}

static int
dr_dev_walk(dr_handle_t *hp, sbd_comp_type_t type, int present_only,
    int (*pre_op)(dr_handle_t *, dr_common_unit_t **, int),
    void (*op)(dr_handle_t *, dr_common_unit_t *),
    int (*post_op)(dr_handle_t *, dr_common_unit_t **, int),
    void (*board_op)(dr_handle_t *, dr_common_unit_t **, int))
{
	int			  devnum, rv;
	dr_common_unit_t	**devlist;

	dr_dev_make_list(hp, type, present_only, &devlist, &devnum);

	rv = 0;
	if (devnum > 0) {
		rv = (*pre_op)(hp, devlist, devnum);
		if (rv == 0) {
			int n;

			for (n = 0; n < devnum; n++)
				(*op)(hp, devlist[n]);

			rv = (*post_op)(hp, devlist, devnum);

			(*board_op)(hp, devlist, devnum);
		}
	}

	dr_dev_clean_up(hp, devlist, devnum);
	return (rv);
}

/*ARGSUSED*/
static int
dr_dev_noop(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	return (0);
}

static void
dr_attach_update_state(dr_handle_t *hp,
    dr_common_unit_t **devlist, int devnum)
{
	dr_board_t	*bp = hp->h_bd;
	int		i;
	dr_devset_t	devs_unattached, devs_present;
	static fn_t	f = "dr_attach_update_state";

	for (i = 0; i < devnum; i++) {
		dr_common_unit_t *cp = devlist[i];

		if (dr_check_unit_attached(cp) == -1) {
			PR_ALL("%s: ERROR %s not attached\n",
			    f, cp->sbdev_path);
			continue;
		}

		DR_DEV_SET_ATTACHED(cp);

		dr_device_transition(cp, DR_STATE_CONFIGURED);
		cp->sbdev_cond = SBD_COND_OK;
	}

	devs_present = DR_DEVS_PRESENT(bp);
	devs_unattached = DR_DEVS_UNATTACHED(bp);

	switch (bp->b_state) {
	case DR_STATE_CONNECTED:
	case DR_STATE_UNCONFIGURED:
		ASSERT(devs_present);

		if (devs_unattached == 0) {
			/*
			 * All devices finally attached.
			 */
			dr_board_transition(bp, DR_STATE_CONFIGURED);
			hp->h_bd->b_ostate = SBD_STAT_CONFIGURED;
			hp->h_bd->b_rstate = SBD_STAT_CONNECTED;
			hp->h_bd->b_cond = SBD_COND_OK;
			hp->h_bd->b_busy = 0;
			(void) drv_getparm(TIME, (void *)&hp->h_bd->b_time);
		} else if (devs_present != devs_unattached) {
			/*
			 * Only some devices are fully attached.
			 */
			dr_board_transition(bp, DR_STATE_PARTIAL);
			hp->h_bd->b_rstate = SBD_STAT_CONNECTED;
			hp->h_bd->b_ostate = SBD_STAT_CONFIGURED;
			(void) drv_getparm(TIME, (void *)&hp->h_bd->b_time);
		}
		break;

	case DR_STATE_PARTIAL:
		ASSERT(devs_present);
		/*
		 * All devices finally attached.
		 */
		if (devs_unattached == 0) {
			dr_board_transition(bp, DR_STATE_CONFIGURED);
			hp->h_bd->b_rstate = SBD_STAT_CONNECTED;
			hp->h_bd->b_ostate = SBD_STAT_CONFIGURED;
			hp->h_bd->b_cond = SBD_COND_OK;
			hp->h_bd->b_busy = 0;
			(void) drv_getparm(TIME, (void *)&hp->h_bd->b_time);
		}
		break;

	default:
		break;
	}
}

static void
dr_dev_configure(dr_handle_t *hp)
{
	int rv;

	rv = dr_dev_walk(hp, SBD_COMP_CPU, 1,
	    dr_pre_attach_cpu,
	    dr_attach_cpu,
	    dr_post_attach_cpu,
	    dr_attach_update_state);

	if (rv >= 0) {
		rv = dr_dev_walk(hp, SBD_COMP_MEM, 1,
		    dr_pre_attach_mem,
		    dr_attach_mem,
		    dr_post_attach_mem,
		    dr_attach_update_state);
	}

	if (rv >= 0) {
		(void) dr_dev_walk(hp, SBD_COMP_IO, 1,
		    dr_pre_attach_io,
		    dr_attach_io,
		    dr_post_attach_io,
		    dr_attach_update_state);
	}
}

static void
dr_release_update_state(dr_handle_t *hp,
    dr_common_unit_t **devlist, int devnum)
{
	_NOTE(ARGUNUSED(devlist))
	_NOTE(ARGUNUSED(devnum))

	dr_board_t *bp = hp->h_bd;

	/*
	 * If the entire board was released and all components
	 * unreferenced then transfer it to the UNREFERENCED state.
	 */
	if ((bp->b_state != DR_STATE_RELEASE) &&
	    (DR_DEVS_RELEASED(bp) == DR_DEVS_ATTACHED(bp))) {
		dr_board_transition(bp, DR_STATE_RELEASE);
		hp->h_bd->b_busy = 1;
	}
}

/* called by dr_release_done [below] and dr_release_mem_done [dr_mem.c] */
int
dr_release_dev_done(dr_common_unit_t *cp)
{
	if (cp->sbdev_state == DR_STATE_RELEASE) {
		ASSERT(DR_DEV_IS_RELEASED(cp));

		DR_DEV_SET_UNREFERENCED(cp);

		dr_device_transition(cp, DR_STATE_UNREFERENCED);

		return (0);
	} else {
		return (-1);
	}
}

static void
dr_release_done(dr_handle_t *hp, dr_common_unit_t *cp)
{
	_NOTE(ARGUNUSED(hp))

	dr_board_t		*bp;
	static fn_t		f = "dr_release_done";

	PR_ALL("%s...\n", f);

	/* get board pointer & sanity check */
	bp = cp->sbdev_bp;
	ASSERT(bp == hp->h_bd);

	/*
	 * Transfer the device which just completed its release
	 * to the UNREFERENCED state.
	 */
	switch (cp->sbdev_type) {
	case SBD_COMP_MEM:
		dr_release_mem_done(cp);
		break;

	default:
		DR_DEV_SET_RELEASED(cp);

		dr_device_transition(cp, DR_STATE_RELEASE);

		(void) dr_release_dev_done(cp);
		break;
	}

	/*
	 * If we're not already in the RELEASE state for this
	 * board and we now have released all that were previously
	 * attached, then transfer the board to the RELEASE state.
	 */
	if ((bp->b_state == DR_STATE_RELEASE) &&
	    (DR_DEVS_RELEASED(bp) == DR_DEVS_UNREFERENCED(bp))) {
		dr_board_transition(bp, DR_STATE_UNREFERENCED);
		bp->b_busy = 1;
		(void) drv_getparm(TIME, (void *)&bp->b_time);
	}
}

static void
dr_dev_release_mem(dr_handle_t *hp, dr_common_unit_t *dv)
{
	dr_release_mem(dv);
	dr_release_done(hp, dv);
}

static void
dr_dev_release(dr_handle_t *hp)
{
	int rv;

	hp->h_bd->b_busy = 1;

	rv = dr_dev_walk(hp, SBD_COMP_CPU, 0,
	    dr_pre_release_cpu,
	    dr_release_done,
	    dr_dev_noop,
	    dr_release_update_state);

	if (rv >= 0) {
		rv = dr_dev_walk(hp, SBD_COMP_MEM, 0,
		    dr_pre_release_mem,
		    dr_dev_release_mem,
		    dr_dev_noop,
		    dr_release_update_state);
	}

	if (rv >= 0) {
		rv = dr_dev_walk(hp, SBD_COMP_IO, 0,
		    dr_pre_release_io,
		    dr_release_done,
		    dr_dev_noop,
		    dr_release_update_state);

	}

	if (rv < 0)
		hp->h_bd->b_busy = 0;
	/* else, b_busy will be cleared in dr_detach_update_state() */
}

static void
dr_detach_update_state(dr_handle_t *hp,
    dr_common_unit_t **devlist, int devnum)
{
	dr_board_t	*bp = hp->h_bd;
	int		i;
	dr_state_t	bstate;
	static fn_t	f = "dr_detach_update_state";

	for (i = 0; i < devnum; i++) {
		dr_common_unit_t *cp = devlist[i];

		if (dr_check_unit_attached(cp) >= 0) {
			/*
			 * Device is still attached probably due
			 * to an error.  Need to keep track of it.
			 */
			PR_ALL("%s: ERROR %s not detached\n",
			    f, cp->sbdev_path);

			continue;
		}

		DR_DEV_CLR_ATTACHED(cp);
		DR_DEV_CLR_RELEASED(cp);
		DR_DEV_CLR_UNREFERENCED(cp);
		dr_device_transition(cp, DR_STATE_UNCONFIGURED);
	}

	bstate = bp->b_state;
	if (bstate != DR_STATE_UNCONFIGURED) {
		if (DR_DEVS_PRESENT(bp) == DR_DEVS_UNATTACHED(bp)) {
			/*
			 * All devices are finally detached.
			 */
			dr_board_transition(bp, DR_STATE_UNCONFIGURED);
			hp->h_bd->b_ostate = SBD_STAT_UNCONFIGURED;
			(void) drv_getparm(TIME, (void *)&hp->h_bd->b_time);
		} else if ((bp->b_state != DR_STATE_PARTIAL) &&
		    (DR_DEVS_ATTACHED(bp) !=
		    DR_DEVS_PRESENT(bp))) {
			/*
			 * Some devices remain attached.
			 */
			dr_board_transition(bp, DR_STATE_PARTIAL);
			(void) drv_getparm(TIME, (void *)&hp->h_bd->b_time);
		}

		if ((hp->h_devset & DR_DEVS_UNATTACHED(bp)) == hp->h_devset)
			hp->h_bd->b_busy = 0;
	}
}

static int
dr_dev_unconfigure(dr_handle_t *hp)
{
	dr_board_t	*bp = hp->h_bd;

	/*
	 * Block out status during IO unconfig.
	 */
	mutex_enter(&bp->b_slock);
	while (bp->b_sflags & DR_BSLOCK) {
		if (cv_wait_sig(&bp->b_scv, &bp->b_slock) == 0) {
			mutex_exit(&bp->b_slock);
			return (EINTR);
		}
	}
	bp->b_sflags |= DR_BSLOCK;
	mutex_exit(&bp->b_slock);

	(void) dr_dev_walk(hp, SBD_COMP_IO, 0,
	    dr_pre_detach_io,
	    dr_detach_io,
	    dr_post_detach_io,
	    dr_detach_update_state);

	dr_unlock_status(bp);

	(void) dr_dev_walk(hp, SBD_COMP_CPU, 0,
	    dr_pre_detach_cpu,
	    dr_detach_cpu,
	    dr_post_detach_cpu,
	    dr_detach_update_state);

	(void) dr_dev_walk(hp, SBD_COMP_MEM, 0,
	    dr_pre_detach_mem,
	    dr_detach_mem,
	    dr_post_detach_mem,
	    dr_detach_update_state);

	return (0);
}

static void
dr_dev_cancel(dr_handle_t *hp)
{
	int		i;
	dr_devset_t	devset;
	dr_board_t	*bp = hp->h_bd;
	static fn_t	f = "dr_dev_cancel";

	PR_ALL("%s...\n", f);

	/*
	 * Only devices which have been "released" are
	 * subject to cancellation.
	 */
	devset = hp->h_devset & DR_DEVS_RELEASED(bp);

	/*
	 * Nothing to do for CPUs or IO other than change back
	 * their state.
	 */
	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		dr_cpu_unit_t	*cp;
		dr_state_t	nstate;

		if (!DEVSET_IN_SET(devset, SBD_COMP_CPU, i))
			continue;

		cp = dr_get_cpu_unit(bp, i);
		if (dr_cancel_cpu(cp) == 0)
			nstate = DR_STATE_CONFIGURED;
		else
			nstate = DR_STATE_FATAL;

		dr_device_transition(&cp->sbc_cm, nstate);
	}

	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		dr_io_unit_t *ip;

		if (!DEVSET_IN_SET(devset, SBD_COMP_IO, i))
			continue;
		ip = dr_get_io_unit(bp, i);
		dr_device_transition(&ip->sbi_cm, DR_STATE_CONFIGURED);
	}
	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		dr_mem_unit_t	*mp;
		dr_state_t	nstate;

		if (!DEVSET_IN_SET(devset, SBD_COMP_MEM, i))
			continue;

		mp = dr_get_mem_unit(bp, i);
		if (dr_cancel_mem(mp) == 0)
			nstate = DR_STATE_CONFIGURED;
		else
			nstate = DR_STATE_FATAL;

		dr_device_transition(&mp->sbm_cm, nstate);
	}

	PR_ALL("%s: unreleasing devset (0x%x)\n", f, (uint_t)devset);

	DR_DEVS_CANCEL(bp, devset);

	if (DR_DEVS_RELEASED(bp) == 0) {
		dr_state_t	new_state;
		/*
		 * If the board no longer has any released devices
		 * than transfer it back to the CONFIG/PARTIAL state.
		 */
		if (DR_DEVS_ATTACHED(bp) == DR_DEVS_PRESENT(bp))
			new_state = DR_STATE_CONFIGURED;
		else
			new_state = DR_STATE_PARTIAL;
		if (bp->b_state != new_state) {
			dr_board_transition(bp, new_state);
		}
		hp->h_bd->b_ostate = SBD_STAT_CONFIGURED;
		hp->h_bd->b_busy = 0;
		(void) drv_getparm(TIME, (void *)&hp->h_bd->b_time);
	}
}

static int
dr_dev_status(dr_handle_t *hp)
{
	int		nstat, mode, ncm, sz, pbsz, pnstat;
	dr_handle_t	*shp;
	dr_devset_t	devset = 0;
	sbd_stat_t	*dstatp = NULL;
	sbd_dev_stat_t	*devstatp;
	dr_board_t	*bp;
	drmach_status_t	 pstat;
	int		rv = 0;

#ifdef _MULTI_DATAMODEL
	int sz32 = 0;
#endif /* _MULTI_DATAMODEL */

	static fn_t	f = "dr_dev_status";

	PR_ALL("%s...\n", f);

	mode = hp->h_mode;
	shp = hp;
	devset = shp->h_devset;
	bp = hp->h_bd;

	/*
	 * Block out disconnect, unassign, IO unconfigure and
	 * devinfo branch creation during status.
	 */
	mutex_enter(&bp->b_slock);
	while (bp->b_sflags & DR_BSLOCK) {
		if (cv_wait_sig(&bp->b_scv, &bp->b_slock) == 0) {
			mutex_exit(&bp->b_slock);
			return (EINTR);
		}
	}
	bp->b_sflags |= DR_BSLOCK;
	mutex_exit(&bp->b_slock);

	ncm = 1;
	if (hp->h_sbdcmd.cmd_cm.c_id.c_type == SBD_COMP_NONE) {
		if (dr_cmd_flags(hp) & SBD_FLAG_ALLCMP) {
		/*
		 * Calculate the maximum number of components possible
		 * for a board.  This number will be used to size the
		 * status scratch buffer used by board and component
		 * status functions.
		 * This buffer may differ in size from what is provided
		 * by the plugin, since the known component set on the
		 * board may change between the plugin's GETNCM call, and
		 * the status call.  Sizing will be adjusted to the plugin's
		 * receptacle buffer at copyout time.
		 */
			ncm = MAX_CPU_UNITS_PER_BOARD +
			    MAX_MEM_UNITS_PER_BOARD +
			    MAX_IO_UNITS_PER_BOARD;

		} else {
			/*
			 * In the case of c_type == SBD_COMP_NONE, and
			 * SBD_FLAG_ALLCMP not specified, only the board
			 * info is to be returned, no components.
			 */
			ncm = 0;
			devset = 0;
		}
	}

	sz = sizeof (sbd_stat_t);
	if (ncm > 1)
		sz += sizeof (sbd_dev_stat_t) * (ncm - 1);


	pbsz = (int)hp->h_sbdcmd.cmd_stat.s_nbytes;
	pnstat = (pbsz - sizeof (sbd_stat_t)) / sizeof (sbd_dev_stat_t);

	/*
	 * s_nbytes describes the size of the preallocated user
	 * buffer into which the application is execting to
	 * receive the sbd_stat_t and sbd_dev_stat_t structures.
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
		pnstat = (pbsz - sizeof (sbd_stat32_t))/
		    sizeof (sbd_dev_stat32_t);
	}

	sz += sz32;
#endif
	/*
	 * Since one sbd_dev_stat_t is included in the sbd_stat_t,
	 * increment the plugin's nstat count.
	 */
	++pnstat;

	if (bp->b_id == 0) {
		bzero(&pstat, sizeof (pstat));
	} else {
		sbd_error_t *err;

		err = drmach_status(bp->b_id, &pstat);
		if (err) {
			DRERR_SET_C(&hp->h_err, &err);
			rv = EIO;
			goto status_done;
		}
	}

	dstatp = (sbd_stat_t *)(void *)GETSTRUCT(char, sz);

	devstatp = &dstatp->s_stat[0];

	dstatp->s_board = bp->b_num;

	/*
	 * Detect transitions between empty and disconnected.
	 */
	if (!pstat.empty && (bp->b_rstate == SBD_STAT_EMPTY))
		bp->b_rstate = SBD_STAT_DISCONNECTED;
	else if (pstat.empty && (bp->b_rstate == SBD_STAT_DISCONNECTED))
		bp->b_rstate = SBD_STAT_EMPTY;

	dstatp->s_rstate = bp->b_rstate;
	dstatp->s_ostate = bp->b_ostate;
	dstatp->s_cond = bp->b_cond = pstat.cond;
	dstatp->s_busy = bp->b_busy | pstat.busy;
	dstatp->s_time = bp->b_time;
	dstatp->s_power = pstat.powered;
	dstatp->s_assigned = bp->b_assigned = pstat.assigned;
	dstatp->s_nstat = nstat = 0;
	bcopy(&pstat.type[0], &dstatp->s_type[0], SBD_TYPE_LEN);
	bcopy(&pstat.info[0], &dstatp->s_info[0], SBD_MAX_INFO);

	devset &= DR_DEVS_PRESENT(bp);
	if (devset == 0) {
		/*
		 * No device chosen.
		 */
		PR_ALL("%s: no device present\n", f);
	}

	if (DEVSET_IN_SET(devset, SBD_COMP_CPU, DEVSET_ANYUNIT))
		if ((nstat = dr_cpu_status(hp, devset, devstatp)) > 0) {
			dstatp->s_nstat += nstat;
			devstatp += nstat;
		}

	if (DEVSET_IN_SET(devset, SBD_COMP_MEM, DEVSET_ANYUNIT))
		if ((nstat = dr_mem_status(hp, devset, devstatp)) > 0) {
			dstatp->s_nstat += nstat;
			devstatp += nstat;
		}

	if (DEVSET_IN_SET(devset, SBD_COMP_IO, DEVSET_ANYUNIT))
		if ((nstat = dr_io_status(hp, devset, devstatp)) > 0) {
			dstatp->s_nstat += nstat;
			devstatp += nstat;
		}

	/*
	 * Due to a possible change in number of components between
	 * the time of plugin's GETNCM call and now, there may be
	 * more or less components than the plugin's buffer can
	 * hold.  Adjust s_nstat accordingly.
	 */

	dstatp->s_nstat = dstatp->s_nstat > pnstat ? pnstat : dstatp->s_nstat;

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		int		i, j;
		sbd_stat32_t	*dstat32p;

		dstat32p = (sbd_stat32_t *)devstatp;

		/* Alignment Paranoia */
		if ((ulong_t)dstat32p & 0x1) {
			PR_ALL("%s: alignment: sz=0x%lx dstat32p=0x%p\n",
			    f, sizeof (sbd_stat32_t), (void *)dstat32p);
			DR_OP_INTERNAL_ERROR(hp);
			rv = EINVAL;
			goto status_done;
		}

		/* paranoia: detect buffer overrun */
		if ((caddr_t)&dstat32p->s_stat[dstatp->s_nstat] >
		    ((caddr_t)dstatp) + sz) {
			DR_OP_INTERNAL_ERROR(hp);
			rv = EINVAL;
			goto status_done;
		}

		/* copy sbd_stat_t structure members */
#define	_SBD_STAT(t, m) dstat32p->m = (t)dstatp->m
		_SBD_STAT(int32_t, s_board);
		_SBD_STAT(int32_t, s_rstate);
		_SBD_STAT(int32_t, s_ostate);
		_SBD_STAT(int32_t, s_cond);
		_SBD_STAT(int32_t, s_busy);
		_SBD_STAT(time32_t, s_time);
		_SBD_STAT(uint32_t, s_power);
		_SBD_STAT(uint32_t, s_assigned);
		_SBD_STAT(int32_t, s_nstat);
		bcopy(&dstatp->s_type[0], &dstat32p->s_type[0],
		    SBD_TYPE_LEN);
		bcopy(&dstatp->s_info[0], &dstat32p->s_info[0],
		    SBD_MAX_INFO);
#undef _SBD_STAT

		for (i = 0; i < dstatp->s_nstat; i++) {
			sbd_dev_stat_t		*dsp = &dstatp->s_stat[i];
			sbd_dev_stat32_t	*ds32p = &dstat32p->s_stat[i];
#define	_SBD_DEV_STAT(t, m) ds32p->m = (t)dsp->m

			/* copy sbd_cm_stat_t structure members */
			_SBD_DEV_STAT(int32_t, ds_type);
			_SBD_DEV_STAT(int32_t, ds_unit);
			_SBD_DEV_STAT(int32_t, ds_ostate);
			_SBD_DEV_STAT(int32_t, ds_cond);
			_SBD_DEV_STAT(int32_t, ds_busy);
			_SBD_DEV_STAT(int32_t, ds_suspend);
			_SBD_DEV_STAT(time32_t, ds_time);
			bcopy(&dsp->ds_name[0], &ds32p->ds_name[0],
			    OBP_MAXPROPNAME);

			switch (dsp->ds_type) {
			case SBD_COMP_CPU:
				/* copy sbd_cpu_stat_t structure members */
				_SBD_DEV_STAT(int32_t, d_cpu.cs_isbootproc);
				_SBD_DEV_STAT(int32_t, d_cpu.cs_cpuid);
				_SBD_DEV_STAT(int32_t, d_cpu.cs_speed);
				_SBD_DEV_STAT(int32_t, d_cpu.cs_ecache);
				break;

			case SBD_COMP_MEM:
				/* copy sbd_mem_stat_t structure members */
				_SBD_DEV_STAT(int32_t, d_mem.ms_interleave);
				_SBD_DEV_STAT(uint32_t, d_mem.ms_basepfn);
				_SBD_DEV_STAT(uint32_t, d_mem.ms_totpages);
				_SBD_DEV_STAT(uint32_t, d_mem.ms_detpages);
				_SBD_DEV_STAT(int32_t, d_mem.ms_pageslost);
				_SBD_DEV_STAT(uint32_t, d_mem.ms_managed_pages);
				_SBD_DEV_STAT(uint32_t, d_mem.ms_noreloc_pages);
				_SBD_DEV_STAT(uint32_t, d_mem.ms_noreloc_first);
				_SBD_DEV_STAT(uint32_t, d_mem.ms_noreloc_last);
				_SBD_DEV_STAT(int32_t, d_mem.ms_cage_enabled);
				_SBD_DEV_STAT(int32_t, d_mem.ms_peer_is_target);
				bcopy(&dsp->d_mem.ms_peer_ap_id[0],
				    &ds32p->d_mem.ms_peer_ap_id[0],
				    sizeof (ds32p->d_mem.ms_peer_ap_id));
				break;

			case SBD_COMP_IO:
				/* copy sbd_io_stat_t structure members */
				_SBD_DEV_STAT(int32_t, d_io.is_referenced);
				_SBD_DEV_STAT(int32_t, d_io.is_unsafe_count);

				for (j = 0; j < SBD_MAX_UNSAFE; j++)
					_SBD_DEV_STAT(int32_t,
					    d_io.is_unsafe_list[j]);

				bcopy(&dsp->d_io.is_pathname[0],
				    &ds32p->d_io.is_pathname[0], MAXPATHLEN);
				break;

			case SBD_COMP_CMP:
				/* copy sbd_cmp_stat_t structure members */
				bcopy(&dsp->d_cmp.ps_cpuid[0],
				    &ds32p->d_cmp.ps_cpuid[0],
				    sizeof (ds32p->d_cmp.ps_cpuid));
				_SBD_DEV_STAT(int32_t, d_cmp.ps_ncores);
				_SBD_DEV_STAT(int32_t, d_cmp.ps_speed);
				_SBD_DEV_STAT(int32_t, d_cmp.ps_ecache);
				break;

			default:
				cmn_err(CE_WARN, "%s: unknown dev type (%d)",
				    f, (int)dsp->ds_type);
				rv = EFAULT;
				goto status_done;
			}
#undef _SBD_DEV_STAT
		}


		if (ddi_copyout((void *)dstat32p,
		    hp->h_sbdcmd.cmd_stat.s_statp, pbsz, mode) != 0) {
			cmn_err(CE_WARN,
			    "%s: failed to copyout status "
			    "for board %d", f, bp->b_num);
			rv = EFAULT;
			goto status_done;
		}
	} else
#endif /* _MULTI_DATAMODEL */

	if (ddi_copyout((void *)dstatp, hp->h_sbdcmd.cmd_stat.s_statp,
	    pbsz, mode) != 0) {
		cmn_err(CE_WARN,
		    "%s: failed to copyout status for board %d",
		    f, bp->b_num);
		rv = EFAULT;
		goto status_done;
	}

status_done:
	if (dstatp != NULL)
		FREESTRUCT(dstatp, char, sz);

	dr_unlock_status(bp);

	return (rv);
}

static int
dr_get_ncm(dr_handle_t *hp)
{
	int		i;
	int		ncm = 0;
	dr_devset_t	devset;

	devset = DR_DEVS_PRESENT(hp->h_bd);
	if (hp->h_sbdcmd.cmd_cm.c_id.c_type != SBD_COMP_NONE)
		devset &= DEVSET(hp->h_sbdcmd.cmd_cm.c_id.c_type,
		    DEVSET_ANYUNIT);

	/*
	 * Handle CPUs first to deal with possible CMP
	 * devices. If the CPU is a CMP, we need to only
	 * increment ncm once even if there are multiple
	 * cores for that CMP present in the devset.
	 */
	for (i = 0; i < MAX_CMP_UNITS_PER_BOARD; i++) {
		if (devset & DEVSET(SBD_COMP_CMP, i)) {
			ncm++;
		}
	}

	/* eliminate the CPU information from the devset */
	devset &= ~(DEVSET(SBD_COMP_CMP, DEVSET_ANYUNIT));

	for (i = 0; i < (sizeof (dr_devset_t) * 8); i++) {
		ncm += devset & 0x1;
		devset >>= 1;
	}

	return (ncm);
}

/* used by dr_mem.c */
/* TODO: eliminate dr_boardlist */
dr_board_t *
dr_lookup_board(int board_num)
{
	dr_board_t *bp;

	ASSERT(board_num >= 0 && board_num < MAX_BOARDS);

	bp = &dr_boardlist[board_num];
	ASSERT(bp->b_num == board_num);

	return (bp);
}

static dr_dev_unit_t *
dr_get_dev_unit(dr_board_t *bp, sbd_comp_type_t nt, int unit_num)
{
	dr_dev_unit_t	*dp;

	dp = DR_GET_BOARD_DEVUNIT(bp, nt, unit_num);
	ASSERT(dp->du_common.sbdev_bp == bp);
	ASSERT(dp->du_common.sbdev_unum == unit_num);
	ASSERT(dp->du_common.sbdev_type == nt);

	return (dp);
}

dr_cpu_unit_t *
dr_get_cpu_unit(dr_board_t *bp, int unit_num)
{
	dr_dev_unit_t	*dp;

	ASSERT(unit_num >= 0 && unit_num < MAX_CPU_UNITS_PER_BOARD);

	dp = dr_get_dev_unit(bp, SBD_COMP_CPU, unit_num);
	return (&dp->du_cpu);
}

dr_mem_unit_t *
dr_get_mem_unit(dr_board_t *bp, int unit_num)
{
	dr_dev_unit_t	*dp;

	ASSERT(unit_num >= 0 && unit_num < MAX_MEM_UNITS_PER_BOARD);

	dp = dr_get_dev_unit(bp, SBD_COMP_MEM, unit_num);
	return (&dp->du_mem);
}

dr_io_unit_t *
dr_get_io_unit(dr_board_t *bp, int unit_num)
{
	dr_dev_unit_t	*dp;

	ASSERT(unit_num >= 0 && unit_num < MAX_IO_UNITS_PER_BOARD);

	dp = dr_get_dev_unit(bp, SBD_COMP_IO, unit_num);
	return (&dp->du_io);
}

dr_common_unit_t *
dr_get_common_unit(dr_board_t *bp, sbd_comp_type_t nt, int unum)
{
	dr_dev_unit_t	*dp;

	dp = dr_get_dev_unit(bp, nt, unum);
	return (&dp->du_common);
}

static dr_devset_t
dr_dev2devset(sbd_comp_id_t *cid)
{
	static fn_t	f = "dr_dev2devset";

	dr_devset_t	devset;
	int		unit = cid->c_unit;

	switch (cid->c_type) {
		case SBD_COMP_NONE:
			devset =  DEVSET(SBD_COMP_CPU, DEVSET_ANYUNIT);
			devset |= DEVSET(SBD_COMP_MEM, DEVSET_ANYUNIT);
			devset |= DEVSET(SBD_COMP_IO,  DEVSET_ANYUNIT);
			PR_ALL("%s: COMP_NONE devset = " DEVSET_FMT_STR "\n",
			    f, DEVSET_FMT_ARG(devset));
			break;

		case SBD_COMP_CPU:
			if ((unit > MAX_CPU_UNITS_PER_BOARD) || (unit < 0)) {
				cmn_err(CE_WARN,
				    "%s: invalid cpu unit# = %d",
				    f, unit);
				devset = 0;
			} else {
				/*
				 * Generate a devset that includes all the
				 * cores of a CMP device. If this is not a
				 * CMP, the extra cores will be eliminated
				 * later since they are not present. This is
				 * also true for CMP devices that do not have
				 * all cores active.
				 */
				devset = DEVSET(SBD_COMP_CMP, unit);
			}

			PR_ALL("%s: CPU devset = " DEVSET_FMT_STR "\n",
			    f, DEVSET_FMT_ARG(devset));
			break;

		case SBD_COMP_MEM:
			if (unit == SBD_NULL_UNIT) {
				unit = 0;
				cid->c_unit = 0;
			}

			if ((unit > MAX_MEM_UNITS_PER_BOARD) || (unit < 0)) {
				cmn_err(CE_WARN,
				    "%s: invalid mem unit# = %d",
				    f, unit);
				devset = 0;
			} else
				devset = DEVSET(cid->c_type, unit);

			PR_ALL("%s: MEM devset = " DEVSET_FMT_STR "\n",
			    f, DEVSET_FMT_ARG(devset));
			break;

		case SBD_COMP_IO:
			if ((unit > MAX_IO_UNITS_PER_BOARD) || (unit < 0)) {
				cmn_err(CE_WARN,
				    "%s: invalid io unit# = %d",
				    f, unit);
				devset = 0;
			} else
				devset = DEVSET(cid->c_type, unit);

			PR_ALL("%s: IO devset = " DEVSET_FMT_STR "\n",
			    f, DEVSET_FMT_ARG(devset));
			break;

		default:
		case SBD_COMP_UNKNOWN:
			devset = 0;
			break;
	}

	return (devset);
}

/*
 * Converts a dynamic attachment point name to a SBD_COMP_* type.
 * Returns SDB_COMP_UNKNOWN if name is not recognized.
 */
static int
dr_dev_type_to_nt(char *type)
{
	int i;

	for (i = 0; dr_devattr[i].s_nodetype != SBD_COMP_UNKNOWN; i++)
		if (strcmp(dr_devattr[i].s_devtype, type) == 0)
			break;

	return (dr_devattr[i].s_nodetype);
}

/*
 * Converts a SBD_COMP_* type to a dynamic attachment point name.
 * Return NULL if SBD_COMP_ type is not recognized.
 */
char *
dr_nt_to_dev_type(int nt)
{
	int i;

	for (i = 0; dr_devattr[i].s_nodetype != SBD_COMP_UNKNOWN; i++)
		if (dr_devattr[i].s_nodetype == nt)
			break;

	return (dr_devattr[i].s_devtype);
}

/*
 * State transition policy is that if there is some component for which
 * the state transition is valid, then let it through. The exception is
 * SBD_CMD_DISCONNECT. On disconnect, the state transition must be valid
 * for ALL components.
 * Returns the state that is in error, if any.
 */
static int
dr_check_transition(dr_board_t *bp, dr_devset_t *devsetp,
    struct dr_state_trans *transp, int cmd)
{
	int			s, ut;
	int			state_err = 0;
	dr_devset_t		devset;
	dr_common_unit_t	*cp;
	static fn_t		f = "dr_check_transition";

	devset = *devsetp;

	if (DEVSET_IN_SET(devset, SBD_COMP_CPU, DEVSET_ANYUNIT)) {
		for (ut = 0; ut < MAX_CPU_UNITS_PER_BOARD; ut++) {
			if (DEVSET_IN_SET(devset, SBD_COMP_CPU, ut) == 0)
				continue;

			cp = dr_get_common_unit(bp, SBD_COMP_CPU, ut);
			s = (int)cp->sbdev_state;
			if (!DR_DEV_IS_PRESENT(cp)) {
				DEVSET_DEL(devset, SBD_COMP_CPU, ut);
			} else {
				if (transp->x_op[s].x_rv) {
					if (!state_err)
						state_err = s;
					DEVSET_DEL(devset, SBD_COMP_CPU, ut);
				}
			}
		}
	}
	if (DEVSET_IN_SET(devset, SBD_COMP_MEM, DEVSET_ANYUNIT)) {
		for (ut = 0; ut < MAX_MEM_UNITS_PER_BOARD; ut++) {
			if (DEVSET_IN_SET(devset, SBD_COMP_MEM, ut) == 0)
				continue;

			cp = dr_get_common_unit(bp, SBD_COMP_MEM, ut);
			s = (int)cp->sbdev_state;
			if (!DR_DEV_IS_PRESENT(cp)) {
				DEVSET_DEL(devset, SBD_COMP_MEM, ut);
			} else {
				if (transp->x_op[s].x_rv) {
					if (!state_err)
						state_err = s;
					DEVSET_DEL(devset, SBD_COMP_MEM, ut);
				}
			}
		}
	}
	if (DEVSET_IN_SET(devset, SBD_COMP_IO, DEVSET_ANYUNIT)) {
		for (ut = 0; ut < MAX_IO_UNITS_PER_BOARD; ut++) {
			if (DEVSET_IN_SET(devset, SBD_COMP_IO, ut) == 0)
				continue;

			cp = dr_get_common_unit(bp, SBD_COMP_IO, ut);
			s = (int)cp->sbdev_state;
			if (!DR_DEV_IS_PRESENT(cp)) {
				DEVSET_DEL(devset, SBD_COMP_IO, ut);
			} else {
				if (transp->x_op[s].x_rv) {
					if (!state_err)
						state_err = s;
					DEVSET_DEL(devset, SBD_COMP_IO, ut);
				}
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
	 * the state error. The exception is SBD_CMD_DISCONNECT.
	 * On disconnect, the state transition must be valid for ALL
	 * components.
	 */
	if (cmd == SBD_CMD_DISCONNECT)
		return (state_err);
	return (devset ? 0 : state_err);
}

void
dr_device_transition(dr_common_unit_t *cp, dr_state_t st)
{
	PR_STATE("%s STATE %s(%d) -> %s(%d)\n",
	    cp->sbdev_path,
	    state_str[cp->sbdev_state], cp->sbdev_state,
	    state_str[st], st);

	cp->sbdev_state = st;
	if (st == DR_STATE_CONFIGURED) {
		cp->sbdev_ostate = SBD_STAT_CONFIGURED;
		if (cp->sbdev_bp->b_ostate != SBD_STAT_CONFIGURED) {
			cp->sbdev_bp->b_ostate = SBD_STAT_CONFIGURED;
			(void) drv_getparm(TIME,
			    (void *) &cp->sbdev_bp->b_time);
		}
	} else
		cp->sbdev_ostate = SBD_STAT_UNCONFIGURED;

	(void) drv_getparm(TIME, (void *) &cp->sbdev_time);
}

static void
dr_board_transition(dr_board_t *bp, dr_state_t st)
{
	PR_STATE("BOARD %d STATE: %s(%d) -> %s(%d)\n",
	    bp->b_num,
	    state_str[bp->b_state], bp->b_state,
	    state_str[st], st);

	bp->b_state = st;
}

void
dr_op_err(int ce, dr_handle_t *hp, int code, char *fmt, ...)
{
	sbd_error_t	*err;
	va_list		args;

	va_start(args, fmt);
	err = drerr_new_v(code, fmt, args);
	va_end(args);

	if (ce != CE_IGNORE)
		sbd_err_log(err, ce);

	DRERR_SET_C(&hp->h_err, &err);
}

void
dr_dev_err(int ce, dr_common_unit_t *cp, int code)
{
	sbd_error_t	*err;

	err = drerr_new(0, code, cp->sbdev_path, NULL);

	if (ce != CE_IGNORE)
		sbd_err_log(err, ce);

	DRERR_SET_C(&cp->sbdev_error, &err);
}

/*
 * A callback routine.  Called from the drmach layer as a result of
 * call to drmach_board_find_devices from dr_init_devlists.
 */
static sbd_error_t *
dr_dev_found(void *data, const char *name, int unum, drmachid_t id)
{
	dr_board_t	*bp = data;
	dr_dev_unit_t	*dp;
	int		 nt;
	static fn_t	f = "dr_dev_found";

	PR_ALL("%s (board = %d, name = %s, unum = %d, id = %p)...\n",
	    f, bp->b_num, name, unum, id);

	nt = dr_dev_type_to_nt((char *)name);
	if (nt == SBD_COMP_UNKNOWN) {
		/*
		 * this should not happen.  When it does, it indicates
		 * a missmatch in devices supported by the drmach layer
		 * vs devices supported by this layer.
		 */
		return (DR_INTERNAL_ERROR());
	}

	dp = DR_GET_BOARD_DEVUNIT(bp, nt, unum);

	/* sanity check */
	ASSERT(dp->du_common.sbdev_bp == bp);
	ASSERT(dp->du_common.sbdev_unum == unum);
	ASSERT(dp->du_common.sbdev_type == nt);

	/* render dynamic attachment point path of this unit */
	(void) snprintf(dp->du_common.sbdev_path,
	    sizeof (dp->du_common.sbdev_path), "%s::%s%d",
	    bp->b_path, name, DR_UNUM2SBD_UNUM(unum, nt));

	dp->du_common.sbdev_id = id;
	DR_DEV_SET_PRESENT(&dp->du_common);

	bp->b_ndev++;

	return (NULL);
}

static sbd_error_t *
dr_init_devlists(dr_board_t *bp)
{
	int		i;
	sbd_error_t	*err;
	dr_dev_unit_t	*dp;
	static fn_t	f = "dr_init_devlists";

	PR_ALL("%s (%s)...\n", f, bp->b_path);

	/* sanity check */
	ASSERT(bp->b_ndev == 0);

	DR_DEVS_DISCONNECT(bp, (uint_t)-1);

	/*
	 * This routine builds the board's devlist and initializes
	 * the common portion of the unit data structures.
	 * Note: because the common portion is considered
	 * uninitialized, the dr_get_*_unit() routines can not
	 * be used.
	 */

	/*
	 * Clear out old entries, if any.
	 */
	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		dp = DR_GET_BOARD_DEVUNIT(bp, SBD_COMP_CPU, i);

		bzero(dp, sizeof (*dp));
		dp->du_common.sbdev_bp = bp;
		dp->du_common.sbdev_unum = i;
		dp->du_common.sbdev_type = SBD_COMP_CPU;
	}

	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		dp = DR_GET_BOARD_DEVUNIT(bp, SBD_COMP_MEM, i);

		bzero(dp, sizeof (*dp));
		dp->du_common.sbdev_bp = bp;
		dp->du_common.sbdev_unum = i;
		dp->du_common.sbdev_type = SBD_COMP_MEM;
	}

	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		dp = DR_GET_BOARD_DEVUNIT(bp, SBD_COMP_IO, i);

		bzero(dp, sizeof (*dp));
		dp->du_common.sbdev_bp = bp;
		dp->du_common.sbdev_unum = i;
		dp->du_common.sbdev_type = SBD_COMP_IO;
	}

	err = NULL;
	if (bp->b_id) {
		/* find devices on this board */
		err = drmach_board_find_devices(
		    bp->b_id, bp, dr_dev_found);
	}

	return (err);
}

/*
 * Return the unit number of the respective drmachid if
 * it's found to be attached.
 */
static int
dr_check_unit_attached(dr_common_unit_t *cp)
{
	int		rv = 0;
	processorid_t	cpuid;
	uint64_t	basepa, endpa;
	struct memlist	*ml;
	extern struct memlist	*phys_install;
	sbd_error_t	*err;
	int		yes;
	static fn_t	f = "dr_check_unit_attached";

	switch (cp->sbdev_type) {
	case SBD_COMP_CPU:
		err = drmach_cpu_get_id(cp->sbdev_id, &cpuid);
		if (err) {
			DRERR_SET_C(&cp->sbdev_error, &err);
			rv = -1;
			break;
		}
		mutex_enter(&cpu_lock);
		if (cpu_get(cpuid) == NULL)
			rv = -1;
		mutex_exit(&cpu_lock);
		break;

	case SBD_COMP_MEM:
		err = drmach_mem_get_slice_info(cp->sbdev_id,
		    &basepa, &endpa, NULL);
		if (err) {
			DRERR_SET_C(&cp->sbdev_error, &err);
			rv = -1;
			break;
		}

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
		if (ml == NULL)
			rv = -1;
		break;

	case SBD_COMP_IO:
		err = drmach_io_is_attached(cp->sbdev_id, &yes);
		if (err) {
			DRERR_SET_C(&cp->sbdev_error, &err);
			rv = -1;
			break;
		} else if (!yes)
			rv = -1;
		break;

	default:
		PR_ALL("%s: unexpected nodetype(%d) for id 0x%p\n",
		    f, cp->sbdev_type, cp->sbdev_id);
		rv = -1;
		break;
	}

	return (rv);
}

/*
 * See if drmach recognizes the passthru command.  DRMACH expects the
 * id to identify the thing to which the command is being applied.  Using
 * nonsense SBD terms, that information has been perversely encoded in the
 * c_id member of the sbd_cmd_t structure.  This logic reads those tea
 * leaves, finds the associated drmach id, then calls drmach to process
 * the passthru command.
 */
static int
dr_pt_try_drmach(dr_handle_t *hp)
{
	dr_board_t	*bp = hp->h_bd;
	sbd_comp_id_t	*comp_id = &hp->h_sbdcmd.cmd_cm.c_id;
	drmachid_t	 id;

	if (comp_id->c_type == SBD_COMP_NONE) {
		id = bp->b_id;
	} else {
		sbd_comp_type_t	 nt;

		nt = dr_dev_type_to_nt(comp_id->c_name);
		if (nt == SBD_COMP_UNKNOWN) {
			dr_op_err(CE_IGNORE, hp, ESBD_INVAL, comp_id->c_name);
			id = 0;
		} else {
			/* pt command applied to dynamic attachment point */
			dr_common_unit_t *cp;
			cp = dr_get_common_unit(bp, nt, comp_id->c_unit);
			id = cp->sbdev_id;
		}
	}

	if (hp->h_err == NULL)
		hp->h_err = drmach_passthru(id, &hp->h_opts);

	return (hp->h_err == NULL ? 0 : -1);
}

static int
dr_pt_ioctl(dr_handle_t *hp)
{
	int		cmd, rv, len;
	int32_t		sz;
	int		found;
	char		*copts;
	static fn_t	f = "dr_pt_ioctl";

	PR_ALL("%s...\n", f);

	sz = hp->h_opts.size;
	copts = hp->h_opts.copts;

	if (sz == 0 || copts == (char *)NULL) {
		cmn_err(CE_WARN, "%s: invalid passthru args", f);
		return (EINVAL);
	}

	found = 0;
	for (cmd = 0; cmd < (sizeof (pt_arr) / sizeof (pt_arr[0])); cmd++) {
		len = strlen(pt_arr[cmd].pt_name);
		found = (strncmp(pt_arr[cmd].pt_name, copts, len) == 0);
		if (found)
			break;
	}

	if (found)
		rv = (*pt_arr[cmd].pt_func)(hp);
	else
		rv = dr_pt_try_drmach(hp);

	return (rv);
}

/*
 * Called at driver load time to determine the state and condition
 * of an existing board in the system.
 */
static void
dr_board_discovery(dr_board_t *bp)
{
	int			i;
	dr_devset_t		devs_lost, devs_attached = 0;
	dr_cpu_unit_t		*cp;
	dr_mem_unit_t		*mp;
	dr_io_unit_t		*ip;
	static fn_t		f = "dr_board_discovery";

	if (DR_DEVS_PRESENT(bp) == 0) {
		PR_ALL("%s: board %d has no devices present\n",
		    f, bp->b_num);
		return;
	}

	/*
	 * Check for existence of cpus.
	 */
	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		cp = dr_get_cpu_unit(bp, i);

		if (!DR_DEV_IS_PRESENT(&cp->sbc_cm))
			continue;

		if (dr_check_unit_attached(&cp->sbc_cm) >= 0) {
			DR_DEV_SET_ATTACHED(&cp->sbc_cm);
			DEVSET_ADD(devs_attached, SBD_COMP_CPU, i);
			PR_ALL("%s: board %d, cpu-unit %d - attached\n",
			    f, bp->b_num, i);
		}
		dr_init_cpu_unit(cp);
	}

	/*
	 * Check for existence of memory.
	 */
	for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
		mp = dr_get_mem_unit(bp, i);

		if (!DR_DEV_IS_PRESENT(&mp->sbm_cm))
			continue;

		if (dr_check_unit_attached(&mp->sbm_cm) >= 0) {
			DR_DEV_SET_ATTACHED(&mp->sbm_cm);
			DEVSET_ADD(devs_attached, SBD_COMP_MEM, i);
			PR_ALL("%s: board %d, mem-unit %d - attached\n",
			    f, bp->b_num, i);
		}
		dr_init_mem_unit(mp);
	}

	/*
	 * Check for i/o state.
	 */
	for (i = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		ip = dr_get_io_unit(bp, i);

		if (!DR_DEV_IS_PRESENT(&ip->sbi_cm))
			continue;

		if (dr_check_unit_attached(&ip->sbi_cm) >= 0) {
			/*
			 * Found it!
			 */
			DR_DEV_SET_ATTACHED(&ip->sbi_cm);
			DEVSET_ADD(devs_attached, SBD_COMP_IO, i);
			PR_ALL("%s: board %d, io-unit %d - attached\n",
			    f, bp->b_num, i);
		}
		dr_init_io_unit(ip);
	}

	DR_DEVS_CONFIGURE(bp, devs_attached);
	if (devs_attached && ((devs_lost = DR_DEVS_UNATTACHED(bp)) != 0)) {
		int		ut;

		/*
		 * It is not legal on board discovery to have a
		 * board that is only partially attached.  A board
		 * is either all attached or all connected.  If a
		 * board has at least one attached device, then
		 * the the remaining devices, if any, must have
		 * been lost or disconnected.  These devices can
		 * only be recovered by a full attach from scratch.
		 * Note that devices previously in the unreferenced
		 * state are subsequently lost until the next full
		 * attach.  This is necessary since the driver unload
		 * that must have occurred would have wiped out the
		 * information necessary to re-configure the device
		 * back online, e.g. memlist.
		 */
		PR_ALL("%s: some devices LOST (" DEVSET_FMT_STR ")...\n",
		    f, DEVSET_FMT_ARG(devs_lost));

		for (ut = 0; ut < MAX_CPU_UNITS_PER_BOARD; ut++) {
			if (!DEVSET_IN_SET(devs_lost, SBD_COMP_CPU, ut))
				continue;

			cp = dr_get_cpu_unit(bp, ut);
			dr_device_transition(&cp->sbc_cm, DR_STATE_EMPTY);
		}

		for (ut = 0; ut < MAX_MEM_UNITS_PER_BOARD; ut++) {
			if (!DEVSET_IN_SET(devs_lost, SBD_COMP_MEM, ut))
				continue;

			mp = dr_get_mem_unit(bp, ut);
			dr_device_transition(&mp->sbm_cm, DR_STATE_EMPTY);
		}

		for (ut = 0; ut < MAX_IO_UNITS_PER_BOARD; ut++) {
			if (!DEVSET_IN_SET(devs_lost, SBD_COMP_IO, ut))
				continue;

			ip = dr_get_io_unit(bp, ut);
			dr_device_transition(&ip->sbi_cm, DR_STATE_EMPTY);
		}

		DR_DEVS_DISCONNECT(bp, devs_lost);
	}
}

static int
dr_board_init(dr_board_t *bp, dev_info_t *dip, int bd)
{
	sbd_error_t	*err;

	mutex_init(&bp->b_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&bp->b_slock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&bp->b_scv, NULL, CV_DRIVER, NULL);
	bp->b_rstate = SBD_STAT_EMPTY;
	bp->b_ostate = SBD_STAT_UNCONFIGURED;
	bp->b_cond = SBD_COND_UNKNOWN;
	(void) drv_getparm(TIME, (void *)&bp->b_time);

	(void) drmach_board_lookup(bd, &bp->b_id);
	bp->b_num = bd;
	bp->b_dip = dip;

	bp->b_dev[DEVSET_NIX(SBD_COMP_CPU)] = GETSTRUCT(dr_dev_unit_t,
	    MAX_CPU_UNITS_PER_BOARD);

	bp->b_dev[DEVSET_NIX(SBD_COMP_MEM)] = GETSTRUCT(dr_dev_unit_t,
	    MAX_MEM_UNITS_PER_BOARD);

	bp->b_dev[DEVSET_NIX(SBD_COMP_IO)] = GETSTRUCT(dr_dev_unit_t,
	    MAX_IO_UNITS_PER_BOARD);

	/*
	 * Initialize the devlists
	 */
	err = dr_init_devlists(bp);
	if (err) {
		sbd_err_clear(&err);
		dr_board_destroy(bp);
		return (-1);
	} else if (bp->b_ndev == 0) {
		dr_board_transition(bp, DR_STATE_EMPTY);
	} else {
		/*
		 * Couldn't have made it down here without
		 * having found at least one device.
		 */
		ASSERT(DR_DEVS_PRESENT(bp) != 0);
		/*
		 * Check the state of any possible devices on the
		 * board.
		 */
		dr_board_discovery(bp);

		bp->b_assigned = 1;

		if (DR_DEVS_UNATTACHED(bp) == 0) {
			/*
			 * The board has no unattached devices, therefore
			 * by reason of insanity it must be configured!
			 */
			dr_board_transition(bp, DR_STATE_CONFIGURED);
			bp->b_ostate = SBD_STAT_CONFIGURED;
			bp->b_rstate = SBD_STAT_CONNECTED;
			bp->b_cond = SBD_COND_OK;
			(void) drv_getparm(TIME, (void *)&bp->b_time);
		} else if (DR_DEVS_ATTACHED(bp)) {
			dr_board_transition(bp, DR_STATE_PARTIAL);
			bp->b_ostate = SBD_STAT_CONFIGURED;
			bp->b_rstate = SBD_STAT_CONNECTED;
			bp->b_cond = SBD_COND_OK;
			(void) drv_getparm(TIME, (void *)&bp->b_time);
		} else {
			dr_board_transition(bp, DR_STATE_CONNECTED);
			bp->b_rstate = SBD_STAT_CONNECTED;
			(void) drv_getparm(TIME, (void *)&bp->b_time);
		}
	}

	return (0);
}

static void
dr_board_destroy(dr_board_t *bp)
{
	PR_ALL("dr_board_destroy: num %d, path %s\n",
	    bp->b_num, bp->b_path);

	dr_board_transition(bp, DR_STATE_EMPTY);
	bp->b_rstate = SBD_STAT_EMPTY;
	(void) drv_getparm(TIME, (void *)&bp->b_time);

	/*
	 * Free up MEM unit structs.
	 */
	FREESTRUCT(bp->b_dev[DEVSET_NIX(SBD_COMP_MEM)],
	    dr_dev_unit_t, MAX_MEM_UNITS_PER_BOARD);
	bp->b_dev[DEVSET_NIX(SBD_COMP_MEM)] = NULL;
	/*
	 * Free up CPU unit structs.
	 */
	FREESTRUCT(bp->b_dev[DEVSET_NIX(SBD_COMP_CPU)],
	    dr_dev_unit_t, MAX_CPU_UNITS_PER_BOARD);
	bp->b_dev[DEVSET_NIX(SBD_COMP_CPU)] = NULL;
	/*
	 * Free up IO unit structs.
	 */
	FREESTRUCT(bp->b_dev[DEVSET_NIX(SBD_COMP_IO)],
	    dr_dev_unit_t, MAX_IO_UNITS_PER_BOARD);
	bp->b_dev[DEVSET_NIX(SBD_COMP_IO)] = NULL;

	mutex_destroy(&bp->b_lock);
	mutex_destroy(&bp->b_slock);
	cv_destroy(&bp->b_scv);

	/*
	 * Reset the board structure to its initial state, otherwise it will
	 * cause trouble on the next call to dr_board_init() for the same board.
	 * dr_board_init() may be called multiple times for the same board
	 * if DR driver fails to initialize some boards.
	 */
	bzero(bp, sizeof (*bp));
}

void
dr_lock_status(dr_board_t *bp)
{
	mutex_enter(&bp->b_slock);
	while (bp->b_sflags & DR_BSLOCK)
		cv_wait(&bp->b_scv, &bp->b_slock);
	bp->b_sflags |= DR_BSLOCK;
	mutex_exit(&bp->b_slock);
}

void
dr_unlock_status(dr_board_t *bp)
{
	mutex_enter(&bp->b_slock);
	bp->b_sflags &= ~DR_BSLOCK;
	cv_signal(&bp->b_scv);
	mutex_exit(&bp->b_slock);
}

/*
 * Extract flags passed via ioctl.
 */
int
dr_cmd_flags(dr_handle_t *hp)
{
	return (hp->h_sbdcmd.cmd_cm.c_flags);
}
