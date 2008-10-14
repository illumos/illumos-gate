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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#define	_DSW_

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/unistat/spcs_s.h>
#include <sys/dkio.h>

#ifdef DS_DDICT
#include "../contract.h"
#endif

#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/nsvers.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "dsw.h"
#include "dsw_dev.h"

#define	DIDINIT		0x01
#define	DIDNODES	0x02


static int iiopen(dev_t *devp, int flag, int otyp, cred_t *crp);
static int iiclose(dev_t dev, int flag, int otyp, cred_t *crp);
static int iiprint(dev_t dev, char *str);
static int iiioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *crp,
    int *rvp);
static int iiprobe(dev_info_t *dip);
static int iiattach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int iidetach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int iistrat(struct buf *);
static int iiread();


static kstat_t *ii_gkstat = NULL;
iigkstat_t iigkstat = {
	{ "ii_debug", KSTAT_DATA_ULONG },
	{ "ii_bitmap", KSTAT_DATA_ULONG },
	{ "ii_throttle_unit", KSTAT_DATA_ULONG },
	{ "ii_throttle_delay", KSTAT_DATA_ULONG },
	{ "ii_copy_direct", KSTAT_DATA_ULONG },
	{ "num-sets", KSTAT_DATA_ULONG },
	{ "assoc-over", KSTAT_DATA_ULONG },
	{ "spilled-over", KSTAT_DATA_ULONG },
};

static struct cb_ops ii_cb_ops = {
	iiopen,
	iiclose,
	iistrat,		/* dummy strategy */
	iiprint,
	nodev,			/* no dump */
	iiread,			/* dummy read */
	nodev,			/* no write */
	iiioctl,
	nodev,			/* no devmap */
	nodev,			/* no mmap */
	nodev,			/* no segmap */
	nochpoll,
	ddi_prop_op,
	NULL,			/* not STREAMS */
	D_NEW | D_MP
};

static struct dev_ops ii_ops = {
	DEVO_REV,
	0,
	nodev,			/* no getinfo */
	nulldev,
	iiprobe,
	iiattach,
	iidetach,
	nodev,			/* no reset */
	&ii_cb_ops,
	(struct bus_ops *)NULL
};

static struct modldrv ii_ldrv = {
	&mod_driverops,
	"nws:Point-in-Time:" ISS_VERSION_STR,
	&ii_ops
};

static struct modlinkage ii_modlinkage = {
	MODREV_1,
	&ii_ldrv,
	NULL
};

struct ii_state {
	dev_info_t *dip;
	int	instance;
};

/* used for logging sysevent, gets set in _ii_attach */
dev_info_t *ii_dip = NULL;

extern _ii_info_t *_ii_info_top;
extern _ii_lsthead_t *_ii_cluster_top;
extern _ii_lsthead_t *_ii_group_top;
extern kmutex_t _ii_cluster_mutex;
extern kmutex_t _ii_group_mutex;

const int dsw_major_rev = ISS_VERSION_MAJ;	/* Major release number */
const int dsw_minor_rev = ISS_VERSION_MIN;	/* Minor release number */
const int dsw_micro_rev = ISS_VERSION_MIC;	/* Micro release number */
const int dsw_baseline_rev = ISS_VERSION_NUM;	/* Baseline revision */
static void *ii_statep;

extern int _ii_init_dev();
extern void _ii_deinit_dev();
extern int _ii_config(intptr_t arg, int ilp32, int *rvp, int iflags);
extern int _ii_disable(intptr_t arg, int ilp32, int *rvp);
extern int _ii_suspend(intptr_t arg, int ilp32, int *rvp);
extern int _ii_bitmap(intptr_t arg, int ilp32, int *rvp);
extern int _ii_segment(intptr_t arg, int ilp32, int *rvp);
extern int _ii_abort(intptr_t arg, int ilp32, int *rvp);
extern int _ii_acopy(intptr_t arg, int ilp32, int *rvp);
extern int _ii_copy(intptr_t arg, int ilp32, int *rvp);
extern int _ii_shutdown(intptr_t arg, int *rvp);
extern int _ii_stat(intptr_t arg, int ilp32, int *rvp);
extern int _ii_version(intptr_t arg, int ilp32, int *rvp);
extern int _ii_wait(intptr_t arg, int ilp32, int *rvp);
extern int _ii_reset(intptr_t arg, int ilp32, int *rvp);
extern int _ii_offline(intptr_t arg, int ilp32, int *rvp);
extern int _ii_list(intptr_t arg, int ilp32, int *rvp);
extern int _ii_listlen(int cmd, int ilp32, int *rvp);
extern int _ii_export(intptr_t arg, int ilp32, int *rvp);
extern int _ii_join(intptr_t arg, int ilp32, int *rvp);
extern int _ii_copyparm(intptr_t arg, int ilp32, int *rvp);
extern int _ii_ocreate(intptr_t arg, int ilp32, int *rvp);
extern int _ii_oattach(intptr_t arg, int ilp32, int *rvp);
extern int _ii_odetach(intptr_t arg, int ilp32, int *rvp);
extern int _ii_olist(intptr_t arg, int ilp32, int *rvp);
extern int _ii_ostat(intptr_t arg, int ilp32, int *rvp, int is_iost_2);
extern int _ii_bitsset(intptr_t arg, int ilp32, int cmd, int *rvp);
extern int _ii_gc_list(intptr_t, int, int *, kmutex_t *, _ii_lsthead_t *);
extern int _ii_clist(intptr_t arg, int ilp32, int *rvp);
extern int _ii_move_grp(intptr_t arg, int ilp32, int *rvp);
extern int _ii_change_tag(intptr_t arg, int ilp32, int *rvp);
extern int ii_debug;
extern int ii_throttle_unit;
extern int ii_throttle_delay;
extern int ii_copy_direct;
extern int ii_bitmap;

int
_init(void)
{
	int error;

	error = ddi_soft_state_init(&ii_statep, sizeof (struct ii_state), 1);
	if (!error) {
		error = mod_install(&ii_modlinkage);
		if (error)
			ddi_soft_state_fini(&ii_statep);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&ii_modlinkage);
	if (!error)
		ddi_soft_state_fini(&ii_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	int rc;

	rc = mod_info(&ii_modlinkage, modinfop);

	return (rc);
}

/* ARGSUSED */

static int
iiprobe(dev_info_t *dip)
{
	return (DDI_PROBE_SUCCESS);
}

/*ARGSUSED*/
static int
ii_stats_update(kstat_t *ksp, int rw)
{
	if (KSTAT_WRITE == rw) {
		return (EACCES);
	}

	/*
	 * We do nothing here for now -- the kstat structure is
	 * updated in-place
	 */

	return (0);
}

static void
ii_create_kstats()
{
	/* create global info structure */
	if (!ii_gkstat) {
		ii_gkstat = kstat_create("ii", 0, "global", "StorEdge",
		    KSTAT_TYPE_NAMED,
		    sizeof (iigkstat) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL);
		if (ii_gkstat) {
			ii_gkstat->ks_data = &iigkstat;
			ii_gkstat->ks_update = ii_stats_update;
			ii_gkstat->ks_private = 0;
			kstat_install(ii_gkstat);

			/* fill in immutable values */
			iigkstat.ii_debug.value.ul = ii_debug;
			iigkstat.ii_bitmap.value.ul = ii_bitmap;
			iigkstat.ii_throttle_unit.value.ul = ii_throttle_unit;
			iigkstat.ii_throttle_delay.value.ul =
			    ii_throttle_delay;
			iigkstat.ii_copy_direct.value.ul = ii_copy_direct;
		} else {
			cmn_err(CE_WARN, "Unable to create II global stats");
		}
	}
}

static int
iiattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct ii_state *xsp;
	int instance;
	int i;
	intptr_t flags;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}
	/* save the dev_info_t to be used in logging using ddi_log_sysevent */
	ii_dip = dip;

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(ii_statep, instance) != 0) {
		cmn_err(CE_WARN, "ii: no memory for instance %d state.",
		    instance);
		return (DDI_FAILURE);
	}

	flags = 0;
	xsp = ddi_get_soft_state(ii_statep, instance);
	if (xsp == NULL) {
		cmn_err(CE_WARN,
		    "ii: attach: could not get state for instance %d.",
		    instance);
		goto out;
	}

	ii_debug = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "ii_debug", 0);
	if (ii_debug != 0) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "ii: initializing ii version %d.%d.%d.%d",
		    dsw_major_rev, dsw_minor_rev,
		    dsw_micro_rev, dsw_baseline_rev);
#else
		if (dsw_micro_rev) {
			cmn_err(CE_NOTE, "ii: initializing ii version %d.%d.%d",
			    dsw_major_rev, dsw_minor_rev, dsw_micro_rev);
		} else {
			cmn_err(CE_NOTE, "ii: initializing ii version %d.%d",
			    dsw_major_rev, dsw_minor_rev);
		}
#endif
		switch (ii_debug) {
		case 1:
		case 2:	cmn_err(CE_NOTE,
			    "ii: ii_debug=%d is enabled.", ii_debug);
			break;
		default:
			cmn_err(CE_WARN,
			    "ii: Value of ii_debug=%d is not 0,1 or 2.",
			    ii_debug);
		}
	}

	ii_bitmap = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "ii_bitmap", II_WTHRU);
	switch (ii_bitmap) {
		case II_KMEM:
		    if (ii_debug > 0)
			cmn_err(CE_NOTE, "ii: ii_bitmap is in memory");
		    break;
		case II_FWC:
		    if (ii_debug > 0)
			cmn_err(CE_NOTE, "ii: ii_bitmap is on disk, no FWC");
		    break;
		case II_WTHRU:
		    if (ii_debug > 0)
			cmn_err(CE_NOTE, "ii: ii_bitmap is on disk");
		    break;
		default:
		    cmn_err(CE_NOTE,
			"ii: ii_bitmap=%d out of range; defaulting WTHRU(%d)",
			ii_bitmap, II_WTHRU);
		ii_bitmap = II_WTHRU;
	}

	/* pick up these values if in ii.conf, otherwise leave alone */
	i = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "ii_throttle_unit", 0);
	if (i > 0) {
		ii_throttle_unit = i;
		if ((ii_throttle_unit < MIN_THROTTLE_UNIT) ||
		    (ii_throttle_unit > MAX_THROTTLE_UNIT) ||
		    (ii_debug > 0))
			cmn_err(CE_NOTE,
				"ii: ii_throttle_unit=%d", ii_throttle_unit);
	}

	i = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "ii_throttle_delay", 0);
	if (i > 0) {
		ii_throttle_delay = i;
		if ((ii_throttle_delay < MIN_THROTTLE_DELAY) ||
		    (ii_throttle_delay > MIN_THROTTLE_DELAY) ||
		    (ii_debug > 0))
			cmn_err(CE_NOTE,
				"ii: ii_throttle_delay=%d", ii_throttle_delay);
	}

	ii_copy_direct = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "ii_copy_direct", 1);
	if (i > 0) {
		ii_copy_direct = i;
		if ((ii_copy_direct < 0) || (ii_copy_direct > 1))
			cmn_err(CE_NOTE,
				"ii: ii_copy_direct=%d", ii_copy_direct);
	}

	if (_ii_init_dev()) {
		cmn_err(CE_WARN, "ii: _ii_init_dev failed");
		goto out;
	}
	flags |= DIDINIT;

	xsp->dip = dip;
	xsp->instance = instance;

	if (ddi_create_minor_node(dip, "ii", S_IFCHR, instance, DDI_PSEUDO, 0)
		    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ii: could not create node.");
		goto out;
	}
	flags |= DIDNODES;

	ddi_set_driver_private(dip, (caddr_t)flags);
	ddi_report_dev(dip);

	ii_create_kstats();

	return (DDI_SUCCESS);

out:
	ddi_set_driver_private(dip, (caddr_t)flags);
	(void) iidetach(dip, DDI_DETACH);

	return (DDI_FAILURE);
}

static int
iidetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct ii_state *xsp;
	int instance;
	intptr_t flags;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (_ii_info_top) {
		return (DDI_FAILURE);	/* busy */
	}

	instance = ddi_get_instance(dip);
	xsp = ddi_get_soft_state(ii_statep, instance);
	if (xsp == NULL) {
		cmn_err(CE_WARN,
		    "ii: detach: could not get state for instance %d.",
		    instance);
		return (DDI_FAILURE);
	}

	flags = (intptr_t)ddi_get_driver_private(dip);
	if (flags & DIDNODES)
		ddi_remove_minor_node(dip, NULL);
	if (flags & DIDINIT)
		_ii_deinit_dev();

	ddi_soft_state_free(ii_statep, instance);

	if (ii_gkstat) {
		kstat_delete(ii_gkstat);
		ii_gkstat = NULL;
	}

	return (DDI_SUCCESS);
}


/* ARGSUSED */

static int
iiopen(dev_t *devp, int flag, int otyp, cred_t *crp)
{
	int error;

	error = drv_priv(crp);

	return (error);
}


/* ARGSUSED */

static int
iiclose(dev_t dev, int flag, int otyp, cred_t *crp)
{
	return (0);
}

/* ARGSUSED */

static int
iiprint(dev_t dev, char *str)
{
	int instance = 0;

	cmn_err(CE_WARN, "ii%d: %s", instance, str);
	return (0);
}

/* ARGSUSED */

static int
iiioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *crp, int *rvp)
{
	int rc;
	int ilp32;

	ilp32 = (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32);


	switch (cmd) {
	case DSWIOC_WAIT:
		rc = _ii_wait(arg, ilp32, rvp);
		break;

	case DSWIOC_RESET:
		rc = _ii_reset(arg, ilp32, rvp);
		break;

	case DSWIOC_VERSION:
		rc = _ii_version(arg, ilp32, rvp);
		break;

	case DSWIOC_ENABLE:
		rc = _ii_config(arg, ilp32, rvp, 0);
		break;

	case DSWIOC_RESUME:
		rc = _ii_config(arg, ilp32, rvp, II_EXISTING);
		break;

	case DSWIOC_DISABLE:
		rc = _ii_disable(arg, ilp32, rvp);
		break;

	case DSWIOC_SUSPEND:
		rc = _ii_suspend(arg, ilp32, rvp);
		break;

	case DSWIOC_ACOPY:
		rc = _ii_acopy(arg, ilp32, rvp);
		break;

	case DSWIOC_COPY:
		rc = _ii_copy(arg, ilp32, rvp);
		break;

	case DSWIOC_SHUTDOWN:
		rc = _ii_shutdown(arg, rvp);
		break;

	case DSWIOC_STAT:
		rc = _ii_stat(arg, ilp32, rvp);
		break;

	case DSWIOC_BITMAP:
		rc = _ii_bitmap(arg, ilp32, rvp);
		break;

	case DSWIOC_SEGMENT:
		rc = _ii_segment(arg, ilp32, rvp);
		break;

	case DSWIOC_ABORT:
		rc = _ii_abort(arg, ilp32, rvp);
		break;

	case DSWIOC_OFFLINE:
		rc = _ii_offline(arg, ilp32, rvp);
		break;

	case DSWIOC_LIST:
		rc = _ii_list(arg, ilp32, rvp);
		break;

	case DSWIOC_LISTLEN:
	case DSWIOC_OLISTLEN:
		rc = _ii_listlen(cmd, ilp32, rvp);
		break;

	case DSWIOC_EXPORT:
		rc = _ii_export(arg, ilp32, rvp);
		break;

	case DSWIOC_IMPORT:
		rc = _ii_config(arg, ilp32, rvp, II_IMPORT);
		break;

	case DSWIOC_JOIN:
		rc = _ii_join(arg, ilp32, rvp);
		break;

	case DSWIOC_COPYP:
		rc = _ii_copyparm(arg, ilp32, rvp);
		break;

	case DSWIOC_OCREAT:
		rc = _ii_ocreate(arg, ilp32, rvp);
		break;

	case DSWIOC_OATTACH:
		rc = _ii_oattach(arg, ilp32, rvp);
		break;

	case DSWIOC_ODETACH:
		rc = _ii_odetach(arg, ilp32, rvp);
		break;

	case DSWIOC_OLIST:
		rc = _ii_olist(arg, ilp32, rvp);
		break;

	case DSWIOC_OSTAT:
		rc = _ii_ostat(arg, ilp32, rvp, FALSE);
		break;

	case DSWIOC_OSTAT2:
		rc = _ii_ostat(arg, ilp32, rvp, TRUE);
		break;

	case DSWIOC_SBITSSET:
	case DSWIOC_CBITSSET:
		rc = _ii_bitsset(arg, ilp32, cmd, rvp);
		break;

	case DSWIOC_CLIST:
		rc = _ii_gc_list(arg, ilp32, rvp, &_ii_cluster_mutex,
		    _ii_cluster_top);
		break;

	case DSWIOC_GLIST:
		rc = _ii_gc_list(arg, ilp32, rvp, &_ii_group_mutex,
		    _ii_group_top);
		break;

	case DSWIOC_MOVEGRP:
		rc = _ii_move_grp(arg, ilp32, rvp);
		break;

	case DSWIOC_CHANGETAG:
		rc = _ii_change_tag(arg, ilp32, rvp);
		break;

	default:
		rc = EINVAL;
		break;
	}

	return (rc);
}

/*
 * dummy function
 */

static int
iistrat(struct buf *bp)
{
	bp->b_error = EIO;
	biodone(bp);

	return (0);
}

static int
iiread()
{
	return (EIO);
}
