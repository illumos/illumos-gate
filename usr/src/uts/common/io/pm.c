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
 */

/*
 * pm	This driver now only handles the ioctl interface.  The scanning
 *	and policy stuff now lives in common/os/sunpm.c.
 *	Not DDI compliant
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/callb.h>		/* callback registration for cpu_deep_idle */
#include <sys/conf.h>		/* driver flags and functions */
#include <sys/open.h>		/* OTYP_CHR definition */
#include <sys/stat.h>		/* S_IFCHR definition */
#include <sys/pathname.h>	/* name -> dev_info xlation */
#include <sys/kmem.h>		/* memory alloc stuff */
#include <sys/debug.h>
#include <sys/pm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/epm.h>
#include <sys/vfs.h>
#include <sys/mode.h>
#include <sys/mkdev.h>
#include <sys/promif.h>
#include <sys/consdev.h>
#include <sys/ddi_impldefs.h>
#include <sys/poll.h>
#include <sys/note.h>
#include <sys/taskq.h>
#include <sys/policy.h>
#include <sys/cpu_pm.h>

/*
 * Minor number is instance<<8 + clone minor from range 1-254; (0 reserved
 * for "original")
 */
#define	PM_MINOR_TO_CLONE(minor) ((minor) & (PM_MAX_CLONE -1))

#define	PM_NUMCMPTS(dip) (DEVI(dip)->devi_pm_num_components)
#define	PM_IS_CFB(dip) (DEVI(dip)->devi_pm_flags & PMC_CONSOLE_FB)
#define	PM_MAJOR(dip) ddi_driver_major(dip)
#define	PM_RELE(dip) ddi_release_devi(dip)

#define	PM_IDLEDOWN_TIME	10
#define	MAXSMBIOSSTRLEN 64	/* from SMBIOS spec */
#define	MAXCOPYBUF	(MAXSMBIOSSTRLEN + 1)

extern kmutex_t	pm_scan_lock;	/* protects autopm_enable, pm_scans_disabled */
extern kmutex_t	pm_clone_lock;	/* protects pm_clones array */
extern int	autopm_enabled;
extern pm_cpupm_t cpupm;
extern pm_cpupm_t cpupm_default_mode;
extern int	pm_default_idle_threshold;
extern int	pm_system_idle_threshold;
extern int	pm_cpu_idle_threshold;
extern kcondvar_t pm_clones_cv[PM_MAX_CLONE];
extern uint_t	pm_poll_cnt[PM_MAX_CLONE];
extern int	autoS3_enabled;
extern void	pm_record_thresh(pm_thresh_rec_t *);
extern void	pm_register_watcher(int, dev_info_t *);
extern int	pm_get_current_power(dev_info_t *, int, int *);
extern int	pm_interest_registered(int);
extern void	pm_all_to_default_thresholds(void);
extern int	pm_current_threshold(dev_info_t *, int, int *);
extern void	pm_deregister_watcher(int, dev_info_t *);
extern void	pm_unrecord_threshold(char *);
extern int	pm_S3_enabled;
extern int	pm_ppm_searchlist(pm_searchargs_t *);
extern psce_t	*pm_psc_clone_to_direct(int);
extern psce_t	*pm_psc_clone_to_interest(int);

/*
 * The soft state of the power manager.  Since there will only
 * one of these, just reference it through a static pointer.
 */
static struct pmstate {
	dev_info_t	*pm_dip;		/* ptr to our dev_info node */
	int		pm_instance;		/* for ddi_get_instance() */
	timeout_id_t	pm_idledown_id;		/* pm idledown timeout id */
	uchar_t		pm_clones[PM_MAX_CLONE]; /* uniqueify multiple opens */
	struct cred	*pm_cred[PM_MAX_CLONE];	/* cred for each unique open */
} pm_state = { NULL, -1, (timeout_id_t)0 };
typedef struct pmstate *pm_state_t;
static pm_state_t pmstp = &pm_state;

static int	pm_open(dev_t *, int, int, cred_t *);
static int	pm_close(dev_t, int, int, cred_t *);
static int	pm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	pm_chpoll(dev_t, short, int, short *, struct pollhead **);

static struct cb_ops pm_cb_ops = {
	pm_open,	/* open */
	pm_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	pm_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	pm_chpoll,	/* poll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* streamtab */
	D_NEW | D_MP	/* driver compatibility flag */
};

static int pm_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result);
static int pm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops pm_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	pm_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	pm_attach,		/* attach */
	pm_detach,		/* detach */
	nodev,			/* reset */
	&pm_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"power management driver",
	&pm_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, 0
};

/* Local functions */
#ifdef DEBUG
static int	print_info(dev_info_t *, void *);

#endif

int
_init(void)
{
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

static int
pm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		i;

	switch (cmd) {

	case DDI_ATTACH:
		if (pmstp->pm_instance != -1)	/* Only allow one instance */
			return (DDI_FAILURE);
		pmstp->pm_instance = ddi_get_instance(dip);
		if (ddi_create_minor_node(dip, "pm", S_IFCHR,
		    (pmstp->pm_instance << 8) + 0,
		    DDI_PSEUDO, 0) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		pmstp->pm_dip = dip;	/* pm_init and getinfo depend on it */

		for (i = 0; i < PM_MAX_CLONE; i++)
			cv_init(&pm_clones_cv[i], NULL, CV_DEFAULT, NULL);

		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/* ARGSUSED */
static int
pm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int i;

	switch (cmd) {
	case DDI_DETACH:
		/*
		 * Don't detach while idledown timeout is pending.  Note that
		 * we already know we're not in pm_ioctl() due to framework
		 * synchronization, so this is a sufficient test
		 */
		if (pmstp->pm_idledown_id)
			return (DDI_FAILURE);

		for (i = 0; i < PM_MAX_CLONE; i++)
			cv_destroy(&pm_clones_cv[i]);

		ddi_remove_minor_node(dip, NULL);
		pmstp->pm_instance = -1;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
pm_close_direct_pm_device(dev_info_t *dip, void *arg)
{
	int clone;
	char *pathbuf;
	pm_info_t *info = PM_GET_PM_INFO(dip);

	clone = *((int *)arg);

	if (!info)
		return (DDI_WALK_CONTINUE);

	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	PM_LOCK_DIP(dip);
	if (clone == info->pmi_clone) {
		PMD(PMD_CLOSE, ("pm_close: found %s@%s(%s#%d)\n",
		    PM_DEVICE(dip)))
		ASSERT(PM_ISDIRECT(dip));
		info->pmi_dev_pm_state &= ~PM_DIRECT;
		PM_UNLOCK_DIP(dip);
		pm_proceed(dip, PMP_RELEASE, -1, -1);
		/* Bring ourselves up if there is a keeper that is up */
		(void) ddi_pathname(dip, pathbuf);
		pm_dispatch_to_dep_thread(PM_DEP_WK_BRINGUP_SELF, NULL,
		    pathbuf, PM_DEP_NOWAIT, NULL, 0);
		PM_LOCK_DIP(dip);
		info->pmi_clone = 0;
		PM_UNLOCK_DIP(dip);
	} else {
		PM_UNLOCK_DIP(dip);
	}
	kmem_free(pathbuf, MAXPATHLEN);

	/* restart autopm on device released from direct pm */
	pm_rescan(dip);

	return (DDI_WALK_CONTINUE);
}

#define	PM_REQ		1
#define	NOSTRUCT	2
#define	DIP		3
#define	NODIP		4
#define	NODEP		5
#define	DEP		6
#define	PM_PSC		7
#define	PM_SRCH		8

#define	CHECKPERMS	0x001
#define	SU		0x002
#define	SG		0x004
#define	OWNER		0x008

#define	INWHO		0x001
#define	INDATAINT	0x002
#define	INDATASTRING	0x004
#define	INDEP		0x008
#define	INDATAOUT	0x010
#define	INDATA	(INDATAOUT | INDATAINT | INDATASTRING | INDEP)

struct pm_cmd_info {
	int cmd;		/* command code */
	char *name;		/* printable string */
	int supported;		/* true if still supported */
	int str_type;		/* PM_REQ or NOSTRUCT */
	int inargs;		/* INWHO, INDATAINT, INDATASTRING, INDEP, */
				/* INDATAOUT */
	int diptype;		/* DIP or NODIP */
	int deptype;		/* DEP or NODEP */
	int permission;		/* SU, GU, or CHECKPERMS */
};

#ifdef DEBUG
char *pm_cmd_string;
int pm_cmd;
#endif

/*
 * Returns true if permission granted by credentials
 */
static int
pm_perms(int perm, cred_t *cr)
{
	if (perm == 0)			/* no restrictions */
		return (1);
	if (perm == CHECKPERMS)		/* ok for now (is checked later) */
		return (1);
	if ((perm & SU) && secpolicy_power_mgmt(cr) == 0) /* privileged? */
		return (1);
	if ((perm & SG) && (crgetgid(cr) == 0))	/* group 0 is ok */
		return (1);
	return (0);
}

#ifdef DEBUG
static int
print_info(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	pm_info_t	*info;
	int		i, j;
	struct pm_component *cp;
	extern int pm_cur_power(pm_component_t *cp);

	info = PM_GET_PM_INFO(dip);
	if (!info)
		return (DDI_WALK_CONTINUE);
	cmn_err(CE_CONT, "pm_info for %s\n", ddi_node_name(dip));
	for (i = 0; i < PM_NUMCMPTS(dip); i++) {
		cp = PM_CP(dip, i);
		cmn_err(CE_CONT, "\tThresholds[%d] =",  i);
		for (j = 0; j < cp->pmc_comp.pmc_numlevels; j++)
			cmn_err(CE_CONT, " %d", cp->pmc_comp.pmc_thresh[i]);
		cmn_err(CE_CONT, "\n");
		cmn_err(CE_CONT, "\tCurrent power[%d] = %d\n", i,
		    pm_cur_power(cp));
	}
	if (PM_ISDIRECT(dip))
		cmn_err(CE_CONT, "\tDirect power management\n");
	return (DDI_WALK_CONTINUE);
}
#endif

/*
 * command, name, supported, str_type, inargs, diptype, deptype, permission
 */
static struct pm_cmd_info pmci[] = {
	{PM_SCHEDULE, "PM_SCHEDULE", 0},
	{PM_GET_IDLE_TIME, "PM_GET_IDLE_TIME", 0},
	{PM_GET_NUM_CMPTS, "PM_GET_NUM_CMPTS", 0},
	{PM_GET_THRESHOLD, "PM_GET_THRESHOLD", 0},
	{PM_SET_THRESHOLD, "PM_SET_THRESHOLD", 0},
	{PM_GET_NORM_PWR, "PM_GET_NORM_PWR", 0},
	{PM_SET_CUR_PWR, "PM_SET_CUR_PWR", 0},
	{PM_GET_CUR_PWR, "PM_GET_CUR_PWR", 0},
	{PM_GET_NUM_DEPS, "PM_GET_NUM_DEPS", 0},
	{PM_GET_DEP, "PM_GET_DEP", 0},
	{PM_ADD_DEP, "PM_ADD_DEP", 0},
	{PM_REM_DEP, "PM_REM_DEP", 0},
	{PM_REM_DEVICE, "PM_REM_DEVICE", 0},
	{PM_REM_DEVICES, "PM_REM_DEVICES", 0},
	{PM_REPARSE_PM_PROPS, "PM_REPARSE_PM_PROPS", 1, PM_REQ, INWHO, DIP,
	    NODEP},
	{PM_DISABLE_AUTOPM, "PM_DISABLE_AUTOPM", 0},
	{PM_REENABLE_AUTOPM, "PM_REENABLE_AUTOPM", 0},
	{PM_SET_NORM_PWR, "PM_SET_NORM_PWR", 0 },
	{PM_SET_DEVICE_THRESHOLD, "PM_SET_DEVICE_THRESHOLD", 1, PM_REQ,
	    INWHO, NODIP, NODEP, SU},
	{PM_GET_SYSTEM_THRESHOLD, "PM_GET_SYSTEM_THRESHOLD", 1, NOSTRUCT},
	{PM_GET_DEFAULT_SYSTEM_THRESHOLD, "PM_GET_DEFAULT_SYSTEM_THRESHOLD",
	    1, NOSTRUCT},
	{PM_SET_SYSTEM_THRESHOLD, "PM_SET_SYSTEM_THRESHOLD", 1, NOSTRUCT,
	    0, 0, 0, SU},
	{PM_START_PM, "PM_START_PM", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_STOP_PM, "PM_STOP_PM", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_RESET_PM, "PM_RESET_PM", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_GET_STATS, "PM_GET_STATS", 1, PM_REQ, INWHO | INDATAOUT,
	    DIP, NODEP},
	{PM_GET_DEVICE_THRESHOLD, "PM_GET_DEVICE_THRESHOLD", 1, PM_REQ, INWHO,
	    DIP, NODEP},
	{PM_GET_POWER_NAME, "PM_GET_POWER_NAME", 1, PM_REQ, INWHO | INDATAOUT,
	    DIP, NODEP},
	{PM_GET_POWER_LEVELS, "PM_GET_POWER_LEVELS", 1, PM_REQ,
	    INWHO | INDATAOUT, DIP, NODEP},
	{PM_GET_NUM_COMPONENTS, "PM_GET_NUM_COMPONENTS", 1, PM_REQ, INWHO,
	    DIP, NODEP},
	{PM_GET_COMPONENT_NAME, "PM_GET_COMPONENT_NAME", 1, PM_REQ,
	    INWHO | INDATAOUT, DIP, NODEP},
	{PM_GET_NUM_POWER_LEVELS, "PM_GET_NUM_POWER_LEVELS", 1, PM_REQ, INWHO,
	    DIP, NODEP},
	{PM_GET_STATE_CHANGE, "PM_GET_STATE_CHANGE", 1, PM_PSC},
	{PM_GET_STATE_CHANGE_WAIT, "PM_GET_STATE_CHANGE_WAIT", 1, PM_PSC},
	{PM_DIRECT_PM, "PM_DIRECT_PM", 1, PM_REQ, INWHO, DIP, NODEP,
	    (SU | SG)},
	{PM_RELEASE_DIRECT_PM, "PM_RELEASE_DIRECT_PM", 1, PM_REQ, INWHO,
	    DIP, NODEP},
	{PM_DIRECT_NOTIFY, "PM_DIRECT_NOTIFY", 1, PM_PSC},
	{PM_DIRECT_NOTIFY_WAIT, "PM_DIRECT_NOTIFY_WAIT", 1, PM_PSC},
	{PM_RESET_DEVICE_THRESHOLD, "PM_RESET_DEVICE_THRESHOLD", 1, PM_REQ,
	    INWHO, DIP, NODEP, SU},
	{PM_GET_PM_STATE, "PM_GET_PM_STATE", 1, NOSTRUCT},
	{PM_GET_AUTOS3_STATE, "PM_GET_AUTOS3_STATE", 1, NOSTRUCT},
	{PM_GET_S3_SUPPORT_STATE, "PM_GET_S3_SUPPORT_STATE", 1, NOSTRUCT},
	{PM_GET_DEVICE_TYPE, "PM_GET_DEVICE_TYPE", 1, PM_REQ, INWHO,
	    DIP, NODEP},
	{PM_SET_COMPONENT_THRESHOLDS, "PM_SET_COMPONENT_THRESHOLDS", 1, PM_REQ,
	    INWHO | INDATAINT, NODIP, NODEP, SU},
	{PM_GET_COMPONENT_THRESHOLDS, "PM_GET_COMPONENT_THRESHOLDS", 1, PM_REQ,
	    INWHO | INDATAOUT, DIP, NODEP},
	{PM_IDLE_DOWN, "PM_IDLE_DOWN", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_GET_DEVICE_THRESHOLD_BASIS, "PM_GET_DEVICE_THRESHOLD_BASIS", 1,
	    PM_REQ, INWHO, DIP, NODEP},
	{PM_SET_CURRENT_POWER, "PM_SET_CURRENT_POWER", 1, PM_REQ, INWHO, DIP,
	    NODEP},
	{PM_GET_CURRENT_POWER, "PM_GET_CURRENT_POWER", 1, PM_REQ, INWHO, DIP,
	    NODEP},
	{PM_GET_FULL_POWER, "PM_GET_FULL_POWER", 1, PM_REQ, INWHO, DIP,
	    NODEP},
	{PM_ADD_DEPENDENT, "PM_ADD_DEPENDENT", 1, PM_REQ, INWHO | INDATASTRING,
	    DIP, DEP, SU},
	{PM_GET_TIME_IDLE, "PM_GET_TIME_IDLE", 1, PM_REQ, INWHO, DIP, NODEP},
	{PM_ADD_DEPENDENT_PROPERTY, "PM_ADD_DEPENDENT_PROPERTY", 1, PM_REQ,
	    INWHO | INDATASTRING, NODIP, DEP, SU},
	{PM_START_CPUPM, "PM_START_CPUPM", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_START_CPUPM_EV, "PM_START_CPUPM_EV", 1, NOSTRUCT, 0,
	    0, 0, SU},
	{PM_START_CPUPM_POLL, "PM_START_CPUPM_POLL", 1, NOSTRUCT, 0,
	    0, 0, SU},
	{PM_STOP_CPUPM, "PM_STOP_CPUPM", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_GET_CPU_THRESHOLD, "PM_GET_CPU_THRESHOLD", 1, NOSTRUCT},
	{PM_SET_CPU_THRESHOLD, "PM_SET_CPU_THRESHOLD", 1, NOSTRUCT,
	    0, 0, 0, SU},
	{PM_GET_CPUPM_STATE, "PM_GET_CPUPM_STATE", 1, NOSTRUCT},
	{PM_START_AUTOS3, "PM_START_AUTOS3", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_STOP_AUTOS3, "PM_STOP_AUTOS3", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_ENABLE_S3, "PM_ENABLE_S3", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_DISABLE_S3, "PM_DISABLE_S3", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_ENTER_S3, "PM_ENTER_S3", 1, NOSTRUCT, 0, 0, 0, SU},
	{PM_SEARCH_LIST, "PM_SEARCH_LIST", 1, PM_SRCH, 0, 0, 0, SU},
	{PM_GET_CMD_NAME, "PM_GET_CMD_NAME", 1, PM_REQ, INDATAOUT, NODIP,
	    NODEP, 0},
	{PM_DISABLE_CPU_DEEP_IDLE, "PM_DISABLE_CPU_DEEP_IDLE", 1, NOSTRUCT, 0,
	    0, 0, SU},
	{PM_ENABLE_CPU_DEEP_IDLE, "PM_START_CPU_DEEP_IDLE", 1, NOSTRUCT, 0,
	    0, 0, SU},
	{PM_DEFAULT_CPU_DEEP_IDLE, "PM_DFLT_CPU_DEEP_IDLE", 1, NOSTRUCT, 0,
	    0, 0, SU},
	{0, NULL}
};

struct pm_cmd_info *
pc_info(int cmd)
{
	struct pm_cmd_info *pcip;

	for (pcip = pmci; pcip->name; pcip++) {
		if (cmd == pcip->cmd)
			return (pcip);
	}
	return (NULL);
}

static char *
pm_decode_cmd(int cmd)
{
	static char invbuf[64];
	struct pm_cmd_info *pcip = pc_info(cmd);
	if (pcip != NULL)
		return (pcip->name);
	(void) sprintf(invbuf, "ioctl: invalid command %d\n", cmd);
	return (invbuf);
}

/*
 * Allocate scan resource, create taskq, then dispatch scan,
 * called only if autopm is enabled.
 */
int
pm_start_pm_walk(dev_info_t *dip, void *arg)
{
	int cmd = *((int *)arg);
#ifdef PMDDEBUG
	char *cmdstr = pm_decode_cmd(cmd);
#endif

	if (!PM_GET_PM_INFO(dip) || PM_ISBC(dip))
		return (DDI_WALK_CONTINUE);

	switch (cmd) {
	case PM_START_CPUPM:
	case PM_START_CPUPM_POLL:
		if (!PM_ISCPU(dip))
			return (DDI_WALK_CONTINUE);
		mutex_enter(&pm_scan_lock);
		if (!PM_CPUPM_DISABLED && !PM_EVENT_CPUPM)
			pm_scan_init(dip);
		mutex_exit(&pm_scan_lock);
		break;
	case PM_START_PM:
		mutex_enter(&pm_scan_lock);
		if (PM_ISCPU(dip) && (PM_CPUPM_DISABLED || PM_EVENT_CPUPM)) {
			mutex_exit(&pm_scan_lock);
			return (DDI_WALK_CONTINUE);
		}
		if (autopm_enabled)
			pm_scan_init(dip);
		mutex_exit(&pm_scan_lock);
		break;
	}

	/*
	 * Start doing pm on device: ensure pm_scan data structure initiated,
	 * no need to guarantee a successful scan run.
	 */
	PMD(PMD_SCAN | PMD_IOCTL, ("ioctl: %s: scan %s@%s(%s#%d)\n", cmdstr,
	    PM_DEVICE(dip)))
	pm_rescan(dip);

	return (DDI_WALK_CONTINUE);
}

/*
 * Bring devices to full power level, then stop scan
 */
int
pm_stop_pm_walk(dev_info_t *dip, void *arg)
{
	pm_info_t *info = PM_GET_PM_INFO(dip);
	int cmd = *((int *)arg);
#ifdef PMDDEBUG
	char *cmdstr = pm_decode_cmd(cmd);
#endif

	if (!info)
		return (DDI_WALK_CONTINUE);

	switch (cmd) {
	case PM_STOP_PM:
		/*
		 * If CPU devices are being managed independently, then don't
		 * stop them as part of PM_STOP_PM. Only stop them as part of
		 * PM_STOP_CPUPM and PM_RESET_PM.
		 */
		if (PM_ISCPU(dip) && PM_POLLING_CPUPM)
			return (DDI_WALK_CONTINUE);
		break;
	case PM_STOP_CPUPM:
		/*
		 * If stopping CPU devices and this device is not marked
		 * as a CPU device, then skip.
		 */
		if (!PM_ISCPU(dip))
			return (DDI_WALK_CONTINUE);
		break;
	}

	/*
	 * Stop the current scan, and then bring it back to normal power.
	 */
	if (!PM_ISBC(dip)) {
		PMD(PMD_SCAN | PMD_IOCTL, ("ioctl: %s: stop scan for "
		    "%s@%s(%s#%d)\n", cmdstr, PM_DEVICE(dip)))
		pm_scan_stop(dip);
	}

	if (!PM_ISBC(dip) && !PM_ISDIRECT(dip) &&
	    !pm_all_at_normal(dip)) {
		PM_LOCK_DIP(dip);
		if (info->pmi_dev_pm_state & PM_DETACHING) {
			PMD(PMD_ALLNORM, ("ioctl: %s: deferring "
			    "all_to_normal because %s@%s(%s#%d) is detaching\n",
			    cmdstr, PM_DEVICE(dip)))
			info->pmi_dev_pm_state |= PM_ALLNORM_DEFERRED;
			PM_UNLOCK_DIP(dip);
			return (DDI_WALK_CONTINUE);
		}
		PM_UNLOCK_DIP(dip);
		if (pm_all_to_normal(dip, PM_CANBLOCK_FAIL) != DDI_SUCCESS) {
			PMD(PMD_ERROR, ("ioctl: %s: could not bring %s@%s"
			    "(%s#%d) to normal\n", cmdstr, PM_DEVICE(dip)))
		}
	}

	return (DDI_WALK_CONTINUE);
}

static int
pm_start_idledown(dev_info_t *dip, void *arg)
{
	int		flag = (int)(intptr_t)arg;
	pm_scan_t	*scanp = PM_GET_PM_SCAN(dip);

	if (!scanp)
		return (DDI_WALK_CONTINUE);

	PM_LOCK_DIP(dip);
	scanp->ps_idle_down |= flag;
	PM_UNLOCK_DIP(dip);
	pm_rescan(dip);

	return (DDI_WALK_CONTINUE);
}

/*ARGSUSED*/
static int
pm_end_idledown(dev_info_t *dip, void *ignore)
{
	pm_scan_t	*scanp = PM_GET_PM_SCAN(dip);

	if (!scanp)
		return (DDI_WALK_CONTINUE);

	PM_LOCK_DIP(dip);
	/*
	 * The PMID_TIMERS bits are place holder till idledown expires.
	 * The bits are also the base for regenerating PMID_SCANS bits.
	 * While it's up to scan thread to clear up the PMID_SCANS bits
	 * after each scan run, PMID_TIMERS ensure aggressive scan down
	 * performance throughout the idledown period.
	 */
	scanp->ps_idle_down &= ~PMID_TIMERS;
	PM_UNLOCK_DIP(dip);

	return (DDI_WALK_CONTINUE);
}

/*ARGSUSED*/
static void
pm_end_idledown_walk(void *ignore)
{
	PMD(PMD_IDLEDOWN, ("ioctl: end_idledown: idledown_id(%lx) timer is "
	    "off\n", (ulong_t)pmstp->pm_idledown_id));

	mutex_enter(&pm_scan_lock);
	pmstp->pm_idledown_id = 0;
	mutex_exit(&pm_scan_lock);

	ddi_walk_devs(ddi_root_node(), pm_end_idledown, NULL);
}

/*
 * pm_timeout_idledown - keep idledown effect for 10 seconds.
 *
 * Return 0 if another competing caller scheduled idledown timeout,
 * otherwise, return idledown timeout_id.
 */
static timeout_id_t
pm_timeout_idledown(void)
{
	timeout_id_t	to_id;

	/*
	 * Keep idle-down in effect for either 10 seconds
	 * or length of a scan interval, which ever is greater.
	 */
	mutex_enter(&pm_scan_lock);
	if (pmstp->pm_idledown_id != 0) {
		to_id = pmstp->pm_idledown_id;
		pmstp->pm_idledown_id = 0;
		mutex_exit(&pm_scan_lock);
		(void) untimeout(to_id);
		mutex_enter(&pm_scan_lock);
		if (pmstp->pm_idledown_id != 0) {
			PMD(PMD_IDLEDOWN, ("ioctl: timeout_idledown: "
			    "another caller got it, idledown_id(%lx)!\n",
			    (ulong_t)pmstp->pm_idledown_id))
			mutex_exit(&pm_scan_lock);
			return (0);
		}
	}
	pmstp->pm_idledown_id = timeout(pm_end_idledown_walk, NULL,
	    PM_IDLEDOWN_TIME * hz);
	PMD(PMD_IDLEDOWN, ("ioctl: timeout_idledown: idledown_id(%lx)\n",
	    (ulong_t)pmstp->pm_idledown_id))
	mutex_exit(&pm_scan_lock);

	return (pmstp->pm_idledown_id);
}

static int
pm_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	extern struct pollhead pm_pollhead;	/* common/os/sunpm.c */
	int	clone;

	clone = PM_MINOR_TO_CLONE(getminor(dev));
	PMD(PMD_IOCTL, ("ioctl: pm_chpoll: clone %d\n", clone))
	if ((events & (POLLIN | POLLRDNORM)) && pm_poll_cnt[clone]) {
		*reventsp |= (POLLIN | POLLRDNORM);
		PMD(PMD_IOCTL, ("ioctl: pm_chpoll: reventsp set\n"))
	} else {
		*reventsp = 0;
		if (!anyyet) {
			PMD(PMD_IOCTL, ("ioctl: pm_chpoll: not anyyet\n"))
			*phpp = &pm_pollhead;
		}
#ifdef DEBUG
		else {
			PMD(PMD_IOCTL, ("ioctl: pm_chpoll: anyyet\n"))
		}
#endif
	}
	return (0);
}

/*
 * called by pm_dicard_entries to free up the memory. It also decrements
 * pm_poll_cnt, if direct is non zero.
 */
static void
pm_free_entries(psce_t *pscep, int clone, int direct)
{
	pm_state_change_t	*p;

	if (pscep) {
		p = pscep->psce_out;
		while (p->size) {
			if (direct) {
				PMD(PMD_IOCTL, ("ioctl: discard: "
				    "pm_poll_cnt[%d] is %d before "
				    "ASSERT\n", clone,
				    pm_poll_cnt[clone]))
				ASSERT(pm_poll_cnt[clone]);
				pm_poll_cnt[clone]--;
			}
			kmem_free(p->physpath, p->size);
			p->size = 0;
			if (p == pscep->psce_last)
				p = pscep->psce_first;
			else
				p++;
		}
		pscep->psce_out = pscep->psce_first;
		pscep->psce_in = pscep->psce_first;
		mutex_exit(&pscep->psce_lock);
	}
}

/*
 * Discard entries for this clone. Calls pm_free_entries to free up memory.
 */
static void
pm_discard_entries(int clone)
{
	psce_t	*pscep;
	int			direct = 0;

	mutex_enter(&pm_clone_lock);
	if ((pscep = pm_psc_clone_to_direct(clone)) != NULL)
		direct = 1;
	pm_free_entries(pscep, clone, direct);
	pscep = pm_psc_clone_to_interest(clone);
	pm_free_entries(pscep, clone, 0);
	mutex_exit(&pm_clone_lock);
}


static void
pm_set_idle_threshold(dev_info_t *dip, int thresh, int flag)
{
	if (!PM_ISBC(dip) && !PM_ISDIRECT(dip)) {
		switch (DEVI(dip)->devi_pm_flags & PMC_THRESH_ALL) {
		case PMC_DEF_THRESH:
		case PMC_CPU_THRESH:
			PMD(PMD_IOCTL, ("ioctl: set_idle_threshold: set "
			    "%s@%s(%s#%d) default thresh to 0t%d\n",
			    PM_DEVICE(dip), thresh))
			pm_set_device_threshold(dip, thresh, flag);
			break;
		default:
			break;
		}
	}
}

static int
pm_set_idle_thresh_walk(dev_info_t *dip, void *arg)
{
	int cmd = *((int *)arg);

	if (!PM_GET_PM_INFO(dip))
		return (DDI_WALK_CONTINUE);

	switch (cmd) {
	case PM_SET_SYSTEM_THRESHOLD:
		if (DEVI(dip)->devi_pm_flags & PMC_CPU_THRESH)
			break;
		pm_set_idle_threshold(dip, pm_system_idle_threshold,
		    PMC_DEF_THRESH);
		pm_rescan(dip);
		break;
	case PM_SET_CPU_THRESHOLD:
		if (!PM_ISCPU(dip))
			break;
		pm_set_idle_threshold(dip, pm_cpu_idle_threshold,
		    PMC_CPU_THRESH);
		pm_rescan(dip);
		break;
	}

	return (DDI_WALK_CONTINUE);
}

/*ARGSUSED*/
static int
pm_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (pmstp->pm_instance == -1)
			return (DDI_FAILURE);
		*result = pmstp->pm_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = getminor(dev) >> 8;
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/*ARGSUSED1*/
static int
pm_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	int		clone;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	mutex_enter(&pm_clone_lock);
	for (clone = 1; clone < PM_MAX_CLONE; clone++)
		if (!pmstp->pm_clones[clone])
			break;

	if (clone == PM_MAX_CLONE) {
		mutex_exit(&pm_clone_lock);
		return (ENXIO);
	}
	pmstp->pm_cred[clone] = cr;
	crhold(cr);

	*devp = makedevice(getmajor(*devp), (pmstp->pm_instance << 8) + clone);
	pmstp->pm_clones[clone] = 1;
	mutex_exit(&pm_clone_lock);

	return (0);
}

/*ARGSUSED1*/
static int
pm_close(dev_t dev, int flag, int otyp, cred_t *cr)
{
	int clone;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	clone = PM_MINOR_TO_CLONE(getminor(dev));
	PMD(PMD_CLOSE, ("pm_close: minor %x, clone %x\n", getminor(dev),
	    clone))

	/*
	 * Walk the entire device tree to find the corresponding
	 * device and operate on it.
	 */
	ddi_walk_devs(ddi_root_node(), pm_close_direct_pm_device,
	    (void *) &clone);

	crfree(pmstp->pm_cred[clone]);
	pmstp->pm_cred[clone] = 0;
	pmstp->pm_clones[clone] = 0;
	pm_discard_entries(clone);
	ASSERT(pm_poll_cnt[clone] == 0);
	pm_deregister_watcher(clone, NULL);
	return (0);
}

/*ARGSUSED*/
static int
pm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr, int *rval_p)
{
	struct pm_cmd_info *pc_info(int);
	struct pm_cmd_info *pcip = pc_info(cmd);
	pm_req_t	req;
	dev_info_t	*dip = NULL;
	pm_info_t	*info = NULL;
	int		clone;
	char		*cmdstr = pm_decode_cmd(cmd);
	/*
	 * To keep devinfo nodes from going away while we're holding a
	 * pointer to their dip, pm_name_to_dip() optionally holds
	 * the devinfo node.  If we've done that, we set dipheld
	 * so we know at the end of the ioctl processing to release the
	 * node again.
	 */
	int		dipheld = 0;
	int		icount = 0;
	int		i;
	int		comps;
	size_t		lencopied;
	int		ret = ENOTTY;
	int		curpower;
	char		who[MAXNAMELEN];
	size_t		wholen;			/* copyinstr length */
	size_t		deplen = MAXNAMELEN;
	char		*dep, i_dep_buf[MAXNAMELEN];
	char		pathbuf[MAXNAMELEN];
	struct pm_component *cp;
#ifdef	_MULTI_DATAMODEL
	pm_state_change32_t		*pscp32;
	pm_state_change32_t		psc32;
	pm_searchargs32_t		psa32;
	size_t				copysize32;
#endif
	pm_state_change_t		*pscp;
	pm_state_change_t		psc;
	pm_searchargs_t		psa;
	char		listname[MAXCOPYBUF];
	char		manufacturer[MAXCOPYBUF];
	char		product[MAXCOPYBUF];
	size_t		copysize;

	PMD(PMD_IOCTL, ("ioctl: %s: begin\n", cmdstr))

#ifdef DEBUG
	if (cmd == 666) {
		ddi_walk_devs(ddi_root_node(), print_info, NULL);
		return (0);
	}
	ret = 0x0badcafe;			/* sanity checking */
	pm_cmd = cmd;				/* for ASSERT debugging */
	pm_cmd_string = cmdstr;	/* for ASSERT debugging */
#endif


	if (pcip == NULL) {
		PMD(PMD_ERROR, ("ioctl: unknown command %d\n", cmd))
		return (ENOTTY);
	}
	if (pcip == NULL || pcip->supported == 0) {
		PMD(PMD_ERROR, ("ioctl: command %s no longer supported\n",
		    pcip->name))
		return (ENOTTY);
	}

	wholen = 0;
	dep = i_dep_buf;
	i_dep_buf[0] = 0;
	clone = PM_MINOR_TO_CLONE(getminor(dev));
	if (!pm_perms(pcip->permission, pmstp->pm_cred[clone])) {
		ret = EPERM;
		return (ret);
	}
	switch (pcip->str_type) {
	case PM_REQ:
	{
#ifdef	_MULTI_DATAMODEL
		if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
			pm_req32_t	req32;

			if (ddi_copyin((caddr_t)arg, &req32,
			    sizeof (req32), mode) != 0) {
				PMD(PMD_ERROR, ("ioctl: %s: ddi_copyin "
				    "EFAULT\n\n", cmdstr))
				ret = EFAULT;
				break;
			}
			req.component = req32.component;
			req.value = req32.value;
			req.datasize = req32.datasize;
			if (pcip->inargs & INWHO) {
				ret = copyinstr((char *)(uintptr_t)
				    req32.physpath, who, MAXNAMELEN, &wholen);
				if (ret) {
					PMD(PMD_ERROR, ("ioctl: %s: "
					    "copyinstr fails returning %d\n",
					    cmdstr, ret))
					break;
				}
				req.physpath = who;
				PMD(PMD_IOCTL, ("ioctl: %s: physpath=%s\n",
				    cmdstr, req.physpath))
			}
			if (pcip->inargs & INDATA) {
				req.data = (void *)(uintptr_t)req32.data;
				req.datasize = req32.datasize;
			} else {
				req.data = NULL;
				req.datasize = 0;
			}
			switch (pcip->diptype) {
			case DIP:
				if (!(dip =
				    pm_name_to_dip(req.physpath, 1))) {
					PMD(PMD_ERROR, ("ioctl: %s: "
					    "pm_name_to_dip for %s failed\n",
					    cmdstr, req.physpath))
					return (ENODEV);
				}
				ASSERT(!dipheld);
				dipheld++;
				break;
			case NODIP:
				break;
			default:
				/*
				 * Internal error, invalid ioctl description
				 * force debug entry even if pm_debug not set
				 */
#ifdef	DEBUG
				pm_log("invalid diptype %d for cmd %d (%s)\n",
				    pcip->diptype, cmd, pcip->name);
#endif
				ASSERT(0);
				return (EIO);
			}
			if (pcip->inargs & INDATAINT) {
				int32_t int32buf;
				int32_t *i32p;
				int *ip;
				icount = req32.datasize / sizeof (int32_t);
				if (icount <= 0) {
					PMD(PMD_ERROR, ("ioctl: %s: datasize"
					    " 0 or neg EFAULT\n\n", cmdstr))
					ret = EFAULT;
					break;
				}
				ASSERT(!(pcip->inargs & INDATASTRING));
				req.datasize = icount * sizeof (int);
				req.data = kmem_alloc(req.datasize, KM_SLEEP);
				ip = req.data;
				ret = 0;
				for (i = 0,
				    i32p = (int32_t *)(uintptr_t)req32.data;
				    i < icount; i++, i32p++) {
					if (ddi_copyin((void *)i32p, &int32buf,
					    sizeof (int32_t), mode)) {
						kmem_free(req.data,
						    req.datasize);
						PMD(PMD_ERROR, ("ioctl: %s: "
						    "entry %d EFAULT\n",
						    cmdstr, i))
						ret = EFAULT;
						break;
					}
					*ip++ = (int)int32buf;
				}
				if (ret)
					break;
			}
			if (pcip->inargs & INDATASTRING) {
				ASSERT(!(pcip->inargs & INDATAINT));
				ASSERT(pcip->deptype == DEP);
				if (req32.data != 0) {
					if (copyinstr((void *)(uintptr_t)
					    req32.data, dep, deplen, NULL)) {
						PMD(PMD_ERROR, ("ioctl: %s: "
						    "0x%p dep size %lx, EFAULT"
						    "\n", cmdstr,
						    (void *)req.data, deplen))
						ret = EFAULT;
						break;
					}
#ifdef DEBUG
					else {
						PMD(PMD_DEP, ("ioctl: %s: "
						    "dep %s\n", cmdstr, dep))
					}
#endif
				} else {
					PMD(PMD_ERROR, ("ioctl: %s: no "
					    "dependent\n", cmdstr))
					ret = EINVAL;
					break;
				}
			}
		} else
#endif /* _MULTI_DATAMODEL */
		{
			if (ddi_copyin((caddr_t)arg,
			    &req, sizeof (req), mode) != 0) {
				PMD(PMD_ERROR, ("ioctl: %s: ddi_copyin "
				    "EFAULT\n\n", cmdstr))
				ret = EFAULT;
				break;
			}
			if (pcip->inargs & INWHO) {
				ret = copyinstr((char *)req.physpath, who,
				    MAXNAMELEN, &wholen);
				if (ret) {
					PMD(PMD_ERROR, ("ioctl: %s copyinstr"
					    " fails returning %d\n", cmdstr,
					    ret))
					break;
				}
				req.physpath = who;
				PMD(PMD_IOCTL, ("ioctl: %s: physpath=%s\n",
				    cmdstr, req.physpath))
			}
			if (!(pcip->inargs & INDATA)) {
				req.data = NULL;
				req.datasize = 0;
			}
			switch (pcip->diptype) {
			case DIP:
				if (!(dip =
				    pm_name_to_dip(req.physpath, 1))) {
					PMD(PMD_ERROR, ("ioctl: %s: "
					    "pm_name_to_dip for %s failed\n",
					    cmdstr, req.physpath))
					return (ENODEV);
				}
				ASSERT(!dipheld);
				dipheld++;
				break;
			case NODIP:
				break;
			default:
				/*
				 * Internal error, invalid ioctl description
				 * force debug entry even if pm_debug not set
				 */
#ifdef	DEBUG
				pm_log("invalid diptype %d for cmd %d (%s)\n",
				    pcip->diptype, cmd, pcip->name);
#endif
				ASSERT(0);
				return (EIO);
			}
			if (pcip->inargs & INDATAINT) {
				int *ip;

				ASSERT(!(pcip->inargs & INDATASTRING));
				ip = req.data;
				icount = req.datasize / sizeof (int);
				if (icount <= 0) {
					PMD(PMD_ERROR, ("ioctl: %s: datasize"
					    " 0 or neg EFAULT\n\n", cmdstr))
					ret = EFAULT;
					break;
				}
				req.data = kmem_alloc(req.datasize, KM_SLEEP);
				if (ddi_copyin((caddr_t)ip, req.data,
				    req.datasize, mode) != 0) {
					PMD(PMD_ERROR, ("ioctl: %s: ddi_copyin "
					    "EFAULT\n\n", cmdstr))
					ret = EFAULT;
					break;
				}
			}
			if (pcip->inargs & INDATASTRING) {
				ASSERT(!(pcip->inargs & INDATAINT));
				ASSERT(pcip->deptype == DEP);
				if (req.data != NULL) {
					if (copyinstr((caddr_t)req.data,
					    dep, deplen, NULL)) {
						PMD(PMD_ERROR, ("ioctl: %s: "
						    "0x%p dep size %lu, "
						    "EFAULT\n", cmdstr,
						    (void *)req.data, deplen))
						ret = EFAULT;
						break;
					}
#ifdef DEBUG
					else {
						PMD(PMD_DEP, ("ioctl: %s: "
						    "dep %s\n", cmdstr, dep))
					}
#endif
				} else {
					PMD(PMD_ERROR, ("ioctl: %s: no "
					    "dependent\n", cmdstr))
					ret = EINVAL;
					break;
				}
			}
		}
		/*
		 * Now we've got all the args in for the commands that
		 * use the new pm_req struct.
		 */
		switch (cmd) {
		case PM_REPARSE_PM_PROPS:
		{
			struct dev_ops	*drv;
			struct cb_ops	*cb;
			void		*propval;
			int length;
			/*
			 * This ioctl is provided only for the ddivs pm test.
			 * We only do it to a driver which explicitly allows
			 * us to do so by exporting a pm-reparse-ok property.
			 * We only care whether the property exists or not.
			 */
			if ((drv = ddi_get_driver(dip)) == NULL) {
				ret = EINVAL;
				break;
			}
			if ((cb = drv->devo_cb_ops) != NULL) {
				if ((*cb->cb_prop_op)(DDI_DEV_T_ANY, dip,
				    PROP_LEN_AND_VAL_ALLOC, (DDI_PROP_CANSLEEP |
				    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
				    "pm-reparse-ok", (caddr_t)&propval,
				    &length) != DDI_SUCCESS) {
					ret = EINVAL;
					break;
				}
			} else if (ddi_prop_op(DDI_DEV_T_ANY, dip,
			    PROP_LEN_AND_VAL_ALLOC, (DDI_PROP_CANSLEEP |
			    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			    "pm-reparse-ok", (caddr_t)&propval,
			    &length) != DDI_SUCCESS) {
				ret = EINVAL;
				break;
			}
			kmem_free(propval, length);
			ret =  e_new_pm_props(dip);
			break;
		}

		case PM_GET_DEVICE_THRESHOLD:
		{
			PM_LOCK_DIP(dip);
			if (!PM_GET_PM_INFO(dip) || PM_ISBC(dip)) {
				PM_UNLOCK_DIP(dip);
				PMD(PMD_ERROR, ("ioctl: %s: ENODEV\n",
				    cmdstr))
				ret = ENODEV;
				break;
			}
			*rval_p = DEVI(dip)->devi_pm_dev_thresh;
			PM_UNLOCK_DIP(dip);
			ret = 0;
			break;
		}

		case PM_DIRECT_PM:
		{
			int has_dep;
			if ((info = PM_GET_PM_INFO(dip)) == NULL) {
				PMD(PMD_ERROR | PMD_DPM, ("ioctl: %s: "
				    "ENODEV\n", cmdstr))
				ret = ENODEV;
				break;
			}
			/*
			 * Check to see if we are there is a dependency on
			 * this kept device, if so, return EBUSY.
			 */
			(void) ddi_pathname(dip, pathbuf);
			pm_dispatch_to_dep_thread(PM_DEP_WK_CHECK_KEPT,
			    NULL, pathbuf, PM_DEP_WAIT, &has_dep, 0);
			if (has_dep) {
				PMD(PMD_ERROR | PMD_DPM, ("%s EBUSY\n",
				    cmdstr))
				ret = EBUSY;
				break;
			}
			PM_LOCK_DIP(dip);
			if (PM_ISDIRECT(dip) || (info->pmi_clone != 0)) {
				PMD(PMD_ERROR | PMD_DPM, ("ioctl: %s: "
				    "%s@%s(%s#%d): EBUSY\n", cmdstr,
				    PM_DEVICE(dip)))
				PM_UNLOCK_DIP(dip);
				ret = EBUSY;
				break;
			}
			info->pmi_dev_pm_state |= PM_DIRECT;
			info->pmi_clone = clone;
			PM_UNLOCK_DIP(dip);
			PMD(PMD_DPM, ("ioctl: %s: info %p, pmi_clone %d\n",
			    cmdstr, (void *)info, clone))
			mutex_enter(&pm_clone_lock);
			pm_register_watcher(clone, dip);
			mutex_exit(&pm_clone_lock);
			ret = 0;
			break;
		}

		case PM_RELEASE_DIRECT_PM:
		{
			if ((info = PM_GET_PM_INFO(dip)) == NULL) {
				PMD(PMD_ERROR | PMD_DPM, ("ioctl: %s: "
				    "ENODEV\n", cmdstr))
				ret = ENODEV;
				break;
			}
			PM_LOCK_DIP(dip);
			if (info->pmi_clone != clone) {
				PMD(PMD_ERROR | PMD_DPM, ("ioctl: %s: "
				    "%s@%s(%s#%d) EINVAL\n", cmdstr,
				    PM_DEVICE(dip)))
				ret = EINVAL;
				PM_UNLOCK_DIP(dip);
				break;
			}
			ASSERT(PM_ISDIRECT(dip));
			info->pmi_dev_pm_state &= ~PM_DIRECT;
			PM_UNLOCK_DIP(dip);
			/* Bring ourselves up if there is a keeper. */
			(void) ddi_pathname(dip, pathbuf);
			pm_dispatch_to_dep_thread(PM_DEP_WK_BRINGUP_SELF,
			    NULL, pathbuf, PM_DEP_WAIT, NULL, 0);
			pm_discard_entries(clone);
			pm_deregister_watcher(clone, dip);
			/*
			 * Now we could let the other threads that are
			 * trying to do a DIRECT_PM thru
			 */
			PM_LOCK_DIP(dip);
			info->pmi_clone = 0;
			PM_UNLOCK_DIP(dip);
			pm_proceed(dip, PMP_RELEASE, -1, -1);
			PMD(PMD_RESCAN | PMD_DPM, ("ioctl: %s: rescan\n",
			    cmdstr))
			pm_rescan(dip);
			ret = 0;
			break;
		}

		case PM_SET_CURRENT_POWER:
		{
			int comp = req.component;
			int  value = req.value;
			PMD(PMD_DPM, ("ioctl: %s: %s component %d to value "
			    "%d\n", cmdstr, req.physpath, comp, value))
			if (!e_pm_valid_comp(dip, comp, NULL) ||
			    !e_pm_valid_power(dip, comp, value)) {
				PMD(PMD_ERROR | PMD_DPM, ("ioctl: %s: "
				    "physpath=%s, comp=%d, level=%d, fails\n",
				    cmdstr, req.physpath, comp, value))
				ret = EINVAL;
				break;
			}

			if ((info = PM_GET_PM_INFO(dip)) == NULL) {
				PMD(PMD_ERROR | PMD_DPM, ("ioctl: %s: "
				    "ENODEV\n", cmdstr))
				ret = ENODEV;
				break;
			}
			if (info->pmi_clone != clone) {
				PMD(PMD_ERROR | PMD_DPM, ("ioctl: %s: "
				    "(not owner) %s fails; clone %d, owner %d"
				    "\n", cmdstr, req.physpath, clone,
				    info->pmi_clone))
				ret = EINVAL;
				break;
			}
			ASSERT(PM_ISDIRECT(dip));

			if (pm_set_power(dip, comp, value, PM_LEVEL_EXACT,
			    PM_CANBLOCK_BLOCK, 0, &ret) != DDI_SUCCESS) {
				PMD(PMD_ERROR | PMD_DPM, ("ioctl: %s: "
				    "pm_set_power for %s fails, errno=%d\n",
				    cmdstr, req.physpath, ret))
				break;
			}

			pm_proceed(dip, PMP_SETPOWER, comp, value);

			/*
			 * Power down all idle components if console framebuffer
			 * is powered off.
			 */
			if (PM_IS_CFB(dip) && (pm_system_idle_threshold ==
			    pm_default_idle_threshold)) {
				dev_info_t	*root = ddi_root_node();
				if (PM_ISBC(dip)) {
					if (comp == 0 && value == 0 &&
					    (pm_timeout_idledown() != 0)) {
						ddi_walk_devs(root,
						    pm_start_idledown,
						    (void *)PMID_CFB);
					}
				} else {
					int count = 0;
					for (i = 0; i < PM_NUMCMPTS(dip); i++) {
						ret = pm_get_current_power(dip,
						    i, &curpower);
						if (ret == DDI_SUCCESS &&
						    curpower == 0)
							count++;
					}
					if ((count == PM_NUMCMPTS(dip)) &&
					    (pm_timeout_idledown() != 0)) {
						ddi_walk_devs(root,
						    pm_start_idledown,
						    (void *)PMID_CFB);
					}
				}
			}

			PMD(PMD_RESCAN | PMD_DPM, ("ioctl: %s: rescan\n",
			    cmdstr))
			pm_rescan(dip);
			*rval_p = 0;
			ret = 0;
			break;
		}

		case PM_GET_FULL_POWER:
		{
			int normal;
			ASSERT(dip);
			PMD(PMD_NORM, ("ioctl: %s: %s component %d\n",
			    cmdstr, req.physpath, req.component))
			normal =  pm_get_normal_power(dip, req.component);

			if (normal == DDI_FAILURE) {
				PMD(PMD_ERROR | PMD_NORM, ("ioctl: %s: "
				    "returns EINVAL\n", cmdstr))
				ret = EINVAL;
				break;
			}
			*rval_p = normal;
			PMD(PMD_NORM, ("ioctl: %s: returns %d\n",
			    cmdstr, normal))
			ret = 0;
			break;
		}

		case PM_GET_CURRENT_POWER:
		{
			if (pm_get_current_power(dip, req.component,
			    rval_p) != DDI_SUCCESS) {
				PMD(PMD_ERROR | PMD_DPM, ("ioctl: %s "
				    "EINVAL\n", cmdstr))
				ret = EINVAL;
				break;
			}
			PMD(PMD_DPM, ("ioctl: %s: %s comp %d returns %d\n",
			    cmdstr, req.physpath, req.component, *rval_p))
			if (*rval_p == PM_LEVEL_UNKNOWN)
				ret = EAGAIN;
			else
				ret = 0;
			break;
		}

		case PM_GET_TIME_IDLE:
		{
			time_t timestamp;
			int comp = req.component;
			pm_component_t *cp;
			if (!e_pm_valid_comp(dip, comp, &cp)) {
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "component %d > numcmpts - 1 %d--EINVAL\n",
				    cmdstr, PM_DEVICE(dip), comp,
				    PM_NUMCMPTS(dip) - 1))
				ret = EINVAL;
				break;
			}
			timestamp = cp->pmc_timestamp;
			if (timestamp) {
				time_t now;
				(void) drv_getparm(TIME, &now);
				*rval_p = (now - timestamp);
			} else {
				*rval_p = 0;
			}
			ret = 0;
			break;
		}

		case PM_ADD_DEPENDENT:
		{
			dev_info_t	*kept_dip;

			PMD(PMD_KEEPS, ("%s, kept %s, keeper %s\n", cmdstr,
			    dep, req.physpath))

			/*
			 * hold and install kept while processing dependency
			 * keeper (in .physpath) has already been held.
			 */
			if (dep[0] == '\0') {
				PMD(PMD_ERROR, ("kept NULL or null\n"))
				ret = EINVAL;
				break;
			} else if ((kept_dip =
			    pm_name_to_dip(dep, 1)) == NULL) {
				PMD(PMD_ERROR, ("no dip for kept %s\n", dep))
				ret = ENODEV;
				break;
			} else if (kept_dip == dip) {
				PMD(PMD_ERROR, ("keeper(%s, %p) - kept(%s, %p) "
				    "self-dependency not allowed.\n",
				    dep, (void *)kept_dip, req.physpath,
				    (void *) dip))
				PM_RELE(dip);	/* release "double" hold */
				ret = EINVAL;
				break;
			}
			ASSERT(!(strcmp(req.physpath, (char *)dep) == 0));

			/*
			 * record dependency, then walk through device tree
			 * independently on behalf of kept and keeper to
			 * establish newly created dependency.
			 */
			pm_dispatch_to_dep_thread(PM_DEP_WK_RECORD_KEEPER,
			    req.physpath, dep, PM_DEP_WAIT, NULL, 0);

			/*
			 * release kept after establishing dependency, keeper
			 * is released as part of ioctl exit processing.
			 */
			PM_RELE(kept_dip);
			*rval_p = 0;
			ret = 0;
			break;
		}

		case PM_ADD_DEPENDENT_PROPERTY:
		{
			char *keeper, *kept;

			if (dep[0] == '\0') {
				PMD(PMD_ERROR, ("ioctl: %s: dep NULL or "
				    "null\n", cmdstr))
				ret = EINVAL;
				break;
			}
			kept = dep;
			keeper = req.physpath;
			/*
			 * record keeper - kept dependency, then walk through
			 * device tree to find out all attached keeper, walk
			 * through again to apply dependency to all the
			 * potential kept.
			 */
			pm_dispatch_to_dep_thread(
			    PM_DEP_WK_RECORD_KEEPER_PROP, keeper, kept,
			    PM_DEP_WAIT, NULL, 0);

			*rval_p = 0;
			ret = 0;
			break;
		}

		case PM_SET_DEVICE_THRESHOLD:
		{
			pm_thresh_rec_t *rp;
			pm_pte_t *ep;	/* threshold header storage */
			int *tp;	/* threshold storage */
			size_t size;
			extern int pm_thresh_specd(dev_info_t *);

			/*
			 * The header struct plus one entry struct plus one
			 * threshold plus the length of the string
			 */
			size = sizeof (pm_thresh_rec_t) +
			    (sizeof (pm_pte_t) * 1) +
			    (1 * sizeof (int)) +
			    strlen(req.physpath) + 1;

			rp = kmem_zalloc(size, KM_SLEEP);
			rp->ptr_size = size;
			rp->ptr_numcomps = 0;	/* means device threshold */
			ep = (pm_pte_t *)((intptr_t)rp + sizeof (*rp));
			rp->ptr_entries = ep;
			tp = (int *)((intptr_t)ep +
			    (1 * sizeof (pm_pte_t)));
			ep->pte_numthresh = 1;
			ep->pte_thresh = tp;
			*tp++ = req.value;
			(void) strcat((char *)tp, req.physpath);
			rp->ptr_physpath = (char *)tp;
			ASSERT((intptr_t)tp + strlen(req.physpath) + 1 ==
			    (intptr_t)rp + rp->ptr_size);
			PMD(PMD_THRESH, ("ioctl: %s: record thresh %d for "
			    "%s\n", cmdstr, req.value, req.physpath))
			pm_record_thresh(rp);
			/*
			 * Don't free rp, pm_record_thresh() keeps it.
			 * We don't try to apply it ourselves because we'd need
			 * to know too much about locking.  Since we don't
			 * hold a lock the entry could be removed before
			 * we get here
			 */
			ASSERT(dip == NULL);
			ret = 0;		/* can't fail now */
			if (!(dip = pm_name_to_dip(req.physpath, 1))) {
				break;
			}
			(void) pm_thresh_specd(dip);
			PMD(PMD_DHR, ("ioctl: %s: releasing %s@%s(%s#%d)\n",
			    cmdstr, PM_DEVICE(dip)))
			PM_RELE(dip);
			break;
		}

		case PM_RESET_DEVICE_THRESHOLD:
		{
			/*
			 * This only applies to a currently attached and power
			 * managed node
			 */
			/*
			 * We don't do this to old-style drivers
			 */
			info = PM_GET_PM_INFO(dip);
			if (info == NULL) {
				PMD(PMD_ERROR, ("ioctl: %s: %s not power "
				    "managed\n", cmdstr, req.physpath))
				ret = EINVAL;
				break;
			}
			if (PM_ISBC(dip)) {
				PMD(PMD_ERROR, ("ioctl: %s: %s is BC\n",
				    cmdstr, req.physpath))
				ret = EINVAL;
				break;
			}
			pm_unrecord_threshold(req.physpath);
			if (DEVI(dip)->devi_pm_flags & PMC_CPU_THRESH)
				pm_set_device_threshold(dip,
				    pm_cpu_idle_threshold, PMC_CPU_THRESH);
			else
				pm_set_device_threshold(dip,
				    pm_system_idle_threshold, PMC_DEF_THRESH);
			ret = 0;
			break;
		}

		case PM_GET_NUM_COMPONENTS:
		{
			ret = 0;
			*rval_p = PM_NUMCMPTS(dip);
			break;
		}

		case PM_GET_DEVICE_TYPE:
		{
			ret = 0;
			if ((info = PM_GET_PM_INFO(dip)) == NULL) {
				PMD(PMD_ERROR, ("ioctl: %s: "
				    "PM_NO_PM_COMPONENTS\n", cmdstr))
				*rval_p = PM_NO_PM_COMPONENTS;
				break;
			}
			if (PM_ISBC(dip)) {
				*rval_p = PM_CREATE_COMPONENTS;
			} else {
				*rval_p = PM_AUTOPM;
			}
			break;
		}

		case PM_SET_COMPONENT_THRESHOLDS:
		{
			int comps = 0;
			int *end = (int *)req.data + icount;
			pm_thresh_rec_t *rp;
			pm_pte_t *ep;	/* threshold header storage */
			int *tp;	/* threshold storage */
			int *ip;
			int j;
			size_t size;
			extern int pm_thresh_specd(dev_info_t *);
			extern int pm_valid_thresh(dev_info_t *,
			    pm_thresh_rec_t *);

			for (ip = req.data; *ip; ip++) {
				if (ip >= end) {
					ret = EFAULT;
					break;
				}
				comps++;
				/* skip over indicated number of entries */
				for (j = *ip; j; j--) {
					if (++ip >= end) {
						ret = EFAULT;
						break;
					}
				}
				if (ret)
					break;
			}
			if (ret)
				break;
			if ((intptr_t)ip != (intptr_t)end - sizeof (int)) {
				/* did not exactly fill buffer */
				ret = EINVAL;
				break;
			}
			if (comps == 0) {
				PMD(PMD_ERROR, ("ioctl: %s: %s 0 components"
				    "--EINVAL\n", cmdstr, req.physpath))
				ret = EINVAL;
				break;
			}
			/*
			 * The header struct plus one entry struct per component
			 * plus the size of the lists minus the counts
			 * plus the length of the string
			 */
			size = sizeof (pm_thresh_rec_t) +
			    (sizeof (pm_pte_t) * comps) + req.datasize -
			    ((comps + 1) * sizeof (int)) +
			    strlen(req.physpath) + 1;

			rp = kmem_zalloc(size, KM_SLEEP);
			rp->ptr_size = size;
			rp->ptr_numcomps = comps;
			ep = (pm_pte_t *)((intptr_t)rp + sizeof (*rp));
			rp->ptr_entries = ep;
			tp = (int *)((intptr_t)ep +
			    (comps * sizeof (pm_pte_t)));
			for (ip = req.data; *ip; ep++) {
				ep->pte_numthresh = *ip;
				ep->pte_thresh = tp;
				for (j = *ip++; j; j--) {
					*tp++ = *ip++;
				}
			}
			(void) strcat((char *)tp, req.physpath);
			rp->ptr_physpath = (char *)tp;
			ASSERT((intptr_t)end == (intptr_t)ip + sizeof (int));
			ASSERT((intptr_t)tp + strlen(req.physpath) + 1 ==
			    (intptr_t)rp + rp->ptr_size);

			ASSERT(dip == NULL);
			/*
			 * If this is not a currently power managed node,
			 * then we can't check for validity of the thresholds
			 */
			if (!(dip = pm_name_to_dip(req.physpath, 1))) {
				/* don't free rp, pm_record_thresh uses it */
				pm_record_thresh(rp);
				PMD(PMD_ERROR, ("ioctl: %s: pm_name_to_dip "
				    "for %s failed\n", cmdstr, req.physpath))
				ret = 0;
				break;
			}
			ASSERT(!dipheld);
			dipheld++;

			if (!pm_valid_thresh(dip, rp)) {
				PMD(PMD_ERROR, ("ioctl: %s: invalid thresh "
				    "for %s@%s(%s#%d)\n", cmdstr,
				    PM_DEVICE(dip)))
				kmem_free(rp, size);
				ret = EINVAL;
				break;
			}
			/*
			 * We don't just apply it ourselves because we'd need
			 * to know too much about locking.  Since we don't
			 * hold a lock the entry could be removed before
			 * we get here
			 */
			pm_record_thresh(rp);
			(void) pm_thresh_specd(dip);
			ret = 0;
			break;
		}

		case PM_GET_COMPONENT_THRESHOLDS:
		{
			int musthave;
			int numthresholds = 0;
			int wordsize;
			int numcomps;
			caddr_t uaddr = req.data;	/* user address */
			int val;	/* int value to be copied out */
			int32_t val32;	/* int32 value to be copied out */
			caddr_t vaddr;	/* address to copyout from */
			int j;

#ifdef	_MULTI_DATAMODEL
			if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
				wordsize = sizeof (int32_t);
			} else
#endif /* _MULTI_DATAMODEL */
			{
				wordsize = sizeof (int);
			}

			ASSERT(dip);

			numcomps = PM_NUMCMPTS(dip);
			for (i = 0; i < numcomps; i++) {
				cp = PM_CP(dip, i);
				numthresholds += cp->pmc_comp.pmc_numlevels - 1;
			}
			musthave = (numthresholds + numcomps + 1) *  wordsize;
			if (req.datasize < musthave) {
				PMD(PMD_ERROR, ("ioctl: %s: size %ld, need "
				    "%d--EINVAL\n", cmdstr, req.datasize,
				    musthave))
				ret = EINVAL;
				break;
			}
			PM_LOCK_DIP(dip);
			for (i = 0; i < numcomps; i++) {
				int *thp;
				cp = PM_CP(dip, i);
				thp = cp->pmc_comp.pmc_thresh;
				/* first copyout the count */
				if (wordsize == sizeof (int32_t)) {
					val32 = cp->pmc_comp.pmc_numlevels - 1;
					vaddr = (caddr_t)&val32;
				} else {
					val = cp->pmc_comp.pmc_numlevels - 1;
					vaddr = (caddr_t)&val;
				}
				if (ddi_copyout(vaddr, (void *)uaddr,
				    wordsize, mode) != 0) {
					PM_UNLOCK_DIP(dip);
					PMD(PMD_ERROR, ("ioctl: %s: %s@%s"
					    "(%s#%d) vaddr %p EFAULT\n",
					    cmdstr, PM_DEVICE(dip),
					    (void*)vaddr))
					ret = EFAULT;
					break;
				}
				vaddr = uaddr;
				vaddr += wordsize;
				uaddr = (caddr_t)vaddr;
				/* then copyout each threshold value */
				for (j = 0; j < cp->pmc_comp.pmc_numlevels - 1;
				    j++) {
					if (wordsize == sizeof (int32_t)) {
						val32 = thp[j + 1];
						vaddr = (caddr_t)&val32;
					} else {
						val = thp[i + 1];
						vaddr = (caddr_t)&val;
					}
					if (ddi_copyout(vaddr, (void *) uaddr,
					    wordsize, mode) != 0) {
						PM_UNLOCK_DIP(dip);
						PMD(PMD_ERROR, ("ioctl: %s: "
						    "%s@%s(%s#%d) uaddr %p "
						    "EFAULT\n", cmdstr,
						    PM_DEVICE(dip),
						    (void *)uaddr))
						ret = EFAULT;
						break;
					}
					vaddr = uaddr;
					vaddr += wordsize;
					uaddr = (caddr_t)vaddr;
				}
			}
			if (ret)
				break;
			/* last copyout a terminating 0 count */
			if (wordsize == sizeof (int32_t)) {
				val32 = 0;
				vaddr = (caddr_t)&val32;
			} else {
				ASSERT(wordsize == sizeof (int));
				val = 0;
				vaddr = (caddr_t)&val;
			}
			if (ddi_copyout(vaddr, uaddr, wordsize, mode) != 0) {
				PM_UNLOCK_DIP(dip);
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "vaddr %p (0 count) EFAULT\n", cmdstr,
				    PM_DEVICE(dip), (void *)vaddr))
				ret = EFAULT;
				break;
			}
			/* finished, so don't need to increment addresses */
			PM_UNLOCK_DIP(dip);
			ret = 0;
			break;
		}

		case PM_GET_STATS:
		{
			time_t now;
			time_t *timestamp;
			extern int pm_cur_power(pm_component_t *cp);
			int musthave;
			int wordsize;

#ifdef	_MULTI_DATAMODEL
			if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
				wordsize = sizeof (int32_t);
			} else
#endif /* _MULTI_DATAMODEL */
			{
				wordsize = sizeof (int);
			}

			comps = PM_NUMCMPTS(dip);
			if (comps == 0 || PM_GET_PM_INFO(dip) == NULL) {
				PMD(PMD_ERROR, ("ioctl: %s: %s no components"
				    " or not power managed--EINVAL\n", cmdstr,
				    req.physpath))
				ret = EINVAL;
				break;
			}
			musthave = comps * 2 * wordsize;
			if (req.datasize < musthave) {
				PMD(PMD_ERROR, ("ioctl: %s: size %lu, need "
				    "%d--EINVAL\n", cmdstr, req.datasize,
				    musthave))
				ret = EINVAL;
				break;
			}

			PM_LOCK_DIP(dip);
			(void) drv_getparm(TIME, &now);
			timestamp = kmem_zalloc(comps * sizeof (time_t),
			    KM_SLEEP);
			pm_get_timestamps(dip, timestamp);
			/*
			 * First the current power levels
			 */
			for (i = 0; i < comps; i++) {
				int curpwr;
				int32_t curpwr32;
				caddr_t cpaddr;

				cp = PM_CP(dip, i);
				if (wordsize == sizeof (int)) {
					curpwr = pm_cur_power(cp);
					cpaddr = (caddr_t)&curpwr;
				} else {
					ASSERT(wordsize == sizeof (int32_t));
					curpwr32 = pm_cur_power(cp);
					cpaddr = (caddr_t)&curpwr32;
				}
				if (ddi_copyout(cpaddr, (void *) req.data,
				    wordsize, mode) != 0) {
					PM_UNLOCK_DIP(dip);
					PMD(PMD_ERROR, ("ioctl: %s: %s@%s"
					    "(%s#%d) req.data %p EFAULT\n",
					    cmdstr, PM_DEVICE(dip),
					    (void *)req.data))
					ASSERT(!dipheld);
					return (EFAULT);
				}
				cpaddr = (caddr_t)req.data;
				cpaddr += wordsize;
				req.data = cpaddr;
			}
			/*
			 * Then the times remaining
			 */
			for (i = 0; i < comps; i++) {
				int retval;
				int32_t retval32;
				caddr_t rvaddr;
				int curpwr;

				cp = PM_CP(dip, i);
				curpwr = cp->pmc_cur_pwr;
				if (curpwr == 0 || timestamp[i] == 0) {
					PMD(PMD_STATS, ("ioctl: %s: "
					    "cur_pwer %x, timestamp %lx\n",
					    cmdstr, curpwr, timestamp[i]))
					retval = INT_MAX;
				} else {
					int thresh;
					(void) pm_current_threshold(dip, i,
					    &thresh);
					retval = thresh - (now - timestamp[i]);
					PMD(PMD_STATS, ("ioctl: %s: current "
					    "thresh %x, now %lx, timestamp %lx,"
					    " retval %x\n", cmdstr, thresh, now,
					    timestamp[i], retval))
				}
				if (wordsize == sizeof (int)) {
					rvaddr = (caddr_t)&retval;
				} else {
					ASSERT(wordsize == sizeof (int32_t));
					retval32 = retval;
					rvaddr = (caddr_t)&retval32;
				}
				if (ddi_copyout(rvaddr, (void *) req.data,
				    wordsize, mode) != 0) {
					PM_UNLOCK_DIP(dip);
					PMD(PMD_ERROR, ("ioctl: %s: %s@%s"
					    "(%s#%d) req.data %p EFAULT\n",
					    cmdstr, PM_DEVICE(dip),
					    (void *)req.data))
					ASSERT(!dipheld);
					kmem_free(timestamp,
					    comps * sizeof (time_t));
					return (EFAULT);
				}
				rvaddr = (caddr_t)req.data;
				rvaddr += wordsize;
				req.data = (int *)rvaddr;
			}
			PM_UNLOCK_DIP(dip);
			*rval_p = comps;
			ret = 0;
			kmem_free(timestamp, comps * sizeof (time_t));
			break;
		}

		case PM_GET_CMD_NAME:
		{
			PMD(PMD_IOCTL, ("%s: %s\n", cmdstr,
			    pm_decode_cmd(req.value)))
			if (ret = copyoutstr(pm_decode_cmd(req.value),
			    (char *)req.data, req.datasize, &lencopied)) {
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "copyoutstr %p failed--EFAULT\n", cmdstr,
				    PM_DEVICE(dip), (void *)req.data))
				break;
			}
			*rval_p = lencopied;
			ret = 0;
			break;
		}

		case PM_GET_COMPONENT_NAME:
		{
			ASSERT(dip);
			if (!e_pm_valid_comp(dip, req.component, &cp)) {
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "component %d > numcmpts - 1 %d--EINVAL\n",
				    cmdstr, PM_DEVICE(dip), req.component,
				    PM_NUMCMPTS(dip) - 1))
				ret = EINVAL;
				break;
			}
			if (ret = copyoutstr(cp->pmc_comp.pmc_name,
			    (char *)req.data, req.datasize, &lencopied)) {
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "copyoutstr %p failed--EFAULT\n", cmdstr,
				    PM_DEVICE(dip), (void *)req.data))
				break;
			}
			*rval_p = lencopied;
			ret = 0;
			break;
		}

		case PM_GET_POWER_NAME:
		{
			int i;

			ASSERT(dip);
			if (!e_pm_valid_comp(dip, req.component, &cp)) {
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "component %d > numcmpts - 1 %d--EINVAL\n",
				    cmdstr, PM_DEVICE(dip), req.component,
				    PM_NUMCMPTS(dip) - 1))
				ret = EINVAL;
				break;
			}
			if ((i = req.value) < 0 ||
			    i > cp->pmc_comp.pmc_numlevels - 1) {
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "value %d > num_levels - 1 %d--EINVAL\n",
				    cmdstr, PM_DEVICE(dip), req.value,
				    cp->pmc_comp.pmc_numlevels - 1))
				ret = EINVAL;
				break;
			}
			dep = cp->pmc_comp.pmc_lnames[req.value];
			if (ret = copyoutstr(dep,
			    req.data, req.datasize, &lencopied)) {
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "copyoutstr %p failed--EFAULT\n", cmdstr,
				    PM_DEVICE(dip), (void *)req.data))
				break;
			}
			*rval_p = lencopied;
			ret = 0;
			break;
		}

		case PM_GET_POWER_LEVELS:
		{
			int musthave;
			int numlevels;
			int wordsize;

#ifdef	_MULTI_DATAMODEL
			if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
				wordsize = sizeof (int32_t);
			} else
#endif /* _MULTI_DATAMODEL */
			{
				wordsize = sizeof (int);
			}
			ASSERT(dip);

			if (!e_pm_valid_comp(dip, req.component, &cp)) {
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "has %d components, component %d requested"
				    "--EINVAL\n", cmdstr, PM_DEVICE(dip),
				    PM_NUMCMPTS(dip), req.component))
				ret = EINVAL;
				break;
			}
			numlevels = cp->pmc_comp.pmc_numlevels;
			musthave = numlevels *  wordsize;
			if (req.datasize < musthave) {
				PMD(PMD_ERROR, ("ioctl: %s: size %lu, need "
				    "%d--EINVAL\n", cmdstr, req.datasize,
				    musthave))
				ret = EINVAL;
				break;
			}
			PM_LOCK_DIP(dip);
			for (i = 0; i < numlevels; i++) {
				int level;
				int32_t level32;
				caddr_t laddr;

				if (wordsize == sizeof (int)) {
					level = cp->pmc_comp.pmc_lvals[i];
					laddr = (caddr_t)&level;
				} else {
					level32 = cp->pmc_comp.pmc_lvals[i];
					laddr = (caddr_t)&level32;
				}
				if (ddi_copyout(laddr, (void *) req.data,
				    wordsize, mode) != 0) {
					PM_UNLOCK_DIP(dip);
					PMD(PMD_ERROR, ("ioctl: %s: %s@%s"
					    "(%s#%d) laddr %p EFAULT\n",
					    cmdstr, PM_DEVICE(dip),
					    (void *)laddr))
					ASSERT(!dipheld);
					return (EFAULT);
				}
				laddr = (caddr_t)req.data;
				laddr += wordsize;
				req.data = (int *)laddr;
			}
			PM_UNLOCK_DIP(dip);
			*rval_p = numlevels;
			ret = 0;
			break;
		}


		case PM_GET_NUM_POWER_LEVELS:
		{
			if (!e_pm_valid_comp(dip, req.component, &cp)) {
				PMD(PMD_ERROR, ("ioctl: %s: %s@%s(%s#%d) "
				    "component %d > numcmpts - 1 %d--EINVAL\n",
				    cmdstr, PM_DEVICE(dip), req.component,
				    PM_NUMCMPTS(dip) - 1))
				ret = EINVAL;
				break;
			}
			*rval_p = cp->pmc_comp.pmc_numlevels;
			ret = 0;
			break;
		}

		case PM_GET_DEVICE_THRESHOLD_BASIS:
		{
			ret = 0;
			PM_LOCK_DIP(dip);
			if ((info = PM_GET_PM_INFO(dip)) == NULL) {
				PM_UNLOCK_DIP(dip);
				PMD(PMD_ERROR, ("ioctl: %s: "
				    "PM_NO_PM_COMPONENTS\n", cmdstr))
				*rval_p = PM_NO_PM_COMPONENTS;
				break;
			}
			if (PM_ISDIRECT(dip)) {
				PM_UNLOCK_DIP(dip);
				*rval_p = PM_DIRECTLY_MANAGED;
				break;
			}
			switch (DEVI(dip)->devi_pm_flags & PMC_THRESH_ALL) {
			case PMC_DEF_THRESH:
			case PMC_NEXDEF_THRESH:
				*rval_p = PM_DEFAULT_THRESHOLD;
				break;
			case PMC_DEV_THRESH:
				*rval_p = PM_DEVICE_THRESHOLD;
				break;
			case PMC_COMP_THRESH:
				*rval_p = PM_COMPONENT_THRESHOLD;
				break;
			case PMC_CPU_THRESH:
				*rval_p = PM_CPU_THRESHOLD;
				break;
			default:
				if (PM_ISBC(dip)) {
					*rval_p = PM_OLD_THRESHOLD;
					break;
				}
				PMD(PMD_ERROR, ("ioctl: %s: default, not "
				    "BC--EINVAL", cmdstr))
				ret = EINVAL;
				break;
			}
			PM_UNLOCK_DIP(dip);
			break;
		}
		default:
			/*
			 * Internal error, invalid ioctl description
			 * force debug entry even if pm_debug not set
			 */
#ifdef	DEBUG
			pm_log("invalid diptype %d for cmd %d (%s)\n",
			    pcip->diptype, cmd, pcip->name);
#endif
			ASSERT(0);
			return (EIO);
		}
		break;
	}

	case PM_PSC:
	{
		/*
		 * Commands that require pm_state_change_t as arg
		 */
#ifdef	_MULTI_DATAMODEL
		if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
			pscp32 = (pm_state_change32_t *)arg;
			if (ddi_copyin((caddr_t)arg, &psc32,
			    sizeof (psc32), mode) != 0) {
				PMD(PMD_ERROR, ("ioctl: %s: ddi_copyin "
				    "EFAULT\n\n", cmdstr))
				ASSERT(!dipheld);
				return (EFAULT);
			}
			psc.physpath = (caddr_t)(uintptr_t)psc32.physpath;
			psc.size = psc32.size;
		} else
#endif /* _MULTI_DATAMODEL */
		{
			pscp = (pm_state_change_t *)arg;
			if (ddi_copyin((caddr_t)arg, &psc,
			    sizeof (psc), mode) != 0) {
				PMD(PMD_ERROR, ("ioctl: %s: ddi_copyin "
				    "EFAULT\n\n", cmdstr))
				ASSERT(!dipheld);
				return (EFAULT);
			}
		}
		switch (cmd) {

		case PM_GET_STATE_CHANGE:
		case PM_GET_STATE_CHANGE_WAIT:
		{
			psce_t			*pscep;
			pm_state_change_t	*p;
			caddr_t			physpath;
			size_t			physlen;

			/*
			 * We want to know if any device has changed state.
			 * We look up by clone.  In case we have another thread
			 * from the same process, we loop.
			 * pm_psc_clone_to_interest() returns a locked entry.
			 * We create an internal copy of the event entry prior
			 * to copyout to user space because we don't want to
			 * hold the psce_lock while doing copyout as we might
			 * hit page fault  which eventually brings us back
			 * here requesting the same lock.
			 */
			mutex_enter(&pm_clone_lock);
			if (!pm_interest_registered(clone))
				pm_register_watcher(clone, NULL);
			while ((pscep =
			    pm_psc_clone_to_interest(clone)) == NULL) {
				if (cmd == PM_GET_STATE_CHANGE) {
					PMD(PMD_IOCTL, ("ioctl: %s: "
					    "EWOULDBLOCK\n", cmdstr))
					mutex_exit(&pm_clone_lock);
					ASSERT(!dipheld);
					return (EWOULDBLOCK);
				} else {
					if (cv_wait_sig(&pm_clones_cv[clone],
					    &pm_clone_lock) == 0) {
						mutex_exit(&pm_clone_lock);
						PMD(PMD_ERROR, ("ioctl: %s "
						    "EINTR\n", cmdstr))
						ASSERT(!dipheld);
						return (EINTR);
					}
				}
			}
			mutex_exit(&pm_clone_lock);

			physlen = pscep->psce_out->size;
			physpath = NULL;
			/*
			 * If we were unable to store the path while bringing
			 * up the console fb upon entering the prom, we give
			 * a "" name with the overrun event set
			 */
			if (physlen == (size_t)-1) {	/* kmemalloc failed */
				physpath = kmem_zalloc(1, KM_SLEEP);
				physlen = 1;
			}
			if ((psc.physpath == NULL) || (psc.size < physlen)) {
				PMD(PMD_ERROR, ("ioctl: %s: EFAULT\n", cmdstr))
				mutex_exit(&pscep->psce_lock);
				ret = EFAULT;
				break;
			}
			if (physpath == NULL) {
				physpath = kmem_zalloc(physlen, KM_SLEEP);
				bcopy((const void *) pscep->psce_out->physpath,
				    (void *) physpath, physlen);
			}

			p = pscep->psce_out;
#ifdef	_MULTI_DATAMODEL
			if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
#ifdef DEBUG
				size_t usrcopysize;
#endif
				psc32.flags = (ushort_t)p->flags;
				psc32.event = (ushort_t)p->event;
				psc32.timestamp = (int32_t)p->timestamp;
				psc32.component = (int32_t)p->component;
				psc32.old_level = (int32_t)p->old_level;
				psc32.new_level = (int32_t)p->new_level;
				copysize32 = ((intptr_t)&psc32.size -
				    (intptr_t)&psc32.component);
#ifdef DEBUG
				usrcopysize = ((intptr_t)&pscp32->size -
				    (intptr_t)&pscp32->component);
				ASSERT(usrcopysize == copysize32);
#endif
			} else
#endif /* _MULTI_DATAMODEL */
			{
				psc.flags = p->flags;
				psc.event = p->event;
				psc.timestamp = p->timestamp;
				psc.component = p->component;
				psc.old_level = p->old_level;
				psc.new_level = p->new_level;
				copysize = ((long)&p->size -
				    (long)&p->component);
			}
			if (p->size != (size_t)-1)
				kmem_free(p->physpath, p->size);
			p->size = 0;
			p->physpath = NULL;
			if (pscep->psce_out == pscep->psce_last)
				p = pscep->psce_first;
			else
				p++;
			pscep->psce_out = p;
			mutex_exit(&pscep->psce_lock);

			ret = copyoutstr(physpath, psc.physpath,
			    physlen, &lencopied);
			kmem_free(physpath, physlen);
			if (ret) {
				PMD(PMD_ERROR, ("ioctl: %s: copyoutstr %p "
				    "failed--EFAULT\n", cmdstr,
				    (void *)psc.physpath))
				break;
			}

#ifdef	_MULTI_DATAMODEL
			if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
				if (ddi_copyout(&psc32.component,
				    &pscp32->component, copysize32, mode)
				    != 0) {
					PMD(PMD_ERROR, ("ioctl: %s: copyout "
					    "failed--EFAULT\n", cmdstr))
					ret = EFAULT;
					break;
				}
			} else
#endif	/* _MULTI_DATAMODEL */
			{
				if (ddi_copyout(&psc.component,
				    &pscp->component, copysize, mode) != 0) {
					PMD(PMD_ERROR, ("ioctl: %s: copyout "
					    "failed--EFAULT\n", cmdstr))
					ret = EFAULT;
					break;
				}
			}
			ret = 0;
			break;
		}

		case PM_DIRECT_NOTIFY:
		case PM_DIRECT_NOTIFY_WAIT:
		{
			psce_t			*pscep;
			pm_state_change_t	*p;
			caddr_t			physpath;
			size_t			physlen;
			/*
			 * We want to know if any direct device of ours has
			 * something we should know about.  We look up by clone.
			 * In case we have another thread from the same process,
			 * we loop.
			 * pm_psc_clone_to_direct() returns a locked entry.
			 */
			mutex_enter(&pm_clone_lock);
			while (pm_poll_cnt[clone] == 0 ||
			    (pscep = pm_psc_clone_to_direct(clone)) == NULL) {
				if (cmd == PM_DIRECT_NOTIFY) {
					PMD(PMD_IOCTL, ("ioctl: %s: "
					    "EWOULDBLOCK\n", cmdstr))
					mutex_exit(&pm_clone_lock);
					ASSERT(!dipheld);
					return (EWOULDBLOCK);
				} else {
					if (cv_wait_sig(&pm_clones_cv[clone],
					    &pm_clone_lock) == 0) {
						mutex_exit(&pm_clone_lock);
						PMD(PMD_ERROR, ("ioctl: %s: "
						    "EINTR\n", cmdstr))
						ASSERT(!dipheld);
						return (EINTR);
					}
				}
			}
			mutex_exit(&pm_clone_lock);
			physlen = pscep->psce_out->size;
			if ((psc.physpath == NULL) || (psc.size < physlen)) {
				mutex_exit(&pscep->psce_lock);
				PMD(PMD_ERROR, ("ioctl: %s: EFAULT\n",
				    cmdstr))
				ret = EFAULT;
				break;
			}
			physpath = kmem_zalloc(physlen, KM_SLEEP);
			bcopy((const void *) pscep->psce_out->physpath,
			    (void *) physpath, physlen);

			p = pscep->psce_out;
#ifdef	_MULTI_DATAMODEL
			if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
#ifdef DEBUG
				size_t usrcopysize;
#endif
				psc32.component = (int32_t)p->component;
				psc32.flags = (ushort_t)p->flags;
				psc32.event = (ushort_t)p->event;
				psc32.timestamp = (int32_t)p->timestamp;
				psc32.old_level = (int32_t)p->old_level;
				psc32.new_level = (int32_t)p->new_level;
				copysize32 = (intptr_t)&psc32.size -
				    (intptr_t)&psc32.component;
				PMD(PMD_DPM, ("ioctl: %s: PDN32 %s, comp %d "
				    "%d -> %d\n", cmdstr, physpath,
				    p->component, p->old_level, p->new_level))
#ifdef DEBUG
				usrcopysize = (intptr_t)&pscp32->size -
				    (intptr_t)&pscp32->component;
				ASSERT(usrcopysize == copysize32);
#endif
			} else
#endif
			{
				psc.component = p->component;
				psc.flags = p->flags;
				psc.event = p->event;
				psc.timestamp = p->timestamp;
				psc.old_level = p->old_level;
				psc.new_level = p->new_level;
				copysize = (intptr_t)&p->size -
				    (intptr_t)&p->component;
				PMD(PMD_DPM, ("ioctl: %s: PDN %s, comp %d "
				    "%d -> %d\n", cmdstr, physpath,
				    p->component, p->old_level, p->new_level))
			}
			mutex_enter(&pm_clone_lock);
			PMD(PMD_IOCTL, ("ioctl: %s: pm_poll_cnt[%d] is %d "
			    "before decrement\n", cmdstr, clone,
			    pm_poll_cnt[clone]))
			pm_poll_cnt[clone]--;
			mutex_exit(&pm_clone_lock);
			kmem_free(p->physpath, p->size);
			p->size = 0;
			p->physpath = NULL;
			if (pscep->psce_out == pscep->psce_last)
				p = pscep->psce_first;
			else
				p++;
			pscep->psce_out = p;
			mutex_exit(&pscep->psce_lock);

			ret = copyoutstr(physpath, psc.physpath,
			    physlen, &lencopied);
			kmem_free(physpath, physlen);
			if (ret) {
				PMD(PMD_ERROR, ("ioctl: %s: copyoutstr %p "
				    "failed--EFAULT\n", cmdstr,
				    (void *)psc.physpath))
				break;
			}

#ifdef	_MULTI_DATAMODEL
			if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
				if (ddi_copyout(&psc32.component,
				    &pscp32->component, copysize32, mode)
				    != 0) {
					PMD(PMD_ERROR, ("ioctl: %s: copyout "
					    "failed--EFAULT\n", cmdstr))
					ret = EFAULT;
					break;
				}
			} else
#endif	/* _MULTI_DATAMODEL */
			{
				if (ddi_copyout(&psc.component,
				    &pscp->component, copysize, mode) != 0) {
					PMD(PMD_ERROR, ("ioctl: %s: copyout "
					    "failed--EFAULT\n", cmdstr))
					ret = EFAULT;
					break;
				}
			}
			ret = 0;
			break;
		}
		default:
			/*
			 * Internal error, invalid ioctl description
			 * force debug entry even if pm_debug not set
			 */
#ifdef	DEBUG
			pm_log("invalid diptype %d for cmd %d (%s)\n",
			    pcip->diptype, cmd, pcip->name);
#endif
			ASSERT(0);
			return (EIO);
		}
		break;
	}

	case PM_SRCH:		/* command that takes a pm_searchargs_t arg */
	{
		/*
		 * If no ppm, then there is nothing to search.
		 */
		if (DEVI(ddi_root_node())->devi_pm_ppm == NULL) {
			ret = ENODEV;
			break;
		}

#ifdef	_MULTI_DATAMODEL
		if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
			if (ddi_copyin((caddr_t)arg, &psa32,
			    sizeof (psa32), mode) != 0) {
				PMD(PMD_ERROR, ("ioctl: %s: ddi_copyin "
				    "EFAULT\n\n", cmdstr))
				return (EFAULT);
			}
			if (copyinstr((void *)(uintptr_t)psa32.pms_listname,
			    listname, MAXCOPYBUF, NULL)) {
				PMD(PMD_ERROR, ("ioctl: %s: 0x%p MAXCOPYBUF "
				    "%d, " "EFAULT\n", cmdstr,
				    (void *)(uintptr_t)psa32.pms_listname,
				    MAXCOPYBUF))
				ret = EFAULT;
				break;
			}
			if (copyinstr((void *)(uintptr_t)psa32.pms_manufacturer,
			    manufacturer, MAXCOPYBUF, NULL)) {
				PMD(PMD_ERROR, ("ioctl: %s: 0x%p MAXCOPYBUF "
				    "%d, " "EFAULT\n", cmdstr,
				    (void *)(uintptr_t)psa32.pms_manufacturer,
				    MAXCOPYBUF))
				ret = EFAULT;
				break;
			}
			if (copyinstr((void *)(uintptr_t)psa32.pms_product,
			    product, MAXCOPYBUF, NULL)) {
				PMD(PMD_ERROR, ("ioctl: %s: 0x%p MAXCOPYBUF "
				    "%d, " "EFAULT\n", cmdstr,
				    (void *)(uintptr_t)psa32.pms_product,
				    MAXCOPYBUF))
				ret = EFAULT;
				break;
			}
		} else
#endif /* _MULTI_DATAMODEL */
		{
			if (ddi_copyin((caddr_t)arg, &psa,
			    sizeof (psa), mode) != 0) {
				PMD(PMD_ERROR, ("ioctl: %s: ddi_copyin "
				    "EFAULT\n\n", cmdstr))
				return (EFAULT);
			}
			if (copyinstr(psa.pms_listname,
			    listname, MAXCOPYBUF, NULL)) {
				PMD(PMD_ERROR, ("ioctl: %s: 0x%p MAXCOPYBUF "
				    "%d, " "EFAULT\n", cmdstr,
				    (void *)psa.pms_listname, MAXCOPYBUF))
				ret = EFAULT;
				break;
			}
			if (copyinstr(psa.pms_manufacturer,
			    manufacturer, MAXCOPYBUF, NULL)) {
				PMD(PMD_ERROR, ("ioctl: %s: 0x%p MAXCOPYBUF "
				    "%d, " "EFAULT\n", cmdstr,
				    (void *)psa.pms_manufacturer, MAXCOPYBUF))
				ret = EFAULT;
				break;
			}
			if (copyinstr(psa.pms_product,
			    product, MAXCOPYBUF, NULL)) {
				PMD(PMD_ERROR, ("ioctl: %s: 0x%p MAXCOPYBUF "
				    "%d, " "EFAULT\n", cmdstr,
				    (void *)psa.pms_product, MAXCOPYBUF))
				ret = EFAULT;
				break;
			}
		}
		psa.pms_listname = listname;
		psa.pms_manufacturer = manufacturer;
		psa.pms_product = product;
		switch (cmd) {
		case PM_SEARCH_LIST:
			ret = pm_ppm_searchlist(&psa);
			break;

		default:
			/*
			 * Internal error, invalid ioctl description
			 * force debug entry even if pm_debug not set
			 */
#ifdef	DEBUG
			pm_log("invalid diptype %d for cmd %d (%s)\n",
			    pcip->diptype, cmd, pcip->name);
#endif
			ASSERT(0);
			return (EIO);
		}
		break;
	}

	case NOSTRUCT:
	{
		switch (cmd) {
		case PM_START_PM:
		case PM_START_CPUPM:
		case PM_START_CPUPM_EV:
		case PM_START_CPUPM_POLL:
		{
			pm_cpupm_t	new_mode = PM_CPUPM_NOTSET;
			pm_cpupm_t	old_mode = PM_CPUPM_NOTSET;
			int		r;

			mutex_enter(&pm_scan_lock);
			if ((cmd == PM_START_PM && autopm_enabled) ||
			    (cmd == PM_START_CPUPM && PM_DEFAULT_CPUPM) ||
			    (cmd == PM_START_CPUPM_EV && PM_EVENT_CPUPM) ||
			    (cmd == PM_START_CPUPM_POLL && PM_POLLING_CPUPM)) {
				mutex_exit(&pm_scan_lock);
				PMD(PMD_ERROR, ("ioctl: %s: EBUSY\n", cmdstr))
				ret = EBUSY;
				break;
			}

			if (cmd == PM_START_PM) {
				autopm_enabled = 1;
			} else if (cmd == PM_START_CPUPM) {
				old_mode = cpupm;
				new_mode = cpupm = cpupm_default_mode;
			} else if (cmd == PM_START_CPUPM_EV) {
				old_mode = cpupm;
				new_mode = cpupm = PM_CPUPM_EVENT;
			} else if (cmd == PM_START_CPUPM_POLL) {
				old_mode = cpupm;
				new_mode = cpupm = PM_CPUPM_POLLING;
			}

			mutex_exit(&pm_scan_lock);

			/*
			 * If we are changing CPUPM modes, and it is active,
			 * then stop it from operating in the old mode.
			 */
			if (old_mode == PM_CPUPM_POLLING) {
				int c = PM_STOP_CPUPM;
				ddi_walk_devs(ddi_root_node(), pm_stop_pm_walk,
				    &c);
			} else if (old_mode == PM_CPUPM_EVENT) {
				r = cpupm_set_policy(CPUPM_POLICY_DISABLED);

				/*
				 * Disabling CPUPM policy should always
				 * succeed
				 */
				ASSERT(r == 0);
			}

			/*
			 * If we are changing to event based CPUPM, enable it.
			 * In the event it's not supported, fall back to
			 * polling based CPUPM.
			 */
			if (new_mode == PM_CPUPM_EVENT &&
			    cpupm_set_policy(CPUPM_POLICY_ELASTIC) < 0) {
				mutex_enter(&pm_scan_lock);
				new_mode = cpupm = PM_CPUPM_POLLING;
				cmd = PM_START_CPUPM_POLL;
				mutex_exit(&pm_scan_lock);
			}
			if (new_mode == PM_CPUPM_POLLING ||
			    cmd == PM_START_PM) {
				ddi_walk_devs(ddi_root_node(), pm_start_pm_walk,
				    &cmd);
			}
			ret = 0;
			break;
		}

		case PM_RESET_PM:
		case PM_STOP_PM:
		case PM_STOP_CPUPM:
		{
			extern void pm_discard_thresholds(void);
			pm_cpupm_t old_mode = PM_CPUPM_NOTSET;

			mutex_enter(&pm_scan_lock);
			if ((cmd == PM_STOP_PM && !autopm_enabled) ||
			    (cmd == PM_STOP_CPUPM && PM_CPUPM_DISABLED)) {
				mutex_exit(&pm_scan_lock);
				PMD(PMD_ERROR, ("ioctl: %s: EINVAL\n",
				    cmdstr))
				ret = EINVAL;
				break;
			}

			if (cmd == PM_STOP_PM) {
				autopm_enabled = 0;
				pm_S3_enabled = 0;
				autoS3_enabled = 0;
			} else if (cmd == PM_STOP_CPUPM) {
				old_mode = cpupm;
				cpupm = PM_CPUPM_DISABLE;
			} else {
				autopm_enabled = 0;
				autoS3_enabled = 0;
				old_mode = cpupm;
				cpupm = PM_CPUPM_NOTSET;
			}
			mutex_exit(&pm_scan_lock);

			/*
			 * bring devices to full power level, stop scan
			 * If CPUPM was operating in event driven mode, disable
			 * that.
			 */
			if (old_mode == PM_CPUPM_EVENT) {
				(void) cpupm_set_policy(CPUPM_POLICY_DISABLED);
			}
			ddi_walk_devs(ddi_root_node(), pm_stop_pm_walk, &cmd);
			ret = 0;
			if (cmd == PM_STOP_PM || cmd == PM_STOP_CPUPM)
				break;
			/*
			 * Now do only PM_RESET_PM stuff.
			 */
			pm_system_idle_threshold = pm_default_idle_threshold;
			pm_cpu_idle_threshold = 0;
			pm_discard_thresholds();
			pm_all_to_default_thresholds();
			pm_dispatch_to_dep_thread(PM_DEP_WK_REMOVE_DEP,
			    NULL, NULL, PM_DEP_WAIT, NULL, 0);
			break;
		}

		case PM_GET_SYSTEM_THRESHOLD:
		{
			*rval_p = pm_system_idle_threshold;
			ret = 0;
			break;
		}

		case PM_GET_DEFAULT_SYSTEM_THRESHOLD:
		{
			*rval_p = pm_default_idle_threshold;
			ret = 0;
			break;
		}

		case PM_GET_CPU_THRESHOLD:
		{
			*rval_p = pm_cpu_idle_threshold;
			ret = 0;
			break;
		}

		case PM_SET_SYSTEM_THRESHOLD:
		case PM_SET_CPU_THRESHOLD:
		{
			if ((int)arg < 0) {
				PMD(PMD_ERROR, ("ioctl: %s: arg 0x%x < 0"
				    "--EINVAL\n", cmdstr, (int)arg))
				ret = EINVAL;
				break;
			}
			PMD(PMD_IOCTL, ("ioctl: %s: 0x%x 0t%d\n", cmdstr,
			    (int)arg, (int)arg))
			if (cmd == PM_SET_SYSTEM_THRESHOLD)
				pm_system_idle_threshold = (int)arg;
			else {
				pm_cpu_idle_threshold = (int)arg;
			}
			ddi_walk_devs(ddi_root_node(), pm_set_idle_thresh_walk,
			    (void *) &cmd);

			ret = 0;
			break;
		}

		case PM_IDLE_DOWN:
		{
			if (pm_timeout_idledown() != 0) {
				ddi_walk_devs(ddi_root_node(),
				    pm_start_idledown, (void *)PMID_IOC);
			}
			ret = 0;
			break;
		}

		case PM_GET_PM_STATE:
		{
			if (autopm_enabled) {
				*rval_p = PM_SYSTEM_PM_ENABLED;
			} else {
				*rval_p = PM_SYSTEM_PM_DISABLED;
			}
			ret = 0;
			break;
		}

		case PM_GET_CPUPM_STATE:
		{
			if (PM_POLLING_CPUPM || PM_EVENT_CPUPM)
				*rval_p = PM_CPU_PM_ENABLED;
			else if (PM_CPUPM_DISABLED)
				*rval_p = PM_CPU_PM_DISABLED;
			else
				*rval_p = PM_CPU_PM_NOTSET;
			ret = 0;
			break;
		}

		case PM_GET_AUTOS3_STATE:
		{
			if (autoS3_enabled) {
				*rval_p = PM_AUTOS3_ENABLED;
			} else {
				*rval_p = PM_AUTOS3_DISABLED;
			}
			ret = 0;
			break;
		}

		case PM_GET_S3_SUPPORT_STATE:
		{
			if (pm_S3_enabled) {
				*rval_p = PM_S3_SUPPORT_ENABLED;
			} else {
				*rval_p = PM_S3_SUPPORT_DISABLED;
			}
			ret = 0;
			break;
		}

		/*
		 * pmconfig tells us if the platform supports S3
		 */
		case PM_ENABLE_S3:
		{
			mutex_enter(&pm_scan_lock);
			if (pm_S3_enabled) {
				mutex_exit(&pm_scan_lock);
				PMD(PMD_ERROR, ("ioctl: %s: EBUSY\n",
				    cmdstr))
				ret = EBUSY;
				break;
			}
			pm_S3_enabled = 1;
			mutex_exit(&pm_scan_lock);
			ret = 0;
			break;
		}

		case PM_DISABLE_S3:
		{
			mutex_enter(&pm_scan_lock);
			pm_S3_enabled = 0;
			mutex_exit(&pm_scan_lock);
			ret = 0;
			break;
		}

		case PM_START_AUTOS3:
		{
			mutex_enter(&pm_scan_lock);
			if (autoS3_enabled) {
				mutex_exit(&pm_scan_lock);
				PMD(PMD_ERROR, ("ioctl: %s: EBUSY\n",
				    cmdstr))
				ret = EBUSY;
				break;
			}
			autoS3_enabled = 1;
			mutex_exit(&pm_scan_lock);
			ret = 0;
			break;
		}

		case PM_STOP_AUTOS3:
		{
			mutex_enter(&pm_scan_lock);
			autoS3_enabled = 0;
			mutex_exit(&pm_scan_lock);
			ret = 0;
			break;
		}

		case PM_ENABLE_CPU_DEEP_IDLE:
		{
			if (callb_execute_class(CB_CL_CPU_DEEP_IDLE,
			    PM_ENABLE_CPU_DEEP_IDLE) == NULL)
				ret = 0;
			else
				ret = EBUSY;
			break;
		}
		case PM_DISABLE_CPU_DEEP_IDLE:
		{
			if (callb_execute_class(CB_CL_CPU_DEEP_IDLE,
			    PM_DISABLE_CPU_DEEP_IDLE) == NULL)
				ret = 0;
			else
				ret = EINVAL;
			break;
		}
		case PM_DEFAULT_CPU_DEEP_IDLE:
		{
			if (callb_execute_class(CB_CL_CPU_DEEP_IDLE,
			    PM_DEFAULT_CPU_DEEP_IDLE) == NULL)
				ret = 0;
			else
				ret = EBUSY;
			break;
		}

		default:
			/*
			 * Internal error, invalid ioctl description
			 * force debug entry even if pm_debug not set
			 */
#ifdef	DEBUG
			pm_log("invalid diptype %d for cmd %d (%s)\n",
			    pcip->diptype, cmd, pcip->name);
#endif
			ASSERT(0);
			return (EIO);
		}
		break;
	}

default:
		/*
		 * Internal error, invalid ioctl description
		 * force debug entry even if pm_debug not set
		 */
#ifdef	DEBUG
		pm_log("ioctl: invalid str_type %d for cmd %d (%s)\n",
		    pcip->str_type, cmd, pcip->name);
#endif
		ASSERT(0);
		return (EIO);
	}
	ASSERT(ret != 0x0badcafe);	/* some cmd in wrong case! */
	if (dipheld) {
		ASSERT(dip);
		PMD(PMD_DHR, ("ioctl: %s: releasing %s@%s(%s#%d) for "
		    "exiting pm_ioctl\n", cmdstr, PM_DEVICE(dip)))
		PM_RELE(dip);
	}
	PMD(PMD_IOCTL, ("ioctl: %s: end, ret=%d\n", cmdstr, ret))
	return (ret);
}
