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
 * Copyright 2017 Joyent, Inc.
 */


/*
 * srn	Provide apm-like interfaces to Xorg
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/modctl.h>
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
#include <sys/srn.h>

/*
 * Minor number is instance<<8 + clone minor from range 1-255;
 * But only one will be allocated
 */
#define	SRN_MINOR_TO_CLONE(minor) ((minor) & (SRN_MAX_CLONE - 1))
#define	SU		0x002
#define	SG		0x004

extern kmutex_t	srn_clone_lock;	/* protects srn_clones array */
extern kcondvar_t srn_clones_cv[SRN_MAX_CLONE];
extern uint_t	srn_poll_cnt[SRN_MAX_CLONE];

/*
 * The soft state of the srn driver.  Since there will only be
 * one of these, just reference it through a static struct.
 */
static struct srnstate {
	dev_info_t	*srn_dip;		/* ptr to our dev_info node */
	int		srn_instance;		/* for ddi_get_instance() */
	uchar_t		srn_clones[SRN_MAX_CLONE]; /* unique opens	*/
	struct cred	*srn_cred[SRN_MAX_CLONE]; /* cred for each open	*/
	int		srn_type[SRN_MAX_CLONE]; /* type of handshake */
	int		srn_delivered[SRN_MAX_CLONE];
	srn_event_info_t srn_pending[SRN_MAX_CLONE];
	int		srn_fault[SRN_MAX_CLONE];
} srn = { NULL, -1};
typedef struct srnstate *srn_state_t;

kcondvar_t	srn_clones_cv[SRN_MAX_CLONE];
uint_t		srn_poll_cnt[SRN_MAX_CLONE];	/* count of events for poll */
int		srn_apm_count;
int		srn_autosx_count;
/* Number of seconds to wait for clients to ack a poll */
int		srn_timeout = 10;

struct pollhead	srn_pollhead[SRN_MAX_CLONE];

static int	srn_open(dev_t *, int, int, cred_t *);
static int	srn_close(dev_t, int, int, cred_t *);
static int	srn_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	srn_chpoll(dev_t, short, int, short *, struct pollhead **);

static struct cb_ops srn_cb_ops = {
	srn_open,	/* open */
	srn_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	srn_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	srn_chpoll,	/* poll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* streamtab */
	D_NEW | D_MP	/* driver compatibility flag */
};

static int srn_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result);
static int srn_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int srn_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static void srn_notify(int type, int event);

static struct dev_ops srn_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	srn_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	srn_attach,		/* attach */
	srn_detach,		/* detach */
	nodev,			/* reset */
	&srn_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"srn driver",
	&srn_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, 0
};

/* Local functions */

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
srn_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		i;
	extern void (*srn_signal)(int, int);

	switch (cmd) {

	case DDI_ATTACH:
		if (srn.srn_instance != -1)	/* Only allow one instance */
			return (DDI_FAILURE);
		srn.srn_instance = ddi_get_instance(dip);
		if (ddi_create_minor_node(dip, "srn", S_IFCHR,
		    (srn.srn_instance << 8) + 0, DDI_PSEUDO, 0)
		    != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		srn.srn_dip = dip;	/* srn_init and getinfo depend on it */

		for (i = 0; i < SRN_MAX_CLONE; i++)
			cv_init(&srn_clones_cv[i], NULL, CV_DEFAULT, NULL);

		srn.srn_instance = ddi_get_instance(dip);
		mutex_enter(&srn_clone_lock);
		srn_signal = srn_notify;
		mutex_exit(&srn_clone_lock);
		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/* ARGSUSED */
static int
srn_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int i;
	extern int srn_inuse;
	extern void (*srn_signal)(int, int);

	switch (cmd) {
	case DDI_DETACH:

		mutex_enter(&srn_clone_lock);
		while (srn_inuse) {
			mutex_exit(&srn_clone_lock);
			delay(1);
			mutex_enter(&srn_clone_lock);
		}
		srn_signal = NULL;
		mutex_exit(&srn_clone_lock);

		for (i = 0; i < SRN_MAX_CLONE; i++)
			cv_destroy(&srn_clones_cv[i]);

		ddi_remove_minor_node(dip, NULL);
		srn.srn_instance = -1;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


#ifdef DEBUG
char *srn_cmd_string;
int srn_cmd;
#endif

/*
 * Returns true if permission granted by credentials
 * XXX
 */
static int
srn_perms(int perm, cred_t *cr)
{
	if ((perm & SU) && secpolicy_power_mgmt(cr) == 0) /* privileged? */
		return (1);
	if ((perm & SG) && (crgetgid(cr) == 0))	/* group 0 is ok */
		return (1);
	return (0);
}

static int
srn_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	extern struct pollhead srn_pollhead[];
	int	clone;

	clone = SRN_MINOR_TO_CLONE(getminor(dev));
	if ((events & (POLLIN | POLLRDNORM)) && srn_poll_cnt[clone]) {
		*reventsp |= (POLLIN | POLLRDNORM);
	} else {
		*reventsp = 0;
	}

	if ((*reventsp == 0 && !anyyet) || (events & POLLET)) {
		*phpp = &srn_pollhead[clone];
	}
	return (0);
}

/*ARGSUSED*/
static int
srn_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (srn.srn_instance == -1)
			return (DDI_FAILURE);
		*result = srn.srn_dip;
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
srn_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	int		clone;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	mutex_enter(&srn_clone_lock);
	for (clone = 1; clone < SRN_MAX_CLONE - 1; clone++)
		if (!srn.srn_clones[clone])
			break;

	if (clone == SRN_MAX_CLONE) {
		mutex_exit(&srn_clone_lock);
		return (ENXIO);
	}
	srn.srn_cred[clone] = cr;
	ASSERT(srn_apm_count >= 0);
	srn_apm_count++;
	srn.srn_type[clone] = SRN_TYPE_APM;
	crhold(cr);

	*devp = makedevice(getmajor(*devp), (srn.srn_instance << 8) +
	    clone);
	srn.srn_clones[clone] = 1;
	srn.srn_cred[clone] = cr;
	crhold(cr);
	mutex_exit(&srn_clone_lock);
	PMD(PMD_SX, ("srn open OK\n"))
	return (0);
}

/*ARGSUSED1*/
static int
srn_close(dev_t dev, int flag, int otyp, cred_t *cr)
{
	int clone;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	clone = SRN_MINOR_TO_CLONE(getminor(dev));
	PMD(PMD_SX, ("srn_close: minor %x, clone %x\n", getminor(dev),
	    clone))
	mutex_enter(&srn_clone_lock);
	crfree(srn.srn_cred[clone]);
	srn.srn_cred[clone] = 0;
	srn_poll_cnt[clone] = 0;
	srn.srn_fault[clone] = 0;
	if (srn.srn_pending[clone].ae_type || srn.srn_delivered[clone]) {
		srn.srn_pending[clone].ae_type = 0;
		srn.srn_delivered[clone] = 0;
		cv_signal(&srn_clones_cv[clone]);
	}
	switch (srn.srn_type[clone]) {
	case SRN_TYPE_AUTOSX:
		ASSERT(srn_autosx_count);
		srn_autosx_count--;
		break;
	case SRN_TYPE_APM:
		ASSERT(srn_apm_count);
		srn_apm_count--;
		break;
	default:
		ASSERT(0);
		return (EINVAL);
	}
	srn.srn_clones[clone] = 0;
	mutex_exit(&srn_clone_lock);
	return (0);
}

/*ARGSUSED*/
static int
srn_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr, int *rval_p)
{
	int clone = SRN_MINOR_TO_CLONE(getminor(dev));

	PMD(PMD_SX, ("ioctl: %x: begin\n", cmd))

	switch (cmd) {
	case SRN_IOC_NEXTEVENT:
	case SRN_IOC_SUSPEND:
	case SRN_IOC_RESUME:
	case SRN_IOC_AUTOSX:
		break;
	default:
		return (ENOTTY);
	}

	if (!srn_perms(SU | SG, srn.srn_cred[clone])) {
		return (EPERM);
	}
	switch (cmd) {
	case SRN_IOC_AUTOSX:
		PMD(PMD_SX, ("SRN_IOC_AUTOSX entered\n"))
		mutex_enter(&srn_clone_lock);
		if (!srn.srn_clones[clone]) {
			PMD(PMD_SX, (" ioctl !srn_clones--EINVAL\n"))
			mutex_exit(&srn_clone_lock);
			return (EINVAL);
		}
		if (srn.srn_pending[clone].ae_type) {
			PMD(PMD_SX, ("AUTOSX while pending--EBUSY\n"))
			mutex_exit(&srn_clone_lock);
			return (EBUSY);
		}
		if (srn.srn_type[clone] == SRN_TYPE_AUTOSX) {
			PMD(PMD_SX, ("AUTOSX already--EBUSY\n"))
			mutex_exit(&srn_clone_lock);
			return (EBUSY);
		}
		ASSERT(srn.srn_type[clone] == SRN_TYPE_APM);
		srn.srn_type[clone] = SRN_TYPE_AUTOSX;
		srn.srn_fault[clone] = 0;
		srn_apm_count--;
		ASSERT(srn_apm_count >= 0);
		ASSERT(srn_autosx_count >= 0);
		srn_autosx_count++;
		mutex_exit(&srn_clone_lock);
		PMD(PMD_SX, ("SRN_IOC_AUTOSX returns success\n"))
		return (0);

	case SRN_IOC_NEXTEVENT:
		/*
		 * return the next suspend or resume event;  there should
		 * be one, cause we only get called if we've signalled a
		 * poll data completion
		 * then wake up the kernel thread sleeping for the delivery
		 */
		PMD(PMD_SX, ("SRN_IOC_NEXTEVENT entered\n"))
		if (srn.srn_fault[clone]) {
			PMD(PMD_SX, ("SRN_IOC_NEXTEVENT clone %d fault "
			    "cleared\n", clone))
			srn.srn_fault[clone] = 0;
		}
		mutex_enter(&srn_clone_lock);
		if (srn_poll_cnt[clone] == 0) {
			mutex_exit(&srn_clone_lock);
			PMD(PMD_SX, ("SRN_IOC_NEXTEVENT clone %d "
			    "EWOULDBLOCK\n", clone))
			return (EWOULDBLOCK);
		}
		ASSERT(srn.srn_pending[clone].ae_type);
		if (ddi_copyout(&srn.srn_pending[clone], (void *)arg,
		    sizeof (srn_event_info_t), mode) != 0) {
			mutex_exit(&srn_clone_lock);
			PMD(PMD_SX, ("SRN_IOC_NEXTEVENT clone %d EFAULT\n",
			    clone))
			return (EFAULT);
		}
		if (srn.srn_type[clone] == SRN_TYPE_APM)
			srn.srn_delivered[clone] =
			    srn.srn_pending[clone].ae_type;
		PMD(PMD_SX, ("SRN_IOC_NEXTEVENT clone %d delivered %x\n",
		    clone, srn.srn_pending[clone].ae_type))
		srn_poll_cnt[clone] = 0;
		mutex_exit(&srn_clone_lock);
		return (0);

	case SRN_IOC_SUSPEND:
		/* ack suspend */
		PMD(PMD_SX, ("SRN_IOC_SUSPEND entered clone %d\n", clone))
		if (srn.srn_fault[clone]) {
			PMD(PMD_SX, ("SRN_IOC_SUSPEND clone %d fault "
			    "cleared\n", clone))
			srn.srn_fault[clone] = 0;
		}
		mutex_enter(&srn_clone_lock);
		if (srn.srn_delivered[clone] != SRN_SUSPEND_REQ) {
			mutex_exit(&srn_clone_lock);
			PMD(PMD_SX, ("SRN_IOC_SUSPEND EINVAL\n"))
			return (EINVAL);
		}
		srn.srn_delivered[clone] = 0;
		srn.srn_pending[clone].ae_type = 0;
		/* notify the kernel suspend thread  to continue */
		PMD(PMD_SX, ("SRN_IOC_SUSPEND clone %d ok\n", clone))
		cv_signal(&srn_clones_cv[clone]);
		mutex_exit(&srn_clone_lock);
		return (0);

	case SRN_IOC_RESUME:
		/* ack resume */
		PMD(PMD_SX, ("SRN_IOC_RESUME entered clone %d\n", clone))
		if (srn.srn_fault[clone]) {
			PMD(PMD_SX, ("SRN_IOC_RESUME clone %d fault "
			    "cleared\n", clone))
			srn.srn_fault[clone] = 0;
		}
		mutex_enter(&srn_clone_lock);
		if (srn.srn_delivered[clone] != SRN_NORMAL_RESUME) {
			mutex_exit(&srn_clone_lock);
			PMD(PMD_SX, ("SRN_IOC_RESUME EINVAL\n"))
			return (EINVAL);
		}
		srn.srn_delivered[clone] = 0;
		srn.srn_pending[clone].ae_type = 0;
		/* notify the kernel resume thread  to continue */
		PMD(PMD_SX, ("SRN_IOC_RESUME ok for clone %d\n", clone))
		cv_signal(&srn_clones_cv[clone]);
		mutex_exit(&srn_clone_lock);
		return (0);

	default:
		PMD(PMD_SX, ("srn_ioctl unknown cmd EINVAL\n"))
		return (EINVAL);
	}
}
/*
 * A very simple handshake with the srn driver,
 * only one outstanding event at a time.
 * The OS delivers the event and depending on type,
 * either blocks waiting for the ack, or drives on
 */
void
srn_notify(int type, int event)
{
	int clone, count;
	PMD(PMD_SX, ("srn_notify entered with type %d, event 0x%x\n",
	    type, event));
	ASSERT(mutex_owned(&srn_clone_lock));
	switch (type) {
	case SRN_TYPE_APM:
		if (srn_apm_count == 0) {
			PMD(PMD_SX, ("no apm types\n"))
			return;
		}
		count = srn_apm_count;
		break;
	case SRN_TYPE_AUTOSX:
		if (srn_autosx_count == 0) {
			PMD(PMD_SX, ("no autosx types\n"))
			return;
		}
		count = srn_autosx_count;
		break;
	default:
		ASSERT(0);
		break;
	}
	ASSERT(count > 0);
	PMD(PMD_SX, ("count %d\n", count))
	for (clone = 0; clone < SRN_MAX_CLONE; clone++) {
		if (srn.srn_type[clone] == type) {
#ifdef DEBUG
			if (type == SRN_TYPE_APM && !srn.srn_fault[clone]) {
				ASSERT(srn.srn_pending[clone].ae_type == 0);
				ASSERT(srn_poll_cnt[clone] == 0);
				ASSERT(srn.srn_delivered[clone] == 0);
			}
#endif
			srn.srn_pending[clone].ae_type = event;
			srn_poll_cnt[clone] = 1;
			PMD(PMD_SX, ("pollwake %d\n", clone))
			pollwakeup(&srn_pollhead[clone], (POLLRDNORM | POLLIN));
			count--;
			if (count == 0)
				break;
		}
	}
	if (type == SRN_TYPE_AUTOSX) {		/* we don't wait */
		PMD(PMD_SX, ("Not waiting for AUTOSX ack\n"))
		return;
	}
	ASSERT(type == SRN_TYPE_APM);
	/* otherwise wait for acks */
restart:
	/*
	 * We wait until all of the pending events are cleared.
	 * We have to start over every time we do a cv_wait because
	 * we give up the mutex and can be re-entered
	 */
	for (clone = 1; clone < SRN_MAX_CLONE; clone++) {
		if (srn.srn_clones[clone] == 0 ||
		    srn.srn_type[clone] != SRN_TYPE_APM)
			continue;
		if (srn.srn_pending[clone].ae_type && !srn.srn_fault[clone]) {
			PMD(PMD_SX, ("srn_notify waiting for ack for clone %d, "
			    "event %x\n", clone, event))
			if (cv_timedwait(&srn_clones_cv[clone],
			    &srn_clone_lock, ddi_get_lbolt() +
			    drv_usectohz(srn_timeout * 1000000)) == -1) {
				/*
				 * Client didn't respond, mark it as faulted
				 * and continue as if a regular signal.
				 */
				PMD(PMD_SX, ("srn_notify: clone %d did not "
				    "ack event %x\n", clone, event))
				cmn_err(CE_WARN, "srn_notify: clone %d did "
				    "not ack event %x\n", clone, event);
				srn.srn_fault[clone] = 1;
			}
			goto restart;
		}
	}
	PMD(PMD_SX, ("srn_notify done with %x\n", event))
}
