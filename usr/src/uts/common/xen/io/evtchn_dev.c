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
 * evtchn.c
 *
 * Driver for receiving and demuxing event-channel signals.
 *
 * Copyright (c) 2004-2005, K A Fraser
 * Multi-process extensions Copyright (c) 2004, Steven Smith
 *
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <sys/types.h>
#include <sys/hypervisor.h>
#include <sys/machsystm.h>
#include <sys/mutex.h>
#include <sys/evtchn_impl.h>
#include <sys/ddi_impldefs.h>
#include <sys/avintr.h>
#include <sys/cpuvar.h>
#include <sys/smp_impldefs.h>
#include <sys/archsystm.h>
#include <sys/sysmacros.h>
#include <sys/fcntl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/psm.h>
#include <sys/cpu.h>
#include <sys/cmn_err.h>
#include <sys/xen_errno.h>
#include <sys/policy.h>
#include <xen/sys/evtchn.h>

/* Some handy macros */
#define	EVTCHNDRV_MINOR2INST(minor)	((int)(minor))
#define	EVTCHNDRV_DEFAULT_NCLONES 	256
#define	EVTCHNDRV_INST2SOFTS(inst)	\
	(ddi_get_soft_state(evtchndrv_statep, (inst)))

/* Soft state data structure for evtchn driver */
struct evtsoftdata {
	dev_info_t *dip;
	/* Notification ring, accessed via /dev/xen/evtchn. */
#define	EVTCHN_RING_SIZE	(PAGESIZE / sizeof (evtchn_port_t))
#define	EVTCHN_RING_MASK(_i)	((_i) & (EVTCHN_RING_SIZE - 1))
	evtchn_port_t *ring;
	unsigned int ring_cons, ring_prod, ring_overflow;

	kcondvar_t evtchn_wait; /* Processes wait on this when ring is empty. */
	kmutex_t evtchn_lock;
	struct pollhead evtchn_pollhead;

	pid_t pid;		/* last pid to bind to this event channel. */
	processorid_t cpu;	/* cpu thread/evtchn is bound to */
};

static void *evtchndrv_statep;
int evtchndrv_nclones = EVTCHNDRV_DEFAULT_NCLONES;
static int *evtchndrv_clone_tab;
static dev_info_t *evtchndrv_dip;
static kmutex_t evtchndrv_clone_tab_mutex;

static int evtchndrv_detach(dev_info_t *, ddi_detach_cmd_t);

/* Who's bound to each port? */
static struct evtsoftdata *port_user[NR_EVENT_CHANNELS];
static kmutex_t port_user_lock;

void
evtchn_device_upcall()
{
	struct evtsoftdata *ep;
	int port;

	/*
	 * This is quite gross, we had to leave the evtchn that led to this
	 * invocation in a per-cpu mailbox, retrieve it now.
	 * We do this because the interface doesn't offer us a way to pass
	 * a dynamic argument up through the generic interrupt service layer.
	 * The mailbox is safe since we either run with interrupts disabled or
	 * non-preemptable till we reach here.
	 */
	port = CPU->cpu_m.mcpu_ec_mbox;
	ASSERT(port != 0);
	CPU->cpu_m.mcpu_ec_mbox = 0;
	ec_clear_evtchn(port);
	mutex_enter(&port_user_lock);

	if ((ep = port_user[port]) != NULL) {
		mutex_enter(&ep->evtchn_lock);
		if ((ep->ring_prod - ep->ring_cons) < EVTCHN_RING_SIZE) {
			ep->ring[EVTCHN_RING_MASK(ep->ring_prod)] = port;
			/*
			 * Wake up reader when ring goes non-empty
			 */
			if (ep->ring_cons == ep->ring_prod++) {
				cv_signal(&ep->evtchn_wait);
				mutex_exit(&ep->evtchn_lock);
				pollwakeup(&ep->evtchn_pollhead,
				    POLLIN | POLLRDNORM);
				goto done;
			}
		} else {
			ep->ring_overflow = 1;
		}
		mutex_exit(&ep->evtchn_lock);
	}

done:
	mutex_exit(&port_user_lock);
}

/* ARGSUSED */
static int
evtchndrv_read(dev_t dev, struct uio *uio, cred_t *cr)
{
	int rc = 0;
	ssize_t count;
	unsigned int c, p, bytes1 = 0, bytes2 = 0;
	struct evtsoftdata *ep;
	minor_t minor = getminor(dev);

	if (secpolicy_xvm_control(cr))
		return (EPERM);

	ep = EVTCHNDRV_INST2SOFTS(EVTCHNDRV_MINOR2INST(minor));

	/* Whole number of ports. */
	count = uio->uio_resid;
	count &= ~(sizeof (evtchn_port_t) - 1);

	if (count == 0)
		return (0);

	if (count > PAGESIZE)
		count = PAGESIZE;

	mutex_enter(&ep->evtchn_lock);
	for (;;) {
		if (ep->ring_overflow) {
			rc = EFBIG;
			goto done;
		}

		if ((c = ep->ring_cons) != (p = ep->ring_prod))
			break;

		if (uio->uio_fmode & O_NONBLOCK) {
			rc = EAGAIN;
			goto done;
		}

		if (cv_wait_sig(&ep->evtchn_wait, &ep->evtchn_lock) == 0) {
			rc = EINTR;
			goto done;
		}
	}

	/* Byte lengths of two chunks. Chunk split (if any) is at ring wrap. */
	if (((c ^ p) & EVTCHN_RING_SIZE) != 0) {
		bytes1 = (EVTCHN_RING_SIZE - EVTCHN_RING_MASK(c)) *
		    sizeof (evtchn_port_t);
		bytes2 = EVTCHN_RING_MASK(p) * sizeof (evtchn_port_t);
	} else {
		bytes1 = (p - c) * sizeof (evtchn_port_t);
		bytes2 = 0;
	}

	/* Truncate chunks according to caller's maximum byte count. */
	if (bytes1 > count) {
		bytes1 = count;
		bytes2 = 0;
	} else if ((bytes1 + bytes2) > count) {
		bytes2 = count - bytes1;
	}

	if (uiomove(&ep->ring[EVTCHN_RING_MASK(c)], bytes1, UIO_READ, uio) ||
	    ((bytes2 != 0) && uiomove(&ep->ring[0], bytes2, UIO_READ, uio))) {
		rc = EFAULT;
		goto done;
	}

	ep->ring_cons += (bytes1 + bytes2) / sizeof (evtchn_port_t);
done:
	mutex_exit(&ep->evtchn_lock);
	return (rc);
}

/* ARGSUSED */
static int
evtchndrv_write(dev_t dev, struct uio *uio, cred_t *cr)
{
	int  rc, i;
	ssize_t count;
	evtchn_port_t *kbuf;
	struct evtsoftdata *ep;
	ulong_t flags;
	minor_t minor = getminor(dev);
	evtchn_port_t sbuf[32];

	if (secpolicy_xvm_control(cr))
		return (EPERM);

	ep = EVTCHNDRV_INST2SOFTS(EVTCHNDRV_MINOR2INST(minor));


	/* Whole number of ports. */
	count = uio->uio_resid;
	count &= ~(sizeof (evtchn_port_t) - 1);

	if (count == 0)
		return (0);

	if (count > PAGESIZE)
		count = PAGESIZE;

	if (count <= sizeof (sbuf))
		kbuf = sbuf;
	else
		kbuf = kmem_alloc(PAGESIZE, KM_SLEEP);
	if ((rc = uiomove(kbuf, count, UIO_WRITE, uio)) != 0)
		goto out;

	mutex_enter(&port_user_lock);
	for (i = 0; i < (count / sizeof (evtchn_port_t)); i++)
		if ((kbuf[i] < NR_EVENT_CHANNELS) &&
		    (port_user[kbuf[i]] == ep)) {
			flags = intr_clear();
			ec_unmask_evtchn(kbuf[i]);
			intr_restore(flags);
		}
	mutex_exit(&port_user_lock);

out:
	if (kbuf != sbuf)
		kmem_free(kbuf, PAGESIZE);
	return (rc);
}

static void
evtchn_bind_to_user(struct evtsoftdata *u, int port)
{
	ulong_t flags;

	/*
	 * save away the PID of the last process to bind to this event channel.
	 * Useful for debugging.
	 */
	u->pid = ddi_get_pid();

	mutex_enter(&port_user_lock);
	ASSERT(port_user[port] == NULL);
	port_user[port] = u;
	ec_irq_add_evtchn(ec_dev_irq, port);
	flags = intr_clear();
	ec_unmask_evtchn(port);
	intr_restore(flags);
	mutex_exit(&port_user_lock);
}

static void
evtchndrv_close_evtchn(int port)
{
	struct evtsoftdata *ep;

	ASSERT(MUTEX_HELD(&port_user_lock));
	ep = port_user[port];
	ASSERT(ep != NULL);
	(void) ec_mask_evtchn(port);
	/*
	 * It is possible the event is in transit to us.
	 * If it is already in the ring buffer, then a client may
	 * get a spurious event notification on the next read of
	 * of the evtchn device.  Clients will need to be able to
	 * handle getting a spurious event notification.
	 */
	port_user[port] = NULL;
	/*
	 * The event is masked and should stay so, clean it up.
	 */
	ec_irq_rm_evtchn(ec_dev_irq, port);
}

/* ARGSUSED */
static int
evtchndrv_ioctl(dev_t dev, int cmd, intptr_t data, int flag, cred_t *cr,
    int *rvalp)
{
	int err = 0;
	struct evtsoftdata *ep;
	minor_t minor = getminor(dev);

	if (secpolicy_xvm_control(cr))
		return (EPERM);

	ep = EVTCHNDRV_INST2SOFTS(EVTCHNDRV_MINOR2INST(minor));

	*rvalp = 0;

	switch (cmd) {
	case IOCTL_EVTCHN_BIND_VIRQ: {
		struct ioctl_evtchn_bind_virq bind;

		if (copyin((void *)data, &bind, sizeof (bind))) {
			err = EFAULT;
			break;
		}

		if ((err = xen_bind_virq(bind.virq, 0, rvalp)) != 0)
			break;

		evtchn_bind_to_user(ep, *rvalp);
		break;
	}

	case IOCTL_EVTCHN_BIND_INTERDOMAIN: {
		struct ioctl_evtchn_bind_interdomain bind;

		if (copyin((void *)data, &bind, sizeof (bind))) {
			err = EFAULT;
			break;
		}

		if ((err = xen_bind_interdomain(bind.remote_domain,
		    bind.remote_port, rvalp)) != 0)
			break;

		ec_bind_vcpu(*rvalp, 0);
		evtchn_bind_to_user(ep, *rvalp);
		break;
	}

	case IOCTL_EVTCHN_BIND_UNBOUND_PORT: {
		struct ioctl_evtchn_bind_unbound_port bind;

		if (copyin((void *)data, &bind, sizeof (bind))) {
			err = EFAULT;
			break;
		}

		if ((err = xen_alloc_unbound_evtchn(bind.remote_domain,
		    rvalp)) != 0)
			break;

		evtchn_bind_to_user(ep, *rvalp);
		break;
	}

	case IOCTL_EVTCHN_UNBIND: {
		struct ioctl_evtchn_unbind unbind;

		if (copyin((void *)data, &unbind, sizeof (unbind))) {
			err = EFAULT;
			break;
		}

		if (unbind.port >= NR_EVENT_CHANNELS) {
			err = EFAULT;
			break;
		}

		mutex_enter(&port_user_lock);

		if (port_user[unbind.port] != ep) {
			mutex_exit(&port_user_lock);
			err = ENOTCONN;
			break;
		}

		evtchndrv_close_evtchn(unbind.port);
		mutex_exit(&port_user_lock);
		break;
	}

	case IOCTL_EVTCHN_NOTIFY: {
		struct ioctl_evtchn_notify notify;

		if (copyin((void *)data, &notify, sizeof (notify))) {
			err = EFAULT;
			break;
		}

		if (notify.port >= NR_EVENT_CHANNELS) {
			err = EINVAL;
		} else if (port_user[notify.port] != ep) {
			err = ENOTCONN;
		} else {
			ec_notify_via_evtchn(notify.port);
		}
		break;
	}

	default:
		err = ENOSYS;
	}

	return (err);
}

static int
evtchndrv_poll(dev_t dev, short ev, int anyyet, short *revp, pollhead_t **phpp)
{
	struct evtsoftdata *ep;
	minor_t minor = getminor(dev);
	short mask = 0;

	ep = EVTCHNDRV_INST2SOFTS(EVTCHNDRV_MINOR2INST(minor));

	if (ev & POLLOUT)
		mask |= POLLOUT;
	if (ep->ring_overflow)
		mask |= POLLERR;
	if (ev & (POLLIN | POLLRDNORM)) {
		mutex_enter(&ep->evtchn_lock);
		if (ep->ring_cons != ep->ring_prod) {
			mask |= (POLLIN | POLLRDNORM) & ev;
		}
		mutex_exit(&ep->evtchn_lock);
	}
	if ((mask == 0 && !anyyet) || (ev & POLLET)) {
		*phpp = &ep->evtchn_pollhead;
	}
	*revp = mask;
	return (0);
}


/* ARGSUSED */
static int
evtchndrv_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	struct evtsoftdata *ep;
	minor_t minor = getminor(*devp);

	if (otyp == OTYP_BLK)
		return (ENXIO);

	/*
	 * only allow open on minor = 0 - the clone device
	 */
	if (minor != 0)
		return (ENXIO);

	/*
	 * find a free slot and grab it
	 */
	mutex_enter(&evtchndrv_clone_tab_mutex);
	for (minor = 1; minor < evtchndrv_nclones; minor++) {
		if (evtchndrv_clone_tab[minor] == 0) {
			evtchndrv_clone_tab[minor] = 1;
			break;
		}
	}
	mutex_exit(&evtchndrv_clone_tab_mutex);
	if (minor == evtchndrv_nclones)
		return (EAGAIN);

	/* Allocate softstate structure */
	if (ddi_soft_state_zalloc(evtchndrv_statep,
	    EVTCHNDRV_MINOR2INST(minor)) != DDI_SUCCESS) {
		mutex_enter(&evtchndrv_clone_tab_mutex);
		evtchndrv_clone_tab[minor] = 0;
		mutex_exit(&evtchndrv_clone_tab_mutex);
		return (EAGAIN);
	}
	ep = EVTCHNDRV_INST2SOFTS(EVTCHNDRV_MINOR2INST(minor));

	/* ... and init it */
	ep->dip = evtchndrv_dip;

	cv_init(&ep->evtchn_wait, NULL, CV_DEFAULT, NULL);
	mutex_init(&ep->evtchn_lock, NULL, MUTEX_DEFAULT, NULL);

	ep->ring = kmem_alloc(PAGESIZE, KM_SLEEP);

	/* clone driver */
	*devp = makedevice(getmajor(*devp), minor);

	return (0);
}

/* ARGSUSED */
static int
evtchndrv_close(dev_t dev, int flag, int otyp, struct cred *credp)
{
	struct evtsoftdata *ep;
	minor_t minor = getminor(dev);
	int i;

	ep = EVTCHNDRV_INST2SOFTS(EVTCHNDRV_MINOR2INST(minor));
	if (ep == NULL)
		return (ENXIO);

	mutex_enter(&port_user_lock);


	for (i = 0; i < NR_EVENT_CHANNELS; i++) {
		if (port_user[i] != ep)
			continue;

		evtchndrv_close_evtchn(i);
	}

	mutex_exit(&port_user_lock);

	kmem_free(ep->ring, PAGESIZE);
	ddi_soft_state_free(evtchndrv_statep, EVTCHNDRV_MINOR2INST(minor));

	/*
	 * free clone tab slot
	 */
	mutex_enter(&evtchndrv_clone_tab_mutex);
	evtchndrv_clone_tab[minor] = 0;
	mutex_exit(&evtchndrv_clone_tab_mutex);

	return (0);
}

/* ARGSUSED */
static int
evtchndrv_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t	dev = (dev_t)arg;
	minor_t	minor = getminor(dev);
	int	retval;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (minor != 0 || evtchndrv_dip == NULL) {
			*result = (void *)NULL;
			retval = DDI_FAILURE;
		} else {
			*result = (void *)evtchndrv_dip;
			retval = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		retval = DDI_SUCCESS;
		break;
	default:
		retval = DDI_FAILURE;
	}
	return (retval);
}


static int
evtchndrv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	error;
	int	unit = ddi_get_instance(dip);


	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		cmn_err(CE_WARN, "evtchn_attach: unknown cmd 0x%x\n", cmd);
		return (DDI_FAILURE);
	}

	/* DDI_ATTACH */

	/*
	 * only one instance - but we clone using the open routine
	 */
	if (ddi_get_instance(dip) > 0)
		return (DDI_FAILURE);

	mutex_init(&evtchndrv_clone_tab_mutex, NULL, MUTEX_DRIVER,
	    NULL);

	error = ddi_create_minor_node(dip, "evtchn", S_IFCHR, unit,
	    DDI_PSEUDO, NULL);
	if (error != DDI_SUCCESS)
		goto fail;

	/*
	 * save dip for getinfo
	 */
	evtchndrv_dip = dip;
	ddi_report_dev(dip);

	mutex_init(&port_user_lock, NULL, MUTEX_DRIVER, NULL);
	(void) memset(port_user, 0, sizeof (port_user));

	ec_dev_irq = ec_dev_alloc_irq();
	(void) add_avintr(NULL, IPL_EVTCHN, (avfunc)evtchn_device_upcall,
	    "evtchn_driver", ec_dev_irq, NULL, NULL, NULL, dip);

	return (DDI_SUCCESS);

fail:
	(void) evtchndrv_detach(dip, DDI_DETACH);
	return (error);
}

/*ARGSUSED*/
static int
evtchndrv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/*
	 * Don't allow detach for now.
	 */
	return (DDI_FAILURE);
}

/* Solaris driver framework */

static 	struct cb_ops evtchndrv_cb_ops = {
	evtchndrv_open,		/* cb_open */
	evtchndrv_close,	/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	evtchndrv_read,		/* cb_read */
	evtchndrv_write,	/* cb_write */
	evtchndrv_ioctl,	/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	evtchndrv_poll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* cb_stream */
	D_NEW | D_MP | D_64BIT	/* cb_flag */
};

static struct dev_ops evtchndrv_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	evtchndrv_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	evtchndrv_attach,	/* devo_attach */
	evtchndrv_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&evtchndrv_cb_ops,	/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Evtchn driver",	/* Name of the module. */
	&evtchndrv_dev_ops	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int err;

	err = ddi_soft_state_init(&evtchndrv_statep,
	    sizeof (struct evtsoftdata), 1);
	if (err)
		return (err);

	err = mod_install(&modlinkage);
	if (err)
		ddi_soft_state_fini(&evtchndrv_statep);
	else
		evtchndrv_clone_tab = kmem_zalloc(
		    sizeof (int) * evtchndrv_nclones, KM_SLEEP);
	return (err);
}

int
_fini(void)
{
	int e;

	e = mod_remove(&modlinkage);
	if (e)
		return (e);

	ddi_soft_state_fini(&evtchndrv_statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
