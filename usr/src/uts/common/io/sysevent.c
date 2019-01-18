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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * Sysevent Driver for GPEC
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/open.h>		/* OTYP_CHR definition */
#include <sys/sysmacros.h>	/* L_BITSMINOR definition */
#include <sys/bitmap.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>

static dev_info_t *sysevent_devi;

/* Definitions for binding handle array */
static ulong_t sysevent_bitmap_initial = 1;	/* index 0 indicates error */
static ulong_t *sysevent_minor_bitmap = &sysevent_bitmap_initial;
static size_t sysevent_minor_bits = BT_NBIPUL;
static kmutex_t sysevent_minor_mutex;

/*
 * evchan_ctl acts as a container for the binding handle
 */
typedef struct evchan_ctl {
	evchan_t *chp;
} evchan_ctl_t;

static void *evchan_ctlp;

/*
 * Check if it's a null terminated array - to avoid DoS attack
 * It is supposed that string points to an array with
 * a minimum length of len. len must be strlen + 1.
 * Checks for printable characters are already done in library.
 */
static int
sysevent_isstrend(char *string, size_t len)
{
	/* Return 0 if string has length of zero */
	if (len > 0) {
		return (string[len - 1] == '\0' ? 1 : 0);
	} else {
		return (0);
	}
}

/*
 * Following sysevent_minor_* routines map
 * a binding handle (evchan_t *) to a minor number
 * Has to be called w/ locks held.
 */
static ulong_t *
sysevent_minor_alloc(void)
{
	ulong_t *bhst = sysevent_minor_bitmap;

	/* Increase bitmap by one BT_NBIPUL */
	if (sysevent_minor_bits + BT_NBIPUL > SYSEVENT_MINOR_MAX) {
		return ((ulong_t *)NULL);
	}
	sysevent_minor_bitmap = kmem_zalloc(
	    BT_SIZEOFMAP(sysevent_minor_bits + BT_NBIPUL), KM_SLEEP);
	bcopy(bhst, sysevent_minor_bitmap, BT_SIZEOFMAP(sysevent_minor_bits));
	if (bhst != &sysevent_bitmap_initial)
		kmem_free(bhst, BT_SIZEOFMAP(sysevent_minor_bits));
	sysevent_minor_bits += BT_NBIPUL;

	return (sysevent_minor_bitmap);
}

static void
sysevent_minor_free(ulong_t *bitmap)
{
	if (bitmap != &sysevent_bitmap_initial)
		kmem_free(bitmap, BT_SIZEOFMAP(sysevent_minor_bits));
}

static index_t
sysevent_minor_get(void)
{
	index_t idx;
	ulong_t *bhst;

	/* Search for an available index */
	mutex_enter(&sysevent_minor_mutex);
	if ((idx = bt_availbit(sysevent_minor_bitmap,
	    sysevent_minor_bits)) == -1) {
		/* All busy - allocate additional binding handle bitmap space */
		if ((bhst = sysevent_minor_alloc()) == NULL) {
			/* Reached our maximum of id's == SHRT_MAX */
			mutex_exit(&sysevent_minor_mutex);
			return (0);
		} else {
			sysevent_minor_bitmap = bhst;
		}
		idx = bt_availbit(sysevent_minor_bitmap, sysevent_minor_bits);
	}
	BT_SET(sysevent_minor_bitmap, idx);
	mutex_exit(&sysevent_minor_mutex);
	return (idx);
}

static void
sysevent_minor_rele(index_t idx)
{
	mutex_enter(&sysevent_minor_mutex);
	ASSERT(BT_TEST(sysevent_minor_bitmap, idx) == 1);
	BT_CLEAR(sysevent_minor_bitmap, idx);
	mutex_exit(&sysevent_minor_mutex);
}

static void
sysevent_minor_init(void)
{
	mutex_init(&sysevent_minor_mutex, NULL, MUTEX_DEFAULT, NULL);
}

/* ARGSUSED */
static int
sysevent_publish(dev_t dev, int *rvalp, void *arg, int flag, cred_t *cr)
{
	int km_flags;
	sev_publish_args_t uargs;
	sysevent_impl_t *ev;
	evchan_ctl_t *ctl;

	ctl = ddi_get_soft_state(evchan_ctlp, getminor(dev));
	if (ctl == NULL || ctl->chp == NULL)
		return (ENXIO);

	if (copyin(arg, &uargs, sizeof (sev_publish_args_t)) != 0)
		return (EFAULT);

	/*
	 * This limits the size of an event
	 */
	if (uargs.ev.len > MAX_EV_SIZE_LEN)
		return (EOVERFLOW);

	/*
	 * Check for valid uargs.flags
	 */
	if (uargs.flags & ~(EVCH_NOSLEEP | EVCH_SLEEP | EVCH_QWAIT))
		return (EINVAL);

	/*
	 * Check that at least one of EVCH_NOSLEEP or EVCH_SLEEP is
	 * specified
	 */
	km_flags = uargs.flags & (EVCH_NOSLEEP | EVCH_SLEEP);
	if (km_flags != EVCH_NOSLEEP && km_flags != EVCH_SLEEP)
		return (EINVAL);

	ev = evch_usrallocev(uargs.ev.len, uargs.flags);

	if (copyin((void *)(uintptr_t)uargs.ev.name, ev, uargs.ev.len) != 0) {
		evch_usrfreeev(ev);
		return (EFAULT);
	}

	return (evch_usrpostevent(ctl->chp, ev, uargs.flags));

	/* Event will be freed internally */
}

/*
 * sysevent_chan_open - used to open a channel in the GPEC channel layer
 */

/* ARGSUSED */
static int
sysevent_chan_open(dev_t dev, int *rvalp, void *arg, int flag, cred_t *cr)
{
	sev_bind_args_t uargs;
	evchan_ctl_t *ctl;
	char *chan_name;
	int ec;

	ctl = ddi_get_soft_state(evchan_ctlp, getminor(dev));
	if (ctl == NULL) {
		return (ENXIO);
	}

	if (copyin(arg, &uargs, sizeof (sev_bind_args_t)) != 0)
		return (EFAULT);

	if (uargs.chan_name.len > MAX_CHNAME_LEN)
		return (EINVAL);

	chan_name = kmem_alloc(uargs.chan_name.len, KM_SLEEP);

	if (copyin((void *)(uintptr_t)uargs.chan_name.name, chan_name,
	    uargs.chan_name.len) != 0) {
		kmem_free(chan_name, uargs.chan_name.len);
		return (EFAULT);
	}

	if (!sysevent_isstrend(chan_name, uargs.chan_name.len)) {
		kmem_free(chan_name, uargs.chan_name.len);
		return (EINVAL);
	}

	/*
	 * Check of uargs.flags and uargs.perms just to avoid DoS attacks.
	 * libsysevent does this carefully
	 */
	ctl->chp = evch_usrchanopen((const char *)chan_name,
	    uargs.flags & EVCH_B_FLAGS, &ec);

	kmem_free(chan_name, uargs.chan_name.len);

	if (ec != 0) {
		return (ec);
	}

	return (0);
}

/* ARGSUSED */
static int
sysevent_chan_control(dev_t dev, int *rvalp, void *arg, int flag, cred_t *cr)
{
	sev_control_args_t uargs;
	evchan_ctl_t *ctl;
	int rc;

	ctl = ddi_get_soft_state(evchan_ctlp, getminor(dev));
	if (ctl == NULL || ctl->chp == NULL)
		return (ENXIO);

	if (copyin(arg, &uargs, sizeof (sev_control_args_t)) != 0)
		return (EFAULT);

	switch (uargs.cmd) {
	case EVCH_GET_CHAN_LEN:
	case EVCH_GET_CHAN_LEN_MAX:
		rc = evch_usrcontrol_get(ctl->chp, uargs.cmd, &uargs.value);
		if (rc == 0) {
			if (copyout((void *)&uargs, arg,
			    sizeof (sev_control_args_t)) != 0) {
				rc = EFAULT;
			}
		}
		break;
	case EVCH_SET_CHAN_LEN:
		rc = evch_usrcontrol_set(ctl->chp, uargs.cmd, uargs.value);
		break;
	default:
		rc = EINVAL;
	}
	return (rc);
}

/* ARGSUSED */
static int
sysevent_subscribe(dev_t dev, int *rvalp, void *arg, int flag, cred_t *cr)
{
	sev_subscribe_args_t uargs;
	char *sid;
	char *class_info = NULL;
	evchan_ctl_t *ctl;
	int rc;

	ctl = ddi_get_soft_state(evchan_ctlp, getminor(dev));
	if (ctl == NULL || ctl->chp == NULL)
		return (ENXIO);

	if (copyin(arg, &uargs, sizeof (sev_subscribe_args_t)) != 0)
		return (EFAULT);

	if (uargs.sid.len > MAX_SUBID_LEN ||
	    uargs.class_info.len > MAX_CLASS_LEN)
		return (EINVAL);

	sid = kmem_alloc(uargs.sid.len, KM_SLEEP);
	if (copyin((void *)(uintptr_t)uargs.sid.name,
	    sid, uargs.sid.len) != 0) {
		kmem_free(sid, uargs.sid.len);
		return (EFAULT);
	}
	if (!sysevent_isstrend(sid, uargs.sid.len)) {
		kmem_free(sid, uargs.sid.len);
		return (EINVAL);
	}

	/* If class string empty then class EC_ALL is assumed */
	if (uargs.class_info.len != 0) {
		class_info = kmem_alloc(uargs.class_info.len, KM_SLEEP);
		if (copyin((void *)(uintptr_t)uargs.class_info.name, class_info,
		    uargs.class_info.len) != 0) {
			kmem_free(class_info, uargs.class_info.len);
			kmem_free(sid, uargs.sid.len);
			return (EFAULT);
		}
		if (!sysevent_isstrend(class_info, uargs.class_info.len)) {
			kmem_free(class_info, uargs.class_info.len);
			kmem_free(sid, uargs.sid.len);
			return (EINVAL);
		}
	}

	/*
	 * Check of uargs.flags just to avoid DoS attacks
	 * libsysevent does this carefully.
	 */
	rc = evch_usrsubscribe(ctl->chp, sid, class_info,
	    (int)uargs.door_desc, uargs.flags);

	kmem_free(class_info, uargs.class_info.len);
	kmem_free(sid, uargs.sid.len);

	return (rc);
}

/* ARGSUSED */
static int
sysevent_unsubscribe(dev_t dev, int *rvalp, void *arg, int flag, cred_t *cr)
{
	sev_unsubscribe_args_t uargs;
	char *sid;
	evchan_ctl_t *ctl;

	if (copyin(arg, &uargs, sizeof (sev_unsubscribe_args_t)) != 0)
		return (EFAULT);

	ctl = ddi_get_soft_state(evchan_ctlp, getminor(dev));
	if (ctl == NULL || ctl->chp == NULL)
		return (ENXIO);

	if (uargs.sid.len > MAX_SUBID_LEN)
		return (EINVAL);

	/* Unsubscribe for all */
	if (uargs.sid.len == 0) {
		evch_usrunsubscribe(ctl->chp, NULL, 0);
		return (0);
	}

	sid = kmem_alloc(uargs.sid.len, KM_SLEEP);

	if (copyin((void *)(uintptr_t)uargs.sid.name,
	    sid, uargs.sid.len) != 0) {
		kmem_free(sid, uargs.sid.len);
		return (EFAULT);
	}

	evch_usrunsubscribe(ctl->chp, sid, 0);

	kmem_free(sid, uargs.sid.len);

	return (0);
}

/* ARGSUSED */
static int
sysevent_channames(dev_t dev, int *rvalp, void *arg, int flag, cred_t *cr)
{
	sev_chandata_args_t uargs;
	char *buf;
	int len;
	int rc = 0;

	if (copyin(arg, &uargs, sizeof (sev_chandata_args_t)) != 0)
		return (EFAULT);

	if (uargs.out_data.len == 0 || uargs.out_data.len > EVCH_MAX_DATA_SIZE)
		return (EINVAL);

	buf = kmem_alloc(uargs.out_data.len, KM_SLEEP);

	if ((len = evch_usrgetchnames(buf, uargs.out_data.len)) == -1) {
		rc = EOVERFLOW;
	}

	if (rc == 0) {
		ASSERT(len <= uargs.out_data.len);
		if (copyout(buf,
		    (void *)(uintptr_t)uargs.out_data.name, len) != 0) {
			rc = EFAULT;
		}
	}

	kmem_free(buf, uargs.out_data.len);

	return (rc);
}

/* ARGSUSED */
static int
sysevent_chandata(dev_t dev, int *rvalp, void *arg, int flag, cred_t *cr)
{
	sev_chandata_args_t uargs;
	char *channel;
	char *buf;
	int len;
	int rc = 0;

	if (copyin(arg, &uargs, sizeof (sev_chandata_args_t)) != 0)
		return (EFAULT);

	if (uargs.in_data.len > MAX_CHNAME_LEN ||
	    uargs.out_data.len > EVCH_MAX_DATA_SIZE)
		return (EINVAL);

	channel = kmem_alloc(uargs.in_data.len, KM_SLEEP);

	if (copyin((void *)(uintptr_t)uargs.in_data.name, channel,
	    uargs.in_data.len) != 0) {
		kmem_free(channel, uargs.in_data.len);
		return (EFAULT);
	}

	if (!sysevent_isstrend(channel, uargs.in_data.len)) {
		kmem_free(channel, uargs.in_data.len);
		return (EINVAL);
	}

	buf = kmem_alloc(uargs.out_data.len, KM_SLEEP);

	len = evch_usrgetchdata(channel, buf, uargs.out_data.len);
	if (len == 0) {
		rc = EOVERFLOW;
	} else if (len == -1) {
		rc = ENOENT;
	}

	if (rc == 0) {
		ASSERT(len <= uargs.out_data.len);
		if (copyout(buf,
		    (void *)(uintptr_t)uargs.out_data.name, len) != 0) {
			rc = EFAULT;
		}
	}

	kmem_free(buf, uargs.out_data.len);
	kmem_free(channel, uargs.in_data.len);

	return (rc);
}

/* ARGSUSED */
static int
sysevent_setpropnvl(dev_t dev, int *rvalp, void *arg, int flag, cred_t *cr)
{
	sev_propnvl_args_t uargs;
	nvlist_t *nvl = NULL;
	evchan_ctl_t *ctl;
	size_t bufsz;
	char *buf;

	ctl = ddi_get_soft_state(evchan_ctlp, getminor(dev));
	if (ctl == NULL || ctl->chp == NULL)
		return (ENXIO);

	if (copyin(arg, &uargs, sizeof (uargs)) != 0)
		return (EFAULT);

	if (uargs.packednvl.name != 0) {
		bufsz = uargs.packednvl.len;

		if (bufsz == 0)
			return (EINVAL);

		if (bufsz > EVCH_MAX_DATA_SIZE)
			return (EOVERFLOW);

		buf = kmem_alloc(bufsz, KM_SLEEP);

		if (copyin((void *)(uintptr_t)uargs.packednvl.name, buf,
		    bufsz) != 0 ||
		    nvlist_unpack(buf, bufsz, &nvl, KM_SLEEP) != 0) {
			kmem_free(buf, bufsz);
			return (EFAULT);
		}

		kmem_free(buf, bufsz);

		if (nvl == NULL)
			return (EINVAL);
	}

	evch_usrsetpropnvl(ctl->chp, nvl);
	return (0);
}

/* ARGSUSED */
static int
sysevent_getpropnvl(dev_t dev, int *rvalp, void *arg, int flag, cred_t *cr)
{
	sev_propnvl_args_t uargs;
	size_t reqsz, avlsz;
	evchan_ctl_t *ctl;
	nvlist_t *nvl;
	int64_t gen;
	int rc;

	ctl = ddi_get_soft_state(evchan_ctlp, getminor(dev));

	if (ctl == NULL || ctl->chp == NULL)
		return (ENXIO);

	if (copyin(arg, &uargs, sizeof (uargs)) != 0)
		return (EFAULT);

	if ((rc = evch_usrgetpropnvl(ctl->chp, &nvl, &gen)) != 0)
		return (rc);

	if (nvl != NULL) {
		avlsz = uargs.packednvl.len;

		if (nvlist_size(nvl, &reqsz, NV_ENCODE_NATIVE) != 0) {
			nvlist_free(nvl);
			return (EINVAL);
		}

		if (reqsz > EVCH_MAX_DATA_SIZE) {
			nvlist_free(nvl);
			return (E2BIG);
		}

		if (reqsz <= avlsz) {
			char *buf = kmem_alloc(reqsz, KM_SLEEP);

			if (nvlist_pack(nvl, &buf, &reqsz,
			    NV_ENCODE_NATIVE, 0) != 0 || copyout(buf,
			    (void *)(uintptr_t)uargs.packednvl.name,
			    reqsz) != 0) {
				kmem_free(buf, reqsz);
				nvlist_free(nvl);
				return (EFAULT);
			}
			kmem_free(buf, reqsz);
			rc = 0;
		} else {
			rc = EOVERFLOW;
		}
		uargs.packednvl.len = (uint32_t)reqsz;
		nvlist_free(nvl);
	} else {
		uargs.packednvl.len = 0;
		rc = 0;
	}

	uargs.generation = gen;
	if (copyout((void *)&uargs, arg, sizeof (uargs)) != 0)
		rc = EFAULT;

	return (rc);
}

/*ARGSUSED*/
static int
sysevent_ioctl(dev_t dev, int cmd, intptr_t arg,
    int flag, cred_t *cr, int *rvalp)
{
	int rc;

	switch (cmd) {
	case SEV_PUBLISH:
		rc = sysevent_publish(dev, rvalp, (void *)arg, flag, cr);
		break;
	case SEV_CHAN_OPEN:
		rc = sysevent_chan_open(dev, rvalp, (void *)arg, flag, cr);
		break;
	case SEV_CHAN_CONTROL:
		rc = sysevent_chan_control(dev, rvalp, (void *)arg, flag, cr);
		break;
	case SEV_SUBSCRIBE:
		rc = sysevent_subscribe(dev, rvalp, (void *)arg, flag, cr);
		break;
	case SEV_UNSUBSCRIBE:
		rc = sysevent_unsubscribe(dev, rvalp, (void *)arg, flag, cr);
		break;
	case SEV_CHANNAMES:
		rc = sysevent_channames(dev, rvalp, (void *)arg, flag, cr);
		break;
	case SEV_CHANDATA:
		rc = sysevent_chandata(dev, rvalp, (void *)arg, flag, cr);
		break;
	case SEV_SETPROPNVL:
		rc = sysevent_setpropnvl(dev, rvalp, (void *)arg, flag, cr);
		break;
	case SEV_GETPROPNVL:
		rc = sysevent_getpropnvl(dev, rvalp, (void *)arg, flag, cr);
		break;
	default:
		rc = EINVAL;
	}

	return (rc);
}

/*ARGSUSED*/
static int
sysevent_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	int minor;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (getminor(*devp) != 0)
		return (ENXIO);

	minor = sysevent_minor_get();
	if (minor == 0)
		/* All minors are busy */
		return (EBUSY);

	if (ddi_soft_state_zalloc(evchan_ctlp, minor)
	    != DDI_SUCCESS) {
		sysevent_minor_rele(minor);
		return (ENOMEM);
	}

	*devp = makedevice(getmajor(*devp), minor);

	return (0);
}

/*ARGSUSED*/
static int
sysevent_close(dev_t dev, int flag, int otyp, cred_t *cr)
{
	int minor = (int)getminor(dev);
	evchan_ctl_t *ctl;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	ctl = ddi_get_soft_state(evchan_ctlp, minor);
	if (ctl == NULL) {
		return (ENXIO);
	}

	if (ctl->chp) {
		/* Release all non-persistant subscriptions */
		evch_usrunsubscribe(ctl->chp, NULL, EVCH_SUB_KEEP);
		evch_usrchanclose(ctl->chp);
	}

	ddi_soft_state_free(evchan_ctlp, minor);
	sysevent_minor_rele(minor);

	return (0);
}

/* ARGSUSED */
static int
sysevent_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = sysevent_devi;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
sysevent_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "sysevent", S_IFCHR,
	    0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	sysevent_devi = devi;

	sysevent_minor_init();

	return (DDI_SUCCESS);
}

static int
sysevent_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	sysevent_minor_free(sysevent_minor_bitmap);
	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

static struct cb_ops sysevent_cb_ops = {
	.cb_open = sysevent_open,
	.cb_close = sysevent_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = sysevent_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_str = NULL,
	.cb_flag = D_NEW | D_MP,
	.cb_rev = CB_REV,
	.cb_aread = NULL,
	.cb_awrite = NULL
};

static struct dev_ops sysevent_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	sysevent_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sysevent_attach,	/* attach */
	sysevent_detach,	/* detach */
	nodev,			/* reset */
	&sysevent_cb_ops,	/* driver operations */
	NULL,			/* no bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, "sysevent driver", &sysevent_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int s;

	s = ddi_soft_state_init(&evchan_ctlp, sizeof (evchan_ctl_t), 1);
	if (s != 0)
		return (s);

	if ((s = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&evchan_ctlp);
	return (s);
}

int
_fini(void)
{
	int s;

	if ((s = mod_remove(&modlinkage)) != 0)
		return (s);

	ddi_soft_state_fini(&evchan_ctlp);
	return (s);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
