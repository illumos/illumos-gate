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

/*
 *	This file contains interface code to make the kernel look it has
 *      an svr4.2 ddi/ddk. It also adds a little other system dependent
 *      functionality that is useful for drivers lower than nsctl.
 */

#include <sys/types.h>
#ifndef DS_DDICT
#include <sys/time.h>		/* only DDI compliant as of 5.9 */
#endif
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#ifndef DS_DDICT
#include <sys/vnode.h>
#endif
#include <sys/open.h>
#include <sys/ddi.h>

#include "nsc_thread.h"

#ifdef DS_DDICT
#include <sys/nsctl/contract.h>
#endif

#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/nsvers.h>
#include "nskernd.h"
#include "nsc_list.h"

kmutex_t _nskern_lock;

void _nsc_stop_proc(void);
void _nsc_start_proc(void);


/*
 * Solaris specific driver module interface code.
 */

static struct cb_ops nskern_cb_ops = {
	nulldev,	/* open */
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	nodev,		/* ioctl */
	nodev,		/* devmap routine */
	nodev,		/* mmap routine */
	nodev,		/* segmap */
	nochpoll,	/* chpoll */
	ddi_prop_op,
	0,		/* not a STREAMS driver, no cb_str routine */
	D_NEW | D_MP | D_64BIT,	/* safe for multi-thread/multi-processor */
	CB_REV,
	nodev,		/* aread */
	nodev,		/* awrite */
};

static int _nskern_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int _nskern_attach(dev_info_t *, ddi_attach_cmd_t);
static int _nskern_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops nskern_ops = {
	DEVO_REV,			/* Driver build version */
	0,				/* device reference count */
	_nskern_getinfo,
	nulldev,			/* identify */
	nulldev,			/* probe */
	_nskern_attach,
	_nskern_detach,
	nodev,				/* reset */
	&nskern_cb_ops,
	(struct bus_ops *)NULL
};

static struct modldrv nskern_ldrv = {
	&mod_driverops,
	"nws:Kernel Interface:" ISS_VERSION_STR,
	&nskern_ops
};

static dev_info_t *nskern_dip;

static struct modlinkage nskern_modlinkage = {
	MODREV_1,
	&nskern_ldrv,
	NULL
};

/*
 * Solaris module load time code
 */

int
_init(void)
{
	void nskern_init();
	int err;

	mutex_init(&_nskern_lock, NULL, MUTEX_DRIVER, NULL);

	err = mod_install(&nskern_modlinkage);
	if (err) {
		mutex_destroy(&_nskern_lock);
		cmn_err(CE_WARN, "nskern_init: mod_install err %d", err);
		return (err);
	}

	nskern_init();

	return (DDI_SUCCESS);
}

/*
 * Solaris module unload time code
 */

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&nskern_modlinkage)) == 0) {
		nskernd_stop();
		_nsc_stop_proc();
		nskernd_deinit();

		mutex_destroy(&_nskern_lock);
	}

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&nskern_modlinkage, modinfop));
}

/*
 * Attach an instance of the device. This happens before an open
 * can succeed.
 */

static int
_nskern_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd == DDI_ATTACH) {
		nskern_dip = dip;
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}

/* ARGSUSED */

static int
_nskern_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_DETACH) {
		nskern_dip = NULL;
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}

/* ARGSUSED */
static int
_nskern_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int rc = DDI_FAILURE;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = nskern_dip;
		rc = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		/* single instance */
		*result = 0;
		rc = DDI_SUCCESS;
		break;
	}

	return (rc);
}

/* ARGSUSED */

int
_nskern_print(dev_t dev, char *s)
{
	cmn_err(CE_WARN, "nskern:%s", s);
	return (0);
}

/*
 * nskern_init - initialize the nskern layer at module load time.
 */

void
nskern_init(void)
{
	_nsc_start_proc();
	nskernd_init();

	(void) nst_startup();
}


#if (defined(DS_DDICT))
static clock_t
nskern_lbolt(void)
{
#ifdef _SunOS_5_6
	clock_t lbolt;

	if (drv_getparm(LBOLT, &lbolt) == 0)
		return (lbolt);

	return (0);
#else
	return (ddi_get_lbolt());
#endif
}
#endif	/* ddict */


/*
 * nsc_usec()
 *	- return the value of the "microsecond timer emulation".
 *
 * Pre-SunOS 5.9:
 * Actually this is a fake free running counter based on the lbolt value.
 *
 * SunOS 5.9+
 * This is based on the gethrtime(9f) DDI facility.
 */

#if (defined(DS_DDICT))
/* these two #defines need to match! */
#define	USEC_SHIFT	16
#define	INCR_TYPE	uint16_t
#endif /* ! _SunOS_5_9+ */

clock_t
nsc_usec(void)
{
	/* avoid divide by zero */
	return (gethrtime() / 1000);
}


/*
 * nsc_yield - yield the cpu.
 */
void
nsc_yield(void)
{
	/* can't call yield() unless there is an lwp context */
	/* do this for now */

	delay(2);
}


/*
 * void
 * ls_ins_before(ls_elt_t *, ls_elt_t *)
 *	Link new into list before old.
 *
 * Calling/Exit State:
 *	None.
 */
#ifdef lint
void
nsc_ddi_ls_ins_before(ls_elt_t *old, ls_elt_t *new)
#else
void
ls_ins_before(ls_elt_t *old, ls_elt_t *new)
#endif
{
	new->ls_prev = old->ls_prev;
	new->ls_next = old;
	new->ls_prev->ls_next = new;
	new->ls_next->ls_prev = new;
}

/*
 * void
 * ls_ins_after(ls_elt_t *, ls_elt_t *)
 *	Link new into list after old.
 *
 * Calling/Exit State:
 *	None.
 */
#ifdef lint
void
nsc_ddi_ls_ins_after(ls_elt_t *old, ls_elt_t *new)
#else
void
ls_ins_after(ls_elt_t *old, ls_elt_t *new)
#endif
{
	new->ls_next = old->ls_next;
	new->ls_prev = old;
	new->ls_next->ls_prev = new;
	new->ls_prev->ls_next = new;
}

/*
 * ls_elt_t *
 * ls_remque(ls_elt_t *)
 *	Unlink first element in the specified list.
 *
 * Calling/Exit State:
 *	Returns the element's address or 0 if list is empty.
 *	Resets elements pointers to empty list state.
 */
ls_elt_t *
ls_remque(ls_elt_t *p)
{
	ls_elt_t *result = 0;

	if (!LS_ISEMPTY(p)) {
		result = p->ls_next;
		result->ls_prev->ls_next = result->ls_next;
		result->ls_next->ls_prev = result->ls_prev;
		LS_INIT(result);
	}
	return (result);
}

/*
 * void
 * ls_remove(ls_elt_t *)
 *	Unlink donated element for list.
 *
 * Calling/Exit State:
 *	Resets elements pointers to empty list state.
 */
#ifdef lint
void
nsc_ddi_ls_remove(ls_elt_t *p)
#else
void
ls_remove(ls_elt_t *p)
#endif
{
	p->ls_prev->ls_next = p->ls_next;
	p->ls_next->ls_prev = p->ls_prev;
	LS_INIT(p);
}
