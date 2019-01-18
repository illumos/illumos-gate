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
 * tnf driver - provides probe control and kernel trace buffer access
 * to the user programs prex and tnfxtract.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/tnf.h>
#include <sys/debug.h>
#include <sys/devops.h>
#include <vm/as.h>
#include <vm/seg_kp.h>
#include <sys/tnf_probe.h>
#include <sys/kobj.h>

#include "tnf_buf.h"
#include "tnf_types.h"
#include "tnf_trace.h"

#ifndef NPROBE

/*
 * Each probe is independently put in the kernel, prex uses
 * __tnf_probe_list_head and __tnf_tag_list_head as pointers to linked list
 * for probes and static tnf_tag_data_t, respectively.
 * tnf used the elf relocation record to build a separate linked list for
 * the probes and tnf_tag_data_t. We will describe how the linked list for
 * __tnf_tag_list_head is made, the probe list is very similar.
 * During the dynamic relocation(in uts/sparc/krtld/kobj_reloc.c),
 * the &__tnf_tag_version_1(the first member in tnf_tag_data_t data struct)
 * (and since it is a global variable which was never defined) will be filled
 * with 0. The following code in kobj_reloc.c will get the address of current
 * __tnf_tag_list_head and put it in value_p:
 *   #define TAG_MARKER_SYMBOL       "__tnf_tag_version_1"
 *   if (strcmp(symname, TAG_MARKER_SYMBOL) == 0) {
 *       *addend_p = 0;
 *       *value_p = (Addr) __tnf_tag_list_head; (value_p points to list head)
 *       __tnf_tag_list_head = (void *)*offset_p;(list head is the next record)
 *       return (0);
 *   }
 *
 * the function do_reloc(in the kobj_reloc.c) will put vlaue_p into
 * &__tnf_tag_version_1
 * Now the &__tnf_tag_version_1 points to the last list head
 * and __tnf_tag_list_head points to the new list head.
 * This is equivalent to attatch a node at the beginning of the list.
 *
 */
extern tnf_probe_control_t *__tnf_probe_list_head;
extern tnf_tag_data_t *__tnf_tag_list_head;
extern int tnf_changed_probe_list;

static int tnf_attach(dev_info_t *, ddi_attach_cmd_t);
static int tnf_detach(dev_info_t *, ddi_detach_cmd_t);
static int tnf_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int tnf_open(dev_t *, int, int, struct cred *);
static int tnf_close(dev_t, int, int, struct cred *);
#ifdef UNUSED
static int tnf_mmap(dev_t, off_t, int);
#endif
static int tnf_ioctl(dev_t, int, intptr_t, int, struct cred *, int *);
#ifdef UNUSED
static int tnf_prop_op(dev_t, dev_info_t *, ddi_prop_op_t,
    int, char *, caddr_t, int *);
#endif
static dev_info_t *tnf_devi;

static struct {
	int		tnf_probe_count;
	boolean_t	tnf_pidfilter_mode;
	boolean_t	ctldev_is_open;
	int		mapdev_open_count;
	kmutex_t	tnf_mtx;
} tnf_drv_state = { 0, B_FALSE, B_FALSE, 0 };

static int tnf_getmaxprobe(caddr_t, int);
static int tnf_getprobevals(caddr_t, int);
static int tnf_getprobestring(caddr_t, int);
static int tnf_setprobevals(caddr_t, int);
static int tnf_getstate(caddr_t, int);
static int tnf_allocbuf(intptr_t);
static int tnf_deallocbuf(void);
static int tnf_settracing(int);
static int tnf_pidfilterset(int);
static int tnf_pidfilterget(caddr_t, int);
static int tnf_getpidstate(caddr_t, int);
static int tnf_setpidstate(int, pid_t, int);
static int tnf_getheader(caddr_t, int);
static int tnf_getblock(caddr_t, int);
static int tnf_getfwzone(caddr_t, int);

static void *tnf_test_1(void *, tnf_probe_control_t *, tnf_probe_setup_t *);
static void *tnf_test_2(void *, tnf_probe_control_t *, tnf_probe_setup_t *);

#define	TNFCTL_MINOR 0
#define	TNFMAP_MINOR 1

struct cb_ops	tnf_cb_ops = {
	tnf_open,		/* open */
	tnf_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	tnf_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

struct dev_ops	tnf_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	tnf_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	tnf_attach,		/* attach */
	tnf_detach,		/* detach */
	nodev,			/* reset */
	&tnf_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* no bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"kernel probes driver",
	&tnf_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init()
{
	register int error;

	mutex_init(&tnf_drv_state.tnf_mtx, NULL, MUTEX_DEFAULT, NULL);

	if ((error = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&tnf_drv_state.tnf_mtx);
		return (error);
	}

	/* Give t0 a tpdp */
	if (!t0.t_tnf_tpdp)
		t0.t_tnf_tpdp = kmem_zalloc(sizeof (tnf_ops_t), KM_SLEEP);
	/* Initialize tag system */
	tnf_tag_core_init();
	tnf_tag_trace_init();
	tnf_changed_probe_list = 1;
	return (0);
}

int
_fini()
{
	/* Not safe to unload this module, currently */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
tnf_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	register int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)tnf_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

static int
tnf_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	if ((ddi_create_minor_node(devi, "tnfctl", S_IFCHR, TNFCTL_MINOR,
	    DDI_PSEUDO, 0) == DDI_FAILURE) ||
	    (ddi_create_minor_node(devi, "tnfmap", S_IFCHR, TNFMAP_MINOR,
	    DDI_PSEUDO, 0) == DDI_FAILURE)) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	tnf_devi = devi;
	return (DDI_SUCCESS);
}

static int
tnf_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

/*
 * property operations. Return the size of the kernel trace buffer.  We
 * only handle size property requests.  Others are passed on.
 */
#ifdef UNUSED
static int
tnf_prop_op(dev_t dev, dev_info_t *di, ddi_prop_op_t prop,
    int m, char *name, caddr_t valuep, int *lengthp)
{
	int length, *retbuf, size;

	if (strcmp(name, "size") == 0) {

		/* Don't need tnf_mtx, since mapdev_open_count > 0 */
		size = tnf_trace_file_size;

		length = *lengthp;		/* get caller's length */
		*lengthp = sizeof (int);	/* set caller's length */

		switch (prop) {

		case PROP_LEN:
			return (DDI_PROP_SUCCESS);

		case PROP_LEN_AND_VAL_ALLOC:
			retbuf = kmem_alloc(sizeof (int),
			    (m & DDI_PROP_CANSLEEP) ? KM_SLEEP : KM_NOSLEEP);
			if (retbuf == NULL)
				return (DDI_PROP_NO_MEMORY);
			*(int **)valuep = retbuf;	/* set caller's buf */
			*retbuf = size;
			return (DDI_PROP_SUCCESS);

		case PROP_LEN_AND_VAL_BUF:
			if (length < sizeof (int))
				return (DDI_PROP_BUF_TOO_SMALL);
			*(int *)valuep = size;
			return (DDI_PROP_SUCCESS);
		}
	}
	return (ddi_prop_op(dev, dip, prop, m, name, valuep, lengthp));
}
#endif

/* ARGSUSED */
static int
tnf_open(dev_t *devp, int flag, int otyp, struct cred *cred)
{
	int err = 0;
	mutex_enter(&tnf_drv_state.tnf_mtx);
	if (getminor(*devp) == TNFCTL_MINOR) {
		if (tnf_drv_state.ctldev_is_open)
			err = EBUSY;
		else {
			tnf_drv_state.ctldev_is_open = B_TRUE;
			/* stop autounloading -- XXX temporary */
			modunload_disable();
		}
	} else {
		/* ASSERT(getminor(*devp) == TNFMAP_MINOR) */
		++tnf_drv_state.mapdev_open_count;
	}
	mutex_exit(&tnf_drv_state.tnf_mtx);
	return (err);
}

/* ARGSUSED */
static int
tnf_close(dev_t dev, int flag, int otyp, struct cred *cred)
{
	if (getminor(dev) == TNFCTL_MINOR) {
		/*
		 * Request the reenablement of autounloading
		 */
		modunload_enable();
		tnf_drv_state.ctldev_is_open = B_FALSE;
	} else {
		/* ASSERT(getminor(dev) == TNFMAP_MINOR) */
		/*
		 * Unconditionally zero the open count since close()
		 * is called when last client closes the device.
		 */
		tnf_drv_state.mapdev_open_count = 0;
	}
	return (0);
}

/*
 * return the address of the image referenced by dev.
 *
 * 1191344: aliasing problem on VAC machines.  It could be made to
 * work by ensuring that tnf_buf is allocated on a vac_size boundary.
 */
#ifdef UNUSED
/*ARGSUSED*/
static int
tnf_mmap(dev_t dev, off_t off, int prot)
{
	register caddr_t addr;
	register caddr_t pg_offset;

	if (getminor(dev) != TNFMAP_MINOR)
		return (-1);
	if (tnf_buf == 0 || off >= tnf_trace_file_size) {
		return (-1);
	}

	addr = tnf_buf;
	pg_offset = (caddr_t)((ulong_t)addr + (ulong_t)off);
	return ((int)hat_getpfnum(kas.a_hat, pg_offset));
}
#endif

/*ARGSUSED4*/
static int
tnf_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	int filterval = 1;

	if ((mode & FMODELS) != FNATIVE)
		return (ENOTSUP);

	if (getminor(dev) != TNFCTL_MINOR &&
	    cmd != TIFIOCGSTATE &&
	    cmd != TIFIOCGHEADER &&
	    cmd != TIFIOCGBLOCK &&
	    cmd != TIFIOCGFWZONE)
		return (EINVAL);

	switch (cmd) {
	case TIFIOCGMAXPROBE:
		return (tnf_getmaxprobe((caddr_t)arg, mode));
	case TIFIOCGPROBEVALS:
		return (tnf_getprobevals((caddr_t)arg, mode));
	case TIFIOCGPROBESTRING:
		return (tnf_getprobestring((caddr_t)arg, mode));
	case TIFIOCSPROBEVALS:
		return (tnf_setprobevals((caddr_t)arg, mode));
	case TIFIOCGSTATE:
		return (tnf_getstate((caddr_t)arg, mode));
	case TIFIOCALLOCBUF:
		return (tnf_allocbuf(arg));
	case TIFIOCDEALLOCBUF:
		return (tnf_deallocbuf());
	case TIFIOCSTRACING:
		/* LINTED cast from 64-bit integer to 32-bit integer */
		return (tnf_settracing((int)arg));
	case TIFIOCSPIDFILTER:
		/* LINTED cast from 64-bit integer to 32-bit integer */
		return (tnf_pidfilterset((int)arg));
	case TIFIOCGPIDSTATE:
		return (tnf_getpidstate((caddr_t)arg, mode));
	case TIFIOCSPIDOFF:
		filterval = 0;
		/*FALLTHROUGH*/
	case TIFIOCSPIDON:
		/* LINTED cast from 64-bit integer to 32-bit integer */
		return (tnf_setpidstate(filterval, (pid_t)arg, mode));
	case TIFIOCPIDFILTERGET:
		return (tnf_pidfilterget((caddr_t)arg, mode));
	case TIFIOCGHEADER:
		return (tnf_getheader((caddr_t)arg, mode));
	case TIFIOCGBLOCK:
		return (tnf_getblock((caddr_t)arg, mode));
	case TIFIOCGFWZONE:
		return (tnf_getfwzone((caddr_t)arg, mode));
	default:
		return (EINVAL);
	}
}

/*
 * ioctls
 */

static int
tnf_getmaxprobe(caddr_t arg, int mode)
{
	tnf_probe_control_t *p;
	/*
	 * XXX Still not right for module unload -- just counting
	 * the probes is not enough
	 */
	if (tnf_changed_probe_list) {
		mutex_enter(&mod_lock);
		tnf_changed_probe_list = 0;
		tnf_drv_state.tnf_probe_count = 0;
		for (p = (tnf_probe_control_t *)__tnf_probe_list_head;
		    p != 0; p = p->next)
			++tnf_drv_state.tnf_probe_count;
		mutex_exit(&mod_lock);
	}
	if (ddi_copyout((caddr_t)&tnf_drv_state.tnf_probe_count,
	    arg, sizeof (tnf_drv_state.tnf_probe_count), mode))
		return (EFAULT);
	return (0);
}

static int
tnf_getprobevals(caddr_t arg, int mode)
{
	tnf_probevals_t probebuf;
	tnf_probe_control_t *p;
	int i, retval = 0;

	if (ddi_copyin(arg, (caddr_t)&probebuf, sizeof (probebuf), mode))
		return (EFAULT);

	mutex_enter(&mod_lock);
	for (i = 1, p = (tnf_probe_control_t *)__tnf_probe_list_head;
	    p != NULL && i != probebuf.probenum;
	    ++i, p = p->next)
		;
	if (p == NULL)
		retval = ENOENT;
	else {
		probebuf.enabled = (p->test_func != NULL);
		probebuf.traced = (p->probe_func == tnf_trace_commit);
		/* LINTED assignment of 64-bit integer to 32-bit integer */
		probebuf.attrsize = strlen(p->attrs) + 1;
		if (ddi_copyout((caddr_t)&probebuf,
		    arg, sizeof (probebuf), mode))
			retval = EFAULT;
	}
	mutex_exit(&mod_lock);
	return (retval);
}

static int
tnf_getprobestring(caddr_t arg, int mode)
{
	tnf_probevals_t probebuf;
	tnf_probe_control_t *p;
	int i, retval = 0;

	if (ddi_copyin(arg, (caddr_t)&probebuf, sizeof (probebuf), mode))
		return (EFAULT);

	mutex_enter(&mod_lock);
	for (i = 1, p = (tnf_probe_control_t *)__tnf_probe_list_head;
	    p != NULL && i != probebuf.probenum;
	    ++i, p = p->next)
		;
	if (p == NULL)
		retval = ENOENT;
	else if (ddi_copyout((caddr_t)p->attrs,
	    arg, strlen(p->attrs) + 1, mode))
		retval = EFAULT;
	mutex_exit(&mod_lock);
	return (retval);
}

static int
tnf_setprobevals(caddr_t arg, int mode)
{
	tnf_probevals_t probebuf;
	tnf_probe_control_t *p;
	int i, retval = 0;

	if (ddi_copyin(arg, (caddr_t)&probebuf, sizeof (probebuf), mode))
		return (EFAULT);

	mutex_enter(&mod_lock);
	for (i = 1, p = (tnf_probe_control_t *)__tnf_probe_list_head;
	    p != NULL && i != probebuf.probenum;
	    ++i, p = p->next)
		;
	if (p == NULL)
		retval = ENOENT;
	else {
		/*
		 * First do trace, then enable.
		 * Set test_func last.
		 */
		if (probebuf.traced)
			p->probe_func = tnf_trace_commit;
		else
			p->probe_func = tnf_trace_rollback;
		if (probebuf.enabled) {
			p->alloc_func = tnf_trace_alloc;
			/* this must be set last */
			if (tnf_drv_state.tnf_pidfilter_mode)
				p->test_func = tnf_test_2;
			else
				p->test_func = tnf_test_1;
		} else
			p->test_func = NULL;
	}
	mutex_exit(&mod_lock);
	return (retval);
}

static int
tnf_getstate(caddr_t arg, int mode)
{
	tifiocstate_t	tstate;
	proc_t		*procp;

	if (tnf_buf == NULL) {
		tstate.buffer_state = TIFIOCBUF_NONE;
		tstate.buffer_size = 0;
	} else {
		switch (tnfw_b_state & ~TNFW_B_STOPPED) {
		case TNFW_B_RUNNING:
			tstate.buffer_state = TIFIOCBUF_OK;
			break;
		case TNFW_B_NOBUFFER:
			tstate.buffer_state = TIFIOCBUF_UNINIT;
			break;
		case TNFW_B_BROKEN:
			tstate.buffer_state = TIFIOCBUF_BROKEN;
			break;
		}
		/* LINTED assignment of 64-bit integer to 32-bit integer */
		tstate.buffer_size = tnf_trace_file_size;
	}
	tstate.trace_stopped = tnfw_b_state & TNFW_B_STOPPED;
	tstate.pidfilter_mode = tnf_drv_state.tnf_pidfilter_mode;
	tstate.pidfilter_size = 0;

	mutex_enter(&pidlock);
	for (procp = practive; procp != NULL; procp = procp->p_next)
		if (PROC_IS_FILTER(procp))
			tstate.pidfilter_size++;
	mutex_exit(&pidlock);

	if (ddi_copyout((caddr_t)&tstate, arg, sizeof (tstate), mode))
		return (EFAULT);
	return (0);
}

static int
tnf_allocbuf(intptr_t arg)
{
	size_t bufsz;

	if (tnf_buf != NULL)
		return (EBUSY);

	bufsz = roundup((size_t)arg, PAGESIZE);
	/*
	 * Validate size
	 * XXX Take kernel VM into consideration as well
	 */
	/* bug fix #4057599 if (bufsz > (physmem << PAGESHIFT) / 2) */
	if (btop(bufsz) > (physmem / 2))
		return (ENOMEM);
	if (bufsz < TNF_TRACE_FILE_MIN)
		bufsz = TNF_TRACE_FILE_MIN;

#if TNF_USE_KMA
	tnf_buf = kmem_zalloc(bufsz, KM_SLEEP);
#else
	/* LINTED cast from 64-bit integer to 32-bit intege */
	tnf_buf = segkp_get(segkp, (int)bufsz,
	    KPD_ZERO | KPD_LOCKED | KPD_NO_ANON);
#endif
	if (tnf_buf == NULL)
		return (ENOMEM);

	tnf_trace_file_size = bufsz;
	tnf_trace_init();
	return (0);
}

/*
 * Process a "deallocate buffer" ioctl request.  Tracing must be turned
 * off.  We must clear references to the buffer from the tag sites;
 * invalidate all threads' notions of block ownership; make sure nobody
 * is executing a probe (they might have started before tracing was
 * turned off); and free the buffer.
 */
static int
tnf_deallocbuf(void)
{
	tnf_ops_t *tpdp;
	kthread_t *t;
	tnf_probe_control_t *probep;
	tnf_tag_data_t *tagp;

	if (tnf_drv_state.mapdev_open_count > 0 || tnf_tracing_active)
		return (EBUSY);
	if (tnf_buf == NULL)
		return (ENOMEM);

	/*
	 * Make sure nobody is executing a probe.
	 * (They could be if they got started while
	 * tnf_tracing_active was still on.)  Grab
	 * pidlock, and check the busy flag in all
	 * TPDP's.
	 */
	mutex_enter(&pidlock);
	t = curthread;
	do {
		if (t->t_tnf_tpdp != NULL) {
		/* LINTED pointer cast may result in improper alignment */
			tpdp = (tnf_ops_t *)t->t_tnf_tpdp;
			if (LOCK_HELD(&tpdp->busy)) {
				mutex_exit(&pidlock);
				return (EBUSY);
			}
			tpdp->wcb.tnfw_w_pos.tnfw_w_block = NULL;
			tpdp->wcb.tnfw_w_tag_pos.tnfw_w_block = NULL;
			tpdp->schedule.record_p = NULL;
		}
		t = t->t_next;
	} while (t != curthread);
	mutex_exit(&pidlock);

	/*
	 * Zap all references to the buffer we're freeing.
	 * Grab mod_lock while walking list to keep it
	 * consistent.
	 */
	mutex_enter(&mod_lock);
	tagp = (tnf_tag_data_t *)__tnf_tag_list_head;
	while (tagp != NULL) {
		tagp->tag_index = 0;
		tagp = (tnf_tag_data_t *)tagp->tag_version;
	}
	probep = (tnf_probe_control_t *)__tnf_probe_list_head;
	while (probep != NULL) {
		probep->index = 0;
		probep = probep->next;
	}
	mutex_exit(&mod_lock);

	tnfw_b_state = TNFW_B_NOBUFFER | TNFW_B_STOPPED;
#if TNF_USE_KMA
	kmem_free(tnf_buf, tnf_trace_file_size);
#else
	segkp_release(segkp, tnf_buf);
#endif
	tnf_buf = NULL;

	return (0);
}

static int
tnf_settracing(int arg)
{
	if (arg)
		if (tnf_buf == NULL)
			return (ENOMEM);
		else
			tnf_trace_on();
	else
		tnf_trace_off();

#ifdef _TNF_SPEED_TEST
#define	NITER	255
	{
		int i;

		for (i = 0; i < NITER; i++)
			TNF_PROBE_0(tnf_speed_0, "tnf", /* CSTYLED */);
		for (i = 0; i < NITER; i++)
			TNF_PROBE_1(tnf_speed_1, "tnf", /* CSTYLED */,
			    tnf_long,	long,	i);
		for (i = 0; i < NITER; i++)
			TNF_PROBE_2(tnf_speed_2, "tnf", /* CSTYLED */,
			    tnf_long,	long1,	i,
			    tnf_long,	long2,	i);
	}
#endif /* _TNF_SPEED_TEST */

	return (0);
}

static int
tnf_getpidstate(caddr_t arg, int mode)
{
	int	err = 0;
	pid_t	pid;
	proc_t	*procp;
	int	result;

	if (ddi_copyin(arg, (caddr_t)&pid, sizeof (pid), mode))
		return (EFAULT);

	mutex_enter(&pidlock);
	if ((procp = prfind(pid)) != NULL)
		result = PROC_IS_FILTER(procp);
	else
		err = ESRCH;
	mutex_exit(&pidlock);

	if (!err)
		if (ddi_copyout((caddr_t)&result, (caddr_t)arg,
		    sizeof (result), mode))
			return (EFAULT);
	return (err);
}

/*ARGSUSED*/
static int
tnf_setpidstate(int filterval, pid_t pid, int mode)
{
	int	err = 0;
	proc_t	*procp;

	mutex_enter(&pidlock);
	if ((procp = prfind(pid)) != NULL)
		if (filterval)
			PROC_FILTER_SET(procp);
		else
			PROC_FILTER_CLR(procp);
	else
		err = ESRCH;
	mutex_exit(&pidlock);

	return (err);
}

static int
tnf_pidfilterset(int mode)
{
	tnf_probe_control_t	*p;
	tnf_probe_test_func_t	func;

	tnf_drv_state.tnf_pidfilter_mode = mode;

	/* Establish correct test func for each probe */
	if (mode)
		func = tnf_test_2;
	else
		func = tnf_test_1;

	mutex_enter(&mod_lock);
	p = (tnf_probe_control_t *)__tnf_probe_list_head;
	while (p != NULL) {
		if (p->test_func != NULL)
			p->test_func = func;
		p = p->next;
	}
	mutex_exit(&mod_lock);

	return (0);
}

static int
tnf_pidfilterget(caddr_t dest, int mode)
{
	int err = 0;
	int filtercount = 0;
	size_t	sz;
	pid_t	*filterbuf, *bufp;
	proc_t	*procp;

	/* Count how many processes in filter set (upper bound) */
	mutex_enter(&pidlock);
	for (procp = practive; procp != NULL; procp = procp->p_next)
		if (PROC_IS_FILTER(procp))
			filtercount++;
	mutex_exit(&pidlock);

	/* Allocate temp space to hold filter set (upper bound) */
	sz = sizeof (pid_t) * (filtercount + 1);
	filterbuf = kmem_zalloc(sz, KM_SLEEP);

	/*
	 * NOTE: The filter set cannot grow between the first and
	 * second acquisitions of pidlock.  This is currently true
	 * because:
	 *	1. /dev/tnfctl is exclusive open, so all driver
	 *	   control operations, including changing the filter
	 *	   set and this code, are effectively single-threaded.
	 *	2. There is no in-kernel API to manipulate the filter
	 *	   set (i.e. toggle the on/off bit in a proc struct).
	 *	3. The proc filter bit is not inherited across a fork()
	 *	   operation; the child starts with the bit off.
	 * If any of these assumptions is invalidated, a possible
	 * solution is to check whether we're overflowing the allocated
	 * filterbuf below, and back out and restart from the beginning
	 * if so.
	 *
	 * The code below handles the case when the filter set shrinks
	 * due to processes exiting.
	 */

	/* Fill in filter set */
	bufp = filterbuf + 1;	/* first word is for count */
	filtercount = 0;	/* recomputed below */
	mutex_enter(&pidlock);
	for (procp = practive; procp != NULL; procp = procp->p_next) {
		if (PROC_IS_FILTER(procp)) {
			filtercount++;
			*bufp++ = procp->p_pid;
		}
	}
	mutex_exit(&pidlock);

	/* Set filtercount */
	*filterbuf = (pid_t)filtercount;

	/* Copy out result */
	if (ddi_copyout((caddr_t)filterbuf, dest, sz, mode))
		err = EFAULT;

	/* Free temp space */
	kmem_free(filterbuf, sz);

	return (err);
}

static int
tnf_getheader(caddr_t arg, int mode)
{
	if (tnf_buf == NULL)
		return (ENOMEM);
	if (ddi_copyout(tnf_buf, arg, TNF_BLOCK_SIZE, mode))
		return (EFAULT);
	return (0);
}

static int
tnf_getblock(caddr_t arg, int mode)
{
	int		err = 0;
	tifiocgblock_t	parms;
	caddr_t		area;
	tnf_block_header_t	*blk;

	if (tnf_buf == NULL)
		return (ENOMEM);
	if (ddi_copyin(arg, (caddr_t)&parms, sizeof (parms), mode))
		return (EFAULT);
	area = tnf_buf + TNF_DIRECTORY_SIZE +
	    parms.block_num * TNF_BLOCK_SIZE;
	if (area < tnf_buf + TNF_DIRECTORY_SIZE ||
	    area >= tnf_buf + tnf_trace_file_size)
		return (EFAULT);
	/* LINTED pointer cast */
	blk = (tnf_block_header_t *)area;
	/*
	 * B-lock the block while we're reading
	 */
	if (!lock_try(&blk->B_lock))
		return (EBUSY);
	if (ddi_copyout(area, parms.dst_addr, TNF_BLOCK_SIZE, mode))
		err = EFAULT;
	lock_clear(&blk->B_lock);
	return (err);
}

static int
tnf_getfwzone(caddr_t arg, int mode)
{
	tifiocgfw_t parms;

	if (tnf_buf == NULL)
		return (ENOMEM);
	if (ddi_copyin(arg, (caddr_t)&parms, sizeof (parms), mode))
		return (EFAULT);
	if (ddi_copyout(tnf_buf + TNF_BLOCK_SIZE + parms.start *
	    sizeof (tnf_ref32_t), (caddr_t)parms.dst_addr,
	    parms.slots * (int)(sizeof (tnf_ref32_t)), mode))
		return (EFAULT);
	return (0);
}

/*ARGSUSED*/
static void *
tnf_test_1(void *tpdp, tnf_probe_control_t *probe_p, tnf_probe_setup_t *sp)
{
	tpdp = (void *)curthread->t_tnf_tpdp;
	if (tpdp != NULL)
		return (tnf_trace_alloc((tnf_ops_t *)tpdp, probe_p, sp));
	return (NULL);
}

/*ARGSUSED*/
static void *
tnf_test_2(void *tpdp, tnf_probe_control_t *probe_p, tnf_probe_setup_t *sp)
{
	tpdp = (void *)curthread->t_tnf_tpdp;
	if (tpdp != NULL && PROC_IS_FILTER(curproc))
		return (tnf_trace_alloc((tnf_ops_t *)tpdp, probe_p, sp));
	return (NULL);
}

#endif /* !NPROBE */
