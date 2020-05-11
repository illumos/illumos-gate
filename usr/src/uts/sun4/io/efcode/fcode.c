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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */


/*
 * fcode helper driver -- provide priv. access and kernel communication
 * to the userland fcode interpreter.
 */
#include <sys/types.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/fcode.h>

static int fc_max_opens = 32;	/* Up to this many simultaneous opens */

/*
 * Soft state associated with each instance of driver open.
 */
static struct fc_state {
	int	state;		/* available flag or active state */
	struct fc_request *req;	/* Active Request */
} *fc_states;

#define	FC_STATE_INACTIVE	0	/* Unopen, available for use */
#define	FC_STATE_OPEN		1	/* Inital open */
#define	FC_STATE_READ_DONE	2	/* blocking read done */
#define	FC_STATE_IN_PROGRESS	3	/* FC_GET_PARAMETERS done, active */
#define	FC_STATE_VALIDATED	4	/* FC_VALIDATE done, active */
#define	FC_STATE_ERROR_SET	5	/* FC_SET_FCODE_ERROR done, active */
#define	FC_STATE_ACTIVE(s)	((s) != 0)
#define	FC_STATE_AVAILABLE(s)	((s) == FC_STATE_INACTIVE)

static kmutex_t fc_open_lock;	/* serialize instance assignment */
static kcondvar_t fc_open_cv;	/* wait for available open */
static int fc_open_count;	/* number of current open instance */

static int fc_open(dev_t *, int, int, cred_t *);
static int fc_close(dev_t, int, int, cred_t *);
static int fc_read(dev_t, struct uio *, cred_t *);
static int fc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int fc_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int fc_attach(dev_info_t *, ddi_attach_cmd_t cmd);
static int fc_detach(dev_info_t *, ddi_detach_cmd_t cmd);

static int fc_get_parameters(dev_t, intptr_t, int, cred_t *, int *);
static int fc_get_my_args(dev_t, intptr_t, int, cred_t *, int *);
static int fc_run_priv(dev_t, intptr_t, int, cred_t *, int *);
static int fc_validate(dev_t, intptr_t, int, cred_t *, int *);
static int fc_get_fcode(dev_t, intptr_t, int, cred_t *, int *);
static int fc_set_fcode_error(dev_t, intptr_t, int, cred_t *, int *);

static struct cb_ops fc_cb_ops = {
	fc_open,		/* open */
	fc_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	fc_read,		/* read */
	nodev,			/* write */
	fc_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops fcode_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	fc_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	fc_attach,		/* attach */
	fc_detach,		/* detach */
	nodev,			/* reset */
	&fc_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	"FCode driver",
	&fcode_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	error;

	mutex_init(&fc_open_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&fc_open_cv, NULL, CV_DRIVER, NULL);

	error = mod_install(&modlinkage);
	if (error != 0) {
		mutex_destroy(&fc_open_lock);
		cv_destroy(&fc_open_cv);
		return (error);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error != 0) {
		return (error);
	}

	mutex_destroy(&fc_open_lock);
	cv_destroy(&fc_open_cv);
	return (0);
}

static dev_info_t *fc_dip;

/*ARGSUSED*/
static int
fc_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)fc_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		/* All dev_t's map to the same, single instance */
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}

static int
fc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int error = DDI_FAILURE;

	switch (cmd) {

	case DDI_ATTACH:
		fc_open_count = 0;
		fc_states = kmem_zalloc(
		    fc_max_opens * sizeof (struct fc_state), KM_SLEEP);

		if (ddi_create_minor_node(dip, "fcode", S_IFCHR,
		    0, DDI_PSEUDO, 0) == DDI_FAILURE) {
			kmem_free(fc_states,
			    fc_max_opens * sizeof (struct fc_state));
			error = DDI_FAILURE;
		} else {
			fc_dip = dip;
			ddi_report_dev(dip);

			error = DDI_SUCCESS;
		}
		break;
	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);
}

static int
fc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int error = DDI_FAILURE;

	switch (cmd) {

	case DDI_DETACH:
		ddi_remove_minor_node(dip, NULL);
		fc_dip = NULL;
		kmem_free(fc_states, fc_max_opens * sizeof (struct fc_state));

		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);
}

/*
 * Allow multiple opens by tweaking the dev_t such that it looks like each
 * open is getting a different minor device.  Each minor gets a separate
 * entry in the fc_states[] table.
 */
/*ARGSUSED*/
static int
fc_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int m;
	struct fc_state *st;

	if (getminor(*devp) != 0)
		return (EINVAL);

	mutex_enter(&fc_open_lock);

	while (fc_open_count >= fc_max_opens)  {
		/*
		 * maximum open instance reached, wait for a close
		 */
		FC_DEBUG0(1, CE_WARN,
		"fcode: Maximum fcode open reached, waiting for exit\n");

		if (cv_wait_sig(&fc_open_cv, &fc_open_lock) == 0) {
			mutex_exit(&fc_open_lock);
			return (EINTR);
			/*NOTREACHED*/
		}
	}
	fc_open_count++;

	for (m = 0, st = fc_states; m < fc_max_opens; m++, st++) {
		if (FC_STATE_ACTIVE(st->state))
			continue;

		st->state = FC_STATE_OPEN;
		st->req = 0;
		break;	/* It's ours. */
	}
	mutex_exit(&fc_open_lock);

	ASSERT(m < fc_max_opens);
	*devp = makedevice(getmajor(*devp), (minor_t)(m + 1));

	FC_DEBUG2(9, CE_CONT, "fc_open: open count = %d (%d)\n",
	    fc_open_count, m + 1);

	return (0);
}

/*ARGSUSED*/
static int
fc_close(dev_t dev, int flag, int otype, cred_t *cred_p)
{
	struct fc_state *st;
	int m = (int)getminor(dev) - 1;
	struct fc_request *fp;
	struct fc_client_interface *cp;

	st = fc_states + m;
	ASSERT(m < fc_max_opens && FC_STATE_ACTIVE(st->state));

	/*
	 * The close indicates we're done with this request.
	 * If we haven't validated this request, then something
	 * bad may have happened (ie: perhaps the user program was
	 * killed), so we should invalidate it, then close the session.
	 */

	if (st->state == FC_STATE_READ_DONE) {
		fp = st->req;
		fp->error = FC_ERROR;
	}

	if (st->state > FC_STATE_READ_DONE) {

		cp = kmem_zalloc(sizeof (struct fc_client_interface), KM_SLEEP);
		fp = st->req;
		ASSERT(fp);
		ASSERT(fp->ap_ops);

		if (st->state != FC_STATE_VALIDATED) {
			FC_DEBUG0(1, CE_CONT,
			    "fc_close: Send invalidate cmd\n");
			cp->svc_name = fc_ptr2cell(FC_SVC_INVALIDATE);
			(void) fp->ap_ops(fp->ap_dip, fp->handle, cp);
			if ((st->state != FC_STATE_ERROR_SET) ||
			    (fp->error == FC_SUCCESS)) {
				fp->error = FC_ERROR;
			}
			/*
			 * else - fp->error already set by userland interpreter
			 */
		}

		bzero(cp, sizeof (struct fc_client_interface));
		FC_DEBUG0(9, CE_CONT, "fc_close: Sending exit cmd\n");
		cp->svc_name = fc_ptr2cell(FC_SVC_EXIT);
		(void) fp->ap_ops(fp->ap_dip, fp->handle, cp);

		kmem_free(cp, sizeof (struct fc_client_interface));
	}

	/*
	 * Mark the request as done ...
	 */
	if ((fp = st->req) != NULL)
		fc_finish_request(fp);

	/*
	 * rectify count and signal any waiters
	 */
	mutex_enter(&fc_open_lock);
	st->state = FC_STATE_INACTIVE;
	st->req = 0;
	FC_DEBUG2(9, CE_CONT, "fc_close: open count = %d (%d)\n",
	    fc_open_count, m + 1);
	if (fc_open_count >= fc_max_opens) {
		cv_broadcast(&fc_open_cv);
	}
	fc_open_count--;
	mutex_exit(&fc_open_lock);

	return (0);
}

/*ARGSUSED*/
static int
fc_read(dev_t dev, struct uio *uio, cred_t *cred)
{
	struct fc_state *st;
	int m = (int)getminor(dev) - 1;
	struct fc_request *fp;

	st = fc_states + m;
	ASSERT(m < fc_max_opens && FC_STATE_ACTIVE(st->state));

	/*
	 * Wait for a internal request for the interpreter
	 * and sleep till one arrives.  When one arrives,
	 * return from the read. (No data is actually returned).
	 */

	if (st->state != FC_STATE_OPEN)  {
		cmn_err(CE_CONT, "fc_read: Wrong state (%d) for read\n",
		    st->state);
		return (EINVAL);
	}

	/*
	 * Wait for a request, allowing the wait to be interrupted.
	 */
	if ((fp = fc_get_request()) == NULL)
		return (EINTR);

	FC_DEBUG1(3, CE_CONT, "fc_read: request fp: %p\n", fp);

	/*
	 * Update our state and store the request pointer.
	 */
	mutex_enter(&fc_open_lock);
	st->req = fp;
	st->state = FC_STATE_READ_DONE;
	mutex_exit(&fc_open_lock);

	return (0);
}

/*ARGSUSED*/
static int
fc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	struct fc_state *st;
	int m = (int)getminor(dev) - 1;

	if (m >= fc_max_opens) {
		return (EINVAL);
	}

	st = fc_states + m;
	ASSERT(FC_STATE_ACTIVE(st->state));

	switch (cmd) {
	case FC_GET_PARAMETERS:
		/*
		 * This should be the first command and is used to
		 * return data about the request, including the
		 * the fcode address and size and the unit address
		 * of the new child.  The fcode offset,size can later
		 * be used as an offset in an mmap request to allow
		 * the fcode to be mapped in.
		 */
		return (fc_get_parameters(dev, arg, mode, credp, rvalp));

	case FC_GET_MY_ARGS:
		/*
		 * Get the inital setting of my-args.  This should be done
		 * after FC_GET_PARAMETERS.
		 */
		return (fc_get_my_args(dev, arg, mode, credp, rvalp));

	case FC_RUN_PRIV:
		/*
		 * Run a priveledged op on behalf of the interpreter,
		 * or download device tree data from the interpreter.
		 */
		return (fc_run_priv(dev, arg, mode, credp, rvalp));

	case FC_VALIDATE:
		/*
		 * The interpreter is done, mark state as done, validating
		 * the data downloaded into the kernel.
		 */
		return (fc_validate(dev, arg, mode, credp, rvalp));

	case FC_GET_FCODE_DATA:
		/*
		 * Copy out device fcode to user buffer.
		 */
		return (fc_get_fcode(dev, arg, mode, credp, rvalp));


	case FC_SET_FCODE_ERROR:
		/*
		 * Copy in interpreter error status
		 */
		return (fc_set_fcode_error(dev, arg, mode, credp, rvalp));
	}
	/*
	 * Invalid ioctl command
	 */
	return (ENOTTY);
}

/*
 * fc_get_parameters:  Get information about the current request.
 * The input 'arg' is a pointer to 'struct fc_parameters' which
 * we write back to the caller with the information from the req
 * structure.
 */

/*ARGSUSED*/
static int
fc_get_parameters(dev_t dev, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	struct fc_state *st;
	int m = (int)getminor(dev) - 1;
	fco_handle_t rp;
	struct fc_parameters *fcp;

	st = fc_states + m;
	ASSERT(m < fc_max_opens && FC_STATE_ACTIVE(st->state));

	/*
	 * It's an error if we're not in state FC_STATE_READ_DONE
	 */

	if (st->state != FC_STATE_READ_DONE) {
		cmn_err(CE_CONT, "fc_ioctl: fc_get_parameters: "
		    "wrong state (%d)\n", st->state);
		return (EINVAL);
	}

	ASSERT(st->req != NULL);
	rp = st->req->handle;

	FC_DEBUG1(3, CE_CONT, "fc_ioctl: fc_get_parameters fp: %p\n", st->req);

	/*
	 * Create and copyout the attachment point ihandle,
	 * the fcode kaddr,len and the unit address.
	 * Note how we treat ihandles and phandles (they are the same thing
	 * only accross this interface ... a dev_info_t *.)
	 */
	fcp = kmem_zalloc(sizeof (struct fc_parameters), KM_SLEEP);
	fcp->fcode_size = rp->fcode_size;
	(void) strncpy(fcp->unit_address, rp->unit_address,
	    sizeof (fcp->unit_address) - 1);

	/*
	 * XXX - APA This needs to be made more bus independant.
	 */
	if (rp->bus_args) {
		bcopy(rp->bus_args, &fcp->config_address, sizeof (int));

		FC_DEBUG1(3, CE_CONT, "fc_ioctl: config_address=%x\n",
		    fcp->config_address);

	} else {
		FC_DEBUG0(3, CE_CONT, "fc_ioctl: fc_get_parameters "
		    "There are no bus specific arguments\n");
	}
	if (copyout(fcp, (void *)arg, sizeof (struct fc_parameters)) == -1) {
		kmem_free(fcp, sizeof (struct fc_parameters));
		return (EFAULT);
	}
	kmem_free(fcp, sizeof (struct fc_parameters));

	/*
	 * Update our state
	 */
	mutex_enter(&fc_open_lock);
	st->state = FC_STATE_IN_PROGRESS;
	mutex_exit(&fc_open_lock);

	return (0);
}

/*
 * fc_get_my_args:  Get the initial setting for my-args.
 * The input 'arg' is a pointer where the my-arg string is written
 * to. The string is NULL terminated.
 */

/*ARGSUSED*/
static int
fc_get_my_args(dev_t dev, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	struct fc_state *st;
	int m = (int)getminor(dev) - 1;
	fco_handle_t rp;

	st = fc_states + m;
	ASSERT(m < fc_max_opens && FC_STATE_ACTIVE(st->state));

	/*
	 * It's an error if we're not in state FC_STATE_READ_DONE
	 */

	if (st->state != FC_STATE_IN_PROGRESS) {
		cmn_err(CE_CONT, "fc_ioctl: fc_get_my_args: "
		    "wrong state (%d)\n", st->state);
		return (EINVAL);
	}

	ASSERT(st->req != NULL);
	rp = st->req->handle;

	FC_DEBUG1(3, CE_CONT, "fc_ioctl: fc_get_my_args fp: %p\n", st->req);

	if (rp->my_args == NULL) {
		FC_DEBUG0(3, CE_CONT, "fc_ioctl: fc_get_my_args "
		    "There are no bus specific my-args\n");
		return (EINVAL);
	}

	if (strlen(rp->my_args) > FC_GET_MY_ARGS_BUFLEN) {
		FC_DEBUG1(3, CE_CONT, "fc_ioctl: fc_get_my_args "
		    "my-args is larger than %d\n", FC_GET_MY_ARGS_BUFLEN);
		return (EINVAL);

	}

	if (copyout(rp->my_args, (void *)arg, strlen(rp->my_args) + 1) == -1) {
		return (EFAULT);
	}

	return (0);
}

/*ARGSUSED*/
static int
fc_run_priv(dev_t dev, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	struct fc_state *st;
	int m = (int)getminor(dev) - 1;
	struct fc_request *fp;

	struct fc_client_interface tc, *cp, *ap;
	size_t csize;
	int nresults, nargs, error;
	char *name;

	ap = (struct fc_client_interface *)arg;

	st = fc_states + m;
	ASSERT(m < fc_max_opens && FC_STATE_ACTIVE(st->state));

	/*
	 * It's an error if we're not in state FC_STATE_IN_PROGRESS
	 */

	if (st->state != FC_STATE_IN_PROGRESS) {
		cmn_err(CE_CONT, "fc_ioctl: fc_run_priv: wrong state (%d)\n",
		    st->state);
		return (EINVAL);
	}

	/*
	 * Get the first three cells to figure out how large the buffer
	 * needs to be; allocate it and copy it in. The array is variable
	 * sized based on the fixed portion plus the given number of arg.
	 * cells and given number of result cells.
	 */
	if (copyin((void *)arg, &tc, 3 * sizeof (fc_cell_t))) {
		FC_DEBUG1(1, CE_CONT, "fc_ioctl: fc_run_priv "
		    "fault copying in first 2 cells from %p\n", arg);
		return (EFAULT);
	}

	/*
	 * XXX We should probably limit #args and #results to something
	 * reasonable without blindly copying it in.
	 */
	nresults = fc_cell2int(tc.nresults); /* save me for later */
	nargs = fc_cell2int(tc.nargs);
	csize = (FCC_FIXED_CELLS + nargs + nresults) * sizeof (fc_cell_t);
	cp = kmem_zalloc(csize, KM_SLEEP);
	/*
	 * Don't bother copying in the result cells
	 */
	if (copyin((void *)arg, cp, csize - (nresults * sizeof (fc_cell_t)))) {
		FC_DEBUG1(1, CE_CONT, "fc_ioctl: fc_run_priv "
		    "fault copying in argument array from %p\n", arg);
		kmem_free(cp, csize);
		return (EFAULT);
	}
	/*
	 * reset the error fields.
	 */
	cp->error = fc_int2cell(0);
	cp->priv_error = fc_int2cell(0);

	/*
	 * Copy in the service name into our copy of the array.
	 * Later, be careful not to copy out the svc name pointer.
	 */
	name = kmem_zalloc(FC_SVC_NAME_LEN, KM_SLEEP);
	if (copyinstr(fc_cell2ptr(cp->svc_name), name,
	    FC_SVC_NAME_LEN - 1, NULL))  {
		FC_DEBUG1(1, CE_CONT, "fc_ioctl: fc_run_priv "
		    "fault copying in service name from %p\n",
		    fc_cell2ptr(cp->svc_name));
		kmem_free(cp, csize);
		kmem_free(name, FC_SVC_NAME_LEN);
		return (EFAULT);
	}
	cp->svc_name = fc_ptr2cell(name);

	FC_DEBUG3(7, CE_CONT, "fc_ioctl: fc_run_priv: "
	    "service name <%s> nargs %d nresults %d\n",
	    name, fc_cell2int(cp->nargs), fc_cell2int(cp->nresults));

	/*
	 * Call the driver's ops function to provide the service
	 */
	fp = st->req;
	ASSERT(fp->ap_ops);

	error = fp->ap_ops(fp->ap_dip, fp->handle, cp);

	/*
	 * If error is non-zero, we need to log the error and
	 * the service name, and write back the error to the
	 * callers argument array.
	 */

	if (error || cp->error) {
		FC_DEBUG1(1, CE_CONT, "fc_ioctl: fc_run_priv: "
		    "service name <%s> was unserviced\n", name);
		cp->error = FC_ERR_SVC_NAME;
		cp->nresults = fc_int2cell(0);
		error = copyout(&cp->error, &ap->error, sizeof (fc_cell_t));
		error |= copyout(&cp->nresults, &ap->nresults,
		    sizeof (fc_cell_t));
		kmem_free(cp, csize);
		kmem_free(name, FC_SVC_NAME_LEN);
		if (error) {
			FC_DEBUG0(1, CE_CONT, "fc_ioctl: fc_run_priv "
			    "fault copying out error result\n");
			return (EFAULT);
		}
		return (0);
	}

	if (cp->priv_error) {
		FC_DEBUG1(1, CE_CONT, "fc_ioctl: fc_run_priv: "
		    "service name <%s> caused a priv violation\n", name);
		cp->priv_error = FC_PRIV_ERROR;
		cp->nresults = fc_int2cell(0);
		error = copyout(&cp->error, &ap->error, sizeof (fc_cell_t));
		error |= copyout(&cp->priv_error, &ap->priv_error,
		    sizeof (fc_cell_t));
		error |= copyout(&cp->nresults, &ap->nresults,
		    sizeof (fc_cell_t));
		kmem_free(cp, csize);
		kmem_free(name, FC_SVC_NAME_LEN);
		if (error) {
			FC_DEBUG0(1, CE_CONT, "fc_ioctl: fc_run_priv "
			    "fault copying out priv error result\n");
			return (EFAULT);
		}
		return (0);
	}

	/*
	 * We believe we have a successful result at this point, thus we
	 * have to copy out the actual number of result cells to be
	 * returned, the two error fields and each of the results.
	 */

	if (fc_cell2int(cp->nresults) > nresults)
		cmn_err(CE_PANIC, "fc_ioctl: fc_run_priv: "
		    "results (from ops function) overflow\n");

	error = copyout(&cp->nresults, &ap->nresults, sizeof (fc_cell_t));
	error |= copyout(&cp->error, &ap->error, sizeof (fc_cell_t));
	error |= copyout(&cp->priv_error, &ap->priv_error, sizeof (fc_cell_t));
	if ((error == 0) && cp->nresults)
		error |= copyout(&fc_result(cp, 0), &(ap->v[nargs]),
		    cp->nresults * sizeof (fc_cell_t));

	kmem_free(cp, csize);
	kmem_free(name, FC_SVC_NAME_LEN);

	if (error) {
		FC_DEBUG0(1, CE_CONT, "fc_ioctl: fc_run_priv "
		    "fault copying out (good) results\n");
		return (EFAULT);
	}
	return (0);
}

/*ARGSUSED*/
static int
fc_validate(dev_t dev, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	struct fc_state *st;
	int m = (int)getminor(dev) - 1;
	struct fc_request *fp;
	struct fc_client_interface *cp;

	st = fc_states + m;
	ASSERT(m < fc_max_opens && FC_STATE_ACTIVE(st->state));

	/*
	 * It's an error if we're not in state FC_STATE_IN_PROGRESS
	 */
	if (st->state != FC_STATE_IN_PROGRESS) {
		cmn_err(CE_CONT, "fc_ioctl: fc_validate: wrong state (%d)\n",
		    st->state);
		return (EINVAL);
	}

	FC_DEBUG0(2, CE_CONT, "fc_ioctl: fc_validate: Sending validate cmd\n");

	/*
	 * Send a "validate" command down the line.
	 * The command has no arguments and no results.
	 */
	cp = kmem_zalloc(sizeof (struct fc_client_interface), KM_SLEEP);
	cp->svc_name = fc_ptr2cell(FC_SVC_VALIDATE);

	fp = st->req;
	ASSERT(fp->ap_ops);
	(void) fp->ap_ops(fp->ap_dip, fp->handle, cp);

	kmem_free(cp, sizeof (struct fc_client_interface));

	/*
	 * Update our state.
	 */
	mutex_enter(&fc_open_lock);
	st->state = FC_STATE_VALIDATED;
	mutex_exit(&fc_open_lock);
	return (0);
}

/*
 * fc_get_fcode:  Copy out device fcode to user buffer.
 * The input 'arg' is a pointer to 'fc_fcode_info_t' which
 * should have fcode_size field set.  The fcode_ptr field is a
 * pointer to a user buffer of fcode_size.
 */

/*ARGSUSED*/
static int
fc_get_fcode(dev_t dev, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	struct fc_state *st;
	int m = (int)getminor(dev) - 1;
	fco_handle_t rp;
	struct fc_fcode_info fcode_info;

	st = fc_states + m;
	ASSERT(m < fc_max_opens && FC_STATE_ACTIVE(st->state));

	/*
	 * It's an error if we're not in state FC_STATE_IN_PROGRESS
	 */
	if (st->state != FC_STATE_IN_PROGRESS) {
		cmn_err(CE_CONT, "fc_ioctl: fc_get_fcode: wrong state (%d)\n",
		    st->state);
		return (EINVAL);
	}

	ASSERT(st->req != NULL);
	rp = st->req->handle;

	FC_DEBUG1(3, CE_CONT, "fc_ioctl: fc_get_fcode fp: %p\n", st->req);

	/*
	 * Get the fc_fcode_info structure from userland.
	 */
	if (copyin((void *)arg, &fcode_info, sizeof (fc_fcode_info_t))) {
		FC_DEBUG1(1, CE_CONT, "fc_ioctl: fc_get_fcode "
		    "fault copying in fcode_info from %p\n", arg);
		return (EFAULT);
	}

	/*
	 * Validate that buffer size is what we expect.
	 */
	if (fcode_info.fcode_size != rp->fcode_size) {
		FC_DEBUG2(1, CE_CONT, "fc_ioctl: fc_get_fcode "
		    "requested size (0x%x) doesn't match real size (0x%x)\n",
		    fcode_info.fcode_size, rp->fcode_size);
		return (EINVAL);
	}

	/*
	 * Copyout the fcode.
	 */
	if (copyout(rp->fcode, fcode_info.fcode_ptr, rp->fcode_size) == -1) {
		FC_DEBUG1(1, CE_CONT, "fc_ioctl: fc_get_fcode "
		    "fault copying out fcode to %p\n", fcode_info.fcode_ptr);
		return (EFAULT);
	}

	return (0);
}

/*
 * fc_set_fcode_error:  Copy in	fcode error.
 * The input 'arg' is a pointer to int which
 * should have the appropriate error code set.
 */

/*ARGSUSED*/
static int
fc_set_fcode_error(dev_t dev, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	struct fc_state *st;
	struct fc_request *fp;
	int m = (int)getminor(dev) - 1;
	int status;

	st = fc_states + m;
	ASSERT(m < fc_max_opens && FC_STATE_ACTIVE(st->state));

	/*
	 * It's an error if we're not in state FC_STATE_IN_PROGRESS.
	 */
	if (st->state != FC_STATE_IN_PROGRESS) {
		cmn_err(CE_CONT,
		    "fc_ioctl:fc_set_fcode_error: wrong state (%d)\n",
		    st->state);
		return (EINVAL);
	}

	ASSERT(st->req != NULL);
	fp = st->req;

	FC_DEBUG1(3, CE_CONT, "fc_ioctl: fc_set_fcode_error fp: %p\n", fp);

	/*
	 * Get the error code from userland.
	 * We expect these to be negative values to denote
	 * interpreter errors.
	 */
	if (copyin((void *)arg, &status, sizeof (int))) {
		FC_DEBUG1(1, CE_CONT, "fc_ioctl: fc_set_fcode_error "
		    "fault copying in status from %p\n", arg);
		return (EFAULT);
	}

	if (!FC_ERROR_VALID(status)) {
		FC_DEBUG1(1, CE_CONT, "fc_ioctl: fc_set_fcode_error "
		    "invalid error code specified %i\n", status);
		return (EINVAL);
	}
	fp->error = status;
	mutex_enter(&fc_open_lock);
	st->state = FC_STATE_ERROR_SET;
	mutex_exit(&fc_open_lock);

	return (0);
}
