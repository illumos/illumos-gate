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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Media independent RPC-like comms
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/varargs.h>
#ifdef DS_DDICT
#include <sys/nsctl/contract.h>
#endif
#include "ncall.h"
#include "ncall_module.h"

#include <sys/nsctl/nsvers.h>

/*
 * cb_ops functions.
 */

static int ncallioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int ncallprint(dev_t, char *);


static struct cb_ops ncall_cb_ops = {
	nulldev,	/* open */
	nulldev,	/* close */
	nulldev,	/* strategy */
	ncallprint,
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	ncallioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,		/* NOT a stream */
	D_NEW | D_MP | D_64BIT,
	CB_REV,
	nodev,		/* aread */
	nodev,		/* awrite */
};


/*
 * dev_ops functions.
 */

static int ncall_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ncall_attach(dev_info_t *, ddi_attach_cmd_t);
static int ncall_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops ncall_ops = {
	DEVO_REV,
	0,
	ncall_getinfo,
	nulldev,	/* identify */
	nulldev,	/* probe */
	ncall_attach,
	ncall_detach,
	nodev,		/* reset */
	&ncall_cb_ops,
	(struct bus_ops *)0,
	NULL		/* power */
};

/*
 * Module linkage.
 */

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"nws:Kernel Call:" ISS_VERSION_STR,
	&ncall_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	0
};

typedef struct ncall_modinfo_s {
	struct ncall_modinfo_s	*next;
	ncall_module_t		*module;
} ncall_modinfo_t;

static dev_info_t *ncall_dip;		/* Single DIP for driver */
static kmutex_t ncall_mutex;

static ncall_modinfo_t *ncall_modules;
static int ncall_active;

static ncall_node_t ncall_nodeinfo;

static int ncallgetnodes(intptr_t, int, int *);
extern void ncall_init_stub(void);

int
_init(void)
{
	int error;

	mutex_init(&ncall_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((error = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&ncall_mutex);
		return (error);
	}

	return (0);
}


int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	mutex_destroy(&ncall_mutex);
	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
ncall_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {

	case DDI_ATTACH:
		ncall_dip = dip;

		if (ddi_create_minor_node(dip, "c,ncall", S_IFCHR,
		    0, DDI_PSEUDO, 0) != DDI_SUCCESS)
			goto failed;

		ddi_report_dev(dip);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

failed:
	(void) ncall_detach(dip, DDI_DETACH);
	return (DDI_FAILURE);
}


static int
ncall_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {

	case DDI_DETACH:

		/*
		 * If still active, then refuse to detach.
		 */

		if (ncall_modules != NULL || ncall_active)
			return (DDI_FAILURE);

		/*
		 * Remove all minor nodes.
		 */

		ddi_remove_minor_node(dip, NULL);
		ncall_dip = NULL;

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */

static int
ncall_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int rc = DDI_FAILURE;

	switch (infocmd) {

	case DDI_INFO_DEVT2DEVINFO:
		*result = ncall_dip;
		rc = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		/*
		 * We only have a single instance.
		 */
		*result = 0;
		rc = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (rc);
}


/* ARGSUSED */
static int
ncallprint(dev_t dev, char *str)
{
	cmn_err(CE_WARN, "%s%d: %s", ddi_get_name(ncall_dip),
	    ddi_get_instance(ncall_dip), str);

	return (0);
}


int
ncall_register_module(ncall_module_t *mp, ncall_node_t *nodep)
{
	ncall_modinfo_t *new;
	int rc = 0;

	if (mp == NULL || mp->ncall_version != NCALL_MODULE_VER)
		return (EINVAL);

	new = kmem_alloc(sizeof (*new), KM_SLEEP);

	if (new != NULL) {
		new->module = mp;

		mutex_enter(&ncall_mutex);

		new->next = ncall_modules;
		ncall_modules = new;

		mutex_exit(&ncall_mutex);
	} else {
		rc = ENOMEM;
	}

	*nodep = ncall_nodeinfo;	/* structure copy */
	return (rc);
}


int
ncall_unregister_module(ncall_module_t *mod)
{
	ncall_modinfo_t **mpp;
	int rc = ESRCH;

	mutex_enter(&ncall_mutex);

	for (mpp = &ncall_modules; *mpp != NULL; mpp = &((*mpp)->next)) {
		if ((*mpp)->module == mod) {
			*mpp = (*mpp)->next;
			rc = 0;
			break;
		}
	}

	mutex_exit(&ncall_mutex);

	return (rc);
}


static int
ncall_stop(void)
{
	ncall_modinfo_t *mod;
	int rc = 0;

	mutex_enter(&ncall_mutex);

	while ((rc == 0) && ((mod = ncall_modules) != NULL)) {
		mutex_exit(&ncall_mutex);

		rc = (*mod->module->ncall_stop)();

		mutex_enter(&ncall_mutex);
	}

	mutex_exit(&ncall_mutex);

	return (rc);
}


/* ARGSUSED */
static int ncallioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *crp, int *rvalp)
{
	ncall_node_t node = { 0, };
	int mirror;
	int rc = 0;

	*rvalp = 0;

	if ((rc = drv_priv(crp)) != 0)
		return (rc);

	switch (cmd) {

	case NC_IOC_START:
		if (ncall_active) {
			rc = EALREADY;
			break;
		}

		if (ddi_copyin((void *)arg, &node, sizeof (node), mode) < 0)
			return (EFAULT);

		bcopy(&node, &ncall_nodeinfo, sizeof (ncall_nodeinfo));
		ncall_init_stub();
		ncall_active = 1;
		break;

	case NC_IOC_STOP:
		ncall_active = 0;
		rc = ncall_stop();
		break;

	case NC_IOC_GETNODE:
		if (!ncall_active) {
			rc = ENONET;
			break;
		}
		if (ddi_copyout(&ncall_nodeinfo, (void *)arg,
		    sizeof (ncall_nodeinfo), mode) < 0) {
			rc = EFAULT;
			break;
		}
		mirror = ncall_mirror(ncall_nodeinfo.nc_nodeid);
		/*
		 * can't return -1, as this will mask the ioctl
		 * failure, so return 0.
		 */
		if (mirror == -1)
			mirror = 0;
		*rvalp = mirror;
		break;

	case NC_IOC_GETNETNODES:
		rc = ncallgetnodes(arg, mode, rvalp);
		break;

	case NC_IOC_PING:
		if (!ncall_active) {
			rc = ENONET;
			break;
		}

		if (ddi_copyin((void *)arg, &node, sizeof (node), mode) < 0) {
			rc = EFAULT;
			break;
		}

		node.nc_nodename[sizeof (node.nc_nodename)-1] = '\0';
		rc = ncall_ping(node.nc_nodename, rvalp);
		break;

	default:
		rc = EINVAL;
		break;
	}

	return (rc);
}


void
ncall_register_svc(int svc_id, void (*func)(ncall_t *, int *))
{
	if (ncall_modules)
		(*ncall_modules->module->ncall_register_svc)(svc_id, func);
}


void
ncall_unregister_svc(int svc_id)
{
	if (ncall_modules)
		(*ncall_modules->module->ncall_unregister_svc)(svc_id);
}


int
ncall_nodeid(char *nodename)
{
	if (ncall_modules)
		return ((ncall_modules->module->ncall_nodeid)(nodename));
	else
		return (0);
}


char *
ncall_nodename(int nodeid)
{
	if (ncall_modules)
		return ((*ncall_modules->module->ncall_nodename)(nodeid));
	else
		return ("unknown");
}


int
ncall_mirror(int nodeid)
{
	if (ncall_modules)
		return ((*ncall_modules->module->ncall_mirror)(nodeid));
	else
		return (-1);
}


int
ncall_self(void)
{
	if (ncall_modules)
		return ((*ncall_modules->module->ncall_self)());
	else
		return (-1);
}


int
ncall_alloc(int host_id, int flags, int net, ncall_t **ncall_p)
{
	int rc = ENOLINK;

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_alloc)(host_id,
		    flags, net, ncall_p);

	return (rc);
}


int
ncall_timedsend(ncall_t *ncall, int flags, int svc_id,
    struct timeval *t, ...)
{
	va_list ap;
	int rc = ENOLINK;

	va_start(ap, t);

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_timedsend)(ncall, flags,
		    svc_id, t, ap);

	va_end(ap);

	return (rc);
}

int
ncall_timedsendnotify(ncall_t *ncall, int flags, int svc_id,
    struct timeval *t, void (*ncall_callback)(ncall_t *, void *),
    void *vptr, ...)
{
	va_list ap;
	int rc = ENOLINK;

	va_start(ap, vptr);

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_timedsendnotify)(ncall,
		    flags, svc_id, t, ncall_callback, vptr, ap);
	va_end(ap);

	return (rc);
}

int
ncall_broadcast(ncall_t *ncall, int flags, int svc_id,
    struct timeval *t, ...)
{
	va_list ap;
	int rc = ENOLINK;

	va_start(ap, t);

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_broadcast)(ncall, flags,
		    svc_id, t, ap);
	va_end(ap);

	return (rc);
}


int
ncall_send(ncall_t *ncall, int flags, int svc_id, ...)
{
	va_list ap;
	int rc = ENOLINK;

	va_start(ap, svc_id);

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_timedsend)(ncall, flags,
		    svc_id, NULL, ap);

	va_end(ap);

	return (rc);
}


int
ncall_read_reply(ncall_t *ncall, int n, ...)
{
	va_list ap;
	int rc = ENOLINK;

	va_start(ap, n);

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_read_reply)(ncall, n, ap);

	va_end(ap);

	return (rc);
}


void
ncall_reset(ncall_t *ncall)
{
	if (ncall_modules)
		(*ncall_modules->module->ncall_reset)(ncall);
}


void
ncall_free(ncall_t *ncall)
{
	if (ncall_modules)
		(*ncall_modules->module->ncall_free)(ncall);
}


int
ncall_put_data(ncall_t *ncall, void *data, int len)
{
	int rc = ENOLINK;

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_put_data)(ncall, data, len);

	return (rc);
}


int
ncall_get_data(ncall_t *ncall, void *data, int len)
{
	int rc = ENOLINK;

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_get_data)(ncall, data, len);

	return (rc);
}


int
ncall_sender(ncall_t *ncall)
{
	int rc = -1;

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_sender)(ncall);

	return (rc);
}


void
ncall_reply(ncall_t *ncall, ...)
{
	va_list ap;

	if (ncall_modules) {
		va_start(ap, ncall);

		(*ncall_modules->module->ncall_reply)(ncall, ap);

		va_end(ap);
	}
}


void
ncall_pend(ncall_t *ncall)
{
	if (ncall_modules)
		(*ncall_modules->module->ncall_pend)(ncall);
}


void
ncall_done(ncall_t *ncall)
{
	if (ncall_modules)
		(*ncall_modules->module->ncall_done)(ncall);
}

int
ncall_ping(char *nodename, int *up)
{
	int rc = ENOLINK;
	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_ping)(nodename, up);
	return (rc);
}

int
ncall_maxnodes()
{
	int rc = 0;

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_maxnodes)();

	return (rc);
}

int
ncall_nextnode(void **vptr)
{
	int rc = 0;

	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_nextnode)(vptr);

	return (rc);
}

int
ncall_errcode(ncall_t *ncall, int *result)
{
	int rc = ENOLINK;
	if (ncall_modules)
		rc = (*ncall_modules->module->ncall_errcode)(ncall, result);

	return (rc);
}

static int
ncallgetnodes(intptr_t uaddr, int mode, int *rvalp)
{
	ncall_node_t *nodelist;
	int slot;
	int rc;
	int nodecnt;
	int nodeid;
	void *sequence;
	char *nodename;

	rc = 0;

	nodecnt = ncall_maxnodes();
	if (nodecnt <= 0) {
		return (ENONET);
	}

	/*
	 * If the user passes up a null address argument, then
	 * they don't want the actual nodes, but the configured
	 * maximum, so space can be correctly allocated.
	 */

	if (uaddr == NULL) {
		*rvalp = nodecnt;
		return (0);
	}
	nodelist = kmem_zalloc(sizeof (*nodelist) * nodecnt, KM_SLEEP);

	slot = 0;
	sequence = NULL;
	while ((nodeid = ncall_nextnode(&sequence)) > 0) {
		nodename = ncall_nodename(nodeid);
		/*
		 * There is a small window where nextnode can
		 * return a valid nodeid, and it being disabled
		 * which will get nodename to return "".
		 * Discard the nodeid if this happens.
		 */
		if (strlen(nodename) > 0) {
			int size = sizeof (nodelist[slot].nc_nodename) - 1;
			ASSERT(slot < nodecnt);
			/*
			 * make sure its null terminated when it
			 * gets to userland.
			 */
			nodelist[slot].nc_nodename[size] = 0;
			(void) strncpy(nodelist[slot].nc_nodename, nodename,
			    size);
			nodelist[slot].nc_nodeid = nodeid;
			slot++;
		}
	}
	if (ddi_copyout(nodelist, (void *)uaddr, sizeof (*nodelist) * slot,
	    mode) < 0) {
		rc = EFAULT;
	} else {
		/*
		 * tell them how many have come back.
		 */
		*rvalp = slot;
	}
	kmem_free(nodelist, sizeof (*nodelist) * nodecnt);
	return (rc);
}
