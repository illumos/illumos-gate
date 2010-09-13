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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/ib/clients/iser/iser.h>

/*
 * iser.c
 *    DDI and core routines for Solaris iSER implementation.
 */

iser_state_t	*iser_state = NULL;	/* global state */
ddi_taskq_t	*iser_taskq = NULL;	/* global taskq */

/* set B_TRUE for console logging */
boolean_t iser_logging = B_FALSE;

/* Driver functions */
static int iser_attach(dev_info_t *, ddi_attach_cmd_t);
static int iser_detach(dev_info_t *, ddi_detach_cmd_t);
static int iser_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int iser_open(dev_t *, int, int, cred_t *);
static int iser_close(dev_t, int, int, cred_t *);
static int iser_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
/* static int iser_close(dev_t, int, int, cred_t *); */

/* Char/Block operations */
static struct cb_ops	iser_cb_ops = {
	iser_open,		/* open */
	iser_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	iser_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev,			/* int (*cb_awrite)() */
};

/* Device operations */
static struct dev_ops iser_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	iser_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	iser_attach,		/* attach */
	iser_detach,		/* detach */
	nodev,			/* reset */
	&iser_cb_ops,		/* cb_ops */
	NULL,			/* bus ops */
	NULL,			/* power */
	ddi_quiesce_not_needed	/* quiesce */
};

/* Module Driver Info */
#define	ISER_NAME_VERSION	"iSCSI Extensions for RDMA"
static struct modldrv iser_modldrv = {
	&mod_driverops,
	ISER_NAME_VERSION,
	&iser_ops,
};

/* Module Linkage */
static struct modlinkage iser_modlinkage = {
	MODREV_1,
	&iser_modldrv,
	NULL
};

/*
 * _init()
 */
int
_init(void)
{
	int	status;

	iser_state = kmem_zalloc(sizeof (iser_state_t), KM_SLEEP);
	status = mod_install(&iser_modlinkage);
	if (status != DDI_SUCCESS) {
		kmem_free(iser_state, sizeof (iser_state_t));
	}

	return (status);
}

/*
 * _info()
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&iser_modlinkage, modinfop));
}

/*
 * _fini()
 */
int
_fini(void)
{
	int status;

	status = mod_remove(&iser_modlinkage);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	kmem_free(iser_state, sizeof (iser_state_t));

	return (DDI_SUCCESS);
}

/*
 * iser_attach()
 */
static int
iser_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	int		status;

	switch (cmd) {
	case DDI_ATTACH:
		ISER_LOG(CE_CONT, "iser_attach: DDI_ATTACH");
		instance = ddi_get_instance(dip);

		iser_state->is_dip = dip;
		iser_state->is_instance = instance;

		/* Initialize the open refcnt and it's lock */
		iser_state->is_open_refcnt = 0;
		mutex_init(&iser_state->is_refcnt_lock, NULL, MUTEX_DRIVER,
		    NULL);

		iser_taskq = ddi_taskq_create(dip, "iser_taskq",
		    ISER_TASKQ_NTHREADS, TASKQ_DEFAULTPRI, 0);

		if (iser_taskq == NULL) {
			ISER_LOG(CE_CONT, "%s%d: failed to create taskq",
			    "iser", instance);
			mutex_destroy(&iser_state->is_refcnt_lock);
			return (DDI_FAILURE);
		}

		/* initialize iSER as IB service */
		status = iser_ib_init();
		if (status != DDI_SUCCESS) {
			ddi_taskq_destroy(iser_taskq);
			mutex_destroy(&iser_state->is_refcnt_lock);
			ISER_LOG(CE_CONT, "%s%d: failed to initialize IB",
			    "iser", instance);
			return (DDI_FAILURE);
		}

		status = ddi_create_minor_node(
		    dip, ddi_get_name(dip), S_IFCHR, instance,
		    DDI_PSEUDO, 0);
		if (status != DDI_SUCCESS) {
			(void) iser_ib_fini();
			ddi_taskq_destroy(iser_taskq);
			mutex_destroy(&iser_state->is_refcnt_lock);
			ISER_LOG(CE_CONT, "%s%d: failed ddi_create_minor_node",
			    "iser", instance);
			return (DDI_FAILURE);
		}

		ddi_report_dev(dip);

		return (DDI_SUCCESS);

	case DDI_RESUME:
		ISER_LOG(CE_CONT, "iser_detach: DDI_RESUME unsupported");
		return (DDI_FAILURE);

	default:
		ISER_LOG(CE_CONT, "%s%d: unknown cmd in attach (0x%x)", "iser",
		    instance, cmd);
		return (DDI_FAILURE);
	}
}

/*
 * iser_detach()
 */
static int
iser_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	mutex_enter(&iser_state->is_refcnt_lock);
	if (iser_state->is_open_refcnt > 0) {
		mutex_exit(&iser_state->is_refcnt_lock);
		return (DDI_FAILURE);
	}
	mutex_exit(&iser_state->is_refcnt_lock);
	mutex_destroy(&iser_state->is_refcnt_lock);

	switch (cmd) {
	case DDI_DETACH:
		ISER_LOG(CE_CONT, "iser_detach: DDI_DETACH");

		if (iser_ib_fini() != DDI_SUCCESS) {
			ISER_LOG(CE_CONT, "iser_ib_fini failed");
			return (DDI_FAILURE);
		}

		if (iser_taskq != NULL) {
			ddi_taskq_destroy(iser_taskq);
			iser_taskq = NULL;
		}
		ddi_remove_minor_node(dip, NULL);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		ISER_LOG(CE_CONT, "iser_detach: DDI_SUSPEND unsupported");
		return (DDI_FAILURE);

	default:
		ISER_LOG(CE_CONT, "iser: unknown cmd in detach (0x%x)", cmd);
		return (DDI_FAILURE);
	}
}

/*
 * iser_getinfo()
 */
/* ARGSUSED */
static int
iser_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)iser_state->is_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

}

/*
 * iser_open()
 */
/* ARGSUSED */
static int
iser_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	minor_t		instance;
	int		status;

	instance = getminor(*devp);

	/* Register the transport with IDM */
	status = iser_idm_register();
	if (status != DDI_SUCCESS) {
		ISER_LOG(CE_CONT, "%s%d: failed to register with IDM",
		    "iser", instance);
		return (ENXIO);
	}

	/* Increment our open refcnt */
	mutex_enter(&iser_state->is_refcnt_lock);
	iser_state->is_open_refcnt++;
	mutex_exit(&iser_state->is_refcnt_lock);

	return (DDI_SUCCESS);
}

/*
 * iser_close()
 */
/* ARGSUSED */
static int
iser_close(dev_t devp, int flag, int otyp, cred_t *credp)
{
	ASSERT(iser_state->is_open_refcnt != 0);

	mutex_enter(&iser_state->is_refcnt_lock);
	iser_state->is_open_refcnt--;
	mutex_exit(&iser_state->is_refcnt_lock);

	return (DDI_SUCCESS);
}

iser_status_t
iser_register_service(idm_svc_t *idm_svc)
{

	return (iser_ib_register_service(idm_svc));
}

iser_status_t
iser_bind_service(idm_svc_t *idm_svc)
{

	return (iser_ib_bind_service(idm_svc));
}

void
iser_unbind_service(idm_svc_t *idm_svc)
{

	iser_ib_unbind_service(idm_svc);
}

void
iser_deregister_service(idm_svc_t *idm_svc)
{

	iser_ib_deregister_service(idm_svc);
}

/*
 * iser_path_exists
 * This function takes in a pair of endpoints and determines if an iSER path
 * exists between the two. The actual path information (required for creating
 * a RC channel) is not returned, instead a boolean value indicating if a path
 * exists is returned.
 *
 * To use an implicit source, a value of NULL is allowed for laddr.
 */
boolean_t
iser_path_exists(idm_sockaddr_t *laddr, idm_sockaddr_t *raddr)
{

	ibt_ip_addr_t		remote_ip, local_ip;
	ibt_path_info_t		path;
	int			status;

	iser_ib_conv_sockaddr2ibtaddr(raddr, &remote_ip);
	iser_ib_conv_sockaddr2ibtaddr(laddr, &local_ip);

	status = iser_ib_get_paths(&local_ip, &remote_ip, &path, NULL);

	return ((status == IBT_SUCCESS) ? B_TRUE : B_FALSE);
}

/*
 * iser_channel_alloc
 * This function allocates a reliable communication channel between the
 * given endpoints.
 */
iser_chan_t *
iser_channel_alloc(idm_sockaddr_t *laddr, idm_sockaddr_t *raddr)
{
	ibt_ip_addr_t		remote_ip, local_ip;

	iser_ib_conv_sockaddr2ibtaddr(raddr, &remote_ip);
	iser_ib_conv_sockaddr2ibtaddr(laddr, &local_ip);

	return (iser_ib_alloc_channel_pathlookup(&local_ip, &remote_ip));
}

/*
 * iser_channel_open
 * This function opens the already allocated communication channel between the
 * two endpoints.
 */
iser_status_t
iser_channel_open(iser_chan_t *chan)
{
	return (iser_ib_open_rc_channel(chan));
}

/*
 * iser_channel_close
 * This function closes the already opened communication channel between the
 * two endpoints.
 */
void
iser_channel_close(iser_chan_t *chan)
{
	iser_ib_close_rc_channel(chan);
}

/*
 * iser_channel_free
 * This function frees the channel between the given endpoints
 */
void
iser_channel_free(iser_chan_t *chan)
{
	iser_ib_free_rc_channel(chan);
}

/* ARGSUSED */
static int
iser_ioctl(dev_t devp, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	return (DDI_SUCCESS);
}
