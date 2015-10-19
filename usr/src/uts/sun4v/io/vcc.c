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
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/stat.h> /* needed for S_IFBLK and S_IFCHR */
#include <sys/debug.h>
#include <sys/promif.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cyclic.h>
#include <sys/termio.h>
#include <sys/intr.h>
#include <sys/ivintr.h>
#include <sys/note.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/sysmacros.h>

#include <sys/ldc.h>
#include <sys/mdeg.h>
#include <sys/vcc_impl.h>

#define	VCC_LDC_RETRIES		5
#define	VCC_LDC_DELAY		1000 /* usec */

/*
 * Function prototypes.
 */

/* DDI entrypoints */
static int	vcc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	vcc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	vcc_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int	vcc_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int	vcc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
			cred_t *credp, int *rvalp);
static int	vcc_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int	vcc_write(dev_t dev, struct uio *uiop, cred_t *credp);
static int	vcc_chpoll(dev_t dev, short events, int anyyet,
			short *reventsp, struct pollhead **phpp);
static int	vcc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
			void *arg, void **resultp);

/* callback functions */
static uint_t	vcc_ldc_cb(uint64_t event, caddr_t arg);
static int	vcc_mdeg_cb(void *cb_argp, mdeg_result_t *resp);

/* Internal functions */
static int	i_vcc_ldc_init(vcc_t *vccp, vcc_port_t *vport);
static int	i_vcc_add_port(vcc_t *vccp, char *group_name, uint64_t tcp_port,
			uint_t portno, char *domain_name);
static int	i_vcc_config_port(vcc_t *vccp, uint_t portno, uint64_t ldc_id);
static int	i_vcc_reset_events(vcc_t *vccp);
static int	i_vcc_cons_tbl(vcc_t *vccp, uint_t num_ports,
			caddr_t buf, int mode);
static int	i_vcc_del_cons_ok(vcc_t *vccp, caddr_t buf, int mode);
static int	i_vcc_close_port(vcc_port_t *vport);
static int	i_vcc_write_ldc(vcc_port_t *vport, vcc_msg_t *buf);
static int	i_vcc_read_ldc(vcc_port_t *vport, char *data_buf, size_t *sz);

static void *vcc_ssp;

static struct cb_ops vcc_cb_ops = {
	vcc_open,	    /* open */
	vcc_close,	    /* close */
	nodev,		    /* strategy */
	nodev,		    /* print */
	nodev,		    /* dump */
	vcc_read,	    /* read */
	vcc_write,	    /* write */
	vcc_ioctl,	    /* ioctl */
	nodev,		    /* devmap */
	nodev,		    /* mmap */
	ddi_segmap,	    /* segmap */
	vcc_chpoll,	    /* chpoll */
	ddi_prop_op,	    /* prop_op */
	NULL,		    /* stream */
	D_NEW | D_MP	    /* flags */
};


static struct dev_ops vcc_ops = {
	DEVO_REV,		/* rev */
	0,			/* ref count */
	vcc_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	vcc_attach,		/* attach */
	vcc_detach,		/* detach */
	nodev,			/* reset */
	&vcc_cb_ops,		/* cb_ops */
	(struct bus_ops *)NULL,	/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

#define	    VCC_CHANNEL_ENDPOINT	"channel-endpoint"
#define	    VCC_ID_PROP		"id"

/*
 * This is the string displayed by modinfo(1m).
 */
static char vcc_ident[] = "sun4v Virtual Console Concentrator Driver";

static struct modldrv md = {
	&mod_driverops, 	/* Type - it is a driver */
	vcc_ident,		/* Name of the module */
	&vcc_ops,		/* driver specfic opts */
};

static struct modlinkage ml = {
	MODREV_1,
	&md,
	NULL
};

/*
 * Matching criteria passed to the MDEG to register interest
 * in changes to 'virtual-device-port' nodes identified by their
 * 'id' property.
 */
static md_prop_match_t vcc_port_prop_match[] = {
	{ MDET_PROP_VAL,	    "id"   },
	{ MDET_LIST_END,	    NULL    }
};

static mdeg_node_match_t vcc_port_match = {"virtual-device-port",
					vcc_port_prop_match};

/*
 * Specification of an MD node passed to the MDEG to filter any
 * 'virtual-device-port' nodes that do not belong to the specified node.
 * This template is copied for each vldc instance and filled in with
 * the appropriate 'cfg-handle' value before being passed to the MDEG.
 */
static mdeg_prop_spec_t vcc_prop_template[] = {
	{ MDET_PROP_STR,    "name",	"virtual-console-concentrator"	},
	{ MDET_PROP_VAL,    "cfg-handle",	NULL	},
	{ MDET_LIST_END,    NULL,		NULL	}
};

#define	VCC_SET_MDEG_PROP_INST(specp, val) (specp)[1].ps_val = (val);


#ifdef DEBUG

/*
 * Print debug messages
 *
 * set vldcdbg to 0xf to enable all messages
 *
 * 0x8 - Errors
 * 0x4 - Warnings
 * 0x2 - All debug messages (most verbose)
 * 0x1 - Minimal debug messages
 */

int vccdbg = 0x8;

static void
vccdebug(const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	cmn_err(CE_CONT, "%s\n", buf);
}

#define	D1		\
if (vccdbg & 0x01)	\
	vccdebug

#define	D2		\
if (vccdbg & 0x02)	\
	vccdebug

#define	DWARN		\
if (vccdbg & 0x04)	\
	vccdebug

#else

#define	D1
#define	D2
#define	DWARN

#endif

/* _init(9E): initialize the loadable module */
int
_init(void)
{
	int error;

	/* init the soft state structure */
	error = ddi_soft_state_init(&vcc_ssp, sizeof (vcc_t), 1);
	if (error != 0) {
		return (error);
	}

	/* Link the driver into the system */
	error = mod_install(&ml);

	return (error);

}

/* _info(9E): return information about the loadable module */
int
_info(struct modinfo *modinfop)
{
	/* Report status of the dynamically loadable driver module */
	return (mod_info(&ml, modinfop));
}

/* _fini(9E): prepare the module for unloading. */
int
_fini(void)
{
	int error;

	/* Unlink the driver module from the system */
	if ((error = mod_remove(&ml)) == 0) {
		/*
		 * We have successfully "removed" the driver.
		 * destroy soft state
		 */
		ddi_soft_state_fini(&vcc_ssp);
	}

	return (error);
}

/* getinfo(9E) */
static int
vcc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,  void *arg, void **resultp)
{
	_NOTE(ARGUNUSED(dip))

	int	instance = VCCINST(getminor((dev_t)arg));
	vcc_t	*vccp = NULL;

	switch (cmd) {

	case DDI_INFO_DEVT2DEVINFO:
		if ((vccp = ddi_get_soft_state(vcc_ssp, instance)) == NULL) {
			*resultp = NULL;
			return (DDI_FAILURE);
		}
		*resultp = vccp->dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	default:
		*resultp = NULL;
		return (DDI_FAILURE);
	}
}

/*
 * There are two cases that need special blocking. One of them is to block
 * a minor node without a port and another is to block application other
 * than vntsd.
 *
 * A minor node can exist in the file system without associated with a port
 * because when a port is deleted, ddi_remove_minor does not unlink it.
 * Clients might try to open a minor node even after the corresponding port
 * node has been removed.  To identify and block these calls,
 * we need to validate the association between a port and its minor node.
 *
 * An application other than vntsd can access a console port as long
 * as vntsd is not using the port. A port opened by an application other
 * than vntsd will be closed when vntsd wants to use the port.
 * However, other application could use same file descriptor
 * access vcc cb_ops. So we need to identify and block caller other
 * than vntsd, when vntsd is using the port.
 */
static int
i_vcc_can_use_port(vcc_minor_t *minorp, vcc_port_t *vport)
{
	if (vport->minorp != minorp) {
		/* port config changed */
		return (ENXIO);
	}

	if (vport->valid_pid == VCC_NO_PID_BLOCKING) {
		/* no blocking needed */
		return (0);
	}

	if (vport->valid_pid != ddi_get_pid()) {
		return (EIO);
	}

	return (0);
}


/* Syncronization between thread using cv_wait */
static int
i_vcc_wait_port_status(vcc_port_t *vport, kcondvar_t *cv, uint32_t status)
{

	int	    rv;

	ASSERT(mutex_owned(&vport->lock));

	for (; ; ) {

		if ((vport->status & VCC_PORT_AVAIL) == 0) {
			/* port has been deleted */
			D1("i_vcc_wait_port_status: port%d deleted\n",
			    vport->number);
			return (EIO);
		}

		if ((vport->status & VCC_PORT_OPEN) == 0) {
			D1("i_vcc_wait_port_status: port%d is closed \n",
			    vport->number);
			return (EIO);
		}

		if (vport->status & VCC_PORT_LDC_LINK_DOWN) {
			return (EIO);
		}

		if ((vport->valid_pid != VCC_NO_PID_BLOCKING) &&
		    (vport->valid_pid != ddi_get_pid())) {
			return (EIO);
		}

		if ((vport->status & status) == status) {
			return (0);
		}

		if (!ddi_can_receive_sig()) {
			return (EIO);
		}

		rv = cv_wait_sig(cv, &vport->lock);
		if (rv == 0) {
			D1("i_vcc_wait_port_status: port%d get intr \n",
			    vport->number);
			/* got signal */
			return (EINTR);
		}
	}

}

/* Syncronization between threads, signal state change */
static void
i_vcc_set_port_status(vcc_port_t *vport, kcondvar_t *cv, uint32_t status)
{

	mutex_enter(&vport->lock);
	vport->status |= status;
	cv_broadcast(cv);
	mutex_exit(&vport->lock);
}

/* initialize a ldc channel */
static int
i_vcc_ldc_init(vcc_t *vccp, vcc_port_t *vport)
{
	ldc_attr_t 	attr;
	int		rv = EIO;

	ASSERT(mutex_owned(&vport->lock));
	ASSERT(vport->ldc_id != VCC_INVALID_CHANNEL);

	/* initialize the channel */
	attr.devclass = LDC_DEV_SERIAL;
	attr.instance = ddi_get_instance(vccp->dip);
	attr.mtu = VCC_MTU_SZ;
	attr.mode = LDC_MODE_RAW;

	if ((rv = ldc_init(vport->ldc_id, &attr, &(vport->ldc_handle))) != 0) {
		cmn_err(CE_CONT, "i_vcc_ldc_init: port %d ldc channel %ld"
		    " failed ldc_init %d \n", vport->number, vport->ldc_id, rv);
		vport->ldc_id = VCC_INVALID_CHANNEL;
		return (rv);
	}

	/* register it */
	if ((rv = ldc_reg_callback(vport->ldc_handle, vcc_ldc_cb,
	    (caddr_t)vport)) != 0) {
		cmn_err(CE_CONT, "i_vcc_ldc_init: port@%d ldc_register_cb"
		    "failed\n", vport->number);
		(void) ldc_fini(vport->ldc_handle);
		vport->ldc_id = VCC_INVALID_CHANNEL;
		return (rv);
	}

	/* open and bring channel up */
	if ((rv = ldc_open(vport->ldc_handle)) != 0) {
		cmn_err(CE_CONT, "i_vcc_ldc_init: port@%d inv channel 0x%lx\n",
		    vport->number, vport->ldc_id);
		(void) ldc_unreg_callback(vport->ldc_handle);
		(void) ldc_fini(vport->ldc_handle);
		vport->ldc_id = VCC_INVALID_CHANNEL;
		return (rv);
	}

	/* init the channel status */
	if ((rv = ldc_status(vport->ldc_handle, &vport->ldc_status)) != 0) {
		cmn_err(CE_CONT, "i_vcc_ldc_init: port@%d ldc_status failed\n",
		    vport->number);
		(void) ldc_close(vport->ldc_handle);
		(void) ldc_unreg_callback(vport->ldc_handle);
		(void) ldc_fini(vport->ldc_handle);
		vport->ldc_id = VCC_INVALID_CHANNEL;
		return (rv);
	}

	return (0);
}

/*  release a ldc channel */
static void
i_vcc_ldc_fini(vcc_port_t *vport)
{
	int 		rv = EIO;
	vcc_msg_t	buf;
	size_t		sz;
	int		retry = 0;

	D1("i_vcc_ldc_fini: port@%lld, ldc_id%%llx\n", vport->number,
	    vport->ldc_id);

	ASSERT(mutex_owned(&vport->lock));

	/* wait for write available */
	rv = i_vcc_wait_port_status(vport, &vport->write_cv,
	    VCC_PORT_USE_WRITE_LDC);

	if (rv == 0) {
		vport->status &= ~VCC_PORT_USE_WRITE_LDC;

		/* send a HUP message */
		buf.type = LDC_CONSOLE_CTRL;
		buf.ctrl_msg = LDC_CONSOLE_HUP;
		buf.size = 0;

		/*
		 * ignore write error since we still want to clean up
		 * ldc channel.
		 */
		(void) i_vcc_write_ldc(vport, &buf);

		mutex_exit(&vport->lock);
		i_vcc_set_port_status(vport, &vport->write_cv,
		    VCC_PORT_USE_WRITE_LDC);
		mutex_enter(&vport->lock);
	}

	/* flush ldc channel */
	rv = i_vcc_wait_port_status(vport, &vport->read_cv,
	    VCC_PORT_USE_READ_LDC);

	if (rv == 0) {
		vport->status &= ~VCC_PORT_USE_READ_LDC;
		do {
			sz = sizeof (buf);
			rv = i_vcc_read_ldc(vport, (char *)&buf, &sz);
		} while (rv == 0 && sz > 0);

		vport->status |= VCC_PORT_USE_READ_LDC;

	}

	/*
	 * ignore read error since we still want to clean up
	 * ldc channel.
	 */

	(void) ldc_set_cb_mode(vport->ldc_handle, LDC_CB_DISABLE);

	/* close LDC channel - retry on EAGAIN */
	while ((rv = ldc_close(vport->ldc_handle)) == EAGAIN) {

		if (++retry > VCC_LDC_RETRIES) {
			cmn_err(CE_CONT, "i_vcc_ldc_fini: cannot close channel"
			    " %ld\n", vport->ldc_id);
			break;
		}

		drv_usecwait(VCC_LDC_DELAY);
	}

	if (rv == 0) {
		(void) ldc_unreg_callback(vport->ldc_handle);
		(void) ldc_fini(vport->ldc_handle);
	} else {
		/*
		 * Closing the LDC channel has failed. Ideally we should
		 * fail here but there is no Zeus level infrastructure
		 * to handle this. The MD has already been changed and
		 * we have to do the close. So we try to do as much
		 * clean up as we can.
		 */
		while (ldc_unreg_callback(vport->ldc_handle) == EAGAIN)
			drv_usecwait(VCC_LDC_DELAY);
	}

}

/* read data from ldc channel */

static int
i_vcc_read_ldc(vcc_port_t *vport, char *data_buf, size_t *sz)
{

	int		rv;
	size_t		size;
	size_t		space_left = *sz;
	vcc_msg_t  	buf;
	int 		i;




	/* make sure holding read lock */
	ASSERT((vport->status & VCC_PORT_USE_READ_LDC) == 0);
	ASSERT(space_left >= VCC_MTU_SZ);

	*sz = 0;
	while (space_left >= VCC_MTU_SZ)  {
		size = sizeof (buf);

		rv = ldc_read(vport->ldc_handle, (caddr_t)&buf, &size);

		if (rv) {
			return (rv);
		}


		/*
		 * FIXME: ldc_read should not reaturn 0 with
		 * either size == 0, buf.size == 0 or size < VCC_HDR_SZ
		 */
		if (size == 0) {
			if (*sz > 0) {
				return (0);
			}
			return (EAGAIN);
		}

		if (size < VCC_HDR_SZ) {
			return (EIO);
		}

		/*
		 * only data is expected from console - otherwise
		 * return error
		 */
		if (buf.type != LDC_CONSOLE_DATA) {
			return (EIO);
		}

		if (buf.size == 0) {
			if (*sz > 0) {
				return (0);
			}
			return (EAGAIN);
		}

		/* copy  data */
		for (i = 0; i < buf.size; i++, (*sz)++) {
			data_buf[*sz] = buf.data[i];
		}

		space_left -= buf.size;
	}

	return (0);
}

/* callback from ldc */
static uint_t
vcc_ldc_cb(uint64_t event, caddr_t arg)
{

	vcc_port_t  *vport = (vcc_port_t *)arg;
	boolean_t   hasdata;

	/*
	 * do not need to hold lock because if ldc calls back, the
	 * ldc_handle must be valid.
	 */
	D2("vcc_ldc_cb: callback invoked port=%d events=%llx\n",
	    vport->number, event);

	/* check event from ldc */
	if (event & LDC_EVT_WRITE) {
		/* channel has space for write */

		i_vcc_set_port_status(vport, &vport->write_cv,
		    VCC_PORT_LDC_WRITE_READY);
		return (LDC_SUCCESS);
	}

	if (event & LDC_EVT_READ) {

		/* channel has data for read */
		(void) ldc_chkq(vport->ldc_handle, &hasdata);
		if (!hasdata) {
			/* data already read */
			return (LDC_SUCCESS);
		}

		i_vcc_set_port_status(vport, &vport->read_cv,
		    VCC_PORT_LDC_DATA_READY);
		return (LDC_SUCCESS);
	}

	if (event & LDC_EVT_DOWN) {
		/* channel is down */
		i_vcc_set_port_status(vport, &vport->write_cv,
		    VCC_PORT_LDC_LINK_DOWN);
		cv_broadcast(&vport->read_cv);

	}

	return (LDC_SUCCESS);

}


/* configure a vcc port with ldc channel */
static int
i_vcc_config_port(vcc_t *vccp, uint_t portno, uint64_t ldc_id)
{
	int 		rv = EIO;
	vcc_port_t 	*vport;

	if ((portno >= VCC_MAX_PORTS) || (portno == VCC_CONTROL_PORT)) {
		cmn_err(CE_CONT, "i_vcc_config_port: invalid port number %d\n",
		    portno);
		return (EINVAL);
	}

	vport = &(vccp->port[portno]);
	if ((vport->status & VCC_PORT_AVAIL) == 0) {
		cmn_err(CE_CONT, "i_vcc_config_port: port@%d does not exist\n",
		    portno);
		return (EINVAL);
	}


	if (vport->ldc_id != VCC_INVALID_CHANNEL) {
		cmn_err(CE_CONT, "i_vcc_config_port: port@%d channel already"
		    "configured\n", portno);
		return (EINVAL);
	}

	mutex_enter(&vport->lock);

	/* store the ldc ID */
	vport->ldc_id = ldc_id;
	/* check if someone has already opened this port */
	if (vport->status & VCC_PORT_OPEN) {

		if ((rv = i_vcc_ldc_init(vccp, vport)) != 0) {
			mutex_exit(&vport->lock);
			return (rv);
		}

		/* mark port as ready */
		vport->status |= VCC_PORT_LDC_CHANNEL_READY;
		cv_broadcast(&vport->read_cv);
		cv_broadcast(&vport->write_cv);
	}

	mutex_exit(&vport->lock);

	D1("i_vcc_config_port: port@%d ldc=%d, domain=%s",
	    vport->number, vport->ldc_id, vport->minorp->domain_name);

	return (0);
}

/* add a vcc console port */
static int
i_vcc_add_port(vcc_t *vccp, char *group_name, uint64_t tcp_port,
    uint_t portno, char *domain_name)
{
	int 		instance;
	int		rv = MDEG_FAILURE;
	minor_t 	minor;
	vcc_port_t 	*vport;
	uint_t		minor_idx;
	char		name[MAXPATHLEN];

	if ((portno >= VCC_MAX_PORTS) || (portno == VCC_CONTROL_PORT)) {
		DWARN("i_vcc_add_port: invalid port number %d\n", portno);
		return (MDEG_FAILURE);
	}

	vport = &(vccp->port[portno]);
	if (vport->status & VCC_PORT_AVAIL) {
		/* this port already exists */
		cmn_err(CE_CONT, "i_vcc_add_port: invalid port - port@%d "
		    "exists\n", portno);
		return (MDEG_FAILURE);
	}

	vport->number = portno;
	vport->ldc_id = VCC_INVALID_CHANNEL;

	if (domain_name == NULL) {
		cmn_err(CE_CONT, "i_vcc_add_port: invalid domain name\n");
		return (MDEG_FAILURE);
	}

	if (group_name == NULL) {
		cmn_err(CE_CONT, "i_vcc_add_port: invalid group name\n");
		return (MDEG_FAILURE);
	}

	/* look up minor number */
	for (minor_idx = 0; minor_idx < vccp->minors_assigned; minor_idx++) {
		if (strcmp(vccp->minor_tbl[minor_idx].domain_name,
		    domain_name) == 0) {
			/* found previous assigned minor number */
			break;
		}
	}

	if (minor_idx == vccp->minors_assigned) {
		/* end of lookup - assign new minor number */
		if (minor_idx == VCC_MAX_PORTS) {
			cmn_err(CE_CONT, "i_vcc_add_port:"
			    "too many minornodes (%d)\n",
			    minor_idx);
			return (MDEG_FAILURE);
		}

		(void) strlcpy(vccp->minor_tbl[minor_idx].domain_name,
		    domain_name, MAXPATHLEN);

		vccp->minors_assigned++;
	}

	vport->minorp = &vccp->minor_tbl[minor_idx];
	vccp->minor_tbl[minor_idx].portno = portno;

	(void) strlcpy(vport->group_name, group_name, MAXPATHLEN);

	vport->tcp_port = tcp_port;
	D1("i_vcc_add_port:@%d domain=%s, group=%s, tcp=%lld",
	    vport->number, vport->minorp->domain_name,
	    vport->group_name, vport->tcp_port);


	/*
	 * Create a minor node. The minor number is
	 * (instance << VCC_INST_SHIFT) | minor_idx
	 */
	instance = ddi_get_instance(vccp->dip);

	minor = (instance << VCC_INST_SHIFT) | (minor_idx);

	(void) snprintf(name, MAXPATHLEN - 1, "%s%s", VCC_MINOR_NAME_PREFIX,
	    domain_name);

	rv = ddi_create_minor_node(vccp->dip, name, S_IFCHR, minor,
	    DDI_NT_SERIAL, 0);

	if (rv != DDI_SUCCESS) {
		vccp->minors_assigned--;
		return (MDEG_FAILURE);
	}

	mutex_enter(&vport->lock);
	vport->status = VCC_PORT_AVAIL | VCC_PORT_ADDED;
	mutex_exit(&vport->lock);


	return (MDEG_SUCCESS);
}

/* delete a port */
static int
i_vcc_delete_port(vcc_t *vccp, vcc_port_t *vport)
{

	char	name[MAXPATHLEN];
	int	rv;


	ASSERT(mutex_owned(&vport->lock));

	if ((vport->status & VCC_PORT_AVAIL) == 0) {
		D1("vcc_del_port port already deleted \n");
		return (0);
	}

	if (vport->status & VCC_PORT_OPEN) {
		/* do not block mdeg callback */
		vport->valid_pid = VCC_NO_PID_BLOCKING;
		rv = i_vcc_close_port(vport);
	}

	/* remove minor node */
	(void) snprintf(name, MAXPATHLEN-1, "%s%s", VCC_MINOR_NAME_PREFIX,
	    vport->minorp->domain_name);

	ddi_remove_minor_node(vccp->dip, name);

	/* let read and write thread know */
	cv_broadcast(&vport->read_cv);
	cv_broadcast(&vport->write_cv);
	vport->status = 0;
	return (rv);


}

/* register callback to MDEG */
static int
i_vcc_mdeg_register(vcc_t *vccp, int instance)
{
	mdeg_prop_spec_t	*pspecp;
	mdeg_node_spec_t	*ispecp;
	mdeg_handle_t		mdeg_hdl;
	int			sz;
	int			rv;

	/*
	 * Allocate and initialize a per-instance copy
	 * of the global property spec array that will
	 * uniquely identify this vcc instance.
	 */
	sz = sizeof (vcc_prop_template);
	pspecp = kmem_alloc(sz, KM_SLEEP);

	bcopy(vcc_prop_template, pspecp, sz);

	VCC_SET_MDEG_PROP_INST(pspecp, instance);

	/* initialize the complete prop spec structure */
	ispecp = kmem_zalloc(sizeof (mdeg_node_spec_t), KM_SLEEP);
	ispecp->namep = "virtual-device";
	ispecp->specp = pspecp;

	/* perform the registration */
	rv = mdeg_register(ispecp, &vcc_port_match, vcc_mdeg_cb,
	    vccp, &mdeg_hdl);

	if (rv != MDEG_SUCCESS) {
		cmn_err(CE_CONT, "i_vcc_mdeg_register:"
		    "mdeg_register failed (%d)\n", rv);
		kmem_free(ispecp, sizeof (mdeg_node_spec_t));
		kmem_free(pspecp, sz);
		return (DDI_FAILURE);
	}

	/* save off data that will be needed later */
	vccp->md_ispecp = (void *)ispecp;
	vccp->mdeg_hdl = mdeg_hdl;

	return (0);
}

/* destroy all mutex from port table */
static void
i_vcc_cleanup_port_table(vcc_t *vccp)
{
	int i;
	vcc_port_t *vport;

	for (i = 0; i < VCC_MAX_PORTS; i++) {
		vport = &(vccp->port[i]);
		mutex_destroy(&vport->lock);
		cv_destroy(&vport->read_cv);
		cv_destroy(&vport->write_cv);
	}
}

/*
 * attach(9E): attach a device to the system.
 * called once for each instance of the device on the system.
 */
static int
vcc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int 		i, instance, inst;
	int 		rv = DDI_FAILURE;
	vcc_t		*vccp;
	minor_t 	minor;
	vcc_port_t	*vport;

	switch (cmd) {

	case DDI_ATTACH:

		instance = ddi_get_instance(dip);
		if (ddi_soft_state_zalloc(vcc_ssp, instance) != DDI_SUCCESS)
			return (DDI_FAILURE);

		vccp = ddi_get_soft_state(vcc_ssp, instance);
		if (vccp == NULL) {
			ddi_soft_state_free(vccp, instance);
			return (ENXIO);
		}

		D1("vcc_attach: DDI_ATTACH instance=%d\n", instance);

		/* initialize the mutex */
		mutex_init(&vccp->lock, NULL, MUTEX_DRIVER, NULL);

		mutex_enter(&vccp->lock);

		vccp->dip = dip;

		for (i = 0; i < VCC_MAX_PORTS; i++) {
			vport = &(vccp->port[i]);
			mutex_init(&vport->lock, NULL, MUTEX_DRIVER, NULL);
			cv_init(&vport->read_cv, NULL, CV_DRIVER, NULL);
			cv_init(&vport->write_cv, NULL, CV_DRIVER, NULL);
			vport->valid_pid = VCC_NO_PID_BLOCKING;
		}

		vport = &vccp->port[VCC_CONTROL_PORT];
		mutex_enter(&vport->lock);

		vport->minorp = &vccp->minor_tbl[VCC_CONTROL_MINOR_IDX];
		vport->status |= VCC_PORT_AVAIL;

		/* create a minor node for vcc control */
		minor = (instance << VCC_INST_SHIFT) | VCC_CONTROL_MINOR_IDX;

		vccp->minor_tbl[VCC_CONTROL_PORT].portno =
		    VCC_CONTROL_MINOR_IDX;


		rv = ddi_create_minor_node(vccp->dip, "ctl", S_IFCHR, minor,
		    DDI_NT_SERIAL, 0);

		mutex_exit(&vport->lock);

		if (rv != DDI_SUCCESS) {
			cmn_err(CE_CONT, "vcc_attach: error"
			    "creating control minor node\n");

			i_vcc_cleanup_port_table(vccp);

			mutex_exit(&vccp->lock);
			/* clean up soft state */
			ddi_soft_state_free(vccp, instance);

			return (DDI_FAILURE);
		}

		/* get the instance number by reading 'reg' property */
		inst = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "reg", -1);
		if (inst == -1) {
			cmn_err(CE_CONT, "vcc_attach: vcc%d has no "
			    "'reg' property\n",
			    ddi_get_instance(dip));

			i_vcc_cleanup_port_table(vccp);

			/* remove minor */
			ddi_remove_minor_node(vccp->dip, NULL);

			/* clean up soft state */
			mutex_exit(&vccp->lock);
			ddi_soft_state_free(vccp, instance);

			return (DDI_FAILURE);
		}

		/*
		 * Mdeg might invoke callback in the same call sequence
		 * if there is a domain port at the time of registration.
		 * Since the callback also grabs vcc->lock mutex, to avoid
		 * mutex reentry error, release the lock before registration
		 */
		mutex_exit(&vccp->lock);

		/* register for notifications from Zeus */
		rv = i_vcc_mdeg_register(vccp, inst);
		if (rv != MDEG_SUCCESS) {
			cmn_err(CE_CONT, "vcc_attach: error register to MD\n");

			i_vcc_cleanup_port_table(vccp);

			/* remove minor */
			ddi_remove_minor_node(vccp->dip, NULL);

			/* clean up soft state */
			ddi_soft_state_free(vccp, instance);

			return (DDI_FAILURE);
		}

		return (DDI_SUCCESS);

	case DDI_RESUME:

		return (DDI_SUCCESS);

	default:

		return (DDI_FAILURE);
	}
}

/*
 * detach(9E): detach a device from the system.
 */
static int
vcc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		    i, instance;
	vcc_t		    *vccp;
	mdeg_node_spec_t    *ispecp;
	vcc_port_t	    *vport;

	switch (cmd) {

	case DDI_DETACH:

		instance = ddi_get_instance(dip);
		vccp = ddi_get_soft_state(vcc_ssp, instance);
		if (vccp == NULL)
			return (ENXIO);

		D1("vcc_detach: DDI_DETACH instance=%d\n", instance);

		mutex_enter(&vccp->lock);

		/* unregister from MD event generator */

		ASSERT(vccp->mdeg_hdl);
		(void) mdeg_unregister(vccp->mdeg_hdl);

		ispecp = (mdeg_node_spec_t *)vccp->md_ispecp;
		ASSERT(ispecp);

		kmem_free(ispecp->specp, sizeof (vcc_prop_template));
		kmem_free(ispecp, sizeof (mdeg_node_spec_t));

		/* remove minor nodes */
		ddi_remove_minor_node(vccp->dip, NULL);
		mutex_exit(&vccp->lock);

		for (i = 0; i < VCC_MAX_PORTS; i++) {

			vport = &vccp->port[i];
			mutex_enter(&vport->lock);
			if (i == VCC_CONTROL_PORT) {
				if (vport->status & VCC_PORT_OPEN) {
					(void) i_vcc_close_port(vport);
				}
			}

			if ((vccp->port[i].status & VCC_PORT_AVAIL) &&
			    (i != VCC_CONTROL_PORT)) {
				D1("vcc_detach: removing port port@%d\n", i);
				(void) i_vcc_delete_port(vccp, vport);
			}
			mutex_exit(&vport->lock);
			cv_destroy(&vport->read_cv);
			cv_destroy(&vport->write_cv);
			mutex_destroy(&vport->lock);
		}



		/* destroy mutex and free the soft state */
		mutex_destroy(&vccp->lock);
		ddi_soft_state_free(vcc_ssp, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:

		return (DDI_SUCCESS);

	default:

		return (DDI_FAILURE);
	}
}

/* cb_open */
static int
vcc_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	_NOTE(ARGUNUSED(otyp, cred))

	int	    instance;
	int	    rv = EIO;
	minor_t	    minor;
	uint_t	    portno;
	vcc_t	    *vccp;
	vcc_port_t  *vport;

	minor = getminor(*devp);
	instance = VCCINST(minor);

	vccp = ddi_get_soft_state(vcc_ssp, instance);
	if (vccp == NULL) {
		return (ENXIO);
	}

	portno = VCCPORT(vccp, minor);

	vport = &(vccp->port[portno]);

	mutex_enter(&vport->lock);

	if ((vport->status & VCC_PORT_AVAIL) == 0) {
		/* port may be removed */
		mutex_exit(&vport->lock);
		return (ENXIO);
	}

	if (vport->status & VCC_PORT_OPEN) {
		/* only one open per port */
		cmn_err(CE_CONT, "vcc_open: virtual-console-concentrator@%d:%d "
		    "is already open\n", instance, portno);
		mutex_exit(&vport->lock);
		return (EAGAIN);
	}

	/* check minor no and pid */
	if ((rv = i_vcc_can_use_port(VCCMINORP(vccp, minor),
	    vport)) != 0) {
		mutex_exit(&vport->lock);
		return (rv);
	}

	if (portno == VCC_CONTROL_PORT) {
		vport->status |= VCC_PORT_OPEN;
		mutex_exit(&vport->lock);
		return (0);
	}

	/*
	 * the port may just be added by mdeg callback and may
	 * not be configured yet.
	 */
	if (vport->ldc_id == VCC_INVALID_CHANNEL) {
		mutex_exit(&vport->lock);
		return (ENXIO);
	}


	/* check if channel has been initialized */
	if ((vport->status & VCC_PORT_LDC_CHANNEL_READY) == 0) {
		rv = i_vcc_ldc_init(vccp, vport);
		if (rv) {
			mutex_exit(&vport->lock);
			return (EIO);
		}

		/* mark port as ready */
		vport->status |= VCC_PORT_LDC_CHANNEL_READY;
	}

	vport->status |= VCC_PORT_USE_READ_LDC | VCC_PORT_USE_WRITE_LDC|
	    VCC_PORT_TERM_RD|VCC_PORT_TERM_WR|VCC_PORT_OPEN;

	if ((flag & O_NONBLOCK) || (flag & O_NDELAY)) {
		vport->status |= VCC_PORT_NONBLOCK;
	}

	mutex_exit(&vport->lock);

	return (0);
}

/* close port */
static int
i_vcc_close_port(vcc_port_t *vport)
{

	if ((vport->status & VCC_PORT_OPEN) == 0) {
		return (0);
	}

	ASSERT(mutex_owned(&vport->lock));

	if (vport->status & VCC_PORT_LDC_CHANNEL_READY) {
		/* clean up ldc channel */
		i_vcc_ldc_fini(vport);
		vport->status &= ~VCC_PORT_LDC_CHANNEL_READY;
	}

	/* reset  rd/wr suspends  */
	vport->status |= VCC_PORT_TERM_RD | VCC_PORT_TERM_WR;
	vport->status &= ~VCC_PORT_NONBLOCK;
	vport->status &= ~VCC_PORT_OPEN;
	vport->valid_pid = VCC_NO_PID_BLOCKING;

	/* signal any blocked read and write thread */
	cv_broadcast(&vport->read_cv);
	cv_broadcast(&vport->write_cv);

	return (0);
}

/* cb_close */
static int
vcc_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	_NOTE(ARGUNUSED(flag, otyp, cred))

	int	    instance;
	minor_t	    minor;
	int	    rv = EIO;
	uint_t	    portno;
	vcc_t	    *vccp;
	vcc_port_t  *vport;

	minor = getminor(dev);

	instance = VCCINST(minor);
	vccp = ddi_get_soft_state(vcc_ssp, instance);
	if (vccp == NULL) {
		return (ENXIO);
	}

	portno = VCCPORT(vccp, minor);

	D1("vcc_close: closing virtual-console-concentrator@%d:%d\n",
	    instance, portno);
	vport = &(vccp->port[portno]);


	/*
	 * needs lock to provent i_vcc_delete_port, which is called by
	 * the mdeg callback, from closing port.
	 */
	mutex_enter(&vport->lock);

	if ((vport->status & VCC_PORT_OPEN) == 0) {
		mutex_exit(&vport->lock);
		return (0);
	}

	if (portno == VCC_CONTROL_PORT) {
		/*
		 * vntsd closes control port before it exits. There
		 * could be events still pending for vntsd.
		 */
		mutex_exit(&vport->lock);
		rv = i_vcc_reset_events(vccp);
		return (0);
	}


	/* check minor no and pid */
	if ((rv = i_vcc_can_use_port(VCCMINORP(vccp, minor),
	    vport)) != 0) {
		mutex_exit(&vport->lock);
		return (rv);
	}

	rv = i_vcc_close_port(vport);
	mutex_exit(&vport->lock);

	return (rv);
}

/*
 * ioctl VCC_CONS_TBL - vntsd allocates buffer according to return of
 * VCC_NUM_PORTS. However, when vntsd requests for the console table, console
 * ports could be deleted or added. parameter num_ports is number of structures
 * that vntsd allocated for the table. If there are more ports than
 * num_ports, set up to wakeup vntsd to add ports.
 * If there less ports than num_ports, fill (-1) for cons_no to tell vntsd.
 */
static int
i_vcc_cons_tbl(vcc_t *vccp, uint_t num_ports, caddr_t buf, int mode)
{
	vcc_console_t	cons;
	int		i;
	vcc_port_t	*vport;
	boolean_t	notify_vntsd = B_FALSE;
	char pathname[MAXPATHLEN];


	(void) ddi_pathname(vccp->dip, pathname);
	for (i = 0; i < VCC_MAX_PORTS; i++) {

		vport = &vccp->port[i];

		if (i == VCC_CONTROL_PORT) {
			continue;
		}

		if ((vport->status & VCC_PORT_AVAIL) == 0) {
			continue;
		}

		/* a port exists before vntsd becomes online */
		mutex_enter(&vport->lock);

		if (num_ports == 0) {
			/* more ports than vntsd's buffer can hold */
			vport->status |= VCC_PORT_ADDED;
			notify_vntsd = B_TRUE;
			mutex_exit(&vport->lock);
			continue;
		}

		bzero(&cons, sizeof (vcc_console_t));

		/* construct console buffer */
		cons.cons_no = vport->number;
		cons.tcp_port = vport->tcp_port;
		(void) memcpy(cons.domain_name,
		    vport->minorp->domain_name, MAXPATHLEN);

		(void) memcpy(cons.group_name, vport->group_name,
		    MAXPATHLEN);
		vport->status &= ~VCC_PORT_ADDED;
		mutex_exit(&vport->lock);

		(void) snprintf(cons.dev_name, MAXPATHLEN-1, "%s:%s%s",
		    pathname, VCC_MINOR_NAME_PREFIX, cons.domain_name);

		/* copy out data */
		if (ddi_copyout(&cons, (void *)buf,
		    sizeof (vcc_console_t), mode)) {
			mutex_exit(&vport->lock);
			return (EFAULT);
		}
		buf += sizeof (vcc_console_t);

		num_ports--;

	}

	if (num_ports == 0) {
		/* vntsd's buffer is full */

		if (notify_vntsd) {
			/* more ports need to notify vntsd */
			vport = &vccp->port[VCC_CONTROL_PORT];
			mutex_enter(&vport->lock);
			vport->pollevent |= VCC_POLL_ADD_PORT;
			mutex_exit(&vport->lock);
		}

		return (0);
	}

	/* less ports than vntsd expected */
	bzero(&cons, sizeof (vcc_console_t));
	cons.cons_no = -1;

	while (num_ports > 0) {
		/* fill vntsd buffer with no console */
		if (ddi_copyout(&cons, (void *)buf,
		    sizeof (vcc_console_t), mode) != 0) {
			mutex_exit(&vport->lock);
			return (EFAULT);
		}
		D1("i_vcc_cons_tbl: a port is  deleted\n");
		buf += sizeof (vcc_console_t) +MAXPATHLEN;
		num_ports--;
	}

	return (0);
}


/* turn off event flag if there is no more change */
static void
i_vcc_turn_off_event(vcc_t *vccp, uint32_t port_status, uint32_t event)
{

	vcc_port_t *vport;
	int i;

	for (i = 0; i < VCC_MAX_PORTS; i++) {

		vport = &(vccp->port[i]);

		if ((vport->status & VCC_PORT_AVAIL) == 0) {
			continue;
		}


		if (vport->status & port_status) {
			/* more port changes status */
			return;
		}

	}

	/* no more changed port  */
	vport = &vccp->port[VCC_CONTROL_PORT];

	/* turn off event */
	mutex_enter(&vport->lock);
	vport->pollevent &= ~event;
	mutex_exit(&vport->lock);
}

/* ioctl VCC_CONS_INFO */
static int
i_vcc_cons_info(vcc_t *vccp, caddr_t buf, int mode)
{
	vcc_console_t	cons;
	uint_t		portno;
	vcc_port_t	*vport;
	char pathname[MAXPATHLEN];

	/* read in portno */
	if (ddi_copyin((void*)buf, &portno, sizeof (uint_t), mode)) {
		return (EFAULT);
	}

	D1("i_vcc_cons_info@%d:\n", portno);

	if ((portno >= VCC_MAX_PORTS) || (portno == VCC_CONTROL_PORT)) {
		return (EINVAL);
	}

	vport = &vccp->port[portno];

	if ((vport->status & VCC_PORT_AVAIL) == 0) {
		return (EINVAL);
	}

	mutex_enter(&vport->lock);
	vport->status &= ~VCC_PORT_ADDED;

	/* construct configruation data  */
	bzero(&cons, sizeof (vcc_console_t));

	cons.cons_no = vport->number;
	cons.tcp_port = vport->tcp_port;

	(void) memcpy(cons.domain_name, vport->minorp->domain_name, MAXPATHLEN);

	(void) memcpy(cons.group_name, vport->group_name, MAXPATHLEN);

	mutex_exit(&vport->lock);

	(void) ddi_pathname(vccp->dip, pathname),

	    /* copy device name */
	    (void) snprintf(cons.dev_name, MAXPATHLEN-1, "%s:%s%s",
	    pathname, VCC_MINOR_NAME_PREFIX, cons.domain_name);
	/* copy data */
	if (ddi_copyout(&cons, (void *)buf,
	    sizeof (vcc_console_t), mode) != 0) {
		mutex_exit(&vport->lock);
		return (EFAULT);
	}

	D1("i_vcc_cons_info@%d:domain:%s serv:%s tcp@%lld %s\n",
	    cons.cons_no, cons.domain_name,
	    cons.group_name, cons.tcp_port, cons.dev_name);

	i_vcc_turn_off_event(vccp, VCC_PORT_ADDED, VCC_POLL_ADD_PORT);

	return (0);
}


/* response to vntsd inquiry ioctl call */
static int
i_vcc_inquiry(vcc_t *vccp, caddr_t buf, int mode)
{
	vcc_port_t	*vport;
	uint_t		i;
	vcc_response_t	msg;

	vport = &(vccp->port[VCC_CONTROL_PORT]);

	if ((vport->pollevent & VCC_POLL_ADD_PORT) == 0) {
		return (EINVAL);
	}

	/* an added port */

	D1("i_vcc_inquiry\n");

	for (i = 0; i < VCC_MAX_PORTS; i++) {
		if ((vccp->port[i].status & VCC_PORT_AVAIL) == 0) {
			continue;
		}

		if (vccp->port[i].status & VCC_PORT_ADDED) {
			/* port added */
			msg.reason = VCC_CONS_ADDED;
			msg.cons_no = i;

			if (ddi_copyout((void *)&msg, (void *)buf,
			    sizeof (msg), mode) == -1) {
				cmn_err(CE_CONT, "i_vcc_find_changed_port:"
				    "ddi_copyout"
				    " failed\n");
				return (EFAULT);
			}
			return (0);
		}
	}

	/* the added port was deleted before vntsd wakes up */
	msg.reason = VCC_CONS_MISS_ADDED;

	if (ddi_copyout((void *)&msg, (void *)buf,
	    sizeof (msg), mode) == -1) {
		cmn_err(CE_CONT, "i_vcc_find_changed_port: ddi_copyout"
		    " failed\n");
		return (EFAULT);
	}

	return (0);
}

/* clean up events after vntsd exits */
static int
i_vcc_reset_events(vcc_t *vccp)
{
	uint_t	    i;
	vcc_port_t  *vport;

	for (i = 0; i < VCC_MAX_PORTS; i++) {
		vport = &(vccp->port[i]);

		if ((vport->status & VCC_PORT_AVAIL) == 0) {
			continue;
		}

		ASSERT(!mutex_owned(&vport->lock));

		if (i == VCC_CONTROL_PORT) {
			/* close control port */
			mutex_enter(&vport->lock);
			vport->status &= ~VCC_PORT_OPEN;

			/* clean up poll events */
			vport->pollevent = 0;
			vport->pollflag = 0;
			mutex_exit(&vport->lock);
			continue;
		}
		if (vport->status & VCC_PORT_ADDED) {
			/* pending added port event to vntsd */
			mutex_enter(&vport->lock);
			vport->status &= ~VCC_PORT_ADDED;
			mutex_exit(&vport->lock);
		}

	}

	vport = &vccp->port[VCC_CONTROL_PORT];

	return (0);
}

/* ioctl VCC_FORCE_CLOSE */
static int
i_vcc_force_close(vcc_t *vccp, caddr_t buf, int mode)
{
	uint_t		portno;
	vcc_port_t	*vport;
	int		rv;

	/* read in portno */
	if (ddi_copyin((void*)buf, &portno, sizeof (uint_t), mode)) {
		return (EFAULT);
	}

	D1("i_vcc_force_close@%d:\n", portno);

	if ((portno >= VCC_MAX_PORTS) || (portno == VCC_CONTROL_PORT)) {
		return (EINVAL);
	}

	vport = &vccp->port[portno];

	if ((vport->status & VCC_PORT_AVAIL) == 0) {
		return (EINVAL);
	}

	mutex_enter(&vport->lock);

	rv = i_vcc_close_port(vport);

	/* block callers other than vntsd */
	vport->valid_pid = ddi_get_pid();

	mutex_exit(&vport->lock);
	return (rv);

}

/* ioctl VCC_CONS_STATUS */
static int
i_vcc_cons_status(vcc_t *vccp, caddr_t buf, int mode)
{
	vcc_console_t	console;
	vcc_port_t	*vport;

	/* read in portno */
	if (ddi_copyin((void*)buf, &console, sizeof (console), mode)) {
		return (EFAULT);
	}

	D1("i_vcc_cons_status@%d:\n", console.cons_no);

	if ((console.cons_no >= VCC_MAX_PORTS) ||
	    (console.cons_no == VCC_CONTROL_PORT)) {
		return (EINVAL);
	}


	vport = &vccp->port[console.cons_no];
	if ((vport->status & VCC_PORT_AVAIL) == 0) {
		console.cons_no = -1;
	} else  if (strncmp(console.domain_name, vport->minorp->domain_name,
	    MAXPATHLEN)) {
		console.cons_no = -1;
	} else if (strncmp(console.group_name, vport->group_name,
	    MAXPATHLEN)) {
		console.cons_no = -1;
	} else if (console.tcp_port != vport->tcp_port) {
		console.cons_no = -1;
	} else if (vport->ldc_id == VCC_INVALID_CHANNEL) {
		console.cons_no = -1;
	}

	D1("i_vcc_cons_status@%d: %s %s %llx\n", console.cons_no,
	    console.group_name, console.domain_name, console.tcp_port);
	if (ddi_copyout(&console, (void *)buf, sizeof (console), mode) == -1) {
		cmn_err(CE_CONT, "i_vcc_cons_status ddi_copyout failed\n");
		return (EFAULT);
	}

	return (0);
}

/* cb_ioctl handler for vcc control port */
static int
i_vcc_ctrl_ioctl(vcc_t *vccp, int cmd, void* arg, int mode)
{

	static uint_t	num_ports;


	switch (cmd) {

	case VCC_NUM_CONSOLE:

		mutex_enter(&vccp->lock);
		num_ports = vccp->num_ports;
		mutex_exit(&vccp->lock);
		/* number of consoles */

		return (ddi_copyout((void *)&num_ports, arg,
		    sizeof (int), mode));
	case VCC_CONS_TBL:

		/* console config table */
		return (i_vcc_cons_tbl(vccp, num_ports, (caddr_t)arg, mode));

	case VCC_INQUIRY:

		/* reason for wakeup */
		return (i_vcc_inquiry(vccp, (caddr_t)arg, mode));

	case VCC_CONS_INFO:
		/* a console config */
		return (i_vcc_cons_info(vccp, (caddr_t)arg, mode));

	case VCC_FORCE_CLOSE:
		/* force to close a console */
		return (i_vcc_force_close(vccp, (caddr_t)arg, mode));

	case VCC_CONS_STATUS:
		/* console status */
		return (i_vcc_cons_status(vccp, (caddr_t)arg, mode));

	default:

		/* unknown command */
		return (ENODEV);
	}


}

/* write data to ldc. may block if channel has no space for write */
static int
i_vcc_write_ldc(vcc_port_t *vport, vcc_msg_t *buf)
{
	int	rv = EIO;
	size_t	size;

	ASSERT(mutex_owned(&vport->lock));
	ASSERT((vport->status & VCC_PORT_USE_WRITE_LDC) == 0);

	for (; ; ) {

		size = VCC_HDR_SZ + buf->size;
		rv = ldc_write(vport->ldc_handle, (caddr_t)buf, &size);

		D1("i_vcc_write_ldc: port@%d: err=%d %d bytes\n",
		    vport->number, rv, size);

		if (rv == 0) {
			return (rv);
		}

		if (rv != EWOULDBLOCK) {
			return (EIO);
		}

		if (vport->status & VCC_PORT_NONBLOCK) {
			return (EAGAIN);
		}

		/*  block util ldc has more space */

		rv = i_vcc_wait_port_status(vport, &vport->write_cv,
		    VCC_PORT_LDC_WRITE_READY);

		if (rv) {
			return (rv);
		}

		vport->status &= ~VCC_PORT_LDC_WRITE_READY;

	}

}



/* cb_ioctl handler for port ioctl */
static int
i_vcc_port_ioctl(vcc_t *vccp, minor_t minor, int portno, int cmd, void *arg,
    int mode)
{

	vcc_port_t	*vport;
	struct termios	term;
	vcc_msg_t	buf;
	int		rv;

	D1("i_vcc_port_ioctl@%d cmd %d\n", portno, cmd);

	vport = &(vccp->port[portno]);

	if ((vport->status & VCC_PORT_AVAIL) == 0) {
		return (EIO);
	}


	switch (cmd) {

	/* terminal support */
	case TCGETA:
	case TCGETS:

		mutex_enter(&vport->lock);

		/* check minor no and pid */
		if ((rv = i_vcc_can_use_port(VCCMINORP(vccp, minor),
		    vport)) != 0) {
			mutex_exit(&vport->lock);
			return (rv);
		}

		(void) memcpy(&term, &vport->term, sizeof (term));
		mutex_exit(&vport->lock);

		return (ddi_copyout(&term, arg, sizeof (term), mode));

	case TCSETS:
	case TCSETA:
	case TCSETAW:
	case TCSETAF:

		if (ddi_copyin(arg, &term, sizeof (term), mode) != 0) {
			return (EFAULT);
		}

		mutex_enter(&vport->lock);

		/* check minor no and pid */
		if ((rv = i_vcc_can_use_port(VCCMINORP(vccp, minor),
		    vport)) != 0) {
			mutex_exit(&vport->lock);
			return (rv);
		}

		(void) memcpy(&vport->term, &term, sizeof (term));
		mutex_exit(&vport->lock);
		return (0);


	case TCSBRK:

		/* send break to console */
		mutex_enter(&vport->lock);

		/* check minor no and pid */
		if ((rv = i_vcc_can_use_port(VCCMINORP(vccp, minor),
		    vport)) != 0) {
			mutex_exit(&vport->lock);
			return (rv);
		}

		/* wait for write available */
		rv = i_vcc_wait_port_status(vport, &vport->write_cv,
		    VCC_PORT_LDC_CHANNEL_READY| VCC_PORT_USE_WRITE_LDC);
		if (rv) {
			mutex_exit(&vport->lock);
			return (rv);
		}

		vport->status &= ~VCC_PORT_USE_WRITE_LDC;

		buf.type = LDC_CONSOLE_CTRL;
		buf.ctrl_msg = LDC_CONSOLE_BREAK;
		buf.size = 0;

		rv = i_vcc_write_ldc(vport, &buf);

		mutex_exit(&vport->lock);

		i_vcc_set_port_status(vport, &vport->write_cv,
		    VCC_PORT_USE_WRITE_LDC);
		return (0);

	case TCXONC:
		/* suspend read or write */
		if (ddi_copyin(arg, &cmd, sizeof (int), mode) != 0) {
			return (EFAULT);
		}

		mutex_enter(&vport->lock);

		/* check minor no and pid */
		if ((rv = i_vcc_can_use_port(VCCMINORP(vccp, minor),
		    vport)) != 0) {
			mutex_exit(&vport->lock);
			return (rv);
		}


		switch (cmd) {

		case 0:
			/* suspend read */
			vport->status &= ~VCC_PORT_TERM_RD;
			break;

		case 1:
			/* resume read */
			vport->status |= VCC_PORT_TERM_RD;
			cv_broadcast(&vport->read_cv);
			break;

		case 2:
			/* suspend write */
			vport->status &= ~VCC_PORT_TERM_WR;
			break;

		case 3:
			/* resume write */
			vport->status |= VCC_PORT_TERM_WR;
			cv_broadcast(&vport->write_cv);
			break;

		default:
			mutex_exit(&vport->lock);
			return (EINVAL);
		}

		mutex_exit(&vport->lock);
		return (0);

	case TCFLSH:
		return (0);

	default:
		return (EINVAL);
	}

}

/* cb_ioctl */
static int
vcc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	int instance;
	minor_t minor;
	int portno;
	vcc_t *vccp;

	minor = getminor(dev);

	instance = VCCINST(minor);

	vccp = ddi_get_soft_state(vcc_ssp, instance);
	if (vccp == NULL) {
		return (ENXIO);
	}

	portno = VCCPORT(vccp, minor);

	D1("vcc_ioctl: virtual-console-concentrator@%d:%d\n", instance, portno);

	if (portno >= VCC_MAX_PORTS) {
		cmn_err(CE_CONT, "vcc_ioctl:virtual-console-concentrator@%d"
		    " invalid portno\n", portno);
		return (EINVAL);
	}

	D1("vcc_ioctl: virtual-console-concentrator@%d:%d ioctl cmd=%d\n",
	    instance, portno, cmd);

	if (portno == VCC_CONTROL_PORT) {
		/* control ioctl */
		return (i_vcc_ctrl_ioctl(vccp, cmd, (void *)arg, mode));
	}

	/* data port ioctl */
	return (i_vcc_port_ioctl(vccp, minor, portno, cmd, (void *)arg, mode));
}

/* cb_read */
static int
vcc_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	int	    instance;
	minor_t	    minor;
	uint_t	    portno;
	vcc_t	    *vccp;
	vcc_port_t  *vport;
	int	    rv = EIO;	/* by default fail ! */
	char 		*buf;
	size_t		uio_size;
	size_t		size;

	minor = getminor(dev);

	instance = VCCINST(minor);

	vccp = ddi_get_soft_state(vcc_ssp, instance);
	if (vccp == NULL) {
		return (ENXIO);
	}

	portno = VCCPORT(vccp, minor);

	/* no read for control port */
	if (portno == VCC_CONTROL_PORT) {
		return (EIO);
	}

	/* temp buf to hold ldc data */
	uio_size = uiop->uio_resid;

	if (uio_size < VCC_MTU_SZ) {
		return (EINVAL);
	}

	vport = &(vccp->port[portno]);

	mutex_enter(&vport->lock);

	/* check minor no and pid */
	if ((rv = i_vcc_can_use_port(VCCMINORP(vccp, minor),
	    vport)) != 0) {
		mutex_exit(&vport->lock);
		return (rv);
	}

	rv = i_vcc_wait_port_status(vport, &vport->read_cv,
	    VCC_PORT_TERM_RD|VCC_PORT_LDC_CHANNEL_READY|
	    VCC_PORT_USE_READ_LDC);
	if (rv) {
		mutex_exit(&vport->lock);
		return (rv);
	}

	buf = kmem_alloc(uio_size, KM_SLEEP);

	vport->status &= ~VCC_PORT_USE_READ_LDC;

	for (; ; ) {

		size = uio_size;
		rv = i_vcc_read_ldc(vport, buf, &size);


		if (rv == EAGAIN) {
			/* should block? */
			if (vport->status & VCC_PORT_NONBLOCK) {
				break;
			}

		} else if (rv) {
			/* error */
			break;
		}

		if (size > 0) {
			/* got data */
			break;
		}

		/* wait for data from ldc */
		vport->status &= ~VCC_PORT_LDC_DATA_READY;

		mutex_exit(&vport->lock);
		i_vcc_set_port_status(vport, &vport->read_cv,
		    VCC_PORT_USE_READ_LDC);
		mutex_enter(&vport->lock);

		rv = i_vcc_wait_port_status(vport, &vport->read_cv,
		    VCC_PORT_TERM_RD|VCC_PORT_LDC_CHANNEL_READY|
		    VCC_PORT_USE_READ_LDC| VCC_PORT_LDC_DATA_READY);
		if (rv) {
			break;
		}

		vport->status &= ~VCC_PORT_USE_READ_LDC;
	}

	mutex_exit(&vport->lock);

	if ((rv == 0) && (size > 0)) {
		/* data is in buf */
		rv = uiomove(buf, size, UIO_READ, uiop);
	}

	kmem_free(buf, uio_size);
	i_vcc_set_port_status(vport, &vport->read_cv, VCC_PORT_USE_READ_LDC);

	return (rv);
}


/* cb_write */
static int
vcc_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	int	    instance;
	minor_t	    minor;
	size_t	    size;
	size_t	    bytes;
	uint_t	    portno;
	vcc_t	    *vccp;

	vcc_port_t  *vport;
	int	    rv = EIO;

	vcc_msg_t	buf;

	minor = getminor(dev);

	instance = VCCINST(minor);

	vccp = ddi_get_soft_state(vcc_ssp, instance);
	if (vccp == NULL) {
		return (ENXIO);
	}

	portno = VCCPORT(vccp, minor);

	/* no write for control port */
	if (portno == VCC_CONTROL_PORT) {
		return (EIO);
	}
	vport = &(vccp->port[portno]);

	/*
	 * check if the channel has been configured,
	 * if write has been suspend and grab write lock.
	 */
	mutex_enter(&vport->lock);

	/* check minor no and pid */
	if ((rv = i_vcc_can_use_port(VCCMINORP(vccp, minor),
	    vport)) != 0) {
		mutex_exit(&vport->lock);
		return (rv);
	}

	rv = i_vcc_wait_port_status(vport, &vport->write_cv,
	    VCC_PORT_TERM_WR|VCC_PORT_LDC_CHANNEL_READY|
	    VCC_PORT_USE_WRITE_LDC);
	if (rv) {
		mutex_exit(&vport->lock);
		return (rv);
	}

	vport->status &= ~VCC_PORT_USE_WRITE_LDC;
	mutex_exit(&vport->lock);
	size = uiop->uio_resid;

	D2("vcc_write: virtual-console-concentrator@%d:%d writing %d bytes\n",
	    instance, portno, size);



	buf.type = LDC_CONSOLE_DATA;

	while (size) {

		bytes = MIN(size, VCC_MTU_SZ);
		/* move data */
		rv = uiomove(&(buf.data), bytes, UIO_WRITE, uiop);

		if (rv) {
			break;
		}

		/* write to ldc */
		buf.size = bytes;

		mutex_enter(&vport->lock);

		/* check minor no and pid */
		if ((rv = i_vcc_can_use_port(VCCMINORP(vccp, minor),
		    vport)) != 0) {
			mutex_exit(&vport->lock);
			return (rv);
		}

		rv = i_vcc_write_ldc(vport, &buf);

		mutex_exit(&vport->lock);

		if (rv) {
			break;
		}

		size -= bytes;

	}

	i_vcc_set_port_status(vport, &vport->write_cv, VCC_PORT_USE_WRITE_LDC);
	return (rv);
}

/* mdeg callback for a removed port */
static int
i_vcc_md_remove_port(md_t *mdp, mde_cookie_t mdep, vcc_t *vccp)
{
	uint64_t  portno;	/* md requires 64bit for port number */
	int rv = MDEG_FAILURE;
	vcc_port_t *vport;

	if (md_get_prop_val(mdp, mdep, "id", &portno)) {
		cmn_err(CE_CONT, "vcc_mdeg_cb: port has no 'id' property\n");
		return (MDEG_FAILURE);
	}

	if ((portno >= VCC_MAX_PORTS) || (portno < 0)) {
		cmn_err(CE_CONT, "i_vcc_md_remove_port@%ld invalid port no\n",
		    portno);
		return (MDEG_FAILURE);
	}

	if (portno == VCC_CONTROL_PORT) {
		cmn_err(CE_CONT, "i_vcc_md_remove_port@%ld can not remove"
		    "control port\n",
		    portno);
		return (MDEG_FAILURE);
	}

	vport = &(vccp->port[portno]);

	/* delete the port */
	mutex_enter(&vport->lock);
	rv = i_vcc_delete_port(vccp, vport);
	mutex_exit(&vport->lock);

	mutex_enter(&vccp->lock);
	vccp->num_ports--;
	mutex_exit(&vccp->lock);

	return (rv ? MDEG_FAILURE : MDEG_SUCCESS);
}

static int
i_vcc_get_ldc_id(md_t *md, mde_cookie_t mdep, uint64_t *ldc_id)
{
	int		num_nodes;
	size_t		size;
	mde_cookie_t	*channel;
	int		num_channels;


	if ((num_nodes = md_node_count(md)) <= 0) {
		cmn_err(CE_CONT, "i_vcc_get_ldc_channel_id:"
		    "  Invalid node count in Machine Description subtree");
		return (-1);
	}
	size = num_nodes*(sizeof (*channel));
	channel = kmem_zalloc(size, KM_SLEEP);
	ASSERT(channel != NULL);	/* because KM_SLEEP */


	/* Look for channel endpoint child(ren) of the vdisk MD node */
	if ((num_channels = md_scan_dag(md, mdep,
	    md_find_name(md, "channel-endpoint"),
	    md_find_name(md, "fwd"), channel)) <= 0) {
		cmn_err(CE_CONT, "i_vcc_get_ldc_id:  No 'channel-endpoint'"
		    " found for vcc");
		kmem_free(channel, size);
		return (-1);
	}

	/* Get the "id" value for the first channel endpoint node */
	if (md_get_prop_val(md, channel[0], "id", ldc_id) != 0) {
		cmn_err(CE_CONT, "i_vcc_get_ldc:  No id property found "
		    "for channel-endpoint of vcc");
		kmem_free(channel, size);
		return (-1);
	}

	if (num_channels > 1) {
		cmn_err(CE_CONT, "i_vcc_get_ldc:  Warning:  Using ID of first"
		    " of multiple channels for this vcc");
	}

	kmem_free(channel, size);
	return (0);
}
/* mdeg callback for an added port  */
static int
i_vcc_md_add_port(md_t *mdp, mde_cookie_t mdep, vcc_t *vccp)
{
	uint64_t	portno;		/* md requires 64 bit */
	char		*domain_name;
	char		*group_name;
	uint64_t	ldc_id;
	uint64_t	tcp_port;
	vcc_port_t	*vport;

	/* read in the port's reg property */
	if (md_get_prop_val(mdp, mdep, "id", &portno)) {
		cmn_err(CE_CONT, "i_vcc_md_add_port_: port has no 'id' "
		    "property\n");
		return (MDEG_FAILURE);
	}

	/* read in the port's "vcc-doman-name" property */
	if (md_get_prop_str(mdp, mdep, "vcc-domain-name", &domain_name)) {
		cmn_err(CE_CONT, "i_vcc_md_add_port: port%ld has "
		    "no 'vcc-domain-name' property\n", portno);
		return (MDEG_FAILURE);
	}


	/* read in the port's "vcc-group-name" property */
	if (md_get_prop_str(mdp, mdep, "vcc-group-name", &group_name)) {
		cmn_err(CE_CONT, "i_vcc_md_add_port: port%ld has no "
		    "'vcc-group-name'property\n", portno);
		return (MDEG_FAILURE);
	}


	/* read in the port's "vcc-tcp-port" property */
	if (md_get_prop_val(mdp, mdep, "vcc-tcp-port", &tcp_port)) {
		cmn_err(CE_CONT, "i_vcc_md_add_port: port%ld has no"
		    "'vcc-tcp-port' property\n", portno);
		return (MDEG_FAILURE);
	}

	D1("i_vcc_md_add_port: port@%d domain-name=%s group-name=%s"
	    " tcp-port=%lld\n", portno, domain_name, group_name, tcp_port);

	/* add the port */
	if (i_vcc_add_port(vccp, group_name, tcp_port, portno, domain_name)) {
		return (MDEG_FAILURE);
	}

	vport = &vccp->port[portno];
	if (i_vcc_get_ldc_id(mdp, mdep, &ldc_id)) {
		mutex_enter(&vport->lock);
		(void) i_vcc_delete_port(vccp, vport);
		mutex_exit(&vport->lock);
		return (MDEG_FAILURE);
	}

	/* configure the port */
	if (i_vcc_config_port(vccp, portno, ldc_id)) {
		mutex_enter(&vport->lock);
		(void) i_vcc_delete_port(vccp, vport);
		mutex_exit(&vport->lock);
		return (MDEG_FAILURE);
	}

	mutex_enter(&vccp->lock);
	vccp->num_ports++;
	mutex_exit(&vccp->lock);

	vport = &vccp->port[VCC_CONTROL_PORT];

	if (vport->pollflag & VCC_POLL_CONFIG) {
		/* wakeup vntsd */
		mutex_enter(&vport->lock);
		vport->pollevent |= VCC_POLL_ADD_PORT;
		mutex_exit(&vport->lock);
		pollwakeup(&vport->poll, POLLIN);
	}

	return (MDEG_SUCCESS);
}

/* mdeg callback */
static int
vcc_mdeg_cb(void *cb_argp, mdeg_result_t *resp)
{
	int	idx;
	vcc_t 	*vccp;
	int	rv;

	vccp = (vcc_t *)cb_argp;
	ASSERT(vccp);

	if (resp == NULL) {
		return (MDEG_FAILURE);
	}

	/* added port */
	D1("vcc_mdeg_cb: added %d port(s)\n", resp->added.nelem);

	for (idx = 0; idx < resp->added.nelem; idx++) {
		rv = i_vcc_md_add_port(resp->added.mdp,
		    resp->added.mdep[idx], vccp);

		if (rv !=  MDEG_SUCCESS) {
			return (rv);
		}
	}

	/* removed port */
	D1("vcc_mdeg_cb: removed %d port(s)\n", resp->removed.nelem);

	for (idx = 0; idx < resp->removed.nelem; idx++) {
		rv = i_vcc_md_remove_port(resp->removed.mdp,
		    resp->removed.mdep[idx], vccp);

		if (rv !=  MDEG_SUCCESS) {
			return (rv);
		}

	}

	/*
	 * XXX - Currently no support for updating already active
	 * ports. So, ignore the match_curr and match_prev arrays
	 * for now.
	 */

	return (MDEG_SUCCESS);
}


/* cb_chpoll */
static int
vcc_chpoll(dev_t dev, short events, int anyyet,  short *reventsp,
    struct pollhead **phpp)
{
	int	    instance;
	minor_t	    minor;
	uint_t	    portno;
	vcc_t	    *vccp;
	vcc_port_t  *vport;

	minor = getminor(dev);

	instance = VCCINST(minor);

	vccp = ddi_get_soft_state(vcc_ssp, instance);
	if (vccp == NULL) {
		return (ENXIO);
	}

	portno = VCCPORT(vccp, minor);

	vport = &(vccp->port[portno]);

	D1("vcc_chpoll: virtual-console-concentrator@%d events 0x%x\n",
	    portno, events);

	*reventsp = 0;

	if (portno != VCC_CONTROL_PORT) {
		return (ENXIO);
	}

	/* poll for config change */
	if (vport->pollevent) {
		*reventsp |= (events & POLLIN);
	}

	if ((((*reventsp) == 0) && (!anyyet)) || (events & POLLET)) {
		*phpp = &vport->poll;
		if (events & POLLIN) {
			mutex_enter(&vport->lock);
			vport->pollflag |= VCC_POLL_CONFIG;
			mutex_exit(&vport->lock);
		} else {
			return (ENXIO);
		}
	}

	D1("vcc_chpoll: virtual-console-concentrator@%d:%d ev=0x%x, "
	    "rev=0x%x pev=0x%x, flag=0x%x\n",
	    instance, portno, events, (*reventsp),
	    vport->pollevent, vport->pollflag);


	return (0);
}
