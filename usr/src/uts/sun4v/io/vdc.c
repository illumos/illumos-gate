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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * LDoms virtual disk client (vdc) device driver
 *
 * This driver runs on a guest logical domain and communicates with the virtual
 * disk server (vds) driver running on the service domain which is exporting
 * virtualized "disks" to the guest logical domain.
 *
 * The driver can be divided into four sections:
 *
 * 1) generic device driver housekeeping
 *	_init, _fini, attach, detach, ops structures, etc.
 *
 * 2) communication channel setup
 *	Setup the communications link over the LDC channel that vdc uses to
 *	talk to the vDisk server. Initialise the descriptor ring which
 *	allows the LDC clients to transfer data via memory mappings.
 *
 * 3) Support exported to upper layers (filesystems, etc)
 *	The upper layers call into vdc via strategy(9E) and DKIO(7I)
 *	ioctl calls. vdc will copy the data to be written to the descriptor
 *	ring or maps the buffer to store the data read by the vDisk
 *	server into the descriptor ring. It then sends a message to the
 *	vDisk server requesting it to complete the operation.
 *
 * 4) Handling responses from vDisk server.
 *	The vDisk server will ACK some or all of the messages vdc sends to it
 *	(this is configured during the handshake). Upon receipt of an ACK
 *	vdc will check the descriptor ring and signal to the upper layer
 *	code waiting on the IO.
 */

#include <sys/conf.h>
#include <sys/disp.h>
#include <sys/ddi.h>
#include <sys/dkio.h>
#include <sys/efi_partition.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/mach_descrip.h>
#include <sys/modctl.h>
#include <sys/mdeg.h>
#include <sys/note.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/promif.h>
#include <sys/vtoc.h>
#include <sys/archsystm.h>
#include <sys/sysmacros.h>

#include <sys/cdio.h>
#include <sys/dktp/cm.h>
#include <sys/dktp/fdisk.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/impl/uscsi.h>	/* Needed for defn of USCSICMD ioctl */
#include <sys/scsi/targets/sddef.h>

#include <sys/ldoms.h>
#include <sys/ldc.h>
#include <sys/vio_common.h>
#include <sys/vio_mailbox.h>
#include <sys/vdsk_common.h>
#include <sys/vdsk_mailbox.h>
#include <sys/vdc.h>

/*
 * function prototypes
 */

/* standard driver functions */
static int	vdc_open(dev_t *dev, int flag, int otyp, cred_t *cred);
static int	vdc_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int	vdc_strategy(struct buf *buf);
static int	vdc_print(dev_t dev, char *str);
static int	vdc_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk);
static int	vdc_read(dev_t dev, struct uio *uio, cred_t *cred);
static int	vdc_write(dev_t dev, struct uio *uio, cred_t *cred);
static int	vdc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
			cred_t *credp, int *rvalp);
static int	vdc_aread(dev_t dev, struct aio_req *aio, cred_t *cred);
static int	vdc_awrite(dev_t dev, struct aio_req *aio, cred_t *cred);

static int	vdc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
			void *arg, void **resultp);
static int	vdc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	vdc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/* setup */
static int	vdc_send(ldc_handle_t ldc_handle, caddr_t pkt, size_t *msglen);
static int	vdc_do_ldc_init(vdc_t *vdc);
static int	vdc_start_ldc_connection(vdc_t *vdc);
static int	vdc_create_device_nodes(vdc_t *vdc);
static int	vdc_create_device_nodes_props(vdc_t *vdc);
static int	vdc_get_ldc_id(dev_info_t *dip, uint64_t *ldc_id);
static void	vdc_terminate_ldc(vdc_t *vdc);
static int	vdc_init_descriptor_ring(vdc_t *vdc);
static void	vdc_destroy_descriptor_ring(vdc_t *vdc);

/* handshake with vds */
static void		vdc_init_handshake_negotiation(void *arg);
static int		vdc_init_ver_negotiation(vdc_t *vdc);
static int		vdc_init_attr_negotiation(vdc_t *vdc);
static int		vdc_init_dring_negotiate(vdc_t *vdc);
static int		vdc_handle_ver_negotiate();
static int		vdc_handle_attr_negotiate();
static void		vdc_reset_connection(vdc_t *vdc, boolean_t resetldc);
static boolean_t	vdc_is_able_to_tx_data(vdc_t *vdc, int flag);

/* processing */
static void	vdc_process_msg_thread(vdc_t *vdc);
static uint_t	vdc_handle_cb(uint64_t event, caddr_t arg);
static void	vdc_process_msg(void *arg);
static int	vdc_process_ctrl_msg(vdc_t *vdc, vio_msg_t msg);
static int	vdc_process_data_msg(vdc_t *vdc, vio_msg_t msg);
static int	vdc_process_err_msg(vdc_t *vdc, vio_msg_t msg);
static void	vdc_do_process_msg(vdc_t *vdc);
static int	vdc_get_next_dring_entry_id(vdc_t *vdc, uint_t needed);
static int	vdc_populate_descriptor(vdc_t *vdc, caddr_t addr,
			size_t nbytes, int op, uint64_t arg, uint64_t slice);
static int	vdc_wait_for_descriptor_update(vdc_t *vdc, uint_t idx,
			vio_dring_msg_t dmsg);
static int	vdc_depopulate_descriptor(vdc_t *vdc, uint_t idx);
static int	vdc_get_response(vdc_t *vdc, int start, int end);
static int	vdc_populate_mem_hdl(vdc_t *vdc, uint_t idx,
			caddr_t addr, size_t nbytes, int operation);
static boolean_t vdc_verify_seq_num(vdc_t *vdc, vio_dring_msg_t *dring_msg, int
			num_msgs);

/* dkio */
static int	vd_process_ioctl(dev_t dev, int cmd, caddr_t arg, int mode);
static int	vdc_create_fake_geometry(vdc_t *vdc);

/*
 * Module variables
 */
uint64_t	vdc_hz_timeout;
uint64_t	vdc_usec_timeout = VDC_USEC_TIMEOUT_MIN;
uint64_t	vdc_dump_usec_timeout = VDC_USEC_TIMEOUT_MIN / 300;
static int	vdc_retries = VDC_RETRIES;
static int	vdc_dump_retries = VDC_RETRIES * 10;

/* Soft state pointer */
static void	*vdc_state;

/* variable level controlling the verbosity of the error/debug messages */
int	vdc_msglevel = 0;


static void
vdc_msg(const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	vcmn_err(CE_CONT, format, args);
	va_end(args);
}

static struct cb_ops vdc_cb_ops = {
	vdc_open,	/* cb_open */
	vdc_close,	/* cb_close */
	vdc_strategy,	/* cb_strategy */
	vdc_print,	/* cb_print */
	vdc_dump,	/* cb_dump */
	vdc_read,	/* cb_read */
	vdc_write,	/* cb_write */
	vdc_ioctl,	/* cb_ioctl */
	nodev,		/* cb_devmap */
	nodev,		/* cb_mmap */
	nodev,		/* cb_segmap */
	nochpoll,	/* cb_chpoll */
	ddi_prop_op,	/* cb_prop_op */
	NULL,		/* cb_str */
	D_MP | D_64BIT,	/* cb_flag */
	CB_REV,		/* cb_rev */
	vdc_aread,	/* cb_aread */
	vdc_awrite	/* cb_awrite */
};

static struct dev_ops vdc_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	vdc_getinfo,	/* devo_getinfo */
	nulldev,	/* devo_identify */
	nulldev,	/* devo_probe */
	vdc_attach,	/* devo_attach */
	vdc_detach,	/* devo_detach */
	nodev,		/* devo_reset */
	&vdc_cb_ops,	/* devo_cb_ops */
	NULL,		/* devo_bus_ops */
	nulldev		/* devo_power */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"virtual disk client %I%",
	&vdc_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/* -------------------------------------------------------------------------- */

/*
 * Device Driver housekeeping and setup
 */

int
_init(void)
{
	int	status;

	if ((status = ddi_soft_state_init(&vdc_state, sizeof (vdc_t), 1)) != 0)
		return (status);
	if ((status = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&vdc_state);
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	status;

	if ((status = mod_remove(&modlinkage)) != 0)
		return (status);
	ddi_soft_state_fini(&vdc_state);
	return (0);
}

static int
vdc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,  void *arg, void **resultp)
{
	_NOTE(ARGUNUSED(dip))

	int	instance = SDUNIT(getminor((dev_t)arg));
	vdc_t	*vdc = NULL;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
			*resultp = NULL;
			return (DDI_FAILURE);
		}
		*resultp = vdc->dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	default:
		*resultp = NULL;
		return (DDI_FAILURE);
	}
}

static int
vdc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	instance;
	int	rv;
	uint_t	retries = 0;
	vdc_t	*vdc = NULL;

	switch (cmd) {
	case DDI_DETACH:
		/* the real work happens below */
		break;
	case DDI_SUSPEND:
		/* nothing to do for this non-device */
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ASSERT(cmd == DDI_DETACH);
	instance = ddi_get_instance(dip);
	PR1("%s[%d] Entered\n", __func__, instance);

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		vdc_msg("%s[%d]:  Could not get state structure.",
		    __func__, instance);
		return (DDI_FAILURE);
	}

	if (vdc->open) {
		PR0("%s[%d]: Cannot detach: device is open",
				__func__, instance);
		return (DDI_FAILURE);
	}

	PR0("%s[%d] proceeding...\n", __func__, instance);

	/*
	 * try and disable callbacks to prevent another handshake
	 */
	rv = ldc_set_cb_mode(vdc->ldc_handle, LDC_CB_DISABLE);
	PR0("%s[%d] callback disabled (rv=%d)\n", __func__, instance, rv);

	/*
	 * Prevent any more attempts to start a handshake with the vdisk
	 * server and tear down the existing connection.
	 */
	mutex_enter(&vdc->lock);
	vdc->initialized |= VDC_HANDSHAKE_STOP;
	vdc_reset_connection(vdc, B_TRUE);
	mutex_exit(&vdc->lock);

	if (vdc->initialized & VDC_THREAD) {
		mutex_enter(&vdc->msg_proc_lock);
		vdc->msg_proc_thr_state = VDC_THR_STOP;
		vdc->msg_pending = B_TRUE;
		cv_signal(&vdc->msg_proc_cv);

		while (vdc->msg_proc_thr_state != VDC_THR_DONE) {
			PR0("%s[%d]: Waiting for thread to exit\n",
				__func__, instance);
			rv = cv_timedwait(&vdc->msg_proc_cv,
				&vdc->msg_proc_lock, VD_GET_TIMEOUT_HZ(1));
			if ((rv == -1) && (retries++ > vdc_retries))
				break;
		}
		mutex_exit(&vdc->msg_proc_lock);
	}

	mutex_enter(&vdc->lock);

	if (vdc->initialized & VDC_DRING)
		vdc_destroy_descriptor_ring(vdc);

	if (vdc->initialized & VDC_LDC)
		vdc_terminate_ldc(vdc);

	mutex_exit(&vdc->lock);

	if (vdc->initialized & VDC_MINOR) {
		ddi_prop_remove_all(dip);
		ddi_remove_minor_node(dip, NULL);
	}

	if (vdc->initialized & VDC_LOCKS) {
		mutex_destroy(&vdc->lock);
		mutex_destroy(&vdc->attach_lock);
		mutex_destroy(&vdc->msg_proc_lock);
		mutex_destroy(&vdc->dring_lock);
		cv_destroy(&vdc->cv);
		cv_destroy(&vdc->attach_cv);
		cv_destroy(&vdc->msg_proc_cv);
	}

	if (vdc->minfo)
		kmem_free(vdc->minfo, sizeof (struct dk_minfo));

	if (vdc->cinfo)
		kmem_free(vdc->cinfo, sizeof (struct dk_cinfo));

	if (vdc->vtoc)
		kmem_free(vdc->vtoc, sizeof (struct vtoc));

	if (vdc->initialized & VDC_SOFT_STATE)
		ddi_soft_state_free(vdc_state, instance);

	PR0("%s[%d] End %p\n", __func__, instance, vdc);

	return (DDI_SUCCESS);
}


static int
vdc_do_attach(dev_info_t *dip)
{
	int		instance;
	vdc_t		*vdc = NULL;
	int		status;
	uint_t		retries = 0;

	ASSERT(dip != NULL);

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(vdc_state, instance) != DDI_SUCCESS) {
		vdc_msg("%s:(%d): Couldn't alloc state structure",
		    __func__, instance);
		return (DDI_FAILURE);
	}

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		vdc_msg("%s:(%d): Could not get state structure.",
		    __func__, instance);
		return (DDI_FAILURE);
	}

	/*
	 * We assign the value to initialized in this case to zero out the
	 * variable and then set bits in it to indicate what has been done
	 */
	vdc->initialized = VDC_SOFT_STATE;

	vdc_hz_timeout = drv_usectohz(vdc_usec_timeout);

	vdc->dip	= dip;
	vdc->instance	= instance;
	vdc->open	= 0;
	vdc->vdisk_type	= VD_DISK_TYPE_UNK;
	vdc->state	= VD_STATE_INIT;
	vdc->ldc_state	= 0;
	vdc->session_id = 0;
	vdc->block_size = DEV_BSIZE;
	vdc->max_xfer_sz = VD_MAX_BLOCK_SIZE / DEV_BSIZE;

	vdc->vtoc = NULL;
	vdc->cinfo = NULL;
	vdc->minfo = NULL;

	mutex_init(&vdc->lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&vdc->attach_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&vdc->msg_proc_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&vdc->dring_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vdc->cv, NULL, CV_DRIVER, NULL);
	cv_init(&vdc->attach_cv, NULL, CV_DRIVER, NULL);
	cv_init(&vdc->msg_proc_cv, NULL, CV_DRIVER, NULL);
	vdc->initialized |= VDC_LOCKS;

	vdc->msg_pending = B_FALSE;
	vdc->msg_proc_thr_id = thread_create(NULL, 0, vdc_process_msg_thread,
		vdc, 0, &p0, TS_RUN, minclsyspri);
	if (vdc->msg_proc_thr_id == NULL) {
		cmn_err(CE_NOTE, "[%d] Failed to create msg processing thread",
				instance);
		return (DDI_FAILURE);
	}
	vdc->initialized |= VDC_THREAD;

	/* initialise LDC channel which will be used to communicate with vds */
	if (vdc_do_ldc_init(vdc) != 0) {
		cmn_err(CE_NOTE, "[%d] Couldn't initialize LDC", instance);
		return (DDI_FAILURE);
	}

	/* Bring up connection with vds via LDC */
	status = vdc_start_ldc_connection(vdc);
	if (status != 0) {
		vdc_msg("%s[%d]  Could not start LDC", __func__, instance);
		return (DDI_FAILURE);
	}

	/*
	 * We need to wait until the handshake has completed before leaving
	 * the attach(). This is to allow the device node(s) to be created
	 * and the first usage of the filesystem to succeed.
	 */
	mutex_enter(&vdc->attach_lock);
	while ((vdc->ldc_state != LDC_UP) ||
		(vdc->state != VD_STATE_DATA)) {

		PR0("%s[%d] handshake in progress [VD %d (LDC %d)]\n",
			__func__, instance, vdc->state, vdc->ldc_state);

		status = cv_timedwait(&vdc->attach_cv, &vdc->attach_lock,
				VD_GET_TIMEOUT_HZ(1));
		if (status == -1) {
			if (retries >= vdc_retries) {
				PR0("%s[%d] Give up handshake wait.\n",
						__func__, instance);
				mutex_exit(&vdc->attach_lock);
				return (DDI_FAILURE);
			} else {
				PR0("%s[%d] Retry #%d for handshake.\n",
						__func__, instance, retries);
				retries++;
			}
		}
	}
	mutex_exit(&vdc->attach_lock);

	if (vdc->vtoc == NULL)
		vdc->vtoc = kmem_zalloc(sizeof (struct vtoc), KM_SLEEP);

	status = vdc_populate_descriptor(vdc, (caddr_t)vdc->vtoc,
			P2ROUNDUP(sizeof (struct vtoc), sizeof (uint64_t)),
			VD_OP_GET_VTOC, FKIOCTL, 0);
	if (status) {
		cmn_err(CE_NOTE, "[%d] Failed to get VTOC", instance);
		return (status);
	}

	/*
	 * Now that we have the device info we can create the
	 * device nodes and properties
	 */
	status = vdc_create_device_nodes(vdc);
	if (status) {
		cmn_err(CE_NOTE, "[%d] Failed to create device nodes",
				instance);
		return (status);
	}
	status = vdc_create_device_nodes_props(vdc);
	if (status) {
		cmn_err(CE_NOTE, "[%d] Failed to create device nodes"
				" properties", instance);
		return (status);
	}

	ddi_report_dev(dip);

	PR0("%s[%d] Attach completed\n", __func__, instance);
	return (status);
}

static int
vdc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	status;

	PR0("%s[%d]  Entered.  Built %s %s\n", __func__, ddi_get_instance(dip),
		__DATE__, __TIME__);

	switch (cmd) {
	case DDI_ATTACH:
		if ((status = vdc_do_attach(dip)) != 0)
			(void) vdc_detach(dip, DDI_DETACH);
		return (status);
	case DDI_RESUME:
		/* nothing to do for this non-device */
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
vdc_do_ldc_init(vdc_t *vdc)
{
	int			status = 0;
	ldc_status_t		ldc_state;
	ldc_attr_t		ldc_attr;
	uint64_t		ldc_id = 0;
	dev_info_t		*dip = NULL;

	ASSERT(vdc != NULL);

	dip = vdc->dip;
	vdc->initialized |= VDC_LDC;

	if ((status = vdc_get_ldc_id(dip, &ldc_id)) != 0) {
		vdc_msg("%s:  Failed to get <ldc_id> property\n", __func__);
		return (EIO);
	}
	vdc->ldc_id = ldc_id;

	ldc_attr.devclass = LDC_DEV_BLK;
	ldc_attr.instance = vdc->instance;
	ldc_attr.mode = LDC_MODE_UNRELIABLE;	/* unreliable transport */
	ldc_attr.qlen = VD_LDC_QLEN;

	if ((vdc->initialized & VDC_LDC_INIT) == 0) {
		status = ldc_init(ldc_id, &ldc_attr, &vdc->ldc_handle);
		if (status != 0) {
			cmn_err(CE_NOTE, "[%d] ldc_init(chan %ld) returned %d",
					vdc->instance, ldc_id, status);
			return (status);
		}
		vdc->initialized |= VDC_LDC_INIT;
	}
	status = ldc_status(vdc->ldc_handle, &ldc_state);
	if (status != 0) {
		vdc_msg("Cannot discover LDC status [err=%d].", status);
		return (status);
	}
	vdc->ldc_state = ldc_state;

	if ((vdc->initialized & VDC_LDC_CB) == 0) {
		status = ldc_reg_callback(vdc->ldc_handle, vdc_handle_cb,
		    (caddr_t)vdc);
		if (status != 0) {
			vdc_msg("%s: ldc_reg_callback()=%d", __func__, status);
			return (status);
		}
		vdc->initialized |= VDC_LDC_CB;
	}

	vdc->initialized |= VDC_LDC;

	/*
	 * At this stage we have initialised LDC, we will now try and open
	 * the connection.
	 */
	if (vdc->ldc_state == LDC_INIT) {
		status = ldc_open(vdc->ldc_handle);
		if (status != 0) {
			cmn_err(CE_NOTE, "[%d] ldc_open(chan %ld) returned %d",
					vdc->instance, vdc->ldc_id, status);
			return (status);
		}
		vdc->initialized |= VDC_LDC_OPEN;
	}

	return (status);
}

static int
vdc_start_ldc_connection(vdc_t *vdc)
{
	int		status = 0;

	ASSERT(vdc != NULL);

	mutex_enter(&vdc->lock);

	if (vdc->ldc_state == LDC_UP) {
		PR0("%s:  LDC is already UP ..\n", __func__);
		mutex_exit(&vdc->lock);
		return (0);
	}

	if ((status = ldc_up(vdc->ldc_handle)) != 0) {
		switch (status) {
		case ECONNREFUSED:	/* listener not ready at other end */
			PR0("%s: ldc_up(%d,...) return %d\n",
					__func__, vdc->ldc_id, status);
			status = 0;
			break;
		default:
			cmn_err(CE_NOTE, "[%d] Failed to bring up LDC: "
					"channel=%ld, err=%d",
					vdc->instance, vdc->ldc_id, status);
		}
	}

	PR0("%s[%d] Finished bringing up LDC\n", __func__, vdc->instance);

	mutex_exit(&vdc->lock);

	return (status);
}


/*
 * Function:
 *	vdc_create_device_nodes
 *
 * Description:
 *	This function creates the block and character device nodes under
 *	/devices along with the node properties. It is called as part of
 *	the attach(9E) of the instance during the handshake with vds after
 *	vds has sent the attributes to vdc.
 *
 *	If the device is of type VD_DISK_TYPE_SLICE then the minor node
 *	of 2 is used in keeping with the Solaris convention that slice 2
 *	refers to a whole disk. Slices start at 'a'
 *
 * Parameters:
 *	vdc 		- soft state pointer
 *
 * Return Values
 *	0		- Success
 *	EIO		- Failed to create node
 *	EINVAL		- Unknown type of disk exported
 */
static int
vdc_create_device_nodes(vdc_t *vdc)
{
	/* uses NNNN which is OK as long as # of disks <= 10000 */
	char		name[sizeof ("disk@NNNN:s,raw")];
	dev_info_t	*dip = NULL;
	int		instance;
	int		num_slices = 1;
	int		i;

	ASSERT(vdc != NULL);

	instance = vdc->instance;
	dip = vdc->dip;

	switch (vdc->vdisk_type) {
	case VD_DISK_TYPE_DISK:
		num_slices = V_NUMPAR;
		break;
	case VD_DISK_TYPE_SLICE:
		num_slices = 1;
		break;
	case VD_DISK_TYPE_UNK:
	default:
		return (EINVAL);
	}

	for (i = 0; i < num_slices; i++) {
		(void) snprintf(name, sizeof (name), "%c", 'a' + i);
		if (ddi_create_minor_node(dip, name, S_IFBLK,
		    VD_MAKE_DEV(instance, i), DDI_NT_BLOCK, 0) != DDI_SUCCESS) {
			vdc_msg("%s[%d]: Couldn't add block node %s.",
				__func__, instance, name);
			return (EIO);
		}

		/* if any device node is created we set this flag */
		vdc->initialized |= VDC_MINOR;

		(void) snprintf(name, sizeof (name), "%c%s",
			'a' + i, ",raw");
		if (ddi_create_minor_node(dip, name, S_IFCHR,
		    VD_MAKE_DEV(instance, i), DDI_NT_BLOCK, 0) != DDI_SUCCESS) {
			vdc_msg("%s[%d]:  Could not add raw node %s.",
				__func__, instance, name);
			return (EIO);
		}
	}

	return (0);
}

/*
 * Function:
 *	vdc_create_device_nodes_props
 *
 * Description:
 *	This function creates the block and character device nodes under
 *	/devices along with the node properties. It is called as part of
 *	the attach(9E) of the instance during the handshake with vds after
 *	vds has sent the attributes to vdc.
 *
 * Parameters:
 *	vdc 		- soft state pointer
 *
 * Return Values
 *	0		- Success
 *	EIO		- Failed to create device node property
 *	EINVAL		- Unknown type of disk exported
 */
static int
vdc_create_device_nodes_props(vdc_t *vdc)
{
	dev_info_t	*dip = NULL;
	int		instance;
	int		num_slices = 1;
	int64_t		size = 0;
	dev_t		dev;
	int		rv;
	int		i;

	ASSERT(vdc != NULL);

	instance = vdc->instance;
	dip = vdc->dip;

	if ((vdc->vtoc == NULL) || (vdc->vtoc->v_sanity != VTOC_SANE)) {
		cmn_err(CE_NOTE, "![%d] Could not create device node property."
				" No VTOC available", instance);
		return (ENXIO);
	}

	switch (vdc->vdisk_type) {
	case VD_DISK_TYPE_DISK:
		num_slices = V_NUMPAR;
		break;
	case VD_DISK_TYPE_SLICE:
		num_slices = 1;
		break;
	case VD_DISK_TYPE_UNK:
	default:
		return (EINVAL);
	}

	for (i = 0; i < num_slices; i++) {
		dev = makedevice(ddi_driver_major(dip),
			VD_MAKE_DEV(instance, i));

		size = vdc->vtoc->v_part[i].p_size * vdc->vtoc->v_sectorsz;
		PR0("%s[%d] sz %ld (%ld Mb)  p_size %lx\n",
				__func__, instance, size, size / (1024 * 1024),
				vdc->vtoc->v_part[i].p_size);

		rv = ddi_prop_update_int64(dev, dip, VDC_SIZE_PROP_NAME, size);
		if (rv != DDI_PROP_SUCCESS) {
			vdc_msg("%s:(%d): Couldn't add \"%s\" [%d]\n",
				__func__, instance, VDC_SIZE_PROP_NAME, size);
			return (EIO);
		}

		rv = ddi_prop_update_int64(dev, dip, VDC_NBLOCKS_PROP_NAME,
			lbtodb(size));
		if (rv != DDI_PROP_SUCCESS) {
			vdc_msg("%s:(%d): Couldn't add \"%s\" [%d]\n", __func__,
				instance, VDC_NBLOCKS_PROP_NAME, lbtodb(size));
			return (EIO);
		}
	}

	return (0);
}

static int
vdc_open(dev_t *dev, int flag, int otyp, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	int		instance;
	int		status = 0;
	vdc_t		*vdc;

	ASSERT(dev != NULL);
	instance = SDUNIT(getminor(*dev));

	PR0("%s[%d] minor = %d flag = %x, otyp = %x\n", __func__, instance,
			getminor(*dev), flag, otyp);

	if ((otyp != OTYP_CHR) && (otyp != OTYP_BLK))
		return (EINVAL);

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		vdc_msg("%s[%d] Could not get state.", __func__, instance);
		return (ENXIO);
	}

	/*
	 * Check to see if we can communicate with vds
	 */
	status = vdc_is_able_to_tx_data(vdc, flag);
	if (status == B_FALSE) {
		PR0("%s[%d] Not ready to transmit data\n", __func__, instance);
		return (ENOLINK);
	}

	mutex_enter(&vdc->lock);
	vdc->open++;
	mutex_exit(&vdc->lock);

	return (0);
}

static int
vdc_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	int	instance;
	vdc_t	*vdc;

	instance = SDUNIT(getminor(dev));

	PR0("%s[%d] flag = %x, otyp = %x\n", __func__, instance, flag, otyp);

	if ((otyp != OTYP_CHR) && (otyp != OTYP_BLK))
		return (EINVAL);

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		vdc_msg("%s[%d] Could not get state.", __func__, instance);
		return (ENXIO);
	}

	/*
	 * Check to see if we can communicate with vds
	 */
	if (vdc_is_able_to_tx_data(vdc, 0) == B_FALSE) {
		PR0("%s[%d] Not ready to transmit data\n", __func__, instance);
		return (ETIMEDOUT);
	}

	if (vdc->dkio_flush_pending) {
		PR0("%s[%d]: Cannot detach: %d outstanding DKIO flushes",
			__func__, instance, vdc->dkio_flush_pending);
		return (EBUSY);
	}

	/*
	 * Should not need the mutex here, since the framework should protect
	 * against more opens on this device, but just in case.
	 */
	mutex_enter(&vdc->lock);
	vdc->open--;
	mutex_exit(&vdc->lock);

	return (0);
}

static int
vdc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	_NOTE(ARGUNUSED(credp))
	_NOTE(ARGUNUSED(rvalp))

	return (vd_process_ioctl(dev, cmd, (caddr_t)arg, mode));
}

static int
vdc_print(dev_t dev, char *str)
{
	cmn_err(CE_NOTE, "vdc%d:  %s", SDUNIT(getminor(dev)), str);
	return (0);
}

static int
vdc_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	int			rv = 0;
	size_t			nbytes = (nblk * DEV_BSIZE);
	int			instance = SDUNIT(getminor(dev));
	vdc_t			*vdc;

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		vdc_msg("%s (%d):  Could not get state.", __func__, instance);
		return (ENXIO);
	}

	rv = vdc_populate_descriptor(vdc, addr, nbytes, VD_OP_BWRITE,
					blkno, SDPART(getminor(dev)));

	PR1("%s: status=%d\n", __func__, rv);

	return (rv);
}

/* -------------------------------------------------------------------------- */

/*
 * Disk access routines
 *
 */

/*
 * vdc_strategy()
 *
 * Return Value:
 *	0:	As per strategy(9E), the strategy() function must return 0
 *		[ bioerror(9f) sets b_flags to the proper error code ]
 */
static int
vdc_strategy(struct buf *buf)
{
	int		rv = -1;
	vdc_t		*vdc = NULL;
	int		instance = SDUNIT(getminor(buf->b_edev));
	int	op = (buf->b_flags & B_READ) ? VD_OP_BREAD : VD_OP_BWRITE;

	PR1("%s: %s %ld bytes at block %ld : b_addr=0x%p",
	    __func__, (buf->b_flags & B_READ) ? "Read" : "Write",
	    buf->b_bcount, buf->b_lblkno, buf->b_un.b_addr);

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		vdc_msg("%s[%d]:  Could not get state.", __func__, instance);
		bioerror(buf, ENXIO);
		biodone(buf);
		return (0);
	}

	ASSERT(buf->b_bcount <= (vdc->max_xfer_sz * vdc->block_size));

	if (vdc_is_able_to_tx_data(vdc, O_NONBLOCK) == B_FALSE) {
		vdc_msg("%s: Not ready to transmit data", __func__);
		bioerror(buf, ENXIO);
		biodone(buf);
		return (0);
	}
	bp_mapin(buf);

	rv = vdc_populate_descriptor(vdc, buf->b_un.b_addr, buf->b_bcount, op,
			buf->b_lblkno, SDPART(getminor(buf->b_edev)));

	PR1("%s: status=%d", __func__, rv);
	bioerror(buf, rv);
	biodone(buf);
	return (0);
}


static int
vdc_read(dev_t dev, struct uio *uio, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	PR1("vdc_read():  Entered");
	return (physio(vdc_strategy, NULL, dev, B_READ, minphys, uio));
}

static int
vdc_write(dev_t dev, struct uio *uio, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	PR1("vdc_write():  Entered");
	return (physio(vdc_strategy, NULL, dev, B_WRITE, minphys, uio));
}

static int
vdc_aread(dev_t dev, struct aio_req *aio, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	PR1("vdc_aread():  Entered");
	return (aphysio(vdc_strategy, anocancel, dev, B_READ, minphys, aio));
}

static int
vdc_awrite(dev_t dev, struct aio_req *aio, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	PR1("vdc_awrite():  Entered");
	return (aphysio(vdc_strategy, anocancel, dev, B_WRITE, minphys, aio));
}


/* -------------------------------------------------------------------------- */

/*
 * Handshake support
 */

/*
 * vdc_init_handshake_negotiation
 *
 * Description:
 *	This function is called to trigger the handshake negotiations between
 *	the client (vdc) and the server (vds). It may be called multiple times.
 *
 * Parameters:
 *	vdc - soft state pointer
 */
static void
vdc_init_handshake_negotiation(void *arg)
{
	vdc_t		*vdc = (vdc_t *)(void *)arg;
	vd_state_t	state;

	ASSERT(vdc != NULL);
	ASSERT(vdc->ldc_state == LDC_UP);

	mutex_enter(&vdc->lock);

	/*
	 * Do not continue if another thread has triggered a handshake which
	 * is in progress or detach() has stopped further handshakes.
	 */
	if (vdc->initialized & (VDC_HANDSHAKE | VDC_HANDSHAKE_STOP)) {
		PR0("%s[%d] Negotiation not triggered. [init=%x]\n",
			__func__, vdc->instance, vdc->initialized);
		mutex_exit(&vdc->lock);
		return;
	}

	PR0("Initializing vdc<->vds handshake\n");

	vdc->initialized |= VDC_HANDSHAKE;

	state = vdc->state;

	if (state == VD_STATE_INIT) {
		(void) vdc_init_ver_negotiation(vdc);
	} else if (state == VD_STATE_VER) {
		(void) vdc_init_attr_negotiation(vdc);
	} else if (state == VD_STATE_ATTR) {
		(void) vdc_init_dring_negotiate(vdc);
	} else if (state == VD_STATE_DATA) {
		/*
		 * nothing to do - we have already completed the negotiation
		 * and we can transmit data when ready.
		 */
		PR0("%s[%d] Negotiation triggered after handshake completed",
			__func__, vdc->instance);
	}

	mutex_exit(&vdc->lock);
}

static int
vdc_init_ver_negotiation(vdc_t *vdc)
{
	vio_ver_msg_t	pkt;
	size_t		msglen = sizeof (pkt);
	int		status = -1;

	PR0("%s: Entered.\n", __func__);

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	/*
	 * set the Session ID to a unique value
	 * (the lower 32 bits of the clock tick)
	 */
	vdc->session_id = ((uint32_t)gettick() & 0xffffffff);

	pkt.tag.vio_msgtype = VIO_TYPE_CTRL;
	pkt.tag.vio_subtype = VIO_SUBTYPE_INFO;
	pkt.tag.vio_subtype_env = VIO_VER_INFO;
	pkt.tag.vio_sid = vdc->session_id;
	pkt.dev_class = VDEV_DISK;
	pkt.ver_major = VD_VER_MAJOR;
	pkt.ver_minor = VD_VER_MINOR;

	status = vdc_send(vdc->ldc_handle, (caddr_t)&pkt, &msglen);
	PR0("%s: vdc_send(status = %d)\n", __func__, status);

	if ((status != 0) || (msglen != sizeof (vio_ver_msg_t))) {
		PR0("%s[%d] vdc_send failed: id(%lx) rv(%d) size(%d)\n",
				__func__, vdc->instance, vdc->ldc_handle,
				status, msglen);
		if (msglen != sizeof (vio_ver_msg_t))
			status = ENOMSG;
	}

	return (status);
}

static int
vdc_init_attr_negotiation(vdc_t *vdc)
{
	vd_attr_msg_t	pkt;
	size_t		msglen = sizeof (pkt);
	int		status;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	PR0("%s[%d] entered\n", __func__, vdc->instance);

	/* fill in tag */
	pkt.tag.vio_msgtype = VIO_TYPE_CTRL;
	pkt.tag.vio_subtype = VIO_SUBTYPE_INFO;
	pkt.tag.vio_subtype_env = VIO_ATTR_INFO;
	pkt.tag.vio_sid = vdc->session_id;
	/* fill in payload */
	pkt.max_xfer_sz = vdc->max_xfer_sz;
	pkt.vdisk_block_size = vdc->block_size;
	pkt.xfer_mode = VIO_DRING_MODE;
	pkt.operations = 0;	/* server will set bits of valid operations */
	pkt.vdisk_type = 0;	/* server will set to valid device type */
	pkt.vdisk_size = 0;	/* server will set to valid size */

	status = vdc_send(vdc->ldc_handle, (caddr_t)&pkt, &msglen);
	PR0("%s: vdc_send(status = %d)\n", __func__, status);

	if ((status != 0) || (msglen != sizeof (vio_ver_msg_t))) {
		PR0("%s[%d] ldc_write failed: id(%lx) rv(%d) size (%d)\n",
			__func__, vdc->instance, vdc->ldc_handle,
			status, msglen);
		if (msglen != sizeof (vio_ver_msg_t))
			status = ENOMSG;
	}

	return (status);
}

static int
vdc_init_dring_negotiate(vdc_t *vdc)
{
	vio_dring_reg_msg_t	pkt;
	size_t			msglen = sizeof (pkt);
	int			status = -1;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	status = vdc_init_descriptor_ring(vdc);
	PR0("%s[%d] Init of descriptor ring completed (status = %d)\n",
			__func__, vdc->instance, status);
	if (status != 0) {
		cmn_err(CE_CONT, "[%d] Failed to init DRing (status = %d)\n",
				vdc->instance, status);
		vdc_reset_connection(vdc, B_FALSE);
		return (status);
	}

	/* fill in tag */
	pkt.tag.vio_msgtype = VIO_TYPE_CTRL;
	pkt.tag.vio_subtype = VIO_SUBTYPE_INFO;
	pkt.tag.vio_subtype_env = VIO_DRING_REG;
	pkt.tag.vio_sid = vdc->session_id;
	/* fill in payload */
	pkt.dring_ident = 0;
	pkt.num_descriptors = VD_DRING_LEN;
	pkt.descriptor_size = VD_DRING_ENTRY_SZ;
	pkt.options = (VIO_TX_DRING | VIO_RX_DRING);
	pkt.ncookies = vdc->dring_cookie_count;
	pkt.cookie[0] = vdc->dring_cookie[0];	/* for now just one cookie */

	status = vdc_send(vdc->ldc_handle, (caddr_t)&pkt, &msglen);
	if (status != 0) {
		PR0("%s[%d] Failed to register DRing (status = %d)\n",
				__func__, vdc->instance, status);
		vdc_reset_connection(vdc, B_FALSE);
	}

	return (status);
}


/* -------------------------------------------------------------------------- */

/*
 * LDC helper routines
 */

/*
 * Function:
 *	vdc_send()
 *
 * Description:
 *	The function encapsulates the call to write a message using LDC.
 *	If LDC indicates that the call failed due to the queue being full,
 *	we retry the ldc_write() [ up to 'vdc_retries' time ], otherwise
 *	we return the error returned by LDC.
 *
 * Arguments:
 *	ldc_handle	- LDC handle for the channel this instance of vdc uses
 *	pkt		- address of LDC message to be sent
 *	msglen		- the size of the message being sent. When the function
 *			  returns, this contains the number of bytes written.
 *
 * Return Code:
 *	0		- Success.
 *	EINVAL		- pkt or msglen were NULL
 *	ECONNRESET	- The connection was not up.
 *	EWOULDBLOCK	- LDC queue is full
 *	xxx		- other error codes returned by ldc_write
 */
static int
vdc_send(ldc_handle_t ldc_handle, caddr_t pkt, size_t *msglen)
{
	size_t	size = 0;
	int	retries = 0;
	int	status = 0;

	ASSERT(msglen != NULL);
	ASSERT(*msglen != 0);

	do {
		size = *msglen;
		status = ldc_write(ldc_handle, pkt, &size);
	} while (status == EWOULDBLOCK && retries++ < vdc_retries);

	/* return the last size written */
	*msglen = size;

	return (status);
}

/*
 * Function:
 *	vdc_get_ldc_id()
 *
 * Description:
 *	This function gets the 'ldc-id' for this particular instance of vdc.
 *	The id returned is the guest domain channel endpoint LDC uses for
 *	communication with vds.
 *
 * Arguments:
 *	dip	- dev info pointer for this instance of the device driver.
 *	ldc_id	- pointer to variable used to return the 'ldc-id' found.
 *
 * Return Code:
 *	0	- Success.
 *	ENOENT	- Expected node or property did not exist.
 *	ENXIO	- Unexpected error communicating with MD framework
 */
static int
vdc_get_ldc_id(dev_info_t *dip, uint64_t *ldc_id)
{
	int		status = ENOENT;
	char		*node_name = NULL;
	md_t		*mdp = NULL;
	int		num_nodes;
	int		num_vdevs;
	int		num_chans;
	mde_cookie_t	rootnode;
	mde_cookie_t	*listp = NULL;
	mde_cookie_t	*chanp = NULL;
	boolean_t	found_inst = B_FALSE;
	int		listsz;
	int		idx;
	uint64_t	md_inst;
	int		obp_inst;
	int		instance = ddi_get_instance(dip);

	ASSERT(ldc_id != NULL);
	*ldc_id = 0;

	/*
	 * Get the OBP instance number for comparison with the MD instance
	 *
	 * The "cfg-handle" property of a vdc node in an MD contains the MD's
	 * notion of "instance", or unique identifier, for that node; OBP
	 * stores the value of the "cfg-handle" MD property as the value of
	 * the "reg" property on the node in the device tree it builds from
	 * the MD and passes to Solaris.  Thus, we look up the devinfo node's
	 * "reg" property value to uniquely identify this device instance.
	 * If the "reg" property cannot be found, the device tree state is
	 * presumably so broken that there is no point in continuing.
	 */
	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, OBP_REG)) {
		cmn_err(CE_WARN, "'%s' property does not exist", OBP_REG);
		return (ENOENT);
	}
	obp_inst = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
			OBP_REG, -1);
	PR1("%s[%d]: OBP inst=%d\n", __func__, instance, obp_inst);

	/*
	 * We now walk the MD nodes and if an instance of a vdc node matches
	 * the instance got from OBP we get the ldc-id property.
	 */
	if ((mdp = md_get_handle()) == NULL) {
		cmn_err(CE_WARN, "unable to init machine description");
		return (ENXIO);
	}

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);

	/* allocate memory for nodes */
	listp = kmem_zalloc(listsz, KM_SLEEP);
	chanp = kmem_zalloc(listsz, KM_SLEEP);

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	/*
	 * Search for all the virtual devices, we will then check to see which
	 * ones are disk nodes.
	 */
	num_vdevs = md_scan_dag(mdp, rootnode,
			md_find_name(mdp, VDC_MD_VDEV_NAME),
			md_find_name(mdp, "fwd"), listp);

	if (num_vdevs <= 0) {
		cmn_err(CE_NOTE, "No '%s' node found", VDC_MD_VDEV_NAME);
		status = ENOENT;
		goto done;
	}

	PR1("%s[%d] num_vdevs=%d\n", __func__, instance, num_vdevs);
	for (idx = 0; idx < num_vdevs; idx++) {
		status = md_get_prop_str(mdp, listp[idx], "name", &node_name);
		if ((status != 0) || (node_name == NULL)) {
			cmn_err(CE_NOTE, "Unable to get name of node type '%s'"
					": err %d", VDC_MD_VDEV_NAME, status);
			continue;
		}

		PR1("%s[%d] Found node %s\n", __func__, instance, node_name);
		if (strcmp(VDC_MD_DISK_NAME, node_name) == 0) {
			status = md_get_prop_val(mdp, listp[idx],
					VDC_MD_CFG_HDL, &md_inst);
			PR1("%s[%d] vdc inst# in MD=%d\n",
					__func__, instance, md_inst);
			if ((status == 0) && (md_inst == obp_inst)) {
				found_inst = B_TRUE;
				break;
			}
		}
	}

	if (found_inst == B_FALSE) {
		cmn_err(CE_NOTE, "Unable to find correct '%s' node",
				VDC_MD_DISK_NAME);
		status = ENOENT;
		goto done;
	}
	PR0("%s[%d] MD inst=%d\n", __func__, instance, md_inst);

	/* get the channels for this node */
	num_chans = md_scan_dag(mdp, listp[idx],
			md_find_name(mdp, VDC_MD_CHAN_NAME),
			md_find_name(mdp, "fwd"), chanp);

	/* expecting at least one channel */
	if (num_chans <= 0) {
		cmn_err(CE_NOTE, "No '%s' node for '%s' port",
				VDC_MD_CHAN_NAME, VDC_MD_VDEV_NAME);
		status = ENOENT;
		goto done;

	} else if (num_chans != 1) {
		PR0("%s[%d] Expected 1 '%s' node for '%s' port, found %d\n",
			__func__, instance, VDC_MD_CHAN_NAME, VDC_MD_VDEV_NAME,
			num_chans);
	}

	/*
	 * We use the first channel found (index 0), irrespective of how
	 * many are there in total.
	 */
	if (md_get_prop_val(mdp, chanp[0], VDC_ID_PROP, ldc_id) != 0) {
		cmn_err(CE_NOTE, "Channel '%s' property not found",
				VDC_ID_PROP);
		status = ENOENT;
	}

	PR0("%s[%d] LDC id is 0x%lx\n", __func__, instance, *ldc_id);

done:
	if (chanp)
		kmem_free(chanp, listsz);
	if (listp)
		kmem_free(listp, listsz);

	(void) md_fini_handle(mdp);

	return (status);
}


/*
 * vdc_is_able_to_tx_data()
 *
 * Description:
 *	This function checks if we are able to send data to the
 *	vDisk server (vds). The LDC connection needs to be up and
 *	vdc & vds need to have completed the handshake negotiation.
 *
 * Parameters:
 *	vdc 		- soft state pointer
 *	flag		- flag to indicate if we can block or not
 *			  [ If O_NONBLOCK or O_NDELAY (which are defined in
 *			    open(2)) are set then do not block)
 *
 * Return Values
 *	B_TRUE		- can talk to vds
 *	B_FALSE		- unable to talk to vds
 */
static boolean_t
vdc_is_able_to_tx_data(vdc_t *vdc, int flag)
{
	vd_state_t	state;
	uint32_t	ldc_state;
	uint_t		retries = 0;
	int		rv = -1;

	ASSERT(vdc != NULL);

	mutex_enter(&vdc->lock);
	state = vdc->state;
	ldc_state = vdc->ldc_state;
	mutex_exit(&vdc->lock);

	if ((state == VD_STATE_DATA) && (ldc_state == LDC_UP))
		return (B_TRUE);

	if ((flag & O_NONBLOCK) || (flag & O_NDELAY)) {
		PR0("%s[%d] Not ready to tx - state %d LDC state %d\n",
			__func__, vdc->instance, state, ldc_state);
		return (B_FALSE);
	}

	/*
	 * We want to check and see if any negotiations triggered earlier
	 * have succeeded. We are prepared to wait a little while in case
	 * they are still in progress.
	 */
	mutex_enter(&vdc->lock);
	while ((vdc->ldc_state != LDC_UP) || (vdc->state != VD_STATE_DATA)) {
		PR0("%s: Waiting for connection at state %d (LDC state %d)\n",
			__func__, vdc->state, vdc->ldc_state);

		rv = cv_timedwait(&vdc->cv, &vdc->lock,
			VD_GET_TIMEOUT_HZ(retries));

		/*
		 * An rv of -1 indicates that we timed out without the LDC
		 * state changing so it looks like the other side (vdc) is
		 * not yet ready/responding.
		 *
		 * Any other value of rv indicates that the LDC triggered an
		 * interrupt so we just loop again, check the handshake state
		 * and keep waiting if necessary.
		 */
		if (rv == -1) {
			if (retries >= vdc_retries) {
				PR0("%s[%d] handshake wait timed out.\n",
						__func__, vdc->instance);
				mutex_exit(&vdc->lock);
				return (B_FALSE);
			} else {
				PR1("%s[%d] Retry #%d for handshake timedout\n",
					__func__, vdc->instance, retries);
				retries++;
			}
		}
	}

	ASSERT(vdc->ldc_state == LDC_UP);
	ASSERT(vdc->state == VD_STATE_DATA);

	mutex_exit(&vdc->lock);

	return (B_TRUE);
}


static void
vdc_terminate_ldc(vdc_t *vdc)
{
	int	instance = ddi_get_instance(vdc->dip);

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	PR0("%s[%d] initialized=%x\n", __func__, instance, vdc->initialized);

	if (vdc->initialized & VDC_LDC_OPEN) {
		PR0("%s[%d]: ldc_close()\n", __func__, instance);
		(void) ldc_close(vdc->ldc_handle);
	}
	if (vdc->initialized & VDC_LDC_CB) {
		PR0("%s[%d]: ldc_unreg_callback()\n", __func__, instance);
		(void) ldc_unreg_callback(vdc->ldc_handle);
	}
	if (vdc->initialized & VDC_LDC) {
		PR0("%s[%d]: ldc_fini()\n", __func__, instance);
		(void) ldc_fini(vdc->ldc_handle);
		vdc->ldc_handle = NULL;
	}

	vdc->initialized &= ~(VDC_LDC | VDC_LDC_CB | VDC_LDC_OPEN);
}

static void
vdc_reset_connection(vdc_t *vdc, boolean_t reset_ldc)
{
	int	status;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	PR0("%s[%d] Entered\n", __func__, vdc->instance);

	vdc->state = VD_STATE_INIT;

	if (reset_ldc == B_TRUE) {
		status = ldc_reset(vdc->ldc_handle);
		PR0("%s[%d]  ldc_reset() = %d\n",
				__func__, vdc->instance, status);
	}

	vdc->initialized &= ~VDC_HANDSHAKE;
	PR0("%s[%d] init=%x\n", __func__, vdc->instance, vdc->initialized);
}

/* -------------------------------------------------------------------------- */

/*
 * Descriptor Ring helper routines
 */

static int
vdc_init_descriptor_ring(vdc_t *vdc)
{
	vd_dring_entry_t	*dep = NULL;	/* DRing Entry pointer */
	int	status = -1;
	int	i;

	PR0("%s\n", __func__);

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));
	ASSERT(vdc->ldc_handle != NULL);

	status = ldc_mem_dring_create(VD_DRING_LEN, VD_DRING_ENTRY_SZ,
			&vdc->ldc_dring_hdl);
	if ((vdc->ldc_dring_hdl == NULL) || (status != 0)) {
		PR0("%s: Failed to create a descriptor ring", __func__);
		return (status);
	}
	vdc->initialized |= VDC_DRING;
	vdc->dring_entry_size = VD_DRING_ENTRY_SZ;
	vdc->dring_len = VD_DRING_LEN;

	vdc->dring_cookie = kmem_zalloc(sizeof (ldc_mem_cookie_t), KM_SLEEP);

	status = ldc_mem_dring_bind(vdc->ldc_handle, vdc->ldc_dring_hdl,
			LDC_SHADOW_MAP, LDC_MEM_RW, &vdc->dring_cookie[0],
			&vdc->dring_cookie_count);
	if (status != 0) {
		PR0("%s: Failed to bind descriptor ring (%p) to channel (%p)\n",
			__func__, vdc->ldc_dring_hdl, vdc->ldc_handle);
		return (status);
	}
	ASSERT(vdc->dring_cookie_count == 1);
	vdc->initialized |= VDC_DRING_BOUND;

	status = ldc_mem_dring_info(vdc->ldc_dring_hdl, &vdc->dring_mem_info);
	if (status != 0) {
		PR0("%s: Failed to get info for descriptor ring (%p)\n",
			__func__, vdc->ldc_dring_hdl);
		return (status);
	}

	/* Allocate the local copy of this dring */
	vdc->local_dring = kmem_zalloc(VD_DRING_LEN * sizeof (vdc_local_desc_t),
						KM_SLEEP);
	vdc->initialized |= VDC_DRING_LOCAL;

	/*
	 * Mark all DRing entries as free and init priv desc memory handles
	 * If any entry is initialized, we need to free it later so we set
	 * the bit in 'initialized' at the start.
	 */
	vdc->initialized |= VDC_DRING_ENTRY;
	for (i = 0; i < VD_DRING_LEN; i++) {
		dep = VDC_GET_DRING_ENTRY_PTR(vdc, i);
		dep->hdr.dstate = VIO_DESC_FREE;

		status = ldc_mem_alloc_handle(vdc->ldc_handle,
				&vdc->local_dring[i].desc_mhdl);
		if (status != 0) {
			cmn_err(CE_NOTE, "![%d] Failed to alloc mem handle for"
					" descriptor %d", vdc->instance, i);
			return (status);
		}
		vdc->local_dring[i].flags = VIO_DESC_FREE;
		vdc->local_dring[i].flags |= VDC_ALLOC_HANDLE;
		vdc->local_dring[i].dep = dep;

		mutex_init(&vdc->local_dring[i].lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&vdc->local_dring[i].cv, NULL, CV_DRIVER, NULL);
	}

	/*
	 * We init the index of the last DRing entry used. Since the code to
	 * get the next available entry increments it before selecting one,
	 * we set it to the last DRing entry so that it wraps around to zero
	 * for the 1st entry to be used.
	 */
	vdc->dring_curr_idx = VD_DRING_LEN - 1;

	return (status);
}

static void
vdc_destroy_descriptor_ring(vdc_t *vdc)
{
	ldc_mem_handle_t	mhdl = NULL;
	int	status = -1;
	int	i;	/* loop */

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));
	ASSERT(vdc->state == VD_STATE_INIT);

	PR0("%s: Entered\n", __func__);

	if (vdc->initialized & VDC_DRING_ENTRY) {
		for (i = 0; i < VD_DRING_LEN; i++) {
			mhdl = vdc->local_dring[i].desc_mhdl;

			if (vdc->local_dring[i].flags | VDC_ALLOC_HANDLE)
				(void) ldc_mem_free_handle(mhdl);

			mutex_destroy(&vdc->local_dring[i].lock);
			cv_destroy(&vdc->local_dring[i].cv);

			bzero(&vdc->local_dring[i].desc_mhdl,
				sizeof (ldc_mem_handle_t));
		}
		vdc->initialized &= ~VDC_DRING_ENTRY;
	}

	if (vdc->initialized & VDC_DRING_LOCAL) {
		kmem_free(vdc->local_dring,
				VD_DRING_LEN * sizeof (vdc_local_desc_t));
		vdc->initialized &= ~VDC_DRING_LOCAL;
	}

	if (vdc->initialized & VDC_DRING_BOUND) {
		status = ldc_mem_dring_unbind(vdc->ldc_dring_hdl);
		if (status == 0) {
			vdc->initialized &= ~VDC_DRING_BOUND;
		} else {
			vdc_msg("%s: Failed to unbind Descriptor Ring (%lx)\n",
				vdc->ldc_dring_hdl);
		}
	}

	if (vdc->initialized & VDC_DRING_INIT) {
		status = ldc_mem_dring_destroy(vdc->ldc_dring_hdl);
		if (status == 0) {
			vdc->ldc_dring_hdl = NULL;
			bzero(&vdc->dring_mem_info, sizeof (ldc_mem_info_t));
			vdc->initialized &= ~VDC_DRING_INIT;
		} else {
			vdc_msg("%s: Failed to destroy Descriptor Ring (%lx)\n",
				vdc->ldc_dring_hdl);
		}
	}
}

/*
 * vdc_get_next_dring_entry_idx()
 *
 * Description:
 *	This function gets the index of the next Descriptor Ring entry available
 *
 * Return Value:
 *	0 <= rv < VD_DRING_LEN		Next available slot
 *	-1 				DRing is full
 */
static int
vdc_get_next_dring_entry_idx(vdc_t *vdc, uint_t num_slots_needed)
{
	_NOTE(ARGUNUSED(num_slots_needed))

	vd_dring_entry_t	*dep = NULL;	/* Dring Entry Pointer */
	int			idx = -1;
	int			start_idx = 0;

	ASSERT(vdc != NULL);
	ASSERT(vdc->dring_len == VD_DRING_LEN);
	ASSERT(vdc->dring_curr_idx >= 0);
	ASSERT(vdc->dring_curr_idx < VD_DRING_LEN);
	ASSERT(mutex_owned(&vdc->dring_lock));

	/* Start at the last entry used */
	idx = start_idx = vdc->dring_curr_idx;

	/*
	 * Loop through Descriptor Ring checking for a free entry until we reach
	 * the entry we started at. We should never come close to filling the
	 * Ring at any stage, instead this is just to prevent an entry which
	 * gets into an inconsistent state (e.g. due to a request timing out)
	 * from blocking progress.
	 */
	do {
		/* Get the next entry after the last known index tried */
		idx = (idx + 1) % VD_DRING_LEN;

		dep = VDC_GET_DRING_ENTRY_PTR(vdc, idx);
		ASSERT(dep != NULL);

		if (dep->hdr.dstate == VIO_DESC_FREE) {
			ASSERT(idx >= 0);
			ASSERT(idx < VD_DRING_LEN);
			vdc->dring_curr_idx = idx;
			return (idx);

		} else if (dep->hdr.dstate == VIO_DESC_READY) {
			PR0("%s: Entry %d waiting to be accepted\n",
					__func__, idx);
			continue;

		} else if (dep->hdr.dstate == VIO_DESC_ACCEPTED) {
			PR0("%s: Entry %d waiting to be processed\n",
					__func__, idx);
			continue;

		} else if (dep->hdr.dstate == VIO_DESC_DONE) {
			PR0("%s: Entry %d done but not marked free\n",
					__func__, idx);

			/*
			 * If we are currently panicking, interrupts are
			 * disabled and we will not be getting ACKs from the
			 * vDisk server so we mark the descriptor ring entries
			 * as FREE here instead of in the ACK handler.
			 */
			if (panicstr) {
				(void) vdc_depopulate_descriptor(vdc, idx);
				dep->hdr.dstate = VIO_DESC_FREE;
				vdc->local_dring[idx].flags = VIO_DESC_FREE;
			}
			continue;

		} else {
			vdc_msg("Public Descriptor Ring entry corrupted");
			mutex_enter(&vdc->lock);
			vdc_reset_connection(vdc, B_TRUE);
			mutex_exit(&vdc->lock);
			return (-1);
		}

	} while (idx != start_idx);

	return (-1);
}

/*
 * Function:
 *	vdc_populate_descriptor
 *
 * Description:
 *	This routine writes the data to be transmitted to vds into the
 *	descriptor, notifies vds that the ring has been updated and
 *	then waits for the request to be processed.
 *
 * Arguments:
 *	vdc	- the soft state pointer
 *	addr	- start address of memory region.
 *	nbytes	- number of bytes to read/write
 *	operation - operation we want vds to perform (VD_OP_XXX)
 *	arg	- parameter to be sent to server (depends on VD_OP_XXX type)
 *			. mode for ioctl(9e)
 *			. LP64 diskaddr_t (block I/O)
 *	slice	- the disk slice this request is for
 *
 * Return Codes:
 *	0
 *	EAGAIN
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
vdc_populate_descriptor(vdc_t *vdc, caddr_t addr, size_t nbytes, int operation,
				uint64_t arg, uint64_t slice)
{
	vdc_local_desc_t *local_dep = NULL;	/* Local Dring Entry Pointer */
	vd_dring_entry_t *dep = NULL;		/* Dring Entry Pointer */
	int			idx = 0;	/* Index of DRing entry used */
	vio_dring_msg_t		dmsg;
	size_t			msglen = sizeof (dmsg);
	int			status = 0;
	int			rv;
	int			retries = 0;

	ASSERT(vdc != NULL);
	ASSERT(slice < V_NUMPAR);

	/*
	 * Get next available DRing entry.
	 */
	mutex_enter(&vdc->dring_lock);
	idx = vdc_get_next_dring_entry_idx(vdc, 1);
	if (idx == -1) {
		mutex_exit(&vdc->dring_lock);
		vdc_msg("%s[%d]: no descriptor ring entry avail, seq=%d\n",
			__func__, vdc->instance, vdc->seq_num);

		/*
		 * Since strategy should not block we don't wait for the DRing
		 * to empty and instead return
		 */
		return (EAGAIN);
	}

	ASSERT(idx < VD_DRING_LEN);
	local_dep = &vdc->local_dring[idx];
	dep = local_dep->dep;
	ASSERT(dep != NULL);

	/*
	 * Wait for anybody still using the DRing entry to finish.
	 * (e.g. still waiting for vds to respond to a request)
	 */
	mutex_enter(&local_dep->lock);

	switch (operation) {
	case VD_OP_BREAD:
	case VD_OP_BWRITE:
		PR1("buf=%p, block=%lx, nbytes=%lx\n", addr, arg, nbytes);
		dep->payload.addr = (diskaddr_t)arg;
		rv = vdc_populate_mem_hdl(vdc, idx, addr, nbytes, operation);
		break;

	case VD_OP_FLUSH:
	case VD_OP_GET_VTOC:
	case VD_OP_SET_VTOC:
	case VD_OP_GET_DISKGEOM:
	case VD_OP_SET_DISKGEOM:
	case VD_OP_SCSICMD:
		if (nbytes > 0) {
			rv = vdc_populate_mem_hdl(vdc, idx, addr, nbytes,
							operation);
		}
		break;
	default:
		cmn_err(CE_NOTE, "[%d] Unsupported vDisk operation [%d]\n",
				vdc->instance, operation);
		rv = EINVAL;
	}

	if (rv != 0) {
		mutex_exit(&local_dep->lock);
		mutex_exit(&vdc->dring_lock);
		return (rv);
	}

	/*
	 * fill in the data details into the DRing
	 */
	dep->payload.req_id = VDC_GET_NEXT_REQ_ID(vdc);
	dep->payload.operation = operation;
	dep->payload.nbytes = nbytes;
	dep->payload.status = EINPROGRESS;	/* vds will set valid value */
	dep->payload.slice = slice;
	dep->hdr.dstate = VIO_DESC_READY;
	dep->hdr.ack = 1;		/* request an ACK for every message */

	local_dep->flags = VIO_DESC_READY;
	local_dep->addr = addr;

	/*
	 * Send a msg with the DRing details to vds
	 */
	VIO_INIT_DRING_DATA_TAG(dmsg);
	VDC_INIT_DRING_DATA_MSG_IDS(dmsg, vdc);
	dmsg.dring_ident = vdc->dring_ident;
	dmsg.start_idx = idx;
	dmsg.end_idx = idx;

	PR1("ident=0x%llx, st=%d, end=%d, seq=%d req=%d dep=%p\n",
			vdc->dring_ident, dmsg.start_idx, dmsg.end_idx,
			dmsg.seq_num, dep->payload.req_id, dep);

	status = vdc_send(vdc->ldc_handle, (caddr_t)&dmsg, &msglen);
	PR1("%s[%d]: ldc_write() status=%d\n", __func__, vdc->instance, status);
	if (status != 0) {
		mutex_exit(&local_dep->lock);
		mutex_exit(&vdc->dring_lock);
		vdc_msg("%s: ldc_write(%d)\n", __func__, status);
		return (EAGAIN);
	}

	/*
	 * XXX - potential performance enhancement (Investigate at a later date)
	 *
	 * for calls from strategy(9E), instead of waiting for a response from
	 * vds, we could return at this stage and let the ACK handling code
	 * trigger the biodone(9F)
	 */

	/*
	 * When a guest is panicking, the completion of requests needs to be
	 * handled differently because interrupts are disabled and vdc
	 * will not get messages. We have to poll for the messages instead.
	 */
	if (ddi_in_panic()) {
		int start = 0;
		retries = 0;
		for (;;) {
			msglen = sizeof (dmsg);
			status = ldc_read(vdc->ldc_handle, (caddr_t)&dmsg,
					&msglen);
			if (status) {
				status = EINVAL;
				break;
			}

			/*
			 * if there are no packets wait and check again
			 */
			if ((status == 0) && (msglen == 0)) {
				if (retries++ > vdc_dump_retries) {
					PR0("[%d] Giving up waiting, idx %d\n",
							vdc->instance, idx);
					status = EAGAIN;
					break;
				}

				PR1("Waiting for next packet @ %d\n", idx);
				delay(drv_usectohz(vdc_dump_usec_timeout));
				continue;
			}

			/*
			 * Ignore all messages that are not ACKs/NACKs to
			 * DRing requests.
			 */
			if ((dmsg.tag.vio_msgtype != VIO_TYPE_DATA) ||
			    (dmsg.tag.vio_subtype_env != VIO_DRING_DATA)) {
				PR0("discarding pkt: type=%d sub=%d env=%d\n",
					dmsg.tag.vio_msgtype,
					dmsg.tag.vio_subtype,
					dmsg.tag.vio_subtype_env);
				continue;
			}

			/*
			 * set the appropriate return value for the
			 * current request.
			 */
			switch (dmsg.tag.vio_subtype) {
			case VIO_SUBTYPE_ACK:
				status = 0;
				break;
			case VIO_SUBTYPE_NACK:
				status = EAGAIN;
				break;
			default:
				continue;
			}

			start = dmsg.start_idx;
			if (start >= VD_DRING_LEN) {
				PR0("[%d] Bogus ack data : start %d\n",
					vdc->instance, start);
				continue;
			}

			dep = VDC_GET_DRING_ENTRY_PTR(vdc, start);

			PR1("[%d] Dumping start=%d idx=%d state=%d\n",
				vdc->instance, start, idx, dep->hdr.dstate);

			if (dep->hdr.dstate != VIO_DESC_DONE) {
				PR0("[%d] Entry @ %d - state !DONE %d\n",
					vdc->instance, start, dep->hdr.dstate);
				continue;
			}

			(void) vdc_depopulate_descriptor(vdc, start);

			/*
			 * We want to process all Dring entries up to
			 * the current one so that we can return an
			 * error with the correct request.
			 */
			if (idx > start) {
				PR0("[%d] Looping: start %d, idx %d\n",
						vdc->instance, idx, start);
				continue;
			}

			/* exit - all outstanding requests are completed */
			break;
		}

		mutex_exit(&local_dep->lock);
		mutex_exit(&vdc->dring_lock);

		return (status);
	}

	/*
	 * Now watch the DRing entries we modified to get the response
	 * from vds.
	 */
	status = vdc_wait_for_descriptor_update(vdc, idx, dmsg);
	if (status == ETIMEDOUT) {
		/* debug info when dumping state on vds side */
		dep->payload.status = ECANCELED;
	}

	status = vdc_depopulate_descriptor(vdc, idx);
	PR1("%s[%d] Status=%d\n", __func__, vdc->instance, status);

	mutex_exit(&local_dep->lock);
	mutex_exit(&vdc->dring_lock);

	return (status);
}

static int
vdc_wait_for_descriptor_update(vdc_t *vdc, uint_t idx, vio_dring_msg_t dmsg)
{
	vd_dring_entry_t *dep = NULL;		/* Dring Entry Pointer */
	vdc_local_desc_t *local_dep = NULL;	/* Local Dring Entry Pointer */
	size_t	msglen = sizeof (dmsg);
	int	retries = 0;
	int	status = ENXIO;
	int	rv = 0;

	ASSERT(vdc != NULL);
	ASSERT(idx < VD_DRING_LEN);
	local_dep = &vdc->local_dring[idx];
	ASSERT(local_dep != NULL);
	dep = local_dep->dep;
	ASSERT(dep != NULL);

	while (dep->hdr.dstate != VIO_DESC_DONE) {
		rv = cv_timedwait(&local_dep->cv, &local_dep->lock,
			VD_GET_TIMEOUT_HZ(retries));
		if (rv == -1) {
			/*
			 * If they persist in ignoring us we'll storm off in a
			 * huff and return ETIMEDOUT to the upper layers.
			 */
			if (retries >= vdc_retries) {
				PR0("%s: Finished waiting on entry %d\n",
					__func__, idx);
				status = ETIMEDOUT;
				break;
			} else {
				retries++;
				PR0("%s[%d]: Timeout #%d on entry %d "
				    "[seq %d][req %d]\n", __func__,
				    vdc->instance,
				    retries, idx, dmsg.seq_num,
				    dep->payload.req_id);
			}

			if (dep->hdr.dstate & VIO_DESC_ACCEPTED) {
				PR0("%s[%d]: vds has accessed entry %d [seq %d]"
				    "[req %d] but not ack'ed it yet\n",
				    __func__, vdc->instance, idx, dmsg.seq_num,
				    dep->payload.req_id);
				continue;
			}

			/*
			 * we resend the message as it may have been dropped
			 * and have never made it to the other side (vds).
			 * (We reuse the original message but update seq ID)
			 */
			VDC_INIT_DRING_DATA_MSG_IDS(dmsg, vdc);
			retries = 0;
			status = vdc_send(vdc->ldc_handle, (caddr_t)&dmsg,
					&msglen);
			if (status != 0) {
				vdc_msg("%s: Error (%d) while resending after "
					"timeout\n", __func__, status);
				status = ETIMEDOUT;
				break;
			}
		}
	}

	return (status);
}

static int
vdc_get_response(vdc_t *vdc, int start, int end)
{
	vdc_local_desc_t	*ldep = NULL;	/* Local Dring Entry Pointer */
	vd_dring_entry_t	*dep = NULL;	/* Dring Entry Pointer */
	int			status = ENXIO;
	int			idx = -1;

	ASSERT(vdc != NULL);
	ASSERT(start >= 0);
	ASSERT(start <= VD_DRING_LEN);
	ASSERT(start >= -1);
	ASSERT(start <= VD_DRING_LEN);

	idx = start;
	ldep = &vdc->local_dring[idx];
	ASSERT(ldep != NULL);
	dep = ldep->dep;
	ASSERT(dep != NULL);

	PR0("%s[%d] DRING entry=%d status=%d\n", __func__, vdc->instance,
			idx, VIO_GET_DESC_STATE(dep->hdr.dstate));
	while (VIO_GET_DESC_STATE(dep->hdr.dstate) == VIO_DESC_DONE) {
		if ((end != -1) && (idx > end))
			return (0);

		switch (ldep->operation) {
		case VD_OP_BREAD:
		case VD_OP_BWRITE:
			/* call bioxxx */
			break;
		default:
			/* signal waiter */
			break;
		}

		/* Clear the DRing entry */
		status = vdc_depopulate_descriptor(vdc, idx);
		PR0("%s[%d] Status=%d\n", __func__, vdc->instance, status);

		/* loop accounting to get next DRing entry */
		idx++;
		ldep = &vdc->local_dring[idx];
		dep = ldep->dep;
	}

	return (status);
}

static int
vdc_depopulate_descriptor(vdc_t *vdc, uint_t idx)
{
	vd_dring_entry_t *dep = NULL;		/* Dring Entry Pointer */
	vdc_local_desc_t *ldep = NULL;	/* Local Dring Entry Pointer */
	int	status = ENXIO;

	ASSERT(vdc != NULL);
	ASSERT(idx < VD_DRING_LEN);
	ldep = &vdc->local_dring[idx];
	ASSERT(ldep != NULL);
	dep = ldep->dep;
	ASSERT(dep != NULL);

	status = dep->payload.status;
	VDC_MARK_DRING_ENTRY_FREE(vdc, idx);
	ldep = &vdc->local_dring[idx];
	VIO_SET_DESC_STATE(ldep->flags, VIO_DESC_FREE);

	/*
	 * If the upper layer passed in a misaligned address we copied the
	 * data into an aligned buffer before sending it to LDC - we now
	 * copy it back to the original buffer.
	 */
	if (ldep->align_addr) {
		ASSERT(ldep->addr != NULL);
		ASSERT(dep->payload.nbytes > 0);

		bcopy(ldep->align_addr, ldep->addr, dep->payload.nbytes);
		kmem_free(ldep->align_addr,
				sizeof (caddr_t) * dep->payload.nbytes);
		ldep->align_addr = NULL;
	}

	status = ldc_mem_unbind_handle(ldep->desc_mhdl);
	if (status != 0) {
		cmn_err(CE_NOTE, "[%d] unbind mem hdl 0x%lx @ idx %d failed:%d",
			vdc->instance, ldep->desc_mhdl, idx, status);
	}

	return (status);
}

static int
vdc_populate_mem_hdl(vdc_t *vdc, uint_t idx, caddr_t addr, size_t nbytes,
			int operation)
{
	vd_dring_entry_t	*dep = NULL;
	vdc_local_desc_t	*ldep = NULL;
	ldc_mem_handle_t	mhdl;
	caddr_t			vaddr;
	int			perm = LDC_MEM_RW;
	int			rv = 0;
	int			i;

	ASSERT(vdc != NULL);
	ASSERT(idx < VD_DRING_LEN);

	dep = VDC_GET_DRING_ENTRY_PTR(vdc, idx);
	ldep = &vdc->local_dring[idx];
	mhdl = ldep->desc_mhdl;

	switch (operation) {
	case VD_OP_BREAD:
		perm = LDC_MEM_W;
		break;

	case VD_OP_BWRITE:
		perm = LDC_MEM_R;
		break;

	case VD_OP_FLUSH:
	case VD_OP_GET_VTOC:
	case VD_OP_SET_VTOC:
	case VD_OP_GET_DISKGEOM:
	case VD_OP_SET_DISKGEOM:
	case VD_OP_SCSICMD:
		perm = LDC_MEM_RW;
		break;

	default:
		ASSERT(0);	/* catch bad programming in vdc */
	}

	/*
	 * LDC expects any addresses passed in to be 8-byte aligned. We need
	 * to copy the contents of any misaligned buffers to a newly allocated
	 * buffer and bind it instead (and copy the the contents back to the
	 * original buffer passed in when depopulating the descriptor)
	 */
	vaddr = addr;
	if (((uint64_t)addr & 0x7) != 0) {
		ldep->align_addr =
			kmem_zalloc(sizeof (caddr_t) * nbytes, KM_SLEEP);
		PR0("%s[%d] Misaligned address %lx reallocating "
		    "(buf=%lx entry=%d)\n",
		    __func__, vdc->instance, addr, ldep->align_addr, idx);
		bcopy(addr, ldep->align_addr, nbytes);
		vaddr = ldep->align_addr;
	}

	rv = ldc_mem_bind_handle(mhdl, vaddr, P2ROUNDUP(nbytes, 8),
		vdc->dring_mem_info.mtype, perm, &dep->payload.cookie[0],
		&dep->payload.ncookies);
	PR1("%s[%d] bound mem handle; ncookies=%d\n",
			__func__, vdc->instance, dep->payload.ncookies);
	if (rv != 0) {
		vdc_msg("%s[%d] failed to ldc_mem_bind_handle "
		    "(mhdl=%lx, buf=%lx entry=%d err=%d)\n",
		    __func__, vdc->instance, mhdl, addr, idx, rv);
		if (ldep->align_addr) {
			kmem_free(ldep->align_addr,
				sizeof (caddr_t) * dep->payload.nbytes);
			ldep->align_addr = NULL;
		}
		return (EAGAIN);
	}

	/*
	 * Get the other cookies (if any).
	 */
	for (i = 1; i < dep->payload.ncookies; i++) {
		rv = ldc_mem_nextcookie(mhdl, &dep->payload.cookie[i]);
		if (rv != 0) {
			(void) ldc_mem_unbind_handle(mhdl);
			vdc_msg("%s: failed to get next cookie(mhdl=%lx "
				"cnum=%d), err=%d", __func__, mhdl, i, rv);
			if (ldep->align_addr) {
				kmem_free(ldep->align_addr,
					sizeof (caddr_t) * dep->payload.nbytes);
				ldep->align_addr = NULL;
			}
			return (EAGAIN);
		}
	}

	return (rv);
}

/*
 * Interrupt handlers for messages from LDC
 */

static uint_t
vdc_handle_cb(uint64_t event, caddr_t arg)
{
	ldc_status_t	ldc_state;
	int		rv = 0;

	vdc_t	*vdc = (vdc_t *)(void *)arg;

	ASSERT(vdc != NULL);

	PR1("%s[%d] event=%x seqID=%d\n",
			__func__, vdc->instance, event, vdc->seq_num);

	/*
	 * Depending on the type of event that triggered this callback,
	 * we modify the handhske state or read the data.
	 *
	 * NOTE: not done as a switch() as event could be triggered by
	 * a state change and a read request. Also the ordering	of the
	 * check for the event types is deliberate.
	 */
	if (event & LDC_EVT_UP) {
		PR0("%s[%d] Received LDC_EVT_UP\n", __func__, vdc->instance);

		/* get LDC state */
		rv = ldc_status(vdc->ldc_handle, &ldc_state);
		if (rv != 0) {
			cmn_err(CE_NOTE, "[%d] Couldn't get LDC status %d",
					vdc->instance, rv);
			vdc_reset_connection(vdc, B_TRUE);
			return (LDC_SUCCESS);
		}

		/*
		 * Reset the transaction sequence numbers when LDC comes up.
		 * We then kick off the handshake negotiation with the vDisk
		 * server.
		 */
		mutex_enter(&vdc->lock);
		vdc->seq_num = 0;
		vdc->seq_num_reply = 0;
		vdc->ldc_state = ldc_state;
		ASSERT(ldc_state == LDC_UP);
		mutex_exit(&vdc->lock);

		vdc_init_handshake_negotiation(vdc);

		ASSERT((event & (LDC_EVT_RESET | LDC_EVT_DOWN)) == 0);
	}

	if (event & LDC_EVT_READ) {
		/*
		 * Wake up the worker thread to process the message
		 */
		mutex_enter(&vdc->msg_proc_lock);
		vdc->msg_pending = B_TRUE;
		cv_signal(&vdc->msg_proc_cv);
		mutex_exit(&vdc->msg_proc_lock);

		ASSERT((event & (LDC_EVT_RESET | LDC_EVT_DOWN)) == 0);

		/* that's all we have to do - no need to handle DOWN/RESET */
		return (LDC_SUCCESS);
	}

	if (event & LDC_EVT_RESET) {
		PR0("%s[%d] Recvd LDC RESET event\n", __func__, vdc->instance);
	}

	if (event & LDC_EVT_DOWN) {
		PR0("%s[%d] Recvd LDC DOWN event\n", __func__, vdc->instance);

		/* get LDC state */
		rv = ldc_status(vdc->ldc_handle, &ldc_state);
		if (rv != 0) {
			cmn_err(CE_NOTE, "[%d] Couldn't get LDC status %d",
					vdc->instance, rv);
			ldc_state = LDC_OPEN;
		}
		mutex_enter(&vdc->lock);
		vdc->ldc_state = ldc_state;
		mutex_exit(&vdc->lock);

		vdc_reset_connection(vdc, B_TRUE);
	}

	if (event & ~(LDC_EVT_UP | LDC_EVT_RESET | LDC_EVT_DOWN | LDC_EVT_READ))
		cmn_err(CE_NOTE, "![%d] Unexpected LDC event (%lx) received",
				vdc->instance, event);

	return (LDC_SUCCESS);
}

/* -------------------------------------------------------------------------- */

/*
 * The following functions process the incoming messages from vds
 */


static void
vdc_process_msg_thread(vdc_t *vdc)
{
	int		status = 0;
	boolean_t	q_is_empty = B_TRUE;

	ASSERT(vdc != NULL);

	mutex_enter(&vdc->msg_proc_lock);
	PR0("%s[%d]: Starting\n", __func__, vdc->instance);

	vdc->msg_proc_thr_state = VDC_THR_RUNNING;

	while (vdc->msg_proc_thr_state == VDC_THR_RUNNING) {

		PR1("%s[%d] Waiting\n", __func__, vdc->instance);
		while (vdc->msg_pending == B_FALSE)
			cv_wait(&vdc->msg_proc_cv, &vdc->msg_proc_lock);

		PR1("%s[%d] Message Received\n", __func__, vdc->instance);

		/* check if there is data */
		status = ldc_chkq(vdc->ldc_handle, &q_is_empty);
		if ((status != 0) &&
		    (vdc->msg_proc_thr_state == VDC_THR_RUNNING)) {
			cmn_err(CE_NOTE, "[%d] Unable to communicate with vDisk"
					" server. Cannot check LDC queue: %d",
					vdc->instance, status);
			mutex_enter(&vdc->lock);
			vdc_reset_connection(vdc, B_TRUE);
			mutex_exit(&vdc->lock);
			vdc->msg_proc_thr_state = VDC_THR_STOP;
			continue;
		}

		if (q_is_empty == B_FALSE) {
			PR1("%s: new pkt(s) available\n", __func__);
			vdc_process_msg(vdc);
		}

		vdc->msg_pending = B_FALSE;
	}

	PR0("Message processing thread stopped\n");
	vdc->msg_pending = B_FALSE;
	vdc->msg_proc_thr_state = VDC_THR_DONE;
	cv_signal(&vdc->msg_proc_cv);
	mutex_exit(&vdc->msg_proc_lock);
	thread_exit();
}


/*
 * Function:
 *	vdc_process_msg()
 *
 * Description:
 *	This function is called by the message processing thread each time it
 *	is triggered when LDC sends an interrupt to indicate that there are
 *	more packets on the queue. When it is called it will continue to loop
 *	and read the messages until there are no more left of the queue. If it
 *	encounters an invalid sized message it will drop it and check the next
 *	message.
 *
 * Arguments:
 *	arg	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	None.
 */
static void
vdc_process_msg(void *arg)
{
	vdc_t		*vdc = (vdc_t *)(void *)arg;
	vio_msg_t	vio_msg;
	size_t		nbytes = sizeof (vio_msg);
	int		status;

	ASSERT(vdc != NULL);

	mutex_enter(&vdc->lock);

	PR1("%s\n", __func__);

	for (;;) {

		/* read all messages - until no more left */
		status = ldc_read(vdc->ldc_handle, (caddr_t)&vio_msg, &nbytes);

		if (status) {
			vdc_msg("%s: ldc_read() failed = %d", __func__, status);

			/* if status is ECONNRESET --- reset vdc state */
			if (status == EIO || status == ECONNRESET) {
				vdc_reset_connection(vdc, B_FALSE);
			}

			mutex_exit(&vdc->lock);
			return;
		}

		if ((nbytes > 0) && (nbytes < sizeof (vio_msg_tag_t))) {
			cmn_err(CE_CONT, "![%d] Expect %lu bytes; recv'd %lu\n",
				vdc->instance, sizeof (vio_msg_tag_t), nbytes);
			mutex_exit(&vdc->lock);
			return;
		}

		if (nbytes == 0) {
			PR2("%s[%d]: ldc_read() done..\n",
					__func__, vdc->instance);
			mutex_exit(&vdc->lock);
			return;
		}

		PR1("%s[%d] (%x/%x/%x)\n", __func__, vdc->instance,
		    vio_msg.tag.vio_msgtype,
		    vio_msg.tag.vio_subtype,
		    vio_msg.tag.vio_subtype_env);

		/*
		 * Verify the Session ID of the message
		 *
		 * Every message after the Version has been negotiated should
		 * have the correct session ID set.
		 */
		if ((vio_msg.tag.vio_sid != vdc->session_id) &&
		    (vio_msg.tag.vio_subtype_env != VIO_VER_INFO)) {
			PR0("%s: Incorrect SID 0x%x msg 0x%lx, expected 0x%x\n",
				__func__, vio_msg.tag.vio_sid, &vio_msg,
				vdc->session_id);
			vdc_reset_connection(vdc, B_FALSE);
			mutex_exit(&vdc->lock);
			return;
		}

		switch (vio_msg.tag.vio_msgtype) {
		case VIO_TYPE_CTRL:
			status = vdc_process_ctrl_msg(vdc, vio_msg);
			break;
		case VIO_TYPE_DATA:
			status = vdc_process_data_msg(vdc, vio_msg);
			break;
		case VIO_TYPE_ERR:
			status = vdc_process_err_msg(vdc, vio_msg);
			break;
		default:
			PR1("%s", __func__);
			status = EINVAL;
			break;
		}

		if (status != 0) {
			PR0("%s[%d] Error (%d) occcurred processing msg\n",
					__func__, vdc->instance, status);
			vdc_reset_connection(vdc, B_FALSE);
		}
	}
	_NOTE(NOTREACHED)
}

/*
 * Function:
 *	vdc_process_ctrl_msg()
 *
 * Description:
 *	This function is called by the message processing thread each time
 *	an LDC message with a msgtype of VIO_TYPE_CTRL is received.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	msg	- the LDC message sent by vds
 *
 * Return Codes:
 *	0	- Success.
 *	EPROTO	- A message was received which shouldn't have happened according
 *		  to the protocol
 *	ENOTSUP	- An action which is allowed according to the protocol but which
 *		  isn't (or doesn't need to be) implemented yet.
 *	EINVAL	- An invalid value was returned as part of a message.
 */
static int
vdc_process_ctrl_msg(vdc_t *vdc, vio_msg_t msg)
{
	size_t			msglen = sizeof (msg);
	vd_attr_msg_t		*attr_msg = NULL;
	vio_dring_reg_msg_t	*dring_msg = NULL;
	int			status = -1;

	ASSERT(msg.tag.vio_msgtype == VIO_TYPE_CTRL);
	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	/* Depending on which state we are in; process the message */
	switch (vdc->state) {
	case VD_STATE_INIT:
		if (msg.tag.vio_subtype_env != VIO_VER_INFO) {
			status = EPROTO;
			break;
		}

		switch (msg.tag.vio_subtype) {
		case VIO_SUBTYPE_ACK:
			vdc->state = VD_STATE_VER;
			status = vdc_init_attr_negotiation(vdc);
			break;
		case VIO_SUBTYPE_NACK:
			/*
			 * For now there is only one version number so we
			 * cannot step back to an earlier version but in the
			 * future we may need to add further logic here
			 * to try negotiating an earlier version as the VIO
			 * design allow for it.
			 */

			/*
			 * vds could not handle the version we sent so we just
			 * stop negotiating.
			 */
			status = EPROTO;
			break;

		case VIO_SUBTYPE_INFO:
			/*
			 * Handle the case where vds starts handshake
			 * (for now only vdc is the instigatior)
			 */
			status = ENOTSUP;
			break;

		default:
			status = ENOTSUP;
			break;
		}
		break;

	case VD_STATE_VER:
		if (msg.tag.vio_subtype_env != VIO_ATTR_INFO) {
			status = EPROTO;
			break;
		}

		switch (msg.tag.vio_subtype) {
		case VIO_SUBTYPE_ACK:
			/*
			 * We now verify the attributes sent by vds.
			 */
			attr_msg = (vd_attr_msg_t *)&msg;
			vdc->vdisk_size = attr_msg->vdisk_size;
			vdc->vdisk_type = attr_msg->vdisk_type;

			if ((attr_msg->max_xfer_sz != vdc->max_xfer_sz) ||
			    (attr_msg->vdisk_block_size != vdc->block_size)) {
				/*
				 * Future support: step down to the block size
				 * and max transfer size suggested by the
				 * server. (If this value is less than 128K
				 * then multiple Dring entries per request
				 * would need to be implemented)
				 */
				cmn_err(CE_NOTE, "[%d] Couldn't process block "
					"attrs from vds", vdc->instance);
				status = EINVAL;
				break;
			}

			if ((attr_msg->xfer_mode != VIO_DRING_MODE) ||
			    (attr_msg->vdisk_size > INT64_MAX) ||
			    (attr_msg->vdisk_type > VD_DISK_TYPE_DISK)) {
				vdc_msg("%s[%d] Couldn't process attrs "
				    "from vds", __func__, vdc->instance);
				status = EINVAL;
				break;
			}

			vdc->state = VD_STATE_ATTR;
			status = vdc_init_dring_negotiate(vdc);
			break;

		case VIO_SUBTYPE_NACK:
			/*
			 * vds could not handle the attributes we sent so we
			 * stop negotiating.
			 */
			status = EPROTO;
			break;

		case VIO_SUBTYPE_INFO:
			/*
			 * Handle the case where vds starts the handshake
			 * (for now; vdc is the only supported instigatior)
			 */
			status = ENOTSUP;
			break;

		default:
			status = ENOTSUP;
			break;
		}
		break;


	case VD_STATE_ATTR:
		if (msg.tag.vio_subtype_env != VIO_DRING_REG) {
			status = EPROTO;
			break;
		}

		switch (msg.tag.vio_subtype) {
		case VIO_SUBTYPE_ACK:
			/* Verify that we have sent all the descr. ring info */
			/* nop for now as we have just 1 dring */
			dring_msg = (vio_dring_reg_msg_t *)&msg;

			/* save the received dring_ident */
			vdc->dring_ident = dring_msg->dring_ident;
			PR0("%s[%d] Received dring ident=0x%lx\n",
				__func__, vdc->instance, vdc->dring_ident);

			/*
			 * Send an RDX message to vds to indicate we are ready
			 * to send data
			 */
			msg.tag.vio_msgtype = VIO_TYPE_CTRL;
			msg.tag.vio_subtype = VIO_SUBTYPE_INFO;
			msg.tag.vio_subtype_env = VIO_RDX;
			msg.tag.vio_sid = vdc->session_id;
			status = vdc_send(vdc->ldc_handle, (caddr_t)&msg,
					&msglen);
			if (status != 0) {
				cmn_err(CE_NOTE, "[%d] Failed to send RDX"
					" message (%d)", vdc->instance, status);
				break;
			}

			status = vdc_create_fake_geometry(vdc);
			if (status != 0) {
				cmn_err(CE_NOTE, "[%d] Failed to create disk "
					"geometery(%d)", vdc->instance, status);
				break;
			}

			vdc->state = VD_STATE_RDX;
			break;

		case VIO_SUBTYPE_NACK:
			/*
			 * vds could not handle the DRing info we sent so we
			 * stop negotiating.
			 */
			cmn_err(CE_CONT, "server could not register DRing\n");
			vdc_reset_connection(vdc, B_FALSE);
			vdc_destroy_descriptor_ring(vdc);
			status = EPROTO;
			break;

		case VIO_SUBTYPE_INFO:
			/*
			 * Handle the case where vds starts handshake
			 * (for now only vdc is the instigatior)
			 */
			status = ENOTSUP;
			break;
		default:
			status = ENOTSUP;
		}
		break;

	case VD_STATE_RDX:
		if (msg.tag.vio_subtype_env != VIO_RDX) {
			status = EPROTO;
			break;
		}

		PR0("%s: Received RDX - handshake successful\n", __func__);

		status = 0;
		vdc->state = VD_STATE_DATA;

		cv_broadcast(&vdc->attach_cv);
		break;

	default:
		cmn_err(CE_NOTE, "[%d] unknown handshake negotiation state %d",
				vdc->instance, vdc->state);
		break;
	}

	return (status);
}


/*
 * Function:
 *	vdc_process_data_msg()
 *
 * Description:
 *	This function is called by the message processing thread each time it
 *	a message with a msgtype of VIO_TYPE_DATA is received. It will either
 *	be an ACK or NACK from vds[1] which vdc handles as follows.
 *		ACK	- wake up the waiting thread
 *		NACK	- resend any messages necessary
 *
 *	[1] Although the message format allows it, vds should not send a
 *	    VIO_SUBTYPE_INFO message to vdc asking it to read data; if for
 *	    some bizarre reason it does, vdc will reset the connection.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	msg	- the LDC message sent by vds
 *
 * Return Code:
 *	0	- Success.
 *	> 0	- error value returned by LDC
 */
static int
vdc_process_data_msg(vdc_t *vdc, vio_msg_t msg)
{
	int			status = 0;
	vdc_local_desc_t	*local_dep = NULL;
	vio_dring_msg_t		*dring_msg = NULL;
	size_t			msglen = sizeof (*dring_msg);
	uint_t			num_msgs;
	uint_t			start;
	uint_t			end;
	uint_t			i;

	ASSERT(msg.tag.vio_msgtype == VIO_TYPE_DATA);
	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	dring_msg = (vio_dring_msg_t *)&msg;

	/*
	 * Check to see if the message has bogus data
	 */
	start = dring_msg->start_idx;
	end = dring_msg->end_idx;
	if ((start >= VD_DRING_LEN) || (end >= VD_DRING_LEN)) {
		vdc_msg("%s: Bogus ACK data : start %d, end %d\n",
			__func__, start, end);
		return (EPROTO);
	}

	/*
	 * calculate the number of messages that vds ACK'ed
	 *
	 * Assumes, (like the rest of vdc) that there is a 1:1 mapping
	 * between requests and Dring entries.
	 */
	num_msgs = (end >= start) ?
			(end - start + 1) :
			(VD_DRING_LEN - start + end + 1);

	/*
	 * Verify that the sequence number is what vdc expects.
	 */
	if (vdc_verify_seq_num(vdc, dring_msg, num_msgs) == B_FALSE) {
		return (ENXIO);
	}

	switch (msg.tag.vio_subtype) {
	case VIO_SUBTYPE_ACK:
		PR2("%s: DATA ACK\n", __func__);

		/*
		 * Wake the thread waiting for each DRing entry ACK'ed
		 */
		for (i = 0; i < num_msgs; i++) {
			int idx = (start + i) % VD_DRING_LEN;

			local_dep = &vdc->local_dring[idx];
			mutex_enter(&local_dep->lock);
			cv_signal(&local_dep->cv);
			mutex_exit(&local_dep->lock);
		}
		break;

	case VIO_SUBTYPE_NACK:
		PR0("%s: DATA NACK\n", __func__);
		dring_msg = (vio_dring_msg_t *)&msg;
		VDC_DUMP_DRING_MSG(dring_msg);

		/* Resend necessary messages */
		for (i = 0; i < num_msgs; i++) {
			int idx = (start + i) % VD_DRING_LEN;

			local_dep = &vdc->local_dring[idx];
			ASSERT(local_dep != NULL);
			mutex_enter(&local_dep->lock);

			if (local_dep->dep->hdr.dstate != VIO_DESC_READY) {
				PR0("%s[%d]: Won't resend entry %d [flag=%d]\n",
					__func__, vdc->instance, idx,
					local_dep->dep->hdr.dstate);
				mutex_exit(&local_dep->lock);
				break;
			}

			/* we'll reuse the message passed in */
			VIO_INIT_DRING_DATA_TAG(msg);
			dring_msg->tag.vio_sid = vdc->session_id;
			dring_msg->seq_num = ++(vdc->seq_num);
			VDC_DUMP_DRING_MSG(dring_msg);

			status = vdc_send(vdc->ldc_handle, (caddr_t)&dring_msg,
					&msglen);
			PR1("%s: ldc_write() status=%d\n", __func__, status);
			if (status != 0) {
				vdc_msg("%s ldc_write(%d)\n", __func__, status);
				mutex_exit(&local_dep->lock);
				break;
			}

			mutex_exit(&local_dep->lock);
		}
		break;

	case VIO_SUBTYPE_INFO:
	default:
		cmn_err(CE_NOTE, "[%d] Got an unexpected DATA msg [subtype %d]",
				vdc->instance, msg.tag.vio_subtype);
		break;
	}

	return (status);
}

/*
 * Function:
 *	vdc_process_err_msg()
 *
 * NOTE: No error messages are used as part of the vDisk protocol
 */
static int
vdc_process_err_msg(vdc_t *vdc, vio_msg_t msg)
{
	_NOTE(ARGUNUSED(vdc))
	_NOTE(ARGUNUSED(msg))

	int	status = ENOTSUP;

	ASSERT(msg.tag.vio_msgtype == VIO_TYPE_ERR);
	cmn_err(CE_NOTE, "[%d] Got an ERR msg", vdc->instance);

	return (status);
}

/*
 * Function:
 *	vdc_verify_seq_num()
 *
 * Description:
 *	This functions verifies that the sequence number sent back by vds with
 *	the latest message correctly follows the last request processed.
 *
 * Arguments:
 *	vdc		- soft state pointer for this instance of the driver.
 *	dring_msg	- pointer to the LDC message sent by vds
 *	num_msgs	- the number of requests being acknowledged
 *
 * Return Code:
 *	B_TRUE	- Success.
 *	B_FALSE	- The seq numbers are so out of sync, vdc cannot deal with them
 */
static boolean_t
vdc_verify_seq_num(vdc_t *vdc, vio_dring_msg_t *dring_msg, int num_msgs)
{
	ASSERT(vdc != NULL);
	ASSERT(dring_msg != NULL);

	/*
	 * Check to see if the messages were responded to in the correct
	 * order by vds. There are 3 possible scenarios:
	 *	- the seq_num we expected is returned (everything is OK)
	 *	- a seq_num earlier than the last one acknowledged is returned,
	 *	  if so something is seriously wrong so we reset the connection
	 *	- a seq_num greater than what we expected is returned.
	 */
	if (dring_msg->seq_num != (vdc->seq_num_reply + num_msgs)) {
		vdc_msg("%s[%d]: Bogus seq_num %d, expected %d\n",
			__func__, vdc->instance, dring_msg->seq_num,
			vdc->seq_num_reply + num_msgs);
		if (dring_msg->seq_num < (vdc->seq_num_reply + num_msgs)) {
			return (B_FALSE);
		} else {
			/*
			 * vds has responded with a seq_num greater than what we
			 * expected
			 */
			return (B_FALSE);
		}
	}
	vdc->seq_num_reply += num_msgs;

	return (B_TRUE);
}

/* -------------------------------------------------------------------------- */

/*
 * DKIO(7) support
 *
 * XXX FIXME - needs to be converted to use the structures defined in the
 * latest VIO spec to communicate with the vDisk server.
 */

typedef struct vdc_dk_arg {
	struct dk_callback	dkc;
	int			mode;
	dev_t			dev;
	vdc_t			*vdc;
} vdc_dk_arg_t;

/*
 * Function:
 * 	vdc_dkio_flush_cb()
 *
 * Description:
 *	This routine is a callback for DKIOCFLUSHWRITECACHE which can be called
 *	by kernel code.
 *
 * Arguments:
 *	arg	- a pointer to a vdc_dk_arg_t structure.
 */
void
vdc_dkio_flush_cb(void *arg)
{
	struct vdc_dk_arg	*dk_arg = (struct vdc_dk_arg *)arg;
	struct dk_callback	*dkc = NULL;
	vdc_t			*vdc = NULL;
	int			rv;

	if (dk_arg == NULL) {
		vdc_msg("%s[?] DKIOCFLUSHWRITECACHE arg is NULL\n", __func__);
		return;
	}
	dkc = &dk_arg->dkc;
	vdc = dk_arg->vdc;
	ASSERT(vdc != NULL);

	rv = vdc_populate_descriptor(vdc, NULL, 0, VD_OP_FLUSH,
		dk_arg->mode, SDPART(getminor(dk_arg->dev)));
	if (rv != 0) {
		PR0("%s[%d] DKIOCFLUSHWRITECACHE failed : model %x\n",
			__func__, vdc->instance,
			ddi_model_convert_from(dk_arg->mode & FMODELS));
		return;
	}

	/*
	 * Trigger the call back to notify the caller the the ioctl call has
	 * been completed.
	 */
	if ((dk_arg->mode & FKIOCTL) &&
	    (dkc != NULL) &&
	    (dkc->dkc_callback != NULL)) {
		ASSERT(dkc->dkc_cookie != NULL);
		(*dkc->dkc_callback)(dkc->dkc_cookie, ENOTSUP);
	}

	/* Indicate that one less DKIO write flush is outstanding */
	mutex_enter(&vdc->lock);
	vdc->dkio_flush_pending--;
	ASSERT(vdc->dkio_flush_pending >= 0);
	mutex_exit(&vdc->lock);
}


/*
 * This structure is used in the DKIO(7I) array below.
 */
typedef struct vdc_dk_ioctl {
	uint8_t		op;		/* VD_OP_XXX value */
	int		cmd;		/* Solaris ioctl operation number */
	uint8_t		copy;		/* copyin and/or copyout needed ? */
	size_t		nbytes;		/* size of structure to be copied */
	size_t		nbytes32;	/* size of 32bit struct if different */
					/*   to 64bit struct (zero otherwise) */
} vdc_dk_ioctl_t;

/*
 * Subset of DKIO(7I) operations currently supported
 */
static vdc_dk_ioctl_t	dk_ioctl[] = {
	{VD_OP_FLUSH, DKIOCFLUSHWRITECACHE, 0,
		0, 0},
	{VD_OP_GET_WCE, DKIOCGETWCE, 0,
		0, 0},
	{VD_OP_SET_WCE, DKIOCSETWCE, 0,
		0, 0},
	{VD_OP_GET_VTOC, DKIOCGVTOC, VD_COPYOUT,
		sizeof (struct vtoc), sizeof (struct vtoc32)},
	{VD_OP_SET_VTOC, DKIOCSVTOC, VD_COPYIN,
		sizeof (struct vtoc), sizeof (struct vtoc32)},
	{VD_OP_SET_DISKGEOM, DKIOCSGEOM, VD_COPYIN,
		sizeof (struct dk_geom), 0},
	{VD_OP_GET_DISKGEOM, DKIOCGGEOM, VD_COPYOUT,
		sizeof (struct dk_geom), 0},
	{VD_OP_GET_DISKGEOM, DKIOCG_PHYGEOM, VD_COPYOUT,
		sizeof (struct dk_geom), 0},
	{VD_OP_GET_DISKGEOM, DKIOCG_VIRTGEOM, VD_COPYOUT,
		sizeof (struct dk_geom), 0},
	{VD_OP_SET_DISKGEOM, DKIOCSGEOM, VD_COPYOUT,
		sizeof (struct dk_geom), 0},
	{VD_OP_SCSICMD, USCSICMD, VD_COPYIN|VD_COPYOUT,
		sizeof (struct uscsi_cmd), sizeof (struct uscsi_cmd32)},
	{0, DKIOCINFO, VD_COPYOUT,
		sizeof (struct dk_cinfo), 0},
	{0, DKIOCGMEDIAINFO, VD_COPYOUT,
		sizeof (struct dk_minfo), 0},
	{0, DKIOCREMOVABLE, 0,
		0, 0},
	{0, CDROMREADOFFSET, 0,
		0, 0}
};

/*
 * Function:
 *	vd_process_ioctl()
 *
 * Description:
 *	This routine is the driver entry point for handling user
 *	requests to get the device geometry.
 *
 * Arguments:
 *	dev	- the device number
 *	cmd	- the operation [dkio(7I)] to be processed
 *	arg	- pointer to user provided structure
 *		  (contains data to be set or reference parameter for get)
 *	mode	- bit flag, indicating open settings, 32/64 bit type, etc
 *	rvalp	- calling process return value, used in some ioctl calls
 *		  (passed throught to vds who fills in the value)
 *
 * Assumptions:
 *	vds will make the ioctl calls in the 64 bit address space so vdc
 *	will convert the data to/from 32 bit as necessary before doing
 *	the copyin or copyout.
 *
 * Return Code:
 *	0
 *	EFAULT
 *	ENXIO
 *	EIO
 *	ENOTSUP
 */
static int
vd_process_ioctl(dev_t dev, int cmd, caddr_t arg, int mode)
{
	int		instance = SDUNIT(getminor(dev));
	vdc_t		*vdc = NULL;
	int		op = -1;		/* VD_OP_XXX value */
	int		rv = -1;
	int		idx = 0;		/* index into dk_ioctl[] */
	size_t		len = 0;		/* #bytes to send to vds */
	size_t		alloc_len = 0;		/* #bytes to allocate mem for */
	size_t		copy_len = 0;		/* #bytes to copy in/out */
	caddr_t		mem_p = NULL;
	boolean_t	do_convert_32to64 = B_FALSE;
	size_t		nioctls = (sizeof (dk_ioctl)) / (sizeof (dk_ioctl[0]));

	PR0("%s: Processing ioctl(%x) for dev %x : model %x\n",
		__func__, cmd, dev, ddi_model_convert_from(mode & FMODELS));

	vdc = ddi_get_soft_state(vdc_state, instance);
	if (vdc == NULL) {
		cmn_err(CE_NOTE, "![%d] Could not get soft state structure",
		    instance);
		return (ENXIO);
	}

	/*
	 * Check to see if we can communicate with the vDisk server
	 */
	rv = vdc_is_able_to_tx_data(vdc, O_NONBLOCK);
	if (rv == B_FALSE) {
		PR0("%s[%d] Not ready to transmit data\n", __func__, instance);
		return (ENOLINK);
	}

	/*
	 * Validate the ioctl operation to be performed.
	 *
	 * If we have looped through the array without finding a match then we
	 * don't support this ioctl.
	 */
	for (idx = 0; idx < nioctls; idx++) {
		if (cmd == dk_ioctl[idx].cmd)
			break;
	}

	if (idx >= nioctls) {
		PR0("%s[%d] Unsupported ioctl(%x)\n",
				__func__, vdc->instance, cmd);
		return (ENOTSUP);
	}

	copy_len = len = dk_ioctl[idx].nbytes;
	op = dk_ioctl[idx].op;

	/*
	 * Some ioctl operations have different sized structures for 32 bit
	 * and 64 bit. If the userland caller is 32 bit, we need to check
	 * to see if the operation is one of those special cases and
	 * flag that we need to convert to and/or from 32 bit since vds
	 * will make the call as 64 bit.
	 */
	if ((ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) &&
	    (dk_ioctl[idx].nbytes != 0) &&
	    (dk_ioctl[idx].nbytes32 != 0)) {
		do_convert_32to64 = B_TRUE;
		copy_len = dk_ioctl[idx].nbytes32;
	}

	/*
	 * Deal with the ioctls which the server does not provide.
	 */
	switch (cmd) {
	case CDROMREADOFFSET:
	case DKIOCREMOVABLE:
		return (ENOTTY);

	case DKIOCINFO:
		{
			struct dk_cinfo	cinfo;
			if (vdc->cinfo == NULL)
				return (ENXIO);

			bcopy(vdc->cinfo, &cinfo, sizeof (struct dk_cinfo));
			cinfo.dki_partition = SDPART(getminor(dev));

			rv = ddi_copyout(&cinfo, (void *)arg,
					sizeof (struct dk_cinfo), mode);
			if (rv != 0)
				return (EFAULT);

			return (0);
		}

	case DKIOCGMEDIAINFO:
		if (vdc->minfo == NULL)
			return (ENXIO);

		rv = ddi_copyout(vdc->minfo, (void *)arg,
				sizeof (struct dk_minfo), mode);
		if (rv != 0)
			return (EFAULT);

		return (0);
	}

	/* catch programming error in vdc - should be a VD_OP_XXX ioctl */
	ASSERT(op != 0);

	/* LDC requires that the memory being mapped is 8-byte aligned */
	alloc_len = P2ROUNDUP(len, sizeof (uint64_t));
	PR1("%s[%d]: struct size %d alloc %d\n",
			__func__, instance, len, alloc_len);

	if (alloc_len != 0)
		mem_p = kmem_zalloc(alloc_len, KM_SLEEP);

	if (dk_ioctl[idx].copy & VD_COPYIN) {
		if (arg == NULL) {
			if (mem_p != NULL)
				kmem_free(mem_p, alloc_len);
			return (EINVAL);
		}

		ASSERT(copy_len != 0);

		rv = ddi_copyin((void *)arg, mem_p, copy_len, mode);
		if (rv != 0) {
			if (mem_p != NULL)
				kmem_free(mem_p, alloc_len);
			return (EFAULT);
		}

		/*
		 * some operations need the data to be converted from 32 bit
		 * to 64 bit structures so that vds can process them on the
		 * other side.
		 */
		if (do_convert_32to64) {
			switch (cmd) {
			case DKIOCSVTOC:
			{
				struct vtoc	vt;
				struct vtoc32	vt32;

				ASSERT(mem_p != NULL);
				vt32 = *((struct vtoc32 *)(mem_p));

				vtoc32tovtoc(vt32, vt);
				bcopy(&vt, mem_p, len);
				break;
			}

			case USCSICMD:
			{
				struct uscsi_cmd	scmd;
				struct uscsi_cmd	*uscmd = &scmd;
				struct uscsi_cmd32	*uscmd32;

				ASSERT(mem_p != NULL);
				uscmd32 = (struct uscsi_cmd32 *)mem_p;

				/*
				 * Convert the ILP32 uscsi data from the
				 * application to LP64 for internal use.
				 */
				uscsi_cmd32touscsi_cmd(uscmd32, uscmd);
				bcopy(uscmd, mem_p, len);
				break;
			}
			default:
				break;
			}
		}
	}

	/*
	 * handle the special case of DKIOCFLUSHWRITECACHE
	 */
	if (cmd == DKIOCFLUSHWRITECACHE) {
		struct dk_callback *dkc = (struct dk_callback *)arg;

		PR0("%s[%d]: DKIOCFLUSHWRITECACHE\n", __func__, instance);

		/* no mem should have been allocated hence no need to free it */
		ASSERT(mem_p == NULL);

		/*
		 * If arg is NULL, we break here and the call operates
		 * synchronously; waiting for vds to return.
		 *
		 * i.e. after the request to vds returns successfully,
		 * all writes completed prior to the ioctl will have been
		 * flushed from the disk write cache to persistent media.
		 */
		if (dkc != NULL) {
			vdc_dk_arg_t	arg;
			arg.mode = mode;
			arg.dev = dev;
			bcopy(dkc, &arg.dkc, sizeof (*dkc));

			mutex_enter(&vdc->lock);
			vdc->dkio_flush_pending++;
			arg.vdc = vdc;
			mutex_exit(&vdc->lock);

			/* put the request on a task queue */
			rv = taskq_dispatch(system_taskq, vdc_dkio_flush_cb,
				(void *)&arg, DDI_SLEEP);

			return (rv == NULL ? ENOMEM : 0);
		}
	}

	/*
	 * send request to vds to service the ioctl.
	 */
	rv = vdc_populate_descriptor(vdc, mem_p, alloc_len, op, mode,
			SDPART((getminor(dev))));
	if (rv != 0) {
		/*
		 * This is not necessarily an error. The ioctl could
		 * be returning a value such as ENOTTY to indicate
		 * that the ioctl is not applicable.
		 */
		PR0("%s[%d]: vds returned %d for ioctl 0x%x\n",
			__func__, instance, rv, cmd);
		if (mem_p != NULL)
			kmem_free(mem_p, alloc_len);
		return (rv);
	}

	/*
	 * If the VTOC has been changed, then vdc needs to update the copy
	 * it saved in the soft state structure and try and update the device
	 * node properties. Failing to set the properties should not cause
	 * an error to be return the caller though.
	 */
	if (cmd == DKIOCSVTOC) {
		bcopy(mem_p, vdc->vtoc, sizeof (struct vtoc));
		if (vdc_create_device_nodes_props(vdc)) {
			cmn_err(CE_NOTE, "![%d] Failed to update device nodes"
				" properties", instance);
		}
	}

	/*
	 * if we don't have to do a copyout, we have nothing left to do
	 * so we just return.
	 */
	if ((dk_ioctl[idx].copy & VD_COPYOUT) == 0) {
		if (mem_p != NULL)
			kmem_free(mem_p, alloc_len);
		return (0);
	}

	/* sanity check */
	if (mem_p == NULL)
		return (EFAULT);


	/*
	 * some operations need the data to be converted from 64 bit
	 * back to 32 bit structures after vds has processed them.
	 */
	if (do_convert_32to64) {
		switch (cmd) {
		case DKIOCGVTOC:
		{
			struct vtoc	vt;
			struct vtoc32	vt32;

			ASSERT(mem_p != NULL);
			vt = *((struct vtoc *)(mem_p));

			vtoctovtoc32(vt, vt32);
			bcopy(&vt32, mem_p, copy_len);
			break;
		}

		case USCSICMD:
		{
			struct uscsi_cmd32	*uc32;
			struct uscsi_cmd	*uc;

			len = sizeof (struct uscsi_cmd32);

			ASSERT(mem_p != NULL);
			uc = (struct uscsi_cmd *)mem_p;
			uc32 = kmem_zalloc(len, KM_SLEEP);

			uscsi_cmdtouscsi_cmd32(uc, uc32);
			bcopy(uc32, mem_p, copy_len);
			PR0("%s[%d]: uscsi_cmd32:%x\n", __func__, instance,
				((struct uscsi_cmd32 *)mem_p)->uscsi_cdblen);
			kmem_free(uc32, len);
			break;
		}
		default:
			PR1("%s[%d]: This mode (%x) should just work for(%x)\n",
				__func__, instance, mode, cmd);
			break;
		}
	}

	ASSERT(len != 0);
	ASSERT(mem_p != NULL);

	rv = ddi_copyout(mem_p, (void *)arg, copy_len, mode);
	if (rv != 0) {
		vdc_msg("%s[%d]: Could not do copy out for ioctl (%x)\n",
			__func__, instance, cmd);
		rv = EFAULT;
	}

	if (mem_p != NULL)
		kmem_free(mem_p, alloc_len);

	return (rv);
}

/*
 * Function:
 *	vdc_create_fake_geometry()
 *
 * Description:
 *	This routine fakes up the disk info needed for some DKIO ioctls.
 *		- DKIOCINFO
 *		- DKIOCGMEDIAINFO
 *
 *	[ just like lofi(7D) and ramdisk(7D) ]
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_create_fake_geometry(vdc_t *vdc)
{
	ASSERT(vdc != NULL);

	/*
	 * DKIOCINFO support
	 */
	vdc->cinfo = kmem_zalloc(sizeof (struct dk_cinfo), KM_SLEEP);

	(void) strcpy(vdc->cinfo->dki_cname, VDC_DRIVER_NAME);
	(void) strcpy(vdc->cinfo->dki_dname, VDC_DRIVER_NAME);
	vdc->cinfo->dki_maxtransfer = vdc->max_xfer_sz / vdc->block_size;
	vdc->cinfo->dki_ctype = DKC_SCSI_CCS;
	vdc->cinfo->dki_flags = DKI_FMTVOL;
	vdc->cinfo->dki_cnum = 0;
	vdc->cinfo->dki_addr = 0;
	vdc->cinfo->dki_space = 0;
	vdc->cinfo->dki_prio = 0;
	vdc->cinfo->dki_vec = 0;
	vdc->cinfo->dki_unit = vdc->instance;
	vdc->cinfo->dki_slave = 0;
	/*
	 * The partition number will be created on the fly depending on the
	 * actual slice (i.e. minor node) that is used to request the data.
	 */
	vdc->cinfo->dki_partition = 0;

	/*
	 * DKIOCGMEDIAINFO support
	 */
	vdc->minfo = kmem_zalloc(sizeof (struct dk_minfo), KM_SLEEP);
	vdc->minfo->dki_media_type = DK_FIXED_DISK;
	vdc->minfo->dki_capacity = 1;
	vdc->minfo->dki_lbsize = DEV_BSIZE;

	return (0);
}
