/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2017 Joyent, Inc.
 */

/*
 * Part of Intel(R) Manageability Engine Interface Linux driver
 *
 * Copyright (c) 2003 - 2008 Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 */

#include <sys/types.h>
#include <sys/note.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/devops.h>
#include <sys/instance.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/priv.h>
#include <sys/systm.h>
#include <sys/mkdev.h>
#include <sys/list.h>
#include <sys/pci.h>
#include "heci_data_structures.h"

#include "heci.h"
#include "heci_interface.h"

#define	MAJOR_VERSION	5
#define	MINOR_VERSION	0
#define	QUICK_FIX_NUMBER	0
#define	VER_BUILD	30

#define	str(s)	name(s)
#define	name(s)	#s
#define	HECI_DRIVER_VERSION	str(MAJOR_VERSION) "." str(MINOR_VERSION) \
	"." str(QUICK_FIX_NUMBER) "." str(VER_BUILD)

#define	HECI_READ_TIMEOUT	45

#define	HECI_DRIVER_NAME	"heci"

/*
 *  heci driver strings
 */
char heci_driver_name[] = HECI_DRIVER_NAME;
char heci_driver_string[] = "Intel(R) Management Engine Interface";
char heci_driver_version[] = HECI_DRIVER_VERSION;
char heci_copyright[] = "Copyright (c) 2003 - 2008 Intel Corporation.";

void * heci_soft_state_p = NULL;

#ifdef DEBUG
int heci_debug = 0;
#endif

/*
 * Local Function Prototypes
 */
static int heci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int heci_initialize(dev_info_t *dip, struct iamt_heci_device *device);
static int heci_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
	void *arg, void **result);
static int heci_detach(dev_info_t *dip,  ddi_detach_cmd_t cmd);
static int heci_quiesce(dev_info_t *dip);
static int heci_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int heci_close(dev_t dev, int flag, int otyp, struct cred *cred);
static int heci_read(dev_t dev, struct uio *uio_p, cred_t *cred_p);
static int heci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *cr, int *rval);
static int heci_write(dev_t dev, struct uio *uio_p, struct cred *cred);
static int heci_poll(dev_t dev, short events, int anyyet,
		short *reventsp, struct pollhead **phpp);
static struct heci_cb_private *find_read_list_entry(
		struct iamt_heci_device *dev,
		struct heci_file_private *file_ext);
static inline int heci_fe_same_id(struct heci_file_private *fe1,
		struct heci_file_private *fe2);

static void heci_resume(dev_info_t *dip);
static int heci_suspend(dev_info_t *dip);
static uint16_t g_sus_wd_timeout;

static struct cb_ops heci_cb_ops = {
	heci_open,		/* open */
	heci_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	heci_read,		/* read */
	heci_write,		/* write */
	heci_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	heci_poll,		/* poll */
	ddi_prop_op,		/* cb_prop op */
	NULL,			/* stream tab */
	D_MP		/* Driver Compatability Flags */
};

static struct dev_ops heci_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	heci_getinfo,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	heci_attach,		/* attach */
	heci_detach,		/* detach */
	nodev,			/* reset */
	&heci_cb_ops,		/* Driver Ops */
	(struct bus_ops *)NULL,	/* Bus Operations */
	NULL,			/* power */
	heci_quiesce		/* devo_quiesce */
};

/*
 * Module linkage information for the kernel
 */

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of Module = Driver */
	heci_driver_string, 	/* Driver Identifier string. */
	&heci_dev_ops,		/* Driver Ops. */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * Module Initialization functions.
 */

int
_init(void)
{
	int stat;

	/* Allocate soft state */
	if ((stat = ddi_soft_state_init(&heci_soft_state_p,
		sizeof (struct iamt_heci_device), 1)) != DDI_SUCCESS) {
	    return (stat);
	}

	if ((stat = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&heci_soft_state_p);

	return (stat);
}

int
_info(struct modinfo *infop)
{

	return (mod_info(&modlinkage, infop));
}

int
_fini(void)
{
	int stat;

	if ((stat = mod_remove(&modlinkage)) != 0)
		return (stat);

	ddi_soft_state_fini(&heci_soft_state_p);

	return (stat);
}

/*
 * heci_attach - Driver Attach Routine
 */
static int
heci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance, status;
	struct iamt_heci_device *device;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		heci_resume(dip);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	DBG("%s - version %s\n", heci_driver_string, heci_driver_version);
	DBG("%s\n", heci_copyright);

	instance = ddi_get_instance(dip);	/* find out which unit */
	status = ddi_soft_state_zalloc(heci_soft_state_p, instance);
	if (status != DDI_SUCCESS)
		return (DDI_FAILURE);
	device = ddi_get_soft_state(heci_soft_state_p, instance);
	ASSERT(device != NULL);	/* can't fail - we only just allocated it */

	device->dip = dip;

	status = heci_initialize(dip, device);
	if (status != DDI_SUCCESS) {
		ddi_soft_state_free(heci_soft_state_p, instance);
		return (DDI_FAILURE);
	}

	status = ddi_create_minor_node(dip, "AMT", S_IFCHR,
	    MAKE_MINOR_NUM(HECI_MINOR_NUMBER, instance),
	    DDI_PSEUDO, 0);

	if (status != DDI_SUCCESS) {

		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(heci_soft_state_p, instance);
		return (DDI_FAILURE);
	}


	return (status);
}

/*
 * heci_probe - Device Initialization Routine
 */
static int
heci_initialize(dev_info_t *dip, struct iamt_heci_device *device)
{
	int err;
	ddi_device_acc_attr_t attr;

	err = ddi_get_iblock_cookie(dip, 0, &device->sc_iblk);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "heci_probe():"
		    " ddi_get_iblock_cookie() failed\n");
		goto end;
	}
	/* initializes the heci device structure */
	init_heci_device(dip, device);

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&device->mem_addr, 0, 0,
	    &attr, &device->io_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "heci%d: unable to map PCI regs\n",
		    ddi_get_instance(dip));
		goto fini_heci_device;
	}

	err = ddi_add_intr(dip, 0, &device->sc_iblk, NULL,
	    heci_isr_interrupt, (caddr_t)device);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "heci_probe(): ddi_add_intr() failed\n");
		goto unmap_memory;
	}

	if (heci_hw_init(device)) {
		cmn_err(CE_WARN, "init hw failure.\n");
		err = -ENODEV;
		goto release_irq;
	}
	(void) heci_initialize_clients(device);
	if (device->heci_state != HECI_ENABLED) {
		err = -ENODEV;
		goto release_hw;
	}
	if (device->wd_timeout)
		device->wd_timer = timeout(heci_wd_timer, device, 1);

	DBG("heci driver initialization successful.\n");
	return (0);

release_hw:
	/* disable interrupts */
	device->host_hw_state = read_heci_register(device, H_CSR);
	heci_csr_disable_interrupts(device);

release_irq:
	ddi_remove_intr(dip, 0, device->sc_iblk);
unmap_memory:
	if (device->mem_addr)
		ddi_regs_map_free(&device->io_handle);
fini_heci_device:
	fini_heci_device(device);
end:
	cmn_err(CE_WARN, "heci driver initialization failed.\n");
	return (err);
}

void
heci_destroy_locks(struct iamt_heci_device *device_object)
{

	mutex_destroy(&device_object->iamthif_file_ext.file_lock);
	mutex_destroy(&device_object->iamthif_file_ext.read_io_lock);
	mutex_destroy(&device_object->iamthif_file_ext.write_io_lock);

	mutex_destroy(&device_object->wd_file_ext.file_lock);
	mutex_destroy(&device_object->wd_file_ext.read_io_lock);
	mutex_destroy(&device_object->wd_file_ext.write_io_lock);
	mutex_destroy(&device_object->device_lock);

	cv_destroy(&device_object->iamthif_file_ext.rx_wait);
	cv_destroy(&device_object->wd_file_ext.rx_wait);
	cv_destroy(&device_object->wait_recvd_msg);
	cv_destroy(&device_object->wait_stop_wd);
}

/*
 * heci_remove - Device Removal Routine
 *
 * @pdev: PCI device information struct
 *
 * heci_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.
 */
static int
heci_detach(dev_info_t *dip,  ddi_detach_cmd_t cmd)
{
	struct iamt_heci_device	*dev;
	int err;

	dev = ddi_get_soft_state(heci_soft_state_p, ddi_get_instance(dip));
	ASSERT(dev != NULL);

	switch (cmd) {
	case DDI_SUSPEND:
		err = heci_suspend(dip);
		if (err)
			return (DDI_FAILURE);
		else
			return (DDI_SUCCESS);

	case DDI_DETACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	if (dev->wd_timer)
		(void) untimeout(dev->wd_timer);

	mutex_enter(&dev->device_lock);
	if (dev->wd_file_ext.state == HECI_FILE_CONNECTED &&
	    dev->wd_timeout) {
		dev->wd_timeout = 0;
		dev->wd_due_counter = 0;
		(void) memcpy(dev->wd_data, stop_wd_params,
		    HECI_WD_PARAMS_SIZE);
		dev->stop = 1;
		if (dev->host_buffer_is_empty &&
		    flow_ctrl_creds(dev, &dev->wd_file_ext)) {
			dev->host_buffer_is_empty = 0;

			if (!heci_send_wd(dev)) {
				DBG("send stop WD failed\n");
			} else
				flow_ctrl_reduce(dev, &dev->wd_file_ext);

			dev->wd_pending = 0;
		} else
			dev->wd_pending = 1;

		dev->wd_stoped = 0;

		err = 0;
		while (!dev->wd_stoped && err != -1) {
			err = cv_reltimedwait(&dev->wait_stop_wd,
			    &dev->device_lock, 10*HZ, TR_CLOCK_TICK);
		}

		if (!dev->wd_stoped) {
			DBG("stop wd failed to complete.\n");
		} else {
			DBG("stop wd complete.\n");
		}

	}

	mutex_exit(&dev->device_lock);

	if (dev->iamthif_file_ext.state == HECI_FILE_CONNECTED) {
		dev->iamthif_file_ext.state = HECI_FILE_DISCONNECTING;
		(void) heci_disconnect_host_client(dev,
		    &dev->iamthif_file_ext);
	}
	if (dev->wd_file_ext.state == HECI_FILE_CONNECTED) {
		dev->wd_file_ext.state = HECI_FILE_DISCONNECTING;
		(void) heci_disconnect_host_client(dev,
		    &dev->wd_file_ext);
	}


	/* remove entry if already in list */
	DBG("list del iamthif and wd file list.\n");
	heci_remove_client_from_file_list(dev, dev->wd_file_ext.
	    host_client_id);
	heci_remove_client_from_file_list(dev,
	    dev->iamthif_file_ext.host_client_id);

	dev->iamthif_current_cb = NULL;
	dev->iamthif_file_ext.file = NULL;

	/* disable interrupts */
	heci_csr_disable_interrupts(dev);

	ddi_remove_intr(dip, 0, dev->sc_iblk);

	if (dev->work)
		ddi_taskq_destroy(dev->work);
	if (dev->reinit_tsk)
		ddi_taskq_destroy(dev->reinit_tsk);
	if (dev->mem_addr)
		ddi_regs_map_free(&dev->io_handle);

	if (dev->me_clients && dev->num_heci_me_clients > 0) {
		kmem_free(dev->me_clients, sizeof (struct heci_me_client) *
		    dev->num_heci_me_clients);
	}

	dev->num_heci_me_clients = 0;

	heci_destroy_locks(dev);

	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(heci_soft_state_p, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}


static int
heci_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error = DDI_SUCCESS;
	struct iamt_heci_device *device;
	int minor, instance;

	_NOTE(ARGUNUSED(dip))

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		minor = getminor((dev_t)arg);
		instance = HECI_MINOR_TO_INSTANCE(minor);
		if (!(device = ddi_get_soft_state(heci_soft_state_p, instance)))
			*result = NULL;
		else
			*result = device->dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		minor = getminor((dev_t)arg);
		instance = HECI_MINOR_TO_INSTANCE(minor);
		*result = (void *)((long)minor);
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}
/*
 * heci_clear_list - remove all callbacks associated with file
 * 		from heci_cb_list
 *
 * @file: file information struct
 * @heci_cb_list: callbacks list
 *
 * heci_clear_list is called to clear resources associated with file
 * when application calls close function or Ctrl-C was pressed
 *
 * @return 1 if callback removed from the list, 0 otherwise
 */
static int
heci_clear_list(struct iamt_heci_device *dev, struct heci_file *file,
    struct list_node *heci_cb_list)
{
	struct heci_cb_private *priv_cb_pos = NULL;
	struct heci_cb_private *priv_cb_next = NULL;
	struct heci_file *file_temp;
	int rets = 0;

	/* list all list member */
	list_for_each_entry_safe(priv_cb_pos, priv_cb_next,
	    heci_cb_list, cb_list, struct heci_cb_private) {
		file_temp = (struct heci_file *)priv_cb_pos->file_object;
		/* check if list member associated with a file */
		if (file_temp == file) {
			/* remove member from the list */
			list_del(&priv_cb_pos->cb_list);
			/* check if cb equal to current iamthif cb */
			if (dev->iamthif_current_cb == priv_cb_pos) {
				dev->iamthif_current_cb = NULL;
				/* send flow control to iamthif client */
				if (!heci_send_flow_control(dev,
				    &dev->iamthif_file_ext)) {
				    DBG("sending flow control failed\n");
				}
			}
			/* free all allocated buffers */
			heci_free_cb_private(priv_cb_pos);
			rets = 1;
		}
	}
	return (rets);
}

/*
 * heci_clear_lists - remove all callbacks associated with file
 *
 * @dev: device information struct
 * @file: file information struct
 *
 * heci_clear_lists is called to clear resources associated with file
 * when application calls close function or Ctrl-C was pressed
 *
 * @return 1 if callback removed from the list, 0 otherwise
 */
static int
heci_clear_lists(struct iamt_heci_device *dev, struct heci_file *file)
{
	int rets = 0;

	/* remove callbacks associated with a file */
	(void) heci_clear_list(dev, file, &dev->pthi_cmd_list.heci_cb.cb_list);
	if (heci_clear_list(dev, file,
	    &dev->pthi_read_complete_list.heci_cb.cb_list))
		rets = 1;

	(void) heci_clear_list(dev, file, &dev->ctrl_rd_list.heci_cb.cb_list);

	if (heci_clear_list(dev, file, &dev->ctrl_wr_list.heci_cb.cb_list))
		rets = 1;

	if (heci_clear_list(dev, file,
	    &dev->write_waiting_list.heci_cb.cb_list))
		rets = 1;

	if (heci_clear_list(dev, file, &dev->write_list.heci_cb.cb_list))
		rets = 1;

	/* check if iamthif_current_cb not NULL */
	if (dev->iamthif_current_cb && (!rets)) {
		/* check file and iamthif current cb association */
		if (dev->iamthif_current_cb->file_object == file) {
			/* remove cb */
			heci_free_cb_private(dev->iamthif_current_cb);
			dev->iamthif_current_cb = NULL;
			rets = 1;
		}
	}
	return (rets);
}

/*
 * heci_open - the open function
 */
static int
heci_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	struct iamt_heci_device *dev;
	struct heci_file_private *file_ext = NULL;
	int minor, if_num, instance;
	struct heci_file *file;

	_NOTE(ARGUNUSED(flags, credp))

	minor = getminor(*devp);

	DBG("heci_open: enter...\n");

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = HECI_MINOR_TO_INSTANCE(minor);
	if_num = HECI_MINOR_TO_IFNUM(minor);

	dev = ddi_get_soft_state(heci_soft_state_p, instance);

	if ((if_num < HECI_MINOR_NUMBER) || (!dev))
		return (-ENODEV);

	file_ext = heci_alloc_file_private(NULL);
	if (file_ext == NULL)
		return (-ENOMEM);

	mutex_enter(&dev->device_lock);
	if (dev->heci_state != HECI_ENABLED) {
		mutex_exit(&dev->device_lock);
		kmem_free(file_ext, sizeof (struct heci_file_private));
		file_ext = NULL;
		return (-ENODEV);
	}
	if (dev->open_handle_count >= HECI_MAX_OPEN_HANDLE_COUNT) {
		mutex_exit(&dev->device_lock);
		kmem_free(file_ext, sizeof (struct heci_file_private));
		file_ext = NULL;
		return (-ENFILE);
	}
	dev->open_handle_count++;
	list_add_tail(&file_ext->link, &dev->file_list);
	while ((dev->heci_host_clients[dev->current_host_client_id / 8]
	    & (1 << (dev->current_host_client_id % 8))) != 0) {

		dev->current_host_client_id++;
		dev->current_host_client_id %= HECI_MAX_OPEN_HANDLE_COUNT;
		DBG("current_host_client_id = %d\n",
		    dev->current_host_client_id);
		DBG("dev->open_handle_count = %lu\n",
		    dev->open_handle_count);
	}
	DBG("current_host_client_id = %d\n", dev->current_host_client_id);
	file_ext->host_client_id = dev->current_host_client_id;
	*devp = makedevice(getmajor(*devp),
	    MAKE_MINOR_NUM(dev->current_host_client_id, instance));
	file = &dev->files[dev->current_host_client_id];
	dev->heci_host_clients[file_ext->host_client_id / 8] |=
	    (1 << (file_ext->host_client_id % 8));
	mutex_exit(&dev->device_lock);
	mutex_enter(&file_ext->file_lock);
	file_ext->state = HECI_FILE_INITIALIZING;
	file_ext->sm_state = 0;

	file->private_data = file_ext;
	mutex_exit(&file_ext->file_lock);

	return (0);
}

/*
 * heci_close - the close function
 */
static int
heci_close(dev_t devt, int flag, int otyp, struct cred *cred)
{
	int rets = 0;
	int minor, if_num, instance;
	struct heci_file_private *file_ext;
	struct heci_cb_private *priv_cb = NULL;
	struct iamt_heci_device *dev;
	struct heci_file *file;

	_NOTE(ARGUNUSED(flag, otyp, cred))

	minor = getminor(devt);

	instance = HECI_MINOR_TO_INSTANCE(minor);
	if_num = HECI_MINOR_TO_IFNUM(minor);

	dev = ddi_get_soft_state(heci_soft_state_p, instance);

	file = &dev->files[if_num];
	file_ext = file->private_data;

	if ((if_num < HECI_MINOR_NUMBER) || (!dev) || (!file_ext))
		return (-ENODEV);

	if (file_ext != &dev->iamthif_file_ext) {
		mutex_enter(&file_ext->file_lock);
		if (file_ext->state == HECI_FILE_CONNECTED) {
			file_ext->state = HECI_FILE_DISCONNECTING;
			mutex_exit(&file_ext->file_lock);
			DBG("disconnecting client host client = %d, "
			    "ME client = %d\n",
			    file_ext->host_client_id,
			    file_ext->me_client_id);
			rets = heci_disconnect_host_client(dev, file_ext);
			mutex_enter(&file_ext->file_lock);
		}
		mutex_enter(&dev->device_lock);
		heci_flush_queues(dev, file_ext);
		DBG("remove client host client = %d, ME client = %d\n",
		    file_ext->host_client_id,
		    file_ext->me_client_id);

		if (dev->open_handle_count > 0) {
			dev->heci_host_clients[file_ext->host_client_id / 8] &=
			    ~(1 << (file_ext->host_client_id % 8));
			dev->open_handle_count--;
		}
		heci_remove_client_from_file_list(dev,
		    file_ext->host_client_id);

		/* free read cb */
		if (file_ext->read_cb != NULL) {
			priv_cb = find_read_list_entry(dev, file_ext);
			/* Remove entry from read list */
			if (priv_cb != NULL)
				list_del(&priv_cb->cb_list);

			priv_cb = file_ext->read_cb;
			file_ext->read_cb = NULL;
		}

		mutex_exit(&dev->device_lock);
		file->private_data = NULL;
		mutex_exit(&file_ext->file_lock);

		if (priv_cb != NULL)
			heci_free_cb_private(priv_cb);

		heci_free_file_private(file_ext);
	} else {
		mutex_enter(&dev->device_lock);

		if (dev->open_handle_count > 0)
			dev->open_handle_count--;

		if (dev->iamthif_file_object == file &&
		    dev->iamthif_state != HECI_IAMTHIF_IDLE) {
			DBG("pthi canceled iamthif state %d\n",
			    dev->iamthif_state);
			dev->iamthif_canceled = 1;
			if (dev->iamthif_state == HECI_IAMTHIF_READ_COMPLETE) {
				DBG("run next pthi iamthif cb\n");
				run_next_iamthif_cmd(dev);
			}
		}

		if (heci_clear_lists(dev, file))
			dev->iamthif_state = HECI_IAMTHIF_IDLE;

		mutex_exit(&dev->device_lock);
	}
	return (rets);
}

static struct heci_cb_private *
find_read_list_entry(struct iamt_heci_device *dev,
    struct heci_file_private *file_ext)
{
	struct heci_cb_private *priv_cb_pos = NULL;
	struct heci_cb_private *priv_cb_next = NULL;
	struct heci_file_private *file_ext_list_temp;

	if (dev->read_list.status == 0 &&
	    !list_empty(&dev->read_list.heci_cb.cb_list)) {

		DBG("remove read_list CB \n");
		list_for_each_entry_safe(priv_cb_pos,
		    priv_cb_next,
		    &dev->read_list.heci_cb.cb_list, cb_list,
		    struct heci_cb_private) {

			file_ext_list_temp = (struct heci_file_private *)
			    priv_cb_pos->file_private;

			if ((file_ext_list_temp != NULL) &&
			    heci_fe_same_id(file_ext, file_ext_list_temp))
				return (priv_cb_pos);

		}
	}
	return (NULL);
}

/*
 * heci_read - the read client message function.
 */
static int
heci_read(dev_t devt, struct uio *uio_p, cred_t *cred_p)
{
	int i;
	int rets = 0;
	size_t length;
	struct heci_file	*file;
	struct heci_file_private *file_ext;
	struct heci_cb_private *priv_cb_pos = NULL;
	int instance, minor, if_num, err;
	struct heci_cb_private *priv_cb = NULL;
	struct iamt_heci_device *dev;

	_NOTE(ARGUNUSED(cred_p))

	minor = getminor(devt);

	instance = HECI_MINOR_TO_INSTANCE(minor);
	if_num = HECI_MINOR_TO_IFNUM(minor);

	dev = ddi_get_soft_state(heci_soft_state_p, instance);

	file = &dev->files[if_num];
	file_ext = file->private_data;

	if ((if_num < HECI_MINOR_NUMBER) || (!dev) || (!file_ext))
		return (-ENODEV);

	mutex_enter(&dev->device_lock);
	if (dev->heci_state != HECI_ENABLED) {
		mutex_exit(&dev->device_lock);
		return (-ENODEV);
	}
	mutex_exit(&dev->device_lock);
	if (!file_ext)
		return (-ENODEV);

	mutex_enter(&file_ext->file_lock);
	if ((file_ext->sm_state & HECI_WD_STATE_INDEPENDENCE_MSG_SENT) == 0) {
		mutex_exit(&file_ext->file_lock);
		/* Do not allow to read watchdog client */
		for (i = 0; i < dev->num_heci_me_clients; i++) {
			if (memcmp(&heci_wd_guid,
			    &dev->me_clients[i].props.protocol_name,
			    sizeof (struct guid)) == 0) {
				if (file_ext->me_client_id ==
				    dev->me_clients[i].client_id)
					return (-EBADF);
			}
		}
	} else {
		file_ext->sm_state &= ~HECI_WD_STATE_INDEPENDENCE_MSG_SENT;
		mutex_exit(&file_ext->file_lock);
	}

	if (file_ext == &dev->iamthif_file_ext) {
		rets = pthi_read(dev, if_num, file, uio_p);
		goto out;
	}

	if (file_ext->read_cb &&
	    file_ext->read_cb->information > UIO_OFFSET(uio_p)) {
		priv_cb = file_ext->read_cb;
		goto copy_buffer;
	} else if (file_ext->read_cb && file_ext->read_cb->information > 0 &&
	    file_ext->read_cb->information <= UIO_OFFSET(uio_p)) {
		priv_cb = file_ext->read_cb;
		rets = 0;
		goto free;
	} else if (
	    (!file_ext->read_cb || file_ext->read_cb->information == 0) &&
	    UIO_OFFSET(uio_p) > 0) {
		/* Offset needs to be cleaned for contingous reads */
		UIO_OFFSET(uio_p) = 0;
		rets = 0;
		goto out;
	}

	mutex_enter(&file_ext->read_io_lock);
	err = heci_start_read(dev, if_num, file_ext);
	if (err != 0 && err != -EBUSY) {
		DBG("heci start read failure with status = %d\n", err);
		mutex_exit(&file_ext->read_io_lock);
		rets = err;
		goto out;
	}
	while (HECI_READ_COMPLETE != file_ext->reading_state &&
	    HECI_FILE_INITIALIZING != file_ext->state &&
	    HECI_FILE_DISCONNECTED != file_ext->state &&
	    HECI_FILE_DISCONNECTING != file_ext->state) {
		mutex_exit(&file_ext->read_io_lock);
		mutex_enter(&dev->device_lock);
		if (cv_wait_sig(&file_ext->rx_wait, &dev->device_lock) == 0) {
			mutex_exit(&dev->device_lock);
			priv_cb = file_ext->read_cb;
			rets = -EINTR;
			goto free;
		}
		mutex_exit(&dev->device_lock);


		if (HECI_FILE_INITIALIZING == file_ext->state ||
		    HECI_FILE_DISCONNECTED == file_ext->state ||
		    HECI_FILE_DISCONNECTING == file_ext->state) {
			rets = -EBUSY;
			goto out;
		}
		mutex_enter(&file_ext->read_io_lock);
	}

	priv_cb = file_ext->read_cb;

	if (!priv_cb) {
		mutex_exit(&file_ext->read_io_lock);
		return (-ENODEV);
	}
	if (file_ext->reading_state != HECI_READ_COMPLETE) {
		mutex_exit(&file_ext->read_io_lock);
		return (0);
	}
	mutex_exit(&file_ext->read_io_lock);
	/* now copy the data to user space */
copy_buffer:
	DBG("priv_cb->response_buffer size - %d\n",
	    priv_cb->response_buffer.size);
	DBG("priv_cb->information - %lu\n", priv_cb->information);
	if (uio_p->uio_resid == 0 || uio_p->uio_resid < priv_cb->information) {
		rets = -EMSGSIZE;
		goto free;
	}
	length = (uio_p->uio_resid <
	    (priv_cb->information - uio_p->uio_offset) ?
	    uio_p->uio_resid : (priv_cb->information - uio_p->uio_offset));

	if (uiomove(priv_cb->response_buffer.data,
	    length, UIO_READ, uio_p)) {
		rets = -EFAULT;
		goto free;
	}
	else
		rets = 0;

free:
	mutex_enter(&dev->device_lock);
	priv_cb_pos = find_read_list_entry(dev, file_ext);
	/* Remove entry from read list */
	if (priv_cb_pos != NULL)
		list_del(&priv_cb_pos->cb_list);
	mutex_exit(&dev->device_lock);
	heci_free_cb_private(priv_cb);
	mutex_enter(&file_ext->read_io_lock);
	file_ext->reading_state = HECI_IDLE;
	file_ext->read_cb = NULL;
	file_ext->read_pending = 0;
	mutex_exit(&file_ext->read_io_lock);
out:	DBG("end heci read rets= %d\n", rets);
	return (rets);
}

/*
 * heci_write - the write function.
 */
static int
heci_write(dev_t devt, struct uio *uio_p, struct cred *cred)
{
	int rets = 0;
	uint8_t i;
	size_t length;
	struct heci_file_private *file_ext;
	struct heci_cb_private *priv_write_cb = NULL;
	struct heci_msg_hdr heci_hdr;
	struct iamt_heci_device *dev;
	unsigned long currtime = ddi_get_time();
	int instance, minor, if_num, err;
	struct heci_file *file;

	_NOTE(ARGUNUSED(cred))
	DBG("heci_write enter...\n");

	minor = getminor(devt);
	instance = HECI_MINOR_TO_INSTANCE(minor);
	if_num = HECI_MINOR_TO_IFNUM(minor);

	dev = ddi_get_soft_state(heci_soft_state_p, instance);

	file = &dev->files[if_num];
	file_ext = file->private_data;
	if ((if_num < HECI_MINOR_NUMBER) || (!dev) || (!file_ext))
		return (-ENODEV);

	mutex_enter(&dev->device_lock);

	if (dev->heci_state != HECI_ENABLED) {
		mutex_exit(&dev->device_lock);
		return (-ENODEV);
	}
	if (file_ext == &dev->iamthif_file_ext) {
		priv_write_cb = find_pthi_read_list_entry(dev, file);
		if ((priv_write_cb != NULL) &&
		    (((currtime - priv_write_cb->read_time) >
		    IAMTHIF_READ_TIMER) ||
		    (file_ext->reading_state == HECI_READ_COMPLETE))) {
			UIO_OFFSET(uio_p) = 0;
			list_del(&priv_write_cb->cb_list);
			heci_free_cb_private(priv_write_cb);
			priv_write_cb = NULL;
		}
	}

	/* free entry used in read */
	if (file_ext->reading_state == HECI_READ_COMPLETE) {
		UIO_OFFSET(uio_p) = 0;
		priv_write_cb = find_read_list_entry(dev, file_ext);
		if (priv_write_cb != NULL) {
			list_del(&priv_write_cb->cb_list);
			heci_free_cb_private(priv_write_cb);
			priv_write_cb = NULL;
			mutex_enter(&file_ext->read_io_lock);
			file_ext->reading_state = HECI_IDLE;
			file_ext->read_cb = NULL;
			file_ext->read_pending = 0;
			mutex_exit(&file_ext->read_io_lock);
		}
	} else if (file_ext->reading_state == HECI_IDLE &&
	    file_ext->read_pending == 0)
		UIO_OFFSET(uio_p) = 0;

	mutex_exit(&dev->device_lock);

	priv_write_cb = kmem_zalloc(sizeof (struct heci_cb_private), KM_SLEEP);
	if (!priv_write_cb)
		return (-ENOMEM);

	priv_write_cb->file_object = file;
	priv_write_cb->file_private = file_ext;
	priv_write_cb->request_buffer.data =
	    kmem_zalloc(uio_p->uio_resid, KM_SLEEP);
	if (!priv_write_cb->request_buffer.data) {
		kmem_free(priv_write_cb, sizeof (struct heci_cb_private));
		return (-ENOMEM);
	}
	length = (int)uio_p->uio_resid;
	DBG("length =%d\n", (int)length);

	err = uiomove(priv_write_cb->request_buffer.data,
	    length, UIO_WRITE, uio_p);
	if (err) {
		rets = err;
		goto fail;
	}

#define	UBUFF	UIO_BUFF(uio_p)

	mutex_enter(&file_ext->file_lock);
	file_ext->sm_state = 0;
	if ((length == 4) &&
	    ((memcmp(heci_wd_state_independence_msg[0], UBUFF, 4) == 0) ||
	    (memcmp(heci_wd_state_independence_msg[1], UBUFF, 4) == 0) ||
	    (memcmp(heci_wd_state_independence_msg[2], UBUFF, 4) == 0)))

		file_ext->sm_state |= HECI_WD_STATE_INDEPENDENCE_MSG_SENT;

	mutex_exit(&file_ext->file_lock);

	LIST_INIT_HEAD(&priv_write_cb->cb_list);
	if (file_ext == &dev->iamthif_file_ext) {
		priv_write_cb->response_buffer.data =
		    kmem_zalloc(IAMTHIF_MTU, KM_SLEEP);
		if (!priv_write_cb->response_buffer.data) {
			rets = -ENOMEM;
			goto fail;
		}
		mutex_enter(&dev->device_lock);
		if (dev->heci_state != HECI_ENABLED) {
			mutex_exit(&dev->device_lock);
			rets = -ENODEV;
			goto fail;
		}
		for (i = 0; i < dev->num_heci_me_clients; i++) {
			if (dev->me_clients[i].client_id ==
			    dev->iamthif_file_ext.me_client_id)
				break;
		}

		ASSERT(dev->me_clients[i].client_id == file_ext->me_client_id);
		if ((i == dev->num_heci_me_clients) ||
		    (dev->me_clients[i].client_id !=
		    dev->iamthif_file_ext.me_client_id)) {

			mutex_exit(&dev->device_lock);
			rets = -ENODEV;
			goto fail;
		} else if ((length >
		    dev->me_clients[i].props.max_msg_length) ||
		    (length == 0)) {
			mutex_exit(&dev->device_lock);
			rets = -EMSGSIZE;
			goto fail;
		}


		priv_write_cb->response_buffer.size = IAMTHIF_MTU;
		priv_write_cb->major_file_operations = HECI_IOCTL;
		priv_write_cb->information = 0;
		priv_write_cb->request_buffer.size = (uint32_t)length;
		if (dev->iamthif_file_ext.state != HECI_FILE_CONNECTED) {
			mutex_exit(&dev->device_lock);
			rets = -ENODEV;
			goto fail;
		}

		if (!list_empty(&dev->pthi_cmd_list.heci_cb.cb_list) ||
		    dev->iamthif_state != HECI_IAMTHIF_IDLE) {
			DBG("pthi_state = %d\n", (int)dev->iamthif_state);
			DBG("add PTHI cb to pthi cmd waiting list\n");
			list_add_tail(&priv_write_cb->cb_list,
			    &dev->pthi_cmd_list.heci_cb.cb_list);
			rets = 0; /* length; */
		} else {
			DBG("call pthi write\n");
			rets = pthi_write(dev, priv_write_cb);

			if (rets != 0) {
				DBG("pthi write failed with status = %d\n",
				    rets);
				mutex_exit(&dev->device_lock);
				goto fail;
			}
			rets = 0; /* length; */
		}
		mutex_exit(&dev->device_lock);
		return (rets);
	}

	priv_write_cb->major_file_operations = HECI_WRITE;
	/* make sure information is zero before we start */

	priv_write_cb->information = 0;
	priv_write_cb->request_buffer.size = (uint32_t)length;

	mutex_enter(&dev->device_lock);
	mutex_enter(&file_ext->write_io_lock);
	DBG("host client = %d, ME client = %d\n",
	    file_ext->host_client_id, file_ext->me_client_id);
	if (file_ext->state != HECI_FILE_CONNECTED) {
		rets = -ENODEV;
		DBG("host client = %d,  is not connected to ME client = %d",
		    file_ext->host_client_id,
		    file_ext->me_client_id);

		goto unlock;
	}
	for (i = 0; i < dev->num_heci_me_clients; i++) {
		if (dev->me_clients[i].client_id ==
		    file_ext->me_client_id)
			break;
	}
	ASSERT(dev->me_clients[i].client_id == file_ext->me_client_id);
	if (i == dev->num_heci_me_clients) {
		rets = -ENODEV;
		goto unlock;
	}
	if (length > dev->me_clients[i].props.max_msg_length || length == 0) {
		rets = -EINVAL;
		goto unlock;
	}
	priv_write_cb->file_private = file_ext;

	if (flow_ctrl_creds(dev, file_ext) &&
	    dev->host_buffer_is_empty) {
		dev->host_buffer_is_empty = 0;
		if (length > ((((dev->host_hw_state & H_CBD) >> 24) *
			sizeof (uint32_t)) - sizeof (struct heci_msg_hdr))) {

			heci_hdr.length =
			    (((dev->host_hw_state & H_CBD) >> 24) *
			    sizeof (uint32_t)) -
			    sizeof (struct heci_msg_hdr);
			heci_hdr.msg_complete = 0;
		} else {
			heci_hdr.length = (uint32_t)length;
			heci_hdr.msg_complete = 1;
		}
		heci_hdr.host_addr = file_ext->host_client_id;
		heci_hdr.me_addr = file_ext->me_client_id;
		heci_hdr.reserved = 0;
		DBG("call heci_write_message header=%08x.\n",
		    *((uint32_t *)(void *)&heci_hdr));
		/*  protect heci low level write */
		if (!heci_write_message(dev, &heci_hdr,
		    (unsigned char *)(priv_write_cb->request_buffer.data),
		    heci_hdr.length)) {

		mutex_exit(&file_ext->write_io_lock);
			mutex_exit(&dev->device_lock);
			heci_free_cb_private(priv_write_cb);
			rets = -ENODEV;
			priv_write_cb->information = 0;
			return (rets);
		}
		file_ext->writing_state = HECI_WRITING;
		priv_write_cb->information = heci_hdr.length;
		if (heci_hdr.msg_complete) {
			flow_ctrl_reduce(dev, file_ext);
			list_add_tail(&priv_write_cb->cb_list,
			    &dev->write_waiting_list.heci_cb.cb_list);
		} else {
			list_add_tail(&priv_write_cb->cb_list,
			    &dev->write_list.heci_cb.cb_list);
		}

	} else {

		priv_write_cb->information = 0;
		file_ext->writing_state = HECI_WRITING;
		list_add_tail(&priv_write_cb->cb_list,
		    &dev->write_list.heci_cb.cb_list);
	}
	mutex_exit(&file_ext->write_io_lock);
	mutex_exit(&dev->device_lock);
	return (0);

unlock:
	mutex_exit(&file_ext->write_io_lock);
	mutex_exit(&dev->device_lock);
fail:
	heci_free_cb_private(priv_write_cb);
	return (rets);

}

/*
 * heci_ioctl - the IOCTL function
 */
static int
heci_ioctl(dev_t devt, int cmd, intptr_t arg, int mode, cred_t *cr, int *rval)
{
	int rets = 0;
	struct heci_file_private *file_ext;
	/* in user space */
	struct heci_message_data *u_msg = (struct heci_message_data *)arg;
	struct heci_message_data k_msg;	/* all in kernel on the stack */
	struct iamt_heci_device *dev;
	int instance, minor, if_num;
	struct heci_file *file;

	_NOTE(ARGUNUSED(cr, rval))

	minor = getminor(devt);

	instance = HECI_MINOR_TO_INSTANCE(minor);
	if_num = HECI_MINOR_TO_IFNUM(minor);

	dev = ddi_get_soft_state(heci_soft_state_p, instance);

	file = &dev->files[if_num];
	file_ext = file->private_data;

	if ((if_num < HECI_MINOR_NUMBER) || (!dev) || (!file_ext))
		return (-ENODEV);

	mutex_enter(&dev->device_lock);
	if (dev->heci_state != HECI_ENABLED) {
		mutex_exit(&dev->device_lock);
		return (-ENODEV);
	}
	mutex_exit(&dev->device_lock);

	/* first copy from user all data needed */
	if (ddi_copyin(u_msg, &k_msg, sizeof (k_msg), mode)) {
		DBG("first copy from user all data needed filled\n");
		return (-EFAULT);
	}
#ifdef _LP64
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		uint32_t    addr32 = (uint32_t)(uint64_t)k_msg.data;
		k_msg.data = (char *)(uint64_t)addr32;
		DBG("IPL32: k_msg.data=%p\n", (void *)k_msg.data);
	}
#endif
	DBG("user message size is %d, cmd = 0x%x\n", k_msg.size, cmd);

	switch (cmd) {
	case IOCTL_HECI_GET_VERSION:
		DBG(": IOCTL_HECI_GET_VERSION\n");
		rets = heci_ioctl_get_version(dev, if_num, u_msg, k_msg,
		    file_ext, mode);
		break;

	case IOCTL_HECI_CONNECT_CLIENT:
		DBG(": IOCTL_HECI_CONNECT_CLIENT.\n");
		rets = heci_ioctl_connect_client(dev, if_num, u_msg, k_msg,
		    file, mode);
		break;

	case IOCTL_HECI_WD:
		DBG(": IOCTL_HECI_WD.\n");
		rets = heci_ioctl_wd(dev, if_num, k_msg, file_ext, mode);
		break;

	case IOCTL_HECI_BYPASS_WD:
		DBG(": IOCTL_HECI_BYPASS_WD.\n");
		rets = heci_ioctl_bypass_wd(dev, if_num, k_msg, file_ext, mode);
		break;

	default:
		rets = -EINVAL;
		break;
	}
	return (rets);
}

/*
 * heci_poll - the poll function
 */
static int
heci_poll(dev_t devt, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	struct heci_file *file;
	struct heci_file_private *file_extension;
	struct iamt_heci_device *device = NULL;
	int instance, minor, if_num;

	_NOTE(ARGUNUSED(events))

	minor = getminor(devt);

	instance = HECI_MINOR_TO_INSTANCE(minor);
	if_num = HECI_MINOR_TO_IFNUM(minor);

	device = ddi_get_soft_state(heci_soft_state_p, instance);

	file = &device->files[if_num];
	file_extension = file->private_data;

	if ((if_num < HECI_MINOR_NUMBER) || (!device) || (!file_extension))
		return (-ENODEV);

	mutex_enter(&device->device_lock);
	if (device->heci_state != HECI_ENABLED) {
		mutex_exit(&device->device_lock);
		return (-ENXIO);

	}

	mutex_exit(&device->device_lock);

	if (file_extension == &device->iamthif_file_ext) {

		mutex_enter(&device->iamthif_file_ext.file_lock);

		if (device->iamthif_state == HECI_IAMTHIF_READ_COMPLETE &&
		    device->iamthif_file_object == file) {
			*reventsp |= (POLLIN | POLLRDNORM);
			mutex_enter(&device->device_lock);
			DBG("heci_poll: run next pthi cb\n");
			run_next_iamthif_cmd(device);
			mutex_exit(&device->device_lock);
		} else {
			DBG("heci_poll: iamthif no event\n");
			*reventsp = 0;
		}
		mutex_exit(&device->iamthif_file_ext.file_lock);

		if ((*reventsp == 0 && !anyyet) || (events & POLLET)) {
			*phpp = &device->iamthif_file_ext.pollwait;
		}
	} else {
		mutex_enter(&file_extension->write_io_lock);
		if (HECI_WRITE_COMPLETE == file_extension->writing_state) {
			*reventsp |= (POLLIN | POLLRDNORM);
			DBG("heci_poll: file_extension poll event\n");
		} else {
			DBG("heci_poll: file_extension no event\n");
			*reventsp = 0;
		}
		mutex_exit(&file_extension->write_io_lock);

		if ((*reventsp == 0 && !anyyet) || (events & POLLET)) {
			*phpp = &file_extension->tx_pollwait;
		}
	}

	return (0);
}

/*
 * heci_fe_same_id - tell if file private data have same id
 *
 * @fe1: private data of 1. file object
 * @fe2: private data of 2. file object
 *
 * @return  !=0 - if ids are the same, 0 - if differ.
 */
static inline int heci_fe_same_id(struct heci_file_private *fe1,
		struct heci_file_private *fe2)
{
	return ((fe1->host_client_id == fe2->host_client_id) &&
	    (fe1->me_client_id == fe2->me_client_id));
}

/*
 * Since the ME firmware won't reset itself during OS reboot, it's not enough
 * to only disable interrupts in quiesce(), here we do a full hand-shake
 * with the firmware.
 */
static int
heci_quiesce(dev_info_t *dip)
{
	struct iamt_heci_device	*dev;

	dev = ddi_get_soft_state(heci_soft_state_p, ddi_get_instance(dip));
	ASSERT(dev != NULL);

	if (dev->wd_file_ext.state == HECI_FILE_CONNECTED &&
	    dev->wd_timeout) {
		dev->wd_timeout = 0;
		dev->wd_due_counter = 0;
		(void) memcpy(dev->wd_data, stop_wd_params,
		    HECI_WD_PARAMS_SIZE);
		if (!heci_send_wd(dev)) {
			DBG("send stop WD failed\n");
		}

	}

	/* disable interrupts */
	heci_csr_disable_interrupts(dev);

	return (DDI_SUCCESS);
}

static int
heci_suspend(dev_info_t *dip)
{
	struct iamt_heci_device *device;
	int err = 0;

	device = ddi_get_soft_state(heci_soft_state_p, ddi_get_instance(dip));

	if (device->reinit_tsk)
		ddi_taskq_wait(device->reinit_tsk);

	/* Stop watchdog if exists */
	if (device->wd_timer)
		(void) untimeout(device->wd_timer);

	mutex_enter(&device->device_lock);

	if (device->wd_file_ext.state == HECI_FILE_CONNECTED &&
	    device->wd_timeout) {
		g_sus_wd_timeout = device->wd_timeout;
		device->wd_timeout = 0;
		device->wd_due_counter = 0;
		(void) memcpy(device->wd_data, stop_wd_params,
		    HECI_WD_PARAMS_SIZE);
		device->stop = 1;
		if (device->host_buffer_is_empty &&
		    flow_ctrl_creds(device, &device->wd_file_ext)) {
			device->host_buffer_is_empty = 0;
			if (!heci_send_wd(device)) {
				DBG("send stop WD failed\n");
			}
			else
				flow_ctrl_reduce(device, &device->wd_file_ext);

			device->wd_pending = 0;
		} else {
			device->wd_pending = 1;
		}
		device->wd_stoped = 0;

		err = 0;
		while (!device->wd_stoped && err != -1) {
			err = cv_reltimedwait(&device->wait_stop_wd,
			    &device->device_lock, 10*HZ, TR_CLOCK_TICK);
		}

		if (!device->wd_stoped) {
			DBG("stop wd failed to complete.\n");
		} else {
			DBG("stop wd complete %d.\n", err);
			err = 0;
		}
	}
	/* Set new heci state */
	if (device->heci_state == HECI_ENABLED ||
	    device->heci_state == HECI_RECOVERING_FROM_RESET) {
		device->heci_state = HECI_POWER_DOWN;
		heci_reset(device, 0);
	}

	/* Here interrupts are already disabled by heci_reset() */

	mutex_exit(&device->device_lock);


	return (err);
}

static void
heci_resume(dev_info_t *dip)
{
	struct iamt_heci_device *device;

	device = ddi_get_soft_state(heci_soft_state_p, ddi_get_instance(dip));

	mutex_enter(&device->device_lock);
	device->heci_state = HECI_POWER_UP;
	heci_reset(device, 1);
	mutex_exit(&device->device_lock);

	/* Start watchdog if stopped in suspend */
	if (g_sus_wd_timeout != 0) {
		device->wd_timeout = g_sus_wd_timeout;

		(void) memcpy(device->wd_data, start_wd_params,
		    HECI_WD_PARAMS_SIZE);
		(void) memcpy(device->wd_data + HECI_WD_PARAMS_SIZE,
		    &device->wd_timeout, sizeof (uint16_t));
		device->wd_due_counter = 1;

		if (device->wd_timeout)
			device->wd_timer = timeout(heci_wd_timer, device, 1);

		g_sus_wd_timeout = 0;
	}
}
