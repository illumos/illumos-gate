/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <sys/sunndi.h>
#include <sys/systm.h>
#include <sys/mkdev.h>
#include <sys/list.h>
#include "heci_data_structures.h"
#include "heci.h"
#include "heci_interface.h"
#include "version.h"


static inline int heci_fe_same_id(struct heci_file_private *fe1,
		struct heci_file_private *fe2);
/*
 * heci_ioctl_get_version - the get driver version IOCTL function
 *
 * @dev: Device object for our driver
 * @if_num:  minor number
 * @*u_msg: pointer to user data struct in user space
 * @k_msg: data in kernel on the stack
 * @file_ext: private data of the file object
 *
 * @return 0 on success, <0 on failure.
 */
int
heci_ioctl_get_version(struct iamt_heci_device *dev, int if_num,
	struct heci_message_data *u_msg,
	struct heci_message_data k_msg,
	struct heci_file_private *file_ext, int mode)
{

	int rets = 0;
	struct heci_driver_version *version;
	struct heci_message_data res_msg;

	if ((if_num < HECI_MINOR_NUMBER) || (!dev) ||
	    (!file_ext))
		return (-ENODEV);

	if (k_msg.size < (sizeof (struct heci_driver_version) - 2)) {
		DBG("user buffer less than heci_driver_version.\n");
		return (-EMSGSIZE);
	}

	res_msg.data = kmem_zalloc(sizeof (struct heci_driver_version),
	    KM_SLEEP);
	if (!res_msg.data) {
		DBG("failed allocation response buffer size = %d.\n",
		    (int)sizeof (struct heci_driver_version));
		return (-ENOMEM);
	}

	version = (struct heci_driver_version *)res_msg.data;
	version->major = MAJOR_VERSION;
	version->minor = MINOR_VERSION;
	version->hotfix = QUICK_FIX_NUMBER;
	version->build = VER_BUILD;
	res_msg.size = sizeof (struct heci_driver_version);
	if (k_msg.size < sizeof (struct heci_driver_version))
		res_msg.size -= 2;

	rets = file_ext->status;
	/* now copy the data to user space */
	if (ddi_copyout(res_msg.data, k_msg.data, res_msg.size, mode)) {
		rets = -EFAULT;
		goto end;
	}
	if (ddi_copyout(&res_msg.size, &u_msg->size, sizeof (uint32_t), mode)) {
		rets = -EFAULT;
		goto end;
	}
end:
	kmem_free(res_msg.data, sizeof (struct heci_driver_version));
	return (rets);
}

/*
 * heci_ioctl_connect_client - the connect to fw client IOCTL function
 *
 * @dev: Device object for our driver
 * @if_num:  minor number
 * @*u_msg: pointer to user data struct in user space
 * @k_msg: data in kernel on the stack
 * @file_ext: private data of the file object
 *
 * @return 0 on success, <0 on failure.
 */
int
heci_ioctl_connect_client(struct iamt_heci_device *dev, int if_num,
	struct heci_message_data *u_msg,
	struct heci_message_data k_msg,
	struct heci_file *file, int mode)
{

	int rets = 0;
	struct heci_message_data req_msg, res_msg;
	struct heci_cb_private *priv_cb = NULL;
	struct heci_client *client;
	struct heci_file_private *file_ext;
	struct heci_file_private *file_pos = NULL;
	struct heci_file_private *file_next = NULL;
	long timeout = 15;	/* 15 second */
	uint8_t i;
	int err = 0;

	if ((if_num < HECI_MINOR_NUMBER) || (!dev) || (!file))
		return (-ENODEV);

	file_ext = file->private_data;
	if (!file_ext)
		return (-ENODEV);

	if (k_msg.size != sizeof (struct guid)) {
		DBG("user buffer size is not equal to size of struct "
		    "guid(16).\n");
		return (-EMSGSIZE);
	}

	if (!k_msg.data)
		return (-EIO);

	req_msg.data = kmem_zalloc(sizeof (struct guid), KM_SLEEP);
	res_msg.data = kmem_zalloc(sizeof (struct heci_client), KM_SLEEP);

	if (!res_msg.data) {
		DBG("failed allocation response buffer size = %d.\n",
		    (int)sizeof (struct heci_client));
		kmem_free(req_msg.data, sizeof (struct guid));
		return (-ENOMEM);
	}
	if (!req_msg.data) {
		DBG("failed allocation request buffer size = %d.\n",
		    (int)sizeof (struct guid));
		if (res_msg.data) {
			kmem_free(res_msg.data, sizeof (struct heci_client));
			res_msg.data = NULL;
			goto fail;
		}
fail:
		return (-ENOMEM);
	}
	req_msg.size = sizeof (struct guid);
	res_msg.size = sizeof (struct heci_client);

	/*
	 * copy the message to kernel space -
	 * use a pointer already copied into kernel space
	 */
	if (ddi_copyin(k_msg.data, req_msg.data, k_msg.size, mode)) {
		rets = -EFAULT;
		goto end;
	}
	/* buffered ioctl cb */
	priv_cb = kmem_zalloc(sizeof (struct heci_cb_private), KM_SLEEP);
	if (!priv_cb) {
		rets = -ENOMEM;
		goto end;
	}
	LIST_INIT_HEAD(&priv_cb->cb_list);
	priv_cb->response_buffer.data = res_msg.data;
	priv_cb->response_buffer.size = res_msg.size;
	priv_cb->request_buffer.data = req_msg.data;
	priv_cb->request_buffer.size = req_msg.size;
	priv_cb->major_file_operations = HECI_IOCTL;
	mutex_enter(&dev->device_lock);
	if (dev->heci_state != HECI_ENABLED) {
		rets = -ENODEV;
		mutex_exit(&dev->device_lock);
		goto end;
	}
	if ((file_ext->state != HECI_FILE_INITIALIZING) &&
	    (file_ext->state != HECI_FILE_DISCONNECTED)) {
		rets = -EBUSY;
		mutex_exit(&dev->device_lock);
		goto end;
	}

	DBG("req_msg.data:%x", *(uint32_t *)(void *)req_msg.data);
	/* find ME client we're trying to connect to */
	for (i = 0; i < dev->num_heci_me_clients; i++) {
		DBG("guid:%x, me_client_id:%d\n",
		    dev->me_clients[i].props.protocol_name.data1,
		    dev->me_clients[i].client_id);
		if (memcmp((struct guid *)req_msg.data,
		    &dev->me_clients[i].props.protocol_name,
		    sizeof (struct guid)) == 0) {
			if (dev->me_clients[i].props.fixed_address == 0) {
				file_ext->me_client_id =
				    dev->me_clients[i].client_id;
				file_ext->state = HECI_FILE_CONNECTING;
			}
			break;
		}
	}
	/*
	 * if we're connecting to PTHI client so we will use the exist
	 * connection
	 */
	if (memcmp((struct guid *)req_msg.data, &heci_pthi_guid,
	    sizeof (struct guid)) == 0) {
		if (dev->iamthif_file_ext.state != HECI_FILE_CONNECTED) {
			rets = -ENODEV;
			mutex_exit(&dev->device_lock);
			goto end;
		}
		dev->heci_host_clients[file_ext->host_client_id / 8] &=
		    ~(1 << (file_ext->host_client_id % 8));
		list_for_each_entry_safe(file_pos,
		    file_next, &dev->file_list, link,
		    struct heci_file_private) {
			if (heci_fe_same_id(file_ext, file_pos)) {
				DBG("remove file private data node host"
				    " client = %d, ME client = %d.\n",
				    file_pos->host_client_id,
				    file_pos->me_client_id);
				list_del(&file_pos->link);
			}

		}
		DBG("free file private data memory.\n");
		kmem_free(file_ext, sizeof (struct heci_file_private));
		file_ext = NULL;
		file->private_data = &dev->iamthif_file_ext;
		client = (struct heci_client *)res_msg.data;
		client->max_message_length =
			dev->me_clients[i].props.max_msg_length;
		client->protocol_version =
			dev->me_clients[i].props.protocol_version;
		rets = dev->iamthif_file_ext.status;
		mutex_exit(&dev->device_lock);

		/* now copy the data to user space */
		if (ddi_copyout(res_msg.data, k_msg.data, res_msg.size, mode)) {
			cmn_err(CE_WARN, "ddi_copyout error on res_msg.data");
			rets = -EFAULT;
			goto end;
		}
		if (ddi_copyout(&res_msg.size, &u_msg->size,
		    sizeof (uint32_t), mode)) {
			cmn_err(CE_WARN, "ddi_copyout error on res_msg.size");
			rets = -EFAULT;
			goto end;
		}
		goto end;
	}
	mutex_enter(&file_ext->file_lock);
	if (file_ext->state != HECI_FILE_CONNECTING) {
		rets = -ENODEV;
		mutex_exit(&file_ext->file_lock);
		mutex_exit(&dev->device_lock);
		goto end;
	}
	mutex_exit(&file_ext->file_lock);
	/* prepare the output buffer */
	client = (struct heci_client *)res_msg.data;
	client->max_message_length = dev->me_clients[i].props.max_msg_length;
	client->protocol_version = dev->me_clients[i].props.protocol_version;
	if (dev->host_buffer_is_empty &&
	    !other_client_is_connecting(dev, file_ext)) {
		dev->host_buffer_is_empty = 0;
		if (!heci_connect(dev, file_ext)) {
			rets = -ENODEV;
			mutex_exit(&dev->device_lock);
			goto end;
		} else {
			file_ext->timer_count = HECI_CONNECT_TIMEOUT;
			priv_cb->file_private = file_ext;
			list_add_tail(&priv_cb->cb_list,
			    &dev->ctrl_rd_list.heci_cb.
			    cb_list);
		}


	} else {
		priv_cb->file_private = file_ext;
		DBG("add connect cb to control write list.\n");
		list_add_tail(&priv_cb->cb_list,
		    &dev->ctrl_wr_list.heci_cb.cb_list);
	}
	err = 0;
	while (err != -1 && HECI_FILE_CONNECTED != file_ext->state &&
	    HECI_FILE_DISCONNECTED != file_ext->state) {
		err = cv_reltimedwait(&dev->wait_recvd_msg,
		    &dev->device_lock, timeout * HZ, TR_CLOCK_TICK);
	}
	mutex_exit(&dev->device_lock);

	if (HECI_FILE_CONNECTED == file_ext->state) {
		DBG("successfully connected to FW client."
		    " me_client_id:%d, host_client_id:%d\n",
		    file_ext->me_client_id,
		    file_ext->host_client_id);
		rets = file_ext->status;
		/* now copy the data to user space */
		if (ddi_copyout(res_msg.data, k_msg.data, res_msg.size, mode)) {
			rets = -EFAULT;
			goto end;
		}
		if (ddi_copyout(&res_msg.size, &u_msg->size,
		    sizeof (uint32_t), mode)) {
			rets = -EFAULT;
			goto end;
		}
		goto end;
	} else {
		DBG("failed to connect to FW client.file_ext->state = %d,"
		    " me_client_id:%d, host_client_id:%d\n",
		    file_ext->state, file_ext->me_client_id,
		    file_ext->host_client_id);
		if (!err) {
			DBG("wait_event_interruptible_timeout failed on client"
			    " connect message fw response message.\n");
		}
		rets = -EFAULT;
		goto remove_list;
	}

remove_list:
	if (priv_cb) {
		mutex_enter(&dev->device_lock);
		heci_flush_list(&dev->ctrl_rd_list, file_ext);
		heci_flush_list(&dev->ctrl_wr_list, file_ext);
		mutex_exit(&dev->device_lock);
	}
end:
	DBG("free connect cb memory.");
	kmem_free(req_msg.data, sizeof (struct guid));
	req_msg.data = NULL;
	kmem_free(res_msg.data, sizeof (struct heci_client));
	res_msg.data = NULL;
	if (priv_cb) {
		kmem_free(priv_cb, sizeof (struct heci_cb_private));
		priv_cb = NULL;
	}
	return (rets);
}

/*
 * heci_ioctl_wd  - the wd IOCTL function
 *
 * @dev: Device object for our driver
 * @if_num:  minor number
 * @k_msg: data in kernel on the stack
 * @file_ext: private data of the file object
 *
 * @return 0 on success, <0 on failure.
 */
int
heci_ioctl_wd(struct iamt_heci_device *dev, int if_num,
	struct heci_message_data k_msg,
	struct heci_file_private *file_ext, int mode)
{
	int rets = 0;
	struct heci_message_data req_msg;	/* in kernel on the stack */

	if (if_num < HECI_MINOR_NUMBER)
		return (-ENODEV);

	mutex_enter(&file_ext->file_lock);
	if (k_msg.size != HECI_WATCHDOG_DATA_SIZE) {
		DBG("user buffer has invalid size.\n");
		mutex_exit(&file_ext->file_lock);
		return (-EMSGSIZE);
	}
	mutex_exit(&file_ext->file_lock);

	req_msg.data = kmem_zalloc(HECI_WATCHDOG_DATA_SIZE, KM_SLEEP);
	if (!req_msg.data) {
		DBG("failed allocation request buffer size = %d.\n",
		    HECI_WATCHDOG_DATA_SIZE);
		return (-ENOMEM);
	}
	req_msg.size = HECI_WATCHDOG_DATA_SIZE;

	/*
	 * copy the message to kernel space - use a pointer already
	 * copied into kernel space
	 */
	if (ddi_copyin(k_msg.data, req_msg.data, k_msg.size, mode)) {
		rets = -EFAULT;
		goto end;
	}
	mutex_enter(&dev->device_lock);
	if (dev->heci_state != HECI_ENABLED) {
		rets = -ENODEV;
		mutex_exit(&dev->device_lock);
		goto end;
	}

	if (dev->wd_file_ext.state != HECI_FILE_CONNECTED) {
		rets = -ENODEV;
		mutex_exit(&dev->device_lock);
		goto end;
	}
	if (!dev->asf_mode) {
		rets = -EIO;
		mutex_exit(&dev->device_lock);
		goto end;
	}

	(void) memcpy(&dev->wd_data[HECI_WD_PARAMS_SIZE], req_msg.data,
	    HECI_WATCHDOG_DATA_SIZE);

	dev->wd_timeout = (req_msg.data[1] << 8) + req_msg.data[0];
	dev->wd_pending = 0;
	dev->wd_due_counter = 1;	/* next timer */
	if (dev->wd_timeout == 0) {
		(void) memcpy(dev->wd_data, &stop_wd_params,
		    HECI_WD_PARAMS_SIZE);
	} else {
		(void) memcpy(dev->wd_data, &start_wd_params,
		    HECI_WD_PARAMS_SIZE);
		dev->wd_timer = timeout(heci_wd_timer, dev, 1);
	}
	mutex_exit(&dev->device_lock);
end:
	kmem_free(req_msg.data, HECI_WATCHDOG_DATA_SIZE);
	return (rets);
}


/*
 * heci_ioctl_bypass_wd  - the bypass_wd IOCTL function
 *
 * @dev: Device object for our driver
 * @if_num:  minor number
 * @k_msg: data in kernel on the stack
 * @file_ext: private data of the file object
 *
 * @return 0 on success, <0 on failure.
 */
int
heci_ioctl_bypass_wd(struct iamt_heci_device *dev, int if_num,
	struct heci_message_data k_msg,
	struct heci_file_private *file_ext, int mode)
{
	uint8_t flag = 0;
	int rets = 0;

	if (if_num < HECI_MINOR_NUMBER)
		return (-ENODEV);

	mutex_enter(&file_ext->file_lock);
	if (k_msg.size < 1) {
		DBG("user buffer less than HECI_WATCHDOG_DATA_SIZE.\n");
		mutex_exit(&file_ext->file_lock);
		return (-EMSGSIZE);
	}
	mutex_exit(&file_ext->file_lock);
	if (ddi_copyin(k_msg.data, &flag, 1, mode)) {
		rets = -EFAULT;
		goto end;
	}

	mutex_enter(&dev->device_lock);
	flag = flag ? (1) : (0);
	dev->wd_bypass = flag;
	mutex_exit(&dev->device_lock);
end:
	return (rets);
}

/*
 * find_pthi_read_list_entry - finds a PTHIlist entry for current file
 *
 * @dev: Device object for our driver
 * @file: pointer to file object
 *
 * @return   returned a list entry on success, NULL on failure.
 */
struct heci_cb_private *
find_pthi_read_list_entry(
		struct iamt_heci_device *dev,
		struct heci_file *file)
{
	struct heci_file_private *file_ext_temp;
	struct heci_cb_private *priv_cb_pos = NULL;
	struct heci_cb_private *priv_cb_next = NULL;

	if ((dev->pthi_read_complete_list.status == 0) &&
	    !list_empty(&dev->pthi_read_complete_list.heci_cb.cb_list)) {

		list_for_each_entry_safe(priv_cb_pos, priv_cb_next,
		    &dev->pthi_read_complete_list.heci_cb.cb_list, cb_list,
		    struct heci_cb_private) {

			file_ext_temp = (struct heci_file_private *)
					priv_cb_pos->file_private;
			if ((file_ext_temp != NULL) &&
			    (file_ext_temp == &dev->iamthif_file_ext) &&
			    (priv_cb_pos->file_object == file))
				return (priv_cb_pos);
		}
	}
	return (NULL);
}

/*
 * pthi_read - read data from pthi client
 *
 * @dev: Device object for our driver
 * @if_num:  minor number
 * @file: pointer to file object
 * @*ubuf: pointer to user data in user space
 * @length: data length to read
 * @offset: data read offset
 *
 * @return
 *  returned data length on success,
 *  zero if no data to read,
 *  negative on failure.
 */
int
pthi_read(struct iamt_heci_device *dev, int if_num, struct heci_file *file,
	struct uio *uio_p)
{

	int rets = 0;
	struct heci_cb_private *priv_cb = NULL;
	struct heci_file_private *file_ext = file->private_data;
	uint8_t i;
	unsigned long currtime = ddi_get_time();

	if ((if_num < HECI_MINOR_NUMBER) || (!dev))
		return (-ENODEV);

	if ((file_ext == NULL) || (file_ext != &dev->iamthif_file_ext))
		return (-ENODEV);

	mutex_enter(&dev->device_lock);
	for (i = 0; i < dev->num_heci_me_clients; i++) {
		if (dev->me_clients[i].client_id ==
		    dev->iamthif_file_ext.me_client_id)
			break;
	}
	ASSERT(dev->me_clients[i].client_id == file_ext->me_client_id);
	if ((i == dev->num_heci_me_clients) ||
	    (dev->me_clients[i].client_id !=
	    dev->iamthif_file_ext.me_client_id)) {
		DBG("PTHI client not found.\n");
		mutex_exit(&dev->device_lock);
		return (-ENODEV);
	}
	priv_cb = find_pthi_read_list_entry(dev, file);
	if (!priv_cb) {
		mutex_exit(&dev->device_lock);
		return (0); /* No more data to read */
	} else {
		if (priv_cb &&
		    (currtime - priv_cb->read_time > IAMTHIF_READ_TIMER)) {
			/* 15 sec for the message has expired */
			list_del(&priv_cb->cb_list);
			mutex_exit(&dev->device_lock);
			rets = -ETIMEDOUT;
			goto free;
		}
		/* if the whole message will fit remove it from the list */
		if ((priv_cb->information >= UIO_OFFSET(uio_p)) &&
		    (UIO_LENGTH(uio_p) >=
		    (priv_cb->information - UIO_OFFSET(uio_p)))) {

			list_del(&priv_cb->cb_list);

		} else if ((priv_cb->information > 0) &&
		    (priv_cb->information <= UIO_OFFSET(uio_p))) {

			/* end of the message has been reached */
			list_del(&priv_cb->cb_list);
			rets = 0;
			mutex_exit(&dev->device_lock);
			goto free;
		}
		/*
		 * else means that not full buffer will be read and do not
		 * remove message from deletion list
		 */
	}
	DBG("pthi priv_cb->response_buffer size - %d\n",
	    priv_cb->response_buffer.size);
	DBG("pthi priv_cb->information - %lu\n",
	    priv_cb->information);
	mutex_exit(&dev->device_lock);

	rets = uiomove(priv_cb->response_buffer.data,
	    min(uio_p->uio_resid, priv_cb->information),
	    UIO_READ, uio_p);
free:
	DBG("free pthi cb memory.\n");
	kmem_free(priv_cb->request_buffer.data, priv_cb->request_buffer.size);
	kmem_free(priv_cb->response_buffer.data, priv_cb->response_buffer.size);
	kmem_free(priv_cb, sizeof (struct heci_cb_private));
	return (rets);
}

/*
 * heci_start_read  - the start read client message function.
 *
 * @dev: Device object for our driver
 * @if_num:  minor number
 * @file_ext: private data of the file object
 *
 * @return 0 on success, <0 on failure.
 */
int
heci_start_read(struct iamt_heci_device *dev, int if_num,
		    struct heci_file_private *file_ext)
{
	int rets = 0;
	uint8_t i;
	struct heci_cb_private *priv_cb = NULL;

	if ((if_num < HECI_MINOR_NUMBER) || (!dev) || (!file_ext)) {
		DBG("received wrong function input param.\n");
		return (-ENODEV);
	}
	if (file_ext->state != HECI_FILE_CONNECTED)
		return (-ENODEV);

	mutex_enter(&dev->device_lock);
	if (dev->heci_state != HECI_ENABLED) {
		mutex_exit(&dev->device_lock);
		return (-ENODEV);
	}
	mutex_exit(&dev->device_lock);
	DBG("check if read is pending.\n");
	if ((file_ext->read_pending) || (file_ext->read_cb != NULL)) {
		DBG("read is pending.\n");
		return (-EBUSY);
	}
	priv_cb = kmem_zalloc(sizeof (struct heci_cb_private), KM_SLEEP);
	if (!priv_cb)
		return (-ENOMEM);

	DBG("allocation call back success\n"
	    "host client = %d, ME client = %d\n",
	    file_ext->host_client_id, file_ext->me_client_id);
	mutex_enter(&dev->device_lock);
	for (i = 0; i < dev->num_heci_me_clients; i++) {
		if (dev->me_clients[i].client_id == file_ext->me_client_id)
			break;

	}

	ASSERT(dev->me_clients[i].client_id == file_ext->me_client_id);
	if (i == dev->num_heci_me_clients) {
		rets = -ENODEV;
		goto unlock;
	}

	priv_cb->response_buffer.size = dev->me_clients[i].props.max_msg_length;
	mutex_exit(&dev->device_lock);
	priv_cb->response_buffer.data =
	    kmem_zalloc(priv_cb->response_buffer.size, KM_SLEEP);
	if (!priv_cb->response_buffer.data) {
		rets = -ENOMEM;
		goto fail;
	}
	DBG("allocation call back data success.\n");
	priv_cb->major_file_operations = HECI_READ;
	/* make sure information is zero before we start */
	priv_cb->information = 0;
	priv_cb->file_private = (void *)file_ext;
	file_ext->read_cb = priv_cb;
	mutex_enter(&dev->device_lock);
	if (dev->host_buffer_is_empty) {
		dev->host_buffer_is_empty = 0;
		if (!heci_send_flow_control(dev, file_ext)) {
			rets = -ENODEV;
			goto unlock;
		} else {
			list_add_tail(&priv_cb->cb_list,
			    &dev->read_list.heci_cb.cb_list);
		}
	} else {
		list_add_tail(&priv_cb->cb_list,
		    &dev->ctrl_wr_list.heci_cb.cb_list);
	}
	mutex_exit(&dev->device_lock);
	return (rets);
unlock:
	mutex_exit(&dev->device_lock);
fail:
	heci_free_cb_private(priv_cb);
	return (rets);
}

/*
 * pthi_write: write iamthif data to pthi client
 *
 * @dev: Device object for our driver
 * @priv_cb: heci call back struct
 *
 * @return 0 on success, <0 on failure.
 */
int
pthi_write(struct iamt_heci_device *dev,
	struct heci_cb_private *priv_cb)
{
	int rets = 0;
	struct heci_msg_hdr heci_hdr;

	if ((!dev) || (!priv_cb))
		return (-ENODEV);

	DBG("write data to pthi client.\n");

	dev->iamthif_state = HECI_IAMTHIF_WRITING;
	dev->iamthif_current_cb = priv_cb;
	dev->iamthif_file_object = priv_cb->file_object;
	dev->iamthif_canceled = 0;
	dev->iamthif_ioctl = 1;
	dev->iamthif_msg_buf_size = priv_cb->request_buffer.size;
	(void) memcpy(dev->iamthif_msg_buf, priv_cb->request_buffer.data,
	    priv_cb->request_buffer.size);

	if (flow_ctrl_creds(dev, &dev->iamthif_file_ext) &&
	    dev->host_buffer_is_empty) {
		dev->host_buffer_is_empty = 0;
		if (priv_cb->request_buffer.size >
		    (((dev->host_hw_state & H_CBD) >> 24) *
		    sizeof (uint32_t)) - sizeof (struct heci_msg_hdr)) {
			heci_hdr.length =
			    (((dev->host_hw_state & H_CBD) >> 24) *
			    sizeof (uint32_t)) - sizeof (struct heci_msg_hdr);
			heci_hdr.msg_complete = 0;
		} else {
			heci_hdr.length = priv_cb->request_buffer.size;
			heci_hdr.msg_complete = 1;
		}

		heci_hdr.host_addr = dev->iamthif_file_ext.host_client_id;
		heci_hdr.me_addr = dev->iamthif_file_ext.me_client_id;
		heci_hdr.reserved = 0;
		dev->iamthif_msg_buf_index += heci_hdr.length;
		if (!heci_write_message(dev, &heci_hdr,
		    (unsigned char *)(dev->iamthif_msg_buf),
		    heci_hdr.length))
			return (-ENODEV);

		if (heci_hdr.msg_complete) {
			flow_ctrl_reduce(dev, &dev->iamthif_file_ext);
			dev->iamthif_flow_control_pending = 1;
			dev->iamthif_state = HECI_IAMTHIF_FLOW_CONTROL;
			DBG("add pthi cb to write waiting list\n");
			dev->iamthif_current_cb = priv_cb;
			dev->iamthif_file_object = priv_cb->file_object;
			list_add_tail(&priv_cb->cb_list,
			    &dev->write_waiting_list.heci_cb.cb_list);
		} else {
			DBG("message does not complete, "
			    "so add pthi cb to write list.\n");
			list_add_tail(&priv_cb->cb_list,
			    &dev->write_list.heci_cb.cb_list);
		}
	} else {
		if (!(dev->host_buffer_is_empty))
			DBG("host buffer is not empty");

		DBG("No flow control credentials, "
		    "so add iamthif cb to write list.\n");
		list_add_tail(&priv_cb->cb_list,
		    &dev->write_list.heci_cb.cb_list);
	}
	return (rets);
}

/*
 * iamthif_ioctl_send_msg - send cmd data to pthi client
 *
 * @dev: Device object for our driver
 *
 * @return 0 on success, <0 on failure.
 */
void
run_next_iamthif_cmd(struct iamt_heci_device *dev)
{
	struct heci_file_private *file_ext_tmp;
	struct heci_cb_private *priv_cb_pos = NULL;
	struct heci_cb_private *priv_cb_next = NULL;
	int status = 0;

	if (!dev)
		return;

	dev->iamthif_msg_buf_size = 0;
	dev->iamthif_msg_buf_index = 0;
	dev->iamthif_canceled = 0;
	dev->iamthif_ioctl = 1;
	dev->iamthif_state = HECI_IAMTHIF_IDLE;
	dev->iamthif_timer = 0;
	dev->iamthif_file_object = NULL;

	if (dev->pthi_cmd_list.status == 0 &&
	    !list_empty(&dev->pthi_cmd_list.heci_cb.cb_list)) {
		DBG("complete pthi cmd_list cb.\n");

		list_for_each_entry_safe(priv_cb_pos, priv_cb_next,
		    &dev->pthi_cmd_list.heci_cb.cb_list, cb_list,
		    struct heci_cb_private) {

			list_del(&priv_cb_pos->cb_list);
			file_ext_tmp = (struct heci_file_private *)
					priv_cb_pos->file_private;

			if ((file_ext_tmp != NULL) &&
			    (file_ext_tmp == &dev->iamthif_file_ext)) {
				status = pthi_write(dev, priv_cb_pos);
				if (status != 0) {
					DBG("pthi write failed status = %d\n",
							status);
					return;
				}
				break;
			}
		}
	}
}

/*
 * heci_free_cb_private - free heci_cb_private related memory
 *
 * @priv_cb: heci callback struct
 */
void
heci_free_cb_private(struct heci_cb_private *priv_cb)
{
	if (priv_cb == NULL)
		return;

	kmem_free(priv_cb->request_buffer.data, priv_cb->request_buffer.size);
	kmem_free(priv_cb->response_buffer.data, priv_cb->response_buffer.size);
	kmem_free(priv_cb, sizeof (struct heci_cb_private));
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
