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


/*
 * USBA: Solaris USB Architecture support
 *
 * Utility functions
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/strsun.h>

extern void usba_free_evdata(usba_evdata_t *);

static mblk_t *usba_get_cfg_cloud(dev_info_t *, usb_pipe_handle_t, int);

/* local functions */
static	int	usba_sync_set_cfg(dev_info_t *, usba_ph_impl_t *,
			usba_pipe_async_req_t *, usb_flags_t);
static int	usba_sync_set_alt_if(dev_info_t *, usba_ph_impl_t *,
			usba_pipe_async_req_t *, usb_flags_t);
static int	usba_sync_clear_feature(dev_info_t *, usba_ph_impl_t *,
			usba_pipe_async_req_t *, usb_flags_t);

/*
 * Wrapper functions returning parsed standard descriptors without
 * getting the config cloud first but by just providing the dip.
 *
 * The client can easily retrieve the device and config descriptor from
 * the usb registration and no separate functions are provided
 *
 * These functions return failure if the full descriptor can not be
 * retrieved.  These functions will not access the device.
 * The caller must allocate the buffer.
 */

/*
 * usb_get_if_descr:
 *	Function to get the cooked interface descriptor
 *	This function will not access the device.
 *
 * Arguments:
 *	dip			- pointer to devinfo of the client
 *	if_index		- interface index
 *	alt_setting	- alt interface setting
 *	descr			- pointer to user allocated interface descr
 *
 * Return Values:
 *	USB_SUCCESS	- descriptor is valid
 *	USB_FAILURE	- full descriptor could not be retrieved
 *	USB_*		- refer to usbai.h
 */
int
usb_get_if_descr(dev_info_t	*dip,
		uint_t		if_index,
		uint_t		alt_setting,
		usb_if_descr_t	*descr)
{
	uchar_t		*usb_cfg;	/* buf for config descriptor */
	size_t		size, cfg_length;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_if_descr: %s, index=0x%x, alt#=0x%x",
	    ddi_node_name(dip), if_index, alt_setting);

	if ((dip == NULL) || (descr == NULL)) {

		return (USB_INVALID_ARGS);
	}

	usb_cfg = usb_get_raw_cfg_data(dip, &cfg_length);
	size = usb_parse_if_descr(usb_cfg, cfg_length,
	    if_index,	/* interface index */
	    alt_setting,	/* alt interface index */
	    descr,
	    USB_IF_DESCR_SIZE);

	if (size != USB_IF_DESCR_SIZE) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "parsing interface: size (%lu) != USB_IF_DESCR_SIZE (%d)",
		    size, USB_IF_DESCR_SIZE);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * usb_get_ep_descr:
 *	Function to get the cooked endpoint descriptor
 *	This function will not access the device.
 *
 * Arguments:
 *	dip			- pointer to devinfo of the client
 *	if_index		- interface index
 *	alt_setting		- alternate interface setting
 *	endpoint_index		- endpoint index
 *	descr			- pointer to user allocated interface descr
 *
 * Return Values:
 *	USB_SUCCESS	- descriptor is valid
 *	USB_FAILURE	- full descriptor could not be retrieved
 *	USB_*		- refer to usbai.h
 */
int
usb_get_ep_descr(dev_info_t	*dip,
		uint_t		if_index,
		uint_t		alt_setting,
		uint_t		endpoint_index,
		usb_ep_descr_t	*descr)
{
	uchar_t		*usb_cfg;	/* buf for config descriptor */
	size_t		size, cfg_length;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_ep_descr: %s, index=0x%x, alt#=0x%x",
	    ddi_node_name(dip), if_index, alt_setting);

	if ((dip == NULL) || (descr == NULL)) {

		return (USB_INVALID_ARGS);
	}

	usb_cfg = usb_get_raw_cfg_data(dip, &cfg_length);
	size = usb_parse_ep_descr(usb_cfg, cfg_length,
	    if_index,	/* interface index */
	    alt_setting,	/* alt interface index */
	    endpoint_index,		/* ep index */
	    descr, USB_EP_DESCR_SIZE);

	if (size != USB_EP_DESCR_SIZE) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "parsing endpoint: size (%lu) != USB_EP_DESCR_SIZE (%d)",
		    size, USB_EP_DESCR_SIZE);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * usb_lookup_ep_data:
 * usb_get_ep_data (deprecated):
 *	Function to get specific endpoint descriptor data
 *	This function will not access the device.
 *
 * Arguments:
 *	dip		- pointer to dev info
 *	usb_client_dev_data_t - pointer to registration data
 *	interface	- requested interface
 *	alternate	- requested alternate
 *	skip		- how many to skip
 *	type		- endpoint type
 *	direction	- endpoint direction or USB_DIR_DONT_CARE
 *
 * Return Values:
 *	NULL or an endpoint descriptor pointer
 */
usb_ep_data_t *
usb_lookup_ep_data(dev_info_t	*dip,
		usb_client_dev_data_t *dev_datap,
		uint_t		interface,
		uint_t		alternate,
		uint_t		skip,
		uint_t		type,
		uint_t		dir)
{
	usb_alt_if_data_t	*altif_data;
	int			i;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_lookup_ep_data: "
	    "if=%d alt=%d skip=%d type=%d dir=%d",
	    interface, alternate, skip, type, dir);

	if ((dip == NULL) || (dev_datap == NULL)) {

		return (NULL);
	}

	altif_data = &dev_datap->dev_curr_cfg->
	    cfg_if[interface].if_alt[alternate];

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "altif=0x%p n_ep=%d", (void *)altif_data, altif_data->altif_n_ep);

	for (i = 0; i < altif_data->altif_n_ep; i++) {
		usb_ep_descr_t *ept = &altif_data->altif_ep[i].ep_descr;
		uint8_t	ept_type = ept->bmAttributes & USB_EP_ATTR_MASK;
		uint8_t ept_dir = ept->bEndpointAddress & USB_EP_DIR_MASK;

		if (ept->bLength == 0) {
			continue;
		}
		if ((ept_type == type) &&
		    ((type == USB_EP_ATTR_CONTROL) || (dir == ept_dir))) {

			if (skip-- == 0) {
				USB_DPRINTF_L4(DPRINT_MASK_USBA,
				    usbai_log_handle,
				    "usb_get_ep_data: data=0x%p",
				    (void *)&altif_data->altif_ep[i]);

				return (&altif_data->altif_ep[i]);
			}
		}
	}
	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_ep_data: returning NULL");

	return (NULL);
}


/*ARGSUSED*/
usb_ep_data_t *
usb_get_ep_data(dev_info_t	*dip,
		usb_client_dev_data_t *dev_datap,
		uint_t		interface,
		uint_t		alternate,
		uint_t		type,
		uint_t		dir)
{
	return (usb_lookup_ep_data(dip, dev_datap, interface,
	    alternate, 0, type, dir));
}


/*
 * usb_get_string_descr:
 *	Function to read the string descriptor
 *	This function will access the device and block.
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *	langid		- LANGID to read different LOCALEs
 *	index		- index to the string
 *	buf		- user provided buffer for string descriptor
 *	buflen		- user provided length of the buffer
 *
 * Return Values:
 *	USB_SUCCESS	- descriptor is valid
 *	USB_FAILURE	- full descriptor could not be retrieved
 *	USB_*		- refer to usbai.h
 */
int
usb_get_string_descr(dev_info_t *dip,
		uint16_t	langid,
		uint8_t 	index,
		char		*buf,
		size_t		buflen)
{
	mblk_t		*data = NULL;
	uint16_t	length;
	int		rval;
	usb_cr_t	completion_reason;
	size_t		len;
	usb_cb_flags_t	cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_string_descr: %s, langid=0x%x index=0x%x",
	    ddi_node_name(dip), langid, index);

	if ((dip == NULL) || (buf == NULL) || (buflen == 0) || (index == 0)) {

		return (USB_INVALID_ARGS);
	}

	/*
	 * determine the length of the descriptor
	 */
	rval = usb_pipe_sync_ctrl_xfer(dip,
	    usba_get_dflt_pipe_handle(dip),
	    USB_DEV_REQ_DEV_TO_HOST,
	    USB_REQ_GET_DESCR,
	    USB_DESCR_TYPE_STRING << 8 | index & 0xff,
	    langid,
	    4,
	    &data, USB_ATTRS_SHORT_XFER_OK,
	    &completion_reason,
	    &cb_flags, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usbai_log_handle,
		    "rval=%d cr=%d", rval, completion_reason);

		goto done;
	}
	if (MBLKL(data) == 0) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usbai_log_handle,
		    "0 bytes received");

		goto done;
	}

	ASSERT(data);
	length = *(data->b_rptr);
	freemsg(data);
	data = NULL;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "rval=%d, cr=%d, length=%d", rval, completion_reason, length);

	/*
	 * if length is zero the next control request may fail.
	 * the HCD may not support a zero length control request
	 * and return an mblk_t which is NULL along with rval
	 * being USB_SUCCESS and "cr" being USB_CR_OK
	 */
	if (length < 2) {
		rval = USB_FAILURE;

		goto done;
	}

	rval = usb_pipe_sync_ctrl_xfer(dip,
	    usba_get_dflt_pipe_handle(dip),
	    USB_DEV_REQ_DEV_TO_HOST,
	    USB_REQ_GET_DESCR,
	    USB_DESCR_TYPE_STRING << 8 | index & 0xff,
	    langid,
	    length,
	    &data, USB_ATTRS_SHORT_XFER_OK,
	    &completion_reason,
	    &cb_flags, USB_FLAGS_SLEEP);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "rval=%d, cb_flags=%d, cr=%d", rval, cb_flags, completion_reason);

	if ((data == NULL) || (rval != USB_SUCCESS)) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usbai_log_handle,
		    "failed to get string descriptor (rval=%d cr=%d)",
		    rval, completion_reason);

		goto done;
	}

	if ((length = MBLKL(data)) != 0) {
		len = usba_ascii_string_descr(data->b_rptr, length, buf,
		    buflen);
		USB_DPRINTF_L4(DPRINT_MASK_USBA,
		    usbai_log_handle, "buf=%s buflen=%lu", buf, len);

		ASSERT(len <= buflen);
	} else {
		rval = USB_FAILURE;
	}
done:
	freemsg(data);

	return (rval);
}


/*
 * usb_get_dev_descr:
 *	 utility function to get device descriptor from usba_device
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *
 * Return Values:
 *	usb_dev_descr	- device  descriptor or NULL
 */
usb_dev_descr_t *
usb_get_dev_descr(dev_info_t *dip)
{
	usba_device_t	*usba_device;
	usb_dev_descr_t *usb_dev_descr = NULL;

	if (dip) {
		USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
		    "usb_get_dev_descr: %s", ddi_node_name(dip));

		usba_device = usba_get_usba_device(dip);
		mutex_enter(&usba_device->usb_mutex);
		usb_dev_descr = usba_device->usb_dev_descr;
		mutex_exit(&usba_device->usb_mutex);
	}

	return (usb_dev_descr);
}


/*
 * usb_get_raw_cfg_data:
 *	 utility function to get raw config descriptor from usba_device
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *	length		- pointer to copy the cfg length
 *
 * Return Values:
 *	usb_cfg	- raw config descriptor
 */
uchar_t *
usb_get_raw_cfg_data(dev_info_t *dip, size_t *length)
{
	usba_device_t	*usba_device;
	uchar_t		*usb_cfg;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_raw_cfg_data: %s", ddi_node_name(dip));

	if ((dip == NULL) || (length == NULL)) {

		return (NULL);
	}

	usba_device = usba_get_usba_device(dip);

	mutex_enter(&usba_device->usb_mutex);
	usb_cfg = usba_device->usb_cfg;
	*length = usba_device->usb_cfg_length;
	mutex_exit(&usba_device->usb_mutex);

	return (usb_cfg);
}


/*
 * usb_get_addr:
 *	utility function to return current usb address, mostly
 *	for debugging purposes
 *
 * Arguments:
 *	dip	- pointer to devinfo of the client
 *
 * Return Values:
 *	address	- USB Device Address
 */
int
usb_get_addr(dev_info_t *dip)
{
	int address = 0;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_addr: %s", ddi_node_name(dip));

	if (dip) {
		usba_device_t	*usba_device = usba_get_usba_device(dip);

		mutex_enter(&usba_device->usb_mutex);
		address = usba_device->usb_addr;
		mutex_exit(&usba_device->usb_mutex);
	}

	return (address);
}


/*
 * usb_set_cfg():
 *	set configuration, use with caution (issues USB_REQ_SET_CONFIG)
 *	Changing configuration will fail if pipes are still open or when
 *	invoked from a driver bound to an interface on a composite device.
 *
 *	This function will access the device and block
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *	cfg_index	- config index
 *	cfg_value	- config value to be set
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for completion
 *	cb		- if USB_FLAGS_SLEEP has not been specified
 *			  this callback function will be called on
 *			  completion. This callback may be NULL
 *			  and no notification of completion will then
 *			  be provided.
 *	cb_arg		- 2nd argument to callback function.
 *
 * Return Values:
 *	USB_SUCCESS:	- new configuration was set
 *	USB_FAILURE:	- new configuration could not be set
 *	USB_BUSY:	- some pipes were open or there were children
 *	USB_*		- refer to usbai.h
 */
int
usb_set_cfg(dev_info_t		*dip,
		uint_t		cfg_index,
		usb_flags_t	usb_flags,
		void		(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
		usb_opaque_t	cb_arg)
{
	usb_pipe_handle_t	ph;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_set_cfg: %s%d, cfg_index = 0x%x, uf = 0x%x",
	    ddi_driver_name(dip), ddi_get_instance(dip), cfg_index,
	    usb_flags);

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	if ((usb_flags & USB_FLAGS_SLEEP) && servicing_interrupt()) {

		return (USB_INVALID_CONTEXT);
	}

	if (!usb_owns_device(dip)) {

		return (USB_INVALID_PERM);
	}

	ph = usba_get_dflt_pipe_handle(dip);
	if (usba_hold_ph_data(ph) == NULL) {

		return (USB_INVALID_PIPE);
	}

	return (usba_pipe_setup_func_call(dip,
	    usba_sync_set_cfg, (usba_ph_impl_t *)ph,
	    (usb_opaque_t)((uintptr_t)cfg_index), usb_flags, cb, cb_arg));
}


static int
usba_sync_set_cfg(dev_info_t	*dip,
		usba_ph_impl_t	*ph_impl,
		usba_pipe_async_req_t	*request,
		usb_flags_t	flags)
{
	int		rval;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	usba_device_t	*usba_device;
	int		i, ph_open_cnt;
	uint_t		cfg_index = (uint_t)((uintptr_t)(request->arg));
	size_t		size;
	usb_cfg_descr_t confdescr;
	dev_info_t	*pdip;

	usba_device = usba_get_usba_device(dip);

	/*
	 * default pipe is still open
	 * all other pipes should be closed
	 */
	for (ph_open_cnt = 0, i = 1; i < USBA_N_ENDPOINTS; i++) {
		if (usba_device->usb_ph_list[i].usba_ph_data) {
			ph_open_cnt++;
			break;
		}
	}

	if (ph_open_cnt || ddi_get_child(dip)) {
		usba_release_ph_data(ph_impl);

		return (USB_BUSY);
	}

	/*
	 * check if the configuration meets the
	 * power budget requirement
	 */
	if (usba_is_root_hub(dip)) {
		/*
		 * root hub should never be multi-configured.
		 * the code is here just to ensure
		 */
		usba_release_ph_data(ph_impl);

		return (USB_FAILURE);
	}
	pdip = ddi_get_parent(dip);

	/*
	 * increase the power budget value back to the unconfigured
	 * state to eliminate the influence of the old configuration
	 * before checking the new configuration; but remember to
	 * make a decrement before leaving this routine to restore
	 * the power consumption state of the device no matter it
	 * is in the new or old configuration
	 */
	usba_hubdi_incr_power_budget(pdip, usba_device);

	if ((usba_hubdi_check_power_budget(pdip, usba_device,
	    cfg_index)) != USB_SUCCESS) {
		usba_hubdi_decr_power_budget(pdip, usba_device);

		usba_release_ph_data(ph_impl);

		return (USB_FAILURE);
	}

	size = usb_parse_cfg_descr(usba_device->usb_cfg_array[cfg_index],
	    USB_CFG_DESCR_SIZE, &confdescr, USB_CFG_DESCR_SIZE);

	/* hubdi should ensure that this descriptor is correct */
	ASSERT(size == USB_CFG_DESCR_SIZE);

	/* set the configuration */
	rval = usb_pipe_sync_ctrl_xfer(dip, (usb_pipe_handle_t)ph_impl,
	    USB_DEV_REQ_HOST_TO_DEV,
	    USB_REQ_SET_CFG,
	    confdescr.bConfigurationValue,
	    0,
	    0,
	    NULL, 0,
	    &completion_reason,
	    &cb_flags, flags | USBA_FLAGS_PRIVILEGED | USB_FLAGS_SLEEP);

	if (rval == USB_SUCCESS) {
		mutex_enter(&usba_device->usb_mutex);
		usba_device->usb_cfg_value = confdescr.bConfigurationValue;
		usba_device->usb_active_cfg_ndx = cfg_index;
		usba_device->usb_cfg = usba_device->usb_cfg_array[cfg_index];
		usba_device->usb_cfg_length = confdescr.wTotalLength;
		mutex_exit(&usba_device->usb_mutex);

		/* update the configuration property */
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "configuration#", usba_device->usb_cfg_value);
	}

	/*
	 * usba_device->usb_cfg always stores current configuration
	 * descriptor no matter SET_CFG request succeeded or not,
	 * so usba_hubdi_decr_power_budget can be done regardless
	 * of rval above
	 */
	usba_hubdi_decr_power_budget(pdip, usba_device);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "rval=%d, cb_flags=%d, cr=%d", rval, cb_flags, completion_reason);

	usba_release_ph_data(ph_impl);

	return (rval);
}



/*
 * usb_get_cfg():
 *	get configuration value
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *	cfg_value	- current config value
 *	flags		- none, always blocks
 *
 * Return Values:
 *	USB_SUCCESS:	- config value was retrieved
 *	USB_FAILURE:	- config value could not be retrieved
 *	USB_*		- refer to usbai.h
 */
int
usb_get_cfg(dev_info_t		*dip,
		uint_t		*cfgval,
		usb_flags_t	flags)
{
	int		rval;
	usb_cr_t	completion_reason;
	mblk_t		*data = NULL;
	usb_cb_flags_t	cb_flags;
	usb_pipe_handle_t ph;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_cfg: %s uf = 0x%x", ddi_node_name(dip), flags);

	if ((cfgval == NULL) || (dip == NULL)) {

		return (USB_INVALID_ARGS);
	}

	ph = usba_get_dflt_pipe_handle(dip);

	/*
	 * get the cfg value
	 */
	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_RCPT_DEV,
	    USB_REQ_GET_CFG,
	    0,
	    0,
	    1,		/* returns one byte of data */
	    &data, 0,
	    &completion_reason,
	    &cb_flags, flags);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "rval=%d cb_flags=%d cr=%d", rval, cb_flags, completion_reason);

	if ((rval == USB_SUCCESS) && data &&
	    (MBLKL(data) == 1)) {
		*cfgval = *(data->b_rptr);
	} else {
		*cfgval = 1;
		if (rval == USB_SUCCESS) {
			rval = USB_FAILURE;
		}
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_cfg: %s cfgval=%d", ddi_node_name(dip), *cfgval);

	freemsg(data);

	return (rval);
}


/*
 * usb_get_current_cfgidx:
 *	get current current config index
 */
uint_t
usb_get_current_cfgidx(dev_info_t *dip)
{
	usba_device_t	*usba_device = usba_get_usba_device(dip);
	uint_t		ndx;

	mutex_enter(&usba_device->usb_mutex);
	ndx = usba_device->usb_active_cfg_ndx;
	mutex_exit(&usba_device->usb_mutex);

	return (ndx);
}


/*
 * usb_get_if_number:
 *	get usb interface number of current OS device node.
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *
 * Return Values:
 *	USB_COMBINED_NODE if the driver is responsible for the entire
 *	    device and this dip doesn't correspond to a device node.
 *	USB_DEVICE_NODE if the driver is responsible for the entire device
 *	    and this dip corresponds to a device node.
 *	interface number: otherwise.
 */
int
usb_get_if_number(dev_info_t *dip)
{
	int interface_num;
	usba_device_t	*usba_device = usba_get_usba_device(dip);
	usb_dev_descr_t	*usb_dev_descr;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_if_number: dip = 0x%p", (void *)dip);

	/* not quite right but we can't return a negative return value */
	if (dip == NULL) {

		return (0);
	}

	if (usba_device) {
		usb_dev_descr = usba_device->usb_dev_descr;
	} else {

		return (0);
	}

	interface_num = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "interface", USB_COMBINED_NODE);

	if (interface_num == USB_COMBINED_NODE) {
		if (!(((usb_dev_descr->bDeviceClass == USB_CLASS_HUB) ||
		    (usb_dev_descr->bDeviceClass == 0)) &&
		    (usba_device->usb_n_cfgs == 1) &&
		    (usba_device->usb_n_ifs == 1))) {
			interface_num = USB_DEVICE_NODE;
		}
	}

	return (interface_num);
}


boolean_t
usb_owns_device(dev_info_t *dip)
{
	int interface_num = usb_get_if_number(dip);

	return (interface_num < 0 ? B_TRUE : B_FALSE);
}


/* check whether the interface is in this interface association */
boolean_t
usba_check_if_in_ia(dev_info_t *dip, int n_if)
{
	int first_if, if_count;

	first_if = usb_get_if_number(dip);
	if_count = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "interface-count", -1);
	if_count += first_if;

	return ((n_if >= first_if && n_if < if_count) ? B_TRUE : B_FALSE);
}


uint8_t
usba_get_ifno(dev_info_t *dip)
{
	int interface_num = usb_get_if_number(dip);

	return (uint8_t)(interface_num < 0 ? 0 : interface_num);
}


/*
 * usb_set_alt_if:
 *	set the alternate interface number. Issues USB_REQ_SET_IF
 *	This function will access the device
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *	if_number	- interface number
 *	alt_number	- alternate interface number
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for completion
 *	cb		- if USB_FLAGS_SLEEP has not been specified
 *			  this callback function will be called on
 *			  completion. This callback may be NULL
 *			  and no notification of completion will then
 *			  be provided.
 *	cb_arg		- 2nd argument to callback function.
 *
 *
 * return values:
 *	USB_SUCCESS	- alternate was set
 *	USB_FAILURE	- alternate could not be set because pipes
 *			  were still open or some access error occurred
 *	USB_*		- refer to usbai.h
 *
 * Note:
 *	we can't easily check if all pipes to endpoints for this interface
 *	are closed since we don't have a map of which endpoints belong
 *	to which interface. If we had this map, we would need to update
 *	this on each alternative or configuration switch
 */
int
usb_set_alt_if(dev_info_t	*dip,
		uint_t		interface,
		uint_t		alt_number,
		usb_flags_t	usb_flags,
		void		(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
		usb_opaque_t	cb_arg)
{
	usb_pipe_handle_t	ph;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_set_alt_if: %s%d, if = %d alt = %d, uf = 0x%x",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    interface, alt_number, usb_flags);

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	if ((usb_flags & USB_FLAGS_SLEEP) && servicing_interrupt()) {

		return (USB_INVALID_CONTEXT);
	}

	ph = usba_get_dflt_pipe_handle(dip);
	if (usba_hold_ph_data(ph) == NULL) {

		return (USB_INVALID_PIPE);
	}

	return (usba_pipe_setup_func_call(dip,
	    usba_sync_set_alt_if, (usba_ph_impl_t *)ph,
	    (usb_opaque_t)((uintptr_t)((interface << 8) | alt_number)),
	    usb_flags, cb, cb_arg));
}


static int
usba_sync_set_alt_if(dev_info_t	*dip,
		usba_ph_impl_t	*ph_impl,
		usba_pipe_async_req_t	*request,
		usb_flags_t	flags)
{
	int		rval;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	usb_opaque_t	arg = request->arg;
	int		interface = ((uintptr_t)arg >> 8) & 0xff;
	int		alt_number = (uintptr_t)arg & 0xff;
	usba_pipe_handle_data_t *ph_data = usba_get_ph_data(
	    (usb_pipe_handle_t)ph_impl);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_set_alt_if: %s, interface#=0x%x, alt#=0x%x, "
	    "uf=0x%x", ddi_node_name(dip), interface,
	    alt_number, flags);

	/* if we don't own the device, we must own the interface or ia */
	if (!usb_owns_device(dip) && !usba_check_if_in_ia(dip, interface) &&
	    (interface != usb_get_if_number(dip))) {
		usba_release_ph_data(ph_data->p_ph_impl);

		return (USB_INVALID_PERM);
	}

	/* set the alternate setting */
	rval = usb_pipe_sync_ctrl_xfer(dip, usba_get_dflt_pipe_handle(dip),
	    USB_DEV_REQ_HOST_TO_DEV | USB_DEV_REQ_RCPT_IF,
	    USB_REQ_SET_IF,
	    alt_number,
	    interface,
	    0,
	    NULL, 0,
	    &completion_reason,
	    &cb_flags, flags | USB_FLAGS_SLEEP);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "rval=%d, cb_flags=%d, cr=%d", rval, cb_flags, completion_reason);

	usba_release_ph_data(ph_data->p_ph_impl);

	return (rval);
}


/*
 * usb_get_alt_if:
 *	get the alternate interface number. Issues USB_REQ_GET_IF
 *	This function will access the device and block
 *
 * Arguments:
 *	dip			- pointer to devinfo of the client
 *	if_number	- interface number
 *	alt_number	- alternate interface number
 *	flags			- none but USB_FLAGS_SLEEP may be passed
 *
 * return values:
 *	USB_SUCCESS:		alternate was set
 *	USB_FAILURE:		alternate could not be set because pipes
 *				were still open or some access error occurred
 */
int
usb_get_alt_if(dev_info_t	*dip,
		uint_t		if_number,
		uint_t		*alt_number,
		usb_flags_t	flags)
{
	int		rval;
	usb_cr_t	completion_reason;
	mblk_t		*data = NULL;
	usb_cb_flags_t	cb_flags;
	usb_pipe_handle_t ph;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_alt_if: %s, interface# = 0x%x, altp = 0x%p, "
	    "uf = 0x%x", ddi_node_name(dip), if_number,
	    (void *)alt_number, flags);

	if ((alt_number == NULL) || (dip == NULL)) {

		return (USB_INVALID_ARGS);
	}

	ph = usba_get_dflt_pipe_handle(dip);

	/*
	 * get the alternate setting
	 */
	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_RCPT_IF,
	    USB_REQ_GET_IF,
	    0,
	    if_number,
	    1,		/* returns one byte of data */
	    &data, 0,
	    &completion_reason,
	    &cb_flags, flags);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "rval=%d cb_flags=%d cr=%d", rval, cb_flags, completion_reason);

	if ((rval == USB_SUCCESS) && data &&
	    (MBLKL(data) == 1)) {
		*alt_number = *(data->b_rptr);
	} else {
		*alt_number = 0;
		if (rval == USB_SUCCESS) {
			rval = USB_FAILURE;
		}
	}

	freemsg(data);

	return (rval);
}


/*
 * usba_get_cfg_cloud:
 *	Get descriptor cloud for a given configuration.
 *
 * Arguments:
 *	dip			- pointer to devinfo of the client
 *	default_ph		- default pipe handle
 *	cfg			- which configuration to retrieve raw cloud of
 *
 * Returns:
 *	on success: mblock containing the raw data.  Caller must free.
 *	on failure: NULL
 */
static mblk_t *
usba_get_cfg_cloud(dev_info_t *dip, usb_pipe_handle_t default_ph, int cfg)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	usb_cfg_descr_t cfg_descr;
	mblk_t		*pdata = NULL;

	if (usb_pipe_sync_ctrl_xfer(dip, default_ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
	    USB_REQ_GET_DESCR,
	    USB_DESCR_TYPE_SETUP_CFG | cfg,
	    0,
	    USB_CFG_DESCR_SIZE,
	    &pdata,
	    0,
	    &completion_reason,
	    &cb_flags,
	    0) != USB_SUCCESS) {

		freemsg(pdata);

		return (NULL);
	}

	(void) usb_parse_cfg_descr(pdata->b_rptr,
	    MBLKL(pdata), &cfg_descr, USB_CFG_DESCR_SIZE);
	freemsg(pdata);
	pdata = NULL;

	if (usb_pipe_sync_ctrl_xfer(dip, default_ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
	    USB_REQ_GET_DESCR,
	    USB_DESCR_TYPE_SETUP_CFG | cfg,
	    0,
	    cfg_descr.wTotalLength,
	    &pdata,
	    0,
	    &completion_reason,
	    &cb_flags,
	    0) != USB_SUCCESS) {

		freemsg(pdata);

		return (NULL);
	}

	return (pdata);
}

/*
 * usb_check_same_device:
 *	Check if the device connected to the port is the same as
 *	the previous device that was in the port.  The previous device is
 *	represented by the dip on record for the port.	Print a message
 *	if the device is different.  If device_string arg is not NULL, it is
 *	included in the message.  Can block.
 *
 * Arguments:
 *	dip			- pointer to devinfo of the client
 *	log_handle		- handle to which messages are logged
 *	log_level		- one of USB_LOG_*
 *	log_mask		- logging mask
 *	check_mask		- one mask containing things to check:
 *					USB_CHK_BASIC: empty mask;
 *						these checks are always done.
 *					USB_CHK_VIDPID:
 *						check vid, pid only.
 *					USB_CHK_SERIAL: check match on device
 *						serial number.
 *					USB_CHK_CFG: check all raw config
 *						clouds for a match.
 *				NOTE: descr length and content always checked
 *	device_string		- Device string to appear in error message
 *
 * return values:
 *	USB_SUCCESS:		same device
 *	USB_INVALID_VERSION	not same device
 *	USB_FAILURE:		Failure processing request
 *	USB_INVALID_ARG:	dip is invalid
 */
int
usb_check_same_device(dev_info_t *dip, usb_log_handle_t log_handle,
    int log_level, int log_mask, uint_t check_mask, char *device_string)
{
	usb_dev_descr_t		usb_dev_descr;
	usba_device_t		*usba_device;
	mblk_t			*pdata = NULL;
	uint16_t		length;
	int			rval;
	char			*buf;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	boolean_t		match = B_TRUE;
	usb_pipe_handle_t	def_ph;

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	usba_device = usba_get_usba_device(dip);
	length = usba_device->usb_dev_descr->bLength;
	def_ph = usba_get_dflt_pipe_handle(dip);
	ASSERT(def_ph);

	/* get the "new" device descriptor */
	rval = usb_pipe_sync_ctrl_xfer(dip, def_ph,
	    USB_DEV_REQ_DEV_TO_HOST |
	    USB_DEV_REQ_TYPE_STANDARD,
	    USB_REQ_GET_DESCR,		/* bRequest */
	    USB_DESCR_TYPE_SETUP_DEV,	/* wValue */
	    0,				/* wIndex */
	    length,				/* wLength */
	    &pdata, 0,
	    &completion_reason,
	    &cb_flags, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		if (!((completion_reason == USB_CR_DATA_OVERRUN) && (pdata))) {
			USB_DPRINTF_L3(DPRINT_MASK_USBA, usbai_log_handle,
			    "getting device descriptor failed (%d)", rval);
			freemsg(pdata);

			return (USB_FAILURE);
		}
	}

	ASSERT(pdata != NULL);

	(void) usb_parse_dev_descr(pdata->b_rptr,
	    MBLKL(pdata), &usb_dev_descr,
	    sizeof (usb_dev_descr_t));

	freemsg(pdata);
	pdata = NULL;

	/* Always check the device descriptor length. */
	if (usb_dev_descr.bLength != length) {
		match = B_FALSE;
	}

	if ((match == B_TRUE) && (check_mask & USB_CHK_VIDPID)) {
		match = (usba_device->usb_dev_descr->idVendor ==
		    usb_dev_descr.idVendor) &&
		    (usba_device->usb_dev_descr->idProduct ==
		    usb_dev_descr.idProduct);
	} else if (bcmp((char *)usba_device->usb_dev_descr,
	    (char *)&usb_dev_descr, length) != 0) {
		match = B_FALSE;
	}

	/* if requested & this device has a serial number check and compare */
	if ((match == B_TRUE) && ((check_mask & USB_CHK_SERIAL) != 0) &&
	    (usba_device->usb_serialno_str != NULL)) {
		buf = kmem_alloc(USB_MAXSTRINGLEN, KM_SLEEP);
		if (usb_get_string_descr(dip, USB_LANG_ID,
		    usb_dev_descr.iSerialNumber, buf,
		    USB_MAXSTRINGLEN) == USB_SUCCESS) {
			match =
			    (strcmp(buf, usba_device->usb_serialno_str) == 0);
		}
		kmem_free(buf, USB_MAXSTRINGLEN);
	}

	if ((match == B_TRUE) && (check_mask & USB_CHK_CFG)) {

		uint8_t num_cfgs = usb_dev_descr.bNumConfigurations;
		uint8_t cfg;
		mblk_t *cloud;

		for (cfg = 0; cfg < num_cfgs; cfg++) {
			cloud = usba_get_cfg_cloud(dip, def_ph, cfg);
			if (cloud == NULL) {
				USB_DPRINTF_L3(DPRINT_MASK_USBA,
				    usbai_log_handle,
				    "Could not retrieve config cloud for "
				    "comparison");
				break;
			}

			if (bcmp((char *)cloud->b_rptr,
			    usba_device->usb_cfg_array[cfg],
			    MBLKL(cloud)) != 0) {
				freemsg(cloud);
				break;
			}

			freemsg(cloud);
		}
		if (cfg != num_cfgs) {
			match = B_FALSE;
		}
	}

	if (match == B_FALSE) {
		boolean_t allocated_here = (device_string == NULL);
		if (allocated_here) {
			device_string =
			    kmem_zalloc(USB_MAXSTRINGLEN, USB_FLAGS_SLEEP);
			(void) usba_get_mfg_prod_sn_str(dip, device_string,
			    USB_MAXSTRINGLEN);
		}
		if (device_string[0] != '\0') {
			(void) usb_log(log_handle, log_level, log_mask,
			    "Cannot access %s.	Please reconnect.",
			    device_string);
		} else {
			(void) usb_log(log_handle, log_level, log_mask,
			    "Device is not identical to the "
			    "previous one this port.\n"
			    "Please disconnect and reconnect");
		}
		if (allocated_here) {
			kmem_free(device_string, USB_MAXSTRINGLEN);
		}

		return (USB_INVALID_VERSION);
	}

	return (USB_SUCCESS);
}


/*
 * usb_pipe_get_state:
 *	Return the state of the pipe
 *
 * Arguments:
 *	pipe_handle	- pipe_handle pointer
 *	pipe_state	- pointer to copy pipe state to
 *	flags:
 *		not used other than to check context
 *
 * Return Values:
 *	USB_SUCCESS	- port state returned
 *	USB_*		- refer to usbai.h
 */
int
usb_pipe_get_state(usb_pipe_handle_t	pipe_handle,
	    usb_pipe_state_t	*pipe_state,
	    usb_flags_t		usb_flags)
{
	usba_pipe_handle_data_t *ph_data = usba_hold_ph_data(pipe_handle);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_get_state: ph_data=0x%p uf=0x%x", (void *)ph_data,
	    usb_flags);

	if (pipe_state == NULL) {
		if (ph_data) {
			usba_release_ph_data(ph_data->p_ph_impl);
		}

		return (USB_INVALID_ARGS);
	}

	if (ph_data == NULL) {
		*pipe_state = USB_PIPE_STATE_CLOSED;

		return (USB_SUCCESS);
	}

	mutex_enter(&ph_data->p_mutex);
	*pipe_state = usba_get_ph_state(ph_data);
	mutex_exit(&ph_data->p_mutex);

	usba_release_ph_data(ph_data->p_ph_impl);

	return (USB_SUCCESS);
}


/*
 * usba_pipe_get_policy:
 *	Return a pipe's policy
 *
 * Arguments:
 *	pipe_handle	- pipe_handle pointer
 *
 * Return Values:
 *	On success: the pipe's policy
 *	On failure: NULL
 */
usb_pipe_policy_t
*usba_pipe_get_policy(usb_pipe_handle_t pipe_handle)
{
	usb_pipe_policy_t *pp = NULL;

	usba_pipe_handle_data_t *ph_data = usba_hold_ph_data(pipe_handle);

	if (ph_data) {
		pp = &ph_data->p_policy;

		usba_release_ph_data(ph_data->p_ph_impl);
	}

	return (pp);
}


/*
 * usb_ep_num:
 *	Return the endpoint number for a given pipe handle
 *
 * Arguments:
 *	pipe_handle	- pipe_handle pointer
 *
 * Return Values:
 *	endpoint number
 */
int
usb_ep_num(usb_pipe_handle_t pipe_handle)
{
	usba_pipe_handle_data_t *ph_data = usba_hold_ph_data(pipe_handle);
	int ep_num;

	if (ph_data == NULL) {

		return (USB_INVALID_PIPE);
	}

	mutex_enter(&ph_data->p_mutex);
	ep_num = ph_data->p_ep.bEndpointAddress & USB_EP_NUM_MASK;
	mutex_exit(&ph_data->p_mutex);

	usba_release_ph_data(ph_data->p_ph_impl);

	return (ep_num);
}


/*
 * usb_get_status
 *	Issues USB_REQ_GET_STATUS to device/endpoint/interface
 *	and report in "status" arg.
 *
 *	status reported for a "device" is
 *		RemoteWakeup enabled
 *		SelfPowered device?
 *
 *	status reported for an "interface" is NONE.
 *	status reported for an "endpoint" is
 *		HALT set (device STALLED?)
 *
 * Arguments:
 *	dip	- pointer to devinfo of the client
 *	ph	- pipe handle
 *	type	- bmRequestType to be used
 *	what	- 0 for device, otherwise interface or ep number
 *	status	- user supplied pointer for storing the status
 *	flags	- USB_FLAGS_SLEEP (mandatory)
 *
 * Return Values:
 *	valid usb_status_t	or USB_FAILURE
 */
int
usb_get_status(dev_info_t		*dip,
		usb_pipe_handle_t	ph,
		uint_t			type,	/* bmRequestType */
		uint_t			what,	/* 0, interface, ept number */
		uint16_t		*status,
		usb_flags_t		flags)
{
	int		rval;
	usb_cr_t	completion_reason;
	mblk_t		*data = NULL;
	usb_cb_flags_t	cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_get_status: type = 0x%x, what = 0x%x, uf = 0x%x",
	    type, what, flags);

	if ((status == NULL) || (dip == NULL)) {

		return (USB_INVALID_ARGS);
	}
	if (ph == NULL) {

		return (USB_INVALID_PIPE);
	}

	type |= USB_DEV_REQ_DEV_TO_HOST;

	/* get the status */
	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    type,
	    USB_REQ_GET_STATUS,
	    0,
	    what,
	    USB_GET_STATUS_LEN,	/* status is fixed 2 bytes long */
	    &data, 0,
	    &completion_reason, &cb_flags, flags);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "rval=%d, cb_flags=%d, cr=%d", rval, cb_flags, completion_reason);

	if ((rval == USB_SUCCESS) && data &&
	    (MBLKL(data) == USB_GET_STATUS_LEN)) {
		*status = (*(data->b_rptr + 1) << 8) | *(data->b_rptr);
	} else {
		*status = 0;
		if (rval == USB_SUCCESS) {
			rval = USB_FAILURE;
		}
	}

	freemsg(data);

	return (rval);
}


/*
 * usb_clear_feature:
 *	Issue USB_REQ_CLEAR_FEATURE to endpoint/device/interface
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *	ph		- pipe handle pointer
 *	type		- bmRequestType to be used
 *	feature		- feature to be cleared
 *	what		- 0 for device, otherwise interface or ep number
 *	flags		- none (but will sleep)
 *
 * Return Values:
 *	USB_SUCCESS	- on doing a successful clear feature
 *	USB_FAILURE	- on failure
 *	USB_*		- refer to usbai.h
 */
int
usb_clear_feature(dev_info_t		*dip,
		usb_pipe_handle_t	ph,
		uint_t			type,	/* bmRequestType */
		uint_t			feature,
		uint_t			what,	/* 0, interface, ept number */
		usb_flags_t		flags)
{
	int		rval;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_clear_feature: type = 0x%x, feature = 0x%x, what = 0x%x "
	    "uf = 0x%x", type, feature, what, flags);

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}
	if (ph == NULL) {

		return (USB_INVALID_PIPE);
	}

	/* issue Clear feature */
	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    type,
	    USB_REQ_CLEAR_FEATURE,
	    feature,
	    what,
	    0,
	    NULL, 0,
	    &completion_reason,
	    &cb_flags, flags | USB_FLAGS_SLEEP);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "rval=%d, cb_flags=%d, cr=%d", rval, cb_flags, completion_reason);

	return (rval);
}


/*
 * usb_clr_feature:
 *	Issue USB_REQ_CLEAR_FEATURE to endpoint/device/interface
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *	type		- bmRequestType to be used
 *	feature		- feature to be cleared
 *	what		- 0 for device, otherwise interface or ep number
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for completion
 *	cb		- if USB_FLAGS_SLEEP has not been specified
 *			  this callback function will be called on
 *			  completion. This callback may be NULL
 *			  and no notification of completion will then
 *			  be provided.
 *	cb_arg		- 2nd argument to callback function.
 *
 *
 * Return Values:
 *	USB_SUCCESS	- on doing a successful clear feature
 *	USB_FAILURE	- on failure
 *	USB_*		- refer to usbai.h
 */
int
usb_clr_feature(
		dev_info_t	*dip,
		uint_t		type,	/* bmRequestType */
		uint_t		feature,
		uint_t		what,	/* 0, interface, ept number */
		usb_flags_t	flags,
		void		(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
		usb_opaque_t	cb_arg)
{
	usb_pipe_handle_t ph;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_clr_feature: type = 0x%x, feature = 0x%x, what = 0x%x "
	    "uf = 0x%x", type, feature, what, flags);

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	if ((flags & USB_FLAGS_SLEEP) && servicing_interrupt()) {

		return (USB_INVALID_CONTEXT);
	}

	ph = usba_get_dflt_pipe_handle(dip);
	if (usba_hold_ph_data(ph) == NULL) {

		return (USB_INVALID_PIPE);
	}

	return (usba_pipe_setup_func_call(dip,
	    usba_sync_clear_feature, (usba_ph_impl_t *)ph,
	    (usb_opaque_t)((uintptr_t)((type << 16 | feature << 8 | what))),
	    flags, cb, cb_arg));
}


static int
usba_sync_clear_feature(dev_info_t *dip,
	usba_ph_impl_t		*ph_impl,
	usba_pipe_async_req_t	*req,
	usb_flags_t		usb_flags)
{
	uint_t	n = (uint_t)((uintptr_t)(req->arg));
	uint_t	type = ((uint_t)n >> 16) & 0xff;
	uint_t	feature = ((uint_t)n >> 8) & 0xff;
	uint_t	what = (uint_t)n & 0xff;
	int	rval;
	usba_device_t		*usba_device;
	usba_pipe_handle_data_t *ph_data;
	usba_ph_impl_t		*ph_im;
	uchar_t			ep_index;
	usb_ep_descr_t		*eptd;


	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_sync_clear_feature: "
	    "dip=0x%p ph=0x%p type=0x%x feature=0x%x what=0x%x fl=0x%x",
	    (void *)dip, (void *)ph_impl, type, feature, what, usb_flags);

	rval = usb_clear_feature(dip, (usb_pipe_handle_t)ph_impl, type,
	    feature, what, usb_flags);

	/*
	 * Reset data toggle to DATA0 for bulk and interrupt endpoint.
	 * Data toggle synchronization is not supported for isochronous
	 * transfer.Halt feature is not supported by control endpoint.
	 *
	 * From USB2.0 specification:
	 * 1.Section 5.8.5 Bulk Transfer Data Sequences
	 * Removal of the halt condition is achieved via software intervention
	 * through a separate control pipe. This recovery will reset the data
	 * toggle bit to DATA0 for the endpoint on both the host and the device.
	 *
	 * 2.Section 5.7.5 Interrupt Transfer Data Sequences
	 * Removal of the halt condition is achieved via software intervention
	 * through a separate control pipe. This recovery will reset the data
	 * toggle bit to DATA0 for the endpoint on both the host and the device.
	 *
	 * 3.Section 9.4.5
	 * If the condition causing a halt has been removed, clearing the Halt
	 * feature via a ClearFeature(ENDPOINT_HALT) request results in the
	 * endpoint no longer returning a STALL. For endpoints using data
	 * toggle, regardless of whether an endpoint has the Halt feature set, a
	 * ClearFeature(ENDPOINT_HALT) request always results in the data toggle
	 * being reinitialized to DATA0.
	 *
	 */
	if (rval == USB_SUCCESS && feature == 0) {
		usba_device = usba_get_usba_device(dip);
		ep_index = usb_get_ep_index((uint8_t)what);
		ph_im = &usba_device->usb_ph_list[ep_index];
		ph_data = usba_get_ph_data((usb_pipe_handle_t)ph_im);
		eptd = &ph_data->p_ep;
		if ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
		    USB_EP_ATTR_BULK || (eptd->bmAttributes &
		    USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR)
			usba_device->usb_hcdi_ops->
			    usba_hcdi_pipe_reset_data_toggle(ph_data);
	}

	usba_release_ph_data(ph_impl);

	return (rval);
}


/*
 * usb_async_req:
 *	function used to dispatch a request to the taskq
 *
 * Arguments:
 *	dip	- pointer to devinfo node
 *	func	- pointer to function issued by taskq
 *	flag	- USB_FLAGS_SLEEP mostly
 *
 * Return Values:
 *	USB_SUCCESS	- on doing a successful taskq invocation
 *	USB_FAILURE	- on failure
 *	USB_*		- refer to usbai.h
 */
int
usb_async_req(dev_info_t *dip,
		void	(*func)(void *),
		void	*arg,
		usb_flags_t flag)
{
	int tq_flag;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_async_req: dip=0x%p func=0x%p, arg=0x%p flag=0x%x",
	    (void *)dip, (void *)func, arg, flag);

	if ((dip == NULL) || (func == NULL)) {

		return (USB_INVALID_ARGS);
	}
	tq_flag = (flag & USB_FLAGS_SLEEP) ? TQ_SLEEP : TQ_NOSLEEP;
	if (flag & USB_FLAGS_NOQUEUE) {
		tq_flag |= TQ_NOQUEUE;
	}

	if (taskq_dispatch(system_taskq, func, arg,
	    tq_flag) == TASKQID_INVALID) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usbai_log_handle,
		    "usb_async_req: failure");

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}

/*
 * usba_async_ph_req:
 *	function used to dispatch a request to the ph taskq
 *
 * Arguments:
 *	ph_data	- pointer to pipe handle data
 *	func	- pointer to function issued by taskq
 *	flag	- USB_FLAGS_SLEEP or USB_FLAGS_NOSLEEP
 *
 * Return Values:
 *	USB_SUCCESS	- on doing a successful taskq invocation
 *	USB_FAILURE	- on failure
 *	USB_*		- refer to usbai.h
 *
 * Note:
 *	If the caller specified  USB_FLAGS_NOSLEEP, it must be
 *	capable of reliably recovering from a failure return
 */
int
usba_async_ph_req(usba_pipe_handle_data_t *ph_data,
		void	(*func)(void *),
		void	*arg,
		usb_flags_t flag)
{
	int	tq_flag;
	taskq_t *taskq;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usba_async_ph_req: ph_data=0x%p func=0x%p, arg=0x%p flag=0x%x",
	    (void *)ph_data, (void *)func, arg, flag);

	if (func == NULL) {

		return (USB_INVALID_ARGS);
	}

	tq_flag = (flag & USB_FLAGS_SLEEP) ? TQ_SLEEP : TQ_NOSLEEP;

	if (ph_data && ph_data->p_taskq) {
		taskq = ph_data->p_taskq;
	} else {
		taskq = system_taskq;
		tq_flag |= TQ_NOQUEUE;
	}

	if (taskq_dispatch(taskq, func, arg, tq_flag) == TASKQID_INVALID) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usbai_log_handle,
		    "usba_async_ph_req: failure");

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * utility functions to display CR, CB, return values
 */
typedef struct conv_table {
	int		what;
	const char	*name;
} conv_table_t;

static const char *
usba_get_name(conv_table_t *conv_table, int value)
{
	int i;
	for (i = 0; conv_table[i].name != NULL; i++) {
		if (conv_table[i].what == value) {

			return (conv_table[i].name);
		}
	}

	return ("unknown");
}


static conv_table_t cr_table[] = {
	{ USB_CR_OK,		"<no errors detected>" },
	{ USB_CR_CRC,		"<crc error detected>" },
	{ USB_CR_BITSTUFFING,	"<Bit stuffing violation>" },
	{ USB_CR_DATA_TOGGLE_MM, "<Data toggle PID did not match>" },
	{ USB_CR_STALL, 	"<Endpoint returned stall PID>" },
	{ USB_CR_DEV_NOT_RESP,	"<Device not responding>" },
	{ USB_CR_PID_CHECKFAILURE, "<Check bits on PID failed>" },
	{ USB_CR_UNEXP_PID,	"<Receive PID was not valid>" },
	{ USB_CR_DATA_OVERRUN,	"<Data size exceeded>" },
	{ USB_CR_DATA_UNDERRUN, "<Less data recieved than requested>" },
	{ USB_CR_BUFFER_OVERRUN, "<Memory write can't keep up>" },
	{ USB_CR_BUFFER_UNDERRUN, "<Buffer underrun>" },
	{ USB_CR_TIMEOUT,	"<Command timed out>" },
	{ USB_CR_NOT_ACCESSED,	"<Not accessed by hardware>" },
	{ USB_CR_NO_RESOURCES,	"<No resources>" },
	{ USB_CR_UNSPECIFIED_ERR, "<Unspecified usba or hcd error>" },
	{ USB_CR_STOPPED_POLLING, "<Intr/ISOC IN polling stopped>" },
	{ USB_CR_PIPE_CLOSING,	"<Intr/ISOC IN pipe being closed>" },
	{ USB_CR_PIPE_RESET,	"<Intr/ISOC IN pipe reset>" },
	{ USB_CR_NOT_SUPPORTED, "<Command not supported>" },
	{ USB_CR_FLUSHED,	"<Req was flushed>" },
	{ USB_CR_HC_HARDWARE_ERR, "<USB host controller error>" },
	{ 0,			NULL }
};

const char *
usb_str_cr(usb_cr_t cr)
{
	return (usba_get_name(cr_table, cr));
}


static conv_table_t cb_flags_table[] = {
	{ USB_CB_NO_INFO,	"<callback processed>" },
	{ USB_CB_STALL_CLEARED, "<stall cleared>" },
	{ USB_CB_FUNCTIONAL_STALL, "<functional stall>" },
	{ USB_CB_PROTOCOL_STALL, "<protocol stall>" },
	{ USB_CB_RESET_PIPE,	"<pipe reset>" },
	{ USB_CB_ASYNC_REQ_FAILED, "<thread could not be started>" },
	{ USB_CB_NO_RESOURCES,	"<no resources>" },
	{ USB_CB_SUBMIT_FAILED, "<submit failed>" },
	{ USB_CB_INTR_CONTEXT,	"<Callback executing in interrupt context>" },
	{ 0,			NULL }
};

/*ARGSUSED*/
char *
usb_str_cb_flags(usb_cb_flags_t cb_flags, char *buffer, size_t length)
{
	int i;
	buffer[0] = '\0';
	if (cb_flags == USB_CB_NO_INFO) {
		(void) strncpy(buffer, cb_flags_table[0].name, length);
	} else {
		for (i = 0; cb_flags_table[i].name != NULL; i++) {
			if (cb_flags & cb_flags_table[i].what) {
				(void) strncpy(&buffer[strlen(buffer)],
				    cb_flags_table[0].name,
				    length - strlen(buffer) - 1);
			}
		}
	}

	return (buffer);
}


static conv_table_t pipe_state_table[] = {
	{ USB_PIPE_STATE_CLOSED,	"<closed>" },
	{ USB_PIPE_STATE_IDLE,		"<idle>" },
	{ USB_PIPE_STATE_ACTIVE,	"<active>" },
	{ USB_PIPE_STATE_ERROR,		"<error>" },
	{ USB_PIPE_STATE_CLOSING,	"<closing>" },
	{ 0,				NULL }
};

const char *
usb_str_pipe_state(usb_pipe_state_t state)
{
	return (usba_get_name(pipe_state_table, state));
}


static conv_table_t dev_state[] = {
	{ USB_DEV_ONLINE,	"<online>" },
	{ USB_DEV_DISCONNECTED,	"<disconnected>" },
	{ USB_DEV_SUSPENDED,	"<suspended>" },
	{ USB_DEV_PWRED_DOWN,	"<powered down>" },
	{ 0,			NULL }
};

const char *
usb_str_dev_state(int state)
{
	return (usba_get_name(dev_state, state));
}


static conv_table_t rval_table[] = {
	{ USB_SUCCESS,		"<success>" },
	{ USB_FAILURE,		"<failure>" },
	{ USB_NO_RESOURCES,	"<no resources>" },
	{ USB_NO_BANDWIDTH,	"<no bandwidth>" },
	{ USB_NOT_SUPPORTED,	"<not supported>" },
	{ USB_PIPE_ERROR,	"<pipe error>" },
	{ USB_INVALID_PIPE,	"<invalid pipe>" },
	{ USB_NO_FRAME_NUMBER,	"<no frame number>" },
	{ USB_INVALID_START_FRAME, "<invalid frame>" },
	{ USB_HC_HARDWARE_ERROR, "<hw error>" },
	{ USB_INVALID_REQUEST,	"<invalid request>" },
	{ USB_INVALID_CONTEXT,	"<invalid context>" },
	{ USB_INVALID_VERSION,	"<invalid version>" },
	{ USB_INVALID_ARGS,	"<invalid args>" },
	{ USB_INVALID_PERM,	"<invalid perms>" },
	{ USB_BUSY,		"<busy>" },
	{ 0,			NULL }
};

const char *
usb_str_rval(int rval)
{
	return (usba_get_name(rval_table, rval));
}


/*
 * function to convert USB return values to close errno
 */
static struct usb_rval2errno_entry {
	int	rval;
	int	Errno;
} usb_rval2errno_table[] = {
	{ USB_SUCCESS,			0	},
	{ USB_FAILURE,			EIO	},
	{ USB_NO_RESOURCES,		ENOMEM	},
	{ USB_NO_BANDWIDTH,		EAGAIN	},
	{ USB_NOT_SUPPORTED,		ENOTSUP },
	{ USB_PIPE_ERROR,		EIO	},
	{ USB_INVALID_PIPE,		EINVAL	},
	{ USB_NO_FRAME_NUMBER,		EINVAL	},
	{ USB_INVALID_START_FRAME,	EINVAL	},
	{ USB_HC_HARDWARE_ERROR,	EIO	},
	{ USB_INVALID_REQUEST,		EINVAL	},
	{ USB_INVALID_CONTEXT,		EINVAL	},
	{ USB_INVALID_VERSION,		EINVAL	},
	{ USB_INVALID_ARGS,		EINVAL	},
	{ USB_INVALID_PERM,		EACCES	},
	{ USB_BUSY,			EBUSY	},
};

#define	USB_RVAL2ERRNO_TABLE_SIZE (sizeof (usb_rval2errno_table) / \
			sizeof (struct usb_rval2errno_entry))
int
usb_rval2errno(int rval)
{
	int i;

	for (i = 0; i < USB_RVAL2ERRNO_TABLE_SIZE; i++) {
		if (usb_rval2errno_table[i].rval == rval) {

			return (usb_rval2errno_table[i].Errno);
		}
	}

	return (EIO);
}


/*
 * serialization
 */
usb_serialization_t
usb_init_serialization(
	dev_info_t	*dip,
	uint_t		flag)
{
	usba_serialization_impl_t *impl_tokenp = kmem_zalloc(
	    sizeof (usba_serialization_impl_t), KM_SLEEP);
	usba_device_t	*usba_device;
	ddi_iblock_cookie_t cookie = NULL;

	if (dip) {
		usba_device = usba_get_usba_device(dip);
		cookie = usba_hcdi_get_hcdi(
		    usba_device->usb_root_hub_dip)->hcdi_iblock_cookie;
	}
	impl_tokenp->s_dip = dip;
	impl_tokenp->s_flag = flag;
	mutex_init(&impl_tokenp->s_mutex, NULL, MUTEX_DRIVER, cookie);
	cv_init(&impl_tokenp->s_cv, NULL, CV_DRIVER, NULL);

	return ((usb_serialization_t)impl_tokenp);
}


void
usb_fini_serialization(
	usb_serialization_t tokenp)
{
	usba_serialization_impl_t *impl_tokenp;

	if (tokenp) {
		impl_tokenp = (usba_serialization_impl_t *)tokenp;
		ASSERT(impl_tokenp->s_count == 0);
		cv_destroy(&impl_tokenp->s_cv);
		mutex_destroy(&impl_tokenp->s_mutex);
		kmem_free(impl_tokenp, sizeof (usba_serialization_impl_t));
	}
}


/*
 * usb_serialize_access() permits single threaded access.
 *
 * If tokenp is initialized with USB_INIT_SER_CHECK_SAME_THREAD,
 * it is reentrant with respect to thread. The thread must
 * hold and release the same number of times.
 *
 * If tokenp is initialized without USB_INIT_SER_CHECK_SAME_THREAD,
 * it is not reentrant by the same thread. It is something like
 * a semaphore.
 */
int
usb_serialize_access(
	usb_serialization_t tokenp, uint_t how_to_wait, uint_t delta_timeout)
{
	int			rval = 1;	/* Must be initialized > 0 */
	clock_t			abs_timeout;
	usba_serialization_impl_t *impl_tokenp;

	impl_tokenp = (usba_serialization_impl_t *)tokenp;

	/*
	 * Convert delta timeout in ms to absolute timeout in ticks, if used.
	 */
	if ((how_to_wait == USB_TIMEDWAIT) ||
	    (how_to_wait == USB_TIMEDWAIT_SIG)) {
		/* Convert timeout arg (in ms) to hz */
		abs_timeout = ddi_get_lbolt() +
		    drv_usectohz(delta_timeout * 1000);
	}

	/* Get mutex after calc abs time, to count time waiting for mutex. */
	mutex_enter(&impl_tokenp->s_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_serialize_access: tok=0x%p dip=0x%p cnt=%d thr=0x%p, "
	    "flg=0x%x, abs_tmo=0x%lx",
	    (void *)impl_tokenp, (void *)impl_tokenp->s_dip,
	    impl_tokenp->s_count, (void *)impl_tokenp->s_thread,
	    how_to_wait, abs_timeout);

	if ((impl_tokenp->s_flag & USB_INIT_SER_CHECK_SAME_THREAD) == 0 ||
	    impl_tokenp->s_thread != curthread) {

		/*
		 * There are three ways to break out of the loop:
		 * 1) Condition met (s_count == 0) - higher prio test
		 * 2) kill(2) signal received (rval == 0)
		 * 3) timeout occurred (rval == -1)
		 * If condition met, whether or not signal or timeout occurred
		 * take access.  If condition not met, check other exit means.
		 */
		while (impl_tokenp->s_count != 0) {

			/* cv_timedwait* returns -1 on timeout. */
			/* cv_wait*_sig returns 0 on (kill(2)) signal. */
			if (rval <= 0) {
				mutex_exit(&impl_tokenp->s_mutex);
				USB_DPRINTF_L4(DPRINT_MASK_USBA,
				    usbai_log_handle,
				    "usb_serialize_access: "
				    "tok=0x%p exit due to %s",
				    (void *)impl_tokenp,
				    ((rval == 0) ? "signal" : "timeout"));

				return (rval);
			}

			switch (how_to_wait) {
			default:
				how_to_wait = USB_WAIT;
				/* FALLTHROUGH */
			case USB_WAIT:
				cv_wait(&impl_tokenp->s_cv,
				    &impl_tokenp->s_mutex);
				break;
			case USB_WAIT_SIG:
				rval = cv_wait_sig(&impl_tokenp->s_cv,
				    &impl_tokenp->s_mutex);
				break;
			case USB_TIMEDWAIT:
				rval = cv_timedwait(&impl_tokenp->s_cv,
				    &impl_tokenp->s_mutex, abs_timeout);
				break;
			case USB_TIMEDWAIT_SIG:
				rval = cv_timedwait_sig(&impl_tokenp->s_cv,
				    &impl_tokenp->s_mutex, abs_timeout);
				break;
			}
		}

		impl_tokenp->s_thread = curthread;
	}
	impl_tokenp->s_count++;

	ASSERT(!(impl_tokenp->s_count > 1 &&
	    (impl_tokenp->s_flag & USB_INIT_SER_CHECK_SAME_THREAD) == 0));

	mutex_exit(&impl_tokenp->s_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_serialize_access exit: tok=0x%p thr=0x%p", (void *)impl_tokenp,
	    (void *)curthread);

	return (1);
}


/*ARGSUSED*/
int
usb_try_serialize_access(
	usb_serialization_t tokenp, uint_t flag)
{
	usba_serialization_impl_t *impl_tokenp =
	    (usba_serialization_impl_t *)tokenp;
	mutex_enter(&impl_tokenp->s_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_try_serialize_access: tok=0x%p dip=0x%p cnt=%d thr=0x%p",
	    (void *)impl_tokenp, (void *)impl_tokenp->s_dip,
	    impl_tokenp->s_count, (void *)curthread);

	/*
	 * If lock is not taken (s_count is 0), take it.
	 * If lock is already taken, the thread is owner and lock
	 * is reentrant, take it.
	 * Otherwise, fail the access.
	 */
	if (!impl_tokenp->s_count || ((impl_tokenp->s_thread == curthread) &&
	    (impl_tokenp->s_flag & USB_INIT_SER_CHECK_SAME_THREAD))) {
		impl_tokenp->s_thread = curthread;
		impl_tokenp->s_count++;

		USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
		    "usb_try_serialize_access success: tok=0x%p",
		    (void *)impl_tokenp);
		mutex_exit(&impl_tokenp->s_mutex);

		return (USB_SUCCESS);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_try_serialize_access failed: "
	    "tok=0x%p dip=0x%p cnt=%d thr=0x%p",
	    (void *)impl_tokenp, (void *)impl_tokenp->s_dip,
	    impl_tokenp->s_count, (void *)impl_tokenp->s_thread);

	mutex_exit(&impl_tokenp->s_mutex);

	return (USB_FAILURE);
}


void
usb_release_access(
	usb_serialization_t tokenp)
{
	usba_serialization_impl_t *impl_tokenp =
	    (usba_serialization_impl_t *)tokenp;
	mutex_enter(&impl_tokenp->s_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_release_access: tok=0x%p dip=0x%p count=%d thr=0x%p",
	    (void *)impl_tokenp, (void *)impl_tokenp->s_dip,
	    impl_tokenp->s_count, (void *)curthread);

	ASSERT(impl_tokenp->s_count > 0);

	if (impl_tokenp->s_flag & USB_INIT_SER_CHECK_SAME_THREAD) {
		if (impl_tokenp->s_thread != curthread) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA, usbai_log_handle,
			    "usb_release_access: release from wrong thread");
		}
		ASSERT(impl_tokenp->s_thread == curthread);
	}

	if (--impl_tokenp->s_count == 0) {
		impl_tokenp->s_thread = NULL;
		cv_broadcast(&impl_tokenp->s_cv);
	}
	mutex_exit(&impl_tokenp->s_mutex);
}


/*
 * usb_fail_checkpoint:
 *	fail checkpoint as driver/device could not be quiesced
 */
/*ARGSUSED*/
void
usb_fail_checkpoint(dev_info_t *dip, usb_flags_t flags)
{
	usba_device_t	*usba_device = usba_get_usba_device(dip);

	USB_DPRINTF_L2(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_fail_checkpoint: %s%d", ddi_driver_name(dip),
	    ddi_get_instance(dip));

	mutex_enter(&usba_device->usb_mutex);
	usba_device->usb_no_cpr++;
	mutex_exit(&usba_device->usb_mutex);
}


_NOTE(SCHEME_PROTECTS_DATA("unique per call", iocblk))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", datab))
/*
 * usba_mk_mctl:
 *	create a USB style M_CTL message, given an iocblk and a buffer
 *	returns mblk_t * on success, NULL on failure
 */
mblk_t *
usba_mk_mctl(struct iocblk mctlmsg, void *buf, size_t len)
{
	mblk_t *bp1, *bp2;

	if ((bp1 = allocb(sizeof (struct iocblk), BPRI_HI)) != NULL) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		*((struct iocblk *)bp1->b_datap->db_base) = mctlmsg;
		bp1->b_datap->db_type = M_CTL;
		bp1->b_wptr += sizeof (struct iocblk);
		if (buf != NULL) {
			if ((bp2 = allocb(len, BPRI_HI)) != NULL) {
				bp1->b_cont = bp2;
				bcopy(buf, bp2->b_datap->db_base, len);
				bp2->b_wptr += len;
			} else {
				freemsg(bp1);
				bp1 = NULL;
			}
		}
	}

	return (bp1);
}


#ifdef ALLOCB_TEST
#undef	allocb
mblk_t *
usba_test_allocb(size_t size, uint_t pri)
{
	if (ddi_get_lbolt() & 0x1) {

		return (NULL);
	} else {

		return (allocb(size, pri));
	}
}
#endif


/*
 * usb common power management for usb_mid, usb_ia and maybe other simple
 * drivers.
 */

/*
 * functions to handle power transition for OS levels 0 -> 3
 */
static int
usb_common_pwrlvl0(dev_info_t *dip, uint8_t *pm, int *dev_state)
{
	int	rval;

	switch (*dev_state) {
	case USB_DEV_ONLINE:
		/* Issue USB D3 command to the device here */
		rval = usb_set_device_pwrlvl3(dip);
		ASSERT(rval == USB_SUCCESS);

		*dev_state = USB_DEV_PWRED_DOWN;
		*pm = USB_DEV_OS_PWR_OFF;
		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnected/cpr'ed device to go to low pwr */

		return (USB_SUCCESS);
	case USB_DEV_PWRED_DOWN:
	default:
		return (USB_FAILURE);
	}
}


/* ARGSUSED */
static int
usb_common_pwrlvl1(dev_info_t *dip, uint8_t *pm, int *dev_state)
{
	int	rval;

	/* Issue USB D2 command to the device here */
	rval = usb_set_device_pwrlvl2(dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/* ARGSUSED */
static int
usb_common_pwrlvl2(dev_info_t *dip, uint8_t *pm, int *dev_state)
{
	int	rval;

	/* Issue USB D1 command to the device here */
	rval = usb_set_device_pwrlvl1(dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


static int
usb_common_pwrlvl3(dev_info_t *dip, uint8_t *pm, int *dev_state)
{
	int	rval;

	switch (*dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(dip);
		ASSERT(rval == USB_SUCCESS);

		*dev_state = USB_DEV_ONLINE;
		*pm = USB_DEV_OS_FULL_PWR;

		/* FALLTHRU */
	case USB_DEV_ONLINE:
		/* we are already in full power */

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnected/cpr'ed device to go to low power */

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usbai_log_handle,
		    "usb_common_pwrlvl3: Illegal state (%s)",
		    usb_str_dev_state(*dev_state));

		return (USB_FAILURE);
	}
}

/* power management */
int
usba_common_power(dev_info_t *dip, uint8_t *pm, int *dev_state, int level)
{
	int rval = DDI_FAILURE;

	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		rval = usb_common_pwrlvl0(dip, pm, dev_state);
		break;
	case USB_DEV_OS_PWR_1:
		rval = usb_common_pwrlvl1(dip, pm, dev_state);
		break;
	case USB_DEV_OS_PWR_2:
		rval = usb_common_pwrlvl2(dip, pm, dev_state);
		break;
	case USB_DEV_OS_FULL_PWR:
		rval = usb_common_pwrlvl3(dip, pm, dev_state);
		break;
	}

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

/*
 * register and unregister for events from our parent for usb_mid and usb_ia
 * and maybe other nexus driver.
 *
 * Note: The cookie fields in usba_device structure is not used. They are
 * used/shared by children.
 */
void
usba_common_register_events(dev_info_t *dip, uint_t if_num,
	void (*event_cb)(dev_info_t *, ddi_eventcookie_t, void *, void *))
{
	int rval;
	usba_evdata_t *evdata;
	ddi_eventcookie_t cookie;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usb_common_register_events:");

	evdata = usba_get_evdata(dip);

	/* get event cookie, discard level and icookie for now */
	rval = ddi_get_eventcookie(dip, DDI_DEVI_REMOVE_EVENT,
	    &cookie);

	if (rval == DDI_SUCCESS) {
		rval = ddi_add_event_handler(dip,
		    cookie, event_cb, NULL, &evdata->ev_rm_cb_id);

		if (rval != DDI_SUCCESS) {

			goto fail;
		}
	}
	rval = ddi_get_eventcookie(dip, DDI_DEVI_INSERT_EVENT,
	    &cookie);
	if (rval == DDI_SUCCESS) {
		rval = ddi_add_event_handler(dip, cookie, event_cb,
		    NULL, &evdata->ev_ins_cb_id);

		if (rval != DDI_SUCCESS) {

			goto fail;
		}
	}
	rval = ddi_get_eventcookie(dip, USBA_PRE_SUSPEND_EVENT, &cookie);
	if (rval == DDI_SUCCESS) {
		rval = ddi_add_event_handler(dip,
		    cookie, event_cb, NULL, &evdata->ev_suspend_cb_id);

		if (rval != DDI_SUCCESS) {

			goto fail;
		}
	}
	rval = ddi_get_eventcookie(dip, USBA_POST_RESUME_EVENT, &cookie);
	if (rval == DDI_SUCCESS) {
		rval = ddi_add_event_handler(dip, cookie, event_cb, NULL,
		    &evdata->ev_resume_cb_id);

		if (rval != DDI_SUCCESS) {

			goto fail;
		}
	}

	return;


fail:
	usba_common_unregister_events(dip, if_num);

}

void
usba_common_unregister_events(dev_info_t *dip, uint_t if_num)
{
	usba_evdata_t	*evdata;
	usba_device_t	*usba_device = usba_get_usba_device(dip);
	int i;

	evdata = usba_get_evdata(dip);

	if (evdata->ev_rm_cb_id != NULL) {
		(void) ddi_remove_event_handler(evdata->ev_rm_cb_id);
		evdata->ev_rm_cb_id = NULL;
	}

	if (evdata->ev_ins_cb_id != NULL) {
		(void) ddi_remove_event_handler(evdata->ev_ins_cb_id);
		evdata->ev_ins_cb_id = NULL;
	}

	if (evdata->ev_suspend_cb_id != NULL) {
		(void) ddi_remove_event_handler(evdata->ev_suspend_cb_id);
		evdata->ev_suspend_cb_id = NULL;
	}

	if (evdata->ev_resume_cb_id != NULL) {
		(void) ddi_remove_event_handler(evdata->ev_resume_cb_id);
		evdata->ev_resume_cb_id = NULL;
	}

	/* clear event data for children, required for cfgmadm unconfigure */
	mutex_enter(&usba_device->usb_mutex);
	if (usb_owns_device(dip)) {
		usba_free_evdata(usba_device->usb_evdata);
		usba_device->usb_evdata = NULL;
		usba_device->rm_cookie = NULL;
		usba_device->ins_cookie = NULL;
		usba_device->suspend_cookie = NULL;
		usba_device->resume_cookie = NULL;
	} else {
		for (i = 0; i < if_num; i++) {
			usba_device->usb_client_flags[usba_get_ifno(dip) + i]
			    &= ~USBA_CLIENT_FLAG_EV_CBS;
		}
	}
	mutex_exit(&usba_device->usb_mutex);
}
