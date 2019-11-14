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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019, Joyent, Inc.
 */


/*
 * USBA: Solaris USB Architecture support
 *
 * all functions exposed to client drivers  have prefix usb_ while all USBA
 * internal functions or functions exposed to HCD or hubd only have prefix
 * usba_
 *
 * this file contains initializations, logging/tracing support and PM
 * support
 */
#define	USBA_FRAMEWORK
#include <sys/varargs.h>
#include <sys/strsun.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/usb/usba/usba10.h>

/*
 * print buffer protected by mutex for debug stuff. the mutex also
 * ensures serializing debug messages
 */
static kmutex_t	usba_print_mutex;
static char usba_print_buf[USBA_PRINT_BUF_LEN];
kmutex_t usbai_mutex;

/*
 * debug stuff
 */
usb_log_handle_t	usbai_log_handle;
uint_t			usbai_errlevel = USB_LOG_L4;
uint_t			usbai_errmask = (uint_t)-1;

#define	USBA_DEBUG_SIZE_EXTRA_ALLOC	8
#ifdef	DEBUG
#define	USBA_DEBUG_BUF_SIZE \
			(0x40000 -  USBA_DEBUG_SIZE_EXTRA_ALLOC)
#else
#define	USBA_DEBUG_BUF_SIZE \
			(0x4000 -  USBA_DEBUG_SIZE_EXTRA_ALLOC)
#endif	/* DEBUG */

#define	USBA_POWER_STR_SIZE		40

int	usba_suppress_dprintf;		/* Suppress debug printing */
int	usba_clear_debug_buf_flag;	/* clear debug buf */
int	usba_buffer_dprintf = 1;	/* Use a debug print buffer */
int	usba_timestamp_dprintf = 0;	/* get time stamps in trace */
int	usba_debug_buf_size = USBA_DEBUG_BUF_SIZE;	/* Size of debug buf */
int	usba_debug_chatty;		/* L1 msg on console */

static char *usba_debug_buf = NULL;	/* The debug buf */
static char *usba_buf_sptr, *usba_buf_eptr;
static hrtime_t usba_last_timestamp;	/* last time stamp in trace */

/* USBA framework initializations */
void
usba_usbai_initialization()
{
	usbai_log_handle = usb_alloc_log_hdl(NULL, "usbai", &usbai_errlevel,
	    &usbai_errmask, NULL, 0);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_usbai_initialization");

	mutex_init(&usba_print_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&usbai_mutex, NULL, MUTEX_DRIVER, NULL);
}


/* USBA framework destroys */
void
usba_usbai_destroy()
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_usbai_destroy");

	mutex_destroy(&usba_print_mutex);
	mutex_destroy(&usbai_mutex);
	if (usba_debug_buf) {
		kmem_free(usba_debug_buf,
		    usba_debug_buf_size + USBA_DEBUG_SIZE_EXTRA_ALLOC);
	}

	usb_free_log_hdl(usbai_log_handle);
}


/*
 * debug, log, and console message handling
 */
usb_log_handle_t
usb_alloc_log_hdl(dev_info_t *dip, char *name,
    uint_t *errlevel, uint_t *mask, uint_t *instance_filter,
    usb_flags_t flags)
{
	usba_log_handle_impl_t	*hdl;

	USBA_CHECK_CONTEXT();
	hdl = kmem_zalloc(sizeof (*hdl), KM_SLEEP);

	hdl->lh_dip = dip;
	if (dip && (name == NULL)) {
		hdl->lh_name = (char *)ddi_driver_name(dip);
	} else {
		hdl->lh_name = name;
	}
	hdl->lh_errlevel = errlevel;
	hdl->lh_mask = mask;
	hdl->lh_instance_filter = instance_filter;
	hdl->lh_flags = flags;

#ifdef __lock_lint
	(void) usb_alloc_log_handle(dip, name, errlevel, mask,
	    instance_filter, 0, flags);
	usb_free_log_handle(NULL);
#endif

	return ((usb_log_handle_t)hdl);
}


/*ARGSUSED*/
usb_log_handle_t
usb_alloc_log_handle(dev_info_t *dip, char *name,
    uint_t *errlevel, uint_t *mask, uint_t *instance_filter,
    uint_t reserved, usb_flags_t flags)
{
	return (usb_alloc_log_hdl(dip, name, errlevel, mask,
	    instance_filter, flags));
}

void
usb_free_log_handle(usb_log_handle_t handle)
{
	if (handle) {
		kmem_free(handle, sizeof (usba_log_handle_impl_t));
	}
}

void
usb_free_log_hdl(usb_log_handle_t handle)
{
	if (handle) {
		kmem_free(handle, sizeof (usba_log_handle_impl_t));
	}
}


static void
usba_clear_dprint_buf()
{
	if (usba_debug_buf) {
		usba_buf_sptr = usba_debug_buf;
		usba_buf_eptr = usba_debug_buf + usba_debug_buf_size;
		bzero(usba_debug_buf, usba_debug_buf_size +
		    USBA_DEBUG_SIZE_EXTRA_ALLOC);
	}
}


#ifdef DEBUG
char *
usba_dbuf_tail(uint_t lines)
{
	int	count;
	char	*r = NULL;

	mutex_enter(&usba_print_mutex);
	if (usba_debug_buf) {
		count = 0;
		r = usba_buf_sptr;
		while ((count < lines) && (r > usba_debug_buf)) {
			if (*r == '\n') {
				count++;
			}
			r--;
		}
	}
	mutex_exit(&usba_print_mutex);

	return (r);
}
#endif	/* DEBUG */


static void usb_vprintf(dev_info_t *, int, char *, char *, va_list)
	__KVPRINTFLIKE(4);

static void
usb_vprintf(dev_info_t *dip, int level, char *label, char *fmt, va_list ap)
{
	size_t len;
	int instance = 0;
	char driver_name[USBA_DRVNAME_LEN];
	char *msg_ptr;

	if (usba_suppress_dprintf) {

		return;
	}

	*driver_name = '\0';
	mutex_enter(&usba_print_mutex);

	/*
	 * Check if we have a valid buf size?
	 * Suppress logging to usb_buffer if so.
	 */
	if (usba_debug_buf_size <= 0) {

		usba_buffer_dprintf = 0;
	}

	/*
	 * if there is label and dip, use <driver name><instance>:
	 * otherwise just use the label
	 */
	if (dip) {
		instance = ddi_get_instance(dip);
		(void) snprintf(driver_name, USBA_DRVNAME_LEN,
		    "%s%d", ddi_driver_name(dip), instance);
	}

	if (label == (char *)NULL) {
		len = snprintf(usba_print_buf, USBA_PRINT_BUF_LEN, "\t");
	} else if (usba_timestamp_dprintf) {
		hrtime_t t = gethrtime();
		hrtime_t elapsed = (t - usba_last_timestamp)/1000;
		usba_last_timestamp = t;

		if (dip) {

			len = snprintf(usba_print_buf, USBA_PRINT_BUF_LEN,
			    "+%lld->%p: %s%d: ", elapsed,
			    (void *)curthread, label, instance);
		} else {
			len = snprintf(usba_print_buf, USBA_PRINT_BUF_LEN,
			    "+%lld->%p: %s: ", elapsed,
			    (void *)curthread, label);
		}
	} else {
		if (dip) {
			len = snprintf(usba_print_buf, USBA_PRINT_BUF_LEN,
			    "%s%d:\t", label, instance);
		} else {
			len = snprintf(usba_print_buf, USBA_PRINT_BUF_LEN,
			    "%s:\t", label);
		}
	}


	msg_ptr = usba_print_buf + len;
	(void) vsnprintf(msg_ptr, USBA_PRINT_BUF_LEN - len - 2, fmt, ap);

	len = min(strlen(usba_print_buf), USBA_PRINT_BUF_LEN - 2);
	usba_print_buf[len++] = '\n';
	usba_print_buf[len] = '\0';

	/*
	 * stuff the message in the debug buf
	 */
	if (usba_buffer_dprintf) {
		if (usba_debug_buf == NULL) {
			usba_debug_buf = kmem_alloc(
			    usba_debug_buf_size + USBA_DEBUG_SIZE_EXTRA_ALLOC,
			    KM_SLEEP);
			usba_clear_dprint_buf();
		} else if (usba_clear_debug_buf_flag) {
			usba_clear_dprint_buf();
			usba_clear_debug_buf_flag = 0;
		}

		/*
		 * overwrite >>>> that might be over the end of the
		 * the buffer
		 */
		*(usba_debug_buf + usba_debug_buf_size) = '\0';

		if ((usba_buf_sptr + len) > usba_buf_eptr) {
			size_t left = _PTRDIFF(usba_buf_eptr, usba_buf_sptr);

			bcopy(usba_print_buf, usba_buf_sptr, left);
			bcopy((caddr_t)usba_print_buf + left,
			    usba_debug_buf, len - left);
			usba_buf_sptr = usba_debug_buf + len - left;
		} else {
			bcopy(usba_print_buf, usba_buf_sptr, len);
			usba_buf_sptr += len;
		}
		/* add marker */
		(void) sprintf(usba_buf_sptr, ">>>>");
	}

	/*
	 * L4-L2 message may go to the log buf if not logged in usba_debug_buf
	 * L1 messages will go to the log buf in non-debug kernels and
	 * to console and log buf in debug kernels if usba_debug_chatty
	 * has been set
	 * L0 messages are warnings and will go to console and log buf and
	 * include the pathname, if available
	 */

	switch (level) {
	case USB_LOG_L4:
	case USB_LOG_L3:
	case USB_LOG_L2:
		if (!usba_buffer_dprintf) {
			cmn_err(CE_CONT, "^%s", usba_print_buf);
		}
		break;
	case USB_LOG_L1:
		if (dip) {
			char *pathname = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);
			if (pathname) {
				cmn_err(CE_CONT,
				    usba_debug_chatty ?
				    "%s (%s): %s" : "?%s (%s): %s",
				    ddi_pathname(dip, pathname),
				    driver_name, msg_ptr);
				kmem_free(pathname, MAXPATHLEN);
			} else {
				cmn_err(CE_CONT,
				    usba_debug_chatty ?
				    "%s" : "?%s", usba_print_buf);
			}
		} else {
			cmn_err(CE_CONT,
			    usba_debug_chatty ? "%s" : "?%s",
			    usba_print_buf);
		}
		break;
	case USB_LOG_L0:
		/* Strip the "\n" added earlier */
		if (usba_print_buf[len - 1] == '\n') {
			usba_print_buf[len - 1] = '\0';
		}
		if (msg_ptr[len - 1] == '\n') {
			msg_ptr[len - 1] = '\0';
		}
		if (dip) {
			char *pathname = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);
			if (pathname) {
				cmn_err(CE_WARN, "%s (%s): %s",
				    ddi_pathname(dip, pathname),
				    driver_name, msg_ptr);
				kmem_free(pathname, MAXPATHLEN);
			} else {
				cmn_err(CE_WARN, usba_print_buf);
			}
		} else {
			cmn_err(CE_WARN, usba_print_buf);
		}
		break;
	}

	mutex_exit(&usba_print_mutex);
}

int
usba_vlog(usb_log_handle_t, uint_t, uint_t, char *, va_list)
    __KVPRINTFLIKE(4);

/* When usba10_calls.c goes away, this function can be made static again. */
int
usba_vlog(usb_log_handle_t handle, uint_t level, uint_t mask,
    char *fmt, va_list ap)
{
	usba_log_handle_impl_t *hdl = (usba_log_handle_impl_t *)handle;
	char *label;
	uint_t hdl_errlevel, hdl_mask, hdl_instance_filter;

	/* if there is no handle, use usba as label */
	if (hdl == NULL) {
		usb_vprintf(NULL, level, "usba", fmt, ap);

		return (USB_SUCCESS);
	}

	/* look up the filters and set defaults */
	if (hdl->lh_errlevel) {
		hdl_errlevel = *(hdl->lh_errlevel);
	} else {
		hdl_errlevel = 0;
	}

	if (hdl->lh_mask) {
		hdl_mask = *(hdl->lh_mask);
	} else {
		hdl_mask = (uint_t)-1;
	}

	if (hdl->lh_instance_filter) {
		hdl_instance_filter = *(hdl->lh_instance_filter);
	} else {
		hdl_instance_filter = (uint_t)-1;
	}

	/* if threshold is lower or mask doesn't match, we are done */
	if ((level > hdl_errlevel) || ((mask & hdl_mask) == 0)) {

		return (USB_FAILURE);
	}

	/*
	 * if we have a dip, and it is not a warning, check
	 * the instance number
	 */
	if (hdl->lh_dip && (level > USB_LOG_L0)) {
		if ((hdl_instance_filter != (uint_t)-1) &&
		    (ddi_get_instance(hdl->lh_dip) != hdl_instance_filter)) {

			return (USB_FAILURE);
		}
	}

	label = hdl->lh_name;

	usb_vprintf(hdl->lh_dip, level, label, fmt, ap);

	return (USB_SUCCESS);
}


void
usb_dprintf4(uint_t mask, usb_log_handle_t handle, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba_vlog(handle, USB_LOG_L4, mask, fmt, ap);
	va_end(ap);
}


void
usb_dprintf3(uint_t mask, usb_log_handle_t handle, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba_vlog(handle, USB_LOG_L3, mask, fmt, ap);
	va_end(ap);
}


void
usb_dprintf2(uint_t mask, usb_log_handle_t handle, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba_vlog(handle, USB_LOG_L2, mask, fmt, ap);
	va_end(ap);
}


void
usb_dprintf1(uint_t mask, usb_log_handle_t handle, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba_vlog(handle, USB_LOG_L1, mask, fmt, ap);
	va_end(ap);
}


void
usb_dprintf0(uint_t mask, usb_log_handle_t handle, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba_vlog(handle, USB_LOG_L0, mask, fmt, ap);
	va_end(ap);
}


int
usb_log(usb_log_handle_t handle, uint_t level, uint_t mask, char *fmt, ...)
{
	va_list	ap;
	int rval;

	va_start(ap, fmt);
	rval = usba_vlog(handle, level, mask, fmt, ap);
	va_end(ap);

	return (rval);
}


/*
 * Provide a default configuration power descriptor
 */
usba_cfg_pwr_descr_t	default_cfg_power = {
	18,	/* bLength */
	USBA_DESCR_TYPE_CFG_PWR_1_1, /* bDescriptorType */
	0,	/* SelfPowerConsumedD0_l */
	0,	/* SelfPowerConsumedD0_h */
	0,	/* bPowerSummaryId */
	0,	/* bBusPowerSavingD1 */
	0,	/* bSelfPowerSavingD1 */
	0,	/* bBusPowerSavingD2 */
	0,	/* bSelfPowerSavingD2 */
	100,	/* bBusPowerSavingD3 */
	100,	/* bSelfPowerSavingD3 */
	0,	/* TransitionTimeFromD1 */
	0,	/* TransitionTimeFromD2 */
	10,	/* TransitionTimeFromD3 1 Second */
};


/*
 * Provide a default interface power descriptor
 */
usba_if_pwr_descr_t default_if_power = {
	15,	/* bLength */
	USBA_DESCR_TYPE_IF_PWR_1_1, /* bDescriptorType */
	8,	/* bmCapabilitiesFlags */
	0,	/* bBusPowerSavingD1 */
	0,	/* bSelfPowerSavingD1 */
	0,	/* bBusPowerSavingD2 */
	0,	/* bSelfPowerSavingD2 */
	100,	/* bBusPowerSavingD3 */
	100,	/* bSelfPowerSavingD3 */
	0,	/* TransitionTimeFromD1 */
	0,	/* TransitionTimeFromD2 */
	10,	/* TransitionTimeFromD3 1 Second */
};


static void
usba_async_req_raise_power(void *arg)
{
	usba_pm_req_t *pmrq = (usba_pm_req_t *)arg;
	int rval;

	/*
	 * To eliminate race condition between the call to power entry
	 * point and our call to raise power level, we first mark the
	 * component busy and later idle
	 */
	(void) pm_busy_component(pmrq->dip, pmrq->comp);
	rval = pm_raise_power(pmrq->dip, pmrq->comp, pmrq->level);
	(void) pm_idle_component(pmrq->dip, pmrq->comp);
	pmrq->cb(pmrq->arg, rval);

	/* We are done with pmrq. Free it now */
	kmem_free(pmrq, sizeof (usba_pm_req_t));
}


/* usb function to perform async pm_request_power_change */
int
usb_req_raise_power(dev_info_t *dip, int comp, int level,
    void (*callback)(void *, int), void *arg, usb_flags_t flags)
{
	usba_pm_req_t *pmrq;

	if (flags & USB_FLAGS_SLEEP) {

		return (pm_raise_power(dip, comp, level));
	}

	if ((pmrq = kmem_alloc(sizeof (usba_pm_req_t), KM_NOSLEEP)) ==
	    NULL) {

		return (USB_FAILURE);
	}

	pmrq->dip = dip;
	pmrq->comp = comp;
	pmrq->level = level;
	pmrq->cb = callback;
	pmrq->arg = arg;
	pmrq->flags = flags;

	if (usb_async_req(dip, usba_async_req_raise_power,
	    (void *)pmrq, USB_FLAGS_NOSLEEP | USB_FLAGS_NOQUEUE) !=
	    USB_SUCCESS) {
		kmem_free(pmrq, sizeof (usba_pm_req_t));

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


static void
usba_async_req_lower_power(void *arg)
{
	usba_pm_req_t *pmrq = (usba_pm_req_t *)arg;
	int rval;

	/*
	 * To eliminate race condition between the call to power entry
	 * point and our call to lower power level, we call idle component
	 * to push ahead the PM timestamp
	 */
	(void) pm_idle_component(pmrq->dip, pmrq->comp);
	rval = pm_lower_power(pmrq->dip, pmrq->comp, pmrq->level);
	pmrq->cb(pmrq->arg, rval);
}


/* usb function to perform async pm_request_power_change */
int
usb_req_lower_power(dev_info_t *dip, int comp, int level,
    void (*callback)(void *, int), void *arg, usb_flags_t flags)
{
	usba_pm_req_t *pmrq;

	if (flags & USB_FLAGS_SLEEP) {

		return (pm_lower_power(dip, comp, level));
	}

	if ((pmrq = kmem_alloc(sizeof (usba_pm_req_t), KM_NOSLEEP)) ==
	    NULL) {

		return (USB_FAILURE);
	}

	pmrq->dip = dip;
	pmrq->comp = comp;
	pmrq->level = level;
	pmrq->cb = callback;
	pmrq->arg = arg;
	pmrq->flags = flags;

	if (usb_async_req(dip, usba_async_req_lower_power,
	    (void *)pmrq, USB_FLAGS_NOSLEEP | USB_FLAGS_NOQUEUE) !=
	    USB_SUCCESS) {
		kmem_free(pmrq, sizeof (usba_pm_req_t));

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/* function to see if pm is enabled for this device */
/*ARGSUSED*/
int
usb_is_pm_enabled(dev_info_t *dip)
{
	/*
	 * At this point we should assume that all devices
	 * are capable of supporting PM
	 */
	return (USB_SUCCESS);
}


/*
 * usba_handle_device_remote_wakeup:
 *	internal function to enable/disable remote wakeup in the device
 *	or interface
 */
static int
usba_handle_device_remote_wakeup(dev_info_t *dip, int cmd)
{
	int		rval;
	uint8_t 	bmRequest = USB_DEV_REQ_HOST_TO_DEV;
	uchar_t		bRequest;
	uint16_t	wIndex = 0;
	usb_cr_t	completion_reason = 0;
	usb_cb_flags_t	cb_flags;
	usb_pipe_handle_t ph;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usbai_log_handle,
	    "usba_handle_device_remote_wakeup: dip = 0x%p", (void *)dip);

	USBA_CHECK_CONTEXT();

	/* get the default pipe */
	ph = usba_get_dflt_pipe_handle(dip);

	/* do we own the device? */
	if (usb_owns_device(dip)) {
		bmRequest |= USB_DEV_REQ_RCPT_DEV;
	} else {
		bmRequest |= USB_DEV_REQ_RCPT_IF;
		wIndex = usba_get_ifno(dip);
	}
	bRequest = ((cmd == USB_REMOTE_WAKEUP_ENABLE) ? USB_REQ_SET_FEATURE :
	    USB_REQ_CLEAR_FEATURE);

	if ((rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    bmRequest,			/* bmRequest */
	    bRequest,			/* bRequest */
	    USB_DEV_REMOTE_WAKEUP,	/* wValue */
	    wIndex,			/* wIndex */
	    0,				/* wLength */
	    NULL, 0,
	    &completion_reason,
	    &cb_flags, USB_FLAGS_SLEEP)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "Set/ClearFeature (RemoteWakep) failed: "
		    "rval = %d, cmd = %d, cr = 0x%x cb = 0x%x",
		    rval, cmd, completion_reason, cb_flags);
	}

	return (rval);
}


void
usb_enable_parent_notification(dev_info_t *dip)
{
	USBA_CHECK_CONTEXT();
	(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
	    "pm-want-child-notification?");
}


/*
 * usb_handle_remote_wakeup:
 *	check if device supports remote wakeup and, if so, enable/disable
 *	remote wake up in the device depending upon the command
 */
int
usb_handle_remote_wakeup(dev_info_t *dip, int cmd)
{
	usb_cfg_descr_t	cfg_descr;
	uchar_t 	*usb_cfg;	/* buf for config descriptor */
	size_t		cfg_length;
	int		rval;

	USBA_CHECK_CONTEXT();

	/* Obtain the raw configuration descriptor */
	usb_cfg = usb_get_raw_cfg_data(dip, &cfg_length);

	/* get configuration descriptor, must succeed */
	rval = usb_parse_cfg_descr(usb_cfg, cfg_length,
	    &cfg_descr, USB_CFG_DESCR_SIZE);
	ASSERT(rval == USB_CFG_DESCR_SIZE);

	/*
	 * If the device supports remote wakeup, and PM is enabled,
	 * we enable remote wakeup in the device
	 */
	if ((usb_is_pm_enabled(dip) == USB_SUCCESS) &&
	    (cfg_descr.bmAttributes & USB_CFG_ATTR_REMOTE_WAKEUP)) {

		rval = usba_handle_device_remote_wakeup(dip, cmd);
	} else {
		rval = USB_FAILURE;
	}

	return (rval);
}


/*
 * usb_create_pm_components:
 *	map descriptor into  pm properties
 */
int
usb_create_pm_components(dev_info_t *dip, uint_t *pwr_states)
{
	uchar_t 		*usb_cfg;	/* buf for config descriptor */
	usb_cfg_descr_t		cfg_descr;
	size_t			cfg_length;
	usba_cfg_pwr_descr_t	confpwr_descr;
	usba_if_pwr_descr_t	ifpwr_descr;
	uint8_t 		cfg_attrib;
	int			i, lvl, rval;
	int			n_prop = 0;
	uint8_t 		*ptr;
	char			*drvname;
	char			str[USBA_POWER_STR_SIZE];
	char			*pm_comp[USBA_N_PMCOMP];

	USBA_CHECK_CONTEXT();

	if (usb_is_pm_enabled(dip) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	/* Obtain the raw configuration descriptor */
	usb_cfg = usb_get_raw_cfg_data(dip, &cfg_length);

	/* get configuration descriptor, must succceed */
	rval = usb_parse_cfg_descr(usb_cfg, cfg_length,
	    &cfg_descr, USB_CFG_DESCR_SIZE);
	ASSERT(rval == USB_CFG_DESCR_SIZE);

	cfg_attrib = cfg_descr.bmAttributes;
	*pwr_states = 0;

	/*
	 * Now start creating the pm-components strings
	 */
	drvname = (char *)ddi_driver_name(dip);
	(void) snprintf(str, USBA_POWER_STR_SIZE, "NAME= %s%d Power",
	    drvname, ddi_get_instance(dip));

	pm_comp[n_prop] = kmem_zalloc(strlen(str) + 1, KM_SLEEP);
	(void) strcpy(pm_comp[n_prop++], str);

	/*
	 * if the device is bus powered we look at the bBusPowerSavingDx
	 * fields else we look at bSelfPowerSavingDx fields.
	 * OS and USB power states are numerically reversed,
	 *
	 * Here is the mapping :-
	 *	OS State	USB State
	 *	0		D3	(minimal or no power)
	 *	1		D2
	 *	2		D1
	 *	3		D0	(Full power)
	 *
	 * if we own the whole device, we look at the config pwr descr
	 * else at the interface pwr descr.
	 */
	if (usb_owns_device(dip)) {
		/* Parse the configuration power descriptor */
		rval = usba_parse_cfg_pwr_descr(usb_cfg, cfg_length,
		    &confpwr_descr, USBA_CFG_PWR_DESCR_SIZE);

		if (rval != USBA_CFG_PWR_DESCR_SIZE) {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_create_pm_components: "
			    "usb_parse_cfg_pwr_descr returns length of %d, "
			    "expecting %d", rval, USBA_CFG_PWR_DESCR_SIZE);

			return (USB_FAILURE);
		}

		if (cfg_attrib & USB_CFG_ATTR_SELFPWR) {
			ptr = &confpwr_descr.bSelfPowerSavingD3;
		} else {
			ptr = &confpwr_descr.bBusPowerSavingD3;
		}
	} else {
		/* Parse the interface power descriptor */
		rval = usba_parse_if_pwr_descr(usb_cfg,
		    cfg_length,
		    usba_get_ifno(dip),	/* interface index */
		    0,			/* XXXX alt interface index */
		    &ifpwr_descr,
		    USBA_IF_PWR_DESCR_SIZE);

		if (rval != USBA_IF_PWR_DESCR_SIZE) {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_create_pm_components: "
			    "usb_parse_if_pwr_descr "
			    "returns length of %d, "
			    "expecting %d", rval, USBA_CFG_PWR_DESCR_SIZE);

			return (USB_FAILURE);
		}

		if (cfg_attrib & USB_CFG_ATTR_SELFPWR) {
			ptr =  &ifpwr_descr.bSelfPowerSavingD3;
		} else {
			ptr =  &ifpwr_descr.bBusPowerSavingD3;
		}
	}

	/* walk thru levels and create prop level=name strings */
	for (lvl = USB_DEV_OS_PWR_0; lvl <= USB_DEV_OS_PWR_3; lvl++) {
		if (*ptr || (lvl == USB_DEV_OS_PWR_3)) {
			(void) snprintf(str, USBA_POWER_STR_SIZE,
			    "%d=USB D%d State",
			    lvl, USB_DEV_OS_PWR2USB_PWR(lvl));
			pm_comp[n_prop] = kmem_zalloc(strlen(str) + 1,
			    KM_SLEEP);
			(void) strcpy(pm_comp[n_prop++], str);

			*pwr_states |= USB_DEV_PWRMASK(lvl);
		}

		ptr -= 2; /* skip to the next power state */
	}

	USB_DPRINTF_L3(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_create_pm_components: pwr_states: %x", *pwr_states);

	/* now create the actual components */
	rval = ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "pm-components", pm_comp, n_prop);
	if (rval == DDI_PROP_SUCCESS) {
		rval = USB_SUCCESS;
	} else {
		rval = USB_FAILURE;
	}

	/* display & delete properties */
	USB_DPRINTF_L3(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_create_pm_components: The properties are:");
	for (i = 0; i < n_prop; i++) {
		USB_DPRINTF_L3(DPRINT_MASK_USBAI, usbai_log_handle,
		    "\t%s", pm_comp[i]);
		kmem_free(pm_comp[i], strlen(pm_comp[i]) + 1);
	}

	return (rval);
}


/*
 * Generic Functions to set the power level of any usb device
 *
 * Since OS and USB power states are numerically reverse,
 * Here is the mapping :-
 *	OS State	USB State
 *	0		D3	(minimal or no power)
 *	1		D2
 *	2		D1
 *	3		D0	(Full power)
 */

/* set device power level to 0 (full power) */
/*ARGSUSED*/
int
usb_set_device_pwrlvl0(dev_info_t *dip)
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_set_device_pwrlvl0 : Not Yet Implemented");

	return (USB_SUCCESS);
}


/* set device power level to 1	*/
/*ARGSUSED*/
int
usb_set_device_pwrlvl1(dev_info_t *dip)
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_set_device_pwrlvl1 : Not Yet Implemented");

	return (USB_SUCCESS);
}


/* set device power level to 2	*/
/*ARGSUSED*/
int
usb_set_device_pwrlvl2(dev_info_t *dip)
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_set_device_pwrlvl2 : Not Yet Implemented");

	return (USB_SUCCESS);
}


/* set device power level to 3	*/
/*ARGSUSED*/
int
usb_set_device_pwrlvl3(dev_info_t *dip)
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_set_device_pwrlvl3 : Not Yet Implemented");

	return (USB_SUCCESS);
}


/*
 * USB event management
 */
typedef void (*peh_t)(dev_info_t *, ddi_eventcookie_t, void *, void *);


/*
 * usb_register_hotplug_cbs:
 *	Register to get callbacks for hotplug events
 */
/*ARGSUSED*/
int
usb_register_hotplug_cbs(dev_info_t *dip,
    int (*disconnect_event_handler)(dev_info_t *),
    int (*reconnect_event_handler)(dev_info_t *))
{
	usba_device_t		*usba_device;
	usba_evdata_t		*evdata;

	if ((dip == NULL) || (disconnect_event_handler == NULL) ||
	    (reconnect_event_handler == NULL)) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_register_hotplug_cbs: Bad argument(s)");

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_register_hotplug_cbs: entry");

	/*
	 * The event list searches by ddi_get_eventcookie calls below, go
	 * through hubd and so do not apply to host controllers.
	 */
	ASSERT(!usba_is_root_hub(dip));

	usba_device = usba_get_usba_device(dip);
	evdata = usba_get_evdata(dip);

	if (usba_device->rm_cookie == NULL) {
		if (ddi_get_eventcookie(dip, DDI_DEVI_REMOVE_EVENT,
		    &usba_device->rm_cookie) != DDI_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_register_hotplug_cbs: get rm cookie failed");

			goto fail;
		}
	}
	if (ddi_add_event_handler(dip, usba_device->rm_cookie,
	    (peh_t)(uintptr_t)disconnect_event_handler,
	    NULL, &evdata->ev_rm_cb_id) != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_register_hotplug_cbs: add disconnect handler failed");

		goto fail;
	}

	if (usba_device->ins_cookie == NULL) {
		if (ddi_get_eventcookie(dip, DDI_DEVI_INSERT_EVENT,
		    &usba_device->ins_cookie) != DDI_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_register_hotplug_cbs: get ins cookie failed");

			goto fail;
		}
	}
	if (ddi_add_event_handler(dip, usba_device->ins_cookie,
	    (peh_t)(uintptr_t)reconnect_event_handler,
	    NULL, &evdata->ev_ins_cb_id) != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_register_hotplug_cbs: add reconnect handler failed");

		goto fail;
	}

	mutex_enter(&usba_device->usb_mutex);
	usba_device->usb_client_flags[usba_get_ifno(dip)] |=
	    USBA_CLIENT_FLAG_EV_CBS;
	usba_device->usb_client_ev_cb_list->dip = dip;
	mutex_exit(&usba_device->usb_mutex);

	return (USB_SUCCESS);

fail:
	usb_unregister_hotplug_cbs(dip);

	return (USB_FAILURE);

}


/*
 * usb_unregister_hotplug_cbs:
 *	Unregister hotplug callbacks
 */
/*ARGSUSED*/
void
usb_unregister_hotplug_cbs(dev_info_t *dip)
{
	usb_unregister_event_cbs(dip, NULL);
}


/*
 * usb_register_event_cbs:
 *	Register to get callbacks for USB events
 */
/*ARGSUSED*/
int
usb_register_event_cbs(dev_info_t *dip, usb_event_t *usb_evdata,
    usb_flags_t flags)
{
	usba_device_t		*usba_device;
	usba_evdata_t		*evdata;

	if ((dip == NULL) || (usb_evdata == NULL)) {

		return (USB_FAILURE);
	}

	/*
	 * The event list searches by ddi_get_eventcookie calls below, go
	 * through hubd and so do not apply to host controllers.
	 */
	ASSERT(!usba_is_root_hub(dip));

	usba_device = usba_get_usba_device(dip);
	evdata = usba_get_evdata(dip);

	if (usb_evdata->disconnect_event_handler != NULL) {
		if (usba_device->rm_cookie == NULL) {
			if (ddi_get_eventcookie(dip, DDI_DEVI_REMOVE_EVENT,
			    &usba_device->rm_cookie) != DDI_SUCCESS) {

				goto fail;
			}
		}
		if (ddi_add_event_handler(dip, usba_device->rm_cookie,
		    (peh_t)(uintptr_t)usb_evdata->disconnect_event_handler,
		    NULL, &evdata->ev_rm_cb_id) != DDI_SUCCESS) {

			goto fail;
		}
	}
	if (usb_evdata->reconnect_event_handler != NULL) {
		if (usba_device->ins_cookie == NULL) {
			if (ddi_get_eventcookie(dip, DDI_DEVI_INSERT_EVENT,
			    &usba_device->ins_cookie) != DDI_SUCCESS) {

				goto fail;
			}
		}
		if (ddi_add_event_handler(dip, usba_device->ins_cookie,
		    (peh_t)(uintptr_t)usb_evdata->reconnect_event_handler,
		    NULL, &evdata->ev_ins_cb_id) != DDI_SUCCESS) {

			goto fail;
		}
	}
	if (usb_evdata->post_resume_event_handler != NULL) {
		if (usba_device->resume_cookie == NULL) {
			if (ddi_get_eventcookie(dip, USBA_POST_RESUME_EVENT,
			    &usba_device->resume_cookie) != DDI_SUCCESS) {

				goto fail;
			}
		}
		if (ddi_add_event_handler(dip, usba_device->resume_cookie,
		    (peh_t)(uintptr_t)usb_evdata->post_resume_event_handler,
		    NULL, &evdata->ev_resume_cb_id) != DDI_SUCCESS) {

			goto fail;
		}
	}
	if (usb_evdata->pre_suspend_event_handler != NULL) {
		if (usba_device->suspend_cookie == NULL) {
			if (ddi_get_eventcookie(dip, USBA_PRE_SUSPEND_EVENT,
			    &usba_device->suspend_cookie) != DDI_SUCCESS) {

				goto fail;
			}
		}
		if (ddi_add_event_handler(dip, usba_device->suspend_cookie,
		    (peh_t)(uintptr_t)usb_evdata->pre_suspend_event_handler,
		    NULL, &evdata->ev_suspend_cb_id) != DDI_SUCCESS) {

			goto fail;
		}
	}

	mutex_enter(&usba_device->usb_mutex);
	usba_device->usb_client_flags[usba_get_ifno(dip)] |=
	    USBA_CLIENT_FLAG_EV_CBS;
	usba_device->usb_client_ev_cb_list->dip = dip;
	usba_device->usb_client_ev_cb_list->ev_data = usb_evdata;
	mutex_exit(&usba_device->usb_mutex);

	return (USB_SUCCESS);

fail:
	usb_unregister_event_cbs(dip, usb_evdata);

	return (USB_FAILURE);

}


/*
 * usb_unregister_event_cbs:
 *	Unregister all event callbacks
 */
/*ARGSUSED*/
void
usb_unregister_event_cbs(dev_info_t *dip, usb_event_t *usb_evdata)
{
	usba_evdata_t		*evdata;
	usba_device_t		*usba_device = usba_get_usba_device(dip);

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

	mutex_enter(&usba_device->usb_mutex);
	usba_device->usb_client_flags[usba_get_ifno(dip)] &=
	    ~USBA_CLIENT_FLAG_EV_CBS;
	mutex_exit(&usba_device->usb_mutex);
}

int
usb_reset_device(dev_info_t *dip, usb_dev_reset_lvl_t reset_level)
{
	return (usba_hubdi_reset_device(dip, reset_level));
}

/*
 * usb device driver registration
 */
int
usb_register_dev_driver(dev_info_t *dip, usb_dev_driver_callback_t cb)
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_register_dev_driver: register the specified driver "
	    "in usba: dip = 0x%p", (void *)dip);

	if (cb != NULL) {
		usb_cap.dip = dip;
		usb_cap.usba_dev_driver_cb = cb;

		return (USB_SUCCESS);
	}

	return (USB_FAILURE);
}

/*
 * usb device driver unregistration
 */
void
usb_unregister_dev_driver(dev_info_t *dip)
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_unregister_dev_driver: unregister the registered "
	    "driver: dip =0x%p", (void *)dip);

	ASSERT(dip == usb_cap.dip);
	usb_cap.dip = NULL;
	usb_cap.usba_dev_driver_cb = NULL;
}
