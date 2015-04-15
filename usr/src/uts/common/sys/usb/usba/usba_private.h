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
 *
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#ifndef	_SYS_USB_USBA_USBA_PRIVATE_H
#define	_SYS_USB_USBA_USBA_PRIVATE_H


#include <sys/sunndi.h>

/*
 * Header file for items to be shared within usba but not to be used
 * by drivers
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * **************************************************************************
 * DDK version 0.8 binaries are supported.
 * **************************************************************************
 */

/* USBA supports (obsolete) legacy version 0.8 of the S8/S9 DDK. */
#define	USBA_LEG_MAJOR_VER	0
#define	USBA_LEG_MINOR_VER	8

/*
 * **************************************************************************
 * Descriptor definitions and parsing functions.
 * **************************************************************************
 */

/*
 * functions to return a pre-processed device descriptor to the client driver.
 * These all extract data from the raw config cloud  returned by a
 * usb_get_raw_cfg_data()
 *
 * The pre-processed descriptor is returned into a buffer supplied by
 * the caller
 * The size of the buffer should allow for padding
 *
 * In the following:
 *	buf		buffer containing data returned by GET_DESCRIPTOR
 *	buflen		length of the data at buf
 *	ret_descr	buffer the data is to be returned in
 *	ret_buf_len	size of the buffer at ret_descr
 *
 * 	first_if	the first interace associated with current iad
 *	if_index	the index in the array of concurrent interfaces
 *			supported by this configuration
 *	alt_if_setting	alternate setting for the interface identified
 *			by if_index
 *	ep_index	the index in the array of endpoints supported by
 *			this configuration
 *
 * These functions return the length of the returned descriptor structure,
 * or USB_PARSE_ERROR on error.
 *
 * No error is returned if ret_buf_len is too small but
 * the data is truncated
 * This allows successful parsing of descriptors that have been
 * extended in a later rev of the spec.
 */
size_t usb_parse_dev_descr(
	uchar_t			*buf,	/* from GET_DESCRIPTOR(DEVICE) */
	size_t			buflen,
	usb_dev_descr_t		*ret_descr,
	size_t			ret_buf_len);


size_t usb_parse_cfg_descr(
	uchar_t			*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	usb_cfg_descr_t		*ret_descr,
	size_t			ret_buf_len);


size_t usb_parse_ia_descr(
	uchar_t			*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	size_t			first_if,
	usb_ia_descr_t		*ret_descr,
	size_t			ret_buf_len);


size_t usb_parse_if_descr(
	uchar_t			*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	uint_t			if_index,
	uint_t			alt_if_setting,
	usb_if_descr_t		*ret_descr,
	size_t			ret_buf_len);


/*
 * the endpoint index is relative to the interface. index 0 is
 * the first endpoint
 */
size_t usb_parse_ep_descr(
	uchar_t			*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	uint_t			if_index,
	uint_t			alt_if_setting,
	uint_t			ep_index,
	usb_ep_descr_t		*ret_descr,
	size_t			ret_buf_len);

/*
 * functions to handle arbitrary descriptors. USBA doesn't know the format
 * and therefore cannot do any automatic pre-processing.
 *
 * In the following:
 *	buf		buffer containing data returned by GET_DESCRIPTOR
 *	buflen		length of the data at buf allowing for padding
 *	fmt		a null terminated string describing the format of
 *			the data structure for general-purpose byte swapping,
 *			use NULL for raw access.
 *			The letters "c", "s", "l", and "L"
 *			represent 1, 2, 4, and 8 byte quantities,
 *			respectively.  A descriptor that consists of a
 *			short and two bytes would be described by "scc\0".
 *	descr_type	type of the desired descriptor, USB_DESCR_TYPE_ANY
 *			to get any type.
 *	descr_index	index of the desired descriptor
 *	ret_descr	buffer the data is to be returned in
 *	ret_buf_len	size of the buffer at ret_descr
 *
 * Specifying descr_index=0 returns the first descriptor of the specified
 * type, specifying descr_index=1 returns the second, and so on.
 *
 * No error is returned if ret_buf_len is too small. This allows successful
 * parsing of descriptors that have been extended in a later rev of the spec.
 */
#define	USB_DESCR_TYPE_ANY			-1	/* Wild card */

size_t usb_parse_CV_cfg_descr(
	uchar_t			*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	char			*fmt,
	uint_t			descr_type,
	uint_t			descr_index,
	void			*ret_descr,
	size_t			ret_buf_len);


size_t usb_parse_CV_if_descr(
	uchar_t			*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	char			*fmt,
	uint_t			if_index,
	uint_t			alt_if_setting,
	uint_t			descr_type,
	uint_t			descr_index,
	void			*ret_descr,
	size_t			ret_buf_len);


size_t usb_parse_CV_ep_descr(
	uchar_t			*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	char			*fmt,
	uint_t			if_index,
	uint_t			alt_if_setting,
	uint_t			ep_index,
	uint_t			descr_type,
	uint_t			descr_index,
	void			*ret_descr,
	size_t			ret_buf_len);


/*
 * for unpacking any kind of LE data
 */
size_t usb_parse_CV_descr(
	char			*format,
	uchar_t			*data,
	size_t			datalen,
	void			*structure,
	size_t			structlen);

/*
 * Returns pointer to the raw config cloud. The client should
 * not free this space.
 */
uchar_t *usb_get_raw_cfg_data(
	dev_info_t		*dip,
	size_t			*length);

/*
 * Return pointer to device descriptor
 */
usb_dev_descr_t *usb_get_dev_descr(
	dev_info_t		*dip);


/*
 * **************************************************************************
 * List entry functions and definitions
 * **************************************************************************
 */

/*
 * Data structure for maintaining lists
 * This data structure private to USBA and not exposed to HCD or client
 * driver or hub driver
 */
typedef struct usba_list_entry {
	struct usba_list_entry	*next;		/* ptr to next element */
	struct usba_list_entry	*prev;		/* ptr to previous element */
	kmutex_t		list_mutex;	/* mutex that protects queue */
	usb_opaque_t		private;	/* ptr to private data */
	int			count;		/* for head of the list */
						/* counts of entries */
} usba_list_entry_t;

_NOTE(MUTEX_PROTECTS_DATA(usba_list_entry::list_mutex, usba_list_entry))


/* list entry functions. */
void	usba_init_list(usba_list_entry_t *, usb_opaque_t,
					ddi_iblock_cookie_t);
void	usba_destroy_list(usba_list_entry_t *);
void	usba_add_to_list(usba_list_entry_t *, usba_list_entry_t *);
int	usba_rm_from_list(usba_list_entry_t *, usba_list_entry_t *);
void	usba_move_list(usba_list_entry_t *, usba_list_entry_t *,
					ddi_iblock_cookie_t);
int	usba_check_in_list(usba_list_entry_t *, usba_list_entry_t *);
int	usba_list_entry_leaks(usba_list_entry_t *, char *);
int	usba_list_entry_count(usba_list_entry_t *);

usb_opaque_t usba_rm_first_pvt_from_list(usba_list_entry_t *);
usba_list_entry_t *usba_rm_first_from_list(usba_list_entry_t *);

/*
 * **************************************************************************
 * Kernel interface definitions and functionality
 * **************************************************************************
 */

/*
 * USBA private event definitions
 */
typedef enum usba_event {
	USBA_EVENT_TAG_HOT_REMOVAL = 0,
	USBA_EVENT_TAG_HOT_INSERTION = 1,
	USBA_EVENT_TAG_PRE_SUSPEND = 2,
	USBA_EVENT_TAG_POST_RESUME = 3,
	USBA_EVENT_TAG_CPR = -1
} usba_event_t;

#define	USBA_PRE_SUSPEND_EVENT	"SUNW,USBA:USBA_PRE_SUSPEND"
#define	USBA_POST_RESUME_EVENT	"SUNW,USBA:USBA_POST_RESUME"

/*
 * Get dma attributes from HC.
 */
ddi_dma_attr_t *usba_get_hc_dma_attr(dev_info_t *dip);

/*
 * This function calls ndi_devi_bind_driver() to bind the
 * driver to the device. If the call fails it reports an
 * error on the console. Attaching of the driver is done
 * later by devfs framework.
 */
int usba_bind_driver(dev_info_t *);

/* check whether the dip owns an interface-associaiton */
boolean_t usba_owns_ia(dev_info_t *dip);

/*
 * Driver binding functions
 */
dev_info_t *usba_ready_device_node(dev_info_t *);
dev_info_t *usba_ready_interface_association_node(dev_info_t *,
					uint_t, uint_t *);
dev_info_t *usba_ready_interface_node(dev_info_t *, uint_t);

/* Some Nexus driver functions. */

/*
 * Common bus ctl for hcd, usb_mid and hubd.
 */
int	usba_bus_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
					void *, void *);

void	usb_enable_parent_notification(dev_info_t *);

/*
 * Some functions for setting/getting usba_device from dip.
 */
struct	usba_device	*usba_get_usba_device(dev_info_t *);
struct	usba_device	*usba_polled_get_usba_device(dev_info_t *);
void	usba_set_usba_device(dev_info_t *, struct usba_device *);

/* extract NDI event registration info */
struct	usba_evdata	*usba_get_evdata(dev_info_t *);

/*
 * **************************************************************************
 * Misc private USBA functions
 * **************************************************************************
 */

/*
 * Get policy of a pipe while holding only opaque pipe handle.
 */
usb_pipe_policy_t *usba_pipe_get_policy(usb_pipe_handle_t);

/*
 * Check interrupt context and or in USB_CB_INTR_CONTEXT to cb_flags as needed.
 */
usb_cb_flags_t	usba_check_intr_context(usb_cb_flags_t);

/* returns interface number, zero if driver owns the device */
uint8_t	usba_get_ifno(dev_info_t *);

/*
 * **************************************************************************
 * Misc private descriptor definitions and functionality
 * **************************************************************************
 */

/* default endpoint descriptor */
extern usb_ep_descr_t   usba_default_ep_descr;

/*
 * The compiler pads the above structures;  the following represent the
 * unpadded, aggregate data sizes.
 */
#define	USB_DEV_DESCR_SIZE	18	/* device descr size */
#define	USB_CFG_DESCR_SIZE	 9	/* configuration desc. size */
#define	USBA_CFG_PWR_DESCR_SIZE	18	/* configuration pwr desc. size */
#define	USB_IF_DESCR_SIZE	 9	/* interface descr size */
#define	USBA_IF_PWR_DESCR_SIZE	15	/* interface pwr descr size */
#define	USB_EP_DESCR_SIZE	 7	/* endpoint descr size */
#define	USB_IA_DESCR_SIZE	 8	/* interface association descr size */

/*
 * For compatibility with old code.
 */
#define	USBA_DESCR_TYPE_CFG_PWR_1_1	0xfe
#define	USBA_DESCR_TYPE_IF_PWR_1_1	0xff

/*
 * Configuration Power Descriptor
 *	This reports the power consuption of the device core
 *	for all types of USB devices.
 */
typedef struct usba_cfg_pwr_descr {
	uint8_t		bLength;	/* size of this descriptor 0x12 */
	uint8_t		bDescriptorType;	/* config pwr descr 0x07 */
	uint16_t	SelfPowerConsumedD0_l;	/* power consumed lower word */
	uint8_t		SelfPowerConsumedD0_h;	/* power consumed upper byte */
	uint8_t		bPowerSummaryId;	/* ID for own power devices */
	uint8_t		bBusPowerSavingD1;	/* power saving in D1 */
	uint8_t		bSelfPowerSavingD1;	/* power saving in D1 */
	uint8_t		bBusPowerSavingD2;	/* power saving in D2 */
	uint8_t		bSelfPowerSavingD2;	/* power saving in D2 */
	uint8_t		bBusPowerSavingD3;	/* power saving in D3 */
	uint8_t		bSelfPowerSavingD3;	/* power saving in D3 */
	uint16_t	TransitionTimeFromD1;	/* D1 -> D0 transition time */
	uint16_t	TransitionTimeFromD2;	/* D2 -> D0 transition time */
	uint16_t	TransitionTimeFromD3;	/* D3 -> D0 transition time */
} usba_cfg_pwr_descr_t;

/*
 * Interface Power Descriptor
 *	This reports the power states implemented by the interface
 *	and its wake-up capabilities.
 */
typedef struct usba_if_pwr_descr {
	uint8_t		bLength;	/* size of this descriptor 0x0F */
	uint8_t		bDescriptorType;	/* i/f pwr descr 0x08 */
	uint8_t		bmCapabilitiesFlags;	/* wakeup & pwr transition */
	uint8_t		bBusPowerSavingD1;	/* power saving in D1 */
	uint8_t		bSelfPowerSavingD1;	/* power saving in D1 */
	uint8_t		bBusPowerSavingD2;	/* power saving in D2 */
	uint8_t		bSelfPowerSavingD2;	/* power saving in D2 */
	uint8_t		bBusPowerSavingD3;	/* power saving in D3 */
	uint8_t		bSelfPowerSavingD3;	/* power saving in D3 */
	uint16_t	TransitionTimeFromD1;	/* D1 -> D0 transition time */
	uint16_t	TransitionTimeFromD2;	/* D2 -> D0 transition time */
	uint16_t	TransitionTimeFromD3;	/* D3 -> D0 transition time */
} usba_if_pwr_descr_t;

size_t usba_parse_cfg_pwr_descr(uchar_t *, size_t, usba_cfg_pwr_descr_t *,
						size_t);

size_t usba_parse_if_pwr_descr(uchar_t *, size_t buflen, uint_t,
	uint_t, usba_if_pwr_descr_t *, size_t);

/*
 * Returns (at ret_descr) a null-terminated string.  Null termination is
 * guaranteed, even if the string is longer than the buffer.  Thus, a
 * maximum of (ret_buf_len - 1) characters are returned.
 *
 * XXX is this needed when there is usb_get_string_descriptor
 * If so, then more comments about how it differs?
 */
size_t usba_ascii_string_descr(uchar_t *, size_t, char *, size_t);


/*
 * usb common power management, for usb_mid, usb_ia and maybe other simple
 * drivers.
 */
typedef struct usb_common_power_struct {
	void		*uc_usb_statep;	/* points back to state structure */

	uint8_t		uc_wakeup_enabled;

	/* this is the bit mask of the power states that device has */
	uint8_t		uc_pwr_states;

	/* wakeup and power transition capabilites of an interface */
	uint8_t		uc_pm_capabilities;

	uint8_t		uc_current_power;	/* current power level */
} usb_common_power_t;

/* warlock directives, stable data */

_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_common_power_t::uc_usb_statep))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_common_power_t::uc_wakeup_enabled))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_common_power_t::uc_pwr_states))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_common_power_t::uc_pm_capabilities))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_common_power_t::uc_current_power))

/* power management */
int usba_common_power(dev_info_t *, uint8_t *, int *, int);

/*
 * usb common events handler for usb_mid, usb_ia and maybe other nexus
 * drivers.
 */

void usba_common_register_events(dev_info_t *, uint_t,
	void (*)(dev_info_t *, ddi_eventcookie_t, void *, void *));

void usba_common_unregister_events(dev_info_t *, uint_t);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBA_USBA_PRIVATE_H */
