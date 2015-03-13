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

#ifndef	_SYS_USB_USBA_USBAI_PRIVATE_H
#define	_SYS_USB_USBA_USBAI_PRIVATE_H


/*
 * Unstable interfaces not part of USBAI but used by Solaris client drivers.
 * These interfaces may not be present in future releases and are highly
 * unstable.
 *
 * Status key:
 *	C = Remove from Sun client drivers before removing from this file
 *	D = May be needed by legacy (DDK) drivers.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * convenience function for getting default config index
 * as saved in usba_device structure
 *
 * Status: C
 */
uint_t usb_get_current_cfgidx(dev_info_t *);

/*
 * **************************************************************************
 * Error and status definitions, and reporting functions
 * **************************************************************************
 */


/*
 * convenience functions to get string corresponding to value
 * usb_cb_flags_name requires a workbuffer of sufficient length
 * for the concatenation of all strings as usb_cb_flags_t is a bit
 * mask
 *
 * Status: C and D
 */
const char	*usb_str_cr(usb_cr_t cr);
char		*usb_str_cb_flags(usb_cb_flags_t cb_flags,
		char *buffer, size_t length);
const char	*usb_str_pipe_state(usb_pipe_state_t state);
const char	*usb_str_dev_state(int state);
const char	*usb_str_rval(int rval);

/* function convert a USB return value to an errno */
int		usb_rval2errno(int rval);

/*
 * **************************************************************************
 * Transfer-related definitions and functions
 * **************************************************************************
 */

/* Status C and D for whole section. */

/* Serialize callbacks per interface or device. */
#define	USB_FLAGS_SERIALIZED_CB	0x8000

/* default timeout for control requests (in seconds) */
#define	USB_PIPE_TIMEOUT	3

/*
 * usb_pipe_sync_ctrl_xfer():
 *	for simple synchronous control transactions this wrapper function
 *	will perform the allocation, xfer, and deallocation.
 *	USB_ATTRS_AUTOCLEARING will be enabled
 *
 * ARGUMENTS:
 *	dip		- pointer to clients devinfo.
 *	pipe_handle	- control pipe pipehandle (obtained via usb_pipe_open().
 *	bmRequestType	- characteristics of request.
 *	bRequest	- specific request.
 *	wValue		- varies according to request.
 *	wIndex		- index or offset.
 *	wLength		- number of bytes to xfer.
 *	data		- pointer to pointer to data
 *			  IN: HCD will allocate data
 *			  OUT: clients driver allocates data.
 *	attrs		- required request attributes.
 *	completion_reason - completion status.
 *	cb_flags	- request completions flags.
 *	flags		- none.
 *
 * RETURN VALUES:
 *	USB_SUCCESS	- request successfully executed.
 *	USB_FAILURE	- request failed.
 *
 * NOTES:
 * - in the case of failure, the client should check completion_reason and
 *   and cb_flags and determine further recovery action
 * - the client should check data and if non-zero, free the data on
 *   completion
 */
int usb_pipe_sync_ctrl_xfer(
	dev_info_t	*dip,
	usb_pipe_handle_t pipe_handle,
	uchar_t 	bmRequestType,
	uchar_t 	bRequest,
	uint16_t	wValue,
	uint16_t	wIndex,
	uint16_t	wLength,
	mblk_t		**data,
	usb_req_attrs_t attrs,
	usb_cr_t	*completion_reason,
	usb_cb_flags_t	*cb_flags,
	usb_flags_t	flags);

/*
 * **************************************************************************
 * Event registration / pre-suspend and post-resume handling
 * **************************************************************************
 */

/* Status: C and D for whole section. */

/*
 * Event registration info for both hotplug and pre-suspend/post-resume
 * callbacks.  Eventually pre-suspend and post-resume callbacks will not be
 * needed, so this is for this OS release only and will go away in a
 * subsequent release.
 */
typedef struct usb_event {
	/* device disconnected/unplugged */
	int	(*disconnect_event_handler)(dev_info_t *dip);

	/* device reconnected */
	int	(*reconnect_event_handler)(dev_info_t *dip);

	/* notification that system is about to checkpoint */
	int	(*pre_suspend_event_handler)(dev_info_t *dip);

	/* notification that system resumed after a checkpoint */
	int	(*post_resume_event_handler)(dev_info_t *dip);
} usb_event_t;

/*
 * Event callbacks
 *	the callbacks should always return USB_SUCCESS.
 */
int usb_register_event_cbs(
	dev_info_t	*dip,
	usb_event_t	*usb_evt_data,
	usb_flags_t	flags);

void usb_unregister_event_cbs(
	dev_info_t	*dip,
	usb_event_t	*usb_evt_data);

/*
 * USB CPR support
 *	A client driver must call this funtion in pre-suspend event handler
 *	to inform the USBA framework that it can't suspend because
 *	driver instance or device could not be quiesced.
 */
void usb_fail_checkpoint(
	dev_info_t	*dip,
	usb_flags_t	flags);


/*
 * **************************************************************************
 * Logging functions remaining Contracted Consolidation Private
 * **************************************************************************
 */

/* Status: C and D for whole section. */

/*
 * Usb logging, debug and console message handling.
 */
typedef struct usb_log_handle *usb_log_handle_t;

#define	USB_LOG_L0	0	/* warnings, console & syslog buffer */
#define	USB_LOG_L1	1	/* errors, syslog buffer */
#define	USB_LOG_L2	2	/* recoverable errors, debug only */
#define	USB_LOG_L3	3	/* interesting data, debug only */
#define	USB_LOG_L4	4	/* tracing, debug only */

#ifdef DEBUG
#define	USB_DPRINTF_L4(...)	usb_dprintf4(__VA_ARGS__)
#define	USB_DPRINTF_L3(...)	usb_dprintf3(__VA_ARGS__)

/*PRINTFLIKE3*/
void usb_dprintf4(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...);
/*PRINTFLIKE3*/
void usb_dprintf3(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...);
#else
#define	USB_DPRINTF_L4(...)	((void)0)
#define	USB_DPRINTF_L3(...)	((void)0)
#endif

#define	USB_DPRINTF_L2	usb_dprintf2
#define	USB_DPRINTF_L1	usb_dprintf1
#define	USB_DPRINTF_L0	usb_dprintf0

/*PRINTFLIKE3*/
void usb_dprintf2(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...);
/*PRINTFLIKE3*/
void usb_dprintf1(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...);
/*PRINTFLIKE3*/
void usb_dprintf0(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...);

usb_log_handle_t usb_alloc_log_hdl(
	dev_info_t	*dip,
	char		*name,
	uint_t		*errlevel,
	uint_t		*mask,
	uint_t		*instance_filter,
	usb_flags_t	flags);

/* free the log handle */
void usb_free_log_hdl(
	usb_log_handle_t handle);

/* log message */
/*PRINTFLIKE4*/
int usb_log(
	usb_log_handle_t handle,
	uint_t		level,
	uint_t		mask,
	char		*fmt, ...);

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
 *					USB_CHK_SERIAL: check match on device
 *						serial number.
 *					USB_CHK_CFG: compare config clouds
 *						byte by byte
 *					USB_CHK_VIDPID: compare product
 *						and vendor ID
 *					USB_CHK_ALL: perform all checks
 *
 *				NOTE: descr length and content always checked
 *	device_string		- Device string to appear in error message
 *
 * return values:
 *	USB_SUCCESS:		same device
 *	USB_INVALID_VERSION	not same device
 *	USB_FAILURE:		Failure processing request
 *	USB_INVALID_ARG:	dip is invalid
 */

/* Checking bits for checks made by usb_check_same_device */
#define	USB_CHK_BASIC	0		/* Empty mask.	Basics always done. */
#define	USB_CHK_SERIAL	0x00000001	/* Compare device serial numbers. */
#define	USB_CHK_CFG	0x00000002	/* Compare raw config clouds. */
#define	USB_CHK_VIDPID	0x00000004	/* Compare product and vendor ID. */
#define	USB_CHK_ALL	0xFFFFFFFF	/* Perform maximum checking. */

int usb_check_same_device(
	dev_info_t		*dip,
	usb_log_handle_t	log_handle,
	int			log_level,
	int			log_mask,
	uint_t			check_mask,
	char			*device_string);

/*
 * **************************************************************************
 * Power management functions remaining Contracted Consolidation Private
 * **************************************************************************
 */

/*
 * usb wrapper around pm_raise_power & pm_lower_power to allow for
 * non blocking behavior
 *
 * Arguments:
 *	dip		- pointer to devinfo node of client.
 *	comp		- component.
 *	level		- power level.
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for completion.
 *	cb		- function called on completion, may be NULL.
 *	arg		- callback argument.
 *	rval		- USB_SUCCESS or USB_FAILURE.
 *
 * Return Values:
 *	USB_SUCCESS	-  if no USB_FLAGS_SLEEP has been specified, the request
 *			   has been queued for async execution. If
 *			   USB_FLAGS_SLEEP has been specified, the raising or
 *			   lowering of power
 *			   succeeded.
 *	USB_FAILURE	-  request could not be queued or raising or lowering
 *			   of power failed.
 */

/* Status: C and D */
int usb_req_raise_power(
	dev_info_t	*dip,
	int		comp,
	int		level,
	void		(*cb)(void *arg, int rval),
	void		*arg,
	usb_flags_t	flags);

/* Status: D */
int usb_req_lower_power(
	dev_info_t	*dip,
	int		comp,
	int		level,
	void		(*cb)(void *arg, int rval),
	void		*arg,
	usb_flags_t	flags);

/*
 * USB wrapper functions to set usb device power level.
 * Note : Power levels indicated here are USB power levels
 * and not OS power levels.
 *
 * Note that these were never implemented, and are noops.  However, they are
 * included here as the skeleton driver in DDK 0.8 and 0.9 mentioned them.
 *
 * Status: C and D.
 */
int usb_set_device_pwrlvl0(
	dev_info_t	*dip);
int usb_set_device_pwrlvl1(
	dev_info_t	*dip);
int usb_set_device_pwrlvl2(
	dev_info_t	*dip);
int usb_set_device_pwrlvl3(
	dev_info_t	*dip);


/*
 * **************************************************************************
 * Serialization functions remaining Contracted Consolidation Private
 * **************************************************************************
 */

/* This whole section: status: C and D. */

/*
 * opaque serialization handle.
 *	Used by all usb_serialization routines.
 *
 *	This handle is opaque to the client driver.
 */
typedef	struct usb_serialization	*usb_serialization_t;

/*
 * usb_init_serialization
 *	setup for serialization
 *
 * ARGUMENTS:
 *	s_dip		- devinfo pointer
 *	flag		- USB_INIT_SER_CHECK_SAME_THREAD
 *			  when set, usb_release_access() will
 *			  verify that the same thread releases
 *			  access. If not, a console warning will
 *			  be issued but access will be released
 *			  anyways.
 *
 * RETURNS:
 *	usb_serialization handle
 *
 */
usb_serialization_t usb_init_serialization(
	dev_info_t	*s_dip,
	uint_t		flag);

#define	USB_INIT_SER_CHECK_SAME_THREAD	1

/* fini for serialization */
void usb_fini_serialization(
	usb_serialization_t usb_serp);

/*
 * Various ways of calling usb_serialize_access.  These correspond to
 * their cv_*wait* function counterparts for usb_serialize_access.
 */
#define	USB_WAIT		0
#define	USB_WAIT_SIG		1
#define	USB_TIMEDWAIT		2
#define	USB_TIMEDWAIT_SIG	3

/*
 * usb_serialize_access:
 *	acquire serialized access
 * ARGUMENTS:
 *	usb_serp	- usb_serialization handle
 *	how_to_wait	- Which cv_*wait* function to wait for condition.
 *				USB_WAIT:		use cv_wait
 *				USB_WAIT_SIG:		use cv_wait_sig
 *				USB_TIMEDWAIT:		use cv_timedwait
 *				USB_TIMEDWAIT_SIG:	use cv_timedwait_sig
 *	delta_timeout	- Time in ms from current time to timeout.  Checked
 *			  only if USB_TIMEDWAIT or USB_TIMEDWAIT_SIG
 *			  specified in how_to_wait.
 * RETURNS:
 *	Same as values returned by cv_*wait* functions,
 *	except for when how_to_wait == USB_WAIT, where 0 is always returned.
 *	For calls where a timeout or signal could be expected, use this value
 *	to tell whether a kill(2) signal or timeout occurred.
 */
int usb_serialize_access(
	usb_serialization_t	usb_serp,
	uint_t			how_to_wait,
	uint_t			delta_timeout);

/*
 * usb_try_serialize_access:
 *	try acquiring serialized access
 *
 * ARGUMENTS:
 *	usb_serp	- usb_serialization handle
 *	flag		- unused
 *
 * RETURNS:
 *	USB_SUCCESS	- access has been acquired
 *	USB_FAILURE	- access has not been acquired
 */
int usb_try_serialize_access(usb_serialization_t usb_serp, uint_t flag);

/*
 * usb_release_access:
 *	release serialized access
 *
 * ARGUMENTS:
 *	usb_serp	- usb_serialization handle
 */
void usb_release_access(usb_serialization_t usb_serp);


/*
 * **************************************************************************
 * Asynchronous functions remaining Contracted Consolidation Private
 * **************************************************************************
 */

/* This whole section: status: C and D. */

/* For async_req functions. */
#define	USB_FLAGS_NOQUEUE	0x200

/*
 * Issue a request to the asynchronous request service
 * All async request functions return USB_SUCCESS or USB_FAILURE
 * Arguments:
 *	dip		- pointer to devinfo node
 *	func		- pointer of function to execute asynchronously
 *	arg		- argument to function
 *	flag		- USB_FLAGS_SLEEP or USB_FLAGS_NOSLEEP or
 *			  USB_FLAGS_NOQUEUE
 * Return Values:
 *	USB_SUCCESS	- function was scheduled
 *	USB_FAILURE	- function could not be scheduled
 *
 * Flag combinations:
 *	SLEEP		- block waiting for resources. always succeeds
 *	NOSLEEP		- do not wait for resources, may fail.
 *	NOSLEEP+NOQUEUE - do not wait for resources, do not queue
 *	SLEEP+NOQUEUE	- block waiting for resources but may still fail
 *			  if no thread available
 */
int usb_async_req(
	dev_info_t	*dip,
	void		(*func)(void *),
	void		*arg,
	usb_flags_t	flag);


/*
 * index for getting to usb_pipehandle_list in usba_device
 */
uchar_t usb_get_ep_index(uint8_t ep_addr);


#ifdef ALLOCB_TEST
#define	allocb(s, p) usba_test_allocb(s, p)
mblk_t *usba_test_allocb(size_t, uint_t);
#endif /* ALLOCB_TEST */

/* create an USB style M_CTL message */
mblk_t *usba_mk_mctl(struct iocblk, void *, size_t);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_USBA_USBAI_PRIVATE_H */
