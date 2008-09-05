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

#ifndef	_SYS_USB_USBA10_H
#define	_SYS_USB_USBA10_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * **************************************************************************
 * The following was static in usbai.c, until the usba10 module needed it.
 * **************************************************************************
 */

int usba_vlog(usb_log_handle_t, uint_t, uint_t, char *, va_list);

/*
 * **************************************************************************
 * Defs needed only for usba10_calls module.
 * **************************************************************************
 */

usb_ep_data_t *
usb_get_ep_data(
	dev_info_t		*dip,
	usb_client_dev_data_t	*dev_datap,
	uint_t			interface,
	uint_t			alternate,
	uint_t			type,
	uint_t			direction);

int
usb_ep_num(usb_pipe_handle_t ph);

int
usb_clear_feature(
	dev_info_t		*dip,
	usb_pipe_handle_t	ph,
	uint_t			type,	/* bmRequestType */
	uint_t			feature,
	uint_t			what,	/* 0, interface, endpoint number */
	usb_flags_t		flags);

int
usb_pipe_bulk_transfer_size(
	dev_info_t		*dip,
	size_t			*size);

uint_t
usb_get_max_isoc_pkts(dev_info_t *dip);

int
usb_is_pm_enabled(dev_info_t *dip);

int
usb_log_descr_tree(
	usb_client_dev_data_t	*dev_data,
	usb_log_handle_t	log_handle,
	uint_t			level,
	uint_t			mask);

int usb_register_client(
	dev_info_t			*dip,
	uint_t				version,
	usb_client_dev_data_t		**dev_data,
	usb_reg_parse_lvl_t		parse_level,
	usb_flags_t			flags);

void usb_unregister_client(
	dev_info_t			*dip,
	usb_client_dev_data_t		*dev_data);

/* allocate a log handle */
usb_log_handle_t usb_alloc_log_handle(
	dev_info_t	*dip,
	char		*name,
	uint_t		*errlevel,
	uint_t		*mask,
	uint_t		*instance_filter,
	uint_t		reserved,
	usb_flags_t	flags);


/* free the log handle */
void usb_free_log_handle(
	usb_log_handle_t handle);

/*
 * **************************************************************************
 * Remaining functions are declarations for wrapper functions exported to
 * legacy drivers.
 * **************************************************************************
 */


int
usba10_usb_register_client(
	dev_info_t			*dip,
	uint_t				version,
	usb_client_dev_data_t		**dev_data,
	usb_reg_parse_lvl_t		parse_level,
	usb_flags_t			flags);

void
usba10_usb_unregister_client(
	dev_info_t			*dip,
	usb_client_dev_data_t		*dev_data);

void
usba10_usb_free_descr_tree(
	dev_info_t			*dip,
	usb_client_dev_data_t		*dev_data);

size_t
usba10_usb_parse_data(
	char			*format,
	uchar_t 		*data,
	size_t			datalen,
	void			*structure,
	size_t			structlen);

usb_ep_data_t *
usba10_usb_get_ep_data(
	dev_info_t		*dip,
	usb_client_dev_data_t	*dev_datap,
	uint_t			interface,
	uint_t			alternate,
	uint_t			type,
	uint_t			direction);

int
usba10_usb_get_string_descr(
	dev_info_t		*dip,
	uint16_t		langid,
	uint8_t			index,
	char			*buf,
	size_t			buflen);

int
usba10_usb_get_addr(dev_info_t *dip);

int
usba10_usb_get_if_number(dev_info_t *dip);

boolean_t
usba10_usb_owns_device(dev_info_t *dip);

int
usba10_usb_pipe_get_state(
	usb_pipe_handle_t	pipe_handle,
	usb_pipe_state_t	*pipe_state,
	usb_flags_t		flags);

int
usba10_usb_ep_num(usb_pipe_handle_t ph);

int
usba10_usb_pipe_open(
	dev_info_t		*dip,
	usb_ep_descr_t		*ep,
	usb_pipe_policy_t	*pipe_policy,
	usb_flags_t		flags,
	usb_pipe_handle_t	*pipe_handle);

void
usba10_usb_pipe_close(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		flags,
	void			(*cb)(
				    usb_pipe_handle_t	ph,
				    usb_opaque_t	arg,	/* cb arg */
				    int			rval,
				    usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);

int
usba10_usb_pipe_drain_reqs(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	uint_t			time,
	usb_flags_t		flags,
	void			(*cb)(
				    usb_pipe_handle_t	ph,
				    usb_opaque_t	arg,	/* cb arg */
				    int			rval,
				    usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);

int
usba10_usb_pipe_set_private(
	usb_pipe_handle_t	pipe_handle,
	usb_opaque_t		data);

usb_opaque_t
usba10_usb_pipe_get_private(usb_pipe_handle_t pipe_handle);

void
usba10_usb_pipe_reset(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		usb_flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);

usb_ctrl_req_t *
usba10_usb_alloc_ctrl_req(
	dev_info_t		*dip,
	size_t			len,
	usb_flags_t		flags);

void
usba10_usb_free_ctrl_req(usb_ctrl_req_t *reqp);

int
usba10_usb_pipe_ctrl_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_ctrl_req_t		*reqp,
	usb_flags_t		flags);

int
usba10_usb_get_status(
	dev_info_t		*dip,
	usb_pipe_handle_t	ph,
	uint_t			type,	/* bmRequestType */
	uint_t			what,	/* 0, interface, endpoint number */
	uint16_t		*status,
	usb_flags_t		flags);

int
usba10_usb_clear_feature(
	dev_info_t		*dip,
	usb_pipe_handle_t	ph,
	uint_t			type,	/* bmRequestType */
	uint_t			feature,
	uint_t			what,	/* 0, interface, endpoint number */
	usb_flags_t		flags);

int
usba10_usb_pipe_ctrl_xfer_wait(
	usb_pipe_handle_t	pipe_handle,
	usb_ctrl_setup_t	*setup,
	mblk_t			**data,
	usb_cr_t		*completion_reason,
	usb_cb_flags_t		*cb_flags,
	usb_flags_t		flags);

int
usba10_usb_set_cfg(
	dev_info_t		*dip,
	uint_t			cfg_index,
	usb_flags_t		usb_flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);

int
usba10_usb_get_cfg(
	dev_info_t		*dip,
	uint_t			*cfgval,
	usb_flags_t		usb_flags);

int
usba10_usb_set_alt_if(
	dev_info_t		*dip,
	uint_t			interface,
	uint_t			alt_number,
	usb_flags_t		usb_flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);

int
usba10_usb_get_alt_if(
	dev_info_t		*dip,
	uint_t			if_number,
	uint_t			*alt_number,
	usb_flags_t		flags);

usb_bulk_req_t *
usba10_usb_alloc_bulk_req(
	dev_info_t		*dip,
	size_t			len,
	usb_flags_t		flags);

void
usba10_usb_free_bulk_req(usb_bulk_req_t *reqp);

int
usba10_usb_pipe_bulk_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_bulk_req_t		*reqp,
	usb_flags_t		flags);

int
usba10_usb_pipe_bulk_transfer_size(
	dev_info_t		*dip,
	size_t			*size);

usb_intr_req_t *
usba10_usb_alloc_intr_req(
	dev_info_t		*dip,
	size_t			len,
	usb_flags_t		flags);

void
usba10_usb_free_intr_req(usb_intr_req_t *reqp);

int
usba10_usb_pipe_intr_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_intr_req_t		*req,
	usb_flags_t		flags);

void
usba10_usb_pipe_stop_intr_polling(
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		flags);

usb_isoc_req_t *
usba10_usb_alloc_isoc_req(
	dev_info_t		*dip,
	uint_t			isoc_pkts_count,
	size_t			len,
	usb_flags_t		flags);

void
usba10_usb_free_isoc_req(usb_isoc_req_t *usb_isoc_req);

usb_frame_number_t
usba10_usb_get_current_frame_number(dev_info_t	*dip);

uint_t
usba10_usb_get_max_isoc_pkts(dev_info_t *dip);

int
usba10_usb_pipe_isoc_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_isoc_req_t		*reqp,
	usb_flags_t		flags);

void
usba10_usb_pipe_stop_isoc_polling(
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		flags);

int
usba10_usb_req_raise_power(
	dev_info_t	*dip,
	int		comp,
	int		level,
	void		(*cb)(void *arg, int rval),
	void		*arg,
	usb_flags_t	flags);

int
usba10_usb_req_lower_power(
	dev_info_t	*dip,
	int		comp,
	int		level,
	void		(*cb)(void *arg, int rval),
	void		*arg,
	usb_flags_t	flags);

int
usba10_usb_is_pm_enabled(dev_info_t *dip);

int
usba10_usb_handle_remote_wakeup(
	dev_info_t	*dip,
	int		cmd);

int
usba10_usb_create_pm_components(
	dev_info_t	*dip,
	uint_t		*pwrstates);

int
usba10_usb_set_device_pwrlvl0(dev_info_t *dip);

int
usba10_usb_set_device_pwrlvl1(dev_info_t *dip);

int
usba10_usb_set_device_pwrlvl2(dev_info_t *dip);

int
usba10_usb_set_device_pwrlvl3(dev_info_t *dip);

int
usba10_usb_async_req(
	dev_info_t	*dip,
	void		(*func)(void *),
	void		*arg,
	usb_flags_t	flag);

int
usba10_usb_register_event_cbs(
	dev_info_t	*dip,
	usb_event_t	*usb_evt_data,
	usb_flags_t	flags);

void
usba10_usb_unregister_event_cbs(
	dev_info_t	*dip,
	usb_event_t	*usb_evt_data);

void
usba10_usb_fail_checkpoint(
	dev_info_t	*dip,
	usb_flags_t	flags);

usb_log_handle_t
usba10_usb_alloc_log_handle(
	dev_info_t	*dip,
	char		*name,
	uint_t		*errlevel,
	uint_t		*mask,
	uint_t		*instance_filter,
	uint_t		show_label,
	usb_flags_t	flags);

int
usba10_usba_vlog(
	usb_log_handle_t handle,
	uint_t		level,
	uint_t		mask,
	char		*fmt,
	va_list		ap);

void
usba10_usb_free_log_handle(usb_log_handle_t handle);

int
usba10_usb_log_descr_tree(
	usb_client_dev_data_t	*dev_data,
	usb_log_handle_t	log_handle,
	uint_t			level,
	uint_t			mask);

int
usba10_usb_print_descr_tree(
	dev_info_t		*dip,
	usb_client_dev_data_t	*dev_data);

int
usba10_usb_check_same_device(
	dev_info_t		*dip,
	usb_log_handle_t	log_handle,
	int			log_level,
	int			log_mask,
	uint_t			check_mask,
	char			*device_string);

const char *
usba10_usb_str_cr(usb_cr_t cr);

char *
usba10_usb_str_cb_flags(
	usb_cb_flags_t cb_flags,
	char *buffer,
	size_t length);

const char *
usba10_usb_str_pipe_state(usb_pipe_state_t state);

const char *
usba10_usb_str_dev_state(int state);

const char *
usba10_usb_str_rval(int rval);

int
usba10_usb_rval2errno(int rval);

usb_serialization_t
usba10_usb_init_serialization(
	dev_info_t	*s_dip,
	uint_t		flag);

void
usba10_usb_fini_serialization(usb_serialization_t usb_serp);

int
usba10_usb_serialize_access(
	usb_serialization_t	usb_serp,
	uint_t			how_to_wait,
	uint_t			delta_timeout);

int
usba10_usb_try_serialize_access(
	usb_serialization_t usb_serp,
	uint_t flag);

void
usba10_usb_release_access(usb_serialization_t usb_serp);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_USBA10_H */
