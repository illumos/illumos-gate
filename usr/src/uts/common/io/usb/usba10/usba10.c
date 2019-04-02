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
 * Copyright 2019, Joyent, Inc.
 */


/*
 * Dummy module to load usba module on behalf of legacy drivers.
 *
 * Please see the on81-patch gate usr/src/uts/common/sys/usba10/usba10_usbai.h
 * header file for descriptions and comments for these functions.
 */

#include <sys/usb/usba.h>
#include <sys/usb/usba/usbai_private.h>
#include <sys/usb/usba/usba10.h>

/*
 * modload support
 */

static struct modlmisc modlmisc	= {
	&mod_miscops,	/* Type	of module */
	"USBA10: USB V0.8 Drvr Supp"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void	*)&modlmisc, NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Turn off lint checking of this module because it will find duplicate names
 * defined here and in the usbai.c source for the usba module.
 */
#ifndef __lint

int
usb_register_client(
	dev_info_t			*dip,
	uint_t				version,
	usb_client_dev_data_t		**dev_data,
	usb_reg_parse_lvl_t		parse_level,
	usb_flags_t			flags)
{
	return (usba10_usb_register_client(
	    dip, version, dev_data, parse_level, flags));
}


void
usb_unregister_client(
	dev_info_t			*dip,
	usb_client_dev_data_t		*dev_data)
{
	usba10_usb_unregister_client(dip, dev_data);
}


void
usb_free_descr_tree(
	dev_info_t			*dip,
	usb_client_dev_data_t		*dev_data)
{
	usba10_usb_free_descr_tree(dip, dev_data);
}


size_t
usb_parse_data(
	char			*format,
	const uchar_t 		*data,
	size_t			datalen,
	void			*structure,
	size_t			structlen)
{
	return (usba10_usb_parse_data(
	    format, data, datalen, structure, structlen));
}


usb_ep_data_t *
usb_get_ep_data(
	dev_info_t		*dip,
	usb_client_dev_data_t	*dev_datap,
	uint_t			interface,
	uint_t			alternate,
	uint_t			type,
	uint_t			direction)
{
	return (usba10_usb_get_ep_data(
	    dip, dev_datap, interface, alternate, type, direction));
}


int
usb_get_string_descr(
	dev_info_t		*dip,
	uint16_t		langid,
	uint8_t			index,
	char			*buf,
	size_t			buflen)
{
	return (usba10_usb_get_string_descr(dip, langid, index, buf, buflen));
}


int
usb_get_addr(dev_info_t *dip)
{
	return (usba10_usb_get_addr(dip));
}


int
usb_get_if_number(dev_info_t *dip)
{
	return (usba10_usb_get_if_number(dip));
}


boolean_t
usb_owns_device(dev_info_t *dip)
{
	return (usba10_usb_owns_device(dip));
}


int
usb_pipe_get_state(
	usb_pipe_handle_t	pipe_handle,
	usb_pipe_state_t	*pipe_state,
	usb_flags_t		flags)
{
	return (usba10_usb_pipe_get_state(pipe_handle, pipe_state, flags));
}


int
usb_ep_num(usb_pipe_handle_t ph)
{
	return (usba10_usb_ep_num(ph));
}


int
usb_pipe_open(
	dev_info_t		*dip,
	usb_ep_descr_t		*ep,
	usb_pipe_policy_t	*pipe_policy,
	usb_flags_t		flags,
	usb_pipe_handle_t	*pipe_handle)
{
	return (usba10_usb_pipe_open(dip, ep, pipe_policy, flags, pipe_handle));
}


void
usb_pipe_close(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		flags,
	void			(*cb)(
				    usb_pipe_handle_t	ph,
				    usb_opaque_t	arg,	/* cb arg */
				    int			rval,
				    usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg)
{
	usba10_usb_pipe_close(dip, pipe_handle, flags, cb, cb_arg);
}


int
usb_pipe_drain_reqs(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	uint_t			time,
	usb_flags_t		flags,
	void			(*cb)(
				    usb_pipe_handle_t	ph,
				    usb_opaque_t	arg,	/* cb arg */
				    int			rval,
				    usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg)
{
	return (usba10_usb_pipe_drain_reqs(
	    dip, pipe_handle, time, flags, cb, cb_arg));
}


int
usb_pipe_set_private(
	usb_pipe_handle_t	pipe_handle,
	usb_opaque_t		data)
{
	return (usba10_usb_pipe_set_private(pipe_handle, data));
}


usb_opaque_t
usb_pipe_get_private(usb_pipe_handle_t pipe_handle)
{
	return (usba10_usb_pipe_get_private(pipe_handle));
}


void
usb_pipe_reset(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		usb_flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg)
{
	usba10_usb_pipe_reset(dip, pipe_handle, usb_flags, cb, cb_arg);
}


usb_ctrl_req_t *
usb_alloc_ctrl_req(
	dev_info_t		*dip,
	size_t			len,
	usb_flags_t		flags)
{
	return (usba10_usb_alloc_ctrl_req(dip, len, flags));
}


void
usb_free_ctrl_req(usb_ctrl_req_t *reqp)
{
	usba10_usb_free_ctrl_req(reqp);
}


int
usb_pipe_ctrl_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_ctrl_req_t		*reqp,
	usb_flags_t		flags)
{
	return (usba10_usb_pipe_ctrl_xfer(pipe_handle, reqp, flags));
}


int
usb_get_status(
	dev_info_t		*dip,
	usb_pipe_handle_t	ph,
	uint_t			type,	/* bmRequestType */
	uint_t			what,	/* 0, interface, endpoint number */
	uint16_t		*status,
	usb_flags_t		flags)
{
	return (usba10_usb_get_status(dip, ph, type, what, status, flags));
}


int
usb_clear_feature(
	dev_info_t		*dip,
	usb_pipe_handle_t	ph,
	uint_t			type,	/* bmRequestType */
	uint_t			feature,
	uint_t			what,	/* 0, interface, endpoint number */
	usb_flags_t		flags)
{
	return (usba10_usb_clear_feature(dip, ph, type, feature, what, flags));
}


int
usb_pipe_ctrl_xfer_wait(
	usb_pipe_handle_t	pipe_handle,
	usb_ctrl_setup_t	*setup,
	mblk_t			**data,
	usb_cr_t		*completion_reason,
	usb_cb_flags_t		*cb_flags,
	usb_flags_t		flags)
{
	return (usba10_usb_pipe_ctrl_xfer_wait(
	    pipe_handle, setup, data, completion_reason, cb_flags, flags));
}


int
usb_set_cfg(
	dev_info_t		*dip,
	uint_t			cfg_index,
	usb_flags_t		usb_flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg)
{
	return (usba10_usb_set_cfg(dip, cfg_index, usb_flags, cb, cb_arg));
}


int
usb_get_cfg(
	dev_info_t		*dip,
	uint_t			*cfgval,
	usb_flags_t		usb_flags)
{
	return (usba10_usb_get_cfg(dip, cfgval, usb_flags));
}


int
usb_set_alt_if(
	dev_info_t		*dip,
	uint_t			interface,
	uint_t			alt_number,
	usb_flags_t		usb_flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg)
{
	return (usba10_usb_set_alt_if(
	    dip, interface, alt_number, usb_flags, cb, cb_arg));
}


int
usb_get_alt_if(
	dev_info_t		*dip,
	uint_t			if_number,
	uint_t			*alt_number,
	usb_flags_t		flags)
{
	return (usba10_usb_get_alt_if(dip, if_number, alt_number, flags));
}


usb_bulk_req_t *
usb_alloc_bulk_req(
	dev_info_t		*dip,
	size_t			len,
	usb_flags_t		flags)
{
	return (usba10_usb_alloc_bulk_req(dip, len, flags));
}


void
usb_free_bulk_req(usb_bulk_req_t *reqp)
{
	usba10_usb_free_bulk_req(reqp);
}


int
usb_pipe_bulk_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_bulk_req_t		*reqp,
	usb_flags_t		flags)
{
	return (usba10_usb_pipe_bulk_xfer(pipe_handle, reqp, flags));
}


int
usb_pipe_bulk_transfer_size(
	dev_info_t		*dip,
	size_t			*size)
{
	return (usba10_usb_pipe_bulk_transfer_size(dip, size));
}


usb_intr_req_t *
usb_alloc_intr_req(
	dev_info_t		*dip,
	size_t			len,
	usb_flags_t		flags)
{
	return (usba10_usb_alloc_intr_req(dip, len, flags));
}


void
usb_free_intr_req(usb_intr_req_t *reqp)
{
	usba10_usb_free_intr_req(reqp);
}


int
usb_pipe_intr_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_intr_req_t		*req,
	usb_flags_t		flags)
{
	return (usba10_usb_pipe_intr_xfer(pipe_handle, req, flags));
}


void
usb_pipe_stop_intr_polling(
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		flags)
{
	usba10_usb_pipe_stop_intr_polling(pipe_handle, flags);
}


usb_isoc_req_t *
usb_alloc_isoc_req(
	dev_info_t		*dip,
	uint_t			isoc_pkts_count,
	size_t			len,
	usb_flags_t		flags)
{
	return (usba10_usb_alloc_isoc_req(dip, isoc_pkts_count, len, flags));
}


void
usb_free_isoc_req(usb_isoc_req_t *usb_isoc_req)
{
	usba10_usb_free_isoc_req(usb_isoc_req);
}


usb_frame_number_t
usb_get_current_frame_number(dev_info_t	*dip)
{
	return (usba10_usb_get_current_frame_number(dip));
}


uint_t
usb_get_max_isoc_pkts(dev_info_t *dip)
{
	return (usba10_usb_get_max_isoc_pkts(dip));
}


int
usb_pipe_isoc_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_isoc_req_t		*reqp,
	usb_flags_t		flags)
{
	return (usba10_usb_pipe_isoc_xfer(pipe_handle, reqp, flags));
}


void
usb_pipe_stop_isoc_polling(
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		flags)
{
	usba10_usb_pipe_stop_isoc_polling(pipe_handle, flags);
}


int
usb_req_raise_power(
	dev_info_t	*dip,
	int		comp,
	int		level,
	void		(*cb)(void *arg, int rval),
	void		*arg,
	usb_flags_t	flags)
{
	return (usba10_usb_req_raise_power(dip, comp, level, cb, arg, flags));
}


int
usb_req_lower_power(
	dev_info_t	*dip,
	int		comp,
	int		level,
	void		(*cb)(void *arg, int rval),
	void		*arg,
	usb_flags_t	flags)
{
	return (usba10_usb_req_raise_power(dip, comp, level, cb, arg, flags));
}


int
usb_is_pm_enabled(dev_info_t *dip)
{
	return (usba10_usb_is_pm_enabled(dip));
}

int
usb_handle_remote_wakeup(
	dev_info_t	*dip,
	int		cmd)
{
	return (usba10_usb_handle_remote_wakeup(dip, cmd));
}


int
usb_create_pm_components(
	dev_info_t	*dip,
	uint_t		*pwrstates)
{
	return (usba10_usb_create_pm_components(dip, pwrstates));
}


int
usb_set_device_pwrlvl0(dev_info_t *dip)
{
	return (usba10_usb_set_device_pwrlvl0(dip));
}


int
usb_set_device_pwrlvl1(dev_info_t *dip)
{
	return (usba10_usb_set_device_pwrlvl1(dip));
}


int
usb_set_device_pwrlvl2(dev_info_t *dip)
{
	return (usba10_usb_set_device_pwrlvl2(dip));
}


int
usb_set_device_pwrlvl3(dev_info_t *dip)
{
	return (usba10_usb_set_device_pwrlvl3(dip));
}


int
usb_async_req(
	dev_info_t	*dip,
	void		(*func)(void *),
	void		*arg,
	usb_flags_t	flag)
{
	return (usba10_usb_async_req(dip, func, arg, flag));
}


int
usb_register_event_cbs(
	dev_info_t	*dip,
	usb_event_t	*usb_evt_data,
	usb_flags_t	flags)
{
	return (usba10_usb_register_event_cbs(dip, usb_evt_data, flags));
}


void
usb_unregister_event_cbs(
	dev_info_t	*dip,
	usb_event_t	*usb_evt_data)
{
	usba10_usb_unregister_event_cbs(dip, usb_evt_data);
}


void
usb_fail_checkpoint(
	dev_info_t	*dip,
	usb_flags_t	flags)
{
	usba10_usb_fail_checkpoint(dip, flags);
}

#ifdef DEBUG

void usb_dprintf4(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba10_usba_vlog(handle, USB_LOG_L4, mask, fmt, ap);
	va_end(ap);
}


void usb_dprintf3(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba10_usba_vlog(handle, USB_LOG_L3, mask, fmt, ap);
	va_end(ap);
}


void usb_dprintf2(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba10_usba_vlog(handle, USB_LOG_L2, mask, fmt, ap);
	va_end(ap);
}

#endif

void usb_dprintf1(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba10_usba_vlog(handle, USB_LOG_L1, mask, fmt, ap);
	va_end(ap);
}



void usb_dprintf0(
	uint_t		mask,
	usb_log_handle_t handle,
	char		*fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) usba10_usba_vlog(handle, USB_LOG_L4, mask, fmt, ap);
	va_end(ap);
}

usb_log_handle_t
usb_alloc_log_handle(
	dev_info_t	*dip,
	char		*name,
	uint_t		*errlevel,
	uint_t		*mask,
	uint_t		*instance_filter,
	uint_t		show_label,
	usb_flags_t	flags)
{
	return (usba10_usb_alloc_log_handle(
	    dip, name, errlevel, mask, instance_filter, show_label, flags));
}


void
usb_free_log_handle(usb_log_handle_t handle)
{
	usba10_usb_free_log_handle(handle);
}


int
usb_log(
	usb_log_handle_t handle,
	uint_t		level,
	uint_t		mask,
	char		*fmt, ...)
{
	va_list ap;
	int rval;

	va_start(ap, fmt);
	rval = usba10_usba_vlog(handle, level, mask, fmt, ap);
	va_end(ap);

	return (rval);
}



int
usb_log_descr_tree(
	usb_client_dev_data_t	*dev_data,
	usb_log_handle_t	log_handle,
	uint_t			level,
	uint_t			mask)
{
	return (usba10_usb_log_descr_tree(dev_data, log_handle, level, mask));
}


int
usb_print_descr_tree(
	dev_info_t		*dip,
	usb_client_dev_data_t	*dev_data)
{
	return (usba10_usb_print_descr_tree(dip, dev_data));
}


int
usb_check_same_device(
	dev_info_t		*dip,
	usb_log_handle_t	log_handle,
	int			log_level,
	int			log_mask,
	uint_t			check_mask,
	char			*device_string)
{
	return (usba10_usb_check_same_device(
	    dip, log_handle, log_level, log_mask, check_mask, device_string));
}


const char *
usb_str_cr(usb_cr_t cr)
{
	return (usba10_usb_str_cr(cr));
}


char *
usb_str_cb_flags(
	usb_cb_flags_t cb_flags,
	char *buffer,
	size_t length)
{
	return (usba10_usb_str_cb_flags(cb_flags, buffer, length));
}


const char *
usb_str_pipe_state(usb_pipe_state_t state)
{
	return (usba10_usb_str_pipe_state(state));
}


const char *
usb_str_dev_state(int state)
{
	return (usba10_usb_str_dev_state(state));
}


const char *
usb_str_rval(int rval)
{
	return (usba10_usb_str_rval(rval));
}


int
usb_rval2errno(int rval)
{
	return (usba10_usb_rval2errno(rval));
}


usb_serialization_t
usb_init_serialization(
	dev_info_t	*s_dip,
	uint_t		flag)
{
	return (usba10_usb_init_serialization(s_dip, flag));
}


void
usb_fini_serialization(usb_serialization_t usb_serp)
{
	usba10_usb_fini_serialization(usb_serp);
}


int
usb_serialize_access(
	usb_serialization_t	usb_serp,
	uint_t			how_to_wait,
	uint_t			delta_timeout)
{
	return (usba10_usb_serialize_access(
	    usb_serp, how_to_wait, delta_timeout));
}


int
usb_try_serialize_access(
	usb_serialization_t usb_serp,
	uint_t flag)
{
	return (usba10_usb_try_serialize_access(usb_serp, flag));
}


void
usb_release_access(usb_serialization_t usb_serp)
{
	usba10_usb_release_access(usb_serp);
}

#endif
