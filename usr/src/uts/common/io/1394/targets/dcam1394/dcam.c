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
 * Copyright 2017 Joyent, Inc.
 */


/*
 * dcam.c
 *
 * dcam1394 driver. Controls IIDC compliant devices attached through a
 * IEEE-1394 bus.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunndi.h>
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/mkdev.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/devops.h>
#include <sys/1394/t1394.h>
#include <sys/tnf_probe.h>

#include <sys/dcam/dcam1394_io.h>
#include <sys/1394/targets/dcam1394/dcam.h>
#include <sys/1394/targets/dcam1394/dcam_reg.h>
#include <sys/1394/targets/dcam1394/dcam_param.h>
#include <sys/1394/targets/dcam1394/dcam_frame.h>

#ifndef NPROBE
extern int tnf_mod_load(void);
extern int tnf_mod_unload(struct modlinkage *mlp);
#endif /* ! NPROBE */


/* for power management (we have only one component) */
static char *dcam_pmc[] = {
	"NAME=dcam1394",
	"0=Off",
	"1=On"
};

int g_vid_mode_frame_num_bytes[] =
{
	57600,		/* vid mode 0 */
	153600,		/* vid mode 1 */
	460800,		/* vid mode 2 */
	614400,		/* vid mode 3 */
	921600,		/* vid mode 4 */
	307200		/* vid mode 5 */
};

static int	byte_copy_to_user_buff(uchar_t *src_addr_p, struct uio *uio_p,
		    size_t num_bytes, int start_index, int *end_index);
static int	byte_copy_from_user_buff(uchar_t *dst_addr_p, struct uio *uio_p,
		    size_t num_bytes, int start_index, int *end_index);
static int	dcam_reset(dcam_state_t *softc_p);

/* opaque state structure head */
void *dcam_state_p;

static struct cb_ops dcam_cb_ops = {
	dcam_open,		/* open		*/
	dcam_close,		/* close	*/
	nodev,			/* strategy	*/
	nodev,			/* print	*/
	nodev,			/* dump		*/
	dcam_read,		/* read		*/
	nodev,			/* write	*/
	dcam_ioctl,		/* ioctl	*/
	nodev,			/* devmap	*/
	nodev,			/* mmap		*/
	nodev,			/* segmap	*/
	dcam_chpoll,		/* chpoll	*/
	ddi_prop_op,		/* prop_op	*/
	NULL,			/* streams	*/
				/* flags	*/
	D_NEW | D_MP | D_64BIT | D_HOTPLUG,
	CB_REV,			/* rev		*/
	nodev,			/* aread	*/
	nodev			/* awrite	*/
};

static struct dev_ops dcam_dev_ops = {
	DEVO_REV,		/* DEVO_REV indicated by manual	*/
	0,			/* device reference count	*/
	dcam_getinfo,		/* getinfo			*/
	nulldev,		/* identify			*/
	nulldev,		/* probe			*/
	dcam_attach,		/* attach			*/
	dcam_detach,		/* detach			*/
	nodev,			/* reset			*/
	&dcam_cb_ops,		/* ptr to cb_ops struct		*/
	NULL,			/* ptr to bus_ops struct; none	*/
	dcam_power,		/* power			*/
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

extern	struct	mod_ops mod_driverops;

static	struct modldrv modldrv = {
	&mod_driverops,
	"SUNW 1394-based Digital Camera driver",
	&dcam_dev_ops,
};

static	struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL,
};


int
_init(void)
{
	int err;

	err = ddi_soft_state_init(&dcam_state_p, sizeof (dcam_state_t), 2);

	if (err) {
		return (err);
	}

#ifndef NPROBE
	(void) tnf_mod_load();
#endif /* ! NPROBE */

	if (err = mod_install(&modlinkage)) {

#ifndef NPROBE
		(void) tnf_mod_unload(&modlinkage);
#endif /* ! NPROBE */

		ddi_soft_state_fini(&dcam_state_p);

	}

	return (err);
}


int
_info(struct modinfo *modinfop)
{
	int err;

	err = mod_info(&modlinkage, modinfop);
	return (err);
}


int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0) {
		return (err);
	}

#ifndef NPROBE
		(void) tnf_mod_unload(&modlinkage);
#endif /* ! NPROBE */

	ddi_soft_state_fini(&dcam_state_p);

	return (err);
}


/*
 * dcam_attach
 */
/* ARGSUSED */
int
dcam_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	char			tmp_str[MAX_STR_LEN];
	dcam_state_t		*softc_p;
	ddi_eventcookie_t	ev_cookie;
	int			instance;
	int			ret_val;

	switch (cmd) {

	case DDI_ATTACH:
		instance = ddi_get_instance(dip);

		if (ddi_soft_state_zalloc(dcam_state_p, instance) !=
		    DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		if ((softc_p = ddi_get_soft_state(dcam_state_p, instance)) ==
		    NULL) {
			ddi_soft_state_free(dcam_state_p, instance);
			return (DDI_FAILURE);
		}

		/*
		 * Initialize soft state
		 */
		softc_p->dip			= dip;
		softc_p->instance		= instance;
		softc_p->usr_model		= -1;
		softc_p->ixlp			= NULL;

		softc_p->seq_count 		= 0;
		softc_p->param_status 		= 0;

		/*
		 * set default vid_mode, frame_rate and ring_buff_capacity
		 */
		softc_p->cur_vid_mode 		= 1;
		softc_p->cur_frame_rate 	= 3;
		softc_p->cur_ring_buff_capacity = 10;
		softc_p->camera_online		= 1;

		(void) sprintf(tmp_str, "dcam%d", instance);

		if (ddi_create_minor_node(dip, tmp_str, S_IFCHR, instance,
		    DDI_PSEUDO, 0) != DDI_SUCCESS) {
			ddi_soft_state_free(dcam_state_p, instance);

			return (DDI_FAILURE);
		}

		(void) sprintf(tmp_str, "dcamctl%d", instance);

		if (ddi_create_minor_node(dip, tmp_str, S_IFCHR,
		    instance + DCAM1394_MINOR_CTRL, "ddi_dcam1394", 0) !=
		    DDI_SUCCESS) {
			ddi_soft_state_free(dcam_state_p, instance);

			return (DDI_FAILURE);
		}

		if (t1394_attach(dip, T1394_VERSION_V1, 0,
		    &(softc_p->attachinfo),
		    &(softc_p->sl_handle)) != DDI_SUCCESS) {
			ddi_soft_state_free(dcam_state_p, instance);
			ddi_remove_minor_node(dip, NULL);

			return (DDI_FAILURE);
		}

		if (t1394_get_targetinfo(softc_p->sl_handle,
		    softc_p->attachinfo.localinfo.bus_generation, 0,
		    &(softc_p->targetinfo)) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "dcam_attach: t1394_get_targetinfo failed\n");
		}

		if (ddi_get_eventcookie(dip, DDI_DEVI_BUS_RESET_EVENT,
		    &ev_cookie) != DDI_SUCCESS) {
			(void) t1394_detach(&softc_p->sl_handle, 0);

			ddi_soft_state_free(dcam_state_p, instance);
			ddi_remove_minor_node(dip, NULL);

			return (DDI_FAILURE);
		}

		if (ddi_add_event_handler(dip, ev_cookie, dcam_bus_reset_notify,
		    softc_p, &softc_p->event_id) != DDI_SUCCESS) {
			(void) t1394_detach(&softc_p->sl_handle, 0);

			ddi_soft_state_free(dcam_state_p, instance);
			ddi_remove_minor_node(dip, NULL);

			return (DDI_FAILURE);
		}

		mutex_init(&softc_p->softc_mutex, NULL, MUTEX_DRIVER,
		    softc_p->attachinfo.iblock_cookie);

		mutex_init(&softc_p->dcam_frame_is_done_mutex, NULL,
		    MUTEX_DRIVER, softc_p->attachinfo.iblock_cookie);

		/*
		 * init the soft state's parameter attribute structure
		 */
		if (param_attr_init(softc_p, softc_p->param_attr) !=
		    DDI_SUCCESS) {
			(void) ddi_remove_event_handler(softc_p->event_id);
			(void) t1394_detach(&softc_p->sl_handle, 0);

			ddi_soft_state_free(dcam_state_p, instance);
			ddi_remove_minor_node(dip, NULL);

			return (DDI_FAILURE);
		}

		/*
		 * power management stuff
		 */
		if (ddi_prop_update_string_array(DDI_DEV_T_NONE,
		    dip, "pm-components", dcam_pmc,
		    sizeof (dcam_pmc)/sizeof (char *)) == DDI_PROP_SUCCESS) {

			(void) pm_raise_power(dip, 0, 1);
			if (ddi_prop_exists(DDI_DEV_T_ANY, dip, 0,
			    "power-managed?")) {
				(void) pm_idle_component(dip, 0);
			} else {
				(void) pm_busy_component(dip, 0);
			}
		}

		softc_p->flags |= DCAM1394_FLAG_ATTACH_COMPLETE;

		ddi_report_dev(dip);
		ret_val = DDI_SUCCESS;
		break;

	case DDI_RESUME:
		instance = ddi_get_instance(dip);
		if ((softc_p = ddi_get_soft_state(dcam_state_p, instance)) ==
		    NULL) {
			ddi_soft_state_free(dcam_state_p, instance);
			return (DDI_FAILURE);
		}

		mutex_enter(&softc_p->softc_mutex);

		if (softc_p->flags & DCAM1394_FLAG_FRAME_RCV_INIT) {
			(void) dcam1394_ioctl_frame_rcv_start(softc_p);
		}

		softc_p->suspended = 0;

		mutex_exit(&softc_p->softc_mutex);

		ret_val = DDI_SUCCESS;
		break;

	default:
		ret_val = DDI_FAILURE;
		break;
	}

	return (ret_val);
}


/*
 * dcam_power: perform dcam power management
 */
/* ARGSUSED */
int
dcam_power(dev_info_t *dip, int component, int level)
{
	dcam_state_t	*softc_p;
	int		instance;

	instance = ddi_get_instance(dip);
	softc_p  = (dcam_state_t *)ddi_get_soft_state(dcam_state_p, instance);

	if (softc_p == NULL)
		return (DDI_FAILURE);

	softc_p->pm_cable_power = level;

	return (DDI_SUCCESS);

}


/*
 * dcam_getinfo
 */
/* ARGSUSED */
int
dcam_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t		 dev;
	dcam_state_t	*softc_p;
	int		 status;
	int		 instance;

	switch (cmd) {

	case DDI_INFO_DEVT2DEVINFO:
		dev	 = (dev_t)arg;
		instance = DEV_TO_INSTANCE(dev);
		softc_p  = (dcam_state_t *)
		    ddi_get_soft_state(dcam_state_p, instance);

		if (softc_p == NULL) {
			return (DDI_FAILURE);
		}

		*result = (void *)softc_p->dip;
		status  = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		dev	 = (dev_t)arg;
		instance = DEV_TO_INSTANCE(dev);
		*result	 = (void *)(uintptr_t)instance;
		status	 = DDI_SUCCESS;
		break;

	default:
		status = DDI_FAILURE;
	}

	return (status);
}


/*
 * dcam_detach
 */
/* ARGSUSED */
int
dcam_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			 instance;
	dcam_state_t		*softc_p;

	instance = ddi_get_instance(dip);

	softc_p = (dcam_state_t *)ddi_get_soft_state(dcam_state_p, instance);
	if (softc_p == NULL) {
		return (DDI_FAILURE);
	}


	switch (cmd) {

	case DDI_SUSPEND:
		mutex_enter(&softc_p->softc_mutex);

		softc_p->suspended = 1;

		if (softc_p->flags & DCAM1394_FLAG_FRAME_RCV_INIT) {
			(void) dcam_frame_rcv_stop(softc_p);
		}

		mutex_exit(&softc_p->softc_mutex);
		return (DDI_SUCCESS);


	case DDI_DETACH:
		/*
		 * power management stuff
		 */
		(void) pm_lower_power(dip, 0, 0);
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "pm-components");

		/*
		 * deregister with 1394 DDI framework
		 */
		if (t1394_detach(&softc_p->sl_handle, 0) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		(void) ddi_remove_event_handler(softc_p->event_id);

		/*
		 * free state structures, mutexes, condvars;
		 * deregister interrupts
		 */
		mutex_destroy(&softc_p->softc_mutex);
		mutex_destroy(&softc_p->dcam_frame_is_done_mutex);

		/*
		 * Remove all minor nodes, all dev_t's properties
		 */
		ddi_remove_minor_node(dip, NULL);

		ddi_soft_state_free(dcam_state_p, instance);
		ddi_prop_remove_all(dip);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	}
}


/*
 * dcam_open
 */
/* ARGSUSED */
int
dcam_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	dcam_state_t	*softc_p;
	int		instance;
	int		is_ctrl_file;
	uint_t		new_flags;

	instance = (int)DEV_TO_INSTANCE(*dev_p);

	if ((softc_p = ddi_get_soft_state(dcam_state_p, instance)) == NULL) {
		return (ENXIO);
	}

	/*
	 * if dcam_attach hasn't completed, return error
	 * XXX: Check this out
	 */
	if (!(softc_p->flags & DCAM1394_FLAG_ATTACH_COMPLETE)) {
		return (ENXIO);
	}

	/* disallow block, mount, and layered opens */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	new_flags    = 0;
	is_ctrl_file = (getminor(*dev_p) & DCAM1394_MINOR_CTRL) ? 1 : 0;

	mutex_enter(&softc_p->softc_mutex);

	/*
	 * The open is either for the capture file or the control file.
	 * If it's the control file construct new flags.
	 *
	 * If it's the capture file return busy if it's already open,
	 * otherwise construct new flags.
	 */
	if (is_ctrl_file) {
		new_flags |= DCAM1394_FLAG_OPEN_CONTROL;
	} else {
		if (softc_p->flags & DCAM1394_FLAG_OPEN_CAPTURE) {
			mutex_exit(&softc_p->softc_mutex);
			return (EBUSY);
		}

		new_flags |= DCAM1394_FLAG_OPEN_CAPTURE;
	}

	new_flags |= DCAM1394_FLAG_OPEN;
	softc_p->flags |= new_flags;

	mutex_exit(&softc_p->softc_mutex);

	/*
	 * power management stuff
	 */
	if (softc_p->pm_open_count == 0) {
		if (ddi_prop_exists(DDI_DEV_T_ANY, softc_p->dip, 0,
		    "power-managed?")) {
			(void) pm_busy_component(softc_p->dip, 0);
			if (softc_p->pm_cable_power == 0) {
				int i;

				(void) pm_raise_power(softc_p->dip, 0, 1);

				/*
				 * Wait for the power to be up and stable
				 * before proceeding.  100 msecs should
				 * certainly be enough, and if we check
				 * every msec we'll probably loop just a
				 * few times.
				 */
				for (i = 0; i < 100; i++) {
					if (param_power_set(softc_p, 1) == 0) {
						break;
					}
					delay((clock_t)drv_usectohz(1000));
				}
			}
		}
	}
	softc_p->pm_open_count++;

	return (0);
}


/*
 * dcam_close
 */
/* ARGSUSED */
int
dcam_close(dev_t dev, int flags, int otyp, cred_t *cred_p)
{
	int instance;
	dcam_state_t *softc;

	instance = DEV_TO_INSTANCE(dev);
	softc    = (dcam_state_t *)ddi_get_soft_state(dcam_state_p, instance);

	/*
	 * power management stuff
	 */
	softc->pm_open_count = 0;
	if (ddi_prop_exists(DDI_DEV_T_ANY, softc->dip, 0, "power-managed?")) {
		(void) pm_idle_component(softc->dip, 0);
	}

	mutex_enter(&softc->softc_mutex);

	if (getminor(dev) & DCAM1394_MINOR_CTRL) {
		softc->flags &= ~DCAM1394_FLAG_OPEN_CONTROL;
	} else {
		/*
		 * If an application which has opened the camera capture
		 * device exits without calling DCAM1394_CMD_FRAME_RCV_STOP
		 * ioctl, then we need to release resources.
		 */
		if (softc->flags & DCAM1394_FLAG_FRAME_RCV_INIT) {
			(void) dcam_frame_rcv_stop(softc);
			softc->flags &= ~DCAM1394_FLAG_FRAME_RCV_INIT;
		}

		(void) param_power_set(softc, 0);

		softc->flags &= ~DCAM1394_FLAG_OPEN_CAPTURE;
	}

	/*
	 * If driver is completely closed, then stabilize the camera
	 * and turn off transient flags
	 */
	if (!(softc->flags &
	    (DCAM1394_FLAG_OPEN_CONTROL | DCAM1394_FLAG_OPEN_CAPTURE))) {
		softc->flags &= DCAM1394_FLAG_ATTACH_COMPLETE;
	}

	mutex_exit(&softc->softc_mutex);

	return (DDI_SUCCESS);

}


/*
 * dcam_read
 *
 * If read pointer is not pointing to the same position as write pointer
 * copy frame data from ring buffer position pointed to by read pointer.
 *
 *	If during the course of copying frame data, the device driver
 *	invalidated this read() request processing operation, restart
 *	this operation.
 *
 *     Increment read pointer and return frame data to user process.
 *
 * Else return error
 *
 */
/* ARGSUSED */
int
dcam_read(dev_t dev, struct uio *uio_p, cred_t *cred_p)
{
	buff_info_t	*buff_info_p;
	dcam_state_t	*softc_p;
	hrtime_t	 timestamp;
	int		 index, instance;
	int		 read_ptr_id;
	size_t		 read_ptr_pos, write_ptr_pos;
	int		 read_req_invalid;
	ring_buff_t	*ring_buff_p;
	uchar_t		*frame_data_p;
	uint_t		 seq_num;
	unsigned long	 user_frame_buff_addr;
	uint_t		 vid_mode;
	int		 gotten_addr_flag;

	instance = DEV_TO_INSTANCE(dev);

	softc_p = (dcam_state_t *)ddi_get_soft_state(dcam_state_p, instance);
	if (softc_p == NULL) {
		return (ENXIO);
	}

	if ((ring_buff_p = softc_p->ring_buff_p) == NULL) {
		return (EAGAIN);
	}

	read_ptr_id = 0;

	mutex_enter(&softc_p->dcam_frame_is_done_mutex);

	softc_p->reader_flags[read_ptr_id] |= DCAM1394_FLAG_READ_REQ_PROC;

	user_frame_buff_addr = 0;
	gotten_addr_flag = 0;

	do {
		read_ptr_pos = ring_buff_read_ptr_pos_get(ring_buff_p,
		    read_ptr_id);

		write_ptr_pos = ring_buff_write_ptr_pos_get(ring_buff_p);

		if (read_ptr_pos != write_ptr_pos) {
			/*
			 * Since the app wants realtime video, set the read
			 * pointer to the newest data.
			 */
			if (write_ptr_pos == 0) {
				read_ptr_pos = ring_buff_p->num_buffs - 1;
			} else {
				read_ptr_pos = write_ptr_pos - 1;
			}

			/*
			 * copy frame data from ring buffer position pointed
			 * to by read pointer
			 */
			index = 0;
			buff_info_p =
			    &(ring_buff_p->buff_info_array_p[read_ptr_pos]);

			vid_mode = softc_p->cur_vid_mode;
			seq_num  = buff_info_p->seq_num;
			timestamp = buff_info_p->timestamp;
			frame_data_p = (uchar_t *)buff_info_p->kaddr_p;

			mutex_exit(&softc_p->dcam_frame_is_done_mutex);

			/*
			 * Fix for bug #4424042
			 * don't lock this section
			 */

			if (byte_copy_to_user_buff((uchar_t *)&vid_mode,
			    uio_p, sizeof (uint_t), index, &index)) {

				return (EFAULT);
			}

			if (byte_copy_to_user_buff((uchar_t *)&seq_num,
			    uio_p, sizeof (unsigned int), index, &index)) {

				return (EFAULT);
			}

			if (byte_copy_to_user_buff((uchar_t *)&timestamp,
			    uio_p, sizeof (hrtime_t), index, &index)) {

				return (EFAULT);
			}

			/*
			 * get buff pointer; do ddi_copyout()
			 * get user buffer address only once
			 */
			if (!gotten_addr_flag) {
				if (byte_copy_from_user_buff(
				    (uchar_t *)&user_frame_buff_addr, uio_p,
				    softc_p->usr_model, index, &index)) {

					return (EFAULT);
				}

#ifdef _MULTI_DATAMODEL
				if (softc_p->usr_model == ILP32_PTR_SIZE) {
					user_frame_buff_addr =
					    ((user_frame_buff_addr >> 32) &
					    0xffffffffULL) |
					    ((user_frame_buff_addr << 32) &
					    0xffffffff00000000ULL);
				}
#endif /* _MULTI_DATAMODEL */

				gotten_addr_flag = 1;
			}

			if (ddi_copyout(
			    (caddr_t)frame_data_p,
			    (caddr_t)user_frame_buff_addr,
			    g_vid_mode_frame_num_bytes[softc_p->cur_vid_mode],
			    0)) {
				return (EFAULT);
			}

			/*
			 * if during the course of copying frame data,
			 * the device driver invalidated this read()
			 * request processing operation; restart this
			 * operation
			 */

			mutex_enter(&softc_p->dcam_frame_is_done_mutex);

			read_req_invalid = softc_p->reader_flags[read_ptr_id] &
			    DCAM1394_FLAG_READ_REQ_INVALID;

			softc_p->reader_flags[read_ptr_id] &=
			    ~(DCAM1394_FLAG_READ_REQ_INVALID);

			mutex_exit(&softc_p->dcam_frame_is_done_mutex);

		} else {
			mutex_exit(&softc_p->dcam_frame_is_done_mutex);
			return (EAGAIN);
		}

		mutex_enter(&softc_p->dcam_frame_is_done_mutex);
	} while (read_req_invalid);

	/*
	 * return number of bytes actually written to user space
	 */
	uio_p->uio_resid -= g_vid_mode_frame_num_bytes[softc_p->cur_vid_mode];

	softc_p->reader_flags[read_ptr_id] &= ~(DCAM1394_FLAG_READ_REQ_PROC);

	/* increment read pointer */
	ring_buff_read_ptr_incr(ring_buff_p, read_ptr_id);

	mutex_exit(&softc_p->dcam_frame_is_done_mutex);

	return (0);
}


/*
 * dcam_ioctl
 */
/* ARGSUSED */
int
dcam_ioctl(dev_t dev, int cmd, intptr_t  arg, int mode, cred_t *cred_p,
    int *rvalp)
{
	dcam_state_t		*softc_p;
	dcam1394_param_list_t	*param_list;
	dcam1394_reg_io_t	 dcam_reg_io;
	int			 instance, is_ctrl_file, rc, i;

	rc = 0;
	param_list = (dcam1394_param_list_t *)0;

	instance = DEV_TO_INSTANCE(dev);

	if ((softc_p = ddi_get_soft_state(dcam_state_p, instance)) == NULL) {
		rc = ENXIO;
		goto done;
	}

	/*
	 * determine user applications data model
	 */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32)
		softc_p->usr_model = ILP32_PTR_SIZE;
	else
		softc_p->usr_model = LP64_PTR_SIZE;


	switch (cmd) {

	case DCAM1394_CMD_REG_READ:
		if (ddi_copyin((caddr_t)arg, &dcam_reg_io,
		    sizeof (dcam1394_reg_io_t), mode)) {
			rc = EFAULT;
			goto done;
		}

		if (dcam_reg_read(softc_p, &dcam_reg_io)) {
			rc = EFAULT;
			goto done;
		}

		if (ddi_copyout(&dcam_reg_io, (caddr_t)arg,
		    sizeof (dcam1394_reg_io_t), mode)) {
			rc = EFAULT;
			goto done;
		}
		break;

	case DCAM1394_CMD_REG_WRITE:
		if (ddi_copyin((caddr_t)arg, &dcam_reg_io,
		    sizeof (dcam1394_reg_io_t), mode)) {
			rc = EFAULT;
			goto done;
		}

		if (dcam_reg_write(softc_p, &dcam_reg_io)) {
			rc = EFAULT;
			goto done;
		}

		if (ddi_copyout(&dcam_reg_io, (caddr_t)arg,
		    sizeof (dcam1394_reg_io_t), mode)) {
			rc = EFAULT;
			goto done;
		}
		break;

	case DCAM1394_CMD_CAM_RESET:
		if (dcam_reset(softc_p)) {
			rc = EIO;
			goto done;
		}
		break;

	case DCAM1394_CMD_PARAM_GET:
		param_list = (dcam1394_param_list_t *)
		    kmem_alloc(sizeof (dcam1394_param_list_t), KM_SLEEP);

		if (ddi_copyin((caddr_t)arg, (caddr_t)param_list,
		    sizeof (dcam1394_param_list_t), mode)) {
			rc = EFAULT;
			goto done;
		}

		if (dcam1394_ioctl_param_get(softc_p, *param_list)) {
			rc = EINVAL;
		}

		if (ddi_copyout((caddr_t)param_list, (caddr_t)arg,
		    sizeof (dcam1394_param_list_t), mode)) {
			rc = EFAULT;
			goto done;
		}
		break;

	case DCAM1394_CMD_PARAM_SET:
		param_list = (dcam1394_param_list_t *)
		    kmem_alloc((size_t)sizeof (dcam1394_param_list_t),
		    KM_SLEEP);

		if (ddi_copyin((caddr_t)arg, (caddr_t)param_list,
		    sizeof (dcam1394_param_list_t), mode)) {
			rc = EFAULT;
			goto done;
		}

		is_ctrl_file = (getminor(dev) & DCAM1394_MINOR_CTRL) ? 1:0;

		if (dcam1394_ioctl_param_set(softc_p, is_ctrl_file,
		    *param_list)) {
			rc = EINVAL;
		}

		if (is_ctrl_file) {
			mutex_enter(&softc_p->dcam_frame_is_done_mutex);
			softc_p->param_status |= DCAM1394_STATUS_PARAM_CHANGE;
			mutex_exit(&softc_p->dcam_frame_is_done_mutex);
		}

		if (ddi_copyout(param_list, (caddr_t)arg,
		    sizeof (dcam1394_param_list_t), mode)) {
			rc = EFAULT;
			goto done;
		}
		break;

	case DCAM1394_CMD_FRAME_RCV_START:
		if (dcam1394_ioctl_frame_rcv_start(softc_p)) {
			rc = ENXIO;
		}
		break;

	case DCAM1394_CMD_FRAME_RCV_STOP:
		if (dcam_frame_rcv_stop(softc_p)) {
			rc = ENXIO;
		}
		break;

	case DCAM1394_CMD_RING_BUFF_FLUSH:
		if (softc_p->ring_buff_p == NULL) {
			rc = EAGAIN;
			break;
		}

		/*
		 * the simplest way to flush ring_buff is to empty it
		 */
		for (i = 0; i < softc_p->ring_buff_p->num_read_ptrs; i++) {
			softc_p->ring_buff_p->read_ptr_pos[i] =
			    softc_p->ring_buff_p->write_ptr_pos;

			/*
			 * if device driver is processing a user
			 * process's read() request
			 */
			if (softc_p->reader_flags[i] &
			    DCAM1394_FLAG_READ_REQ_PROC) {

				/*
				 * invalidate the read() request processing
				 * operation
				 */
				softc_p->reader_flags[i] |=
				    DCAM1394_FLAG_READ_REQ_INVALID;
			}
		}
		break;

	case DCAM1394_CMD_FRAME_SEQ_NUM_COUNT_RESET:
		mutex_enter(&softc_p->dcam_frame_is_done_mutex);
		softc_p->seq_count = 0;
		mutex_exit(&softc_p->dcam_frame_is_done_mutex);
		break;

	default:
		rc = EIO;
		break;

	}

done:
	if (param_list)
		kmem_free(param_list, sizeof (dcam1394_param_list_t));

	return (rc);
}


/* ARGSUSED */
int
dcam_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	dcam_state_t	*softc_p;
	int		instance;
	short		revent = 0;

	/*
	 * Without the logic to perform wakeups (see comment below), reject
	 * attempts at edge-triggered polling.
	 */
	if (events & POLLET) {
		return (EPERM);
	}

	instance = DEV_TO_INSTANCE(dev);
	softc_p = (dcam_state_t *)ddi_get_soft_state(dcam_state_p, instance);
	if (softc_p == NULL) {
		return (ENXIO);
	}

	if (softc_p->ring_buff_p != NULL) {
		size_t read_ptr_pos, write_ptr_pos;

		mutex_enter(&softc_p->dcam_frame_is_done_mutex);
		read_ptr_pos =
		    ring_buff_read_ptr_pos_get(softc_p->ring_buff_p, 0);
		write_ptr_pos =
		    ring_buff_write_ptr_pos_get(softc_p->ring_buff_p);
		mutex_exit(&softc_p->dcam_frame_is_done_mutex);

		if ((events & POLLRDNORM) && read_ptr_pos != write_ptr_pos) {
			revent |= POLLRDNORM;
		}
	}

	if ((events & POLLPRI) && softc_p->param_status) {
		revent |= POLLPRI;
	}

	/*
	 * No portion of this driver was ever wired up to perform a
	 * pollwakeup() on an associated pollhead.  The lack of an emitted
	 * pollhead informs poll/devpoll that the event status of this resource
	 * is not cacheable.
	 */
	*reventsp = revent;

	return (0);
}


/*
 * dcam_bus_reset_notify
 */
/* ARGSUSED */
void
dcam_bus_reset_notify(dev_info_t *dip, ddi_eventcookie_t ev_cookie, void *arg,
    void *impl_data)
{

	dcam_state_t 		*softc_p;
	t1394_localinfo_t 	*localinfo = impl_data;
	t1394_targetinfo_t 	targetinfo;

	softc_p = arg;

	/*
	 * this is needed to handle LG camera "changing GUID" bug
	 * XXX: What's this about?
	 */
	if ((dip == NULL) || (arg == NULL) || (impl_data == NULL) ||
	    (softc_p->sl_handle == NULL)) {
		return;
	}

	localinfo = impl_data;

	/*
	 * simply return if no target info
	 */
	if (t1394_get_targetinfo(softc_p->sl_handle,
	    localinfo->bus_generation, 0, &targetinfo) != DDI_SUCCESS)
		return;

	if (localinfo->local_nodeID == softc_p->targetinfo.target_nodeID) {
		softc_p->param_status |= DCAM1394_STATUS_CAM_UNPLUG;
	} else {
		softc_p->param_status &= ~DCAM1394_STATUS_CAM_UNPLUG;
	}

	/* struct copies */
	softc_p->attachinfo.localinfo = *localinfo;

	if (targetinfo.target_nodeID != T1394_INVALID_NODEID) {
		softc_p->targetinfo.current_max_payload =
		    targetinfo.current_max_payload;

		softc_p->targetinfo.current_max_speed =
		    targetinfo.current_max_speed;

		softc_p->targetinfo.target_nodeID =
		    targetinfo.target_nodeID;
	}
}


/*
 * byte_copy_to_user_buff
 */
static int
byte_copy_to_user_buff(uchar_t *src_addr_p, struct uio *uio_p, size_t num_bytes,
    int start_index, int *end_index_p)
{
	int	 index;
	size_t	 len;
	uchar_t	*u8_p;

	index = start_index;
	u8_p  = (uchar_t *)src_addr_p;

	while (num_bytes) {

		len = num_bytes;

		if (uiomove(u8_p, len, UIO_READ, uio_p)) {
			return (-1);
		}

		index++;
		u8_p		+= len;
		num_bytes	-= len;
	}

	*end_index_p = index;

	return (0);
}


/*
 * byte_copy_from_user_buff
 */
static int
byte_copy_from_user_buff(uchar_t *dst_addr_p, struct uio *uio_p,
    size_t num_bytes, int start_index, int *end_index_p)
{
	int	 index;
	size_t	 len;
	uchar_t	*u8_p;

	index = start_index;
	u8_p  = (uchar_t *)dst_addr_p;

	while (num_bytes) {
		len = num_bytes;

		if (uiomove(u8_p, len, UIO_WRITE, uio_p)) {
			return (-1);

		}

		index++;
		u8_p		+= len;
		num_bytes	-= len;

	}

	*end_index_p = index;

	return (0);
}


/*
 * dcam_reset()
 */
static int
dcam_reset(dcam_state_t *softc_p)
{
	dcam1394_reg_io_t dcam_reg_io;

	dcam_reg_io.offs = DCAM1394_REG_OFFS_INITIALIZE;
	dcam_reg_io.val  = DCAM1394_REG_VAL_INITIALIZE_ASSERT;

	if (dcam_reg_write(softc_p, &dcam_reg_io)) {
		return (-1);
	}

	/*
	 * If the camera has a TI VSP, tweak the iris feature
	 * to "on" and value 4.
	 */
	dcam_reg_io.offs = DCAM1394_REG_OFFS_FEATURE_CSR_BASE +
	    DCAM1394_REG_OFFS_IRIS_CSR;
	dcam_reg_io.val  = 0x82000004;

	if (dcam_reg_write(softc_p, &dcam_reg_io)) {
		return (-1);
	}

	return (0);
}
