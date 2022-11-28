/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * dcam_param.c
 *
 * dcam1394 driver.  Device parameter access.
 */

#include <sys/1394/targets/dcam1394/dcam.h>
#include <sys/1394/targets/dcam1394/dcam_param.h>
#include <sys/1394/targets/dcam1394/dcam_reg.h>

/* index by vid_mode */
int g_frame_num_bytes[] = {
	57600,  /* vid mode 0 */
	153600, /* vid mode 1 */
	460800, /* vid mode 2 */
	614400, /* vid mode 3 */
	921600, /* vid mode 4 */
	307200  /* vid mode 5 */
};


static uint_t feature_csr_val_construct(uint_t subparam, uint_t param_val,
    uint_t init_val);
static uint_t feature_csr_val_subparam_extract(uint_t subparam,
    uint_t feature_csr_val);
static uint_t feature_elm_inq_reg_val_subparam_extract(uint_t subparam,
    uint_t reg_val);


/*
 * param_attr_init
 */
int
param_attr_init(dcam_state_t *softc_p, dcam1394_param_attr_t param_attr)
{
	int	err, ret_err;
	uint_t	attr_bmap, cap_on_off, cap_power_ctrl, cap_read;
	uint_t	param, presence, subparam;

	bzero(param_attr, sizeof (dcam1394_param_attr_t));

	ret_err = DDI_SUCCESS;

	/*
	 * power ctrl cap
	 */
	param = DCAM1394_PARAM_CAP_POWER_CTRL;
	subparam = DCAM1394_SUBPARAM_NONE;
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
	param_attr_set(param_attr, param, subparam, attr_bmap);

	/*
	 * video mode cap
	 */
	param = DCAM1394_PARAM_CAP_VID_MODE;
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;

	for (subparam = DCAM1394_SUBPARAM_VID_MODE_0;
	    subparam <= DCAM1394_SUBPARAM_VID_MODE_5; subparam++) {
		param_attr_set(param_attr, param, subparam, attr_bmap);
	}

	/*
	 * frame rate cap
	 */
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;

	for (param = DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_0;
	    param <= DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_5; param++) {

		for (subparam = DCAM1394_SUBPARAM_FRAME_RATE_0;
		    subparam <= DCAM1394_SUBPARAM_FRAME_RATE_4; subparam++) {
			param_attr_set(param_attr, param, subparam, attr_bmap);
		}
	}

	/*
	 * power
	 */
	param = DCAM1394_PARAM_POWER;
	subparam = DCAM1394_SUBPARAM_NONE;
	err = dcam1394_param_get(softc_p, DCAM1394_PARAM_CAP_POWER_CTRL,
	    DCAM1394_SUBPARAM_NONE, &cap_power_ctrl);
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;

	if (cap_power_ctrl) {
		attr_bmap |= CAP_SET;
	}
	param_attr_set(param_attr, param, subparam, attr_bmap);

	/*
	 * video mode
	 */
	param = DCAM1394_PARAM_VID_MODE;
	subparam = DCAM1394_SUBPARAM_NONE;
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET | CAP_SET;
	param_attr_set(param_attr, param, subparam, attr_bmap);

	/*
	 * frame rate
	 */
	param = DCAM1394_PARAM_FRAME_RATE;
	subparam = DCAM1394_SUBPARAM_NONE;
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET | CAP_SET;
	param_attr_set(param_attr, param, subparam, attr_bmap);

	/*
	 * ring buffer capacity
	 */
	param = DCAM1394_PARAM_RING_BUFF_CAPACITY;
	subparam = DCAM1394_SUBPARAM_NONE;
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET | CAP_SET;
	param_attr_set(param_attr, param, subparam, attr_bmap);

	/*
	 * ring buffer: num frames ready
	 */
	param = DCAM1394_PARAM_RING_BUFF_NUM_FRAMES_READY;
	subparam = DCAM1394_SUBPARAM_NONE;
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
	param_attr_set(param_attr, param, subparam, attr_bmap);

	/*
	 * ring buffer: read ptr increment stride
	 */
	param = DCAM1394_PARAM_RING_BUFF_READ_PTR_INCR;
	subparam = DCAM1394_SUBPARAM_NONE;
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET | CAP_SET;
	param_attr_set(param_attr, param, subparam, attr_bmap);

	/*
	 * frame size
	 */
	param = DCAM1394_PARAM_FRAME_NUM_BYTES;
	subparam = DCAM1394_SUBPARAM_NONE;
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
	param_attr_set(param_attr, param, subparam, attr_bmap);

	/*
	 * cam status
	 */
	param = DCAM1394_PARAM_STATUS;
	subparam = DCAM1394_SUBPARAM_NONE;
	attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
	param_attr_set(param_attr, param, subparam, attr_bmap);

	/*
	 * features
	 */
	for (param = DCAM1394_PARAM_BRIGHTNESS; param <= DCAM1394_PARAM_TILT;
	    param++) {

		/*
		 * get feature presence
		 * If the operation to read the parameter fails, then act as
		 * though the feature is not implemented (because it isn't),
		 * don't report a DDI failure (as was previously done).
		 */
		err = dcam1394_param_get(softc_p, param,
		    DCAM1394_SUBPARAM_PRESENCE, &presence);

		if (!err) {
			/* feature presence */
			subparam  = DCAM1394_SUBPARAM_PRESENCE;
			attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
			param_attr_set(param_attr, param, subparam, attr_bmap);

			if (presence) {
				/* feature cap read */
				subparam  = DCAM1394_SUBPARAM_CAP_READ;
				attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
				param_attr_set(param_attr, param,
				    subparam, attr_bmap);

				/* feature cap on/off */
				subparam  = DCAM1394_SUBPARAM_CAP_ON_OFF;
				attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
				param_attr_set(param_attr, param,
				    subparam, attr_bmap);

				/* feature cap ctrl auto */
				subparam  = DCAM1394_SUBPARAM_CAP_CTRL_AUTO;
				attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
				param_attr_set(param_attr, param,
				    subparam, attr_bmap);

				/* feature cap ctrl manual */
				subparam  = DCAM1394_SUBPARAM_CAP_CTRL_MANUAL;
				attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
				param_attr_set(param_attr, param,
				    subparam, attr_bmap);

				/* feature min val */
				subparam  = DCAM1394_SUBPARAM_MIN_VAL;
				attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
				param_attr_set(param_attr, param,
				    subparam, attr_bmap);

				/* feature max val */
				subparam  = DCAM1394_SUBPARAM_MAX_VAL;
				attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;
				param_attr_set(param_attr, param,
				    subparam, attr_bmap);

				/* feature on/off */
				subparam = DCAM1394_SUBPARAM_ON_OFF;

				err = dcam1394_param_get(softc_p, param,
				    DCAM1394_SUBPARAM_CAP_ON_OFF, &cap_on_off);

				attr_bmap = IS_VALID | IS_PRESENT | CAP_GET;

				if (cap_on_off) {
					attr_bmap |= (CAP_SET | CAP_CTRL_SET);
				}

				param_attr_set(param_attr, param,
				    subparam, attr_bmap);

				/* feature control mode */
				subparam = DCAM1394_SUBPARAM_CTRL_MODE;
				attr_bmap = IS_VALID | IS_PRESENT | CAP_GET |
				    CAP_SET | CAP_CTRL_SET;

				param_attr_set(param_attr, param,
				    subparam, attr_bmap);

				/* get value read-out capability */
				err  = dcam1394_param_get(softc_p, param,
				    DCAM1394_SUBPARAM_CAP_READ,
				    &cap_read);

				if (param == DCAM1394_PARAM_WHITE_BALANCE) {
					/*
					 * white balance feature: u, v value
					 */
					subparam = DCAM1394_SUBPARAM_U_VALUE;
					attr_bmap = IS_VALID | IS_PRESENT |
					    CAP_SET | CAP_CTRL_SET;

					if (cap_read) {
						attr_bmap |= CAP_GET;
					}

					param_attr_set(param_attr, param,
					    subparam, attr_bmap);

					subparam = DCAM1394_SUBPARAM_V_VALUE;
					attr_bmap = IS_VALID | IS_PRESENT |
					    CAP_SET | CAP_CTRL_SET;

					if (cap_read) {
						attr_bmap |= CAP_GET;
					}

					param_attr_set(param_attr, param,
					    subparam, attr_bmap);

				} else {
					/* feature value */
					subparam = DCAM1394_SUBPARAM_VALUE;
					attr_bmap = IS_VALID | IS_PRESENT |
					    CAP_SET | CAP_CTRL_SET;

					if (cap_read) {
						attr_bmap |= CAP_GET;
					}

					param_attr_set(param_attr, param,
					    subparam, attr_bmap);
				}

			}

		}
	}

	return (ret_err);
}


/*
 * param_attr_set
 */
void
param_attr_set(dcam1394_param_attr_t  param_attr, uint_t param,
    uint_t subparam, uint_t attr_bmap)
{
	param_attr[param][subparam] = attr_bmap;
}


/*
 * dcam1394_ioctl_param_get
 *
 * softc's param_attr field must be initialized via param_attr_init()
 * before using this function.
 */
int
dcam1394_ioctl_param_get(dcam_state_t *softc_p,
    dcam1394_param_list_t param_list)
{
	int err, ret_err;
	int param, subparam;
	uint_t cap_get, is_present, is_valid, val;

	ret_err = 0;

	for (param = 0; param < DCAM1394_NUM_PARAM; param++) {
		for (subparam = 0;
		    subparam < DCAM1394_NUM_SUBPARAM;
		    subparam++) {

			if (param_list[param][subparam].flag) {
				is_valid =
				    softc_p->param_attr[param][subparam] &
				    IS_VALID;
				is_present =
				    softc_p->param_attr[param][subparam] &
				    IS_PRESENT;
				cap_get =
				    softc_p->param_attr[param][subparam] &
				    CAP_GET;

				if (is_valid && is_present && cap_get) {
					if (err = dcam1394_param_get(softc_p,
					    param, subparam, &val)) {

					    param_list[param][subparam].err = 1;
					    ret_err = 1;
					}

					if (!err) {
					    param_list[param][subparam].val =
						val;
					}
				} else {
					param_list[param][subparam].err = 1;
					ret_err = 1;
				}
			}
		}
	}

	return (ret_err);
}


/*
 * dcam1394_ioctl_param_set
 * softc's param_attr field must be initialized via param_attr_init()
 * before using this function.
 */
int
dcam1394_ioctl_param_set(dcam_state_t *softc_p, int is_ctrl_file,
    dcam1394_param_list_t param_list)
{
	int param, subparam;
	int ret_err;
	uint_t cap_set, is_present, is_valid, val;

	ret_err = 0;

	for (param = 0; param < DCAM1394_NUM_PARAM; param++) {
		for (subparam = 0;
		    subparam < DCAM1394_NUM_SUBPARAM;
		    subparam++) {
			if (param_list[param][subparam].flag) {
				is_valid =
				    softc_p->param_attr[param][subparam] &
				    IS_VALID;
				is_present =
				    softc_p->param_attr[param][subparam] &
				    IS_PRESENT;

				cap_set = is_ctrl_file ?
				    (softc_p->param_attr[param][subparam]
				    & CAP_CTRL_SET) :
				    (softc_p->param_attr[param][subparam]
				    & CAP_SET);

				if (is_valid && is_present && cap_set) {
					val = param_list[param][subparam].val;

					if (dcam1394_param_set(softc_p,
					    param, subparam, val)) {

					    param_list[param][subparam].err = 1;
					    ret_err = 1;
					}
				} else {
					param_list[param][subparam].err = 1;
					ret_err = 1;
				}
			}
		}
	}

	return (ret_err);
}


/*
 * dcam1394_param_get
 */
int
dcam1394_param_get(dcam_state_t  *softc_p, uint_t param, uint_t subparam,
    uint_t *val_p)
{
	int err;

	switch (param) {

	case DCAM1394_PARAM_CAP_POWER_CTRL:
		err = param_cap_power_ctrl_get(softc_p, val_p);
		break;

	case DCAM1394_PARAM_CAP_VID_MODE:
		err = param_cap_vid_mode_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_0:
	case DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_1:
	case DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_2:
	case DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_3:
	case DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_4:
	case DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_5:
		err = param_cap_frame_rate_get(softc_p, param, subparam, val_p);
		break;

	case DCAM1394_PARAM_POWER:
		err = param_power_get(softc_p, val_p);
		break;

	case DCAM1394_PARAM_VID_MODE:
		err = param_vid_mode_get(softc_p, val_p);
		break;

	case DCAM1394_PARAM_FRAME_RATE:
		err = param_frame_rate_get(softc_p, val_p);
		break;

	case DCAM1394_PARAM_RING_BUFF_CAPACITY:
		err = param_ring_buff_capacity_get(softc_p, val_p);
		break;

	case DCAM1394_PARAM_RING_BUFF_NUM_FRAMES_READY:
		err = param_ring_buff_num_frames_ready_get(softc_p, val_p);
		break;

	case DCAM1394_PARAM_RING_BUFF_READ_PTR_INCR:
		err = param_ring_buff_read_ptr_incr_get(softc_p, val_p);
		break;

	case DCAM1394_PARAM_FRAME_NUM_BYTES:
		err = param_frame_num_bytes_get(softc_p, val_p);
		break;

	case DCAM1394_PARAM_STATUS:
		err = param_status_get(softc_p, val_p);
		break;

	case DCAM1394_PARAM_BRIGHTNESS:
		err = param_brightness_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_EXPOSURE:
		err = param_exposure_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_SHARPNESS:
		err = param_sharpness_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_WHITE_BALANCE:
		err = param_white_balance_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_HUE:
		err = param_hue_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_SATURATION:
		err = param_saturation_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_GAMMA:
		err = param_gamma_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_SHUTTER:
		err = param_shutter_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_GAIN:
		err = param_gain_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_IRIS:
		err = param_iris_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_FOCUS:
		err = param_focus_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_ZOOM:
		err = param_zoom_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_PAN:
		err = param_pan_get(softc_p, subparam, val_p);
		break;

	case DCAM1394_PARAM_TILT:
		err = param_tilt_get(softc_p, subparam, val_p);
		break;

	default:
		err = 1;
		break;
	}

	return (err);
}


/*
 * dcam1394_param_set
 */
int
dcam1394_param_set(dcam_state_t *softc_p, uint_t param, uint_t subparam,
    uint_t val)
{
	int err;

	switch (param) {

	case DCAM1394_PARAM_POWER:
		err = param_power_set(softc_p, val);
		break;

	case DCAM1394_PARAM_VID_MODE:
		err = param_vid_mode_set(softc_p, val);
		break;

	case DCAM1394_PARAM_FRAME_RATE:
		err = param_frame_rate_set(softc_p, val);
		break;

	case DCAM1394_PARAM_RING_BUFF_CAPACITY:
		err = param_ring_buff_capacity_set(softc_p, val);
		break;

	case DCAM1394_PARAM_RING_BUFF_READ_PTR_INCR:
		err = param_ring_buff_read_ptr_incr_set(softc_p, val);
		break;

	case DCAM1394_PARAM_BRIGHTNESS:
		err = param_brightness_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_EXPOSURE:
		err = param_exposure_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_SHARPNESS:
		err = param_sharpness_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_WHITE_BALANCE:
		err = param_white_balance_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_HUE:
		err = param_hue_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_SATURATION:
		err = param_saturation_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_GAMMA:
		err = param_gamma_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_SHUTTER:
		err = param_shutter_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_GAIN:
		err = param_gain_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_IRIS:
		err = param_iris_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_FOCUS:
		err = param_focus_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_ZOOM:
		err = param_zoom_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_PAN:
		err = param_pan_set(softc_p, subparam, val);
		break;

	case DCAM1394_PARAM_TILT:
		err = param_tilt_set(softc_p, subparam, val);
		break;

	default:
		err = 1;
		break;
	}

	return (err);
}


/*
 * feature_get
 */
int
feature_get(dcam_state_t *softc_p, uint_t feature_csr_offs,
    uint_t feature_elm_inq_reg_offs, uint_t subparam, uint_t *val_p)
{
	dcam1394_reg_io_t	reg_io;
	uint_t			val;

	switch (subparam) {

	case DCAM1394_SUBPARAM_PRESENCE:
	case DCAM1394_SUBPARAM_ON_OFF:
	case DCAM1394_SUBPARAM_CTRL_MODE:
	case DCAM1394_SUBPARAM_VALUE:
	case DCAM1394_SUBPARAM_U_VALUE:
	case DCAM1394_SUBPARAM_V_VALUE:
		reg_io.offs = feature_csr_offs +
		    DCAM1394_REG_OFFS_FEATURE_CSR_BASE;

		if (dcam_reg_read(softc_p, &reg_io)) {
			return (1);
		}

		val = feature_csr_val_subparam_extract(subparam, reg_io.val);
		break;

	case DCAM1394_SUBPARAM_CAP_READ:
	case DCAM1394_SUBPARAM_CAP_ON_OFF:
	case DCAM1394_SUBPARAM_CAP_CTRL_AUTO:
	case DCAM1394_SUBPARAM_CAP_CTRL_MANUAL:
	case DCAM1394_SUBPARAM_MIN_VAL:
	case DCAM1394_SUBPARAM_MAX_VAL:
		reg_io.offs = feature_elm_inq_reg_offs +
		    DCAM1394_REG_OFFS_FEATURE_ELM_INQ_BASE;

		if (dcam_reg_read(softc_p, &reg_io)) {
			return (1);
		}

		val = feature_elm_inq_reg_val_subparam_extract(subparam,
		    reg_io.val);

		break;

	default:
		return (1);
	}

	*val_p = val;

	return (0);
}


/*
 * feature_set
 */
int
feature_set(dcam_state_t *softc_p, uint_t feature_csr_offs,
    uint_t subparam, uint_t val)
{
	dcam1394_reg_io_t  reg_io;

	reg_io.offs = feature_csr_offs + DCAM1394_REG_OFFS_FEATURE_CSR_BASE;

	if (dcam_reg_read(softc_p, &reg_io)) {
		return (1);
	}

	reg_io.val = feature_csr_val_construct(subparam, val, reg_io.val);

	if (dcam_reg_write(softc_p, &reg_io)) {
		return (1);
	}

	return (0);
}


/*
 * param_cap_power_ctrl_get
 */
int
param_cap_power_ctrl_get(dcam_state_t *softc_p, uint_t *val_p)
{
	dcam1394_reg_io_t reg_io;

	reg_io.offs = DCAM1394_REG_OFFS_BASIC_FUNC_INQ;

	if (dcam_reg_read(softc_p, &reg_io)) {
		return (1);
	}

	*val_p = (reg_io.val & DCAM1394_MASK_CAM_POWER_CTRL) >>
	    DCAM1394_SHIFT_CAM_POWER_CTRL;

	return (0);
}


/*
 * param_cap_vid_mode_get
 * dcam spec: sec 1.2.1.1
 */
int
param_cap_vid_mode_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	dcam1394_reg_io_t	reg_io;
	uint_t			mask, shift, vid_mode;

	vid_mode    = subparam - DCAM1394_SUBPARAM_VID_MODE_0;
	reg_io.offs = DCAM1394_REG_OFFS_VID_MODE_INQ;

	if (dcam_reg_read(softc_p, &reg_io)) {
		return (1);
	}

	mask  = 1 << (31 - vid_mode);
	shift = 31 - vid_mode;

	*val_p = (reg_io.val & mask) >> shift;

	return (0);
}


/*
 * param_cap_frame_rate_get()
 * dcam spec: sec 1.2.2
 */
int
param_cap_frame_rate_get(dcam_state_t *softc_p, uint_t param,
    uint_t subparam, uint_t *val_p)
{
	dcam1394_reg_io_t	reg_io;
	uint_t			frame_rate, mask, shift, vid_mode;

	vid_mode   = param - DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_0;
	frame_rate = subparam - DCAM1394_SUBPARAM_FRAME_RATE_0;

	reg_io.offs = DCAM1394_REG_OFFS_FRAME_RATE_INQ_BASE + (4 * vid_mode);

	if (dcam_reg_read(softc_p, &reg_io)) {
		return (1);
	}

	mask = 1 << (31 - (frame_rate + 1));
	shift = 31 - (frame_rate + 1);

	*val_p = (reg_io.val & mask) >> shift;

	return (0);
}


/*
 * param_power_get
 */
int
param_power_get(dcam_state_t *softc_p, uint_t *val_p)
{
	dcam1394_reg_io_t reg_io;

	reg_io.offs = DCAM1394_REG_OFFS_CAMERA_POWER;

	if (dcam_reg_read(softc_p, &reg_io)) {
		return (1);
	}

	*val_p = reg_io.val >> DCAM1394_SHIFT_CAMERA_POWER;

	return (0);
}


/*
 * param_power_set()
 */
int
param_power_set(dcam_state_t *softc_p, uint_t val)
{
	dcam1394_reg_io_t reg_io;

	reg_io.offs = DCAM1394_REG_OFFS_CAMERA_POWER;
	reg_io.val = val << DCAM1394_SHIFT_CAMERA_POWER;

	if (dcam_reg_write(softc_p, &reg_io)) {
		return (1);
	}

	return (0);
}


/*
 * param_vid_mode_get
 */
int
param_vid_mode_get(dcam_state_t *softc_p, uint_t *val_p)
{
	dcam1394_reg_io_t  reg_io;

	reg_io.offs = DCAM1394_REG_OFFS_CUR_V_MODE;

	if (dcam_reg_read(softc_p, &reg_io)) {
		return (1);
	}

	*val_p = reg_io.val >> DCAM1394_SHIFT_CUR_V_MODE;

	return (0);
}


/*
 * param_vid_mode_set
 */
int
param_vid_mode_set(dcam_state_t *softc_p, uint_t val)
{
	dcam1394_reg_io_t	reg_io;
	uint_t			vid_mode;

	vid_mode = val - DCAM1394_VID_MODE_0;

	reg_io.offs = DCAM1394_REG_OFFS_CUR_V_MODE;
	reg_io.val  = vid_mode << DCAM1394_SHIFT_CUR_V_MODE;

	if (dcam_reg_write(softc_p, &reg_io)) {
		return (1);
	}

	softc_p->cur_vid_mode = val;

	/*
	 * if we are currently receiving frames, we need to do a restart
	 * so that the new vid mode value takes effect
	 */
	if (softc_p->flags & DCAM1394_FLAG_FRAME_RCV_INIT) {
		(void) dcam_frame_rcv_stop(softc_p);
		(void) dcam1394_ioctl_frame_rcv_start(softc_p);
	}

	return (0);
}


/*
 * param_frame_rate_get
 */
int
param_frame_rate_get(dcam_state_t *softc_p, uint_t *val_p)
{
	dcam1394_reg_io_t	reg_io;
	uint_t			frame_rate;

	reg_io.offs = DCAM1394_REG_OFFS_CUR_V_FRM_RATE;

	if (dcam_reg_read(softc_p, &reg_io)) {
		return (1);
	}

	frame_rate = reg_io.val >> DCAM1394_SHIFT_CUR_V_FRM_RATE;

	*val_p = frame_rate - 1 + DCAM1394_FRAME_RATE_0;

	return (0);
}


/*
 * param_frame_rate_set
 */
int
param_frame_rate_set(dcam_state_t *softc_p, uint_t val)
{
	dcam1394_reg_io_t	reg_io;
	uint_t			frame_rate;

	/* if we are currently receiving frames, stop the camera */
	if (softc_p->flags & DCAM1394_FLAG_FRAME_RCV_INIT) {
		(void) dcam_frame_rcv_stop(softc_p);

		frame_rate = val - DCAM1394_FRAME_RATE_0 + 1;

		reg_io.offs = DCAM1394_REG_OFFS_CUR_V_FRM_RATE;
		reg_io.val  = frame_rate << DCAM1394_SHIFT_CUR_V_FRM_RATE;

		if (dcam_reg_write(softc_p, &reg_io)) {
			return (1);
		}

		/*
		 * Update the state info.
		 * note: the driver maintains frame rate in an array
		 * whereas the the camera uses predefined values whose
		 * lowest frame rate starts at 6
		 */
		softc_p->cur_frame_rate = val - 6;

		/* restart the camera */
		(void) dcam1394_ioctl_frame_rcv_start(softc_p);
	} else {
		frame_rate = val - DCAM1394_FRAME_RATE_0 + 1;

		reg_io.offs = DCAM1394_REG_OFFS_CUR_V_FRM_RATE;
		reg_io.val  = frame_rate << DCAM1394_SHIFT_CUR_V_FRM_RATE;

		if (dcam_reg_write(softc_p, &reg_io)) {
			return (1);
		}

		/* see note above re skewing of value by 6 */
		softc_p->cur_frame_rate = val - 6;
	}

	return (0);
}


/*
 * param_ring_buff_capacity_get()
 */
int
param_ring_buff_capacity_get(dcam_state_t *softc_p, uint_t *val_p)
{
	*val_p = softc_p->cur_ring_buff_capacity;

	return (0);
}


/*
 * param_ring_buff_capacity_set
 */
int
param_ring_buff_capacity_set(dcam_state_t *softc_p, uint_t val)
{
	/* bounds check */
	if ((val < 2) || (val > 30)) {
		return (1);
	}

	/* update our state info */
	softc_p->cur_ring_buff_capacity = val;


	/*
	 * if we are currently receiving frames, we need to do a restart
	 * so that the new buff_capacity value takes effect
	 */
	if (softc_p->flags & DCAM1394_FLAG_FRAME_RCV_INIT) {
		(void) dcam_frame_rcv_stop(softc_p);
		(void) dcam1394_ioctl_frame_rcv_start(softc_p);
	}
	return (0);
}


/*
 * param_ring_buff_num_frames_ready_get()
 */
int
param_ring_buff_num_frames_ready_get(dcam_state_t *softc_p, uint_t *val_p)
{
	size_t read_pos, write_pos;

	/*
	 * note: currently we support only one read_ptr_id, so the
	 * following logic will work. If multiple read_ptr_id's are
	 * supported, this function call will need to receive a
	 * read_ptr_id
	 */

	if (softc_p->ring_buff_p == NULL) {
		return (1);
	}

	mutex_enter(&softc_p->dcam_frame_is_done_mutex);

	read_pos  = ring_buff_read_ptr_pos_get(softc_p->ring_buff_p, 0);
	write_pos = ring_buff_write_ptr_pos_get(softc_p->ring_buff_p);

	if (read_pos < write_pos) {
		*val_p = write_pos - read_pos;
	} else {
		*val_p = (softc_p->ring_buff_p->num_buffs + write_pos) -
		    read_pos;
	}

	mutex_exit(&softc_p->dcam_frame_is_done_mutex);

	return (0);
}


/*
 * param_ring_buff_read_ptr_incr_get()
 */

int
param_ring_buff_read_ptr_incr_get(dcam_state_t *softc_p, uint_t *val_p)
{
	if (softc_p->ring_buff_p == NULL) {
		return (1);
	}

	*val_p = softc_p->ring_buff_p->read_ptr_incr_val;

	return (0);
}


/*
 * param_ring_buff_read_ptr_incr_set
 */
int
param_ring_buff_read_ptr_incr_set(dcam_state_t *softc_p, uint_t val)
{
	if (softc_p->ring_buff_p == NULL) {
		return (1);
	}

	softc_p->ring_buff_p->read_ptr_incr_val = val;

	return (0);
}


/*
 * param_frame_num_bytes_get
 */
int
param_frame_num_bytes_get(dcam_state_t *softc_p, uint_t *val_p)
{
	if (softc_p == NULL) {
		return (1);
	}

	*val_p = g_frame_num_bytes[softc_p->cur_vid_mode];

	return (0);
}


/*
 * param_status_get()
 */

int
param_status_get(dcam_state_t *softc_p, uint_t *val_p)
{
	mutex_enter(&softc_p->dcam_frame_is_done_mutex);

	*val_p = softc_p->param_status;
	softc_p->param_status = 0;

	mutex_exit(&softc_p->dcam_frame_is_done_mutex);

	return (0);
}


/*
 * param_brightness_get
 */
int
param_brightness_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_BRIGHTNESS_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_BRIGHTNESS_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_brightness_set()
 */
int
param_brightness_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_BRIGHTNESS_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_exposure_get
 */
int
param_exposure_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_EXPOSURE_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_EXPOSURE_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_exposure_set
 */
int
param_exposure_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_EXPOSURE_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_sharpness_get
 */
int
param_sharpness_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_SHARPNESS_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_SHARPNESS_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_sharpness_set
 */
int
param_sharpness_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_SHARPNESS_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_white_balance_get
 */
int
param_white_balance_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_WHITE_BALANCE_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_WHITE_BALANCE_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_white_balance_set
 */
int
param_white_balance_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_WHITE_BALANCE_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_hue_get
 */
int
param_hue_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_HUE_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_HUE_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_hue_set
 */
int
param_hue_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_HUE_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_saturation_get
 */
int
param_saturation_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_SATURATION_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_SATURATION_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_saturation_set
 */
int
param_saturation_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_SATURATION_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_gamma_get
 */
int
param_gamma_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_GAMMA_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_GAMMA_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_gamma_set
 */
int
param_gamma_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_GAMMA_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_shutter_get
 */
int
param_shutter_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_SHUTTER_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_SHUTTER_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_shutter_set
 */
int
param_shutter_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_SHUTTER_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_gain_get
 */
int
param_gain_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_GAIN_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_GAIN_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_gain_set
 */
int
param_gain_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_GAIN_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_iris_get
 */
int
param_iris_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_IRIS_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_IRIS_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	switch (subparam) {
		case DCAM1394_SUBPARAM_PRESENCE:
			*val_p = 0;
			break;
		case DCAM1394_SUBPARAM_ON_OFF:
			*val_p = 1;
			break;
		case DCAM1394_SUBPARAM_MIN_VAL:
		case DCAM1394_SUBPARAM_MAX_VAL:
		case DCAM1394_SUBPARAM_VALUE:
			*val_p = 4;
			break;
		default:
			break;
	}

	return (ret_val);
}


/*
 * param_iris_set
 */
int
param_iris_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_IRIS_CSR;

	if (subparam == DCAM1394_SUBPARAM_ON_OFF) {
		val = 1;
	} else if (subparam == DCAM1394_SUBPARAM_VALUE) {
		val = 4;
	}
	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_focus_get
 */
int
param_focus_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_FOCUS_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_FOCUS_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_focus_set
 */
int
param_focus_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_FOCUS_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_zoom_get
 */
int
param_zoom_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_ZOOM_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_ZOOM_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_zoom_set
 */
int
param_zoom_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_ZOOM_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_pan_get
 */
int
param_pan_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_PAN_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_PAN_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_pan_set
 */
int
param_pan_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_PAN_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * param_tilt_get
 */
int
param_tilt_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p)
{
	int	ret_val;
	uint_t	feature_csr_offs;
	uint_t	feature_elm_inq_reg_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_TILT_CSR;
	feature_elm_inq_reg_offs = DCAM1394_REG_OFFS_TILT_INQ;

	ret_val = feature_get(softc_p, feature_csr_offs,
	    feature_elm_inq_reg_offs, subparam, val_p);

	return (ret_val);
}


/*
 * param_tilt_set
 */
int
param_tilt_set(dcam_state_t *softc_p, uint_t subparam, uint_t val)
{
	int	ret_val;
	uint_t	feature_csr_offs;

	feature_csr_offs = DCAM1394_REG_OFFS_TILT_CSR;

	ret_val = feature_set(softc_p, feature_csr_offs, subparam, val);

	return (ret_val);
}


/*
 * feature_csr_val_construct
 */
static uint_t
feature_csr_val_construct(uint_t subparam, uint_t param_val, uint_t init_val)
{
	uint_t ret_val;

	switch (subparam) {

	case DCAM1394_SUBPARAM_ON_OFF:
		ret_val = (init_val & ~(DCAM1394_MASK_ON_OFF)) |
		    (param_val << DCAM1394_SHIFT_ON_OFF);
		break;

	case DCAM1394_SUBPARAM_CTRL_MODE:
		ret_val = (init_val & ~(DCAM1394_MASK_A_M_MODE)) |
		    (param_val << DCAM1394_SHIFT_A_M_MODE);
		break;

	case DCAM1394_SUBPARAM_VALUE:
		ret_val = (init_val & ~(DCAM1394_MASK_VALUE)) |
		    (param_val << DCAM1394_SHIFT_VALUE);
		break;

	case DCAM1394_SUBPARAM_U_VALUE:
		ret_val = (init_val & ~(DCAM1394_MASK_U_VALUE)) |
		    (param_val << DCAM1394_SHIFT_U_VALUE);
		break;

	case DCAM1394_SUBPARAM_V_VALUE:
		ret_val = (init_val & ~(DCAM1394_MASK_V_VALUE)) |
		    (param_val << DCAM1394_SHIFT_V_VALUE);
		break;

	default:
		break;

	}

	return (ret_val);
}


/*
 * feature_csr_val_subparam_extract
 */
static uint_t
feature_csr_val_subparam_extract(uint_t subparam, uint_t reg_val)
{
	uint_t ret_val;

	switch (subparam) {

	case DCAM1394_SUBPARAM_PRESENCE:
		ret_val = (reg_val & DCAM1394_MASK_PRESENCE_INQ) >>
		    DCAM1394_SHIFT_PRESENCE_INQ;
		break;

	case DCAM1394_SUBPARAM_ON_OFF:
		ret_val = (reg_val & DCAM1394_MASK_ON_OFF) >>
		    DCAM1394_SHIFT_ON_OFF;
		break;

	case DCAM1394_SUBPARAM_CTRL_MODE:
		ret_val = (reg_val & DCAM1394_MASK_A_M_MODE) >>
		    DCAM1394_SHIFT_A_M_MODE;
		break;

	case DCAM1394_SUBPARAM_VALUE:
		ret_val = (reg_val & DCAM1394_MASK_VALUE) >>
		    DCAM1394_SHIFT_VALUE;
		break;

	case DCAM1394_SUBPARAM_U_VALUE:
		ret_val = (reg_val & DCAM1394_MASK_U_VALUE) >>
		    DCAM1394_SHIFT_U_VALUE;
		break;

	case DCAM1394_SUBPARAM_V_VALUE:

		ret_val = (reg_val & DCAM1394_MASK_V_VALUE) >>
		    DCAM1394_SHIFT_V_VALUE;
		break;

	default:

		ret_val = 0;

		break;

	}

	return (ret_val);

}


/*
 * feature_elm_inq_reg_val_subparam_extract
 */
static uint_t
feature_elm_inq_reg_val_subparam_extract(uint_t subparam,
    uint_t reg_val)
{
	uint_t ret_val;

	switch (subparam) {

	case DCAM1394_SUBPARAM_CAP_READ:
		ret_val = (reg_val & DCAM1394_MASK_READOUT_INQ) >>
		    DCAM1394_SHIFT_READOUT_INQ;
		break;

	case DCAM1394_SUBPARAM_CAP_ON_OFF:
		ret_val = (reg_val & DCAM1394_MASK_ON_OFF_INQ) >>
		    DCAM1394_SHIFT_ON_OFF_INQ;
		break;

	case DCAM1394_SUBPARAM_CAP_CTRL_AUTO:
		ret_val = (reg_val & DCAM1394_MASK_AUTO_INQ) >>
		    DCAM1394_SHIFT_AUTO_INQ;
		break;

	case DCAM1394_SUBPARAM_CAP_CTRL_MANUAL:
		ret_val = (reg_val & DCAM1394_MASK_MANUAL_INQ) >>
		    DCAM1394_SHIFT_MANUAL_INQ;
		break;

	case DCAM1394_SUBPARAM_MIN_VAL:
		ret_val = (reg_val & DCAM1394_MASK_MIN_VAL) >>
		    DCAM1394_SHIFT_MIN_VAL;
		break;

	case DCAM1394_SUBPARAM_MAX_VAL:
		ret_val = (reg_val & DCAM1394_MASK_MAX_VAL) >>
		    DCAM1394_SHIFT_MAX_VAL;
		break;

	default:
		ret_val = 0;
		break;

	}

	return (ret_val);
}
