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

#ifndef	_SYS_1394_TARGETS_DCAM1394_PARAM_H
#define	_SYS_1394_TARGETS_DCAM1394_PARAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	IS_VALID	0x1
#define	IS_PRESENT	0x2
#define	CAP_GET		0x4
#define	CAP_SET		0x8
#define	CAP_CTRL_SET	0x10


int	param_attr_init(dcam_state_t *softc_p,
	    dcam1394_param_attr_t param_attr);
void	param_attr_set(dcam1394_param_attr_t param_attr, uint_t param,
	    uint_t subparam, uint_t attr_bmap);

int	dcam1394_ioctl_param_get(dcam_state_t *softc_p,
	    dcam1394_param_list_t param_list);
int	dcam1394_ioctl_param_set(dcam_state_t *softc_p, int is_ctrl_file,
	    dcam1394_param_list_t param_list);

int	dcam1394_param_get(dcam_state_t *softc_p, uint_t param,
	    uint_t subparam, uint_t *val_p);
int	dcam1394_param_set(dcam_state_t *softc_p, uint_t param,
	    uint_t subparam, uint_t val);

int	 feature_get(dcam_state_t *softc_p, uint_t feature_csr_offs,
	    uint_t feature_elm_inq_reg_offs, uint_t subparam, uint_t *val_p);
int	feature_set(dcam_state_t *softc_p, uint_t feature_csr_offs,
	    uint_t subparam, uint_t val);

int	param_cap_power_ctrl_get(dcam_state_t *softc_p, uint_t *val_p);
int	param_cap_vid_mode_get(dcam_state_t *softc_p, uint_t subparam,
	    uint_t *val_p);
int	param_cap_frame_rate_get(dcam_state_t  *softc_p, uint_t param,
	    uint_t subparam, uint_t *val_p);
int	param_power_get(dcam_state_t *softc_p, uint_t *val_p);
int	param_power_set(dcam_state_t *softc_p, uint_t val);
int	param_vid_mode_get(dcam_state_t *softc_p, uint_t *val_p);
int	param_vid_mode_set(dcam_state_t *softc_p, uint_t val);
int	param_frame_rate_get(dcam_state_t *softc_p, uint_t *val_p);
int	param_frame_rate_set(dcam_state_t *softc_p, uint_t val);
int	param_ring_buff_capacity_get(dcam_state_t *softc_p, uint_t *val_p);
int	param_ring_buff_capacity_set(dcam_state_t *softc_p, uint_t val);
int	param_ring_buff_num_frames_ready_get(dcam_state_t *softc_p,
	    uint_t *val_p);
int	param_ring_buff_read_ptr_incr_get(dcam_state_t *softc_p, uint_t *val_p);
int	param_ring_buff_read_ptr_incr_set(dcam_state_t *softc_p, uint_t val);
int	param_frame_num_bytes_get(dcam_state_t *softc_p, uint_t *val_p);
int	param_status_get(dcam_state_t *softc_p, uint_t *val_p);
int	param_brightness_get(dcam_state_t *softc_p, uint_t subparam,
	    uint_t *val_p);
int	param_brightness_set(dcam_state_t *softc_p, uint_t subparam,
	    uint_t val);
int	param_exposure_get(dcam_state_t *softc_p, uint_t subparam,
	    uint_t *val_p);
int	param_exposure_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_sharpness_get(dcam_state_t *softc_p, uint_t subparam,
	    uint_t *val_p);
int	param_sharpness_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_white_balance_get(dcam_state_t *softc_p, uint_t subparam,
	    uint_t *val_p);
int	param_white_balance_set(dcam_state_t *softc_p, uint_t subparam,
	    uint_t val);
int	param_hue_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p);
int	param_hue_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_saturation_get(dcam_state_t *softc_p, uint_t subparam,
	    uint_t *val_p);
int	param_saturation_set(dcam_state_t *softc_p, uint_t subparam,
	    uint_t val);
int	param_gamma_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p);
int	param_gamma_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_shutter_get(dcam_state_t *softc_p, uint_t subparam,
	    uint_t *val_p);
int	param_shutter_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_gain_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p);
int	param_gain_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_iris_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p);
int	param_iris_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_focus_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p);
int	param_focus_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_zoom_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p);
int	param_zoom_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_pan_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p);
int	param_pan_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);
int	param_tilt_get(dcam_state_t *softc_p, uint_t subparam, uint_t *val_p);
int	param_tilt_set(dcam_state_t *softc_p, uint_t subparam, uint_t val);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_TARGETS_DCAM1394_PARAM_H */
