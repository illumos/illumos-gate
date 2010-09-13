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

#ifndef	_SYS_1394_TARGETS_DCAM1394_FRAME_H
#define	_SYS_1394_TARGETS_DCAM1394_FRAME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

int	dcam1394_ioctl_frame_rcv_start(dcam_state_t *softc_p);
int	dcam_frame_rcv_init(dcam_state_t *softc_p, int vid_mode,
	    int frame_rate, int ring_buff_num_frames);
int	dcam_frame_rcv_fini(dcam_state_t *softc_p);
int	dcam_frame_rcv_start(dcam_state_t *softc_p);
int	dcam_frame_rcv_stop(dcam_state_t *softc_p);
void	dcam_frame_is_done(void *ssp, ixl1394_callback_t *ixlp);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_TARGETS_DCAM1394_FRAME_H */
