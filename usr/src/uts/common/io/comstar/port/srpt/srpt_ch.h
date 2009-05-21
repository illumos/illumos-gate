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

#ifndef _SRPT_CH_H
#define	_SRPT_CH_H

/*
 * Prototypes and data structures specific to SCSI Session
 * interface.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Prototypes
 */
srpt_channel_t *srpt_ch_alloc(srpt_target_port_t *tgt, uint8_t port);
void srpt_ch_add_ref(srpt_channel_t *ch);
void srpt_ch_release_ref(srpt_channel_t *ch, uint_t wait);
void srpt_ch_disconnect(srpt_channel_t *ch);
void srpt_ch_cleanup(srpt_channel_t *ch);

ibt_wrid_t srpt_ch_alloc_swqe_wrid(srpt_channel_t *ch,
	srpt_swqe_type_t wqe_type, void *addr);
void srpt_ch_free_swqe_wrid(srpt_channel_t *ch, ibt_wrid_t id);

ibt_status_t srpt_ch_post_send(srpt_channel_t *ch, srpt_iu_t *iu,
	uint32_t len, uint_t fence);

#ifdef	__cplusplus
}
#endif

#endif /* _SRPT_CH_H */
