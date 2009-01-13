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

#ifndef	_SYS_PX_INTR_H
#define	_SYS_PX_INTR_H

#ifdef	__cplusplus
extern "C" {
#endif

extern dev_info_t *px_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip);

extern int px_intx_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
	ddi_intr_handle_impl_t *handle, void *result);
extern int px_msix_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
	ddi_intr_handle_impl_t *handle, void *result);

extern int px_add_intx_intr(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp);
extern int px_rem_intx_intr(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp);

extern int px_add_msiq_intr(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp, msiq_rec_type_t rec_type,
	msgcode_t msg_code, msiqid_t *msiq_id_p);
extern int px_rem_msiq_intr(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp, msiq_rec_type_t rec_type,
	msgcode_t msg_code, msiqid_t msiq_id);

extern uint_t px_intx_intr(caddr_t arg);
extern uint_t px_msiq_intr(caddr_t arg);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_INTR_H */
