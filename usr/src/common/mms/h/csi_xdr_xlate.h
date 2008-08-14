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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _CSI_XDR_XLATE_
#define	_CSI_XDR_XLATE_

#define	CHECKSIZE(cur_size, obj_size, tot_size)                               \
	(cur_size + obj_size > tot_size) ?  TRUE : FALSE

#define	RETURN_PARTIAL_PACKET(xdrsp, bufferp)                                 \
{                                                                             \
	if (XDR_DECODE == xdrsp->x_op) {                                      \
	bufferp->size = csi_xcur_size;                                        \
	bufferp->translated_size = csi_xcur_size;                             \
	bufferp->packet_status =					\
			(CSI_PAKSTAT_INITIAL == bufferp->packet_status)\
	? CSI_PAKSTAT_XLATE_ERROR : bufferp->packet_status;             \
	if (xdr_allocated)                                                    \
		bufferp->maxsize = csi_xcur_size;                             \
	}                                                                     \
	else if (XDR_ENCODE == xdrsp->x_op) {                                 \
	bufferp->translated_size = csi_xcur_size;                             \
	}                                                                     \
	return (1);                                                            \
}

#define	RETURN_COMPLETE_PACKET(xdrsp, bufferp)                                \
{                                                                             \
	bufferp->packet_status = CSI_PAKSTAT_XLATE_COMPLETED; \
	RETURN_PARTIAL_PACKET(xdrsp, bufferp)                 \
}



#endif /* _CSI_XDR_XLATE_ */
