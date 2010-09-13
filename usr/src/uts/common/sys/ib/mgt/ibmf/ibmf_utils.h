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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IBMF_IBMF_UTILS_H
#define	_SYS_IB_MGT_IBMF_IBMF_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file contains helper functions for parsing management
 * datagram MADs.
 */
void
ibmf_utils_unpack_data(char *format, uchar_t *data, size_t datalen,
    void *structure, size_t structlen);

void
ibmf_utils_pack_data(char *format, void *structure, size_t structlen,
    uchar_t *data, size_t datalen);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBMF_IBMF_UTILS_H */
