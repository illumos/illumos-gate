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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IBMF_IBMF_SAA_UTILS_H
#define	_SYS_IB_MGT_IBMF_IBMF_SAA_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ib/mgt/sa_recs.h>

/*
 * The defines, sizes, and functions used in ibmf_saa_utils.h are currently
 * based on version 1.1 of the IB spec.  With each iteration of the
 * spec this file and ibmf_saa_utils.c must be updated.
 */
int
ibmf_saa_utils_pack_sa_hdr(ib_sa_hdr_t *sa_hdr, void **packed_class_hdr,
    size_t *packed_class_hdr_len, int km_sleep_flag);

int
ibmf_saa_utils_unpack_sa_hdr(void *packed_class_hdr,
    size_t packed_class_hdr_len, ib_sa_hdr_t **sa_hdr, int km_sleep_flag);

int
ibmf_saa_utils_unpack_payload(uchar_t *buf_payload, size_t buf_payload_length,
    uint16_t attr_id, void **structs_payloadp, size_t *structs_payload_lengthp,
    uint16_t attr_offset, boolean_t is_get_resp, int km_sleep_flag);

int
ibmf_saa_utils_pack_payload(uchar_t *structs_payload, size_t
    structs_payload_length, uint16_t attr_id, void **buf_payloadp,
    size_t *buf_payload_lengthp, int km_sleep_flag);

void
ibmf_saa_gid_trap_parse_buffer(uchar_t *buffer, sm_trap_64_t *sm_trap_64);

void
ibmf_saa_capmask_chg_trap_parse_buffer(uchar_t *buffer,
    sm_trap_144_t *sm_trap_144);

void
ibmf_saa_sysimg_guid_chg_trap_parse_buffer(uchar_t *buffer,
    sm_trap_145_t *sm_trap_145);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_MGT_IBMF_IBMF_SAA_UTILS_H */
