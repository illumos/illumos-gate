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


#ifndef _ACSAPI_PVT_
#define	_ACSAPI_PVT_
#ifndef _ACSAPI_H_

#endif

#ifndef _ACSSYS_PVT_

#endif

#if (!defined __STDDEF_H)&&(!defined __stddef_h)
#if (!defined _H_STDDEF) && (!defined __size_t)

#endif
#endif


extern int		sd_in;
extern TYPE		my_module_type;
extern ACCESSID		global_aid;

STATUS acs_verify_ssi_running(void);

STATUS acs_select_input(int timeout);

STATUS acs_ipc_read(ALIGNED_BYTES rbuf, size_t *size);

STATUS acs_get_response(ALIGNED_BYTES rbuf, size_t *size);

STATUS acs_ipc_write(ALIGNED_BYTES rbuf, size_t size);

STATUS acs_send_request(ALIGNED_BYTES rbuf, size_t size);

STATUS acs_cvt_v1_v2(ALIGNED_BYTES rbuf, size_t *byte_count);
STATUS acs_cvt_v2_v3(ALIGNED_BYTES rbuf, size_t *byte_count);
STATUS acs_cvt_v3_v4(ALIGNED_BYTES rbuf, size_t *byte_count);
STATUS acs_cvt_v4_v3(ALIGNED_BYTES rbuf, size_t *byte_count);
STATUS acs_cvt_v3_v2(ALIGNED_BYTES rbuf, size_t *byte_count);
STATUS acs_cvt_v2_v1(ALIGNED_BYTES rbuf, size_t *byte_count);

STATUS acs_build_header
(
    char		*rp,
    size_t		packetLength,
    SEQ_NO		seqNumber,
    COMMAND		requestCommand,
    unsigned char		requestOptions,
    VERSION		packetVersion,
    LOCKID		requestLock
);

STATUS acs_audit_int_response(char *buffer, ALIGNED_BYTES rbuf);

STATUS acs_audit_fin_response(char *buffer, ALIGNED_BYTES rbuf);

STATUS acs_register_int_response(char *buffer, ALIGNED_BYTES rbuf);

STATUS acs_query_response(char *buffer, ALIGNED_BYTES rbuf);

STATUS acs_vary_response(char *buffer, ALIGNED_BYTES rbuf);

char *acs_get_sockname(void);

#endif /* _ACSAPI_PVT_ */
