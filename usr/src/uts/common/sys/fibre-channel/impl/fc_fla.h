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
 */

#ifndef	_SYS_FIBRE_CHANNEL_IMPL_FC_FLA_H
#define	_SYS_FIBRE_CHANNEL_IMPL_FC_FLA_H


#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_BIT_FIELDS_LTOH) && !defined(_BIT_FIELDS_HTOL)
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */

/*
 * Fabric Loop timers; Double check them with standards
 */
#define	FLA_RR_TOV			2

/*
 * SCR registration function codes
 */
#define	FC_SCR_FABRIC_REGISTRATION	0x01
#define	FC_SCR_NPORT_REGISTRATION	0x02
#define	FC_SCR_FULL_REGISTRATION	0x03
#define	FC_SCR_CLEAR_REGISTRATION	0xFF

/*
 * Address format of affected D_ID in RSCN Payload
 */
#define	FC_RSCN_PORT_ADDRESS		0x00
#define	FC_RSCN_AREA_ADDRESS		0x01
#define	FC_RSCN_DOMAIN_ADDRESS		0x02
#define	FC_RSCN_FABRIC_ADDRESS		0x03

#define	FC_RSCN_ADDRESS_MASK		0x03

/*
 * State Change Registration
 */
typedef struct scr_request {
	ls_code_t	ls_code;

#if defined(_BIT_FIELDS_LTOH)
	uint32_t	scr_func : 8,
			scr_rsvd : 24;
#else
	uint32_t	scr_rsvd : 24,
			scr_func : 8;
#endif	/* _BIT_FIELDS_LTOH */

} fc_scr_req_t;

typedef struct scr_response {
	uint32_t	scr_acc;
} fc_scr_resp_t;

typedef struct rscn_payload {
	uchar_t		rscn_code;
	uchar_t		rscn_len;
	uint16_t	rscn_payload_len;
} fc_rscn_t;

typedef struct affected_id {
#if defined(_BIT_FIELDS_LTOH)
	uint32_t	aff_d_id : 24,
			aff_format : 8;
#else
	uint32_t	aff_format : 8,
			aff_d_id : 24;
#endif	/* _BIT_FIELDS_LTOH */

} fc_affected_id_t;

typedef struct linit_req {
	ls_code_t	ls_code;
	uchar_t		rsvd;
	uchar_t		func;
	uchar_t		lip_b3;
	uchar_t		lip_b4;
} fc_linit_req_t;

typedef struct linit_resp {
	ls_code_t	ls_code;
#if defined(_BIT_FIELDS_LTOH)
	uint32_t	status: 8,
			rsvd : 24;
#else
	uint32_t	rsvd : 24,
			status : 8;
#endif	/* _BIT_FIELDS_LTOH */

} fc_linit_resp_t;

typedef struct loop_status_req {
	ls_code_t	ls_code;
} fc_lsts_req_t;

typedef struct loop_status_resp {
	ls_code_t	lsts_ls_code;
	uchar_t		lsts_rsvd1;
	uchar_t		lsts_failed_rx;
	uchar_t		lsts_fla_rev;
	uchar_t		lsts_state;
	uchar_t		lsts_pub_bitmap[16];
	uchar_t		lsts_priv_bitmap[16];
	uchar_t		lsts_lilp_length;
	uchar_t		lsts_lilp_map[127];
} fc_lsts_resp_t;

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request", scr_response))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", scr_request))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", rscn_payload))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", linit_req))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", linit_resp))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", loop_status_resp))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", loop_status_req))
#endif /* __lint */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FIBRE_CHANNEL_IMPL_FC_FLA_H */
