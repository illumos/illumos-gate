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

#ifndef	_SYS_FIBRE_CHANNEL_IMPL_FC_LINKAPP_H
#define	_SYS_FIBRE_CHANNEL_IMPL_FC_LINKAPP_H



#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_BIT_FIELDS_LTOH) && !defined(_BIT_FIELDS_HTOL)
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */

/*
 * Link Application Opcodes.
 */
#define	LA_ELS_RJT		0x01
#define	LA_ELS_ACC		0x02
#define	LA_ELS_PLOGI		0x03
#define	LA_ELS_FLOGI		0x04
#define	LA_ELS_LOGO		0x05
#define	LA_ELS_ABTX		0x06
#define	LA_ELS_RCS		0x07
#define	LA_ELS_RES		0x08
#define	LA_ELS_RSS		0x09
#define	LA_ELS_RSI		0x0a
#define	LA_ELS_ESTS		0x0b
#define	LA_ELS_ESTC		0x0c
#define	LA_ELS_ADVC		0x0d
#define	LA_ELS_RTV		0x0e
#define	LA_ELS_RLS		0x0f
#define	LA_ELS_ECHO		0x10
#define	LA_ELS_RRQ		0x12
#define	LA_ELS_PRLI		0x20
#define	LA_ELS_PRLO		0x21
#define	LA_ELS_SCN		0x22
#define	LA_ELS_TPLS		0x23
#define	LA_ELS_GPRLO		0x24
#define	LA_ELS_GAID		0x30
#define	LA_ELS_FACT		0x31
#define	LA_ELS_FDACT		0x32
#define	LA_ELS_NACT		0x33
#define	LA_ELS_NDACT		0x34
#define	LA_ELS_QoSR		0x40
#define	LA_ELS_RVCS		0x41
#define	LA_ELS_PDISC		0x50
#define	LA_ELS_FDISC		0x51
#define	LA_ELS_ADISC		0x52
#define	LA_ELS_RSCN		0x61
#define	LA_ELS_SCR		0x62
#define	LA_ELS_LINIT		0x70
#define	LA_ELS_RNID		0x78

/*
 * LINIT status codes in the ACC
 */
#define	FC_LINIT_SUCCESS	0x01
#define	FC_LINIT_FAILURE	0x02

/* Basic Accept Payload. */
typedef struct la_ba_acc {

#if defined(_BIT_FIELDS_LTOH)
	uint32_t	org_sid : 24,
			seq_id : 8;

#else
	uint32_t	seq_id : 8,
			org_sid : 24;

#endif	/* _BIT_FIELDS_LTOH */

	uint16_t	ox_id;
	uint16_t	rx_id;
} la_ba_acc_t;


/* Basic Reject. */
typedef struct la_ba_rjt {
	uchar_t		reserved;
	uchar_t		reason_code;
	uchar_t		explanation;
	uchar_t		vendor;
} la_ba_rjt_t;


/* Logout payload. */
typedef struct la_els_logo {
	ls_code_t	ls_code;
	fc_portid_t	nport_id;
	la_wwn_t	nport_ww_name;
} la_els_logo_t;

/* Address discovery */
typedef	struct la_els_adisc {
	ls_code_t	ls_code;
	fc_hardaddr_t	hard_addr;
	la_wwn_t	port_wwn;
	la_wwn_t	node_wwn;
	fc_portid_t	nport_id;
} la_els_adisc_t;


/* Link Application Reject */
typedef struct la_els_rjt {
	ls_code_t	ls_code;
	uchar_t		action;
	uchar_t		reason;
	uchar_t		reserved;
	uchar_t		vu;
} la_els_rjt_t;

/* Process Login/Logout Service Parameter Page */
#define	SP_OPA_VALID			0x8000
#define	SP_RPA_VALID			0x4000
#define	SP_ESTABLISH_IMAGE_PAIR		0x2000
#define	SP_RESP_CODE_MASK		0x0F00
#define	SP_RESP_CODE_REQ_EXECUTED	0x0100

typedef struct service_parameter_page {
	uint8_t		type_code;
	uint8_t		type_code_ext;
	uint16_t	flags;
	uint32_t	opa;
	uint32_t	rpa;
	uint32_t	sp;
} service_parameter_page_t;

/* Process login */
typedef struct la_els_prli {
#if defined(_BIT_FIELDS_LTOH)
	uint32_t	payload_length : 16,
			page_length : 8,
			ls_code : 8;

#elif	defined(_BIT_FIELDS_HTOL)
	uint32_t	ls_code : 8,
			page_length : 8,
			payload_length : 16;

#endif	/* _BIT_FIELDS_LTOH */
	uchar_t		service_params[16];
} la_els_prli_t;

/* Process Logout */
typedef struct la_els_prlo {
	uint8_t		ls_code;
	uint8_t		page_length;
	uint16_t	payload_length;
	uint8_t		type_code;
	uint8_t		type_code_extension;
	uint16_t	flags;
	uint32_t	opa;
	uint32_t	rpa;
	uint32_t	reserved;
} la_els_prlo_t;

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request", la_ba_rjt))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", la_els_logo))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", la_els_adisc))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", la_els_rjt))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", la_els_prli_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", la_ba_acc))
#endif /* __lint */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FIBRE_CHANNEL_IMPL_FC_LINKAPP_H */
