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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

#ifndef _AT_H
#define	_AT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * There is a lot of alignment problems in AppleTalk packets.
 * This is the reason some of the headers use uint8_t arrays instead of the
 * natural datatype.
 */

/* AARP */

#define	AARP_REQ		1
#define	AARP_RESP		2
#define	AARP_PROBE		3


/* DDP */

struct ddp_hdr {
	uint8_t		ddp_hop_len;
	uint8_t		ddp_len_lo;
	uint16_t	ddp_cksum;
	uint16_t	ddp_dest_net;
	uint16_t	ddp_src_net;
	uint8_t		ddp_dest_id;
	uint8_t		ddp_src_id;
	uint8_t		ddp_dest_sock;
	uint8_t		ddp_src_sock;
	uint8_t		ddp_type;
};

#define	ddp_pad(x)	((x)->ddp_hop_len & 0xc0)
#define	ddp_hop(x)	(((x)->ddp_hop_len >> 2) & 0xf)
#define	ddp_len(x)	((((x)->ddp_hop_len & 0x3) << 8) + (x)->ddp_len_lo)

#define	DDPHDR_SIZE 13

#define	DDP_TYPE_RTMPRQ		5
#define	DDP_TYPE_RTMPRESP	1
#define	DDP_TYPE_NBP		2
#define	DDP_TYPE_ATP		3
#define	DDP_TYPE_AEP		4
#define	DDP_TYPE_ZIP		6
#define	DDP_TYPE_ADSP		7


/* AECHO */

#define	AEP_REQ			1
#define	AEP_REPLY		2

/* NBP */

struct nbp_hdr {
	uint8_t		ddphdr[DDPHDR_SIZE];
	uint8_t		nbp_fun_cnt;
	uint8_t		nbp_id;
};

#define	NBP_BRRQ		1
#define	NBP_LKUP		2
#define	NBP_LKUP_REPLY		3
#define	NBP_FWDREQ		4


/* ZIP */

struct zip_hdr {
	uint8_t		ddphdr[DDPHDR_SIZE];
	uint8_t		zip_func;
	uint8_t		zip_netcnt;
};

#define	ZIP_QUERY		1
#define	ZIP_REPLY		2
#define	ZIP_GET_NET_INFO	5
#define	ZIP_GET_NET_INFO_REPLY	6
#define	ZIP_NOTIFY		7
#define	ZIP_EXT_REPLY		8

#define	ZIP_ATP_GETMYZONE	7
#define	ZIP_ATP_GETZONELIST	8
#define	ZIP_ATP_GETLOCALZONES	9

#define	ZIP_FLG_ONEZ		0x20
#define	ZIP_FLG_USEBRC		0x40
#define	ZIP_FLG_ZINV		0x80


/* ATP */

struct atp_hdr {
	uint8_t		ddphdr[DDPHDR_SIZE];
	uint8_t		atp_ctrl;
	uint8_t		atp_seq;
	uint8_t		atp_tid[2];
	uint8_t		atp_user[4];
};

#define	ATPHDR_SIZE	8

#define	atp_fun(x)	(((x) >> 6) & 0x3)
#define	atp_tmo(x)	((x) & 0x7)

#define	ATP_TREQ		1
#define	ATP_TRESP		2
#define	ATP_TREL		3
#define	ATP_FLG_STS		0x08
#define	ATP_FLG_EOM		0x10
#define	ATP_FLG_XO		0x20


#define	NODE_ID_BROADCAST	0xff

struct ddp_adsphdr {
	uint8_t	ddphdr[DDPHDR_SIZE];
	uint8_t	ad_connid[2];		/* short */
	uint8_t	ad_fbseq[4];		/* long */
	uint8_t	ad_nrseq[4];		/* long */
	uint8_t	ad_rcvwin[2];		/* short */
	uint8_t	ad_desc;
};

#define	AD_CTRL		0x80
#define	AD_ACKREQ	0x40
#define	AD_EOM		0x20
#define	AD_ATT		0x10
#define	AD_CTRL_MASK	0x0f

#define	AD_CREQ		0x81		/* Open Conn Request */
#define	AD_CACK		0x82		/* Open Conn Ack */
#define	AD_CREQ_ACK	0x83		/* Open Conn Req+Ack */
#define	AD_CDENY	0x84		/* Open Conn Denial */

struct ddp_adsp_att {
	struct ddp_adsphdr	ad;
	uint8_t		ad_att_code[2];	/* short */
};

struct ddp_adsp_open {
	struct ddp_adsphdr	ad;
	uint8_t		ad_version[2];	/* short */
	uint8_t		ad_dconnid[2];	/* short */
	uint8_t		ad_attseq[4];	/* long */
};

#define	RTMP_REQ	1
#define	RTMP_RDR_SH	2	/* Route Data Request, split horizon */
#define	RTMP_RDR_NSH	3	/* Route Data Request, no split horizon */

#define	RTMP_DIST_MASK	0x1f
#define	RTMP_EXTEND	0x80
#define	RTMP_FILLER	0x82


uint16_t get_short(uint8_t *);
uint32_t get_long(uint8_t *);

extern void interpret_aarp(int, char *, int);
extern void interpret_at(int, struct ddp_hdr *, int);
extern void interpret_nbp(int, struct nbp_hdr *, int);
extern void interpret_rtmp(int, struct ddp_hdr *, int);
extern void interpret_aecho(int, struct ddp_hdr *, int);
extern void interpret_atp(int, struct ddp_hdr *, int);
extern void interpret_adsp(int, struct ddp_adsphdr *, int);
extern void interpret_ddp_zip(int, struct zip_hdr *, int);
extern void interpret_atp_zip(int, struct atp_hdr *, int);

#ifdef __cplusplus
}
#endif

#endif /* _AT_H */
