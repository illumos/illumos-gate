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

#ifndef _HXGE_PFC_H
#define	_HXGE_PFC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* 0 and 4095 are reserved */
#define	VLAN_ID_MIN			1
#define	VLAN_ID_MAX			4094
#define	VLAN_ID_IMPLICIT		0

#define	HXGE_MAC_DEFAULT_ADDR_SLOT	0

#define	HASH_BITS			8
#define	NMCFILTER_BITS			(1 << HASH_BITS)
#define	HASH_REG_WIDTH			16
#define	NMCFILTER_REGS			(NMCFILTER_BITS / HASH_REG_WIDTH)
					/* Number of multicast filter regs */
#define	MAC_MAX_HASH_ENTRY		NMCFILTER_REGS

#define	REG_PIO_WRITE64(handle, offset, value) \
		HXGE_REG_WR64((handle), (offset), (value))
#define	REG_PIO_READ64(handle, offset, val_p) \
		HXGE_REG_RD64((handle), (offset), (val_p))

#define	TCAM_CTL_RWC_TCAM_WR		0x0
#define	TCAM_CTL_RWC_TCAM_CMP		0x2
#define	TCAM_CTL_RWC_RAM_WR		0x4
#define	TCAM_CTL_RWC_RAM_RD		0x5
#define	TCAM_CTL_RWC_RWC_STAT		0x1
#define	TCAM_CTL_RWC_RWC_MATCH		0x1

#define	WRITE_TCAM_REG_CTL(handle, ctl) \
		REG_PIO_WRITE64(handle, PFC_TCAM_CTRL, ctl)

#define	READ_TCAM_REG_CTL(handle, val_p) \
		REG_PIO_READ64(handle, PFC_TCAM_CTRL, val_p)

#define	WRITE_TCAM_REG_KEY0(handle, key)	\
		REG_PIO_WRITE64(handle,  PFC_TCAM_KEY0, key)
#define	WRITE_TCAM_REG_KEY1(handle, key) \
		REG_PIO_WRITE64(handle,  PFC_TCAM_KEY1, key)
#define	WRITE_TCAM_REG_MASK0(handle, mask)   \
		REG_PIO_WRITE64(handle,  PFC_TCAM_MASK0, mask)
#define	WRITE_TCAM_REG_MASK1(handle, mask)   \
		REG_PIO_WRITE64(handle,  PFC_TCAM_MASK1, mask)

#define	READ_TCAM_REG_KEY0(handle, val_p)	\
		REG_PIO_READ64(handle,  PFC_TCAM_KEY0, val_p)
#define	READ_TCAM_REG_KEY1(handle, val_p)	\
		REG_PIO_READ64(handle,  PFC_TCAM_KEY1, val_p)
#define	READ_TCAM_REG_MASK0(handle, val_p)	\
		REG_PIO_READ64(handle,  PFC_TCAM_MASK0, val_p)
#define	READ_TCAM_REG_MASK1(handle, val_p)	\
		REG_PIO_READ64(handle,  PFC_TCAM_MASK1, val_p)

typedef union _hxge_tcam_res_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t padding:32;
		uint32_t padding_l:2;
		uint32_t reserved:15;
		uint32_t parity:1;
		uint32_t hit_count:4;
		uint32_t channel_d:2;
		uint32_t channel_c:2;
		uint32_t channel_b:2;
		uint32_t channel_a:2;
		uint32_t source_hash:1;
		uint32_t discard:1;
#else
		uint32_t discard:1;
		uint32_t source_hash:1;
		uint32_t channel_a:2;
		uint32_t channel_b:2;
		uint32_t channel_c:2;
		uint32_t channel_d:2;
		uint32_t hit_count:4;
		uint32_t parity:1;
		uint32_t reserved:15;
		uint32_t padding_l:2;
		uint32_t padding:32;
#endif
	} bits;
} hxge_tcam_res_t, *p_hxge_tcam_res_t;

typedef struct tcam_reg {
#if defined(_BIG_ENDIAN)
	uint64_t	reg1;		/* 99:64 */
	uint64_t	reg0;		/* 63:0 */
#else
	uint64_t	reg0;		/* 63:0 */
	uint64_t	reg1;		/* 99:64 */
#endif
} hxge_tcam_reg_t;

typedef struct hxge_tcam_ipv4_S {
#if defined(_BIG_ENDIAN)
	uint32_t	class_code:4;   /* 99:96 */
	uint32_t	class_code_l:1;   /* 95:95 */
	uint32_t	blade_id:4;	/* 94:91 */
	uint32_t	rsrvd2:2;	/* 90:89 */
	uint32_t	noport:1;	/* 88 */
	uint32_t	protocol:8;	/* 87:80 */
	uint32_t	l4_hdr:16;	/* 79:64 */
	uint32_t	l4_hdr_l:16;	/* 63:48 */
	uint32_t	rsrvd:16;	/* 47:32 */
	uint32_t	ip_daddr;	/* 31:0 */
#else
	uint32_t	ip_daddr;	/* 31:0 */
	uint32_t	rsrvd:16;	/* 47:32 */
	uint32_t	l4_hdr_l:16;	/* 63:48 */
	uint32_t	l4_hdr:16;	/* 79:64 */
	uint32_t	protocol:8;	/* 87:80 */
	uint32_t	noport:1;	/* 88 */
	uint32_t	rsrvd2:2;	/* 90:89 */
	uint32_t	blade_id:4;	/* 94:91 */
	uint32_t	class_code_l:1;   /* 95:95 */
	uint32_t	class_code:4;   /* 99:96 */
#endif
} hxge_tcam_ipv4_t;

typedef struct hxge_tcam_ipv6_S {
#if defined(_BIG_ENDIAN)
	uint32_t	class_code:4;   /* 99:96 */
	uint32_t	class_code_l:1;   /* 95:95 */
	uint32_t	blade_id:4;	/* 94:91 */
	uint32_t	rsrvd2:3;	/* 90:88 */
	uint32_t	protocol:8;	/* 87:80 */
	uint32_t	l4_hdr:16;	/* 79:64 */
	uint32_t	l4_hdr_l:16;	/* 63:48 */
	uint32_t	rsrvd:16;	/* 47:32 */
	uint32_t	rsrvd_l:32;	/* 31:0 */
#else
	uint32_t	rsrvd_l:32;	/* 31:0 */
	uint32_t	rsrvd:16;	/* 47:32 */
	uint32_t	l4_hdr_l:16;	/* 63:48 */
	uint32_t	l4_hdr:16;	/* 79:64 */
	uint32_t	protocol:8;	/* 87:80 */
	uint32_t	rsrvd2:3;	/* 90:88 */
	uint32_t	blade_id:4;	/* 94:91 */
	uint32_t	class_code_l:1;   /* 95:95 */
	uint32_t	class_code:4;   /* 99:96 */
#endif
} hxge_tcam_ipv6_t;

typedef struct hxge_tcam_enet_S {
#if defined(_BIG_ENDIAN)
	uint8_t		class_code:4;   /* 99:96 */
	uint8_t		class_code_l:1; /* 95:95 */
	uint8_t		blade_id:4;	/* 94:91 */
	uint8_t		rsrvd:3;	/* 90:88 */
	uint8_t		eframe[11];	/* 87:0 */
#else
	uint8_t		eframe[11];	/* 87:0 */
	uint8_t		rsrvd:3;	/* 90:88 */
	uint8_t		blade_id:4;	/* 94:91 */
	uint8_t		class_code_l:1; /* 95:95 */
	uint8_t		class_code:4;   /* 99:96 */
#endif
} hxge_tcam_ether_t;

typedef struct hxge_tcam_spread_S {
#if defined(_BIG_ENDIAN)
	uint32_t	unused:28;	/* 127:100 */
	uint32_t	class_code:4;   /* 99:96 */
	uint32_t	class_code_l:1; /* 95:95 */
	uint32_t	blade_id:4;	/* 94:91 */
	uint32_t	wild1:27;	/* 90:64 */
	uint32_t	wild;		/* 63:32 */
	uint32_t	wild_l;		/* 31:0 */
#else
	uint32_t	wild_l;		/* 31:0 */
	uint32_t	wild;		/* 63:32 */
	uint32_t	wild1:27;	/* 90:64 */
	uint32_t	blade_id:4;	/* 94:91 */
	uint32_t	class_code_l:1; /* 95:95 */
	uint32_t	class_code:4;   /* 99:96 */
	uint32_t	unused:28;	/* 127:100 */
#endif
} hxge_tcam_spread_t;

typedef struct hxge_tcam_entry_S {
	union _hxge_tcam_entry {
		hxge_tcam_ipv4_t	ipv4;
		hxge_tcam_ipv6_t	ipv6;
		hxge_tcam_ether_t	enet;
		hxge_tcam_reg_t		regs;
		hxge_tcam_spread_t	spread;
	} key, mask;
	hxge_tcam_res_t			match_action;
	uint16_t			ether_type;
} hxge_tcam_entry_t;

#define	key_reg0		key.regs.reg0
#define	key_reg1		key.regs.reg1
#define	mask_reg0		mask.regs.reg0
#define	mask_reg1		mask.regs.reg1

#define	key0			key.regs.reg0
#define	key1			key.regs.reg1
#define	mask0			mask.regs.reg0
#define	mask1			mask.regs.reg1

#define	ip4_class_key		key.ipv4.class_code
#define	ip4_class_key_l		key.ipv4.class_code_l
#define	ip4_blade_id_key	key.ipv4.blade_id
#define	ip4_noport_key		key.ipv4.noport
#define	ip4_proto_key		key.ipv4.protocol
#define	ip4_l4_hdr_key		key.ipv4.l4_hdr
#define	ip4_l4_hdr_key_l	key.ipv4.l4_hdr_l
#define	ip4_dest_key		key.ipv4.ip_daddr

#define	ip4_class_mask		mask.ipv4.class_code
#define	ip4_class_mask_l	mask.ipv4.class_code_l
#define	ip4_blade_id_mask	mask.ipv4.blade_id
#define	ip4_noport_mask		mask.ipv4.noport
#define	ip4_proto_mask		mask.ipv4.protocol
#define	ip4_l4_hdr_mask		mask.ipv4.l4_hdr
#define	ip4_l4_hdr_mask_l	mask.ipv4.l4_hdr_l
#define	ip4_dest_mask		mask.ipv4.ip_daddr

#define	ip6_class_key		key.ipv6.class_code
#define	ip6_class_key_l		key.ipv6.class_code_l
#define	ip6_blade_id_key	key.ipv6.blade_id
#define	ip6_proto_key		key.ipv6.protocol
#define	ip6_l4_hdr_key		key.ipv6.l4_hdr
#define	ip6_l4_hdr_key_l	key.ipv6.l4_hdr_l

#define	ip6_class_mask		mask.ipv6.class_code
#define	ip6_class_mask_l	mask.ipv6.class_code_l
#define	ip6_blade_id_mask	mask.ipv6.blade_id
#define	ip6_proto_mask		mask.ipv6.protocol
#define	ip6_l4_hdr_mask		mask.ipv6.l4_hdr
#define	ip6_l4_hdr_mask_l	mask.ipv6.l4_hdr_l

#define	ether_class_key		key.enet.class_code
#define	ether_class_key_l	key.enet.class_code_l
#define	ether_blade_id_key	key.enet.blade_id
#define	ether_ethframe_key	key.enet.eframe

#define	ether_class_mask	mask.enet.class_code
#define	ether_class_mask_l	mask.enet.class_code_l
#define	ether_blade_id_mask	mask.enet.blade_id
#define	ether_ethframe_mask	mask.enet.eframe

typedef	struct _pfc_errlog {
	uint32_t		tcp_ctrl_drop;    /* pfc_drop_log */
	uint32_t		l2_addr_drop;
	uint32_t		class_code_drop;
	uint32_t		tcam_drop;
	uint32_t		vlan_drop;

	uint32_t		vlan_par_err_log; /* pfc_vlan_par_err_log */
	uint32_t		tcam_par_err_log; /* pfc_tcam_par_err_log */
} pfc_errlog_t, *p_pfc_errlog_t;

typedef struct _pfc_stats {
	uint32_t		pkt_drop;	/* pfc_int_status */
	uint32_t		tcam_parity_err;
	uint32_t		vlan_parity_err;

	uint32_t		bad_cs_count;	/* pfc_bad_cs_counter */
	uint32_t		drop_count;	/* pfc_drop_counter */
	pfc_errlog_t		errlog;
} hxge_pfc_stats_t, *p_hxge_pfc_stats_t;

typedef enum pfc_tcam_class {
	TCAM_CLASS_INVALID = 0,
	TCAM_CLASS_DUMMY = 1,
	TCAM_CLASS_ETYPE_1 = 2,
	TCAM_CLASS_ETYPE_2,
	TCAM_CLASS_RESERVED_4,
	TCAM_CLASS_RESERVED_5,
	TCAM_CLASS_RESERVED_6,
	TCAM_CLASS_RESERVED_7,
	TCAM_CLASS_TCP_IPV4,
	TCAM_CLASS_UDP_IPV4,
	TCAM_CLASS_AH_ESP_IPV4,
	TCAM_CLASS_SCTP_IPV4,
	TCAM_CLASS_TCP_IPV6,
	TCAM_CLASS_UDP_IPV6,
	TCAM_CLASS_AH_ESP_IPV6,
	TCAM_CLASS_SCTP_IPV6,
	TCAM_CLASS_ARP,
	TCAM_CLASS_RARP,
	TCAM_CLASS_DUMMY_12,
	TCAM_CLASS_DUMMY_13,
	TCAM_CLASS_DUMMY_14,
	TCAM_CLASS_DUMMY_15,
	TCAM_CLASS_MAX
} tcam_class_t;

typedef struct _tcam_key_cfg_t {
	boolean_t	lookup_enable;
	boolean_t	discard;
} tcam_key_cfg_t;

typedef struct _hash_filter_t {
	uint_t		hash_ref_cnt;
	uint16_t	hash_filter_regs[NMCFILTER_REGS];
	uint32_t	hash_bit_ref_cnt[NMCFILTER_BITS];
} hash_filter_t, *p_hash_filter_t;

#define	HXGE_ETHER_FLOWS	(FLOW_ETHER_DHOST | FLOW_ETHER_SHOST | \
					FLOW_ETHER_TYPE)
#define	HXGE_VLAN_FLOWS		(FLOW_ETHER_TPID | FLOW_ETHER_TCI)
#define	HXGE_ETHERNET_FLOWS	(HXGE_ETHER_FLOWS | HXGE_VLAN_FLOWS)
#define	HXGE_PORT_FLOWS		(FLOW_ULP_PORT_REMOTE | FLOW_ULP_PORT_LOCAL)
#define	HXGE_ADDR_FLOWS		(FLOW_IP_REMOTE | FLOW_IP_LOCAL)
#define	HXGE_IP_FLOWS		(FLOW_IP_VERSION | FLOW_IP_PROTOCOL | \
					HXGE_PORT_FLOWS | HXGE_ADDR_FLOWS)
#define	HXGE_SUPPORTED_FLOWS	(HXGE_ETHERNET_FLOWS | HXGE_IP_FLOWS)

#define	CLS_CODE_MASK		0x1f
#define	BLADE_ID_MASK		0xf
#define	PID_MASK		0xff
#define	IP_PORT_MASK		0xffff

#define	IP_ADDR_SA_MASK		0xFFFFFFFF
#define	IP_ADDR_DA_MASK		IP_ADDR_SA_MASK
#define	L4PT_SPI_MASK		IP_ADDR_SA_MASK

#define	BLADE_ID_OFFSET		127	/* Last entry in HCR_REG */

#ifdef __cplusplus
}
#endif

#endif /* !_HXGE_PFC_H */
