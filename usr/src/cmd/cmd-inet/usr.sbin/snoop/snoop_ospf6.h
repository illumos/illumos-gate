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

#ifndef _OSPF6_H
#define	_OSPF6_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for parsing OSPF packets (RFC 2328)
 */

#ifdef __cplusplus
extern "C" {
#endif

struct lsa6_hdr {
	uint16_t ls6_age;
	uint16_t ls6_type;
	uint32_t ls6_stateid;
	uint32_t ls6_router;
	uint32_t ls6_seq;
	uint16_t ls6_chksum;
	uint16_t ls6_length;
};

struct lsa6_prefix {
	uint8_t  lsa6_plen;
	uint8_t  lsa6_popt;
	uint16_t lsa6_pmbz;
	uint8_t  lsa6_pfx[4];
};

/* link state advertisement */
struct lsa6 {
	struct lsa6_hdr ls6_hdr;

	/* Link state types */
	union {
		/* Router links advertisements */
		struct {
			union {
				uint8_t  rla_flg;
				uint32_t rla_opt;
			} un_rla_flgopt;
#define	rla6_flags	un_rla_flgopt.rla_flg
#define	rla6_options	un_rla_flgopt.rla_opt
			struct rla6link {
				uint8_t link_type;
				uint8_t link_zero[1];
				uint16_t link_metric;
				uint32_t link_ifid;
				uint32_t link_nifid;
				uint32_t link_nrtid;
			} rla_link[1];		/* may repeat	*/
		} un_rla;

		/* Network links advertisements */
		struct {
			uint32_t nla_options;
			uint32_t nla_router[1];	/* may repeat	*/
		} un_nla;

		/* Inter Area Prefix LSA */
		struct {
			uint32_t inter_ap_metric;
			struct lsa6_prefix inter_ap_prefix[1];
		} un_inter_ap;

		/* Link LSA */
		struct llsa {
			union {
				uint8_t pri;
				uint32_t opt;
			} llsa_priandopt;
#define	llsa_priority	llsa_priandopt.pri
#define	llsa_options	llsa_priandopt.opt
			struct in6_addr llsa_lladdr;
			uint32_t llsa_nprefix;
			struct lsa6_prefix llsa_prefix[1];
		} un_llsa;

		/* Intra-Area-Prefix */
		struct {
			uint16_t intra_ap_nprefix;
			uint16_t intra_ap_lstype;
			uint32_t intra_ap_lsid;
			uint32_t intra_ap_rtid;
			struct lsa6_prefix intra_ap_prefix[1];
		} un_intra_ap;
	} lsa_un;
};

struct ospf6hdr {
	uint8_t ospf6_version;
	uint8_t ospf6_type;
	uint16_t ospf6_len;
	uint32_t ospf6_routerid;
	uint32_t ospf6_areaid;
	uint16_t ospf6_chksum;
	uint8_t ospf6_instanceid;
	uint8_t ospf6_rsvd;
	union {

		/* Hello packet */
		struct {
			uint32_t hello_ifid;
			union {
				uint8_t pri;
				uint32_t opt;
			} hello_priandopt;
#define	hello6_priority	hello_priandopt.pri
#define	hello6_options	hello_priandopt.opt
			uint16_t hello_helloint;
			uint16_t hello_deadint;
			uint32_t hello_dr;
			uint32_t hello_bdr;
			uint32_t hello_neighbor[1];	/* may repeat	*/
		} un_hello;

		/* Database Description packet */
		struct {
			uint32_t db_options;
			uint16_t db_mtu;
			uint8_t db_mbz;
			uint8_t db_flags;
			uint32_t db_seq;
			struct lsa6_hdr db_lshdr[1];	/* may repeat	*/
		} un_db;

		/* Link State Request */
		struct lsr6 {
			uint16_t ls_mbz;
			uint16_t ls_type;
			uint32_t ls_stateid;
			uint32_t ls_router;
		} un_lsr[1];				/* may repeat	*/

		/* Link State Update */
		struct {
			uint32_t lsu_count;
			struct lsa6 lsu_lsa[1]; 	/* may repeat	*/
		} un_lsu;

		/* Link State Acknowledgement */
		struct {
			struct lsa6_hdr lsa_lshdr[1]; 	/* may repeat	*/
		} un_lsa;
	} ospf6_un;
};

#define	ospf6_hello	ospf6_un.un_hello
#define	ospf6_db	ospf6_un.un_db
#define	ospf6_lsr	ospf6_un.un_lsr
#define	ospf6_lsu	ospf6_un.un_lsu
#define	ospf6_lsa	ospf6_un.un_lsa

#ifdef __cplusplus
}
#endif

#endif /* _OSPF6_H */
