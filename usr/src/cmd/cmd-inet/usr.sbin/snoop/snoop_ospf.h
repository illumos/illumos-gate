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

#ifndef _OSPF_H
#define	_OSPF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for parsing OSPF packets (RFC 2328 and RFC 2740)
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	OSPF_TYPE_UMD	0	/* UMD's special monitoring packets */
#define	OSPF_TYPE_HELLO	1	/* Hello */
#define	OSPF_TYPE_DB	2	/* Database Description */
#define	OSPF_TYPE_LSR	3	/* Link State Request */
#define	OSPF_TYPE_LSU	4	/* Link State Update */
#define	OSPF_TYPE_LSA	5	/* Link State Ack */
#define	OSPF_TYPE_MAX	6

extern char *ospf_types[];
struct bits {
	uint32_t bit;
	const char *str;
};
char *ospf_print_bits(const struct bits *, uchar_t);
char *ospf_print_lsa_age(long);

/* Options *_options	*/
#define	OSPF_OPTION_T	0x01	/* RFC 2328 T bit: TOS support	*/
#define	OSPF_OPTION_E	0x02	/* E bit: External routes advertised	*/
#define	OSPF_OPTION_MC	0x04	/* MC bit: Multicast capable */
#define	OSPF_OPTION_N	0x08	/* N bit: For type-7 LSA */
#define	OSPF_OPTION_R	0x10	/* R bit: Router bit */
#define	OSPF_OPTION_DC	0x20	/* DC bit: Demand circuits */

#define	OSPF_OPTION_V6	0x01	/* RFC 2740 V6 bit */

/* ospf_authtype	*/
#define	OSPF_AUTH_NONE		0	/* No auth-data */
#define	OSPF_AUTH_SIMPLE	1	/* Simple password */
#define	OSPF_AUTH_MD5		2	/* MD5 authentication */
#define	OSPF_AUTH_MD5_LEN	16	/* length of MD5 authentication */

#define	OSPF_AUTH_TYPE_MAX	3

/* db_flags	*/
#define	OSPF_DB_INIT		0x04	/* "I"  */
#define	OSPF_DB_MORE		0x02 	/* "M"  */
#define	OSPF_DB_MASTER		0x01	/* "MS" */


/* ls_type	*/
#define	LS_TYPE_ROUTER		1   /* router link */
#define	LS_TYPE_NETWORK		2   /* network link */
#define	LS_TYPE_SUM_IP		3   /* summary link */
#define	LS_TYPE_SUM_ABR		4   /* summary area link */
#define	LS_TYPE_ASE		5   /* ASE  */
#define	LS_TYPE_GROUP		6   /* Group membership (multicast */
				    /* extensions 23 July 1991) */
#define	LS_TYPE_TYPE7		7   /* Type 7 LSA */
#define	LS_TYPE_LINK		8   /* Link LSA */
#define	LS_TYPE_INTRA_AP	9   /* Intra-Area-Prefix */
#define	LS_TYPE_MAX		10
#define	LS_TYPE_MASK		0x1fff

#define	LS_TYPE_INTER_AP	3   /* RFC 2740 Inter-Area-Prefix */
#define	LS_TYPE_INTER_AR	4   /* RFC 2740 Inter-Area-Router */

#define	LS6_SCOPE_LINKLOCAL	0x0000
#define	LS6_SCOPE_AREA		0x2000
#define	LS6_SCOPE_AS		0x4000
#define	LS6_SCOPE_MASK		0x6000

/* rla_link.link_type	*/
#define	RLA_TYPE_ROUTER		1   /* point-to-point to another router	*/
#define	RLA_TYPE_TRANSIT	2   /* connection to transit network	*/
#define	RLA_TYPE_STUB		3   /* connection to stub network	*/
#define	RLA_TYPE_VIRTUAL	4   /* virtual link			*/

/* rla_flags	*/
#define	RLA_FLAG_B	0x01
#define	RLA_FLAG_E	0x02
#define	RLA_FLAG_V	0x04
#define	RLA_FLAG_W	0x08


/* sla_tosmetric breakdown	*/
#define	SLA_MASK_TOS		0x7f000000
#define	SLA_MASK_METRIC		0x00ffffff
#define	SLA_SHIFT_TOS		24

/* asla_tosmetric breakdown	*/
#define	ASLA_FLAG_EXTERNAL	0x80000000
#define	ASLA_MASK_TOS		0x7f000000
#define	ASLA_SHIFT_TOS		24
#define	ASLA_MASK_METRIC	0x00ffffff

/* multicast vertex type 	*/
#define	MCLA_VERTEX_ROUTER	1
#define	MCLA_VERTEX_NETWORK	2

/* link state advertisement header */
struct lsa_hdr {
	ushort_t ls_age;
	uchar_t ls_options;
	uchar_t ls_type;
	struct in_addr ls_stateid;
	struct in_addr ls_router;
	uint32_t ls_seq;
	ushort_t ls_chksum;
	ushort_t ls_length;
};

/* link state advertisement */
struct lsa {
	struct lsa_hdr ls_hdr;

	/* Link state types */
	union {
		/* Router links advertisements */
		struct {
			uchar_t rla_flags;
			uchar_t rla_zero[1];
			ushort_t rla_count;
			struct rlalink {
				struct in_addr link_id;
				struct in_addr link_data;
				uchar_t link_type;
				uchar_t link_toscount;
				ushort_t link_tos0metric;
			} rla_link[1];		/* may repeat	*/
		} un_rla;

		/* Network links advertisements */
		struct {
			struct in_addr nla_mask;
			struct in_addr nla_router[1];	/* may repeat	*/
		} un_nla;

		/* Summary links advertisements */
		struct {
			struct in_addr sla_mask;
			uint32_t sla_tosmetric[1];	/* may repeat	*/
		} un_sla;

		/* AS external links advertisements */
		struct {
			struct in_addr asla_mask;
			struct aslametric {
				uint32_t asla_tosmetric;
				struct in_addr asla_forward;
				struct in_addr asla_tag;
			} asla_metric[1];		/* may repeat	*/
		} un_asla;

		/* Multicast group membership */
		struct mcla {
			uint32_t mcla_vtype;
			struct in_addr mcla_vid;
		} un_mcla[1];
	} lsa_un;
};

/*
 * TOS metric struct (will be 0 or more in router links update)
 */
struct tos_metric {
	uchar_t tos_type;
	uchar_t tos_zero;
	ushort_t tos_metric;
};

/*
 * OSPF minimum header sizes
 */
#define	OSPF_AUTH_SIZE			8
#define	OSPF_MIN_HEADER_SIZE		24
#define	OSPF6_MIN_HEADER_SIZE		16
#define	OSPF_MIN_HELLO_HEADER_SIZE	20
#define	OSPF_MIN_DB_HEADER_SIZE		8
#define	OSPF6_MIN_DB_HEADER_SIZE	12
#define	OSPF_MIN_LSR_HEADER_SIZE	12
#define	OSPF_MIN_LSU_HEADER_SIZE	4

/*
 * ospf packet header
 */
struct ospfhdr {
	uchar_t ospf_version;
	uchar_t ospf_type;
	ushort_t ospf_len;
	struct in_addr ospf_routerid;
	struct in_addr ospf_areaid;
	ushort_t ospf_chksum;
	ushort_t ospf_authtype;
	uchar_t ospf_authdata[OSPF_AUTH_SIZE];
	union {

		/* Hello packet */
		struct {
			struct in_addr hello_mask;
			ushort_t hello_helloint;
			uchar_t hello_options;
			uchar_t hello_priority;
			uint32_t hello_deadint;
			struct in_addr hello_dr;
			struct in_addr hello_bdr;
			struct in_addr hello_neighbor[1]; /* may repeat	*/
		} un_hello;

		/* Database Description packet */
		struct {
			uchar_t db_zero[2];
			uchar_t db_options;
			uchar_t db_flags;
			uint32_t db_seq;
			struct lsa_hdr db_lshdr[1];	/* may repeat */
		} un_db;

		/* Link State Request */
		struct lsr {
			uint32_t ls_type;
			struct in_addr ls_stateid;
			struct in_addr ls_router;
		} un_lsr[1];				/* may repeat */

		/* Link State Update */
		struct {
			uint32_t lsu_count;
			struct lsa lsu_lsa[1]; 		/* may repeat */
		} un_lsu;

		/* Link State Acknowledgement */
		struct {
			struct lsa_hdr lsa_lshdr[1]; 	/* may repeat */
		} un_lsa;
	} ospf_un;
};

#define	ospf_hello	ospf_un.un_hello
#define	ospf_db		ospf_un.un_db
#define	ospf_lsr	ospf_un.un_lsr
#define	ospf_lsu	ospf_un.un_lsu
#define	ospf_lsa	ospf_un.un_lsa



#ifdef __cplusplus
}
#endif

#endif /* _OSPF_H */
