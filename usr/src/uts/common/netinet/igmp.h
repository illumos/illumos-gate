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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_NETINET_IGMP_H
#define	_NETINET_IGMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Internet Group Management Protocol (IGMP) definitions.
 *
 * Written by Steve Deering, Stanford, May 1988.
 * Modified by Rosen Sharma, Stanford, Aug 1994
 * Modified by Bill Fenner, Xerox PARC, April 1995
 *
 * MULTICAST 3.5.1.1
 */

/*
 * IGMP packet format.
 */
struct igmp {
	uchar_t		igmp_type;	/* version & type of IGMP message  */
	uchar_t		igmp_code;	/* code for routing sub-msgs	   */
	ushort_t	igmp_cksum;	/* IP-style checksum		   */
	struct in_addr	igmp_group;	/* group address being reported	   */
};					/*  (zero for queries)		   */

/* IGMPv3 Membership Report common header */
struct igmp3r {
	uchar_t		igmp3r_type;	/* version & type of IGMP message  */
	uchar_t		igmp3r_code;	/* code for routing sub-msgs	   */
	ushort_t	igmp3r_cksum;	/* IP-style checksum		   */
	ushort_t	igmp3r_res;	/* Reserved			   */
	ushort_t	igmp3r_numrec;	/* Number of group records	   */
};

/* IGMPv3 Group Record header */
struct grphdr {
	uchar_t		grphdr_type;	/* type of record		   */
	uchar_t		grphdr_auxlen;	/* auxiliary data length	   */
	ushort_t	grphdr_numsrc;	/* number of sources		   */
	struct in_addr	grphdr_group;	/* group address being reported	   */
};

/* IGMPv3 Membership Query header */
struct igmp3q {
	uchar_t		igmp3q_type;	/* type of IGMP message		   */
	uchar_t		igmp3q_mxrt;	/* maximum response time	   */
	ushort_t	igmp3q_cksum;	/* IP-style checksum		   */
	struct in_addr	igmp3q_group;	/* group address being queried	   */
	ushort_t	igmp3q_res;	/* reserved			   */
	ushort_t	igmp3q_numsrc;	/* number of sources		   */
};

#ifdef _KERNEL
typedef struct igmp_s {
	uint8_t		igmp_type;	/* version & type of IGMP message  */
	uint8_t		igmp_code;	/* code for routing sub-msgs	   */
	uint8_t		igmp_cksum[2];	/* IP-style checksum		   */
	uint8_t		igmp_group[4];	/* group address being reported	   */
} igmp_t;				/*  (zero for queries)		   */

/* Aligned igmp header */
typedef struct igmpa_s {
	uint8_t		igmpa_type;	/* version & type of IGMP message  */
	uint8_t		igmpa_code;	/* code for routing sub-msgs	   */
	uint16_t	igmpa_cksum;	/* IP-style checksum		   */
	ipaddr_t	igmpa_group;	/* group address being reported	   */
} igmpa_t;				/*  (zero for queries)		   */

/* Aligned IGMPv3 Membership Report common header */
typedef struct igmp3ra_s {
	uint8_t		igmp3ra_type;	/* version & type of IGMP message  */
	uint8_t		igmp3ra_res;	/* Reserved			   */
	uint16_t	igmp3ra_cksum;	/* IP-style checksum		   */
	uint16_t	igmp3ra_res1;	/* Reserved			   */
	uint16_t	igmp3ra_numrec;	/* Number of group records	   */
} igmp3ra_t;

/* Aligned IGMPv3 Group Record header */
typedef struct grphdra_s {
	uint8_t		grphdra_type;	/* type of record		   */
	uint8_t		grphdra_auxlen;	/* auxiliary data length	   */
	uint16_t	grphdra_numsrc;	/* number of sources		   */
	ipaddr_t	grphdra_group;	/* group addrss being reported	   */
} grphdra_t;

/* Aligned IGMpv3 Membership Query header */
typedef struct igmp3qa_s {
	uint8_t		igmp3qa_type;	/* type of IGMP message		   */
	uint8_t		igmp3qa_mxrc;	/* maximum response code	   */
	uint16_t	igmp3qa_cksum;	/* IP-style checksum		   */
	ipaddr_t	igmp3qa_group;	/* group address being queried	   */
	uint8_t		igmp3qa_sqrv;	/* S Flag, Q's Robustness Variable */
	uint8_t		igmp3qa_qqic;	/* Querier's Query Interval Code   */
	uint16_t	igmp3qa_numsrc;	/* number of sources		   */
} igmp3qa_t;

#endif	/* _KERNEL */


#define	IGMP_MINLEN			8
#define	IGMP_V3_QUERY_MINLEN		12


/*
 * Message types, including version number.
 */

#define	IGMP_MEMBERSHIP_QUERY		0x11	/* membership query    */
#define	IGMP_V1_MEMBERSHIP_REPORT	0x12	/* Vers.1 membership report */
#define	IGMP_V2_MEMBERSHIP_REPORT	0x16	/* Vers.2 membership report */
#define	IGMP_V3_MEMBERSHIP_REPORT	0x22	/* Vers.3 membership report */
#define	IGMP_V2_LEAVE_GROUP		0x17	/* Leave-group message	    */
#define	IGMP_DVMRP			0x13	/* DVMRP routing message    */
#define	IGMP_PIM			0x14	/* PIM routing message	    */

#define	IGMP_MTRACE_RESP		0x1e  	/* traceroute resp to sender */
#define	IGMP_MTRACE			0x1f	/* mcast traceroute messages */

#define	IGMP_MAX_HOST_REPORT_DELAY	10	/* max delay for response to */
						/* query (in seconds)	*/
						/* according to RFC1112 */

#define	IGMP_V3_MAXRT_FPMIN		0x80	/* max resp code fp format */
#define	IGMP_V3_MAXRT_MANT_MASK		0x0f
#define	IGMP_V3_MAXRT_EXP_MASK		0x70

#define	IGMP_V3_SFLAG_MASK		0x8	/* mask off s part of sqrv */
#define	IGMP_V3_RV_MASK			0x7	/* mask off qrv part of sqrv */

#define	IGMP_V3_QQI_FPMIN		0x80	/* qqi code fp format */
#define	IGMP_V3_QQI_MANT_MASK		0x0f
#define	IGMP_V3_QQI_EXP_MASK		0x70

/*
 * IGMPv3/MLDv2-specific definitions
 */
/*
 * Group Record Types.  The values of these enums match the Record Type
 * field values defined in RFCs 3376 and 3810 for IGMPv3 and MLDv2 reports.
 */
typedef enum {
	MODE_IS_INCLUDE = 1,
	MODE_IS_EXCLUDE,
	CHANGE_TO_INCLUDE,
	CHANGE_TO_EXCLUDE,
	ALLOW_NEW_SOURCES,
	BLOCK_OLD_SOURCES
} mcast_record_t;

/* Router Alert Option */
#define	RTRALERT_LEN			4
#define	RTRALERT_LEN_IN_WORDS		1

/*
 * The following four defininitions are for backwards compatibility.
 * They should be removed as soon as all applications are updated to
 * use the new constant names.
 */
#define	IGMP_HOST_MEMBERSHIP_QUERY	IGMP_MEMBERSHIP_QUERY
#define	IGMP_HOST_MEMBERSHIP_REPORT	IGMP_V1_MEMBERSHIP_REPORT
#define	IGMP_HOST_NEW_MEMBERSHIP_REPORT	IGMP_V2_MEMBERSHIP_REPORT
#define	IGMP_HOST_LEAVE_MESSAGE		IGMP_V2_LEAVE_GROUP

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_IGMP_H */
