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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NDPD_H
#define	_NDPD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	NDPD_SNMP_SOCKET	"/var/run/in.ndpd_mib"
#define	NDPD_SNMP_INFO_REQ	1
#define	NDPD_SNMP_INFO_RESPONSE	2
#define	NDPD_PHYINT_INFO	3
#define	NDPD_PREFIX_INFO	4
#define	NDPD_ROUTER_INFO	5

#define	NDPD_SNMP_INFO_VER	1
#define	NDPD_PHYINT_INFO_VER    1
#define	NDPD_PREFIX_INFO_VER    1
#define	NDPD_ROUTER_INFO_VER	1

/*
 * Data structures used to handle configuration variables set in ndpd.conf.
 * cf_notdefault is set for variables explicitly set in ndpd.conf.
 */
struct confvar {
	uint_t		cf_value;
	boolean_t	cf_notdefault;
};

extern struct confvar ifdefaults[];

/*
 * Interfaces configuration variable indicies
 */
#define	I_DupAddrDetectTransmits	0	/* From RFC 2462 */
#define	I_AdvSendAdvertisements		1
#define	I_MaxRtrAdvInterval		2	/* In seconds */
#define	I_MinRtrAdvInterval		3	/* In seconds */
#define	I_AdvManagedFlag		4
#define	I_AdvOtherConfigFlag		5
#define	I_AdvLinkMTU			6
#define	I_AdvReachableTime		7	/* In milliseconds */
#define	I_AdvRetransTimer		8	/* In milliseconds */
#define	I_AdvCurHopLimit		9
#define	I_AdvDefaultLifetime		10	/* In seconds */
#define	I_StatelessAddrConf		11
#define	I_TmpAddrsEnabled		12	/* From RFC 3041 */
#define	I_TmpValidLifetime		13	/* In seconds */
#define	I_TmpPreferredLifetime		14	/* In seconds */
#define	I_TmpRegenAdvance		15	/* In seconds */
#define	I_TmpMaxDesyncFactor		16	/* In seconds */
#define	I_StatefulAddrConf		17
#define	I_IFSIZE			18	/* # of variables */

typedef struct ndpd_info_s {
	uint_t	info_type;
	uint_t	info_version;
	uint_t	info_num_of_phyints;
} ndpd_info_t;

typedef struct ndpd_prefix_info_s {
	uint_t		prefix_info_type;
	uint_t		prefix_info_version;
	struct in6_addr prefix_prefix;		/* Used to indentify prefix */
	uint_t		prefix_len;		/* Num bits valid */
	uint_t		prefix_flags;		/* IFF_ flags */
	uint_t		prefix_phyint_index;
	uint_t		prefix_ValidLifetime;	 /* In ms w/ 2 hour rule */
	uint_t		prefix_PreferredLifetime; /* In millseconds */
	uint_t		prefix_OnLinkLifetime;	/* ms valid w/o 2 hour rule */
	boolean_t	prefix_OnLinkFlag;
	boolean_t	prefix_AutonomousFlag;
} ndpd_prefix_info_t;

typedef struct ndpd_router_info_s {
	uint_t		router_info_type;
	uint_t		router_info_version;
	struct in6_addr	router_address;		/* Used to identify router */
	uint_t		router_lifetime;	/* In milliseconds */
	uint_t		router_phyint_index;
} ndpd_router_info_t;


typedef struct ndpd_phyint_info_s {
	uint_t		phyint_info_type;
	uint_t		phyint_info_version;
	int		phyint_index;
	struct confvar 	phyint_config[I_IFSIZE];
#define	phyint_DupAddrDetectTransmits 	\
				phyint_config[I_DupAddrDetectTransmits].cf_value
#define	phyint_AdvSendAdvertisements 	\
				phyint_config[I_AdvSendAdvertisements].cf_value
#define	phyint_MaxRtrAdvInterval	\
				phyint_config[I_MaxRtrAdvInterval].cf_value
#define	phyint_MinRtrAdvInterval	\
				phyint_config[I_MinRtrAdvInterval].cf_value
#define	phyint_AdvManagedFlag	phyint_config[I_AdvManagedFlag].cf_value
#define	phyint_AdvOtherConfigFlag	\
				phyint_config[I_AdvOtherConfigFlag].cf_value
#define	phyint_AdvLinkMTU	phyint_config[I_AdvLinkMTU].cf_value
#define	phyint_AdvReachableTime	phyint_config[I_AdvReachableTime].cf_value
#define	phyint_AdvRetransTimer	phyint_config[I_AdvRetransTimer].cf_value
#define	phyint_AdvCurHopLimit	phyint_config[I_AdvCurHopLimit].cf_value
#define	phyint_AdvDefaultLifetime	\
				phyint_config[I_AdvDefaultLifetime].cf_value
#define	phyint_StatelessAddrConf	\
				phyint_config[I_StatelessAddrConf].cf_value
#define	phyint_TmpAddrsEnabled	phyint_config[I_TmpAddrsEnabled].cf_value
#define	phyint_TmpValidLifetime	phyint_config[I_TmpValidLifetime].cf_value
#define	phyint_TmpPreferredLifetime	\
				phyint_config[I_TmpPreferredLifetime].cf_value
#define	phyint_TmpRegenAdvance	phyint_config[I_TmpRegenAdvance].cf_value
#define	phyint_TmpMaxDesyncFactor	\
				phyint_config[I_TmpMaxDesyncFactor].cf_value
#define	phyint_StatefulAddrConf	\
				phyint_config[I_StatefulAddrConf].cf_value
	uint_t 		phyint_num_of_prefixes;
	uint_t 		phyint_num_of_routers;
} ndpd_phyint_info_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _NDPD_H */
