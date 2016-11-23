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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2015 Garrett D'Amore <garrett@damore.org>
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_SYS_MAC_ETHER_H
#define	_SYS_MAC_ETHER_H

/*
 * Ethernet MAC Plugin
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#define	MAC_PLUGIN_IDENT_ETHER	"mac_ether"

/*
 * Do not reorder, and add only to the end of this list.
 */
enum ether_stat {
	/* RFC 1643 stats */
	ETHER_STAT_ALIGN_ERRORS = MACTYPE_STAT_MIN,
	ETHER_STAT_FCS_ERRORS,
	ETHER_STAT_FIRST_COLLISIONS,
	ETHER_STAT_MULTI_COLLISIONS,
	ETHER_STAT_SQE_ERRORS,
	ETHER_STAT_DEFER_XMTS,
	ETHER_STAT_TX_LATE_COLLISIONS,
	ETHER_STAT_EX_COLLISIONS,
	ETHER_STAT_MACXMT_ERRORS,
	ETHER_STAT_CARRIER_ERRORS,
	ETHER_STAT_TOOLONG_ERRORS,
	ETHER_STAT_MACRCV_ERRORS,

	/* MII/GMII stats */
	ETHER_STAT_XCVR_ADDR,
	ETHER_STAT_XCVR_ID,
	ETHER_STAT_XCVR_INUSE,
	ETHER_STAT_CAP_1000FDX,
	ETHER_STAT_CAP_1000HDX,
	ETHER_STAT_CAP_100FDX,
	ETHER_STAT_CAP_100HDX,
	ETHER_STAT_CAP_10FDX,
	ETHER_STAT_CAP_10HDX,
	ETHER_STAT_CAP_ASMPAUSE,
	ETHER_STAT_CAP_PAUSE,
	ETHER_STAT_CAP_AUTONEG,
	ETHER_STAT_ADV_CAP_1000FDX,
	ETHER_STAT_ADV_CAP_1000HDX,
	ETHER_STAT_ADV_CAP_100FDX,
	ETHER_STAT_ADV_CAP_100HDX,
	ETHER_STAT_ADV_CAP_10FDX,
	ETHER_STAT_ADV_CAP_10HDX,
	ETHER_STAT_ADV_CAP_ASMPAUSE,
	ETHER_STAT_ADV_CAP_PAUSE,
	ETHER_STAT_ADV_CAP_AUTONEG,
	ETHER_STAT_LP_CAP_1000FDX,
	ETHER_STAT_LP_CAP_1000HDX,
	ETHER_STAT_LP_CAP_100FDX,
	ETHER_STAT_LP_CAP_100HDX,
	ETHER_STAT_LP_CAP_10FDX,
	ETHER_STAT_LP_CAP_10HDX,
	ETHER_STAT_LP_CAP_ASMPAUSE,
	ETHER_STAT_LP_CAP_PAUSE,
	ETHER_STAT_LP_CAP_AUTONEG,
	ETHER_STAT_LINK_ASMPAUSE,
	ETHER_STAT_LINK_PAUSE,
	ETHER_STAT_LINK_AUTONEG,
	ETHER_STAT_LINK_DUPLEX,

	ETHER_STAT_TOOSHORT_ERRORS,
	ETHER_STAT_CAP_REMFAULT,
	ETHER_STAT_ADV_REMFAULT,
	ETHER_STAT_LP_REMFAULT,

	ETHER_STAT_JABBER_ERRORS,
	ETHER_STAT_CAP_100T4,
	ETHER_STAT_ADV_CAP_100T4,
	ETHER_STAT_LP_CAP_100T4,

	ETHER_STAT_CAP_10GFDX,
	ETHER_STAT_ADV_CAP_10GFDX,
	ETHER_STAT_LP_CAP_10GFDX,

	ETHER_STAT_CAP_40GFDX,
	ETHER_STAT_ADV_CAP_40GFDX,
	ETHER_STAT_LP_CAP_40GFDX,

	ETHER_STAT_CAP_100GFDX,
	ETHER_STAT_ADV_CAP_100GFDX,
	ETHER_STAT_LP_CAP_100GFDX,

	ETHER_STAT_CAP_2500FDX,
	ETHER_STAT_ADV_CAP_2500FDX,
	ETHER_STAT_LP_CAP_2500FDX,

	ETHER_STAT_CAP_5000FDX,
	ETHER_STAT_ADV_CAP_5000FDX,
	ETHER_STAT_LP_CAP_5000FDX,

	ETHER_STAT_CAP_25GFDX,
	ETHER_STAT_ADV_CAP_25GFDX,
	ETHER_STAT_LP_CAP_25GFDX,

	ETHER_STAT_CAP_50GFDX,
	ETHER_STAT_ADV_CAP_50GFDX,
	ETHER_STAT_LP_CAP_50GFDX,
};

#define	ETHER_NSTAT	\
	(ETHER_STAT_LP_CAP_50GFDX - ETHER_STAT_ALIGN_ERRORS + 1)

#define	ETHER_STAT_ISACOUNTER(_ether_stat)				\
	    ((_ether_stat) == ETHER_STAT_ALIGN_ERRORS ||		\
		(_ether_stat) == ETHER_STAT_FCS_ERRORS ||		\
		(_ether_stat) == ETHER_STAT_FIRST_COLLISIONS ||		\
		(_ether_stat) == ETHER_STAT_MULTI_COLLISIONS ||		\
		(_ether_stat) == ETHER_STAT_SQE_ERRORS ||		\
		(_ether_stat) == ETHER_STAT_DEFER_XMTS ||		\
		(_ether_stat) == ETHER_STAT_TX_LATE_COLLISIONS ||	\
		(_ether_stat) == ETHER_STAT_EX_COLLISIONS ||		\
		(_ether_stat) == ETHER_STAT_MACXMT_ERRORS ||		\
		(_ether_stat) == ETHER_STAT_CARRIER_ERRORS ||		\
		(_ether_stat) == ETHER_STAT_TOOLONG_ERRORS ||		\
		(_ether_stat) == ETHER_STAT_TOOSHORT_ERRORS ||		\
		(_ether_stat) == ETHER_STAT_JABBER_ERRORS ||		\
		(_ether_stat) == ETHER_STAT_MACRCV_ERRORS)

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MAC_ETHER_H */
