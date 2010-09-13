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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <npi_fflp.h>
#include <nxge_defs.h>
#include <nxge_fflp.h>
#include <nxge_flow.h>
#include <nxge_impl.h>
#include <nxge_common.h>

/*
 * Globals: tunable parameters (/etc/system or adb)
 *
 */
int nxge_tcam_class_enable = 0;
int nxge_tcam_lookup_enable = 0;
int nxge_flow_dist_enable = NXGE_CLASS_FLOW_USE_DST_PORT |
	NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_IPDST |
	NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_PROTO |
	NXGE_CLASS_FLOW_USE_PORTNUM;

/*
 * Bit mapped
 * 0x80000000:      Drop
 * 0x0000:      NO TCAM Lookup Needed
 * 0x0001:      TCAM Lookup Needed with Dest Addr (IPv6)
 * 0x0003:      TCAM Lookup Needed with SRC Addr (IPv6)
 * 0x0010:      use MAC Port
 * 0x0020:      use L2DA
 * 0x0040:      use VLAN
 * 0x0080:      use proto
 * 0x0100:      use IP src addr
 * 0x0200:      use IP dest addr
 * 0x0400:      use Src Port
 * 0x0800:      use Dest Port
 * 0x0fff:      enable all options for IPv6 (with src addr)
 * 0x0ffd:      enable all options for IPv6 (with dest addr)
 * 0x0fff:      enable all options for IPv4
 * 0x0ffd:      enable all options for IPv4
 *
 */

/*
 * the default is to distribute as function of:
 * protocol
 * ip src address
 * ip dest address
 * src port
 * dest port
 *
 * 0x0f80
 *
 */

int nxge_tcp4_class = NXGE_CLASS_FLOW_USE_DST_PORT |
	NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_IPDST |
	NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_PROTO |
	NXGE_CLASS_FLOW_USE_PORTNUM;

int nxge_udp4_class = NXGE_CLASS_FLOW_USE_DST_PORT |
	NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_IPDST |
	NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_PROTO |
	NXGE_CLASS_FLOW_USE_PORTNUM;

int nxge_ah4_class = NXGE_CLASS_FLOW_USE_DST_PORT |
	NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_IPDST |
	NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_PROTO |
	NXGE_CLASS_FLOW_USE_PORTNUM;
int nxge_sctp4_class = NXGE_CLASS_FLOW_USE_DST_PORT |
	NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_IPDST |
	NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_PROTO |
	NXGE_CLASS_FLOW_USE_PORTNUM;

int nxge_tcp6_class = NXGE_CLASS_FLOW_USE_DST_PORT |
	NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_IPDST |
	NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_PROTO |
	NXGE_CLASS_FLOW_USE_PORTNUM;

int nxge_udp6_class = NXGE_CLASS_FLOW_USE_DST_PORT |
	NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_IPDST |
	NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_PROTO |
	NXGE_CLASS_FLOW_USE_PORTNUM;

int nxge_ah6_class = NXGE_CLASS_FLOW_USE_DST_PORT |
	NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_IPDST |
	NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_PROTO |
	NXGE_CLASS_FLOW_USE_PORTNUM;

int nxge_sctp6_class = NXGE_CLASS_FLOW_USE_DST_PORT |
	NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_IPDST |
	NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_PROTO |
	NXGE_CLASS_FLOW_USE_PORTNUM;

uint32_t nxge_fflp_init_h1 = 0xffffffff;
uint32_t nxge_fflp_init_h2 = 0xffff;

uint64_t class_quick_config_distribute[NXGE_CLASS_CONFIG_PARAMS] = {
	0xffffffffULL,		/* h1_init */
	0xffffULL,		/* h2_init */
	0x0,			/* cfg_ether_usr1 */
	0x0,			/* cfg_ether_usr2 */
	0x0,			/* cfg_ip_usr4 */
	0x0,			/* cfg_ip_usr5 */
	0x0,			/* cfg_ip_usr6 */
	0x0,			/* cfg_ip_usr7 */
	0x0,			/* opt_ip_usr4 */
	0x0,			/* opt_ip_usr5 */
	0x0,			/* opt_ip_usr6 */
	0x0,			/* opt_ip_usr7 */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv4_tcp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv4_udp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv4_ah */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv4_sctp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv6_tcp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv6_udp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv6_ah */
	NXGE_CLASS_FLOW_GEN_SERVER	/* opt_ipv6_sctp */
};

uint64_t class_quick_config_web_server[NXGE_CLASS_CONFIG_PARAMS] = {
	0xffffffffULL,		/* h1_init */
	0xffffULL,		/* h2_init */
	0x0,			/* cfg_ether_usr1 */
	0x0,			/* cfg_ether_usr2 */
	0x0,			/* cfg_ip_usr4 */
	0x0,			/* cfg_ip_usr5 */
	0x0,			/* cfg_ip_usr6 */
	0x0,			/* cfg_ip_usr7 */
	0x0,			/* opt_ip_usr4 */
	0x0,			/* opt_ip_usr5 */
	0x0,			/* opt_ip_usr6 */
	0x0,			/* opt_ip_usr7 */
	NXGE_CLASS_FLOW_WEB_SERVER,	/* opt_ipv4_tcp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv4_udp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv4_ah */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv4_sctp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv6_tcp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv6_udp */
	NXGE_CLASS_FLOW_GEN_SERVER,	/* opt_ipv6_ah */
	NXGE_CLASS_FLOW_GEN_SERVER	/* opt_ipv6_sctp */
};

nxge_status_t
nxge_classify_init(p_nxge_t nxgep)
{
	nxge_status_t status = NXGE_OK;

	status = nxge_classify_init_sw(nxgep);
	if (status != NXGE_OK)
		return (status);
	status = nxge_set_hw_classify_config(nxgep);
	if (status != NXGE_OK)
		return (status);

	status = nxge_classify_init_hw(nxgep);
	if (status != NXGE_OK)
		return (status);

	return (NXGE_OK);
}

nxge_status_t
nxge_classify_uninit(p_nxge_t nxgep)
{
	nxge_status_t status = NXGE_OK;

	status = nxge_classify_exit_sw(nxgep);
	if (status != NXGE_OK) {
		return (status);
	}
	return (NXGE_OK);
}

/* ARGSUSED */
uint64_t
nxge_classify_get_cfg_value(p_nxge_t nxgep, uint8_t cfg_type, uint8_t cfg_param)
{
	uint64_t cfg_value;

	if (cfg_param >= NXGE_CLASS_CONFIG_PARAMS)
		return (-1);
	switch (cfg_type) {
	case CFG_L3_WEB:
		cfg_value = class_quick_config_web_server[cfg_param];
		break;
	case CFG_L3_DISTRIBUTE:
	default:
		cfg_value = class_quick_config_distribute[cfg_param];
		break;
	}
	return (cfg_value);
}

nxge_status_t
nxge_set_hw_classify_config(p_nxge_t nxgep)
{
	p_nxge_dma_pt_cfg_t p_all_cfgp;
	p_nxge_hw_pt_cfg_t p_cfgp;

	NXGE_DEBUG_MSG((nxgep, OBP_CTL, "==> nxge_get_hw_classify_config"));

	/* Get mac rdc table info from HW/Prom/.conf etc ...... */
	/* for now, get it from dma configs */
	p_all_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_all_cfgp->hw_config;

	/*
	 * classify_init needs to call first.
	 */
	nxgep->class_config.mac_rdcgrp = p_cfgp->def_mac_rxdma_grpid;
	nxgep->class_config.mcast_rdcgrp = p_cfgp->def_mac_rxdma_grpid;
	NXGE_DEBUG_MSG((nxgep, OBP_CTL, "<== nxge_get_hw_classify_config"));

	return (NXGE_OK);
}
