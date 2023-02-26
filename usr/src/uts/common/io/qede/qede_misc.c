/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017, Joyent, Inc. 
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Misc. support routines
 */

#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include "qede.h"

typedef struct {
	uint32_t qsm_type;
	uint32_t qsm_speed;
	mac_ether_media_t qsm_media;
} qede_sfp_map_t;

typedef enum {
	QS_1G	= 1000,
	QS_10G	= 10000,
	QS_25G	= 25000,
	QS_40G	= 40000,
	QS_100G	= 100000
} qede_speed_t;

/*
 * Note, we currently have no mapping for the QEDE 1G PCC/ACC as it is not clear
 * what spec those are actually referring to. While they have explicit
 * multi-speed settings for 40/100, we assume the 1/10 multi-speed could occur
 * and check just in case.
 */
static const qede_sfp_map_t qede_sfp_map[] = {
	{ ETH_TRANSCEIVER_TYPE_1G_LX, QS_1G, ETHER_MEDIA_1000BASE_LX },
	{ ETH_TRANSCEIVER_TYPE_1G_SX, QS_1G, ETHER_MEDIA_1000BASE_SX },
	{ ETH_TRANSCEIVER_TYPE_10G_SR, QS_10G, ETHER_MEDIA_10GBASE_SR },
	{ ETH_TRANSCEIVER_TYPE_10G_SR, QS_1G, ETHER_MEDIA_1000BASE_SX },
	{ ETH_TRANSCEIVER_TYPE_10G_LR, QS_10G, ETHER_MEDIA_10GBASE_LR },
	{ ETH_TRANSCEIVER_TYPE_10G_LR, QS_1G, ETHER_MEDIA_1000BASE_LX },
	{ ETH_TRANSCEIVER_TYPE_10G_LRM, QS_10G, ETHER_MEDIA_10GBASE_LRM },
	{ ETH_TRANSCEIVER_TYPE_10G_ER, QS_10G, ETHER_MEDIA_10GBASE_ER },
	{ ETH_TRANSCEIVER_TYPE_10G_PCC, QS_10G, ETHER_MEDIA_10GBASE_CR },
	{ ETH_TRANSCEIVER_TYPE_10G_ACC, QS_10G, ETHER_MEDIA_10GBASE_ACC },
	{ ETH_TRANSCEIVER_TYPE_XLPPI, QS_40G, ETHER_MEDIA_40G_XLPPI },
	{ ETH_TRANSCEIVER_TYPE_40G_LR4, QS_40G, ETHER_MEDIA_40GBASE_LR4 },
	{ ETH_TRANSCEIVER_TYPE_40G_SR4, QS_40G, ETHER_MEDIA_40GBASE_SR4 },
	{ ETH_TRANSCEIVER_TYPE_40G_CR4, QS_40G, ETHER_MEDIA_40GBASE_CR4 },
	{ ETH_TRANSCEIVER_TYPE_100G_AOC, QS_100G, ETHER_MEDIA_100GBASE_AOC4 },
	{ ETH_TRANSCEIVER_TYPE_100G_SR4, QS_100G, ETHER_MEDIA_100GBASE_SR4 },
	{ ETH_TRANSCEIVER_TYPE_100G_LR4, QS_100G, ETHER_MEDIA_100GBASE_LR4 },
	{ ETH_TRANSCEIVER_TYPE_100G_ER4, QS_100G, ETHER_MEDIA_100GBASE_ER4 },
	{ ETH_TRANSCEIVER_TYPE_100G_ACC, QS_100G, ETHER_MEDIA_100GBASE_ACC4 },
	{ ETH_TRANSCEIVER_TYPE_100G_CR4, QS_100G, ETHER_MEDIA_100GBASE_CR4 },
	{ ETH_TRANSCEIVER_TYPE_4x10G_SR, QS_40G, ETHER_MEDIA_40GBASE_SR4 },
	{ ETH_TRANSCEIVER_TYPE_25G_CA_N, QS_25G, ETHER_MEDIA_25GBASE_CR },
	{ ETH_TRANSCEIVER_TYPE_25G_CA_L, QS_25G, ETHER_MEDIA_25GBASE_CR },
	{ ETH_TRANSCEIVER_TYPE_25G_CA_S, QS_25G, ETHER_MEDIA_25GBASE_CR },
	{ ETH_TRANSCEIVER_TYPE_25G_ACC_S, QS_25G, ETHER_MEDIA_25GBASE_ACC },
	{ ETH_TRANSCEIVER_TYPE_25G_ACC_M, QS_25G, ETHER_MEDIA_25GBASE_ACC },
	{ ETH_TRANSCEIVER_TYPE_25G_ACC_L, QS_25G, ETHER_MEDIA_25GBASE_ACC },
	{ ETH_TRANSCEIVER_TYPE_25G_SR, QS_25G, ETHER_MEDIA_25GBASE_SR },
	{ ETH_TRANSCEIVER_TYPE_25G_LR, QS_25G, ETHER_MEDIA_25GBASE_LR },
	{ ETH_TRANSCEIVER_TYPE_25G_AOC, QS_25G, ETHER_MEDIA_25GBASE_AOC },
	{ ETH_TRANSCEIVER_TYPE_4x10G, QS_40G, ETHER_MEDIA_40GBASE_CR4 },
	{ ETH_TRANSCEIVER_TYPE_4x25G_CR, QS_100G, ETHER_MEDIA_100GBASE_CR4 },
	{ ETH_TRANSCEIVER_TYPE_1000BASET, QS_1G, ETHER_MEDIA_1000BASE_T },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_10G_40G_SR, QS_40G,
	    ETHER_MEDIA_40GBASE_SR4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_10G_40G_SR, QS_10G,
	    ETHER_MEDIA_10GBASE_SR },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_10G_40G_CR, QS_40G,
	    ETHER_MEDIA_40GBASE_CR4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_10G_40G_CR, QS_10G,
	    ETHER_MEDIA_10GBASE_CR },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_10G_40G_LR, QS_40G,
	    ETHER_MEDIA_40GBASE_LR4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_10G_40G_LR, QS_10G,
	    ETHER_MEDIA_10GBASE_LR },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_40G_100G_SR, QS_100G,
	    ETHER_MEDIA_100GBASE_SR4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_40G_100G_SR, QS_40G,
	    ETHER_MEDIA_40GBASE_SR4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_40G_100G_CR, QS_100G,
	    ETHER_MEDIA_100GBASE_CR4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_40G_100G_CR, QS_40G,
	    ETHER_MEDIA_40GBASE_CR4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_40G_100G_LR, QS_100G,
	    ETHER_MEDIA_100GBASE_LR4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_40G_100G_LR, QS_40G,
	    ETHER_MEDIA_40GBASE_LR4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_40G_100G_AOC, QS_100G,
	    ETHER_MEDIA_100GBASE_AOC4 },
	{ ETH_TRANSCEIVER_TYPE_MULTI_RATE_40G_100G_AOC, QS_40G,
	    ETHER_MEDIA_40GBASE_AOC4 },
};

mac_ether_media_t
qede_link_to_media(qede_link_cfg_t *cfg, uint32_t speed)
{
	uint32_t type = (cfg->txr_data & ETH_TRANSCEIVER_TYPE_MASK) >>
	    ETH_TRANSCEIVER_TYPE_SHIFT;
	switch (cfg->media) {
	case MEDIA_SFPP_10G_FIBER:
	case MEDIA_XFP_FIBER:
	case MEDIA_DA_TWINAX:
	case MEDIA_SFP_1G_FIBER:
	case MEDIA_MODULE_FIBER:
		for (size_t i = 0; i < ARRAY_SIZE(qede_sfp_map); i++) {
			if (qede_sfp_map[i].qsm_type == type &&
			    qede_sfp_map[i].qsm_speed == speed) {
				return (qede_sfp_map[i].qsm_media);
			}
		}
		return (ETHER_MEDIA_UNKNOWN);
	case MEDIA_BASE_T:
		switch (speed) {
		case QS_1G:
			return (ETHER_MEDIA_1000BASE_T);
		case QS_10G:
			return (ETHER_MEDIA_10GBASE_T);
		default:
			return (ETHER_MEDIA_UNKNOWN);
		}
	/*
	 * We don't really know which KR speeds this driver supports and they
	 * don't show up in the common code, so just put our best guesses in
	 * case it ever does.
	 */
	case MEDIA_KR:
		switch (speed) {
		case QS_1G:
			return (ETHER_MEDIA_1000BASE_KX);
		case QS_10G:
			return (ETHER_MEDIA_10GBASE_KR);
		case QS_25G:
			return (ETHER_MEDIA_25GBASE_KR);
		case QS_40G:
			return (ETHER_MEDIA_40GBASE_KR4);
		case QS_100G:
			return (ETHER_MEDIA_100GBASE_KR4);
		default:
			return (ETHER_MEDIA_UNKNOWN);
		}
	case MEDIA_NOT_PRESENT:
		return (ETHER_MEDIA_NONE);
	case MEDIA_UNSPECIFIED:
	default:
		return (ETHER_MEDIA_UNKNOWN);
	}
}

/*
 * This is our own wrapper around the underlying ecore APIs to read both a
 * module type and transceiver information data in one go. This should be used
 * whenever the link is being updated as we cache it to answer questions about
 * the MAC media or to know whether or not to allow transceiver access to
 * continue.
 *
 * If this fails we will just update the media info with a claim of unknown.
 */
void
qede_update_media_info(struct ecore_dev *edev, qede_link_cfg_t *link)
{
	struct ecore_hwfn *hwfn = &edev->hwfns[0];
        struct ecore_ptt *ptt;

	link->media = MEDIA_UNSPECIFIED;
	link->txr_data = ETH_TRANSCEIVER_STATE_UPDATING;

	if (IS_VF(edev) || !ecore_mcp_is_init(hwfn))
		return;

        ptt = ecore_ptt_acquire(hwfn);
	if (ptt == NULL)
		return;

	link->media = ecore_rd(hwfn, ptt, hwfn->mcp_info->port_addr +
            offsetof(struct public_port, media_type));
	link->txr_data = ecore_rd(hwfn, ptt, hwfn->mcp_info->port_addr +
            offsetof(struct public_port, transceiver_data));
        ecore_ptt_release(hwfn, ptt);
}

/*
 * We need to emulate sprintf. Unfortunately illumos sprintf does not return the
 * number of bytes written, only a pointer to the string. Therefore we need this
 * wrapper.
 */
size_t
qede_sprintf(char *s, const char *fmt, ...)
{
	size_t r;
	va_list args;

	va_start(args, fmt);
	r = vsnprintf(s, SIZE_MAX, fmt, args);
	va_end(args);

	return (r);
}
