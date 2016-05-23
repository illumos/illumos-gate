/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/ksynch.h>
#include <sys/cpuvar.h>
#include <sys/cpu.h>
#include <sys/vlan.h>

#include <inet/tcp.h>

#include "sfxge.h"

void
sfxge_gld_link_update(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	link_state_t link;

	switch (smp->sm_link_mode) {
	case EFX_LINK_UNKNOWN:
		link = LINK_STATE_UNKNOWN;
		break;
	case EFX_LINK_DOWN:
		link = LINK_STATE_DOWN;
		break;
	default:
		link = LINK_STATE_UP;
	}

	mac_link_update(sp->s_mh, link);
}

void
sfxge_gld_mtu_update(sfxge_t *sp)
{
#ifdef _USE_MTU_UPDATE
	(void) mac_maxsdu_update(sp->s_mh, sp->s_mtu);
#else
	_NOTE(ARGUNUSED(sp));
#endif
}

void
sfxge_gld_rx_post(sfxge_t *sp, unsigned int index, mblk_t *mp)
{
	_NOTE(ARGUNUSED(index))

	mac_rx(sp->s_mh, NULL, mp);
}


void
sfxge_gld_rx_push(sfxge_t *sp)
{
	_NOTE(ARGUNUSED(sp))
}


static uint64_t
sfxge_phy_dfl_cap_test64(sfxge_t *sp, uint32_t field)
{
	return (sfxge_phy_cap_test(sp, EFX_PHY_CAP_DEFAULT, field, NULL) ?
	    1ull : 0ull);
}


static uint64_t
sfxge_phy_cur_cap_test64(sfxge_t *sp, uint32_t field)
{
	return (sfxge_phy_cap_test(sp, EFX_PHY_CAP_CURRENT, field, NULL) ?
	    1ull : 0ull);
}

static uint64_t
sfxge_phy_lp_cap_test64(sfxge_t *sp, uint32_t field)
{
	return (sfxge_phy_lp_cap_test(sp, field) ? 1ull : 0ull);
}

static int
sfxge_gld_getstat(void *arg, unsigned int id, uint64_t *valp)
{
	sfxge_t *sp = arg;
	efx_nic_t *enp = sp->s_enp;
	int rc;

	if (sp->s_mac.sm_state != SFXGE_MAC_STARTED) {
		rc = ENODEV;
		goto fail1;
	}

	switch (id) {
	case MAC_STAT_IFSPEED: {
		unsigned int speed;

		sfxge_mac_link_speed_get(sp, &speed);

		*valp = (uint64_t)speed * 1000000ull;
		break;
	}
	case ETHER_STAT_LINK_DUPLEX: {
		sfxge_link_duplex_t duplex;

		sfxge_mac_link_duplex_get(sp, &duplex);

		switch (duplex) {
		case SFXGE_LINK_DUPLEX_UNKNOWN:
			*valp = LINK_DUPLEX_UNKNOWN;
			break;

		case SFXGE_LINK_DUPLEX_HALF:
			*valp = LINK_DUPLEX_HALF;
			break;

		case SFXGE_LINK_DUPLEX_FULL:
			*valp = LINK_DUPLEX_FULL;
			break;

		default:
			ASSERT(B_FALSE);
			break;
		}
		break;
	}

	case ETHER_STAT_CAP_40GFDX:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_40000FDX);
		break;
	case ETHER_STAT_CAP_10GFDX:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_10000FDX);
		break;
	case ETHER_STAT_CAP_1000FDX:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_1000FDX);
		break;
	case ETHER_STAT_CAP_1000HDX:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_1000HDX);
		break;
	case ETHER_STAT_CAP_100FDX:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_100FDX);
		break;
	case ETHER_STAT_CAP_100HDX:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_100HDX);
		break;
	case ETHER_STAT_CAP_10FDX:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_10FDX);
		break;
	case ETHER_STAT_CAP_10HDX:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_10HDX);
		break;
	case ETHER_STAT_CAP_ASMPAUSE:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_ASYM);
		break;
	case ETHER_STAT_CAP_PAUSE:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_PAUSE);
		break;
	case ETHER_STAT_CAP_AUTONEG:
		*valp = sfxge_phy_dfl_cap_test64(sp, EFX_PHY_CAP_AN);
		break;
	case ETHER_STAT_ADV_CAP_40GFDX:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_40000FDX);
		break;
	case ETHER_STAT_ADV_CAP_10GFDX:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_10000FDX);
		break;
	case ETHER_STAT_ADV_CAP_1000FDX:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_1000FDX);
		break;
	case ETHER_STAT_ADV_CAP_1000HDX:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_1000HDX);
		break;
	case ETHER_STAT_ADV_CAP_100FDX:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_100FDX);
		break;
	case ETHER_STAT_ADV_CAP_100HDX:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_100HDX);
		break;
	case ETHER_STAT_ADV_CAP_10FDX:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_10FDX);
		break;
	case ETHER_STAT_ADV_CAP_10HDX:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_10HDX);
		break;
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_ASYM);
		break;
	case ETHER_STAT_ADV_CAP_PAUSE:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_PAUSE);
		break;
	case ETHER_STAT_ADV_CAP_AUTONEG:
		*valp = sfxge_phy_cur_cap_test64(sp, EFX_PHY_CAP_AN);
		break;
	case ETHER_STAT_LP_CAP_40GFDX:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_40000FDX);
		break;
	case ETHER_STAT_LP_CAP_10GFDX:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_10000FDX);
		break;
	case ETHER_STAT_LP_CAP_1000FDX:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_1000FDX);
		break;
	case ETHER_STAT_LP_CAP_1000HDX:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_1000HDX);
		break;
	case ETHER_STAT_LP_CAP_100FDX:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_100FDX);
		break;
	case ETHER_STAT_LP_CAP_100HDX:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_100HDX);
		break;
	case ETHER_STAT_LP_CAP_10FDX:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_10FDX);
		break;
	case ETHER_STAT_LP_CAP_10HDX:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_10HDX);
		break;
	case ETHER_STAT_LP_CAP_ASMPAUSE:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_ASYM);
		break;
	case ETHER_STAT_LP_CAP_PAUSE:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_PAUSE);
		break;
	case ETHER_STAT_LP_CAP_AUTONEG:
		*valp = sfxge_phy_lp_cap_test64(sp, EFX_PHY_CAP_AN);
		break;

	case ETHER_STAT_XCVR_ADDR: {
		const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
		*valp = encp->enc_port;
		break;
	}
	case ETHER_STAT_XCVR_ID: {
		uint32_t oui;

		if ((rc = efx_phy_oui_get(sp->s_enp, &oui)) != 0)
			goto fail2;
		*valp = oui;
		break;
	}
	case MAC_STAT_MULTIRCV:
		sfxge_mac_stat_get(sp, EFX_MAC_RX_MULTICST_PKTS, valp);
		break;

	case MAC_STAT_BRDCSTRCV:
		sfxge_mac_stat_get(sp, EFX_MAC_RX_BRDCST_PKTS, valp);
		break;

	case MAC_STAT_MULTIXMT:
		sfxge_mac_stat_get(sp, EFX_MAC_TX_MULTICST_PKTS, valp);
		break;

	case MAC_STAT_BRDCSTXMT:
		sfxge_mac_stat_get(sp, EFX_MAC_TX_BRDCST_PKTS, valp);
		break;

	case MAC_STAT_IERRORS:
		sfxge_mac_stat_get(sp, EFX_MAC_RX_ERRORS, valp);
		break;

	case MAC_STAT_OERRORS:
		sfxge_mac_stat_get(sp, EFX_MAC_TX_ERRORS, valp);
		break;

	case MAC_STAT_RBYTES:
		sfxge_mac_stat_get(sp, EFX_MAC_RX_OCTETS, valp);
		break;

	case MAC_STAT_IPACKETS:
		sfxge_mac_stat_get(sp, EFX_MAC_RX_PKTS, valp);
		break;

	case MAC_STAT_OBYTES:
		sfxge_mac_stat_get(sp, EFX_MAC_TX_OCTETS, valp);
		break;

	case MAC_STAT_OPACKETS:
		sfxge_mac_stat_get(sp, EFX_MAC_TX_PKTS, valp);
		break;

	case MAC_STAT_NORCVBUF:
		sfxge_mac_stat_get(sp, EFX_MAC_RX_DROP_EVENTS, valp);
		break;

	case ETHER_STAT_FCS_ERRORS:
		sfxge_mac_stat_get(sp, EFX_MAC_RX_FCS_ERRORS, valp);
		break;

	default:
		rc = ENOTSUP;
		goto fail3;
	}

	return (0);
fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_gld_start(void *arg)
{
	sfxge_t *sp = arg;
	int rc;

	if ((rc = sfxge_start(sp, B_FALSE)) != 0)
		goto fail1;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_gld_stop(void *arg)
{
	sfxge_t *sp = arg;

	sfxge_stop(sp);
}

static int
sfxge_gld_setpromisc(void *arg, boolean_t on)
{
	sfxge_t *sp = arg;

	return sfxge_mac_promisc_set(sp,
	    (on) ? SFXGE_PROMISC_ALL_PHYS : SFXGE_PROMISC_OFF);
}

static int
sfxge_gld_multicst(void *arg, boolean_t add, const uint8_t *addr)
{
	sfxge_t *sp = arg;
	int rc;

	if (add) {
		if ((rc = sfxge_mac_multicst_add(sp, addr)) != 0)
			goto fail1;
	} else {
		if ((rc = sfxge_mac_multicst_remove(sp, addr)) != 0)
			goto fail2;
	}

	return (0);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);
	return (rc);
}

static int
sfxge_gld_unicst(void *arg, const uint8_t *addr)
{
	sfxge_t *sp = arg;
	int rc;

	if ((rc = sfxge_mac_unicst_set(sp, (uint8_t *)addr)) != 0)
		goto fail1;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_gld_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	sfxge_t *sp = arg;

	sfxge_ioctl(sp, wq, mp);
}


static mblk_t *
sfxge_gld_tx(void *arg, mblk_t *mp)
{
	sfxge_t *sp = arg;
	mblk_t *next;

	/* Walk the packet chain */
	do {
		/* Break the packet out of the chain */
		next = mp->b_next;
		mp->b_next = NULL;

		if (next != NULL)
			prefetch_read_many(next);

		/* Post the packet in the appropriate transmit queue */
		if (sfxge_tx_packet_add(sp, mp) == ENOSPC) {
			mp->b_next = next;
			return (mp);
		}

		mp = next;
	} while (mp != NULL);

	return (NULL);
}

/*
 * This must not be static, in order to be tunable by /etc/system.
 * (Static declarations may be optmized away by the compiler.)
 */
boolean_t	sfxge_lso = B_TRUE;

static boolean_t
sfxge_gld_getcapab(void *arg, mac_capab_t cap, void *cap_arg)
{
	int rc;

	_NOTE(ARGUNUSED(arg))

	switch (cap) {
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *lsop = cap_arg;

		/* Check whether LSO is disabled */
		if (!sfxge_lso) {
			rc = ENOTSUP;
			goto fail1;
		}

		DTRACE_PROBE(lso);

		lsop->lso_flags = LSO_TX_BASIC_TCP_IPV4;
		lsop->lso_basic_tcp_ipv4.lso_max = TCP_MAX_LSO_LENGTH;
		break;
	}
	case MAC_CAPAB_HCKSUM: {
		uint32_t *hcksump = cap_arg;

		DTRACE_PROBE(cksum);

		*hcksump = HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM;
		break;
	}
	default:
		rc = ENOTSUP;
		goto fail1;
	}

	return (B_TRUE);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (B_FALSE);
}

/*
 * GLDv3 driver-private property names must be preceded by an underscore - see
 * mc_getprop(9E).
 */
#define	SFXGE_PRIV_PROP_NAME(s) ("_" #s)

#define	SFXGE_XSTR(s) SFXGE_STR(s)
#define	SFXGE_STR(s) #s

static void
sfxge_gld_priv_prop_info(sfxge_t *sp, const char *name,
    mac_prop_info_handle_t handle)
{
	if (strcmp(name, SFXGE_PRIV_PROP_NAME(rx_coalesce_mode)) == 0) {
		mac_prop_info_set_default_uint32(handle,
		    SFXGE_RX_COALESCE_OFF);
		mac_prop_info_set_perm(handle, MAC_PROP_PERM_RW);
		return;
	}

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(rx_scale_count)) == 0) {
		mac_prop_info_set_default_uint32(handle, ncpus);
		mac_prop_info_set_range_uint32(handle, 1,
		    (uint32_t)sp->s_intr.si_nalloc);
		mac_prop_info_set_perm(handle, MAC_PROP_PERM_RW);
		return;
	}

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(intr_moderation)) == 0) {
		mac_prop_info_set_default_uint32(handle,
		    SFXGE_DEFAULT_MODERATION);
		mac_prop_info_set_range_uint32(handle,
		    0, efx_nic_cfg_get(sp->s_enp)->enc_evq_timer_max_us);
		mac_prop_info_set_perm(handle, MAC_PROP_PERM_RW);
		return;
	}

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(mon_polling)) == 0) {
		mac_prop_info_set_default_uint8(handle, 0);
		mac_prop_info_set_perm(handle, MAC_PROP_PERM_RW);
		return;
	}

#if EFSYS_OPT_MCDI_LOGGING
	if (strcmp(name, SFXGE_PRIV_PROP_NAME(mcdi_logging)) == 0) {
		mac_prop_info_set_default_uint8(handle, 0);
		mac_prop_info_set_perm(handle, MAC_PROP_PERM_RW);
		return;
	}
#endif
	DTRACE_PROBE(unknown_priv_prop);
}


static int
sfxge_gld_priv_prop_get(sfxge_t *sp, const char *name,
    unsigned int size, void *valp)
{
	long val;
	int rc;

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(rx_coalesce_mode)) == 0) {
		sfxge_rx_coalesce_mode_t mode;

		sfxge_rx_coalesce_mode_get(sp, &mode);

		val = (long)mode;
		goto done;
	}

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(rx_scale_count)) == 0) {
		unsigned int count;

		if (sfxge_rx_scale_count_get(sp, &count) != 0)
			count = 0;

		val = (long)count;
		goto done;
	}

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(intr_moderation)) == 0) {
		unsigned int us;

		sfxge_ev_moderation_get(sp, &us);

		val = (long)us;
		goto done;
	}

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(mon_polling)) == 0) {
		val = (long)sp->s_mon.sm_polling;
		goto done;
	}

#if EFSYS_OPT_MCDI_LOGGING
	if (strcmp(name, SFXGE_PRIV_PROP_NAME(mcdi_logging)) == 0) {
		val = (long)sp->s_mcdi_logging;
		goto done;
	}
#endif

	rc = ENOTSUP;
	goto fail1;

done:
	(void) snprintf(valp, size, "%ld", val);

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}


static int
sfxge_gld_priv_prop_set(sfxge_t *sp, const char *name, unsigned int size,
    const void *valp)
{
	long val;
	int rc = 0;

	_NOTE(ARGUNUSED(size))

	(void) ddi_strtol(valp, (char **)NULL, 0, &val);

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(rx_coalesce_mode)) == 0) {
		if ((rc = sfxge_rx_coalesce_mode_set(sp,
		    (sfxge_rx_coalesce_mode_t)val)) != 0)
			goto fail1;

		goto done;
	}

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(rx_scale_count)) == 0) {
		if ((rc = sfxge_rx_scale_count_set(sp, (unsigned int)val)) != 0)
			goto fail1;

		goto done;
	}

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(intr_moderation)) == 0) {
		if ((rc = sfxge_ev_moderation_set(sp, (unsigned int) val)) != 0)
			goto fail1;

		goto done;
	}

	if (strcmp(name, SFXGE_PRIV_PROP_NAME(mon_polling)) == 0) {
		sp->s_mon.sm_polling = (int)val;
		goto done;
	}

#if EFSYS_OPT_MCDI_LOGGING
	if (strcmp(name, SFXGE_PRIV_PROP_NAME(mcdi_logging)) == 0) {
		sp->s_mcdi_logging = (int)val;
		goto done;
	}
#endif


	rc = ENOTSUP;
	goto fail1;

done:
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}


#if EFSYS_OPT_MCDI_LOGGING
#define	SFXGE_N_NAMED_PROPS	4
#else
#define	SFXGE_N_NAMED_PROPS	3
#endif

static void
sfxge_gld_priv_prop_init(sfxge_t *sp)
{
	sfxge_mac_priv_prop_t *mac_priv_props;
	unsigned int nprops = 0;

	/*
	 * We have named_props (3 or 4) named properties and the structure must
	 * be finished by a NULL pointer.
	 */
	sp->s_mac_priv_props_alloc = SFXGE_N_NAMED_PROPS + 1;
	sp->s_mac_priv_props = kmem_zalloc(sizeof (sfxge_mac_priv_prop_t) *
	    sp->s_mac_priv_props_alloc,
	    KM_SLEEP);

	/*
	 * Driver-private property names start with an underscore - see
	 * mc_getprop(9E).
	 */

	mac_priv_props = sp->s_mac_priv_props;

	*mac_priv_props = kmem_zalloc(MAXLINKPROPNAME, KM_SLEEP);
	(void) snprintf(*mac_priv_props, MAXLINKPROPNAME - 1,
	    SFXGE_PRIV_PROP_NAME(rx_coalesce_mode));
	mac_priv_props++;
	nprops++;

	*mac_priv_props = kmem_zalloc(MAXLINKPROPNAME, KM_SLEEP);
	(void) snprintf(*mac_priv_props, MAXLINKPROPNAME - 1,
	    SFXGE_PRIV_PROP_NAME(rx_scale_count));
	mac_priv_props++;
	nprops++;

	*mac_priv_props = kmem_zalloc(MAXLINKPROPNAME, KM_SLEEP);
	(void) snprintf(*mac_priv_props, MAXLINKPROPNAME - 1,
	    SFXGE_PRIV_PROP_NAME(intr_moderation));
	mac_priv_props++;
	nprops++;

#if EFSYS_OPT_MCDI_LOGGING
	*mac_priv_props = kmem_zalloc(MAXLINKPROPNAME, KM_SLEEP);
	(void) snprintf(*mac_priv_props, MAXLINKPROPNAME - 1,
	    SFXGE_PRIV_PROP_NAME(mcdi_logging));
	mac_priv_props++;
	nprops++;
#endif

	ASSERT3U((nprops + 1), ==, sp->s_mac_priv_props_alloc);

	/* Terminated by a NULL pointer */
	*mac_priv_props = NULL;
}

static void
sfxge_gld_priv_prop_fini(sfxge_t *sp)
{
	char **mac_priv_props;
	unsigned int id;

	mac_priv_props = sp->s_mac_priv_props;

	for (id = 0; id < SFXGE_N_NAMED_PROPS; id++) {
		kmem_free(*mac_priv_props, MAXLINKPROPNAME);
		mac_priv_props++;
	}

	kmem_free(sp->s_mac_priv_props, sizeof (sfxge_mac_priv_prop_t) *
	    sp->s_mac_priv_props_alloc);
	sp->s_mac_priv_props = NULL;
}


static int
sfxge_gld_getprop(void *arg, const char *name, mac_prop_id_t id,
    unsigned int size, void *valp)
{
	sfxge_t *sp = arg;
	uint32_t flag = EFX_PHY_CAP_CURRENT;
	uint8_t *v8 = ((uint8_t *)valp);
	int rc;

	/* check size */
	switch (id) {
	case MAC_PROP_DUPLEX:
		if (size < sizeof (link_duplex_t)) {
			rc = EINVAL;
			goto fail1;
		}
		break;
	case MAC_PROP_FLOWCTRL:
		if (size < sizeof (link_flowctrl_t)) {
			rc = EINVAL;
			goto fail1;
		}
		break;
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
		if (size < sizeof (uint64_t)) {
			rc = EINVAL;
			goto fail1;
		}
		break;
	case MAC_PROP_MTU:
		if (size < sizeof (uint32_t)) {
			rc = EINVAL;
			goto fail1;
		}
		break;
	case MAC_PROP_EN_AUTONEG:
	case MAC_PROP_AUTONEG:
	case MAC_PROP_EN_40GFDX_CAP:
	case MAC_PROP_ADV_40GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000HDX_CAP:
	case MAC_PROP_ADV_1000HDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100HDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_EN_10FDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_EN_10HDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
		if (size < sizeof (uint8_t)) {
			rc = EINVAL;
			goto fail1;
		}
		break;
	case MAC_PROP_PRIVATE:
		/* sfxge_gld_priv_prop_get should do any size checking */
		break;
	default:
		rc = ENOTSUP;
		goto fail1;
	}

	switch (id) {
	case MAC_PROP_DUPLEX: {
		sfxge_link_duplex_t duplex;

		sfxge_mac_link_duplex_get(sp, &duplex);

		switch (duplex) {
		case SFXGE_LINK_DUPLEX_UNKNOWN:
			*((link_duplex_t *)valp) = LINK_DUPLEX_UNKNOWN;
			break;

		case SFXGE_LINK_DUPLEX_HALF:
			*((link_duplex_t *)valp) = LINK_DUPLEX_HALF;
			break;

		case SFXGE_LINK_DUPLEX_FULL:
			*((link_duplex_t *)valp) = LINK_DUPLEX_FULL;
			break;

		default:
			ASSERT(B_FALSE);
			break;
		}

		break;
	}
	case MAC_PROP_SPEED: {
		unsigned int speed;

		sfxge_mac_link_speed_get(sp, &speed);

		*((uint64_t *)valp) = (uint64_t)speed * 1000000ull;

		break;
	}
	case MAC_PROP_STATUS: {
		boolean_t up;

		sfxge_mac_link_check(sp, &up);

		*((link_state_t *)valp) = (up) ?
		    LINK_STATE_UP : LINK_STATE_DOWN;

		break;
	}
	case MAC_PROP_EN_AUTONEG:
	case MAC_PROP_AUTONEG:
		*v8 = sfxge_phy_cap_test(sp, flag, EFX_PHY_CAP_AN, NULL);
		break;
	case MAC_PROP_EN_40GFDX_CAP:
	case MAC_PROP_ADV_40GFDX_CAP:
		*v8 = sfxge_phy_cap_test(sp, flag, EFX_PHY_CAP_40000FDX, NULL);
		break;
	case MAC_PROP_EN_10GFDX_CAP:
	case MAC_PROP_ADV_10GFDX_CAP:
		*v8 = sfxge_phy_cap_test(sp, flag, EFX_PHY_CAP_10000FDX, NULL);
		break;
	case MAC_PROP_EN_1000FDX_CAP:
	case MAC_PROP_ADV_1000FDX_CAP:
		*v8 = sfxge_phy_cap_test(sp, flag, EFX_PHY_CAP_1000FDX, NULL);
		break;
	case MAC_PROP_EN_1000HDX_CAP:
	case MAC_PROP_ADV_1000HDX_CAP:
		*v8 = sfxge_phy_cap_test(sp, flag, EFX_PHY_CAP_1000HDX, NULL);
		break;
	case MAC_PROP_EN_100FDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
		*v8 = sfxge_phy_cap_test(sp, flag, EFX_PHY_CAP_100FDX, NULL);
		break;
	case MAC_PROP_EN_100HDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
		*v8 = sfxge_phy_cap_test(sp, flag, EFX_PHY_CAP_100HDX, NULL);
		break;
	case MAC_PROP_EN_10FDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
		*v8 = sfxge_phy_cap_test(sp, flag, EFX_PHY_CAP_10FDX, NULL);
		break;
	case MAC_PROP_EN_10HDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
		*v8 = sfxge_phy_cap_test(sp, flag, EFX_PHY_CAP_10HDX, NULL);
		break;
	case MAC_PROP_MTU:
		*((uint32_t *)valp) = (uint32_t)(sp->s_mtu);
		break;

	case MAC_PROP_FLOWCTRL: {
		unsigned int fcntl;

		sfxge_mac_fcntl_get(sp, &fcntl);

		switch (fcntl) {
		case 0:
			*((link_flowctrl_t *)valp) = LINK_FLOWCTRL_NONE;
			break;

		case EFX_FCNTL_GENERATE:
			*((link_flowctrl_t *)valp) = LINK_FLOWCTRL_RX;
			break;

		case EFX_FCNTL_RESPOND:
			*((link_flowctrl_t *)valp) = LINK_FLOWCTRL_TX;
			break;

		case (EFX_FCNTL_GENERATE | EFX_FCNTL_RESPOND):
			*((link_flowctrl_t *)valp) = LINK_FLOWCTRL_BI;
			break;

		default:
			ASSERT(B_FALSE);
			break;
		}
		break;
	}
	case MAC_PROP_PRIVATE:
		if ((rc = sfxge_gld_priv_prop_get(sp, name, size, valp)) != 0)
			goto fail2;
		break;
	default:
		rc = ENOTSUP;
		goto fail3;
	}

	return (0);

fail3:
	DTRACE_PROBE(fail3);

fail2:
	DTRACE_PROBE(fail2);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}


static int
sfxge_gld_setprop(void *arg, const char *name, mac_prop_id_t id,
    unsigned int size, const void *valp)
{
	sfxge_t *sp = arg;
	int v8 =  *(uint8_t *)valp;
	int rc;

	/* get size checks out fo the way */
	switch (id) {
	/*
	 * On Sol11 (no updates) dladm seems to be using MAC_PROP_AUTONEG to set
	 * the autoneg parameter. This does not match the scheme suggested in
	 * mac(9E) but as they both map to the same think in the driver and in
	 * dladm it doesn't matter.
	 */
	case MAC_PROP_AUTONEG:
	case MAC_PROP_EN_AUTONEG:
	case MAC_PROP_EN_40GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
	case MAC_PROP_EN_1000HDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
	case MAC_PROP_EN_100HDX_CAP:
	case MAC_PROP_EN_10FDX_CAP:
	case MAC_PROP_EN_10HDX_CAP:
		if (size < sizeof (uint8_t)) {
			rc = EINVAL;
			goto fail1;
		}
		break;
	case MAC_PROP_MTU:
		if (size < sizeof (uint32_t)) {
			rc = EINVAL;
			goto fail1;
		}
		break;
	case MAC_PROP_FLOWCTRL:
		if (size < sizeof (link_flowctrl_t)) {
			rc = EINVAL;
			goto fail1;
		}
		break;
	case MAC_PROP_PRIVATE:
		/* sfxge_gld_priv_prop_set should do any size checking */
		break;
	default:
		rc = ENOTSUP;
		goto fail1;
	}

	switch (id) {
	/*
	 * It is unclear which of MAC_PROP_AUTONEG and MAC_PROP_EN_AUTONEG is
	 * used.  Try both.
	 */
	case MAC_PROP_AUTONEG:
	case MAC_PROP_EN_AUTONEG:
		if ((rc = sfxge_phy_cap_set(sp, EFX_PHY_CAP_AN, v8)) != 0)
			goto fail2;
		break;
	case MAC_PROP_EN_40GFDX_CAP:
		if ((rc = sfxge_phy_cap_set(sp, EFX_PHY_CAP_40000FDX, v8)) != 0)
			goto fail2;
		break;
	case MAC_PROP_EN_10GFDX_CAP: {
		if ((rc = sfxge_phy_cap_set(sp, EFX_PHY_CAP_10000FDX, v8)) != 0)
			goto fail2;
		break;
	}
	case MAC_PROP_EN_1000FDX_CAP: {
		if ((rc = sfxge_phy_cap_set(sp, EFX_PHY_CAP_1000FDX, v8)) != 0)
			goto fail2;
		break;
	}
	case MAC_PROP_EN_1000HDX_CAP: {
		if ((rc = sfxge_phy_cap_set(sp, EFX_PHY_CAP_1000HDX, v8)) != 0)
			goto fail2;
		break;
	}
	case MAC_PROP_EN_100FDX_CAP: {
		if ((rc = sfxge_phy_cap_set(sp, EFX_PHY_CAP_100FDX, v8)) != 0)
			goto fail2;
		break;
	}
	case MAC_PROP_EN_100HDX_CAP: {
		if ((rc = sfxge_phy_cap_set(sp, EFX_PHY_CAP_100HDX, v8)) != 0)
			goto fail2;
		break;
	}
	case MAC_PROP_EN_10FDX_CAP: {
		if ((rc = sfxge_phy_cap_set(sp, EFX_PHY_CAP_10FDX, v8)) != 0)
			goto fail2;
		break;
	}
	case MAC_PROP_EN_10HDX_CAP: {
		if ((rc = sfxge_phy_cap_set(sp, EFX_PHY_CAP_10HDX, v8)) != 0)
			goto fail2;
		break;
	}
	case MAC_PROP_MTU: {
		size_t mtu = (size_t)(*((uint32_t *)valp));

		if (mtu > EFX_MAC_SDU_MAX) {
			rc = EINVAL;
			goto fail2;
		}

		sp->s_mtu = mtu;

		DTRACE_PROBE(restart_mtu);
		(void) sfxge_restart_dispatch(sp, DDI_SLEEP, SFXGE_HW_OK,
		    "MTU changing", (uint32_t)mtu);

		break;
	}
	case MAC_PROP_FLOWCTRL: {
		unsigned int fcntl = 0;

		switch (*((link_flowctrl_t *)valp)) {
		case LINK_FLOWCTRL_NONE:
			fcntl = 0;
			break;

		case LINK_FLOWCTRL_RX:
			fcntl = EFX_FCNTL_GENERATE;
			break;

		case LINK_FLOWCTRL_TX:
			fcntl = EFX_FCNTL_RESPOND;
			break;

		case LINK_FLOWCTRL_BI:
			fcntl = EFX_FCNTL_GENERATE | EFX_FCNTL_RESPOND;
			break;

		default:
			rc = EINVAL;
			goto fail2;
		}

		if ((rc = sfxge_mac_fcntl_set(sp, fcntl)) != 0)
			goto fail3;

		break;
	}
	case MAC_PROP_PRIVATE:
		if ((rc = sfxge_gld_priv_prop_set(sp, name, size, valp)) != 0)
			goto fail4;

		break;
	default:
		rc = ENOTSUP;
		goto fail5;
	}

	return (0);

fail5:
	DTRACE_PROBE(fail5);

fail4:
	DTRACE_PROBE(fail4);

fail3:
	DTRACE_PROBE(fail3);

fail2:
	DTRACE_PROBE(fail2);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_gld_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t handle)
{
	sfxge_t *sp = arg;
	efx_phy_cap_type_t phy_cap = EFX_PHY_CAP_INVALID;
	switch (id) {
		case MAC_PROP_DUPLEX:
			mac_prop_info_set_perm(handle, MAC_PROP_PERM_READ);
			return;
		case MAC_PROP_FLOWCTRL:
			mac_prop_info_set_perm(handle, MAC_PROP_PERM_RW);
			mac_prop_info_set_default_link_flowctrl(handle,
			    LINK_FLOWCTRL_BI);
			return;
		case MAC_PROP_SPEED:
			mac_prop_info_set_perm(handle, MAC_PROP_PERM_READ);
			return;
		case MAC_PROP_STATUS:
			mac_prop_info_set_perm(handle, MAC_PROP_PERM_READ);
			return;
		case MAC_PROP_MTU: {
			uint32_t mtu_default;
			mac_prop_info_set_perm(handle, MAC_PROP_PERM_RW);
			mtu_default = ddi_prop_get_int(DDI_DEV_T_ANY,
			    sp->s_dip, DDI_PROP_DONTPASS, "mtu", ETHERMTU);
			mac_prop_info_set_default_uint32(handle, mtu_default);
			return;
			}
		case MAC_PROP_PRIVATE:
			sfxge_gld_priv_prop_info(sp, name, handle);
			return;
		case MAC_PROP_EN_AUTONEG:
		case MAC_PROP_AUTONEG:
			phy_cap = EFX_PHY_CAP_AN;
			break;
		case MAC_PROP_EN_10GFDX_CAP:
		case MAC_PROP_ADV_10GFDX_CAP:
			phy_cap = EFX_PHY_CAP_10000FDX;
			break;
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_ADV_1000FDX_CAP:
			phy_cap = EFX_PHY_CAP_1000FDX;
			break;
		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
			phy_cap = EFX_PHY_CAP_1000HDX;
			break;
		case MAC_PROP_EN_100FDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
			phy_cap = EFX_PHY_CAP_100FDX;
			break;
		case MAC_PROP_EN_100HDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
			phy_cap = EFX_PHY_CAP_100HDX;
			break;
		case MAC_PROP_EN_10FDX_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
			phy_cap = EFX_PHY_CAP_10FDX;
			break;
		case MAC_PROP_EN_10HDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
			phy_cap = EFX_PHY_CAP_10HDX;
			break;
		default:
			DTRACE_PROBE(unknown_prop);
			return;
	}
	if (phy_cap != EFX_PHY_CAP_INVALID) {
		boolean_t rw;
		uint8_t cap_default;
		cap_default = sfxge_phy_cap_test(sp, EFX_PHY_CAP_DEFAULT,
		    phy_cap, &rw);
		if (rw == B_TRUE)
			mac_prop_info_set_perm(handle, MAC_PROP_PERM_RW);
		else
			mac_prop_info_set_perm(handle, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(handle, cap_default);
	}
}

int
sfxge_gld_register(sfxge_t *sp)
{
	mac_callbacks_t *mcp;
	mac_register_t *mrp;
	mac_handle_t mh;
	uint8_t addr[ETHERADDRL];
	int rc;

	if ((mrp = mac_alloc(MAC_VERSION)) == NULL) {
		rc = ENOTSUP;
		goto fail1;
	}

	mrp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mrp->m_driver = sp;
	mrp->m_dip = sp->s_dip;

	/* Set up the callbacks */
	mcp = &(sp->s_mc);
	bzero(mcp, sizeof (mac_callbacks_t));

	mcp->mc_getstat = sfxge_gld_getstat;
	mcp->mc_start = sfxge_gld_start;
	mcp->mc_stop = sfxge_gld_stop;
	mcp->mc_setpromisc = sfxge_gld_setpromisc;
	mcp->mc_multicst = sfxge_gld_multicst;
	mcp->mc_unicst = sfxge_gld_unicst;
	mcp->mc_tx = sfxge_gld_tx;

	mcp->mc_callbacks |= MC_IOCTL;
	mcp->mc_ioctl = sfxge_gld_ioctl;

	mcp->mc_callbacks |= MC_GETCAPAB;
	mcp->mc_getcapab = sfxge_gld_getcapab;

	mcp->mc_callbacks |= MC_SETPROP;
	mcp->mc_setprop = sfxge_gld_setprop;

	mcp->mc_callbacks |= MC_GETPROP;
	mcp->mc_getprop = sfxge_gld_getprop;

	mcp->mc_callbacks |= MC_PROPINFO;
	mcp->mc_propinfo = sfxge_gld_propinfo;

	mrp->m_callbacks = mcp;

	mrp->m_src_addr = addr;

	if ((rc = sfxge_mac_unicst_get(sp, SFXGE_UNICST_BIA,
	    mrp->m_src_addr)) != 0)
		goto fail2;

	mrp->m_min_sdu = 0;
	mrp->m_max_sdu = sp->s_mtu;

	mrp->m_margin = VLAN_TAGSZ;

	/* Set up the private properties */
	/* NOTE: m_priv_props added in s10u9 */
	mrp->m_priv_props = sp->s_mac_priv_props;
	sfxge_gld_priv_prop_init(sp);

	/* NOTE: m_flags added in s11.0 */
	/* NOTE: m_multicast_sdu added in s11.0 */

	/* Register the interface */
	if ((rc = mac_register(mrp, &mh)) != 0)
		goto fail3;

	/* Free the stack registration object */
	kmem_free(mrp, sizeof (mac_register_t));

	sp->s_mh = mh;

	return (0);
fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);

	/* Free the stack registration object */
	mac_free(mrp);

	/* Tear down the private properties */
	sfxge_gld_priv_prop_fini(sp);

	/* Clear the callbacks */
	bzero(&(sp->s_mc), sizeof (mac_callbacks_t));

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

int
sfxge_gld_unregister(sfxge_t *sp)
{
	mac_handle_t mh = sp->s_mh;
	int rc;

	if ((rc = mac_unregister(mh)) != 0)
		goto fail1;

	sp->s_mh = NULL;

	/* Tear down the private properties */
	sfxge_gld_priv_prop_fini(sp);

	/* Clear the callbacks */
	bzero(&(sp->s_mc), sizeof (mac_callbacks_t));

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}
