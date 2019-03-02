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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*
 * Generic Lan Driver interface for netvsc.
 */

#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <inet/ip.h>
#include <sys/vlan.h>

#include "if_hnvar.h"
#include "hn_rndis.h"
#include "if_hnreg.h"
#include "hn_nvs.h"

static mblk_t		*hn_tx_ring_send(void *, mblk_t *);
static int		hn_m_getstat(void *, uint_t, uint64_t *);
static int		hn_m_start(void *);
static void		hn_m_stop(void *);
static int		hn_m_setpromisc(void *, boolean_t);
static int		hn_m_multicst(void *, boolean_t, const uint8_t *);
static boolean_t	hn_m_getcapab(void *, mac_capab_t, void *);
static int		hn_m_getprop(void *, const char *, mac_prop_id_t,
			    uint_t, void *);
static int		hn_m_setprop(void *, const char *, mac_prop_id_t,
			    uint_t, const void *);
static void		hn_m_propinfo(void *, const char *, mac_prop_id_t,
			    mac_prop_info_handle_t);

/* Read-only properties */
#define	HN_PROP_NVS_VERSION		"_nvs_version"
#define	HN_PROP_NDIS_VERSION		"_ndis_version"
#define	HN_PROP_HOST_CAPABILITIES	"_host_capabilities"
#define	HN_PROP_RX_RINGS_USED		"_rx_rings_used"
#define	HN_PROP_RX_RINGS		"_rx_rings"
#define	HN_PROP_TX_RINGS_USED		"_tx_rings_used"
#define	HN_PROP_TX_RINGS		"_tx_rings"
#define	HN_PROP_TX_CHIM_MAXSIZE		"_tx_chimney_maxsize"

/* Writeable properties */
#define	HN_PROP_TRUST_HOST_CKSUM	"_trust_host_cksum"
#define	HN_PROP_TX_CHIM_SIZE		"_tx_chimney_size"

char *hn_priv_props[] = {
	HN_PROP_NVS_VERSION,
	HN_PROP_NDIS_VERSION,
	HN_PROP_HOST_CAPABILITIES,
	HN_PROP_RX_RINGS_USED,
	HN_PROP_RX_RINGS,
	HN_PROP_TX_RINGS_USED,
	HN_PROP_TX_RINGS,
	HN_PROP_TX_CHIM_MAXSIZE,
	HN_PROP_TRUST_HOST_CKSUM,
	HN_PROP_TX_CHIM_SIZE,
	NULL
};

#define	HN_M_CALLBACK_FLAGS \
	(MC_GETCAPAB | MC_PROPERTIES)

/* MAC callbacks */
static mac_callbacks_t hn_mac_callbacks = {
	.mc_callbacks =	HN_M_CALLBACK_FLAGS,
	.mc_getstat =	hn_m_getstat,
	.mc_start =	hn_m_start,
	.mc_stop =	hn_m_stop,
	.mc_setpromisc = hn_m_setpromisc,
	.mc_multicst =	hn_m_multicst,
	.mc_unicst =	NULL,
	.mc_tx =	NULL,
	.mc_ioctl =	NULL,
	.mc_getcapab =	hn_m_getcapab,
	.mc_getprop =	hn_m_getprop,
	.mc_setprop =	hn_m_setprop,
	.mc_propinfo =	hn_m_propinfo
};

extern int hn_tso_maxlen;

int
hn_get_priv_prop(struct hn_softc *sc, const char *prop_name,
    uint_t prop_val_size, void *prop_val)
{
	int value;

	HN_LOCK(sc);

	/*
	 * Note: private prop values are always passed as strings
	 */
	if (strcmp(prop_name, HN_PROP_NVS_VERSION) == 0) {
		(void) snprintf(prop_val, prop_val_size, "0x%x",
		    sc->hn_nvs_ver);
		goto done;
	} else if (strcmp(prop_name, HN_PROP_NDIS_VERSION) == 0) {
		(void) snprintf(prop_val, prop_val_size, "%u.%u",
		    HN_NDIS_VERSION_MAJOR(sc->hn_ndis_ver),
		    HN_NDIS_VERSION_MINOR(sc->hn_ndis_ver));
		goto done;
	} else if (strcmp(prop_name, HN_PROP_HOST_CAPABILITIES) == 0) {
		uint32_t caps = sc->hn_caps;
		(void) snprintf(prop_val, prop_val_size, "%s%s%s%s%s%s%s%s%s",
		    (caps & HN_CAP_VLAN) ?	"VLAN " : "",
		    (caps & HN_CAP_MTU) ?	"MTU " : "",
		    (caps & HN_CAP_IPCS) ?	"IPCS " : "",
		    (caps & HN_CAP_TCP4CS) ?	"TCP4CS " : "",
		    (caps & HN_CAP_TCP6CS) ?	"TCP6CS " : "",
		    (caps & HN_CAP_UDP4CS) ?	"UDP4CS " : "",
		    (caps & HN_CAP_UDP6CS) ?	"UDP6CS " : "",
		    (caps & HN_CAP_TSO4) ?	"TSO4 " : "",
		    (caps & HN_CAP_TSO6) ?	"TSO6 " : "");
		goto done;
	} else if (strcmp(prop_name, HN_PROP_RX_RINGS_USED) == 0) {
		value = sc->hn_rx_ring_inuse;
	} else if (strcmp(prop_name, HN_PROP_RX_RINGS) == 0) {
		value = sc->hn_rx_ring_cnt;
	} else if (strcmp(prop_name, HN_PROP_TX_RINGS_USED) == 0) {
		value = sc->hn_tx_ring_inuse;
	} else if (strcmp(prop_name, HN_PROP_TX_RINGS) == 0) {
		value = sc->hn_tx_ring_cnt;
	} else if (strcmp(prop_name, HN_PROP_TX_CHIM_MAXSIZE) == 0) {
		value = sc->hn_chim_szmax;
	} else if (strcmp(prop_name, HN_PROP_TX_CHIM_SIZE) == 0) {
		value = sc->hn_tx_ring[0].hn_chim_size;
	} else if (strcmp(prop_name, HN_PROP_TRUST_HOST_CKSUM) == 0) {
		value = (sc->hn_rx_ring[0].hn_trust_hcsum == 0) ? 0 : 1;
	} else {
		HN_UNLOCK(sc);
		return (ENOTSUP);
	}

	(void) snprintf(prop_val, prop_val_size, "%d", value);
done:
	HN_UNLOCK(sc);
	return (0);
}

static int
hn_m_getprop(void *data, const char *prop_name, mac_prop_id_t prop_id,
    uint_t prop_val_size, void *prop_val)
{
	struct hn_softc *sc = data;
	int error = 0;

	switch (prop_id) {
	case MAC_PROP_MTU:
		ASSERT(prop_val_size >= sizeof (uint32_t));
		bcopy(&sc->hn_mtu, prop_val, sizeof (uint32_t));
		break;
	case MAC_PROP_PRIVATE:
		error = hn_get_priv_prop(sc, prop_name, prop_val_size,
		    prop_val);
		break;
	default:
		HN_WARN(sc, "hn_get_prop property %d not supported", prop_id);
		error = ENOTSUP;
	}
	return (error);
}

/*ARGSUSED*/
int
hn_set_priv_prop(struct hn_softc *sc, const char *prop_name,
    uint_t prop_val_size, const void *prop_val)
{
	long value = -1;
	int error = 0;

	HN_DEBUG(sc, 2, "Setting private property %s to %s",
	    prop_name, (const char *)prop_val);
	/*
	 * Note: private prop values are always passed as strings
	 */
	if (strcmp(prop_name, HN_PROP_TRUST_HOST_CKSUM) == 0) {
		(void) ddi_strtol(prop_val, (char **)NULL, 0, &value);
		if (value == 0 || value == 1) {
			int hcsum = (value == 1) ? HN_TRUST_HCSUM_ALL : 0;
			HN_LOCK(sc);
			for (int i = 0; i < sc->hn_rx_ring_inuse; ++i) {
				struct hn_rx_ring *rxr = &sc->hn_rx_ring[i];
				rxr->hn_trust_hcsum = hcsum;
			}
			HN_UNLOCK(sc);
			return (0);
		} else {
			error = EINVAL;
		}
	} else if (strcmp(prop_name, HN_PROP_TX_CHIM_SIZE) == 0) {
		(void) ddi_strtol(prop_val, (char **)NULL, 0, &value);
		if (value >= 0 && value <= sc->hn_chim_szmax) {
			HN_LOCK(sc);
			hn_set_chim_size(sc, value);
			HN_UNLOCK(sc);
			return (0);
		} else {
			error = EINVAL;
		}
	} else {
		HN_DEBUG(sc, 2, "Unknown private property");
		error = EINVAL;
	}

	return (error);
}

/*ARGSUSED*/
static int
hn_m_setprop(void *data, const char *prop_name, mac_prop_id_t prop_id,
    uint_t prop_val_size, const void *prop_val)
{
	struct hn_softc *sc = data;
	uint32_t new_mtu;
	int error;

	switch (prop_id) {
	case MAC_PROP_MTU:
		ASSERT(prop_val_size >= sizeof (uint32_t));
		bcopy(prop_val, &new_mtu, sizeof (new_mtu));
		error = hn_change_mtu(sc, new_mtu);
		break;
	case MAC_PROP_PRIVATE:
		error = hn_set_priv_prop(sc, prop_name, prop_val_size,
		    prop_val);
		break;
	default:
		HN_WARN(sc, "hn_set_prop property %d not supported", prop_id);
		error = ENOTSUP;
	}

	return (error);
}

void
hn_priv_prop_info(struct hn_softc *sc, const char *prop_name,
    mac_prop_info_handle_t prh)
{
	char valstr[64];
	int value;

	/*
	 * Note: private prop values are always passed as strings
	 */
	if (strcmp(prop_name, HN_PROP_NVS_VERSION) == 0 ||
	    strcmp(prop_name, HN_PROP_NDIS_VERSION) == 0 ||
	    strcmp(prop_name, HN_PROP_HOST_CAPABILITIES) == 0 ||
	    strcmp(prop_name, HN_PROP_RX_RINGS_USED) == 0 ||
	    strcmp(prop_name, HN_PROP_RX_RINGS) == 0 ||
	    strcmp(prop_name, HN_PROP_TX_RINGS_USED) == 0 ||
	    strcmp(prop_name, HN_PROP_TX_RINGS) == 0 ||
	    strcmp(prop_name, HN_PROP_TX_CHIM_MAXSIZE) == 0) {
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		return;
	} else if (strcmp(prop_name, HN_PROP_TRUST_HOST_CKSUM) == 0) {
		value = HN_DEFAULT_TRUST_HOST_CKSUM;
	} else if (strcmp(prop_name, HN_PROP_TX_CHIM_SIZE) == 0) {
		value = sc->hn_chim_szmax;
	} else {
		return;
	}

	(void) snprintf(valstr, sizeof (valstr), "%d", value);
	mac_prop_info_set_default_str(prh, valstr);
}

/*ARGSUSED*/
static void
hn_m_propinfo(void *data, const char *prop_name, mac_prop_id_t prop_id,
    mac_prop_info_handle_t prop_handle)
{
	struct hn_softc *sc = data;

	switch (prop_id) {
	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prop_handle, 0, HN_MTU_MAX);
		break;
	case MAC_PROP_PRIVATE:
		hn_priv_prop_info(sc, prop_name, prop_handle);
		break;
	default:
		HN_WARN(sc, "hn_prop_info: property %d not supported", prop_id);
	}
}

static void
hn_get_rx_stat(struct hn_softc *sc, uint_t stat, uint64_t *val)
{
	uint64_t counter = 0;

	for (int i = 0; i < sc->hn_rx_ring_cnt; i++) {
		struct hn_rx_ring *rxr = &sc->hn_rx_ring[i];
		hn_rx_stats_t *stats = &rxr->hn_rx_stats;

		mutex_enter(&rxr->hn_rx_lock);
		switch (stat) {
		case MAC_STAT_MULTIRCV:
			counter += stats->mcast_pkts;
			break;
		case MAC_STAT_BRDCSTRCV:
			counter += stats->bcast_pkts;
			break;
		case MAC_STAT_NORCVBUF:
			counter += stats->norxbufs;
			break;
		case MAC_STAT_IERRORS:
			counter += stats->ierrors;
			break;
		case MAC_STAT_RBYTES:
			counter += stats->bytes;
			break;
		case MAC_STAT_IPACKETS:
			counter += stats->pkts;
			break;
		default:
			/* can only happen if bug in hn_m_getstat */
			ASSERT(0);
		}
		mutex_exit(&rxr->hn_rx_lock);
	}
	*val = counter;
}

static void
hn_get_tx_stat(struct hn_softc *sc, uint_t stat, uint64_t *val)
{
	uint64_t counter = 0;

	for (int i = 0; i < sc->hn_tx_ring_cnt; i++) {
		struct hn_tx_ring *txr = &sc->hn_tx_ring[i];
		hn_tx_stats_t *stats = &txr->hn_tx_stats;

		mutex_enter(&txr->hn_tx_lock);
		switch (stat) {
		case MAC_STAT_MULTIXMT:
			counter += stats->mcast_pkts;
			break;
		case MAC_STAT_BRDCSTXMT:
			counter += stats->bcast_pkts;
			break;
		case MAC_STAT_NOXMTBUF:
			counter += stats->no_txdescs;
			break;
		case MAC_STAT_OERRORS:
			counter += stats->send_failed + stats->dma_failed;
			break;
		case MAC_STAT_OBYTES:
			counter += stats->bytes;
			break;
		case MAC_STAT_OPACKETS:
			counter += stats->pkts;
			break;
		default:
			/* can only happen if bug in hn_m_getstat */
			ASSERT(0);
		}
		mutex_exit(&txr->hn_tx_lock);
	}
	*val = counter;
}

static int
hn_m_getstat(void *data, uint_t stat, uint64_t *val)
{
	struct hn_softc *sc = data;

	HN_DEBUG(sc, 3, "getstat(%u)", stat);

	switch (stat) {
	case MAC_STAT_MULTIRCV:
	case MAC_STAT_BRDCSTRCV:
	case MAC_STAT_NORCVBUF:
	case MAC_STAT_IERRORS:
	case MAC_STAT_RBYTES:
	case MAC_STAT_IPACKETS:
		hn_get_rx_stat(sc, stat, val);
		break;

	case MAC_STAT_MULTIXMT:
	case MAC_STAT_BRDCSTXMT:
	case MAC_STAT_NOXMTBUF:
	case MAC_STAT_OERRORS:
	case MAC_STAT_OBYTES:
	case MAC_STAT_OPACKETS:
		hn_get_tx_stat(sc, stat, val);
		break;

	case MAC_STAT_IFSPEED:
		return (ENOTSUP);

	case MAC_STAT_COLLISIONS:
		*val = 0;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
hn_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	struct hn_rx_ring *rxr = (struct hn_rx_ring *)rh;
	hn_rx_stats_t *stats = &rxr->hn_rx_stats;
	int error = 0;

	mutex_enter(&rxr->hn_rx_lock);

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = stats->bytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = stats->pkts;
		break;

	case MAC_STAT_IERRORS:
		*val = stats->ierrors;
		break;

	default:
		*val = 0;
		error = ENOTSUP;
	}

	mutex_exit(&rxr->hn_rx_lock);

	return (error);
}

/*
 * Retrieve a value for one of the statistics for a particular tx ring
 */
int
hn_tx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	struct hn_tx_ring *txr = (struct hn_tx_ring *)rh;
	hn_tx_stats_t *stats = &txr->hn_tx_stats;
	int error = 0;

	mutex_enter(&txr->hn_tx_lock);

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = stats->bytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = stats->pkts;
		break;

	case MAC_STAT_OERRORS:
		*val = stats->send_failed + stats->dma_failed;
		break;

	default:
		*val = 0;
		error = ENOTSUP;
	}

	mutex_exit(&txr->hn_tx_lock);

	return (error);
}

int
hn_m_start(void *data)
{
	struct hn_softc *sc = data;

	HN_DEBUG(sc, 1, "start()");

	hn_init(sc);

	return (0);
}

void
hn_m_stop(void *data)
{
	struct hn_softc *sc = data;

	HN_DEBUG(sc, 1, "stop()");

	HN_LOCK(sc);
	hn_stop(sc);
	HN_UNLOCK(sc);
}

/*
 * Set the MAC address for the device.
 */
static int
hn_addmac(void *arg, const uint8_t *mac_addr)
{
	hn_rx_group_t *rx_group = arg;
	struct hn_softc *sc = rx_group->sc;

	HN_DEBUG(sc, 2, "addmac("MACADDR_FMT_PRETTY")",
	    MACADDR_FMT_ARGS(mac_addr));

	if (sc->hn_mac_addr_set) {
		HN_WARN(sc, "hn_addmac: MAC address already set");
		return (ENOSPC);
	}

	/* check if device is already configured with this MAC address */
	if (memcmp(mac_addr, sc->hn_macaddr, ETHERADDRL) != 0) {
		if (hn_rndis_set_eaddr(sc, mac_addr) != 0)
			return (EIO);
		bcopy(mac_addr, sc->hn_macaddr, ETHERADDRL);
	}

	sc->hn_mac_addr_set = B_TRUE;

	return (0);
}

/*
 * Do nothing as the netvsc device only supports one MAC address.
 */
/*ARGSUSED*/
static int
hn_remmac(void *arg, const uint8_t *mac_addr)
{
	hn_rx_group_t *rx_group = arg;
	struct hn_softc *sc = rx_group->sc;

	HN_DEBUG(sc, 2, "remmac("MACADDR_FMT_PRETTY")",
	    MACADDR_FMT_ARGS(mac_addr));

	sc->hn_mac_addr_set = B_FALSE;

	return (0);
}

/*ARGSUSED*/
static int
hn_m_multicst(void *data, boolean_t add, const uint8_t *macaddr)
{
	struct hn_softc *sc = data;

	HN_DEBUG(sc, 2, "multicast(%s, "MACADDR_FMT_PRETTY")",
	    add ? "add" : "remove", MACADDR_FMT_ARGS(macaddr));

	/*
	 * Multicast address filtering is not currently supported.
	 * We accept all multicast addresses.
	 */

	return (0);
}

/*
 * Set the promiscuity of the device.
 */
int
hn_m_setpromisc(void *data, boolean_t promisc)
{
	struct hn_softc *sc = data;

	HN_LOCK(sc);
	HN_DEBUG(sc, 2, "setpromisc(%s)", promisc ? "TRUE" : "FALSE");
	sc->hn_promiscuous = promisc;

	(void) hn_set_rxfilter(sc);
	HN_UNLOCK(sc);

	return (0);
}

/*ARGSUSED*/
static int
hn_rx_ring_intr_enable(mac_intr_handle_t intrh)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
hn_rx_ring_intr_disable(mac_intr_handle_t intrh)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
mblk_t *
hn_rx_ring_poll(void *arg, int bytes)
{
	/*
	 * Polled mode is currently not implemented, however we must still
	 * provide a function to the framework.
	 */
	return (NULL);
}

static int
hn_rx_ring_start(mac_ring_driver_t rh, uint64_t mr_gen_num)
{
	struct hn_rx_ring *rxr = (struct hn_rx_ring *)rh;

	mutex_enter(&rxr->hn_rx_lock);
	rxr->hn_ring_gen_num = mr_gen_num;
	mutex_exit(&rxr->hn_rx_lock);
	return (0);
}

static mblk_t *
hn_tx_ring_send(void *arg, mblk_t *mp)
{
	struct hn_tx_ring *txr = arg;

	mutex_enter(&txr->hn_tx_lock);
	mblk_t *mps_left = hn_xmit(txr, mp);
	mutex_exit(&txr->hn_tx_lock);

	return (mps_left);
}

/*
 * Callback function for MAC layer to register all rings.
 */
/* ARGSUSED */
static void
hn_fill_ring(void *arg, mac_ring_type_t rtype, const int rg_index,
    const int index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	struct hn_softc *sc = arg;
	mac_intr_t *mintr = &infop->mri_intr;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		ASSERT(index < sc->hn_rx_ring_cnt);

		struct hn_rx_ring *rxr = &sc->hn_rx_ring[index];

		rxr->hn_ring_handle = rh;

		infop->mri_driver = (mac_ring_driver_t)rxr;
		infop->mri_start = hn_rx_ring_start;
		infop->mri_stop = NULL;
		infop->mri_poll = (mac_ring_poll_t)hn_rx_ring_poll;
		infop->mri_stat = hn_rx_ring_stat;

		mintr->mi_handle = (mac_intr_handle_t)rxr;
		mintr->mi_enable = hn_rx_ring_intr_enable;
		mintr->mi_disable = hn_rx_ring_intr_disable;
		mintr->mi_ddi_handle = NULL;
		break;
	}
	case MAC_RING_TYPE_TX: {
		ASSERT(index < sc->hn_tx_ring_cnt);

		struct hn_tx_ring *txr = &sc->hn_tx_ring[index];

		txr->hn_ring_handle = rh;

		infop->mri_driver = (mac_ring_driver_t)txr;
		infop->mri_start = NULL;
		infop->mri_stop = NULL;
		infop->mri_tx = hn_tx_ring_send;
		infop->mri_stat = hn_tx_ring_stat;
		mintr->mi_ddi_handle = NULL;
		break;
	}
	default:
		break;
	}
}

static void
hn_fill_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	struct hn_softc *sc = arg;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		hn_rx_group_t *rx_group = &sc->hn_rx_group;

		ASSERT0(index);

		rx_group->group_handle = gh;
		rx_group->index = index;
		rx_group->sc = sc;

		infop->mgi_driver = (mac_group_driver_t)rx_group;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = hn_addmac;
		infop->mgi_remmac = hn_remmac;
		infop->mgi_count = sc->hn_rx_ring_inuse;

		break;
	}
	case MAC_RING_TYPE_TX:
		break;
	default:
		break;
	}
}

static boolean_t
hn_m_getcapab(void *data, mac_capab_t cap, void *cap_data)
{
	struct hn_softc *sc = data;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *tx_hcksum_flags = cap_data;

		/*
		 * We advertise our capabilities only if tx hcksum offload is
		 * enabled.  On receive, the stack will accept checksummed
		 * packets anyway, even if we haven't said we can deliver
		 * them.
		 */

		*tx_hcksum_flags = sc->hn_hcksum_flags;
		break;
	}
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = cap_data;

		if ((sc->hn_lso_flags & LSO_TX_BASIC_TCP_IPV4) == 0)
			return (B_FALSE);

		int tso_maxlen = hn_tso_maxlen;
		if (tso_maxlen <= 0 || tso_maxlen > IP_MAXPACKET)
			tso_maxlen = IP_MAXPACKET;
		tso_maxlen = MIN(tso_maxlen, sc->hn_ndis_tso_szmax);
		cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
		cap_lso->lso_basic_tcp_ipv4.lso_max = tso_maxlen;
		break;
	}
	case MAC_CAPAB_RINGS: {
		mac_capab_rings_t *cap_rings = cap_data;

		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_RX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = sc->hn_rx_ring_inuse;
			cap_rings->mr_gnum = 1;
			cap_rings->mr_rget = hn_fill_ring;
			cap_rings->mr_gget = hn_fill_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;

			break;
		case MAC_RING_TYPE_TX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = sc->hn_tx_ring_inuse;
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rget = hn_fill_ring;
			cap_rings->mr_gget = NULL;

			break;
		default:
			break;
		}
		break;
	}

	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

int
hn_register_mac(struct hn_softc *sc)
{
	int error;
	mac_register_t *mac;

	/*
	 * Get MAC address of adapter
	 */
	error = hn_rndis_get_eaddr(sc, sc->hn_macaddr);
	if (error != 0) {
		HN_WARN(sc, "Failed to retrieve MAC address");
		return (error);
	}

	if ((mac = mac_alloc(MAC_VERSION)) == NULL)
		return (EINVAL);

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = sc;
	mac->m_dip = sc->hn_dev;
	mac->m_src_addr = sc->hn_macaddr;
	mac->m_callbacks = &hn_mac_callbacks;
	mac->m_min_sdu = HN_MTU_MIN;
	mac->m_max_sdu = sc->hn_mtu;
	mac->m_margin = VLAN_TAGSZ;
	mac->m_priv_props = hn_priv_props;
	mac->m_v12n = MAC_VIRT_LEVEL1;

	error = mac_register(mac, &sc->hn_mac_hdl);
	mac_free(mac);

	return (error);
}
