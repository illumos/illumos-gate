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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Joyent, Inc.
 */

/*
 * MAC Services Module
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/kstat.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_stat.h>
#include <sys/mac_soft_ring.h>
#include <sys/vlan.h>

#define	MAC_KSTAT_NAME	"mac"
#define	MAC_KSTAT_CLASS	"net"

enum mac_stat {
	MAC_STAT_LCL,
	MAC_STAT_LCLBYTES,
	MAC_STAT_INTRS,
	MAC_STAT_INTRBYTES,
	MAC_STAT_POLLS,
	MAC_STAT_POLLBYTES,
	MAC_STAT_RXSDROPS,
	MAC_STAT_CHU10,
	MAC_STAT_CH10T50,
	MAC_STAT_CHO50,
	MAC_STAT_BLOCK,
	MAC_STAT_UNBLOCK,
	MAC_STAT_TXSDROPS,
	MAC_STAT_TX_ERRORS,
	MAC_STAT_MACSPOOFED,
	MAC_STAT_IPSPOOFED,
	MAC_STAT_DHCPSPOOFED,
	MAC_STAT_RESTRICTED,
	MAC_STAT_DHCPDROPPED,
	MAC_STAT_MULTIRCVBYTES,
	MAC_STAT_BRDCSTRCVBYTES,
	MAC_STAT_MULTIXMTBYTES,
	MAC_STAT_BRDCSTXMTBYTES
};

static mac_stat_info_t	i_mac_si[] = {
	{ MAC_STAT_IFSPEED,	"ifspeed",	KSTAT_DATA_UINT64,	0 },
	{ MAC_STAT_MULTIRCV,	"multircv",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_BRDCSTRCV,	"brdcstrcv",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_MULTIXMT,	"multixmt",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_BRDCSTXMT,	"brdcstxmt",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_NORCVBUF,	"norcvbuf",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_IERRORS,	"ierrors",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_UNKNOWNS,	"unknowns",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_NOXMTBUF,	"noxmtbuf",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_OERRORS,	"oerrors",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_COLLISIONS,	"collisions",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_UNDERFLOWS,	"uflo",		KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_OVERFLOWS,	"oflo",		KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_RBYTES,	"rbytes",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_IPACKETS,	"ipackets",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_OBYTES,	"obytes",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_OPACKETS,	"opackets",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_RBYTES,	"rbytes64",	KSTAT_DATA_UINT64,	0 },
	{ MAC_STAT_IPACKETS,	"ipackets64",	KSTAT_DATA_UINT64,	0 },
	{ MAC_STAT_OBYTES,	"obytes64",	KSTAT_DATA_UINT64,	0 },
	{ MAC_STAT_OPACKETS,	"opackets64",	KSTAT_DATA_UINT64,	0 }
};
#define	MAC_NKSTAT \
	(sizeof (i_mac_si) / sizeof (mac_stat_info_t))

static mac_stat_info_t	i_mac_mod_si[] = {
	{ MAC_STAT_LINK_STATE,	"link_state",	KSTAT_DATA_UINT32,
	    (uint64_t)LINK_STATE_UNKNOWN },
	{ MAC_STAT_LINK_UP,	"link_up",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_PROMISC,	"promisc",	KSTAT_DATA_UINT32,	0 }
};
#define	MAC_MOD_NKSTAT \
	(sizeof (i_mac_mod_si) / sizeof (mac_stat_info_t))

#define	MAC_MOD_KSTAT_OFFSET	0
#define	MAC_KSTAT_OFFSET	MAC_MOD_KSTAT_OFFSET + MAC_MOD_NKSTAT
#define	MAC_TYPE_KSTAT_OFFSET	MAC_KSTAT_OFFSET + MAC_NKSTAT

/*
 * Definitions for per rx ring statistics
 */
static mac_stat_info_t  i_mac_rx_ring_si[] = {
	{ MAC_STAT_RBYTES,	"rbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_IPACKETS,	"ipackets",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_HDROPS,	"hdrops",	KSTAT_DATA_UINT64,	0}
};
#define	MAC_RX_RING_NKSTAT \
	(sizeof (i_mac_rx_ring_si) / sizeof (mac_stat_info_t))

/*
 * Definitions for per tx ring statistics
 */
static mac_stat_info_t  i_mac_tx_ring_si[] = {
	{ MAC_STAT_OBYTES,	"obytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_OPACKETS,	"opackets",	KSTAT_DATA_UINT64,	0}
};
#define	MAC_TX_RING_NKSTAT \
	(sizeof (i_mac_tx_ring_si) / sizeof (mac_stat_info_t))


/*
 * Definitions for per software lane tx statistics
 */
static mac_stat_info_t  i_mac_tx_swlane_si[] = {
	{ MAC_STAT_OBYTES,	"obytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_OPACKETS,	"opackets",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_OERRORS,	"oerrors",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_BLOCK,	"blockcnt",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_UNBLOCK,	"unblockcnt",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_TXSDROPS,	"txsdrops",	KSTAT_DATA_UINT64,	0}
};
#define	MAC_TX_SWLANE_NKSTAT \
	(sizeof (i_mac_tx_swlane_si) / sizeof (mac_stat_info_t))

/*
 * Definitions for per software lane rx statistics
 */
static mac_stat_info_t  i_mac_rx_swlane_si[] = {
	{ MAC_STAT_IPACKETS,	"ipackets",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_RBYTES,	"rbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_LCL,		"local",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_LCLBYTES,	"localbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_INTRS,	"intrs",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_INTRBYTES,	"intrbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_RXSDROPS,	"rxsdrops",	KSTAT_DATA_UINT64,	0}
};
#define	MAC_RX_SWLANE_NKSTAT \
	(sizeof (i_mac_rx_swlane_si) / sizeof (mac_stat_info_t))

/*
 * Definitions for per hardware lane rx statistics
 */
static mac_stat_info_t  i_mac_rx_hwlane_si[] = {
	{ MAC_STAT_IPACKETS,	"ipackets",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_RBYTES,	"rbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_INTRS,	"intrs",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_INTRBYTES,	"intrbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_POLLS,	"polls",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_POLLBYTES,	"pollbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_RXSDROPS,	"rxsdrops",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_CHU10,	"chainunder10",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_CH10T50,	"chain10to50",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_CHO50,	"chainover50",	KSTAT_DATA_UINT64,	0}
};
#define	MAC_RX_HWLANE_NKSTAT \
	(sizeof (i_mac_rx_hwlane_si) / sizeof (mac_stat_info_t))

/*
 * Definitions for misc statistics
 */
static mac_stat_info_t  i_mac_misc_si[] = {
	{ MAC_STAT_MULTIRCV,	"multircv",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_BRDCSTRCV,	"brdcstrcv",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_MULTIXMT,	"multixmt",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_BRDCSTXMT,	"brdcstxmt",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_MULTIRCVBYTES, "multircvbytes",   KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_BRDCSTRCVBYTES, "brdcstrcvbytes", KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_MULTIXMTBYTES,  "multixmtbytes",  KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_BRDCSTXMTBYTES, "brdcstxmtbytes", KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_TX_ERRORS,	"txerrors",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_MACSPOOFED,	"macspoofed",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_IPSPOOFED,	"ipspoofed",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_DHCPSPOOFED,	"dhcpspoofed",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_RESTRICTED,	"restricted",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_DHCPDROPPED,	"dhcpdropped",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_IPACKETS,	"ipackets",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_RBYTES,	"rbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_LCL,		"local",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_LCLBYTES,	"localbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_INTRS,	"intrs",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_INTRBYTES,	"intrbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_POLLS,	"polls",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_POLLBYTES,	"pollbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_RXSDROPS,	"rxsdrops",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_CHU10,	"chainunder10",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_CH10T50,	"chain10to50",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_CHO50,	"chainover50",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_OBYTES,	"obytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_OPACKETS,	"opackets",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_OERRORS,	"oerrors",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_BLOCK,	"blockcnt",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_UNBLOCK,	"unblockcnt",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_TXSDROPS,	"txsdrops",	KSTAT_DATA_UINT64,	0}
};
#define	MAC_SUMMARY_NKSTAT \
	(sizeof (i_mac_misc_si) / sizeof (mac_stat_info_t))

/*
 * Definitions for per hardware lane tx statistics
 */
static mac_stat_info_t  i_mac_tx_hwlane_si[] = {
	{ MAC_STAT_OBYTES,	"obytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_OPACKETS,	"opackets",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_OERRORS,	"oerrors",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_BLOCK,	"blockcnt",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_UNBLOCK,	"unblockcnt",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_TXSDROPS,	"txsdrops",	KSTAT_DATA_UINT64,	0}
};
#define	MAC_TX_HWLANE_NKSTAT \
	(sizeof (i_mac_tx_hwlane_si) / sizeof (mac_stat_info_t))

/*
 * Definitions for per fanout rx statistics
 */
static mac_stat_info_t  i_mac_rx_fanout_si[] = {
	{ MAC_STAT_RBYTES,	"rbytes",	KSTAT_DATA_UINT64,	0},
	{ MAC_STAT_IPACKETS,	"ipackets",	KSTAT_DATA_UINT64,	0},
};
#define	MAC_RX_FANOUT_NKSTAT \
	(sizeof (i_mac_rx_fanout_si) / sizeof (mac_stat_info_t))

/*
 * Private functions.
 */

typedef struct {
	uint_t	si_offset;
} stat_info_t;

#define	RX_SRS_STAT_OFF(f)	(offsetof(mac_rx_stats_t, f))
static stat_info_t rx_srs_stats_list[] = {
	{RX_SRS_STAT_OFF(mrs_lclbytes)},
	{RX_SRS_STAT_OFF(mrs_lclcnt)},
	{RX_SRS_STAT_OFF(mrs_pollcnt)},
	{RX_SRS_STAT_OFF(mrs_pollbytes)},
	{RX_SRS_STAT_OFF(mrs_intrcnt)},
	{RX_SRS_STAT_OFF(mrs_intrbytes)},
	{RX_SRS_STAT_OFF(mrs_sdrops)},
	{RX_SRS_STAT_OFF(mrs_chaincntundr10)},
	{RX_SRS_STAT_OFF(mrs_chaincnt10to50)},
	{RX_SRS_STAT_OFF(mrs_chaincntover50)},
	{RX_SRS_STAT_OFF(mrs_ierrors)}
};
#define	RX_SRS_STAT_SIZE 		\
	(sizeof (rx_srs_stats_list) / sizeof (stat_info_t))

#define	TX_SOFTRING_STAT_OFF(f)	(offsetof(mac_tx_stats_t, f))
static stat_info_t tx_softring_stats_list[] = {
	{TX_SOFTRING_STAT_OFF(mts_obytes)},
	{TX_SOFTRING_STAT_OFF(mts_opackets)},
	{TX_SOFTRING_STAT_OFF(mts_oerrors)},
	{TX_SOFTRING_STAT_OFF(mts_blockcnt)},
	{TX_SOFTRING_STAT_OFF(mts_unblockcnt)},
	{TX_SOFTRING_STAT_OFF(mts_sdrops)},
};
#define	TX_SOFTRING_STAT_SIZE 		\
	(sizeof (tx_softring_stats_list) / sizeof (stat_info_t))

static void
i_mac_add_stats(void *sum, void *op1, void *op2,
    stat_info_t stats_list[], uint_t size)
{
	int 	i;

	for (i = 0; i < size; i++) {
		uint64_t *op1_val = (uint64_t *)
		    ((uchar_t *)op1 + stats_list[i].si_offset);
		uint64_t *op2_val = (uint64_t *)
		    ((uchar_t *)op2 + stats_list[i].si_offset);
		uint64_t *sum_val = (uint64_t *)
		    ((uchar_t *)sum + stats_list[i].si_offset);

		*sum_val =  *op1_val + *op2_val;
	}
}

static int
i_mac_driver_stat_update(kstat_t *ksp, int rw)
{
	mac_impl_t	*mip = ksp->ks_private;
	kstat_named_t	*knp = ksp->ks_data;
	uint_t		i;
	uint64_t	val;
	mac_stat_info_t	*msi;
	uint_t		msi_index;

	if (rw != KSTAT_READ)
		return (EACCES);

	for (i = 0; i < mip->mi_kstat_count; i++, msi_index++) {
		if (i == MAC_MOD_KSTAT_OFFSET) {
			msi_index = 0;
			msi = i_mac_mod_si;
		} else if (i == MAC_KSTAT_OFFSET) {
			msi_index = 0;
			msi = i_mac_si;
		} else if (i == MAC_TYPE_KSTAT_OFFSET) {
			msi_index = 0;
			msi = mip->mi_type->mt_stats;
		}

		val = mac_stat_get((mac_handle_t)mip, msi[msi_index].msi_stat);
		switch (msi[msi_index].msi_type) {
		case KSTAT_DATA_UINT64:
			knp->value.ui64 = val;
			break;
		case KSTAT_DATA_UINT32:
			knp->value.ui32 = (uint32_t)val;
			break;
		default:
			ASSERT(B_FALSE);
			break;
		}

		knp++;
	}

	return (0);
}

static void
i_mac_kstat_init(kstat_named_t *knp, mac_stat_info_t *si, uint_t count)
{
	int i;
	for (i = 0; i < count; i++) {
		kstat_named_init(knp, si[i].msi_name, si[i].msi_type);
		knp++;
	}
}

static int
i_mac_stat_update(kstat_t *ksp, int rw, uint64_t (*fn)(void *, uint_t),
    mac_stat_info_t *msi, uint_t count)
{
	kstat_named_t	*knp = ksp->ks_data;
	uint_t		i;
	uint64_t	val;

	if (rw != KSTAT_READ)
		return (EACCES);

	for (i = 0; i < count; i++) {
		val = fn(ksp->ks_private, msi[i].msi_stat);

		switch (msi[i].msi_type) {
		case KSTAT_DATA_UINT64:
			knp->value.ui64 = val;
			break;
		case KSTAT_DATA_UINT32:
			knp->value.ui32 = (uint32_t)val;
			break;
		default:
			ASSERT(B_FALSE);
			break;
		}
		knp++;
	}
	return (0);
}

/*
 * Create kstat with given name - statname, update function - fn
 * and initialize it with given names - init_stat_info
 */
static kstat_t *
i_mac_stat_create(void *handle, const char *modname, const char *statname,
    int (*fn) (kstat_t *, int),
    mac_stat_info_t *init_stat_info, uint_t count)
{
	kstat_t		*ksp;
	kstat_named_t	*knp;

	ksp = kstat_create_zone(modname, 0, statname, "net",
	    KSTAT_TYPE_NAMED, count, 0, getzoneid());

	if (ksp == NULL)
		return (NULL);

	ksp->ks_update = fn;
	ksp->ks_private = handle;

	knp = (kstat_named_t *)ksp->ks_data;
	i_mac_kstat_init(knp, init_stat_info, count);
	kstat_install(ksp);

	return (ksp);
}

/*
 * Per rx ring statistics
 */
uint64_t
mac_rx_ring_stat_get(void *handle, uint_t stat)
{
	mac_ring_t		*ring = (mac_ring_t *)handle;
	uint64_t		val = 0;

	/*
	 * XXX Every ring-capable driver must implement an entry point to
	 * query per ring statistics. CR 6893122 tracks this work item.
	 * Once this bug is fixed, the framework should fail registration
	 * for a driver that does not implement this entry point and
	 * assert ring->mr_stat != NULL here.
	 */
	if (ring->mr_stat != NULL)
		ring->mr_stat(ring->mr_driver, stat, &val);

	return (val);
}

static int
i_mac_rx_ring_stat_update(kstat_t *ksp, int rw)
{
	return (i_mac_stat_update(ksp, rw, mac_rx_ring_stat_get,
	    i_mac_rx_ring_si, MAC_RX_RING_NKSTAT));
}

static void
i_mac_rx_ring_stat_create(mac_ring_t *ring, const char *modname,
    const char *statname)
{
	kstat_t		*ksp;

	ksp = i_mac_stat_create(ring, modname, statname,
	    i_mac_rx_ring_stat_update, i_mac_rx_ring_si, MAC_RX_RING_NKSTAT);

	ring->mr_ksp = ksp;
}

/*
 * Per tx ring statistics
 */
uint64_t
mac_tx_ring_stat_get(void *handle, uint_t stat)
{
	mac_ring_t		*ring = (mac_ring_t *)handle;
	uint64_t		val = 0;

	/*
	 * XXX Every ring-capable driver must implement an entry point to
	 * query per ring statistics. CR 6893122 tracks this work item.
	 * Once this bug is fixed, the framework should fail registration
	 * for a driver that does not implement this entry point and
	 * assert ring->mr_stat != NULL here.
	 */
	if (ring->mr_stat != NULL)
		ring->mr_stat(ring->mr_driver, stat, &val);

	return (val);
}

static int
i_mac_tx_ring_stat_update(kstat_t *ksp, int rw)
{
	return (i_mac_stat_update(ksp, rw, mac_tx_ring_stat_get,
	    i_mac_tx_ring_si, MAC_TX_RING_NKSTAT));
}

static void
i_mac_tx_ring_stat_create(mac_ring_t *ring, const char *modname,
    const char *statname)
{
	kstat_t		*ksp;

	ksp = i_mac_stat_create(ring, modname, statname,
	    i_mac_tx_ring_stat_update, i_mac_tx_ring_si, MAC_TX_RING_NKSTAT);

	ring->mr_ksp = ksp;
}

/*
 * Per software lane tx statistics
 */
static uint64_t
i_mac_tx_swlane_stat_get(void *handle, uint_t stat)
{
	mac_soft_ring_set_t *mac_srs = (mac_soft_ring_set_t *)handle;
	mac_tx_stats_t *mac_tx_stat = &mac_srs->srs_tx.st_stat;

	switch (stat) {
	case MAC_STAT_OBYTES:
		return (mac_tx_stat->mts_obytes);

	case MAC_STAT_OPACKETS:
		return (mac_tx_stat->mts_opackets);

	case MAC_STAT_OERRORS:
		return (mac_tx_stat->mts_oerrors);

	case MAC_STAT_BLOCK:
		return (mac_tx_stat->mts_blockcnt);

	case MAC_STAT_UNBLOCK:
		return (mac_tx_stat->mts_unblockcnt);

	case MAC_STAT_TXSDROPS:
		return (mac_tx_stat->mts_sdrops);

	default:
		return (0);
	}
}

static int
i_mac_tx_swlane_stat_update(kstat_t *ksp, int rw)
{
	return (i_mac_stat_update(ksp, rw, i_mac_tx_swlane_stat_get,
	    i_mac_tx_swlane_si, MAC_TX_SWLANE_NKSTAT));
}

static void
i_mac_tx_swlane_stat_create(mac_soft_ring_set_t *mac_srs, const char *modname,
    const char *statname)
{
	kstat_t		*ksp;

	ksp = i_mac_stat_create(mac_srs, modname, statname,
	    i_mac_tx_swlane_stat_update, i_mac_tx_swlane_si,
	    MAC_TX_SWLANE_NKSTAT);

	mac_srs->srs_ksp = ksp;
}

/*
 * Per software lane rx statistics
 */
static uint64_t
i_mac_rx_swlane_stat_get(void *handle, uint_t stat)
{
	mac_soft_ring_set_t	*mac_srs = (mac_soft_ring_set_t *)handle;
	mac_rx_stats_t		*mac_rx_stat = &mac_srs->srs_rx.sr_stat;

	switch (stat) {
	case MAC_STAT_IPACKETS:
		return (mac_rx_stat->mrs_intrcnt +
		    mac_rx_stat->mrs_lclcnt);

	case MAC_STAT_RBYTES:
		return (mac_rx_stat->mrs_intrbytes +
		    mac_rx_stat->mrs_lclbytes);

	case MAC_STAT_LCL:
		return (mac_rx_stat->mrs_lclcnt);

	case MAC_STAT_LCLBYTES:
		return (mac_rx_stat->mrs_lclbytes);

	case MAC_STAT_INTRS:
		return (mac_rx_stat->mrs_intrcnt);

	case MAC_STAT_INTRBYTES:
		return (mac_rx_stat->mrs_intrbytes);

	case MAC_STAT_RXSDROPS:
		return (mac_rx_stat->mrs_sdrops);

	default:
		return (0);
	}
}

static int
i_mac_rx_swlane_stat_update(kstat_t *ksp, int rw)
{
	return (i_mac_stat_update(ksp, rw, i_mac_rx_swlane_stat_get,
	    i_mac_rx_swlane_si, MAC_RX_SWLANE_NKSTAT));
}

static void
i_mac_rx_swlane_stat_create(mac_soft_ring_set_t *mac_srs, const char *modname,
    const char *statname)
{
	kstat_t		*ksp;

	ksp = i_mac_stat_create(mac_srs, modname, statname,
	    i_mac_rx_swlane_stat_update, i_mac_rx_swlane_si,
	    MAC_RX_SWLANE_NKSTAT);

	mac_srs->srs_ksp = ksp;
}


/*
 * Per hardware lane rx statistics
 */
static uint64_t
i_mac_rx_hwlane_stat_get(void *handle, uint_t stat)
{
	mac_soft_ring_set_t	*mac_srs = (mac_soft_ring_set_t *)handle;
	mac_rx_stats_t		*mac_rx_stat = &mac_srs->srs_rx.sr_stat;

	switch (stat) {
	case MAC_STAT_IPACKETS:
		return (mac_rx_stat->mrs_intrcnt +
		    mac_rx_stat->mrs_pollcnt);

	case MAC_STAT_RBYTES:
		return (mac_rx_stat->mrs_intrbytes +
		    mac_rx_stat->mrs_pollbytes);

	case MAC_STAT_INTRS:
		return (mac_rx_stat->mrs_intrcnt);

	case MAC_STAT_INTRBYTES:
		return (mac_rx_stat->mrs_intrbytes);

	case MAC_STAT_POLLS:
		return (mac_rx_stat->mrs_pollcnt);

	case MAC_STAT_POLLBYTES:
		return (mac_rx_stat->mrs_pollbytes);

	case MAC_STAT_RXSDROPS:
		return (mac_rx_stat->mrs_sdrops);

	case MAC_STAT_CHU10:
		return (mac_rx_stat->mrs_chaincntundr10);

	case MAC_STAT_CH10T50:
		return (mac_rx_stat->mrs_chaincnt10to50);

	case MAC_STAT_CHO50:
		return (mac_rx_stat->mrs_chaincntover50);

	default:
		return (0);
	}
}

static int
i_mac_rx_hwlane_stat_update(kstat_t *ksp, int rw)
{
	return (i_mac_stat_update(ksp, rw, i_mac_rx_hwlane_stat_get,
	    i_mac_rx_hwlane_si, MAC_RX_HWLANE_NKSTAT));
}

static void
i_mac_rx_hwlane_stat_create(mac_soft_ring_set_t *mac_srs, const char *modname,
    const char *statname)
{
	kstat_t		*ksp;

	ksp = i_mac_stat_create(mac_srs, modname, statname,
	    i_mac_rx_hwlane_stat_update, i_mac_rx_hwlane_si,
	    MAC_RX_HWLANE_NKSTAT);

	mac_srs->srs_ksp = ksp;
}


/*
 * Misc statistics
 *
 * Counts for
 *	- Multicast/broadcast Rx/Tx counts
 *	- Tx errors
 */
static uint64_t
i_mac_misc_stat_get(void *handle, uint_t stat)
{
	flow_entry_t 		*flent = handle;
	mac_client_impl_t 	*mcip = flent->fe_mcip;
	mac_misc_stats_t	*mac_misc_stat = &mcip->mci_misc_stat;
	mac_rx_stats_t		*mac_rx_stat;
	mac_tx_stats_t		*mac_tx_stat;

	mac_rx_stat = &mac_misc_stat->mms_defunctrxlanestats;
	mac_tx_stat = &mac_misc_stat->mms_defuncttxlanestats;

	switch (stat) {
	case MAC_STAT_MULTIRCV:
		return (mac_misc_stat->mms_multircv);

	case MAC_STAT_BRDCSTRCV:
		return (mac_misc_stat->mms_brdcstrcv);

	case MAC_STAT_MULTIXMT:
		return (mac_misc_stat->mms_multixmt);

	case MAC_STAT_BRDCSTXMT:
		return (mac_misc_stat->mms_brdcstxmt);

	case MAC_STAT_MULTIRCVBYTES:
		return (mac_misc_stat->mms_multircvbytes);

	case MAC_STAT_BRDCSTRCVBYTES:
		return (mac_misc_stat->mms_brdcstrcvbytes);

	case MAC_STAT_MULTIXMTBYTES:
		return (mac_misc_stat->mms_multixmtbytes);

	case MAC_STAT_BRDCSTXMTBYTES:
		return (mac_misc_stat->mms_brdcstxmtbytes);

	case MAC_STAT_TX_ERRORS:
		return (mac_misc_stat->mms_txerrors);

	case MAC_STAT_MACSPOOFED:
		return (mac_misc_stat->mms_macspoofed);

	case MAC_STAT_IPSPOOFED:
		return (mac_misc_stat->mms_ipspoofed);

	case MAC_STAT_DHCPSPOOFED:
		return (mac_misc_stat->mms_dhcpspoofed);

	case MAC_STAT_RESTRICTED:
		return (mac_misc_stat->mms_restricted);

	case MAC_STAT_DHCPDROPPED:
		return (mac_misc_stat->mms_dhcpdropped);

	case MAC_STAT_IPACKETS:
		return (mac_rx_stat->mrs_intrcnt +
		    mac_rx_stat->mrs_pollcnt);

	case MAC_STAT_RBYTES:
		return (mac_rx_stat->mrs_intrbytes +
		    mac_rx_stat->mrs_pollbytes);

	case MAC_STAT_LCL:
		return (mac_rx_stat->mrs_lclcnt);

	case MAC_STAT_LCLBYTES:
		return (mac_rx_stat->mrs_lclbytes);

	case MAC_STAT_INTRS:
		return (mac_rx_stat->mrs_intrcnt);

	case MAC_STAT_INTRBYTES:
		return (mac_rx_stat->mrs_intrbytes);

	case MAC_STAT_POLLS:
		return (mac_rx_stat->mrs_pollcnt);

	case MAC_STAT_POLLBYTES:
		return (mac_rx_stat->mrs_pollbytes);

	case MAC_STAT_RXSDROPS:
		return (mac_rx_stat->mrs_sdrops);

	case MAC_STAT_CHU10:
		return (mac_rx_stat->mrs_chaincntundr10);

	case MAC_STAT_CH10T50:
		return (mac_rx_stat->mrs_chaincnt10to50);

	case MAC_STAT_CHO50:
		return (mac_rx_stat->mrs_chaincntover50);

	case MAC_STAT_OBYTES:
		return (mac_tx_stat->mts_obytes);

	case MAC_STAT_OPACKETS:
		return (mac_tx_stat->mts_opackets);

	case MAC_STAT_OERRORS:
		return (mac_tx_stat->mts_oerrors);

	case MAC_STAT_BLOCK:
		return (mac_tx_stat->mts_blockcnt);

	case MAC_STAT_UNBLOCK:
		return (mac_tx_stat->mts_unblockcnt);

	case MAC_STAT_TXSDROPS:
		return (mac_tx_stat->mts_sdrops);

	default:
		return (0);
	}
}

static int
i_mac_misc_stat_update(kstat_t *ksp, int rw)
{
	return (i_mac_stat_update(ksp, rw, i_mac_misc_stat_get,
	    i_mac_misc_si, MAC_SUMMARY_NKSTAT));
}

static void
i_mac_misc_stat_create(flow_entry_t *flent, const char *modname,
    const char *statname)
{
	kstat_t		*ksp;

	ksp = i_mac_stat_create(flent, modname, statname,
	    i_mac_misc_stat_update, i_mac_misc_si,
	    MAC_SUMMARY_NKSTAT);

	flent->fe_misc_stat_ksp = ksp;
}

/*
 * Per hardware lane tx statistics
 */
static uint64_t
i_mac_tx_hwlane_stat_get(void *handle, uint_t stat)
{
	mac_soft_ring_t	*ringp = (mac_soft_ring_t *)handle;
	mac_tx_stats_t	*mac_tx_stat = &ringp->s_st_stat;

	switch (stat) {
	case MAC_STAT_OBYTES:
		return (mac_tx_stat->mts_obytes);

	case MAC_STAT_OPACKETS:
		return (mac_tx_stat->mts_opackets);

	case MAC_STAT_OERRORS:
		return (mac_tx_stat->mts_oerrors);

	case MAC_STAT_BLOCK:
		return (mac_tx_stat->mts_blockcnt);

	case MAC_STAT_UNBLOCK:
		return (mac_tx_stat->mts_unblockcnt);

	case MAC_STAT_TXSDROPS:
		return (mac_tx_stat->mts_sdrops);

	default:
		return (0);
	}
}

static int
i_mac_tx_hwlane_stat_update(kstat_t *ksp, int rw)
{
	return (i_mac_stat_update(ksp, rw, i_mac_tx_hwlane_stat_get,
	    i_mac_tx_hwlane_si, MAC_TX_HWLANE_NKSTAT));
}

static void
i_mac_tx_hwlane_stat_create(mac_soft_ring_t *ringp, const char *modname,
    const char *statname)
{
	kstat_t		*ksp;

	ksp = i_mac_stat_create(ringp, modname, statname,
	    i_mac_tx_hwlane_stat_update, i_mac_tx_hwlane_si,
	    MAC_TX_HWLANE_NKSTAT);

	ringp->s_ring_ksp = ksp;
}

/*
 * Per fanout rx statistics
 */
static uint64_t
i_mac_rx_fanout_stat_get(void *handle, uint_t stat)
{
	mac_soft_ring_t 	*tcp_ringp = (mac_soft_ring_t *)handle;
	mac_soft_ring_t		*udp_ringp = NULL, *oth_ringp = NULL;
	mac_soft_ring_set_t 	*mac_srs = tcp_ringp->s_ring_set;
	int			index;
	uint64_t		val;

	mutex_enter(&mac_srs->srs_lock);
	/* Extract corresponding udp and oth ring pointers */
	for (index = 0; mac_srs->srs_tcp_soft_rings[index] != NULL; index++) {
		if (mac_srs->srs_tcp_soft_rings[index] == tcp_ringp) {
			udp_ringp = mac_srs->srs_udp_soft_rings[index];
			oth_ringp = mac_srs->srs_oth_soft_rings[index];
			break;
		}
	}

	ASSERT((udp_ringp != NULL) && (oth_ringp != NULL));

	switch (stat) {
	case MAC_STAT_RBYTES:
		val = (tcp_ringp->s_ring_total_rbytes) +
		    (udp_ringp->s_ring_total_rbytes) +
		    (oth_ringp->s_ring_total_rbytes);
		break;

	case MAC_STAT_IPACKETS:
		val = (tcp_ringp->s_ring_total_inpkt) +
		    (udp_ringp->s_ring_total_inpkt) +
		    (oth_ringp->s_ring_total_inpkt);
		break;

	default:
		val = 0;
		break;
	}
	mutex_exit(&mac_srs->srs_lock);
	return (val);
}

static int
i_mac_rx_fanout_stat_update(kstat_t *ksp, int rw)
{
	return (i_mac_stat_update(ksp, rw, i_mac_rx_fanout_stat_get,
	    i_mac_rx_fanout_si, MAC_RX_FANOUT_NKSTAT));
}

static void
i_mac_rx_fanout_stat_create(mac_soft_ring_t *ringp, const char *modname,
    const char *statname)
{
	kstat_t		*ksp;

	ksp = i_mac_stat_create(ringp, modname, statname,
	    i_mac_rx_fanout_stat_update, i_mac_rx_fanout_si,
	    MAC_RX_FANOUT_NKSTAT);

	ringp->s_ring_ksp = ksp;
}

/*
 * Exported functions.
 */

/*
 * Create the "mac" kstat.  The "mac" kstat is comprised of three kinds of
 * statistics: statistics maintained by the mac module itself, generic mac
 * statistics maintained by the driver, and MAC-type specific statistics
 * also maintained by the driver.
 */
void
mac_driver_stat_create(mac_impl_t *mip)
{
	kstat_t		*ksp;
	kstat_named_t	*knp;
	uint_t		count;
	major_t		major = getmajor(mip->mi_phy_dev);

	count = MAC_MOD_NKSTAT + MAC_NKSTAT + mip->mi_type->mt_statcount;
	ksp = kstat_create_zone((const char *)ddi_major_to_name(major),
	    getminor(mip->mi_phy_dev) - 1, MAC_KSTAT_NAME,
	    MAC_KSTAT_CLASS, KSTAT_TYPE_NAMED, count, 0, getzoneid());
	if (ksp == NULL)
		return;

	ksp->ks_update = i_mac_driver_stat_update;
	ksp->ks_private = mip;
	mip->mi_ksp = ksp;
	mip->mi_kstat_count = count;

	knp = (kstat_named_t *)ksp->ks_data;
	i_mac_kstat_init(knp, i_mac_mod_si, MAC_MOD_NKSTAT);
	knp += MAC_MOD_NKSTAT;
	i_mac_kstat_init(knp, i_mac_si, MAC_NKSTAT);
	if (mip->mi_type->mt_statcount > 0) {
		knp += MAC_NKSTAT;
		i_mac_kstat_init(knp, mip->mi_type->mt_stats,
		    mip->mi_type->mt_statcount);
	}

	kstat_install(ksp);
}

/*ARGSUSED*/
void
mac_driver_stat_delete(mac_impl_t *mip)
{
	if (mip->mi_ksp != NULL) {
		kstat_delete(mip->mi_ksp);
		mip->mi_ksp = NULL;
		mip->mi_kstat_count = 0;
	}
}

uint64_t
mac_driver_stat_default(mac_impl_t *mip, uint_t stat)
{
	uint_t	stat_index;

	if (IS_MAC_STAT(stat)) {
		stat_index = stat - MAC_STAT_MIN;
		ASSERT(stat_index < MAC_NKSTAT);
		return (i_mac_si[stat_index].msi_default);
	}
	ASSERT(IS_MACTYPE_STAT(stat));
	stat_index = stat - MACTYPE_STAT_MIN;
	ASSERT(stat_index < mip->mi_type->mt_statcount);
	return (mip->mi_type->mt_stats[stat_index].msi_default);
}

void
mac_ring_stat_create(mac_ring_t *ring)
{
	mac_impl_t	*mip = ring->mr_mip;
	mac_group_t	*grp = (mac_group_t *)ring->mr_gh;
	char		statname[MAXNAMELEN];
	char		modname[MAXNAMELEN];

	if (mip->mi_state_flags & MIS_IS_AGGR) {
		(void) strlcpy(modname, mip->mi_clients_list->mci_name,
		    MAXNAMELEN);
	} else
		(void) strlcpy(modname, mip->mi_name, MAXNAMELEN);

	switch (ring->mr_type) {
	case MAC_RING_TYPE_RX:
		(void) snprintf(statname, sizeof (statname),
		    "mac_rx_ring_%d_%d", grp->mrg_index, ring->mr_index);
		i_mac_rx_ring_stat_create(ring, modname, statname);
		break;

	case MAC_RING_TYPE_TX:
		(void) snprintf(statname, sizeof (statname), "mac_tx_ring%d",
		    ring->mr_index);
		i_mac_tx_ring_stat_create(ring, modname, statname);
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}
}

void
mac_srs_stat_create(mac_soft_ring_set_t *mac_srs)
{
	flow_entry_t	*flent = mac_srs->srs_flent;
	char 		statname[MAXNAMELEN];
	boolean_t	is_tx_srs;

	/* No hardware/software lanes for user defined flows */
	if ((flent->fe_type & FLOW_USER) != 0)
		return;

	is_tx_srs = ((mac_srs->srs_type & SRST_TX) != 0);

	if (is_tx_srs) {
		mac_srs_tx_t	*srs_tx = &mac_srs->srs_tx;
		mac_ring_t	*ring = srs_tx->st_arg2;

		if (ring != NULL) {
			(void) snprintf(statname, sizeof (statname),
			    "mac_tx_hwlane%d", ring->mr_index);
		} else {
			(void) snprintf(statname, sizeof (statname),
			    "mac_tx_swlane0");
		}
		i_mac_tx_swlane_stat_create(mac_srs, flent->fe_flow_name,
		    statname);
	} else {
		mac_ring_t	*ring = mac_srs->srs_ring;

		if (ring == NULL) {
			(void) snprintf(statname, sizeof (statname),
			    "mac_rx_swlane0");
			i_mac_rx_swlane_stat_create(mac_srs,
			    flent->fe_flow_name, statname);
		} else {
			(void) snprintf(statname, sizeof (statname),
			    "mac_rx_hwlane%d", ring->mr_index);
			i_mac_rx_hwlane_stat_create(mac_srs,
			    flent->fe_flow_name, statname);
		}
	}
}

void
mac_misc_stat_create(flow_entry_t *flent)
{
	char	statname[MAXNAMELEN];

	/* No misc stats for user defined or mcast/bcast flows */
	if (((flent->fe_type & FLOW_USER) != 0) ||
	    ((flent->fe_type & FLOW_MCAST) != 0))
		return;

	(void) snprintf(statname, sizeof (statname), "mac_misc_stat");
	i_mac_misc_stat_create(flent, flent->fe_flow_name, statname);
}

void
mac_soft_ring_stat_create(mac_soft_ring_t *ringp)
{
	mac_soft_ring_set_t	*mac_srs = ringp->s_ring_set;
	flow_entry_t		*flent = ringp->s_ring_mcip->mci_flent;
	mac_ring_t		*ring = (mac_ring_t *)ringp->s_ring_tx_arg2;
	boolean_t		is_tx_srs;
	char			statname[MAXNAMELEN];

	/* No hardware/software lanes for user defined flows */
	if ((flent->fe_type & FLOW_USER) != 0)
		return;

	is_tx_srs = ((mac_srs->srs_type & SRST_TX) != 0);
	if (is_tx_srs) {	/* tx side hardware lane */
		ASSERT(ring != NULL);
		(void) snprintf(statname, sizeof (statname), "mac_tx_hwlane%d",
		    ring->mr_index);
		i_mac_tx_hwlane_stat_create(ringp, flent->fe_flow_name,
		    statname);
	} else {		/* rx side fanout */
				/* Maintain single stat for (tcp, udp, oth) */
		if (ringp->s_ring_type & ST_RING_TCP) {
			int			index;
			mac_soft_ring_t		*softring;

			for (index = 0, softring = mac_srs->srs_soft_ring_head;
			    softring != NULL;
			    index++, softring = softring->s_ring_next) {
				if (softring == ringp)
					break;
			}

			if (mac_srs->srs_ring == NULL) {
				(void) snprintf(statname, sizeof (statname),
				    "mac_rx_swlane0_fanout%d", index/3);
			} else {
				(void) snprintf(statname, sizeof (statname),
				    "mac_rx_hwlane%d_fanout%d",
				    mac_srs->srs_ring->mr_index, index/3);
			}
			i_mac_rx_fanout_stat_create(ringp, flent->fe_flow_name,
			    statname);
		}
	}
}

void
mac_ring_stat_delete(mac_ring_t *ring)
{
	if (ring->mr_ksp != NULL) {
		kstat_delete(ring->mr_ksp);
		ring->mr_ksp = NULL;
	}
}

void
mac_srs_stat_delete(mac_soft_ring_set_t *mac_srs)
{
	boolean_t	is_tx_srs;

	is_tx_srs = ((mac_srs->srs_type & SRST_TX) != 0);
	if (!is_tx_srs) {
		/*
		 * Rx ring has been taken away. Before destroying corresponding
		 * SRS, save the stats recorded by that SRS.
		 */
		mac_client_impl_t	*mcip = mac_srs->srs_mcip;
		mac_misc_stats_t	*mac_misc_stat = &mcip->mci_misc_stat;
		mac_rx_stats_t		*mac_rx_stat = &mac_srs->srs_rx.sr_stat;

		i_mac_add_stats(&mac_misc_stat->mms_defunctrxlanestats,
		    mac_rx_stat, &mac_misc_stat->mms_defunctrxlanestats,
		    rx_srs_stats_list, RX_SRS_STAT_SIZE);
	}

	if (mac_srs->srs_ksp != NULL) {
		kstat_delete(mac_srs->srs_ksp);
		mac_srs->srs_ksp = NULL;
	}
}

void
mac_misc_stat_delete(flow_entry_t *flent)
{
	if (flent->fe_misc_stat_ksp != NULL) {
		kstat_delete(flent->fe_misc_stat_ksp);
		flent->fe_misc_stat_ksp = NULL;
	}
}

void
mac_soft_ring_stat_delete(mac_soft_ring_t *ringp)
{
	mac_soft_ring_set_t	*mac_srs = ringp->s_ring_set;
	boolean_t		is_tx_srs;

	is_tx_srs = ((mac_srs->srs_type & SRST_TX) != 0);
	if (is_tx_srs) {
		/*
		 * Tx ring has been taken away. Before destroying corresponding
		 * soft ring, save the stats recorded by that soft ring.
		 */
		mac_client_impl_t	*mcip = mac_srs->srs_mcip;
		mac_misc_stats_t	*mac_misc_stat = &mcip->mci_misc_stat;
		mac_tx_stats_t		*mac_tx_stat = &ringp->s_st_stat;

		i_mac_add_stats(&mac_misc_stat->mms_defuncttxlanestats,
		    mac_tx_stat, &mac_misc_stat->mms_defuncttxlanestats,
		    tx_softring_stats_list, TX_SOFTRING_STAT_SIZE);
	}

	if (ringp->s_ring_ksp) {
		kstat_delete(ringp->s_ring_ksp);
		ringp->s_ring_ksp = NULL;
	}
}

void
mac_pseudo_ring_stat_rename(mac_impl_t *mip)
{
	mac_group_t	*group;
	mac_ring_t	*ring;

	/* Recreate pseudo rx ring kstats */
	for (group = mip->mi_rx_groups; group != NULL;
	    group = group->mrg_next) {
		for (ring = group->mrg_rings; ring != NULL;
		    ring = ring->mr_next) {
			mac_ring_stat_delete(ring);
			mac_ring_stat_create(ring);
		}
	}

	/* Recreate pseudo tx ring kstats */
	for (group = mip->mi_tx_groups; group != NULL;
	    group = group->mrg_next) {
		for (ring = group->mrg_rings; ring != NULL;
		    ring = ring->mr_next) {
			mac_ring_stat_delete(ring);
			mac_ring_stat_create(ring);
		}
	}
}

void
mac_stat_rename(mac_client_impl_t *mcip)
{
	flow_entry_t		*flent = mcip->mci_flent;
	mac_soft_ring_set_t	*mac_srs;
	mac_soft_ring_t		*ringp;
	int			i, j;

	ASSERT(flent != NULL);

	/* Recreate rx SRSes kstats */
	for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
		mac_srs = (mac_soft_ring_set_t *)flent->fe_rx_srs[i];
		mac_srs_stat_delete(mac_srs);
		mac_srs_stat_create(mac_srs);

		/* Recreate rx fanout kstats */
		for (j = 0; j < mac_srs->srs_tcp_ring_count; j++) {
			ringp = mac_srs->srs_tcp_soft_rings[j];
			mac_soft_ring_stat_delete(ringp);
			mac_soft_ring_stat_create(ringp);
		}
	}

	/* Recreate tx SRS kstats */
	mac_srs = (mac_soft_ring_set_t *)flent->fe_tx_srs;
	mac_srs_stat_delete(mac_srs);
	mac_srs_stat_create(mac_srs);

	/* Recreate tx sofring kstats */
	for (ringp = mac_srs->srs_soft_ring_head; ringp;
	    ringp = ringp->s_ring_next) {
		mac_soft_ring_stat_delete(ringp);
		mac_soft_ring_stat_create(ringp);
	}

	/* Recreate misc kstats */
	mac_misc_stat_delete(flent);
	mac_misc_stat_create(flent);
}

void
mac_tx_srs_stat_recreate(mac_soft_ring_set_t *tx_srs, boolean_t add_stats)
{
	mac_client_impl_t	*mcip = tx_srs->srs_mcip;
	mac_misc_stats_t	*mac_misc_stat = &mcip->mci_misc_stat;
	mac_tx_stats_t		*mac_tx_stat = &tx_srs->srs_tx.st_stat;

	if (add_stats) {
		/* Add the stats to cumulative stats */
		i_mac_add_stats(&mac_misc_stat->mms_defuncttxlanestats,
		    mac_tx_stat, &mac_misc_stat->mms_defuncttxlanestats,
		    tx_softring_stats_list, TX_SOFTRING_STAT_SIZE);
	}

	bzero(mac_tx_stat, sizeof (mac_tx_stats_t));
	mac_srs_stat_delete(tx_srs);
	mac_srs_stat_create(tx_srs);
}
