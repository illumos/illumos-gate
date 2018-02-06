/*	$NetBSD: if_iwn.c,v 1.78 2016/06/10 13:27:14 ozaki-r Exp $	*/
/*	$OpenBSD: if_iwn.c,v 1.135 2014/09/10 07:22:09 dcoppa Exp $	*/

/*-
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright 2016 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

/*
 * Driver for Intel WiFi Link 4965 and 100/1000/2000/5000/6000 Series 802.11
 * network adapters.
 */

/*
 * TODO:
 * - turn tunables into driver properties
 */

#undef IWN_HWCRYPTO	/* XXX does not even compile yet */

#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>

#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/conf.h>

#include <sys/pci.h>
#include <sys/pcie.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>

#include <sys/dlpi.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#include <sys/firmload.h>
#include <sys/queue.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kstat.h>

#include <sys/sdt.h>

#include "if_iwncompat.h"
#include "if_iwnreg.h"
#include "if_iwnvar.h"
#include <inet/wifi_ioctl.h>

#ifdef DEBUG
#define IWN_DEBUG
#endif

/*
 * regs access attributes
 */
static ddi_device_acc_attr_t iwn_reg_accattr = {
	.devacc_attr_version	= DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder	= DDI_STRICTORDER_ACC,
	.devacc_attr_access	= DDI_DEFAULT_ACC
};

/*
 * DMA access attributes for descriptor
 */
static ddi_device_acc_attr_t iwn_dma_descattr = {
	.devacc_attr_version	= DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder	= DDI_STRICTORDER_ACC,
	.devacc_attr_access	= DDI_DEFAULT_ACC
};

/*
 * DMA access attributes
 */
static ddi_device_acc_attr_t iwn_dma_accattr = {
	.devacc_attr_version	= DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder	= DDI_STRICTORDER_ACC,
	.devacc_attr_access	= DDI_DEFAULT_ACC
};


/*
 * Supported rates for 802.11a/b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset iwn_rateset_11a =
	{ 8, { 12, 18, 24, 36, 48, 72, 96, 108 } };

static const struct ieee80211_rateset iwn_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset iwn_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

static void	iwn_kstat_create(struct iwn_softc *, const char *, size_t,
    kstat_t **, void **);
static void	iwn_kstat_free(kstat_t *, void *, size_t);
static void	iwn_kstat_init(struct iwn_softc *);
static void	iwn_kstat_init_2000(struct iwn_softc *);
static void	iwn_kstat_init_4965(struct iwn_softc *);
static void	iwn_kstat_init_6000(struct iwn_softc *);
static void	iwn_intr_teardown(struct iwn_softc *);
static int	iwn_intr_add(struct iwn_softc *, int);
static int	iwn_intr_setup(struct iwn_softc *);
static int	iwn_attach(dev_info_t *, ddi_attach_cmd_t);
static int	iwn4965_attach(struct iwn_softc *);
static int	iwn5000_attach(struct iwn_softc *, uint16_t);
static int	iwn_detach(dev_info_t *, ddi_detach_cmd_t);
static int	iwn_quiesce(dev_info_t *);
static int	iwn_nic_lock(struct iwn_softc *);
static int	iwn_eeprom_lock(struct iwn_softc *);
static int	iwn_init_otprom(struct iwn_softc *);
static int	iwn_read_prom_data(struct iwn_softc *, uint32_t, void *, int);
static int	iwn_dma_contig_alloc(struct iwn_softc *, struct iwn_dma_info *,
    uint_t, uint_t, void **, ddi_device_acc_attr_t *, uint_t);
static void	iwn_dma_contig_free(struct iwn_dma_info *);
static int	iwn_alloc_sched(struct iwn_softc *);
static void	iwn_free_sched(struct iwn_softc *);
static int	iwn_alloc_kw(struct iwn_softc *);
static void	iwn_free_kw(struct iwn_softc *);
static int	iwn_alloc_ict(struct iwn_softc *);
static void	iwn_free_ict(struct iwn_softc *);
static int	iwn_alloc_fwmem(struct iwn_softc *);
static void	iwn_free_fwmem(struct iwn_softc *);
static int	iwn_alloc_rx_ring(struct iwn_softc *, struct iwn_rx_ring *);
static void	iwn_reset_rx_ring(struct iwn_softc *, struct iwn_rx_ring *);
static void	iwn_free_rx_ring(struct iwn_softc *, struct iwn_rx_ring *);
static int	iwn_alloc_tx_ring(struct iwn_softc *, struct iwn_tx_ring *,
		    int);
static void	iwn_reset_tx_ring(struct iwn_softc *, struct iwn_tx_ring *);
static void	iwn_free_tx_ring(struct iwn_softc *, struct iwn_tx_ring *);
static void	iwn5000_ict_reset(struct iwn_softc *);
static int	iwn_read_eeprom(struct iwn_softc *);
static void	iwn4965_read_eeprom(struct iwn_softc *);

#ifdef IWN_DEBUG
static void	iwn4965_print_power_group(struct iwn_softc *, int);
#endif
static void	iwn5000_read_eeprom(struct iwn_softc *);
static void	iwn_read_eeprom_channels(struct iwn_softc *, int, uint32_t);
static void	iwn_read_eeprom_enhinfo(struct iwn_softc *);
static struct	ieee80211_node *iwn_node_alloc(ieee80211com_t *);
static void	iwn_node_free(ieee80211_node_t *);
static void	iwn_newassoc(struct ieee80211_node *, int);
static int	iwn_newstate(struct ieee80211com *, enum ieee80211_state, int);
static void	iwn_iter_func(void *, struct ieee80211_node *);
static void	iwn_calib_timeout(void *);
static void	iwn_rx_phy(struct iwn_softc *, struct iwn_rx_desc *,
		    struct iwn_rx_data *);
static void	iwn_rx_done(struct iwn_softc *, struct iwn_rx_desc *,
		    struct iwn_rx_data *);
#ifndef IEEE80211_NO_HT
static void	iwn_rx_compressed_ba(struct iwn_softc *, struct iwn_rx_desc *,
		    struct iwn_rx_data *);
#endif
static void	iwn5000_rx_calib_results(struct iwn_softc *,
		    struct iwn_rx_desc *, struct iwn_rx_data *);
static void	iwn_rx_statistics(struct iwn_softc *, struct iwn_rx_desc *,
		    struct iwn_rx_data *);
static void	iwn4965_tx_done(struct iwn_softc *, struct iwn_rx_desc *,
		    struct iwn_rx_data *);
static void	iwn5000_tx_done(struct iwn_softc *, struct iwn_rx_desc *,
		    struct iwn_rx_data *);
static void	iwn_tx_done(struct iwn_softc *, struct iwn_rx_desc *, int,
		    uint8_t);
static void	iwn_cmd_done(struct iwn_softc *, struct iwn_rx_desc *);
static void	iwn_notif_intr(struct iwn_softc *);
static void	iwn_wakeup_intr(struct iwn_softc *);
static void	iwn_fatal_intr(struct iwn_softc *);
static uint_t	iwn_intr(caddr_t, caddr_t);
static void	iwn4965_update_sched(struct iwn_softc *, int, int, uint8_t,
		    uint16_t);
static void	iwn5000_update_sched(struct iwn_softc *, int, int, uint8_t,
		    uint16_t);
#ifdef notyet
static void	iwn5000_reset_sched(struct iwn_softc *, int, int);
#endif
static int	iwn_send(ieee80211com_t *, mblk_t *, uint8_t);
static void	iwn_watchdog(void *);
static int	iwn_cmd(struct iwn_softc *, uint8_t, void *, int, int);
static int	iwn4965_add_node(struct iwn_softc *, struct iwn_node_info *,
		    int);
static int	iwn5000_add_node(struct iwn_softc *, struct iwn_node_info *,
		    int);
static int	iwn_set_link_quality(struct iwn_softc *,
		    struct ieee80211_node *);
static int	iwn_add_broadcast_node(struct iwn_softc *, int);
static void	iwn_set_led(struct iwn_softc *, uint8_t, uint8_t, uint8_t);
static int	iwn_set_critical_temp(struct iwn_softc *);
static int	iwn_set_timing(struct iwn_softc *, struct ieee80211_node *);
static void	iwn4965_power_calibration(struct iwn_softc *, int);
static int	iwn4965_set_txpower(struct iwn_softc *, int);
static int	iwn5000_set_txpower(struct iwn_softc *, int);
static int	iwn4965_get_rssi(const struct iwn_rx_stat *);
static int	iwn5000_get_rssi(const struct iwn_rx_stat *);
static int	iwn_get_noise(const struct iwn_rx_general_stats *);
static int	iwn4965_get_temperature(struct iwn_softc *);
static int	iwn5000_get_temperature(struct iwn_softc *);
static int	iwn_init_sensitivity(struct iwn_softc *);
static void	iwn_collect_noise(struct iwn_softc *,
		    const struct iwn_rx_general_stats *);
static int	iwn4965_init_gains(struct iwn_softc *);
static int	iwn5000_init_gains(struct iwn_softc *);
static int	iwn4965_set_gains(struct iwn_softc *);
static int	iwn5000_set_gains(struct iwn_softc *);
static void	iwn_tune_sensitivity(struct iwn_softc *,
		    const struct iwn_rx_stats *);
static int	iwn_send_sensitivity(struct iwn_softc *);
static int	iwn_set_pslevel(struct iwn_softc *, int, int, int);
static int	iwn5000_runtime_calib(struct iwn_softc *);

static int	iwn_config_bt_coex_bluetooth(struct iwn_softc *);
static int	iwn_config_bt_coex_prio_table(struct iwn_softc *);
static int	iwn_config_bt_coex_adv1(struct iwn_softc *);
static int	iwn_config_bt_coex_adv2(struct iwn_softc *);

static int	iwn_config(struct iwn_softc *);
static uint16_t	iwn_get_active_dwell_time(struct iwn_softc *, uint16_t,
		    uint8_t);
static uint16_t	iwn_limit_dwell(struct iwn_softc *, uint16_t);
static uint16_t	iwn_get_passive_dwell_time(struct iwn_softc *, uint16_t);
static int	iwn_scan(struct iwn_softc *, uint16_t);
static int	iwn_auth(struct iwn_softc *);
static int	iwn_run(struct iwn_softc *);
#ifdef IWN_HWCRYPTO
static int	iwn_set_key(struct ieee80211com *, struct ieee80211_node *,
		    struct ieee80211_key *);
static void	iwn_delete_key(struct ieee80211com *, struct ieee80211_node *,
		    struct ieee80211_key *);
#endif
static int	iwn_wme_update(struct ieee80211com *);
#ifndef IEEE80211_NO_HT
static int	iwn_ampdu_rx_start(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
static void	iwn_ampdu_rx_stop(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
static int	iwn_ampdu_tx_start(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
static void	iwn_ampdu_tx_stop(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
static void	iwn4965_ampdu_tx_start(struct iwn_softc *,
		    struct ieee80211_node *, uint8_t, uint16_t);
static void	iwn4965_ampdu_tx_stop(struct iwn_softc *,
		    uint8_t, uint16_t);
static void	iwn5000_ampdu_tx_start(struct iwn_softc *,
		    struct ieee80211_node *, uint8_t, uint16_t);
static void	iwn5000_ampdu_tx_stop(struct iwn_softc *,
		    uint8_t, uint16_t);
#endif
static int	iwn5000_query_calibration(struct iwn_softc *);
static int	iwn5000_send_calibration(struct iwn_softc *);
static int	iwn5000_send_wimax_coex(struct iwn_softc *);
static int	iwn6000_temp_offset_calib(struct iwn_softc *);
static int	iwn2000_temp_offset_calib(struct iwn_softc *);
static int	iwn4965_post_alive(struct iwn_softc *);
static int	iwn5000_post_alive(struct iwn_softc *);
static int	iwn4965_load_bootcode(struct iwn_softc *, const uint8_t *,
		    int);
static int	iwn4965_load_firmware(struct iwn_softc *);
static int	iwn5000_load_firmware_section(struct iwn_softc *, uint32_t,
		    const uint8_t *, int);
static int	iwn5000_load_firmware(struct iwn_softc *);
static int	iwn_read_firmware_leg(struct iwn_softc *,
		    struct iwn_fw_info *);
static int	iwn_read_firmware_tlv(struct iwn_softc *,
		    struct iwn_fw_info *, uint16_t);
static int	iwn_read_firmware(struct iwn_softc *);
static int	iwn_clock_wait(struct iwn_softc *);
static int	iwn_apm_init(struct iwn_softc *);
static void	iwn_apm_stop_master(struct iwn_softc *);
static void	iwn_apm_stop(struct iwn_softc *);
static int	iwn4965_nic_config(struct iwn_softc *);
static int	iwn5000_nic_config(struct iwn_softc *);
static int	iwn_hw_prepare(struct iwn_softc *);
static int	iwn_hw_init(struct iwn_softc *);
static void	iwn_hw_stop(struct iwn_softc *, boolean_t);
static int	iwn_init(struct iwn_softc *);
static void	iwn_abort_scan(void *);
static void	iwn_periodic(void *);
static int	iwn_fast_recover(struct iwn_softc *);

static uint8_t	*ieee80211_add_ssid(uint8_t *, const uint8_t *, uint32_t);
static uint8_t	*ieee80211_add_rates(uint8_t *,
    const struct ieee80211_rateset *);
static uint8_t	*ieee80211_add_xrates(uint8_t *,
    const struct ieee80211_rateset *);

static void	iwn_fix_channel(struct iwn_softc *, mblk_t *,
		    struct iwn_rx_stat *);

#ifdef IWN_DEBUG

#define	IWN_DBG(...)	iwn_dbg("?" __VA_ARGS__)

static int iwn_dbg_print = 0;

static void
iwn_dbg(const char *fmt, ...)
{
	va_list	ap;

	if (iwn_dbg_print != 0) {
		va_start(ap, fmt);
		vcmn_err(CE_CONT, fmt, ap);
		va_end(ap);
	}
}

#else
#define	IWN_DBG(...)
#endif

/*
 * tunables
 */

/*
 * enable 5GHz scanning
 */
int iwn_enable_5ghz = 1;

/*
 * If more than 50 consecutive beacons are missed,
 * we've probably lost our connection.
 * If more than 5 consecutive beacons are missed,
 * reinitialize the sensitivity state machine.
 */
int iwn_beacons_missed_disconnect = 50;
int iwn_beacons_missed_sensitivity = 5;

/*
 * iwn_periodic interval, in units of msec
 */
int iwn_periodic_interval = 100;

/*
 * scan timeout in sec
 */
int iwn_scan_timeout = 20;

static ether_addr_t etherbroadcastaddr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void *iwn_state = NULL;

/*
 * Mac Call Back entries
 */
static int	iwn_m_stat(void *, uint_t, uint64_t *);
static int	iwn_m_start(void *);
static void	iwn_m_stop(void *);
static int	iwn_m_unicst(void *, const uint8_t *);
static int	iwn_m_multicst(void *, boolean_t, const uint8_t *);
static int	iwn_m_promisc(void *, boolean_t);
static mblk_t	*iwn_m_tx(void *, mblk_t *);
static void	iwn_m_ioctl(void *, queue_t *, mblk_t *);
static int	iwn_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static int	iwn_m_getprop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static void	iwn_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

mac_callbacks_t	iwn_m_callbacks = {
	.mc_callbacks	= MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	.mc_getstat	= iwn_m_stat,
	.mc_start	= iwn_m_start,
	.mc_stop	= iwn_m_stop,
	.mc_setpromisc	= iwn_m_promisc,
	.mc_multicst	= iwn_m_multicst,
	.mc_unicst	= iwn_m_unicst,
	.mc_tx		= iwn_m_tx,
	.mc_reserved	= NULL,
	.mc_ioctl	= iwn_m_ioctl,
	.mc_getcapab	= NULL,
	.mc_open	= NULL,
	.mc_close	= NULL,
	.mc_setprop	= iwn_m_setprop,
	.mc_getprop	= iwn_m_getprop,
	.mc_propinfo	= iwn_m_propinfo
};

static inline uint32_t
iwn_read(struct iwn_softc *sc, int reg)
{
	/*LINTED: E_PTR_BAD_CAST_ALIGN*/
	return (ddi_get32(sc->sc_regh, (uint32_t *)(sc->sc_base + reg)));
}

static inline void
iwn_write(struct iwn_softc *sc, int reg, uint32_t val)
{
	/*LINTED: E_PTR_BAD_CAST_ALIGN*/
	ddi_put32(sc->sc_regh, (uint32_t *)(sc->sc_base + reg), val);
}

static inline void
iwn_write_1(struct iwn_softc *sc, int reg, uint8_t val)
{
	ddi_put8(sc->sc_regh, (uint8_t *)(sc->sc_base + reg), val);
}

static void
iwn_kstat_create(struct iwn_softc *sc, const char *name, size_t size,
    kstat_t **ks, void **data)
{
	*ks = kstat_create(ddi_driver_name(sc->sc_dip),
	    ddi_get_instance(sc->sc_dip), name, "misc", KSTAT_TYPE_NAMED,
	    size / sizeof (kstat_named_t), 0);
	if (*ks == NULL)
		*data = kmem_zalloc(size, KM_SLEEP);
	else
		*data = (*ks)->ks_data;
}

static void
iwn_kstat_free(kstat_t *ks, void *data, size_t size)
{
	if (ks != NULL)
		kstat_delete(ks);
	else if (data != NULL)
		kmem_free(data, size);
}

static void
iwn_kstat_init(struct iwn_softc *sc)
{
	if (sc->sc_ks_misc != NULL)
		sc->sc_ks_misc->ks_lock = &sc->sc_mtx;
	if (sc->sc_ks_ant != NULL)
		sc->sc_ks_ant->ks_lock = &sc->sc_mtx;
	if (sc->sc_ks_sens != NULL)
		sc->sc_ks_sens->ks_lock = &sc->sc_mtx;
	if (sc->sc_ks_timing != NULL)
		sc->sc_ks_timing->ks_lock = &sc->sc_mtx;
	if (sc->sc_ks_edca != NULL)
		sc->sc_ks_edca->ks_lock = &sc->sc_mtx;

	kstat_named_init(&sc->sc_misc->temp,
	    "temperature", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_misc->crit_temp,
	    "critical temperature", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_misc->pslevel,
	    "power saving level", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_misc->noise,
	    "noise", KSTAT_DATA_LONG);


	kstat_named_init(&sc->sc_ant->tx_ant,
	    "TX mask", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_ant->rx_ant,
	    "RX mask", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_ant->conn_ant,
	    "connected mask", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_ant->gain[0],
	    "gain A", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_ant->gain[1],
	    "gain B", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_ant->gain[2],
	    "gain C", KSTAT_DATA_ULONG);

	kstat_named_init(&sc->sc_sens->ofdm_x1,
	    "OFDM X1", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_sens->ofdm_mrc_x1,
	    "OFDM MRC X1", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_sens->ofdm_x4,
	    "OFDM X4", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_sens->ofdm_mrc_x4,
	    "OFDM MRC X4", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_sens->cck_x4,
	    "CCK X4", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_sens->cck_mrc_x4,
	    "CCK MRC X4", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_sens->energy_cck,
	    "energy CCK", KSTAT_DATA_ULONG);

	kstat_named_init(&sc->sc_timing->bintval,
	    "bintval", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_timing->tstamp,
	    "timestamp", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&sc->sc_timing->init,
	    "init", KSTAT_DATA_ULONG);

	kstat_named_init(&sc->sc_edca->ac[0].cwmin,
	    "background cwmin", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[0].cwmax,
	    "background cwmax", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[0].aifsn,
	    "background aifsn", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[0].txop,
	    "background txop", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[1].cwmin,
	    "best effort cwmin", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[1].cwmax,
	    "best effort cwmax", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[1].aifsn,
	    "best effort aifsn", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[1].txop,
	    "best effort txop", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[2].cwmin,
	    "video cwmin", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[2].cwmax,
	    "video cwmax", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[2].aifsn,
	    "video aifsn", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[2].txop,
	    "video txop", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[3].cwmin,
	    "voice cwmin", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[3].cwmax,
	    "voice cwmax", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[3].aifsn,
	    "voice aifsn", KSTAT_DATA_ULONG);
	kstat_named_init(&sc->sc_edca->ac[3].txop,
	    "voice txop", KSTAT_DATA_ULONG);
}

static void
iwn_kstat_init_2000(struct iwn_softc *sc)
{
	if (sc->sc_ks_toff != NULL)
		sc->sc_ks_toff->ks_lock = &sc->sc_mtx;

	kstat_named_init(&sc->sc_toff.t2000->toff_lo,
	    "temperature offset low", KSTAT_DATA_LONG);
	kstat_named_init(&sc->sc_toff.t2000->toff_hi,
	    "temperature offset high", KSTAT_DATA_LONG);
	kstat_named_init(&sc->sc_toff.t2000->volt,
	    "reference voltage", KSTAT_DATA_LONG);
}

static void
iwn_kstat_init_4965(struct iwn_softc *sc)
{
	int i, r;

	if (sc->sc_ks_txpower != NULL)
		sc->sc_ks_txpower->ks_lock = &sc->sc_mtx;

	kstat_named_init(&sc->sc_txpower->vdiff,
	    "voltage comp", KSTAT_DATA_LONG);
	kstat_named_init(&sc->sc_txpower->chan,
	    "channel", KSTAT_DATA_LONG);
	kstat_named_init(&sc->sc_txpower->group,
	    "attenuation group", KSTAT_DATA_LONG);
	kstat_named_init(&sc->sc_txpower->subband,
	    "sub-band", KSTAT_DATA_LONG);
	for (i = 0; i != 2; i++) {
		char tmp[KSTAT_STRLEN];

		(void) snprintf(tmp, KSTAT_STRLEN - 1, "Ant %d power", i);
		kstat_named_init(&sc->sc_txpower->txchain[i].power,
		    tmp, KSTAT_DATA_LONG);

		(void) snprintf(tmp, KSTAT_STRLEN - 1, "Ant %d gain", i);
		kstat_named_init(&sc->sc_txpower->txchain[i].gain,
		    tmp, KSTAT_DATA_LONG);

		(void) snprintf(tmp, KSTAT_STRLEN - 1, "Ant %d temperature", i);
		kstat_named_init(&sc->sc_txpower->txchain[i].temp,
		    tmp, KSTAT_DATA_LONG);

		(void) snprintf(tmp, KSTAT_STRLEN - 1,
		    "Ant %d temperature compensation", i);
		kstat_named_init(&sc->sc_txpower->txchain[i].tcomp,
		    tmp, KSTAT_DATA_LONG);

		for (r = 0; r <= IWN_RIDX_MAX; r++) {
			(void) snprintf(tmp, KSTAT_STRLEN - 1,
			    "Ant %d Rate %d RF gain", i, r);
			kstat_named_init(
			    &sc->sc_txpower->txchain[i].rate[r].rf_gain,
			    tmp, KSTAT_DATA_LONG);

			(void) snprintf(tmp, KSTAT_STRLEN - 1,
			    "Ant %d Rate %d DSP gain", i, r);
			kstat_named_init(
			    &sc->sc_txpower->txchain[0].rate[0].dsp_gain,
			    tmp, KSTAT_DATA_LONG);
		}
	}
}

static void
iwn_kstat_init_6000(struct iwn_softc *sc)
{
	if (sc->sc_ks_toff != NULL)
		sc->sc_ks_toff->ks_lock = &sc->sc_mtx;

	kstat_named_init(&sc->sc_toff.t6000->toff,
	    "temperature offset", KSTAT_DATA_LONG);
}

static void
iwn_intr_teardown(struct iwn_softc *sc)
{
	if (sc->sc_intr_htable != NULL) {
		if ((sc->sc_intr_cap & DDI_INTR_FLAG_BLOCK) != 0) {
			(void) ddi_intr_block_disable(sc->sc_intr_htable,
			    sc->sc_intr_count);
		} else {
			(void) ddi_intr_disable(sc->sc_intr_htable[0]);
		}
		(void) ddi_intr_remove_handler(sc->sc_intr_htable[0]);
		(void) ddi_intr_free(sc->sc_intr_htable[0]);
		sc->sc_intr_htable[0] = NULL;

		kmem_free(sc->sc_intr_htable, sc->sc_intr_size);
		sc->sc_intr_size = 0;
		sc->sc_intr_htable = NULL;
	}
}

static int
iwn_intr_add(struct iwn_softc *sc, int intr_type)
{
	int ni, na;
	int ret;
	char *func;

	if (ddi_intr_get_nintrs(sc->sc_dip, intr_type, &ni) != DDI_SUCCESS)
		return (DDI_FAILURE);


	if (ddi_intr_get_navail(sc->sc_dip, intr_type, &na) != DDI_SUCCESS)
		return (DDI_FAILURE);

	sc->sc_intr_size = sizeof (ddi_intr_handle_t);
	sc->sc_intr_htable = kmem_zalloc(sc->sc_intr_size, KM_SLEEP);

	ret = ddi_intr_alloc(sc->sc_dip, sc->sc_intr_htable, intr_type, 0, 1,
	    &sc->sc_intr_count, DDI_INTR_ALLOC_STRICT);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!ddi_intr_alloc() failed");
		return (DDI_FAILURE);
	}

	ret = ddi_intr_get_pri(sc->sc_intr_htable[0], &sc->sc_intr_pri);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!ddi_intr_get_pri() failed");
		return (DDI_FAILURE);
	}

	ret = ddi_intr_add_handler(sc->sc_intr_htable[0], iwn_intr, (caddr_t)sc,
	    NULL);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!ddi_intr_add_handler() failed");
		return (DDI_FAILURE);
	}

	ret = ddi_intr_get_cap(sc->sc_intr_htable[0], &sc->sc_intr_cap);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!ddi_intr_get_cap() failed");
		return (DDI_FAILURE);
	}

	if ((sc->sc_intr_cap & DDI_INTR_FLAG_BLOCK) != 0) {
		ret = ddi_intr_block_enable(sc->sc_intr_htable,
		    sc->sc_intr_count);
		func = "ddi_intr_enable_block";
	} else {
		ret = ddi_intr_enable(sc->sc_intr_htable[0]);
		func = "ddi_intr_enable";
	}

	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!%s() failed", func);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
iwn_intr_setup(struct iwn_softc *sc)
{
	int intr_type;
	int ret;

	ret = ddi_intr_get_supported_types(sc->sc_dip, &intr_type);
	if (ret != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!ddi_intr_get_supported_types() failed");
		return (DDI_FAILURE);
	}

	if ((intr_type & DDI_INTR_TYPE_MSIX)) {
		if (iwn_intr_add(sc, DDI_INTR_TYPE_MSIX) == DDI_SUCCESS)
			return (DDI_SUCCESS);
		iwn_intr_teardown(sc);
	}

	if ((intr_type & DDI_INTR_TYPE_MSI)) {
		if (iwn_intr_add(sc, DDI_INTR_TYPE_MSI) == DDI_SUCCESS)
			return (DDI_SUCCESS);
		iwn_intr_teardown(sc);
	}

	if ((intr_type & DDI_INTR_TYPE_FIXED)) {
		if (iwn_intr_add(sc, DDI_INTR_TYPE_FIXED) == DDI_SUCCESS)
			return (DDI_SUCCESS);
		iwn_intr_teardown(sc);
	}

	dev_err(sc->sc_dip, CE_WARN, "!iwn_intr_setup() failed");
	return (DDI_FAILURE);
}

static int
iwn_pci_get_capability(ddi_acc_handle_t pcih, int cap, int *cap_off)
{
	uint8_t ptr;
	uint8_t val;

	for (ptr = pci_config_get8(pcih, PCI_CONF_CAP_PTR);
	    ptr != 0 && ptr != 0xff;
	    ptr = pci_config_get8(pcih, ptr + PCI_CAP_NEXT_PTR)) {
		val = pci_config_get8(pcih, ptr + PCIE_CAP_ID);
		if (val == 0xff)
			return (DDI_FAILURE);

		if (cap != val)
			continue;

		*cap_off = ptr;
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
iwn_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;

	struct iwn_softc *sc;
	struct ieee80211com *ic;
	char strbuf[32];
	wifi_data_t wd = { 0 };
	mac_register_t *macp;
	uint32_t reg;
	int i, error;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		instance = ddi_get_instance(dip);
		sc = ddi_get_soft_state(iwn_state,
		    instance);
		ASSERT(sc != NULL);

		if (sc->sc_flags & IWN_FLAG_RUNNING) {
			(void) iwn_init(sc);
		}

		sc->sc_flags &= ~IWN_FLAG_SUSPEND;

		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(iwn_state, instance) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "!ddi_soft_state_zalloc() failed");
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(iwn_state, instance);
	ddi_set_driver_private(dip, (caddr_t)sc);

	ic = &sc->sc_ic;

	sc->sc_dip = dip;

	iwn_kstat_create(sc, "hw_state", sizeof (struct iwn_ks_misc),
	    &sc->sc_ks_misc, (void **)&sc->sc_misc);
	iwn_kstat_create(sc, "antennas", sizeof (struct iwn_ks_ant),
	    &sc->sc_ks_ant, (void **)&sc->sc_ant);
	iwn_kstat_create(sc, "sensitivity", sizeof (struct iwn_ks_sens),
	    &sc->sc_ks_sens, (void **)&sc->sc_sens);
	iwn_kstat_create(sc, "timing", sizeof (struct iwn_ks_timing),
	    &sc->sc_ks_timing, (void **)&sc->sc_timing);
	iwn_kstat_create(sc, "edca", sizeof (struct iwn_ks_edca),
	    &sc->sc_ks_edca, (void **)&sc->sc_edca);

	if (pci_config_setup(dip, &sc->sc_pcih) != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!pci_config_setup() failed");
		goto fail_pci_config;
	}

	/*
	 * Get the offset of the PCI Express Capability Structure in PCI
	 * Configuration Space.
	 */
	error = iwn_pci_get_capability(sc->sc_pcih, PCI_CAP_ID_PCI_E,
	    &sc->sc_cap_off);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!PCIe capability structure not found!");
		goto fail_pci_capab;
	}

	/* Clear device-specific "PCI retry timeout" register (41h). */
	reg = pci_config_get8(sc->sc_pcih, 0x41);
	if (reg)
		pci_config_put8(sc->sc_pcih, 0x41, 0);

	error = ddi_regs_map_setup(dip, 1, &sc->sc_base, 0, 0, &iwn_reg_accattr,
	    &sc->sc_regh);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!ddi_regs_map_setup() failed");
		goto fail_regs_map;
	}

	/* Clear pending interrupts. */
	IWN_WRITE(sc, IWN_INT, 0xffffffff);

	/* Disable all interrupts. */
	IWN_WRITE(sc, IWN_INT_MASK, 0);

	/* Install interrupt handler. */
	if (iwn_intr_setup(sc) != DDI_SUCCESS)
		goto fail_intr;

	mutex_init(&sc->sc_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->sc_intr_pri));
	mutex_init(&sc->sc_tx_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->sc_intr_pri));
	mutex_init(&sc->sc_mt_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->sc_intr_pri));

	cv_init(&sc->sc_cmd_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->sc_scan_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->sc_fhdma_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->sc_alive_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->sc_calib_cv, NULL, CV_DRIVER, NULL);

	iwn_kstat_init(sc);

	/* Read hardware revision and attach. */
	sc->hw_type =
	    (IWN_READ(sc, IWN_HW_REV) & IWN_HW_REV_TYPE_MASK)
	      >> IWN_HW_REV_TYPE_SHIFT;
	if (sc->hw_type == IWN_HW_REV_TYPE_4965)
		error = iwn4965_attach(sc);
	else
		error = iwn5000_attach(sc, sc->sc_devid);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!could not attach device");
		goto fail_hw;
	}

	if ((error = iwn_hw_prepare(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!hardware not ready");
		goto fail_hw;
	}

	/* Read MAC address, channels, etc from EEPROM. */
	if ((error = iwn_read_eeprom(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!could not read EEPROM");
		goto fail_hw;
	}

	/* Allocate DMA memory for firmware transfers. */
	if ((error = iwn_alloc_fwmem(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not allocate memory for firmware");
		goto fail_fwmem;
	}

	/* Allocate "Keep Warm" page. */
	if ((error = iwn_alloc_kw(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not allocate keep warm page");
		goto fail_kw;
	}

	/* Allocate ICT table for 5000 Series. */
	if (sc->hw_type != IWN_HW_REV_TYPE_4965 &&
	    (error = iwn_alloc_ict(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!could not allocate ICT table");
		goto fail_ict;
	}

	/* Allocate TX scheduler "rings". */
	if ((error = iwn_alloc_sched(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not allocate TX scheduler rings");
		goto fail_sched;
	}

	/* Allocate TX rings (16 on 4965AGN, 20 on >=5000). */
	for (i = 0; i < sc->ntxqs; i++) {
		if ((error = iwn_alloc_tx_ring(sc, &sc->txq[i], i)) != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not allocate TX ring %d", i);
			while (--i >= 0)
				iwn_free_tx_ring(sc, &sc->txq[i]);
			goto fail_txring;
		}
	}

	/* Allocate RX ring. */
	if ((error = iwn_alloc_rx_ring(sc, &sc->rxq)) != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!could not allocate RX ring");
		goto fail_rxring;
	}

	/* Clear pending interrupts. */
	IWN_WRITE(sc, IWN_INT, 0xffffffff);

	/* Count the number of available chains. */
	sc->ntxchains =
	    ((sc->txchainmask >> 2) & 1) +
	    ((sc->txchainmask >> 1) & 1) +
	    ((sc->txchainmask >> 0) & 1);
	sc->nrxchains =
	    ((sc->rxchainmask >> 2) & 1) +
	    ((sc->rxchainmask >> 1) & 1) +
	    ((sc->rxchainmask >> 0) & 1);
	dev_err(sc->sc_dip, CE_CONT, "!MIMO %dT%dR, %s, address %s",
	    sc->ntxchains, sc->nrxchains, sc->eeprom_domain,
	    ieee80211_macaddr_sprintf(ic->ic_macaddr));

	sc->sc_ant->tx_ant.value.ul = sc->txchainmask;
	sc->sc_ant->rx_ant.value.ul = sc->rxchainmask;

	ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	/* Set device capabilities. */
	/* XXX OpenBSD has IEEE80211_C_WEP, IEEE80211_C_RSN,
	 * and IEEE80211_C_PMGT too. */
	ic->ic_caps =
	    IEEE80211_C_IBSS |		/* IBSS mode support */
	    IEEE80211_C_WPA |		/* 802.11i */
	    IEEE80211_C_MONITOR |	/* monitor mode supported */
	    IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHSLOT |	/* short slot time supported */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_WME;		/* 802.11e */

#ifndef IEEE80211_NO_HT
	if (sc->sc_flags & IWN_FLAG_HAS_11N) {
		/* Set HT capabilities. */
		ic->ic_htcaps =
#if IWN_RBUF_SIZE == 8192
		    IEEE80211_HTCAP_AMSDU7935 |
#endif
		    IEEE80211_HTCAP_CBW20_40 |
		    IEEE80211_HTCAP_SGI20 |
		    IEEE80211_HTCAP_SGI40;
		if (sc->hw_type != IWN_HW_REV_TYPE_4965)
			ic->ic_htcaps |= IEEE80211_HTCAP_GF;
		if (sc->hw_type == IWN_HW_REV_TYPE_6050)
			ic->ic_htcaps |= IEEE80211_HTCAP_SMPS_DYN;
		else
			ic->ic_htcaps |= IEEE80211_HTCAP_SMPS_DIS;
	}
#endif	/* !IEEE80211_NO_HT */

	/* Set supported legacy rates. */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = iwn_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = iwn_rateset_11g;
	if (sc->sc_flags & IWN_FLAG_HAS_5GHZ) {
		ic->ic_sup_rates[IEEE80211_MODE_11A] = iwn_rateset_11a;
	}
#ifndef IEEE80211_NO_HT
	if (sc->sc_flags & IWN_FLAG_HAS_11N) {
		/* Set supported HT rates. */
		ic->ic_sup_mcs[0] = 0xff;		/* MCS 0-7 */
		if (sc->nrxchains > 1)
			ic->ic_sup_mcs[1] = 0xff;	/* MCS 7-15 */
		if (sc->nrxchains > 2)
			ic->ic_sup_mcs[2] = 0xff;	/* MCS 16-23 */
	}
#endif

	/* IBSS channel undefined for now. */
	ic->ic_ibss_chan = &ic->ic_sup_channels[0];

	ic->ic_node_newassoc = iwn_newassoc;
	ic->ic_xmit = iwn_send;
#ifdef IWN_HWCRYPTO
	ic->ic_crypto.cs_key_set = iwn_set_key;
	ic->ic_crypto.cs_key_delete = iwn_delete_key;
#endif
	ic->ic_wme.wme_update = iwn_wme_update;
#ifndef IEEE80211_NO_HT
	ic->ic_ampdu_rx_start = iwn_ampdu_rx_start;
	ic->ic_ampdu_rx_stop = iwn_ampdu_rx_stop;
	ic->ic_ampdu_tx_start = iwn_ampdu_tx_start;
	ic->ic_ampdu_tx_stop = iwn_ampdu_tx_stop;
#endif
	/*
	 * attach to 802.11 module
	 */
	ieee80211_attach(ic);

	ieee80211_register_door(ic, ddi_driver_name(dip), ddi_get_instance(dip));

	/* Override 802.11 state transition machine. */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = iwn_newstate;
	ic->ic_watchdog = iwn_watchdog;

	ic->ic_node_alloc = iwn_node_alloc;
	ic->ic_node_free = iwn_node_free;

	ieee80211_media_init(ic);

	/*
	 * initialize default tx key
	 */
	ic->ic_def_txkey = 0;

	sc->amrr.amrr_min_success_threshold =  1;
	sc->amrr.amrr_max_success_threshold = 15;

	/*
	 * Initialize pointer to device specific functions
	 */
	wd.wd_secalloc = WIFI_SEC_NONE;
	wd.wd_opmode = ic->ic_opmode;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_macaddr);

	/*
	 * create relation to GLD
	 */
	macp = mac_alloc(MAC_VERSION);
	if (NULL == macp) {
		dev_err(sc->sc_dip, CE_WARN, "!mac_alloc() failed");
		goto fail_mac_alloc;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= dip;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &iwn_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	/*
	 * Register the macp to mac
	 */
	error = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!mac_register() failed");
		goto fail_mac_alloc;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "iwn%d", instance);
	error = ddi_create_minor_node(dip, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!ddi_create_minor_node() failed");
		goto fail_minor;
	}

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	sc->sc_periodic = ddi_periodic_add(iwn_periodic, sc,
	    iwn_periodic_interval * MICROSEC, 0);

	if (sc->sc_ks_misc)
		kstat_install(sc->sc_ks_misc);
	if (sc->sc_ks_ant)
		kstat_install(sc->sc_ks_ant);
	if (sc->sc_ks_sens)
		kstat_install(sc->sc_ks_sens);
	if (sc->sc_ks_timing)
		kstat_install(sc->sc_ks_timing);
	if (sc->sc_ks_edca)
		kstat_install(sc->sc_ks_edca);
	if (sc->sc_ks_txpower)
		kstat_install(sc->sc_ks_txpower);
	if (sc->sc_ks_toff)
		kstat_install(sc->sc_ks_toff);

	sc->sc_flags |= IWN_FLAG_ATTACHED;

	return (DDI_SUCCESS);

	/* Free allocated memory if something failed during attachment. */
fail_minor:
	mac_unregister(ic->ic_mach);

fail_mac_alloc:
	ieee80211_detach(ic);
	iwn_free_rx_ring(sc, &sc->rxq);

fail_rxring:
	for (i = 0; i < sc->ntxqs; i++)
		iwn_free_tx_ring(sc, &sc->txq[i]);

fail_txring:
	iwn_free_sched(sc);

fail_sched:
	if (sc->ict != NULL)
		iwn_free_ict(sc);

fail_ict:
	iwn_free_kw(sc);

fail_kw:
	iwn_free_fwmem(sc);

fail_fwmem:
fail_hw:
	iwn_intr_teardown(sc);

	iwn_kstat_free(sc->sc_ks_txpower, sc->sc_txpower,
	    sizeof (struct iwn_ks_txpower));

	if (sc->hw_type == IWN_HW_REV_TYPE_6005)
		iwn_kstat_free(sc->sc_ks_toff, sc->sc_toff.t6000,
		    sizeof (struct iwn_ks_toff_6000));
	else
		iwn_kstat_free(sc->sc_ks_toff, sc->sc_toff.t2000,
		    sizeof (struct iwn_ks_toff_2000));

fail_intr:
	ddi_regs_map_free(&sc->sc_regh);

fail_regs_map:
fail_pci_capab:
	pci_config_teardown(&sc->sc_pcih);

fail_pci_config:
	iwn_kstat_free(sc->sc_ks_misc, sc->sc_misc,
	    sizeof (struct iwn_ks_misc));
	iwn_kstat_free(sc->sc_ks_ant, sc->sc_ant,
	    sizeof (struct iwn_ks_ant));
	iwn_kstat_free(sc->sc_ks_sens, sc->sc_sens,
	    sizeof (struct iwn_ks_sens));
	iwn_kstat_free(sc->sc_ks_timing, sc->sc_timing,
	    sizeof (struct iwn_ks_timing));
	iwn_kstat_free(sc->sc_ks_edca, sc->sc_edca,
	    sizeof (struct iwn_ks_edca));

	ddi_soft_state_free(iwn_state, instance);

	return (DDI_FAILURE);
}

int
iwn4965_attach(struct iwn_softc *sc)
{
	struct iwn_ops *ops = &sc->ops;

	ops->load_firmware = iwn4965_load_firmware;
	ops->read_eeprom = iwn4965_read_eeprom;
	ops->post_alive = iwn4965_post_alive;
	ops->nic_config = iwn4965_nic_config;
	ops->config_bt_coex = iwn_config_bt_coex_bluetooth;
	ops->update_sched = iwn4965_update_sched;
	ops->get_temperature = iwn4965_get_temperature;
	ops->get_rssi = iwn4965_get_rssi;
	ops->set_txpower = iwn4965_set_txpower;
	ops->init_gains = iwn4965_init_gains;
	ops->set_gains = iwn4965_set_gains;
	ops->add_node = iwn4965_add_node;
	ops->tx_done = iwn4965_tx_done;
#ifndef IEEE80211_NO_HT
	ops->ampdu_tx_start = iwn4965_ampdu_tx_start;
	ops->ampdu_tx_stop = iwn4965_ampdu_tx_stop;
#endif
	sc->ntxqs = IWN4965_NTXQUEUES;
	sc->ndmachnls = IWN4965_NDMACHNLS;
	sc->broadcast_id = IWN4965_ID_BROADCAST;
	sc->rxonsz = IWN4965_RXONSZ;
	sc->schedsz = IWN4965_SCHEDSZ;
	sc->fw_text_maxsz = IWN4965_FW_TEXT_MAXSZ;
	sc->fw_data_maxsz = IWN4965_FW_DATA_MAXSZ;
	sc->fwsz = IWN4965_FWSZ;
	sc->sched_txfact_addr = IWN4965_SCHED_TXFACT;
	sc->limits = &iwn4965_sensitivity_limits;
	sc->fwname = "iwlwifi-4965-2.ucode";
	/* Override chains masks, ROM is known to be broken. */
	sc->txchainmask = IWN_ANT_AB;
	sc->rxchainmask = IWN_ANT_ABC;

	iwn_kstat_create(sc, "txpower", sizeof (struct iwn_ks_txpower),
	    &sc->sc_ks_txpower, (void **)&sc->sc_txpower);
	iwn_kstat_init_4965(sc);

	return 0;
}

int
iwn5000_attach(struct iwn_softc *sc, uint16_t pid)
{
	struct iwn_ops *ops = &sc->ops;

	ops->load_firmware = iwn5000_load_firmware;
	ops->read_eeprom = iwn5000_read_eeprom;
	ops->post_alive = iwn5000_post_alive;
	ops->nic_config = iwn5000_nic_config;
	ops->config_bt_coex = iwn_config_bt_coex_bluetooth;
	ops->update_sched = iwn5000_update_sched;
	ops->get_temperature = iwn5000_get_temperature;
	ops->get_rssi = iwn5000_get_rssi;
	ops->set_txpower = iwn5000_set_txpower;
	ops->init_gains = iwn5000_init_gains;
	ops->set_gains = iwn5000_set_gains;
	ops->add_node = iwn5000_add_node;
	ops->tx_done = iwn5000_tx_done;
#ifndef IEEE80211_NO_HT
	ops->ampdu_tx_start = iwn5000_ampdu_tx_start;
	ops->ampdu_tx_stop = iwn5000_ampdu_tx_stop;
#endif
	sc->ntxqs = IWN5000_NTXQUEUES;
	sc->ndmachnls = IWN5000_NDMACHNLS;
	sc->broadcast_id = IWN5000_ID_BROADCAST;
	sc->rxonsz = IWN5000_RXONSZ;
	sc->schedsz = IWN5000_SCHEDSZ;
	sc->fw_text_maxsz = IWN5000_FW_TEXT_MAXSZ;
	sc->fw_data_maxsz = IWN5000_FW_DATA_MAXSZ;
	sc->fwsz = IWN5000_FWSZ;
	sc->sched_txfact_addr = IWN5000_SCHED_TXFACT;

	switch (sc->hw_type) {
	case IWN_HW_REV_TYPE_5100:
		sc->limits = &iwn5000_sensitivity_limits;
		sc->fwname = "iwlwifi-5000-2.ucode";
		/* Override chains masks, ROM is known to be broken. */
		sc->txchainmask = IWN_ANT_B;
		sc->rxchainmask = IWN_ANT_AB;
		break;
	case IWN_HW_REV_TYPE_5150:
		sc->limits = &iwn5150_sensitivity_limits;
		sc->fwname = "iwlwifi-5150-2.ucode";
		break;
	case IWN_HW_REV_TYPE_5300:
	case IWN_HW_REV_TYPE_5350:
		sc->limits = &iwn5000_sensitivity_limits;
		sc->fwname = "iwlwifi-5000-2.ucode";
		break;
	case IWN_HW_REV_TYPE_1000:
		sc->limits = &iwn1000_sensitivity_limits;
		if (pid == PCI_PRODUCT_INTEL_WIFI_LINK_100_1 ||
		    pid == PCI_PRODUCT_INTEL_WIFI_LINK_100_2)
			sc->fwname = "iwlwifi-100-5.ucode";
		else
			sc->fwname = "iwlwifi-1000-3.ucode";
		break;
	case IWN_HW_REV_TYPE_6000:
		sc->limits = &iwn6000_sensitivity_limits;
		sc->fwname = "iwlwifi-6000-4.ucode";
		if (pid == PCI_PRODUCT_INTEL_WIFI_LINK_6000_IPA_1 ||
		    pid == PCI_PRODUCT_INTEL_WIFI_LINK_6000_IPA_2) {
			sc->sc_flags |= IWN_FLAG_INTERNAL_PA;
			/* Override chains masks, ROM is known to be broken. */
			sc->txchainmask = IWN_ANT_BC;
			sc->rxchainmask = IWN_ANT_BC;
		}
		break;
	case IWN_HW_REV_TYPE_6050:
		sc->limits = &iwn6000_sensitivity_limits;
		sc->fwname = "iwlwifi-6050-5.ucode";
		break;
	case IWN_HW_REV_TYPE_6005:
		sc->limits = &iwn6000_sensitivity_limits;
		/* Type 6030 cards return IWN_HW_REV_TYPE_6005 */
		if (pid == PCI_PRODUCT_INTEL_WIFI_LINK_1030_1 ||
		    pid == PCI_PRODUCT_INTEL_WIFI_LINK_1030_2 ||
		    pid == PCI_PRODUCT_INTEL_WIFI_LINK_6230_1 ||
		    pid == PCI_PRODUCT_INTEL_WIFI_LINK_6230_2 ||
		    pid == PCI_PRODUCT_INTEL_WIFI_LINK_6235   ||
		    pid == PCI_PRODUCT_INTEL_WIFI_LINK_6235_2) {
			sc->fwname = "iwlwifi-6000g2b-6.ucode";
			ops->config_bt_coex = iwn_config_bt_coex_adv1;
		}
		else
			sc->fwname = "iwlwifi-6000g2a-6.ucode";

		iwn_kstat_create(sc, "temp_offset",
		    sizeof (struct iwn_ks_toff_6000),
		    &sc->sc_ks_toff, (void **)&sc->sc_toff.t6000);
		iwn_kstat_init_6000(sc);
		break;
	case IWN_HW_REV_TYPE_2030:
		sc->limits = &iwn2000_sensitivity_limits;
		sc->fwname = "iwlwifi-2030-6.ucode";
		ops->config_bt_coex = iwn_config_bt_coex_adv2;

		iwn_kstat_create(sc, "temp_offset",
		    sizeof (struct iwn_ks_toff_2000),
		    &sc->sc_ks_toff, (void **)&sc->sc_toff.t2000);
		iwn_kstat_init_2000(sc);
		break;
	case IWN_HW_REV_TYPE_2000:
		sc->limits = &iwn2000_sensitivity_limits;
		sc->fwname = "iwlwifi-2000-6.ucode";

		iwn_kstat_create(sc, "temp_offset",
		    sizeof (struct iwn_ks_toff_2000),
		    &sc->sc_ks_toff, (void **)&sc->sc_toff.t2000);
		iwn_kstat_init_2000(sc);
		break;
	case IWN_HW_REV_TYPE_135:
		sc->limits = &iwn2000_sensitivity_limits;
		sc->fwname = "iwlwifi-135-6.ucode";
		ops->config_bt_coex = iwn_config_bt_coex_adv2;

		iwn_kstat_create(sc, "temp_offset",
		    sizeof (struct iwn_ks_toff_2000),
		    &sc->sc_ks_toff, (void **)&sc->sc_toff.t2000);
		iwn_kstat_init_2000(sc);
		break;
	case IWN_HW_REV_TYPE_105:
		sc->limits = &iwn2000_sensitivity_limits;
		sc->fwname = "iwlwifi-105-6.ucode";

		iwn_kstat_create(sc, "temp_offset",
		    sizeof (struct iwn_ks_toff_2000),
		    &sc->sc_ks_toff, (void **)&sc->sc_toff.t2000);
		iwn_kstat_init_2000(sc);
		break;
	default:
		dev_err(sc->sc_dip, CE_WARN, "!adapter type %d not supported",
		    sc->hw_type);
		return ENOTSUP;
	}
	return 0;
}

static int
iwn_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct iwn_softc *sc = ddi_get_driver_private(dip);
	ieee80211com_t *ic = &sc->sc_ic;
	int qid, error;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		sc->sc_flags &= ~IWN_FLAG_HW_ERR_RECOVER;
		sc->sc_flags &= ~IWN_FLAG_RATE_AUTO_CTL;

		sc->sc_flags |= IWN_FLAG_SUSPEND;

		if (sc->sc_flags & IWN_FLAG_RUNNING) {
			iwn_hw_stop(sc, B_TRUE);
			ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

		}

		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (!(sc->sc_flags & IWN_FLAG_ATTACHED)) {
		return (DDI_FAILURE);
	}

	error = mac_disable(ic->ic_mach);
	if (error != DDI_SUCCESS)
		return (error);

	mutex_enter(&sc->sc_mtx);
	sc->sc_flags |= IWN_FLAG_STOP_CALIB_TO;
	mutex_exit(&sc->sc_mtx);

	if (sc->calib_to != 0)
		(void) untimeout(sc->calib_to);
	sc->calib_to = 0;

	if (sc->scan_to != 0)
		(void) untimeout(sc->scan_to);
	sc->scan_to = 0;

	ddi_periodic_delete(sc->sc_periodic);

	/*
	 * stop chipset
	 */
	iwn_hw_stop(sc, B_TRUE);

	/*
	 * Unregister from GLD
	 */
	(void) mac_unregister(ic->ic_mach);
	ieee80211_detach(ic);

	/* Uninstall interrupt handler. */
	iwn_intr_teardown(sc);

	/* Free DMA resources. */
	mutex_enter(&sc->sc_mtx);
	iwn_free_rx_ring(sc, &sc->rxq);
	for (qid = 0; qid < sc->ntxqs; qid++)
		iwn_free_tx_ring(sc, &sc->txq[qid]);
	iwn_free_sched(sc);
	iwn_free_kw(sc);
	if (sc->ict != NULL)
		iwn_free_ict(sc);
	iwn_free_fwmem(sc);
	mutex_exit(&sc->sc_mtx);

	iwn_kstat_free(sc->sc_ks_misc, sc->sc_misc,
	    sizeof (struct iwn_ks_misc));
	iwn_kstat_free(sc->sc_ks_ant, sc->sc_ant,
	    sizeof (struct iwn_ks_ant));
	iwn_kstat_free(sc->sc_ks_sens, sc->sc_sens,
	    sizeof (struct iwn_ks_sens));
	iwn_kstat_free(sc->sc_ks_timing, sc->sc_timing,
	    sizeof (struct iwn_ks_timing));
	iwn_kstat_free(sc->sc_ks_edca, sc->sc_edca,
	    sizeof (struct iwn_ks_edca));
	iwn_kstat_free(sc->sc_ks_txpower, sc->sc_txpower,
	    sizeof (struct iwn_ks_txpower));

	if (sc->hw_type == IWN_HW_REV_TYPE_6005)
		iwn_kstat_free(sc->sc_ks_toff, sc->sc_toff.t6000,
		    sizeof (struct iwn_ks_toff_6000));
	else
		iwn_kstat_free(sc->sc_ks_toff, sc->sc_toff.t2000,
		    sizeof (struct iwn_ks_toff_2000));

	ddi_regs_map_free(&sc->sc_regh);
	pci_config_teardown(&sc->sc_pcih);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(iwn_state, ddi_get_instance(dip));

	return 0;
}

static int
iwn_quiesce(dev_info_t *dip)
{
	struct iwn_softc *sc;

	sc = ddi_get_soft_state(iwn_state, ddi_get_instance(dip));
	if (sc == NULL)
		return (DDI_FAILURE);

#ifdef IWN_DEBUG
	/* bypass any messages */
	iwn_dbg_print = 0;
#endif

	/*
	 * No more blocking is allowed while we are in the
	 * quiesce(9E) entry point.
	 */
	sc->sc_flags |= IWN_FLAG_QUIESCED;

	/*
	 * Disable and mask all interrupts.
	 */
	iwn_hw_stop(sc, B_FALSE);

	return (DDI_SUCCESS);
}

static int
iwn_nic_lock(struct iwn_softc *sc)
{
	int ntries;

	/* Request exclusive access to NIC. */
	IWN_SETBITS(sc, IWN_GP_CNTRL, IWN_GP_CNTRL_MAC_ACCESS_REQ);

	/* Spin until we actually get the lock. */
	for (ntries = 0; ntries < 1000; ntries++) {
		if ((IWN_READ(sc, IWN_GP_CNTRL) &
		     (IWN_GP_CNTRL_MAC_ACCESS_ENA | IWN_GP_CNTRL_SLEEP)) ==
		    IWN_GP_CNTRL_MAC_ACCESS_ENA)
			return 0;
		DELAY(10);
	}
	return ETIMEDOUT;
}

static __inline void
iwn_nic_unlock(struct iwn_softc *sc)
{
	IWN_CLRBITS(sc, IWN_GP_CNTRL, IWN_GP_CNTRL_MAC_ACCESS_REQ);
}

static __inline uint32_t
iwn_prph_read(struct iwn_softc *sc, uint32_t addr)
{
	IWN_WRITE(sc, IWN_PRPH_RADDR, IWN_PRPH_DWORD | addr);
	IWN_BARRIER_READ_WRITE(sc);
	return IWN_READ(sc, IWN_PRPH_RDATA);
}

static __inline void
iwn_prph_write(struct iwn_softc *sc, uint32_t addr, uint32_t data)
{
	IWN_WRITE(sc, IWN_PRPH_WADDR, IWN_PRPH_DWORD | addr);
	IWN_BARRIER_WRITE(sc);
	IWN_WRITE(sc, IWN_PRPH_WDATA, data);
}

static __inline void
iwn_prph_setbits(struct iwn_softc *sc, uint32_t addr, uint32_t mask)
{
	iwn_prph_write(sc, addr, iwn_prph_read(sc, addr) | mask);
}

static __inline void
iwn_prph_clrbits(struct iwn_softc *sc, uint32_t addr, uint32_t mask)
{
	iwn_prph_write(sc, addr, iwn_prph_read(sc, addr) & ~mask);
}

static __inline void
iwn_prph_write_region_4(struct iwn_softc *sc, uint32_t addr,
    const uint32_t *data, int count)
{
	for (; count > 0; count--, data++, addr += 4)
		iwn_prph_write(sc, addr, *data);
}

static __inline uint32_t
iwn_mem_read(struct iwn_softc *sc, uint32_t addr)
{
	IWN_WRITE(sc, IWN_MEM_RADDR, addr);
	IWN_BARRIER_READ_WRITE(sc);
	return IWN_READ(sc, IWN_MEM_RDATA);
}

static __inline void
iwn_mem_write(struct iwn_softc *sc, uint32_t addr, uint32_t data)
{
	IWN_WRITE(sc, IWN_MEM_WADDR, addr);
	IWN_BARRIER_WRITE(sc);
	IWN_WRITE(sc, IWN_MEM_WDATA, data);
}

#ifndef IEEE80211_NO_HT
static __inline void
iwn_mem_write_2(struct iwn_softc *sc, uint32_t addr, uint16_t data)
{
	uint32_t tmp;

	tmp = iwn_mem_read(sc, addr & ~3);
	if (addr & 3)
		tmp = (tmp & 0x0000ffff) | data << 16;
	else
		tmp = (tmp & 0xffff0000) | data;
	iwn_mem_write(sc, addr & ~3, tmp);
}
#endif

static __inline void
iwn_mem_read_region_4(struct iwn_softc *sc, uint32_t addr, uint32_t *data,
    int count)
{
	for (; count > 0; count--, addr += 4)
		*data++ = iwn_mem_read(sc, addr);
}

static __inline void
iwn_mem_set_region_4(struct iwn_softc *sc, uint32_t addr, uint32_t val,
    int count)
{
	for (; count > 0; count--, addr += 4)
		iwn_mem_write(sc, addr, val);
}

static int
iwn_eeprom_lock(struct iwn_softc *sc)
{
	int i, ntries;

	for (i = 0; i < 100; i++) {
		/* Request exclusive access to EEPROM. */
		IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
		    IWN_HW_IF_CONFIG_EEPROM_LOCKED);

		/* Spin until we actually get the lock. */
		for (ntries = 0; ntries < 100; ntries++) {
			if (IWN_READ(sc, IWN_HW_IF_CONFIG) &
			    IWN_HW_IF_CONFIG_EEPROM_LOCKED)
				return 0;
			DELAY(10);
		}
	}
	return ETIMEDOUT;
}

static __inline void
iwn_eeprom_unlock(struct iwn_softc *sc)
{
	IWN_CLRBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_EEPROM_LOCKED);
}

/*
 * Initialize access by host to One Time Programmable ROM.
 * NB: This kind of ROM can be found on 1000 or 6000 Series only.
 */
static int
iwn_init_otprom(struct iwn_softc *sc)
{
	uint16_t prev = 0, base, next;
	int count, error;

	/* Wait for clock stabilization before accessing prph. */
	if ((error = iwn_clock_wait(sc)) != 0)
		return error;

	if ((error = iwn_nic_lock(sc)) != 0)
		return error;
	iwn_prph_setbits(sc, IWN_APMG_PS, IWN_APMG_PS_RESET_REQ);
	DELAY(5);
	iwn_prph_clrbits(sc, IWN_APMG_PS, IWN_APMG_PS_RESET_REQ);
	iwn_nic_unlock(sc);

	/* Set auto clock gate disable bit for HW with OTP shadow RAM. */
	if (sc->hw_type != IWN_HW_REV_TYPE_1000) {
		IWN_SETBITS(sc, IWN_DBG_LINK_PWR_MGMT,
		    IWN_RESET_LINK_PWR_MGMT_DIS);
	}
	IWN_CLRBITS(sc, IWN_EEPROM_GP, IWN_EEPROM_GP_IF_OWNER);
	/* Clear ECC status. */
	IWN_SETBITS(sc, IWN_OTP_GP,
	    IWN_OTP_GP_ECC_CORR_STTS | IWN_OTP_GP_ECC_UNCORR_STTS);

	/*
	 * Find the block before last block (contains the EEPROM image)
	 * for HW without OTP shadow RAM.
	 */
	if (sc->hw_type == IWN_HW_REV_TYPE_1000) {
		/* Switch to absolute addressing mode. */
		IWN_CLRBITS(sc, IWN_OTP_GP, IWN_OTP_GP_RELATIVE_ACCESS);
		base = 0;
		for (count = 0; count < IWN1000_OTP_NBLOCKS; count++) {
			error = iwn_read_prom_data(sc, base, &next, 2);
			if (error != 0)
				return error;
			if (next == 0)	/* End of linked-list. */
				break;
			prev = base;
			base = le16toh(next);
		}
		if (count == 0 || count == IWN1000_OTP_NBLOCKS)
			return EIO;
		/* Skip "next" word. */
		sc->prom_base = prev + 1;
	}
	return 0;
}

static int
iwn_read_prom_data(struct iwn_softc *sc, uint32_t addr, void *data, int count)
{
	uint8_t *out = data;
	uint32_t val, tmp;
	int ntries;

	addr += sc->prom_base;
	for (; count > 0; count -= 2, addr++) {
		IWN_WRITE(sc, IWN_EEPROM, addr << 2);
		for (ntries = 0; ntries < 10; ntries++) {
			val = IWN_READ(sc, IWN_EEPROM);
			if (val & IWN_EEPROM_READ_VALID)
				break;
			DELAY(5);
		}
		if (ntries == 10) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!timeout reading ROM at 0x%x", addr);
			return ETIMEDOUT;
		}
		if (sc->sc_flags & IWN_FLAG_HAS_OTPROM) {
			/* OTPROM, check for ECC errors. */
			tmp = IWN_READ(sc, IWN_OTP_GP);
			if (tmp & IWN_OTP_GP_ECC_UNCORR_STTS) {
				dev_err(sc->sc_dip, CE_WARN,
				    "!OTPROM ECC error at 0x%x", addr);
				return EIO;
			}
			if (tmp & IWN_OTP_GP_ECC_CORR_STTS) {
				/* Correctable ECC error, clear bit. */
				IWN_SETBITS(sc, IWN_OTP_GP,
				    IWN_OTP_GP_ECC_CORR_STTS);
			}
		}
		*out++ = val >> 16;
		if (count > 1)
			*out++ = val >> 24;
	}
	return 0;
}

static int
iwn_dma_contig_alloc(struct iwn_softc *sc, struct iwn_dma_info *dma,
    uint_t size, uint_t flags, void **kvap, ddi_device_acc_attr_t *acc_attr,
    uint_t align)
{
	ddi_dma_attr_t dma_attr = {
		.dma_attr_version	= DMA_ATTR_V0,
		.dma_attr_addr_lo	= 0,
		.dma_attr_addr_hi	= 0xfffffffffULL,
		.dma_attr_count_max	= 0xfffffffffULL,
		.dma_attr_align		= align,
		.dma_attr_burstsizes	= 0x7ff,
		.dma_attr_minxfer	= 1,
		.dma_attr_maxxfer	= 0xfffffffffULL,
		.dma_attr_seg		= 0xfffffffffULL,
		.dma_attr_sgllen	= 1,
		.dma_attr_granular	= 1,
		.dma_attr_flags		= 0,
	};
	int error;

	error = ddi_dma_alloc_handle(sc->sc_dip, &dma_attr, DDI_DMA_SLEEP, NULL,
	    &dma->dma_hdl);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN,
		    "ddi_dma_alloc_handle() failed, error = %d", error);
		goto fail;
	}

	error = ddi_dma_mem_alloc(dma->dma_hdl, size, acc_attr,
	    flags & (DDI_DMA_CONSISTENT | DDI_DMA_STREAMING), DDI_DMA_SLEEP, 0,
	    &dma->vaddr, &dma->length, &dma->acc_hdl);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN,
		    "ddi_dma_mem_alloc() failed, error = %d", error);
		goto fail2;
	}

	bzero(dma->vaddr, dma->length);

	error = ddi_dma_addr_bind_handle(dma->dma_hdl, NULL, dma->vaddr,
	    dma->length, flags, DDI_DMA_SLEEP, NULL, &dma->cookie,
	    &dma->ncookies);
	if (error != DDI_DMA_MAPPED) {
		dma->ncookies = 0;
		dev_err(sc->sc_dip, CE_WARN,
		    "ddi_dma_addr_bind_handle() failed, error = %d", error);
		goto fail3;
	}

	dma->size = size;
	dma->paddr = dma->cookie.dmac_laddress;

	if (kvap != NULL)
		*kvap = (void *)dma->vaddr;

	return (DDI_SUCCESS);

fail3:
	ddi_dma_mem_free(&dma->acc_hdl);
fail2:
	ddi_dma_free_handle(&dma->dma_hdl);
fail:
	bzero(dma, sizeof (struct iwn_dma_info));
	return (DDI_FAILURE);
}

static void
iwn_dma_contig_free(struct iwn_dma_info *dma)
{
	if (dma->dma_hdl != NULL) {
		if (dma->ncookies)
			(void) ddi_dma_unbind_handle(dma->dma_hdl);
		ddi_dma_free_handle(&dma->dma_hdl);
	}

	if (dma->acc_hdl != NULL)
		ddi_dma_mem_free(&dma->acc_hdl);

	bzero(dma, sizeof (struct iwn_dma_info));
}

static int
iwn_alloc_sched(struct iwn_softc *sc)
{
	/* TX scheduler rings must be aligned on a 1KB boundary. */

	return iwn_dma_contig_alloc(sc, &sc->sched_dma, sc->schedsz,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, (void **)&sc->sched,
	    &iwn_dma_accattr, 1024);
}

static void
iwn_free_sched(struct iwn_softc *sc)
{
	iwn_dma_contig_free(&sc->sched_dma);
}

static int
iwn_alloc_kw(struct iwn_softc *sc)
{
	/* "Keep Warm" page must be aligned on a 4KB boundary. */

	return iwn_dma_contig_alloc(sc, &sc->kw_dma, IWN_KW_SIZE,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, NULL, &iwn_dma_accattr, 4096);
}

static void
iwn_free_kw(struct iwn_softc *sc)
{
	iwn_dma_contig_free(&sc->kw_dma);
}

static int
iwn_alloc_ict(struct iwn_softc *sc)
{
	/* ICT table must be aligned on a 4KB boundary. */

	return iwn_dma_contig_alloc(sc, &sc->ict_dma, IWN_ICT_SIZE,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, (void **)&sc->ict,
	    &iwn_dma_descattr, 4096);
}

static void
iwn_free_ict(struct iwn_softc *sc)
{
	iwn_dma_contig_free(&sc->ict_dma);
}

static int
iwn_alloc_fwmem(struct iwn_softc *sc)
{
	/* Must be aligned on a 16-byte boundary. */
	return iwn_dma_contig_alloc(sc, &sc->fw_dma, sc->fwsz,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, NULL, &iwn_dma_accattr, 16);
}

static void
iwn_free_fwmem(struct iwn_softc *sc)
{
	iwn_dma_contig_free(&sc->fw_dma);
}

static int
iwn_alloc_rx_ring(struct iwn_softc *sc, struct iwn_rx_ring *ring)
{
	size_t size;
	int i, error;

	ring->cur = 0;

	/* Allocate RX descriptors (256-byte aligned). */
	size = IWN_RX_RING_COUNT * sizeof (uint32_t);
	error = iwn_dma_contig_alloc(sc, &ring->desc_dma, size,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, (void **)&ring->desc,
	    &iwn_dma_descattr, 256);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not allocate RX ring DMA memory");
		goto fail;
	}

	/* Allocate RX status area (16-byte aligned). */
	error = iwn_dma_contig_alloc(sc, &ring->stat_dma,
	    sizeof (struct iwn_rx_status), DDI_DMA_CONSISTENT | DDI_DMA_RDWR,
	    (void **)&ring->stat, &iwn_dma_descattr, 16);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not allocate RX status DMA memory");
		goto fail;
	}

	/*
	 * Allocate and map RX buffers.
	 */
	for (i = 0; i < IWN_RX_RING_COUNT; i++) {
		struct iwn_rx_data *data = &ring->data[i];

		error = iwn_dma_contig_alloc(sc, &data->dma_data, IWN_RBUF_SIZE,
		    DDI_DMA_CONSISTENT | DDI_DMA_READ, NULL, &iwn_dma_accattr,
		    256);
		if (error != DDI_SUCCESS) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not create RX buf DMA map");
			goto fail;
		}

		/* Set physical address of RX buffer (256-byte aligned). */
		ring->desc[i] = htole32(data->dma_data.paddr >> 8);
	}

	(void) ddi_dma_sync(ring->desc_dma.dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);

	return 0;

fail:	iwn_free_rx_ring(sc, ring);
	return error;
}

static void
iwn_reset_rx_ring(struct iwn_softc *sc, struct iwn_rx_ring *ring)
{
	int ntries;

	if (iwn_nic_lock(sc) == 0) {
		IWN_WRITE(sc, IWN_FH_RX_CONFIG, 0);
		for (ntries = 0; ntries < 1000; ntries++) {
			if (IWN_READ(sc, IWN_FH_RX_STATUS) &
			    IWN_FH_RX_STATUS_IDLE)
				break;
			DELAY(10);
		}
		iwn_nic_unlock(sc);
	}
	ring->cur = 0;
	sc->last_rx_valid = 0;
}

static void
iwn_free_rx_ring(struct iwn_softc *sc, struct iwn_rx_ring *ring)
{
	_NOTE(ARGUNUSED(sc));
	int i;

	iwn_dma_contig_free(&ring->desc_dma);
	iwn_dma_contig_free(&ring->stat_dma);

	for (i = 0; i < IWN_RX_RING_COUNT; i++) {
		struct iwn_rx_data *data = &ring->data[i];

		if (data->dma_data.dma_hdl)
			iwn_dma_contig_free(&data->dma_data);
	}
}

static int
iwn_alloc_tx_ring(struct iwn_softc *sc, struct iwn_tx_ring *ring, int qid)
{
	uintptr_t paddr;
	size_t size;
	int i, error;

	ring->qid = qid;
	ring->queued = 0;
	ring->cur = 0;

	/* Allocate TX descriptors (256-byte aligned). */
	size = IWN_TX_RING_COUNT * sizeof (struct iwn_tx_desc);
	error = iwn_dma_contig_alloc(sc, &ring->desc_dma, size,
	    DDI_DMA_CONSISTENT | DDI_DMA_WRITE, (void **)&ring->desc,
	    &iwn_dma_descattr, 256);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not allocate TX ring DMA memory");
		goto fail;
	}
	/*
	 * We only use rings 0 through 4 (4 EDCA + cmd) so there is no need
	 * to allocate commands space for other rings.
	 * XXX Do we really need to allocate descriptors for other rings?
	 */
	if (qid > 4)
		return 0;

	size = IWN_TX_RING_COUNT * sizeof (struct iwn_tx_cmd);
	error = iwn_dma_contig_alloc(sc, &ring->cmd_dma, size,
	    DDI_DMA_CONSISTENT | DDI_DMA_WRITE, (void **)&ring->cmd,
	    &iwn_dma_accattr, 4);
	if (error != DDI_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not allocate TX cmd DMA memory");
		goto fail;
	}

	paddr = ring->cmd_dma.paddr;
	for (i = 0; i < IWN_TX_RING_COUNT; i++) {
		struct iwn_tx_data *data = &ring->data[i];

		data->cmd_paddr = paddr;
		data->scratch_paddr = paddr + 12;
		paddr += sizeof (struct iwn_tx_cmd);

		error = iwn_dma_contig_alloc(sc, &data->dma_data, IWN_TBUF_SIZE,
		    DDI_DMA_CONSISTENT | DDI_DMA_WRITE, NULL, &iwn_dma_accattr,
		    256);
		if (error != DDI_SUCCESS) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not create TX buf DMA map");
			goto fail;
		}
	}
	return 0;

fail:	iwn_free_tx_ring(sc, ring);
	return error;
}

static void
iwn_reset_tx_ring(struct iwn_softc *sc, struct iwn_tx_ring *ring)
{
	int i;

	if (ring->qid < 4)
		for (i = 0; i < IWN_TX_RING_COUNT; i++) {
			struct iwn_tx_data *data = &ring->data[i];

			(void) ddi_dma_sync(data->dma_data.dma_hdl, 0, 0,
			    DDI_DMA_SYNC_FORDEV);
		}

	/* Clear TX descriptors. */
	memset(ring->desc, 0, ring->desc_dma.size);
	(void) ddi_dma_sync(ring->desc_dma.dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);
	sc->qfullmsk &= ~(1 << ring->qid);
	ring->queued = 0;
	ring->cur = 0;
}

static void
iwn_free_tx_ring(struct iwn_softc *sc, struct iwn_tx_ring *ring)
{
	_NOTE(ARGUNUSED(sc));
	int i;

	iwn_dma_contig_free(&ring->desc_dma);
	iwn_dma_contig_free(&ring->cmd_dma);

	for (i = 0; i < IWN_TX_RING_COUNT; i++) {
		struct iwn_tx_data *data = &ring->data[i];

		if (data->dma_data.dma_hdl)
			iwn_dma_contig_free(&data->dma_data);
	}
}

static void
iwn5000_ict_reset(struct iwn_softc *sc)
{
	/* Disable interrupts. */
	IWN_WRITE(sc, IWN_INT_MASK, 0);

	/* Reset ICT table. */
	memset(sc->ict, 0, IWN_ICT_SIZE);
	sc->ict_cur = 0;

	/* Set physical address of ICT table (4KB aligned). */
	IWN_WRITE(sc, IWN_DRAM_INT_TBL, IWN_DRAM_INT_TBL_ENABLE |
	    IWN_DRAM_INT_TBL_WRAP_CHECK | sc->ict_dma.paddr >> 12);

	/* Enable periodic RX interrupt. */
	sc->int_mask |= IWN_INT_RX_PERIODIC;
	/* Switch to ICT interrupt mode in driver. */
	sc->sc_flags |= IWN_FLAG_USE_ICT;

	/* Re-enable interrupts. */
	IWN_WRITE(sc, IWN_INT, 0xffffffff);
	IWN_WRITE(sc, IWN_INT_MASK, sc->int_mask);
}

static int
iwn_read_eeprom(struct iwn_softc *sc)
{
	struct iwn_ops *ops = &sc->ops;
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t val;
	int error;

	/* Check whether adapter has an EEPROM or an OTPROM. */
	if (sc->hw_type >= IWN_HW_REV_TYPE_1000 &&
	    (IWN_READ(sc, IWN_OTP_GP) & IWN_OTP_GP_DEV_SEL_OTP))
		sc->sc_flags |= IWN_FLAG_HAS_OTPROM;
	IWN_DBG("%s found",
	    (sc->sc_flags & IWN_FLAG_HAS_OTPROM) ? "OTPROM" : "EEPROM");

	/* Adapter has to be powered on for EEPROM access to work. */
	if ((error = iwn_apm_init(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not power ON adapter");
		return error;
	}

	if ((IWN_READ(sc, IWN_EEPROM_GP) & 0x7) == 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!bad ROM signature");
		return EIO;
	}
	if ((error = iwn_eeprom_lock(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not lock ROM (error=%d)", error);
		return error;
	}
	if (sc->sc_flags & IWN_FLAG_HAS_OTPROM) {
		if ((error = iwn_init_otprom(sc)) != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not initialize OTPROM");
			return error;
		}
	}

	iwn_read_prom_data(sc, IWN_EEPROM_SKU_CAP, &val, 2);
	IWN_DBG("SKU capabilities=0x%04x", le16toh(val));
	/* Check if HT support is bonded out. */
	if (val & htole16(IWN_EEPROM_SKU_CAP_11N))
		sc->sc_flags |= IWN_FLAG_HAS_11N;

	iwn_read_prom_data(sc, IWN_EEPROM_RFCFG, &val, 2);
	sc->rfcfg = le16toh(val);
	IWN_DBG("radio config=0x%04x", sc->rfcfg);
	/* Read Tx/Rx chains from ROM unless it's known to be broken. */
	if (sc->txchainmask == 0)
		sc->txchainmask = IWN_RFCFG_TXANTMSK(sc->rfcfg);
	if (sc->rxchainmask == 0)
		sc->rxchainmask = IWN_RFCFG_RXANTMSK(sc->rfcfg);

	/* Read MAC address. */
	iwn_read_prom_data(sc, IWN_EEPROM_MAC, ic->ic_macaddr, 6);

	/* Read adapter-specific information from EEPROM. */
	ops->read_eeprom(sc);

	iwn_apm_stop(sc);	/* Power OFF adapter. */

	iwn_eeprom_unlock(sc);
	return 0;
}

static void
iwn4965_read_eeprom(struct iwn_softc *sc)
{
	uint32_t addr;
	uint16_t val;
	int i;

	/* Read regulatory domain (4 ASCII characters). */
	iwn_read_prom_data(sc, IWN4965_EEPROM_DOMAIN, sc->eeprom_domain, 4);

	/* Read the list of authorized channels (20MHz ones only). */
	for (i = 0; i < 5; i++) {
		addr = iwn4965_regulatory_bands[i];
		iwn_read_eeprom_channels(sc, i, addr);
	}

	/* Read maximum allowed TX power for 2GHz and 5GHz bands. */
	iwn_read_prom_data(sc, IWN4965_EEPROM_MAXPOW, &val, 2);
	sc->maxpwr2GHz = val & 0xff;
	sc->maxpwr5GHz = val >> 8;
	/* Check that EEPROM values are within valid range. */
	if (sc->maxpwr5GHz < 20 || sc->maxpwr5GHz > 50)
		sc->maxpwr5GHz = 38;
	if (sc->maxpwr2GHz < 20 || sc->maxpwr2GHz > 50)
		sc->maxpwr2GHz = 38;
	IWN_DBG("maxpwr 2GHz=%d 5GHz=%d", sc->maxpwr2GHz, sc->maxpwr5GHz);

	/* Read samples for each TX power group. */
	iwn_read_prom_data(sc, IWN4965_EEPROM_BANDS, sc->bands,
	    sizeof sc->bands);

	/* Read voltage at which samples were taken. */
	iwn_read_prom_data(sc, IWN4965_EEPROM_VOLTAGE, &val, 2);
	sc->eeprom_voltage = (int16_t)le16toh(val);
	IWN_DBG("voltage=%d (in 0.3V)", sc->eeprom_voltage);

#ifdef IWN_DEBUG
	/* Print samples. */
	if (iwn_dbg_print != 0) {
		for (i = 0; i < IWN_NBANDS; i++)
			iwn4965_print_power_group(sc, i);
	}
#endif
}

#ifdef IWN_DEBUG
static void
iwn4965_print_power_group(struct iwn_softc *sc, int i)
{
	struct iwn4965_eeprom_band *band = &sc->bands[i];
	struct iwn4965_eeprom_chan_samples *chans = band->chans;
	int j, c;

	dev_err(sc->sc_dip, CE_CONT, "!===band %d===", i);
	dev_err(sc->sc_dip, CE_CONT, "!chan lo=%d, chan hi=%d", band->lo,
	    band->hi);
	dev_err(sc->sc_dip, CE_CONT,  "!chan1 num=%d", chans[0].num);
	for (c = 0; c < 2; c++) {
		for (j = 0; j < IWN_NSAMPLES; j++) {
			dev_err(sc->sc_dip, CE_CONT, "!chain %d, sample %d: "
			    "temp=%d gain=%d power=%d pa_det=%d", c, j,
			    chans[0].samples[c][j].temp,
			    chans[0].samples[c][j].gain,
			    chans[0].samples[c][j].power,
			    chans[0].samples[c][j].pa_det);
		}
	}
	dev_err(sc->sc_dip, CE_CONT, "!chan2 num=%d", chans[1].num);
	for (c = 0; c < 2; c++) {
		for (j = 0; j < IWN_NSAMPLES; j++) {
			dev_err(sc->sc_dip, CE_CONT, "!chain %d, sample %d: "
			    "temp=%d gain=%d power=%d pa_det=%d", c, j,
			    chans[1].samples[c][j].temp,
			    chans[1].samples[c][j].gain,
			    chans[1].samples[c][j].power,
			    chans[1].samples[c][j].pa_det);
		}
	}
}
#endif

static void
iwn5000_read_eeprom(struct iwn_softc *sc)
{
	struct iwn5000_eeprom_calib_hdr hdr;
	int32_t volt;
	uint32_t base, addr;
	uint16_t val;
	int i;

	/* Read regulatory domain (4 ASCII characters). */
	iwn_read_prom_data(sc, IWN5000_EEPROM_REG, &val, 2);
	base = le16toh(val);
	iwn_read_prom_data(sc, base + IWN5000_EEPROM_DOMAIN,
	    sc->eeprom_domain, 4);

	/* Read the list of authorized channels (20MHz ones only). */
	for (i = 0; i < 5; i++) {
		addr = base + iwn5000_regulatory_bands[i];
		iwn_read_eeprom_channels(sc, i, addr);
	}

	/* Read enhanced TX power information for 6000 Series. */
	if (sc->hw_type >= IWN_HW_REV_TYPE_6000)
		iwn_read_eeprom_enhinfo(sc);

	iwn_read_prom_data(sc, IWN5000_EEPROM_CAL, &val, 2);
	base = le16toh(val);
	iwn_read_prom_data(sc, base, &hdr, sizeof hdr);
	IWN_DBG("calib version=%u pa type=%u voltage=%u",
	    hdr.version, hdr.pa_type, le16toh(hdr.volt));
	sc->calib_ver = hdr.version;

	if (sc->hw_type == IWN_HW_REV_TYPE_2030 ||
	    sc->hw_type == IWN_HW_REV_TYPE_2000 ||
	    sc->hw_type == IWN_HW_REV_TYPE_135  ||
	    sc->hw_type == IWN_HW_REV_TYPE_105) {
		sc->eeprom_voltage = le16toh(hdr.volt);
		iwn_read_prom_data(sc, base + IWN5000_EEPROM_TEMP, &val, 2);
		sc->eeprom_temp = le16toh(val);
		iwn_read_prom_data(sc, base + IWN2000_EEPROM_RAWTEMP, &val, 2);
		sc->eeprom_rawtemp = le16toh(val);
	}

	if (sc->hw_type == IWN_HW_REV_TYPE_5150) {
		/* Compute temperature offset. */
		iwn_read_prom_data(sc, base + IWN5000_EEPROM_TEMP, &val, 2);
		sc->eeprom_temp = le16toh(val);
		iwn_read_prom_data(sc, base + IWN5000_EEPROM_VOLT, &val, 2);
		volt = le16toh(val);
		sc->temp_off = sc->eeprom_temp - (volt / -5);
		IWN_DBG("temp=%d volt=%d offset=%dK",
		    sc->eeprom_temp, volt, sc->temp_off);
	} else {
		/* Read crystal calibration. */
		iwn_read_prom_data(sc, base + IWN5000_EEPROM_CRYSTAL,
		    &sc->eeprom_crystal, sizeof (uint32_t));
		IWN_DBG("crystal calibration 0x%08x",
		    le32toh(sc->eeprom_crystal));
	}
}

static void
iwn_read_eeprom_channels(struct iwn_softc *sc, int n, uint32_t addr)
{
	struct ieee80211com *ic = &sc->sc_ic;
	const struct iwn_chan_band *band = &iwn_bands[n];
	struct iwn_eeprom_chan channels[IWN_MAX_CHAN_PER_BAND];
	uint8_t chan;
	int i;

	iwn_read_prom_data(sc, addr, channels,
	    band->nchan * sizeof (struct iwn_eeprom_chan));

	for (i = 0; i < band->nchan; i++) {
		if (!(channels[i].flags & IWN_EEPROM_CHAN_VALID))
			continue;

		chan = band->chan[i];

		if (n == 0) {	/* 2GHz band */
			ic->ic_sup_channels[chan].ich_freq =
			    ieee80211_ieee2mhz(chan, IEEE80211_CHAN_2GHZ);
			ic->ic_sup_channels[chan].ich_flags =
			    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
			    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;

		} else {	/* 5GHz band */
			/*
			 * Some adapters support channels 7, 8, 11 and 12
			 * both in the 2GHz and 4.9GHz bands.
			 * Because of limitations in our net80211 layer,
			 * we don't support them in the 4.9GHz band.
			 */
			if (chan <= 14)
				continue;

			ic->ic_sup_channels[chan].ich_freq =
			    ieee80211_ieee2mhz(chan, IEEE80211_CHAN_5GHZ);
			ic->ic_sup_channels[chan].ich_flags =
			    IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM;
			/* We have at least one valid 5GHz channel. */
			sc->sc_flags |= IWN_FLAG_HAS_5GHZ;
		}

		/* Is active scan allowed on this channel? */
		if (!(channels[i].flags & IWN_EEPROM_CHAN_ACTIVE)) {
			ic->ic_sup_channels[chan].ich_flags |=
			    IEEE80211_CHAN_PASSIVE;
		}

		/* Save maximum allowed TX power for this channel. */
		sc->maxpwr[chan] = channels[i].maxpwr;

		IWN_DBG("adding chan %d flags=0x%x maxpwr=%d",
		    chan, channels[i].flags, sc->maxpwr[chan]);
	}
}

static void
iwn_read_eeprom_enhinfo(struct iwn_softc *sc)
{
	struct iwn_eeprom_enhinfo enhinfo[35];
	uint16_t val, base;
	int8_t maxpwr;
	int i;

	iwn_read_prom_data(sc, IWN5000_EEPROM_REG, &val, 2);
	base = le16toh(val);
	iwn_read_prom_data(sc, base + IWN6000_EEPROM_ENHINFO,
	    enhinfo, sizeof enhinfo);

	memset(sc->enh_maxpwr, 0, sizeof sc->enh_maxpwr);
	for (i = 0; i < __arraycount(enhinfo); i++) {
		if (enhinfo[i].chan == 0 || enhinfo[i].reserved != 0)
			continue;	/* Skip invalid entries. */

		maxpwr = 0;
		if (sc->txchainmask & IWN_ANT_A)
			maxpwr = MAX(maxpwr, enhinfo[i].chain[0]);
		if (sc->txchainmask & IWN_ANT_B)
			maxpwr = MAX(maxpwr, enhinfo[i].chain[1]);
		if (sc->txchainmask & IWN_ANT_C)
			maxpwr = MAX(maxpwr, enhinfo[i].chain[2]);
		if (sc->ntxchains == 2)
			maxpwr = MAX(maxpwr, enhinfo[i].mimo2);
		else if (sc->ntxchains == 3)
			maxpwr = MAX(maxpwr, enhinfo[i].mimo3);
		maxpwr /= 2;	/* Convert half-dBm to dBm. */

		IWN_DBG("enhinfo %d, maxpwr=%d", i, maxpwr);
		sc->enh_maxpwr[i] = maxpwr;
	}
}

static struct ieee80211_node *
iwn_node_alloc(ieee80211com_t *ic)
{
	_NOTE(ARGUNUSED(ic));
	return (kmem_zalloc(sizeof (struct iwn_node), KM_NOSLEEP));
}

static void
iwn_node_free(ieee80211_node_t *in)
{
	ASSERT(in != NULL);
	ASSERT(in->in_ic != NULL);

	if (in->in_wpa_ie != NULL)
		ieee80211_free(in->in_wpa_ie);

	if (in->in_wme_ie != NULL)
		ieee80211_free(in->in_wme_ie);

	if (in->in_htcap_ie != NULL)
		ieee80211_free(in->in_htcap_ie);

	kmem_free(in, sizeof (struct iwn_node));
}

static void
iwn_newassoc(struct ieee80211_node *ni, int isnew)
{
	_NOTE(ARGUNUSED(isnew));
	struct iwn_softc *sc = (struct iwn_softc *)&ni->in_ic;
	struct iwn_node *wn = (void *)ni;
	uint8_t rate, ridx;
	int i;

	ieee80211_amrr_node_init(&sc->amrr, &wn->amn);
	/*
	 * Select a medium rate and depend on AMRR to raise/lower it.
	 */
	ni->in_txrate = ni->in_rates.ir_nrates / 2;

	for (i = 0; i < ni->in_rates.ir_nrates; i++) {
		rate = ni->in_rates.ir_rates[i] & IEEE80211_RATE_VAL;
		/* Map 802.11 rate to HW rate index. */
		for (ridx = 0; ridx <= IWN_RIDX_MAX; ridx++)
			if (iwn_rates[ridx].rate == rate)
				break;
		wn->ridx[i] = ridx;
	}
}

static int
iwn_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct iwn_softc *sc = (struct iwn_softc *)ic;
	enum ieee80211_state ostate;
	int error;

	mutex_enter(&sc->sc_mtx);
	sc->sc_flags |= IWN_FLAG_STOP_CALIB_TO;
	mutex_exit(&sc->sc_mtx);

	(void) untimeout(sc->calib_to);
	sc->calib_to = 0;

	mutex_enter(&sc->sc_mtx);
	ostate = ic->ic_state;

	DTRACE_PROBE5(new__state, int, sc->sc_flags,
	    enum ieee80211_state, ostate,
	    const char *, ieee80211_state_name[ostate],
	    enum ieee80211_state, nstate,
	    const char *, ieee80211_state_name[nstate]);

	if ((sc->sc_flags & IWN_FLAG_RADIO_OFF) && nstate != IEEE80211_S_INIT) {
		mutex_exit(&sc->sc_mtx);
		return (IWN_FAIL);
	}

	if (!(sc->sc_flags & IWN_FLAG_HW_INITED) &&
	    nstate != IEEE80211_S_INIT) {
		mutex_exit(&sc->sc_mtx);
		return (IWN_FAIL);
	}

	switch (nstate) {
	case IEEE80211_S_SCAN:
		/* XXX Do not abort a running scan. */
		if (sc->sc_flags & IWN_FLAG_SCANNING) {
			if (ostate != nstate)
				dev_err(sc->sc_dip, CE_WARN, "!scan request(%d)"
				    " while scanning(%d) ignored", nstate,
				    ostate);
			mutex_exit(&sc->sc_mtx);
			return (0);
		}

		bcopy(&sc->rxon, &sc->rxon_save, sizeof (sc->rxon));
		sc->sc_ostate = ostate;

		/* XXX Not sure if call and flags are needed. */
		ieee80211_node_table_reset(&ic->ic_scan);
		ic->ic_flags |= IEEE80211_F_SCAN | IEEE80211_F_ASCAN;
		sc->sc_flags |= IWN_FLAG_SCANNING_2GHZ;

		/* Make the link LED blink while we're scanning. */
		iwn_set_led(sc, IWN_LED_LINK, 10, 10);

		ic->ic_state = nstate;

		error = iwn_scan(sc, IEEE80211_CHAN_2GHZ);
		if (error != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not initiate scan");
			sc->sc_flags &= ~IWN_FLAG_SCANNING;
			mutex_exit(&sc->sc_mtx);
			return (error);
		}

		mutex_exit(&sc->sc_mtx);
		sc->scan_to = timeout(iwn_abort_scan, sc, iwn_scan_timeout *
		    drv_usectohz(MICROSEC));
		return (error);

	case IEEE80211_S_ASSOC:
		if (ostate != IEEE80211_S_RUN) {
			mutex_exit(&sc->sc_mtx);
			break;
		}
		/* FALLTHROUGH */
	case IEEE80211_S_AUTH:
		/* Reset state to handle reassociations correctly. */
		sc->rxon.associd = 0;
		sc->rxon.filter &= ~htole32(IWN_FILTER_BSS);
		sc->calib.state = IWN_CALIB_STATE_INIT;

		if ((error = iwn_auth(sc)) != 0) {
			mutex_exit(&sc->sc_mtx);
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not move to auth state");
			return error;
		}
		mutex_exit(&sc->sc_mtx);
		break;

	case IEEE80211_S_RUN:
		if ((error = iwn_run(sc)) != 0) {
			mutex_exit(&sc->sc_mtx);
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not move to run state");
			return error;
		}
		mutex_exit(&sc->sc_mtx);
		break;

	case IEEE80211_S_INIT:
		sc->sc_flags &= ~IWN_FLAG_SCANNING;
		sc->calib.state = IWN_CALIB_STATE_INIT;

		/*
		 * set LED off after init
		 */
		iwn_set_led(sc, IWN_LED_LINK, 1, 0);

		cv_signal(&sc->sc_scan_cv);
		mutex_exit(&sc->sc_mtx);
		if (sc->scan_to != 0)
			(void) untimeout(sc->scan_to);
		sc->scan_to = 0;
		break;
	}

	error = sc->sc_newstate(ic, nstate, arg);

	if (nstate == IEEE80211_S_RUN)
		ieee80211_start_watchdog(ic, 1);

	return (error);
}

static void
iwn_iter_func(void *arg, struct ieee80211_node *ni)
{
	struct iwn_softc *sc = arg;
	struct iwn_node *wn = (struct iwn_node *)ni;

	ieee80211_amrr_choose(&sc->amrr, ni, &wn->amn);
}

static void
iwn_calib_timeout(void *arg)
{
	struct iwn_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;

	mutex_enter(&sc->sc_mtx);

	if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) {
		if (ic->ic_opmode == IEEE80211_M_STA)
			iwn_iter_func(sc, ic->ic_bss);
		else
			ieee80211_iterate_nodes(&ic->ic_sta, iwn_iter_func, sc);
	}
	/* Force automatic TX power calibration every 60 secs. */
	if (++sc->calib_cnt >= 120) {
		uint32_t flags = 0;

		DTRACE_PROBE(get__statistics);
		(void)iwn_cmd(sc, IWN_CMD_GET_STATISTICS, &flags,
		    sizeof flags, 1);
		sc->calib_cnt = 0;
	}

	/* Automatic rate control triggered every 500ms. */
	if ((sc->sc_flags & IWN_FLAG_STOP_CALIB_TO) == 0)
		sc->calib_to = timeout(iwn_calib_timeout, sc,
		    drv_usectohz(500000));

	mutex_exit(&sc->sc_mtx);
}

/*
 * Process an RX_PHY firmware notification.  This is usually immediately
 * followed by an MPDU_RX_DONE notification.
 */
static void
iwn_rx_phy(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
	struct iwn_rx_stat *stat = (struct iwn_rx_stat *)(desc + 1);

	(void) ddi_dma_sync(data->dma_data.dma_hdl, sizeof (*desc),
	    sizeof (*stat), DDI_DMA_SYNC_FORKERNEL);

	DTRACE_PROBE1(rx__phy, struct iwn_rx_stat *, stat);

	/* Save RX statistics, they will be used on MPDU_RX_DONE. */
	memcpy(&sc->last_rx_stat, stat, sizeof (*stat));
	sc->last_rx_valid = 1;
}

/*
 * Process an RX_DONE (4965AGN only) or MPDU_RX_DONE firmware notification.
 * Each MPDU_RX_DONE notification must be preceded by an RX_PHY one.
 */
static void
iwn_rx_done(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
	struct iwn_ops *ops = &sc->ops;
	struct ieee80211com *ic = &sc->sc_ic;
	struct iwn_rx_ring *ring = &sc->rxq;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	mblk_t *m;
	struct iwn_rx_stat *stat;
	char	*head;
	uint32_t flags;
	int len, rssi;

	if (desc->type == IWN_MPDU_RX_DONE) {
		/* Check for prior RX_PHY notification. */
		if (!sc->last_rx_valid) {
			dev_err(sc->sc_dip, CE_WARN,
			    "missing RX_PHY");
			return;
		}
		sc->last_rx_valid = 0;
		stat = &sc->last_rx_stat;
	} else
		stat = (struct iwn_rx_stat *)(desc + 1);

	(void) ddi_dma_sync(data->dma_data.dma_hdl, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	if (stat->cfg_phy_len > IWN_STAT_MAXLEN) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!invalid RX statistic header");
		return;
	}
	if (desc->type == IWN_MPDU_RX_DONE) {
		struct iwn_rx_mpdu *mpdu = (struct iwn_rx_mpdu *)(desc + 1);
		head = (char *)(mpdu + 1);
		len = le16toh(mpdu->len);
	} else {
		head = (char *)(stat + 1) + stat->cfg_phy_len;
		len = le16toh(stat->len);
	}
	/*LINTED: E_PTR_BAD_CAST_ALIGN*/
	flags = le32toh(*(uint32_t *)(head + len));

	/* Discard frames with a bad FCS early. */
	if ((flags & IWN_RX_NOERROR) != IWN_RX_NOERROR) {
		sc->sc_rx_err++;
		ic->ic_stats.is_fcs_errors++;
		return;
	}
	/* Discard frames that are too short. */
	if (len < sizeof (*wh)) {
		sc->sc_rx_err++;
		return;
	}

	m = allocb(len, BPRI_MED);
	if (m == NULL) {
		sc->sc_rx_nobuf++;
		return;
	}

	/* Update RX descriptor. */
	ring->desc[ring->cur] =
	    htole32(data->dma_data.paddr >> 8);
	(void) ddi_dma_sync(ring->desc_dma.dma_hdl,
	    ring->cur * sizeof (uint32_t), sizeof (uint32_t),
	    DDI_DMA_SYNC_FORDEV);

	/* Grab a reference to the source node. */
	wh = (struct ieee80211_frame*)head;
	ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame *)wh);

	/* XXX OpenBSD adds decryption here (see also comments in iwn_tx). */
	/* NetBSD does decryption in ieee80211_input. */

	rssi = ops->get_rssi(stat);

	/*
	 * convert dBm to percentage
	 */
	rssi = (100 * 75 * 75 - (-20 - rssi) * (15 * 75 + 62 * (-20 - rssi)))
	    / (75 * 75);
	if (rssi > 100)
		rssi = 100;
	else if (rssi < 1)
		rssi = 1;

	bcopy(wh, m->b_wptr, len);
	m->b_wptr += len;

	/* XXX Added for NetBSD: scans never stop without it */
	if (ic->ic_state == IEEE80211_S_SCAN)
		iwn_fix_channel(sc, m, stat);

	/* Send the frame to the 802.11 layer. */
	ieee80211_input(ic, m, ni, rssi, 0);

	/* Node is no longer needed. */
	ieee80211_free_node(ni);
}

#ifndef IEEE80211_NO_HT
/* Process an incoming Compressed BlockAck. */
static void
iwn_rx_compressed_ba(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
	struct iwn_compressed_ba *ba = (struct iwn_compressed_ba *)(desc + 1);
	struct iwn_tx_ring *txq;

	(void) ddi_dma_sync(data->dma_data.dma_hdl, sizeof (*desc),
	    sizeof (*ba), DDI_DMA_SYNC_FORKERNEL);

	txq = &sc->txq[le16toh(ba->qid)];
	/* XXX TBD */
}
#endif

/*
 * Process a CALIBRATION_RESULT notification sent by the initialization
 * firmware on response to a CMD_CALIB_CONFIG command (5000 only).
 */
static void
iwn5000_rx_calib_results(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
	struct iwn_phy_calib *calib = (struct iwn_phy_calib *)(desc + 1);
	int len, idx = -1;

	/* Runtime firmware should not send such a notification. */
	if (sc->sc_flags & IWN_FLAG_CALIB_DONE)
		return;

	len = (le32toh(desc->len) & 0x3fff) - 4;
	(void) ddi_dma_sync(data->dma_data.dma_hdl, sizeof (*desc), len,
	    DDI_DMA_SYNC_FORKERNEL);

	switch (calib->code) {
	case IWN5000_PHY_CALIB_DC:
		if (sc->hw_type == IWN_HW_REV_TYPE_5150 ||
		    sc->hw_type == IWN_HW_REV_TYPE_2030 ||
		    sc->hw_type == IWN_HW_REV_TYPE_2000 ||
		    sc->hw_type == IWN_HW_REV_TYPE_135  ||
		    sc->hw_type == IWN_HW_REV_TYPE_105)
			idx = 0;
		break;
	case IWN5000_PHY_CALIB_LO:
		idx = 1;
		break;
	case IWN5000_PHY_CALIB_TX_IQ:
		idx = 2;
		break;
	case IWN5000_PHY_CALIB_TX_IQ_PERIODIC:
		if (sc->hw_type < IWN_HW_REV_TYPE_6000 &&
		    sc->hw_type != IWN_HW_REV_TYPE_5150)
			idx = 3;
		break;
	case IWN5000_PHY_CALIB_BASE_BAND:
		idx = 4;
		break;
	}
	if (idx == -1)	/* Ignore other results. */
		return;

	/* Save calibration result. */
	if (sc->calibcmd[idx].buf != NULL)
		kmem_free(sc->calibcmd[idx].buf, sc->calibcmd[idx].len);
	sc->calibcmd[idx].buf = kmem_zalloc(len, KM_NOSLEEP);
	if (sc->calibcmd[idx].buf == NULL) {
		return;
	}
	sc->calibcmd[idx].len = len;
	memcpy(sc->calibcmd[idx].buf, calib, len);
}

/*
 * Process an RX_STATISTICS or BEACON_STATISTICS firmware notification.
 * The latter is sent by the firmware after each received beacon.
 */
static void
iwn_rx_statistics(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
	struct iwn_ops *ops = &sc->ops;
	struct ieee80211com *ic = &sc->sc_ic;
	struct iwn_calib_state *calib = &sc->calib;
	struct iwn_stats *stats = (struct iwn_stats *)(desc + 1);
	int temp = 0;

	/* Ignore statistics received during a scan. */
	if (ic->ic_state != IEEE80211_S_RUN)
		return;

	(void) ddi_dma_sync(data->dma_data.dma_hdl, sizeof (*desc),
	    sizeof (*stats), DDI_DMA_SYNC_FORKERNEL);

	sc->calib_cnt = 0;	/* Reset TX power calibration timeout. */

	/* Test if temperature has changed. */
	if (stats->general.temp != sc->rawtemp) {
		/* Convert "raw" temperature to degC. */
		sc->rawtemp = stats->general.temp;
		temp = ops->get_temperature(sc);
		sc->sc_misc->temp.value.ul = temp;

		/* Update TX power if need be (4965AGN only). */
		if (sc->hw_type == IWN_HW_REV_TYPE_4965)
			iwn4965_power_calibration(sc, temp);
	}

	DTRACE_PROBE2(rx__statistics, struct iwn_stats *, stats, int, temp);

	if (desc->type != IWN_BEACON_STATISTICS)
		return;	/* Reply to a statistics request. */

	sc->noise = iwn_get_noise(&stats->rx.general);
	sc->sc_misc->noise.value.l = sc->noise;

	/* Test that RSSI and noise are present in stats report. */
	if (le32toh(stats->rx.general.flags) != 1) {
		return;
	}

	/*
	 * XXX Differential gain calibration makes the 6005 firmware
	 * crap out, so skip it for now.  This effectively disables
	 * sensitivity tuning as well.
	 */
	if (sc->hw_type == IWN_HW_REV_TYPE_6005)
		return;

	if (calib->state == IWN_CALIB_STATE_ASSOC)
		iwn_collect_noise(sc, &stats->rx.general);
	else if (calib->state == IWN_CALIB_STATE_RUN)
		iwn_tune_sensitivity(sc, &stats->rx);
}

/*
 * Process a TX_DONE firmware notification.  Unfortunately, the 4965AGN
 * and 5000 adapters have different incompatible TX status formats.
 */
static void
iwn4965_tx_done(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
	struct iwn4965_tx_stat *stat = (struct iwn4965_tx_stat *)(desc + 1);

	(void) ddi_dma_sync(data->dma_data.dma_hdl, sizeof (*desc),
	    sizeof (*stat), DDI_DMA_SYNC_FORKERNEL);
	iwn_tx_done(sc, desc, stat->ackfailcnt, le32toh(stat->status) & 0xff);
}

static void
iwn5000_tx_done(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
	struct iwn5000_tx_stat *stat = (struct iwn5000_tx_stat *)(desc + 1);

#ifdef notyet
	/* Reset TX scheduler slot. */
	iwn5000_reset_sched(sc, desc->qid & 0xf, desc->idx);
#endif

	(void) ddi_dma_sync(data->dma_data.dma_hdl, sizeof (*desc),
	    sizeof (*stat), DDI_DMA_SYNC_FORKERNEL);
	iwn_tx_done(sc, desc, stat->ackfailcnt, le16toh(stat->status) & 0xff);
}

/*
 * Adapter-independent backend for TX_DONE firmware notifications.
 */
static void
iwn_tx_done(struct iwn_softc *sc, struct iwn_rx_desc *desc, int ackfailcnt,
    uint8_t status)
{
	struct iwn_tx_ring *ring = &sc->txq[desc->qid & 0xf];
	struct iwn_tx_data *data = &ring->data[desc->idx];
	struct iwn_node *wn = (struct iwn_node *)data->ni;

	/* Update rate control statistics. */
	wn->amn.amn_txcnt++;
	if (ackfailcnt > 0)
		wn->amn.amn_retrycnt++;

	if (status != 1 && status != 2)
		sc->sc_tx_err++;
	else
		sc->sc_ic.ic_stats.is_tx_frags++;

	ieee80211_free_node(data->ni);
	data->ni = NULL;

	mutex_enter(&sc->sc_tx_mtx);
	sc->sc_tx_timer = 0;
	if (--ring->queued < IWN_TX_RING_LOMARK) {
		sc->qfullmsk &= ~(1 << ring->qid);
	}
	mac_tx_update(sc->sc_ic.ic_mach);
	mutex_exit(&sc->sc_tx_mtx);
}

/*
 * Process a "command done" firmware notification.  This is where we wakeup
 * processes waiting for a synchronous command completion.
 */
static void
iwn_cmd_done(struct iwn_softc *sc, struct iwn_rx_desc *desc)
{
	struct iwn_tx_ring *ring = &sc->txq[IWN_CMD_QUEUE_NUM];
	struct iwn_tx_data *data;

	if ((desc->qid & 0xf) != IWN_CMD_QUEUE_NUM)
		return;	/* Not a command ack. */

	data = &ring->data[desc->idx];

	(void) ddi_dma_sync(data->dma_data.dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);

	/* If the command was mapped in an extra buffer, free it. */
	if (data->cmd_dma.dma_hdl) {
		(void) ddi_dma_sync(data->cmd_dma.dma_hdl, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
		iwn_dma_contig_free(&data->cmd_dma);
	}

	mutex_enter(&sc->sc_mtx);
	sc->sc_cmd_flag = SC_CMD_FLG_DONE;
	cv_signal(&sc->sc_cmd_cv);
	mutex_exit(&sc->sc_mtx);
}

/*
 * Process an INT_FH_RX or INT_SW_RX interrupt.
 */
static void
iwn_notif_intr(struct iwn_softc *sc)
{
	struct iwn_ops *ops = &sc->ops;
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t hw;

	ASSERT(sc != NULL);

	(void) ddi_dma_sync(sc->rxq.stat_dma.dma_hdl, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	hw = le16toh(sc->rxq.stat->closed_count) & 0xfff;
	while (sc->rxq.cur != hw) {
		struct iwn_rx_data *data = &sc->rxq.data[sc->rxq.cur];
		struct iwn_rx_desc *desc;

		(void) ddi_dma_sync(data->dma_data.dma_hdl, 0, sizeof (*desc),
		    DDI_DMA_SYNC_FORKERNEL);
		desc = (struct iwn_rx_desc *)data->dma_data.vaddr;

		DTRACE_PROBE1(notification__intr, struct iwn_rx_desc *, desc);

		if (!(desc->qid & 0x80))	/* Reply to a command. */
			iwn_cmd_done(sc, desc);

		switch (desc->type) {
		case IWN_RX_PHY:
			iwn_rx_phy(sc, desc, data);
			break;

		case IWN_RX_DONE:		/* 4965AGN only. */
		case IWN_MPDU_RX_DONE:
			/* An 802.11 frame has been received. */
			iwn_rx_done(sc, desc, data);
			break;
#ifndef IEEE80211_NO_HT
		case IWN_RX_COMPRESSED_BA:
			/* A Compressed BlockAck has been received. */
			iwn_rx_compressed_ba(sc, desc, data);
			break;
#endif
		case IWN_TX_DONE:
			/* An 802.11 frame has been transmitted. */
			ops->tx_done(sc, desc, data);
			break;

		case IWN_RX_STATISTICS:
		case IWN_BEACON_STATISTICS:
			mutex_enter(&sc->sc_mtx);
			iwn_rx_statistics(sc, desc, data);
			mutex_exit(&sc->sc_mtx);
			break;

		case IWN_BEACON_MISSED:
		{
			struct iwn_beacon_missed *miss =
			    (struct iwn_beacon_missed *)(desc + 1);

			(void) ddi_dma_sync(data->dma_data.dma_hdl,
			    sizeof (*desc), sizeof (*miss),
			    DDI_DMA_SYNC_FORKERNEL);
			/*
			 * If more than iwn_beacons_missed_disconnect
			 * consecutive beacons are missed, we've probably lost
			 * our connection.
			 * If more than iwn_beacons_missed_sensitivity
			 * consecutive beacons are missed, reinitialize the
			 * sensitivity state machine.
			 */
			DTRACE_PROBE1(beacons__missed,
			    struct iwn_beacon_missed *, miss);
			if (ic->ic_state == IEEE80211_S_RUN) {
				if (le32toh(miss->consecutive)
				    > iwn_beacons_missed_disconnect) {
					dev_err(sc->sc_dip, CE_WARN,
					    "!iwn_notif_intr(): %d consecutive "
					    "beacons missed, disconnecting",
					    le32toh(miss->consecutive));
					ieee80211_new_state(ic,
					    IEEE80211_S_INIT, -1);
				} else if (le32toh(miss->consecutive)
				    > iwn_beacons_missed_sensitivity) {
					mutex_enter(&sc->sc_mtx);
					(void)iwn_init_sensitivity(sc);
					mutex_exit(&sc->sc_mtx);
				}
			}
			break;
		}
		case IWN_UC_READY:
		{
			struct iwn_ucode_info *uc =
			    (struct iwn_ucode_info *)(desc + 1);

			/* The microcontroller is ready. */
			(void) ddi_dma_sync(data->dma_data.dma_hdl,
			    sizeof (*desc), sizeof (*uc),
			    DDI_DMA_SYNC_FORKERNEL);
			DTRACE_PROBE1(uc__ready, struct iwn_ucode_info *, uc)

			if (le32toh(uc->valid) != 1) {
				dev_err(sc->sc_dip, CE_WARN,
				    "!microcontroller initialization failed");
				break;
			}
			if (uc->subtype == IWN_UCODE_INIT) {
				/* Save microcontroller report. */
				memcpy(&sc->ucode_info, uc, sizeof (*uc));
			}
			/* Save the address of the error log in SRAM. */
			sc->errptr = le32toh(uc->errptr);
			break;
		}
		case IWN_STATE_CHANGED:
		{
			/*LINTED: E_PTR_BAD_CAST_ALIGN*/
			uint32_t *status = (uint32_t *)(desc + 1);

			/* Enabled/disabled notification. */
			(void) ddi_dma_sync(data->dma_data.dma_hdl,
			    sizeof (*desc), sizeof (*status),
			    DDI_DMA_SYNC_FORKERNEL);
			DTRACE_PROBE1(state__changed, uint32_t, *status);

			if (le32toh(*status) & 1) {
				/* The radio button has to be pushed. */
				dev_err(sc->sc_dip, CE_WARN,
				    "!Radio transmitter is off");
				/* Turn the interface down. */
				mutex_enter(&sc->sc_mtx);
				sc->sc_flags |=
				    IWN_FLAG_HW_ERR_RECOVER |
				    IWN_FLAG_RADIO_OFF;
				mutex_exit(&sc->sc_mtx);
				ieee80211_new_state(&sc->sc_ic,
				    IEEE80211_S_INIT, -1);

				return;	/* No further processing. */
			}
			break;
		}
		case IWN_START_SCAN:
		{
			struct iwn_start_scan *scan =
			    (struct iwn_start_scan *)(desc + 1);

			(void) ddi_dma_sync(data->dma_data.dma_hdl,
			    sizeof (*desc), sizeof (*scan),
			    DDI_DMA_SYNC_FORKERNEL);
			DTRACE_PROBE2(start__scan, uint8_t, scan->chan,
			    uint32_t, le32toh(scan->status));

			/* Fix current channel. */
			ic->ic_curchan = ic->ic_bss->in_chan =
			    &ic->ic_sup_channels[scan->chan];
			break;
		}
		case IWN_STOP_SCAN:
		{
			struct iwn_stop_scan *scan =
			    (struct iwn_stop_scan *)(desc + 1);

			(void) ddi_dma_sync(data->dma_data.dma_hdl,
			    sizeof (*desc), sizeof (*scan),
			    DDI_DMA_SYNC_FORKERNEL);
			DTRACE_PROBE3(stop__scan, uint8_t, scan->chan,
			    uint32_t, le32toh(scan->status),
			    uint8_t, scan->nchan);

			if (iwn_enable_5ghz != 0 &&
			    (sc->sc_flags & IWN_FLAG_SCANNING_2GHZ) &&
			    (sc->sc_flags & IWN_FLAG_HAS_5GHZ)) {
				/*
				 * We just finished scanning 2GHz channels,
				 * start scanning 5GHz ones.
				 */
				mutex_enter(&sc->sc_mtx);
				sc->sc_flags |= IWN_FLAG_SCANNING_5GHZ;
				sc->sc_flags &= ~IWN_FLAG_SCANNING_2GHZ;
				if (iwn_scan(sc, IEEE80211_CHAN_5GHZ) == 0) {
					mutex_exit(&sc->sc_mtx);
					break;
				}
				mutex_exit(&sc->sc_mtx);
			}
			ieee80211_end_scan(ic);
			mutex_enter(&sc->sc_mtx);
			sc->sc_flags &= ~IWN_FLAG_SCANNING;
			cv_signal(&sc->sc_scan_cv);
			mutex_exit(&sc->sc_mtx);
			(void) untimeout(sc->scan_to);
			sc->scan_to = 0;
			break;
		}
		case IWN5000_CALIBRATION_RESULT:
			iwn5000_rx_calib_results(sc, desc, data);
			break;

		case IWN5000_CALIBRATION_DONE:
			mutex_enter(&sc->sc_mtx);
			sc->sc_flags |= IWN_FLAG_CALIB_DONE;
			cv_signal(&sc->sc_calib_cv);
			mutex_exit(&sc->sc_mtx);
			break;
		}

		sc->rxq.cur = (sc->rxq.cur + 1) % IWN_RX_RING_COUNT;
	}

	/* Tell the firmware what we have processed. */
	hw = (hw == 0) ? IWN_RX_RING_COUNT - 1 : hw - 1;
	IWN_WRITE(sc, IWN_FH_RX_WPTR, hw & ~7);
}

/*
 * Process an INT_WAKEUP interrupt raised when the microcontroller wakes up
 * from power-down sleep mode.
 */
static void
iwn_wakeup_intr(struct iwn_softc *sc)
{
	int qid;

	DTRACE_PROBE(wakeup__intr);

	/* Wakeup RX and TX rings. */
	IWN_WRITE(sc, IWN_FH_RX_WPTR, sc->rxq.cur & ~7);
	for (qid = 0; qid < sc->ntxqs; qid++) {
		struct iwn_tx_ring *ring = &sc->txq[qid];
		IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | ring->cur);
	}
}

/*
 * Dump the error log of the firmware when a firmware panic occurs.  Although
 * we can't debug the firmware because it is neither open source nor free, it
 * can help us to identify certain classes of problems.
 */
static void
iwn_fatal_intr(struct iwn_softc *sc)
{
	struct iwn_fw_dump dump;
	int i;

	/* Force a complete recalibration on next init. */
	sc->sc_flags &= ~IWN_FLAG_CALIB_DONE;

	/* Check that the error log address is valid. */
	if (sc->errptr < IWN_FW_DATA_BASE ||
	    sc->errptr + sizeof (dump) >
	    IWN_FW_DATA_BASE + sc->fw_data_maxsz) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!bad firmware error log address 0x%08x", sc->errptr);
		return;
	}
	if (iwn_nic_lock(sc) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not read firmware error log");
		return;
	}
	/* Read firmware error log from SRAM. */
	/*LINTED: E_PTR_BAD_CAST_ALIGN*/
	iwn_mem_read_region_4(sc, sc->errptr, (uint32_t *)&dump,
	    sizeof (dump) / sizeof (uint32_t));
	iwn_nic_unlock(sc);

	if (dump.valid == 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!firmware error log is empty");
		return;
	}
	dev_err(sc->sc_dip, CE_WARN, "!firmware error log:");
	dev_err(sc->sc_dip, CE_CONT, "!  error type      = \"%s\" (0x%08X)",
	    (dump.id < __arraycount(iwn_fw_errmsg)) ?
		iwn_fw_errmsg[dump.id] : "UNKNOWN",
	    dump.id);
	dev_err(sc->sc_dip, CE_CONT, "!  program counter = 0x%08X", dump.pc);
	dev_err(sc->sc_dip, CE_CONT, "!  source line     = 0x%08X",
	    dump.src_line);
	dev_err(sc->sc_dip, CE_CONT, "!  error data      = 0x%08X%08X",
	    dump.error_data[0], dump.error_data[1]);
	dev_err(sc->sc_dip, CE_CONT, "!  branch link     = 0x%08X%08X",
	    dump.branch_link[0], dump.branch_link[1]);
	dev_err(sc->sc_dip, CE_CONT, "!  interrupt link  = 0x%08X%08X",
	    dump.interrupt_link[0], dump.interrupt_link[1]);
	dev_err(sc->sc_dip, CE_CONT, "!  time            = %u", dump.time[0]);

	/* Dump driver status (TX and RX rings) while we're here. */
	dev_err(sc->sc_dip, CE_WARN, "!driver status:");
	for (i = 0; i < sc->ntxqs; i++) {
		struct iwn_tx_ring *ring = &sc->txq[i];
		dev_err(sc->sc_dip, CE_WARN,
		    "!  tx ring %2d: qid=%2d cur=%3d queued=%3d",
		    i, ring->qid, ring->cur, ring->queued);
	}
	dev_err(sc->sc_dip, CE_WARN, "!  rx ring: cur=%d", sc->rxq.cur);
	dev_err(sc->sc_dip, CE_WARN, "!  802.11 state %d", sc->sc_ic.ic_state);
}

/*ARGSUSED1*/
static uint_t
iwn_intr(caddr_t arg, caddr_t unused)
{
	_NOTE(ARGUNUSED(unused));
	/*LINTED: E_PTR_BAD_CAST_ALIGN*/
	struct iwn_softc *sc = (struct iwn_softc *)arg;
	uint32_t r1, r2, tmp;

	if (sc == NULL)
		return (DDI_INTR_UNCLAIMED);

	/* Disable interrupts. */
	IWN_WRITE(sc, IWN_INT_MASK, 0);

	/* Read interrupts from ICT (fast) or from registers (slow). */
	if (sc->sc_flags & IWN_FLAG_USE_ICT) {
		(void) ddi_dma_sync(sc->ict_dma.dma_hdl, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		tmp = 0;
		while (sc->ict[sc->ict_cur] != 0) {
			tmp |= sc->ict[sc->ict_cur];
			sc->ict[sc->ict_cur] = 0;	/* Acknowledge. */
			sc->ict_cur = (sc->ict_cur + 1) % IWN_ICT_COUNT;
		}
		(void) ddi_dma_sync(sc->ict_dma.dma_hdl, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
		tmp = le32toh(tmp);
		if (tmp == 0xffffffff)	/* Shouldn't happen. */
			tmp = 0;
		else if (tmp & 0xc0000)	/* Workaround a HW bug. */
			tmp |= 0x8000;
		r1 = (tmp & 0xff00) << 16 | (tmp & 0xff);
		r2 = 0;	/* Unused. */
	} else {
		r1 = IWN_READ(sc, IWN_INT);
		if (r1 == 0xffffffff || (r1 & 0xfffffff0) == 0xa5a5a5a0)
			return (DDI_INTR_UNCLAIMED);	/* Hardware gone! */
		r2 = IWN_READ(sc, IWN_FH_INT);
	}
	if (r1 == 0 && r2 == 0) {
		IWN_WRITE(sc, IWN_INT_MASK, sc->int_mask);
		return (DDI_INTR_UNCLAIMED);	/* Interrupt not for us. */
	}

	/* Acknowledge interrupts. */
	IWN_WRITE(sc, IWN_INT, r1);
	if (!(sc->sc_flags & IWN_FLAG_USE_ICT))
		IWN_WRITE(sc, IWN_FH_INT, r2);

	if (r1 & IWN_INT_RF_TOGGLED) {
		tmp = IWN_READ(sc, IWN_GP_CNTRL);
		dev_err(sc->sc_dip, CE_NOTE,
		    "!RF switch: radio %s",
		    (tmp & IWN_GP_CNTRL_RFKILL) ? "enabled" : "disabled");
	}
	if (r1 & IWN_INT_CT_REACHED) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!critical temperature reached!");
	}
	if (r1 & (IWN_INT_SW_ERR | IWN_INT_HW_ERR)) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!fatal firmware error");
		/* Dump firmware error log and stop. */
		iwn_fatal_intr(sc);
		iwn_hw_stop(sc, B_TRUE);
		if (!IWN_CHK_FAST_RECOVER(sc))
			ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		mutex_enter(&sc->sc_mtx);
		sc->sc_flags |= IWN_FLAG_HW_ERR_RECOVER;
		mutex_exit(&sc->sc_mtx);

		return (DDI_INTR_CLAIMED);
	}
	if ((r1 & (IWN_INT_FH_RX | IWN_INT_SW_RX | IWN_INT_RX_PERIODIC)) ||
	    (r2 & IWN_FH_INT_RX)) {
		if (sc->sc_flags & IWN_FLAG_USE_ICT) {
			int ena = (r1 & (IWN_INT_FH_RX | IWN_INT_SW_RX));

			if (ena)
				IWN_WRITE(sc, IWN_FH_INT, IWN_FH_INT_RX);
			IWN_WRITE_1(sc, IWN_INT_PERIODIC,
			    IWN_INT_PERIODIC_DIS);
			iwn_notif_intr(sc);
			if (ena)
				IWN_WRITE_1(sc, IWN_INT_PERIODIC,
				    IWN_INT_PERIODIC_ENA);
		} else {
			iwn_notif_intr(sc);
		}
	}

	if ((r1 & IWN_INT_FH_TX) || (r2 & IWN_FH_INT_TX)) {
		if (sc->sc_flags & IWN_FLAG_USE_ICT)
			IWN_WRITE(sc, IWN_FH_INT, IWN_FH_INT_TX);
		mutex_enter(&sc->sc_mtx);
		sc->sc_flags |= IWN_FLAG_FW_DMA;
		cv_signal(&sc->sc_fhdma_cv);
		mutex_exit(&sc->sc_mtx);
	}

	if (r1 & IWN_INT_ALIVE) {
		mutex_enter(&sc->sc_mtx);
		sc->sc_flags |= IWN_FLAG_FW_ALIVE;
		cv_signal(&sc->sc_alive_cv);
		mutex_exit(&sc->sc_mtx);
	}

	if (r1 & IWN_INT_WAKEUP)
		iwn_wakeup_intr(sc);

	/* Re-enable interrupts. */
	IWN_WRITE(sc, IWN_INT_MASK, sc->int_mask);
	return (DDI_INTR_CLAIMED);
}

/*
 * Update TX scheduler ring when transmitting an 802.11 frame (4965AGN and
 * 5000 adapters use a slightly different format).
 */
static void
iwn4965_update_sched(struct iwn_softc *sc, int qid, int idx, uint8_t id,
    uint16_t len)
{
	_NOTE(ARGUNUSED(id));
	int w_idx = qid * IWN4965_SCHED_COUNT + idx;
	uint16_t *w = &sc->sched[w_idx];

	*w = htole16(len + 8);
	(void) ddi_dma_sync(sc->sched_dma.dma_hdl, w_idx * sizeof (uint16_t),
	    sizeof (uint16_t), DDI_DMA_SYNC_FORDEV);
	if (idx < IWN_SCHED_WINSZ) {
		*(w + IWN_TX_RING_COUNT) = *w;
		(void) ddi_dma_sync(sc->sched_dma.dma_hdl,
		    (w_idx + IWN_TX_RING_COUNT) * sizeof (uint16_t),
		    sizeof (uint16_t), DDI_DMA_SYNC_FORDEV);
	}
}

static void
iwn5000_update_sched(struct iwn_softc *sc, int qid, int idx, uint8_t id,
    uint16_t len)
{
	int w_idx = qid * IWN5000_SCHED_COUNT + idx;
	uint16_t *w = &sc->sched[w_idx];

	*w = htole16(id << 12 | (len + 8));
	(void) ddi_dma_sync(sc->sched_dma.dma_hdl, w_idx * sizeof (uint16_t),
	    sizeof (uint16_t), DDI_DMA_SYNC_FORDEV);
	if (idx < IWN_SCHED_WINSZ) {
		*(w + IWN_TX_RING_COUNT) = *w;
		(void) ddi_dma_sync(sc->sched_dma.dma_hdl,
		    (w_idx + IWN_TX_RING_COUNT) * sizeof (uint16_t),
		    sizeof (uint16_t), DDI_DMA_SYNC_FORDEV);
	}
}

#ifdef notyet
static void
iwn5000_reset_sched(struct iwn_softc *sc, int qid, int idx)
{
	int w_idx = qid * IWN5000_SCHED_COUNT + idx;
	uint16_t *w = &sc->sched[w_idx];

	*w = (*w & htole16(0xf000)) | htole16(1);
	(void) ddi_dma_sync(sc->sched_dma.dma_hdl, w_idx * sizeof (uint16_t),
	    sizeof (uint16_t), DDI_DMA_SYNC_FORDEV);
	if (idx < IWN_SCHED_WINSZ) {
		*(w + IWN_TX_RING_COUNT) = *w;
		(void) ddi_dma_sync(sc->sched_dma.dma_hdl,
		    (w_idx + IWN_TX_RING_COUNT) * sizeof (uint16_t),
		    sizeof (uint16_t), DDI_DMA_SYNC_FORDEV);
	}
}
#endif

/*
 * This function is only for compatibility with Net80211 module.
 * iwn_qosparam_to_hw() is the actual function updating EDCA
 * parameters to hardware.
 */
static int
iwn_wme_update(struct ieee80211com *ic)
{
	_NOTE(ARGUNUSED(ic));
	return (0);
}

static int
iwn_wme_to_qos_ac(struct iwn_softc *sc, int wme_ac)
{
	int qos_ac;

	switch (wme_ac) {
	case WME_AC_BE:
		qos_ac = QOS_AC_BK;
		break;
	case WME_AC_BK:
		qos_ac = QOS_AC_BE;
		break;
	case WME_AC_VI:
		qos_ac = QOS_AC_VI;
		break;
	case WME_AC_VO:
		qos_ac = QOS_AC_VO;
		break;
	default:
		dev_err(sc->sc_dip, CE_WARN, "!iwn_wme_to_qos_ac(): "
		    "WME AC index is not in suitable range.\n");
		qos_ac = QOS_AC_INVALID;
		break;
	}

	return (qos_ac);
}

static uint16_t
iwn_cw_e_to_cw(uint8_t cw_e)
{
	uint16_t cw = 1;

	while (cw_e > 0) {
		cw <<= 1;
		cw_e--;
	}

	cw -= 1;
	return (cw);
}

static int
iwn_wmeparam_check(struct iwn_softc *sc, struct wmeParams *wmeparam)
{
	int i;

	for (i = 0; i < WME_NUM_AC; i++) {

		if ((wmeparam[i].wmep_logcwmax > QOS_CW_RANGE_MAX) ||
		    (wmeparam[i].wmep_logcwmin >= wmeparam[i].wmep_logcwmax)) {
			cmn_err(CE_WARN, "iwn_wmeparam_check(): "
			    "Contention window is not in suitable range.\n");
			return (IWN_FAIL);
		}

		if ((wmeparam[i].wmep_aifsn < QOS_AIFSN_MIN) ||
		    (wmeparam[i].wmep_aifsn > QOS_AIFSN_MAX)) {
			dev_err(sc->sc_dip, CE_WARN, "!iwn_wmeparam_check(): "
			    "Arbitration interframe space number"
			    "is not in suitable range.\n");
			return (IWN_FAIL);
		}
	}

	return (IWN_SUCCESS);
}

/*
 * This function updates EDCA parameters into hardware.
 * FIFO0-background, FIFO1-best effort, FIFO2-video, FIFO3-voice.
 */
static int
iwn_qosparam_to_hw(struct iwn_softc *sc, int async)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	struct wmeParams *wmeparam;
	struct iwn_edca_params edcaparam;
	int i, j;
	int err = IWN_FAIL;

	if ((in->in_flags & IEEE80211_NODE_QOS) &&
	    (IEEE80211_M_STA == ic->ic_opmode)) {
		wmeparam = ic->ic_wme.wme_chanParams.cap_wmeParams;
	} else {
		return (IWN_SUCCESS);
	}

	(void) memset(&edcaparam, 0, sizeof (edcaparam));

	err = iwn_wmeparam_check(sc, wmeparam);
	if (err != IWN_SUCCESS) {
		return (err);
	}

	if (in->in_flags & IEEE80211_NODE_QOS) {
		edcaparam.flags |= QOS_PARAM_FLG_UPDATE_EDCA;
	}

	if (in->in_flags & (IEEE80211_NODE_QOS | IEEE80211_NODE_HT)) {
		edcaparam.flags |= QOS_PARAM_FLG_TGN;
	}

	for (i = 0; i < WME_NUM_AC; i++) {

		j = iwn_wme_to_qos_ac(sc, i);
		if (j < QOS_AC_BK || j > QOS_AC_VO) {
			return (IWN_FAIL);
		}

		sc->sc_edca->ac[j].cwmin.value.ul = edcaparam.ac[j].cwmin =
		    iwn_cw_e_to_cw(wmeparam[i].wmep_logcwmin);
		sc->sc_edca->ac[j].cwmax.value.ul = edcaparam.ac[j].cwmax =
		    iwn_cw_e_to_cw(wmeparam[i].wmep_logcwmax);
		sc->sc_edca->ac[j].aifsn.value.ul = edcaparam.ac[j].aifsn =
		    wmeparam[i].wmep_aifsn;
		sc->sc_edca->ac[j].txop.value.ul = edcaparam.ac[j].txoplimit =
		    (uint16_t)(wmeparam[i].wmep_txopLimit * 32);
	}

	err = iwn_cmd(sc, IWN_CMD_EDCA_PARAMS, &edcaparam,
	    sizeof (edcaparam), async);
	if (err != IWN_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!iwn_qosparam_to_hw(): "
		    "failed to update QoS parameters into hardware.");
		return (err);
	}

	return (err);
}

static inline int
iwn_wme_tid_qos_ac(int tid)
{
	switch (tid) {
	case 1:
	case 2:
		return (QOS_AC_BK);
	case 0:
	case 3:
		return (QOS_AC_BE);
	case 4:
	case 5:
		return (QOS_AC_VI);
	case 6:
	case 7:
		return (QOS_AC_VO);
	}

	return (QOS_AC_BE);
}

static inline int
iwn_qos_ac_to_txq(int qos_ac)
{
	switch (qos_ac) {
	case QOS_AC_BK:
		return (QOS_AC_BK_TO_TXQ);
	case QOS_AC_BE:
		return (QOS_AC_BE_TO_TXQ);
	case QOS_AC_VI:
		return (QOS_AC_VI_TO_TXQ);
	case QOS_AC_VO:
		return (QOS_AC_VO_TO_TXQ);
	}

	return (QOS_AC_BE_TO_TXQ);
}

static int
iwn_wme_tid_to_txq(struct iwn_softc *sc, int tid)
{
	int queue_n = TXQ_FOR_AC_INVALID;
	int qos_ac;

	if (tid < WME_TID_MIN ||
	    tid > WME_TID_MAX) {
		dev_err(sc->sc_dip, CE_WARN, "!wme_tid_to_txq(): "
		    "TID is not in suitable range.");
		return (queue_n);
	}

	qos_ac = iwn_wme_tid_qos_ac(tid);
	queue_n = iwn_qos_ac_to_txq(qos_ac);

	return (queue_n);
}

static int
iwn_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct iwn_softc *sc = (struct iwn_softc *)ic;
	struct iwn_node *wn;
	struct iwn_tx_ring *ring;
	struct iwn_tx_desc *desc;
	struct iwn_tx_data *data;
	struct iwn_tx_cmd *cmd;
	struct iwn_cmd_data *tx;
	ieee80211_node_t *in;
	const struct iwn_rate *rinfo;
	struct ieee80211_frame *wh;
	struct ieee80211_key *k = NULL;
	uint32_t flags;
	uint_t hdrlen;
	uint8_t ridx, txant;
	int i, totlen, seglen, pad;
	int txq_id = NON_QOS_TXQ;
	struct ieee80211_qosframe *qwh = NULL;
	uint8_t tid = WME_TID_INVALID;
	ddi_dma_cookie_t cookie;
	mblk_t *m0, *m;
	int mblen, off;

	int noack = 0;

	if (ic == NULL)
		return (EIO);

	if ((mp == NULL) || (MBLKL(mp) <= 0))
		return (EIO);

	if (sc->sc_flags & IWN_FLAG_SUSPEND) {
		freemsg(mp);
		sc->sc_tx_err++;
		return(EIO);
	}

	wh = (struct ieee80211_frame *)mp->b_rptr;

	hdrlen = ieee80211_hdrspace(ic, mp->b_rptr);

	/*
	 * determine send which AP or station in IBSS
	 */
	in = ieee80211_find_txnode(ic, wh->i_addr1);
	if (in == NULL) {
		dev_err(sc->sc_dip, CE_WARN, "!iwn_send(): "
		    "failed to find tx node");
		freemsg(mp);
		sc->sc_tx_err++;
		return(EIO);
	}

	wn = (struct iwn_node *)in;

	/*
	 * Determine TX queue according to traffic ID in frame
	 * if working in QoS mode.
	 */
	if (in->in_flags & IEEE80211_NODE_QOS) {
		if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_DATA) {
			if (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_QOS) {
				qwh = (struct ieee80211_qosframe *)wh;

				tid = qwh->i_qos[0] & IEEE80211_QOS_TID;
				txq_id = iwn_wme_tid_to_txq(sc, tid);

				if (txq_id < TXQ_FOR_AC_MIN ||
				    (txq_id > TXQ_FOR_AC_MAX)) {
					freemsg(mp);
					sc->sc_tx_err++;
					return(EIO);
				}
			} else {
				txq_id = NON_QOS_TXQ;
			}
		} else if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_MGT) {
			txq_id = QOS_TXQ_FOR_MGT;
		} else {
			txq_id = NON_QOS_TXQ;
		}
	} else {
		txq_id = NON_QOS_TXQ;
	}

	if (sc->qfullmsk & (1 << txq_id)) {
		sc->sc_tx_err++;
		/* net80211-initiated send */
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA)
			freemsg(mp);
		return (EAGAIN);
	}

	/* Choose a TX rate index. */
	if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
	    type != IEEE80211_FC0_TYPE_DATA) {
		ridx = (ic->ic_curmode == IEEE80211_MODE_11A) ?
		    IWN_RIDX_OFDM6 : IWN_RIDX_CCK1;
	} else if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE) {
		ridx = sc->fixed_ridx;
	} else
		ridx = wn->ridx[in->in_txrate];
	rinfo = &iwn_rates[ridx];

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (m) {
		for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
			mblen = MBLKL(m0);
			bcopy(m0->b_rptr, m->b_rptr + off, mblen);
			off += mblen;
		}

		m->b_wptr += off;

		freemsg(mp);
		mp = m;

		wh = (struct ieee80211_frame *)mp->b_rptr;
	} else {
		dev_err(sc->sc_dip, CE_WARN, "!iwn_send(): can't copy");
		/* net80211-initiated send */
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA)
			freemsg(mp);
		return (EAGAIN);
	}


	/*
	 * Net80211 module encapsulate outbound data frames.
	 * Add some fields of 80211 frame.
	 */
	if ((type & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA)
		(void) ieee80211_encap(ic, mp, in);

	/* Encrypt the frame if need be. */
	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, mp);
		if (k == NULL) {
			freemsg(mp);
			return(EIO);
		}
		/* Packet header may have moved, reset our local pointer. */
		wh = (struct ieee80211_frame *)mp->b_rptr;
	}
	totlen = msgdsize(mp);

	mutex_enter(&sc->sc_tx_mtx);
	ring = &sc->txq[txq_id];
	desc = &ring->desc[ring->cur];
	data = &ring->data[ring->cur];

	/* Prepare TX firmware command. */
	cmd = &ring->cmd[ring->cur];
	cmd->code = IWN_CMD_TX_DATA;
	cmd->flags = 0;
	cmd->qid = ring->qid;
	cmd->idx = ring->cur;

	tx = (struct iwn_cmd_data *)cmd->data;
	/* NB: No need to clear tx, all fields are reinitialized here. */
	tx->scratch = 0;	/* clear "scratch" area */

	flags = 0;
	if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		/* Unicast frame, check if an ACK is expected. */
		if (!noack)
			flags |= IWN_TX_NEED_ACK;
	}

	if ((wh->i_fc[0] &
	    (IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_MASK)) ==
	    (IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_BAR))
		flags |= IWN_TX_IMM_BA;		/* Cannot happen yet. */

	ASSERT((flags & IWN_TX_IMM_BA) == 0);

	if (wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG)
		flags |= IWN_TX_MORE_FRAG;	/* Cannot happen yet. */

	ASSERT((flags & IWN_TX_MORE_FRAG) == 0);

	/* Check if frame must be protected using RTS/CTS or CTS-to-self. */
	if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		/* NB: Group frames are sent using CCK in 802.11b/g. */
		if (totlen + IEEE80211_CRC_LEN > ic->ic_rtsthreshold) {
			flags |= IWN_TX_NEED_RTS;
		} else if ((ic->ic_flags & IEEE80211_F_USEPROT) &&
		    ridx >= IWN_RIDX_OFDM6) {
			if (ic->ic_protmode == IEEE80211_PROT_CTSONLY)
				flags |= IWN_TX_NEED_CTS;
			else if (ic->ic_protmode == IEEE80211_PROT_RTSCTS)
				flags |= IWN_TX_NEED_RTS;
		}
		if (flags & (IWN_TX_NEED_RTS | IWN_TX_NEED_CTS)) {
			if (sc->hw_type != IWN_HW_REV_TYPE_4965) {
				/* 5000 autoselects RTS/CTS or CTS-to-self. */
				flags &= ~(IWN_TX_NEED_RTS | IWN_TX_NEED_CTS);
				flags |= IWN_TX_NEED_PROTECTION;
			} else
				flags |= IWN_TX_FULL_TXOP;
		}
	}

	if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
	    type != IEEE80211_FC0_TYPE_DATA)
		tx->id = sc->broadcast_id;
	else
		tx->id = wn->id;

	if (type == IEEE80211_FC0_TYPE_MGT) {
		uint8_t subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

#ifndef IEEE80211_STA_ONLY
		/* Tell HW to set timestamp in probe responses. */
		/* XXX NetBSD rev 1.11 added probe requests here but */
		/* probe requests do not take timestamps (from Bergamini). */
		if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
			flags |= IWN_TX_INSERT_TSTAMP;
#endif
		/* XXX NetBSD rev 1.11 and 1.20 added AUTH/DAUTH and RTS/CTS */
		/* changes here. These are not needed (from Bergamini). */
		if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ||
		    subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)
			tx->timeout = htole16(3);
		else
			tx->timeout = htole16(2);
	} else
		tx->timeout = htole16(0);

	if (hdrlen & 3) {
		/* First segment length must be a multiple of 4. */
		flags |= IWN_TX_NEED_PADDING;
		pad = 4 - (hdrlen & 3);
	} else
		pad = 0;

	if (tid != WME_TID_INVALID) {
		flags &= ~IWN_TX_AUTO_SEQ;
	} else {
		flags |= IWN_TX_AUTO_SEQ;
		tid = 0;
	}

	tx->len = htole16(totlen);
	tx->tid = tid;
	tx->rts_ntries = 60;
	tx->data_ntries = 15;
	tx->lifetime = htole32(IWN_LIFETIME_INFINITE);
	tx->plcp = rinfo->plcp;
	tx->rflags = rinfo->flags;
	if (tx->id == sc->broadcast_id) {
		/* Group or management frame. */
		tx->linkq = 0;
		/* XXX Alternate between antenna A and B? */
		txant = IWN_LSB(sc->txchainmask);
		tx->rflags |= IWN_RFLAG_ANT(txant);
	} else {
		tx->linkq = in->in_rates.ir_nrates - in->in_txrate - 1;
		flags |= IWN_TX_LINKQ;	/* enable MRR */
	}
	/* Set physical address of "scratch area". */
	tx->loaddr = htole32(IWN_LOADDR(data->scratch_paddr));
	tx->hiaddr = IWN_HIADDR(data->scratch_paddr);

	/* Copy 802.11 header in TX command. */
	/* XXX NetBSD changed this in rev 1.20 */
	memcpy(((uint8_t *)tx) + sizeof(*tx), wh, hdrlen);
	mp->b_rptr += hdrlen;

	bcopy(mp->b_rptr, data->dma_data.vaddr, totlen - hdrlen);
	tx->security = 0;
	tx->flags = htole32(flags);

	data->ni = in;

	DTRACE_PROBE4(tx, int, ring->qid, int, ring->cur, size_t, MBLKL(mp),
	    int, data->dma_data.ncookies);

	/* Fill TX descriptor. */
	desc->nsegs = 1 + data->dma_data.ncookies;
	/* First DMA segment is used by the TX command. */
	desc->segs[0].addr = htole32(IWN_LOADDR(data->cmd_paddr));
	desc->segs[0].len  = htole16(IWN_HIADDR(data->cmd_paddr) |
	    (4 + sizeof (*tx) + hdrlen + pad) << 4);

	/* Other DMA segments are for data payload. */
	cookie = data->dma_data.cookie;
	for (i = 1, seglen = totlen - hdrlen;
	     i <= data->dma_data.ncookies;
	     i++, seglen -= cookie.dmac_size) {
		desc->segs[i].addr = htole32(IWN_LOADDR(cookie.dmac_laddress));
		desc->segs[i].len  = htole16(IWN_HIADDR(cookie.dmac_laddress) |
		    seglen << 4);
		if (i < data->dma_data.ncookies)
			ddi_dma_nextcookie(data->dma_data.dma_hdl, &cookie);
	}

	(void) ddi_dma_sync(data->dma_data.dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);
	(void) ddi_dma_sync(ring->cmd_dma.dma_hdl, ring->cur * sizeof (*cmd),
	    sizeof (*cmd), DDI_DMA_SYNC_FORDEV);
	(void) ddi_dma_sync(ring->desc_dma.dma_hdl, ring->cur * sizeof (*desc),
	    sizeof (*desc), DDI_DMA_SYNC_FORDEV);

	/* Update TX scheduler. */
	sc->ops.update_sched(sc, ring->qid, ring->cur, tx->id, totlen);

	/* Kick TX ring. */
	ring->cur = (ring->cur + 1) % IWN_TX_RING_COUNT;
	IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

	/* Mark TX ring as full if we reach a certain threshold. */
	if (++ring->queued > IWN_TX_RING_HIMARK)
		sc->qfullmsk |= 1 << ring->qid;
	mutex_exit(&sc->sc_tx_mtx);
	freemsg(mp);

	ic->ic_stats.is_tx_bytes += totlen;

	mutex_enter(&sc->sc_mt_mtx);
	if (sc->sc_tx_timer == 0)
		sc->sc_tx_timer = 5;
	mutex_exit(&sc->sc_mt_mtx);

	return 0;
}

static mblk_t *
iwn_m_tx(void *arg, mblk_t *mp)
{
	struct iwn_softc *sc;
	ieee80211com_t *ic;
	mblk_t *next;

	sc = (struct iwn_softc *)arg;
	ASSERT(sc != NULL);
	ic = &sc->sc_ic;

	if (sc->sc_flags & IWN_FLAG_SUSPEND) {
		freemsgchain(mp);
		return (NULL);
	}

	if (ic->ic_state != IEEE80211_S_RUN) {
		freemsgchain(mp);
		return (NULL);
	}

	if ((sc->sc_flags & IWN_FLAG_HW_ERR_RECOVER)) {
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (iwn_send(ic, mp, IEEE80211_FC0_TYPE_DATA) == EAGAIN) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}

	return (mp);
}

static void
iwn_watchdog(void *arg)
{
	struct iwn_softc *sc = (struct iwn_softc *)arg;
	ieee80211com_t *ic = &sc->sc_ic;
	timeout_id_t timeout_id = ic->ic_watchdog_timer;

	ieee80211_stop_watchdog(ic);

	mutex_enter(&sc->sc_mt_mtx);
	if (sc->sc_tx_timer > 0) {
		if (--sc->sc_tx_timer == 0) {
			dev_err(sc->sc_dip, CE_WARN, "!device timeout");
			sc->sc_flags |= IWN_FLAG_HW_ERR_RECOVER;
			sc->sc_ostate = IEEE80211_S_RUN;
			DTRACE_PROBE(recover__send__fail);
		}
	}
	mutex_exit(&sc->sc_mt_mtx);

	if ((ic->ic_state != IEEE80211_S_AUTH) &&
	    (ic->ic_state != IEEE80211_S_ASSOC))
		return;

	if (ic->ic_bss->in_fails > 10) {
		DTRACE_PROBE2(watchdog__reset, timeout_id_t, timeout_id,
		    struct ieee80211node *, ic->ic_bss);
		dev_err(sc->sc_dip, CE_WARN, "!iwn_watchdog reset");
		ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	} else {
		ic->ic_bss->in_fails++;

		DTRACE_PROBE2(watchdog__timeout, timeout_id_t, timeout_id,
		    struct ieee80211node *, ic->ic_bss);

		ieee80211_watchdog(ic);
	}
}

static void
iwn_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct iwn_softc *sc;
	struct ieee80211com *ic;
	int  error = 0;

	sc = (struct iwn_softc *)arg;
	ASSERT(sc != NULL);
	ic = &sc->sc_ic;

	mutex_enter(&sc->sc_mtx);
	while (sc->sc_flags & IWN_FLAG_SCANNING)
		cv_wait(&sc->sc_scan_cv, &sc->sc_mtx);
	mutex_exit(&sc->sc_mtx);

	error = ieee80211_ioctl(ic, wq, mp);
	if (error == ENETRESET) {
		/*
		 * This is special for the hidden AP connection.
		 * In any case, we should make sure only one 'scan'
		 * in the driver for a 'connect' CLI command. So
		 * when connecting to a hidden AP, the scan is just
		 * sent out to the air when we know the desired
		 * essid of the AP we want to connect.
		 */
		if (ic->ic_des_esslen) {
			if (sc->sc_flags & IWN_FLAG_RUNNING) {
				DTRACE_PROBE(netreset);
				iwn_m_stop(sc);
				(void) iwn_m_start(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
			}
		}
	}
}

/*
 * Call back functions for get/set property
 */
static int
iwn_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct iwn_softc *sc;

	sc = (struct iwn_softc *)arg;
	ASSERT(sc != NULL);

	return (ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf));
}

static void
iwn_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	struct iwn_softc *sc;

	sc = (struct iwn_softc *)arg;
	ASSERT(sc != NULL);

	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, prh);
}

static int
iwn_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct iwn_softc *sc;
	ieee80211com_t *ic;
	int err = EINVAL;

	sc = (struct iwn_softc *)arg;
	ASSERT(sc != NULL);
	ic = &sc->sc_ic;

	mutex_enter(&sc->sc_mtx);
	while (sc->sc_flags & IWN_FLAG_SCANNING)
		cv_wait(&sc->sc_scan_cv, &sc->sc_mtx);
	mutex_exit(&sc->sc_mtx);

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num, wldp_length,
	    wldp_buf);

	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (sc->sc_flags & IWN_FLAG_RUNNING) {
				DTRACE_PROBE(netreset);
				iwn_m_stop(sc);
				(void) iwn_m_start(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
			}
		}
		err = 0;
	}

	return (err);
}

/*
 * invoked by GLD get statistics from NIC and driver
 */
static int
iwn_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct iwn_softc *sc;
	ieee80211com_t *ic;
	ieee80211_node_t *in;

	sc = (struct iwn_softc *)arg;
	ASSERT(sc != NULL);
	ic = &sc->sc_ic;

	mutex_enter(&sc->sc_mtx);

	switch (stat) {
	case MAC_STAT_IFSPEED:
		in = ic->ic_bss;
		*val = ((IEEE80211_FIXED_RATE_NONE == ic->ic_fixed_rate) ?
		    IEEE80211_RATE(in->in_txrate) :
		    ic->ic_fixed_rate) / 2 * 1000000;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = sc->sc_tx_nobuf;
		break;
	case MAC_STAT_NORCVBUF:
		*val = sc->sc_rx_nobuf;
		break;
	case MAC_STAT_IERRORS:
		*val = sc->sc_rx_err;
		break;
	case MAC_STAT_RBYTES:
		*val = ic->ic_stats.is_rx_bytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = ic->ic_stats.is_rx_frags;
		break;
	case MAC_STAT_OBYTES:
		*val = ic->ic_stats.is_tx_bytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = ic->ic_stats.is_tx_frags;
		break;
	case MAC_STAT_OERRORS:
	case WIFI_STAT_TX_FAILED:
		*val = sc->sc_tx_err;
		break;
	case WIFI_STAT_TX_RETRANS:
		*val = sc->sc_tx_retries;
		break;
	case WIFI_STAT_FCS_ERRORS:
	case WIFI_STAT_WEP_ERRORS:
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	case WIFI_STAT_RX_DUPS:
		mutex_exit(&sc->sc_mtx);
		return (ieee80211_stat(ic, stat, val));
	default:
		mutex_exit(&sc->sc_mtx);
		return (ENOTSUP);
	}

	mutex_exit(&sc->sc_mtx);

	return (0);

}

/*
 * invoked by GLD to configure NIC
 */
static int
iwn_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct iwn_softc *sc;
	ieee80211com_t	*ic;
	int err = IWN_SUCCESS;

	sc = (struct iwn_softc *)arg;
	ASSERT(sc != NULL);
	ic = &sc->sc_ic;

	if (!IEEE80211_ADDR_EQ(ic->ic_macaddr, macaddr)) {
		mutex_enter(&sc->sc_mtx);
		IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);
		err = iwn_config(sc);
		mutex_exit(&sc->sc_mtx);
		if (err != IWN_SUCCESS) {
			dev_err(sc->sc_dip, CE_WARN, "!iwn_m_unicst(): "
			    "failed to configure device");
			goto fail;
		}
	}

	return (err);

fail:
	return (err);
}

/*ARGSUSED*/
static int
iwn_m_multicst(void *arg, boolean_t add, const uint8_t *m)
{
	return (IWN_SUCCESS);
}

/*ARGSUSED*/
static int
iwn_m_promisc(void *arg, boolean_t on)
{
	_NOTE(ARGUNUSED(on));

	return (IWN_SUCCESS);
}

static void
iwn_abort_scan(void *arg)
{
	struct iwn_softc *sc = (struct iwn_softc *)arg;
	ieee80211com_t *ic = &sc->sc_ic;

	mutex_enter(&sc->sc_mtx);
	if ((sc->sc_flags & IWN_FLAG_SCANNING) == 0) {
		mutex_exit(&sc->sc_mtx);
		return;
	}

	dev_err(sc->sc_dip, CE_WARN,
	    "!aborting scan, flags = %x, state = %s",
	    sc->sc_flags, ieee80211_state_name[ic->ic_state]);
	sc->sc_flags &= ~IWN_FLAG_SCANNING;
	iwn_hw_stop(sc, B_FALSE);
	mutex_exit(&sc->sc_mtx);

	sc->scan_to = 0;
	(void) iwn_init(sc);
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
}

/*
 * periodic function to deal with RF switch and HW error recovery
 */
static void
iwn_periodic(void *arg)
{
	struct iwn_softc *sc = (struct iwn_softc *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	int err;
	uint32_t tmp;

	mutex_enter(&sc->sc_mtx);
	tmp = IWN_READ(sc, IWN_GP_CNTRL);
	if (tmp & IWN_GP_CNTRL_RFKILL) {
		sc->sc_flags &= ~IWN_FLAG_RADIO_OFF;
	} else {
		sc->sc_flags |= IWN_FLAG_RADIO_OFF;
	}

	/*
	 * If the RF is OFF, do nothing.
	 */
	if (sc->sc_flags & IWN_FLAG_RADIO_OFF) {
		mutex_exit(&sc->sc_mtx);
		return;
	}

	mutex_exit(&sc->sc_mtx);

	/*
	 * recovery fatal error
	 */
	if (ic->ic_mach &&
	    (sc->sc_flags & IWN_FLAG_HW_ERR_RECOVER)) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!trying to restore previous state");

		mutex_enter(&sc->sc_mtx);
		sc->sc_flags |= IWN_FLAG_STOP_CALIB_TO;
		mutex_exit(&sc->sc_mtx);

		if (sc->calib_to != 0)
			(void) untimeout(sc->calib_to);
		sc->calib_to = 0;

		if (sc->scan_to != 0)
			(void) untimeout(sc->scan_to);
		sc->scan_to = 0;

		iwn_hw_stop(sc, B_TRUE);

		if (IWN_CHK_FAST_RECOVER(sc)) {
			/* save runtime configuration */
			bcopy(&sc->rxon, &sc->rxon_save, sizeof (sc->rxon));
		} else {
			ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
		}

		err = iwn_init(sc);
		if (err != IWN_SUCCESS)
			return;

		mutex_enter(&sc->sc_mtx);
		sc->sc_flags |= IWN_FLAG_RUNNING;
		mutex_exit(&sc->sc_mtx);

		if (!IWN_CHK_FAST_RECOVER(sc) ||
		    iwn_fast_recover(sc) != IWN_SUCCESS) {
			mutex_enter(&sc->sc_mtx);
			sc->sc_flags &= ~IWN_FLAG_HW_ERR_RECOVER;
			mutex_exit(&sc->sc_mtx);
			if (sc->sc_ostate != IEEE80211_S_INIT) {
				ieee80211_new_state(ic, IEEE80211_S_SCAN, 0);
			}
		}
	}
}

/*
 * Send a command to the firmware.
 */
static int
iwn_cmd(struct iwn_softc *sc, uint8_t code, void *buf, int size, int async)
{
	struct iwn_tx_ring *ring = &sc->txq[IWN_CMD_QUEUE_NUM];
	struct iwn_tx_desc *desc;
	struct iwn_tx_data *data;
	struct iwn_tx_cmd *cmd;
	clock_t clk;
	uintptr_t paddr;
	int totlen, ret;

	ASSERT(mutex_owned(&sc->sc_mtx));

	desc = &ring->desc[ring->cur];
	data = &ring->data[ring->cur];
	totlen = 4 + size;

	if (size > sizeof (cmd->data)) {
		/* Command is too large to fit in a descriptor. */
		if (iwn_dma_contig_alloc(sc, &data->cmd_dma, totlen,
		    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, (void **)&cmd,
		    &iwn_dma_accattr, 1) != DDI_SUCCESS)
			return ENOBUFS;
		paddr = data->cmd_dma.paddr;
	} else {
		cmd = &ring->cmd[ring->cur];
		paddr = data->cmd_paddr;
	}

	cmd->code = code;
	cmd->flags = 0;
	cmd->qid = ring->qid;
	cmd->idx = ring->cur;
	bzero(cmd->data, size);
	memcpy(cmd->data, buf, size);

	bzero(desc, sizeof(*desc));
	desc->nsegs = 1;
	desc->segs[0].addr = htole32(IWN_LOADDR(paddr));
	desc->segs[0].len  = htole16(IWN_HIADDR(paddr) | totlen << 4);

	if (size > sizeof cmd->data) {
		(void) ddi_dma_sync(data->cmd_dma.dma_hdl, 0, totlen,
		    DDI_DMA_SYNC_FORDEV);
	} else {
		(void) ddi_dma_sync(ring->cmd_dma.dma_hdl,
		    ring->cur * sizeof (*cmd),
		    totlen, DDI_DMA_SYNC_FORDEV);
	}
	(void) ddi_dma_sync(ring->desc_dma.dma_hdl,
	    ring->cur * sizeof (*desc),
	    sizeof (*desc), DDI_DMA_SYNC_FORDEV);

	/* Update TX scheduler. */
	sc->ops.update_sched(sc, ring->qid, ring->cur, 0, 0);

	/* Kick command ring. */
	ring->cur = (ring->cur + 1) % IWN_TX_RING_COUNT;
	IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

	if (async)
		return (IWN_SUCCESS);

	sc->sc_cmd_flag = SC_CMD_FLG_NONE;
	clk = ddi_get_lbolt() + drv_usectohz(2000000);
	while (sc->sc_cmd_flag != SC_CMD_FLG_DONE)
		if (cv_timedwait(&sc->sc_cmd_cv, &sc->sc_mtx, clk) < 0)
			break;

	ret = (sc->sc_cmd_flag == SC_CMD_FLG_DONE) ? IWN_SUCCESS : IWN_FAIL;
	sc->sc_cmd_flag = SC_CMD_FLG_NONE;

	return (ret);
}

static int
iwn4965_add_node(struct iwn_softc *sc, struct iwn_node_info *node, int async)
{
	struct iwn4965_node_info hnode;
	char *src, *dst;

	/*
	 * We use the node structure for 5000 Series internally (it is
	 * a superset of the one for 4965AGN). We thus copy the common
	 * fields before sending the command.
	 */
	src = (char *)node;
	dst = (char *)&hnode;
	memcpy(dst, src, 48);
	/* Skip TSC, RX MIC and TX MIC fields from ``src''. */
	memcpy(dst + 48, src + 72, 20);
	return iwn_cmd(sc, IWN_CMD_ADD_NODE, &hnode, sizeof hnode, async);
}

static int
iwn5000_add_node(struct iwn_softc *sc, struct iwn_node_info *node, int async)
{
	/* Direct mapping. */
	return iwn_cmd(sc, IWN_CMD_ADD_NODE, node, sizeof (*node), async);
}

static int
iwn_set_link_quality(struct iwn_softc *sc, struct ieee80211_node *ni)
{
	struct iwn_node *wn = (void *)ni;
	struct ieee80211_rateset *rs = &ni->in_rates;
	struct iwn_cmd_link_quality linkq;
	const struct iwn_rate *rinfo;
	uint8_t txant;
	int i, txrate;

	/* Use the first valid TX antenna. */
	txant = IWN_LSB(sc->txchainmask);

	memset(&linkq, 0, sizeof linkq);
	linkq.id = wn->id;
	linkq.antmsk_1stream = txant;
	linkq.antmsk_2stream = IWN_ANT_AB;
	linkq.ampdu_max = 31;
	linkq.ampdu_threshold = 3;
	linkq.ampdu_limit = htole16(4000);	/* 4ms */

	/* Start at highest available bit-rate. */
	txrate = rs->ir_nrates - 1;
	for (i = 0; i < IWN_MAX_TX_RETRIES; i++) {
		rinfo = &iwn_rates[wn->ridx[txrate]];
		linkq.retry[i].plcp = rinfo->plcp;
		linkq.retry[i].rflags = rinfo->flags;
		linkq.retry[i].rflags |= IWN_RFLAG_ANT(txant);
		/* Next retry at immediate lower bit-rate. */
		if (txrate > 0)
			txrate--;
	}
	return iwn_cmd(sc, IWN_CMD_LINK_QUALITY, &linkq, sizeof linkq, 1);
}

/*
 * Broadcast node is used to send group-addressed and management frames.
 */
static int
iwn_add_broadcast_node(struct iwn_softc *sc, int async)
{
	struct iwn_ops *ops = &sc->ops;
	struct iwn_node_info node;
	struct iwn_cmd_link_quality linkq;
	const struct iwn_rate *rinfo;
	uint8_t txant;
	int i, error;

	memset(&node, 0, sizeof node);
	IEEE80211_ADDR_COPY(node.macaddr, etherbroadcastaddr);
	node.id = sc->broadcast_id;
	DTRACE_PROBE(add__broadcast__node);
	if ((error = ops->add_node(sc, &node, async)) != 0)
		return error;

	/* Use the first valid TX antenna. */
	txant = IWN_LSB(sc->txchainmask);

	memset(&linkq, 0, sizeof linkq);
	linkq.id = sc->broadcast_id;
	linkq.antmsk_1stream = txant;
	linkq.antmsk_2stream = IWN_ANT_AB;
	linkq.ampdu_max = 64;
	linkq.ampdu_threshold = 3;
	linkq.ampdu_limit = htole16(4000);	/* 4ms */

	/* Use lowest mandatory bit-rate. */
	rinfo = (sc->sc_ic.ic_curmode != IEEE80211_MODE_11A) ?
	    &iwn_rates[IWN_RIDX_CCK1] : &iwn_rates[IWN_RIDX_OFDM6];
	linkq.retry[0].plcp = rinfo->plcp;
	linkq.retry[0].rflags = rinfo->flags;
	linkq.retry[0].rflags |= IWN_RFLAG_ANT(txant);
	/* Use same bit-rate for all TX retries. */
	for (i = 1; i < IWN_MAX_TX_RETRIES; i++) {
		linkq.retry[i].plcp = linkq.retry[0].plcp;
		linkq.retry[i].rflags = linkq.retry[0].rflags;
	}
	return iwn_cmd(sc, IWN_CMD_LINK_QUALITY, &linkq, sizeof linkq, async);
}

static void
iwn_set_led(struct iwn_softc *sc, uint8_t which, uint8_t off, uint8_t on)
{
	struct iwn_cmd_led led;

	/* Clear microcode LED ownership. */
	IWN_CLRBITS(sc, IWN_LED, IWN_LED_BSM_CTRL);

	led.which = which;
	led.unit = htole32(10000);	/* on/off in unit of 100ms */
	led.off = off;
	led.on = on;
	DTRACE_PROBE1(led__change, const char *,
	    (off != 0 && on != 0) ? "blinking" :
	    (off != 0) ? "off" : "on");
	(void)iwn_cmd(sc, IWN_CMD_SET_LED, &led, sizeof led, 1);
}

/*
 * Set the critical temperature at which the firmware will stop the radio
 * and notify us.
 */
static int
iwn_set_critical_temp(struct iwn_softc *sc)
{
	struct iwn_critical_temp crit;
	int32_t temp;

	IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_CTEMP_STOP_RF);

	if (sc->hw_type == IWN_HW_REV_TYPE_5150)
		temp = (IWN_CTOK(110) - sc->temp_off) * -5;
	else if (sc->hw_type == IWN_HW_REV_TYPE_4965)
		temp = IWN_CTOK(110);
	else
		temp = 110;

	sc->sc_misc->crit_temp.value.ul = temp;

	memset(&crit, 0, sizeof crit);
	crit.tempR = htole32(temp);
	return iwn_cmd(sc, IWN_CMD_SET_CRITICAL_TEMP, &crit, sizeof crit, 0);
}

static int
iwn_set_timing(struct iwn_softc *sc, struct ieee80211_node *ni)
{
	struct iwn_cmd_timing cmd;
	uint64_t val, mod;

	memset(&cmd, 0, sizeof cmd);
	memcpy(&cmd.tstamp, ni->in_tstamp.data, sizeof (uint64_t));
	cmd.bintval = htole16(ni->in_intval);
	cmd.lintval = htole16(10);

	/* Compute remaining time until next beacon. */
	val = (uint64_t)ni->in_intval * 1024;	/* msecs -> usecs */
	mod = le64toh(cmd.tstamp) % val;
	cmd.binitval = htole32((uint32_t)(val - mod));

	sc->sc_timing->bintval.value.ul = ni->in_intval;
	sc->sc_timing->tstamp.value.ul = ni->in_tstamp.tsf;
	sc->sc_timing->init.value.ul = (uint32_t)(val - mod);

	return iwn_cmd(sc, IWN_CMD_TIMING, &cmd, sizeof cmd, 1);
}

static void
iwn4965_power_calibration(struct iwn_softc *sc, int temp)
{
	/* Adjust TX power if need be (delta >= 3 degC). */
	IWN_DBG("temperature %d->%d", sc->temp, temp);
	if (abs(temp - sc->temp) >= 3) {
		/* Record temperature of last calibration. */
		sc->temp = temp;
		(void)iwn4965_set_txpower(sc, 1);
	}
}

/*
 * Set TX power for current channel (each rate has its own power settings).
 * This function takes into account the regulatory information from EEPROM,
 * the current temperature and the current voltage.
 */
static int
iwn4965_set_txpower(struct iwn_softc *sc, int async)
{
/* Fixed-point arithmetic division using a n-bit fractional part. */
#define fdivround(a, b, n)	\
	((((1 << n) * (a)) / (b) + (1 << n) / 2) / (1 << n))
/* Linear interpolation. */
#define interpolate(x, x1, y1, x2, y2, n)	\
	((y1) + fdivround(((int)(x) - (x1)) * ((y2) - (y1)), (x2) - (x1), n))

	static const int tdiv[IWN_NATTEN_GROUPS] = { 9, 8, 8, 8, 6 };
	struct ieee80211com *ic = &sc->sc_ic;
	struct iwn_ucode_info *uc = &sc->ucode_info;
	struct ieee80211_channel *ch;
	struct iwn4965_cmd_txpower cmd;
	struct iwn4965_eeprom_chan_samples *chans;
	const uint8_t *rf_gain, *dsp_gain;
	int32_t vdiff, tdiff;
	int i, c, grp, maxpwr;
	uint8_t chan;

	/* Retrieve current channel from last RXON. */
	chan = sc->rxon.chan;
	sc->sc_txpower->chan.value.l = chan;
	ch = &ic->ic_sup_channels[chan];

	memset(&cmd, 0, sizeof cmd);
	cmd.band = IEEE80211_IS_CHAN_5GHZ(ch) ? 0 : 1;
	cmd.chan = chan;

	if (IEEE80211_IS_CHAN_5GHZ(ch)) {
		maxpwr   = sc->maxpwr5GHz;
		rf_gain  = iwn4965_rf_gain_5ghz;
		dsp_gain = iwn4965_dsp_gain_5ghz;
	} else {
		maxpwr   = sc->maxpwr2GHz;
		rf_gain  = iwn4965_rf_gain_2ghz;
		dsp_gain = iwn4965_dsp_gain_2ghz;
	}

	/* Compute voltage compensation. */
	vdiff = ((int32_t)le32toh(uc->volt) - sc->eeprom_voltage) / 7;
	if (vdiff > 0)
		vdiff *= 2;
	if (abs(vdiff) > 2)
		vdiff = 0;
	sc->sc_txpower->vdiff.value.l = vdiff;

	/* Get channel attenuation group. */
	if (chan <= 20)		/* 1-20 */
		grp = 4;
	else if (chan <= 43)	/* 34-43 */
		grp = 0;
	else if (chan <= 70)	/* 44-70 */
		grp = 1;
	else if (chan <= 124)	/* 71-124 */
		grp = 2;
	else			/* 125-200 */
		grp = 3;
	sc->sc_txpower->group.value.l = grp;

	/* Get channel sub-band. */
	for (i = 0; i < IWN_NBANDS; i++)
		if (sc->bands[i].lo != 0 &&
		    sc->bands[i].lo <= chan && chan <= sc->bands[i].hi)
			break;
	if (i == IWN_NBANDS)	/* Can't happen in real-life. */
		return EINVAL;
	chans = sc->bands[i].chans;
	sc->sc_txpower->subband.value.l = i;

	for (c = 0; c < 2; c++) {
		uint8_t power, gain, temp;
		int maxchpwr, pwr, ridx, idx;

		power = interpolate(chan,
		    chans[0].num, chans[0].samples[c][1].power,
		    chans[1].num, chans[1].samples[c][1].power, 1);
		gain  = interpolate(chan,
		    chans[0].num, chans[0].samples[c][1].gain,
		    chans[1].num, chans[1].samples[c][1].gain, 1);
		temp  = interpolate(chan,
		    chans[0].num, chans[0].samples[c][1].temp,
		    chans[1].num, chans[1].samples[c][1].temp, 1);
		sc->sc_txpower->txchain[c].power.value.l = power;
		sc->sc_txpower->txchain[c].gain.value.l = gain;
		sc->sc_txpower->txchain[c].temp.value.l = temp;

		/* Compute temperature compensation. */
		tdiff = ((sc->temp - temp) * 2) / tdiv[grp];
		sc->sc_txpower->txchain[c].tcomp.value.l = tdiff;

		for (ridx = 0; ridx <= IWN_RIDX_MAX; ridx++) {
			/* Convert dBm to half-dBm. */
			maxchpwr = sc->maxpwr[chan] * 2;
			if ((ridx / 8) & 1)
				maxchpwr -= 6;	/* MIMO 2T: -3dB */

			pwr = maxpwr;

			/* Adjust TX power based on rate. */
			if ((ridx % 8) == 5)
				pwr -= 15;	/* OFDM48: -7.5dB */
			else if ((ridx % 8) == 6)
				pwr -= 17;	/* OFDM54: -8.5dB */
			else if ((ridx % 8) == 7)
				pwr -= 20;	/* OFDM60: -10dB */
			else
				pwr -= 10;	/* Others: -5dB */

			/* Do not exceed channel max TX power. */
			if (pwr > maxchpwr)
				pwr = maxchpwr;

			idx = gain - (pwr - power) - tdiff - vdiff;
			if ((ridx / 8) & 1)	/* MIMO */
				idx += (int32_t)le32toh(uc->atten[grp][c]);

			if (cmd.band == 0)
				idx += 9;	/* 5GHz */
			if (ridx == IWN_RIDX_MAX)
				idx += 5;	/* CCK */

			/* Make sure idx stays in a valid range. */
			if (idx < 0)
				idx = 0;
			else if (idx > IWN4965_MAX_PWR_INDEX)
				idx = IWN4965_MAX_PWR_INDEX;

			sc->sc_txpower->txchain[c].rate[ridx].rf_gain.value.l =
			    cmd.power[ridx].rf_gain[c] = rf_gain[idx];
			sc->sc_txpower->txchain[c].rate[ridx].dsp_gain.value.l =
			    cmd.power[ridx].dsp_gain[c] = dsp_gain[idx];
		}
	}

	return iwn_cmd(sc, IWN_CMD_TXPOWER, &cmd, sizeof cmd, async);

#undef interpolate
#undef fdivround
}

static int
iwn5000_set_txpower(struct iwn_softc *sc, int async)
{
	struct iwn5000_cmd_txpower cmd;

	/*
	 * TX power calibration is handled automatically by the firmware
	 * for 5000 Series.
	 */
	memset(&cmd, 0, sizeof cmd);
	cmd.global_limit = 2 * IWN5000_TXPOWER_MAX_DBM;	/* 16 dBm */
	cmd.flags = IWN5000_TXPOWER_NO_CLOSED;
	cmd.srv_limit = IWN5000_TXPOWER_AUTO;
	return iwn_cmd(sc, IWN_CMD_TXPOWER_DBM, &cmd, sizeof cmd, async);
}

/*
 * Retrieve the maximum RSSI (in dBm) among receivers.
 */
static int
iwn4965_get_rssi(const struct iwn_rx_stat *stat)
{
	const struct iwn4965_rx_phystat *phy = (const void *)stat->phybuf;
	uint8_t mask, agc;
	int rssi;

	mask = (le16toh(phy->antenna) >> 4) & IWN_ANT_ABC;
	agc  = (le16toh(phy->agc) >> 7) & 0x7f;

	rssi = 0;
	if (mask & IWN_ANT_A)
		rssi = MAX(rssi, phy->rssi[0]);
	if (mask & IWN_ANT_B)
		rssi = MAX(rssi, phy->rssi[2]);
	if (mask & IWN_ANT_C)
		rssi = MAX(rssi, phy->rssi[4]);

	return rssi - agc - IWN_RSSI_TO_DBM;
}

static int
iwn5000_get_rssi(const struct iwn_rx_stat *stat)
{
	const struct iwn5000_rx_phystat *phy = (const void *)stat->phybuf;
	uint8_t agc;
	int rssi;

	agc = (le32toh(phy->agc) >> 9) & 0x7f;

	rssi = MAX(le16toh(phy->rssi[0]) & 0xff,
		   le16toh(phy->rssi[1]) & 0xff);
	rssi = MAX(le16toh(phy->rssi[2]) & 0xff, rssi);

	return rssi - agc - IWN_RSSI_TO_DBM;
}

/*
 * Retrieve the average noise (in dBm) among receivers.
 */
static int
iwn_get_noise(const struct iwn_rx_general_stats *stats)
{
	int i, total, nbant, noise;

	total = nbant = 0;
	for (i = 0; i < 3; i++) {
		if ((noise = le32toh(stats->noise[i]) & 0xff) == 0)
			continue;
		total += noise;
		nbant++;
	}
	/* There should be at least one antenna but check anyway. */
	return (nbant == 0) ? -127 : (total / nbant) - 107;
}

/*
 * Compute temperature (in degC) from last received statistics.
 */
static int
iwn4965_get_temperature(struct iwn_softc *sc)
{
	struct iwn_ucode_info *uc = &sc->ucode_info;
	int32_t r1, r2, r3, r4, temp;

	r1 = le32toh(uc->temp[0].chan20MHz);
	r2 = le32toh(uc->temp[1].chan20MHz);
	r3 = le32toh(uc->temp[2].chan20MHz);
	r4 = le32toh(sc->rawtemp);

	if (r1 == r3)	/* Prevents division by 0 (should not happen). */
		return 0;

	/* Sign-extend 23-bit R4 value to 32-bit. */
	r4 = ((r4 & 0xffffff) ^ 0x800000) - 0x800000;
	/* Compute temperature in Kelvin. */
	temp = (259 * (r4 - r2)) / (r3 - r1);
	temp = (temp * 97) / 100 + 8;

	return IWN_KTOC(temp);
}

static int
iwn5000_get_temperature(struct iwn_softc *sc)
{
	int32_t temp;

	/*
	 * Temperature is not used by the driver for 5000 Series because
	 * TX power calibration is handled by firmware.  We export it to
	 * users through a kstat though.
	 */
	temp = le32toh(sc->rawtemp);
	if (sc->hw_type == IWN_HW_REV_TYPE_5150) {
		temp = (temp / -5) + sc->temp_off;
		temp = IWN_KTOC(temp);
	}
	return temp;
}

/*
 * Initialize sensitivity calibration state machine.
 */
static int
iwn_init_sensitivity(struct iwn_softc *sc)
{
	struct iwn_ops *ops = &sc->ops;
	struct iwn_calib_state *calib = &sc->calib;
	uint32_t flags;
	int error;

	/* Reset calibration state machine. */
	memset(calib, 0, sizeof (*calib));
	calib->state = IWN_CALIB_STATE_INIT;
	calib->cck_state = IWN_CCK_STATE_HIFA;
	/* Set initial correlation values. */
	calib->ofdm_x1     = sc->limits->min_ofdm_x1;
	calib->ofdm_mrc_x1 = sc->limits->min_ofdm_mrc_x1;
	calib->ofdm_x4     = sc->limits->min_ofdm_x4;
	calib->ofdm_mrc_x4 = sc->limits->min_ofdm_mrc_x4;
	calib->cck_x4      = 125;
	calib->cck_mrc_x4  = sc->limits->min_cck_mrc_x4;
	calib->energy_cck  = sc->limits->energy_cck;

	/* Write initial sensitivity. */
	if ((error = iwn_send_sensitivity(sc)) != 0)
		return error;

	/* Write initial gains. */
	if ((error = ops->init_gains(sc)) != 0)
		return error;

	/* Request statistics at each beacon interval. */
	flags = 0;
	return iwn_cmd(sc, IWN_CMD_GET_STATISTICS, &flags, sizeof flags, 1);
}

/*
 * Collect noise and RSSI statistics for the first 20 beacons received
 * after association and use them to determine connected antennas and
 * to set differential gains.
 */
static void
iwn_collect_noise(struct iwn_softc *sc,
    const struct iwn_rx_general_stats *stats)
{
	struct iwn_ops *ops = &sc->ops;
	struct iwn_calib_state *calib = &sc->calib;
	uint32_t val;
	int i;

	/* Accumulate RSSI and noise for all 3 antennas. */
	for (i = 0; i < 3; i++) {
		calib->rssi[i] += le32toh(stats->rssi[i]) & 0xff;
		calib->noise[i] += le32toh(stats->noise[i]) & 0xff;
	}
	/* NB: We update differential gains only once after 20 beacons. */
	if (++calib->nbeacons < 20)
		return;

	/* Determine highest average RSSI. */
	val = MAX(calib->rssi[0], calib->rssi[1]);
	val = MAX(calib->rssi[2], val);

	/* Determine which antennas are connected. */
	sc->chainmask = sc->rxchainmask;
	for (i = 0; i < 3; i++)
		if (val - calib->rssi[i] > 15 * 20)
			sc->chainmask &= ~(1 << i);

	sc->sc_ant->conn_ant.value.ul = sc->chainmask;

	/* If none of the TX antennas are connected, keep at least one. */
	if ((sc->chainmask & sc->txchainmask) == 0)
		sc->chainmask |= IWN_LSB(sc->txchainmask);

	(void)ops->set_gains(sc);
	calib->state = IWN_CALIB_STATE_RUN;

#ifdef notyet
	/* XXX Disable RX chains with no antennas connected. */
	sc->rxon.rxchain = htole16(IWN_RXCHAIN_SEL(sc->chainmask));
	DTRACE_PROBE2(rxon, struct iwn_rxon *, &sc->rxon, int, sc->rxonsz);
	(void)iwn_cmd(sc, IWN_CMD_RXON, &sc->rxon, sc->rxonsz, 1);
#endif

	/* Enable power-saving mode if requested by user. */
	if (sc->sc_ic.ic_flags & IEEE80211_F_PMGTON)
		(void)iwn_set_pslevel(sc, 0, 3, 1);
}

static int
iwn4965_init_gains(struct iwn_softc *sc)
{
	struct iwn_phy_calib_gain cmd;

	memset(&cmd, 0, sizeof cmd);
	cmd.code = IWN4965_PHY_CALIB_DIFF_GAIN;
	/* Differential gains initially set to 0 for all 3 antennas. */
	return iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 1);
}

static int
iwn5000_init_gains(struct iwn_softc *sc)
{
	struct iwn_phy_calib cmd;

	memset(&cmd, 0, sizeof cmd);
	cmd.code = sc->reset_noise_gain;
	cmd.ngroups = 1;
	cmd.isvalid = 1;
	return iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 1);
}

static int
iwn4965_set_gains(struct iwn_softc *sc)
{
	struct iwn_calib_state *calib = &sc->calib;
	struct iwn_phy_calib_gain cmd;
	int i, delta, noise;

	/* Get minimal noise among connected antennas. */
	noise = INT_MAX;	/* NB: There's at least one antenna. */
	for (i = 0; i < 3; i++)
		if (sc->chainmask & (1 << i))
			noise = MIN(calib->noise[i], noise);

	memset(&cmd, 0, sizeof cmd);
	cmd.code = IWN4965_PHY_CALIB_DIFF_GAIN;
	/* Set differential gains for connected antennas. */
	for (i = 0; i < 3; i++) {
		if (sc->chainmask & (1 << i)) {
			/* Compute attenuation (in unit of 1.5dB). */
			delta = (noise - calib->noise[i]) / 30;
			/* NB: delta <= 0 */
			/* Limit to [-4.5dB,0]. */
			cmd.gain[i] = (uint8_t)MIN(abs(delta), 3);
			if (delta < 0)
				cmd.gain[i] |= 1 << 2;	/* sign bit */
			sc->sc_ant->gain[i].value.ul = cmd.gain[i];
		}
	}
	return iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 1);
}

static int
iwn5000_set_gains(struct iwn_softc *sc)
{
	struct iwn_calib_state *calib = &sc->calib;
	struct iwn_phy_calib_gain cmd;
	int i, ant, div, delta;

	/* We collected 20 beacons and !=6050 need a 1.5 factor. */
	div = (sc->hw_type == IWN_HW_REV_TYPE_6050) ? 20 : 30;

	memset(&cmd, 0, sizeof cmd);
	cmd.code = sc->noise_gain;
	cmd.ngroups = 1;
	cmd.isvalid = 1;
	/* Get first available RX antenna as referential. */
	ant = IWN_LSB(sc->rxchainmask);
	/* Set differential gains for other antennas. */
	for (i = ant + 1; i < 3; i++) {
		if (sc->chainmask & (1 << i)) {
			/* The delta is relative to antenna "ant". */
			delta = (calib->noise[ant] - calib->noise[i]) / div;
			/* Limit to [-4.5dB,+4.5dB]. */
			cmd.gain[i - 1] = (uint8_t)MIN(abs(delta), 3);
			if (delta < 0)
				cmd.gain[i - 1] |= 1 << 2;	/* sign bit */
			sc->sc_ant->gain[i - 1].value.ul
			    = cmd.gain[i - 1];
		}
	}
	return iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 1);
}

/*
 * Tune RF RX sensitivity based on the number of false alarms detected
 * during the last beacon period.
 */
static void
iwn_tune_sensitivity(struct iwn_softc *sc, const struct iwn_rx_stats *stats)
{
#define inc(val, inc, max)			\
	if ((val) < (max)) {			\
		if ((val) < (max) - (inc))	\
			(val) += (inc);		\
		else				\
			(val) = (max);		\
		needs_update = 1;		\
	}
#define dec(val, dec, min)			\
	if ((val) > (min)) {			\
		if ((val) > (min) + (dec))	\
			(val) -= (dec);		\
		else				\
			(val) = (min);		\
		needs_update = 1;		\
	}

	const struct iwn_sensitivity_limits *limits = sc->limits;
	struct iwn_calib_state *calib = &sc->calib;
	uint32_t val, rxena, fa;
	uint32_t energy[3], energy_min;
	uint8_t noise[3], noise_ref;
	int i, needs_update = 0;

	/* Check that we've been enabled long enough. */
	if ((rxena = le32toh(stats->general.load)) == 0)
		return;

	/* Compute number of false alarms since last call for OFDM. */
	fa  = le32toh(stats->ofdm.bad_plcp) - calib->bad_plcp_ofdm;
	fa += le32toh(stats->ofdm.fa) - calib->fa_ofdm;
	fa *= 200 * 1024;	/* 200TU */

	/* Save counters values for next call. */
	calib->bad_plcp_ofdm = le32toh(stats->ofdm.bad_plcp);
	calib->fa_ofdm = le32toh(stats->ofdm.fa);

	if (fa > 50 * rxena) {
		/* High false alarm count, decrease sensitivity. */
		IWN_DBG("OFDM high false alarm count: %u", fa);
		inc(calib->ofdm_x1,     1, limits->max_ofdm_x1);
		inc(calib->ofdm_mrc_x1, 1, limits->max_ofdm_mrc_x1);
		inc(calib->ofdm_x4,     1, limits->max_ofdm_x4);
		inc(calib->ofdm_mrc_x4, 1, limits->max_ofdm_mrc_x4);

	} else if (fa < 5 * rxena) {
		/* Low false alarm count, increase sensitivity. */
		IWN_DBG("OFDM low false alarm count: %u", fa);
		dec(calib->ofdm_x1,     1, limits->min_ofdm_x1);
		dec(calib->ofdm_mrc_x1, 1, limits->min_ofdm_mrc_x1);
		dec(calib->ofdm_x4,     1, limits->min_ofdm_x4);
		dec(calib->ofdm_mrc_x4, 1, limits->min_ofdm_mrc_x4);
	}

	/* Compute maximum noise among 3 receivers. */
	for (i = 0; i < 3; i++)
		noise[i] = (le32toh(stats->general.noise[i]) >> 8) & 0xff;
	val = MAX(noise[0], noise[1]);
	val = MAX(noise[2], val);
	/* Insert it into our samples table. */
	calib->noise_samples[calib->cur_noise_sample] = (uint8_t)val;
	calib->cur_noise_sample = (calib->cur_noise_sample + 1) % 20;

	/* Compute maximum noise among last 20 samples. */
	noise_ref = calib->noise_samples[0];
	for (i = 1; i < 20; i++)
		noise_ref = MAX(noise_ref, calib->noise_samples[i]);

	/* Compute maximum energy among 3 receivers. */
	for (i = 0; i < 3; i++)
		energy[i] = le32toh(stats->general.energy[i]);
	val = MIN(energy[0], energy[1]);
	val = MIN(energy[2], val);
	/* Insert it into our samples table. */
	calib->energy_samples[calib->cur_energy_sample] = val;
	calib->cur_energy_sample = (calib->cur_energy_sample + 1) % 10;

	/* Compute minimum energy among last 10 samples. */
	energy_min = calib->energy_samples[0];
	for (i = 1; i < 10; i++)
		energy_min = MAX(energy_min, calib->energy_samples[i]);
	energy_min += 6;

	/* Compute number of false alarms since last call for CCK. */
	fa  = le32toh(stats->cck.bad_plcp) - calib->bad_plcp_cck;
	fa += le32toh(stats->cck.fa) - calib->fa_cck;
	fa *= 200 * 1024;	/* 200TU */

	/* Save counters values for next call. */
	calib->bad_plcp_cck = le32toh(stats->cck.bad_plcp);
	calib->fa_cck = le32toh(stats->cck.fa);

	if (fa > 50 * rxena) {
		/* High false alarm count, decrease sensitivity. */
		IWN_DBG("CCK high false alarm count: %u", fa);
		calib->cck_state = IWN_CCK_STATE_HIFA;
		calib->low_fa = 0;

		if (calib->cck_x4 > 160) {
			calib->noise_ref = noise_ref;
			if (calib->energy_cck > 2)
				dec(calib->energy_cck, 2, energy_min);
		}
		if (calib->cck_x4 < 160) {
			calib->cck_x4 = 161;
			needs_update = 1;
		} else
			inc(calib->cck_x4, 3, limits->max_cck_x4);

		inc(calib->cck_mrc_x4, 3, limits->max_cck_mrc_x4);

	} else if (fa < 5 * rxena) {
		/* Low false alarm count, increase sensitivity. */
		IWN_DBG("CCK low false alarm count: %u", fa);
		calib->cck_state = IWN_CCK_STATE_LOFA;
		calib->low_fa++;

		if (calib->cck_state != IWN_CCK_STATE_INIT &&
		    (((int32_t)calib->noise_ref - (int32_t)noise_ref) > 2 ||
		     calib->low_fa > 100)) {
			inc(calib->energy_cck, 2, limits->min_energy_cck);
			dec(calib->cck_x4,     3, limits->min_cck_x4);
			dec(calib->cck_mrc_x4, 3, limits->min_cck_mrc_x4);
		}
	} else {
		/* Not worth to increase or decrease sensitivity. */
		IWN_DBG("CCK normal false alarm count: %u", fa);
		calib->low_fa = 0;
		calib->noise_ref = noise_ref;

		if (calib->cck_state == IWN_CCK_STATE_HIFA) {
			/* Previous interval had many false alarms. */
			dec(calib->energy_cck, 8, energy_min);
		}
		calib->cck_state = IWN_CCK_STATE_INIT;
	}

	if (needs_update)
		(void)iwn_send_sensitivity(sc);
#undef dec
#undef inc
}

static int
iwn_send_sensitivity(struct iwn_softc *sc)
{
	struct iwn_calib_state *calib = &sc->calib;
	struct iwn_enhanced_sensitivity_cmd cmd;
	int len;

	memset(&cmd, 0, sizeof cmd);
	len = sizeof (struct iwn_sensitivity_cmd);
	cmd.which = IWN_SENSITIVITY_WORKTBL;
	/* OFDM modulation. */
	cmd.corr_ofdm_x1     = htole16(calib->ofdm_x1);
	cmd.corr_ofdm_mrc_x1 = htole16(calib->ofdm_mrc_x1);
	cmd.corr_ofdm_x4     = htole16(calib->ofdm_x4);
	cmd.corr_ofdm_mrc_x4 = htole16(calib->ofdm_mrc_x4);
	cmd.energy_ofdm      = htole16(sc->limits->energy_ofdm);
	cmd.energy_ofdm_th   = htole16(62);
	/* CCK modulation. */
	cmd.corr_cck_x4      = htole16(calib->cck_x4);
	cmd.corr_cck_mrc_x4  = htole16(calib->cck_mrc_x4);
	cmd.energy_cck       = htole16(calib->energy_cck);
	/* Barker modulation: use default values. */
	cmd.corr_barker      = htole16(190);
	cmd.corr_barker_mrc  = htole16(390);
	if (!(sc->sc_flags & IWN_FLAG_ENH_SENS))
		goto send;
	/* Enhanced sensitivity settings. */
	len = sizeof (struct iwn_enhanced_sensitivity_cmd);
	cmd.ofdm_det_slope_mrc = htole16(668);
	cmd.ofdm_det_icept_mrc = htole16(4);
	cmd.ofdm_det_slope     = htole16(486);
	cmd.ofdm_det_icept     = htole16(37);
	cmd.cck_det_slope_mrc  = htole16(853);
	cmd.cck_det_icept_mrc  = htole16(4);
	cmd.cck_det_slope      = htole16(476);
	cmd.cck_det_icept      = htole16(99);
send:

	sc->sc_sens->ofdm_x1.value.ul = calib->ofdm_x1;
	sc->sc_sens->ofdm_mrc_x1.value.ul = calib->ofdm_mrc_x1;
	sc->sc_sens->ofdm_x4.value.ul = calib->ofdm_x4;
	sc->sc_sens->ofdm_mrc_x4.value.ul = calib->ofdm_mrc_x4;
	sc->sc_sens->cck_x4.value.ul = calib->cck_x4;
	sc->sc_sens->cck_mrc_x4.value.ul = calib->cck_mrc_x4;
	sc->sc_sens->energy_cck.value.ul = calib->energy_cck;

	return iwn_cmd(sc, IWN_CMD_SET_SENSITIVITY, &cmd, len, 1);
}

/*
 * Set STA mode power saving level (between 0 and 5).
 * Level 0 is CAM (Continuously Aware Mode), 5 is for maximum power saving.
 */
static int
iwn_set_pslevel(struct iwn_softc *sc, int dtim, int level, int async)
{
	struct iwn_pmgt_cmd cmd;
	const struct iwn_pmgt *pmgt;
	uint32_t maxp, skip_dtim;
	uint32_t reg;
	int i;

	/* Select which PS parameters to use. */
	if (dtim <= 2)
		pmgt = &iwn_pmgt[0][level];
	else if (dtim <= 10)
		pmgt = &iwn_pmgt[1][level];
	else
		pmgt = &iwn_pmgt[2][level];

	memset(&cmd, 0, sizeof cmd);
	if (level != 0)	/* not CAM */
		cmd.flags |= htole16(IWN_PS_ALLOW_SLEEP);
	if (level == 5)
		cmd.flags |= htole16(IWN_PS_FAST_PD);
	/* Retrieve PCIe Active State Power Management (ASPM). */
	reg = pci_config_get32(sc->sc_pcih,
	    sc->sc_cap_off + PCIE_LINKCTL);
	if (!(reg & PCIE_LINKCTL_ASPM_CTL_L0S)) /* L0s Entry disabled. */
		cmd.flags |= htole16(IWN_PS_PCI_PMGT);
	cmd.rxtimeout = htole32(pmgt->rxtimeout * 1024);
	cmd.txtimeout = htole32(pmgt->txtimeout * 1024);

	if (dtim == 0) {
		dtim = 1;
		skip_dtim = 0;
	} else
		skip_dtim = pmgt->skip_dtim;
	if (skip_dtim != 0) {
		cmd.flags |= htole16(IWN_PS_SLEEP_OVER_DTIM);
		maxp = pmgt->intval[4];
		if (maxp == (uint32_t)-1)
			maxp = dtim * (skip_dtim + 1);
		else if (maxp > dtim)
			maxp = (maxp / dtim) * dtim;
	} else
		maxp = dtim;
	for (i = 0; i < 5; i++)
		cmd.intval[i] = htole32(MIN(maxp, pmgt->intval[i]));

	sc->sc_misc->pslevel.value.ul = level;
	return iwn_cmd(sc, IWN_CMD_SET_POWER_MODE, &cmd, sizeof cmd, async);
}

int
iwn5000_runtime_calib(struct iwn_softc *sc)
{
	struct iwn5000_calib_config cmd;

	memset(&cmd, 0, sizeof cmd);
	cmd.ucode.once.enable = 0xffffffff;
	cmd.ucode.once.start = IWN5000_CALIB_DC;
	return iwn_cmd(sc, IWN5000_CMD_CALIB_CONFIG, &cmd, sizeof(cmd), 0);
}

static int
iwn_config_bt_coex_bluetooth(struct iwn_softc *sc)
{
	struct iwn_bluetooth bluetooth;

	memset(&bluetooth, 0, sizeof bluetooth);
	bluetooth.flags = IWN_BT_COEX_ENABLE;
	bluetooth.lead_time = IWN_BT_LEAD_TIME_DEF;
	bluetooth.max_kill = IWN_BT_MAX_KILL_DEF;

	return iwn_cmd(sc, IWN_CMD_BT_COEX, &bluetooth, sizeof bluetooth, 0);
}

static int
iwn_config_bt_coex_prio_table(struct iwn_softc *sc)
{
	uint8_t prio_table[16];

	memset(&prio_table, 0, sizeof prio_table);
	prio_table[ 0] =  6;	/* init calibration 1		*/
	prio_table[ 1] =  7;	/* init calibration 2		*/
	prio_table[ 2] =  2;	/* periodic calib low 1		*/
	prio_table[ 3] =  3;	/* periodic calib low 2		*/
	prio_table[ 4] =  4;	/* periodic calib high 1	*/
	prio_table[ 5] =  5;	/* periodic calib high 2	*/
	prio_table[ 6] =  6;	/* dtim				*/
	prio_table[ 7] =  8;	/* scan52			*/
	prio_table[ 8] = 10;	/* scan24			*/

	return iwn_cmd(sc, IWN_CMD_BT_COEX_PRIO_TABLE,
	               &prio_table, sizeof prio_table, 0);
}

static int
iwn_config_bt_coex_adv_config(struct iwn_softc *sc, struct iwn_bt_basic *basic,
    size_t len)
{
	struct iwn_btcoex_prot btprot;
	int error;

	basic->bt.flags = IWN_BT_COEX_ENABLE;
	basic->bt.lead_time = IWN_BT_LEAD_TIME_DEF;
	basic->bt.max_kill = IWN_BT_MAX_KILL_DEF;
	basic->bt.bt3_timer_t7_value = IWN_BT_BT3_T7_DEF;
	basic->bt.kill_ack_mask = IWN_BT_KILL_ACK_MASK_DEF;
	basic->bt.kill_cts_mask = IWN_BT_KILL_CTS_MASK_DEF;
	basic->bt3_prio_sample_time = IWN_BT_BT3_PRIO_SAMPLE_DEF;
	basic->bt3_timer_t2_value = IWN_BT_BT3_T2_DEF;
	basic->bt3_lookup_table[ 0] = htole32(0xaaaaaaaa); /* Normal */
	basic->bt3_lookup_table[ 1] = htole32(0xaaaaaaaa);
	basic->bt3_lookup_table[ 2] = htole32(0xaeaaaaaa);
	basic->bt3_lookup_table[ 3] = htole32(0xaaaaaaaa);
	basic->bt3_lookup_table[ 4] = htole32(0xcc00ff28);
	basic->bt3_lookup_table[ 5] = htole32(0x0000aaaa);
	basic->bt3_lookup_table[ 6] = htole32(0xcc00aaaa);
	basic->bt3_lookup_table[ 7] = htole32(0x0000aaaa);
	basic->bt3_lookup_table[ 8] = htole32(0xc0004000);
	basic->bt3_lookup_table[ 9] = htole32(0x00004000);
	basic->bt3_lookup_table[10] = htole32(0xf0005000);
	basic->bt3_lookup_table[11] = htole32(0xf0005000);
	basic->reduce_txpower = 0; /* as not implemented */
	basic->valid = IWN_BT_ALL_VALID_MASK;

	error = iwn_cmd(sc, IWN_CMD_BT_COEX, &basic, len, 0);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not configure advanced bluetooth coexistence");
		return error;
	}

	error = iwn_config_bt_coex_prio_table(sc);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not configure send BT priority table");
		return error;
	}

	/* Force BT state machine change */
	memset(&btprot, 0, sizeof btprot);
	btprot.open = 1;
	btprot.type = 1;
	error = iwn_cmd(sc, IWN_CMD_BT_COEX_PROT, &btprot, sizeof btprot, 1);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!could not open BT protcol");
		return error;
	}

	btprot.open = 0;
	error = iwn_cmd(sc, IWN_CMD_BT_COEX_PROT, &btprot, sizeof btprot, 1);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!could not close BT protcol");
		return error;
	}
	return 0;
}

static int
iwn_config_bt_coex_adv1(struct iwn_softc *sc)
{
	struct iwn_bt_adv1 d;

	memset(&d, 0, sizeof d);
	d.prio_boost = IWN_BT_PRIO_BOOST_DEF;
	d.tx_prio_boost = 0;
	d.rx_prio_boost = 0;
	return iwn_config_bt_coex_adv_config(sc, &d.basic, sizeof d);
}

static int
iwn_config_bt_coex_adv2(struct iwn_softc *sc)
{
	struct iwn_bt_adv2 d;

	memset(&d, 0, sizeof d);
	d.prio_boost = IWN_BT_PRIO_BOOST_DEF;
	d.tx_prio_boost = 0;
	d.rx_prio_boost = 0;
	return iwn_config_bt_coex_adv_config(sc, &d.basic, sizeof d);
}

static int
iwn_config(struct iwn_softc *sc)
{
	struct iwn_ops *ops = &sc->ops;
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t txmask;
	uint16_t rxchain;
	int error;

	error = ops->config_bt_coex(sc);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not configure bluetooth coexistence");
		return error;
	}

	/* Set radio temperature sensor offset. */
	if (sc->hw_type == IWN_HW_REV_TYPE_6005) {
		error = iwn6000_temp_offset_calib(sc);
		if (error != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not set temperature offset");
			return error;
		}
	}

	if (sc->hw_type == IWN_HW_REV_TYPE_2030 ||
	    sc->hw_type == IWN_HW_REV_TYPE_2000 ||
	    sc->hw_type == IWN_HW_REV_TYPE_135  ||
	    sc->hw_type == IWN_HW_REV_TYPE_105) {
		error = iwn2000_temp_offset_calib(sc);
		if (error != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not set temperature offset");
			return error;
		}
	}

	if (sc->hw_type == IWN_HW_REV_TYPE_6050 ||
	    sc->hw_type == IWN_HW_REV_TYPE_6005) {
		/* Configure runtime DC calibration. */
		error = iwn5000_runtime_calib(sc);
		if (error != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not configure runtime calibration");
			return error;
		}
	}

	/* Configure valid TX chains for 5000 Series. */
	if (sc->hw_type != IWN_HW_REV_TYPE_4965) {
		txmask = htole32(sc->txchainmask);
		error = iwn_cmd(sc, IWN5000_CMD_TX_ANT_CONFIG, &txmask,
		    sizeof txmask, 0);
		if (error != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not configure valid TX chains");
			return error;
		}
	}

	/* Set mode, channel, RX filter and enable RX. */
	memset(&sc->rxon, 0, sizeof (struct iwn_rxon));
	IEEE80211_ADDR_COPY(sc->rxon.myaddr, ic->ic_macaddr);
	IEEE80211_ADDR_COPY(sc->rxon.wlap, ic->ic_macaddr);
	sc->rxon.chan = ieee80211_chan2ieee(ic, ic->ic_ibss_chan);
	sc->rxon.flags = htole32(IWN_RXON_TSF | IWN_RXON_CTS_TO_SELF);
	if (IEEE80211_IS_CHAN_2GHZ(ic->ic_ibss_chan))
		sc->rxon.flags |= htole32(IWN_RXON_AUTO | IWN_RXON_24GHZ);
	switch (ic->ic_opmode) {
	case IEEE80211_M_IBSS:
		sc->rxon.mode = IWN_MODE_IBSS;
		sc->rxon.filter = htole32(IWN_FILTER_MULTICAST);
		break;
	case IEEE80211_M_STA:
		sc->rxon.mode = IWN_MODE_STA;
		sc->rxon.filter = htole32(IWN_FILTER_MULTICAST);
		break;
	case IEEE80211_M_MONITOR:
		sc->rxon.mode = IWN_MODE_MONITOR;
		sc->rxon.filter = htole32(IWN_FILTER_MULTICAST |
		    IWN_FILTER_CTL | IWN_FILTER_PROMISC);
		break;
	default:
		/* Should not get there. */
		ASSERT(ic->ic_opmode == IEEE80211_M_IBSS ||
		    ic->ic_opmode == IEEE80211_M_STA ||
		    ic->ic_opmode == IEEE80211_M_MONITOR);
		break;
	}
	sc->rxon.cck_mask  = 0x0f;	/* not yet negotiated */
	sc->rxon.ofdm_mask = 0xff;	/* not yet negotiated */
	sc->rxon.ht_single_mask = 0xff;
	sc->rxon.ht_dual_mask = 0xff;
	sc->rxon.ht_triple_mask = 0xff;
	rxchain =
	    IWN_RXCHAIN_VALID(sc->rxchainmask) |
	    IWN_RXCHAIN_MIMO_COUNT(2) |
	    IWN_RXCHAIN_IDLE_COUNT(2);
	sc->rxon.rxchain = htole16(rxchain);
	DTRACE_PROBE2(rxon, struct iwn_rxon *, &sc->rxon, int, sc->rxonsz);
	error = iwn_cmd(sc, IWN_CMD_RXON, &sc->rxon, sc->rxonsz, 0);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!RXON command failed");
		return error;
	}

	if ((error = iwn_add_broadcast_node(sc, 0)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not add broadcast node");
		return error;
	}

	/* Configuration has changed, set TX power accordingly. */
	if ((error = ops->set_txpower(sc, 0)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not set TX power");
		return error;
	}

	if ((error = iwn_set_critical_temp(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not set critical temperature");
		return error;
	}

	/* Set power saving level to CAM during initialization. */
	if ((error = iwn_set_pslevel(sc, 0, 0, 0)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not set power saving level");
		return error;
	}
	return 0;
}

static uint16_t
iwn_get_active_dwell_time(struct iwn_softc *sc, uint16_t flags,
    uint8_t n_probes)
{
	_NOTE(ARGUNUSED(sc));

	/* No channel? Default to 2GHz settings */
	if (flags & IEEE80211_CHAN_2GHZ)
		return IWN_ACTIVE_DWELL_TIME_2GHZ +
		    IWN_ACTIVE_DWELL_FACTOR_2GHZ * (n_probes + 1);

	/* 5GHz dwell time */
	return IWN_ACTIVE_DWELL_TIME_5GHZ +
	    IWN_ACTIVE_DWELL_FACTOR_5GHZ * (n_probes + 1);
}

/*
 * Limit the total dwell time to 85% of the beacon interval.
 *
 * Returns the dwell time in milliseconds.
 */
static uint16_t
iwn_limit_dwell(struct iwn_softc *sc, uint16_t dwell_time)
{
	_NOTE(ARGUNUSED(dwell_time));

	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	int bintval = 0;

	/* bintval is in TU (1.024mS) */
	if (ni != NULL)
		bintval = ni->in_intval;

	/*
	 * If it's non-zero, we should calculate the minimum of
	 * it and the DWELL_BASE.
	 *
	 * XXX Yes, the math should take into account that bintval
	 * is 1.024mS, not 1mS..
	 */
	if (bintval > 0)
		return MIN(IWN_PASSIVE_DWELL_BASE, ((bintval * 85) / 100));

	/* No association context? Default */
	return IWN_PASSIVE_DWELL_BASE;
}

static uint16_t
iwn_get_passive_dwell_time(struct iwn_softc *sc, uint16_t flags)
{
	uint16_t passive;
	if (flags & IEEE80211_CHAN_2GHZ)
		passive = IWN_PASSIVE_DWELL_BASE + IWN_PASSIVE_DWELL_TIME_2GHZ;
	else
		passive = IWN_PASSIVE_DWELL_BASE + IWN_PASSIVE_DWELL_TIME_5GHZ;

	/* Clamp to the beacon interval if we're associated */
	return iwn_limit_dwell(sc, passive);
}

static int
iwn_scan(struct iwn_softc *sc, uint16_t flags)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct iwn_scan_hdr *hdr;
	struct iwn_cmd_data *tx;
	struct iwn_scan_essid *essid;
	struct iwn_scan_chan *chan;
	struct ieee80211_frame *wh;
	struct ieee80211_rateset *rs;
	struct ieee80211_channel *c;
	uint8_t *buf, *frm;
	uint16_t rxchain, dwell_active, dwell_passive;
	uint8_t txant;
	int buflen, error, is_active;

	buf = kmem_zalloc(IWN_SCAN_MAXSZ, KM_NOSLEEP);
	if (buf == NULL) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not allocate buffer for scan command");
		return ENOMEM;
	}
	hdr = (struct iwn_scan_hdr *)buf;
	/*
	 * Move to the next channel if no frames are received within 20ms
	 * after sending the probe request.
	 */
	hdr->quiet_time = htole16(20);		/* timeout in milliseconds */
	hdr->quiet_threshold = htole16(1);	/* min # of packets */

	/* Select antennas for scanning. */
	rxchain =
	    IWN_RXCHAIN_VALID(sc->rxchainmask) |
	    IWN_RXCHAIN_FORCE_MIMO_SEL(sc->rxchainmask) |
	    IWN_RXCHAIN_DRIVER_FORCE;
	if ((flags & IEEE80211_CHAN_5GHZ) &&
	    sc->hw_type == IWN_HW_REV_TYPE_4965) {
		/* Ant A must be avoided in 5GHz because of an HW bug. */
		rxchain |= IWN_RXCHAIN_FORCE_SEL(IWN_ANT_BC);
	} else	/* Use all available RX antennas. */
		rxchain |= IWN_RXCHAIN_FORCE_SEL(sc->rxchainmask);
	hdr->rxchain = htole16(rxchain);
	hdr->filter = htole32(IWN_FILTER_MULTICAST |  IWN_FILTER_BEACON);

	tx = (struct iwn_cmd_data *)(hdr + 1);
	tx->flags = htole32(IWN_TX_AUTO_SEQ);
	tx->id = sc->broadcast_id;
	tx->lifetime = htole32(IWN_LIFETIME_INFINITE);

	if (flags & IEEE80211_CHAN_5GHZ) {
		/* Send probe requests at 6Mbps. */
		tx->plcp = iwn_rates[IWN_RIDX_OFDM6].plcp;
		rs = &ic->ic_sup_rates[IEEE80211_MODE_11A];
	} else {
		hdr->flags = htole32(IWN_RXON_24GHZ | IWN_RXON_AUTO);
		/* Send probe requests at 1Mbps. */
		tx->plcp = iwn_rates[IWN_RIDX_CCK1].plcp;
		tx->rflags = IWN_RFLAG_CCK;
		rs = &ic->ic_sup_rates[IEEE80211_MODE_11G];
	}

	hdr->crc_threshold = 0xffff;

	/* Use the first valid TX antenna. */
	txant = IWN_LSB(sc->txchainmask);
	tx->rflags |= IWN_RFLAG_ANT(txant);

	/*
	 * Only do active scanning if we're announcing a probe request
	 * for a given SSID (or more, if we ever add it to the driver.)
	 */
	is_active = 0;

	essid = (struct iwn_scan_essid *)(tx + 1);
	if (ic->ic_des_esslen != 0) {
		char essidstr[IEEE80211_NWID_LEN+1];
		memcpy(essidstr, ic->ic_des_essid, ic->ic_des_esslen);
		essidstr[ic->ic_des_esslen] = '\0';

		DTRACE_PROBE1(scan__direct, char *, essidstr);

		essid[0].id = IEEE80211_ELEMID_SSID;
		essid[0].len = ic->ic_des_esslen;
		memcpy(essid[0].data, ic->ic_des_essid, ic->ic_des_esslen);

		is_active = 1;
		/* hdr->crc_threshold = 0x1; */
		hdr->scan_flags = htole32(IWN_SCAN_PASSIVE2ACTIVE);
	}
	/*
	 * Build a probe request frame.  Most of the following code is a
	 * copy & paste of what is done in net80211.
	 */
	wh = (struct ieee80211_frame *)(essid + 20);
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
	    IEEE80211_FC0_SUBTYPE_PROBE_REQ;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	IEEE80211_ADDR_COPY(wh->i_addr1, etherbroadcastaddr);
	IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_macaddr);
	IEEE80211_ADDR_COPY(wh->i_addr3, etherbroadcastaddr);
	wh->i_dur[0] = wh->i_dur[1] = 0; /* filled by HW */
	wh->i_seq[0] = wh->i_seq[1] = 0; /* filled by HW */

	frm = (uint8_t *)(wh + 1);
	frm = ieee80211_add_ssid(frm, ic->ic_des_essid, ic->ic_des_esslen);
	frm = ieee80211_add_rates(frm, rs);
#ifndef IEEE80211_NO_HT
	if (ic->ic_flags & IEEE80211_F_HTON)
		frm = ieee80211_add_htcaps(frm, ic);
#endif
	if (rs->ir_nrates > IEEE80211_RATE_SIZE)
		frm = ieee80211_add_xrates(frm, rs);

	/* Set length of probe request. */
	/*LINTED: E_PTRDIFF_OVERFLOW*/
	tx->len = htole16(frm - (uint8_t *)wh);


	/*
	 * If active scanning is requested but a certain channel is
	 * marked passive, we can do active scanning if we detect
	 * transmissions.
	 *
	 * There is an issue with some firmware versions that triggers
	 * a sysassert on a "good CRC threshold" of zero (== disabled),
	 * on a radar channel even though this means that we should NOT
	 * send probes.
	 *
	 * The "good CRC threshold" is the number of frames that we
	 * need to receive during our dwell time on a channel before
	 * sending out probes -- setting this to a huge value will
	 * mean we never reach it, but at the same time work around
	 * the aforementioned issue. Thus use IWN_GOOD_CRC_TH_NEVER
	 * here instead of IWN_GOOD_CRC_TH_DISABLED.
	 *
	 * This was fixed in later versions along with some other
	 * scan changes, and the threshold behaves as a flag in those
	 * versions.
	 */

	/*
	 * If we're doing active scanning, set the crc_threshold
	 * to a suitable value.  This is different to active veruss
	 * passive scanning depending upon the channel flags; the
	 * firmware will obey that particular check for us.
	 */
	if (sc->tlv_feature_flags & IWN_UCODE_TLV_FLAGS_NEWSCAN)
		hdr->crc_threshold = is_active ?
		    IWN_GOOD_CRC_TH_DEFAULT : IWN_GOOD_CRC_TH_DISABLED;
	else
		hdr->crc_threshold = is_active ?
		    IWN_GOOD_CRC_TH_DEFAULT : IWN_GOOD_CRC_TH_NEVER;

	chan = (struct iwn_scan_chan *)frm;
	for (c  = &ic->ic_sup_channels[1];
	     c <= &ic->ic_sup_channels[IEEE80211_CHAN_MAX]; c++) {
		if ((c->ich_flags & flags) != flags)
			continue;
		chan->chan = htole16(ieee80211_chan2ieee(ic, c));
		chan->flags = 0;
		if (!(c->ich_flags & IEEE80211_CHAN_PASSIVE))
			chan->flags |= htole32(IWN_CHAN_ACTIVE);
		if (ic->ic_des_esslen != 0)
			chan->flags |= htole32(IWN_CHAN_NPBREQS(1));

		/*
		 * Calculate the active/passive dwell times.
		 */

		dwell_active = iwn_get_active_dwell_time(sc, flags, is_active);
		dwell_passive = iwn_get_passive_dwell_time(sc, flags);

		/* Make sure they're valid */
		if (dwell_passive <= dwell_active)
			dwell_passive = dwell_active + 1;

		chan->active = htole16(dwell_active);
		chan->passive = htole16(dwell_passive);

		chan->dsp_gain = 0x6e;
		if (IEEE80211_IS_CHAN_5GHZ(c)) {
			chan->rf_gain = 0x3b;
		} else {
			chan->rf_gain = 0x28;
		}
		DTRACE_PROBE5(add__channel, uint8_t, chan->chan,
		    uint32_t, chan->flags, uint8_t, chan->rf_gain,
		    uint16_t, chan->active, uint16_t, chan->passive);
		hdr->nchan++;
		chan++;
	}

	/*LINTED: E_PTRDIFF_OVERFLOW*/
	buflen = (uint8_t *)chan - buf;
	hdr->len = htole16(buflen);

	error = iwn_cmd(sc, IWN_CMD_SCAN, buf, buflen, 1);
	kmem_free(buf, IWN_SCAN_MAXSZ);
	return error;
}

static int
iwn_auth(struct iwn_softc *sc)
{
	struct iwn_ops *ops = &sc->ops;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	int error;

	ASSERT(ni->in_chan != NULL);

	/* Update adapter configuration. */
	IEEE80211_ADDR_COPY(sc->rxon.bssid, ni->in_bssid);
	sc->rxon.chan = ieee80211_chan2ieee(ic, ni->in_chan);
	sc->rxon.flags = htole32(IWN_RXON_TSF | IWN_RXON_CTS_TO_SELF);
	if ((ni->in_chan != IEEE80211_CHAN_ANYC) &&
	    IEEE80211_IS_CHAN_2GHZ(ni->in_chan))
		sc->rxon.flags |= htole32(IWN_RXON_AUTO | IWN_RXON_24GHZ);
	if (ic->ic_flags & IEEE80211_F_SHSLOT)
		sc->rxon.flags |= htole32(IWN_RXON_SHSLOT);
	if (ic->ic_flags & IEEE80211_F_SHPREAMBLE)
		sc->rxon.flags |= htole32(IWN_RXON_SHPREAMBLE);
	switch (ic->ic_curmode) {
	case IEEE80211_MODE_11A:
		sc->rxon.cck_mask  = 0;
		sc->rxon.ofdm_mask = 0x15;
		break;
	case IEEE80211_MODE_11B:
		sc->rxon.cck_mask  = 0x03;
		sc->rxon.ofdm_mask = 0;
		break;
	default:	/* Assume 802.11b/g. */
		sc->rxon.cck_mask  = 0x0f;
		sc->rxon.ofdm_mask = 0x15;
	}
	DTRACE_PROBE2(rxon, struct iwn_rxon *, &sc->rxon, int, sc->rxonsz);
	error = iwn_cmd(sc, IWN_CMD_RXON, &sc->rxon, sc->rxonsz, 1);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!RXON command failed");
		return error;
	}

	/* Configuration has changed, set TX power accordingly. */
	if ((error = ops->set_txpower(sc, 1)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not set TX power");
		return error;
	}
	/*
	 * Reconfiguring RXON clears the firmware nodes table so we must
	 * add the broadcast node again.
	 */
	if ((error = iwn_add_broadcast_node(sc, 1)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not add broadcast node");
		return error;
	}
	return 0;
}

static int
iwn_fast_recover(struct iwn_softc *sc)
{
	int err = IWN_FAIL;

	mutex_enter(&sc->sc_mtx);

	/* restore runtime configuration */
	bcopy(&sc->rxon_save, &sc->rxon,
	    sizeof (sc->rxon));

	sc->rxon.associd = 0;
	sc->rxon.filter &= ~htole32(IWN_FILTER_BSS);

	if ((err = iwn_auth(sc)) != IWN_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!iwn_fast_recover(): "
		    "could not setup authentication");
		mutex_exit(&sc->sc_mtx);
		return (err);
	}

	bcopy(&sc->rxon_save, &sc->rxon, sizeof (sc->rxon));

	/* update adapter's configuration */
	err = iwn_run(sc);
	if (err != IWN_SUCCESS) {
		dev_err(sc->sc_dip, CE_WARN, "!iwn_fast_recover(): "
		    "failed to setup association");
		mutex_exit(&sc->sc_mtx);
		return (err);
	}
	/* set LED on */
	iwn_set_led(sc, IWN_LED_LINK, 0, 1);

	sc->sc_flags &= ~IWN_FLAG_HW_ERR_RECOVER;
	mutex_exit(&sc->sc_mtx);

	/* start queue */
	DTRACE_PROBE(resume__xmit);

	return (IWN_SUCCESS);
}

static int
iwn_run(struct iwn_softc *sc)
{
	struct iwn_ops *ops = &sc->ops;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	struct iwn_node_info node;
	int error;

	if (ic->ic_opmode == IEEE80211_M_MONITOR) {
		/* Link LED blinks while monitoring. */
		iwn_set_led(sc, IWN_LED_LINK, 5, 5);
		return 0;
	}
	if ((error = iwn_set_timing(sc, ni)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not set timing");
		return error;
	}

	/* Update adapter configuration. */
	IEEE80211_ADDR_COPY(sc->rxon.bssid, ni->in_bssid);
	sc->rxon.associd = htole16(IEEE80211_AID(ni->in_associd));
	/* Short preamble and slot time are negotiated when associating. */
	sc->rxon.flags &= ~htole32(IWN_RXON_SHPREAMBLE | IWN_RXON_SHSLOT);
	if (ic->ic_flags & IEEE80211_F_SHSLOT)
		sc->rxon.flags |= htole32(IWN_RXON_SHSLOT);
	if (ic->ic_flags & IEEE80211_F_SHPREAMBLE)
		sc->rxon.flags |= htole32(IWN_RXON_SHPREAMBLE);
	sc->rxon.filter |= htole32(IWN_FILTER_BSS);
	if (ic->ic_opmode != IEEE80211_M_STA &&
	    ic->ic_opmode != IEEE80211_M_IBSS)
		sc->rxon.filter |= htole32(IWN_FILTER_BEACON);
	DTRACE_PROBE2(rxon, struct iwn_rxon *, &sc->rxon, int, sc->rxonsz);
	error = iwn_cmd(sc, IWN_CMD_RXON, &sc->rxon, sc->rxonsz, 1);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not update configuration");
		return error;
	}

	/* Configuration has changed, set TX power accordingly. */
	if ((error = ops->set_txpower(sc, 1)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not set TX power");
		return error;
	}

	/* Fake a join to initialize the TX rate. */
	((struct iwn_node *)ni)->id = IWN_ID_BSS;
	iwn_newassoc(ni, 1);

	/* Add BSS node. */
	memset(&node, 0, sizeof node);
	IEEE80211_ADDR_COPY(node.macaddr, ni->in_macaddr);
	node.id = IWN_ID_BSS;
#ifdef notyet
	node.htflags = htole32(IWN_AMDPU_SIZE_FACTOR(3) |
	    IWN_AMDPU_DENSITY(5));	/* 2us */
#endif
	error = ops->add_node(sc, &node, 1);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not add BSS node");
		return error;
	}
	if ((error = iwn_set_link_quality(sc, ni)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not setup link quality for node %d", node.id);
		return error;
	}

	if ((error = iwn_init_sensitivity(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not set sensitivity");
		return error;
	}

	if ((error = iwn_qosparam_to_hw(sc, 1)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not set QoS params");
		return (error);
	}

	/* Start periodic calibration timer. */
	sc->sc_flags &= ~IWN_FLAG_STOP_CALIB_TO;
	sc->calib.state = IWN_CALIB_STATE_ASSOC;
	sc->calib_cnt = 0;
	sc->calib_to = timeout(iwn_calib_timeout, sc, drv_usectohz(500000));

	/* Link LED always on while associated. */
	iwn_set_led(sc, IWN_LED_LINK, 0, 1);
	return 0;
}

#ifdef IWN_HWCRYPTO
/*
 * We support CCMP hardware encryption/decryption of unicast frames only.
 * HW support for TKIP really sucks.  We should let TKIP die anyway.
 */
static int
iwn_set_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct iwn_softc *sc = ic->ic_softc;
	struct iwn_ops *ops = &sc->ops;
	struct iwn_node *wn = (void *)ni;
	struct iwn_node_info node;
	uint16_t kflags;

	if ((k->k_flags & IEEE80211_KEY_GROUP) ||
	    k->k_cipher != IEEE80211_CIPHER_CCMP)
		return ieee80211_set_key(ic, ni, k);

	kflags = IWN_KFLAG_CCMP | IWN_KFLAG_MAP | IWN_KFLAG_KID(k->k_id);
	if (k->k_flags & IEEE80211_KEY_GROUP)
		kflags |= IWN_KFLAG_GROUP;

	memset(&node, 0, sizeof node);
	node.id = (k->k_flags & IEEE80211_KEY_GROUP) ?
	    sc->broadcast_id : wn->id;
	node.control = IWN_NODE_UPDATE;
	node.flags = IWN_FLAG_SET_KEY;
	node.kflags = htole16(kflags);
	node.kid = k->k_id;
	memcpy(node.key, k->k_key, k->k_len);
	DTRACE_PROBE2(set__key, int, k->k_id, int, node.id);
	return ops->add_node(sc, &node, 1);
}

static void
iwn_delete_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct iwn_softc *sc = ic->ic_softc;
	struct iwn_ops *ops = &sc->ops;
	struct iwn_node *wn = (void *)ni;
	struct iwn_node_info node;

	if ((k->k_flags & IEEE80211_KEY_GROUP) ||
	    k->k_cipher != IEEE80211_CIPHER_CCMP) {
		/* See comment about other ciphers above. */
		ieee80211_delete_key(ic, ni, k);
		return;
	}
	if (ic->ic_state != IEEE80211_S_RUN)
		return;	/* Nothing to do. */
	memset(&node, 0, sizeof node);
	node.id = (k->k_flags & IEEE80211_KEY_GROUP) ?
	    sc->broadcast_id : wn->id;
	node.control = IWN_NODE_UPDATE;
	node.flags = IWN_FLAG_SET_KEY;
	node.kflags = htole16(IWN_KFLAG_INVALID);
	node.kid = 0xff;
	DTRACE_PROBE1(del__key, int, node.id);
	(void)ops->add_node(sc, &node, 1);
}
#endif

#ifndef IEEE80211_NO_HT
/*
 * This function is called by upper layer when an ADDBA request is received
 * from another STA and before the ADDBA response is sent.
 */
static int
iwn_ampdu_rx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct ieee80211_rx_ba *ba = &ni->in_rx_ba[tid];
	struct iwn_softc *sc = ic->ic_softc;
	struct iwn_ops *ops = &sc->ops;
	struct iwn_node *wn = (void *)ni;
	struct iwn_node_info node;

	memset(&node, 0, sizeof node);
	node.id = wn->id;
	node.control = IWN_NODE_UPDATE;
	node.flags = IWN_FLAG_SET_ADDBA;
	node.addba_tid = tid;
	node.addba_ssn = htole16(ba->ba_winstart);
	DTRACE_PROBE3(addba, uint8_t, wn->id, uint8_t, tid, int, ba->ba_winstart);
	return ops->add_node(sc, &node, 1);
}

/*
 * This function is called by upper layer on teardown of an HT-immediate
 * Block Ack agreement (eg. uppon receipt of a DELBA frame).
 */
static void
iwn_ampdu_rx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct iwn_softc *sc = ic->ic_softc;
	struct iwn_ops *ops = &sc->ops;
	struct iwn_node *wn = (void *)ni;
	struct iwn_node_info node;

	memset(&node, 0, sizeof node);
	node.id = wn->id;
	node.control = IWN_NODE_UPDATE;
	node.flags = IWN_FLAG_SET_DELBA;
	node.delba_tid = tid;
	DTRACE_PROBE2(delba, uint8_t, wn->id, uint8_t, tid);
	(void)ops->add_node(sc, &node, 1);
}

/*
 * This function is called by upper layer when an ADDBA response is received
 * from another STA.
 */
static int
iwn_ampdu_tx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct ieee80211_tx_ba *ba = &ni->in_tx_ba[tid];
	struct iwn_softc *sc = ic->ic_softc;
	struct iwn_ops *ops = &sc->ops;
	struct iwn_node *wn = (void *)ni;
	struct iwn_node_info node;
	int error;

	/* Enable TX for the specified RA/TID. */
	wn->disable_tid &= ~(1 << tid);
	memset(&node, 0, sizeof node);
	node.id = wn->id;
	node.control = IWN_NODE_UPDATE;
	node.flags = IWN_FLAG_SET_DISABLE_TID;
	node.disable_tid = htole16(wn->disable_tid);
	error = ops->add_node(sc, &node, 1);
	if (error != 0)
		return error;

	if ((error = iwn_nic_lock(sc)) != 0)
		return error;
	ops->ampdu_tx_start(sc, ni, tid, ba->ba_winstart);
	iwn_nic_unlock(sc);
	return 0;
}

static void
iwn_ampdu_tx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct ieee80211_tx_ba *ba = &ni->in_tx_ba[tid];
	struct iwn_softc *sc = ic->ic_softc;
	struct iwn_ops *ops = &sc->ops;

	if (iwn_nic_lock(sc) != 0)
		return;
	ops->ampdu_tx_stop(sc, tid, ba->ba_winstart);
	iwn_nic_unlock(sc);
}

static void
iwn4965_ampdu_tx_start(struct iwn_softc *sc, struct ieee80211_node *ni,
    uint8_t tid, uint16_t ssn)
{
	struct iwn_node *wn = (void *)ni;
	int qid = 7 + tid;

	/* Stop TX scheduler while we're changing its configuration. */
	iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
	    IWN4965_TXQ_STATUS_CHGACT);

	/* Assign RA/TID translation to the queue. */
	iwn_mem_write_2(sc, sc->sched_base + IWN4965_SCHED_TRANS_TBL(qid),
	    wn->id << 4 | tid);

	/* Enable chain-building mode for the queue. */
	iwn_prph_setbits(sc, IWN4965_SCHED_QCHAIN_SEL, 1 << qid);

	/* Set starting sequence number from the ADDBA request. */
	IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | (ssn & 0xff));
	iwn_prph_write(sc, IWN4965_SCHED_QUEUE_RDPTR(qid), ssn);

	/* Set scheduler window size. */
	iwn_mem_write(sc, sc->sched_base + IWN4965_SCHED_QUEUE_OFFSET(qid),
	    IWN_SCHED_WINSZ);
	/* Set scheduler frame limit. */
	iwn_mem_write(sc, sc->sched_base + IWN4965_SCHED_QUEUE_OFFSET(qid) + 4,
	    IWN_SCHED_LIMIT << 16);

	/* Enable interrupts for the queue. */
	iwn_prph_setbits(sc, IWN4965_SCHED_INTR_MASK, 1 << qid);

	/* Mark the queue as active. */
	iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
	    IWN4965_TXQ_STATUS_ACTIVE | IWN4965_TXQ_STATUS_AGGR_ENA |
	    iwn_tid2fifo[tid] << 1);
}

static void
iwn4965_ampdu_tx_stop(struct iwn_softc *sc, uint8_t tid, uint16_t ssn)
{
	int qid = 7 + tid;

	/* Stop TX scheduler while we're changing its configuration. */
	iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
	    IWN4965_TXQ_STATUS_CHGACT);

	/* Set starting sequence number from the ADDBA request. */
	IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | (ssn & 0xff));
	iwn_prph_write(sc, IWN4965_SCHED_QUEUE_RDPTR(qid), ssn);

	/* Disable interrupts for the queue. */
	iwn_prph_clrbits(sc, IWN4965_SCHED_INTR_MASK, 1 << qid);

	/* Mark the queue as inactive. */
	iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
	    IWN4965_TXQ_STATUS_INACTIVE | iwn_tid2fifo[tid] << 1);
}

static void
iwn5000_ampdu_tx_start(struct iwn_softc *sc, struct ieee80211_node *ni,
    uint8_t tid, uint16_t ssn)
{
	struct iwn_node *wn = (void *)ni;
	int qid = 10 + tid;

	/* Stop TX scheduler while we're changing its configuration. */
	iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
	    IWN5000_TXQ_STATUS_CHGACT);

	/* Assign RA/TID translation to the queue. */
	iwn_mem_write_2(sc, sc->sched_base + IWN5000_SCHED_TRANS_TBL(qid),
	    wn->id << 4 | tid);

	/* Enable chain-building mode for the queue. */
	iwn_prph_setbits(sc, IWN5000_SCHED_QCHAIN_SEL, 1 << qid);

	/* Enable aggregation for the queue. */
	iwn_prph_setbits(sc, IWN5000_SCHED_AGGR_SEL, 1 << qid);

	/* Set starting sequence number from the ADDBA request. */
	IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | (ssn & 0xff));
	iwn_prph_write(sc, IWN5000_SCHED_QUEUE_RDPTR(qid), ssn);

	/* Set scheduler window size and frame limit. */
	iwn_mem_write(sc, sc->sched_base + IWN5000_SCHED_QUEUE_OFFSET(qid) + 4,
	    IWN_SCHED_LIMIT << 16 | IWN_SCHED_WINSZ);

	/* Enable interrupts for the queue. */
	iwn_prph_setbits(sc, IWN5000_SCHED_INTR_MASK, 1 << qid);

	/* Mark the queue as active. */
	iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
	    IWN5000_TXQ_STATUS_ACTIVE | iwn_tid2fifo[tid]);
}

static void
iwn5000_ampdu_tx_stop(struct iwn_softc *sc, uint8_t tid, uint16_t ssn)
{
	int qid = 10 + tid;

	/* Stop TX scheduler while we're changing its configuration. */
	iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
	    IWN5000_TXQ_STATUS_CHGACT);

	/* Disable aggregation for the queue. */
	iwn_prph_clrbits(sc, IWN5000_SCHED_AGGR_SEL, 1 << qid);

	/* Set starting sequence number from the ADDBA request. */
	IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | (ssn & 0xff));
	iwn_prph_write(sc, IWN5000_SCHED_QUEUE_RDPTR(qid), ssn);

	/* Disable interrupts for the queue. */
	iwn_prph_clrbits(sc, IWN5000_SCHED_INTR_MASK, 1 << qid);

	/* Mark the queue as inactive. */
	iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
	    IWN5000_TXQ_STATUS_INACTIVE | iwn_tid2fifo[tid]);
}
#endif	/* !IEEE80211_NO_HT */

/*
 * Query calibration tables from the initialization firmware.  We do this
 * only once at first boot.  Called from a process context.
 */
static int
iwn5000_query_calibration(struct iwn_softc *sc)
{
	struct iwn5000_calib_config cmd;
	int error;
	clock_t clk;

	ASSERT(mutex_owned(&sc->sc_mtx));

	memset(&cmd, 0, sizeof cmd);
	cmd.ucode.once.enable = 0xffffffff;
	cmd.ucode.once.start  = 0xffffffff;
	cmd.ucode.once.send   = 0xffffffff;
	cmd.ucode.flags       = 0xffffffff;
	error = iwn_cmd(sc, IWN5000_CMD_CALIB_CONFIG, &cmd, sizeof cmd, 0);
	if (error != 0)
		return error;

	/* Wait at most two seconds for calibration to complete. */
	clk = ddi_get_lbolt() + drv_usectohz(2000000);
	while (!(sc->sc_flags & IWN_FLAG_CALIB_DONE))
		if (cv_timedwait(&sc->sc_calib_cv, &sc->sc_mtx, clk) < 0)
			return (IWN_FAIL);

	return (IWN_SUCCESS);
}

/*
 * Send calibration results to the runtime firmware.  These results were
 * obtained on first boot from the initialization firmware.
 */
static int
iwn5000_send_calibration(struct iwn_softc *sc)
{
	int idx, error;

	for (idx = 0; idx < 5; idx++) {
		if (sc->calibcmd[idx].buf == NULL)
			continue;	/* No results available. */
		error = iwn_cmd(sc, IWN_CMD_PHY_CALIB, sc->calibcmd[idx].buf,
		    sc->calibcmd[idx].len, 0);
		if (error != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not send calibration result");
			return error;
		}
	}
	return 0;
}

static int
iwn5000_send_wimax_coex(struct iwn_softc *sc)
{
	struct iwn5000_wimax_coex wimax;

#ifdef notyet
	if (sc->hw_type == IWN_HW_REV_TYPE_6050) {
		/* Enable WiMAX coexistence for combo adapters. */
		wimax.flags =
		    IWN_WIMAX_COEX_ASSOC_WA_UNMASK |
		    IWN_WIMAX_COEX_UNASSOC_WA_UNMASK |
		    IWN_WIMAX_COEX_STA_TABLE_VALID |
		    IWN_WIMAX_COEX_ENABLE;
		memcpy(wimax.events, iwn6050_wimax_events,
		    sizeof iwn6050_wimax_events);
	} else
#endif
	{
		/* Disable WiMAX coexistence. */
		wimax.flags = 0;
		memset(wimax.events, 0, sizeof wimax.events);
	}
	return iwn_cmd(sc, IWN5000_CMD_WIMAX_COEX, &wimax, sizeof wimax, 0);
}

static int
iwn6000_temp_offset_calib(struct iwn_softc *sc)
{
	struct iwn6000_phy_calib_temp_offset cmd;

	memset(&cmd, 0, sizeof cmd);
	cmd.code = IWN6000_PHY_CALIB_TEMP_OFFSET;
	cmd.ngroups = 1;
	cmd.isvalid = 1;
	if (sc->eeprom_temp != 0)
		cmd.offset = htole16(sc->eeprom_temp);
	else
		cmd.offset = htole16(IWN_DEFAULT_TEMP_OFFSET);
	sc->sc_toff.t6000->toff.value.l = le16toh(cmd.offset);
	return iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 0);
}

static int
iwn2000_temp_offset_calib(struct iwn_softc *sc)
{
	struct iwn2000_phy_calib_temp_offset cmd;

	memset(&cmd, 0, sizeof cmd);
	cmd.code = IWN2000_PHY_CALIB_TEMP_OFFSET;
	cmd.ngroups = 1;
	cmd.isvalid = 1;
	if (sc->eeprom_rawtemp != 0) {
		cmd.offset_low = htole16(sc->eeprom_rawtemp);
		cmd.offset_high = htole16(sc->eeprom_temp);
	} else {
		cmd.offset_low = htole16(IWN_DEFAULT_TEMP_OFFSET);
		cmd.offset_high = htole16(IWN_DEFAULT_TEMP_OFFSET);
	}
	cmd.burnt_voltage_ref = htole16(sc->eeprom_voltage);
	sc->sc_toff.t2000->toff_lo.value.l = le16toh(cmd.offset_low);
	sc->sc_toff.t2000->toff_hi.value.l = le16toh(cmd.offset_high);
	sc->sc_toff.t2000->volt.value.l = le16toh(cmd.burnt_voltage_ref);

	return iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 0);
}

/*
 * This function is called after the runtime firmware notifies us of its
 * readiness (called in a process context).
 */
static int
iwn4965_post_alive(struct iwn_softc *sc)
{
	int error, qid;

	if ((error = iwn_nic_lock(sc)) != 0)
		return error;

	/* Clear TX scheduler state in SRAM. */
	sc->sched_base = iwn_prph_read(sc, IWN_SCHED_SRAM_ADDR);
	iwn_mem_set_region_4(sc, sc->sched_base + IWN4965_SCHED_CTX_OFF, 0,
	    IWN4965_SCHED_CTX_LEN / sizeof (uint32_t));

	/* Set physical address of TX scheduler rings (1KB aligned). */
	iwn_prph_write(sc, IWN4965_SCHED_DRAM_ADDR, sc->sched_dma.paddr >> 10);

	IWN_SETBITS(sc, IWN_FH_TX_CHICKEN, IWN_FH_TX_CHICKEN_SCHED_RETRY);

	/* Disable chain mode for all our 16 queues. */
	iwn_prph_write(sc, IWN4965_SCHED_QCHAIN_SEL, 0);

	for (qid = 0; qid < IWN4965_NTXQUEUES; qid++) {
		iwn_prph_write(sc, IWN4965_SCHED_QUEUE_RDPTR(qid), 0);
		IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | 0);

		/* Set scheduler window size. */
		iwn_mem_write(sc, sc->sched_base +
		    IWN4965_SCHED_QUEUE_OFFSET(qid), IWN_SCHED_WINSZ);
		/* Set scheduler frame limit. */
		iwn_mem_write(sc, sc->sched_base +
		    IWN4965_SCHED_QUEUE_OFFSET(qid) + 4,
		    IWN_SCHED_LIMIT << 16);
	}

	/* Enable interrupts for all our 16 queues. */
	iwn_prph_write(sc, IWN4965_SCHED_INTR_MASK, 0xffff);
	/* Identify TX FIFO rings (0-7). */
	iwn_prph_write(sc, IWN4965_SCHED_TXFACT, 0xff);

	/* Mark TX rings (4 EDCA + cmd + 2 HCCA) as active. */
	for (qid = 0; qid < 7; qid++) {
		static uint8_t qid2fifo[] = { 3, 2, 1, 0, 4, 5, 6 };
		iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
		    IWN4965_TXQ_STATUS_ACTIVE | qid2fifo[qid] << 1);
	}
	iwn_nic_unlock(sc);
	return 0;
}

/*
 * This function is called after the initialization or runtime firmware
 * notifies us of its readiness (called in a process context).
 */
static int
iwn5000_post_alive(struct iwn_softc *sc)
{
	int error, qid;

	/* Switch to using ICT interrupt mode. */
	iwn5000_ict_reset(sc);

	if ((error = iwn_nic_lock(sc)) != 0)
		return error;

	/* Clear TX scheduler state in SRAM. */
	sc->sched_base = iwn_prph_read(sc, IWN_SCHED_SRAM_ADDR);
	iwn_mem_set_region_4(sc, sc->sched_base + IWN5000_SCHED_CTX_OFF, 0,
	    IWN5000_SCHED_CTX_LEN / sizeof (uint32_t));

	/* Set physical address of TX scheduler rings (1KB aligned). */
	iwn_prph_write(sc, IWN5000_SCHED_DRAM_ADDR, sc->sched_dma.paddr >> 10);

	IWN_SETBITS(sc, IWN_FH_TX_CHICKEN, IWN_FH_TX_CHICKEN_SCHED_RETRY);

	/* Enable chain mode for all queues, except command queue. */
	iwn_prph_write(sc, IWN5000_SCHED_QCHAIN_SEL, 0xfffef);
	iwn_prph_write(sc, IWN5000_SCHED_AGGR_SEL, 0);

	for (qid = 0; qid < IWN5000_NTXQUEUES; qid++) {
		iwn_prph_write(sc, IWN5000_SCHED_QUEUE_RDPTR(qid), 0);
		IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | 0);

		iwn_mem_write(sc, sc->sched_base +
		    IWN5000_SCHED_QUEUE_OFFSET(qid), 0);
		/* Set scheduler window size and frame limit. */
		iwn_mem_write(sc, sc->sched_base +
		    IWN5000_SCHED_QUEUE_OFFSET(qid) + 4,
		    IWN_SCHED_LIMIT << 16 | IWN_SCHED_WINSZ);
	}

	/* Enable interrupts for all our 20 queues. */
	iwn_prph_write(sc, IWN5000_SCHED_INTR_MASK, 0xfffff);
	/* Identify TX FIFO rings (0-7). */
	iwn_prph_write(sc, IWN5000_SCHED_TXFACT, 0xff);

	/* Mark TX rings (4 EDCA + cmd + 2 HCCA) as active. */
	for (qid = 0; qid < 7; qid++) {
		static uint8_t qid2fifo[] = { 3, 2, 1, 0, 7, 5, 6 };
		iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
		    IWN5000_TXQ_STATUS_ACTIVE | qid2fifo[qid]);
	}
	iwn_nic_unlock(sc);

	/* Configure WiMAX coexistence for combo adapters. */
	error = iwn5000_send_wimax_coex(sc);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not configure WiMAX coexistence");
		return error;
	}
	if (sc->hw_type != IWN_HW_REV_TYPE_5150) {
		struct iwn5000_phy_calib_crystal cmd;

		/* Perform crystal calibration. */
		memset(&cmd, 0, sizeof cmd);
		cmd.code = IWN5000_PHY_CALIB_CRYSTAL;
		cmd.ngroups = 1;
		cmd.isvalid = 1;
		cmd.cap_pin[0] = le32toh(sc->eeprom_crystal) & 0xff;
		cmd.cap_pin[1] = (le32toh(sc->eeprom_crystal) >> 16) & 0xff;
		error = iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 0);
		if (error != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!crystal calibration failed");
			return error;
		}
	}
	if (!(sc->sc_flags & IWN_FLAG_CALIB_DONE)) {
		/* Query calibration from the initialization firmware. */
		if ((error = iwn5000_query_calibration(sc)) != 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!could not query calibration");
			return error;
		}
		/*
		 * We have the calibration results now, reboot with the
		 * runtime firmware (call ourselves recursively!)
		 */
		iwn_hw_stop(sc, B_FALSE);
		error = iwn_hw_init(sc);
	} else {
		/* Send calibration results to runtime firmware. */
		error = iwn5000_send_calibration(sc);
	}
	return error;
}

/*
 * The firmware boot code is small and is intended to be copied directy into
 * the NIC internal memory (no DMA transfer).
 */
static int
iwn4965_load_bootcode(struct iwn_softc *sc, const uint8_t *ucode, int size)
{
	int error, ntries;

	size /= sizeof (uint32_t);

	if ((error = iwn_nic_lock(sc)) != 0)
		return error;

	/* Copy microcode image into NIC memory. */
	iwn_prph_write_region_4(sc, IWN_BSM_SRAM_BASE,
	    /*LINTED: E_PTR_BAD_CAST_ALIGN*/
	    (const uint32_t *)ucode, size);

	iwn_prph_write(sc, IWN_BSM_WR_MEM_SRC, 0);
	iwn_prph_write(sc, IWN_BSM_WR_MEM_DST, IWN_FW_TEXT_BASE);
	iwn_prph_write(sc, IWN_BSM_WR_DWCOUNT, size);

	/* Start boot load now. */
	iwn_prph_write(sc, IWN_BSM_WR_CTRL, IWN_BSM_WR_CTRL_START);

	/* Wait for transfer to complete. */
	for (ntries = 0; ntries < 1000; ntries++) {
		if (!(iwn_prph_read(sc, IWN_BSM_WR_CTRL) &
		    IWN_BSM_WR_CTRL_START))
			break;
		DELAY(10);
	}
	if (ntries == 1000) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not load boot firmware");
		iwn_nic_unlock(sc);
		return ETIMEDOUT;
	}

	/* Enable boot after power up. */
	iwn_prph_write(sc, IWN_BSM_WR_CTRL, IWN_BSM_WR_CTRL_START_EN);

	iwn_nic_unlock(sc);
	return 0;
}

static int
iwn4965_load_firmware(struct iwn_softc *sc)
{
	struct iwn_fw_info *fw = &sc->fw;
	struct iwn_dma_info *dma = &sc->fw_dma;
	int error;
	clock_t clk;

	ASSERT(mutex_owned(&sc->sc_mtx));

	/* Copy initialization sections into pre-allocated DMA-safe memory. */
	memcpy(dma->vaddr, fw->init.data, fw->init.datasz);
	memcpy((char *)dma->vaddr + IWN4965_FW_DATA_MAXSZ,
	    fw->init.text, fw->init.textsz);
	(void) ddi_dma_sync(dma->dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);

	/* Tell adapter where to find initialization sections. */
	if ((error = iwn_nic_lock(sc)) != 0)
		return error;
	iwn_prph_write(sc, IWN_BSM_DRAM_DATA_ADDR, dma->paddr >> 4);
	iwn_prph_write(sc, IWN_BSM_DRAM_DATA_SIZE, fw->init.datasz);
	iwn_prph_write(sc, IWN_BSM_DRAM_TEXT_ADDR,
	    (dma->paddr + IWN4965_FW_DATA_MAXSZ) >> 4);
	iwn_prph_write(sc, IWN_BSM_DRAM_TEXT_SIZE, fw->init.textsz);
	iwn_nic_unlock(sc);

	/* Load firmware boot code. */
	error = iwn4965_load_bootcode(sc, fw->boot.text, fw->boot.textsz);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not load boot firmware");
		return error;
	}
	/* Now press "execute". */
	IWN_WRITE(sc, IWN_RESET, 0);

	/* Wait at most one second for first alive notification. */
	clk = ddi_get_lbolt() + drv_usectohz(1000000);
	while ((sc->sc_flags & IWN_FLAG_FW_ALIVE) == 0) {
		if (cv_timedwait(&sc->sc_alive_cv, &sc->sc_mtx, clk) < 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!timeout waiting for adapter to initialize");
			return (IWN_FAIL);
		}
	}

	/* Retrieve current temperature for initial TX power calibration. */
	sc->rawtemp = sc->ucode_info.temp[3].chan20MHz;
	sc->temp = iwn4965_get_temperature(sc);
	sc->sc_misc->temp.value.ul = sc->temp;

	/* Copy runtime sections into pre-allocated DMA-safe memory. */
	memcpy(dma->vaddr, fw->main.data, fw->main.datasz);
	memcpy((char *)dma->vaddr + IWN4965_FW_DATA_MAXSZ,
	    fw->main.text, fw->main.textsz);
	(void) ddi_dma_sync(dma->dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);

	/* Tell adapter where to find runtime sections. */
	if ((error = iwn_nic_lock(sc)) != 0)
		return error;
	iwn_prph_write(sc, IWN_BSM_DRAM_DATA_ADDR, dma->paddr >> 4);
	iwn_prph_write(sc, IWN_BSM_DRAM_DATA_SIZE, fw->main.datasz);
	iwn_prph_write(sc, IWN_BSM_DRAM_TEXT_ADDR,
	    (dma->paddr + IWN4965_FW_DATA_MAXSZ) >> 4);
	iwn_prph_write(sc, IWN_BSM_DRAM_TEXT_SIZE,
	    IWN_FW_UPDATED | fw->main.textsz);
	iwn_nic_unlock(sc);

	return 0;
}

static int
iwn5000_load_firmware_section(struct iwn_softc *sc, uint32_t dst,
    const uint8_t *section, int size)
{
	struct iwn_dma_info *dma = &sc->fw_dma;
	int error;
	clock_t clk;

	ASSERT(mutex_owned(&sc->sc_mtx));

	/* Copy firmware section into pre-allocated DMA-safe memory. */
	memcpy(dma->vaddr, section, size);
	(void) ddi_dma_sync(dma->dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);

	if ((error = iwn_nic_lock(sc)) != 0)
		return error;

	IWN_WRITE(sc, IWN_FH_TX_CONFIG(IWN_SRVC_DMACHNL),
	    IWN_FH_TX_CONFIG_DMA_PAUSE);

	IWN_WRITE(sc, IWN_FH_SRAM_ADDR(IWN_SRVC_DMACHNL), dst);
	IWN_WRITE(sc, IWN_FH_TFBD_CTRL0(IWN_SRVC_DMACHNL),
	    IWN_LOADDR(dma->paddr));
	IWN_WRITE(sc, IWN_FH_TFBD_CTRL1(IWN_SRVC_DMACHNL),
	    IWN_HIADDR(dma->paddr) << 28 | size);
	IWN_WRITE(sc, IWN_FH_TXBUF_STATUS(IWN_SRVC_DMACHNL),
	    IWN_FH_TXBUF_STATUS_TBNUM(1) |
	    IWN_FH_TXBUF_STATUS_TBIDX(1) |
	    IWN_FH_TXBUF_STATUS_TFBD_VALID);

	/* Kick Flow Handler to start DMA transfer. */
	IWN_WRITE(sc, IWN_FH_TX_CONFIG(IWN_SRVC_DMACHNL),
	    IWN_FH_TX_CONFIG_DMA_ENA | IWN_FH_TX_CONFIG_CIRQ_HOST_ENDTFD);

	iwn_nic_unlock(sc);

	/* Wait at most five seconds for FH DMA transfer to complete. */
	clk = ddi_get_lbolt() + drv_usectohz(5000000);
	while ((sc->sc_flags & IWN_FLAG_FW_DMA) == 0) {
		if (cv_timedwait(&sc->sc_fhdma_cv, &sc->sc_mtx, clk) < 0)
			return (IWN_FAIL);
	}
	sc->sc_flags &= ~IWN_FLAG_FW_DMA;

	return (IWN_SUCCESS);
}

static int
iwn5000_load_firmware(struct iwn_softc *sc)
{
	struct iwn_fw_part *fw;
	int error;

	/* Load the initialization firmware on first boot only. */
	fw = (sc->sc_flags & IWN_FLAG_CALIB_DONE) ?
	    &sc->fw.main : &sc->fw.init;

	error = iwn5000_load_firmware_section(sc, IWN_FW_TEXT_BASE,
	    fw->text, fw->textsz);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not load firmware %s section", ".text");
		return error;
	}
	error = iwn5000_load_firmware_section(sc, IWN_FW_DATA_BASE,
	    fw->data, fw->datasz);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not load firmware %s section", ".data");
		return error;
	}

	/* Now press "execute". */
	IWN_WRITE(sc, IWN_RESET, 0);
	return 0;
}

/*
 * Extract text and data sections from a legacy firmware image.
 */
static int
iwn_read_firmware_leg(struct iwn_softc *sc, struct iwn_fw_info *fw)
{
	_NOTE(ARGUNUSED(sc));
	const uint32_t *ptr;
	size_t hdrlen = 24;
	uint32_t rev;

	/*LINTED: E_PTR_BAD_CAST_ALIGN*/
	ptr = (const uint32_t *)fw->data;
	rev = le32toh(*ptr++);

	/* Check firmware API version. */
	if (IWN_FW_API(rev) <= 1) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!bad firmware, need API version >=2");
		return EINVAL;
	}
	if (IWN_FW_API(rev) >= 3) {
		/* Skip build number (version 2 header). */
		hdrlen += 4;
		ptr++;
	}
	if (fw->size < hdrlen) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!firmware too short: %lld bytes", (longlong_t)fw->size);
		return EINVAL;
	}
	fw->main.textsz = le32toh(*ptr++);
	fw->main.datasz = le32toh(*ptr++);
	fw->init.textsz = le32toh(*ptr++);
	fw->init.datasz = le32toh(*ptr++);
	fw->boot.textsz = le32toh(*ptr++);

	/* Check that all firmware sections fit. */
	if (fw->size < hdrlen + fw->main.textsz + fw->main.datasz +
	    fw->init.textsz + fw->init.datasz + fw->boot.textsz) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!firmware too short: %lld bytes", (longlong_t)fw->size);
		return EINVAL;
	}

	/* Get pointers to firmware sections. */
	fw->main.text = (const uint8_t *)ptr;
	fw->main.data = fw->main.text + fw->main.textsz;
	fw->init.text = fw->main.data + fw->main.datasz;
	fw->init.data = fw->init.text + fw->init.textsz;
	fw->boot.text = fw->init.data + fw->init.datasz;
	return 0;
}

/*
 * Extract text and data sections from a TLV firmware image.
 */
static int
iwn_read_firmware_tlv(struct iwn_softc *sc, struct iwn_fw_info *fw,
    uint16_t alt)
{
	_NOTE(ARGUNUSED(sc));
	const struct iwn_fw_tlv_hdr *hdr;
	const struct iwn_fw_tlv *tlv;
	const uint8_t *ptr, *end;
	uint64_t altmask;
	uint32_t len;

	if (fw->size < sizeof (*hdr)) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!firmware too short: %lld bytes", (longlong_t)fw->size);
		return EINVAL;
	}
	hdr = (const struct iwn_fw_tlv_hdr *)fw->data;
	if (hdr->signature != htole32(IWN_FW_SIGNATURE)) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!bad firmware signature 0x%08x", le32toh(hdr->signature));
		return EINVAL;
	}

	/*
	 * Select the closest supported alternative that is less than
	 * or equal to the specified one.
	 */
	altmask = le64toh(hdr->altmask);
	while (alt > 0 && !(altmask & (1ULL << alt)))
		alt--;	/* Downgrade. */
	IWN_DBG("using alternative %d", alt);

	ptr = (const uint8_t *)(hdr + 1);
	end = (const uint8_t *)(fw->data + fw->size);

	/* Parse type-length-value fields. */
	while (ptr + sizeof (*tlv) <= end) {
		tlv = (const struct iwn_fw_tlv *)ptr;
		len = le32toh(tlv->len);

		ptr += sizeof (*tlv);
		if (ptr + len > end) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!firmware too short: %lld bytes",
			    (longlong_t)fw->size);
			return EINVAL;
		}
		/* Skip other alternatives. */
		if (tlv->alt != 0 && le16toh(tlv->alt) != alt) {
			IWN_DBG("skipping other alternative");
			goto next;
		}

		switch (le16toh(tlv->type)) {
		case IWN_FW_TLV_MAIN_TEXT:
			fw->main.text = ptr;
			fw->main.textsz = len;
			break;
		case IWN_FW_TLV_MAIN_DATA:
			fw->main.data = ptr;
			fw->main.datasz = len;
			break;
		case IWN_FW_TLV_INIT_TEXT:
			fw->init.text = ptr;
			fw->init.textsz = len;
			break;
		case IWN_FW_TLV_INIT_DATA:
			fw->init.data = ptr;
			fw->init.datasz = len;
			break;
		case IWN_FW_TLV_BOOT_TEXT:
			fw->boot.text = ptr;
			fw->boot.textsz = len;
			break;
		case IWN_FW_TLV_ENH_SENS:
			if (len != 0) {
				dev_err(sc->sc_dip, CE_WARN,
				    "!TLV type %d has invalid size %u",
				    le16toh(tlv->type), len);
				goto next;
			}
			sc->sc_flags |= IWN_FLAG_ENH_SENS;
			break;
		case IWN_FW_TLV_PHY_CALIB:
			if (len != sizeof(uint32_t)) {
				dev_err(sc->sc_dip, CE_WARN,
				    "!TLV type %d has invalid size %u",
				    le16toh(tlv->type), len);
				goto next;
			}
			if (le32toh(*ptr) <= IWN5000_PHY_CALIB_MAX) {
				sc->reset_noise_gain = le32toh(*ptr);
				sc->noise_gain = le32toh(*ptr) + 1;
			}
			break;
		case IWN_FW_TLV_FLAGS:
			if (len < sizeof(uint32_t))
				break;
			if (len % sizeof(uint32_t))
				break;
			sc->tlv_feature_flags = le32toh(*ptr);
			IWN_DBG("feature: 0x%08x", sc->tlv_feature_flags);
			break;
		default:
			IWN_DBG("TLV type %d not handled", le16toh(tlv->type));
			break;
		}
 next:		/* TLV fields are 32-bit aligned. */
		ptr += (len + 3) & ~3;
	}
	return 0;
}

static int
iwn_read_firmware(struct iwn_softc *sc)
{
	struct iwn_fw_info *fw = &sc->fw;
	firmware_handle_t fwh;
	int error;

	/*
	 * Some PHY calibration commands are firmware-dependent; these
	 * are the default values that will be overridden if
	 * necessary.
	 */
	sc->reset_noise_gain = IWN5000_PHY_CALIB_RESET_NOISE_GAIN;
	sc->noise_gain = IWN5000_PHY_CALIB_NOISE_GAIN;

	/* Initialize for error returns */
	fw->data = NULL;
	fw->size = 0;

	/* Open firmware image. */
	if ((error = firmware_open("iwn", sc->fwname, &fwh)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not get firmware handle %s", sc->fwname);
		return error;
	}
	fw->size = firmware_get_size(fwh);
	if (fw->size < sizeof (uint32_t)) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!firmware too short: %lld bytes", (longlong_t)fw->size);
		(void) firmware_close(fwh);
		return EINVAL;
	}

	/* Read the firmware. */
	fw->data = kmem_alloc(fw->size, KM_SLEEP);
	error = firmware_read(fwh, 0, fw->data, fw->size);
	(void) firmware_close(fwh);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not read firmware %s", sc->fwname);
		goto out;
	}

	/* Retrieve text and data sections. */
	/*LINTED: E_PTR_BAD_CAST_ALIGN*/
	if (*(const uint32_t *)fw->data != 0)	/* Legacy image. */
		error = iwn_read_firmware_leg(sc, fw);
	else
		error = iwn_read_firmware_tlv(sc, fw, 1);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not read firmware sections");
		goto out;
	}

	/* Make sure text and data sections fit in hardware memory. */
	if (fw->main.textsz > sc->fw_text_maxsz ||
	    fw->main.datasz > sc->fw_data_maxsz ||
	    fw->init.textsz > sc->fw_text_maxsz ||
	    fw->init.datasz > sc->fw_data_maxsz ||
	    fw->boot.textsz > IWN_FW_BOOT_TEXT_MAXSZ ||
	    (fw->boot.textsz & 3) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!firmware sections too large");
		goto out;
	}

	/* We can proceed with loading the firmware. */
	return 0;
out:
	kmem_free(fw->data, fw->size);
	fw->data = NULL;
	fw->size = 0;
	return error ? error : EINVAL;
}

static int
iwn_clock_wait(struct iwn_softc *sc)
{
	int ntries;

	/* Set "initialization complete" bit. */
	IWN_SETBITS(sc, IWN_GP_CNTRL, IWN_GP_CNTRL_INIT_DONE);

	/* Wait for clock stabilization. */
	for (ntries = 0; ntries < 2500; ntries++) {
		if (IWN_READ(sc, IWN_GP_CNTRL) & IWN_GP_CNTRL_MAC_CLOCK_READY)
			return 0;
		DELAY(10);
	}
	dev_err(sc->sc_dip, CE_WARN,
	    "!timeout waiting for clock stabilization");
	return ETIMEDOUT;
}

static int
iwn_apm_init(struct iwn_softc *sc)
{
	uint32_t reg;
	int error;

	/* Disable L0s exit timer (NMI bug workaround). */
	IWN_SETBITS(sc, IWN_GIO_CHICKEN, IWN_GIO_CHICKEN_DIS_L0S_TIMER);
	/* Don't wait for ICH L0s (ICH bug workaround). */
	IWN_SETBITS(sc, IWN_GIO_CHICKEN, IWN_GIO_CHICKEN_L1A_NO_L0S_RX);

	/* Set FH wait threshold to max (HW bug under stress workaround). */
	IWN_SETBITS(sc, IWN_DBG_HPET_MEM, 0xffff0000);

	/* Enable HAP INTA to move adapter from L1a to L0s. */
	IWN_SETBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_HAP_WAKE_L1A);

	/* Retrieve PCIe Active State Power Management (ASPM). */
	reg = pci_config_get32(sc->sc_pcih,
	    sc->sc_cap_off + PCIE_LINKCTL);
	/* Workaround for HW instability in PCIe L0->L0s->L1 transition. */
	if (reg & PCIE_LINKCTL_ASPM_CTL_L1)	/* L1 Entry enabled. */
		IWN_SETBITS(sc, IWN_GIO, IWN_GIO_L0S_ENA);
	else
		IWN_CLRBITS(sc, IWN_GIO, IWN_GIO_L0S_ENA);

	if (sc->hw_type != IWN_HW_REV_TYPE_4965 &&
	    sc->hw_type <= IWN_HW_REV_TYPE_1000)
		IWN_SETBITS(sc, IWN_ANA_PLL, IWN_ANA_PLL_INIT);

	/* Wait for clock stabilization before accessing prph. */
	if ((error = iwn_clock_wait(sc)) != 0)
		return error;

	if ((error = iwn_nic_lock(sc)) != 0)
		return error;
	if (sc->hw_type == IWN_HW_REV_TYPE_4965) {
		/* Enable DMA and BSM (Bootstrap State Machine). */
		iwn_prph_write(sc, IWN_APMG_CLK_EN,
		    IWN_APMG_CLK_CTRL_DMA_CLK_RQT |
		    IWN_APMG_CLK_CTRL_BSM_CLK_RQT);
	} else {
		/* Enable DMA. */
		iwn_prph_write(sc, IWN_APMG_CLK_EN,
		    IWN_APMG_CLK_CTRL_DMA_CLK_RQT);
	}
	DELAY(20);
	/* Disable L1-Active. */
	iwn_prph_setbits(sc, IWN_APMG_PCI_STT, IWN_APMG_PCI_STT_L1A_DIS);
	iwn_nic_unlock(sc);

	return 0;
}

static void
iwn_apm_stop_master(struct iwn_softc *sc)
{
	int ntries;

	/* Stop busmaster DMA activity. */
	IWN_SETBITS(sc, IWN_RESET, IWN_RESET_STOP_MASTER);
	for (ntries = 0; ntries < 100; ntries++) {
		if (IWN_READ(sc, IWN_RESET) & IWN_RESET_MASTER_DISABLED)
			return;
		DELAY(10);
	}
	dev_err(sc->sc_dip, CE_WARN,
	    "!timeout waiting for master");
}

static void
iwn_apm_stop(struct iwn_softc *sc)
{
	iwn_apm_stop_master(sc);

	/* Reset the entire device. */
	IWN_SETBITS(sc, IWN_RESET, IWN_RESET_SW);
	DELAY(10);
	/* Clear "initialization complete" bit. */
	IWN_CLRBITS(sc, IWN_GP_CNTRL, IWN_GP_CNTRL_INIT_DONE);
}

static int
iwn4965_nic_config(struct iwn_softc *sc)
{
	if (IWN_RFCFG_TYPE(sc->rfcfg) == 1) {
		/*
		 * I don't believe this to be correct but this is what the
		 * vendor driver is doing. Probably the bits should not be
		 * shifted in IWN_RFCFG_*.
		 */
		IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
		    IWN_RFCFG_TYPE(sc->rfcfg) |
		    IWN_RFCFG_STEP(sc->rfcfg) |
		    IWN_RFCFG_DASH(sc->rfcfg));
	}
	IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
	    IWN_HW_IF_CONFIG_RADIO_SI | IWN_HW_IF_CONFIG_MAC_SI);
	return 0;
}

static int
iwn5000_nic_config(struct iwn_softc *sc)
{
	uint32_t tmp;
	int error;

	if (IWN_RFCFG_TYPE(sc->rfcfg) < 3) {
		IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
		    IWN_RFCFG_TYPE(sc->rfcfg) |
		    IWN_RFCFG_STEP(sc->rfcfg) |
		    IWN_RFCFG_DASH(sc->rfcfg));
	}
	IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
	    IWN_HW_IF_CONFIG_RADIO_SI | IWN_HW_IF_CONFIG_MAC_SI);

	if ((error = iwn_nic_lock(sc)) != 0)
		return error;
	iwn_prph_setbits(sc, IWN_APMG_PS, IWN_APMG_PS_EARLY_PWROFF_DIS);

	if (sc->hw_type == IWN_HW_REV_TYPE_1000) {
		/*
		 * Select first Switching Voltage Regulator (1.32V) to
		 * solve a stability issue related to noisy DC2DC line
		 * in the silicon of 1000 Series.
		 */
		tmp = iwn_prph_read(sc, IWN_APMG_DIGITAL_SVR);
		tmp &= ~IWN_APMG_DIGITAL_SVR_VOLTAGE_MASK;
		tmp |= IWN_APMG_DIGITAL_SVR_VOLTAGE_1_32;
		iwn_prph_write(sc, IWN_APMG_DIGITAL_SVR, tmp);
	}
	iwn_nic_unlock(sc);

	if (sc->sc_flags & IWN_FLAG_INTERNAL_PA) {
		/* Use internal power amplifier only. */
		IWN_WRITE(sc, IWN_GP_DRIVER, IWN_GP_DRIVER_RADIO_2X2_IPA);
	}
	if ((sc->hw_type == IWN_HW_REV_TYPE_6050 ||
		sc->hw_type == IWN_HW_REV_TYPE_6005) && sc->calib_ver >= 6) {
		/* Indicate that ROM calibration version is >=6. */
		IWN_SETBITS(sc, IWN_GP_DRIVER, IWN_GP_DRIVER_CALIB_VER6);
	}
	if (sc->hw_type == IWN_HW_REV_TYPE_6005)
		IWN_SETBITS(sc, IWN_GP_DRIVER, IWN_GP_DRIVER_6050_1X2);
	if (sc->hw_type == IWN_HW_REV_TYPE_2030 ||
	    sc->hw_type == IWN_HW_REV_TYPE_2000 ||
	    sc->hw_type == IWN_HW_REV_TYPE_135  ||
	    sc->hw_type == IWN_HW_REV_TYPE_105)
		IWN_SETBITS(sc, IWN_GP_DRIVER, IWN_GP_DRIVER_RADIO_IQ_INVERT);
	return 0;
}

/*
 * Take NIC ownership over Intel Active Management Technology (AMT).
 */
static int
iwn_hw_prepare(struct iwn_softc *sc)
{
	int ntries;

	/* Check if hardware is ready. */
	IWN_SETBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_NIC_READY);
	for (ntries = 0; ntries < 5; ntries++) {
		if (IWN_READ(sc, IWN_HW_IF_CONFIG) &
		    IWN_HW_IF_CONFIG_NIC_READY)
			return 0;
		DELAY(10);
	}

	/* Hardware not ready, force into ready state. */
	IWN_SETBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_PREPARE);
	for (ntries = 0; ntries < 15000; ntries++) {
		if (!(IWN_READ(sc, IWN_HW_IF_CONFIG) &
		    IWN_HW_IF_CONFIG_PREPARE_DONE))
			break;
		DELAY(10);
	}
	if (ntries == 15000)
		return ETIMEDOUT;

	/* Hardware should be ready now. */
	IWN_SETBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_NIC_READY);
	for (ntries = 0; ntries < 5; ntries++) {
		if (IWN_READ(sc, IWN_HW_IF_CONFIG) &
		    IWN_HW_IF_CONFIG_NIC_READY)
			return 0;
		DELAY(10);
	}
	return ETIMEDOUT;
}

static int
iwn_hw_init(struct iwn_softc *sc)
{
	struct iwn_ops *ops = &sc->ops;
	int error, chnl, qid;
	clock_t clk;
	uint32_t rx_config;

	ASSERT(mutex_owned(&sc->sc_mtx));

	/* Clear pending interrupts. */
	IWN_WRITE(sc, IWN_INT, 0xffffffff);

	if ((error = iwn_apm_init(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not power ON adapter");
		return error;
	}

	/* Select VMAIN power source. */
	if ((error = iwn_nic_lock(sc)) != 0)
		return error;
	iwn_prph_clrbits(sc, IWN_APMG_PS, IWN_APMG_PS_PWR_SRC_MASK);
	iwn_nic_unlock(sc);

	/* Perform adapter-specific initialization. */
	if ((error = ops->nic_config(sc)) != 0)
		return error;

	/* Initialize RX ring. */
	if ((error = iwn_nic_lock(sc)) != 0)
		return error;
	IWN_WRITE(sc, IWN_FH_RX_CONFIG, 0);
	IWN_WRITE(sc, IWN_FH_RX_WPTR, 0);
	/* Set physical address of RX ring (256-byte aligned). */
	IWN_WRITE(sc, IWN_FH_RX_BASE, sc->rxq.desc_dma.paddr >> 8);
	/* Set physical address of RX status (16-byte aligned). */
	IWN_WRITE(sc, IWN_FH_STATUS_WPTR, sc->rxq.stat_dma.paddr >> 4);
	/* Enable RX. */
	rx_config =
	    IWN_FH_RX_CONFIG_ENA	   |
#if IWN_RBUF_SIZE == 8192
	    IWN_FH_RX_CONFIG_RB_SIZE_8K    |
#endif
	    IWN_FH_RX_CONFIG_IGN_RXF_EMPTY |	/* HW bug workaround */
	    IWN_FH_RX_CONFIG_IRQ_DST_HOST  |
	    IWN_FH_RX_CONFIG_SINGLE_FRAME  |
	    IWN_FH_RX_CONFIG_RB_TIMEOUT(0) |
	    IWN_FH_RX_CONFIG_NRBD(IWN_RX_RING_COUNT_LOG);
	IWN_WRITE(sc, IWN_FH_RX_CONFIG, rx_config);
	iwn_nic_unlock(sc);
	IWN_WRITE(sc, IWN_FH_RX_WPTR, (IWN_RX_RING_COUNT - 1) & ~7);

	if ((error = iwn_nic_lock(sc)) != 0)
		return error;

	/* Initialize TX scheduler. */
	iwn_prph_write(sc, sc->sched_txfact_addr, 0);

	/* Set physical address of "keep warm" page (16-byte aligned). */
	IWN_WRITE(sc, IWN_FH_KW_ADDR, sc->kw_dma.paddr >> 4);

	/* Initialize TX rings. */
	for (qid = 0; qid < sc->ntxqs; qid++) {
		struct iwn_tx_ring *txq = &sc->txq[qid];

		/* Set physical address of TX ring (256-byte aligned). */
		IWN_WRITE(sc, IWN_FH_CBBC_QUEUE(qid),
		    txq->desc_dma.paddr >> 8);
	}
	iwn_nic_unlock(sc);

	/* Enable DMA channels. */
	for (chnl = 0; chnl < sc->ndmachnls; chnl++) {
		IWN_WRITE(sc, IWN_FH_TX_CONFIG(chnl),
		    IWN_FH_TX_CONFIG_DMA_ENA |
		    IWN_FH_TX_CONFIG_DMA_CREDIT_ENA);
	}

	/* Clear "radio off" and "commands blocked" bits. */
	IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_RFKILL);
	IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_CMD_BLOCKED);

	/* Clear pending interrupts. */
	IWN_WRITE(sc, IWN_INT, 0xffffffff);
	/* Enable interrupt coalescing. */
	IWN_WRITE(sc, IWN_INT_COALESCING, 512 / 32);
	/* Enable interrupts. */
	IWN_WRITE(sc, IWN_INT_MASK, sc->int_mask);

	/* _Really_ make sure "radio off" bit is cleared! */
	IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_RFKILL);
	IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_RFKILL);

	/* Enable shadow registers. */
	if (sc->hw_type >= IWN_HW_REV_TYPE_6000)
		IWN_SETBITS(sc, IWN_SHADOW_REG_CTRL, 0x800fffff);

	if ((error = ops->load_firmware(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!could not load firmware");
		return error;
	}
	/* Wait at most one second for firmware alive notification. */
	clk = ddi_get_lbolt() + drv_usectohz(1000000);
	while ((sc->sc_flags & IWN_FLAG_FW_ALIVE) == 0) {
		if (cv_timedwait(&sc->sc_alive_cv, &sc->sc_mtx, clk) < 0) {
			dev_err(sc->sc_dip, CE_WARN,
			    "!timeout waiting for adapter to initialize");
			return (IWN_FAIL);
		}
	}
	/* Do post-firmware initialization. */
	return ops->post_alive(sc);
}

static void
iwn_hw_stop(struct iwn_softc *sc, boolean_t lock)
{
	int chnl, qid, ntries;

	if (lock) {
		mutex_enter(&sc->sc_mtx);
	}

	IWN_WRITE(sc, IWN_RESET, IWN_RESET_NEVO);

	/* Disable interrupts. */
	IWN_WRITE(sc, IWN_INT_MASK, 0);
	IWN_WRITE(sc, IWN_INT, 0xffffffff);
	IWN_WRITE(sc, IWN_FH_INT, 0xffffffff);
	sc->sc_flags &= ~IWN_FLAG_USE_ICT;

	/* Make sure we no longer hold the NIC lock. */
	iwn_nic_unlock(sc);

	/* Stop TX scheduler. */
	iwn_prph_write(sc, sc->sched_txfact_addr, 0);

	/* Stop all DMA channels. */
	if (iwn_nic_lock(sc) == 0) {
		for (chnl = 0; chnl < sc->ndmachnls; chnl++) {
			IWN_WRITE(sc, IWN_FH_TX_CONFIG(chnl), 0);
			for (ntries = 0; ntries < 200; ntries++) {
				if (IWN_READ(sc, IWN_FH_TX_STATUS) &
				    IWN_FH_TX_STATUS_IDLE(chnl))
					break;
				DELAY(10);
			}
		}
		iwn_nic_unlock(sc);
	}

	/* Stop RX ring. */
	iwn_reset_rx_ring(sc, &sc->rxq);

	/* Reset all TX rings. */
	for (qid = 0; qid < sc->ntxqs; qid++)
		iwn_reset_tx_ring(sc, &sc->txq[qid]);

	if (iwn_nic_lock(sc) == 0) {
		iwn_prph_write(sc, IWN_APMG_CLK_DIS,
		    IWN_APMG_CLK_CTRL_DMA_CLK_RQT);
		iwn_nic_unlock(sc);
	}
	DELAY(5);
	/* Power OFF adapter. */
	iwn_apm_stop(sc);

	sc->sc_flags &= ~(IWN_FLAG_HW_INITED | IWN_FLAG_FW_ALIVE);

	if (lock) {
		mutex_exit(&sc->sc_mtx);
	}
}

static int
iwn_init(struct iwn_softc *sc)
{
	int error;

	mutex_enter(&sc->sc_mtx);
	if (sc->sc_flags & IWN_FLAG_HW_INITED)
		goto out;
	if ((error = iwn_hw_prepare(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!hardware not ready");
		goto fail;
	}

	/* Check that the radio is not disabled by hardware switch. */
	if (!(IWN_READ(sc, IWN_GP_CNTRL) & IWN_GP_CNTRL_RFKILL)) {
		dev_err(sc->sc_dip, CE_WARN,
		    "!radio is disabled by hardware switch");
		error = EPERM;	/* :-) */
		goto fail;
	}

	/* Read firmware images from the filesystem. */
	if ((error = iwn_read_firmware(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!could not read firmware");
		goto fail;
	}

	/* Initialize interrupt mask to default value. */
	sc->int_mask = IWN_INT_MASK_DEF;
	sc->sc_flags &= ~IWN_FLAG_USE_ICT;

	/* Initialize hardware and upload firmware. */
	ASSERT(sc->fw.data != NULL && sc->fw.size > 0);
	error = iwn_hw_init(sc);
	if (error != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!could not initialize hardware");
		goto fail;
	}

	/* Configure adapter now that it is ready. */
	if ((error = iwn_config(sc)) != 0) {
		dev_err(sc->sc_dip, CE_WARN, "!could not configure device");
		goto fail;
	}

	sc->sc_flags |= IWN_FLAG_HW_INITED;
out:
	mutex_exit(&sc->sc_mtx);
	return 0;

fail:
	iwn_hw_stop(sc, B_FALSE);
	mutex_exit(&sc->sc_mtx);
	return error;
}

/*
 * XXX code from usr/src/uts/common/io/net80211/net880211_output.c
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002, 2003 Sam Leffler, Errno Consulting
 * Copyright (c) 2007-2009 Damien Bergamini
 * All rights reserved.
 */

/*
 * Add SSID element to a frame
 */
static uint8_t *
ieee80211_add_ssid(uint8_t *frm, const uint8_t *ssid, uint32_t len)
{
	*frm++ = IEEE80211_ELEMID_SSID;
	*frm++ = (uint8_t)len;
	bcopy(ssid, frm, len);
	return (frm + len);
}

/*
 * Add supported rates information element to a frame.
 */
static uint8_t *
ieee80211_add_rates(uint8_t *frm, const struct ieee80211_rateset *rs)
{
	uint8_t nrates;

	*frm++ = IEEE80211_ELEMID_RATES;
	nrates = rs->ir_nrates;
	if (nrates > IEEE80211_RATE_SIZE)
		nrates = IEEE80211_RATE_SIZE;
	*frm++ = nrates;
	bcopy(rs->ir_rates, frm, nrates);
	return (frm + nrates);
}

/*
 * Add extended supported rates element to a frame, usually for 11g mode
 */
static uint8_t *
ieee80211_add_xrates(uint8_t *frm, const struct ieee80211_rateset *rs)
{
	if (rs->ir_nrates > IEEE80211_RATE_SIZE) {
		uint8_t nrates = rs->ir_nrates - IEEE80211_RATE_SIZE;

		*frm++ = IEEE80211_ELEMID_XRATES;
		*frm++ = nrates;
		bcopy(rs->ir_rates + IEEE80211_RATE_SIZE, frm, nrates);
		frm += nrates;
	}
	return (frm);
}

/*
 * XXX: Hack to set the current channel to the value advertised in beacons or
 * probe responses. Only used during AP detection.
 * XXX: Duplicated from if_iwi.c
 */
static void
iwn_fix_channel(struct iwn_softc *sc, mblk_t *m,
    struct iwn_rx_stat *stat)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_frame *wh;
	uint8_t subtype;
	uint8_t *frm, *efrm;

	wh = (struct ieee80211_frame *)m->b_rptr;

	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_MGT)
		return;

	subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	if (subtype != IEEE80211_FC0_SUBTYPE_BEACON &&
	    subtype != IEEE80211_FC0_SUBTYPE_PROBE_RESP)
		return;

	if (sc->sc_flags & IWN_FLAG_SCANNING_5GHZ) {
		int chan = le16toh(stat->chan);
		if (chan < __arraycount(ic->ic_sup_channels))
			ic->ic_curchan = &ic->ic_sup_channels[chan];
		return;
	}

	frm = (uint8_t *)(wh + 1);
	efrm = (uint8_t *)m->b_wptr;

	frm += 12;      /* skip tstamp, bintval and capinfo fields */
	while (frm < efrm) {
		if (*frm == IEEE80211_ELEMID_DSPARMS)
#if IEEE80211_CHAN_MAX < 255
		if (frm[2] <= IEEE80211_CHAN_MAX)
#endif
			ic->ic_curchan = &ic->ic_sup_channels[frm[2]];

		frm += frm[1] + 2;
	}
}

/*
 * invoked by GLD to start or open NIC
 */
static int
iwn_m_start(void *arg)
{
	struct iwn_softc *sc;
	ieee80211com_t	*ic;
	int err = IWN_FAIL;

	sc = (struct iwn_softc *)arg;
	ASSERT(sc != NULL);
	ic = &sc->sc_ic;

	err = iwn_init(sc);
	if (err != IWN_SUCCESS) {
		/*
		 * If initialization failed because the RF switch is off,
		 * return success anyway to make the 'plumb' succeed.
		 * The iwn_thread() tries to re-init background.
		 */
		if (err == EPERM &&
		    !(IWN_READ(sc, IWN_GP_CNTRL) & IWN_GP_CNTRL_RFKILL)) {
			mutex_enter(&sc->sc_mtx);
			sc->sc_flags |= IWN_FLAG_HW_ERR_RECOVER;
			sc->sc_flags |= IWN_FLAG_RADIO_OFF;
			mutex_exit(&sc->sc_mtx);
			return (IWN_SUCCESS);
		}

		return (err);
	}

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	mutex_enter(&sc->sc_mtx);
	sc->sc_flags |= IWN_FLAG_RUNNING;
	mutex_exit(&sc->sc_mtx);

	return (IWN_SUCCESS);
}

/*
 * invoked by GLD to stop or down NIC
 */
static void
iwn_m_stop(void *arg)
{
	struct iwn_softc *sc;
	ieee80211com_t	*ic;

	sc = (struct iwn_softc *)arg;
	ASSERT(sc != NULL);
	ic = &sc->sc_ic;

	iwn_hw_stop(sc, B_TRUE);

	/*
	 * release buffer for calibration
	 */

	ieee80211_stop_watchdog(ic);
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	mutex_enter(&sc->sc_mtx);
	sc->sc_flags &= ~IWN_FLAG_HW_ERR_RECOVER;
	sc->sc_flags &= ~IWN_FLAG_RATE_AUTO_CTL;

	sc->sc_flags &= ~IWN_FLAG_RUNNING;
	sc->sc_flags &= ~IWN_FLAG_SCANNING;
	mutex_exit(&sc->sc_mtx);
}


/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(iwn_devops, nulldev, nulldev, iwn_attach,
    iwn_detach, nodev, NULL, D_MP, NULL, iwn_quiesce);

static struct modldrv iwn_modldrv = {
	&mod_driverops,
	"Intel WiFi Link 4965 and 1000/5000/6000 series driver",
	&iwn_devops
};

static struct modlinkage iwn_modlinkage = {
	MODREV_1,
	&iwn_modldrv,
	NULL
};

int
_init(void)
{
	int	status;

	status = ddi_soft_state_init(&iwn_state,
	    sizeof (struct iwn_softc), 1);
	if (status != DDI_SUCCESS)
		return (status);

	mac_init_ops(&iwn_devops, "iwn");
	status = mod_install(&iwn_modlinkage);
	if (status != DDI_SUCCESS) {
		mac_fini_ops(&iwn_devops);
		ddi_soft_state_fini(&iwn_state);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&iwn_modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&iwn_devops);
		ddi_soft_state_fini(&iwn_state);
	}

	return (status);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&iwn_modlinkage, mip));
}
