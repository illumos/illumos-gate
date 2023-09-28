/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright(c) 2004
 *	Damien Bergamini <damien.bergamini@free.fr>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>
#include <sys/ethernet.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <sys/note.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/dlpi.h>
#include <sys/mac_provider.h>
#include <net/if.h>
#include <sys/mac_wifi.h>
#include <sys/varargs.h>
#include <sys/policy.h>

#include "ipw2100.h"
#include "ipw2100_impl.h"
#include <inet/wifi_ioctl.h>

/*
 * kCF framework include files
 */
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>

static void   *ipw2100_ssp	= NULL;
static char   ipw2100_ident[]	= IPW2100_DRV_DESC;

/*
 * PIO access attribute for register
 */
static ddi_device_acc_attr_t ipw2100_csr_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t ipw2100_dma_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t ipw2100_dma_attr = {
	DMA_ATTR_V0,
	0x0000000000000000ULL,
	0x00000000ffffffffULL,
	0x00000000ffffffffULL,
	0x0000000000000004ULL,
	0xfff,
	1,
	0x00000000ffffffffULL,
	0x00000000ffffffffULL,
	1,
	1,
	0
};

static const struct ieee80211_rateset ipw2100_rateset_11b = { 4,
	{2, 4, 11, 22}
};

/*
 * For mfthread only
 */
extern pri_t minclsyspri;

/*
 * ipw2100 specific hardware operations
 */
static void	ipw2100_hwconf_get(struct ipw2100_softc *sc);
static int	ipw2100_chip_reset(struct ipw2100_softc *sc);
static void	ipw2100_master_stop(struct ipw2100_softc *sc);
static void	ipw2100_stop(struct ipw2100_softc *sc);
static int	ipw2100_config(struct ipw2100_softc *sc);
static int	ipw2100_cmd(struct ipw2100_softc *sc, uint32_t type,
    void *buf, size_t len);
static int	ipw2100_dma_region_alloc(struct ipw2100_softc *sc,
    struct dma_region *dr, size_t size, uint_t dir, uint_t flags);
static void	ipw2100_dma_region_free(struct dma_region *dr);
static void	ipw2100_tables_init(struct ipw2100_softc *sc);
static void	ipw2100_ring_hwsetup(struct ipw2100_softc *sc);
static int	ipw2100_ring_alloc(struct ipw2100_softc *sc);
static void	ipw2100_ring_free(struct ipw2100_softc *sc);
static void	ipw2100_ring_reset(struct ipw2100_softc *sc);
static int	ipw2100_ring_init(struct ipw2100_softc *sc);

/*
 * GLD specific operations
 */
static int	ipw2100_m_stat(void *arg, uint_t stat, uint64_t *val);
static int	ipw2100_m_start(void *arg);
static void	ipw2100_m_stop(void *arg);
static int	ipw2100_m_unicst(void *arg, const uint8_t *macaddr);
static int	ipw2100_m_multicst(void *arg, boolean_t add, const uint8_t *m);
static int	ipw2100_m_promisc(void *arg, boolean_t on);
static mblk_t  *ipw2100_m_tx(void *arg, mblk_t *mp);
static void	ipw2100_m_ioctl(void *arg, queue_t *wq, mblk_t *mp);
static int	ipw2100_m_setprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, const void *wldp_buf);
static int	ipw2100_m_getprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, void *wldp_buf);
static void	ipw2100_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

/*
 * Interrupt and Data transferring operations
 */
static uint_t	ipw2100_intr(caddr_t arg);
static int	ipw2100_send(struct ieee80211com *ic, mblk_t *mp, uint8_t type);
static void	ipw2100_rcvpkt(struct ipw2100_softc *sc,
    struct ipw2100_status *status, uint8_t *rxbuf);

/*
 * WiFi specific operations
 */
static int	ipw2100_newstate(struct ieee80211com *ic,
    enum ieee80211_state state, int arg);
static void	ipw2100_thread(struct ipw2100_softc *sc);

/*
 * IOCTL Handler
 */
static int	ipw2100_ioctl(struct ipw2100_softc *sc, queue_t *q, mblk_t *m);
static int	ipw2100_getset(struct ipw2100_softc *sc,
    mblk_t *m, uint32_t cmd, boolean_t *need_net80211);
static int	ipw_wificfg_radio(struct ipw2100_softc *sc,
    uint32_t cmd,  wldp_t *outfp);
static int	ipw_wificfg_desrates(wldp_t *outfp);
static int	ipw_wificfg_disassoc(struct ipw2100_softc *sc,
    wldp_t *outfp);

/*
 * Suspend / Resume operations
 */
static int	ipw2100_cpr_suspend(struct ipw2100_softc *sc);
static int	ipw2100_cpr_resume(struct ipw2100_softc *sc);

/*
 * Mac Call Back entries
 */
mac_callbacks_t	ipw2100_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	ipw2100_m_stat,
	ipw2100_m_start,
	ipw2100_m_stop,
	ipw2100_m_promisc,
	ipw2100_m_multicst,
	ipw2100_m_unicst,
	ipw2100_m_tx,
	NULL,
	ipw2100_m_ioctl,
	NULL,
	NULL,
	NULL,
	ipw2100_m_setprop,
	ipw2100_m_getprop,
	ipw2100_m_propinfo
};


/*
 * DEBUG Facility
 */
#define	MAX_MSG (128)
uint32_t ipw2100_debug = 0;
/*
 * supported debug marsks:
 *	| IPW2100_DBG_INIT
 *	| IPW2100_DBG_GLD
 *	| IPW2100_DBG_TABLE
 *	| IPW2100_DBG_SOFTINT
 *	| IPW2100_DBG_CSR
 *	| IPW2100_DBG_INT
 *	| IPW2100_DBG_FW
 *	| IPW2100_DBG_IOCTL
 *	| IPW2100_DBG_HWCAP
 *	| IPW2100_DBG_STATISTIC
 *	| IPW2100_DBG_RING
 *	| IPW2100_DBG_WIFI
 *	| IPW2100_DBG_BRUSSELS
 */

/*
 * global tuning parameters to work around unknown hardware issues
 */
static uint32_t delay_config_stable 	= 100000;	/* 100ms */
static uint32_t delay_fatal_recover	= 100000 * 20;	/* 2s */
static uint32_t delay_aux_thread 	= 100000;	/* 100ms */

void
ipw2100_dbg(dev_info_t *dip, int level, const char *fmt, ...)
{
	va_list	ap;
	char    buf[MAX_MSG];
	int	instance;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (dip) {
		instance = ddi_get_instance(dip);
		cmn_err(level, "%s%d: %s", IPW2100_DRV_NAME, instance, buf);
	} else
		cmn_err(level, "%s: %s", IPW2100_DRV_NAME, buf);
}

/*
 * device operations
 */
int
ipw2100_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct ipw2100_softc	*sc;
	ddi_acc_handle_t	cfgh;
	caddr_t			regs;
	struct ieee80211com	*ic;
	int			instance, err, i;
	char			strbuf[32];
	wifi_data_t		wd = { 0 };
	mac_register_t		*macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(ipw2100_ssp, ddi_get_instance(dip));
		if (sc == NULL) {
			err = DDI_FAILURE;
			goto fail1;
		}
		return (ipw2100_cpr_resume(sc));
	default:
		err = DDI_FAILURE;
		goto fail1;
	}

	instance = ddi_get_instance(dip);
	err = ddi_soft_state_zalloc(ipw2100_ssp, instance);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): unable to allocate soft state\n"));
		goto fail1;
	}
	sc = ddi_get_soft_state(ipw2100_ssp, instance);
	sc->sc_dip = dip;

	/*
	 * Map config spaces register
	 */
	err = ddi_regs_map_setup(dip, IPW2100_PCI_CFG_RNUM, &regs,
	    0, 0, &ipw2100_csr_accattr, &cfgh);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): unable to map spaces regs\n"));
		goto fail2;
	}
	ddi_put8(cfgh, (uint8_t *)(regs + 0x41), 0);
	ddi_regs_map_free(&cfgh);

	/*
	 * Map operating registers
	 */
	err = ddi_regs_map_setup(dip, IPW2100_PCI_CSR_RNUM, &sc->sc_regs,
	    0, 0, &ipw2100_csr_accattr, &sc->sc_ioh);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): unable to map device regs\n"));
		goto fail2;
	}

	/*
	 * Reset the chip
	 */
	err = ipw2100_chip_reset(sc);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): reset failed\n"));
		goto fail3;
	}

	/*
	 * Get the hw conf, including MAC address, then init all rings.
	 */
	ipw2100_hwconf_get(sc);
	err = ipw2100_ring_init(sc);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): "
		    "unable to allocate and initialize rings\n"));
		goto fail3;
	}

	/*
	 * Initialize mutexs and condvars
	 */
	err = ddi_get_iblock_cookie(dip, 0, &sc->sc_iblk);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): ddi_get_iblock_cookie() failed\n"));
		goto fail4;
	}
	/*
	 * interrupt lock
	 */
	mutex_init(&sc->sc_ilock, "interrupt-lock", MUTEX_DRIVER,
	    (void *) sc->sc_iblk);
	cv_init(&sc->sc_fw_cond, "firmware", CV_DRIVER, NULL);
	cv_init(&sc->sc_cmd_cond, "command", CV_DRIVER, NULL);
	/*
	 * tx ring lock
	 */
	mutex_init(&sc->sc_tx_lock, "tx-ring", MUTEX_DRIVER,
	    (void *) sc->sc_iblk);
	cv_init(&sc->sc_tx_cond, "tx-ring", CV_DRIVER, NULL);
	/*
	 * rescheuled lock
	 */
	mutex_init(&sc->sc_resched_lock, "reschedule-lock", MUTEX_DRIVER,
	    (void *) sc->sc_iblk);
	/*
	 * initialize the mfthread
	 */
	mutex_init(&sc->sc_mflock, "function-lock", MUTEX_DRIVER,
	    (void *) sc->sc_iblk);
	cv_init(&sc->sc_mfthread_cv, NULL, CV_DRIVER, NULL);
	sc->sc_mf_thread = NULL;
	sc->sc_mfthread_switch = 0;
	/*
	 * Initialize the wifi part, which will be used by
	 * generic layer
	 */
	ic = &sc->sc_ic;
	ic->ic_phytype  = IEEE80211_T_DS;
	ic->ic_opmode   = IEEE80211_M_STA;
	ic->ic_state    = IEEE80211_S_INIT;
	ic->ic_maxrssi  = 49;
	/*
	 * Future, could use s/w to handle encryption: IEEE80211_C_WEP
	 * and need to add support for IEEE80211_C_IBSS
	 */
	ic->ic_caps = IEEE80211_C_SHPREAMBLE | IEEE80211_C_TXPMGT |
	    IEEE80211_C_PMGT;
	ic->ic_sup_rates[IEEE80211_MODE_11B] = ipw2100_rateset_11b;
	IEEE80211_ADDR_COPY(ic->ic_macaddr, sc->sc_macaddr);
	for (i = 1; i < 16; i++) {
		if (sc->sc_chmask &(1 << i)) {
			/* IEEE80211_CHAN_B */
			ic->ic_sup_channels[i].ich_freq  = ieee80211_ieee2mhz(i,
			    IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK);
			ic->ic_sup_channels[i].ich_flags =
			    IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK;
		}
	}
	ic->ic_ibss_chan = &ic->ic_sup_channels[0];
	ic->ic_xmit = ipw2100_send;
	/*
	 * init Wifi layer
	 */
	ieee80211_attach(ic);

	/*
	 * Override 80211 default routines
	 */
	ieee80211_media_init(ic);
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = ipw2100_newstate;
	/*
	 * initialize default tx key
	 */
	ic->ic_def_txkey = 0;
	/*
	 * Set the Authentication to AUTH_Open only.
	 */
	sc->sc_authmode = IEEE80211_AUTH_OPEN;

	/*
	 * Add the interrupt handler
	 */
	err = ddi_add_intr(dip, 0, &sc->sc_iblk, NULL,
	    ipw2100_intr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): ddi_add_intr() failed\n"));
		goto fail5;
	}

	/*
	 * Initialize pointer to device specific functions
	 */
	wd.wd_secalloc = WIFI_SEC_NONE;
	wd.wd_opmode = ic->ic_opmode;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	macp = mac_alloc(MAC_VERSION);
	if (err != 0) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): mac_alloc() failed\n"));
		goto fail6;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= dip;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &ipw2100_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	/*
	 * Register the macp to mac
	 */
	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): mac_register() failed\n"));
		goto fail6;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    IPW2100_DRV_NAME, instance);
	err = ddi_create_minor_node(dip, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS)
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): ddi_create_minor_node() failed\n"));

	/*
	 * Cache firmware, always return true
	 */
	(void) ipw2100_cache_firmware(sc);

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	/*
	 * create the mf thread to handle the link status,
	 * recovery fatal error, etc.
	 */
	sc->sc_mfthread_switch = 1;
	if (sc->sc_mf_thread == NULL)
		sc->sc_mf_thread = thread_create((caddr_t)NULL, 0,
		    ipw2100_thread, sc, 0, &p0, TS_RUN, minclsyspri);

	return (DDI_SUCCESS);

fail6:
	ddi_remove_intr(dip, 0, sc->sc_iblk);
fail5:
	ieee80211_detach(ic);

	mutex_destroy(&sc->sc_ilock);
	mutex_destroy(&sc->sc_tx_lock);
	mutex_destroy(&sc->sc_mflock);
	mutex_destroy(&sc->sc_resched_lock);
	cv_destroy(&sc->sc_mfthread_cv);
	cv_destroy(&sc->sc_tx_cond);
	cv_destroy(&sc->sc_cmd_cond);
	cv_destroy(&sc->sc_fw_cond);
fail4:
	ipw2100_ring_free(sc);
fail3:
	ddi_regs_map_free(&sc->sc_ioh);
fail2:
	ddi_soft_state_free(ipw2100_ssp, instance);
fail1:
	return (err);
}

int
ipw2100_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct ipw2100_softc	*sc =
	    ddi_get_soft_state(ipw2100_ssp, ddi_get_instance(dip));
	int err;

	ASSERT(sc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (ipw2100_cpr_suspend(sc));
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Destroy the mf_thread
	 */
	mutex_enter(&sc->sc_mflock);
	sc->sc_mfthread_switch = 0;
	while (sc->sc_mf_thread != NULL) {
		if (cv_wait_sig(&sc->sc_mfthread_cv, &sc->sc_mflock) == 0)
			break;
	}
	mutex_exit(&sc->sc_mflock);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	err = mac_unregister(sc->sc_ic.ic_mach);
	if (err != DDI_SUCCESS)
		return (err);

	ddi_remove_intr(dip, 0, sc->sc_iblk);

	/*
	 * destroy the cv
	 */
	mutex_destroy(&sc->sc_ilock);
	mutex_destroy(&sc->sc_tx_lock);
	mutex_destroy(&sc->sc_mflock);
	mutex_destroy(&sc->sc_resched_lock);
	cv_destroy(&sc->sc_mfthread_cv);
	cv_destroy(&sc->sc_tx_cond);
	cv_destroy(&sc->sc_cmd_cond);
	cv_destroy(&sc->sc_fw_cond);

	/*
	 * detach ieee80211
	 */
	ieee80211_detach(&sc->sc_ic);

	(void) ipw2100_free_firmware(sc);
	ipw2100_ring_free(sc);

	ddi_regs_map_free(&sc->sc_ioh);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(ipw2100_ssp, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

int
ipw2100_cpr_suspend(struct ipw2100_softc *sc)
{
	IPW2100_DBG(IPW2100_DBG_INIT, (sc->sc_dip, CE_CONT,
	    "ipw2100_cpr_suspend(): enter\n"));

	/*
	 * Destroy the mf_thread
	 */
	mutex_enter(&sc->sc_mflock);
	sc->sc_mfthread_switch = 0;
	while (sc->sc_mf_thread != NULL) {
		if (cv_wait_sig(&sc->sc_mfthread_cv, &sc->sc_mflock) == 0)
			break;
	}
	mutex_exit(&sc->sc_mflock);

	/*
	 * stop the hardware; this mask all interrupts
	 */
	ipw2100_stop(sc);
	sc->sc_flags &= ~IPW2100_FLAG_RUNNING;
	sc->sc_suspended = 1;

	(void) ipw2100_free_firmware(sc);
	ipw2100_ring_free(sc);

	return (DDI_SUCCESS);
}

int
ipw2100_cpr_resume(struct ipw2100_softc *sc)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	dev_info_t		*dip = sc->sc_dip;
	int			err;

	IPW2100_DBG(IPW2100_DBG_INIT, (sc->sc_dip, CE_CONT,
	    "ipw2100_cpr_resume(): enter\n"));

	/*
	 * Reset the chip
	 */
	err = ipw2100_chip_reset(sc);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): reset failed\n"));
		return (DDI_FAILURE);
	}

	/*
	 * Get the hw conf, including MAC address, then init all rings.
	 */
	/* ipw2100_hwconf_get(sc); */
	err = ipw2100_ring_init(sc);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((dip, CE_WARN,
		    "ipw2100_attach(): "
		    "unable to allocate and initialize rings\n"));
		return (DDI_FAILURE);
	}

	/*
	 * Cache firmware, always return true
	 */
	(void) ipw2100_cache_firmware(sc);

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	/*
	 * create the mf thread to handle the link status,
	 * recovery fatal error, etc.
	 */
	sc->sc_mfthread_switch = 1;
	if (sc->sc_mf_thread == NULL)
		sc->sc_mf_thread = thread_create((caddr_t)NULL, 0,
		    ipw2100_thread, sc, 0, &p0, TS_RUN, minclsyspri);

	/*
	 * enable all interrupts
	 */
	sc->sc_suspended = 0;
	ipw2100_csr_put32(sc, IPW2100_CSR_INTR_MASK, IPW2100_INTR_MASK_ALL);

	/*
	 * initialize ipw2100 hardware
	 */
	(void) ipw2100_init(sc);

	sc->sc_flags |= IPW2100_FLAG_RUNNING;

	return (DDI_SUCCESS);
}

/*
 * quiesce(9E) entry point.
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 * Contributed by Juergen Keil, <jk@tools.de>.
 */
static int
ipw2100_quiesce(dev_info_t *dip)
{
	struct ipw2100_softc	*sc =
	    ddi_get_soft_state(ipw2100_ssp, ddi_get_instance(dip));

	if (sc == NULL)
		return (DDI_FAILURE);

	/*
	 * No more blocking is allowed while we are in the
	 * quiesce(9E) entry point.
	 */
	sc->sc_flags |= IPW2100_FLAG_QUIESCED;

	/*
	 * Disable and mask all interrupts.
	 */
	ipw2100_stop(sc);
	return (DDI_SUCCESS);
}

static void
ipw2100_tables_init(struct ipw2100_softc *sc)
{
	sc->sc_table1_base = ipw2100_csr_get32(sc, IPW2100_CSR_TABLE1_BASE);
	sc->sc_table2_base = ipw2100_csr_get32(sc, IPW2100_CSR_TABLE2_BASE);
}

static void
ipw2100_stop(struct ipw2100_softc *sc)
{
	struct ieee80211com	*ic = &sc->sc_ic;

	ipw2100_master_stop(sc);
	ipw2100_csr_put32(sc, IPW2100_CSR_RST, IPW2100_RST_SW_RESET);
	sc->sc_flags &= ~IPW2100_FLAG_FW_INITED;

	if (!(sc->sc_flags & IPW2100_FLAG_QUIESCED))
		ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
}

static int
ipw2100_config(struct ipw2100_softc *sc)
{
	struct ieee80211com		*ic = &sc->sc_ic;
	struct ipw2100_security		sec;
	struct ipw2100_wep_key		wkey;
	struct ipw2100_scan_options	sopt;
	struct ipw2100_configuration	cfg;
	uint32_t			data;
	int				err, i;

	/*
	 * operation mode
	 */
	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
	case IEEE80211_M_HOSTAP:
		data = LE_32(IPW2100_MODE_BSS);
		break;

	case IEEE80211_M_IBSS:
	case IEEE80211_M_AHDEMO:
		data = LE_32(IPW2100_MODE_IBSS);
		break;
	}

	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting mode to %u\n", LE_32(data)));

	err = ipw2100_cmd(sc, IPW2100_CMD_SET_MODE,
	    &data, sizeof (data));
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * operation channel if IBSS or MONITOR
	 */
	if (ic->ic_opmode == IEEE80211_M_IBSS) {

		data = LE_32(ieee80211_chan2ieee(ic, ic->ic_ibss_chan));

		IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
		    "ipw2100_config(): Setting channel to %u\n", LE_32(data)));

		err = ipw2100_cmd(sc, IPW2100_CMD_SET_CHANNEL,
		    &data, sizeof (data));
		if (err != DDI_SUCCESS)
			return (err);
	}

	/*
	 * set MAC address
	 */
	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting MAC address to "
	    "%02x:%02x:%02x:%02x:%02x:%02x\n",
	    ic->ic_macaddr[0], ic->ic_macaddr[1], ic->ic_macaddr[2],
	    ic->ic_macaddr[3], ic->ic_macaddr[4], ic->ic_macaddr[5]));
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_MAC_ADDRESS, ic->ic_macaddr,
	    IEEE80211_ADDR_LEN);
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * configuration capabilities
	 */
	cfg.flags = IPW2100_CFG_BSS_MASK | IPW2100_CFG_IBSS_MASK |
	    IPW2100_CFG_PREAMBLE_AUTO | IPW2100_CFG_802_1x_ENABLE;
	if (ic->ic_opmode == IEEE80211_M_IBSS)
		cfg.flags |= IPW2100_CFG_IBSS_AUTO_START;
	if (sc->if_flags & IFF_PROMISC)
		cfg.flags |= IPW2100_CFG_PROMISCUOUS;
	cfg.flags	= LE_32(cfg.flags);
	cfg.bss_chan	= LE_32(sc->sc_chmask >> 1);
	cfg.ibss_chan	= LE_32(sc->sc_chmask >> 1);

	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting configuration to 0x%x\n",
	    LE_32(cfg.flags)));

	err = ipw2100_cmd(sc, IPW2100_CMD_SET_CONFIGURATION,
	    &cfg, sizeof (cfg));

	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * set 802.11 Tx rates
	 */
	data = LE_32(0x3);  /* 1, 2 */
	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting 802.11 Tx rates to 0x%x\n",
	    LE_32(data)));
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_BASIC_TX_RATES,
	    &data, sizeof (data));
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * set 802.11b Tx rates
	 */
	data = LE_32(0xf);  /* 1, 2, 5.5, 11 */
	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting 802.11b Tx rates to 0x%x\n",
	    LE_32(data)));
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_TX_RATES, &data, sizeof (data));
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * set power mode
	 */
	data = LE_32(IPW2100_POWER_MODE_CAM);
	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting power mode to %u\n", LE_32(data)));
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_POWER_MODE, &data, sizeof (data));
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * set power index
	 */
	if (ic->ic_opmode == IEEE80211_M_IBSS) {
		data = LE_32(32);
		IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
		    "ipw2100_config(): Setting Tx power index to %u\n",
		    LE_32(data)));
		err = ipw2100_cmd(sc, IPW2100_CMD_SET_TX_POWER_INDEX,
		    &data, sizeof (data));
		if (err != DDI_SUCCESS)
			return (err);
	}

	/*
	 * set RTS threshold
	 */
	ic->ic_rtsthreshold = 2346;
	data = LE_32(ic->ic_rtsthreshold);
	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting RTS threshold to %u\n", LE_32(data)));
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_RTS_THRESHOLD,
	    &data, sizeof (data));
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * set frag threshold
	 */
	ic->ic_fragthreshold = 2346;
	data = LE_32(ic->ic_fragthreshold);
	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting frag threshold to %u\n", LE_32(data)));
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_FRAG_THRESHOLD,
	    &data, sizeof (data));
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * set ESSID
	 */
	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting ESSID to %u, ESSID[0]%c\n",
	    ic->ic_des_esslen, ic->ic_des_essid[0]));
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_ESSID,
	    ic->ic_des_essid, ic->ic_des_esslen);
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * no mandatory BSSID
	 */
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_MANDATORY_BSSID, NULL, 0);
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * set BSSID, if any
	 */
	if (ic->ic_flags & IEEE80211_F_DESBSSID) {
		IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
		    "ipw2100_config(): Setting BSSID to %u\n",
		    IEEE80211_ADDR_LEN));
		err = ipw2100_cmd(sc, IPW2100_CMD_SET_DESIRED_BSSID,
		    ic->ic_des_bssid, IEEE80211_ADDR_LEN);
		if (err != DDI_SUCCESS)
			return (err);
	}

	/*
	 * set security information
	 */
	(void) memset(&sec, 0, sizeof (sec));
	/*
	 * use the value set to ic_bss to retrieve current sharedmode
	 */
	sec.authmode = (ic->ic_bss->in_authmode == WL_SHAREDKEY) ?
	    IPW2100_AUTH_SHARED : IPW2100_AUTH_OPEN;
	sec.ciphers = LE_32(IPW2100_CIPHER_NONE);
	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting authmode to %u\n", sec.authmode));
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_SECURITY_INFORMATION,
	    &sec, sizeof (sec));
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * set WEP if any
	 */
	if (ic->ic_flags & IEEE80211_F_PRIVACY) {
		for (i = 0; i < IEEE80211_WEP_NKID; i++) {
			if (ic->ic_nw_keys[i].wk_keylen == 0)
				continue;
			wkey.idx = (uint8_t)i;
			wkey.len = ic->ic_nw_keys[i].wk_keylen;
			(void) memset(wkey.key, 0, sizeof (wkey.key));
			if (ic->ic_nw_keys[i].wk_keylen)
				(void) memcpy(wkey.key,
				    ic->ic_nw_keys[i].wk_key,
				    ic->ic_nw_keys[i].wk_keylen);
			err = ipw2100_cmd(sc, IPW2100_CMD_SET_WEP_KEY,
			    &wkey, sizeof (wkey));
			if (err != DDI_SUCCESS)
				return (err);
		}
		data = LE_32(ic->ic_def_txkey);
		err = ipw2100_cmd(sc, IPW2100_CMD_SET_WEP_KEY_INDEX,
		    &data, sizeof (data));
		if (err != DDI_SUCCESS)
			return (err);
	}

	/*
	 * turn on WEP
	 */
	data = LE_32((ic->ic_flags & IEEE80211_F_PRIVACY) ? 0x8 : 0);
	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Setting WEP flags to %u\n", LE_32(data)));
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_WEP_FLAGS, &data, sizeof (data));
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * set beacon interval if IBSS or HostAP
	 */
	if (ic->ic_opmode == IEEE80211_M_IBSS ||
	    ic->ic_opmode == IEEE80211_M_HOSTAP) {

		data = LE_32(ic->ic_lintval);
		IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
		    "ipw2100_config(): Setting beacon interval to %u\n",
		    LE_32(data)));
		err = ipw2100_cmd(sc, IPW2100_CMD_SET_BEACON_INTERVAL,
		    &data, sizeof (data));
		if (err != DDI_SUCCESS)
			return (err);
	}

	/*
	 * set scan options
	 */
	sopt.flags = LE_32(0);
	sopt.channels = LE_32(sc->sc_chmask >> 1);
	err = ipw2100_cmd(sc, IPW2100_CMD_SET_SCAN_OPTIONS,
	    &sopt, sizeof (sopt));
	if (err != DDI_SUCCESS)
		return (err);

	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_config(): Enabling adapter\n"));

	return (ipw2100_cmd(sc, IPW2100_CMD_ENABLE, NULL, 0));
}

static int
ipw2100_cmd(struct ipw2100_softc *sc, uint32_t type, void *buf, size_t len)
{
	struct ipw2100_bd	*txbd;
	clock_t			clk;
	uint32_t		idx;

	/*
	 * prepare command buffer
	 */
	sc->sc_cmd->type = LE_32(type);
	sc->sc_cmd->subtype = LE_32(0);
	sc->sc_cmd->seq = LE_32(0);
	/*
	 * copy data if any
	 */
	if (len && buf)
		(void) memcpy(sc->sc_cmd->data, buf, len);
	sc->sc_cmd->len = LE_32(len);

	/*
	 * get host & device descriptor to submit command
	 */
	mutex_enter(&sc->sc_tx_lock);

	IPW2100_DBG(IPW2100_DBG_RING, (sc->sc_dip, CE_CONT,
	    "ipw2100_cmd(): tx-free=%d\n", sc->sc_tx_free));

	/*
	 * command need 1 descriptor
	 */
	while (sc->sc_tx_free < 1)  {
		sc->sc_flags |= IPW2100_FLAG_CMD_WAIT;
		cv_wait(&sc->sc_tx_cond, &sc->sc_tx_lock);
	}
	idx = sc->sc_tx_cur;

	IPW2100_DBG(IPW2100_DBG_RING, (sc->sc_dip, CE_CONT,
	    "ipw2100_cmd(): tx-cur=%d\n", idx));

	sc->sc_done = 0;

	txbd		= &sc->sc_txbd[idx];
	txbd->phyaddr	= LE_32(sc->sc_dma_cmd.dr_pbase);
	txbd->len	= LE_32(sizeof (struct ipw2100_cmd));
	txbd->flags	= IPW2100_BD_FLAG_TX_FRAME_COMMAND
	    | IPW2100_BD_FLAG_TX_LAST_FRAGMENT;
	txbd->nfrag	= 1;
	/*
	 * sync for device
	 */
	(void) ddi_dma_sync(sc->sc_dma_cmd.dr_hnd, 0,
	    sizeof (struct ipw2100_cmd), DDI_DMA_SYNC_FORDEV);
	(void) ddi_dma_sync(sc->sc_dma_txbd.dr_hnd,
	    idx * sizeof (struct ipw2100_bd),
	    sizeof (struct ipw2100_bd), DDI_DMA_SYNC_FORDEV);

	/*
	 * ring move forward
	 */
	sc->sc_tx_cur = RING_FORWARD(sc->sc_tx_cur, 1, IPW2100_NUM_TXBD);
	sc->sc_tx_free--;
	ipw2100_csr_put32(sc, IPW2100_CSR_TX_WRITE_INDEX, sc->sc_tx_cur);
	mutex_exit(&sc->sc_tx_lock);

	/*
	 * wait for command done
	 */
	clk = drv_usectohz(1000000);	/* 1 second */
	mutex_enter(&sc->sc_ilock);
	while (sc->sc_done == 0) {
		/*
		 * pending for the response
		 */
		if (cv_reltimedwait(&sc->sc_cmd_cond, &sc->sc_ilock,
		    clk, TR_CLOCK_TICK) < 0)
			break;
	}
	mutex_exit(&sc->sc_ilock);

	IPW2100_DBG(IPW2100_DBG_RING, (sc->sc_dip, CE_CONT,
	    "ipw2100_cmd(): cmd-done=%s\n", sc->sc_done ? "yes" : "no"));

	if (sc->sc_done == 0)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

int
ipw2100_init(struct ipw2100_softc *sc)
{
	int	err;

	IPW2100_DBG(IPW2100_DBG_INIT, (sc->sc_dip, CE_CONT,
	    "ipw2100_init(): enter\n"));

	/*
	 * no firmware is available, return fail directly
	 */
	if (!(sc->sc_flags & IPW2100_FLAG_FW_CACHED)) {
		IPW2100_WARN((sc->sc_dip, CE_WARN,
		    "ipw2100_init(): no firmware is available\n"));
		return (DDI_FAILURE);
	}

	ipw2100_stop(sc);

	err = ipw2100_chip_reset(sc);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((sc->sc_dip, CE_WARN,
		    "ipw2100_init(): could not reset adapter\n"));
		goto fail;
	}

	/*
	 * load microcode
	 */
	IPW2100_DBG(IPW2100_DBG_INIT, (sc->sc_dip, CE_CONT,
	    "ipw2100_init(): loading microcode\n"));
	err = ipw2100_load_uc(sc);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((sc->sc_dip, CE_WARN,
		    "ipw2100_init(): could not load microcode, try again\n"));
		goto fail;
	}

	ipw2100_master_stop(sc);

	ipw2100_ring_hwsetup(sc);

	/*
	 * load firmware
	 */
	IPW2100_DBG(IPW2100_DBG_INIT, (sc->sc_dip, CE_CONT,
	    "ipw2100_init(): loading firmware\n"));
	err = ipw2100_load_fw(sc);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((sc->sc_dip, CE_WARN,
		    "ipw2100_init(): could not load firmware, try again\n"));
		goto fail;
	}

	/*
	 * initialize tables
	 */
	ipw2100_tables_init(sc);
	ipw2100_table1_put32(sc, IPW2100_INFO_LOCK, 0);

	/*
	 * Hardware will be enabled after configuration
	 */
	err = ipw2100_config(sc);
	if (err != DDI_SUCCESS) {
		IPW2100_WARN((sc->sc_dip, CE_WARN,
		    "ipw2100_init(): device configuration failed\n"));
		goto fail;
	}

	delay(drv_usectohz(delay_config_stable));

	return (DDI_SUCCESS);

fail:
	ipw2100_stop(sc);

	return (err);
}

/*
 * get hardware configurations from EEPROM embedded within chip
 */
static void
ipw2100_hwconf_get(struct ipw2100_softc *sc)
{
	int		i;
	uint16_t	val;

	/*
	 * MAC address
	 */
	i = 0;
	val = ipw2100_rom_get16(sc, IPW2100_ROM_MAC + 0);
	sc->sc_macaddr[i++] = val >> 8;
	sc->sc_macaddr[i++] = val & 0xff;
	val = ipw2100_rom_get16(sc, IPW2100_ROM_MAC + 1);
	sc->sc_macaddr[i++] = val >> 8;
	sc->sc_macaddr[i++] = val & 0xff;
	val = ipw2100_rom_get16(sc, IPW2100_ROM_MAC + 2);
	sc->sc_macaddr[i++] = val >> 8;
	sc->sc_macaddr[i++] = val & 0xff;

	/*
	 * formatted MAC address string
	 */
	(void) snprintf(sc->sc_macstr, sizeof (sc->sc_macstr),
	    "%02x:%02x:%02x:%02x:%02x:%02x",
	    sc->sc_macaddr[0], sc->sc_macaddr[1],
	    sc->sc_macaddr[2], sc->sc_macaddr[3],
	    sc->sc_macaddr[4], sc->sc_macaddr[5]);

	/*
	 * channel mask
	 */
	val = ipw2100_rom_get16(sc, IPW2100_ROM_CHANNEL_LIST);
	if (val == 0)
		val = 0x7ff;
	sc->sc_chmask = val << 1;
	IPW2100_DBG(IPW2100_DBG_HWCAP, (sc->sc_dip, CE_CONT,
	    "ipw2100_hwconf_get(): channel-mask=0x%08x\n", sc->sc_chmask));

	/*
	 * radio switch
	 */
	val = ipw2100_rom_get16(sc, IPW2100_ROM_RADIO);
	if (val & 0x08)
		sc->sc_flags |= IPW2100_FLAG_HAS_RADIO_SWITCH;

	IPW2100_DBG(IPW2100_DBG_HWCAP, (sc->sc_dip, CE_CONT,
	    "ipw2100_hwconf_get(): has-radio-switch=%s(%u)\n",
	    (sc->sc_flags & IPW2100_FLAG_HAS_RADIO_SWITCH)?  "yes" : "no",
	    val));
}

/*
 * all ipw2100 interrupts will be masked by this routine
 */
static void
ipw2100_master_stop(struct ipw2100_softc *sc)
{
	uint32_t	tmp;
	int		ntries;

	/*
	 * disable interrupts
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_INTR_MASK, 0);

	ipw2100_csr_put32(sc, IPW2100_CSR_RST, IPW2100_RST_STOP_MASTER);
	for (ntries = 0; ntries < 50; ntries++) {
		if (ipw2100_csr_get32(sc, IPW2100_CSR_RST)
		    & IPW2100_RST_MASTER_DISABLED)
			break;
		drv_usecwait(10);
	}
	if (ntries == 50 && !(sc->sc_flags & IPW2100_FLAG_QUIESCED))
		IPW2100_WARN((sc->sc_dip, CE_WARN,
		    "ipw2100_master_stop(): timeout when stop master\n"));

	tmp = ipw2100_csr_get32(sc, IPW2100_CSR_RST);
	ipw2100_csr_put32(sc, IPW2100_CSR_RST,
	    tmp | IPW2100_RST_PRINCETON_RESET);

	sc->sc_flags &= ~IPW2100_FLAG_FW_INITED;
}

/*
 * all ipw2100 interrupts will be masked by this routine
 */
static int
ipw2100_chip_reset(struct ipw2100_softc *sc)
{
	int		ntries;
	uint32_t	tmp;

	ipw2100_master_stop(sc);

	/*
	 * move adapter to DO state
	 */
	tmp = ipw2100_csr_get32(sc, IPW2100_CSR_CTL);
	ipw2100_csr_put32(sc, IPW2100_CSR_CTL, tmp | IPW2100_CTL_INIT);

	/*
	 * wait for clock stabilization
	 */
	for (ntries = 0; ntries < 1000; ntries++) {
		if (ipw2100_csr_get32(sc, IPW2100_CSR_CTL)
		    & IPW2100_CTL_CLOCK_READY)
			break;
		drv_usecwait(200);
	}
	if (ntries == 1000)
		return (DDI_FAILURE);

	tmp = ipw2100_csr_get32(sc, IPW2100_CSR_RST);
	ipw2100_csr_put32(sc, IPW2100_CSR_RST, tmp | IPW2100_RST_SW_RESET);

	drv_usecwait(10);

	tmp = ipw2100_csr_get32(sc, IPW2100_CSR_CTL);
	ipw2100_csr_put32(sc, IPW2100_CSR_CTL, tmp | IPW2100_CTL_INIT);

	return (DDI_SUCCESS);
}

/*
 * get the radio status from IPW_CSR_IO, invoked by wificonfig/dladm
 */
int
ipw2100_get_radio(struct ipw2100_softc *sc)
{
	if (ipw2100_csr_get32(sc, IPW2100_CSR_IO) & IPW2100_IO_RADIO_DISABLED)
		return (0);
	else
		return (1);

}
/*
 * This function is used to get the statistic, invoked by wificonfig/dladm
 */
void
ipw2100_get_statistics(struct ipw2100_softc *sc)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	uint32_t		addr, size, i;
	uint32_t		atbl[256], *datatbl;

	datatbl = atbl;

	if (!(sc->sc_flags & IPW2100_FLAG_FW_INITED)) {
		IPW2100_DBG(IPW2100_DBG_STATISTIC, (sc->sc_dip, CE_CONT,
		    "ipw2100_get_statistic(): fw doesn't download yet."));
		return;
	}

	ipw2100_csr_put32(sc, IPW2100_CSR_AUTOINC_ADDR, sc->sc_table1_base);

	size = ipw2100_csr_get32(sc, IPW2100_CSR_AUTOINC_DATA);
	atbl[0] = size;
	for (i = 1, ++datatbl; i < size; i++, datatbl++) {
		addr = ipw2100_csr_get32(sc, IPW2100_CSR_AUTOINC_DATA);
		*datatbl = ipw2100_imem_get32(sc, addr);
	}

	/*
	 * To retrieve the statistic information into proper places. There are
	 * lot of information.
	 */
	IPW2100_DBG(IPW2100_DBG_STATISTIC, (sc->sc_dip, CE_CONT,
	    "ipw2100_get_statistic(): \n"
	    "operating mode = %u\n"
	    "type of authentification= %u\n"
	    "average RSSI= %u\n"
	    "current channel = %d\n",
	    atbl[191], atbl[199], atbl[173], atbl[189]));
	/* WIFI_STAT_TX_FRAGS */
	ic->ic_stats.is_tx_frags = (uint32_t)atbl[2];
	/* WIFI_STAT_MCAST_TX = (all frame - unicast frame) */
	ic->ic_stats.is_tx_mcast = (uint32_t)atbl[2] - (uint32_t)atbl[3];
	/* WIFI_STAT_TX_RETRANS */
	ic->ic_stats.is_tx_retries = (uint32_t)atbl[42];
	/* WIFI_STAT_TX_FAILED */
	ic->ic_stats.is_tx_failed = (uint32_t)atbl[51];
	/* MAC_STAT_OBYTES */
	ic->ic_stats.is_tx_bytes = (uint32_t)atbl[41];
	/* WIFI_STAT_RX_FRAGS */
	ic->ic_stats.is_rx_frags = (uint32_t)atbl[61];
	/* WIFI_STAT_MCAST_RX */
	ic->ic_stats.is_rx_mcast = (uint32_t)atbl[71];
	/* MAC_STAT_IBYTES */
	ic->ic_stats.is_rx_bytes = (uint32_t)atbl[101];
	/* WIFI_STAT_ACK_FAILURE */
	ic->ic_stats.is_ack_failure = (uint32_t)atbl[59];
	/* WIFI_STAT_RTS_SUCCESS */
	ic->ic_stats.is_rts_success = (uint32_t)atbl[22];
}

/*
 * dma region alloc
 */
static int
ipw2100_dma_region_alloc(struct ipw2100_softc *sc,
    struct dma_region *dr, size_t size, uint_t dir, uint_t flags)
{
	dev_info_t	*dip = sc->sc_dip;
	int		err;

	IPW2100_DBG(IPW2100_DBG_DMA, (dip, CE_CONT,
	    "ipw2100_dma_region_alloc() name=%s size=%u\n",
	    dr->dr_name, size));

	err = ddi_dma_alloc_handle(dip, &ipw2100_dma_attr, DDI_DMA_SLEEP, NULL,
	    &dr->dr_hnd);
	if (err != DDI_SUCCESS) {
		IPW2100_DBG(IPW2100_DBG_DMA, (dip, CE_CONT,
		    "ipw2100_dma_region_alloc(): "
		    "ddi_dma_alloc_handle() failed\n"));
		goto fail0;
	}

	err = ddi_dma_mem_alloc(dr->dr_hnd, size, &ipw2100_dma_accattr,
	    flags, DDI_DMA_SLEEP, NULL, &dr->dr_base,
	    &dr->dr_size, &dr->dr_acc);
	if (err != DDI_SUCCESS) {
		IPW2100_DBG(IPW2100_DBG_DMA, (dip, CE_CONT,
		    "ipw2100_dma_region_alloc(): "
		    "ddi_dma_mem_alloc() failed\n"));
		goto fail1;
	}

	err = ddi_dma_addr_bind_handle(dr->dr_hnd, NULL,
	    dr->dr_base, dr->dr_size, dir | flags, DDI_DMA_SLEEP, NULL,
	    &dr->dr_cookie, &dr->dr_ccnt);
	if (err != DDI_DMA_MAPPED) {
		IPW2100_DBG(IPW2100_DBG_DMA, (dip, CE_CONT,
		    "ipw2100_dma_region_alloc(): "
		    "ddi_dma_addr_bind_handle() failed\n"));
		goto fail2;
	}

	if (dr->dr_ccnt != 1) {
		err = DDI_FAILURE;
		goto fail3;
	}
	dr->dr_pbase = dr->dr_cookie.dmac_address;

	IPW2100_DBG(IPW2100_DBG_DMA, (dip, CE_CONT,
	    "ipw2100_dma_region_alloc(): get physical-base=0x%08x\n",
	    dr->dr_pbase));

	return (DDI_SUCCESS);

fail3:
	(void) ddi_dma_unbind_handle(dr->dr_hnd);
fail2:
	ddi_dma_mem_free(&dr->dr_acc);
fail1:
	ddi_dma_free_handle(&dr->dr_hnd);
fail0:
	return (err);
}

static void
ipw2100_dma_region_free(struct dma_region *dr)
{
	(void) ddi_dma_unbind_handle(dr->dr_hnd);
	ddi_dma_mem_free(&dr->dr_acc);
	ddi_dma_free_handle(&dr->dr_hnd);
}

static int
ipw2100_ring_alloc(struct ipw2100_softc *sc)
{
	int	err, i;

	/*
	 * tx ring
	 */
	sc->sc_dma_txbd.dr_name = "ipw2100-tx-ring-bd";
	err = ipw2100_dma_region_alloc(sc, &sc->sc_dma_txbd,
	    IPW2100_TXBD_SIZE, DDI_DMA_WRITE, DDI_DMA_CONSISTENT);
	if (err != DDI_SUCCESS)
		goto fail0;
	/*
	 * tx bufs
	 */
	for (i = 0; i < IPW2100_NUM_TXBUF; i++) {
		sc->sc_dma_txbufs[i].dr_name = "ipw2100-tx-buf";
		err = ipw2100_dma_region_alloc(sc, &sc->sc_dma_txbufs[i],
		    IPW2100_TXBUF_SIZE, DDI_DMA_WRITE, DDI_DMA_STREAMING);
		if (err != DDI_SUCCESS) {
			while (i > 0) {
				i--;
				ipw2100_dma_region_free(&sc->sc_dma_txbufs[i]);
			}
			goto fail1;
		}
	}
	/*
	 * rx ring
	 */
	sc->sc_dma_rxbd.dr_name = "ipw2100-rx-ring-bd";
	err = ipw2100_dma_region_alloc(sc, &sc->sc_dma_rxbd,
	    IPW2100_RXBD_SIZE, DDI_DMA_WRITE, DDI_DMA_CONSISTENT);
	if (err != DDI_SUCCESS)
		goto fail2;
	/*
	 * rx bufs
	 */
	for (i = 0; i < IPW2100_NUM_RXBUF; i++) {
		sc->sc_dma_rxbufs[i].dr_name = "ipw2100-rx-buf";
		err = ipw2100_dma_region_alloc(sc, &sc->sc_dma_rxbufs[i],
		    IPW2100_RXBUF_SIZE, DDI_DMA_READ, DDI_DMA_STREAMING);
		if (err != DDI_SUCCESS) {
			while (i > 0) {
				i--;
				ipw2100_dma_region_free(&sc->sc_dma_rxbufs[i]);
			}
			goto fail3;
		}
	}
	/*
	 * status
	 */
	sc->sc_dma_status.dr_name = "ipw2100-rx-status";
	err = ipw2100_dma_region_alloc(sc, &sc->sc_dma_status,
	    IPW2100_STATUS_SIZE, DDI_DMA_READ, DDI_DMA_CONSISTENT);
	if (err != DDI_SUCCESS)
		goto fail4;
	/*
	 * command
	 */
	sc->sc_dma_cmd.dr_name = "ipw2100-cmd";
	err = ipw2100_dma_region_alloc(sc, &sc->sc_dma_cmd, IPW2100_CMD_SIZE,
	    DDI_DMA_WRITE, DDI_DMA_CONSISTENT);
	if (err != DDI_SUCCESS)
		goto fail5;

	return (DDI_SUCCESS);

fail5:
	ipw2100_dma_region_free(&sc->sc_dma_status);
fail4:
	for (i = 0; i < IPW2100_NUM_RXBUF; i++)
		ipw2100_dma_region_free(&sc->sc_dma_rxbufs[i]);
fail3:
	ipw2100_dma_region_free(&sc->sc_dma_rxbd);
fail2:
	for (i = 0; i < IPW2100_NUM_TXBUF; i++)
		ipw2100_dma_region_free(&sc->sc_dma_txbufs[i]);
fail1:
	ipw2100_dma_region_free(&sc->sc_dma_txbd);
fail0:
	return (err);
}

static void
ipw2100_ring_free(struct ipw2100_softc *sc)
{
	int	i;

	/*
	 * tx ring
	 */
	ipw2100_dma_region_free(&sc->sc_dma_txbd);
	/*
	 * tx buf
	 */
	for (i = 0; i < IPW2100_NUM_TXBUF; i++)
		ipw2100_dma_region_free(&sc->sc_dma_txbufs[i]);
	/*
	 * rx ring
	 */
	ipw2100_dma_region_free(&sc->sc_dma_rxbd);
	/*
	 * rx buf
	 */
	for (i = 0; i < IPW2100_NUM_RXBUF; i++)
		ipw2100_dma_region_free(&sc->sc_dma_rxbufs[i]);
	/*
	 * status
	 */
	ipw2100_dma_region_free(&sc->sc_dma_status);
	/*
	 * command
	 */
	ipw2100_dma_region_free(&sc->sc_dma_cmd);
}

static void
ipw2100_ring_reset(struct ipw2100_softc *sc)
{
	int	i;

	/*
	 * tx ring
	 */
	sc->sc_tx_cur   = 0;
	sc->sc_tx_free  = IPW2100_NUM_TXBD;
	sc->sc_txbd	= (struct ipw2100_bd *)sc->sc_dma_txbd.dr_base;
	for (i = 0; i < IPW2100_NUM_TXBUF; i++)
		sc->sc_txbufs[i] =
		    (struct ipw2100_txb *)sc->sc_dma_txbufs[i].dr_base;
	/*
	 * rx ring
	 */
	sc->sc_rx_cur   = 0;
	sc->sc_rx_free  = IPW2100_NUM_RXBD;
	sc->sc_status   = (struct ipw2100_status *)sc->sc_dma_status.dr_base;
	sc->sc_rxbd	= (struct ipw2100_bd *)sc->sc_dma_rxbd.dr_base;
	for (i = 0; i < IPW2100_NUM_RXBUF; i++) {
		sc->sc_rxbufs[i] =
		    (struct ipw2100_rxb *)sc->sc_dma_rxbufs[i].dr_base;
		/*
		 * initialize Rx buffer descriptors, both host and device
		 */
		sc->sc_rxbd[i].phyaddr  = LE_32(sc->sc_dma_rxbufs[i].dr_pbase);
		sc->sc_rxbd[i].len	= LE_32(sc->sc_dma_rxbufs[i].dr_size);
		sc->sc_rxbd[i].flags	= 0;
		sc->sc_rxbd[i].nfrag	= 1;
	}
	/*
	 * command
	 */
	sc->sc_cmd = (struct ipw2100_cmd *)sc->sc_dma_cmd.dr_base;
}

/*
 * tx, rx rings and command initialization
 */
static int
ipw2100_ring_init(struct ipw2100_softc *sc)
{
	int	err;

	err = ipw2100_ring_alloc(sc);
	if (err != DDI_SUCCESS)
		return (err);

	ipw2100_ring_reset(sc);

	return (DDI_SUCCESS);
}

static void
ipw2100_ring_hwsetup(struct ipw2100_softc *sc)
{
	ipw2100_ring_reset(sc);
	/*
	 * tx ring
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_TX_BD_BASE, sc->sc_dma_txbd.dr_pbase);
	ipw2100_csr_put32(sc, IPW2100_CSR_TX_BD_SIZE, IPW2100_NUM_TXBD);
	/*
	 * no new packet to transmit, tx-rd-index == tx-wr-index
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_TX_READ_INDEX, sc->sc_tx_cur);
	ipw2100_csr_put32(sc, IPW2100_CSR_TX_WRITE_INDEX, sc->sc_tx_cur);
	/*
	 * rx ring
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_RX_BD_BASE, sc->sc_dma_rxbd.dr_pbase);
	ipw2100_csr_put32(sc, IPW2100_CSR_RX_BD_SIZE, IPW2100_NUM_RXBD);
	/*
	 * all rx buffer are empty, rx-rd-index == 0 && rx-wr-index == N-1
	 */
	IPW2100_DBG(IPW2100_DBG_RING, (sc->sc_dip, CE_CONT,
	    "ipw2100_ring_hwsetup(): rx-cur=%u, backward=%u\n",
	    sc->sc_rx_cur, RING_BACKWARD(sc->sc_rx_cur, 1, IPW2100_NUM_RXBD)));
	ipw2100_csr_put32(sc, IPW2100_CSR_RX_READ_INDEX, sc->sc_rx_cur);
	ipw2100_csr_put32(sc, IPW2100_CSR_RX_WRITE_INDEX,
	    RING_BACKWARD(sc->sc_rx_cur, 1, IPW2100_NUM_RXBD));
	/*
	 * status
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_RX_STATUS_BASE,
	    sc->sc_dma_status.dr_pbase);
}

/*
 * ieee80211_new_state() is not be used, since the hardware can handle the
 * state transfer. Here, we just keep the status of the hardware notification
 * result.
 */
/* ARGSUSED */
static int
ipw2100_newstate(struct ieee80211com *ic, enum ieee80211_state state, int arg)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)ic;
	struct ieee80211_node	*in;
	uint8_t			macaddr[IEEE80211_ADDR_LEN];
	uint32_t		len;
	wifi_data_t		wd = { 0 };

	IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
	    "ipw2100_newstate(): %s -> %s\n",
	    ieee80211_state_name[ic->ic_state], ieee80211_state_name[state]));

	switch (state) {
	case IEEE80211_S_RUN:
		/*
		 * we only need to use BSSID as to find the node
		 */
		drv_usecwait(200); /* firmware needs a short delay here */
		len = IEEE80211_ADDR_LEN;
		(void) ipw2100_table2_getbuf(sc, IPW2100_INFO_CURRENT_BSSID,
		    macaddr, &len);

		in = ieee80211_find_node(&ic->ic_scan, macaddr);
		if (in == NULL)
			break;

		(void) ieee80211_sta_join(ic, in);
		ieee80211_node_authorize(in);

		/*
		 * We can send data now; update the fastpath with our
		 * current associated BSSID.
		 */
		if (ic->ic_flags & IEEE80211_F_PRIVACY)
			wd.wd_secalloc = WIFI_SEC_WEP;
		else
			wd.wd_secalloc = WIFI_SEC_NONE;
		wd.wd_opmode = ic->ic_opmode;
		IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);
		(void) mac_pdata_update(ic->ic_mach, &wd, sizeof (wd));

		break;

	case IEEE80211_S_INIT:
	case IEEE80211_S_SCAN:
	case IEEE80211_S_AUTH:
	case IEEE80211_S_ASSOC:
		break;
	}

	/*
	 * notify to update the link
	 */
	if ((ic->ic_state != IEEE80211_S_RUN) && (state == IEEE80211_S_RUN)) {
		/*
		 * previously disconnected and now connected
		 */
		sc->sc_linkstate = LINK_STATE_UP;
		sc->sc_flags |= IPW2100_FLAG_LINK_CHANGE;
	} else if ((ic->ic_state == IEEE80211_S_RUN) &&
	    (state != IEEE80211_S_RUN)) {
		/*
		 * previously connected andd now disconnected
		 */
		sc->sc_linkstate = LINK_STATE_DOWN;
		sc->sc_flags |= IPW2100_FLAG_LINK_CHANGE;
	}

	ic->ic_state = state;
	return (DDI_SUCCESS);
}

/*
 * GLD operations
 */
/* ARGSUSED */
static int
ipw2100_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	ieee80211com_t	*ic = (ieee80211com_t *)arg;
	IPW2100_DBG(IPW2100_DBG_GLD, (((struct ipw2100_softc *)arg)->sc_dip,
	    CE_CONT,
	    "ipw2100_m_stat(): enter\n"));
	/*
	 * some of below statistic data are from hardware, some from net80211
	 */
	switch (stat) {
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
	/*
	 * Get below from hardware statistic, retrieve net80211 value once 1s
	 */
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_TX_FAILED:
	case WIFI_STAT_TX_RETRANS:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	/*
	 * Get blow information from net80211
	 */
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_RX_DUPS:
	case WIFI_STAT_FCS_ERRORS:
	case WIFI_STAT_WEP_ERRORS:
		return (ieee80211_stat(ic, stat, val));
	/*
	 * need be supported in the future
	 */
	case MAC_STAT_IFSPEED:
	case MAC_STAT_NOXMTBUF:
	case MAC_STAT_IERRORS:
	case MAC_STAT_OERRORS:
	default:
		return (ENOTSUP);
	}
	return (0);
}

/* ARGSUSED */
static int
ipw2100_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	/* not supported */
	IPW2100_DBG(IPW2100_DBG_GLD, (((struct ipw2100_softc *)arg)->sc_dip,
	    CE_CONT,
	    "ipw2100_m_multicst(): enter\n"));

	return (0);
}

/*
 * This thread function is used to handle the fatal error.
 */
static void
ipw2100_thread(struct ipw2100_softc *sc)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	int32_t			nlstate;
	int			stat_cnt = 0;

	IPW2100_DBG(IPW2100_DBG_SOFTINT, (sc->sc_dip, CE_CONT,
	    "ipw2100_thread(): into ipw2100 thread--> %d\n",
	    sc->sc_linkstate));

	mutex_enter(&sc->sc_mflock);

	while (sc->sc_mfthread_switch) {
		/*
		 * notify the link state
		 */
		if (ic->ic_mach && (sc->sc_flags & IPW2100_FLAG_LINK_CHANGE)) {
			IPW2100_DBG(IPW2100_DBG_SOFTINT, (sc->sc_dip, CE_CONT,
			    "ipw2100_thread(): link status --> %d\n",
			    sc->sc_linkstate));

			sc->sc_flags &= ~IPW2100_FLAG_LINK_CHANGE;
			nlstate = sc->sc_linkstate;

			mutex_exit(&sc->sc_mflock);
			mac_link_update(ic->ic_mach, nlstate);
			mutex_enter(&sc->sc_mflock);
		}

		/*
		 * recovery interrupt fatal error
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & IPW2100_FLAG_HW_ERR_RECOVER)) {

			IPW2100_DBG(IPW2100_DBG_FATAL, (sc->sc_dip, CE_CONT,
			    "try to recover fatal hw error\n"));
			sc->sc_flags &= ~IPW2100_FLAG_HW_ERR_RECOVER;

			mutex_exit(&sc->sc_mflock);
			(void) ipw2100_init(sc); /* Force stat machine */
			delay(drv_usectohz(delay_fatal_recover));
			mutex_enter(&sc->sc_mflock);
		}

		/*
		 * get statistic, the value will be retrieved by m_stat
		 */
		if (stat_cnt == 10) {
			stat_cnt = 0; /* re-start */

			mutex_exit(&sc->sc_mflock);
			ipw2100_get_statistics(sc);
			mutex_enter(&sc->sc_mflock);
		} else
			stat_cnt++; /* until 1s */

		mutex_exit(&sc->sc_mflock);
		delay(drv_usectohz(delay_aux_thread));
		mutex_enter(&sc->sc_mflock);
	}
	sc->sc_mf_thread = NULL;
	cv_broadcast(&sc->sc_mfthread_cv);
	mutex_exit(&sc->sc_mflock);
}

static int
ipw2100_m_start(void *arg)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)arg;

	IPW2100_DBG(IPW2100_DBG_GLD, (sc->sc_dip, CE_CONT,
	    "ipw2100_m_start(): enter\n"));

	/*
	 * initialize ipw2100 hardware
	 */
	(void) ipw2100_init(sc);

	sc->sc_flags |= IPW2100_FLAG_RUNNING;
	/*
	 * fix KCF bug. - workaround, need to fix it in net80211
	 */
	(void) crypto_mech2id(SUN_CKM_RC4);

	return (0);
}

static void
ipw2100_m_stop(void *arg)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)arg;

	IPW2100_DBG(IPW2100_DBG_GLD, (sc->sc_dip, CE_CONT,
	    "ipw2100_m_stop(): enter\n"));

	ipw2100_stop(sc);

	sc->sc_flags &= ~IPW2100_FLAG_RUNNING;
}

static int
ipw2100_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)arg;
	struct ieee80211com	*ic = &sc->sc_ic;
	int			err;

	IPW2100_DBG(IPW2100_DBG_GLD, (sc->sc_dip, CE_CONT,
	    "ipw2100_m_unicst(): enter\n"));

	IPW2100_DBG(IPW2100_DBG_GLD, (sc->sc_dip, CE_CONT,
	    "ipw2100_m_unicst(): GLD setting MAC address to "
	    "%02x:%02x:%02x:%02x:%02x:%02x\n",
	    macaddr[0], macaddr[1], macaddr[2],
	    macaddr[3], macaddr[4], macaddr[5]));

	if (!IEEE80211_ADDR_EQ(ic->ic_macaddr, macaddr)) {
		IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);

		if (sc->sc_flags & IPW2100_FLAG_RUNNING) {
			err = ipw2100_config(sc);
			if (err != DDI_SUCCESS) {
				IPW2100_WARN((sc->sc_dip, CE_WARN,
				    "ipw2100_m_unicst(): "
				    "device configuration failed\n"));
				goto fail;
			}
		}
	}

	return (0);
fail:
	return (EIO);
}

static int
ipw2100_m_promisc(void *arg, boolean_t on)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)arg;
	int recfg, err;

	IPW2100_DBG(IPW2100_DBG_GLD, (sc->sc_dip, CE_CONT,
	    "ipw2100_m_promisc(): enter. "
	    "GLD setting promiscuous mode - %d\n", on));

	recfg = 0;
	if (on)
		if (!(sc->if_flags & IFF_PROMISC)) {
			sc->if_flags |= IFF_PROMISC;
			recfg = 1;
		}
	else
		if (sc->if_flags & IFF_PROMISC) {
			sc->if_flags &= ~IFF_PROMISC;
			recfg = 1;
		}

	if (recfg && (sc->sc_flags & IPW2100_FLAG_RUNNING)) {
		err = ipw2100_config(sc);
		if (err != DDI_SUCCESS) {
			IPW2100_WARN((sc->sc_dip, CE_WARN,
			    "ipw2100_m_promisc(): "
			    "device configuration failed\n"));
			goto fail;
		}
	}

	return (0);
fail:
	return (EIO);
}

static mblk_t *
ipw2100_m_tx(void *arg, mblk_t *mp)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)arg;
	struct ieee80211com	*ic = &sc->sc_ic;
	mblk_t			*next;

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (ic->ic_state != IEEE80211_S_RUN) {
		IPW2100_DBG(IPW2100_DBG_GLD, (sc->sc_dip, CE_CONT,
		    "ipw2100_m_tx(): discard msg, ic_state = %u\n",
		    ic->ic_state));
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (ipw2100_send(ic, mp, IEEE80211_FC0_TYPE_DATA) !=
		    DDI_SUCCESS) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

/* ARGSUSED */
static int
ipw2100_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)ic;
	struct ieee80211_node	*in;
	struct ieee80211_frame	wh, *wh_tmp;
	struct ieee80211_key	*k;
	uint8_t			*hdat;
	mblk_t			*m0, *m;
	size_t			cnt, off;
	struct ipw2100_bd	*txbd[2];
	struct ipw2100_txb	*txbuf;
	struct dma_region	*dr;
	struct ipw2100_hdr	*h;
	uint32_t		idx, bidx;
	int			err;

	ASSERT(mp->b_next == NULL);

	m0 = NULL;
	m = NULL;
	err = DDI_SUCCESS;

	IPW2100_DBG(IPW2100_DBG_GLD, (sc->sc_dip, CE_CONT,
	    "ipw2100_send(): enter\n"));

	if ((type & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA) {
		/*
		 * it is impossible to send non-data 802.11 frame in current
		 * ipw driver. Therefore, drop the package
		 */
		freemsg(mp);
		err = DDI_SUCCESS;
		goto fail0;
	}

	mutex_enter(&sc->sc_tx_lock);

	/*
	 * need 2 descriptors: 1 for SEND cmd parameter header,
	 * and the other for payload, i.e., 802.11 frame including 802.11
	 * frame header
	 */
	if (sc->sc_tx_free < 2) {
		mutex_enter(&sc->sc_resched_lock);
		IPW2100_DBG(IPW2100_DBG_RING, (sc->sc_dip, CE_WARN,
		    "ipw2100_send(): no enough descriptors(%d)\n",
		    sc->sc_tx_free));
		ic->ic_stats.is_tx_nobuf++; /* no enough buffer */
		sc->sc_flags |= IPW2100_FLAG_TX_SCHED;
		err = DDI_FAILURE;
		mutex_exit(&sc->sc_resched_lock);
		goto fail1;
	}
	IPW2100_DBG(IPW2100_DBG_RING, (sc->sc_dip, CE_CONT,
	    "ipw2100_send(): tx-free=%d,tx-curr=%d\n",
	    sc->sc_tx_free, sc->sc_tx_cur));

	wh_tmp = (struct ieee80211_frame *)mp->b_rptr;
	in = ieee80211_find_txnode(ic, wh_tmp->i_addr1);
	if (in == NULL) { /* can not find tx node, drop the package */
		freemsg(mp);
		err = DDI_SUCCESS;
		goto fail1;
	}
	in->in_inact = 0;
	(void) ieee80211_encap(ic, mp, in);
	ieee80211_free_node(in);

	if (wh_tmp->i_fc[1] & IEEE80211_FC1_WEP) {
		/*
		 * it is very bad that ieee80211_crypto_encap can only accept a
		 * single continuous buffer.
		 */
		/*
		 * allocate 32 more bytes is to be compatible with further
		 * ieee802.11i standard.
		 */
		m = allocb(msgdsize(mp) + 32, BPRI_MED);
		if (m == NULL) { /* can not alloc buf, drop this package */
			IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
			    "ipw2100_send(): msg allocation failed\n"));

			freemsg(mp);

			err = DDI_SUCCESS;
			goto fail1;
		}
		off = 0;
		m0 = mp;
		while (m0) {
			cnt = MBLKL(m0);
			if (cnt) {
				(void) memcpy(m->b_rptr + off, m0->b_rptr, cnt);
				off += cnt;
			}
			m0 = m0->b_cont;
		}
		m->b_wptr += off;
		IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
		    "ipw2100_send(): "
		    "Encrypting 802.11 frame started, %d, %d\n",
		    msgdsize(mp), MBLKL(mp)));
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) { /* can not get the key, drop packages */
			IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
			    "ipw2100_send(): "
			    "Encrypting 802.11 frame failed\n"));

			freemsg(mp);
			err = DDI_SUCCESS;
			goto fail2;
		}
		IPW2100_DBG(IPW2100_DBG_WIFI, (sc->sc_dip, CE_CONT,
		    "ipw2100_send(): "
		    "Encrypting 802.11 frame finished, %d, %d, k=0x%08x\n",
		    msgdsize(mp), MBLKL(mp), k->wk_flags));
	}

	/*
	 * header descriptor
	 */
	idx = sc->sc_tx_cur;
	txbd[0]  = &sc->sc_txbd[idx];
	if ((idx & 1) == 0)
		bidx = idx / 2;
	sc->sc_tx_cur = RING_FORWARD(sc->sc_tx_cur, 1, IPW2100_NUM_TXBD);
	sc->sc_tx_free--;

	/*
	 * payload descriptor
	 */
	idx = sc->sc_tx_cur;
	txbd[1]  = &sc->sc_txbd[idx];
	if ((idx & 1) == 0)
		bidx = idx / 2;
	sc->sc_tx_cur = RING_FORWARD(sc->sc_tx_cur, 1, IPW2100_NUM_TXBD);
	sc->sc_tx_free--;

	/*
	 * one buffer, SEND cmd header and payload buffer
	 */
	txbuf = sc->sc_txbufs[bidx];
	dr = &sc->sc_dma_txbufs[bidx];

	/*
	 * extract 802.11 header from message, fill wh from m0
	 */
	hdat = (uint8_t *)&wh;
	off = 0;
	if (m)
		m0 = m;
	else
		m0 = mp;
	while (off < sizeof (wh)) {
		cnt = MBLKL(m0);
		if (cnt > (sizeof (wh) - off))
			cnt = sizeof (wh) - off;
		if (cnt) {
			(void) memcpy(hdat + off, m0->b_rptr, cnt);
			off += cnt;
			m0->b_rptr += cnt;
		}
		else
			m0 = m0->b_cont;
	}

	/*
	 * prepare SEND cmd header
	 */
	h		= &txbuf->txb_hdr;
	h->type		= LE_32(IPW2100_CMD_SEND);
	h->subtype	= LE_32(0);
	h->encrypted    = ic->ic_flags & IEEE80211_F_PRIVACY ? 1 : 0;
	h->encrypt	= 0;
	h->keyidx	= 0;
	h->keysz	= 0;
	h->fragsz	= LE_16(0);
	IEEE80211_ADDR_COPY(h->saddr, wh.i_addr2);
	if (ic->ic_opmode == IEEE80211_M_STA)
		IEEE80211_ADDR_COPY(h->daddr, wh.i_addr3);
	else
		IEEE80211_ADDR_COPY(h->daddr, wh.i_addr1);

	/*
	 * extract payload from message into tx data buffer
	 */
	off = 0;
	while (m0) {
		cnt = MBLKL(m0);
		if (cnt) {
			(void) memcpy(&txbuf->txb_dat[off], m0->b_rptr, cnt);
			off += cnt;
		}
		m0 = m0->b_cont;
	}

	/*
	 * fill SEND cmd header descriptor
	 */
	txbd[0]->phyaddr = LE_32(dr->dr_pbase +
	    OFFSETOF(struct ipw2100_txb, txb_hdr));
	txbd[0]->len	= LE_32(sizeof (struct ipw2100_hdr));
	txbd[0]->flags	= IPW2100_BD_FLAG_TX_FRAME_802_3 |
	    IPW2100_BD_FLAG_TX_NOT_LAST_FRAGMENT;
	txbd[0]->nfrag	= 2;
	/*
	 * fill payload descriptor
	 */
	txbd[1]->phyaddr = LE_32(dr->dr_pbase +
	    OFFSETOF(struct ipw2100_txb, txb_dat[0]));
	txbd[1]->len	= LE_32(off);
	txbd[1]->flags	= IPW2100_BD_FLAG_TX_FRAME_802_3 |
	    IPW2100_BD_FLAG_TX_LAST_FRAGMENT;
	txbd[1]->nfrag	= 0;

	/*
	 * dma sync
	 */
	(void) ddi_dma_sync(dr->dr_hnd, 0, sizeof (struct ipw2100_txb),
	    DDI_DMA_SYNC_FORDEV);
	(void) ddi_dma_sync(sc->sc_dma_txbd.dr_hnd,
	    (txbd[0] - sc->sc_txbd) * sizeof (struct ipw2100_bd),
	    sizeof (struct ipw2100_bd), DDI_DMA_SYNC_FORDEV);
	/*
	 * since txbd[1] may not be successive to txbd[0] due to the ring
	 * organization, another dma_sync is needed to simplify the logic
	 */
	(void) ddi_dma_sync(sc->sc_dma_txbd.dr_hnd,
	    (txbd[1] - sc->sc_txbd) * sizeof (struct ipw2100_bd),
	    sizeof (struct ipw2100_bd), DDI_DMA_SYNC_FORDEV);
	/*
	 * update txcur
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_TX_WRITE_INDEX, sc->sc_tx_cur);

	if (mp) /* success, free the original message */
		freemsg(mp);
fail2:
	if (m)
		freemsg(m);
fail1:
	mutex_exit(&sc->sc_tx_lock);
fail0:
	IPW2100_DBG(IPW2100_DBG_GLD, (sc->sc_dip, CE_CONT,
	    "ipw2100_send(): exit - err=%d\n", err));

	return (err);
}

/*
 * IOCTL Handler
 */
#define	IEEE80211_IOCTL_REQUIRED	(1)
#define	IEEE80211_IOCTL_NOT_REQUIRED	(0)
static void
ipw2100_m_ioctl(void *arg, queue_t *q, mblk_t *m)
{
	struct ipw2100_softc	*sc  = (struct ipw2100_softc *)arg;
	struct ieee80211com	*ic = &sc->sc_ic;
	int			err;

	IPW2100_DBG(IPW2100_DBG_GLD, (sc->sc_dip, CE_CONT,
	    "ipw2100_m_ioctl(): enter\n"));

	/*
	 * check whether or not need to handle this in net80211
	 */
	if (ipw2100_ioctl(sc, q, m) == IEEE80211_IOCTL_NOT_REQUIRED)
		return; /* succes or fail */

	err = ieee80211_ioctl(ic, q, m);
	if (err == ENETRESET) {
		if (sc->sc_flags & IPW2100_FLAG_RUNNING) {
			(void) ipw2100_m_start(sc);
			(void) ieee80211_new_state(ic,
			    IEEE80211_S_SCAN, -1);
		}
	}
	if (err == ERESTART) {
		if (sc->sc_flags & IPW2100_FLAG_RUNNING)
			(void) ipw2100_chip_reset(sc);
	}
}

static int
ipw2100_ioctl(struct ipw2100_softc *sc, queue_t *q, mblk_t *m)
{
	struct iocblk	*iocp;
	uint32_t	len, ret, cmd;
	mblk_t		*m0;
	boolean_t	need_privilege;
	boolean_t	need_net80211;

	if (MBLKL(m) < sizeof (struct iocblk)) {
		IPW2100_DBG(IPW2100_DBG_IOCTL, (sc->sc_dip, CE_CONT,
		    "ipw2100_ioctl(): ioctl buffer too short, %u\n",
		    MBLKL(m)));
		miocnak(q, m, 0, EINVAL);
		return (IEEE80211_IOCTL_NOT_REQUIRED);
	}

	/*
	 * Validate the command
	 */
	iocp = (struct iocblk *)(uintptr_t)m->b_rptr;
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;
	need_privilege = B_TRUE;
	switch (cmd) {
	case WLAN_SET_PARAM:
	case WLAN_COMMAND:
		break;
	case WLAN_GET_PARAM:
		need_privilege = B_FALSE;
		break;
	default:
		IPW2100_DBG(IPW2100_DBG_IOCTL, (sc->sc_dip, CE_CONT,
		    "ieee80211_ioctl(): unknown cmd 0x%x", cmd));
		miocnak(q, m, 0, EINVAL);
		return (IEEE80211_IOCTL_NOT_REQUIRED);
	}

	if (need_privilege && (ret = secpolicy_dl_config(iocp->ioc_cr)) != 0) {
		miocnak(q, m, 0, ret);
		return (IEEE80211_IOCTL_NOT_REQUIRED);
	}

	/*
	 * sanity check
	 */
	m0 = m->b_cont;
	if (iocp->ioc_count == 0 || iocp->ioc_count < sizeof (wldp_t) ||
	    m0 == NULL) {
		miocnak(q, m, 0, EINVAL);
		return (IEEE80211_IOCTL_NOT_REQUIRED);
	}
	/*
	 * assuming single data block
	 */
	if (m0->b_cont) {
		freemsg(m0->b_cont);
		m0->b_cont = NULL;
	}

	need_net80211 = B_FALSE;
	ret = ipw2100_getset(sc, m0, cmd, &need_net80211);
	if (!need_net80211) {
		len = msgdsize(m0);

		IPW2100_DBG(IPW2100_DBG_IOCTL, (sc->sc_dip, CE_CONT,
		    "ipw2100_ioctl(): go to call miocack with "
		    "ret = %d, len = %d\n", ret, len));
		miocack(q, m, len, ret);
		return (IEEE80211_IOCTL_NOT_REQUIRED);
	}

	/*
	 * IEEE80211_IOCTL_REQUIRED - need net80211 handle
	 */
	return (IEEE80211_IOCTL_REQUIRED);
}

static int
ipw2100_getset(struct ipw2100_softc *sc, mblk_t *m, uint32_t cmd,
	boolean_t *need_net80211)
{
	wldp_t		*infp, *outfp;
	uint32_t	id;
	int		ret; /* IEEE80211_IOCTL - handled by net80211 */

	infp  = (wldp_t *)(uintptr_t)m->b_rptr;
	outfp = (wldp_t *)(uintptr_t)m->b_rptr;
	outfp->wldp_result = WL_NOTSUPPORTED;

	id = infp->wldp_id;
	IPW2100_DBG(IPW2100_DBG_IOCTL, (sc->sc_dip, CE_CONT,
	    "ipw2100_getset(): id = 0x%x\n", id));
	switch (id) {
	/*
	 * which is not supported by net80211, so it
	 * has to be handled from driver side
	 */
	case WL_RADIO:
		ret = ipw_wificfg_radio(sc, cmd, outfp);
		break;
	/*
	 * so far, drier doesn't support fix-rates
	 */
	case WL_DESIRED_RATES:
		ret = ipw_wificfg_desrates(outfp);
		break;
	/*
	 * current net80211 implementation clears the bssid while
	 * this command received, which will result in the all zero
	 * mac address for scan'ed AP which is just disconnected.
	 * This is a workaround solution until net80211 find a
	 * better method.
	 */
	case WL_DISASSOCIATE:
		ret = ipw_wificfg_disassoc(sc, outfp);
		break;
	default:
		/*
		 * The wifi IOCTL net80211 supported:
		 *	case WL_ESSID:
		 *	case WL_BSSID:
		 *	case WL_WEP_KEY_TAB:
		 *	case WL_WEP_KEY_ID:
		 *	case WL_AUTH_MODE:
		 *	case WL_ENCRYPTION:
		 *	case WL_BSS_TYPE:
		 *	case WL_ESS_LIST:
		 *	case WL_LINKSTATUS:
		 *	case WL_RSSI:
		 *	case WL_SCAN:
		 *	case WL_LOAD_DEFAULTS:
		 */

		/*
		 * When radio is off, need to ignore all ioctl.  What need to
		 * do is to check radio status firstly.  If radio is ON, pass
		 * it to net80211, otherwise, return to upper layer directly.
		 *
		 * Considering the WL_SUCCESS also means WL_CONNECTED for
		 * checking linkstatus, one exception for WL_LINKSTATUS is to
		 * let net80211 handle it.
		 */
		if ((ipw2100_get_radio(sc) == 0) &&
		    (id != WL_LINKSTATUS)) {

			IPW2100_REPORT((sc->sc_dip, CE_WARN,
			    "ipw: RADIO is OFF\n"));

			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_SUCCESS;
			ret = 0;
			break;
		}

		*need_net80211 = B_TRUE; /* let net80211 do the rest */
		return (0);
	}
	/*
	 * we will overwrite everything
	 */
	m->b_wptr = m->b_rptr + outfp->wldp_length;

	return (ret);
}

/*
 * Call back functions for get/set proporty
 */
static int
ipw2100_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)arg;
	struct ieee80211com	*ic = &sc->sc_ic;
	int 			err = 0;

	switch (wldp_pr_num) {
	/* mac_prop_id */
	case MAC_PROP_WL_DESIRED_RATES:
		IPW2100_DBG(IPW2100_DBG_BRUSSELS, (sc->sc_dip, CE_CONT,
		    "ipw2100_m_getprop(): Not Support DESIRED_RATES\n"));
		break;
	case MAC_PROP_WL_RADIO:
		*(wl_linkstatus_t *)wldp_buf = ipw2100_get_radio(sc);
		break;
	default:
		/* go through net80211 */
		err = ieee80211_getprop(ic, pr_name, wldp_pr_num,
		    wldp_length, wldp_buf);
		break;
	}

	return (err);
}

static void
ipw2100_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)arg;
	struct ieee80211com	*ic = &sc->sc_ic;

	ieee80211_propinfo(ic, pr_name, wldp_pr_num, prh);

}

static int
ipw2100_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)arg;
	struct ieee80211com	*ic = &sc->sc_ic;
	int			err;

	switch (wldp_pr_num) {
	/* mac_prop_id */
	case MAC_PROP_WL_DESIRED_RATES:
		IPW2100_DBG(IPW2100_DBG_BRUSSELS, (sc->sc_dip, CE_CONT,
		    "ipw2100_m_setprop(): Not Support DESIRED_RATES\n"));
		err = ENOTSUP;
		break;
	case MAC_PROP_WL_RADIO:
		IPW2100_DBG(IPW2100_DBG_BRUSSELS, (sc->sc_dip, CE_CONT,
		    "ipw2100_m_setprop(): Not Support RADIO\n"));
		err = ENOTSUP;
		break;
	default:
		/* go through net80211 */
		err = ieee80211_setprop(ic, pr_name, wldp_pr_num, wldp_length,
		    wldp_buf);
		break;
	}

	if (err == ENETRESET) {
		if (sc->sc_flags & IPW2100_FLAG_RUNNING) {
			(void) ipw2100_m_start(sc);
			(void) ieee80211_new_state(ic,
			    IEEE80211_S_SCAN, -1);
		}

		err = 0;
	}

	return (err);
}

static int
ipw_wificfg_radio(struct ipw2100_softc *sc, uint32_t cmd, wldp_t *outfp)
{
	uint32_t	ret = ENOTSUP;

	switch (cmd) {
	case WLAN_GET_PARAM:
		*(wl_linkstatus_t *)(outfp->wldp_buf) = ipw2100_get_radio(sc);
		outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_linkstatus_t);
		outfp->wldp_result = WL_SUCCESS;
		ret = 0; /* command sucess */
		break;
	case WLAN_SET_PARAM:
	default:
		break;
	}
	return (ret);
}

static int
ipw_wificfg_desrates(wldp_t *outfp)
{
	/*
	 * return success, but with result NOTSUPPORTED
	 */
	outfp->wldp_length = WIFI_BUF_OFFSET;
	outfp->wldp_result = WL_NOTSUPPORTED;
	return (0);
}

static int
ipw_wificfg_disassoc(struct ipw2100_softc *sc, wldp_t *outfp)
{
	struct ieee80211com	*ic = &sc->sc_ic;

	/*
	 * init the state
	 */
	if (ic->ic_state != IEEE80211_S_INIT) {
		(void) ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	}

	/*
	 * return success always
	 */
	outfp->wldp_length = WIFI_BUF_OFFSET;
	outfp->wldp_result = WL_SUCCESS;
	return (0);
}
/* End of IOCTL Handler */

static void
ipw2100_fix_channel(struct ieee80211com *ic, mblk_t *m)
{
	struct ieee80211_frame	*wh;
	uint8_t			subtype;
	uint8_t			*frm, *efrm;

	wh = (struct ieee80211_frame *)m->b_rptr;

	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_MGT)
		return;

	subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	if (subtype != IEEE80211_FC0_SUBTYPE_BEACON &&
	    subtype != IEEE80211_FC0_SUBTYPE_PROBE_RESP)
		return;

	/*
	 * assume the message contains only 1 block
	 */
	frm   = (uint8_t *)(wh + 1);
	efrm  = (uint8_t *)m->b_wptr;
	frm  += 12;  /* skip tstamp, bintval and capinfo fields */
	while (frm < efrm) {
		if (*frm == IEEE80211_ELEMID_DSPARMS) {
#if IEEE80211_CHAN_MAX < 255
			if (frm[2] <= IEEE80211_CHAN_MAX)
#endif
			{
				ic->ic_curchan = &ic->ic_sup_channels[frm[2]];
			}
		}
		frm += frm[1] + 2;
	}
}

static void
ipw2100_rcvpkt(struct ipw2100_softc *sc, struct ipw2100_status *status,
    uint8_t *rxbuf)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	mblk_t			*m;
	struct ieee80211_frame	*wh = (struct ieee80211_frame *)rxbuf;
	struct ieee80211_node	*in;
	uint32_t		rlen;

	in = ieee80211_find_rxnode(ic, wh);
	rlen = LE_32(status->len);
	m = allocb(rlen, BPRI_MED);
	if (m) {
		(void) memcpy(m->b_wptr, rxbuf, rlen);
		m->b_wptr += rlen;
		if (ic->ic_state == IEEE80211_S_SCAN)
			ipw2100_fix_channel(ic, m);
		(void) ieee80211_input(ic, m, in, status->rssi, 0);
	} else
		IPW2100_WARN((sc->sc_dip, CE_WARN,
		    "ipw2100_rcvpkg(): cannot allocate receive message(%u)\n",
		    LE_32(status->len)));
	ieee80211_free_node(in);
}

static uint_t
ipw2100_intr(caddr_t arg)
{
	struct ipw2100_softc	*sc = (struct ipw2100_softc *)(uintptr_t)arg;
	uint32_t		ireg, ridx, len, i;
	struct ieee80211com	*ic = &sc->sc_ic;
	struct ipw2100_status	*status;
	uint8_t			*rxbuf;
	struct dma_region	*dr;
	uint32_t		state;
#if DEBUG
	struct ipw2100_bd *rxbd;
#endif

	if (sc->sc_suspended)
		return (DDI_INTR_UNCLAIMED);

	ireg = ipw2100_csr_get32(sc, IPW2100_CSR_INTR);

	if (!(ireg & IPW2100_INTR_MASK_ALL))
		return (DDI_INTR_UNCLAIMED);

	/*
	 * mask all interrupts
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_INTR_MASK, 0);

	/*
	 * acknowledge all fired interrupts
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_INTR, ireg);

	IPW2100_DBG(IPW2100_DBG_INT, (sc->sc_dip, CE_CONT,
	    "ipw2100_intr(): interrupt is fired. int=0x%08x\n", ireg));

	if (ireg & IPW2100_INTR_MASK_ERR) {

		IPW2100_DBG(IPW2100_DBG_FATAL, (sc->sc_dip, CE_CONT,
		    "ipw2100_intr(): interrupt is fired, MASK = 0x%08x\n",
		    ireg));

		/*
		 * inform mfthread to recover hw error
		 */
		mutex_enter(&sc->sc_mflock);
		sc->sc_flags |= IPW2100_FLAG_HW_ERR_RECOVER;
		mutex_exit(&sc->sc_mflock);

		goto enable_interrupt;
	}

	/*
	 * FW intr
	 */
	if (ireg & IPW2100_INTR_FW_INIT_DONE) {
		mutex_enter(&sc->sc_ilock);
		sc->sc_flags |= IPW2100_FLAG_FW_INITED;
		cv_signal(&sc->sc_fw_cond);
		mutex_exit(&sc->sc_ilock);
	}

	/*
	 * RX intr
	 */
	if (ireg & IPW2100_INTR_RX_TRANSFER) {
		ridx = ipw2100_csr_get32(sc,
		    IPW2100_CSR_RX_READ_INDEX);

		for (; sc->sc_rx_cur != ridx;
		    sc->sc_rx_cur = RING_FORWARD(
		    sc->sc_rx_cur, 1, IPW2100_NUM_RXBD)) {

			i	= sc->sc_rx_cur;
			status	= &sc->sc_status[i];
			rxbuf	= &sc->sc_rxbufs[i]->rxb_dat[0];
			dr	= &sc->sc_dma_rxbufs[i];

			/*
			 * sync
			 */
			(void) ddi_dma_sync(sc->sc_dma_status.dr_hnd,
			    i * sizeof (struct ipw2100_status),
			    sizeof (struct ipw2100_status),
			    DDI_DMA_SYNC_FORKERNEL);
			(void) ddi_dma_sync(sc->sc_dma_rxbd.dr_hnd,
			    i * sizeof (struct ipw2100_bd),
			    sizeof (struct ipw2100_bd),
			    DDI_DMA_SYNC_FORKERNEL);
			(void) ddi_dma_sync(dr->dr_hnd, 0,
			    sizeof (struct ipw2100_rxb),
			    DDI_DMA_SYNC_FORKERNEL);
			IPW2100_DBG(IPW2100_DBG_INT, (sc->sc_dip, CE_CONT,
			    "ipw2100_intr(): status code=0x%04x, len=0x%08x, "
			    "flags=0x%02x, rssi=%02x\n",
			    LE_16(status->code), LE_32(status->len),
			    status->flags, status->rssi));
#if DEBUG
			rxbd	= &sc->sc_rxbd[i];
			IPW2100_DBG(IPW2100_DBG_INT, (sc->sc_dip, CE_CONT,
			    "ipw2100_intr(): rxbd,phyaddr=0x%08x, len=0x%08x, "
			    "flags=0x%02x,nfrag=%02x\n",
			    LE_32(rxbd->phyaddr), LE_32(rxbd->len),
			    rxbd->flags, rxbd->nfrag));
#endif
			switch (LE_16(status->code) & 0x0f) {
			/*
			 * command complete response
			 */
			case IPW2100_STATUS_CODE_COMMAND:
				mutex_enter(&sc->sc_ilock);
				sc->sc_done = 1;
				cv_signal(&sc->sc_cmd_cond);
				mutex_exit(&sc->sc_ilock);
				break;
			/*
			 * change state
			 */
			case IPW2100_STATUS_CODE_NEWSTATE:
				state = LE_32(* ((uint32_t *)(uintptr_t)rxbuf));
				IPW2100_DBG(IPW2100_DBG_INT,
				    (sc->sc_dip, CE_CONT,
				    "ipw2100_intr(): newstate,state=0x%x\n",
				    state));

				switch (state) {
				case IPW2100_STATE_ASSOCIATED:
					ieee80211_new_state(ic,
					    IEEE80211_S_RUN, -1);
					break;
				case IPW2100_STATE_ASSOCIATION_LOST:
					case IPW2100_STATE_DISABLED:
					ieee80211_new_state(ic,
					    IEEE80211_S_INIT, -1);
					break;
				/*
				 * When radio is OFF, need a better
				 * scan approach to ensure scan
				 * result correct.
				 */
				case IPW2100_STATE_RADIO_DISABLED:
					IPW2100_REPORT((sc->sc_dip, CE_WARN,
					    "ipw2100_intr(): RADIO is OFF\n"));
					ipw2100_stop(sc);
					break;
				case IPW2100_STATE_SCAN_COMPLETE:
					ieee80211_cancel_scan(ic);
					break;
				case IPW2100_STATE_SCANNING:
					if (ic->ic_state != IEEE80211_S_RUN)
						ieee80211_new_state(ic,
						    IEEE80211_S_SCAN, -1);
					ic->ic_flags |= IEEE80211_F_SCAN;

					break;
				default:
					break;
				}
				break;
			case IPW2100_STATUS_CODE_DATA_802_11:
			case IPW2100_STATUS_CODE_DATA_802_3:
				ipw2100_rcvpkt(sc, status, rxbuf);
				break;
			case IPW2100_STATUS_CODE_NOTIFICATION:
				break;
			default:
				IPW2100_WARN((sc->sc_dip, CE_WARN,
				    "ipw2100_intr(): "
				    "unknown status code 0x%04x\n",
				    LE_16(status->code)));
				break;
			}
		}
		/*
		 * write sc_rx_cur backward 1 step to RX_WRITE_INDEX
		 */
		ipw2100_csr_put32(sc, IPW2100_CSR_RX_WRITE_INDEX,
		    RING_BACKWARD(sc->sc_rx_cur, 1, IPW2100_NUM_RXBD));
	}

	/*
	 * TX intr
	 */
	if (ireg & IPW2100_INTR_TX_TRANSFER) {
		mutex_enter(&sc->sc_tx_lock);
		ridx = ipw2100_csr_get32(sc, IPW2100_CSR_TX_READ_INDEX);
		len = RING_FLEN(RING_FORWARD(sc->sc_tx_cur,
		    sc->sc_tx_free, IPW2100_NUM_TXBD),
		    ridx, IPW2100_NUM_TXBD);
		sc->sc_tx_free += len;
		IPW2100_DBG(IPW2100_DBG_INT, (sc->sc_dip, CE_CONT,
		    "ipw2100_intr(): len=%d\n", len));
		mutex_exit(&sc->sc_tx_lock);

		mutex_enter(&sc->sc_resched_lock);
		if (len > 1 && (sc->sc_flags & IPW2100_FLAG_TX_SCHED)) {
			sc->sc_flags &= ~IPW2100_FLAG_TX_SCHED;
			mac_tx_update(ic->ic_mach);
		}
		mutex_exit(&sc->sc_resched_lock);
	}

enable_interrupt:
	/*
	 * enable all interrupts
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_INTR_MASK, IPW2100_INTR_MASK_ALL);

	return (DDI_INTR_CLAIMED);
}


/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(ipw2100_devops, nulldev, nulldev, ipw2100_attach,
    ipw2100_detach, nodev, NULL, D_MP, NULL, ipw2100_quiesce);

static struct modldrv ipw2100_modldrv = {
	&mod_driverops,
	ipw2100_ident,
	&ipw2100_devops
};

static struct modlinkage ipw2100_modlinkage = {
	MODREV_1,
	&ipw2100_modldrv,
	NULL
};

int
_init(void)
{
	int	status;

	status = ddi_soft_state_init(&ipw2100_ssp,
	    sizeof (struct ipw2100_softc), 1);
	if (status != DDI_SUCCESS)
		return (status);

	mac_init_ops(&ipw2100_devops, IPW2100_DRV_NAME);
	status = mod_install(&ipw2100_modlinkage);
	if (status != DDI_SUCCESS) {
		mac_fini_ops(&ipw2100_devops);
		ddi_soft_state_fini(&ipw2100_ssp);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&ipw2100_modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&ipw2100_devops);
		ddi_soft_state_fini(&ipw2100_ssp);
	}

	return (status);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&ipw2100_modlinkage, mip));
}
