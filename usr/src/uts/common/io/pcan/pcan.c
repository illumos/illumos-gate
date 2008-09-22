/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1997, 1998, 1999
 *      Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/strsun.h>
#include <sys/stat.h>
#include <sys/byteorder.h>
#include <sys/pccard.h>
#include <sys/pci.h>
#include <sys/policy.h>
#include <sys/mac.h>
#include <sys/stream.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>

#include "pcan.h"
#include <sys/mac_wifi.h>
#include <inet/wifi_ioctl.h>

#ifdef	DEBUG
#define	PCAN_DBG_BASIC		0x1
#define	PCAN_DBG_INFO		0x2
#define	PCAN_DBG_SEND		0x4
#define	PCAN_DBG_RCV		0x8
#define	PCAN_DBG_LINKINFO	0x10
#define	PCAN_DBG_FW_VERSION	0x20
#define	PCAN_DBG_CMD		0x40
uint32_t pcan_debug = 0;
#define	PCANDBG(x) \
	if (pcan_debug & PCAN_DBG_BASIC) cmn_err x
#else
#define	PCANDBG(x)
#endif

static ddi_device_acc_attr_t accattr = {
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_LE_ACC,
		DDI_STRICTORDER_ACC,
};

static ddi_dma_attr_t control_cmd_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffull,	/* highest usable address */
	0xffffffffull,		/* maximum DMAable byte count */
	4,			/* alignment in bytes */
	0xfff,			/* burst sizes (any) */
	1,			/* minimum transfer */
	0xffffull,		/* maximum transfer */
	0xffffffffffffffffull,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

void *pcan_soft_state_p = NULL;
static int pcan_device_type;

mac_callbacks_t pcan_m_callbacks = {
	MC_IOCTL,
	pcan_gstat,
	pcan_start,
	pcan_stop,
	pcan_prom,
	pcan_sdmulti,
	pcan_saddr,
	pcan_tx,
	NULL,
	pcan_ioctl
};

static char *pcan_name_str = "pcan";

DDI_DEFINE_STREAM_OPS(pcan_dev_ops, nulldev, pcan_probe, pcan_attach,
    pcan_detach, nodev, NULL, D_MP, NULL, ddi_quiesce_not_supported);

extern struct mod_ops mod_driverops;
static struct modldrv modldrv = {
	&mod_driverops,
	"Cisco-Aironet 802.11b driver",
	&pcan_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
	};

int
_init(void)
{
	int stat;

	/* Allocate soft state */
	if ((stat = ddi_soft_state_init(&pcan_soft_state_p,
	    sizeof (pcan_maci_t), 2)) != DDI_SUCCESS)
		return (stat);

	mac_init_ops(&pcan_dev_ops, "pcan");
	stat = mod_install(&modlinkage);
	if (stat != 0) {
		mac_fini_ops(&pcan_dev_ops);
		ddi_soft_state_fini(&pcan_soft_state_p);
	}

	return (stat);
}

int
_fini(void)
{
	int stat;

	stat = mod_remove(&modlinkage);
	if (stat != DDI_SUCCESS)
		return (stat);
	mac_fini_ops(&pcan_dev_ops);
	ddi_soft_state_fini(&pcan_soft_state_p);
	return (stat);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
pcan_probe(dev_info_t *dip)
{
	int len, ret;
	char *buf;
	dev_info_t *pdip = ddi_get_parent(dip);

	PCANDBG((CE_NOTE, "pcan probe: parent dip=0x%p-%s(%d)\n", (void *)pdip,
	    ddi_driver_name(pdip), ddi_get_instance(pdip)));

	ret = ddi_getlongprop(DDI_DEV_T_ANY, pdip, 0, "device_type",
	    (caddr_t)&buf, &len);
	if (ret != DDI_SUCCESS)
		return (DDI_PROBE_FAILURE);

	PCANDBG((CE_NOTE, "pcan probe: device_type %s\n", buf));
	if ((strcmp(buf, "pccard") == 0) || (strcmp(buf, "pcmcia") == 0)) {
		pcan_device_type = PCAN_DEVICE_PCCARD;
#ifdef DEBUG
		if (pcan_debug & PCAN_DBG_FW_VERSION) {
			cmn_err(CE_NOTE, "Cisco 802.11 pccard\n");
		}
#endif
		ret = DDI_PROBE_SUCCESS;
	} else if (strcmp(buf, "pci") == 0) {
		pcan_device_type = PCAN_DEVICE_PCI;
#ifdef DEBUG
		if (pcan_debug & PCAN_DBG_FW_VERSION) {
			cmn_err(CE_NOTE, "Cisco 802.11 minipci card\n");
		}
#endif
		ret = DDI_PROBE_SUCCESS;
	} else {
		cmn_err(CE_NOTE, "pcan probe: unsupported card\n");
		ret = DDI_PROBE_FAILURE;
	}

	kmem_free(buf, len);
	return (ret);
}

static int
pcan_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	int instance;
	uint16_t stat;
	uint32_t err;
	pcan_maci_t *pcan_p;
	wifi_data_t	wd = { 0 };
	mac_register_t	*macp;
	modify_config_t cfgmod;
	char strbuf[256];

	PCANDBG((CE_NOTE, "dip=0x%p cmd=%x\n", (void *)dip, cmd));
	if (cmd != DDI_ATTACH)
		goto attach_fail1;

	/*
	 * Since this driver is porting from freebsd, so just like
	 * the original driver, the minipci card doesn't work on amd64
	 * machine.
	 * For sparc, since no pci card is available for the test, so this
	 * version doesn't support sparc. If there is card available and
	 * requirement, future version will try to support sparc.
	 * This driver works well for minipci card on 32bit x86
	 * machine, so keep the code to just support minipci card on 32bit
	 * mode.
	 */
#if defined(sparc) || defined(__sparc)
	if (pcan_device_type == PCAN_DEVICE_PCI) {
		cmn_err(CE_NOTE, "pcan attach: this driver does not support "
		    "PCI/MiniPCI card on Sparc\n");
		goto attach_fail1;
	}
#endif /* sparc */
#if defined(__amd64)
	if (pcan_device_type == PCAN_DEVICE_PCI) {
		cmn_err(CE_NOTE, "pcan attach: this driver does not support "
		    "PCI/MiniPCI card on amd64\n");
		goto attach_fail1;
	}
#endif /* amd64 */

	/* Allocate soft state associated with this instance. */
	if (ddi_soft_state_zalloc(pcan_soft_state_p,
	    ddi_get_instance(dip)) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "pcan attach: alloc softstate failed\n");
		goto attach_fail1;
	}
	pcan_p = (pcan_maci_t *)ddi_get_soft_state(pcan_soft_state_p,
	    ddi_get_instance(dip));

	pcan_p->pcan_device_type = pcan_device_type;
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		if (ddi_regs_map_setup(dip, 0,
		    (caddr_t *)&pcan_p->pcan_cfg_base, 0, 0,
		    &accattr, &pcan_p->pcan_cfg_handle) != DDI_SUCCESS)
			goto attach_fail2;

		stat = ddi_get16(pcan_p->pcan_cfg_handle,
		    (uint16_t *)(pcan_p->pcan_cfg_base + PCI_CONF_COMM));
		stat |= (PCI_COMM_IO | PCI_COMM_MAE);
		ddi_put16(pcan_p->pcan_cfg_handle,
		    (uint16_t *)(pcan_p->pcan_cfg_base + PCI_CONF_COMM), stat);

		ddi_regs_map_free(&pcan_p->pcan_cfg_handle);
		if (ddi_regs_map_setup(dip, 1, (caddr_t *)&pcan_p->pcan_bar0,
		    0, 0, &accattr, &pcan_p->pcan_handle0) != DDI_SUCCESS)
			goto attach_fail3;
		if (ddi_regs_map_setup(dip, 2, (caddr_t *)&pcan_p->pcan_bar1,
		    0, 0, &accattr, &pcan_p->pcan_handle1) != DDI_SUCCESS)
			goto attach_fail3;
		if (ddi_regs_map_setup(dip, 3, (caddr_t *)&pcan_p->pcan_bar2,
		    0, 0, &accattr, &pcan_p->pcan_handle2) != DDI_SUCCESS)
			goto attach_fail3;
	}

	pcan_p->pcan_dip		= dip;
	pcan_p->pcan_flag		= 0;
	pcan_p->glds_nocarrier		= 0;
	pcan_p->glds_noxmtbuf		= 0;
	pcan_p->glds_norcvbuf		= 0;
	pcan_p->pcan_socket		= ddi_getprop(DDI_DEV_T_NONE, dip,
	    DDI_PROP_DONTPASS, "socket", -1);

	pcan_p->pcan_reschedule_need = B_FALSE;
	pcan_p->pcan_info_softint_pending = 0;
	pcan_p->pcan_reset_delay = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reset-delay", 5000);

	if (ddi_get_iblock_cookie(dip,
	    0, &pcan_p->pcan_ib_cookie) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pcan attach: get_iblk_cookie failed\n");
		goto attach_fail3;
	}

	mutex_init(&pcan_p->pcan_glock, NULL,
	    MUTEX_DRIVER, pcan_p->pcan_ib_cookie);
	mutex_init(&pcan_p->pcan_scanlist_lock, NULL,
	    MUTEX_DRIVER, pcan_p->pcan_ib_cookie);
	mutex_init(&pcan_p->pcan_txring.an_tx_lock, NULL,
	    MUTEX_DRIVER, pcan_p->pcan_ib_cookie);

	if (ret = ddi_add_softintr(dip, DDI_SOFTINT_LOW,
	    &pcan_p->pcan_info_softint_id, &pcan_p->pcan_ib_cookie, NULL,
	    pcan_info_softint, (caddr_t)pcan_p)) {
		cmn_err(CE_WARN, "pcan attach: add info_softintr failed\n");
		goto attach_fail3a;
	}

	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		if (ret = ddi_add_intr(dip, 0, NULL, NULL,
		    pcan_intr, (caddr_t)pcan_p)) {
			cmn_err(CE_WARN, "pcan attach: add intr failed\n");
			goto attach_fail4;
		}
	} else if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
		if (ret = pcan_register_cs(dip, pcan_p)) {
			PCANDBG((CE_NOTE, "pcan attach: register_cs failed"
			    " %x\n", ret));
			goto attach_fail4;
		}
	} else {
		cmn_err(CE_WARN, "pcan attach: unsupported device type\n");
		goto attach_fail4;
	}

	mutex_enter(&pcan_p->pcan_glock);
	pcan_reset_backend(pcan_p, pcan_p->pcan_reset_delay);
	/* leaves IF down, intr disabled */

	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		if (ret = pcan_init_dma(dip, pcan_p)) {
			cmn_err(CE_WARN, "pcan init_dma: failed\n");
			mutex_exit(&pcan_p->pcan_glock);
			goto attach_fail5;
		}
	}
	if (ret = pcan_get_cap(pcan_p)) { /* sets macaddr for gld_register */
		cmn_err(CE_WARN, "pcan attach: get_cap failed %x\n", ret);
		mutex_exit(&pcan_p->pcan_glock);
		goto attach_fail6;
	}

	mutex_exit(&pcan_p->pcan_glock);
	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_pdata_update()
	 */
	wd.wd_secalloc = WIFI_SEC_NONE;
	wd.wd_opmode = IEEE80211_M_STA;

	macp = mac_alloc(MAC_VERSION);
	if (macp == NULL) {
		PCANDBG((CE_NOTE, "pcan attach: "
		    "MAC version mismatch\n"));
		goto attach_fail6;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= pcan_p;
	macp->m_dip		= dip;
	macp->m_src_addr	= pcan_p->pcan_mac_addr;
	macp->m_callbacks	= &pcan_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &pcan_p->pcan_mh);
	mac_free(macp);
	if (err != 0) {
		PCANDBG((CE_NOTE, "pcan attach: "
		    "mac_register err\n"));
		goto attach_fail6;
	}

	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
		/* turn on CS interrupt */
		cfgmod.Attributes = CONF_ENABLE_IRQ_STEERING |
		    CONF_IRQ_CHANGE_VALID;
		cfgmod.Vpp1 = 50;
		cfgmod.Vpp2 = 50;
		(void) csx_ModifyConfiguration(pcan_p->pcan_chdl, &cfgmod);

		mutex_enter(&pcan_p->pcan_glock);
		if (ret = pcan_init_nicmem(pcan_p)) {
			cmn_err(CE_WARN, "pcan attach: init_nicmem failed %x\n",
			    ret);
			mutex_exit(&pcan_p->pcan_glock);
			goto attach_fail7;
		}
		mutex_exit(&pcan_p->pcan_glock);
	}
	(void) ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "bad-rids", (caddr_t)&pcan_p->pcan_badrids,
	    &pcan_p->pcan_badrids_len);

	pcan_p->an_config.an_rxmode = AN_NORMAL_RXMODE;
	ether_copy(pcan_p->pcan_mac_addr, pcan_p->an_config.an_macaddr);
	mutex_enter(&pcan_p->pcan_glock);
	list_create(&pcan_p->an_scan_list, sizeof (an_scan_list_t),
	    offsetof(an_scan_list_t, an_scan_node));
	pcan_p->an_scan_num = 0;
	mutex_exit(&pcan_p->pcan_glock);
	pcan_p->an_scanlist_timeout_id = timeout(pcan_scanlist_timeout,
	    pcan_p, drv_usectohz(1000000));

	instance = ddi_get_instance(dip);
	(void) snprintf(strbuf, sizeof (strbuf), "pcan%d", instance);
	if (ddi_create_minor_node(dip, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0) != DDI_SUCCESS) {
		goto attach_fail8;
	}
	mutex_enter(&pcan_p->pcan_glock);
	PCAN_DISABLE_INTR_CLEAR(pcan_p);
	(void) pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0);
	pcan_p->pcan_flag |= PCAN_ATTACHED;
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		pcan_p->pcan_flag |= PCAN_CARD_READY;
	}
	mutex_exit(&pcan_p->pcan_glock);
	return (DDI_SUCCESS);
attach_fail8:
	if (pcan_p->an_scanlist_timeout_id != 0) {
		(void) untimeout(pcan_p->an_scanlist_timeout_id);
		pcan_p->an_scanlist_timeout_id = 0;
	}
	list_destroy(&pcan_p->an_scan_list);
attach_fail7:
	(void) mac_unregister(pcan_p->pcan_mh);
attach_fail6:
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI)
		pcan_free_dma(pcan_p);
attach_fail5:
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		ddi_remove_intr(dip, 0, pcan_p->pcan_ib_cookie);
	} else if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
		pcan_unregister_cs(pcan_p);
	}
attach_fail4:
	if (pcan_p->pcan_info_softint_id)
		ddi_remove_softintr(pcan_p->pcan_info_softint_id);
attach_fail3a:
	pcan_destroy_locks(pcan_p);
attach_fail3:
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		if (pcan_p->pcan_handle0)
			ddi_regs_map_free(&pcan_p->pcan_handle0);
		if (pcan_p->pcan_handle1)
			ddi_regs_map_free(&pcan_p->pcan_handle1);
		if (pcan_p->pcan_handle2)
			ddi_regs_map_free(&pcan_p->pcan_handle2);
	}
attach_fail2:
	ddi_soft_state_free(pcan_soft_state_p, ddi_get_instance(dip));
attach_fail1:
	return (DDI_FAILURE);
}

static int
pcan_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	pcan_maci_t *pcan_p;
	an_scan_list_t *scan_item0;
	int ret;
	pcan_p = ddi_get_soft_state(pcan_soft_state_p, ddi_get_instance(dip));

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	if (!(pcan_p->pcan_flag & PCAN_ATTACHED))
		return (DDI_FAILURE);

	ret = mac_disable(pcan_p->pcan_mh);
	if (ret != 0)
		return (DDI_FAILURE);

	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		mutex_enter(&pcan_p->pcan_glock);
		pcan_stop_locked(pcan_p);
		PCAN_DISABLE_INTR(pcan_p);
		mutex_exit(&pcan_p->pcan_glock);
	}
	if (pcan_p->an_scanlist_timeout_id != 0) {
		(void) untimeout(pcan_p->an_scanlist_timeout_id);
		pcan_p->an_scanlist_timeout_id = 0;
	}
	if (pcan_p->pcan_connect_timeout_id != 0) {
		(void) untimeout(pcan_p->pcan_connect_timeout_id);
		pcan_p->pcan_connect_timeout_id = 0;
	}
	mutex_enter(&pcan_p->pcan_scanlist_lock);
	scan_item0 = list_head(&pcan_p->an_scan_list);
	while (scan_item0) {
		pcan_delete_scan_item(pcan_p, scan_item0);
		scan_item0 = list_head(&pcan_p->an_scan_list);
	}
	list_destroy(&pcan_p->an_scan_list);
	mutex_exit(&pcan_p->pcan_scanlist_lock);

	(void) mac_unregister(pcan_p->pcan_mh);

	mutex_enter(&pcan_p->pcan_glock);
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		ddi_remove_intr(dip, 0, pcan_p->pcan_ib_cookie);
		pcan_free_dma(pcan_p);
		if (pcan_p->pcan_handle0)
			ddi_regs_map_free(&pcan_p->pcan_handle0);
		if (pcan_p->pcan_handle1)
			ddi_regs_map_free(&pcan_p->pcan_handle1);
		if (pcan_p->pcan_handle2)
			ddi_regs_map_free(&pcan_p->pcan_handle2);
	} else if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
		pcan_unregister_cs(pcan_p);
	} else {
		cmn_err(CE_WARN, "pcan detach: unsupported device type\n");
	}
	mutex_exit(&pcan_p->pcan_glock);
	pcan_destroy_locks(pcan_p);
	if (pcan_p->pcan_info_softint_id)
		ddi_remove_softintr(pcan_p->pcan_info_softint_id);

	if (pcan_p->pcan_badrids_len)
		kmem_free(pcan_p->pcan_badrids, pcan_p->pcan_badrids_len);

	ddi_soft_state_free(pcan_soft_state_p, ddi_get_instance(dip));
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/*
 * card services and event handlers
 */

static int
pcan_register_cs(dev_info_t *dip, pcan_maci_t *pcan_p)
{
	int ret;
	client_reg_t cr;
	client_handle_t chdl; /* uint encoding of socket, function, client */
	get_status_t card_status;
	request_socket_mask_t sock_req;

	bzero(&cr, sizeof (cr));
	cr.Attributes	= INFO_IO_CLIENT|INFO_CARD_EXCL|INFO_CARD_SHARE;
	cr.EventMask	= CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL |
	    CS_EVENT_REGISTRATION_COMPLETE | CS_EVENT_CARD_REMOVAL_LOWP |
	    CS_EVENT_CARD_READY | CS_EVENT_PM_RESUME | CS_EVENT_PM_SUSPEND |
	    CS_EVENT_CLIENT_INFO;
	cr.event_callback_args.client_data = pcan_p;
	cr.Version = CS_VERSION;
	cr.event_handler = (csfunction_t *)pcan_ev_hdlr;
	cr.dip = dip;
	(void) strcpy(cr.driver_name, pcan_name_str);
	if (ret = csx_RegisterClient(&chdl, &cr)) {
		cmn_err(CE_WARN, "pcan: RegisterClient failed %x", ret);
		goto regcs_ret;
	}

	pcan_p->pcan_chdl = chdl;

	bzero(&card_status, sizeof (card_status));
	(void) csx_GetStatus(chdl, &card_status);
	PCANDBG((CE_NOTE, "pcan: getstat Sock=%x CState=%x SState=%x rState=%x",
	    card_status.Socket, card_status.CardState,
	    card_status.SocketState, card_status.raw_CardState));
	if (!(card_status.CardState & CS_STATUS_CARD_INSERTED)) {
		/* card is not present, why are we attaching ? */
		ret = CS_NO_CARD;
		goto unreg;
	}
	cv_init(&pcan_p->pcan_cscv, NULL, CV_DRIVER, NULL);
	mutex_init(&pcan_p->pcan_cslock, NULL, MUTEX_DRIVER, *cr.iblk_cookie);
	mutex_enter(&pcan_p->pcan_cslock);
	if (ret = csx_MapLogSocket(chdl, &pcan_p->pcan_log_sock)) {
		cmn_err(CE_WARN, "pcan: MapLogSocket failed %x", ret);
		goto fail;
	}
	PCANDBG((CE_NOTE, "pcan: logsock: LogSock=%x PhyAdapter=%x PhySock=%x",
	    pcan_p->pcan_log_sock.LogSocket,
	    pcan_p->pcan_log_sock.PhyAdapter,
	    pcan_p->pcan_log_sock.PhySocket));

	/* turn on initialization events */
	sock_req.Socket = 0;
	sock_req.EventMask = CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL |
	    CS_EVENT_REGISTRATION_COMPLETE;
	if (ret = csx_RequestSocketMask(chdl, &sock_req)) {
		cmn_err(CE_WARN, "pcan: RequestSocketMask failed %x\n", ret);
		goto fail;
	}

	/* wait for and process card insertion events */
	while (!(pcan_p->pcan_flag & PCAN_CARD_READY))
		cv_wait(&pcan_p->pcan_cscv, &pcan_p->pcan_cslock);
	mutex_exit(&pcan_p->pcan_cslock);

	pcan_p->pcan_flag |= PCAN_CS_REGISTERED;
	return (CS_SUCCESS);
fail:
	mutex_destroy(&pcan_p->pcan_cslock);
	cv_destroy(&pcan_p->pcan_cscv);
unreg:
	(void) csx_DeregisterClient(chdl);
regcs_ret:
	pcan_p->pcan_flag &= ~PCAN_CS_REGISTERED;
	return (ret);
}

static void
pcan_unregister_cs(pcan_maci_t *pcan_p)
{
	int ret;
	release_socket_mask_t mask;
	mask.Socket = pcan_p->pcan_socket;

	/*
	 * The card service not registered means register_cs function
	 * doesnot return TRUE. Then all the lelated resource has been
	 * released in register_cs.
	 */
	if (!(pcan_p->pcan_flag | PCAN_CS_REGISTERED))
		return;
	(void) csx_ReleaseSocketMask(pcan_p->pcan_chdl, &mask);

	if (pcan_p->pcan_flag & PCAN_CARD_READY) {
		pcan_card_remove(pcan_p);
		pcan_p->pcan_flag &= ~PCAN_CARD_READY;
	}
	mutex_destroy(&pcan_p->pcan_cslock);
	cv_destroy(&pcan_p->pcan_cscv);
	if (ret = csx_DeregisterClient(pcan_p->pcan_chdl))
		cmn_err(CE_WARN, "pcan: deregister failed %x\n", ret);
}
static void
pcan_destroy_locks(pcan_maci_t *pcan_p)
{
	mutex_destroy(&pcan_p->pcan_txring.an_tx_lock);
	mutex_destroy(&pcan_p->pcan_scanlist_lock);
	mutex_destroy(&pcan_p->pcan_glock);
}

static int
pcan_ev_hdlr(event_t event, int priority, event_callback_args_t *arg)
{
	int ret = CS_SUCCESS;
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg->client_data;
	client_info_t *ci_p = (client_info_t *)&arg->client_info;

	mutex_enter(&pcan_p->pcan_cslock);
	switch (event) {
	case CS_EVENT_CARD_INSERTION:
		ret = pcan_card_insert(pcan_p);
		cv_broadcast(&pcan_p->pcan_cscv);
		break;
	case CS_EVENT_REGISTRATION_COMPLETE:
		cv_broadcast(&pcan_p->pcan_cscv);
		break;
	case CS_EVENT_CARD_REMOVAL:
		if (priority & CS_EVENT_PRI_HIGH)
			break;
		pcan_card_remove(pcan_p);
		cv_broadcast(&pcan_p->pcan_cscv);
		break;
	case CS_EVENT_CLIENT_INFO:
		if (GET_CLIENT_INFO_SUBSVC(ci_p->Attributes) !=
		    CS_CLIENT_INFO_SUBSVC_CS)
			break;

		ci_p->Revision = 0x0101;
		ci_p->CSLevel = CS_VERSION;
		ci_p->RevDate = CS_CLIENT_INFO_MAKE_DATE(9, 12, 14);
		(void) strcpy(ci_p->ClientName, PCAN_IDENT_STRING);
		(void) strcpy(ci_p->VendorName, CS_SUN_VENDOR_DESCRIPTION);
		ci_p->Attributes |= CS_CLIENT_INFO_VALID;
		break;
	default:
		ret = CS_UNSUPPORTED_EVENT;
		break;
	}
	mutex_exit(&pcan_p->pcan_cslock);
	return (ret);
}

static int
pcan_card_insert(pcan_maci_t *pcan_p)
{
	int ret, hi, lo;
	tuple_t tuple;
	cisparse_t cisparse;
	io_req_t	io;
	irq_req_t	irq;
	config_req_t	cfg;
	cistpl_config_t config;
	cistpl_cftable_entry_t *tbl_p;
	register client_handle_t chdl = pcan_p->pcan_chdl;

	bzero(&tuple, sizeof (tuple));
	tuple.DesiredTuple = CISTPL_MANFID;
	if (ret = csx_GetFirstTuple(chdl, &tuple)) {
		cmn_err(CE_WARN, "pcan: get manufacture id failed %x\n", ret);
		goto insert_ret;
	}
	bzero(&cisparse, sizeof (cisparse));
	if (ret = csx_Parse_CISTPL_MANFID(chdl, &tuple, &cisparse.manfid)) {
		cmn_err(CE_WARN, "pcan: parse manufacture id failed %x\n", ret);
		goto insert_ret;
	}
	/* verify manufacture ID */
	PCANDBG((CE_NOTE, "pcan: manufacturer_id=%x card=%x\n",
	    cisparse.manfid.manf, cisparse.manfid.card));

	bzero(&tuple, sizeof (tuple));
	tuple.DesiredTuple = CISTPL_FUNCID;
	if (ret = csx_GetFirstTuple(chdl, &tuple)) {
		cmn_err(CE_WARN, "pcan: get function id failed %x\n", ret);
		goto insert_ret;
	}
	bzero(&cisparse, sizeof (cisparse));
	if (ret = csx_Parse_CISTPL_FUNCID(chdl, &tuple, &cisparse.funcid)) {
		cmn_err(CE_WARN, "pcan: parse function id failed %x\n", ret);
		goto insert_ret;
	}
	/* verify function ID */
	PCANDBG((CE_NOTE, "funcid=%x\n", cisparse.funcid.function));

	bzero(&tuple, sizeof (tuple));
	tuple.DesiredTuple = CISTPL_CONFIG;
	if (ret = csx_GetFirstTuple(chdl, &tuple)) {
		cmn_err(CE_WARN, "pcan: get config failed %x\n", ret);
		goto insert_ret;
	}
	bzero(&config, sizeof (config));
	if (ret = csx_Parse_CISTPL_CONFIG(chdl, &tuple, &config)) {
		cmn_err(CE_WARN, "pcan: parse config failed %x\n", ret);
		goto insert_ret;
	}
	PCANDBG((CE_NOTE,
	    "pcan: config present=%x nr=%x hr=%x regs[0]=%x base=%x last=%x\n",
	    config.present, config.nr, config.hr, config.regs[0],
	    config.base, config.last));

	hi = 0;
	lo = (int)-1;		/* really big number */
	tbl_p = &cisparse.cftable;
	tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;
	for (tbl_p->index = 0; tbl_p->index <= config.hr; ) {
		PCANDBG((CE_NOTE, "pcan: tuple idx=%x:\n", tbl_p->index));
		if (ret = csx_GetNextTuple(chdl, &tuple)) {
			cmn_err(CE_WARN, "pcan: get cftable failed %x\n", ret);
			break;
		}
		bzero((caddr_t)&cisparse, sizeof (cisparse));
		if (ret = csx_Parse_CISTPL_CFTABLE_ENTRY(chdl, &tuple, tbl_p)) {
			cmn_err(CE_WARN, "pcan: parse cftable failed%x\n", ret);
			break;
		}
		if (tbl_p->flags & CISTPL_CFTABLE_TPCE_FS_PWR &&
		    tbl_p->pd.flags & CISTPL_CFTABLE_TPCE_FS_PWR_VCC) {
			if (tbl_p->pd.pd_vcc.avgI > hi) {
				hi = tbl_p->pd.pd_vcc.avgI;
				pcan_p->pcan_config_hi = tbl_p->index;
			}
			if (tbl_p->pd.pd_vcc.avgI < lo) {
				lo = tbl_p->pd.pd_vcc.avgI;
				pcan_p->pcan_config = tbl_p->index;
			}
		}
		if (tbl_p->flags & CISTPL_CFTABLE_TPCE_DEFAULT) {
			if (tbl_p->pd.flags & CISTPL_CFTABLE_TPCE_FS_PWR_VCC)
				pcan_p->pcan_vcc = tbl_p->pd.pd_vcc.nomV;
			if (tbl_p->flags & CISTPL_CFTABLE_TPCE_FS_IO)
				pcan_p->pcan_iodecode = tbl_p->io.addr_lines;
		}
	}
	PCANDBG((CE_NOTE, "pcan: cfg_hi=%x cfg=%x vcc=%x iodecode=%x\n",
	    pcan_p->pcan_config_hi, pcan_p->pcan_config,
	    pcan_p->pcan_vcc, pcan_p->pcan_iodecode));

	bzero(&io, sizeof (io));
	io.BasePort1.base = 0;
	io.NumPorts1 = 1 << pcan_p->pcan_iodecode;
	io.Attributes1 = IO_DATA_PATH_WIDTH_16;
	io.IOAddrLines = pcan_p->pcan_iodecode;
	if (ret = csx_RequestIO(chdl, &io)) {
		cmn_err(CE_WARN, "pcan: RequestIO failed %x\n", ret);
		goto insert_ret;
	}
	pcan_p->pcan_port = io.BasePort1.handle;

	if (ret = ddi_add_softintr(DIP(pcan_p), DDI_SOFTINT_HIGH,
	    &pcan_p->pcan_softint_id, &pcan_p->pcan_ib_cookie, NULL,
	    pcan_intr, (caddr_t)pcan_p)) {
		cmn_err(CE_NOTE, "pcan: Add softintr failed\n");
		goto insert_ret;
	}
	irq.Attributes = IRQ_TYPE_EXCLUSIVE;
	irq.irq_handler = ddi_intr_hilevel(DIP(pcan_p), 0) ?
	    (csfunction_t *)pcan_intr_hi : (csfunction_t *)pcan_intr;
	irq.irq_handler_arg = pcan_p;
	if (ret = csx_RequestIRQ(chdl, &irq)) {
		cmn_err(CE_WARN, "pcan: RequestIRQ failed %x\n", ret);
		goto un_io;
	}

	bzero(&cfg, sizeof (cfg));
	cfg.Attributes = 0; /* not ready for CONF_ENABLE_IRQ_STEERING yet */
	cfg.Vcc = 50; /* pcan_vcc == 0 */
	cfg.Vpp1 = 50;
	cfg.Vpp2 = 50;
	cfg.IntType = SOCKET_INTERFACE_MEMORY_AND_IO;
	cfg.ConfigBase = config.base;
	cfg.ConfigIndex = pcan_p->pcan_config;
	cfg.Status = CCSR_IO_IS_8; /* no use */
	cfg.Present = config.present;
	pcan_p->pcan_flag |= PCAN_CARD_READY;
	if (ret = csx_RequestConfiguration(chdl, &cfg)) {
		cmn_err(CE_WARN, "pcan: RequestConfiguration failed %x\n", ret);
		goto un_irq;
	}
	return (CS_SUCCESS);
un_irq:
	(void) csx_ReleaseIRQ(chdl, &irq);
un_io:
	ddi_remove_softintr(pcan_p->pcan_softint_id);

	(void) csx_ReleaseIO(chdl, &io);
	pcan_p->pcan_port = 0;
insert_ret:
	pcan_p->pcan_flag &= ~PCAN_CARD_READY;
	return (ret);
}

/*
 * assume card is already removed, don't touch the hardware
 */
static void
pcan_card_remove(pcan_maci_t *pcan_p)
{
	int ret;
	io_req_t io;
	irq_req_t irq;

	if (!(pcan_p->pcan_flag & PCAN_CARD_READY))
		return;
	if (ret = csx_ReleaseConfiguration(pcan_p->pcan_chdl, NULL))
		cmn_err(CE_WARN, "pcan: ReleaseConfiguration failed %x\n", ret);

	bzero(&irq, sizeof (irq));
	if (ret = csx_ReleaseIRQ(pcan_p->pcan_chdl, &irq))
		cmn_err(CE_WARN, "pcan: ReleaseIRQ failed %x\n", ret);

	ddi_remove_softintr(pcan_p->pcan_softint_id);

	bzero(&io, sizeof (io));
	io.BasePort1.handle = pcan_p->pcan_port;
	io.NumPorts1 = 16;
	if (ret = csx_ReleaseIO(pcan_p->pcan_chdl, &io))
		cmn_err(CE_WARN, "pcan: Release IO failed %x\n", ret);

	pcan_p->pcan_port = 0;
	pcan_p->pcan_flag &= ~PCAN_CARD_READY;
}

/*
 * gld operation interface routines
 */
static int
pcan_start(void *arg)
{
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;

	mutex_enter(&pcan_p->pcan_glock);
	if (!(pcan_p->pcan_flag & PCAN_CARD_READY)) {
		mutex_exit(&pcan_p->pcan_glock);
		return (PCAN_FAIL);
	}
	(void) pcan_loaddef(pcan_p);
	pcan_start_locked(pcan_p);
	mutex_exit(&pcan_p->pcan_glock);
	return (PCAN_SUCCESS);
}

static void
pcan_stop(void *arg)
{
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;

	mutex_enter(&pcan_p->pcan_glock);
	if (!(pcan_p->pcan_flag & PCAN_CARD_READY)) {
		mutex_exit(&pcan_p->pcan_glock);
		return;
	}
	pcan_stop_locked(pcan_p);
	mutex_exit(&pcan_p->pcan_glock);
	if (pcan_p->pcan_connect_timeout_id != 0) {
		(void) untimeout(pcan_p->pcan_connect_timeout_id);
		pcan_p->pcan_connect_timeout_id = 0;
	}
}

/*
 * mac address can only be set in 'disable' state and
 * be effective after 'enable' state.
 */
static int
pcan_saddr(void *arg, const uint8_t *macaddr)
{
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;
	int ret = PCAN_SUCCESS;
	ether_copy(macaddr, pcan_p->pcan_mac_addr);

	mutex_enter(&pcan_p->pcan_glock);
	if (!(pcan_p->pcan_flag & PCAN_CARD_READY)) {
		ret = PCAN_FAIL;
		goto done;
	}
	ether_copy(pcan_p->pcan_mac_addr, pcan_p->an_config.an_macaddr);
	if (pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0)) {
		cmn_err(CE_WARN, "pcan set mac addr: failed\n");
		ret = PCAN_FAIL;
		goto done;
	}
	if (pcan_config_mac(pcan_p)) {
		cmn_err(CE_WARN, "pcan set mac addr: config_mac failed\n");
		ret = PCAN_FAIL;
		goto done;
	}
	if (pcan_set_cmd(pcan_p, AN_CMD_ENABLE, 0)) {
		cmn_err(CE_WARN, "pcan set mac addr: failed\n");
		ret = PCAN_FAIL;
	}
done:
	mutex_exit(&pcan_p->pcan_glock);
	return (ret);
}

/*
 * send a packet out for pccard
 */
static int
pcan_send(pcan_maci_t *pcan_p, mblk_t *mblk_p)
{
	char *buf, *buf_p;
	an_txfrm_t *frm_p;
#ifdef PCAN_SEND_DEBUG
	struct an_ltv_status radio_status;
#endif /* PCAN_SEND_DEBUG */
	uint16_t pkt_len, xmt_id, ring_idx;
	struct ieee80211_frame *wh;
	int i = 0;

	mutex_enter(&pcan_p->pcan_glock);
	if (!(pcan_p->pcan_flag & PCAN_CARD_READY)) {
		mutex_exit(&pcan_p->pcan_glock);
		freemsg(mblk_p);
		return (PCAN_SUCCESS);		/* drop packet */
	}
	if (!(pcan_p->pcan_flag & PCAN_CARD_LINKUP)) {	/* link down */
		PCANDBG((CE_NOTE, "pcan: link down, dropped\n"));
		pcan_p->glds_nocarrier++;
		mutex_exit(&pcan_p->pcan_glock);
		freemsg(mblk_p);
		return (PCAN_SUCCESS);		/* drop packet */
	}
	mutex_exit(&pcan_p->pcan_glock);
	if (pullupmsg(mblk_p, -1) == 0) {
		cmn_err(CE_NOTE, "pcan send: pullupmsg failed\n");
		freemsg(mblk_p);
		return (PCAN_SUCCESS);		/* drop packet */
	}
	wh = (struct ieee80211_frame *)mblk_p->b_rptr;

	mutex_enter(&pcan_p->pcan_txring.an_tx_lock);
	ring_idx = pcan_p->pcan_txring.an_tx_prod;
	pcan_p->pcan_txring.an_tx_prod = (ring_idx + 1) & AN_TX_RING_MASK;

	/* check whether there is a xmt buffer available */
	while ((i < AN_TX_RING_CNT) &&
	    (pcan_p->pcan_txring.an_tx_ring[ring_idx])) {
		ring_idx = pcan_p->pcan_txring.an_tx_prod;
		pcan_p->pcan_txring.an_tx_prod =
		    (ring_idx + 1) & AN_TX_RING_MASK;
		i++;
	}

	if (i == AN_TX_RING_CNT) {
		mutex_exit(&pcan_p->pcan_txring.an_tx_lock);
		PCANDBG((CE_NOTE, "pcan: ring full, retrying\n"));
		mutex_enter(&pcan_p->pcan_glock);
		pcan_p->pcan_reschedule_need = B_TRUE;
		mutex_exit(&pcan_p->pcan_glock);
		pcan_p->glds_noxmtbuf++;
		return (PCAN_FAIL);
	}
	xmt_id = pcan_p->pcan_txring.an_tx_fids[ring_idx];
	pcan_p->pcan_txring.an_tx_ring[ring_idx] = xmt_id;
	mutex_exit(&pcan_p->pcan_txring.an_tx_lock);

	buf = kmem_zalloc(PCAN_NICMEM_SZ, KM_SLEEP); /* too big for stack */
	buf_p = (ulong_t)buf & 1 ? buf + 1 : buf;	/* 16-bit round up */
	frm_p = (an_txfrm_t *)buf_p;

#ifdef DEBUG
	if (pcan_debug & PCAN_DBG_SEND) {
		cmn_err(CE_NOTE, "pcan send: packet from plugin");
		for (i = 0; i < MBLKL(mblk_p); i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((unsigned char *)mblk_p->b_rptr + i));
	}
#endif
	pkt_len = msgdsize(mblk_p);
	if (pkt_len > PCAN_NICMEM_SZ - sizeof (an_txfrm_t)) {
		cmn_err(CE_WARN, "pcan send: mblk is too long");
		kmem_free(buf, PCAN_NICMEM_SZ);
		freemsg(mblk_p);
		return (PCAN_SUCCESS);		/* drop packet */
	}
	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) !=
	    IEEE80211_FC1_DIR_TODS) {
		kmem_free(buf, PCAN_NICMEM_SZ);
		freemsg(mblk_p);
		return (PCAN_SUCCESS);		/* drop packet */
	}

	/* initialize xmt frame header, payload_len must be stored in LE */
	bzero(frm_p, sizeof (an_txfrm_t) + 2);
	frm_p->an_tx_ctl = AN_TXCTL_8023;

	/*
	 * mblk sent down from plugin includes station mode 802.11 frame and
	 * llc, so we here need to remove them and add an ethernet header.
	 */
	pkt_len = pkt_len - (sizeof (*wh) + sizeof (struct ieee80211_llc))
	    + 2;
	bcopy(wh->i_addr3, buf_p + 0x38, ETHERADDRL); /* dst macaddr */
	bcopy(wh->i_addr2, buf_p + 0x3e, ETHERADDRL); /* src macaddr */
	*((uint16_t *)(buf_p + 0x36)) = pkt_len;
	bcopy(mblk_p->b_rptr + sizeof (*wh) + sizeof (struct ieee80211_llc)
	    - 2, buf_p + 0x44, pkt_len);

	if (pkt_len & 1) {	/* round up to 16-bit boundary and pad 0 */
		buf_p[pkt_len + 0x44] = 0;
		pkt_len++;
	}
	ASSERT(pkt_len <= PCAN_NICMEM_SZ);
#ifdef DEBUG
	if (pcan_debug & PCAN_DBG_SEND) {
		cmn_err(CE_NOTE, "pcan send: packet to hardware--pkt_len=%x",
		    pkt_len);
		for (i = 0; i < pkt_len + 4; i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((unsigned char *)buf_p + 0x36 + i));
	}
#endif
	mutex_enter(&pcan_p->pcan_glock);
	(void) WRCH1(pcan_p, xmt_id, 0, (uint16_t *)buf_p, 0x38); /* frm */
	(void) WRPKT(pcan_p, xmt_id, 0x38, (uint16_t *)(buf_p + 0x38),
	    pkt_len + 12);
	ring_idx = pcan_set_cmd(pcan_p, AN_CMD_TX, xmt_id);
	mutex_exit(&pcan_p->pcan_glock);

	PCANDBG((CE_NOTE, "pcan: pkt_len=0x44+%x=%x xmt=%x ret=%x\n",
	    pkt_len, 0x44 + pkt_len, xmt_id, ring_idx));
	kmem_free(buf, PCAN_NICMEM_SZ);
#ifdef PCAN_SEND_DEBUG
	if (pkt_len = pcan_status_ltv(PCAN_READ_LTV, pcan_p, &radio_status)) {
		PCANDBG((CE_NOTE, "pcan: bad radio status %x\n", pkt_len));
	} else {
		PCANDBG((CE_NOTE, "pcan: radio status:\n"));
	}
#endif /* PCAN_SEND_DEBUG */
	if (ring_idx)
		return (PCAN_FAIL);
	else {
		freemsg(mblk_p);
		return (PCAN_SUCCESS);
	}
}

/*
 * send a packet out for PCI/MiniPCI card
 */
static int
pcian_send(pcan_maci_t *pcan_p, mblk_t *mblk_p)
{
	char *buf;
	uint16_t pkt_len = msgdsize(mblk_p), ring_idx;
	uint32_t i;
	struct ieee80211_frame *wh;
	struct an_card_tx_desc an_tx_desc;

	ring_idx = pcan_p->pcan_txring.an_tx_prod;

	mutex_enter(&pcan_p->pcan_glock);
	if (!(pcan_p->pcan_flag & PCAN_CARD_LINKUP)) {	/* link down */
		mutex_exit(&pcan_p->pcan_glock);
		pcan_p->glds_nocarrier++;
		freemsg(mblk_p);
		return (PCAN_SUCCESS);		/* drop packet */
	}
	mutex_exit(&pcan_p->pcan_glock);
	if (pullupmsg(mblk_p, -1) == 0) {
		cmn_err(CE_NOTE, "pcan(pci) send: pullupmsg failed\n");
		freemsg(mblk_p);
		return (PCAN_SUCCESS);		/* drop packet */
	}
	wh = (struct ieee80211_frame *)mblk_p->b_rptr;

	mutex_enter(&pcan_p->pcan_txring.an_tx_lock);
	if ((pcan_p->pcan_flag & PCAN_CARD_SEND) &&
	    (ring_idx == pcan_p->pcan_txring.an_tx_cons)) {
		pcan_p->glds_noxmtbuf++;
		pcan_p->pcan_reschedule_need = B_TRUE;
		mutex_exit(&pcan_p->pcan_txring.an_tx_lock);
		return (PCAN_FAIL);
	}
	mutex_exit(&pcan_p->pcan_txring.an_tx_lock);

#ifdef DEBUG
	if (pcan_debug & PCAN_DBG_SEND) {
		cmn_err(CE_NOTE, "pcan(pci) send: packet from plugin");
		for (i = 0; i < MBLKL(mblk_p); i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((unsigned char *)mblk_p->b_rptr + i));
	}
#endif
	mutex_enter(&pcan_p->pcan_glock);

	buf = pcan_p->pcan_tx[ring_idx].dma_virtaddr;
	bzero(buf, AN_TX_BUFFER_SIZE);

	/*
	 * mblk sent down from plugin includes station mode 802.11 frame and
	 * llc, so we here need to remove them and add an ethernet header.
	 */
	*((uint16_t *)(buf + 8)) = htons(AN_TXCTL_8023);
	pkt_len = pkt_len - (sizeof (*wh) + sizeof (struct ieee80211_llc))
	    + 2;
	bcopy(wh->i_addr3, buf + 0x38, ETHERADDRL); /* dst macaddr */
	bcopy(wh->i_addr2, buf + 0x3e, ETHERADDRL); /* src macaddr */
	*((uint16_t *)(buf + 0x36)) = pkt_len;
	bcopy(mblk_p->b_rptr + sizeof (*wh) + sizeof (struct ieee80211_llc)
	    - 2, buf + 0x44, pkt_len);

#ifdef DEBUG
	if (pcan_debug & PCAN_DBG_SEND) {
		cmn_err(CE_NOTE, "pcan(pci) send: packet to hardware "
		    "pkt_len=%x", pkt_len);
		for (i = 0; i < pkt_len + 14; i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((unsigned char *)buf + 0x36 + i));
	}
#endif
	bzero(&an_tx_desc, sizeof (an_tx_desc));
	an_tx_desc.an_offset = 0;
	an_tx_desc.an_eoc = (ring_idx == (AN_MAX_TX_DESC-1) ? 1 : 0);
	an_tx_desc.an_valid = 1;
	an_tx_desc.an_len =  0x44 + pkt_len;
	an_tx_desc.an_phys  = pcan_p->pcan_tx[ring_idx].dma_physaddr;
	for (i = 0; i < sizeof (an_tx_desc) / 4; i++) {
		PCAN_AUX_PUT32(pcan_p, AN_TX_DESC_OFFSET +
		    (ring_idx * sizeof (an_tx_desc)) + (i * 4),
		    ((uint32_t *)&an_tx_desc)[i]);
	}

	mutex_enter(&pcan_p->pcan_txring.an_tx_lock);
	pcan_p->pcan_txring.an_tx_prod = (ring_idx + 1) % AN_MAX_TX_DESC;
	pcan_p->pcan_flag |= PCAN_CARD_SEND;
	PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_ALLOC);
	mutex_exit(&pcan_p->pcan_txring.an_tx_lock);

	freemsg(mblk_p);
	mutex_exit(&pcan_p->pcan_glock);
	return (PCAN_SUCCESS);
}

static mblk_t *
pcan_tx(void *arg, mblk_t *mp)
{
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;
	mblk_t *next;
	int ret = 0;

	ASSERT(mp != NULL);
	mutex_enter(&pcan_p->pcan_glock);
	if ((pcan_p->pcan_flag & (PCAN_CARD_LINKUP | PCAN_CARD_READY)) !=
	    (PCAN_CARD_LINKUP | PCAN_CARD_READY)) {
		mutex_exit(&pcan_p->pcan_glock);
		return (mp);
	}
	mutex_exit(&pcan_p->pcan_glock);
	while (mp != NULL) {
		next =  mp->b_next;
		mp->b_next = NULL;

		if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
			ret = pcian_send(pcan_p, mp);
		} else if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
			ret = pcan_send(pcan_p, mp);
		}
		if (ret) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

/*
 * this driver is porting from freebsd, the code in freebsd
 * doesn't show how to set promiscous mode.
 */
/*ARGSUSED*/
static int
pcan_prom(void *arg, boolean_t on)
{
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;
	int ret = PCAN_SUCCESS;

	mutex_enter(&pcan_p->pcan_glock);
	if (!(pcan_p->pcan_flag & PCAN_CARD_READY)) {
		ret = PCAN_FAIL;
	}
	mutex_exit(&pcan_p->pcan_glock);
	return (ret);
}

/*ARGSUSED*/
static int
pcan_gstat(void *arg, uint_t statitem, uint64_t *val)
{
	uint16_t i;
	int ret = PCAN_SUCCESS;
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;
	uint64_t *cntr_p = pcan_p->pcan_cntrs_s;

	PCANDBG((CE_NOTE, "pcan: gstat called\n"));

	mutex_enter(&pcan_p->pcan_glock);
	if (!(pcan_p->pcan_flag & PCAN_CARD_READY)) {
		ret = PCAN_FAIL;
		goto done;
	}
	if (pcan_get_ltv(pcan_p, sizeof (pcan_p->an_stats),
	    AN_RID_16BITS_DELTACLR, (uint16_t *)&pcan_p->an_stats)) {
		cmn_err(CE_WARN, "pcan kstat: get ltv(32 delta statistics)"
		    " failed \n");
		ret = PCAN_FAIL;
		goto done;
	}
	for (i = 0; i < ANC_STAT_CNT; i++) {
		cntr_p[i] += *((uint16_t *)&pcan_p->an_stats + 1 + i);
	}
	if (pcan_status_ltv(PCAN_READ_LTV, pcan_p, &pcan_p->an_status)) {
		cmn_err(CE_WARN, "pcan kstat: read status failed \n");
		ret = PCAN_FAIL;
		goto done;
	}

	switch (statitem) {
	case MAC_STAT_IFSPEED:
		*val = 500000 * pcan_p->an_status.an_cur_tx_rate;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = pcan_p->glds_noxmtbuf;
		break;
	case MAC_STAT_NORCVBUF:
		*val = pcan_p->glds_norcvbuf;
		break;
	case MAC_STAT_IERRORS:
		*val = cntr_p[ANC_RX_OVERRUNS] +
		    cntr_p[ANC_RX_PLCP_CSUM_ERRS] +
		    cntr_p[ANC_RX_PLCP_FORMAT_ERRS] +
		    cntr_p[ANC_RX_PLCP_LEN_ERRS] +
		    cntr_p[ANC_RX_MAC_CRC_ERRS] +
		    cntr_p[ANC_RX_WEP_ERRS];
		break;
	case MAC_STAT_OERRORS:
		*val = cntr_p[ANC_TX_HOST_FAILED];
		break;
	case MAC_STAT_RBYTES:
		*val = cntr_p[ANC_HOST_RX_BYTES];
		break;
	case MAC_STAT_IPACKETS:
		*val = cntr_p[ANC_RX_HOST_UCASTS];
		break;
	case MAC_STAT_OBYTES:
		*val = cntr_p[ANC_HOST_TX_BYTES];
		break;
	case MAC_STAT_OPACKETS:
		*val = cntr_p[ANC_TX_HOST_UCASTS];
		break;
	case WIFI_STAT_TX_FAILED:
		*val = cntr_p[ANC_TX_HOST_FAILED];
		break;
	case WIFI_STAT_TX_RETRANS:
		*val = cntr_p[ANC_HOST_RETRIES];
		break;
	case WIFI_STAT_FCS_ERRORS:
		*val = cntr_p[ANC_RX_MAC_CRC_ERRS];
		break;
	case WIFI_STAT_WEP_ERRORS:
		*val = cntr_p[ANC_RX_WEP_ERRS];
		break;
	case WIFI_STAT_MCAST_TX:
		*val = cntr_p[ANC_TX_HOST_MCASTS];
		break;
	case WIFI_STAT_MCAST_RX:
		*val = cntr_p[ANC_RX_HOST_MCASTS];
		break;
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_RX_FRAGS:
		*val = 0;
		break;
	case WIFI_STAT_RTS_SUCCESS:
		*val = cntr_p[ANC_TX_RTS_OK];
		break;
	case WIFI_STAT_RTS_FAILURE:
		*val = cntr_p[ANC_NO_CTS];
		break;
	case WIFI_STAT_ACK_FAILURE:
		*val = cntr_p[ANC_NO_ACK];
		break;
	case WIFI_STAT_RX_DUPS:
		*val = cntr_p[ANC_RX_DUPS];
		break;
	default:
		ret = ENOTSUP;
	}


done:
	mutex_exit(&pcan_p->pcan_glock);
	return (ret);
}

/*
 * this driver is porting from freebsd, the code in freebsd
 * doesn't show how to set multi address.
 */
/*ARGSUSED*/
static int
pcan_sdmulti(void *arg, boolean_t add, const uint8_t *eth_p)
{
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;

	mutex_enter(&pcan_p->pcan_glock);
	if (!(pcan_p->pcan_flag & PCAN_CARD_READY)) {
		mutex_exit(&pcan_p->pcan_glock);
		return (PCAN_FAIL);
	}
	mutex_exit(&pcan_p->pcan_glock);
	return (PCAN_SUCCESS);
}

static uint_t
pcan_info_softint(caddr_t arg)
{
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;
	wifi_data_t wd = { 0 };
	uint16_t link;
	uint32_t link_up;

	mutex_enter(&pcan_p->pcan_glock);
	if (pcan_p->pcan_info_softint_pending != 1) {
		mutex_exit(&pcan_p->pcan_glock);
		return (DDI_INTR_UNCLAIMED);
	}

	PCAN_READ(pcan_p, AN_LINKSTAT(pcan_p), link);
	link_up = pcan_p->pcan_flag & PCAN_CARD_LINKUP;
	if ((link == AN_LINKSTAT_ASSOCIATED) && !link_up) {
		pcan_p->pcan_flag |= PCAN_CARD_LINKUP;
		mutex_exit(&pcan_p->pcan_glock);
		if (pcan_p->pcan_connect_timeout_id != 0) {
			(void) untimeout(pcan_p->pcan_connect_timeout_id);
			pcan_p->pcan_connect_timeout_id = 0;
		}
		mac_link_update(GLD3(pcan_p), LINK_STATE_UP);
		mutex_enter(&pcan_p->pcan_glock);
		(void) pcan_status_ltv(PCAN_READ_LTV, pcan_p,
		    &pcan_p->an_status);
		bcopy(pcan_p->an_status.an_cur_bssid, wd.wd_bssid, 6);
		wd.wd_secalloc = WIFI_SEC_NONE;
		wd.wd_opmode = IEEE80211_M_STA;
		(void) mac_pdata_update(pcan_p->pcan_mh, &wd,
		    sizeof (wd));
#ifdef DEBUG
		if (pcan_debug & PCAN_DBG_LINKINFO) {
			cmn_err(CE_NOTE, "pcan: link Up, chan=%d, "
			    "ssid=\"%s\""
			    " (%02x:%02x:%02x:%02x:%02x:%02x)\n",
			    pcan_p->an_status.an_channel_set,
			    pcan_p->an_status.an_ssid,
			    pcan_p->an_status.an_cur_bssid[0],
			    pcan_p->an_status.an_cur_bssid[1],
			    pcan_p->an_status.an_cur_bssid[2],
			    pcan_p->an_status.an_cur_bssid[3],
			    pcan_p->an_status.an_cur_bssid[4],
			    pcan_p->an_status.an_cur_bssid[5]);
		}
#endif
	}
	if ((link != AN_LINKSTAT_ASSOCIATED) && link_up) {
		pcan_p->pcan_flag &= ~PCAN_CARD_LINKUP;
#ifdef DEBUG
		if (pcan_debug & PCAN_DBG_LINKINFO) {
			cmn_err(CE_NOTE, "pcan: link Down 0x%x\n", link);
		}
#endif
		if (link != AN_LINKSTAT_SYNCLOST_HOSTREQ) {
			pcan_p->pcan_connect_timeout_id =
			    timeout(pcan_connect_timeout,
			    pcan_p, drv_usectohz(1000));
		}
		mutex_exit(&pcan_p->pcan_glock);
		mac_link_update(GLD3(pcan_p), LINK_STATE_DOWN);
		mutex_enter(&pcan_p->pcan_glock);
	}

	pcan_p->pcan_info_softint_pending = 0;
	mutex_exit(&pcan_p->pcan_glock);
	return (DDI_INTR_CLAIMED);
}

static uint_t
pcan_intr(caddr_t arg)
{
	uint16_t stat;
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;

	mutex_enter(&pcan_p->pcan_glock);
	if ((pcan_p->pcan_flag & (PCAN_CARD_READY | PCAN_CARD_INTREN)) !=
	    (PCAN_CARD_READY | PCAN_CARD_INTREN)) {
		mutex_exit(&pcan_p->pcan_glock);
		return (DDI_INTR_UNCLAIMED);
	}
	PCAN_READ(pcan_p, AN_EVENT_STAT(pcan_p), stat);

	if (!(stat & AN_INTRS(pcan_p)) || stat == AN_EV_ALL) {
		mutex_exit(&pcan_p->pcan_glock);
		return (DDI_INTR_UNCLAIMED);
	}

	PCAN_DISABLE_INTR(pcan_p);
	PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), ~AN_INTRS(pcan_p));

	PCANDBG((CE_NOTE, "pcan intr: stat=%x pcan_flags=%x\n", stat,
	    pcan_p->pcan_flag));

	if (stat & AN_EV_AWAKE) {
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_AWAKE);
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_AWAKE);
	}
	if (stat & AN_EV_LINKSTAT) {
		pcan_p->pcan_info_softint_pending = 1;
		ddi_trigger_softintr(pcan_p->pcan_info_softint_id);
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_LINKSTAT);
	}
	if (stat & AN_EV_RX) {
		if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
			pcian_rcv(pcan_p);
		} else if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
			pcan_rcv(pcan_p);
		}
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_RX);
	}
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		if (stat & AN_EV_TX_CPY) {
			(void) pcan_txdone(pcan_p, stat & AN_EV_TX_CPY);
			if (pcan_p->pcan_reschedule_need == B_TRUE) {
				mac_tx_update(GLD3(pcan_p));
				pcan_p->pcan_reschedule_need = B_FALSE;
			}
			PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_TX_CPY);
	}
	}
	if (stat & AN_EV_TX) {
		if (pcan_txdone(pcan_p, stat & AN_EV_TX) == 0) {
			if (pcan_p->pcan_reschedule_need == B_TRUE) {
				mac_tx_update(GLD3(pcan_p));
				pcan_p->pcan_reschedule_need = B_FALSE;
			}
		}
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_TX);
	}
	if (stat & AN_EV_TX_EXC) {
		if (pcan_txdone(pcan_p, stat & AN_EV_TX_EXC) == 0) {
			if (pcan_p->pcan_reschedule_need == B_TRUE) {
				mutex_exit(&pcan_p->pcan_glock);
				mac_tx_update(GLD3(pcan_p));
				mutex_enter(&pcan_p->pcan_glock);
				pcan_p->pcan_reschedule_need = B_FALSE;
			}
		}
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_TX_EXC);
	}
	if (stat & AN_EV_ALLOC) {
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_ALLOC);
		PCANDBG((CE_NOTE, "pcan intr: nicmem alloc done\n"));
	}
	if (stat & AN_EV_MIC) {
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_MIC);
	}
	PCAN_ENABLE_INTR(pcan_p);
	mutex_exit(&pcan_p->pcan_glock);
	return (DDI_INTR_CLAIMED);
}

static uint_t
pcan_intr_hi(caddr_t arg)
{
	uint16_t stat;
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;

	mutex_enter(&pcan_p->pcan_glock);
	if ((pcan_p->pcan_flag & (PCAN_CARD_READY | PCAN_CARD_INTREN)) !=
	    (PCAN_CARD_READY | PCAN_CARD_INTREN)) {
		mutex_exit(&pcan_p->pcan_glock);
		return (DDI_INTR_UNCLAIMED);
	}
	PCAN_READ(pcan_p, AN_EVENT_STAT(pcan_p), stat);
	PCANDBG((CE_NOTE, "pcan intr(hi): stat=%x pcan_flags=%x\n", stat,
	    pcan_p->pcan_flag));

	if (!(stat & AN_INTRS(pcan_p)) || stat == AN_EV_ALL) {
		mutex_exit(&pcan_p->pcan_glock);
		return (DDI_INTR_UNCLAIMED);
	}
	/* disable interrupt without ack */
	PCAN_WRITE(pcan_p, AN_INT_EN(pcan_p), 0);
	mutex_exit(&pcan_p->pcan_glock);
	ddi_trigger_softintr(pcan_p->pcan_softint_id);
	return (DDI_INTR_CLAIMED);
}

/*
 * retrieve data from pccard
 */
static void
pcan_rcv(pcan_maci_t *pcan_p)
{
	uint16_t id, off, ret, data_len, pkt_stat, frm_ctl;
	an_rxfrm_t frm;
	struct ieee80211_llc *llc;

	mblk_t *mp = allocb(PCAN_NICMEM_SZ, BPRI_MED);
	if (!mp) {
		cmn_err(CE_WARN, "pcan: failed to alloc rcv buf");
		pcan_p->glds_norcvbuf++;
		return;
	}
	ASSERT(mp->b_rptr == mp->b_wptr);

	PCAN_READ(pcan_p, AN_RX_FID, id);
	if (id == AN_INVALID_FID) {
		PCANDBG((CE_NOTE, "pcan rcv: can't get rx_fid\n"));
		pcan_p->glds_norcvbuf++;
		ret = PCAN_FAIL;
		goto done;
	}
	if (ret = RDCH0(pcan_p, id, 0, (uint16_t *)&frm, sizeof (frm))) {
		PCANDBG((CE_NOTE, "pcan rcv: read frm err %x\n", ret));
		goto done;
	}
	off = sizeof (frm);
	if (frm.an_rx_status) {
		PCANDBG((CE_NOTE, "pcan rcv: err stat %x\n", frm.an_rx_status));
		ret = frm.an_rx_status;
		goto done;
	}
	PCANDBG((CE_NOTE, "pcan rcv: payload_len=%x gap_len=%x\n",
	    frm.an_rx_payload_len, frm.an_gaplen));
	if (frm.an_rx_payload_len > PCAN_NICMEM_SZ ||
	    frm.an_gaplen > AN_RXGAP_MAX) {
		PCANDBG((CE_NOTE, "pcan rcv: bad len\n"));
		ret = PCAN_FAIL;
		goto done;
	}
	if (ret = RDCH0(pcan_p, id, off, &pkt_stat, sizeof (pkt_stat))) {
		PCANDBG((CE_NOTE, "pcan rcv: pkt status err %x\n", ret));
		ret = PCAN_FAIL;
		goto done;
	}
	off += sizeof (pkt_stat);
	if (ret = RDCH0(pcan_p, id, off, &data_len, sizeof (data_len))) {
		PCANDBG((CE_NOTE, "pcan rcv: payload len err %x\n", ret));
		ret = PCAN_FAIL;
		goto done;
	}
	off += sizeof (data_len);
	off += ETHERADDRL << 1;
	PCANDBG((CE_NOTE, "pcan rcv: pkt_stat=%x payload_len=%x+c off=%x\n",
	    pkt_stat, data_len, off));

#ifdef DEBUG
	if (pcan_debug & PCAN_DBG_RCV) {
		int i;
		cmn_err(CE_NOTE, "pcan rcv: frm header\n");
		for (i = 0; i < sizeof (frm); i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((uint8_t *)&frm + i));
	}
#endif
	/*
	 * this driver deal with WEP by itself. so plugin always thinks no wep.
	 */
	frm.an_frame_ctl &= ~(IEEE80211_FC1_WEP << 8);
	frm_ctl = frm.an_frame_ctl;
	PCAN_SWAP16((uint16_t *)&frm.an_frame_ctl,
	    sizeof (struct ieee80211_frame));
	/*
	 * discard those frames which are not from the AP we connect or
	 * without 'ap->sta' direction
	 */
	if (((pcan_p->an_config.an_opmode == AN_OPMODE_INFR_STATION)) &&
	    ((((frm_ctl >> 8) & IEEE80211_FC1_DIR_MASK) !=
	    IEEE80211_FC1_DIR_FROMDS) ||
	    bcmp(pcan_p->an_status.an_cur_bssid, frm.an_addr2, 6) != 0)) {
		ret = PCAN_FAIL;
		goto done;
	}
	bcopy(&frm.an_frame_ctl, mp->b_wptr,
	    sizeof (struct ieee80211_frame));
	mp->b_wptr += sizeof (struct ieee80211_frame);

	/* the plugin need a llc here */
	llc = (struct ieee80211_llc *)mp->b_wptr;
	llc->illc_dsap = llc->illc_ssap = AN_SNAP_K1;
	llc->illc_control = AN_SNAP_CONTROL;
	bzero(llc->illc_oc, sizeof (llc->illc_oc));
	mp->b_wptr += AN_SNAPHDR_LEN;

	/* read in the rest of data */
	data_len += data_len & 1;	/* adjust to word boundary */
	if (data_len > MBLKSIZE(mp)) {
		cmn_err(CE_NOTE, "pcan rcv: data over length%x\n", data_len);
		ret = PCAN_FAIL;
		goto done;
	}

	if (ret = RDPKT(pcan_p, id, off, (uint16_t *)mp->b_wptr, data_len)) {
		PCANDBG((CE_NOTE, "pcan rcv: err read data %x\n", ret));
	}
done:
	if (ret) {
		PCANDBG((CE_NOTE, "pcan rcv: rd data %x\n", ret));
		freemsg(mp);
		return;
	}
	mp->b_wptr += data_len;
#ifdef DEBUG
	if (pcan_debug & PCAN_DBG_RCV) {
		int i;
		cmn_err(CE_NOTE, "pcan rcv: len=0x%x\n", data_len);
		for (i = 0; i < data_len + sizeof (frm); i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((uint8_t *)mp->b_rptr + i));
	}
#endif
	mutex_exit(&pcan_p->pcan_glock);
	mac_rx(GLD3(pcan_p), NULL, mp);
	mutex_enter(&pcan_p->pcan_glock);
}

/*
 * retrieve data from mini-pci card
 */
static void
pcian_rcv(pcan_maci_t *pcan_p)
{
	struct an_card_rx_desc an_rx_desc;
	char *buf;
	uint16_t ret = 0, data_len;
	int i, j;
	struct ieee80211_frame *frm;
	struct ieee80211_llc *llc;

	mblk_t *mp = allocb(AN_RX_BUFFER_SIZE, BPRI_MED);
	if (!mp) {
		cmn_err(CE_WARN, "pcan(pci): failed to alloc rcv buf");
		pcan_p->glds_norcvbuf++;
		return;
	}
	ASSERT(mp->b_rptr == mp->b_wptr);

	for (i = 0; i < sizeof (an_rx_desc) / 4; i++)
		PCAN_AUX_GET32(pcan_p, AN_RX_DESC_OFFSET + (i * 4),
		    ((uint32_t *)&an_rx_desc)[i]);
	if (an_rx_desc.an_done && !an_rx_desc.an_valid) {
		buf = pcan_p->pcan_rx[0].dma_virtaddr;
		data_len = an_rx_desc.an_len;
#ifdef DEBUG
		if (pcan_debug & PCAN_DBG_RCV) {
			cmn_err(CE_NOTE, "pcan(pci) rcv: data_len=%x",
			    data_len);
			for (j = 0; j < data_len + 14; j++)
				cmn_err(CE_NOTE, "pcan_rcv %d: %x", j,
				    *((uint8_t *)buf + j));
		}
#endif
		if (data_len > MBLKSIZE(mp)) {
			cmn_err(CE_NOTE, "pcan(pci) rcv: data over length%x\n",
			    data_len);
			ret = PCAN_FAIL;
			goto done;
		}
		/*
		 * minipci card receive an ethernet frame, so assembly a 802.11
		 * frame here manually.
		 */
		frm = (struct ieee80211_frame *)mp->b_wptr;
		bzero(frm, sizeof (*frm));
		frm->i_fc[0] |= IEEE80211_FC0_TYPE_DATA;
		frm->i_fc[1] |= IEEE80211_FC1_DIR_FROMDS;
		bcopy(pcan_p->an_status.an_cur_bssid, frm->i_addr2, 6);
		bcopy(buf, frm->i_addr1, 6);
		bcopy(buf + 6, frm->i_addr3, 6);
		mp->b_wptr += sizeof (struct ieee80211_frame);

		llc = (struct ieee80211_llc *)mp->b_wptr;
		llc->illc_dsap = llc->illc_ssap = AN_SNAP_K1;
		llc->illc_control = AN_SNAP_CONTROL;
		bzero(llc->illc_oc, sizeof (llc->illc_oc));
		mp->b_wptr += AN_SNAPHDR_LEN;

		bcopy(buf + 12, mp->b_wptr, data_len);
		mp->b_wptr += data_len;
#ifdef DEBUG
		if (pcan_debug & PCAN_DBG_RCV) {
			int i;
			cmn_err(CE_NOTE, "pcan(pci) rcv: len=0x%x\n", data_len);
			for (i = 0; i < data_len + sizeof (*frm)
			    + sizeof (*llc); i++)
				cmn_err(CE_NOTE, "%x: %x\n", i,
				    *((uint8_t *)mp->b_rptr + i));
		}
#endif
		mutex_exit(&pcan_p->pcan_glock);
		mac_rx(GLD3(pcan_p), NULL, mp);
		mutex_enter(&pcan_p->pcan_glock);
	}
done:
	bzero(&an_rx_desc, sizeof (an_rx_desc));
	an_rx_desc.an_valid = 1;
	an_rx_desc.an_len = AN_RX_BUFFER_SIZE;
	an_rx_desc.an_done = 0;
	an_rx_desc.an_phys = pcan_p->pcan_rx[0].dma_physaddr;

	for (i = 0; i < sizeof (an_rx_desc) / 4; i++)
		PCAN_AUX_PUT32(pcan_p, AN_RX_DESC_OFFSET + (i * 4),
		    ((uint32_t *)&an_rx_desc)[i]);
	if (ret) {
		freemsg(mp);
	}
}

/*ARGSUSED*/
static uint32_t
pcan_txdone(pcan_maci_t *pcan_p, uint16_t err)
{
	uint16_t fid, i, ring_idx;
	uint32_t ret = 0;

	PCAN_READ(pcan_p, AN_TX_CMP_FID(pcan_p), fid);
	mutex_enter(&pcan_p->pcan_txring.an_tx_lock);
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		if (pcan_p->pcan_flag & PCAN_CARD_SEND) {
			ring_idx = pcan_p->pcan_txring.an_tx_cons;
			pcan_p->pcan_txring.an_tx_cons =
			    (ring_idx + 1) % AN_MAX_TX_DESC;
			if (pcan_p->pcan_txring.an_tx_prod ==
			    pcan_p->pcan_txring.an_tx_cons) {
				pcan_p->pcan_flag &= ~PCAN_CARD_SEND;
			}
		}
		ret = 0;
	} else if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
		for (i = 0; i < AN_TX_RING_CNT; i++) {
			if (fid == pcan_p->pcan_txring.an_tx_ring[i]) {
				pcan_p->pcan_txring.an_tx_ring[i] = 0;
				break;
			}
		}
		pcan_p->pcan_txring.an_tx_cons =
		    (pcan_p->pcan_txring.an_tx_cons + 1) & AN_TX_RING_MASK;
		ret = (i == AN_TX_RING_CNT ? 1 : 0);
	}
	mutex_exit(&pcan_p->pcan_txring.an_tx_lock);
	return (ret);
}

/*
 * delay in which the mutex is not hold.
 * assuming the mutex has already been hold.
 */
static void
pcan_delay(pcan_maci_t *pcan_p, clock_t microsecs)
{
	ASSERT(mutex_owned(&pcan_p->pcan_glock));

	mutex_exit(&pcan_p->pcan_glock);
	delay(drv_usectohz(microsecs));
	mutex_enter(&pcan_p->pcan_glock);
}

static void
pcan_reset_backend(pcan_maci_t *pcan_p, int timeout)
{
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		(void) pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0);
		PCAN_DISABLE_INTR_CLEAR(pcan_p);
		(void) pcan_set_cmd(pcan_p, AN_CMD_FW_RESTART, 0);
		(void) pcan_set_cmd(pcan_p, AN_CMD_NOOP2, 0);
		(void) pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0);
	} else if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
		(void) pcan_set_cmd0(pcan_p, AN_CMD_DISABLE, 0, 0, 0);
		(void) pcan_set_cmd0(pcan_p, AN_CMD_NOOP2, 0, 0, 0);
		PCAN_WRITE(pcan_p, AN_COMMAND(pcan_p), AN_CMD_FW_RESTART);
		pcan_delay(pcan_p, timeout); /* wait for firmware restart */

		(void) pcan_set_cmd(pcan_p, AN_CMD_NOOP, 0);
		(void) pcan_set_cmd0(pcan_p, AN_CMD_DISABLE, 0, 0, 0);

		PCAN_DISABLE_INTR_CLEAR(pcan_p);
	}
}

/*
 * set command without the need of ACK.
 */
static uint16_t
pcan_set_cmd0(pcan_maci_t *pcan_p, uint16_t cmd, uint16_t p0,
    uint16_t p1, uint16_t p2)
{
	int i;
	uint16_t stat, r0, r1, r2;

	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		for (i = 0; i < AN_TIMEOUT; i++) {
			PCAN_READ(pcan_p, AN_COMMAND(pcan_p), stat);
			if (!(stat & AN_CMD_BUSY))
				break;
		}
		if (i == AN_TIMEOUT) {
			PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p),
			    AN_EV_CLR_STUCK_BUSY);
			PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_CMD);
			drv_usecwait(10);
		}
		PCAN_WRITE(pcan_p, AN_PARAM0(pcan_p), p0);
		PCAN_WRITE(pcan_p, AN_PARAM1(pcan_p), p1);
		PCAN_WRITE(pcan_p, AN_PARAM2(pcan_p), p2);
	}
	PCAN_WRITE(pcan_p, AN_COMMAND(pcan_p), cmd);
	for (i = 0; i < AN_TIMEOUT; i++) {
		PCAN_READ(pcan_p, AN_EVENT_STAT(pcan_p), stat);
		if (stat & AN_EV_CMD)
			break;
	}
	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		PCAN_READ(pcan_p, AN_RESP0(pcan_p), r0);
		PCAN_READ(pcan_p, AN_RESP1(pcan_p), r1);
		PCAN_READ(pcan_p, AN_RESP2(pcan_p), r2);
		PCAN_READ(pcan_p, AN_COMMAND(pcan_p), stat);
		if (stat & AN_CMD_BUSY)
			PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p),
			    AN_EV_CLR_STUCK_BUSY);
		PCANDBG((CE_NOTE, "pcan set_cmd0: "
		    "stat=%x, r0=%x, r1=%x, r2=%x\n",
		    stat, r0, r1, r2));
	}
	PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_CMD);
	return (i == AN_TIMEOUT ? PCAN_TIMEDOUT_ACCESS : PCAN_SUCCESS);
}

static uint16_t
pcan_set_cmd(pcan_maci_t *pcan_p, uint16_t cmd, uint16_t param)
{
	int i;
	uint16_t stat, r0, r1, r2;
	uint16_t ret;

	if (((cmd == AN_CMD_ENABLE) &&
	    ((pcan_p->pcan_flag & PCAN_ENABLED) != 0)) ||
	    ((cmd == AN_CMD_DISABLE) &&
	    ((pcan_p->pcan_flag & PCAN_ENABLED) == 0)))
		return (PCAN_SUCCESS);
	for (i = 0; i < AN_TIMEOUT; i++) {
		PCAN_READ(pcan_p, AN_COMMAND(pcan_p), stat);
		if (!(stat & AN_CMD_BUSY)) {
			break;
		}
	}
	if (i == AN_TIMEOUT) {
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_CLR_STUCK_BUSY);
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_CMD);
		drv_usecwait(10);
	}

	PCAN_WRITE(pcan_p, AN_PARAM0(pcan_p), param);
	PCAN_WRITE(pcan_p, AN_PARAM1(pcan_p), 0);
	PCAN_WRITE(pcan_p, AN_PARAM2(pcan_p), 0);
	PCAN_WRITE(pcan_p, AN_COMMAND(pcan_p), cmd);

	for (i = 0; i < AN_TIMEOUT; i++) {
		PCAN_READ(pcan_p, AN_EVENT_STAT(pcan_p), stat);
		if (stat & AN_EV_CMD) {
			break;
		}
		PCAN_READ(pcan_p, AN_COMMAND(pcan_p), stat);
		if (stat == cmd)
			PCAN_WRITE(pcan_p, AN_COMMAND(pcan_p), cmd);
	}
	if (i == AN_TIMEOUT) {
		if (cmd == AN_CMD_FW_RESTART) {
			PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_CMD);
			return (PCAN_SUCCESS);
		}
#ifdef DEBUG
		if (pcan_debug & PCAN_DBG_CMD) {
			cmn_err(CE_WARN, "pcan set_cmd: %x timeout stat=%x\n",
			    cmd, stat);
		}
#endif
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_CMD);
		return (PCAN_TIMEDOUT_CMD);
	}

	for (i = 0; i < AN_TIMEOUT; i++) {
		PCAN_READ(pcan_p, AN_STATUS(pcan_p), stat);
		PCAN_READ(pcan_p, AN_RESP0(pcan_p), r0);
		PCAN_READ(pcan_p, AN_RESP1(pcan_p), r1);
		PCAN_READ(pcan_p, AN_RESP2(pcan_p), r2);
		if ((stat & AN_STAT_CMD_CODE) == (cmd & AN_STAT_CMD_CODE))
			break;
	}
	if (cmd == AN_CMD_FW_RESTART) {
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_CMD);
		return (PCAN_SUCCESS);
	}
	if (i == AN_TIMEOUT) {
#ifdef DEBUG
		if (pcan_debug & PCAN_DBG_CMD) {
			cmn_err(CE_WARN, "pcan set_cmd<%x,%x>: timeout "
			    "%x,%x,%x,%x\n", cmd, param, stat, r0, r1, r2);
		}
#endif
		ret = PCAN_TIMEDOUT_ACCESS;
	} else {
		if (stat & AN_STAT_CMD_RESULT) {
#ifdef DEBUG
			if (pcan_debug & PCAN_DBG_CMD) {
				cmn_err(CE_WARN, "pcan set_cmd<%x,%x>: failed "
				    "%x,%x,%x,%x\n",
				    cmd, param, stat, r0, r1, r2);
			}
#endif
			ret = PCAN_TIMEDOUT_ACCESS;
		} else {
			ret = PCAN_SUCCESS;
		}
	}
	PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_CMD);
	PCAN_READ(pcan_p, AN_COMMAND(pcan_p), stat);
	if (stat & AN_CMD_BUSY)
		PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_CLR_STUCK_BUSY);
	if (ret == PCAN_SUCCESS) {
		if (cmd == AN_CMD_ENABLE)
			pcan_p->pcan_flag |= PCAN_ENABLED;
		if (cmd == AN_CMD_DISABLE)
			pcan_p->pcan_flag &= (~PCAN_ENABLED);
	}
	return (ret);
}

static uint16_t
pcan_set_ch(pcan_maci_t *pcan_p, uint16_t type, uint16_t off, uint16_t channel)
{
	int i;
	uint16_t stat, select, offset;

	if (channel) {
		select = AN_SEL1;
		offset = AN_OFF1;
	} else {
		select = AN_SEL0;
		offset = AN_OFF0;
	}
	PCAN_WRITE(pcan_p, select, type);
	PCAN_WRITE(pcan_p, offset, off);
	for (i = 0; i < AN_TIMEOUT; i++) {
		PCAN_READ(pcan_p, offset, stat);
		if (!(stat & (AN_OFF_BUSY|AN_OFF_ERR)))
			break;
	}
	if (stat & (AN_OFF_BUSY|AN_OFF_ERR)) { /* time out */
		PCANDBG((CE_WARN, "pcan: set_ch%d %x %x TO %x\n",
		    channel, type, off, stat));
		return (PCAN_TIMEDOUT_TARGET);
	}
	return (PCAN_SUCCESS);
}

static uint16_t
pcan_get_ltv(pcan_maci_t *pcan_p, uint16_t len, uint16_t type, uint16_t *val_p)
{
	uint16_t stat;

	PCANDBG((CE_NOTE, "pcan: get_ltv(%p,%x,%x,%p)\n",
	    (void *)pcan_p, len, type, (void *)val_p));
	ASSERT(!(len & 1));

	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		uint32_t i;
		struct an_card_rid_desc an_rid_desc;
		struct an_ltv_gen *an_ltv;
		if (!pcan_p->pcan_cmd.dma_virtaddr)
			return (EIO);
		an_rid_desc.an_valid = 1;
		an_rid_desc.an_len = AN_RID_BUFFER_SIZE;
		an_rid_desc.an_rid = 0;
		an_rid_desc.an_phys = pcan_p->pcan_cmd.dma_physaddr;
		bzero(pcan_p->pcan_cmd.dma_virtaddr, AN_RID_BUFFER_SIZE);

		for (i = 0; i < sizeof (an_rid_desc) / 4; i++)
			PCAN_AUX_PUT32(pcan_p, AN_HOST_DESC_OFFSET + i * 4,
			    ((uint32_t *)&an_rid_desc)[i]);

		if (pcan_set_cmd0(pcan_p, AN_CMD_ACCESS |
		    AN_ACCESS_READ, type, 0, 0)) {
			cmn_err(CE_WARN, "pcan get_ltv: set cmd error");
			return (EIO);
		}

		an_ltv = (struct an_ltv_gen *)pcan_p->pcan_cmd.dma_virtaddr;
#ifdef DEBUG
		if (pcan_debug & PCAN_DBG_INFO) {
			cmn_err(CE_NOTE, "pcan get_ltv: type=%x,"
			    "expected len=%d," "actual len=%d",
			    type, len, an_ltv->an_len);
			for (i = 0; i < an_ltv->an_len; i++)
				cmn_err(CE_NOTE, "%d: %x", i,
				    *(((uint8_t *)an_ltv) + i));
		}
#endif
		if (an_ltv->an_len != len) {
			PCANDBG((CE_WARN, "pcan get_ltv: rid=%x expected len=%d"
			    "actual: len=%d", type,
			    len, an_ltv->an_len));
			/* return (EIO); */
		}
		bcopy(an_ltv, val_p, len);
	} else if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
		len >>= 1;	/* convert bytes to 16-bit words */

		/* 1. select read mode */
		if (stat = pcan_set_cmd(pcan_p, AN_CMD_ACCESS |
		    AN_ACCESS_READ, type))
			return (stat);

		/* 2. select Buffer Access Path (channel) 1 for PIO */
		if (stat = pcan_set_ch(pcan_p, type, 0, 1))
			return (stat);

		/* 3. read length */
		PCAN_READ(pcan_p, AN_DATA1, stat);
		*val_p++ = stat;
		if (stat != (len << 1)) {
			PCANDBG((CE_NOTE, "pcan get_ltv[%x]:expect %x,"
			    "got %x\n", type, (len + 1) << 1, stat));
			stat = (stat >> 1) - 1;
			len = MIN(stat, len);
		}
		/* 4. read value */
		for (stat = 0; stat < len - 1; stat++, val_p++) {
			PCAN_READ_P(pcan_p, AN_DATA1, val_p, 1);
		}
	}
	return (PCAN_SUCCESS);
}

static uint16_t
pcan_put_ltv(pcan_maci_t *pcan_p, uint16_t len, uint16_t type, uint16_t *val_p)
{
	uint16_t stat;
	int i;

	ASSERT(!(len & 1));

	if (pcan_p->pcan_device_type == PCAN_DEVICE_PCI) {
		struct an_card_rid_desc an_rid_desc;

		for (i = 0; i < AN_TIMEOUT; i++) {
			PCAN_READ(pcan_p, AN_COMMAND(pcan_p), stat);
			if (!(stat & AN_CMD_BUSY)) {
				break;
			}
		}
		if (i == AN_TIMEOUT) {
			cmn_err(CE_WARN, "pcan put_ltv: busy");
		}

		an_rid_desc.an_valid = 1;
		an_rid_desc.an_len = len;
		an_rid_desc.an_rid = type;
		an_rid_desc.an_phys = pcan_p->pcan_cmd.dma_physaddr;

		bcopy(val_p, pcan_p->pcan_cmd.dma_virtaddr,
		    an_rid_desc.an_len);

		for (i = 0; i < sizeof (an_rid_desc) / 4; i++)
			PCAN_AUX_PUT32(pcan_p, AN_HOST_DESC_OFFSET + i * 4,
			    ((uint32_t *)&an_rid_desc)[i]);
		pcan_delay(pcan_p, 100000);
		stat = pcan_set_cmd0(pcan_p, AN_CMD_ACCESS |
		    AN_ACCESS_WRITE, type, 0, 0);
		pcan_delay(pcan_p, 100000);
		return (stat);
	} else if (pcan_p->pcan_device_type == PCAN_DEVICE_PCCARD) {
		/* 0. select read mode first */
		if (stat = pcan_set_cmd(pcan_p, AN_CMD_ACCESS |
		    AN_ACCESS_READ, type))
			return (stat);

		/* 1. select Buffer Access Path (channel) 1 for PIO */
		if (stat = pcan_set_ch(pcan_p, type, 0, 1))
			return (stat);

		/* 2. write length */
		len >>= 1;		/* convert bytes to 16-bit words */
		stat = len;
		PCAN_WRITE(pcan_p, AN_DATA1, stat);

		/* 3. write value */
		val_p++;
		for (stat = 0; stat < len-1; stat++, val_p++) {
			PCAN_WRITE_P(pcan_p, AN_DATA1, val_p, 1);
		}

		/* 4. select write mode */
		return (pcan_set_cmd(pcan_p, AN_CMD_ACCESS |
		    AN_ACCESS_WRITE, type));
	}
	return (PCAN_FAIL);
}

/*ARGSUSED*/
static uint16_t
pcan_rdch0(pcan_maci_t *pcan_p, uint16_t type, uint16_t off, uint16_t *buf_p,
	int len, int order)
{
	ASSERT(!(len & 1));

	if (pcan_set_ch(pcan_p, type, off, 0) != PCAN_SUCCESS)
		return (PCAN_FAIL);
	len >>= 1;
	for (off = 0; off < len; off++, buf_p++) {
		PCAN_READ_P(pcan_p, AN_DATA0, buf_p, order);
	}
	return (PCAN_SUCCESS);
}

/*ARGSUSED*/
static uint16_t
pcan_wrch1(pcan_maci_t *pcan_p, uint16_t type, uint16_t off, uint16_t *buf_p,
	int len, int order)
{
	ASSERT(!(len & 1));

	if (pcan_set_ch(pcan_p, type, off, 1) != PCAN_SUCCESS)
		return (PCAN_FAIL);
	len >>= 1;
	for (off = 0; off < len; off++, buf_p++) {
		PCAN_WRITE_P(pcan_p, AN_DATA1, buf_p, order);
	}
	return (PCAN_SUCCESS);
}

static uint16_t
pcan_status_ltv(int rw, pcan_maci_t *pcan_p, struct an_ltv_status *status_p)
{
	uint16_t ret, len;

	if (rw != PCAN_READ_LTV) {
		cmn_err(CE_WARN, "pcan status_ltv: unsupported op %x", rw);
		return (PCAN_FAIL);
	}
	if (ret = pcan_get_ltv(pcan_p, sizeof (*status_p), AN_RID_STATUS,
	    (uint16_t *)status_p))
		return (ret);

	PCAN_SWAP16_BUF(status_p->an_macaddr);
	PCAN_SWAP16_BUF(status_p->an_ssid);
	len = min(status_p->an_ssidlen, 31);
	status_p->an_ssid[len] = '\0';
	PCAN_SWAP16_BUF(status_p->an_ap_name);
	PCAN_SWAP16_BUF(status_p->an_cur_bssid);
	PCAN_SWAP16_BUF(status_p->an_prev_bssid1);
	PCAN_SWAP16_BUF(status_p->an_prev_bssid2);
	PCAN_SWAP16_BUF(status_p->an_prev_bssid3);
	PCAN_SWAP16_BUF(status_p->an_ap_ip_address);
	PCAN_SWAP16_BUF(status_p->an_carrier);
	return (PCAN_SUCCESS);
}

static uint16_t
pcan_cfg_ltv(int rw, pcan_maci_t *pcan_p, struct an_ltv_genconfig *cfg_p)
{
	uint16_t ret;
	uint16_t rid = cfg_p == &pcan_p->an_config ?
	    AN_RID_GENCONFIG : AN_RID_ACTUALCFG;

	if (rw == PCAN_READ_LTV) {
		if (ret = pcan_get_ltv(pcan_p, sizeof (*cfg_p), rid,
		    (uint16_t *)cfg_p))
			return (ret);
		goto done;
	}
	PCAN_SWAP16_BUF(cfg_p->an_macaddr);
	PCAN_SWAP16_BUF(cfg_p->an_rates);
	if (ret = pcan_put_ltv(pcan_p, sizeof (*cfg_p),
	    rid, (uint16_t *)cfg_p))
		return (ret);
done:
	PCAN_SWAP16_BUF(cfg_p->an_macaddr);
	PCAN_SWAP16_BUF(cfg_p->an_rates);
	return (ret);
}

static uint16_t
pcan_cap_ltv(int rw, pcan_maci_t *pcan_p)
{
	uint16_t ret;

	if (rw != PCAN_READ_LTV) {
		cmn_err(CE_WARN, "pcan cap_ltv: unsupported op %x", rw);
		return (PCAN_FAIL);
	}
	if (ret = pcan_get_ltv(pcan_p, sizeof (struct an_ltv_caps),
	    AN_RID_CAPABILITIES, (uint16_t *)&pcan_p->an_caps))
		return (ret);

	PCAN_SWAP16_BUF(pcan_p->an_caps.an_oui);
	PCAN_SWAP16_BUF(pcan_p->an_caps.an_manufname);
	PCAN_SWAP16_BUF(pcan_p->an_caps.an_prodname);
	PCAN_SWAP16_BUF(pcan_p->an_caps.an_prodvers);
	PCAN_SWAP16_BUF(pcan_p->an_caps.an_oemaddr);
	PCAN_SWAP16_BUF(pcan_p->an_caps.an_aironetaddr);
	PCAN_SWAP16_BUF(pcan_p->an_caps.an_callid);
	PCAN_SWAP16_BUF(pcan_p->an_caps.an_supported_rates);
	return (PCAN_SUCCESS);
}

static uint16_t
pcan_ssid_ltv(int rw, pcan_maci_t *pcan_p)
{
	uint16_t ret;

	if (rw == PCAN_READ_LTV) {
		if (ret = pcan_get_ltv(pcan_p, sizeof (struct an_ltv_ssidlist),
		    AN_RID_SSIDLIST, (uint16_t *)&pcan_p->an_ssidlist))
			return (ret);
		goto done;
	}
	PCAN_SWAP16_BUF(pcan_p->an_ssidlist.an_ssid1);
	PCAN_SWAP16_BUF(pcan_p->an_ssidlist.an_ssid2);
	PCAN_SWAP16_BUF(pcan_p->an_ssidlist.an_ssid3);
	if (ret = pcan_put_ltv(pcan_p, sizeof (struct an_ltv_ssidlist),
	    AN_RID_SSIDLIST, (uint16_t *)&pcan_p->an_ssidlist))
		return (ret);
done:
	PCAN_SWAP16_BUF(pcan_p->an_ssidlist.an_ssid1);
	PCAN_SWAP16_BUF(pcan_p->an_ssidlist.an_ssid2);
	PCAN_SWAP16_BUF(pcan_p->an_ssidlist.an_ssid3);
	return (ret);
}

static uint16_t
pcan_aplist_ltv(int rw, pcan_maci_t *pcan_p)
{
	uint16_t ret;

	if (rw == PCAN_READ_LTV) {
		if (ret = pcan_get_ltv(pcan_p, sizeof (struct an_ltv_aplist),
		    AN_RID_APLIST, (uint16_t *)&pcan_p->an_aplist))
			return (ret);
		goto done;
	}
	PCAN_SWAP16_BUF(pcan_p->an_aplist.an_ap1);
	PCAN_SWAP16_BUF(pcan_p->an_aplist.an_ap2);
	PCAN_SWAP16_BUF(pcan_p->an_aplist.an_ap3);
	PCAN_SWAP16_BUF(pcan_p->an_aplist.an_ap4);
	if (ret = pcan_put_ltv(pcan_p, sizeof (struct an_ltv_aplist),
	    AN_RID_APLIST, (uint16_t *)&pcan_p->an_aplist))
		return (ret);
done:
	PCAN_SWAP16_BUF(pcan_p->an_aplist.an_ap1);
	PCAN_SWAP16_BUF(pcan_p->an_aplist.an_ap2);
	PCAN_SWAP16_BUF(pcan_p->an_aplist.an_ap3);
	PCAN_SWAP16_BUF(pcan_p->an_aplist.an_ap4);
	return (ret);
}

static uint16_t
pcan_scanresult_ltv(int rw, pcan_maci_t *pcan_p, uint16_t type,
    struct an_ltv_scanresult *scanresult_p)
{
	uint16_t ret, len;

	if (rw != PCAN_READ_LTV) {
		cmn_err(CE_WARN, "pcan scan_ltv: readonly rid %x\n", type);
		return (PCAN_FAIL);
	}
	if (ret = pcan_get_ltv(pcan_p, sizeof (struct an_ltv_scanresult),
	    type, (uint16_t *)scanresult_p))
		return (ret);
	PCAN_SWAP16_BUF(scanresult_p->an_bssid);
	PCAN_SWAP16_BUF(scanresult_p->an_ssid);
	len = min(scanresult_p->an_ssidlen, 31);
	scanresult_p->an_ssid[len] = '\0';
	PCAN_SWAP16_BUF(scanresult_p->an_rates);
	return (PCAN_SUCCESS);
}

static uint16_t
pcan_one_wepkey(int rw, pcan_maci_t *pcan_p, struct an_ltv_wepkey *wkp,
    uint16_t rid)
{
	uint16_t ret;

	if (rw == PCAN_READ_LTV) {
		if (ret = pcan_get_ltv(pcan_p, sizeof (struct an_ltv_wepkey),
		    rid, (uint16_t *)wkp)) {
			return (ret);
		}
		goto done;
	}
	PCAN_SWAP16_BUF(wkp->an_macaddr);
	PCAN_SWAP16_BUF(wkp->an_key);
	if (ret = pcan_put_ltv(pcan_p, sizeof (struct an_ltv_wepkey),
	    rid, (uint16_t *)wkp))
		return (ret);
done:
	PCAN_SWAP16_BUF(wkp->an_macaddr);
	PCAN_SWAP16_BUF(wkp->an_key);
	return (ret);
}

static uint16_t
pcan_wepkey_ltv(int rw, pcan_maci_t *pcan_p)
{
	uint16_t ret, i;
	struct an_ltv_wepkey wk;

	if (rw == PCAN_READ_LTV) {
		uint16_t rid = AN_RID_WEPKEY2;

		if (ret = pcan_one_wepkey(rw, pcan_p, &wk, rid))
			return (ret);
		for (i = 0; i < 5; i++) {
			if (wk.an_index < 4)
				pcan_p->an_wepkey[wk.an_index] = wk;
			else if (wk.an_index == 0xffff)
				pcan_p->an_cur_wepkey = wk.an_macaddr[0];
			rid = AN_RID_WEPKEY;
		}
		return (PCAN_SUCCESS);
	}
	for (i = 0; i < MAX_NWEPKEYS; i++) {
		if (pcan_p->an_wepkey[i].an_index == i) {
			if (ret = pcan_one_wepkey(rw, pcan_p,
			    &pcan_p->an_wepkey[i], AN_RID_WEPKEY2))
				return (ret);
		}
	}
	/* Now set the default key */
	(void) memset(&wk, 0, sizeof (wk));
	wk.an_index = 0xffff;
	wk.an_macaddr[0] = pcan_p->an_cur_wepkey;
	ret = pcan_one_wepkey(rw, pcan_p, &wk, AN_RID_WEPKEY2);
	return (ret);
}

static uint16_t
pcan_alloc_nicmem(pcan_maci_t *pcan_p, uint16_t len, uint16_t *id_p)
{
	int i;
	uint16_t stat;

	len = ((len + 1) >> 1) << 1;	/* round up to 16-bit boundary */

	if (stat = pcan_set_cmd(pcan_p, AN_CMD_ALLOC_MEM, len))
		return (stat);
	for (i = 0; !(stat & AN_EV_ALLOC) && (i < AN_TIMEOUT); i++) {
		PCAN_READ(pcan_p, AN_EVENT_STAT(pcan_p), stat);
	}
	if (!(stat & AN_EV_ALLOC))
		return (PCAN_TIMEDOUT_ALLOC);
	PCAN_READ(pcan_p, AN_ALLOC_FID, stat);
	PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), AN_EV_ALLOC);
	*id_p = stat;

	/* zero fill the allocated NIC mem - sort of pcan_fill_ch0 */
	(void) pcan_set_ch(pcan_p, stat, 0, 0);
	for (len >>= 1, stat = 0; stat < len; stat++) {
		PCAN_WRITE(pcan_p, AN_DATA0, 0);
	}
	return (PCAN_SUCCESS);
}

static void
pcan_stop_rx_dma(pcan_maci_t *pcan_p)
{
	int i, j;
	struct an_card_rx_desc  an_rx_desc;

	for (i = 0; i < AN_MAX_RX_DESC; i++) {
		bzero(&an_rx_desc, sizeof (an_rx_desc));
		an_rx_desc.an_valid = 0;
		an_rx_desc.an_len = AN_RX_BUFFER_SIZE;
		an_rx_desc.an_done = 1;
		an_rx_desc.an_phys = pcan_p->pcan_rx[i].dma_physaddr;
		for (j = 0; j < sizeof (an_rx_desc) / 4; j++)
			PCAN_AUX_PUT32(pcan_p, AN_RX_DESC_OFFSET
			    + (i * sizeof (an_rx_desc))
			    + (j * 4), ((uint32_t *)&an_rx_desc)[j]);
	}
}

static int
pcan_init_dma_desc(pcan_maci_t *pcan_p)
{
	int i, j;
	struct an_card_rid_desc an_rid_desc;
	struct an_card_rx_desc  an_rx_desc;
	struct an_card_tx_desc  an_tx_desc;

	/* Allocate DMA for rx */
	if (pcan_set_cmd0(pcan_p, AN_CMD_ALLOC_DESC,
	    AN_DESCRIPTOR_RX, AN_RX_DESC_OFFSET,
	    AN_MAX_RX_DESC) != PCAN_SUCCESS) {
		cmn_err(CE_WARN, "pcan init_dma: fail to alloc rx descriptor");
		goto error;
	}
	for (i = 0; i < AN_MAX_RX_DESC; i++) {
		bzero(&an_rx_desc, sizeof (an_rx_desc));
		an_rx_desc.an_valid = 1;
		an_rx_desc.an_len = AN_RX_BUFFER_SIZE;
		an_rx_desc.an_done = 0;
		an_rx_desc.an_phys = pcan_p->pcan_rx[i].dma_physaddr;
		for (j = 0; j < sizeof (an_rx_desc) / 4; j++)
			PCAN_AUX_PUT32(pcan_p, AN_RX_DESC_OFFSET
			    + (i * sizeof (an_rx_desc))
			    + (j * 4), ((uint32_t *)&an_rx_desc)[j]);
	}


	/* Allocate DMA for tx */
	if (pcan_set_cmd0(pcan_p, AN_CMD_ALLOC_DESC,
	    AN_DESCRIPTOR_TX, AN_TX_DESC_OFFSET,
	    AN_MAX_TX_DESC) != PCAN_SUCCESS) {
		cmn_err(CE_WARN, "pcan init_dma: fail to alloc tx descriptor");
		goto error;
	}

	for (i = 0; i < AN_MAX_TX_DESC; i++) {
		an_tx_desc.an_offset = 0;
		an_tx_desc.an_eoc = 0;
		an_tx_desc.an_valid = 0;
		an_tx_desc.an_len = 0;
		an_tx_desc.an_phys = pcan_p->pcan_tx[i].dma_physaddr;

		for (j = 0; j < sizeof (an_tx_desc) / 4; j++)
			PCAN_AUX_PUT32(pcan_p, AN_TX_DESC_OFFSET
			    + (i * sizeof (an_tx_desc))
			    + (j * 4), ((uint32_t *)&an_tx_desc)[j]);
	}

	/* Allocate DMA for rid */
	if (pcan_set_cmd0(pcan_p, AN_CMD_ALLOC_DESC,
	    AN_DESCRIPTOR_HOSTRW, AN_HOST_DESC_OFFSET, 1) != PCAN_SUCCESS) {
		cmn_err(CE_WARN, "pcan init_dma: fail to alloc rid descriptor");
		goto error;
	}
	bzero(&an_rid_desc, sizeof (an_rid_desc));
	an_rid_desc.an_valid = 1;
	an_rid_desc.an_len = AN_RID_BUFFER_SIZE;
	an_rid_desc.an_rid = 0;
	an_rid_desc.an_phys = pcan_p->pcan_cmd.dma_physaddr;

	for (i = 0; i < sizeof (an_rid_desc) / 4; i++)
		PCAN_AUX_PUT32(pcan_p, AN_HOST_DESC_OFFSET + i * 4,
		    ((uint32_t *)&an_rid_desc)[i]);

	pcan_p->pcan_txring.an_tx_prod = 0;
	pcan_p->pcan_txring.an_tx_cons = 0;
	pcan_p->pcan_flag &= ~PCAN_CARD_SEND;
	return (PCAN_SUCCESS);
error:
	return (PCAN_FAIL);
}

static int
pcan_init_dma(dev_info_t *dip, pcan_maci_t *pcan_p)
{
	int i, ret = PCAN_FAIL;
	ddi_dma_cookie_t dma_cookie;
	size_t len;

	/* Allocate DMA for rx */
	for (i = 0; i < AN_MAX_RX_DESC; i++) {
		if (ddi_dma_alloc_handle(dip, &control_cmd_dma_attr,
		    DDI_DMA_SLEEP, 0,
		    &pcan_p->pcan_rx[i].dma_handle) != DDI_SUCCESS)
			goto error;

		if (ddi_dma_mem_alloc(pcan_p->pcan_rx[i].dma_handle,
		    AN_RX_BUFFER_SIZE, &accattr,
		    DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
		    (caddr_t *)&pcan_p->pcan_rx[i].dma_virtaddr, &len,
		    &pcan_p->pcan_rx[i].dma_acc_handle) != DDI_SUCCESS) {
			goto error;
		}
		if (ddi_dma_addr_bind_handle(
		    pcan_p->pcan_rx[i].dma_handle,
		    NULL, (caddr_t)pcan_p->pcan_rx[i].dma_virtaddr,
		    len, DDI_DMA_READ |
		    DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0, &dma_cookie,
		    &pcan_p->pcan_rx[i].ncookies) != DDI_DMA_MAPPED) {
			goto error;
		}
		ASSERT(pcan_p->pcan_rx[i].ncookies == 1);
		pcan_p->pcan_rx[i].dma_physaddr = dma_cookie.dmac_address;
	}

	/* Allocate DMA for tx */
	for (i = 0; i < AN_MAX_TX_DESC; i++) {
		if (ddi_dma_alloc_handle(dip, &control_cmd_dma_attr,
		    DDI_DMA_SLEEP, 0,
		    &pcan_p->pcan_tx[i].dma_handle) != DDI_SUCCESS)
			goto error;

		if (ddi_dma_mem_alloc(pcan_p->pcan_tx[i].dma_handle,
		    AN_TX_BUFFER_SIZE, &accattr,
		    DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
		    (caddr_t *)&pcan_p->pcan_tx[i].dma_virtaddr, &len,
		    &pcan_p->pcan_tx[i].dma_acc_handle) != DDI_SUCCESS) {
			goto error;
		}
		if (ddi_dma_addr_bind_handle(
		    pcan_p->pcan_tx[i].dma_handle,
		    NULL, (caddr_t)pcan_p->pcan_tx[i].dma_virtaddr,
		    len, DDI_DMA_WRITE |
		    DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0, &dma_cookie,
		    &pcan_p->pcan_tx[i].ncookies) != DDI_DMA_MAPPED) {
			goto error;
		}
		ASSERT(pcan_p->pcan_tx[i].ncookies == 1);
		pcan_p->pcan_tx[i].dma_physaddr = dma_cookie.dmac_address;
	}

	/* Allocate DMA for rid */
	if (ddi_dma_alloc_handle(dip, &control_cmd_dma_attr,
	    DDI_DMA_SLEEP, 0,
	    &pcan_p->pcan_cmd.dma_handle) != DDI_SUCCESS)
		goto error;

	if (ddi_dma_mem_alloc(pcan_p->pcan_cmd.dma_handle,
	    AN_RID_BUFFER_SIZE, &accattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    (caddr_t *)&pcan_p->pcan_cmd.dma_virtaddr, &len,
	    &pcan_p->pcan_cmd.dma_acc_handle) != DDI_SUCCESS) {
		goto error;
	}
	if (ddi_dma_addr_bind_handle(
	    pcan_p->pcan_cmd.dma_handle,
	    NULL, (caddr_t)pcan_p->pcan_cmd.dma_virtaddr,
	    len, DDI_DMA_RDWR |
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0, &dma_cookie,
	    &pcan_p->pcan_cmd.ncookies) != DDI_DMA_MAPPED) {
		goto error;
	}
	ASSERT(pcan_p->pcan_cmd.ncookies == 1);
	pcan_p->pcan_cmd.dma_physaddr = dma_cookie.dmac_address;

	if (ret = pcan_init_dma_desc(pcan_p)) {
		cmn_err(CE_WARN, "pcan init_dma_desc: failed\n");
		goto error;
	}

	return (PCAN_SUCCESS);
error:
	pcan_free_dma(pcan_p);
	return (ret);
}

static void
pcan_free_dma(pcan_maci_t *pcan_p)
{
	int i;

	/* free RX dma */
	pcan_stop_rx_dma(pcan_p);
	for (i = 0; i < AN_MAX_RX_DESC; i++) {
		if (pcan_p->pcan_rx[i].dma_handle != NULL) {
			if (pcan_p->pcan_rx[i].ncookies) {
				(void) ddi_dma_unbind_handle(
				    pcan_p->pcan_rx[i].dma_handle);
				pcan_p->pcan_rx[i].ncookies = 0;
			}
			ddi_dma_free_handle(
			    &pcan_p->pcan_rx[i].dma_handle);
			pcan_p->pcan_rx[i].dma_handle = NULL;
		}
		if (pcan_p->pcan_rx[i].dma_acc_handle != NULL) {
			ddi_dma_mem_free(
			    &pcan_p->pcan_rx[i].dma_acc_handle);
			pcan_p->pcan_rx[i].dma_acc_handle = NULL;
		}
	}

	/* free TX dma */
	for (i = 0; i < AN_MAX_TX_DESC; i++) {
		if (pcan_p->pcan_tx[i].dma_handle != NULL) {
			if (pcan_p->pcan_tx[i].ncookies) {
				(void) ddi_dma_unbind_handle(
				    pcan_p->pcan_tx[i].dma_handle);
				pcan_p->pcan_tx[i].ncookies = 0;
			}
			ddi_dma_free_handle(
			    &pcan_p->pcan_tx[i].dma_handle);
			pcan_p->pcan_tx[i].dma_handle = NULL;
		}
		if (pcan_p->pcan_tx[i].dma_acc_handle != NULL) {
			ddi_dma_mem_free(
			    &pcan_p->pcan_tx[i].dma_acc_handle);
			pcan_p->pcan_tx[i].dma_acc_handle = NULL;
		}
	}

	/* free cmd dma */
	if (pcan_p->pcan_cmd.dma_handle != NULL) {
		if (pcan_p->pcan_cmd.ncookies) {
			(void) ddi_dma_unbind_handle(
			    pcan_p->pcan_cmd.dma_handle);
			pcan_p->pcan_cmd.ncookies = 0;
		}
		ddi_dma_free_handle(
		    &pcan_p->pcan_cmd.dma_handle);
		pcan_p->pcan_cmd.dma_handle = NULL;
	}
	if (pcan_p->pcan_cmd.dma_acc_handle != NULL) {
		ddi_dma_mem_free(
		    &pcan_p->pcan_cmd.dma_acc_handle);
		pcan_p->pcan_cmd.dma_acc_handle = NULL;
	}
}

/*
 * get card capability (WEP, default channel), setup broadcast, mac addresses
 */
static uint32_t
pcan_get_cap(pcan_maci_t *pcan_p)
{
	uint16_t stat;

	if (stat = pcan_cfg_ltv(PCAN_READ_LTV, pcan_p, &pcan_p->an_config)) {
		PCANDBG((CE_NOTE, "pcan get_cap: read cfg fail %x", stat));
		return ((uint32_t)AN_RID_GENCONFIG << 16 | stat);
	}

	if (stat = pcan_cap_ltv(PCAN_READ_LTV, pcan_p)) {
		PCANDBG((CE_NOTE, "pcan get_cap: read cap fail %x", stat));
		return ((uint32_t)AN_RID_CAPABILITIES << 16 | stat);
	}
#ifdef DEBUG
	if (pcan_debug & PCAN_DBG_FW_VERSION) {
		cmn_err(CE_NOTE, "the version of the firmware in the wifi card "
		    "'%s %s %s' is %s\n",
		    pcan_p->an_caps.an_manufname,
		    pcan_p->an_caps.an_prodname,
		    pcan_p->pcan_device_type == PCAN_DEVICE_PCI ?
		    "minipci" : "pccard",
		    pcan_p->an_caps.an_prodvers);
	}
#endif

	if (stat = pcan_ssid_ltv(PCAN_READ_LTV, pcan_p)) {
		PCANDBG((CE_NOTE, "pcan get_cap: read ssid fail %x", stat));
		return ((uint32_t)AN_RID_SSIDLIST << 16 | stat);
	}

	if (stat = pcan_aplist_ltv(PCAN_READ_LTV, pcan_p)) {
		PCANDBG((CE_NOTE, "pcan get_cap: read aplist fail %x", stat));
		return ((uint32_t)AN_RID_APLIST << 16 | stat);
	}
	if (stat = pcan_wepkey_ltv(PCAN_READ_LTV, pcan_p)) {
		PCANDBG((CE_NOTE, "pcan get_cap: read wepkey fail %x", stat));
		return ((uint32_t)AN_RID_WEPKEY2 << 16 | stat);
	}
	ether_copy(pcan_p->an_caps.an_oemaddr, pcan_p->pcan_mac_addr);
	return (PCAN_SUCCESS);
}

static int
pcan_config_mac(pcan_maci_t *pcan_p)
{
	uint16_t stat;

	if (stat = pcan_ssid_ltv(PCAN_WRITE_LTV, pcan_p)) {
		PCANDBG((CE_NOTE, "pcan config_mac: write SSID failed%x\n",
		    stat));
		return ((int)stat);
	}

	if (stat = pcan_aplist_ltv(PCAN_WRITE_LTV, pcan_p)) {
		PCANDBG((CE_NOTE, "pcan config_mac: write APlist failed%x\n",
		    stat));
		return ((int)stat);
	}
	if (stat = pcan_wepkey_ltv(PCAN_WRITE_LTV, pcan_p)) {
		PCANDBG((CE_NOTE, "pcan config_mac: write wepkey failed%x\n",
		    stat));
		return ((int)stat);
	}
	if (pcan_p->pcan_usewep)
		pcan_p->an_config.an_authtype |=
		    AN_AUTHTYPE_ENABLEWEP | AN_AUTHTYPE_ALLOW_UNENCRYPTED;
	PCANDBG((CE_NOTE, "pcan config_mac: usewep=%x authtype=%x opmode=%x\n",
	    pcan_p->pcan_usewep, pcan_p->an_config.an_authtype,
	    pcan_p->an_config.an_opmode));

	pcan_p->an_config.an_assoc_timeout = 5000; /* stop assoc seq in 5 sec */
	if (stat = pcan_cfg_ltv(PCAN_WRITE_LTV, pcan_p, &pcan_p->an_config)) {
		PCANDBG((CE_NOTE, "pcan config_mac: write cfg failed %x\n",
		    stat));
		return ((int)stat);
	}

	if (stat = pcan_cfg_ltv(PCAN_READ_LTV, pcan_p,
	    &pcan_p->an_actual_config)) {
		PCANDBG((CE_NOTE, "pcan config_mac: read cfg failed%x\n",
		    stat));
		return ((int)stat);
	}
	PCANDBG((CE_NOTE, "pcan config_mac: optionmask=%x authtype=%x\n", 0,
	    pcan_p->an_actual_config.an_authtype));

	if (stat = pcan_status_ltv(PCAN_READ_LTV, pcan_p, &pcan_p->an_status)) {
		PCANDBG((CE_NOTE, "pcan config_mac: read status failed %x\n",
		    stat));
		return ((int)stat);
	}
	return (PCAN_SUCCESS);
}

static int
pcan_loaddef(pcan_maci_t *pcan_p)
{
	int i;

	pcan_p->an_ssidlist.an_ssid1_len = 0;
	bzero(pcan_p->an_ssidlist.an_ssid1,
	    sizeof (pcan_p->an_ssidlist.an_ssid1));
	for (i = 0; i < MAX_NWEPKEYS; i++) {
		pcan_p->an_wepkey[i].an_index = 0xffff;
		bzero(pcan_p->an_wepkey[i].an_key,
		    sizeof (pcan_p->an_wepkey[i].an_key));
		pcan_p->an_wepkey[i].an_keylen = 0;
		bzero(pcan_p->an_wepkey[i].an_macaddr,
		    sizeof (pcan_p->an_wepkey[i].an_macaddr));
		pcan_p->an_wepkey[i].an_macaddr[0] = 1;
	}
	pcan_p->an_cur_wepkey = 0;

	pcan_p->pcan_usewep = 0;
	pcan_p->an_config.an_opmode = AN_OPMODE_INFR_STATION;
	pcan_p->an_config.an_authtype = AN_AUTHTYPE_OPEN;
	pcan_p->an_config.an_stationary = 1;
	pcan_p->an_config.an_max_beacon_lost_time = 0xffff;
	i = pcan_config_mac(pcan_p);

	return (i);
}

static int
pcan_init_nicmem(pcan_maci_t *pcan_p)
{
	int i;
	uint16_t ret;
	pcan_txring_t *ring_p = &pcan_p->pcan_txring;

	for (i = 0; i < AN_TX_RING_CNT; i++) {
		uint16_t rc;
		ret = pcan_alloc_nicmem(pcan_p, PCAN_NICMEM_SZ, &rc);
		if (ret) {
			cmn_err(CE_WARN, "pcan alloc NIC Tx buf[%x]: failed "
			    "%x\n", i, ret);
			return (DDI_FAILURE);
		}
		ring_p->an_tx_fids[i] = rc;
		ring_p->an_tx_ring[i] = 0;
		PCANDBG((CE_NOTE, "pcan: NIC tx_id[%x]=%x\n", i, rc));
	}
	ring_p->an_tx_prod = ring_p->an_tx_cons = 0;
	return (PCAN_SUCCESS);
}



static void
pcan_start_locked(pcan_maci_t *pcan_p)
{
	pcan_p->pcan_flag |= PCAN_CARD_INTREN;
	PCAN_ENABLE_INTR(pcan_p);
}

static void
pcan_stop_locked(pcan_maci_t *pcan_p)
{
	PCAN_DISABLE_INTR_CLEAR(pcan_p);
	pcan_p->pcan_flag &= ~PCAN_CARD_INTREN;
}

/*
 * for scan result
 */
static int
pcan_add_scan_item(pcan_maci_t *pcan_p, struct an_ltv_scanresult s)
{
	an_scan_list_t *scan_item;

	scan_item = kmem_zalloc(sizeof (an_scan_list_t), KM_SLEEP);
	if (scan_item == NULL) {
		cmn_err(CE_WARN, "pcan add_scan_item: zalloc failed\n");
		return (PCAN_FAIL);
	}
	scan_item->an_val = s;
	scan_item->an_timeout = AN_SCAN_TIMEOUT_MAX;
	list_insert_tail(&pcan_p->an_scan_list, scan_item);
	pcan_p->an_scan_num++;
	return (PCAN_SUCCESS);
}

static void
pcan_delete_scan_item(pcan_maci_t *pcan_p, an_scan_list_t *s)
{
	list_remove(&pcan_p->an_scan_list, s);
	kmem_free(s, sizeof (*s));
	pcan_p->an_scan_num--;
}

static void
pcan_scanlist_timeout(void *arg)
{
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;
	an_scan_list_t *scan_item0, *scan_item1;

	mutex_enter(&pcan_p->pcan_scanlist_lock);
	scan_item0 = list_head(&pcan_p->an_scan_list);
	for (; scan_item0; ) {
		PCANDBG((CE_NOTE, "pcan scanlist: ssid = %s\n",
		    scan_item0->an_val.an_ssid));
		PCANDBG((CE_NOTE, "pcan scanlist: timeout left: %ds",
		    scan_item0->an_timeout));
		scan_item1 = list_next(&pcan_p->an_scan_list, scan_item0);
		if (scan_item0->an_timeout == 0) {
			pcan_delete_scan_item(pcan_p, scan_item0);
		} else {
			scan_item0->an_timeout--;
		}
		scan_item0 = scan_item1;
	}
	mutex_exit(&pcan_p->pcan_scanlist_lock);
	pcan_p->an_scanlist_timeout_id = timeout(pcan_scanlist_timeout,
	    pcan_p, drv_usectohz(1000000));
}


/*
 * for wificonfig and dlamd ioctl
 */
static int
pcan_cfg_essid(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	char *value;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;
	struct an_ltv_status *status_p;
	struct an_ltv_ssidlist *ssidlist_p;

	status_p = &pcan_p->an_status;
	ssidlist_p = &pcan_p->an_ssidlist;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_essid: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	if (cmd == WLAN_GET_PARAM) {
		if (pcan_status_ltv(PCAN_READ_LTV, pcan_p, status_p)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			goto done;
		}

		outfp->wldp_length = WIFI_BUF_OFFSET +
		    offsetof(wl_essid_t, wl_essid_essid) +
		    status_p->an_ssidlen;
		((wl_essid_t *)(outfp->wldp_buf))->wl_essid_length =
		    status_p->an_ssidlen;
		bcopy(status_p->an_ssid, buf + WIFI_BUF_OFFSET +
		    offsetof(wl_essid_t, wl_essid_essid),
		    status_p->an_ssidlen);
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		bzero(ssidlist_p, sizeof (*ssidlist_p));
		value = ((wl_essid_t *)(infp->wldp_buf))->wl_essid_essid;
		(void) strncpy(ssidlist_p->an_ssid1, value,
		    MIN(32, strlen(value)));
		ssidlist_p->an_ssid1_len = strlen(value);
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_SUCCESS;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
done:
	for (i = 0; i < (outfp->wldp_length); i++) {
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	}
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
pcan_cfg_bssid(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	wldp_t *infp;
	wldp_t *outfp;
	char *buf;
	wl_bssid_t *value;
	int iret;
	struct an_ltv_status *status_p;
	struct an_ltv_aplist *aplist_p;

	status_p = &pcan_p->an_status;
	aplist_p = &pcan_p->an_aplist;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_bssid: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_bssid_t);

	if (cmd == WLAN_GET_PARAM) {
		if (pcan_status_ltv(PCAN_READ_LTV, pcan_p, status_p)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			goto done;
		}

		bcopy(status_p->an_cur_bssid, buf + WIFI_BUF_OFFSET,
		    sizeof (wl_bssid_t));
		outfp->wldp_result = WL_SUCCESS;
		PCANDBG((CE_CONT,
		    "pcan: cfg_bssid: bssid=%x %x %x %x %x %x\n",
		    status_p->an_cur_bssid[0],
		    status_p->an_cur_bssid[1],
		    status_p->an_cur_bssid[2],
		    status_p->an_cur_bssid[3],
		    status_p->an_cur_bssid[4],
		    status_p->an_cur_bssid[5]));
	} else if (cmd == WLAN_SET_PARAM) {
		value = (wl_bssid_t *)(infp->wldp_buf);
		(void) strncpy((char *)aplist_p->an_ap1, (char *)value, 6);
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_SUCCESS;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
done:
	for (i = 0; i < (outfp->wldp_length); i++) {
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	}
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

/*ARGSUSED*/
static int
pcan_cmd_scan(pcan_maci_t *pcan_p)
{
	uint16_t i = 0, j, ret = WL_SUCCESS;
	uint8_t	bssid_t[6];
	uint32_t check_num, enable;
	an_scan_list_t *scan_item0;

	enable = pcan_p->pcan_flag & PCAN_ENABLED;
	if ((!enable) &&
	    (ret = pcan_set_cmd(pcan_p, AN_CMD_ENABLE, 0))) {
		ret = (int)WL_HW_ERROR;
		goto exit;
	}
	if (ret = pcan_set_cmd(pcan_p, AN_CMD_SCAN, 0)) {
		ret = (int)WL_HW_ERROR;
		goto exit;
	}

	pcan_delay(pcan_p, 500000);
	ret =  pcan_scanresult_ltv(PCAN_READ_LTV,
	    pcan_p, AN_RID_ESSIDLIST_FIRST, &pcan_p->an_scanresult[i]);
	if ((ret) || pcan_p->an_scanresult[i].an_index == 0xffff) {
		goto done;
	}
	do
	{
		i++;
		ret =  pcan_scanresult_ltv(PCAN_READ_LTV,
		    pcan_p, AN_RID_ESSIDLIST_NEXT, &pcan_p->an_scanresult[i]);
	} while ((!ret) && (i < 32) &&
	    (pcan_p->an_scanresult[i].an_index != 0xffff));
done:
	if ((!enable) &&
	    (ret = pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0))) {
		ret = (int)WL_HW_ERROR;
		goto exit;
	}
	/* record the scan result for future use */
	bzero(bssid_t, sizeof (bssid_t));
	for (j = 0; j < i; j++) {
		/*
		 * sometimes, those empty items are recorded by hardware,
		 * this is wrong, just ignore those items here.
		 */
		if (bcmp(pcan_p->an_scanresult[j].an_bssid,
		    bssid_t, 6) == 0) {
			continue;
		}
		/*
		 * save/update the scan item in scanlist
		 */
		mutex_enter(&pcan_p->pcan_scanlist_lock);
		check_num = 0;
		scan_item0 = list_head(&pcan_p->an_scan_list);
		if (scan_item0 == NULL) {
			if (pcan_add_scan_item(pcan_p,
			    pcan_p->an_scanresult[j]) != 0) {
				mutex_exit(&pcan_p->pcan_scanlist_lock);
				return (WL_SUCCESS);
			}
		}
		for (; scan_item0; ) {
			if (bcmp(pcan_p->an_scanresult[j].an_bssid,
			    scan_item0->an_val.an_bssid, 6) == 0) {
				scan_item0->an_val = pcan_p->an_scanresult[j];
				scan_item0->an_timeout = AN_SCAN_TIMEOUT_MAX;
				break;
			} else {
				check_num++;
			}
			scan_item0 = list_next(&pcan_p->an_scan_list,
			    scan_item0);
		}
		if (check_num == pcan_p->an_scan_num) {
			if (pcan_add_scan_item(pcan_p,
			    pcan_p->an_scanresult[j]) != 0) {
				mutex_exit(&pcan_p->pcan_scanlist_lock);
				return (WL_SUCCESS);
			}
		}
		mutex_exit(&pcan_p->pcan_scanlist_lock);
	}
exit:
	if (ret)
		cmn_err(CE_WARN, "pcan: scan failed due to hardware error");
	return (ret);
}

/*ARGSUSED*/
static int
pcan_cfg_scan(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	wl_ess_conf_t *p_ess_conf;
	wldp_t *outfp;
	char *buf;
	uint16_t i;
	an_scan_list_t *scan_item;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_scanlist: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	mutex_enter(&pcan_p->pcan_scanlist_lock);
	((wl_ess_list_t *)(outfp->wldp_buf))->wl_ess_list_num =
	    pcan_p->an_scan_num;
	outfp->wldp_length = WIFI_BUF_OFFSET +
	    offsetof(wl_ess_list_t, wl_ess_list_ess) +
	    pcan_p->an_scan_num * sizeof (wl_ess_conf_t);

	scan_item = list_head(&pcan_p->an_scan_list);
	for (i = 0; i < pcan_p->an_scan_num; i++) {
		if (!scan_item)
			goto done;

		p_ess_conf = (wl_ess_conf_t *)(buf + WIFI_BUF_OFFSET +
		    offsetof(wl_ess_list_t, wl_ess_list_ess) +
		    i * sizeof (wl_ess_conf_t));
		bcopy(scan_item->an_val.an_ssid,
		    p_ess_conf->wl_ess_conf_essid.wl_essid_essid,
		    mi_strlen(scan_item->an_val.an_ssid));
		bcopy(scan_item->an_val.an_bssid,
		    p_ess_conf->wl_ess_conf_bssid, 6);
		(p_ess_conf->wl_phy_conf).wl_phy_dsss_conf.wl_dsss_subtype
		    = WL_DSSS;
		p_ess_conf->wl_ess_conf_wepenabled =
		    (scan_item->an_val.an_cap & 0x10 ?
		    WL_ENC_WEP : WL_NOENCRYPTION);
		p_ess_conf->wl_ess_conf_bsstype =
		    (scan_item->an_val.an_cap & 0x1 ?
		    WL_BSS_BSS : WL_BSS_IBSS);
		p_ess_conf->wl_phy_conf.wl_phy_dsss_conf.wl_dsss_channel =
		    scan_item->an_val.an_dschannel;
		p_ess_conf->wl_ess_conf_sl = 15 -
		    ((scan_item->an_val.an_rssi & 0xff) * 15 / 128);
		p_ess_conf->wl_supported_rates[0] = WL_RATE_1M;
		p_ess_conf->wl_supported_rates[1] = WL_RATE_2M;
		p_ess_conf->wl_supported_rates[2] = WL_RATE_5_5M;
		p_ess_conf->wl_supported_rates[3] = WL_RATE_11M;
		scan_item = list_next(&pcan_p->an_scan_list, scan_item);
	}
done:
	mutex_exit(&pcan_p->pcan_scanlist_lock);
	outfp->wldp_result = WL_SUCCESS;
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	kmem_free(buf, MAX_BUF_LEN);
	return (WL_SUCCESS);
}

/*ARGSUSED*/
static int
pcan_cfg_linkstatus(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	wldp_t *outfp;
	char *buf;
	uint16_t i;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_linkstatus: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	if (pcan_p->pcan_flag & PCAN_CARD_LINKUP)
		*(wl_linkstatus_t *)(outfp->wldp_buf) = WL_CONNECTED;
	else
		*(wl_linkstatus_t *)(outfp->wldp_buf) = WL_NOTCONNECTED;
	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_encryption_t);
	outfp->wldp_result = WL_SUCCESS;
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	kmem_free(buf, MAX_BUF_LEN);
	return (WL_SUCCESS);
}

static int
pcan_cfg_bsstype(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;
	struct an_ltv_genconfig *cfg_p;

	cfg_p = &pcan_p->an_config;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_bsstype: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_bss_type_t);

	if (cmd == WLAN_GET_PARAM) {
		if (cfg_p->an_opmode == AN_OPMODE_INFR_STATION) {
			*(wl_bss_type_t *)(outfp->wldp_buf) = WL_BSS_BSS;
		} else if (cfg_p->an_opmode == AN_OPMODE_IBSS_ADHOC) {
			*(wl_bss_type_t *)(outfp->wldp_buf) = WL_BSS_IBSS;
		}
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		if (*(wl_bss_type_t *)(infp->wldp_buf) == WL_BSS_BSS)
			cfg_p->an_opmode = AN_OPMODE_INFR_STATION;
		if (*(wl_bss_type_t *)(infp->wldp_buf) == WL_BSS_IBSS)
			cfg_p->an_opmode = AN_OPMODE_IBSS_ADHOC;
		if (*(wl_bss_type_t *)(infp->wldp_buf) == WL_BSS_ANY)
			cfg_p->an_opmode = AN_OPMODE_INFR_STATION;
		cfg_p->an_assoc_timeout = 5000;
		outfp->wldp_result = WL_SUCCESS;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
pcan_cfg_phy(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t ret, i;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;
	struct an_ltv_genconfig *cfg_p;
	struct an_ltv_status *status_p;

	cfg_p = &pcan_p->an_config;
	status_p = &pcan_p->an_status;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_phy: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_dsss_t);
	if (cmd == WLAN_GET_PARAM) {
		if (ret = pcan_status_ltv(PCAN_READ_LTV, pcan_p, status_p)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			goto done;
		}
		((wl_dsss_t *)(outfp->wldp_buf))->wl_dsss_channel =
		    status_p->an_channel_set;
		((wl_dsss_t *)(outfp->wldp_buf))->wl_dsss_subtype = WL_DSSS;
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		ret = (uint16_t)
		    (((wl_phy_conf_t *)(infp->wldp_buf))
		    ->wl_phy_dsss_conf.wl_dsss_channel);
		if (ret < 1 || ret > 14) {
			outfp->wldp_result = WL_NOTSUPPORTED;
			goto done;
		}
		cfg_p->an_ds_channel = ret;
		cfg_p->an_assoc_timeout = 5000;
		outfp->wldp_result = WL_SUCCESS;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
done:
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);

}

/*ARGSUSED*/
static int
pcan_cfg_desiredrates(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	uint8_t rates = 0;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;
	struct an_ltv_genconfig *cfg_p;
	struct an_ltv_genconfig *actcfg_p;

	cfg_p = &pcan_p->an_config;
	actcfg_p = &pcan_p->an_actual_config;
	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_rates: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	if (cmd == WLAN_GET_PARAM) {
		if (pcan_cfg_ltv(PCAN_READ_LTV, pcan_p, actcfg_p)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			goto done;
		}
		for (i = 0; i < sizeof (actcfg_p->an_rates); i++) {
			if (actcfg_p->an_rates[i] == 0)
				break;
			rates = MAX(rates, actcfg_p->an_rates[i]);
		}
		(((wl_rates_t *)(outfp->wldp_buf))->wl_rates_rates)[0]
		    = rates;
		((wl_rates_t *)(outfp->wldp_buf))->wl_rates_num = 1;
		outfp->wldp_length = WIFI_BUF_OFFSET +
		    offsetof(wl_rates_t, wl_rates_rates) + sizeof (char);
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		bzero(cfg_p->an_rates, sizeof (cfg_p->an_rates));
		for (i = 0; i < ((wl_rates_t *)(infp->wldp_buf))->wl_rates_num;
		    i++) {
			cfg_p->an_rates[i] = (((wl_rates_t *)
			    (infp->wldp_buf))->wl_rates_rates)[i];
		}
		cfg_p->an_assoc_timeout = 5000;
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_SUCCESS;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
done:
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

/*ARGSUSED*/
static int
pcan_cfg_supportrates(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	int iret;
	wldp_t *outfp;
	char *buf;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_supportedrates: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	if (cmd == WLAN_GET_PARAM) {
		((wl_rates_t *)(outfp->wldp_buf))->wl_rates_num = 4;
		(((wl_rates_t *)(outfp->wldp_buf))->wl_rates_rates)[0]
		    = WL_RATE_1M;
		(((wl_rates_t *)(outfp->wldp_buf))->wl_rates_rates)[1]
		    = WL_RATE_2M;
		(((wl_rates_t *)(outfp->wldp_buf))->wl_rates_rates)[2]
		    = WL_RATE_5_5M;
		(((wl_rates_t *)(outfp->wldp_buf))->wl_rates_rates)[3]
		    = WL_RATE_11M;
		outfp->wldp_length = WIFI_BUF_OFFSET +
		    offsetof(wl_rates_t, wl_rates_rates) +
		    4 * sizeof (char);
		outfp->wldp_result = WL_SUCCESS;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
done:
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

/*ARGSUSED*/
static int
pcan_cfg_powermode(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	wldp_t *outfp;
	char *buf;
	int iret;
	struct an_ltv_genconfig *actcfg_p;

	actcfg_p = &pcan_p->an_actual_config;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_powermode: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	if (cmd == WLAN_GET_PARAM) {
		if (pcan_cfg_ltv(PCAN_READ_LTV, pcan_p, actcfg_p)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			goto done;
		}
		((wl_ps_mode_t *)(outfp->wldp_buf))->wl_ps_mode =
		    actcfg_p->an_psave_mode;
		outfp->wldp_length = WIFI_BUF_OFFSET +
		    sizeof (wl_ps_mode_t);
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_LACK_FEATURE;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
done:
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);

}

static int
pcan_cfg_authmode(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	wldp_t *outfp;
	char *buf;
	int iret;
	struct an_ltv_genconfig *cfg_p;
	struct an_ltv_genconfig *actcfg_p;

	cfg_p = &pcan_p->an_config;
	actcfg_p = &pcan_p->an_actual_config;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_autymode: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	if (cmd == WLAN_GET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_authmode_t);
		if (cfg_p->an_authtype & AN_AUTHTYPE_SHAREDKEY) {
			*(wl_bss_type_t *)(outfp->wldp_buf) = WL_SHAREDKEY;
		} else {
			*(wl_bss_type_t *)(outfp->wldp_buf) = WL_OPENSYSTEM;
		}
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		if (*(wl_authmode_t *)(outfp->wldp_buf) == WL_OPENSYSTEM) {
			cfg_p->an_authtype |= AN_AUTHTYPE_OPEN;
			cfg_p->an_assoc_timeout = 5000;
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_SUCCESS;
		} else {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_LACK_FEATURE;
		}
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
	PCANDBG((CE_NOTE, "pcan cfg_authmode: actual.authmode=%x",
	    actcfg_p->an_authtype));
	PCANDBG((CE_NOTE, "pcan cfg_authmode: actual.home_product=%x",
	    actcfg_p->an_rsvd6[2]));
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
pcan_cfg_encryption(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	wldp_t *outfp;
	char *buf;
	int iret;
	struct an_ltv_genconfig *cfg_p;

	cfg_p = &pcan_p->an_config;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_encryption: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	if (cmd == WLAN_GET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_encryption_t);
		if (cfg_p->an_authtype & AN_AUTHTYPE_ENABLEWEP) {
			*(wl_bss_type_t *)(outfp->wldp_buf) = WL_ENC_WEP;
		} else {
			*(wl_bss_type_t *)(outfp->wldp_buf) = WL_NOENCRYPTION;
		}
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		if (*(wl_encryption_t *)(outfp->wldp_buf) == WL_ENC_WEP) {
			cfg_p->an_authtype |= (AN_AUTHTYPE_ENABLEWEP |
			    AN_AUTHTYPE_ALLOW_UNENCRYPTED);
			pcan_p->pcan_usewep = 1;
		}
		if (*(wl_authmode_t *)(outfp->wldp_buf) == WL_NOENCRYPTION) {
			cfg_p->an_authtype &= (~(AN_AUTHTYPE_ENABLEWEP |
			    AN_AUTHTYPE_ALLOW_UNENCRYPTED));
			pcan_p->pcan_usewep = 0;
		}
		cfg_p->an_assoc_timeout = 5000;
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_SUCCESS;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
pcan_cfg_wepkeyid(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i, ret;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;
	struct an_ltv_wepkey wepkey;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_wepkeyid: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	if (cmd == WLAN_GET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_wep_key_id_t);
		outfp->wldp_result = WL_SUCCESS;
		*(wl_wep_key_id_t *)(outfp->wldp_buf) = pcan_p->an_cur_wepkey;
	} else if (cmd == WLAN_SET_PARAM) {
		ret = (uint16_t)(*(wl_wep_key_id_t *)(infp->wldp_buf));
		if (ret > 3) {
			kmem_free(buf, MAX_BUF_LEN);
			return (EINVAL);
		}
		wepkey.an_index = 0xffff;
		wepkey.an_macaddr[0] = ret & 0xff;
		pcan_p->an_cur_wepkey = ret;
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_SUCCESS;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

/*ARGSUSED*/
static int
pcan_cfg_createibss(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_createibss: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_create_ibss_t);
	outfp->wldp_result = WL_LACK_FEATURE;
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
pcan_cfg_rssi(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i, val;
	int iret;
	wldp_t *outfp;
	char *buf;
	struct an_ltv_status *status_p;
	status_p = &pcan_p->an_status;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_rssi: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_rssi_t);

	if (cmd == WLAN_GET_PARAM) {
		if (val = pcan_status_ltv(PCAN_READ_LTV, pcan_p, status_p)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			goto done;
		}
		val = status_p->an_cur_signal_quality;
		PCANDBG((CE_NOTE, "pcan cfg_rssi: sl=%x", val));
		/*
		 * we reflect the value to 1-15 as rssi
		 */
		*(wl_rssi_t *)(outfp->wldp_buf) = 15 -
		    ((val & 0xff) * 15 / 128 + 1);
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		outfp->wldp_result = WL_READONLY;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
done:
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

/*ARGSUSED*/
static int
pcan_cfg_radio(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	int iret;
	wldp_t *outfp;
	char *buf;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_radio: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	if (cmd == WLAN_GET_PARAM) {
		*(wl_radio_t *)(outfp->wldp_buf) = B_TRUE;
		outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_radio_t);
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_LACK_FEATURE;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
pcan_cfg_wepkey(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	uint16_t i;
	wl_wep_key_t *p_wepkey_tab;
	wldp_t *outfp;
	char *buf;
	int iret;
	wldp_t	*infp;
	struct an_ltv_wepkey *wepkey_p;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCANDBG((CE_NOTE, "pcan cfg_wep: failed to alloc "
		    "memory(%d)\n", MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	if (cmd == WLAN_GET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET +
		    sizeof (wl_wep_key_tab_t);
		outfp->wldp_result = WL_WRITEONLY;
	} else if (cmd == WLAN_SET_PARAM) {
		p_wepkey_tab = (wl_wep_key_t *)(infp->wldp_buf);
		for (i = 0; i < MAX_NWEPKEYS; i++) {
			if (p_wepkey_tab[i].wl_wep_operation == WL_ADD) {
				wepkey_p = &pcan_p->an_wepkey[i];
				bzero(wepkey_p, sizeof (*wepkey_p));
				wepkey_p->an_keylen =
				    p_wepkey_tab[i].wl_wep_length;
				bcopy(p_wepkey_tab[i].wl_wep_key,
				    wepkey_p->an_key,
				    p_wepkey_tab[i].wl_wep_length);
				wepkey_p->an_index = i;
				wepkey_p->an_macaddr[0] = 1;
			}
		}
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_SUCCESS;
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static void
pcan_connect_timeout(void *arg)
{
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;
	uint16_t ret;

	mutex_enter(&pcan_p->pcan_glock);
	if (ret = pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0))
		goto done;
	pcan_p->pcan_flag &= ~PCAN_CARD_LINKUP;
	if (ret = pcan_config_mac(pcan_p))
		goto done;
	ret = pcan_set_cmd(pcan_p, AN_CMD_ENABLE, 0);
done:
	if (ret)
		cmn_err(CE_WARN, "pcan: connect failed due to hardware error");
	mutex_exit(&pcan_p->pcan_glock);
	pcan_p->pcan_connect_timeout_id = 0;
}

static int
pcan_getset(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd)
{
	int ret = WL_SUCCESS;
	int connect = 0;

	mutex_enter(&pcan_p->pcan_glock);
	if (!(pcan_p->pcan_flag & PCAN_CARD_READY)) {
		mutex_exit(&pcan_p->pcan_glock);
		return (PCAN_FAIL);
	}

	switch (((wldp_t *)mp->b_rptr)->wldp_id) {
	case WL_ESSID:
		ret = pcan_cfg_essid(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_essid\n"));
		break;
	case WL_BSSID:
		ret = pcan_cfg_bssid(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_bssid\n"));
		break;
	case WL_ESS_LIST:
		ret = pcan_cfg_scan(mp, pcan_p, cmd);
		PCANDBG((CE_NOTE, "cfg_scan\n"));
		break;
	case WL_LINKSTATUS:
		ret = pcan_cfg_linkstatus(mp, pcan_p, cmd);
		PCANDBG((CE_NOTE, "cfg_linkstatus\n"));
		break;
	case WL_BSS_TYPE:
		ret = pcan_cfg_bsstype(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_bsstype\n"));
		break;
	case WL_PHY_CONFIG:
		ret = pcan_cfg_phy(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_phy\n"));
		break;
	case WL_DESIRED_RATES:
		ret = pcan_cfg_desiredrates(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_disred-rates\n"));
		break;
	case WL_SUPPORTED_RATES:
		ret = pcan_cfg_supportrates(mp, pcan_p, cmd);
		PCANDBG((CE_NOTE, "cfg_supported-rates\n"));
		break;
	case WL_POWER_MODE:
		ret = pcan_cfg_powermode(mp, pcan_p, cmd);
		PCANDBG((CE_NOTE, "cfg_powermode\n"));
		break;
	case WL_AUTH_MODE:
		ret = pcan_cfg_authmode(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_authmode\n"));
		break;
	case WL_ENCRYPTION:
		ret = pcan_cfg_encryption(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_encryption\n"));
		break;
	case WL_WEP_KEY_ID:
		ret = pcan_cfg_wepkeyid(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_wepkeyid\n"));
		break;
	case WL_CREATE_IBSS:
		ret = pcan_cfg_createibss(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_create-ibss\n"));
		break;
	case WL_RSSI:
		ret = pcan_cfg_rssi(mp, pcan_p, cmd);
		PCANDBG((CE_NOTE, "cfg_rssi\n"));
		break;
	case WL_RADIO:
		ret = pcan_cfg_radio(mp, pcan_p, cmd);
		PCANDBG((CE_NOTE, "cfg_radio\n"));
		break;
	case WL_WEP_KEY_TAB:
		ret = pcan_cfg_wepkey(mp, pcan_p, cmd);
		connect = 1;
		PCANDBG((CE_NOTE, "cfg_wepkey\n"));
		break;
	case WL_SCAN:
		mutex_exit(&pcan_p->pcan_glock);
		if (pcan_p->pcan_connect_timeout_id != 0) {
			(void) untimeout(pcan_p->pcan_connect_timeout_id);
			pcan_p->pcan_connect_timeout_id = 0;
		}
		mutex_enter(&pcan_p->pcan_glock);
		ret = pcan_cmd_scan(pcan_p);
		/*
		 * a trick here.
		 * since the scan doesn't return too many items due to hardware
		 * reason, so the current scan result is an accumulation of
		 * several scans. For the first time or after many of the items
		 * aged, we scan again if too few items now in the scan table.
		 */
		if (pcan_p->an_scan_num < AN_SCAN_AGAIN_THRESHOLD)
			ret = pcan_cmd_scan(pcan_p);
		break;
	case WL_LOAD_DEFAULTS:
		if (ret = pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		if (ret = pcan_loaddef(pcan_p)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		if (ret = pcan_set_cmd(pcan_p, AN_CMD_ENABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		PCANDBG((CE_NOTE, "loaddef\n"));
		break;
	case WL_DISASSOCIATE:
		mutex_exit(&pcan_p->pcan_glock);
		if (pcan_p->pcan_connect_timeout_id != 0) {
			(void) untimeout(pcan_p->pcan_connect_timeout_id);
			pcan_p->pcan_connect_timeout_id = 0;
		}
		mutex_enter(&pcan_p->pcan_glock);
		pcan_p->pcan_flag &= ~PCAN_CARD_LINKUP;
		if (ret = pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		if (ret = pcan_loaddef(pcan_p)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		PCANDBG((CE_NOTE, "disassociate\n"));
		break;
	case WL_REASSOCIATE:
	case WL_ASSOCIAT:
		mutex_exit(&pcan_p->pcan_glock);
		if (pcan_p->pcan_connect_timeout_id != 0) {
			(void) untimeout(pcan_p->pcan_connect_timeout_id);
			pcan_p->pcan_connect_timeout_id = 0;
		}
		mutex_enter(&pcan_p->pcan_glock);
		if (ret = pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		pcan_p->pcan_flag &= ~PCAN_CARD_LINKUP;
		if (ret = pcan_config_mac(pcan_p)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		if (ret = pcan_set_cmd(pcan_p, AN_CMD_ENABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		PCANDBG((CE_NOTE, "associate"));
		break;

	default:
		break;
	}
	mutex_exit(&pcan_p->pcan_glock);
	if ((cmd == WLAN_SET_PARAM) && (ret == WL_SUCCESS) && (connect)) {
		pcan_p->pcan_flag &= ~PCAN_CARD_LINKUP;
		(void) pcan_set_cmd(pcan_p, AN_CMD_DISABLE, 0);
		if (pcan_p->pcan_connect_timeout_id != 0) {
			(void) untimeout(pcan_p->pcan_connect_timeout_id);
			pcan_p->pcan_connect_timeout_id = 0;
		}
		pcan_p->pcan_connect_timeout_id = timeout(pcan_connect_timeout,
		    pcan_p, drv_usectohz(1000000));
	}
	return (ret);
}

static void
pcan_wlan_ioctl(pcan_maci_t *pcan_p, queue_t *wq, mblk_t *mp, uint32_t cmd)
{

	struct	iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	uint32_t len, ret;
	mblk_t	*mp1;

	/* sanity check */
	if (iocp->ioc_count == 0 || !(mp1 = mp->b_cont)) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	/* assuming single data block */
	if (mp1->b_cont) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}

	/* we will overwrite everything */
	mp1->b_wptr = mp1->b_rptr;

	ret = pcan_getset(mp1, pcan_p, cmd);
	len = msgdsize(mp1);
	miocack(wq, mp, len, ret);
}

static void
pcan_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp;
	uint32_t cmd, ret;
	pcan_maci_t *pcan_p = (pcan_maci_t *)arg;
	boolean_t need_privilege = B_TRUE;

	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		miocnak(wq, mp, 0, EINVAL);
		return;
	case WLAN_GET_PARAM:
		need_privilege = B_FALSE;
		break;
	case WLAN_SET_PARAM:
	case WLAN_COMMAND:
		break;
	}

	if (need_privilege && (ret = secpolicy_dl_config(iocp->ioc_cr)) != 0)
		miocnak(wq, mp, 0, ret);
	else
		pcan_wlan_ioctl(pcan_p, wq, mp, cmd);
}
