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
#include <sys/mac_provider.h>
#include <sys/stream.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>

#include "pcwl.h"
#include <sys/mac_wifi.h>
#include <inet/wifi_ioctl.h>

#ifdef DEBUG
#define	PCWL_DBG_BASIC		0x1
#define	PCWL_DBG_INFO		0x2
#define	PCWL_DBG_SEND		0x4
#define	PCWL_DBG_RCV		0x8
#define	PCWL_DBG_LINKINFO	0x10
uint32_t pcwl_debug = 0;
#define	PCWLDBG(x) \
	if (pcwl_debug & PCWL_DBG_BASIC) cmn_err x
#else
#define	PCWLDBG(x)
#endif

/* for pci card */
static ddi_device_acc_attr_t accattr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC,
		DDI_DEFAULT_ACC
};

void *pcwl_soft_state_p = NULL;
static int pcwl_device_type;

mac_callbacks_t pcwl_m_callbacks = {
	MC_IOCTL,
	pcwl_gstat,
	pcwl_start,
	pcwl_stop,
	pcwl_prom,
	pcwl_sdmulti,
	pcwl_saddr,
	pcwl_tx,
	pcwl_ioctl
};

static char *pcwl_name_str = "pcwl";

DDI_DEFINE_STREAM_OPS(pcwl_dev_ops, nulldev, pcwl_probe, pcwl_attach,
    pcwl_detach, nodev, NULL, D_MP, NULL, ddi_quiesce_not_supported);

extern struct mod_ops mod_driverops;
static struct modldrv modldrv = {
	&mod_driverops,
	"Lucent/PRISM-II 802.11b driver",
	&pcwl_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
	};

int
_init(void)
{
	int stat;

	/* Allocate soft state */
	if ((stat = ddi_soft_state_init(&pcwl_soft_state_p,
	    sizeof (pcwl_maci_t), N_PCWL)) != DDI_SUCCESS)
		return (stat);

	mac_init_ops(&pcwl_dev_ops, "pcwl");
	wl_frame_default.wl_dat[0] = htons(WL_SNAP_WORD0);
	wl_frame_default.wl_dat[1] = htons(WL_SNAP_WORD1);
	stat = mod_install(&modlinkage);
	if (stat != DDI_SUCCESS) {
		mac_fini_ops(&pcwl_dev_ops);
		ddi_soft_state_fini(&pcwl_soft_state_p);
	}
	return (stat);
}

int
_fini(void)
{
	int stat;

	if ((stat = mod_remove(&modlinkage)) != DDI_SUCCESS)
		return (stat);
	mac_fini_ops(&pcwl_dev_ops);
	ddi_soft_state_fini(&pcwl_soft_state_p);

	return (stat);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
pcwl_probe(dev_info_t *dip)
{
	int len, ret;
	char *buf;
	dev_info_t *pdip = ddi_get_parent(dip);

	ret = ddi_getlongprop(DDI_DEV_T_ANY, pdip, 0, "device_type",
	    (caddr_t)&buf, &len);
	if (ret != DDI_SUCCESS)
		return (DDI_PROBE_FAILURE);

	PCWLDBG((CE_NOTE, "pcwl probe: device_type %s\n", buf));
	if ((strcmp(buf, "pccard") == 0) || (strcmp(buf, "pcmcia") == 0)) {
		pcwl_device_type = PCWL_DEVICE_PCCARD;
		ret = DDI_PROBE_SUCCESS;
	} else if (strcmp(buf, "pci") == 0) {
		pcwl_device_type = PCWL_DEVICE_PCI;
		ret = DDI_PROBE_SUCCESS;
	} else {
		ret = DDI_PROBE_FAILURE;
	}
	kmem_free(buf, len);
	return (ret);
}

static int
pcwl_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret, i;
	int instance;
	uint16_t stat;
	uint32_t err;
	pcwl_maci_t *pcwl_p;
	wifi_data_t	wd = { 0 };
	mac_register_t	*macp;
	modify_config_t cfgmod;
	char strbuf[256];

	PCWLDBG((CE_NOTE, "pcwl attach: dip=0x%p cmd=%x\n", (void *)dip, cmd));
	if (cmd != DDI_ATTACH)
		goto attach_fail1;
	/*
	 * Allocate soft state associated with this instance.
	 */
	if (ddi_soft_state_zalloc(pcwl_soft_state_p,
	    ddi_get_instance(dip)) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "pcwl attach: alloc softstate failed\n");
		goto attach_fail1;
	}
	pcwl_p = (pcwl_maci_t *)ddi_get_soft_state(pcwl_soft_state_p,
	    ddi_get_instance(dip));
	pcwl_p->pcwl_device_type = pcwl_device_type;
	if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCI) {
		if (ddi_regs_map_setup(dip, 0,
		    (caddr_t *)&pcwl_p->pcwl_cfg_base, 0, 0,
		    &accattr, &pcwl_p->pcwl_cfg_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "pcwl(pci) attach: pci_regs_map_setup"
			    " failed\n");
			goto attach_fail2;
		}

		stat = ddi_get16(pcwl_p->pcwl_cfg_handle,
		    (uint16_t *)(pcwl_p->pcwl_cfg_base + PCI_CONF_COMM));
		stat |= (PCI_COMM_IO | PCI_COMM_MAE);
		ddi_put16(pcwl_p->pcwl_cfg_handle,
		    (uint16_t *)(pcwl_p->pcwl_cfg_base + PCI_CONF_COMM), stat);
		stat = ddi_get16(pcwl_p->pcwl_cfg_handle,
		    (uint16_t *)(pcwl_p->pcwl_cfg_base + PCI_CONF_COMM));
		if ((stat & (PCI_COMM_IO | PCI_COMM_MAE)) !=
		    (PCI_COMM_IO | PCI_COMM_MAE)) {
			cmn_err(CE_WARN, "pcwl(pci) attach: pci command"
			    " reg enable failed\n");
			goto attach_fail2a;
		}


		if (ddi_regs_map_setup(dip, 1, (caddr_t *)&pcwl_p->pcwl_bar,
		    0, 0, &accattr, (ddi_acc_handle_t *)&pcwl_p->pcwl_handle)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "pcwl(pci) attach: pci_regs_map_setup"
			    " failed\n");
			goto attach_fail2a;
		}
		PCWLDBG((CE_NOTE, "pcwl(pci): regs_map_setup,bar=%p\n",
		    (void *)pcwl_p->pcwl_bar));

		/*
		 * tricky! copy from freebsd code.
		 */
		PCWL_WRITE(pcwl_p, 0x26, 0x80);
		drv_usecwait(500000);
		PCWL_WRITE(pcwl_p, 0x26, 0x0);
		drv_usecwait(500000);

		for (i = 0; i < WL_TIMEOUT; i++) {
			PCWL_READ(pcwl_p, 0x0, stat);
			if (stat & WL_CMD_BUSY)
				drv_usecwait(10);
			else
				break;
		}
		if (i == WL_TIMEOUT) {
			cmn_err(CE_WARN, "pcwl(pci) attach: hardware init"
			    " failed\n");
			goto attach_fail3;
		}

		/*
		 * magic number verification.
		 * tricky! copy from freebsd code.
		 */
		PCWL_WRITE(pcwl_p, 0x28, 0x4a2d);
		PCWL_READ(pcwl_p, 0x28, stat);
		PCWLDBG((CE_NOTE, "pcwl(pci):magic number = %x\n", stat));
		if (stat != 0x4a2d) {
			cmn_err(CE_WARN, "pcwl(pci) attach: magic verify"
			    " failed\n");
			goto attach_fail3;
		}
	}
	pcwl_p->pcwl_dip	= dip;
	pcwl_p->pcwl_flag	= 0;
	pcwl_p->pcwl_socket	= ddi_getprop(DDI_DEV_T_NONE, dip,
	    DDI_PROP_DONTPASS, "socket", -1);
	pcwl_p->pcwl_reschedule_need = B_FALSE;

	if (ddi_get_iblock_cookie(dip,
	    0, &pcwl_p->pcwl_ib_cookie) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pcwl attach: get_iblk_cookie failed\n");
		goto attach_fail3;
	}

	mutex_init(&pcwl_p->pcwl_glock, NULL, MUTEX_DRIVER,
	    pcwl_p->pcwl_ib_cookie);
	mutex_init(&pcwl_p->pcwl_scanlist_lock, NULL, MUTEX_DRIVER,
	    pcwl_p->pcwl_ib_cookie);
	mutex_init(&pcwl_p->pcwl_txring.wl_tx_lock, NULL, MUTEX_DRIVER,
	    pcwl_p->pcwl_ib_cookie);

	if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCI) {
		if (ret = ddi_add_intr(dip, 0, NULL, NULL,
		    pcwl_intr, (caddr_t)pcwl_p)) {
			cmn_err(CE_NOTE, "pcwl(pci) attach: add intr failed\n");
			goto attach_fail3a;
		}
	} else if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCCARD) {
		if (ret = pcwl_register_cs(dip, pcwl_p)) {
			cmn_err(CE_WARN, "pcwl attach(pccard): "
			    "register_cs err %x\n", ret);
			goto attach_fail3a;
		}
	} else {
		cmn_err(CE_WARN, "pcwl attach: unsupported device type\n");
		goto attach_fail3a;
	}
	mutex_enter(&pcwl_p->pcwl_glock);
	if (ret = pcwl_reset_backend(pcwl_p)) {
		cmn_err(CE_WARN, "pcwl attach: reset_backend failed %x\n", ret);
		mutex_exit(&pcwl_p->pcwl_glock);
		goto attach_fail4;
	}
	if (ret = pcwl_get_cap(pcwl_p)) { /* sets macaddr for mac_register */
		cmn_err(CE_WARN, "pcwl attach: get_cap failed %x\n", ret);
		mutex_exit(&pcwl_p->pcwl_glock);
		goto attach_fail4;
	}
	mutex_exit(&pcwl_p->pcwl_glock);
	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_pdata_update()
	 */
	wd.wd_secalloc = WIFI_SEC_NONE;
	wd.wd_opmode = IEEE80211_M_STA;

	macp = mac_alloc(MAC_VERSION);
	if (macp == NULL) {
		PCWLDBG((CE_NOTE, "pcwl attach: "
		    "MAC version mismatch\n"));
		goto attach_fail4;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= pcwl_p;
	macp->m_dip		= dip;
	macp->m_src_addr	= pcwl_p->pcwl_mac_addr;
	macp->m_callbacks	= &pcwl_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &pcwl_p->pcwl_mh);
	mac_free(macp);
	if (err != 0) {
		PCWLDBG((CE_NOTE, "pcwl attach: "
		    "mac_register err\n"));
		goto attach_fail4;
	}

	mutex_enter(&pcwl_p->pcwl_glock);
	if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCCARD) {
		/*
		 * turn on CS interrupt
		 */
		cfgmod.Attributes = CONF_ENABLE_IRQ_STEERING |
		    CONF_IRQ_CHANGE_VALID;
		cfgmod.Vpp1 = 0;
		cfgmod.Vpp2 = 0;
		(void) csx_ModifyConfiguration(pcwl_p->pcwl_chdl, &cfgmod);

	}
	if (ret = pcwl_init_nicmem(pcwl_p)) {
		cmn_err(CE_WARN, "pcwl(pccard) attach: pcwl_init_nicmem"
		    " failed %x\n", ret);
		mutex_exit(&pcwl_p->pcwl_glock);
		goto attach_fail5;
	}
	pcwl_chip_type(pcwl_p);
	if (ret = pcwl_loaddef_rf(pcwl_p)) {
		cmn_err(CE_WARN, "pcwl attach: config_rf failed%x\n", ret);
		mutex_exit(&pcwl_p->pcwl_glock);
		goto attach_fail5;
	}
	(void) pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0);
	pcwl_stop_locked(pcwl_p);	/* leaves interface down */
	list_create(&pcwl_p->pcwl_scan_list, sizeof (wl_scan_list_t),
	    offsetof(wl_scan_list_t, wl_scan_node));
	pcwl_p->pcwl_scan_num = 0;
	mutex_exit(&pcwl_p->pcwl_glock);
	pcwl_p->pcwl_scanlist_timeout_id = timeout(pcwl_scanlist_timeout,
	    pcwl_p, drv_usectohz(1000000));
	instance = ddi_get_instance(dip);
	(void) snprintf(strbuf, sizeof (strbuf), "pcwl%d", instance);
	if (ddi_create_minor_node(dip, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0) != DDI_SUCCESS) {
		goto attach_fail6;
	}
	pcwl_p->pcwl_flag |= PCWL_ATTACHED;
	if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCI) {
		pcwl_p->pcwl_flag |= PCWL_CARD_READY;
	}
	return (DDI_SUCCESS);
attach_fail6:
	if (pcwl_p->pcwl_scanlist_timeout_id != 0) {
		(void) untimeout(pcwl_p->pcwl_scanlist_timeout_id);
		pcwl_p->pcwl_scanlist_timeout_id = 0;
	}
	list_destroy(&pcwl_p->pcwl_scan_list);
attach_fail5:
	(void) mac_unregister(pcwl_p->pcwl_mh);
attach_fail4:
	if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCI) {
		ddi_remove_intr(dip, 0, pcwl_p->pcwl_ib_cookie);
	} else if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCCARD) {
		pcwl_unregister_cs(pcwl_p);
	}
attach_fail3a:
	pcwl_destroy_locks(pcwl_p);
attach_fail3:
	if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCI)
		ddi_regs_map_free(&pcwl_p->pcwl_handle);
attach_fail2a:
	if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCI)
		ddi_regs_map_free(&pcwl_p->pcwl_cfg_handle);
attach_fail2:
	ddi_soft_state_free(pcwl_soft_state_p, ddi_get_instance(dip));
attach_fail1:
	return (DDI_FAILURE);
}

static int
pcwl_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	pcwl_maci_t *pcwl_p;
	wl_scan_list_t *scan_item0;
	int ret;
	pcwl_p = ddi_get_soft_state(pcwl_soft_state_p, ddi_get_instance(dip));

	PCWLDBG((CE_NOTE, "pcwl detach: dip=0x%p cmd=%x\n", (void *)dip, cmd));
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	if (!(pcwl_p->pcwl_flag & PCWL_ATTACHED))
		return (DDI_FAILURE);

	ret = mac_disable(pcwl_p->pcwl_mh);
	if (ret != 0)
		return (DDI_FAILURE);

	if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCI) {
		mutex_enter(&pcwl_p->pcwl_glock);
		(void) pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0);
		PCWL_DISABLE_INTR(pcwl_p);
		mutex_exit(&pcwl_p->pcwl_glock);
	}
	if (pcwl_p->pcwl_scanlist_timeout_id != 0) {
		(void) untimeout(pcwl_p->pcwl_scanlist_timeout_id);
		pcwl_p->pcwl_scanlist_timeout_id = 0;
	}
	if (pcwl_p->pcwl_connect_timeout_id != 0) {
		(void) untimeout(pcwl_p->pcwl_connect_timeout_id);
		pcwl_p->pcwl_connect_timeout_id = 0;
	}
	mutex_enter(&pcwl_p->pcwl_scanlist_lock);
	scan_item0 = list_head(&pcwl_p->pcwl_scan_list);
	while (scan_item0) {
		pcwl_delete_scan_item(pcwl_p, scan_item0);
		scan_item0 = list_head(&pcwl_p->pcwl_scan_list);
	}
	list_destroy(&pcwl_p->pcwl_scan_list);
	mutex_exit(&pcwl_p->pcwl_scanlist_lock);
	(void) mac_unregister(pcwl_p->pcwl_mh);

	mutex_enter(&pcwl_p->pcwl_glock);
	if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCI) {
		ddi_remove_intr(dip, 0, pcwl_p->pcwl_ib_cookie);
		ddi_regs_map_free(&pcwl_p->pcwl_handle);
		ddi_regs_map_free(&pcwl_p->pcwl_cfg_handle);
	} else if (pcwl_p->pcwl_device_type == PCWL_DEVICE_PCCARD) {
		pcwl_unregister_cs(pcwl_p);
	}
	mutex_exit(&pcwl_p->pcwl_glock);
	pcwl_destroy_locks(pcwl_p);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(pcwl_soft_state_p, ddi_get_instance(dip));
	return (DDI_SUCCESS);
}

/*
 * card services and event handlers
 */
static int
pcwl_register_cs(dev_info_t *dip, pcwl_maci_t *pcwl_p)
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
	    CS_EVENT_CARD_READY | CS_EVENT_PM_RESUME |
	    CS_EVENT_PM_SUSPEND | CS_EVENT_CLIENT_INFO;
	cr.event_callback_args.client_data = pcwl_p;
	cr.Version = CS_VERSION;
	cr.event_handler = (csfunction_t *)pcwl_ev_hdlr;
	cr.dip = dip;
	(void) strcpy(cr.driver_name, pcwl_name_str);
	if (ret = csx_RegisterClient(&chdl, &cr)) {
		cmn_err(CE_WARN, "pcwl: RegisterClient failed %x\n", ret);
		goto regcs_ret;
	}
	pcwl_p->pcwl_chdl = chdl;

	bzero(&card_status, sizeof (card_status));
	(void) csx_GetStatus(chdl, &card_status);
	PCWLDBG((CE_NOTE,
	    "pcwl: register_cs: Sock=%x CState=%x SState=%x rState=%x\n",
	    card_status.Socket, card_status.CardState,
	    card_status.SocketState, card_status.raw_CardState));
	if (!(card_status.CardState & CS_STATUS_CARD_INSERTED)) {
		/* card is not present, why are we attaching ? */
		ret = CS_NO_CARD;
		goto regcs_unreg;
	}
	cv_init(&pcwl_p->pcwl_cscv, NULL, CV_DRIVER, NULL);
	mutex_init(&pcwl_p->pcwl_cslock, NULL, MUTEX_DRIVER, *cr.iblk_cookie);
	mutex_enter(&pcwl_p->pcwl_cslock);
	if (ret = csx_MapLogSocket(chdl, &pcwl_p->pcwl_log_sock)) {
		cmn_err(CE_WARN, "pcwl: MapLogSocket failed %x\n", ret);
		goto regcs_fail;
	}
	PCWLDBG((CE_NOTE,
	    "pcwl: register_cs: LogSock=%x PhyAdapter=%x PhySock=%x\n",
	    pcwl_p->pcwl_log_sock.LogSocket,
	    pcwl_p->pcwl_log_sock.PhyAdapter,
	    pcwl_p->pcwl_log_sock.PhySocket));
	/* turn on initialization events */
	sock_req.Socket = 0;
	sock_req.EventMask = CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL |
	    CS_EVENT_REGISTRATION_COMPLETE;
	if (ret = csx_RequestSocketMask(chdl, &sock_req)) {
		cmn_err(CE_WARN, "pcwl: RequestSocketMask failed %x\n", ret);
		goto regcs_fail;
	}
	/* wait for and process card insertion events */
	while (!(pcwl_p->pcwl_flag & PCWL_CARD_READY))
		cv_wait(&pcwl_p->pcwl_cscv, &pcwl_p->pcwl_cslock);
	mutex_exit(&pcwl_p->pcwl_cslock);

	pcwl_p->pcwl_flag |= PCWL_CS_REGISTERED;
	return (PCWL_SUCCESS);
regcs_fail:
	mutex_destroy(&pcwl_p->pcwl_cslock);
	cv_destroy(&pcwl_p->pcwl_cscv);
regcs_unreg:
	(void) csx_DeregisterClient(chdl);
regcs_ret:
	pcwl_p->pcwl_flag &= ~PCWL_CS_REGISTERED;
	return (ret);
}

static void
pcwl_unregister_cs(pcwl_maci_t *pcwl_p)
{
	int ret;
	release_socket_mask_t mask;
	mask.Socket = pcwl_p->pcwl_socket;

	/*
	 * The card service not registered means register_cs function
	 * doesnot return TRUE. Then all the lelated resource has been
	 * released in register_cs.
	 */
	if (!(pcwl_p->pcwl_flag | PCWL_CS_REGISTERED))
		return;

	if (ret = csx_ReleaseSocketMask(pcwl_p->pcwl_chdl, &mask))
		cmn_err(CE_WARN, "pcwl: ReleaseSocket mask failed %x\n", ret);

	if (pcwl_p->pcwl_flag & PCWL_CARD_READY) {
		pcwl_card_remove(pcwl_p);
		pcwl_p->pcwl_flag &= ~PCWL_CARD_READY;
	}
	mutex_destroy(&pcwl_p->pcwl_cslock);
	cv_destroy(&pcwl_p->pcwl_cscv);
	if (ret = csx_DeregisterClient(pcwl_p->pcwl_chdl))
		cmn_err(CE_WARN, "pcwl: Deregister failed %x\n", ret);
}

static void
pcwl_destroy_locks(pcwl_maci_t *pcwl_p)
{
	mutex_destroy(&pcwl_p->pcwl_txring.wl_tx_lock);
	mutex_destroy(&pcwl_p->pcwl_scanlist_lock);
	mutex_destroy(&pcwl_p->pcwl_glock);
}

static int
pcwl_ev_hdlr(event_t event, int priority, event_callback_args_t *arg)
{
	int ret = CS_SUCCESS;
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg->client_data;
	client_info_t *ci_p = (client_info_t *)&arg->client_info;

	mutex_enter(&pcwl_p->pcwl_cslock);
	switch (event) {
	case CS_EVENT_CARD_INSERTION:
		ret = pcwl_card_insert(pcwl_p);
		cv_broadcast(&pcwl_p->pcwl_cscv);
		break;
	case CS_EVENT_REGISTRATION_COMPLETE:
		cv_broadcast(&pcwl_p->pcwl_cscv);
		break;
	case CS_EVENT_CARD_REMOVAL:
		if (priority & CS_EVENT_PRI_HIGH)
			break;
		pcwl_card_remove(pcwl_p);
		cv_broadcast(&pcwl_p->pcwl_cscv);
		break;
	case CS_EVENT_CLIENT_INFO:
		if (GET_CLIENT_INFO_SUBSVC(ci_p->Attributes) !=
		    CS_CLIENT_INFO_SUBSVC_CS)
			break;

		ci_p->Revision = 0x0101;
		ci_p->CSLevel = CS_VERSION;
		ci_p->RevDate = CS_CLIENT_INFO_MAKE_DATE(9, 12, 14);
		(void) strcpy(ci_p->ClientName, PCWL_IDENT_STRING);
		(void) strcpy(ci_p->VendorName, CS_SUN_VENDOR_DESCRIPTION);
		ci_p->Attributes |= CS_CLIENT_INFO_VALID;
		break;
	default:
		ret = CS_UNSUPPORTED_EVENT;
		break;
	}
	mutex_exit(&pcwl_p->pcwl_cslock);
	return (ret);
}

static int
pcwl_card_insert(pcwl_maci_t *pcwl_p)
{
	int ret, hi, lo;
	tuple_t tuple;
	cisparse_t cisparse;
	io_req_t	io;
	irq_req_t	irq;
	config_req_t	cfg;
	cistpl_config_t config;
	cistpl_cftable_entry_t *tbl_p;
	register client_handle_t chdl = pcwl_p->pcwl_chdl;

	bzero(&tuple, sizeof (tuple));
	tuple.DesiredTuple = CISTPL_MANFID;
	if (ret = csx_GetFirstTuple(chdl, &tuple)) {
		cmn_err(CE_WARN, "pcwl: get manufacture id failed %x\n", ret);
		goto insert_ret;
	}
	bzero(&cisparse, sizeof (cisparse));
	if (ret = csx_Parse_CISTPL_MANFID(chdl, &tuple, &cisparse.manfid)) {
		cmn_err(CE_WARN, "pcwl: parse manufacture id failed %x\n", ret);
		goto insert_ret;
	}

	/*
	 * verify manufacture ID
	 */
	PCWLDBG((CE_NOTE, "pcwl insert: manufacturer_id=%x card=%x\n",
	    cisparse.manfid.manf, cisparse.manfid.card));
	bzero(&tuple, sizeof (tuple));
	tuple.DesiredTuple = CISTPL_FUNCID;
	if (ret = csx_GetFirstTuple(chdl, &tuple)) {
		cmn_err(CE_WARN, "pcwl: get function id failed %x\n", ret);
		goto insert_ret;
	}
	bzero(&cisparse, sizeof (cisparse));
	if (ret = csx_Parse_CISTPL_FUNCID(chdl, &tuple, &cisparse.funcid)) {
		cmn_err(CE_WARN, "pcwl: parse function id failed %x\n", ret);
		goto insert_ret;
	}

	/*
	 * verify function ID
	 */
	PCWLDBG((CE_NOTE, "insert:fun_id=%x\n", cisparse.funcid.function));
	bzero(&tuple, sizeof (tuple));
	tuple.DesiredTuple = CISTPL_CONFIG;
	if (ret = csx_GetFirstTuple(chdl, &tuple)) {
		cmn_err(CE_WARN, "pcwl: get config failed %x\n", ret);
		goto insert_ret;
	}
	bzero(&config, sizeof (config));
	if (ret = csx_Parse_CISTPL_CONFIG(chdl, &tuple, &config)) {
		cmn_err(CE_WARN, "pcwl: parse config failed %x\n", ret);
		goto insert_ret;
	}
	PCWLDBG((CE_NOTE,
	    "pcwl: config present=%x nr=%x hr=%x regs[0]=%x base=%x last=%x\n",
	    config.present, config.nr, config.hr, config.regs[0],
	    config.base, config.last));
	hi = 0;
	lo = (int)-1;		/* really big number */
	tbl_p = &cisparse.cftable;
	tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;
	for (tbl_p->index = 0; tbl_p->index <= config.hr; ) {
		PCWLDBG((CE_NOTE, "pcwl insert:tuple idx=%x:\n", tbl_p->index));
		if (ret = csx_GetNextTuple(chdl, &tuple)) {
			cmn_err(CE_WARN, "pcwl: get cftable failed %x\n",
			    ret);
			break;
		}
		bzero((caddr_t)&cisparse, sizeof (cisparse));
		if (ret = csx_Parse_CISTPL_CFTABLE_ENTRY(chdl, &tuple, tbl_p)) {
			cmn_err(CE_WARN, "pcwl: parse cftable failed %x\n",
			    ret);
			break;
		}
		if (tbl_p->flags & CISTPL_CFTABLE_TPCE_FS_PWR &&
		    tbl_p->pd.flags & CISTPL_CFTABLE_TPCE_FS_PWR_VCC) {
			if (tbl_p->pd.pd_vcc.avgI > hi) {
				hi = tbl_p->pd.pd_vcc.avgI;
				pcwl_p->pcwl_config_hi = tbl_p->index;
			}
			if (tbl_p->pd.pd_vcc.avgI < lo) {
				lo = tbl_p->pd.pd_vcc.avgI;
				pcwl_p->pcwl_config = tbl_p->index;
			}
		}
		if (tbl_p->flags & CISTPL_CFTABLE_TPCE_DEFAULT) {
			if (tbl_p->pd.flags & CISTPL_CFTABLE_TPCE_FS_PWR_VCC)
				pcwl_p->pcwl_vcc = tbl_p->pd.pd_vcc.nomV;
			if (tbl_p->flags & CISTPL_CFTABLE_TPCE_FS_IO)
				pcwl_p->pcwl_iodecode = tbl_p->io.addr_lines;
		}
	}
	PCWLDBG((CE_NOTE, "pcwl: insert:cfg_hi=%x cfg=%x vcc=%x iodecode=%x\n",
	    pcwl_p->pcwl_config_hi, pcwl_p->pcwl_config,
	    pcwl_p->pcwl_vcc, pcwl_p->pcwl_iodecode));
	bzero(&io, sizeof (io));
	io.BasePort1.base = 0;
	io.NumPorts1 = 1 << pcwl_p->pcwl_iodecode;
	io.Attributes1 = IO_DATA_PATH_WIDTH_16;
	io.IOAddrLines = pcwl_p->pcwl_iodecode;
	if (ret = csx_RequestIO(chdl, &io)) {
		cmn_err(CE_WARN, "pcwl: RequestIO failed %x\n", ret);
		goto insert_ret;
	}
	pcwl_p->pcwl_port = io.BasePort1.handle;
	if (ret = ddi_add_softintr(DIP(pcwl_p), DDI_SOFTINT_HIGH,
	    &pcwl_p->pcwl_softint_id, &pcwl_p->pcwl_ib_cookie, NULL,
	    pcwl_intr, (caddr_t)pcwl_p)) {
		cmn_err(CE_NOTE, "pcwl(pccard): add softintr failed\n");
		goto insert_ret;
	}
	irq.Attributes = IRQ_TYPE_EXCLUSIVE;
	irq.irq_handler = ddi_intr_hilevel(DIP(pcwl_p), 0) ?
	    (csfunction_t *)pcwl_intr_hi : (csfunction_t *)pcwl_intr;
	irq.irq_handler_arg = pcwl_p;
	if (ret = csx_RequestIRQ(pcwl_p->pcwl_chdl, &irq)) {
		cmn_err(CE_WARN, "pcwl: RequestIRQ failed %x\n", ret);
		goto un_io;
	}
	bzero(&cfg, sizeof (cfg));
	cfg.Attributes = 0; /* not ready for CONF_ENABLE_IRQ_STEERING yet */
	cfg.Vcc = 50;
	cfg.IntType = SOCKET_INTERFACE_MEMORY_AND_IO;
	cfg.ConfigBase = config.base;
	cfg.ConfigIndex = pcwl_p->pcwl_config;
	cfg.Status = CCSR_IO_IS_8;
	cfg.Present = config.present;
	pcwl_p->pcwl_flag |= PCWL_CARD_READY;
	if (ret = csx_RequestConfiguration(chdl, &cfg)) {
		cmn_err(CE_WARN, "pcwl: RequestConfiguration failed %x\n", ret);
		goto un_irq;
	}
	return (CS_SUCCESS);
un_irq:
	(void) csx_ReleaseIRQ(chdl, &irq);
un_io:
	ddi_remove_softintr(pcwl_p->pcwl_softint_id);
	(void) csx_ReleaseIO(chdl, &io);
	pcwl_p->pcwl_port = 0;
insert_ret:
	pcwl_p->pcwl_flag &= ~PCWL_CARD_READY;
	return (ret);

}

/*
 * assume card is already removed, don't touch the hardware
 */
static void
pcwl_card_remove(pcwl_maci_t *pcwl_p)
{
	int ret;
	io_req_t io;
	irq_req_t irq;

	/*
	 * The card not ready means Insert function doesnot return TRUE.
	 * then the IO and IRQ has been released in Insert
	 */
	if (!(pcwl_p->pcwl_flag & PCWL_CARD_READY))
		return;
	if (ret = csx_ReleaseConfiguration(pcwl_p->pcwl_chdl, NULL))
		cmn_err(CE_WARN, "pcwl: ReleaseConfiguration failed %x\n", ret);

	bzero(&irq, sizeof (irq));
	if (ret = csx_ReleaseIRQ(pcwl_p->pcwl_chdl, &irq))
		cmn_err(CE_WARN, "pcwl: ReleaseIRQ failed %x\n", ret);

	ddi_remove_softintr(pcwl_p->pcwl_softint_id);

	bzero(&io, sizeof (io));
	io.BasePort1.handle = pcwl_p->pcwl_port;
	io.NumPorts1 = 16;
	if (ret = csx_ReleaseIO(pcwl_p->pcwl_chdl, &io))
		cmn_err(CE_WARN, "pcwl: ReleaseIO failed %x\n", ret);

	pcwl_p->pcwl_port = 0;
	pcwl_p->pcwl_flag &= ~PCWL_CARD_READY;
}

/*
 * mac operation interface routines
 */
static int
pcwl_start(void *arg)
{
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;

	mutex_enter(&pcwl_p->pcwl_glock);
	if (!(pcwl_p->pcwl_flag & PCWL_CARD_READY)) {
		mutex_exit(&pcwl_p->pcwl_glock);
		return (PCWL_FAIL);
	}
	pcwl_start_locked(pcwl_p);
	mutex_exit(&pcwl_p->pcwl_glock);
	return (PCWL_SUCCESS);
}

static void
pcwl_stop(void *arg)
{
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;

	PCWLDBG((CE_NOTE, "pcwl_stop called\n"));
	mutex_enter(&pcwl_p->pcwl_glock);
	if (!(pcwl_p->pcwl_flag & PCWL_CARD_READY)) {
		mutex_exit(&pcwl_p->pcwl_glock);
		return;
	}

	pcwl_stop_locked(pcwl_p);
	mutex_exit(&pcwl_p->pcwl_glock);
	if (pcwl_p->pcwl_connect_timeout_id != 0) {
		(void) untimeout(pcwl_p->pcwl_connect_timeout_id);
		pcwl_p->pcwl_connect_timeout_id = 0;
	}
}

static int
pcwl_saddr(void *arg, const uint8_t *macaddr)
{
	int ret = PCWL_SUCCESS;
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;

	mutex_enter(&pcwl_p->pcwl_glock);
	if (!(pcwl_p->pcwl_flag & PCWL_CARD_READY)) {
		ret = PCWL_FAIL;
		goto done;
	}
	ether_copy(macaddr, pcwl_p->pcwl_mac_addr);
	if (pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0)) {
		ret = PCWL_FAIL;
		goto done;
	}
	if (pcwl_saddr_locked(pcwl_p)) {
		ret = PCWL_FAIL;
		goto done;
	}
	if (pcwl_set_cmd(pcwl_p, WL_CMD_ENABLE, 0)) {
		ret = PCWL_FAIL;
	}
done:
	if (ret)
		cmn_err(CE_WARN, "pcwl set_mac_addr: failed\n");
	mutex_exit(&pcwl_p->pcwl_glock);
	return (ret);
}

static int
pcwl_send(pcwl_maci_t *pcwl_p, mblk_t *mblk_p)
{
	int i = 0;
	char *buf, *buf_p;
	wl_frame_t *frm_p;
	uint16_t pkt_len, ret;
	uint16_t xmt_id, ring_idx;
	struct ieee80211_frame *wh;
	struct ieee80211_llc *llc;

	mutex_enter(&pcwl_p->pcwl_glock);
	if ((pcwl_p->pcwl_flag & (PCWL_CARD_READY | PCWL_CARD_LINKUP)) !=
	    (PCWL_CARD_READY | PCWL_CARD_LINKUP)) {
		mutex_exit(&pcwl_p->pcwl_glock);
		freemsg(mblk_p);
		return (PCWL_SUCCESS);		/* drop packet */
	}
	mutex_exit(&pcwl_p->pcwl_glock);

	if (pullupmsg(mblk_p, -1) == 0) {
		freemsg(mblk_p);
		return (PCWL_SUCCESS);		/* drop packet */
	}
	wh = (struct ieee80211_frame *)mblk_p->b_rptr;
	llc = (struct ieee80211_llc *)&wh[1];

	mutex_enter(&pcwl_p->pcwl_txring.wl_tx_lock);
	ring_idx = pcwl_p->pcwl_txring.wl_tx_prod;
	pcwl_p->pcwl_txring.wl_tx_prod = (ring_idx + 1) & (WL_XMT_BUF_NUM - 1);

	/*
	 * check whether there is a xmt buffer available
	 */
	while ((i < WL_XMT_BUF_NUM) &&
	    (pcwl_p->pcwl_txring.wl_tx_ring[ring_idx])) {
		ring_idx = pcwl_p->pcwl_txring.wl_tx_prod;
		pcwl_p->pcwl_txring.wl_tx_prod =
		    (ring_idx + 1) & (WL_XMT_BUF_NUM - 1);
		i++;
	}
	if (i == WL_XMT_BUF_NUM) {
		mutex_exit(&pcwl_p->pcwl_txring.wl_tx_lock);
		mutex_enter(&pcwl_p->pcwl_glock);
		pcwl_p->pcwl_reschedule_need = B_TRUE;
		mutex_exit(&pcwl_p->pcwl_glock);
		pcwl_p->pcwl_noxmtbuf++;
		return (PCWL_FAIL);
	}
	xmt_id = pcwl_p->pcwl_txring.wl_tx_fids[ring_idx];
	pcwl_p->pcwl_txring.wl_tx_ring[ring_idx] = xmt_id;
	mutex_exit(&pcwl_p->pcwl_txring.wl_tx_lock);

	buf = kmem_zalloc(PCWL_NICMEM_SZ, KM_SLEEP);
	buf_p = (ulong_t)buf & 1 ? buf + 1 : buf;
	frm_p = (wl_frame_t *)buf_p;
#ifdef DEBUG
	if (pcwl_debug & PCWL_DBG_SEND) {
		cmn_err(CE_NOTE, "pcwl send: packet");
		for (i = 0; i < MBLKL(mblk_p); i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((unsigned char *)mblk_p->b_rptr + i));
	}
#endif
	pkt_len = msgdsize(mblk_p);
	if (pkt_len > (PCWL_NICMEM_SZ - sizeof (wl_frame_t))) {
		cmn_err(CE_WARN, "pcwl: send mblk is too long");
		kmem_free(buf, PCWL_NICMEM_SZ);
		freemsg(mblk_p);
		return (PCWL_SUCCESS);		/* drop packet */
	}
	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) !=
	    IEEE80211_FC1_DIR_TODS) {
		kmem_free(buf, PCWL_NICMEM_SZ);
		freemsg(mblk_p);
		return (PCWL_SUCCESS);		/* drop packet */
	}
	bzero(frm_p, WL_802_11_HDRLEN);

	frm_p->wl_tx_ctl = WL_TXCNTL_SET;
	bcopy(wh->i_addr3, frm_p->wl_dst_addr, ETHERADDRL); /* dst macaddr */
	bcopy(wh->i_addr2, frm_p->wl_src_addr, ETHERADDRL); /* src macaddr */
	frm_p->wl_len = htons(pkt_len  - sizeof (*wh));
	bcopy(llc, &frm_p->wl_dat[0], pkt_len - sizeof (*wh));
	pkt_len = pkt_len - (sizeof (*wh) + sizeof (*llc)) +
	    WL_802_11_HDRLEN;
	PCWLDBG((CE_NOTE, "send: DIX frmsz=%x pkt_len=%x\n",
	    WL_802_11_HDRLEN, pkt_len));

	if (pkt_len & 1)	/* round up to 16-bit boundary and pad 0 */
		buf_p[pkt_len++] = 0;

	ASSERT(pkt_len <= PCWL_NICMEM_SZ);
#ifdef DEBUG
	if (pcwl_debug & PCWL_DBG_SEND) {
		cmn_err(CE_NOTE, "pkt_len = %x\n", pkt_len);
		for (i = 0; i < pkt_len; i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((unsigned char *)buf + i));
	}
#endif
	mutex_enter(&pcwl_p->pcwl_glock);
	ret = (WRCH1(pcwl_p, xmt_id, 0, (uint16_t *)buf_p, 0x2e) ||
	    WRPKT(pcwl_p, xmt_id, 0x2e, (uint16_t *)(buf_p + 0x2e),
	    pkt_len - 0x2e));
	if (ret) {
		goto done;
	}
	PCWLDBG((CE_NOTE, "send: xmt_id=%x send=%x\n", xmt_id, pkt_len));
	(void) pcwl_set_cmd(pcwl_p, WL_CMD_TX | WL_RECLAIM, xmt_id);

done:
	mutex_exit(&pcwl_p->pcwl_glock);
	kmem_free(buf, PCWL_NICMEM_SZ);
	freemsg(mblk_p);
	return (PCWL_SUCCESS);
}

static mblk_t *
pcwl_tx(void *arg, mblk_t *mp)
{
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;
	mblk_t *next;

	ASSERT(mp != NULL);
	mutex_enter(&pcwl_p->pcwl_glock);
	if ((pcwl_p->pcwl_flag & (PCWL_CARD_LINKUP | PCWL_CARD_READY)) !=
	    (PCWL_CARD_LINKUP | PCWL_CARD_READY)) {
		mutex_exit(&pcwl_p->pcwl_glock);
		return (mp);
	}
	mutex_exit(&pcwl_p->pcwl_glock);
	while (mp != NULL) {
		next =  mp->b_next;
		mp->b_next = NULL;

		if (pcwl_send(pcwl_p, mp)) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

static int
pcwl_prom(void *arg, boolean_t on)
{
	int ret = PCWL_SUCCESS;
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;

	mutex_enter(&pcwl_p->pcwl_glock);
	if (!(pcwl_p->pcwl_flag & PCWL_CARD_READY)) {
		ret = PCWL_FAIL;
		goto done;
	}

	PCWLDBG((CE_NOTE, "pcwl_prom called %x\n", on));

	if (on)
		pcwl_p->pcwl_rf.rf_promiscuous = 1;
	else
		pcwl_p->pcwl_rf.rf_promiscuous = 0;
	if (ret = pcwl_fil_ltv(pcwl_p, 2, WL_RID_PROMISC,
	    pcwl_p->pcwl_rf.rf_promiscuous)) {
		ret = PCWL_FAIL;
	}
done:
	if (ret)
		cmn_err(CE_WARN, "pcwl promisc: failed\n");
	mutex_exit(&pcwl_p->pcwl_glock);
	return (ret);
}

static int
pcwl_gstat(void *arg, uint_t statitem, uint64_t *val)
{
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;
	int ret = PCWL_SUCCESS;
	uint64_t *cntr_p = pcwl_p->pcwl_cntrs_s;
	uint16_t rate = 0;
	uint64_t speed;

	PCWLDBG((CE_NOTE, "pcwl_gstat called\n"));
	mutex_enter(&pcwl_p->pcwl_glock);
	if (!(pcwl_p->pcwl_flag & PCWL_CARD_READY)) {
		ret = PCWL_FAIL;
		goto done;
	}

	if (pcwl_get_ltv(pcwl_p, 2, WL_RID_CUR_TX_RATE, &rate)) {
		cmn_err(CE_WARN, "pcwl kstat: get speed failed\n");
		ret = PCWL_FAIL;
		goto done;
	}
	switch (pcwl_p->pcwl_chip_type) {
	case PCWL_CHIP_PRISMII:
		switch (rate) {
		case WL_SPEED_1Mbps_P2:		rate = 2;	break;
		case WL_SPEED_2Mbps_P2:		rate = 4;	break;
		case WL_SPEED_55Mbps_P2:	rate = 11;	break;
		case WL_SPEED_11Mbps_P2:	rate = 22;	break;
		default:			rate = 0;	break;
		}
		speed = rate * 500000;
		break;
	case PCWL_CHIP_LUCENT:
	default:
		speed = rate * 1000000;
		if (rate == 6)
			speed = 5500000;
		break;
	}

	switch (statitem) {
	case MAC_STAT_IFSPEED:
		*val = speed;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = pcwl_p->pcwl_noxmtbuf;
		break;
	case MAC_STAT_NORCVBUF:
		*val = cntr_p[WLC_RX_DISCARDS_NOBUF];
		break;
	case MAC_STAT_IERRORS:
		*val = 0;
		break;
	case MAC_STAT_OERRORS:
		*val = cntr_p[WLC_TX_DISCARDS] +
		    cntr_p[WLC_TX_DISCARDS_WRONG_SA];
		break;
	case MAC_STAT_RBYTES:
		*val = cntr_p[WLC_RX_UNICAST_OCTETS];
		break;
	case MAC_STAT_IPACKETS:
		*val = cntr_p[WLC_RX_UNICAST_FRAMES];
		break;
	case MAC_STAT_OBYTES:
		*val = cntr_p[WLC_TX_UNICAST_OCTETS];
		break;
	case MAC_STAT_OPACKETS:
		*val = cntr_p[WLC_TX_UNICAST_FRAMES];
		break;
	case WIFI_STAT_TX_FAILED:
		*val = cntr_p[WLC_TX_RETRY_LIMIT] +
		    cntr_p[WLC_TX_DEFERRED_XMITS];
		break;
	case WIFI_STAT_TX_RETRANS:
		*val = cntr_p[WLC_TX_SINGLE_RETRIES] +
		    cntr_p[WLC_TX_MULTI_RETRIES];
		break;
	case WIFI_STAT_FCS_ERRORS:
		*val = cntr_p[WLC_RX_FCS_ERRORS];
		break;
	case WIFI_STAT_WEP_ERRORS:
		*val = cntr_p[WLC_RX_WEP_CANT_DECRYPT];
		break;
	case WIFI_STAT_MCAST_TX:
		*val = cntr_p[WLC_TX_MULTICAST_FRAMES];
		break;
	case WIFI_STAT_MCAST_RX:
		*val = cntr_p[WLC_RX_MULTICAST_FRAMES];
		break;
	case WIFI_STAT_TX_FRAGS:
		*val = cntr_p[WLC_TX_FRAGMENTS];
		break;
	case WIFI_STAT_RX_FRAGS:
		*val =	cntr_p[WLC_RX_FRAGMENTS] +
		    cntr_p[WLC_RX_MSG_IN_MSG_FRAGS] +
		    cntr_p[WLC_RX_MSG_IN_BAD_MSG_FRAGS];
		break;
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_DUPS:
		*val = 0;
		break;
	default:
		ret = ENOTSUP;
	}
done:
	mutex_exit(&pcwl_p->pcwl_glock);
	return (ret);
}

static int
pcwl_sdmulti(void *arg, boolean_t add, const uint8_t *eth_p)
{
	int ret = PCWL_SUCCESS;
	uint16_t i;
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;
	uint16_t *mc_p = pcwl_p->pcwl_mcast;

	mutex_enter(&pcwl_p->pcwl_glock);
	if (!(pcwl_p->pcwl_flag & PCWL_CARD_READY)) {
		ret = PCWL_FAIL;
		goto done;
	}

	if (add) { /* enable multicast on eth_p, search for available entries */
		for (i = 0; i < 16; i++, mc_p += (ETHERADDRL >> 1)) {
			if (!ether_cmp(eth_p, mc_p))
				break;
		}
		if (i < 16)	/* already part of the filter */
			goto done;
		mc_p = pcwl_p->pcwl_mcast;	/* reset mc_p for 2nd scan */
		for (i = 0; i < 16; i++, mc_p += (ETHERADDRL >> 1)) {
			PCWLDBG((CE_NOTE, "smulti: mc[%x]=%s\n", i,
			    ether_sprintf((struct ether_addr *)mc_p)));
			if (mc_p[0] == 0 && mc_p[1] == 0 && mc_p[2] == 0)
				break;
		}
		if (i >= 16)	/* can't find a vacant entry */
			goto done;
		ether_copy(eth_p, mc_p);
	} else { /* disable multicast, locate the entry and clear it */
		for (i = 0; i < 16; i++, mc_p += (ETHERADDRL >> 1)) {
			if (!ether_cmp(eth_p, mc_p))
				break;
		}
		if (i >= 16)
			goto done;
		mc_p[0] = 0;
		mc_p[1] = 0;
		mc_p[2] = 0;
	}
	/*
	 * re-blow the entire 16 entries buffer
	 */
	if (i = pcwl_put_ltv(pcwl_p, ETHERADDRL << 4, WL_RID_MCAST,
	    pcwl_p->pcwl_mcast)) {
		ret = PCWL_FAIL;
	}
done:
	if (ret)
		cmn_err(CE_WARN, "pcwl set multi addr: failed\n");
	mutex_exit(&pcwl_p->pcwl_glock);
	return (ret);
}

static uint_t
pcwl_intr(caddr_t arg)
{
	uint16_t stat;
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;

	mutex_enter(&pcwl_p->pcwl_glock);
	if ((pcwl_p->pcwl_flag & (PCWL_CARD_READY | PCWL_CARD_INTREN)) !=
	    (PCWL_CARD_READY | PCWL_CARD_INTREN)) {
		mutex_exit(&pcwl_p->pcwl_glock);
		return (DDI_INTR_UNCLAIMED);
	}
	PCWL_READ(pcwl_p, WL_EVENT_STAT, stat);
	if (!(stat & WL_INTRS) || stat == WL_EV_ALL) {
		mutex_exit(&pcwl_p->pcwl_glock);
		return (DDI_INTR_UNCLAIMED);
	}

	PCWL_WRITE(pcwl_p, WL_INT_EN, 0);
	if (stat & WL_EV_RX) {
		pcwl_rcv(pcwl_p);
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_RX);
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_RX);
	}
	if (stat & WL_EV_TX) {
		if (pcwl_txdone(pcwl_p) == PCWL_SUCCESS) {
			if (pcwl_p->pcwl_reschedule_need == B_TRUE) {
				mutex_exit(&pcwl_p->pcwl_glock);
				mac_tx_update(GLD3(pcwl_p));
				mutex_enter(&pcwl_p->pcwl_glock);
				pcwl_p->pcwl_reschedule_need = B_FALSE;
			}
		}
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_TX);
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_TX);
	}
	if (stat & WL_EV_ALLOC) {
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_ALLOC | 0x1000);
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, 0x1000);
	}
	if (stat & WL_EV_INFO) {
		pcwl_infodone(pcwl_p);
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_INFO);
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_INFO);
	}
	if (stat & WL_EV_TX_EXC) {
		if (pcwl_txdone(pcwl_p) == PCWL_SUCCESS) {
			if (pcwl_p->pcwl_reschedule_need == B_TRUE) {
				mutex_exit(&pcwl_p->pcwl_glock);
				mac_tx_update(GLD3(pcwl_p));
				mutex_enter(&pcwl_p->pcwl_glock);
				pcwl_p->pcwl_reschedule_need = B_FALSE;
			}
		}
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_TX_EXC);
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_TX_EXC);
	}
	if (stat & WL_EV_INFO_DROP) {
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_INFO_DROP);
		PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_INFO_DROP);
	}
	PCWL_ENABLE_INTR(pcwl_p);
	mutex_exit(&pcwl_p->pcwl_glock);

	return (DDI_INTR_CLAIMED);
}

static uint_t
pcwl_intr_hi(caddr_t arg)
{
	uint16_t stat;
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;

	mutex_enter(&pcwl_p->pcwl_glock);
	if ((pcwl_p->pcwl_flag & (PCWL_CARD_READY | PCWL_CARD_INTREN)) !=
	    (PCWL_CARD_READY | PCWL_CARD_INTREN)) {
		mutex_exit(&pcwl_p->pcwl_glock);
		return (DDI_INTR_UNCLAIMED);
	}
	PCWL_READ(pcwl_p, WL_EVENT_STAT, stat);
	if (!(stat & WL_INTRS) || stat == WL_EV_ALL) {
		mutex_exit(&pcwl_p->pcwl_glock);
		return (DDI_INTR_UNCLAIMED);
	}
	PCWL_WRITE(pcwl_p, WL_INT_EN, 0); /* disable interrupt without ack */
	mutex_exit(&pcwl_p->pcwl_glock);
	ddi_trigger_softintr(pcwl_p->pcwl_softint_id);
	return (DDI_INTR_CLAIMED);
}

/*
 * called at interrupt context to retrieve data from card
 */
static void
pcwl_rcv(pcwl_maci_t *pcwl_p)
{
	uint16_t id, len, off, ret, frm_ctl;
	wl_frame_t frm;
	mblk_t *mp = allocb(PCWL_NICMEM_SZ, BPRI_MED);
	if (!mp)
		return;
	ASSERT(mp->b_rptr == mp->b_wptr);

	PCWL_READ(pcwl_p, WL_RX_FID, id);
	PCWL_WRITE(pcwl_p, WL_RX_FID, 0);
	if (id == WL_INVALID_FID) {
		PCWLDBG((CE_NOTE, "pcwl rcv: get rx_fid failed\n"));
		ret = PCWL_FAIL;
		goto done;
	}
	if (ret = RDCH0(pcwl_p, id, 0, (uint16_t *)&frm, sizeof (frm))) {
		PCWLDBG((CE_NOTE, "pcwl rcv: read frm failed %x\n", ret));
		goto done;
	}
	if (frm.wl_status & WL_STAT_ERRSTAT) {
		PCWLDBG((CE_NOTE, "pcwl rcv: errstat %x\n", frm.wl_status));
		ret = frm.wl_status;
		goto done;
	}
	PCWLDBG((CE_NOTE, "pcwl rcv: frame type %x\n", frm.wl_status));
#ifdef DEBUG
	if (pcwl_debug & PCWL_DBG_RCV) {
		int i;
		cmn_err(CE_NOTE, "pcwl rcv: frm header\n");
		for (i = 0; i < WL_802_11_HDRLEN; i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((uint8_t *)&frm + i));
	}
#endif
	len = frm.wl_dat_len;
	/*
	 * this driver deal with WEP by itself. so plugin always thinks no wep.
	 */
	frm.wl_frame_ctl &= ~(IEEE80211_FC1_WEP << 8);
	frm_ctl = frm.wl_frame_ctl;
	switch (frm.wl_status) {
	case WL_STAT_1042:
	case WL_STAT_TUNNEL:
	case WL_STAT_WMP_MSG:
		PCWL_SWAP16((uint16_t *)&frm.wl_frame_ctl,
		    sizeof (struct ieee80211_frame));
		/*
		 * discard those frames which are not from the AP we connect or
		 * without 'ap->sta' direction
		 */
		if ((pcwl_p->pcwl_rf.rf_porttype == WL_BSS_BSS) &&
		    ((((frm_ctl >> 8) & IEEE80211_FC1_DIR_MASK) !=
		    IEEE80211_FC1_DIR_FROMDS) ||
		    bcmp(pcwl_p->pcwl_bssid, frm.wl_addr2, 6) != 0)) {
			ret = PCWL_FAIL;
			goto done;
		}

		bcopy(&frm.wl_frame_ctl, mp->b_wptr,
		    sizeof (struct ieee80211_frame));
		mp->b_wptr += sizeof (struct ieee80211_frame);

		PCWL_SWAP16((uint16_t *)&frm.wl_dat[0],
		    sizeof (struct ieee80211_llc));
		bcopy(&frm.wl_dat[0], mp->b_wptr,
		    sizeof (struct ieee80211_llc));
		mp->b_wptr += sizeof (struct ieee80211_llc);

		len -= (2 + WL_SNAPHDR_LEN);
		off = WL_802_11_HDRLEN;
		break;
	default:
		PCWLDBG((CE_NOTE, "pcwl rcv: incorrect pkt\n"));
		break;
	}
	if (len > MBLKSIZE(mp)) {
		PCWLDBG((CE_NOTE, "pcwl rcv: oversz pkt %x\n", len));
		ret = PCWL_FAIL;
		goto done;
	}
	if (len & 1)
		len++;
	ret = RDPKT(pcwl_p, id, off, (uint16_t *)mp->b_wptr, len);
done:
	if (ret) {
		PCWLDBG((CE_NOTE, "pcwl rcv: rd data %x\n", ret));
		freemsg(mp);
		return;
	}
	mp->b_wptr = mp->b_wptr + len;
#ifdef DEBUG
	if (pcwl_debug & PCWL_DBG_RCV) {
		int i;
		cmn_err(CE_NOTE, "pcwl rcv: len=0x%x\n", len);
		for (i = 0; i < len+14; i++)
			cmn_err(CE_NOTE, "%x: %x\n", i,
			    *((uint8_t *)mp->b_rptr + i));
	}
#endif
	mutex_exit(&pcwl_p->pcwl_glock);
	mac_rx(GLD3(pcwl_p), NULL, mp);
	mutex_enter(&pcwl_p->pcwl_glock);
}

static uint32_t
pcwl_txdone(pcwl_maci_t *pcwl_p)
{
	uint16_t fid, i;
	PCWL_READ(pcwl_p, WL_ALLOC_FID, fid);
	PCWL_WRITE(pcwl_p, WL_ALLOC_FID, 0);

	mutex_enter(&pcwl_p->pcwl_txring.wl_tx_lock);
	for (i = 0; i < WL_XMT_BUF_NUM; i++) {
		if (fid == pcwl_p->pcwl_txring.wl_tx_ring[i]) {
			pcwl_p->pcwl_txring.wl_tx_ring[i] = 0;
			break;
		}
	}
	pcwl_p->pcwl_txring.wl_tx_cons =
	    (pcwl_p->pcwl_txring.wl_tx_cons + 1) & (WL_XMT_BUF_NUM - 1);
	mutex_exit(&pcwl_p->pcwl_txring.wl_tx_lock);
	if (i == WL_XMT_BUF_NUM)
		return (PCWL_FAIL);
	return (PCWL_SUCCESS);

}

static void
pcwl_infodone(pcwl_maci_t *pcwl_p)
{
	uint16_t id, ret, i;
	uint16_t linkStatus[2];
	uint16_t linkStat;
	wifi_data_t wd = { 0 };

	PCWL_READ(pcwl_p, WL_INFO_FID, id);
	if (id == WL_INVALID_FID) {
		cmn_err(CE_WARN, "pcwl infodone: read info_fid failed\n");
		return;
	}
	if (ret = RDCH0(pcwl_p, id, 0, linkStatus, sizeof (linkStatus))) {
		PCWLDBG((CE_WARN, "pcwl infodone read infoFrm failed %x\n",
		    ret));
		return;
	}
	PCWLDBG((CE_NOTE, "pcwl infodone: Frame length= %x, Frame Type = %x\n",
	    linkStatus[0], linkStatus[1]));

	switch (linkStatus[1]) {
	case WL_INFO_LINK_STAT:
		(void) RDCH0(pcwl_p, id, sizeof (linkStatus), &linkStat,
		    sizeof (linkStat));
		PCWLDBG((CE_NOTE, "pcwl infodone: link status=%x\n", linkStat));
		if (!(pcwl_p->pcwl_flag & PCWL_CARD_LINKUP) &&
		    linkStat == WL_LINK_CONNECT) {
#ifdef DEBUG
		if (pcwl_debug & PCWL_DBG_LINKINFO)
			cmn_err(CE_NOTE, "pcwl: Link up \n");
#endif
			pcwl_p->pcwl_flag |= PCWL_CARD_LINKUP;
			mutex_exit(&pcwl_p->pcwl_glock);
			if (pcwl_p->pcwl_connect_timeout_id != 0) {
				(void) untimeout(pcwl_p->
				    pcwl_connect_timeout_id);
				pcwl_p->pcwl_connect_timeout_id = 0;
			}
			mutex_enter(&pcwl_p->pcwl_glock);
			mac_link_update(GLD3(pcwl_p), LINK_STATE_UP);
			(void) pcwl_get_ltv(pcwl_p, 6,
			    WL_RID_BSSID, (uint16_t *)pcwl_p->pcwl_bssid);
			PCWL_SWAP16((uint16_t *)pcwl_p->pcwl_bssid, 6);
			pcwl_get_rssi(pcwl_p);
			bcopy(pcwl_p->pcwl_bssid, wd.wd_bssid, 6);
			wd.wd_secalloc = WIFI_SEC_NONE;
			wd.wd_opmode = IEEE80211_M_STA;
			(void) mac_pdata_update(pcwl_p->pcwl_mh, &wd,
			    sizeof (wd));
		}
		if ((pcwl_p->pcwl_flag & PCWL_CARD_LINKUP) &&
		    ((linkStat == WL_LINK_DISCONNECT) ||
		    (linkStat == WL_LINK_AP_OOR))) {
#ifdef DEBUG
		if (pcwl_debug & PCWL_DBG_LINKINFO)
			cmn_err(CE_NOTE, "pcwl: Link down \n");
#endif
			PCWLDBG((CE_NOTE, "pcwl infodone: link status = %d\n",
			    linkStat));
			pcwl_p->pcwl_flag &= ~PCWL_CARD_LINKUP;
			if (linkStat == WL_LINK_AP_OOR)
				pcwl_p->pcwl_connect_timeout_id =
				    timeout(pcwl_connect_timeout,
				    pcwl_p, drv_usectohz(1000));
			mutex_exit(&pcwl_p->pcwl_glock);
			mac_link_update(GLD3(pcwl_p), LINK_STATE_DOWN);
			mutex_enter(&pcwl_p->pcwl_glock);
		}
		break;
	case WL_INFO_SCAN_RESULTS:
	case WL_INFO_HSCAN_RESULTS:
		pcwl_ssid_scan(pcwl_p, id, linkStatus[0], linkStatus[1]);
			break;
	case WL_INFO_COUNTERS:
		linkStatus[0]--;
		if (linkStatus[0] > WLC_STAT_CNT) {
			linkStatus[0] = MIN(linkStatus[0], WLC_STAT_CNT);
		}
		(void) RDCH0(pcwl_p, id, sizeof (linkStatus),
		    pcwl_p->pcwl_cntrs_t, linkStatus[0]<<1);
		/*
		 * accumulate all the statistics items for kstat use.
		 */
		for (i = 0; i < WLC_STAT_CNT; i++)
			pcwl_p->pcwl_cntrs_s[i] += pcwl_p->pcwl_cntrs_t[i];
		break;
	default:
		break;
	}
}

static uint16_t
pcwl_set_cmd(pcwl_maci_t *pcwl_p, uint16_t cmd, uint16_t param)
{
	int i;
	uint16_t stat;

	if (((cmd == WL_CMD_ENABLE) &&
	    ((pcwl_p->pcwl_flag & PCWL_ENABLED) != 0)) ||
	    ((cmd == WL_CMD_DISABLE) &&
	    ((pcwl_p->pcwl_flag & PCWL_ENABLED) == 0)))
		return (PCWL_SUCCESS);

	for (i = 0; i < WL_TIMEOUT; i++) {
		PCWL_READ(pcwl_p, WL_COMMAND, stat);
		if (stat & WL_CMD_BUSY) {
			drv_usecwait(1);
		} else {
			break;
		}
	}
	if (i == WL_TIMEOUT) {
		cmn_err(CE_WARN, "pcwl: setcmd %x, %x timeout %x due to "
		    "busy bit\n", cmd, param, stat);
		return (PCWL_TIMEDOUT_CMD);
	}

	PCWL_WRITE(pcwl_p, WL_PARAM0, param);
	PCWL_WRITE(pcwl_p, WL_PARAM1, 0);
	PCWL_WRITE(pcwl_p, WL_PARAM2, 0);
	PCWL_WRITE(pcwl_p, WL_COMMAND, cmd);
	if (cmd == WL_CMD_INI)
		drv_usecwait(100000); /* wait .1 sec */

	for (i = 0; i < WL_TIMEOUT; i++) {
		PCWL_READ(pcwl_p, WL_EVENT_STAT, stat);
		if (!(stat & WL_EV_CMD)) {
			drv_usecwait(1);
		} else {
			break;
		}
	}
	if (i == WL_TIMEOUT) {
		cmn_err(CE_WARN, "pcwl: setcmd %x,%x timeout %x\n",
		    cmd, param, stat);
		if (stat & (WL_EV_ALLOC | WL_EV_RX))
			PCWL_WRITE(pcwl_p, WL_EVENT_ACK, stat);
		return (PCWL_TIMEDOUT_CMD);
	}
	PCWL_READ(pcwl_p, WL_STATUS, stat);
	PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_CMD);
	if (stat & WL_STAT_CMD_RESULT) { /* err in feedback status */
		cmn_err(CE_WARN, "pcwl: set_cmd %x,%x failed %x\n",
		    cmd, param, stat);
		return (PCWL_FAILURE_CMD);
	}
	if (cmd == WL_CMD_ENABLE)
		pcwl_p->pcwl_flag |= PCWL_ENABLED;
	if (cmd == WL_CMD_DISABLE)
		pcwl_p->pcwl_flag &= (~PCWL_ENABLED);
	return (PCWL_SUCCESS);
}

static uint16_t
pcwl_set_ch(pcwl_maci_t *pcwl_p, uint16_t type, uint16_t off, uint16_t channel)
{
	int i;
	uint16_t stat, select, offset;

	if (channel) {
		select = WL_SEL1;
		offset = WL_OFF1;
	} else {
		select = WL_SEL0;
		offset = WL_OFF0;
	}
	PCWL_WRITE(pcwl_p, select, type);
	PCWL_WRITE(pcwl_p, offset, off);
	for (stat = 0, i = 0; i < WL_TIMEOUT; i++) {
		PCWL_READ(pcwl_p, offset, stat);
		if (!(stat & (WL_OFF_BUSY|WL_OFF_ERR)))
			break;
		else {
			drv_usecwait(1);
		}
	}
	if (i == WL_TIMEOUT) {
		cmn_err(CE_WARN, "set_ch%d %x,%x failed %x\n",
		    channel, type, off, stat);
		return (PCWL_TIMEDOUT_TARGET);
	}
	return (PCWL_SUCCESS);
}

static uint16_t
pcwl_get_ltv(pcwl_maci_t *pcwl_p, uint16_t len, uint16_t type, uint16_t *val_p)
{
	uint16_t stat;

	ASSERT(!(len & 1));
	len >>= 1;	/* convert bytes to 16-bit words */

	/*
	 * 1. select read mode
	 */
	if (stat = pcwl_set_cmd(pcwl_p, WL_CMD_ACCESS | WL_ACCESS_READ, type))
		return (stat);

	/*
	 * 2. select Buffer Access Path (channel) 1 for PIO
	 */
	if (stat = pcwl_set_ch(pcwl_p, type, 0, 1))
		return (stat);

	/*
	 * 3. read length
	 */
	PCWL_READ(pcwl_p, WL_DATA1, stat);
	if (stat != (len + 1)) {
		PCWLDBG((CE_NOTE, "get_ltv 0x%x expected 0x%x+1, got 0x%x\n",
		    type, (len + 1) << 1, stat));
		stat = (stat >> 1) - 1;
		len = MIN(stat, len);
	}

	/*
	 * 4. read type
	 */
	PCWL_READ(pcwl_p, WL_DATA1, stat);
	if (stat != type)
		return (PCWL_BADTYPE);

	/*
	 * 5. read value
	 */
	for (stat = 0; stat < len; stat++, val_p++) {
		PCWL_READ_P(pcwl_p, WL_DATA1, val_p, 1);
	}
	return (PCWL_SUCCESS);
}

static uint16_t
pcwl_fil_ltv(pcwl_maci_t *pcwl_p, uint16_t len, uint16_t type, uint16_t val)
{
	uint16_t stat;

	ASSERT(!(len & 1));

	/*
	 * 1. select Buffer Access Path (channel) 1 for PIO
	 */
	if (stat = pcwl_set_ch(pcwl_p, type, 0, 1))
		return (stat);

	/*
	 * 2. write length
	 */
	len >>= 1;		/* convert bytes to 16-bit words */
	stat = len + 1;		/* 1 extra word */
	PCWL_WRITE(pcwl_p, WL_DATA1, stat);

	/*
	 * 3. write type
	 */
	PCWL_WRITE(pcwl_p, WL_DATA1, type);

	/*
	 * 4. fill value
	 */
	for (stat = 0; stat < len; stat++) {
		PCWL_WRITE(pcwl_p, WL_DATA1, val);
	}

	/*
	 * 5. select write mode
	 */
	return (pcwl_set_cmd(pcwl_p, WL_CMD_ACCESS|WL_ACCESS_WRITE, type));
}

static uint16_t
pcwl_put_ltv(pcwl_maci_t *pcwl_p, uint16_t len, uint16_t type, uint16_t *val_p)
{
	uint16_t stat;

	ASSERT(!(len & 1));

	/*
	 * 1. select Buffer Access Path (channel) 1 for PIO
	 */
	if (stat = pcwl_set_ch(pcwl_p, type, 0, 1))
		return (stat);

	/*
	 * 2. write length
	 */
	len >>= 1;		/* convert bytes to 16-bit words */
	stat = len + 1;		/* 1 extra word */
	PCWL_WRITE(pcwl_p, WL_DATA1, stat);

	/*
	 * 3. write type
	 */
	PCWL_WRITE(pcwl_p, WL_DATA1, type);

	/*
	 * 4. write value
	 */
	for (stat = 0; stat < len; stat++, val_p++) {
		PCWL_WRITE_P(pcwl_p, WL_DATA1, val_p, 1);
	}

	/*
	 * 5. select write mode
	 */
	return (pcwl_set_cmd(pcwl_p, WL_CMD_ACCESS|WL_ACCESS_WRITE, type));
}

#define	PCWL_COMPSTR_LEN	34
static uint16_t
pcwl_put_str(pcwl_maci_t *pcwl_p, uint16_t type, char *str_p)
{
	uint16_t buf[PCWL_COMPSTR_LEN / 2];
	uint8_t str_len = strlen(str_p);

	bzero(buf, PCWL_COMPSTR_LEN);
	buf[0] = str_len;
	bcopy(str_p, (caddr_t)(buf + 1), str_len);
	PCWLDBG((CE_NOTE, "put_str: buf[0]=%x buf=%s\n",
	    buf[0], (caddr_t)(buf + 1)));
	PCWL_SWAP16(buf + 1, PCWL_COMPSTR_LEN - 2);
	return (pcwl_put_ltv(pcwl_p, PCWL_COMPSTR_LEN, type, buf));
}

/*ARGSUSED*/
static uint16_t
pcwl_rdch0(pcwl_maci_t *pcwl_p, uint16_t type, uint16_t off, uint16_t *buf_p,
	int len, int order)
{
	uint16_t o;
	ASSERT(!(len & 1));
	/*
	 * It seems that for PrismII chip, frequently overlap use of path0
	 * and path1 may hang the hardware. So for PrismII chip, just use
	 * path1. Test proves this workaround is OK.
	 */
	if (pcwl_p->pcwl_chip_type == PCWL_CHIP_PRISMII) {
		if (type = pcwl_set_ch(pcwl_p, type, off, 1))
			return (type);
		o = WL_DATA1;
	} else {
		if (type = pcwl_set_ch(pcwl_p, type, off, 0))
			return (type);
		o = WL_DATA0;
	}
	len >>= 1;
	for (off = 0; off < len; off++, buf_p++) {
		PCWL_READ_P(pcwl_p, o, buf_p, order);
	}
	return (PCWL_SUCCESS);
}

/*ARGSUSED*/
static uint16_t
pcwl_wrch1(pcwl_maci_t *pcwl_p, uint16_t type, uint16_t off, uint16_t *buf_p,
	int len, int order)
{
	ASSERT(!(len & 1));
	if (type = pcwl_set_ch(pcwl_p, type, off, 1))
		return (type);
	len >>= 1;
	for (off = 0; off < len; off++, buf_p++) {
		PCWL_WRITE_P(pcwl_p, WL_DATA1, buf_p, order);
	}
	return (PCWL_SUCCESS);
}

static uint16_t
pcwl_alloc_nicmem(pcwl_maci_t *pcwl_p, uint16_t len, uint16_t *id_p)
{
	int i;
	uint16_t stat;

	len = ((len + 1) >> 1) << 1;	/* round up to 16-bit boundary */

	if (stat = pcwl_set_cmd(pcwl_p, WL_CMD_ALLOC_MEM, len))
		return (stat);
	for (stat = 0, i = 0; i < WL_TIMEOUT; i++) {
		PCWL_READ(pcwl_p, WL_EVENT_STAT, stat);
		if (stat & WL_EV_ALLOC)
			break;
		else
			drv_usecwait(1);
	}
	if (i == WL_TIMEOUT)
		return (PCWL_TIMEDOUT_ALLOC);
	PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_ALLOC);
	PCWL_READ(pcwl_p, WL_ALLOC_FID, stat);
	*id_p = stat;

	/*
	 * zero fill the allocated NIC mem - sort of pcwl_fill_ch
	 */
	(void) pcwl_set_ch(pcwl_p, stat, 0, 1);

	for (len >>= 1, stat = 0; stat < len; stat++) {
		PCWL_WRITE(pcwl_p, WL_DATA1, 0);
	}
	return (PCWL_SUCCESS);
}

static int
pcwl_add_scan_item(pcwl_maci_t *pcwl_p, wl_scan_result_t s)
{
	wl_scan_list_t *scan_item;

	scan_item = kmem_zalloc(sizeof (wl_scan_list_t), KM_SLEEP);
	if (scan_item == NULL) {
		cmn_err(CE_WARN, "pcwl add_scan_item: zalloc failed\n");
		return (PCWL_FAIL);
	}
	scan_item->wl_val = s;
	scan_item->wl_timeout = WL_SCAN_TIMEOUT_MAX;
	list_insert_tail(&pcwl_p->pcwl_scan_list, scan_item);
	pcwl_p->pcwl_scan_num++;
	return (PCWL_SUCCESS);
}

static void
pcwl_delete_scan_item(pcwl_maci_t *pcwl_p, wl_scan_list_t *s)
{
	list_remove(&pcwl_p->pcwl_scan_list, s);
	kmem_free(s, sizeof (*s));
	pcwl_p->pcwl_scan_num--;
}

static void
pcwl_scanlist_timeout(void *arg)
{
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;
	wl_scan_list_t *scan_item0, *scan_item1;

	mutex_enter(&pcwl_p->pcwl_scanlist_lock);
	scan_item0 = list_head(&pcwl_p->pcwl_scan_list);
	for (; scan_item0; ) {
		PCWLDBG((CE_NOTE, "ssid = %s\n",
		    scan_item0->wl_val.wl_srt_ssid));
		PCWLDBG((CE_NOTE, "timeout left: %ds",
		    scan_item0->wl_timeout));
		scan_item1 = list_next(&pcwl_p->pcwl_scan_list, scan_item0);
		if (scan_item0->wl_timeout == 0) {
			pcwl_delete_scan_item(pcwl_p, scan_item0);
		} else {
			scan_item0->wl_timeout--;
		}
		scan_item0 = scan_item1;
	}
	mutex_exit(&pcwl_p->pcwl_scanlist_lock);
	pcwl_p->pcwl_scanlist_timeout_id = timeout(pcwl_scanlist_timeout,
	    pcwl_p, drv_usectohz(1000000));
}

static void
pcwl_get_rssi(pcwl_maci_t *pcwl_p)
{
	wl_scan_list_t *scan_item0;
	uint16_t cq[3];

	bzero(cq, sizeof (cq));
	mutex_enter(&pcwl_p->pcwl_scanlist_lock);
	scan_item0 = list_head(&pcwl_p->pcwl_scan_list);
	for (; scan_item0; ) {
		if (bcmp(scan_item0->wl_val.wl_srt_bssid,
		    pcwl_p->pcwl_bssid, 6) == 0) {
			pcwl_p->pcwl_rssi = scan_item0->wl_val.wl_srt_sl;
		}
		scan_item0 = list_next(&pcwl_p->pcwl_scan_list, scan_item0);
	}
	mutex_exit(&pcwl_p->pcwl_scanlist_lock);
	if (!pcwl_p->pcwl_rssi) {
		(void) pcwl_get_ltv(pcwl_p, 6, WL_RID_COMMQUAL, cq);
		pcwl_p->pcwl_rssi = cq[1];
	}
}

/*
 * Note:
 * PrismII chipset has 2 extra space for the reason why scan is initiated
 */
static void
pcwl_ssid_scan(pcwl_maci_t *pcwl_p, uint16_t fid, uint16_t flen, uint16_t stype)
{
	uint16_t stat;
	uint16_t ssidNum, i;
	uint16_t off, szbuf;
	uint16_t tmp[2];
	wl_scan_list_t *scan_item0;
	uint32_t check_num;
	uint8_t	bssid_t[6];

	wl_scan_result_t sctbl;

	off = sizeof (uint16_t) * 2;
	switch (pcwl_p->pcwl_chip_type) {
	case PCWL_CHIP_PRISMII:
		(void) RDCH0(pcwl_p, fid, off, tmp, 4);
		off += 4;
		szbuf = (stype == WL_INFO_SCAN_RESULTS ? 31 : 32);
		PCWLDBG((CE_NOTE, "pcwl ssid_scan: PRISM chip\n"));
		break;
	case PCWL_CHIP_LUCENT:
		PCWLDBG((CE_NOTE, "pcwl ssid_scan LUCENT chip\n"));
	default:
		szbuf = 25;
	}

	flen = flen + 1 - (off >> 1);
	ssidNum = flen/szbuf;
	ssidNum = min(WL_SRT_MAX_NUM, ssidNum);

	PCWLDBG((CE_NOTE, "pcwl: ssid_scan frame length = %d\n", flen));

	PCWLDBG((CE_NOTE, "pcwl ssid_scan: %d ssid(s) available", ssidNum));

	bzero(bssid_t, sizeof (bssid_t));
	for (i = 0; i < ssidNum; i++) {
		(void) RDCH0(pcwl_p, fid, off, (uint16_t *)&sctbl, 2*szbuf);

#ifdef DEBUG
		if (pcwl_debug & PCWL_DBG_INFO) {
			int j;
			for (j = 0; j < sizeof (sctbl); j++)
				cmn_err(CE_NOTE, "%d: %x\n", j,
				    *((uint8_t *)&sctbl + j));
		}
#endif

		off += (szbuf << 1);
		stat = min(sctbl.wl_srt_ssidlen, 31);
		PCWL_SWAP16((uint16_t *)(sctbl.wl_srt_bssid), 6);
		PCWL_SWAP16((uint16_t *)(sctbl.wl_srt_ssid), stat);
		sctbl.wl_srt_ssid[stat] = '\0';
		sctbl.wl_srt_sl &= 0x7f;

		/*
		 * sometimes, those empty items are recorded by hardware,
		 * this is wrong, just ignore those items here.
		 */
		if (bcmp(sctbl.wl_srt_bssid,
		    bssid_t, 6) == 0) {
			continue;
		}
		if (bcmp(sctbl.wl_srt_bssid,
		    pcwl_p->pcwl_bssid, 6) == 0) {
			pcwl_p->pcwl_rssi = sctbl.wl_srt_sl;
		}
		/*
		 * save/update the scan item in scanlist
		 */
		mutex_enter(&pcwl_p->pcwl_scanlist_lock);
		check_num = 0;
		scan_item0 = list_head(&pcwl_p->pcwl_scan_list);
		if (scan_item0 == NULL) {
			if (pcwl_add_scan_item(pcwl_p, sctbl)
			    != 0) {
				mutex_exit(&pcwl_p->pcwl_scanlist_lock);
				return;
			}
		}
		for (; scan_item0; ) {
			if (bcmp(sctbl.wl_srt_bssid,
			    scan_item0->wl_val.wl_srt_bssid, 6) == 0) {
				scan_item0->wl_val = sctbl;
				scan_item0->wl_timeout = WL_SCAN_TIMEOUT_MAX;
				break;
			} else {
				check_num++;
			}
			scan_item0 = list_next(&pcwl_p->pcwl_scan_list,
			    scan_item0);
		}
		if (check_num == pcwl_p->pcwl_scan_num) {
			if (pcwl_add_scan_item(pcwl_p, sctbl)
			    != 0) {
				mutex_exit(&pcwl_p->pcwl_scanlist_lock);
				return;
			}
		}
		mutex_exit(&pcwl_p->pcwl_scanlist_lock);
		PCWLDBG((CE_NOTE, "pcwl ssid_scan: ssid%d = %s\n", i+1,
		    sctbl.wl_srt_ssid));
		PCWLDBG((CE_NOTE, "pcwl ssid_scan: channel = %d\n",
		    sctbl.wl_srt_chid));
		PCWLDBG((CE_NOTE, "pcwl ssid_scan: signal level= %d\n",
		    sctbl.wl_srt_sl));
		PCWLDBG((CE_NOTE, "pcwl ssid_scan: noise level = %d\n",
		    sctbl.wl_srt_anl));
		PCWLDBG((CE_NOTE, "pcwl ssid_scan: bssid%d ="
		    " %x %x %x %x %x %x\n\n", i+1,
		    sctbl.wl_srt_bssid[0],
		    sctbl.wl_srt_bssid[1],
		    sctbl.wl_srt_bssid[2],
		    sctbl.wl_srt_bssid[3],
		    sctbl.wl_srt_bssid[4],
		    sctbl.wl_srt_bssid[5]));
	}

}

/*
 * delay in which the mutex is not hold.
 * assuming the mutex has already been hold.
 */
static void
pcwl_delay(pcwl_maci_t *pcwl_p, clock_t microsecs)
{
	ASSERT(mutex_owned(&pcwl_p->pcwl_glock));

	mutex_exit(&pcwl_p->pcwl_glock);
	delay(drv_usectohz(microsecs));
	mutex_enter(&pcwl_p->pcwl_glock);
}

static int
pcwl_reset_backend(pcwl_maci_t *pcwl_p)
{
	uint16_t ret = 0;

	if (ret =  pcwl_set_cmd(pcwl_p, WL_CMD_INI, 0)) {
		return ((int)ret);
	}

	pcwl_delay(pcwl_p, 100000); /* wait .1 sec */

	if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_INI, 0)) {
		return ((int)ret);
	}
	pcwl_delay(pcwl_p, 100000); /* wait .1 sec */

	PCWL_DISABLE_INTR(pcwl_p);
	return (PCWL_SUCCESS);
}


/*
 * get card capability (WEP, default channel), setup broadcast, mac addresses
 */
static int
pcwl_get_cap(pcwl_maci_t *pcwl_p)
{
	uint16_t stat, ch_no;
	uint16_t buf[ETHERADDRL >> 1];

	bzero(buf, ETHERADDRL);
	if (stat = pcwl_get_ltv(pcwl_p, 2, WL_RID_OWN_CHNL, &ch_no)) {
		cmn_err(CE_CONT, "pcwl get_cap: get def channel failed"
		    " %x\n", stat);
		return ((int)stat);
	}
	if (stat = pcwl_get_ltv(pcwl_p, 2, WL_RID_WEP_AVAIL,
	    &pcwl_p->pcwl_has_wep)) {
		cmn_err(CE_CONT, "pcwl get_cap: get WEP capability failed"
		    " %x\n", stat);
		return ((int)stat);
	}
	if (stat = pcwl_get_ltv(pcwl_p, ETHERADDRL, WL_RID_MAC_NODE, buf)) {
		cmn_err(CE_CONT, "pcwl get_cap: get macaddr failed"
		    " %x\n", stat);
		return ((int)stat);
	}

	/*
	 * don't assume m_xxx members are 16-bit aligned
	 */
	PCWL_SWAP16(buf, ETHERADDRL);
	ether_copy(buf, pcwl_p->pcwl_mac_addr);
	return (PCWL_SUCCESS);
}

static int
pcwl_init_nicmem(pcwl_maci_t *pcwl_p)
{
	uint16_t ret, i;
	uint16_t rc;

	for (i = 0; i < WL_XMT_BUF_NUM; i++) {
		ret = pcwl_alloc_nicmem(pcwl_p, PCWL_NICMEM_SZ, &rc);
		if (ret) {
			cmn_err(CE_WARN,
			    "pcwl: alloc NIC Tx buf failed %x\n", ret);
			return (PCWL_FAIL);
		}
		pcwl_p->pcwl_txring.wl_tx_fids[i] = rc;
		pcwl_p->pcwl_txring.wl_tx_ring[i] = 0;
		PCWLDBG((CE_NOTE, "pcwl: alloc_nicmem_id[%d]=%x\n", i, rc));
	}
	pcwl_p->pcwl_txring.wl_tx_prod = pcwl_p->pcwl_txring.wl_tx_cons = 0;

	ret = pcwl_alloc_nicmem(pcwl_p, PCWL_NICMEM_SZ, &pcwl_p->pcwl_mgmt_id);
	if (ret) {
		cmn_err(CE_WARN, "pcwl: alloc NIC Mgmt buf failed %x\n", ret);
		return (PCWL_FAIL);
	}
	PCWLDBG((CE_NOTE, "pcwl: alloc_nicmem mgmt_id=%x\n",
	    pcwl_p->pcwl_mgmt_id));
	return (PCWL_SUCCESS);
}

static int
pcwl_loaddef_rf(pcwl_maci_t *pcwl_p)
{
	pcwl_p->pcwl_rf.rf_max_datalen = WL_DEFAULT_DATALEN;
	pcwl_p->pcwl_rf.rf_create_ibss = WL_DEFAULT_CREATE_IBSS;
	pcwl_p->pcwl_rf.rf_porttype = WL_BSS_BSS;
	pcwl_p->pcwl_rf.rf_rts_thresh = WL_DEFAULT_RTS_THRESH;
	pcwl_p->pcwl_rf.rf_tx_rate = WL_TX_RATE_FIX_11M(pcwl_p);
	pcwl_p->pcwl_rf.rf_pm_enabled = WL_DEFAULT_PM_ENABLED;
	pcwl_p->pcwl_rf.rf_own_chnl = WL_DEFAULT_CHAN;
	(void) strcpy(pcwl_p->pcwl_rf.rf_own_ssid, "");
	(void) strcpy(pcwl_p->pcwl_rf.rf_desired_ssid, "");
	(void) strcpy(pcwl_p->pcwl_rf.rf_nodename, "");
	pcwl_p->pcwl_rf.rf_encryption = WL_NOENCRYPTION;
	pcwl_p->pcwl_rf.rf_authtype = WL_OPENSYSTEM;
	pcwl_p->pcwl_rf.rf_tx_crypt_key = WL_DEFAULT_TX_CRYPT_KEY;
	bzero((pcwl_p->pcwl_rf.rf_ckeys), sizeof (rf_ckey_t) * 4);

	pcwl_p->pcwl_rf.rf_promiscuous = 0;

	return (pcwl_config_rf(pcwl_p));
}

static int
pcwl_config_rf(pcwl_maci_t *pcwl_p)
{
	pcwl_rf_t *rf_p = &pcwl_p->pcwl_rf;
	uint16_t create_ibss, porttype;

	/*
	 * Lucent card:
	 * 0 Join ESS or IBSS; 1 Join ESS or join/create IBSS
	 * PrismII card:
	 * 3 Join ESS or IBSS(do not create IBSS);
	 * 1 Join ESS or join/create IBSS
	 */
	create_ibss = rf_p->rf_create_ibss;
	if (pcwl_p->pcwl_chip_type == PCWL_CHIP_PRISMII) {
		if (rf_p->rf_create_ibss == 0)
			create_ibss = 3;
	}
	/*
	 * Lucent card:
	 * 1 BSS; 3 pseudo IBSS(only for test,not the 802.11 IBSS)
	 * so porttype register should always be set to 1
	 * PrismII card:
	 * 0 IBSS; 1 BSS; 2 WDS; 3 pseudo IBSS; 6 hostAP
	 */
	switch (pcwl_p->pcwl_chip_type) {
	case PCWL_CHIP_PRISMII:
		if (rf_p->rf_porttype == WL_BSS_BSS)
			porttype = 1;
		else if (rf_p->rf_porttype == WL_BSS_IBSS)
			porttype = 0;
		else
			porttype = 0;
		break;
	case PCWL_CHIP_LUCENT:
	default:
		porttype = 1;
	}


	FIL_LTV(pcwl_p, PCWL_MCBUF_LEN, WL_RID_MCAST, 0);
	FIL_LTV(pcwl_p, 2,	WL_RID_PROMISC,		0);
	FIL_LTV(pcwl_p, 2,	WL_RID_TICK_TIME,	0);

	FIL_LTV(pcwl_p, 2, WL_RID_MAX_DATALEN, rf_p->rf_max_datalen);
	FIL_LTV(pcwl_p, 2, WL_RID_CREATE_IBSS, create_ibss);
	FIL_LTV(pcwl_p, 2, WL_RID_PORTTYPE, porttype);
	FIL_LTV(pcwl_p, 2, WL_RID_RTS_THRESH, rf_p->rf_rts_thresh);
	FIL_LTV(pcwl_p, 2, WL_RID_TX_RATE, rf_p->rf_tx_rate);
	FIL_LTV(pcwl_p, 2, WL_RID_SYSTEM_SCALE, rf_p->rf_system_scale);
	FIL_LTV(pcwl_p, 2, WL_RID_PM_ENABLED, rf_p->rf_pm_enabled);
	FIL_LTV(pcwl_p, 2, WL_RID_MAX_SLEEP, rf_p->rf_max_sleep);
	FIL_LTV(pcwl_p, 2, WL_RID_OWN_CHNL, rf_p->rf_own_chnl);

	PUT_STR(pcwl_p, WL_RID_OWN_SSID, rf_p->rf_own_ssid);
	PUT_STR(pcwl_p, WL_RID_DESIRED_SSID, rf_p->rf_desired_ssid);
	PUT_STR(pcwl_p, WL_RID_NODENAME, rf_p->rf_nodename);

	if (!pcwl_p->pcwl_has_wep)
		goto done;

	switch (pcwl_p->pcwl_chip_type) {
	case PCWL_CHIP_PRISMII: {
		int i;

		for (i = 0; i < 4; i++) {
			int k_len = strlen((char *)rf_p->rf_ckeys[i].ckey_dat);
			if (k_len == 0)
				continue;
			k_len = k_len > 5 ? 14 : 6;
			PUT_LTV(pcwl_p, k_len, WL_RID_CRYPT_KEY0_P2 + i,
			    (uint16_t *)&rf_p->rf_ckeys[i].ckey_dat);
		}
		FIL_LTV(pcwl_p, 2, WL_RID_TX_CRYPT_KEY_P2,
		    rf_p->rf_tx_crypt_key);
		FIL_LTV(pcwl_p, 2, WL_RID_AUTHTYPE_P2,
		    rf_p->rf_authtype);
		FIL_LTV(pcwl_p, 2, WL_RID_ENCRYPTION_P2,
		    rf_p->rf_encryption);
		if (pcwl_p->pcwl_rf.rf_promiscuous)
			FIL_LTV(pcwl_p, 2, WL_RID_PROMISC, 1);
		}
		break;
	case PCWL_CHIP_LUCENT:
	default:
		FIL_LTV(pcwl_p, 2, WL_RID_ENCRYPTION,
		    rf_p->rf_encryption);
		FIL_LTV(pcwl_p, 2, WL_RID_AUTHTYPE_L,
		    rf_p->rf_authtype);
		FIL_LTV(pcwl_p, 2, WL_RID_TX_CRYPT_KEY,
		    rf_p->rf_tx_crypt_key);
		PUT_LTV(pcwl_p, sizeof (rf_p->rf_ckeys),
		    WL_RID_DEFLT_CRYPT_KEYS,
		    (uint16_t *)rf_p->rf_ckeys);
		break;
	}
done:
	return (PCWL_SUCCESS);
}

static void
pcwl_start_locked(pcwl_maci_t *pcwl_p)
{
	pcwl_p->pcwl_flag |= PCWL_CARD_INTREN;
	PCWL_ENABLE_INTR(pcwl_p);
}

static void
pcwl_stop_locked(pcwl_maci_t *pcwl_p)
{
	PCWL_DISABLE_INTR(pcwl_p);
	pcwl_p->pcwl_flag &= (~PCWL_CARD_INTREN);
	PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_TX|WL_EV_RX|WL_EV_TX_EXC|
	    WL_EV_ALLOC|WL_EV_INFO|WL_EV_INFO_DROP);
	PCWL_WRITE(pcwl_p, WL_EVENT_ACK, WL_EV_TX|WL_EV_RX|WL_EV_TX_EXC|
	    WL_EV_ALLOC| WL_EV_INFO|WL_EV_INFO_DROP);
}

/*ARGSUSED*/
static int
pcwl_saddr_locked(pcwl_maci_t *pcwl_p)
{
	int ret;
	uint16_t buf[ETHERADDRL >> 1];

	ether_copy(pcwl_p->pcwl_mac_addr, buf);
	PCWL_SWAP16(buf, ETHERADDRL);
	ret = pcwl_put_ltv(pcwl_p, ETHERADDRL, WL_RID_MAC_NODE, buf);
	if (ret) {
		cmn_err(CE_WARN, "pcwl set_mac_addr: failed %x\n", ret);
		return (PCWL_FAIL);
	}
	return (PCWL_SUCCESS);
}

static void
pcwl_chip_type(pcwl_maci_t *pcwl_p)
{
	pcwl_ltv_ver_t ver;
	pcwl_ltv_fwver_t f;

	bzero(&ver, sizeof (ver));
	(void) pcwl_get_ltv(pcwl_p, sizeof (ver),
	    WL_RID_CARD_ID, (uint16_t *)&ver);
	PCWLDBG((CE_NOTE, "card id:%04x-%04x-%04x-%04x\n",
	    ver.wl_compid, ver.wl_variant, ver.wl_major, ver.wl_minor));
	if ((ver.wl_compid & 0xf000) != 0x8000)
		return;	/* lucent */

	pcwl_p->pcwl_chip_type = PCWL_CHIP_PRISMII;
	(void) pcwl_get_ltv(pcwl_p, sizeof (ver), WL_RID_COMP_IDENT,
	    (uint16_t *)&ver);
	PCWLDBG((CE_NOTE, "PRISM-II ver:%04x-%04x-%04x-%04x\n",
	    ver.wl_compid, ver.wl_variant, ver.wl_major, ver.wl_minor));

	bzero(&f, sizeof (f));
	(void) pcwl_get_ltv(pcwl_p, sizeof (f), WL_RID_FWVER, (uint16_t *)&f);
	PCWL_SWAP16((uint16_t *)&f, sizeof (f));
	PCWLDBG((CE_NOTE, "Firmware Pri:%s 2,3:%s\n",
	    (char *)f.pri, (char *)f.st));
}

/*
 * for wificonfig and dladm ioctl
 */

static int
pcwl_cfg_essid(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	char ssid[36];
	uint16_t ret, i;
	uint16_t val;
	pcwl_rf_t *rf_p;
	char *value;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;

	bzero(ssid, sizeof (ssid));
	if (cmd == WLAN_GET_PARAM) {
		ret =  pcwl_get_ltv(pcwl_p, 2,
		    WL_RID_PORTSTATUS, &val);
		if (ret) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			PCWLDBG((CE_WARN, "cfg_essid_get_error\n"));
			goto done;
		}
		PCWLDBG((CE_NOTE, "PortStatus = %d\n", val));

		if (val == WL_PORT_DISABLED || val == WL_PORT_INITIAL) {
			outfp->wldp_length = WIFI_BUF_OFFSET +
			    offsetof(wl_essid_t, wl_essid_essid) +
			    mi_strlen(rf_p->rf_desired_ssid);
			((wl_essid_t *)(outfp->wldp_buf))->wl_essid_length =
			    mi_strlen(rf_p->rf_desired_ssid);
			bcopy(rf_p->rf_desired_ssid, buf + WIFI_BUF_OFFSET +
			    offsetof(wl_essid_t, wl_essid_essid),
			    mi_strlen(rf_p->rf_desired_ssid));
		} else if (val == WL_PORT_TO_IBSS ||
		    val == WL_PORT_TO_BSS ||
		    val == WL_PORT_OOR) {
			(void) pcwl_get_ltv((pcwl_p), 34,
			    WL_RID_SSID, (uint16_t *)ssid);
			PCWL_SWAP16((uint16_t *)(ssid+2), *(uint16_t *)ssid);
			ssid[*(uint16_t *)ssid + 2] = '\0';
			outfp->wldp_length = WIFI_BUF_OFFSET +
			    offsetof(wl_essid_t, wl_essid_essid) +
			    mi_strlen(ssid+2);
			((wl_essid_t *)(outfp->wldp_buf))->wl_essid_length =
			    mi_strlen(ssid+2);
			bcopy(ssid + 2, buf + WIFI_BUF_OFFSET +
			    offsetof(wl_essid_t, wl_essid_essid),
			    mi_strlen(ssid+2));
		} else {
			outfp->wldp_length = WIFI_BUF_OFFSET;
		}
		outfp->wldp_result = WL_SUCCESS;
		PCWLDBG((CE_CONT, "outfp->length=%d\n", outfp->wldp_length));
		PCWLDBG((CE_CONT, "pcwl: get desired essid=%s\n",
		    rf_p->rf_desired_ssid));
	} else if (cmd == WLAN_SET_PARAM) {
		value = ((wl_essid_t *)(infp->wldp_buf))->wl_essid_essid;
		(void) strncpy(rf_p->rf_desired_ssid, value,
		    MIN(32, strlen(value)));
		rf_p->rf_desired_ssid[strlen(value)] = '\0';
		(void) strncpy(rf_p->rf_own_ssid, value,
		    MIN(32, strlen(value)));
		rf_p->rf_own_ssid[strlen(value)] = '\0';
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_SUCCESS;
		PCWLDBG((CE_CONT, "pcwl: set: desired essid=%s\n",
		    rf_p->rf_desired_ssid));
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
pcwl_cfg_bssid(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t ret, i;
	int iret;
	wldp_t *outfp;
	char *buf;
	uint8_t bssid[6];

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_bssid_t);
	if (cmd == WLAN_GET_PARAM) {
		if (ret = pcwl_get_ltv(pcwl_p, 2,
		    WL_RID_PORTSTATUS, &ret)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			goto done;
		}
		PCWLDBG((CE_NOTE, "PortStatus = %d\n", ret));
		if (ret == WL_PORT_DISABLED || ret == WL_PORT_INITIAL) {
			bzero(buf + WIFI_BUF_OFFSET,
			    sizeof (wl_bssid_t));
		} else if (ret == WL_PORT_TO_IBSS ||
		    ret == WL_PORT_TO_BSS || ret == WL_PORT_OOR) {
			(void) pcwl_get_ltv(pcwl_p, 6,
			    WL_RID_BSSID, (uint16_t *)bssid);
			PCWL_SWAP16((uint16_t *)bssid, 6);
			bcopy(bssid, buf + WIFI_BUF_OFFSET,
			    sizeof (wl_bssid_t));
		}
		outfp->wldp_result = WL_SUCCESS;

		PCWLDBG((CE_CONT, "pcwl_getset: bssid=%x %x %x %x %x %x\n",
		    bssid[0], bssid[1], bssid[2],
		    bssid[3], bssid[4], bssid[5]));
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
pcwl_cmd_scan(pcwl_maci_t *pcwl_p)
{
	uint16_t vall[18], ret = WL_SUCCESS;
	pcwl_rf_t *rf_p;
	uint32_t enable, i;
	size_t	len;

	rf_p = &pcwl_p->pcwl_rf;

	/*
	 * The logic of this funtion is really tricky.
	 * Firstly, the chip can only scan in BSS mode, so necessary
	 * backup and restore is required before and after the scan
	 * command.
	 * Secondly, for Lucent chip, Alrealy associated with an AP
	 * can only scan the APes on the fixed channel, so we must
	 * set the desired_ssid as "" before scan and restore after.
	 * Thirdly, scan cmd is effective only when the card is enabled
	 * and any 'set' operation(such as set bsstype, ssid)must disable
	 * the card first and then enable the card after the 'set'
	 */
	enable = pcwl_p->pcwl_flag & PCWL_ENABLED;
	len = strlen(rf_p->rf_desired_ssid);

	if (pcwl_p->pcwl_rf.rf_porttype != WL_BSS_BSS) {
		if ((enable) &&
		    (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0))) {
			ret = (int)WL_HW_ERROR;
			goto done;
		}
		FIL_LTV(pcwl_p, 2, WL_RID_PORTTYPE, WL_BSS_BSS);
	}

	if ((pcwl_p->pcwl_chip_type == PCWL_CHIP_LUCENT) && (len != 0)) {
		if ((enable) &&
		    (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0))) {
			ret = (int)WL_HW_ERROR;
			goto done;
		}
		PUT_STR(pcwl_p, WL_RID_DESIRED_SSID, "");
	}

	if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_ENABLE, 0)) {
		ret = (int)WL_HW_ERROR;
		goto done;
	}
	pcwl_delay(pcwl_p, 1000000);

	switch (pcwl_p->pcwl_chip_type) {
	case PCWL_CHIP_PRISMII:
		bzero(vall, sizeof (vall));
		vall[0] = 0x3fff; /* channel mask */
		vall[1] = 0x1; /* tx rate */
		for (i = 0; i < WL_MAX_SCAN_TIMES; i++) {
			PUT_LTV(pcwl_p, sizeof (vall),
			    WL_RID_HSCAN_REQUEST, vall);
			pcwl_delay(pcwl_p, 1000000);
			if (pcwl_p->pcwl_scan_num >= WL_SCAN_AGAIN_THRESHOLD)
				break;
		}
		PCWLDBG((CE_NOTE, "PRISM chip\n"));
		break;

	case PCWL_CHIP_LUCENT:
		PCWLDBG((CE_NOTE, "LUCENT chip\n"));
	default:
		for (i = 0; i < WL_MAX_SCAN_TIMES; i++) {
			if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_INQUIRE,
			    WL_INFO_SCAN_RESULTS)) {
				ret = (int)WL_HW_ERROR;
				goto done;
			}
			pcwl_delay(pcwl_p, 500000);
			if (pcwl_p->pcwl_scan_num >= WL_SCAN_AGAIN_THRESHOLD)
				break;
		}
		break;
	}
	if ((pcwl_p->pcwl_rf.rf_porttype != WL_BSS_BSS) ||
	    ((pcwl_p->pcwl_chip_type == PCWL_CHIP_LUCENT) && (len != 0))) {
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			goto done;
		}
		if (ret = pcwl_config_rf(pcwl_p)) {
			ret = (int)WL_HW_ERROR;
			goto done;
		}
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_ENABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			goto done;
		}

		pcwl_delay(pcwl_p, 1000000);
	}

	if ((!enable) && (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0))) {
		ret = (int)WL_HW_ERROR;
	}
done:
	if (ret)
		cmn_err(CE_WARN, "pcwl: scan failed due to hardware error");
	return (ret);

}

/*ARGSUSED*/
static int
pcwl_cfg_scan(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	wl_ess_conf_t *p_ess_conf;
	wldp_t *outfp;
	char *buf;
	uint16_t i;
	wl_scan_list_t *scan_item;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	mutex_enter(&pcwl_p->pcwl_scanlist_lock);
	((wl_ess_list_t *)(outfp->wldp_buf))->wl_ess_list_num =
	    pcwl_p->pcwl_scan_num;
	outfp->wldp_length = WIFI_BUF_OFFSET +
	    offsetof(wl_ess_list_t, wl_ess_list_ess) +
	    pcwl_p->pcwl_scan_num * sizeof (wl_ess_conf_t);

	scan_item = list_head(&pcwl_p->pcwl_scan_list);
	for (i = 0; i < pcwl_p->pcwl_scan_num; i++) {
		if (!scan_item)
			goto done;
		p_ess_conf = (wl_ess_conf_t *)(buf + WIFI_BUF_OFFSET +
		    offsetof(wl_ess_list_t, wl_ess_list_ess) +
		    i * sizeof (wl_ess_conf_t));
		bcopy(scan_item->wl_val.wl_srt_ssid,
		    p_ess_conf->wl_ess_conf_essid.wl_essid_essid,
		    mi_strlen(scan_item->wl_val.wl_srt_ssid));
		bcopy(scan_item->wl_val.wl_srt_bssid,
		    p_ess_conf->wl_ess_conf_bssid, 6);
		(p_ess_conf->wl_phy_conf).wl_phy_dsss_conf.wl_dsss_subtype
		    = WL_DSSS;
		p_ess_conf->wl_ess_conf_wepenabled =
		    (scan_item->wl_val.wl_srt_cap & 0x10 ?
		    WL_ENC_WEP : WL_NOENCRYPTION);
		p_ess_conf->wl_ess_conf_bsstype =
		    (scan_item->wl_val.wl_srt_cap & 0x1 ?
		    WL_BSS_BSS : WL_BSS_IBSS);
		p_ess_conf->wl_phy_conf.wl_phy_dsss_conf.wl_dsss_channel =
		    scan_item->wl_val.wl_srt_chid;
		if (pcwl_p->pcwl_chip_type == PCWL_CHIP_PRISMII) {
			p_ess_conf->wl_ess_conf_sl =
			    min(scan_item->wl_val.wl_srt_sl * 15 / 85 + 1,
			    15);
		} else {
			if (scan_item->wl_val.wl_srt_sl <= 27)
				p_ess_conf->wl_ess_conf_sl = 1;
			else if (scan_item->wl_val.wl_srt_sl > 154)
				p_ess_conf->wl_ess_conf_sl = 15;
			else
				p_ess_conf->wl_ess_conf_sl = min(15,
				    ((scan_item->wl_val.wl_srt_sl - 27)
				    * 15 / 127));
		}
		p_ess_conf->wl_supported_rates[0] = WL_RATE_1M;
		p_ess_conf->wl_supported_rates[1] = WL_RATE_2M;
		p_ess_conf->wl_supported_rates[2] = WL_RATE_5_5M;
		p_ess_conf->wl_supported_rates[3] = WL_RATE_11M;
		scan_item = list_next(&pcwl_p->pcwl_scan_list, scan_item);
	}
done:
	mutex_exit(&pcwl_p->pcwl_scanlist_lock);
	outfp->wldp_result = WL_SUCCESS;

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	kmem_free(buf, MAX_BUF_LEN);
	return (WL_SUCCESS);
}

/*ARGSUSED*/
static int
pcwl_cfg_linkstatus(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	wldp_t *outfp;
	char *buf;
	uint16_t i, ret, val;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	ret =  pcwl_get_ltv(pcwl_p, 2,
	    WL_RID_PORTSTATUS, &val);
	if (ret) {
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_HW_ERROR;
		PCWLDBG((CE_WARN, "cfg_linkstatus_get_error\n"));
		goto done;
	}
	PCWLDBG((CE_NOTE, "PortStatus = %d\n", val));
	if (val == WL_PORT_DISABLED || val == WL_PORT_INITIAL) {
		*(wl_linkstatus_t *)(outfp->wldp_buf) = WL_NOTCONNECTED;
		outfp->wldp_length = WIFI_BUF_OFFSET +
		    sizeof (wl_linkstatus_t);
	} else if (val == WL_PORT_TO_IBSS ||
	    val == WL_PORT_TO_BSS || val == WL_PORT_OOR) {
		*(wl_linkstatus_t *)(outfp->wldp_buf) = WL_CONNECTED;
		outfp->wldp_length = WIFI_BUF_OFFSET +
		    sizeof (wl_linkstatus_t);
	} else {
		outfp->wldp_length = WIFI_BUF_OFFSET;
	}
	outfp->wldp_result = WL_SUCCESS;
done:
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
pcwl_cfg_bsstype(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t ret, i;
	pcwl_rf_t *rf_p;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_bss_type_t);
	if (cmd == WLAN_GET_PARAM) {
		*(wl_bss_type_t *)(outfp->wldp_buf) = rf_p->rf_porttype;
		PCWLDBG((CE_CONT, "pcwl_getset: porttype=%d\n",
		    rf_p->rf_porttype));
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		ret = (uint16_t)(*(wl_bss_type_t *)(infp->wldp_buf));
		if ((ret != WL_BSS_BSS) &&
		    (ret != WL_BSS_IBSS) &&
		    (ret != WL_BSS_ANY)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_NOTSUPPORTED;
			goto done;
		}
		rf_p->rf_porttype = ret;
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

static int
pcwl_cfg_phy(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t ret, retval, i;
	pcwl_rf_t *rf_p;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_dsss_t);
	if (cmd == WLAN_GET_PARAM) {
		if (ret = pcwl_get_ltv(pcwl_p, 2,
		    WL_RID_CURRENT_CHNL, &retval)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			goto done;
		}
		((wl_dsss_t *)(outfp->wldp_buf))->wl_dsss_channel = retval;
		PCWLDBG((CE_CONT, "pcwl_getset: channel=%d\n", retval));
		((wl_dsss_t *)(outfp->wldp_buf))->wl_dsss_subtype = WL_DSSS;
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		ret = (uint16_t)
		    (((wl_phy_conf_t *)(infp->wldp_buf))
		    ->wl_phy_dsss_conf.wl_dsss_channel);
		if (ret < 1 || ret > 14) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_NOTSUPPORTED;
			goto done;
		}
		rf_p->rf_own_chnl = ret;
		PCWLDBG((CE_CONT, "pcwl: set channel=%d\n", rf_p->rf_own_chnl));
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

static int
pcwl_cfg_desiredrates(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t rate;
	uint16_t i;
	pcwl_rf_t *rf_p;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;
	char rates[4];
	char maxrate;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;

	if (cmd == WLAN_GET_PARAM) {
		if (i = pcwl_get_ltv(pcwl_p, 2, WL_RID_TX_RATE, &rate)) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_HW_ERROR;
			goto done;
		}

		if (pcwl_p->pcwl_chip_type == PCWL_CHIP_PRISMII) {
			((wl_rates_t *)(outfp->wldp_buf))->wl_rates_num = 1;
			outfp->wldp_length = WIFI_BUF_OFFSET +
			    offsetof(wl_rates_t, wl_rates_rates) +
			    1 * sizeof (char);
			switch (rate) {
			case WL_SPEED_1Mbps_P2:
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_1M;
				break;
			case WL_SPEED_2Mbps_P2:
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_2M;
				break;
			case WL_SPEED_55Mbps_P2:
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_5_5M;
				break;
			case WL_SPEED_11Mbps_P2:
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_11M;
				break;
			default:
				outfp->wldp_length = WIFI_BUF_OFFSET;
				outfp->wldp_result = WL_HW_ERROR;
				goto done;
			}
		} else {
			switch (rate) {
			case WL_L_TX_RATE_FIX_1M:
				((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_num = 1;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_1M;
				outfp->wldp_length = WIFI_BUF_OFFSET +
				    offsetof(wl_rates_t, wl_rates_rates) +
				    1 * sizeof (char);
				break;
			case WL_L_TX_RATE_FIX_2M:
				((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_num = 1;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_2M;
				outfp->wldp_length = WIFI_BUF_OFFSET +
				    offsetof(wl_rates_t, wl_rates_rates) +
				    1 * sizeof (char);
				break;
			case WL_L_TX_RATE_AUTO_H:
				((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_num = 4;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_1M;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[1] = WL_RATE_2M;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[2] = WL_RATE_5_5M;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[3] = WL_RATE_11M;
				outfp->wldp_length = WIFI_BUF_OFFSET +
				    offsetof(wl_rates_t, wl_rates_rates) +
				    4 * sizeof (char);
				break;
			case WL_L_TX_RATE_FIX_5M:
				((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_num = 1;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_5_5M;
				outfp->wldp_length = WIFI_BUF_OFFSET +
				    offsetof(wl_rates_t, wl_rates_rates) +
				    1 * sizeof (char);
				break;
			case WL_L_TX_RATE_FIX_11M:
				((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_num = 1;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_11M;
				outfp->wldp_length = WIFI_BUF_OFFSET +
				    offsetof(wl_rates_t, wl_rates_rates) +
				    1 * sizeof (char);
				break;
			case WL_L_TX_RATE_AUTO_L:
				((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_num = 2;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_1M;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[1] = WL_RATE_2M;
				outfp->wldp_length = WIFI_BUF_OFFSET +
				    offsetof(wl_rates_t, wl_rates_rates) +
				    2 * sizeof (char);
				break;
			case WL_L_TX_RATE_AUTO_M:
				((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_num = 3;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[0] = WL_RATE_1M;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[1] = WL_RATE_2M;
				(((wl_rates_t *)(outfp->wldp_buf))->
				    wl_rates_rates)[2] = WL_RATE_5_5M;
				outfp->wldp_length = WIFI_BUF_OFFSET +
				    offsetof(wl_rates_t, wl_rates_rates) +
				    3 * sizeof (char);
				break;
			default:
				outfp->wldp_length = WIFI_BUF_OFFSET;
				outfp->wldp_result = WL_HW_ERROR;
				goto done;
			}
		}
		PCWLDBG((CE_CONT, "pcwl: get rate=%d\n", rate));
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		bzero(rates, sizeof (rates));
		for (i = 0; i < 4; i++) {
			rates[i] = (((wl_rates_t *)
			    (infp->wldp_buf))->wl_rates_rates)[i];
			PCWLDBG((CE_CONT, "pcwl: set tx_rate[%d]=%d\n",
			    i, rates[i]));
		}
		PCWLDBG((CE_CONT, "pcwl: set rate_num=%d\n",
		    ((wl_rates_t *)(infp->wldp_buf))
		    ->wl_rates_num));
		switch (((wl_rates_t *)
		    (infp->wldp_buf))->wl_rates_num) {
		case 1:
			switch (rates[0]) {
			case WL_RATE_1M:
				rf_p->rf_tx_rate = WL_TX_RATE_FIX_1M(pcwl_p);
				break;
			case WL_RATE_2M:
				rf_p->rf_tx_rate = WL_TX_RATE_FIX_2M(pcwl_p);
				break;
			case WL_RATE_11M:
				rf_p->rf_tx_rate = WL_TX_RATE_FIX_11M(pcwl_p);
				break;
			case WL_RATE_5_5M:
				rf_p->rf_tx_rate = WL_TX_RATE_FIX_5M(pcwl_p);
				break;
			default:
				outfp->wldp_length = WIFI_BUF_OFFSET;
				outfp->wldp_result = WL_NOTSUPPORTED;
				goto done;
			}
			break;
		case 2:
			maxrate = (rates[0] > rates[1] ?
			    rates[0] : rates[1]);
			switch (maxrate) {
			case WL_RATE_2M:
				rf_p->rf_tx_rate = WL_TX_RATE_AUTO_L(pcwl_p);
				break;
			case WL_RATE_11M:
				rf_p->rf_tx_rate = WL_TX_RATE_AUTO_H(pcwl_p);
				break;
			case WL_RATE_5_5M:
				rf_p->rf_tx_rate = WL_TX_RATE_AUTO_M(pcwl_p);
				break;
			default:
				outfp->wldp_length = WIFI_BUF_OFFSET;
				outfp->wldp_result = WL_NOTSUPPORTED;
				goto done;
			}
			break;
		case 3:
			maxrate = (rates[0] > rates[1] ?
			    rates[0] : rates[1]);
			maxrate = (rates[2] > maxrate ?
			    rates[2] : maxrate);
			switch (maxrate) {
			case WL_RATE_11M:
				rf_p->rf_tx_rate = WL_TX_RATE_AUTO_H(pcwl_p);
				break;
			case WL_RATE_5_5M:
				rf_p->rf_tx_rate = WL_TX_RATE_AUTO_M(pcwl_p);
				break;
			default:
				outfp->wldp_length = WIFI_BUF_OFFSET;
				outfp->wldp_result = WL_NOTSUPPORTED;
				goto done;
			}
			break;
		case 4:
			rf_p->rf_tx_rate = WL_TX_RATE_AUTO_H(pcwl_p);
			break;
		default:
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_LACK_FEATURE;
			goto done;
		}
		PCWLDBG((CE_CONT, "pcwl: set tx_rate=%d\n", rf_p->rf_tx_rate));
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
pcwl_cfg_supportrates(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t i;
	wldp_t *outfp;
	char *buf;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
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
		for (i = 0; i < (outfp->wldp_length); i++)
			(void) mi_mpprintf_putc((char *)mp, buf[i]);
		kmem_free(buf, MAX_BUF_LEN);
		return (WL_SUCCESS);
	} else {
		kmem_free(buf, MAX_BUF_LEN);
		return (EINVAL);
	}
}

static int
pcwl_cfg_powermode(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t i, ret;
	pcwl_rf_t *rf_p;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_ps_mode_t);
	if (cmd == WLAN_GET_PARAM) {
		((wl_ps_mode_t *)(outfp->wldp_buf))->wl_ps_mode =
		    rf_p->rf_pm_enabled;
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		ret = (uint16_t)(((wl_ps_mode_t *)(infp->wldp_buf))
		    ->wl_ps_mode);
		if (ret != WL_PM_AM && ret != WL_PM_MPS && ret != WL_PM_FAST) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_NOTSUPPORTED;
			goto done;
		}
		rf_p->rf_pm_enabled = ret;
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

static int
pcwl_cfg_authmode(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t i, ret;
	pcwl_rf_t *rf_p;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;


	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_authmode_t);
	if (cmd == WLAN_GET_PARAM) {
		*(wl_authmode_t *)(outfp->wldp_buf) = rf_p->rf_authtype;
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		ret = (uint16_t)(*(wl_authmode_t *)(infp->wldp_buf));
		if (ret != WL_OPENSYSTEM && ret != WL_SHAREDKEY) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_NOTSUPPORTED;
			goto done;
		}
		rf_p->rf_authtype = ret;
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

static int
pcwl_cfg_encryption(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t i, ret;
	pcwl_rf_t *rf_p;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_encryption_t);
	if (cmd == WLAN_GET_PARAM) {
		*(wl_encryption_t *)(outfp->wldp_buf) = rf_p->rf_encryption;
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		ret = (uint16_t)(*(wl_encryption_t *)(infp->wldp_buf));
		PCWLDBG((CE_NOTE, "set encryption: %d\n", ret));
		if (ret != WL_NOENCRYPTION && ret != WL_ENC_WEP) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_NOTSUPPORTED;
			goto done;
		}
		rf_p->rf_encryption = ret;
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

static int
pcwl_cfg_wepkeyid(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t i, ret;
	pcwl_rf_t *rf_p;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_wep_key_id_t);
	if (cmd == WLAN_GET_PARAM) {
		*(wl_wep_key_id_t *)(outfp->wldp_buf) = rf_p->rf_tx_crypt_key;
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		ret = (uint16_t)(*(wl_wep_key_id_t *)(infp->wldp_buf));
		if (ret >= MAX_NWEPKEYS) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_NOTSUPPORTED;
			goto done;
		}
		rf_p->rf_tx_crypt_key = ret;
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

static int
pcwl_cfg_createibss(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t i, ret;
	pcwl_rf_t *rf_p;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_create_ibss_t);
	if (cmd == WLAN_GET_PARAM) {
		*(wl_create_ibss_t *)(outfp->wldp_buf) = rf_p->rf_create_ibss;
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		ret = (uint16_t)(*(wl_create_ibss_t *)(infp->wldp_buf));
		if (ret != 0 && ret != 1) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_NOTSUPPORTED;
			goto done;
		}
		rf_p->rf_create_ibss = ret;
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

static int
pcwl_cfg_rssi(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t i;
	int iret;
	wldp_t *outfp;
	char *buf;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_rssi_t);

	if (cmd == WLAN_GET_PARAM) {
		if (pcwl_p->pcwl_chip_type == PCWL_CHIP_PRISMII) {
			*(wl_rssi_t *)(outfp->wldp_buf) =
			    min((pcwl_p->pcwl_rssi * 15 / 85 + 1), 15);
		} else {
		/*
		 * According to the description of the
		 * datasheet(Lucent card), the signal level
		 * value is between 27 -- 154.
		 * we reflect these value to 1-15 as rssi.
		 */
			if (pcwl_p->pcwl_rssi <= 27)
				*(wl_rssi_t *)(outfp->wldp_buf) = 1;
			else if (pcwl_p->pcwl_rssi > 154)
				*(wl_rssi_t *)(outfp->wldp_buf) = 15;
			else
				*(wl_rssi_t *)(outfp->wldp_buf) =
				    min(15, ((pcwl_p->pcwl_rssi - 27)
				    * 15 / 127));
		}
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
pcwl_cfg_radio(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t i;
	int iret;
	wldp_t *outfp;
	char *buf;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
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
pcwl_cfg_wepkey(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	uint16_t i;
	wl_wep_key_t *p_wepkey_tab;
	pcwl_rf_t *rf_p;
	wldp_t	*infp;
	wldp_t *outfp;
	char *buf;
	int iret;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_NOSLEEP);
	if (buf == NULL) {
		PCWLDBG((CE_NOTE, "can not alloc so much memory!(%d)\n",
		    MAX_BUF_LEN));
		return (ENOMEM);
	}
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	rf_p = &pcwl_p->pcwl_rf;
	bzero((rf_p->rf_ckeys), sizeof (rf_ckey_t) * MAX_NWEPKEYS);

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_wep_key_tab_t);
	if (cmd == WLAN_GET_PARAM) {
		outfp->wldp_result = WL_WRITEONLY;
	} else if (cmd == WLAN_SET_PARAM) {
		p_wepkey_tab = (wl_wep_key_t *)(infp->wldp_buf);
		for (i = 0; i < MAX_NWEPKEYS; i++) {
			if (p_wepkey_tab[i].wl_wep_operation == WL_ADD) {
				rf_p->rf_ckeys[i].ckey_len =
				    p_wepkey_tab[i].wl_wep_length;
				bcopy(p_wepkey_tab[i].wl_wep_key,
				    rf_p->rf_ckeys[i].ckey_dat,
				    p_wepkey_tab[i].wl_wep_length);
				PCWL_SWAP16((uint16_t *)
				    &rf_p->rf_ckeys[i].ckey_dat,
				    rf_p->rf_ckeys[i].ckey_len + 1);
				PCWLDBG((CE_CONT, "%s, %d\n",
				    rf_p->rf_ckeys[i].ckey_dat, i));
			}
			PCWLDBG((CE_CONT, "pcwl: rf_ckeys[%d]=%s\n", i,
			    (char *)(rf_p->rf_ckeys[i].ckey_dat)));
		}
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

static void
pcwl_connect_timeout(void *arg)
{
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;
	uint16_t ret = 0;

	mutex_enter(&pcwl_p->pcwl_glock);
	PCWL_DISABLE_INTR(pcwl_p);
	if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0)) {
		goto done;
	}
	if (ret = pcwl_config_rf(pcwl_p)) {
		goto done;
	}
	if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_ENABLE, 0)) {
		goto done;
	}
	PCWL_ENABLE_INTR(pcwl_p);
done:
	if (ret)
		cmn_err(CE_WARN, "pcwl: connect failed due to hardware error");
	mutex_exit(&pcwl_p->pcwl_glock);
	pcwl_p->pcwl_connect_timeout_id = 0;
}

static int
pcwl_getset(mblk_t *mp, pcwl_maci_t *pcwl_p, uint32_t cmd)
{
	int ret = WL_SUCCESS;
	int connect = 0;

	mutex_enter(&pcwl_p->pcwl_glock);
	if (!(pcwl_p->pcwl_flag & PCWL_CARD_READY)) {
		mutex_exit(&pcwl_p->pcwl_glock);
		return (PCWL_FAIL);
	}
	switch (((wldp_t *)mp->b_rptr)->wldp_id) {
	case WL_ESSID:
		ret = pcwl_cfg_essid(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_essid\n"));
		break;
	case WL_BSSID:
		ret = pcwl_cfg_bssid(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_bssid\n"));
		break;
	case WL_ESS_LIST:
		ret = pcwl_cfg_scan(mp, pcwl_p, cmd);
		PCWLDBG((CE_NOTE, "cfg_scan\n"));
		break;
	case WL_LINKSTATUS:
		ret = pcwl_cfg_linkstatus(mp, pcwl_p, cmd);
		PCWLDBG((CE_NOTE, "cfg_linkstatus\n"));
		break;
	case WL_BSS_TYPE:
		ret = pcwl_cfg_bsstype(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_bsstype\n"));
		break;
	case WL_PHY_CONFIG:
		ret = pcwl_cfg_phy(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_phy\n"));
		break;
	case WL_DESIRED_RATES:
		ret = pcwl_cfg_desiredrates(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_disred-rates\n"));
		break;
	case WL_SUPPORTED_RATES:
		ret = pcwl_cfg_supportrates(mp, pcwl_p, cmd);
		PCWLDBG((CE_NOTE, "cfg_supported-rates\n"));
		break;
	case WL_POWER_MODE:
		ret = pcwl_cfg_powermode(mp, pcwl_p, cmd);
		PCWLDBG((CE_NOTE, "cfg_powermode\n"));
		break;
	case WL_AUTH_MODE:
		ret = pcwl_cfg_authmode(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_authmode\n"));
		break;
	case WL_ENCRYPTION:
		ret = pcwl_cfg_encryption(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_encryption\n"));
		break;
	case WL_WEP_KEY_ID:
		ret = pcwl_cfg_wepkeyid(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_wepkeyid\n"));
		break;
	case WL_CREATE_IBSS:
		ret = pcwl_cfg_createibss(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_create-ibss\n"));
		break;
	case WL_RSSI:
		ret = pcwl_cfg_rssi(mp, pcwl_p, cmd);
		PCWLDBG((CE_NOTE, "cfg_rssi\n"));
		break;
	case WL_RADIO:
		ret = pcwl_cfg_radio(mp, pcwl_p, cmd);
		PCWLDBG((CE_NOTE, "cfg_radio\n"));
		break;
	case WL_WEP_KEY_TAB:
		ret = pcwl_cfg_wepkey(mp, pcwl_p, cmd);
		connect = 1;
		PCWLDBG((CE_NOTE, "cfg_wepkey\n"));
		break;
	case WL_SCAN:
		mutex_exit(&pcwl_p->pcwl_glock);
		if (pcwl_p->pcwl_connect_timeout_id != 0) {
			(void) untimeout(pcwl_p->pcwl_connect_timeout_id);
			pcwl_p->pcwl_connect_timeout_id = 0;
		}
		mutex_enter(&pcwl_p->pcwl_glock);
		ret = pcwl_cmd_scan(pcwl_p);
		break;
	case WL_LOAD_DEFAULTS:
		mutex_exit(&pcwl_p->pcwl_glock);
		if (pcwl_p->pcwl_connect_timeout_id != 0) {
			(void) untimeout(pcwl_p->pcwl_connect_timeout_id);
			pcwl_p->pcwl_connect_timeout_id = 0;
		}
		mutex_enter(&pcwl_p->pcwl_glock);
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		if (ret = pcwl_loaddef_rf(pcwl_p)) {
			ret = (int)WL_HW_ERROR;
			PCWLDBG((CE_WARN, "cfg_loaddef_err\n"));
			break;
		}
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_ENABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		pcwl_delay(pcwl_p, 1000000);
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		PCWLDBG((CE_NOTE, "loaddef\n"));
		break;
	case WL_DISASSOCIATE:
		mutex_exit(&pcwl_p->pcwl_glock);
		if (pcwl_p->pcwl_connect_timeout_id != 0) {
			(void) untimeout(pcwl_p->pcwl_connect_timeout_id);
			pcwl_p->pcwl_connect_timeout_id = 0;
		}

		mutex_enter(&pcwl_p->pcwl_glock);
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		/*
		 * A workaround here: If the card is in ad-hoc mode, the
		 * following scan will not work correctly, so any
		 * 'dladm connect-wifi' which need a scan first will not
		 * succeed. software reset the card here as a workround.
		 */
		if ((pcwl_p->pcwl_rf.rf_porttype == WL_BSS_IBSS) &&
		    (pcwl_p->pcwl_chip_type == PCWL_CHIP_LUCENT)) {
			if (ret = pcwl_reset_backend(pcwl_p)) {
				ret = (int)WL_HW_ERROR;
				break;
			}
			if (ret = pcwl_init_nicmem(pcwl_p)) {
				ret = (int)WL_HW_ERROR;
				break;
			}
			pcwl_start_locked(pcwl_p);
		}
		if (ret = pcwl_loaddef_rf(pcwl_p)) {
			ret = (int)WL_HW_ERROR;
			PCWLDBG((CE_WARN, "cfg_loaddef_err\n"));
			break;
		}
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_ENABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		pcwl_delay(pcwl_p, 1000000);
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		PCWLDBG((CE_NOTE, "disassociate\n"));
		break;
	case WL_REASSOCIATE:
	case WL_ASSOCIAT:
		mutex_exit(&pcwl_p->pcwl_glock);
		if (pcwl_p->pcwl_connect_timeout_id != 0) {
			(void) untimeout(pcwl_p->pcwl_connect_timeout_id);
			pcwl_p->pcwl_connect_timeout_id = 0;
		}
		mutex_enter(&pcwl_p->pcwl_glock);
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		if (ret = pcwl_config_rf(pcwl_p)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		if (ret = pcwl_set_cmd(pcwl_p, WL_CMD_ENABLE, 0)) {
			ret = (int)WL_HW_ERROR;
			break;
		}
		PCWLDBG((CE_NOTE, "associate"));
		break;
	default:
		break;
	}
	mutex_exit(&pcwl_p->pcwl_glock);
	if ((cmd == WLAN_SET_PARAM) && (connect)) {
		(void) pcwl_set_cmd(pcwl_p, WL_CMD_DISABLE, 0);
		if (pcwl_p->pcwl_connect_timeout_id != 0) {
			(void) untimeout(pcwl_p->pcwl_connect_timeout_id);
			pcwl_p->pcwl_connect_timeout_id = 0;
		}
		pcwl_p->pcwl_connect_timeout_id = timeout(pcwl_connect_timeout,
		    pcwl_p, 2 * drv_usectohz(1000000));
	}
	return (ret);
}

static void
pcwl_wlan_ioctl(pcwl_maci_t *pcwl_p, queue_t *wq, mblk_t *mp, uint32_t cmd)
{

	struct	iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	wldp_t 	*infp;
	uint32_t len, ret;
	mblk_t		*mp1;

	/*
	 * sanity check
	 */
	if (iocp->ioc_count == 0 || !(mp1 = mp->b_cont)) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	/*
	 * assuming single data block
	 */
	if (mp1->b_cont) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}

	/*
	 * we will overwrite everything
	 */
	mp1->b_wptr = mp1->b_rptr;

	infp = (wldp_t *)mp1->b_rptr;
	PCWLDBG((CE_NOTE, "pcwl: wldp->length=0x%x\n", infp->wldp_length));
	PCWLDBG((CE_NOTE, "pcwl: wldp->type =:%s\n",
	    infp->wldp_type == NET_802_11 ? "NET_802_11" : "Unknown"));
	PCWLDBG((CE_NOTE, "pcwl: wldp->id=0x%x\n", infp->wldp_id));
	PCWLDBG((CE_NOTE, "pcwl: wldp->result=0x%x\n", infp->wldp_result));

	ret = pcwl_getset(mp1, pcwl_p, cmd);
	len = msgdsize(mp1);
	PCWLDBG((CE_CONT, "pcwl: ioctl message length = %d\n", len));
	miocack(wq, mp, len, ret);

}


static void
pcwl_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp;
	uint32_t cmd, ret;
	pcwl_maci_t *pcwl_p = (pcwl_maci_t *)arg;
	boolean_t need_privilege = B_TRUE;

	/*
	 * Validate the command before bothering with the mutexen ...
	 */
	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		PCWLDBG((CE_CONT, "pcwl_ioctl: unknown cmd 0x%x", cmd));
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
		pcwl_wlan_ioctl(pcwl_p, wq, mp, cmd);
}
