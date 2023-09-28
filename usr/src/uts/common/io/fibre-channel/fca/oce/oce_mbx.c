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

/* Copyright © 2003-2011 Emulex. All rights reserved.  */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Source file containing the implementation of MBOX
 * and related helper functions
 */

#include <oce_impl.h>

static ddi_dma_attr_t oce_sgl_dma_attr = {
	DMA_ATTR_V0,		/* version number */
	0x0000000000000000ull,	/* low address */
	0xFFFFFFFFFFFFFFFFull,	/* high address */
	0x0000000000010000ull,	/* dma counter max */
	0x1000,			/* alignment 4K for mbx bufs */
	0x1,			/* burst sizes */
	0x00000004,		/* minimum transfer size */
	0x00000000FFFFFFFFull,	/* maximum transfer size */
	0xFFFFFFFFFFFFFFFFull,	/* maximum segment size */
	MAX_MBX_SGE,		/* scatter/gather list length */
	0x00000001,		/* granularity */
	0			/* DMA flags */
};

static ddi_device_acc_attr_t oce_sgl_buf_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
};

/*
 * common inline function to fill an ioctl request header
 *
 * hdr - pointer to a buffer where the header will be initialized
 * dom - domain
 * port - port number
 * opcode - command code for this MBX
 * timeout - timeout in seconds
 * pyld_len - length of the command buffer described by this header
 *
 * return none
 */
void
mbx_common_req_hdr_init(struct mbx_hdr *hdr,
    uint8_t dom, uint8_t port,
    uint8_t subsys, uint8_t opcode,
    uint32_t timeout, uint32_t pyld_len)
{
	ASSERT(hdr != NULL);

	hdr->u0.req.opcode = opcode;
	hdr->u0.req.subsystem = subsys;
	hdr->u0.req.port_number = port;
	hdr->u0.req.domain = dom;

	hdr->u0.req.timeout = timeout;
	hdr->u0.req.request_length = pyld_len - sizeof (struct mbx_hdr);
	hdr->u0.req.rsvd0 = 0;
} /* mbx_common_req_hdr_init */

/*
 * function to initialize the hw with host endian information
 *
 * dev - software handle to the device
 *
 * return 0 on success, ETIMEDOUT on failure
 */
int
oce_mbox_init(struct oce_dev *dev)
{
	struct oce_bmbx *mbx;
	uint8_t *ptr;
	int ret = 0;

	ASSERT(dev != NULL);

	mbx = (struct oce_bmbx *)DBUF_VA(dev->bmbx);
	ptr = (uint8_t *)&mbx->mbx;

	/* Endian Signature */
	*ptr++ = 0xff;
	*ptr++ = 0x12;
	*ptr++ = 0x34;
	*ptr++ = 0xff;
	*ptr++ = 0xff;
	*ptr++ = 0x56;
	*ptr++ = 0x78;
	*ptr   = 0xff;

	ret = oce_mbox_dispatch(dev, 0);

	if (ret != 0)
		oce_log(dev, CE_NOTE, MOD_CONFIG,
		    "Failed to set endian %d", ret);

	return (ret);
} /* oce_mbox_init */

/*
 * function to wait till we get a mbox ready after writing to the
 * mbox doorbell
 *
 * dev - software handle to the device
 *
 * return 0=ready, ETIMEDOUT=>not ready but timed out
 */
int
oce_mbox_wait(struct oce_dev *dev, uint32_t tmo_sec)
{
	clock_t tmo;
	clock_t now, tstamp;
	pd_mpu_mbox_db_t mbox_db;

	tmo = (tmo_sec > 0) ? drv_usectohz(tmo_sec * 1000000) :
	    drv_usectohz(DEFAULT_MQ_MBOX_TIMEOUT);

	/* Add the default timeout to wait for a mailbox to complete */
	tmo += drv_usectohz(MBX_READY_TIMEOUT);

	tstamp = ddi_get_lbolt();
	for (;;) {
		now = ddi_get_lbolt();
		if ((now - tstamp) >= tmo) {
			tmo = 0;
			break;
		}

		mbox_db.dw0 = OCE_DB_READ32(dev, PD_MPU_MBOX_DB);
		if (oce_fm_check_acc_handle(dev, dev->db_handle) != DDI_FM_OK) {
			ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
			oce_fm_ereport(dev, DDI_FM_DEVICE_INVAL_STATE);
		}

		if (mbox_db.bits.ready) {
			return (0);
		}
		drv_usecwait(5);
	}

	return (ETIMEDOUT);
} /* oce_mbox_wait */

/*
 * function to dispatch a mailbox command present in the mq mbox
 *
 * dev - software handle to the device
 *
 * return 0 on success, ETIMEDOUT on failure
 */
int
oce_mbox_dispatch(struct oce_dev *dev, uint32_t tmo_sec)
{
	pd_mpu_mbox_db_t mbox_db;
	uint32_t pa;
	int ret;

	/* sync the bmbx */
	(void) DBUF_SYNC(dev->bmbx, DDI_DMA_SYNC_FORDEV);

	/* write 30 bits of address hi dword */
	pa = (uint32_t)(DBUF_PA(dev->bmbx) >> 34);
	bzero(&mbox_db, sizeof (pd_mpu_mbox_db_t));
	mbox_db.bits.ready = 0;
	mbox_db.bits.hi = 1;
	mbox_db.bits.address = pa;

	/* wait for mbox ready */
	ret = oce_mbox_wait(dev, tmo_sec);
	if (ret != 0) {
		return (ret);
	}

	/* ring the doorbell */
	OCE_DB_WRITE32(dev, PD_MPU_MBOX_DB, mbox_db.dw0);

	if (oce_fm_check_acc_handle(dev, dev->db_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
	}

	/* wait for mbox ready */
	ret = oce_mbox_wait(dev, tmo_sec);
	if (ret != 0) {
		oce_log(dev, CE_NOTE, MOD_CONFIG,
		    "BMBX TIMED OUT PROGRAMMING HI ADDR: %d", ret);
		/* if mbx times out, hw is in invalid state */
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
		oce_fm_ereport(dev, DDI_FM_DEVICE_INVAL_STATE);
		return (ret);
	}

	/* now write 30 bits of address lo dword */
	pa = (uint32_t)(DBUF_PA(dev->bmbx) >> 4) & 0x3fffffff;
	mbox_db.bits.ready = 0;
	mbox_db.bits.hi = 0;
	mbox_db.bits.address = pa;

	/* ring the doorbell */
	OCE_DB_WRITE32(dev, PD_MPU_MBOX_DB, mbox_db.dw0);
	if (oce_fm_check_acc_handle(dev, dev->db_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
	}

	/* wait for mbox ready */
	ret = oce_mbox_wait(dev, tmo_sec);
	/* sync */
	(void) ddi_dma_sync(DBUF_DHDL(dev->bmbx), 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);
	if (oce_fm_check_dma_handle(dev, DBUF_DHDL(dev->bmbx)) != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}
	return (ret);
} /* oce_mbox_dispatch */

/*
 * function to post a MBX to the mbox
 *
 * dev - software handle to the device
 * mbx - pointer to the MBX to send
 * mbxctx - pointer to the mbx context structure
 *
 * return 0 on success, ETIMEDOUT on failure
 */
int
oce_mbox_post(struct oce_dev *dev, struct oce_mbx *mbx,
    struct oce_mbx_ctx *mbxctx)
{
	struct oce_mbx *mb_mbx = NULL;
	struct oce_mq_cqe *mb_cqe = NULL;
	struct oce_bmbx *mb = NULL;
	int ret = 0;
	uint32_t tmo = 0;

	mutex_enter(&dev->bmbx_lock);

	mb = (struct oce_bmbx *)DBUF_VA(dev->bmbx);
	mb_mbx = &mb->mbx;

	/* get the tmo */
	tmo = mbx->tag[0];
	mbx->tag[0] = 0;

	/* copy mbx into mbox */
	bcopy(mbx, mb_mbx, sizeof (struct oce_mbx));

	/* now dispatch */
	ret = oce_mbox_dispatch(dev, tmo);
	if (ret != 0) {
		mutex_exit(&dev->bmbx_lock);
		return (ret);
	}

	/* sync */

	(void) ddi_dma_sync(DBUF_DHDL(dev->bmbx), 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);
	ret = oce_fm_check_dma_handle(dev, DBUF_DHDL(dev->bmbx));
	if (ret != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
		mutex_exit(&dev->bmbx_lock);
		return (EIO);
	}

	/*
	 * the command completed successfully. Now get the
	 * completion queue entry
	 */
	mb_cqe = &mb->cqe;
	DW_SWAP(u32ptr(&mb_cqe->u0.dw[0]), sizeof (struct oce_mq_cqe));

	/* copy mbox mbx back */
	bcopy(mb_mbx, mbx, sizeof (struct oce_mbx));

	/* check mbox status */
	if (mb_cqe->u0.s.completion_status != 0) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "MBOX Command Failed with Status: %d %d",
		    mb_cqe->u0.s.completion_status,
		    mb_cqe->u0.s.extended_status);
		mutex_exit(&dev->bmbx_lock);
		return (EIO);
	}

	/*
	 * store the mbx context in the cqe tag section so that
	 * the upper layer handling the cqe can associate the mbx
	 * with the response
	 */
	if (mbxctx) {
		/* save context */
		mbxctx->mbx = mb_mbx;
		bcopy(&mbxctx, mb_cqe->u0.s.mq_tag,
		    sizeof (struct oce_mbx_ctx *));
	}

	mutex_exit(&dev->bmbx_lock);
	return (0);
} /* oce_mbox_post */

/*
 * function to get the firmware version
 *
 * dev - software handle to the device
 *
 * return 0 on success, EIO on failure
 */
int
oce_get_fw_version(struct oce_dev *dev)
{
	struct oce_mbx mbx;
	struct mbx_get_common_fw_version *fwcmd;
	int ret = 0;

	bzero(&mbx, sizeof (struct oce_mbx));

	/* initialize the ioctl header */
	fwcmd = (struct mbx_get_common_fw_version *)&mbx.payload;
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_GET_COMMON_FW_VERSION,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_get_common_fw_version));

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_get_common_fw_version);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* now post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	if (ret != 0) {
		return (ret);
	}
	bcopy(fwcmd->params.rsp.fw_ver_str, dev->fw_version, 32);

	oce_log(dev, CE_NOTE, MOD_CONFIG, "%s %s",
	    fwcmd->params.rsp.fw_ver_str,
	    fwcmd->params.rsp.fw_on_flash_ver_str);

	return (0);
} /* oce_get_fw_version */

/*
 * function to invoke f/w reset via. mailbox
 * does not hold bootstap lock called by quiesce
 *
 * dev - software handle to the device
 *
 * return 0 on success, ETIMEDOUT on failure
 *
 */
int
oce_reset_fun(struct oce_dev *dev)
{
	struct oce_mbx *mbx;
	struct oce_bmbx *mb;
	struct ioctl_common_function_reset *fwcmd;

	mb = (struct oce_bmbx *)DBUF_VA(dev->bmbx);
	mbx = &mb->mbx;
	bzero(mbx, sizeof (struct oce_mbx));
	/* initialize the ioctl header */
	fwcmd = (struct ioctl_common_function_reset *)&mbx->payload;
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_COMMON_FUNCTION_RESET,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct ioctl_common_function_reset));

	/* fill rest of mbx */
	mbx->u0.s.embedded = 1;
	mbx->payload_length = sizeof (struct ioctl_common_function_reset);
	DW_SWAP(u32ptr(mbx), mbx->payload_length + OCE_BMBX_RHDR_SZ);

	return (oce_mbox_dispatch(dev, 0));
} /* oce_reset_fun */

/*
 * function to read the mac address associated with an interface
 *
 * dev - software handle to the device
 * if_id - interface id to read the address from
 * perm - set to 1 if reading the factory mac address. In this case
 *	if_id is ignored
 * type - type of the mac address, whether network or storage
 * mac - [OUTPUT] pointer to a buffer containing the mac address
 *	    when the command succeeds
 *
 * return 0 on success, EIO on failure
 */
int
oce_read_mac_addr(struct oce_dev *dev, uint32_t if_id, uint8_t perm,
    uint8_t type, struct mac_address_format *mac)
{
	struct oce_mbx mbx;
	struct mbx_query_common_iface_mac *fwcmd;
	int ret = 0;

	bzero(&mbx, sizeof (struct oce_mbx));
	/* initialize the ioctl header */
	fwcmd = (struct mbx_query_common_iface_mac *)&mbx.payload;
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_QUERY_COMMON_IFACE_MAC,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_query_common_iface_mac));

	/* fill the command */
	fwcmd->params.req.permanent = perm;
	if (perm)
		fwcmd->params.req.if_id = (uint16_t)if_id;
	else
		fwcmd->params.req.if_id = 0;
	fwcmd->params.req.type = type;

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_query_common_iface_mac);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* now post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);
	if (ret != 0) {
		return (ret);
	}

	/* get the response */
	oce_log(dev, CE_NOTE, MOD_CONFIG,
	    "MAC addr size = 0x%x",
	    LE_16(fwcmd->params.rsp.mac.size_of_struct));
	oce_log(dev, CE_NOTE, MOD_CONFIG,
	    "MAC_ADDR:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x",
	    fwcmd->params.rsp.mac.mac_addr[0],
	    fwcmd->params.rsp.mac.mac_addr[1],
	    fwcmd->params.rsp.mac.mac_addr[2],
	    fwcmd->params.rsp.mac.mac_addr[3],
	    fwcmd->params.rsp.mac.mac_addr[4],
	    fwcmd->params.rsp.mac.mac_addr[5]);

	/* copy the mac addres in the output parameter */
	mac->size_of_struct = LE_16(fwcmd->params.rsp.mac.size_of_struct);
	bcopy(&fwcmd->params.rsp.mac.mac_addr[0], &mac->mac_addr[0],
	    mac->size_of_struct);

	return (0);
} /* oce_read_mac_addr */

/*
 * function to create an interface using the OPCODE_CREATE_COMMON_IFACE
 * command
 *
 * dev - software handle to the device
 * cap_flags - capability flags
 * en_flags - enable capability flags
 * vlan_tag - optional vlan tag to associate with the if
 * mac_addr - pointer to a buffer containing the mac address
 * if_id - [OUTPUT] pointer to an integer to hold the ID of the
 *	    interface created
 *
 * return 0 on success, EIO on failure
 */
int
oce_if_create(struct oce_dev *dev, uint32_t cap_flags, uint32_t en_flags,
    uint16_t vlan_tag, uint8_t *mac_addr,
    uint32_t *if_id)
{
	struct oce_mbx mbx;
	struct mbx_create_common_iface *fwcmd;
	int ret = 0;

	bzero(&mbx, sizeof (struct oce_mbx));

	/* initialize the ioctl header */
	fwcmd = (struct mbx_create_common_iface *)&mbx.payload;
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_CREATE_COMMON_IFACE,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_create_common_iface));
	DW_SWAP(u32ptr(&fwcmd->hdr), sizeof (struct mbx_hdr));

	/* fill the command */
	fwcmd->params.req.version   = 0;
	fwcmd->params.req.cap_flags = LE_32(cap_flags);
	fwcmd->params.req.enable_flags   = LE_32(en_flags);
	if (mac_addr != NULL) {
		bcopy(mac_addr, &fwcmd->params.req.mac_addr[0],
		    ETHERADDRL);
		fwcmd->params.req.vlan_tag.u0.normal.vtag = LE_16(vlan_tag);
		fwcmd->params.req.mac_invalid = B_FALSE;
	} else {
		fwcmd->params.req.mac_invalid = B_TRUE;
	}

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_create_common_iface);
	DW_SWAP(u32ptr(&mbx), OCE_BMBX_RHDR_SZ);

	/* now post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);
	if (ret != 0) {
		return (ret);
	}



	/* get response */
	*if_id = LE_32(fwcmd->params.rsp.if_id);
	oce_log(dev, CE_NOTE, MOD_CONFIG,
	    "IF_ID = 0x%x", *if_id);

	/* If asked to set mac addr save the pmac handle */
	if (mac_addr != NULL) {
		dev->pmac_id = LE_32(fwcmd->params.rsp.pmac_id);
		oce_log(dev, CE_NOTE, MOD_CONFIG,
		    "PMAC_ID = 0x%x", dev->pmac_id);
	}
	return (0);
} /* oce_if_create */

/*
 * function to delete an interface
 *
 * dev - software handle to the device
 * if_id - ID of the interface to delete
 *
 * return 0 on success, EIO on failure
 */
int
oce_if_del(struct oce_dev *dev, uint32_t if_id)
{
	struct oce_mbx mbx;
	struct mbx_destroy_common_iface *fwcmd;
	int ret = 0;

	bzero(&mbx, sizeof (struct oce_mbx));
	/* initialize the ioctl header */
	fwcmd = (struct mbx_destroy_common_iface *)&mbx.payload;
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_DESTROY_COMMON_IFACE,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_destroy_common_iface));

	/* fill the command */
	fwcmd->params.req.if_id = if_id;

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_destroy_common_iface);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);
	return (ret);
} /* oce_if_del */

/*
 * function to query the link status from the hardware
 *
 * dev - software handle to the device
 * link_status - [OUT] pointer to the structure returning the link attributes
 *
 * return 0 on success, EIO on failure
 */
int
oce_get_link_status(struct oce_dev *dev, struct link_status *link)
{
	struct oce_mbx mbx;
	struct mbx_query_common_link_status *fwcmd;
	int ret = 0;

	bzero(&mbx, sizeof (struct oce_mbx));

	/* initialize the ioctl header */
	fwcmd = (struct mbx_query_common_link_status *)&mbx.payload;
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_QUERY_COMMON_LINK_STATUS,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_query_common_link_status));

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_query_common_link_status);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	if (ret != 0) {
		return (ret);
	}

	/* interpret response */
	bcopy(&fwcmd->params.rsp, link, sizeof (struct link_status));
	link->logical_link_status = LE_32(link->logical_link_status);
	link->qos_link_speed = LE_16(link->qos_link_speed);

	return (0);
} /* oce_get_link_status */

/*
 * function to configure the rx filter on the interface
 *
 * dev - software handle to the device
 * filter - mbx command containing the filter parameters
 *
 * return 0 on success, EIO on failure
 */
int
oce_set_rx_filter(struct oce_dev *dev,
    struct mbx_set_common_ntwk_rx_filter *filter)
{
	struct oce_mbx mbx;
	struct mbx_set_common_ntwk_rx_filter *fwcmd;
	int ret;

	bzero(&mbx, sizeof (struct oce_mbx));
	fwcmd = (struct mbx_set_common_ntwk_rx_filter *)&mbx.payload;
	/* fill the command */
	bcopy(filter, fwcmd, sizeof (struct mbx_set_common_ntwk_rx_filter));

	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_COMMON_NTWK_RX_FILTER,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_set_common_ntwk_rx_filter));

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_set_common_ntwk_rx_filter);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	return (ret);
} /* oce_set_rx_filter */

/*
 * function to send the mbx command to update the mcast table with fw
 *
 * dev - software handle to the device
 * mca_table - array of mcast address to update
 * mca_cnt - number of elements in mca_table
 * enable_promisc - flag to enable/disable mcast-promiscuous mode
 *
 * return 0 on success, EIO on failure
 */
int
oce_set_multicast_table(struct oce_dev *dev, uint32_t if_id,
struct ether_addr *mca_table, uint16_t mca_cnt, boolean_t promisc)
{
	struct oce_mbx mbx;
	struct  mbx_set_common_iface_multicast *fwcmd;
	int ret;

	bzero(&mbx, sizeof (struct oce_mbx));
	fwcmd = (struct mbx_set_common_iface_multicast *)&mbx.payload;

	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_SET_COMMON_IFACE_MULTICAST,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_set_common_iface_multicast));

	/* fill the command */
	fwcmd->params.req.if_id = (uint8_t)if_id;
	if (mca_table != NULL) {
		bcopy(mca_table, &fwcmd->params.req.mac[0],
		    mca_cnt * ETHERADDRL);
	}
	fwcmd->params.req.num_mac = LE_16(mca_cnt);
	fwcmd->params.req.promiscuous = (uint8_t)promisc;

	/* fill rest of mbx */
	mbx.u0.s.embedded = B_TRUE;
	mbx.payload_length = sizeof (struct mbx_set_common_iface_multicast);
	/* Swap only MBX header + BOOTSTRAP HDR */
	DW_SWAP(u32ptr(&mbx), (OCE_BMBX_RHDR_SZ + OCE_MBX_RRHDR_SZ));

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	return (ret);
} /* oce_set_multicast_table */

/*
 * function to query the fw attributes from the hw
 *
 * dev - software handle to the device
 *
 * return 0 on success, EIO on failure
 */
int
oce_get_fw_config(struct oce_dev *dev)
{
	struct oce_mbx mbx;
	struct mbx_common_query_fw_config *fwcmd;
	int ret = 0;

	bzero(&mbx, sizeof (struct oce_mbx));
	/* initialize the ioctl header */
	fwcmd = (struct mbx_common_query_fw_config *)&mbx.payload;
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_QUERY_COMMON_FIRMWARE_CONFIG,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_common_query_fw_config));

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_common_query_fw_config);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* now post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	if (ret != 0) {
		return (ret);
	}

	/* swap and copy into buffer */
	DW_SWAP(u32ptr(fwcmd), sizeof (struct mbx_common_query_fw_config));

	dev->config_number = fwcmd->params.rsp.config_number;
	dev->asic_revision = fwcmd->params.rsp.asic_revision;
	dev->port_id = fwcmd->params.rsp.port_id;
	dev->function_mode = fwcmd->params.rsp.function_mode;

	/* get the max rings alloted for this function */
	if (fwcmd->params.rsp.ulp[0].mode & ULP_NIC_MODE) {
		dev->max_tx_rings = fwcmd->params.rsp.ulp[0].wq_count;
		dev->max_rx_rings = fwcmd->params.rsp.ulp[0].rq_count;
	} else {
		dev->max_tx_rings = fwcmd->params.rsp.ulp[1].wq_count;
		dev->max_rx_rings = fwcmd->params.rsp.ulp[1].rq_count;
	}
	dev->function_caps = fwcmd->params.rsp.function_caps;
	return (0);
} /* oce_get_fw_config */

/*
 * function to retrieve statistic counters from the hardware
 *
 * dev - software handle to the device
 *
 * return 0 on success, EIO on failure
 */
int
oce_get_hw_stats(struct oce_dev *dev)
{
	struct oce_mbx mbx;
	struct mbx_get_nic_stats *fwcmd = dev->hw_stats;
	int ret = 0;

	bzero(&mbx, sizeof (struct oce_mbx));
	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_NIC,
	    OPCODE_GET_NIC_STATS,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_get_nic_stats));
	DW_SWAP(u32ptr(fwcmd), sizeof (struct mbx_get_nic_stats));

	/* fill rest of mbx */
	mbx.payload.u0.u1.sgl[0].pa_lo = ADDR_LO(DBUF_PA(dev->stats_dbuf));
	mbx.payload.u0.u1.sgl[0].pa_hi = ADDR_HI(DBUF_PA(dev->stats_dbuf));
	mbx.payload.u0.u1.sgl[0].length = sizeof (struct mbx_get_nic_stats);
	mbx.payload_length = sizeof (struct mbx_get_nic_stats);

	mbx.u0.s.embedded = 0;
	mbx.u0.s.sge_count = 1;

	DW_SWAP(u32ptr(&mbx), sizeof (struct oce_mq_sge) + OCE_BMBX_RHDR_SZ);

	bzero(&dev->hw_stats->params, sizeof (dev->hw_stats->params));

	/* sync for device */
	(void) DBUF_SYNC(dev->stats_dbuf, DDI_DMA_SYNC_FORDEV);

	/* now post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);
	/* sync the stats */
	(void) DBUF_SYNC(dev->stats_dbuf, DDI_DMA_SYNC_FORKERNEL);

	/* Check the mailbox status and command completion status */
	if (ret != 0) {
		return (ret);
	}

	DW_SWAP(u32ptr(dev->hw_stats), sizeof (struct mbx_get_nic_stats));
	return (0);
} /* oce_get_hw_stats */

/*
 * function to set the number of vectors with the cev
 *
 * dev - software handle to the device
 * num_vectors - number of MSI messages
 *
 * return 0 on success, EIO on failure
 */
int
oce_num_intr_vectors_set(struct oce_dev *dev, uint32_t num_vectors)
{
	struct oce_mbx mbx;
	struct mbx_common_cev_modify_msi_messages *fwcmd;
	int ret = 0;

	bzero(&mbx, sizeof (struct oce_mbx));
	/* initialize the ioctl header */
	fwcmd = (struct mbx_common_cev_modify_msi_messages *)&mbx.payload;
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_COMMON_CEV_MODIFY_MSI_MESSAGES,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_common_cev_modify_msi_messages));

	/* fill the command */
	fwcmd->params.req.num_msi_msgs = LE_32(num_vectors);

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length =
	    sizeof (struct mbx_common_cev_modify_msi_messages);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	return (ret);
} /* oce_num_intr_vectors_set */

/*
 * function to set flow control capability in the hardware
 *
 * dev - software handle to the device
 * flow_control - flow control flags to set
 *
 * return 0 on success, EIO on failure
 */
int
oce_set_flow_control(struct oce_dev *dev, uint32_t flow_control)
{
	struct oce_mbx mbx;
	struct mbx_common_get_set_flow_control *fwcmd =
	    (struct mbx_common_get_set_flow_control *)&mbx.payload;
	int ret;

	bzero(&mbx, sizeof (struct oce_mbx));
	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_SET_COMMON_FLOW_CONTROL,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_common_get_set_flow_control));

	/* fill command */
	if (flow_control & OCE_FC_TX)
		fwcmd->tx_flow_control = 1;

	if (flow_control & OCE_FC_RX)
		fwcmd->rx_flow_control = 1;

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_common_get_set_flow_control);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	return (ret);
} /* oce_set_flow_control */

/*
 * function to get the current flow control setting with the hardware
 *
 * dev - software handle to the device
 * flow_control - [OUT] pointer to location where flow_control setting
 * is returned
 *
 * return 0 on success, EIO on failure
 */
int
oce_get_flow_control(struct oce_dev *dev, uint32_t *flow_control)
{
	struct oce_mbx mbx;
	struct mbx_common_get_set_flow_control *fwcmd;
	int ret;

	DEV_LOCK(dev);
	if (dev->suspended) {
		DEV_UNLOCK(dev);
		return (EIO);
	}
	DEV_UNLOCK(dev);

	bzero(&mbx, sizeof (struct oce_mbx));
	fwcmd = (struct mbx_common_get_set_flow_control *)&mbx.payload;

	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_GET_COMMON_FLOW_CONTROL,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_common_get_set_flow_control));

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_common_get_set_flow_control);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	if (ret != 0) {
		return (ret);
	}

	/* get the flow control */
	DW_SWAP(u32ptr(fwcmd),
	    sizeof (struct mbx_common_get_set_flow_control));
	*flow_control = 0;
	if (fwcmd->tx_flow_control)
		*flow_control |= OCE_FC_TX;

	if (fwcmd->rx_flow_control)
		*flow_control |= OCE_FC_RX;

	return (0);
} /* oce_get_flow_control */

/*
 * function to enable/disable device promiscuous mode
 *
 * dev - software handle to the device
 * enable - enable/disable flag
 *
 * return 0 on success, EIO on failure
 */
int
oce_set_promiscuous(struct oce_dev *dev, boolean_t enable)
{
	struct oce_mbx mbx;
	struct mbx_config_nic_promiscuous *fwcmd;
	int ret;

	bzero(&mbx, sizeof (struct oce_mbx));

	fwcmd = (struct mbx_config_nic_promiscuous *)&mbx.payload;

	if (dev->port_id == 0) {
		fwcmd->params.req.port0_promisc = (uint8_t)enable;

	} else {
		fwcmd->params.req.port1_promisc = (uint8_t)enable;
	}

	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_NIC,
	    OPCODE_CONFIG_NIC_PROMISCUOUS,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_config_nic_promiscuous));
	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_config_nic_promiscuous);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	return (ret);
}

/*
 * function to add a unicast address to an interface
 *
 * dev - software handle to the device
 * mac - unicast address
 *
 * return 0 on success, EIO on failure
 */
int
oce_add_mac(struct oce_dev *dev, uint32_t if_id,
			const uint8_t *mac, uint32_t *pmac_id)
{
	struct oce_mbx mbx;
	struct mbx_add_common_iface_mac *fwcmd;
	int ret;

	bzero(&mbx, sizeof (struct oce_mbx));
	fwcmd = (struct mbx_add_common_iface_mac *)&mbx.payload;
	fwcmd->params.req.if_id = LE_32(if_id);
	bcopy(mac, &fwcmd->params.req.mac_address[0], ETHERADDRL);

	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_ADD_COMMON_IFACE_MAC,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_add_common_iface_mac));

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_add_common_iface_mac);
	DW_SWAP(u32ptr(&mbx), OCE_BMBX_RHDR_SZ + OCE_MBX_RRHDR_SZ);

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	if (ret != 0) {
		return (ret);
	}

	*pmac_id = LE_32(fwcmd->params.rsp.pmac_id);
	return (0);
}

/*
 * function to delete an unicast address associated with an interface
 *
 * dev - software handle to the device
 * pmac_id - handle to the address added using ace_add_mac
 *
 * return 0 on success, EIO on failure
 */
int
oce_del_mac(struct oce_dev *dev,  uint32_t if_id, uint32_t *pmac_id)
{
	struct oce_mbx mbx;
	struct mbx_del_common_iface_mac *fwcmd;
	int ret;

	bzero(&mbx, sizeof (struct oce_mbx));
	fwcmd = (struct mbx_del_common_iface_mac *)&mbx.payload;
	fwcmd->params.req.if_id = if_id;
	fwcmd->params.req.pmac_id = *pmac_id;

	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_DEL_COMMON_IFACE_MAC,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_add_common_iface_mac));

	/* fill rest of mbx */
	mbx.u0.s.embedded = 1;
	mbx.payload_length = sizeof (struct mbx_del_common_iface_mac);
	DW_SWAP(u32ptr(&mbx), mbx.payload_length + OCE_BMBX_RHDR_SZ);

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	return (ret);
}


/*
 * function to send the mbx command to configure vlan
 *
 * dev - software handle to the device
 * vtag_arr - array of vlan tags
 * vtag_cnt - number of elements in array
 * untagged - boolean TRUE/FLASE
 * enable_promisc - flag to enable/disable VLAN promiscuous mode
 *
 * return 0 on success, EIO on failure
 */
int
oce_config_vlan(struct oce_dev *dev, uint32_t if_id,
    struct normal_vlan *vtag_arr, uint8_t vtag_cnt,
    boolean_t untagged, boolean_t enable_promisc)
{
	struct oce_mbx mbx;
	struct  mbx_common_config_vlan *fwcmd;
	int ret;

	bzero(&mbx, sizeof (struct oce_mbx));
	fwcmd = (struct mbx_common_config_vlan *)&mbx.payload;

	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_CONFIG_COMMON_IFACE_VLAN,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_common_config_vlan));

	fwcmd->params.req.if_id	= (uint8_t)if_id;
	fwcmd->params.req.promisc = (uint8_t)enable_promisc;
	fwcmd->params.req.untagged = (uint8_t)untagged;
	fwcmd->params.req.num_vlans = vtag_cnt;

	/* Set the vlan tag filter on hw */
	if (!enable_promisc) {
		bcopy(fwcmd->params.req.tags.normal_vlans, vtag_arr,
		    vtag_cnt * sizeof (struct normal_vlan));
	}

	/* fill rest of mbx */
	mbx.u0.s.embedded = B_TRUE;
	mbx.payload_length = sizeof (struct mbx_common_config_vlan);
	DW_SWAP(u32ptr(&mbx), (OCE_BMBX_RHDR_SZ + mbx.payload_length));

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	return (ret);
} /* oce_config_vlan */


/*
 * function to enable or disable the link
 *
 * dev - software handle to the device
 * mca_table - array of mcast address to update
 * mca_cnt - number of elements in mca_table
 * enable_promisc - flag to enable/disable mcast-promiscuous mode
 *
 * return 0 on success, EIO on failure
 */
int
oce_config_link(struct oce_dev *dev, boolean_t enable)
{
	struct oce_mbx mbx;
	struct  mbx_common_func_link_cfg *fwcmd;
	int ret;

	bzero(&mbx, sizeof (struct oce_mbx));
	fwcmd = (struct mbx_common_func_link_cfg *)&mbx.payload;

	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_COMMON,
	    OPCODE_COMMON_FUNCTION_LINK_CONFIG,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_common_config_vlan));

	fwcmd->params.req.enable = enable;

	/* fill rest of mbx */
	mbx.u0.s.embedded = B_TRUE;
	mbx.payload_length = sizeof (struct mbx_common_func_link_cfg);
	DW_SWAP(u32ptr(&mbx), (OCE_BMBX_RHDR_SZ + mbx.payload_length));

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	return (ret);
} /* oce_config_link */

int
oce_config_rss(struct oce_dev *dev, uint16_t if_id, char *hkey, char *itbl,
    int  tbl_sz, uint16_t rss_type, uint8_t flush)
{
	struct oce_mbx mbx;
	struct mbx_config_nic_rss *fwcmd;
	int i;
	int ret = 0;

	bzero(&mbx, sizeof (struct oce_mbx));
	fwcmd = (struct mbx_config_nic_rss *)&mbx.payload;

	/* initialize the ioctl header */
	mbx_common_req_hdr_init(&fwcmd->hdr, 0, 0,
	    MBX_SUBSYSTEM_NIC,
	    OPCODE_CONFIG_NIC_RSS,
	    MBX_TIMEOUT_SEC,
	    sizeof (struct mbx_config_nic_rss));
	fwcmd->params.req.enable_rss = LE_16(rss_type);
	fwcmd->params.req.flush = flush;
	fwcmd->params.req.if_id = LE_32(if_id);

	if (hkey != NULL) {
		bcopy(hkey, fwcmd->params.req.hash, OCE_HKEY_SIZE);
	}


	/* Fill the indirection table */
	for (i = 0; i < tbl_sz; i++) {
		fwcmd->params.req.cputable[i] = itbl[i];
	}

	fwcmd->params.req.cpu_tbl_sz_log2 = LE_16(OCE_LOG2(tbl_sz));

	/* fill rest of mbx */
	mbx.u0.s.embedded = B_TRUE;
	mbx.payload_length = sizeof (struct mbx_config_nic_rss);
	DW_SWAP(u32ptr(&mbx), (OCE_BMBX_RHDR_SZ + OCE_MBX_RRHDR_SZ));

	/* post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	return (ret);
}

/*
 * function called from the gld ioctl entry point to send a mbx to fw
 *
 * dev - software handle to the device
 * mp - mblk_t containing the user data
 * payload_len = [OUT] pointer to return the length of the payload written
 *
 * return 0 on Success
 */
int
oce_issue_mbox(struct oce_dev *dev, queue_t *wq, mblk_t *mp,
    uint32_t *payload_len)
{
	int ret;
	struct oce_mbx mbx;
	struct mbx_hdr hdr;
	ddi_dma_handle_t dma_handle;
	boolean_t is_embedded = B_FALSE;
	uint32_t payload_length;
	int num_buf = 0;
	int alloc_len;
	caddr_t sg_va;
	ddi_acc_handle_t acc_handle;
	size_t actual_len;

	_NOTE(ARGUNUSED(wq));

	bzero(&mbx, sizeof (struct oce_mbx));

	bcopy(mp->b_cont->b_rptr, &hdr, sizeof (struct mbx_hdr));
	DW_SWAP(u32ptr(&hdr), sizeof (struct mbx_hdr));

	payload_length = hdr.u0.req.request_length +
	    sizeof (struct mbx_hdr);

	is_embedded = (payload_length <= sizeof (struct oce_mbx_payload));

	alloc_len = msgdsize(mp->b_cont);

	oce_log(dev, CE_NOTE, MOD_CONFIG, "Mailbox: "
	    "DW[0] 0x%x DW[1] 0x%x DW[2]0x%x DW[3]0x%x,"
	    "MBLKL(%lu)  ALLOCLEN(%d)",
	    hdr.u0.dw[0], hdr.u0.dw[1],
	    hdr.u0.dw[2], hdr.u0.dw[3],
	    MBLKL(mp->b_cont), alloc_len);

	/* get the timeout from the command header */
	mbx.tag[0] = hdr.u0.req.timeout;

	if (hdr.u0.req.opcode == OPCODE_WRITE_COMMON_FLASHROM) {
		struct mbx_common_read_write_flashrom *fwcmd =
		    (struct mbx_common_read_write_flashrom *)
		    mp->b_cont->b_rptr;

		if (dev->cookie != 0 && dev->cookie != hdr.u0.req.rsvd0)
			return (EINVAL);

		if (dev->cookie == 0)
			dev->cookie = hdr.u0.req.rsvd0;
		hdr.u0.req.rsvd0 = 0;

		oce_log(dev, CE_NOTE, MOD_CONFIG, "Mailbox params:"
		    "OPCODE(%d) OPTYPE = %d  SIZE = %d  OFFSET = %d",
		    fwcmd->flash_op_code, fwcmd->flash_op_type,
		    fwcmd->data_buffer_size, fwcmd->data_offset);
	}

	if (!is_embedded) {
		mblk_t *tmp = NULL;
		ddi_dma_cookie_t cookie;
		uint32_t count = 0;
		int offset = 0;

		/* allocate dma handle */
		ret = ddi_dma_alloc_handle(dev->dip,
		    &oce_sgl_dma_attr, DDI_DMA_DONTWAIT, NULL,
		    &dma_handle);
		if (ret != DDI_SUCCESS) {
			oce_log(dev, CE_NOTE, MOD_CONFIG, "%s",
			    "Failed to alloc DMA handle");
			ret = ENOMEM;
			goto fail;
		}

		/* allocate the DMA-able memory */
		ret = ddi_dma_mem_alloc(dma_handle, alloc_len,
		    &oce_sgl_buf_accattr,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT,
		    NULL, &sg_va, &actual_len, &acc_handle);
		if (ret != DDI_SUCCESS) {
			oce_log(dev, CE_NOTE, MOD_CONFIG, "%s",
			    "Failed to alloc DMA memory");
			ret = ENOMEM;
			goto dma_alloc_fail;
		}

		for (tmp = mp->b_cont; tmp != NULL; tmp = tmp->b_cont) {
			bcopy((caddr_t)tmp->b_rptr, sg_va + offset, MBLKL(tmp));
			offset += MBLKL(tmp);
		}

		/* bind mblk mem to handle */
		ret = ddi_dma_addr_bind_handle(
		    dma_handle,
		    (struct as *)0, sg_va,
		    alloc_len,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, NULL, &cookie, &count);
		if (ret != DDI_DMA_MAPPED) {
			ret = ENOMEM;
			oce_log(dev, CE_NOTE, MOD_CONFIG,
			    "Failed to bind DMA handle ret code: %d",
			    ret);
			goto dma_bind_fail;
		}

		for (num_buf = 0; num_buf < count; num_buf++) {
			/* fill the mbx sglist */
			mbx.payload.u0.u1.sgl[num_buf].pa_lo =
			    ADDR_LO(cookie.dmac_laddress);
			mbx.payload.u0.u1.sgl[num_buf].pa_hi =
			    ADDR_HI(cookie.dmac_laddress);
			mbx.payload.u0.u1.sgl[num_buf].length =
			    (uint32_t)cookie.dmac_size;
			mbx.payload_length +=
			    mbx.payload.u0.u1.sgl[num_buf].length;
			mbx.u0.s.sge_count++;

			if (count > 1)
				(void) ddi_dma_nextcookie(dma_handle, &cookie);
		}
		mbx.u0.s.embedded = 0;

		DW_SWAP(u32ptr(&mbx), OCE_BMBX_RHDR_SZ +
		    (sizeof (struct oce_mq_sge) * count));
	} else {
		/* fill rest of mbx */
		mbx.u0.s.embedded = 1;
		mbx.payload_length = payload_length;
		bcopy(mp->b_cont->b_rptr, &mbx.payload, payload_length);

		DW_SWAP(u32ptr(&mbx), OCE_BMBX_RHDR_SZ);
	}

	/* now post the command */
	ret = oce_mbox_post(dev, &mbx, NULL);

	bcopy(mp->b_cont->b_rptr, &hdr, sizeof (struct mbx_hdr));
	DW_SWAP(u32ptr(&hdr), sizeof (struct mbx_hdr));

	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Failed to post the mailbox: %d", ret);

		*payload_len = hdr.u0.rsp.rsp_length +
		    sizeof (struct mbx_hdr);
		if (is_embedded) {
			bcopy(&mbx.payload, mp->b_cont->b_rptr,
			    MBLKL(mp->b_cont));
			goto fail;
		} else {
			(void) ddi_dma_sync(dma_handle, 0, 0,
			    DDI_DMA_SYNC_FORKERNEL);

			if (oce_fm_check_dma_handle(dev, dma_handle) !=
			    DDI_FM_OK) {
				ddi_fm_service_impact(dev->dip,
				    DDI_SERVICE_DEGRADED);
			}
			bcopy(sg_va, mp->b_cont->b_rptr,
			    sizeof (struct mbx_hdr));
			goto post_fail;
		}
	}

	if (hdr.u0.req.opcode == OPCODE_WRITE_COMMON_FLASHROM) {
		struct mbx_common_read_write_flashrom *fwcmd =
		    (struct mbx_common_read_write_flashrom *)
		    mp->b_cont->b_rptr;

		if (LE_32(fwcmd->flash_op_code) == MGMT_FLASHROM_OPCODE_FLASH)
			dev->cookie = 0;
	}

	payload_length = hdr.u0.rsp.rsp_length + sizeof (struct mbx_hdr);

	/* Copy the response back only if this is an embedded mbx cmd */
	if (is_embedded) {
		bcopy(&mbx.payload, mp->b_cont->b_rptr,
		    min(payload_length, MBLKL(mp->b_cont)));
	} else {
		mblk_t *tmp = NULL;
		int offset = 0;
		/* sync */
		(void) ddi_dma_sync(dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		if (oce_fm_check_dma_handle(dev, dma_handle) != DDI_FM_OK) {
			ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
		}

		/* copy back from kernel allocated buffer to user buffer  */
		for (tmp = mp->b_cont; tmp != NULL; tmp = tmp->b_cont) {
			bcopy(sg_va + offset, tmp->b_rptr, MBLKL(tmp));
			offset += MBLKL(tmp);
		}

		/* unbind and free dma handles */
		(void) ddi_dma_unbind_handle(dma_handle);
		ddi_dma_mem_free(&acc_handle);
		ddi_dma_free_handle(&dma_handle);
	}

	*payload_len = payload_length;

	return (0);

post_fail:
	(void) ddi_dma_unbind_handle(dma_handle);

dma_bind_fail:
	ddi_dma_mem_free(&acc_handle);

dma_alloc_fail:
	ddi_dma_free_handle(&dma_handle);

fail:
	if (hdr.u0.req.opcode == OPCODE_WRITE_COMMON_FLASHROM) {
		dev->cookie = 0;
	}
	return (ret);
}
