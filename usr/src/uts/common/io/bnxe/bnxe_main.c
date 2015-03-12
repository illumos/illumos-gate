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
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright (c) 2002, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#include "bnxe.h"

#ifndef STRINGIFY
#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)
#endif

#define BNXE_PRODUCT_BANNER "QLogic NetXtreme II 10 Gigabit Ethernet Driver v" STRINGIFY(MAJVERSION) "." STRINGIFY(MINVERSION) "." STRINGIFY(REVVERSION)
#define BNXE_PRODUCT_INFO   "QLogic NXII 10 GbE v" STRINGIFY(MAJVERSION) "." STRINGIFY(MINVERSION) "." STRINGIFY(REVVERSION)

#define BNXE_REGISTER_BAR_NUM      1
#define BNXE_REGS_MAP_OFFSET       0
#define BNXE_L2_MEMORY_WINDOW_SIZE 0x40000 /* 256K for PCI Config Registers */

u32_t    dbg_code_path   = CP_ALL;
u8_t     dbg_trace_level = LV_VERBOSE;
u32_t    g_dbg_flags     = 0;

kmutex_t bnxeLoaderMutex;
u32_t    bnxeNumPlumbed;

extern ddi_dma_attr_t bnxeDmaPageAttrib;
extern ddi_dma_attr_t bnxeRxDmaAttrib;
extern ddi_dma_attr_t bnxeTxDmaAttrib;
extern ddi_dma_attr_t bnxeTxCbDmaAttrib;


u8_t BnxeInstance(void * pDev)
{
    um_device_t * pUM = (um_device_t *)pDev;
    return (pUM == NULL) ? 0xf : pUM->instance;
}


/* pass in pointer to either lm_device_t or um_device_t */
char * BnxeDevName(void * pDev)
{
    um_device_t * pUM = (um_device_t *)pDev;
    return ((pUM == NULL) || (*pUM->devName == 0)) ? "(bnxe)" : pUM->devName;
}


char * BnxeChipName(um_device_t * pUM)
{
    switch (CHIP_NUM(&pUM->lm_dev) >> 16)
    {
    case 0x164e: return "BCM57710";
    case 0x164f: return "BCM57711";
    case 0x1650: return "BCM57711E";
    case 0x1662: return "BCM57712";
    case 0x1663: return "BCM57712NP";
    case 0x16a1: return "BCM57840";
    case 0x168d: return "BCM57840";
    case 0x16a4: return "BCM57840NP";
    case 0x16ab: return "BCM57840NP";
    case 0x168e: return "BCM57810";
    case 0x16ae: return "BCM57810NP";
    case 0x168a: return "BCM57800";
    case 0x16a5: return "BCM57800NP";
    default:     return "UNKNOWN";
    }
}


boolean_t BnxeProtoSupport(um_device_t * pUM, int proto)
{
    boolean_t do_eth;
    boolean_t do_fcoe;
    uint32_t port_feature_config_sf;

    if (IS_MULTI_VNIC(&pUM->lm_dev))
    {
        do_eth  = B_FALSE;
        do_fcoe = B_FALSE;

        if (pUM->lm_dev.hw_info.mcp_detected == 1)
        {
            if (pUM->lm_dev.params.mf_proto_support_flags &
                LM_PROTO_SUPPORT_ETHERNET)
            {
                do_eth = B_TRUE;
            }

            if (pUM->lm_dev.params.mf_proto_support_flags &
                LM_PROTO_SUPPORT_FCOE)
            {
                do_fcoe = B_TRUE;
            }
        }
        else
        {
            /* mcp is not present so allow enumeration */
            do_eth  = B_TRUE;
            do_fcoe = B_TRUE;
        }
    }
    else /* SF */
    {
        do_eth  = B_TRUE;
        do_fcoe = B_FALSE;

        /* check per port storage personality config from NVRAM */
        port_feature_config_sf = (pUM->lm_dev.hw_info.port_feature_config &
                                  PORT_FEAT_CFG_STORAGE_PERSONALITY_MASK);

        switch (port_feature_config_sf)
        {
        case PORT_FEAT_CFG_STORAGE_PERSONALITY_ISCSI:
            break;

        case PORT_FEAT_CFG_STORAGE_PERSONALITY_FCOE:
        case PORT_FEAT_CFG_STORAGE_PERSONALITY_BOTH:
        case PORT_FEAT_CFG_STORAGE_PERSONALITY_DEFAULT:
        default:
            do_fcoe = B_TRUE;
            break;
        }
    }

    if (pUM->lm_dev.params.max_func_fcoe_cons == 0)
    {
        do_fcoe = B_FALSE;
    }

    return (((proto == LM_PROTO_SUPPORT_ETHERNET) && do_eth) ||
            ((proto == LM_PROTO_SUPPORT_FCOE) && do_fcoe));
}


boolean_t BnxeProtoFcoeAfex(um_device_t * pUM)
{
    return ((pUM->lm_dev.params.mf_mode == MULTI_FUNCTION_AFEX) &&
            BnxeProtoSupport(pUM, LM_PROTO_SUPPORT_FCOE)) ? B_TRUE : B_FALSE;
}


static boolean_t BnxePciInit(um_device_t * pUM)
{
    /* setup resources needed for accessing the PCI configuration space */
    if (pci_config_setup(pUM->pDev, &pUM->pPciCfg) != DDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to setup PCI config");
        return B_FALSE;
    }

    return B_TRUE;
}


static void BnxePciDestroy(um_device_t * pUM)
{
    if (pUM->pPciCfg)
    {
        pci_config_teardown(&pUM->pPciCfg);
        pUM->pPciCfg = NULL;
    }
}


static void BnxeBarMemDestroy(um_device_t * pUM)
{
    BnxeMemRegion * pMemRegion;

    /* free the BAR mappings */
    while (!d_list_is_empty(&pUM->memRegionList))
    {
        pMemRegion = (BnxeMemRegion *)d_list_peek_head(&pUM->memRegionList);
        mm_unmap_io_space(&pUM->lm_dev,
                          pMemRegion->pRegAddr,
                          pMemRegion->size);
    }
}


static void BnxeMutexInit(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    int idx;

    for (idx = 0; idx < (MAX_RSS_CHAINS + 1); idx++)
    {
        mutex_init(&pUM->intrMutex[idx], NULL,
                   MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
        mutex_init(&pUM->intrFlipMutex[idx], NULL,
                   MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
        mutex_init(&pUM->sbMutex[idx], NULL,
                   MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    }

    for (idx = 0; idx < MAX_ETH_CONS; idx++)
    {
        mutex_init(&pUM->txq[idx].txMutex, NULL,
                   MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
        mutex_init(&pUM->txq[idx].freeTxDescMutex, NULL,
                   MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
        pUM->txq[idx].pUM = pUM;
        pUM->txq[idx].idx = idx;
    }

    for (idx = 0; idx < MAX_ETH_CONS; idx++)
    {
        mutex_init(&pUM->rxq[idx].rxMutex, NULL,
                   MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
        mutex_init(&pUM->rxq[idx].doneRxMutex, NULL,
                   MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
        pUM->rxq[idx].pUM = pUM;
        pUM->rxq[idx].idx = idx;
    }

    for (idx = 0; idx < USER_OPTION_RX_RING_GROUPS_MAX; idx++)
    {
        pUM->rxqGroup[idx].pUM = pUM;
        pUM->rxqGroup[idx].idx = idx;
    }

    mutex_init(&pUM->ethConMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->mcpMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->phyMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->indMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->cidMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->spqMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->spReqMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->rrReqMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->islesCtrlMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->toeMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->memMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->offloadMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->hwInitMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->gldMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    rw_init(&pUM->gldTxMutex, NULL, RW_DRIVER, NULL);
    mutex_init(&pUM->timerMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
    mutex_init(&pUM->kstatMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));
}


static void BnxeMutexDestroy(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    int idx;

    for (idx = 0; idx < (MAX_RSS_CHAINS + 1); idx++)
    {
        mutex_destroy(&pUM->intrMutex[idx]);
        mutex_destroy(&pUM->intrFlipMutex[idx]);
        mutex_destroy(&pUM->sbMutex[idx]);
    }

    for (idx = 0; idx < MAX_ETH_CONS; idx++)
    {
        mutex_destroy(&pUM->txq[idx].txMutex);
        mutex_destroy(&pUM->txq[idx].freeTxDescMutex);
    }

    for (idx = 0; idx < MAX_ETH_CONS; idx++)
    {
        mutex_destroy(&pUM->rxq[idx].rxMutex);
        mutex_destroy(&pUM->rxq[idx].doneRxMutex);
    }

    mutex_destroy(&pUM->ethConMutex);
    mutex_destroy(&pUM->mcpMutex);
    mutex_destroy(&pUM->phyMutex);
    mutex_destroy(&pUM->indMutex);
    mutex_destroy(&pUM->cidMutex);
    mutex_destroy(&pUM->spqMutex);
    mutex_destroy(&pUM->spReqMutex);
    mutex_destroy(&pUM->rrReqMutex);
    mutex_destroy(&pUM->islesCtrlMutex);
    mutex_destroy(&pUM->toeMutex);
    mutex_destroy(&pUM->memMutex);   /* not until all mem deleted */
    mutex_destroy(&pUM->offloadMutex);
    mutex_destroy(&pUM->hwInitMutex);
    mutex_destroy(&pUM->gldMutex);
    rw_destroy(&pUM->gldTxMutex);
    mutex_destroy(&pUM->timerMutex);
    mutex_destroy(&pUM->kstatMutex);
}


/* FMA support */

int BnxeCheckAccHandle(ddi_acc_handle_t handle)
{
    ddi_fm_error_t de;

    ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
    ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);

    return (de.fme_status);
}


int BnxeCheckDmaHandle(ddi_dma_handle_t handle)
{
    ddi_fm_error_t de;

    ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);

    return (de.fme_status);
}


/* The IO fault service error handling callback function */
static int BnxeFmErrorCb(dev_info_t *     pDev,
                         ddi_fm_error_t * err,
                         const void *     impl_data)
{
    /*
     * As the driver can always deal with an error in any dma or
     * access handle, we can just return the fme_status value.
     */
    pci_ereport_post(pDev, err, NULL);

    return (err->fme_status);
}


static void BnxeFmInit(um_device_t * pUM)
{
    ddi_iblock_cookie_t iblk;
    int fma_acc_flag;
    int fma_dma_flag;

    /* Only register with IO Fault Services if we have some capability */
    if (pUM->fmCapabilities & DDI_FM_ACCCHK_CAPABLE)
    {
        bnxeAccessAttribBAR.devacc_attr_version = DDI_DEVICE_ATTR_V1;
        bnxeAccessAttribBAR.devacc_attr_access = DDI_FLAGERR_ACC;
    }

    if (pUM->fmCapabilities & DDI_FM_DMACHK_CAPABLE)
    {
        bnxeDmaPageAttrib.dma_attr_flags = DDI_DMA_FLAGERR;
        bnxeRxDmaAttrib.dma_attr_flags   = DDI_DMA_FLAGERR;
        bnxeTxDmaAttrib.dma_attr_flags   = DDI_DMA_FLAGERR;
        bnxeTxCbDmaAttrib.dma_attr_flags = DDI_DMA_FLAGERR;
    }

    if (pUM->fmCapabilities) 
    {
        /* Register capabilities with IO Fault Services */
        ddi_fm_init(pUM->pDev, &pUM->fmCapabilities, &iblk);

        /* Initialize pci ereport capabilities if ereport capable */
        if (DDI_FM_EREPORT_CAP(pUM->fmCapabilities) ||
            DDI_FM_ERRCB_CAP(pUM->fmCapabilities))
        {
            pci_ereport_setup(pUM->pDev);
        }

        /* Register error callback if error callback capable */
        if (DDI_FM_ERRCB_CAP(pUM->fmCapabilities))
        {
            ddi_fm_handler_register(pUM->pDev, BnxeFmErrorCb, (void *)pUM);
        }
    }
}


static void BnxeFmFini(um_device_t * pUM)
{
    /* Only unregister FMA capabilities if we registered some */
    if (pUM->fmCapabilities) 
    {
        /* Release any resources allocated by pci_ereport_setup() */
        if (DDI_FM_EREPORT_CAP(pUM->fmCapabilities) ||
            DDI_FM_ERRCB_CAP(pUM->fmCapabilities))
        {
            pci_ereport_teardown(pUM->pDev);
        }

        /* Un-register error callback if error callback capable */
        if (DDI_FM_ERRCB_CAP(pUM->fmCapabilities))
        {
            ddi_fm_handler_unregister(pUM->pDev);
        }

        /* Unregister from IO Fault Services */
        ddi_fm_fini(pUM->pDev);
    }
}


void BnxeFmErrorReport(um_device_t * pUM,
                       char *        detail)
{
    uint64_t ena;
    char buf[FM_MAX_CLASS];

    (void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);

    ena = fm_ena_generate(0, FM_ENA_FMT1);

    if (DDI_FM_EREPORT_CAP(pUM->fmCapabilities))
    {
        ddi_fm_ereport_post(pUM->pDev, buf, ena, DDI_NOSLEEP,
                            FM_VERSION, DATA_TYPE_UINT8,
                            FM_EREPORT_VERS0, NULL);
    }
}


static boolean_t BnxeAttachDevice(um_device_t * pUM)
{
    int rc;
    int * props = NULL;
    uint_t numProps;
    u32_t vendor_id;
    u32_t device_id;

    /* fm-capable in bnxe.conf can be used to set fmCapabilities. */
    pUM->fmCapabilities = ddi_prop_get_int(DDI_DEV_T_ANY,
                                           pUM->pDev,
                                           DDI_PROP_DONTPASS,
                                           "fm-capable",
                                           (DDI_FM_EREPORT_CAPABLE |
                                            DDI_FM_ACCCHK_CAPABLE  |
                                            DDI_FM_DMACHK_CAPABLE  |
                                            DDI_FM_ERRCB_CAPABLE));

    /* Register capabilities with IO Fault Services. */
    BnxeFmInit(pUM);

    if (!BnxePciInit(pUM))
    {
        BnxeFmFini(pUM);

        return B_FALSE;
    }

    BnxeMutexInit(pUM);

    if (!BnxeWorkQueueInit(pUM))
    {
        return B_FALSE;
    }

    rc = lm_get_dev_info(&pUM->lm_dev);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->pPciCfg) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        BnxeWorkQueueWaitAndDestroy(pUM);
        BnxeMutexDestroy(pUM);
        BnxePciDestroy(pUM);
        BnxeFmFini(pUM);

        return B_FALSE;
    }

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->lm_dev.vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        BnxeWorkQueueWaitAndDestroy(pUM);
        BnxeMutexDestroy(pUM);
        BnxePciDestroy(pUM);
        BnxeFmFini(pUM);

        return B_FALSE;
    }

    if (rc != LM_STATUS_SUCCESS)
    {
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        BnxeWorkQueueWaitAndDestroy(pUM);
        BnxeMutexDestroy(pUM);
        BnxePciDestroy(pUM);
        BnxeFmFini(pUM);

        BnxeLogWarn(pUM, "Failed to get device information");
        return B_FALSE;
    }

#if 0
    if (IS_PFDEV(&pUM->lm_dev) && lm_check_if_pf_assigned_to_vm(&pUM->lm_dev))
    {
        lm_set_virt_mode(&pUM->lm_dev, DEVICE_TYPE_PF, VT_ASSIGNED_TO_VM_PF);
    }
#endif
 
    /* check if FCoE is enabled on this function */
#if 0
    pUM->do_fcoe =
        ((CHIP_IS_E2(&pUM->lm_dev) || CHIP_IS_E3(&pUM->lm_dev)) &&
         BnxeProtoSupport(pUM, LM_PROTO_SUPPORT_FCOE)) ? B_TRUE :
                                                         B_FALSE;
#else
    pUM->do_fcoe = B_FALSE;
#endif

    lm_get_iscsi_boot_info_block(&pUM->lm_dev, &pUM->iscsiInfo);
    if (pUM->iscsiInfo.signature != 0)
    {
        BnxeLogInfo(pUM, "MBA FCoE boot occurred on this interface.");
    }

    if (!BnxeIntrInit(pUM))
    {
        BnxeBarMemDestroy(pUM);
        BnxeWorkQueueWaitAndDestroy(pUM);
        BnxeMutexDestroy(pUM);
        BnxePciDestroy(pUM);
        BnxeFmFini(pUM);

        return B_FALSE;
    }

    if (!BnxeKstatInit(pUM))
    {
        BnxeIntrFini(pUM);
        BnxeBarMemDestroy(pUM);
        BnxeWorkQueueWaitAndDestroy(pUM);
        BnxeMutexDestroy(pUM);
        BnxePciDestroy(pUM);
        BnxeFmFini(pUM);

        return B_FALSE;
    }

    if (BnxeProtoFcoeAfex(pUM))
    {
        /* No support for L2 on FCoE enabled AFEX function! */
        BnxeLogInfo(pUM, "FCoE AFEX function, not registering with GLD.");
#if 0
        /*
         * The following is wonky. Doing a CLONE_DEV makes it visible to
         * various L2 networking commands even though the instance was
         * not registered with GLDv3 via mac_register().
         */

        /* Create a style-2 DLPI device */
        if (ddi_create_minor_node(pUM->pDev,
                                  (char *)ddi_driver_name(pUM->pDev),
                                  S_IFCHR,
                                  0,
                                  DDI_PSEUDO, //DDI_NT_NET,
                                  CLONE_DEV) != DDI_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to create device minor node.");
            BnxeKstatFini(pUM);
            BnxeIntrFini(pUM);
            BnxeBarMemDestroy(pUM);
            BnxeWorkQueueWaitAndDestroy(pUM);
            BnxeMutexDestroy(pUM);
            BnxePciDestroy(pUM);
            BnxeFmFini(pUM);

            return B_FALSE;
        }

        /* Create a style-1 DLPI device */
        if (ddi_create_minor_node(pUM->pDev,
                                  pUM->devName,
                                  S_IFCHR,
                                  pUM->instance,
                                  DDI_PSEUDO, //DDI_NT_NET,
                                  0) != DDI_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to create device instance minor node.");
            ddi_remove_minor_node(pUM->pDev, (char *)ddi_driver_name(pUM->pDev));
            BnxeKstatFini(pUM);
            BnxeIntrFini(pUM);
            BnxeBarMemDestroy(pUM);
            BnxeWorkQueueWaitAndDestroy(pUM);
            BnxeMutexDestroy(pUM);
            BnxePciDestroy(pUM);
            BnxeFmFini(pUM);

            return B_FALSE;
        }
#endif
    }
    else
    {
        /* register with the GLDv3 MAC layer */
        if (!BnxeGldInit(pUM))
        {
            BnxeKstatFini(pUM);
            BnxeIntrFini(pUM);
            BnxeBarMemDestroy(pUM);
            BnxeWorkQueueWaitAndDestroy(pUM);
            BnxeMutexDestroy(pUM);
            BnxePciDestroy(pUM);
            BnxeFmFini(pUM);

            return B_FALSE;
        }
    }

    snprintf(pUM->version,
             sizeof(pUM->version),
             "%d.%d.%d",
             MAJVERSION,
             MINVERSION,
             REVVERSION);

    snprintf(pUM->versionLM,
             sizeof(pUM->versionLM),
             "%d.%d.%d",
             LM_DRIVER_MAJOR_VER,
             LM_DRIVER_MINOR_VER,
             LM_DRIVER_FIX_NUM);

    snprintf(pUM->versionFW,
             sizeof(pUM->versionFW),
             "%d.%d.%d.%d",
             BCM_5710_FW_MAJOR_VERSION,
             BCM_5710_FW_MINOR_VERSION,
             BCM_5710_FW_REVISION_VERSION,
             BCM_5710_FW_ENGINEERING_VERSION);

    snprintf(pUM->versionBC,
             sizeof(pUM->versionBC),
             "%d.%d.%d",
             ((pUM->lm_dev.hw_info.bc_rev >> 24) & 0xff),
             ((pUM->lm_dev.hw_info.bc_rev >> 16) & 0xff),
             ((pUM->lm_dev.hw_info.bc_rev >>  8) & 0xff));

    snprintf(pUM->chipName,
             sizeof(pUM->chipName),
             "%s",
             BnxeChipName(pUM));

    snprintf(pUM->chipID,
             sizeof(pUM->chipID),
             "0x%x",
             pUM->lm_dev.hw_info.chip_id);

    *pUM->bus_dev_func = 0;
	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, pUM->pDev,
                                   0, "reg", &props, &numProps);
	if ((rc == DDI_PROP_SUCCESS) && (numProps > 0))
    {
        snprintf(pUM->bus_dev_func,
                 sizeof(pUM->bus_dev_func),
                 "%04x:%02x:%02x",
                 PCI_REG_BUS_G(props[0]),
                 PCI_REG_DEV_G(props[0]),
                 PCI_REG_FUNC_G(props[0]));
		ddi_prop_free(props);
	}

    vendor_id = 0;
	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, pUM->pDev,
                                   0, "vendor-id", &props, &numProps);
	if ((rc == DDI_PROP_SUCCESS) && (numProps > 0))
    {
        vendor_id = props[0];
		ddi_prop_free(props);
	}

    device_id = 0;
	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, pUM->pDev,
                                   0, "device-id", &props, &numProps);
	if ((rc == DDI_PROP_SUCCESS) && (numProps > 0))
    {
        device_id = props[0];
		ddi_prop_free(props);
	}

    snprintf(pUM->vendor_device,
             sizeof(pUM->vendor_device),
             "%04x:%04x",
             vendor_id,
             device_id);

    snprintf(pUM->intrAlloc,
             sizeof(pUM->intrAlloc),
             "%d %s",
             (pUM->intrType == DDI_INTR_TYPE_FIXED) ? 1 : (pUM->defIntr.intrCount +
                                                           pUM->fcoeIntr.intrCount +
                                                           pUM->rssIntr.intrCount),
             (pUM->intrType == DDI_INTR_TYPE_MSIX) ? "MSIX" :
             (pUM->intrType == DDI_INTR_TYPE_MSI)  ? "MSI"  :
                                                     "Fixed");

    BnxeLogInfo(pUM,
                "(0x%p) %s %s - v%s - FW v%s - BC v%s - %s (%s)",
                pUM,
                pUM->chipName,
                pUM->chipID,
                pUM->version,
                pUM->versionFW,
                pUM->versionBC,
                IS_MULTI_VNIC(&pUM->lm_dev) ? "MF" : "SF",
                pUM->intrAlloc);

    return B_TRUE;
}


static boolean_t BnxeDetachDevice(um_device_t * pUM)
{
    int rc;

    rc = BnxeFcoeFini(pUM);

    if ((rc != 0) && (rc != ENOTSUP) && (rc != ENODEV))
    {
        return B_FALSE;
    }

    if (BnxeProtoFcoeAfex(pUM))
    {
        /* No support for L2 on FCoE enabled AFEX function! */
        ;
#if 0
        ddi_remove_minor_node(pUM->pDev, pUM->devName);
        ddi_remove_minor_node(pUM->pDev, (char *)ddi_driver_name(pUM->pDev));
#endif
    }
    else
    {
        if (!BnxeGldFini(pUM))
        {
            return B_FALSE;
        }
    }

    BnxeKstatFini(pUM);
    BnxeIntrFini(pUM);
    BnxeBarMemDestroy(pUM);
    BnxeWorkQueueWaitAndDestroy(pUM);
    BnxeMutexDestroy(pUM);
    BnxePciDestroy(pUM);
    BnxeFmFini(pUM);

    return B_TRUE;
}


static int BnxeAttach(dev_info_t * pDev, ddi_attach_cmd_t cmd)
{
    um_device_t * pUM;

    switch (cmd)
    {
    case DDI_ATTACH:

        if ((pUM = kmem_zalloc(sizeof(um_device_t), KM_SLEEP)) == NULL)
        {
            BnxeLogWarn(NULL, "failed to allocate device structure");
            return DDI_FAILURE;
        }

        ddi_set_driver_private(pDev, pUM);

        /* set magic number for identification */
        pUM->magic = BNXE_MAGIC;

        /* default for debug logging is dump everything */
        pUM->devParams.debug_level = (CP_ALL | LV_MASK);

        /* save dev_info_t in the driver structure */
        pUM->pDev = pDev;

        d_list_clear(&pUM->memBlockList);
        d_list_clear(&pUM->memDmaList);
        d_list_clear(&pUM->memRegionList);
#ifdef BNXE_DEBUG_DMA_LIST
        d_list_clear(&pUM->memDmaListSaved);
#endif

        /* obtain a human-readable device name log messages with */
        pUM->instance = ddi_get_instance(pDev);
        snprintf(pUM->devName, sizeof(pUM->devName),
                 "bnxe%d", pUM->instance);

        if (!BnxeAttachDevice(pUM))
        {
            kmem_free(pUM, sizeof(um_device_t));
            return DDI_FAILURE;
        }

        if (BNXE_FCOE(pUM) && pUM->devParams.fcoeEnable)
        {
            BnxeFcoeStartStop(pUM);
        }

        return DDI_SUCCESS;

    case DDI_RESUME:
#if !(defined(__S11) || defined(__S12))
    case DDI_PM_RESUME:
#endif

        pUM = (um_device_t *)ddi_get_driver_private(pDev);

        /* sanity check */
        if (pUM == NULL || pUM->pDev != pDev)
        {
            BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
            return DDI_FAILURE;
        }

        if (BnxeHwResume(pUM) != 0)
        {
            BnxeLogWarn(pUM, "Fail to resume this device!");
            return DDI_FAILURE;
        }

        return DDI_SUCCESS;

    default:

        return DDI_FAILURE;
    }
}


static int BnxeDetach(dev_info_t * pDev, ddi_detach_cmd_t cmd)
{
    um_device_t * pUM;

    switch (cmd)
    {
    case DDI_DETACH:

        pUM = (um_device_t *)ddi_get_driver_private(pDev);

        /* sanity check */
        if (pUM == NULL || pUM->pDev != pDev)
        {
            BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
            return DDI_FAILURE;
        }

        if (pUM->intrEnabled != B_FALSE)
        {
            BnxeLogWarn(pUM, "Detaching a device that is currently running!");
            return DDI_FAILURE;
        }

        if (!BnxeDetachDevice(pUM))
        {
            BnxeLogWarn(pUM, "Can't detach it now, please try again later!");
            return DDI_FAILURE;
        }

        kmem_free(pUM, sizeof(um_device_t));

        return DDI_SUCCESS;

    case DDI_SUSPEND:
#if !(defined(__S11) || defined(__S12))
    case DDI_PM_SUSPEND:
#endif

        pUM = (um_device_t *)ddi_get_driver_private(pDev);

        /* sanity check */
        if (pUM == NULL || pUM->pDev != pDev)
        {
            BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
            return DDI_FAILURE;
        }

        if (BnxeHwSuspend(pUM) != 0)
        {
            BnxeLogWarn(pUM, "Fail to suspend this device!");
            return DDI_FAILURE;
        }

        return DDI_SUCCESS;

    default:

        return DDI_FAILURE;
    }
}


#if (DEVO_REV > 3)

static int BnxeQuiesce(dev_info_t * pDev)
{
    um_device_t * pUM;

    pUM = (um_device_t *)ddi_get_driver_private(pDev);

    /* sanity check */
    if (pUM == NULL || pUM->pDev != pDev)
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
        return DDI_FAILURE;
    }

    if (!pUM->plumbed)
    {
        return DDI_SUCCESS;
    }

    if (BnxeHwQuiesce(pUM) != 0)
    {
        BnxeLogWarn(pUM, "Failed to quiesce the device!");
        return DDI_FAILURE;
    }

    return DDI_SUCCESS;
}

#endif


void BnxeFcoeInitChild(dev_info_t * pDev,
                       dev_info_t * cDip)
{
    um_device_t *pUM = (um_device_t *) ddi_get_driver_private(pDev);

    if ((pUM == NULL) || (pUM->pDev != pDev))
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed ", __func__);
        return;
    }

    ddi_set_name_addr(cDip, ddi_get_name_addr(pUM->pDev));
}


void BnxeFcoeUninitChild(dev_info_t * pDev,
                         dev_info_t * cDip)
{
	ddi_set_name_addr(cDip, NULL);
}


static int BnxeBusCtl(dev_info_t *   pDev,
                      dev_info_t *   pRDev,
                      ddi_ctl_enum_t op,
                      void *         pArg,
                      void *         pResult)
{
    um_device_t * pUM = (um_device_t *)ddi_get_driver_private(pDev);

    /* sanity check */
    if (pUM == NULL || pUM->pDev != pDev)
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
        return DDI_FAILURE;
    }

    BnxeLogDbg(pUM, "BnxeBusCtl (%d)", op);

    switch (op)
    {
    case DDI_CTLOPS_REPORTDEV:
    case DDI_CTLOPS_IOMIN:
        break;
    case DDI_CTLOPS_INITCHILD:
        BnxeFcoeInitChild(pDev, (dev_info_t *) pArg);
        break;
    case DDI_CTLOPS_UNINITCHILD:
        BnxeFcoeUninitChild(pDev, (dev_info_t *) pArg);
        break;

    default:

        return (ddi_ctlops(pDev, pRDev, op, pArg, pResult));
    }

    return DDI_SUCCESS;
}


static int BnxeCbIoctl(dev_t    dev,
                       int      cmd,
                       intptr_t arg,
                       int      mode,
                       cred_t * credp,
                       int *    rvalp)
{
    BnxeBinding * pBinding = (BnxeBinding *)arg;
    um_device_t * pUM;

    (void)dev;
    (void)mode;
    (void)credp;
    (void)rvalp;

    if ((pBinding == NULL) ||
        (pBinding->pCliDev == NULL) ||
        (pBinding->pPrvDev == NULL))
    {
        BnxeLogWarn(NULL, "Invalid binding arg to ioctl %d", cmd);
        return DDI_FAILURE;
    }

    pUM = (um_device_t *)ddi_get_driver_private(pBinding->pPrvDev);

    /* sanity checks */

    if (pBinding->version != BNXE_BINDING_VERSION)
    {
        BnxeLogWarn(NULL, "%s: Invalid binding version (0x%08x)",
                    __func__, pBinding->version);
        return DDI_FAILURE;
    }

    if ((pUM == NULL) ||
        (pUM->fcoe.pDev != pBinding->pCliDev) ||
        (pUM->pDev != pBinding->pPrvDev))
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
        return DDI_FAILURE;
    }

    switch (cmd)
    {
    case BNXE_BIND_FCOE:

        /* copy the binding struct and fill in the provider callback */

        BnxeLogInfo(pUM, "FCoE BIND start");

        if (!CLIENT_DEVI(pUM, LM_CLI_IDX_FCOE))
        {
            BnxeLogWarn(pUM, "FCoE BIND when DEVI is offline!");
            return DDI_FAILURE;
        }

        if (CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE))
        {
            BnxeLogWarn(pUM, "FCoE BIND when alread bound!");
            return DDI_FAILURE;
        }

        pUM->fcoe.bind = *pBinding;

        pUM->fcoe.bind.prvCtl           = pBinding->prvCtl           = BnxeFcoePrvCtl;
        pUM->fcoe.bind.prvTx            = pBinding->prvTx            = BnxeFcoePrvTx;
        pUM->fcoe.bind.prvPoll          = pBinding->prvPoll          = BnxeFcoePrvPoll;
        pUM->fcoe.bind.prvSendWqes      = pBinding->prvSendWqes      = BnxeFcoePrvSendWqes;
        pUM->fcoe.bind.prvMapMailboxq   = pBinding->prvMapMailboxq   = BnxeFcoePrvMapMailboxq;
        pUM->fcoe.bind.prvUnmapMailboxq = pBinding->prvUnmapMailboxq = BnxeFcoePrvUnmapMailboxq;

        pUM->devParams.numRxDesc[LM_CLI_IDX_FCOE] = pBinding->numRxDescs;
        pUM->devParams.numTxDesc[LM_CLI_IDX_FCOE] = pBinding->numTxDescs;

        pUM->lm_dev.params.l2_rx_desc_cnt[LM_CLI_IDX_FCOE] = pBinding->numRxDescs;
        BnxeInitBdCnts(pUM, LM_CLI_IDX_FCOE);

        if (BnxeHwStartFCOE(pUM))
        {
            return DDI_FAILURE;
        }

        CLIENT_BIND_SET(pUM, LM_CLI_IDX_FCOE);
        lm_mcp_indicate_client_bind(&pUM->lm_dev, LM_CLI_IDX_FCOE);

        BnxeLogInfo(pUM, "FCoE BIND done");
        return DDI_SUCCESS;

    case BNXE_UNBIND_FCOE:

        /* clear the binding struct and stats */

        BnxeLogInfo(pUM, "FCoE UNBIND start");

        if (CLIENT_DEVI(pUM, LM_CLI_IDX_FCOE))
        {
            BnxeLogWarn(pUM, "FCoE UNBIND when DEVI is online!");
            return DDI_FAILURE;
        }

        if (!CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE))
        {
            BnxeLogWarn(pUM, "FCoE UNBIND when not bound!");
            return DDI_FAILURE;
        }

        /* We must not detach until all packets held by fcoe are retrieved. */
        if (!BnxeWaitForPacketsFromClient(pUM, LM_CLI_IDX_FCOE))
        {
            return DDI_FAILURE;
        }

        lm_mcp_indicate_client_unbind(&pUM->lm_dev, LM_CLI_IDX_FCOE);
        CLIENT_BIND_RESET(pUM, LM_CLI_IDX_FCOE);

        BnxeHwStopFCOE(pUM);

        memset(&pUM->fcoe.bind, 0, sizeof(pUM->fcoe.bind));
        memset(&pUM->fcoe.stats, 0, sizeof(pUM->fcoe.stats));

        pBinding->prvCtl           = NULL;
        pBinding->prvTx            = NULL;
        pBinding->prvPoll          = NULL;
        pBinding->prvSendWqes      = NULL;
        pBinding->prvMapMailboxq   = NULL;
        pBinding->prvUnmapMailboxq = NULL;

        pUM->fcoe.pDev = NULL; /* sketchy? */

        BnxeLogInfo(pUM, "FCoE UNBIND done");
        return DDI_SUCCESS;

    default:

        BnxeLogWarn(pUM, "Unknown ioctl %d", cmd);
        return DDI_FAILURE;
    }
}

#ifndef ILLUMOS
static struct bus_ops bnxe_bus_ops =
{
    BUSO_REV,
    nullbusmap,        /* bus_map */
    NULL,              /* bus_get_intrspec */
    NULL,              /* bus_add_intrspec */
    NULL,              /* bus_remove_intrspec */
    i_ddi_map_fault,   /* bus_map_fault */
    ddi_dma_map,       /* bus_dma_map */
    ddi_dma_allochdl,  /* bus_dma_allochdl */
    ddi_dma_freehdl,   /* bus_dma_freehdl */
    ddi_dma_bindhdl,   /* bus_dma_bindhdl */
    ddi_dma_unbindhdl, /* bus_unbindhdl */
    ddi_dma_flush,     /* bus_dma_flush */
    ddi_dma_win,       /* bus_dma_win */
    ddi_dma_mctl,      /* bus_dma_ctl */
    BnxeBusCtl,        /* bus_ctl */
    ddi_bus_prop_op,   /* bus_prop_op */
    NULL,              /* bus_get_eventcookie */
    NULL,              /* bus_add_eventcall */
    NULL,              /* bus_remove_event */
    NULL,              /* bus_post_event */
    NULL,              /* bus_intr_ctl */
    NULL,              /* bus_config */
    NULL,              /* bus_unconfig */
    NULL,              /* bus_fm_init */
    NULL,              /* bus_fm_fini */
    NULL,              /* bus_fm_access_enter */
    NULL,              /* bus_fm_access_exit */
    NULL,              /* bus_power */
    NULL
};
#endif	/* ILLUMOS */


static struct cb_ops bnxe_cb_ops =
{
    nulldev,               /* cb_open */
    nulldev,               /* cb_close */
    nodev,                 /* cb_strategy */
    nodev,                 /* cb_print */
    nodev,                 /* cb_dump */
    nodev,                 /* cb_read */
    nodev,                 /* cb_write */
    BnxeCbIoctl,           /* cb_ioctl */
    nodev,                 /* cb_devmap */
    nodev,                 /* cb_mmap */
    nodev,                 /* cb_segmap */
    nochpoll,              /* cb_chpoll */
    ddi_prop_op,           /* cb_prop_op */
    NULL,                  /* cb_stream */
    (int)(D_MP | D_64BIT), /* cb_flag */
    CB_REV,                /* cb_rev */
    nodev,                 /* cb_aread */
    nodev,                 /* cb_awrite */
};


#if (DEVO_REV > 3)

static struct dev_ops bnxe_dev_ops =
{
    DEVO_REV,      /* devo_rev */
    0,             /* devo_refcnt */
    NULL,          /* devo_getinfo */
    nulldev,       /* devo_identify */
    nulldev,       /* devo_probe */
    BnxeAttach,    /* devo_attach */
    BnxeDetach,    /* devo_detach */
    nodev,         /* devo_reset */
    &bnxe_cb_ops,  /* devo_cb_ops */
#ifndef	ILLUMOS
    &bnxe_bus_ops, /* devo_bus_ops */
#else
    NULL,          /* devo_bus_ops */
#endif
    NULL,          /* devo_power */
    BnxeQuiesce    /* devo_quiesce */
};

#else

static struct dev_ops bnxe_dev_ops =
{
    DEVO_REV,      /* devo_rev */
    0,             /* devo_refcnt */
    NULL,          /* devo_getinfo */
    nulldev,       /* devo_identify */
    nulldev,       /* devo_probe */
    BnxeAttach,    /* devo_attach */
    BnxeDetach,    /* devo_detach */
    nodev,         /* devo_reset */
    &bnxe_cb_ops,  /* devo_cb_ops */
    &bnxe_bus_ops, /* devo_bus_ops */
    NULL           /* devo_power */
};

#endif


static struct modldrv bnxe_modldrv =
{
    &mod_driverops,    /* drv_modops (must be mod_driverops for drivers) */
    BNXE_PRODUCT_INFO, /* drv_linkinfo (string displayed by modinfo) */
    &bnxe_dev_ops      /* drv_dev_ops */
};


static struct modlinkage bnxe_modlinkage =
{
    MODREV_1,        /* ml_rev */
    {
      &bnxe_modldrv, /* ml_linkage */
      NULL           /* NULL termination */
    }
};


int _init(void)
{
    int rc;

    mac_init_ops(&bnxe_dev_ops, "bnxe");

    /* Install module information with O/S */
    if ((rc = mod_install(&bnxe_modlinkage)) != DDI_SUCCESS)
    {
        BnxeLogWarn(NULL, "mod_install returned 0x%x", rc);
        mac_fini_ops(&bnxe_dev_ops);
        return rc;
    }

    mutex_init(&bnxeLoaderMutex, NULL, MUTEX_DRIVER, NULL);
    bnxeNumPlumbed = 0;

    BnxeLogInfo(NULL, "%s", BNXE_PRODUCT_BANNER);

    return rc;
}


int _fini(void)
{
    int rc;

    if ((rc = mod_remove(&bnxe_modlinkage)) == DDI_SUCCESS)
    {
        mac_fini_ops(&bnxe_dev_ops);
        mutex_destroy(&bnxeLoaderMutex);

        if (bnxeNumPlumbed > 0)
        {
            /*
             * This shouldn't be possible since modunload must only call _fini
             * when no instances are currently plumbed.
             */
            BnxeLogWarn(NULL, "%d instances have not been unplumbed", bnxeNumPlumbed);
        }
    }

    return rc;
}


int _info(struct modinfo * pModinfo)
{
    return mod_info(&bnxe_modlinkage, pModinfo);
}

