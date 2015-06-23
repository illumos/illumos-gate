/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#define	EMLXS_FW_TABLE_DEF
#define	EMLXS_MODEL_DEF

#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_HBA_C);


static void emlxs_handle_async_event(emlxs_hba_t *hba, CHANNEL *cp,
    IOCBQ *iocbq);

static void emlxs_pci_cap_offsets(emlxs_hba_t *hba);

#ifdef MSI_SUPPORT
uint32_t emlxs_msi_map[EMLXS_MSI_MODES][EMLXS_MSI_MAX_INTRS] =
	{EMLXS_MSI_MAP1, EMLXS_MSI_MAP2, EMLXS_MSI_MAP4, EMLXS_MSI_MAP8};
uint32_t emlxs_msi_mask[EMLXS_MSI_MODES] =
	{EMLXS_MSI0_MASK1, EMLXS_MSI0_MASK2, EMLXS_MSI0_MASK4,
	EMLXS_MSI0_MASK8};
#endif /* MSI_SUPPORT */

emlxs_firmware_t emlxs_fw_table[] = EMLXS_FW_TABLE;
int emlxs_fw_count = sizeof (emlxs_fw_table) / sizeof (emlxs_firmware_t);

emlxs_table_t emlxs_pci_cap[] = {
	{PCI_CAP_ID_PM, "PCI_CAP_ID_PM"},
	{PCI_CAP_ID_AGP, "PCI_CAP_ID_AGP"},
	{PCI_CAP_ID_VPD, "PCI_CAP_ID_VPD"},
	{PCI_CAP_ID_SLOT_ID, "PCI_CAP_ID_SLOT_ID"},
	{PCI_CAP_ID_MSI, "PCI_CAP_ID_MSI"},
	{PCI_CAP_ID_cPCI_HS, "PCI_CAP_ID_cPCI_HS"},
	{PCI_CAP_ID_PCIX, "PCI_CAP_ID_PCIX"},
	{PCI_CAP_ID_HT, "PCI_CAP_ID_HT"},
	{PCI_CAP_ID_VS, "PCI_CAP_ID_VS"},
	{PCI_CAP_ID_DEBUG_PORT, "PCI_CAP_ID_DEBUG_PORT"},
	{PCI_CAP_ID_cPCI_CRC, "PCI_CAP_ID_cPCI_CRC"},
	{PCI_CAP_ID_PCI_HOTPLUG, "PCI_CAP_ID_PCI_HOTPLUG"},
	{PCI_CAP_ID_P2P_SUBSYS, "PCI_CAP_ID_P2P_SUBSYS"},
	{PCI_CAP_ID_AGP_8X, "PCI_CAP_ID_AGP_8X"},
	{PCI_CAP_ID_SECURE_DEV, "PCI_CAP_ID_SECURE_DEV"},
	{PCI_CAP_ID_PCI_E, "PCI_CAP_ID_PCI_E"},
	{PCI_CAP_ID_MSI_X, "PCI_CAP_ID_MSI_X"},
	{PCI_CAP_ID_SATA, "PCI_CAP_ID_SATA"},
	{PCI_CAP_ID_FLR, "PCI_CAP_ID_FLR"}

}; /* emlxs_pci_cap */

emlxs_table_t emlxs_pci_ecap[] = {
	{PCIE_EXT_CAP_ID_AER, "PCIE_EXT_CAP_ID_AER"},
	{PCIE_EXT_CAP_ID_VC, "PCIE_EXT_CAP_ID_VC"},
	{PCIE_EXT_CAP_ID_SER, "PCIE_EXT_CAP_ID_SER"},
	{PCIE_EXT_CAP_ID_PWR_BUDGET, "PCIE_EXT_CAP_ID_PWR_BUDGET"},
	{PCIE_EXT_CAP_ID_RC_LINK_DECL, "PCIE_EXT_CAP_ID_RC_LINK_DECL"},
	{PCIE_EXT_CAP_ID_RC_INT_LINKCTRL, "PCIE_EXT_CAP_ID_RC_INT_LINKCTRL"},
	{PCIE_EXT_CAP_ID_RC_EVNT_CEA, "PCIE_EXT_CAP_ID_RC_EVNT_CEA"},
	{PCIE_EXT_CAP_ID_MFVC, "PCIE_EXT_CAP_ID_MFVC"},
	{PCIE_EXT_CAP_ID_VC_WITH_MFVC, "PCIE_EXT_CAP_ID_VC_WITH_MFVC"},
	{PCIE_EXT_CAP_ID_RCRB, "PCIE_EXT_CAP_ID_RCRB"},
	{PCIE_EXT_CAP_ID_VS, "PCIE_EXT_CAP_ID_VS"},
	{PCIE_EXT_CAP_ID_CAC, "PCIE_EXT_CAP_ID_CAC"},
	{PCIE_EXT_CAP_ID_ACS, "PCIE_EXT_CAP_ID_ACS"},
	{PCIE_EXT_CAP_ID_ARI, "PCIE_EXT_CAP_ID_ARI"},
	{PCIE_EXT_CAP_ID_ATS, "PCIE_EXT_CAP_ID_ATS"},
	{PCI_EXT_CAP_ID_SRIOV, "PCI_EXT_CAP_ID_SRIOV"},
	{PCI_EXT_CAP_ID_TPH, "PCI_EXT_CAP_ID_TPH"},
	{PCI_EXT_CAP_ID_SEC_PCI, "PCI_EXT_CAP_ID_SEC_PCI"}

}; /* emlxs_pci_ecap */


emlxs_table_t emlxs_ring_table[] = {
	{FC_FCP_RING, "FCP Ring"},
	{FC_IP_RING, "IP  Ring"},
	{FC_ELS_RING, "ELS Ring"},
	{FC_CT_RING, "CT  Ring"}

}; /* emlxs_ring_table */

emlxs_table_t emlxs_ffstate_table[] = {
	{0, "NULL"},
	{FC_ERROR, "ERROR"},
	{FC_KILLED, "KILLED"},
	{FC_WARM_START, "WARM_START"},
	{FC_INIT_START, "INIT_START"},
	{FC_INIT_NVPARAMS, "INIT_NVPARAMS"},
	{FC_INIT_REV, "INIT_REV"},
	{FC_INIT_CFGPORT, "INIT_CFGPORT"},
	{FC_INIT_CFGRING, "INIT_CFGRING"},
	{FC_INIT_INITLINK, "INIT_INITLINK"},
	{FC_LINK_DOWN, "LINK_DOWN"},
	{FC_LINK_UP, "LINK_UP"},
	{FC_CLEAR_LA, "CLEAR_LA"},
	{FC_READY, "READY"}

}; /* emlxs_ffstate_table */


#ifdef MSI_SUPPORT
/* EMLXS_INTR_INIT */
int32_t
emlxs_msi_init(emlxs_hba_t *hba, uint32_t max)
{
	emlxs_port_t *port = &PPORT;
	int32_t pass = 0;
	int32_t type = 0;
	char s_type[16];
	int32_t types;
	int32_t count;
	int32_t nintrs;
	int32_t mode;
	int32_t actual;
	int32_t new_actual;
	int32_t i;
	int32_t ret;
	ddi_intr_handle_t *htable = NULL;
	ddi_intr_handle_t *new_htable = NULL;
	uint32_t *intr_pri = NULL;
	int32_t *intr_cap = NULL;
	int32_t hilevel_pri;
	emlxs_config_t *cfg = &CFG;

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		return (emlxs_intx_init(hba, max));
	}

	if (hba->intr_flags & EMLXS_MSI_INITED) {
		return (DDI_SUCCESS);
	}

	/* Set max interrupt count if not specified */
	if (max == 0) {
		if ((cfg[CFG_MSI_MODE].current == 2) ||
		    (cfg[CFG_MSI_MODE].current == 3)) {
			max = EMLXS_MSI_MAX_INTRS;
		} else {
			max = 1;
		}
	}

	/* Filter max interrupt count with adapter model specification */
	if (hba->model_info.intr_limit && (max > hba->model_info.intr_limit)) {
		max = hba->model_info.intr_limit;
	}

	/* Get the available interrupt types from the kernel */
	types = 0;
	ret = ddi_intr_get_supported_types(hba->dip, &types);

	if ((ret != DDI_SUCCESS)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: ddi_intr_get_supported_types failed. ret=%d", ret);

		/* Default to fixed type */
		types = DDI_INTR_TYPE_FIXED;
	}

	/* Check if fixed interrupts are being forced */
	if (cfg[CFG_MSI_MODE].current == 0) {
		types &= DDI_INTR_TYPE_FIXED;
	}

	/* Check if MSI interrupts are being forced */
	else if ((cfg[CFG_MSI_MODE].current == 1) ||
	    (cfg[CFG_MSI_MODE].current == 2)) {
		types &= (DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_FIXED);
	}

begin:

	/* Set interrupt type and interrupt count */
	type = 0;

	/* Check if MSIX is fully supported */
	if ((types & DDI_INTR_TYPE_MSIX) &&
	    (hba->model_info.flags & EMLXS_MSIX_SUPPORTED)) {
		/* Get the max interrupt count from the adapter */
		nintrs = 0;
		ret =
		    ddi_intr_get_nintrs(hba->dip, DDI_INTR_TYPE_MSIX,
		    &nintrs);

		if (ret == DDI_SUCCESS && nintrs) {
			type = DDI_INTR_TYPE_MSIX;
			(void) strlcpy(s_type, "TYPE_MSIX", sizeof (s_type));
			goto initialize;
		}
	}

	/* Check if MSI is fully supported */
	if ((types & DDI_INTR_TYPE_MSI) &&
	    (hba->model_info.flags & EMLXS_MSI_SUPPORTED)) {
		/* Get the max interrupt count from the adapter */
		nintrs = 0;
		ret =
		    ddi_intr_get_nintrs(hba->dip, DDI_INTR_TYPE_MSI, &nintrs);

		if (ret == DDI_SUCCESS && nintrs) {
			type = DDI_INTR_TYPE_MSI;
			(void) strlcpy(s_type, "TYPE_MSI", sizeof (s_type));
			goto initialize;
		}
	}

	/* Check if fixed interrupts are fully supported */
	if ((types & DDI_INTR_TYPE_FIXED) &&
	    (hba->model_info.flags & EMLXS_INTX_SUPPORTED)) {
		/* Get the max interrupt count from the adapter */
		nintrs = 0;
		ret =
		    ddi_intr_get_nintrs(hba->dip, DDI_INTR_TYPE_FIXED,
		    &nintrs);

		if (ret == DDI_SUCCESS) {
			type = DDI_INTR_TYPE_FIXED;
			(void) strlcpy(s_type, "TYPE_FIXED", sizeof (s_type));
			goto initialize;
		}
	}

	goto init_failed;


initialize:

	pass++;
	mode = 0;
	actual = 0;
	htable = NULL;
	intr_pri = NULL;
	intr_cap = NULL;
	hilevel_pri = 0;

	if (pass == 1) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: %s: mode=%d types=0x%x nintrs=%d", s_type,
		    cfg[CFG_MSI_MODE].current, types, nintrs);
	}

	/* Validate interrupt count */
	count = min(nintrs, max);

	if (count >= 8) {
		count = 8;
	} else if (count >= 4) {
		count = 4;
	} else if (count >= 2) {
		count = 2;
	} else {
		count = 1;
	}

	/* Allocate an array of interrupt handles */
	htable =
	    kmem_alloc((size_t)(count * sizeof (ddi_intr_handle_t)),
	    KM_SLEEP);

	/* Allocate 'count' interrupts */
	ret =
	    ddi_intr_alloc(hba->dip, htable, type, EMLXS_MSI_INUMBER, count,
	    &actual, DDI_INTR_ALLOC_NORMAL);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "MSI: %s: count=%d actual=%d ret=%d", s_type, count, actual, ret);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: Unable to allocate interrupts. error=%d", ret);

		actual = 0;
		goto init_failed;
	}

	if (actual != count) {
		/* Validate actual count */
		if (actual >= 8) {
			new_actual = 8;
		} else if (actual >= 4) {
			new_actual = 4;
		} else if (actual >= 2) {
			new_actual = 2;
		} else {
			new_actual = 1;
		}

		if (new_actual < actual) {
			/* Free extra handles */
			for (i = new_actual; i < actual; i++) {
				(void) ddi_intr_free(htable[i]);
			}

			actual = new_actual;
		}

		/* Allocate a new array of interrupt handles */
		new_htable =
		    kmem_alloc((size_t)(actual * sizeof (ddi_intr_handle_t)),
		    KM_SLEEP);

		/* Copy old array to new array */
		bcopy((uint8_t *)htable, (uint8_t *)new_htable,
		    (actual * sizeof (ddi_intr_handle_t)));

		/* Free the old array */
		kmem_free(htable, (count * sizeof (ddi_intr_handle_t)));

		htable = new_htable;
		count = actual;
	}

	/* Allocate interrupt priority table */
	intr_pri =
	    (uint32_t *)kmem_alloc((size_t)(count * sizeof (uint32_t)),
	    KM_SLEEP);

	/* Allocate interrupt capability table */
	intr_cap = kmem_alloc((size_t)(count * sizeof (uint32_t)), KM_SLEEP);

	/* Get minimum hilevel priority */
	hilevel_pri = ddi_intr_get_hilevel_pri();

	/* Fill the priority and capability tables */
	for (i = 0; i < count; ++i) {
		ret = ddi_intr_get_pri(htable[i], &intr_pri[i]);

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: ddi_intr_get_pri(%d) failed. "
			    "handle=%p ret=%d",
			    i, &htable[i], ret);

			/* Clean up the interrupts */
			goto init_failed;
		}

		if (intr_pri[i] >= hilevel_pri) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: Interrupt(%d) level too high. "
			    "pri=0x%x hilevel=0x%x",
			    i, intr_pri[i], hilevel_pri);

			/* Clean up the interrupts */
			goto init_failed;
		}

		ret = ddi_intr_get_cap(htable[i], &intr_cap[i]);

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: ddi_intr_get_cap(%d) failed. "
			    "handle=%p ret=%d",
			    i, &htable[i], ret);

			/* Clean up the interrupts */
			goto init_failed;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: %s: %d: cap=0x%x pri=0x%x hilevel=0x%x", s_type, i,
		    intr_cap[i], intr_pri[i], hilevel_pri);

	}

	/* Set mode */
	switch (count) {
	case 8:
		mode = EMLXS_MSI_MODE8;
		break;

	case 4:
		mode = EMLXS_MSI_MODE4;
		break;

	case 2:
		mode = EMLXS_MSI_MODE2;
		break;

	default:
		mode = EMLXS_MSI_MODE1;
	}

	/* Save the info */
	hba->intr_htable = htable;
	hba->intr_count = count;
	hba->intr_pri = intr_pri;
	hba->intr_cap = intr_cap;
	hba->intr_type = type;
	hba->intr_arg = (void *)((unsigned long)intr_pri[0]);
	hba->intr_mask = emlxs_msi_mask[mode];

	hba->intr_cond = 0;

	/* Adjust number of channels based on intr_count */
	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		hba->chan_count = hba->intr_count * cfg[CFG_NUM_WQ].current;
	}

	for (i = 0; i < EMLXS_MSI_MAX_INTRS; i++) {
		hba->intr_map[i] = emlxs_msi_map[mode][i];
		hba->intr_cond |= emlxs_msi_map[mode][i];

		mutex_init(&hba->intr_lock[i], NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(hba->intr_arg));
	}

	/* Set flag to indicate support */
	hba->intr_flags |= EMLXS_MSI_INITED;

	/* Create the interrupt threads */
	for (i = 0; i < hba->chan_count; i++) {
		mutex_init(&hba->chan[i].rsp_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(hba->intr_arg));

		emlxs_thread_create(hba, &hba->chan[i].intr_thread);
	}

	return (DDI_SUCCESS);

init_failed:

	if (intr_cap) {
		kmem_free(intr_cap, (count * sizeof (int32_t)));
	}

	if (intr_pri) {
		kmem_free(intr_pri, (count * sizeof (int32_t)));
	}

	if (htable) {
		/* Process the interrupt handlers */
		for (i = 0; i < actual; i++) {
			/* Free the handle[i] */
			(void) ddi_intr_free(htable[i]);
		}

		kmem_free(htable, (count * sizeof (ddi_intr_handle_t)));
	}

	/* Initialize */
	hba->intr_htable = NULL;
	hba->intr_count = 0;
	hba->intr_pri = NULL;
	hba->intr_cap = NULL;
	hba->intr_type = 0;
	hba->intr_arg = NULL;
	hba->intr_cond = 0;
	bzero(hba->intr_map, sizeof (hba->intr_map));
	bzero(hba->intr_lock, sizeof (hba->intr_lock));

	if (type == DDI_INTR_TYPE_MSIX) {
		types &= (DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_FIXED);
		goto begin;
	} else if (type == DDI_INTR_TYPE_MSI) {
		types &= DDI_INTR_TYPE_FIXED;
		goto begin;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
	    "MSI: Unable to initialize interrupts");

	return (DDI_FAILURE);


} /* emlxs_msi_init() */


/* EMLXS_INTR_UNINIT */
int32_t
emlxs_msi_uninit(emlxs_hba_t *hba)
{
	uint32_t count;
	int32_t i;
	ddi_intr_handle_t *htable;
	uint32_t *intr_pri;
	int32_t *intr_cap;
	int32_t ret;

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		return (emlxs_intx_uninit(hba));
	}

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	 *    "MSI: msi_uninit called. flags=%x",
	 *    hba->intr_flags);
	 */

	/* Make sure interrupts have been removed first */
	if ((hba->intr_flags & EMLXS_MSI_ADDED)) {
		ret = emlxs_msi_remove(hba);

		if (ret != DDI_SUCCESS) {
			return (ret);
		}
	}

	/* Check if the interrupts are still initialized */
	if (!(hba->intr_flags & EMLXS_MSI_INITED)) {
		return (DDI_SUCCESS);
	}
	hba->intr_flags &= ~EMLXS_MSI_INITED;

	/* Get handle table parameters */
	htable = hba->intr_htable;
	count = hba->intr_count;
	intr_pri = hba->intr_pri;
	intr_cap = hba->intr_cap;

	/* Clean up */
	hba->intr_count = 0;
	hba->intr_htable = NULL;
	hba->intr_pri = NULL;
	hba->intr_cap = NULL;
	hba->intr_type = 0;
	hba->intr_arg = NULL;
	hba->intr_cond = 0;
	bzero(hba->intr_map, sizeof (hba->intr_map));

	if (intr_cap) {
		kmem_free(intr_cap, (count * sizeof (int32_t)));
	}

	if (intr_pri) {
		kmem_free(intr_pri, (count * sizeof (int32_t)));
	}

	if (htable) {
		/* Process the interrupt handlers */
		for (i = 0; i < count; ++i) {
			/* Free the handle[i] */
			ret = ddi_intr_free(htable[i]);
		}

		kmem_free(htable, (count * sizeof (ddi_intr_handle_t)));
	}

	/* Destroy the intr locks */
	for (i = 0; i < EMLXS_MSI_MAX_INTRS; i++) {
		mutex_destroy(&hba->intr_lock[i]);
	}

	/* Destroy the interrupt threads */
	for (i = 0; i < hba->chan_count; i++) {
		emlxs_thread_destroy(&hba->chan[i].intr_thread);
		mutex_destroy(&hba->chan[i].rsp_lock);
	}

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	 *    "MSI: msi_uninit done. flags=%x",
	 *    hba->intr_flags);
	 */

	return (DDI_SUCCESS);

} /* emlxs_msi_uninit() */


/* EMLXS_INTR_ADD */
int32_t
emlxs_msi_add(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int32_t count;
	int32_t i;
	int32_t ret;
	ddi_intr_handle_t *htable = NULL;
	int32_t *intr_cap = NULL;

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		return (emlxs_intx_add(hba));
	}

	/* Check if interrupts have already been added */
	if (hba->intr_flags & EMLXS_MSI_ADDED) {
		return (DDI_SUCCESS);
	}

	/* Check if interrupts have been initialized */
	if (!(hba->intr_flags & EMLXS_MSI_INITED)) {
		ret = emlxs_msi_init(hba, 0);

		if (ret != DDI_SUCCESS) {
			return (ret);
		}
	}

	/* Get handle table parameters */
	htable = hba->intr_htable;
	count = hba->intr_count;
	intr_cap = hba->intr_cap;

	/* Add the interrupt handlers */
	for (i = 0; i < count; ++i) {
		/* add handler for handle[i] */
		ret =
		    ddi_intr_add_handler(htable[i], EMLXS_SLI_MSI_INTR,
		    (char *)hba, (char *)((unsigned long)i));

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "MSI: ddi_intr_add_handler(%d) failed. "
			    "handle=%p ret=%d",
			    i, &htable[i], ret);

			/* Process the remaining interrupt handlers */
			while (i) {
				/* Decrement i */
				i--;

				/* Remove the handler */
				ret = ddi_intr_remove_handler(htable[i]);

			}

			return (DDI_FAILURE);
		}
	}

	/* Enable the interrupts */
	if (intr_cap[0] & DDI_INTR_FLAG_BLOCK) {
		ret = ddi_intr_block_enable(htable, count);

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: ddi_intr_block_enable(%d) failed. ret=%d",
			    count, ret);

			for (i = 0; i < count; ++i) {
				ret = ddi_intr_enable(htable[i]);

				if (ret != DDI_SUCCESS) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_debug_msg,
					    "MSI: ddi_intr_enable(%d) failed. "
					    "ret=%d",
					    i, ret);
				}
			}
		}
	} else {
		for (i = 0; i < count; ++i) {
			ret = ddi_intr_enable(htable[i]);

			if (ret != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_init_debug_msg,
				    "MSI: ddi_intr_enable(%d) failed. ret=%d",
				    i, ret);
			}
		}
	}


	/* Set flag to indicate support */
	hba->intr_flags |= EMLXS_MSI_ADDED;

	return (DDI_SUCCESS);

} /* emlxs_msi_add() */



/* EMLXS_INTR_REMOVE */
int32_t
emlxs_msi_remove(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t count;
	int32_t i;
	ddi_intr_handle_t *htable;
	int32_t *intr_cap;
	int32_t ret;

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		return (emlxs_intx_remove(hba));
	}

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	 *    "MSI: msi_remove called. flags=%x",
	 *    hba->intr_flags);
	 */

	/* Check if interrupts have already been removed */
	if (!(hba->intr_flags & EMLXS_MSI_ADDED)) {
		return (DDI_SUCCESS);
	}
	hba->intr_flags &= ~EMLXS_MSI_ADDED;

	/* Disable all adapter interrupts */
	EMLXS_SLI_DISABLE_INTR(hba, 0);

	/* Get handle table parameters */
	htable = hba->intr_htable;
	count = hba->intr_count;
	intr_cap = hba->intr_cap;

	/* Disable the interrupts */
	if (intr_cap[0] & DDI_INTR_FLAG_BLOCK) {
		ret = ddi_intr_block_disable(htable, count);

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: ddi_intr_block_disable(%d) failed. ret=%d",
			    count, ret);

			for (i = 0; i < count; i++) {
				ret = ddi_intr_disable(htable[i]);

				if (ret != DDI_SUCCESS) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_debug_msg,
					    "MSI: ddi_intr_disable(%d) failed. "
					    "ret=%d",
					    i, ret);
				}
			}
		}
	} else {
		for (i = 0; i < count; i++) {
			ret = ddi_intr_disable(htable[i]);

			if (ret != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_init_debug_msg,
				    "MSI: ddi_intr_disable(%d) failed. ret=%d",
				    i, ret);
			}
		}
	}

	/* Process the interrupt handlers */
	for (i = 0; i < count; i++) {
		/* Remove the handler */
		ret = ddi_intr_remove_handler(htable[i]);


	}

	return (DDI_SUCCESS);

} /* emlxs_msi_remove() */

#endif /* MSI_SUPPORT */


/* EMLXS_INTR_INIT */
/* ARGSUSED */
int32_t
emlxs_intx_init(emlxs_hba_t *hba, uint32_t max)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	int32_t ret;
	uint32_t i;

	/* Check if interrupts have already been initialized */
	if (hba->intr_flags & EMLXS_INTX_INITED) {
		return (DDI_SUCCESS);
	}

	/* Check if adapter is flagged for INTX support */
	if (!(hba->model_info.flags & EMLXS_INTX_SUPPORTED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "INTX: %s does not support INTX.  flags=0x%x",
		    hba->model_info.model, hba->model_info.flags);

		return (DDI_FAILURE);
	}

	/*
	 * Interrupt number '0' is a high-level interrupt. This driver
	 * does not support having its interrupts mapped above scheduler
	 * priority; i.e., we always expect to be able to call general
	 * kernel routines that may invoke the scheduler.
	 */
	if (ddi_intr_hilevel(hba->dip, EMLXS_INUMBER) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "INTX: High-level interrupt not supported.");

		return (DDI_FAILURE);
	}

	/* Get an iblock cookie */
	ret =
	    ddi_get_iblock_cookie(hba->dip, (uint32_t)EMLXS_INUMBER,
	    (ddi_iblock_cookie_t *)&hba->intr_arg);
	if (ret != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "INTX: ddi_get_iblock_cookie failed. ret=%d", ret);

		return (ret);
	}

	hba->intr_flags |= EMLXS_INTX_INITED;

	hba->intr_count = 1;
	/* Adjust number of channels based on intr_count */
	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		hba->chan_count = cfg[CFG_NUM_WQ].current;
	}

	/* Create the interrupt threads */
	for (i = 0; i < hba->chan_count; i++) {
		mutex_init(&hba->chan[i].rsp_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(hba->intr_arg));

		emlxs_thread_create(hba, &hba->chan[i].intr_thread);
	}

	return (DDI_SUCCESS);

} /* emlxs_intx_init() */


/* EMLXS_INTR_UNINIT */
int32_t
emlxs_intx_uninit(emlxs_hba_t *hba)
{
	int32_t ret;
	uint32_t i;

	/* Make sure interrupts have been removed */
	if ((hba->intr_flags & EMLXS_INTX_ADDED)) {
		ret = emlxs_intx_remove(hba);

		if (ret != DDI_SUCCESS) {
			return (ret);
		}
	}

	/* Check if the interrupts are still initialized */
	if (!(hba->intr_flags & EMLXS_INTX_INITED)) {
		return (DDI_SUCCESS);
	}
	hba->intr_flags &= ~EMLXS_INTX_INITED;

	hba->intr_arg = NULL;

	/* Create the interrupt threads */
	for (i = 0; i < hba->chan_count; i++) {
		emlxs_thread_destroy(&hba->chan[i].intr_thread);
		mutex_destroy(&hba->chan[i].rsp_lock);
	}

	return (DDI_SUCCESS);

} /* emlxs_intx_uninit() */


/*
 * This is the legacy method for adding interrupts in Solaris
 * EMLXS_INTR_ADD
 */
int32_t
emlxs_intx_add(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int32_t ret;

	/* Check if interrupts have already been added */
	if (hba->intr_flags & EMLXS_INTX_ADDED) {
		return (DDI_SUCCESS);
	}

	/* Check if interrupts have been initialized */
	if (!(hba->intr_flags & EMLXS_INTX_INITED)) {
		ret = emlxs_intx_init(hba, 0);

		if (ret != DDI_SUCCESS) {
			return (ret);
		}
	}

	/* add intrrupt handler routine */
	ret = ddi_add_intr((void *)hba->dip,
	    (uint_t)EMLXS_INUMBER,
	    (ddi_iblock_cookie_t *)&hba->intr_arg,
	    (ddi_idevice_cookie_t *)0,
	    (uint_t(*)())EMLXS_SLI_INTX_INTR, (caddr_t)hba);

	if (ret != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "INTX: ddi_add_intr failed. ret=%d", ret);

		return (ret);
	}

	hba->intr_flags |= EMLXS_INTX_ADDED;

	return (DDI_SUCCESS);

} /* emlxs_intx_add() */


/* EMLXS_INTR_REMOVE */
int32_t
emlxs_intx_remove(emlxs_hba_t *hba)
{
	/* Check if interrupts have already been removed */
	if (!(hba->intr_flags & EMLXS_INTX_ADDED)) {
		return (DDI_SUCCESS);
	}
	hba->intr_flags &= ~EMLXS_INTX_ADDED;

	/* Diable all adapter interrupts */
	EMLXS_SLI_DISABLE_INTR(hba, 0);

	/* Remove the interrupt */
	(void) ddi_remove_intr((void *)hba->dip, (uint_t)EMLXS_INUMBER,
	    hba->intr_arg);

	return (DDI_SUCCESS);

} /* emlxs_intx_remove() */


extern void
emlxs_process_link_speed(emlxs_hba_t *hba)
{
	emlxs_vpd_t *vpd;
	emlxs_config_t *cfg;
	uint32_t hi;

	/*
	 * This routine modifies the link-speed config parameter entry
	 * based on adapter capabilities
	 */
	vpd = &VPD;
	cfg = &hba->config[CFG_LINK_SPEED];

	(void) strlcpy(cfg->help, "Select link speed. [0=Auto",
	    EMLXS_CFG_HELP_SIZE);
	hi = 0;

	if (vpd->link_speed & LMT_1GB_CAPABLE) {
		(void) strlcat(cfg->help, ", 1=1Gb", EMLXS_CFG_HELP_SIZE);
		hi = 1;
	}

	if (vpd->link_speed & LMT_2GB_CAPABLE) {
		(void) strlcat(cfg->help, ", 2=2Gb", EMLXS_CFG_HELP_SIZE);
		hi = 2;
	}

	if (vpd->link_speed & LMT_4GB_CAPABLE) {
		(void) strlcat(cfg->help, ", 4=4Gb", EMLXS_CFG_HELP_SIZE);
		hi = 4;
	}

	if (vpd->link_speed & LMT_8GB_CAPABLE) {
		(void) strlcat(cfg->help, ", 8=8Gb", EMLXS_CFG_HELP_SIZE);
		hi = 8;
	}

	if (vpd->link_speed & LMT_10GB_CAPABLE) {
		(void) strlcat(cfg->help, ", 10=10Gb", EMLXS_CFG_HELP_SIZE);
		hi = 10;
	}

	if (vpd->link_speed & LMT_16GB_CAPABLE) {
		(void) strlcat(cfg->help, ", 16=16Gb", EMLXS_CFG_HELP_SIZE);
		hi = 16;
	}

	(void) strlcat(cfg->help, "]", EMLXS_CFG_HELP_SIZE);
	cfg->hi = hi;

	/* Now revalidate the current parameter setting */
	cfg->current = emlxs_check_parm(hba, CFG_LINK_SPEED, cfg->current);

	return;

} /* emlxs_process_link_speed() */


/*
 * emlxs_parse_vpd()
 *
 * This routine will parse the VPD data
 */
extern int
emlxs_parse_vpd(emlxs_hba_t *hba, uint8_t *vpd_buf, uint32_t size)
{
	emlxs_port_t *port = &PPORT;
	char tag[3];
	uint8_t lenlo, lenhi;
	uint32_t n;
	uint16_t block_size;
	uint32_t block_index = 0;
	uint8_t sub_size;
	uint32_t sub_index;
	int32_t finished = 0;
	int32_t index = 0;
	char buffer[128];
	emlxs_vpd_t *vpd;

	vpd = &VPD;


	while (!finished && (block_index < size)) {
		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
		 *    "block_index = %x", block_index);
		 */

		switch (vpd_buf[block_index]) {
		case 0x82:
			index = block_index;
			index += 1;
			lenlo = vpd_buf[index];
			index += 1;
			lenhi = vpd_buf[index];
			index += 1;
			block_index = index;

			block_size = ((((uint16_t)lenhi) << 8) + lenlo);
			block_index += block_size;

			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			 *    "block_size = %x", block_size);
			 */

			n = sizeof (buffer);
			bzero(buffer, n);
			bcopy(&vpd_buf[index], buffer,
			    (block_size < (n - 1)) ? block_size : (n - 1));

			(void) strncpy(vpd->id, buffer, (sizeof (vpd->id)-1));
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg, "ID: %s",
			    vpd->id);

			break;

		case 0x90:
			index = block_index;
			index += 1;
			lenlo = vpd_buf[index];
			index += 1;
			lenhi = vpd_buf[index];
			index += 1;
			block_index = index;
			sub_index = index;

			block_size = ((((uint16_t)lenhi) << 8) + lenlo);
			block_index += block_size;

			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			 *    "block_size = %x", block_size);
			 */

			/* Scan for sub-blocks */
			while ((sub_index < block_index) &&
			    (sub_index < size)) {
				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 *    "sub_index = %x", sub_index);
				 */

				index = sub_index;
				tag[0] = vpd_buf[index++];
				tag[1] = vpd_buf[index++];
				tag[2] = 0;
				sub_size = vpd_buf[index++];

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 *    "sub_size = %x", sub_size);
				 */

				sub_index = (index + sub_size);

				n = sizeof (buffer);
				bzero(buffer, n);
				bcopy(&vpd_buf[index], buffer,
				    (sub_size < (n - 1)) ? sub_size : (n - 1));

				/*
				 * Look for Engineering Change (EC)
				 */
				if (strcmp(tag, "EC") == 0) {
					(void) strncpy(vpd->eng_change, buffer,
					    (sizeof (vpd->eng_change)-1));
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "EC: %s",
					    vpd->eng_change);
				}
				/*
				 * Look for Manufacturer (MN)
				 */
				else if (strcmp(tag, "MN") == 0) {
					(void) strncpy(vpd->manufacturer,
					    buffer,
					    (sizeof (vpd->manufacturer)-1));
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "MN: %s",
					    vpd->manufacturer);
				}
				/*
				 * Look for Serial Number (SN)
				 */
				else if (strcmp(tag, "SN") == 0) {
					(void) strncpy(vpd->serial_num, buffer,
					    (sizeof (vpd->serial_num)-1));
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "SN: %s",
					    vpd->serial_num);

					/* Validate the serial number */
					if (strncmp(buffer, "FFFFFFFFFF", 10) ==
					    0 ||
					    strncmp(buffer, "0000000000", 10) ==
					    0) {
						vpd->serial_num[0] = 0;
					}
				}
				/*
				 * Look for Part Number (PN)
				 */
				else if (strcmp(tag, "PN") == 0) {
					(void) strncpy(vpd->part_num, buffer,
					    (sizeof (vpd->part_num)-1));
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "PN: %s",
					    vpd->part_num);
				}
				/*
				 * Look for (V0)
				 */
				else if (strcmp(tag, "V0") == 0) {
					/* Not used */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "V0: %s", buffer);
				}
				/*
				 * Look for model description (V1)
				 */
				else if (strcmp(tag, "V1") == 0) {
					(void) strncpy(vpd->model_desc, buffer,
					    (sizeof (vpd->model_desc)-1));
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "Desc: %s",
					    vpd->model_desc);
				}
				/*
				 * Look for model (V2)
				 */
				else if (strcmp(tag, "V2") == 0) {
					(void) strncpy(vpd->model, buffer,
					    (sizeof (vpd->model)-1));
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "Model: %s",
					    vpd->model);
				}
				/*
				 * Look for program type (V3)
				 */

				else if (strcmp(tag, "V3") == 0) {
					(void) strncpy(vpd->prog_types,
					    buffer,
					    (sizeof (vpd->prog_types)-1));
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "Prog Types: %s",
					    vpd->prog_types);
				}
				/*
				 * Look for port number (V4)
				 */
				else if (strcmp(tag, "V4") == 0) {
					(void) strncpy(vpd->port_num, buffer,
					    (sizeof (vpd->port_num)-1));
					vpd->port_index =
					    emlxs_strtol(vpd->port_num, 10);

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "Port: %s",
					    (vpd->port_num[0]) ? vpd->
					    port_num : "not applicable");
				}
				/*
				 * Look for checksum (RV)
				 */
				else if (strcmp(tag, "RV") == 0) {
					/* Not used */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "Checksum: 0x%x",
					    buffer[0]);
				}

				else {
					/* Generic */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg, "Tag: %s: %s",
					    tag, buffer);
				}
			}

			break;

		case 0x78:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg, "End Tag.");
			finished = 1;
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			    "Unknown block: %x %x %x %x %x %x %x %x",
			    vpd_buf[index], vpd_buf[index + 1],
			    vpd_buf[index + 2], vpd_buf[index + 3],
			    vpd_buf[index + 4], vpd_buf[index + 5],
			    vpd_buf[index + 6], vpd_buf[index + 7]);
			return (0);
		}
	}

	return (1);

} /* emlxs_parse_vpd */


/*
 * emlxs_parse_fcoe()
 *
 * This routine will parse the VPD data
 */
extern int
emlxs_parse_fcoe(emlxs_hba_t *hba, uint8_t *fcoep, uint32_t size)
{
	emlxs_port_t *port = &PPORT;
	tlv_fcoe_t *fcoelist;
	tlv_fcfconnectlist_t *fcflist;
	int i;
	uint32_t flags;
	uint32_t entry_count;
	char FabricName[32];
	char SwitchName[32];

	/* Validate the config region 23 signature */
	if ((*fcoep != 'R') || (*(fcoep+1) != 'G') ||
	    (*(fcoep+2) != '2') || (*(fcoep+3) != '3')) {
		return (0);
	}

	/* Search the config region 23, for FCOE Parameters record */
	i = 4;
	while ((i < size) && (*(fcoep+i) != 0xA0) && (*(fcoep+i) != 0xff)) {
		i += fcoep[i+1] * sizeof (uint32_t) + 2;
	}

	if (*(fcoep+i) == 0xA0) {
		fcoelist = (tlv_fcoe_t *)(fcoep+i);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
		    "Found FCOE Params (A0):%d  x%x",
		    fcoelist->length, fcoelist->fip_flags);
		bcopy((uint8_t *)fcoelist, (uint8_t *)&hba->sli.sli4.cfgFCOE,
		    sizeof (tlv_fcoe_t));
	}


	/* Search the config region 23, for FCF record */
	i = 4;
	while ((i < size) && (*(fcoep+i) != 0xA1) && (*(fcoep+i) != 0xff)) {
		i += fcoep[i+1] * sizeof (uint32_t) + 2;
	}

	if (*(fcoep+i) == 0xA1) {
		fcflist = (tlv_fcfconnectlist_t *)(fcoep+i);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
		    "Found FCF ConnectList (A1):%d", fcflist->length);

		bcopy((uint8_t *)fcflist, (uint8_t *)&hba->sli.sli4.cfgFCF,
		    sizeof (tlv_fcfconnectlist_t));

		/* Display the list */
		entry_count = (hba->sli.sli4.cfgFCF.length *
		    sizeof (uint32_t)) / sizeof (tlv_fcfconnectentry_t);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
		    "FCF List: %d entries", entry_count);

		for (i = 0; i < entry_count; i++) {
			flags = *(uint32_t *)&hba->sli.sli4.cfgFCF.entry[i];
			(void) emlxs_wwn_xlate(FabricName, sizeof (FabricName),
			    hba->sli.sli4.cfgFCF.entry[i].FabricName);
			(void) emlxs_wwn_xlate(SwitchName, sizeof (SwitchName),
			    hba->sli.sli4.cfgFCF.entry[i].SwitchName);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			    "FCF List:%02d %08x %s %s",
			    i, flags, FabricName, SwitchName);
		}
	}

	return (1);

} /* emlxs_parse_fcoe */


extern void
emlxs_decode_firmware_rev(emlxs_hba_t *hba, emlxs_vpd_t *vpd)
{
	if (vpd->rBit) {
		switch (hba->sli_mode) {
		case EMLXS_HBA_SLI4_MODE:
			(void) strncpy(vpd->fw_version, vpd->sli4FwName,
			    (sizeof (vpd->fw_version)-1));
			(void) strncpy(vpd->fw_label, vpd->sli4FwLabel,
			    (sizeof (vpd->fw_label)-1));
			break;
		case EMLXS_HBA_SLI3_MODE:
			(void) strncpy(vpd->fw_version, vpd->sli3FwName,
			    (sizeof (vpd->fw_version)-1));
			(void) strncpy(vpd->fw_label, vpd->sli3FwLabel,
			    (sizeof (vpd->fw_label)-1));
			break;
		case EMLXS_HBA_SLI2_MODE:
			(void) strncpy(vpd->fw_version, vpd->sli2FwName,
			    (sizeof (vpd->fw_version)-1));
			(void) strncpy(vpd->fw_label, vpd->sli2FwLabel,
			    (sizeof (vpd->fw_label)-1));
			break;
		case EMLXS_HBA_SLI1_MODE:
			(void) strncpy(vpd->fw_version, vpd->sli1FwName,
			    (sizeof (vpd->fw_version)-1));
			(void) strncpy(vpd->fw_label, vpd->sli1FwLabel,
			    (sizeof (vpd->fw_label)-1));
			break;
		default:
			(void) strncpy(vpd->fw_version, "unknown",
			    (sizeof (vpd->fw_version)-1));
			(void) strncpy(vpd->fw_label, vpd->fw_version,
			    (sizeof (vpd->fw_label)-1));
		}
	} else {
		emlxs_decode_version(vpd->smFwRev, vpd->fw_version,
		    sizeof (vpd->fw_version));
		(void) strncpy(vpd->fw_label, vpd->fw_version,
		    (sizeof (vpd->fw_label)-1));
	}

	return;

} /* emlxs_decode_firmware_rev() */



extern void
emlxs_decode_version(uint32_t version, char *buffer, size_t len)
{
	uint32_t b1, b2, b3, b4;
	char c;

	b1 = (version & 0x0000f000) >> 12;
	b2 = (version & 0x00000f00) >> 8;
	b3 = (version & 0x000000c0) >> 6;
	b4 = (version & 0x00000030) >> 4;

	if (b1 == 0 && b2 == 0) {
		(void) snprintf(buffer, len, "none");
		return;
	}

	c = 0;
	switch (b4) {
	case 0:
		c = 'n';
		break;
	case 1:
		c = 'a';
		break;
	case 2:
		c = 'b';
		break;
	case 3:
		if ((version & 0x0000000f)) {
			c = 'x';
		}
		break;

	}
	b4 = (version & 0x0000000f);

	if (c == 0) {
		(void) snprintf(buffer, len, "%d.%d%d", b1, b2, b3);
	} else {
		(void) snprintf(buffer, len, "%d.%d%d%c%d", b1, b2, b3, c, b4);
	}

	return;

} /* emlxs_decode_version() */


extern void
emlxs_decode_label(char *label, char *buffer, int bige, size_t len)
{
	uint32_t i;
	char name[16];

	bzero(name, sizeof (name));
	bcopy(label, name, MIN(sizeof (name), len));
	/* bige is TRUE if the data format is big endian */

	if (bige) {
		/* Data format big Endian */
		LE_SWAP32_BUFFER((uint8_t *)name, sizeof (name));

		for (i = 0; i < sizeof (name); i++) {
			if (name[i] == 0x20) {
				name[i] = 0;
			}
		}
	} else {
		/* Data format little Endian */
		BE_SWAP32_BUFFER((uint8_t *)name, sizeof (name));

		for (i = 0; i < sizeof (name); i++) {
			if (name[i] == 0x20) {
				name[i] = 0;
			}
		}
	}

	(void) strlcpy(buffer, name, len);

	return;

} /* emlxs_decode_label() */


extern uint32_t
emlxs_strtol(char *str, uint32_t base)
{
	uint32_t value = 0;
	char *ptr;
	uint32_t factor = 1;
	uint32_t digits;

	if (*str == 0) {
		return (0);
	}

	if (base != 10 && base != 16) {
		return (0);
	}

	/* Get max digits of value */
	digits = (base == 10) ? 9 : 8;

	/* Position pointer to end of string */
	ptr = str + strlen(str);

	/* Process string backwards */
	while ((ptr-- > str) && digits) {
		/* check for base 10 numbers */
		if (*ptr >= '0' && *ptr <= '9') {
			value += ((uint32_t)(*ptr - '0')) * factor;
			factor *= base;
			digits--;
		} else if (base == 16) {
			/* Check for base 16 numbers */
			if (*ptr >= 'a' && *ptr <= 'f') {
				value +=
				    ((uint32_t)(*ptr - 'a') + 10) * factor;
				factor *= base;
				digits--;
			} else if (*ptr >= 'A' && *ptr <= 'F') {
				value +=
				    ((uint32_t)(*ptr - 'A') + 10) * factor;
				factor *= base;
				digits--;
			} else if (factor > 1) {
				break;
			}
		} else if (factor > 1) {
			break;
		}
	}

	return (value);

} /* emlxs_strtol() */


extern uint64_t
emlxs_strtoll(char *str, uint32_t base)
{
	uint64_t value = 0;
	char *ptr;
	uint32_t factor = 1;
	uint32_t digits;

	if (*str == 0) {
		return (0);
	}

	if (base != 10 && base != 16) {
		return (0);
	}

	/* Get max digits of value */
	digits = (base == 10) ? 19 : 16;

	/* Position pointer to end of string */
	ptr = str + strlen(str);

	/* Process string backwards */
	while ((ptr-- > str) && digits) {
		/* check for base 10 numbers */
		if (*ptr >= '0' && *ptr <= '9') {
			value += ((uint32_t)(*ptr - '0')) * factor;
			factor *= base;
			digits--;
		} else if (base == 16) {
			/* Check for base 16 numbers */
			if (*ptr >= 'a' && *ptr <= 'f') {
				value +=
				    ((uint32_t)(*ptr - 'a') + 10) * factor;
				factor *= base;
				digits--;
			} else if (*ptr >= 'A' && *ptr <= 'F') {
				value +=
				    ((uint32_t)(*ptr - 'A') + 10) * factor;
				factor *= base;
				digits--;
			} else if (factor > 1) {
				break;
			}
		} else if (factor > 1) {
			break;
		}
	}

	return (value);

} /* emlxs_strtoll() */

extern void
emlxs_parse_prog_types(emlxs_hba_t *hba, char *prog_types)
{
	emlxs_port_t *port = &PPORT;
	uint32_t i;
	char *ptr;
	emlxs_model_t *model;
	char types_buffer[256];
	char *types;

	bcopy(prog_types, types_buffer, 256);
	types = types_buffer;

	model = &hba->model_info;

	while (*types) {
		if (strncmp(types, "T2:", 3) == 0) {
			bzero(model->pt_2, sizeof (model->pt_2));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_2[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "T2[%d]: 0x%x", i-1, model->pt_2[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}

		} else if (strncmp(types, "T3:", 3) == 0) {
			bzero(model->pt_3, sizeof (model->pt_3));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_3[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "T3[%d]: 0x%x", i-1, model->pt_3[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "T6:", 3) == 0) {
			bzero(model->pt_6, sizeof (model->pt_6));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_6[i++] =
				    (uint8_t)emlxs_strtol(types, 16);
				model->pt_6[i] = 0;

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "T6[%d]: 0x%x", i-1, model->pt_6[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "T7:", 3) == 0) {
			bzero(model->pt_7, sizeof (model->pt_7));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_7[i++] =
				    (uint8_t)emlxs_strtol(types, 16);
				model->pt_7[i] = 0;

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "T7[%d]: 0x%x", i-1, model->pt_7[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "TA:", 3) == 0) {
			bzero(model->pt_A, sizeof (model->pt_A));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_A[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "TA[%d]: 0x%x", i-1, model->pt_A[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "TB:", 3) == 0) {
			bzero(model->pt_B, sizeof (model->pt_B));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_B[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "TB[%d]: 0x%x", i-1, model->pt_B[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "TFF:", 4) == 0) {
			bzero(model->pt_FF, sizeof (model->pt_FF));
			types += 4;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_FF[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "TF[%d]: 0x%x", i-1, model->pt_FF[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "T20:", 4) == 0) {
			bzero(model->pt_20, sizeof (model->pt_20));
			types += 4;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_20[i++] =
				    (uint8_t)emlxs_strtol(types, 16);
				model->pt_20[i] = 0;

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "T20[%d]: 0x%x", i-1, model->pt_20[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			    "Unknown prog type string = %s", types);
			break;
		}
	}

	return;

} /* emlxs_parse_prog_types() */


extern void
emlxs_build_prog_types(emlxs_hba_t *hba, emlxs_vpd_t *vpd)
{
	uint32_t i;
	uint32_t found = 0;
	char buffer[256];

	bzero(vpd->prog_types, sizeof (vpd->prog_types));

	/* Rebuild the prog type string */
	if (hba->model_info.pt_2[0]) {
		(void) strlcat(vpd->prog_types, "T2:",
		    sizeof (vpd->prog_types));
		found = 1;

		i = 0;
		while ((i < 8) && (hba->model_info.pt_2[i])) {
			(void) snprintf(buffer, sizeof (buffer), "%X,",
			    hba->model_info.pt_2[i]);
			(void) strlcat(vpd->prog_types, buffer,
			    sizeof (vpd->prog_types));
			i++;
		}
	}

	if (hba->model_info.pt_3[0]) {
		(void) strlcat(vpd->prog_types, "T3:",
		    sizeof (vpd->prog_types));
		found = 1;

		i = 0;
		while ((i < 8) && (hba->model_info.pt_3[i])) {
			(void) snprintf(buffer, sizeof (buffer), "%X,",
			    hba->model_info.pt_3[i]);
			(void) strlcat(vpd->prog_types, buffer,
			    sizeof (vpd->prog_types));
			i++;

		}
	}

	if (hba->model_info.pt_6[0]) {
		(void) strlcat(vpd->prog_types, "T6:",
		    sizeof (vpd->prog_types));
		found = 1;

		i = 0;
		while ((i < 8) && (hba->model_info.pt_6[i])) {
			(void) snprintf(buffer, sizeof (buffer), "%X,",
			    hba->model_info.pt_6[i]);
			(void) strlcat(vpd->prog_types, buffer,
			    sizeof (vpd->prog_types));
			i++;
		}
	}

	if (hba->model_info.pt_7[0]) {
		(void) strlcat(vpd->prog_types, "T7:",
		    sizeof (vpd->prog_types));
		found = 1;

		i = 0;
		while ((i < 8) && (hba->model_info.pt_7[i])) {
			(void) snprintf(buffer, sizeof (buffer), "%X,",
			    hba->model_info.pt_7[i]);
			(void) strlcat(vpd->prog_types, buffer,
			    sizeof (vpd->prog_types));
			i++;
		}
	}

	if (hba->model_info.pt_A[0]) {
		(void) strlcat(vpd->prog_types, "TA:",
		    sizeof (vpd->prog_types));
		found = 1;

		i = 0;
		while ((i < 8) && (hba->model_info.pt_A[i])) {
			(void) snprintf(buffer, sizeof (buffer), "%X,",
			    hba->model_info.pt_A[i]);
			(void) strlcat(vpd->prog_types, buffer,
			    sizeof (vpd->prog_types));
			i++;
		}
	}


	if (hba->model_info.pt_B[0]) {
		(void) strlcat(vpd->prog_types, "TB:",
		    sizeof (vpd->prog_types));
		found = 1;

		i = 0;
		while ((i < 8) && (hba->model_info.pt_B[i])) {
			(void) snprintf(buffer, sizeof (buffer), "%X,",
			    hba->model_info.pt_B[i]);
			(void) strlcat(vpd->prog_types, buffer,
			    sizeof (vpd->prog_types));
			i++;
		}
	}

	if (hba->model_info.pt_20[0]) {
		(void) strlcat(vpd->prog_types, "T20:",
		    sizeof (vpd->prog_types));
		found = 1;

		i = 0;
		while ((i < 8) && (hba->model_info.pt_20[i])) {
			(void) snprintf(buffer, sizeof (buffer), "%X,",
			    hba->model_info.pt_20[i]);
			(void) strlcat(vpd->prog_types, buffer,
			    sizeof (vpd->prog_types));
			i++;
		}
	}

	if (hba->model_info.pt_FF[0]) {
		(void) strlcat(vpd->prog_types, "TFF:",
		    sizeof (vpd->prog_types));
		found = 1;

		i = 0;
		while ((i < 8) && (hba->model_info.pt_FF[i])) {
			(void) snprintf(buffer, sizeof (buffer), "%X,",
			    hba->model_info.pt_FF[i]);
			(void) strlcat(vpd->prog_types, buffer,
			    sizeof (vpd->prog_types));
			i++;
		}
	}

	if (found) {
		/* Terminate at the last comma in string */
		vpd->prog_types[(strlen(vpd->prog_types) - 1)] = 0;
	}

	return;

} /* emlxs_build_prog_types() */


extern uint32_t
emlxs_init_adapter_info(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t pci_id;
	uint32_t cache_line;
	uint32_t channels;
	uint16_t device_id;
	uint16_t ssdid;
	uint32_t i;
	uint32_t found = 0;
	int32_t *prop;
	uint32_t num_prop;

	if (hba->bus_type == SBUS_FC) {
		if (hba->pci_acc_handle == NULL) {
			bcopy(&emlxs_sbus_model[0], &hba->model_info,
			    sizeof (emlxs_model_t));

			hba->model_info.device_id = 0;

			return (0);
		}

		/* Read the PCI device id */
		pci_id =
		    ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_VENDOR_ID_REGISTER));
		device_id = (uint16_t)(pci_id >> 16);

		/* Find matching adapter model */
		for (i = 1; i < EMLXS_SBUS_MODEL_COUNT; i++) {
			if (emlxs_sbus_model[i].device_id == device_id) {
				bcopy(&emlxs_sbus_model[i], &hba->model_info,
				    sizeof (emlxs_model_t));
				found = 1;
				break;
			}
		}

		/* If not found then use the unknown model */
		if (!found) {
			bcopy(&emlxs_sbus_model[0], &hba->model_info,
			    sizeof (emlxs_model_t));

			hba->model_info.device_id = device_id;

			return (0);
		}
	} else {	/* PCI model */

		if (hba->pci_acc_handle == NULL) {
			bcopy(&emlxs_pci_model[0], &hba->model_info,
			    sizeof (emlxs_model_t));

			hba->model_info.device_id = 0;

			return (0);
		}

		/* Read the PCI device id */
		device_id =
		    ddi_get16(hba->pci_acc_handle,
		    (uint16_t *)(hba->pci_addr + PCI_DEVICE_ID_REGISTER));

		/* Read the PCI Subsystem id */
		ssdid =
		    ddi_get16(hba->pci_acc_handle,
		    (uint16_t *)(hba->pci_addr + PCI_SSDID_REGISTER));

		if (ssdid == 0 || ssdid == 0xffff) {
			ssdid = device_id;
		}

		/* Read the Cache Line reg */
		cache_line =
		    ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_CACHE_LINE_REGISTER));

		/* Check for the multifunction bit being set */
		if ((cache_line & 0x00ff0000) == 0x00800000) {
			channels = EMLXS_MULTI_CHANNEL;
		} else {
			channels = EMLXS_SINGLE_CHANNEL;
		}

		/* If device ids are unique, then use them for search */
		if (device_id != ssdid) {
			/*
			 * Find matching adapter model using
			 * device_id, ssdid, and channels
			 */
			for (i = 1; i < emlxs_pci_model_count; i++) {
				if (emlxs_pci_model[i].device_id ==
				    device_id &&
				    emlxs_pci_model[i].ssdid == ssdid &&
				    emlxs_pci_model[i].channels ==
				    channels) {
					bcopy(&emlxs_pci_model[i],
					    &hba->model_info,
					    sizeof (emlxs_model_t));
					found = 1;
					break;
				}
			}
		}

		/* If adapter not found, try again */
		if (!found) {
			/*
			 * Find matching adapter model using
			 * device_id and channels
			 */
			for (i = 1; i < emlxs_pci_model_count; i++) {
				if (emlxs_pci_model[i].device_id == device_id &&
				    emlxs_pci_model[i].channels == channels) {
					bcopy(&emlxs_pci_model[i],
					    &hba->model_info,
					    sizeof (emlxs_model_t));
					found = 1;
					break;
				}
			}
		}

		/* If adapter not found, try one last time */
		if (!found) {
			/*
			 * Find matching adapter model using
			 * device_id only
			 */
			for (i = 1; i < emlxs_pci_model_count; i++) {
				if (emlxs_pci_model[i].device_id == device_id) {
					bcopy(&emlxs_pci_model[i],
					    &hba->model_info,
					    sizeof (emlxs_model_t));
					found = 1;
					break;
				}
			}
		}

		/* If not found, set adapter to unknown */
		if (!found) {
			bcopy(&emlxs_pci_model[0], &hba->model_info,
			    sizeof (emlxs_model_t));

			hba->model_info.device_id = device_id;
			hba->model_info.ssdid = ssdid;

			return (0);
		}

#ifndef SATURN_MSI_SUPPORT
		/*
		 * This will disable MSI support for Saturn adapter's
		 * due to a PCI bus issue
		 */
		if (hba->model_info.chip == EMLXS_SATURN_CHIP) {
			hba->model_info.flags &=
			    ~(EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED);
		}
#endif /* !SATURN_MSI_SUPPORT */

		/* Scan the PCI capabilities */
		emlxs_pci_cap_offsets(hba);

#ifdef MSI_SUPPORT
		/* Verify MSI support */
		if ((hba->model_info.flags & EMLXS_MSI_SUPPORTED) &&
		    !hba->pci_cap_offset[PCI_CAP_ID_MSI]) {
			hba->model_info.flags &= ~EMLXS_MSI_SUPPORTED;
		}

		/* Verify MSI-X support */
		if ((hba->model_info.flags & EMLXS_MSIX_SUPPORTED) &&
		    !hba->pci_cap_offset[PCI_CAP_ID_MSI_X]) {
			hba->model_info.flags &= ~EMLXS_MSIX_SUPPORTED;
		}
#endif /* MSI_SUPPORT */

		/* Set the sli_intf value */
		if (hba->pci_cap_offset[PCI_CAP_ID_VS]) {
			/* Save the SLI_INTF register, this contains */
			/* information about the BAR register layout */
			/* and other HBA information. */
			hba->sli_intf =
			    ddi_get32(hba->pci_acc_handle,
			    (uint32_t *)(hba->pci_addr +
			    hba->pci_cap_offset[PCI_CAP_ID_VS] +
			    PCI_VS_SLI_INTF_OFFSET));

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_init_debug_msg, "PCI_CAP_ID_VS: "
			    "SLI_INTF:%08x",
			    hba->sli_intf);

			/* Check validity */
			if ((hba->sli_intf & SLI_INTF_VALID_MASK) !=
			    SLI_INTF_VALID) {
				hba->sli_intf = 0;
			}
		}
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hba->dip, 0,
	    "reg", &prop, &num_prop) == DDI_PROP_SUCCESS) {
		/* Parse the property for PCI function, device and bus no. */
		hba->pci_function_number =
		    (uint8_t)((prop[0] & 0x00000700) >> 8);
		hba->pci_device_number =
		    (uint8_t)((prop[0] & 0x0000f800) >> 11);
		hba->pci_bus_number = (uint8_t)((prop[0] & 0x00ff0000) >> 16);
		ddi_prop_free((void *)prop);
	}

	switch (hba->sli_intf & SLI_INTF_SLI_REV_MASK) {
	case SLI_INTF_SLI_REV_NONE: /* Legacy support */
		if (hba->model_info.sli_mask & EMLXS_SLI4_MASK) {
			hba->sli_api = emlxs_sli4_api;
		} else {
			hba->sli_api = emlxs_sli3_api;
		}
		break;

	case SLI_INTF_SLI_REV_3:
		if (!(hba->model_info.sli_mask & EMLXS_SLI3_MASK)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_init_failed_msg,
			    "Adapter does not support SLI3 interface. "
			    "sli_intf=%08x sli_mask=%08x",
			    hba->sli_intf, hba->model_info.sli_mask);
			return (0);
		}
		hba->sli_api = emlxs_sli3_api;
		break;

	case SLI_INTF_SLI_REV_4:
		if (!(hba->model_info.sli_mask & EMLXS_SLI4_MASK)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_init_failed_msg,
			    "Adapter does not support SLI4 interface. "
			    "sli_intf=%08x sli_mask=%08x",
			    hba->sli_intf, hba->model_info.sli_mask);
			return (0);
		}
		hba->sli_api = emlxs_sli4_api;
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_init_failed_msg,
		    "Invalid SLI interface specified. "
		    "sli_intf=%08x sli_mask=%08x",
		    hba->sli_intf, hba->model_info.sli_mask);
		return (0);
	}

#ifdef FMA_SUPPORT
	if (emlxs_fm_check_acc_handle(hba, hba->pci_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (0);
	}
#endif  /* FMA_SUPPORT */

	return (1);

} /* emlxs_init_adapter_info()  */


/* ARGSUSED */
static void
emlxs_handle_async_event(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;
	uint32_t *w;
	int i, j;

	iocb = &iocbq->iocb;

	if (iocb->ULPSTATUS != 0) {
		return;
	}

	switch (iocb->un.astat.EventCode) {
	case 0x0100:	/* Temp Warning */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_temp_warning_msg,
		    "Adapter is very hot (%d °C). Take corrective action.",
		    iocb->ULPCONTEXT);

		hba->temperature = iocb->ULPCONTEXT;
		emlxs_log_temp_event(port, 0x02, iocb->ULPCONTEXT);


		break;


	case 0x0101:	/* Temp Safe */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_temp_msg,
		    "Adapter temperature now safe (%d °C).",
		    iocb->ULPCONTEXT);

		hba->temperature = iocb->ULPCONTEXT;
		emlxs_log_temp_event(port, 0x03, iocb->ULPCONTEXT);

		break;

	default:

		w = (uint32_t *)iocb;
		for (i = 0, j = 0; i < 8; i++, j += 2) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_async_msg,
			    "(Word[%d]=%x Word[%d]=%x)", j, w[j], j + 1,
			    w[j + 1]);
		}

		emlxs_log_async_event(port, iocb);
	}

	return;

} /* emlxs_handle_async_event() */


/* ARGSUSED */
extern void
emlxs_reset_link_thread(emlxs_hba_t *hba, void *arg1, void *arg2)
{
	emlxs_port_t *port = &PPORT;

	/* Attempt a link reset to recover */
	(void) emlxs_reset(port, FC_FCA_LINK_RESET);

	return;

} /* emlxs_reset_link_thread() */


/* ARGSUSED */
extern void
emlxs_restart_thread(emlxs_hba_t *hba, void *arg1, void *arg2)
{
	emlxs_port_t *port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_trans_msg, "Restarting...");

	/* Attempt a full hardware reset to recover */
	if (emlxs_reset(port, FC_FCA_RESET) != FC_SUCCESS) {
		EMLXS_STATE_CHANGE(hba, FC_ERROR);

		emlxs_shutdown_thread(hba, arg1, arg2);
	}

	return;

} /* emlxs_restart_thread() */


/* ARGSUSED */
extern void
emlxs_shutdown_thread(emlxs_hba_t *hba, void *arg1, void *arg2)
{
	emlxs_port_t *port = &PPORT;

	mutex_enter(&EMLXS_PORT_LOCK);
	if (hba->flag & FC_SHUTDOWN) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	hba->flag |= FC_SHUTDOWN;
	mutex_exit(&EMLXS_PORT_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_trans_msg,
	    "Shutting down...");

	/* Take adapter offline and leave it there */
	(void) emlxs_offline(hba, 0);

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		/*
		 * Dump is not defined for SLI4, so just
		 * reset the HBA for now.
		 */
		EMLXS_SLI_HBA_RESET(hba, 1, 1, 0);

	} else {
		if (hba->flag & FC_OVERTEMP_EVENT) {
			emlxs_log_temp_event(port, 0x01,
			    hba->temperature);
		} else {
			emlxs_log_dump_event(port, NULL, 0);
		}
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_shutdown_msg, "Reboot required.");

	return;

} /* emlxs_shutdown_thread() */


/* ARGSUSED */
extern void
emlxs_proc_channel(emlxs_hba_t *hba, CHANNEL *cp, void *arg2)
{
	IOCBQ *iocbq;
	IOCBQ *rsp_head;

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	 * "proc_channel: channel=%d", cp->channelno);
	 */

	mutex_enter(&cp->rsp_lock);

	while ((rsp_head = cp->rsp_head) != NULL) {
		cp->rsp_head = NULL;
		cp->rsp_tail = NULL;

		mutex_exit(&cp->rsp_lock);

		while ((iocbq = rsp_head) != NULL) {
			rsp_head = (IOCBQ *) iocbq->next;

			emlxs_proc_channel_event(hba, cp, iocbq);
		}

		mutex_enter(&cp->rsp_lock);
	}

	mutex_exit(&cp->rsp_lock);

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, 0);

	return;

} /* emlxs_proc_channel() */


/*
 * Called from SLI ring event routines to process a rsp ring IOCB.
 */
void
emlxs_proc_channel_event(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	char buffer[MAX_MSG_DATA + 1];
	IOCB *iocb;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt;

	iocb = &iocbq->iocb;

#ifdef DEBUG_CMPL_IOCB
	emlxs_data_dump(port, "CMPL_IOCB", (uint32_t *)iocb, 8, 0);
#endif

	sbp = (emlxs_buf_t *)iocbq->sbp;
	if (sbp) {
		if (!(sbp->pkt_flags & PACKET_VALID) ||
		    (sbp->pkt_flags & (PACKET_ULP_OWNED |
		    PACKET_IN_COMPLETION))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_stale_msg,
			    "Duplicate: iocb=%p cmd=%x status=%x "
			    "error=%x iotag=%d context=%x info=%x",
			    iocbq, (uint8_t)iocbq->iocb.ULPCOMMAND,
			    iocbq->iocb.ULPSTATUS,
			    (uint8_t)iocbq->iocb.un.grsp.perr.statLocalError,
			    (uint16_t)iocbq->iocb.ULPIOTAG,
			    (uint16_t)iocbq->iocb.ULPCONTEXT,
			    (uint8_t)iocbq->iocb.ULPRSVDBYTE);

			/* Drop this IO immediately */
			return;
		}

		if (sbp->pkt_flags & PACKET_IN_TIMEOUT) {
			/*
			 * If the packet is tagged for timeout then set the
			 * return codes appropriately
			 */
			iocb->ULPSTATUS = IOSTAT_LOCAL_REJECT;
			iocb->un.grsp.perr.statLocalError = IOERR_ABORT_TIMEOUT;
		} else if (sbp->pkt_flags &
		    (PACKET_IN_FLUSH | PACKET_IN_ABORT)) {
			/*
			 * If the packet is tagged for abort then set the
			 * return codes appropriately
			 */
			iocb->ULPSTATUS = IOSTAT_LOCAL_REJECT;
			iocb->un.grsp.perr.statLocalError =
			    IOERR_ABORT_REQUESTED;
		}
	}

	/* Check for IOCB local error */
	if (iocb->ULPSTATUS == IOSTAT_LOCAL_REJECT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_event_msg,
		    "Local reject. ringno=%d iocb=%p cmd=%x "
		    "iotag=%d context=%x info=%x error=%x",
		    cp->channelno, iocb, (uint8_t)iocb->ULPCOMMAND,
		    (uint16_t)iocb->ULPIOTAG, (uint16_t)iocb->ULPCONTEXT,
		    (uint8_t)iocb->ULPRSVDBYTE,
		    (uint8_t)iocb->un.grsp.perr.statLocalError);
	}

	switch (iocb->ULPCOMMAND) {
		/* RING 0 FCP commands */
	case CMD_FCP_ICMND_CR:
	case CMD_FCP_ICMND_CX:
	case CMD_FCP_IREAD_CR:
	case CMD_FCP_IREAD_CX:
	case CMD_FCP_IWRITE_CR:
	case CMD_FCP_IWRITE_CX:
	case CMD_FCP_ICMND64_CR:
	case CMD_FCP_ICMND64_CX:
	case CMD_FCP_IREAD64_CR:
	case CMD_FCP_IREAD64_CX:
	case CMD_FCP_IWRITE64_CR:
	case CMD_FCP_IWRITE64_CX:
		emlxs_handle_fcp_event(hba, cp, iocbq);
		break;

#ifdef SFCT_SUPPORT
	case CMD_FCP_TSEND_CX:		/* FCP_TARGET IOCB command */
	case CMD_FCP_TSEND64_CX:	/* FCP_TARGET IOCB command */
	case CMD_FCP_TRECEIVE_CX:	/* FCP_TARGET IOCB command */
	case CMD_FCP_TRECEIVE64_CX:	/* FCP_TARGET IOCB command */
	case CMD_FCP_TRSP_CX:		/* FCP_TARGET IOCB command */
	case CMD_FCP_TRSP64_CX:		/* FCP_TARGET IOCB command */
		if (port->mode == MODE_TARGET) {
			(void) emlxs_fct_handle_fcp_event(hba, cp, iocbq);
		}
		break;
#endif /* SFCT_SUPPORT */

		/* RING 1 IP commands */
	case CMD_XMIT_BCAST_CN:
	case CMD_XMIT_BCAST_CX:
	case CMD_XMIT_BCAST64_CN:
	case CMD_XMIT_BCAST64_CX:
		(void) emlxs_ip_handle_event(hba, cp, iocbq);
		break;

	case CMD_XMIT_SEQUENCE_CX:
	case CMD_XMIT_SEQUENCE_CR:
	case CMD_XMIT_SEQUENCE64_CX:
	case CMD_XMIT_SEQUENCE64_CR:
		switch (iocb->un.rcvseq64.w5.hcsw.Type) {
		case FC_TYPE_IS8802_SNAP:
			(void) emlxs_ip_handle_event(hba, cp, iocbq);
			break;

		case FC_TYPE_FC_SERVICES:
			(void) emlxs_ct_handle_event(hba, cp, iocbq);
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_invalid_msg,
			    "cmd=%x type=%x status=%x iotag=%d context=%x ",
			    iocb->ULPCOMMAND, iocb->un.rcvseq64.w5.hcsw.Type,
			    iocb->ULPSTATUS, iocb->ULPIOTAG,
			    iocb->ULPCONTEXT);
		}
		break;

	case CMD_RCV_SEQUENCE_CX:
	case CMD_RCV_SEQUENCE64_CX:
	case CMD_RCV_SEQ64_CX:
	case CMD_RCV_ELS_REQ_CX:	/* Unsolicited ELS frame  */
	case CMD_RCV_ELS_REQ64_CX:	/* Unsolicited ELS frame  */
	case CMD_RCV_ELS64_CX:		/* Unsolicited ELS frame  */
		if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
			(void) emlxs_handle_rcv_seq(hba, cp, iocbq);
		}
		break;

	case CMD_RCV_SEQ_LIST64_CX:
		(void) emlxs_ip_handle_rcv_seq_list(hba, cp, iocbq);
		break;

	case CMD_CREATE_XRI_CR:
	case CMD_CREATE_XRI_CX:
		(void) emlxs_handle_create_xri(hba, cp, iocbq);
		break;

		/* RING 2 ELS commands */
	case CMD_ELS_REQUEST_CR:
	case CMD_ELS_REQUEST_CX:
	case CMD_XMIT_ELS_RSP_CX:
	case CMD_ELS_REQUEST64_CR:
	case CMD_ELS_REQUEST64_CX:
	case CMD_XMIT_ELS_RSP64_CX:
		(void) emlxs_els_handle_event(hba, cp, iocbq);
		break;

		/* RING 3 CT commands */
	case CMD_GEN_REQUEST64_CR:
	case CMD_GEN_REQUEST64_CX:
		switch (iocb->un.rcvseq64.w5.hcsw.Type) {
#ifdef MENLO_SUPPORT
		case EMLXS_MENLO_TYPE:
			(void) emlxs_menlo_handle_event(hba, cp, iocbq);
			break;
#endif /* MENLO_SUPPORT */

		case FC_TYPE_FC_SERVICES:
			(void) emlxs_ct_handle_event(hba, cp, iocbq);
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_invalid_msg,
			    "cmd=%x type=%x status=%x iotag=%d context=%x ",
			    iocb->ULPCOMMAND, iocb->un.rcvseq64.w5.hcsw.Type,
			    iocb->ULPSTATUS, iocb->ULPIOTAG,
			    iocb->ULPCONTEXT);
		}
		break;

	case CMD_ABORT_XRI_CN:	/* Abort fcp command */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "ABORT_XRI_CN: rpi=%d iotag=%d status=%x parm=%x",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag, iocb->ULPSTATUS,
		    iocb->un.acxri.parm);

#ifdef SFCT_SUPPORT
		if (port->mode == MODE_TARGET) {
			(void) emlxs_fct_handle_abort(hba, cp, iocbq);
		}
#endif /* SFCT_SUPPORT */
		break;

	case CMD_ABORT_XRI_CX:	/* Abort command */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "ABORT_XRI_CX: rpi=%d iotag=%d status=%x parm=%x sbp=%p",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag, iocb->ULPSTATUS,
		    iocb->un.acxri.parm, iocbq->sbp);

#ifdef SFCT_SUPPORT
		if (port->mode == MODE_TARGET) {
			(void) emlxs_fct_handle_abort(hba, cp, iocbq);
		}
#endif /* SFCT_SUPPORT */
		break;

	case CMD_XRI_ABORTED_CX:	/* Handle ABORT condition */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "XRI_ABORTED_CX: rpi=%d iotag=%d status=%x parm=%x",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag, iocb->ULPSTATUS,
		    iocb->un.acxri.parm);

#ifdef SFCT_SUPPORT
		if (port->mode == MODE_TARGET) {
			(void) emlxs_fct_handle_abort(hba, cp, iocbq);
		}
#endif /* SFCT_SUPPORT */
		break;

	case CMD_CLOSE_XRI_CN:	/* Handle CLOSE condition */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "CLOSE_XRI_CN: rpi=%d iotag=%d status=%x parm=%x",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag, iocb->ULPSTATUS,
		    iocb->un.acxri.parm);

#ifdef SFCT_SUPPORT
		if (port->mode == MODE_TARGET) {
			(void) emlxs_fct_handle_abort(hba, cp, iocbq);
		}
#endif /* SFCT_SUPPORT */
		break;

	case CMD_CLOSE_XRI_CX:	/* Handle CLOSE condition */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "CLOSE_XRI_CX: rpi=%d iotag=%d status=%x parm=%x sbp=%p",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag, iocb->ULPSTATUS,
		    iocb->un.acxri.parm, iocbq->sbp);

#ifdef SFCT_SUPPORT
		if (port->mode == MODE_TARGET) {
			(void) emlxs_fct_handle_abort(hba, cp, iocbq);
		}
#endif /* SFCT_SUPPORT */
		break;

	case CMD_ADAPTER_MSG:
		/* Allows debug adapter firmware messages to print on host */
		bzero(buffer, sizeof (buffer));
		bcopy((uint8_t *)iocb, buffer, MAX_MSG_DATA);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_msg, "%s", buffer);

		break;

	case CMD_QUE_RING_LIST64_CN:
	case CMD_QUE_RING_BUF64_CN:
		break;

	case CMD_ASYNC_STATUS:
		emlxs_handle_async_event(hba, cp, iocbq);
		break;

	case CMD_XMIT_BLS_RSP64_CX:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "CMD_XMIT_BLS_RSP64_CX: sbp = %p", sbp);

		/*
		 * The exchange should have been already freed in the wqe_cmpl
		 * so just free up the pkt here.
		 */
		pkt = PRIV2PKT(sbp);
		emlxs_pkt_free(pkt);
		break;

	default:
		if (iocb->ULPCOMMAND == 0) {
			break;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_invalid_msg,
		    "cmd=%x status=%x iotag=%d context=%x", iocb->ULPCOMMAND,
		    iocb->ULPSTATUS, iocb->ULPIOTAG, iocb->ULPCONTEXT);

		break;
	}	/* switch(entry->ULPCOMMAND) */

	return;

} /* emlxs_proc_channel_event() */


extern char *
emlxs_ffstate_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_ffstate_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_ffstate_table[i].code) {
			return (emlxs_ffstate_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "state=0x%x", state);
	return (buffer);

} /* emlxs_ffstate_xlate() */


extern char *
emlxs_ring_xlate(uint32_t ringno)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_ring_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (ringno == emlxs_ring_table[i].code) {
			return (emlxs_ring_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "ring=0x%x", ringno);
	return (buffer);

} /* emlxs_ring_xlate() */


extern char *
emlxs_pci_cap_xlate(uint32_t id)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_pci_cap) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (id == emlxs_pci_cap[i].code) {
			return (emlxs_pci_cap[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "PCI_CAP_ID_%02X", id);
	return (buffer);

} /* emlxs_pci_cap_xlate() */


extern char *
emlxs_pci_ecap_xlate(uint32_t id)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_pci_ecap) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (id == emlxs_pci_ecap[i].code) {
			return (emlxs_pci_ecap[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "PCI_EXT_CAP_ID_%02X", id);
	return (buffer);

} /* emlxs_pci_ecap_xlate() */


extern void
emlxs_pcix_mxr_update(emlxs_hba_t *hba, uint32_t verbose)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbq;
	MAILBOX *mb;
	emlxs_config_t *cfg;
	uint32_t value;

	cfg = &CFG;

xlate:

	switch (cfg[CFG_PCI_MAX_READ].current) {
	case 512:
		value = 0;
		break;

	case 1024:
		value = 1;
		break;

	case 2048:
		value = 2;
		break;

	case 4096:
		value = 3;
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "PCI_MAX_READ: Invalid parameter value. old=%d new=%d",
		    cfg[CFG_PCI_MAX_READ].current, cfg[CFG_PCI_MAX_READ].def);

		cfg[CFG_PCI_MAX_READ].current = cfg[CFG_PCI_MAX_READ].def;
		goto xlate;
	}

	if ((mbq = (MAILBOXQ *) kmem_zalloc((sizeof (MAILBOXQ)),
	    KM_SLEEP)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "PCI_MAX_READ: Unable to allocate mailbox buffer.");
		return;
	}
	mb = (MAILBOX *)mbq;

	emlxs_mb_set_var(hba, mbq, 0x00100506, value);

	if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		if (verbose || (mb->mbxStatus != 0x12)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "PCI_MAX_READ: Unable to update. "
			    "status=%x value=%d (%d bytes)",
			    mb->mbxStatus, value,
			    cfg[CFG_PCI_MAX_READ].current);
		}
	} else {
		if (verbose &&
		    (cfg[CFG_PCI_MAX_READ].current !=
		    cfg[CFG_PCI_MAX_READ].def)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "PCI_MAX_READ: Updated. %d bytes",
			    cfg[CFG_PCI_MAX_READ].current);
		}
	}

	(void) kmem_free((uint8_t *)mbq, sizeof (MAILBOXQ));

	return;

} /* emlxs_pcix_mxr_update */



extern uint32_t
emlxs_get_key(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb = (MAILBOX *)mbq;
	uint32_t npname0, npname1;
	uint32_t tmpkey, theKey;
	uint16_t key850;
	uint32_t t1, t2, t3, t4;
	uint32_t ts;

#define	SEED 0x876EDC21

	/* This key is only used currently for SBUS adapters */
	if (hba->bus_type != SBUS_FC) {
		return (0);
	}

	tmpkey = mb->un.varWords[30];
	EMLXS_STATE_CHANGE(hba, FC_INIT_NVPARAMS);

	emlxs_mb_read_nv(hba, mbq);
	if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to read nvram. cmd=%x status=%x", mb->mbxCommand,
		    mb->mbxStatus);

		return (0);
	}
	npname0 = mb->un.varRDnvp.portname[0];
	npname1 = mb->un.varRDnvp.portname[1];

	key850 = (uint16_t)((tmpkey & 0x00FFFF00) >> 8);
	ts = (uint16_t)(npname1 + 1);
	t1 = ts * key850;
	ts = (uint16_t)((npname1 >> 16) + 1);
	t2 = ts * key850;
	ts = (uint16_t)(npname0 + 1);
	t3 = ts * key850;
	ts = (uint16_t)((npname0 >> 16) + 1);
	t4 = ts * key850;
	theKey = SEED + t1 + t2 + t3 + t4;

	return (theKey);

} /* emlxs_get_key() */


extern void
emlxs_fw_show(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t i;

	/* Display firmware library one time */
	for (i = 0; i < emlxs_fw_count; i++) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_library_msg, "%s",
		    emlxs_fw_table[i].label);
	}

	return;

} /* emlxs_fw_show() */


#ifdef MODFW_SUPPORT
extern void
emlxs_fw_load(emlxs_hba_t *hba, emlxs_firmware_t *fw)
{
	emlxs_port_t *port = &PPORT;
	int (*emlxs_fw_get)(emlxs_firmware_t *);
	int err;
	char name[64];

	/* Make sure image is unloaded and image buffer pointer is clear */
	emlxs_fw_unload(hba, fw);

	err = 0;
	hba->fw_modhandle =
	    ddi_modopen(EMLXS_FW_MODULE, KRTLD_MODE_FIRST, &err);
	if (!hba->fw_modhandle) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to load firmware module. error=%d", err);

		return;
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
		    "Firmware module loaded.");
	}

	(void) snprintf(name, sizeof (name), "%s_fw_get", DRIVER_NAME);
	err = 0;
	emlxs_fw_get =
	    (int (*)())ddi_modsym(hba->fw_modhandle, name, &err);
	if ((void *)emlxs_fw_get == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "%s not present. error=%d", name, err);

		emlxs_fw_unload(hba, fw);
		return;
	}

	if (emlxs_fw_get(fw)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Invalid firmware image module found. %s", fw->label);

		emlxs_fw_unload(hba, fw);
		return;
	}

	return;

} /* emlxs_fw_load() */


extern void
emlxs_fw_unload(emlxs_hba_t *hba, emlxs_firmware_t *fw)
{
	emlxs_port_t *port = &PPORT;

	/* Clear the firmware image */
	fw->image = NULL;
	fw->size = 0;

	if (hba->fw_modhandle) {
		/* Close the module */
		(void) ddi_modclose(hba->fw_modhandle);
		hba->fw_modhandle = NULL;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
		    "Firmware module unloaded.");
	}

	return;

} /* emlxs_fw_unload() */
#endif /* MODFW_SUPPORT */


static void
emlxs_pci_cap_offsets(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t reg;
	uint8_t	offset;
	uint8_t	next;
	uint8_t	id;
	uint16_t eoffset;
	uint16_t enext;
	uint8_t eversion;
	uint16_t eid;

	/* Read PCI capbabilities */

	bzero(hba->pci_cap_offset, sizeof (hba->pci_cap_offset));

	/* Read first offset */
	offset = PCI_CAP_POINTER;
	offset = ddi_get8(hba->pci_acc_handle,
	    (uint8_t *)(hba->pci_addr + offset));

	while (offset >= PCI_CAP_PTR_OFF) {
		/* Read the cap */
		reg = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + offset));

		id = ((reg >> PCI_CAP_ID_SHIFT) & PCI_CAP_ID_MASK);
		next = ((reg >> PCI_CAP_NEXT_PTR_SHIFT) &
		    PCI_CAP_NEXT_PTR_MASK);

		if ((id < PCI_CAP_MAX_PTR) &&
		    (hba->pci_cap_offset[id] == 0)) {
			hba->pci_cap_offset[id] = offset;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "%s: offset=0x%x next=0x%x",
		    emlxs_pci_cap_xlate(id), offset, next);

		offset = next;
	}

	/* Workaround for BE adapters */
	if ((hba->pci_cap_offset[PCI_CAP_ID_VS] == 0) &&
	    (hba->model_info.chip & EMLXS_BE_CHIPS)) {
		hba->pci_cap_offset[PCI_CAP_ID_VS] = 0x54;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "%s: offset=0x%x  Added.",
		    emlxs_pci_cap_xlate(PCI_CAP_ID_VS),
		    hba->pci_cap_offset[PCI_CAP_ID_VS]);
	}

	if (! hba->pci_cap_offset[PCI_CAP_ID_PCI_E]) {
		/* It's not a PCIE adapter. */
		return;
	}

	/* Read PCI Extended capbabilities */

	bzero(hba->pci_ecap_offset, sizeof (hba->pci_ecap_offset));

	/* Set first offset */
	eoffset = PCIE_EXT_CAP;

	while (eoffset >= PCIE_EXT_CAP) {
		/* Read the cap */
		reg = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + eoffset));

		eid = ((reg >> PCIE_EXT_CAP_ID_SHIFT) & PCIE_EXT_CAP_ID_MASK);
		eversion = ((reg >> PCIE_EXT_CAP_VER_SHIFT) &
		    PCIE_EXT_CAP_VER_MASK);
		enext = ((reg >> PCIE_EXT_CAP_NEXT_PTR_SHIFT) &
		    PCIE_EXT_CAP_NEXT_PTR_MASK);

		if ((eid < PCI_EXT_CAP_MAX_PTR) &&
		    (hba->pci_ecap_offset[eid] == 0)) {
			hba->pci_ecap_offset[eid] = eoffset;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "%s: offset=0x%x version=0x%x next=0x%x",
		    emlxs_pci_ecap_xlate(eid),
		    eoffset, eversion, enext);

		eoffset = enext;
	}

	return;

} /* emlxs_pci_cap_offsets() */
