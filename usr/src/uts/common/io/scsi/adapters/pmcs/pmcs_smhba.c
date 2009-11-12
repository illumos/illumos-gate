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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file contains SM-HBA support for PMC-S driver
 */

#include <sys/scsi/adapters/pmcs/pmcs.h>


void
pmcs_smhba_add_hba_prop(pmcs_hw_t *pwp, data_type_t dt,
    char *prop_name, void *prop_val)
{
	ASSERT(pwp != NULL);

	switch (dt) {
	case DATA_TYPE_INT32:
		if (ddi_prop_update_int(DDI_DEV_T_NONE, pwp->dip,
		    prop_name, *(int *)prop_val)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: %s prop update failed", __func__, prop_name);
		}
		break;
	case DATA_TYPE_STRING:
		if (ddi_prop_update_string(DDI_DEV_T_NONE, pwp->dip,
		    prop_name, (char *)prop_val)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: %s prop update failed", __func__, prop_name);
		}
		break;
	default:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s: "
		    "Unhandled datatype(%d) for (%s). Skipping prop update.",
		    __func__, dt, prop_name);
	}
}


void
pmcs_smhba_add_iport_prop(pmcs_iport_t *iport, data_type_t dt,
    char *prop_name, void *prop_val)
{
	ASSERT(iport != NULL);

	switch (dt) {
	case DATA_TYPE_INT32:
		if (ddi_prop_update_int(DDI_DEV_T_NONE, iport->dip,
		    prop_name, *(int *)prop_val)) {
			pmcs_prt(iport->pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: %s prop update failed", __func__, prop_name);
		}
		break;
	case DATA_TYPE_STRING:
		if (ddi_prop_update_string(DDI_DEV_T_NONE, iport->dip,
		    prop_name, (char *)prop_val)) {
			pmcs_prt(iport->pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: %s prop update failed", __func__, prop_name);
		}
		break;
	default:
		pmcs_prt(iport->pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s: "
		    "Unhandled datatype(%d) for(%s). Skipping prop update.",
		    __func__, dt, prop_name);
	}
}


void
pmcs_smhba_add_tgt_prop(pmcs_xscsi_t *tgt, data_type_t dt,
    char *prop_name, void *prop_val)
{
	ASSERT(tgt != NULL);

	switch (dt) {
	case DATA_TYPE_INT32:
		if (ddi_prop_update_int(DDI_DEV_T_NONE, tgt->dip,
		    prop_name, *(int *)prop_val)) {
			pmcs_prt(tgt->pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: %s prop update failed", __func__, prop_name);
		}
		break;
	case DATA_TYPE_STRING:
		if (ddi_prop_update_string(DDI_DEV_T_NONE, tgt->dip,
		    prop_name, (char *)prop_val)) {
			pmcs_prt(tgt->pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: %s prop update failed", __func__, prop_name);
		}
		break;
	default:
		pmcs_prt(tgt->pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s: "
		    "Unhandled datatype(%d) for (%s). Skipping prop update.",
		    __func__, dt, prop_name);
	}
}

/* ARGSUSED */
void
pmcs_smhba_set_scsi_device_props(pmcs_hw_t *pwp, pmcs_phy_t *pptr,
    struct scsi_device *sd)
{
	char		*addr;
	int		ua_form = 1;
	uint64_t	wwn;
	pmcs_phy_t	*pphy;

	pphy = pptr->parent;

	if (pphy != NULL) {
		addr = kmem_zalloc(PMCS_MAX_UA_SIZE, KM_SLEEP);
		wwn = pmcs_barray2wwn(pphy->sas_address);
		(void) scsi_wwn_to_wwnstr(wwn, ua_form, addr);

		if (pphy->dtype == SATA) {
			(void) scsi_device_prop_update_string(sd,
			    SCSI_DEVICE_PROP_PATH,
			    SCSI_ADDR_PROP_BRIDGE_PORT, addr);
		}
		if (pphy->dtype == EXPANDER) {
			(void) scsi_device_prop_update_string(sd,
			    SCSI_DEVICE_PROP_PATH,
			    SCSI_ADDR_PROP_ATTACHED_PORT, addr);
		}
		kmem_free(addr, PMCS_MAX_UA_SIZE);
	}
}

void
pmcs_smhba_set_phy_props(pmcs_iport_t *iport)
{
	int		i;
	size_t		packed_size;
	char		*packed_data;
	pmcs_hw_t	*pwp = iport->pwp;
	pmcs_phy_t	*phy_ptr;
	nvlist_t	**phy_props;
	nvlist_t	*nvl;

	mutex_enter(&iport->lock);
	if (iport->nphy == 0) {
		mutex_exit(&iport->lock);
		return;
	}

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: nvlist_alloc() failed", __func__);
	}

	phy_props = kmem_zalloc(sizeof (nvlist_t *) * iport->nphy, KM_SLEEP);

	for (phy_ptr = list_head(&iport->phys), i = 0;
	    phy_ptr != NULL;
	    phy_ptr = list_next(&iport->phys, phy_ptr), i++) {
		pmcs_lock_phy(phy_ptr);

		(void) nvlist_alloc(&phy_props[i], NV_UNIQUE_NAME, 0);

		(void) nvlist_add_uint8(phy_props[i], SAS_PHY_ID,
		    phy_ptr->phynum);
		(void) nvlist_add_int8(phy_props[i], SAS_NEG_LINK_RATE,
		    phy_ptr->link_rate);
		(void) nvlist_add_int8(phy_props[i], SAS_PROG_MIN_LINK_RATE,
		    phy_ptr->state.prog_min_rate);
		(void) nvlist_add_int8(phy_props[i], SAS_HW_MIN_LINK_RATE,
		    phy_ptr->state.hw_min_rate);
		(void) nvlist_add_int8(phy_props[i], SAS_PROG_MAX_LINK_RATE,
		    phy_ptr->state.prog_max_rate);
		(void) nvlist_add_int8(phy_props[i], SAS_HW_MAX_LINK_RATE,
		    phy_ptr->state.hw_max_rate);

		pmcs_unlock_phy(phy_ptr);
	}

	(void) nvlist_add_nvlist_array(nvl, SAS_PHY_INFO_NVL, phy_props,
	    iport->nphy);

	(void) nvlist_size(nvl, &packed_size, NV_ENCODE_NATIVE);
	packed_data = kmem_zalloc(packed_size, KM_SLEEP);
	(void) nvlist_pack(nvl, &packed_data, &packed_size,
	    NV_ENCODE_NATIVE, 0);

	(void) ddi_prop_update_byte_array(DDI_DEV_T_NONE, iport->dip,
	    SAS_PHY_INFO, (uchar_t *)packed_data, packed_size);

	for (i = 0; i < iport->nphy && phy_props[i] != NULL; i++) {
		nvlist_free(phy_props[i]);
	}
	nvlist_free(nvl);
	kmem_free(phy_props, sizeof (nvlist_t *) * iport->nphy);
	mutex_exit(&iport->lock);
	kmem_free(packed_data, packed_size);
}

/*
 * Called with PHY lock held on phyp
 */
void
pmcs_smhba_log_sysevent(pmcs_hw_t *pwp, char *subclass, char *etype,
    pmcs_phy_t *phyp)
{
	nvlist_t	*attr_list;
	char		*pname;
	char		sas_addr[PMCS_MAX_UA_SIZE];
	uint8_t		phynum = 0;
	uint8_t		lrate = 0;
	uint64_t	wwn;
	int		ua_form = 0;

	if (pwp->dip == NULL)
		return;
	if (phyp == NULL)
		return;

	pname = kmem_zalloc(MAXPATHLEN, KM_NOSLEEP);
	if (pname == NULL)
		return;

	if ((strcmp(subclass, ESC_SAS_PHY_EVENT) == 0) ||
	    (strcmp(subclass, ESC_SAS_HBA_PORT_BROADCAST) == 0)) {
		ASSERT(phyp != NULL);
		(void) strncpy(pname, phyp->path, strlen(phyp->path));
		phynum = phyp->phynum;
		wwn = pmcs_barray2wwn(phyp->sas_address);
		(void) scsi_wwn_to_wwnstr(wwn, ua_form, sas_addr);
		if (strcmp(etype, SAS_PHY_ONLINE) == 0) {
			lrate = phyp->link_rate;
		}
	}
	if (strcmp(subclass, ESC_SAS_HBA_PORT_BROADCAST) == 0) {
		(void) ddi_pathname(pwp->dip, pname);
	}

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, 0) != 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: Failed to post sysevent", __func__);
		kmem_free(pname, MAXPATHLEN);
		return;
	}

	if (nvlist_add_int32(attr_list, SAS_DRV_INST,
	    ddi_get_instance(pwp->dip)) != 0)
		goto fail;

	if (nvlist_add_string(attr_list, SAS_PORT_ADDR, sas_addr) != 0)
		goto fail;

	if (nvlist_add_string(attr_list, SAS_DEVFS_PATH, pname) != 0)
		goto fail;

	if (nvlist_add_uint8(attr_list, SAS_PHY_ID, phynum) != 0)
		goto fail;

	if (strcmp(etype, SAS_PHY_ONLINE) == 0) {
		if (nvlist_add_uint8(attr_list, SAS_LINK_RATE, lrate) != 0)
			goto fail;
	}

	if (nvlist_add_string(attr_list, SAS_EVENT_TYPE, etype) != 0)
		goto fail;

	(void) ddi_log_sysevent(pwp->dip, DDI_VENDOR_SUNW, EC_HBA, subclass,
	    attr_list, NULL, DDI_NOSLEEP);

fail:
	kmem_free(pname, MAXPATHLEN);
	nvlist_free(attr_list);
}
