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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * This file contains SM-HBA support for MPT SAS driver
 */

#if defined(lint) || defined(DEBUG)
#define	MPTSAS_DEBUG
#endif

/*
 * standard header files
 */
#include <sys/note.h>
#include <sys/scsi/scsi.h>
#include <sys/pci.h>

#pragma pack(1)
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_type.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_cnfg.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_init.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_ioc.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_sas.h>
#pragma pack()

/*
 * private header files.
 */
#include <sys/scsi/adapters/mpt_sas/mptsas_var.h>
#include <sys/scsi/adapters/mpt_sas/mptsas_smhba.h>

void
mptsas_smhba_add_hba_prop(mptsas_t *mpt, data_type_t dt,
    char *prop_name, void *prop_val);

void
mptsas_smhba_show_phy_info(mptsas_t *mpt);

void
mptsas_smhba_add_hba_prop(mptsas_t *mpt, data_type_t dt,
    char *prop_name, void *prop_val)
{
	ASSERT(mpt != NULL);

	switch (dt) {
	case DATA_TYPE_INT32:
		if (ddi_prop_update_int(DDI_DEV_T_NONE, mpt->m_dip,
		    prop_name, *(int *)prop_val)) {
			mptsas_log(mpt, CE_WARN,
			    "%s: %s prop update failed", __func__, prop_name);
		}
		break;
	case DATA_TYPE_STRING:
		if (ddi_prop_update_string(DDI_DEV_T_NONE, mpt->m_dip,
		    prop_name, (char *)prop_val)) {
			mptsas_log(mpt, CE_WARN,
			    "%s: %s prop update failed", __func__, prop_name);
		}
		break;
	default:
		mptsas_log(mpt, CE_WARN, "%s: "
		    "Unhandled datatype(%d) for (%s). Skipping prop update.",
		    __func__, dt, prop_name);
	}
}

void
mptsas_smhba_show_phy_info(mptsas_t *mpt)
{
	int i;

	ASSERT(mpt != NULL);

	for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
		mptsas_log(mpt, CE_WARN,
		    "phy %d, Owner hdl:0x%x, attached hdl: 0x%x,"
		    "attached phy identifier %d,Program link rate 0x%x,"
		    "hw link rate 0x%x, negotiator link rate 0x%x, path %s",
		    i, mpt->m_phy_info[i].smhba_info.owner_devhdl,
		    mpt->m_phy_info[i].smhba_info.attached_devhdl,
		    mpt->m_phy_info[i].smhba_info.attached_phy_identify,
		    mpt->m_phy_info[i].smhba_info.programmed_link_rate,
		    mpt->m_phy_info[i].smhba_info.hw_link_rate,
		    mpt->m_phy_info[i].smhba_info.negotiated_link_rate,
		    mpt->m_phy_info[i].smhba_info.path);
	}
}

void
mptsas_smhba_set_phy_props(mptsas_t *mpt, char *iport, dev_info_t *dip,
    uint8_t phy_nums, uint16_t *attached_devhdl)
{
	int		i;
	int		j = 0;
	int		rval;
	size_t		packed_size;
	char		*packed_data = NULL;
	char		phymask[MPTSAS_MAX_PHYS];
	nvlist_t	**phy_props;
	nvlist_t	*nvl;
	smhba_info_t	*pSmhba = NULL;

	if (phy_nums == 0) {
		return;
	}
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		mptsas_log(mpt, CE_WARN, "%s: nvlist_alloc() failed", __func__);
	}

	phy_props = kmem_zalloc(sizeof (nvlist_t *) * phy_nums,
	    KM_SLEEP);

	for (i = 0; i < mpt->m_num_phys; i++) {

		bzero(phymask, sizeof (phymask));
		(void) sprintf(phymask, "%x", mpt->m_phy_info[i].phy_mask);
		if (strcmp(phymask, iport) == 0) {
			pSmhba = &mpt->m_phy_info[i].smhba_info;
			(void) nvlist_alloc(&phy_props[j], NV_UNIQUE_NAME, 0);
			(void) nvlist_add_uint8(phy_props[j], SAS_PHY_ID, i);
			(void) nvlist_add_uint8(phy_props[j],
			    "phyState",
			    (pSmhba->negotiated_link_rate
			    & 0x0f));
			(void) nvlist_add_int8(phy_props[j],
			    SAS_NEG_LINK_RATE,
			    (pSmhba->negotiated_link_rate
			    & 0x0f));
			(void) nvlist_add_int8(phy_props[j],
			    SAS_PROG_MIN_LINK_RATE,
			    (pSmhba->programmed_link_rate
			    & 0x0f));
			(void) nvlist_add_int8(phy_props[j],
			    SAS_HW_MIN_LINK_RATE,
			    (pSmhba->hw_link_rate
			    & 0x0f));
			(void) nvlist_add_int8(phy_props[j],
			    SAS_PROG_MAX_LINK_RATE,
			    ((pSmhba->programmed_link_rate
			    & 0xf0) >> 4));
			(void) nvlist_add_int8(phy_props[j],
			    SAS_HW_MAX_LINK_RATE,
			    ((pSmhba->hw_link_rate
			    & 0xf0) >> 4));

			j++;

			if (pSmhba->attached_devhdl &&
			    (attached_devhdl != NULL)) {
				*attached_devhdl =
				    pSmhba->attached_devhdl;
			}
		}
	}

	rval = nvlist_add_nvlist_array(nvl, SAS_PHY_INFO_NVL, phy_props,
	    phy_nums);
	if (rval) {
		mptsas_log(mpt, CE_WARN,
		    " nv list array add failed, return value %d.",
		    rval);
		goto exit;
	}
	(void) nvlist_size(nvl, &packed_size, NV_ENCODE_NATIVE);
	packed_data = kmem_zalloc(packed_size, KM_SLEEP);
	(void) nvlist_pack(nvl, &packed_data, &packed_size,
	    NV_ENCODE_NATIVE, 0);

	(void) ddi_prop_update_byte_array(DDI_DEV_T_NONE, dip,
	    SAS_PHY_INFO, (uchar_t *)packed_data, packed_size);

exit:
	for (i = 0; i < phy_nums && phy_props[i] != NULL; i++) {
		nvlist_free(phy_props[i]);
	}
	nvlist_free(nvl);
	kmem_free(phy_props, sizeof (nvlist_t *) * phy_nums);

	if (packed_data != NULL) {
		kmem_free(packed_data, packed_size);
	}
}

/*
 * Called with PHY lock held on phyp
 */
void
mptsas_smhba_log_sysevent(mptsas_t *mpt, char *subclass, char *etype,
    smhba_info_t *phyp)
{
	nvlist_t	*attr_list;
	char		*pname;
	char		sas_addr[MPTSAS_WWN_STRLEN];
	uint8_t		phynum = 0;
	uint8_t		lrate = 0;

	if (mpt->m_dip == NULL)
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
		phynum = phyp->phy_id;
		bzero(sas_addr, sizeof (sas_addr));
		(void) sprintf(sas_addr, "w%016"PRIx64, phyp->sas_addr);
		if (strcmp(etype, SAS_PHY_ONLINE) == 0) {
			lrate = phyp->negotiated_link_rate;
		}
	}
	if (strcmp(subclass, ESC_SAS_HBA_PORT_BROADCAST) == 0) {
		(void) ddi_pathname(mpt->m_dip, pname);
	}

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, 0) != 0) {
		mptsas_log(mpt, CE_WARN,
		    "%s: Failed to post sysevent", __func__);
		kmem_free(pname, MAXPATHLEN);
		return;
	}

	if (nvlist_add_int32(attr_list, SAS_DRV_INST,
	    ddi_get_instance(mpt->m_dip)) != 0)
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

	(void) ddi_log_sysevent(mpt->m_dip, DDI_VENDOR_SUNW, EC_HBA, subclass,
	    attr_list, NULL, DDI_NOSLEEP);

fail:
	kmem_free(pname, MAXPATHLEN);
	nvlist_free(attr_list);
}

void
mptsas_create_phy_stats(mptsas_t *mpt, char *iport, dev_info_t *dip)
{
	sas_phy_stats_t		*ps;
	smhba_info_t		*phyp;
	int			ndata;
	char			ks_name[KSTAT_STRLEN];
	char			phymask[MPTSAS_MAX_PHYS];
	int			i;

	ASSERT(iport != NULL);
	ASSERT(mpt != NULL);

	for (i = 0; i < mpt->m_num_phys; i++) {

		bzero(phymask, sizeof (phymask));
		(void) sprintf(phymask, "%x", mpt->m_phy_info[i].phy_mask);
		if (strcmp(phymask, iport) == 0) {

			phyp = &mpt->m_phy_info[i].smhba_info;
			mutex_enter(&phyp->phy_mutex);

			if (phyp->phy_stats != NULL) {
				mutex_exit(&phyp->phy_mutex);
				/* We've already created this kstat instance */
				continue;
			}

			ndata = (sizeof (sas_phy_stats_t)/
			    sizeof (kstat_named_t));
			(void) snprintf(ks_name, sizeof (ks_name),
			    "%s.%llx.%d.%d", ddi_driver_name(dip),
			    (longlong_t)mpt->un.m_base_wwid,
			    ddi_get_instance(dip), i);

			phyp->phy_stats = kstat_create("mptsas",
			    ddi_get_instance(dip), ks_name, KSTAT_SAS_PHY_CLASS,
			    KSTAT_TYPE_NAMED, ndata, 0);

			if (phyp->phy_stats == NULL) {
				mutex_exit(&phyp->phy_mutex);
				mptsas_log(mpt, CE_WARN,
				    "%s: Failed to create %s kstats", __func__,
				    ks_name);
				continue;
			}

			ps = (sas_phy_stats_t *)phyp->phy_stats->ks_data;

			kstat_named_init(&ps->seconds_since_last_reset,
			    "SecondsSinceLastReset", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&ps->tx_frames,
			    "TxFrames", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&ps->rx_frames,
			    "RxFrames", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&ps->tx_words,
			    "TxWords", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&ps->rx_words,
			    "RxWords", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&ps->invalid_dword_count,
			    "InvalidDwordCount", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&ps->running_disparity_error_count,
			    "RunningDisparityErrorCount", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&ps->loss_of_dword_sync_count,
			    "LossofDwordSyncCount", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&ps->phy_reset_problem_count,
			    "PhyResetProblemCount", KSTAT_DATA_ULONGLONG);

			phyp->phy_stats->ks_private = phyp;
			phyp->phy_stats->ks_update = mptsas_update_phy_stats;
			kstat_install(phyp->phy_stats);
			mutex_exit(&phyp->phy_mutex);
		}
	}
}

int
mptsas_update_phy_stats(kstat_t *ks, int rw)
{
	int			ret = DDI_FAILURE;
	smhba_info_t		*pptr = NULL;
	sas_phy_stats_t		*ps = ks->ks_data;
	uint32_t 		page_address;
	mptsas_t 		*mpt;

	_NOTE(ARGUNUSED(rw));

	pptr = (smhba_info_t *)ks->ks_private;
	ASSERT((pptr != NULL));
	mpt = (mptsas_t *)pptr->mpt;
	ASSERT((mpt != NULL));
	page_address = (MPI2_SAS_PHY_PGAD_FORM_PHY_NUMBER | pptr->phy_id);

	/*
	 * We just want to lock against other invocations of kstat;
	 * we don't need to pmcs_lock_phy() for this.
	 */
	mutex_enter(&mpt->m_mutex);

	ret = mptsas_get_sas_phy_page1(pptr->mpt, page_address, pptr);

	if (ret == DDI_FAILURE)
		goto fail;

	ps->invalid_dword_count.value.ull =
	    (unsigned long long)pptr->invalid_dword_count;

	ps->running_disparity_error_count.value.ull =
	    (unsigned long long)pptr->running_disparity_error_count;

	ps->loss_of_dword_sync_count.value.ull =
	    (unsigned long long)pptr->loss_of_dword_sync_count;

	ps->phy_reset_problem_count.value.ull =
	    (unsigned long long)pptr->phy_reset_problem_count;

	ret = DDI_SUCCESS;
fail:
	mutex_exit(&mpt->m_mutex);

	return (ret);
}

void
mptsas_destroy_phy_stats(mptsas_t *mpt)
{
	smhba_info_t	*phyp;
	int			i = 0;

	ASSERT(mpt != NULL);

	for (i = 0; i < mpt->m_num_phys; i++) {
		phyp = &mpt->m_phy_info[i].smhba_info;
		if (phyp == NULL) {
			continue;
		}

		mutex_enter(&phyp->phy_mutex);
		if (phyp->phy_stats != NULL) {
			kstat_delete(phyp->phy_stats);
			phyp->phy_stats = NULL;
		}
		mutex_exit(&phyp->phy_mutex);
	}
}

int
mptsas_smhba_phy_init(mptsas_t *mpt)
{
	int		i = 0;
	int		rval = DDI_SUCCESS;
	uint32_t	page_address;

	ASSERT(mutex_owned(&mpt->m_mutex));

	for (i = 0; i < mpt->m_num_phys; i++) {
		page_address =
		    (MPI2_SAS_PHY_PGAD_FORM_PHY_NUMBER |
		    (MPI2_SAS_PHY_PGAD_PHY_NUMBER_MASK & i));
		rval = mptsas_get_sas_phy_page0(mpt,
		    page_address, &mpt->m_phy_info[i].smhba_info);
		if (rval != DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN,
			    "Failed to get sas phy page 0"
			    " for each phy");
			return (DDI_FAILURE);
		}
		mpt->m_phy_info[i].smhba_info.phy_id = (uint8_t)i;
		mpt->m_phy_info[i].smhba_info.sas_addr =
		    mpt->un.m_base_wwid + i;
		mpt->m_phy_info[i].smhba_info.mpt = mpt;
	}

	return (DDI_SUCCESS);
}
