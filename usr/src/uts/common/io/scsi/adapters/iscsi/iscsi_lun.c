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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * iSCSI logical unit interfaces
 */

#include "iscsi.h"
#include <sys/fs/dv_node.h>	/* devfs_clean */

/* tpgt bytes in string form */
#define	TPGT_EXT_SIZE	5

/* logical unit number bytes in string form */
#define	LUN_EXT_SIZE	10

/*
 * Addition addr size of size of ',' + max str form of tpgt (2 bytes) +
 * ',' + max str form of logical unit number (4 bytes).
 */
#define	ADDR_EXT_SIZE	(1 + TPGT_EXT_SIZE + 1 + LUN_EXT_SIZE)

/* internal interfaces */
static iscsi_status_t iscsi_lun_virt_create(iscsi_sess_t *isp,
    uint16_t lun_num, iscsi_lun_t *ilp, struct scsi_inquiry *inq);
static iscsi_status_t iscsi_lun_phys_create(iscsi_sess_t *isp,
    uint16_t lun_num, iscsi_lun_t *ilp, struct scsi_inquiry *inq);

extern dev_info_t	*scsi_vhci_dip;

/*
 * +--------------------------------------------------------------------+
 * | External Connection Interfaces					|
 * +--------------------------------------------------------------------+
 */


/*
 * iscsi_lun_create - This function will create a lun mapping.
 * logic specific to MPxIO vs. NDI node creation is switched
 * out to a helper function.
 */
iscsi_status_t
iscsi_lun_create(iscsi_sess_t *isp, uint16_t lun_num, uint8_t lun_addr_type,
    struct scsi_inquiry *inq, char *guid)
{
	iscsi_status_t		rtn		= ISCSI_STATUS_INTERNAL_ERROR;
	iscsi_hba_t		*ihp		= NULL;
	iscsi_lun_t		*ilp		= NULL;
	iscsi_lun_t		*ilp_tmp	= NULL;
	char			*addr		= NULL;

	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	addr = kmem_zalloc((strlen((char *)isp->sess_name) +
	    ADDR_EXT_SIZE + 1), KM_SLEEP);
	(void) snprintf(addr,
	    (strlen((char *)isp->sess_name) +
	    ADDR_EXT_SIZE + 1),
	    "%02X%02X%s%04X,%d", isp->sess_isid[4],
	    isp->sess_isid[5], isp->sess_name,
	    isp->sess_tpgt_conf & 0xFFFF, lun_num);

	/* allocate space for lun struct */
	ilp = kmem_zalloc(sizeof (iscsi_lun_t), KM_SLEEP);
	ilp->lun_sig = ISCSI_SIG_LUN;
	ilp->lun_state = ISCSI_LUN_STATE_OFFLINE;

	/* initialize common LU information */
	ilp->lun_num	    = lun_num;
	ilp->lun_addr_type  = lun_addr_type;
	ilp->lun_sess	    = isp;
	ilp->lun_addr	    = addr;

	mutex_enter(&iscsi_oid_mutex);
	ilp->lun_oid = iscsi_oid++;
	mutex_exit(&iscsi_oid_mutex);

	bcopy(inq->inq_vid, ilp->lun_vid, sizeof (inq->inq_vid));
	bcopy(inq->inq_pid, ilp->lun_pid, sizeof (inq->inq_pid));

	/* store GUID if valid one exists */
	if (guid != NULL) {
		ilp->lun_guid_size = strlen(guid) + 1;
		ilp->lun_guid = kmem_zalloc(ilp->lun_guid_size, KM_SLEEP);
		(void) strcpy(ilp->lun_guid, guid);
	} else {
		ilp->lun_guid_size = 0;
		ilp->lun_guid = NULL;
	}

	/*
	 * We need to add the lun to our lists now because during the
	 * lun creation we will get called back into multiple times
	 * depending on the createion type.  These callbacks will
	 * occur via our tran_init_lun, tran_get_name, tran_get_bus_addr,
	 * tran_init_pkt, tran_start.
	 */
	rw_enter(&isp->sess_lun_list_rwlock, RW_WRITER);
	if (isp->sess_lun_list == NULL) {
		isp->sess_lun_list = ilp;
	} else {
		ilp->lun_next = isp->sess_lun_list;
		isp->sess_lun_list = ilp;
	}

	/* Attempt to create a scsi_vhci binding if GUID is available */
	if ((ihp->hba_mpxio_enabled == B_TRUE) &&
	    (guid != NULL)) {
		rtn = iscsi_lun_virt_create(isp, lun_num, ilp, inq);
	}
	if (!ISCSI_SUCCESS(rtn)) {
		/* unable to bind under scsi_vhci, failback to ndi */
		rtn = iscsi_lun_phys_create(isp, lun_num, ilp, inq);
	}

	/*
	 * If NOT successful we need to remove the lun from the
	 * session and free any related resources.
	 */
	if (!ISCSI_SUCCESS(rtn)) {
		if (ilp == isp->sess_lun_list) {
			/* if head, set head to our next */
			isp->sess_lun_list = ilp->lun_next;
		} else {
			/* if not head, set prev lun's next to our next */
			for (ilp_tmp = isp->sess_lun_list; ilp_tmp;
			    ilp_tmp = ilp_tmp->lun_next) {
				if (ilp_tmp->lun_next == ilp) {
					ilp_tmp->lun_next = ilp->lun_next;
					break;
				}
			}
		}

		kmem_free(ilp->lun_addr,
		    (strlen((char *)isp->sess_name) +
		    ADDR_EXT_SIZE + 1));
		ilp->lun_addr = NULL;

		if (ilp->lun_guid != NULL) {
			kmem_free(ilp->lun_guid, ilp->lun_guid_size);
			ilp->lun_guid = NULL;
		}
		kmem_free(ilp, sizeof (iscsi_lun_t));
	} else {
		ilp->lun_state = ISCSI_LUN_STATE_ONLINE;
		ilp->lun_time_online = ddi_get_time();
	}
	rw_exit(&isp->sess_lun_list_rwlock);

	return (rtn);
}


/*
 * iscsi_lun_destroy - offline and remove lun
 *
 * This interface is called when a name service change has
 * occured and the storage is no longer available to this
 * initiator.  This function will offline and free the
 * solaris node resources.  Then it will free all iscsi lun
 * resources.
 *
 * This function can fail with ISCSI_STATUS_BUSY if the
 * logical unit is in use.  The user should unmount or
 * close the device and perform the nameservice operation
 * again if this occurs.
 */
iscsi_status_t
iscsi_lun_destroy(iscsi_hba_t *ihp, iscsi_lun_t *ilp)
{
	iscsi_status_t		status		= ISCSI_STATUS_SUCCESS;
	iscsi_sess_t		*isp		= NULL;
	iscsi_lun_t		*t_ilp		= NULL;

	ASSERT(ilp != NULL);
	isp = ilp->lun_sess;
	ASSERT(isp != NULL);

	/* attempt to offline and free solaris node */
	status = iscsi_lun_offline(ihp, ilp, B_TRUE);

	/* If we successfully unplumbed the lun remove it from our lists */
	if (ISCSI_SUCCESS(status)) {
		if (isp->sess_lun_list == ilp) {
			/* target first item in list */
			isp->sess_lun_list = ilp->lun_next;
		} else {
			/*
			 * search session list for ilp pointing
			 * to lun being removed.  Then
			 * update that luns next pointer.
			 */
			t_ilp = isp->sess_lun_list;
			while (t_ilp->lun_next != NULL) {
				if (t_ilp->lun_next == ilp) {
					break;
				}
				t_ilp = t_ilp->lun_next;
			}
			if (t_ilp->lun_next == ilp) {
				t_ilp->lun_next = ilp->lun_next;
			} else {
				/* couldn't find session */
				ASSERT(FALSE);
			}
		}

		/* release its memory */
		kmem_free(ilp->lun_addr, (strlen((char *)isp->sess_name) +
		    ADDR_EXT_SIZE + 1));
		ilp->lun_addr = NULL;
		if (ilp->lun_guid != NULL) {
			kmem_free(ilp->lun_guid, ilp->lun_guid_size);
			ilp->lun_guid = NULL;
		}
		kmem_free(ilp, sizeof (iscsi_lun_t));
		ilp = NULL;
	}

	return (status);
}

/*
 * +--------------------------------------------------------------------+
 * | External Logical Unit Interfaces					|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_lun_virt_create - Creates solaris logical unit via MDI
 */
static iscsi_status_t
iscsi_lun_virt_create(iscsi_sess_t *isp, uint16_t lun_num, iscsi_lun_t *ilp,
    struct scsi_inquiry *inq)
{
	iscsi_status_t		rtn		= ISCSI_STATUS_INTERNAL_ERROR;
	int			mdi_rtn		= MDI_FAILURE;
	iscsi_hba_t		*ihp		= NULL;
	mdi_pathinfo_t		*pip		= NULL;
	char			*nodename	= NULL;
	char			**compatible	= NULL;
	int			ncompatible	= 0;
	int			circ = 0;

	ASSERT(isp != NULL);
	ASSERT(ilp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	/*
	 * Generate compatible property
	 */
	scsi_hba_nodename_compatible_get(inq, "vhci",
	    inq->inq_dtype, NULL, &nodename, &compatible, &ncompatible);

	/* if nodename can't be determined then print a message and skip it */
	if (nodename == NULL) {
		cmn_err(CE_WARN, "iscsi driver found no compatible driver "
		    "for %s lun %d dtype:0x%02x", isp->sess_name, lun_num,
		    inq->inq_dtype);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	/*
	 *
	 */
	ndi_devi_enter(scsi_vhci_dip, &circ);
	mdi_rtn = mdi_pi_alloc_compatible(ihp->hba_dip, nodename,
	    ilp->lun_guid, ilp->lun_addr, compatible, ncompatible,
	    0, &pip);

	if (mdi_rtn == MDI_SUCCESS) {
		mdi_pi_set_phci_private(pip, (caddr_t)ilp);

		if (mdi_prop_update_string(pip, MDI_GUID,
		    ilp->lun_guid) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "iscsi driver unable to create "
			    "property for %s lun %d (MDI_GUID)",
			    isp->sess_name, lun_num);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		if (mdi_prop_update_int(pip, TARGET_PROP,
		    isp->sess_oid) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "iscsi driver unable to create "
			    "property for %s lun %d (TARGET_PROP)",
			    isp->sess_name, lun_num);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		if (mdi_prop_update_int(pip, LUN_PROP,
		    ilp->lun_num) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "iscsi driver unable to create "
			    "property for %s lun %d (LUN_PROP)",
			    isp->sess_name, lun_num);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		if (mdi_prop_update_string_array(pip, "compatible",
		    compatible, ncompatible) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "iscsi driver unable to create "
			    "property for %s lun %d (COMPATIBLE)",
			    isp->sess_name, lun_num);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		mdi_rtn = mdi_pi_online(pip, 0);
		if (mdi_rtn == MDI_NOT_SUPPORTED) {
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		ilp->lun_pip = pip;
		ilp->lun_dip = NULL;

virt_create_done:

		if (pip && mdi_rtn != MDI_SUCCESS) {
			ilp->lun_pip = NULL;
			ilp->lun_dip = NULL;
			(void) mdi_prop_remove(pip, NULL);
			(void) mdi_pi_free(pip, 0);
		} else {
			rtn = ISCSI_STATUS_SUCCESS;
		}
	}
	ndi_devi_exit(scsi_vhci_dip, circ);

	scsi_hba_nodename_compatible_free(nodename, compatible);

	return (rtn);
}


/*
 * iscsi_lun_phys_create - creates solaris logical unit via NDI
 */
static iscsi_status_t
iscsi_lun_phys_create(iscsi_sess_t *isp, uint16_t lun_num,
    iscsi_lun_t *ilp, struct scsi_inquiry *inq)
{
	iscsi_status_t		rtn		= ISCSI_STATUS_INTERNAL_ERROR;
	int			ndi_rtn		= NDI_FAILURE;
	iscsi_hba_t		*ihp		= NULL;
	dev_info_t		*lun_dip	= NULL;
	char			*nodename	= NULL;
	char			**compatible	= NULL;
	int			ncompatible	= 0;
	char			*scsi_binding_set = NULL;
	char			instance[32];
	int			circ		= 0;

	ASSERT(isp != NULL);
	ASSERT(ilp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);
	ASSERT(inq != NULL);

	/* get the 'scsi-binding-set' property */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, isp->sess_hba->hba_dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, "scsi-binding-set",
	    &scsi_binding_set) != DDI_PROP_SUCCESS) {
		scsi_binding_set = NULL;
	}

	/* generate compatible property */
	scsi_hba_nodename_compatible_get(inq, scsi_binding_set,
	    inq->inq_dtype, NULL, &nodename, &compatible, &ncompatible);
	if (scsi_binding_set)
		ddi_prop_free(scsi_binding_set);

	/* if nodename can't be determined then print a message and skip it */
	if (nodename == NULL) {
		cmn_err(CE_WARN, "iscsi driver found no compatible driver "
		    "for %s lun %d", isp->sess_name, lun_num);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	ndi_devi_enter(ihp->hba_dip, &circ);

	ndi_rtn = ndi_devi_alloc(ihp->hba_dip, nodename,
	    DEVI_SID_NODEID, &lun_dip);

	/* if lun alloc success, set props */
	if (ndi_rtn == NDI_SUCCESS) {

		if (ndi_prop_update_int(DDI_DEV_T_NONE,
		    lun_dip, TARGET_PROP, (int)isp->sess_oid) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "iscsi driver unable to create "
			    "property for %s lun %d (TARGET_PROP)",
			    isp->sess_name, lun_num);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		if (ndi_prop_update_int(DDI_DEV_T_NONE,
		    lun_dip, LUN_PROP, (int)ilp->lun_num) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "iscsi driver unable to create "
			    "property for %s lun %d (LUN_PROP)",
			    isp->sess_name, lun_num);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		if (ndi_prop_update_string_array(DDI_DEV_T_NONE,
		    lun_dip, "compatible", compatible, ncompatible)
		    != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "iscsi driver unable to create "
			    "property for %s lun %d (COMPATIBLE)",
			    isp->sess_name, lun_num);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

phys_create_done:
		/* If props were setup ok, online the lun */
		if (ndi_rtn == NDI_SUCCESS) {
			/* Try to online the new node */
			ndi_rtn = ndi_devi_online(lun_dip, 0);
		}

		/* If success set rtn flag, else unwire alloc'd lun */
		if (ndi_rtn == NDI_SUCCESS) {
			rtn = ISCSI_STATUS_SUCCESS;
			/*
			 * Assign the instance number for the dev_link
			 * generator.  This will ensure the link name is
			 * unique and persistent across reboots.
			 */
			(void) snprintf(instance, 32, "%d",
			    ddi_get_instance(lun_dip));
			(void) ndi_prop_update_string(DDI_DEV_T_NONE,
			    lun_dip, NDI_GUID, instance);
		} else {
			cmn_err(CE_WARN, "iscsi driver unable to online "
			    "%s lun %d", isp->sess_name, lun_num);
			ndi_prop_remove_all(lun_dip);
			(void) ndi_devi_free(lun_dip);
		}

	}
	ndi_devi_exit(ihp->hba_dip, circ);

	ilp->lun_dip = lun_dip;
	ilp->lun_pip = NULL;

	scsi_hba_nodename_compatible_free(nodename, compatible);

	return (rtn);
}


/*
 * iscsi_lun_online - _di_online logical unit
 *
 * This is called after a path has recovered it will cause
 * an offline path to become online/active again.
 */
void
iscsi_lun_online(iscsi_hba_t *ihp, iscsi_lun_t *ilp)
{
	int			circ = 0;
	int			rval;

	ASSERT(ilp != NULL);
	ASSERT((ilp->lun_pip != NULL) || (ilp->lun_dip != NULL));


	if (ilp->lun_pip != NULL) {
		ndi_devi_enter(scsi_vhci_dip, &circ);
		rval =  mdi_pi_online(ilp->lun_pip, 0);
		ndi_devi_exit(scsi_vhci_dip, circ);
		if (rval == MDI_SUCCESS) {
			ilp->lun_state = ISCSI_LUN_STATE_ONLINE;
			ilp->lun_time_online = ddi_get_time();
		}

	} else if (ilp->lun_dip != NULL) {
		ndi_devi_enter(ihp->hba_dip, &circ);
		rval =  ndi_devi_online(ilp->lun_dip, 0);
		ndi_devi_exit(ihp->hba_dip, circ);
		if (rval == NDI_SUCCESS) {
			ilp->lun_state = ISCSI_LUN_STATE_ONLINE;
			ilp->lun_time_online = ddi_get_time();
		}
	}
}

/*
 * iscsi_lun_offline - attempt _di_offline [and optional _di_free]
 *
 * This function is called via two paths.  When a transport
 * path has failed it will be called to offline the logical
 * unit.  When nameservice access has been removed it will
 * be called to both offline and free the logical unit.
 * (This operates soley on the solaris node states.
 * iscsi_lun_destroy() should be called when attempting
 * to free all iscsi lun resources.)
 *
 * This function can fail with ISCSI_STATUS_BUSY if the
 * logical unit is in use.  The user should unmount or
 * close the device and perform the nameservice operation
 * again if this occurs.
 */
iscsi_status_t
iscsi_lun_offline(iscsi_hba_t *ihp, iscsi_lun_t *ilp, boolean_t lun_free)
{
	iscsi_status_t		status	= ISCSI_STATUS_SUCCESS;
	int			circ	= 0;
	dev_info_t		*cdip, *pdip;
	char			*devname;
	int			rval;

	ASSERT(ilp != NULL);
	ASSERT((ilp->lun_pip != NULL) || (ilp->lun_dip != NULL));

	/*
	 * Since we carry the logical units parent
	 * lock across the offline call it will not
	 * issue devfs_clean() and may fail with a
	 * devi_ref count > 0.
	 */
	if (ilp->lun_pip == NULL) {
		cdip = ilp->lun_dip;
	} else {
		cdip = mdi_pi_get_client(ilp->lun_pip);
	}

	if ((cdip != NULL) &&
	    (lun_free == B_TRUE) &&
	    (ilp->lun_state == ISCSI_LUN_STATE_ONLINE)) {
		/*
		 * Make sure node is attached otherwise
		 * it won't have related cache nodes to
		 * clean up.  i_ddi_devi_attached is
		 * similiar to i_ddi_node_state(cdip) >=
		 * DS_ATTACHED. We should clean up only
		 * when lun_free is set.
		 */
		if (i_ddi_devi_attached(cdip)) {

			/* Get parent dip */
			pdip = ddi_get_parent(cdip);

			/* Get full devname */
			devname = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
			ndi_devi_enter(pdip, &circ);
			(void) ddi_deviname(cdip, devname);
			/* Release lock before devfs_clean() */
			ndi_devi_exit(pdip, circ);

			/* Clean cache */
			rval = devfs_clean(pdip, devname + 1,
			    DV_CLEAN_FORCE);
			kmem_free(devname, MAXNAMELEN + 1);

			if ((rval != 0) && (ilp->lun_pip == NULL)) {
				return (ISCSI_STATUS_BUSY);
			}
		}
	}

	/* Attempt to offline the logical units */
	if (ilp->lun_pip != NULL) {

		/* virt/mdi */
		ndi_devi_enter(scsi_vhci_dip, &circ);
		if ((lun_free == B_TRUE) &&
		    (ilp->lun_state == ISCSI_LUN_STATE_ONLINE)) {
			rval = mdi_pi_offline(ilp->lun_pip,
			    NDI_DEVI_REMOVE);
		} else {
			rval = mdi_pi_offline(ilp->lun_pip, 0);
		}

		if (rval == MDI_SUCCESS) {
			ilp->lun_state = ISCSI_LUN_STATE_OFFLINE;
			if (lun_free == B_TRUE) {
				(void) mdi_prop_remove(ilp->lun_pip, NULL);
				(void) mdi_pi_free(ilp->lun_pip, 0);
			}
		} else {
			status = ISCSI_STATUS_INTERNAL_ERROR;
		}
		ndi_devi_exit(scsi_vhci_dip, circ);

	} else  {

		/* phys/ndi */
		ndi_devi_enter(ihp->hba_dip, &circ);
		if ((lun_free == B_TRUE) &&
		    (ilp->lun_state == ISCSI_LUN_STATE_ONLINE)) {
			rval = ndi_devi_offline(
			    ilp->lun_dip, NDI_DEVI_REMOVE);
		} else {
			rval = ndi_devi_offline(
			    ilp->lun_dip, 0);
		}
		if (rval != NDI_SUCCESS) {
			status = ISCSI_STATUS_INTERNAL_ERROR;
		} else {
			ilp->lun_state = ISCSI_LUN_STATE_OFFLINE;
		}
		ndi_devi_exit(ihp->hba_dip, circ);

	}
	return (status);
}
