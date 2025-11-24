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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2021 Racktop Systems, Inc.
 * Copyright 2023 Oxide Computer Company
 * Copyright 2025 Hans Rosenfeld
 */

/*
 * SNIA Multipath Management API implementation
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/disp.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/services.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/scsi/adapters/scsi_vhci.h>

/* used to manually force a request sense */
int vhci_force_manual_sense = 0;

#define	STD_ACTIVE_OPTIMIZED	0x0
#define	STD_ACTIVE_NONOPTIMIZED	0x1
#define	STD_STANDBY		0x2
#define	STD_UNAVAILABLE		0x3
#define	STD_TRANSITIONING	0xf

/*
 * MP-API Prototypes
 */
int vhci_mpapi_init(struct scsi_vhci *);
void vhci_mpapi_add_dev_prod(struct scsi_vhci *, char *);
int vhci_mpapi_ctl(dev_t, int, intptr_t, int, cred_t *, int *);
void vhci_update_mpapi_data(struct scsi_vhci *,
    scsi_vhci_lun_t *, mdi_pathinfo_t *);
void* vhci_get_mpapi_item(struct scsi_vhci *, mpapi_list_header_t *,
    uint8_t, void*);
int vhci_mpapi_sync_init_port_list(dev_info_t *, void *);
int vhci_mpapi_get_vhci(dev_info_t *, void *);
void vhci_mpapi_set_path_state(dev_info_t *, mdi_pathinfo_t *, int);
void vhci_mpapi_synthesize_tpg_data(struct scsi_vhci *, scsi_vhci_lun_t *,
    mdi_pathinfo_t *);
void vhci_mpapi_update_tpg_data(struct scsi_address *, char *, int);
int vhci_mpapi_update_tpg_acc_state_for_lu(struct scsi_vhci *,
    scsi_vhci_lun_t *);

/* Static Functions */
static int vhci_get_driver_prop(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_dev_prod_list(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_dev_prod_prop(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_lu_list(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_lu_list_from_tpg(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_tpg_list_for_lu(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_lu_prop(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_path_list_for_mp_lu(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_path_list_for_init_port(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_path_list_for_target_port(struct scsi_vhci *,
    mp_iocdata_t *, void *, void *, int);
static int vhci_get_path_prop(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_init_port_list(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_init_port_prop(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_target_port_prop(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_tpg_prop(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_target_port_list_for_tpg(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_set_tpg_access_state(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_prop_lb_list(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_get_prop_lb_prop(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_assign_lu_to_tpg(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_enable_auto_failback(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_disable_auto_failback(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_enable_path(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_disable_path(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_send_uscsi_cmd(dev_t dev, struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_set_lu_loadbalance_type(struct scsi_vhci *, mp_iocdata_t *,
    void *, void *, int);
static int vhci_mpapi_validate(void *, mp_iocdata_t *, int, cred_t *);
static uint64_t vhci_mpapi_create_oid(mpapi_priv_t *, uint8_t);
static int vhci_mpapi_ioctl(dev_t dev, struct scsi_vhci *, void *,
    mp_iocdata_t *, int, cred_t *);
static int vhci_mpapi_add_to_list(mpapi_list_header_t *, mpapi_item_list_t *);
static mpapi_item_list_t *vhci_mpapi_create_item(struct scsi_vhci *,
    uint8_t, void *);
static mpapi_item_list_t *vhci_mpapi_get_alua_item(struct scsi_vhci *,
    void *, void *, void *);
static mpapi_item_list_t *vhci_mpapi_get_tpg_item(struct scsi_vhci *,
    uint32_t, void *, char *, void *);
static mpapi_list_header_t *vhci_mpapi_create_list_head();
static int vhci_get_mpiocdata(const void *, mp_iocdata_t *, int);
static int vhci_is_model_type32(int);
static int vhci_mpapi_copyout_iocdata(void *, void *, int);
static int vhci_mpapi_chk_last_path(mdi_pathinfo_t *);
static int vhci_mpapi_sync_lu_oid_list(struct scsi_vhci *);
static void vhci_mpapi_set_lu_valid(struct scsi_vhci *, mpapi_item_t *, int);
static void vhci_mpapi_set_tpg_as_prop(struct scsi_vhci *, mpapi_item_t *,
    uint32_t);
static mpapi_item_list_t *vhci_mpapi_get_tpg_for_lun(struct scsi_vhci *,
    char *, void *, void *);
static int vhci_mpapi_check_tp_in_tpg(mpapi_tpg_data_t *tpgdata, void *tp);
static void vhci_mpapi_log_sysevent(dev_info_t *, uint64_t *, char *);
static mpapi_item_list_t *vhci_mpapi_match_pip(struct scsi_vhci *,
    mpapi_item_list_t *, void *);
static mpapi_item_list_t *vhci_mpapi_match_lu(struct scsi_vhci *,
    mpapi_item_list_t *, void *);
static void *vhci_mpapi_get_rel_tport_pair(struct scsi_vhci *vhci,
    mpapi_list_header_t *list, void *tgt_port, uint32_t rel_tid);

/*
 * Extern variables, structures and functions
 */
extern void	*vhci_softstate;
extern char	vhci_version_name[];
extern int vhci_tpgs_set_target_groups(struct scsi_address *, int, int);


extern void mdi_vhci_walk_phcis(dev_info_t *,
    int (*)(dev_info_t *, void *), void *);
extern void vhci_update_pathstates(void *);
extern int vhci_uscsi_iostart(struct buf *bp);

/*
 * Routine for SCSI VHCI MPAPI IOCTL implementation.
 */
/* ARGSUSED */
int
vhci_mpapi_ctl(dev_t dev, int cm, intptr_t data, int mode,
    cred_t *credp, int *rval)
{
	struct scsi_vhci		*vhci;
	dev_info_t			*vdip;
	int				retval = 0;
	mp_iocdata_t			mpio_blk;
	mp_iocdata_t			*mpioc = &mpio_blk;

	/* Check for validity of vhci structure */
	vhci = ddi_get_soft_state(vhci_softstate, MINOR2INST(getminor(dev)));
	if (vhci == NULL) {
		return (ENXIO);
	}

	mutex_enter(&vhci->vhci_mutex);
	if ((vhci->vhci_state & VHCI_STATE_OPEN) == 0) {
		mutex_exit(&vhci->vhci_mutex);
		return (ENXIO);
	}
	mutex_exit(&vhci->vhci_mutex);

	/* Get the vhci dip */
	vdip = vhci->vhci_dip;
	ASSERT(vdip != NULL);

	/*
	 * Get IOCTL parameters from userland
	 */
	if (vhci_get_mpiocdata((const void *)data, mpioc, mode) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_mpapi_ctl: "
		    "vhci_get_mpiocdata() failed"));
	}
	if (mpioc->mp_cmd < MP_API_SUBCMD_MIN ||
	    mpioc->mp_cmd > MP_API_SUBCMD_MAX) {
		return (ENXIO);
	}

	retval = vhci_mpapi_ioctl(dev, vhci, (void *)data, mpioc, mode, credp);

	return (retval);
}

/* ARGSUSED */
static int
vhci_mpapi_validate(void *udata, mp_iocdata_t *mpioc, int mode, cred_t *credp)
{
	int		rval = 0, olen = 0;
	int		mode32 = 0;

	if (vhci_is_model_type32(mode) == 1) {
		mode32 = 1;
	}

	switch (mpioc->mp_cmd) {

	case MP_GET_DEV_PROD_LIST:
	case MP_GET_LU_LIST: /* XXX: This wont come; Plugin already has it */
	case MP_GET_INIT_PORT_LIST: /* XXX: This call wont come either */
	case MP_GET_TPG_LIST:
	case MP_GET_PROPRIETARY_LOADBALANCE_LIST:
	{
		if ((mpioc->mp_olen == 0) ||
		    (mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen == 0) {
			/* We don't know alen yet, No point trying to set it */
			mpioc->mp_errno = MP_MORE_DATA;
			rval = MP_MORE_DATA;
		}
	}
	break;

	case MP_GET_DRIVER_PROP:
	{
		olen = sizeof (mp_driver_prop_t);

		if ((mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_olen < olen) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen < olen) {
			mpioc->mp_alen = olen;
			mpioc->mp_errno = MP_MORE_DATA;
		}
	}
	break;

	case MP_GET_DEV_PROD_PROP:
	{
		olen = sizeof (mp_dev_prod_prop_t);

		if ((mpioc->mp_olen < olen) ||
		    (mpioc->mp_ilen < sizeof (uint64_t)) ||
		    (mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen < olen) {
			mpioc->mp_alen = olen;
			mpioc->mp_errno = MP_MORE_DATA;
		}
	}
	break;

	case MP_GET_LU_PROP:
	{
		olen = sizeof (mp_logical_unit_prop_t);

		if ((mpioc->mp_ilen != sizeof (uint64_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_olen < olen) ||
		    (mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen < olen) {
			mpioc->mp_alen = olen;
			mpioc->mp_errno = MP_MORE_DATA;
		}
	}
	break;

	case MP_GET_PATH_PROP:
	{
		olen = sizeof (mp_path_prop_t);

		if ((mpioc->mp_ilen != sizeof (uint64_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_olen < olen) ||
		    (mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen < olen) {
			mpioc->mp_alen = olen;
			mpioc->mp_errno = MP_MORE_DATA;
		}
	}
	break;

	case MP_GET_INIT_PORT_PROP:
	{
		olen = sizeof (mp_init_port_prop_t);

		if ((mpioc->mp_ilen != sizeof (uint64_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_olen < olen) ||
		    (mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen < olen) {
			mpioc->mp_alen = olen;
			mpioc->mp_errno = MP_MORE_DATA;
		}
	}
	break;

	case MP_GET_TARGET_PORT_PROP:
	{
		olen = sizeof (mp_target_port_prop_t);

		if ((mpioc->mp_ilen != sizeof (uint64_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_olen < olen) ||
		    (mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen < olen) {
			mpioc->mp_alen = olen;
			mpioc->mp_errno = MP_MORE_DATA;
		}
	}
	break;

	case MP_GET_TPG_PROP:
	{
		olen = sizeof (mp_tpg_prop_t);

		if ((mpioc->mp_ilen != sizeof (uint64_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_olen < olen) ||
		    (mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen < olen) {
			mpioc->mp_alen = olen;
			mpioc->mp_errno = MP_MORE_DATA;
		}
	}
	break;

	case MP_GET_PROPRIETARY_LOADBALANCE_PROP:
	{
		olen = sizeof (mp_proprietary_loadbalance_prop_t);

		if ((mpioc->mp_ilen != sizeof (uint64_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_olen < olen) ||
		    (mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen < olen) {
			mpioc->mp_alen = olen;
			mpioc->mp_errno = MP_MORE_DATA;
		}
	}
	break;

	case MP_GET_PATH_LIST_FOR_MP_LU:
	case MP_GET_PATH_LIST_FOR_INIT_PORT:
	case MP_GET_PATH_LIST_FOR_TARGET_PORT:
	case MP_GET_LU_LIST_FROM_TPG:
	case MP_GET_TPG_LIST_FOR_LU:
	case MP_GET_TARGET_PORT_LIST_FOR_TPG:
	{
		if ((mpioc->mp_ilen != sizeof (uint64_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_olen == 0) ||
		    (mpioc->mp_obuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_READ)) {
			rval = EINVAL;
		}
		if (mpioc->mp_olen == 0) {
			/* We don't know alen yet, No point trying to set it */
			mpioc->mp_errno = MP_MORE_DATA;
			rval = MP_MORE_DATA;
		}
	}
	break;

	case MP_SET_TPG_ACCESS_STATE:
	{
		if (drv_priv(credp) != 0) {
			rval = EPERM;
			break;
		}
		if ((mpioc->mp_ilen != sizeof (mp_set_tpg_state_req_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_WRITE)) {
			rval = EINVAL;
		}
	}
	break;

	case MP_ENABLE_AUTO_FAILBACK:
	case MP_DISABLE_AUTO_FAILBACK:
	{
		if (drv_priv(credp) != 0) {
			rval = EPERM;
			break;
		}
		if ((mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_xfer !=  MP_XFER_WRITE)) {
			rval = EINVAL;
		}
	}
	break;

	case MP_ENABLE_PATH:
	case MP_DISABLE_PATH:
	{
		if (drv_priv(credp) != 0) {
			rval = EPERM;
			break;
		}
		if ((mpioc->mp_ilen != sizeof (uint64_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_xfer !=  MP_XFER_WRITE)) {
			rval = EINVAL;
		}
	}
	break;

	case MP_SEND_SCSI_CMD:
	{
		cred_t	*cr;
		int	olen = 0;

		cr = ddi_get_cred();
		if (drv_priv(credp) != 0 && drv_priv(cr) != 0) {
			rval = EPERM;
			break;
		}
		if (mode32 == 1) {
			olen = sizeof (struct uscsi_cmd32);
		} else {
			olen = sizeof (struct uscsi_cmd);
		}
		/* oid is in the ibuf and the uscsi cmd is in the obuf */
		if ((mpioc->mp_ilen != sizeof (uint64_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_olen != olen) ||
		    (mpioc->mp_obuf == NULL)) {
			rval = EINVAL;
		}
	}
	break;

	case MP_ASSIGN_LU_TO_TPG:
	{
		if (drv_priv(credp) != 0) {
			rval = EPERM;
			break;
		}
		if ((mpioc->mp_ilen != sizeof (mp_lu_tpg_pair_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_xfer !=  MP_XFER_WRITE)) {
			rval = EINVAL;
		}
	}
	break;

	case MP_SET_LU_LOADBALANCE_TYPE:
	{
		if (drv_priv(credp) != 0) {
			rval = EPERM;
			break;
		}
		if ((mpioc->mp_ilen != sizeof (mp_set_lu_lb_type_req_t)) ||
		    (mpioc->mp_ibuf == NULL) ||
		    (mpioc->mp_xfer != MP_XFER_WRITE)) {
			rval = EINVAL;
		}
	}
	break;

	default:
	{
		rval = EINVAL;
	}

	} /* Closing the main switch */

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_driver_prop(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	mp_driver_prop_t	*mpdp = (mp_driver_prop_t *)output_data;

	if (output_data == NULL) {
		return (EINVAL);
	}

	(void) strlcpy(mpdp->driverVersion, vhci_version_name,
	    sizeof (mpdp->driverVersion));
	mpdp->supportedLoadBalanceTypes =
	    MP_DRVR_LOAD_BALANCE_TYPE_NONE |
	    MP_DRVR_LOAD_BALANCE_TYPE_ROUNDROBIN |
	    MP_DRVR_LOAD_BALANCE_TYPE_LBA_REGION;
	mpdp->canSetTPGAccess = B_TRUE;
	mpdp->canOverridePaths = B_FALSE;
	mpdp->exposesPathDeviceFiles = B_FALSE;
	(void) strlcpy(mpdp->deviceFileNamespace, "/devices/scsi_vhci",
	    sizeof (mpdp->deviceFileNamespace));
	mpdp->onlySupportsSpecifiedProducts = 1;
	mpdp->maximumWeight = 1;
	mpdp->failbackPollingRateMax = 0;
	mpdp->currentFailbackPollingRate = 0;
	mpdp->autoFailbackSupport = MP_DRVR_AUTO_FAILBACK_SUPPORT;
	mutex_enter(&vhci->vhci_mutex);
	mpdp->autoFailbackEnabled =
	    ((vhci->vhci_conf_flags & VHCI_CONF_FLAGS_AUTO_FAILBACK) ?
	    1 : 0);
	mutex_exit(&vhci->vhci_mutex);
	mpdp->defaultLoadBalanceType =
	    MP_DRVR_LOAD_BALANCE_TYPE_ROUNDROBIN;
	mpdp->probingPollingRateMax = 0;
	mpdp->currentProbingPollingRate = 0;
	mpdp->autoProbingSupport = 0;
	mpdp->autoProbingEnabled = 0;

	if (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    mpioc->mp_olen, mode) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_driver_prop: "
		    "ddi_copyout() for 64-bit failed"));
		mpioc->mp_errno = EFAULT;
	} else {
		mpioc->mp_errno = 0;
		mpioc->mp_alen = sizeof (mp_iocdata_t);
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_dev_prod_list(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			count = 0, rval = 0;
	int			list_len = mpioc->mp_olen / sizeof (uint64_t);
	uint64_t		*oid_list = (uint64_t *)(output_data);
	mpapi_item_list_t	*ilist;

	if (output_data == NULL) {
		return (EINVAL);
	}

	/*
	 * XXX: Get the Plugin OID from the input_data and apply below
	 * Currently, we know we have only 1 plugin, so it ok to directly
	 * return this only plugin's device product list.
	 */

	ilist = vhci->mp_priv->
	    obj_hdr_list[MP_OBJECT_TYPE_DEVICE_PRODUCT]->head;

	while (ilist != NULL) {
		if (count < list_len) {
			oid_list[count] = (uint64_t)ilist->item->oid.raw_oid;
		} else {
			rval = MP_MORE_DATA;
		}
		ilist = ilist->next;
		count++;
	}

	mpioc->mp_alen = (uint32_t)(count * sizeof (uint64_t));
	if ((rval == MP_MORE_DATA) || (mpioc->mp_alen > mpioc->mp_olen)) {
		mpioc->mp_errno = MP_MORE_DATA;
		return (EINVAL);
	}

	if (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (count * sizeof (uint64_t)), mode) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_dev_prod_list: "
		    "ddi_copyout() failed"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	} else {
		mpioc->mp_errno = 0;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_dev_prod_prop(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	uint64_t		*oid = (uint64_t *)(input_data);
	mp_dev_prod_prop_t	*dev_prop = NULL;
	mpapi_item_list_t	*ilist;

	if ((output_data == NULL) || (input_data == NULL)) {
		return (EINVAL);
	}
	ilist = vhci->mp_priv->
	    obj_hdr_list[MP_OBJECT_TYPE_DEVICE_PRODUCT]->head;
	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid)) {
		ilist = ilist->next;
	}
	if (ilist != NULL) {
		dev_prop = (mp_dev_prod_prop_t *)(ilist->item->idata);
		if (dev_prop == NULL) {
			return (EINVAL);
		}
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_dev_prod_prop: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}
	/*
	 * Here were are not using the 'output_data' that is
	 * passed as the required information is already
	 * in the required format!
	 */
	if (ddi_copyout((void *)dev_prop, mpioc->mp_obuf,
	    sizeof (mp_dev_prod_prop_t), mode) != 0) {
		return (EFAULT);
	}
	return (rval);
}

/* ARGSUSED */
static int
vhci_get_lu_list(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			count = 0, rval = 0;
	int			list_len = mpioc->mp_olen / sizeof (uint64_t);
	uint64_t		*oid_list = (uint64_t *)(output_data);
	mpapi_item_list_t	*ilist;
	mpapi_lu_data_t		*ld;

	if (output_data == NULL) {
		return (EINVAL);
	}

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;

	while (ilist != NULL) {
		if (count < list_len) {
			oid_list[count] = (uint64_t)(ilist->item->oid.raw_oid);
		} else {
			rval = MP_MORE_DATA;
		}
		ld = ilist->item->idata;
		if (ld->valid == 0) {
			count--;
		}
		ilist = ilist->next;
		count++;
	}

	mpioc->mp_alen = (uint32_t)(count * sizeof (uint64_t));
	if ((rval == MP_MORE_DATA) || (mpioc->mp_alen > mpioc->mp_olen)) {
		mpioc->mp_errno = MP_MORE_DATA;
		return (EINVAL);
	}

	if (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (count * sizeof (uint64_t)), mode) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_lu_list: "
		    "ddi_copyout() FAILED"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	} else {
		mpioc->mp_errno = 0;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_lu_list_from_tpg(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			count = 0, rval = 0;
	int			list_len = mpioc->mp_olen / sizeof (uint64_t);
	uint64_t		*oid_list = (uint64_t *)(output_data);
	uint64_t		*oid = (uint64_t *)(input_data);
	mpapi_item_list_t	*ilist, *tpg_lu_list = NULL;
	mpapi_tpg_data_t	*mptpglu;
	mpapi_lu_data_t		*ld;

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_TARGET_PORT_GROUP]
	    ->head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid))
		ilist = ilist->next;

	if (ilist == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_lu_list_from_tpg: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		rval = EINVAL;
	} else if (*oid == ilist->item->oid.raw_oid) {
		mptpglu = (mpapi_tpg_data_t *)(ilist->item->idata);
		if (mptpglu->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_lu_list_from_"
			    "tpg: OID NOT FOUND - TPG IS INVALID"));
			mpioc->mp_errno = MP_DRVR_INVALID_ID;
			return (EINVAL);
		}
		tpg_lu_list = mptpglu->lu_list->head;
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_lu_list_from_tpg: "
		    "Unknown Error"));
	}

	while (tpg_lu_list != NULL) {
		if (count < list_len) {
			oid_list[count] = (uint64_t)tpg_lu_list->
			    item->oid.raw_oid;
		} else {
			rval = MP_MORE_DATA;
		}
		/*
		 * Get rid of the latest entry if item is invalid
		 */
		ld = tpg_lu_list->item->idata;
		if (ld->valid == 0) {
			count--;
		}
		tpg_lu_list = tpg_lu_list->next;
		count++;
	}

	mpioc->mp_alen = (uint32_t)(count * sizeof (uint64_t));
	if ((rval == MP_MORE_DATA) || (mpioc->mp_alen > mpioc->mp_olen)) {
		mpioc->mp_errno = MP_MORE_DATA;
		return (EINVAL);
	}

	if ((count > 0) && (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (count * sizeof (uint64_t)), mode) != 0)) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_lu_list_from_tpg: "
		    "ddi_copyout() FAILED"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_tpg_list_for_lu(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			count = 0, rval = 0;
	int			list_len = mpioc->mp_olen / sizeof (uint64_t);
	uint64_t		*oid_list = (uint64_t *)(output_data);
	uint64_t		*oid = (uint64_t *)(input_data);
	mpapi_item_list_t	*ilist, *mplu_tpg_list = NULL;
	mpapi_lu_data_t		*mplutpg;
	mpapi_tpg_data_t	*tpgd;

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid))
		ilist = ilist->next;

	if (ilist == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_tpg_list_for_lu: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		rval = EINVAL;
	} else if (*oid == ilist->item->oid.raw_oid) {
		mplutpg = (mpapi_lu_data_t *)(ilist->item->idata);
		if (mplutpg->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_tpg_list_for_"
			    "lu: OID NOT FOUND - LU IS OFFLINE"));
			mpioc->mp_errno = MP_DRVR_INVALID_ID;
			return (EINVAL);
		}
		mplu_tpg_list = mplutpg->tpg_list->head;
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_tpg_list_for_lu: "
		    "Unknown Error"));
	}

	while (mplu_tpg_list != NULL) {
		if (count < list_len) {
			oid_list[count] =
			    (uint64_t)mplu_tpg_list->item->oid.raw_oid;
		} else {
			rval = MP_MORE_DATA;
		}
		tpgd = mplu_tpg_list->item->idata;
		if (tpgd->valid == 0) {
			count--;
		}
		mplu_tpg_list = mplu_tpg_list->next;
		count++;
	}

	mpioc->mp_alen = (uint32_t)(count * sizeof (uint64_t));
	if ((rval == MP_MORE_DATA) || (mpioc->mp_alen > mpioc->mp_olen)) {
		mpioc->mp_errno = MP_MORE_DATA;
		return (EINVAL);
	}

	if ((count > 0) && (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (count * sizeof (uint64_t)), mode) != 0)) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_tpg_list_for_lu: "
		    "ddi_copyout() FAILED"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_lu_prop(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	uint64_t		*oid = (uint64_t *)(input_data);
	mp_logical_unit_prop_t	*mplup_prop;
	mpapi_item_list_t	*ilist;
	mpapi_lu_data_t		*mplup;

	mplup_prop = (mp_logical_unit_prop_t *)output_data;
	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid)) {
		ilist = ilist->next;
	}

	if (ilist != NULL) {
		mplup = (mpapi_lu_data_t *)(ilist->item->idata);
		if (mplup == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_lu_prop: "
			    "idata in ilist is NULL"));
			return (EINVAL);
		} else if (mplup->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_lu_prop: "
			    "OID NOT FOUND - LU GONE OFFLINE"));
			mpioc->mp_errno = MP_DRVR_INVALID_ID;
			return (EINVAL);
		}
		mplup_prop = (mp_logical_unit_prop_t *)(&mplup->prop);
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_lu_prop: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}

	/*
	 * Here were are not using the 'output_data' that is
	 * passed as the required information is already
	 * in the required format!
	 */
	if (ddi_copyout((void *)mplup_prop, mpioc->mp_obuf,
	    sizeof (mp_logical_unit_prop_t), mode) != 0) {
		return (EFAULT);
	}
	return (rval);
}

/* ARGSUSED */
static int
vhci_get_path_list_for_mp_lu(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			count = 0, rval = 0;
	int			list_len = mpioc->mp_olen / sizeof (uint64_t);
	uint64_t		*oid_list = (uint64_t *)(output_data);
	uint64_t		*oid = (uint64_t *)(input_data);
	mpapi_item_list_t	*ilist, *mplu_path_list = NULL;
	mpapi_lu_data_t		*mplup;
	mpapi_path_data_t	*mppathp;
	mdi_pathinfo_t		*pip;

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid))
		ilist = ilist->next;

	if (ilist == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_mp_lu: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		rval = EINVAL;
	} else if (*oid == ilist->item->oid.raw_oid) {
		mplup = (mpapi_lu_data_t *)(ilist->item->idata);
		if (mplup->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_"
			    "mp_lu: MP_DRVR_PATH_STATE_LU_ERR - LU OFFLINE"));
			mpioc->mp_errno = MP_DRVR_PATH_STATE_LU_ERR;
			return (EINVAL);
		}
		mplu_path_list = mplup->path_list->head;
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_mp_lu: "
		    "Unknown Error"));
	}

	while (mplu_path_list != NULL) {
		mppathp  = (mpapi_path_data_t *)(mplu_path_list->item->idata);
		/* skip a path that should be hidden. */
		if (!(mppathp->hide) && (mppathp->valid != 0)) {
			pip = (mdi_pathinfo_t *)mppathp->resp;
			mdi_hold_path(pip);
			/*
			 * check if the pip is marked as device removed.
			 * When pi_flag MDI_PATHINFO_FLAGS_DEVICE_REMOVED is set
			 * the node should have been destroyed but did not
			 * due to open on the client node.
			 * The driver tracks such a node through the hide flag
			 * and doesn't report it throuth ioctl response.
			 * The devinfo driver doesn't report such a path.
			 */
			if (!(MDI_PI_FLAGS_IS_DEVICE_REMOVED(pip))) {
				if (count < list_len) {
					oid_list[count] =
					    (uint64_t)mplu_path_list->
					    item->oid.raw_oid;
				} else {
					rval = MP_MORE_DATA;
				}
				count++;
			}
			mdi_rele_path(pip);
		}
		mplu_path_list = mplu_path_list->next;
	}

	mpioc->mp_alen = (uint32_t)(count * sizeof (uint64_t));
	if ((rval == MP_MORE_DATA) || (mpioc->mp_alen > mpioc->mp_olen)) {
		mpioc->mp_errno = MP_MORE_DATA;
		return (EINVAL);
	}

	if ((count > 0) && (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (count * sizeof (uint64_t)), mode) != 0)) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_mp_lu: "
		    "ddi_copyout() FAILED"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_path_list_for_init_port(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			count = 0, rval = 0;
	int			list_len = mpioc->mp_olen / sizeof (uint64_t);
	uint64_t		*oid_list = (uint64_t *)(output_data);
	uint64_t		*oid = (uint64_t *)(input_data);
	mpapi_item_list_t	*ilist, *mpinit_path_list = NULL;
	mpapi_initiator_data_t	*mpinitp;
	mpapi_path_data_t	*mppathp;
	mdi_pathinfo_t		*pip;

	ilist = vhci->mp_priv->
	    obj_hdr_list[MP_OBJECT_TYPE_INITIATOR_PORT]->head;

	/*
	 * While walking the mpapi database for initiator ports invalidate all
	 * initiator ports. The succeeding call to walk the phci list through
	 * MDI walker will validate the currently existing pHCIS.
	 */
	while (ilist != NULL) {
		mpinitp = ilist->item->idata;
		mpinitp->valid = 0;
		ilist = ilist->next;
	}

	mdi_vhci_walk_phcis(vhci->vhci_dip, vhci_mpapi_sync_init_port_list,
	    vhci);

	ilist = vhci->mp_priv->
	    obj_hdr_list[MP_OBJECT_TYPE_INITIATOR_PORT]->head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid))
		ilist = ilist->next;

	if (ilist == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_init_"
		    "port: OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		rval = EINVAL;
	} else if (*oid == ilist->item->oid.raw_oid) {
		mpinitp = (mpapi_initiator_data_t *)(ilist->item->idata);
		if (mpinitp->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_"
			    "init_port: OID NOT FOUND - INIT PORT INVALID"));
			mpioc->mp_errno = MP_DRVR_INVALID_ID;
			return (EINVAL);
		}
		mpinit_path_list = mpinitp->path_list->head;
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_init_"
		    "port: Unknown Error"));
	}

	while (mpinit_path_list != NULL) {
		mppathp  = (mpapi_path_data_t *)(mpinit_path_list->item->idata);
		/* skip a path that should be hidden. */
		if (!(mppathp->hide)) {
			pip = (mdi_pathinfo_t *)mppathp->resp;
			mdi_hold_path(pip);
			/*
			 * check if the pip is marked as device removed.
			 * When pi_flag MDI_PATHINFO_FLAGS_DEVICE_REMOVED is set
			 * the node should have been destroyed but did not
			 * due to open on the client node.
			 * The driver tracks such a node through the hide flag
			 * and doesn't report it throuth ioctl response.
			 * The devinfo driver doesn't report such a path.
			 */
			if (!(MDI_PI_FLAGS_IS_DEVICE_REMOVED(pip))) {
				if (count < list_len) {
					oid_list[count] =
					    (uint64_t)mpinit_path_list->
					    item->oid.raw_oid;
				} else {
					rval = MP_MORE_DATA;
				}
				count++;
			}
			mdi_rele_path(pip);
		}
		mpinit_path_list = mpinit_path_list->next;
	}

	mpioc->mp_alen = (uint32_t)(count * sizeof (uint64_t));
	if ((rval == MP_MORE_DATA) || (mpioc->mp_alen > mpioc->mp_olen)) {
		mpioc->mp_errno = MP_MORE_DATA;
		return (EINVAL);
	}

	if ((count > 0) && (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (count * sizeof (uint64_t)), mode) != 0)) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_init_"
		    "port: ddi_copyout() FAILED"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_path_list_for_target_port(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			count = 0, rval = 0;
	int			list_len = mpioc->mp_olen / sizeof (uint64_t);
	uint64_t		*oid_list = (uint64_t *)(output_data);
	uint64_t		*oid = (uint64_t *)(input_data);
	mpapi_item_list_t	*ilist, *mptp_path_list = NULL;
	mpapi_tport_data_t	*mptpp;
	mpapi_path_data_t	*mppathp;
	mdi_pathinfo_t		*pip;

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_TARGET_PORT]->head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid))
		ilist = ilist->next;

	if (ilist == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_target_"
		    "port: OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		rval = EINVAL;
	} else if (*oid == ilist->item->oid.raw_oid) {
		mptpp = (mpapi_tport_data_t *)(ilist->item->idata);
		if (mptpp->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_"
			    "target_port: OID NOT FOUND - TGT PORT INVALID"));
			mpioc->mp_errno = MP_DRVR_INVALID_ID;
			return (EINVAL);
		}
		mptp_path_list = mptpp->path_list->head;
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_target_"
		    "port: Unknown Error"));
	}

	while (mptp_path_list != NULL) {
		mppathp  = (mpapi_path_data_t *)(mptp_path_list->item->idata);
		/* skip a path that should be hidden. */
		if (!(mppathp->hide)) {
			pip = (mdi_pathinfo_t *)mppathp->resp;
			mdi_hold_path(pip);
			/*
			 * check if the pip is marked as device removed.
			 * When pi_flag MDI_PATHINFO_FLAGS_DEVICE_REMOVED is set
			 * the node should have been destroyed but did not
			 * due to open on the client node.
			 * The driver tracks such a node through the hide flag
			 * and doesn't report it throuth ioctl response.
			 * The devinfo driver doesn't report such a path.
			 */
			if (!(MDI_PI_FLAGS_IS_DEVICE_REMOVED(pip))) {
				if (count < list_len) {
					oid_list[count] =
					    (uint64_t)mptp_path_list->
					    item->oid.raw_oid;
				} else {
					rval = MP_MORE_DATA;
				}
				count++;
			}
			mdi_rele_path(pip);
		}
		mptp_path_list = mptp_path_list->next;
	}

	mpioc->mp_alen = (uint32_t)(count * sizeof (uint64_t));
	if ((rval == MP_MORE_DATA) || (mpioc->mp_alen > mpioc->mp_olen)) {
		mpioc->mp_errno = MP_MORE_DATA;
		return (EINVAL);
	}

	if ((count > 0) && (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (count * sizeof (uint64_t)), mode) != 0)) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_list_for_target_"
		    "port: ddi_copyout() FAILED"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_path_prop(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	uint64_t		oid;
	mp_path_prop_t		*mpp_prop = (mp_path_prop_t *)output_data;
	mpapi_item_list_t	*ilist;
	mpapi_path_data_t	*mpp;

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_PATH_LU]->head;

	rval = ddi_copyin(mpioc->mp_ibuf, &oid, mpioc->mp_ilen, mode);

	while ((ilist != NULL) && (oid != ilist->item->oid.raw_oid))
		ilist = ilist->next;

	if (ilist != NULL) {
		mpp = (mpapi_path_data_t *)(ilist->item->idata);
		if (mpp == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_prop: "
			    "idata in ilist is NULL"));
			return (EINVAL);
		}
		mpp_prop = (mp_path_prop_t *)(&mpp->prop);
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_path_prop: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}

	/*
	 * Here were are not using the 'output_data' that is
	 * passed as the required information is already
	 * in the required format!
	 */
	if (ddi_copyout((void *)mpp_prop, mpioc->mp_obuf,
	    sizeof (mp_path_prop_t), mode) != 0) {
		return (EFAULT);
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_init_port_list(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			count = 0, rval = 0;
	int			list_len = mpioc->mp_olen / sizeof (uint64_t);
	uint64_t		*oid_list = (uint64_t *)(output_data);
	mpapi_item_list_t	*ilist;
	mpapi_initiator_data_t	*initd;

	ilist = vhci->mp_priv->
	    obj_hdr_list[MP_OBJECT_TYPE_INITIATOR_PORT]->head;

	/*
	 * While walking the mpapi database for initiator ports invalidate all
	 * initiator ports. The succeeding call to walk the phci list through
	 * MDI walker will validate the currently existing pHCIS.
	 */
	while (ilist != NULL) {
		initd = ilist->item->idata;
		initd->valid = 0;
		ilist = ilist->next;
	}

	mdi_vhci_walk_phcis(vhci->vhci_dip, vhci_mpapi_sync_init_port_list,
	    vhci);

	ilist = vhci->mp_priv->
	    obj_hdr_list[MP_OBJECT_TYPE_INITIATOR_PORT]->head;

	while (ilist != NULL) {
		if (count < list_len) {
			oid_list[count] = (uint64_t)ilist->item->oid.raw_oid;
		} else {
			rval = MP_MORE_DATA;
		}
		/*
		 * Get rid of the latest entry if item is invalid
		 */
		initd = ilist->item->idata;
		if (initd->valid == 0) {
			count--;
		}
		ilist = ilist->next;
		count++;
	}

	mpioc->mp_alen = (uint32_t)(count * sizeof (uint64_t));
	if ((rval == MP_MORE_DATA) || (mpioc->mp_alen > mpioc->mp_olen)) {
		mpioc->mp_errno = MP_MORE_DATA;
		return (EINVAL);
	}

	if (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (count * sizeof (uint64_t)), mode) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_init_port_list: "
		    "ddi_copyout() FAILED"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	} else {
		mpioc->mp_errno = 0;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_init_port_prop(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	uint64_t		*oid = (uint64_t *)(input_data);
	mp_init_port_prop_t	*mpip_prop = (mp_init_port_prop_t *)output_data;
	mpapi_item_list_t	*ilist;
	mpapi_initiator_data_t	*mpip;

	ilist = vhci->mp_priv->
	    obj_hdr_list[MP_OBJECT_TYPE_INITIATOR_PORT]->head;

	/*
	 * While walking the mpapi database for initiator ports invalidate all
	 * initiator ports. The succeeding call to walk the phci list through
	 * MDI walker will validate the currently existing pHCIS.
	 */
	while (ilist != NULL) {
		mpip = ilist->item->idata;
		mpip->valid = 0;
		ilist = ilist->next;
	}

	mdi_vhci_walk_phcis(vhci->vhci_dip, vhci_mpapi_sync_init_port_list,
	    vhci);

	ilist = vhci->mp_priv->
	    obj_hdr_list[MP_OBJECT_TYPE_INITIATOR_PORT]->head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid)) {
		ilist = ilist->next;
	}

	if (ilist != NULL) {
		mpip = (mpapi_initiator_data_t *)(ilist->item->idata);
		if (mpip == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_init_port_prop:"
			    " idata in ilist is NULL"));
			return (EINVAL);
		} else if (mpip->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_init_port_prop"
			    ": OID NOT FOUND - INIT PORT IS INVALID"));
			mpioc->mp_errno = MP_DRVR_INVALID_ID;
			return (EINVAL);
		}
		mpip_prop = (mp_init_port_prop_t *)(&mpip->prop);
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_init_port_prop: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}

	/*
	 * Here were are not using the 'output_data' that is
	 * passed as the required information is already
	 * in the required format!
	 */
	if (ddi_copyout((void *)mpip_prop, mpioc->mp_obuf,
	    sizeof (mp_init_port_prop_t), mode) != 0) {
		return (EFAULT);
	}
	return (rval);
}

/* ARGSUSED */
static int
vhci_get_target_port_prop(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	uint64_t		*oid = (uint64_t *)(input_data);
	mp_target_port_prop_t	*mptp_prop;
	mpapi_item_list_t	*ilist;
	mpapi_tport_data_t	*mptp;

	mptp_prop = (mp_target_port_prop_t *)output_data;
	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_TARGET_PORT]->head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid)) {
		ilist = ilist->next;
	}

	if (ilist != NULL) {
		mptp = (mpapi_tport_data_t *)(ilist->item->idata);
		if (mptp == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_target_port_"
			    "prop: idata in ilist is NULL"));
			return (EINVAL);
		} else if (mptp->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_target_port_"
			    "prop: OID NOT FOUND - TARGET PORT INVALID"));
			mpioc->mp_errno = MP_DRVR_INVALID_ID;
			return (EINVAL);
		}
		mptp_prop = (mp_target_port_prop_t *)(&mptp->prop);
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_target_port_prop: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}
	/*
	 * Here were are not using the 'output_data' that is
	 * passed as the required information is already
	 * in the required format!
	 */
	if (ddi_copyout((void *)mptp_prop, mpioc->mp_obuf,
	    sizeof (mp_target_port_prop_t), mode) != 0) {
		return (EFAULT);
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_tpg_prop(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	uint64_t		*oid = (uint64_t *)(input_data);
	mp_tpg_prop_t		*mptpg_prop;
	mpapi_item_list_t	*ilist;
	mpapi_tpg_data_t	*mptpg;

	mptpg_prop = (mp_tpg_prop_t *)output_data;
	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_TARGET_PORT_GROUP]->
	    head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid)) {
		ilist = ilist->next;
	}

	if (ilist != NULL) {
		mptpg = (mpapi_tpg_data_t *)(ilist->item->idata);
		if (mptpg == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_tpg_prop: "
			    "idata in ilist is NULL"));
			return (EINVAL);
		} else if (mptpg->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_tpg_prop: "
			    "OID NOT FOUND - TPG INVALID"));
			mpioc->mp_errno = MP_DRVR_INVALID_ID;
			return (EINVAL);
		}
		mptpg_prop = (mp_tpg_prop_t *)(&mptpg->prop);
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_tpg_prop: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}
	/*
	 * Here were are not using the 'output_data' that is
	 * passed as the required information is already
	 * in the required format!
	 */
	if (ddi_copyout((void *)mptpg_prop, mpioc->mp_obuf,
	    sizeof (mp_tpg_prop_t), mode) != 0) {
		return (EFAULT);
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_target_port_list_for_tpg(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			count = 0, rval = 0;
	int			list_len = mpioc->mp_olen / sizeof (uint64_t);
	uint64_t		*oid_list = (uint64_t *)(output_data);
	uint64_t		*oid = (uint64_t *)(input_data);
	mpapi_item_list_t	*ilist, *tpg_tp_list = NULL;
	mpapi_tpg_data_t	*mptpgtp;
	mpapi_tport_data_t	*mptpp;

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_TARGET_PORT_GROUP]
	    ->head;

	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid))
		ilist = ilist->next;

	if (ilist == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_target_port_list_for_"
		    "tpg: OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		rval = EINVAL;
	} else if (*oid == ilist->item->oid.raw_oid) {
		mptpgtp = (mpapi_tpg_data_t *)(ilist->item->idata);
		if (mptpgtp->valid == 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_target_port_"
			    "list_for_tpg: OID NOT FOUND - TPG INVALID"));
			mpioc->mp_errno = MP_DRVR_INVALID_ID;
			return (EINVAL);
		}
		tpg_tp_list = mptpgtp->tport_list->head;
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_target_port_list_for_"
		    "tpg: Unknown Error"));
	}

	while (tpg_tp_list != NULL) {
		if (count < list_len) {
			oid_list[count] = (uint64_t)tpg_tp_list->
			    item->oid.raw_oid;
		} else {
			rval = MP_MORE_DATA;
		}
		mptpp = tpg_tp_list->item->idata;
		if (mptpp->valid == 0) {
			count--;
		}
		tpg_tp_list = tpg_tp_list->next;
		count++;
	}

	mpioc->mp_alen = (uint32_t)(count * sizeof (uint64_t));
	if ((rval == MP_MORE_DATA) || (mpioc->mp_alen > mpioc->mp_olen)) {
		mpioc->mp_errno = MP_MORE_DATA;
		return (EINVAL);
	}

	if ((count > 0) && (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (count * sizeof (uint64_t)), mode) != 0)) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_target_port_list_for_"
		    "tpg: ddi_copyout() FAILED"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_set_tpg_access_state(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0, retval = 0, held = 0;
	uint32_t		desired_state, t10_tpgid;
	uint64_t		lu_oid, tpg_oid;
	mp_set_tpg_state_req_t	mp_set_tpg;
	mpapi_item_list_t	*lu_list, *tpg_list;
	mpapi_tpg_data_t	*mptpgd;
	scsi_vhci_lun_t		*svl;
	scsi_vhci_priv_t	*svp;
	mdi_pathinfo_t		*pip;
	struct scsi_address	*ap = NULL;

	lu_list = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]
	    ->head;
	tpg_list = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_TARGET_PORT_GROUP]
	    ->head;

	rval = ddi_copyin(mpioc->mp_ibuf, &mp_set_tpg, mpioc->mp_ilen, mode);
	lu_oid = mp_set_tpg.luTpgPair.luId;
	tpg_oid = mp_set_tpg.luTpgPair.tpgId;
	desired_state = mp_set_tpg.desiredState;

	VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_set_tpg_access_state: lu_oid: %lx,"
	    "tpg_oid: %lx, des_as: %x\n", (long)lu_oid, (long)tpg_oid,
	    desired_state));

	while ((lu_list != NULL) && (lu_oid != lu_list->item->oid.raw_oid))
		lu_list = lu_list->next;
	while ((tpg_list != NULL) && (tpg_oid != tpg_list->item->oid.raw_oid))
		tpg_list = tpg_list->next;

	if ((lu_list == NULL) || (tpg_list == NULL)) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_tpg_access_state: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}
	if ((desired_state != MP_DRVR_ACCESS_STATE_ACTIVE) &&
	    (desired_state != MP_DRVR_ACCESS_STATE_ACTIVE_OPTIMIZED) &&
	    (desired_state != MP_DRVR_ACCESS_STATE_ACTIVE_NONOPTIMIZED) &&
	    (desired_state != MP_DRVR_ACCESS_STATE_STANDBY)) {
		mpioc->mp_errno = MP_DRVR_ILLEGAL_ACCESS_STATE_REQUEST;
		return (EINVAL);
	}
	mptpgd = (mpapi_tpg_data_t *)(tpg_list->item->idata);
	if (desired_state == mptpgd->prop.accessState) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_tpg_access_"
		    "state: TPG already in desired State"));
		return (EINVAL);
	}
	t10_tpgid = mptpgd->prop.tpgId;

	/*
	 * All input seems to be ok, Go ahead & change state.
	 */
	svl = ((mpapi_lu_data_t *)(lu_list->item->idata))->resp;
	if (!SCSI_FAILOVER_IS_TPGS(svl->svl_fops)) {

		VHCI_HOLD_LUN(svl, VH_SLEEP, held);
		/*
		 * retval specifically cares about failover
		 * status and not about this routine's success.
		 */
		retval = mdi_failover(vhci->vhci_dip, svl->svl_dip,
		    MDI_FAILOVER_SYNC);
		if (retval != 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_tpg_access_"
			    "state: FAILOVER FAILED: %x", retval));
			VHCI_RELEASE_LUN(svl);
			return (EIO);
		} else {
			/*
			 * Don't set TPG's accessState here. Let mdi_failover's
			 * call-back routine "vhci_failover()" call
			 * vhci_mpapi_update_tpg_acc_state_for_lu().
			 */
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_tpg_access_"
			    "state: FAILOVER SUCCESS: %x", retval));
		}
		VHCI_RELEASE_LUN(svl);
	} else {
		/*
		 * Send SET_TARGET_PORT_GROUP SCSI Command. This is supported
		 * ONLY by devices which have TPGS EXPLICIT Failover support.
		 */
		retval = mdi_select_path(svl->svl_dip, NULL,
		    MDI_SELECT_ONLINE_PATH, NULL, &pip);
		if ((rval != MDI_SUCCESS) || (pip == NULL)) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_tpg_access_"
			    "state: Unable to find path: %x", retval));
			return (EINVAL);
		}
		svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
		if (svp == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_tpg_access_"
			    "state: Unable to find vhci private data"));
			mdi_rele_path(pip);
			return (EINVAL);
		}
		if (svp->svp_psd == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_tpg_access_"
			    "state: Unable to find scsi device"));
			mdi_rele_path(pip);
			return (EINVAL);
		}
		mdi_rele_path(pip);
		ap = &svp->svp_psd->sd_address;
		ASSERT(ap != NULL);

		retval = vhci_tpgs_set_target_groups(ap, desired_state,
		    t10_tpgid);
		if (retval != 0) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_tpg_access_"
			    "state:(ALUA) FAILOVER FAILED: %x", retval));
			return (EIO);
		} else {
			/*
			 * Don't set accessState here.
			 * std_report_target_groups() call needs to sync up
			 * properly.
			 */
			VHCI_DEBUG(4, (CE_WARN, NULL, "vhci_set_tpg_access_"
			    "state:(ALUA) FAILOVER SUCCESS: %x", retval));

			VHCI_HOLD_LUN(svl, VH_NOSLEEP, held);
			if (!held) {
				return (TRAN_BUSY);
			} else {
				vhci_update_pathstates((void *)svl);
			}
			if (desired_state != mptpgd->prop.accessState &&
			    (desired_state != MP_DRVR_ACCESS_STATE_ACTIVE ||
			    (mptpgd->prop.accessState !=
			    MP_DRVR_ACCESS_STATE_ACTIVE_OPTIMIZED &&
			    mptpgd->prop.accessState !=
			    MP_DRVR_ACCESS_STATE_ACTIVE_NONOPTIMIZED))) {
				VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_tpg_"
				    "access_state: TPGAccessState NOT Set: "
				    "des_state=%x, cur_state=%x", desired_state,
				    mptpgd->prop.accessState));
				return (EIO);
			}

		}
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_prop_lb_list(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int		rval = 0;
	uint64_t	*oid_list = (uint64_t *)(output_data);

	oid_list[0] = 0;

	if (ddi_copyout(output_data, (void *)mpioc->mp_obuf,
	    (sizeof (uint64_t)), mode) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_prop_lb_list: "
		    "ddi_copyout() FAILED"));
		mpioc->mp_errno = EFAULT;
		rval = EINVAL;
	} else {
		mpioc->mp_errno = 0;
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_get_prop_lb_prop(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int rval = EINVAL;

	return (rval);
}

/*
 * Operation not supported currently as we do not know
 * support any devices that allow this in the first place.
 */
/* ARGSUSED */
static int
vhci_assign_lu_to_tpg(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int rval = ENOTSUP;

	return (rval);
}

/* ARGSUSED */
static int
vhci_enable_auto_failback(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	mpapi_item_list_t	*ilist;
	mpapi_lu_data_t		*lud;
	uint64_t		raw_oid;

	mutex_enter(&vhci->vhci_mutex);
	vhci->vhci_conf_flags |= VHCI_CONF_FLAGS_AUTO_FAILBACK;
	mutex_exit(&vhci->vhci_mutex);

	/* Enable auto-failback for each lun in MPAPI database */
	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;
	while (ilist != NULL) {
		lud = ilist->item->idata;
		lud->prop.autoFailbackEnabled = 1;
		ilist = ilist->next;
	}

	/*
	 * We don't really know the plugin OSN so just set 0, it will be ignored
	 * by libmpscsi_vhci.
	 */
	raw_oid = 0;
	vhci_mpapi_log_sysevent(vhci->vhci_dip, &raw_oid,
	    ESC_SUN_MP_PLUGIN_CHANGE);

	return (rval);
}

/* ARGSUSED */
static int
vhci_disable_auto_failback(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	mpapi_item_list_t	*ilist;
	mpapi_lu_data_t		*lud;
	uint64_t		raw_oid;

	mutex_enter(&vhci->vhci_mutex);
	vhci->vhci_conf_flags &= ~VHCI_CONF_FLAGS_AUTO_FAILBACK;
	mutex_exit(&vhci->vhci_mutex);

	/* Disable auto-failback for each lun in MPAPI database */
	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;
	while (ilist != NULL) {
		lud = ilist->item->idata;
		lud->prop.autoFailbackEnabled = 0;
		ilist = ilist->next;
	}

	/*
	 * We don't really know the plugin OSN so just set 0, it will be ignored
	 * by libmpscsi_vhci.
	 */
	raw_oid = 0;
	vhci_mpapi_log_sysevent(vhci->vhci_dip, &raw_oid,
	    ESC_SUN_MP_PLUGIN_CHANGE);

	return (rval);
}

/*
 * Find the oid in the object type list. If found lock and return
 * the item. If not found return NULL. The caller must unlock the item.
 */
void *
vhci_mpapi_hold_item(struct scsi_vhci *vhci, uint64_t *oid, uint8_t obj_type)
{
	mpapi_item_list_t	*ilist;

	ilist = vhci->mp_priv->obj_hdr_list[obj_type]->head;
	while ((ilist != NULL) && (*oid != ilist->item->oid.raw_oid))
		ilist = ilist->next;

	if (ilist == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_hold_item: "
		    "OID NOT FOUND. oid: %p", (void *)oid));
		return (NULL);
	}
	if (*oid == ilist->item->oid.raw_oid) {
		mutex_enter(&ilist->item->item_mutex);
		return (ilist);
	}
	VHCI_DEBUG(4, (CE_WARN, NULL, "vhci_mpapi_hold_item: "
	    "Unknown Error. oid: %p", (void *)oid));
	return (NULL);
}

/*
 * Check that the pip sent in by the user is still associated with
 * the same oid. This is done through checking the path name.
 */
mdi_pathinfo_t *
vhci_mpapi_chk_path(struct scsi_vhci *vhci, mpapi_item_list_t *ilist)
{
	mdi_pathinfo_t		*pip;
	mpapi_path_data_t	*mpp;

	mpp = (mpapi_path_data_t *)(ilist->item->idata);
	if (mpp == NULL || mpp->valid == 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_chk_path: "
		    "pathinfo is not valid: %p", (void *)mpp));
		return (NULL);
	}
	pip = mpp->resp;
	/* make sure it is the same pip by checking path */
	if (vhci_mpapi_match_pip(vhci, ilist, pip) == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_chk_path: "
		    "Can not match pip: %p", (void *)pip));
		return (NULL);
	}
	return (pip);
}

/*
 * Get the pip from the oid passed in. the vhci_mpapi_chk_path
 * will check the name with the passed in pip name.  the mdi_select_path()
 * path will lock the pip and this should get released by the caller
 */
mdi_pathinfo_t *
vhci_mpapi_hold_pip(struct scsi_vhci *vhci, mpapi_item_list_t *ilist, int flags)
{
	mdi_pathinfo_t		*pip, *opip, *npip;
	scsi_vhci_lun_t		*svl;
	int			rval;
	mpapi_path_data_t	*mpp;

	mpp = (mpapi_path_data_t *)(ilist->item->idata);
	pip = mpp->resp;
	/* make sure it is the same pip by checking path */
	if (vhci_mpapi_chk_path(vhci, ilist) == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_hold_pip: "
		    "Can not match pip: %p", (void *)pip));
		return (NULL);
	}

	svl = mdi_client_get_vhci_private(mdi_pi_get_client(pip));
	opip = npip = NULL;

	/*
	 * use the select path to find the right pip since
	 * it does all the state checking and locks the pip
	 */
	rval = mdi_select_path(svl->svl_dip, NULL,
	    flags, NULL, &npip);
	do {
		if ((rval != MDI_SUCCESS) || (npip == NULL)) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_hold_pip:"
			    " Unable to find path: %x.", rval));
			return (NULL);
		}
		if (npip == pip) {
			break;
		}
		opip = npip;
		rval = mdi_select_path(svl->svl_dip, NULL,
		    flags, opip, &npip);
		mdi_rele_path(opip);
	} while ((npip != NULL) && (rval == MDI_SUCCESS));
	return (npip);
}

/*
 * Initialize the uscsi command. Lock the pip and the item in
 * the item list.
 */
static mp_uscsi_cmd_t *
vhci_init_uscsi_cmd(struct scsi_vhci *vhci,
    mp_iocdata_t *mpioc, uint64_t *oid, mpapi_item_list_t **list)
{
	int			arq_enabled;
	mp_uscsi_cmd_t		*mp_uscmdp;
	scsi_vhci_priv_t	*svp;
	struct scsi_address	*ap;
	mdi_pathinfo_t		*pip;
	mpapi_item_list_t	*ilist;
	struct buf		*bp;

	VHCI_DEBUG(4, (CE_WARN, NULL,
	    "vhci_init_uscsi_cmd: enter"));

	*list = NULL;
	/* lock the item */
	if ((ilist = (mpapi_item_list_t *)vhci_mpapi_hold_item(
	    vhci, oid, MP_OBJECT_TYPE_PATH_LU)) == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "vhci_init_uscsi_cmd: exit EINVAL"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (NULL);
	}

	/* lock the pip */
	if ((pip = vhci_mpapi_hold_pip(vhci, ilist,
	    (MDI_SELECT_STANDBY_PATH | MDI_SELECT_ONLINE_PATH))) == 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "vhci_init_uscsi_cmd: exit PATH_UNAVAIL"));
		mpioc->mp_errno = MP_DRVR_PATH_UNAVAILABLE;
		mutex_exit(&ilist->item->item_mutex);
		return (NULL);
	};

	/* get the address of the pip */
	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
	if (svp == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_init_uscsi_cmd:"
		    " Unable to find vhci private data"));
		mpioc->mp_errno = MP_DRVR_PATH_UNAVAILABLE;
		mdi_rele_path(pip);
		mutex_exit(&ilist->item->item_mutex);
		return (NULL);
	}
	if (svp->svp_psd == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_init_uscsi_cmd:"
		    " Unable to find scsi device"));
		mpioc->mp_errno = MP_DRVR_PATH_UNAVAILABLE;
		mdi_rele_path(pip);
		mutex_exit(&ilist->item->item_mutex);
		return (NULL);
	}
	ap = &svp->svp_psd->sd_address;
	ASSERT(ap != NULL);

	/* initialize the buffer */
	bp = getrbuf(KM_SLEEP);
	ASSERT(bp != NULL);

	/* initialize the mp_uscsi_cmd */
	mp_uscmdp = kmem_zalloc((size_t)sizeof (mp_uscsi_cmd_t), KM_SLEEP);
	ASSERT(mp_uscmdp != NULL);
	mp_uscmdp->ap = ap;
	mp_uscmdp->pip = pip;
	mp_uscmdp->cmdbp = bp;
	mp_uscmdp->rqbp = NULL;

	bp->b_private = mp_uscmdp;

	/* used to debug a manual sense */
	if (vhci_force_manual_sense) {
		(void) scsi_ifsetcap(ap, "auto-rqsense", 0, 0);
	} else {
		if (scsi_ifgetcap(ap, "auto-rqsense", 1) != 1) {
			(void) scsi_ifsetcap(ap, "auto-rqsense", 1, 1);
		}
	}
	arq_enabled = scsi_ifgetcap(ap, "auto-rqsense", 1);
	if (arq_enabled == 1) {
		mp_uscmdp->arq_enabled = 1;
	} else {
		mp_uscmdp->arq_enabled = 0;
	}
	/* set the list pointer for the caller */
	*list = ilist;
	VHCI_DEBUG(4, (CE_WARN, NULL,
	    "vhci_init_uscsi_cmd: mp_uscmdp: %p ilist: %p mp_errno: %d "
	    "bp: %p arq: %d",
	    (void *)mp_uscmdp, (void *)*list, mpioc->mp_errno,
	    (void *)bp, arq_enabled));

	return (mp_uscmdp);
}


/*
 * Initialize the uscsi information and then issue the command.
 */
/* ARGSUSED */
static int
vhci_send_uscsi_cmd(dev_t dev, struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0, uioseg = 0;
	struct uscsi_cmd	*uscmdp;
	uint64_t		*oid = (uint64_t *)(input_data);
	mp_uscsi_cmd_t		*mp_uscmdp;
	mpapi_item_list_t	*ilist;

	VHCI_DEBUG(4, (CE_WARN, NULL,
	    "vhci_send_uscsi_cmd: enter: mode: %x", mode));
	mpioc->mp_errno = 0;
	mp_uscmdp = vhci_init_uscsi_cmd(vhci, mpioc, oid, &ilist);
	if (mp_uscmdp == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "vhci_send_uscsi_cmd: exit INVALID_ID. rval: %d", rval));
		return (EINVAL);
	}
	rval = scsi_uscsi_alloc_and_copyin((intptr_t)mpioc->mp_obuf,
	    mode, mp_uscmdp->ap, &uscmdp);
	if (rval != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_send_uscsi_cmd: "
		    "scsi_uscsi_alloc_and_copyin failed. rval: %d", rval));
		mpioc->mp_errno = EINVAL;
		mdi_rele_path(mp_uscmdp->pip);
		mutex_exit(&ilist->item->item_mutex);
		if (mp_uscmdp->cmdbp)
			freerbuf(mp_uscmdp->cmdbp);
		kmem_free(mp_uscmdp, sizeof (mp_uscsi_cmd_t));
		return (EINVAL);
	}
	/* initialize the mp_uscsi_cmd with the uscsi_cmd from uscsi_alloc */
	mp_uscmdp->uscmdp = uscmdp;

	uioseg = (mode & FKIOCTL) ? UIO_SYSSPACE : UIO_USERSPACE;

	/* start the command sending the buffer as an argument */
	rval = scsi_uscsi_handle_cmd(dev, uioseg,
	    uscmdp, vhci_uscsi_iostart, mp_uscmdp->cmdbp, mp_uscmdp);
	if (rval != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_send_uscsi_cmd: "
		    "scsi_uscsi_handle_cmd failed. rval: %d", rval));
		mpioc->mp_errno = EIO;
	}

	if (scsi_uscsi_copyout_and_free((intptr_t)mpioc->mp_obuf,
	    uscmdp) != 0 && rval == 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_send_uscsi_cmd: "
		    "scsi_uscsi_copyout_and_free failed. rval: %d", rval));
		mpioc->mp_errno = EFAULT;
		rval = EFAULT;
	}
	/* cleanup */
	mdi_rele_path(mp_uscmdp->pip);
	mutex_exit(&ilist->item->item_mutex);
	if (mp_uscmdp->cmdbp)
		freerbuf(mp_uscmdp->cmdbp);
	kmem_free(mp_uscmdp, sizeof (mp_uscsi_cmd_t));
	VHCI_DEBUG(4, (CE_WARN, NULL,
	    "vhci_send_uscsi_cmd: rval: %d mp_errno: %d",
	    rval, mpioc->mp_errno));

	return (rval);
}

static int vhci_set_lu_loadbalance_type(struct scsi_vhci *vhci,
    mp_iocdata_t *mpioc, void *input_data, void *output_data, int mode)
{
	int			rval = 0, held = 0;
	mp_set_lu_lb_type_req_t	mp_set_lu_lb_type;
	mpapi_item_list_t	*lu_list;
	mpapi_lu_data_t		*lu;
	scsi_vhci_lun_t		*svl;
	uint32_t		lb_type;
	uint64_t		lu_oid;

	lu_list =
	    vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;

	rval = ddi_copyin(mpioc->mp_ibuf, &mp_set_lu_lb_type, mpioc->mp_ilen,
	    mode);
	if (rval != DDI_SUCCESS) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_lu_loadbalance_type:"
		    "Unable to copyin mpioc: %d", rval));
		return (EFAULT);
	}

	lu_oid = mp_set_lu_lb_type.luId;
	lb_type = mp_set_lu_lb_type.desiredType;

	VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_set_lu_loadbalance_type: lu_oid: "
	    "%lx, lb_type: %x\n", (long)lu_oid, lb_type));

	while ((lu_list != NULL) && (lu_oid != lu_list->item->oid.raw_oid))
		lu_list = lu_list->next;

	if (lu_list == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_lu_loadbalance_type: "
		    "OID NOT FOUND"));
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}

	lu = (mpapi_lu_data_t *)lu_list->item->idata;
	svl = lu->resp;

	VHCI_HOLD_LUN(svl, VH_SLEEP, held);
	if (lb_type == LOAD_BALANCE_NONE) {
		lu->prop.currentLoadBalanceType =
		    MP_DRVR_LOAD_BALANCE_TYPE_NONE;
	} else if (lb_type == LOAD_BALANCE_RR) {
		lu->prop.currentLoadBalanceType =
		    MP_DRVR_LOAD_BALANCE_TYPE_ROUNDROBIN;
	} else if (lb_type == LOAD_BALANCE_LBA) {
		lu->prop.currentLoadBalanceType =
		    MP_DRVR_LOAD_BALANCE_TYPE_LBA_REGION;
	} else {
		mpioc->mp_errno = MP_DRVR_ILLEGAL_LOAD_BALANCING_TYPE;
		VHCI_RELEASE_LUN(svl);
		return (EINVAL);
	}

	rval = mdi_set_lb_policy(svl->svl_dip, lb_type);
	VHCI_RELEASE_LUN(svl);

	if (rval != MDI_SUCCESS) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_set_lu_loadbalance_type: "
		    "SET LOADBALANCE POLICY FAILED: %x:", rval));
		return (EIO);
	}

	return (rval);
}

/* ARGSUSED */
static int
vhci_enable_path(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	uint64_t		*oid = (uint64_t *)(input_data);
	mdi_pathinfo_t		*pip;
	mpapi_item_list_t	*ilist;
	mpapi_path_data_t	*mpp;

	if ((ilist = (mpapi_item_list_t *)vhci_mpapi_hold_item(vhci, oid,
	    MP_OBJECT_TYPE_PATH_LU)) == NULL) {
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}

	mpp = (mpapi_path_data_t *)(ilist->item->idata);
	pip = (mdi_pathinfo_t *)mpp->resp;

	if (vhci_mpapi_chk_path(vhci, ilist) == NULL) {
		mutex_exit(&ilist->item->item_mutex);
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}

	if (mdi_pi_enable_path(pip, USER_DISABLE) != 0) {
		rval = EFAULT;
	} else {
		mpp->prop.disabled = 0;
		vhci_mpapi_log_sysevent(vhci->vhci_dip,
		    &(((mpoid_t *)oid)->raw_oid), ESC_SUN_MP_PATH_CHANGE);
	}
	mutex_exit(&ilist->item->item_mutex);
	return (rval);
}

/* ARGSUSED */
static int
vhci_disable_path(struct scsi_vhci *vhci, mp_iocdata_t *mpioc,
    void *input_data, void *output_data, int mode)
{
	int			rval = 0;
	uint64_t		*oid = (uint64_t *)(input_data);
	mdi_pathinfo_t		*pip = NULL;
	mpapi_item_list_t	*ilist;
	mpapi_path_data_t	*mpp;

	if ((ilist = (mpapi_item_list_t *)vhci_mpapi_hold_item(vhci, oid,
	    MP_OBJECT_TYPE_PATH_LU)) == NULL) {
		mpioc->mp_errno = MP_DRVR_INVALID_ID;
		return (EINVAL);
	}

	mpp = (mpapi_path_data_t *)(ilist->item->idata);
	pip = (mdi_pathinfo_t *)mpp->resp;

	if (vhci_mpapi_chk_path(vhci, ilist) == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_disable_path: Request "
		    "received to disable last path. Cant disable, Sorry!"));
		mutex_exit(&ilist->item->item_mutex);
		return (EINVAL);
	}
	if (vhci_mpapi_chk_last_path(pip) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_disable_path(1): Request "
		    "received to disable last path. Cant disable, Sorry!"));
		mutex_exit(&ilist->item->item_mutex);
		return (EINVAL);
	}

	if (mdi_pi_disable_path(pip, USER_DISABLE) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_disable_path(2): Request "
		    "received to disable last path. Cant disable, Sorry!"));
		rval = EFAULT;
	} else {
		mpp->prop.disabled = 1;
		vhci_mpapi_log_sysevent(vhci->vhci_dip,
		    &(((mpoid_t *)oid)->raw_oid), ESC_SUN_MP_PATH_CHANGE);
	}
	mutex_exit(&ilist->item->item_mutex);

	return (rval);
}

/* ARGSUSED */
static int
vhci_mpapi_ioctl(dev_t dev, struct scsi_vhci *vhci, void *udata,
    mp_iocdata_t *mpioc, int mode, cred_t *credp)
{
	int		rval = 0;
	uint64_t	oid;
	void		*input_data = NULL, *output_data = NULL;

	/* validate mpioc */
	rval = vhci_mpapi_validate(udata, mpioc, mode, credp);

	if (rval == EINVAL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_ioctl: "
		    " vhci_mpapi_validate() Returned %x: INVALID DATA", rval));
		if (vhci_mpapi_copyout_iocdata(mpioc, udata, mode)) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_ioctl: "
			    "vhci_mpapi_copyout_iocdata FAILED in EINVAL"));
		}
		return (rval);
	} else if (rval == EPERM) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_ioctl: "
		    " vhci_mpapi_validate() Returned %x: NO CREDS", rval));
		if (vhci_mpapi_copyout_iocdata(mpioc, udata, mode)) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_ioctl: "
			    "vhci_mpapi_copyout_iocdata FAILED in EPERM"));
		}
		return (rval);
	/* Process good cases & also cases where we need to get correct alen */
	} else if ((rval == 0) || (rval == MP_MORE_DATA)) {
		/* allocate an input buffer */
		if ((mpioc->mp_ibuf) && (mpioc->mp_ilen != 0)) {
			input_data = kmem_zalloc(mpioc->mp_ilen,
			    KM_SLEEP);
			ASSERT(input_data != NULL);
			rval = ddi_copyin(mpioc->mp_ibuf,
			    input_data, mpioc->mp_ilen, mode);
			oid = (uint64_t)(*((uint64_t *)input_data));

			VHCI_DEBUG(7, (CE_NOTE, NULL, "Requesting op for "
			    "OID = %lx w/ mpioc = %p mp_cmd = %x\n",
			    (long)oid, (void *)mpioc, mpioc->mp_cmd));

		}
		if ((mpioc->mp_xfer == MP_XFER_READ) && (mpioc->mp_olen != 0)) {
			output_data = kmem_zalloc(mpioc->mp_olen, KM_SLEEP);
			ASSERT(output_data != NULL);
		}
	}

	if (vhci_mpapi_sync_lu_oid_list(vhci) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_mpapi_ioctl: "
		    "vhci_mpapi_sync_lu_oid_list() failed"));
	}
	mdi_vhci_walk_phcis(vhci->vhci_dip,
	    vhci_mpapi_sync_init_port_list, vhci);

	/* process ioctls */
	switch (mpioc->mp_cmd) {
	case MP_GET_DRIVER_PROP:
		rval = vhci_get_driver_prop(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_DEV_PROD_LIST:
		rval = vhci_get_dev_prod_list(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_DEV_PROD_PROP:
		rval = vhci_get_dev_prod_prop(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_LU_LIST:
		rval = vhci_get_lu_list(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_LU_LIST_FROM_TPG:
		rval = vhci_get_lu_list_from_tpg(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_TPG_LIST_FOR_LU:
		rval = vhci_get_tpg_list_for_lu(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_LU_PROP:
		rval = vhci_get_lu_prop(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_PATH_LIST_FOR_MP_LU:
		rval = vhci_get_path_list_for_mp_lu(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_PATH_LIST_FOR_INIT_PORT:
		rval = vhci_get_path_list_for_init_port(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_PATH_LIST_FOR_TARGET_PORT:
		rval = vhci_get_path_list_for_target_port(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_PATH_PROP:
		rval = vhci_get_path_prop(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_INIT_PORT_LIST: /* Not Required */
		rval = vhci_get_init_port_list(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_INIT_PORT_PROP:
		rval = vhci_get_init_port_prop(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_TARGET_PORT_PROP:
		rval = vhci_get_target_port_prop(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_TPG_LIST: /* Not Required */
		rval = vhci_get_tpg_list_for_lu(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_TPG_PROP:
		rval = vhci_get_tpg_prop(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_TARGET_PORT_LIST_FOR_TPG:
		rval = vhci_get_target_port_list_for_tpg(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_SET_TPG_ACCESS_STATE:
		rval = vhci_set_tpg_access_state(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_ASSIGN_LU_TO_TPG:
		rval = vhci_assign_lu_to_tpg(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_PROPRIETARY_LOADBALANCE_LIST:
		rval = vhci_get_prop_lb_list(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_GET_PROPRIETARY_LOADBALANCE_PROP:
		rval = vhci_get_prop_lb_prop(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_ENABLE_AUTO_FAILBACK:
		rval = vhci_enable_auto_failback(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_DISABLE_AUTO_FAILBACK:
		rval = vhci_disable_auto_failback(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_ENABLE_PATH:
		rval = vhci_enable_path(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_DISABLE_PATH:
		rval = vhci_disable_path(vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_SEND_SCSI_CMD:
		rval = vhci_send_uscsi_cmd(dev, vhci, mpioc,
		    input_data, output_data, mode);
		break;
	case MP_SET_LU_LOADBALANCE_TYPE:
		rval = vhci_set_lu_loadbalance_type(vhci, mpioc, input_data,
		    output_data, mode);
		break;
	default:
		rval = EINVAL;
		break;
	}

	VHCI_DEBUG(6, (CE_NOTE, NULL, "vhci_mpapi_ioctl: output_data = %p, "
	    "mp_obuf = %p, mp_olen = %lx, mp_alen = %lx, mp_errno = %x, "
	    "mode = %x, rval=%x\n", (void *)output_data, (void *)mpioc->mp_obuf,
	    mpioc->mp_olen, mpioc->mp_alen, mpioc->mp_errno, mode, rval));

	if (vhci_mpapi_copyout_iocdata(mpioc, udata, mode)) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_ioctl: "
		    "vhci_mpapi_copyout_iocdata FAILED"));
		rval = EFAULT;
	}

	if (input_data) {
		kmem_free(input_data, mpioc->mp_ilen);
	}

	if (output_data) {
		kmem_free(output_data, mpioc->mp_olen);
	}

	return (rval);
}

/* ARGSUSED */
int
vhci_mpapi_init(struct scsi_vhci *vhci)
{
	mpapi_item_list_t	*ilist;
	mpapi_item_t		*item;
	mp_driver_prop_t	*drv;
	uint8_t			i;

	/*
	 * This tstamp value is present in the upper 32-bits of all OIDs
	 * that are issued in this boot session. Use it to identify
	 * stale OIDs that an application/ioctl may pass to you and
	 * reject it - Done in vhci_mpapi_validate() routine.
	 */
	mutex_enter(&tod_lock);
	vhci->mp_priv->tstamp = (time32_t)(tod_get().tv_sec);
	mutex_exit(&tod_lock);

	for (i = 0; i < MP_MAX_OBJECT_TYPE; i++) {
		vhci->mp_priv->obj_hdr_list[i] = vhci_mpapi_create_list_head();
	}

	/*
	 * Let us now allocate and initialize the drv block.
	 */
	ilist = kmem_zalloc(sizeof (mpapi_item_list_t), KM_SLEEP);
	item = kmem_zalloc(sizeof (mpapi_item_t), KM_SLEEP);
	ilist->item = item;
	item->oid.raw_oid = vhci_mpapi_create_oid(vhci->mp_priv,
	    MP_OBJECT_TYPE_PLUGIN);
	drv = kmem_zalloc(sizeof (mp_driver_prop_t), KM_SLEEP);
	drv->driverVersion[0] = '\0';
	drv->supportedLoadBalanceTypes =
	    (MP_DRVR_LOAD_BALANCE_TYPE_ROUNDROBIN |
	    MP_DRVR_LOAD_BALANCE_TYPE_LBA_REGION);
	drv->canSetTPGAccess = TRUE;
	drv->canOverridePaths = FALSE;
	drv->exposesPathDeviceFiles = FALSE;
	drv->deviceFileNamespace[0] = '\0';
	drv->onlySupportsSpecifiedProducts = 1;
	drv->maximumWeight = 1;
	drv->failbackPollingRateMax = 0;
	drv->currentFailbackPollingRate = 0;
	drv->autoFailbackSupport = 1;
	drv->autoFailbackEnabled = 1;
	drv->defaultLoadBalanceType = MP_DRVR_LOAD_BALANCE_TYPE_ROUNDROBIN;
	drv->probingPollingRateMax = 0;
	drv->currentProbingPollingRate = 0;
	drv->autoProbingSupport = 0;
	drv->autoProbingEnabled = 0;
	item->idata = drv;
	mutex_init(&item->item_mutex, NULL, MUTEX_DRIVER, NULL);
	if (vhci_mpapi_add_to_list(vhci->mp_priv->obj_hdr_list
	    [MP_OBJECT_TYPE_PLUGIN], ilist) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_init: "
		    "vhci_mpapi_create_add_to_list() of PLUGIN failed"));
		return (EFAULT);

	}
	return (0);
}

void
vhci_mpapi_add_dev_prod(struct scsi_vhci *vhci, char *vidpid)
{
	mpapi_item_list_t	*dev_prod_list;
	mpapi_item_t		*dev_prod_item;
	mp_dev_prod_prop_t	*dev_prod;

	/* add to list */
	dev_prod_list = kmem_zalloc(sizeof (mpapi_item_list_t), KM_SLEEP);
	dev_prod_item = kmem_zalloc(sizeof (mpapi_item_t), KM_SLEEP);
	dev_prod_list->item = dev_prod_item;
	dev_prod_list->item->oid.raw_oid = vhci_mpapi_create_oid
	    (vhci->mp_priv, MP_OBJECT_TYPE_DEVICE_PRODUCT);
	dev_prod = kmem_zalloc(sizeof (mp_dev_prod_prop_t), KM_SLEEP);

	(void) strncpy(dev_prod->prodInfo.vendor, vidpid, strlen(vidpid));
	dev_prod->supportedLoadBalanceTypes =
	    MP_DRVR_LOAD_BALANCE_TYPE_ROUNDROBIN;
	dev_prod->id = dev_prod_list->item->oid.raw_oid;

	dev_prod_list->item->idata = dev_prod;
	(void) vhci_mpapi_add_to_list(vhci->mp_priv->obj_hdr_list
	    [MP_OBJECT_TYPE_DEVICE_PRODUCT], (void *)dev_prod_list);
	vhci_mpapi_log_sysevent(vhci->vhci_dip,
	    &(dev_prod_list->item->oid.raw_oid),
	    ESC_SUN_MP_DEV_PROD_ADD);
}

/* ARGSUSED */
static uint64_t
vhci_mpapi_create_oid(mpapi_priv_t *mp_priv, uint8_t obj_type)
{
	mpoid_t		oid;

	oid.disc_oid.tstamp = mp_priv->tstamp;
	oid.disc_oid.type = obj_type;
	oid.disc_oid.seq_id = ++(mp_priv->oid_seq[obj_type]);
	return (oid.raw_oid);
}

/* ARGSUSED */
static int
vhci_mpapi_add_to_list(mpapi_list_header_t *hdr, mpapi_item_list_t *item)
{

	mpapi_list_header_t	*tmp_hdr = hdr;
	mpapi_item_list_t	*tmp_item = item;

	if (item == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_add_to_list: "
		    "NULL item passed"));
		return (EFAULT);
	}
	if (hdr == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_add_to_list: "
		    "NULL hdr passed"));
		return (EFAULT);
	}
	/*
	 * Check if the item is already there in the list.
	 * Catches duplicates while assigning TPGs.
	 */
	tmp_item = tmp_hdr->head;
	while (tmp_item != NULL) {
		if (item == tmp_item) {
			VHCI_DEBUG(4, (CE_WARN, NULL, "vhci_mpapi_add_to_list: "
			    "Item already in list"));
			return (1);
		} else {
			tmp_item = tmp_item->next;
		}
	}

	item->next = NULL;
	if (hdr->head == NULL) {
		hdr->head = item;
		hdr->tail = item;
	} else {
		hdr->tail->next = item;
		hdr->tail = item;
	}

	return (0);
}

/*
 * Local convenience routine to fetch reference to a mpapi item entry if it
 * exits based on the pointer to the vhci resource that is passed.
 * Returns NULL if no entry is found.
 */
/* ARGSUSED */
void*
vhci_get_mpapi_item(struct scsi_vhci *vhci,  mpapi_list_header_t *list,
    uint8_t obj_type, void* res)
{
	mpapi_item_list_t	*ilist;

	if (list == NULL) {
		/*
		 * Since the listhead is null, the search is being
		 * performed in implicit mode - that is to use the
		 * level one list.
		 */
		ilist = vhci->mp_priv->obj_hdr_list[obj_type]->head;
	} else {
		/*
		 * The search is being performed on a sublist within
		 * one of the toplevel list items. Use the listhead
		 * that is passed in.
		 */
		ilist = list->head;
	}

	if (res == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_mpapi_item: "
		    " Got Item w/ NULL resource ptr"));
		return (NULL);
	}

	/*
	 * Since the resource field within the item data is specific
	 * to a particular object type, we need to use the object type
	 * to enable us to perform the search and compare appropriately.
	 */
	switch (obj_type) {
		case	MP_OBJECT_TYPE_INITIATOR_PORT:
			while (ilist) {
				void	*wwn = ((mpapi_initiator_data_t *)
				    ilist->item->idata)->resp;
				if (strncmp(wwn, res, strlen(res)) == 0) {
					/* Found a match */
					return ((void*)ilist);
				}
				ilist = ilist->next;
			}
		break;

		case	MP_OBJECT_TYPE_TARGET_PORT:
			while (ilist) {
				void	*wwn = ((mpapi_tport_data_t *)ilist->
				    item->idata)->resp;
				if (strncmp(wwn, res, strlen(res)) == 0) {
					/* Found a match */
					return ((void*)ilist);
				}
				ilist = ilist->next;
			}
		break;

		case	MP_OBJECT_TYPE_TARGET_PORT_GROUP:
			/*
			 * For TPG Synthesis, Use TPG specific routines
			 * Use this case only for ALUA devices which give TPG ID
			 */
			while (ilist) {
				void	*tpg_id = ((mpapi_tpg_data_t *)ilist->
				    item->idata)->resp;
				if (strncmp(tpg_id, res, strlen(res)) == 0) {
					/* Found a match */
					return ((void*)ilist);
				}
				ilist = ilist->next;
			}
		break;

		case	MP_OBJECT_TYPE_MULTIPATH_LU:
			return ((void *)(vhci_mpapi_match_lu
			    (vhci, ilist, res)));

		case	MP_OBJECT_TYPE_PATH_LU:
			return ((void *)(vhci_mpapi_match_pip
			    (vhci, ilist, res)));

		default:
			/*
			 * This should not happen
			 */
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_mpapi_item:"
			    "Got Unsupported OBJECT TYPE"));
			return (NULL);
	}
	return (NULL);
}

/*
 * Local convenience routine to create and initialize mpapi item
 * based on the object type passed.
 */
/* ARGSUSED */
static mpapi_item_list_t *
vhci_mpapi_create_item(struct scsi_vhci *vhci, uint8_t obj_type, void* res)
{
	int			major;
	int			instance;
	mpapi_item_list_t	*ilist;
	mpapi_item_t		*item;
	char			*pname = NULL;

	ilist = kmem_zalloc(sizeof (mpapi_item_list_t), KM_SLEEP);
	item = kmem_zalloc(sizeof (mpapi_item_t), KM_SLEEP);
	mutex_init(&item->item_mutex, NULL, MUTEX_DRIVER, NULL);
	ilist->item = item;
	item->oid.raw_oid = 0;

	switch (obj_type) {
		case	MP_OBJECT_TYPE_INITIATOR_PORT:
		{
			mpapi_initiator_data_t	*init;
			dev_info_t		*pdip = res;
			char			*init_port_res;
			char			*interconnect;
			int			mp_interconnect_type, len;
			int			prop_not_ddi_alloced = 0;

			pname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
			major = (int)ddi_driver_major(pdip);
			instance = ddi_get_instance(pdip);
			(void) ddi_pathname(pdip, pname);
			item->oid.raw_oid =
			    MP_STORE_INST_TO_ID(instance, item->oid.raw_oid);
			item->oid.raw_oid =
			    MP_STORE_MAJOR_TO_ID(major, item->oid.raw_oid);
			/*
			 * Just make a call to keep correct Sequence count.
			 * Don't use the OID returned though.
			 */
			(void) vhci_mpapi_create_oid(vhci->mp_priv, obj_type);
			init_port_res = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
			(void) strlcpy(init_port_res, pname, MAXPATHLEN);

			if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip, 0,
			    "initiator-interconnect-type",
			    &interconnect) != DDI_PROP_SUCCESS)) {
				/* XXX: initiator-interconnect-type not set */
				VHCI_DEBUG(1, (CE_WARN, NULL,
				    "vhci_mpapi_create_item: initiator-"
				    "-interconnect-type prop not found"));
				len = strlen("UNKNOWN") + 1;
				interconnect = kmem_zalloc(len, KM_SLEEP);
				(void) strlcpy(interconnect, "UNKNOWN", len);
				prop_not_ddi_alloced = 1;
			}
			/*
			 * Map the initiator-interconnect-type values between
			 * SCSA(as defined in services.h) and MPAPI
			 * (as defined in mpapi_impl.h)
			 */
			if (strncmp(interconnect,
			    INTERCONNECT_FABRIC_STR,
			    strlen(interconnect)) == 0) {
				mp_interconnect_type =
				    MP_DRVR_TRANSPORT_TYPE_FC;
			} else if (strncmp(interconnect,
			    INTERCONNECT_PARALLEL_STR,
			    strlen(interconnect)) == 0) {
				mp_interconnect_type =
				    MP_DRVR_TRANSPORT_TYPE_SPI;
			} else if (strncmp(interconnect,
			    INTERCONNECT_ISCSI_STR,
			    strlen(interconnect)) == 0) {
				mp_interconnect_type =
				    MP_DRVR_TRANSPORT_TYPE_ISCSI;
			} else if (strncmp(interconnect,
			    INTERCONNECT_IBSRP_STR,
			    strlen(interconnect)) == 0) {
				mp_interconnect_type =
				    MP_DRVR_TRANSPORT_TYPE_IFB;
			} else {
				mp_interconnect_type =
				    MP_DRVR_TRANSPORT_TYPE_UNKNOWN;
			}

			init = kmem_zalloc(
			    sizeof (mpapi_initiator_data_t), KM_SLEEP);
			init->resp = init_port_res;
			init->valid = 1;
			init->prop.id = item->oid.raw_oid;
			init->prop.portType = mp_interconnect_type;
			(void) strlcpy(init->prop.portID, pname,
			    sizeof (init->prop.portID));
			(void) strlcpy(init->prop.osDeviceFile, "/devices",
			    sizeof (init->prop.osDeviceFile));
			(void) strlcat(init->prop.osDeviceFile, pname,
			    sizeof (init->prop.osDeviceFile));
			init->path_list = vhci_mpapi_create_list_head();
			item->idata = (void *)init;
			vhci_mpapi_log_sysevent(vhci->vhci_dip,
			    &(item->oid.raw_oid), ESC_SUN_MP_INIT_PORT_CHANGE);

			if (prop_not_ddi_alloced != 1) {
				ddi_prop_free(interconnect);
			} else {
				kmem_free(interconnect, len);
			}
			if (pname) {
				kmem_free(pname, MAXPATHLEN);
			}
		}
		break;

		case	MP_OBJECT_TYPE_TARGET_PORT:
		{
			mpapi_tport_data_t	*tport;
			char			*tgt_port_res;

			item->oid.raw_oid =
			    vhci_mpapi_create_oid(vhci->mp_priv, obj_type);
			tport = kmem_zalloc(sizeof (mpapi_tport_data_t),
			    KM_SLEEP);
			tgt_port_res = kmem_zalloc(strlen(res) + 1, KM_SLEEP);
			(void) strlcpy(tgt_port_res, res, strlen(res) + 1);
			tport->resp = tgt_port_res;
			tport->valid = 1;
			tport->prop.id = item->oid.raw_oid;
			tport->prop.relativePortID = 0;
			(void) strlcpy(tport->prop.portName, res,
			    sizeof (tport->prop.portName));
			tport->path_list = vhci_mpapi_create_list_head();
			item->idata = (void *)tport;
			vhci_mpapi_log_sysevent(vhci->vhci_dip,
			    &(item->oid.raw_oid), ESC_SUN_MP_TARGET_PORT_ADD);
		}
		break;

		case	MP_OBJECT_TYPE_TARGET_PORT_GROUP:
		{
			mpapi_tpg_data_t	*tpg;
			char			*tpg_res;

			item->oid.raw_oid =
			    vhci_mpapi_create_oid(vhci->mp_priv, obj_type);
			tpg = kmem_zalloc(
			    sizeof (mpapi_tpg_data_t), KM_SLEEP);
			tpg_res = kmem_zalloc(strlen(res) + 1, KM_SLEEP);
			(void) strlcpy(tpg_res, res, strlen(res) + 1);
			tpg->resp = tpg_res;
			tpg->valid = 1;
			tpg->prop.id = item->oid.raw_oid;
			/*
			 * T10 TPG ID is a 2 byte value. Keep up with it.
			 */
			tpg->prop.tpgId =
			    ((item->oid.raw_oid) & 0x000000000000ffff);
			tpg->tport_list = vhci_mpapi_create_list_head();
			tpg->lu_list = vhci_mpapi_create_list_head();
			item->idata = (void *)tpg;
			vhci_mpapi_log_sysevent(vhci->vhci_dip,
			    &(item->oid.raw_oid), ESC_SUN_MP_TPG_ADD);
		}
		break;

		case	MP_OBJECT_TYPE_MULTIPATH_LU:
		{
			mpapi_lu_data_t	*lu;
			scsi_vhci_lun_t	*svl = res;
			client_lb_t	lb_policy;
			/*
			 * We cant use ddi_get_instance(svl->svl_dip) at this
			 * point because the dip is not yet in DS_READY state.
			 */
			item->oid.raw_oid =
			    vhci_mpapi_create_oid(vhci->mp_priv, obj_type);

			lu = kmem_zalloc(sizeof (mpapi_lu_data_t), KM_SLEEP);
			lu->resp = res;
			lu->prop.id = (uint64_t)item->oid.raw_oid;
			/*
			 * XXX: luGroupID is currently unsupported
			 */
			lu->prop.luGroupID = 0xFFFFFFFF;

			(void) strlcpy(lu->prop.name, svl->svl_lun_wwn,
			    sizeof (lu->prop.name));

			/*
			 * deviceFileName field is currently not used.
			 * Set to an empty string.
			 */
			lu->prop.deviceFileName[0] = '\0';

			if ((svl != NULL) &&
			    (SCSI_FAILOVER_IS_ASYM(svl) ||
			    SCSI_FAILOVER_IS_TPGS(svl->svl_fops))) {
				lu->prop.asymmetric = 1;
			}

			lu->prop.autoFailbackEnabled =
			    ((VHCI_CONF_FLAGS_AUTO_FAILBACK & vhci->
			    vhci_conf_flags) ? 1 : 0);

			/*
			 * Retrieve current load balance policy from mdi client.
			 * Both client and client's dip should already exist
			 * here and the client should be initialized.
			 */
			lb_policy = mdi_get_lb_policy(svl->svl_dip);
			if (lb_policy == LOAD_BALANCE_NONE) {
				lu->prop.currentLoadBalanceType =
				    MP_DRVR_LOAD_BALANCE_TYPE_NONE;
			} else if (lb_policy == LOAD_BALANCE_RR) {
				lu->prop.currentLoadBalanceType =
				    MP_DRVR_LOAD_BALANCE_TYPE_ROUNDROBIN;
			} else if (lb_policy == LOAD_BALANCE_LBA) {
				lu->prop.currentLoadBalanceType =
				    MP_DRVR_LOAD_BALANCE_TYPE_LBA_REGION;
			} else {
				/*
				 * We still map Load Balance Type to UNKNOWN
				 * although "none" also maps to the same case.
				 * MPAPI spec does not have a "NONE" LB type.
				 */
				lu->prop.currentLoadBalanceType =
				    MP_DRVR_LOAD_BALANCE_TYPE_UNKNOWN;
			}
			/*
			 * Allocate header lists for cross reference
			 */
			lu->path_list = vhci_mpapi_create_list_head();
			lu->tpg_list = vhci_mpapi_create_list_head();
			item->idata = (void *)lu;
			vhci_mpapi_set_lu_valid(vhci, item, 1);
		}
		break;

		case	MP_OBJECT_TYPE_PATH_LU:
		{
			mpapi_path_data_t	*path;
			mdi_pathinfo_t		*pip = res;
			scsi_vhci_lun_t		*svl;
			char			*iport, *tport;

			item->oid.raw_oid =
			    vhci_mpapi_create_oid(vhci->mp_priv, obj_type);
			path = kmem_zalloc(
			    sizeof (mpapi_path_data_t), KM_SLEEP);
			pname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

			iport = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
			(void) ddi_pathname(mdi_pi_get_phci(pip), iport);

			if (mdi_prop_lookup_string(pip,
			    SCSI_ADDR_PROP_TARGET_PORT, &tport) !=
			    DDI_PROP_SUCCESS) {
				/* XXX: target-port prop not found */
				tport = (char *)mdi_pi_get_addr(pip);
				VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_"
				    "create_item: mdi_prop_lookup_string() "
				    "returned failure; "));
			}

			svl = mdi_client_get_vhci_private
			    (mdi_pi_get_client(pip));

			(void) strlcat(pname, iport, MAXPATHLEN);
			(void) strlcat(pname, tport, MAXPATHLEN);
			(void) strlcat(pname, svl->svl_lun_wwn, MAXPATHLEN);
			kmem_free(iport, MAXPATHLEN);

			path->resp = res;
			path->path_name = pname;
			path->valid = 1;
			path->hide = 0;
			path->prop.id = item->oid.raw_oid;
			item->idata = (void *)path;
			vhci_mpapi_log_sysevent(vhci->vhci_dip,
			    &(item->oid.raw_oid), ESC_SUN_MP_PATH_ADD);
		}
		break;

		case	MP_OBJECT_TYPE_DEVICE_PRODUCT:
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_create_item:"
			    " DEVICE PRODUCT not handled here."));
		break;

		default:
			/*
			 * This should not happen
			 */
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_create_item:"
			    "Got Unsupported OBJECT TYPE"));
			return (NULL);
	}

	(void) vhci_mpapi_add_to_list(vhci->mp_priv->obj_hdr_list[obj_type],
	    ilist);
	return (ilist);
}

/*
 * Local routine to allocate mpapi list header block
 */
/* ARGSUSED */
static mpapi_list_header_t *
vhci_mpapi_create_list_head()
{
	mpapi_list_header_t	*lh;

	lh =  kmem_zalloc(sizeof (mpapi_list_header_t), KM_SLEEP);
	lh->head = lh->tail = NULL;
	return (lh);
}

/*
 * Routine to create Level 1 mpapi_private data structure and also
 * establish cross references between the resources being managed
 */
/* ARGSUSED */
void
vhci_update_mpapi_data(struct scsi_vhci *vhci, scsi_vhci_lun_t *vlun,
    mdi_pathinfo_t *pip)
{
	char			*tmp_wwn = NULL, *init = NULL, *path_class;
	dev_info_t		*pdip;
	mpapi_item_list_t	*lu_list, *path_list, *init_list, *tgt_list;
	mpapi_item_list_t	*tp_path_list, *init_path_list, *lu_path_list;
	mpapi_lu_data_t		*ld;
	mpapi_path_data_t	*pd;
	mpapi_tport_data_t	*tpd;
	mpapi_initiator_data_t	*initd;
	int			path_class_not_mdi_alloced = 0;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "vhci_update_mpapi_data: vhci: %p, "
	    "vlun: %p, pip: %p\n", (void *)vhci, (void *)vlun, (void *)pip));

	/*
	 * Check that the lun is not a TPGS device
	 * TPGS devices create the same information in another routine.
	 */
	if (SCSI_FAILOVER_IS_TPGS(vlun->svl_fops)) {
		return;
	}
	/*
	 * LEVEL 1 - Actions:
	 * Check if the appropriate resource pointers already
	 * exist in the Level 1 list and add them if they are new.
	 */

	/*
	 * Build MP LU list
	 */
	lu_list = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_MULTIPATH_LU, (void*)vlun);
	if (lu_list == NULL) {
		/* Need to create lu_list entry */
		lu_list = vhci_mpapi_create_item(vhci,
		    MP_OBJECT_TYPE_MULTIPATH_LU, (void*)vlun);
	} else {
		/*
		 * Matched this lu w/ an existing one in current lu list.
		 * SAME LUN came online!! So, update the resp in main list.
		 */
		ld = lu_list->item->idata;
		vhci_mpapi_set_lu_valid(vhci, lu_list->item, 1);
		ld->resp = vlun;
	}

	/*
	 * Find out the "path-class" property on the pip
	 */
	if (mdi_prop_lookup_string(pip, "path-class", &path_class)
	    != DDI_PROP_SUCCESS) {
		/* XXX: path-class prop not found */
		path_class = kmem_zalloc(MPAPI_SCSI_MAXPCLASSLEN, KM_SLEEP);
		(void) strlcpy(path_class, "NONE", MPAPI_SCSI_MAXPCLASSLEN);
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_update_mpapi_data: "
		    "mdi_prop_lookup_string() returned failure; "
		    "Hence path_class = NONE"));
		path_class_not_mdi_alloced = 1;
	}

	/*
	 * Build Path LU list
	 */
	path_list = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_PATH_LU, (void*)pip);
	if (path_list == NULL) {
		/* Need to create path_list entry */
		path_list = vhci_mpapi_create_item(vhci,
		    MP_OBJECT_TYPE_PATH_LU, (void*)pip);
	} else {
		/*
		 * Matched this pip w/ an existing one in current pip list.
		 * SAME PATH came online!! So, update the resp in main list.
		 */
		pd = path_list->item->idata;
		pd->valid = 1;
		pd->hide = 0;
		pd->resp = pip;
	}

	if (MDI_PI_IS_ONLINE(pip)) {
		vhci_mpapi_set_path_state(vhci->vhci_dip, pip,
		    MP_DRVR_PATH_STATE_ACTIVE);
	} else if (MDI_PI_IS_STANDBY(pip)) {
		vhci_mpapi_set_path_state(vhci->vhci_dip, pip,
		    MP_DRVR_PATH_STATE_PASSIVE);
	} else {
		vhci_mpapi_set_path_state(vhci->vhci_dip, pip,
		    MP_DRVR_PATH_STATE_UNKNOWN);
	}

	/*
	 * Build Initiator Port list
	 */
	pdip = mdi_pi_get_phci(pip);
	init = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(pdip, init);

	init_list = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_INITIATOR_PORT, (void*)init);
	if (init_list == NULL) {
		/*
		 * Need to create init_list entry
		 * The resource ptr is no really pdip. It will be changed
		 * in vhci_mpapi_create_item(). The real resource ptr
		 * is the Port ID. But we pass the pdip, to create OID.
		 */
		init_list = vhci_mpapi_create_item(vhci,
		    MP_OBJECT_TYPE_INITIATOR_PORT, (void*)pdip);
	} else {
		initd = init_list->item->idata;
		initd->valid = 1;
	}
	kmem_free(init, MAXPATHLEN);

	/*
	 * Build Target Port list
	 * Can get the tdip: tdip = mdi_pi_get_client(pip);
	 * But what's the use? We want TARGET_PORT.
	 * So try getting Target Port's WWN which is unique per port.
	 */
	tmp_wwn = NULL;
	if (mdi_prop_lookup_string(pip, SCSI_ADDR_PROP_TARGET_PORT,
	    &tmp_wwn) != DDI_PROP_SUCCESS) {
		/* XXX: target-port prop not found */
		tmp_wwn = (char *)mdi_pi_get_addr(pip);
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_update_mpapi_data: "
		    "mdi_prop_lookup_string() returned failure; "
		    "Hence tmp_wwn = %p", (void *)tmp_wwn));
	}

	tgt_list = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_TARGET_PORT, (void*)tmp_wwn);
	if (tgt_list == NULL) {
		/* Need to create tgt_list entry */
		tgt_list = vhci_mpapi_create_item(vhci,
		    MP_OBJECT_TYPE_TARGET_PORT, (void*)tmp_wwn);
	} else {
		tpd = tgt_list->item->idata;
		tpd->valid = 1;
	}

	/*
	 * LEVEL 2 - Actions:
	 * Since all the Object type item lists are updated to account
	 * for the new resources, now lets cross-reference these
	 * resources (mainly through paths) to maintain the
	 * relationship between them.
	 */

	ld = (mpapi_lu_data_t *)lu_list->item->idata;
	if (vhci_get_mpapi_item(vhci, ld->path_list,
	    MP_OBJECT_TYPE_PATH_LU, (void*)pip) == NULL) {
		lu_path_list = kmem_zalloc(sizeof (mpapi_item_list_t),
		    KM_SLEEP);
		lu_path_list->item = path_list->item;
		(void) vhci_mpapi_add_to_list(ld->path_list, lu_path_list);
	}

	initd = (mpapi_initiator_data_t *)init_list->item->idata;
	if (vhci_get_mpapi_item(vhci, initd->path_list,
	    MP_OBJECT_TYPE_PATH_LU, (void*)pip) == NULL) {
		init_path_list = kmem_zalloc(sizeof (mpapi_item_list_t),
		    KM_SLEEP);
		init_path_list->item = path_list->item;
		(void) vhci_mpapi_add_to_list(initd->path_list, init_path_list);
	}

	tpd = (mpapi_tport_data_t *)tgt_list->item->idata;
	if (vhci_get_mpapi_item(vhci, tpd->path_list,
	    MP_OBJECT_TYPE_PATH_LU, (void*)pip) == NULL) {
		tp_path_list = kmem_zalloc(
		    sizeof (mpapi_item_list_t), KM_SLEEP);
		tp_path_list->item = path_list->item;
		(void) vhci_mpapi_add_to_list(tpd->path_list, tp_path_list);
	}

	/*
	 * Level-1: Fill-out Path Properties now, since we got all details.
	 * Actually, It is a structure copy, rather than just filling details.
	 */
	pd = path_list->item->idata;
	(void) strlcpy(pd->pclass, path_class, sizeof (pd->pclass));
	bcopy(&(ld->prop), &(pd->prop.logicalUnit),
	    sizeof (struct mp_logical_unit_prop));
	bcopy(&(initd->prop), &(pd->prop.initPort),
	    sizeof (struct mp_init_port_prop));
	bcopy(&(tpd->prop), &(pd->prop.targetPort),
	    sizeof (struct mp_target_port_prop));

	vhci_mpapi_synthesize_tpg_data(vhci, vlun, pip);

	if (path_class_not_mdi_alloced == 1) {
		kmem_free(path_class, MPAPI_SCSI_MAXPCLASSLEN);
	}

}

/*
 * Routine to search (& return if found) a TPG object with a specified
 * tpg_id and rel_tp_id for a specified vlun structure. Returns NULL
 * if either TPG object or the lu item is not found.
 * This routine is used for TPGS(ALUA) devices.
 */
/* ARGSUSED */
static mpapi_item_list_t *
vhci_mpapi_get_alua_item(struct scsi_vhci *vhci, void *vlun, void *tpg_id,
    void *tp)
{
	mpapi_list_header_t	*this_tpghdr;
	mpapi_item_list_t	*tpglist, *this_lulist, *this_tpglist;
	mpapi_tpg_data_t	*tpgdata, *this_tpgdata;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "vhci_mpapi_get_alua_item: ENTER: vlun="
	    "%p, tpg_id=%s, tp=%s\n",
	    (void *)vlun, (char *)tpg_id, (char *)tp));

	/*
	 * Check if target port is already in any existing group
	 */
	tpglist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_TARGET_PORT_GROUP]
	    ->head;
	while (tpglist != NULL) {
		tpgdata = tpglist->item->idata;

		if ((tpgdata) &&
		    (vhci_mpapi_check_tp_in_tpg(tpgdata, tp) == 1) &&
		    (strcmp(tpgdata->resp, tpg_id) == 0)) {
			return (tpglist);
		} else {
			tpglist = tpglist->next;
		}
	}

	/*
	 * If target port is not existed, search TPG associated
	 * with this LU to see if this LU has a TPG with the same
	 * tpg_id.
	 */
	this_lulist = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_MULTIPATH_LU, vlun);
	if (this_lulist != NULL) {
		this_tpghdr = ((mpapi_lu_data_t *)(this_lulist->item->idata))
		    ->tpg_list;
		this_tpglist = this_tpghdr->head;
		while (this_tpglist != NULL) {
			this_tpgdata = this_tpglist->item->idata;
			if ((this_tpgdata) &&
			    (strcmp(this_tpgdata->resp, tpg_id) == 0)) {
				return (this_tpglist);
			} else {
				this_tpglist = this_tpglist->next;
			}
		}
	}

	VHCI_DEBUG(4, (CE_WARN, NULL, "vhci_mpapi_get_tpg_item: Returns NULL"));

	return (NULL);
}

/*
 * Routine to search (& return if found) a TPG object with a specified
 * accessState for a specified vlun structure. Returns NULL if either
 * TPG object or the lu item is not found.
 * This routine is used for NON-TPGS devices.
 */
/* ARGSUSED */
static mpapi_item_list_t *
vhci_mpapi_get_tpg_item(struct scsi_vhci *vhci, uint32_t acc_state, void *vlun,
    char *pclass, void *tp)
{
	mpapi_list_header_t	*tpghdr, *this_tpghdr;
	mpapi_item_list_t	*lulist, *tpglist, *this_lulist, *this_tpglist;
	mpapi_tpg_data_t	*tpgdata, *this_tpgdata;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "vhci_mpapi_get_tpg_item: ENTER: vlun="
	    "%p, acc_state=%x, pclass=%s, tp=%s\n",
	    (void *)vlun, acc_state, pclass, (char *)tp));

	lulist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;

	while (lulist != NULL) {
		tpghdr = ((mpapi_lu_data_t *)(lulist->item->idata))->tpg_list;
		tpglist = tpghdr->head;
		while (tpglist != NULL) {
			tpgdata = tpglist->item->idata;

			if ((tpgdata) &&
			    (vhci_mpapi_check_tp_in_tpg(tpgdata, tp) == 1) &&
			    (strncmp(tpgdata->pclass, pclass,
			    strlen(pclass)) == 0)) {
				return (tpglist);
			} else {
				tpglist = tpglist->next;
			}
		}
		lulist = lulist->next;
	}

	this_lulist = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_MULTIPATH_LU, vlun);
	if (this_lulist != NULL) {
		this_tpghdr = ((mpapi_lu_data_t *)(this_lulist->item->idata))
		    ->tpg_list;
		this_tpglist = this_tpghdr->head;
		while (this_tpglist != NULL) {
			this_tpgdata = this_tpglist->item->idata;

			if ((this_tpgdata) &&
			    (strncmp(this_tpgdata->pclass, pclass,
			    strlen(pclass)) == 0)) {
				return (this_tpglist);
			} else {
				this_tpglist = this_tpglist->next;
			}
		}
	}

	VHCI_DEBUG(4, (CE_WARN, NULL, "vhci_mpapi_get_tpg_item: Returns NULL"));

	return (NULL);
}

/*
 * Routine to search (& return if found) a TPG object with a specified
 * accessState for a specified vlun structure. Returns NULL if either
 * TPG object or the lu item is not found.
 * This routine is used for NON-TPGS devices.
 */
/* ARGSUSED */
mpapi_item_list_t *
vhci_mpapi_get_tpg_for_lun(struct scsi_vhci *vhci, char *pclass,
    void *vlun, void *tp)
{
	mpapi_list_header_t	*this_tpghdr;
	mpapi_item_list_t	*this_lulist, *this_tpglist;
	mpapi_tpg_data_t	*this_tpgdata;

	VHCI_DEBUG(4, (CE_NOTE, NULL, "vhci_mpapi_get_tpg_for_lun: ENTER: vlun="
	    "%p, pclass=%s, tp=%s\n", (void *)vlun, pclass, (char *)tp));

	this_lulist = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_MULTIPATH_LU, vlun);
	if (this_lulist != NULL) {
		this_tpghdr = ((mpapi_lu_data_t *)(this_lulist->item->idata))
		    ->tpg_list;
		this_tpglist = this_tpghdr->head;
		while (this_tpglist != NULL) {
			this_tpgdata = this_tpglist->item->idata;

			if ((this_tpgdata) &&
			    (vhci_mpapi_check_tp_in_tpg(this_tpgdata,
			    tp) == 1) && (strncmp(this_tpgdata->pclass, pclass,
			    strlen(pclass)) == 0)) {
				return (this_tpglist);
			}
			this_tpglist = this_tpglist->next;
		}
	}

	VHCI_DEBUG(4, (CE_WARN, NULL, "vhci_mpapi_get_tpg_for_lun: Returns "
	    "NULL"));

	return (NULL);
}

/*
 * Routine to search a Target Port in a TPG
 */
/* ARGSUSED */
static int
vhci_mpapi_check_tp_in_tpg(mpapi_tpg_data_t *tpgdata, void *tp)
{
	mpapi_item_list_t	*tplist;

	if (tpgdata) {
		tplist = tpgdata->tport_list->head;
	} else {
		return (0);
	}

	while (tplist != NULL) {
		void	*resp = ((mpapi_tport_data_t *)tplist->
		    item->idata)->resp;
		if (strncmp(resp, tp, strlen(resp)) == 0) {
			/* Found a match */
			return (1);
		}
		tplist = tplist->next;
	}

	return (0);
}

/*
 * Routine to create Level 1 mpapi_private data structure for TPG object &
 * establish cross references between the TPG resources being managed.
 * TPG SYNTHESIS MODE: Process for NON-SCSI_FAILOVER_IS_TPGS devices ONLY.
 * SCSI_FAILOVER_IS_TPGS devices have TPGS(ALUA support) and provide
 * REPORT_TARGET_PORT_GROUP data which we can parse directly in the next
 * routine(vhci_mpapi_update_tpg_data) to create TPG list in mpapi_priv block.
 */
/* ARGSUSED */
void
vhci_mpapi_synthesize_tpg_data(struct scsi_vhci *vhci, scsi_vhci_lun_t *vlun,
    mdi_pathinfo_t *pip)
{
	uint32_t		as;
	char			*tmp_wwn = NULL, *path_class = NULL;
	mpapi_item_list_t	*tpg_tport_list, *tpg_lu_list, *lu_list;
	mpapi_item_list_t	*lu_tpg_list, *item_list, *tpg_list;
	mpapi_tpg_data_t	*tpg_data;
	int			path_class_not_mdi_alloced = 0;

	/*
	 * Build Target Port Group list
	 * Start by finding out the affected Target Port.
	 */
	if (mdi_prop_lookup_string(pip, SCSI_ADDR_PROP_TARGET_PORT,
	    &tmp_wwn) != DDI_PROP_SUCCESS) {
		/* XXX: target-port prop not found */
		tmp_wwn = (char *)mdi_pi_get_addr(pip);
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_synthesize_tpg_data: "
		    "mdi_prop_lookup_string() returned failure; "
		    "Hence tmp_wwn = %p", (void *)tmp_wwn));
	}

	/*
	 * Finding out the "path-class" property
	 */
	if (mdi_prop_lookup_string(pip, "path-class", &path_class)
	    != DDI_PROP_SUCCESS) {
		/* XXX: path-class prop not found */
		path_class = kmem_zalloc(MPAPI_SCSI_MAXPCLASSLEN, KM_SLEEP);
		(void) strlcpy(path_class, "NONE", MPAPI_SCSI_MAXPCLASSLEN);
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_synthesize_tpg_data: "
		    "mdi_prop_lookup_string() returned failure; "
		    "Hence path_class = NONE"));
		path_class_not_mdi_alloced = 1;
	}

	/*
	 * Check the vlun's accessState through pip; we'll use it later.
	 */
	if (MDI_PI_IS_ONLINE(pip)) {
		as = MP_DRVR_ACCESS_STATE_ACTIVE;
	} else if (MDI_PI_IS_STANDBY(pip)) {
		as = MP_DRVR_ACCESS_STATE_STANDBY;
	} else {
		as = MP_DRVR_ACCESS_STATE_UNAVAILABLE;
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_synthesize_tpg_data: "
		    "Unknown pip state seen in TPG synthesis"));
	}

	VHCI_DEBUG(4, (CE_NOTE, NULL, "vhci_mpapi_synthesize_tpg_data: ENTER: "
	    "vlun=%s, acc_state=%x, path_class=%s, tp=%s\n",
	    vlun->svl_lun_wwn, as, path_class, tmp_wwn));

	/*
	 * Create Level 1 and Level 2 data structures for type
	 */
	if (!SCSI_FAILOVER_IS_TPGS(vlun->svl_fops)) {
		/*
		 * First check if the lun has a TPG list in its level 2
		 * structure then, check if this lun is already
		 * accounted for through a different Target Port.
		 * If yes, get the ptr to the TPG & skip new TPG creation.
		 */
		lu_list = vhci_get_mpapi_item(vhci, NULL,
		    MP_OBJECT_TYPE_MULTIPATH_LU, vlun);
		tpg_list = vhci_mpapi_get_tpg_item(vhci, as, vlun, path_class,
		    (void *)tmp_wwn);
		if (tpg_list == NULL) {
			tpg_list = vhci_mpapi_create_item(vhci,
			    MP_OBJECT_TYPE_TARGET_PORT_GROUP, (void *)tmp_wwn);
			tpg_data = tpg_list->item->idata;
			(void) strlcpy(tpg_data->pclass, path_class,
			    sizeof (tpg_data->pclass));
			tpg_data->prop.accessState = as;
		} else {
			tpg_data = tpg_list->item->idata;
		}

		if ((vlun != NULL) && SCSI_FAILOVER_IS_ASYM(vlun)) {
			tpg_data->prop.explicitFailover = 1;
		}

		/*
		 * Level 2, Lun Cross referencing to TPG.
		 */
		if (vhci_get_mpapi_item(vhci, tpg_data->lu_list,
		    MP_OBJECT_TYPE_MULTIPATH_LU, (void *)vlun) == NULL) {
			tpg_lu_list = kmem_zalloc(sizeof (mpapi_item_list_t),
			    KM_SLEEP);
			item_list = vhci_get_mpapi_item(vhci, NULL,
			    MP_OBJECT_TYPE_MULTIPATH_LU, (void *)vlun);
			tpg_lu_list->item = item_list->item;
			(void) vhci_mpapi_add_to_list(tpg_data->lu_list,
			    tpg_lu_list);
		}

		/*
		 * Level 2, Target Port Cross referencing to TPG.
		 */
		if (vhci_get_mpapi_item(vhci, tpg_data->tport_list,
		    MP_OBJECT_TYPE_TARGET_PORT, (void *)tmp_wwn) == NULL) {
			tpg_tport_list = kmem_zalloc(sizeof (mpapi_item_list_t),
			    KM_SLEEP);
			item_list = vhci_get_mpapi_item(vhci, NULL,
			    MP_OBJECT_TYPE_TARGET_PORT, (void *)tmp_wwn);
			tpg_tport_list->item = item_list->item;
			(void) vhci_mpapi_add_to_list(tpg_data->tport_list,
			    tpg_tport_list);
		}

		/*
		 * Level 2, TPG Cross referencing to Lun.
		 */
		lu_tpg_list = vhci_mpapi_get_tpg_for_lun
		    (vhci, path_class, vlun, tmp_wwn);
		if (lu_tpg_list == NULL) {
			lu_tpg_list = kmem_zalloc(sizeof (mpapi_item_list_t),
			    KM_SLEEP);
			lu_tpg_list->item = tpg_list->item;
			(void) vhci_mpapi_add_to_list(((mpapi_lu_data_t *)
			    (lu_list->item->idata))->tpg_list, lu_tpg_list);
		}

		/*
		 * Update the AccessState of related MPAPI TPGs
		 * This takes care of a special case where a failover doesn't
		 * happen but a TPG accessState needs to be updated from
		 * Unavailable to Standby
		 */
		(void) vhci_mpapi_update_tpg_acc_state_for_lu(vhci, vlun);
	}

	if (path_class_not_mdi_alloced == 1) {
		kmem_free(path_class, MPAPI_SCSI_MAXPCLASSLEN);
	}

}

/*
 * Routine to create Level 1 mpapi_private data structure for TPG object,
 * for devices which support TPG and establish cross references between
 * the TPG resources being managed. The RTPG response sent by std_asymmetric
 * module is parsed in this routine and mpapi_priv data structure is updated.
 */
/* ARGSUSED */
void
vhci_mpapi_update_tpg_data(struct scsi_address *ap, char *ptr,
    int rel_tgt_port)
{
	struct scsi_vhci_lun	*vlun;
	struct scsi_vhci	*vhci;
	struct scsi_device	*psd = NULL;
	scsi_vhci_priv_t	*svp;
	mdi_pathinfo_t		*pip;
	dev_info_t		*pdip;
	char			tpg_id[16], *tgt_port, *init = NULL;
	uint32_t		int_tpg_id, rel_tid, as;
	int			i, rel_tport_cnt;
	mpapi_item_list_t	*path_list, *init_list;
	mpapi_item_list_t	*tp_path_list, *init_path_list, *lu_path_list;
	mpapi_item_list_t	*tpg_tport_list, *tpg_lu_list, *lu_list;
	mpapi_item_list_t	*lu_tpg_list, *item_list, *tpg_list, *tgt_list;
	mpapi_lu_data_t		*ld;
	mpapi_tpg_data_t	*tpg_data;
	mpapi_path_data_t	*pd;
	mpapi_tport_data_t	*tpd;
	mpapi_initiator_data_t	*initd;

	/*
	 * Find out the TPG ID (resource ptr for TPG is T10 TPG ID)
	 */
	int_tpg_id = ((ptr[2] & 0xff) << 8) | (ptr[3] & 0xff);
	(void) sprintf(tpg_id, "%04x", int_tpg_id);

	/*
	 * Check the TPG's accessState; we'll use it later.
	 */
	as = (ptr[0] & 0x0f);
	if (as == STD_ACTIVE_OPTIMIZED) {
		as = MP_DRVR_ACCESS_STATE_ACTIVE_OPTIMIZED;
	} else if (as == STD_ACTIVE_NONOPTIMIZED) {
		as = MP_DRVR_ACCESS_STATE_ACTIVE_NONOPTIMIZED;
	} else if (as == STD_STANDBY) {
		as = MP_DRVR_ACCESS_STATE_STANDBY;
	} else {
		as = MP_DRVR_ACCESS_STATE_UNAVAILABLE;
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_update_tpg_data: "
		    "UNAVAILABLE accessState seen in ALUA TPG setup"));
	}

	/*
	 * The scsi_address passed is associated with a scsi_vhci allocated
	 * scsi_device structure for a pathinfo node. Getting the vlun from
	 * this is a bit complicated.
	 */
	if (ap->a_hba_tran->tran_hba_flags & SCSI_HBA_ADDR_COMPLEX)
		psd = scsi_address_device(ap);
	else if (ap->a_hba_tran->tran_hba_flags & SCSI_HBA_TRAN_CLONE)
		psd = ap->a_hba_tran->tran_sd;
	ASSERT(psd);
	pip = (mdi_pathinfo_t *)psd->sd_pathinfo;

	/*
	 * It is possable for this code to be called without the sd_pathinfo
	 * being set. This may happen as part of a probe to see if a device
	 * should be mapped under mdi. At this point we know enough to answer
	 * correctly so we can return.
	 */
	if (pip == NULL)
		return;
	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
	vlun = svp->svp_svl;

	/*
	 * Now get the vhci ptr using the walker
	 */
	mdi_walk_vhcis(vhci_mpapi_get_vhci, &vhci);

	VHCI_DEBUG(4, (CE_NOTE, NULL, "vhci_mpapi_update_tpg_data: vhci=%p, "
	    "(vlun)wwn=(%p)%s, pip=%p, ap=%p, ptr=%p, as=%x, tpg_id=%s, fops="
	    "%p\n", (void *)vhci, (void *)vlun,
	    vlun ? vlun->svl_lun_wwn : "NONE",
	    (void *)pip, (void *)ap, (void *)ptr, as, tpg_id,
	    (void *)(vlun ? vlun->svl_fops : NULL)));

	if ((vhci == NULL) || (vlun == NULL) ||
	    !SCSI_FAILOVER_IS_TPGS(vlun->svl_fops)) {
		/* Cant help, unfortunate situation */
		return;
	}

	/*
	 * LEVEL 1 - Actions:
	 * Check if the appropriate resource pointers already
	 * exist in the Level 1 list and add them if they are new.
	 */

	/*
	 * Build MP LU list
	 */
	lu_list = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_MULTIPATH_LU, (void*)vlun);
	if (lu_list == NULL) {
		/* Need to create lu_list entry */
		lu_list = vhci_mpapi_create_item(vhci,
		    MP_OBJECT_TYPE_MULTIPATH_LU, (void*)vlun);
	} else {
		/*
		 * Matched this lu w/ an existing one in current lu list.
		 * SAME LUN came online!! So, update the resp in main list.
		 */
		ld = lu_list->item->idata;
		vhci_mpapi_set_lu_valid(vhci, lu_list->item, 1);
		ld->resp = vlun;
	}

	/*
	 * Build Path LU list
	 */
	path_list = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_PATH_LU, (void*)pip);
	if (path_list == NULL) {
		/* Need to create path_list entry */
		path_list = vhci_mpapi_create_item(vhci,
		    MP_OBJECT_TYPE_PATH_LU, (void*)pip);
	} else {
		/*
		 * Matched this pip w/ an existing one in current pip list.
		 * SAME PATH came online!! So, update the resp in main list.
		 */
		pd = path_list->item->idata;
		pd->valid = 1;
		pd->resp = pip;
	}

	if (MDI_PI_IS_ONLINE(pip)) {
		vhci_mpapi_set_path_state(vhci->vhci_dip, pip,
		    MP_DRVR_PATH_STATE_ACTIVE);
	} else if (MDI_PI_IS_STANDBY(pip)) {
		vhci_mpapi_set_path_state(vhci->vhci_dip, pip,
		    MP_DRVR_PATH_STATE_PASSIVE);
	} else {
		vhci_mpapi_set_path_state(vhci->vhci_dip, pip,
		    MP_DRVR_PATH_STATE_UNKNOWN);
	}

	/*
	 * Build Initiator Port list
	 */
	pdip = mdi_pi_get_phci(pip);
	init = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(pdip, init);

	init_list = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_INITIATOR_PORT, (void*)init);
	if (init_list == NULL) {
		/*
		 * Need to create init_list entry
		 * The resource ptr is no really pdip. It will be changed
		 * in vhci_mpapi_create_item(). The real resource ptr
		 * is the Port ID. But we pass the pdip, to create OID.
		 */
		init_list = vhci_mpapi_create_item(vhci,
		    MP_OBJECT_TYPE_INITIATOR_PORT, (void*)pdip);
	} else {
		initd = init_list->item->idata;
		initd->valid = 1;
	}
	kmem_free(init, MAXPATHLEN);

	/*
	 * LEVEL 2 - Actions:
	 * Since all the Object type item lists are updated to account
	 * for the new resources, now lets cross-reference these
	 * resources (mainly through paths) to maintain the
	 * relationship between them.
	 */

	ld = (mpapi_lu_data_t *)lu_list->item->idata;
	if (vhci_get_mpapi_item(vhci, ld->path_list,
	    MP_OBJECT_TYPE_PATH_LU, (void*)pip) == NULL) {
		lu_path_list = kmem_zalloc(sizeof (mpapi_item_list_t),
		    KM_SLEEP);
		lu_path_list->item = path_list->item;
		(void) vhci_mpapi_add_to_list(ld->path_list, lu_path_list);
	}

	initd = (mpapi_initiator_data_t *)init_list->item->idata;
	if (vhci_get_mpapi_item(vhci, initd->path_list,
	    MP_OBJECT_TYPE_PATH_LU, (void*)pip) == NULL) {
		init_path_list = kmem_zalloc(sizeof (mpapi_item_list_t),
		    KM_SLEEP);
		init_path_list->item = path_list->item;
		(void) vhci_mpapi_add_to_list(initd->path_list, init_path_list);
	}

	/*
	 * Building Target Port list is different here.
	 * For each different Relative Target Port. we have a new MPAPI
	 * Target Port OID generated.
	 * Just find out the main Target Port property here.
	 */
	tgt_port = NULL;
	if (mdi_prop_lookup_string(pip, SCSI_ADDR_PROP_TARGET_PORT,
	    &tgt_port) != DDI_PROP_SUCCESS) {
		/* XXX: target-port prop not found */
		tgt_port = (char *)mdi_pi_get_addr(pip);
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_update_tpg_data: "
		    "mdi_prop_lookup_string() returned failure; "
		    "Hence tgt_port = %p", (void *)tgt_port));
	}

	/* Search for existing group that contains this target port */
	tpg_list = vhci_mpapi_get_alua_item(vhci, vlun, &tpg_id, tgt_port);
	if (tpg_list == NULL) {
		tpg_list = vhci_mpapi_create_item(vhci,
		    MP_OBJECT_TYPE_TARGET_PORT_GROUP, &tpg_id);
	}
	tpg_data = tpg_list->item->idata;
	tpg_data->prop.accessState = as;
	tpg_data->prop.tpgId = int_tpg_id;

	/*
	 * Set explicitFailover for TPG -
	 * based on tpgs_bits setting in Std Inquiry response.
	 */
	switch (psd->sd_inq->inq_tpgs) {
	case TPGS_FAILOVER_EXPLICIT:
	case TPGS_FAILOVER_BOTH:
		tpg_data->prop.explicitFailover = 1;
		break;
	case TPGS_FAILOVER_IMPLICIT:
		tpg_data->prop.explicitFailover = 0;
		break;
	default:
		return;
	}

	/*
	 * Level 2, Lun Cross referencing to TPG.
	 */
	if (vhci_get_mpapi_item(vhci, tpg_data->lu_list,
	    MP_OBJECT_TYPE_MULTIPATH_LU, (void *)vlun) == NULL) {
		tpg_lu_list = kmem_zalloc(sizeof (mpapi_item_list_t),
		    KM_SLEEP);
		item_list = vhci_get_mpapi_item(vhci, NULL,
		    MP_OBJECT_TYPE_MULTIPATH_LU, (void *)vlun);
		tpg_lu_list->item = item_list->item;
		(void) vhci_mpapi_add_to_list(tpg_data->lu_list,
		    tpg_lu_list);
	}

	/*
	 * Level 2, TPG Cross referencing to Lun.
	 */
	if (vhci_get_mpapi_item(vhci, ld->tpg_list,
	    MP_OBJECT_TYPE_TARGET_PORT_GROUP, &tpg_id) == 0) {
		lu_tpg_list = kmem_zalloc(sizeof (mpapi_item_list_t),
		    KM_SLEEP);
		lu_tpg_list->item = tpg_list->item;
		(void) vhci_mpapi_add_to_list(((mpapi_lu_data_t *)
		    (lu_list->item->idata))->tpg_list, lu_tpg_list);
	}

	/*
	 * Level 1, Relative Target Port + Target Port Creation
	 */
	rel_tport_cnt = (ptr[7] & 0xff);
	ptr += 8;
	for (i = 0; i < rel_tport_cnt; i++) {
		rel_tid = 0;
		rel_tid |= ((ptr[2] & 0Xff) << 8);
		rel_tid |= (ptr[3] & 0xff);

		if (rel_tid != rel_tgt_port) {
			ptr += 4;
			continue;
		}

		VHCI_DEBUG(4, (CE_NOTE, NULL, "vhci_mpapi_update_tpg_data: "
		    "TgtPort=%s, RelTgtPort=%x\n", tgt_port, rel_tid));

		tgt_list = vhci_mpapi_get_rel_tport_pair(vhci, NULL,
		    (void *)tgt_port, rel_tid);
		if (tgt_list == NULL) {
			/* Need to create tgt_list entry */
			tgt_list = vhci_mpapi_create_item(vhci,
			    MP_OBJECT_TYPE_TARGET_PORT,
			    (void *)tgt_port);
			tpd = tgt_list->item->idata;
			tpd->valid = 1;
			tpd->prop.relativePortID = rel_tid;
		} else {
			tpd = tgt_list->item->idata;
			tpd->valid = 1;
		}

		tpd = (mpapi_tport_data_t *)tgt_list->item->idata;
		if (vhci_get_mpapi_item(vhci, tpd->path_list,
		    MP_OBJECT_TYPE_PATH_LU, (void*)pip) == NULL) {
			tp_path_list = kmem_zalloc(sizeof (mpapi_item_list_t),
			    KM_SLEEP);
			tp_path_list->item = path_list->item;
			(void) vhci_mpapi_add_to_list(tpd->path_list,
			    tp_path_list);
		}

		if (vhci_mpapi_get_rel_tport_pair(vhci,
		    tpg_data->tport_list, tgt_port, rel_tid) == NULL) {
			tpg_tport_list = kmem_zalloc
			    (sizeof (mpapi_item_list_t), KM_SLEEP);
			tpg_tport_list->item = tgt_list->item;
			(void) vhci_mpapi_add_to_list(tpg_data->
			    tport_list, tpg_tport_list);
		}
		ptr += 4;
	}

	/*
	 * Level-1: Fill-out Path Properties now, since we got all details.
	 * Actually, It is a structure copy, rather than just filling details.
	 */
	pd = path_list->item->idata;
	bcopy(&(ld->prop), &(pd->prop.logicalUnit),
	    sizeof (struct mp_logical_unit_prop));
	bcopy(&(initd->prop), &(pd->prop.initPort),
	    sizeof (struct mp_init_port_prop));
	bcopy(&(tpd->prop), &(pd->prop.targetPort),
	    sizeof (struct mp_target_port_prop));
}

/*
 * Routine to get mpapi ioctl argument structure from userland.
 */
/* ARGSUSED */
static int
vhci_get_mpiocdata(const void *data, mp_iocdata_t *mpioc, int mode)
{
	int	retval = 0;

#ifdef  _MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
	{
		mp_iocdata32_t	ioc32;

		VHCI_DEBUG(6, (CE_WARN, NULL, "vhci_get_mpiocdata: "
		    "Case DDI_MODEL_ILP32"));
		if (ddi_copyin((void *)data, (void *)&ioc32,
		    sizeof (mp_iocdata32_t), mode)) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_mpiocdata: "
			    "ddi_copyin() FAILED"));
			retval = EFAULT;
			break;
		}
		mpioc->mp_xfer	= (uint16_t)(uintptr_t)ioc32.mp_xfer;
		mpioc->mp_cmd	= (uint16_t)(uintptr_t)ioc32.mp_cmd;
		mpioc->mp_flags	= (uint16_t)(uintptr_t)ioc32.mp_flags;
		mpioc->mp_cmd_flags	= (uint16_t)ioc32.mp_cmd_flags;
		mpioc->mp_ilen	= (size_t)(uintptr_t)ioc32.mp_ilen;
		mpioc->mp_ibuf	= (caddr_t)(uintptr_t)ioc32.mp_ibuf;
		mpioc->mp_olen	= (size_t)(uintptr_t)ioc32.mp_olen;
		mpioc->mp_obuf	= (caddr_t)(uintptr_t)ioc32.mp_obuf;
		mpioc->mp_alen	= (size_t)(uintptr_t)ioc32.mp_alen;
		mpioc->mp_abuf	= (caddr_t)(uintptr_t)ioc32.mp_abuf;
		mpioc->mp_errno	= (int)(uintptr_t)ioc32.mp_errno;
		break;
	}

	case DDI_MODEL_NONE:
		if (ddi_copyin(data, (void*)mpioc, sizeof (*mpioc), mode)) {
			retval = EFAULT;
			break;
		}
		break;

	default:
		if (ddi_copyin(data, (void*)mpioc, sizeof (*mpioc), mode)) {
			retval = EFAULT;
			break;
		}
		break;
	}
#else   /* _MULTI_DATAMODEL */
	if (ddi_copyin(data, (void *)mpioc, sizeof (*mpioc), mode)) {
		retval = EFAULT;
	}
#endif  /* _MULTI_DATAMODEL */

	if (retval) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "vhci_get_mpiocdata: cmd <%x> "
		    "iocdata copyin failed", mpioc->mp_cmd));
	}

	return (retval);
}

/* ARGSUSED */
static int
vhci_is_model_type32(int mode)
{
#ifdef  _MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
			return (1);
		default:
			return (0);
	}
#else   /* _MULTI_DATAMODEL */
	return (0);
#endif  /* _MULTI_DATAMODEL */
}

/*
 * Convenience routine to copy mp_iocdata(32) to user land
 */
/* ARGSUSED */
static int
vhci_mpapi_copyout_iocdata(void *mpioc, void *udata, int mode)
{
	int	rval = 0;

	if (vhci_is_model_type32(mode)) {
		mp_iocdata32_t	*mpioc32;

		mpioc32 = (mp_iocdata32_t *)kmem_zalloc
		    (sizeof (mp_iocdata32_t), KM_SLEEP);
		mpioc32->mp_xfer = (uint16_t)((mp_iocdata_t *)mpioc)->mp_xfer;
		mpioc32->mp_cmd	 = (uint16_t)((mp_iocdata_t *)mpioc)->mp_cmd;
		mpioc32->mp_flags = (uint16_t)((mp_iocdata_t *)mpioc)->mp_flags;
		mpioc32->mp_cmd_flags = (uint16_t)((mp_iocdata_t *)
		    mpioc)->mp_cmd_flags;
		mpioc32->mp_ilen = (uint32_t)((mp_iocdata_t *)mpioc)->mp_ilen;
		mpioc32->mp_ibuf = (caddr32_t)((mp_iocdata32_t *)
		    mpioc)->mp_ibuf;
		mpioc32->mp_olen = (uint32_t)((mp_iocdata_t *)mpioc)->mp_olen;
		mpioc32->mp_obuf = (caddr32_t)((mp_iocdata32_t *)
		    mpioc)->mp_obuf;
		mpioc32->mp_alen = (uint32_t)((mp_iocdata_t *)mpioc)->mp_alen;
		mpioc32->mp_abuf = (caddr32_t)((mp_iocdata32_t *)
		    mpioc)->mp_abuf;
		mpioc32->mp_errno = (int32_t)((mp_iocdata_t *)mpioc)->mp_errno;

		if (ddi_copyout(mpioc32, udata, sizeof (mp_iocdata32_t), mode)
		    != 0) {
			rval = EFAULT;
		}
		kmem_free(mpioc32, sizeof (mp_iocdata32_t));
	} else {
		/* 64-bit ddicopyout */
		if (ddi_copyout(mpioc, udata, sizeof (mp_iocdata_t), mode)
		    != 0) {
			rval = EFAULT;
		}
	}

	return (rval);

}

/*
 * Routine to sync OIDs of MPLU to match with the ssd instance# of the
 * scsi_vhci lun, to accommodate the DINFOCACHE implementation of the plugin.
 * ssd instance# = devi_instance from the dev_info structure.
 * dev_info structure of the scsi_vhci lun is pointed by svl_dip field of
 * scsi_vhci_lun structure.
 */
/* ARGSUSED */
static int
vhci_mpapi_sync_lu_oid_list(struct scsi_vhci *vhci)
{
	int			rval = 0;
	mpapi_item_list_t	*ilist;
	mpapi_lu_data_t		*lud;
	mpapi_path_data_t	*pd;
	scsi_vhci_lun_t		*svl;
	dev_info_t		*lun_dip;
	uint64_t		raw_oid;

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;

	while (ilist != NULL) {
		lud = ilist->item->idata;
		if (lud->valid == 1) {
			svl = lud->resp;

			/*
			 * Compose OID from major number and instance number.
			 */
			raw_oid = 0;
			raw_oid = MP_STORE_INST_TO_ID(
			    ddi_get_instance(svl->svl_dip), raw_oid);
			raw_oid = MP_STORE_MAJOR_TO_ID(
			    ddi_driver_major(svl->svl_dip), raw_oid);

			ilist->item->oid.raw_oid = raw_oid;
			lud->prop.id = raw_oid;
		}
		ilist = ilist->next;
	}

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_PATH_LU]->head;
	while (ilist != NULL) {
		pd = ilist->item->idata;
		if (pd->valid == 1) {
			lun_dip = mdi_pi_get_client
			    ((mdi_pathinfo_t *)(pd->resp));

			/*
			 * Compose OID from major number and instance number.
			 */
			raw_oid = 0;
			raw_oid = MP_STORE_INST_TO_ID(
			    ddi_get_instance(lun_dip), raw_oid);
			raw_oid = MP_STORE_MAJOR_TO_ID(
			    ddi_driver_major(lun_dip), raw_oid);

			pd->prop.logicalUnit.id = raw_oid;
		}
		ilist = ilist->next;
	}

	return (rval);
}

/*
 * Set new value for the valid field of an MP LU.
 *
 * This should be called to set new value for the valid field instead of
 * accessing it directly. If the value has changed, the appropriate
 * sysevent is generated.
 *
 * An exception is when the LU is created an the valid field is set for
 * the first time. In this case we do not want to generate an event
 * so the field should be set directly instead of calling this function.
 *
 * Rationale for introducing ESC_SUN_MP_LU_{ADD|REMOVE}: When the last
 * path to a MPLU goes offline, the client node is offlined (not removed).
 * When a path to the MPLU goes back online, the client node is onlined.
 * There is no existing sysevent that whould announce this.
 * EC_DEVFS / ESC_DEVFS_DEVI_{ADD|REMOVE} do not work, because the
 * client node is just offlined/onlined, not removed/re-added.
 * EC_DEV_{ADD|REMOVE} / ESC_DISK only works for block devices, not
 * for other LUs (such as tape). Therefore special event subclasses
 * for addition/removal of a MPLU are needed.
 */
static void vhci_mpapi_set_lu_valid(struct scsi_vhci *vhci,
    mpapi_item_t *lu_item, int valid)
{
	mpapi_lu_data_t *lu_data;

	lu_data = (mpapi_lu_data_t *)lu_item->idata;
	if (valid == lu_data->valid)
		return;
	lu_data->valid = valid;

	vhci_mpapi_log_sysevent(vhci->vhci_dip, &(lu_item->oid.raw_oid),
	    valid ? ESC_SUN_MP_LU_ADD : ESC_SUN_MP_LU_REMOVE);
}

/*
 * Set new value for TPG accessState property.
 *
 * This should be called to set the new value instead of changing the field
 * directly. If the value has changed, the appropriate sysevent is generated.
 *
 * An exception is when the TPG is created and the accessState field is set
 * for the first time. In this case we do not want to generate an event
 * so the field should be set directly instead of calling this function.
 */
static void vhci_mpapi_set_tpg_as_prop(struct scsi_vhci *vhci,
    mpapi_item_t *tpg_item, uint32_t new_state)
{
	mpapi_tpg_data_t *tpg_data;

	tpg_data = (mpapi_tpg_data_t *)tpg_item->idata;
	if (new_state == tpg_data->prop.accessState)
		return;
	tpg_data->prop.accessState = new_state;

	vhci_mpapi_log_sysevent(vhci->vhci_dip, &(tpg_item->oid.raw_oid),
	    ESC_SUN_MP_TPG_CHANGE);
}

/*
 * Routine to sync Initiator Port List with what MDI maintains. This means
 * MP API knows about Initiator Ports which don't have a pip.
 */
/* ARGSUSED */
int
vhci_mpapi_sync_init_port_list(dev_info_t *pdip, void *arg)
{
	int			init_not_ddi_alloced = 0;
	struct scsi_vhci	*vhci = arg;
	char			*init, *init_port_res;
	mpapi_item_list_t	*init_list;
	mpapi_initiator_data_t	*initd;

	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS,
	    SCSI_ADDR_PROP_INITIATOR_PORT, &init) != DDI_PROP_SUCCESS)) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_sync_init_port_list: "
		    SCSI_ADDR_PROP_INITIATOR_PORT " prop not found"));
		init = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		init_not_ddi_alloced = 1;
		(void) ddi_pathname(pdip, init);
	}

	init_port_res = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(pdip, init_port_res);

	init_list = vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_INITIATOR_PORT, (void*)init_port_res);
	if (init_list == NULL) {
		/*
		 * Need to create init_list entry
		 * The resource ptr is not really pdip. It will be changed
		 * in vhci_mpapi_create_item(). The real resource ptr
		 * is the Port ID. But we pass the pdip, to create OID.
		 */
		init_list = vhci_mpapi_create_item(vhci,
		    MP_OBJECT_TYPE_INITIATOR_PORT, (void*)pdip);
	}

	initd = init_list->item->idata;
	initd->valid = 1;
	(void) strlcpy(initd->prop.portID, init, sizeof (initd->prop.portID));

	if (init_not_ddi_alloced == 1) {
		kmem_free(init, MAXPATHLEN);
	} else if (init) {
		ddi_prop_free(init);
	}
	kmem_free(init_port_res, MAXPATHLEN);

	return (DDI_WALK_CONTINUE);
}

/* ARGSUSED */
static void
vhci_mpapi_log_sysevent(dev_info_t *dip, uint64_t *oid, char *subclass)
{
	nvlist_t	*attr_list;

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
	    KM_SLEEP) != DDI_SUCCESS) {
		goto alloc_failed;
	}

	if (nvlist_add_uint64_array(attr_list, "oid", oid, 1) != DDI_SUCCESS) {
		goto error;
	}

	(void) ddi_log_sysevent(dip, DDI_VENDOR_SUNW, EC_SUN_MP, subclass,
	    attr_list, NULL, DDI_SLEEP);

error:
	nvlist_free(attr_list);
	return;

alloc_failed:
	VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_log_sysevent: "
	    "Unable to send sysevent"));

}

/* ARGSUSED */
void
vhci_mpapi_set_path_state(dev_info_t *vdip, mdi_pathinfo_t *pip, int state)
{
	struct scsi_vhci	*vhci;
	struct scsi_vhci_lun	*svl;
	scsi_vhci_priv_t	*svp;
	mpapi_item_list_t	*ilist, *lu_list;
	mpapi_path_data_t	*pp;
	int			old_state;
	int			old_in_okay, new_in_okay;

	vhci = ddi_get_soft_state(vhci_softstate, ddi_get_instance(vdip));

	ilist = vhci_get_mpapi_item(vhci, NULL, MP_OBJECT_TYPE_PATH_LU, pip);

	if (ilist != NULL) {
		mutex_enter(&ilist->item->item_mutex);
		pp = ilist->item->idata;
		old_state = pp->prop.pathState;
		pp->prop.pathState = state;
		pp->valid = 1;

		/*
		 * MP API does not distiguish between ACTIVE and PASSIVE
		 * and thus libmpscsi_vhci renders both as MP_PATH_STATE_OKAY.
		 * Therefore if we are transitioning between ACTIVE and PASSIVE
		 * we do not want to generate an event.
		 */

		old_in_okay = (old_state == MP_DRVR_PATH_STATE_ACTIVE ||
		    old_state == MP_DRVR_PATH_STATE_PASSIVE);
		new_in_okay = (state == MP_DRVR_PATH_STATE_ACTIVE ||
		    state == MP_DRVR_PATH_STATE_PASSIVE);

		if (state != old_state && !(old_in_okay && new_in_okay)) {
			vhci_mpapi_log_sysevent(vdip,
			    &(ilist->item->oid.raw_oid),
			    ESC_SUN_MP_PATH_CHANGE);
		}
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_set_path_state: "
		    "pip(%p) not found", (void *)pip));
		return;
	}

	/*
	 * Check if the pathinfo is uninitialized(destroyed).
	 */
	if (state == MP_DRVR_PATH_STATE_UNINIT) {
		pp->hide = 1;
		VHCI_DEBUG(6, (CE_NOTE, NULL, "vhci_mpapi_set_path_state: "
		    "path(pip: %p) is uninited(destroyed).",
		    (void *)pip));
	} else {
		pp->hide = 0;
	}
	/*
	 * Find if there are any paths at all to the lun
	 */
	if ((state == MP_DRVR_PATH_STATE_REMOVED) || (state ==
	    MP_DRVR_PATH_STATE_PATH_ERR) || (state ==
	    MP_DRVR_PATH_STATE_LU_ERR) || (state ==
	    MP_DRVR_PATH_STATE_UNKNOWN) || pp->hide) {
		pp->valid = 0;
		VHCI_DEBUG(6, (CE_NOTE, NULL, "vhci_mpapi_set_path_state: "
		    "path(pip: %p) is not okay state.  Set to invalid.",
		    (void *)pip));
		svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
		svl = svp->svp_svl;
		/*
		 * Update the AccessState of related MPAPI TPGs
		 * This takes care of a special case where a path goes offline
		 * & the TPG accessState may need an update from
		 * Active/Standby to Unavailable.
		 */
		if (!SCSI_FAILOVER_IS_TPGS(svl->svl_fops)) {
			(void) vhci_mpapi_update_tpg_acc_state_for_lu(vhci,
			    svl);
		}

		/*
		 * Following means the lun is offline
		 */
		if (vhci_mpapi_chk_last_path(pip) == -1) {
			lu_list = vhci_get_mpapi_item(vhci, NULL,
			    MP_OBJECT_TYPE_MULTIPATH_LU, (void *)svl);
			if (lu_list != NULL) {
				vhci_mpapi_set_lu_valid(vhci, lu_list->item, 0);

				VHCI_DEBUG(6, (CE_NOTE, NULL,
				    "vhci_mpapi_set_path_state: "
				    " Invalidated LU(%s)", svl->svl_lun_wwn));
			}
		}
	}
	mutex_exit(&ilist->item->item_mutex);

}

/* ARGSUSED */
static mpapi_item_list_t *
vhci_mpapi_match_pip(struct scsi_vhci *vhci, mpapi_item_list_t *ilist,
    void *res)
{
	mpapi_path_data_t	*pd;
	scsi_vhci_lun_t		*this_svl;
	mdi_pathinfo_t		*this_pip;
	char			*this_iport;
	char			*this_tport;
	char			*pname;

	this_pip = (mdi_pathinfo_t *)res;
	if ((this_pip == NULL) || (ilist == NULL)) {
		return (NULL);
	}

	this_iport = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(mdi_pi_get_phci(this_pip), this_iport);

	if (mdi_prop_lookup_string(this_pip, SCSI_ADDR_PROP_TARGET_PORT,
	    &this_tport) != DDI_PROP_SUCCESS) {
		/* XXX: target-port prop not found */
		this_tport = (char *)mdi_pi_get_addr(this_pip);
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_mpapi_match_pip: "
		    "mdi_prop_lookup_string() returned failure; "
		    "Hence this_tport = %p", (void *)this_tport));
	}

	this_svl = mdi_client_get_vhci_private(mdi_pi_get_client(this_pip));

	pname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) strlcat(pname, this_iport, MAXPATHLEN);
	(void) strlcat(pname, this_tport, MAXPATHLEN);
	(void) strlcat(pname, this_svl->svl_lun_wwn, MAXPATHLEN);
	kmem_free(this_iport, MAXPATHLEN);

	while (ilist != NULL) {
		pd = (mpapi_path_data_t *)(ilist->item->idata);
		if ((pd != NULL) && (strncmp
		    (pd->path_name, pname, strlen(pname)) == 0)) {
			VHCI_DEBUG(6, (CE_WARN, NULL, "vhci_mpapi_match_pip: "
			    "path_name = %s", pd->path_name));
			kmem_free(pname, MAXPATHLEN);
			return (ilist);
		}
		ilist = ilist->next;
	}

	kmem_free(pname, MAXPATHLEN);
	return (NULL);
}

/* ARGSUSED */
static
mpapi_item_list_t *vhci_mpapi_match_lu(struct scsi_vhci *vhci,
    mpapi_item_list_t *ilist, void *res)
{
	mpapi_lu_data_t		*ld;
	scsi_vhci_lun_t		*this_svl;

	this_svl = (scsi_vhci_lun_t *)res;
	if ((this_svl == NULL) || (ilist == NULL)) {
		return (NULL);
	}

	while (ilist != NULL) {
		ld = (mpapi_lu_data_t *)(ilist->item->idata);
		if ((ld != NULL) && (strncmp
		    (ld->prop.name, this_svl->svl_lun_wwn,
		    strlen(this_svl->svl_lun_wwn)) == 0)) {
			VHCI_DEBUG(6, (CE_WARN, NULL, "vhci_mpapi_match_lu: "
			    "this_wwn = %s", this_svl->svl_lun_wwn));
			return (ilist);
		}
		ilist = ilist->next;
	}

	return (NULL);
}

/*
 * Routine to handle TPG AccessState Change - Called after each LU failover
 */
int
vhci_mpapi_update_tpg_acc_state_for_lu(struct scsi_vhci *vhci,
    scsi_vhci_lun_t *vlun)
{
	int			rval = 0;
	mpapi_item_list_t	*lu_list, *path_list, *tpg_list;
	mpapi_lu_data_t		*lu_data;
	mpapi_path_data_t	*path_data;
	mpapi_tpg_data_t	*tpg_data;
	char			*tgt_port;
	boolean_t		set_lu_valid;

	lu_list = vhci_get_mpapi_item(vhci, NULL, MP_OBJECT_TYPE_MULTIPATH_LU,
	    (void *)vlun);
	if (lu_list == NULL) {
		return (-1);
	}
	lu_data = lu_list->item->idata;
	if (lu_data == NULL) {
		return (-1);
	}
	lu_data->resp = vlun;

	/*
	 * For each "pclass of PATH" and "pclass of TPG" match of this LU,
	 * Update the TPG AccessState to reflect the state of the path.
	 * Exit the inner loop after the 1st successful ACTIVE/STANDBY update
	 * is made, because subsequent matches also lead to the same TPG.
	 */
	tpg_list = lu_data->tpg_list->head;
	set_lu_valid = B_FALSE;

	while (tpg_list != NULL) {
		tpg_data = tpg_list->item->idata;
		path_list = lu_data->path_list->head;
		while (path_list != NULL) {
			path_data = path_list->item->idata;
			/*
			 * path class is not reliable for ALUA if the
			 * vhci has done the update on one of the class
			 * but ignore to update on another one.
			 */
			tgt_port = NULL;
			if (path_data->valid == 1 &&
			    (mdi_prop_lookup_string(path_data->resp,
			    SCSI_ADDR_PROP_TARGET_PORT,
			    &tgt_port) == DDI_PROP_SUCCESS) &&
			    tgt_port != NULL &&
			    (vhci_mpapi_check_tp_in_tpg(
			    tpg_data, tgt_port) == 1)) {
				VHCI_DEBUG(4, (CE_NOTE, NULL,
				    "vhci_mpapi_update_tpg_acc_state_"
				    "for_ lu: Operating on LUN(%s), "
				    " PATH(%p), TPG(%x: %s)\n",
				    lu_data->prop.name, path_data->resp,
				    tpg_data->prop.tpgId,
				    tpg_data->pclass));
				if (MDI_PI_IS_ONLINE(path_data->resp)) {
					vhci_mpapi_set_tpg_as_prop(vhci,
					    tpg_list->item,
					    MP_DRVR_ACCESS_STATE_ACTIVE);
					set_lu_valid = B_TRUE;
					break;
				} else if (MDI_PI_IS_STANDBY(path_data->resp)) {
					vhci_mpapi_set_tpg_as_prop(vhci,
					    tpg_list->item,
					    MP_DRVR_ACCESS_STATE_STANDBY);
					set_lu_valid = B_TRUE;
					break;
				} else {
					vhci_mpapi_set_tpg_as_prop(vhci,
					    tpg_list->item,
					    MP_DRVR_ACCESS_STATE_UNAVAILABLE);
				}
			}
			path_list = path_list->next;
		}
		tpg_list = tpg_list->next;
	}

	/*
	 * Only make LU valid if the encountered path was active or standby.
	 * Otherwise we would cause the LU to reappear transiently after
	 * the last path to it has gone and before it is finally marked
	 * invalid by vhci_mpapi_set_path_state(), causing bogus visibility
	 * events.
	 */
	if (set_lu_valid != B_FALSE)
		vhci_mpapi_set_lu_valid(vhci, lu_list->item, 1);

	return (rval);
}

int
vhci_mpapi_get_vhci(dev_info_t *vdip, void *ptr2vhci)
{
	struct scsi_vhci	*local_vhci;

	if (strncmp("scsi_vhci", ddi_get_name(vdip),
	    strlen("scsi_vhci")) == 0) {
		local_vhci = ddi_get_soft_state(vhci_softstate,
		    ddi_get_instance(vdip));
		bcopy(&local_vhci, ptr2vhci, sizeof (local_vhci));
		return (DDI_WALK_TERMINATE);
	}

	return (DDI_WALK_CONTINUE);

}

/* ARGSUSED */
void *
vhci_mpapi_get_rel_tport_pair(struct scsi_vhci *vhci, mpapi_list_header_t *list,
    void *tgt_port, uint32_t rel_tid)
{
	mpapi_item_list_t	*ilist;
	mpapi_tport_data_t	*tpd;

	if (list == NULL) {
		/*
		 * Since the listhead is null, the search is being
		 * performed in implicit mode - that is to use the
		 * level one list.
		 */
		ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_TARGET_PORT]
		    ->head;
	} else {
		/*
		 * The search is being performed on a sublist within
		 * one of the toplevel list items. Use the listhead
		 * that is passed in.
		 */
		ilist = list->head;
	}

	if (tgt_port == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_get_mpapi_item: "
		    " Got Target Port w/ NULL resource"));
		return (NULL);
	}

	while (ilist) {
		tpd = (mpapi_tport_data_t *)ilist->item->idata;
		if ((strncmp(tpd->resp, tgt_port, strlen(tgt_port)) == 0) &&
		    (tpd->prop.relativePortID == rel_tid)) {
			/* Match */
			return ((void*)ilist);
		} else {
			ilist = ilist->next;
		}
	}

	return (NULL);
}

/*
 * Returns 0, if 2 more paths are available to the lun;
 * Returns 1, if ONLY 1 path is available to the lun;
 * Return -1 for all other cases.
 */
static int
vhci_mpapi_chk_last_path(mdi_pathinfo_t *pip)
{
	dev_info_t	*pdip = NULL, *cdip = NULL;
	int		count = 0;
	mdi_pathinfo_t	*ret_pip;

	if (pip == NULL) {
		return (-1);
	} else {
		pdip = mdi_pi_get_phci(pip);
		cdip = mdi_pi_get_client(pip);
	}

	if ((pdip == NULL) || (cdip == NULL)) {
		return (-1);
	}

	ndi_devi_enter(cdip);
	ret_pip = mdi_get_next_phci_path(cdip, NULL);

	while ((ret_pip != NULL) && (count < 2)) {
		mdi_pi_lock(ret_pip);
		if ((MDI_PI_IS_ONLINE(ret_pip) ||
		    MDI_PI_IS_STANDBY(ret_pip) ||
		    MDI_PI_IS_INIT(ret_pip)) &&
		    !(MDI_PI_IS_DISABLE(ret_pip) ||
		    MDI_PI_IS_TRANSIENT(ret_pip) ||
		    MDI_PI_FLAGS_IS_DEVICE_REMOVED(ret_pip))) {
			count++;
		}
		mdi_pi_unlock(ret_pip);
		ret_pip = mdi_get_next_phci_path(cdip, ret_pip);
	}
	ndi_devi_exit(cdip);

	if (count > 1) {
		return (0);
	} else if (count == 1) {
		return (1);
	}

	return (-1);
}
