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
 * iSCSI Software Initiator
 */

#include "iscsi.h"	/* main header */

kstat_item_t	kstat_items_hba[KN_HBA_IDX_MAX] = {
	{"_name", KSTAT_DATA_STRING},
	{"_alias", KSTAT_DATA_STRING},
	{"_cntr_sess", KSTAT_DATA_ULONG}
};

kstat_item_t	kstat_items_sess[KN_SESS_IDX_MAX] = {
	{"_state", KSTAT_DATA_STRING},
	{"_oid", KSTAT_DATA_ULONG},
	{"_hba", KSTAT_DATA_STRING},
	{"_cntr_conn", KSTAT_DATA_ULONG},
	{"_cntr_reset", KSTAT_DATA_ULONG},
	{"_cntr_pkt_pending", KSTAT_DATA_ULONG},
	{"_cmd_sn", KSTAT_DATA_ULONG},
	{"_cmd_sn_exp", KSTAT_DATA_ULONG},
	{"_cmd_sn_max", KSTAT_DATA_ULONG},
	{"_target_name", KSTAT_DATA_STRING},
	{"_target_alias", KSTAT_DATA_STRING},
	{"_tpgt", KSTAT_DATA_ULONG}
};

kstat_item_t	kstat_items_conn[KN_CONN_IDX_MAX] = {
	{"_state", KSTAT_DATA_STRING},
	{"_cid", KSTAT_DATA_ULONG},
	{"_oid", KSTAT_DATA_ULONG},
	{"_session", KSTAT_DATA_STRING},
	{"_err_header_digest", KSTAT_DATA_ULONG},
	{"_err_data_digest", KSTAT_DATA_ULONG},
	{"_err_connection_reset", KSTAT_DATA_ULONG},
	{"_err_protocol_error", KSTAT_DATA_ULONG},
	{"_cntr_tx_bytes", KSTAT_DATA_ULONGLONG},
	{"_cntr_rx_bytes", KSTAT_DATA_ULONGLONG},
	{"_cntr_qactive", KSTAT_DATA_ULONG},
	{"_stat_sn_exp", KSTAT_DATA_ULONG},
	{"_stat_sn_last", KSTAT_DATA_ULONG}
};

int iscsi_hba_kstat_update(kstat_t *ks, int rw);
int iscsi_sess_kstat_update(kstat_t *ks, int rw);
int iscsi_conn_kstat_update(kstat_t *ks, int rw);

/*
 * HBA
 */

/*
 * iscsi_hba_kstat_init - This function registers with the kstat service.
 */
boolean_t
iscsi_hba_kstat_init(iscsi_hba_t *ihp)
{
	char			ks_name[KSTAT_STRLEN];
	iscsi_hba_stats_t	*ihs;
	int			i;

	/*
	 * The name of the KSTAT structure is built.
	 */
	bzero(ks_name, sizeof (ks_name));

	if (snprintf(ks_name, sizeof (ks_name) - 1, iSCSI_HBA_BASE_NAME,
	    ihp->hba_oid) >= sizeof (ks_name)) {
		return (TRUE);
	}

	ihp->stats.ks = kstat_create(iSCSI_MODULE_NAME,
	    ddi_get_instance(ihp->hba_dip), ks_name, iSCSI_CLASS_HBA,
	    KSTAT_TYPE_NAMED, 0, KSTAT_FLAG_VIRTUAL);

	if (ihp->stats.ks == NULL) {
		cmn_err(CE_NOTE, "iscsi kstat creation failed for hba(%d)",
		    ihp->hba_oid);
		return (TRUE);
	}

	ihs = &ihp->stats.ks_data;
	ihp->stats.ks->ks_data = &ihp->stats.ks_data;
	ihp->stats.ks->ks_data_size = sizeof (ihp->stats.ks_data);
	ihp->stats.ks->ks_ndata = KN_HBA_IDX_MAX;

	for (i = 0; i < KN_HBA_IDX_MAX; i++) {
		kstat_named_init(&ihs->kn[i], kstat_items_hba[i]._name,
		    kstat_items_hba[i]._data_type);
	}

	ihp->stats.ks->ks_update = iscsi_hba_kstat_update;
	ihp->stats.ks->ks_private = (void *)ihp;

	kstat_install(ihp->stats.ks);

	return (FALSE);
}

/*
 * iscsi_hba_kstat_term - This function deregisters from the kstat service.
 */
boolean_t
iscsi_hba_kstat_term(iscsi_hba_t *ihp)
{
	kstat_delete(ihp->stats.ks);
	return (FALSE);
}

/*
 * iscsi_hba_kstat_update - This function update the kstat structure of the HBA.
 */
int
iscsi_hba_kstat_update(kstat_t *ks, int rw)
{
	iscsi_hba_t		*ihp = (iscsi_hba_t *)ks->ks_private;
	iscsi_hba_stats_t	*ihs = &ihp->stats.ks_data;

	if (rw == KSTAT_READ) {
		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		bcopy(ihp->hba_name, ihs->name, ihp->hba_name_length);

		bcopy(ihp->hba_alias, ihs->alias, ihp->hba_alias_length);

		ihs->name[ihp->hba_name_length] = 0;
		ihs->alias[ihp->hba_alias_length] = 0;

		kstat_named_setstr(&ihs->kn[KN_HBA_IDX_NAME],
		    (const char *)ihs->name);
		kstat_named_setstr(&ihs->kn[KN_HBA_IDX_ALIAS],
		    (const char *)ihs->alias);
		rw_exit(&ihp->hba_sess_list_rwlock);
	}
	return (0);
}

/*
 * Session
 */

/*
 * iscsi_sess_kstat_init - This function registers with the kstat service.
 */
boolean_t
iscsi_sess_kstat_init(iscsi_sess_t *isp)
{
	iscsi_hba_t		*ihp;
	char			ks_name[KSTAT_STRLEN];
	iscsi_sess_stats_t	*iss;
	int			i;

	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	/*
	 * The name of the KSTAT structure is built.
	 */
	bzero(ks_name, sizeof (ks_name));

	if (snprintf(ks_name, sizeof (ks_name) - 1, iSCSI_SESS_BASE_NAME,
	    isp->sess_hba->hba_oid, isp->sess_oid) >= sizeof (ks_name)) {
		cmn_err(CE_NOTE, "iscsi kstat creation failed for "
		    "session(%u)", isp->sess_oid);
		return (TRUE);
	}

	isp->stats.ks = kstat_create(iSCSI_MODULE_NAME,
	    ddi_get_instance(ihp->hba_dip), ks_name, iSCSI_CLASS_SESS,
	    KSTAT_TYPE_NAMED, 0, KSTAT_FLAG_VIRTUAL);

	if (isp->stats.ks == NULL) {
		cmn_err(CE_NOTE, "iscsi kstat creation failed "
		    "for session(%u)", isp->sess_oid);
		return (TRUE);
	}

	iss = &isp->stats.ks_data;
	isp->stats.ks->ks_data = (void *)&isp->stats.ks_data;
	isp->stats.ks->ks_data_size = sizeof (isp->stats.ks_data);
	isp->stats.ks->ks_ndata = KN_SESS_IDX_MAX;

	for (i = 0; i < KN_SESS_IDX_MAX; i++) {
		kstat_named_init(&iss->kn[i], kstat_items_sess[i]._name,
		    kstat_items_sess[i]._data_type);
	}

	/* The static information is updated immediately */
	bzero(iss->hba_str, sizeof (iss->hba_str));
	bcopy(ihp->stats.ks->ks_name, iss->hba_str, sizeof (iss->hba_str));
	kstat_named_setstr(&iss->kn[KN_SESS_IDX_HBA],
	    (const char *)iss->hba_str);

	iss->kn[KN_SESS_IDX_OID].value.ul = isp->sess_oid;

	isp->stats.ks->ks_update = iscsi_sess_kstat_update;
	isp->stats.ks->ks_private = (void *)isp;

	/* The IO KSTAT structure is created */
	bzero(ks_name, sizeof (ks_name));

	if (snprintf(ks_name, sizeof (ks_name) - 1, iSCSI_SESS_IO_BASE_NAME,
	    isp->sess_hba->hba_oid, isp->sess_oid) >= sizeof (ks_name)) {
		cmn_err(CE_NOTE, "iscsi kstat createion failed "
		    "for session(%u)", isp->sess_oid);
		kstat_delete(isp->stats.ks);
		return (TRUE);
	}

	isp->stats.ks_io = kstat_create(iSCSI_MODULE_NAME,
	    ddi_get_instance(ihp->hba_dip), ks_name, iSCSI_CLASS_SESS,
	    KSTAT_TYPE_IO, 1, KSTAT_FLAG_VIRTUAL);

	if (isp->stats.ks_io == NULL) {
		kstat_delete(isp->stats.ks);
		cmn_err(CE_NOTE, "iscsi kstat creation failed "
		    "for session(%u)", isp->sess_oid);
		return (TRUE);
	}
	mutex_init(&isp->stats.ks_io_lock, NULL, MUTEX_DRIVER, NULL);
	isp->stats.ks_io->ks_data = &isp->stats.ks_io_data;
	isp->stats.ks_io->ks_lock = &isp->stats.ks_io_lock;

	kstat_install(isp->stats.ks);
	kstat_install(isp->stats.ks_io);

	return (FALSE);
}

/*
 * iscsi_sess_kstat_term - This function deregisters with the kstat service.
 */
boolean_t
iscsi_sess_kstat_term(iscsi_sess_t *isp)
{
	kstat_delete(isp->stats.ks_io);
	mutex_destroy(&isp->stats.ks_io_lock);
	kstat_delete(isp->stats.ks);
	return (FALSE);
}

/*
 * iscsi_sess_kstat_update - This function update the kstat
 *	structure of the HBA.
 */
int
iscsi_sess_kstat_update(kstat_t *ks, int rw)
{
	iscsi_sess_t		*isp = (iscsi_sess_t *)ks->ks_private;
	iscsi_sess_stats_t	*iss = &isp->stats.ks_data;
	char			*ptr;
	int			len;

	if (rw == KSTAT_READ) {

		/* String indicating the state of the session */
		ptr = iscsi_sess_state_str(isp->sess_state);
		len =  strlen(ptr);
		if (len > sizeof (iss->state_str)) {
			len = sizeof (iss->state_str);
		}
		bzero(iss->state_str, sizeof (iss->state_str));
		bcopy(ptr, iss->state_str, len);
		kstat_named_setstr(
		    &iss->kn[KN_SESS_IDX_STATE],
		    (const char *)iss->state_str);

		/* Target name string */
		if (isp->sess_name_length > sizeof (iss->target_name)) {
			len = sizeof (iss->target_name);
		} else {
			len =  isp->sess_name_length;
		}
		bzero(iss->target_name, sizeof (iss->target_name));
		bcopy(isp->sess_name, iss->target_name, len);
		kstat_named_setstr(&iss->kn[KN_SESS_IDX_TARGET_NAME],
		    (const char *)iss->target_name);

		/* Target alias string */
		if (isp->sess_alias_length > sizeof (iss->target_alias)) {
			len = sizeof (iss->target_alias);
		} else {
			len =  isp->sess_alias_length;
		}
		bzero(iss->target_alias, sizeof (iss->target_alias));
		bcopy(isp->sess_alias, iss->target_alias, len);
		kstat_named_setstr(
		    &iss->kn[KN_SESS_IDX_TARGET_ALIAS],
		    (const char *)iss->target_alias);

		iss->kn[KN_SESS_IDX_CNTR_PKT_PENDING].value.ul =
		    isp->sess_queue_pending.count;
		iss->kn[KN_SESS_IDX_CMDSN].value.ul =
		    isp->sess_cmdsn;
		iss->kn[KN_SESS_IDX_EXPCMDSN].value.ul =
		    isp->sess_expcmdsn;
		iss->kn[KN_SESS_IDX_MAXCMDSN].value.ul =
		    isp->sess_maxcmdsn;
		iss->kn[KN_SESS_IDX_TPGT].value.ul =
		    isp->sess_tpgt_conf;

	}
	return (0);
}

/*
 * Connection
 */

/*
 * iscsi_conn_kstat_init - This function registers with the kstat service.
 */
boolean_t
iscsi_conn_kstat_init(iscsi_conn_t *icp)
{
	iscsi_sess_t		*isp = icp->conn_sess;
	iscsi_hba_t		*ihp = isp->sess_hba;
	iscsi_conn_stats_t	*ics;
	int			i;
	char			ks_name[KSTAT_STRLEN];

	/*
	 * The name of the KSTAT structure is built.
	 */
	bzero(ks_name, sizeof (ks_name));

	if (snprintf(ks_name, sizeof (ks_name) - 1, iSCSI_CONN_BASE_NAME,
	    icp->conn_sess->sess_hba->hba_oid, icp->conn_sess->sess_oid,
	    icp->conn_oid) >= sizeof (ks_name)) {
		return (TRUE);
	}

	icp->stats.ks = kstat_create(iSCSI_MODULE_NAME,
	    ddi_get_instance(ihp->hba_dip), ks_name, iSCSI_CLASS_CONN,
	    KSTAT_TYPE_NAMED, 0, KSTAT_FLAG_VIRTUAL);

	if (icp->stats.ks == NULL) {
		cmn_err(CE_NOTE, "iscsi kstat creation failed "
		    "for connection(%d)", icp->conn_oid);
		return (TRUE);
	}

	ics = &icp->stats.ks_data;
	icp->stats.ks->ks_data = (void *)ics;
	icp->stats.ks->ks_data_size = sizeof (*ics);
	icp->stats.ks->ks_ndata = KN_CONN_IDX_MAX;

	for (i = 0; i < KN_CONN_IDX_MAX; i++) {
		kstat_named_init(&ics->kn[i], kstat_items_conn[i]._name,
		    kstat_items_conn[i]._data_type);
	}

	/* The static information is updated immediately */
	bzero(ics->sess_str, sizeof (ics->sess_str));
	bcopy(isp->stats.ks->ks_name,
	    ics->sess_str,
	    sizeof (ics->sess_str));

	kstat_named_setstr(&ics->kn[KN_CONN_IDX_SESS],
	    (const char *)ics->sess_str);

	ics->kn[KN_CONN_IDX_OID].value.ul = isp->sess_oid;
	ics->kn[KN_CONN_IDX_CID].value.ul = icp->conn_cid;
	icp->stats.ks->ks_update = iscsi_conn_kstat_update;
	icp->stats.ks->ks_private = (void *)icp;

	kstat_install(icp->stats.ks);

	return (FALSE);
}

/*
 * iscsi_conn_kstat_term - This function deregisters with the kstat service.
 */
void
iscsi_conn_kstat_term(iscsi_conn_t *icp)
{
	kstat_delete(icp->stats.ks);
}

/*
 * iscsi_conn_kstat_update - This function update the kstat
 *	structure of the HBA.
 */
int
iscsi_conn_kstat_update(kstat_t *ks, int rw)
{
	iscsi_conn_t	*icp = (iscsi_conn_t *)ks->ks_private;
	iscsi_conn_stats_t	*ics = &icp->stats.ks_data;
	char			*ptr;
	int			len;

	if (rw == KSTAT_READ) {
		ptr = iscsi_conn_state_str(icp->conn_state);
		len =  strlen(ptr);
		if (len > sizeof (ics->state_str)) {
			len = sizeof (ics->state_str);
		}
		bzero(ics->state_str, sizeof (ics->state_str));
		bcopy(ptr, ics->state_str, len);
		kstat_named_setstr(&ics->kn[KN_CONN_IDX_STATE],
		    (const char *)ics->state_str);

		ics->kn[KN_CONN_IDX_CNTR_QACTIVE].value.ul =
		    icp->conn_queue_active.count;
		ics->kn[KN_CONN_IDX_EXPSTATSN].value.ul =
		    icp->conn_expstatsn;
		ics->kn[KN_CONN_IDX_LASTSTATSN].value.ul =
		    icp->conn_laststatsn;
	}
	return (0);
}
