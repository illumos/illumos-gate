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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>

#include <libnwam_priv.h>

/*
 * Record libnwam's audit events (enable, disable, update and remove profiles).
 */
void
nwam_record_audit_event(const ucred_t *ucr, au_event_t eid,
    char *name, char *descr_arg, int status, int error)
{
	adt_session_data_t *ah;
	adt_event_data_t *edata;

	if (adt_start_session(&ah, NULL, 0) != 0)
		return;

	if (adt_set_from_ucred(ah, ucr, ADT_NEW) != 0) {
		(void) adt_end_session(ah);
		return;
	}

	if ((edata = adt_alloc_event(ah, eid)) == NULL) {
		(void) adt_end_session(ah);
		return;
	}

	switch (eid) {
	case ADT_nwam_enable:
		edata->adt_nwam_enable.profile_name = name;
		edata->adt_nwam_enable.profile_type = descr_arg;
		break;
	case ADT_nwam_disable:
		edata->adt_nwam_disable.profile_name = name;
		edata->adt_nwam_disable.profile_type = descr_arg;
		break;
	case ADT_netcfg_update:
		edata->adt_netcfg_update.object_name = name;
		edata->adt_netcfg_update.parent_file = descr_arg;
		break;
	case ADT_netcfg_remove:
		edata->adt_netcfg_remove.object_name = name;
		edata->adt_netcfg_remove.parent_file = descr_arg;
		break;
	default:
		goto out;
	}

	(void) adt_put_event(edata, status, error);

out:
	adt_free_event(edata);
	(void) adt_end_session(ah);
}
