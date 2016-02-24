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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef DS_DDICT
#include "../contract.h"
#endif

#define	SVE_STE_CLASS	"SVE_STE"
#define	SVE_II_CLASS	"SVE_II"
#define	SVE_CACHE_CLASS	"SVE_CACHE"

void
nsc_do_sysevent(char *driver_name, char *trap_messages, int errorno,
	int alertlevel, char *component, dev_info_t *info_dip)
{
#if !defined(DS_DDICT) && !defined(_SunOS_5_6) && \
	!defined(_SunOS_5_7) && !defined(_SunOS_5_8)

	nvlist_t *attr_list;
	int rc;

	attr_list = NULL;
	rc = nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, KM_SLEEP);
	if (rc != 0) {
		goto out;
	}
	rc = nvlist_add_int32(attr_list, "alertlevel", alertlevel);
	if (rc != 0) {
		goto out;
	}
	rc = nvlist_add_string(attr_list, "messagevalue", trap_messages);
	if (rc != 0) {
		goto out;
	}
	rc = nvlist_add_int32(attr_list, "errorno", errorno);
	if (rc != 0) {
		goto out;
	}
	if (strcmp(driver_name, "sdbc") == 0)
		rc = ddi_log_sysevent(info_dip, DDI_VENDOR_SUNW,
		    SVE_CACHE_CLASS, component, attr_list, NULL, DDI_SLEEP);
	else if (strcmp(driver_name, "ste") == 0)
		rc = ddi_log_sysevent(info_dip, DDI_VENDOR_SUNW,
		    SVE_STE_CLASS, component, attr_list, NULL, DDI_SLEEP);
	else if (strcmp(driver_name, "ii") == 0)
		rc = ddi_log_sysevent(info_dip, DDI_VENDOR_SUNW,
		    SVE_II_CLASS, component, attr_list, NULL, DDI_SLEEP);
out:
	nvlist_free(attr_list);

	if (rc != 0) {
		cmn_err(CE_WARN, "!%s: unable to log sysevent %d:%s and %d",
		    driver_name, errorno, trap_messages, alertlevel);
	}
#endif  /* which O/S? */
}
