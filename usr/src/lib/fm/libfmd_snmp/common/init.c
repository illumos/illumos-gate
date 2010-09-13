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

#include <fm/fmd_snmp.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "sunFM_impl.h"
#include "module.h"
#include "resource.h"
#include "problem.h"

static const sunFm_table_t sun_fm_tables[] = {
	TABLE_REG(sunFmModuleTable),
	TABLE_REG(sunFmResourceTable),
	TABLE_REG(sunFmProblemTable),
	TABLE_REG(sunFmFaultEventTable),
	TABLE_NULL
};

/*
 * This is our entry point for initialization by the agent, which
 * (for reasons unknown) ignores the return value.  The name is fixed
 * by the agent API.
 */
int
init_sunFM(void)
{
	int			max_err = MIB_REGISTERED_OK;
	const sunFm_table_t	*table;

	for (table = sun_fm_tables; table->t_name != NULL; table++) {
		int err = table->t_init();

		switch (err) {
		case MIB_REGISTERED_OK:
			DEBUGMSGTL((MODNAME_STR, "registered table %s\n",
			    table->t_name));
			break;
		case MIB_DUPLICATE_REGISTRATION:
			(void) snmp_log(LOG_ERR, MODNAME_STR
			    ": table %s initialization failed: duplicate "
			    "registration\n", table->t_name);
			break;
		case MIB_REGISTRATION_FAILED:
			(void) snmp_log(LOG_ERR, MODNAME_STR
			    ": table %s initialization failed: agent "
			    "registration failure\n", table->t_name);
			break;
		default:
			(void) snmp_log(LOG_ERR, MODNAME_STR
			    ": table %s initialization failed: "
			    "unknown reason\n", table->t_name);
		}

		if (err > max_err)
			max_err = err;
	}

	return (max_err);
}
