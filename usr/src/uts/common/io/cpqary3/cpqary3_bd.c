/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (C) 2014 Hewlett-Packard Development Company, L.P.
 */

/*
 * Abstract:
 * In this file, we define the static array of board definitions.
 * the individual entries are in cpqary3_bd_defs.h, which is
 * auto-generated from the controllers file by sacdf using
 * the cpqary3_bd_defs.h.sacdf template.
 */

#include "cpqary3.h"
#include "cpqary3_bd.h"

static cpqary3_bd_t cpqary3_bds[] = {
	{
		"Smart Array 5300 Controller",
		4,
		0x0e11,
		0x4070,
		OUTBOUND_LIST_5300_EXISTS,
		0,
		0,
		INTR_SIMPLE_MASK,
		INTR_SIMPLE_LOCKUP_MASK,
		0
	},
	{
		"Smart Array 5i Controller",
		8,
		0x0e11,
		0x4080,
		OUTBOUND_LIST_5I_EXISTS,
		0,
		0,
		INTR_SIMPLE_5I_MASK,
		INTR_SIMPLE_5I_LOCKUP_MASK,
		0
	},
	{
		"Smart Array 532 Controller",
		8,
		0x0e11,
		0x4082,
		OUTBOUND_LIST_5I_EXISTS,
		0,
		0,
		INTR_SIMPLE_5I_MASK,
		INTR_SIMPLE_5I_LOCKUP_MASK,
		0
	},
	{
		"Smart Array 5312 Controller",
		8,
		0x0e11,
		0x4083,
		OUTBOUND_LIST_5I_EXISTS,
		0,
		0,
		INTR_SIMPLE_5I_MASK,
		INTR_SIMPLE_5I_LOCKUP_MASK,
		0
	},
	{
		"Smart Array 6i Controller",
		8,
		0x0e11,
		0x4091,
		OUTBOUND_LIST_5300_EXISTS,
		0,
		0,
		INTR_SIMPLE_MASK,
		INTR_SIMPLE_LOCKUP_MASK,
		0
	},
	{
		"Smart Array 641 Controller",
		8,
		0x0e11,
		0x409a,
		OUTBOUND_LIST_5300_EXISTS,
		0,
		0,
		INTR_SIMPLE_MASK,
		INTR_SIMPLE_LOCKUP_MASK,
		0
	},
	{
		"Smart Array 642 Controller",
		8,
		0x0e11,
		0x409b,
		OUTBOUND_LIST_5300_EXISTS,
		0,
		0,
		INTR_SIMPLE_MASK,
		INTR_SIMPLE_LOCKUP_MASK,
		0
	},
	{
		"Smart Array 6400 Controller",
		8,
		0x0e11,
		0x409c,
		OUTBOUND_LIST_5300_EXISTS,
		0,
		0,
		INTR_SIMPLE_MASK,
		INTR_SIMPLE_LOCKUP_MASK,
		0
	},
	{
		"Smart Array 6400 EM Controller",
		8,
		0x0e11,
		0x409d,
		OUTBOUND_LIST_5300_EXISTS,
		0,
		0,
		INTR_SIMPLE_MASK,
		INTR_SIMPLE_LOCKUP_MASK,
		0
	},
	{
		"Smart Array 6422 Controller",
		8,
		0x0e11,
		0x409e,
		OUTBOUND_LIST_5300_EXISTS,
		0,
		0,
		INTR_SIMPLE_MASK,
		INTR_SIMPLE_LOCKUP_MASK,
		0
	},
	{
		"Smart Array E200i Controller",
		8,
		0x103c,
		0x3211,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		1,
		INTR_E200_PERF_MASK,
		0,
		0
	},
	{
		"Smart Array E200 Controller",
		8,
		0x103c,
		0x3212,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		1,
		INTR_E200_PERF_MASK,
		0,
		0
	},
	{
		"Smart Array P800 Controller",
		8,
		0x103c,
		0x3223,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		INTR_PERF_LOCKUP_MASK,
		0
	},
	{
		"Smart Array P600 Controller",
		8,
		0x103c,
		0x3225,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		INTR_PERF_LOCKUP_MASK,
		0
	},
	{
		"Smart Array P400 Controller",
		8,
		0x103c,
		0x3234,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		INTR_PERF_LOCKUP_MASK,
		0
	},
	{
		"Smart Array P400i Controller",
		8,
		0x103c,
		0x3235,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		INTR_PERF_LOCKUP_MASK,
		0
	},
	{
		"Smart Array E500 Controller",
		8,
		0x103c,
		0x3237,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		INTR_PERF_LOCKUP_MASK,
		0
	},
	{
		"Smart Array P700m Controller",
		8,
		0x103c,
		0x323d,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		INTR_PERF_LOCKUP_MASK,
		0
	},
	{
		"Smart Array P212 Controller",
		8,
		0x103c,
		0x3241,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P410 Controller",
		8,
		0x103c,
		0x3243,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P410i Controller",
		8,
		0x103c,
		0x3245,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P411 Controller",
		8,
		0x103c,
		0x3247,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P812 Controller",
		8,
		0x103c,
		0x3249,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P712m Controller",
		8,
		0x103c,
		0x324a,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P711m Controller",
		8,
		0x103c,
		0x324b,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P222 Controller",
		8,
		0x103c,
		0x3350,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P420 Controller",
		8,
		0x103c,
		0x3351,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P421 Controller",
		8,
		0x103c,
		0x3352,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P822 Controller",
		8,
		0x103c,
		0x3353,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P420i Controller",
		8,
		0x103c,
		0x3354,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P220i Controller",
		8,
		0x103c,
		0x3355,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P721m Controller",
		8,
		0x103c,
		0x3356,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P230i Controller",
		8,
		0x103c,
		0x1928,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P430i Controller",
		8,
		0x103c,
		0x1920,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P430 Controller",
		8,
		0x103c,
		0x1922,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P431 Controller",
		8,
		0x103c,
		0x1923,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P731m Controller",
		8,
		0x103c,
		0x1926,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P830i Controller",
		8,
		0x103c,
		0x1921,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	},
	{
		"Smart Array P830 Controller",
		8,
		0x103c,
		0x1924,
		OUTBOUND_LIST_5300_EXISTS,
		SA_BD_SAS,
		0,
		INTR_PERF_MASK,
		0,
		1
	}
};

#define	NBOARD_DEFS (sizeof (cpqary3_bds) / sizeof (cpqary3_bd_t))

cpqary3_bd_t *
cpqary3_bd_getbybid(uint32_t bid)
{
	uint16_t vid = ((bid >> 16) & 0xffff);
	uint16_t sid = (bid & 0xffff);
	int i;

	/* search the array for a matching board */
	for (i = 0; i < NBOARD_DEFS; i++) {
		if ((vid == cpqary3_bds[i].bd_pci_subvenid) &&
		    (sid == cpqary3_bds[i].bd_pci_subsysid))
			return (&(cpqary3_bds[i]));
	}

	/* board id not found */
	return (NULL);
}
