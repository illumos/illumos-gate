/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>

#include "rdimpl.h"


void
prtelement(FILE *fp, id_info_t *id)
{
	(void) fprintf(fp, "\n"
	"processID                   = %d\n"
	"userID                      = %d\n"
	"taskID                      = %d\n"
	"projectID		     = %d\n"
	"setID                       = %d\n"
	"UserModeTime                = %f\n"
	"SystemModeTime              = %f\n"
	"SystemTrapTime              = %f\n"
	"TextPageFaultSleepTime      = %f\n"
	"DataPageFaultSleepTime      = %f\n"
	"SystemPageFaultSleepTime    = %f\n"
	"UserLockWaitSleepTime       = %f\n"
	"OtherSleepTime              = %f\n"
	"WaitCPUTime                 = %f\n"
	"StoppedTime                 = %f\n"
	"MinorPageFaults             = %" PRId64 "\n"
	"MajorPageFaults             = %" PRId64 "\n"
	"SwapOperations              = %" PRId64 "\n"
	"BlocksRead                  = %" PRId64 "\n"
	"BlocksWritten               = %" PRId64 "\n"
	"MessagesSent                = %" PRId64 "\n"
	"MessagesReceived            = %" PRId64 "\n"
	"SignalsReceived             = %" PRId64 "\n"
	"VoluntaryContextSwitches    = %" PRId64 "\n"
	"InvoluntaryContextSwitches  = %" PRId64 "\n"
	"SystemCallsMade             = %" PRId64 "\n"
	"CharacterIOUsage            = %" PRId64 "\n"
	"ProcessHeapSize             = %" PRId64 "\n"
	"ProcessVMSize               = %" PRId64 "\n"
	"ProcessResidentSetSize      = %" PRId64 "\n"
	"PercentCPUTime              = %f\n"
	"PercentMemorySize           = %f\n"
	"UserSystemModeTime          = %" PRId64 "\n"
	"NumThreads                  = %d\n"
	"NumProcesses                = %d\n"
	"TIMESTAMP in us             = %" PRId64 "\n"
	"name                        = %s\n",
	id->id_pid,
	id->id_uid,
	id->id_taskid,
	id->id_projid,
	id->id_psetid,
	id->id_usr,
	id->id_sys,
	id->id_ttime,
	id->id_tpftime,
	id->id_dpftime,
	id->id_kpftime,
	id->id_lck,
	id->id_slp,
	id->id_lat,
	id->id_stime,
	id->id_minf,
	id->id_majf,
	id->id_nswap,
	id->id_inblk,
	id->id_oublk,
	id->id_msnd,
	id->id_mrcv,
	id->id_sigs,
	id->id_vctx,
	id->id_ictx,
	id->id_scl,
	id->id_ioch,
	id->id_hpsize,
	id->id_size,
	id->id_rssize,
	id->id_pctcpu,
	id->id_pctmem,
	id->id_time,
	id->id_nlwps,
	id->id_nproc,
	id->id_timestamp,
	id->id_name);
}
