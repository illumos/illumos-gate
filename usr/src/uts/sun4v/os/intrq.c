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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/machsystm.h>
#include <sys/cpu.h>
#include <sys/intreg.h>
#include <sys/machcpuvar.h>
#include <vm/hat_sfmmu.h>
#include <sys/error.h>
#include <sys/hypervisor_api.h>

/*
 * XXX needs to be set by some algorithm that derives this
 * from the partition description
 */
int cpu_q_entries = 128;
int dev_q_entries = 128;

/*
 * Once the partition description if finallized
 * cpu_q_entries and dev_q_entries will be set
 * and be garaunteed to be two's power multiples.
 */
#define	INTR_CPU_Q	0x3c
#define	INTR_DEV_Q	0x3d
#define	INTR_REPORT_SIZE	64
#define	INTR_CPU_Q_SIZE	(cpu_q_entries * INTR_REPORT_SIZE)
#define	INTR_DEV_Q_SIZE	(dev_q_entries * INTR_REPORT_SIZE)

/*
 * XXX -  This needs to be rewritten with prom calls to
 * let OBP know the queues are allocated
 */
void
cpu_intrq_register(struct cpu *cpu)
{
	struct machcpu *mcpup = &cpu->cpu_m;
	uint64_t ret;

	ret = hv_cpu_qconf(INTR_CPU_Q, mcpup->cpu_q_base_pa, cpu_q_entries);
	if (ret != H_EOK)
		cmn_err(CE_PANIC, "cpu%d: cpu_mondo queue configuration "
		    "failed, error %lu", cpu->cpu_id, ret);

	ret = hv_cpu_qconf(INTR_DEV_Q, mcpup->dev_q_base_pa, dev_q_entries);
	if (ret != H_EOK)
		cmn_err(CE_PANIC, "cpu%d: dev_mondo queue configuration "
		    "failed, error %lu", cpu->cpu_id, ret);

	ret = hv_cpu_qconf(CPU_RQ, mcpup->cpu_rq_base_pa, CPU_RQ_ENTRIES);
	if (ret != H_EOK)
		cmn_err(CE_PANIC, "cpu%d: resumable error queue configuration "
		    "failed, error %lu", cpu->cpu_id, ret);

	ret = hv_cpu_qconf(CPU_NRQ, mcpup->cpu_nrq_base_pa,
	    CPU_NRQ_ENTRIES);
	if (ret != H_EOK)
		cmn_err(CE_PANIC, "cpu%d: non-resumable error queue "
		    "configuration failed, error %lu", cpu->cpu_id, ret);
}

void
cpu_intrq_setup(struct cpu *cpu)
{
	struct machcpu *mcpup = &cpu->cpu_m;
	int cpu_list_size;

	/*
	 * Allocate mondo data for xcalls.
	 */
	mcpup->mondo_data = contig_mem_alloc(INTR_REPORT_SIZE);
	if (mcpup->mondo_data == NULL)
		cmn_err(CE_PANIC, "cpu%d: cpu mondo_data allocation failed",
		    cpu->cpu_id);

	/*
	 *  Allocate a percpu list of NCPU for xcalls
	 */
	cpu_list_size = NCPU * sizeof (uint16_t);
	if (cpu_list_size < INTR_REPORT_SIZE)
		cpu_list_size = INTR_REPORT_SIZE;

	mcpup->cpu_list = contig_mem_alloc(cpu_list_size);
	if (mcpup->cpu_list == NULL)
		cmn_err(CE_PANIC, "cpu%d: cpu cpu_list allocation failed",
		    cpu->cpu_id);
	mcpup->cpu_list_ra = va_to_pa(mcpup->cpu_list);

	/*
	 * va_to_pa() is too expensive to call for every crosscall
	 * so we do it here at init time and save it in machcpu.
	 */
	mcpup->mondo_data_ra = va_to_pa(mcpup->mondo_data);

	/*
	 * Allocate sun4v interrupt and error queues.
	 */
	mcpup->cpu_q_va = contig_mem_alloc(INTR_CPU_Q_SIZE);
	if (mcpup->cpu_q_va == NULL)
		cmn_err(CE_PANIC, "cpu%d: cpu intrq allocation failed",
		    cpu->cpu_id);
	mcpup->cpu_q_base_pa = va_to_pa(mcpup->cpu_q_va);
	mcpup->cpu_q_size =  INTR_CPU_Q_SIZE;

	mcpup->dev_q_va = contig_mem_alloc(INTR_DEV_Q_SIZE);
	if (mcpup->dev_q_va == NULL)
		cmn_err(CE_PANIC, "cpu%d: dev intrq allocation failed",
		    cpu->cpu_id);
	mcpup->dev_q_base_pa = va_to_pa(mcpup->dev_q_va);
	mcpup->dev_q_size =  INTR_DEV_Q_SIZE;

	/* Allocate resumable queue and its kernel buffer */
	mcpup->cpu_rq_va = contig_mem_alloc(2 * CPU_RQ_SIZE);
	if (mcpup->cpu_rq_va == NULL)
		cmn_err(CE_PANIC, "cpu%d: resumable queue allocation failed",
		    cpu->cpu_id);
	mcpup->cpu_rq_base_pa = va_to_pa(mcpup->cpu_rq_va);
	mcpup->cpu_rq_size = CPU_RQ_SIZE;
	/* zero out the memory */
	bzero(mcpup->cpu_rq_va, 2 * CPU_RQ_SIZE);

	/* Allocate nonresumable queue here */
	mcpup->cpu_nrq_va = contig_mem_alloc(2 * CPU_NRQ_SIZE);
	if (mcpup->cpu_nrq_va == NULL)
		cmn_err(CE_PANIC, "cpu%d: nonresumable queue "
		    "allocation failed", cpu->cpu_id);
	mcpup->cpu_nrq_base_pa = va_to_pa(mcpup->cpu_nrq_va);
	mcpup->cpu_nrq_size = CPU_NRQ_SIZE;
	/* zero out the memory */
	bzero(mcpup->cpu_nrq_va, 2 * CPU_NRQ_SIZE);

}
