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

#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/cpu.h>
#include <sys/intreg.h>
#include <sys/machcpuvar.h>
#include <vm/hat_sfmmu.h>
#include <sys/error.h>
#include <sys/hypervisor_api.h>

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

	ret = hv_cpu_qconf(CPU_RQ, mcpup->cpu_rq_base_pa, cpu_rq_entries);
	if (ret != H_EOK)
		cmn_err(CE_PANIC, "cpu%d: resumable error queue configuration "
		    "failed, error %lu", cpu->cpu_id, ret);

	ret = hv_cpu_qconf(CPU_NRQ, mcpup->cpu_nrq_base_pa, cpu_nrq_entries);
	if (ret != H_EOK)
		cmn_err(CE_PANIC, "cpu%d: non-resumable error queue "
		    "configuration failed, error %lu", cpu->cpu_id, ret);
}

int
cpu_intrq_setup(struct cpu *cpu)
{
	struct machcpu *mcpup = &cpu->cpu_m;
	size_t size;

	/*
	 * This routine will return with an error return if any
	 * contig_mem_alloc() fails.  It is expected that the caller will
	 * call cpu_intrq_cleanup() (or cleanup_cpu_common() which will).
	 * That will cleanly free only those blocks that were alloc'd.
	 */

	/*
	 * Allocate mondo data for xcalls.
	 */
	mcpup->mondo_data = contig_mem_alloc(INTR_REPORT_SIZE);

	if (mcpup->mondo_data == NULL) {
		cmn_err(CE_NOTE, "cpu%d: cpu mondo_data allocation failed",
		    cpu->cpu_id);
		return (ENOMEM);
	}
	/*
	 * va_to_pa() is too expensive to call for every crosscall
	 * so we do it here at init time and save it in machcpu.
	 */
	mcpup->mondo_data_ra = va_to_pa(mcpup->mondo_data);

	/*
	 *  Allocate a per-cpu list of ncpu_guest_max for xcalls
	 */
	size = ncpu_guest_max * sizeof (uint16_t);
	if (size < INTR_REPORT_SIZE)
		size = INTR_REPORT_SIZE;

	/*
	 * contig_mem_alloc() requires size to be a power of 2.
	 * Increase size to a power of 2 if necessary.
	 */
	if (!ISP2(size)) {
		size = 1 << highbit(size);
	}

	mcpup->cpu_list = contig_mem_alloc(size);

	if (mcpup->cpu_list == NULL) {
		cmn_err(CE_NOTE, "cpu%d: cpu cpu_list allocation failed",
		    cpu->cpu_id);
		return (ENOMEM);
	}
	mcpup->cpu_list_ra = va_to_pa(mcpup->cpu_list);

	/*
	 * Allocate sun4v interrupt and error queues.
	 */
	size = cpu_q_entries * INTR_REPORT_SIZE;

	mcpup->cpu_q_va = contig_mem_alloc(size);

	if (mcpup->cpu_q_va == NULL) {
		cmn_err(CE_NOTE, "cpu%d: cpu intrq allocation failed",
		    cpu->cpu_id);
		return (ENOMEM);
	}
	mcpup->cpu_q_base_pa = va_to_pa(mcpup->cpu_q_va);
	mcpup->cpu_q_size = size;

	/*
	 * Allocate device queues
	 */
	size = dev_q_entries * INTR_REPORT_SIZE;

	mcpup->dev_q_va = contig_mem_alloc(size);

	if (mcpup->dev_q_va == NULL) {
		cmn_err(CE_NOTE, "cpu%d: dev intrq allocation failed",
		    cpu->cpu_id);
		return (ENOMEM);
	}
	mcpup->dev_q_base_pa = va_to_pa(mcpup->dev_q_va);
	mcpup->dev_q_size = size;

	/*
	 * Allocate resumable queue and its kernel buffer
	 */
	size = cpu_rq_entries * Q_ENTRY_SIZE;

	mcpup->cpu_rq_va = contig_mem_alloc(2 * size);

	if (mcpup->cpu_rq_va == NULL) {
		cmn_err(CE_NOTE, "cpu%d: resumable queue allocation failed",
		    cpu->cpu_id);
		return (ENOMEM);
	}
	mcpup->cpu_rq_base_pa = va_to_pa(mcpup->cpu_rq_va);
	mcpup->cpu_rq_size = size;
	/* zero out the memory */
	bzero(mcpup->cpu_rq_va, 2 * size);

	/*
	 * Allocate non-resumable queues
	 */
	size = cpu_nrq_entries * Q_ENTRY_SIZE;

	mcpup->cpu_nrq_va = contig_mem_alloc(2 * size);

	if (mcpup->cpu_nrq_va == NULL) {
		cmn_err(CE_NOTE, "cpu%d: nonresumable queue allocation failed",
		    cpu->cpu_id);
		return (ENOMEM);
	}
	mcpup->cpu_nrq_base_pa = va_to_pa(mcpup->cpu_nrq_va);
	mcpup->cpu_nrq_size = size;
	/* zero out the memory */
	bzero(mcpup->cpu_nrq_va, 2 * size);

	return (0);
}

void
cpu_intrq_cleanup(struct cpu *cpu)
{
	struct machcpu *mcpup = &cpu->cpu_m;
	int cpu_list_size;
	uint64_t cpu_q_size;
	uint64_t dev_q_size;
	uint64_t cpu_rq_size;
	uint64_t cpu_nrq_size;

	/*
	 * Free mondo data for xcalls.
	 */
	if (mcpup->mondo_data) {
		contig_mem_free(mcpup->mondo_data, INTR_REPORT_SIZE);
		mcpup->mondo_data = NULL;
		mcpup->mondo_data_ra = NULL;
	}

	/*
	 *  Free per-cpu list of ncpu_guest_max for xcalls
	 */
	cpu_list_size = ncpu_guest_max * sizeof (uint16_t);
	if (cpu_list_size < INTR_REPORT_SIZE)
		cpu_list_size = INTR_REPORT_SIZE;

	/*
	 * contig_mem_alloc() requires size to be a power of 2.
	 * Increase size to a power of 2 if necessary.
	 */
	if (!ISP2(cpu_list_size)) {
		cpu_list_size = 1 << highbit(cpu_list_size);
	}

	if (mcpup->cpu_list) {
		contig_mem_free(mcpup->cpu_list, cpu_list_size);
		mcpup->cpu_list = NULL;
		mcpup->cpu_list_ra = NULL;
	}

	/*
	 * Free sun4v interrupt and error queues.
	 */
	if (mcpup->cpu_q_va) {
		cpu_q_size = cpu_q_entries * INTR_REPORT_SIZE;
		contig_mem_free(mcpup->cpu_q_va, cpu_q_size);
		mcpup->cpu_q_va = NULL;
		mcpup->cpu_q_base_pa = NULL;
		mcpup->cpu_q_size = 0;
	}

	if (mcpup->dev_q_va) {
		dev_q_size = dev_q_entries * INTR_REPORT_SIZE;
		contig_mem_free(mcpup->dev_q_va, dev_q_size);
		mcpup->dev_q_va = NULL;
		mcpup->dev_q_base_pa = NULL;
		mcpup->dev_q_size = 0;
	}

	if (mcpup->cpu_rq_va) {
		cpu_rq_size = cpu_rq_entries * Q_ENTRY_SIZE;
		contig_mem_free(mcpup->cpu_rq_va, 2 * cpu_rq_size);
		mcpup->cpu_rq_va = NULL;
		mcpup->cpu_rq_base_pa = NULL;
		mcpup->cpu_rq_size = 0;
	}

	if (mcpup->cpu_nrq_va) {
		cpu_nrq_size = cpu_nrq_entries * Q_ENTRY_SIZE;
		contig_mem_free(mcpup->cpu_nrq_va, 2 * cpu_nrq_size);
		mcpup->cpu_nrq_va = NULL;
		mcpup->cpu_nrq_base_pa = NULL;
		mcpup->cpu_nrq_size = 0;
	}
}
