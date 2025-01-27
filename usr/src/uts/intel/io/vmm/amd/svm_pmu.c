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
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/kernel.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/x86_archext.h>

#include <sys/vmm_kernel.h>
#include "svm.h"
#include "svm_softc.h"
#include "svm_pmu.h"

/*
 * Allow guests to use perf counter resources.
 */
int svm_pmu_enabled = 1;

/*
 * Force guest exits (preclude disabling intercepts) access to perf counter
 * resources via RDPMC and RDMSR/WRMSR.
 */
int svm_pmu_force_exit = 0;

void
svm_pmu_init(struct svm_softc *svm_sc)
{
	if (!is_x86_feature(x86_featureset, X86FSET_AMD_PCEC) ||
	    svm_pmu_enabled == 0) {
		svm_sc->pmu_flavor = SPF_NONE;
		return;
	}

	switch (uarchrev_uarch(cpuid_getuarchrev(CPU))) {
	case X86_UARCH_AMD_LEGACY:
		svm_sc->pmu_flavor = SPF_PRE_ZEN;
		break;
	case X86_UARCH_AMD_ZEN1:
	case X86_UARCH_AMD_ZENPLUS:
		svm_sc->pmu_flavor = SPF_ZEN1;
		break;
	case X86_UARCH_AMD_ZEN2:
	case X86_UARCH_AMD_ZEN3:
	case X86_UARCH_AMD_ZEN4:
	case X86_UARCH_AMD_ZEN5:
		svm_sc->pmu_flavor = SPF_ZEN2;
		break;
	default:
		/* Exclude unrecognized uarch from perf counter access */
		svm_sc->pmu_flavor = SPF_NONE;
		return;
	}

	/* Turn on base and extended CPCs for all vCPUs */
	const uint_t maxcpu = vm_get_maxcpus(svm_sc->vm);
	for (uint_t i = 0; i < maxcpu; i++) {
		struct svm_pmu_vcpu *pmu_vcpu = svm_get_pmu(svm_sc, i);

		pmu_vcpu->spv_hma_state.hscs_flags = HCF_EN_BASE | HCF_EN_EXTD;
	}
}

static bool
svm_pmu_is_active(const struct svm_pmu_vcpu *pmu)
{
	return (pmu->spv_hma_state.hscs_flags != HCF_DISABLED);
}

static bool
svm_pmu_is_evt_msr(uint32_t msr)
{
	switch (msr) {
	case MSR_AMD_K7_PERF_EVTSEL0:
	case MSR_AMD_K7_PERF_EVTSEL1:
	case MSR_AMD_K7_PERF_EVTSEL2:
	case MSR_AMD_K7_PERF_EVTSEL3:
	case MSR_AMD_F15H_PERF_EVTSEL0:
	case MSR_AMD_F15H_PERF_EVTSEL1:
	case MSR_AMD_F15H_PERF_EVTSEL2:
	case MSR_AMD_F15H_PERF_EVTSEL3:
	case MSR_AMD_F15H_PERF_EVTSEL4:
	case MSR_AMD_F15H_PERF_EVTSEL5:
		return (true);
	default:
		return (false);
	}
}

static bool
svm_pmu_is_ctr_msr(uint32_t msr)
{
	switch (msr) {
	case MSR_AMD_K7_PERF_CTR0:
	case MSR_AMD_K7_PERF_CTR1:
	case MSR_AMD_K7_PERF_CTR2:
	case MSR_AMD_K7_PERF_CTR3:
	case MSR_AMD_F15H_PERF_CTR0:
	case MSR_AMD_F15H_PERF_CTR1:
	case MSR_AMD_F15H_PERF_CTR2:
	case MSR_AMD_F15H_PERF_CTR3:
	case MSR_AMD_F15H_PERF_CTR4:
	case MSR_AMD_F15H_PERF_CTR5:
		return (true);
	default:
		return (false);
	}
}

static uint_t
svm_pmu_msr_to_idx(uint32_t msr)
{
	switch (msr) {
	case MSR_AMD_K7_PERF_EVTSEL0:
	case MSR_AMD_K7_PERF_EVTSEL1:
	case MSR_AMD_K7_PERF_EVTSEL2:
	case MSR_AMD_K7_PERF_EVTSEL3:
		return (msr - MSR_AMD_K7_PERF_EVTSEL0);
	case MSR_AMD_K7_PERF_CTR0:
	case MSR_AMD_K7_PERF_CTR1:
	case MSR_AMD_K7_PERF_CTR2:
	case MSR_AMD_K7_PERF_CTR3:
		return (msr - MSR_AMD_K7_PERF_CTR0);
	case MSR_AMD_F15H_PERF_EVTSEL0:
	case MSR_AMD_F15H_PERF_EVTSEL1:
	case MSR_AMD_F15H_PERF_EVTSEL2:
	case MSR_AMD_F15H_PERF_EVTSEL3:
	case MSR_AMD_F15H_PERF_EVTSEL4:
	case MSR_AMD_F15H_PERF_EVTSEL5:
		return ((msr - MSR_AMD_F15H_PERF_EVTSEL0) / 2);
	case MSR_AMD_F15H_PERF_CTR0:
	case MSR_AMD_F15H_PERF_CTR1:
	case MSR_AMD_F15H_PERF_CTR2:
	case MSR_AMD_F15H_PERF_CTR3:
	case MSR_AMD_F15H_PERF_CTR4:
	case MSR_AMD_F15H_PERF_CTR5:
		return ((msr - MSR_AMD_F15H_PERF_CTR0) / 2);
	default:
		panic("unexpected perf. counter MSR: %X", msr);
	}
}

bool
svm_pmu_owned_msr(uint32_t msr)
{
	return (svm_pmu_is_evt_msr(msr) || svm_pmu_is_ctr_msr(msr));
}

/*
 * Is guest access to a given evtsel allowed for the "flavor" of the PMU?
 *
 * Initial access is fairly limited, providing access to only the evtsels
 * expected to be used by Linux `perf stat`.
 */
static bool
svm_pmu_evtsel_allowed(uint64_t evtsel, svm_pmu_flavor_t flavor)
{
	const uint64_t evt = evtsel & AMD_PERF_EVTSEL_EVT_MASK;
	const uint16_t umask = evtsel & AMD_PERF_EVTSEL_UNIT_MASK;

	/*
	 * Some of the perf counters have stayed fairly consistent in their
	 * identifiers throughout the AMD product line.
	 */
	switch (evt) {
	case 0x76:	/* CPU cycles */
	case 0xc0:	/* Retired instructions */
	case 0xc2:	/* Branch instructions */
	case 0xc3:	/* Branch misses */
		return (true);
	default:
		break;
	}

	if (flavor == SPF_PRE_ZEN) {
		switch (evt) {
		case 0x7d: /* Cache hits */
		case 0x7e: /* Cache misses */
			return (true);
		default:
			return (false);
		}
	} else if (flavor == SPF_ZEN1) {
		switch (evt) {
		case 0x60: /* L2 accesses (group 1) */
		case 0x64: /* Core to L2 access status */
			return (true);
		case 0x87: /* IC fetch stall */
			switch (umask) {
			case 0x0100: /* backend */
			case 0x0200: /* frontend */
				return (true);
			default:
				return (false);
			}
		default:
			return (false);
		}
	} else if (flavor == SPF_ZEN2) {
		switch (evt) {
		case 0x60: /* L2 accesses (group 1) */
		case 0x64: /* Core to L2 access status */
		case 0xa9: /* u-op queue empty (frontend stall) */
			return (true);
		default:
			return (false);
		}
	}

	return (false);
}

vm_msr_result_t
svm_pmu_rdmsr(struct svm_softc *svm_sc, int vcpu, uint32_t msr, uint64_t *valp)
{
	ASSERT(svm_pmu_owned_msr(msr));

	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);

	if (!svm_pmu_is_active(pmu)) {
		return (VMR_UNHANLDED);
	}

	if (svm_pmu_is_evt_msr(msr)) {
		const uint_t idx = svm_pmu_msr_to_idx(msr);

		*valp = pmu->spv_evtsel_shadow[idx];
	} else if (svm_pmu_is_ctr_msr(msr)) {
		const uint_t idx = svm_pmu_msr_to_idx(msr);

		*valp = pmu->spv_hma_state.hscs_regs[idx].hc_ctr;
	} else {
		/* UNREACHABLE */
		return (VMR_UNHANLDED);
	}

	return (VMR_OK);
}

vm_msr_result_t
svm_pmu_wrmsr(struct svm_softc *svm_sc, int vcpu, uint32_t msr, uint64_t val)
{
	ASSERT(svm_pmu_owned_msr(msr));

	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);
	const svm_pmu_flavor_t flavor = svm_sc->pmu_flavor;

	if (!svm_pmu_is_active(pmu)) {
		return (VMR_UNHANLDED);
	}

	if (svm_pmu_is_evt_msr(msr)) {
		const uint_t idx = svm_pmu_msr_to_idx(msr);

		/*
		 * Keep the unmodified evtsel shadowed, should the guest choose
		 * to read it out later.
		 *
		 * XXX: Should we balk at reserved bits being set?
		 */
		pmu->spv_evtsel_shadow[idx] = val;

		if (!svm_pmu_evtsel_allowed(val, flavor)) {
			/*
			 * Disable any counters which have been configured with
			 * an event selector which we do not allow access to.
			 */
			val = 0;
		}
		pmu->spv_hma_state.hscs_regs[idx].hc_evtsel = val;
	} else if (svm_pmu_is_ctr_msr(msr)) {
		const uint_t idx = svm_pmu_msr_to_idx(msr);

		pmu->spv_hma_state.hscs_regs[idx].hc_ctr = val;
	} else {
		/* UNREACHABLE */
		return (VMR_UNHANLDED);
	}

	return (VMR_OK);
}

bool
svm_pmu_rdpmc(struct svm_softc *svm_sc, int vcpu, uint32_t ecx, uint64_t *valp)
{
	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);

	if (!svm_pmu_is_active(pmu)) {
		return (false);
	}
	if (ecx >= SVM_PMU_MAX_COUNTERS) {
		return (false);
	}

	*valp = pmu->spv_hma_state.hscs_regs[ecx].hc_ctr;
	return (true);
}

/*
 * Attempt to load guest PMU state, if the guest vCPU happens to be actively
 * using any counters.  Host state will be saved if such loading occurs.
 *
 * The results of any state loading may require adjustment of guest intercepts
 * and thus demands a call to svm_apply_dirty() prior to VM entry.
 */
void
svm_pmu_enter(struct svm_softc *svm_sc, int vcpu)
{
	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);

	if (!svm_pmu_is_active(pmu)) {
		return;
	}

	hma_svm_cpc_res_t entry = hma_svm_cpc_enter(&pmu->spv_hma_state);

	/*
	 * Until per-vCPU MSR bitmaps are available, ignore ability to expose
	 * direct guest access to counter MSRs
	 */
	entry &= ~HSCR_ACCESS_CTR_MSR;

	if (entry != pmu->spv_last_entry) {
		/* Update intercepts to match what is allowed per HMA.  */
		if (entry & HSCR_ACCESS_RDPMC && svm_pmu_force_exit == 0) {
			svm_disable_intercept(svm_sc, vcpu, VMCB_CTRL1_INTCPT,
			    VMCB_INTCPT_RDPMC);
		} else {
			svm_enable_intercept(svm_sc, vcpu, VMCB_CTRL1_INTCPT,
			    VMCB_INTCPT_RDPMC);
		}
	}
	pmu->spv_last_entry = entry;
}

/*
 * If guest PMU state is active, save it, and restore the host state.
 */
void
svm_pmu_exit(struct svm_softc *svm_sc, int vcpu)
{
	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);

	if (!svm_pmu_is_active(pmu)) {
		return;
	}

	hma_svm_cpc_exit(&pmu->spv_hma_state);
}

static int
svm_pmu_data_read(struct vm *vm, int vcpuid, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_PMU_AMD);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_pmu_amd_v1));

	struct svm_softc *svm_sc = vm_get_cookie(vm);
	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpuid);
	struct vdi_pmu_amd_v1 *out = req->vdr_data;

	if (!svm_pmu_is_active(pmu)) {
		bzero(out, sizeof (out));
		return (0);
	}

	for (uint_t i = 0; i < SVM_PMU_MAX_COUNTERS; i++) {
		out->vpa_evtsel[i] = pmu->spv_evtsel_shadow[i];
		out->vpa_ctr[i] = pmu->spv_hma_state.hscs_regs[i].hc_ctr;
	}
	return (0);
}

static int
svm_pmu_data_write(struct vm *vm, int vcpuid, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_PMU_AMD);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_pmu_amd_v1));

	struct svm_softc *svm_sc = vm_get_cookie(vm);
	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpuid);
	const struct vdi_pmu_amd_v1 *src = req->vdr_data;

	if (!svm_pmu_is_active(pmu)) {
		/*
		 * Skip importing state for an inactive PMU.
		 *
		 * It might be appropriate to return an error here, but it's not
		 * clear what would be most appropriate (or what userspace would
		 * do in such a case).
		 */
		return (0);
	}

	const svm_pmu_flavor_t flavor = svm_sc->pmu_flavor;
	for (uint_t i = 0; i < SVM_PMU_MAX_COUNTERS; i++) {
		const uint64_t evtsel = src->vpa_evtsel[i];

		/*
		 * Shadow evtsel is kept as-is, but the "active" value undergoes
		 * same verification as guest WRMSR.
		 */
		pmu->spv_evtsel_shadow[i] = evtsel;
		if (svm_pmu_evtsel_allowed(evtsel, flavor)) {
			pmu->spv_hma_state.hscs_regs[i].hc_evtsel = evtsel;
		} else {
			pmu->spv_hma_state.hscs_regs[i].hc_evtsel = 0;
		}
		pmu->spv_hma_state.hscs_regs[i].hc_ctr = src->vpa_ctr[i];
	}
	return (0);
}

static const vmm_data_version_entry_t pmu_amd_v1 = {
	.vdve_class = VDC_PMU_AMD,
	.vdve_version = 1,
	.vdve_len_expect = sizeof (struct vdi_pmu_amd_v1),
	.vdve_vcpu_readf = svm_pmu_data_read,
	.vdve_vcpu_writef = svm_pmu_data_write,
};
VMM_DATA_VERSION(pmu_amd_v1);
