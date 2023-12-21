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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This file implements various utility functions we use for the xsave tests.
 */

#include <string.h>
#include <strings.h>
#include <sys/auxv.h>
#include <sys/sysmacros.h>
#include <err.h>
#include <stdlib.h>
#include <procfs.h>
#include <sys/x86_archext.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/debug.h>
#include <ieeefp.h>

#include "xsave_util.h"

static uint_t xsu_proc_timeout = 60 * 1000; /* 60s in ms */

/*
 * Determine if we have the hardware support required for a given level of
 * hardware support.
 */
uint32_t
xsu_hwsupport(void)
{
	uint_t isa[3];
	uint_t nisa = getisax(isa, ARRAY_SIZE(isa));

	if (nisa != ARRAY_SIZE(isa)) {
		errx(EXIT_FAILURE, "did not get all %zu hwcap values, found %u",
		    ARRAY_SIZE(isa), nisa);
	}

	if ((isa[0] & AV_386_XSAVE) == 0) {
		errx(EXIT_FAILURE, "xsave not present: this test should have "
		    "been skipped");
	}

	if ((isa[1] & AV_386_2_AVX512F) != 0) {
		warnx("found %%zmm support");
		return (XSU_ZMM);
	}

	if ((isa[0] & AV_386_AVX) != 0) {
		warnx("found %%ymm support");
		return (XSU_YMM);
	}

	errx(EXIT_FAILURE, "no non-XMM xsave state found: this test should "
	    "have been skipped");
}

/*
 * Fill all the valid regions of an FPU based on treating the vector register as
 * a series of uint32_t values and going from there.
 */
void
xsu_fill(xsu_fpu_t *fpu, uint32_t level, uint32_t start)
{
	(void) memset(fpu, 0, sizeof (xsu_fpu_t));

	switch (level) {
	default:
		errx(EXIT_FAILURE, "given unknown xsu level: 0x%x", level);
	case XSU_YMM:
		for (uint32_t regno = 0; regno < XSU_MAX_YMM; regno++) {
			for (uint32_t u32 = 0; u32 < XSU_YMM_U32; u32++,
			    start++) {
				fpu->xf_reg[regno]._l[u32] = start;
			}
		}
		break;
	case XSU_ZMM:
		for (uint32_t regno = 0; regno < XSU_MAX_ZMM; regno++) {
			for (uint32_t u32 = 0; u32 < XSU_ZMM_U32; u32++,
			    start++) {
				fpu->xf_reg[regno]._l[u32] = start;
			}
		}
		for (uint32_t regno = 0; regno < ARRAY_SIZE(fpu->xf_opmask);
		    regno++) {
			uint64_t val = start | (((uint64_t)start + 1) << 32);
			fpu->xf_opmask[regno] = val;
			start += 2;
		}
		break;
	}
}

static void
xsu_overwrite_uctx_xmm(ucontext_t *uctx, const xsu_fpu_t *fpu)
{
	struct _fpchip_state *fp;

	fp = &uctx->uc_mcontext.fpregs.fp_reg_set.fpchip_state;
	for (uint32_t i = 0; i < XSU_MAX_XMM; i++) {
		(void) memcpy(&fp->xmm[i], &fpu->xf_reg[i]._l[0],
		    XSU_XMM_U32 * sizeof (uint32_t));
	}
}

static void
xsu_overwrite_uctx_ymm(uintptr_t arg, const xsu_fpu_t *fpu)
{
	prxregset_ymm_t *ymm = (void *)arg;

	for (uint32_t i = 0; i < XSU_MAX_YMM; i++) {
		(void) memcpy(&ymm->prx_ymm[i]._l[0],
		    &fpu->xf_reg[i]._l[XSU_XMM_U32],
		    XSU_XMM_U32 * sizeof (uint32_t));
	}
}

static void
xsu_overwrite_uctx_zmm(uintptr_t arg, const xsu_fpu_t *fpu)
{
	prxregset_zmm_t *zmm = (void *)arg;

	/*
	 * Because this is the low zmm registers, we actually use the max ymm
	 * value as that's what actually fits in the low zmm and not the full
	 * definition.
	 */
	for (uint32_t i = 0; i < XSU_MAX_YMM; i++) {
		(void) memcpy(&zmm->prx_zmm[i]._l[0],
		    &fpu->xf_reg[i]._l[XSU_YMM_U32],
		    XSU_YMM_U32 * sizeof (uint32_t));
	}
}

static void
xsu_overwrite_uctx_hi_zmm(uintptr_t arg, const xsu_fpu_t *fpu)
{
#ifdef __amd64
	prxregset_hi_zmm_t *zmm = (void *)arg;

	for (uint32_t i = XSU_MAX_YMM; i < XSU_MAX_ZMM; i++) {
		(void) memcpy(&zmm->prx_hi_zmm[i - XSU_MAX_YMM]._l[0],
		    &fpu->xf_reg[i]._l[0],
		    XSU_ZMM_U32 * sizeof (uint32_t));
	}
#else	/* !__amd64 */
	warnx("attempted to set High ZMM registers on a 32-bit process!");
	abort();
#endif	/* __amd64 */
}

void
xsu_overwrite_uctx(ucontext_t *uctx, const xsu_fpu_t *fpu, uint32_t hwsup)
{
	size_t xsave_size = sizeof (uc_xsave_t);
	void *new_buf;
	uc_xsave_t *ucs;
	uintptr_t write_ptr;

	if (hwsup != XSU_YMM && hwsup != XSU_ZMM) {
		errx(EXIT_FAILURE, "given unknown xsu level: 0x%x", hwsup);
	}

	if (hwsup >= XSU_YMM) {
		xsave_size += sizeof (prxregset_ymm_t);
	}

	if (hwsup >= XSU_ZMM) {
		xsave_size += sizeof (prxregset_zmm_t);
		xsave_size += sizeof (prxregset_opmask_t);
		if (XSU_MAX_ZMM > 16) {
			xsave_size += sizeof (prxregset_hi_zmm_t);
		}
	}

	new_buf = calloc(1, xsave_size);
	if (new_buf == NULL) {
		errx(EXIT_FAILURE, "failed to allocate xsave buf");
	}
	ucs = new_buf;
	ucs->ucx_vers = UC_XSAVE_VERS;
	ucs->ucx_len = xsave_size;
	if (hwsup >= XSU_YMM) {
		ucs->ucx_bv |= XFEATURE_AVX;
	}

	if (hwsup >= XSU_ZMM) {
		ucs->ucx_bv |= XFEATURE_AVX512_OPMASK | XFEATURE_AVX512_ZMM;
		if (XSU_MAX_ZMM > 16)
			ucs->ucx_bv |= XFEATURE_AVX512_HI_ZMM;
	}

	/*
	 * At this point we have rigged things up. XMM values are in the
	 * ucontext_t itself. After that we must write things out in the kernel
	 * signal order. Note, the XMM state is not set in the bit-vector
	 * because well, we don't actually use the xsave pieces for it because o
	 * the ucontext_t ABI has the xmm state always there. See
	 * uts/intel/os/fpu.c's big theory statement for more info.
	 */
	xsu_overwrite_uctx_xmm(uctx, fpu);
	write_ptr = (uintptr_t)new_buf + sizeof (uc_xsave_t);
	if (hwsup >= XSU_YMM) {
		xsu_overwrite_uctx_ymm(write_ptr, fpu);
		write_ptr += sizeof (prxregset_ymm_t);
	}

	if (hwsup >= XSU_ZMM) {
		(void) memcpy((void *)write_ptr, fpu->xf_opmask,
		    sizeof (fpu->xf_opmask));
		write_ptr += sizeof (fpu->xf_opmask);
		xsu_overwrite_uctx_zmm(write_ptr, fpu);
		write_ptr += sizeof (prxregset_zmm_t);
		if (XSU_MAX_ZMM > 16) {
			xsu_overwrite_uctx_hi_zmm(write_ptr, fpu);
			write_ptr += sizeof (prxregset_hi_zmm_t);
		}
	}

	uctx->uc_xsave = (long)(uintptr_t)new_buf;
}

static boolean_t
xsu_check_vector(const upad512_t *src, const upad512_t *chk, uint32_t regno,
    uint32_t nu32)
{
	boolean_t valid = B_TRUE;

	for (uint32_t i = 0; i < nu32; i++) {
		if (src->_l[i] != chk->_l[i]) {
			warnx("vec[%u] u32 %u differs: expected 0x%x, "
			    "found 0x%x", regno, i, src->_l[i], chk->_l[i]);
			valid = B_FALSE;
		}
	}

	return (valid);
}

boolean_t
xsu_same(const xsu_fpu_t *src, const xsu_fpu_t *check, uint32_t hwsup)
{
	boolean_t valid = B_TRUE;

	switch (hwsup) {
	default:
		errx(EXIT_FAILURE, "given unknown xsu level: 0x%x", hwsup);
	case XSU_YMM:
		for (uint32_t i = 0; i < XSU_MAX_YMM; i++) {
			if (!xsu_check_vector(&src->xf_reg[i],
			    &check->xf_reg[i], i, XSU_YMM_U32)) {
				valid = B_FALSE;
			}
		}
		break;
	case XSU_ZMM:
		for (uint32_t i = 0; i < XSU_MAX_ZMM; i++) {
			if (!xsu_check_vector(&src->xf_reg[i],
			    &check->xf_reg[i], i, XSU_ZMM_U32)) {
				valid = B_FALSE;
			}
		}
		for (uint32_t i = 0; i < ARRAY_SIZE(src->xf_opmask); i++) {
			if (src->xf_opmask[i] != check->xf_opmask[i]) {
				warnx("mask[%u] differs: expected 0x%" PRIx64
				    ", found 0x%" PRIx64, i, src->xf_opmask[i],
				    check->xf_opmask[i]);
				valid = B_FALSE;
			}
		}
		break;
	}
	return (valid);
}


void *
xsu_sleeper_thread(void *arg __unused)
{
	for (;;) {
		(void) sleep(100);
	}
	return (NULL);
}

static void
xsu_dump_vector(FILE *f, const upad512_t *reg, uint32_t nu32, const char *name,
    uint32_t idx)
{
	VERIFY3U(nu32 % 4, ==, 0);
	for (uint32_t i = 0; i < nu32; i += 4) {
		(void) fprintf(f, "%s[%02u] [%02u:%02u] = { 0x%08x 0x%08x "
		    "0x%08x 0x%08x }\n", name, idx, i + 3, i,  reg->_l[i + 3],
		    reg->_l[i + 2], reg->_l[i + 1], reg->_l[i]);
	}
}

void
xsu_dump(FILE *f, const xsu_fpu_t *fpu, uint32_t hwsup)
{

	switch (hwsup) {
	default:
		errx(EXIT_FAILURE, "given unknown xsu level: 0x%x", hwsup);
	case XSU_YMM:
		for (uint32_t i = 0; i < XSU_MAX_YMM; i++) {
			xsu_dump_vector(f, &fpu->xf_reg[i], XSU_YMM_U32,
			    "ymm", i);
		}
		break;
	case XSU_ZMM:
		for (uint32_t i = 0; i < XSU_MAX_ZMM; i++) {
			xsu_dump_vector(f, &fpu->xf_reg[i], XSU_ZMM_U32,
			    "zmm", i);
		}

		for (uint32_t i = 0; i < ARRAY_SIZE(fpu->xf_opmask); i++) {
			(void) fprintf(f, "%%k%u 0x%016" PRIx64"\n", i,
			    fpu->xf_opmask[i]);
		}
		break;
	}
}

typedef struct xsu_prx {
	uint32_t xp_hwsup;
	prxregset_xsave_t *xp_xsave;
	prxregset_ymm_t *xp_ymm;
	prxregset_opmask_t *xp_opmask;
	prxregset_zmm_t *xp_zmm;
	prxregset_hi_zmm_t *xp_hi_zmm;
} xsu_prx_t;

static void
xsu_fpu_to_xregs_xsave(xsu_prx_t *prx, const xsu_fpu_t *fpu)
{
	prx->xp_xsave->prx_fx_fcw = FPU_CW_INIT;
	prx->xp_xsave->prx_fx_mxcsr = SSE_MXCSR_INIT;
	for (uint32_t i = 0; i < XSU_MAX_XMM; i++) {
		(void) memcpy(&prx->xp_xsave->prx_fx_xmm[i],
		    &fpu->xf_reg[i]._l[0], XSU_XMM_U32 * sizeof (uint32_t));
	}

	prx->xp_xsave->prx_xsh_xstate_bv = XFEATURE_LEGACY_FP |
	    XFEATURE_SSE;
	if (prx->xp_hwsup >= XSU_YMM) {
		prx->xp_xsave->prx_xsh_xstate_bv |= XFEATURE_AVX;
	}

	if (prx->xp_hwsup >= XSU_ZMM) {
		prx->xp_xsave->prx_xsh_xstate_bv |= XFEATURE_AVX512;
	}
}

static void
xsu_fpu_to_xregs_ymm(xsu_prx_t *prx, const xsu_fpu_t *fpu)
{
	/* Copy the upper 128-bits to the YMM save area */
	for (uint32_t i = 0; i < XSU_MAX_YMM; i++) {
		(void) memcpy(&prx->xp_ymm->prx_ymm[i],
		    &fpu->xf_reg[i]._l[XSU_XMM_U32],
		    XSU_XMM_U32 * sizeof (uint32_t));
	}
}

static void
xsu_fpu_to_xregs_zmm(xsu_prx_t *prx, const xsu_fpu_t *fpu)
{
	/* The lower 16 regs are only 256-bit, the upper are 512-bit */
	for (uint32_t i = 0; i < MIN(XSU_MAX_ZMM, 16); i++) {
		(void) memcpy(&prx->xp_zmm->prx_zmm[i],
		    &fpu->xf_reg[i]._l[XSU_YMM_U32],
		    XSU_YMM_U32 * sizeof (uint32_t));
	}

#ifdef __amd64
	for (uint32_t i = 16; i < XSU_MAX_ZMM; i++) {
		(void) memcpy(&prx->xp_hi_zmm->prx_hi_zmm[i - 16],
		    &fpu->xf_reg[i]._l[0],
		    XSU_ZMM_U32 * sizeof (uint32_t));
	}
#endif

	(void) memcpy(prx->xp_opmask->prx_opmask, fpu->xf_opmask,
	    sizeof (prx->xp_opmask->prx_opmask));
}


void
xsu_fpu_to_xregs(const xsu_fpu_t *fpu, uint32_t hwsup, prxregset_t **prxp,
    size_t *sizep)
{
	uint32_t ninfo = 1, curinfo;
	size_t len = sizeof (prxregset_hdr_t) + sizeof (prxregset_info_t) +
	    sizeof (prxregset_xsave_t);
	prxregset_hdr_t *hdr;
	uint32_t off;
	xsu_prx_t prx;

	if (hwsup != XSU_YMM && hwsup != XSU_ZMM) {
		errx(EXIT_FAILURE, "given unknown xsu level: 0x%x", hwsup);
	}

	if (hwsup >= XSU_YMM) {
		len += sizeof (prxregset_info_t) + sizeof (prxregset_ymm_t);
		ninfo++;
	}

	if (hwsup >= XSU_ZMM) {
		len += 3 * sizeof (prxregset_info_t) +
		    sizeof (prxregset_opmask_t) + sizeof (prxregset_zmm_t) +
		    sizeof (prxregset_hi_zmm_t);
		ninfo += 3;
	}

	hdr = calloc(1, len);
	if (hdr == NULL) {
		err(EXIT_FAILURE, "failed to allocate prxregset_t (%zu bytes)",
		    len);
	}
	(void) memset(&prx, 0, sizeof (prx));
	prx.xp_hwsup = hwsup;

#ifdef __amd64
	VERIFY3U(len, <=, UINT32_MAX);
#endif	/* __amd64 */
	hdr->pr_type = PR_TYPE_XSAVE;
	hdr->pr_size = (uint32_t)len;
	hdr->pr_ninfo = ninfo;

	curinfo = 0;
	off = sizeof (prxregset_hdr_t) + sizeof (prxregset_info_t) * ninfo;
	hdr->pr_info[curinfo].pri_type = PRX_INFO_XSAVE;
	hdr->pr_info[curinfo].pri_size = sizeof (prxregset_xsave_t);
	hdr->pr_info[curinfo].pri_offset = off;
	prx.xp_xsave = (void *)((uintptr_t)hdr + off);
	off += sizeof (prxregset_xsave_t);
	curinfo++;

	if (hwsup >= XSU_YMM) {
		hdr->pr_info[curinfo].pri_type = PRX_INFO_YMM;
		hdr->pr_info[curinfo].pri_size = sizeof (prxregset_ymm_t);
		hdr->pr_info[curinfo].pri_offset = off;
		prx.xp_ymm = (void *)((uintptr_t)hdr + off);
		off += sizeof (prxregset_ymm_t);
		curinfo++;
	}

	if (hwsup >= XSU_ZMM) {
		hdr->pr_info[curinfo].pri_type = PRX_INFO_OPMASK;
		hdr->pr_info[curinfo].pri_size = sizeof (prxregset_opmask_t);
		hdr->pr_info[curinfo].pri_offset = off;
		prx.xp_opmask = (void *)((uintptr_t)hdr + off);
		off += sizeof (prxregset_opmask_t);
		curinfo++;

		hdr->pr_info[curinfo].pri_type = PRX_INFO_ZMM;
		hdr->pr_info[curinfo].pri_size = sizeof (prxregset_zmm_t);
		hdr->pr_info[curinfo].pri_offset = off;
		prx.xp_zmm = (void *)((uintptr_t)hdr + off);
		off += sizeof (prxregset_zmm_t);
		curinfo++;

		hdr->pr_info[curinfo].pri_type = PRX_INFO_HI_ZMM;
		hdr->pr_info[curinfo].pri_size = sizeof (prxregset_hi_zmm_t);
		hdr->pr_info[curinfo].pri_offset = off;
		prx.xp_hi_zmm = (void *)((uintptr_t)hdr + off);
		off += sizeof (prxregset_hi_zmm_t);
		curinfo++;
	}

	xsu_fpu_to_xregs_xsave(&prx, fpu);
	if (hwsup >= XSU_YMM) {
		xsu_fpu_to_xregs_ymm(&prx, fpu);
	}

	if (hwsup >= XSU_ZMM) {
		xsu_fpu_to_xregs_zmm(&prx, fpu);
	}

	*prxp = (prxregset_t *)hdr;
	*sizep = len;
}

/*
 * This pairs with xsu_proc_finish() below. The goal is to allow us to inject
 * state after hitting a breakpoint, which is generally used right before
 * something wants to print data.
 */
void
xsu_proc_bkpt(xsu_proc_t *xp)
{
	int perr;
	struct ps_prochandle *P;
	char *const argv[3] = { xp->xp_prog, xp->xp_arg, NULL };
	GElf_Sym sym;

	P = Pcreate(xp->xp_prog, argv, &perr, NULL, 0);
	if (P == NULL) {
		errx(EXIT_FAILURE, "failed to create %s: %s", xp->xp_prog,
		    Pcreate_error(perr));
	}

	xp->xp_proc = P;
	(void) Punsetflags(P, PR_RLC);
	if (Psetflags(P, PR_KLC | PR_BPTADJ) != 0) {
		int e = errno;
		Prelease(P, PRELEASE_KILL);
		errc(EXIT_FAILURE, e, "failed to set PR_KLC | PR_BPTADJ flags");
	}

	if (Pxlookup_by_name(P, LM_ID_BASE, xp->xp_object, xp->xp_symname, &sym,
	    NULL) != 0) {
		err(EXIT_FAILURE, "failed to find %s`%s", xp->xp_object,
		    xp->xp_symname);
	}

	if (Pfault(P, FLTBPT, 1) != 0) {
		errx(EXIT_FAILURE, "failed to set the FLTBPT disposition");
	}

	xp->xp_addr = sym.st_value;
	if (Psetbkpt(P, sym.st_value, &xp->xp_instr) != 0) {
		err(EXIT_FAILURE, "failed to set breakpoint on xsu_getfpu "
		    "(0x%" PRIx64 ")", sym.st_value);
	}

	if (Psetrun(P, 0, 0) != 0) {
		err(EXIT_FAILURE, "failed to resume running our target");
	}

	if (Pwait(P, xsu_proc_timeout) != 0) {
		err(EXIT_FAILURE, "%s did not hit our expected breakpoint",
		    argv[1]);
	}
}

/*
 * Run a process to completion and get its wait exit status.
 */
void
xsu_proc_finish(xsu_proc_t *xp)
{
	pid_t pid = Ppsinfo(xp->xp_proc)->pr_pid;

	if (Pdelbkpt(xp->xp_proc, xp->xp_addr, xp->xp_instr) != 0) {
		err(EXIT_FAILURE, "failed to delete %s`%s() breakpoint",
		    xp->xp_object, xp->xp_symname);
	}

	if (Psetrun(xp->xp_proc, 0, PRCFAULT) != 0) {
		err(EXIT_FAILURE, "failed to resume running our target");
	}

	if (waitpid(pid, &xp->xp_wait, 0) != pid) {
		err(EXIT_FAILURE, "failed to get our child processes's (%"
		    _PRIdID "), wait info", pid);
	}

	if (WIFEXITED(xp->xp_wait) == 0) {
		errx(EXIT_FAILURE, "our child process didn't actually exit!");
	}

	Pfree(xp->xp_proc);
	xp->xp_proc = NULL;
}

void
xsu_fpregset_xmm_set(fpregset_t *fpr, uint32_t seed)
{
	size_t nregs = ARRAY_SIZE(fpr->fp_reg_set.fpchip_state.xmm);
	for (uint32_t i = 0; i < nregs; i++) {
		upad128_t *u128 = &fpr->fp_reg_set.fpchip_state.xmm[i];
		for (uint32_t u32 = 0; u32 < XSU_XMM_U32; u32++, seed++) {
			u128->_l[u32] = seed;
		}
	}
}

void
xsu_xregs_xmm_set(prxregset_t *prx, uint32_t seed)
{
	prxregset_hdr_t *hdr = (prxregset_hdr_t *)prx;
	prxregset_xsave_t *xsave = NULL;

	for (uint32_t i = 0; i < hdr->pr_ninfo; i++) {
		if (hdr->pr_info[i].pri_type == PRX_INFO_XSAVE) {
			xsave = (void *)((uintptr_t)prx +
			    hdr->pr_info[i].pri_offset);
			break;
		}
	}

	if (xsave == NULL) {
		errx(EXIT_FAILURE, "asked to set xsave %%xmm regs, but no "
		    "xsave info present");
	}

	size_t nregs = ARRAY_SIZE(xsave->prx_fx_xmm);
	for (uint32_t i = 0; i < nregs; i++) {
		for (uint32_t u32 = 0; u32 < XSU_XMM_U32; u32++, seed++) {
			xsave->prx_fx_xmm[i]._l[u32] = seed;
		}
	}
}

static const prxregset_info_t *
xsu_xregs_find_comp(const prxregset_hdr_t *hdr, uint32_t comp, uintptr_t *datap)
{
	for (uint32_t i = 0; i < hdr->pr_ninfo; i++) {
		if (hdr->pr_info[i].pri_type == comp) {
			*datap = (uintptr_t)hdr + hdr->pr_info[i].pri_offset;
			return (&hdr->pr_info[i]);
		}
	}

	return (NULL);
}

boolean_t
xsu_xregs_comp_equal(const prxregset_t *src, const prxregset_t *dest,
    uint32_t comp)
{
	const prxregset_hdr_t *shdr = (prxregset_hdr_t *)src;
	const prxregset_hdr_t *dhdr = (prxregset_hdr_t *)dest;
	const prxregset_info_t *sinfo = NULL, *dinfo = NULL;
	uintptr_t sdata, ddata;

	sinfo = xsu_xregs_find_comp(shdr, comp, &sdata);
	if (sinfo == NULL) {
		warnx("source xregs missing component %u", comp);
		return (B_FALSE);
	}

	dinfo = xsu_xregs_find_comp(dhdr, comp, &ddata);
	if (dinfo == NULL) {
		warnx("destination xregs missing component %u", comp);
		return (B_FALSE);
	}

	if (sinfo->pri_size != dinfo->pri_size) {
		warnx("source xregs length 0x%x does not match dest xregs 0x%x",
		    sinfo->pri_size, dinfo->pri_size);
	}

	if (bcmp((void *)sdata, (void *)ddata, sinfo->pri_size) != 0) {
		warnx("component data differs: dumping!");
		for (uint32_t i = 0; i < sinfo->pri_offset; i++) {
			const uint8_t *su8 = (uint8_t *)sdata;
			const uint8_t *du8 = (uint8_t *)ddata;

			if (su8[i] != du8[i]) {
				(void) fprintf(stderr,
				    "src[%u] = 0x%2x\tdst[%u] = 0x%x\n",
				    i, su8[i], i, du8[i]);
			}
		}

		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
xsu_fpregs_cmp(const fpregset_t *fpr, const prxregset_t *prx)
{
	boolean_t valid = B_TRUE;
	const prxregset_hdr_t *hdr = (prxregset_hdr_t *)prx;
	const prxregset_xsave_t *xsave = NULL;
	uint16_t fpr_cw, fpr_sw;

	for (uint32_t i = 0; i < hdr->pr_ninfo; i++) {
		if (hdr->pr_info[i].pri_type == PRX_INFO_XSAVE) {
			xsave = (void *)((uintptr_t)prx +
			    hdr->pr_info[i].pri_offset);
			break;
		}
	}

	if (xsave == NULL) {
		warnx("xregs missing xsave component for fpregs comparison");
		return (B_FALSE);
	}

	/*
	 * First check the XMM registers because those don't require ifdefs,
	 * thankfully.
	 */
	size_t nregs = ARRAY_SIZE(fpr->fp_reg_set.fpchip_state.xmm);
	for (size_t i = 0; i < nregs; i++) {
		const upad128_t *u128 = &fpr->fp_reg_set.fpchip_state.xmm[i];
		for (uint32_t u32 = 0; u32 < XSU_XMM_U32; u32++) {
			if (u128->_l[u32] != xsave->prx_fx_xmm[i]._l[u32]) {
				valid = B_FALSE;
				(void) fprintf(stderr, "fpregset xmm[%u] "
				    "u32[%u] does not match xsave, fpregset: "
				    "0x%x, xsave: 0x%x\n", i, u32,
				    u128->_l[u32],
				    xsave->prx_fx_xmm[i]._l[u32]);
			}
		}
	}

	if (xsave->prx_fx_mxcsr != fpr->fp_reg_set.fpchip_state.mxcsr) {
		valid = B_FALSE;
		(void) fprintf(stderr, "mxcsr mismatched: fpregset: 0x%x, "
		    "xsave: 0x%x\n", fpr->fp_reg_set.fpchip_state.mxcsr,
		    xsave->prx_fx_mxcsr);
	}

	/*
	 * Extract the basic x87 state. This requires ifdefs because the 32-bit
	 * ABI here is a bit, particular. The 32-bit fpregs is the mcontext_t
	 * struct which is mostly opaque and we need to use the ieeefp.h types
	 * which are only visible for ILP32. It also treats 16-bit values as
	 * 32-bit ones, hence masking below.
	 */
#ifdef __amd64
	fpr_cw = fpr->fp_reg_set.fpchip_state.cw;
	fpr_sw = fpr->fp_reg_set.fpchip_state.sw;
#else	/* !__amd64 (__i386) */
	struct _fpstate fps;

	(void) memcpy(&fps, &fpr->fp_reg_set.fpchip_state, sizeof (fps));
	fpr_cw = fps.cw & 0xffff;
	fpr_sw = fps.sw & 0xffff;
#endif	/* __amd64 */

	if (fpr_cw != xsave->prx_fx_fcw) {
		valid = B_FALSE;
		(void) fprintf(stderr, "x87 cw mismatched: fpregset: 0x%x, "
		    "xsave: 0x%x\n", fpr_cw, xsave->prx_fx_fcw);
	}

	if (fpr_sw != xsave->prx_fx_fsw) {
		valid = B_FALSE;
		(void) fprintf(stderr, "x87 sw mismatched: fpregset: 0x%x, "
		    "xsave: 0x%x\n", fpr_sw, xsave->prx_fx_fsw);
	}

	return (valid);
}

void
xsu_ustack_alloc(ucontext_t *ctx)
{
	static void *stack = NULL;
	static size_t size = 0;

	if (size == 0) {
		long sys = sysconf(_SC_THREAD_STACK_MIN);
		if (sys == -1) {
			err(EXIT_FAILURE, "failed to get minimum stack size");
		}
		size = (size_t)sys;

		stack = calloc(size, sizeof (uint8_t));
		if (stack == NULL) {
			err(EXIT_FAILURE, "failed to allocate stack buffer");
		}
	}

	ctx->uc_stack.ss_size = size;
	ctx->uc_stack.ss_sp = stack;
	ctx->uc_stack.ss_flags = 0;
}
