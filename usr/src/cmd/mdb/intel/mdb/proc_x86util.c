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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Doma Gergő Mihály <doma.gergo.mihaly@gmail.com>
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Consolidated routines that are shared between the 32-bit and 64-bit x86 mdb
 * proc targets.
 */

#include <mdb/mdb_proc.h>
#include <mdb/mdb_err.h>
#include <mdb/proc_x86util.h>
#include <mdb/mdb.h>

#include <libproc.h>
#include <sys/fp.h>
#include <ieeefp.h>
#include <sys/sysmacros.h>

const char *
fpcw2str(uint32_t cw, char *buf, size_t nbytes)
{
	char *end = buf + nbytes;
	char *p = buf;

	buf[0] = '\0';

	/*
	 * Decode all exception masks in the x87 FPU Control Word.
	 *
	 * See here:
	 * Intel® 64 and IA-32 Architectures Software Developer’s Manual,
	 * Volume 1: Basic Architecture, 8.1.5 x87 FPU Control Word
	 */
	if (cw & FPIM)	/* Invalid operation mask. */
		p += mdb_snprintf(p, (size_t)(end - p), "|IM");
	if (cw & FPDM)	/* Denormalized operand mask. */
		p += mdb_snprintf(p, (size_t)(end - p), "|DM");
	if (cw & FPZM)	/* Zero divide mask. */
		p += mdb_snprintf(p, (size_t)(end - p), "|ZM");
	if (cw & FPOM)	/* Overflow mask. */
		p += mdb_snprintf(p, (size_t)(end - p), "|OM");
	if (cw & FPUM)	/* Underflow mask. */
		p += mdb_snprintf(p, (size_t)(end - p), "|UM");
	if (cw & FPPM)	/* Precision mask. */
		p += mdb_snprintf(p, (size_t)(end - p), "|PM");

	/*
	 * Decode precision control options.
	 */
	switch (cw & FPPC) {
	case FPSIG24:
		/* 24-bit significand, single precision. */
		p += mdb_snprintf(p, (size_t)(end - p), "|SIG24");
		break;
	case FPSIG53:
		/* 53-bit significand, double precision. */
		p += mdb_snprintf(p, (size_t)(end - p), "|SIG53");
		break;
	case FPSIG64:
		/* 64-bit significand, double extended precision. */
		p += mdb_snprintf(p, (size_t)(end - p), "|SIG64");
		break;
	default:
		/*
		 * Should never happen.
		 * Value 0x00000100 is 'Reserved'.
		 */
		break;
	}

	/*
	 * Decode rounding control options.
	 */
	switch (cw & FPRC) {
	case FPRTN:
		/* Round to nearest, or to even if equidistant. */
		p += mdb_snprintf(p, (size_t)(end - p), "|RTN");
		break;
	case FPRD:
		/* Round down. */
		p += mdb_snprintf(p, (size_t)(end - p), "|RD");
		break;
	case FPRU:
		/* Round up. */
		p += mdb_snprintf(p, (size_t)(end - p), "|RU");
		break;
	case FPCHOP:
		/* Truncate. */
		p += mdb_snprintf(p, (size_t)(end - p), "|RTZ");
		break;
	default:
		/*
		 * This is a two-bit field.
		 * No other options left.
		 */
		break;
	}

	/*
	 * Decode infinity control options.
	 *
	 * This field has been retained for compatibility with
	 * the 287 and earlier co-processors.
	 * In the more modern FPUs, this bit is disregarded and
	 * both -infinity and +infinity are respected.
	 * Comment source: SIMPLY FPU by Raymond Filiatreault
	 */
	switch (cw & FPIC) {
	case FPP:
		/*
		 * Projective infinity.
		 * Both -infinity and +infinity are treated as
		 * unsigned infinity.
		 */
		p += mdb_snprintf(p, (size_t)(end - p), "|P");
		break;
	case FPA:
		/*
		 * Affine infinity.
		 * Respects both -infinity and +infinity.
		 */
		p += mdb_snprintf(p, (size_t)(end - p), "|A");
		break;
	default:
		/*
		 * This is a one-bit field.
		 * No other options left.
		 */
		break;
	}

	if (cw & WFPB17)
		p += mdb_snprintf(p, (size_t)(end - p), "|WFPB17");
	if (cw & WFPB24)
		p += mdb_snprintf(p, (size_t)(end - p), "|WFPB24");

	if (buf[0] == '|')
		return (buf + 1);

	return ("0");
}

const char *
fpsw2str(uint32_t cw, char *buf, size_t nbytes)
{
	char *end = buf + nbytes;
	char *p = buf;

	buf[0] = '\0';

	/*
	 * Decode all masks in the 80387 status word.
	 */
	if (cw & FPS_IE)
		p += mdb_snprintf(p, (size_t)(end - p), "|IE");
	if (cw & FPS_DE)
		p += mdb_snprintf(p, (size_t)(end - p), "|DE");
	if (cw & FPS_ZE)
		p += mdb_snprintf(p, (size_t)(end - p), "|ZE");
	if (cw & FPS_OE)
		p += mdb_snprintf(p, (size_t)(end - p), "|OE");
	if (cw & FPS_UE)
		p += mdb_snprintf(p, (size_t)(end - p), "|UE");
	if (cw & FPS_PE)
		p += mdb_snprintf(p, (size_t)(end - p), "|PE");
	if (cw & FPS_SF)
		p += mdb_snprintf(p, (size_t)(end - p), "|SF");
	if (cw & FPS_ES)
		p += mdb_snprintf(p, (size_t)(end - p), "|ES");
	if (cw & FPS_C0)
		p += mdb_snprintf(p, (size_t)(end - p), "|C0");
	if (cw & FPS_C1)
		p += mdb_snprintf(p, (size_t)(end - p), "|C1");
	if (cw & FPS_C2)
		p += mdb_snprintf(p, (size_t)(end - p), "|C2");
	if (cw & FPS_C3)
		p += mdb_snprintf(p, (size_t)(end - p), "|C3");
	if (cw & FPS_B)
		p += mdb_snprintf(p, (size_t)(end - p), "|B");

	if (buf[0] == '|')
		return (buf + 1);

	return ("0");
}

const char *
fpmxcsr2str(uint32_t mxcsr, char *buf, size_t nbytes)
{
	char *end = buf + nbytes;
	char *p = buf;

	buf[0] = '\0';

	/*
	 * Decode the MXCSR word
	 */
	if (mxcsr & SSE_IE)
		p += mdb_snprintf(p, (size_t)(end - p), "|IE");
	if (mxcsr & SSE_DE)
		p += mdb_snprintf(p, (size_t)(end - p), "|DE");
	if (mxcsr & SSE_ZE)
		p += mdb_snprintf(p, (size_t)(end - p), "|ZE");
	if (mxcsr & SSE_OE)
		p += mdb_snprintf(p, (size_t)(end - p), "|OE");
	if (mxcsr & SSE_UE)
		p += mdb_snprintf(p, (size_t)(end - p), "|UE");
	if (mxcsr & SSE_PE)
		p += mdb_snprintf(p, (size_t)(end - p), "|PE");

	if (mxcsr & SSE_DAZ)
		p += mdb_snprintf(p, (size_t)(end - p), "|DAZ");

	if (mxcsr & SSE_IM)
		p += mdb_snprintf(p, (size_t)(end - p), "|IM");
	if (mxcsr & SSE_DM)
		p += mdb_snprintf(p, (size_t)(end - p), "|DM");
	if (mxcsr & SSE_ZM)
		p += mdb_snprintf(p, (size_t)(end - p), "|ZM");
	if (mxcsr & SSE_OM)
		p += mdb_snprintf(p, (size_t)(end - p), "|OM");
	if (mxcsr & SSE_UM)
		p += mdb_snprintf(p, (size_t)(end - p), "|UM");
	if (mxcsr & SSE_PM)
		p += mdb_snprintf(p, (size_t)(end - p), "|PM");

	if ((mxcsr & SSE_RC) == (SSE_RD|SSE_RU))
		p += mdb_snprintf(p, (size_t)(end - p), "|RTZ");
	else if (mxcsr & SSE_RD)
		p += mdb_snprintf(p, (size_t)(end - p), "|RD");
	else if (mxcsr & SSE_RU)
		p += mdb_snprintf(p, (size_t)(end - p), "|RU");
	else
		p += mdb_snprintf(p, (size_t)(end - p), "|RTN");

	if (mxcsr & SSE_FZ)
		p += mdb_snprintf(p, (size_t)(end - p), "|FZ");

	if (buf[0] == '|')
		return (buf + 1);
	return ("0");
}

const char *
fptag2str(uint32_t val)
{
	/*
	 * Array of strings corresponding to FPU tag word values (see
	 * section 7.3.6 of the Intel Programmer's Reference Manual).
	 */
	const char *tag_strings[] = { "valid", "zero", "special", "empty" };

	if (val >= ARRAY_SIZE(tag_strings)) {
		return ("unknown");
	}

	return (tag_strings[val]);
}

static uintptr_t
xregs_data_ptr(const prxregset_hdr_t *prx, const prxregset_info_t *info)
{
	uintptr_t base = (uintptr_t)prx;
	return (base + info->pri_offset);
}

static boolean_t
xregs_valid_data(const prxregset_hdr_t *prx, const prxregset_info_t *info,
    size_t exp_size, const char *type)
{
	size_t last_byte;

	if (info->pri_size != exp_size) {
		mdb_warn("%s has unexpeced size 0x%lx, expected 0x%lx -- "
		    "cannot use\n", type, info->pri_size, exp_size);
		return (B_FALSE);
	}

	last_byte = (size_t)info->pri_size + (size_t)info->pri_offset;
	if (last_byte < MIN(info->pri_size, info->pri_offset)) {
		mdb_warn("%s size 0x%lx and offset 0x%lx appear to overflow -- "
		    "canot use\n", type, info->pri_size, info->pri_offset);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static const char *
fp_type_to_str(x86_vector_type_t type)
{
	switch (type) {
	case XMM:
		return ("128-bit %xmm");
	case YMM:
		return ("256-bit %ymm");
	case ZMM:
		return ("512-bit %zmm");
	default:
		return ("unknown");
	}
}

/*
 * Go through the xregs data that we have and make sure that it makes sense for
 * printing. In particular we need to make sure:
 *
 *  o The structure type is what we expect
 *  o That its overall size is correct
 *  o That we can find the expected set of data pointers that should be here
 *  o That the information pointers actually make sense and their contents are
 *    both the correct size and within the overall structure. Note, we do not
 *    check for overlapping data regions right now, meaning that some weird
 *    notes may still lead to weird data.
 */
static boolean_t
pt_xregs_process(const prxregset_hdr_t *prx, size_t found_size,
    x86_xregs_info_t *xinfo)
{
	bzero(xinfo, sizeof (*xinfo));

	if (prx->pr_type != PR_TYPE_XSAVE) {
		mdb_warn("prxregset has unknown type: 0x%x -- falling back "
		    "to fpregset_t\n", prx->pr_type);
		return (B_FALSE);
	}

	if (prx->pr_size < found_size) {
		mdb_warn("prxregset has greater size than we were given: "
		    "found 0x%lx, have 0x%lx -- falling back to fpregset_t\n",
		    prx->pr_size, found_size);
		return (B_FALSE);
	}

	for (uint32_t i = 0; i < prx->pr_ninfo; i++) {
		switch (prx->pr_info[i].pri_type) {
		case PRX_INFO_XCR:
			if (xregs_valid_data(prx, &prx->pr_info[i],
			    sizeof (prxregset_xcr_t), "xcr")) {
				xinfo->xri_xcr = (void *)xregs_data_ptr(prx,
				    &prx->pr_info[i]);
			}
			break;
		case PRX_INFO_XSAVE:
			if (xregs_valid_data(prx, &prx->pr_info[i],
			    sizeof (prxregset_xsave_t), "xsave")) {
				xinfo->xri_xsave = (void *)xregs_data_ptr(prx,
				    &prx->pr_info[i]);
			}
			break;
		case PRX_INFO_YMM:
			if (xregs_valid_data(prx, &prx->pr_info[i],
			    sizeof (prxregset_ymm_t), "ymm")) {
				xinfo->xri_ymm = (void *)xregs_data_ptr(prx,
				    &prx->pr_info[i]);
			}
			break;
		case PRX_INFO_OPMASK:
			if (xregs_valid_data(prx, &prx->pr_info[i],
			    sizeof (prxregset_opmask_t), "opmask")) {
				xinfo->xri_opmask = (void *)xregs_data_ptr(prx,
				    &prx->pr_info[i]);
			}
			break;
		case PRX_INFO_ZMM:
			if (xregs_valid_data(prx, &prx->pr_info[i],
			    sizeof (prxregset_zmm_t), "zmm")) {
				xinfo->xri_zmm = (void *)xregs_data_ptr(prx,
				    &prx->pr_info[i]);
			}
			break;
		case PRX_INFO_HI_ZMM:
			if (xregs_valid_data(prx, &prx->pr_info[i],
			    sizeof (prxregset_hi_zmm_t), "hi_zmm")) {
				xinfo->xri_hi_zmm = (void *)xregs_data_ptr(prx,
				    &prx->pr_info[i]);
			}
			break;
		default:
			mdb_warn("ignoring unexpected xreg info type: 0x%x\n",
			    prx->pr_info[i].pri_type);
			break;
		}
	}

	/*
	 * Now that we have gotten this far, we go and figure out what the
	 * largest type of information we actually have is. We check from the
	 * simplest to the most complex as to see the more complex state
	 * requires having the more basic state, due to how Intel designed the
	 * xsave state.
	 */
	if (xinfo->xri_xsave == NULL) {
		mdb_warn("missing required xsave information: xregs not "
		    "usable -- falling back to fpregset_t\n");
		return (B_FALSE);
	}

	xinfo->xri_type = XMM;
	if (xinfo->xri_ymm != NULL) {
		xinfo->xri_type = YMM;
		uint_t nzmm = 0;
		if (xinfo->xri_opmask != NULL)
			nzmm++;
		if (xinfo->xri_zmm != NULL)
			nzmm++;
		if (xinfo->xri_hi_zmm != NULL)
			nzmm++;
		if (nzmm == 3) {
			xinfo->xri_type = ZMM;
		} else if (nzmm != 0) {
			mdb_warn("encountered mismatched AVX-512 components, "
			    "defaulting back to YMM\n");
			mdb_warn("found opmask %s, zmm %s, hi zmm %s\n",
			    xinfo->xri_opmask != NULL ? "present" : "missing",
			    xinfo->xri_zmm != NULL ? "present" : "missing",
			    xinfo->xri_hi_zmm != NULL ? "present" : "missing");
		}
	}

	return (B_TRUE);
}

static void
pt_xreg_single_vector(const upad128_t *xmm, const upad128_t *ymm,
    const upad256_t *zmm, uint32_t num)
{

	if (zmm != NULL) {
		mdb_printf("%%zmm%u%s[511:384] 0x%08x %08x %08x %08x\n"
		    "       [383:256] 0x%08x %08x %08x %08x\n", num,
		    num >= 10 ? " " : "  ",
		    zmm->_l[7], zmm->_l[6], zmm->_l[5], zmm->_l[4],
		    zmm->_l[3], zmm->_l[2], zmm->_l[1], zmm->_l[0]);
	}

	if (ymm != NULL) {
		mdb_printf("%%ymm%u%s[255:128] 0x%08x %08x %08x %08x\n",
		    num, num >= 10 ? " " : "  ",
		    ymm->_l[3], ymm->_l[2], ymm->_l[1], ymm->_l[0]);
	}

	if (xmm != NULL) {
		mdb_printf("%%xmm%u%s[127:0]   0x%08x %08x %08x %08x\n",
		    num, num >= 10 ? " " : "  ",
		    xmm->_l[3], xmm->_l[2], xmm->_l[1], xmm->_l[0]);
	}

	/*
	 * Insert output spacing if we exceed more than one line which happens
	 * if ymm state is present.
	 */
	if (ymm != NULL) {
		mdb_printf("\n");
	}
}

/*
 * Variant of the above, but all of the data is one single register. This is
 * only used for the high zmm registers which are only present on amd64.
 */
#ifdef __amd64
static void
pt_xreg_single_u512(const upad512_t *zmm, uint32_t num)
{
	mdb_printf("%%zmm%u%s[511:384] 0x%08x %08x %08x %08x\n"
	    "       [383:256] 0x%08x %08x %08x %08x\n", num,
	    num >= 10 ? " " : "  ",
	    zmm->_l[15], zmm->_l[14], zmm->_l[13], zmm->_l[12],
	    zmm->_l[11], zmm->_l[10], zmm->_l[9], zmm->_l[8]);

	mdb_printf("%%zmm%u%s[255:128] 0x%08x %08x %08x %08x\n",
	    num, num >= 10 ? " " : "  ",
	    zmm->_l[7], zmm->_l[6], zmm->_l[5], zmm->_l[4]);

	mdb_printf("%%zmm%u%s[127:0]   0x%08x %08x %08x %08x\n",
	    num, num >= 10 ? " " : "  ",
	    zmm->_l[3], zmm->_l[2], zmm->_l[1], zmm->_l[0]);

	mdb_printf("\n");
}
#endif	/* __amd64 */

/*
 * There are two different cases that we need to consider for vector printing.
 * The first 16 FPU registers are shadowed as the low bits of xmm0 overlap with
 * ymm0, overlap with zmm0.
 */
static void
pt_xregs_vectors(const x86_xregs_info_t *xinfo)
{
	size_t nregs = ARRAY_SIZE(xinfo->xri_xsave->prx_fx_xmm);
	for (size_t i = 0; i < nregs; i++) {
		switch (xinfo->xri_type) {
		case XMM:
			pt_xreg_single_vector(&xinfo->xri_xsave->prx_fx_xmm[i],
			    NULL, NULL, i);
			break;
		case YMM:
			pt_xreg_single_vector(&xinfo->xri_xsave->prx_fx_xmm[i],
			    &xinfo->xri_ymm->prx_ymm[i], NULL, i);
			break;
		case ZMM:
			pt_xreg_single_vector(&xinfo->xri_xsave->prx_fx_xmm[i],
			    &xinfo->xri_ymm->prx_ymm[i],
			    &xinfo->xri_zmm->prx_zmm[i], i);
			break;
		}
	}

	/*
	 * If we have ZMM state, next print the remaining 16 registers and then
	 * the 8 opmask registers. Note, we only have the high ZMM registers on
	 * 64-bit processes.
	 */
	if (xinfo->xri_type == ZMM) {
#ifdef __amd64
		nregs = ARRAY_SIZE(xinfo->xri_hi_zmm->prx_hi_zmm);
		for (size_t i = 0; i < nregs; i++) {
			pt_xreg_single_u512(&xinfo->xri_hi_zmm->prx_hi_zmm[i],
			    i + 16);
		}
#endif	/* __amd64 */

		mdb_printf("%%k0  0x%016x\t\t%%k1  0x%016x\n",
		    xinfo->xri_opmask->prx_opmask[0],
		    xinfo->xri_opmask->prx_opmask[1]);
		mdb_printf("%%k2  0x%016x\t\t%%k3  0x%016x\n",
		    xinfo->xri_opmask->prx_opmask[2],
		    xinfo->xri_opmask->prx_opmask[3]);
		mdb_printf("%%k4  0x%016x\t\t%%k5  0x%016x\n",
		    xinfo->xri_opmask->prx_opmask[4],
		    xinfo->xri_opmask->prx_opmask[5]);
		mdb_printf("%%k6  0x%016x\t\t%%k7  0x%016x\n",
		    xinfo->xri_opmask->prx_opmask[6],
		    xinfo->xri_opmask->prx_opmask[7]);

		mdb_printf("\n");
	}
}

int
x86_pt_fpregs_common(uintptr_t addr, uint_t flags, int argc,
    prfpregset_t *fprsp)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_tid_t tid;
	prxregset_t *xregs = NULL;
	size_t xregsize = 0;
	x86_xregs_info_t xinfo;
	x86_vector_type_t vector_type = XMM;

	if (argc != 0)
		return (DCMD_USAGE);

	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) == PS_UNDEAD) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	if (Pstate(t->t_pshandle) == PS_LOST) {
		mdb_warn("debugger has lost control of process\n");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC)
		tid = (mdb_tgt_tid_t)addr;
	else
		tid = PTL_TID(t);

	/*
	 * We ultimately need both the xregs and the fpregs. The fpregs have
	 * included synthetic-kernel created state that is not part of the FPU
	 * (the status / xstatus bits). If we find the xregs state, then we
	 * focus on using its data in lieu of the standard fxsave piece.
	 */
	if (PTL_GETFPREGS(t, tid, fprsp) != 0) {
		mdb_warn("failed to get floating point registers");
		return (DCMD_ERR);
	}

	bzero(&xinfo, sizeof (x86_xregs_info_t));
	if (PTL_GETXREGS(t, tid, &xregs, &xregsize) == 0) {
		prxregset_hdr_t *prx = (prxregset_hdr_t *)xregs;
		if (!pt_xregs_process(prx, xregsize, &xinfo)) {
			PTL_FREEXREGS(t, xregs, xregsize);
			xregs = NULL;
		} else {
			vector_type = xinfo.xri_type;
		}
	} else if (errno != ENOENT && errno != ENODATA && errno != ENOTSUP) {
		mdb_warn("failed to get xregs");
	}

	/*
	 * As we only support the amd64 kernel, we basically phrase the FPU the
	 * same way regardless of whether it is a 32-bit or 64-bit process.
	 */
	mdb_printf("x86 FPU with %s registers\n", fp_type_to_str(vector_type));
	if (xinfo.xri_xcr != NULL) {
		mdb_printf("xcr0\t\t0x%lx\n", xinfo.xri_xcr->prx_xcr_xcr0);
		mdb_printf("xfd\t\t0x%lx\n", xinfo.xri_xcr->prx_xcr_xfd);
	}

	if (xinfo.xri_xsave != NULL) {
		mdb_printf("xstate_bv\t0x%lx\n",
		    xinfo.xri_xsave->prx_xsh_xstate_bv);
		mdb_printf("xcomp_bv\t0x%lx\n",
		    xinfo.xri_xsave->prx_xsh_xcomp_bv);

		mdb_printf("\n");
		/*
		 * xsave is required for us to use the xregset, so from here as
		 * it to print vectors.
		 */
		pt_xregs_vectors(&xinfo);
	} else {
		size_t nregs = ARRAY_SIZE(fprsp->fp_reg_set.fpchip_state.xmm);
		for (uint32_t i = 0; i < nregs; i++) {
			const upad128_t *u128 =
			    &fprsp->fp_reg_set.fpchip_state.xmm[i];
			pt_xreg_single_vector(u128, NULL, NULL, i);
		}

		mdb_printf("\n");
	}

	if (xregs != NULL) {
		PTL_FREEXREGS(t, xregs, xregsize);
	}

	return (DCMD_OK);
}

void
x86_pt_fpregs_sse_ctl(uint32_t mxcsr, uint32_t xstatus, char *buf,
    size_t buflen)
{
	mdb_printf("\nSSE Control State\n");
	mdb_printf("mxcsr  0x%04x (%s)\n", mxcsr,
	    fpmxcsr2str(mxcsr, buf, buflen));
	mdb_printf("xcp    0x%04x (%s)\n", xstatus,
	    fpmxcsr2str(xstatus, buf, buflen));
}
