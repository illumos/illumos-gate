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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mca_x86.h>
#include <sys/cpu_module_impl.h>
#include <sys/cpu_module_ms.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/pghw.h>
#include <sys/x86_archext.h>
#include <sys/sysmacros.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/log.h>
#include <sys/psw.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/errorq.h>
#include <sys/mca_x86.h>
#include <sys/fm/cpu/GMCA.h>
#include <sys/sysevent.h>
#include <sys/ontrap.h>

#include "gcpu.h"

/*
 * gcpu_mca_stack_flag is a debug assist option to capture a stack trace at
 * error logout time.  The stack will be included in the ereport if the
 * error type selects stack inclusion, or in all cases if
 * gcpu_mca_stack_ereport_include is nonzero.
 */
int gcpu_mca_stack_flag = 0;
int gcpu_mca_stack_ereport_include = 0;

/*
 * The number of times to re-read MCA telemetry to try to obtain a
 * consistent snapshot if we find it to be changing under our feet.
 */
int gcpu_mca_telemetry_retries = 5;

static gcpu_error_disp_t gcpu_errtypes[] = {

	/*
	 * Unclassified
	 */
	{
		FM_EREPORT_CPU_GENERIC_UNCLASSIFIED,
		NULL,
		FM_EREPORT_PAYLOAD_FLAGS_COMMON,
		MCAX86_SIMPLE_UNCLASSIFIED_MASKON,
		MCAX86_SIMPLE_UNCLASSIFIED_MASKOFF
	},

	/*
	 * Microcode ROM Parity Error
	 */
	{
		FM_EREPORT_CPU_GENERIC_MC_CODE_PARITY,
		NULL,
		FM_EREPORT_PAYLOAD_FLAGS_COMMON,
		MCAX86_SIMPLE_MC_CODE_PARITY_MASKON,
		MCAX86_SIMPLE_MC_CODE_PARITY_MASKOFF
	},

	/*
	 * External - BINIT# from another processor during power-on config
	 */
	{
		FM_EREPORT_CPU_GENERIC_EXTERNAL,
		NULL,
		FM_EREPORT_PAYLOAD_FLAGS_COMMON,
		MCAX86_SIMPLE_EXTERNAL_MASKON,
		MCAX86_SIMPLE_EXTERNAL_MASKOFF
	},

	/*
	 * Functional redundancy check master/slave error
	 */
	{
		FM_EREPORT_CPU_GENERIC_FRC,
		NULL,
		FM_EREPORT_PAYLOAD_FLAGS_COMMON,
		MCAX86_SIMPLE_FRC_MASKON,
		MCAX86_SIMPLE_FRC_MASKOFF
	},

	/*
	 * Internal timer error
	 */
	{
		FM_EREPORT_CPU_GENERIC_INTERNAL_TIMER,
		NULL,
		FM_EREPORT_PAYLOAD_FLAGS_COMMON,
		MCAX86_SIMPLE_INTERNAL_TIMER_MASKON,
		MCAX86_SIMPLE_INTERNAL_TIMER_MASKOFF
	},

	/*
	 * Internal unclassified
	 */
	{
		FM_EREPORT_CPU_GENERIC_INTERNAL_UNCLASS,
		NULL,
		FM_EREPORT_PAYLOAD_FLAGS_COMMON,
		MCAX86_SIMPLE_INTERNAL_UNCLASS_MASK_MASKON,
		MCAX86_SIMPLE_INTERNAL_UNCLASS_MASK_MASKOFF
	},

	/*
	 * Compound error codes - generic memory hierarchy
	 */
	{
		FM_EREPORT_CPU_GENERIC_GENMEMHIER,
		NULL,
		FM_EREPORT_PAYLOAD_FLAGS_COMMON, /* yes, no compound name */
		MCAX86_COMPOUND_GENERIC_MEMHIER_MASKON,
		MCAX86_COMPOUND_GENERIC_MEMHIER_MASKOFF
	},

	/*
	 * Compound error codes - TLB errors
	 */
	{
		FM_EREPORT_CPU_GENERIC_TLB,
		"%1$s" "TLB" "%2$s" "_ERR",
		FM_EREPORT_PAYLOAD_FLAGS_COMPOUND_ERR,
		MCAX86_COMPOUND_TLB_MASKON,
		MCAX86_COMPOUND_TLB_MASKOFF
	},

	/*
	 * Compound error codes - memory hierarchy
	 */
	{
		FM_EREPORT_CPU_GENERIC_MEMHIER,
		"%1$s" "CACHE" "%2$s" "_" "%3$s" "_ERR",
		FM_EREPORT_PAYLOAD_FLAGS_COMPOUND_ERR,
		MCAX86_COMPOUND_MEMHIER_MASKON,
		MCAX86_COMPOUND_MEMHIER_MASKOFF
	},

	/*
	 * Compound error codes - bus and interconnect errors
	 */
	{
		FM_EREPORT_CPU_GENERIC_BUS_INTERCONNECT,
		"BUS" "%2$s" "_" "%4$s" "_" "%3$s" "_" "%5$s" "_" "%6$s" "_ERR",
		FM_EREPORT_PAYLOAD_FLAGS_COMPOUND_ERR,
		MCAX86_COMPOUND_BUS_INTERCONNECT_MASKON,
		MCAX86_COMPOUND_BUS_INTERCONNECT_MASKOFF
	},
};

static gcpu_error_disp_t gcpu_unknown = {
	FM_EREPORT_CPU_GENERIC_UNKNOWN,
	"UNKNOWN",
	FM_EREPORT_PAYLOAD_FLAGS_COMMON,
	0,
	0
};

static errorq_t *gcpu_mca_queue;
static kmutex_t gcpu_mca_queue_lock;

static const gcpu_error_disp_t *
gcpu_disp_match(uint16_t code)
{
	const gcpu_error_disp_t *ged = gcpu_errtypes;
	int i;

	for (i = 0; i < sizeof (gcpu_errtypes) / sizeof (gcpu_error_disp_t);
	    i++, ged++) {
		uint16_t on = ged->ged_errcode_mask_on;
		uint16_t off = ged->ged_errcode_mask_off;

		if ((code & on) == on && (code & off) == 0)
			return (ged);
	}

	return (NULL);
}

static uint8_t
bit_strip(uint16_t code, uint16_t mask, uint16_t shift)
{
	return ((uint8_t)(code & mask) >> shift);
}

#define	BIT_STRIP(code, name) \
	bit_strip(code, MCAX86_ERRCODE_##name##_MASK, \
	MCAX86_ERRCODE_##name##_SHIFT)

#define	GCPU_MNEMONIC_UNDEF	"undefined"
#define	GCPU_MNEMONIC_RESVD	"reserved"

/*
 * Mappings of TT, LL, RRRR, PP, II and T values to compound error name
 * mnemonics and to ereport class name components.
 */

struct gcpu_mnexp {
	const char *mne_compound;	/* used in expanding compound errname */
	const char *mne_ereport;	/* used in expanding ereport class */
};

static struct gcpu_mnexp gcpu_TT_mnemonics[] = { /* MCAX86_ERRCODE_TT_* */
	{ "I", FM_EREPORT_CPU_GENERIC_TT_INSTR },		/* INSTR */
	{ "D", FM_EREPORT_CPU_GENERIC_TT_DATA },		/* DATA */
	{ "G", FM_EREPORT_CPU_GENERIC_TT_GEN },			/* GEN */
	{ GCPU_MNEMONIC_UNDEF, "" }
};

static struct gcpu_mnexp gcpu_LL_mnemonics[] = { /* MCAX86_ERRCODE_LL_* */
	{ "LO", FM_EREPORT_CPU_GENERIC_LL_L0 },			/* L0 */
	{ "L1",	FM_EREPORT_CPU_GENERIC_LL_L1 },			/* L1 */
	{ "L2",	FM_EREPORT_CPU_GENERIC_LL_L2 },			/* L2 */
	{ "LG", FM_EREPORT_CPU_GENERIC_LL_LG }			/* LG */
};

static struct gcpu_mnexp gcpu_RRRR_mnemonics[] = { /* MCAX86_ERRCODE_RRRR_* */
	{ "ERR", FM_EREPORT_CPU_GENERIC_RRRR_ERR },		/* ERR */
	{ "RD",	FM_EREPORT_CPU_GENERIC_RRRR_RD },		/* RD */
	{ "WR", FM_EREPORT_CPU_GENERIC_RRRR_WR },		/* WR */
	{ "DRD", FM_EREPORT_CPU_GENERIC_RRRR_DRD },		/* DRD */
	{ "DWR", FM_EREPORT_CPU_GENERIC_RRRR_DWR },		/* DWR */
	{ "IRD", FM_EREPORT_CPU_GENERIC_RRRR_IRD },		/* IRD */
	{ "PREFETCH", FM_EREPORT_CPU_GENERIC_RRRR_PREFETCH },	/* PREFETCH */
	{ "EVICT", FM_EREPORT_CPU_GENERIC_RRRR_EVICT },		/* EVICT */
	{ "SNOOP", FM_EREPORT_CPU_GENERIC_RRRR_SNOOP },		/* SNOOP */
};

static struct gcpu_mnexp gcpu_PP_mnemonics[] = { /* MCAX86_ERRCODE_PP_* */
	{ "SRC", FM_EREPORT_CPU_GENERIC_PP_SRC },		/* SRC */
	{ "RES", FM_EREPORT_CPU_GENERIC_PP_RES },		/* RES */
	{ "OBS", FM_EREPORT_CPU_GENERIC_PP_OBS },		/* OBS */
	{ "", FM_EREPORT_CPU_GENERIC_PP_GEN }			/* GEN */
};

static struct gcpu_mnexp gcpu_II_mnemonics[] = { /* MCAX86_ERRCODE_II_* */
	{ "M", FM_EREPORT_CPU_GENERIC_II_MEM },			/* MEM */
	{ GCPU_MNEMONIC_RESVD, "" },
	{ "IO", FM_EREPORT_CPU_GENERIC_II_IO },			/* IO */
	{ "", FM_EREPORT_CPU_GENERIC_II_GEN }			/* GEN */
};

static struct gcpu_mnexp gcpu_T_mnemonics[] = {	 /* MCAX86_ERRCODE_T_* */
	{ "NOTIMEOUT", FM_EREPORT_CPU_GENERIC_T_NOTIMEOUT },	/* NONE */
	{ "TIMEOUT", FM_EREPORT_CPU_GENERIC_T_TIMEOUT }		/* TIMEOUT */
};

enum gcpu_mn_namespace {
	GCPU_MN_NAMESPACE_COMPOUND,
	GCPU_MN_NAMESPACE_EREPORT
};

static const char *
gcpu_mnemonic(const struct gcpu_mnexp *tbl, size_t tbl_sz, uint8_t val,
    enum gcpu_mn_namespace nspace)
{
	if (val >= tbl_sz)
		return (GCPU_MNEMONIC_UNDEF);	/* for all namespaces */

	switch (nspace) {
	case GCPU_MN_NAMESPACE_COMPOUND:
		return (tbl[val].mne_compound);
		/*NOTREACHED*/

	case GCPU_MN_NAMESPACE_EREPORT:
		return (tbl[val].mne_ereport);
		/*NOTREACHED*/

	default:
		return (GCPU_MNEMONIC_UNDEF);
		/*NOTREACHED*/
	}
}

/*
 * The ereport class leaf component is either a simple string with no
 * format specifiers, or a string with one or more embedded %n$s specifiers -
 * positional selection for string arguments.  The kernel snprintf does
 * not support %n$ (and teaching it to do so is too big a headache) so
 * we will expand this restricted format string ourselves.
 */

#define	GCPU_CLASS_VARCOMPS	7

#define	GCPU_MNEMONIC(code, name, nspace) \
	gcpu_mnemonic(gcpu_##name##_mnemonics, \
	sizeof (gcpu_##name##_mnemonics) / sizeof (struct gcpu_mnexp), \
	BIT_STRIP(code, name), nspace)

static void
gcpu_mn_fmt(const char *fmt, char *buf, size_t buflen, uint64_t status,
    enum gcpu_mn_namespace nspace)
{
	uint16_t code = MCAX86_ERRCODE(status);
	const char *mn[GCPU_CLASS_VARCOMPS];
	char *p = buf;			/* current position in buf */
	char *q = buf + buflen;		/* pointer past last char in buf */
	int which, expfmtchar, error;
	char c;

	mn[0] = GCPU_MNEMONIC(code, TT, nspace);
	mn[1] = GCPU_MNEMONIC(code, LL, nspace);
	mn[2] = GCPU_MNEMONIC(code, RRRR, nspace);
	mn[3] = GCPU_MNEMONIC(code, PP, nspace);
	mn[4] = GCPU_MNEMONIC(code, II, nspace);
	mn[5] = GCPU_MNEMONIC(code, T, nspace);
	mn[6] = (status & MSR_MC_STATUS_UC) ? "_uc" : "";

	while (p < q - 1 && (c = *fmt++) != '\0') {
		if (c != '%') {
			/* not the beginning of a format specifier - copy */
			*p++ = c;
			continue;
		}

		error = 0;
		which = -1;
		expfmtchar = -1;

nextfmt:
		if ((c = *fmt++) == '\0')
			break;	/* early termination of fmt specifier */

		switch (c) {
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
			if (which != -1) { /* allow only one positional digit */
				error++;
				break;
			}
			which = c - '1';
			goto nextfmt;
			/*NOTREACHED*/

		case '$':
			if (which == -1) { /* no position specified */
				error++;
				break;
			}
			expfmtchar = 's';
			goto nextfmt;
			/*NOTREACHED*/

		case 's':
			if (expfmtchar != 's') {
				error++;
				break;
			}
			(void) snprintf(p, (uintptr_t)q - (uintptr_t)p, "%s",
			    mn[which]);
			p += strlen(p);
			break;

		default:
			error++;
			break;
		}

		if (error)
			break;
	}

	*p = '\0';	/* NUL termination */
}

static void
gcpu_erpt_clsfmt(const char *fmt, char *buf, size_t buflen, uint64_t status,
    const char *cpuclass, const char *leafclass)
{
	char *p = buf;			/* current position in buf */
	char *q = buf + buflen;		/* pointer past last char in buf */

	(void) snprintf(buf, (uintptr_t)q - (uintptr_t)p, "%s.%s.",
	    FM_ERROR_CPU, cpuclass ? cpuclass : FM_EREPORT_CPU_GENERIC);

	p += strlen(p);
	if (p >= q)
		return;

	if (leafclass == NULL) {
		gcpu_mn_fmt(fmt, p, (uintptr_t)q - (uintptr_t)p, status,
		    GCPU_MN_NAMESPACE_EREPORT);
	} else {
		(void) snprintf(p, (uintptr_t)q - (uintptr_t)p, "%s",
		    leafclass);
	}
}

/*
 * Create an "hc" scheme FMRI identifying the given cpu.  We don't know
 * the actual topology/connectivity of cpus in the system, so we'll
 * apply /motherboard=0/chip=.../cpu=... in all cases.
 */
static nvlist_t *
gcpu_fmri_create(cmi_hdl_t hdl, nv_alloc_t *nva)
{
	nvlist_t *nvl;

	if ((nvl = fm_nvlist_create(nva)) == NULL)
		return (NULL);

	fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, NULL, 3,
	    "motherboard", 0,
	    "chip", cmi_hdl_chipid(hdl),
	    "cpu", cmi_hdl_coreid(hdl));

	return (nvl);
}

int gcpu_bleat_count_thresh = 5;
hrtime_t gcpu_bleat_min_interval = 10 * 1000000000ULL;

/*
 * Called when we are unable to propogate a logout structure onto an
 * errorq for subsequent ereport preparation and logging etc.  The caller
 * should usually only decide to call this for severe errors - those we
 * suspect we may need to panic for.
 */
static void
gcpu_bleat(cmi_hdl_t hdl, gcpu_logout_t *gcl)
{
	hrtime_t now  = gethrtime_waitfree();
	static hrtime_t gcpu_last_bleat;
	gcpu_bank_logout_t *gbl;
	static int bleatcount;
	int i;

	/*
	 * Throttle spamming of the console.  The first gcpu_bleat_count_thresh
	 * can come as fast as we like, but once we've spammed that many
	 * to the console we require a minimum interval to pass before
	 * any more complaints.
	 */
	if (++bleatcount > gcpu_bleat_count_thresh) {
		if (now - gcpu_last_bleat < gcpu_bleat_min_interval)
			return;
		else
			bleatcount = 0;
	}
	gcpu_last_bleat = now;

	cmn_err(CE_WARN, "Machine-Check Errors unlogged on chip %d core %d, "
	    "raw dump follows", cmi_hdl_chipid(hdl), cmi_hdl_coreid(hdl));
	cmn_err(CE_WARN, "MCG_STATUS 0x%016llx",
	    (u_longlong_t)gcl->gcl_mcg_status);
	for (i = 0, gbl = &gcl->gcl_data[0]; i < gcl->gcl_nbanks; i++, gbl++) {
		uint64_t status = gbl->gbl_status;

		if (!(status & MSR_MC_STATUS_VAL))
			continue;

		switch (status & (MSR_MC_STATUS_ADDRV | MSR_MC_STATUS_MISCV)) {
		case MSR_MC_STATUS_ADDRV | MSR_MC_STATUS_MISCV:
			cmn_err(CE_WARN, "Bank %d (offset 0x%llx) "
			    "STAT 0x%016llx ADDR 0x%016llx MISC 0x%016llx",
			    i, IA32_MSR_MC(i, STATUS),
			    (u_longlong_t)status,
			    (u_longlong_t)gbl->gbl_addr,
			    (u_longlong_t)gbl->gbl_misc);
			break;

		case MSR_MC_STATUS_ADDRV:
			cmn_err(CE_WARN, "Bank %d (offset 0x%llx) "
			    "STAT 0x%016llx ADDR 0x%016llx",
			    i, IA32_MSR_MC(i, STATUS),
			    (u_longlong_t)status,
			    (u_longlong_t)gbl->gbl_addr);
			break;

		case MSR_MC_STATUS_MISCV:
			cmn_err(CE_WARN, "Bank %d (offset 0x%llx) "
			    "STAT 0x%016llx MISC 0x%016llx",
			    i, IA32_MSR_MC(i, STATUS),
			    (u_longlong_t)status,
			    (u_longlong_t)gbl->gbl_misc);
			break;

		default:
			cmn_err(CE_WARN, "Bank %d (offset 0x%llx) "
			    "STAT 0x%016llx",
			    i, IA32_MSR_MC(i, STATUS),
			    (u_longlong_t)status);
			break;

		}
	}
}

#define	_GCPU_BSTATUS(status, what) \
	FM_EREPORT_PAYLOAD_NAME_MC_STATUS_##what, DATA_TYPE_BOOLEAN_VALUE, \
	(status) & MSR_MC_STATUS_##what ? B_TRUE : B_FALSE

static void
gcpu_ereport_add_logout(nvlist_t *ereport, const gcpu_logout_t *gcl,
    uint_t bankno, const gcpu_error_disp_t *ged, uint16_t code)
{
	uint64_t members = ged ? ged->ged_ereport_members :
	    FM_EREPORT_PAYLOAD_FLAGS_COMMON;
	uint64_t mcg = gcl->gcl_mcg_status;
	int mcip = mcg & MCG_STATUS_MCIP;
	const gcpu_bank_logout_t *gbl = &gcl->gcl_data[bankno];
	uint64_t bstat = gbl->gbl_status;

	/*
	 * Include the compound error name if requested and if this
	 * is a compound error type.
	 */
	if (members & FM_EREPORT_PAYLOAD_FLAG_COMPOUND_ERR && ged &&
	    ged->ged_compound_fmt != NULL) {
		char buf[FM_MAX_CLASS];

		gcpu_mn_fmt(ged->ged_compound_fmt, buf, sizeof (buf), code,
		    GCPU_MN_NAMESPACE_COMPOUND);
		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_COMPOUND_ERR,
		    DATA_TYPE_STRING, buf, NULL);
	}

	/*
	 * Include disposition information for this error
	 */
	if (members & FM_EREPORT_PAYLOAD_FLAG_DISP &&
	    gbl->gbl_disp != 0) {
		int i, empty = 1;
		char buf[128];
		char *p = buf, *q = buf + 128;
		static struct _gcpu_disp_name {
			uint64_t dv;
			const char *dn;
		} disp_names[] = {
			{ CMI_ERRDISP_CURCTXBAD,
			    "processor_context_corrupt" },
			{ CMI_ERRDISP_RIPV_INVALID,
			    "return_ip_invalid" },
			{ CMI_ERRDISP_UC_UNCONSTRAINED,
			    "unconstrained" },
			{ CMI_ERRDISP_FORCEFATAL,
			    "forcefatal" },
			{ CMI_ERRDISP_IGNORED,
			    "ignored" },
			{ CMI_ERRDISP_PCC_CLEARED,
			    "corrupt_context_cleared" },
			{ CMI_ERRDISP_UC_CLEARED,
			    "uncorrected_data_cleared" },
			{ CMI_ERRDISP_POISONED,
			    "poisoned" },
			{ CMI_ERRDISP_INCONSISTENT,
			    "telemetry_unstable" },
		};

		for (i = 0; i < sizeof (disp_names) /
		    sizeof (struct _gcpu_disp_name); i++) {
			if ((gbl->gbl_disp & disp_names[i].dv) == 0)
				continue;

			(void) snprintf(p, (uintptr_t)q - (uintptr_t)p,
			    "%s%s", empty ? "" : ",", disp_names[i].dn);
			p += strlen(p);
			empty = 0;
		}

		if (p != buf)
			fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_DISP,
			    DATA_TYPE_STRING, buf, NULL);
	}

	/*
	 * If MCG_STATUS is included add that and an indication of whether
	 * this ereport was the result of a machine check or poll.
	 */
	if (members & FM_EREPORT_PAYLOAD_FLAG_MCG_STATUS) {
		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_MCG_STATUS,
		    DATA_TYPE_UINT64, mcg, NULL);

		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_MCG_STATUS_MCIP,
		    DATA_TYPE_BOOLEAN_VALUE, mcip ? B_TRUE : B_FALSE, NULL);
	}

	/*
	 * If an instruction pointer is to be included add one provided
	 * MCG_STATUS indicated it is valid; meaningless for polled events.
	 */
	if (mcip && members & FM_EREPORT_PAYLOAD_FLAG_IP &&
	    mcg & MCG_STATUS_EIPV) {
		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_IP,
		    DATA_TYPE_UINT64, gcl->gcl_ip, NULL);
	}

	/*
	 * Add an indication of whether the trap occured during privileged code.
	 */
	if (mcip && members & FM_EREPORT_PAYLOAD_FLAG_PRIV) {
		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_PRIV,
		    DATA_TYPE_BOOLEAN_VALUE,
		    gcl->gcl_flags & GCPU_GCL_F_PRIV ? B_TRUE : B_FALSE, NULL);
	}

	/*
	 * If requested, add the index of the MCA bank.  This indicates the
	 * n'th bank of 4 MCA registers, and does not necessarily correspond
	 * to MCi_* - use the bank offset to correlate
	 */
	if (members & FM_EREPORT_PAYLOAD_FLAG_BANK_NUM) {
		fm_payload_set(ereport,
		    /* Bank number */
		    FM_EREPORT_PAYLOAD_NAME_BANK_NUM, DATA_TYPE_UINT8, bankno,
		    /* Offset of MCi_CTL */
		    FM_EREPORT_PAYLOAD_NAME_BANK_MSR_OFFSET, DATA_TYPE_UINT64,
		    IA32_MSR_MC(bankno, CTL),
		    NULL);
	}

	/*
	 * Add MCi_STATUS if requested, and decode it.
	 */
	if (members & FM_EREPORT_PAYLOAD_FLAG_MC_STATUS) {
		const char *tbes[] = {
			"No tracking",			/* 00 */
			"Green - below threshold",	/* 01 */
			"Yellow - above threshold",	/* 10 */
			"Reserved"			/* 11 */
		};

		fm_payload_set(ereport,
		    /* Bank MCi_STATUS */
		    FM_EREPORT_PAYLOAD_NAME_MC_STATUS, DATA_TYPE_UINT64, bstat,
		    /* Overflow? */
		    _GCPU_BSTATUS(bstat, OVER),
		    /* Uncorrected? */
		    _GCPU_BSTATUS(bstat, UC),
		    /* Enabled? */
		    _GCPU_BSTATUS(bstat, EN),
		    /* Processor context corrupt? */
		    _GCPU_BSTATUS(bstat, PCC),
		    /* Error code */
		    FM_EREPORT_PAYLOAD_NAME_MC_STATUS_ERRCODE,
		    DATA_TYPE_UINT16, MCAX86_ERRCODE(bstat),
		    /* Model-specific error code */
		    FM_EREPORT_PAYLOAD_NAME_MC_STATUS_EXTERRCODE,
		    DATA_TYPE_UINT16, MCAX86_MSERRCODE(bstat),
		    NULL);

		/*
		 * If MCG_CAP.TES_P indicates that that thresholding info
		 * is present in the architural component of the bank status
		 * then include threshold information for this bank.
		 */
		if (gcl->gcl_flags & GCPU_GCL_F_TES_P) {
			fm_payload_set(ereport,
			    FM_EREPORT_PAYLOAD_NAME_MC_STATUS_TES,
			    DATA_TYPE_STRING, tbes[MCAX86_TBES_VALUE(bstat)],
			    NULL);
		}
	}

	/*
	 * MCi_ADDR info if requested and valid.
	 */
	if (members & FM_EREPORT_PAYLOAD_FLAG_MC_ADDR &&
	    bstat & MSR_MC_STATUS_ADDRV) {
		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_MC_ADDR,
		    DATA_TYPE_UINT64, gbl->gbl_addr, NULL);
	}

	/*
	 * MCi_MISC if requested and MCi_STATUS.MISCV).
	 */
	if (members & FM_EREPORT_PAYLOAD_FLAG_MC_MISC &&
	    bstat & MSR_MC_STATUS_MISCV) {
		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_MC_MISC,
		    DATA_TYPE_UINT64, gbl->gbl_misc, NULL);
	}

}

/*
 * Construct and post an ereport based on the logout information from a
 * single MCA bank.  We are not necessarily running on the cpu that
 * detected the error.
 */
static void
gcpu_ereport_post(const gcpu_logout_t *gcl, int bankidx,
    const gcpu_error_disp_t *ged, cms_cookie_t mscookie, uint64_t status)
{
	gcpu_data_t *gcpu = gcl->gcl_gcpu;
	cmi_hdl_t hdl = gcpu->gcpu_hdl;
	const gcpu_bank_logout_t *gbl = &gcl->gcl_data[bankidx];
	const char *cpuclass = NULL, *leafclass = NULL;
	uint16_t code = MCAX86_ERRCODE(status);
	errorq_elem_t *eqep, *scr_eqep;
	nvlist_t *ereport, *detector;
	char buf[FM_MAX_CLASS];
	const char *classfmt;
	nv_alloc_t *nva;

	if (panicstr) {
		if ((eqep = errorq_reserve(ereport_errorq)) == NULL)
			return;
		ereport = errorq_elem_nvl(ereport_errorq, eqep);

		/*
		 * Allocate another element for scratch space, but fallback
		 * to the one we have if that fails.  We'd like to use the
		 * additional scratch space for nvlist construction.
		 */
		if ((scr_eqep = errorq_reserve(ereport_errorq)) != NULL)
			nva = errorq_elem_nva(ereport_errorq, scr_eqep);
		else
			nva = errorq_elem_nva(ereport_errorq, eqep);
	} else {
		ereport = fm_nvlist_create(NULL);
		nva = NULL;
	}

	if (ereport == NULL)
		return;

	/*
	 * Common payload data required by the protocol:
	 *	- ereport class
	 *	- detector
	 *	- ENA
	 */

	/*
	 * Ereport class - call into model-specific support to allow it to
	 * provide a cpu class or leaf class, otherwise calculate our own.
	 */
	cms_ereport_class(hdl, mscookie, &cpuclass, &leafclass);
	classfmt = ged ?  ged->ged_class_fmt : FM_EREPORT_CPU_GENERIC_UNKNOWN;
	gcpu_erpt_clsfmt(classfmt, buf, sizeof (buf), status, cpuclass,
	    leafclass);

	/*
	 * The detector FMRI.
	 */
	if ((detector = cms_ereport_detector(hdl, mscookie, nva)) == NULL)
		detector = gcpu_fmri_create(hdl, nva);

	/*
	 * Should we define a new ENA format 3?? for chip/core/strand?
	 * It will be better when virtualized.
	 */
	fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
	    fm_ena_generate_cpu(gcl->gcl_timestamp,
	    cmi_hdl_chipid(hdl) << 6 | cmi_hdl_coreid(hdl) << 3 |
	    cmi_hdl_strandid(hdl), FM_ENA_FMT1), detector, NULL);

	if (panicstr) {
		fm_nvlist_destroy(detector, FM_NVA_RETAIN);
		nv_alloc_reset(nva);
	} else {
		fm_nvlist_destroy(detector, FM_NVA_FREE);
	}

	/*
	 * Add the architectural ereport class-specific payload data.
	 */
	gcpu_ereport_add_logout(ereport, gcl, bankidx, ged, code);

	/*
	 * Allow model-specific code to add ereport members.
	 */
	cms_ereport_add_logout(hdl, ereport, nva, bankidx, gbl->gbl_status,
	    gbl->gbl_addr, gbl->gbl_misc, gcl->gcl_ms_logout, mscookie);

	/*
	 * Include stack if options is turned on and either selected in
	 * the payload member bitmask or inclusion is forced.
	 */
	if (gcpu_mca_stack_flag &&
	    (cms_ereport_includestack(hdl, mscookie) ==
	    B_TRUE || gcpu_mca_stack_ereport_include)) {
		fm_payload_stack_add(ereport, gcl->gcl_stack,
		    gcl->gcl_stackdepth);
	}

	/*
	 * Post ereport.
	 */
	if (panicstr) {
		errorq_commit(ereport_errorq, eqep, ERRORQ_SYNC);
		if (scr_eqep)
			errorq_cancel(ereport_errorq, scr_eqep);
	} else {
		(void) fm_ereport_post(ereport, EVCH_TRYHARD);
		fm_nvlist_destroy(ereport, FM_NVA_FREE);
	}

}

/*ARGSUSED*/
void
gcpu_mca_drain(void *ignored, const void *data, const errorq_elem_t *eqe)
{
	const gcpu_logout_t *gcl = data;
	const gcpu_bank_logout_t *gbl;
	int i;

	for (i = 0, gbl = &gcl->gcl_data[0]; i < gcl->gcl_nbanks; i++, gbl++) {
		const gcpu_error_disp_t *gened;
		cms_cookie_t mscookie;

		if (gbl->gbl_status & MSR_MC_STATUS_VAL &&
		    !(gbl->gbl_disp & CMI_ERRDISP_INCONSISTENT)) {
			uint16_t code = MCAX86_ERRCODE(gbl->gbl_status);

			/*
			 * Perform a match based on IA32 MCA architectural
			 * components alone.
			 */
			gened = gcpu_disp_match(code); /* may be NULL */

			/*
			 * Now see if an model-specific match can be made.
			 */
			mscookie = cms_disp_match(gcl->gcl_gcpu->gcpu_hdl, i,
			    gbl->gbl_status, gbl->gbl_addr, gbl->gbl_misc,
			    gcl->gcl_ms_logout);

			/*
			 * Prepare and dispatch an ereport for logging and
			 * diagnosis.
			 */
			gcpu_ereport_post(gcl, i, gened, mscookie,
			    gbl->gbl_status);
		} else if (gbl->gbl_status & MSR_MC_STATUS_VAL &&
		    (gbl->gbl_disp & CMI_ERRDISP_INCONSISTENT)) {
			/*
			 * Telemetry kept changing as we tried to read
			 * it.  Force an unknown ereport leafclass but
			 * keep the telemetry unchanged for logging.
			 */
			gcpu_ereport_post(gcl, i, &gcpu_unknown, NULL,
			    gbl->gbl_status);
		}
	}
}

static size_t gcpu_mca_queue_datasz = 0;

/*
 * The following code is ready to make a weak attempt at growing the
 * errorq structure size.  Since it is not foolproof (we don't know
 * who may already be producing to the outgoing errorq) our caller
 * instead assures that we'll always be called with no greater data
 * size than on our first call.
 */
static void
gcpu_errorq_init(size_t datasz)
{
	int slots;

	mutex_enter(&gcpu_mca_queue_lock);

	if (gcpu_mca_queue_datasz >= datasz) {
		mutex_exit(&gcpu_mca_queue_lock);
		return;
	}

	membar_producer();
	if (gcpu_mca_queue) {
		gcpu_mca_queue_datasz = 0;
		errorq_destroy(gcpu_mca_queue);
	}

	slots = MAX(GCPU_MCA_ERRS_PERCPU * max_ncpus, GCPU_MCA_MIN_ERRORS);
	slots = MIN(slots, GCPU_MCA_MAX_ERRORS);

	gcpu_mca_queue = errorq_create("gcpu_mca_queue", gcpu_mca_drain,
	    NULL, slots, datasz, 1, ERRORQ_VITAL);

	if (gcpu_mca_queue != NULL)
		gcpu_mca_queue_datasz = datasz;

	mutex_exit(&gcpu_mca_queue_lock);
}

/*
 * Perform MCA initialization as described in section 14.6 of Intel 64
 * and IA-32 Architectures Software Developer's Manual Volume 3A.
 */

static uint_t global_nbanks;

void
gcpu_mca_init(cmi_hdl_t hdl)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
	uint64_t cap;
	uint_t vendor = cmi_hdl_vendor(hdl);
	uint_t family = cmi_hdl_family(hdl);
	gcpu_mca_t *mca = &gcpu->gcpu_mca;
	int mcg_ctl_present;
	uint_t nbanks;
	size_t mslsz;
	int i;

	if (gcpu == NULL)
		return;

	/*
	 * Protect from some silly /etc/system settings.
	 */
	if (gcpu_mca_telemetry_retries < 0 || gcpu_mca_telemetry_retries > 100)
		gcpu_mca_telemetry_retries = 5;

	if (cmi_hdl_rdmsr(hdl, IA32_MSR_MCG_CAP, &cap) != CMI_SUCCESS)
		return;

	/*
	 * CPU startup code only calls cmi_mca_init if x86_feature indicates
	 * both MCA and MCE support (i.e., X86_MCA).  P5, K6, and earlier
	 * processors, which have their own * more primitive way of doing
	 * machine checks, will not have cmi_mca_init called since their
	 * CPUID information will not indicate both MCA and MCE features.
	 */
#ifndef	__xpv
	ASSERT(x86_feature & X86_MCA);
#endif /* __xpv */

	/*
	 * Determine whether the IA32_MCG_CTL register is present.  If it
	 * is we will enable all features by writing -1 to it towards
	 * the end of this initialization;  if it is absent then volume 3A
	 * says we must nonetheless continue to initialize the individual
	 * banks.
	 */
	mcg_ctl_present = cap & MCG_CAP_CTL_P;

	/*
	 * We squirell values away for inspection/debugging.
	 */
	mca->gcpu_mca_bioscfg.bios_mcg_cap = cap;
	if (mcg_ctl_present)
		(void) cmi_hdl_rdmsr(hdl, IA32_MSR_MCG_CTL,
		    &mca->gcpu_mca_bioscfg.bios_mcg_ctl);

	/*
	 * Determine the number of error-reporting banks implemented.
	 */
	mca->gcpu_mca_nbanks = nbanks = cap & MCG_CAP_COUNT_MASK;

	if (nbanks != 0 && global_nbanks == 0)
		global_nbanks = nbanks;	/* no race - BSP will get here first */

	/*
	 * If someone is hiding the number of banks (perhaps we are fully
	 * virtualized?) or if this processor has more banks than the
	 * first to set global_nbanks then bail.  The latter requirement
	 * is because we need to size our errorq data structure and we
	 * don't want to have to grow the errorq (destroy and recreate)
	 * which may just lose some telemetry.
	 */
	if (nbanks == 0 || nbanks > global_nbanks)
		return;

	mca->gcpu_mca_bioscfg.bios_bankcfg = kmem_zalloc(nbanks *
	    sizeof (struct gcpu_bios_bankcfg), KM_SLEEP);

	/*
	 * Calculate the size we need to allocate for a gcpu_logout_t
	 * with a gcl_data array big enough for all banks of this cpu.
	 * Add any space requested by the model-specific logout support.
	 */
	mslsz = cms_logout_size(hdl);
	mca->gcpu_mca_lgsz = sizeof (gcpu_logout_t) +
	    (nbanks - 1) * sizeof (gcpu_bank_logout_t) + mslsz;

	for (i = 0; i < GCPU_MCA_LOGOUT_NUM; i++) {
		gcpu_logout_t *gcl;

		mca->gcpu_mca_logout[i] = gcl =
		    kmem_zalloc(mca->gcpu_mca_lgsz, KM_SLEEP);
		gcl->gcl_gcpu = gcpu;
		gcl->gcl_nbanks = nbanks;
		gcl->gcl_ms_logout = (mslsz == 0) ? NULL :
		    (char *)(&gcl->gcl_data[0]) + nbanks *
		    sizeof (gcpu_bank_logout_t);

	}
	mca->gcpu_mca_nextpoll_idx = GCPU_MCA_LOGOUT_POLLER_1;

	/*
	 * Create our errorq to transport the logout structures.  This
	 * can fail so users of gcpu_mca_queue must be prepared for NULL.
	 */
	gcpu_errorq_init(mca->gcpu_mca_lgsz);

	/*
	 * Not knowing which, if any, banks are shared between cores we
	 * assure serialization of MCA bank initialization by each cpu
	 * on the chip.  On chip architectures in which some banks are
	 * shared this will mean the shared resource is initialized more
	 * than once - we're simply aiming to avoid simultaneous MSR writes
	 * to the shared resource.
	 *
	 * Even with these precautions, some platforms may yield a GP fault
	 * if a core other than a designated master tries to write anything
	 * but all 0's to MCi_{STATUS,ADDR,CTL}.  So we will perform
	 * those writes under on_trap protection.
	 */
	mutex_enter(&gcpu->gcpu_shared->gcpus_cfglock);

	/*
	 * Initialize poller data, but don't start polling yet.
	 */
	gcpu_mca_poll_init(hdl);

	/*
	 * Work out which MCA banks we will initialize.  In MCA logout
	 * code we will only read those banks which we initialize here.
	 */
	for (i = 0; i < nbanks; i++) {
		/*
		 * On Intel family 6 and AMD family 6 we must not enable
		 * machine check from bank 0 detectors.  In the Intel
		 * case bank 0 is reserved for the platform, while in the
		 * AMD case reports are that enabling bank 0 (DC) produces
		 * spurious machine checks.
		 */
		if (i == 0 && ((vendor == X86_VENDOR_Intel ||
		    vendor == X86_VENDOR_AMD) && family == 6))
			continue;

		if (cms_bankctl_skipinit(hdl, i))
			continue;

		/*
		 * Record which MCA banks were enabled, both from the
		 * point of view of this core and accumulating for the
		 * whole chip (if some cores share a bank we must be
		 * sure either can logout from it).
		 */
		mca->gcpu_actv_banks |= 1 << i;
		atomic_or_32(&gcpu->gcpu_shared->gcpus_actv_banks, 1 << i);
	}

	/*
	 * Log any valid telemetry lurking in the MCA banks, but do not
	 * clear the status registers.  Ignore the disposition returned -
	 * we have already paniced or reset for any nasty errors found here.
	 */
	gcpu_mca_logout(hdl, NULL, -1ULL, NULL, B_FALSE);

	/*
	 * Initialize all MCi_CTL and clear all MCi_STATUS, allowing the
	 * model-specific module the power of veto.
	 */
	for (i = 0; i < nbanks; i++) {
		struct gcpu_bios_bankcfg *bcfgp =
		    mca->gcpu_mca_bioscfg.bios_bankcfg + i;

		/*
		 * Stash inherited bank MCA state, even for banks we will
		 * not initialize ourselves.  Do not read the MISC register
		 * unconditionally - on some processors that will #GP on
		 * banks that do not implement the MISC register (would be
		 * caught by on_trap, anyway).
		 */
		(void) cmi_hdl_rdmsr(hdl, IA32_MSR_MC(i, CTL),
		    &bcfgp->bios_bank_ctl);

		(void) cmi_hdl_rdmsr(hdl, IA32_MSR_MC(i, STATUS),
		    &bcfgp->bios_bank_status);

		if (bcfgp->bios_bank_status & MSR_MC_STATUS_ADDRV)
			(void) cmi_hdl_rdmsr(hdl, IA32_MSR_MC(i, ADDR),
			    &bcfgp->bios_bank_addr);

		if (bcfgp->bios_bank_status & MSR_MC_STATUS_MISCV)
			(void) cmi_hdl_rdmsr(hdl, IA32_MSR_MC(i, MISC),
			    &bcfgp->bios_bank_misc);

		if (!(mca->gcpu_actv_banks & 1 << i))
			continue;

		(void) cmi_hdl_wrmsr(hdl, IA32_MSR_MC(i, CTL),
		    cms_bankctl_val(hdl, i, -1ULL));

		if (!cms_bankstatus_skipinit(hdl, i)) {
			(void) cmi_hdl_wrmsr(hdl, IA32_MSR_MC(i, STATUS),
			    cms_bankstatus_val(hdl, i, 0ULL));
		}
	}

	/*
	 * Now let the model-specific support perform further initialization
	 * of non-architectural features.
	 */
	cms_mca_init(hdl, nbanks);

	(void) cmi_hdl_wrmsr(hdl, IA32_MSR_MCG_STATUS, 0ULL);
	membar_producer();

	/* enable all machine-check features */
	if (mcg_ctl_present)
		(void) cmi_hdl_wrmsr(hdl, IA32_MSR_MCG_CTL,
		    cms_mcgctl_val(hdl, nbanks, -1ULL));

	mutex_exit(&gcpu->gcpu_shared->gcpus_cfglock);

	/* enable machine-check exception in CR4 */
	cmi_hdl_enable_mce(hdl);
}

static uint64_t
gcpu_mca_process(cmi_hdl_t hdl, struct regs *rp, int nerr, gcpu_data_t *gcpu,
    gcpu_logout_t *gcl, int ismc, gcpu_mce_status_t *mcesp)
{
	int curctxbad = 0, unconstrained = 0, forcefatal = 0;
	gcpu_mca_t *mca = &gcpu->gcpu_mca;
	int nbanks = mca->gcpu_mca_nbanks;
	gcpu_mce_status_t mce;
	gcpu_bank_logout_t *gbl;
	uint64_t disp = 0;
	int i;

	if (mcesp == NULL)
		mcesp = &mce;

	mcesp->mce_nerr = nerr;

	mcesp->mce_npcc = mcesp->mce_npcc_ok = mcesp->mce_nuc =
	    mcesp->mce_nuc_ok = mcesp->mce_nuc_poisoned =
	    mcesp->mce_forcefatal = mcesp->mce_ignored = 0;

	/*
	 * If this a machine check then if the return instruction pointer
	 * is not valid the current context is lost.
	 */
	if (ismc && !(gcl->gcl_mcg_status & MCG_STATUS_RIPV))
		disp |= CMI_ERRDISP_RIPV_INVALID;

	for (i = 0, gbl = &gcl->gcl_data[0]; i < nbanks; i++, gbl++) {
		uint64_t mcistatus = gbl->gbl_status;
		uint32_t ms_scope;
		int pcc, uc;
		int poisoned;

		if (!(mcistatus & MSR_MC_STATUS_VAL))
			continue;

		if (gbl->gbl_disp & CMI_ERRDISP_INCONSISTENT)
			continue;

		pcc = (mcistatus & MSR_MC_STATUS_PCC) != 0;
		uc = (mcistatus & MSR_MC_STATUS_UC) != 0;
		mcesp->mce_npcc += pcc;
		mcesp->mce_nuc += uc;

		ms_scope = cms_error_action(hdl, ismc, i, mcistatus,
		    gbl->gbl_addr, gbl->gbl_misc, gcl->gcl_ms_logout);

		if (pcc && ms_scope & CMS_ERRSCOPE_CURCONTEXT_OK) {
			pcc = 0;
			mcesp->mce_npcc_ok++;
			gbl->gbl_disp |= CMI_ERRDISP_PCC_CLEARED;
		}

		if (uc && ms_scope & CMS_ERRSCOPE_CLEARED_UC) {
			uc = 0;
			mcesp->mce_nuc_ok++;
			gbl->gbl_disp |= CMI_ERRDISP_UC_CLEARED;
		}

		if (uc) {
			poisoned = (ms_scope & CMS_ERRSCOPE_POISONED) != 0;
			if (poisoned) {
				mcesp->mce_nuc_poisoned++;
				gbl->gbl_disp |= CMI_ERRDISP_POISONED;
			}
		}

		if ((ms_scope & CMS_ERRSCOPE_IGNORE_ERR) == 0) {
			/*
			 * We're not being instructed to ignore the error,
			 * so apply our standard disposition logic to it.
			 */
			if (uc && !poisoned) {
				unconstrained++;
				gbl->gbl_disp |= disp |
				    CMI_ERRDISP_UC_UNCONSTRAINED;
			}

			if (pcc && ismc) {
				curctxbad++;
				gbl->gbl_disp |= disp |
				    CMI_ERRDISP_CURCTXBAD;
			}

			/*
			 * Even if the above may not indicate that the error
			 * is terminal, model-specific support may insist
			 * that we treat it as such.  Such errors wil be
			 * fatal even if discovered via poll.
			 */
			if (ms_scope & CMS_ERRSCOPE_FORCE_FATAL) {
				forcefatal++;
				mcesp->mce_forcefatal++;
				gbl->gbl_disp |= disp |
				    CMI_ERRDISP_FORCEFATAL;
			}
		} else {
			mcesp->mce_ignored++;
			gbl->gbl_disp |= disp | CMI_ERRDISP_IGNORED;
		}
	}

	if (unconstrained > 0)
		disp |= CMI_ERRDISP_UC_UNCONSTRAINED;

	if (curctxbad > 0)
		disp |= CMI_ERRDISP_CURCTXBAD;

	if (forcefatal > 0)
		disp |= CMI_ERRDISP_FORCEFATAL;

	if (gcpu_mca_queue != NULL) {
		int how;

		if (ismc) {
			how = cmi_mce_response(rp, disp) ?
			    ERRORQ_ASYNC :	/* no panic, so arrange drain */
			    ERRORQ_SYNC;	/* panic flow will drain */
		} else {
			how = (disp & CMI_ERRDISP_FORCEFATAL &&
			    cmi_panic_on_ue()) ?
			    ERRORQ_SYNC :	/* poller will panic */
			    ERRORQ_ASYNC;	/* no panic */
		}

		errorq_dispatch(gcpu_mca_queue, gcl, mca->gcpu_mca_lgsz, how);
	} else if (disp != 0) {
		gcpu_bleat(hdl, gcl);
	}

	mcesp->mce_disp = disp;

	return (disp);
}

/*
 * Gather error telemetry from our source, and then submit it for
 * processing.
 */

#define	IS_MCE_CANDIDATE(status) (((status) & MSR_MC_STATUS_EN) != 0 && \
	((status) & (MSR_MC_STATUS_UC | MSR_MC_STATUS_PCC)) != 0)

#define	STATUS_EQV(s1, s2) \
	(((s1) & ~MSR_MC_STATUS_OVER) == ((s2) & ~MSR_MC_STATUS_OVER))

static uint32_t gcpu_deferrred_polled_clears;

void
gcpu_mca_logout(cmi_hdl_t hdl, struct regs *rp, uint64_t bankmask,
    gcpu_mce_status_t *mcesp, boolean_t clrstatus)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
	gcpu_mca_t *mca = &gcpu->gcpu_mca;
	int nbanks = mca->gcpu_mca_nbanks;
	gcpu_bank_logout_t *gbl, *pgbl;
	gcpu_logout_t *gcl, *pgcl;
	int ismc = (rp != NULL);
	int ispoll = !ismc;
	int i, nerr = 0;
	cmi_errno_t err;
	uint64_t mcg_status;
	uint64_t disp;
	uint64_t cap;

	if (cmi_hdl_rdmsr(hdl, IA32_MSR_MCG_STATUS, &mcg_status) !=
	    CMI_SUCCESS || cmi_hdl_rdmsr(hdl, IA32_MSR_MCG_CAP, &cap) !=
	    CMI_SUCCESS) {
		if (mcesp != NULL)
			mcesp->mce_nerr = mcesp->mce_disp = 0;
		return;
	}

	if (ismc) {
		gcl = mca->gcpu_mca_logout[GCPU_MCA_LOGOUT_EXCEPTION];
	} else {
		int pidx = mca->gcpu_mca_nextpoll_idx;
		int ppidx = (pidx == GCPU_MCA_LOGOUT_POLLER_1) ?
		    GCPU_MCA_LOGOUT_POLLER_2 : GCPU_MCA_LOGOUT_POLLER_1;

		gcl = mca->gcpu_mca_logout[pidx];	/* current logout */
		pgcl = mca->gcpu_mca_logout[ppidx];	/* previous logout */
		mca->gcpu_mca_nextpoll_idx = ppidx;	/* switch next time */
	}

	gcl->gcl_timestamp = gethrtime_waitfree();
	gcl->gcl_mcg_status = mcg_status;
	gcl->gcl_ip = rp ? rp->r_pc : 0;

	gcl->gcl_flags = (rp && USERMODE(rp->r_cs)) ? GCPU_GCL_F_PRIV : 0;
	if (cap & MCG_CAP_TES_P)
		gcl->gcl_flags |= GCPU_GCL_F_TES_P;

	for (i = 0, gbl = &gcl->gcl_data[0]; i < nbanks; i++, gbl++) {
		uint64_t status, status2, addr, misc;
		int retries = gcpu_mca_telemetry_retries;

		gbl->gbl_status = 0;
		gbl->gbl_disp = 0;
		gbl->gbl_clrdefcnt = 0;

		/*
		 * Only logout from MCA banks we have initialized from at
		 * least one core.  If a core shares an MCA bank with another
		 * but perhaps lost the race to initialize it, then it must
		 * still be allowed to logout from the shared bank.
		 */
		if (!(gcpu->gcpu_shared->gcpus_actv_banks & 1 << i))
			continue;

		/*
		 * On a poll look only at the banks we've been asked to check.
		 */
		if (rp == NULL && !(bankmask & 1 << i))
			continue;


		if (cmi_hdl_rdmsr(hdl, IA32_MSR_MC(i, STATUS), &status) !=
		    CMI_SUCCESS)
			continue;
retry:
		if (!(status & MSR_MC_STATUS_VAL))
			continue;

		addr = -1;
		misc = 0;

		if (status & MSR_MC_STATUS_ADDRV)
			(void) cmi_hdl_rdmsr(hdl, IA32_MSR_MC(i, ADDR), &addr);

		if (status & MSR_MC_STATUS_MISCV)
			(void) cmi_hdl_rdmsr(hdl, IA32_MSR_MC(i, MISC), &misc);

		/*
		 * Allow the model-specific code to extract bank telemetry.
		 */
		cms_bank_logout(hdl, i, status, addr, misc, gcl->gcl_ms_logout);

		/*
		 * Not all cpu models assure us that the status/address/misc
		 * data will not change during the above sequence of MSR reads,
		 * or that it can only change by the addition of the OVerflow
		 * bit to the status register.  If the status has changed
		 * other than in the overflow bit then we attempt to reread
		 * for a consistent snapshot, but eventually give up and
		 * go with what we've got.  We only perform this check
		 * for a poll - a further #MC during a #MC will reset, and
		 * polled errors should not overwrite higher-priority
		 * trapping errors (but could set the overflow bit).
		 */
		if (ispoll && (err = cmi_hdl_rdmsr(hdl, IA32_MSR_MC(i, STATUS),
		    &status2)) == CMI_SUCCESS) {
			if (!STATUS_EQV(status, status2)) {
				if (retries-- > 0) {
					status = status2;
					goto retry;
				} else {
					gbl->gbl_disp |=
					    CMI_ERRDISP_INCONSISTENT;
				}
			}
		} else if (ispoll && err != CMI_SUCCESS) {
			gbl->gbl_disp |= CMI_ERRDISP_INCONSISTENT;
		}

		nerr++;
		gbl->gbl_status = status;
		gbl->gbl_addr = addr;
		gbl->gbl_misc = misc;

		if (clrstatus == B_FALSE)
			goto serialize;

		/*
		 * For machine checks we always clear status here.  For polls
		 * we must be a little more cautious since there is an
		 * outside chance that we may clear telemetry from a shared
		 * MCA bank on which a sibling core is machine checking.
		 *
		 * For polled observations of errors that look like they may
		 * produce a machine check (UC/PCC and ENabled, although these
		 * do not guarantee a machine check on error occurence)
		 * we will not clear the status at this wakeup unless
		 * we saw the same status at the previous poll.  We will
		 * always process and log the current observations - it
		 * is only the clearing of MCi_STATUS which may be
		 * deferred until the next wakeup.
		 */
		if (ismc || !IS_MCE_CANDIDATE(status)) {
			(void) cmi_hdl_wrmsr(hdl, IA32_MSR_MC(i, STATUS), 0ULL);
			goto serialize;
		}

		/*
		 * We have a polled observation of a machine check
		 * candidate.  If we saw essentially the same status at the
		 * last poll then clear the status now since this appears
		 * not to be a #MC candidate after all.  If we see quite
		 * different status now then do not clear, but reconsider at
		 * the next poll.  In no actual machine check clears
		 * the status in the interim then the status should not
		 * keep changing forever (meaning we'd never clear it)
		 * since before long we'll simply have latched the highest-
		 * priority error and set the OVerflow bit.  Nonetheless
		 * we count how many times we defer clearing and after
		 * a while insist on clearing the status.
		 */
		pgbl = &pgcl->gcl_data[i];
		if (pgbl->gbl_clrdefcnt != 0) {
			/* We deferred clear on this bank at last wakeup */
			if (STATUS_EQV(status, pgcl->gcl_data[i].gbl_status) ||
			    pgbl->gbl_clrdefcnt > 5) {
				/*
				 * Status is unchanged so clear it now and,
				 * since we have already logged this info,
				 * avoid logging it again.
				 */
				gbl->gbl_status = 0;
				nerr--;
				(void) cmi_hdl_wrmsr(hdl,
				    IA32_MSR_MC(i, STATUS), 0ULL);
			} else {
				/* Record deferral for next wakeup */
				gbl->gbl_clrdefcnt = pgbl->gbl_clrdefcnt + 1;
			}
		} else {
			/* Record initial deferral for next wakeup */
			gbl->gbl_clrdefcnt = 1;
			gcpu_deferrred_polled_clears++;
		}

serialize:
		/*
		 * Intel Vol 3A says to execute a serializing instruction
		 * here, ie CPUID.  Well WRMSR is also defined to be
		 * serializing, so the status clear above should suffice.
		 * To be a good citizen, and since some clears are deferred,
		 * we'll execute a CPUID instruction here.
		 */
		{
			struct cpuid_regs tmp;
			(void) __cpuid_insn(&tmp);
		}
	}

	if (gcpu_mca_stack_flag)
		gcl->gcl_stackdepth = getpcstack(gcl->gcl_stack, FM_STK_DEPTH);
	else
		gcl->gcl_stackdepth = 0;

	/*
	 * Decide our disposition for this error or errors, and submit for
	 * logging and subsequent diagnosis.
	 */
	if (nerr != 0) {
		disp = gcpu_mca_process(hdl, rp, nerr, gcpu, gcl, ismc, mcesp);
	} else {
		disp = 0;
		if (mcesp) {
			mcesp->mce_nerr = mcesp->mce_disp = 0;
		}
	}

	/*
	 * Clear MCG_STATUS if MCIP is set (machine check in progress).
	 * If a second #MC had occured before now the system would have
	 * reset.  We can only do thise once gcpu_mca_process has copied
	 * the logout structure.
	 */
	if (ismc && mcg_status & MCG_STATUS_MCIP)
		(void) cmi_hdl_wrmsr(hdl, IA32_MSR_MCG_STATUS, 0);

	/*
	 * At this point we have read and logged all telemetry that is visible
	 * under the MCA.  On architectures for which the NorthBridge is
	 * on-chip this may include NB-observed errors, but where the NB
	 * is off chip it may have been the source of the #MC request and
	 * so we must call into the memory-controller driver to give it
	 * a chance to log errors.
	 */
	if (ismc) {
		int willpanic = (cmi_mce_response(rp, disp) == 0);
		cmi_mc_logout(hdl, 1, willpanic);
	}
}

int gcpu_mca_trap_vomit_summary = 0;

/*
 * On a native machine check exception we come here from mcetrap via
 * cmi_mca_trap.  A machine check on one cpu of a chip does not trap others
 * cpus of the chip, so it is possible that another cpu on this chip could
 * initiate a poll while we're in the #mc handler;  it is also possible that
 * this trap has occured during a poll on this cpu.  So we must acquire
 * the chip-wide poll lock, but be careful to avoid deadlock.
 *
 * The 'data' pointer cannot be NULL due to init order.
 */
uint64_t
gcpu_mca_trap(cmi_hdl_t hdl, struct regs *rp)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
	kmutex_t *poll_lock = NULL;
	gcpu_mce_status_t mce;
	uint64_t mcg_status;
	int tooklock = 0;

	if (cmi_hdl_rdmsr(hdl, IA32_MSR_MCG_STATUS, &mcg_status) !=
	    CMI_SUCCESS || !(mcg_status & MCG_STATUS_MCIP))
		return (0);

	/*
	 * Synchronize with any poller from another core that may happen
	 * to share access to one or more of the MCA banks.
	 */
	if (gcpu->gcpu_shared != NULL)
		poll_lock = &gcpu->gcpu_shared->gcpus_poll_lock;

	if (poll_lock != NULL && !mutex_owned(poll_lock)) {
		/*
		 * The lock is not owned by the thread we have
		 * interrupted.  Spin for this adaptive lock.
		 */
		while (!mutex_tryenter(poll_lock)) {
			while (mutex_owner(poll_lock) != NULL)
				;
		}
		tooklock = 1;
	}

	gcpu_mca_logout(hdl, rp, 0, &mce, B_TRUE);

	if (tooklock)
		mutex_exit(poll_lock);

	/*
	 * gcpu_mca_trap_vomit_summary may be set for debug assistance.
	 */
	if (mce.mce_nerr != 0 && gcpu_mca_trap_vomit_summary) {
		cmn_err(CE_WARN, "MCE: %u errors, disp=0x%llx, "
		    "%u PCC (%u ok), "
		    "%u UC (%d ok, %u poisoned), "
		    "%u forcefatal, %u ignored",
		    mce.mce_nerr, (u_longlong_t)mce.mce_disp,
		    mce.mce_npcc, mce.mce_npcc_ok,
		    mce.mce_nuc, mce.mce_nuc_ok, mce.mce_nuc_poisoned,
		    mce.mce_forcefatal, mce.mce_ignored);
	}

	return (mce.mce_disp);
}

/*ARGSUSED*/
void
gcpu_faulted_enter(cmi_hdl_t hdl)
{
	/* Nothing to do here */
}

/*ARGSUSED*/
void
gcpu_faulted_exit(cmi_hdl_t hdl)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);

	gcpu->gcpu_mca.gcpu_mca_flags |= GCPU_MCA_F_UNFAULTING;
}

/*
 * Write the requested values to the indicated MSRs.  Having no knowledge
 * of the model-specific requirements for writing to these model-specific
 * registers, we will only blindly write to those MSRs if the 'force'
 * argument is nonzero.  That option should only be used in prototyping
 * and debugging.
 */
/*ARGSUSED*/
cmi_errno_t
gcpu_msrinject(cmi_hdl_t hdl, cmi_mca_regs_t *regs, uint_t nregs,
    int force)
{
	int i, errs = 0;

	for (i = 0; i < nregs; i++) {
		uint_t msr = regs[i].cmr_msrnum;
		uint64_t val = regs[i].cmr_msrval;

		if (cms_present(hdl)) {
			if (cms_msrinject(hdl, msr, val) != CMS_SUCCESS)
				errs++;
		} else if (force) {
			errs += (cmi_hdl_wrmsr(hdl, msr, val) != CMI_SUCCESS);
		} else {
			errs++;
		}
	}

	return (errs == 0 ? CMI_SUCCESS : CMIERR_UNKNOWN);
}
