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
 *
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * Portions Copyright 2009 Advanced Micro Devices, Inc.
 */

/*
 * Copyright 2012 Jens Elkner <jel+illumos@cs.uni-magdeburg.de>
 * Copyright 2012 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Support functions that interpret CPUID and similar information.
 * These should not be used from anywhere other than cpuid.c and
 * cmi_hw.c - as such we will not list them in any header file
 * such as x86_archext.h.
 *
 * In cpuid.c we process CPUID information for each cpu_t instance
 * we're presented with, and stash this raw information and material
 * derived from it in per-cpu_t structures.
 *
 * If we are virtualized then the CPUID information derived from CPUID
 * instructions executed in the guest is based on whatever the hypervisor
 * wanted to make things look like, and the cpu_t are not necessarily in 1:1
 * or fixed correspondence with real processor execution resources.  In cmi_hw.c
 * we are interested in the native properties of a processor - for fault
 * management (and potentially other, such as power management) purposes;
 * it will tunnel through to real hardware information, and use the
 * functionality provided in this file to process it.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/bitmap.h>
#include <sys/x86_archext.h>
#include <sys/pci_cfgspace.h>
#include <sys/sysmacros.h>
#ifdef __xpv
#include <sys/hypervisor.h>
#endif

/*
 * AMD socket types.
 * First index defines a processor family; see notes inline.  The second index
 * selects the socket type by either (model & 0x3) for family 0fh or the CPUID
 * pkg bits (Fn8000_0001_EBX[31:28]) for later families.
 */
static uint32_t amd_skts[][16] = {
	/*
	 * Family 0xf revisions B through E
	 */
#define	A_SKTS_0			0
	{
		[0] = X86_SOCKET_754,
		[1] = X86_SOCKET_940,
		[2] = X86_SOCKET_754,
		[3] = X86_SOCKET_939,
	},
	/*
	 * Family 0xf revisions F and G
	 */
#define	A_SKTS_1			1
	{
		[0] = X86_SOCKET_S1g1,
		[1] = X86_SOCKET_F1207,
		[3] = X86_SOCKET_AM2
	},
	/*
	 * Family 0x10
	 */
#define	A_SKTS_2			2
	{
		[0] = X86_SOCKET_F1207,
		[1] = X86_SOCKET_AM2R2,
		[2] = X86_SOCKET_S1g3,
		[3] = X86_SOCKET_G34,
		[4] = X86_SOCKET_ASB2,
		[5] = X86_SOCKET_C32
	},

	/*
	 * Family 0x11
	 */
#define	A_SKTS_3			3
	{
		[2] = X86_SOCKET_S1g2
	},

	/*
	 * Family 0x12
	 */
#define	A_SKTS_4			4
	{
		[1] = X86_SOCKET_FS1,
		[2] = X86_SOCKET_FM1
	},

	/*
	 * Family 0x14
	 */
#define	A_SKTS_5			5
	{
		[0] = X86_SOCKET_FT1
	},

	/*
	 * Family 0x15 models 00 - 0f
	 */
#define	A_SKTS_6			6
	{
		[1] = X86_SOCKET_AM3R2,
		[3] = X86_SOCKET_G34,
		[5] = X86_SOCKET_C32
	},

	/*
	 * Family 0x15 models 10 - 1f
	 */
#define	A_SKTS_7			7
	{
		[0] = X86_SOCKET_FP2,
		[1] = X86_SOCKET_FS1R2,
		[2] = X86_SOCKET_FM2
	},

	/*
	 * Family 0x15 models 30-3f
	 */
#define	A_SKTS_8			8
	{
		[0] = X86_SOCKET_FP3,
		[1] = X86_SOCKET_FM2R2
	},

	/*
	 * Family 0x15 models 60-6f
	 */
#define	A_SKTS_9			9
	{
		[0] = X86_SOCKET_FP4,
		[2] = X86_SOCKET_AM4,
		[3] = X86_SOCKET_FM2R2
	},

	/*
	 * Family 0x15 models 70-7f
	 */
#define	A_SKTS_10			10
	{
		[0] = X86_SOCKET_FP4,
		[2] = X86_SOCKET_AM4,
		[4] = X86_SOCKET_FT4
	},

	/*
	 * Family 0x16 models 00-0f
	 */
#define	A_SKTS_11			11
	{
		[0] = X86_SOCKET_FT3,
		[1] = X86_SOCKET_FS1B
	},

	/*
	 * Family 0x16 models 30-3f
	 */
#define	A_SKTS_12			12
	{
		[0] = X86_SOCKET_FT3B,
		[3] = X86_SOCKET_FP4
	},

	/*
	 * Family 0x17 models 00-0f	(Zen 1 - Naples, Ryzen)
	 */
#define	A_SKTS_NAPLES			13
	{
		[2] = X86_SOCKET_AM4,
		[4] = X86_SOCKET_SP3,
		[7] = X86_SOCKET_SP3R2
	},

	/*
	 * Family 0x17 models 10-2f	(Zen 1 - APU: Raven Ridge)
	 *				(Zen 1 - APU: Banded Kestrel)
	 *				(Zen 1 - APU: Dali)
	 */
#define	A_SKTS_RAVEN			14
	{
		[0] = X86_SOCKET_FP5,
		[2] = X86_SOCKET_AM4
	},

	/*
	 * Family 0x17 models 30-3f	(Zen 2 - Rome)
	 */
#define	A_SKTS_ROME			15
	{
		[4] = X86_SOCKET_SP3,
		[7] = X86_SOCKET_SP3R2
	},

	/*
	 * Family 0x17 models 60-6f	(Zen 2 - Renoir)
	 */
#define	A_SKTS_RENOIR			16
	{
		[0] = X86_SOCKET_FP6,
		[2] = X86_SOCKET_AM4
	},

	/*
	 * Family 0x17 models 70-7f	(Zen 2 - Matisse)
	 */
#define	A_SKTS_MATISSE			17
	{
		[2] = X86_SOCKET_AM4,
	},

	/*
	 * Family 0x18 models 00-0f	(Dhyana)
	 */
#define	A_SKTS_DHYANA			18
	{
		[4] = X86_SOCKET_SL1,
		[6] = X86_SOCKET_DM1,
		[7] = X86_SOCKET_SL1R2
	},

	/*
	 * Family 0x19 models 00-0f	(Zen 3 - Milan)
	 */
#define	A_SKTS_MILAN			19
	{
		[4] = X86_SOCKET_SP3,
		[7] = X86_SOCKET_STRX4
	},

	/*
	 * Family 0x19 models 20-2f	(Zen 3 - Vermeer)
	 */
#define	A_SKTS_VERMEER			20
	{
		[2] = X86_SOCKET_AM4,
	},

	/*
	 * Family 0x19 models 50-5f	(Zen 3 - Cezanne)
	 */
#define	A_SKTS_CEZANNE			21
	{
		[0] = X86_SOCKET_FP6,
		[2] = X86_SOCKET_AM4
	},

	/*
	 * Family 0x19 models 10-1f	(Zen 4 - Genoa)
	 */
#define	A_SKTS_GENOA			22
	{
		[4] = X86_SOCKET_SP5,
		[8] = X86_SOCKET_TR5
	},

	/*
	 * Family 0x19 models 40-4f	(Zen 3 - Rembrandt)
	 */
#define	A_SKTS_REMBRANDT			23
	{
		[0] = X86_SOCKET_AM5,
		[1] = X86_SOCKET_FP7,
		[2] = X86_SOCKET_FP7R2
	},

	/*
	 * Family 0x19 models 60-6f	(Zen 4 - Raphael)
	 */
#define	A_SKTS_RAPHAEL			24
	{
		[0] = X86_SOCKET_AM5,
		[1] = X86_SOCKET_FL1
	},

	/*
	 * The always-unknown socket group, used for undocumented parts.  It
	 * need not be last; the position is arbitrary. The default initializer
	 * for this is zero which is x86 socket unknown.
	 */
#define	A_SKTS_UNKNOWN			25
	{
	},
	/*
	 * Family 0x17 models 90-97	(Zen 2 - Van Gogh)
	 */
#define	A_SKTS_VANGOGH			26
	{
		[3] = X86_SOCKET_FF3
	},
	/*
	 * Family 0x17 models a0-af	(Zen 2 - Mendocino)
	 */
#define	A_SKTS_MENDOCINO			27
	{
		[1] = X86_SOCKET_FT6
	},

	/*
	 * Family 0x19 models 70-7f	(Zen 4 - Phoenix)
	 */
#define	A_SKTS_PHOENIX			28
	{
		[0] = X86_SOCKET_AM5,
		[1] = X86_SOCKET_FP8,
		[4] = X86_SOCKET_FP7,
		[5] = X86_SOCKET_FP7R2,
	},

	/*
	 * Family 0x19 models a0-af	(Zen 4c - Bergamo/Siena)
	 */
#define	A_SKTS_BERGAMO			29
	{
		[4] = X86_SOCKET_SP5,
		[8] = X86_SOCKET_SP6
	},
	/*
	 * Family 0x1a models 00-1f	(Zen 5[c] - Turin)
	 */
#define	A_SKTS_TURIN			30
	{
		[4] = X86_SOCKET_SP5,
	}
};

struct amd_sktmap_s {
	uint32_t	skt_code;
	char		sktstr[16];
};
static struct amd_sktmap_s amd_sktmap_strs[] = {
	{ X86_SOCKET_754,	"754" },
	{ X86_SOCKET_939,	"939" },
	{ X86_SOCKET_940,	"940" },
	{ X86_SOCKET_S1g1,	"S1g1" },
	{ X86_SOCKET_AM2,	"AM2" },
	{ X86_SOCKET_F1207,	"F(1207)" },
	{ X86_SOCKET_S1g2,	"S1g2" },
	{ X86_SOCKET_S1g3,	"S1g3" },
	{ X86_SOCKET_AM,	"AM" },
	{ X86_SOCKET_AM2R2,	"AM2r2" },
	{ X86_SOCKET_AM3,	"AM3" },
	{ X86_SOCKET_G34,	"G34" },
	{ X86_SOCKET_ASB2,	"ASB2" },
	{ X86_SOCKET_C32,	"C32" },
	{ X86_SOCKET_S1g4,	"S1g4" },
	{ X86_SOCKET_FT1,	"FT1" },
	{ X86_SOCKET_FM1,	"FM1" },
	{ X86_SOCKET_FS1,	"FS1" },
	{ X86_SOCKET_AM3R2,	"AM3r2" },
	{ X86_SOCKET_FP2,	"FP2" },
	{ X86_SOCKET_FS1R2,	"FS1r2" },
	{ X86_SOCKET_FM2,	"FM2" },
	{ X86_SOCKET_FP3,	"FP3" },
	{ X86_SOCKET_FM2R2,	"FM2r2" },
	{ X86_SOCKET_FP4,	"FP4" },
	{ X86_SOCKET_AM4,	"AM4" },
	{ X86_SOCKET_FT3,	"FT3" },
	{ X86_SOCKET_FT4,	"FT4" },
	{ X86_SOCKET_FS1B,	"FS1b" },
	{ X86_SOCKET_FT3B,	"FT3b" },
	{ X86_SOCKET_SP3,	"SP3" },
	{ X86_SOCKET_SP3R2,	"SP3r2" },
	{ X86_SOCKET_FP5,	"FP5" },
	{ X86_SOCKET_FP6,	"FP6" },
	{ X86_SOCKET_STRX4,	"sTRX4" },
	{ X86_SOCKET_SL1,	"SL1" },
	{ X86_SOCKET_SL1R2,	"SL1R2" },
	{ X86_SOCKET_DM1,	"DM1" },
	{ X86_SOCKET_SP5,	"SP5" },
	{ X86_SOCKET_AM5,	"AM5" },
	{ X86_SOCKET_FP7,	"FP7" },
	{ X86_SOCKET_FP7R2,	"FP7r2" },
	{ X86_SOCKET_FF3,	"FF3" },
	{ X86_SOCKET_FT6,	"FT6" },
	{ X86_SOCKET_FP8,	"FP8" },
	{ X86_SOCKET_FL1,	"FL1" },
	{ X86_SOCKET_SP6,	"SP6" },
	{ X86_SOCKET_TR5,	"TR5" },
	{ X86_SOCKET_UNKNOWN,	"Unknown" }	/* Must be last! */
};

/* Keep the array above in sync with the definitions in x86_archext.h. */
CTASSERT(ARRAY_SIZE(amd_sktmap_strs) == X86_NUM_SOCKETS + 1);

/*
 * Table for mapping AMD family/model/stepping ranges onto three derived items:
 *
 * * The "chiprev" and associated string, which is generally the AMD silicon
 * revision along with a symbolic representation of the marketing (not cpuid)
 * family.  In line with the overall cpuid usage, we refer to this as a
 * processor family.
 * * The uarch, which is analogous to the chiprev and provides the
 * microarchitecture/core generation and silicon revision.  Note that this is
 * distinct from the package-level silicon/product revision and is often common
 * to multiple product lines offered at a given time.
 * * The socket map selector, used to translate this collection of products'
 * last 4 model bits (for family 0xf only) or Fn8000_0001_EBX[30:28] into a
 * socket ID.
 *
 * The first member of this array that matches a given family, extended model
 * plus model range, and stepping range will be considered a match.  This allows
 * us to end each cpuid family and/or processor family with a catchall that
 * while less specific than we might like still allows us to provide a fair
 * amount of detail to both other kernel consumers and userland.
 */
static const struct amd_rev_mapent {
	uint_t rm_family;
	uint_t rm_modello;
	uint_t rm_modelhi;
	uint_t rm_steplo;
	uint_t rm_stephi;
	x86_chiprev_t rm_chiprev;
	const char *rm_chiprevstr;
	x86_uarchrev_t rm_uarchrev;
	uint_t rm_sktidx;
} amd_revmap[] = {
	/*
	 * =============== AuthenticAMD Family 0xf ===============
	 */

	/*
	 * Rev B includes model 0x4 stepping 0 and model 0x5 stepping 0 and 1.
	 */
	{ 0xf, 0x04, 0x04, 0x0, 0x0, X86_CHIPREV_AMD_LEGACY_F_REV_B, "B",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_0 },
	{ 0xf, 0x05, 0x05, 0x0, 0x1, X86_CHIPREV_AMD_LEGACY_F_REV_B, "B",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_0 },
	/*
	 * Rev C0 includes model 0x4 stepping 8 and model 0x5 stepping 8
	 */
	{ 0xf, 0x04, 0x05, 0x8, 0x8, X86_CHIPREV_AMD_LEGACY_F_REV_C0, "C0",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_0 },
	/*
	 * Rev CG is the rest of extended model 0x0 - i.e., everything
	 * but the rev B and C0 combinations covered above.
	 */
	{ 0xf, 0x00, 0x0f, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_F_REV_CG, "CG",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_0 },
	/*
	 * Rev D has extended model 0x1.
	 */
	{ 0xf, 0x10, 0x1f, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_F_REV_D, "D",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_0 },
	/*
	 * Rev E has extended model 0x2.
	 * Extended model 0x3 is unused but available to grow into.
	 */
	{ 0xf, 0x20, 0x3f, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_F_REV_E, "E",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_0 },
	/*
	 * Rev F has extended models 0x4 and 0x5.
	 */
	{ 0xf, 0x40, 0x5f, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_F_REV_F, "F",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_1 },
	/*
	 * Rev G has extended model 0x6.
	 */
	{ 0xf, 0x60, 0x6f, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_F_REV_G, "G",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_1 },

	/*
	 * =============== AuthenticAMD Family 0x10 ===============
	 */

	/*
	 * Rev A has model 0 and stepping 0/1/2 for DR-{A0,A1,A2}.
	 * Give all of model 0 stepping range to rev A.
	 */
	{ 0x10, 0x00, 0x00, 0x0, 0x2, X86_CHIPREV_AMD_LEGACY_10_REV_A, "A",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_2 },

	/*
	 * Rev B has model 2 and steppings 0/1/0xa/2 for DR-{B0,B1,BA,B2}.
	 * Give all of model 2 stepping range to rev B.
	 */
	{ 0x10, 0x02, 0x02, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_10_REV_B, "B",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_2 },

	/*
	 * Rev C has models 4-6 (depending on L3 cache configuration)
	 * Give all of models 4-6 stepping range 0-2 to rev C2.
	 */
	{ 0x10, 0x4, 0x6, 0x0, 0x2, X86_CHIPREV_AMD_LEGACY_10_REV_C2, "C2",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_2 },

	/*
	 * Rev C has models 4-6 (depending on L3 cache configuration)
	 * Give all of models 4-6 stepping range >= 3 to rev C3.
	 */
	{ 0x10, 0x4, 0x6, 0x3, 0xf, X86_CHIPREV_AMD_LEGACY_10_REV_C3, "C3",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_2 },

	/*
	 * Rev D has models 8 and 9
	 * Give all of model 8 and 9 stepping 0 to rev D0.
	 */
	{ 0x10, 0x8, 0x9, 0x0, 0x0, X86_CHIPREV_AMD_LEGACY_10_REV_D0, "D0",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_2 },

	/*
	 * Rev D has models 8 and 9
	 * Give all of model 8 and 9 stepping range >= 1 to rev D1.
	 */
	{ 0x10, 0x8, 0x9, 0x1, 0xf, X86_CHIPREV_AMD_LEGACY_10_REV_D1, "D1",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_2 },

	/*
	 * Rev E has models A and stepping 0
	 * Give all of model A stepping range to rev E.
	 */
	{ 0x10, 0xA, 0xA, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_10_REV_E, "E",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_2 },

	{ 0x10, 0x0, 0xff, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_10_UNKNOWN, "??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_2 },

	/*
	 * =============== AuthenticAMD Family 0x11 ===============
	 */
	{ 0x11, 0x03, 0x03, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_11_REV_B, "B",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_3 },
	{ 0x11, 0x00, 0xff, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_11_UNKNOWN, "??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_3 },

	/*
	 * =============== AuthenticAMD Family 0x12 ===============
	 */
	{ 0x12, 0x01, 0x01, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_12_REV_B, "B",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_4 },
	{ 0x12, 0x00, 0x00, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_12_UNKNOWN, "??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_4 },

	/*
	 * =============== AuthenticAMD Family 0x14 ===============
	 */
	{ 0x14, 0x01, 0x01, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_14_REV_B, "B",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_5 },
	{ 0x14, 0x02, 0x02, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_14_REV_C, "C",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_5 },
	{ 0x14, 0x00, 0xff, 0x0, 0xf, X86_CHIPREV_AMD_LEGACY_14_UNKNOWN, "??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_5 },

	/*
	 * =============== AuthenticAMD Family 0x15 ===============
	 */
	{ 0x15, 0x01, 0x01, 0x2, 0x2, X86_CHIPREV_AMD_OROCHI_REV_B2, "OR-B2",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_6 },
	{ 0x15, 0x02, 0x02, 0x0, 0x0, X86_CHIPREV_AMD_OROCHI_REV_C0, "OR-C0",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_6 },
	{ 0x15, 0x00, 0x0f, 0x0, 0xf, X86_CHIPREV_AMD_OROCHI_UNKNOWN, "OR-??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_6 },

	{ 0x15, 0x10, 0x10, 0x1, 0x1, X86_CHIPREV_AMD_TRINITY_REV_A1, "TN-A1",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_7 },
	{ 0x15, 0x10, 0x1f, 0x0, 0xf, X86_CHIPREV_AMD_TRINITY_UNKNOWN, "TN-??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_7 },

	{ 0x15, 0x30, 0x30, 0x1, 0x1, X86_CHIPREV_AMD_KAVERI_REV_A1, "KV-A1",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_8 },
	{ 0x15, 0x30, 0x3f, 0x0, 0xf, X86_CHIPREV_AMD_KAVERI_UNKNOWN, "KV-??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_8 },

	/*
	 * The Carrizo rev guide mentions A0 as having an ID of "00600F00h" but
	 * this appears to be a typo as elsewhere it's given as "00660F00h".  We
	 * assume the latter is correct.
	 */
	{ 0x15, 0x60, 0x60, 0x0, 0x0, X86_CHIPREV_AMD_CARRIZO_REV_A0, "CZ-A0",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_9 },
	{ 0x15, 0x60, 0x60, 0x1, 0x1, X86_CHIPREV_AMD_CARRIZO_REV_A1, "CZ-A1",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_9 },
	/*
	 * CZ-DDR4 and BR-A1 are indistinguishable via cpuid; the rev guide
	 * indicates that they should be distinguished by the contents of the
	 * OSVW MSR, but this register is just a software scratch space which
	 * means the actual method of distinguishing the two is not documented
	 * and on PCs will be done by a BIOS.  In the extremely unlikely event
	 * it becomes necessary to distinguish these, an OSVW-driven fixup can
	 * be added.
	 */
	{ 0x15, 0x65, 0x65, 0x1, 0x1, X86_CHIPREV_AMD_CARRIZO_REV_DDR4,
	    "CZ-DDR4", X86_UARCHREV_AMD_LEGACY, A_SKTS_9 },
	{ 0x15, 0x60, 0x6f, 0x0, 0xf, X86_CHIPREV_AMD_CARRIZO_UNKNOWN, "CZ-??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_9 },

	{ 0x15, 0x70, 0x70, 0x0, 0x0, X86_CHIPREV_AMD_STONEY_RIDGE_REV_A0,
	    "ST-A0", X86_UARCHREV_AMD_LEGACY, A_SKTS_10 },
	{ 0x15, 0x70, 0x7f, 0x0, 0xf, X86_CHIPREV_AMD_STONEY_RIDGE_UNKNOWN,
	    "ST-??", X86_UARCHREV_AMD_LEGACY, A_SKTS_10 },

	/*
	 * =============== AuthenticAMD Family 0x16 ===============
	 */
	{ 0x16, 0x00, 0x00, 0x1, 0x1, X86_CHIPREV_AMD_KABINI_A1, "KB-A1",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_11 },
	{ 0x16, 0x00, 0x0f, 0x0, 0xf, X86_CHIPREV_AMD_KABINI_UNKNOWN, "KB-??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_11 },

	{ 0x16, 0x30, 0x30, 0x1, 0x1, X86_CHIPREV_AMD_MULLINS_A1, "ML-A1",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_12 },
	{ 0x16, 0x30, 0x3f, 0x0, 0xf, X86_CHIPREV_AMD_MULLINS_UNKNOWN, "ML-??",
	    X86_UARCHREV_AMD_LEGACY, A_SKTS_12 },

	/*
	 * =============== AuthenticAMD Family 0x17 ===============
	 */
	/* Naples == Zeppelin == ZP */
	{ 0x17, 0x00, 0x00, 0x0, 0x0, X86_CHIPREV_AMD_NAPLES_A0, "ZP-A0",
	    X86_UARCHREV_AMD_ZEN1, A_SKTS_NAPLES },
	{ 0x17, 0x01, 0x01, 0x1, 0x1, X86_CHIPREV_AMD_NAPLES_B1, "ZP-B1",
	    X86_UARCHREV_AMD_ZEN1, A_SKTS_NAPLES },
	{ 0x17, 0x01, 0x01, 0x2, 0x2, X86_CHIPREV_AMD_NAPLES_B2, "ZP-B2",
	    X86_UARCHREV_AMD_ZEN1, A_SKTS_NAPLES },
	{ 0x17, 0x00, 0x07, 0x0, 0xf, X86_CHIPREV_AMD_NAPLES_UNKNOWN, "ZP-??",
	    X86_UARCHREV_AMD_ZEN1, A_SKTS_NAPLES },
	{ 0x17, 0x08, 0x08, 0x2, 0x2, X86_CHIPREV_AMD_PINNACLE_RIDGE_B2,
	    "PiR-B2", X86_UARCHREV_AMD_ZENPLUS, A_SKTS_NAPLES },
	{ 0x17, 0x08, 0x0f, 0x0, 0xf, X86_CHIPREV_AMD_PINNACLE_RIDGE_UNKNOWN,
	    "PiR-??", X86_UARCHREV_AMD_ZENPLUS, A_SKTS_NAPLES },

	{ 0x17, 0x11, 0x11, 0x0, 0x0, X86_CHIPREV_AMD_RAVEN_RIDGE_B0,
	    "RV-B0", X86_UARCHREV_AMD_ZEN1, A_SKTS_RAVEN },
	{ 0x17, 0x11, 0x11, 0x1, 0x1, X86_CHIPREV_AMD_RAVEN_RIDGE_B1,
	    "RV-B1", X86_UARCHREV_AMD_ZEN1, A_SKTS_RAVEN },
	{ 0x17, 0x10, 0x17, 0x0, 0xf, X86_CHIPREV_AMD_RAVEN_RIDGE_UNKNOWN,
	    "RV-??", X86_UARCHREV_AMD_ZEN1, A_SKTS_RAVEN },
	{ 0x17, 0x18, 0x18, 0x1, 0x1, X86_CHIPREV_AMD_PICASSO_B1, "PCO-B1",
	    X86_UARCHREV_AMD_ZENPLUS, A_SKTS_RAVEN },
	{ 0x17, 0x18, 0x1f, 0x0, 0xf, X86_CHIPREV_AMD_PICASSO_UNKNOWN, "PCO-??",
	    X86_UARCHREV_AMD_ZENPLUS, A_SKTS_RAVEN },

	{ 0x17, 0x20, 0x20, 0x1, 0x1, X86_CHIPREV_AMD_DALI_A1, "RV2X-A1",
	    X86_UARCHREV_AMD_ZEN1, A_SKTS_RAVEN },
	{ 0x17, 0x20, 0x2f, 0x0, 0xf, X86_CHIPREV_AMD_DALI_UNKNOWN, "RV2X-??",
	    X86_UARCHREV_AMD_ZEN1, A_SKTS_RAVEN },

	/* Rome == Starship == SSP */
	{ 0x17, 0x30, 0x30, 0x0, 0x0, X86_CHIPREV_AMD_ROME_A0, "SSP-A0",
	    X86_UARCHREV_AMD_ZEN2_A0, A_SKTS_ROME },
	{ 0x17, 0x31, 0x31, 0x0, 0x0, X86_CHIPREV_AMD_ROME_B0, "SSP-B0",
	    X86_UARCHREV_AMD_ZEN2_B0, A_SKTS_ROME },
	{ 0x17, 0x30, 0x3f, 0x0, 0xf, X86_CHIPREV_AMD_ROME_UNKNOWN, "SSP-??",
	    X86_UARCHREV_AMD_ZEN2_UNKNOWN, A_SKTS_ROME },

	{ 0x17, 0x60, 0x60, 0x1, 0x1, X86_CHIPREV_AMD_RENOIR_A1, "RN-A1",
	    X86_UARCHREV_AMD_ZEN2_B0, A_SKTS_RENOIR },
	{ 0x17, 0x60, 0x67, 0x0, 0xf, X86_CHIPREV_AMD_RENOIR_UNKNOWN, "RN-??",
	    X86_UARCHREV_AMD_ZEN2_UNKNOWN, A_SKTS_RENOIR },
	{ 0x17, 0x68, 0x68, 0x1, 0x1, X86_CHIPREV_AMD_RENOIR_LCN_A1, "LCN-A1",
	    X86_UARCHREV_AMD_ZEN2_B0, A_SKTS_RENOIR },
	{ 0x17, 0x68, 0x6f, 0x0, 0xf, X86_CHIPREV_AMD_RENOIR_UNKNOWN, "LCN-??",
	    X86_UARCHREV_AMD_ZEN2_UNKNOWN, A_SKTS_RENOIR },

	{ 0x17, 0x71, 0x71, 0x0, 0x0, X86_CHIPREV_AMD_MATISSE_B0, "MTS-B0",
	    X86_UARCHREV_AMD_ZEN2_B0, A_SKTS_MATISSE },
	{ 0x17, 0x70, 0x7f, 0x0, 0xf, X86_CHIPREV_AMD_MATISSE_UNKNOWN, "MTS-??",
	    X86_UARCHREV_AMD_ZEN2_UNKNOWN, A_SKTS_MATISSE },

	{ 0x17, 0x90, 0x97, 0x0, 0xf, X86_CHIPREV_AMD_VAN_GOGH_UNKNOWN, "??",
	    X86_UARCHREV_AMD_ZEN2_UNKNOWN, A_SKTS_VANGOGH },
	{ 0x17, 0x98, 0x9f, 0x0, 0xf, X86_CHIPREV_AMD_VAN_GOGH_UNKNOWN, "??",
	    X86_UARCHREV_AMD_ZEN2_UNKNOWN, A_SKTS_UNKNOWN },

	{ 0x17, 0xa0, 0xaf, 0x0, 0xf, X86_CHIPREV_AMD_MENDOCINO_UNKNOWN, "??",
	    X86_UARCHREV_AMD_ZEN2_UNKNOWN, A_SKTS_MENDOCINO },

	/*
	 * =============== HygonGenuine Family 0x18 ===============
	 */
	{ 0x18, 0x00, 0x00, 0x1, 0x1, X86_CHIPREV_HYGON_DHYANA_A1, "DN_A1",
	    X86_UARCHREV_AMD_ZEN1, A_SKTS_DHYANA },
	{ 0x18, 0x00, 0x0f, 0x0, 0xf, X86_CHIPREV_HYGON_DHYANA_UNKNOWN, "DN_??",
	    X86_UARCHREV_AMD_ZEN1, A_SKTS_DHYANA },

	/*
	 * =============== AuthenticAMD Family 0x19 ===============
	 */
	/* Milan == Genesis == GN */
	{ 0x19, 0x00, 0x00, 0x0, 0x0, X86_CHIPREV_AMD_MILAN_A0, "GN-A0",
	    X86_UARCHREV_AMD_ZEN3_A0, A_SKTS_MILAN },
	{ 0x19, 0x01, 0x01, 0x0, 0x0, X86_CHIPREV_AMD_MILAN_B0, "GN-B0",
	    X86_UARCHREV_AMD_ZEN3_B0, A_SKTS_MILAN },
	{ 0x19, 0x01, 0x01, 0x1, 0x1, X86_CHIPREV_AMD_MILAN_B1, "GN-B1",
	    X86_UARCHREV_AMD_ZEN3_B1, A_SKTS_MILAN },
	/* Marketed as Milan-X but still GN */
	{ 0x19, 0x01, 0x01, 0x2, 0x2, X86_CHIPREV_AMD_MILAN_B2, "GN-B2",
	    X86_UARCHREV_AMD_ZEN3_B2, A_SKTS_MILAN },
	{ 0x19, 0x00, 0x0f, 0x0, 0xf, X86_CHIPREV_AMD_MILAN_UNKNOWN, "GN-??",
	    X86_UARCHREV_AMD_ZEN3_UNKNOWN, A_SKTS_MILAN },

	/* Genoa == Stones == RS */
	{ 0x19, 0x10, 0x10, 0x0, 0x0, X86_CHIPREV_AMD_GENOA_A0, "RS-A0",
	    X86_UARCHREV_AMD_ZEN4_A0, A_SKTS_GENOA },
	/* RS-A0 & RS-A1 both map to Zen 4 uarch A0 */
	{ 0x19, 0x10, 0x10, 0x1, 0x1, X86_CHIPREV_AMD_GENOA_A1, "RS-A1",
	    X86_UARCHREV_AMD_ZEN4_A0, A_SKTS_GENOA },
	{ 0x19, 0x11, 0x11, 0x0, 0x0, X86_CHIPREV_AMD_GENOA_B0, "RS-B0",
	    X86_UARCHREV_AMD_ZEN4_B0, A_SKTS_GENOA },
	{ 0x19, 0x11, 0x11, 0x1, 0x1, X86_CHIPREV_AMD_GENOA_B1, "RS-B1",
	    X86_UARCHREV_AMD_ZEN4_B1, A_SKTS_GENOA },
	{ 0x19, 0x10, 0x1f, 0x0, 0xf, X86_CHIPREV_AMD_GENOA_UNKNOWN, "RS-??",
	    X86_UARCHREV_AMD_ZEN4_UNKNOWN, A_SKTS_GENOA },

	{ 0x19, 0x20, 0x20, 0x0, 0x0, X86_CHIPREV_AMD_VERMEER_A0, "VMR-A0",
	    X86_UARCHREV_AMD_ZEN3_A0, A_SKTS_VERMEER },
	{ 0x19, 0x21, 0x21, 0x0, 0x0, X86_CHIPREV_AMD_VERMEER_B0, "VMR-B0",
	    X86_UARCHREV_AMD_ZEN3_B0, A_SKTS_VERMEER },
	{ 0x19, 0x21, 0x21, 0x2, 0x2, X86_CHIPREV_AMD_VERMEER_B2, "VMR-B2",
	    X86_UARCHREV_AMD_ZEN3_B2, A_SKTS_VERMEER },
	{ 0x19, 0x20, 0x2f, 0x0, 0xf, X86_CHIPREV_AMD_VERMEER_UNKNOWN, "VMR-??",
	    X86_UARCHREV_AMD_ZEN3_UNKNOWN, A_SKTS_VERMEER },

	/* Rev guide is missing AM5 information, including A0 and B0 */
	{ 0x19, 0x40, 0x40, 0x0, 0x0, X86_CHIPREV_AMD_REMBRANDT_A0, "RMB-A0",
	    X86_UARCHREV_AMD_ZEN3_B0, A_SKTS_REMBRANDT },
	{ 0x19, 0x44, 0x44, 0x0, 0x0, X86_CHIPREV_AMD_REMBRANDT_B0, "RMB-B0",
	    X86_UARCHREV_AMD_ZEN3_B0, A_SKTS_REMBRANDT },
	{ 0x19, 0x44, 0x44, 0x1, 0x1, X86_CHIPREV_AMD_REMBRANDT_B1, "RMB-B1",
	    X86_UARCHREV_AMD_ZEN3_B0, A_SKTS_REMBRANDT },
	{ 0x19, 0x40, 0x4f, 0x0, 0xf, X86_CHIPREV_AMD_REMBRANDT_UNKNOWN,
	    "RMB-??", X86_UARCHREV_AMD_ZEN3_UNKNOWN, A_SKTS_REMBRANDT },

	/* Cezanne */
	{ 0x19, 0x50, 0x50, 0x0, 0x0, X86_CHIPREV_AMD_CEZANNE_A0, "CZN-A0",
	    X86_UARCHREV_AMD_ZEN3_B0, A_SKTS_CEZANNE },
	{ 0x19, 0x50, 0x5f, 0x0, 0xf, X86_CHIPREV_AMD_CEZANNE_UNKNOWN, "CZN-??",
	    X86_UARCHREV_AMD_ZEN3_UNKNOWN, A_SKTS_CEZANNE },

	/* Raphael */
	{ 0x19, 0x61, 0x61, 0x2, 0x2, X86_CHIPREV_AMD_RAPHAEL_B2, "RPL-B2",
	    X86_UARCHREV_AMD_ZEN4_B2, A_SKTS_RAPHAEL },
	{ 0x19, 0x60, 0x6f, 0x0, 0xf, X86_CHIPREV_AMD_RAPHAEL_UNKNOWN, "RPL-??",
	    X86_UARCHREV_AMD_ZEN4_UNKNOWN, A_SKTS_RAPHAEL },

	/* Phoenix */
	{ 0x19, 0x74, 0x74, 0x1, 0x1, X86_CHIPREV_AMD_PHOENIX_A1, "PHX-A1",
	    X86_UARCHREV_AMD_ZEN4_A1, A_SKTS_PHOENIX },
	{ 0x19, 0x70, 0x7f, 0x0, 0xf, X86_CHIPREV_AMD_PHOENIX_UNKNOWN, "PHX-??",
	    X86_UARCHREV_AMD_ZEN4_UNKNOWN, A_SKTS_PHOENIX },

	/* Bergamo / Siena */
	{ 0x19, 0xa0, 0xaf, 0x0, 0x0, X86_CHIPREV_AMD_BERGAMO_A0, "RSDN-A0",
	    X86_UARCHREV_AMD_ZEN4_A0, A_SKTS_BERGAMO },
	{ 0x19, 0xa0, 0xaf, 0x1, 0x1, X86_CHIPREV_AMD_BERGAMO_A1, "RSDN-A1",
	    X86_UARCHREV_AMD_ZEN4_A1, A_SKTS_BERGAMO },
	{ 0x19, 0xa0, 0xaf, 0x2, 0x2, X86_CHIPREV_AMD_BERGAMO_A2, "RSDN-A2",
	    X86_UARCHREV_AMD_ZEN4_A2, A_SKTS_BERGAMO },
	{ 0x19, 0xa0, 0xaf, 0x0, 0xf, X86_CHIPREV_AMD_BERGAMO_UNKNOWN, "???",
	    X86_UARCHREV_AMD_ZEN4_UNKNOWN, A_SKTS_BERGAMO },

	/* Turin */
	{ 0x1a, 0x00, 0x00, 0x0, 0x0, X86_CHIPREV_AMD_TURIN_A0, "BRH-A0",
	    X86_UARCHREV_AMD_ZEN5_A0, A_SKTS_TURIN},
	/* BRH-A0 & BRH-B0 both map to Zen 5 uarch A0 */
	{ 0x1a, 0x01, 0x01, 0x0, 0x0, X86_CHIPREV_AMD_TURIN_B0, "BRH-B0",
	    X86_UARCHREV_AMD_ZEN5_A0, A_SKTS_TURIN},
	/* BRH-B1 maps to Zen 5 uarch B0 */
	{ 0x1a, 0x01, 0x01, 0x1, 0x1, X86_CHIPREV_AMD_TURIN_B1, "BRH-B1",
	    X86_UARCHREV_AMD_ZEN5_B0, A_SKTS_TURIN},
	{ 0x1a, 0x02, 0x02, 0x0, 0x0, X86_CHIPREV_AMD_TURIN_C0, "BRH-C0",
	    X86_UARCHREV_AMD_ZEN5_C0, A_SKTS_TURIN},
	{ 0x1a, 0x02, 0x02, 0x1, 0x1, X86_CHIPREV_AMD_TURIN_C1, "BRH-C1",
	    X86_UARCHREV_AMD_ZEN5_C1, A_SKTS_TURIN},
	{ 0x1a, 0x00, 0x0f, 0x0, 0xf, X86_CHIPREV_AMD_TURIN_UNKNOWN, "BRH-???",
	    X86_UARCHREV_AMD_ZEN5_UNKNOWN, A_SKTS_TURIN},
	{ 0x1a, 0x10, 0x10, 0x0, 0x0, X86_CHIPREV_AMD_DENSE_TURIN_A0,
	    "BRHD-A0", X86_UARCHREV_AMD_ZEN5_A0, A_SKTS_TURIN},
	{ 0x1a, 0x11, 0x11, 0x0, 0x0, X86_CHIPREV_AMD_DENSE_TURIN_B0,
	    "BRHD-B0", X86_UARCHREV_AMD_ZEN5_B0, A_SKTS_TURIN},
	/* BRHD-B0 & BRHD-B1 both map to Zen 5 uarch B0 */
	{ 0x1a, 0x11, 0x11, 0x1, 0x1, X86_CHIPREV_AMD_DENSE_TURIN_B1,
	    "BRHD-B1", X86_UARCHREV_AMD_ZEN5_B0, A_SKTS_TURIN},
	{ 0x1a, 0x10, 0x1f, 0x0, 0xf, X86_CHIPREV_AMD_DENSE_TURIN_UNKNOWN,
	    "BRHD-???", X86_UARCHREV_AMD_ZEN5_UNKNOWN, A_SKTS_TURIN}

};

/*
 * AMD keeps the socket type in CPUID Fn8000_0001_EBX, bits 31:28.
 */
static uint32_t
synth_amd_skt_cpuid(uint_t family, uint_t sktid)
{
	struct cpuid_regs cp;
	uint_t idx;

	cp.cp_eax = 0x80000001;
	(void) __cpuid_insn(&cp);

	/* PkgType bits */
	idx = BITX(cp.cp_ebx, 31, 28);

	if (family == 0x10) {
		uint32_t val;

		val = pci_getl_func(0, 24, 2, 0x94);
		if (BITX(val, 8, 8)) {
			if (amd_skts[sktid][idx] == X86_SOCKET_AM2R2) {
				return (X86_SOCKET_AM3);
			} else if (amd_skts[sktid][idx] == X86_SOCKET_S1g3) {
				return (X86_SOCKET_S1g4);
			}
		}
	}

	return (amd_skts[sktid][idx]);
}

static void
synth_amd_info(uint_t family, uint_t model, uint_t step,
    uint32_t *skt_p, x86_chiprev_t *chiprev_p, const char **chiprevstr_p,
    x86_uarchrev_t *uarchrev_p)
{
	const struct amd_rev_mapent *rmp;
	int found = 0;
	int i;

	if (family < 0xf)
		return;

	for (i = 0, rmp = amd_revmap; i < ARRAY_SIZE(amd_revmap); i++, rmp++) {
		if (family == rmp->rm_family &&
		    model >= rmp->rm_modello && model <= rmp->rm_modelhi &&
		    step >= rmp->rm_steplo && step <= rmp->rm_stephi) {
			found = 1;
			break;
		}
	}

	if (found) {
		if (chiprev_p != NULL)
			*chiprev_p = rmp->rm_chiprev;
		if (chiprevstr_p != NULL)
			*chiprevstr_p = rmp->rm_chiprevstr;
		if (uarchrev_p != NULL)
			*uarchrev_p = rmp->rm_uarchrev;
	}

	if (skt_p != NULL) {
		int platform;

#ifdef __xpv
		/* PV guest */
		if (!is_controldom()) {
			*skt_p = X86_SOCKET_UNKNOWN;
			return;
		}
#endif
		platform = get_hwenv();

		if ((platform & HW_VIRTUAL) != 0) {
			*skt_p = X86_SOCKET_UNKNOWN;
			return;
		}

		if (!found)
			return;

		if (family == 0xf) {
			*skt_p = amd_skts[rmp->rm_sktidx][model & 0x3];
		} else {
			*skt_p = synth_amd_skt_cpuid(family, rmp->rm_sktidx);
		}
	}
}

uint32_t
_cpuid_skt(uint_t vendor, uint_t family, uint_t model, uint_t step)
{
	uint32_t skt = X86_SOCKET_UNKNOWN;

	switch (vendor) {
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		synth_amd_info(family, model, step, &skt, NULL, NULL, NULL);
		break;

	default:
		break;

	}

	return (skt);
}

const char *
_cpuid_sktstr(uint_t vendor, uint_t family, uint_t model, uint_t step)
{
	const char *sktstr = "Unknown";
	struct amd_sktmap_s *sktmapp;
	uint32_t skt = X86_SOCKET_UNKNOWN;

	switch (vendor) {
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		synth_amd_info(family, model, step, &skt, NULL, NULL, NULL);

		sktmapp = amd_sktmap_strs;
		while (sktmapp->skt_code != X86_SOCKET_UNKNOWN) {
			if (sktmapp->skt_code == skt)
				break;
			sktmapp++;
		}
		sktstr = sktmapp->sktstr;
		break;

	default:
		break;

	}

	return (sktstr);
}

x86_chiprev_t
_cpuid_chiprev(uint_t vendor, uint_t family, uint_t model, uint_t step)
{
	x86_chiprev_t chiprev = X86_CHIPREV_UNKNOWN;

	switch (vendor) {
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		synth_amd_info(family, model, step, NULL, &chiprev, NULL, NULL);
		break;

	default:
		break;

	}

	return (chiprev);
}

x86_uarchrev_t
_cpuid_uarchrev(uint_t vendor, uint_t family, uint_t model, uint_t step)
{
	x86_uarchrev_t uarchrev = X86_UARCHREV_UNKNOWN;

	switch (vendor) {
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		synth_amd_info(family, model, step, NULL, NULL, NULL,
		    &uarchrev);
		break;

	default:
		break;

	}

	return (uarchrev);
}

const char *
_cpuid_chiprevstr(uint_t vendor, uint_t family, uint_t model, uint_t step)
{
	const char *revstr = "Unknown";

	switch (vendor) {
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		synth_amd_info(family, model, step, NULL, NULL, &revstr, NULL);
		break;

	default:
		break;

	}

	return (revstr);

}

/*
 * Map the vendor string to a type code
 */
uint_t
_cpuid_vendorstr_to_vendorcode(char *vendorstr)
{
	if (strcmp(vendorstr, X86_VENDORSTR_Intel) == 0)
		return (X86_VENDOR_Intel);
	else if (strcmp(vendorstr, X86_VENDORSTR_AMD) == 0)
		return (X86_VENDOR_AMD);
	else if (strcmp(vendorstr, X86_VENDORSTR_HYGON) == 0)
		return (X86_VENDOR_HYGON);
	else if (strcmp(vendorstr, X86_VENDORSTR_TM) == 0)
		return (X86_VENDOR_TM);
	else if (strcmp(vendorstr, X86_VENDORSTR_CYRIX) == 0)
		return (X86_VENDOR_Cyrix);
	else if (strcmp(vendorstr, X86_VENDORSTR_UMC) == 0)
		return (X86_VENDOR_UMC);
	else if (strcmp(vendorstr, X86_VENDORSTR_NexGen) == 0)
		return (X86_VENDOR_NexGen);
	else if (strcmp(vendorstr, X86_VENDORSTR_Centaur) == 0)
		return (X86_VENDOR_Centaur);
	else if (strcmp(vendorstr, X86_VENDORSTR_Rise) == 0)
		return (X86_VENDOR_Rise);
	else if (strcmp(vendorstr, X86_VENDORSTR_SiS) == 0)
		return (X86_VENDOR_SiS);
	else if (strcmp(vendorstr, X86_VENDORSTR_NSC) == 0)
		return (X86_VENDOR_NSC);
	else
		return (X86_VENDOR_IntelClone);
}
