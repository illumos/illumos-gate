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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_AMDZEN_THM_H
#define	_SYS_AMDZEN_THM_H

#include <sys/bitext.h>
#include <sys/amdzen/smn.h>

/*
 * This header covers the SMU's (system management unit) thermal block. The SMU,
 * often called MP1 in various AMD docs, exists as a single entity in the I/O
 * die (or a Zen 1 Zeppelin die), leaving most registers at a fixed entry point
 * and block.
 *
 * The thermal block SMN registers are generally shadows or calculated
 * information based on a series of internal diodes, slewing, and other related
 * features that exist within the SOC. Only a subset of the overall thermal
 * registers are described here which are used by us to obtain information. The
 * majority of the other registers are only used by the SMU and perhaps the PSP.
 * Note, similar information is provided over the sideband temperature interface
 * (SB-TSI), which is consumed by the service processor on a system board that
 * maintains a thermal loop.
 *
 * Note, CCDs have their own separate thermal block, SMU::THMCCD.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SMU::THM registers, per-die.  This functional unit is present in all Zen CPUs
 * and is effectively a singleton.
 */
#define	SMU_THM_APERTURE_MASK	0xfffffffffffff800
AMDZEN_MAKE_SMN_REG_FN(amdzen_smuthm_smn_reg, SMU_THM, 0x59800,
    SMU_THM_APERTURE_MASK, 1, 0);

/*
 * SMU::THM::THM_TCON_CUR_TMP -- the primary thermal sensor in a given die. This
 * is where Tctl generally comes from. Regardless of whether it encodes Tctl or
 * Tj, the value is measured in 0.125 steps, hence a granularity of 8. The three
 * lower bits of the temperature are to the right of the decimal.
 */
#define	THM_CURTEMP		SMN_MAKE_REG(0x59800)
#define	THM_CURTEMP_GET_TEMP(r)		bitx32(r, 31, 21)
#define	THM_CURTEMP_TEMP_DEC_BITS	3
#define	THM_CURTEMP_TEMP_DEC_MASK	0x7
#define	THM_CURTEMP_TEMP_DEC_GRAN	8
#define	THM_CURTEMP_GET_MCM(r)		bitx32(r, 20, 20)
#define	THM_CURTEMP_GET_RANGE(r)	bitx32(r, 19, 19)
#define	THM_CURTEMP_RANGE_O_225		0
#define	THM_CURTEMP_RANGE_N49_206	1
#define	THM_CURTEMP_RANGE_ADJ		(-49)
#define	THM_CURTEMP_GET_SLEW_SEL(r)	bitx32(r, 18, 18)
#define	THM_CURTEMP_GET_TJ_SEL(r)	bitx32(r, 17, 16)
#define	THM_CURTEMP_TJ_SEL_TCTL		0
#define	THM_CURTEMP_TJ_SEL_TJ		2
#define	THM_CURTEMP_TJ_SEL_RW		3
#define	THM_CURTEMP_GET_TIME_DOWN(r)	bitx32(r, 12, 8)
#define	THM_CURTEMP_GET_SLEW_DOWN_EN(r)	bitx32(r, 7, 7)
#define	THM_CURTEMP_GET_MAX_DIFF(r)	bitx32(r, 6, 5)
#define	THM_CURTEMP_GET_TIME_UP(r)	bitx32(r, 4, 0)

/*
 * SMU::THM::THM_DIEX_TEMP -- this is a per-die measurement that comes from the
 * thermal monitor. It measures Tdie and is in degrees C. The value is otherwise
 * in the same format as described for SMU::THM::THM_TCON_CUR_TMP. Unlike Tctl
 * above, this has a valid bit that must be consulted. Our understanding is that
 * the valid bit, once set, will generally remain true.
 *
 * This register has a bit of an unfortunate history. The number of these that
 * are valid and their location unfortunately changes on a per-CPU basis. This
 * results in a much more complicated function for getting this with
 * corresponding limits.
 */
static inline uint16_t
THM_DIE_MAX_UNITS(x86_processor_family_t fam)
{
	switch (fam) {
	case X86_PF_AMD_NAPLES:
	case X86_PF_AMD_PINNACLE_RIDGE:
	case X86_PF_AMD_RAVEN_RIDGE:
	case X86_PF_AMD_PICASSO:
	case X86_PF_AMD_DALI:
	case X86_PF_HYGON_DHYANA:
		return (4);
	case X86_PF_AMD_ROME:
	case X86_PF_AMD_RENOIR:
	case X86_PF_AMD_MATISSE:
	case X86_PF_AMD_VAN_GOGH:
	case X86_PF_AMD_MILAN:
	case X86_PF_AMD_VERMEER:
	case X86_PF_AMD_CEZANNE:
	case X86_PF_AMD_MENDOCINO:
	case X86_PF_AMD_REMBRANDT:
	case X86_PF_AMD_RAPHAEL:
	case X86_PF_AMD_PHOENIX:
	case X86_PF_AMD_GRANITE_RIDGE:
		return (8);
	case X86_PF_AMD_GENOA:
	case X86_PF_AMD_BERGAMO:
		return (12);
	case X86_PF_AMD_TURIN:
	case X86_PF_AMD_DENSE_TURIN:
		return (16);
	case X86_PF_AMD_STRIX:
	default:
		return (0);
	}
}

static inline smn_reg_t
THM_DIE(uint8_t dieno, x86_processor_family_t fam)
{
	smn_reg_def_t regdef = { 0 };
	regdef.srd_unit = SMN_UNIT_SMU_THM;
	regdef.srd_nents = THM_DIE_MAX_UNITS(fam);
	ASSERT3U(regdef.srd_nents, !=, 0);

	switch (fam) {
	case X86_PF_AMD_NAPLES:
	case X86_PF_AMD_PINNACLE_RIDGE:
	case X86_PF_AMD_RAVEN_RIDGE:
	case X86_PF_AMD_PICASSO:
	case X86_PF_AMD_DALI:
	case X86_PF_HYGON_DHYANA:
	case X86_PF_AMD_ROME:
	case X86_PF_AMD_RENOIR:
	case X86_PF_AMD_MATISSE:
	case X86_PF_AMD_VAN_GOGH:
	case X86_PF_AMD_MILAN:
	case X86_PF_AMD_VERMEER:
	case X86_PF_AMD_CEZANNE:
		regdef.srd_reg = 0x154;
		break;
	case X86_PF_AMD_MENDOCINO:
	case X86_PF_AMD_REMBRANDT:
	case X86_PF_AMD_GENOA:
	case X86_PF_AMD_BERGAMO:
		regdef.srd_reg = 0x300;
		break;
	case X86_PF_AMD_RAPHAEL:
	case X86_PF_AMD_PHOENIX:
	case X86_PF_AMD_GRANITE_RIDGE:
		regdef.srd_reg = 0x308;
		break;
	case X86_PF_AMD_TURIN:
	case X86_PF_AMD_DENSE_TURIN:
		regdef.srd_reg = 0x1f0;
		break;
	default:
		panic("encountered unknown family 0x%x while constructing "
		    "SMU::THM::THM_DIEX_TEMP", fam);
	}

	return (amdzen_smuthm_smn_reg(0, regdef, dieno));
}
#define	THM_DIE_GET_VALID(r)	bitx32(r, 11, 11)
#define	THM_DIE_GET_TEMP(r)	bitx32(r, 10, 0)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AMDZEN_THM_H */
