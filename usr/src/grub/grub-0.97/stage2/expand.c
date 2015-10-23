/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
 *  Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <expand.h>
#include <shared.h>

#ifdef	SUPPORT_NETBOOT
#include <grub.h>
#endif

#include <cpu.h>

#define	EVF_DEFINED	0x01
#define	EVF_VALUESET	0x02

typedef struct variable {
	char v_name[EV_NAMELEN];
	unsigned int v_flags;
	char v_value[220];	/* 256 - EV_NAMELEN - sizeof (fields) */
} variable_t;

static variable_t expvars[32];
static const unsigned int nexpvars = 32;

int
set_variable(const char *name, const char *value)
{
	unsigned int i;
	unsigned int avail = nexpvars;

	if (strlen(name) >= sizeof (expvars[0].v_name))
		return (ERR_WONT_FIT);

	if (value != NULL && strlen(value) >= sizeof (expvars[0].v_value))
		return (ERR_WONT_FIT);

	for (i = 0; i < nexpvars; i++) {
		if (expvars[i].v_flags & EVF_DEFINED) {
			if (grub_strcmp(expvars[i].v_name, name) == 0)
				break;
		} else if (i < avail) {
			avail = i;
		}
	}

	if (i == nexpvars) {
		if (avail == nexpvars)
			return (ERR_WONT_FIT);

		i = avail;
		(void) grub_strcpy(expvars[i].v_name, name);
		expvars[i].v_flags = EVF_DEFINED;
	}

	if (value != NULL) {
		(void) grub_strcpy(expvars[i].v_value, value);
		expvars[i].v_flags |= EVF_VALUESET;
	} else {
		expvars[i].v_flags &= ~EVF_VALUESET;
	}

	return (0);
}

const char *
get_variable(const char *name)
{
	unsigned int i;

	for (i = 0; i < nexpvars; i++) {
		if (!(expvars[i].v_flags & EVF_DEFINED))
			continue;
		if (grub_strcmp(expvars[i].v_name, name) == 0) {
			if (expvars[i].v_flags & EVF_VALUESET)
				return (expvars[i].v_value);
			return ("");
		}
	}

	return (NULL);
}

static int
detect_target_operating_mode(void)
{
	int ret, ah;

	/*
	 * This function returns 16 bits.  The upper 8 are the value of %ah
	 * after calling int 15/ec00.  The lower 8 bits are zero if the BIOS
	 * call left CF clear, nonzero otherwise.
	 */
	ret = get_target_operating_mode();
	ah = ret >> 8;
	ret &= 0xff;

	if (ah == 0x86 && ret != 0) {
		grub_printf("[BIOS 'Detect Target Operating Mode' "
		    "callback unsupported on this platform]\n");
		return (1);	/* unsupported, ignore */
	}

	if (ah == 0 && ret == 0) {
		grub_printf("[BIOS accepted mixed-mode target setting!]\n");
		return (1);	/* told the bios what we're up to */
	}

	if (ah == 0 && ret != 0) {
		grub_printf("fatal: BIOS reports this machine CANNOT run in "
		    "mixed 32/64-bit mode!\n");
		return (0);
	}

	grub_printf("warning: BIOS Detect Target Operating Mode callback "
	    "confused.\n         %%ax >> 8 = 0x%x, carry = %d\n", ah, ret);

	return (1);
}

static int
amd64_config_cpu(void)
{
	struct amd64_cpuid_regs __vcr, *vcr = &__vcr;
	uint32_t maxeax;
	uint32_t max_maxeax = 0x100;
	char vendor[13];
	int isamd64 = 0;
	uint32_t stdfeatures = 0, xtdfeatures = 0;
	uint64_t efer;

	/*
	 * This check may seem silly, but if the C preprocesor symbol __amd64
	 * is #defined during compilation, something that may outwardly seem
	 * like a good idea, uts/common/sys/isa_defs.h will #define _LP64,
	 * which will cause uts/common/sys/int_types.h to typedef uint64_t as
	 * an unsigned long - which is only 4 bytes in size when using a 32-bit
	 * compiler.
	 *
	 * If that happens, all the page table translation routines will fail
	 * horribly, so check the size of uint64_t just to insure some degree
	 * of sanity in future operations.
	 */
	/*LINTED [sizeof result is invarient]*/
	if (sizeof (uint64_t) != 8)
		prom_panic("grub compiled improperly, unable to boot "
		    "64-bit AMD64 executables");

	/*
	 * If the CPU doesn't support the CPUID instruction, it's definitely
	 * not an AMD64.
	 */
	if (amd64_cpuid_supported() == 0)
		return (0);

	amd64_cpuid_insn(0, vcr);

	maxeax = vcr->r_eax;
	{
		/*LINTED [vendor string from cpuid data]*/
		uint32_t *iptr = (uint32_t *)vendor;

		*iptr++ = vcr->r_ebx;
		*iptr++ = vcr->r_edx;
		*iptr++ = vcr->r_ecx;

		vendor[12] = '\0';
	}

	if (maxeax > max_maxeax) {
		grub_printf("cpu: warning, maxeax was 0x%x -> 0x%x\n",
		    maxeax, max_maxeax);
		maxeax = max_maxeax;
	}

	if (maxeax < 1)
		return (0);	/* no additional functions, not an AMD64 */
	else {
		uint_t family, model, step;

		amd64_cpuid_insn(1, vcr);

		/*
		 * All AMD64/IA32e processors technically SHOULD report
		 * themselves as being in family 0xf, but for some reason
		 * Simics doesn't, and this may change in the future, so
		 * don't error out if it's not true.
		 */
		if ((family = BITX(vcr->r_eax, 11, 8)) == 0xf)
			family += BITX(vcr->r_eax, 27, 20);

		if ((model = BITX(vcr->r_eax, 7, 4)) == 0xf)
			model += BITX(vcr->r_eax, 19, 16) << 4;
		step = BITX(vcr->r_eax, 3, 0);

		grub_printf("cpu: '%s' family %d model %d step %d\n",
		    vendor, family, model, step);
		stdfeatures = vcr->r_edx;
	}

	amd64_cpuid_insn(0x80000000, vcr);

	if (vcr->r_eax & 0x80000000) {
		uint32_t xmaxeax = vcr->r_eax;
		const uint32_t max_xmaxeax = 0x80000100;

		if (xmaxeax > max_xmaxeax) {
			grub_printf("amd64: warning, xmaxeax was "
			    "0x%x -> 0x%x\n", xmaxeax, max_xmaxeax);
			xmaxeax = max_xmaxeax;
		}

		if (xmaxeax >= 0x80000001) {
			amd64_cpuid_insn(0x80000001, vcr);
			xtdfeatures = vcr->r_edx;
		}
	}

	if (BITX(xtdfeatures, 29, 29))		/* long mode */
		isamd64++;
	else
		grub_printf("amd64: CPU does NOT support long mode\n");

	if (!BITX(stdfeatures, 0, 0)) {
		grub_printf("amd64: CPU does NOT support FPU\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 4, 4)) {
		grub_printf("amd64: CPU does NOT support TSC\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 5, 5)) {
		grub_printf("amd64: CPU does NOT support MSRs\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 6, 6)) {
		grub_printf("amd64: CPU does NOT support PAE\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 8, 8)) {
		grub_printf("amd64: CPU does NOT support CX8\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 13, 13)) {
		grub_printf("amd64: CPU does NOT support PGE\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 19, 19)) {
		grub_printf("amd64: CPU does NOT support CLFSH\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 23, 23)) {
		grub_printf("amd64: CPU does NOT support MMX\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 24, 24)) {
		grub_printf("amd64: CPU does NOT support FXSR\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 25, 25)) {
		grub_printf("amd64: CPU does NOT support SSE\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 26, 26)) {
		grub_printf("amd64: CPU does NOT support SSE2\n");
		isamd64--;
	}

	if (isamd64 < 1) {
		grub_printf("amd64: CPU does not support amd64 executables.\n");
		return (0);
	}

	amd64_rdmsr(MSR_AMD_EFER, &efer);
	if (efer & AMD_EFER_SCE)
		grub_printf("amd64: EFER_SCE (syscall/sysret) already "
		    "enabled\n");
	if (efer & AMD_EFER_NXE)
		grub_printf("amd64: EFER_NXE (no-exec prot) already enabled\n");
	if (efer & AMD_EFER_LME)
		grub_printf("amd64: EFER_LME (long mode) already enabled\n");

	return (detect_target_operating_mode());
}

static int
isamd64()
{
	static int ret = -1;

	if (ret == -1)
		ret = amd64_config_cpu();

	return (ret);
}

static int
check_min_mem64(void)
{
	if (min_mem64 == 0)
		return (1);

	if ((mbi.mem_upper / 10240) * 11 >= min_mem64)
		return (1);

	return (0);
}

/*
 * Given the nul-terminated input string s, expand all variable references
 * within that string into the buffer pointed to by d, which must be of length
 * not less than len bytes.
 *
 * We also expand the special case tokens "$ISADIR" and "$ZFS-BOOTFS" here.
 *
 * If the string will not fit, returns ERR_WONT_FIT.
 * If a nonexistent variable is referenced, returns ERR_NOVAR.
 * Otherwise, returns 0.  The resulting string is nul-terminated.  On error,
 * the contents of the destination buffer are undefined.
 */
int
expand_string(const char *s, char *d, unsigned int len)
{
	unsigned int i;
	int vlen;
	const char *p;
	char *q;
	const char *start;
	char name[EV_NAMELEN];
	const char *val;

	for (p = s, q = d; *p != '\0' && q < d + len; ) {
		/* Special case: $ISADIR */
		if (grub_strncmp(p, "$ISADIR", 7) == 0) {
			if (isamd64() && check_min_mem64()) {
				if (q + 5 >= d + len)
					return (ERR_WONT_FIT);
				(void) grub_memcpy(q, "amd64", 5);
				q += 5;	/* amd64 */
			}
			p += 7;	/* $ISADIR */
			continue;
		}
		/* Special case: $ZFS-BOOTFS */
		if (grub_strncmp(p, "$ZFS-BOOTFS", 11) == 0 &&
		    is_zfs_mount != 0) {
			if (current_bootpath[0] == '\0' &&
			    current_devid[0] == '\0') {
				return (ERR_NO_BOOTPATH);
			}

			/* zfs-bootfs=%s/%u */
			vlen = (current_bootfs_obj > 0) ? 10 : 0;
			vlen += 11;
			vlen += strlen(current_rootpool);

			/* ,bootpath=\"%s\" */
			if (current_bootpath[0] != '\0')
				vlen += 12 + strlen(current_bootpath);

			/* ,diskdevid=\"%s\" */
			if (current_devid[0] != '\0')
				vlen += 13 + strlen(current_devid);

			if (q + vlen >= d + len)
				return (ERR_WONT_FIT);

			if (current_bootfs_obj > 0) {
				q += grub_sprintf(q, "zfs-bootfs=%s/%u",
				    current_rootpool, current_bootfs_obj);
			} else {
				q += grub_sprintf(q, "zfs-bootfs=%s",
				    current_rootpool);
			}
			if (current_bootpath[0] != '\0') {
				q += grub_sprintf(q, ",bootpath=\"%s\"",
				    current_bootpath);
			}
			if (current_devid[0] != '\0') {
				q += grub_sprintf(q, ",diskdevid=\"%s\"",
				    current_devid);
			}

			p += 11;	/* $ZFS-BOOTFS */
			continue;
		}
		if (*p == '$' && *(p + 1) == '{') {
			start = p + 2;
			for (p = start; *p != '\0' && *p != '}' &&
			    p - start < sizeof (name) - 1; p++) {
				name[p - start] = *p;
			}
			/*
			 * Unterminated reference.  Copy verbatim.
			 */
			if (p - start >= sizeof (name) - 1 || *p != '}') {
				p = start;
				*q++ = '$';
				*q++ = '{';
				continue;
			}

			name[p - start] = '\0';
			val = get_variable(name);
			if (val == NULL)
				return (ERR_NOVAR);

			if ((vlen = grub_strlen(val)) >= q + len - d)
				return (ERR_WONT_FIT);

			(void) grub_memcpy(q, val, vlen);
			q += vlen;
			p++;
		} else {
			*q++ = *p++;
		}
	}

	if (q >= d + len)
		return (ERR_WONT_FIT);

	*q = '\0';

	return (0);
}

void
dump_variables(void)
{
	unsigned int i;

	for (i = 0; i < nexpvars; i++) {
		if (!(expvars[i].v_flags & EVF_DEFINED))
			continue;
		(void) grub_printf("[%u] '%s' => '%s'\n", i, expvars[i].v_name,
		    (expvars[i].v_flags & EVF_VALUESET) ?
		    expvars[i].v_value : "");
	}
}
