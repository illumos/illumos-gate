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
 * Copyright 2010 Advanced Micro Devices, Inc.
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * PCI Mechanism 1 low-level routines with ECS support for AMD family >= 0x10
 */

#include <sys/controlregs.h>
#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/sunddi.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/x86_archext.h>

boolean_t
pci_check_amd_ioecs(void)
{
	struct cpuid_regs cp;
	int family;

	if (!is_x86_feature(x86_featureset, X86FSET_CPUID))
		return (B_FALSE);

	/*
	 * Get the CPU vendor string from CPUID.
	 * This PCI mechanism only applies to AMD CPUs.
	 */
	cp.cp_eax = 0;
	(void) __cpuid_insn(&cp);

	if ((cp.cp_ebx != 0x68747541) || /* Auth */
	    (cp.cp_edx != 0x69746e65) || /* enti */
	    (cp.cp_ecx != 0x444d4163))   /* cAMD */
		return (B_FALSE);

	/*
	 * Get the CPU family from CPUID.
	 * This PCI mechanism is only available on family 0x10 or higher.
	 */
	cp.cp_eax = 1;
	(void) __cpuid_insn(&cp);
	family = ((cp.cp_eax >> 8) & 0xf) + ((cp.cp_eax >> 20) & 0xff);

	if (family < 0x10)
		return (B_FALSE);

	/*
	 * Set the EnableCf8ExtCfg bit in the Northbridge Configuration Register
	 * to enable accessing PCI ECS using in/out instructions.
	 */
	wrmsr(MSR_AMD_NB_CFG, rdmsr(MSR_AMD_NB_CFG) | AMD_GH_NB_CFG_EN_ECS);
	return (B_TRUE);
}

/*
 * Macro to setup PCI Extended Configuration Space (ECS) address to give to
 * "in/out" instructions
 */
#define	PCI_CADDR1_ECS(b, d, f, r) \
	(PCI_CADDR1((b), (d), (f), (r)) | ((((r) >> 8) & 0xf) << 24))

/*
 * Per PCI 2.1 section 3.7.4.1 and PCI-PCI Bridge Architecture 1.0 section
 * 5.3.1.2:  dev=31 func=7 reg=0 means a special cycle.  We don't want to
 * trigger that by accident, so we pretend that dev 31, func 7 doesn't
 * exist.  If we ever want special cycle support, we'll add explicit
 * special cycle support.
 */

uint8_t
pci_mech1_amd_getb(int bus, int device, int function, int reg)
{
	uint8_t val;

	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return (0xff);
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1_ECS(bus, device, function, reg));
	val = inb(PCI_CONFDATA | (reg & 0x3));
	mutex_exit(&pcicfg_mutex);
	return (val);
}

uint16_t
pci_mech1_amd_getw(int bus, int device, int function, int reg)
{
	uint16_t val;

	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return (0xffff);
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1_ECS(bus, device, function, reg));
	val =  inw(PCI_CONFDATA | (reg & 0x2));
	mutex_exit(&pcicfg_mutex);
	return (val);
}

uint32_t
pci_mech1_amd_getl(int bus, int device, int function, int reg)
{
	uint32_t val;

	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return (0xffffffffu);
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1_ECS(bus, device, function, reg));
	val = inl(PCI_CONFDATA);
	mutex_exit(&pcicfg_mutex);
	return (val);
}

void
pci_mech1_amd_putb(int bus, int device, int function, int reg, uint8_t val)
{
	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return;
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1_ECS(bus, device, function, reg));
	outb(PCI_CONFDATA | (reg & 0x3), val);
	mutex_exit(&pcicfg_mutex);
}

void
pci_mech1_amd_putw(int bus, int device, int function, int reg, uint16_t val)
{
	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return;
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1_ECS(bus, device, function, reg));
	outw(PCI_CONFDATA | (reg & 0x2), val);
	mutex_exit(&pcicfg_mutex);
}

void
pci_mech1_amd_putl(int bus, int device, int function, int reg, uint32_t val)
{
	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return;
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1_ECS(bus, device, function, reg));
	outl(PCI_CONFDATA, val);
	mutex_exit(&pcicfg_mutex);
}
