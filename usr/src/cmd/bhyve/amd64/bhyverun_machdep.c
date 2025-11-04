/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2025 Oxide Computer Company
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <machine/vmm.h>

#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/vmm.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "bootrom.h"
#include "acpi.h"
#include "atkbdc.h"
#include "config.h"
#include "debug.h"
#include "e820.h"
#include "fwctl.h"
#include "ioapic.h"
#include "inout.h"
#ifndef	__FreeBSD__
#include "kernemu_dev.h"
#endif
#include "mptbl.h"
#include "pci_emul.h"
#include "pci_irq.h"
#include "spinup_ap.h"
#include "pci_lpc.h"
#include "rtc.h"
#include "smbiostbl.h"
#include "xmsr.h"

void
bhyve_usage(int code)
{
	const char *progname = getprogname();

	fprintf(stderr,
#ifdef	__FreeBSD__
		"Usage: %s [-AaCDeHhPSuWwxY]\n"
#else
		"Usage: %s [-aCDdeHhPSuWwxY]\n"
#endif
		"       %2$.*3$s [-c [[cpus=]numcpus][,sockets=n][,cores=n][,threads=n]]\n"
#ifdef	__FreeBSD__
		"       %2$.*3$s [-G port] [-k config_file] [-l lpc] [-m mem] [-o var=value]\n"
		"       %2$.*3$s [-p vcpu:hostcpu] [-r file] [-s pci] [-U uuid] vmname\n"

		"       -A: create ACPI tables\n"
#else
		"       %2$.*3$s [-k <config_file>] [-l <lpc>] [-m mem] [-o <var>=<value>]\n"
		"       %2$.*3$s [-s <pci>] [-U uuid] vmname\n"
#endif
		"       -a: local apic is in xAPIC mode (deprecated)\n"
#ifndef __FreeBSD__
		"       -B type,key=value,...: set SMBIOS information\n"
#endif
		"       -C: include guest memory in core file\n"
		"       -c: number of CPUs and/or topology specification\n"
		"       -D: destroy on power-off\n"
#ifndef __FreeBSD__
		"       -d: suspend cpu at boot\n"
#endif
		"       -e: exit on unhandled I/O access\n"
#ifdef	__FreeBSD__
		"       -G: start a debug server\n"
#endif
		"       -H: vmexit from the guest on HLT\n"
		"       -h: help\n"
		"       -k: key=value flat config file\n"
		"       -K: PS2 keyboard layout\n"
		"       -l: LPC device configuration\n"
		"       -m: memory size\n"
		"       -o: set config 'var' to 'value'\n"
		"       -P: vmexit from the guest on pause\n"
#ifdef	__FreeBSD__
		"       -p: pin 'vcpu' to 'hostcpu'\n"
#endif
		"       -S: guest memory cannot be swapped\n"
		"       -s: <slot,driver,configinfo> PCI slot config\n"
		"       -U: UUID\n"
		"       -u: RTC keeps UTC time\n"
		"       -W: force virtio to use single-vector MSI\n"
		"       -w: ignore unimplemented MSRs\n"
		"       -x: local APIC is in x2APIC mode\n"
		"       -Y: disable MPtable generation\n",
		progname, "", (int)strlen(progname));

	exit(code);
}

void
bhyve_optparse(int argc, char **argv)
{
	const char *optstr;
	int c;

#ifdef	__FreeBSD__
	optstr = "aehuwxACDHIPSWYk:f:o:p:G:c:s:m:l:K:U:";
#else
	/* +d, +B, -p */
	optstr = "adehuwxACDHIPSWYk:f:o:G:c:s:m:l:B:K:U:";
#endif
	while ((c = getopt(argc, argv, optstr)) != -1) {
		switch (c) {
		case 'a':
			set_config_bool("x86.x2apic", false);
			break;
		case 'A':
			set_config_bool("acpi_tables", true);
			break;
		case 'D':
			set_config_bool("destroy_on_poweroff", true);
			break;
#ifndef	__FreeBSD__
		case 'B':
			if (smbios_parse(optarg) != 0) {
				errx(EX_USAGE, "invalid SMBIOS "
				    "configuration '%s'", optarg);
			}
			break;
		case 'd':
			set_config_bool("suspend_at_boot", true);
			break;
#endif
#ifdef	__FreeBSD__
		case 'p':
			if (pincpu_parse(optarg) != 0) {
				errx(EX_USAGE, "invalid vcpu pinning "
				    "configuration '%s'", optarg);
			}
			break;
#endif
		case 'c':
			if (bhyve_topology_parse(optarg) != 0) {
			    errx(EX_USAGE, "invalid cpu topology "
				"'%s'", optarg);
			}
			break;
		case 'C':
			set_config_bool("memory.guest_in_core", true);
			break;
		case 'f':
			if (qemu_fwcfg_parse_cmdline_arg(optarg) != 0) {
			    errx(EX_USAGE, "invalid fwcfg item '%s'", optarg);
			}
			break;
		case 'G':
			bhyve_parse_gdb_options(optarg);
			break;
		case 'k':
			bhyve_parse_simple_config_file(optarg);
			break;
		case 'K':
			set_config_value("keyboard.layout", optarg);
			break;
		case 'l':
			if (strncmp(optarg, "help", strlen(optarg)) == 0) {
				lpc_print_supported_devices();
				exit(0);
			} else if (lpc_device_parse(optarg) != 0) {
				errx(EX_USAGE, "invalid lpc device "
				    "configuration '%s'", optarg);
			}
			break;
		case 's':
			if (strncmp(optarg, "help", strlen(optarg)) == 0) {
				pci_print_supported_devices();
				exit(0);
			} else if (pci_parse_slot(optarg) != 0)
				exit(4);
			else
				break;
		case 'S':
			set_config_bool("memory.wired", true);
			break;
		case 'm':
			set_config_value("memory.size", optarg);
			break;
		case 'o':
			if (!bhyve_parse_config_option(optarg))
				errx(EX_USAGE, "invalid configuration option '%s'", optarg);
			break;
		case 'H':
			set_config_bool("x86.vmexit_on_hlt", true);
			break;
		case 'I':
			/*
			 * The "-I" option was used to add an ioapic to the
			 * virtual machine.
			 *
			 * An ioapic is now provided unconditionally for each
			 * virtual machine and this option is now deprecated.
			 */
			break;
		case 'P':
			set_config_bool("x86.vmexit_on_pause", true);
			break;
		case 'e':
			set_config_bool("x86.strictio", true);
			break;
		case 'u':
			set_config_bool("rtc.use_localtime", false);
			break;
		case 'U':
			set_config_value("uuid", optarg);
			break;
		case 'w':
			set_config_bool("x86.strictmsr", false);
			break;
		case 'W':
			set_config_bool("virtio.msix", false);
			break;
		case 'x':
			set_config_bool("x86.x2apic", true);
			break;
		case 'Y':
			set_config_bool("x86.mptable", false);
			break;
		case 'h':
			bhyve_usage(0);
		default:
			bhyve_usage(1);
		}
	}

	/* Handle backwards compatibility aliases in config options. */
	if (get_config_value("lpc.bootrom") != NULL &&
	    get_config_value("bootrom") == NULL) {
		warnx("lpc.bootrom is deprecated, use '-o bootrom' instead");
		set_config_value("bootrom", get_config_value("lpc.bootrom"));
	}
	if (get_config_value("lpc.bootvars") != NULL &&
	    get_config_value("bootvars") == NULL) {
		warnx("lpc.bootvars is deprecated, use '-o bootvars' instead");
		set_config_value("bootvars", get_config_value("lpc.bootvars"));
	}
}

void
bhyve_init_config(void)
{
	init_config();

	/* Set default values prior to option parsing. */
	set_config_bool("acpi_tables", false);
	set_config_bool("acpi_tables_in_memory", true);
	set_config_value("memory.size", "256M");
	set_config_bool("x86.strictmsr", true);
	set_config_value("lpc.fwcfg", "bhyve");
}

void
bhyve_init_vcpu(struct vcpu *vcpu)
{
	int err, tmp;

#ifdef	__FreeBSD__
	if (get_config_bool_default("x86.vmexit_on_hlt", false)) {
		err = vm_get_capability(vcpu, VM_CAP_HALT_EXIT, &tmp);
		if (err < 0) {
			EPRINTLN("VM exit on HLT not supported");
			exit(4);
		}
		vm_set_capability(vcpu, VM_CAP_HALT_EXIT, 1);
	}
#else
	/*
	 * We insist that vmexit-on-hlt is available on the host CPU, and enable
	 * it by default.  Configuration of that feature is done with both of
	 * those facts in mind.
	 */
	tmp = (int)get_config_bool_default("x86.vmexit_on_hlt", true);
	err = vm_set_capability(vcpu, VM_CAP_HALT_EXIT, tmp);
	if (err < 0) {
		fprintf(stderr, "VM exit on HLT not supported\n");
		exit(4);
	}
#endif /* __FreeBSD__ */

	if (get_config_bool_default("x86.vmexit_on_pause", false)) {
		/*
		 * pause exit support required for this mode
		 */
		err = vm_get_capability(vcpu, VM_CAP_PAUSE_EXIT, &tmp);
		if (err < 0) {
			EPRINTLN("SMP mux requested, no pause support");
			exit(4);
		}
		vm_set_capability(vcpu, VM_CAP_PAUSE_EXIT, 1);
	}

	if (get_config_bool_default("x86.x2apic", false))
		err = vm_set_x2apic_state(vcpu, X2APIC_ENABLED);
	else
		err = vm_set_x2apic_state(vcpu, X2APIC_DISABLED);

	if (err) {
		EPRINTLN("Unable to set x2apic state (%d)", err);
		exit(4);
	}

#ifdef	__FreeBSD__
	vm_set_capability(vcpu, VM_CAP_ENABLE_INVPCID, 1);

	err = vm_set_capability(vcpu, VM_CAP_IPI_EXIT, 1);
	assert(err == 0);
#endif
}

void
bhyve_start_vcpu(struct vcpu *vcpu, bool bsp, bool suspend)
{
	int error;

	if (!bsp) {
#ifndef	__FreeBSD__
		/*
		 * On illumos, all APs are spun up halted and run-state
		 * transitions (INIT, SIPI, etc) are handled in-kernel.
		 */
		spinup_ap(vcpu, 0);
#endif

		bhyve_init_vcpu(vcpu);

#ifdef	__FreeBSD__
		/*
		 * Enable the 'unrestricted guest' mode for APs.
		 *
		 * APs startup in power-on 16-bit mode.
		 */
		error = vm_set_capability(vcpu, VM_CAP_UNRESTRICTED_GUEST, 1);
		assert(error == 0);
#endif
	}

#ifndef	__FreeBSD__
	/*
	 * The value of 'suspend' for the BSP depends on whether the -d
	 * (suspend_at_boot) flag was given to bhyve. Regardless of that
	 * value we always want to set the BSP to VRS_RUN and all others to
	 * VRS_HALT.
	 */
	error = vm_set_run_state(vcpu, bsp ? VRS_RUN : VRS_HALT, 0);
	assert(error == 0);
#endif

	fbsdrun_addcpu(vcpu_id(vcpu), suspend);
}

int
bhyve_init_platform(struct vmctx *ctx, struct vcpu *bsp __unused)
{
	int error;

	error = init_msr();
	if (error != 0)
		return (error);
	init_inout();
#ifdef	__FreeBSD__
	kernemu_dev_init();
#endif
	atkbdc_init(ctx);
	pci_irq_init(ctx);
	ioapic_init(ctx);
	rtc_init(ctx);
	sci_init(ctx);
#ifndef	__FreeBSD__
	pmtmr_init(ctx);
#endif
	error = e820_init(ctx);
	if (error != 0)
		return (error);
	error = bootrom_loadrom(ctx);
	if (error != 0)
		return (error);

#ifndef	__FreeBSD__
	if (get_config_bool_default("e820.debug", false))
		e820_dump_table();
#endif

	return (0);
}

int
bhyve_init_platform_late(struct vmctx *ctx, struct vcpu *bsp __unused)
{
	int error;

	if (get_config_bool_default("x86.mptable", true)) {
		error = mptable_build(ctx, guest_ncpus);
		if (error != 0)
			return (error);
	}
	error = smbios_build(ctx);
	if (error != 0)
		return (error);
	error = e820_finalize();
	if (error != 0)
		return (error);

	if (bootrom_boot() && strcmp(lpc_fwcfg(), "bhyve") == 0)
		fwctl_init();

	if (get_config_bool("acpi_tables")) {
		error = acpi_build(ctx, guest_ncpus);
		assert(error == 0);
	}

	return (0);
}
