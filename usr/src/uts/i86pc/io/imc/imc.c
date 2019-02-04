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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Generic Intel Integrated Memory Controller (IMC) Driver
 *
 * This driver talks to the CPU's IMC to understand the detailed topology of the
 * processor and to determine how to map between physical addresses to the
 * corresponding DIMM. This driver supports the following generations of Intel
 * chips:
 *
 *  - Sandy Bridge
 *  - Ivy Bridge
 *  - Haswell
 *  - Broadwell
 *  - Skylake / Cascade Lake
 *
 * Memory Decoding
 * ---------------
 *
 * For more detailed summaries of the memory decoding process, please refer to
 * the Intel External Design Specifications for the corresponding processor.
 * What follows is a rough overview of how the memory decoding system works.
 *
 * First, we'd like to define the following concepts:
 *
 * SYSTEM ADDRESS
 *
 *	This is a physical address that the operating system normally uses. This
 *	address may refer to DRAM, it may refer to memory mapped PCI
 *	configuration space or device registers, or it may refer to other parts
 *	of the system's memory map, such as the extended advanced programmable
 *	interrupt controller (xAPIC), etc.
 *
 * DIMM
 *
 *	Dual-inline memory module. This refers to a physical stick of volatile
 *	memory that is inserted into a slot on the motherboard.
 *
 * RANK
 *
 *	A potential sub-division of a DIMM. A DIMM's memory capacity is divided
 *	into a number of equal sized ranks. For example, an 8 GiB DIMM, may have
 *	1 8 GiB rank, 2 4 GiB ranks, or 4 2 GiB ranks.
 *
 * RANK ADDRESS
 *
 *	An address that exists in the context of a given rank on a DIMM. All
 *	ranks have overlapping addresses, so the address 0x400 exists on all
 *	ranks on a given DIMM.
 *
 * CHANNEL
 *
 *	Multiple DIMMs may be combined into a single channel. The channel
 *	represents the combined memory of all the DIMMs. A given channel only
 *	ever exists on a socket and is bound to a single memory controller.
 *
 * CHANNEL ADDRESS
 *
 *	This is an address that exists logically on a channel. Each address on a
 *	channel maps to a corresponding DIMM that exists on that channel. The
 *	address space on one channel is independent from that on another. This
 *	means that address 0x1000 can exist on each memory channel in the
 *	system.
 *
 * INTERLEAVE
 *
 *	There are several different cases where interleaving occurs on the
 *	system. For example, addresses may be interleaved across sockets,
 *	memory channels, or DIMM ranks. When addresses are interleaved, then
 *	some number of bits in an address are used to select which target to go
 *	to (usually through a look up table). The effect of interleaving is that
 *	addresses that are next to one another may not all go to the same
 *	device. The following image shows a non-interleaving case.
 *
 *	0x0fff +-----+             +-----+ 0x7ff
 *	       |     |\___________/|     |
 *	       |     |  __________ | (b) |
 *	       |     | /          \|     |
 *	0x0800 |=====|=            +-----+ 0x000       +-----+ 0x7ff
 *	       |     | \______________________________/|     |
 *	       |     | _______________________________ | (a) |
 *	       |     |/                               \|     |
 *	0x0000 +-----+                                 +-----+ 0x000
 *
 *	In this example of non-interleaving, addresses 0x0000 to 0x07ff go to
 *	device (a). While, addresses 0x08000 to 0xfff, go to device (b).
 *	However, each range is divided into the same number of components.
 *
 *	If instead, we were to look at that with interleaving, what we might say
 *	is that rather than splitting the range in half, we might say that if
 *	the address has bit 8 set (0x100), then it goes to (b), otherwise it
 *	goes to (a). This means that addresses 0x000 to 0x0ff, would go to (a).
 *	0x100 to 0x1ff would go to (b). 0x200 to 0x2ff would go back to (a)
 *	again, and then 0x300 to 0x2ff would go back to (b). This would continue
 *	for a while. This would instead look something more like:
 *
 *
 *      0x0fff +-----+       A: 0x7ff +---------+   B: 0x7ff +---------+
 *             | (b) |                | e00-eff |            | f00-fff |
 *      0x0f00 |-----|          0x700 +---------+      0x700 +---------+
 *             | (a) |                | c00-cff |            | d00-dff |
 *      0x0e00 ~~~~~~~          0x600 +---------+      0x600 +---------+
 *               ***                  | a00-aff |            | b00-bff |
 *      0x0400 ~~~~~~~          0x500 +---------+      0x500 +---------+
 *             | (b) |                | 800-8ff |            | 900-9ff |
 *      0x0300 |-----|          0x400 +---------+      0x400 +---------+
 *             | (a) |                | 600-6ff |            | 700-7ff |
 *      0x0200 |-----|          0x300 +---------+      0x300 +---------+
 *             | (b) |                | 400-4ff |            | 500-5ff |
 *      0x0100 |-----|          0x200 +---------+      0x200 +---------+
 *             | (a) |                | 200-2ff |            | 300-3ff |
 *      0x0000 +-----+          0x100 +---------+      0x100 +---------+
 *                                    | 000-0ff |            | 100-1ff |
 *                              0x000 +---------+      0x000 +---------+
 *
 *	In this example we've performed two-way interleaving. The number of ways
 *	that something can interleave varies based on what we're interleaving
 *	between.
 *
 * MEMORY CONTROLLER
 *
 *	A given processor die (see uts/i86pc/os/cpuid.c) contains a number of
 *	memory controllers. Usually 1 or two. Each memory controller supports a
 *	given number of DIMMs, which are divided across multiple channels.
 *
 * TARGET ADDRESS DECODER
 *
 *	The target address decoder (TAD) is responsible for taking a system
 *	address and transforming it into a channel address based on the rules
 *	that are present. Each memory controller has a corresponding TAD. The
 *	TAD is often contained in a device called a 'Home Agent'.
 *
 * SYSTEM ADDRESS DECODER
 *
 *	The system address decoder (SAD) is responsible for taking a system
 *	address and directing it to the right place, whether this be memory or
 *	otherwise. There is a single memory controller per socket (see
 *	uts/i86pc/os/cpuid.c) that is shared between all the cores currently.
 *
 * NODE IDENTIFIER
 *
 *	The node identifier is used to uniquely identify an element in the
 *	various routing topologies on the die (see uts/i86pc/os/cpuid.c for the
 *	definition of 'die'). One can roughly think about this as a unique
 *	identifier for the socket itself. In general, the primary node ID for a
 *	socket should map to the socket APIC ID.
 *
 * Finding Devices
 * ---------------
 *
 * There is a bit of a chicken and egg problem on Intel systems and in the
 * device driver interface. The information that we need in the system is spread
 * out amongst a large number of different PCI devices that the processor
 * exposes. The number of such devices can vary based on the processor
 * generation and the specific SKU in the processor. To deal with this, we break
 * the driver into two different components: a stub driver and the full driver.
 *
 * The stub driver has aliases for all known PCI devices that we might attach to
 * in a given generation on the system. This driver is called 'imcstub'. When a
 * stub attaches, it just registers itself with the main driver, upon which it
 * has a module dependency.
 *
 * The main driver, 'imc', is a pseudo-device driver. When it first attaches, it
 * kicks off a scan of the device tree which takes place in a task queue. Once
 * there, it determines the number of devices that it expects to exist by
 * walking the tree and comparing it against the generation-specific table.
 *
 * If all devices are found, we'll go ahead and read through all the devices and
 * build a map of all the information we need to understand the topology of the
 * system and to be able to decode addresses. We do this here, because we can be
 * asked to perform decoding in dangerous contexts (after taking an MCE, panic,
 * etc) where we don't want to have to rely on the broader kernel functioning at
 * this point in time.
 *
 * Once our topology is built, we'll create minor nodes which are used by the
 * fault management architecture to query for information and register our
 * decoding functionality with the kernel.
 *
 * PCI Numbering
 * -------------
 *
 * For each device that we care about, Intel defines the device and function
 * that we can expect to find the information and PCI configuration space
 * registers that we care about at. However, the PCI bus is not well defined.
 * Devices that are on the same socket use the same set of bus numbers; however,
 * some sockets have multiple device numbers that they'll use to represent
 * different classes. These bus numbers are programmed by systems firmware as
 * part of powering on the system. This means, that we need the ability to
 * map together these disparate ranges ourselves.
 *
 * There is a device called a utility box (UBOX), which exists per-socket and
 * maps the different sockets together. We use this to determine which devices
 * correspond to which sockets.
 *
 * Mapping Sockets
 * ---------------
 *
 * Another wrinkle is that the way that the OS sees the numbering of the CPUs is
 * generally based on the APIC ID (see uts/i86pc/os/cpuid.c for more
 * information). However, to map to the corresponding socket, we need to look at
 * the socket's node ID. The order of PCI buses in the system is not required to
 * have any relation to the socket ID. Therefore, we have to have yet another
 * indirection table in the imc_t.
 *
 * Exposing Data
 * -------------
 *
 * We expose topology data to FMA using the OS-private memory controller
 * interfaces. By creating minor nodes of the type, 'ddi_mem_ctrl', there are a
 * number of specific interfaces that we can then implement. The ioctl API asks
 * us for a snapshot of data, which basically has us go through and send an
 * nvlist_t to userland. This nvlist_t is constructed as part of the scan
 * process. This nvlist uses the version 1 format, which more explicitly encodes
 * the topology in a series of nested nvlists.
 *
 * In addition, the tool /usr/lib/fm/fmd/mcdecode can be used to query the
 * decoder and ask it to perform decoding.
 *
 * Decoding Addresses
 * ------------------
 *
 * The decoding logic can be found in common/imc/imc_decode.c. This file is
 * shared between the kernel and userland to allow for easier testing and
 * additional flexibility in operation. The decoding process happens in a few
 * different phases.
 *
 * The first phase, is to determine which memory controller on which socket is
 * responsible for this data. To determine this, we use the system address
 * decoder and walk the rules, looking for the correct target. There are various
 * manipulations to the address that exist which are used to determine which
 * index we use. The way that we interpret the output of the rule varies
 * somewhat based on the generation. Sandy Bridge just has a node ID which
 * points us to the socket with its single IMC. On Ivy Bridge through Broadwell,
 * the memory controller to use is also encoded in part of the node ID. Finally,
 * on Skylake, the SAD tells us which socket to look at. The socket in question
 * then has a routing table which tells us which channel on which memory
 * controller that is local to that socket.
 *
 * Once we have the target memory controller, we walk the list of target address
 * decoder rules. These rules can help tell us which channel we care about
 * (which is required on Sandy Bridge through Broadwell) and then describe some
 * amount of the interleaving rules which are used to turn the system address
 * into a channel address.
 *
 * Once we know the channel and the channel address, we walk the rank interleave
 * rules which help us determine which DIMM and the corresponding rank on it
 * that the corresponding channel address is on. It also has logic that we need
 * to use to determine how to transform a channel address into an address on
 * that specific rank. Once we have that, then the initial decoding is done.
 *
 * The logic in imc_decode.c is abstracted away from the broader kernel CMI
 * logic.  This is on purpose and allows us not only an easier time unit testing
 * the logic, but also allows us to express more high fidelity errors that are
 * translated into a much smaller subset. This logic is exercised in the
 * 'imc_test' program which is built in 'test/os-tests/tests/imc'.
 *
 * Limitations
 * -----------
 *
 * Currently, this driver has the following limitations:
 *
 *  o It doesn't decode the row and column addresses.
 *  o It doesn't encode from a DIMM address to a system address.
 *  o It doesn't properly support lockstep and mirroring modes on Sandy Bridge -
 *    Broadwell platforms.
 *  o It doesn't support virtual lockstep and adaptive mirroring on Purley
 *    platforms.
 *  o It doesn't properly handle Intel Optane (3D-X Point) NVDIMMs.
 *  o It doesn't know how to decode three way channel interleaving.
 *
 * None of these are intrinsic problems to the driver, it's mostly a matter of
 * having proper documentation and testing.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>
#include <sys/avl.h>
#include <sys/stat.h>
#include <sys/policy.h>

#include <sys/cpu_module.h>
#include <sys/mc.h>
#include <sys/mc_intel.h>

#include "imc.h"

/*
 * These tables contain generational data that varies between processor
 * generation such as the maximum number of sockets, memory controllers, and the
 * offsets of the various registers.
 */

static const imc_gen_data_t imc_gen_data_snb = {
	.igd_max_sockets = 4,
	.igd_max_imcs = 2,
	.igd_max_channels = 4,
	.igd_max_dimms = 3,
	.igd_max_ranks = IMC_MTR_DDR_RANKS_MAX,
	.igd_mtr_offsets = { IMC_REG_MC_MTR0, IMC_REG_MC_MTR1,
	    IMC_REG_MC_MTR2 },
	.igd_mcmtr_offset = 0x7c,
	.igd_tolm_offset = 0x80,
	.igd_tohm_low_offset = 0x84,
	.igd_sad_dram_offset = 0x80,
	.igd_sad_ndram_rules = 10,
	.igd_sad_nodeid_offset = 0x40,
	.igd_tad_nrules = 12,
	.igd_tad_rule_offset = 0x40,
	.igd_tad_chan_offset = 0x90,
	.igd_tad_sysdef = 0x80,
	.igd_tad_sysdef2 = 0x84,
	.igd_mc_mirror = 0xac,
	.igd_rir_nways = 5,
	.igd_rir_way_offset = 0x108,
	.igd_rir_nileaves = 8,
	.igd_rir_ileave_offset = 0x120,
	.igd_ubox_cpubusno_offset = 0xd0,
};

static const imc_gen_data_t imc_gen_data_ivb = {
	.igd_max_sockets = 4,
	.igd_max_imcs = 2,
	.igd_max_channels = 4,
	.igd_max_dimms = 3,
	.igd_max_ranks = IMC_MTR_DDR_RANKS_MAX,
	.igd_mtr_offsets = { IMC_REG_MC_MTR0, IMC_REG_MC_MTR1,
	    IMC_REG_MC_MTR2 },
	.igd_mcmtr_offset = 0x7c,
	.igd_tolm_offset = 0x80,
	.igd_tohm_low_offset = 0x84,
	.igd_sad_dram_offset = 0x60,
	.igd_sad_ndram_rules = 20,
	.igd_sad_nodeid_offset = 0x40,
	.igd_tad_nrules = 12,
	.igd_tad_rule_offset = 0x40,
	.igd_tad_chan_offset = 0x90,
	.igd_tad_sysdef = 0x80,
	.igd_tad_sysdef2 = 0x84,
	.igd_mc_mirror = 0xac,
	.igd_rir_nways = 5,
	.igd_rir_way_offset = 0x108,
	.igd_rir_nileaves = 8,
	.igd_rir_ileave_offset = 0x120,
	.igd_ubox_cpubusno_offset = 0xd0,
};

static const imc_gen_data_t imc_gen_data_has_brd = {
	.igd_max_sockets = 4,
	.igd_max_imcs = 2,
	.igd_max_channels = 4,
	.igd_max_dimms = 3,
	.igd_max_ranks = IMC_MTR_DDR_RANKS_MAX_HAS_SKX,
	.igd_mtr_offsets = { IMC_REG_MC_MTR0, IMC_REG_MC_MTR1,
	    IMC_REG_MC_MTR2 },
	.igd_mcmtr_offset = 0x7c,
	.igd_tolm_offset = 0xd0,
	.igd_tohm_low_offset = 0xd4,
	.igd_tohm_hi_offset = 0xd8,
	.igd_sad_dram_offset = 0x60,
	.igd_sad_ndram_rules = 20,
	.igd_sad_nodeid_offset = 0x40,
	.igd_tad_nrules = 12,
	.igd_tad_rule_offset = 0x40,
	.igd_tad_chan_offset = 0x90,
	.igd_tad_sysdef = 0x80,
	.igd_tad_sysdef2 = 0x84,
	.igd_mc_mirror = 0xac,
	.igd_rir_nways = 5,
	.igd_rir_way_offset = 0x108,
	.igd_rir_nileaves = 8,
	.igd_rir_ileave_offset = 0x120,
	.igd_ubox_cpubusno_offset = 0xd0,
};

static const imc_gen_data_t imc_gen_data_skx = {
	.igd_max_sockets = 8,
	.igd_max_imcs = 2,
	.igd_max_channels = 3,
	.igd_max_dimms = 2,
	.igd_max_ranks = IMC_MTR_DDR_RANKS_MAX,
	.igd_mtr_offsets = { IMC_REG_MC_MTR0, IMC_REG_MC_MTR1 },
	.igd_mcmtr_offset = 0x87c,
	.igd_topo_offset = 0x88,
	.igd_tolm_offset = 0xd0,
	.igd_tohm_low_offset = 0xd4,
	.igd_tohm_hi_offset = 0xd8,
	.igd_sad_dram_offset = 0x60,
	.igd_sad_ndram_rules = 24,
	.igd_sad_nodeid_offset = 0xc0,
	.igd_tad_nrules = 8,
	.igd_tad_rule_offset = 0x850,
	.igd_tad_chan_offset = 0x90,
	.igd_rir_nways = 4,
	.igd_rir_way_offset = 0x108,
	.igd_rir_nileaves = 4,
	.igd_rir_ileave_offset = 0x120,
	.igd_ubox_cpubusno_offset = 0xcc,
};

/*
 * This table contains all of the devices that we're looking for from a stub
 * perspective. These are organized by generation. Different generations behave
 * in slightly different ways. For example, Sandy Bridge through Broadwell use
 * unique PCI IDs for each PCI device/function combination that appears. Whereas
 * Skylake based systems use the same PCI ID; however, different device/function
 * values indicate that the IDs are used for different purposes.
 */
/* BEGIN CSTYLED */
static const imc_stub_table_t imc_stub_table[] = {
	/* Sandy Bridge */
	{ IMC_GEN_SANDY, IMC_TYPE_MC0_MAIN0, 0x3ca8, 15, 0, "IMC 0 Main 0" },
	{ IMC_GEN_SANDY, IMC_TYPE_MC0_MAIN1, 0x3c71, 15, 1, "IMC 0 Main 0" },
	{ IMC_GEN_SANDY, IMC_TYPE_MC0_CHANNEL0, 0x3caa, 15, 2, "IMC 0 Channel 0 Info" },
	{ IMC_GEN_SANDY, IMC_TYPE_MC0_CHANNEL1, 0x3cab, 15, 3, "IMC 0 Channel 1 Info" },
	{ IMC_GEN_SANDY, IMC_TYPE_MC0_CHANNEL2, 0x3cac, 15, 4, "IMC 0 Channel 2 Info" },
	{ IMC_GEN_SANDY, IMC_TYPE_MC0_CHANNEL3, 0x3cad, 15, 5, "IMC 0 Channel 3 Info" },
	{ IMC_GEN_SANDY, IMC_TYPE_SAD_DRAM, 0x3cf4, 12, 6, "SAD DRAM Rules" },
	{ IMC_GEN_SANDY, IMC_TYPE_SAD_MMIO, 0x3cf5, 13, 6, "SAD MMIO Rules" },
	{ IMC_GEN_SANDY, IMC_TYPE_SAD_MISC, 0x3cf6, 12, 7, "SAD Memory Map" },
	{ IMC_GEN_SANDY, IMC_TYPE_UBOX, 0x3ce0, 11, 0, "UBox" },
	{ IMC_GEN_SANDY, IMC_TYPE_UBOX_CPUBUSNO, 0x3ce3, 11, 3, "UBox Scratch" },
	{ IMC_GEN_SANDY, IMC_TYPE_HA0, 0x3ca0, 14, 0, "Home Agent" },
	/* Ivy Bridge */
	{ IMC_GEN_IVY, IMC_TYPE_MC0_MAIN0, 0x0ea8, 15, 0, "IMC 0 Main 0" },
	{ IMC_GEN_IVY, IMC_TYPE_MC0_MAIN1, 0x0e71, 15, 1, "IMC 0 Main 1" },
	{ IMC_GEN_IVY, IMC_TYPE_MC0_CHANNEL0, 0x0eaa, 15, 2, "IMC 0 Channel 0 Info" },
	{ IMC_GEN_IVY, IMC_TYPE_MC0_CHANNEL1, 0x0eab, 15, 3, "IMC 0 Channel 1 Info" },
	{ IMC_GEN_IVY, IMC_TYPE_MC0_CHANNEL2, 0x0eac, 15, 4, "IMC 0 Channel 2 Info" },
	{ IMC_GEN_IVY, IMC_TYPE_MC0_CHANNEL3, 0x0ead, 15, 5, "IMC 0 Channel 3 Info" },
	{ IMC_GEN_IVY, IMC_TYPE_MC1_MAIN0, 0x0e68, 29, 0, "IMC 1 Main 0" },
	{ IMC_GEN_IVY, IMC_TYPE_MC1_MAIN1, 0x0e79, 29, 1, "IMC 1 Main 1" },
	{ IMC_GEN_IVY, IMC_TYPE_MC1_CHANNEL0, 0x0e6a, 15, 2, "IMC 1 Channel 0 Info" },
	{ IMC_GEN_IVY, IMC_TYPE_MC1_CHANNEL1, 0x0e6b, 15, 3, "IMC 1 Channel 1 Info" },
	{ IMC_GEN_IVY, IMC_TYPE_MC1_CHANNEL2, 0x0e6c, 15, 4, "IMC 1 Channel 2 Info" },
	{ IMC_GEN_IVY, IMC_TYPE_MC1_CHANNEL3, 0x0e6d, 15, 5, "IMC 1 Channel 3 Info" },
	{ IMC_GEN_IVY, IMC_TYPE_SAD_DRAM, 0x0ec8, 22, 0, "SAD DRAM Rules" },
	{ IMC_GEN_IVY, IMC_TYPE_SAD_MMIO, 0x0ec9, 22, 1, "SAD MMIO Rules" },
	{ IMC_GEN_IVY, IMC_TYPE_SAD_MISC, 0x0eca, 22, 2, "SAD Memory Map" },
	{ IMC_GEN_IVY, IMC_TYPE_UBOX, 0x0e1e, 11, 0, "UBox" },
	{ IMC_GEN_IVY, IMC_TYPE_UBOX_CPUBUSNO, 0x0e1f, 11, 3, "UBox Scratch" },
	{ IMC_GEN_IVY, IMC_TYPE_HA0, 0x0ea0, 14, 0, "Home Agent 0" },
	{ IMC_GEN_IVY, IMC_TYPE_HA1, 0x0e60, 28, 0, "Home Agent 1" },
	/* Haswell */
	{ IMC_GEN_HASWELL, IMC_TYPE_MC0_MAIN0, 0x2fa8, 19, 0, "IMC 0 Main 0" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC0_MAIN1, 0x2f71, 19, 1, "IMC 0 Main 1" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC0_CHANNEL0, 0x2faa, 19, 2, "IMC 0 Channel 0 Info" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC0_CHANNEL1, 0x2fab, 19, 3, "IMC 0 Channel 1 Info" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC0_CHANNEL2, 0x2fac, 19, 4, "IMC 0 Channel 2 Info" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC0_CHANNEL3, 0x2fad, 19, 5, "IMC 0 Channel 3 Info" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC1_MAIN0, 0x2f68, 22, 0, "IMC 1 Main 0" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC1_MAIN1, 0x2f79, 22, 1, "IMC 1 Main 1" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC1_CHANNEL0, 0x2f6a, 22, 2, "IMC 1 Channel 0 Info" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC1_CHANNEL1, 0x2f6b, 22, 3, "IMC 1 Channel 1 Info" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC1_CHANNEL2, 0x2f6c, 22, 4, "IMC 1 Channel 2 Info" },
	{ IMC_GEN_HASWELL, IMC_TYPE_MC1_CHANNEL3, 0x2f6d, 22, 5, "IMC 1 Channel 3 Info" },
	{ IMC_GEN_HASWELL, IMC_TYPE_SAD_DRAM, 0x2ffc, 15, 4, "SAD DRAM Rules" },
	{ IMC_GEN_HASWELL, IMC_TYPE_SAD_MMIO, 0x2ffd, 15, 5, "SAD MMIO Rules" },
	{ IMC_GEN_HASWELL, IMC_TYPE_VTD_MISC, 0x2f28, 5, 0, "Misc. Vritualization" },
	{ IMC_GEN_HASWELL, IMC_TYPE_UBOX, 0x2f1e, 16, 5, "UBox" },
	{ IMC_GEN_HASWELL, IMC_TYPE_UBOX_CPUBUSNO, 0x2f1f, 16, 7, "UBox Scratch" },
	{ IMC_GEN_HASWELL, IMC_TYPE_HA0, 0x2fa0, 18, 0, "Home Agent 0" },
	{ IMC_GEN_HASWELL, IMC_TYPE_HA1, 0x2f60, 18, 4, "Home Agent 1" },
	/* Broadwell Devices */
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC0_MAIN0, 0x6fa8, 19, 0, "IMC 0 Main 0" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC0_MAIN1, 0x6f71, 19, 1, "IMC 0 Main 1" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC0_CHANNEL0, 0x6faa, 19, 2, "IMC 0 Channel 0 Info" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC0_CHANNEL1, 0x6fab, 19, 3, "IMC 0 Channel 1 Info" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC0_CHANNEL2, 0x6fac, 19, 4, "IMC 0 Channel 2 Info" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC0_CHANNEL3, 0x6fad, 19, 5, "IMC 0 Channel 3 Info" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC1_MAIN0, 0x6f68, 22, 0, "IMC 1 Main 0" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC1_MAIN1, 0x6f79, 22, 1, "IMC 1 Main 1" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC1_CHANNEL0, 0x6f6a, 22, 2, "IMC 1 Channel 0 Info" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC1_CHANNEL1, 0x6f6b, 22, 3, "IMC 1 Channel 1 Info" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC1_CHANNEL2, 0x6f6c, 22, 4, "IMC 1 Channel 2 Info" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_MC1_CHANNEL3, 0x6f6d, 22, 5, "IMC 1 Channel 3 Info" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_SAD_DRAM, 0x6ffc, 15, 4, "SAD DRAM Rules" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_SAD_MMIO, 0x6ffd, 15, 5, "SAD MMIO Rules" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_VTD_MISC, 0x6f28, 5, 0, "Misc. Vritualization" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_UBOX, 0x6f1e, 16, 5, "UBox" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_UBOX_CPUBUSNO, 0x6f1f, 16, 7, "UBox Scratch" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_HA0, 0x6fa0, 18, 0, "Home Agent 0" },
	{ IMC_GEN_BROADWELL, IMC_TYPE_HA1, 0x6f60, 18, 4, "Home Agent 1" },
	/* Skylake and Cascade Lake Devices */
	{ IMC_GEN_SKYLAKE, IMC_TYPE_MC0_M2M, 0x2066, 8, 0, "IMC 0 M2M" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_MC1_M2M, 0x2066, 9, 0, "IMC 0 M2M" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_MC0_MAIN0, 0x2040, 10, 0, "IMC 0 Main / Channel 0" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_MC1_MAIN0, 0x2040, 12, 0, "IMC 0 Main / Channel 0" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_MC0_CHANNEL1, 0x2044, 10, 4, "IMC 0 Channel 1" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_MC0_CHANNEL2, 0x2048, 11, 0, "IMC 0 Channel 2" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_MC1_CHANNEL1, 0x2044, 12, 4, "IMC 1 Channel 1" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_MC1_CHANNEL2, 0x2048, 13, 0, "IMC 1 Channel 2" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_DRAM, 0x2054, 29, 0, "SAD DRAM Rules" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MMIO, 0x2055, 29, 1, "SAD MMIO Rules" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_VTD_MISC, 0x2024, 5, 0, "Misc. Virtualization" },

	/*
	 * There is one SAD MC Route type device per core! Because of this a
	 * wide array of device and functions are allocated. For now, we list
	 * all 28 of them out.
	 */
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 14, 0, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 14, 1, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 14, 2, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 14, 3, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 14, 4, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 14, 5, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 14, 6, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 14, 7, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 15, 0, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 15, 1, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 15, 2, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 15, 3, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 15, 4, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 15, 5, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 15, 6, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 15, 7, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 16, 0, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 16, 1, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 16, 2, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 16, 3, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 16, 4, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 16, 5, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 16, 6, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 16, 7, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 17, 0, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 17, 1, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 17, 2, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 17, 3, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 17, 4, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 17, 5, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 17, 6, "Per-Core SAD" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_SAD_MCROUTE, 0x208e, 17, 7, "Per-Core SAD" },

	{ IMC_GEN_SKYLAKE, IMC_TYPE_UBOX, 0x2014, 8, 0, "UBox" },
	{ IMC_GEN_SKYLAKE, IMC_TYPE_UBOX_CPUBUSNO, 0x2016, 8, 2, "DECS" },
};
/* END CSTYLED */

#define	IMC_PCI_VENDOR_INTC	0x8086

/*
 * Our IMC data is global and statically set up during a combination of
 * _init(9E) and attach(9E). While we have a module dependency between the PCI
 * stub driver, imcstub, and this pseudo-driver, imc, the dependencies don't
 * guarantee that the imc driver has finished attaching. As such we make sure
 * that it can operate without it being attached in any way.
 */
static imc_t *imc_data = NULL;

/*
 * By default we should not allow the stubs to detach as we don't have a good
 * way of forcing them to attach again. This is provided in case someone does
 * want to allow the driver to unload.
 */
int imc_allow_detach = 0;

static void
imc_set_gen_data(imc_t *imc)
{
	switch (imc->imc_gen) {
	case IMC_GEN_SANDY:
		imc->imc_gen_data = &imc_gen_data_snb;
		break;
	case IMC_GEN_IVY:
		imc->imc_gen_data = &imc_gen_data_ivb;
		break;
	case IMC_GEN_HASWELL:
	case IMC_GEN_BROADWELL:
		imc->imc_gen_data = &imc_gen_data_has_brd;
		break;
	case IMC_GEN_SKYLAKE:
		imc->imc_gen_data = &imc_gen_data_skx;
		break;
	default:
		dev_err(imc->imc_dip, CE_PANIC, "imc driver programmer error: "
		    "set to unknown generation: %u", imc->imc_gen);
	}
}

/*
 * If our device (dev_info_t) does not have a non-zero unit address, then
 * devfsadmd will not pay attention to us at all. Therefore we need to set the
 * unit address below, before we create minor nodes.
 *
 * The rest of the system expects us to have one minor node per socket. The
 * minor node ID should be the ID of the socket.
 */
static boolean_t
imc_create_minors(imc_t *imc)
{
	uint_t i;

	ddi_set_name_addr(imc->imc_dip, "1");
	for (i = 0; i < imc->imc_nsockets; i++) {
		char buf[MAXNAMELEN];

		if (snprintf(buf, sizeof (buf), "mc-imc-%u", i) >=
		    sizeof (buf)) {
			goto fail;
		}

		if (ddi_create_minor_node(imc->imc_dip, buf, S_IFCHR, i,
		    "ddi_mem_ctrl", 0) != DDI_SUCCESS) {
			dev_err(imc->imc_dip, CE_WARN, "failed to create "
			    "minor node %u: %s", i, buf);
			goto fail;
		}
	}
	return (B_TRUE);

fail:
	ddi_remove_minor_node(imc->imc_dip, NULL);
	return (B_FALSE);
}

/*
 * Check the current MC route value for this SAD. On Skylake systems there is
 * one per core. Every core should agree. If not, we will not trust the SAD
 * MCROUTE values and this will cause system address decoding to fail on
 * skylake.
 */
static void
imc_mcroute_check(imc_t *imc, imc_sad_t *sad, imc_stub_t *stub)
{
	uint32_t val;

	val = pci_config_get32(stub->istub_cfgspace,
	    IMC_REG_SKX_SAD_MC_ROUTE_TABLE);
	if (val == PCI_EINVAL32) {
		sad->isad_valid |= IMC_SAD_V_BAD_PCI_READ;
		return;
	}

	if ((sad->isad_flags & IMC_SAD_MCROUTE_VALID) == 0 && val != 0) {
		sad->isad_flags |= IMC_SAD_MCROUTE_VALID;
		sad->isad_mcroute.ismc_raw_mcroute = val;
		return;
	}

	/*
	 * Occasionally we see MC ROUTE table entries with a value of zero.
	 * We should ignore those for now.
	 */
	if (val != sad->isad_mcroute.ismc_raw_mcroute && val != 0) {
		dev_err(imc->imc_dip, CE_WARN, "SAD MC_ROUTE_TABLE mismatch "
		    "with socket. SAD has val 0x%x, system has %x\n",
		    val, sad->isad_mcroute.ismc_raw_mcroute);
		sad->isad_valid |= IMC_SAD_V_BAD_MCROUTE;
	}
}

/*
 * On Skylake, many of the devices that we care about are on separate PCI Buses.
 * These can be mapped together by the DECS register. However, we need to know
 * how to map different buses together so that we can more usefully associate
 * information. The set of buses is all present in the DECS register. We'll
 * effectively assign sockets to buses. This is also still something that comes
 * up on pre-Skylake systems as well.
 */
static boolean_t
imc_map_buses(imc_t *imc)
{
	imc_stub_t *stub;
	uint_t nsock;

	/*
	 * Find the UBOX_DECS registers so we can establish socket mappings. On
	 * Skylake, there are three different sets of buses that we need to
	 * cover all of our devices, while there are only two before that.
	 */
	for (nsock = 0, stub = avl_first(&imc->imc_stubs); stub != NULL;
	    stub = AVL_NEXT(&imc->imc_stubs, stub)) {
		uint32_t busno;

		if (stub->istub_table->imcs_type != IMC_TYPE_UBOX_CPUBUSNO) {
			continue;
		}

		busno = pci_config_get32(stub->istub_cfgspace,
		    imc->imc_gen_data->igd_ubox_cpubusno_offset);
		if (busno == PCI_EINVAL32) {
			dev_err(imc->imc_dip, CE_WARN, "failed to read "
			    "UBOX_DECS CPUBUSNO0: invalid PCI read");
			return (B_FALSE);
		}

		if (imc->imc_gen >= IMC_GEN_SKYLAKE) {
			imc->imc_sockets[nsock].isock_nbus = 3;
			imc->imc_sockets[nsock].isock_bus[0] =
			    IMC_UBOX_CPUBUSNO_0(busno);
			imc->imc_sockets[nsock].isock_bus[1] =
			    IMC_UBOX_CPUBUSNO_1(busno);
			imc->imc_sockets[nsock].isock_bus[2] =
			    IMC_UBOX_CPUBUSNO_2(busno);
		} else {
			imc->imc_sockets[nsock].isock_bus[0] =
			    IMC_UBOX_CPUBUSNO_0(busno);
			imc->imc_sockets[nsock].isock_bus[1] =
			    IMC_UBOX_CPUBUSNO_1(busno);
			imc->imc_sockets[nsock].isock_nbus = 2;
		}
		nsock++;
	}
	imc->imc_nsockets = nsock;

	return (B_TRUE);
}

/*
 * For a given stub that we've found, map it to its corresponding socket based
 * on the PCI bus that it has.
 */
static imc_socket_t *
imc_map_find_socket(imc_t *imc, imc_stub_t *stub)
{
	uint_t i;

	for (i = 0; i < imc->imc_nsockets; i++) {
		uint_t bus;

		for (bus = 0; bus < imc->imc_sockets[i].isock_nbus; bus++) {
			if (imc->imc_sockets[i].isock_bus[bus] ==
			    stub->istub_bus) {
				return (&imc->imc_sockets[i]);
			}
		}
	}

	return (NULL);
}

static boolean_t
imc_map_stubs(imc_t *imc)
{
	imc_stub_t *stub;

	if (!imc_map_buses(imc)) {
		return (B_FALSE);
	}

	stub = avl_first(&imc->imc_stubs);
	for (stub = avl_first(&imc->imc_stubs); stub != NULL;
	    stub = AVL_NEXT(&imc->imc_stubs, stub)) {
		imc_socket_t *sock = imc_map_find_socket(imc, stub);

		if (sock == NULL) {
			dev_err(imc->imc_dip, CE_WARN, "found stub type %u "
			    "PCI%x,%x with bdf %u/%u/%u that does not match a "
			    "known PCI bus for any of %u sockets",
			    stub->istub_table->imcs_type, stub->istub_vid,
			    stub->istub_did, stub->istub_bus, stub->istub_dev,
			    stub->istub_func, imc->imc_nsockets);
			continue;
		}

		/*
		 * We don't have to worry about duplicates here. We check to
		 * make sure that we have unique bdfs here.
		 */
		switch (stub->istub_table->imcs_type) {
		case IMC_TYPE_MC0_M2M:
			sock->isock_imcs[0].icn_m2m = stub;
			break;
		case IMC_TYPE_MC1_M2M:
			sock->isock_imcs[1].icn_m2m = stub;
			break;
		case IMC_TYPE_MC0_MAIN0:
			sock->isock_nimc++;
			sock->isock_imcs[0].icn_main0 = stub;

			/*
			 * On Skylake, the MAIN0 does double duty as channel
			 * zero and as the TAD.
			 */
			if (imc->imc_gen >= IMC_GEN_SKYLAKE) {
				sock->isock_imcs[0].icn_nchannels++;
				sock->isock_imcs[0].icn_channels[0].ich_desc =
				    stub;
				sock->isock_tad[0].itad_stub = stub;
				sock->isock_ntad++;
			}
			break;
		case IMC_TYPE_MC0_MAIN1:
			sock->isock_imcs[0].icn_main1 = stub;
			break;
		case IMC_TYPE_MC1_MAIN0:
			sock->isock_nimc++;
			sock->isock_imcs[1].icn_main0 = stub;

			/*
			 * On Skylake, the MAIN0 does double duty as channel
			 * zero and as the TAD.
			 */
			if (imc->imc_gen >= IMC_GEN_SKYLAKE) {
				sock->isock_imcs[1].icn_nchannels++;
				sock->isock_imcs[1].icn_channels[0].ich_desc =
				    stub;
				sock->isock_tad[1].itad_stub = stub;
				sock->isock_ntad++;
			}
			break;
		case IMC_TYPE_MC1_MAIN1:
			sock->isock_imcs[1].icn_main1 = stub;
			break;
		case IMC_TYPE_MC0_CHANNEL0:
			sock->isock_imcs[0].icn_nchannels++;
			sock->isock_imcs[0].icn_channels[0].ich_desc = stub;
			break;
		case IMC_TYPE_MC0_CHANNEL1:
			sock->isock_imcs[0].icn_nchannels++;
			sock->isock_imcs[0].icn_channels[1].ich_desc = stub;
			break;
		case IMC_TYPE_MC0_CHANNEL2:
			sock->isock_imcs[0].icn_nchannels++;
			sock->isock_imcs[0].icn_channels[2].ich_desc = stub;
			break;
		case IMC_TYPE_MC0_CHANNEL3:
			sock->isock_imcs[0].icn_nchannels++;
			sock->isock_imcs[0].icn_channels[3].ich_desc = stub;
			break;
		case IMC_TYPE_MC1_CHANNEL0:
			sock->isock_imcs[1].icn_nchannels++;
			sock->isock_imcs[1].icn_channels[0].ich_desc = stub;
			break;
		case IMC_TYPE_MC1_CHANNEL1:
			sock->isock_imcs[1].icn_nchannels++;
			sock->isock_imcs[1].icn_channels[1].ich_desc = stub;
			break;
		case IMC_TYPE_MC1_CHANNEL2:
			sock->isock_imcs[1].icn_nchannels++;
			sock->isock_imcs[1].icn_channels[2].ich_desc = stub;
			break;
		case IMC_TYPE_MC1_CHANNEL3:
			sock->isock_imcs[1].icn_nchannels++;
			sock->isock_imcs[1].icn_channels[3].ich_desc = stub;
			break;
		case IMC_TYPE_SAD_DRAM:
			sock->isock_sad.isad_dram = stub;
			break;
		case IMC_TYPE_SAD_MMIO:
			sock->isock_sad.isad_mmio = stub;
			break;
		case IMC_TYPE_SAD_MISC:
			sock->isock_sad.isad_tolh = stub;
			break;
		case IMC_TYPE_VTD_MISC:
			/*
			 * Some systems have multiple VT-D Misc. entry points
			 * in the system. In this case, only use the first one
			 * we find.
			 */
			if (imc->imc_gvtd_misc == NULL) {
				imc->imc_gvtd_misc = stub;
			}
			break;
		case IMC_TYPE_SAD_MCROUTE:
			ASSERT3U(imc->imc_gen, >=, IMC_GEN_SKYLAKE);
			imc_mcroute_check(imc, &sock->isock_sad, stub);
			break;
		case IMC_TYPE_UBOX:
			sock->isock_ubox = stub;
			break;
		case IMC_TYPE_HA0:
			sock->isock_ntad++;
			sock->isock_tad[0].itad_stub = stub;
			break;
		case IMC_TYPE_HA1:
			sock->isock_ntad++;
			sock->isock_tad[1].itad_stub = stub;
			break;
		case IMC_TYPE_UBOX_CPUBUSNO:
			sock->isock_cpubusno = stub;
			break;
		default:
			/*
			 * Attempt to still attach if we can.
			 */
			dev_err(imc->imc_dip, CE_WARN, "Encountered unknown "
			    "IMC type (%u) on PCI %x,%x",
			    stub->istub_table->imcs_type,
			    stub->istub_vid, stub->istub_did);
			break;
		}
	}

	return (B_TRUE);
}

/*
 * Go through and fix up various aspects of the stubs mappings on systems. The
 * following are a list of what we need to fix up:
 *
 *  1. On Haswell and newer systems, there is only one global VT-d device. We
 *     need to go back and map that to all of the per-socket imc_sad_t entries.
 */
static void
imc_fixup_stubs(imc_t *imc)
{
	if (imc->imc_gen >= IMC_GEN_HASWELL) {
		uint_t i;

		for (i = 0; i < imc->imc_nsockets; i++) {
			ASSERT3P(imc->imc_sockets[i].isock_sad.isad_tolh,
			    ==, NULL);
			imc->imc_sockets[i].isock_sad.isad_tolh =
			    imc->imc_gvtd_misc;
		}
	}
}

/*
 * Attempt to map all of the discovered sockets to the corresponding APIC based
 * socket. We do these mappings by getting the node id of the socket and
 * adjusting it to make sure that no home agent is present in it. We use the
 * UBOX to avoid any home agent related bits that are present in other
 * registers.
 */
static void
imc_map_sockets(imc_t *imc)
{
	uint_t i;

	for (i = 0; i < imc->imc_nsockets; i++) {
		uint32_t nodeid;
		ddi_acc_handle_t h;

		h = imc->imc_sockets[i].isock_ubox->istub_cfgspace;
		nodeid = pci_config_get32(h,
		    imc->imc_gen_data->igd_sad_nodeid_offset);
		if (nodeid == PCI_EINVAL32) {
			imc->imc_sockets[i].isock_valid |=
			    IMC_SOCKET_V_BAD_NODEID;
			continue;
		}

		imc->imc_sockets[i].isock_nodeid = IMC_NODEID_UBOX_MASK(nodeid);
		imc->imc_spointers[nodeid] = &imc->imc_sockets[i];
	}
}

/*
 * Decode the MTR, accounting for variances between processor generations.
 */
static void
imc_decode_mtr(imc_t *imc, imc_mc_t *icn, imc_dimm_t *dimm, uint32_t mtr)
{
	uint8_t disable;

	/*
	 * Check present first, before worrying about anything else.
	 */
	if (imc->imc_gen < IMC_GEN_SKYLAKE &&
	    IMC_MTR_PRESENT_SNB_BRD(mtr) == 0) {
		dimm->idimm_present = B_FALSE;
		return;
	} else if (imc->imc_gen >= IMC_GEN_SKYLAKE &&
	    IMC_MTR_PRESENT_SKYLAKE(mtr) == 0) {
		dimm->idimm_present = B_FALSE;
		return;
	}

	dimm->idimm_present = B_TRUE;
	dimm->idimm_ncolumns = IMC_MTR_CA_WIDTH(mtr) + IMC_MTR_CA_BASE;
	if (dimm->idimm_ncolumns < IMC_MTR_CA_MIN ||
	    dimm->idimm_ncolumns > IMC_MTR_CA_MAX) {
		dimm->idimm_valid |= IMC_DIMM_V_BAD_COLUMNS;
	}

	dimm->idimm_nrows = IMC_MTR_RA_WIDTH(mtr) + IMC_MTR_RA_BASE;
	if (dimm->idimm_nrows < IMC_MTR_RA_MIN ||
	    dimm->idimm_nrows > IMC_MTR_RA_MAX) {
		dimm->idimm_valid |= IMC_DIMM_V_BAD_ROWS;
	}

	/*
	 * Determine Density, this information is not present on Sandy Bridge.
	 */
	switch (imc->imc_gen) {
	case IMC_GEN_IVY:
		dimm->idimm_density = 1U << IMC_MTR_DENSITY_IVY_BRD(mtr);
		break;
	case IMC_GEN_HASWELL:
	case IMC_GEN_BROADWELL:
		switch (IMC_MTR_DENSITY_IVY_BRD(mtr)) {
		case 0:
		default:
			dimm->idimm_density = 0;
			dimm->idimm_valid |= IMC_DIMM_V_BAD_DENSITY;
			break;
		case 1:
			dimm->idimm_density = 2;
			break;
		case 2:
			dimm->idimm_density = 4;
			break;
		case 3:
			dimm->idimm_density = 8;
			break;
		}
		break;
	case IMC_GEN_SKYLAKE:
		switch (IMC_MTR_DENSITY_SKX(mtr)) {
		case 0:
		default:
			dimm->idimm_density = 0;
			dimm->idimm_valid |= IMC_DIMM_V_BAD_DENSITY;
			break;
		case 1:
			dimm->idimm_density = 2;
			break;
		case 2:
			dimm->idimm_density = 4;
			break;
		case 3:
			dimm->idimm_density = 8;
			break;
		case 4:
			dimm->idimm_density = 16;
			break;
		case 5:
			dimm->idimm_density = 12;
			break;
		}
		break;
	case IMC_GEN_UNKNOWN:
	case IMC_GEN_SANDY:
		dimm->idimm_density = 0;
		break;
	}

	/*
	 * The values of width are the same on IVY->SKX, but the bits are
	 * different. This doesn't exist on SNB.
	 */
	if (imc->imc_gen > IMC_GEN_SANDY) {
		uint8_t width;

		if (imc->imc_gen >= IMC_GEN_BROADWELL) {
			width = IMC_MTR_WIDTH_BRD_SKX(mtr);
		} else {
			width = IMC_MTR_WIDTH_IVB_HAS(mtr);
		}
		switch (width) {
		case 0:
			dimm->idimm_width = 4;
			break;
		case 1:
			dimm->idimm_width = 8;
			break;
		case 2:
			dimm->idimm_width = 16;
			break;
		default:
			dimm->idimm_width = 0;
			dimm->idimm_valid |= IMC_DIMM_V_BAD_WIDTH;
			break;
		}
	} else {
		dimm->idimm_width = 0;
	}

	dimm->idimm_nranks = 1 << IMC_MTR_DDR_RANKS(mtr);
	switch (imc->imc_gen) {
	case IMC_GEN_HASWELL:
	case IMC_GEN_BROADWELL:
	case IMC_GEN_SKYLAKE:
		if (dimm->idimm_nranks > IMC_MTR_DDR_RANKS_MAX_HAS_SKX) {
			dimm->idimm_nranks = 0;
			dimm->idimm_valid |= IMC_DIMM_V_BAD_RANKS;
		}
		break;
	default:
		if (dimm->idimm_nranks > IMC_MTR_DDR_RANKS_MAX) {
			dimm->idimm_nranks = 0;
			dimm->idimm_valid |= IMC_DIMM_V_BAD_RANKS;
		}
	}

	disable = IMC_MTR_RANK_DISABLE(mtr);
	dimm->idimm_ranks_disabled[0] = (disable & 0x1) != 0;
	dimm->idimm_ranks_disabled[1] = (disable & 0x2) != 0;
	dimm->idimm_ranks_disabled[2] = (disable & 0x4) != 0;
	dimm->idimm_ranks_disabled[3] = (disable & 0x8) != 0;

	/*
	 * Only Haswell and later have this information.
	 */
	if (imc->imc_gen >= IMC_GEN_HASWELL) {
		dimm->idimm_hdrl = IMC_MTR_HDRL_HAS_SKX(mtr) != 0;
		dimm->idimm_hdrl_parity = IMC_MTR_HDRL_PARITY_HAS_SKX(mtr) != 0;
		dimm->idimm_3dsranks = IMC_MTR_3DSRANKS_HAS_SKX(mtr);
		if (dimm->idimm_3dsranks != 0) {
			dimm->idimm_3dsranks = 1 << dimm->idimm_3dsranks;
		}
	}


	if (icn->icn_dimm_type == IMC_DIMM_DDR4) {
		dimm->idimm_nbanks = 16;
	} else {
		dimm->idimm_nbanks = 8;
	}

	/*
	 * To calculate the DIMM size we need first take the number of rows and
	 * columns. This gives us the number of slots per chip. In a given rank
	 * there are nbanks of these. There are nrank entries of those. Each of
	 * these slots can fit a byte.
	 */
	dimm->idimm_size = dimm->idimm_nbanks * dimm->idimm_nranks * 8 *
	    (1ULL << (dimm->idimm_ncolumns + dimm->idimm_nrows));
}

static void
imc_fill_dimms(imc_t *imc, imc_mc_t *icn, imc_channel_t *chan)
{
	uint_t i;

	/*
	 * There's one register for each DIMM that might be present, we always
	 * read that information to determine information about the DIMMs.
	 */
	chan->ich_ndimms = imc->imc_gen_data->igd_max_dimms;
	for (i = 0; i < imc->imc_gen_data->igd_max_dimms; i++) {
		uint32_t mtr;
		imc_dimm_t *dimm = &chan->ich_dimms[i];

		bzero(dimm, sizeof (imc_dimm_t));
		mtr = pci_config_get32(chan->ich_desc->istub_cfgspace,
		    imc->imc_gen_data->igd_mtr_offsets[i]);
		dimm->idimm_mtr = mtr;
		/*
		 * We don't really expect to get a bad PCIe read. However, if we
		 * do, treat that for the moment as though the DIMM is bad.
		 */
		if (mtr == PCI_EINVAL32) {
			dimm->idimm_valid |= IMC_DIMM_V_BAD_PCI_READ;
			continue;
		}

		imc_decode_mtr(imc, icn, dimm, mtr);
	}
}

static boolean_t
imc_fill_controller(imc_t *imc, imc_mc_t *icn)
{
	uint32_t mcmtr;

	mcmtr = pci_config_get32(icn->icn_main0->istub_cfgspace,
	    imc->imc_gen_data->igd_mcmtr_offset);
	if (mcmtr == PCI_EINVAL32) {
		icn->icn_invalid = B_TRUE;
		return (B_FALSE);
	}

	icn->icn_closed = IMC_MCMTR_CLOSED_PAGE(mcmtr) != 0;
	if (imc->imc_gen < IMC_GEN_SKYLAKE) {
		icn->icn_lockstep = IMC_MCMTR_LOCKSTEP(mcmtr) != 0;
	} else {
		icn->icn_lockstep = B_FALSE;
	}

	icn->icn_ecc = IMC_MCMTR_ECC_ENABLED(mcmtr) != 0;

	/*
	 * SNB and IVB only support DDR3. Haswell and Broadwell may support
	 * DDR4, depends on the SKU. Skylake only supports DDR4.
	 */
	switch (imc->imc_gen) {
	case IMC_GEN_SANDY:
	case IMC_GEN_IVY:
		icn->icn_dimm_type = IMC_DIMM_DDR3;
		break;
	case IMC_GEN_HASWELL:
	case IMC_GEN_BROADWELL:
		if (IMC_MCMTR_DDR4_HAS_BRD(mcmtr)) {
			icn->icn_dimm_type = IMC_DIMM_DDR4;
		} else {
			icn->icn_dimm_type = IMC_DIMM_DDR3;
		}
		break;
	default:
		/*
		 * Skylake and on are all DDR4.
		 */
		icn->icn_dimm_type = IMC_DIMM_DDR4;
		break;
	}

	if (imc->imc_gen >= IMC_GEN_SKYLAKE && icn->icn_m2m != NULL) {
		icn->icn_topo = pci_config_get32(icn->icn_m2m->istub_cfgspace,
		    imc->imc_gen_data->igd_topo_offset);
	}

	return (B_TRUE);
}

/*
 * Walk the IMC data and fill in the information on DIMMs and the memory
 * controller configurations.
 */
static void
imc_fill_data(imc_t *imc)
{
	uint_t csock, cmc, cchan;

	for (csock = 0; csock < imc->imc_nsockets; csock++) {
		imc_socket_t *sock = &imc->imc_sockets[csock];

		for (cmc = 0; cmc < sock->isock_nimc; cmc++) {
			imc_mc_t *icn = &sock->isock_imcs[cmc];

			if (!imc_fill_controller(imc, icn))
				continue;

			for (cchan = 0; cchan < icn->icn_nchannels; cchan++) {
				imc_fill_dimms(imc, icn,
				    &icn->icn_channels[cchan]);
			}
		}
	}
}

static nvlist_t *
imc_nvl_create_dimm(imc_t *imc, imc_dimm_t *dimm)
{
	nvlist_t *nvl;

	nvl = fnvlist_alloc();
	fnvlist_add_boolean_value(nvl, MCINTEL_NVLIST_V1_DIMM_PRESENT,
	    dimm->idimm_present);
	if (!dimm->idimm_present) {
		return (nvl);
	}

	fnvlist_add_uint64(nvl, MCINTEL_NVLIST_V1_DIMM_SIZE, dimm->idimm_size);
	fnvlist_add_uint32(nvl, MCINTEL_NVLIST_V1_DIMM_NCOLS,
	    dimm->idimm_ncolumns);
	fnvlist_add_uint32(nvl, MCINTEL_NVLIST_V1_DIMM_NROWS,
	    dimm->idimm_nrows);

	if (imc->imc_gen > IMC_GEN_SANDY) {
		fnvlist_add_uint64(nvl, MCINTEL_NVLIST_V1_DIMM_DENSITY,
		    dimm->idimm_density * (1ULL << 30));
		fnvlist_add_uint32(nvl, MCINTEL_NVLIST_V1_DIMM_WIDTH,
		    dimm->idimm_width);
	}
	fnvlist_add_uint32(nvl, MCINTEL_NVLIST_V1_DIMM_RANKS,
	    dimm->idimm_nranks);
	fnvlist_add_uint32(nvl, MCINTEL_NVLIST_V1_DIMM_BANKS,
	    dimm->idimm_nbanks);
	fnvlist_add_boolean_array(nvl, MCINTEL_NVLIST_V1_DIMM_RDIS,
	    dimm->idimm_ranks_disabled, IMC_MAX_RANK_DISABLE);

	if (imc->imc_gen >= IMC_GEN_HASWELL) {
		fnvlist_add_boolean_value(nvl, MCINTEL_NVLIST_V1_DIMM_HDRL,
		    dimm->idimm_hdrl);
		fnvlist_add_boolean_value(nvl, MCINTEL_NVLIST_V1_DIMM_HDRLP,
		    dimm->idimm_hdrl_parity);
		if (dimm->idimm_3dsranks > 0) {
			fnvlist_add_uint32(nvl, MCINTEL_NVLIST_V1_DIMM_3DRANK,
			    dimm->idimm_3dsranks);
		}
	}

	return (nvl);
}

static nvlist_t *
imc_nvl_create_channel(imc_t *imc, imc_channel_t *chan)
{
	nvlist_t *nvl;
	nvlist_t *dimms[IMC_MAX_DIMMPERCHAN];
	uint_t i;

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, MCINTEL_NVLIST_V1_CHAN_NDPC,
	    imc->imc_gen_data->igd_max_dimms);
	for (i = 0; i < imc->imc_gen_data->igd_max_dimms; i++) {
		dimms[i] = imc_nvl_create_dimm(imc, &chan->ich_dimms[i]);
	}

	fnvlist_add_nvlist_array(nvl, MCINTEL_NVLIST_V1_CHAN_DIMMS,
	    dimms, i);

	for (; i > 0; i--) {
		nvlist_free(dimms[i-1]);
	}

	return (nvl);
}

static nvlist_t *
imc_nvl_create_mc(imc_t *imc, imc_mc_t *icn)
{
	nvlist_t *nvl;
	nvlist_t *channels[IMC_MAX_CHANPERMC];
	uint_t i;

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, MCINTEL_NVLIST_V1_MC_NCHAN, icn->icn_nchannels);
	fnvlist_add_boolean_value(nvl, MCINTEL_NVLIST_V1_MC_ECC,
	    icn->icn_ecc);
	if (icn->icn_lockstep) {
		fnvlist_add_string(nvl, MCINTEL_NVLIST_V1_MC_CHAN_MODE,
		    MCINTEL_NVLIST_V1_MC_CHAN_MODE_LOCK);
	} else {
		fnvlist_add_string(nvl, MCINTEL_NVLIST_V1_MC_CHAN_MODE,
		    MCINTEL_NVLIST_V1_MC_CHAN_MODE_INDEP);

	}

	if (icn->icn_closed) {
		fnvlist_add_string(nvl, MCINTEL_NVLIST_V1_MC_POLICY,
		    MCINTEL_NVLIST_V1_MC_POLICY_CLOSED);
	} else {
		fnvlist_add_string(nvl, MCINTEL_NVLIST_V1_MC_POLICY,
		    MCINTEL_NVLIST_V1_MC_POLICY_OPEN);
	}

	for (i = 0; i < icn->icn_nchannels; i++) {
		channels[i] = imc_nvl_create_channel(imc,
		    &icn->icn_channels[i]);
	}
	fnvlist_add_nvlist_array(nvl, MCINTEL_NVLIST_V1_MC_CHANNELS,
	    channels, icn->icn_nchannels);
	for (i = 0; i < icn->icn_nchannels; i++) {
		nvlist_free(channels[i]);
	}

	return (nvl);
}

static void
imc_nvl_pack(imc_socket_t *sock, boolean_t sleep)
{
	char *buf = NULL;
	size_t len = 0;
	int kmflag;

	if (sock->isock_nvl == NULL)
		return;

	if (sock->isock_buf != NULL)
		return;

	if (sleep) {
		kmflag = KM_SLEEP;
	} else {
		kmflag = KM_NOSLEEP | KM_NORMALPRI;
	}

	if (nvlist_pack(sock->isock_nvl, &buf, &len, NV_ENCODE_XDR,
	    kmflag) != 0) {
		return;
	}

	sock->isock_buf = buf;
	sock->isock_buflen = len;
	sock->isock_gen++;
}

static void
imc_decoder_pack(imc_t *imc)
{
	char *buf = NULL;
	size_t len = 0;

	if (imc->imc_decoder_buf != NULL)
		return;

	if (imc->imc_decoder_dump == NULL) {
		imc->imc_decoder_dump = imc_dump_decoder(imc);
	}

	if (nvlist_pack(imc->imc_decoder_dump, &buf, &len, NV_ENCODE_XDR,
	    KM_NOSLEEP | KM_NORMALPRI) != 0) {
		return;
	}

	imc->imc_decoder_buf = buf;
	imc->imc_decoder_len = len;
}

static void
imc_nvl_create(imc_t *imc)
{
	uint_t csock;
	for (csock = 0; csock < imc->imc_nsockets; csock++) {
		uint_t i;
		nvlist_t *nvl;
		nvlist_t *mcs[IMC_MAX_IMCPERSOCK];
		imc_socket_t *sock = &imc->imc_sockets[csock];

		nvl = fnvlist_alloc();
		fnvlist_add_uint8(nvl, MCINTEL_NVLIST_VERSTR,
		    MCINTEL_NVLIST_VERS1);
		fnvlist_add_uint8(nvl, MCINTEL_NVLIST_V1_NMC,
		    sock->isock_nimc);

		for (i = 0; i < sock->isock_nimc; i++) {
			mcs[i] = imc_nvl_create_mc(imc, &sock->isock_imcs[i]);
		}

		fnvlist_add_nvlist_array(nvl, MCINTEL_NVLIST_V1_MCS,
		    mcs, sock->isock_nimc);

		for (i = 0; i < sock->isock_nimc; i++) {
			nvlist_free(mcs[i]);
		}

		sock->isock_nvl = nvl;
		imc_nvl_pack(sock, B_TRUE);
	}
}

/*
 * Determine the top of low and high memory. These determine whether transaction
 * addresses target main memory or not. Unfortunately, the way that these are
 * stored and fetched changes with different generations.
 */
static void
imc_sad_read_tohm(imc_t *imc, imc_sad_t *sad)
{
	uint32_t tolm, tohm_low, tohm_hi;

	tolm = pci_config_get32(sad->isad_tolh->istub_cfgspace,
	    imc->imc_gen_data->igd_tolm_offset);
	tohm_low = pci_config_get32(sad->isad_tolh->istub_cfgspace,
	    imc->imc_gen_data->igd_tohm_low_offset);
	if (imc->imc_gen_data->igd_tohm_hi_offset != 0) {
		tohm_hi = pci_config_get32(sad->isad_tolh->istub_cfgspace,
		    imc->imc_gen_data->igd_tohm_hi_offset);
	} else {
		tohm_hi = 0;
	}

	if (tolm == PCI_EINVAL32 || tohm_low == PCI_EINVAL32 ||
	    tohm_hi == PCI_EINVAL32) {
		sad->isad_valid |= IMC_SAD_V_BAD_PCI_READ;
		return;
	}

	switch (imc->imc_gen) {
	case IMC_GEN_SANDY:
	case IMC_GEN_IVY:
		sad->isad_tolm = ((uint64_t)tolm & IMC_TOLM_SNB_IVY_MASK) <<
		    IMC_TOLM_SNB_IVY_SHIFT;
		sad->isad_tohm = ((uint64_t)tohm_low & IMC_TOHM_SNB_IVY_MASK) <<
		    IMC_TOLM_SNB_IVY_SHIFT;
		break;
	case IMC_GEN_HASWELL:
	case IMC_GEN_BROADWELL:
	case IMC_GEN_SKYLAKE:
		sad->isad_tolm = (uint64_t)tolm & IMC_TOLM_HAS_SKX_MASK;
		sad->isad_tohm = ((uint64_t)tohm_low &
		    IMC_TOHM_LOW_HAS_SKX_MASK) | ((uint64_t)tohm_hi << 32);

		/*
		 * Adjust the values to turn them into an exclusive range.
		 */
		sad->isad_tolm += IMC_TOLM_HAS_SKY_EXCL;
		sad->isad_tohm += IMC_TOHM_HAS_SKY_EXCL;
		break;
	default:
		dev_err(imc->imc_dip, CE_PANIC, "imc driver programmer error: "
		    "set to unknown generation: %u", imc->imc_gen);
		return;
	}
}

static void
imc_sad_fill_rule(imc_t *imc, imc_sad_t *sad, imc_sad_rule_t *rule,
    uint32_t raw)
{
	uint_t attr;
	uint64_t limit;
	bzero(rule, sizeof (imc_sad_rule_t));

	rule->isr_raw_dram = raw;
	rule->isr_enable = IMC_SAD_DRAM_RULE_ENABLE(raw) != 0;
	if (imc->imc_gen < IMC_GEN_SKYLAKE) {
		switch (IMC_SAD_DRAM_INTERLEAVE_SNB_BRD(raw)) {
		case IMC_SAD_DRAM_INTERLEAVE_SNB_BRD_8t6:
			rule->isr_imode = IMC_SAD_IMODE_8t6;
			break;
		case IMC_SAD_DRAM_INTERLEAVE_SNB_BRD_8t6XOR:
			rule->isr_imode = IMC_SAD_IMODE_8t6XOR;
			break;
		}
	} else {
		switch (IMC_SAD_DRAM_INTERLEAVE_SKX(raw)) {
		case IMC_SAD_DRAM_INTERLEAVE_SKX_8t6:
			rule->isr_imode = IMC_SAD_IMODE_8t6;
			break;
		case IMC_SAD_DRAM_INTERLEAVE_SKX_10t8:
			rule->isr_imode = IMC_SAD_IMODE_10t8;
			break;
		case IMC_SAD_DRAM_INTERLEAVE_SKX_14t12:
			rule->isr_imode = IMC_SAD_IMODE_14t12;
			break;
		case IMC_SAD_DRAM_INTERLEAVE_SKX_32t30:
			rule->isr_imode = IMC_SAD_IMODE_32t30;
			break;
		}
	}

	if (imc->imc_gen >= IMC_GEN_SKYLAKE) {
		attr = IMC_SAD_DRAM_ATTR_SKX(raw);
	} else {
		attr = IMC_SAD_DRAM_ATTR_SNB_BRD(raw);
	}

	switch (attr) {
	case IMC_SAD_DRAM_ATTR_DRAM:
		rule->isr_type = IMC_SAD_TYPE_DRAM;
		break;
	case IMC_SAD_DRAM_ATTR_MMCFG:
		rule->isr_type = IMC_SAD_TYPE_MMCFG;
		break;
	case IMC_SAD_DRAM_ATTR_NXM:
		if (imc->imc_gen < IMC_GEN_SKYLAKE) {
			sad->isad_valid |= IMC_SAD_V_BAD_DRAM_ATTR;
		}
		rule->isr_type = IMC_SAD_TYPE_NXM;
		break;
	default:
		sad->isad_valid |= IMC_SAD_V_BAD_DRAM_ATTR;
		break;
	}

	/*
	 * Fetch the limit which represents bits 45:26 and then adjust this so
	 * that it is exclusive.
	 */
	if (imc->imc_gen >= IMC_GEN_SKYLAKE) {
		limit = IMC_SAD_DRAM_LIMIT_SKX(raw);
	} else {
		limit = IMC_SAD_DRAM_LIMIT_SNB_BRD(raw);
	}
	rule->isr_limit = (limit << IMC_SAD_DRAM_LIMIT_SHIFT) +
	    IMC_SAD_DRAM_LIMIT_EXCLUSIVE;

	/*
	 * The rest of this does not apply to Sandy Bridge.
	 */
	if (imc->imc_gen == IMC_GEN_SANDY)
		return;

	if (imc->imc_gen >= IMC_GEN_IVY && imc->imc_gen < IMC_GEN_SKYLAKE) {
		rule->isr_a7mode = IMC_SAD_DRAM_A7_IVB_BRD(raw) != 0;
		return;
	}

	switch (IMC_SAD_DRAM_MOD23_SKX(raw)) {
	case IMC_SAD_DRAM_MOD23_MOD3:
		rule->isr_mod_type = IMC_SAD_MOD_TYPE_MOD3;
		break;
	case IMC_SAD_DRAM_MOD23_MOD2_C01:
		rule->isr_mod_type = IMC_SAD_MOD_TYPE_MOD2_01;
		break;
	case IMC_SAD_DRAM_MOD23_MOD2_C12:
		rule->isr_mod_type = IMC_SAD_MOD_TYPE_MOD2_12;
		break;
	case IMC_SAD_DRAM_MOD23_MOD2_C02:
		rule->isr_mod_type = IMC_SAD_MOD_TYPE_MOD2_02;
		break;
	}

	rule->isr_need_mod3 = IMC_SAD_DRAM_MOD3_SKX(raw) != 0;
	switch (IMC_SAD_DRAM_MOD3_SKX(raw)) {
	case IMC_SAD_DRAM_MOD3_MODE_45t6:
		rule->isr_mod_mode = IMC_SAD_MOD_MODE_45t6;
		break;
	case IMC_SAD_DRAM_MOD3_MODE_45t8:
		rule->isr_mod_mode = IMC_SAD_MOD_MODE_45t8;
		break;
	case IMC_SAD_DRAM_MOD3_MODE_45t12:
		rule->isr_mod_mode = IMC_SAD_MOD_MODE_45t12;
		break;
	default:
		sad->isad_valid |= IMC_SAD_V_BAD_MOD3;
		break;
	}
}

static void
imc_sad_fill_rule_interleave(imc_t *imc, imc_sad_rule_t *rule, uint32_t raw)
{
	uint_t i;
	uint32_t mlen, mbase, skipbits, skipafter;

	rule->isr_raw_interleave = raw;

	/*
	 * Right now all architectures always have the maximum number of SAD
	 * interleave targets.
	 */
	rule->isr_ntargets = IMC_MAX_SAD_INTERLEAVE;

	/*
	 * Sandy Bridge has a gap in the interleave list due to the fact that it
	 * uses a smaller length.
	 */
	if (imc->imc_gen > IMC_GEN_SANDY) {
		mlen = IMC_SAD_ILEAVE_IVB_SKX_LEN;
		mbase = IMC_SAD_ILEAVE_IVB_SKX_MASK;
		skipbits = skipafter = 0;
	} else {
		mlen = IMC_SAD_ILEAVE_SNB_LEN;
		mbase = IMC_SAD_ILEAVE_SNB_MASK;
		skipbits = 2;
		skipafter = 4;
	}

	for (i = 0; i < rule->isr_ntargets; i++) {
		uint32_t mask, shift;

		shift = i * mlen;
		if (i >= skipafter)
			shift += skipbits;
		mask = mbase << shift;
		rule->isr_targets[i] = (raw & mask) >> shift;
	}
}

static void
imc_sad_read_dram_rules(imc_t *imc, imc_sad_t *sad)
{
	uint_t i;
	off_t off;

	sad->isad_nrules = imc->imc_gen_data->igd_sad_ndram_rules;
	for (i = 0, off = imc->imc_gen_data->igd_sad_dram_offset;
	    i < sad->isad_nrules; i++, off += sizeof (uint64_t)) {
		uint32_t dram, interleave;
		imc_sad_rule_t *rule = &sad->isad_rules[i];

		dram = pci_config_get32(sad->isad_dram->istub_cfgspace, off);
		interleave = pci_config_get32(sad->isad_dram->istub_cfgspace,
		    off + 4);

		if (dram == PCI_EINVAL32 || interleave == PCI_EINVAL32) {
			sad->isad_valid |= IMC_SAD_V_BAD_PCI_READ;
			return;
		}

		imc_sad_fill_rule(imc, sad, rule, dram);
		imc_sad_fill_rule_interleave(imc, rule, interleave);
	}
}

static void
imc_sad_decode_mcroute(imc_t *imc, imc_sad_t *sad)
{
	uint_t i;
	imc_sad_mcroute_table_t *mc = &sad->isad_mcroute;

	if (imc->imc_gen < IMC_GEN_SKYLAKE)
		return;
	if (sad->isad_valid != 0)
		return;

	mc->ismc_nroutes = IMC_MAX_SAD_MCROUTES;
	for (i = 0; i < IMC_MAX_SAD_MCROUTES; i++) {
		uint_t chanoff, ringoff;

		ringoff = i * IMC_MC_ROUTE_RING_BITS;
		chanoff = i * IMC_MC_ROUTE_CHAN_BITS + IMC_MC_ROUTE_CHAN_OFFSET;

		mc->ismc_mcroutes[i].ismce_imc = (mc->ismc_raw_mcroute >>
		    ringoff) & IMC_MC_ROUTE_RING_MASK;
		mc->ismc_mcroutes[i].ismce_pchannel = (mc->ismc_raw_mcroute >>
		    chanoff) & IMC_MC_ROUTE_CHAN_MASK;
	}
}

/*
 * Initialize the SAD. To do this we have to do a few different things:
 *
 * 1. Determine where the top of low and high memory is.
 * 2. Read and decode all of the rules for the SAD
 * 3. On systems with a route table, decode the raw routes
 *
 * At this point in time, we treat TOLM and TOHM as a per-socket construct, even
 * though it really should be global, this just makes life a bit simpler.
 */
static void
imc_decoder_init_sad(imc_t *imc)
{
	uint_t i;

	for (i = 0; i < imc->imc_nsockets; i++) {
		imc_sad_read_tohm(imc, &imc->imc_sockets[i].isock_sad);
		imc_sad_read_dram_rules(imc, &imc->imc_sockets[i].isock_sad);
		imc_sad_decode_mcroute(imc, &imc->imc_sockets[i].isock_sad);
	}
}

static void
imc_tad_fill_rule(imc_t *imc, imc_tad_t *tad, imc_tad_rule_t *prev,
    imc_tad_rule_t *rule, uint32_t val)
{
	uint64_t limit;

	limit = IMC_TAD_LIMIT(val);
	rule->itr_limit = (limit << IMC_TAD_LIMIT_SHIFT) +
	    IMC_TAD_LIMIT_EXCLUSIVE;
	rule->itr_raw = val;

	switch (IMC_TAD_SOCK_WAY(val)) {
	case IMC_TAD_SOCK_WAY_1:
		rule->itr_sock_way = 1;
		break;
	case IMC_TAD_SOCK_WAY_2:
		rule->itr_sock_way = 2;
		break;
	case IMC_TAD_SOCK_WAY_4:
		rule->itr_sock_way = 4;
		break;
	case IMC_TAD_SOCK_WAY_8:
		rule->itr_sock_way = 8;
		break;
	}

	rule->itr_chan_way = IMC_TAD_CHAN_WAY(val) + 1;
	rule->itr_sock_gran = IMC_TAD_GRAN_64B;
	rule->itr_chan_gran = IMC_TAD_GRAN_64B;

	/*
	 * Starting with Skylake the targets that are used are no longer part of
	 * the TAD. Those come from the IMC route table.
	 */
	if (imc->imc_gen >= IMC_GEN_SKYLAKE) {
		rule->itr_ntargets = 0;
		return;
	}

	rule->itr_ntargets = IMC_TAD_SNB_BRD_NTARGETS;
	rule->itr_targets[0] = IMC_TAD_TARG0(val);
	rule->itr_targets[1] = IMC_TAD_TARG1(val);
	rule->itr_targets[2] = IMC_TAD_TARG2(val);
	rule->itr_targets[3] = IMC_TAD_TARG3(val);

	if (prev == NULL) {
		rule->itr_base = 0;
	} else {
		rule->itr_base = prev->itr_limit + 1;
	}
}

static void
imc_tad_fill_skx(imc_t *imc, imc_tad_t *tad, imc_tad_rule_t *rule,
    uint32_t val)
{
	uint64_t base;

	rule->itr_raw_gran = val;
	base = IMC_TAD_BASE_BASE(val);
	rule->itr_base = base << IMC_TAD_BASE_SHIFT;

	switch (IMC_TAD_BASE_CHAN_GRAN(val)) {
	case IMC_TAD_BASE_CHAN_GRAN_64B:
		rule->itr_sock_gran = IMC_TAD_GRAN_64B;
		break;
	case IMC_TAD_BASE_CHAN_GRAN_256B:
		rule->itr_sock_gran = IMC_TAD_GRAN_256B;
		break;
	case IMC_TAD_BASE_CHAN_GRAN_4KB:
		rule->itr_sock_gran = IMC_TAD_GRAN_4KB;
		break;
	default:
		tad->itad_valid |= IMC_TAD_V_BAD_CHAN_GRAN;
		return;
	}

	switch (IMC_TAD_BASE_SOCK_GRAN(val)) {
	case IMC_TAD_BASE_SOCK_GRAN_64B:
		rule->itr_sock_gran = IMC_TAD_GRAN_64B;
		break;
	case IMC_TAD_BASE_SOCK_GRAN_256B:
		rule->itr_sock_gran = IMC_TAD_GRAN_256B;
		break;
	case IMC_TAD_BASE_SOCK_GRAN_4KB:
		rule->itr_sock_gran = IMC_TAD_GRAN_4KB;
		break;
	case IMC_TAD_BASE_SOCK_GRAN_1GB:
		rule->itr_sock_gran = IMC_TAD_GRAN_1GB;
		break;
	}
}

/*
 * When mirroring is enabled, at least in Sandy Bridge to Broadwell, it's
 * suggested that the channel wayness will take this into account and therefore
 * should be accurately reflected.
 */
static void
imc_tad_read_rules(imc_t *imc, imc_tad_t *tad)
{
	uint_t i;
	off_t baseoff;
	imc_tad_rule_t *prev;

	tad->itad_nrules = imc->imc_gen_data->igd_tad_nrules;
	for (i = 0, baseoff = imc->imc_gen_data->igd_tad_rule_offset,
	    prev = NULL; i < tad->itad_nrules;
	    i++, baseoff += sizeof (uint32_t)) {
		uint32_t val;
		off_t off;
		imc_tad_rule_t *rule = &tad->itad_rules[i];

		/*
		 * On Skylake, the TAD rules are split among two registers. The
		 * latter set mimics what exists on pre-Skylake.
		 */
		if (imc->imc_gen >= IMC_GEN_SKYLAKE) {
			off = baseoff + IMC_SKX_WAYNESS_OFFSET;
		} else {
			off = baseoff;
		}

		val = pci_config_get32(tad->itad_stub->istub_cfgspace, off);
		if (val == PCI_EINVAL32) {
			tad->itad_valid |= IMC_TAD_V_BAD_PCI_READ;
			return;
		}

		imc_tad_fill_rule(imc, tad, prev, rule, val);
		prev = rule;
		if (imc->imc_gen < IMC_GEN_SKYLAKE)
			continue;

		val = pci_config_get32(tad->itad_stub->istub_cfgspace, baseoff);
		if (val == PCI_EINVAL32) {
			tad->itad_valid |= IMC_TAD_V_BAD_PCI_READ;
			return;
		}

		imc_tad_fill_skx(imc, tad, rule, val);
	}
}

/*
 * Check for features which change how decoding works.
 */
static void
imc_tad_read_features(imc_t *imc, imc_tad_t *tad, imc_mc_t *mc)
{
	uint32_t val;

	/*
	 * Determine whether or not lockstep mode or mirroring are enabled.
	 * These change the behavior of how we're supposed to interpret channel
	 * wayness. Lockstep is available in the TAD's features. Mirroring is
	 * available on the IMC's features. This isn't present in Skylake+. On
	 * Skylake Mirorring is a property of the SAD rule and there is no
	 * lockstep.
	 */
	switch (imc->imc_gen) {
	case IMC_GEN_SANDY:
	case IMC_GEN_IVY:
	case IMC_GEN_HASWELL:
	case IMC_GEN_BROADWELL:
		val = pci_config_get32(tad->itad_stub->istub_cfgspace,
		    imc->imc_gen_data->igd_tad_sysdef);
		if (val == PCI_EINVAL32) {
			tad->itad_valid |= IMC_TAD_V_BAD_PCI_READ;
			return;
		}
		if (IMC_TAD_SYSDEF_LOCKSTEP(val)) {
			tad->itad_flags |= IMC_TAD_FLAG_LOCKSTEP;
		}

		val = pci_config_get32(mc->icn_main1->istub_cfgspace,
		    imc->imc_gen_data->igd_mc_mirror);
		if (val == PCI_EINVAL32) {
			tad->itad_valid |= IMC_TAD_V_BAD_PCI_READ;
			return;
		}
		if (IMC_MC_MIRROR_SNB_BRD(val)) {
			tad->itad_flags |= IMC_TAD_FLAG_MIRROR;
		}
		break;
	default:
		break;
	}

	/*
	 * Now, go through and look at values that'll change how we do the
	 * channel index and adddress calculation. These are only present
	 * between Ivy Bridge and Broadwell. They don't exist on Sandy Bridge
	 * and they don't exist on Skylake+.
	 */
	switch (imc->imc_gen) {
	case IMC_GEN_IVY:
	case IMC_GEN_HASWELL:
	case IMC_GEN_BROADWELL:
		val = pci_config_get32(tad->itad_stub->istub_cfgspace,
		    imc->imc_gen_data->igd_tad_sysdef2);
		if (val == PCI_EINVAL32) {
			tad->itad_valid |= IMC_TAD_V_BAD_PCI_READ;
			return;
		}
		if (IMC_TAD_SYSDEF2_SHIFTUP(val)) {
			tad->itad_flags |= IMC_TAD_FLAG_CHANSHIFT;
		}
		if (IMC_TAD_SYSDEF2_SHIFTUP(val)) {
			tad->itad_flags |= IMC_TAD_FLAG_CHANHASH;
		}
		break;
	default:
		break;
	}
}

/*
 * Read the IMC channel interleave records
 */
static void
imc_tad_read_interleave(imc_t *imc, imc_channel_t *chan)
{
	uint_t i;
	off_t off;

	chan->ich_ntad_offsets = imc->imc_gen_data->igd_tad_nrules;
	for (i = 0, off = imc->imc_gen_data->igd_tad_chan_offset;
	    i < chan->ich_ntad_offsets; i++, off += sizeof (uint32_t)) {
		uint32_t val;
		uint64_t offset;

		val = pci_config_get32(chan->ich_desc->istub_cfgspace,
		    off);
		if (val == PCI_EINVAL32) {
			chan->ich_valid |= IMC_CHANNEL_V_BAD_PCI_READ;
			return;
		}

		if (imc->imc_gen >= IMC_GEN_SKYLAKE) {
			offset = IMC_TADCHAN_OFFSET_SKX(val);
		} else {
			offset = IMC_TADCHAN_OFFSET_SNB_BRD(val);
		}

		chan->ich_tad_offsets[i] = offset << IMC_TADCHAN_OFFSET_SHIFT;
		chan->ich_tad_offsets_raw[i] = val;
	}
}

static void
imc_decoder_init_tad(imc_t *imc)
{
	uint_t i;

	for (i = 0; i < imc->imc_nsockets; i++) {
		uint_t j;

		for (j = 0; j < imc->imc_sockets[i].isock_ntad; j++) {
			imc_tad_read_features(imc,
			    &imc->imc_sockets[i].isock_tad[j],
			    &imc->imc_sockets[i].isock_imcs[j]);
			imc_tad_read_rules(imc,
			    &imc->imc_sockets[i].isock_tad[j]);
		}
	}

	for (i = 0; i < imc->imc_nsockets; i++) {
		uint_t j;
		imc_socket_t *sock = &imc->imc_sockets[i];

		for (j = 0; j < imc->imc_sockets[i].isock_nimc; j++) {
			uint_t k;
			imc_mc_t *mc = &sock->isock_imcs[j];

			for (k = 0; k < mc->icn_nchannels; k++) {
				imc_channel_t *chan = &mc->icn_channels[k];
				imc_tad_read_interleave(imc, chan);
			}
		}
	}
}

static void
imc_rir_read_ileave_offsets(imc_t *imc, imc_channel_t *chan,
    imc_rank_ileave_t *rank, uint_t rirno, boolean_t contig)
{
	uint_t i;
	off_t off, incr;

	/*
	 * Rank interleave offset registers come in two forms. Either they are
	 * contiguous for a given wayness, meaning that all of the entries for
	 * wayness zero are contiguous, or they are sparse, meaning that there
	 * is a bank for entry zero for all wayness, then entry one for all
	 * wayness, etc.
	 */
	if (contig) {
		off = imc->imc_gen_data->igd_rir_ileave_offset +
		    (rirno * imc->imc_gen_data->igd_rir_nileaves *
		    sizeof (uint32_t));
		incr = sizeof (uint32_t);
	} else {
		off = imc->imc_gen_data->igd_rir_ileave_offset +
		    (rirno * sizeof (uint32_t));
		incr = imc->imc_gen_data->igd_rir_nileaves * sizeof (uint32_t);
	}
	for (i = 0; i < rank->irle_nentries; i++, off += incr) {
		uint32_t val;
		uint64_t offset;
		imc_rank_ileave_entry_t *ent = &rank->irle_entries[i];

		val = pci_config_get32(chan->ich_desc->istub_cfgspace, off);
		if (val == PCI_EINVAL32) {
			chan->ich_valid |= IMC_CHANNEL_V_BAD_PCI_READ;
			return;
		}

		switch (imc->imc_gen) {
		case IMC_GEN_BROADWELL:
			ent->irle_target = IMC_RIR_OFFSET_TARGET_BRD(val);
			break;
		default:
			ent->irle_target = IMC_RIR_OFFSET_TARGET(val);
			break;
		}
		if (imc->imc_gen >= IMC_GEN_HASWELL) {
			offset = IMC_RIR_OFFSET_OFFSET_HAS_SKX(val);
		} else {
			offset = IMC_RIR_OFFSET_OFFSET_SNB_IVB(val);
		}
		ent->irle_offset = offset << IMC_RIR_OFFSET_SHIFT;
	}
}

static void
imc_rir_read_wayness(imc_t *imc, imc_channel_t *chan)
{
	uint_t i;
	off_t off;

	chan->ich_nrankileaves = imc->imc_gen_data->igd_rir_nways;
	for (i = 0, off = imc->imc_gen_data->igd_rir_way_offset;
	    i < chan->ich_nrankileaves; i++, off += sizeof (uint32_t)) {
		uint32_t val;
		uint64_t lim;
		imc_rank_ileave_t *ent = &chan->ich_rankileaves[i];

		val = pci_config_get32(chan->ich_desc->istub_cfgspace, off);
		if (val == PCI_EINVAL32) {
			chan->ich_valid |= IMC_CHANNEL_V_BAD_PCI_READ;
			return;
		}

		ent->irle_raw = val;
		ent->irle_enabled = IMC_RIR_WAYNESS_ENABLED(val) != 0;
		ent->irle_nways = 1 << IMC_RIR_WAYNESS_WAY(val);
		ent->irle_nwaysbits = IMC_RIR_WAYNESS_WAY(val);
		if (imc->imc_gen >= IMC_GEN_HASWELL) {
			lim = IMC_RIR_LIMIT_HAS_SKX(val);
		} else {
			lim = IMC_RIR_LIMIT_SNB_IVB(val);
		}

		ent->irle_limit = (lim << IMC_RIR_LIMIT_SHIFT) +
		    IMC_RIR_LIMIT_EXCLUSIVE;

		ent->irle_nentries = imc->imc_gen_data->igd_rir_nileaves;
		if (imc->imc_gen >= IMC_GEN_SKYLAKE) {
			imc_rir_read_ileave_offsets(imc, chan, ent, i, B_FALSE);
		} else {
			imc_rir_read_ileave_offsets(imc, chan, ent, i, B_TRUE);
		}
	}
}

static void
imc_decoder_init_rir(imc_t *imc)
{
	uint_t i;

	for (i = 0; i < imc->imc_nsockets; i++) {
		uint_t j;
		imc_socket_t *sock = &imc->imc_sockets[i];

		for (j = 0; j < imc->imc_sockets[i].isock_nimc; j++) {
			uint_t k;
			imc_mc_t *mc = &sock->isock_imcs[j];

			for (k = 0; k < mc->icn_nchannels; k++) {
				imc_channel_t *chan = &mc->icn_channels[k];
				imc_rir_read_wayness(imc, chan);
			}
		}
	}
}

static cmi_errno_t
imc_mc_patounum(void *arg, uint64_t pa, uint8_t valid_hi, uint8_t valid_lo,
    uint32_t synd, int syndtype, mc_unum_t *unump)
{
	imc_t *imc = arg;
	uint_t i;
	imc_decode_state_t dec;

	bzero(&dec, sizeof (dec));
	if (!imc_decode_pa(imc, pa, &dec)) {
		switch (dec.ids_fail) {
		case IMC_DECODE_F_LEGACY_RANGE:
		case IMC_DECODE_F_OUTSIDE_DRAM:
			return (CMIERR_MC_NOTDIMMADDR);
		default:
			return (CMIERR_MC_BADSTATE);
		}
	}

	unump->unum_board = 0;
	/*
	 * The chip id needs to be in the order that the OS expects it, which
	 * may not be our order.
	 */
	for (i = 0; i < imc->imc_nsockets; i++) {
		if (imc->imc_spointers[i] == dec.ids_socket)
			break;
	}
	if (i == imc->imc_nsockets) {
		return (CMIERR_MC_BADSTATE);
	}
	unump->unum_chip = i;
	unump->unum_mc = dec.ids_tadid;
	unump->unum_chan = dec.ids_channelid;
	unump->unum_cs = dec.ids_dimmid;
	unump->unum_rank = dec.ids_rankid;
	unump->unum_offset = dec.ids_rankaddr;
	for (i = 0; i < MC_UNUM_NDIMM; i++) {
		unump->unum_dimms[i] = MC_INVALNUM;
	}

	return (CMI_SUCCESS);
}

static cmi_errno_t
imc_mc_unumtopa(void *arg, mc_unum_t *unum, nvlist_t *nvl, uint64_t *pa)
{
	return (CMIERR_UNKNOWN);
}

static const cmi_mc_ops_t imc_mc_ops = {
	.cmi_mc_patounum = imc_mc_patounum,
	.cmi_mc_unumtopa = imc_mc_unumtopa
};

/*
 * This is where we really finish attaching and become open for business. This
 * occurs once we have all of the expected stubs attached. Here's where all of
 * the real fun begins.
 */
static void
imc_attach_complete(void *arg)
{
	imc_t *imc = arg;
	cmi_errno_t err;

	imc_set_gen_data(imc);

	/*
	 * On SKX and newer, we can fail to map PCI buses at this point due to
	 * bad PCIe reads.
	 */
	if (!imc_map_stubs(imc)) {
		goto done;
	}

	imc_fixup_stubs(imc);
	imc_map_sockets(imc);

	if (!imc_create_minors(imc)) {
		goto done;
	}

	imc_fill_data(imc);
	imc_nvl_create(imc);

	/*
	 * Gather additional information that we need so that we can properly
	 * initialize the memory decoder and encoder.
	 */
	imc_decoder_init_sad(imc);
	imc_decoder_init_tad(imc);
	imc_decoder_init_rir(imc);

	/*
	 * Register decoder functions. This may fail. If so, try and complain
	 * loudly, but stay active to allow other data to be useful. Register a
	 * global handle.
	 */
	if ((err = cmi_mc_register_global(&imc_mc_ops, imc)) != CMI_SUCCESS) {
		imc->imc_flags |= IMC_F_MCREG_FAILED;
		dev_err(imc->imc_dip, CE_WARN, "failed to register memory "
		    "decoding operations: 0x%x", err);
	}

done:
	mutex_enter(&imc->imc_lock);
	imc->imc_flags &= IMC_F_ATTACH_DISPATCHED;
	imc->imc_flags |= IMC_F_ATTACH_COMPLETE;
	mutex_exit(&imc->imc_lock);
}

static int
imc_stub_comparator(const void *l, const void *r)
{
	const imc_stub_t *sl = l, *sr = r;
	if (sl->istub_bus > sr->istub_bus)
		return (1);
	if (sl->istub_bus < sr->istub_bus)
		return (-1);
	if (sl->istub_dev > sr->istub_dev)
		return (1);
	if (sl->istub_dev < sr->istub_dev)
		return (-1);
	if (sl->istub_func > sr->istub_func)
		return (1);
	if (sl->istub_func < sr->istub_func)
		return (-1);
	return (0);
}

static int
imc_stub_scan_cb(dev_info_t *dip, void *arg)
{
	int vid, did;
	const imc_stub_table_t *table;
	imc_t *imc = arg;
	int *regs;
	uint_t i, nregs;

	if (dip == ddi_root_node()) {
		return (DDI_WALK_CONTINUE);
	}

	/*
	 * Get the dev info name. PCI devices will always be children of PCI
	 * devices today on x86. If we reach something that has a device name
	 * that's not PCI, then we can prune it's children.
	 */
	if (strncmp("pci", ddi_get_name(dip), 3) != 0) {
		return (DDI_WALK_PRUNECHILD);
	}

	/*
	 * Get the device and vendor ID and see if this is something the imc
	 * knows about or cares about.
	 */
	vid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", PCI_EINVAL16);
	did = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", PCI_EINVAL16);
	if (vid == PCI_EINVAL16 || did == PCI_EINVAL16) {
		return (DDI_WALK_CONTINUE);
	}

	if (vid != IMC_PCI_VENDOR_INTC) {
		return (DDI_WALK_PRUNECHILD);
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &regs, &nregs) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_CONTINUE);
	}

	if (nregs == 0) {
		ddi_prop_free(regs);
		return (DDI_WALK_CONTINUE);
	}


	table = NULL;
	for (i = 0; i < ARRAY_SIZE(imc_stub_table); i++) {
		if (imc_stub_table[i].imcs_devid == did &&
		    imc_stub_table[i].imcs_pcidev == PCI_REG_DEV_G(regs[0]) &&
		    imc_stub_table[i].imcs_pcifunc == PCI_REG_FUNC_G(regs[0])) {
			table = &imc_stub_table[i];
			break;
		}
	}
	ddi_prop_free(regs);

	/*
	 * Not a match, not interesting.
	 */
	if (table == NULL) {
		return (DDI_WALK_CONTINUE);
	}

	mutex_enter(&imc->imc_lock);
	imc->imc_nscanned++;
	mutex_exit(&imc->imc_lock);

	return (DDI_WALK_CONTINUE);
}

/*
 * From here, go through and see how many of the devices that we know about.
 */
static void
imc_stub_scan(void *arg)
{
	imc_t *imc = arg;
	boolean_t dispatch = B_FALSE;

	/*
	 * Zero out the scan results in case we've been detached and reattached.
	 */
	mutex_enter(&imc->imc_lock);
	imc->imc_nscanned = 0;
	mutex_exit(&imc->imc_lock);

	ddi_walk_devs(ddi_root_node(), imc_stub_scan_cb, imc);

	mutex_enter(&imc->imc_lock);
	imc->imc_flags |= IMC_F_SCAN_COMPLETE;
	imc->imc_flags &= ~IMC_F_SCAN_DISPATCHED;

	/*
	 * If the scan found no nodes, then that means that we're on a hardware
	 * platform that we don't support. Therefore, there's no reason to do
	 * anything here.
	 */
	if (imc->imc_nscanned == 0) {
		imc->imc_flags |= IMC_F_UNSUP_PLATFORM;
		mutex_exit(&imc->imc_lock);
		return;
	}

	if (avl_numnodes(&imc->imc_stubs) == imc->imc_nscanned) {
		imc->imc_flags |= IMC_F_ATTACH_DISPATCHED;
		dispatch = B_TRUE;
	}

	mutex_exit(&imc->imc_lock);

	if (dispatch) {
		(void) ddi_taskq_dispatch(imc->imc_taskq, imc_attach_complete,
		    imc, DDI_SLEEP);
	}
}

/*
 * By default, refuse to allow stubs to detach.
 */
int
imc_detach_stub(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	imc_stub_t *stub;
	imc_t *imc = imc_data;

	mutex_enter(&imc->imc_lock);

	/*
	 * By default, we do not allow stubs to detach. However, if the driver
	 * has attached to devices on a platform it doesn't recognize or
	 * support or if the override flag has been set, then allow detach to
	 * proceed.
	 */
	if ((imc->imc_flags & IMC_F_UNSUP_PLATFORM) == 0 &&
	    imc_allow_detach == 0) {
		mutex_exit(&imc->imc_lock);
		return (DDI_FAILURE);
	}

	for (stub = avl_first(&imc->imc_stubs); stub != NULL;
	    stub = AVL_NEXT(&imc->imc_stubs, stub)) {
		if (stub->istub_dip == dip) {
			break;
		}
	}

	/*
	 * A device was attached to us that we somehow don't know about. Allow
	 * this to proceed.
	 */
	if (stub == NULL) {
		mutex_exit(&imc->imc_lock);
		return (DDI_SUCCESS);
	}

	pci_config_teardown(&stub->istub_cfgspace);
	avl_remove(&imc->imc_stubs, stub);
	kmem_free(stub, sizeof (imc_stub_t));
	mutex_exit(&imc->imc_lock);

	return (DDI_SUCCESS);
}

int
imc_attach_stub(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	imc_stub_t *stub, *lookup;
	int did, vid, *regs;
	uint_t i, nregs;
	const imc_stub_table_t *table;
	avl_index_t idx;
	boolean_t dispatch = B_FALSE;
	imc_t *imc = imc_data;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/*
	 * We've been asked to attach a stub. First, determine if this is even a
	 * PCI device that we should care about. Then, append it to our global
	 * list and kick off the configuration task. Note that we do this
	 * configuration task in a taskq so that we don't interfere with the
	 * normal attach / detach path processing.
	 */
	if (strncmp("pci", ddi_get_name(dip), 3) != 0) {
		return (DDI_FAILURE);
	}

	/*
	 * Get the device and vendor ID and see if this is something the imc
	 * knows about or cares about.
	 */
	vid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", PCI_EINVAL16);
	did = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", PCI_EINVAL16);
	if (vid == PCI_EINVAL16 || did == PCI_EINVAL16) {
		return (DDI_FAILURE);
	}

	/*
	 * Only accept INTC parts on the imc driver.
	 */
	if (vid != IMC_PCI_VENDOR_INTC) {
		return (DDI_FAILURE);
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &regs, &nregs) != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (nregs == 0) {
		ddi_prop_free(regs);
		return (DDI_FAILURE);
	}

	/*
	 * Determine if this matches a known device.
	 */
	table = NULL;
	for (i = 0; i < ARRAY_SIZE(imc_stub_table); i++) {
		if (imc_stub_table[i].imcs_devid == did &&
		    imc_stub_table[i].imcs_pcidev == PCI_REG_DEV_G(regs[0]) &&
		    imc_stub_table[i].imcs_pcifunc == PCI_REG_FUNC_G(regs[0])) {
			table = &imc_stub_table[i];
			break;
		}
	}

	if (i == ARRAY_SIZE(imc_stub_table)) {
		ddi_prop_free(regs);
		return (DDI_FAILURE);
	}

	/*
	 * We've found something. Make sure the generation matches our current
	 * one. If it does, construct the entry and append it to the list.
	 */
	mutex_enter(&imc->imc_lock);
	if (imc->imc_gen != IMC_GEN_UNKNOWN && imc->imc_gen !=
	    table->imcs_gen) {
		mutex_exit(&imc->imc_lock);
		ddi_prop_free(regs);
		dev_err(dip, CE_WARN, "Encountered IMC stub device (%u/%u) "
		    "that has different hardware generation (%u) from current "
		    "generation (%u)", vid, did, table->imcs_gen, imc->imc_gen);
		return (DDI_FAILURE);
	} else {
		imc->imc_gen = table->imcs_gen;
	}
	mutex_exit(&imc->imc_lock);

	stub = kmem_zalloc(sizeof (imc_stub_t), KM_SLEEP);
	stub->istub_dip = dip;
	stub->istub_vid = vid;
	stub->istub_did = did;
	stub->istub_bus = PCI_REG_BUS_G(regs[0]);
	stub->istub_dev = PCI_REG_DEV_G(regs[0]);
	stub->istub_func = PCI_REG_FUNC_G(regs[0]);
	ddi_prop_free(regs);
	stub->istub_table = table;

	if (pci_config_setup(dip, &stub->istub_cfgspace) != DDI_SUCCESS) {
		kmem_free(stub, sizeof (stub));
		dev_err(dip, CE_WARN, "Failed to set up PCI config space "
		    "for IMC stub device %s (%u/%u)", ddi_node_name(dip),
		    vid, did);
		return (DDI_FAILURE);
	}

	mutex_enter(&imc->imc_lock);
	if ((lookup = avl_find(&imc->imc_stubs, stub, &idx)) != NULL) {
		dev_err(dip, CE_WARN, "IMC stub %s (%u/%u) has duplicate "
		    "bdf %u/%u/%u with %s (%u/%u), not attaching",
		    ddi_node_name(imc->imc_dip), vid, did,
		    stub->istub_bus, stub->istub_dev, stub->istub_func,
		    ddi_node_name(lookup->istub_dip), lookup->istub_vid,
		    lookup->istub_did);
		mutex_exit(&imc->imc_lock);
		pci_config_teardown(&stub->istub_cfgspace);
		kmem_free(stub, sizeof (stub));

		return (DDI_FAILURE);
	}
	avl_insert(&imc->imc_stubs, stub, idx);

	if ((imc->imc_flags & IMC_F_ALL_FLAGS) == IMC_F_SCAN_COMPLETE &&
	    avl_numnodes(&imc->imc_stubs) == imc->imc_nscanned) {
		imc->imc_flags |= IMC_F_ATTACH_DISPATCHED;
		dispatch = B_TRUE;
	}
	mutex_exit(&imc->imc_lock);

	if (dispatch) {
		(void) ddi_taskq_dispatch(imc->imc_taskq, imc_attach_complete,
		    imc, DDI_SLEEP);
	}

	return (DDI_SUCCESS);
}

static int
imc_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	imc_t *imc = imc_data;

	if ((flag & (FEXCL | FNDELAY)) != 0)
		return (EINVAL);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	mutex_enter(&imc->imc_lock);

	if ((imc->imc_flags & IMC_F_UNSUP_PLATFORM) != 0) {
		mutex_exit(&imc->imc_lock);
		return (ENOTSUP);
	}

	/*
	 * It's possible that someone has come in during the window between when
	 * we've created the minor node and when we've finished doing work.
	 */
	if ((imc->imc_flags & IMC_F_ATTACH_COMPLETE) == 0) {
		mutex_exit(&imc->imc_lock);
		return (EAGAIN);
	}

	/*
	 * It's not clear how someone would get a minor that we didn't create.
	 * But be paranoid and make sure.
	 */
	if (getminor(*devp) >= imc->imc_nsockets) {
		mutex_exit(&imc->imc_lock);
		return (EINVAL);
	}

	/*
	 * Make sure this socket entry has been filled in.
	 */
	if (imc->imc_spointers[getminor(*devp)] == NULL) {
		mutex_exit(&imc->imc_lock);
		return (EINVAL);
	}

	mutex_exit(&imc->imc_lock);

	return (0);
}

static void
imc_ioctl_decode(imc_t *imc, mc_encode_ioc_t *encode)
{
	imc_decode_state_t dec;
	uint_t i;

	bzero(&dec, sizeof (dec));
	if (!imc_decode_pa(imc, encode->mcei_pa, &dec)) {
		encode->mcei_err = (uint32_t)dec.ids_fail;
		encode->mcei_errdata = dec.ids_fail_data;
		return;
	}

	encode->mcei_errdata = 0;
	encode->mcei_err = 0;
	encode->mcei_board = 0;
	for (i = 0; i < imc->imc_nsockets; i++) {
		if (imc->imc_spointers[i] == dec.ids_socket)
			break;
	}
	encode->mcei_chip = i;
	encode->mcei_mc = dec.ids_tadid;
	encode->mcei_chan = dec.ids_channelid;
	encode->mcei_dimm = dec.ids_dimmid;
	encode->mcei_rank_addr = dec.ids_rankaddr;
	encode->mcei_rank = dec.ids_rankid;
	encode->mcei_row = UINT32_MAX;
	encode->mcei_column = UINT32_MAX;
	encode->mcei_pad = 0;
}

static int
imc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int ret;
	minor_t m;
	mc_snapshot_info_t info;
	mc_encode_ioc_t encode;
	imc_t *imc = imc_data;
	imc_socket_t *sock;

	mutex_enter(&imc->imc_lock);
	m = getminor(dev);
	if (m >= imc->imc_nsockets) {
		ret = EINVAL;
		goto done;
	}
	sock = imc->imc_spointers[m];
	if (sock == NULL) {
		ret = EINVAL;
		goto done;
	}

	/*
	 * Note, other memory controller drivers don't check mode for reading
	 * data nor do they care who can read it from a credential perspective.
	 * As such we don't either at this time.
	 */
	switch (cmd) {
	case MC_IOC_SNAPSHOT_INFO:
		imc_nvl_pack(sock, B_FALSE);
		if (sock->isock_buf == NULL) {
			ret = EIO;
			break;
		}

		info.mcs_size = sock->isock_buflen;
		info.mcs_gen = sock->isock_gen;

		if (ddi_copyout(&info, (void *)arg, sizeof (info), mode) != 0) {
			ret = EFAULT;
			break;
		}

		ret = 0;
		break;
	case MC_IOC_SNAPSHOT:
		imc_nvl_pack(sock, B_FALSE);
		if (sock->isock_buf == NULL) {
			ret = EIO;
			break;
		}

		if (ddi_copyout(sock->isock_buf, (void *)arg,
		    sock->isock_buflen, mode) != 0) {
			ret = EFAULT;
			break;
		}

		ret = 0;
		break;
	case MC_IOC_DECODE_SNAPSHOT_INFO:
		imc_decoder_pack(imc);
		if (imc->imc_decoder_buf == NULL) {
			ret = EIO;
			break;
		}

		info.mcs_size = imc->imc_decoder_len;
		info.mcs_gen = imc->imc_spointers[0]->isock_gen;

		if (ddi_copyout(&info, (void *)arg, sizeof (info), mode) != 0) {
			ret = EFAULT;
			break;
		}

		ret = 0;
		break;
	case MC_IOC_DECODE_SNAPSHOT:
		imc_decoder_pack(imc);
		if (imc->imc_decoder_buf == NULL) {
			ret = EIO;
			break;
		}

		if (ddi_copyout(imc->imc_decoder_buf, (void *)arg,
		    imc->imc_decoder_len, mode) != 0) {
			ret = EFAULT;
			break;
		}

		ret = 0;
		break;
	case MC_IOC_DECODE_PA:
		if (crgetzoneid(credp) != GLOBAL_ZONEID ||
		    drv_priv(credp) != 0) {
			ret = EPERM;
			break;
		}

		if (ddi_copyin((void *)arg, &encode, sizeof (encode),
		    mode & FKIOCTL) != 0) {
			ret = EPERM;
			break;
		}

		imc_ioctl_decode(imc, &encode);
		ret = 0;

		if (ddi_copyout(&encode, (void *)arg, sizeof (encode),
		    mode & FKIOCTL) != 0) {
			ret = EPERM;
			break;
		}
		break;
	default:
		ret = EINVAL;
		goto done;
	}

done:
	mutex_exit(&imc->imc_lock);
	return (ret);
}

static int
imc_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

static int
imc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (imc_data == NULL || imc_data->imc_dip != NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&imc_data->imc_lock);
	if ((imc_data->imc_taskq = ddi_taskq_create(dip, "imc", 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		mutex_exit(&imc_data->imc_lock);
		return (DDI_FAILURE);
	}

	imc_data->imc_dip = dip;
	imc_data->imc_flags |= IMC_F_SCAN_DISPATCHED;
	mutex_exit(&imc_data->imc_lock);

	(void) ddi_taskq_dispatch(imc_data->imc_taskq, imc_stub_scan, imc_data,
	    DDI_SLEEP);

	return (DDI_SUCCESS);
}

/*
 * We only export a single instance.
 */
static int
imc_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **resultp)
{
	/*
	 * getinfo(9E) shouldn't be called if we're not attached. But be
	 * paranoid.
	 */
	if (imc_data == NULL || imc_data->imc_dip == NULL) {
		return (DDI_FAILURE);
	}

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = imc_data->imc_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)0;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
imc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (imc_data == NULL || imc_data->imc_dip) {
		return (DDI_FAILURE);
	}

	mutex_enter(&imc_data->imc_lock);

	/*
	 * While a scan or attach is outstanding, don't allow us to detach.
	 */
	if ((imc_data->imc_flags &
	    (IMC_F_SCAN_DISPATCHED | IMC_F_ATTACH_DISPATCHED)) != 0) {
		mutex_exit(&imc_data->imc_lock);
		return (DDI_FAILURE);
	}

	/*
	 * Because the stub driver depends on the imc driver, we shouldn't be
	 * able to have any entries in this list when we detach. However, we
	 * check just to make sure.
	 */
	if (!avl_is_empty(&imc_data->imc_stubs)) {
		mutex_exit(&imc_data->imc_lock);
		return (DDI_FAILURE);
	}

	nvlist_free(imc_data->imc_decoder_dump);
	imc_data->imc_decoder_dump = NULL;
	if (imc_data->imc_decoder_buf != NULL) {
		kmem_free(imc_data->imc_decoder_buf, imc_data->imc_decoder_len);
		imc_data->imc_decoder_buf = NULL;
		imc_data->imc_decoder_len = 0;
	}

	ddi_remove_minor_node(imc_data->imc_dip, NULL);
	imc_data->imc_dip = NULL;
	mutex_exit(&imc_data->imc_lock);

	ddi_taskq_wait(imc_data->imc_taskq);
	ddi_taskq_destroy(imc_data->imc_taskq);
	imc_data->imc_taskq = NULL;

	return (DDI_SUCCESS);
}

static void
imc_free(void)
{
	if (imc_data == NULL) {
		return;
	}

	VERIFY(avl_is_empty(&imc_data->imc_stubs));
	avl_destroy(&imc_data->imc_stubs);
	mutex_destroy(&imc_data->imc_lock);
	kmem_free(imc_data, sizeof (imc_t));
	imc_data = NULL;
}

static void
imc_alloc(void)
{
	imc_data = kmem_zalloc(sizeof (imc_t), KM_SLEEP);

	mutex_init(&imc_data->imc_lock, NULL, MUTEX_DRIVER, NULL);
	avl_create(&imc_data->imc_stubs, imc_stub_comparator,
	    sizeof (imc_stub_t), offsetof(imc_stub_t, istub_link));
}

static struct cb_ops imc_cb_ops = {
	.cb_open = imc_open,
	.cb_close = imc_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = imc_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops imc_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = imc_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = imc_attach,
	.devo_detach = imc_detach,
	.devo_reset = nodev,
	.devo_cb_ops = &imc_cb_ops,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv imc_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Intel Integrated Memory Controller Driver",
	.drv_dev_ops = &imc_dev_ops
};

static struct modlinkage imc_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &imc_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&imc_modlinkage)) == 0) {
		imc_alloc();
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&imc_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&imc_modlinkage)) == 0) {
		imc_free();
	}
	return (ret);
}
