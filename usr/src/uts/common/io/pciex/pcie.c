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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * PCIe Initialization
 * -------------------
 *
 * The PCIe subsystem is split about and initializes itself in a couple of
 * different places. This is due to the platform-specific nature of initializing
 * resources and the nature of the SPARC PROM and how that influenced the
 * subsystem. Note that traditional PCI (mostly seen these days in Virtual
 * Machines) follows most of the same basic path outlined here, but skips a
 * large chunk of PCIe-specific initialization.
 *
 * First, there is an initial device discovery phase that is taken care of by
 * the platform. This is where we discover the set of devices that are present
 * at system power on. These devices may or may not be hot-pluggable. In
 * particular, this happens in a platform-specific way right now. In general, we
 * expect most discovery to be driven by scanning each bus, device, and
 * function, and seeing what actually exists and responds to configuration space
 * reads. This is driven via pci_boot.c on x86. This may be seeded by something
 * like device tree, a PROM, supplemented with ACPI, or by knowledge that the
 * underlying platform has.
 *
 * As a part of this discovery process, the full set of resources that exist in
 * the system for PCIe are:
 *
 *   o PCI buses
 *   o Prefetchable Memory
 *   o Non-prefetchable memory
 *   o I/O ports
 *
 * This process is driven by a platform's PCI platform Resource Discovery (PRD)
 * module. The PRD definitions can be found in <sys/plat/pci_prd.h> and are used
 * to discover these resources, which will be converted into the initial set of
 * the standard properties in the system: 'regs', 'available', 'ranges', etc.
 * Currently it is up to platform-specific code (which should ideally be
 * consolidated at some point) to set up all these properties.
 *
 * As a part of the discovery process, the platform code will create a device
 * node (dev_info_t) for each discovered function and will create a PCIe nexus
 * for each overall root complex that exists in the system. Most root complexes
 * will have multiple root ports, each of which is the foundation of an
 * independent PCIe bus due to the point-to-point nature of PCIe. When a root
 * complex is found, a nexus driver such as npe (Nexus for PCIe Express) is
 * attached. In the case of a non-PCIe-capable system this is where the older
 * pci nexus driver would be used instead.
 *
 * To track data about a given device on a bus, a 'pcie_bus_t' structure is
 * created for and assigned to every PCIe-based dev_info_t. This can be used to
 * find the root port and get basic information about the device, its faults,
 * and related information. This contains pointers to the corresponding root
 * port as well.
 *
 * A root complex has its pcie_bus_t initialized as part of the device discovery
 * process. That is, because we're trying to bootstrap the actual tree and most
 * platforms don't have a representation for this that's explicitly
 * discoverable, this is created manually. See callers of pcie_rc_init_bus().
 *
 * For other devices, bridges, and switches, the process is split into two.
 * There is an initial pcie_bus_t that is created which will exist before we go
 * through the actual driver attachment process. For example, on x86 this is
 * done as part of the device and function discovery. The second pass of
 * initialization is done only after the nexus driver actually is attached and
 * it goes through and finishes processing all of its children.
 *
 * Child Initialization
 * --------------------
 *
 * Generally speaking, the platform will first enumerate all PCIe devices that
 * are in the sytem before it actually creates a device tree. This is part of
 * the bus/device/function scanning that is performed and from that dev_info_t
 * nodes are created for each discovered device and are inserted into the
 * broader device tree. Later in boot, the actual device tree is walked and the
 * nodes go through the standard dev_info_t initialization process (DS_PROTO,
 * DS_LINKED, DS_BOUND, etc.).
 *
 * PCIe-specific initialization can roughly be broken into the following pieces:
 *
 *   1. Platform initial discovery and resource assignment
 *   2. The pcie_bus_t initialization
 *   3. Nexus driver child initialization
 *   4. Fabric initialization
 *   5. Device driver-specific initialization
 *
 * The first part of this (1) and (2) are discussed in the previous section.
 * Part (1) in particular is a combination of the PRD (platform resource
 * discovery) and general device initialization. After this, because we have a
 * device tree, most of the standard nexus initialization happens.
 *
 * (5) is somewhat simple, so let's get into it before we discuss (3) and (4).
 * This is the last thing that is called and that happens after all of the
 * others are done. This is the logic that occurs in a driver's attach(9E) entry
 * point. This is always device-specific and generally speaking should not be
 * manipulating standard PCIe registers directly on their own. For example, the
 * MSI/MSI-X, AER, Serial Number, etc. capabilities will be automatically dealt
 * with by the framework in (3) and (4) below. In many cases, particularly
 * things that are part of (4), adjusting them in the individual driver is not
 * safe.
 *
 * Finally, let's talk about (3) and (4) as these are related. The NDI provides
 * for a standard hook for a nexus to initialize its children. In our platforms,
 * there are basically two possible PCIe nexus drivers: there is the generic
 * pcieb -- PCIe bridge -- driver which is used for standard root ports,
 * switches, etc. Then there is the platform-specific primary nexus driver,
 * which is being slowly consolidated into a single one where it makes sense. An
 * example of this is npe.
 *
 * Each of these has a child initialization function which is called from their
 * DDI_CTLOPS_INITCHILD operation on the bus_ctl function pointer. This goes
 * through and initializes a large number of different pieces of PCIe-based
 * settings through the common pcie_initchild() function. This takes care of
 * things like:
 *
 *   o Advanced Error Reporting
 *   o Alternative Routing
 *   o Capturing information around link speed, width, serial numbers, etc.
 *   o Setting common properties around aborts
 *
 * There are a few caveats with this that need to be kept in mind:
 *
 *   o A dev_info_t indicates a specific function. This means that a
 *     multi-function device will not all be initialized at the same time and
 *     there is no guarantee that all children will be initialized before one of
 *     them is attached.
 *   o A child is only initialized if we have found a driver that matches an
 *     alias in the dev_info_t's compatible array property.  While a lot of
 *     multi-function devices are often multiple instances of the same thing
 *     (e.g. a multi-port NIC with a function / NIC), this is not always the
 *     case and one cannot make any assumptions here.
 *
 * This in turn leads to the next form of initialization that takes place in the
 * case of (4). This is where we take care of things that need to be consistent
 * across either entire devices or more generally across an entire root port and
 * all of its children. There are a few different examples of this:
 *
 *   o Setting the maximum packet size
 *   o Determining the tag width
 *
 * Note that features which are only based on function 0, such as ASPM (Active
 * State Power Management), hardware autonomous width disable, etc. ultimately
 * do not go through this path today. There are some implications here in that
 * today several of these things are captured on functions which may not have
 * any control here. This is an area of needed improvement.
 *
 * The settings in (4) are initialized in a common way, via
 * pcie_fabric_setup(). This is called into from two different parts of
 * the stack:
 *
 *   1. When we attach a root port, which is driven by pcieb.
 *   2. When we have a hotplug event that adds a device.
 *
 * In general here we are going to use the term 'fabric' to refer to everything
 * that is downstream of a root port. This corresponds to what the PCIe
 * specification calls a 'hierarchy domain'. Strictly speaking, this is fine
 * until peer-to-peer requests begin to happen that cause you to need to forward
 * things across root ports. At that point the scope of the fabric increases and
 * these settings become more complicated. We currently optimize for the much
 * more common case, which is that each root port is effectively independent
 * from a PCIe transaction routing perspective.
 *
 * Put differently, we use the term 'fabric' to refer to a set of PCIe devices
 * that can route transactions to one another, which is generally constrained to
 * everything under a root port and that root ports are independent. If this
 * constraint changes, then all one needs to do is replace the discussion of the
 * root port below with the broader root complex and system.
 *
 * A challenge with these settings is that once they're set and devices are
 * actively making requests, we cannot really change them without resetting the
 * links and cancelling all outstanding transactions via device resets. Because
 * this is not something that we want to do, we instead look at how and when we
 * set this to constrain what's going on.
 *
 * Because of this we basically say that if a given fabric has more than one
 * hot-plug capable device that's encountered, then we have to use safe defaults
 * (which we can allow an operator to tune eventually via pcieadm). If we have a
 * mix of non-hotpluggable slots with downstream endpoints present and
 * hot-pluggable slots, then we're in this case. If we don't have hot-pluggable
 * slots, then we can have an arbitrarily complex setup. Let's look at a few of
 * these visually:
 *
 * In the following diagrams, RP stands for Root Port, EP stands for Endpoint.
 * If something is hot-pluggable, then we label it with (HP).
 *
 *   (1) RP --> EP
 *   (2) RP --> Switch --> EP
 *                    +--> EP
 *                    +--> EP
 *
 *   (3) RP --> Switch --> EP
 *                    +--> EP
 *                    +--> Switch --> EP
 *                               +--> EP
 *                    +--> EP
 *
 *
 *   (4) RP (HP) --> EP
 *   (5) RP (HP) --> Switch --> EP
 *                         +--> EP
 *                         +--> EP
 *
 *   (6) RP --> Switch (HP) --> EP
 *   (7) RP (HP) --> Switch (HP) --> EP
 *
 * If we look at all of these, these are all cases where it's safe for us to set
 * things based on all devices. (1), (2), and (3) are straightforward because
 * they have no hot-pluggable elements. This means that nothing should come/go
 * on the system and we can set up fabric-wide properties as part of the root
 * port.
 *
 * Case (4) is the most standard one that we encounter for hot-plug. Here you
 * have a root port directly connected to an endpoint. The most common example
 * would be an NVMe device plugged into a root port. Case (5) is interesting to
 * highlight. While there is a switch and multiple endpoints there, they are
 * showing up as a unit. This ends up being a weirder variant of (4), but it is
 * safe for us to set advanced properties because we can figure out what the
 * total set should be.
 *
 * Now, the more interesting bits here are (6) and (7). The reason that (6)
 * works is that ultimately there is only a single down-stream port here that is
 * hot-pluggable and all non-hotpluggable ports do not have a device present,
 * which suggests that they will never have a device present. (7) also could be
 * made to work by making the observation that if there's truly only one
 * endpoint in a fabric, it doesn't matter how many switches there are that are
 * hot-pluggable. This would only hold if we can assume for some reason that no
 * other endpoints could be added.
 *
 * In turn, let's look at several cases that we believe aren't safe:
 *
 *   (8) RP --> Switch --> EP
 *                    +--> EP
 *               (HP) +--> EP
 *
 *   (9) RP --> Switch (HP) +--> EP
 *                     (HP) +--> EP
 *
 *   (10) RP (HP) --> Switch (HP) +--> EP
 *                           (HP) +--> EP
 *
 * All of these are situations where it's much more explicitly unsafe. Let's
 * take (8). The problem here is that the devices on the non-hotpluggable
 * downstream switches are always there and we should assume all device drivers
 * will be active and performing I/O when the hot-pluggable slot changes. If the
 * hot-pluggable slot has a lower max payload size, then we're mostly out of
 * luck. The case of (9) is very similar to (8), just that we have more hot-plug
 * capable slots.
 *
 * Finally (10) is a case of multiple instances of hotplug. (9) and (10) are the
 * more general case of (6) and (7). While we can try to detect (6) and (7) more
 * generally or try to make it safe, we're going to start with a simpler form of
 * detection for this, which roughly follows the following rules:
 *
 *   o If there are no hot-pluggable slots in an entire fabric, then we can set
 *     all fabric properties based on device capabilities.
 *   o If we encounter a hot-pluggable slot, we can only set fabric properties
 *     based on device capabilities if:
 *
 *       1. The hotpluggable slot is a root port.
 *       2. There are no other hotpluggable devices downstream of it.
 *
 * Otherwise, if neither of the above is true, then we must use the basic PCIe
 * defaults for various fabric-wide properties (discussed below). Even in these
 * more complicated cases, device-specific properties such as the configuration
 * of AERs, ASPM, etc. are still handled in the general pcie_init_bus() and
 * related discussed earlier here.
 *
 * Because the only fabrics that we'll change are those that correspond to root
 * ports, we will only call into the actual fabric feature setup when one of
 * those changes. This has the side effect of simplifying locking. When we make
 * changes here we need to be able to hold the entire device tree under the root
 * port (including the root port and its parent). This is much harder to do
 * safely when starting in the middle of the tree.
 *
 * Handling of Specific Properties
 * -------------------------------
 *
 * This section goes into the rationale behind how we initialize and program
 * various parts of the PCIe stack.
 *
 * 5-, 8-, 10- AND 14-BIT TAGS
 *
 * Tags are part of PCIe transactions and when combined with a device identifier
 * are used to uniquely identify a transaction. In PCIe parlance, a Requester
 * (someone who initiates a PCIe request) sets a unique tag in the request and
 * the Completer (someone who processes and responds to a PCIe request) echoes
 * the tag back. This means that a requester generally is responsible for
 * ensuring that they don't reuse a tag between transactions.
 *
 * Thus the number of tags that a device has relates to the number of
 * outstanding transactions that it can have, which are usually tied to the
 * number of outstanding DMA transfers. The size of these transactions is also
 * then scoped by the handling of the Maximum Packet Payload.
 *
 * In PCIe 1.0, devices default to a 5-bit tag. There was also an option to
 * support an 8-bit tag. The 8-bit extended tag did not distinguish between a
 * Requester or Completer. There was a bit to indicate device support of 8-bit
 * tags in the Device Capabilities Register of the PCIe Capability and a
 * separate bit to enable it in the Device Control Register of the PCIe
 * Capability.
 *
 * In PCIe 4.0, support for a 10-bit tag was added. The specification broke
 * apart the support bit into multiple pieces. In particular, in the Device
 * Capabilities 2 register of the PCIe Capability there is a separate bit to
 * indicate whether the device supports 10-bit completions and 10-bit requests.
 * All PCIe 4.0 compliant devices are required to support 10-bit tags if they
 * operate at 16.0 GT/s speed (a PCIe Gen 4 compliant device does not have to
 * operate at Gen 4 speeds).
 *
 * This allows a device to support 10-bit completions but not 10-bit requests.
 * A device that supports 10-bit requests is required to support 10-bit
 * completions. There is no ability to enable or disable 10-bit completion
 * support in the Device Capabilities 2 register. There is only a bit to enable
 * 10-bit requests. This distinction makes our life easier as this means that as
 * long as the entire fabric supports 10-bit completions, it doesn't matter if
 * not all devices support 10-bit requests and we can enable them as required.
 * More on this in a bit.
 *
 * In PCIe 6.0, another set of bits was added for 14-bit tags. These follow the
 * same pattern as the 10-bit tags. The biggest difference is that the
 * capabilities and control for these are found in the Device Capabilities 3
 * and Device Control 3 register of the Device 3 Extended Capability. Similar to
 * what we see with 10-bit tags, requesters are required to support the
 * completer capability. The only control bit is for whether or not they enable
 * a 14-bit requester.
 *
 * PCIe switches which sit between root ports and endpoints and show up to
 * software as a set of bridges. Bridges generally don't have to know about tags
 * as they are usually neither requesters or completers (unless directly talking
 * to the bridge instance). That is they are generally required to forward
 * packets without modifying them. This works until we deal with switch error
 * handling. At that point, the switch may try to interpret the transaction and
 * if it doesn't understand the tagging scheme in use, return the transaction to
 * with the wrong tag and also an incorrectly diagnosed error (usually a
 * malformed TLP).
 *
 * With all this, we construct a somewhat simple policy of how and when we
 * enable extended tags:
 *
 *    o If we have a complex hotplug-capable fabric (based on the discussion
 *      earlier in fabric-specific settings), then we cannot enable any of the
 *      8-bit, 10-bit, and 14-bit tagging features. This is due to the issues
 *      with intermediate PCIe switches and related.
 *
 *    o If every device supports 8-bit capable tags, then we will go through and
 *      enable those everywhere.
 *
 *    o If every device supports 10-bit capable completions, then we will enable
 *      10-bit requester on every device that supports it.
 *
 *    o If every device supports 14-bit capable completions, then we will enable
 *      14-bit requesters on every device that supports it.
 *
 * This is the simpler end of the policy and one that is relatively easy to
 * implement. While we could attempt to relax the constraint that every device
 * in the fabric implement these features by making assumptions about peer-to-
 * peer requests (that is devices at the same layer in the tree won't talk to
 * one another), that is a lot of complexity. For now, we leave such an
 * implementation to those who need it in the future.
 *
 * MAX PAYLOAD SIZE
 *
 * When performing transactions on the PCIe bus, a given transaction has a
 * maximum allowed size. This size is called the MPS or 'Maximum Payload Size'.
 * A given device reports its maximum supported size in the Device Capabilities
 * register of the PCIe Capability. It is then set in the Device Control
 * register.
 *
 * One of the challenges with this value is that different functions of a device
 * have independent values, but strictly speaking are required to actually have
 * the same value programmed in all of them lest device behavior goes awry. When
 * a device has the ARI (alternative routing ID) capability enabled, then only
 * function 0 controls the actual payload size.
 *
 * The settings for this need to be consistent throughout the fabric. A
 * Transmitter is not allowed to create a TLP that exceeds its maximum packet
 * size and a Receiver is not allowed to receive a packet that exceeds its
 * maximum packet size. In all of these cases, this would result in something
 * like a malformed TLP error.
 *
 * Effectively, this means that everything on a given fabric must have the same
 * value programmed in its Device Control register for this value. While in the
 * case of tags, switches generally weren't completers or requesters, here every
 * device along the path is subject to this. This makes the actual value that we
 * set throughout the fabric even more important and the constraints of hotplug
 * even worse to deal with.
 *
 * Because a hotplug device can be inserted with any packet size, if we hit
 * anything other than the simple hotplug cases discussed in the fabric-specific
 * settings section, then we must use the smallest size of 128 byte payloads.
 * This is because a device could be plugged in that supports something smaller
 * than we had otherwise set. If there are other active devices, those could not
 * be changed without quiescing the entire fabric. As such our algorithm is as
 * follows:
 *
 *     1. Scan the entire fabric, keeping track of the smallest seen MPS in the
 *        Device Capabilities Register.
 *     2. If we have a complex fabric, program each Device Control register with
 *        a 128 byte maximum payload size, otherwise, program it with the
 *        discovered value.
 *
 *
 * MAX READ REQUEST SIZE
 *
 * The maximum read request size (mrrs) is a much more confusing thing when
 * compared to the maximum payload size counterpart. The maximum payload size
 * (MPS) above is what restricts the actual size of a TLP. The mrrs value
 * is used to control part of the behavior of Memory Read Request, which is not
 * strictly speaking subject to the MPS. A PCIe device is allowed to respond to
 * a Memory Read Request with less bytes than were actually requested in a
 * single completion. In general, the default size that a root complex and its
 * root port will reply to are based around the length of a cache line.
 *
 * What this ultimately controls is the number of requests that the Requester
 * has to make and trades off bandwidth, bus sharing, and related here. For
 * example, if the maximum read request size is 4 KiB, then the requester would
 * only issue a single read request asking for 4 KiB. It would still receive
 * these as multiple packets in units of the MPS. If however, the maximum read
 * request was only say 512 B, then it would need to make 8 separate requests,
 * potentially increasing latency. On the other hand, if systems are relying on
 * total requests for QoS, then it's important to set it to something that's
 * closer to the actual MPS.
 *
 * Traditionally, the OS has not been the most straightforward about this. It's
 * important to remember that setting this up is also somewhat in the realm of
 * system firmware. Due to the PCI Firmware specification, the firmware may have
 * set up a value for not just the MRRS but also the MPS. As such, our logic
 * basically left the MRRS alone and used whatever the device had there as long
 * as we weren't shrinking the device's MPS. If we were, then we'd set it to the
 * MPS. If the device was a root port, then it was just left at a system wide
 * and PCIe default of 512 bytes.
 *
 * If we survey firmware (which isn't easy due to its nature), we have seen most
 * cases where the firmware just doesn't do anything and leaves it to the
 * device's default, which is basically just the PCIe default, unless it has a
 * specific knowledge of something like say wanting to do something for an NVMe
 * device. The same is generally true of other systems, leaving it at its
 * default unless otherwise set by a device driver.
 *
 * Because this value doesn't really have the same constraints as other fabric
 * properties, this becomes much simpler and we instead opt to set it as part of
 * the device node initialization. In addition, there are no real rules about
 * different functions having different values here as it doesn't really impact
 * the TLP processing the same way that the MPS does.
 *
 * While we should add a fuller way of setting this and allowing operator
 * override of the MRRS based on things like device class, etc. that is driven
 * by pcieadm, that is left to the future. For now we opt to that all devices
 * are kept at their default (512 bytes or whatever firmware left behind) and we
 * ensure that root ports always have the mrrs set to 512.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/promif.h>
#include <sys/disp.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/pci_cap.h>
#include <sys/pci_impl.h>
#include <sys/pcie_impl.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/hotplug/pci/pciehpc.h>
#include <sys/hotplug/pci/pcishpc.h>
#include <sys/hotplug/pci/pcicfg.h>
#include <sys/pci_cfgacc.h>
#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/pcie.h>

/* Local functions prototypes */
static void pcie_init_pfd(dev_info_t *);
static void pcie_fini_pfd(dev_info_t *);

#ifdef DEBUG
uint_t pcie_debug_flags = 0;
static void pcie_print_bus(pcie_bus_t *bus_p);
void pcie_dbg(char *fmt, ...);
#endif /* DEBUG */

/* Variable to control default PCI-Express config settings */
ushort_t pcie_command_default =
    PCI_COMM_SERR_ENABLE |
    PCI_COMM_WAIT_CYC_ENAB |
    PCI_COMM_PARITY_DETECT |
    PCI_COMM_ME |
    PCI_COMM_MAE |
    PCI_COMM_IO;

/* xxx_fw are bits that are controlled by FW and should not be modified */
ushort_t pcie_command_default_fw =
    PCI_COMM_SPEC_CYC |
    PCI_COMM_MEMWR_INVAL |
    PCI_COMM_PALETTE_SNOOP |
    PCI_COMM_WAIT_CYC_ENAB |
    0xF800; /* Reserved Bits */

ushort_t pcie_bdg_command_default_fw =
    PCI_BCNF_BCNTRL_ISA_ENABLE |
    PCI_BCNF_BCNTRL_VGA_ENABLE |
    0xF000; /* Reserved Bits */

/* PCI-Express Base error defaults */
ushort_t pcie_base_err_default =
    PCIE_DEVCTL_CE_REPORTING_EN |
    PCIE_DEVCTL_NFE_REPORTING_EN |
    PCIE_DEVCTL_FE_REPORTING_EN |
    PCIE_DEVCTL_UR_REPORTING_EN;

/*
 * This contains default values and masks that are used to manipulate the device
 * control register and ensure that it is in a normal state. The mask controls
 * things that are managed by pcie_fabric_setup(), firmware, or other sources
 * and therefore should be preserved unless we're explicitly trying to change
 * it.
 */
uint16_t pcie_devctl_default = PCIE_DEVCTL_RO_EN | PCIE_DEVCTL_MAX_READ_REQ_512;
uint16_t pcie_devctl_default_mask = PCIE_DEVCTL_MAX_READ_REQ_MASK |
    PCIE_DEVCTL_MAX_PAYLOAD_MASK | PCIE_DEVCTL_EXT_TAG_FIELD_EN;

/* PCI-Express AER Root Control Register */
#define	PCIE_ROOT_SYS_ERR	(PCIE_ROOTCTL_SYS_ERR_ON_CE_EN | \
				PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN | \
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN)

ushort_t pcie_root_ctrl_default =
    PCIE_ROOTCTL_SYS_ERR_ON_CE_EN |
    PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN;

/* PCI-Express Root Error Command Register */
ushort_t pcie_root_error_cmd_default =
    PCIE_AER_RE_CMD_CE_REP_EN |
    PCIE_AER_RE_CMD_NFE_REP_EN |
    PCIE_AER_RE_CMD_FE_REP_EN;

/* ECRC settings in the PCIe AER Control Register */
uint32_t pcie_ecrc_value =
    PCIE_AER_CTL_ECRC_GEN_ENA |
    PCIE_AER_CTL_ECRC_CHECK_ENA;

/*
 * If a particular platform wants to disable certain errors such as UR/MA,
 * instead of using #defines have the platform's PCIe Root Complex driver set
 * these masks using the pcie_get_XXX_mask and pcie_set_XXX_mask functions.  For
 * x86 the closest thing to a PCIe root complex driver is NPE.	For SPARC the
 * closest PCIe root complex driver is PX.
 *
 * pcie_serr_disable_flag : disable SERR only (in RCR and command reg) x86
 * systems may want to disable SERR in general.  For root ports, enabling SERR
 * causes NMIs which are not handled and results in a watchdog timeout error.
 */
uint32_t pcie_aer_uce_mask = 0;		/* AER UE Mask */
uint32_t pcie_aer_ce_mask = 0;		/* AER CE Mask */
uint32_t pcie_aer_suce_mask = 0;	/* AER Secondary UE Mask */
uint32_t pcie_serr_disable_flag = 0;	/* Disable SERR */

/* Default severities needed for eversholt.  Error handling doesn't care */
uint32_t pcie_aer_uce_severity = PCIE_AER_UCE_MTLP | PCIE_AER_UCE_RO | \
    PCIE_AER_UCE_FCP | PCIE_AER_UCE_SD | PCIE_AER_UCE_DLP | \
    PCIE_AER_UCE_TRAINING;
uint32_t pcie_aer_suce_severity = PCIE_AER_SUCE_SERR_ASSERT | \
    PCIE_AER_SUCE_UC_ADDR_ERR | PCIE_AER_SUCE_UC_ATTR_ERR | \
    PCIE_AER_SUCE_USC_MSG_DATA_ERR;

int pcie_disable_ari = 0;

/*
 * On some platforms, such as the AMD B450 chipset, we've seen an odd
 * relationship between enabling link bandwidth notifications and AERs about
 * ECRC errors. This provides a mechanism to disable it.
 */
int pcie_disable_lbw = 0;

/*
 * Amount of time to wait for an in-progress retraining. The default is to try
 * 500 times in 10ms chunks, thus a total of 5s.
 */
uint32_t pcie_link_retrain_count = 500;
uint32_t pcie_link_retrain_delay_ms = 10;

taskq_t *pcie_link_tq;
kmutex_t pcie_link_tq_mutex;

static int pcie_link_bw_intr(dev_info_t *);
static void pcie_capture_speeds(dev_info_t *);

dev_info_t *pcie_get_rc_dip(dev_info_t *dip);

/*
 * modload support
 */

static struct modlmisc modlmisc	= {
	&mod_miscops,	/* Type	of module */
	"PCI Express Framework Module"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void	*)&modlmisc,
	NULL
};

/*
 * Global Variables needed for a non-atomic version of ddi_fm_ereport_post.
 * Currently used to send the pci.fabric ereports whose payload depends on the
 * type of PCI device it is being sent for.
 */
char		*pcie_nv_buf;
nv_alloc_t	*pcie_nvap;
nvlist_t	*pcie_nvl;

int
_init(void)
{
	int rval;

	pcie_nv_buf = kmem_alloc(ERPT_DATA_SZ, KM_SLEEP);
	pcie_nvap = fm_nva_xcreate(pcie_nv_buf, ERPT_DATA_SZ);
	pcie_nvl = fm_nvlist_create(pcie_nvap);
	mutex_init(&pcie_link_tq_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((rval = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&pcie_link_tq_mutex);
		fm_nvlist_destroy(pcie_nvl, FM_NVA_RETAIN);
		fm_nva_xdestroy(pcie_nvap);
		kmem_free(pcie_nv_buf, ERPT_DATA_SZ);
	}
	return (rval);
}

int
_fini()
{
	int		rval;

	if ((rval = mod_remove(&modlinkage)) == 0) {
		if (pcie_link_tq != NULL) {
			taskq_destroy(pcie_link_tq);
		}
		mutex_destroy(&pcie_link_tq_mutex);
		fm_nvlist_destroy(pcie_nvl, FM_NVA_RETAIN);
		fm_nva_xdestroy(pcie_nvap);
		kmem_free(pcie_nv_buf, ERPT_DATA_SZ);
	}
	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
int
pcie_init(dev_info_t *dip, caddr_t arg)
{
	int	ret = DDI_SUCCESS;

	/*
	 * Our _init function is too early to create a taskq. Create the pcie
	 * link management taskq here now instead.
	 */
	mutex_enter(&pcie_link_tq_mutex);
	if (pcie_link_tq == NULL) {
		pcie_link_tq = taskq_create("pcie_link", 1, minclsyspri, 0, 0,
		    0);
	}
	mutex_exit(&pcie_link_tq_mutex);


	/*
	 * Create a "devctl" minor node to support DEVCTL_DEVICE_*
	 * and DEVCTL_BUS_* ioctls to this bus.
	 */
	if ((ret = ddi_create_minor_node(dip, "devctl", S_IFCHR,
	    PCI_MINOR_NUM(ddi_get_instance(dip), PCI_DEVCTL_MINOR),
	    DDI_NT_NEXUS, 0)) != DDI_SUCCESS) {
		PCIE_DBG("Failed to create devctl minor node for %s%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		return (ret);
	}

	if ((ret = pcie_hp_init(dip, arg)) != DDI_SUCCESS) {
		/*
		 * On some x86 platforms, we observed unexpected hotplug
		 * initialization failures in recent years. The known cause
		 * is a hardware issue: while the problem PCI bridges have
		 * the Hotplug Capable registers set, the machine actually
		 * does not implement the expected ACPI object.
		 *
		 * We don't want to stop PCI driver attach and system boot
		 * just because of this hotplug initialization failure.
		 * Continue with a debug message printed.
		 */
		PCIE_DBG("%s%d: Failed setting hotplug framework\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

#if defined(__sparc)
		ddi_remove_minor_node(dip, "devctl");

		return (ret);
#endif /* defined(__sparc) */
	}

	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
pcie_uninit(dev_info_t *dip)
{
	int	ret = DDI_SUCCESS;

	if (pcie_ari_is_enabled(dip) == PCIE_ARI_FORW_ENABLED)
		(void) pcie_ari_disable(dip);

	if ((ret = pcie_hp_uninit(dip)) != DDI_SUCCESS) {
		PCIE_DBG("Failed to uninitialize hotplug for %s%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		return (ret);
	}

	if (pcie_link_bw_supported(dip)) {
		(void) pcie_link_bw_disable(dip);
	}

	ddi_remove_minor_node(dip, "devctl");

	return (ret);
}

/*
 * PCIe module interface for enabling hotplug interrupt.
 *
 * It should be called after pcie_init() is done and bus driver's
 * interrupt handlers have being attached.
 */
int
pcie_hpintr_enable(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	pcie_hp_ctrl_t	*ctrl_p = PCIE_GET_HP_CTRL(dip);

	if (PCIE_IS_PCIE_HOTPLUG_ENABLED(bus_p)) {
		(void) (ctrl_p->hc_ops.enable_hpc_intr)(ctrl_p);
	} else if (PCIE_IS_PCI_HOTPLUG_ENABLED(bus_p)) {
		(void) pcishpc_enable_irqs(ctrl_p);
	}
	return (DDI_SUCCESS);
}

/*
 * PCIe module interface for disabling hotplug interrupt.
 *
 * It should be called before pcie_uninit() is called and bus driver's
 * interrupt handlers is dettached.
 */
int
pcie_hpintr_disable(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	pcie_hp_ctrl_t	*ctrl_p = PCIE_GET_HP_CTRL(dip);

	if (PCIE_IS_PCIE_HOTPLUG_ENABLED(bus_p)) {
		(void) (ctrl_p->hc_ops.disable_hpc_intr)(ctrl_p);
	} else if (PCIE_IS_PCI_HOTPLUG_ENABLED(bus_p)) {
		(void) pcishpc_disable_irqs(ctrl_p);
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
pcie_intr(dev_info_t *dip)
{
	int hp, lbw;

	hp = pcie_hp_intr(dip);
	lbw = pcie_link_bw_intr(dip);

	if (hp == DDI_INTR_CLAIMED || lbw == DDI_INTR_CLAIMED) {
		return (DDI_INTR_CLAIMED);
	}

	return (DDI_INTR_UNCLAIMED);
}

/* ARGSUSED */
int
pcie_open(dev_info_t *dip, dev_t *devp, int flags, int otyp, cred_t *credp)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Handle the open by tracking the device state.
	 */
	if ((bus_p->bus_soft_state == PCI_SOFT_STATE_OPEN_EXCL) ||
	    ((flags & FEXCL) &&
	    (bus_p->bus_soft_state != PCI_SOFT_STATE_CLOSED))) {
		return (EBUSY);
	}

	if (flags & FEXCL)
		bus_p->bus_soft_state = PCI_SOFT_STATE_OPEN_EXCL;
	else
		bus_p->bus_soft_state = PCI_SOFT_STATE_OPEN;

	return (0);
}

/* ARGSUSED */
int
pcie_close(dev_info_t *dip, dev_t dev, int flags, int otyp, cred_t *credp)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	bus_p->bus_soft_state = PCI_SOFT_STATE_CLOSED;

	return (0);
}

/* ARGSUSED */
int
pcie_ioctl(dev_info_t *dip, dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	struct devctl_iocdata	*dcp;
	uint_t			bus_state;
	int			rv = DDI_SUCCESS;

	/*
	 * We can use the generic implementation for devctl ioctl
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(dip, cmd, arg, mode, 0));
	default:
		break;
	}

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {
	case DEVCTL_BUS_QUIESCE:
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_QUIESCED)
				break;
		(void) ndi_set_bus_state(dip, BUS_QUIESCED);
		break;
	case DEVCTL_BUS_UNQUIESCE:
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_ACTIVE)
				break;
		(void) ndi_set_bus_state(dip, BUS_ACTIVE);
		break;
	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:
	case DEVCTL_DEVICE_RESET:
		rv = ENOTSUP;
		break;
	default:
		rv = ENOTTY;
	}

	ndi_dc_freehdl(dcp);
	return (rv);
}

/* ARGSUSED */
int
pcie_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	if (dev == DDI_DEV_T_ANY)
		goto skip;

	if (PCIE_IS_HOTPLUG_CAPABLE(dip) &&
	    strcmp(name, "pci-occupant") == 0) {
		int	pci_dev = PCI_MINOR_NUM_TO_PCI_DEVNUM(getminor(dev));

		pcie_hp_create_occupant_props(dip, dev, pci_dev);
	}

skip:
	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}

int
pcie_init_cfghdl(dev_info_t *cdip)
{
	pcie_bus_t		*bus_p;
	ddi_acc_handle_t	eh = NULL;

	bus_p = PCIE_DIP2BUS(cdip);
	if (bus_p == NULL)
		return (DDI_FAILURE);

	/* Create an config access special to error handling */
	if (pci_config_setup(cdip, &eh) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Cannot setup config access"
		    " for BDF 0x%x\n", bus_p->bus_bdf);
		return (DDI_FAILURE);
	}

	bus_p->bus_cfg_hdl = eh;
	return (DDI_SUCCESS);
}

void
pcie_fini_cfghdl(dev_info_t *cdip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(cdip);

	pci_config_teardown(&bus_p->bus_cfg_hdl);
}

void
pcie_determine_serial(dev_info_t *dip)
{
	pcie_bus_t		*bus_p = PCIE_DIP2BUS(dip);
	ddi_acc_handle_t	h;
	uint16_t		cap;
	uchar_t			serial[8];
	uint32_t		low, high;

	if (!PCIE_IS_PCIE(bus_p))
		return;

	h = bus_p->bus_cfg_hdl;

	if ((PCI_CAP_LOCATE(h, PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_SER), &cap)) ==
	    DDI_FAILURE)
		return;

	high = PCI_XCAP_GET32(h, 0, cap, PCIE_SER_SID_UPPER_DW);
	low = PCI_XCAP_GET32(h, 0, cap, PCIE_SER_SID_LOWER_DW);

	/*
	 * Here, we're trying to figure out if we had an invalid PCIe read. From
	 * looking at the contents of the value, it can be hard to tell the
	 * difference between a value that has all 1s correctly versus if we had
	 * an error. In this case, we only assume it's invalid if both register
	 * reads are invalid. We also only use 32-bit reads as we're not sure if
	 * all devices will support these as 64-bit reads, while we know that
	 * they'll support these as 32-bit reads.
	 */
	if (high == PCI_EINVAL32 && low == PCI_EINVAL32)
		return;

	serial[0] = low & 0xff;
	serial[1] = (low >> 8) & 0xff;
	serial[2] = (low >> 16) & 0xff;
	serial[3] = (low >> 24) & 0xff;
	serial[4] = high & 0xff;
	serial[5] = (high >> 8) & 0xff;
	serial[6] = (high >> 16) & 0xff;
	serial[7] = (high >> 24) & 0xff;

	(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip, "pcie-serial",
	    serial, sizeof (serial));
}

static void
pcie_determine_aspm(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint32_t	linkcap;
	uint16_t	linkctl;

	if (!PCIE_IS_PCIE(bus_p))
		return;

	linkcap = PCIE_CAP_GET(32, bus_p, PCIE_LINKCAP);
	linkctl = PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL);

	switch (linkcap & PCIE_LINKCAP_ASPM_SUP_MASK) {
	case PCIE_LINKCAP_ASPM_SUP_L0S:
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "pcie-aspm-support", "l0s");
		break;
	case PCIE_LINKCAP_ASPM_SUP_L1:
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "pcie-aspm-support", "l1");
		break;
	case PCIE_LINKCAP_ASPM_SUP_L0S_L1:
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "pcie-aspm-support", "l0s,l1");
		break;
	default:
		return;
	}

	switch (linkctl & PCIE_LINKCTL_ASPM_CTL_MASK) {
	case PCIE_LINKCTL_ASPM_CTL_DIS:
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "pcie-aspm-state", "disabled");
		break;
	case PCIE_LINKCTL_ASPM_CTL_L0S:
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "pcie-aspm-state", "l0s");
		break;
	case PCIE_LINKCTL_ASPM_CTL_L1:
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "pcie-aspm-state", "l1");
		break;
	case PCIE_LINKCTL_ASPM_CTL_L0S_L1:
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "pcie-aspm-state", "l0s,l1");
		break;
	}
}

/*
 * PCI-Express child device initialization. Note, this only will be called on a
 * device or function if we actually attach a device driver to it.
 *
 * This function enables generic pci-express interrupts and error handling.
 * Note, tagging, the max packet size, and related are all set up before this
 * point and is performed in pcie_fabric_setup().
 *
 * @param pdip		root dip (root nexus's dip)
 * @param cdip		child's dip (device's dip)
 * @return		DDI_SUCCESS or DDI_FAILURE
 */
/* ARGSUSED */
int
pcie_initchild(dev_info_t *cdip)
{
	uint16_t		tmp16, reg16;
	pcie_bus_t		*bus_p;
	uint32_t		devid, venid;

	bus_p = PCIE_DIP2BUS(cdip);
	if (bus_p == NULL) {
		PCIE_DBG("%s: BUS not found.\n",
		    ddi_driver_name(cdip));

		return (DDI_FAILURE);
	}

	if (pcie_init_cfghdl(cdip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Update pcie_bus_t with real Vendor Id Device Id.
	 *
	 * For assigned devices in IOV environment, the OBP will return
	 * faked device id/vendor id on configration read and for both
	 * properties in root domain. translate_devid() function will
	 * update the properties with real device-id/vendor-id on such
	 * platforms, so that we can utilize the properties here to get
	 * real device-id/vendor-id and overwrite the faked ids.
	 *
	 * For unassigned devices or devices in non-IOV environment, the
	 * operation below won't make a difference.
	 *
	 * The IOV implementation only supports assignment of PCIE
	 * endpoint devices. Devices under pci-pci bridges don't need
	 * operation like this.
	 */
	devid = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "device-id", -1);
	venid = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "vendor-id", -1);
	bus_p->bus_dev_ven_id = (devid << 16) | (venid & 0xffff);

	/* Clear the device's status register */
	reg16 = PCIE_GET(16, bus_p, PCI_CONF_STAT);
	PCIE_PUT(16, bus_p, PCI_CONF_STAT, reg16);

	/* Setup the device's command register */
	reg16 = PCIE_GET(16, bus_p, PCI_CONF_COMM);
	tmp16 = (reg16 & pcie_command_default_fw) | pcie_command_default;

	if (pcie_serr_disable_flag && PCIE_IS_PCIE(bus_p))
		tmp16 &= ~PCI_COMM_SERR_ENABLE;

	PCIE_PUT(16, bus_p, PCI_CONF_COMM, tmp16);
	PCIE_DBG_CFG(cdip, bus_p, "COMMAND", 16, PCI_CONF_COMM, reg16);

	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if (PCIE_IS_BDG(bus_p)) {
		/* Clear the device's secondary status register */
		reg16 = PCIE_GET(16, bus_p, PCI_BCNF_SEC_STATUS);
		PCIE_PUT(16, bus_p, PCI_BCNF_SEC_STATUS, reg16);

		/* Setup the device's secondary command register */
		reg16 = PCIE_GET(16, bus_p, PCI_BCNF_BCNTRL);
		tmp16 = (reg16 & pcie_bdg_command_default_fw);

		tmp16 |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		/*
		 * Workaround for this Nvidia bridge. Don't enable the SERR
		 * enable bit in the bridge control register as it could lead to
		 * bogus NMIs.
		 */
		if (bus_p->bus_dev_ven_id == 0x037010DE)
			tmp16 &= ~PCI_BCNF_BCNTRL_SERR_ENABLE;

		if (pcie_command_default & PCI_COMM_PARITY_DETECT)
			tmp16 |= PCI_BCNF_BCNTRL_PARITY_ENABLE;

		/*
		 * Enable Master Abort Mode only if URs have not been masked.
		 * For PCI and PCIe-PCI bridges, enabling this bit causes a
		 * Master Aborts/UR to be forwarded as a UR/TA or SERR.  If this
		 * bit is masked, posted requests are dropped and non-posted
		 * requests are returned with -1.
		 */
		if (pcie_aer_uce_mask & PCIE_AER_UCE_UR)
			tmp16 &= ~PCI_BCNF_BCNTRL_MAST_AB_MODE;
		else
			tmp16 |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		PCIE_PUT(16, bus_p, PCI_BCNF_BCNTRL, tmp16);
		PCIE_DBG_CFG(cdip, bus_p, "SEC CMD", 16, PCI_BCNF_BCNTRL,
		    reg16);
	}

	if (PCIE_IS_PCIE(bus_p)) {
		/*
		 * Get the device control register into an initial state that
		 * makes sense. The maximum payload, tagging, and related will
		 * be dealt with in pcie_fabric_setup().
		 */
		reg16 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
		tmp16 = (reg16 & pcie_devctl_default_mask) |
		    (pcie_devctl_default & ~pcie_devctl_default_mask);
		PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, tmp16);
		PCIE_DBG_CAP(cdip, bus_p, "DEVCTL", 16, PCIE_DEVCTL, reg16);

		/* Enable PCIe errors */
		pcie_enable_errors(cdip);

		pcie_determine_serial(cdip);

		pcie_determine_aspm(cdip);

		pcie_capture_speeds(cdip);
	}

	bus_p->bus_ari = B_FALSE;
	if ((pcie_ari_is_enabled(ddi_get_parent(cdip))
	    == PCIE_ARI_FORW_ENABLED) && (pcie_ari_device(cdip)
	    == PCIE_ARI_DEVICE)) {
		bus_p->bus_ari = B_TRUE;
	}

	return (DDI_SUCCESS);
}

static void
pcie_init_pfd(dev_info_t *dip)
{
	pf_data_t	*pfd_p = PCIE_ZALLOC(pf_data_t);
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	PCIE_DIP2PFD(dip) = pfd_p;

	pfd_p->pe_bus_p = bus_p;
	pfd_p->pe_severity_flags = 0;
	pfd_p->pe_severity_mask = 0;
	pfd_p->pe_orig_severity_flags = 0;
	pfd_p->pe_lock = B_FALSE;
	pfd_p->pe_valid = B_FALSE;

	/* Allocate the root fault struct for both RC and RP */
	if (PCIE_IS_ROOT(bus_p)) {
		PCIE_ROOT_FAULT(pfd_p) = PCIE_ZALLOC(pf_root_fault_t);
		PCIE_ROOT_FAULT(pfd_p)->scan_bdf = PCIE_INVALID_BDF;
		PCIE_ROOT_EH_SRC(pfd_p) = PCIE_ZALLOC(pf_root_eh_src_t);
	}

	PCI_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_err_regs_t);
	PFD_AFFECTED_DEV(pfd_p) = PCIE_ZALLOC(pf_affected_dev_t);
	PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf = PCIE_INVALID_BDF;

	if (PCIE_IS_BDG(bus_p))
		PCI_BDG_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_bdg_err_regs_t);

	if (PCIE_IS_PCIE(bus_p)) {
		PCIE_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_err_regs_t);

		if (PCIE_IS_RP(bus_p))
			PCIE_RP_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcie_rp_err_regs_t);

		PCIE_ADV_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_adv_err_regs_t);
		PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_bdf = PCIE_INVALID_BDF;

		if (PCIE_IS_RP(bus_p)) {
			PCIE_ADV_RP_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcie_adv_rp_err_regs_t);
			PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ce_src_id =
			    PCIE_INVALID_BDF;
			PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ue_src_id =
			    PCIE_INVALID_BDF;
		} else if (PCIE_IS_PCIE_BDG(bus_p)) {
			PCIE_ADV_BDG_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcie_adv_bdg_err_regs_t);
			PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_bdf =
			    PCIE_INVALID_BDF;
		}

		if (PCIE_IS_PCIE_BDG(bus_p) && PCIE_IS_PCIX(bus_p)) {
			PCIX_BDG_ERR_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcix_bdg_err_regs_t);

			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				PCIX_BDG_ECC_REG(pfd_p, 0) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
				PCIX_BDG_ECC_REG(pfd_p, 1) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
			}
		}

		PCIE_SLOT_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_slot_regs_t);
		PCIE_SLOT_REG(pfd_p)->pcie_slot_regs_valid = B_FALSE;
		PCIE_SLOT_REG(pfd_p)->pcie_slot_cap = 0;
		PCIE_SLOT_REG(pfd_p)->pcie_slot_control = 0;
		PCIE_SLOT_REG(pfd_p)->pcie_slot_status = 0;

	} else if (PCIE_IS_PCIX(bus_p)) {
		if (PCIE_IS_BDG(bus_p)) {
			PCIX_BDG_ERR_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcix_bdg_err_regs_t);

			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				PCIX_BDG_ECC_REG(pfd_p, 0) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
				PCIX_BDG_ECC_REG(pfd_p, 1) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
			}
		} else {
			PCIX_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pcix_err_regs_t);

			if (PCIX_ECC_VERSION_CHECK(bus_p))
				PCIX_ECC_REG(pfd_p) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
		}
	}
}

static void
pcie_fini_pfd(dev_info_t *dip)
{
	pf_data_t	*pfd_p = PCIE_DIP2PFD(dip);
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_PCIE(bus_p)) {
		if (PCIE_IS_PCIE_BDG(bus_p) && PCIE_IS_PCIX(bus_p)) {
			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 0),
				    sizeof (pf_pcix_ecc_regs_t));
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 1),
				    sizeof (pf_pcix_ecc_regs_t));
			}

			kmem_free(PCIX_BDG_ERR_REG(pfd_p),
			    sizeof (pf_pcix_bdg_err_regs_t));
		}

		if (PCIE_IS_RP(bus_p))
			kmem_free(PCIE_ADV_RP_REG(pfd_p),
			    sizeof (pf_pcie_adv_rp_err_regs_t));
		else if (PCIE_IS_PCIE_BDG(bus_p))
			kmem_free(PCIE_ADV_BDG_REG(pfd_p),
			    sizeof (pf_pcie_adv_bdg_err_regs_t));

		kmem_free(PCIE_ADV_REG(pfd_p),
		    sizeof (pf_pcie_adv_err_regs_t));

		if (PCIE_IS_RP(bus_p))
			kmem_free(PCIE_RP_REG(pfd_p),
			    sizeof (pf_pcie_rp_err_regs_t));

		kmem_free(PCIE_ERR_REG(pfd_p), sizeof (pf_pcie_err_regs_t));
	} else if (PCIE_IS_PCIX(bus_p)) {
		if (PCIE_IS_BDG(bus_p)) {
			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 0),
				    sizeof (pf_pcix_ecc_regs_t));
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 1),
				    sizeof (pf_pcix_ecc_regs_t));
			}

			kmem_free(PCIX_BDG_ERR_REG(pfd_p),
			    sizeof (pf_pcix_bdg_err_regs_t));
		} else {
			if (PCIX_ECC_VERSION_CHECK(bus_p))
				kmem_free(PCIX_ECC_REG(pfd_p),
				    sizeof (pf_pcix_ecc_regs_t));

			kmem_free(PCIX_ERR_REG(pfd_p),
			    sizeof (pf_pcix_err_regs_t));
		}
	}

	if (PCIE_IS_BDG(bus_p))
		kmem_free(PCI_BDG_ERR_REG(pfd_p),
		    sizeof (pf_pci_bdg_err_regs_t));

	kmem_free(PFD_AFFECTED_DEV(pfd_p), sizeof (pf_affected_dev_t));
	kmem_free(PCI_ERR_REG(pfd_p), sizeof (pf_pci_err_regs_t));

	if (PCIE_IS_ROOT(bus_p)) {
		kmem_free(PCIE_ROOT_FAULT(pfd_p), sizeof (pf_root_fault_t));
		kmem_free(PCIE_ROOT_EH_SRC(pfd_p), sizeof (pf_root_eh_src_t));
	}

	kmem_free(PCIE_DIP2PFD(dip), sizeof (pf_data_t));

	PCIE_DIP2PFD(dip) = NULL;
}


/*
 * Special functions to allocate pf_data_t's for PCIe root complexes.
 * Note: Root Complex not Root Port
 */
void
pcie_rc_init_pfd(dev_info_t *dip, pf_data_t *pfd_p)
{
	pfd_p->pe_bus_p = PCIE_DIP2DOWNBUS(dip);
	pfd_p->pe_severity_flags = 0;
	pfd_p->pe_severity_mask = 0;
	pfd_p->pe_orig_severity_flags = 0;
	pfd_p->pe_lock = B_FALSE;
	pfd_p->pe_valid = B_FALSE;

	PCIE_ROOT_FAULT(pfd_p) = PCIE_ZALLOC(pf_root_fault_t);
	PCIE_ROOT_FAULT(pfd_p)->scan_bdf = PCIE_INVALID_BDF;
	PCIE_ROOT_EH_SRC(pfd_p) = PCIE_ZALLOC(pf_root_eh_src_t);
	PCI_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_err_regs_t);
	PFD_AFFECTED_DEV(pfd_p) = PCIE_ZALLOC(pf_affected_dev_t);
	PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf = PCIE_INVALID_BDF;
	PCI_BDG_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_bdg_err_regs_t);
	PCIE_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_err_regs_t);
	PCIE_RP_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_rp_err_regs_t);
	PCIE_ADV_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_adv_err_regs_t);
	PCIE_ADV_RP_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_adv_rp_err_regs_t);
	PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ce_src_id = PCIE_INVALID_BDF;
	PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ue_src_id = PCIE_INVALID_BDF;

	PCIE_ADV_REG(pfd_p)->pcie_ue_sev = pcie_aer_uce_severity;
}

void
pcie_rc_fini_pfd(pf_data_t *pfd_p)
{
	kmem_free(PCIE_ADV_RP_REG(pfd_p), sizeof (pf_pcie_adv_rp_err_regs_t));
	kmem_free(PCIE_ADV_REG(pfd_p), sizeof (pf_pcie_adv_err_regs_t));
	kmem_free(PCIE_RP_REG(pfd_p), sizeof (pf_pcie_rp_err_regs_t));
	kmem_free(PCIE_ERR_REG(pfd_p), sizeof (pf_pcie_err_regs_t));
	kmem_free(PCI_BDG_ERR_REG(pfd_p), sizeof (pf_pci_bdg_err_regs_t));
	kmem_free(PFD_AFFECTED_DEV(pfd_p), sizeof (pf_affected_dev_t));
	kmem_free(PCI_ERR_REG(pfd_p), sizeof (pf_pci_err_regs_t));
	kmem_free(PCIE_ROOT_FAULT(pfd_p), sizeof (pf_root_fault_t));
	kmem_free(PCIE_ROOT_EH_SRC(pfd_p), sizeof (pf_root_eh_src_t));
}

/*
 * init pcie_bus_t for root complex
 *
 * Only a few of the fields in bus_t is valid for root complex.
 * The fields that are bracketed are initialized in this routine:
 *
 * dev_info_t *		<bus_dip>
 * dev_info_t *		bus_rp_dip
 * ddi_acc_handle_t	bus_cfg_hdl
 * uint_t		<bus_fm_flags>
 * pcie_req_id_t	bus_bdf
 * pcie_req_id_t	bus_rp_bdf
 * uint32_t		bus_dev_ven_id
 * uint8_t		bus_rev_id
 * uint8_t		<bus_hdr_type>
 * uint16_t		<bus_dev_type>
 * uint8_t		bus_bdg_secbus
 * uint16_t		bus_pcie_off
 * uint16_t		<bus_aer_off>
 * uint16_t		bus_pcix_off
 * uint16_t		bus_ecc_ver
 * pci_bus_range_t	bus_bus_range
 * ppb_ranges_t	*	bus_addr_ranges
 * int			bus_addr_entries
 * pci_regspec_t *	bus_assigned_addr
 * int			bus_assigned_entries
 * pf_data_t *		bus_pfd
 * pcie_domain_t *	<bus_dom>
 * int			bus_mps
 * uint64_t		bus_cfgacc_base
 * void	*		bus_plat_private
 */
void
pcie_rc_init_bus(dev_info_t *dip)
{
	pcie_bus_t *bus_p;

	bus_p = (pcie_bus_t *)kmem_zalloc(sizeof (pcie_bus_t), KM_SLEEP);
	bus_p->bus_dip = dip;
	bus_p->bus_dev_type = PCIE_PCIECAP_DEV_TYPE_RC_PSEUDO;
	bus_p->bus_hdr_type = PCI_HEADER_ONE;

	/* Fake that there are AER logs */
	bus_p->bus_aer_off = (uint16_t)-1;

	/* Needed only for handle lookup */
	atomic_or_uint(&bus_p->bus_fm_flags, PF_FM_READY);

	ndi_set_bus_private(dip, B_FALSE, DEVI_PORT_TYPE_PCI, bus_p);

	PCIE_BUS2DOM(bus_p) = PCIE_ZALLOC(pcie_domain_t);
}

void
pcie_rc_fini_bus(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2DOWNBUS(dip);
	ndi_set_bus_private(dip, B_FALSE, 0, NULL);
	kmem_free(PCIE_BUS2DOM(bus_p), sizeof (pcie_domain_t));
	kmem_free(bus_p, sizeof (pcie_bus_t));
}

static int
pcie_width_to_int(pcie_link_width_t width)
{
	switch (width) {
	case PCIE_LINK_WIDTH_X1:
		return (1);
	case PCIE_LINK_WIDTH_X2:
		return (2);
	case PCIE_LINK_WIDTH_X4:
		return (4);
	case PCIE_LINK_WIDTH_X8:
		return (8);
	case PCIE_LINK_WIDTH_X12:
		return (12);
	case PCIE_LINK_WIDTH_X16:
		return (16);
	case PCIE_LINK_WIDTH_X32:
		return (32);
	default:
		return (0);
	}
}

/*
 * Return the speed in Transfers / second. This is a signed quantity to match
 * the ndi/ddi property interfaces.
 */
static int64_t
pcie_speed_to_int(pcie_link_speed_t speed)
{
	switch (speed) {
	case PCIE_LINK_SPEED_2_5:
		return (2500000000LL);
	case PCIE_LINK_SPEED_5:
		return (5000000000LL);
	case PCIE_LINK_SPEED_8:
		return (8000000000LL);
	case PCIE_LINK_SPEED_16:
		return (16000000000LL);
	case PCIE_LINK_SPEED_32:
		return (32000000000LL);
	case PCIE_LINK_SPEED_64:
		return (64000000000LL);
	default:
		return (0);
	}
}

/*
 * Translate the recorded speed information into devinfo properties.
 */
static void
pcie_speeds_to_devinfo(dev_info_t *dip, pcie_bus_t *bus_p)
{
	if (bus_p->bus_max_width != PCIE_LINK_WIDTH_UNKNOWN) {
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "pcie-link-maximum-width",
		    pcie_width_to_int(bus_p->bus_max_width));
	}

	if (bus_p->bus_cur_width != PCIE_LINK_WIDTH_UNKNOWN) {
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "pcie-link-current-width",
		    pcie_width_to_int(bus_p->bus_cur_width));
	}

	if (bus_p->bus_cur_speed != PCIE_LINK_SPEED_UNKNOWN) {
		(void) ndi_prop_update_int64(DDI_DEV_T_NONE, dip,
		    "pcie-link-current-speed",
		    pcie_speed_to_int(bus_p->bus_cur_speed));
	}

	if (bus_p->bus_max_speed != PCIE_LINK_SPEED_UNKNOWN) {
		(void) ndi_prop_update_int64(DDI_DEV_T_NONE, dip,
		    "pcie-link-maximum-speed",
		    pcie_speed_to_int(bus_p->bus_max_speed));
	}

	if (bus_p->bus_target_speed != PCIE_LINK_SPEED_UNKNOWN) {
		(void) ndi_prop_update_int64(DDI_DEV_T_NONE, dip,
		    "pcie-link-target-speed",
		    pcie_speed_to_int(bus_p->bus_target_speed));
	}

	if ((bus_p->bus_speed_flags & PCIE_LINK_F_ADMIN_TARGET) != 0) {
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "pcie-link-admin-target-speed");
	}

	if (bus_p->bus_sup_speed != PCIE_LINK_SPEED_UNKNOWN) {
		int64_t speeds[PCIE_NSPEEDS];
		uint_t nspeeds = 0;

		if (bus_p->bus_sup_speed & PCIE_LINK_SPEED_2_5) {
			speeds[nspeeds++] =
			    pcie_speed_to_int(PCIE_LINK_SPEED_2_5);
		}

		if (bus_p->bus_sup_speed & PCIE_LINK_SPEED_5) {
			speeds[nspeeds++] =
			    pcie_speed_to_int(PCIE_LINK_SPEED_5);
		}

		if (bus_p->bus_sup_speed & PCIE_LINK_SPEED_8) {
			speeds[nspeeds++] =
			    pcie_speed_to_int(PCIE_LINK_SPEED_8);
		}

		if (bus_p->bus_sup_speed & PCIE_LINK_SPEED_16) {
			speeds[nspeeds++] =
			    pcie_speed_to_int(PCIE_LINK_SPEED_16);
		}

		if (bus_p->bus_sup_speed & PCIE_LINK_SPEED_32) {
			speeds[nspeeds++] =
			    pcie_speed_to_int(PCIE_LINK_SPEED_32);
		}

		if (bus_p->bus_sup_speed & PCIE_LINK_SPEED_64) {
			speeds[nspeeds++] =
			    pcie_speed_to_int(PCIE_LINK_SPEED_64);
		}

		(void) ndi_prop_update_int64_array(DDI_DEV_T_NONE, dip,
		    "pcie-link-supported-speeds", speeds, nspeeds);
	}
}

/*
 * We need to capture the supported, maximum, and current device speed and
 * width. The way that this has been done has changed over time.
 *
 * Prior to PCIe Gen 3, there were only current and supported speed fields.
 * These were found in the link status and link capabilities registers of the
 * PCI express capability. With the change to PCIe Gen 3, the information in the
 * link capabilities changed to the maximum value. The supported speeds vector
 * was moved to the link capabilities 2 register.
 *
 * Now, a device may not implement some of these registers. To determine whether
 * or not it's here, we have to do the following. First, we need to check the
 * revision of the PCI express capability. The link capabilities 2 register did
 * not exist prior to version 2 of this capability. If a modern device does not
 * implement it, it is supposed to return zero for the register.
 */
static void
pcie_capture_speeds(dev_info_t *dip)
{
	uint16_t	vers, status;
	uint32_t	cap, cap2, ctl2;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	dev_info_t	*rcdip;

	if (!PCIE_IS_PCIE(bus_p))
		return;

	rcdip = pcie_get_rc_dip(dip);
	if (bus_p->bus_cfg_hdl == NULL) {
		vers = pci_cfgacc_get16(rcdip, bus_p->bus_bdf,
		    bus_p->bus_pcie_off + PCIE_PCIECAP);
	} else {
		vers = PCIE_CAP_GET(16, bus_p, PCIE_PCIECAP);
	}
	if (vers == PCI_EINVAL16)
		return;
	vers &= PCIE_PCIECAP_VER_MASK;

	/*
	 * Verify the capability's version.
	 */
	switch (vers) {
	case PCIE_PCIECAP_VER_1_0:
		cap2 = 0;
		ctl2 = 0;
		break;
	case PCIE_PCIECAP_VER_2_0:
		if (bus_p->bus_cfg_hdl == NULL) {
			cap2 = pci_cfgacc_get32(rcdip, bus_p->bus_bdf,
			    bus_p->bus_pcie_off + PCIE_LINKCAP2);
			ctl2 = pci_cfgacc_get16(rcdip, bus_p->bus_bdf,
			    bus_p->bus_pcie_off + PCIE_LINKCTL2);
		} else {
			cap2 = PCIE_CAP_GET(32, bus_p, PCIE_LINKCAP2);
			ctl2 = PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL2);
		}
		if (cap2 == PCI_EINVAL32)
			cap2 = 0;
		if (ctl2 == PCI_EINVAL16)
			ctl2 = 0;
		break;
	default:
		/* Don't try and handle an unknown version */
		return;
	}

	if (bus_p->bus_cfg_hdl == NULL) {
		status = pci_cfgacc_get16(rcdip, bus_p->bus_bdf,
		    bus_p->bus_pcie_off + PCIE_LINKSTS);
		cap = pci_cfgacc_get32(rcdip, bus_p->bus_bdf,
		    bus_p->bus_pcie_off + PCIE_LINKCAP);
	} else {
		status = PCIE_CAP_GET(16, bus_p, PCIE_LINKSTS);
		cap = PCIE_CAP_GET(32, bus_p, PCIE_LINKCAP);
	}
	if (status == PCI_EINVAL16 || cap == PCI_EINVAL32)
		return;

	mutex_enter(&bus_p->bus_speed_mutex);

	switch (status & PCIE_LINKSTS_SPEED_MASK) {
	case PCIE_LINKSTS_SPEED_2_5:
		bus_p->bus_cur_speed = PCIE_LINK_SPEED_2_5;
		break;
	case PCIE_LINKSTS_SPEED_5:
		bus_p->bus_cur_speed = PCIE_LINK_SPEED_5;
		break;
	case PCIE_LINKSTS_SPEED_8:
		bus_p->bus_cur_speed = PCIE_LINK_SPEED_8;
		break;
	case PCIE_LINKSTS_SPEED_16:
		bus_p->bus_cur_speed = PCIE_LINK_SPEED_16;
		break;
	case PCIE_LINKSTS_SPEED_32:
		bus_p->bus_cur_speed = PCIE_LINK_SPEED_32;
		break;
	case PCIE_LINKSTS_SPEED_64:
		bus_p->bus_cur_speed = PCIE_LINK_SPEED_64;
		break;
	default:
		bus_p->bus_cur_speed = PCIE_LINK_SPEED_UNKNOWN;
		break;
	}

	switch (status & PCIE_LINKSTS_NEG_WIDTH_MASK) {
	case PCIE_LINKSTS_NEG_WIDTH_X1:
		bus_p->bus_cur_width = PCIE_LINK_WIDTH_X1;
		break;
	case PCIE_LINKSTS_NEG_WIDTH_X2:
		bus_p->bus_cur_width = PCIE_LINK_WIDTH_X2;
		break;
	case PCIE_LINKSTS_NEG_WIDTH_X4:
		bus_p->bus_cur_width = PCIE_LINK_WIDTH_X4;
		break;
	case PCIE_LINKSTS_NEG_WIDTH_X8:
		bus_p->bus_cur_width = PCIE_LINK_WIDTH_X8;
		break;
	case PCIE_LINKSTS_NEG_WIDTH_X12:
		bus_p->bus_cur_width = PCIE_LINK_WIDTH_X12;
		break;
	case PCIE_LINKSTS_NEG_WIDTH_X16:
		bus_p->bus_cur_width = PCIE_LINK_WIDTH_X16;
		break;
	case PCIE_LINKSTS_NEG_WIDTH_X32:
		bus_p->bus_cur_width = PCIE_LINK_WIDTH_X32;
		break;
	default:
		bus_p->bus_cur_width = PCIE_LINK_WIDTH_UNKNOWN;
		break;
	}

	switch (cap & PCIE_LINKCAP_MAX_WIDTH_MASK) {
	case PCIE_LINKCAP_MAX_WIDTH_X1:
		bus_p->bus_max_width = PCIE_LINK_WIDTH_X1;
		break;
	case PCIE_LINKCAP_MAX_WIDTH_X2:
		bus_p->bus_max_width = PCIE_LINK_WIDTH_X2;
		break;
	case PCIE_LINKCAP_MAX_WIDTH_X4:
		bus_p->bus_max_width = PCIE_LINK_WIDTH_X4;
		break;
	case PCIE_LINKCAP_MAX_WIDTH_X8:
		bus_p->bus_max_width = PCIE_LINK_WIDTH_X8;
		break;
	case PCIE_LINKCAP_MAX_WIDTH_X12:
		bus_p->bus_max_width = PCIE_LINK_WIDTH_X12;
		break;
	case PCIE_LINKCAP_MAX_WIDTH_X16:
		bus_p->bus_max_width = PCIE_LINK_WIDTH_X16;
		break;
	case PCIE_LINKCAP_MAX_WIDTH_X32:
		bus_p->bus_max_width = PCIE_LINK_WIDTH_X32;
		break;
	default:
		bus_p->bus_max_width = PCIE_LINK_WIDTH_UNKNOWN;
		break;
	}

	/*
	 * If we have the Link Capabilities 2, then we can get the supported
	 * speeds from it and treat the bits in Link Capabilities 1 as the
	 * maximum. If we don't, then we need to follow the Implementation Note
	 * in the standard under Link Capabilities 2. Effectively, this means
	 * that if the value of 10b is set in Link Capabilities register, that
	 * it supports both 2.5 and 5 GT/s speeds.
	 */
	if (cap2 != 0) {
		if (cap2 & PCIE_LINKCAP2_SPEED_2_5)
			bus_p->bus_sup_speed |= PCIE_LINK_SPEED_2_5;
		if (cap2 & PCIE_LINKCAP2_SPEED_5)
			bus_p->bus_sup_speed |= PCIE_LINK_SPEED_5;
		if (cap2 & PCIE_LINKCAP2_SPEED_8)
			bus_p->bus_sup_speed |= PCIE_LINK_SPEED_8;
		if (cap2 & PCIE_LINKCAP2_SPEED_16)
			bus_p->bus_sup_speed |= PCIE_LINK_SPEED_16;
		if (cap2 & PCIE_LINKCAP2_SPEED_32)
			bus_p->bus_sup_speed |= PCIE_LINK_SPEED_32;
		if (cap2 & PCIE_LINKCAP2_SPEED_64)
			bus_p->bus_sup_speed |= PCIE_LINK_SPEED_64;

		switch (cap & PCIE_LINKCAP_MAX_SPEED_MASK) {
		case PCIE_LINKCAP_MAX_SPEED_2_5:
			bus_p->bus_max_speed = PCIE_LINK_SPEED_2_5;
			break;
		case PCIE_LINKCAP_MAX_SPEED_5:
			bus_p->bus_max_speed = PCIE_LINK_SPEED_5;
			break;
		case PCIE_LINKCAP_MAX_SPEED_8:
			bus_p->bus_max_speed = PCIE_LINK_SPEED_8;
			break;
		case PCIE_LINKCAP_MAX_SPEED_16:
			bus_p->bus_max_speed = PCIE_LINK_SPEED_16;
			break;
		case PCIE_LINKCAP_MAX_SPEED_32:
			bus_p->bus_max_speed = PCIE_LINK_SPEED_32;
			break;
		case PCIE_LINKCAP_MAX_SPEED_64:
			bus_p->bus_max_speed = PCIE_LINK_SPEED_64;
			break;
		default:
			bus_p->bus_max_speed = PCIE_LINK_SPEED_UNKNOWN;
			break;
		}
	} else {
		if (cap & PCIE_LINKCAP_MAX_SPEED_5) {
			bus_p->bus_max_speed = PCIE_LINK_SPEED_5;
			bus_p->bus_sup_speed = PCIE_LINK_SPEED_2_5 |
			    PCIE_LINK_SPEED_5;
		} else if (cap & PCIE_LINKCAP_MAX_SPEED_2_5) {
			bus_p->bus_max_speed = PCIE_LINK_SPEED_2_5;
			bus_p->bus_sup_speed = PCIE_LINK_SPEED_2_5;
		}
	}

	switch (ctl2 & PCIE_LINKCTL2_TARGET_SPEED_MASK) {
	case PCIE_LINKCTL2_TARGET_SPEED_2_5:
		bus_p->bus_target_speed = PCIE_LINK_SPEED_2_5;
		break;
	case PCIE_LINKCTL2_TARGET_SPEED_5:
		bus_p->bus_target_speed = PCIE_LINK_SPEED_5;
		break;
	case PCIE_LINKCTL2_TARGET_SPEED_8:
		bus_p->bus_target_speed = PCIE_LINK_SPEED_8;
		break;
	case PCIE_LINKCTL2_TARGET_SPEED_16:
		bus_p->bus_target_speed = PCIE_LINK_SPEED_16;
		break;
	case PCIE_LINKCTL2_TARGET_SPEED_32:
		bus_p->bus_target_speed = PCIE_LINK_SPEED_32;
		break;
	case PCIE_LINKCTL2_TARGET_SPEED_64:
		bus_p->bus_target_speed = PCIE_LINK_SPEED_64;
		break;
	default:
		bus_p->bus_target_speed = PCIE_LINK_SPEED_UNKNOWN;
		break;
	}

	pcie_speeds_to_devinfo(dip, bus_p);
	mutex_exit(&bus_p->bus_speed_mutex);
}

/*
 * partially init pcie_bus_t for device (dip,bdf) for accessing pci
 * config space
 *
 * This routine is invoked during boot, either after creating a devinfo node
 * (x86 case) or during px driver attach (sparc case); it is also invoked
 * in hotplug context after a devinfo node is created.
 *
 * The fields that are bracketed are initialized if flag PCIE_BUS_INITIAL
 * is set:
 *
 * dev_info_t *		<bus_dip>
 * dev_info_t *		<bus_rp_dip>
 * ddi_acc_handle_t	bus_cfg_hdl
 * uint_t		bus_fm_flags
 * pcie_req_id_t	<bus_bdf>
 * pcie_req_id_t	<bus_rp_bdf>
 * uint32_t		<bus_dev_ven_id>
 * uint8_t		<bus_rev_id>
 * uint8_t		<bus_hdr_type>
 * uint16_t		<bus_dev_type>
 * uint8_t		<bus_bdg_secbus
 * uint16_t		<bus_pcie_off>
 * uint16_t		<bus_aer_off>
 * uint16_t		<bus_pcix_off>
 * uint16_t		<bus_ecc_ver>
 * pci_bus_range_t	bus_bus_range
 * ppb_ranges_t	*	bus_addr_ranges
 * int			bus_addr_entries
 * pci_regspec_t *	bus_assigned_addr
 * int			bus_assigned_entries
 * pf_data_t *		bus_pfd
 * pcie_domain_t *	bus_dom
 * int			bus_mps
 * uint64_t		bus_cfgacc_base
 * void	*		bus_plat_private
 *
 * The fields that are bracketed are initialized if flag PCIE_BUS_FINAL
 * is set:
 *
 * dev_info_t *		bus_dip
 * dev_info_t *		bus_rp_dip
 * ddi_acc_handle_t	bus_cfg_hdl
 * uint_t		bus_fm_flags
 * pcie_req_id_t	bus_bdf
 * pcie_req_id_t	bus_rp_bdf
 * uint32_t		bus_dev_ven_id
 * uint8_t		bus_rev_id
 * uint8_t		bus_hdr_type
 * uint16_t		bus_dev_type
 * uint8_t		<bus_bdg_secbus>
 * uint16_t		bus_pcie_off
 * uint16_t		bus_aer_off
 * uint16_t		bus_pcix_off
 * uint16_t		bus_ecc_ver
 * pci_bus_range_t	<bus_bus_range>
 * ppb_ranges_t	*	<bus_addr_ranges>
 * int			<bus_addr_entries>
 * pci_regspec_t *	<bus_assigned_addr>
 * int			<bus_assigned_entries>
 * pf_data_t *		<bus_pfd>
 * pcie_domain_t *	bus_dom
 * int			bus_mps
 * uint64_t		bus_cfgacc_base
 * void	*		<bus_plat_private>
 */

pcie_bus_t *
pcie_init_bus(dev_info_t *dip, pcie_req_id_t bdf, uint8_t flags)
{
	uint16_t	status, base, baseptr, num_cap;
	uint32_t	capid;
	int		range_size;
	pcie_bus_t	*bus_p = NULL;
	dev_info_t	*rcdip;
	dev_info_t	*pdip;
	const char	*errstr = NULL;

	if (!(flags & PCIE_BUS_INITIAL))
		goto initial_done;

	bus_p = kmem_zalloc(sizeof (pcie_bus_t), KM_SLEEP);

	bus_p->bus_dip = dip;
	bus_p->bus_bdf = bdf;

	rcdip = pcie_get_rc_dip(dip);
	ASSERT(rcdip != NULL);

	/* Save the Vendor ID, Device ID and revision ID */
	bus_p->bus_dev_ven_id = pci_cfgacc_get32(rcdip, bdf, PCI_CONF_VENID);
	bus_p->bus_rev_id = pci_cfgacc_get8(rcdip, bdf, PCI_CONF_REVID);
	/* Save the Header Type */
	bus_p->bus_hdr_type = pci_cfgacc_get8(rcdip, bdf, PCI_CONF_HEADER);
	bus_p->bus_hdr_type &= PCI_HEADER_TYPE_M;

	/*
	 * Figure out the device type and all the relavant capability offsets
	 */
	/* set default value */
	bus_p->bus_dev_type = PCIE_PCIECAP_DEV_TYPE_PCI_PSEUDO;

	status = pci_cfgacc_get16(rcdip, bdf, PCI_CONF_STAT);
	if (status == PCI_CAP_EINVAL16 || !(status & PCI_STAT_CAP))
		goto caps_done; /* capability not supported */

	/* Relevant conventional capabilities first */

	/* Conventional caps: PCI_CAP_ID_PCI_E, PCI_CAP_ID_PCIX */
	num_cap = 2;

	switch (bus_p->bus_hdr_type) {
	case PCI_HEADER_ZERO:
		baseptr = PCI_CONF_CAP_PTR;
		break;
	case PCI_HEADER_PPB:
		baseptr = PCI_BCNF_CAP_PTR;
		break;
	case PCI_HEADER_CARDBUS:
		baseptr = PCI_CBUS_CAP_PTR;
		break;
	default:
		cmn_err(CE_WARN, "%s: unexpected pci header type:%x",
		    __func__, bus_p->bus_hdr_type);
		goto caps_done;
	}

	base = baseptr;
	for (base = pci_cfgacc_get8(rcdip, bdf, base); base && num_cap;
	    base = pci_cfgacc_get8(rcdip, bdf, base + PCI_CAP_NEXT_PTR)) {
		capid = pci_cfgacc_get8(rcdip, bdf, base);
		uint16_t pcap;

		switch (capid) {
		case PCI_CAP_ID_PCI_E:
			bus_p->bus_pcie_off = base;
			pcap = pci_cfgacc_get16(rcdip, bdf, base +
			    PCIE_PCIECAP);
			bus_p->bus_dev_type = pcap & PCIE_PCIECAP_DEV_TYPE_MASK;
			bus_p->bus_pcie_vers = pcap & PCIE_PCIECAP_VER_MASK;

			/* Check and save PCIe hotplug capability information */
			if ((PCIE_IS_RP(bus_p) || PCIE_IS_SWD(bus_p)) &&
			    (pci_cfgacc_get16(rcdip, bdf, base + PCIE_PCIECAP)
			    & PCIE_PCIECAP_SLOT_IMPL) &&
			    (pci_cfgacc_get32(rcdip, bdf, base + PCIE_SLOTCAP)
			    & PCIE_SLOTCAP_HP_CAPABLE))
				bus_p->bus_hp_sup_modes |= PCIE_NATIVE_HP_MODE;

			num_cap--;
			break;
		case PCI_CAP_ID_PCIX:
			bus_p->bus_pcix_off = base;
			if (PCIE_IS_BDG(bus_p))
				bus_p->bus_ecc_ver =
				    pci_cfgacc_get16(rcdip, bdf, base +
				    PCI_PCIX_SEC_STATUS) & PCI_PCIX_VER_MASK;
			else
				bus_p->bus_ecc_ver =
				    pci_cfgacc_get16(rcdip, bdf, base +
				    PCI_PCIX_COMMAND) & PCI_PCIX_VER_MASK;
			num_cap--;
			break;
		default:
			break;
		}
	}

	/* Check and save PCI hotplug (SHPC) capability information */
	if (PCIE_IS_BDG(bus_p)) {
		base = baseptr;
		for (base = pci_cfgacc_get8(rcdip, bdf, base);
		    base; base = pci_cfgacc_get8(rcdip, bdf,
		    base + PCI_CAP_NEXT_PTR)) {
			capid = pci_cfgacc_get8(rcdip, bdf, base);
			if (capid == PCI_CAP_ID_PCI_HOTPLUG) {
				bus_p->bus_pci_hp_off = base;
				bus_p->bus_hp_sup_modes |= PCIE_PCI_HP_MODE;
				break;
			}
		}
	}

	/* Then, relevant extended capabilities */

	if (!PCIE_IS_PCIE(bus_p))
		goto caps_done;

	/* Extended caps: PCIE_EXT_CAP_ID_AER */
	for (base = PCIE_EXT_CAP; base; base = (capid >>
	    PCIE_EXT_CAP_NEXT_PTR_SHIFT) & PCIE_EXT_CAP_NEXT_PTR_MASK) {
		capid = pci_cfgacc_get32(rcdip, bdf, base);
		if (capid == PCI_CAP_EINVAL32)
			break;
		switch ((capid >> PCIE_EXT_CAP_ID_SHIFT) &
		    PCIE_EXT_CAP_ID_MASK) {
		case PCIE_EXT_CAP_ID_AER:
			bus_p->bus_aer_off = base;
			break;
		case PCIE_EXT_CAP_ID_DEV3:
			bus_p->bus_dev3_off = base;
			break;
		}
	}

caps_done:
	/* save RP dip and RP bdf */
	if (PCIE_IS_RP(bus_p)) {
		bus_p->bus_rp_dip = dip;
		bus_p->bus_rp_bdf = bus_p->bus_bdf;

		bus_p->bus_fab = PCIE_ZALLOC(pcie_fabric_data_t);
	} else {
		for (pdip = ddi_get_parent(dip); pdip;
		    pdip = ddi_get_parent(pdip)) {
			pcie_bus_t *parent_bus_p = PCIE_DIP2BUS(pdip);

			/*
			 * If RP dip and RP bdf in parent's bus_t have
			 * been initialized, simply use these instead of
			 * continuing up to the RC.
			 */
			if (parent_bus_p->bus_rp_dip != NULL) {
				bus_p->bus_rp_dip = parent_bus_p->bus_rp_dip;
				bus_p->bus_rp_bdf = parent_bus_p->bus_rp_bdf;
				break;
			}

			/*
			 * When debugging be aware that some NVIDIA x86
			 * architectures have 2 nodes for each RP, One at Bus
			 * 0x0 and one at Bus 0x80.  The requester is from Bus
			 * 0x80
			 */
			if (PCIE_IS_ROOT(parent_bus_p)) {
				bus_p->bus_rp_dip = pdip;
				bus_p->bus_rp_bdf = parent_bus_p->bus_bdf;
				break;
			}
		}
	}

	bus_p->bus_soft_state = PCI_SOFT_STATE_CLOSED;
	(void) atomic_swap_uint(&bus_p->bus_fm_flags, 0);

	ndi_set_bus_private(dip, B_TRUE, DEVI_PORT_TYPE_PCI, (void *)bus_p);

	if (PCIE_IS_HOTPLUG_CAPABLE(dip))
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "hotplug-capable");

initial_done:
	if (!(flags & PCIE_BUS_FINAL))
		goto final_done;

	/* already initialized? */
	bus_p = PCIE_DIP2BUS(dip);

	/* Save the Range information if device is a switch/bridge */
	if (PCIE_IS_BDG(bus_p)) {
		/* get "bus_range" property */
		range_size = sizeof (pci_bus_range_t);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "bus-range", (caddr_t)&bus_p->bus_bus_range, &range_size)
		    != DDI_PROP_SUCCESS) {
			errstr = "Cannot find \"bus-range\" property";
			cmn_err(CE_WARN,
			    "PCIE init err info failed BDF 0x%x:%s\n",
			    bus_p->bus_bdf, errstr);
		}

		/* get secondary bus number */
		rcdip = pcie_get_rc_dip(dip);
		ASSERT(rcdip != NULL);

		bus_p->bus_bdg_secbus = pci_cfgacc_get8(rcdip,
		    bus_p->bus_bdf, PCI_BCNF_SECBUS);

		/* Get "ranges" property */
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "ranges", (caddr_t)&bus_p->bus_addr_ranges,
		    &bus_p->bus_addr_entries) != DDI_PROP_SUCCESS)
			bus_p->bus_addr_entries = 0;
		bus_p->bus_addr_entries /= sizeof (ppb_ranges_t);
	}

	/* save "assigned-addresses" property array, ignore failues */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&bus_p->bus_assigned_addr,
	    &bus_p->bus_assigned_entries) == DDI_PROP_SUCCESS)
		bus_p->bus_assigned_entries /= sizeof (pci_regspec_t);
	else
		bus_p->bus_assigned_entries = 0;

	pcie_init_pfd(dip);

	pcie_init_plat(dip);

	pcie_capture_speeds(dip);

final_done:

	PCIE_DBG("Add %s(dip 0x%p, bdf 0x%x, secbus 0x%x)\n",
	    ddi_driver_name(dip), (void *)dip, bus_p->bus_bdf,
	    bus_p->bus_bdg_secbus);
#ifdef DEBUG
	if (bus_p != NULL) {
		pcie_print_bus(bus_p);
	}
#endif

	return (bus_p);
}

/*
 * Invoked before destroying devinfo node, mostly during hotplug
 * operation to free pcie_bus_t data structure
 */
/* ARGSUSED */
void
pcie_fini_bus(dev_info_t *dip, uint8_t flags)
{
	pcie_bus_t *bus_p = PCIE_DIP2UPBUS(dip);
	ASSERT(bus_p);

	if (flags & PCIE_BUS_INITIAL) {
		pcie_fini_plat(dip);
		pcie_fini_pfd(dip);

		if (PCIE_IS_RP(bus_p)) {
			kmem_free(bus_p->bus_fab, sizeof (pcie_fabric_data_t));
			bus_p->bus_fab = NULL;
		}

		kmem_free(bus_p->bus_assigned_addr,
		    (sizeof (pci_regspec_t) * bus_p->bus_assigned_entries));
		kmem_free(bus_p->bus_addr_ranges,
		    (sizeof (ppb_ranges_t) * bus_p->bus_addr_entries));
		/* zero out the fields that have been destroyed */
		bus_p->bus_assigned_addr = NULL;
		bus_p->bus_addr_ranges = NULL;
		bus_p->bus_assigned_entries = 0;
		bus_p->bus_addr_entries = 0;
	}

	if (flags & PCIE_BUS_FINAL) {
		if (PCIE_IS_HOTPLUG_CAPABLE(dip)) {
			(void) ndi_prop_remove(DDI_DEV_T_NONE, dip,
			    "hotplug-capable");
		}

		ndi_set_bus_private(dip, B_TRUE, 0, NULL);
		kmem_free(bus_p, sizeof (pcie_bus_t));
	}
}

int
pcie_postattach_child(dev_info_t *cdip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(cdip);

	if (!bus_p)
		return (DDI_FAILURE);

	return (pcie_enable_ce(cdip));
}

/*
 * PCI-Express child device de-initialization.
 * This function disables generic pci-express interrupts and error
 * handling.
 */
void
pcie_uninitchild(dev_info_t *cdip)
{
	pcie_disable_errors(cdip);
	pcie_fini_cfghdl(cdip);
	pcie_fini_dom(cdip);
}

/*
 * find the root complex dip
 */
dev_info_t *
pcie_get_rc_dip(dev_info_t *dip)
{
	dev_info_t *rcdip;
	pcie_bus_t *rc_bus_p;

	for (rcdip = ddi_get_parent(dip); rcdip;
	    rcdip = ddi_get_parent(rcdip)) {
		rc_bus_p = PCIE_DIP2BUS(rcdip);
		if (rc_bus_p && PCIE_IS_RC(rc_bus_p))
			break;
	}

	return (rcdip);
}

boolean_t
pcie_is_pci_device(dev_info_t *dip)
{
	dev_info_t	*pdip;
	char		*device_type;

	pdip = ddi_get_parent(dip);
	if (pdip == NULL)
		return (B_FALSE);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS,
	    "device_type", &device_type) != DDI_PROP_SUCCESS)
		return (B_FALSE);

	if (strcmp(device_type, "pciex") != 0 &&
	    strcmp(device_type, "pci") != 0) {
		ddi_prop_free(device_type);
		return (B_FALSE);
	}

	ddi_prop_free(device_type);
	return (B_TRUE);
}

typedef struct {
	boolean_t	init;
	uint8_t		flags;
} pcie_bus_arg_t;

/*ARGSUSED*/
static int
pcie_fab_do_init_fini(dev_info_t *dip, void *arg)
{
	pcie_req_id_t	bdf;
	pcie_bus_arg_t	*bus_arg = (pcie_bus_arg_t *)arg;

	if (!pcie_is_pci_device(dip))
		goto out;

	if (bus_arg->init) {
		if (pcie_get_bdf_from_dip(dip, &bdf) != DDI_SUCCESS)
			goto out;

		(void) pcie_init_bus(dip, bdf, bus_arg->flags);
	} else {
		(void) pcie_fini_bus(dip, bus_arg->flags);
	}

	return (DDI_WALK_CONTINUE);

out:
	return (DDI_WALK_PRUNECHILD);
}

void
pcie_fab_init_bus(dev_info_t *rcdip, uint8_t flags)
{
	dev_info_t	*dip = ddi_get_child(rcdip);
	pcie_bus_arg_t	arg;

	arg.init = B_TRUE;
	arg.flags = flags;

	ndi_devi_enter(rcdip);
	ddi_walk_devs(dip, pcie_fab_do_init_fini, &arg);
	ndi_devi_exit(rcdip);
}

void
pcie_fab_fini_bus(dev_info_t *rcdip, uint8_t flags)
{
	dev_info_t	*dip = ddi_get_child(rcdip);
	pcie_bus_arg_t	arg;

	arg.init = B_FALSE;
	arg.flags = flags;

	ndi_devi_enter(rcdip);
	ddi_walk_devs(dip, pcie_fab_do_init_fini, &arg);
	ndi_devi_exit(rcdip);
}

void
pcie_enable_errors(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	reg16, tmp16;
	uint32_t	reg32, tmp32;

	ASSERT(bus_p);

	/*
	 * Clear any pending errors
	 */
	pcie_clear_errors(dip);

	if (!PCIE_IS_PCIE(bus_p))
		return;

	/*
	 * Enable Baseline Error Handling but leave CE reporting off (poweron
	 * default).
	 */
	if ((reg16 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL)) !=
	    PCI_CAP_EINVAL16) {
		tmp16 = (reg16 & pcie_devctl_default_mask) |
		    (pcie_devctl_default & ~pcie_devctl_default_mask) |
		    (pcie_base_err_default & ~PCIE_DEVCTL_CE_REPORTING_EN);

		PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, tmp16);
		PCIE_DBG_CAP(dip, bus_p, "DEVCTL", 16, PCIE_DEVCTL, reg16);
	}

	/* Enable Root Port Baseline Error Receiving */
	if (PCIE_IS_ROOT(bus_p) &&
	    (reg16 = PCIE_CAP_GET(16, bus_p, PCIE_ROOTCTL)) !=
	    PCI_CAP_EINVAL16) {

		tmp16 = pcie_serr_disable_flag ?
		    (pcie_root_ctrl_default & ~PCIE_ROOT_SYS_ERR) :
		    pcie_root_ctrl_default;
		PCIE_CAP_PUT(16, bus_p, PCIE_ROOTCTL, tmp16);
		PCIE_DBG_CAP(dip, bus_p, "ROOT DEVCTL", 16, PCIE_ROOTCTL,
		    reg16);
	}

	/*
	 * Enable PCI-Express Advanced Error Handling if Exists
	 */
	if (!PCIE_HAS_AER(bus_p))
		return;

	/* Set Uncorrectable Severity */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_UCE_SERV)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = pcie_aer_uce_severity;

		PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_SERV, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER UCE SEV", 32, PCIE_AER_UCE_SERV,
		    reg32);
	}

	/* Enable Uncorrectable errors */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_UCE_MASK)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = pcie_aer_uce_mask;

		PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_MASK, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER UCE MASK", 32, PCIE_AER_UCE_MASK,
		    reg32);
	}

	/* Enable ECRC generation and checking */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_CTL)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = reg32 | pcie_ecrc_value;
		PCIE_AER_PUT(32, bus_p, PCIE_AER_CTL, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER CTL", 32, PCIE_AER_CTL, reg32);
	}

	/* Enable Secondary Uncorrectable errors if this is a bridge */
	if (!PCIE_IS_PCIE_BDG(bus_p))
		goto root;

	/* Set Uncorrectable Severity */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_SUCE_SERV)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = pcie_aer_suce_severity;

		PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_SERV, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER SUCE SEV", 32, PCIE_AER_SUCE_SERV,
		    reg32);
	}

	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_SUCE_MASK)) !=
	    PCI_CAP_EINVAL32) {
		PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_MASK, pcie_aer_suce_mask);
		PCIE_DBG_AER(dip, bus_p, "AER SUCE MASK", 32,
		    PCIE_AER_SUCE_MASK, reg32);
	}

root:
	/*
	 * Enable Root Control this is a Root device
	 */
	if (!PCIE_IS_ROOT(bus_p))
		return;

	if ((reg16 = PCIE_AER_GET(16, bus_p, PCIE_AER_RE_CMD)) !=
	    PCI_CAP_EINVAL16) {
		PCIE_AER_PUT(16, bus_p, PCIE_AER_RE_CMD,
		    pcie_root_error_cmd_default);
		PCIE_DBG_AER(dip, bus_p, "AER Root Err Cmd", 16,
		    PCIE_AER_RE_CMD, reg16);
	}
}

/*
 * This function is used for enabling CE reporting and setting the AER CE mask.
 * When called from outside the pcie module it should always be preceded by
 * a call to pcie_enable_errors.
 */
int
pcie_enable_ce(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	device_sts, device_ctl;
	uint32_t	tmp_pcie_aer_ce_mask;

	if (!PCIE_IS_PCIE(bus_p))
		return (DDI_SUCCESS);

	/*
	 * The "pcie_ce_mask" property is used to control both the CE reporting
	 * enable field in the device control register and the AER CE mask. We
	 * leave CE reporting disabled if pcie_ce_mask is set to -1.
	 */

	tmp_pcie_aer_ce_mask = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie_ce_mask", pcie_aer_ce_mask);

	if (tmp_pcie_aer_ce_mask == (uint32_t)-1) {
		/*
		 * Nothing to do since CE reporting has already been disabled.
		 */
		return (DDI_SUCCESS);
	}

	if (PCIE_HAS_AER(bus_p)) {
		/* Enable AER CE */
		PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_MASK, tmp_pcie_aer_ce_mask);
		PCIE_DBG_AER(dip, bus_p, "AER CE MASK", 32, PCIE_AER_CE_MASK,
		    0);

		/* Clear any pending AER CE errors */
		PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_STS, -1);
	}

	/* clear any pending CE errors */
	if ((device_sts = PCIE_CAP_GET(16, bus_p, PCIE_DEVSTS)) !=
	    PCI_CAP_EINVAL16)
		PCIE_CAP_PUT(16, bus_p, PCIE_DEVSTS,
		    device_sts & (~PCIE_DEVSTS_CE_DETECTED));

	/* Enable CE reporting */
	device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL,
	    (device_ctl & (~PCIE_DEVCTL_ERR_MASK)) | pcie_base_err_default);
	PCIE_DBG_CAP(dip, bus_p, "DEVCTL", 16, PCIE_DEVCTL, device_ctl);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
void
pcie_disable_errors(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	device_ctl;
	uint32_t	aer_reg;

	if (!PCIE_IS_PCIE(bus_p))
		return;

	/*
	 * Disable PCI-Express Baseline Error Handling
	 */
	device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
	device_ctl &= ~PCIE_DEVCTL_ERR_MASK;
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, device_ctl);

	/*
	 * Disable PCI-Express Advanced Error Handling if Exists
	 */
	if (!PCIE_HAS_AER(bus_p))
		goto root;

	/* Disable Uncorrectable errors */
	PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_MASK, PCIE_AER_UCE_BITS);

	/* Disable Correctable errors */
	PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_MASK, PCIE_AER_CE_BITS);

	/* Disable ECRC generation and checking */
	if ((aer_reg = PCIE_AER_GET(32, bus_p, PCIE_AER_CTL)) !=
	    PCI_CAP_EINVAL32) {
		aer_reg &= ~(PCIE_AER_CTL_ECRC_GEN_ENA |
		    PCIE_AER_CTL_ECRC_CHECK_ENA);

		PCIE_AER_PUT(32, bus_p, PCIE_AER_CTL, aer_reg);
	}
	/*
	 * Disable Secondary Uncorrectable errors if this is a bridge
	 */
	if (!PCIE_IS_PCIE_BDG(bus_p))
		goto root;

	PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_MASK, PCIE_AER_SUCE_BITS);

root:
	/*
	 * disable Root Control this is a Root device
	 */
	if (!PCIE_IS_ROOT(bus_p))
		return;

	if (!pcie_serr_disable_flag) {
		device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_ROOTCTL);
		device_ctl &= ~PCIE_ROOT_SYS_ERR;
		PCIE_CAP_PUT(16, bus_p, PCIE_ROOTCTL, device_ctl);
	}

	if (!PCIE_HAS_AER(bus_p))
		return;

	if ((device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_AER_RE_CMD)) !=
	    PCI_CAP_EINVAL16) {
		device_ctl &= ~pcie_root_error_cmd_default;
		PCIE_CAP_PUT(16, bus_p, PCIE_AER_RE_CMD, device_ctl);
	}
}

/*
 * Extract bdf from "reg" property.
 */
int
pcie_get_bdf_from_dip(dev_info_t *dip, pcie_req_id_t *bdf)
{
	pci_regspec_t	*regspec;
	int		reglen;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&regspec, (uint_t *)&reglen) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (reglen < (sizeof (pci_regspec_t) / sizeof (int))) {
		ddi_prop_free(regspec);
		return (DDI_FAILURE);
	}

	/* Get phys_hi from first element.  All have same bdf. */
	*bdf = (regspec->pci_phys_hi & (PCI_REG_BDFR_M ^ PCI_REG_REG_M)) >> 8;

	ddi_prop_free(regspec);
	return (DDI_SUCCESS);
}

dev_info_t *
pcie_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t *cdip = rdip;

	for (; ddi_get_parent(cdip) != dip; cdip = ddi_get_parent(cdip))
		;

	return (cdip);
}

uint32_t
pcie_get_bdf_for_dma_xfer(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t *cdip;

	/*
	 * As part of the probing, the PCI fcode interpreter may setup a DMA
	 * request if a given card has a fcode on it using dip and rdip of the
	 * hotplug connector i.e, dip and rdip of px/pcieb driver. In this
	 * case, return a invalid value for the bdf since we cannot get to the
	 * bdf value of the actual device which will be initiating this DMA.
	 */
	if (rdip == dip)
		return (PCIE_INVALID_BDF);

	cdip = pcie_get_my_childs_dip(dip, rdip);

	/*
	 * For a given rdip, return the bdf value of dip's (px or pcieb)
	 * immediate child or secondary bus-id if dip is a PCIe2PCI bridge.
	 *
	 * XXX - For now, return a invalid bdf value for all PCI and PCI-X
	 * devices since this needs more work.
	 */
	return (PCI_GET_PCIE2PCI_SECBUS(cdip) ?
	    PCIE_INVALID_BDF : PCI_GET_BDF(cdip));
}

uint32_t
pcie_get_aer_uce_mask()
{
	return (pcie_aer_uce_mask);
}
uint32_t
pcie_get_aer_ce_mask()
{
	return (pcie_aer_ce_mask);
}
uint32_t
pcie_get_aer_suce_mask()
{
	return (pcie_aer_suce_mask);
}
uint32_t
pcie_get_serr_mask()
{
	return (pcie_serr_disable_flag);
}

void
pcie_set_aer_uce_mask(uint32_t mask)
{
	pcie_aer_uce_mask = mask;
	if (mask & PCIE_AER_UCE_UR)
		pcie_base_err_default &= ~PCIE_DEVCTL_UR_REPORTING_EN;
	else
		pcie_base_err_default |= PCIE_DEVCTL_UR_REPORTING_EN;

	if (mask & PCIE_AER_UCE_ECRC)
		pcie_ecrc_value = 0;
}

void
pcie_set_aer_ce_mask(uint32_t mask)
{
	pcie_aer_ce_mask = mask;
}
void
pcie_set_aer_suce_mask(uint32_t mask)
{
	pcie_aer_suce_mask = mask;
}
void
pcie_set_serr_mask(uint32_t mask)
{
	pcie_serr_disable_flag = mask;
}

/*
 * Is the rdip a child of dip.	Used for checking certain CTLOPS from bubbling
 * up erronously.  Ex.	ISA ctlops to a PCI-PCI Bridge.
 */
boolean_t
pcie_is_child(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t	*cdip = ddi_get_child(dip);
	for (; cdip; cdip = ddi_get_next_sibling(cdip))
		if (cdip == rdip)
			break;
	return (cdip != NULL);
}

boolean_t
pcie_is_link_disabled(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_PCIE(bus_p)) {
		if (PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL) &
		    PCIE_LINKCTL_LINK_DISABLE)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Determines if there are any root ports attached to a root complex.
 *
 * dip - dip of root complex
 *
 * Returns - DDI_SUCCESS if there is at least one root port otherwise
 *	     DDI_FAILURE.
 */
int
pcie_root_port(dev_info_t *dip)
{
	int port_type;
	uint16_t cap_ptr;
	ddi_acc_handle_t config_handle;
	dev_info_t *cdip = ddi_get_child(dip);

	/*
	 * Determine if any of the children of the passed in dip
	 * are root ports.
	 */
	for (; cdip; cdip = ddi_get_next_sibling(cdip)) {

		if (pci_config_setup(cdip, &config_handle) != DDI_SUCCESS)
			continue;

		if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_E,
		    &cap_ptr)) == DDI_FAILURE) {
			pci_config_teardown(&config_handle);
			continue;
		}

		port_type = PCI_CAP_GET16(config_handle, 0, cap_ptr,
		    PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;

		pci_config_teardown(&config_handle);

		if (port_type == PCIE_PCIECAP_DEV_TYPE_ROOT)
			return (DDI_SUCCESS);
	}

	/* No root ports were found */

	return (DDI_FAILURE);
}

/*
 * Function that determines if a device a PCIe device.
 *
 * dip - dip of device.
 *
 * returns - DDI_SUCCESS if device is a PCIe device, otherwise DDI_FAILURE.
 */
int
pcie_dev(dev_info_t *dip)
{
	/* get parent device's device_type property */
	char *device_type;
	int rc = DDI_FAILURE;
	dev_info_t *pdip = ddi_get_parent(dip);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip,
	    DDI_PROP_DONTPASS, "device_type", &device_type)
	    != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (strcmp(device_type, "pciex") == 0)
		rc = DDI_SUCCESS;
	else
		rc = DDI_FAILURE;

	ddi_prop_free(device_type);
	return (rc);
}

void
pcie_set_rber_fatal(dev_info_t *dip, boolean_t val)
{
	pcie_bus_t *bus_p = PCIE_DIP2UPBUS(dip);
	bus_p->bus_pfd->pe_rber_fatal = val;
}

/*
 * Return parent Root Port's pe_rber_fatal value.
 */
boolean_t
pcie_get_rber_fatal(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2UPBUS(dip);
	pcie_bus_t *rp_bus_p = PCIE_DIP2UPBUS(bus_p->bus_rp_dip);
	return (rp_bus_p->bus_pfd->pe_rber_fatal);
}

int
pcie_ari_supported(dev_info_t *dip)
{
	uint32_t devcap2;
	uint16_t pciecap;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);
	uint8_t dev_type;

	PCIE_DBG("pcie_ari_supported: dip=%p\n", dip);

	if (bus_p == NULL)
		return (PCIE_ARI_FORW_NOT_SUPPORTED);

	dev_type = bus_p->bus_dev_type;

	if ((dev_type != PCIE_PCIECAP_DEV_TYPE_DOWN) &&
	    (dev_type != PCIE_PCIECAP_DEV_TYPE_ROOT))
		return (PCIE_ARI_FORW_NOT_SUPPORTED);

	if (pcie_disable_ari) {
		PCIE_DBG("pcie_ari_supported: dip=%p: ARI Disabled\n", dip);
		return (PCIE_ARI_FORW_NOT_SUPPORTED);
	}

	pciecap = PCIE_CAP_GET(16, bus_p, PCIE_PCIECAP);

	if ((pciecap & PCIE_PCIECAP_VER_MASK) < PCIE_PCIECAP_VER_2_0) {
		PCIE_DBG("pcie_ari_supported: dip=%p: Not 2.0\n", dip);
		return (PCIE_ARI_FORW_NOT_SUPPORTED);
	}

	devcap2 = PCIE_CAP_GET(32, bus_p, PCIE_DEVCAP2);

	PCIE_DBG("pcie_ari_supported: dip=%p: DevCap2=0x%x\n",
	    dip, devcap2);

	if (devcap2 & PCIE_DEVCAP2_ARI_FORWARD) {
		PCIE_DBG("pcie_ari_supported: "
		    "dip=%p: ARI Forwarding is supported\n", dip);
		return (PCIE_ARI_FORW_SUPPORTED);
	}
	return (PCIE_ARI_FORW_NOT_SUPPORTED);
}

int
pcie_ari_enable(dev_info_t *dip)
{
	uint16_t devctl2;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	PCIE_DBG("pcie_ari_enable: dip=%p\n", dip);

	if (pcie_ari_supported(dip) == PCIE_ARI_FORW_NOT_SUPPORTED)
		return (DDI_FAILURE);

	devctl2 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL2);
	devctl2 |= PCIE_DEVCTL2_ARI_FORWARD_EN;
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL2, devctl2);

	PCIE_DBG("pcie_ari_enable: dip=%p: writing 0x%x to DevCtl2\n",
	    dip, devctl2);

	return (DDI_SUCCESS);
}

int
pcie_ari_disable(dev_info_t *dip)
{
	uint16_t devctl2;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	PCIE_DBG("pcie_ari_disable: dip=%p\n", dip);

	if (pcie_ari_supported(dip) == PCIE_ARI_FORW_NOT_SUPPORTED)
		return (DDI_FAILURE);

	devctl2 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL2);
	devctl2 &= ~PCIE_DEVCTL2_ARI_FORWARD_EN;
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL2, devctl2);

	PCIE_DBG("pcie_ari_disable: dip=%p: writing 0x%x to DevCtl2\n",
	    dip, devctl2);

	return (DDI_SUCCESS);
}

int
pcie_ari_is_enabled(dev_info_t *dip)
{
	uint16_t devctl2;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	PCIE_DBG("pcie_ari_is_enabled: dip=%p\n", dip);

	if (pcie_ari_supported(dip) == PCIE_ARI_FORW_NOT_SUPPORTED)
		return (PCIE_ARI_FORW_DISABLED);

	devctl2 = PCIE_CAP_GET(32, bus_p, PCIE_DEVCTL2);

	PCIE_DBG("pcie_ari_is_enabled: dip=%p: DevCtl2=0x%x\n",
	    dip, devctl2);

	if (devctl2 & PCIE_DEVCTL2_ARI_FORWARD_EN) {
		PCIE_DBG("pcie_ari_is_enabled: "
		    "dip=%p: ARI Forwarding is enabled\n", dip);
		return (PCIE_ARI_FORW_ENABLED);
	}

	return (PCIE_ARI_FORW_DISABLED);
}

int
pcie_ari_device(dev_info_t *dip)
{
	ddi_acc_handle_t handle;
	uint16_t cap_ptr;

	PCIE_DBG("pcie_ari_device: dip=%p\n", dip);

	/*
	 * XXX - This function may be called before the bus_p structure
	 * has been populated.  This code can be changed to remove
	 * pci_config_setup()/pci_config_teardown() when the RFE
	 * to populate the bus_p structures early in boot is putback.
	 */

	/* First make sure it is a PCIe device */

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS)
		return (PCIE_NOT_ARI_DEVICE);

	if ((PCI_CAP_LOCATE(handle, PCI_CAP_ID_PCI_E, &cap_ptr))
	    != DDI_SUCCESS) {
		pci_config_teardown(&handle);
		return (PCIE_NOT_ARI_DEVICE);
	}

	/* Locate the ARI Capability */

	if ((PCI_CAP_LOCATE(handle, PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_ARI),
	    &cap_ptr)) == DDI_FAILURE) {
		pci_config_teardown(&handle);
		return (PCIE_NOT_ARI_DEVICE);
	}

	/* ARI Capability was found so it must be a ARI device */
	PCIE_DBG("pcie_ari_device: ARI Device dip=%p\n", dip);

	pci_config_teardown(&handle);
	return (PCIE_ARI_DEVICE);
}

int
pcie_ari_get_next_function(dev_info_t *dip, int *func)
{
	uint32_t val;
	uint16_t cap_ptr, next_function;
	ddi_acc_handle_t handle;

	/*
	 * XXX - This function may be called before the bus_p structure
	 * has been populated.  This code can be changed to remove
	 * pci_config_setup()/pci_config_teardown() when the RFE
	 * to populate the bus_p structures early in boot is putback.
	 */

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((PCI_CAP_LOCATE(handle,
	    PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_ARI), &cap_ptr)) == DDI_FAILURE) {
		pci_config_teardown(&handle);
		return (DDI_FAILURE);
	}

	val = PCI_CAP_GET32(handle, 0, cap_ptr, PCIE_ARI_CAP);

	next_function = (val >> PCIE_ARI_CAP_NEXT_FUNC_SHIFT) &
	    PCIE_ARI_CAP_NEXT_FUNC_MASK;

	pci_config_teardown(&handle);

	*func = next_function;

	return (DDI_SUCCESS);
}

dev_info_t *
pcie_func_to_dip(dev_info_t *dip, pcie_req_id_t function)
{
	pcie_req_id_t child_bdf;
	dev_info_t *cdip;

	for (cdip = ddi_get_child(dip); cdip;
	    cdip = ddi_get_next_sibling(cdip)) {

		if (pcie_get_bdf_from_dip(cdip, &child_bdf) == DDI_FAILURE)
			return (NULL);

		if ((child_bdf & PCIE_REQ_ID_ARI_FUNC_MASK) == function)
			return (cdip);
	}
	return (NULL);
}

#ifdef	DEBUG

static void
pcie_print_bus(pcie_bus_t *bus_p)
{
	pcie_dbg("\tbus_dip = 0x%p\n", bus_p->bus_dip);
	pcie_dbg("\tbus_fm_flags = 0x%x\n", bus_p->bus_fm_flags);

	pcie_dbg("\tbus_bdf = 0x%x\n", bus_p->bus_bdf);
	pcie_dbg("\tbus_dev_ven_id = 0x%x\n", bus_p->bus_dev_ven_id);
	pcie_dbg("\tbus_rev_id = 0x%x\n", bus_p->bus_rev_id);
	pcie_dbg("\tbus_hdr_type = 0x%x\n", bus_p->bus_hdr_type);
	pcie_dbg("\tbus_dev_type = 0x%x\n", bus_p->bus_dev_type);
	pcie_dbg("\tbus_bdg_secbus = 0x%x\n", bus_p->bus_bdg_secbus);
	pcie_dbg("\tbus_pcie_off = 0x%x\n", bus_p->bus_pcie_off);
	pcie_dbg("\tbus_aer_off = 0x%x\n", bus_p->bus_aer_off);
	pcie_dbg("\tbus_pcix_off = 0x%x\n", bus_p->bus_pcix_off);
	pcie_dbg("\tbus_ecc_ver = 0x%x\n", bus_p->bus_ecc_ver);
}

/*
 * For debugging purposes set pcie_dbg_print != 0 to see printf messages
 * during interrupt.
 *
 * When a proper solution is in place this code will disappear.
 * Potential solutions are:
 * o circular buffers
 * o taskq to print at lower pil
 */
int pcie_dbg_print = 0;
void
pcie_dbg(char *fmt, ...)
{
	va_list ap;

	if (!pcie_debug_flags) {
		return;
	}
	va_start(ap, fmt);
	if (servicing_interrupt()) {
		if (pcie_dbg_print) {
			prom_vprintf(fmt, ap);
		}
	} else {
		prom_vprintf(fmt, ap);
	}
	va_end(ap);
}
#endif	/* DEBUG */

boolean_t
pcie_link_bw_supported(dev_info_t *dip)
{
	uint32_t linkcap;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	if (!PCIE_IS_PCIE(bus_p)) {
		return (B_FALSE);
	}

	if (!PCIE_IS_RP(bus_p) && !PCIE_IS_SWD(bus_p)) {
		return (B_FALSE);
	}

	linkcap = PCIE_CAP_GET(32, bus_p, PCIE_LINKCAP);
	return ((linkcap & PCIE_LINKCAP_LINK_BW_NOTIFY_CAP) != 0);
}

int
pcie_link_bw_enable(dev_info_t *dip)
{
	uint16_t linkctl;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	if (pcie_disable_lbw != 0) {
		return (DDI_FAILURE);
	}

	if (!pcie_link_bw_supported(dip)) {
		return (DDI_FAILURE);
	}

	mutex_init(&bus_p->bus_lbw_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&bus_p->bus_lbw_cv, NULL, CV_DRIVER, NULL);
	linkctl = PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL);
	linkctl |= PCIE_LINKCTL_LINK_BW_INTR_EN;
	linkctl |= PCIE_LINKCTL_LINK_AUTO_BW_INTR_EN;
	PCIE_CAP_PUT(16, bus_p, PCIE_LINKCTL, linkctl);

	bus_p->bus_lbw_pbuf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	bus_p->bus_lbw_cbuf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	bus_p->bus_lbw_state |= PCIE_LBW_S_ENABLED;

	return (DDI_SUCCESS);
}

int
pcie_link_bw_disable(dev_info_t *dip)
{
	uint16_t linkctl;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	if ((bus_p->bus_lbw_state & PCIE_LBW_S_ENABLED) == 0) {
		return (DDI_FAILURE);
	}

	mutex_enter(&bus_p->bus_lbw_mutex);
	while ((bus_p->bus_lbw_state &
	    (PCIE_LBW_S_DISPATCHED | PCIE_LBW_S_RUNNING)) != 0) {
		cv_wait(&bus_p->bus_lbw_cv, &bus_p->bus_lbw_mutex);
	}
	mutex_exit(&bus_p->bus_lbw_mutex);

	linkctl = PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL);
	linkctl &= ~PCIE_LINKCTL_LINK_BW_INTR_EN;
	linkctl &= ~PCIE_LINKCTL_LINK_AUTO_BW_INTR_EN;
	PCIE_CAP_PUT(16, bus_p, PCIE_LINKCTL, linkctl);

	bus_p->bus_lbw_state &= ~PCIE_LBW_S_ENABLED;
	kmem_free(bus_p->bus_lbw_pbuf, MAXPATHLEN);
	kmem_free(bus_p->bus_lbw_cbuf, MAXPATHLEN);
	bus_p->bus_lbw_pbuf = NULL;
	bus_p->bus_lbw_cbuf = NULL;

	mutex_destroy(&bus_p->bus_lbw_mutex);
	cv_destroy(&bus_p->bus_lbw_cv);

	return (DDI_SUCCESS);
}

void
pcie_link_bw_taskq(void *arg)
{
	dev_info_t *dip = arg;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);
	dev_info_t *cdip;
	boolean_t again;
	sysevent_t *se;
	sysevent_value_t se_val;
	sysevent_id_t eid;
	sysevent_attr_list_t *ev_attr_list;

top:
	ndi_devi_enter(dip);
	se = NULL;
	ev_attr_list = NULL;
	mutex_enter(&bus_p->bus_lbw_mutex);
	bus_p->bus_lbw_state &= ~PCIE_LBW_S_DISPATCHED;
	bus_p->bus_lbw_state |= PCIE_LBW_S_RUNNING;
	mutex_exit(&bus_p->bus_lbw_mutex);

	/*
	 * Update our own speeds as we've likely changed something.
	 */
	pcie_capture_speeds(dip);

	/*
	 * Walk our children. We only care about updating this on function 0
	 * because the PCIe specification requires that these all be the same
	 * otherwise.
	 */
	for (cdip = ddi_get_child(dip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {
		pcie_bus_t *cbus_p = PCIE_DIP2BUS(cdip);

		if (cbus_p == NULL) {
			continue;
		}

		if ((cbus_p->bus_bdf & PCIE_REQ_ID_FUNC_MASK) != 0) {
			continue;
		}

		/*
		 * It's possible that this can fire while a child is otherwise
		 * only partially constructed. Therefore, if we don't have the
		 * config handle, don't bother updating the child.
		 */
		if (cbus_p->bus_cfg_hdl == NULL) {
			continue;
		}

		pcie_capture_speeds(cdip);
		break;
	}

	se = sysevent_alloc(EC_PCIE, ESC_PCIE_LINK_STATE,
	    ILLUMOS_KERN_PUB "pcie", SE_SLEEP);

	(void) ddi_pathname(dip, bus_p->bus_lbw_pbuf);
	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = bus_p->bus_lbw_pbuf;
	if (sysevent_add_attr(&ev_attr_list, PCIE_EV_DETECTOR_PATH, &se_val,
	    SE_SLEEP) != 0) {
		ndi_devi_exit(dip);
		goto err;
	}

	if (cdip != NULL) {
		(void) ddi_pathname(cdip, bus_p->bus_lbw_cbuf);

		se_val.value_type = SE_DATA_TYPE_STRING;
		se_val.value.sv_string = bus_p->bus_lbw_cbuf;

		/*
		 * If this fails, that's OK. We'd rather get the event off and
		 * there's a chance that there may not be anything there for us.
		 */
		(void) sysevent_add_attr(&ev_attr_list, PCIE_EV_CHILD_PATH,
		    &se_val, SE_SLEEP);
	}

	ndi_devi_exit(dip);

	/*
	 * Before we generate and send down a sysevent, we need to tell the
	 * system that parts of the devinfo cache need to be invalidated. While
	 * the function below takes several args, it ignores them all. Because
	 * this is a global invalidation, we don't bother trying to do much more
	 * than requesting a global invalidation, lest we accidentally kick off
	 * several in a row.
	 */
	ddi_prop_cache_invalidate(DDI_DEV_T_NONE, NULL, NULL, 0);

	if (sysevent_attach_attributes(se, ev_attr_list) != 0) {
		goto err;
	}
	ev_attr_list = NULL;

	if (log_sysevent(se, SE_SLEEP, &eid) != 0) {
		goto err;
	}

err:
	sysevent_free_attr(ev_attr_list);
	sysevent_free(se);

	mutex_enter(&bus_p->bus_lbw_mutex);
	bus_p->bus_lbw_state &= ~PCIE_LBW_S_RUNNING;
	cv_broadcast(&bus_p->bus_lbw_cv);
	again = (bus_p->bus_lbw_state & PCIE_LBW_S_DISPATCHED) != 0;
	mutex_exit(&bus_p->bus_lbw_mutex);

	if (again) {
		goto top;
	}
}

int
pcie_link_bw_intr(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);
	uint16_t linksts;
	uint16_t flags = PCIE_LINKSTS_LINK_BW_MGMT | PCIE_LINKSTS_AUTO_BW;
	hrtime_t now;

	if ((bus_p->bus_lbw_state & PCIE_LBW_S_ENABLED) == 0) {
		return (DDI_INTR_UNCLAIMED);
	}

	linksts = PCIE_CAP_GET(16, bus_p, PCIE_LINKSTS);
	if ((linksts & flags) == 0) {
		return (DDI_INTR_UNCLAIMED);
	}

	now = gethrtime();

	/*
	 * Check if we've already dispatched this event. If we have already
	 * dispatched it, then there's nothing else to do, we coalesce multiple
	 * events.
	 */
	mutex_enter(&bus_p->bus_lbw_mutex);
	bus_p->bus_lbw_nevents++;
	bus_p->bus_lbw_last_ts = now;
	if ((bus_p->bus_lbw_state & PCIE_LBW_S_DISPATCHED) == 0) {
		if ((bus_p->bus_lbw_state & PCIE_LBW_S_RUNNING) == 0) {
			taskq_dispatch_ent(pcie_link_tq, pcie_link_bw_taskq,
			    dip, 0, &bus_p->bus_lbw_ent);
		}

		bus_p->bus_lbw_state |= PCIE_LBW_S_DISPATCHED;
	}
	mutex_exit(&bus_p->bus_lbw_mutex);

	PCIE_CAP_PUT(16, bus_p, PCIE_LINKSTS, flags);
	return (DDI_INTR_CLAIMED);
}

int
pcie_link_set_target(dev_info_t *dip, pcie_link_speed_t speed)
{
	uint16_t ctl2, rval;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	if (!PCIE_IS_PCIE(bus_p)) {
		return (ENOTSUP);
	}

	if (!PCIE_IS_RP(bus_p) && !PCIE_IS_SWD(bus_p)) {
		return (ENOTSUP);
	}

	if (bus_p->bus_pcie_vers < 2) {
		return (ENOTSUP);
	}

	switch (speed) {
	case PCIE_LINK_SPEED_2_5:
		rval = PCIE_LINKCTL2_TARGET_SPEED_2_5;
		break;
	case PCIE_LINK_SPEED_5:
		rval = PCIE_LINKCTL2_TARGET_SPEED_5;
		break;
	case PCIE_LINK_SPEED_8:
		rval = PCIE_LINKCTL2_TARGET_SPEED_8;
		break;
	case PCIE_LINK_SPEED_16:
		rval = PCIE_LINKCTL2_TARGET_SPEED_16;
		break;
	case PCIE_LINK_SPEED_32:
		rval = PCIE_LINKCTL2_TARGET_SPEED_32;
		break;
	case PCIE_LINK_SPEED_64:
		rval = PCIE_LINKCTL2_TARGET_SPEED_64;
		break;
	default:
		return (EINVAL);
	}

	mutex_enter(&bus_p->bus_speed_mutex);
	if ((bus_p->bus_sup_speed & speed) == 0) {
		mutex_exit(&bus_p->bus_speed_mutex);
		return (ENOTSUP);
	}

	bus_p->bus_target_speed = speed;
	bus_p->bus_speed_flags |= PCIE_LINK_F_ADMIN_TARGET;

	ctl2 = PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL2);
	ctl2 &= ~PCIE_LINKCTL2_TARGET_SPEED_MASK;
	ctl2 |= rval;
	PCIE_CAP_PUT(16, bus_p, PCIE_LINKCTL2, ctl2);
	mutex_exit(&bus_p->bus_speed_mutex);

	/*
	 * Make sure our updates have been reflected in devinfo.
	 */
	pcie_capture_speeds(dip);

	return (0);
}

int
pcie_link_retrain(dev_info_t *dip)
{
	uint16_t ctl;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	if (!PCIE_IS_PCIE(bus_p)) {
		return (ENOTSUP);
	}

	if (!PCIE_IS_RP(bus_p) && !PCIE_IS_SWD(bus_p)) {
		return (ENOTSUP);
	}

	/*
	 * The PCIe specification suggests that we make sure that the link isn't
	 * in training before issuing this command in case there was a state
	 * machine transition prior to when we got here. We wait and then go
	 * ahead and issue the command anyways.
	 */
	for (uint32_t i = 0; i < pcie_link_retrain_count; i++) {
		uint16_t sts;

		sts = PCIE_CAP_GET(16, bus_p, PCIE_LINKSTS);
		if ((sts & PCIE_LINKSTS_LINK_TRAINING) == 0)
			break;
		delay(drv_usectohz(pcie_link_retrain_delay_ms * 1000));
	}

	ctl = PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL);
	ctl |= PCIE_LINKCTL_RETRAIN_LINK;
	PCIE_CAP_PUT(16, bus_p, PCIE_LINKCTL, ctl);

	/*
	 * Wait again to see if it clears before returning to the user.
	 */
	for (uint32_t i = 0; i < pcie_link_retrain_count; i++) {
		uint16_t sts;

		sts = PCIE_CAP_GET(16, bus_p, PCIE_LINKSTS);
		if ((sts & PCIE_LINKSTS_LINK_TRAINING) == 0)
			break;
		delay(drv_usectohz(pcie_link_retrain_delay_ms * 1000));
	}

	return (0);
}

/*
 * Here we're going through and grabbing information about a given PCIe device.
 * Our situation is a little bit complicated at this point. This gets invoked
 * both during early initialization and during hotplug events. We cannot rely on
 * the device node having been fully set up, that is, while the pcie_bus_t
 * normally contains a ddi_acc_handle_t for configuration space, that may not be
 * valid yet as this can occur before child initialization or we may be dealing
 * with a function that will never have a handle.
 *
 * However, we should always have a fully furnished pcie_bus_t, which means that
 * we can get its bdf and use that to access the devices configuration space.
 */
static int
pcie_fabric_feature_scan(dev_info_t *dip, void *arg)
{
	pcie_bus_t *bus_p;
	uint32_t devcap;
	uint16_t mps;
	dev_info_t *rcdip;
	pcie_fabric_data_t *fab = arg;

	/*
	 * Skip over non-PCIe devices. If we encounter something here, we don't
	 * bother going through any of its children because we don't have reason
	 * to believe that a PCIe device that this will impact will exist below
	 * this. While it is possible that there's a PCIe fabric downstream an
	 * intermediate old PCI/PCI-X bus, at that point, we'll still trigger
	 * our complex fabric detection and use the minimums.
	 *
	 * The reason this doesn't trigger an immediate flagging as a complex
	 * case like the one below is because we could be scanning a device that
	 * is a nexus driver and has children already (albeit that would be
	 * somewhat surprising as we don't anticipate being called at this
	 * point).
	 */
	if (pcie_dev(dip) != DDI_SUCCESS) {
		return (DDI_WALK_PRUNECHILD);
	}

	/*
	 * If we fail to find a pcie_bus_t for some reason, that's somewhat
	 * surprising. We log this fact and set the complex flag and indicate it
	 * was because of this case. This immediately transitions us to a
	 * "complex" case which means use the minimal, safe, settings.
	 */
	bus_p = PCIE_DIP2BUS(dip);
	if (bus_p == NULL) {
		dev_err(dip, CE_WARN, "failed to find associated pcie_bus_t "
		    "during fabric scan");
		fab->pfd_flags |= PCIE_FABRIC_F_COMPLEX;
		return (DDI_WALK_TERMINATE);
	}

	/*
	 * In a similar case, there is hardware out there which is a PCIe
	 * device, but does not advertise a PCIe capability. An example of this
	 * is the IDT Tsi382A which can hide its PCIe capability. If this is
	 * the case, we immediately terminate scanning and flag this as a
	 * 'complex' case which causes us to use guaranteed safe settings.
	 */
	if (bus_p->bus_pcie_off == 0) {
		dev_err(dip, CE_WARN, "encountered PCIe device without PCIe "
		    "capability");
		fab->pfd_flags |= PCIE_FABRIC_F_COMPLEX;
		return (DDI_WALK_TERMINATE);
	}

	rcdip = pcie_get_rc_dip(dip);

	/*
	 * First, start by determining what the device's tagging and max packet
	 * size is. All PCIe devices will always have the 8-bit tag information
	 * as this has existed since PCIe 1.0. 10-bit tagging requires a V2
	 * PCIe capability. 14-bit requires the DEV3 cap. If we are missing a
	 * version or capability, then we always treat that as lacking the bits
	 * in the fabric.
	 */
	ASSERT3U(bus_p->bus_pcie_off, !=, 0);
	devcap = pci_cfgacc_get32(rcdip, bus_p->bus_bdf, bus_p->bus_pcie_off +
	    PCIE_DEVCAP);
	mps = devcap & PCIE_DEVCAP_MAX_PAYLOAD_MASK;
	if (mps < fab->pfd_mps_found) {
		fab->pfd_mps_found = mps;
	}

	if ((devcap & PCIE_DEVCAP_EXT_TAG_8BIT) == 0) {
		fab->pfd_tag_found &= ~PCIE_TAG_8B;
	}

	if (bus_p->bus_pcie_vers == PCIE_PCIECAP_VER_2_0) {
		uint32_t devcap2 = pci_cfgacc_get32(rcdip, bus_p->bus_bdf,
		    bus_p->bus_pcie_off + PCIE_DEVCAP2);
		if ((devcap2 & PCIE_DEVCAP2_10B_TAG_COMP_SUP) == 0) {
			fab->pfd_tag_found &= ~PCIE_TAG_10B_COMP;
		}
	} else {
		fab->pfd_tag_found &= ~PCIE_TAG_10B_COMP;
	}

	if (bus_p->bus_dev3_off != 0) {
		uint32_t devcap3 = pci_cfgacc_get32(rcdip, bus_p->bus_bdf,
		    bus_p->bus_dev3_off + PCIE_DEVCAP3);
		if ((devcap3 & PCIE_DEVCAP3_14B_TAG_COMP_SUP) == 0) {
			fab->pfd_tag_found &= ~PCIE_TAG_14B_COMP;
		}
	} else {
		fab->pfd_tag_found &= ~PCIE_TAG_14B_COMP;
	}

	/*
	 * Now that we have captured device information, we must go and ask
	 * questions of the topology here. The big theory statement enumerates
	 * several types of cases. The big question we need to answer is have we
	 * encountered a hotpluggable bridge that means we need to mark this as
	 * complex.
	 *
	 * The big theory statement notes several different kinds of hotplug
	 * topologies that exist that we can theoretically support. Right now we
	 * opt to keep our lives simple and focus solely on (4) and (5). These
	 * can both be summarized by a single, fairly straightforward rule:
	 *
	 * The only allowed hotpluggable entity is a root port.
	 *
	 * The reason that this can work and detect cases like (6), (7), and our
	 * other invalid ones is that the hotplug code will scan and find all
	 * children before we are called into here.
	 */
	if (bus_p->bus_hp_sup_modes != 0) {
		/*
		 * We opt to terminate in this case because there's no value in
		 * scanning the rest of the tree at this point.
		 */
		if (!PCIE_IS_RP(bus_p)) {
			fab->pfd_flags |= PCIE_FABRIC_F_COMPLEX;
			return (DDI_WALK_TERMINATE);
		}

		fab->pfd_flags |= PCIE_FABRIC_F_RP_HP;
	}

	/*
	 * As our walk starts at a root port, we need to make sure that we don't
	 * pick up any of its siblings and their children as those would be
	 * different PCIe fabric domains for us to scan. In many hardware
	 * platforms multiple root ports are all at the same level in the tree.
	 */
	if (bus_p->bus_rp_dip == dip) {
		return (DDI_WALK_PRUNESIB);
	}

	return (DDI_WALK_CONTINUE);
}

static int
pcie_fabric_feature_set(dev_info_t *dip, void *arg)
{
	pcie_bus_t *bus_p;
	dev_info_t *rcdip;
	pcie_fabric_data_t *fab = arg;
	uint32_t devcap, devctl;

	if (pcie_dev(dip) != DDI_SUCCESS) {
		return (DDI_WALK_PRUNECHILD);
	}

	/*
	 * The missing bus_t sent us into the complex case previously. We still
	 * need to make sure all devices have values we expect here and thus
	 * don't terminate like the above. The same is true for the case where
	 * there is no PCIe capability.
	 */
	bus_p = PCIE_DIP2BUS(dip);
	if (bus_p == NULL || bus_p->bus_pcie_off == 0) {
		return (DDI_WALK_CONTINUE);
	}
	rcdip = pcie_get_rc_dip(dip);

	devcap = pci_cfgacc_get32(rcdip, bus_p->bus_bdf, bus_p->bus_pcie_off +
	    PCIE_DEVCAP);
	devctl = pci_cfgacc_get16(rcdip, bus_p->bus_bdf, bus_p->bus_pcie_off +
	    PCIE_DEVCTL);

	if ((devcap & PCIE_DEVCAP_EXT_TAG_8BIT) != 0 &&
	    (fab->pfd_tag_act & PCIE_TAG_8B) != 0) {
		devctl |= PCIE_DEVCTL_EXT_TAG_FIELD_EN;
	}

	devctl &= ~PCIE_DEVCTL_MAX_PAYLOAD_MASK;
	ASSERT0(fab->pfd_mps_act & ~PCIE_DEVCAP_MAX_PAYLOAD_MASK);
	devctl |= fab->pfd_mps_act << PCIE_DEVCTL_MAX_PAYLOAD_SHIFT;

	pci_cfgacc_put16(rcdip, bus_p->bus_bdf, bus_p->bus_pcie_off +
	    PCIE_DEVCTL, devctl);

	if (bus_p->bus_pcie_vers == PCIE_PCIECAP_VER_2_0 &&
	    (fab->pfd_tag_act & PCIE_TAG_10B_COMP) != 0) {
		uint32_t devcap2 = pci_cfgacc_get32(rcdip, bus_p->bus_bdf,
		    bus_p->bus_pcie_off + PCIE_DEVCAP2);

		if ((devcap2 & PCIE_DEVCAP2_10B_TAG_REQ_SUP) == 0) {
			uint16_t devctl2 = pci_cfgacc_get16(rcdip,
			    bus_p->bus_bdf, bus_p->bus_pcie_off + PCIE_DEVCTL2);
			devctl2 |= PCIE_DEVCTL2_10B_TAG_REQ_EN;
			pci_cfgacc_put16(rcdip, bus_p->bus_bdf,
			    bus_p->bus_pcie_off + PCIE_DEVCTL2, devctl2);
		}
	}

	if (bus_p->bus_dev3_off != 0 &&
	    (fab->pfd_tag_act & PCIE_TAG_14B_COMP) != 0) {
		uint32_t devcap3 = pci_cfgacc_get32(rcdip, bus_p->bus_bdf,
		    bus_p->bus_dev3_off + PCIE_DEVCAP3);

		if ((devcap3 & PCIE_DEVCAP3_14B_TAG_REQ_SUP) == 0) {
			uint16_t devctl3 = pci_cfgacc_get16(rcdip,
			    bus_p->bus_bdf, bus_p->bus_dev3_off + PCIE_DEVCTL3);
			devctl3 |= PCIE_DEVCTL3_14B_TAG_REQ_EN;
			pci_cfgacc_put16(rcdip, bus_p->bus_bdf,
			    bus_p->bus_pcie_off + PCIE_DEVCTL2, devctl3);
		}
	}

	/*
	 * As our walk starts at a root port, we need to make sure that we don't
	 * pick up any of its siblings and their children as those would be
	 * different PCIe fabric domains for us to scan. In many hardware
	 * platforms multiple root ports are all at the same level in the tree.
	 */
	if (bus_p->bus_rp_dip == dip) {
		return (DDI_WALK_PRUNESIB);
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * This is used to scan and determine the total set of PCIe fabric settings that
 * we should have in the system for everything downstream of this specified root
 * port. Note, it is only really safe to call this while working from the
 * perspective of a root port as we will be walking down the entire device tree.
 *
 * However, our callers, particularly hoptlug, don't have all the information
 * we'd like. In particular, we need to check that:
 *
 *   o This is actually a PCIe device.
 *   o That this is a root port (see the big theory statement to understand this
 *     constraint).
 */
void
pcie_fabric_setup(dev_info_t *dip)
{
	pcie_bus_t *bus_p;
	pcie_fabric_data_t *fab;
	dev_info_t *pdip;

	bus_p = PCIE_DIP2BUS(dip);
	if (bus_p == NULL || !PCIE_IS_RP(bus_p)) {
		return;
	}

	VERIFY3P(bus_p->bus_fab, !=, NULL);
	fab = bus_p->bus_fab;

	/*
	 * For us to call ddi_walk_devs(), our parent needs to be held.
	 * ddi_walk_devs() will take care of grabbing our dip as part of its
	 * walk before we iterate over our children.
	 *
	 * A reasonable question to ask here is why is it safe to ask for our
	 * parent? In this case, because we have entered here through some
	 * thread that's operating on us whether as part of attach or a hotplug
	 * event, our dip somewhat by definition has to be valid. If we were
	 * looking at our dip's children and then asking them for a parent, then
	 * that would be a race condition.
	 */
	pdip = ddi_get_parent(dip);
	VERIFY3P(pdip, !=, NULL);
	ndi_devi_enter(pdip);
	fab->pfd_flags |= PCIE_FABRIC_F_SCANNING;

	/*
	 * Reinitialize the tracking structure to basically set the maximum
	 * caps. These will be chipped away during the scan.
	 */
	fab->pfd_mps_found = PCIE_DEVCAP_MAX_PAYLOAD_4096;
	fab->pfd_tag_found = PCIE_TAG_ALL;
	fab->pfd_flags &= ~PCIE_FABRIC_F_COMPLEX;

	ddi_walk_devs(dip, pcie_fabric_feature_scan, fab);

	if ((fab->pfd_flags & PCIE_FABRIC_F_COMPLEX) != 0) {
		fab->pfd_tag_act = PCIE_TAG_5B;
		fab->pfd_mps_act = PCIE_DEVCAP_MAX_PAYLOAD_128;
	} else {
		fab->pfd_tag_act = fab->pfd_tag_found;
		fab->pfd_mps_act = fab->pfd_mps_found;
	}

	ddi_walk_devs(dip, pcie_fabric_feature_set, fab);

	fab->pfd_flags &= ~PCIE_FABRIC_F_SCANNING;
	ndi_devi_exit(pdip);
}
