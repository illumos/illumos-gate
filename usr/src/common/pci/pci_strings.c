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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include "pci_strings.h"

const pci_class_strings_t class_pci[] = {
	0, 0, 0,	"Unspecified class",			"unknown",
	0, 1, 0,	"VGA compatible controller",		"unknown",

	1, 0, 0,	"SCSI bus controller",			"scsi",
	1, 1, 0x80,	"IDE controller", /* Special case */	"ide",
	1, 2, 0,	"Floppy controller",			"flpydis",
	1, 3, 0,	"IPI bus controller",			"ipi",
	1, 4, 0,	"RAID controller",			"raid",
	1, 5, 0x20,	"ATA controller with single DMA",	"ata",
	1, 5, 0x30,	"ATA controller with chained DMA",	"ata",
	1, 6, 0,	"Serial ATA Direct Port Access (DPA)",	"sata",
	1, 6, 1,	"SATA AHCI Interface",			"sata",
	1, 6, 2,	"Serial Storage Bus Interface",		"sata",
	1, 7, 0,	"Serial Attached SCSI Controller",	"sas",
	1, 7, 1,	"Serial Storage Bus Interface",		"sas",
	1, 0x80, 0,	"Mass storage controller",		"unknown",

	2, 0, 0,	"Ethernet controller",			"etherne",
	2, 1, 0,	"Token ring controller",		"tokenrg",
	2, 2, 0,	"FDDI controller",			"fddi",
	2, 3, 0,	"ATM controller",			"atm",
	2, 4, 0,	"ISDN controller",			"isdn",
	2, 5, 0,	"WorldFip controller",			"unknown",
	2, 6, 0,	"PICMG 2.14 Multi computing controller", "mcd",
	2, 0x80, 0,	"Network controller",			"unknown",

	3, 0, 0,	"VGA compatible controller",		"vga",
	3, 0, 1,	"8514-compatible display controller",	"vgs8514",
	3, 1, 0,	"XGA video controller",			"xga",
	3, 2, 0,	"3D controller",			"3d",
	3, 0x80, 0,	"Video controller",			"unknown",

	4, 0, 0,	"Video device",				"video",
	4, 1, 0,	"Audio device",				"audio",
	4, 2, 0,	"Computer Telephony device",		"teleph",
	4, 3, 0,	"Mixed Mode device",			"mixed",
	4, 0x80, 0,	"Multimedia device",			"unknown",

	5, 0, 0,	"Ram",					"ram",
	5, 1, 0,	"Flash memory",				"flash",
	5, 0x80, 0,	"Memory controller",			"unknown",

	6, 0, 0,	"Host bridge",				"hostpci",
	6, 1, 0,	"ISA bridge",				"pci-isa",
	6, 2, 0,	"EISA bridge",				"pcieisa",
	6, 3, 0,	"MCA bridge",				"pci-mca",
	6, 4, 0,	"PCI-PCI bridge",			"pci-pci",
	6, 4, 1,	"Subtractive Decode PCI-PCI bridge",	"unknown",
	6, 5, 0,	"PCMCIA bridge",			"pcipcmc",
	6, 6, 0,	"NuBus bridge",				"pcinubu",
	6, 7, 0,	"CardBus bridge",			"pcicard",
	6, 8, 0,	"RACE-way bridge transport mode",	"pcirace",
	6, 8, 1,	"RACE-way bridge endpoint mode",	"pcirace",
	6, 9, 0x40,	"Semi-transparent PCI-PCI primary bridge",   "stpci",
	6, 9, 0x80,	"Semi-transparent PCI-PCI secondary bridge", "stpci",
	6, 0xA, 0,	"Infiniband-PCI bridge",		"ib-pci",
	6, 0xB, 0,	"AS Custom Interface bridge",		"as-pci",
	6, 0xB, 1,	"ASI-SIG Defined Portal Interface",	"as-pci",
	6, 0x80, 0,	"Bridge device",			"unknown",

	7, 0, 0,	"Serial controller",			"serial",
	7, 0, 1,	"16450-compatible serial controller",	"paralle",
	7, 0, 2,	"16550-compatible serial controller",	"paralle",
	7, 0, 3,	"16650-compatible serial controller",	"paralle",
	7, 0, 4,	"16750-compatible serial controller",	"paralle",
	7, 0, 5,	"16850-compatible serial controller",	"paralle",
	7, 0, 6,	"16950-compatible serial controller",	"paralle",
	7, 1, 0,	"Parallel port",			"paralle",
	7, 1, 1,	"Bidirectional parallel port",		"paralle",
	7, 1, 2,	"ECP 1.X parallel port",		"paralle",
	7, 1, 3,	"IEEE 1284 parallel port",		"paralle",
	7, 1, 0xFE,	"IEEE 1284 target device",		"1284tar",
	7, 2, 0,	"Multiport serial controller",		"multise",
	7, 3, 0,	"Modem controller",			"mdmctrl",
	7, 3, 1,	"Hayes 16450-compatible modem",		"modem",
	7, 3, 2,	"Hayes 16550-compatible modem",		"modem",
	7, 3, 3,	"Hayes 16650-compatible modem",		"modem",
	7, 3, 4,	"Hayes 16750-compatible modem",		"modem",
	7, 4, 0,	"GPIB controller",			"gpibctl",
	7, 5, 0,	"Smartcard controller",			"smctrlr",
	7, 0x80, 0,	"Communication device",			"commdev",

	8, 0, 0,	"8259 PIC",				"pic",
	8, 0, 1,	"ISA PIC",				"pic",
	8, 0, 2,	"EISA PIC",				"pic",
	8, 0, 0x10,	"I/O APIC",				"pic",
	8, 0, 0x20,	"I/O(x) APIC",				"iopic",
	8, 1, 0,	"8237 DMA controller",			"dma",
	8, 1, 1,	"ISA DMA controller",			"dma",
	8, 1, 2,	"EISA DMA controller",			"dma",
	8, 2, 0,	"8254 system timer",			"timer",
	8, 2, 1,	"ISA system timer",			"timer",
	8, 2, 2,	"EISA system timers",			"timer",
	8, 2, 3,	"High Performance Event timer",		"timer",
	8, 3, 0,	"Real time clock",			"rtc",
	8, 3, 1,	"ISA real time clock",			"rtc",
	8, 4, 0,	"PCI Hot-Plug controller",		"pcihp",
	8, 5, 0,	"SD Host controller",			"sd-hc",
	8, 6, 0,	"IOMMU controller",			"iommu",
	8, 0x80, 0,	"System peripheral",			"unknown",

	9, 0, 0,	"Keyboard controller",			"keyboar",
	9, 1, 0,	"Digitizer (pen)",			"tablet",
	9, 2, 0,	"Mouse controller",			"mouse",
	9, 3, 0,	"Scanner controller",			"scanner",
	9, 4, 0,	"Gameport controller",			"gamepor",
	9, 4, 0x10,	"Gameport Legacy controller",		"gamepor",
	9, 0x80, 0,	"Input controller",			"unknown",

	10, 0, 0,	"Generic Docking station",		"docking",
	10, 0x80, 0,	"Docking station",			"unknown",

	11, 0, 0,	"386",					"386",
	11, 1, 0,	"486",					"486",
	11, 2, 0,	"Pentium",				"pentium",
	11, 0x10, 0,	"Alpha",				"alpha",
	11, 0x20, 0,	"Power-PC",				"powerpc",
	11, 0x30, 0,	"MIPS",					"mips",
	11, 0x40, 0,	"Co-processor",				"coproc",
	11, 0x80, 0,	"Processor",				"unknown",

	12, 0, 0,	"FireWire (IEEE 1394)",			"1394",
	12, 0, 0x10,	"FireWire (IEEE 1394) OpenHCI compliant", "1394",
	12, 1, 0,	"ACCESS.bus",				"access",
	12, 2, 0,	"SSA",					"ssa",
	12, 3, 0,	"Universal Serial Bus UHCI compliant",	"usb",
	12, 3, 0x10,	"Universal Serial Bus OHCI compliant",	"usb",
	12, 3, 0x20,	"Universal Serial Bus EHCI compliant",	"usb",
	12, 3, 0x80,	"Universal Serial Bus generic HCD",	"usb",
	12, 3, 0xFE,	"Universal Serial Bus device",		"usb",
	12, 4, 0,	"Fibre Channel",			"fibre",
	12, 5, 0,	"SMBus (System Management Bus)",	"smbus",
	12, 6, 0,	"InfiniBand",				"ib",
	12, 7, 0,	"IPMI SMIC Interface",			"ipmi",
	12, 7, 1,	"IPMI Keyboard Controller Style Interface", "ipmi",
	12, 7, 2,	"IPMI Block Transfer Interface",	"ipmi",
	12, 8, 0,	"SERCOS Interface Standard",		"sercos",
	12, 9, 0,	"CANbus",				"canbus",
	12, 0x80, 0,	"Serial Bus Controller",		"unknown",

	13, 0, 0,	"IRDA Wireless controller",		"irda",
	13, 1, 0,	"Consumer IR Wireless controller",	"ir",
	13, 1, 0x10,	"UWB Radio  controller",		"ir-uwb",
	13, 0x10, 0,	"RF Wireless controller",		"rf",
	13, 0x11, 0,	"Bluetooth Wireless controller",	"btooth",
	13, 0x12, 0,	"Broadband Wireless controller",	"brdband",
	13, 0x20, 0,	"802.11a Wireless controller",		"802.11a",
	13, 0x21, 0,	"802.11b Wireless controller",		"802.11b",
	13, 0x80, 0,	"Wireless controller",			"unknown",

	14, 0, 0,	"I20 controller",			"i2o",
	14, 0, 1,	"I20 Arch Specification 1.0",		"i2o",

	15, 1, 0,	"TV Satellite controller",		"tv",
	15, 2, 0,	"Audio Satellite controller",		"audio",
	15, 3, 0,	"Voice Satellite controller",		"voice",
	15, 4, 0,	"Data Satellite controller",		"data",
	15, 0x80, 0,	"Satellite Comm controller",		"unknown",

	16, 0, 0,	"Network and computing en/decryption",	"netcryp",
	16, 1, 0,	"Entertainment en/decryption",		"entcryp",
	16, 0x80, 0,	"En/decryption controller",		"unknown",

	17, 0, 0,	"DPIO modules",				"dpio",
	17, 1, 0,	"Performance counters",			"perfcnt",
	17, 0x10, 0,	"Comm Synch time and freq test/measurement", "cstftm",
	17, 0x20, 0,	"Management card",			"mgmtcrd",
	17, 0x80, 0,	"DSP/DAP controllers",			"unknown"
};

int class_pci_items = sizeof (class_pci) / sizeof (class_pci[0]);
