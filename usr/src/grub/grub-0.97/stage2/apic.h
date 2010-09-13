/*
 *  <Insert copyright here : it must be BSD-like so everyone can use it>
 *
 *  Author:  Erich Boleyn  <erich@uruk.org>   http://www.uruk.org/~erich/
 *
 *  Header file for Intel Architecture local and I/O APIC definitions.
 *
 *  This file was created from information in the Intel Pentium Pro
 *  Family Developer's Manual, Volume 3: Operating System Writer's
 *  Manual, order number 242692-001, which can be ordered from the
 *  Intel literature center.
 */

#ifndef _APIC_H
#define _APIC_H

/*
 *  APIC Defines.
 */

#define APIC_BROADCAST_ID		       	0xFF

/*
 *  APIC register definitions
 */

/*
 *  Shared defines for I/O and local APIC definitions
 */
/* APIC version register */
#define	APIC_VERSION(x)				((x) & 0xFF)
/* if the APIC version is equal or greater than APIC_VER_NEW, it
   is a "new" APIC */
#define APIC_VER_NEW				0x10
/* this next one is used in all cases but an old local APIC, which has
   2 entries in it's LVT */
#define	APIC_MAXREDIR(x)			(((x) >> 16) & 0xFF)
/* APIC id register */
#define	APIC_OLD_ID(x)				((x) >> 24)
#define	APIC_NEW_ID(x)				(((x) >> 24) & 0xF)

#define IOAPIC_REGSEL				0
#define IOAPIC_RW				0x10
#define		IOAPIC_ID			0
#define		IOAPIC_VER			1
#define		IOAPIC_REDIR			0x10
#define LAPIC_ID				0x20
#define LAPIC_VER				0x30
#define LAPIC_TPR				0x80
#define LAPIC_APR				0x90
#define LAPIC_PPR				0xA0
#define LAPIC_EOI				0xB0
#define LAPIC_LDR				0xD0
#define LAPIC_DFR				0xE0
#define LAPIC_SPIV				0xF0
#define		LAPIC_SPIV_ENABLE_APIC		0x100
#define LAPIC_ISR				0x100
#define LAPIC_TMR				0x180
#define LAPIC_IRR				0x200
#define LAPIC_ESR				0x280
#define LAPIC_ICR				0x300
#define		LAPIC_DEST_MASK			0xFFFFFF
#define LAPIC_LVTT				0x320
#define LAPIC_LVTPC		       		0x340
#define LAPIC_LVT0				0x350
#define LAPIC_LVT1				0x360
#define LAPIC_LVTE				0x370
#define LAPIC_TICR				0x380
#define LAPIC_TCCR				0x390
#define LAPIC_TDCR				0x3E0

#endif /* _APIC_H */
