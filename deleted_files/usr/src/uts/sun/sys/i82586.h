/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1991,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_I82586_H
#define	_SYS_I82586_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This is the number of bytes occupied by the 3E interface buffer.
 */
#define	IE_TE_MEMSIZE	0x20000

/*
 * There are 128 lines of 32 bytes wide IORAM on a Sun4/4XX.
 */
#define	IE_IORAM_SIZE	0x1000

#define	I82586ALIGN	4
#define	IENULLOFF	0xffff	/* null offset value */

/*
 * Register definitions for the Sun 3E Ethernet board.
 *
 * The prefix for the 3E specific structures is tie (the t stands for
 * three).
 *
 * Board ignores high order nibble of chip generated addresses.
 * Reset chip: set tie_csr = TIE_RESET; delay 10us; set tie_csr = 0
 *
 * The address of the register is base + 0x1FF02.
 * The address of the level 3 interrupt vector is base + 0x1FF12.
 */
#define	SCSIREG	15

struct tie_device {
	ushort_t tie_csr;
	uchar_t	tie_unused[SCSIREG];	/* SCSI registers & interrupt vector */
	uchar_t	tie_ivec;		/* Ethernet interrupt vector */
};

#define	TIE_RESET	0x8000		/* board reset */
#define	TIE_NOLOOP	0x4000		/* loopback disable */
#define	TIE_CA		0x2000		/* channel attention */
#define	TIE_IE		0x1000		/* interrupt enable */
#define	TIE_INTR	0x0100		/* interrupt request */

/*
 * Register definitions for the Sun-4 On-board version of the
 * Intel EDLC based Ethernet interface.
 * Reset: write zeros to register. Must poll to check for OBIE_BUSERR
 */
uchar_t obie_csr;

#define	OBIE_NORESET	0x80		/* R/W: Ethernet chips reset */
#define	OBIE_NOLOOP	0x40		/* R/W: loopback */
#define	OBIE_CA		0x20		/* R/W: channel attention */
#define	OBIE_IE		0x10		/* R/W: interrupt enable */
#define	OBIE_LEVEL2	0x04		/* R/O: 0=Level 1 xcvr, 1=Level 2 */
#define	OBIE_BUSERR	0x02		/* R/O: Ether DMA got bus error */
#define	OBIE_INTR	0x01		/* R/O: interrupt request */

typedef	ushort_t 	ieoff_t;	/* CB offsets from iscp cbbase */
typedef ushort_t 	ieint_t;	/* 16 bit integers */
typedef ulong_t		ieaddr_t;	/* data (24-bit) addresses */

/*
 * System Configuration Pointer
 * Must be at 0xFFFFF6 in chip's address space
 */
#define	IESCPADDR	0xFFFFF4	/* compensate for alignment junk */
#define	IESCPPAD	5

struct iescp {
	ushort_t 	iescp_unused0;	/* pad for sparc aligment */
	uchar_t		iescp_sysbus;	/* bus width: 0 => 16, 1 => 8 */
	uchar_t		iescp_unused1[IESCPPAD];
	ieaddr_t	iescp_iscp;	/* address of iscp */
};

/*
 * Intermediate System Configuration Pointer
 * Specifies base of all other control blocks and the offset of the SCB
 */
struct ieiscp {
	uchar_t		ieiscp_busy;	/* 1 => initialization in progress */
	uchar_t		ieiscp_unused;	/* unused */
	ieoff_t		ieiscp_scb;	/* offset of SCB */
	ieaddr_t	ieiscp_cbbase;	/* base of all control blocks */
};

/*
 * The remaining chip data structures all start with a 16-bit status
 * word.  The meaning of the individual bits within a status word
 * depends on the kind of descriptor or control block the word is
 * embedded in.  The driver accesses some status words only through
 * their individual bits; others are accessed as words as well.
 * These latter are defined as unions.
 */

/*
 * System Control Block - the focus of communication
 */
struct iescb {
	ushort_t iescb_status;		/* chip status word */
	ushort_t iescb_cmd;		/* command word */
	ieoff_t	iescb_cbl;		/* command list */
	ieoff_t	iescb_rfa;		/* receive frame area */
	ieint_t	iescb_crcerrs;		/* count of CRC errors */
	ieint_t	iescb_alnerrs;		/* count of alignment errors */
	ieint_t	iescb_rscerrs;		/* count of discarded packets */
	ieint_t	iescb_ovrnerrs;		/* count of overrun packets */
};

/* iescb_status */
#define	IESCB_RUS	0x7000		/* receive unit status */
#define	IESCB_CX	0x0080		/* command done (interrupt) */
#define	IESCB_FR	0x0040		/* frame received (interrupt) */
#define	IESCB_CNA	0x0020		/* command unit left active state */
#define	IESCB_RNR	0x0010		/* receive unit left ready state */
#define	IESCB_CUS	0x0007		/* command unit status */

/* IESCB_RUS */
#define	IERUS_IDLE		0x0	/* Receiving unit idle */
#define	IERUS_SUSPENDED		0x1000	/* Receiving unit suspended */
#define	IERUS_NORESOURCE	0x2000	/* Receiving unit out of resources */
#define	IERUS_READY		0x4000	/* Receiving ready */

/* IESCB_CUS */
#define	IECUS_IDLE		0	/* not executing command */
#define	IECUS_SUSPENDED		1	/* suspended as required */
#define	IECUS_ACTIVE		2	/* busy executing command */

/* iescb_cmd */
#define	IECMD_RESET		0x8000	/* reset chip */
#define	IECMD_RU_START		(1<<12)	/* start receiver unit */
#define	IECMD_RU_RESUME		(2<<12)	/* resume receiver unit */
#define	IECMD_RU_SUSPEND	(3<<12)	/* suspend receiver unit */
#define	IECMD_RU_ABORT		(4<<12)	/* abort receiver unit */
#define	IECMD_ACK_CX		0x80	/* ack command executed */
#define	IECMD_ACK_FR		0x40	/* ack frame received */
#define	IECMD_ACK_CNA		0x20	/* ack CU not ready */
#define	IECMD_ACK_RNR		0x10	/* ack RU not ready */
#define	IECMD_CU_START		1	/* start command unit */
#define	IECMD_CU_RESUME		2	/* resume command unit */
#define	IECMD_CU_SUSPEND	3	/* suspend command unit */
#define	IECMD_CU_ABORT		4	/* abort command unit */


/*
 * Command Unit data structures
 */

/*
 * Generic command block
 *	Status word bits that are defined here have the
 *	same meaning for all command types.  Bits not
 *	defined here don't have a common meaning.
 */
struct iecb {
	ushort_t iecb_status;		/* status word */
	ushort_t iecb_cmd;		/* command word */
	ieoff_t	iecb_next;		/* next CB */
};

/* iecb_status */
#define	IECB_DONE	0x0080		/* command done */
#define	IECB_BUSY	0x0040		/* command busy */
#define	IECB_OK		0x0020		/* command successful */
#define	IECB_ABORTED	0x0010		/* command aborted */

/* iecb_cmd */
#define	IECB_CMD	0x0700		/* command # */
#define	IECB_EL		0x0080		/* end of list */
#define	IECB_SUSP	0x0040		/* suspend when done */
#define	IECB_INTR	0x0020		/* interrupt when done */

/*
 * CB commands (iecb_cmd)
 */
#define	IE_NOP		0x0000
#define	IE_IADDR	0x0100	/* individual address setup */
#define	IE_CONFIG	0x0200	/* configure */
#define	IE_MADDR	0x0300	/* multicast address setup */
#define	IE_TRANSMIT	0x0400	/* transmit */
#define	IE_TDR		0x0500	/* TDR test */
#define	IE_DUMP		0x0600	/* dump registers */
#define	IE_DIAGNOSE	0x0700	/* internal diagnostics */

/*
 * Individual address setup command block
 */
#define	IEETHERADDRL	6

struct ieiaddr {
	struct	iecb ieia_cb;			/* common command block */
	uchar_t	ieia_addr[IEETHERADDRL];	/* the actual address */
};

/*
 * Maximum number of multicast addresses allowed per interface.
 */
#define	IEMCADDRMAX	64

/*
 * Multicast address setup command block
 */
struct iemcaddr {
	struct	iecb	iemc_cb;		/* common command block */
	ieint_t	iemc_count;			/* count of MC addresses */
	uchar_t	iemc_addr[IEMCADDRMAX*6];	/* pool of addresses */
};

/*
 * Configure command
 */
struct ieconf {
	struct	iecb ieconf_cb;	/* common command block */
	uchar_t	ieconf_bytes;	/* # of conf bytes: only the low-order 4 bits */
	uchar_t	ieconf_fifolim;	/* fifo limit: only the low-order 4 bits */
	ushort_t ieconf_data0;
	uchar_t	ieconf_data1;
	uchar_t	ieconf_space;	/* interframe spacing */
	uchar_t	ieconf_slttml8;	/* low bits of slot time */
	uchar_t  ieconf_data2;
	ushort_t ieconf_data3;
	uchar_t	ieconf_minfrm;	/* min frame length */
	uchar_t	ieconf_pad;
};

/* ieconf_data0 */
#define	IECONF_SAVBF	0x8000		/* save bad frames */
#define	IECONF_SRDY	0x4000		/* srdy/ardy (?) */
#define	IECONF_EXTLP	0x0080		/* external loopback */
#define	IECONF_INTLP	0x0040		/* internal loopback */
#define	IECONF_PREAM	0x0030		/* preamble length code */
#define	IECONF_ACLOC	0x0008		/* addr & type fields separate */
#define	IECONF_ALEN	0x0007		/* address length */

/* ieconf_data1 */
#define	IECONF_BOF	0x80		/* backoff method */
#define	IECONF_ACR	0x70		/* exponential prio */
#define	IECONF_LINPRIO	0x70		/* linear prio */

/* ieconf_data2 */
#define	IECONF_RETRY	0xf0		/* # xmit retries */
#define	IECONF_SLTTMH	0x07		/* high bits of slot time */

/* ieconf_data3 */
#define	IECONF_PAD	0x8000		/* flag padding */
#define	IECONF_HDLC	0x4000		/* HDLC framing */
#define	IECONF_CRC16	0x2000		/* CRC type */
#define	IECONF_NOCRC	0x1000		/* disable CRC appending */
#define	IECONF_NOCARR	0x0800		/* no carrier OK */
#define	IECONF_MANCH	0x0400		/* Manchester encoding */
#define	IECONF_NOBRD	0x0200		/* broadcast disable */
#define	IECONF_PROMISC	0x0100		/* promiscuous mode */
#define	IECONF_CDSRC	0x0080		/* CD source */
#define	IECONF_CDFILT	0x0070		/* CD filter bits (?) */
#define	IECONF_CRSRC	0x0008		/* carrier source */
#define	IECONF_CRFILT	0x0007		/* carrier filter bits */

/*
 * Transmit frame descriptor ( Transmit command block )
 */
struct ietcb {
	ushort_t ietcb_status;		/* transmit command block status */
	ushort_t ietcb_command;		/* command # */
	ieoff_t	ietcb_next;		/* next TCB */
	ieoff_t	ietcb_tbd;		/* pointer to buffer descriptor */
	uchar_t	ietcb_dhost[6];		/* destination address field */
	ushort_t ietcb_type;		/* Ethernet packet type field */
};

/* ietcb_status */
#define	IETCB_DEFER	0x8000		/* transmission deferred */
#define	IETCB_HEART	0x4000		/* heartbeat */
#define	IETCB_XCOLL	0x2000		/* too many collisions */
#define	IETCB_NCOLL	0x0f00		/* number of collisions */
#define	IETCB_DONE	0x0080		/* command done */
#define	IETCB_BUSY	0x0040		/* command busy */
#define	IETCB_OK	0x0020		/* command successful */
#define	IETCB_ABORTED	0x0010		/* command aborted */
#define	IETCB_NOCARR	0x0004		/* no carrier sense */
#define	IETCB_NOCTS	0x0002		/* lost clear to send */
#define	IETCB_UNDERRUN	0x0001		/* DMA underrun */

/* ietcb_command */
#define	IETCB_CMD	0x0700		/* command # */
#define	IETCB_EL	0x0080		/* end of list */
#define	IETCB_SUSP	0x0040		/* suspend when done */
#define	IETCB_INTR	0x0020		/* interrupt when done */

/*
 * Transmit buffer descriptor
 */
struct ietbd {
	uchar_t	 ietbd_cntlo;		/* Low order 8 bits of count */
	uchar_t	 ietbd_eofcnthi;
	ieoff_t	 ietbd_next;		/* next TBD */
	ieaddr_t ietbd_buf;		/* pointer to buffer */
};

/* ietbd_eofcnthi */
#define	IETBD_EOF	0x80		/* last buffer for this packet */
#define	IETBD_CNTHI	0x3f		/* high order 6 bits of count */

/*
 * Receive Unit data structures
 */

/*
 * Receive frame descriptor
 */
struct ierfd {
	ushort_t ierfd_status;		/* rfd status word */
	uchar_t	ierfd_pad;		/* unused */
	uchar_t	ierfd_command;		/* rfd command word */
	ieoff_t	ierfd_next;		/* next RFD */
	volatile ieoff_t ierfd_rbd;	/* pointer to buffer descriptor */
	uchar_t	ierfd_dhost[6];		/* destination address field */
	uchar_t	ierfd_shost[6];		/* source address field */
	ushort_t ierfd_type;		/* Ethernet packet type field */
	ushort_t pad;			/* for 32-bit alignment */
};

/* ierfd_status */
#define	IERFD_SHORT	0x8000		/* short frame */
#define	IERFD_NOEOF	0x4000		/* no EOF (for bitstuffing) */
#define	IERFD_DONE	0x0080		/* command done */
#define	IERFD_BUSY	0x0040		/* command busy */
#define	IERFD_OK	0x0020		/* command successful */
#define	IERFD_CRCERR	0x0008		/* crc error */
#define	IERFD_ALIGN	0x0004		/* alignment error */
#define	IERFD_NOSPACE	0x0002		/* out of buffer space */
#define	IERFD_OVERRUN	0x0001		/* DMA overrun */

/* ierfd_command */
#define	IERFD_EL	0x80		/* end of list */
#define	IERFD_SUSP	0x40		/* suspend when done */

/*
 * Receive buffer descriptor
 */
struct ierbd {
	uchar_t ierbd_cntlo;		/* Low order 8 bits of count */
	uchar_t ierbd_status;		/* rbd status word */
	ieoff_t ierbd_next;		/* next RBD */
	ieaddr_t ierbd_buf;		/* pointer to buffer */
	uchar_t	ierbd_sizelo;		/* Low order 8 bits of buffer size */
	uchar_t	ierbd_elsize;		/* high order bits and el */
	ushort_t pad;			/* For 32-bit alignment */
};

/* ierbd_status */
#define	IERBD_EOF	0x80		/* last buffer of the packet */
#define	IERBD_VALID	0x40		/* CNT is valid */
#define	IERBD_CNTHI	0x3f		/* high order 6 bits of count */

/* ierbd_elsize */
#define	IERBD_EL	0x80		/* end-of-list if set */
#define	IERBD_SIZEHI	0x3f		/* high order 6 bits of buffer size */

typedef struct ietcb ietcb_t;
typedef struct ietbd ietbd_t;
typedef struct ierfd ierfd_t;
typedef struct ierbd ierbd_t;

#ifdef	__cplusplus
}
#endif

#endif /* !_SYS_I82586_H */
