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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_SCSI_IMPL_COMMANDS_H
#define	_SYS_SCSI_IMPL_COMMANDS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Implementation dependent command definitions.
 * This file is included by <sys/scsi/generic/commands.h>
 */

/*
 * Implementation dependent view of a SCSI command descriptor block
 */

/*
 * Standard SCSI control blocks definitions.
 *
 * These go in or out over the SCSI bus.
 *
 * The first 8 bits of the command block are the same for all
 * defined command groups.  The first byte is an operation which consists
 * of a command code component and a group code component.
 *
 * The group code determines the length of the rest of the command.
 * Group 0 commands are 6 bytes, Group 1 and 2  are 10 bytes, Group 4
 * are 16 bytes, and Group 5 are 12 bytes. Groups 3 is Reserved.
 * Groups 6 and 7 are Vendor Unique.
 *
 */
#define	CDB_SIZE	CDB_GROUP5	/* deprecated, do not use */
#define	SCSI_CDB_SIZE	CDB_GROUP4	/* sizeof (union scsi_cdb) */

union scsi_cdb {		/* scsi command description block */
	struct {
		uchar_t	cmd;		/* cmd code (byte 0) */
#if defined(_BIT_FIELDS_LTOH)
		uchar_t tag	:5;	/* rest of byte 1 */
		uchar_t lun	:3;	/* lun (byte 1) (reserved in SCSI-3) */
#elif defined(_BIT_FIELDS_HTOL)
		uchar_t	lun	:3,	/* lun (byte 1) (reserved in SCSI-3) */
			tag	:5;	/* rest of byte 1 */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
		union {

		uchar_t	scsi[SCSI_CDB_SIZE-2];
		/*
		 *	G R O U P   0   F O R M A T (6 bytes)
		 */
#define		scc_cmd		cdb_un.cmd
#define		scc_lun		cdb_un.lun
#define		g0_addr2	cdb_un.tag
#define		g0_addr1	cdb_un.sg.g0.addr1
#define		g0_addr0	cdb_un.sg.g0.addr0
#define		g0_count0	cdb_un.sg.g0.count0
#define		g0_vu_1		cdb_un.sg.g0.vu_57
#define		g0_vu_0		cdb_un.sg.g0.vu_56
#define		g0_naca		cdb_un.sg.g0.naca
#define		g0_flag		cdb_un.sg.g0.flag
#define		g0_link		cdb_un.sg.g0.link
	/*
	 * defines for SCSI tape cdb.
	 */
#define		t_code		cdb_un.tag
#define		high_count	cdb_un.sg.g0.addr1
#define		mid_count	cdb_un.sg.g0.addr0
#define		low_count	cdb_un.sg.g0.count0
		struct scsi_g0 {
			uchar_t addr1;	/* middle part of address */
			uchar_t addr0;	/* low part of address */
			uchar_t count0;	/* usually block count */
#if defined(_BIT_FIELDS_LTOH)
			uchar_t link	:1; /* another command follows 	*/
			uchar_t flag	:1; /* interrupt when done 	*/
			uchar_t naca	:1; /* normal ACA  		*/
			uchar_t rsvd	:3; /* reserved 		*/
			uchar_t vu_56	:1; /* vendor unique (byte 5 bit6) */
			uchar_t vu_57	:1; /* vendor unique (byte 5 bit7) */
#elif defined(_BIT_FIELDS_HTOL)
			uchar_t vu_57	:1; /* vendor unique (byte 5 bit 7) */
			uchar_t vu_56	:1; /* vendor unique (byte 5 bit 6) */
			uchar_t rsvd	:3; /* reserved */
			uchar_t naca	:1; /* normal ACA  		*/
			uchar_t flag	:1; /* interrupt when done */
			uchar_t link	:1; /* another command follows */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
		} g0;


		/*
		 *	G R O U P   1, 2   F O R M A T  (10 byte)
		 */
#define		g1_reladdr	cdb_un.tag
#define		g1_rsvd0	cdb_un.sg.g1.rsvd1
#define		g1_addr3	cdb_un.sg.g1.addr3	/* msb */
#define		g1_addr2	cdb_un.sg.g1.addr2
#define		g1_addr1	cdb_un.sg.g1.addr1
#define		g1_addr0	cdb_un.sg.g1.addr0	/* lsb */
#define		g1_count1	cdb_un.sg.g1.count1	/* msb */
#define		g1_count0	cdb_un.sg.g1.count0	/* lsb */
#define		g1_vu_1		cdb_un.sg.g1.vu_97
#define		g1_vu_0		cdb_un.sg.g1.vu_96
#define		g1_naca		cdb_un.sg.g1.naca
#define		g1_flag		cdb_un.sg.g1.flag
#define		g1_link		cdb_un.sg.g1.link
		struct scsi_g1 {
			uchar_t addr3;	/* most sig. byte of address */
			uchar_t addr2;
			uchar_t addr1;
			uchar_t addr0;
			uchar_t rsvd1;	/* reserved (byte 6) */
			uchar_t count1;	/* transfer length (msb) */
			uchar_t count0;	/* transfer length (lsb) */
#if defined(_BIT_FIELDS_LTOH)
			uchar_t link	:1; /* another command follows 	*/
			uchar_t flag	:1; /* interrupt when done 	*/
			uchar_t naca	:1; /* normal ACA		*/
			uchar_t rsvd0	:3; /* reserved 		*/
			uchar_t vu_96	:1; /* vendor unique (byte 9 bit6) */
			uchar_t vu_97	:1; /* vendor unique (byte 9 bit7) */
#elif defined(_BIT_FIELDS_HTOL)
			uchar_t vu_97	:1; /* vendor unique (byte 9 bit 7) */
			uchar_t vu_96	:1; /* vendor unique (byte 9 bit 6) */
			uchar_t rsvd0	:3; /* reserved */
			uchar_t naca	:1; /* normal ACA		*/
			uchar_t flag	:1; /* interrupt when done */
			uchar_t link	:1; /* another command follows */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
		} g1;

		/*
		 *	G R O U P   4   F O R M A T  (16 byte)
		 */
#define		g4_reladdr		cdb_un.tag
#define		g4_addr3		cdb_un.sg.g4.addr3	/* msb */
#define		g4_addr2		cdb_un.sg.g4.addr2
#define		g4_addr1		cdb_un.sg.g4.addr1
#define		g4_addr0		cdb_un.sg.g4.addr0	/* lsb */
#define		g4_addtl_cdb_data3	cdb_un.sg.g4.addtl_cdb_data3
#define		g4_addtl_cdb_data2	cdb_un.sg.g4.addtl_cdb_data2
#define		g4_addtl_cdb_data1	cdb_un.sg.g4.addtl_cdb_data1
#define		g4_addtl_cdb_data0	cdb_un.sg.g4.addtl_cdb_data0
#define		g4_count3		cdb_un.sg.g4.count3	/* msb */
#define		g4_count2		cdb_un.sg.g4.count2
#define		g4_count1		cdb_un.sg.g4.count1
#define		g4_count0		cdb_un.sg.g4.count0	/* lsb */
#define		g4_rsvd0		cdb_un.sg.g4.rsvd1
#define		g4_vu_1			cdb_un.sg.g4.vu_157
#define		g4_vu_0			cdb_un.sg.g4.vu_156
#define		g4_naca			cdb_un.sg.g4.naca
#define		g4_flag			cdb_un.sg.g4.flag
#define		g4_link			cdb_un.sg.g4.link
		struct scsi_g4 {
			uchar_t addr3;	/* most sig. byte of address */
			uchar_t addr2;
			uchar_t addr1;
			uchar_t addr0;
			uchar_t addtl_cdb_data3;
			uchar_t addtl_cdb_data2;
			uchar_t addtl_cdb_data1;
			uchar_t addtl_cdb_data0;
			uchar_t count3;	/* transfer length (msb) */
			uchar_t count2;
			uchar_t count1;
			uchar_t count0;	/* transfer length (lsb) */
			uchar_t rsvd1;	/* reserved */
#if defined(_BIT_FIELDS_LTOH)
			uchar_t link	:1; /* another command follows 	*/
			uchar_t flag	:1; /* interrupt when done 	*/
			uchar_t naca	:1; /* normal ACA		*/
			uchar_t rsvd0	:3; /* reserved 		*/
			uchar_t vu_156	:1; /* vendor unique (byte 15 bit6) */
			uchar_t vu_157	:1; /* vendor unique (byte 15 bit7) */
#elif defined(_BIT_FIELDS_HTOL)
			uchar_t vu_157	:1; /* vendor unique (byte 15 bit 7) */
			uchar_t vu_156	:1; /* vendor unique (byte 15 bit 6) */
			uchar_t rsvd0	:3; /* reserved */
			uchar_t naca	:1; /* normal ACA		*/
			uchar_t flag	:1; /* interrupt when done */
			uchar_t link	:1; /* another command follows */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
		} g4;

		/*
		 *	G R O U P   5   F O R M A T  (12 byte)
		 */
#define		scc5_reladdr	cdb_un.tag
#define		scc5_addr3	cdb_un.sg.g5.addr3	/* msb */
#define		scc5_addr2	cdb_un.sg.g5.addr2
#define		scc5_addr1	cdb_un.sg.g5.addr1
#define		scc5_addr0	cdb_un.sg.g5.addr0	/* lsb */
#define		scc5_count3	cdb_un.sg.g5.count3	/* msb */
#define		scc5_count2	cdb_un.sg.g5.count2
#define		scc5_count1	cdb_un.sg.g5.count1
#define		scc5_count0	cdb_un.sg.g5.count0	/* lsb */
#define		scc5_rsvd0	cdb_un.sg.g5.rsvd1
#define		scc5_vu_1	cdb_un.sg.g5.v117
#define		scc5_vu_0	cdb_un.sg.g5.v116
#define		scc5_naca	cdb_un.sg.g5.naca
#define		scc5_flag	cdb_un.sg.g5.flag
#define		scc5_link	cdb_un.sg.g5.link
		struct scsi_g5 {
			uchar_t addr3;	/* most sig. byte of address */
			uchar_t addr2;
			uchar_t addr1;
			uchar_t addr0;
			uchar_t count3;	/* most sig. byte of count */
			uchar_t count2;
			uchar_t count1;
			uchar_t count0;
			uchar_t rsvd1;	/* reserved */
#if defined(_BIT_FIELDS_LTOH)
			uchar_t link	:1; /* another command follows 	*/
			uchar_t flag	:1; /* interrupt when done 	*/
			uchar_t naca	:1; /* normal ACA		*/
			uchar_t rsvd0	:3; /* reserved 		*/
			uchar_t vu_116	:1; /* vendor unique (byte 11 bit6) */
			uchar_t vu_117	:1; /* vendor unique (byte 11 bit7) */
#elif defined(_BIT_FIELDS_HTOL)
			uchar_t vu_117	:1; /* vendor unique (byte 11 bit 7) */
			uchar_t vu_116	:1; /* vendor unique (byte 11 bit 6) */
			uchar_t rsvd0	:3; /* reserved */
			uchar_t naca	:1; /* normal ACA		*/
			uchar_t flag	:1; /* interrupt when done */
			uchar_t link	:1; /* another command follows */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
		} g5;
		}sg;
	} cdb_un;
	uchar_t cdb_opaque[SCSI_CDB_SIZE]; /* addressed as opaque char array */
	uint_t cdb_long[SCSI_CDB_SIZE / sizeof (uint_t)]; /* as a word array */
};


/*
 *	Various useful Macros for SCSI commands
 */

/*
 * defines for getting/setting fields in data received from or destined for
 * a SCSI device.  These macros are necessary (in place of BE16/BE32/BE64)
 * because the address to be read or written may not be on a proper alignment.
 */

#define	SCSI_READ16(Sr16_Addr) \
	(((uint16_t)*((uint8_t *)(Sr16_Addr)) << 8) | \
	    ((uint16_t)*((uint8_t *)(Sr16_Addr)+1)))

#define	SCSI_READ24(Sr32_Addr)	\
	(((uint32_t)*((uint8_t *)(Sr32_Addr)) << 16) | \
	    ((uint32_t)*((uint8_t *)(Sr32_Addr)+1) << 8) | \
	    ((uint32_t)*((uint8_t *)(Sr32_Addr)+2)))

#define	SCSI_READ32(Sr32_Addr) \
	(((uint32_t)*((uint8_t *)(Sr32_Addr)) << 24) | \
	    ((uint32_t)*((uint8_t *)(Sr32_Addr)+1) << 16) | \
	    ((uint32_t)*((uint8_t *)(Sr32_Addr)+2) << 8) | \
	    ((uint32_t)*((uint8_t *)(Sr32_Addr)+3)))

#define	SCSI_READ40(Sr64_Addr)	\
	(((uint64_t)*((uint8_t *)(Sr64_Addr)) << 32) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+1) << 24) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+2) << 16) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+3) << 8) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+4)))

#define	SCSI_READ48(Sr64_Addr)	\
	(((uint64_t)*((uint8_t *)(Sr64_Addr)) << 40) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+1) << 32) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+2) << 24) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+3) << 16) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+4) << 8) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+5)))

#define	SCSI_READ64(Sr64_Addr) \
	(((uint64_t)*((uint8_t *)(Sr64_Addr)) << 56) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+1) << 48) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+2) << 40) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+3) << 32) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+4) << 24) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+5) << 16) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+6) << 8) | \
	    ((uint64_t)*((uint8_t *)(Sr64_Addr)+7)))

#define	SCSI_WRITE16(Sr16_Addr, Sr16_Val) \
	*((uint8_t *)(Sr16_Addr)) = (((uint16_t)(Sr16_Val) >> 8) & 0xff), \
	*((uint8_t *)(Sr16_Addr)+1) = ((uint16_t)(Sr16_Val) & 0xff)

#define	SCSI_WRITE24(Sr24_Addr, Sr24_Val) \
	SCSI_WRITE16((Sr24_Addr), ((Sr24_Val) & 0xffff00) >> 8),	\
	*((uint8_t *)(Sr24_Addr)+2) = ((uint8_t)((Sr24_Val) & 0xff))

#define	SCSI_WRITE32(Sr32_Addr, Sr32_Val) \
	*(uint8_t *)(Sr32_Addr) = (((uint32_t)(Sr32_Val) >> 24) & 0xff), \
	*((uint8_t *)(Sr32_Addr)+1) = \
	    (((uint32_t)(Sr32_Val) >> 16) & 0xff), \
	*((uint8_t *)(Sr32_Addr)+2) = (((uint32_t)(Sr32_Val) >> 8) & 0xff), \
	*((uint8_t *)(Sr32_Addr)+3) = (((uint32_t)(Sr32_Val)) & 0xff)

#define	SCSI_WRITE40(Sr40_Addr, Sr40_Val) \
	SCSI_WRITE32((Sr40_Addr), ((Sr40_Val) & 0xffffffff00ULL) >> 8),	\
	*((uint8_t *)(Sr40_Addr)+4) = ((uint8_t)(Sr40_Val) & 0xff)

#define	SCSI_WRITE48(Sr48_Addr, Sr40_Val) \
	SCSI_WRITE32((Sr48_Addr), ((Sr48_Val) & 0xffffffff0000ULL) >> 16), \
	SCSI_WRITE16((uint8_t *)(Sr48_Addr)+4, (Sr40_Val) & 0xffff)

#define	SCSI_WRITE64(Sr64_Addr, Sr64_Val) \
	*(uint8_t *)(Sr64_Addr) = (((uint64_t)(Sr64_Val) >> 56) & 0xff), \
	*((uint8_t *)(Sr64_Addr)+1) = \
	    (((uint64_t)(Sr64_Val) >> 48) & 0xff), \
	*((uint8_t *)(Sr64_Addr)+2) = \
	    (((uint64_t)(Sr64_Val) >> 40) & 0xff), \
	*((uint8_t *)(Sr64_Addr)+3) = \
	    (((uint64_t)(Sr64_Val) >> 32) & 0xff), \
	*((uint8_t *)(Sr64_Addr)+4) = \
	    (((uint64_t)(Sr64_Val) >> 24) & 0xff), \
	*((uint8_t *)(Sr64_Addr)+5) = \
	    (((uint64_t)(Sr64_Val) >> 16) & 0xff), \
	*((uint8_t *)(Sr64_Addr)+6) = \
	    (((uint64_t)(Sr64_Val) >> 8) & 0xff), \
	*((uint8_t *)(Sr64_Addr)+7) = (((uint64_t)(Sr64_Val)) & 0xff)

/*
 * These macros deal with unaligned data that crosses a byte boundary.
 */
#define	SCSI_MK8(ms, ls)	\
	(((uint8_t)(ms) << 4) | (uint8_t)ls)

#define	SCSI_MK12_4_8(ms, ls)	\
	(((uint16_t)(ms) << 8) | (uint16_t)(ls))
#define	SCSI_MK12_8_4(ms, ls)	\
	(((uint16_t)(ms) << 4) | (uint16_t)(ls))

#define	SCSI_MK16_4_8_4(hi, mid, lo)	\
	(((uint16_t)(hi) << 12) | ((uint16_t)(mid) << 4) | (uint16_t)(lo))

#define	SCSI_MK20_4_16(ms, ls)	\
	(((uint32_t)(ms) << 16) | ((uint32_t)(ls)))
#define	SCSI_MK20_16_4(ms, ls)	\
	(((uint32_t)(ms) << 4) | ((uint32_t)(ls)))

#define	SCSI_MK24_4_16_4(hi, mid, lo)	\
	(((uint32_t)(hi) << 20) | ((uint32_t)(mid) << 4) | (uint32_t)(lo))

#define	SCSI_MK36_4_32(ms, ls)	\
	(((uint64_t)(ms) << 32) | (uint64_t)(ls))
#define	SCSI_MK36_32_4(ms, ls)	\
	(((uint64_t)(ms) << 4) | (uint64_t)(ls))

/*
 * defines for getting/setting fields within the various command groups
 */

#define	GETCMD(cdb)		((cdb)->scc_cmd & 0x1F)
#define	GETGROUP(cdb)		(CDB_GROUPID((cdb)->scc_cmd))

#define	FORMG0COUNT(cdb, cnt)	(cdb)->g0_count0  = (cnt)

#define	FORMG0ADDR(cdb, addr) 	(cdb)->g0_addr2  = (addr) >> 16; \
				(cdb)->g0_addr1  = ((addr) >> 8) & 0xFF; \
				(cdb)->g0_addr0  = (addr) & 0xFF

#define	GETG0COUNT(cdb)		(cdb)->g0_count0

#define	GETG0ADDR(cdb)		((((cdb)->g0_addr2 & 0x1F) << 16) + \
				((cdb)->g0_addr1 << 8) + ((cdb)->g0_addr0))

#define	GETG0TAG(cdb)		((cdb)->g0_addr2)

#define	FORMG0COUNT_S(cdb, cnt)	(cdb)->high_count  = (cnt) >> 16; \
				(cdb)->mid_count = ((cnt) >> 8) & 0xFF; \
				(cdb)->low_count = (cnt) & 0xFF

#define	FORMG1COUNT(cdb, cnt)	(cdb)->g1_count1 = ((cnt) >> 8); \
				(cdb)->g1_count0 = (cnt) & 0xFF

#define	FORMG1ADDR(cdb, addr)	(cdb)->g1_addr3  = (addr) >> 24; \
				(cdb)->g1_addr2  = ((addr) >> 16) & 0xFF; \
				(cdb)->g1_addr1  = ((addr) >> 8) & 0xFF; \
				(cdb)->g1_addr0  = (addr) & 0xFF

#define	GETG1COUNT(cdb)		(((cdb)->g1_count1 << 8) + ((cdb)->g1_count0))

#define	GETG1ADDR(cdb)		(((cdb)->g1_addr3 << 24) + \
				((cdb)->g1_addr2 << 16) + \
				((cdb)->g1_addr1 << 8)  + \
				((cdb)->g1_addr0))

#define	GETG1TAG(cdb)		(cdb)->g1_reladdr

#define	FORMG4COUNT(cdb, cnt)	(cdb)->g4_count3 = ((cnt) >> 24); \
				(cdb)->g4_count2 = ((cnt) >> 16) & 0xFF; \
				(cdb)->g4_count1 = ((cnt) >> 8) & 0xFF; \
				(cdb)->g4_count0 = (cnt) & 0xFF

#define	FORMG4LONGADDR(cdb, addr)	(cdb)->g4_addr3 = (addr) >> 56; \
					(cdb)->g4_addr2 = \
						((addr) >> 48) & 0xFF; \
					(cdb)->g4_addr1 = \
						((addr) >> 40) & 0xFF; \
					(cdb)->g4_addr0 = \
						((addr) >> 32) & 0xFF; \
					(cdb)->g4_addtl_cdb_data3 = \
						((addr) >> 24) & 0xFF; \
					(cdb)->g4_addtl_cdb_data2 = \
						((addr) >> 16) & 0xFF; \
					(cdb)->g4_addtl_cdb_data1 = \
						((addr) >> 8) & 0xFF; \
					(cdb)->g4_addtl_cdb_data0 = \
						(addr) & 0xFF

#define	GETG4COUNT(cdb)		(((cdb)->g4_count3 << 24) + \
				((cdb)->g4_count2 << 16) + \
				((cdb)->g4_count1 << 8) + \
				((cdb)->g4_count0))

#define	GETG4LONGADDR(cdb)	(((diskaddr_t)(cdb)->g4_addr3 << 56) + \
			((diskaddr_t)(cdb)->g4_addr2 << 48) + \
			((diskaddr_t)(cdb)->g4_addr1 << 40) + \
			((diskaddr_t)(cdb)->g4_addr0 << 32) + \
			((diskaddr_t)(cdb)->g4_addtl_cdb_data3 << 24) + \
			((diskaddr_t)(cdb)->g4_addtl_cdb_data2 << 16) + \
			((diskaddr_t)(cdb)->g4_addtl_cdb_data1 << 8) + \
			((diskaddr_t)(cdb)->g4_addtl_cdb_data0))

#define	FORMG4ADDR(cdb, addr)	(cdb)->g4_addr3 = (addr) >> 24; \
				(cdb)->g4_addr2 = ((addr) >> 16) & 0xFF; \
				(cdb)->g4_addr1 = ((addr) >> 8) & 0xFF; \
				(cdb)->g4_addr0 = (addr) & 0xFF

#define	FORMG4ADDTL(cdb, addtl_cdb_data) (cdb)->g4_addtl_cdb_data3 = \
					(addtl_cdb_data) >> 24; \
				(cdb)->g4_addtl_cdb_data2 = \
					((addtl_cdb_data) >> 16) & 0xFF; \
				(cdb)->g4_addtl_cdb_data1 = \
					((addtl_cdb_data) >> 8) & 0xFF; \
				(cdb)->g4_addtl_cdb_data0 = \
					(addtl_cdb_data) & 0xFF

#define	GETG4ADDR(cdb)		((cdb)->g4_addr3 << 24) + \
				((cdb)->g4_addr2 << 16) + \
				((cdb)->g4_addr1 << 8)  + \
				((cdb)->g4_addr0)

#define	GETG4ADDRTL(cdb)	(((cdb)->g4_addtl_cdb_data3 << 24) + \
				((cdb)->g4_addtl_cdb_data2 << 16) + \
				((cdb)->g4_addtl_cdb_data1 << 8) + \
				(cdb)->g4_addtl_cdb_data0)

#define	GETG4TAG(cdb)		(cdb)->g4_reladdr

#define	FORMG5COUNT(cdb, cnt)	(cdb)->scc5_count3 = ((cnt) >> 24); \
				(cdb)->scc5_count2 = ((cnt) >> 16) & 0xFF; \
				(cdb)->scc5_count1 = ((cnt) >> 8) & 0xFF; \
				(cdb)->scc5_count0 = (cnt) & 0xFF

#define	FORMG5ADDR(cdb, addr)	(cdb)->scc5_addr3  = (addr) >> 24; \
				(cdb)->scc5_addr2  = ((addr) >> 16) & 0xFF; \
				(cdb)->scc5_addr1  = ((addr) >> 8) & 0xFF; \
				(cdb)->scc5_addr0  = (addr) & 0xFF

#define	GETG5ADDR(cdb)		((cdb)->scc5_addr3 << 24) + \
				((cdb)->scc5_addr2 << 16) + \
				((cdb)->scc5_addr1 << 8)  + \
				((cdb)->scc5_addr0)

#define	GETG5COUNT(cdb)		((cdb)->scc5_count3 << 24) + \
				((cdb)->scc5_count2 << 16) + \
				((cdb)->scc5_count1 << 8) + \
				((cdb)->scc5_count0)

#define	GETG5TAG(cdb)		(cdb)->scc5_reladdr


/*
 * Shorthand macros for forming commands
 *
 * Works only with pre-SCSI-3 because they put lun as part of CDB.
 * scsi_setup_cdb() is the recommended interface.
 */

#define	MAKECOM_COMMON(pktp, devp, flag, cmd)	\
	(pktp)->pkt_address = (devp)->sd_address, \
	(pktp)->pkt_flags = (flag), \
	((union scsi_cdb *)(pktp)->pkt_cdbp)->scc_cmd = (cmd), \
	((union scsi_cdb *)(pktp)->pkt_cdbp)->scc_lun = \
	    (pktp)->pkt_address.a_lun

#define	MAKECOM_G0(pktp, devp, flag, cmd, addr, cnt)	\
	MAKECOM_COMMON((pktp), (devp), (flag), (cmd)), \
	FORMG0ADDR(((union scsi_cdb *)(pktp)->pkt_cdbp), (addr)), \
	FORMG0COUNT(((union scsi_cdb *)(pktp)->pkt_cdbp), (cnt))

#define	MAKECOM_G0_S(pktp, devp, flag, cmd, cnt, fixbit)	\
	MAKECOM_COMMON((pktp), (devp), (flag), (cmd)), \
	FORMG0COUNT_S(((union scsi_cdb *)(pktp)->pkt_cdbp), (cnt)), \
	((union scsi_cdb *)(pktp)->pkt_cdbp)->t_code = (fixbit)

#define	MAKECOM_G1(pktp, devp, flag, cmd, addr, cnt)	\
	MAKECOM_COMMON((pktp), (devp), (flag), (cmd)), \
	FORMG1ADDR(((union scsi_cdb *)(pktp)->pkt_cdbp), (addr)), \
	FORMG1COUNT(((union scsi_cdb *)(pktp)->pkt_cdbp), (cnt))

#define	MAKECOM_G5(pktp, devp, flag, cmd, addr, cnt)	\
	MAKECOM_COMMON((pktp), (devp), (flag), (cmd)), \
	FORMG5ADDR(((union scsi_cdb *)(pktp)->pkt_cdbp), (addr)), \
	FORMG5COUNT(((union scsi_cdb *)(pktp)->pkt_cdbp), (cnt))


/*
 * Direct access disk format defines and parameters.
 *
 * This is still pretty ugly and is mostly derived
 * from Emulex MD21 specific formatting.
 */

#define	fmt_parm_bits		g0_addr2	/* for format options */
#define	fmt_interleave		g0_count0	/* for encode interleave */
#define	defect_list_descrip	g1_addr3	/* list description bits */

/*
 * defines for value of fmt_parm_bits.
 */

#define	FPB_BFI			0x04	/* bytes-from-index fmt */
#define	FPB_CMPLT		0x08	/* full defect list provided */
#define	FPB_DATA		0x10	/* defect list data provided */

/*
 * Defines for value of defect_list_descrip.
 */

#define	DLD_MAN_DEF_LIST	0x10	/* manufacturer's defect list */
#define	DLD_GROWN_DEF_LIST	0x08	/* grown defect list */
#define	DLD_BLOCK_FORMAT	0x00	/* block format */
#define	DLD_BFI_FORMAT		0x04	/* bytes-from-index format */
#define	DLD_PS_FORMAT		0x05	/* physical sector format */

/*
 * Defines for value of CONTROL byte of cdb.
 */
#define	CDB_FLAG_NACA		0x04	/* naca flag */

/*
 * Disk defect list - used by format command.
 */
#define	RDEF_ALL	0	/* read all defects */
#define	RDEF_MANUF	1	/* read manufacturer's defects */
#define	RDEF_CKLEN	2	/* check length of manufacturer's list */
#define	ST506_NDEFECT	127	/* must fit in 1K controller buffer... */
#define	ESDI_NDEFECT	ST506_NDEFECT

struct scsi_bfi_defect {	/* defect in bytes from index format */
	unsigned cyl  : 24;
	unsigned head : 8;
	int	bytes_from_index;
};

struct scsi_format_params {	/* BFI format list */
	ushort_t reserved;
	ushort_t length;
	struct  scsi_bfi_defect list[ESDI_NDEFECT];
};

/*
 * Defect list returned by READ_DEFECT_LIST command.
 */
struct scsi_defect_hdr {	/* For getting defect list size */
	uchar_t	reserved;
	uchar_t	descriptor;
	ushort_t length;
};

struct scsi_defect_list {	/* BFI format list */
	uchar_t	reserved;
	uchar_t	descriptor;
	ushort_t length;
	struct	scsi_bfi_defect list[ESDI_NDEFECT];
};

/*
 *
 * Direct Access device Reassign Block parameter
 *
 * Defect list format used by reassign block command (logical block format).
 *
 * This defect list is limited to 1 defect, as that is the only way we use it.
 *
 */

struct scsi_reassign_blk {
	ushort_t reserved;
	ushort_t length;	/* defect length in bytes (defects * 4) */
	uint_t 	defect;		/* Logical block address of defect */
};

/*
 * Direct Access Device Capacity Structure -- 8 byte version
 */

struct scsi_capacity {
	uint_t	capacity;
	uint_t	lbasize;
};

/*
 * Direct Access Device Capacity Structure -- 16 byte version
 */

struct scsi_capacity_16 {
	uint64_t	sc_capacity;
	uint_t		sc_lbasize;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t 	sc_rto_en	:1;
	uchar_t 	sc_prot_en	:1;
	uchar_t 	sc_rsvd0	:6;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t 	sc_rsvd0	:6;
	uchar_t 	sc_prot_en	:1;
	uchar_t 	sc_rto_en	:1;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t 	sc_rsvd1[19];
};

#ifdef	_KERNEL

/*
 * Functional versions of the above macros, and other functions.
 * the makecom functions have been deprecated. Please use
 * scsi_setup_cdb()
 */

extern void 	makecom_g0(struct scsi_pkt *pkt, struct scsi_device *devp,
				int flag, int cmd, int addr, int cnt);
extern void 	makecom_g0_s(struct scsi_pkt *pkt, struct scsi_device *devp,
				int flag, int cmd, int cnt, int fixbit);
extern void 	makecom_g1(struct scsi_pkt *pkt, struct scsi_device *devp,
				int flag, int cmd, int addr, int cnt);
extern void 	makecom_g5(struct scsi_pkt *pkt, struct scsi_device *devp,
				int flag, int cmd, int addr, int cnt);
extern int	scsi_setup_cdb(union scsi_cdb *cdbp, uchar_t cmd, uint_t addr,
				uint_t cnt, uint_t addtl_cdb_data);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_COMMANDS_H */
