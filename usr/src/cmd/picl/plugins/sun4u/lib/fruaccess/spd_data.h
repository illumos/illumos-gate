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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SPD_DATA_H
#define	_SPD_DATA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <sys/types.h>

size_t get_sp_sec_hdr(void *sec_hdr, size_t sec_hdr_len);
size_t get_sp_seg_hdr(void *seg_hdr, size_t seg_hdr_len);
int get_spd_data(int fd, char *spd_data, size_t ctr_len, off_t ctr_offset);
int cvrt_dim_data(const char *spd_data, size_t spd_data_len,
    uchar_t **sp_seg_ptr, size_t *sp_seg_len);

enum spd_memtype {
	SPDMEM_RESERVED = 0,
	SPDMEM_FPM_DRAM,
	SPDMEM_EDO,
	SPDMEM_PIPE,
	SPDMEM_SDRAM,
	SPDMEM_ROM,
	SPDMEM_SGRAM_DDR,
	SPDMEM_SDRAM_DDR,
	SPDMEM_DDR2_SDRAM
};

typedef struct {
	uchar_t		spd_len;	/* bytes written by manufacturer */
	uchar_t		spd_max_len;	/* total available prom space */
	uchar_t		memory_type;	/* e.g. SDRAM DDR = 0x07 */
	uchar_t		n_rows;		/* row address bits */
	uchar_t		n_cols;		/* column address bits */
	uchar_t		n_mod_rows;	/* number of module rows */
	uchar_t		ls_data_width;	/* e.g. 72 bits */
	uchar_t		ms_data_width;
	uchar_t		vddq_if;	/* e.g. SSTL 2.5V = 0x04 */
	uchar_t		cycle_time25;	/* cycle time at CAS latency 2.5 */
	uchar_t		access_time25;
	uchar_t		config;		/* e.g. ECC = 0x02 */
	uchar_t		refresh;	/* e.g. 7.8uS & self refresh = 0x82 */
	uchar_t		primary_width;
	uchar_t		err_chk_width;
	uchar_t		tCCD;
	uchar_t		burst_lengths;	/* e.g. 2,4,8 = 0x0e */
	uchar_t		n_banks;
	uchar_t		cas_lat;
	uchar_t		cs_lat;
	uchar_t		we_lat;
	uchar_t		mod_attrs;
	uchar_t		dev_attrs;
	uchar_t		cycle_time20;	/* cycle time at CAS latency 2.0 */
	uchar_t		access_time20;
	uchar_t		cycle_time15;
	uchar_t		access_time15;
	uchar_t		tRP;
	uchar_t		tRRD;
	uchar_t		tRCD;
	uchar_t		tRAS;
	uchar_t		mod_row_density;
	uchar_t		addr_ip_setup;
	uchar_t		addr_ip_hold;
	uchar_t		data_ip_setup;
	uchar_t		data_ip_hold;
	uchar_t		superset[62 - 36];
	uchar_t		spd_rev;
	uchar_t		chksum_0_62;
	uchar_t		jedec[8];
	uchar_t		manu_loc;
	uchar_t		manu_part_no[91 - 73];
	uchar_t		manu_rev_pcb;
	uchar_t		manu_rev_comp;
	uchar_t		manu_year;
	uchar_t		manu_week;
	uchar_t		asmb_serial_no[4];
	uchar_t		manu_specific[128 - 99];
} spd_data_t;

/*
 * sample section and SP segment headers
 */
#define	SP_SEC_HDR	\
	{ 0x08, 0x00, 0x01, 0x00,  0x33, 0x01 }

#define	SP_SEG_HDR	\
	{ 'S', 'P', 0x00, 0x00,  0x41, 0xb6, 0x00, 0x00,  0x00, 0x8d }

/*
 * sample SP segment
 */
#define	SP_DATA	{ \
	0xc1, 0x08, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00,  \
	0x00, 0x00, 0xf0, 0x00,   0xfb, 0x00, 0x00, 0x00,  \
	0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, \
	0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, \
	0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, \
	0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, \
	0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, \
	0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, \
	0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, \
	0x00, 0x00, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00,  \
	0x0c, 0x00, 0x00, 0x00,   0x00 }

/*
 * offsets of records in SP_DATA
 */
#define	DIMM_CAP_OFF	2
#define	SPD_R_OFF	13

/*
 * offsets of certain fields within SPD-R record
 */
#define	DATA_WIDTH	6
#define	MANUF_ID	64
#define	MANUF_LOC	66
#define	MANUF_YEAR	87
#define	MANUF_WEEK	89
/* length of complete SPD-R record */
#define	SPD_R_LEN	123

#ifdef	__cplusplus
}
#endif

#endif	/* _SPD_DATA_H */
