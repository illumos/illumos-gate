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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MEM_SPD_H
#define	_MEM_SPD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Layout of SPD-format data, as per PICL.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct spd_data {
	uint8_t		spd_len;	/* bytes written by manufacturer */
	uint8_t		spd_max_len;	/* total available prom space */
	uint8_t		memory_type;	/* e.g. SDRAM DDR = 0x07 */
	uint8_t		n_rows;		/* row address bits */
	uint8_t		n_cols;		/* column address bits */
	uint8_t		n_mod_rows;	/* number of module rows */
	uint8_t		ls_data_width;	/* e.g. 72 bits */
	uint8_t		ms_data_width;
	uint8_t		vddq_if;	/* e.g. SSTL 2.5V = 0x04 */
	uint8_t		cycle_time25;	/* cycle time at CAS latency 2.5 */
	uint8_t		access_time25;
	uint8_t		config;		/* e.g. ECC = 0x02 */
	uint8_t		refresh;	/* e.g. 7.8uS & self refresh = 0x82 */
	uint8_t		primary_width;
	uint8_t		err_chk_width;
	uint8_t		tCCD;
	uint8_t		burst_lengths;	/* e.g. 2,4,8 = 0x0e */
	uint8_t		n_banks;
	uint8_t		cas_lat;
	uint8_t		cs_lat;
	uint8_t		we_lat;
	uint8_t		mod_attrs;
	uint8_t		dev_attrs;
	uint8_t		cycle_time20;	/* cycle time at CAS latency 2.0 */
	uint8_t		access_time20;
	uint8_t		cycle_time15;
	uint8_t		access_time15;
	uint8_t		tRP;
	uint8_t		tRRD;
	uint8_t		tRCD;
	uint8_t		tRAS;
	uint8_t		mod_row_density;
	uint8_t		addr_ip_setup;
	uint8_t		addr_ip_hold;
	uint8_t		data_ip_setup;
	uint8_t		data_ip_hold;
	uint8_t		superset[62 - 36];
	uint8_t		spd_rev;
	uint8_t		chksum_0_62;
	uint8_t		jedec[8];
	uint8_t		manu_loc;
	uint8_t		manu_part_no[91 - 73];
	uint8_t		manu_rev_pcb;
	uint8_t		manu_rev_comp;
	uint8_t		manu_year;
	uint8_t		manu_week;
	uint8_t		asmb_serial_no[4];
	uint8_t		manu_specific[128 - 99];
} spd_data_t;

#ifdef __cplusplus
}
#endif

#endif /* _MEM_SPD_H */
