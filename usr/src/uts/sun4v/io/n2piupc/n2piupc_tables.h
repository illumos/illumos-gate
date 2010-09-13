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

#ifndef	_N2PIUPC_TABLES_H
#define	_N2PIUPC_TABLES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Table definitions for the N2 PIU performance counter driver.
 *
 * Each table consists of one or more groups of counters.
 *
 * A counter group will a name (used by busstat as the kstat "module" name),
 * have its own set of kstats, and a common event select register.  A group is
 * represented as an n2piu_grp_t.
 *
 * Each counter is represented by an n2piu_cntr_t.  Each has its own register
 * offset (or address), bits for the data it represents, plus an associated
 * register for zeroing it.
 *
 * All registers for n2piu are 64 bit, but a size field can be entered into this
 * structure if registers sizes vary for other implementations (as if this code
 * is leveraged for a future driver).
 *
 * A select register is represented by an n2piu_regsel_t.  This defines the
 * offset or address, and an array of fields which define the events for each
 * counter it services.  All counters need to have an entry in the fields array
 * even if they don't have any representation in a select register.  Please see
 * the explanation of the events array (below) for more information.  Counters
 * without representation in a select register can specify their (non-existant)
 * select register field with mask NONPROG_DUMMY_MASK and offset
 * NONPROG_DUMMY_OFF.
 *
 * This implementation supports only one select register per group.  If more
 * are needed (e.g. if this implementation is used as a template for another
 * device which has multiple select registers per group) the data structures can
 * easily be changed to support an array of them.   Add an array index in the
 * counter structure to associate that counter with a particular select
 * register, and add a field for the number of select registers in the group
 * structure.
 *
 * Each counter has an array of programmable events associated with it, even if
 * it is not programmable.  This array is a series of name/value pairs defined
 * by n2piu_event_t.  The value is the event value loaded into the select
 * register to select that event for that counter.  The last entry in the array
 * is always an entry with a bitmask of LSB-aligned bits of that counter's
 * select register's field's width;  it is usually called the CLEAR_PIC entry.
 * CLEAR_PIC entries are not shown to the user.
 *
 * Note that counters without programmable events still need to define a
 * (small) events array with at least CLEAR_PIC and a single event, so that
 * event's name can display in busstat output.  The CLEAR_PIC entry of
 * nonprogrammable counters can have a value of NONPROG_DUMMY_MASK.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/kstat.h>
#include "n2piupc_acc.h"

/*
 * Description of a counter's events.  Each counter will have an array of these,
 * to define the events it can be programmed to report.  Nonprogrammable
 * counters still need an array of these, to contain the name busstat will
 * display for it, and a CLEAR_PIC entry.
 */
typedef struct n2piu_event {
	char *name;
	uint64_t value;
} n2piu_event_t;

/*
 * Description of a counter's event selection.  There will be one entry for
 * each counter in the group.
 */
typedef struct n2piu_regsel_fld {
	n2piu_event_t *events_p;
	int num_events;		/* Size of events array. */
	uint64_t event_mask;	/* Width of the event field. */
	int event_offset;	/* Offset of the event field. */
} n2piu_regsel_fld_t;

#define	NUM_EVTS(x)	(sizeof (x) / sizeof (n2piu_event_t))

/*
 * Description of a group's select register.
 */
typedef struct n2piu_regsel {
	off_t regoff;			/* Register offset or address. */
	n2piu_regsel_fld_t *fields_p;	/* select reg subfield descriptions.  */
	int num_fields;			/* Size of the fields array. */
} n2piu_regsel_t;

#define	NUM_FLDS(x)	(sizeof (x) / sizeof (n2piu_regsel_fld_t))

/*
 * Counter description, including its access logistics and how to zero it.
 */
typedef struct n2piu_cntr {
	off_t regoff;		/* Register offset or address. */
	uint64_t fld_mask;	/* Width of the active part of the register */
	off_t zero_regoff;	/* Offset of register used to zero counter. */
	uint64_t zero_value;	/* Value to write to zero_regoff, to clr cntr */
} n2piu_cntr_t;

#define	FULL64BIT	-1ULL	/* Can use this for fld_mask. */

/*
 * Group description.
 */
typedef struct n2piu_grp {
	char *grp_name;		  /* Name, shows up as busstat "module" name. */
	n2piu_regsel_t *regsel_p; /* Select register. */
	n2piu_cntr_t *counters_p; /* Counter definitions. */
	int num_counters;	  /* Size of the counters array. */
	kstat_t **name_kstats_pp; /* Named kstats.  One for all instances. */
} n2piu_grp_t;

#define	NUM_CTRS(x) (sizeof (x) / sizeof (n2piu_cntr_t))

/* N2PIU-specific definitions. */

/* Where groups are in the leaf_grps array. */

#define	NUM_GRPS	4
#define	IMU_GRP		0
#define	MMU_GRP		1
#define	PEU_GRP		2
#define	BIT_ERR_GRP	3

/* The table itself. */
extern n2piu_grp_t *leaf_grps[];

/* Standin symbol for when there is no register. */
#define	NO_REGISTER			(off_t)-1ULL

/*
 * Default event values used in n2piu_event_t structures for non-programmable
 * registers.
 */
#define	NONPROG_DUMMY_MASK	0
#define	NONPROG_DUMMY_OFF	0

/*
 * Event bitmask definitions for all groups.
 */
#define	IMU_CTR_EVT_MASK	0xffull
#define	IMU_CTR_0_EVT_OFF	0
#define	IMU_CTR_1_EVT_OFF	8

#define	MMU_CTR_EVT_MASK	0xffull
#define	MMU_CTR_0_EVT_OFF	0
#define	MMU_CTR_1_EVT_OFF	8

#define	PEU_CTR_01_EVT_MASK	0xffull
#define	PEU_CTR_2_EVT_MASK	0x3ull
#define	PEU_CTR_0_EVT_OFF	0
#define	PEU_CTR_1_EVT_OFF	8
#define	PEU_CTR_2_EVT_OFF	16

#define	BTERR_CTR_0_EVT_MASK	0x1ull
#define	BTERR_CTR_0_EVT_OFF	0

/*
 * Fake the biterr event register to be one with two fields, to store the
 * overall enable/disable event (looks like pic0 reset) and the bterr3 events.
 */

#define	BTERR_CTR_3_EVT_MASK	0xfull
#define	BTERR_CTR_3_EVT_OFF	0

/*
 * Note: this "event" is really an enable, and it serves all 4 PICs.
 *
 * PICs 0,1,2 are from the first counter, PIC3 is from the second counter.
 */
#define	BTERR_CTR_ENABLE_MASK	0x1ull
#define	BTERR_CTR_ENABLE_OFF	63

#define	BTERR_CTR_ENABLE	(BTERR_CTR_ENABLE_MASK << BTERR_CTR_ENABLE_OFF)

/*
 * This register also has a bit to zero the counters.
 */
#define	BTERR_CTR_CLR_MASK	0x1ull
#define	BTERR_CTR_CLR_OFF	62

#define	BTERR_CTR_CLR		(BTERR_CTR_CLR_MASK << BTERR_CTR_CLR_OFF)

#define	BTERR_CTR_ENABLE_AND_CLR	(BTERR_CTR_ENABLE | BTERR_CTR_CLR)

/*
 * Definitions of the different types of events.
 *
 * The first part says which registers these events are for.
 * For example, IMU01 means the IMU performance counters 0 and 1
 */

/* String sought by busstat to locate the event field width "event" entry. */
#define	COMMON_S_CLEAR_PIC			"clear_pic"


#define	IMU01_S_EVT_NONE			"event_none"
#define	IMU01_S_EVT_CLK				"clock_cyc"
#define	IMU01_S_EVT_TOTAL_MONDO			"total_mondo"
#define	IMU01_S_EVT_TOTAL_MSI			"total_msi"
#define	IMU01_S_EVT_NAK_MONDO			"mondo_nak"
#define	IMU01_S_EVT_EQ_WR			"eq_write"
#define	IMU01_S_EVT_EQ_MONDO			"eq_mondo"

#define	IMU01_EVT_NONE				0
#define	IMU01_EVT_CLK				1
#define	IMU01_EVT_TOTAL_MONDO			2
#define	IMU01_EVT_TOTAL_MSI			3
#define	IMU01_EVT_NAK_MONDO			4
#define	IMU01_EVT_EQ_WR				5
#define	IMU01_EVT_EQ_MONDO			6


#define	MMU01_S_EVT_NONE			"event_none"
#define	MMU01_S_EVT_CLK				"clock_cyc"
#define	MMU01_S_EVT_TRANS			"total_transl"
#define	MMU01_S_EVT_STALL			"total_stall_cyc"
#define	MMU01_S_EVT_TRANS_MISS			"total_transl_miss"
#define	MMU01_S_EVT_TBLWLK_STALL		"tblwlk_stall_cyc"
#define	MMU01_S_EVT_BYPASS_TRANSL		"bypass_transl"
#define	MMU01_S_EVT_TRANSL_TRANSL		"transl_transl"
#define	MMU01_S_EVT_FLOW_CNTL_STALL		"flow_stall_cyc"
#define	MMU01_S_EVT_FLUSH_CACHE_ENT		"cache_entr_flush"

#define	MMU01_EVT_NONE				0
#define	MMU01_EVT_CLK				1
#define	MMU01_EVT_TRANS				2
#define	MMU01_EVT_STALL				3
#define	MMU01_EVT_TRANS_MISS			4
#define	MMU01_EVT_TBLWLK_STALL			5
#define	MMU01_EVT_BYPASS_TRANSL			6
#define	MMU01_EVT_TRANSL_TRANSL			7
#define	MMU01_EVT_FLOW_CNTL_STALL		8
#define	MMU01_EVT_FLUSH_CACHE_ENT		9


#define	PEU2_S_EVT_NONE				"event_none"
#define	PEU2_S_EVT_NONPST_CMPL_TIME		"npost_compl_time"
#define	PEU2_S_EVT_XMIT_DATA			"xmit_data"
#define	PEU2_S_EVT_RCVD_DATA			"rcvd_data"

#define	PEU2_EVT_NONE				0
#define	PEU2_EVT_NONPST_CMPL_TIME		1
#define	PEU2_EVT_XMIT_DATA			2
#define	PEU2_EVT_RCVD_DATA			3


#define	PEU01_S_EVT_NONE			"event_none"
#define	PEU01_S_EVT_CLK				"clock_cyc"
#define	PEU01_S_EVT_COMPL			"compl_recvd"
#define	PEU01_S_EVT_XMT_POST_CR_UNAV		"post_cr_unav_cyc"
#define	PEU01_S_EVT_XMT_NPOST_CR_UNAV		"npost_cr_unav_cyc"
#define	PEU01_S_EVT_XMT_CMPL_CR_UNAV		"compl_cr_unav_cyc"
#define	PEU01_S_EVT_XMT_ANY_CR_UNAV		"trans_cr_any_unav"
#define	PEU01_S_EVT_RETRY_CR_UNAV		"retry_cr_unav"
#define	PEU01_S_EVT_MEMRD_PKT_RCVD		"recvd_mem_rd_pkt"
#define	PEU01_S_EVT_MEMWR_PKT_RCVD		"recvd_mem_wr_pkt"
#define	PEU01_S_EVT_RCV_CR_THRESH		"recv_cr_thresh"
#define	PEU01_S_EVT_RCV_PST_HDR_CR_EXH		"recv_hdr_cr_exh_cyc"
#define	PEU01_S_EVT_RCV_PST_DA_CR_MPS		"recv_post_da_cr_mps"
#define	PEU01_S_EVT_RCV_NPST_HDR_CR_EXH		"recv_npost_hdr_cr_exh"
#define	PEU01_S_EVT_RCVR_L0S			"recvr_l0s_cyc"
#define	PEU01_S_EVT_RCVR_L0S_TRANS		"recvr_l0s_trans"
#define	PEU01_S_EVT_XMTR_L0S			"trans_l0s_cyc"
#define	PEU01_S_EVT_XMTR_L0S_TRANS		"trans_l0s_trans"
#define	PEU01_S_EVT_RCVR_ERR			"recvr_err"
#define	PEU01_S_EVT_BAD_TLP			"bad_tlp"
#define	PEU01_S_EVT_BAD_DLLP			"bad_dllp"
#define	PEU01_S_EVT_REPLAY_ROLLOVER		"replay_rollover"
#define	PEU01_S_EVT_REPLAY_TMO			"replay_to"

#define	PEU01_EVT_NONE				0x0
#define	PEU01_EVT_CLK				0x1
#define	PEU01_EVT_COMPL				0x2
#define	PEU01_EVT_XMT_POST_CR_UNAV		0x10
#define	PEU01_EVT_XMT_NPOST_CR_UNAV		0x11
#define	PEU01_EVT_XMT_CMPL_CR_UNAV		0x12
#define	PEU01_EVT_XMT_ANY_CR_UNAV		0x13
#define	PEU01_EVT_RETRY_CR_UNAV			0x14
#define	PEU01_EVT_MEMRD_PKT_RCVD		0x20
#define	PEU01_EVT_MEMWR_PKT_RCVD		0x21
#define	PEU01_EVT_RCV_CR_THRESH			0x22
#define	PEU01_EVT_RCV_PST_HDR_CR_EXH		0x23
#define	PEU01_EVT_RCV_PST_DA_CR_MPS		0x24
#define	PEU01_EVT_RCV_NPST_HDR_CR_EXH		0x25
#define	PEU01_EVT_RCVR_L0S			0x30
#define	PEU01_EVT_RCVR_L0S_TRANS		0x31
#define	PEU01_EVT_XMTR_L0S			0x32
#define	PEU01_EVT_XMTR_L0S_TRANS		0x33
#define	PEU01_EVT_RCVR_ERR			0x40
#define	PEU01_EVT_BAD_TLP			0x42
#define	PEU01_EVT_BAD_DLLP			0x43
#define	PEU01_EVT_REPLAY_ROLLOVER		0x44
#define	PEU01_EVT_REPLAY_TMO			0x47

/*
 * BTERR counter 3 is presented by the device as one register with 8 different
 * counters.  Since busstat displays in decimal and not in hex, display of the
 * raw data is impractical except to make a non-zero test.  Fake that this
 * register has multiple modes, so that each lane can be shown separately.
 * Then one can use Busstat capabilities to display alternating events of a
 * register.
 */

#define	BTERR3_S_EVT_NONE			"event_none"
#define	BTERR3_S_EVT_ENC_ALL			"encd_err_ln_all"
#define	BTERR3_S_EVT_ENC_LANE_0			"encd_err_ln_0"
#define	BTERR3_S_EVT_ENC_LANE_1			"encd_err_ln_1"
#define	BTERR3_S_EVT_ENC_LANE_2			"encd_err_ln_2"
#define	BTERR3_S_EVT_ENC_LANE_3			"encd_err_ln_3"
#define	BTERR3_S_EVT_ENC_LANE_4			"encd_err_ln_4"
#define	BTERR3_S_EVT_ENC_LANE_5			"encd_err_ln_5"
#define	BTERR3_S_EVT_ENC_LANE_6			"encd_err_ln_6"
#define	BTERR3_S_EVT_ENC_LANE_7			"encd_err_ln_7"

#define	BTERR3_EVT_ENC_NONE			0
#define	BTERR3_EVT_ENC_ALL			1
#define	BTERR3_EVT_ENC_LANE_0			2
#define	BTERR3_EVT_ENC_LANE_1			3
#define	BTERR3_EVT_ENC_LANE_2			4
#define	BTERR3_EVT_ENC_LANE_3			5
#define	BTERR3_EVT_ENC_LANE_4			6
#define	BTERR3_EVT_ENC_LANE_5			7
#define	BTERR3_EVT_ENC_LANE_6			8
#define	BTERR3_EVT_ENC_LANE_7			9

/*
 * For non-programmable registers, include an n2piu_event_t which has two
 * fields, a default field (which gives the field a name even though it
 * can't be programmed, and clear_pic which busstat needs.
 */
#define	BTERR2_S_EVT_PRE			"phys_rcvr_errs"

#define	BTERR2_EVT_PRE				0

#define	BTERR1_S_EVT_BTLP			"bad_tlps"

#define	BTERR1_EVT_BTLP				0

/*
 * Note: All 4 biterr counter fields (split among two counter registers) are
 * tied together with a single enable.  Treat the first field as programmable
 * to provide a way to reset the counter set.
 */
#define	BTERR0_S_EVT_RESET	"reset_bterr"	/* All biterr counter zero */
#define	BTERR0_S_EVT_BDLLP	"bad_dllps"

#define	BTERR0_EVT_RESET	0
#define	BTERR0_EVT_BDLLP	1

/*
 * First bit error counter register has three counters.  Here are the
 * placements of these counters within the (virtual) registers.
 */
#define	BE1_BAD_DLLP_MASK	0xff000000ULL
#define	BE1_BAD_TLP_MASK	0xff0000ULL
#define	BE1_BAD_PRE_MASK	0x3ffULL
#define	BE2_8_10_MASK		FULL64BIT

#ifdef	__cplusplus
}
#endif

#endif	/* _N2PIUPC_TABLES_H */
