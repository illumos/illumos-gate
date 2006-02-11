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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MCAMD_API_H
#define	_MCAMD_API_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Primary header file for mcamd_* routines in $SRC/common/mc.  The
 * routines not implemented there are required to be implemented in the
 * kernel or userland consumer of this interface (such as the mc-amd driver).
 * The common code must use the wrapper functions provided by the consumer
 * to navigate the MC tree, get properties etc.
 */

#if defined(_KERNEL)
#include <sys/systm.h>
#include <sys/sunddi.h>
#else
#include <string.h>
#include <assert.h>
#endif

#include <sys/types.h>
#include <sys/mc.h>
#include <sys/mca_amd.h>
#include <sys/mc_amd.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Consumers of this common code must implement the following types.
 */
typedef struct mcamd_node mcamd_node_t;
struct mcamd_hdl;

/*
 * If changing the properties below be sure to propogate to mcamd_misc.c
 * in common code, mcamd_subr.c in the mc-amd driver, and mcamd_prop.c
 * from libmcamd.
 */

#define	MCAMD_PROP_NUM			0
#define	MCAMD_PROP_BASE_ADDR		1
#define	MCAMD_PROP_LIM_ADDR		2
#define	MCAMD_PROP_MASK			3
#define	MCAMD_PROP_DRAM_ILEN		4
#define	MCAMD_PROP_DRAM_ILSEL		5
#define	MCAMD_PROP_DRAM_HOLE		6
#define	MCAMD_PROP_DRAM_CONFIG		7
#define	MCAMD_PROP_ACCESS_WIDTH		8
#define	MCAMD_PROP_LODIMM		9
#define	MCAMD_PROP_UPDIMM		10
#define	MCAMD_PROP_CSBANKMAP		11
#define	MCAMD_PROP_SIZE			12
#define	MCAMD_PROP_CSBANK_INTLV		13
#define	MCAMD_PROP_CS0			14 /* CS0 to CS3 must be contiguous */
#define	MCAMD_PROP_CS1			15
#define	MCAMD_PROP_CS2			16
#define	MCAMD_PROP_CS3			17
#define	MCAMD_PROP_REV			18
#define	MCAMD_PROP_DISABLED_CS		19

#define	MCAMD_NUMPROPS			20

#define	MCAMD_PROPSTR_NUM		"num"
#define	MCAMD_PROPSTR_BASE_ADDR		"base-addr"
#define	MCAMD_PROPSTR_LIM_ADDR		"lim-addr"
#define	MCAMD_PROPSTR_MASK		"mask"
#define	MCAMD_PROPSTR_DRAM_ILEN		"dram-ilen"
#define	MCAMD_PROPSTR_DRAM_ILSEL	"dram-ilsel"
#define	MCAMD_PROPSTR_DRAM_HOLE		"dram-hole"
#define	MCAMD_PROPSTR_DRAM_CONFIG	"dram-config"
#define	MCAMD_PROPSTR_ACCESS_WIDTH	"access-width"
#define	MCAMD_PROPSTR_LODIMM		"lodimm-num"
#define	MCAMD_PROPSTR_UPDIMM		"updimm-num"
#define	MCAMD_PROPSTR_CSBANKMAP		"bank-mapping"
#define	MCAMD_PROPSTR_SIZE		"size"
#define	MCAMD_PROPSTR_CSBANK_INTLV	"csbank-intlv"
#define	MCAMD_PROPSTR_CS0		"csnum0"
#define	MCAMD_PROPSTR_CS1		"csnum1"
#define	MCAMD_PROPSTR_CS2		"csnum2"
#define	MCAMD_PROPSTR_CS3		"csnum3"
#define	MCAMD_PROPSTR_REV		"revision"
#define	MCAMD_PROPSTR_DISABLED_CS	"disabled-cs"

/*
 * Flags for mcamd_dprintf
 */
#define	MCAMD_DBG_ERR		0x1
#define	MCAMD_DBG_FLOW		0x2

typedef union mcamd_dimm_offset_un mcamd_dimm_offset_un_t;

/*
 * Offset definition.  Encode everything in a single uint64_t, allowing some
 * room for growth in numbers of rows/columns/banks in future MC revisions.
 * Some consumers will handle this as an opaque uint64 to be passed around,
 * while others will want to look inside via the union defined below.
 */

#define	MCAMD_OFFSET_VERSION_0			0x0
#define	MCAMD_OFFSET_VERSION			MCAMD_OFFSET_VERSION_0

union mcamd_dimm_offset_un {
	uint64_t _dou_offset;
	struct {
		struct {
			uint32_t dou_col:20;	/* column address */
			uint32_t dou_bank:4;	/* internal sdram bank number */
			uint32_t unused:8;
		} lo;
		struct {
			uint32_t dou_row:20;	/* row address */
			uint32_t dou_rank:3;	/* cs rank on dimm */
			uint32_t unused:4;
			uint32_t dou_version:4;	/* offset encoding version */
			uint32_t dou_valid:1;	/* set if valid */
		} hi;
	} _dou_hilo;
};

#define	do_offset  _dou_offset

#define	do_valid _dou_hilo.hi.dou_valid
#define	do_version _dou_hilo.hi.dou_version
#define	do_rank _dou_hilo.hi.dou_rank
#define	do_row _dou_hilo.hi.dou_row
#define	do_bank _dou_hilo.lo.dou_bank
#define	do_col _dou_hilo.lo.dou_col

/*
 * The following work on an offset treated as a uint64_t.
 */
#define	MCAMD_RC_OFFSET_VALID(offset) (((uint64_t)(offset) & (1ULL << 63)) != 0)
#define	MCAMD_RC_OFFSET_VERSION(offset) (((uint64_t)offset >> 59) & 0xf)

/*
 * Value to be used to indicate an invalid offset.
 */
#define	MCAMD_RC_INVALID_OFFSET 0x0

/*
 * Routines provided by the common mcamd code.
 */
extern const char *mcamd_get_propname(uint_t);

extern int mcamd_patounum(struct mcamd_hdl *, mcamd_node_t *, uint64_t,
    uint32_t, int, struct mc_unum *);

extern int mcamd_unumtopa(struct mcamd_hdl *, mcamd_node_t *, struct mc_unum *,
    uint64_t *);

extern int mcamd_cs_size(struct mcamd_hdl *, mcamd_node_t *, int, size_t *);

extern int mcamd_synd_validate(struct mcamd_hdl *, uint32_t, int);
extern int mcamd_eccsynd_decode(struct mcamd_hdl *, uint32_t, uint_t *);
extern int mcamd_cksynd_decode(struct mcamd_hdl *, uint32_t, uint_t *,
    uint_t *);
extern int mcamd_cksym_decode(struct mcamd_hdl *, uint_t, int *, int *,
    int *, int *);

extern void *mcamd_set_errno_ptr(struct mcamd_hdl *, int);
extern const char *mcamd_strerror(int);
extern const char *mcamd_errmsg(struct mcamd_hdl *);

/*
 * Routines to be provided by wrapper code.
 */
extern mcamd_node_t *mcamd_mc_next(struct mcamd_hdl *, mcamd_node_t *,
    mcamd_node_t *);
extern mcamd_node_t *mcamd_cs_next(struct mcamd_hdl *, mcamd_node_t *,
    mcamd_node_t *);
extern mcamd_node_t *mcamd_dimm_next(struct mcamd_hdl *, mcamd_node_t *,
    mcamd_node_t *);

extern mcamd_node_t *mcamd_cs_mc(struct mcamd_hdl *, mcamd_node_t *);
extern mcamd_node_t *mcamd_dimm_mc(struct mcamd_hdl *, mcamd_node_t *);

extern int mcamd_get_numprop(struct mcamd_hdl *, mcamd_node_t *, uint_t,
    uint64_t *);

extern int mcamd_errno(struct mcamd_hdl *);
extern int mcamd_set_errno(struct mcamd_hdl *, int);
extern void mcamd_dprintf(struct mcamd_hdl *, int, const char *, ...);

#ifdef __cplusplus
}
#endif

#endif /* _MCAMD_API_H */
