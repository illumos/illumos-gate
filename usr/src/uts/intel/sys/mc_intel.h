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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MC_INTEL_H
#define	_MC_INTEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	FM_EREPORT_CPU_INTEL	"intel"

#define	MCINTEL_NVLIST_VERSTR	"mcintel-nvlist-version"
#define	MCINTEL_NVLIST_VERS0	0

#define	MCINTEL_NVLIST_VERS	MCINTEL_NVLIST_VERS0

#define	MCINTEL_NVLIST_MC	"memory-channels"
#define	MCINTEL_NVLIST_DIMMS	"memory-dimms"
#define	MCINTEL_NVLIST_DIMMSZ	"memory-dimm-size"
#define	MCINTEL_NVLIST_RANKS	"dimm-ranks"
#define	MCINTEL_NVLIST_ROWS	"dimm-rows"
#define	MCINTEL_NVLIST_COL	"dimm-column"
#define	MCINTEL_NVLIST_BANK	"dimm-banks"
#define	MCINTEL_NVLIST_WIDTH	"dimm-width"
#define	MCINTEL_NVLIST_MID	"dimm-manufacture-id"
#define	MCINTEL_NVLIST_MLOC	"dimm-manufacture-location"
#define	MCINTEL_NVLIST_MWEEK	"dimm-manufacture-week"
#define	MCINTEL_NVLIST_MYEAR	"dimm-manufacture-year"
#define	MCINTEL_NVLIST_SERIALNO	"dimm-serial-number"
#define	MCINTEL_NVLIST_PARTNO	"dimm-part-number"
#define	MCINTEL_NVLIST_REV	"dimm-part-rev"

#define	FM_EREPORT_PAYLOAD_NAME_FERR_GLOBAL		"ferr_global"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_GLOBAL		"nerr_global"
#define	FM_EREPORT_PAYLOAD_NAME_FSB			"fsb"
#define	FM_EREPORT_PAYLOAD_NAME_FERR_FAT_FSB		"ferr_fat_fsb"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_FAT_FSB		"nerr_fat_fsb"
#define	FM_EREPORT_PAYLOAD_NAME_FERR_NF_FSB		"ferr_nf_fsb"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_NF_FSB		"nerr_nf_fsb"
#define	FM_EREPORT_PAYLOAD_NAME_NRECFSB			"nrecfsb"
#define	FM_EREPORT_PAYLOAD_NAME_NRECFSB_ADDR		"nrecfsb_addr"
#define	FM_EREPORT_PAYLOAD_NAME_RECFSB			"recfsb"
#define	FM_EREPORT_PAYLOAD_NAME_PEX			"pex"
#define	FM_EREPORT_PAYLOAD_NAME_PEX_FAT_FERR		"pex_fat_ferr"
#define	FM_EREPORT_PAYLOAD_NAME_PEX_FAT_NERR		"pex_fat_nerr"
#define	FM_EREPORT_PAYLOAD_NAME_PEX_NF_CORR_FERR	"pex_nf_corr_ferr"
#define	FM_EREPORT_PAYLOAD_NAME_PEX_NF_CORR_NERR	"pex_nf_corr_nerr"
#define	FM_EREPORT_PAYLOAD_NAME_UNCERRSEV		"uncerrsev"
#define	FM_EREPORT_PAYLOAD_NAME_RPERRSTS		"rperrsts"
#define	FM_EREPORT_PAYLOAD_NAME_RPERRSID		"rperrsid"
#define	FM_EREPORT_PAYLOAD_NAME_UNCERRSTS		"uncerrsts"
#define	FM_EREPORT_PAYLOAD_NAME_AERRCAPCTRL		"aerrcapctrl"
#define	FM_EREPORT_PAYLOAD_NAME_CORERRSTS		"corerrsts"
#define	FM_EREPORT_PAYLOAD_NAME_PEXDEVSTS		"pexdevsts"
#define	FM_EREPORT_PAYLOAD_NAME_FERR_FAT_INT		"ferr_fat_int"
#define	FM_EREPORT_PAYLOAD_NAME_FERR_NF_INT		"ferr_nf_int"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_FAT_INT		"nerr_fat_int"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_NF_INT		"nerr_nf_int"
#define	FM_EREPORT_PAYLOAD_NAME_NRECINT			"nrecint"
#define	FM_EREPORT_PAYLOAD_NAME_RECINT			"recint"
#define	FM_EREPORT_PAYLOAD_NAME_NRECSF			"nrecsf"
#define	FM_EREPORT_PAYLOAD_NAME_RECSF			"recsf"
#define	FM_EREPORT_PAYLOAD_NAME_RANK			"rank"
#define	FM_EREPORT_PAYLOAD_NAME_BANK			"bank"
#define	FM_EREPORT_PAYLOAD_NAME_CAS			"cas"
#define	FM_EREPORT_PAYLOAD_NAME_RAS			"ras"
#define	FM_EREPORT_PAYLOAD_NAME_FERR_FAT_FBD		"ferr_fat_fbd"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_FAT_FBD		"nerr_fat_fbd"
#define	FM_EREPORT_PAYLOAD_NAME_NRECMEMA		"nrecmema"
#define	FM_EREPORT_PAYLOAD_NAME_NRECMEMB		"nrecmemb"
#define	FM_EREPORT_PAYLOAD_NAME_NRECFGLOG		"nrecfglog"
#define	FM_EREPORT_PAYLOAD_NAME_NRECFBDA		"nrecfbda"
#define	FM_EREPORT_PAYLOAD_NAME_NRECFBDB		"nrecfbdb"
#define	FM_EREPORT_PAYLOAD_NAME_NRECFBDC		"nrecfbdc"
#define	FM_EREPORT_PAYLOAD_NAME_NRECFBDD		"nrecfbdd"
#define	FM_EREPORT_PAYLOAD_NAME_NRECFBDE		"nrecfbde"
#define	FM_EREPORT_PAYLOAD_NAME_NRECFBDF		"nrecfbdf"
#define	FM_EREPORT_PAYLOAD_NAME_SPCPC			"spcpc"
#define	FM_EREPORT_PAYLOAD_NAME_SPCPS			"spcps"
#define	FM_EREPORT_PAYLOAD_NAME_UERRCNT			"uerrcnt"
#define	FM_EREPORT_PAYLOAD_NAME_UERRCNT_LAST		"uerrcnt_last"
#define	FM_EREPORT_PAYLOAD_NAME_BADRAMA			"badrama"
#define	FM_EREPORT_PAYLOAD_NAME_BADRAMB			"badramb"
#define	FM_EREPORT_PAYLOAD_NAME_BADCNT			"badcnt"
#define	FM_EREPORT_PAYLOAD_NAME_MC			"mc"
#define	FM_EREPORT_PAYLOAD_NAME_MCA			"mca"
#define	FM_EREPORT_PAYLOAD_NAME_TOLM			"tolm"
#define	FM_EREPORT_PAYLOAD_NAME_MIR			"mir"
#define	FM_EREPORT_PAYLOAD_NAME_MTR			"mtr"
#define	FM_EREPORT_PAYLOAD_NAME_DMIR			"dmir"
#define	FM_EREPORT_PAYLOAD_NAME_FERR_NF_FBD		"ferr_nf_fbd"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_NF_FBD		"nerr_nf_fbd"
#define	FM_EREPORT_PAYLOAD_NAME_RECMEMA			"recmema"
#define	FM_EREPORT_PAYLOAD_NAME_RECMEMB			"recmemb"
#define	FM_EREPORT_PAYLOAD_NAME_RECFGLOG		"recfglog"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDA			"recfbda"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDB			"recfbdb"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDC			"recfbdc"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDD			"recfbdd"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDE			"recfbde"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDF			"recfbdf"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNT			"cerrcnt"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNT_LAST		"cerrcnt_last"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNTA		"cerrcnta"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNTB		"cerrcntb"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNTC		"cerrcntc"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNTD		"cerrcntd"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNTA_LAST		"cerrcnta_last"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNTB_LAST		"cerrcntb_last"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNTC_LAST		"cerrcntc_last"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNTD_LAST		"cerrcntd_last"
#define	FM_EREPORT_PAYLOAD_NAME_PCISTS			"pcists"
#define	FM_EREPORT_PAYLOAD_NAME_PEXDEVSTS		"pexdevsts"
#define	FM_EREPORT_PAYLOAD_NAME_ERROR_NO		"intel-error-list"

#define	FM_EREPORT_PAYLOAD_NAME_CTSTS			"ctsts"
#define	FM_EREPORT_PAYLOAD_NAME_THRTSTS			"thrtsts"
#define	FM_EREPORT_PAYLOAD_NAME_FERR_FAT_THR		"ferr_fat_thr"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_FAT_THR		"nerr_fat_thr"
#define	FM_EREPORT_PAYLOAD_NAME_FERR_NF_THR		"ferr_nf_thr"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_NF_THR		"nerr_nf_thr"

#define	FM_EREPORT_PAYLOAD_NAME_ADDR			"addr"
#define	FM_EREPORT_PAYLOAD_NAME_BANK_NUM		"bank-number"
#define	FM_EREPORT_PAYLOAD_NAME_BANK_MISC		"bank-misc"
#define	FM_EREPORT_PAYLOAD_NAME_BANK_STAT		"bank-status"
#define	FM_EREPORT_PAYLOAD_NAME_BANK_OFFSET		"bank-offset"
#define	FM_EREPORT_PAYLOAD_NAME_MC_TYPE			"mc-type"
#define	FM_EREPORT_PAYLOAD_CPUID			"cpuid"

#define	FM_EREPORT_PAYLOAD_BQR				"Bus-queue-request"
#define	FM_EREPORT_PAYLOAD_BQET				"Bus-queue-error-type"
#define	FM_EREPORT_PAYLOAD_FRC				"FRC-error"
#define	FM_EREPORT_PAYLOAD_BERR				"BERR"
#define	FM_EREPORT_PAYLOAD_INT_BINT			"Internal-BINT"
#define	FM_EREPORT_PAYLOAD_EXT_BINT			"External-BINT"
#define	FM_EREPORT_PAYLOAD_BUS_BINT			"Bus-BINT"
#define	FM_EREPORT_PAYLOAD_TO_BINT			"Timeout-BINT"
#define	FM_EREPORT_PAYLOAD_HARD				"Hard-error"
#define	FM_EREPORT_PAYLOAD_IERR				"IERR"
#define	FM_EREPORT_PAYLOAD_AERR				"AERR"
#define	FM_EREPORT_PAYLOAD_UERR				"UERR"
#define	FM_EREPORT_PAYLOAD_CECC				"CECC"
#define	FM_EREPORT_PAYLOAD_UECC				"UECC"
#define	FM_EREPORT_PAYLOAD_ECC_SYND			"ECC-syndrome"

#define	FM_EREPORT_PAYLOAD_FSB_PARITY			"fsb-address-parity"
#define	FM_EREPORT_PAYLOAD_RESP_HF			"response-hard-fail"
#define	FM_EREPORT_PAYLOAD_RESP_PARITY			"response-parity"
#define	FM_EREPORT_PAYLOAD_DATA_PARITY			"bus-data-parity"
#define	FM_EREPORT_PAYLOAD_INV_PIC			"invalid-pic-request"
#define	FM_EREPORT_PAYLOAD_PAD_SM			"pad-state-machine"
#define	FM_EREPORT_PAYLOAD_PAD_SG			"pad-strobe-glitch"

#define	FM_EREPORT_PAYLOAD_TAG				"tag-error"
#define	FM_EREPORT_PAYLOAD_TAG_CLEAN			"clean"
#define	FM_EREPORT_PAYLOAD_TAG_HIT			"hit"
#define	FM_EREPORT_PAYLOAD_TAG_MISS			"miss"
#define	FM_EREPORT_PAYLOAD_DATA				"data-error"
#define	FM_EREPORT_PAYLOAD_DATA_SINGLE			"single-bit"
#define	FM_EREPORT_PAYLOAD_DATA_DBL_CLEAN		"double-bit-clean"
#define	FM_EREPORT_PAYLOAD_DATA_DBL_MOD			"double-bit-modified"
#define	FM_EREPORT_PAYLOAD_L3				"l3-cache"
#define	FM_EREPORT_PAYLOAD_INV_PIC			"invalid-pic-request"
#define	FM_EREPORT_PAYLOAD_CACHE_NERRORS		"cache-error-count"

#define	INTEL_NB_5000P	0x25d88086
#define	INTEL_NB_5000V	0x25d48086
#define	INTEL_NB_5000X	0x25c08086
#define	INTEL_NB_5000Z	0x25d08086
#define	INTEL_NB_5400	0x40008086
#define	INTEL_NB_5400A	0x40018086
#define	INTEL_NB_5400B	0x40038086
#define	INTEL_NB_7300	0x36008086

#ifdef __cplusplus
}
#endif

#endif /* _MC_INTEL_H */
