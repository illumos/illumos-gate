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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MC_INTEL_H
#define	_MC_INTEL_H

#ifdef __cplusplus
extern "C" {
#endif

#define	FM_EREPORT_CPU_INTEL	"intel"

#define	MCINTEL_NVLIST_VERSTR	"mcintel-nvlist-version"
#define	MCINTEL_NVLIST_VERS0	0

#define	MCINTEL_NVLIST_VERS	MCINTEL_NVLIST_VERS0

#define	MCINTEL_NVLIST_MEM	"memory-controller"
#define	MCINTEL_NVLIST_NMEM	"memory-controllers"
#define	MCINTEL_NVLIST_MC	"memory-channels"
#define	MCINTEL_NVLIST_DIMMS	"memory-dimms"
#define	MCINTEL_NVLIST_DIMMSZ	"memory-dimm-size"
#define	MCINTEL_NVLIST_NRANKS	"dimm-max-ranks"
#define	MCINTEL_NVLIST_NDIMMS	"dimm-max-dimms"
#define	MCINTEL_NVLIST_RANKS	"dimm-ranks"
#define	MCINTEL_NVLIST_1ST_RANK	"dimm-start-rank"
#define	MCINTEL_NVLIST_DIMM_NUM	"dimm-number"
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
#define	FM_EREPORT_PAYLOAD_NAME_VALIDLOG		"validlog"
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
#define	FM_EREPORT_PAYLOAD_NAME_BADRAM			"badram"
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
#define	FM_EREPORT_PAYLOAD_NAME_FERR_NF_MEM		"ferr_nf_mem"
#define	FM_EREPORT_PAYLOAD_NAME_NERR_NF_MEM		"nerr_nf_mem"
#define	FM_EREPORT_PAYLOAD_NAME_RECMEMA			"recmema"
#define	FM_EREPORT_PAYLOAD_NAME_RECMEMB			"recmemb"
#define	FM_EREPORT_PAYLOAD_NAME_REDMEMA			"redmema"
#define	FM_EREPORT_PAYLOAD_NAME_REDMEMB			"redmemb"
#define	FM_EREPORT_PAYLOAD_NAME_RECFGLOG		"recfglog"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDA			"recfbda"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDB			"recfbdb"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDC			"recfbdc"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDD			"recfbdd"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDE			"recfbde"
#define	FM_EREPORT_PAYLOAD_NAME_RECFBDF			"recfbdf"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNT			"cerrcnt"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNT_LAST		"cerrcnt_last"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNT_EXT		"cerrcnt_ext"
#define	FM_EREPORT_PAYLOAD_NAME_CERRCNT_EXT_LAST	"cerrcnt_ext_last"
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

#define	FM_EREPORT_PAYLOAD_NAME_RESOURCE		"resource"
#define	FM_EREPORT_PAYLOAD_MEM_ECC_COUNTER_THIS	"mem_cor_ecc_counter"
#define	FM_EREPORT_PAYLOAD_MEM_ECC_COUNTER_LAST	"mem_cor_ecc_counter_last"

#define	INTEL_NB_5000P	0x25d88086
#define	INTEL_NB_5000V	0x25d48086
#define	INTEL_NB_5000X	0x25c08086
#define	INTEL_NB_5000Z	0x25d08086
#define	INTEL_NB_5100	0x65c08086
#define	INTEL_NB_5400	0x40008086
#define	INTEL_NB_5400A	0x40018086
#define	INTEL_NB_5400B	0x40038086
#define	INTEL_NB_7300	0x36008086

#define	INTEL_NHM	0x2c408086
#define	INTEL_QP_IO	0x34008086
#define	INTEL_QP_36D	0x34068086
#define	INTEL_QP_24D	0x34038086
#define	INTEL_QP_WP	0x34058086
#define	INTEL_QP_U1	0x34018086
#define	INTEL_QP_U2	0x34028086
#define	INTEL_QP_U3	0x34048086
#define	INTEL_QP_U4	0x34078086
#define	INTEL_QP_JF	0x37208086
#define	INTEL_QP_JF0	0x37008086
#define	INTEL_QP_JF1	0x37018086
#define	INTEL_QP_JF2	0x37028086
#define	INTEL_QP_JF3	0x37038086
#define	INTEL_QP_JF4	0x37048086
#define	INTEL_QP_JF5	0x37058086
#define	INTEL_QP_JF6	0x37068086
#define	INTEL_QP_JF7	0x37078086
#define	INTEL_QP_JF8	0x37088086
#define	INTEL_QP_JF9	0x37098086
#define	INTEL_QP_JFa	0x370a8086
#define	INTEL_QP_JFb	0x370b8086
#define	INTEL_QP_JFc	0x370c8086
#define	INTEL_QP_JFd	0x370d8086
#define	INTEL_QP_JFe	0x370e8086
#define	INTEL_QP_JFf	0x370f8086

/* Intel QuickPath Bus Interconnect Errors */

#define	MSR_MC_STATUS_QP_HEADER_PARITY		(1 << 16)
#define	MSR_MC_STATUS_QP_DATA_PARITY		(1 << 17)
#define	MSR_MC_STATUS_QP_RETRIES_EXCEEDED	(1 << 18)
#define	MSR_MC_STATUS_QP_POISON		(1 << 19)

#define	MSR_MC_STATUS_QP_UNSUPPORTED_MSG	(1 << 22)
#define	MSR_MC_STATUS_QP_UNSUPPORTED_CREDIT	(1 << 23)
#define	MSR_MC_STATUS_QP_FLIT_BUF_OVER		(1 << 24)
#define	MSR_MC_STATUS_QP_FAILED_RESPONSE	(1 << 25)
#define	MSR_MC_STATUS_QP_CLOCK_JITTER		(1 << 26)

#define	MSR_MC_MISC_QP_CLASS		0x000000ff
#define	MSR_MC_MISC_QP_RTID		0x00003f00
#define	MSR_MC_MISC_QP_RHNID		0x00070000
#define	MSR_MC_MISC_QP_IIB		0x01000000

/* Intel QuickPath Memory Errors */

#define	MCAX86_COMPOUND_BUS_MEMORY		0x0080
#define	MCAX86_COMPOUND_BUS_MEMORY_MASK		0xff80
#define	MCAX86_COMPOUND_BUS_MEMORY_TRANSACTION	0x0070
#define	MCAX86_COMPOUND_BUS_MEMORY_READ		0x0010
#define	MCAX86_COMPOUND_BUS_MEMORY_WRITE	0x0020
#define	MCAX86_COMPOUND_BUS_MEMORY_CMD		0x0030
#define	MCAX86_COMPOUND_BUS_MEMORY_CHANNEL	0x000f

#define	MSR_MC_STATUS_MEM_ECC_READ	(1 << 16)
#define	MSR_MC_STATUS_MEM_ECC_SCRUB	(1 << 17)
#define	MSR_MC_STATUS_MEM_PARITY	(1 << 18)
#define	MSR_MC_STATUS_MEM_REDUNDANT_MEM	(1 << 19)
#define	MSR_MC_STATUS_MEM_SPARE_MEM	(1 << 20)
#define	MSR_MC_STATUS_MEM_ILLEGAL_ADDR	(1 << 21)
#define	MSR_MC_STATUS_MEM_BAD_ID	(1 << 22)
#define	MSR_MC_STATUS_MEM_ADDR_PARITY	(1 << 23)
#define	MSR_MC_STATUS_MEM_BYTE_PARITY	(1 << 24)

#define	MSR_MC_MISC_MEM_RTID		0x00000000000000ffULL
#define	MSR_MC_MISC_MEM_DIMM		0x0000000000030000ULL
#define	MSR_MC_MISC_MEM_DIMM_SHIFT	16
#define	MSR_MC_MISC_MEM_CHANNEL		0x00000000000c0000ULL
#define	MSR_MC_MISC_MEM_CHANNEL_SHIFT	18
#define	MSR_MC_MISC_MEM_SYNDROME	0xffffffff00000000ULL
#define	MSR_MC_MISC_MEM_SYNDROME_SHIFT	32

#define	OFFSET_ROW_BANK_COL	0x8000000000000000ULL
#define	OFFSET_RANK_SHIFT	52
#define	OFFSET_RAS_SHIFT	32
#define	OFFSET_BANK_SHIFT	24
#define	TCODE_OFFSET(rank, bank, ras, cas) (OFFSET_ROW_BANK_COL | \
	((uint64_t)(rank) << OFFSET_RANK_SHIFT) | \
	((uint64_t)(ras) << OFFSET_RAS_SHIFT) | \
	((uint64_t)(bank) << OFFSET_BANK_SHIFT) | (cas))

#define	MAX_CAS_MASK	0xFFFFFF
#define	MAX_BANK_MASK	0xFF
#define	MAX_RAS_MASK	0xFFFFF
#define	MAX_RANK_MASK	0x7FF
#define	TCODE_OFFSET_RANK(tcode) \
	(((tcode) >> OFFSET_RANK_SHIFT) & MAX_RANK_MASK)
#define	TCODE_OFFSET_RAS(tcode) (((tcode) >> OFFSET_RAS_SHIFT) & MAX_RAS_MASK)
#define	TCODE_OFFSET_BANK(tcode) \
	(((tcode) >> OFFSET_BANK_SHIFT) & MAX_BANK_MASK)
#define	TCODE_OFFSET_CAS(tcode) ((tcode) & MAX_CAS_MASK)

#ifdef __cplusplus
}
#endif

#endif /* _MC_INTEL_H */
