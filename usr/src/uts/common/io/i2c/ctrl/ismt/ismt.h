/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _ISMT_H
#define	_ISMT_H

/*
 * Intel SMBus Message Target Register Definitions
 */

#include <sys/types.h>
#include <sys/bitext.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * General control register.
 */
#define	ISMT_R_GCTRL		0x000
#define	ISMT_R_GCTRL_SET_SRST(r, v)	bitset32(r, 6, 6, v)
#define	ISMT_R_GCTRL_SET_KILL(r, v)	bitset32(r, 3, 3, v)
#define	ISMT_R_GCTRL_SET_TRST(r, v)	bitset32(r, 2, 2, v)

/*
 * Interrupt cause DMA logging. While we don't actually use this information, we
 * assume that hwarwdare may want to write to it.
 */
#define	ISMT_R_SMTICL		0x008

/*
 * These registers contain error masks that in theory firmware might manipulate.
 * We don't mask any errors by default and leave these at their defaults. The
 * last one is the current error status. Errors here are from the Xeon
 * D-1700/1800/2700/2800. We don't know if they're used across more devices or
 * not.
 */
#define	ISMT_R_ERRINTMSK	0x010
#define	ISMT_R_ERRAERMSK	0x014
#define	ISMT_R_ERRSTS		0x018
typedef enum {
	ISMT_ERR_CPE	= 1 << 0,
	ISMT_ERR_SPDWE	= 1 << 1,
	ISMT_ERR_IRE	= 1 << 8,
	ISMT_ERR_IRDPE	= 1 << 9,
	ISMT_ERR_ITE	= 1 << 10,
	ISMT_ERR_IMAE	= 1 << 11,
	ISMT_ERR_IHIE	= 1 << 12,
	ISMT_ERR_TRBAF	= 1 << 16,
	ISMT_ERR_TRBF	= 1 << 17,
	ISMT_ERR_CKLTO	= 1 << 24
} ismt_err_t;

/*
 * When an error occurs this is used to set information about what errors
 * occurred in the ERRSTS register.
 */
#define	ISMT_R_ERRINFO		0x01c
#define	ISMT_R_ERRINFO_GET_INFO2(r)	bitx32(r, 15, 13)
#define	ISMT_R_ERRINFO_GET_PTRO2(r)	bitx32(r, 12, 8)
#define	ISMT_R_ERRINFO_GET_INFO1(r)	bitx32(r, 7, 5)
#define	ISMT_R_ERRINFO_GET_PTRO1(r)	bitx32(r, 4, 0)

/*
 * Controller-specific registers.
 */

/*
 * Controller descriptor base address. Must be 64 byte aligned.
 */
#define	ISMT_R_MDBA		0x100

/*
 * Controller control register.
 */
#define	ISMT_R_MCTRL		0x108
#define	ISMT_R_MCTRL_SET_FMHP(r, v)	bitset32(r, 23, 16, v)
#define	ISMT_R_MCTRL_SET_MEIE(r, v)	bitset32(r, 4, 4, v)
#define	ISMT_R_MCTRL_GET_SPDDIS(r, v)	bitx32(r, 3, 3)
#define	ISMT_R_MCTRL_SET_SS(r, v)	bitset32(r, 0, 0, v)

/*
 * Controller status register.
 */
#define	ISMT_R_MSTS		0x10c
#define	ISMT_R_MSTS_GET_HMTP(r)		bitx32(r, 23, 16)
#define	ISMT_R_MSTS_SET_HMTP(r, v)	bitset32(r, 23, 16, v)
#define	ISMT_R_MSTS_GET_MIS(r)		bitx32(r, 5, 5)
#define	ISMT_R_MSTS_GET_MEIS(r)		bitx32(r, 4, 4)
#define	ISMT_R_MSTS_GET_IP(r)		bitx32(r, 0, 0)

/*
 * Controller descriptor size register. Sets the descriptor ring size. The
 * value is 0s based, menaing the actual value is x + 1.
 */
#define	ISMT_R_MDS		0x110
#define	ISMT_R_MDS_SET_SIZE(r, v)	bitset32(r, 7, 0, v)

/*
 * This register controls the various retry policy aspects.
 */
#define	ISMT_R_RPOLICY		0x114

/*
 * Timing related registers. These are more registers that are in theory
 * supposed to only be manipulated by firmware and several of these are supposed
 * to be fused. We expose these mostly as read-only properties.
 */
#define	ISMT_R_SPGT		0x300
#define	ISMT_R_SPGT_GET_SPD(r)		bitx32(r, 31, 30)
#define	ISMT_R_SPT_SPD_80K	0
#define	ISMT_R_SPT_SPD_100K	1
#define	ISMT_R_SPT_SPD_400K	2
#define	ISMT_R_SPT_SPD_1M	3
#define	ISMT_R_SPGT_GET_THDDAT(r)	bitx32(r, 19, 16)
#define	ISMT_R_SPGT_GET_TSUDAT(r)	bitx32(r, 11, 8)
#define	ISMT_R_SPGT_GET_DG(r)		bitx32(r, 7, 0)
#define	ISMT_R_SPMT		0x304
#define	ISMT_R_SPMT_GET_THIGH(r)	bitx32(r, 31, 24)
#define	ISMT_R_SPMT_GET_TLOW(r)		bitx32(r, 23, 16)
#define	ISMT_R_SPMT_GET_THDSTA(r)	bitx32(r, 15, 12)
#define	ISMT_R_SPMT_GET_TSUSTA(r)	bitx32(r, 11, 8)
#define	ISMT_R_SPMT_GET_TBUF(r)		bitx32(r, 7, 4)
#define	ISMT_R_SPMT_GET_TSUSTO(r)	bitx32(r, 3, 0)

typedef struct {
	uint32_t id_cmd_addr;
	uint32_t id_status;
	uint32_t id_low;
	uint32_t id_high;
} ismt_desc_t;

/*
 * Flags that control various behaviors:
 */
#define	ISMT_DESC_CMD_SET_SOE(r, v)	bitset32(r, 31, 31, v)
#define	ISMT_DESC_CMD_SET_INT(r, v)	bitset32(r, 30, 30, v)
#define	ISMT_DESC_CMD_SET_I2C(r, v)	bitset32(r, 29, 29, v)
#define	ISMT_DESC_CMD_SET_PEC(r, v)	bitset32(r, 28, 28, v)
#define	ISMT_DESC_CMD_SET_FAIR(r, v)	bitset32(r, 27, 27, v)
#define	ISMT_DESC_CMD_SET_BLK(r, v)	bitset32(r, 26, 26, v)
#define	ISMT_DESC_CMD_SET_CWRL(r, v)	bitset32(r, 24, 24, v)

/*
 * This sets the read and write lenths, as well as the address.
 */
#define	ISMT_DESC_CMD_SET_RDLEN(r, v)	bitset32(r, 23, 16, v)
#define	ISMT_DESC_CMD_SET_WRLEN(r, v)	bitset32(r, 15, 8, v)
#define	ISMT_DESC_CMD_SET_ADDR(r, v)	bitset32(r, 7, 1, v)
#define	ISMT_DESC_CMD_SET_RW(r, v)	bitset32(r, 0, 0, v)
#define	ISMT_DESC_CMD_RW_READ		1
#define	ISMT_DESC_CMD_RW_WRITE		0

/*
 * Actual number of transmitted and read bytes.
 */
#define	ISMT_DESC_STS_GET_WRLEN(r)	bitx32(r, 31, 24)
#define	ISMT_DESC_STS_GET_RDLEN(r)	bitx32(r, 23, 16)
#define	ISMT_DESC_STS_GET_COLRTRY(r)	bitx32(r, 14, 12)
#define	ISMT_DESC_STS_GET_RETRY(r)	bitx32(r, 11, 8)
#define	ISMT_DESC_STS_GET_LPR(r)	bitx32(r, 7, 7)
#define	ISMT_DESC_STS_GET_COL(r)	bitx32(r, 6, 6)
#define	ISMT_DESC_STS_GET_CLTO(r)	bitx32(r, 5, 5)
#define	ISMT_DESC_STS_GET_CRC(r)	bitx32(r, 4, 4)
#define	ISMT_DESC_STS_GET_NACK(r)	bitx32(r, 3, 3)
#define	ISMT_DESC_STS_GET_SCS(r)	bitx32(r, 0, 0)

/*
 * Hardware maximum read and write lengths. The maximum write length includes
 * the address byte and any command codes. The documentation is not the clearest
 * around maximums (using Intel doc #595910, Rev 2.3) as an example.
 *
 * It says at various points that I2C transactions can be up to 240 bytes.
 * However, it also says in the context of internal buffers that reads needs to
 * be less than 32 bytes and writes less than 80 bytes. However, this is also
 * referenced to a section about PEC. The 80 byte value is also supposed to
 * include the command and the address, meaning that it would be limited to 78
 * bytes. Ultimately, we constrain any SMBus style transaction to 32 bytes and
 * allow all I2C transactions to be up to 240.
 */
#define	ISMT_MAX_SMBUS	32
#define	ISMT_MAX_I2C	240

#ifdef __cplusplus
}
#endif

#endif /* _ISMT_H */
