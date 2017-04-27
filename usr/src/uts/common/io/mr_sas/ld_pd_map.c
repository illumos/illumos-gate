/*
 * **********************************************************************
 *
 * ld_pd_map.c
 *
 * Solaris MegaRAID device driver for SAS2.0 controllers
 * Copyright (c) 2008-2012, LSI Logic Corporation.
 * All rights reserved.
 *
 * Version:
 * Author:
 *		Swaminathan K S
 *		Arun Chandrashekhar
 *		Manju R
 *		Rasheed
 *		Shakeel Bukhari
 *
 *
 * This module contains functions for device drivers
 * to get pd-ld mapping information.
 *
 * **********************************************************************
 */
/*
 * Copyright 2015 Garrett D'Amore <garrett@damore.org>
 * Copyright 2017 Citrus IT Limited. All rights reserved.
 */

#include <sys/scsi/scsi.h>
#include "mr_sas.h"
#include "ld_pd_map.h"

/*
 * This function will check if FAST IO is possible on this logical drive
 * by checking the EVENT information available in the driver
 */
#define	MR_LD_STATE_OPTIMAL 3
#define	ABS_DIFF(a, b)   (((a) > (b)) ? ((a) - (b)) : ((b) - (a)))

static void mr_update_load_balance_params(MR_FW_RAID_MAP_ALL *,
    PLD_LOAD_BALANCE_INFO);

#define	FALSE 0
#define	TRUE 1

typedef	U64	REGION_KEY;
typedef	U32	REGION_LEN;
extern int 	debug_level_g;


MR_LD_RAID
*MR_LdRaidGet(U32 ld, MR_FW_RAID_MAP_ALL *map)
{
	return (&map->raidMap.ldSpanMap[ld].ldRaid);
}

U16
MR_GetLDTgtId(U32 ld, MR_FW_RAID_MAP_ALL *map)
{
	return (map->raidMap.ldSpanMap[ld].ldRaid.targetId);
}


static MR_SPAN_BLOCK_INFO *
MR_LdSpanInfoGet(U32 ld, MR_FW_RAID_MAP_ALL *map)
{
	return (&map->raidMap.ldSpanMap[ld].spanBlock[0]);
}

static U8
MR_LdDataArmGet(U32 ld, U32 armIdx, MR_FW_RAID_MAP_ALL *map)
{
	return (map->raidMap.ldSpanMap[ld].dataArmMap[armIdx]);
}

static U16
MR_ArPdGet(U32 ar, U32 arm, MR_FW_RAID_MAP_ALL *map)
{
	return (map->raidMap.arMapInfo[ar].pd[arm]);
}

static U16
MR_LdSpanArrayGet(U32 ld, U32 span, MR_FW_RAID_MAP_ALL *map)
{
	return (map->raidMap.ldSpanMap[ld].spanBlock[span].span.arrayRef);
}

static U16
MR_PdDevHandleGet(U32 pd, MR_FW_RAID_MAP_ALL *map)
{
	return (map->raidMap.devHndlInfo[pd].curDevHdl);
}

U16
MR_TargetIdToLdGet(U32 ldTgtId, MR_FW_RAID_MAP_ALL *map)
{
	return (map->raidMap.ldTgtIdToLd[ldTgtId]);
}

U16
MR_CheckDIF(U32 ldTgtId, MR_FW_RAID_MAP_ALL *map)
{
	MR_LD_RAID	*raid;
	U32		ld;

	ld = MR_TargetIdToLdGet(ldTgtId, map);

	if (ld >= MAX_LOGICAL_DRIVES) {
		return (FALSE);
	}

	raid = MR_LdRaidGet(ld, map);

	return (raid->capability.ldPiMode == 0x8);
}

static MR_LD_SPAN *
MR_LdSpanPtrGet(U32 ld, U32 span, MR_FW_RAID_MAP_ALL *map)
{
	return (&map->raidMap.ldSpanMap[ld].spanBlock[span].span);
}

/*
 * This function will validate Map info data provided by FW
 */
U8
MR_ValidateMapInfo(MR_FW_RAID_MAP_ALL *map, PLD_LOAD_BALANCE_INFO lbInfo)
{
	MR_FW_RAID_MAP *pFwRaidMap = &map->raidMap;
	U32 fwsize = sizeof (MR_FW_RAID_MAP) - sizeof (MR_LD_SPAN_MAP) +
	    (sizeof (MR_LD_SPAN_MAP) * pFwRaidMap->ldCount);

	if (pFwRaidMap->totalSize != fwsize) {

		con_log(CL_ANN1, (CE_NOTE,
		    "map info structure size 0x%x is "
		    "not matching with ld count\n", fwsize));
		/* sizeof (foo) returns size_t, which is *LONG*. */
		con_log(CL_ANN1, (CE_NOTE, "span map 0x%x total size 0x%x\n",\
		    (int)sizeof (MR_LD_SPAN_MAP), pFwRaidMap->totalSize));

		return (0);
	}

	mr_update_load_balance_params(map, lbInfo);

	return (1);
}

U32
MR_GetSpanBlock(U32 ld, U64 row, U64 *span_blk, MR_FW_RAID_MAP_ALL *map,
    int *div_error)
{
	MR_SPAN_BLOCK_INFO *pSpanBlock = MR_LdSpanInfoGet(ld, map);
	MR_QUAD_ELEMENT	*qe;
	MR_LD_RAID	*raid = MR_LdRaidGet(ld, map);
	U32		span, j;

	for (span = 0; span < raid->spanDepth; span++, pSpanBlock++) {
		for (j = 0; j < pSpanBlock->block_span_info.noElements; j++) {
			qe = &pSpanBlock->block_span_info.quads[j];
			if (qe->diff == 0) {
				*div_error = 1;
				return (span);
			}
			if (qe->logStart <= row && row <= qe->logEnd &&
			    (((row - qe->logStart) % qe->diff)) == 0) {
				if (span_blk != NULL) {
					U64	blk;
					blk = ((row - qe->logStart) /
					    (qe->diff));

					blk = (blk + qe->offsetInSpan) <<
					    raid->stripeShift;
					*span_blk = blk;
				}
				return (span);
			}
		}
	}
	return (span);
}


/*
 * *************************************************************
 *
 * This routine calculates the arm, span and block for
 * the specified stripe and reference in stripe.
 *
 * Inputs :
 *
 *    ld   - Logical drive number
 *    stripRow        - Stripe number
 *    stripRef    - Reference in stripe
 *
 * Outputs :
 *
 *    span          - Span number
 *    block         - Absolute Block number in the physical disk
 */
U8
MR_GetPhyParams(struct mrsas_instance *instance, U32 ld, U64 stripRow,
    U16 stripRef, U64 *pdBlock, U16 *pDevHandle,
    MPI2_SCSI_IO_VENDOR_UNIQUE *pRAID_Context, MR_FW_RAID_MAP_ALL *map)
{
	MR_LD_RAID	*raid = MR_LdRaidGet(ld, map);
	U32		pd, arRef;
	U8		physArm, span;
	U64		row;
	int		error_code = 0;
	U8		retval = TRUE;
	U32		rowMod;
	U32		armQ;
	U32		arm;

	ASSERT(raid->rowDataSize != 0);

	row = (stripRow / raid->rowDataSize);

	if (raid->level == 6) {
		U32 logArm =  (stripRow % (raid->rowDataSize));

		if (raid->rowSize == 0) {
			return (FALSE);
		}
		rowMod = (row % (raid->rowSize));
		armQ = raid->rowSize-1-rowMod;
		arm = armQ + 1 + logArm;
		if (arm >= raid->rowSize)
			arm -= raid->rowSize;
		physArm = (U8)arm;
	} else {
		if (raid->modFactor == 0)
			return (FALSE);
		physArm = MR_LdDataArmGet(ld,
		    (stripRow % (raid->modFactor)), map);
	}
	if (raid->spanDepth == 1) {
		span = 0;
		*pdBlock = row << raid->stripeShift;
	} else
		span = (U8)MR_GetSpanBlock(ld, row, pdBlock, map, &error_code);

	if (error_code == 1)
		return (FALSE);

	/* Get the array on which this span is present. */
	arRef		= MR_LdSpanArrayGet(ld, span, map);
	/* Get the Pd. */
	pd		= MR_ArPdGet(arRef, physArm, map);
	/* Get dev handle from Pd. */
	if (pd != MR_PD_INVALID) {
		*pDevHandle	= MR_PdDevHandleGet(pd, map);
	} else {
		*pDevHandle = MR_PD_INVALID; /* set dev handle as invalid. */
		if (raid->level >= 5 && (!instance->gen3 ||
		    raid->regTypeReqOnRead != REGION_TYPE_UNUSED)) {
			pRAID_Context->regLockFlags = REGION_TYPE_EXCLUSIVE;
		} else if (raid->level == 1) {
			/* Get Alternate Pd. */
			pd = MR_ArPdGet(arRef, physArm + 1, map);
			/* Get dev handle from Pd. */
			if (pd != MR_PD_INVALID)
				*pDevHandle = MR_PdDevHandleGet(pd, map);
		}
	}

	*pdBlock += stripRef + MR_LdSpanPtrGet(ld, span, map)->startBlk;

	pRAID_Context->spanArm = (span << RAID_CTX_SPANARM_SPAN_SHIFT) |
	    physArm;

	return (retval);
}



/*
 * ***********************************************************************
 *
 * MR_BuildRaidContext function
 *
 * This function will initiate command processing.  The start/end row and strip
 * information is calculated then the lock is acquired.
 * This function will return 0 if region lock
 * was acquired OR return num strips ???
 */

U8
MR_BuildRaidContext(struct mrsas_instance *instance,
    struct IO_REQUEST_INFO *io_info, MPI2_SCSI_IO_VENDOR_UNIQUE *pRAID_Context,
    MR_FW_RAID_MAP_ALL *map)
{
	MR_LD_RAID	*raid;
	U32		ld, stripSize, stripe_mask;
	U64		endLba, endStrip, endRow;
	U64		start_row, start_strip;
	REGION_KEY	regStart;
	REGION_LEN	regSize;
	U8		num_strips, numRows;
	U16		ref_in_start_stripe;
	U16		ref_in_end_stripe;

	U64		ldStartBlock;
	U32		numBlocks, ldTgtId;
	U8		isRead;
	U8		retval = 0;

	ldStartBlock = io_info->ldStartBlock;
	numBlocks = io_info->numBlocks;
	ldTgtId = io_info->ldTgtId;
	isRead = io_info->isRead;

	if (map == NULL) {
		io_info->fpOkForIo = FALSE;
		return (FALSE);
	}

	ld = MR_TargetIdToLdGet(ldTgtId, map);

	if (ld >= MAX_LOGICAL_DRIVES) {
		io_info->fpOkForIo = FALSE;
		return (FALSE);
	}

	raid = MR_LdRaidGet(ld, map);

	stripSize = 1 << raid->stripeShift;
	stripe_mask = stripSize-1;
	/*
	 * calculate starting row and stripe, and number of strips and rows
	 */
	start_strip		= ldStartBlock >> raid->stripeShift;
	ref_in_start_stripe	= (U16)(ldStartBlock & stripe_mask);
	endLba			= ldStartBlock + numBlocks - 1;
	ref_in_end_stripe	= (U16)(endLba & stripe_mask);
	endStrip		= endLba >> raid->stripeShift;
	num_strips		= (U8)(endStrip - start_strip + 1);
	/* Check to make sure is not dividing by zero */
	if (raid->rowDataSize == 0)
		return (FALSE);
	start_row		=  (start_strip / raid->rowDataSize);
	endRow			=  (endStrip  / raid->rowDataSize);
	/* get the row count */
	numRows			= (U8)(endRow - start_row + 1);

	/*
	 * calculate region info.
	 */
	regStart	= start_row << raid->stripeShift;
	regSize		= stripSize;

	/* Check if we can send this I/O via FastPath */
	if (raid->capability.fpCapable) {
		if (isRead) {
			io_info->fpOkForIo = (raid->capability.fpReadCapable &&
			    ((num_strips == 1) ||
			    raid->capability.fpReadAcrossStripe));
		} else {
			io_info->fpOkForIo =
			    (raid->capability.fpWriteCapable &&
			    ((num_strips == 1) ||
			    raid->capability.fpWriteAcrossStripe));
		}
	} else
		io_info->fpOkForIo = FALSE;


	/*
	 * Check for DIF support
	 */
	if (!raid->capability.ldPiMode) {
		io_info->ldPI = FALSE;
	} else {
		io_info->ldPI = TRUE;
	}

	if (numRows == 1) {
		if (num_strips == 1) {
			regStart += ref_in_start_stripe;
			regSize = numBlocks;
		}
	} else {
		if (start_strip == (start_row + 1) * raid->rowDataSize - 1) {
			regStart += ref_in_start_stripe;
		regSize = stripSize - ref_in_start_stripe;
		}

		if (numRows > 2) {
			regSize += (numRows - 2) << raid->stripeShift;
		}

		if (endStrip == endRow * raid->rowDataSize) {
			regSize += ref_in_end_stripe + 1;
		} else {
			regSize += stripSize;
		}
	}

	pRAID_Context->timeoutValue = map->raidMap.fpPdIoTimeoutSec;

	if (instance->gen3) {
		pRAID_Context->regLockFlags = (isRead) ?
		    raid->regTypeReqOnRead : raid->regTypeReqOnWrite;
	} else {
		pRAID_Context->regLockFlags = (isRead) ?
		    REGION_TYPE_SHARED_READ : raid->regTypeReqOnWrite;
	}

	pRAID_Context->ldTargetId = raid->targetId;
	pRAID_Context->regLockRowLBA = regStart;
	pRAID_Context->regLockLength = regSize;
	pRAID_Context->configSeqNum = raid->seqNum;

	/*
	 * Get Phy Params only if FP capable,
	 * or else leave it to MR firmware to do the calculation.
	 */
	if (io_info->fpOkForIo) {
		/* if fast path possible then get the physical parameters */
		retval = MR_GetPhyParams(instance, ld, start_strip,
		    ref_in_start_stripe, &io_info->pdBlock,
		    &io_info->devHandle, pRAID_Context, map);

		/* If IO on an invalid Pd, then FP is not possible. */
		if (io_info->devHandle == MR_PD_INVALID)
			io_info->fpOkForIo = FALSE;

		return (retval);

	} else if (isRead) {
		uint_t stripIdx;

		for (stripIdx = 0; stripIdx < num_strips; stripIdx++) {
			if (!MR_GetPhyParams(instance, ld,
			    start_strip + stripIdx, ref_in_start_stripe,
			    &io_info->pdBlock, &io_info->devHandle,
			    pRAID_Context, map)) {
				return (TRUE);
			}
		}
	}
	return (TRUE);
}


void
mr_update_load_balance_params(MR_FW_RAID_MAP_ALL *map,
    PLD_LOAD_BALANCE_INFO lbInfo)
{
	int ldCount;
	U16 ld;
	MR_LD_RAID *raid;

	for (ldCount = 0; ldCount < MAX_LOGICAL_DRIVES; ldCount++) {
		ld = MR_TargetIdToLdGet(ldCount, map);

		if (ld >= MAX_LOGICAL_DRIVES) {
			con_log(CL_ANN1,
			    (CE_NOTE, "mrsas: ld=%d Invalid ld \n", ld));
			continue;
		}

		raid = MR_LdRaidGet(ld, map);

		/* Two drive Optimal RAID 1 */
		if ((raid->level == 1) && (raid->rowSize == 2) &&
		    (raid->spanDepth == 1) &&
		    raid->ldState == MR_LD_STATE_OPTIMAL) {
			U32 pd, arRef;

			lbInfo[ldCount].loadBalanceFlag = 1;

			/* Get the array on which this span is present. */
			arRef = MR_LdSpanArrayGet(ld, 0, map);

			pd = MR_ArPdGet(arRef, 0, map);	    /* Get the Pd. */
			/* Get dev handle from Pd. */
			lbInfo[ldCount].raid1DevHandle[0] =
			    MR_PdDevHandleGet(pd, map);

			pd = MR_ArPdGet(arRef, 1, map);	    /* Get the Pd. */
			/* Get dev handle from Pd. */
			lbInfo[ldCount].raid1DevHandle[1] =
			    MR_PdDevHandleGet(pd, map);
			con_log(CL_ANN1, (CE_NOTE,
			    "mrsas: ld=%d load balancing enabled \n", ldCount));
		} else {
			lbInfo[ldCount].loadBalanceFlag = 0;
		}
	}
}


U8
megasas_get_best_arm(PLD_LOAD_BALANCE_INFO lbInfo, U8 arm, U64 block,
    U32 count)
{
	U16 pend0, pend1;
	U64 diff0, diff1;
	U8 bestArm;

	/* get the pending cmds for the data and mirror arms */
	pend0 = lbInfo->scsi_pending_cmds[0];
	pend1 = lbInfo->scsi_pending_cmds[1];

	/* Determine the disk whose head is nearer to the req. block */
	diff0 = ABS_DIFF(block, lbInfo->last_accessed_block[0]);
	diff1 = ABS_DIFF(block, lbInfo->last_accessed_block[1]);
	bestArm = (diff0 <= diff1 ? 0 : 1);

	if ((bestArm == arm && pend0 > pend1 + 16) ||
	    (bestArm != arm && pend1 > pend0 + 16)) {
		bestArm ^= 1;
	}

	/* Update the last accessed block on the correct pd */
	lbInfo->last_accessed_block[bestArm] = block + count - 1;
	return (bestArm);
}

U16
get_updated_dev_handle(PLD_LOAD_BALANCE_INFO lbInfo,
    struct IO_REQUEST_INFO *io_info)
{
	U8 arm, old_arm;
	U16 devHandle;

	old_arm = lbInfo->raid1DevHandle[0] == io_info->devHandle ? 0 : 1;

	/* get best new arm */
	arm  = megasas_get_best_arm(lbInfo, old_arm, io_info->ldStartBlock,
	    io_info->numBlocks);

	devHandle = lbInfo->raid1DevHandle[arm];

	lbInfo->scsi_pending_cmds[arm]++;

	return (devHandle);
}
