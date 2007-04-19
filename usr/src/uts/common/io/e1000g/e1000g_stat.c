/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2007 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * **********************************************************************
 *									*
 * Module Name:  e1000g_stat.c						*
 *									*
 * Abstract:     Functions for displaying statistics			*
 *									*
 * **********************************************************************
 */
#include "e1000g_sw.h"
#include "e1000g_debug.h"

static int UpdateStatsCounters(kstat_t *ksp, int rw);

/*
 * **********************************************************************
 *									*
 * Name:	    AdjustTbiAcceptedStats				*
 *									*
 * Description:     Adjusts statistic counters when a frame is accepted	*
 *		  under the TBI workaround. This function has been	*
 *		  adapted for Solaris from shared code.			*
 *									*
 * Author:	  Bill Campbell						*
 *									*
 * Born on Date:    4/12/2001						*
 *									*
 * Arguments:								*
 *      Adapter     - Ptr to this card's adapter data structure.	*
 *      FrameLength - Length as reported from Hardware			*
 *      MacAddress  - Pointer to MAC address field in frame.		*
 *									*
 * Returns:								*
 *      VOID								*
 *									*
 * **********************************************************************
 */
void
AdjustTbiAcceptedStats(struct e1000g *Adapter,
    UINT32 FrameLength, PUCHAR MacAddress)
{
	UINT32 CarryBit;
	e1000gstat *e1000g_ksp;

	e1000g_ksp = (e1000gstat *)Adapter->e1000g_ksp->ks_data;

	/*
	 * First adjust the frame length.
	 */
	FrameLength--;
	/*
	 * We need to adjust the statistics counters, since the hardware
	 * counters overcount this packet as a CRC error and undercount
	 * the packet as a good packet
	 */

	/*
	 * This packet should not be counted as a CRC error.
	 */
	e1000g_ksp->Crcerrs.value.ul--;
	/*
	 * This packet does count as a Good Packet Received.
	 */
	e1000g_ksp->Gprc.value.ul++;

	/*
	 * Adjust the Good Octets received counters
	 */
	CarryBit = 0x80000000 & e1000g_ksp->Gorl.value.ul;
	e1000g_ksp->Gorl.value.ul += FrameLength;
	/*
	 * If the high bit of Gorcl (the low 32 bits of the Good Octets
	 * Received Count) was one before the addition,
	 * AND it is zero after, then we lost the carry out,
	 * need to add one to Gorch (Good Octets Received Count High).
	 * This could be simplified if all environments supported
	 * 64-bit integers.
	 */
	if (CarryBit && ((e1000g_ksp->Gorl.value.ul & 0x80000000) == 0)) {
		e1000g_ksp->Gorh.value.ul++;
	}
	/*
	 * Is this a broadcast or multicast?  Check broadcast first,
	 * since the test for a multicast frame will test positive on
	 * a broadcast frame.
	 */
	if ((MacAddress[0] == (UCHAR) 0xff) &&
	    (MacAddress[1] == (UCHAR) 0xff)) {
		/*
		 * Broadcast packet
		 */
		e1000g_ksp->Bprc.value.ul++;
	} else if (*MacAddress & 0x01) {
		/*
		 * Multicast packet
		 */
		e1000g_ksp->Mprc.value.ul++;
	}
	if (FrameLength == Adapter->Shared.max_frame_size) {
		/*
		 * In this case, the hardware has overcounted the number of
		 * oversize frames.
		 */
		if (e1000g_ksp->Roc.value.ul > 0)
			e1000g_ksp->Roc.value.ul--;
	}

	/*
	 * Adjust the bin counters when the extra byte put the frame in the
	 * wrong bin. Remember that the FrameLength was adjusted above.
	 */
	if (FrameLength == 64) {
		e1000g_ksp->Prc64.value.ul++;
		e1000g_ksp->Prc127.value.ul--;
	} else if (FrameLength == 127) {
		e1000g_ksp->Prc127.value.ul++;
		e1000g_ksp->Prc255.value.ul--;
	} else if (FrameLength == 255) {
		e1000g_ksp->Prc255.value.ul++;
		e1000g_ksp->Prc511.value.ul--;
	} else if (FrameLength == 511) {
		e1000g_ksp->Prc511.value.ul++;
		e1000g_ksp->Prc1023.value.ul--;
	} else if (FrameLength == 1023) {
		e1000g_ksp->Prc1023.value.ul++;
		e1000g_ksp->Prc1522.value.ul--;
	} else if (FrameLength == 1522) {
		e1000g_ksp->Prc1522.value.ul++;
	}
}


/*
 * **********************************************************************
 * Name:	UpdateStatsCounters					*
 *									*
 * Description: This routine will dump and reset the 1000's internal	*
 *	      Statistics counters.  The current stats dump values will	*
 *	      be sent to the kernel status area.			*
 *									*
 * Author:      Phil Cayton						*
 *									*
 * Born on Date:    7/13/98						*
 *									*
 * Arguments:								*
 *     *ksp - A kernel stat pointer					*
 *     rw   - Read/Write flag						*
 *									*
 * Returns:								*
 *      (EACCES) If an attempt is made to write stats to the hw		*
 *      (0) On successful read of statistics to kernel stats.		*
 *									*
 * File: e1000g_stat.c							*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  ------------------------------------------------------*
 * Sept 10,99 Vinay New Counters for Livengood have been added.		*
 * **********************************************************************
 */
static int
UpdateStatsCounters(IN kstat_t *ksp, int rw)
{
	uint16_t LineSpeed, Duplex;
	struct e1000g *Adapter;
	e1000gstat *e1000g_ksp;
	uint64_t val;
	uint32_t low_val, high_val;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	Adapter = (struct e1000g *)ksp->ks_private;
	ASSERT(Adapter != NULL);
	e1000g_ksp = (e1000gstat *)ksp->ks_data;
	ASSERT(e1000g_ksp != NULL);

	e1000g_ksp->link_speed.value.ul = Adapter->link_speed;
	e1000g_ksp->rx_none.value.ul = Adapter->rx_none;
	e1000g_ksp->rx_error.value.ul = Adapter->rx_error;
	e1000g_ksp->rx_no_freepkt.value.ul = Adapter->rx_no_freepkt;
	e1000g_ksp->rx_esballoc_fail.value.ul = Adapter->rx_esballoc_fail;
	e1000g_ksp->rx_exceed_pkt.value.ul = Adapter->rx_exceed_pkt;
	e1000g_ksp->rx_multi_desc.value.ul = Adapter->rx_multi_desc;
	e1000g_ksp->rx_allocb_fail.value.ul = Adapter->rx_allocb_fail;
	e1000g_ksp->rx_avail_freepkt.value.ul = Adapter->rx_avail_freepkt;
	e1000g_ksp->rx_seq_intr.value.ul = Adapter->rx_seq_intr;
	e1000g_ksp->tx_no_desc.value.ul = Adapter->tx_no_desc;
	e1000g_ksp->tx_no_swpkt.value.ul = Adapter->tx_no_swpkt;
	e1000g_ksp->tx_lack_desc.value.ul = Adapter->tx_lack_desc;
	e1000g_ksp->tx_send_fail.value.ul = Adapter->tx_send_fail;
	e1000g_ksp->tx_multi_cookie.value.ul = Adapter->tx_multi_cookie;
	e1000g_ksp->tx_over_size.value.ul = Adapter->tx_over_size;
	e1000g_ksp->tx_under_size.value.ul = Adapter->tx_under_size;
	e1000g_ksp->tx_copy.value.ul = Adapter->tx_copy;
	e1000g_ksp->tx_bind.value.ul = Adapter->tx_bind;
	e1000g_ksp->tx_multi_copy.value.ul = Adapter->tx_multi_copy;
	e1000g_ksp->tx_reschedule.value.ul = Adapter->tx_reschedule;
	e1000g_ksp->tx_empty_frags.value.ul = Adapter->tx_empty_frags;
	e1000g_ksp->tx_exceed_frags.value.ul = Adapter->tx_exceed_frags;
	e1000g_ksp->tx_recycle.value.ul = Adapter->tx_recycle;
	e1000g_ksp->tx_recycle_retry.value.ul = Adapter->tx_recycle_retry;
	e1000g_ksp->tx_recycle_intr.value.ul = Adapter->tx_recycle_intr;
	e1000g_ksp->tx_recycle_none.value.ul = Adapter->tx_recycle_none;
	e1000g_ksp->StallWatchdog.value.ul = Adapter->StallWatchdog;
	e1000g_ksp->reset_count.value.ul = Adapter->reset_count;
	e1000g_ksp->JumboTx_4K.value.ul = Adapter->JumboTx_4K;
	e1000g_ksp->JumboRx_4K.value.ul = Adapter->JumboRx_4K;
	e1000g_ksp->JumboTx_8K.value.ul = Adapter->JumboTx_8K;
	e1000g_ksp->JumboRx_8K.value.ul = Adapter->JumboRx_8K;
	e1000g_ksp->JumboTx_16K.value.ul = Adapter->JumboTx_16K;
	e1000g_ksp->JumboRx_16K.value.ul = Adapter->JumboRx_16K;
	e1000g_ksp->intr_type.value.ul = Adapter->intr_type;

	/*
	 * Mutex required if in TBI mode
	 */
	if (Adapter->Shared.tbi_compatibility_on == 1) {
		mutex_enter(&Adapter->TbiCntrMutex);
	}

	/*
	 * Standard Stats
	 */
	e1000g_ksp->Mpc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, MPC);

	e1000g_ksp->Symerrs.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, SYMERRS);

	e1000g_ksp->Rlec.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, RLEC);

	e1000g_ksp->Xonrxc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, XONRXC);

	e1000g_ksp->Xontxc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, XONTXC);

	e1000g_ksp->Xoffrxc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, XOFFRXC);

	e1000g_ksp->Xofftxc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, XOFFTXC);

	e1000g_ksp->Fcruc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, FCRUC);

	e1000g_ksp->Prc64.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PRC64);

	e1000g_ksp->Prc127.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PRC127);

	e1000g_ksp->Prc255.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PRC255);

	e1000g_ksp->Prc511.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PRC511);

	e1000g_ksp->Prc1023.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PRC1023);

	e1000g_ksp->Prc1522.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PRC1522);

	e1000g_ksp->Gprc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, GPRC);

	e1000g_ksp->Gptc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, GPTC);

	/*
	 * The 64-bit register will reset whenever the upper
	 * 32 bits are read. So we need to read the lower
	 * 32 bits first, then read the upper 32 bits.
	 */
	low_val = E1000_READ_REG(&Adapter->Shared, GORCL);
	high_val = E1000_READ_REG(&Adapter->Shared, GORCH);
	val = (uint64_t)e1000g_ksp->Gorh.value.ul << 32 |
	    (uint64_t)e1000g_ksp->Gorl.value.ul;
	val += (uint64_t)high_val << 32 | (uint64_t)low_val;
	e1000g_ksp->Gorl.value.ul = (uint32_t)val;
	e1000g_ksp->Gorh.value.ul = (uint32_t)(val >> 32);

	low_val = E1000_READ_REG(&Adapter->Shared, GOTCL);
	high_val = E1000_READ_REG(&Adapter->Shared, GOTCH);
	val = (uint64_t)e1000g_ksp->Goth.value.ul << 32 |
	    (uint64_t)e1000g_ksp->Gotl.value.ul;
	val += (uint64_t)high_val << 32 | (uint64_t)low_val;
	e1000g_ksp->Gotl.value.ul = (uint32_t)val;
	e1000g_ksp->Goth.value.ul = (uint32_t)(val >> 32);

	e1000g_ksp->Ruc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, RUC);

	e1000g_ksp->Rfc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, RFC);

	e1000g_ksp->Roc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, ROC);

	e1000g_ksp->Rjc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, RJC);

	low_val = E1000_READ_REG(&Adapter->Shared, TORL);
	high_val = E1000_READ_REG(&Adapter->Shared, TORH);
	val = (uint64_t)e1000g_ksp->Torh.value.ul << 32 |
	    (uint64_t)e1000g_ksp->Torl.value.ul;
	val += (uint64_t)high_val << 32 | (uint64_t)low_val;
	e1000g_ksp->Torl.value.ul = (uint32_t)val;
	e1000g_ksp->Torh.value.ul = (uint32_t)(val >> 32);

	low_val = E1000_READ_REG(&Adapter->Shared, TOTL);
	high_val = E1000_READ_REG(&Adapter->Shared, TOTH);
	val = (uint64_t)e1000g_ksp->Toth.value.ul << 32 |
	    (uint64_t)e1000g_ksp->Totl.value.ul;
	val += (uint64_t)high_val << 32 | (uint64_t)low_val;
	e1000g_ksp->Totl.value.ul = (uint32_t)val;
	e1000g_ksp->Toth.value.ul = (uint32_t)(val >> 32);

	e1000g_ksp->Tpr.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, TPR);

	/*
	 * Adaptive Calculations
	 */
	Adapter->Shared.tx_packet_delta =
	    E1000_READ_REG(&Adapter->Shared, TPT);
	e1000g_ksp->Tpt.value.ul +=
	    Adapter->Shared.tx_packet_delta;

	e1000g_ksp->Ptc64.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PTC64);

	e1000g_ksp->Ptc127.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PTC127);

	e1000g_ksp->Ptc255.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PTC255);

	e1000g_ksp->Ptc511.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PTC511);

	e1000g_ksp->Ptc1023.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PTC1023);

	e1000g_ksp->Ptc1522.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, PTC1522);

	/*
	 * Livengood Counters
	 */
	e1000g_ksp->Tncrs.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, TNCRS);

	e1000g_ksp->Tsctc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, TSCTC);

	e1000g_ksp->Tsctfc.value.ul +=
	    E1000_READ_REG(&Adapter->Shared, TSCTFC);

	/*
	 * Mutex required if in TBI mode
	 */
	if (Adapter->Shared.tbi_compatibility_on == 1) {
		mutex_exit(&Adapter->TbiCntrMutex);
	}

	return (0);
}

int
e1000g_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	e1000gstat *e1000g_ksp;
	uint32_t low_val, high_val;
	uint16_t phy_reg, phy_reg_2;

	e1000g_ksp = (e1000gstat *)Adapter->e1000g_ksp->ks_data;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = Adapter->link_speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		e1000g_ksp->Mprc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, MPRC);
		*val = e1000g_ksp->Mprc.value.ul;
		break;

	case MAC_STAT_BRDCSTRCV:
		e1000g_ksp->Bprc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, BPRC);
		*val = e1000g_ksp->Bprc.value.ul;
		break;

	case MAC_STAT_MULTIXMT:
		e1000g_ksp->Mptc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, MPTC);
		*val = e1000g_ksp->Mptc.value.ul;
		break;

	case MAC_STAT_BRDCSTXMT:
		e1000g_ksp->Bptc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, BPTC);
		*val = e1000g_ksp->Bptc.value.ul;
		break;

	case MAC_STAT_NORCVBUF:
		e1000g_ksp->Rnbc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, RNBC);
		*val = e1000g_ksp->Rnbc.value.ul;
		break;

	case MAC_STAT_IERRORS:
		e1000g_ksp->Rxerrc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, RXERRC);
		e1000g_ksp->Algnerrc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, ALGNERRC);
		e1000g_ksp->Rlec.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, RLEC);
		e1000g_ksp->Crcerrs.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, CRCERRS);
		e1000g_ksp->Cexterr.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, CEXTERR);
		*val = e1000g_ksp->Rxerrc.value.ul +
		    e1000g_ksp->Algnerrc.value.ul +
		    e1000g_ksp->Rlec.value.ul +
		    e1000g_ksp->Crcerrs.value.ul +
		    e1000g_ksp->Cexterr.value.ul;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = Adapter->tx_no_desc;
		break;

	case MAC_STAT_OERRORS:
		e1000g_ksp->Ecol.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, ECOL);
		*val = e1000g_ksp->Ecol.value.ul;
		break;

	case MAC_STAT_COLLISIONS:
		e1000g_ksp->Colc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, COLC);
		*val = e1000g_ksp->Colc.value.ul;
		break;

	case MAC_STAT_RBYTES:
		/*
		 * The 64-bit register will reset whenever the upper
		 * 32 bits are read. So we need to read the lower
		 * 32 bits first, then read the upper 32 bits.
		 */
		low_val = E1000_READ_REG(&Adapter->Shared, TORL);
		high_val = E1000_READ_REG(&Adapter->Shared, TORH);
		*val = (uint64_t)e1000g_ksp->Torh.value.ul << 32 |
		    (uint64_t)e1000g_ksp->Torl.value.ul;
		*val += (uint64_t)high_val << 32 | (uint64_t)low_val;

		e1000g_ksp->Torl.value.ul = (uint32_t)*val;
		e1000g_ksp->Torh.value.ul = (uint32_t)(*val >> 32);
		break;

	case MAC_STAT_IPACKETS:
		e1000g_ksp->Tpr.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, TPR);
		*val = e1000g_ksp->Tpr.value.ul;
		break;

	case MAC_STAT_OBYTES:
		/*
		 * The 64-bit register will reset whenever the upper
		 * 32 bits are read. So we need to read the lower
		 * 32 bits first, then read the upper 32 bits.
		 */
		low_val = E1000_READ_REG(&Adapter->Shared, TOTL);
		high_val = E1000_READ_REG(&Adapter->Shared, TOTH);
		*val = (uint64_t)e1000g_ksp->Toth.value.ul << 32 |
		    (uint64_t)e1000g_ksp->Totl.value.ul;
		*val += (uint64_t)high_val << 32 | (uint64_t)low_val;

		e1000g_ksp->Totl.value.ul = (uint32_t)*val;
		e1000g_ksp->Toth.value.ul = (uint32_t)(*val >> 32);
		break;

	case MAC_STAT_OPACKETS:
		e1000g_ksp->Tpt.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, TPT);
		*val = e1000g_ksp->Tpt.value.ul;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		e1000g_ksp->Algnerrc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, ALGNERRC);
		*val = e1000g_ksp->Algnerrc.value.ul;
		break;

	case ETHER_STAT_FCS_ERRORS:
		e1000g_ksp->Crcerrs.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, CRCERRS);
		*val = e1000g_ksp->Crcerrs.value.ul;
		break;

	case ETHER_STAT_SQE_ERRORS:
		e1000g_ksp->Sec.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, SEC);
		*val = e1000g_ksp->Sec.value.ul;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		e1000g_ksp->Cexterr.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, CEXTERR);
		*val = e1000g_ksp->Cexterr.value.ul;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		e1000g_ksp->Ecol.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, ECOL);
		*val = e1000g_ksp->Ecol.value.ul;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		e1000g_ksp->Latecol.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, LATECOL);
		*val = e1000g_ksp->Latecol.value.ul;
		break;

	case ETHER_STAT_DEFER_XMTS:
		e1000g_ksp->Dc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, DC);
		*val = e1000g_ksp->Dc.value.ul;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		e1000g_ksp->Scc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, SCC);
		*val = e1000g_ksp->Scc.value.ul;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		e1000g_ksp->Mcc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, MCC);
		*val = e1000g_ksp->Mcc.value.ul;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		e1000g_ksp->Rxerrc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, RXERRC);
		*val = e1000g_ksp->Rxerrc.value.ul;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		e1000g_ksp->Ecol.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, ECOL);
		*val = e1000g_ksp->Ecol.value.ul;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		e1000g_ksp->Roc.value.ul +=
		    E1000_READ_REG(&Adapter->Shared, ROC);
		*val = e1000g_ksp->Roc.value.ul;
		break;

	case ETHER_STAT_XCVR_ADDR:
		/* The Internal PHY's MDI address for each MAC is 1 */
		*val = 1;
		break;

	case ETHER_STAT_XCVR_ID:
		e1000_read_phy_reg(&Adapter->Shared, PHY_ID1, &phy_reg);
		e1000_read_phy_reg(&Adapter->Shared, PHY_ID2, &phy_reg_2);
		*val = (uint32_t)((phy_reg << 16) | phy_reg_2);
		break;

	case ETHER_STAT_XCVR_INUSE:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS, &phy_reg);
		switch (Adapter->link_speed) {
		case SPEED_1000:
			*val =
			    (Adapter->Shared.media_type ==
			    e1000_media_type_copper) ? XCVR_1000T :
			    XCVR_1000X;
			break;
		case SPEED_100:
			*val =
			    (Adapter->Shared.media_type ==
			    e1000_media_type_copper) ? (phy_reg &
			    MII_SR_100T4_CAPS) ? XCVR_100T4 : XCVR_100T2 :
			    XCVR_100X;
			break;
		case SPEED_10:
			*val = XCVR_10;
			break;
		default:
			*val = XCVR_NONE;
			break;
		}
		break;

	case ETHER_STAT_CAP_1000FDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_EXT_STATUS,
		    &phy_reg);
		*val = ((phy_reg & IEEE_ESR_1000T_FD_CAPS) ||
		    (phy_reg & IEEE_ESR_1000X_FD_CAPS)) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_1000HDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_EXT_STATUS,
		    &phy_reg);
		*val = ((phy_reg & IEEE_ESR_1000T_HD_CAPS) ||
		    (phy_reg & IEEE_ESR_1000X_HD_CAPS)) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_100FDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS, &phy_reg);
		*val = ((phy_reg & MII_SR_100X_FD_CAPS) ||
		    (phy_reg & MII_SR_100T2_FD_CAPS)) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_100HDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS, &phy_reg);
		*val = ((phy_reg & MII_SR_100X_HD_CAPS) ||
		    (phy_reg & MII_SR_100T2_HD_CAPS)) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_10FDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS, &phy_reg);
		*val = (phy_reg & MII_SR_10T_FD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_10HDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS, &phy_reg);
		*val = (phy_reg & MII_SR_10T_HD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_ASM_DIR) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_PAUSE:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_PAUSE) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS, &phy_reg);
		*val = (phy_reg & MII_SR_AUTONEG_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_1000T_CTRL,
		    &phy_reg);
		*val = (phy_reg & CR_1000T_FD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_1000T_CTRL,
		    &phy_reg);
		*val = (phy_reg & CR_1000T_HD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_100TX_FD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_100TX_HD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_10T_FD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_10T_HD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_ASM_DIR) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_PAUSE) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = Adapter->Shared.autoneg;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_1000T_STATUS,
		    &phy_reg);
		*val = (phy_reg & SR_1000T_LP_FD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_1000T_STATUS,
		    &phy_reg);
		*val = (phy_reg & SR_1000T_LP_HD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		*val = (phy_reg & NWAY_LPAR_100TX_FD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		*val = (phy_reg & NWAY_LPAR_100TX_HD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		*val = (phy_reg & NWAY_LPAR_10T_FD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		*val = (phy_reg & NWAY_LPAR_10T_HD_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		*val = (phy_reg & NWAY_LPAR_ASM_DIR) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		*val = (phy_reg & NWAY_LPAR_PAUSE) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_EXP,
		    &phy_reg);
		*val = (phy_reg & NWAY_ER_LP_NWAY_CAPS) ? 1 : 0;
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_ASM_DIR) ? 1 : 0;
		break;

	case ETHER_STAT_LINK_PAUSE:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		*val = (phy_reg & NWAY_AR_PAUSE) ? 1 : 0;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		e1000_read_phy_reg(&Adapter->Shared, PHY_CTRL, &phy_reg);
		*val = (phy_reg & MII_CR_AUTO_NEG_EN) ? 1 : 0;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = (Adapter->link_duplex == FULL_DUPLEX) ?
		    LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}

/*
 * **********************************************************************
 * Name:	InitStatsCounters					*
 *									*
 * Description: This routine will create and initialize the kernel	*
 *	       statistics counters.					*
 *									*
 * Author:      Phil Cayton						*
 *									*
 * Born on Date:    7/13/98						*
 *									*
 * Arguments:								*
 *      Adapter - A pointer to our context sensitive "Adapter"		*
 *		structure.						*
 *									*
 * Returns:								*
 *      '0' if unable to create kernel statistics structure.		*
 *      '1' if creation and initialization successful			*
 *									*
 * File: e1000g_stat.c							*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  ------------------------------------------------------*
 *									*
 * **********************************************************************
 */
int
InitStatsCounters(IN struct e1000g *Adapter)
{
	kstat_t *ksp;
	e1000gstat *e1000g_ksp;

	/*
	 * Create and init kstat
	 */
	ksp = kstat_create(WSNAME, ddi_get_instance(Adapter->dip),
	    "statistics", "net", KSTAT_TYPE_NAMED,
	    sizeof (e1000gstat) / sizeof (kstat_named_t), 0);

	if (ksp == NULL) {
		e1000g_log(Adapter, CE_WARN,
		    "Could not create kernel statistics\n");
		return (DDI_FAILURE);
	}

	Adapter->e1000g_ksp = ksp;	/* Fill in the Adapters ksp */

	e1000g_ksp = (e1000gstat *) ksp->ks_data;

	/*
	 * Initialize all the statistics
	 */
	kstat_named_init(&e1000g_ksp->link_speed, "link_speed",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_none, "Rx No Data",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_error, "Rx Error",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_no_freepkt, "Rx Freelist Empty",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_avail_freepkt, "Rx Freelist Avail",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_esballoc_fail, "Rx Desballoc Failure",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_exceed_pkt, "Rx Exceed Max Pkt Count",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_multi_desc, "Rx Span Multi Desc",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_allocb_fail, "Rx Allocb Failure",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_seq_intr, "Rx Seq Err Intr",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_no_desc, "Tx No Desc",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_no_swpkt, "Tx No Buffer",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_lack_desc, "Tx Desc Insufficient",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_send_fail,
	    "Tx Send Failure", KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_multi_cookie,
	    "Tx Bind Multi Cookies", KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_over_size, "Tx Pkt Over Size",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_under_size, "Tx Pkt Under Size",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_copy, "Tx Send Copy",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_bind, "Tx Send Bind",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_multi_copy, "Tx Copy Multi Frags",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_reschedule, "Tx Reschedule",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_empty_frags, "Tx Empty Frags",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_exceed_frags, "Tx Exceed Max Frags",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_recycle,
	    "Tx Desc Recycle", KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_recycle_retry,
	    "Tx Desc Recycle Retry", KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_recycle_intr,
	    "Tx Desc Recycle Intr", KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_recycle_none,
	    "Tx Desc Recycled None", KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->StallWatchdog,
	    "Tx Stall Watchdog", KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->reset_count,
	    "Reset Count", KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->intr_type,
	    "Interrupt Type", KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Mpc, "Recv_Missed_Packets",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Symerrs, "Recv_Symbol_Errors",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Rlec, "Recv_Length_Errors",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Xonrxc, "XONs_Recvd",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Xontxc, "XONs_Xmitd",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Xoffrxc, "XOFFs_Recvd",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Xofftxc, "XOFFs_Xmitd",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Fcruc, "Recv_Unsupport_FC_Pkts",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Prc64, "Pkts_Recvd_(  64b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Prc127, "Pkts_Recvd_(  65- 127b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Prc255, "Pkts_Recvd_( 127- 255b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Prc511, "Pkts_Recvd_( 256- 511b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Prc1023, "Pkts_Recvd_( 511-1023b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Prc1522, "Pkts_Recvd_(1024-1522b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Gprc, "Good_Pkts_Recvd",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Gptc, "Good_Pkts_Xmitd",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Gorl, "Good_Octets_Recvd_Lo",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Gorh, "Good_Octets_Recvd_Hi",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Gotl, "Good_Octets_Xmitd_Lo",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Goth, "Good_Octets_Xmitd_Hi",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Ruc, "Recv_Undersize",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Rfc, "Recv_Frag",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Roc, "Recv_Oversize",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Rjc, "Recv_Jabber",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Torl, "Total_Octets_Recvd_Lo",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Torh, "Total_Octets_Recvd_Hi",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Totl, "Total_Octets_Xmitd_Lo",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Toth, "Total_Octets_Xmitd_Hi",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Tpr, "Total_Packets_Recvd",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Tpt, "Total_Packets_Xmitd",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Ptc64, "Pkts_Xmitd_(  64b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Ptc127, "Pkts_Xmitd_(  65- 127b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Ptc255, "Pkts_Xmitd_( 128- 255b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Ptc511, "Pkts_Xmitd_( 255- 511b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Ptc1023, "Pkts_Xmitd_( 512-1023b)",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Ptc1522, "Pkts_Xmitd_(1024-1522b)",
	    KSTAT_DATA_ULONG);

	/*
	 * Livengood Initializations
	 */
	kstat_named_init(&e1000g_ksp->Tncrs, "Xmit_with_No_CRS",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Tsctc, "Xmit_TCP_Seg_Contexts",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Tsctfc, "Xmit_TCP_Seg_Contexts_Fail",
	    KSTAT_DATA_ULONG);

	/*
	 * Jumbo Frame Counters
	 */
	kstat_named_init(&e1000g_ksp->JumboTx_4K, "Jumbo Tx Frame  4K",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->JumboRx_4K, "Jumbo Rx Frame  4K",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->JumboTx_8K, "Jumbo Tx Frame  8K",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->JumboRx_8K, "Jumbo Rx Frame  8K",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->JumboTx_16K, "Jumbo Tx Frame 16K",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->JumboRx_16K, "Jumbo Rx Frame 16K",
	    KSTAT_DATA_ULONG);

	/*
	 * Function to provide kernel stat update on demand
	 */
	ksp->ks_update = UpdateStatsCounters;

	/*
	 * Pointer into provider's raw statistics
	 */
	ksp->ks_private = (void *)Adapter;

	/*
	 * Add kstat to systems kstat chain
	 */
	kstat_install(ksp);

	return (DDI_SUCCESS);
}
