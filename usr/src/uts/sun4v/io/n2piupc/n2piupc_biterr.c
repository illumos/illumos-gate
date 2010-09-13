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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * "Virtual register" implementation for the bit error performance counters.
 * See n2piupc-biterr.h for a description of the registers.
 */

#include <sys/types.h>
#include "n2piupc_acc.h"
#include "n2piupc_tables.h"
#include "n2piupc.h"
#include "n2piupc_biterr.h"

/* The real register's Link Bit Error fields are 6 bits wide. */
#define	REAL_BE2_8_10_MASK	0x3full

typedef struct {
	uint64_t sw_biterr_events;
} n2piupc_sw_biterr_t;

/*
 * Per-instance initialization required by this module.  Returns an arg which
 * is opaque to the outside.
 */
int
n2piupc_biterr_attach(void **arg)
{
	*arg = kmem_zalloc(sizeof (n2piupc_sw_biterr_t), KM_SLEEP);
	return (DDI_SUCCESS);
}

/*
 * Per-instance cleanup.  Takes opaque arg delivered by n2piupc_biterr_attach.
 */
void
n2piupc_biterr_detach(void *arg)
{
	if (arg != NULL)
		kmem_free(arg, sizeof (n2piupc_sw_biterr_t));
}

/*
 * Exported write interface.  Takes same args as n2piupc_write.  Translates to
 * real register interfaces.
 */
int
n2piupc_biterr_write(n2piupc_t *n2piupc_p, int regid, uint64_t data_in)
{
	uint64_t dev_data;	/* Write this to the device. */
	cntr_handle_t handle = n2piupc_p->n2piupc_handle;
	n2piupc_sw_biterr_t *biterr_p = n2piupc_p->n2piupc_biterr_p;
	int rval = SUCCESS;

	switch (regid) {

	case SW_N2PIU_BITERR_SEL:
		/*
		 * Write out only the biterr enable to the device.
		 * Note: the entire register (which has events for PIC3 as well)
		 * will be saved in sw_biterr_events.
		 */
		dev_data = data_in & BTERR_CTR_ENABLE;
		break;

	case SW_N2PIU_BITERR_CLR:
		/* Write out existing enable bit ORed with the zero request.  */
		dev_data = (biterr_p->sw_biterr_events & BTERR_CTR_ENABLE) |
		    (data_in & BTERR_CTR_CLR);
		break;

	/*
	 * All other registers, including the virtual biterr counter registers
	 * which are read-only, are not legal.
	 */
	default:
		N2PIUPC_DBG1("n2piupc_biterr_write: regid %d is invalid\n",
		    regid);
		return (EIO);
	}

	/*
	 * Enable and clear requests go to counter 1.  Note that bits 62 and 63
	 * of the real counter 1 maps to same bits of the respective virtual
	 * clear and select registers.
	 */
	if (n2piupc_set_perfreg(handle, HVIO_N2PIU_PERFREG_BITERR_CNT1,
	    dev_data) != H_EOK) {
		rval = EIO;

	/*
	 * Extra handling for virtual select register:  Save all the data
	 * (events) for CNT2 as well as the overall biterr enable.
	 */
	} else if (regid == SW_N2PIU_BITERR_SEL) {
		N2PIUPC_DBG1(
		    "n2piupc_biterr_write: Saving 0x%lx to bterr_sel, "
		    "write 0x%lx to dev\n", data_in, dev_data);
		biterr_p->sw_biterr_events = data_in;
	}

	N2PIUPC_DBG2("n2piupc_biterr_write: eventsreg:0x%lx, status:%d\n",
	    biterr_p->sw_biterr_events, rval);
	return (rval);
}


/*
 * Exported read interface.  Takes same args as n2piupc_read.  Translates to
 * real register interfaces.
 */
int
n2piupc_biterr_read(n2piupc_t *n2piupc_p, int regid, uint64_t *data)
{
	uint64_t raw_data;
	uint64_t biterr_cnt2_events;
	n2piupc_sw_biterr_t *biterr_p = n2piupc_p->n2piupc_biterr_p;
	cntr_handle_t handle = n2piupc_p->n2piupc_handle;
	int rval = SUCCESS;

	N2PIUPC_DBG1("n2piupc_biterr_read enter: handle:0x%lx, regid:%d\n",
	    handle, regid);

	switch (regid) {
	case SW_N2PIU_BITERR_CNT1_DATA:
		/* Virtual counter 1 maps directly to its real equivalent. */
		if (n2piupc_get_perfreg(handle, HVIO_N2PIU_PERFREG_BITERR_CNT1,
		    &raw_data) != H_EOK) {
			rval = EIO;
		}
		break;

	case SW_N2PIU_BITERR_CNT2_DATA:

		biterr_cnt2_events = biterr_p->sw_biterr_events &
		    (BTERR_CTR_3_EVT_MASK << BTERR_CTR_3_EVT_OFF);

		/*
		 * Virtual counter 2 can return one lane of data at a time, or
		 * all lanes at once, depending on the event selected for it.
		 */
		N2PIUPC_DBG1("n2piupc_biterr_read: counter2 data, evt:%ld\n",
		    biterr_cnt2_events);

		/* No event selected, return 0 */
		if (biterr_cnt2_events == BTERR3_EVT_ENC_NONE) {
			*data = 0ull;
			break;

		}

		/* All other events require reading real register. */
		if (n2piupc_get_perfreg(handle, HVIO_N2PIU_PERFREG_BITERR_CNT2,
		    &raw_data) != H_EOK) {
			rval = EIO;
			break;
		}

		N2PIUPC_DBG1("n2piupc_read: n2piupc_get_perfreg: data:0x%lx\n",
		    raw_data);

		/*
		 * Note that biterr counter 2 supports the register which
		 * busstat calls PIC3.  This is why events are BTERR3_...
		 */

		switch (biterr_cnt2_events) {

		case BTERR3_EVT_ENC_ALL:
			/* Return the whole register if all lanes requested. */
			*data = raw_data;
			break;

		case BTERR3_EVT_ENC_LANE_0:
		case BTERR3_EVT_ENC_LANE_1:
		case BTERR3_EVT_ENC_LANE_2:
		case BTERR3_EVT_ENC_LANE_3:
		case BTERR3_EVT_ENC_LANE_4:
		case BTERR3_EVT_ENC_LANE_5:
		case BTERR3_EVT_ENC_LANE_6:
		case BTERR3_EVT_ENC_LANE_7:
			/*
			 * Return an individual lane.  Each lane is a 6 bit
			 * field with lsb lining up with byte lsbs.
			 */
			*data = raw_data >>
			    ((biterr_cnt2_events - BTERR3_EVT_ENC_LANE_0) * 8) &
			    REAL_BE2_8_10_MASK;
			N2PIUPC_DBG2(
			    "DATA: raw:0x%lx, >> (%ld * 8) & 0x%llx = 0x%lx\n",
			    raw_data,
			    (biterr_cnt2_events - BTERR3_EVT_ENC_LANE_0),
			    REAL_BE2_8_10_MASK, *data);
			break;

		default:
			cmn_err(CE_WARN,
			    "n2piupc: Invalid bterr PIC3 event: 0x%lx\n",
			    biterr_cnt2_events);
			rval = EINVAL;
			break;
		}
		break;

	case SW_N2PIU_BITERR_SEL:
		/*
		 * Return the virtual select register data.
		 * No need to read the device.
		 */
		N2PIUPC_DBG2("n2piupc_biterr_read: returning events: 0x%lx\n",
		    biterr_p->sw_biterr_events);
		*data = biterr_p->sw_biterr_events;
		break;

	default:
		N2PIUPC_DBG1("n2piupc_biterr_read: invalid regid: %d\n", regid);
		rval = EIO;
		break;
	}

	N2PIUPC_DBG1("n2piupc_read exit: data:0x%lx, status:%d\n", *data,
	    rval);

	return (rval);
}
