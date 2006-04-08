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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>

#ifdef DEBUG
/*
 * SCF driver trace flag
 */
ushort_t	scf_trace_exec = 1;	/* 1:trace exec,  0:Trace no exec */

ushort_t	scf_trace_flag = 0xff00;
/*
 * xxxx xxxx : scf_trace_flag
 * 1         : Error trace exec
 *  1        : Busy trace exec
 *   1       : Messege trace exec
 *    1      : RD register trace exec
 *      1    : WR register trace exec
 *       1   : Timer trace exec
 *        1  : Func out trace exec
 *         1 : Func in trace exec
 */

/*
 * SCF driver trace debug flag
 */
uint_t	scf_trace_msg_flag = 0x00000000;	/* trace massege flag */


/*
 * Function list
 */
void	scf_trace(ushort_t code, ushort_t line, uchar_t *info, ushort_t size);


/*
 * scf_trace()
 *
 * SCF Driver trace get processing.
 *
 *   0 +--------------+
 *     | sorce line   | trace get source line
 *   2 +--------------+
 *     | time         | trace get time (100ms)
 *   4 +--------------+
 *     | triger code  | trace triger code
 *   6 +--------------+
 *     | info size    | infomarion size
 *   8 +--------------+
 *     |              |
 *   A +              +
 *     |              |
 *   C +     info     +  infomarion
 *     |              |
 *   E +              +
 *     |              |
 *  10 +--------------+
 *
 */
void
scf_trace(ushort_t code, ushort_t line, uchar_t *info, ushort_t size)
{
	scf_trctbl_t		trace_wk;
	scf_trctbl_t		*trcp;
	uchar_t			*in_p;
	uchar_t			*out_p;
	clock_t			clock_val;
	int			ii;
	int			trcflag = 0;

	if ((scf_trace_exec) &&
		((code & scf_trace_flag) || (!(code & 0xFF00)))) {
		if (scf_comtbl.resource_flag & DID_MUTEX_TRC) {
			mutex_enter(&scf_comtbl.trc_mutex);
			trcflag = 1;
		}
	}

	if (!trcflag) {
		return;
	}

	trcp = (scf_trctbl_t *)&trace_wk.line;
	trcp->line = line;
	clock_val = ddi_get_lbolt();
	trcp->tmvl = (ushort_t)(drv_hztousec(clock_val) / 100000);
	trcp->code = code;
	trcp->size = size;
	for (ii = 0; ii < sizeof (trace_wk.info); ii++) {
		if (ii < size) {
			trcp->info[ii] = *(info+ii);
		} else {
			trcp->info[ii] = 0;
		}
	}

	if (trcflag) {
		in_p = (uchar_t *)trcp;
		out_p = (uchar_t *)scf_comtbl.trace_w;
		scf_comtbl.trace_w++;
		if (scf_comtbl.trace_w == scf_comtbl.trace_l) {
			scf_comtbl.trace_w = scf_comtbl.trace_f;
		}
		for (ii = 0; ii < 16; ii++, in_p++, out_p++) *out_p = *in_p;
		if (trcp->code & (TC_ERR | TC_ERRCD)) {
			in_p = (uchar_t *)trcp;
			out_p = (uchar_t *)scf_comtbl.err_trace_w;
			for (ii = 0; ii < 16; ii++, in_p++, out_p++)
				*out_p = *in_p;
			scf_comtbl.err_trace_w++;
			if (scf_comtbl.err_trace_w == scf_comtbl.err_trace_l) {
				scf_comtbl.err_trace_w = scf_comtbl.err_trace_f;
			}
		}
	}

	if (trcflag) {
		mutex_exit(&scf_comtbl.trc_mutex);
	}
}
#endif
