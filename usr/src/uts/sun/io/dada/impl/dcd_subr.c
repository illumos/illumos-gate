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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dada/dada.h>


/*
 * Utility DADA routines
 */


/*
 * Polling support routines
 */

extern uintptr_t	dcd_callback_id;


#ifdef NOT_NEEDED
static int	dcd_poll_busycnt = DCD_POLL_TIMEOUT;
#endif


/*
 * Common buffer for dcd_lod
 */

extern kmutex_t  dcd_log_mutex;
static char dcd_log_buffer[256];


#define	A_TO_TRAN(ap) 	(ap->a_hba_tran)
#define	P_TO_TRAN(pkt)	((pkt)->pkt_address.a_hba_tran)
#define	P_TO_ADDR(pkt)	(&((pkt)->pkt_address))


#ifdef NOT_NEEDED
int
dcd_poll(struct dcd_pkt *pkt)
{

	register	busy_count, rval = -1, savef;
	clock_t	savet;
	void	(*savec)();


	/*
	 * Save old flags
	 */
	savef = pkt->pkt_flags;
	savec = pkt->pkt_comp;
	savet = pkt->pkt_time;

	pkt->pkt_flags |= FLAG_NOINTR;


	/*
	 * Set the Pkt_comp to NULL
	 */

	pkt->pkt_comp = 0;

	/*
	 * Set the Pkt time for the polled command
	 */
	if (pkt->pkt_time == 0) {
		pkt->pkt_time = DCD_POLL_TIMEOUT;
	}


	/* Now transport the command */
	for (busy_count = 0; busy_count < dcd_poll_busycnt; busy_count++) {
		if (dcd_transport(pkt) != TRAN_ACCEPT) {
			break;
		}
		if (pkt->pkt_reason == CMD_INCOMPLETE && pkt->pkt_state == 0) {
			drv_usecwait(1000000);
		} else if (pkt->pkt_reason  != CMD_CMPLT) {
			break;
		} else if (((*pkt->pkt_scbp) & STATUS_ATA_MASK)
			    == STATUS_ATA_BUSY) {
			drv_usecwait(1000000);
		} else {
			rval = 0;
			break;
		}
	}

	pkt->pkt_flags = savef;
	pkt->pkt_comp = savec;
	pkt->pkt_time = savet;
	return (rval);
}
#endif


/*PRINTFLIKE4*/
void
dcd_log(dev_info_t *dev, char *label, uint_t level, const char *fmt, ...)
{

	auto char name[256];
	va_list	ap;
	int	log_only = 0;
	int	boot_only = 0;
	int	console_only = 0;


	mutex_enter(&dcd_log_mutex);


	if (dev) {

		if (level == CE_PANIC || level == CE_WARN) {
			(void) sprintf(name, "%s (%s%d):\n",
				ddi_pathname(dev, dcd_log_buffer), label,
				ddi_get_instance(dev));
		} else if (level == CE_NOTE ||
			level >= (uint_t)DCD_DEBUG) {
			(void) sprintf(name, "%s%d:", label,
						ddi_get_instance(dev));
		} else if (level == CE_CONT) {
			name[0] = '\0';
		}
	} else {
		(void) sprintf(name, "%s:", label);
	}


	va_start(ap, fmt);
	(void) vsprintf(dcd_log_buffer, fmt, ap);
	va_end(ap);


	switch (dcd_log_buffer[0]) {
	case '!':
		log_only = 1;
		break;
	case '?':
		boot_only = 1;
		break;
	case '^':
		console_only = 1;
		break;
	}

	switch (level) {

	case CE_NOTE:
		level = CE_CONT;
		/* FALLTHROUGH */
	case CE_CONT:
	case CE_WARN:
	case CE_PANIC:
		if (boot_only) {
			cmn_err(level, "?%s\t%s", name,
				&dcd_log_buffer[1]);
		} else if (console_only) {
			cmn_err(level, "^%s\t%s", name,
				&dcd_log_buffer[1]);
		} else if (log_only) {
			cmn_err(level, "!%s\t%s", name,
				&dcd_log_buffer[1]);
		} else {
			cmn_err(level, "%s\t%s", name,
				dcd_log_buffer);
		}
		break;
	case (uint_t)DCD_DEBUG:
	default:
		cmn_err(CE_CONT, "^DEBUG: %s\t%s\n", name,
				dcd_log_buffer);
		break;
	}

	mutex_exit(&dcd_log_mutex);
}
