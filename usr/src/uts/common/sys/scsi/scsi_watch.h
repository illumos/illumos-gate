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

#ifndef	_SYS_SCSI_SCSI_WATCH_H
#define	_SYS_SCSI_SCSI_WATCH_H

#ifdef	__cplusplus
extern "C" {
#endif

struct scsi_watch_result {
	struct scsi_status		*statusp;
	struct scsi_extended_sense	*sensep;
	uchar_t				actual_sense_length;
	uchar_t				mmc_data[8];
	struct scsi_pkt			*pkt;
};

/*
 * 120 seconds is a *very* reasonable amount of time for most slow devices
 */
#define	SCSI_WATCH_IO_TIME	120

/*
 * values to pass in "flags" arg for scsi_watch_request_terminate()
 */
#define	SCSI_WATCH_TERMINATE_WAIT	0x0
#define	SCSI_WATCH_TERMINATE_NOWAIT	0x1
#define	SCSI_WATCH_TERMINATE_ALL_WAIT	0x2

#define	SCSI_WATCH_TERMINATE_SUCCESS	0x0
#define	SCSI_WATCH_TERMINATE_FAIL	0x1

void	scsi_watch_init();
void	scsi_watch_fini();
opaque_t scsi_watch_request_submit(struct scsi_device *devp,
	    int interval, int sense_length,
	    int (*callback)(), caddr_t cb_arg);
opaque_t scsi_mmc_watch_request_submit(struct scsi_device *devp,
	    int interval, int sense_length,
	    int (*callback)(), caddr_t cb_arg);
int	scsi_watch_request_terminate(opaque_t token, int flags);
int	scsi_watch_get_ref_count(opaque_t token);
void	scsi_watch_resume(opaque_t token);
void	scsi_watch_suspend(opaque_t token);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_SCSI_WATCH_H */
