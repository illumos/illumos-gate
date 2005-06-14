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

#ifndef	_TRANSPORT_H
#define	_TRANSPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scsi/impl/uscsi.h>
#include <sys/types.h>

#define	SENSE_KEY(rqbuf)	(rqbuf[2])	/* scsi error category */
#define	ASC(rqbuf)		(rqbuf[12])	/* additional sense code */
#define	ASCQ(rqbuf)		(rqbuf[13])	/* ASC qualifier */

#define	RQBUFLEN	32
extern char rqbuf[RQBUFLEN];
uchar_t uscsi_status, rqstatus, rqresid;

struct uscsi_cmd *get_uscsi_cmd(void);
int uscsi(int fd, struct uscsi_cmd *scmd);

#ifdef	__cplusplus
}
#endif

#endif /* _TRANSPORT_H */
