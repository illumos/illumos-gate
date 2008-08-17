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

#ifndef	_SMBSRV_SMBFMT_H
#define	_SMBSRV_SMBFMT_H

#pragma ident	"@(#)smbfmt.h	1.2	08/07/30 SMI"

/*
 * SMB message header formats.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	SMB_HEADER_ED_FMT "Mbbbwbww8c2.wwww"
#define	SMB_HEADER_ED_LEN (4+1+1+1+2+1+2+12+2+2+2+2)
#define	SMB_TRANSHDR_ED_FMT "wwwwb.wl2.wwwwb."
#define	SMB_TRANSHDR_ED_LEN (2+2+2+2+1+1+2+4+2+2+2+2+2+1+1)
#define	SMB_TRANSSHDR_ED_FMT	"wwwwwwwww"
#define	SMB_TRANSSHDR_ED_LEN (2+2+2+2+2+2+2+2)
#define	SMB_TRANS2SHDR_ED_FMT	"wwwwwwwww"
#define	SMB_TRANS2SHDR_ED_LEN (2+2+2+2+2+2+2+2+2)
/* There is something wrong with this. Should be 38 bytes. It is 37 bytes */
#define	SMB_NT_TRANSHDR_ED_FMT	"b2.llllllllbw"
#define	SMB_NT_TRANSHDR_ED_LEN (1+2+4+4+4+4+4+4+4+4+1+2)

#ifdef	__cplusplus
}
#endif

#endif	/* _SMBSRV_SMBFMT_H */
