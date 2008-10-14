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

#ifndef _SD_BIO_H
#define	_SD_BIO_H

#ifdef	__cplusplus
extern "C" {
#endif

extern int _sdbc_iobuf_load(void);
extern void _sdbc_iobuf_unload(void);
extern int _sdbc_iobuf_configure(int);
extern void _sdbc_iobuf_deconfigure(void);
extern int _sd_pending_iobuf(void);
extern struct buf *sd_alloc_iob(dev_t, nsc_off_t, int, int);
extern void sd_add_fba(struct buf *, sd_addr_t *, nsc_off_t, nsc_size_t);
extern void sd_add_mem(struct buf *, char *, nsc_size_t);
extern int sd_start_io(struct buf *, strategy_fn_t, sdbc_ea_fn_t, blind_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SD_BIO_H */
