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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SGFRU_PRIV_H
#define	_SGFRU_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sgfru.h>
#include <sys/conf.h>
#include <sys/ddi_impldefs.h>

#define	SGFRU_DRV_NAME		"sgfru"

#ifdef DEBUG
extern uint_t sgfru_debug;

#define	SGFRU_DBG_STATE		0x00000001
#define	SGFRU_DBG_HANDLE	0x00000002
#define	SGFRU_DBG_NODE		0x00000004
#define	SGFRU_DBG_SECTION	0x00000008
#define	SGFRU_DBG_SEGMENT	0x00000010
#define	SGFRU_DBG_PACKET	0x00000020
#define	SGFRU_DBG_PAYLOAD	0x00000040
#define	SGFRU_DBG_MBOX		0x00000080
#define	SGFRU_DBG_ALL		0x000000FF

#define	PR_ALL		if (sgfru_debug)			printf
#define	PR_STATE	if (sgfru_debug & SGFRU_DBG_STATE)	printf
#define	PR_HANDLE	if (sgfru_debug & SGFRU_DBG_HANDLE)	printf
#define	PR_NODE		if (sgfru_debug & SGFRU_DBG_NODE)	printf
#define	PR_SECTION	if (sgfru_debug & SGFRU_DBG_SECTION)	printf
#define	PR_SEGMENT	if (sgfru_debug & SGFRU_DBG_SEGMENT)	printf
#define	PR_PACKET	if (sgfru_debug & SGFRU_DBG_PACKET)	printf
#define	PR_PAYLOAD	if (sgfru_debug & SGFRU_DBG_PAYLOAD)	printf
#define	PR_MBOX		if (sgfru_debug & SGFRU_DBG_MBOX)	printf
#else /* DEBUG */
#define	PR_ALL		if (0) printf
#define	PR_STATE	PR_ALL
#define	PR_HANDLE	PR_ALL
#define	PR_NODE		PR_ALL
#define	PR_SECTION	PR_ALL
#define	PR_SEGMENT	PR_ALL
#define	PR_PACKET	PR_ALL
#define	PR_PAYLOAD	PR_ALL
#define	PR_MBOX		PR_ALL
#endif /* DEBUG */

#define	MAX_HANDLES		100
#define	MAX_SECTIONS		8
#define	MAX_SEGMENTS		200
#define	MAX_PACKETS		200
#define	MAX_PAYLOADSIZE		0x1000	/* No support for Tag Type G 2**48 */
#define	MAX_SEGMENTSIZE		0x10000	/* New SEEPROM size likely to be 64k */

typedef struct sgfru_soft_state {
	dev_info_t *fru_dip;		/* devinfo structure */
	dev_info_t *fru_pdip;		/* parent's devinfo structure */
	int instance;
} sgfru_soft_state_t;

typedef struct {
	dev_t dev;
	int cmd;
	int mode;
	intptr_t argp;
} sgfru_init_arg_t;

/*
 * Prototypes
 */
static int sgfru_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int sgfru_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int sgfru_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
static int sgfru_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int sgfru_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p);

/*
 * functions local to this driver.
 */
static int sgfru_getchildlist(const sgfru_init_arg_t *iargp);
static int sgfru_getchildhandles(const sgfru_init_arg_t *iargp);
static int sgfru_getnodeinfo(const sgfru_init_arg_t *iargp);
static int sgfru_getsections(const sgfru_init_arg_t *iargp);
static int sgfru_getsegments(const sgfru_init_arg_t *iargp);
static int sgfru_addsegment(const sgfru_init_arg_t *iargp);
static int sgfru_readsegment(const sgfru_init_arg_t *iargp);
static int sgfru_writesegment(const sgfru_init_arg_t *iargp);
static int sgfru_getpackets(const sgfru_init_arg_t *iargp);
static int sgfru_appendpacket(const sgfru_init_arg_t *iargp);
static int sgfru_getpayload(const sgfru_init_arg_t *iargp);
static int sgfru_updatepayload(const sgfru_init_arg_t *iargp);
static int sgfru_getnum(const sgfru_init_arg_t *iargp);
static int sgfru_delete(const sgfru_init_arg_t *iargp);

static int sgfru_copyin_frup(const sgfru_init_arg_t *argp, frup_info_t *frup);
static int sgfru_copyin_fru(const sgfru_init_arg_t *argp, fru_info_t *fru);
static int sgfru_copyin_segment(const sgfru_init_arg_t *argp,
    const frup_info_t *frup, segment_t *segp);
static int sgfru_copyin_append(const sgfru_init_arg_t *argp,
    append_info_t *app);
static int sgfru_copyin_buffer(const sgfru_init_arg_t *argp,
    const caddr_t data, const int cnt, char *buffer);

static int sgfru_copyout_fru(const sgfru_init_arg_t *argp,
    const fru_info_t *fru);
static int sgfru_copyout_handle(const sgfru_init_arg_t *argp,
    const void *addr, const fru_hdl_t *hdlp);
static int sgfru_copyout_handles(const sgfru_init_arg_t *argp,
    const frup_info_t *frup, const fru_hdl_t *hdlp);
static int sgfru_copyout_nodes(const sgfru_init_arg_t *argp,
    const frup_info_t *frup, const node_t *nodep);
static int sgfru_copyout_sections(const sgfru_init_arg_t *argp,
    const frup_info_t *frup, const section_t *sectp);
static int sgfru_copyout_segments(const sgfru_init_arg_t *argp,
    const frup_info_t *frup, const segment_t *segp);
static int sgfru_copyout_packets(const sgfru_init_arg_t *argp,
    const frup_info_t *frup, const packet_t *packp);
static int sgfru_copyout_buffer(const sgfru_init_arg_t *argp,
    const frup_info_t *frup, const char *buffer);

#ifdef	__cplusplus
}
#endif

#endif	/* _SGFRU_PRIV_H */
