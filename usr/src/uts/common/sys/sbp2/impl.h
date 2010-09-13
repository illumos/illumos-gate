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

#ifndef	_SYS_SBP2_IMPL_H
#define	_SYS_SBP2_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Serial Bus Protocol 2 (SBP-2) implementation
 */

#include <sys/sbp2/common.h>
#include <sys/sbp2/bus.h>
#include <sys/sbp2/driver.h>
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Config ROM parser internal structure */
typedef struct sbp2_cfgrom_parse_arg {
	sbp2_cfgrom_ent_t	*pa_dir;	/* directory to parse */
	sbp2_cfgrom_ent_t	*pa_pdir;	/* parent directory */
	sbp2_cfgrom_ent_t	*pa_ref;	/* referred entry */
	int			pa_depth;	/* current depth */
} sbp2_cfgrom_parse_arg_t;

typedef struct sbp2_cfgrom_ent_by_key {
	uint8_t			kt;
	uint8_t			kv;
	int			num;
	sbp2_cfgrom_ent_t	*ent;
	int			cnt;
} sbp2_cfgrom_ent_by_key_t;

_NOTE(SCHEME_PROTECTS_DATA("unique per call", { sbp2_cfgrom_ent_by_key
    sbp2_cfgrom_parse_arg }))

enum {
	SBP2_CFGROM_MAX_DEPTH	= 5,	/* max directory depth */
	SBP2_CFGROM_GROW_INCR	= 4,	/* entry array growth increment */

	SBP2_MOT_MIN		= 500,	/* minimum mgt ORB timeout, in ms */
	SBP2_MOT_DFLT		= 2000,	/* default mgt ORB timeout, in ms */
	SBP2_ORB_SIZE_MIN	= 4,	/* minimum ORB size, in bytes */
	SBP2_ORB_SIZE_DFLT	= 32	/* default ORB size, in bytes */
};

/* busops macros */
#define	SBP2_CSR_BASE(t)	t->t_bus->sb_csr_base
#define	SBP2_CFGROM_ADDR(t)	t->t_bus->sb_cfgrom_addr
#define	SBP2_GET_IBLOCK_COOKIE(t) \
	(t)->t_bus->sb_get_iblock_cookie((t)->t_bus_hdl)
#define	SBP2_GET_NODE_ID(t)	(t)->t_bus->sb_get_node_id((t)->t_bus_hdl)
#define	SBP2_ALLOC_BUF(t, buf)	(t)->t_bus->sb_alloc_buf((t)->t_bus_hdl, buf)
#define	SBP2_FREE_BUF(t, buf)	(t)->t_bus->sb_free_buf((t)->t_bus_hdl, buf)
#define	SBP2_SYNC_BUF(t, buf, offset, length, type) \
	(t)->t_bus->sb_sync_buf((t)->t_bus_hdl, buf, offset, length, type)
#define	SBP2_BUF_RD_DONE(t, buf, reqh, error) \
	(t)->t_bus->sb_buf_rd_done((t)->t_bus_hdl, buf, reqh, error)
#define	SBP2_BUF_WR_DONE(t, buf, reqh, error) \
	(t)->t_bus->sb_buf_wr_done((t)->t_bus_hdl, buf, reqh, error)
#define	SBP2_ALLOC_CMD(t, cmdp, f) \
	(t)->t_bus->sb_alloc_cmd((t)->t_bus_hdl, cmdp, f)
#define	SBP2_FREE_CMD(t, cmd) \
	(t)->t_bus->sb_free_cmd((t)->t_bus_hdl, cmd)
#define	SBP2_RQ(t, cmd, addr, q, berr) \
	(t)->t_bus->sb_rq((t)->t_bus_hdl, cmd, addr, q, berr)
#define	SBP2_RB(t, cmd, addr, bp, len, berr) \
	(t)->t_bus->sb_rb((t)->t_bus_hdl, cmd, addr, bp, len, berr)
#define	SBP2_WQ(t, cmd, addr, q, berr) \
	(t)->t_bus->sb_wq((t)->t_bus_hdl, cmd, addr, q, berr)
#define	SBP2_WB(t, cmd, addr, bp, len, berr) \
	(t)->t_bus->sb_wb((t)->t_bus_hdl, cmd, addr, bp, len, berr)

int	sbp2_cfgrom_parse(sbp2_tgt_t *, sbp2_cfgrom_t *);
void	sbp2_cfgrom_free(sbp2_tgt_t *, sbp2_cfgrom_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBP2_IMPL_H */
