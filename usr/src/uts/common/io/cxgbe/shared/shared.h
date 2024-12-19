/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#ifndef __CXGBE_SHARED_H
#define	__CXGBE_SHARED_H

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "osdep.h"

#define	CH_ERR(sc, ...)		cxgb_printf(sc->dip, CE_WARN, ##__VA_ARGS__)
#define	CH_WARN(sc, ...)	cxgb_printf(sc->dip, CE_WARN, ##__VA_ARGS__)
#define	CH_WARN_RATELIMIT(sc, ...) cxgb_printf(sc->dip, CE_WARN, ##__VA_ARGS__)
#define	CH_ALERT(sc, ...)	cxgb_printf(sc->dip, CE_NOTE, ##__VA_ARGS__)
#define	CH_INFO(sc, ...)	cxgb_printf(sc->dip, CE_NOTE, ##__VA_ARGS__)

#define	CH_MSG(sc, level, category, fmt, ...)	do {} while (0)
#ifdef DEBUG
#define	CH_DBG(sc, category, fmt, ...)	\
	cxgb_printf(sc->dip, CE_NOTE, ##__VA_ARGS__)
#else
#define	CH_DBG(sc, category, fmt, ...)		do {} while (0)
#endif

extern int cxgb_printf(dev_info_t *dip, int level, char *f, ...);

/* Attach/detach logic used by cxgbe, calling into t4nex */
struct port_info;
extern int t4_cxgbe_attach(struct port_info *, dev_info_t *);
extern int t4_cxgbe_detach(struct port_info *);

#endif /* __CXGBE_SHARED_H */
