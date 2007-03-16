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
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* cspi.h */

#ifndef CHELSIO_CSPI_H
#define CHELSIO_CSPI_H

#include "common.h"

struct pecspi;

struct pecspi *t1_cspi_create(adapter_t *);
void t1_cspi_destroy(struct pecspi *);
int t1_cspi_init(struct pecspi *cspi);

int t1_cspi_intr_enable(struct pecspi *);
int t1_cspi_intr_disable(struct pecspi *);
int t1_cspi_intr_status_read(struct pecspi *, u32 *);

#endif
