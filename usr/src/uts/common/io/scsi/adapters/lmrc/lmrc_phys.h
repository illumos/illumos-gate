/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Racktop Systems, Inc.
 */

#ifndef _LMRC_PHYS_H
#define	_LMRC_PHYS_H

#include <sys/types.h>
#include <sys/debug.h>

#include <sys/scsi/adapters/mfi/mfi_evt.h>

#include "lmrc.h"
#include "lmrc_raid.h"

int lmrc_setup_pdmap(lmrc_t *);
void lmrc_free_pdmap(lmrc_t *);

boolean_t lmrc_pd_tm_capable(lmrc_t *, uint16_t);

int lmrc_get_pd_list(lmrc_t *);

int lmrc_phys_attach(dev_info_t *);
int lmrc_phys_detach(dev_info_t *);

int lmrc_phys_aen_handler(lmrc_t *, mfi_evt_detail_t *);

#endif /* _LMRC_PHYS_H */
