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
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _DISK_DRIVERS_H
#define	_DISK_DRIVERS_H

#include <fm/topo_mod.h>
#include <libdevinfo.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MPTSAS_DRV	"mpt_sas"
#define	NVME_DRV	"nvme"

int disk_mptsas_find_disk(topo_mod_t *, tnode_t *, char **);
int disk_nvme_enum_disk(topo_mod_t *, tnode_t *);

#ifdef __cplusplus
}
#endif

#endif /* _DISK_DRIVERS_H */
