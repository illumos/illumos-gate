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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_VSCAN_H
#define	_VSCAN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/param.h>
#include <sys/vnode.h>

/*
 * vscan.h provides definitions for vscan kernel module
 */

#define	VS_DRV_MAX_FILES	1024	/* max concurent file scans */
#define	VS_DRV_PATH		"/devices/pseudo/vscan@0:vscan"
#define	VS_DRV_IOCTL_ENABLE	0x0001	/* door rendezvous */
#define	VS_DRV_IOCTL_DISABLE	0x0002	/* vscand shutting down */
#define	VS_DRV_IOCTL_CONFIG	0x0004	/* vscand config data update */

/* vsr_access */
#define	VS_ACCESS_UNDEFINED	0
#define	VS_ACCESS_ALLOW		1
#define	VS_ACCESS_DENY		2

#define	VS_TYPES_LEN		4096	/* vs_config_t - types buffer */

/*
 * AV_SCANSTAMP_SZ is the size of the scanstamp stored in the
 * filesystem. vs_scanstamp_t is 1 character longer to allow
 * a null terminated string to be used within vscan
 */
typedef char vs_scanstamp_t[AV_SCANSTAMP_SZ + 1];

/* used for both request to and response from vscand */
typedef struct vs_scan_req {
	uint32_t vsr_id;
	uint32_t vsr_flags;
	uint64_t vsr_size;
	uint8_t vsr_modified;
	uint8_t vsr_quarantined;
	char vsr_path[MAXPATHLEN];
	vs_scanstamp_t vsr_scanstamp;
	uint32_t vsr_access; /* VS_ACCESS_ALLOW, VS_ACCESS_DENY */
} vs_scan_req_t;


/* passed in VS_DRV_IOCTL_CONFIG */
typedef struct vs_config {
	char vsc_types[VS_TYPES_LEN];
	uint64_t vsc_types_len;
	uint64_t vsc_max_size;	/* files > max size (bytes) not scan */
	uint64_t vsc_allow;	/* allow access to file exceeding max_size? */
} vs_config_t;


#ifdef _KERNEL

/*
 * max no of types in vs_config_t.vsc_types
 * used as dimention for array of pointers to types
 */
#define	VS_TYPES_MAX		VS_TYPES_LEN / 2

int vscan_svc_init(void);
void vscan_svc_fini(void);
void vscan_svc_enable(boolean_t);
int vscan_svc_configure(vs_config_t *);
boolean_t vscan_svc_in_use(void);
vnode_t *vscan_svc_get_vnode(int);

int vscan_door_init(void);
void vscan_door_fini(void);
int vscan_door_open(int);
void vscan_door_close(void);
int vscan_door_scan_file(vs_scan_req_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif


#endif /* _VSCAN_H */
