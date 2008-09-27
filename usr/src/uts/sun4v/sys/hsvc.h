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

#ifndef _SYS_HSVC_H
#define	_SYS_HSVC_H

/*
 * Niagara services information
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Hypervisor service groups
 */
#define	HSVC_GROUP_SUN4V		0x0000
#define	HSVC_GROUP_CORE			0x0001
#define	HSVC_GROUP_INTR			0x0002
#define	HSVC_GROUP_SOFT_STATE		0x0003
#define	HSVC_GROUP_MEM_IFLUSH		0x0010
#define	HSVC_GROUP_TM			0x0080
#define	HSVC_GROUP_VPCI			0x0100
#define	HSVC_GROUP_LDC			0x0101
#define	HSVC_GROUP_VSC			0x0102
#define	HSVC_GROUP_NCS			0x0103
#define	HSVC_GROUP_RNG			0x0104
#define	HSVC_GROUP_NIAGARA_CPU		0x0200
#define	HSVC_GROUP_FIRE_PERF		0x0201
#define	HSVC_GROUP_NIAGARA2_CPU		0x0202
#define	HSVC_GROUP_NIU			0x0204
#define	HSVC_GROUP_VFALLS_CPU		0x0205
#define	HSVC_GROUP_RKPERF		0x0206
#define	HSVC_GROUP_DIAG			0x0300

#ifndef _ASM

#include <sys/types.h>

/*
 * Hypervisor service negotiation data strcture
 */
struct hsvc_info {
	int		hsvc_rev;	/* data structure revision number */
	void		*hsvc_private;	/* reserved for the framework */
	uint64_t	hsvc_group;	/* hypervisor API group */
	uint64_t	hsvc_major;	/* API group major number */
	uint64_t	hsvc_minor;	/* API group minor number */
	char		*hsvc_modname;	/* module name */
};

typedef struct hsvc_info hsvc_info_t;

/*
 * hsvc_rev field
 */
#define	HSVC_REV_1		1

extern	int	hsvc_kdi_mem_iflush_negotiated;

/*
 * External interface
 */
extern int hsvc_register(hsvc_info_t *hsvcreq, uint64_t *supported_minor);
extern int hsvc_unregister(hsvc_info_t *hsvcreq);
extern int hsvc_version(uint64_t hsvc_group, uint64_t *major, uint64_t *minor);

#endif /* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_HSVC_H */
