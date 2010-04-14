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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_DLD_IOC_H
#define	_SYS_DLD_IOC_H

#include <sys/types.h>
#include <sys/cred.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The name of the dld control device.  All GLDv3 control ioctls are
 * performed on this device.
 */
#define	DLD_CONTROL_DEV		"/dev/dld"

/*
 * GLDv3 ioctl values are structured as follows:
 *
 * |    16-bits     |     16-bits    |
 * +----------------+----------------+
 * |   module-id    |   command-id   |
 * +----------------+----------------+
 */
#define	DLD_IOC_CMD(modid, cmdid)	(((uint_t)(modid) << 16) | (cmdid))
#define	DLD_IOC_MODID(cmd)		(((cmd) & 0xffff0000) >> 16)
/*
 * GLDv3 module ids to be passed in as the first argument to
 * dld_ioc_register() and dld_ioc_unregister().
 */
#define	DLD_IOC		0x0D1D
#define	AGGR_IOC	0x0A66
#define	VNIC_IOC	0x0171
#define	SIMNET_IOC	0x5132
#define	IPTUN_IOC	0x454A
#define	BRIDGE_IOC	0xB81D
#define	IBPART_IOC	0x6171

/* GLDv3 modules use these macros to generate unique ioctl commands */
#define	DLDIOC(cmdid)		DLD_IOC_CMD(DLD_IOC, (cmdid))
#define	AGGRIOC(cmdid)		DLD_IOC_CMD(AGGR_IOC, (cmdid))
#define	VNICIOC(cmdid)		DLD_IOC_CMD(VNIC_IOC, (cmdid))
#define	SIMNETIOC(cmdid)	DLD_IOC_CMD(SIMNET_IOC, (cmdid))
#define	IPTUNIOC(cmdid)		DLD_IOC_CMD(IPTUN_IOC, (cmdid))
#define	BRIDGEIOC(cmdid)	DLD_IOC_CMD(BRIDGE_IOC, (cmdid))
#define	IBPARTIOC(cmdid)	DLD_IOC_CMD(IBPART_IOC, (cmdid))

#ifdef _KERNEL

/*
 * GLDv3 modules register the ioctls they're interested in by passing
 * in an array of dld_ioc_info_t to dld_ioc_register().  Modules
 * should call dld_ioc_register() either in _init() or attach().  The
 * dld module assumes that ddi_hold_devi_by_instance(<module>, 0, 0)
 * will cause the module to load and call dld_ioc_register().
 *
 * The di_cmd field is an ioctl command generated using one of the
 * macros above.  The di_argsize value is used by dld to copyin or
 * copyout the correct amount of data depending on whether the
 * DLDCOPYIN or DLDCOPYOUT flags are set so that every di_func()
 * callback function does not need to copyin/out its own data.
 */

typedef int (dld_ioc_func_t)(void *, intptr_t, int, cred_t *, int *);
typedef int (dld_ioc_priv_func_t)(const cred_t *);
typedef struct dld_ioc_info {
	uint_t		di_cmd;
	uint_t		di_flags;
	size_t		di_argsize;
	dld_ioc_func_t	*di_func;
	dld_ioc_priv_func_t *di_priv_func;
} dld_ioc_info_t;

/* Values for di_flags */
#define	DLDCOPYIN	0x00000001 /* copyin di_argsize amount of data */
#define	DLDCOPYOUT	0x00000002 /* copyout di_argsize amount of data */
#define	DLDCOPYINOUT	(DLDCOPYIN | DLDCOPYOUT)

#define	DLDIOCCNT(l)	(sizeof (l) / sizeof (dld_ioc_info_t))
int	dld_ioc_register(uint16_t, dld_ioc_info_t *, uint_t);
void	dld_ioc_unregister(uint16_t);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLD_IOC_H */
