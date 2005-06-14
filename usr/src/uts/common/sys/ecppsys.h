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
 * Copyright (c) 1990-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_ECPPSYS_H
#define	_SYS_ECPPSYS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	ECPPIOC_SETPARMS	_IOW('p', 70, struct ecpp_transfer_parms)
#define	ECPPIOC_GETPARMS	_IOR('p', 71, struct ecpp_transfer_parms)
#define	ECPPIOC_GETDEVID	_IOWR('p', 73, struct ecpp_device_id)

/* current_mode values */
#define	ECPP_CENTRONICS 	0x01 /* non-1284 */
#define	ECPP_COMPAT_MODE	0x02
#define	ECPP_BYTE_MODE		0x03
#define	ECPP_NIBBLE_MODE	0x04
#define	ECPP_ECP_MODE		0x05
#define	ECPP_FAILURE_MODE	0x06
#define	ECPP_DIAG_MODE		0x07
#define	ECPP_INIT_MODE		0x08
#define	ECPP_EPP_MODE		0x09

typedef struct p1284_ioctl_st {
	int array[10];
	char *cptr;
	char *name;
} P1284Ioctl;

struct ecpp_transfer_parms {
	int	write_timeout;
	int	mode;
};

/*
 * Structure for retrieving IEEE 1284 Device ID
 */
struct ecpp_device_id {
	int	mode;	/* mode to use for reading device id */
	int	len;	/* length of buffer */
	int	rlen;	/* actual length of device id string */
	char	*addr;	/* buffer address */
#ifndef _LP64
	int	filler[2];
#endif
};

#ifdef _KERNEL
/*
 * 32bit support for ioctl
 */
struct ecpp_device_id32 {
	int		mode;   /* mode to use for reading device id */
	int		len;    /* length of buffer */
	int		rlen;   /* actual length of device id string */
	caddr32_t	addr;   /* buffer address */
	int		filler[2];
};
#endif /* _KERNEL */
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ECPPSYS_H */
