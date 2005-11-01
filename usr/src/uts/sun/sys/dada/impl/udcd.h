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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DADA_IMPL_UDCD_H
#define	_SYS_DADA_IMPL_UDCD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * definition for user dcd command  structure
 */

struct udcd_cmd {
	uchar_t	udcd_error_reg;	/* The error register value */
	uchar_t	udcd_status_reg; /* The status register */
	ushort_t	udcd_status;	/* The resulting status */
	ushort_t	udcd_timeout;	/* Timeout value for completion */
	int	udcd_flags;	/* Flags for specifying  read,write etc. */
	uint_t	udcd_resid;	/* This is the resid */
	uint_t	udcd_buflen;	/* Size of the io request */
	caddr_t	udcd_bufaddr;	/* Place to take the data or put the data in */
	struct  dcd_cmd *udcd_cmd; /* Command to be sent out */
	caddr_t	udcd_reserved;	/* reserved for future use */
	uint_t	version_no;	/* Version number for this struct */
};

#if defined(_SYSCALL32)
struct udcd_cmd32 {
	uchar_t   udcd_error_reg;	/* The error register value */
	uchar_t   udcd_status_reg; /* The status register */
	ushort_t  udcd_status;	/* The resulting status */
	ushort_t  udcd_timeout;	/* Timeout value for completion */
	int	  udcd_flags;	/* Flags for specifying  read,write etc. */
	uint_t    udcd_resid;	/* This is the resid */
	uint_t    udcd_buflen;	/* Size of the io request */
	caddr32_t udcd_bufaddr; /* Place to take the data or put the data in */
	caddr32_t udcd_cmd; /* Command to be sent out */
	caddr32_t udcd_reserved;	/* reserved for future use */
	uint_t    version_no;	/* Version number for this struct */
};

#define	udcd_cmd32toudcd_cmd(u32, ucmd)					\
	ucmd->udcd_error_reg	= u32->udcd_error_reg;			\
	ucmd->udcd_status_reg	= u32->udcd_status_reg;			\
	ucmd->udcd_status	= u32->udcd_status;			\
	ucmd->udcd_timeout	= u32->udcd_timeout;			\
	ucmd->udcd_flags	= u32->udcd_flags;			\
	ucmd->udcd_resid	= u32->udcd_resid;			\
	ucmd->udcd_buflen	= u32->udcd_buflen;			\
	ucmd->udcd_bufaddr	= (caddr_t)(uintptr_t)u32->udcd_bufaddr; \
	ucmd->udcd_cmd		= (struct  dcd_cmd *)(uintptr_t)u32->udcd_cmd; \
	ucmd->udcd_reserved	= (caddr_t)(uintptr_t)u32->udcd_reserved; \
	ucmd->version_no	= u32->version_no;

#define	udcd_cmdtoudcd_cmd32(ucmd, u32)					\
	u32->udcd_error_reg	= ucmd->udcd_error_reg;			\
	u32->udcd_status_reg	= ucmd->udcd_status_reg;		\
	u32->udcd_status	= ucmd->udcd_status;			\
	u32->udcd_timeout	= ucmd->udcd_timeout;			\
	u32->udcd_flags		= ucmd->udcd_flags;			\
	u32->udcd_resid		= ucmd->udcd_resid;			\
	u32->udcd_buflen	= ucmd->udcd_buflen;			\
	u32->udcd_bufaddr	= (caddr32_t)(uintptr_t)ucmd->udcd_bufaddr; \
	u32->udcd_cmd		= (caddr32_t)(uintptr_t)ucmd->udcd_cmd;	\
	u32->udcd_reserved	= (caddr32_t)(uintptr_t)ucmd->udcd_reserved; \
	u32->version_no		= ucmd->version_no;

#endif /* _SYSCALL32 */


/*
 * Flags for the Udcd_flags field
 */
#define	UDCD_WRITE	0x00000 /* Send data to device */
#define	UDCD_SILENT	0x00001	/* no error messages */
#define	UDCD_DIAGNOSE	0x00002 /* Fail of any error occurs */
#define	UDCD_ISOLATE	0x00004	/* isolate from normal command */
#define	UDCD_READ	0x00008	/* Read data from device */
#define	UDCD_NOINTR	0x00040 /*  No interrupts */
#define	UDCD_RESET	0x04000 /* Reset the target */


/*
 * User ATA io control command
 */
#define	UDCDIOC	(0x05 << 8)
#define	UDCDCMD	(UDCDIOC|201) /* User dcd command */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DADA_IMPL_UDCD_H */
