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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Defines for user SCSI commands					*
 */

#ifndef _SYS_SCSI_IMPL_USCSI_H
#define	_SYS_SCSI_IMPL_USCSI_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * definition for user-scsi command structure
 */
struct uscsi_cmd {
	int		uscsi_flags;	/* read, write, etc. see below */
	short		uscsi_status;	/* resulting status  */
	short		uscsi_timeout;	/* Command Timeout */
	caddr_t		uscsi_cdb;	/* cdb to send to target */
	caddr_t		uscsi_bufaddr;	/* i/o source/destination */
	size_t		uscsi_buflen;	/* size of i/o to take place */
	size_t		uscsi_resid;	/* resid from i/o operation */
	uchar_t		uscsi_cdblen;	/* # of valid cdb bytes */
	uchar_t		uscsi_rqlen;	/* size of uscsi_rqbuf */
	uchar_t		uscsi_rqstatus;	/* status of request sense cmd */
	uchar_t		uscsi_rqresid;	/* resid of request sense cmd */
	caddr_t		uscsi_rqbuf;	/* request sense buffer */
	ulong_t		uscsi_path_instance; /* private: hardware path */
};

#if defined(_SYSCALL32)
struct uscsi_cmd32 {
	int		uscsi_flags;	/* read, write, etc. see below */
	short		uscsi_status;	/* resulting status  */
	short		uscsi_timeout;	/* Command Timeout */
	caddr32_t	uscsi_cdb;	/* cdb to send to target */
	caddr32_t	uscsi_bufaddr;	/* i/o source/destination */
	size32_t	uscsi_buflen;	/* size of i/o to take place */
	size32_t	uscsi_resid;	/* resid from i/o operation */
	uchar_t		uscsi_cdblen;	/* # of valid cdb bytes */
	uchar_t		uscsi_rqlen;	/* size of uscsi_rqbuf */
	uchar_t		uscsi_rqstatus;	/* status of request sense cmd */
	uchar_t		uscsi_rqresid;	/* resid of request sense cmd */
	caddr32_t	uscsi_rqbuf;	/* request sense buffer */
	uint32_t	uscsi_path_instance; /* private: hardware path */
};

#define	uscsi_cmd32touscsi_cmd(u32, ucmd)				\
	ucmd->uscsi_flags	= u32->uscsi_flags;			\
	ucmd->uscsi_status	= u32->uscsi_status;			\
	ucmd->uscsi_timeout	= u32->uscsi_timeout;			\
	ucmd->uscsi_cdb		= (caddr_t)(uintptr_t)u32->uscsi_cdb;	\
	ucmd->uscsi_bufaddr	= (caddr_t)(uintptr_t)u32->uscsi_bufaddr; \
	ucmd->uscsi_buflen	= (size_t)u32->uscsi_buflen;		\
	ucmd->uscsi_resid	= (size_t)u32->uscsi_resid;		\
	ucmd->uscsi_cdblen	= u32->uscsi_cdblen;			\
	ucmd->uscsi_rqlen	= u32->uscsi_rqlen;			\
	ucmd->uscsi_rqstatus	= u32->uscsi_rqstatus;			\
	ucmd->uscsi_rqresid	= u32->uscsi_rqresid;			\
	ucmd->uscsi_rqbuf	= (caddr_t)(uintptr_t)u32->uscsi_rqbuf;	\
	ucmd->uscsi_path_instance = (ulong_t)u32->uscsi_path_instance;


#define	uscsi_cmdtouscsi_cmd32(ucmd, u32)				\
	u32->uscsi_flags	= ucmd->uscsi_flags;			\
	u32->uscsi_status	= ucmd->uscsi_status;			\
	u32->uscsi_timeout	= ucmd->uscsi_timeout;			\
	u32->uscsi_cdb		= (caddr32_t)(uintptr_t)ucmd->uscsi_cdb;  \
	u32->uscsi_bufaddr	= (caddr32_t)(uintptr_t)ucmd->uscsi_bufaddr; \
	u32->uscsi_buflen	= (size32_t)ucmd->uscsi_buflen;		\
	u32->uscsi_resid	= (size32_t)ucmd->uscsi_resid;		\
	u32->uscsi_cdblen	= ucmd->uscsi_cdblen;			\
	u32->uscsi_rqlen	= ucmd->uscsi_rqlen;			\
	u32->uscsi_rqstatus	= ucmd->uscsi_rqstatus;			\
	u32->uscsi_rqresid	= ucmd->uscsi_rqresid;			\
	u32->uscsi_rqbuf	= (caddr32_t)(uintptr_t)ucmd->uscsi_rqbuf; \
	u32->uscsi_path_instance = (uint32_t)ucmd->uscsi_path_instance;

#endif /* _SYSCALL32 */


/*
 * flags for uscsi_flags field
 */
/*
 * generic flags
 */
#define	USCSI_SILENT	0x00000001	/* no error messages */
#define	USCSI_DIAGNOSE	0x00000002	/* fail if any error occurs */
#define	USCSI_ISOLATE	0x00000004	/* isolate from normal commands */
#define	USCSI_READ	0x00000008	/* get data from device */
#define	USCSI_WRITE	0x00000000	/* send data to device */

#define	USCSI_RESET	0x00004000	/* Reset target */
#define	USCSI_RESET_TARGET	\
			USCSI_RESET	/* Reset target */
#define	USCSI_RESET_ALL	0x00008000	/* Reset all targets */
#define	USCSI_RQENABLE	0x00010000	/* Enable Request Sense extensions */
#define	USCSI_RENEGOT	0x00020000	/* renegotiate wide/sync on next I/O */
#define	USCSI_RESET_LUN	0x00040000	/* Reset logical unit */
#define	USCSI_PATH_INSTANCE	\
			0x00080000	/* use path instance for transport */

/*
 * suitable for parallel SCSI bus only
 */
#define	USCSI_ASYNC	0x00001000	/* Set bus to asynchronous mode */
#define	USCSI_SYNC	0x00002000	/* Set bus to sync mode if possible */

/*
 * the following flags should not be used at user level but may
 * be used by a scsi target driver for internal commands
 */
/*
 * generic flags
 */
#define	USCSI_NOINTR	0x00000040	/* No interrupts, NEVER use this flag */
#define	USCSI_NOTAG	0x00000100	/* Disable tagged queueing */
#define	USCSI_OTAG	0x00000200	/* ORDERED QUEUE tagged cmd */
#define	USCSI_HTAG	0x00000400	/* HEAD OF QUEUE tagged cmd */
#define	USCSI_HEAD	0x00000800	/* Head of HA queue */

/*
 * suitable for parallel SCSI bus only
 */
#define	USCSI_NOPARITY	0x00000010	/* run command without parity */
#define	USCSI_NODISCON	0x00000020	/* run command without disconnects */

/*
 * suitable for FMA module for PM purpose
 */
#define	USCSI_PMFAILFAST	0x00100000	/* fail command if device is */
						/* in low power */


#define	USCSI_RESERVED	0xffe00000	/* Reserved Bits, must be zero */

struct uscsi_rqs {
	int		rqs_flags;	/* see below */
	ushort_t	rqs_buflen;	/* maximum number or bytes to return */
	ushort_t	rqs_resid;	/* untransferred length of RQS data */
	caddr_t		rqs_bufaddr;	/* request sense buffer */
};

#if defined(_SYSCALL32)
struct uscsi_rqs32	{
	int		rqs_flags;	/* see below */
	ushort_t	rqs_buflen;	/* maximum number or bytes to return */
	ushort_t	rqs_resid;	/* untransferred length of RQS data */
	caddr32_t	rqs_bufaddr;	/* request sense buffer */
};
#endif /* _SYSCALL32 */


/*
 * uscsi_rqs flags
 */

#define	RQS_OVR		0x01	/* RQS data has been overwritten */
#define	RQS_VALID	0x02	/* RQS data is valid */

/*
 * User SCSI io control command
 */
#define	USCSIIOC	(0x04 << 8)
#define	USCSICMD	(USCSIIOC|201) 	/* user scsi command */

#ifdef	_KERNEL

#include <sys/scsi/scsi_types.h>

struct uscsi_cmd *scsi_uscsi_alloc();
int	scsi_uscsi_copyin(intptr_t, int,
	    struct scsi_address *, struct uscsi_cmd **);
int	scsi_uscsi_alloc_and_copyin(intptr_t, int,
	    struct scsi_address *, struct uscsi_cmd **);

int	scsi_uscsi_pktinit(struct uscsi_cmd *, struct scsi_pkt *);
int	scsi_uscsi_handle_cmd(dev_t, enum uio_seg,
	    struct uscsi_cmd *, int (*)(struct buf *),
	    struct buf *, void *);
int	scsi_uscsi_pktfini(struct scsi_pkt *, struct uscsi_cmd *);

int	scsi_uscsi_copyout(intptr_t, struct uscsi_cmd *);
void	scsi_uscsi_free(struct uscsi_cmd *);
int	scsi_uscsi_copyout_and_free(intptr_t, struct uscsi_cmd *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_USCSI_H */
