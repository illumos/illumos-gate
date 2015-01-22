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
 * Copyright (c) 2015 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_LX_AIO_H
#define	_SYS_LX_AIO_H

#ifdef __cplusplus
extern "C" {
#endif

#define	LX_IOCB_FLAG_RESFD		0x0001

#define	LX_IOCB_CMD_PREAD		0
#define	LX_IOCB_CMD_PWRITE		1
#define	LX_IOCB_CMD_FSYNC		2
#define	LX_IOCB_CMD_FDSYNC		3
#define	LX_IOCB_CMD_PREADX		4
#define	LX_IOCB_CMD_POLL		5
#define	LX_IOCB_CMD_NOOP		6
#define	LX_IOCB_CMD_PREADV		7
#define	LX_IOCB_CMD_PWRITEV		8

#define	LX_KIOCB_KEY			0

typedef struct lx_io_event lx_io_event_t;
typedef struct lx_iocb lx_iocb_t;
typedef struct lx_aiocb lx_aiocb_t;
typedef struct lx_aio_context lx_aio_context_t;

/*
 * Linux binary definition of an I/O event.
 */
struct lx_io_event {
	uint64_t	lxioe_data;	/* data payload */
	uint64_t	lxioe_object;	/* object of origin */
	int64_t		lxioe_res;	/* result code */
	int64_t		lxioe_res2;	/* "secondary" result (WTF?) */
};

/*
 * Linux binary definition of an I/O control block.
 */
struct lx_iocb {
	uint64_t	lxiocb_data;		/* data payload */
	uint32_t	lxiocb_key;		/* must be LX_KIOCB_KEY (!) */
	uint32_t	lxiocb_reserved1;
	uint16_t	lxiocb_op;		/* operation */
	int16_t		lxiocb_reqprio;		/* request priority */
	uint32_t	lxiocb_fd;		/* file descriptor */
	uint64_t	lxiocb_buf;		/* data buffer */
	uint64_t	lxiocb_nbytes;		/* number of bytes */
	int64_t		lxiocb_offset;		/* offset in file */
	uint64_t	lxiocb_reserved2;
	uint32_t	lxiocb_flags;		/* LX_IOCB_FLAG_* flags */
	uint32_t	lxiocb_resfd;		/* eventfd fd, if any */
};

extern long lx_io_setup(unsigned int, lx_aio_context_t **);
extern long lx_io_submit(lx_aio_context_t *, long nr, uintptr_t **);
extern long lx_io_getevents(lx_aio_context_t *, long, long,
    lx_io_event_t *, struct timespec *);
extern long lx_io_cancel(lx_aio_context_t *, lx_iocb_t *, lx_io_event_t *);
extern long lx_io_destroy(lx_aio_context_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_AIO_H */
