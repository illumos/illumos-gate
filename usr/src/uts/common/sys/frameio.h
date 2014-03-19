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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_FRAMEIO_H
#define	_SYS_FRAMEIO_H

/*
 * Frame I/O definitions
 */

#include <sys/types.h>

#ifdef _KERNEL
/* Kernel only headers */
#include <sys/stream.h>
#endif	/* _KERNEL */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * An individual frame vector component. Collections of these are used to make
 * ioctls.
 */
typedef struct framevec {
	void	*fv_buf;	/* Buffer with data */
	size_t	fv_buflen;	/* Size of the buffer */
	size_t	fv_actlen;	/* Amount of buffer consumed, ignore on error */
} framevec_t;

/*
 * The base unit used with frameio.
 */
typedef struct frameio {
	uint_t	fio_version;	/* Should always be FRAMEIO_CURRENT_VERSION */
	uint_t	fio_nvpf;	/* How many vectors make up one frame */
	uint_t	fio_nvecs;	/* The total number of vectors */
	framevec_t fio_vecs[];	/* C99 VLA */
} frameio_t;


#define	FRAMEIO_VERSION_ONE	1
#define	FRAMEIO_CURRENT_VERSION	FRAMEIO_VERSION_ONE

#define	FRAMEIO_NVECS_MAX	32

/*
 * Definitions for kernel modules to include as helpers. These are consolidation
 * private.
 */
#ifdef _KERNEL

/*
 * 32-bit versions for 64-bit kernels
 */
typedef struct framevec32 {
	caddr32_t fv_buf;
	size32_t fv_buflen;
	size32_t fv_actlen;
} framevec32_t;

typedef struct frameio32 {
	uint_t fio_version;
	uint_t fio_vecspframe;
	uint_t fio_nvecs;
	framevec32_t fio_vecs[];
} frameio32_t;

/*
 * Describe the different ways that vectors should map to frames.
 */
typedef enum frameio_write_mblk_map {
	MAP_BLK_FRAME
} frameio_write_mblk_map_t;

int frameio_init(void);
void frameio_fini(void);
frameio_t *frameio_alloc(int);
void frameio_free(frameio_t *);
int frameio_hdr_copyin(frameio_t *, int, const void *, uint_t);
int frameio_mblk_chain_read(frameio_t *, mblk_t **, int *, int);
int frameio_mblk_chain_write(frameio_t *, frameio_write_mblk_map_t, mblk_t *,
    int *, int);
int frameio_hdr_copyout(frameio_t *, int, void *, uint_t);
size_t frameio_frame_length(frameio_t *, framevec_t *);
void frameio_mark_consumed(frameio_t *, int);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FRAMEIO_H */
