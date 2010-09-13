/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AGPAMD64GART_IO_H
#define	_SYS_AGPAMD64GART_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	AMD64GART_NAME		"amd64_gart"
#define	CPUGART_DEVLINK		"/dev/agp/cpugart"

#define	AGPAMD64GARTIOC_BASE	'M'

#define	AMD64_GET_INFO		_IOR(AGPAMD64GARTIOC_BASE, 50, amdgart_info_t)
#define	AMD64_SET_GART_ADDR	_IOW(AGPAMD64GARTIOC_BASE, 51, uint32_t)
#define	AMD64_FLUSH_GTLB	_IO(AGPAMD64GARTIOC_BASE, 52)
#define	AMD64_CONFIGURE		_IO(AGPAMD64GARTIOC_BASE, 53)
#define	AMD64_UNCONFIG		_IO(AGPAMD64GARTIOC_BASE, 54)

/* Used to retrieve attributes of the amd64 gart device */
typedef struct amdgart_info {
	uint64_t	cgart_aperbase;
	size_t		cgart_apersize;
} amdgart_info_t;

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AGPAMD64GART_IO_H */
