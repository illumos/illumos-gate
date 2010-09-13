/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2000 Doug Rabson
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef	_SYS_AGPGART_H
#define	_SYS_AGPGART_H

#ifdef __cplusplus
extern "C" {
#endif

#define	AGP_NORMAL	0	/* mapped to user land, no cache */

typedef struct _agp_version {
	uint16_t	agpv_major;
	uint16_t	agpv_minor;
} agp_version_t;


typedef struct	_agp_info {
	agp_version_t	agpi_version;
	uint32_t	agpi_devid;	/* bridge vendor + device */
	uint32_t	agpi_mode;	/* mode of brdige */
	ulong_t		agpi_aperbase;	/* base of aperture */
	size_t		agpi_apersize;	/* aperture range size */
	uint32_t	agpi_pgtotal;	/* max number of pages in aperture */
	uint32_t	agpi_pgsystem;	/* same as pg_total */
	uint32_t	agpi_pgused;	/* NUMBER of currently used pages */
} agp_info_t;

typedef struct _agp_setup {
	uint32_t	agps_mode;
} agp_setup_t;

typedef struct _agp_allocate {
	int32_t		agpa_key;
	uint32_t	agpa_pgcount;
	uint32_t	agpa_type;
	uint32_t	agpa_physical;	/* for i810 only, private */
} agp_allocate_t;

typedef struct _agp_bind_pages {
	uint32_t	agpb_pgstart;
	pfn_t		*agpb_pages;
	unsigned long 	agpb_pgcount;
} agp_bind_pages_t;

typedef struct _agp_unbind_pages {
	uint32_t	agpb_pgstart;
	unsigned long	agpb_pgcount;
	uint32_t	agpb_type;
} agp_unbind_pages_t;

typedef struct _agp_bind {
	int32_t		agpb_key;
	uint32_t	agpb_pgstart;
} agp_bind_t;

typedef struct _agp_unbind {
	int32_t		agpu_key;
	uint32_t	agpu_pri;	/* no use in solaris */
} agp_unbind_t;

#define	AGPIOC_BASE		'G'
#define	AGPIOC_INFO		_IOR(AGPIOC_BASE, 0, 100)
#define	AGPIOC_ACQUIRE		_IO(AGPIOC_BASE, 1)
#define	AGPIOC_RELEASE		_IO(AGPIOC_BASE, 2)
#define	AGPIOC_SETUP		_IOW(AGPIOC_BASE, 3, agp_setup_t)
#define	AGPIOC_ALLOCATE		_IOWR(AGPIOC_BASE, 4, agp_allocate_t)
#define	AGPIOC_DEALLOCATE	_IOW(AGPIOC_BASE, 5, int)
#define	AGPIOC_BIND		_IOW(AGPIOC_BASE, 6, agp_bind_t)
#define	AGPIOC_UNBIND		_IOW(AGPIOC_BASE, 7, agp_unbind_t)
#define	AGPIOC_IOREMAP		_IO(AGPIOC_BASE, 8)
#define	AGPIOC_IOREMAP_FREE	_IO(AGPIOC_BASE, 9)
#define	AGPIOC_READ		_IO(AGPIOC_BASE, 10)
#define	AGPIOC_WRITE		_IO(AGPIOC_BASE, 11)
#define	AGPIOC_FLUSHCHIPSET	_IO(AGPIOC_BASE, 12)
#define	AGPIOC_PAGES_BIND	_IOW(AGPIOC_BASE, 13, agp_bind_pages_t)
#define	AGPIOC_PAGES_UNBIND	_IOW(AGPIOC_BASE, 14, agp_unbind_pages_t)
#define	AGPIOC_PAGES_REBIND	_IO(AGPIOC_BASE, 15)

/* AGP status register bits definition */
#define	AGPSTAT_RQ_MASK		0xff000000	/* target only */
#define	AGPSTAT_SBA		(0x1 << 9)	/* always 1 for 3.0 */
#define	AGPSTAT_OVER4G		(0x1 << 5)
#define	AGPSTAT_FW		(0x1 << 4)
#define	AGPSTAT_RATE_MASK	0x7
/* rate for 2.0 mode */
#define	AGP2_RATE_1X		0x1
#define	AGP2_RATE_2X		0x2
#define	AGP2_RATE_4X		0x4
/* AGP 3.0 only bits */
#define	AGPSTAT_ARQSZ_MASK	(0x7 << 13)	/* target only */
#define	AGPSTAT_CAL_MASK	(0x7 << 10)
#define	AGPSTAT_GART64B		(0x1 << 7)	/* target only */
#define	AGPSTAT_MODE3		(0x1 << 3)
/* Rate for 3.0 mode */
#define	AGP3_RATE_4X		0x1
#define	AGP3_RATE_8X		0x2

/* AGP command register bits definition */
#define	AGPCMD_RQ_MASK		0xff000000	/* master only */
#define	AGPCMD_SBAEN		(0x1 << 9)	/* must be 1 for 3.0 */
#define	AGPCMD_AGPEN		(0x1 << 8)
#define	AGPCMD_OVER4GEN		(0x1 << 5)
#define	AGPCMD_FWEN		(0x1 << 4)
#define	AGPCMD_RATE_MASK	0x7
/* AGP 3.0 only bits */
#define	AGP3_CMD_ARQSZ_MASK	(0x7 << 13)	/* master only */
#define	AGP3_CMD_CAL_MASK	(0x7 << 10)	/* target only */
#define	AGP3_CMD_GART64BEN	(0x1 << 7)	/* target only */

#define	AGP_DEVICE	"/dev/agpgart"

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AGPGART_H */
