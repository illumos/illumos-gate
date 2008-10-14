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

#ifndef	_SDBC_STATS_H
#define	_SDBC_STATS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Internal flags to denote data collection status
 */
#define	GOT_SET_KSTAT	0x01
#define	GOT_IO_KSTAT	0x02
#define	GOT_COMPLETE_SDBC	(GOT_SET_KSTAT | GOT_IO_KSTAT)

#define	SDBC_COMPLETE(x)	(((x) & (GOT_COMPLETE_SDBC)) != \
				    (GOT_COMPLETE_SDBC))

#define	SDBC_KBYTES	0x01
#define	SDBC_INTAVG	0x02

#define	KILOBYTE	1024

typedef struct sdbcstat_s
{
	kstat_t			*pre_set;
	kstat_t			*pre_io;
	kstat_t			*cur_set;
	kstat_t			*cur_io;
	int			collected;
	struct sdbcstat_s	*next;
} sdbcstat_t;

typedef struct sdbcvals_t
{
	uint32_t	cache_read;
	uint32_t	cache_write;
	uint32_t	total_cache;

	float		cache_hit;
	float		read_hit;
	float		write_hit;

	uint32_t	disk_read;
	uint32_t	disk_write;
	uint32_t	total_disk;

	uint32_t	destaged;
	uint32_t	write_cancellations;

	uint32_t	total_reads;
	uint32_t	total_writes;
} sdbcvals_t;

extern kstat_t *sdbc_global;

/* Prototypes */
int sdbc_discover(kstat_ctl_t *);
int sdbc_update(kstat_ctl_t *);
int sdbc_report();
sdbcstat_t *sdbc_getstat(char *);
int sdbc_getvalues(sdbcstat_t *, sdbcvals_t *, int);

#ifdef	__cplusplus
}
#endif

#endif /* _SDBC_STATS_H */
