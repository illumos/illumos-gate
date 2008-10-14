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

#ifndef _NSC_MEM_H
#define	_NSC_MEM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __NSC_GEN__
Error: Illegal #include - private file.
#endif


/*
 * Macro definitions.
 */


/*
 * Definition of control structure.
 */
typedef struct nsc_mem_s {
	struct nsc_mem_s *next;		/* Link to next type */
	char	*name;			/* Description */
	int	type;			/* Memory type */
	int	flag;			/* Allocation flags */
	size_t	used;			/* Current usage */
	size_t	hwm;			/* High Water Mark */
	int	pages;			/* Usage in pages */
	int	pagehwm;		/* Page High Water Mark */
	caddr_t base;			/* Base address of RM area */
	int	nalloc;			/* Number of allocates */
	int	nfree;			/* Number of frees */
	int	pend;			/* Operation pending */
} nsc_mem_t;


/*
 * Definition of global memory header
 */

#define	_NSCTL_HDRMAGIC	0x5344474c	/* Magic number for header */
#define	_NSCTL_HDRVER	2		/* Version number for header */
#define	_NSCTL_HDRVER3	3		/* Version number for header */
#define	_NSC_GLSLOT	125		/* Number of global slots */
#define	_NSC_GLALIGN	4095		/* Alignment between areas */


typedef struct nsc_rmhdr_s {
	uint32_t	magic;		/* Magic number */
	uint32_t	ver;		/* Version number of header */
	uint32_t	size;		/* Size of header section */
	int32_t		rh_dirty;	/* dirty bit for nvmem */
	int32_t		maxdev;		/* Configured nsc_max_devices */
	int32_t		pad[14];	/* Future expansion */
	nsc_rmmap_t	map[1];		/* Start of map array */
} nsc_rmhdr_t;

extern nsc_rmmap_t *_nsc_global_nvmemmap_lookup(nsc_rmmap_t *);

extern int _nsc_get_global_sizes(void *, int *);
extern int _nsc_get_global_data(void *, int *);
extern int _nsc_clear_dirty(int);
extern int _nsc_check_mapinuse(void);
extern int _nsc_is_nsctl_map(char *);

extern caddr_t _nsc_rm_base;

#ifdef __cplusplus
}
#endif

#endif /* _NSC_MEM_H */
