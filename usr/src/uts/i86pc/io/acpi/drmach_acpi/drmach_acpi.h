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
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_SYS_DRMACH_ACPI_H
#define	_SYS_DRMACH_ACPI_H
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/drmach.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/* Use ACPI handle as DRMACH handle on x86 systems. */
#define	DRMACH_HANDLE		ACPI_HANDLE

/* Macros to deal with object type. */
#define	DRMACH_OBJ(id)		((drmach_common_t *)id)

#define	DRMACH_NULL_ID(id)	((id) == 0)

#define	DRMACH_IS_BOARD_ID(id)	\
	((id != 0) && (DRMACH_OBJ(id)->isa == (void *)drmach_board_new))

#define	DRMACH_IS_CPU_ID(id)	\
	((id != 0) && (DRMACH_OBJ(id)->isa == (void *)drmach_cpu_new))

#define	DRMACH_IS_MEM_ID(id)	\
	((id != 0) && (DRMACH_OBJ(id)->isa == (void *)drmach_mem_new))

#define	DRMACH_IS_IO_ID(id)	\
	((id != 0) && (DRMACH_OBJ(id)->isa == (void *)drmach_io_new))

#define	DRMACH_IS_DEVICE_ID(id)					\
	((id != 0) &&						\
	(DRMACH_OBJ(id)->isa == (void *)drmach_cpu_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_mem_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_io_new))

#define	DRMACH_IS_ID(id)					\
	((id != 0) &&						\
	(DRMACH_OBJ(id)->isa == (void *)drmach_board_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_cpu_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_mem_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_io_new))

#define	DRMACH_INTERNAL_ERROR() \
	drerr_new(1, EX86_INTERNAL, drmach_ie_fmt, __LINE__)

#ifdef DEBUG
extern int drmach_debug;

#define	DRMACH_PR		if (drmach_debug) printf
#else
#define	DRMACH_PR		_NOTE(CONSTANTCONDITION) if (0) printf
#endif /* DEBUG */

typedef struct {
	struct drmach_node	*node;
	void			*data;
	void			*func;
} drmach_node_walk_args_t;

typedef struct drmach_node {
	void		*here;

	DRMACH_HANDLE	(*get_dnode)(struct drmach_node *node);
	dev_info_t	*(*getdip)(struct drmach_node *node);
	int		(*getproplen)(struct drmach_node *node, char *name,
				int *len);
	int		(*getprop)(struct drmach_node *node, char *name,
				void *buf, int len);
	int		(*walk)(struct drmach_node *node, void *data,
				int (*cb)(drmach_node_walk_args_t *args));
} drmach_node_t;

typedef struct {
	int		 min_index;
	int		 max_index;
	int		 arr_sz;
	drmachid_t	*arr;
} drmach_array_t;

typedef struct {
	void		*isa;

	void		(*dispose)(drmachid_t);
	sbd_error_t	*(*release)(drmachid_t);
	sbd_error_t	*(*status)(drmachid_t, drmach_status_t *);

	char		 name[MAXNAMELEN];
} drmach_common_t;

typedef struct {
	drmach_common_t	 cm;
	uint_t		 bnum;
	int		 assigned;
	int		 powered;
	int		 connected;
	int		 cond;
	drmach_node_t	*tree;
	drmach_array_t	*devices;
	int		 boot_board;	/* if board exists on bootup */
} drmach_board_t;

typedef struct {
	drmach_common_t	 cm;
	drmach_board_t	*bp;
	int		 unum;
	uint_t		 portid;
	int		 busy;
	int		 powered;
	const char	*type;
	drmach_node_t	*node;
} drmach_device_t;

typedef struct drmach_cpu {
	drmach_device_t  dev;
	processorid_t    cpuid;
	uint32_t	 apicid;
} drmach_cpu_t;

typedef struct drmach_mem {
	drmach_device_t dev;
	uint64_t	mem_alignment;
	uint64_t	slice_base;
	uint64_t	slice_top;
	uint64_t	slice_size;
	uint64_t	base_pa;	/* lowest installed memory base */
	uint64_t	nbytes;		/* size of installed memory */
	struct memlist *memlist;
} drmach_mem_t;

typedef struct drmach_io {
	drmach_device_t  dev;
} drmach_io_t;

typedef struct drmach_domain_info {
	uint64_t	floating;
	int		allow_dr;
} drmach_domain_info_t;

typedef struct {
	drmach_board_t	*obj;
	int		 ndevs;
	void		*a;
	sbd_error_t	*(*found)(void *a, const char *, int, drmachid_t);
	sbd_error_t	*err;
} drmach_board_cb_data_t;

extern drmach_domain_info_t drmach_domain;

extern drmach_board_t	*drmach_board_new(uint_t, int);
extern sbd_error_t	*drmach_device_new(drmach_node_t *,
				drmach_board_t *, int, drmachid_t *);
extern sbd_error_t	*drmach_cpu_new(drmach_device_t *, drmachid_t *);
extern sbd_error_t	*drmach_mem_new(drmach_device_t *, drmachid_t *);
extern sbd_error_t	*drmach_io_new(drmach_device_t *, drmachid_t *);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_DRMACH_ACPI_H */
