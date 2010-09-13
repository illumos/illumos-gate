/*
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AGPGART_IMPL_H
#define	_SYS_AGPGART_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif


#ifdef _KERNEL

#define	AGPGART_MAX_INSTANCES	1
#define	AGP_MAXKEYS		256
#define	AGPGART_DEVNODE		"agpgart"

/*
 * The values of type agp_arc_type_t are used as indexes into arc_name
 * in agp_kstat.c.
 * So if agp_arc_type_t's values are changed in the future, the content
 * of arc_name must be changed accordingly.
 */
enum agp_arc_type {
	ARC_IGD810 = 0,
	ARC_IGD830 = 1,
	ARC_INTELAGP = 2,
	ARC_AMD64AGP = 3,
	ARC_UNKNOWN = 5
};
typedef enum agp_arc_type agp_arc_type_t;

/* linked list structure of multiple agp gart devices access handles */
typedef struct	amd64_gart_dev_list {
	ldi_handle_t			gart_devhdl;
	struct	amd64_gart_dev_list	*next;
} amd64_gart_dev_list_t;

typedef struct amd64_garts_dev {
	int			gart_device_num;
	amd64_gart_dev_list_t	*gart_dev_list_head;
} amd64_garts_dev_t;

/*
 * AGP target and master device register their config space access
 * interface here.
 * In AMD64, gart_device_num is the number of hostbridge (device(1100, 1022))
 * refer to <<Bios and Kernel Developer's Guide for AMD athlon64 and operton>>
 */
typedef struct agp_registered_dev {
	amd64_garts_dev_t	agprd_cpugarts;
	ldi_handle_t		agprd_targethdl;
	ldi_handle_t		agprd_masterhdl;
	agp_arc_type_t		agprd_arctype; /* system types */
} agp_registered_dev_t;

/*
 * If the OS have direct mapping support for mapping physical page frames
 * directly to user address, we use this struct for memory
 * allocation.
 */
typedef struct agp_pmem_handle {
	devmap_pmem_cookie_t pmem_cookie;
} agp_pmem_handle_t;

/*
 * This struct is used for DDI-compliant memory allocations.
 */
typedef struct agp_kmem_handle {
	ddi_dma_handle_t	kmem_handle;
	ddi_dma_cookie_t	kmem_dcookie;
	uint32_t		kmem_cookies_num;
	caddr_t			kmem_kvaddr;
	size_t			kmem_reallen;
	ddi_acc_handle_t	kmem_acchdl;
} agp_kmem_handle_t;

typedef struct keytable_ent {
	int		kte_type; 	/* agp memory type */
	int		kte_key;	/* memory key */
	uint32_t	kte_pgoff;	/* aperture offset bound in pages */
	pgcnt_t		kte_pages;	/* user-requested size in pages */
	int		kte_bound;	/* bound to gart table */
	void		*kte_memhdl;	/* agp_kmem or agp_pmem handle */
	pfn_t		*kte_pfnarray;	/* page frame numbers allocated */
	int	kte_refcnt;	/* reference count */
} keytable_ent_t;

typedef struct key_list {
	int	key_idx;
	struct	key_list *next;
} key_list_t;

/*
 * for kstat
 */
typedef struct agp_kern_info {
	uint32_t	agpki_mdevid;
	agp_version_t	agpki_mver;
	uint32_t	agpki_mstatus;
	size_t		agpki_presize;	/* valid only for IGD, in KB */
	uint32_t	agpki_tdevid;
	agp_version_t	agpki_tver;
	uint32_t	agpki_tstatus;
	uint64_t	agpki_aperbase;
	uint32_t	agpki_apersize;	/* in MB */
} agp_kern_info_t;

#ifdef	_MULTI_DATAMODEL
typedef struct _agp_info32 {
	agp_version_t	agpi32_version;
	uint32_t	agpi32_devid; /* device VID + DID */
	uint32_t	agpi32_mode; /* mode of bridge */
	uint32_t	agpi32_aperbase; /* base of aperture */
	uint32_t	agpi32_apersize; /* in MB */
	uint32_t	agpi32_pgtotal;	/* max number of pages */
	uint32_t	agpi32_pgsystem; /* same as pg_total */
	uint32_t	agpi32_pgused; /* pages consumed */
} agp_info32_t;
#endif /* _MULTI_DATAMODEL */

struct list_head {
	struct list_head *next, *prev;
	struct igd_gtt_seg  *gttseg;
};


typedef struct	agpgart_softstate {
	dev_info_t	*asoft_dip;
	kmutex_t	asoft_instmutex;
	agp_kern_info_t	asoft_info;
	int		asoft_opened;	/* 0 not opened, non-0 opened */
	int		asoft_acquired;	/* 0 released, 1 acquired */
	int		asoft_agpen;	/* 0 disbaled, 1 enabled */
	pid_t		asoft_curpid;	/* the process accquiring gart */
	uint32_t	asoft_mode;	/* agp mode be set */
	uint32_t	asoft_pgtotal;	/* total available pages */
	uint32_t	asoft_pgused;	/* pages already used */
	/* resource handles */
	ldi_ident_t	asoft_li;	/* for ldi ops */
	keytable_ent_t	*asoft_table;	/* key table for all allocated table */
	ddi_dma_handle_t	gart_dma_handle; 	/* for GATT table */
	ddi_acc_handle_t	gart_dma_acc_handle;	/* for GATT table */

	/* gart table info */
	uint64_t	gart_pbase; /* gart table physical address */
	caddr_t		gart_vbase; /* kernel-vir addr for GATT table */
	size_t		gart_size;  /* the size of aperture in megabytes */
	/* all registered agp device in here */
	agp_registered_dev_t	asoft_devreg;
	kstat_t			*asoft_ksp;
	struct		list_head	mapped_list;
} agpgart_softstate_t;

typedef struct agpgart_ctx {
	offset_t	actx_off;
	agpgart_softstate_t *actx_sc;
} agpgart_ctx_t;

#define	KMEMP(p)		((agp_kmem_handle_t *)p)
#define	PMEMP(p)		((agp_pmem_handle_t *)p)

int agp_init_kstats(agpgart_softstate_t *);
void agp_fini_kstats(agpgart_softstate_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AGPGART_IMPL_H */
