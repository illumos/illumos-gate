/*
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Portions Philip Brown phil@bolthole.com Dec 2001
 */


/*
 * agpgart driver
 *
 * This driver is primary targeted at providing memory support for INTEL
 * AGP device, INTEL memory less video card, and AMD64 cpu GART devices.
 * So there are four main architectures, ARC_IGD810, ARC_IGD830, ARC_INTELAGP,
 * ARC_AMD64AGP to agpgart driver. However, the memory
 * interfaces are the same for these architectures. The difference is how to
 * manage the hardware GART table for them.
 *
 * For large memory allocation, this driver use direct mapping to userland
 * application interface to save kernel virtual memory .
 */

#include <sys/types.h>
#include <sys/pci.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/kstat.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/policy.h>
#include <sys/ddidevmap.h>
#include <vm/seg_dev.h>
#include <sys/pmem.h>
#include <sys/agpgart.h>
#include <sys/agp/agpdefs.h>
#include <sys/agp/agpgart_impl.h>
#include <sys/agp/agpamd64gart_io.h>
#include <sys/agp/agpmaster_io.h>
#include <sys/agp/agptarget_io.h>

/* Dynamic debug support */
int agp_debug_var = 0;
#define	AGPDB_PRINT1(fmt)	if (agp_debug_var == 1) cmn_err fmt
#define	AGPDB_PRINT2(fmt)	if (agp_debug_var >= 1) cmn_err fmt

/* Driver global softstate handle */
static void *agpgart_glob_soft_handle;

#define	MAX_INSTNUM			16

#define	AGP_DEV2INST(devt)	(getminor((devt)) >> 4)
#define	AGP_INST2MINOR(instance)	((instance) << 4)
#define	IS_INTEL_830(type)	((type) == ARC_IGD830)
#define	IS_TRUE_AGP(type)	(((type) == ARC_INTELAGP) || \
	((type) == ARC_AMD64AGP))

#define	AGP_HASH_NODE	1024

static void
list_head_init(struct list_head  *head) {
	struct	list_head	*entry,	*tmp;
	/* HASH for accelerate */
	entry = kmem_zalloc(AGP_HASH_NODE *
		sizeof (struct list_head), KM_SLEEP);
	head->next = entry;
	for (int i = 0; i < AGP_HASH_NODE; i++) {
	tmp = &entry[i];
	tmp->next = tmp;
	tmp->prev = tmp;
	tmp->gttseg = NULL;
	}
}

static void
list_head_add_new(struct list_head	*head,
		igd_gtt_seg_t	*gttseg)
{
	struct list_head  *entry, *tmp;
	int key;
	entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
	key = gttseg->igs_pgstart % AGP_HASH_NODE;
	tmp = &head->next[key];
	tmp->next->prev = entry;
	entry->next = tmp->next;
	entry->prev = tmp;
	tmp->next = entry;
	entry->gttseg = gttseg;
}

static void
list_head_del(struct list_head	*entry) {
	(entry)->next->prev = (entry)->prev;      \
	(entry)->prev->next = (entry)->next;      \
	(entry)->gttseg = NULL; \
}

#define	list_head_for_each_safe(entry,	temp,	head)	\
	for (int key = 0; key < AGP_HASH_NODE; key++)	\
	for (entry = (&(head)->next[key])->next, temp = (entry)->next;	\
		entry != &(head)->next[key];	\
		entry = temp, temp = temp->next)


#define	agpinfo_default_to_32(v, v32)	\
	{	\
		(v32).agpi32_version = (v).agpi_version;	\
		(v32).agpi32_devid = (v).agpi_devid;	\
		(v32).agpi32_mode = (v).agpi_mode;	\
		(v32).agpi32_aperbase = (uint32_t)(v).agpi_aperbase;	\
		(v32).agpi32_apersize = (uint32_t)(v).agpi_apersize;	\
		(v32).agpi32_pgtotal = (v).agpi_pgtotal;	\
		(v32).agpi32_pgsystem = (v).agpi_pgsystem;	\
		(v32).agpi32_pgused = (v).agpi_pgused;	\
	}

static ddi_dma_attr_t agpgart_dma_attr = {
	DMA_ATTR_V0,
	0U,				/* dma_attr_addr_lo */
	0xffffffffU,			/* dma_attr_addr_hi */
	0xffffffffU,			/* dma_attr_count_max */
	(uint64_t)AGP_PAGE_SIZE,	/* dma_attr_align */
	1,				/* dma_attr_burstsizes */
	1,				/* dma_attr_minxfer */
	0xffffffffU,			/* dma_attr_maxxfer */
	0xffffffffU,			/* dma_attr_seg */
	1,				/* dma_attr_sgllen, variable */
	4,				/* dma_attr_granular */
	0				/* dma_attr_flags */
};

/*
 * AMD64 supports gart table above 4G. See alloc_gart_table.
 */
static ddi_dma_attr_t garttable_dma_attr = {
	DMA_ATTR_V0,
	0U,				/* dma_attr_addr_lo */
	0xffffffffU,			/* dma_attr_addr_hi */
	0xffffffffU,			/* dma_attr_count_max */
	(uint64_t)AGP_PAGE_SIZE,	/* dma_attr_align */
	1,				/* dma_attr_burstsizes */
	1,				/* dma_attr_minxfer */
	0xffffffffU,			/* dma_attr_maxxfer */
	0xffffffffU,			/* dma_attr_seg */
	1,				/* dma_attr_sgllen, variable */
	4,				/* dma_attr_granular */
	0				/* dma_attr_flags */
};

/*
 * AGPGART table need a physical contiguous memory. To assure that
 * each access to gart table is strongly ordered and uncachable,
 * we use DDI_STRICTORDER_ACC.
 */
static ddi_device_acc_attr_t gart_dev_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC	/* must be DDI_STRICTORDER_ACC */
};

/*
 * AGP memory is usually used as texture memory or for a framebuffer, so we
 * can set the memory attribute to write combining. Video drivers will
 * determine the frame buffer attributes, for example the memory is write
 * combinging or non-cachable. However, the interface between Xorg and agpgart
 * driver to support attribute selcetion doesn't exist yet. So we set agp memory
 * to non-cachable by default now. This attribute might be overridden
 * by MTTR in X86.
 */
static ddi_device_acc_attr_t mem_dev_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC	/* Can be DDI_MERGING_OK_ACC */
};

static keytable_ent_t *
agp_find_bound_keyent(agpgart_softstate_t *softstate, uint32_t pg_offset);
static void
amd64_gart_unregister(amd64_garts_dev_t *cpu_garts);


static void
agp_devmap_unmap(devmap_cookie_t handle, void *devprivate,
    offset_t off, size_t len, devmap_cookie_t new_handle1,
    void **new_devprivate1, devmap_cookie_t new_handle2,
    void **new_devprivate2)
{

	struct keytable_ent *mementry;
	agpgart_softstate_t *softstate;
	agpgart_ctx_t *ctxp, *newctxp1, *newctxp2;

	ASSERT(AGP_ALIGNED(len) && AGP_ALIGNED(off));
	ASSERT(devprivate);
	ASSERT(handle);

	ctxp = (agpgart_ctx_t *)devprivate;
	softstate = ctxp->actx_sc;
	ASSERT(softstate);

	if (new_handle1 != NULL) {
		newctxp1 = kmem_zalloc(sizeof (agpgart_ctx_t), KM_SLEEP);
		newctxp1->actx_sc = softstate;
		newctxp1->actx_off = ctxp->actx_off;
		*new_devprivate1 = newctxp1;
	}

	if (new_handle2 != NULL) {
		newctxp2 = kmem_zalloc(sizeof (agpgart_ctx_t), KM_SLEEP);
		newctxp2->actx_sc = softstate;
		newctxp2->actx_off = off + len;
		*new_devprivate2 = newctxp2;
	}

	mutex_enter(&softstate->asoft_instmutex);
	if ((new_handle1 == NULL) && (new_handle2 == NULL)) {
		mementry =
		    agp_find_bound_keyent(softstate, AGP_BYTES2PAGES(off));
		ASSERT(mementry);
		mementry->kte_refcnt--;
	} else if ((new_handle1 != NULL) && (new_handle2 != NULL)) {
		mementry =
		    agp_find_bound_keyent(softstate, AGP_BYTES2PAGES(off));
		ASSERT(mementry);
		mementry->kte_refcnt++;
	}
	ASSERT(mementry->kte_refcnt >= 0);
	mutex_exit(&softstate->asoft_instmutex);
	kmem_free(ctxp, sizeof (struct agpgart_ctx));
}

/*ARGSUSED*/
static int
agp_devmap_map(devmap_cookie_t handle, dev_t dev,
    uint_t flags, offset_t offset, size_t len, void **new_devprivate)
{
	agpgart_softstate_t *softstate;
	int instance;
	struct keytable_ent *mementry;
	agpgart_ctx_t *newctxp;

	ASSERT(handle);
	instance = AGP_DEV2INST(dev);
	softstate = ddi_get_soft_state(agpgart_glob_soft_handle, instance);
	if (softstate == NULL) {
		AGPDB_PRINT2((CE_WARN, "agp_devmap_map: get soft state err"));
		return (ENXIO);
	}

	ASSERT(softstate);
	ASSERT(mutex_owned(&softstate->asoft_instmutex));
	ASSERT(len);
	ASSERT(AGP_ALIGNED(offset) && AGP_ALIGNED(len));

	mementry =
	    agp_find_bound_keyent(softstate, AGP_BYTES2PAGES(offset));
	ASSERT(mementry);
	mementry->kte_refcnt++;
	ASSERT(mementry->kte_refcnt >= 0);
	newctxp = kmem_zalloc(sizeof (agpgart_ctx_t), KM_SLEEP);
	newctxp->actx_off = offset;
	newctxp->actx_sc = softstate;
	*new_devprivate = newctxp;

	return (0);
}

/*ARGSUSED*/
static int agp_devmap_dup(devmap_cookie_t handle, void *devprivate,
    devmap_cookie_t new_handle, void **new_devprivate)
{
	struct keytable_ent *mementry;
	agpgart_ctx_t *newctxp, *ctxp;
	agpgart_softstate_t *softstate;

	ASSERT(devprivate);
	ASSERT(handle && new_handle);

	ctxp = (agpgart_ctx_t *)devprivate;
	ASSERT(AGP_ALIGNED(ctxp->actx_off));

	newctxp = kmem_zalloc(sizeof (agpgart_ctx_t), KM_SLEEP);
	newctxp->actx_off = ctxp->actx_off;
	newctxp->actx_sc = ctxp->actx_sc;
	softstate = (agpgart_softstate_t *)newctxp->actx_sc;

	mutex_enter(&softstate->asoft_instmutex);
	mementry = agp_find_bound_keyent(softstate,
	    AGP_BYTES2PAGES(newctxp->actx_off));
	mementry->kte_refcnt++;
	ASSERT(mementry->kte_refcnt >= 0);
	mutex_exit(&softstate->asoft_instmutex);
	*new_devprivate = newctxp;

	return (0);
}

struct devmap_callback_ctl agp_devmap_cb = {
	DEVMAP_OPS_REV,		/* rev */
	agp_devmap_map,		/* map */
	NULL,			/* access */
	agp_devmap_dup,		/* dup */
	agp_devmap_unmap,	/* unmap */
};

/*
 * agp_master_regis_byname()
 *
 * Description:
 * 	Open the AGP master device node by device path name and
 * 	register the device handle for later operations.
 * 	We check all possible driver instance from 0
 * 	to MAX_INSTNUM because the master device could be
 * 	at any instance number. Only one AGP master is supported.
 *
 * Arguments:
 * 	master_hdlp		AGP master device LDI handle pointer
 *	agpgart_l		AGPGART driver LDI identifier
 *
 * Returns:
 * 	-1			failed
 * 	0			success
 */
static int
agp_master_regis_byname(ldi_handle_t *master_hdlp, ldi_ident_t agpgart_li)
{
	int	i;
	char	buf[MAXPATHLEN];

	ASSERT(master_hdlp);
	ASSERT(agpgart_li);

	/*
	 * Search all possible instance numbers for the agp master device.
	 * Only one master device is supported now, so the search ends
	 * when one master device is found.
	 */
	for (i = 0; i < MAX_INSTNUM; i++) {
		(void) snprintf(buf, MAXPATHLEN, "%s%d", AGPMASTER_DEVLINK, i);
		if ((ldi_open_by_name(buf, 0, kcred,
		    master_hdlp, agpgart_li)))
			continue;
		AGPDB_PRINT1((CE_NOTE,
		    "master device found: instance number=%d", i));
		break;

	}

	/* AGP master device not found */
	if (i == MAX_INSTNUM)
		return (-1);

	return (0);
}

/*
 * agp_target_regis_byname()
 *
 * Description:
 * 	This function opens agp bridge device node by
 * 	device path name and registers the device handle
 * 	for later operations.
 * 	We check driver instance from 0 to MAX_INSTNUM
 * 	because the master device could be at any instance
 * 	number. Only one agp target is supported.
 *
 *
 * Arguments:
 *	target_hdlp		AGP target device LDI handle pointer
 *	agpgart_l		AGPGART driver LDI identifier
 *
 * Returns:
 * 	-1			failed
 * 	0			success
 */
static int
agp_target_regis_byname(ldi_handle_t *target_hdlp, ldi_ident_t agpgart_li)
{
	int	i;
	char	buf[MAXPATHLEN];

	ASSERT(target_hdlp);
	ASSERT(agpgart_li);

	for (i = 0; i < MAX_INSTNUM; i++) {
		(void) snprintf(buf, MAXPATHLEN, "%s%d", AGPTARGET_DEVLINK, i);
		if ((ldi_open_by_name(buf, 0, kcred,
		    target_hdlp, agpgart_li)))
			continue;

		AGPDB_PRINT1((CE_NOTE,
		    "bridge device found: instance number=%d", i));
		break;

	}

	/* AGP bridge device not found */
	if (i == MAX_INSTNUM) {
		AGPDB_PRINT2((CE_WARN, "bridge device not found"));
		return (-1);
	}

	return (0);
}

/*
 * amd64_gart_regis_byname()
 *
 * Description:
 * 	Open all amd64 gart device nodes by deice path name and
 * 	register the device handles for later operations. Each cpu
 * 	has its own amd64 gart device.
 *
 * Arguments:
 * 	cpu_garts		cpu garts device list header
 *	agpgart_l		AGPGART driver LDI identifier
 *
 * Returns:
 * 	-1			failed
 * 	0			success
 */
static int
amd64_gart_regis_byname(amd64_garts_dev_t *cpu_garts, ldi_ident_t agpgart_li)
{
	amd64_gart_dev_list_t	*gart_list;
	int			i;
	char			buf[MAXPATHLEN];
	ldi_handle_t		gart_hdl;
	int			ret;

	ASSERT(cpu_garts);
	ASSERT(agpgart_li);

	/*
	 * Search all possible instance numbers for the gart devices.
	 * There can be multiple on-cpu gart devices for Opteron server.
	 */
	for (i = 0; i < MAX_INSTNUM; i++) {
		(void) snprintf(buf, MAXPATHLEN, "%s%d", CPUGART_DEVLINK, i);
		ret = ldi_open_by_name(buf, 0, kcred,
		    &gart_hdl, agpgart_li);

		if (ret == ENODEV)
			continue;
		else if (ret != 0) { /* There was an error opening the device */
			amd64_gart_unregister(cpu_garts);
			return (ret);
		}

		AGPDB_PRINT1((CE_NOTE,
		    "amd64 gart device found: instance number=%d", i));

		gart_list = (amd64_gart_dev_list_t *)
		    kmem_zalloc(sizeof (amd64_gart_dev_list_t), KM_SLEEP);

		/* Add new item to the head of the gart device list */
		gart_list->gart_devhdl = gart_hdl;
		gart_list->next = cpu_garts->gart_dev_list_head;
		cpu_garts->gart_dev_list_head = gart_list;
		cpu_garts->gart_device_num++;
	}

	if (cpu_garts->gart_device_num == 0)
		return (ENODEV);
	return (0);
}

/*
 * Unregister agp master device handle
 */
static void
agp_master_unregister(ldi_handle_t *master_hdlp)
{
	ASSERT(master_hdlp);

	if (master_hdlp) {
		(void) ldi_close(*master_hdlp, 0, kcred);
		*master_hdlp = NULL;
	}
}

/*
 * Unregister agp bridge device handle
 */
static void
agp_target_unregister(ldi_handle_t *target_hdlp)
{
	if (target_hdlp) {
		(void) ldi_close(*target_hdlp, 0, kcred);
		*target_hdlp = NULL;
	}
}

/*
 * Unregister all amd64 gart device handles
 */
static void
amd64_gart_unregister(amd64_garts_dev_t *cpu_garts)
{
	amd64_gart_dev_list_t	*gart_list;
	amd64_gart_dev_list_t	*next;

	ASSERT(cpu_garts);

	for (gart_list = cpu_garts->gart_dev_list_head;
	    gart_list; gart_list = next) {

		ASSERT(gart_list->gart_devhdl);
		(void) ldi_close(gart_list->gart_devhdl, 0, kcred);
		next = gart_list->next;
		/* Free allocated memory */
		kmem_free(gart_list, sizeof (amd64_gart_dev_list_t));
	}
	cpu_garts->gart_dev_list_head = NULL;
	cpu_garts->gart_device_num = 0;
}

/*
 * lyr_detect_master_type()
 *
 * Description:
 * 	This function gets agp master type by querying agp master device.
 *
 * Arguments:
 * 	master_hdlp		agp master device ldi handle pointer
 *
 * Returns:
 * 	-1			unsupported device
 * 	DEVICE_IS_I810		i810 series
 * 	DEVICE_IS_I810		i830 series
 * 	DEVICE_IS_AGP		true agp master
 */
static int
lyr_detect_master_type(ldi_handle_t *master_hdlp)
{
	int vtype;
	int err;

	ASSERT(master_hdlp);

	/* ldi_ioctl(agpmaster) */
	err = ldi_ioctl(*master_hdlp, DEVICE_DETECT,
	    (intptr_t)&vtype, FKIOCTL, kcred, 0);
	if (err) /* Unsupported graphics device */
		return (-1);
	return (vtype);
}

/*
 * devtect_target_type()
 *
 * Description:
 * 	This function gets the host bridge chipset type by querying the agp
 *	target device.
 *
 * Arguments:
 * 	target_hdlp		agp target device LDI handle pointer
 *
 * Returns:
 * 	CHIP_IS_INTEL		Intel agp chipsets
 * 	CHIP_IS_AMD		AMD agp chipset
 * 	-1			unsupported chipset
 */
static int
lyr_detect_target_type(ldi_handle_t *target_hdlp)
{
	int btype;
	int err;

	ASSERT(target_hdlp);

	err = ldi_ioctl(*target_hdlp, CHIP_DETECT, (intptr_t)&btype,
	    FKIOCTL, kcred, 0);
	if (err)	/* Unsupported bridge device */
		return (-1);
	return (btype);
}

/*
 * lyr_init()
 *
 * Description:
 * 	This function detects the  graphics system architecture and
 * 	registers all relative device handles in a global structure
 * 	"agp_regdev". Then it stores the system arc type in driver
 * 	soft state.
 *
 * Arguments:
 *	agp_regdev		AGP devices registration struct pointer
 *	agpgart_l		AGPGART driver LDI identifier
 *
 * Returns:
 * 	0	System arc supported and agp devices registration successed.
 * 	-1	System arc not supported or device registration failed.
 */
int
lyr_init(agp_registered_dev_t *agp_regdev, ldi_ident_t agpgart_li)
{
	ldi_handle_t *master_hdlp;
	ldi_handle_t *target_hdlp;
	amd64_garts_dev_t *garts_dev;
	int card_type, chip_type;
	int ret;

	ASSERT(agp_regdev);

	bzero(agp_regdev, sizeof (agp_registered_dev_t));
	agp_regdev->agprd_arctype = ARC_UNKNOWN;
	/*
	 * Register agp devices, assuming all instances attached, and
	 * detect which agp architucture this server belongs to. This
	 * must be done before the agpgart driver starts to use layered
	 * driver interfaces.
	 */
	master_hdlp = &agp_regdev->agprd_masterhdl;
	target_hdlp = &agp_regdev->agprd_targethdl;
	garts_dev = &agp_regdev->agprd_cpugarts;

	/* Check whether the system is amd64 arc */
	if ((ret = amd64_gart_regis_byname(garts_dev, agpgart_li)) == ENODEV) {
		/* No amd64 gart devices */
		AGPDB_PRINT1((CE_NOTE,
		    "lyr_init: this is not an amd64 system"));
		if (agp_master_regis_byname(master_hdlp, agpgart_li)) {
			AGPDB_PRINT2((CE_WARN,
			    "lyr_init: register master device unsuccessful"));
			goto err1;
		}
		if (agp_target_regis_byname(target_hdlp, agpgart_li)) {
			AGPDB_PRINT2((CE_WARN,
			    "lyr_init: register target device unsuccessful"));
			goto err2;
		}
		card_type = lyr_detect_master_type(master_hdlp);
		/*
		 * Detect system arc by master device. If it is a intel
		 * integrated device, finish the detection successfully.
		 */
		switch (card_type) {
		case DEVICE_IS_I810:	/* I810 likewise graphics */
			AGPDB_PRINT1((CE_NOTE,
			    "lyr_init: the system is Intel 810 arch"));
			agp_regdev->agprd_arctype = ARC_IGD810;
			return (0);
		case DEVICE_IS_I830:	/* I830 likewise graphics */
			AGPDB_PRINT1((CE_NOTE,
			    "lyr_init: the system is Intel 830 arch"));
			agp_regdev->agprd_arctype = ARC_IGD830;
			return (0);
		case DEVICE_IS_AGP:	/* AGP graphics */
			break;
		default:		/* Non IGD/AGP graphics */
			AGPDB_PRINT2((CE_WARN,
			    "lyr_init: non-supported master device"));
			goto err3;
		}

		chip_type = lyr_detect_target_type(target_hdlp);

		/* Continue to detect AGP arc by target device */
		switch (chip_type) {
		case CHIP_IS_INTEL:	/* Intel chipset */
			AGPDB_PRINT1((CE_NOTE,
			    "lyr_init: Intel AGP arch detected"));
			agp_regdev->agprd_arctype = ARC_INTELAGP;
			return (0);
		case CHIP_IS_AMD:	/* AMD chipset */
			AGPDB_PRINT2((CE_WARN,
			    "lyr_init: no cpu gart, but have AMD64 chipsets"));
			goto err3;
		default:		/* Non supported chipset */
			AGPDB_PRINT2((CE_WARN,
			    "lyr_init: detection can not continue"));
			goto err3;
		}

	}

	if (ret)
		return (-1); /* Errors in open amd64 cpu gart devices */

	/*
	 * AMD64 cpu gart device exsits, continue detection
	 */
	if (agp_master_regis_byname(master_hdlp, agpgart_li)) {
		AGPDB_PRINT1((CE_NOTE, "lyr_init: no AGP master in amd64"));
		goto err1;
	}

	if (agp_target_regis_byname(target_hdlp, agpgart_li)) {
		AGPDB_PRINT1((CE_NOTE,
		    "lyr_init: no AGP bridge"));
		goto err2;
	}

	AGPDB_PRINT1((CE_NOTE,
	    "lyr_init: the system is AMD64 AGP architecture"));

	agp_regdev->agprd_arctype = ARC_AMD64AGP;

	return (0); /* Finished successfully */

err3:
	agp_target_unregister(&agp_regdev->agprd_targethdl);
err2:
	agp_master_unregister(&agp_regdev->agprd_masterhdl);
err1:
	/* AMD64 CPU gart registered ? */
	if (ret == 0) {
		amd64_gart_unregister(garts_dev);
	}
	agp_regdev->agprd_arctype = ARC_UNKNOWN;
	return (-1);
}

void
lyr_end(agp_registered_dev_t *agp_regdev)
{
	ASSERT(agp_regdev);

	switch (agp_regdev->agprd_arctype) {
	case ARC_IGD810:
	case ARC_IGD830:
	case ARC_INTELAGP:
		agp_master_unregister(&agp_regdev->agprd_masterhdl);
		agp_target_unregister(&agp_regdev->agprd_targethdl);

		return;
	case ARC_AMD64AGP:
		agp_master_unregister(&agp_regdev->agprd_masterhdl);
		agp_target_unregister(&agp_regdev->agprd_targethdl);
		amd64_gart_unregister(&agp_regdev->agprd_cpugarts);

		return;
	default:
		ASSERT(0);
		return;
	}
}

int
lyr_get_info(agp_kern_info_t *info, agp_registered_dev_t *agp_regdev)
{
	ldi_handle_t hdl;
	igd_info_t value1;
	i_agp_info_t value2;
	size_t prealloc_size;
	int err;

	ASSERT(info);
	ASSERT(agp_regdev);

	switch (agp_regdev->agprd_arctype) {
	case ARC_IGD810:
		hdl = agp_regdev->agprd_masterhdl;
		err = ldi_ioctl(hdl, I8XX_GET_INFO, (intptr_t)&value1,
		    FKIOCTL, kcred, 0);
		if (err)
			return (-1);
		info->agpki_mdevid = value1.igd_devid;
		info->agpki_aperbase = value1.igd_aperbase;
		info->agpki_apersize = (uint32_t)value1.igd_apersize;

		hdl = agp_regdev->agprd_targethdl;
		err = ldi_ioctl(hdl, I8XX_GET_PREALLOC_SIZE,
		    (intptr_t)&prealloc_size, FKIOCTL, kcred, 0);
		if (err)
			return (-1);
		info->agpki_presize = prealloc_size;

		break;

	case ARC_IGD830:
		hdl = agp_regdev->agprd_masterhdl;
		err = ldi_ioctl(hdl, I8XX_GET_INFO, (intptr_t)&value1,
		    FKIOCTL, kcred, 0);
		if (err)
			return (-1);
		info->agpki_mdevid = value1.igd_devid;
		info->agpki_aperbase = value1.igd_aperbase;
		info->agpki_apersize = (uint32_t)value1.igd_apersize;

		hdl = agp_regdev->agprd_targethdl;
		err = ldi_ioctl(hdl, I8XX_GET_PREALLOC_SIZE,
		    (intptr_t)&prealloc_size, FKIOCTL, kcred, 0);
		if (err)
			return (-1);

		/*
		 * Assume all units are kilobytes unless explicitly
		 * stated below:
		 * preallocated GTT memory = preallocated memory - GTT size
		 * 	- scratch page size
		 *
		 * scratch page size = 4
		 * GTT size (KB) = aperture size (MB)
		 * this algorithm came from Xorg source code
		 */
		if (prealloc_size > (info->agpki_apersize + 4))
			prealloc_size =
			    prealloc_size - info->agpki_apersize - 4;
		else {
			AGPDB_PRINT2((CE_WARN, "lyr_get_info: "
			    "pre-allocated memory too small, setting to zero"));
			prealloc_size = 0;
		}
		info->agpki_presize = prealloc_size;
		AGPDB_PRINT2((CE_NOTE,
		    "lyr_get_info: prealloc_size = %ldKB, apersize = %dMB",
		    prealloc_size, info->agpki_apersize));
		break;
	case ARC_INTELAGP:
	case ARC_AMD64AGP:
		/* AGP devices */
		hdl = agp_regdev->agprd_masterhdl;
		err = ldi_ioctl(hdl, AGP_MASTER_GETINFO,
		    (intptr_t)&value2, FKIOCTL, kcred, 0);
		if (err)
			return (-1);
		info->agpki_mdevid = value2.iagp_devid;
		info->agpki_mver = value2.iagp_ver;
		info->agpki_mstatus = value2.iagp_mode;
		hdl = agp_regdev->agprd_targethdl;
		err = ldi_ioctl(hdl, AGP_TARGET_GETINFO,
		    (intptr_t)&value2, FKIOCTL, kcred, 0);
		if (err)
			return (-1);
		info->agpki_tdevid = value2.iagp_devid;
		info->agpki_tver = value2.iagp_ver;
		info->agpki_tstatus = value2.iagp_mode;
		info->agpki_aperbase = value2.iagp_aperbase;
		info->agpki_apersize = (uint32_t)value2.iagp_apersize;
		break;
	default:
		AGPDB_PRINT2((CE_WARN,
		    "lyr_get_info: function doesn't work for unknown arc"));
		return (-1);
	}
	if ((info->agpki_apersize >= MAXAPERMEGAS) ||
	    (info->agpki_apersize == 0) ||
	    (info->agpki_aperbase == 0)) {
		AGPDB_PRINT2((CE_WARN,
		    "lyr_get_info: aperture is not programmed correctly!"));
		return (-1);
	}

	return (0);
}

/*
 * lyr_i8xx_add_to_gtt()
 *
 * Description:
 * 	This function sets up the integrated video device gtt table
 * 	via an ioclt to the AGP master driver.
 *
 * Arguments:
 * 	pg_offset	The start entry to be setup
 * 	keyent		Keytable entity pointer
 *	agp_regdev	AGP devices registration struct pointer
 *
 * Returns:
 * 	0		success
 * 	-1		invalid operations
 */
int
lyr_i8xx_add_to_gtt(uint32_t pg_offset, keytable_ent_t *keyent,
    agp_registered_dev_t *agp_regdev)
{
	int err = 0;
	int rval;
	ldi_handle_t hdl;
	igd_gtt_seg_t gttseg;
	uint32_t *addrp, i;
	uint32_t npages;

	ASSERT(keyent);
	ASSERT(agp_regdev);
	gttseg.igs_pgstart =  pg_offset;
	npages = keyent->kte_pages;
	gttseg.igs_npage = npages;
	gttseg.igs_type = keyent->kte_type;
	gttseg.igs_phyaddr = (uint32_t *)kmem_zalloc
	    (sizeof (uint32_t) * gttseg.igs_npage, KM_SLEEP);

	addrp = gttseg.igs_phyaddr;
	for (i = 0; i < npages; i++, addrp++) {
		*addrp =
		    (uint32_t)((keyent->kte_pfnarray[i]) << GTT_PAGE_SHIFT);
	}

	hdl = agp_regdev->agprd_masterhdl;
	if (ldi_ioctl(hdl, I8XX_ADD2GTT, (intptr_t)&gttseg, FKIOCTL,
	    kcred, &rval)) {
		AGPDB_PRINT2((CE_WARN, "lyr_i8xx_add_to_gtt: ldi_ioctl error"));
		AGPDB_PRINT2((CE_WARN, "lyr_i8xx_add_to_gtt: pg_start=0x%x",
		    gttseg.igs_pgstart));
		AGPDB_PRINT2((CE_WARN, "lyr_i8xx_add_to_gtt: pages=0x%x",
		    gttseg.igs_npage));
		AGPDB_PRINT2((CE_WARN, "lyr_i8xx_add_to_gtt: type=0x%x",
		    gttseg.igs_type));
		err = -1;
	}
	kmem_free(gttseg.igs_phyaddr, sizeof (uint32_t) * gttseg.igs_npage);
	return (err);
}

/*
 * lyr_i8xx_remove_from_gtt()
 *
 * Description:
 * 	This function clears the integrated video device gtt table via
 * 	an ioctl to the agp master device.
 *
 * Arguments:
 * 	pg_offset	The starting entry to be cleared
 * 	npage		The number of entries to be cleared
 *	agp_regdev	AGP devices struct pointer
 *
 * Returns:
 * 	0		success
 * 	-1		invalid operations
 */
int
lyr_i8xx_remove_from_gtt(uint32_t pg_offset, uint32_t npage,
    agp_registered_dev_t *agp_regdev)
{
	int			rval;
	ldi_handle_t		hdl;
	igd_gtt_seg_t		gttseg;

	gttseg.igs_pgstart =  pg_offset;
	gttseg.igs_npage = npage;

	hdl = agp_regdev->agprd_masterhdl;
	if (ldi_ioctl(hdl, I8XX_REM_GTT, (intptr_t)&gttseg, FKIOCTL,
	    kcred, &rval))
		return (-1);

	return (0);
}

/*
 * lyr_set_gart_addr()
 *
 * Description:
 *	This function puts the gart table physical address in the
 * 	gart base register.
 *	Please refer to gart and gtt table base register format for
 *	gart base register format in agpdefs.h.
 *
 * Arguments:
 * 	phy_base	The base physical address of gart table
 *	agp_regdev	AGP devices registration struct pointer
 *
 * Returns:
 * 	0		success
 * 	-1		failed
 *
 */

int
lyr_set_gart_addr(uint64_t phy_base, agp_registered_dev_t *agp_regdev)
{
	amd64_gart_dev_list_t	*gart_list;
	ldi_handle_t		hdl;
	int			err = 0;

	ASSERT(agp_regdev);
	switch (agp_regdev->agprd_arctype) {
	case ARC_IGD810:
	{
		uint32_t base;

		ASSERT((phy_base & I810_POINTER_MASK) == 0);
		base = (uint32_t)phy_base;

		hdl = agp_regdev->agprd_masterhdl;
		err = ldi_ioctl(hdl, I810_SET_GTT_BASE,
		    (intptr_t)&base, FKIOCTL, kcred, 0);
		break;
	}
	case ARC_INTELAGP:
	{
		uint32_t addr;
		addr = (uint32_t)phy_base;

		ASSERT((phy_base & GTT_POINTER_MASK) == 0);
		hdl = agp_regdev->agprd_targethdl;
		err = ldi_ioctl(hdl, AGP_TARGET_SET_GATTADDR,
		    (intptr_t)&addr, FKIOCTL, kcred, 0);
		break;
	}
	case ARC_AMD64AGP:
	{
		uint32_t addr;

		ASSERT((phy_base & AMD64_POINTER_MASK) == 0);
		addr = (uint32_t)((phy_base >> AMD64_GARTBASE_SHIFT)
		    & AMD64_GARTBASE_MASK);

		for (gart_list = agp_regdev->agprd_cpugarts.gart_dev_list_head;
		    gart_list;
		    gart_list = gart_list->next) {
			hdl = gart_list->gart_devhdl;
			if (ldi_ioctl(hdl, AMD64_SET_GART_ADDR,
			    (intptr_t)&addr, FKIOCTL, kcred, 0)) {
				err = -1;
				break;
			}
		}
		break;
	}
	default:
		err = -1;
	}

	if (err)
		return (-1);

	return (0);
}

int
lyr_set_agp_cmd(uint32_t cmd, agp_registered_dev_t *agp_regdev)
{
	ldi_handle_t hdl;
	uint32_t command;

	ASSERT(agp_regdev);
	command = cmd;
	hdl = agp_regdev->agprd_targethdl;
	if (ldi_ioctl(hdl, AGP_TARGET_SETCMD,
	    (intptr_t)&command, FKIOCTL, kcred, 0))
		return (-1);
	hdl = agp_regdev->agprd_masterhdl;
	if (ldi_ioctl(hdl, AGP_MASTER_SETCMD,
	    (intptr_t)&command, FKIOCTL, kcred, 0))
		return (-1);

	return (0);
}

int
lyr_config_devices(agp_registered_dev_t *agp_regdev)
{
	amd64_gart_dev_list_t	*gart_list;
	ldi_handle_t		hdl;
	int			rc = 0;

	ASSERT(agp_regdev);
	switch (agp_regdev->agprd_arctype) {
	case ARC_IGD830:
	case ARC_IGD810:
		break;
	case ARC_INTELAGP:
	{
		hdl = agp_regdev->agprd_targethdl;
		rc = ldi_ioctl(hdl, AGP_TARGET_CONFIGURE,
		    0, FKIOCTL, kcred, 0);
		break;
	}
	case ARC_AMD64AGP:
	{
		/*
		 * BIOS always shadow registers such like Aperture Base
		 * register, Aperture Size Register from the AGP bridge
		 * to the AMD64 CPU host bridge. If future BIOSes are broken
		 * in this regard, we may need to shadow these registers
		 * in driver.
		 */

		for (gart_list = agp_regdev->agprd_cpugarts.gart_dev_list_head;
		    gart_list;
		    gart_list = gart_list->next) {
			hdl = gart_list->gart_devhdl;
			if (ldi_ioctl(hdl, AMD64_CONFIGURE,
			    0, FKIOCTL, kcred, 0)) {
				rc = -1;
				break;
			}
		}
		break;
	}
	default:
		rc = -1;
	}

	if (rc)
		return (-1);

	return (0);
}

int
lyr_unconfig_devices(agp_registered_dev_t *agp_regdev)
{
	amd64_gart_dev_list_t	*gart_list;
	ldi_handle_t		hdl;
	int			rc = 0;

	ASSERT(agp_regdev);
	switch (agp_regdev->agprd_arctype) {
	case ARC_IGD830:
	case ARC_IGD810:
	{
		hdl = agp_regdev->agprd_masterhdl;
		rc = ldi_ioctl(hdl, I8XX_UNCONFIG, 0, FKIOCTL, kcred, 0);
		break;
	}
	case ARC_INTELAGP:
	{
		hdl = agp_regdev->agprd_targethdl;
		rc = ldi_ioctl(hdl, AGP_TARGET_UNCONFIG,
		    0, FKIOCTL, kcred, 0);
		break;
	}
	case ARC_AMD64AGP:
	{
		for (gart_list = agp_regdev->agprd_cpugarts.gart_dev_list_head;
		    gart_list; gart_list = gart_list->next) {
			hdl = gart_list->gart_devhdl;
			if (ldi_ioctl(hdl, AMD64_UNCONFIG,
			    0, FKIOCTL, kcred, 0)) {
				rc = -1;
				break;
			}
		}
		break;
	}
	default:
		rc = -1;
	}

	if (rc)
		return (-1);

	return (0);
}

/*
 * lyr_flush_gart_cache()
 *
 * Description:
 * 	This function flushes the GART translation look-aside buffer. All
 * 	GART translation caches will be flushed after this operation.
 *
 * Arguments:
 *	agp_regdev	AGP devices struct pointer
 */
void
lyr_flush_gart_cache(agp_registered_dev_t *agp_regdev)
{
	amd64_gart_dev_list_t	*gart_list;
	ldi_handle_t		hdl;

	ASSERT(agp_regdev);
	if (agp_regdev->agprd_arctype == ARC_AMD64AGP) {
		for (gart_list = agp_regdev->agprd_cpugarts.gart_dev_list_head;
		    gart_list; gart_list = gart_list->next) {
			hdl = gart_list->gart_devhdl;
			(void) ldi_ioctl(hdl, AMD64_FLUSH_GTLB,
			    0, FKIOCTL, kcred, 0);
		}
	} else if (agp_regdev->agprd_arctype == ARC_INTELAGP) {
		hdl = agp_regdev->agprd_targethdl;
		(void) ldi_ioctl(hdl, AGP_TARGET_FLUSH_GTLB, 0,
		    FKIOCTL, kcred, 0);
	}
}

/*
 * get_max_pages()
 *
 * Description:
 * 	This function compute the total pages allowed for agp aperture
 *	based on the ammount of physical pages.
 * 	The algorithm is: compare the aperture size with 1/4 of total
 *	physical pages, and use the smaller one to for the max available
 * 	pages. But the minimum video memory should be 192M.
 *
 * Arguments:
 * 	aper_size	system agp aperture size (in MB)
 *
 * Returns:
 * 	The max possible number of agp memory pages available to users
 */
static uint32_t
get_max_pages(uint32_t aper_size)
{
	uint32_t i, j, size;

	ASSERT(aper_size <= MAXAPERMEGAS);

	i = AGP_MB2PAGES(aper_size);
	j = (physmem >> 2);

	size = ((i < j) ? i : j);

	if (size < AGP_MB2PAGES(MINAPERMEGAS))
		size = AGP_MB2PAGES(MINAPERMEGAS);
	return (size);
}

/*
 * agp_fill_empty_keyent()
 *
 * Description:
 * 	This function finds a empty key table slot and
 * 	fills it with a new entity.
 *
 * Arguments:
 * 	softsate	driver soft state pointer
 * 	entryp		new entity data pointer
 *
 * Returns:
 * 	NULL	no key table slot available
 * 	entryp	the new entity slot pointer
 */
static keytable_ent_t *
agp_fill_empty_keyent(agpgart_softstate_t *softstate, keytable_ent_t *entryp)
{
	int key;
	keytable_ent_t *newentryp;

	ASSERT(softstate);
	ASSERT(entryp);
	ASSERT(entryp->kte_memhdl);
	ASSERT(entryp->kte_pfnarray);
	ASSERT(mutex_owned(&softstate->asoft_instmutex));

	for (key = 0; key < AGP_MAXKEYS; key++) {
		newentryp = &softstate->asoft_table[key];
		if (newentryp->kte_memhdl == NULL) {
			break;
		}
	}

	if (key >= AGP_MAXKEYS) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_fill_empty_keyent: key table exhausted"));
		return (NULL);
	}

	ASSERT(newentryp->kte_pfnarray == NULL);
	bcopy(entryp, newentryp, sizeof (keytable_ent_t));
	newentryp->kte_key = key;

	return (newentryp);
}

/*
 * agp_find_bound_keyent()
 *
 * Description:
 * 	This function finds the key table entity by agp aperture page offset.
 * 	Every keytable entity will have an agp aperture range after the binding
 *	operation.
 *
 * Arguments:
 * 	softsate	driver soft state pointer
 * 	pg_offset	agp aperture page offset
 *
 * Returns:
 * 	NULL		no such keytable entity
 * 	pointer		key table entity pointer found
 */
static keytable_ent_t *
agp_find_bound_keyent(agpgart_softstate_t *softstate, uint32_t pg_offset)
{
	int keycount;
	keytable_ent_t *entryp;

	ASSERT(softstate);
	ASSERT(mutex_owned(&softstate->asoft_instmutex));

	for (keycount = 0; keycount < AGP_MAXKEYS; keycount++) {
		entryp = &softstate->asoft_table[keycount];
		if (entryp->kte_bound == 0) {
			continue;
		}

		if (pg_offset < entryp->kte_pgoff)
			continue;
		if (pg_offset >= (entryp->kte_pgoff + entryp->kte_pages))
			continue;

		ASSERT(entryp->kte_memhdl);
		ASSERT(entryp->kte_pfnarray);

		return (entryp);
	}

	return (NULL);
}

/*
 * agp_check_off()
 *
 * Description:
 * 	This function checks whether an AGP aperture range to be bound
 *	overlaps with AGP offset already bound.
 *
 * Arguments:
 *	entryp		key table start entry pointer
 * 	pg_start	AGP range start page offset
 *	pg_num		pages number to be bound
 *
 * Returns:
 *	0		Does not overlap
 *	-1		Overlaps
 */

static int
agp_check_off(keytable_ent_t *entryp, uint32_t pg_start, uint32_t pg_num)
{
	int key;
	uint64_t pg_end;
	uint64_t kpg_end;

	ASSERT(entryp);

	pg_end = pg_start + pg_num;
	for (key = 0; key < AGP_MAXKEYS; key++) {
		if (!entryp[key].kte_bound)
			continue;

		kpg_end = entryp[key].kte_pgoff + entryp[key].kte_pages;
		if (!((pg_end <= entryp[key].kte_pgoff) ||
		    (pg_start >= kpg_end)))
			break;
	}

	if (key == AGP_MAXKEYS)
		return (0);
	else
		return (-1);
}

static int
is_controlling_proc(agpgart_softstate_t *st)
{
	ASSERT(st);

	if (!st->asoft_acquired) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_setup: gart not acquired"));
		return (-1);
	}
	if (st->asoft_curpid != ddi_get_pid()) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_release: not  controlling process"));
		return (-1);
	}

	return (0);
}

static void release_control(agpgart_softstate_t *st)
{
	st->asoft_curpid = 0;
	st->asoft_acquired = 0;
}

static void acquire_control(agpgart_softstate_t *st)
{
	st->asoft_curpid = ddi_get_pid();
	st->asoft_acquired = 1;
}

/*
 * agp_remove_from_gart()
 *
 * Description:
 * 	This function fills the gart table entries by a given page
 * 	frame number array and setup the agp aperture page to physical
 * 	memory page translation.
 * Arguments:
 * 	pg_offset	Starting aperture page to be bound
 * 	entries		the number of pages to be bound
 * 	acc_hdl		GART table dma memory acc handle
 * 	tablep		GART table kernel virtual address
 */
static void
agp_remove_from_gart(
    uint32_t pg_offset,
    uint32_t entries,
    ddi_dma_handle_t dma_hdl,
    uint32_t *tablep)
{
	uint32_t items = 0;
	uint32_t *entryp;

	entryp = tablep + pg_offset;
	while (items < entries) {
		*(entryp + items) = 0;
		items++;
	}
	(void) ddi_dma_sync(dma_hdl, pg_offset * sizeof (uint32_t),
	    entries * sizeof (uint32_t), DDI_DMA_SYNC_FORDEV);
}

/*
 * agp_unbind_key()
 *
 * Description:
 * 	This function unbinds AGP memory from the gart table. It will clear
 * 	all the gart entries related to this agp memory.
 *
 * Arguments:
 * 	softstate		driver soft state pointer
 * 	entryp			key table entity pointer
 *
 * Returns:
 * 	EINVAL		invalid key table entity pointer
 * 	0		success
 *
 */
static int
agp_unbind_key(agpgart_softstate_t *softstate, keytable_ent_t *entryp)
{
	int retval = 0;

	ASSERT(entryp);
	ASSERT((entryp->kte_key >= 0) && (entryp->kte_key < AGP_MAXKEYS));

	if (!entryp->kte_bound) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_unbind_key: key = 0x%x, not bound",
		    entryp->kte_key));
		return (EINVAL);
	}
	if (entryp->kte_refcnt) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_unbind_key: memory is exported to users"));
		return (EINVAL);
	}

	ASSERT((entryp->kte_pgoff + entryp->kte_pages) <=
	    AGP_MB2PAGES(softstate->asoft_info.agpki_apersize));
	ASSERT((softstate->asoft_devreg.agprd_arctype != ARC_UNKNOWN));

	switch (softstate->asoft_devreg.agprd_arctype) {
	case ARC_IGD810:
	case ARC_IGD830:
		retval = lyr_i8xx_remove_from_gtt(
		    entryp->kte_pgoff, entryp->kte_pages,
		    &softstate->asoft_devreg);
		if (retval) {
			AGPDB_PRINT2((CE_WARN,
			    "agp_unbind_key: Key = 0x%x, clear table error",
			    entryp->kte_key));
			return (EIO);
		}
		break;
	case ARC_INTELAGP:
	case ARC_AMD64AGP:
		agp_remove_from_gart(entryp->kte_pgoff,
		    entryp->kte_pages,
		    softstate->gart_dma_handle,
		    (uint32_t *)softstate->gart_vbase);
		/* Flush GTLB table */
		lyr_flush_gart_cache(&softstate->asoft_devreg);

		break;
	}

	entryp->kte_bound = 0;

	return (0);
}

/*
 * agp_dealloc_kmem()
 *
 * Description:
 * 	This function deallocates dma memory resources for userland
 * 	applications.
 *
 * Arguments:
 * 	entryp		keytable entity pointer
 */
static void
agp_dealloc_kmem(keytable_ent_t *entryp)
{
	kmem_free(entryp->kte_pfnarray, sizeof (pfn_t) * entryp->kte_pages);
	entryp->kte_pfnarray = NULL;

	(void) ddi_dma_unbind_handle(KMEMP(entryp->kte_memhdl)->kmem_handle);
	KMEMP(entryp->kte_memhdl)->kmem_cookies_num = 0;
	ddi_dma_mem_free(&KMEMP(entryp->kte_memhdl)->kmem_acchdl);
	KMEMP(entryp->kte_memhdl)->kmem_acchdl = NULL;
	KMEMP(entryp->kte_memhdl)->kmem_reallen = 0;
	KMEMP(entryp->kte_memhdl)->kmem_kvaddr = NULL;

	ddi_dma_free_handle(&(KMEMP(entryp->kte_memhdl)->kmem_handle));
	KMEMP(entryp->kte_memhdl)->kmem_handle = NULL;

	kmem_free(entryp->kte_memhdl, sizeof (agp_kmem_handle_t));
	entryp->kte_memhdl = NULL;
}

/*
 * agp_dealloc_mem()
 *
 * Description:
 * 	This function deallocates physical memory resources allocated for
 *	userland applications.
 *
 * Arguments:
 * 	st		driver soft state pointer
 * 	entryp		key table entity pointer
 *
 * Returns:
 * 	-1		not a valid memory type or the memory is mapped by
 * 			user area applications
 * 	0		success
 */
static int
agp_dealloc_mem(agpgart_softstate_t *st, keytable_ent_t	*entryp)
{

	ASSERT(entryp);
	ASSERT(st);
	ASSERT(entryp->kte_memhdl);
	ASSERT(mutex_owned(&st->asoft_instmutex));

	/* auto unbind here */
	if (entryp->kte_bound && !entryp->kte_refcnt) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_dealloc_mem: key=0x%x, auto unbind",
		    entryp->kte_key));

		/*
		 * agp_dealloc_mem may be called indirectly by agp_detach.
		 * In the agp_detach function, agpgart_close is already
		 * called which will free the gart table. agp_unbind_key
		 * will panic if no valid gart table exists. So test if
		 * gart table exsits here.
		 */
		if (st->asoft_opened)
			(void) agp_unbind_key(st, entryp);
	}
	if (entryp->kte_refcnt) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_dealloc_mem: memory is exported to users"));
		return (-1);
	}

	switch (entryp->kte_type) {
	case AGP_NORMAL:
	case AGP_PHYSICAL:
		agp_dealloc_kmem(entryp);
		break;
	default:
		return (-1);
	}

	return (0);
}

/*
 * agp_del_allkeys()
 *
 * Description:
 * 	This function calls agp_dealloc_mem to release all the agp memory
 *	resource allocated.
 *
 * Arguments:
 * 	softsate	driver soft state pointer
 * Returns:
 * 	-1		can not free all agp memory
 * 	0		success
 *
 */
static int
agp_del_allkeys(agpgart_softstate_t *softstate)
{
	int key;
	int ret = 0;

	ASSERT(softstate);
	for (key = 0; key < AGP_MAXKEYS; key++) {
		if (softstate->asoft_table[key].kte_memhdl != NULL) {
			/*
			 * Check if we can free agp memory now.
			 * If agp memory is exported to user
			 * applications, agp_dealloc_mem will fail.
			 */
			if (agp_dealloc_mem(softstate,
			    &softstate->asoft_table[key]))
				ret = -1;
		}
	}

	return (ret);
}

/*
 * pfn2gartentry()
 *
 * Description:
 *	This function converts a physical address to GART entry.
 *	For AMD64, hardware only support addresses below 40bits,
 *	about 1024G physical address, so the largest pfn
 *	number is below 28 bits. Please refer to GART and GTT entry
 *	format table in agpdefs.h for entry format. Intel IGD only
 * 	only supports GTT entry below 1G. Intel AGP only supports
 * 	GART entry below 4G.
 *
 * Arguments:
 * 	arc_type		system agp arc type
 * 	pfn			page frame number
 * 	itemv			the entry item to be returned
 * Returns:
 * 	-1			not a invalid page frame
 * 	0			conversion success
 */
static int
pfn2gartentry(agp_arc_type_t arc_type, pfn_t pfn, uint32_t *itemv)
{
	uint64_t paddr;

	paddr = (uint64_t)pfn << AGP_PAGE_SHIFT;
	AGPDB_PRINT1((CE_NOTE, "checking pfn number %lu for type %d",
	    pfn, arc_type));

	switch (arc_type) {
	case ARC_INTELAGP:
	{
		/* Only support 32-bit hardware address */
		if ((paddr & AGP_INTEL_POINTER_MASK) != 0) {
			AGPDB_PRINT2((CE_WARN,
			    "INTEL AGP Hardware only support 32 bits"));
			return (-1);
		}
		*itemv =  (pfn << AGP_PAGE_SHIFT) | AGP_ENTRY_VALID;

		break;
	}
	case ARC_AMD64AGP:
	{
		uint32_t value1, value2;
		/* Physaddr should not exceed 40-bit */
		if ((paddr & AMD64_POINTER_MASK) != 0) {
			AGPDB_PRINT2((CE_WARN,
			    "AMD64 GART hardware only supoort 40 bits"));
			return (-1);
		}
		value1 = (uint32_t)pfn >> 20;
		value1 <<= 4;
		value2 = (uint32_t)pfn << 12;

		*itemv = value1 | value2 | AMD64_ENTRY_VALID;
		break;
	}
	case ARC_IGD810:
		if ((paddr & I810_POINTER_MASK) != 0) {
			AGPDB_PRINT2((CE_WARN,
			    "Intel i810 only support 30 bits"));
			return (-1);
		}
		break;

	case ARC_IGD830:
		if ((paddr & GTT_POINTER_MASK) != 0) {
			AGPDB_PRINT2((CE_WARN,
			    "Intel IGD only support 32 bits"));
			return (-1);
		}
		break;
	default:
		AGPDB_PRINT2((CE_WARN,
		    "pfn2gartentry: arc type = %d, not support", arc_type));
		return (-1);
	}
	return (0);
}

/*
 * Check allocated physical pages validity, only called in DEBUG
 * mode.
 */
static int
agp_check_pfns(agp_arc_type_t arc_type, pfn_t *pfnarray, int items)
{
	int count;
	uint32_t ret;

	for (count = 0; count < items; count++) {
		if (pfn2gartentry(arc_type, pfnarray[count], &ret))
			break;
	}
	if (count < items)
		return (-1);
	else
		return (0);
}

/*
 * kmem_getpfns()
 *
 * Description:
 * 	This function gets page frame numbers from dma handle.
 *
 * Arguments:
 * 	dma_handle		dma hanle allocated by ddi_dma_alloc_handle
 * 	dma_cookip		dma cookie pointer
 * 	cookies_num		cookies number
 * 	pfnarray		array to store page frames
 *
 * Returns:
 *	0		success
 */
static int
kmem_getpfns(
    ddi_dma_handle_t dma_handle,
    ddi_dma_cookie_t *dma_cookiep,
    int cookies_num,
    pfn_t *pfnarray)
{
	int	num_cookies;
	int	index = 0;

	num_cookies = cookies_num;

	while (num_cookies > 0) {
		uint64_t ck_startaddr, ck_length, ck_end;
		ck_startaddr = dma_cookiep->dmac_address;
		ck_length = dma_cookiep->dmac_size;

		ck_end = ck_startaddr + ck_length;
		while (ck_startaddr < ck_end) {
			pfnarray[index] = (pfn_t)ck_startaddr >> AGP_PAGE_SHIFT;
			ck_startaddr += AGP_PAGE_SIZE;
			index++;
		}

		num_cookies--;
		if (num_cookies > 0) {
			ddi_dma_nextcookie(dma_handle, dma_cookiep);
		}
	}

	return (0);
}

static int
copyinfo(agpgart_softstate_t *softstate, agp_info_t *info)
{
	switch (softstate->asoft_devreg.agprd_arctype) {
	case ARC_IGD810:
	case ARC_IGD830:
		info->agpi_version.agpv_major = 0;
		info->agpi_version.agpv_minor = 0;
		info->agpi_devid = softstate->asoft_info.agpki_mdevid;
		info->agpi_mode = 0;
		break;
	case ARC_INTELAGP:
	case ARC_AMD64AGP:
		info->agpi_version = softstate->asoft_info.agpki_tver;
		info->agpi_devid = softstate->asoft_info.agpki_tdevid;
		info->agpi_mode = softstate->asoft_info.agpki_tstatus;
		break;
	default:
		AGPDB_PRINT2((CE_WARN, "copyinfo: UNKNOW ARC"));
		return (-1);
	}
	/*
	 * 64bit->32bit conversion possible
	 */
	info->agpi_aperbase = softstate->asoft_info.agpki_aperbase;
	info->agpi_apersize = softstate->asoft_info.agpki_apersize;
	info->agpi_pgtotal = softstate->asoft_pgtotal;
	info->agpi_pgsystem = info->agpi_pgtotal;
	info->agpi_pgused = softstate->asoft_pgused;

	return (0);
}

static uint32_t
agp_v2_setup(uint32_t tstatus, uint32_t mstatus, uint32_t mode)
{
	uint32_t cmd;
	int rq, sba, over4g, fw, rate;

	/*
	 * tstatus: target device status
	 * mstatus: master device status
	 * mode: the agp mode to be sent
	 */

	/*
	 * RQ - Request Queue size
	 * set RQ to the min of mode and tstatus
	 * if mode set a RQ larger than hardware can support,
	 * use the max RQ which hardware can support.
	 * tstatus & AGPSTAT_RQ_MASK is the max RQ hardware can support
	 * Corelogic will enqueue agp transaction
	 */
	rq = mode & AGPSTAT_RQ_MASK;
	if ((tstatus & AGPSTAT_RQ_MASK) < rq)
		rq = tstatus & AGPSTAT_RQ_MASK;

	/*
	 * SBA - Sideband Addressing
	 *
	 * Sideband Addressing provides an additional bus to pass requests
	 * (address and command) to the target from the master.
	 *
	 * set SBA if all three support it
	 */
	sba = (tstatus & AGPSTAT_SBA) & (mstatus & AGPSTAT_SBA)
	    & (mode & AGPSTAT_SBA);

	/* set OVER4G  if all three support it */
	over4g = (tstatus & AGPSTAT_OVER4G) & (mstatus & AGPSTAT_OVER4G)
	    & (mode & AGPSTAT_OVER4G);

	/*
	 * FW - fast write
	 *
	 * acceleration of memory write transactions from the corelogic to the
	 * A.G.P. master device acting like a PCI target.
	 *
	 * set FW if all three support it
	 */
	fw = (tstatus & AGPSTAT_FW) & (mstatus & AGPSTAT_FW)
	    & (mode & AGPSTAT_FW);

	/*
	 * figure out the max rate
	 * AGP v2 support: 4X, 2X, 1X speed
	 * status bit		meaning
	 * ---------------------------------------------
	 * 7:3			others
	 * 3			0 stand for V2 support
	 * 0:2			001:1X, 010:2X, 100:4X
	 * ----------------------------------------------
	 */
	rate = (tstatus & AGPSTAT_RATE_MASK) & (mstatus & AGPSTAT_RATE_MASK)
	    & (mode & AGPSTAT_RATE_MASK);
	if (rate & AGP2_RATE_4X)
		rate = AGP2_RATE_4X;
	else if (rate & AGP2_RATE_2X)
		rate = AGP2_RATE_2X;
	else
		rate = AGP2_RATE_1X;

	cmd = rq | sba | over4g | fw | rate;
	/* enable agp mode */
	cmd |= AGPCMD_AGPEN;

	return (cmd);
}

static uint32_t
agp_v3_setup(uint32_t tstatus, uint32_t mstatus, uint32_t mode)
{
	uint32_t cmd = 0;
	uint32_t rq, arqsz, cal, sba, over4g, fw, rate;

	/*
	 * tstatus: target device status
	 * mstatus: master device status
	 * mode: the agp mode to be set
	 */

	/*
	 * RQ - Request Queue size
	 * Set RQ to the min of mode and tstatus
	 * If mode set a RQ larger than hardware can support,
	 * use the max RQ which hardware can support.
	 * tstatus & AGPSTAT_RQ_MASK is the max RQ hardware can support
	 * Corelogic will enqueue agp transaction;
	 */
	rq = mode & AGPSTAT_RQ_MASK;
	if ((tstatus & AGPSTAT_RQ_MASK) < rq)
		rq = tstatus & AGPSTAT_RQ_MASK;

	/*
	 * ARQSZ - Asynchronous Request Queue size
	 * Set the value equal to tstatus.
	 * Don't allow the mode register to override values
	 */
	arqsz = tstatus & AGPSTAT_ARQSZ_MASK;

	/*
	 * CAL - Calibration cycle
	 * Set to the min of tstatus and mstatus
	 * Don't allow override by mode register
	 */
	cal = tstatus & AGPSTAT_CAL_MASK;
	if ((mstatus & AGPSTAT_CAL_MASK) < cal)
		cal = mstatus & AGPSTAT_CAL_MASK;

	/*
	 * SBA - Sideband Addressing
	 *
	 * Sideband Addressing provides an additional bus to pass requests
	 * (address and command) to the target from the master.
	 *
	 * SBA in agp v3.0 must be set
	 */
	sba = AGPCMD_SBAEN;

	/* GART64B is not set since no hardware supports it now */

	/* Set OVER4G if all three support it */
	over4g = (tstatus & AGPSTAT_OVER4G) & (mstatus & AGPSTAT_OVER4G)
	    & (mode & AGPSTAT_OVER4G);

	/*
	 * FW - fast write
	 *
	 * Acceleration of memory write transactions from the corelogic to the
	 * A.G.P. master device acting like a PCI target.
	 *
	 * Always set FW in AGP 3.0
	 */
	fw = (tstatus & AGPSTAT_FW) & (mstatus & AGPSTAT_FW)
	    & (mode & AGPSTAT_FW);

	/*
	 * Figure out the max rate
	 *
	 * AGP v3 support: 8X, 4X speed
	 *
	 * status bit		meaning
	 * ---------------------------------------------
	 * 7:3			others
	 * 3			1 stand for V3 support
	 * 0:2			001:4X, 010:8X, 011:4X,8X
	 * ----------------------------------------------
	 */
	rate = (tstatus & AGPSTAT_RATE_MASK) & (mstatus & AGPSTAT_RATE_MASK)
	    & (mode & AGPSTAT_RATE_MASK);
	if (rate & AGP3_RATE_8X)
		rate = AGP3_RATE_8X;
	else
		rate = AGP3_RATE_4X;

	cmd = rq | arqsz | cal | sba | over4g | fw | rate;
	/* Enable AGP mode */
	cmd |= AGPCMD_AGPEN;

	return (cmd);
}

static int
agp_setup(agpgart_softstate_t *softstate, uint32_t mode)
{
	uint32_t tstatus, mstatus;
	uint32_t agp_mode;

	tstatus = softstate->asoft_info.agpki_tstatus;
	mstatus = softstate->asoft_info.agpki_mstatus;

	/*
	 * There are three kinds of AGP mode. AGP mode 1.0, 2.0, 3.0
	 * AGP mode 2.0 is fully compatible with AGP mode 1.0, so we
	 * only check 2.0 and 3.0 mode. AGP 3.0 device can work in
	 * two AGP 2.0 or AGP 3.0 mode. By checking AGP status register,
	 * we can get which mode it is working at. The working mode of
	 * AGP master and AGP target must be consistent. That is, both
	 * of them must work on AGP 3.0 mode or AGP 2.0 mode.
	 */
	if ((softstate->asoft_info.agpki_tver.agpv_major == 3) &&
	    (tstatus & AGPSTAT_MODE3)) {
		/* Master device should be 3.0 mode, too */
		if ((softstate->asoft_info.agpki_mver.agpv_major != 3) ||
		    ((mstatus & AGPSTAT_MODE3) == 0))
			return (EIO);

		agp_mode = agp_v3_setup(tstatus, mstatus, mode);
		/* Write to the AGPCMD register of target and master devices */
		if (lyr_set_agp_cmd(agp_mode,
		    &softstate->asoft_devreg))
			return (EIO);

		softstate->asoft_mode = agp_mode;

		return (0);
	}

	/*
	 * If agp taget device doesn't work in AGP 3.0 mode,
	 * it must work in AGP 2.0 mode. And make sure
	 * master device work in AGP 2.0 mode too
	 */
	if ((softstate->asoft_info.agpki_mver.agpv_major == 3) &&
	    (mstatus & AGPSTAT_MODE3))
		return (EIO);

	agp_mode = agp_v2_setup(tstatus, mstatus, mode);
	if (lyr_set_agp_cmd(agp_mode, &softstate->asoft_devreg))
		return (EIO);
	softstate->asoft_mode = agp_mode;

	return (0);
}

/*
 * agp_alloc_kmem()
 *
 * Description:
 * 	This function allocates physical memory for userland applications
 * 	by ddi interfaces. This function can also be called to allocate
 *	small phsyical contiguous pages, usually tens of kilobytes.
 *
 * Arguments:
 * 	softsate	driver soft state pointer
 * 	length		memory size
 *
 * Returns:
 * 	entryp		new keytable entity pointer
 * 	NULL		no keytable slot available or no physical
 *			memory available
 */
static keytable_ent_t *
agp_alloc_kmem(agpgart_softstate_t *softstate, size_t length, int type)
{
	keytable_ent_t	keyentry;
	keytable_ent_t	*entryp;
	int		ret;

	ASSERT(AGP_ALIGNED(length));

	bzero(&keyentry, sizeof (keytable_ent_t));

	keyentry.kte_pages = AGP_BYTES2PAGES(length);
	keyentry.kte_type = type;

	/*
	 * Set dma_attr_sgllen to assure contiguous physical pages
	 */
	if (type == AGP_PHYSICAL)
		agpgart_dma_attr.dma_attr_sgllen = 1;
	else
		agpgart_dma_attr.dma_attr_sgllen = (int)keyentry.kte_pages;

	/* 4k size pages */
	keyentry.kte_memhdl = kmem_zalloc(sizeof (agp_kmem_handle_t), KM_SLEEP);

	if (ddi_dma_alloc_handle(softstate->asoft_dip,
	    &agpgart_dma_attr,
	    DDI_DMA_SLEEP, NULL,
	    &(KMEMP(keyentry.kte_memhdl)->kmem_handle))) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_alloc_kmem: ddi_dma_allco_hanlde error"));
		goto err4;
	}

	if ((ret = ddi_dma_mem_alloc(
	    KMEMP(keyentry.kte_memhdl)->kmem_handle,
	    length,
	    &gart_dev_acc_attr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL,
	    &KMEMP(keyentry.kte_memhdl)->kmem_kvaddr,
	    &KMEMP(keyentry.kte_memhdl)->kmem_reallen,
	    &KMEMP(keyentry.kte_memhdl)->kmem_acchdl)) != 0) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_alloc_kmem: ddi_dma_mem_alloc error"));

		goto err3;
	}

	ret = ddi_dma_addr_bind_handle(
	    KMEMP(keyentry.kte_memhdl)->kmem_handle,
	    NULL,
	    KMEMP(keyentry.kte_memhdl)->kmem_kvaddr,
	    length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &KMEMP(keyentry.kte_memhdl)->kmem_dcookie,
	    &KMEMP(keyentry.kte_memhdl)->kmem_cookies_num);

	/*
	 * Even dma_attr_sgllen = 1, ddi_dma_addr_bind_handle may return more
	 * than one cookie, we check this in the if statement.
	 */

	if ((ret != DDI_DMA_MAPPED) ||
	    ((agpgart_dma_attr.dma_attr_sgllen == 1) &&
	    (KMEMP(keyentry.kte_memhdl)->kmem_cookies_num != 1))) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_alloc_kmem: can not alloc physical memory properly"));
		goto err2;
	}

	keyentry.kte_pfnarray = (pfn_t *)kmem_zalloc(sizeof (pfn_t) *
	    keyentry.kte_pages, KM_SLEEP);

	if (kmem_getpfns(
	    KMEMP(keyentry.kte_memhdl)->kmem_handle,
	    &KMEMP(keyentry.kte_memhdl)->kmem_dcookie,
	    KMEMP(keyentry.kte_memhdl)->kmem_cookies_num,
	    keyentry.kte_pfnarray)) {
		AGPDB_PRINT2((CE_WARN, "agp_alloc_kmem: get pfn array error"));
		goto err1;
	}

	ASSERT(!agp_check_pfns(softstate->asoft_devreg.agprd_arctype,
	    keyentry.kte_pfnarray, keyentry.kte_pages));
	if (agp_check_pfns(softstate->asoft_devreg.agprd_arctype,
	    keyentry.kte_pfnarray, keyentry.kte_pages))
		goto err1;
	entryp = agp_fill_empty_keyent(softstate, &keyentry);
	if (!entryp) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_alloc_kmem: agp_fill_empty_keyent error"));

		goto err1;
	}
	ASSERT((entryp->kte_key >= 0) && (entryp->kte_key < AGP_MAXKEYS));

	return (entryp);

err1:
	kmem_free(keyentry.kte_pfnarray, sizeof (pfn_t) * keyentry.kte_pages);
	keyentry.kte_pfnarray = NULL;
	(void) ddi_dma_unbind_handle(KMEMP(keyentry.kte_memhdl)->kmem_handle);
	KMEMP(keyentry.kte_memhdl)->kmem_cookies_num = 0;
err2:
	ddi_dma_mem_free(&KMEMP(keyentry.kte_memhdl)->kmem_acchdl);
	KMEMP(keyentry.kte_memhdl)->kmem_acchdl = NULL;
	KMEMP(keyentry.kte_memhdl)->kmem_reallen = 0;
	KMEMP(keyentry.kte_memhdl)->kmem_kvaddr = NULL;
err3:
	ddi_dma_free_handle(&(KMEMP(keyentry.kte_memhdl)->kmem_handle));
	KMEMP(keyentry.kte_memhdl)->kmem_handle = NULL;
err4:
	kmem_free(keyentry.kte_memhdl, sizeof (agp_kmem_handle_t));
	keyentry.kte_memhdl = NULL;
	return (NULL);

}

/*
 * agp_alloc_mem()
 *
 * Description:
 * 	This function allocate physical memory for userland applications,
 * 	in order to save kernel virtual space, we use the direct mapping
 * 	memory interface if it is available.
 *
 * Arguments:
 * 	st		driver soft state pointer
 * 	length		memory size
 * 	type		AGP_NORMAL: normal agp memory, AGP_PHISYCAL: specical
 *			memory type for intel i810 IGD
 *
 * Returns:
 * 	NULL 	Invalid memory type or can not allocate memory
 * 	Keytable entry pointer returned by agp_alloc_kmem
 */
static keytable_ent_t *
agp_alloc_mem(agpgart_softstate_t *st, size_t length, int type)
{

	/*
	 * AGP_PHYSICAL type require contiguous physical pages exported
	 * to X drivers, like i810 HW cursor, ARGB cursor. the number of
	 * pages needed is usuallysmall and contiguous, 4K, 16K. So we
	 * use DDI interface to allocated such memory. And X use xsvc
	 * drivers to map this memory into its own address space.
	 */
	ASSERT(st);

	switch (type) {
	case AGP_NORMAL:
	case AGP_PHYSICAL:
		return (agp_alloc_kmem(st, length, type));
	default:
		return (NULL);
	}
}

/*
 * free_gart_table()
 *
 * Description:
 * 	This function frees the gart table memory allocated by driver.
 * 	Must disable gart table before calling this function.
 *
 * Arguments:
 * 	softstate		driver soft state pointer
 *
 */
static void
free_gart_table(agpgart_softstate_t *st)
{

	if (st->gart_dma_handle == NULL)
		return;

	(void) ddi_dma_unbind_handle(st->gart_dma_handle);
	ddi_dma_mem_free(&st->gart_dma_acc_handle);
	st->gart_dma_acc_handle = NULL;
	ddi_dma_free_handle(&st->gart_dma_handle);
	st->gart_dma_handle = NULL;
	st->gart_vbase = 0;
	st->gart_size = 0;
}

/*
 * alloc_gart_table()
 *
 * Description:
 * 	This function allocates one physical continuous gart table.
 * 	INTEL integrated video device except i810 have their special
 * 	video bios; No need to allocate gart table for them.
 *
 * Arguments:
 * 	st		driver soft state pointer
 *
 * Returns:
 * 	0		success
 * 	-1		can not allocate gart tabl
 */
static int
alloc_gart_table(agpgart_softstate_t *st)
{
	int			num_pages;
	size_t			table_size;
	int			ret = DDI_SUCCESS;
	ddi_dma_cookie_t	cookie;
	uint32_t		num_cookies;

	num_pages = AGP_MB2PAGES(st->asoft_info.agpki_apersize);

	/*
	 * Only 40-bit maximum physical memory is supported by today's
	 * AGP hardware (32-bit gart tables can hold 40-bit memory addresses).
	 * No one supports 64-bit gart entries now, so the size of gart
	 * entries defaults to 32-bit though AGP3.0 specifies the possibility
	 * of 64-bit gart entries.
	 */

	table_size = num_pages * (sizeof (uint32_t));

	/*
	 * Only AMD64 can put gart table above 4G, 40 bits at maximum
	 */
	if (st->asoft_devreg.agprd_arctype == ARC_AMD64AGP)
		garttable_dma_attr.dma_attr_addr_hi = 0xffffffffffLL;
	else
		garttable_dma_attr.dma_attr_addr_hi = 0xffffffffU;
	/* Allocate physical continuous page frame for gart table */
	if (ret = ddi_dma_alloc_handle(st->asoft_dip,
	    &garttable_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL, &st->gart_dma_handle)) {
		AGPDB_PRINT2((CE_WARN,
		    "alloc_gart_table: ddi_dma_alloc_handle failed"));
		goto err3;
	}

	if (ret = ddi_dma_mem_alloc(st->gart_dma_handle,
	    table_size,
	    &gart_dev_acc_attr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL,
	    &st->gart_vbase,
	    &st->gart_size,
	    &st->gart_dma_acc_handle)) {
		AGPDB_PRINT2((CE_WARN,
		    "alloc_gart_table: ddi_dma_mem_alloc failed"));
		goto err2;

	}

	ret = ddi_dma_addr_bind_handle(st->gart_dma_handle,
	    NULL, st->gart_vbase,
	    table_size,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL,
	    &cookie,  &num_cookies);

	st->gart_pbase = cookie.dmac_address;

	if ((ret != DDI_DMA_MAPPED) || (num_cookies != 1)) {
		if (num_cookies > 1)
			(void) ddi_dma_unbind_handle(st->gart_dma_handle);
		AGPDB_PRINT2((CE_WARN,
		    "alloc_gart_table: alloc contiguous phys memory failed"));
		goto err1;
	}

	return (0);
err1:
	ddi_dma_mem_free(&st->gart_dma_acc_handle);
	st->gart_dma_acc_handle = NULL;
err2:
	ddi_dma_free_handle(&st->gart_dma_handle);
	st->gart_dma_handle = NULL;
err3:
	st->gart_pbase = 0;
	st->gart_size = 0;
	st->gart_vbase = 0;

	return (-1);
}

/*
 * agp_add_to_gart()
 *
 * Description:
 * 	This function fills the gart table entries by a given page frame number
 * 	array and set up the agp aperture page to physical memory page
 * 	translation.
 * Arguments:
 * 	type		valid system arc types ARC_AMD64AGP, ARC_INTELAGP,
 * 			ARC_AMD64AGP
 * 	pfnarray	allocated physical page frame number array
 * 	pg_offset	agp aperture start page to be bound
 * 	entries		the number of pages to be bound
 * 	dma_hdl		gart table dma memory handle
 * 	tablep		gart table kernel virtual address
 * Returns:
 * 	-1		failed
 * 	0		success
 */
static int
agp_add_to_gart(
    agp_arc_type_t type,
    pfn_t *pfnarray,
    uint32_t pg_offset,
    uint32_t entries,
    ddi_dma_handle_t dma_hdl,
    uint32_t *tablep)
{
	int items = 0;
	uint32_t *entryp;
	uint32_t itemv;

	entryp = tablep + pg_offset;
	while (items < entries) {
		if (pfn2gartentry(type, pfnarray[items], &itemv))
			break;
		*(entryp + items) = itemv;
		items++;
	}
	if (items < entries)
		return (-1);

	(void) ddi_dma_sync(dma_hdl, pg_offset * sizeof (uint32_t),
	    entries * sizeof (uint32_t), DDI_DMA_SYNC_FORDEV);

	return (0);
}

/*
 * agp_bind_key()
 *
 * Description:
 * 	This function will call low level gart table access functions to
 * 	set up gart table translation. Also it will do some sanity
 * 	checking on key table entry.
 *
 * Arguments:
 * 	softstate		driver soft state pointer
 * 	keyent			key table entity pointer to be bound
 * 	pg_offset		aperture start page to be bound
 * Returns:
 * 	EINVAL			not a valid operation
 */
static int
agp_bind_key(agpgart_softstate_t *softstate,
    keytable_ent_t  *keyent, uint32_t  pg_offset)
{
	uint64_t pg_end;
	int ret = 0;

	ASSERT(keyent);
	ASSERT((keyent->kte_key >= 0) && (keyent->kte_key < AGP_MAXKEYS));
	ASSERT(mutex_owned(&softstate->asoft_instmutex));

	pg_end = pg_offset + keyent->kte_pages;

	if (pg_end > AGP_MB2PAGES(softstate->asoft_info.agpki_apersize)) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_bind_key: key=0x%x,exceed aper range",
		    keyent->kte_key));

		return (EINVAL);
	}

	if (agp_check_off(softstate->asoft_table,
	    pg_offset, keyent->kte_pages)) {
		AGPDB_PRINT2((CE_WARN,
		    "agp_bind_key: pg_offset=0x%x, pages=0x%lx overlaped",
		    pg_offset, keyent->kte_pages));
		return (EINVAL);
	}

	ASSERT(keyent->kte_pfnarray != NULL);

	switch (softstate->asoft_devreg.agprd_arctype) {
	case ARC_IGD810:
	case ARC_IGD830:
		ret = lyr_i8xx_add_to_gtt(pg_offset, keyent,
		    &softstate->asoft_devreg);
		if (ret)
			return (EIO);
		break;
	case ARC_INTELAGP:
	case ARC_AMD64AGP:
		ret =  agp_add_to_gart(
		    softstate->asoft_devreg.agprd_arctype,
		    keyent->kte_pfnarray,
		    pg_offset,
		    keyent->kte_pages,
		    softstate->gart_dma_handle,
		    (uint32_t *)softstate->gart_vbase);
		if (ret)
			return (EINVAL);
		/* Flush GTLB table */
		lyr_flush_gart_cache(&softstate->asoft_devreg);
		break;
	default:
		AGPDB_PRINT2((CE_WARN,
		    "agp_bind_key: arc type = 0x%x unsupported",
		    softstate->asoft_devreg.agprd_arctype));
		return (EINVAL);
	}
	return (0);
}

static int
agpgart_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	agpgart_softstate_t *softstate;

	if (cmd != DDI_ATTACH) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_attach: only attach op supported"));
		return (DDI_FAILURE);
	}
	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(agpgart_glob_soft_handle, instance)
	    != DDI_SUCCESS) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_attach: soft state zalloc failed"));
		goto err1;

	}
	softstate = ddi_get_soft_state(agpgart_glob_soft_handle, instance);
	mutex_init(&softstate->asoft_instmutex, NULL, MUTEX_DRIVER, NULL);
	softstate->asoft_dip = dip;
	/*
	 * Allocate LDI identifier for agpgart driver
	 * Agpgart driver is the kernel consumer
	 */
	if (ldi_ident_from_dip(dip, &softstate->asoft_li)) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_attach: LDI indentifier allcation failed"));
		goto err2;
	}

	softstate->asoft_devreg.agprd_arctype = ARC_UNKNOWN;
	/* Install agp kstat */
	if (agp_init_kstats(softstate)) {
		AGPDB_PRINT2((CE_WARN, "agpgart_attach: init kstats error"));
		goto err3;
	}
	/*
	 * devfs will create /dev/agpgart
	 * and  /devices/agpgart:agpgart
	 */

	if (ddi_create_minor_node(dip, AGPGART_DEVNODE, S_IFCHR,
	    AGP_INST2MINOR(instance),
	    DDI_NT_AGP_PSEUDO, 0)) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_attach: Can not create minor node"));
		goto err4;
	}

	softstate->asoft_table = kmem_zalloc(
	    AGP_MAXKEYS * (sizeof (keytable_ent_t)),
	    KM_SLEEP);

	list_head_init(&softstate->mapped_list);

	return (DDI_SUCCESS);
err4:
	agp_fini_kstats(softstate);
err3:
	ldi_ident_release(softstate->asoft_li);
err2:
	ddi_soft_state_free(agpgart_glob_soft_handle, instance);
err1:
	return (DDI_FAILURE);
}

static int
agpgart_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	agpgart_softstate_t *st;

	instance = ddi_get_instance(dip);

	st = ddi_get_soft_state(agpgart_glob_soft_handle, instance);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	/*
	 * Caller should free all the memory allocated explicitly.
	 * We release the memory allocated by caller which is not
	 * properly freed. mutex_enter here make sure assertion on
	 * softstate mutex success in agp_dealloc_mem.
	 */
	mutex_enter(&st->asoft_instmutex);
	if (agp_del_allkeys(st)) {
		AGPDB_PRINT2((CE_WARN, "agpgart_detach: agp_del_allkeys err"));
		AGPDB_PRINT2((CE_WARN,
		    "you might free agp memory exported to your applications"));

		mutex_exit(&st->asoft_instmutex);
		return (DDI_FAILURE);
	}
	mutex_exit(&st->asoft_instmutex);
	if (st->asoft_table) {
		kmem_free(st->asoft_table,
		    AGP_MAXKEYS * (sizeof (keytable_ent_t)));
		st->asoft_table = 0;
	}

	struct list_head	*entry,	*temp,	*head;
	igd_gtt_seg_t	*gttseg;
	list_head_for_each_safe(entry, temp, &st->mapped_list) {
		gttseg = entry->gttseg;
		list_head_del(entry);
		kmem_free(entry, sizeof (*entry));
		kmem_free(gttseg->igs_phyaddr,
		    sizeof (uint32_t) * gttseg->igs_npage);
		kmem_free(gttseg, sizeof (igd_gtt_seg_t));
	}
	head = &st->mapped_list;
	kmem_free(head->next,
	    AGP_HASH_NODE * sizeof (struct list_head));
	head->next = NULL;

	ddi_remove_minor_node(dip, AGPGART_DEVNODE);
	agp_fini_kstats(st);
	ldi_ident_release(st->asoft_li);
	mutex_destroy(&st->asoft_instmutex);
	ddi_soft_state_free(agpgart_glob_soft_handle, instance);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
agpgart_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp)
{
	agpgart_softstate_t *st;
	int instance, rval = DDI_FAILURE;
	dev_t dev;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = AGP_DEV2INST(dev);
		st = ddi_get_soft_state(agpgart_glob_soft_handle, instance);
		if (st != NULL) {
			mutex_enter(&st->asoft_instmutex);
			*resultp = st->asoft_dip;
			mutex_exit(&st->asoft_instmutex);
			rval = DDI_SUCCESS;
		} else
			*resultp = NULL;

		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = AGP_DEV2INST(dev);
		*resultp = (void *)(uintptr_t)instance;
		rval = DDI_SUCCESS;

		break;
	default:
		break;
	}

	return (rval);
}

/*
 * agpgart_open()
 *
 * Description:
 * 	This function is the driver open entry point. If it is the
 * 	first time the agpgart driver is opened, the driver will
 * 	open other agp related layered drivers and set up the agpgart
 * 	table properly.
 *
 * Arguments:
 * 	dev			device number pointer
 * 	openflags		open flags
 *	otyp			OTYP_BLK, OTYP_CHR
 * 	credp			user's credential's struct pointer
 *
 * Returns:
 * 	ENXIO			operation error
 * 	EAGAIN			resoure temporarily unvailable
 * 	0			success
 */
/*ARGSUSED*/
static int
agpgart_open(dev_t *dev, int openflags, int otyp, cred_t *credp)
{
	int instance = AGP_DEV2INST(*dev);
	agpgart_softstate_t *softstate;
	int rc = 0;
	uint32_t devid;

	if (secpolicy_gart_access(credp)) {
		AGPDB_PRINT2((CE_WARN, "agpgart_open: permission denied"));
		return (EPERM);
	}
	softstate = ddi_get_soft_state(agpgart_glob_soft_handle, instance);
	if (softstate == NULL) {
		AGPDB_PRINT2((CE_WARN, "agpgart_open: get soft state err"));
		return (ENXIO);
	}

	mutex_enter(&softstate->asoft_instmutex);

	if (softstate->asoft_opened) {
		softstate->asoft_opened++;
		mutex_exit(&softstate->asoft_instmutex);
		return (0);
	}

	/*
	 * The driver is opened first time, so we initialize layered
	 * driver interface and softstate member here.
	 */
	softstate->asoft_pgused = 0;
	if (lyr_init(&softstate->asoft_devreg, softstate->asoft_li)) {
		AGPDB_PRINT2((CE_WARN, "agpgart_open: lyr_init failed"));
		mutex_exit(&softstate->asoft_instmutex);
		return (EAGAIN);
	}

	/* Call into layered driver */
	if (lyr_get_info(&softstate->asoft_info, &softstate->asoft_devreg)) {
		AGPDB_PRINT2((CE_WARN, "agpgart_open: lyr_get_info error"));
		lyr_end(&softstate->asoft_devreg);
		mutex_exit(&softstate->asoft_instmutex);
		return (EIO);
	}

	/*
	 * BIOS already set up gtt table for ARC_IGD830
	 */
	if (IS_INTEL_830(softstate->asoft_devreg.agprd_arctype)) {
		softstate->asoft_opened++;

		softstate->asoft_pgtotal =
		    get_max_pages(softstate->asoft_info.agpki_apersize);

		if (lyr_config_devices(&softstate->asoft_devreg)) {
			AGPDB_PRINT2((CE_WARN,
			    "agpgart_open: lyr_config_devices error"));
			lyr_end(&softstate->asoft_devreg);
			mutex_exit(&softstate->asoft_instmutex);

			return (EIO);
		}
		devid = softstate->asoft_info.agpki_mdevid;
		if (IS_INTEL_915(devid) ||
		    IS_INTEL_965(devid) ||
		    IS_INTEL_X33(devid) ||
		    IS_INTEL_G4X(devid)) {
			rc = ldi_ioctl(softstate->asoft_devreg.agprd_targethdl,
			    INTEL_CHIPSET_FLUSH_SETUP, 0, FKIOCTL, kcred, 0);
		}
		if (rc) {
			AGPDB_PRINT2((CE_WARN,
			    "agpgart_open: Intel chipset flush setup error"));
			lyr_end(&softstate->asoft_devreg);
			mutex_exit(&softstate->asoft_instmutex);
			return (EIO);
		}
		mutex_exit(&softstate->asoft_instmutex);
		return (0);
	}

	rc = alloc_gart_table(softstate);

	/*
	 * Allocate physically contiguous pages for AGP arc or
	 * i810 arc. If failed, divide aper_size by 2 to
	 * reduce gart table size until 4 megabytes. This
	 * is just a workaround for systems with very few
	 * physically contiguous memory.
	 */
	if (rc) {
		while ((softstate->asoft_info.agpki_apersize >= 4) &&
		    (alloc_gart_table(softstate))) {
			softstate->asoft_info.agpki_apersize >>= 1;
		}
		if (softstate->asoft_info.agpki_apersize >= 4)
			rc = 0;
	}

	if (rc != 0) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_open: alloc gart table failed"));
		lyr_end(&softstate->asoft_devreg);
		mutex_exit(&softstate->asoft_instmutex);
		return (EAGAIN);
	}

	softstate->asoft_pgtotal =
	    get_max_pages(softstate->asoft_info.agpki_apersize);
	/*
	 * BIOS doesn't initialize GTT for i810,
	 * So i810 GTT must be created by driver.
	 *
	 * Set up gart table and enable it.
	 */
	if (lyr_set_gart_addr(softstate->gart_pbase,
	    &softstate->asoft_devreg)) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_open: set gart table addr failed"));
		free_gart_table(softstate);
		lyr_end(&softstate->asoft_devreg);
		mutex_exit(&softstate->asoft_instmutex);
		return (EIO);
	}
	if (lyr_config_devices(&softstate->asoft_devreg)) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_open: lyr_config_devices failed"));
		free_gart_table(softstate);
		lyr_end(&softstate->asoft_devreg);
		mutex_exit(&softstate->asoft_instmutex);
		return (EIO);
	}

	softstate->asoft_opened++;
	mutex_exit(&softstate->asoft_instmutex);

	return (0);
}

/*
 * agpgart_close()
 *
 * Description:
 * 	agpgart_close will release resources allocated in the first open
 * 	and close other open layered drivers. Also it frees the memory
 *	allocated by ioctls.
 *
 * Arguments:
 * 	dev			device number
 * 	flag			file status flag
 *	otyp			OTYP_BLK, OTYP_CHR
 * 	credp			user's credential's struct pointer
 *
 * Returns:
 * 	ENXIO			not an error, to support "deferred attach"
 * 	0			success
 */
/*ARGSUSED*/
static int
agpgart_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int instance = AGP_DEV2INST(dev);
	agpgart_softstate_t *softstate;
	int rc = 0;
	uint32_t devid;

	softstate = ddi_get_soft_state(agpgart_glob_soft_handle, instance);
	if (softstate == NULL) {
		AGPDB_PRINT2((CE_WARN, "agpgart_close: get soft state err"));
		return (ENXIO);
	}

	mutex_enter(&softstate->asoft_instmutex);
	ASSERT(softstate->asoft_opened);


	/*
	 * If the last process close this device is not the controlling
	 * process, also release the control over agpgart driver here if the
	 * the controlling process fails to release the control before it
	 * close the driver.
	 */
	if (softstate->asoft_acquired == 1) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_close: auto release control over driver"));
		release_control(softstate);
	}

	devid = softstate->asoft_info.agpki_mdevid;
	if (IS_INTEL_915(devid) ||
	    IS_INTEL_965(devid) ||
	    IS_INTEL_X33(devid) ||
	    IS_INTEL_G4X(devid)) {
		rc = ldi_ioctl(softstate->asoft_devreg.agprd_targethdl,
		    INTEL_CHIPSET_FLUSH_FREE, 0, FKIOCTL, kcred, 0);
	}
	if (rc) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_open: Intel chipset flush free error"));
	}

	if (lyr_unconfig_devices(&softstate->asoft_devreg)) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_close: lyr_unconfig_device error"));
		mutex_exit(&softstate->asoft_instmutex);
		return (EIO);
	}
	softstate->asoft_agpen = 0;

	if (!IS_INTEL_830(softstate->asoft_devreg.agprd_arctype)) {
		free_gart_table(softstate);
	}

	lyr_end(&softstate->asoft_devreg);

	/*
	 * This statement must be positioned before agp_del_allkeys
	 * agp_dealloc_mem indirectly called by agp_del_allkeys
	 * will test this variable.
	 */
	softstate->asoft_opened = 0;

	/*
	 * Free the memory allocated by user applications which
	 * was never deallocated.
	 */
	(void) agp_del_allkeys(softstate);

	mutex_exit(&softstate->asoft_instmutex);

	return (0);
}

static int
ioctl_agpgart_info(agpgart_softstate_t  *softstate, void  *arg, int flags)
{
	agp_info_t infostruct;
#ifdef _MULTI_DATAMODEL
	agp_info32_t infostruct32;
#endif

	bzero(&infostruct, sizeof (agp_info_t));

#ifdef _MULTI_DATAMODEL
	bzero(&infostruct32, sizeof (agp_info32_t));
	if (ddi_model_convert_from(flags & FMODELS) == DDI_MODEL_ILP32) {
		if (copyinfo(softstate, &infostruct))
			return (EINVAL);

		agpinfo_default_to_32(infostruct, infostruct32);
		if (ddi_copyout(&infostruct32, arg,
		    sizeof (agp_info32_t), flags) != 0)
			return (EFAULT);

		return (0);
	}
#endif /* _MULTI_DATAMODEL */
	if (copyinfo(softstate, &infostruct))
		return (EINVAL);

	if (ddi_copyout(&infostruct, arg, sizeof (agp_info_t), flags) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
ioctl_agpgart_acquire(agpgart_softstate_t  *st)
{
	if (st->asoft_acquired) {
		AGPDB_PRINT2((CE_WARN, "ioctl_acquire: already acquired"));
		return (EBUSY);
	}
	acquire_control(st);
	return (0);
}

static int
ioctl_agpgart_release(agpgart_softstate_t  *st)
{
	if (is_controlling_proc(st) < 0) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_release: not a controlling process"));
		return (EPERM);
	}
	release_control(st);
	return (0);
}

static int
ioctl_agpgart_setup(agpgart_softstate_t  *st, void  *arg, int flags)
{
	agp_setup_t data;
	int rc = 0;

	if (is_controlling_proc(st) < 0) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_setup: not a controlling process"));
		return (EPERM);
	}

	if (!IS_TRUE_AGP(st->asoft_devreg.agprd_arctype)) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_setup: no true agp bridge"));
		return (EINVAL);
	}

	if (ddi_copyin(arg, &data, sizeof (agp_setup_t), flags) != 0)
		return (EFAULT);

	if (rc = agp_setup(st, data.agps_mode))
		return (rc);
	/* Store agp mode status for kstat */
	st->asoft_agpen = 1;
	return (0);
}

static int
ioctl_agpgart_alloc(agpgart_softstate_t  *st, void  *arg, int flags)
{
	agp_allocate_t	alloc_info;
	keytable_ent_t	*entryp;
	size_t		length;
	uint64_t	pg_num;

	if (is_controlling_proc(st) < 0) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_alloc: not a controlling process"));
		return (EPERM);
	}

	if (ddi_copyin(arg, &alloc_info,
	    sizeof (agp_allocate_t), flags) != 0) {
		return (EFAULT);
	}
	pg_num = st->asoft_pgused + alloc_info.agpa_pgcount;
	if (pg_num > st->asoft_pgtotal) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_alloc: exceeding the memory pages limit"));
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_alloc: request %x pages failed",
		    alloc_info.agpa_pgcount));
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_alloc: pages used %x total is %x",
		    st->asoft_pgused, st->asoft_pgtotal));

		return (EINVAL);
	}

	length = AGP_PAGES2BYTES(alloc_info.agpa_pgcount);
	entryp = agp_alloc_mem(st, length, alloc_info.agpa_type);
	if (!entryp) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_alloc: allocate 0x%lx bytes failed",
		    length));
		return (ENOMEM);
	}
	ASSERT((entryp->kte_key >= 0) && (entryp->kte_key < AGP_MAXKEYS));
	alloc_info.agpa_key = entryp->kte_key;
	if (alloc_info.agpa_type == AGP_PHYSICAL) {
		alloc_info.agpa_physical =
		    (uint32_t)(entryp->kte_pfnarray[0] << AGP_PAGE_SHIFT);
	}
	/* Update the memory pagse used */
	st->asoft_pgused += alloc_info.agpa_pgcount;

	if (ddi_copyout(&alloc_info, arg,
	    sizeof (agp_allocate_t), flags) != 0) {

		return (EFAULT);
	}

	return (0);
}

static int
ioctl_agpgart_dealloc(agpgart_softstate_t  *st, intptr_t arg)
{
	int key;
	keytable_ent_t  *keyent;

	if (is_controlling_proc(st) < 0) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_dealloc: not a controlling process"));
		return (EPERM);
	}
	key = (int)arg;
	if ((key >= AGP_MAXKEYS) || key < 0) {
		return (EINVAL);
	}
	keyent = &st->asoft_table[key];
	if (!keyent->kte_memhdl) {
		return (EINVAL);
	}

	if (agp_dealloc_mem(st, keyent))
		return (EINVAL);

	/* Update the memory pages used */
	st->asoft_pgused -= keyent->kte_pages;
	bzero(keyent, sizeof (keytable_ent_t));

	return (0);
}

static int
ioctl_agpgart_bind(agpgart_softstate_t  *st, void  *arg, int flags)
{
	agp_bind_t 	bind_info;
	keytable_ent_t	*keyent;
	int		key;
	uint32_t	pg_offset;
	int		retval = 0;

	if (is_controlling_proc(st) < 0) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_bind: not a controlling process"));
		return (EPERM);
	}

	if (ddi_copyin(arg, &bind_info, sizeof (agp_bind_t), flags) != 0) {
		return (EFAULT);
	}

	key = bind_info.agpb_key;
	if ((key >= AGP_MAXKEYS) || key < 0) {
		AGPDB_PRINT2((CE_WARN, "ioctl_agpgart_bind: invalid key"));
		return (EINVAL);
	}

	if (IS_INTEL_830(st->asoft_devreg.agprd_arctype)) {
		if (AGP_PAGES2KB(bind_info.agpb_pgstart) <
		    st->asoft_info.agpki_presize) {
			AGPDB_PRINT2((CE_WARN,
			    "ioctl_agpgart_bind: bind to prealloc area "
			    "pgstart = %dKB < presize = %ldKB",
			    AGP_PAGES2KB(bind_info.agpb_pgstart),
			    st->asoft_info.agpki_presize));
			return (EINVAL);
		}
	}

	pg_offset = bind_info.agpb_pgstart;
	keyent = &st->asoft_table[key];
	if (!keyent->kte_memhdl) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_bind: Key = 0x%x can't get keyenty",
		    key));
		return (EINVAL);
	}

	if (keyent->kte_bound != 0) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_bind: Key = 0x%x already bound",
		    key));
		return (EINVAL);
	}
	retval = agp_bind_key(st, keyent, pg_offset);

	if (retval == 0) {
		keyent->kte_pgoff = pg_offset;
		keyent->kte_bound = 1;
	}

	return (retval);
}

static int
ioctl_agpgart_unbind(agpgart_softstate_t  *st, void  *arg, int flags)
{
	int key, retval = 0;
	agp_unbind_t unbindinfo;
	keytable_ent_t *keyent;

	if (is_controlling_proc(st) < 0) {
		AGPDB_PRINT2((CE_WARN,
		    "ioctl_agpgart_bind: not a controlling process"));
		return (EPERM);
	}

	if (ddi_copyin(arg, &unbindinfo, sizeof (unbindinfo), flags) != 0) {
		return (EFAULT);
	}
	key = unbindinfo.agpu_key;
	if ((key >= AGP_MAXKEYS) || key < 0) {
		AGPDB_PRINT2((CE_WARN, "ioctl_agpgart_unbind: invalid key"));
		return (EINVAL);
	}
	keyent = &st->asoft_table[key];
	if (!keyent->kte_bound) {
		return (EINVAL);
	}

	if ((retval = agp_unbind_key(st, keyent)) != 0)
		return (retval);

	return (0);
}

static int
ioctl_agpgart_flush_chipset(agpgart_softstate_t *st)
{
	ldi_handle_t	hdl;
	uint32_t devid;
	int rc = 0;
	devid = st->asoft_info.agpki_mdevid;
	hdl = st->asoft_devreg.agprd_targethdl;
	if (IS_INTEL_915(devid) ||
	    IS_INTEL_965(devid) ||
	    IS_INTEL_X33(devid) ||
	    IS_INTEL_G4X(devid)) {
		rc = ldi_ioctl(hdl, INTEL_CHIPSET_FLUSH, 0, FKIOCTL, kcred, 0);
	}
	return	(rc);
}

static int
ioctl_agpgart_pages_bind(agpgart_softstate_t  *st, void  *arg, int flags)
{
	agp_bind_pages_t 	bind_info;
	uint32_t	pg_offset;
	int err = 0;
	ldi_handle_t hdl;
	uint32_t npages;
	igd_gtt_seg_t *gttseg;
	uint32_t i;
	int rval;
	if (ddi_copyin(arg, &bind_info,
	    sizeof (agp_bind_pages_t), flags) != 0) {
		return (EFAULT);
	}

	gttseg = (igd_gtt_seg_t *)kmem_zalloc(sizeof (igd_gtt_seg_t),
	    KM_SLEEP);

	pg_offset = bind_info.agpb_pgstart;

	gttseg->igs_pgstart =  pg_offset;
	npages = (uint32_t)bind_info.agpb_pgcount;
	gttseg->igs_npage = npages;

	gttseg->igs_type = AGP_NORMAL;
	gttseg->igs_phyaddr = (uint32_t *)kmem_zalloc
	    (sizeof (uint32_t) * gttseg->igs_npage, KM_SLEEP);

	for (i = 0; i < npages; i++) {
		gttseg->igs_phyaddr[i] = bind_info.agpb_pages[i] <<
		    GTT_PAGE_SHIFT;
	}

	hdl = st->asoft_devreg.agprd_masterhdl;
	if (ldi_ioctl(hdl, I8XX_ADD2GTT, (intptr_t)gttseg, FKIOCTL,
	    kcred, &rval)) {
		AGPDB_PRINT2((CE_WARN, "ioctl_agpgart_pages_bind: start0x%x",
		    gttseg->igs_pgstart));
		AGPDB_PRINT2((CE_WARN, "ioctl_agpgart_pages_bind: pages=0x%x",
		    gttseg->igs_npage));
		AGPDB_PRINT2((CE_WARN, "ioctl_agpgart_pages_bind: type=0x%x",
		    gttseg->igs_type));
		err = -1;
	}

	list_head_add_new(&st->mapped_list, gttseg);
	return (err);
}

static int
ioctl_agpgart_pages_unbind(agpgart_softstate_t  *st, void  *arg, int flags)
{
	agp_unbind_pages_t unbind_info;
	int	rval;
	ldi_handle_t	hdl;
	igd_gtt_seg_t	*gttseg;

	if (ddi_copyin(arg, &unbind_info, sizeof (unbind_info), flags) != 0) {
		return (EFAULT);
	}

	struct list_head  *entry, *temp;
	list_head_for_each_safe(entry, temp, &st->mapped_list) {
		if (entry->gttseg->igs_pgstart == unbind_info.agpb_pgstart) {
			gttseg = entry->gttseg;
			/* not unbind if VT switch */
			if (unbind_info.agpb_type) {
				list_head_del(entry);
				kmem_free(entry, sizeof (*entry));
			}
			break;
		}
	}
	ASSERT(gttseg != NULL);
	gttseg->igs_pgstart =  unbind_info.agpb_pgstart;
	ASSERT(gttseg->igs_npage == unbind_info.agpb_pgcount);

	hdl = st->asoft_devreg.agprd_masterhdl;
	if (ldi_ioctl(hdl, I8XX_REM_GTT, (intptr_t)gttseg, FKIOCTL,
	    kcred, &rval))
		return (-1);

	if (unbind_info.agpb_type) {
		kmem_free(gttseg->igs_phyaddr, sizeof (uint32_t) *
		    gttseg->igs_npage);
		kmem_free(gttseg, sizeof (igd_gtt_seg_t));
	}

	return (0);
}

static int
ioctl_agpgart_pages_rebind(agpgart_softstate_t  *st)
{
	int	rval;
	ldi_handle_t	hdl;
	igd_gtt_seg_t	*gttseg;
	int err = 0;

	hdl = st->asoft_devreg.agprd_masterhdl;
	struct list_head  *entry, *temp;
	list_head_for_each_safe(entry, temp, &st->mapped_list) {
		gttseg = entry->gttseg;
		list_head_del(entry);
		kmem_free(entry, sizeof (*entry));
		if (ldi_ioctl(hdl, I8XX_ADD2GTT, (intptr_t)gttseg, FKIOCTL,
		    kcred, &rval)) {
			AGPDB_PRINT2((CE_WARN, "agpgart_pages_rebind errori"));
			err = -1;
			break;
		}
		kmem_free(gttseg->igs_phyaddr, sizeof (uint32_t) *
		    gttseg->igs_npage);
		kmem_free(gttseg, sizeof (igd_gtt_seg_t));

	}
	return (err);

}

/*ARGSUSED*/
static int
agpgart_ioctl(dev_t dev, int cmd, intptr_t intarg, int flags,
    cred_t *credp, int *rvalp)
{
	int instance;
	int retval = 0;
	void *arg = (void*)intarg;

	agpgart_softstate_t *softstate;

	instance = AGP_DEV2INST(dev);
	softstate = ddi_get_soft_state(agpgart_glob_soft_handle, instance);
	if (softstate == NULL) {
		AGPDB_PRINT2((CE_WARN, "agpgart_ioctl: get soft state err"));
		return (ENXIO);
	}

	mutex_enter(&softstate->asoft_instmutex);

	switch (cmd) {
	case AGPIOC_INFO:
		retval = ioctl_agpgart_info(softstate, arg, flags);
		break;
	case AGPIOC_ACQUIRE:
		retval = ioctl_agpgart_acquire(softstate);
		break;
	case AGPIOC_RELEASE:
		retval = ioctl_agpgart_release(softstate);
		break;
	case AGPIOC_SETUP:
		retval = ioctl_agpgart_setup(softstate, arg, flags);
		break;
	case AGPIOC_ALLOCATE:
		retval = ioctl_agpgart_alloc(softstate, arg, flags);
		break;
	case AGPIOC_DEALLOCATE:
		retval = ioctl_agpgart_dealloc(softstate, intarg);
		break;
	case AGPIOC_BIND:
		retval = ioctl_agpgart_bind(softstate, arg, flags);
		break;
	case AGPIOC_UNBIND:
		retval = ioctl_agpgart_unbind(softstate, arg, flags);
		break;
	case AGPIOC_FLUSHCHIPSET:
		retval = ioctl_agpgart_flush_chipset(softstate);
		break;
	case AGPIOC_PAGES_BIND:
		retval = ioctl_agpgart_pages_bind(softstate, arg, flags);
		break;
	case AGPIOC_PAGES_UNBIND:
		retval = ioctl_agpgart_pages_unbind(softstate, arg, flags);
		break;
	case AGPIOC_PAGES_REBIND:
		retval = ioctl_agpgart_pages_rebind(softstate);
		break;
	default:
		AGPDB_PRINT2((CE_WARN, "agpgart_ioctl: wrong argument"));
		retval = ENXIO;
		break;
	}

	mutex_exit(&softstate->asoft_instmutex);
	return (retval);
}

static int
agpgart_segmap(dev_t dev, off_t off, struct as *asp,
    caddr_t *addrp, off_t len, unsigned int prot,
    unsigned int maxprot, unsigned int flags, cred_t *credp)
{

	struct agpgart_softstate *softstate;
	int instance;
	int rc = 0;

	instance = AGP_DEV2INST(dev);
	softstate = ddi_get_soft_state(agpgart_glob_soft_handle, instance);
	if (softstate == NULL) {
		AGPDB_PRINT2((CE_WARN, "agpgart_segmap: get soft state err"));
		return (ENXIO);
	}
	if (!AGP_ALIGNED(len))
		return (EINVAL);

	mutex_enter(&softstate->asoft_instmutex);

	rc = devmap_setup(dev, (offset_t)off, asp, addrp,
	    (size_t)len, prot, maxprot, flags, credp);

	mutex_exit(&softstate->asoft_instmutex);
	return (rc);
}

/*ARGSUSED*/
static int
agpgart_devmap(dev_t dev, devmap_cookie_t cookie, offset_t offset, size_t len,
    size_t *mappedlen, uint_t model)
{
	struct agpgart_softstate *softstate;
	int instance, status;
	struct keytable_ent *mementry;
	offset_t local_offset;

	instance = AGP_DEV2INST(dev);
	softstate = ddi_get_soft_state(agpgart_glob_soft_handle, instance);
	if (softstate == NULL) {
		AGPDB_PRINT2((CE_WARN, "agpgart_devmap: get soft state err"));
		return (ENXIO);
	}


	if (offset > MB2BYTES(softstate->asoft_info.agpki_apersize)) {
		AGPDB_PRINT2((CE_WARN, "agpgart_devmap: offset is too large"));
		return (EINVAL);
	}

	/*
	 * Can not find any memory now, so fail.
	 */

	mementry = agp_find_bound_keyent(softstate, AGP_BYTES2PAGES(offset));

	if (mementry == NULL) {
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_devmap: can not find the proper keyent"));
		return (EINVAL);
	}

	local_offset = offset - AGP_PAGES2BYTES(mementry->kte_pgoff);

	if (len > (AGP_PAGES2BYTES(mementry->kte_pages) - local_offset)) {
		len = AGP_PAGES2BYTES(mementry->kte_pages) - local_offset;
	}

	switch (mementry->kte_type) {
	case AGP_NORMAL:
		if (PMEMP(mementry->kte_memhdl)->pmem_cookie) {
			status = devmap_pmem_setup(cookie,
			    softstate->asoft_dip,
			    &agp_devmap_cb,
			    PMEMP(mementry->kte_memhdl)->pmem_cookie,
			    local_offset,
			    len, PROT_ALL,
			    (DEVMAP_DEFAULTS|IOMEM_DATA_UC_WR_COMBINE),
			    &mem_dev_acc_attr);
		} else {
			AGPDB_PRINT2((CE_WARN,
			    "agpgart_devmap: not a valid memory type"));
			return (EINVAL);

		}

		break;
	default:
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_devmap: not a valid memory type"));
		return (EINVAL);
	}


	if (status == 0) {
		*mappedlen = len;
	} else {
		*mappedlen = 0;
		AGPDB_PRINT2((CE_WARN,
		    "agpgart_devmap: devmap interface failed"));
		return (EINVAL);
	}

	return (0);
}

static struct cb_ops	agpgart_cb_ops = {
	agpgart_open,		/* open() */
	agpgart_close,		/* close() */
	nodev,			/* strategy() */
	nodev,			/* print routine */
	nodev,			/* no dump routine */
	nodev,			/* read() */
	nodev,			/* write() */
	agpgart_ioctl,		/* agpgart_ioctl */
	agpgart_devmap,		/* devmap routine */
	nodev,			/* no longer use mmap routine */
	agpgart_segmap,		/* system segmap routine */
	nochpoll,		/* no chpoll routine */
	ddi_prop_op,		/* system prop operations */
	0,			/* not a STREAMS driver */
	D_DEVMAP | D_MP,	/* safe for multi-thread/multi-processor */
	CB_REV,			/* cb_ops version? */
	nodev,			/* cb_aread() */
	nodev,			/* cb_awrite() */
};

static struct dev_ops agpgart_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	agpgart_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	agpgart_attach,		/* devo_attach */
	agpgart_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&agpgart_cb_ops,	/* devo_cb_ops */
	(struct bus_ops *)0,	/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

static	struct modldrv modldrv = {
	&mod_driverops,
	"AGP driver",
	&agpgart_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* MODREV_1 is indicated by manual */
	{&modldrv, NULL, NULL, NULL}
};

static void *agpgart_glob_soft_handle;

int
_init(void)
{
	int ret = DDI_SUCCESS;

	ret = ddi_soft_state_init(&agpgart_glob_soft_handle,
	    sizeof (agpgart_softstate_t),
	    AGPGART_MAX_INSTANCES);

	if (ret != 0) {
		AGPDB_PRINT2((CE_WARN,
		    "_init: soft state init error code=0x%x", ret));
		return (ret);
	}

	if ((ret = mod_install(&modlinkage)) != 0) {
		AGPDB_PRINT2((CE_WARN,
		    "_init: mod install error code=0x%x", ret));
		ddi_soft_state_fini(&agpgart_glob_soft_handle);
		return (ret);
	}

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&agpgart_glob_soft_handle);
	}

	return (ret);
}
