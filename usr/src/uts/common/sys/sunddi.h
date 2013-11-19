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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#ifndef	_SYS_SUNDDI_H
#define	_SYS_SUNDDI_H

/*
 * Sun Specific DDI definitions
 */

#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/ddipropdefs.h>
#include <sys/devops.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/ddidevmap.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/ddi_isa.h>
#include <sys/model.h>
#include <sys/devctl.h>
#if defined(__i386) || defined(__amd64)
#include <sys/dma_engine.h>
#endif
#include <sys/sunpm.h>
#include <sys/nvpair.h>
#include <sys/sysevent.h>
#include <sys/thread.h>
#include <sys/stream.h>
#if defined(__GNUC__) && defined(_ASM_INLINES) && defined(_KERNEL)
#include <asm/sunddi.h>
#endif
#ifdef _KERNEL
#include <sys/ddi_obsolete.h>
#endif
#include <sys/u8_textprep.h>
#include <sys/kiconv.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Generic Sun DDI definitions.
 */

#define	DDI_SUCCESS	(0)	/* successful return */
#define	DDI_FAILURE	(-1)	/* unsuccessful return */
#define	DDI_NOT_WELL_FORMED (-2)  /* A dev_info node is not valid */
#define	DDI_EAGAIN	(-3)	/* not enough interrupt resources */
#define	DDI_EINVAL	(-4)	/* invalid request or arguments */
#define	DDI_ENOTSUP	(-5)	/* operation is not supported */
#define	DDI_EPENDING	(-6)	/* operation or an event is pending */
#define	DDI_EALREADY	(-7)	/* operation already in progress */

/*
 * General-purpose DDI error return value definitions
 */
#define	DDI_ENOMEM		1	/* memory not available */
#define	DDI_EBUSY		2	/* busy */
#define	DDI_ETRANSPORT		3	/* transport down */
#define	DDI_ECONTEXT		4	/* context error */


/*
 * General DDI sleep/nosleep allocation flags
 */
#define	DDI_SLEEP	0
#define	DDI_NOSLEEP	1

/*
 * The following special nodeid values are reserved for use when creating
 * nodes ONLY.  They specify the attributes of the DDI_NC_PSEUDO class node
 * being created:
 *
 *  o	DEVI_PSEUDO_NODEID specifics a node without persistence.
 *  o	DEVI_SID_NODEID specifies a node with persistence.
 *  o	DEVI_SID_HIDDEN_NODEID specifies a hidden node with persistence.
 *
 * A node with the 'hidden' attribute will not show up in devinfo snapshots
 * or in /devices file system.
 *
 * A node with the 'persistent' attribute will not be automatically removed by
 * the framework in the current implementation - driver.conf nodes are without
 * persistence.
 *
 * The actual nodeid value may be assigned by the framework and may be
 * different than these special values. Drivers may not make assumptions
 * about the nodeid value that is actually assigned to the node.
 */

#define	DEVI_PSEUDO_NODEID	((int)-1)
#define	DEVI_SID_NODEID		((int)-2)
#define	DEVI_SID_HIDDEN_NODEID	((int)-3)
#define	DEVI_SID_HP_NODEID	((int)-4)
#define	DEVI_SID_HP_HIDDEN_NODEID ((int)-5)

#define	DEVI_PSEUDO_NEXNAME	"pseudo"
#define	DEVI_ISA_NEXNAME	"isa"
#define	DEVI_EISA_NEXNAME	"eisa"

/*
 * ddi_create_minor_node flags
 */
#define	CLONE_DEV		1	/* device is a clone device */
#define	PRIVONLY_DEV		0x10	/* policy-based permissions only */

/*
 * Historical values used for the flag field in ddi_create_minor_node.
 * Future use of flag bits should avoid these fields to keep binary
 * compatibility
 * #define	GLOBAL_DEV		0x2
 * #define	NODEBOUND_DEV		0x4
 * #define	NODESPECIFIC_DEV	0x6
 * #define	ENUMERATED_DEV		0x8
 */

/*
 * Device type defines which are used by the 'node_type' element of the
 * ddi_minor_data structure
 */
#define	DDI_NT_SERIAL	"ddi_serial"		/* Serial port */
#define	DDI_NT_SERIAL_MB "ddi_serial:mb"	/* the 'built-in' serial */
						/* ports (the old ttya, b */
						/* (,c ,d)) */
#define	DDI_NT_SERIAL_DO "ddi_serial:dialout"	/* dialout ports */
#define	DDI_NT_SERIAL_MB_DO "ddi_serial:dialout,mb" /* dialout for onboard */
						/* ports */
#define	DDI_NT_SERIAL_LOMCON "ddi_serial:lomcon" /* LOMlite2 console port */

/*
 * *_CHAN disk type devices have channel numbers or target numbers.
 * (i.e. ipi and scsi devices)
 */
#define	DDI_NT_BLOCK	"ddi_block"		/* hard disks */
/*
 * The next define is for block type devices that can possible exist on
 * a sub-bus like the scsi bus or the ipi channel.  The 'disks' program
 * will pick up on this and create logical names like c0t0d0s0 instead of
 * c0d0s0
 */
#define	DDI_NT_BLOCK_CHAN	"ddi_block:channel"
#define	DDI_NT_BLOCK_WWN	"ddi_block:wwn"
#define	DDI_NT_CD	"ddi_block:cdrom"	/* rom drives (cd-rom) */
#define	DDI_NT_CD_CHAN	"ddi_block:cdrom:channel" /* rom drives (scsi type) */
#define	DDI_NT_FD	"ddi_block:diskette"	/* floppy disks */

#define	DDI_NT_ENCLOSURE	"ddi_enclosure"
#define	DDI_NT_SCSI_ENCLOSURE	"ddi_enclosure:scsi"

#define	DDI_NT_BLOCK_SAS	"ddi_block:sas"

/*
 * xVM virtual block devices
 */
#define	DDI_NT_BLOCK_XVMD	"ddi_block:xvmd"
#define	DDI_NT_CD_XVMD		"ddi_block:cdrom:xvmd"


#define	DDI_NT_TAPE	"ddi_byte:tape"		/* tape drives */

#define	DDI_NT_NET	"ddi_network"		/* DLPI network devices */

#define	DDI_NT_NET_WIFI	"ddi_network:wifi"	/* wifi devices */

#define	DDI_NT_DISPLAY	"ddi_display"		/* display devices */

#define	DDI_NT_DISPLAY_DRM	"ddi_display:drm" /* drm display devices */

#define	DDI_PSEUDO	"ddi_pseudo"		/* general pseudo devices */

#define	DDI_NT_AUDIO	"ddi_audio"		/* audio device */

#define	DDI_NT_MOUSE	"ddi_mouse"		/* mouse device */

#define	DDI_NT_KEYBOARD	"ddi_keyboard"		/* keyboard device */

#define	DDI_NT_PARALLEL "ddi_parallel"		/* parallel port */

#define	DDI_NT_PRINTER	"ddi_printer"		/* printer device */

#define	DDI_NT_UGEN	"ddi_generic:usb"	/* USB generic drv */

#define	DDI_NT_SMP	"ddi_sas_smp" 		/* smp devcies */

#define	DDI_NT_NEXUS	"ddi_ctl:devctl"	/* nexus drivers */

#define	DDI_NT_SCSI_NEXUS	"ddi_ctl:devctl:scsi"	/* nexus drivers */

#define	DDI_NT_SATA_NEXUS	"ddi_ctl:devctl:sata"	/* nexus drivers */

#define	DDI_NT_IB_NEXUS		"ddi_ctl:devctl:ib"	/* nexus drivers */

#define	DDI_NT_ATTACHMENT_POINT	"ddi_ctl:attachment_point" /* attachment pt */

#define	DDI_NT_SCSI_ATTACHMENT_POINT	"ddi_ctl:attachment_point:scsi"
						/* scsi attachment pt */

#define	DDI_NT_SATA_ATTACHMENT_POINT	"ddi_ctl:attachment_point:sata"
						/* sata attachment pt */

#define	DDI_NT_SDCARD_ATTACHMENT_POINT	"ddi_ctl:attachment_point:sdcard"
						/* sdcard attachment pt */

#define	DDI_NT_PCI_ATTACHMENT_POINT	"ddi_ctl:attachment_point:pci"
						/* PCI attachment pt */
#define	DDI_NT_SBD_ATTACHMENT_POINT	"ddi_ctl:attachment_point:sbd"
						/* generic bd attachment pt */
#define	DDI_NT_FC_ATTACHMENT_POINT	"ddi_ctl:attachment_point:fc"
						/* FC attachment pt */
#define	DDI_NT_USB_ATTACHMENT_POINT	"ddi_ctl:attachment_point:usb"
						/* USB devices */
#define	DDI_NT_BLOCK_FABRIC		"ddi_block:fabric"
						/* Fabric Devices */
#define	DDI_NT_IB_ATTACHMENT_POINT	"ddi_ctl:attachment_point:ib"
						/* IB devices */

#define	DDI_NT_AV_ASYNC "ddi_av:async"		/* asynchronous AV device */
#define	DDI_NT_AV_ISOCH "ddi_av:isoch"		/* isochronous AV device */

/* Device types used for agpgart driver related devices */
#define	DDI_NT_AGP_PSEUDO	"ddi_agp:pseudo" /* agpgart pseudo device */
#define	DDI_NT_AGP_MASTER	"ddi_agp:master" /* agp master device */
#define	DDI_NT_AGP_TARGET	"ddi_agp:target" /* agp target device */
#define	DDI_NT_AGP_CPUGART	"ddi_agp:cpugart" /* amd64 on-cpu gart device */

#define	DDI_NT_REGACC		"ddi_tool_reg"	/* tool register access */
#define	DDI_NT_INTRCTL		"ddi_tool_intr"	/* tool intr access */

/*
 * DDI event definitions
 */
#define	EC_DEVFS	"EC_devfs"	/* Event class devfs */
#define	EC_DDI		"EC_ddi"	/* Event class ddi */

/* Class devfs subclasses */
#define	ESC_DEVFS_MINOR_CREATE	"ESC_devfs_minor_create"
#define	ESC_DEVFS_MINOR_REMOVE	"ESC_devfs_minor_remove"
#define	ESC_DEVFS_DEVI_ADD	"ESC_devfs_devi_add"
#define	ESC_DEVFS_DEVI_REMOVE	"ESC_devfs_devi_remove"
#define	ESC_DEVFS_INSTANCE_MOD	"ESC_devfs_instance_mod"
#define	ESC_DEVFS_BRANCH_ADD	"ESC_devfs_branch_add"
#define	ESC_DEVFS_BRANCH_REMOVE	"ESC_devfs_branch_remove"
#define	ESC_DEVFS_START		"ESC_devfs_start"

/* Class ddi subclasses */
#define	ESC_DDI_INITIATOR_REGISTER	"ESC_ddi_initiator_register"
#define	ESC_DDI_INITIATOR_UNREGISTER	"ESC_ddi_initiator_unregister"

/* DDI/NDI event publisher */
#define	EP_DDI	SUNW_KERN_PUB"ddi"

/*
 * devfs event class attributes
 *
 * The following attributes are private to EC_DEVFS event data.
 */
#define	DEVFS_DRIVER_NAME	"di.driver"
#define	DEVFS_INSTANCE		"di.instance"
#define	DEVFS_PATHNAME		"di.path"
#define	DEVFS_DEVI_CLASS	"di.devi_class"
#define	DEVFS_BRANCH_EVENT	"di.branch_event"
#define	DEVFS_MINOR_NAME	"mi.name"
#define	DEVFS_MINOR_NODETYPE	"mi.nodetype"
#define	DEVFS_MINOR_ISCLONE	"mi.isclone"
#define	DEVFS_MINOR_MAJNUM	"mi.majorno"
#define	DEVFS_MINOR_MINORNUM	"mi.minorno"

/*
 * ddi event class payload
 *
 * The following attributes are private to EC_DDI event data.
 */
#define	DDI_DRIVER_NAME		"ddi.driver"
#define	DDI_DRIVER_MAJOR	"ddi.major"
#define	DDI_INSTANCE		"ddi.instance"
#define	DDI_PATHNAME		"ddi.path"
#define	DDI_CLASS		"ddi.class"

/*
 * Fault-related definitions
 *
 * The specific numeric values have been chosen to be ordered, but
 * not consecutive, to allow for future interpolation if required.
 */
typedef enum {
    DDI_SERVICE_LOST = -32,
    DDI_SERVICE_DEGRADED = -16,
    DDI_SERVICE_UNAFFECTED = 0,
    DDI_SERVICE_RESTORED = 16
} ddi_fault_impact_t;

typedef enum {
    DDI_DATAPATH_FAULT = -32,
    DDI_DEVICE_FAULT = -16,
    DDI_EXTERNAL_FAULT = 0
} ddi_fault_location_t;

typedef enum {
    DDI_DEVSTATE_OFFLINE = -32,
    DDI_DEVSTATE_DOWN = -16,
    DDI_DEVSTATE_QUIESCED = 0,
    DDI_DEVSTATE_DEGRADED = 16,
    DDI_DEVSTATE_UP = 32
} ddi_devstate_t;

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

/*
 * Common property definitions
 */
#define	DDI_FORCEATTACH		"ddi-forceattach"
#define	DDI_NO_AUTODETACH	"ddi-no-autodetach"
#define	DDI_VHCI_CLASS		"ddi-vhci-class"
#define	DDI_NO_ROOT_SUPPORT	"ddi-no-root-support"
#define	DDI_OPEN_RETURNS_EINTR	"ddi-open-returns-eintr"
#define	DDI_DEVID_REGISTRANT	"ddi-devid-registrant"

/*
 * Values that the function supplied to the dev_info
 * tree traversal functions defined below must return.
 */

/*
 * Continue search, if appropriate.
 */
#define	DDI_WALK_CONTINUE	0

/*
 * Terminate current depth of traversal. That is, terminate
 * the current traversal of children nodes, but continue
 * traversing sibling nodes and their children (if any).
 */

#define	DDI_WALK_PRUNECHILD	-1

/*
 * Terminate current width of traversal. That is, terminate
 * the current traversal of sibling nodes, but continue with
 * traversing children nodes and their siblings (if appropriate).
 */

#define	DDI_WALK_PRUNESIB	-2

/*
 * Terminate the entire search.
 */

#define	DDI_WALK_TERMINATE	-3

/*
 * Terminate the entire search because an error occurred in function
 */
#define	DDI_WALK_ERROR		-4

/*
 * Drivers that are prepared to support full driver layering
 * should create and export a null-valued property of the following
 * name.
 *
 * Such drivers should be prepared to be called with FKLYR in
 * the 'flag' argument of their open(9E), close(9E) routines, and
 * with FKIOCTL in the 'mode' argument of their ioctl(9E) routines.
 *
 * See ioctl(9E) and ddi_copyin(9F) for details.
 */
#define	DDI_KERNEL_IOCTL	"ddi-kernel-ioctl"

/*
 * Model definitions for ddi_mmap_get_model(9F) and ddi_model_convert_from(9F).
 */
#define	DDI_MODEL_MASK		DATAMODEL_MASK	/* Note: 0x0FF00000 */
#define	DDI_MODEL_ILP32		DATAMODEL_ILP32
#define	DDI_MODEL_LP64		DATAMODEL_LP64
#define	DDI_MODEL_NATIVE	DATAMODEL_NATIVE
#define	DDI_MODEL_NONE		DATAMODEL_NONE

/* if set to B_TRUE is DER_MODE is equivalent to DERE_PANIC */
extern boolean_t ddi_err_panic;

/*
 * Defines for ddi_err().
 */
typedef enum {
	DER_INVALID = 0,	/* must be 0 */
	DER_CONT = 1,
	DER_CONS,
	DER_LOG,
	DER_VERB,
	DER_NOTE,
	DER_WARN,
	DER_PANIC,
	DER_MODE,
	DER_DEBUG
} ddi_err_t;

extern void ddi_err(ddi_err_t de, dev_info_t *rdip, const char *fmt, ...);


extern char *ddi_strdup(const char *str, int flag);
extern char *strdup(const char *str);
extern void strfree(char *str);

/*
 * Functions and data references which really should be in <sys/ddi.h>
 */

extern int maxphys;
extern void minphys(struct buf *);
extern int physio(int (*)(struct buf *), struct buf *, dev_t,
	int, void (*)(struct buf *), struct uio *);
extern void disksort(struct diskhd *, struct buf *);

extern size_t strlen(const char *) __PURE;
extern size_t strnlen(const char *, size_t) __PURE;
extern char *strcpy(char *, const char *);
extern char *strncpy(char *, const char *, size_t);
/* Need to be consistent with <string.h> C++ definition for strchr() */
#if __cplusplus >= 199711L
extern const char *strchr(const char *, int);
#ifndef	_STRCHR_INLINE
#define	_STRCHR_INLINE
extern	"C++" {
	inline char *strchr(char *__s, int __c) {
		return (char *)strchr((const char *)__s, __c);
	}
}
#endif	/* _STRCHR_INLINE */
#else
extern char *strchr(const char *, int);
#endif	/* __cplusplus >= 199711L */
#define	DDI_STRSAME(s1, s2)	((*(s1) == *(s2)) && (strcmp((s1), (s2)) == 0))
extern int strcmp(const char *, const char *) __PURE;
extern int strncmp(const char *, const char *, size_t) __PURE;
extern char *strncat(char *, const char *, size_t);
extern size_t strlcat(char *, const char *, size_t);
extern size_t strlcpy(char *, const char *, size_t);
extern size_t strspn(const char *, const char *);
extern size_t strcspn(const char *, const char *);
extern char *strsep(char **, const char *);
extern int bcmp(const void *, const void *, size_t) __PURE;
extern int stoi(char **);
extern void numtos(ulong_t, char *);
extern void bcopy(const void *, void *, size_t);
extern void bzero(void *, size_t);

extern void *memcpy(void *, const  void  *, size_t);
extern void *memset(void *, int, size_t);
extern void *memmove(void *, const void *, size_t);
extern int memcmp(const void *, const void *, size_t) __PURE;
/* Need to be consistent with <string.h> C++ definition for memchr() */
#if __cplusplus >= 199711L
extern const void *memchr(const void *, int, size_t);
#ifndef	_MEMCHR_INLINE
#define	_MEMCHR_INLINE
extern "C++" {
	inline void *memchr(void * __s, int __c, size_t __n) {
		return (void *)memchr((const void *)__s, __c, __n);
	}
}
#endif  /* _MEMCHR_INLINE */
#else
extern void *memchr(const void *, int, size_t);
#endif /* __cplusplus >= 199711L */

extern int ddi_strtol(const char *, char **, int, long *);
extern int ddi_strtoul(const char *, char **, int, unsigned long *);
extern int ddi_strtoll(const char *, char **, int, longlong_t *);
extern int ddi_strtoull(const char *, char **, int, u_longlong_t *);

/*
 * kiconv functions and their macros.
 */
#define	KICONV_IGNORE_NULL	(0x0001)
#define	KICONV_REPLACE_INVALID	(0x0002)

extern kiconv_t kiconv_open(const char *, const char *);
extern size_t kiconv(kiconv_t, char **, size_t *, char **, size_t *, int *);
extern int kiconv_close(kiconv_t);
extern size_t kiconvstr(const char *, const char *, char *, size_t *, char *,
	size_t *, int, int *);

#endif /* _KERNEL || _FAKE_KERNEL */
#ifdef	_KERNEL

/*
 * ddi_map_regs
 *
 *	Map in the register set given by rnumber.
 *	The register number determine which register
 *	set will be mapped if more than one exists.
 *	The parent driver gets the information
 *	from parent private data and sets up the
 *	appropriate mappings and returns the kernel
 *	virtual address of the register set in *kaddrp.
 *	The offset specifies an offset into the register
 *	space to start from and len indicates the size
 *	of the area to map. If len and offset are 0 then
 *	the entire space is mapped.  It returns DDI_SUCCESS on
 *	success or DDI_FAILURE otherwise.
 *
 */
int
ddi_map_regs(dev_info_t *dip, uint_t rnumber, caddr_t *kaddrp,
	off_t offset, off_t len);

/*
 * ddi_unmap_regs
 *
 *	Undo mappings set up by ddi_map_regs.
 *	The register number determines which register
 *	set will be unmapped if more than one exists.
 *	This is provided for drivers preparing
 *	to detach themselves from the system to
 *	allow them to release allocated mappings.
 *
 *	The kaddrp and len specify the area to be
 *	unmapped. *kaddrp was returned from ddi_map_regs
 *	and len should match what ddi_map_regs was called
 *	with.
 */

void
ddi_unmap_regs(dev_info_t *dip, uint_t rnumber, caddr_t *kaddrp,
	off_t offset, off_t len);

int
ddi_map(dev_info_t *dp, ddi_map_req_t *mp, off_t offset, off_t len,
	caddr_t *addrp);

int
ddi_apply_range(dev_info_t *dip, dev_info_t *rdip, struct regspec *rp);

/*
 * ddi_rnumber_to_regspec: Not for use by leaf drivers.
 */
struct regspec *
ddi_rnumber_to_regspec(dev_info_t *dip, int rnumber);

int
ddi_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp, off_t offset,
	off_t len, caddr_t *vaddrp);

int
nullbusmap(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp, off_t offset,
	off_t len, caddr_t *vaddrp);

int ddi_peek8(dev_info_t *dip, int8_t *addr, int8_t *val_p);
int ddi_peek16(dev_info_t *dip, int16_t *addr, int16_t *val_p);
int ddi_peek32(dev_info_t *dip, int32_t *addr, int32_t *val_p);
int ddi_peek64(dev_info_t *dip, int64_t *addr, int64_t *val_p);

int ddi_poke8(dev_info_t *dip, int8_t *addr, int8_t val);
int ddi_poke16(dev_info_t *dip, int16_t *addr, int16_t val);
int ddi_poke32(dev_info_t *dip, int32_t *addr, int32_t val);
int ddi_poke64(dev_info_t *dip, int64_t *addr, int64_t val);

/*
 * Peek and poke to and from a uio structure in xfersize pieces,
 * using the parent nexi.
 */
int ddi_peekpokeio(dev_info_t *devi, struct uio *uio, enum uio_rw rw,
	caddr_t addr, size_t len, uint_t xfersize);

/*
 * Pagesize conversions using the parent nexi
 */
unsigned long ddi_btop(dev_info_t *dip, unsigned long bytes);
unsigned long ddi_btopr(dev_info_t *dip, unsigned long bytes);
unsigned long ddi_ptob(dev_info_t *dip, unsigned long pages);

/*
 * There are no more "block" interrupt functions, per se.
 * All thread of control should be done with MP/MT lockings.
 *
 * However, there are certain times in which a driver needs
 * absolutely a critical guaranteed non-preemptable time
 * in which to execute a few instructions.
 *
 * The following pair of functions attempt to guarantee this,
 * but they are dangerous to use. That is, use them with
 * extreme care. They do not guarantee to stop other processors
 * from executing, but they do guarantee that the caller
 * of ddi_enter_critical will continue to run until the
 * caller calls ddi_exit_critical. No intervening DDI functions
 * may be called between an entry and an exit from a critical
 * region.
 *
 * ddi_enter_critical returns an integer identifier which must
 * be passed to ddi_exit_critical.
 *
 * Be very sparing in the use of these functions since it is
 * likely that absolutely nothing else can occur in the system
 * whilst in the critical region.
 */

unsigned int
ddi_enter_critical(void);

void
ddi_exit_critical(unsigned int);

/*
 * devmap functions
 */
int
devmap_setup(dev_t dev, offset_t off, ddi_as_handle_t as, caddr_t *addrp,
	size_t len, uint_t prot, uint_t maxprot, uint_t flags,
	struct cred *cred);

int
ddi_devmap_segmap(dev_t dev, off_t off, ddi_as_handle_t as, caddr_t *addrp,
	off_t len, uint_t prot, uint_t maxprot, uint_t flags,
	struct cred *cred);

int
devmap_load(devmap_cookie_t dhp, offset_t offset, size_t len, uint_t type,
	uint_t rw);

int
devmap_unload(devmap_cookie_t dhp, offset_t offset, size_t len);

int
devmap_devmem_setup(devmap_cookie_t dhp, dev_info_t *dip,
	struct devmap_callback_ctl *callback_ops,
	uint_t rnumber, offset_t roff, size_t len, uint_t maxprot,
	uint_t flags, ddi_device_acc_attr_t *accattrp);

int
devmap_umem_setup(devmap_cookie_t dhp, dev_info_t *dip,
	struct devmap_callback_ctl *callback_ops,
	ddi_umem_cookie_t cookie, offset_t off, size_t len, uint_t maxprot,
	uint_t flags, ddi_device_acc_attr_t *accattrp);

int
devmap_devmem_remap(devmap_cookie_t dhp, dev_info_t *dip,
	uint_t rnumber, offset_t roff, size_t len, uint_t maxprot,
	uint_t flags, ddi_device_acc_attr_t *accattrp);

int
devmap_umem_remap(devmap_cookie_t dhp, dev_info_t *dip,
	ddi_umem_cookie_t cookie, offset_t off, size_t len, uint_t maxprot,
	uint_t flags, ddi_device_acc_attr_t *accattrp);

void
devmap_set_ctx_timeout(devmap_cookie_t dhp, clock_t ticks);

int
devmap_default_access(devmap_cookie_t dhp, void *pvtp, offset_t off,
	size_t len, uint_t type, uint_t rw);

int
devmap_do_ctxmgt(devmap_cookie_t dhp, void *pvtp, offset_t off, size_t len,
	uint_t type, uint_t rw, int (*ctxmgt)(devmap_cookie_t, void *, offset_t,
	size_t, uint_t, uint_t));


void *ddi_umem_alloc(size_t size, int flag, ddi_umem_cookie_t *cookiep);

void ddi_umem_free(ddi_umem_cookie_t cookie);

/*
 * Functions to lock user memory and do repeated I/O or do devmap_umem_setup
 */
int
ddi_umem_lock(caddr_t addr, size_t size, int flags, ddi_umem_cookie_t *cookie);

void
ddi_umem_unlock(ddi_umem_cookie_t cookie);

struct buf *
ddi_umem_iosetup(ddi_umem_cookie_t cookie, off_t off, size_t len, int direction,
    dev_t dev, daddr_t blkno, int (*iodone)(struct buf *), int sleepflag);

/*
 * Mapping functions
 */
int
ddi_segmap(dev_t dev, off_t offset, struct as *asp, caddr_t *addrp, off_t len,
	uint_t prot, uint_t maxprot, uint_t flags, cred_t *credp);

int
ddi_segmap_setup(dev_t dev, off_t offset, struct as *as, caddr_t *addrp,
	off_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cred,
	ddi_device_acc_attr_t *accattrp, uint_t rnumber);

int
ddi_map_fault(dev_info_t *dip, struct hat *hat, struct seg *seg, caddr_t addr,
	struct devpage *dp, pfn_t pfn, uint_t prot, uint_t lock);

int
ddi_device_mapping_check(dev_t dev, ddi_device_acc_attr_t *accattrp,
	uint_t rnumber, uint_t *hat_flags);

/*
 * Property functions:   See also, ddipropdefs.h.
 *			In general, the underlying driver MUST be held
 *			to call it's property functions.
 */

/*
 * Used to create, modify, and lookup integer properties
 */
int ddi_prop_get_int(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, int defvalue);
int64_t ddi_prop_get_int64(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, int64_t defvalue);
int ddi_prop_lookup_int_array(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, int **data, uint_t *nelements);
int ddi_prop_lookup_int64_array(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, int64_t **data, uint_t *nelements);
int ddi_prop_update_int(dev_t match_dev, dev_info_t *dip,
    char *name, int data);
int ddi_prop_update_int64(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t data);
int ddi_prop_update_int_array(dev_t match_dev, dev_info_t *dip,
    char *name, int *data, uint_t nelements);
int ddi_prop_update_int64_array(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t *data, uint_t nelements);
/*
 * Used to create, modify, and lookup string properties
 */
int ddi_prop_lookup_string(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, char **data);
int ddi_prop_lookup_string_array(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, char ***data, uint_t *nelements);
int ddi_prop_update_string(dev_t match_dev, dev_info_t *dip,
    char *name, char *data);
int ddi_prop_update_string_array(dev_t match_dev, dev_info_t *dip,
    char *name, char **data, uint_t nelements);

/*
 * Used to create, modify, and lookup byte properties
 */
int ddi_prop_lookup_byte_array(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, uchar_t **data, uint_t *nelements);
int ddi_prop_update_byte_array(dev_t match_dev, dev_info_t *dip,
    char *name, uchar_t *data, uint_t nelements);

/*
 * Used to verify the existence of a property or to see if a boolean
 * property exists.
 */
int ddi_prop_exists(dev_t match_dev, dev_info_t *dip, uint_t flags, char *name);

/*
 * Used to free the data returned by the above property routines.
 */
void ddi_prop_free(void *data);

/*
 * nopropop: For internal use in `dummy' cb_prop_op functions only
 */

int
nopropop(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
	char *name, caddr_t valuep, int *lengthp);

/*
 * ddi_prop_op: The basic property operator for drivers.
 *
 * In ddi_prop_op, the type of valuep is interpreted based on prop_op:
 *
 *	prop_op			valuep
 *	------			------
 *
 *	PROP_LEN		<unused>
 *
 *	PROP_LEN_AND_VAL_BUF	Pointer to callers buffer
 *
 *	PROP_LEN_AND_VAL_ALLOC	Address of callers pointer (will be set to
 *				address of allocated buffer, if successful)
 */

int
ddi_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
	char *name, caddr_t valuep, int *lengthp);

/* ddi_prop_op_size: for drivers that implement size in bytes */
int
ddi_prop_op_size(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
	int mod_flags, char *name, caddr_t valuep, int *lengthp,
	uint64_t size64);

/* ddi_prop_op_size_blksize: like ddi_prop_op_size, in blksize blocks */
int
ddi_prop_op_size_blksize(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
	int mod_flags, char *name, caddr_t valuep, int *lengthp,
	uint64_t size64, uint_t blksize);

/* ddi_prop_op_nblocks: for drivers that implement size in DEV_BSIZE blocks */
int
ddi_prop_op_nblocks(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
	int mod_flags, char *name, caddr_t valuep, int *lengthp,
	uint64_t nblocks64);

/* ddi_prop_op_nblocks_blksize: like ddi_prop_op_nblocks, in blksize blocks */
int
ddi_prop_op_nblocks_blksize(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
	int mod_flags, char *name, caddr_t valuep, int *lengthp,
	uint64_t nblocks64, uint_t blksize);

/*
 * Variable length props...
 */

/*
 * ddi_getlongprop:	Get variable length property len+val into a buffer
 *		allocated by property provider via kmem_alloc. Requester
 *		is responsible for freeing returned property via kmem_free.
 *
 * 	Arguments:
 *
 *	dev:	Input:	dev_t of property.
 *	dip:	Input:	dev_info_t pointer of child.
 *	flags:	Input:	Possible flag modifiers are:
 *		DDI_PROP_DONTPASS:	Don't pass to parent if prop not found.
 *		DDI_PROP_CANSLEEP:	Memory allocation may sleep.
 *	name:	Input:	name of property.
 *	valuep:	Output:	Addr of callers buffer pointer.
 *	lengthp:Output:	*lengthp will contain prop length on exit.
 *
 * 	Possible Returns:
 *
 *		DDI_PROP_SUCCESS:	Prop found and returned.
 *		DDI_PROP_NOT_FOUND:	Prop not found
 *		DDI_PROP_UNDEFINED:	Prop explicitly undefined.
 *		DDI_PROP_NO_MEMORY:	Prop found, but unable to alloc mem.
 */

int
ddi_getlongprop(dev_t dev, dev_info_t *dip, int flags,
	char *name, caddr_t valuep, int *lengthp);

/*
 *
 * ddi_getlongprop_buf:		Get long prop into pre-allocated callers
 *				buffer. (no memory allocation by provider).
 *
 *	dev:	Input:	dev_t of property.
 *	dip:	Input:	dev_info_t pointer of child.
 *	flags:	Input:	DDI_PROP_DONTPASS or NULL
 *	name:	Input:	name of property
 *	valuep:	Input:	ptr to callers buffer.
 *	lengthp:I/O:	ptr to length of callers buffer on entry,
 *			actual length of property on exit.
 *
 *	Possible returns:
 *
 *		DDI_PROP_SUCCESS	Prop found and returned
 *		DDI_PROP_NOT_FOUND	Prop not found
 *		DDI_PROP_UNDEFINED	Prop explicitly undefined.
 *		DDI_PROP_BUF_TOO_SMALL	Prop found, callers buf too small,
 *					no value returned, but actual prop
 *					length returned in *lengthp
 *
 */

int
ddi_getlongprop_buf(dev_t dev, dev_info_t *dip, int flags,
	char *name, caddr_t valuep, int *lengthp);

/*
 * Integer/boolean sized props.
 *
 * Call is value only... returns found boolean or int sized prop value or
 * defvalue if prop not found or is wrong length or is explicitly undefined.
 * Only flag is DDI_PROP_DONTPASS...
 *
 * By convention, this interface returns boolean (0) sized properties
 * as value (int)1.
 */

int
ddi_getprop(dev_t dev, dev_info_t *dip, int flags, char *name, int defvalue);

/*
 * Get prop length interface: flags are 0 or DDI_PROP_DONTPASS
 * if returns DDI_PROP_SUCCESS, length returned in *lengthp.
 */

int
ddi_getproplen(dev_t dev, dev_info_t *dip, int flags, char *name, int *lengthp);


/*
 * Interface to create/modify a managed property on child's behalf...
 * Only flag is DDI_PROP_CANSLEEP to allow memory allocation to sleep
 * if no memory available for internal prop structure.  Long property
 * (non integer sized) value references are not copied.
 *
 * Define property with DDI_DEV_T_NONE dev_t for properties not associated
 * with any particular dev_t. Use the same dev_t when modifying or undefining
 * a property.
 *
 * No guarantee on order of property search, so don't mix the same
 * property name with wildcard and non-wildcard dev_t's.
 */

/*
 * ddi_prop_create:	Define a managed property:
 */

int
ddi_prop_create(dev_t dev, dev_info_t *dip, int flag,
	char *name, caddr_t value, int length);

/*
 * ddi_prop_modify:	Modify a managed property value
 */

int
ddi_prop_modify(dev_t dev, dev_info_t *dip, int flag,
	char *name, caddr_t value, int length);

/*
 * ddi_prop_remove:	Undefine a managed property:
 */

int
ddi_prop_remove(dev_t dev, dev_info_t *dip, char *name);

/*
 * ddi_prop_remove_all:		Used before unloading a driver to remove
 *				all properties. (undefines all dev_t's props.)
 *				Also removes `undefined' prop defs.
 */

void
ddi_prop_remove_all(dev_info_t *dip);


/*
 * ddi_prop_undefine:	Explicitly undefine a property.  Property
 *			searches which match this property return
 *			the error code DDI_PROP_UNDEFINED.
 *
 *			Use ddi_prop_remove to negate effect of
 *			ddi_prop_undefine
 */

int
ddi_prop_undefine(dev_t dev, dev_info_t *dip, int flag, char *name);


/*
 * ddi_prop_cache_invalidate
 *			Invalidate a property in the current cached
 *			devinfo snapshot - next cached snapshot will
 *			return the latest property value available.
 */
void
ddi_prop_cache_invalidate(dev_t dev, dev_info_t *dip, char *name, int flags);

/*
 * The default ddi_bus_prop_op wrapper...
 */

int
ddi_bus_prop_op(dev_t dev, dev_info_t *dip, dev_info_t *ch_dip,
	ddi_prop_op_t prop_op, int mod_flags,
	char *name, caddr_t valuep, int *lengthp);


/*
 * Routines to traverse the tree of dev_info nodes.
 * The general idea of these functions is to provide
 * various tree traversal utilities. For each node
 * that the tree traversal function finds, a caller
 * supplied function is called with arguments of
 * the current node and a caller supplied argument.
 * The caller supplied function should return one
 * of the integer values defined below which will
 * indicate to the tree traversal function whether
 * the traversal should be continued, and if so, how,
 * or whether the traversal should terminate.
 */

/*
 * This general-purpose routine traverses the tree of dev_info nodes,
 * starting from the given node, and calls the given function for each
 * node that it finds with the current node and the pointer arg (which
 * can point to a structure of information that the function
 * needs) as arguments.
 *
 * It does the walk a layer at a time, not depth-first.
 *
 * The given function must return one of the values defined above.
 *
 */

void
ddi_walk_devs(dev_info_t *, int (*)(dev_info_t *, void *), void *);

/*
 * Routines to get at elements of the dev_info structure
 */

/*
 * ddi_node_name gets the device's 'name' from the device node.
 *
 * ddi_binding_name gets the string the OS used to bind the node to a driver,
 * in certain cases, the binding name may be different from the node name,
 * if the node name does not name a specific device driver.
 *
 * ddi_get_name is a synonym for ddi_binding_name().
 */
char *
ddi_get_name(dev_info_t *dip);

char *
ddi_binding_name(dev_info_t *dip);

const char *
ddi_driver_name(dev_info_t *dip);

major_t
ddi_driver_major(dev_info_t *dip);

major_t
ddi_compatible_driver_major(dev_info_t *dip, char **formp);

char *
ddi_node_name(dev_info_t *dip);

int
ddi_get_nodeid(dev_info_t *dip);

int
ddi_get_instance(dev_info_t *dip);

struct dev_ops *
ddi_get_driver(dev_info_t *dip);

void
ddi_set_driver(dev_info_t *dip, struct dev_ops *devo);

void
ddi_set_driver_private(dev_info_t *dip, void *data);

void *
ddi_get_driver_private(dev_info_t *dip);

/*
 * ddi_dev_is_needed tells system that a device is about to use a
 * component. Returns when component is ready.
 */
int
ddi_dev_is_needed(dev_info_t *dip, int cmpt, int level);

/*
 * check if DDI_SUSPEND may result in power being removed from a device.
 */
int
ddi_removing_power(dev_info_t *dip);

/*
 *  (Obsolete) power entry point
 */
int
ddi_power(dev_info_t *dip, int cmpt, int level);

/*
 * ddi_get_parent requires that the branch of the tree with the
 * node be held (ddi_hold_installed_driver) or that the devinfo tree
 * lock be held
 */
dev_info_t *
ddi_get_parent(dev_info_t *dip);

/*
 * ddi_get_child and ddi_get_next_sibling require that the devinfo
 * tree lock be held
 */
dev_info_t *
ddi_get_child(dev_info_t *dip);

dev_info_t *
ddi_get_next_sibling(dev_info_t *dip);

dev_info_t *
ddi_get_next(dev_info_t *dip);

void
ddi_set_next(dev_info_t *dip, dev_info_t *nextdip);

/*
 * dev_info manipulation functions
 */

/*
 * Add and remove child devices. These are part of the system framework.
 *
 * ddi_add_child creates a dev_info structure with the passed name,
 * nodeid and instance arguments and makes it a child of pdip. Devices
 * that are known directly by the hardware have real nodeids; devices
 * that are software constructs use the defined DEVI_PSEUDO_NODEID
 * for the node id.
 *
 * ddi_remove_node removes the node from the tree. This fails if this
 * child has children. Parent and driver private data should already
 * be released (freed) prior to calling this function.  If flag is
 * non-zero, the child is removed from it's linked list of instances.
 */
dev_info_t *
ddi_add_child(dev_info_t *pdip, char *name, uint_t nodeid, uint_t instance);

int
ddi_remove_child(dev_info_t *dip, int flag);

/*
 * Given the major number for a driver, make sure that dev_info nodes
 * are created form the driver's hwconf file, the driver for the named
 * device is loaded and attached, as well as any drivers for parent devices.
 * Return a pointer to the driver's dev_ops struct with the dev_ops held.
 * Note - Callers must release the dev_ops with ddi_rele_driver.
 *
 * When a driver is held, the branch of the devinfo tree from any of the
 * drivers devinfos to the root node are automatically held.  This only
 * applies to tree traversals up (and back down) the tree following the
 * parent pointers.
 *
 * Use of this interface is discouraged, it may be removed in a future release.
 */
struct dev_ops *
ddi_hold_installed_driver(major_t major);

void
ddi_rele_driver(major_t major);

/*
 * Attach and hold the specified instance of a driver.  The flags argument
 * should be zero.
 */
dev_info_t *
ddi_hold_devi_by_instance(major_t major, int instance, int flags);

void
ddi_release_devi(dev_info_t *);

/*
 * Associate a streams queue with a devinfo node
 */
void
ddi_assoc_queue_with_devi(queue_t *, dev_info_t *);

/*
 * Given the identifier string passed, make sure that dev_info nodes
 * are created form the driver's hwconf file, the driver for the named
 * device is loaded and attached, as well as any drivers for parent devices.
 *
 * Note that the driver is not held and is subject to being removed the instant
 * this call completes.  You probably really want ddi_hold_installed_driver.
 */
int
ddi_install_driver(char *idstring);

/*
 * Routines that return specific nodes
 */

dev_info_t *
ddi_root_node(void);

/*
 * Given a name and an instance number, find and return the
 * dev_info from the current state of the device tree.
 *
 * If instance number is -1, return the first named instance.
 *
 * If attached is 1, exclude all nodes that are < DS_ATTACHED
 *
 * Requires that the devinfo tree be locked.
 * If attached is 1, the driver must be held.
 */
dev_info_t *
ddi_find_devinfo(char *name, int instance, int attached);

/*
 * Synchronization of I/O with respect to various
 * caches and system write buffers.
 *
 * Done at varying points during an I/O transfer (including at the
 * removal of an I/O mapping).
 *
 * Due to the support of systems with write buffers which may
 * not be able to be turned off, this function *must* used at
 * any point in which data consistency might be required.
 *
 * Generally this means that if a memory object has multiple mappings
 * (both for I/O, as described by the handle, and the IU, via, e.g.
 * a call to ddi_dma_kvaddrp), and one mapping may have been
 * used to modify the memory object, this function must be called
 * to ensure that the modification of the memory object is
 * complete, as well as possibly to inform other mappings of
 * the object that any cached references to the object are
 * now stale (and flush or invalidate these stale cache references
 * as necessary).
 *
 * The function ddi_dma_sync() provides the general interface with
 * respect to this capability. Generally, ddi_dma_free() (below) may
 * be used in preference to ddi_dma_sync() as ddi_dma_free() calls
 * ddi_dma_sync().
 *
 * Returns 0 if all caches that exist and are specified by cache_flags
 * are successfully operated on, else -1.
 *
 * The argument offset specifies an offset into the mapping of the mapped
 * object in which to perform the synchronization. It will be silently
 * truncated to the granularity of underlying cache line sizes as
 * appropriate.
 *
 * The argument len specifies a length starting from offset in which to
 * perform the synchronization. A value of (uint_t) -1 means that the length
 * proceeds from offset to the end of the mapping. The length argument
 * will silently rounded up to the granularity of underlying cache line
 * sizes  as appropriate.
 *
 * The argument flags specifies what to synchronize (the device's view of
 * the object or the cpu's view of the object).
 *
 * Inquiring minds want to know when ddi_dma_sync should be used:
 *
 * +	When an object is mapped for dma, assume that an
 *	implicit ddi_dma_sync() is done for you.
 *
 * +	When an object is unmapped (ddi_dma_free()), assume
 *	that an implicit ddi_dma_sync() is done for you.
 *
 * +	At any time between the two times above that the
 *	memory object may have been modified by either
 *	the DMA device or a processor and you wish that
 *	the change be noticed by the master that didn't
 *	do the modifying.
 *
 * Clearly, only the third case above requires the use of ddi_dma_sync.
 *
 * Inquiring minds also want to know which flag to use:
 *
 * +	If you *modify* with a cpu the object, you use
 *	ddi_dma_sync(...DDI_DMA_SYNC_FORDEV) (you are making sure
 *	that the DMA device sees the changes you made).
 *
 * +	If you are checking, with the processor, an area
 *	of the object that the DMA device *may* have modified,
 *	you use ddi_dma_sync(....DDI_DMA_SYNC_FORCPU) (you are
 *	making sure that the processor(s) will see the changes
 *	that the DMA device may have made).
 */

int
ddi_dma_sync(ddi_dma_handle_t handle, off_t offset, size_t len, uint_t flags);

/*
 * Return the allowable DMA burst size for the object mapped by handle.
 * The burst sizes will returned in an integer that encodes power
 * of two burst sizes that are allowed in bit encoded format. For
 * example, a transfer that could allow 1, 2, 4, 8 and 32 byte bursts
 * would be encoded as 0x2f. A transfer that could be allowed as solely
 * a halfword (2 byte) transfers would be returned as 0x2.
 */

int
ddi_dma_burstsizes(ddi_dma_handle_t handle);

/*
 * Merge DMA attributes
 */

void
ddi_dma_attr_merge(ddi_dma_attr_t *attr, ddi_dma_attr_t *mod);

/*
 * Allocate a DMA handle
 */

int
ddi_dma_alloc_handle(dev_info_t *dip, ddi_dma_attr_t *attr,
	int (*waitfp)(caddr_t), caddr_t arg,
	ddi_dma_handle_t *handlep);

/*
 * Free DMA handle
 */

void
ddi_dma_free_handle(ddi_dma_handle_t *handlep);

/*
 * Allocate memory for DMA transfers
 */

int
ddi_dma_mem_alloc(ddi_dma_handle_t handle, size_t length,
	ddi_device_acc_attr_t *accattrp, uint_t xfermodes,
	int (*waitfp)(caddr_t), caddr_t arg, caddr_t *kaddrp,
	size_t *real_length, ddi_acc_handle_t *handlep);

/*
 * Free DMA memory
 */

void
ddi_dma_mem_free(ddi_acc_handle_t *hp);

/*
 * bind address to a DMA handle
 */

int
ddi_dma_addr_bind_handle(ddi_dma_handle_t handle, struct as *as,
	caddr_t addr, size_t len, uint_t flags,
	int (*waitfp)(caddr_t), caddr_t arg,
	ddi_dma_cookie_t *cookiep, uint_t *ccountp);

/*
 * bind buffer to DMA handle
 */

int
ddi_dma_buf_bind_handle(ddi_dma_handle_t handle, struct buf *bp,
	uint_t flags, int (*waitfp)(caddr_t), caddr_t arg,
	ddi_dma_cookie_t *cookiep, uint_t *ccountp);

/*
 * unbind mapping object to handle
 */

int
ddi_dma_unbind_handle(ddi_dma_handle_t handle);

/*
 * get next DMA cookie
 */

void
ddi_dma_nextcookie(ddi_dma_handle_t handle, ddi_dma_cookie_t *cookiep);

/*
 * get number of DMA windows
 */

int
ddi_dma_numwin(ddi_dma_handle_t handle, uint_t *nwinp);

/*
 * get specific DMA window
 */

int
ddi_dma_getwin(ddi_dma_handle_t handle, uint_t win, off_t *offp,
	size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp);

/*
 * activate 64 bit SBus support
 */

int
ddi_dma_set_sbus64(ddi_dma_handle_t handle, ulong_t burstsizes);

/*
 * Miscellaneous functions
 */

/*
 * ddi_report_dev:	Report a successful attach.
 */

void
ddi_report_dev(dev_info_t *dev);

/*
 * ddi_dev_regsize
 *
 *	If the device has h/w register(s), report
 *	the size, in bytes, of the specified one into *resultp.
 *
 *	Returns DDI_FAILURE if there are not registers,
 *	or the specified register doesn't exist.
 */

int
ddi_dev_regsize(dev_info_t *dev, uint_t rnumber, off_t *resultp);

/*
 * ddi_dev_nregs
 *
 *	If the device has h/w register(s), report
 *	how many of them that there are into resultp.
 *	Return DDI_FAILURE if the device has no registers.
 */

int
ddi_dev_nregs(dev_info_t *dev, int *resultp);

/*
 * ddi_dev_is_sid
 *
 *	If the device is self-identifying, i.e.,
 *	has already been probed by a smart PROM
 *	(and thus registers are known to be valid)
 *	return DDI_SUCCESS, else DDI_FAILURE.
 */


int
ddi_dev_is_sid(dev_info_t *dev);

/*
 * ddi_slaveonly
 *
 *	If the device is on a bus that precludes
 *	the device from being either a dma master or
 *	a dma slave, return DDI_SUCCESS.
 */

int
ddi_slaveonly(dev_info_t *);


/*
 * ddi_dev_affinity
 *
 *	Report, via DDI_SUCCESS, whether there exists
 *	an 'affinity' between two dev_info_t's. An
 *	affinity is defined to be either a parent-child,
 *	or a sibling relationship such that the siblings
 *	or in the same part of the bus they happen to be
 *	on.
 */

int
ddi_dev_affinity(dev_info_t *deva, dev_info_t *devb);


/*
 * ddi_set_callback
 *
 *	Set a function/arg pair into the callback list identified
 *	by listid. *listid must always initially start out as zero.
 */

void
ddi_set_callback(int (*funcp)(caddr_t), caddr_t arg, uintptr_t *listid);

/*
 * ddi_run_callback
 *
 *	Run the callback list identified by listid.
 */

void
ddi_run_callback(uintptr_t *listid);

/*
 * More miscellaneous
 */

int
nochpoll(dev_t dev, short events, int anyyet, short *reventsp,
	struct pollhead **phpp);

dev_info_t *
nodevinfo(dev_t dev, int otyp);

int
ddi_no_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result);

int
ddi_getinfo_1to1(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);

int
ddifail(dev_info_t *devi, ddi_attach_cmd_t cmd);

int
ddi_no_dma_map(dev_info_t *dip, dev_info_t *rdip,
    struct ddi_dma_req *dmareqp, ddi_dma_handle_t *handlep);

int
ddi_no_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep);

int
ddi_no_dma_freehdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle);

int
ddi_no_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
    ddi_dma_cookie_t *cp, uint_t *ccountp);

int
ddi_no_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle);

int
ddi_no_dma_flush(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len,
    uint_t cache_flags);

int
ddi_no_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp,
    size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp);

int
ddi_no_dma_mctl(register dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, enum ddi_dma_ctlops request,
    off_t *offp, size_t *lenp, caddr_t *objp, uint_t flags);

void
ddivoid();

cred_t *
ddi_get_cred(void);

time_t
ddi_get_time(void);

pid_t
ddi_get_pid(void);

kt_did_t
ddi_get_kt_did(void);

boolean_t
ddi_can_receive_sig(void);

void
swab(void *src, void *dst, size_t nbytes);

int
ddi_create_minor_node(dev_info_t *dip, char *name, int spec_type,
    minor_t minor_num, char *node_type, int flag);

int
ddi_create_priv_minor_node(dev_info_t *dip, char *name, int spec_type,
    minor_t minor_num, char *node_type, int flag,
    const char *rdpriv, const char *wrpriv, mode_t priv_mode);

void
ddi_remove_minor_node(dev_info_t *dip, char *name);

int
ddi_in_panic(void);

int
ddi_streams_driver(dev_info_t *dip);

/*
 * DDI wrappers for ffs and fls
 */
int
ddi_ffs(long mask);

int
ddi_fls(long mask);

/*
 * The ddi_soft_state* routines comprise generic storage management utilities
 * for driver soft state structures.  Two types of soft_state indexes are
 * supported: 'integer index', and 'string index'.
 */
typedef	struct __ddi_soft_state_bystr	ddi_soft_state_bystr;

/*
 * Initialize a soft_state set, establishing the 'size' of soft state objects
 * in the set.
 *
 * For an 'integer indexed' soft_state set, the initial set will accommodate
 * 'n_items' objects - 'n_items' is a hint (i.e. zero is allowed), allocations
 * that exceed 'n_items' have additional overhead.
 *
 * For a 'string indexed' soft_state set, 'n_items' should be the typical
 * number of soft state objects in the set - 'n_items' is a hint, there may
 * be additional overhead if the hint is too small (and wasted memory if the
 * hint is too big).
 */
int
ddi_soft_state_init(void **state_p, size_t size, size_t n_items);
int
ddi_soft_state_bystr_init(ddi_soft_state_bystr **state_p,
    size_t size, int n_items);

/*
 * Allocate a soft state object associated with either 'integer index' or
 * 'string index' from a soft_state set.
 */
int
ddi_soft_state_zalloc(void *state, int item);
int
ddi_soft_state_bystr_zalloc(ddi_soft_state_bystr *state, const char *str);

/*
 * Get the pointer to the allocated soft state object associated with
 * either 'integer index' or 'string index'.
 */
void *
ddi_get_soft_state(void *state, int item);
void *
ddi_soft_state_bystr_get(ddi_soft_state_bystr *state, const char *str);

/*
 * Free the soft state object associated with either 'integer index'
 * or 'string index'.
 */
void
ddi_soft_state_free(void *state, int item);
void
ddi_soft_state_bystr_free(ddi_soft_state_bystr *state, const char *str);

/*
 * Free the soft state set and any associated soft state objects.
 */
void
ddi_soft_state_fini(void **state_p);
void
ddi_soft_state_bystr_fini(ddi_soft_state_bystr **state_p);

/*
 * The ddi_strid_* routines provide string-to-index management utilities.
 */
typedef	struct __ddi_strid	ddi_strid;
int
ddi_strid_init(ddi_strid **strid_p, int n_items);
id_t
ddi_strid_alloc(ddi_strid *strid, char *str);
id_t
ddi_strid_str2id(ddi_strid *strid, char *str);
char *
ddi_strid_id2str(ddi_strid *strid, id_t id);
void
ddi_strid_free(ddi_strid *strid, id_t id);
void
ddi_strid_fini(ddi_strid **strid_p);

/*
 * Set the addr field of the name in dip to name
 */
void
ddi_set_name_addr(dev_info_t *dip, char *name);

/*
 * Get the address part of the name.
 */
char *
ddi_get_name_addr(dev_info_t *dip);

void
ddi_set_parent_data(dev_info_t *dip, void *pd);

void *
ddi_get_parent_data(dev_info_t *dip);

int
ddi_initchild(dev_info_t *parent, dev_info_t *proto);

int
ddi_uninitchild(dev_info_t *dip);

major_t
ddi_name_to_major(char *name);

char *
ddi_major_to_name(major_t major);

char *
ddi_deviname(dev_info_t *dip, char *name);

char *
ddi_pathname(dev_info_t *dip, char *path);

char *
ddi_pathname_minor(struct ddi_minor_data *dmdp, char *path);

char *
ddi_pathname_obp(dev_info_t *dip, char *path);

int
ddi_pathname_obp_set(dev_info_t *dip, char *component);

int
ddi_dev_pathname(dev_t devt, int spec_type, char *name);

dev_t
ddi_pathname_to_dev_t(char *pathname);

/*
 * High resolution system timer functions.
 *
 * These functions are already in the kernel (see sys/time.h).
 * The ddi supports the notion of a hrtime_t type and the
 * functions gethrtime, hrtadd, hrtsub and hrtcmp.
 */


/*
 * Nexus wrapper functions
 *
 * These functions are for entries in a bus nexus driver's bus_ops
 * structure for when the driver doesn't have such a function and
 * doesn't wish to prohibit such a function from existing. They
 * may also be called to start passing a request up the dev_info
 * tree.
 */

/*
 * bus_ctl wrapper
 */

int
ddi_ctlops(dev_info_t *d, dev_info_t *r, ddi_ctl_enum_t o, void *a, void *v);

/*
 * bus_dma_map wrapper
 */

int
ddi_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
	int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep);

int
ddi_dma_freehdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle);

int
ddi_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
	ddi_dma_cookie_t *cp, uint_t *ccountp);

int
ddi_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle);

int
ddi_dma_flush(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, off_t off, size_t len,
	uint_t cache_flags);

int
ddi_dma_win(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, uint_t win, off_t *offp,
	size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp);

/*
 * bus_dma_ctl wrapper
 */

int
ddi_dma_mctl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
	enum ddi_dma_ctlops request, off_t *offp, size_t *lenp,
	caddr_t *objp, uint_t flags);

/*
 * dvma support for networking drivers
 */

unsigned long
dvma_pagesize(dev_info_t *dip);

int
dvma_reserve(dev_info_t *dip,  ddi_dma_lim_t *limp, uint_t pages,
	ddi_dma_handle_t *handlep);

void
dvma_release(ddi_dma_handle_t h);

void
dvma_kaddr_load(ddi_dma_handle_t h, caddr_t a, uint_t len, uint_t index,
	ddi_dma_cookie_t *cp);

void
dvma_unload(ddi_dma_handle_t h, uint_t objindex, uint_t type);

void
dvma_sync(ddi_dma_handle_t h, uint_t objindex, uint_t type);

/*
 * Layered driver support
 */

extern int ddi_copyin(const void *, void *, size_t, int);
extern int ddi_copyout(const void *, void *, size_t, int);

/*
 * Send signals to processes
 */
extern void *proc_ref(void);
extern void proc_unref(void *pref);
extern int proc_signal(void *pref, int sig);

/* I/O port access routines */
extern uint8_t inb(int port);
extern uint16_t inw(int port);
extern uint32_t inl(int port);
extern void outb(int port, uint8_t value);
extern void outw(int port, uint16_t value);
extern void outl(int port, uint32_t value);

/*
 * Console bell routines
 */
extern void ddi_ring_console_bell(clock_t duration);
extern void ddi_set_console_bell(void (*bellfunc)(clock_t duration));

/*
 * Fault-related functions
 */
extern int ddi_check_acc_handle(ddi_acc_handle_t);
extern int ddi_check_dma_handle(ddi_dma_handle_t);
extern void ddi_dev_report_fault(dev_info_t *, ddi_fault_impact_t,
	ddi_fault_location_t, const char *);
extern ddi_devstate_t ddi_get_devstate(dev_info_t *);

/*
 * Miscellaneous redefines
 */
#define	uiophysio	physio

/*
 * utilities - "reg" mapping and all common portable data access functions
 */

/*
 * error code from ddi_regs_map_setup
 */

#define	DDI_REGS_ACC_CONFLICT	(-10)

/*
 * Device address advance flags
 */

#define	 DDI_DEV_NO_AUTOINCR	0x0000
#define	 DDI_DEV_AUTOINCR	0x0001

int
ddi_regs_map_setup(dev_info_t *dip, uint_t rnumber, caddr_t *addrp,
	offset_t offset, offset_t len, ddi_device_acc_attr_t *accattrp,
	ddi_acc_handle_t *handle);

void
ddi_regs_map_free(ddi_acc_handle_t *handle);

/*
 * these are the prototypes for the common portable data access functions
 */

uint8_t
ddi_get8(ddi_acc_handle_t handle, uint8_t *addr);

uint16_t
ddi_get16(ddi_acc_handle_t handle, uint16_t *addr);

uint32_t
ddi_get32(ddi_acc_handle_t handle, uint32_t *addr);

uint64_t
ddi_get64(ddi_acc_handle_t handle, uint64_t *addr);

void
ddi_rep_get8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
	size_t repcount, uint_t flags);

void
ddi_rep_get16(ddi_acc_handle_t handle, uint16_t *host_addr, uint16_t *dev_addr,
	size_t repcount, uint_t flags);

void
ddi_rep_get32(ddi_acc_handle_t handle, uint32_t *host_addr, uint32_t *dev_addr,
	size_t repcount, uint_t flags);

void
ddi_rep_get64(ddi_acc_handle_t handle, uint64_t *host_addr, uint64_t *dev_addr,
	size_t repcount, uint_t flags);

void
ddi_put8(ddi_acc_handle_t handle, uint8_t *addr, uint8_t value);

void
ddi_put16(ddi_acc_handle_t handle, uint16_t *addr, uint16_t value);

void
ddi_put32(ddi_acc_handle_t handle, uint32_t *addr, uint32_t value);

void
ddi_put64(ddi_acc_handle_t handle, uint64_t *addr, uint64_t value);

void
ddi_rep_put8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
	size_t repcount, uint_t flags);
void
ddi_rep_put16(ddi_acc_handle_t handle, uint16_t *host_addr, uint16_t *dev_addr,
	size_t repcount, uint_t flags);
void
ddi_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr, uint32_t *dev_addr,
	size_t repcount, uint_t flags);

void
ddi_rep_put64(ddi_acc_handle_t handle, uint64_t *host_addr, uint64_t *dev_addr,
	size_t repcount, uint_t flags);

/*
 * these are special device handling functions
 */
int
ddi_device_zero(ddi_acc_handle_t handle, caddr_t dev_addr,
	size_t bytecount, ssize_t dev_advcnt, uint_t dev_datasz);

int
ddi_device_copy(
	ddi_acc_handle_t src_handle, caddr_t src_addr, ssize_t src_advcnt,
	ddi_acc_handle_t dest_handle, caddr_t dest_addr, ssize_t dest_advcnt,
	size_t bytecount, uint_t dev_datasz);

/*
 * these are software byte swapping functions
 */
uint16_t
ddi_swap16(uint16_t value);

uint32_t
ddi_swap32(uint32_t value);

uint64_t
ddi_swap64(uint64_t value);

/*
 * these are the prototypes for PCI local bus functions
 */
/*
 * PCI power management capabilities reporting in addition to those
 * provided by the PCI Power Management Specification.
 */
#define	PCI_PM_IDLESPEED	0x1		/* clock for idle dev - cap  */
#define	PCI_PM_IDLESPEED_ANY	(void *)-1	/* any clock for idle dev */
#define	PCI_PM_IDLESPEED_NONE	(void *)-2	/* regular clock for idle dev */

int
pci_config_setup(dev_info_t *dip, ddi_acc_handle_t *handle);

void
pci_config_teardown(ddi_acc_handle_t *handle);

uint8_t
pci_config_get8(ddi_acc_handle_t handle, off_t offset);

uint16_t
pci_config_get16(ddi_acc_handle_t handle, off_t offset);

uint32_t
pci_config_get32(ddi_acc_handle_t handle, off_t offset);

uint64_t
pci_config_get64(ddi_acc_handle_t handle, off_t offset);

void
pci_config_put8(ddi_acc_handle_t handle, off_t offset, uint8_t value);

void
pci_config_put16(ddi_acc_handle_t handle, off_t offset, uint16_t value);

void
pci_config_put32(ddi_acc_handle_t handle, off_t offset, uint32_t value);

void
pci_config_put64(ddi_acc_handle_t handle, off_t offset, uint64_t value);

int
pci_report_pmcap(dev_info_t *dip, int cap, void *arg);

int
pci_restore_config_regs(dev_info_t *dip);

int
pci_save_config_regs(dev_info_t *dip);

void
pci_ereport_setup(dev_info_t *dip);

void
pci_ereport_teardown(dev_info_t *dip);

void
pci_ereport_post(dev_info_t *dip, ddi_fm_error_t *derr, uint16_t *status);

#if defined(__i386) || defined(__amd64)
int
pci_peekpoke_check(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *, void *,
	int (*handler)(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
	void *), kmutex_t *, kmutex_t *,
	void (*scan)(dev_info_t *, ddi_fm_error_t *));
#endif

void
pci_target_enqueue(uint64_t, char *, char *, uint64_t);

void
pci_targetq_init(void);

int
pci_post_suspend(dev_info_t *dip);

int
pci_pre_resume(dev_info_t *dip);

/*
 * the prototype for the C Language Type Model inquiry.
 */
model_t	ddi_mmap_get_model(void);
model_t	ddi_model_convert_from(model_t);

/*
 * these are the prototypes for device id functions.
 */
int
ddi_devid_valid(ddi_devid_t devid);

int
ddi_devid_register(dev_info_t *dip, ddi_devid_t devid);

void
ddi_devid_unregister(dev_info_t *dip);

int
ddi_devid_init(dev_info_t *dip, ushort_t devid_type, ushort_t nbytes,
    void *id, ddi_devid_t *ret_devid);

int
ddi_devid_get(dev_info_t *dip, ddi_devid_t *ret_devid);

size_t
ddi_devid_sizeof(ddi_devid_t devid);

void
ddi_devid_free(ddi_devid_t devid);

int
ddi_devid_compare(ddi_devid_t id1, ddi_devid_t id2);

int
ddi_devid_scsi_encode(int version, char *driver_name,
    uchar_t *inq, size_t inq_len, uchar_t *inq80, size_t inq80_len,
    uchar_t *inq83, size_t inq83_len, ddi_devid_t *ret_devid);

int
ddi_devid_smp_encode(int version, char *driver_name,
    char *wwnstr, uchar_t *srmir_buf, size_t srmir_len,
    ddi_devid_t *ret_devid);

char
*ddi_devid_to_guid(ddi_devid_t devid);

void
ddi_devid_free_guid(char *guid);

int
ddi_lyr_get_devid(dev_t dev, ddi_devid_t *ret_devid);

int
ddi_lyr_get_minor_name(dev_t dev, int spec_type, char **minor_name);

int
ddi_lyr_devid_to_devlist(ddi_devid_t devid, char *minor_name, int *retndevs,
    dev_t **retdevs);

void
ddi_lyr_free_devlist(dev_t *devlist, int ndevs);

char *
ddi_devid_str_encode(ddi_devid_t devid, char *minor_name);

int
ddi_devid_str_decode(char *devidstr, ddi_devid_t *devidp, char **minor_namep);

void
ddi_devid_str_free(char *devidstr);

int
ddi_devid_str_compare(char *id1_str, char *id2_str);

/*
 * Event to post to when a devinfo node is removed.
 */
#define	DDI_DEVI_REMOVE_EVENT		"DDI:DEVI_REMOVE"
#define	DDI_DEVI_INSERT_EVENT		"DDI:DEVI_INSERT"
#define	DDI_DEVI_BUS_RESET_EVENT	"DDI:DEVI_BUS_RESET"
#define	DDI_DEVI_DEVICE_RESET_EVENT	"DDI:DEVI_DEVICE_RESET"

/*
 * Invoke bus nexus driver's implementation of the
 * (*bus_remove_eventcall)() interface to remove a registered
 * callback handler for "event".
 */
int
ddi_remove_event_handler(ddi_callback_id_t id);

/*
 * Invoke bus nexus driver's implementation of the
 * (*bus_add_eventcall)() interface to register a callback handler
 * for "event".
 */
int
ddi_add_event_handler(dev_info_t *dip, ddi_eventcookie_t event,
	void (*handler)(dev_info_t *, ddi_eventcookie_t, void *, void *),
	void *arg, ddi_callback_id_t *id);

/*
 * Return a handle for event "name" by calling up the device tree
 * hierarchy via  (*bus_get_eventcookie)() interface until claimed
 * by a bus nexus or top of dev_info tree is reached.
 */
int
ddi_get_eventcookie(dev_info_t *dip, char *name,
	ddi_eventcookie_t *event_cookiep);

/*
 * log a system event
 */
int
ddi_log_sysevent(dev_info_t *dip, char *vendor, char *class_name,
	char *subclass_name, nvlist_t *attr_list, sysevent_id_t *eidp,
	int sleep_flag);

/*
 * ddi_log_sysevent() vendors
 */
#define	DDI_VENDOR_SUNW		"SUNW"

/*
 * Opaque task queue handle.
 */
typedef struct ddi_taskq ddi_taskq_t;

/*
 * Use default system priority.
 */
#define	TASKQ_DEFAULTPRI -1

/*
 * Create a task queue
 */
ddi_taskq_t *ddi_taskq_create(dev_info_t *dip, const char *name,
	int nthreads, pri_t pri, uint_t cflags);

/*
 * destroy a task queue
 */
void ddi_taskq_destroy(ddi_taskq_t *tq);

/*
 * Dispatch a task to a task queue
 */
int ddi_taskq_dispatch(ddi_taskq_t *tq, void (* func)(void *),
	void *arg, uint_t dflags);

/*
 * Wait for all previously scheduled tasks to complete.
 */
void ddi_taskq_wait(ddi_taskq_t *tq);

/*
 * Suspend all task execution.
 */
void ddi_taskq_suspend(ddi_taskq_t *tq);

/*
 * Resume task execution.
 */
void ddi_taskq_resume(ddi_taskq_t *tq);

/*
 * Is task queue suspended?
 */
boolean_t ddi_taskq_suspended(ddi_taskq_t *tq);

/*
 * Parse an interface name of the form <alphanumeric>##<numeric> where
 * <numeric> is maximal.
 */
int ddi_parse(const char *, char *, uint_t *);

/*
 * DDI interrupt priority level
 */
#define	DDI_IPL_0	(0)	/* kernel context */
#define	DDI_IPL_1	(1)	/* interrupt priority level 1 */
#define	DDI_IPL_2	(2)	/* interrupt priority level 2 */
#define	DDI_IPL_3	(3)	/* interrupt priority level 3 */
#define	DDI_IPL_4	(4)	/* interrupt priority level 4 */
#define	DDI_IPL_5	(5)	/* interrupt priority level 5 */
#define	DDI_IPL_6	(6)	/* interrupt priority level 6 */
#define	DDI_IPL_7	(7)	/* interrupt priority level 7 */
#define	DDI_IPL_8	(8)	/* interrupt priority level 8 */
#define	DDI_IPL_9	(9)	/* interrupt priority level 9 */
#define	DDI_IPL_10	(10)	/* interrupt priority level 10 */

/*
 * DDI periodic timeout interface
 */
ddi_periodic_t ddi_periodic_add(void (*)(void *), void *, hrtime_t, int);
void ddi_periodic_delete(ddi_periodic_t);

/*
 * Default quiesce(9E) implementation for drivers that don't need to do
 * anything.
 */
int ddi_quiesce_not_needed(dev_info_t *);

/*
 * Default quiesce(9E) initialization function for drivers that should
 * implement quiesce but haven't yet.
 */
int ddi_quiesce_not_supported(dev_info_t *);

/*
 * DDI generic callback interface
 */

typedef struct __ddi_cb **ddi_cb_handle_t;

int	ddi_cb_register(dev_info_t *dip, ddi_cb_flags_t flags,
	    ddi_cb_func_t cbfunc, void *arg1, void *arg2,
	    ddi_cb_handle_t *ret_hdlp);
int	ddi_cb_unregister(ddi_cb_handle_t hdl);

/* Notify DDI of memory added */
void ddi_mem_update(uint64_t addr, uint64_t size);

/* Path alias interfaces */
typedef struct plat_alias {
	char *pali_current;
	uint64_t pali_naliases;
	char **pali_aliases;
} plat_alias_t;

typedef struct alias_pair {
	char *pair_alias;
	char *pair_curr;
} alias_pair_t;

extern boolean_t ddi_aliases_present;

typedef struct ddi_alias {
	alias_pair_t	*dali_alias_pairs;
	alias_pair_t	*dali_curr_pairs;
	int		dali_num_pairs;
	mod_hash_t	*dali_alias_TLB;
	mod_hash_t	*dali_curr_TLB;
} ddi_alias_t;

extern ddi_alias_t ddi_aliases;

void ddi_register_aliases(plat_alias_t *pali, uint64_t npali);
dev_info_t *ddi_alias_redirect(char *alias);
char *ddi_curr_redirect(char *curr);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SUNDDI_H */
