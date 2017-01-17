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
 * Copyright 2016 Nexenta Systems, Inc.
 */

#ifndef	_SYS_BOOTCONF_H
#define	_SYS_BOOTCONF_H


/*
 * Boot time configuration information objects
 */

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/sysmacros.h>
#include <sys/memlist.h>
#include <sys/bootstat.h>
#include <net/if.h>			/* for IFNAMSIZ */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * masks to hand to bsys_alloc memory allocator
 * XXX	These names shouldn't really be srmmu derived.
 */
#define	BO_NO_ALIGN	0x00001000
#define	BO_ALIGN_L3	0x00001000
#define	BO_ALIGN_L2	0x00040000
#define	BO_ALIGN_L1	0x01000000

/*
 *  We pass a ptr to the space that boot has been using
 *  for its memory lists.
 */
struct bsys_mem {
	struct memlist *physinstalled;	/* amt of physmem installed */
	struct memlist *physavail;	/* amt of physmem avail for use */
	struct memlist *virtavail;	/* amt of virtmem avail for use */
	uint_t		extent; 	/* number of bytes in the space */
};

#define	BO_VERSION	9		/* bootops interface revision # */

#define	BOOTOPS_ARE_1275(bop) \
	((BOP_GETVERSION(bop)) >= 9 && (bop->bsys_1275_call != 0))

typedef struct bootops {
	/*
	 * the ubiquitous version number
	 */
	uint_t	bsys_version;

	/*
	 * The entry point to jump to for boot services.
	 * Pass this routine the array of boot_cell_t's describing the
	 * service requested.
	 */
	uint64_t bsys_1275_call;

	/*
	 * print formatted output - PRINTFLIKE1
	 * here (and maintained) so old kernels can fail with
	 * an error message rather than something weird.
	 * not really 'printf' though.
	 */
	uint32_t	bsys_printf;
} bootops_t;

extern void bop_init(void);
extern int bop_open(const char *s, int flags);
extern int bop_read(int fd, caddr_t buf, size_t size);
extern int bop_seek(int fd, off_t off);
extern int bop_close(int fd);
extern caddr_t bop_alloc(caddr_t virthint, size_t size, int align);
extern caddr_t bop_alloc_virt(caddr_t virt, size_t size);
extern caddr_t bop_temp_alloc(size_t size, int align);
extern caddr_t bop_alloc_chunk(caddr_t virthint, size_t size, int align);
extern void bop_free(caddr_t virt, size_t size);
extern int bop_getproplen(const char *name);
extern int bop_getprop(const char *name, void *value);
extern int bop_mountroot(void);
extern int bop_unmountroot(void);
extern int bop_fstat(int fd, struct bootstat *st);
extern void bop_enter_mon(void);
extern void bop_fini(void);

extern void bop_printf(void *ops, const char *fmt, ...);
extern void bop_putsarg(const char *fmt, char *arg);
extern void bop_panic(const char *s);

#define	BOP_OPEN(s, flags)		bop_open(s, flags)
#define	BOP_READ(fd, buf, size)		bop_read(fd, buf, size)
#define	BOP_SEEK(fd, off)		bop_seek(fd, off)
#define	BOP_CLOSE(fd)			bop_close(fd)
#define	BOP_ALLOC(bop, virthint, size, align)	\
				bop_alloc(virthint, size, align)
#define	BOP_ALLOC_VIRT(virt, size)	bop_alloc_virt(virt, size)
#define	BOP_FREE(bop, virt, size)	bop_free(virt, size)
#define	BOP_GETPROPLEN(bop, name)	bop_getproplen(name)
#define	BOP_GETPROP(bop, name, buf)	bop_getprop(name, buf)
#define	BOP_MOUNTROOT()			bop_mountroot()
#define	BOP_UNMOUNTROOT()		bop_unmountroot()
#define	BOP_FSTAT(bop, fd, st)		bop_fstat(fd, st)

/* special routine for kmdb only */
#define	BOP_PUTSARG(bop, fmt, arg)	bop_putsarg(fmt, arg)

/*
 * macros and declarations needed by clients of boot to
 * call the 1275-like boot interface routines.
 */

typedef unsigned long long boot_cell_t;

/*
 * Macros that work in both compilation models, to permit either a
 * sun4u/ILP32 or a sun4u/LP64 program to interface with the new
 * 1275-like boot service replacement for bootops.
 *
 * These macros stuff/unstuff arguments into/from boot_cell_t's, which are
 * fixed size in all models. Note that some of the types (e.g. off_t)
 * change size in the models.
 */
#define	boot_ptr2cell(p)	((boot_cell_t)((uintptr_t)((void *)(p))))
#define	boot_int2cell(i)	((boot_cell_t)((int)(i)))
#define	boot_uint2cell(u)	((boot_cell_t)((unsigned int)(u)))
#define	boot_uint642cell(u)	((boot_cell_t)((uint64_t)(u)))
#define	boot_offt2cell(u)	((boot_cell_t)((off_t)(u)))
#define	boot_size2cell(u)	((boot_cell_t)((size_t)(u)))
#define	boot_phandle2cell(ph)	((boot_cell_t)((unsigned)((phandle_t)(ph))))
#define	boot_dnode2cell(d)	((boot_cell_t)((unsigned)((pnode_t)(d))))
#define	boot_ihandle2cell(ih)	((boot_cell_t)((unsigned)((ihandle_t)(ih))))

#define	boot_cell2ptr(p)	((void *)(uintptr_t)((boot_cell_t)(p)))
#define	boot_cell2int(i)	((int)((boot_cell_t)(i)))
#define	boot_cell2uint(u)	((unsigned int)((boot_cell_t)(u)))
#define	boot_cell2uint64(u)	((uint64_t)((boot_cell_t)(u)))
#define	boot_cell2offt(u)	((off_t)((boot_cell_t)(u)))
#define	boot_cell2size(u)	((size_t)((boot_cell_t)(u)))
#define	boot_cell2phandle(ph)	((phandle_t)((boot_cell_t)(ph)))
#define	boot_cell2dnode(d)	((pnode_t)((boot_cell_t)(d)))
#define	boot_cell2ihandle(ih)	((ihandle_t)((boot_cell_t)(ih)))
#define	boot_cells2ull(h, l)	((unsigned long long)(boot_cell_t)(l))

#define	BOOT_SVC_FAIL	(int)(-1)
#define	BOOT_SVC_OK	(int)(1)

#if defined(_KERNEL) && !defined(_BOOT)

/*
 * Boot configuration information
 */

#define	BO_MAXFSNAME	16
#define	BO_MAXOBJNAME	256

struct bootobj {
	char	bo_fstype[BO_MAXFSNAME];	/* vfs type name (e.g. nfs) */
	char	bo_name[BO_MAXOBJNAME];		/* name of object */
	int	bo_flags;			/* flags, see below */
	int	bo_size;			/* number of blocks */
	struct vnode *bo_vp;			/* vnode of object */
	char	bo_devname[BO_MAXOBJNAME];
	char	bo_ifname[BO_MAXOBJNAME];
	int	bo_ppa;
};

/*
 * flags
 */
#define	BO_VALID	0x01	/* all information in object is valid */
#define	BO_BUSY		0x02	/* object is busy */

extern struct bootobj rootfs;
extern struct bootobj swapfile;

extern char obp_bootpath[BO_MAXOBJNAME];

extern dev_t getrootdev(void);
extern void getfsname(char *, char *, size_t);
extern int loadrootmodules(void);

extern int strplumb(void);
extern int strplumb_load(void);

extern void consconfig(void);
extern void release_bootstrap(void);

extern int dhcpinit(void);

/* XXX	Doesn't belong here */
extern int zsgetspeed(dev_t);

extern void param_check(void);

extern struct bootops *bootops;
extern int netboot;
extern int swaploaded;
extern int modrootloaded;
extern char kern_bootargs[];
extern char kern_bootfile[];
extern char *kobj_module_path;
extern char *default_path;
extern char *dhcack;
extern int dhcacklen;
extern char dhcifname[IFNAMSIZ];
extern char *netdev_path;

extern char *strplumb_get_netdev_path(void);

#endif /* _KERNEL && !_BOOT */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_BOOTCONF_H */
