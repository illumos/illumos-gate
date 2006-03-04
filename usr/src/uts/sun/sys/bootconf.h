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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BOOTCONF_H
#define	_SYS_BOOTCONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* SunOS-4.0 1.7 */

/*
 * Boot time configuration information objects
 */

#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/bootstat.h>

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
	 * pointer to our parents bootops
	 */
	struct bootops  *bsys_super;

	/*
	 * the area containing boot's memlists (non-LP64 boot)
	 */
	struct  bsys_mem *boot_mem;

#ifndef _LP64
	uint32_t	bsys_pad2[2]; /* pointers above get larger */
#endif
	/*
	 * The entry point to jump to for boot services.
	 * Pass this routine the array of boot_cell_t's describing the
	 * service requested.
	 */
	uint64_t bsys_1275_call;

	uint32_t	bsys_pad1[7];
	/*
	 * print formatted output - PRINTFLIKE1
	 * here (and maintained) so old kernels can fail with
	 * an error message rather than something weird.
	 * not really 'printf' though.
	 */
	uint32_t	bsys_printf;
} bootops_t;

extern uint_t bop_getversion(struct bootops *bootops);
extern int bop_open(struct bootops *bop, char *s, int flags);
extern int bop_read(struct bootops *bop, int fd, caddr_t buf, size_t size);
extern int bop_seek(struct bootops *bop, int fd, off_t hi, off_t lo);
extern int bop_close(struct bootops *bop, int fd);
extern caddr_t bop_alloc(struct bootops *bop, caddr_t virthint, size_t size,
    int align);
extern caddr_t bop_alloc_virt(struct bootops *bop, caddr_t virt, size_t size);
extern void bop_free(struct bootops *bop, caddr_t virt, size_t size);
extern caddr_t bop_map(struct bootops *bop, caddr_t virt, int space,
    caddr_t phys, size_t size);
extern void bop_unmap(struct bootops *bop, caddr_t virt, size_t size);
extern void bop_quiesce_io(struct bootops *bop);
extern int bop_getproplen(struct bootops *bop, char *name);
extern int bop_getprop(struct bootops *bop, char *name, void *value);
extern char *bop_nextprop(struct bootops *bop, char *prevprop);
extern int bop_mountroot(struct bootops *bop, char *path);
extern int bop_unmountroot(struct bootops *bop);
extern void bop_puts(struct bootops *, char *);
extern void bop_putsarg(struct bootops *, const char *, ...);
extern int bop_fstat(struct bootops *, int fd, struct bootstat *);
extern void bop_enter_mon(struct bootops *bop);

#define	BOP_GETVERSION(bop)		bop_getversion(bop)
#define	BOP_OPEN(bop, s, flags)		bop_open(bop, s, flags)
#define	BOP_READ(bop, fd, buf, size)	bop_read(bop, fd, buf, size)
#define	BOP_SEEK(bop, fd, hi, lo)	bop_seek(bop, fd, hi, lo)
#define	BOP_CLOSE(bop, fd)		bop_close(bop, fd)
#define	BOP_ALLOC(bop, virthint, size, align)	\
				bop_alloc(bop, virthint, size, align)
#define	BOP_ALLOC_VIRT(bop, virt, size)	bop_alloc_virt(bop, virt, size)
#define	BOP_FREE(bop, virt, size)	bop_free(bop, virt, size)
#define	BOP_MAP(bop, virt, space, phys, size)	\
				bop_map(bop, virt, space, phys, size)
#define	BOP_UNMAP(bop, virt, size)	bop_unmap(bop, virt, size)
#define	BOP_QUIESCE_IO(bop)		bop_quiesce_io(bop)
#define	BOP_GETPROPLEN(bop, name)	bop_getproplen(bop, name)
#define	BOP_GETPROP(bop, name, buf)	bop_getprop(bop, name, buf)
#define	BOP_NEXTPROP(bop, prev)		bop_nextprop(bop, prev)
#define	BOP_MOUNTROOT(bop, path)	bop_mountroot(bop, path)
#define	BOP_UNMOUNTROOT(bop)		bop_unmountroot(bop)
#define	BOP_PUTS(bop, msg)		bop_puts(bop, msg)
#define	BOP_PUTSARG(bop, msg, arg)	bop_putsarg(bop, msg, arg)
#define	BOP_FSTAT(bop, fd, st)		bop_fstat(bop, fd, st)
#define	BOP_ENTER_MON(bop)		bop_enter_mon(bop)

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
extern char svm_bootpath[BO_MAXOBJNAME];
extern char zfs_bootpath[BO_MAXOBJNAME];

extern dev_t getrootdev(void);
extern void getfsname(char *, char *, size_t);
extern int loadrootmodules(void);

extern int strplumb(void);
extern int strplumb_load(void);

extern void consconfig(void);

extern int dhcpinit(void);

/* XXX	Doesn't belong here */
extern int zsgetspeed(dev_t);

extern void param_check(void);

extern struct bootops *bootops;
extern int netboot;
extern int swaploaded;
extern int modrootloaded;
extern char kern_bootargs[];
extern char *default_path;
extern char *dhcack;
extern char *netdev_path;

#endif /* _KERNEL && !_BOOT */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_BOOTCONF_H */
