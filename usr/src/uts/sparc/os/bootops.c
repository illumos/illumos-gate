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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Definitions of interfaces that provide services from the secondary
 * boot program to its clients (primarily Solaris, krtld, kmdb and their
 * successors.) This interface replaces the bootops (BOP) implementation
 * as the interface to be called by boot clients.
 *
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/reboot.h>
#include <sys/param.h>
#include <sys/varargs.h>
#include <sys/obpdefs.h>
#include <sys/promimpl.h>
#include <sys/prom_plat.h>
#include <sys/bootconf.h>
#include <sys/bootstat.h>
#include <sys/kobj_impl.h>

struct bootops *bootops;
struct bootops kbootops;

pnode_t chosennode;
/*
 * Flag to disable the use of real ramdisks (in the OBP - on Sparc) when
 * the associated memory is no longer available.
 */
int bootops_obp_ramdisk_disabled = 0;

#define	FAKE_ROOT	(pnode_t)1

struct fakeprop {
	char	*bootname;
	pnode_t	promnode;
	char	*promname;
} fakeprops[] = {
	{ "mfg-name", FAKE_ROOT, "name" },
	{ NULL, 0, NULL }
};

static void
fakelook_init(void)
{
	struct fakeprop *fpp = fakeprops;

	while (fpp->bootname != NULL) {
		switch (fpp->promnode) {
		case FAKE_ROOT:
			fpp->promnode = prom_rootnode();
			break;
		}
		fpp++;
	}
}

static struct fakeprop *
fakelook(const char *prop)
{
	struct fakeprop *fpp = fakeprops;

	while (fpp->bootname != NULL) {
		if (strcmp(prop, fpp->bootname) == 0)
			return (fpp);
		fpp++;
	}
	return (NULL);
}

ihandle_t bfs_ih = OBP_BADNODE;
ihandle_t afs_ih = OBP_BADNODE;

void
bop_init(void)
{
	chosennode = prom_chosennode();

	fakelook_init();

	/* fake bootops - it needs to point to non-NULL */
	bootops = &kbootops;
}

#define	MAXPROMFD	16

static ihandle_t prom_ihs[MAXPROMFD];
int filter_etc = 1;

/*
 * Implementation of the "open" boot service.
 */
/*ARGSUSED*/
int
bop_open(const char *name, int flags)
{
	int fd = -1, layered;
	ihandle_t ih;

	/*
	 * Only look underneath archive for /etc files
	 */
	layered = filter_etc ?
	    strncmp(name, "/etc", sizeof ("/etc") - 1) == 0 : 1;

	if (afs_ih != OBP_BADNODE) {
		ih = afs_ih;
		fd = prom_fopen(ih, (char *)name);
		if (fd == -1 && !layered)
			return (BOOT_SVC_FAIL);
	}
	if (fd == -1 && bfs_ih != OBP_BADNODE) {
		ih = bfs_ih;
		fd = prom_fopen(ih, (char *)name);
	}
	if (fd == -1)
		return (BOOT_SVC_FAIL);
	ASSERT(fd < MAXPROMFD);
	ASSERT(prom_ihs[fd] == 0);
	prom_ihs[fd] = ih;
	return (fd);
}

static void
spinner(void)
{
	static int pos;
	static char ind[] = "|/-\\";	/* that's entertainment? */
	static int blks_read;

	if ((blks_read++ & 0x3) == 0)
		prom_printf("%c\b", ind[pos++ & 3]);
}

/*
 * Implementation of the "read" boot service.
 */
int
bop_read(int fd, caddr_t buf, size_t size)
{
	ASSERT(prom_ihs[fd] != 0);
	spinner();
	return (prom_fread(prom_ihs[fd], fd, buf, size));
}

/*
 * Implementation of the "seek" boot service.
 */
int
bop_seek(int fd, off_t off)
{
	ASSERT(prom_ihs[fd] != 0);
	return (prom_fseek(prom_ihs[fd], fd, off));
}

/*
 * Implementation of the "close" boot service.
 */
int
bop_close(int fd)
{
	ASSERT(prom_ihs[fd] != 0);
	prom_fclose(prom_ihs[fd], fd);
	prom_ihs[fd] = 0;
	return (0);
}

/*
 * Simple temp memory allocator
 *
 * >PAGESIZE allocations are gotten directly from prom at bighand
 * smaller ones are satisfied from littlehand, which does a
 *  1 page bighand allocation when it runs out of memory
 */
static	caddr_t bighand = (caddr_t)BOOTTMPBASE;
static	caddr_t littlehand = (caddr_t)BOOTTMPBASE;

#define	NTMPALLOC	128

static	caddr_t temp_base[NTMPALLOC];
static	size_t	temp_size[NTMPALLOC];
static	int temp_indx;

#if defined(C_OBP)
void	cobp_free_mem(caddr_t, size_t);
#endif	/* C_OBP */


/*
 * temporary memory storage until bop_tmp_freeall is called
 * (after the kernel heap is initialized)
 */
caddr_t
bop_temp_alloc(size_t size, int align)
{
	caddr_t ret;

	/*
	 * OBP allocs 10MB to boot, which is where virthint = 0
	 * memory was allocated from.  Without boot, we allocate
	 * from BOOTTMPBASE and free when we're ready to take
	 * the machine from OBP
	 */
	if (size < PAGESIZE) {
		size_t left =
		    ALIGN(littlehand, PAGESIZE) - (uintptr_t)littlehand;

		size = roundup(size, MAX(align, 8));
		if (size <= left) {
			ret = littlehand;
			littlehand += size;
			return (ret);
		}
		littlehand = bighand + size;
	}
	size = roundup(size, PAGESIZE);
	ret = prom_alloc(bighand, size, align);
	if (ret == NULL)
		prom_panic("boot temp overflow");
	bighand += size;

	/* log it for bop_fini() */
	temp_base[temp_indx] = ret;
	temp_size[temp_indx] = size;
	if (++temp_indx == NTMPALLOC)
		prom_panic("out of bop temp space");

	return (ret);
}

void
bop_temp_freeall(void)
{
	int i;

	/*
	 * We have to call prom_free() with the same args
	 * as we used in prom_alloc()
	 */
	for (i = 0; i < NTMPALLOC; i++) {
		if (temp_base[i] == NULL)
			break;
#if !defined(C_OBP)
		prom_free(temp_base[i], temp_size[i]);
#else	/* !C_OBP */
		cobp_free_mem(temp_base[i], temp_size[i]);
#endif	/* !C_OBP */
	}
}


/*
 * Implementation of the "alloc" boot service.
 */
caddr_t
bop_alloc(caddr_t virthint, size_t size, int align)
{
	if (virthint == NULL)
		return (bop_temp_alloc(size, align));
	return (prom_alloc(virthint, size, align));
}


/*
 * Similar to bop_alloc functionality except that
 * it will try to breakup into PAGESIZE chunk allocations
 * if the original single chunk request failed.
 * This routine does not guarantee physical contig
 * allocation.
 */
caddr_t
bop_alloc_chunk(caddr_t virthint, size_t size, int align)
{
	caddr_t ret;
	size_t chunksz;

	if (virthint == NULL)
		return (bop_temp_alloc(size, align));

	if ((ret = prom_alloc(virthint, size, align)))
		return (ret);

	/*
	 * Normal request to prom_alloc has failed.
	 * We will attempt to satisfy the request by allocating
	 * smaller chunks resulting in allocation that
	 * will be virtually contiguous but potentially
	 * not physically contiguous. There are additional
	 * requirements before we want to do this:
	 * 1. virthirt must be PAGESIZE aligned.
	 * 2. align must not be greater than PAGESIZE
	 * 3. size request must be at least PAGESIZE
	 * Otherwise, we will revert back to the original
	 * bop_alloc behavior i.e. return failure.
	 */
	if (P2PHASE_TYPED(virthint, PAGESIZE, size_t) != 0 ||
	    align > PAGESIZE || size < PAGESIZE)
		return (ret);

	/*
	 * Now we will break up the allocation
	 * request in smaller chunks that are
	 * always PAGESIZE aligned.
	 */
	ret = virthint;
	chunksz = P2ALIGN((size >> 1), PAGESIZE);
	chunksz = MAX(chunksz, PAGESIZE);

	while (size) {
		do {
			/*LINTED E_FUNC_SET_NOT_USED*/
			caddr_t res;
			if ((res = prom_alloc(virthint, chunksz,
			    PAGESIZE))) {
				ASSERT(virthint == res);
				break;
			}

			chunksz >>= 1;
			chunksz = P2ALIGN(chunksz, PAGESIZE);
		} while (chunksz >= PAGESIZE);

		if (chunksz < PAGESIZE)
			/* Can't really happen.. */
			prom_panic("bop_alloc_chunk failed");

		virthint += chunksz;
		size -= chunksz;
		if (size < chunksz)
			chunksz = size;
	}
	return (ret);
}


/*
 * Implementation of the "alloc_virt" boot service
 */
caddr_t
bop_alloc_virt(caddr_t virt, size_t size)
{
	return (prom_claim_virt(size, virt));
}

/*
 * Implementation of the "free" boot service.
 */
/*ARGSUSED*/
void
bop_free(caddr_t virt, size_t size)
{
	prom_free(virt, size);
}



/*
 * Implementation of the "getproplen" boot service.
 */
/*ARGSUSED*/
int
bop_getproplen(const char *name)
{
	struct fakeprop *fpp;
	pnode_t node;
	char *prop;

	fpp = fakelook(name);
	if (fpp != NULL) {
		node = fpp->promnode;
		prop = fpp->promname;
	} else {
		node = chosennode;
		prop = (char *)name;
	}
	return (prom_getproplen(node, prop));
}

/*
 * Implementation of the "getprop" boot service.
 */
/*ARGSUSED*/
int
bop_getprop(const char *name, void *value)
{
	struct fakeprop *fpp;
	pnode_t node;
	char *prop;

	fpp = fakelook(name);
	if (fpp != NULL) {
		node = fpp->promnode;
		prop = fpp->promname;
	} else {
		node = chosennode;
		prop = (char *)name;
	}
	return (prom_getprop(node, prop, value));
}

/*
 * Implementation of the "print" boot service.
 */
/*ARGSUSED*/
void
vbop_printf(void *ptr, const char *fmt, va_list ap)
{
	prom_vprintf(fmt, ap);
}

void
bop_printf(void *ops, const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vbop_printf(ops, fmt, adx);
	va_end(adx);
}

/*
 * Special routine for kmdb
 */
void
bop_putsarg(const char *fmt, char *arg)
{
	prom_printf(fmt, arg);
}

/*
 * panic for krtld only
 */
void
bop_panic(const char *s)
{
	prom_panic((char *)s);
}

/*
 * Implementation of the "mount" boot service.
 *
 */
/*ARGSUSED*/
int
bop_mountroot(void)
{
	(void) prom_getprop(chosennode, "bootfs", (caddr_t)&bfs_ih);
	(void) prom_getprop(chosennode, "archfs", (caddr_t)&afs_ih);
	return ((bfs_ih == -1 && afs_ih == -1) ? BOOT_SVC_FAIL : BOOT_SVC_OK);
}

/*
 * Implementation of the "unmountroot" boot service.
 */
/*ARGSUSED*/
int
bop_unmountroot(void)
{

	if (bfs_ih != OBP_BADNODE) {
		(void) prom_close(bfs_ih);
		bfs_ih = OBP_BADNODE;
	}
	if (afs_ih != OBP_BADNODE) {
		(void) prom_close(afs_ih);
		afs_ih = OBP_BADNODE;
	}
	return (BOOT_SVC_OK);
}

/*
 * Implementation of the "fstat" boot service.
 */
int
bop_fstat(int fd, struct bootstat *st)
{
	ASSERT(prom_ihs[fd] != 0);
	return (prom_fsize(prom_ihs[fd], fd, (size_t *)&st->st_size));
}

int
boot_compinfo(int fd, struct compinfo *cb)
{
	ASSERT(prom_ihs[fd] != 0);
	return (prom_compinfo(prom_ihs[fd], fd,
	    &cb->iscmp, &cb->fsize, &cb->blksize));
}

void
bop_free_archive(void)
{
	char archive[OBP_MAXPATHLEN];
	pnode_t arph;
	uint32_t arbase, arsize, alloc_size;

	/*
	 * If the ramdisk will eventually be root, or we weren't
	 * booted via the archive, then nothing to do here
	 */
	if (root_is_ramdisk == B_TRUE ||
	    prom_getprop(chosennode, "bootarchive", archive) == -1)
		return;
	arph = prom_finddevice(archive);
	if (arph == -1 ||
	    prom_getprop(arph, OBP_ALLOCSIZE, (caddr_t)&alloc_size) == -1 ||
	    prom_getprop(arph, OBP_SIZE, (caddr_t)&arsize) == -1 ||
	    prom_getprop(arph, OBP_ADDRESS, (caddr_t)&arbase) == -1)
		prom_panic("can't free boot archive");

	bootops_obp_ramdisk_disabled = 1;

#if !defined(C_OBP)
	if (alloc_size == 0)
		prom_free((caddr_t)(uintptr_t)arbase, arsize);
	else {
		uint32_t arend = arbase + arsize;

		while (arbase < arend) {
			prom_free((caddr_t)(uintptr_t)arbase,
			    MIN(alloc_size, arend - arbase));
			arbase += alloc_size;
		}
	}
#else	/* !C_OBP */
	cobp_free_mem((caddr_t)(uintptr_t)arbase, arsize);
#endif	/* !C_OBP */
}

#if defined(C_OBP)
/*
 * Blech.  The C proms have a bug when freeing areas that cross
 * page sizes, so we have to break up the free into sections
 * bounded by the various pagesizes.
 */
void
cobp_free_mem(caddr_t base, size_t size)
{
	int i;
	size_t len, pgsz;

	/*
	 * Large pages only used when size > 512k
	 */
	if (size < MMU_PAGESIZE512K ||
	    ((uintptr_t)base & MMU_PAGEOFFSET512K) != 0) {
		prom_free(base, size);
		return;
	}
	for (i = 3; i >= 0; i--) {
		pgsz = page_get_pagesize(i);
		if (size < pgsz)
			continue;
		len = size & ~(pgsz - 1);
		prom_free(base, len);
		base += len;
		size -= len;
	}
}
#endif	/* C_OBP */


/*
 * Implementation of the "enter_mon" boot service.
 */
void
bop_enter_mon(void)
{
	prom_enter_mon();
}

/*
 * free elf info allocated by booter
 */
void
bop_free_elf(void)
{
	uint32_t eadr;
	uint32_t esize;
	extern Addr dynseg;
	extern size_t dynsize;

	if (bop_getprop("elfheader-address", (caddr_t)&eadr) == -1 ||
	    bop_getprop("elfheader-length", (caddr_t)&esize) == -1)
		prom_panic("missing elfheader");
	prom_free((caddr_t)(uintptr_t)eadr, roundup(esize, PAGESIZE));

	prom_free((caddr_t)(uintptr_t)dynseg, roundup(dynsize, PAGESIZE));
}


/* Simple message to indicate that the bootops pointer has been zeroed */
#ifdef DEBUG
int bootops_gone_on = 0;
#define	BOOTOPS_GONE() \
	if (bootops_gone_on) \
		prom_printf("The bootops vec is zeroed now!\n");
#else
#define	BOOTOPS_GONE()
#endif	/* DEBUG */

void
bop_fini(void)
{
	bop_free_archive();
	(void) bop_unmountroot();
	bop_free_elf();
	bop_temp_freeall();

	bootops = (struct bootops *)NULL;
	BOOTOPS_GONE();
}
