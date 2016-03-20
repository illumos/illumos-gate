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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 *
 * Copyright 2013 Joyent, Inc.  All rights reserved.
 */

/*
 * This file contains the functionality that mimics the boot operations
 * on SPARC systems or the old boot.bin/multiboot programs on x86 systems.
 * The x86 kernel now does everything on its own.
 */

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>
#include <sys/multiboot.h>
#include <sys/bootvfs.h>
#include <sys/bootprops.h>
#include <sys/varargs.h>
#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/boot_console.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/promif.h>
#include <sys/archsystm.h>
#include <sys/x86_archext.h>
#include <sys/kobj.h>
#include <sys/privregs.h>
#include <sys/sysmacros.h>
#include <sys/ctype.h>
#include <sys/fastboot.h>
#ifdef __xpv
#include <sys/hypervisor.h>
#include <net/if.h>
#endif
#include <vm/kboot_mmu.h>
#include <vm/hat_pte.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/fastboot_impl.h>
#include "acpi_fw.h"

static int have_console = 0;	/* set once primitive console is initialized */
static char *boot_args = "";

/*
 * Debugging macros
 */
static uint_t kbm_debug = 0;
#define	DBG_MSG(s)	{ if (kbm_debug) bop_printf(NULL, "%s", s); }
#define	DBG(x)		{ if (kbm_debug)			\
	bop_printf(NULL, "%s is %" PRIx64 "\n", #x, (uint64_t)(x));	\
	}

#define	PUT_STRING(s) {				\
	char *cp;				\
	for (cp = (s); *cp; ++cp)		\
		bcons_putchar(*cp);		\
	}

struct xboot_info *xbootp;	/* boot info from "glue" code in low memory */
bootops_t bootop;	/* simple bootops we'll pass on to kernel */
struct bsys_mem bm;

static uintptr_t next_virt;	/* next available virtual address */
static paddr_t next_phys;	/* next available physical address from dboot */
static paddr_t high_phys = -(paddr_t)1;	/* last used physical address */

/*
 * buffer for vsnprintf for console I/O
 */
#define	BUFFERSIZE	512
static char buffer[BUFFERSIZE];
/*
 * stuff to store/report/manipulate boot property settings.
 */
typedef struct bootprop {
	struct bootprop *bp_next;
	char *bp_name;
	uint_t bp_vlen;
	char *bp_value;
} bootprop_t;

static bootprop_t *bprops = NULL;
static char *curr_page = NULL;		/* ptr to avail bprop memory */
static int curr_space = 0;		/* amount of memory at curr_page */

#ifdef __xpv
start_info_t *xen_info;
shared_info_t *HYPERVISOR_shared_info;
#endif

/*
 * some allocator statistics
 */
static ulong_t total_bop_alloc_scratch = 0;
static ulong_t total_bop_alloc_kernel = 0;

static void build_firmware_properties(void);

static int early_allocation = 1;

int force_fastreboot = 0;
volatile int fastreboot_onpanic = 0;
int post_fastreboot = 0;
#ifdef	__xpv
volatile int fastreboot_capable = 0;
#else
volatile int fastreboot_capable = 1;
#endif

/*
 * Information saved from current boot for fast reboot.
 * If the information size exceeds what we have allocated, fast reboot
 * will not be supported.
 */
multiboot_info_t saved_mbi;
mb_memory_map_t saved_mmap[FASTBOOT_SAVED_MMAP_COUNT];
uint8_t saved_drives[FASTBOOT_SAVED_DRIVES_SIZE];
char saved_cmdline[FASTBOOT_SAVED_CMDLINE_LEN];
int saved_cmdline_len = 0;
size_t saved_file_size[FASTBOOT_MAX_FILES_MAP];

/*
 * Turn off fastreboot_onpanic to avoid panic loop.
 */
char fastreboot_onpanic_cmdline[FASTBOOT_SAVED_CMDLINE_LEN];
static const char fastreboot_onpanic_args[] = " -B fastreboot_onpanic=0";

/*
 * Pointers to where System Resource Affinity Table (SRAT), System Locality
 * Information Table (SLIT) and Maximum System Capability Table (MSCT)
 * are mapped into virtual memory
 */
struct srat	*srat_ptr = NULL;
struct slit	*slit_ptr = NULL;
struct msct	*msct_ptr = NULL;

/*
 * Allocate aligned physical memory at boot time. This allocator allocates
 * from the highest possible addresses. This avoids exhausting memory that
 * would be useful for DMA buffers.
 */
paddr_t
do_bop_phys_alloc(uint64_t size, uint64_t align)
{
	paddr_t	pa = 0;
	paddr_t	start;
	paddr_t	end;
	struct memlist	*ml = (struct memlist *)xbootp->bi_phys_install;

	/*
	 * Be careful if high memory usage is limited in startup.c
	 * Since there are holes in the low part of the physical address
	 * space we can treat physmem as a pfn (not just a pgcnt) and
	 * get a conservative upper limit.
	 */
	if (physmem != 0 && high_phys > pfn_to_pa(physmem))
		high_phys = pfn_to_pa(physmem);

	/*
	 * find the lowest or highest available memory in physinstalled
	 * On 32 bit avoid physmem above 4Gig if PAE isn't enabled
	 */
#if defined(__i386)
	if (xbootp->bi_use_pae == 0 && high_phys > FOUR_GIG)
		high_phys = FOUR_GIG;
#endif

	/*
	 * find the highest available memory in physinstalled
	 */
	size = P2ROUNDUP(size, align);
	for (; ml; ml = ml->ml_next) {
		start = P2ROUNDUP(ml->ml_address, align);
		end = P2ALIGN(ml->ml_address + ml->ml_size, align);
		if (start < next_phys)
			start = P2ROUNDUP(next_phys, align);
		if (end > high_phys)
			end = P2ALIGN(high_phys, align);

		if (end <= start)
			continue;
		if (end - start < size)
			continue;

		/*
		 * Early allocations need to use low memory, since
		 * physmem might be further limited by bootenv.rc
		 */
		if (early_allocation) {
			if (pa == 0 || start < pa)
				pa = start;
		} else {
			if (end - size > pa)
				pa = end - size;
		}
	}
	if (pa != 0) {
		if (early_allocation)
			next_phys = pa + size;
		else
			high_phys = pa;
		return (pa);
	}
	bop_panic("do_bop_phys_alloc(0x%" PRIx64 ", 0x%" PRIx64
	    ") Out of memory\n", size, align);
	/*NOTREACHED*/
}

uintptr_t
alloc_vaddr(size_t size, paddr_t align)
{
	uintptr_t rv;

	next_virt = P2ROUNDUP(next_virt, (uintptr_t)align);
	rv = (uintptr_t)next_virt;
	next_virt += size;
	return (rv);
}

/*
 * Allocate virtual memory. The size is always rounded up to a multiple
 * of base pagesize.
 */

/*ARGSUSED*/
static caddr_t
do_bsys_alloc(bootops_t *bop, caddr_t virthint, size_t size, int align)
{
	paddr_t a = align;	/* same type as pa for masking */
	uint_t pgsize;
	paddr_t pa;
	uintptr_t va;
	ssize_t s;		/* the aligned size */
	uint_t level;
	uint_t is_kernel = (virthint != 0);

	if (a < MMU_PAGESIZE)
		a = MMU_PAGESIZE;
	else if (!ISP2(a))
		prom_panic("do_bsys_alloc() incorrect alignment");
	size = P2ROUNDUP(size, MMU_PAGESIZE);

	/*
	 * Use the next aligned virtual address if we weren't given one.
	 */
	if (virthint == NULL) {
		virthint = (caddr_t)alloc_vaddr(size, a);
		total_bop_alloc_scratch += size;
	} else {
		total_bop_alloc_kernel += size;
	}

	/*
	 * allocate the physical memory
	 */
	pa = do_bop_phys_alloc(size, a);

	/*
	 * Add the mappings to the page tables, try large pages first.
	 */
	va = (uintptr_t)virthint;
	s = size;
	level = 1;
	pgsize = xbootp->bi_use_pae ? TWO_MEG : FOUR_MEG;
	if (xbootp->bi_use_largepage && a == pgsize) {
		while (IS_P2ALIGNED(pa, pgsize) && IS_P2ALIGNED(va, pgsize) &&
		    s >= pgsize) {
			kbm_map(va, pa, level, is_kernel);
			va += pgsize;
			pa += pgsize;
			s -= pgsize;
		}
	}

	/*
	 * Map remaining pages use small mappings
	 */
	level = 0;
	pgsize = MMU_PAGESIZE;
	while (s > 0) {
		kbm_map(va, pa, level, is_kernel);
		va += pgsize;
		pa += pgsize;
		s -= pgsize;
	}
	return (virthint);
}

/*
 * Free virtual memory - we'll just ignore these.
 */
/*ARGSUSED*/
static void
do_bsys_free(bootops_t *bop, caddr_t virt, size_t size)
{
	bop_printf(NULL, "do_bsys_free(virt=0x%p, size=0x%lx) ignored\n",
	    (void *)virt, size);
}

/*
 * Old interface
 */
/*ARGSUSED*/
static caddr_t
do_bsys_ealloc(
	bootops_t *bop,
	caddr_t virthint,
	size_t size,
	int align,
	int flags)
{
	prom_panic("unsupported call to BOP_EALLOC()\n");
	return (0);
}


static void
bsetprop(char *name, int nlen, void *value, int vlen)
{
	uint_t size;
	uint_t need_size;
	bootprop_t *b;

	/*
	 * align the size to 16 byte boundary
	 */
	size = sizeof (bootprop_t) + nlen + 1 + vlen;
	size = (size + 0xf) & ~0xf;
	if (size > curr_space) {
		need_size = (size + (MMU_PAGEOFFSET)) & MMU_PAGEMASK;
		curr_page = do_bsys_alloc(NULL, 0, need_size, MMU_PAGESIZE);
		curr_space = need_size;
	}

	/*
	 * use a bootprop_t at curr_page and link into list
	 */
	b = (bootprop_t *)curr_page;
	curr_page += sizeof (bootprop_t);
	curr_space -=  sizeof (bootprop_t);
	b->bp_next = bprops;
	bprops = b;

	/*
	 * follow by name and ending zero byte
	 */
	b->bp_name = curr_page;
	bcopy(name, curr_page, nlen);
	curr_page += nlen;
	*curr_page++ = 0;
	curr_space -= nlen + 1;

	/*
	 * copy in value, but no ending zero byte
	 */
	b->bp_value = curr_page;
	b->bp_vlen = vlen;
	if (vlen > 0) {
		bcopy(value, curr_page, vlen);
		curr_page += vlen;
		curr_space -= vlen;
	}

	/*
	 * align new values of curr_page, curr_space
	 */
	while (curr_space & 0xf) {
		++curr_page;
		--curr_space;
	}
}

static void
bsetprops(char *name, char *value)
{
	bsetprop(name, strlen(name), value, strlen(value) + 1);
}

static void
bsetprop64(char *name, uint64_t value)
{
	bsetprop(name, strlen(name), (void *)&value, sizeof (value));
}

static void
bsetpropsi(char *name, int value)
{
	char prop_val[32];

	(void) snprintf(prop_val, sizeof (prop_val), "%d", value);
	bsetprops(name, prop_val);
}

/*
 * to find the size of the buffer to allocate
 */
/*ARGSUSED*/
int
do_bsys_getproplen(bootops_t *bop, const char *name)
{
	bootprop_t *b;

	for (b = bprops; b; b = b->bp_next) {
		if (strcmp(name, b->bp_name) != 0)
			continue;
		return (b->bp_vlen);
	}
	return (-1);
}

/*
 * get the value associated with this name
 */
/*ARGSUSED*/
int
do_bsys_getprop(bootops_t *bop, const char *name, void *value)
{
	bootprop_t *b;

	for (b = bprops; b; b = b->bp_next) {
		if (strcmp(name, b->bp_name) != 0)
			continue;
		bcopy(b->bp_value, value, b->bp_vlen);
		return (0);
	}
	return (-1);
}

/*
 * get the name of the next property in succession from the standalone
 */
/*ARGSUSED*/
static char *
do_bsys_nextprop(bootops_t *bop, char *name)
{
	bootprop_t *b;

	/*
	 * A null name is a special signal for the 1st boot property
	 */
	if (name == NULL || strlen(name) == 0) {
		if (bprops == NULL)
			return (NULL);
		return (bprops->bp_name);
	}

	for (b = bprops; b; b = b->bp_next) {
		if (name != b->bp_name)
			continue;
		b = b->bp_next;
		if (b == NULL)
			return (NULL);
		return (b->bp_name);
	}
	return (NULL);
}

/*
 * Parse numeric value from a string. Understands decimal, hex, octal, - and ~
 */
static int
parse_value(char *p, uint64_t *retval)
{
	int adjust = 0;
	uint64_t tmp = 0;
	int digit;
	int radix = 10;

	*retval = 0;
	if (*p == '-' || *p == '~')
		adjust = *p++;

	if (*p == '0') {
		++p;
		if (*p == 0)
			return (0);
		if (*p == 'x' || *p == 'X') {
			radix = 16;
			++p;
		} else {
			radix = 8;
			++p;
		}
	}
	while (*p) {
		if ('0' <= *p && *p <= '9')
			digit = *p - '0';
		else if ('a' <= *p && *p <= 'f')
			digit = 10 + *p - 'a';
		else if ('A' <= *p && *p <= 'F')
			digit = 10 + *p - 'A';
		else
			return (-1);
		if (digit >= radix)
			return (-1);
		tmp = tmp * radix + digit;
		++p;
	}
	if (adjust == '-')
		tmp = -tmp;
	else if (adjust == '~')
		tmp = ~tmp;
	*retval = tmp;
	return (0);
}

/*
 * 2nd part of building the table of boot properties. This includes:
 * - values from /boot/solaris/bootenv.rc (ie. eeprom(1m) values)
 *
 * lines look like one of:
 * ^$
 * ^# comment till end of line
 * setprop name 'value'
 * setprop name value
 * setprop name "value"
 *
 * we do single character I/O since this is really just looking at memory
 */
void
boot_prop_finish(void)
{
	int fd;
	char *line;
	int c;
	int bytes_read;
	char *name;
	int n_len;
	char *value;
	int v_len;
	char *inputdev;	/* these override the command line if serial ports */
	char *outputdev;
	char *consoledev;
	uint64_t lvalue;
	int use_xencons = 0;

#ifdef __xpv
	if (!DOMAIN_IS_INITDOMAIN(xen_info))
		use_xencons = 1;
#endif /* __xpv */

	DBG_MSG("Opening /boot/solaris/bootenv.rc\n");
	fd = BRD_OPEN(bfs_ops, "/boot/solaris/bootenv.rc", 0);
	DBG(fd);

	line = do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, MMU_PAGESIZE);
	while (fd >= 0) {

		/*
		 * get a line
		 */
		for (c = 0; ; ++c) {
			bytes_read = BRD_READ(bfs_ops, fd, line + c, 1);
			if (bytes_read == 0) {
				if (c == 0)
					goto done;
				break;
			}
			if (line[c] == '\n')
				break;
		}
		line[c] = 0;

		/*
		 * ignore comment lines
		 */
		c = 0;
		while (ISSPACE(line[c]))
			++c;
		if (line[c] == '#' || line[c] == 0)
			continue;

		/*
		 * must have "setprop " or "setprop\t"
		 */
		if (strncmp(line + c, "setprop ", 8) != 0 &&
		    strncmp(line + c, "setprop\t", 8) != 0)
			continue;
		c += 8;
		while (ISSPACE(line[c]))
			++c;
		if (line[c] == 0)
			continue;

		/*
		 * gather up the property name
		 */
		name = line + c;
		n_len = 0;
		while (line[c] && !ISSPACE(line[c]))
			++n_len, ++c;

		/*
		 * gather up the value, if any
		 */
		value = "";
		v_len = 0;
		while (ISSPACE(line[c]))
			++c;
		if (line[c] != 0) {
			value = line + c;
			while (line[c] && !ISSPACE(line[c]))
				++v_len, ++c;
		}

		if (v_len >= 2 && value[0] == value[v_len - 1] &&
		    (value[0] == '\'' || value[0] == '"')) {
			++value;
			v_len -= 2;
		}
		name[n_len] = 0;
		if (v_len > 0)
			value[v_len] = 0;
		else
			continue;

		/*
		 * ignore "boot-file" property, it's now meaningless
		 */
		if (strcmp(name, "boot-file") == 0)
			continue;
		if (strcmp(name, "boot-args") == 0 &&
		    strlen(boot_args) > 0)
			continue;

		/*
		 * If a property was explicitly set on the command line
		 * it will override a setting in bootenv.rc
		 */
		if (do_bsys_getproplen(NULL, name) > 0)
			continue;

		bsetprop(name, n_len, value, v_len + 1);
	}
done:
	if (fd >= 0)
		(void) BRD_CLOSE(bfs_ops, fd);

	/*
	 * Check if we have to limit the boot time allocator
	 */
	if (do_bsys_getproplen(NULL, "physmem") != -1 &&
	    do_bsys_getprop(NULL, "physmem", line) >= 0 &&
	    parse_value(line, &lvalue) != -1) {
		if (0 < lvalue && (lvalue < physmem || physmem == 0)) {
			physmem = (pgcnt_t)lvalue;
			DBG(physmem);
		}
	}
	early_allocation = 0;

	/*
	 * check to see if we have to override the default value of the console
	 */
	if (!use_xencons) {
		inputdev = line;
		v_len = do_bsys_getproplen(NULL, "input-device");
		if (v_len > 0)
			(void) do_bsys_getprop(NULL, "input-device", inputdev);
		else
			v_len = 0;
		inputdev[v_len] = 0;

		outputdev = inputdev + v_len + 1;
		v_len = do_bsys_getproplen(NULL, "output-device");
		if (v_len > 0)
			(void) do_bsys_getprop(NULL, "output-device",
			    outputdev);
		else
			v_len = 0;
		outputdev[v_len] = 0;

		consoledev = outputdev + v_len + 1;
		v_len = do_bsys_getproplen(NULL, "console");
		if (v_len > 0) {
			(void) do_bsys_getprop(NULL, "console", consoledev);
			if (post_fastreboot &&
			    strcmp(consoledev, "graphics") == 0) {
				bsetprops("console", "text");
				v_len = strlen("text");
				bcopy("text", consoledev, v_len);
			}
		} else {
			v_len = 0;
		}
		consoledev[v_len] = 0;
		bcons_init2(inputdev, outputdev, consoledev);
	} else {
		/*
		 * Ensure console property exists
		 * If not create it as "hypervisor"
		 */
		v_len = do_bsys_getproplen(NULL, "console");
		if (v_len < 0)
			bsetprops("console", "hypervisor");
		inputdev = outputdev = consoledev = "hypervisor";
		bcons_init2(inputdev, outputdev, consoledev);
	}

	if (strstr((char *)xbootp->bi_cmdline, "prom_debug") || kbm_debug) {
		value = line;
		bop_printf(NULL, "\nBoot properties:\n");
		name = "";
		while ((name = do_bsys_nextprop(NULL, name)) != NULL) {
			bop_printf(NULL, "\t0x%p %s = ", (void *)name, name);
			(void) do_bsys_getprop(NULL, name, value);
			v_len = do_bsys_getproplen(NULL, name);
			bop_printf(NULL, "len=%d ", v_len);
			value[v_len] = 0;
			bop_printf(NULL, "%s\n", value);
		}
	}
}

/*
 * print formatted output
 */
/*PRINTFLIKE2*/
/*ARGSUSED*/
void
bop_printf(bootops_t *bop, const char *fmt, ...)
{
	va_list	ap;

	if (have_console == 0)
		return;

	va_start(ap, fmt);
	(void) vsnprintf(buffer, BUFFERSIZE, fmt, ap);
	va_end(ap);
	PUT_STRING(buffer);
}

/*
 * Another panic() variant; this one can be used even earlier during boot than
 * prom_panic().
 */
/*PRINTFLIKE1*/
void
bop_panic(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	bop_printf(NULL, fmt, ap);
	va_end(ap);

	bop_printf(NULL, "\nPress any key to reboot.\n");
	(void) bcons_getchar();
	bop_printf(NULL, "Resetting...\n");
	pc_reset();
}

/*
 * Do a real mode interrupt BIOS call
 */
typedef struct bios_regs {
	unsigned short ax, bx, cx, dx, si, di, bp, es, ds;
} bios_regs_t;
typedef int (*bios_func_t)(int, bios_regs_t *);

/*ARGSUSED*/
static void
do_bsys_doint(bootops_t *bop, int intnum, struct bop_regs *rp)
{
#if defined(__xpv)
	prom_panic("unsupported call to BOP_DOINT()\n");
#else	/* __xpv */
	static int firsttime = 1;
	bios_func_t bios_func = (bios_func_t)(void *)(uintptr_t)0x5000;
	bios_regs_t br;

	/*
	 * The first time we do this, we have to copy the pre-packaged
	 * low memory bios call code image into place.
	 */
	if (firsttime) {
		extern char bios_image[];
		extern uint32_t bios_size;

		bcopy(bios_image, (void *)bios_func, bios_size);
		firsttime = 0;
	}

	br.ax = rp->eax.word.ax;
	br.bx = rp->ebx.word.bx;
	br.cx = rp->ecx.word.cx;
	br.dx = rp->edx.word.dx;
	br.bp = rp->ebp.word.bp;
	br.si = rp->esi.word.si;
	br.di = rp->edi.word.di;
	br.ds = rp->ds;
	br.es = rp->es;

	DBG_MSG("Doing BIOS call...");
	DBG(br.ax);
	DBG(br.bx);
	DBG(br.dx);
	rp->eflags = bios_func(intnum, &br);
	DBG_MSG("done\n");

	rp->eax.word.ax = br.ax;
	rp->ebx.word.bx = br.bx;
	rp->ecx.word.cx = br.cx;
	rp->edx.word.dx = br.dx;
	rp->ebp.word.bp = br.bp;
	rp->esi.word.si = br.si;
	rp->edi.word.di = br.di;
	rp->ds = br.ds;
	rp->es = br.es;
#endif /* __xpv */
}

static struct boot_syscalls bop_sysp = {
	bcons_getchar,
	bcons_putchar,
	bcons_ischar,
};

static char *whoami;

#define	BUFLEN	64

#if defined(__xpv)

static char namebuf[32];

static void
xen_parse_props(char *s, char *prop_map[], int n_prop)
{
	char **prop_name = prop_map;
	char *cp = s, *scp;

	do {
		scp = cp;
		while ((*cp != NULL) && (*cp != ':'))
			cp++;

		if ((scp != cp) && (*prop_name != NULL)) {
			*cp = NULL;
			bsetprops(*prop_name, scp);
		}

		cp++;
		prop_name++;
		n_prop--;
	} while (n_prop > 0);
}

#define	VBDPATHLEN	64

/*
 * parse the 'xpv-root' property to create properties used by
 * ufs_mountroot.
 */
static void
xen_vbdroot_props(char *s)
{
	char vbdpath[VBDPATHLEN] = "/xpvd/xdf@";
	const char lnamefix[] = "/dev/dsk/c0d";
	char *pnp;
	char *prop_p;
	char mi;
	short minor;
	long addr = 0;

	pnp = vbdpath + strlen(vbdpath);
	prop_p = s + strlen(lnamefix);
	while ((*prop_p != '\0') && (*prop_p != 's') && (*prop_p != 'p'))
		addr = addr * 10 + *prop_p++ - '0';
	(void) snprintf(pnp, VBDPATHLEN, "%lx", addr);
	pnp = vbdpath + strlen(vbdpath);
	if (*prop_p == 's')
		mi = 'a';
	else if (*prop_p == 'p')
		mi = 'q';
	else
		ASSERT(0); /* shouldn't be here */
	prop_p++;
	ASSERT(*prop_p != '\0');
	if (ISDIGIT(*prop_p)) {
		minor = *prop_p - '0';
		prop_p++;
		if (ISDIGIT(*prop_p)) {
			minor = minor * 10 + *prop_p - '0';
		}
	} else {
		/* malformed root path, use 0 as default */
		minor = 0;
	}
	ASSERT(minor < 16); /* at most 16 partitions */
	mi += minor;
	*pnp++ = ':';
	*pnp++ = mi;
	*pnp++ = '\0';
	bsetprops("fstype", "ufs");
	bsetprops("bootpath", vbdpath);

	DBG_MSG("VBD bootpath set to ");
	DBG_MSG(vbdpath);
	DBG_MSG("\n");
}

/*
 * parse the xpv-nfsroot property to create properties used by
 * nfs_mountroot.
 */
static void
xen_nfsroot_props(char *s)
{
	char *prop_map[] = {
		BP_SERVER_IP,	/* server IP address */
		BP_SERVER_NAME,	/* server hostname */
		BP_SERVER_PATH,	/* root path */
	};
	int n_prop = sizeof (prop_map) / sizeof (prop_map[0]);

	bsetprop("fstype", 6, "nfs", 4);

	xen_parse_props(s, prop_map, n_prop);

	/*
	 * If a server name wasn't specified, use a default.
	 */
	if (do_bsys_getproplen(NULL, BP_SERVER_NAME) == -1)
		bsetprops(BP_SERVER_NAME, "unknown");
}

/*
 * Extract our IP address, etc. from the "xpv-ip" property.
 */
static void
xen_ip_props(char *s)
{
	char *prop_map[] = {
		BP_HOST_IP,		/* IP address */
		NULL,			/* NFS server IP address (ignored in */
					/* favour of xpv-nfsroot) */
		BP_ROUTER_IP,		/* IP gateway */
		BP_SUBNET_MASK,		/* IP subnet mask */
		"xpv-hostname",		/* hostname (ignored) */
		BP_NETWORK_INTERFACE,	/* interface name */
		"xpv-hcp",		/* host configuration protocol */
	};
	int n_prop = sizeof (prop_map) / sizeof (prop_map[0]);
	char ifname[IFNAMSIZ];

	xen_parse_props(s, prop_map, n_prop);

	/*
	 * A Linux dom0 administrator expects all interfaces to be
	 * called "ethX", which is not the case here.
	 *
	 * If the interface name specified is "eth0", presume that
	 * this is really intended to be "xnf0" (the first domU ->
	 * dom0 interface for this domain).
	 */
	if ((do_bsys_getprop(NULL, BP_NETWORK_INTERFACE, ifname) == 0) &&
	    (strcmp("eth0", ifname) == 0)) {
		bsetprops(BP_NETWORK_INTERFACE, "xnf0");
		bop_printf(NULL,
		    "network interface name 'eth0' replaced with 'xnf0'\n");
	}
}

#else	/* __xpv */

static void
setup_rarp_props(struct sol_netinfo *sip)
{
	char buf[BUFLEN];	/* to hold ip/mac addrs */
	uint8_t *val;

	val = (uint8_t *)&sip->sn_ciaddr;
	(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
	    val[0], val[1], val[2], val[3]);
	bsetprops(BP_HOST_IP, buf);

	val = (uint8_t *)&sip->sn_siaddr;
	(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
	    val[0], val[1], val[2], val[3]);
	bsetprops(BP_SERVER_IP, buf);

	if (sip->sn_giaddr != 0) {
		val = (uint8_t *)&sip->sn_giaddr;
		(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
		    val[0], val[1], val[2], val[3]);
		bsetprops(BP_ROUTER_IP, buf);
	}

	if (sip->sn_netmask != 0) {
		val = (uint8_t *)&sip->sn_netmask;
		(void) snprintf(buf, BUFLEN, "%d.%d.%d.%d",
		    val[0], val[1], val[2], val[3]);
		bsetprops(BP_SUBNET_MASK, buf);
	}

	if (sip->sn_mactype != 4 || sip->sn_maclen != 6) {
		bop_printf(NULL, "unsupported mac type %d, mac len %d\n",
		    sip->sn_mactype, sip->sn_maclen);
	} else {
		val = sip->sn_macaddr;
		(void) snprintf(buf, BUFLEN, "%x:%x:%x:%x:%x:%x",
		    val[0], val[1], val[2], val[3], val[4], val[5]);
		bsetprops(BP_BOOT_MAC, buf);
	}
}

#endif	/* __xpv */

static void
build_panic_cmdline(const char *cmd, int cmdlen)
{
	int proplen;
	size_t arglen;

	arglen = sizeof (fastreboot_onpanic_args);
	/*
	 * If we allready have fastreboot-onpanic set to zero,
	 * don't add them again.
	 */
	if ((proplen = do_bsys_getproplen(NULL, FASTREBOOT_ONPANIC)) > 0 &&
	    proplen <=  sizeof (fastreboot_onpanic_cmdline)) {
		(void) do_bsys_getprop(NULL, FASTREBOOT_ONPANIC,
		    fastreboot_onpanic_cmdline);
		if (FASTREBOOT_ONPANIC_NOTSET(fastreboot_onpanic_cmdline))
			arglen = 1;
	}

	/*
	 * construct fastreboot_onpanic_cmdline
	 */
	if (cmdlen + arglen > sizeof (fastreboot_onpanic_cmdline)) {
		DBG_MSG("Command line too long: clearing "
		    FASTREBOOT_ONPANIC "\n");
		fastreboot_onpanic = 0;
	} else {
		bcopy(cmd, fastreboot_onpanic_cmdline, cmdlen);
		if (arglen != 1)
			bcopy(fastreboot_onpanic_args,
			    fastreboot_onpanic_cmdline + cmdlen, arglen);
		else
			fastreboot_onpanic_cmdline[cmdlen] = 0;
	}
}


#ifndef	__xpv
/*
 * Construct boot command line for Fast Reboot
 */
static void
build_fastboot_cmdline(void)
{
	saved_cmdline_len =  strlen(xbootp->bi_cmdline) + 1;
	if (saved_cmdline_len > FASTBOOT_SAVED_CMDLINE_LEN) {
		DBG(saved_cmdline_len);
		DBG_MSG("Command line too long: clearing fastreboot_capable\n");
		fastreboot_capable = 0;
	} else {
		bcopy((void *)(xbootp->bi_cmdline), (void *)saved_cmdline,
		    saved_cmdline_len);
		saved_cmdline[saved_cmdline_len - 1] = '\0';
		build_panic_cmdline(saved_cmdline, saved_cmdline_len - 1);
	}
}

/*
 * Save memory layout, disk drive information, unix and boot archive sizes for
 * Fast Reboot.
 */
static void
save_boot_info(multiboot_info_t *mbi, struct xboot_info *xbi)
{
	struct boot_modules *modp;
	int i;

	bcopy(mbi, &saved_mbi, sizeof (multiboot_info_t));
	if (mbi->mmap_length > sizeof (saved_mmap)) {
		DBG_MSG("mbi->mmap_length too big: clearing "
		    "fastreboot_capable\n");
		fastreboot_capable = 0;
	} else {
		bcopy((void *)(uintptr_t)mbi->mmap_addr, (void *)saved_mmap,
		    mbi->mmap_length);
	}

	if ((mbi->flags & MB_INFO_DRIVE_INFO) != 0) {
		if (mbi->drives_length > sizeof (saved_drives)) {
			DBG(mbi->drives_length);
			DBG_MSG("mbi->drives_length too big: clearing "
			    "fastreboot_capable\n");
			fastreboot_capable = 0;
		} else {
			bcopy((void *)(uintptr_t)mbi->drives_addr,
			    (void *)saved_drives, mbi->drives_length);
		}
	} else {
		saved_mbi.drives_length = 0;
		saved_mbi.drives_addr = NULL;
	}

	/*
	 * Current file sizes.  Used by fastboot.c to figure out how much
	 * memory to reserve for panic reboot.
	 * Use the module list from the dboot-constructed xboot_info
	 * instead of the list referenced by the multiboot structure
	 * because that structure may not be addressable now.
	 */
	saved_file_size[FASTBOOT_NAME_UNIX] = FOUR_MEG - PAGESIZE;
	for (i = 0, modp = (struct boot_modules *)(uintptr_t)xbi->bi_modules;
	    i < xbi->bi_module_cnt; i++, modp++) {
		saved_file_size[FASTBOOT_NAME_BOOTARCHIVE] += modp->bm_size;
	}
}
#endif	/* __xpv */


/*
 * 1st pass at building the table of boot properties. This includes:
 * - values set on the command line: -B a=x,b=y,c=z ....
 * - known values we just compute (ie. from xbootp)
 * - values from /boot/solaris/bootenv.rc (ie. eeprom(1m) values)
 *
 * the grub command line looked like:
 * kernel boot-file [-B prop=value[,prop=value]...] [boot-args]
 *
 * whoami is the same as boot-file
 */
static void
build_boot_properties(void)
{
	char *name;
	int name_len;
	char *value;
	int value_len;
	struct boot_modules *bm, *rdbm;
	char *propbuf;
	int quoted = 0;
	int boot_arg_len;
	uint_t i, midx;
	char modid[32];
#ifndef __xpv
	static int stdout_val = 0;
	uchar_t boot_device;
	char str[3];
	multiboot_info_t *mbi;
	int netboot;
	struct sol_netinfo *sip;
#endif

	/*
	 * These have to be done first, so that kobj_mount_root() works
	 */
	DBG_MSG("Building boot properties\n");
	propbuf = do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, 0);
	DBG((uintptr_t)propbuf);
	if (xbootp->bi_module_cnt > 0) {
		bm = xbootp->bi_modules;
		rdbm = NULL;
		for (midx = i = 0; i < xbootp->bi_module_cnt; i++) {
			if (bm[i].bm_type == BMT_ROOTFS) {
				rdbm = &bm[i];
				continue;
			}
			if (bm[i].bm_type == BMT_HASH || bm[i].bm_name == NULL)
				continue;

			(void) snprintf(modid, sizeof (modid),
			    "module-name-%u", midx);
			bsetprops(modid, (char *)bm[i].bm_name);
			(void) snprintf(modid, sizeof (modid),
			    "module-addr-%u", midx);
			bsetprop64(modid, (uint64_t)(uintptr_t)bm[i].bm_addr);
			(void) snprintf(modid, sizeof (modid),
			    "module-size-%u", midx);
			bsetprop64(modid, (uint64_t)bm[i].bm_size);
			++midx;
		}
		if (rdbm != NULL) {
			bsetprop64("ramdisk_start",
			    (uint64_t)(uintptr_t)rdbm->bm_addr);
			bsetprop64("ramdisk_end",
			    (uint64_t)(uintptr_t)rdbm->bm_addr + rdbm->bm_size);
		}
	}

	/*
	 * If there are any boot time modules or hashes present, then disable
	 * fast reboot.
	 */
	if (xbootp->bi_module_cnt > 1) {
		fastreboot_disable(FBNS_BOOTMOD);
	}

	DBG_MSG("Parsing command line for boot properties\n");
	value = xbootp->bi_cmdline;

	/*
	 * allocate memory to collect boot_args into
	 */
	boot_arg_len = strlen(xbootp->bi_cmdline) + 1;
	boot_args = do_bsys_alloc(NULL, NULL, boot_arg_len, MMU_PAGESIZE);
	boot_args[0] = 0;
	boot_arg_len = 0;

#ifdef __xpv
	/*
	 * Xen puts a lot of device information in front of the kernel name
	 * let's grab them and make them boot properties.  The first
	 * string w/o an "=" in it will be the boot-file property.
	 */
	(void) strcpy(namebuf, "xpv-");
	for (;;) {
		/*
		 * get to next property
		 */
		while (ISSPACE(*value))
			++value;
		name = value;
		/*
		 * look for an "="
		 */
		while (*value && !ISSPACE(*value) && *value != '=') {
			value++;
		}
		if (*value != '=') { /* no "=" in the property */
			value = name;
			break;
		}
		name_len = value - name;
		value_len = 0;
		/*
		 * skip over the "="
		 */
		value++;
		while (value[value_len] && !ISSPACE(value[value_len])) {
			++value_len;
		}
		/*
		 * build property name with "xpv-" prefix
		 */
		if (name_len + 4 > 32) { /* skip if name too long */
			value += value_len;
			continue;
		}
		bcopy(name, &namebuf[4], name_len);
		name_len += 4;
		namebuf[name_len] = 0;
		bcopy(value, propbuf, value_len);
		propbuf[value_len] = 0;
		bsetprops(namebuf, propbuf);

		/*
		 * xpv-root is set to the logical disk name of the xen
		 * VBD when booting from a disk-based filesystem.
		 */
		if (strcmp(namebuf, "xpv-root") == 0)
			xen_vbdroot_props(propbuf);
		/*
		 * While we're here, if we have a "xpv-nfsroot" property
		 * then we need to set "fstype" to "nfs" so we mount
		 * our root from the nfs server.  Also parse the xpv-nfsroot
		 * property to create the properties that nfs_mountroot will
		 * need to find the root and mount it.
		 */
		if (strcmp(namebuf, "xpv-nfsroot") == 0)
			xen_nfsroot_props(propbuf);

		if (strcmp(namebuf, "xpv-ip") == 0)
			xen_ip_props(propbuf);
		value += value_len;
	}
#endif

	while (ISSPACE(*value))
		++value;
	/*
	 * value now points at the boot-file
	 */
	value_len = 0;
	while (value[value_len] && !ISSPACE(value[value_len]))
		++value_len;
	if (value_len > 0) {
		whoami = propbuf;
		bcopy(value, whoami, value_len);
		whoami[value_len] = 0;
		bsetprops("boot-file", whoami);
		/*
		 * strip leading path stuff from whoami, so running from
		 * PXE/miniroot makes sense.
		 */
		if (strstr(whoami, "/platform/") != NULL)
			whoami = strstr(whoami, "/platform/");
		bsetprops("whoami", whoami);
	}

	/*
	 * Values forcibly set boot properties on the command line via -B.
	 * Allow use of quotes in values. Other stuff goes on kernel
	 * command line.
	 */
	name = value + value_len;
	while (*name != 0) {
		/*
		 * anything not " -B" is copied to the command line
		 */
		if (!ISSPACE(name[0]) || name[1] != '-' || name[2] != 'B') {
			boot_args[boot_arg_len++] = *name;
			boot_args[boot_arg_len] = 0;
			++name;
			continue;
		}

		/*
		 * skip the " -B" and following white space
		 */
		name += 3;
		while (ISSPACE(*name))
			++name;
		while (*name && !ISSPACE(*name)) {
			value = strstr(name, "=");
			if (value == NULL)
				break;
			name_len = value - name;
			++value;
			value_len = 0;
			quoted = 0;
			for (; ; ++value_len) {
				if (!value[value_len])
					break;

				/*
				 * is this value quoted?
				 */
				if (value_len == 0 &&
				    (value[0] == '\'' || value[0] == '"')) {
					quoted = value[0];
					++value_len;
				}

				/*
				 * In the quote accept any character,
				 * but look for ending quote.
				 */
				if (quoted) {
					if (value[value_len] == quoted)
						quoted = 0;
					continue;
				}

				/*
				 * a comma or white space ends the value
				 */
				if (value[value_len] == ',' ||
				    ISSPACE(value[value_len]))
					break;
			}

			if (value_len == 0) {
				bsetprop(name, name_len, "true", 5);
			} else {
				char *v = value;
				int l = value_len;
				if (v[0] == v[l - 1] &&
				    (v[0] == '\'' || v[0] == '"')) {
					++v;
					l -= 2;
				}
				bcopy(v, propbuf, l);
				propbuf[l] = '\0';
				bsetprop(name, name_len, propbuf,
				    l + 1);
			}
			name = value + value_len;
			while (*name == ',')
				++name;
		}
	}

	/*
	 * set boot-args property
	 * 1275 name is bootargs, so set
	 * that too
	 */
	bsetprops("boot-args", boot_args);
	bsetprops("bootargs", boot_args);

#ifndef __xpv
	/*
	 * set the BIOS boot device from GRUB
	 */
	netboot = 0;
	mbi = xbootp->bi_mb_info;

	/*
	 * Build boot command line for Fast Reboot
	 */
	build_fastboot_cmdline();

	/*
	 * Save various boot information for Fast Reboot
	 */
	save_boot_info(mbi, xbootp);

	if (mbi != NULL && mbi->flags & MB_INFO_BOOTDEV) {
		boot_device = mbi->boot_device >> 24;
		if (boot_device == 0x20)
			netboot++;
		str[0] = (boot_device >> 4) + '0';
		str[1] = (boot_device & 0xf) + '0';
		str[2] = 0;
		bsetprops("bios-boot-device", str);
	} else {
		netboot = 1;
	}

	/*
	 * In the netboot case, drives_info is overloaded with the dhcp ack.
	 * This is not multiboot compliant and requires special pxegrub!
	 */
	if (netboot && mbi->drives_length != 0) {
		sip = (struct sol_netinfo *)(uintptr_t)mbi->drives_addr;
		if (sip->sn_infotype == SN_TYPE_BOOTP)
			bsetprop("bootp-response", sizeof ("bootp-response"),
			    (void *)(uintptr_t)mbi->drives_addr,
			    mbi->drives_length);
		else if (sip->sn_infotype == SN_TYPE_RARP)
			setup_rarp_props(sip);
	}
	bsetprop("stdout", strlen("stdout"),
	    &stdout_val, sizeof (stdout_val));
#endif /* __xpv */

	/*
	 * more conjured up values for made up things....
	 */
#if defined(__xpv)
	bsetprops("mfg-name", "i86xpv");
	bsetprops("impl-arch-name", "i86xpv");
#else
	bsetprops("mfg-name", "i86pc");
	bsetprops("impl-arch-name", "i86pc");
#endif

	/*
	 * Build firmware-provided system properties
	 */
	build_firmware_properties();

	/*
	 * XXPV
	 *
	 * Find out what these are:
	 * - cpuid_feature_ecx_include
	 * - cpuid_feature_ecx_exclude
	 * - cpuid_feature_edx_include
	 * - cpuid_feature_edx_exclude
	 *
	 * Find out what these are in multiboot:
	 * - netdev-path
	 * - fstype
	 */
}

#ifdef __xpv
/*
 * Under the Hypervisor, memory usable for DMA may be scarce. One
 * very likely large pool of DMA friendly memory is occupied by
 * the boot_archive, as it was loaded by grub into low MFNs.
 *
 * Here we free up that memory by copying the boot archive to what are
 * likely higher MFN pages and then swapping the mfn/pfn mappings.
 */
#define	PFN_2GIG	0x80000
static void
relocate_boot_archive(void)
{
	mfn_t max_mfn = HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL);
	struct boot_modules *bm = xbootp->bi_modules;
	uintptr_t va;
	pfn_t va_pfn;
	mfn_t va_mfn;
	caddr_t copy;
	pfn_t copy_pfn;
	mfn_t copy_mfn;
	size_t	len;
	int slop;
	int total = 0;
	int relocated = 0;
	int mmu_update_return;
	mmu_update_t t[2];
	x86pte_t pte;

	/*
	 * If all MFN's are below 2Gig, don't bother doing this.
	 */
	if (max_mfn < PFN_2GIG)
		return;
	if (xbootp->bi_module_cnt < 1) {
		DBG_MSG("no boot_archive!");
		return;
	}

	DBG_MSG("moving boot_archive to high MFN memory\n");
	va = (uintptr_t)bm->bm_addr;
	len = bm->bm_size;
	slop = va & MMU_PAGEOFFSET;
	if (slop) {
		va += MMU_PAGESIZE - slop;
		len -= MMU_PAGESIZE - slop;
	}
	len = P2ALIGN(len, MMU_PAGESIZE);

	/*
	 * Go through all boot_archive pages, swapping any low MFN pages
	 * with memory at next_phys.
	 */
	while (len != 0) {
		++total;
		va_pfn = mmu_btop(va - ONE_GIG);
		va_mfn = mfn_list[va_pfn];
		if (mfn_list[va_pfn] < PFN_2GIG) {
			copy = kbm_remap_window(next_phys, 1);
			bcopy((void *)va, copy, MMU_PAGESIZE);
			copy_pfn = mmu_btop(next_phys);
			copy_mfn = mfn_list[copy_pfn];

			pte = mfn_to_ma(copy_mfn) | PT_NOCONSIST | PT_VALID;
			if (HYPERVISOR_update_va_mapping(va, pte,
			    UVMF_INVLPG | UVMF_LOCAL))
				bop_panic("relocate_boot_archive():  "
				    "HYPERVISOR_update_va_mapping() failed");

			mfn_list[va_pfn] = copy_mfn;
			mfn_list[copy_pfn] = va_mfn;

			t[0].ptr = mfn_to_ma(copy_mfn) | MMU_MACHPHYS_UPDATE;
			t[0].val = va_pfn;
			t[1].ptr = mfn_to_ma(va_mfn) | MMU_MACHPHYS_UPDATE;
			t[1].val = copy_pfn;
			if (HYPERVISOR_mmu_update(t, 2, &mmu_update_return,
			    DOMID_SELF) != 0 || mmu_update_return != 2)
				bop_panic("relocate_boot_archive():  "
				    "HYPERVISOR_mmu_update() failed");

			next_phys += MMU_PAGESIZE;
			++relocated;
		}
		len -= MMU_PAGESIZE;
		va += MMU_PAGESIZE;
	}
	DBG_MSG("Relocated pages:\n");
	DBG(relocated);
	DBG_MSG("Out of total pages:\n");
	DBG(total);
}
#endif /* __xpv */

#if !defined(__xpv)
/*
 * Install a temporary IDT that lets us catch errors in the boot time code.
 * We shouldn't get any faults at all while this is installed, so we'll
 * just generate a traceback and exit.
 */
#ifdef __amd64
static const int bcode_sel = B64CODE_SEL;
#else
static const int bcode_sel = B32CODE_SEL;
#endif

/*
 * simple description of a stack frame (args are 32 bit only currently)
 */
typedef struct bop_frame {
	struct bop_frame *old_frame;
	pc_t retaddr;
	long arg[1];
} bop_frame_t;

void
bop_traceback(bop_frame_t *frame)
{
	pc_t pc;
	int cnt;
	char *ksym;
	ulong_t off;
#if defined(__i386)
	int a;
#endif

	bop_printf(NULL, "Stack traceback:\n");
	for (cnt = 0; cnt < 30; ++cnt) {	/* up to 30 frames */
		pc = frame->retaddr;
		if (pc == 0)
			break;
		ksym = kobj_getsymname(pc, &off);
		if (ksym)
			bop_printf(NULL, "  %s+%lx", ksym, off);
		else
			bop_printf(NULL, "  0x%lx", pc);

		frame = frame->old_frame;
		if (frame == 0) {
			bop_printf(NULL, "\n");
			break;
		}
#if defined(__i386)
		for (a = 0; a < 6; ++a) {	/* try for 6 args */
			if ((void *)&frame->arg[a] == (void *)frame->old_frame)
				break;
			if (a == 0)
				bop_printf(NULL, "(");
			else
				bop_printf(NULL, ",");
			bop_printf(NULL, "0x%lx", frame->arg[a]);
		}
		bop_printf(NULL, ")");
#endif
		bop_printf(NULL, "\n");
	}
}

struct trapframe {
	ulong_t error_code;	/* optional */
	ulong_t inst_ptr;
	ulong_t code_seg;
	ulong_t flags_reg;
#ifdef __amd64
	ulong_t stk_ptr;
	ulong_t stk_seg;
#endif
};

void
bop_trap(ulong_t *tfp)
{
	struct trapframe *tf = (struct trapframe *)tfp;
	bop_frame_t fakeframe;
	static int depth = 0;

	/*
	 * Check for an infinite loop of traps.
	 */
	if (++depth > 2)
		bop_panic("Nested trap");

	bop_printf(NULL, "Unexpected trap\n");

	/*
	 * adjust the tf for optional error_code by detecting the code selector
	 */
	if (tf->code_seg != bcode_sel)
		tf = (struct trapframe *)(tfp - 1);
	else
		bop_printf(NULL, "error code           0x%lx\n",
		    tf->error_code & 0xffffffff);

	bop_printf(NULL, "instruction pointer  0x%lx\n", tf->inst_ptr);
	bop_printf(NULL, "code segment         0x%lx\n", tf->code_seg & 0xffff);
	bop_printf(NULL, "flags register       0x%lx\n", tf->flags_reg);
#ifdef __amd64
	bop_printf(NULL, "return %%rsp          0x%lx\n", tf->stk_ptr);
	bop_printf(NULL, "return %%ss           0x%lx\n", tf->stk_seg & 0xffff);
#endif

	/* grab %[er]bp pushed by our code from the stack */
	fakeframe.old_frame = (bop_frame_t *)*(tfp - 3);
	fakeframe.retaddr = (pc_t)tf->inst_ptr;
	bop_printf(NULL, "Attempting stack backtrace:\n");
	bop_traceback(&fakeframe);
	bop_panic("unexpected trap in early boot");
}

extern void bop_trap_handler(void);

static gate_desc_t *bop_idt;

static desctbr_t bop_idt_info;

static void
bop_idt_init(void)
{
	int t;

	bop_idt = (gate_desc_t *)
	    do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, MMU_PAGESIZE);
	bzero(bop_idt, MMU_PAGESIZE);
	for (t = 0; t < NIDT; ++t) {
		/*
		 * Note that since boot runs without a TSS, the
		 * double fault handler cannot use an alternate stack
		 * (64-bit) or a task gate (32-bit).
		 */
		set_gatesegd(&bop_idt[t], &bop_trap_handler, bcode_sel,
		    SDT_SYSIGT, TRP_KPL, 0);
	}
	bop_idt_info.dtr_limit = (NIDT * sizeof (gate_desc_t)) - 1;
	bop_idt_info.dtr_base = (uintptr_t)bop_idt;
	wr_idtr(&bop_idt_info);
}
#endif	/* !defined(__xpv) */

/*
 * This is where we enter the kernel. It dummies up the boot_ops and
 * boot_syscalls vectors and jumps off to _kobj_boot()
 */
void
_start(struct xboot_info *xbp)
{
	bootops_t *bops = &bootop;
	extern void _kobj_boot();

	/*
	 * 1st off - initialize the console for any error messages
	 */
	xbootp = xbp;
#ifdef __xpv
	HYPERVISOR_shared_info = (void *)xbootp->bi_shared_info;
	xen_info = xbootp->bi_xen_start_info;
#endif

#ifndef __xpv
	if (*((uint32_t *)(FASTBOOT_SWTCH_PA + FASTBOOT_STACK_OFFSET)) ==
	    FASTBOOT_MAGIC) {
		post_fastreboot = 1;
		*((uint32_t *)(FASTBOOT_SWTCH_PA + FASTBOOT_STACK_OFFSET)) = 0;
	}
#endif

	bcons_init((void *)xbootp->bi_cmdline);
	have_console = 1;

	/*
	 * enable debugging
	 */
	if (strstr((char *)xbootp->bi_cmdline, "kbm_debug"))
		kbm_debug = 1;

	DBG_MSG("\n\n*** Entered Solaris in _start() cmdline is: ");
	DBG_MSG((char *)xbootp->bi_cmdline);
	DBG_MSG("\n\n\n");

	/*
	 * physavail is no longer used by startup
	 */
	bm.physinstalled = xbp->bi_phys_install;
	bm.pcimem = xbp->bi_pcimem;
	bm.rsvdmem = xbp->bi_rsvdmem;
	bm.physavail = NULL;

	/*
	 * initialize the boot time allocator
	 */
	next_phys = xbootp->bi_next_paddr;
	DBG(next_phys);
	next_virt = (uintptr_t)xbootp->bi_next_vaddr;
	DBG(next_virt);
	DBG_MSG("Initializing boot time memory management...");
#ifdef __xpv
	{
		xen_platform_parameters_t p;

		/* This call shouldn't fail, dboot already did it once. */
		(void) HYPERVISOR_xen_version(XENVER_platform_parameters, &p);
		mfn_to_pfn_mapping = (pfn_t *)(xen_virt_start = p.virt_start);
		DBG(xen_virt_start);
	}
#endif
	kbm_init(xbootp);
	DBG_MSG("done\n");

	/*
	 * Fill in the bootops vector
	 */
	bops->bsys_version = BO_VERSION;
	bops->boot_mem = &bm;
	bops->bsys_alloc = do_bsys_alloc;
	bops->bsys_free = do_bsys_free;
	bops->bsys_getproplen = do_bsys_getproplen;
	bops->bsys_getprop = do_bsys_getprop;
	bops->bsys_nextprop = do_bsys_nextprop;
	bops->bsys_printf = bop_printf;
	bops->bsys_doint = do_bsys_doint;

	/*
	 * BOP_EALLOC() is no longer needed
	 */
	bops->bsys_ealloc = do_bsys_ealloc;

#ifdef __xpv
	/*
	 * On domain 0 we need to free up some physical memory that is
	 * usable for DMA. Since GRUB loaded the boot_archive, it is
	 * sitting in low MFN memory. We'll relocated the boot archive
	 * pages to high PFN memory.
	 */
	if (DOMAIN_IS_INITDOMAIN(xen_info))
		relocate_boot_archive();
#endif

#ifndef __xpv
	/*
	 * Install an IDT to catch early pagefaults (shouldn't have any).
	 * Also needed for kmdb.
	 */
	bop_idt_init();
#endif

	/*
	 * Start building the boot properties from the command line
	 */
	DBG_MSG("Initializing boot properties:\n");
	build_boot_properties();

	if (strstr((char *)xbootp->bi_cmdline, "prom_debug") || kbm_debug) {
		char *name;
		char *value;
		char *cp;
		int len;

		value = do_bsys_alloc(NULL, NULL, MMU_PAGESIZE, MMU_PAGESIZE);
		bop_printf(NULL, "\nBoot properties:\n");
		name = "";
		while ((name = do_bsys_nextprop(NULL, name)) != NULL) {
			bop_printf(NULL, "\t0x%p %s = ", (void *)name, name);
			(void) do_bsys_getprop(NULL, name, value);
			len = do_bsys_getproplen(NULL, name);
			bop_printf(NULL, "len=%d ", len);
			value[len] = 0;
			for (cp = value; *cp; ++cp) {
				if (' ' <= *cp && *cp <= '~')
					bop_printf(NULL, "%c", *cp);
				else
					bop_printf(NULL, "-0x%x-", *cp);
			}
			bop_printf(NULL, "\n");
		}
	}

	/*
	 * jump into krtld...
	 */
	_kobj_boot(&bop_sysp, NULL, bops, NULL);
}


/*ARGSUSED*/
static caddr_t
no_more_alloc(bootops_t *bop, caddr_t virthint, size_t size, int align)
{
	panic("Attempt to bsys_alloc() too late\n");
	return (NULL);
}

/*ARGSUSED*/
static void
no_more_free(bootops_t *bop, caddr_t virt, size_t size)
{
	panic("Attempt to bsys_free() too late\n");
}

void
bop_no_more_mem(void)
{
	DBG(total_bop_alloc_scratch);
	DBG(total_bop_alloc_kernel);
	bootops->bsys_alloc = no_more_alloc;
	bootops->bsys_free = no_more_free;
}


/*
 * Set ACPI firmware properties
 */

static caddr_t
vmap_phys(size_t length, paddr_t pa)
{
	paddr_t	start, end;
	caddr_t	va;
	size_t	len, page;

#ifdef __xpv
	pa = pfn_to_pa(xen_assign_pfn(mmu_btop(pa))) | (pa & MMU_PAGEOFFSET);
#endif
	start = P2ALIGN(pa, MMU_PAGESIZE);
	end = P2ROUNDUP(pa + length, MMU_PAGESIZE);
	len = end - start;
	va = (caddr_t)alloc_vaddr(len, MMU_PAGESIZE);
	for (page = 0; page < len; page += MMU_PAGESIZE)
		kbm_map((uintptr_t)va + page, start + page, 0, 0);
	return (va + (pa & MMU_PAGEOFFSET));
}

static uint8_t
checksum_table(uint8_t *tp, size_t len)
{
	uint8_t sum = 0;

	while (len-- > 0)
		sum += *tp++;

	return (sum);
}

static int
valid_rsdp(struct rsdp *rp)
{

	/* validate the V1.x checksum */
	if (checksum_table((uint8_t *)&rp->v1, sizeof (struct rsdp_v1)) != 0)
		return (0);

	/* If pre-ACPI 2.0, this is a valid RSDP */
	if (rp->v1.revision < 2)
		return (1);

	/* validate the V2.x checksum */
	if (checksum_table((uint8_t *)rp, sizeof (struct rsdp)) != 0)
		return (0);

	return (1);
}

/*
 * Scan memory range for an RSDP;
 * see ACPI 3.0 Spec, 5.2.5.1
 */
static struct rsdp *
scan_rsdp(paddr_t start, paddr_t end)
{
	size_t len  = end - start + 1;
	caddr_t ptr;

	ptr = vmap_phys(len, start);
	while (len > 0) {
		if (strncmp(ptr, ACPI_RSDP_SIG, ACPI_RSDP_SIG_LEN) == 0)
			if (valid_rsdp((struct rsdp *)ptr))
				return ((struct rsdp *)ptr);
		ptr += 16;
		len -= 16;
	}

	return (NULL);
}

/*
 * Refer to ACPI 3.0 Spec, section 5.2.5.1 to understand this function
 */
static struct rsdp *
find_rsdp()
{
	struct rsdp *rsdp;
	uint16_t *ebda_seg;
	paddr_t  ebda_addr;

	/*
	 * Get the EBDA segment and scan the first 1K
	 */
	ebda_seg = (uint16_t *)vmap_phys(sizeof (uint16_t), ACPI_EBDA_SEG_ADDR);
	ebda_addr = *ebda_seg << 4;
	rsdp = scan_rsdp(ebda_addr, ebda_addr + ACPI_EBDA_LEN - 1);
	if (rsdp == NULL)
		/* if EBDA doesn't contain RSDP, look in BIOS memory */
		rsdp = scan_rsdp(0xe0000, 0xfffff);
	return (rsdp);
}

static struct table_header *
map_fw_table(paddr_t table_addr)
{
	struct table_header *tp;
	size_t len = MAX(sizeof (struct table_header), MMU_PAGESIZE);

	/*
	 * Map at least a page; if the table is larger than this, remap it
	 */
	tp = (struct table_header *)vmap_phys(len, table_addr);
	if (tp->len > len)
		tp = (struct table_header *)vmap_phys(tp->len, table_addr);
	return (tp);
}

static struct table_header *
find_fw_table(char *signature)
{
	static int revision = 0;
	static struct xsdt *xsdt;
	static int len;
	paddr_t xsdt_addr;
	struct rsdp *rsdp;
	struct table_header *tp;
	paddr_t table_addr;
	int	n;

	if (strlen(signature) != ACPI_TABLE_SIG_LEN)
		return (NULL);

	/*
	 * Reading the ACPI 3.0 Spec, section 5.2.5.3 will help
	 * understand this code.  If we haven't already found the RSDT/XSDT,
	 * revision will be 0. Find the RSDP and check the revision
	 * to find out whether to use the RSDT or XSDT.  If revision is
	 * 0 or 1, use the RSDT and set internal revision to 1; if it is 2,
	 * use the XSDT.  If the XSDT address is 0, though, fall back to
	 * revision 1 and use the RSDT.
	 */
	if (revision == 0) {
		if ((rsdp = (struct rsdp *)find_rsdp()) != NULL) {
			revision = rsdp->v1.revision;
			switch (revision) {
			case 2:
				/*
				 * Use the XSDT unless BIOS is buggy and
				 * claims to be rev 2 but has a null XSDT
				 * address
				 */
				xsdt_addr = rsdp->xsdt;
				if (xsdt_addr != 0)
					break;
				/* FALLTHROUGH */
			case 0:
				/* treat RSDP rev 0 as revision 1 internally */
				revision = 1;
				/* FALLTHROUGH */
			case 1:
				/* use the RSDT for rev 0/1 */
				xsdt_addr = rsdp->v1.rsdt;
				break;
			default:
				/* unknown revision */
				revision = 0;
				break;
			}
		}
		if (revision == 0)
			return (NULL);

		/* cache the XSDT info */
		xsdt = (struct xsdt *)map_fw_table(xsdt_addr);
		len = (xsdt->hdr.len - sizeof (xsdt->hdr)) /
		    ((revision == 1) ? sizeof (uint32_t) : sizeof (uint64_t));
	}

	/*
	 * Scan the table headers looking for a signature match
	 */
	for (n = 0; n < len; n++) {
		table_addr = (revision == 1) ? xsdt->p.r[n] : xsdt->p.x[n];
		if (table_addr == 0)
			continue;
		tp = map_fw_table(table_addr);
		if (strncmp(tp->sig, signature, ACPI_TABLE_SIG_LEN) == 0) {
			return (tp);
		}
	}
	return (NULL);
}

static void
process_mcfg(struct mcfg *tp)
{
	struct cfg_base_addr_alloc *cfg_baap;
	char *cfg_baa_endp;
	int64_t ecfginfo[4];

	cfg_baap = tp->CfgBaseAddrAllocList;
	cfg_baa_endp = ((char *)tp) + tp->Length;
	while ((char *)cfg_baap < cfg_baa_endp) {
		if (cfg_baap->base_addr != 0 && cfg_baap->segment == 0) {
			ecfginfo[0] = cfg_baap->base_addr;
			ecfginfo[1] = cfg_baap->segment;
			ecfginfo[2] = cfg_baap->start_bno;
			ecfginfo[3] = cfg_baap->end_bno;
			bsetprop(MCFG_PROPNAME, strlen(MCFG_PROPNAME),
			    ecfginfo, sizeof (ecfginfo));
			break;
		}
		cfg_baap++;
	}
}

#ifndef __xpv
static void
process_madt(struct madt *tp)
{
	struct madt_processor *cpu, *end;
	uint32_t cpu_count = 0;
	uint32_t cpu_possible_count = 0;
	uint8_t cpu_apicid_array[UINT8_MAX + 1];

	if (tp != NULL) {
		/*
		 * Determine number of CPUs and keep track of "final" APIC ID
		 * for each CPU by walking through ACPI MADT processor list
		 */
		end = (struct madt_processor *)(tp->hdr.len + (uintptr_t)tp);
		cpu = tp->list;
		while (cpu < end) {
			if (cpu->type == MADT_PROCESSOR) {
				if (cpu->flags & 1) {
					if (cpu_count < UINT8_MAX)
						cpu_apicid_array[cpu_count] =
						    cpu->apic_id;
					cpu_count++;
				}
				cpu_possible_count++;
			}

			cpu = (struct madt_processor *)
			    (cpu->len + (uintptr_t)cpu);
		}

		/*
		 * Make boot property for array of "final" APIC IDs for each
		 * CPU
		 */
		bsetprop(BP_CPU_APICID_ARRAY, strlen(BP_CPU_APICID_ARRAY),
		    cpu_apicid_array, cpu_count * sizeof (uint8_t));
	}

	/*
	 * Check whehter property plat-max-ncpus is already set.
	 */
	if (do_bsys_getproplen(NULL, PLAT_MAX_NCPUS_NAME) < 0) {
		/*
		 * Set plat-max-ncpus to number of maximum possible CPUs given
		 * in MADT if it hasn't been set.
		 * There's no formal way to detect max possible CPUs supported
		 * by platform according to ACPI spec3.0b. So current CPU
		 * hotplug implementation expects that all possible CPUs will
		 * have an entry in MADT table and set plat-max-ncpus to number
		 * of entries in MADT.
		 * With introducing of ACPI4.0, Maximum System Capability Table
		 * (MSCT) provides maximum number of CPUs supported by platform.
		 * If MSCT is unavailable, fall back to old way.
		 */
		if (tp != NULL)
			bsetpropsi(PLAT_MAX_NCPUS_NAME, cpu_possible_count);
	}

	/*
	 * Set boot property boot-max-ncpus to number of CPUs existing at
	 * boot time. boot-max-ncpus is mainly used for optimization.
	 */
	if (tp != NULL)
		bsetpropsi(BOOT_MAX_NCPUS_NAME, cpu_count);

	/*
	 * User-set boot-ncpus overrides firmware count
	 */
	if (do_bsys_getproplen(NULL, BOOT_NCPUS_NAME) >= 0)
		return;

	/*
	 * Set boot property boot-ncpus to number of active CPUs given in MADT
	 * if it hasn't been set yet.
	 */
	if (tp != NULL)
		bsetpropsi(BOOT_NCPUS_NAME, cpu_count);
}

static void
process_srat(struct srat *tp)
{
	struct srat_item *item, *end;
	int i;
	int proc_num, mem_num;
#pragma pack(1)
	struct {
		uint32_t domain;
		uint32_t apic_id;
		uint32_t sapic_id;
	} processor;
	struct {
		uint32_t domain;
		uint32_t x2apic_id;
	} x2apic;
	struct {
		uint32_t domain;
		uint64_t addr;
		uint64_t length;
		uint32_t flags;
	} memory;
#pragma pack()
	char prop_name[30];
	uint64_t maxmem = 0;

	if (tp == NULL)
		return;

	proc_num = mem_num = 0;
	end = (struct srat_item *)(tp->hdr.len + (uintptr_t)tp);
	item = tp->list;
	while (item < end) {
		switch (item->type) {
		case SRAT_PROCESSOR:
			if (!(item->i.p.flags & SRAT_ENABLED))
				break;
			processor.domain = item->i.p.domain1;
			for (i = 0; i < 3; i++)
				processor.domain +=
				    item->i.p.domain2[i] << ((i + 1) * 8);
			processor.apic_id = item->i.p.apic_id;
			processor.sapic_id = item->i.p.local_sapic_eid;
			(void) snprintf(prop_name, 30, "acpi-srat-processor-%d",
			    proc_num);
			bsetprop(prop_name, strlen(prop_name), &processor,
			    sizeof (processor));
			proc_num++;
			break;
		case SRAT_MEMORY:
			if (!(item->i.m.flags & SRAT_ENABLED))
				break;
			memory.domain = item->i.m.domain;
			memory.addr = item->i.m.base_addr;
			memory.length = item->i.m.len;
			memory.flags = item->i.m.flags;
			(void) snprintf(prop_name, 30, "acpi-srat-memory-%d",
			    mem_num);
			bsetprop(prop_name, strlen(prop_name), &memory,
			    sizeof (memory));
			if ((item->i.m.flags & SRAT_HOT_PLUG) &&
			    (memory.addr + memory.length > maxmem)) {
				maxmem = memory.addr + memory.length;
			}
			mem_num++;
			break;
		case SRAT_X2APIC:
			if (!(item->i.xp.flags & SRAT_ENABLED))
				break;
			x2apic.domain = item->i.xp.domain;
			x2apic.x2apic_id = item->i.xp.x2apic_id;
			(void) snprintf(prop_name, 30, "acpi-srat-processor-%d",
			    proc_num);
			bsetprop(prop_name, strlen(prop_name), &x2apic,
			    sizeof (x2apic));
			proc_num++;
			break;
		}

		item = (struct srat_item *)
		    (item->len + (caddr_t)item);
	}

	/*
	 * The maximum physical address calculated from the SRAT table is more
	 * accurate than that calculated from the MSCT table.
	 */
	if (maxmem != 0) {
		plat_dr_physmax = btop(maxmem);
	}
}

static void
process_slit(struct slit *tp)
{

	/*
	 * Check the number of localities; if it's too huge, we just
	 * return and locality enumeration code will handle this later,
	 * if possible.
	 *
	 * Note that the size of the table is the square of the
	 * number of localities; if the number of localities exceeds
	 * UINT16_MAX, the table size may overflow an int when being
	 * passed to bsetprop() below.
	 */
	if (tp->number >= SLIT_LOCALITIES_MAX)
		return;

	bsetprop(SLIT_NUM_PROPNAME, strlen(SLIT_NUM_PROPNAME), &tp->number,
	    sizeof (tp->number));
	bsetprop(SLIT_PROPNAME, strlen(SLIT_PROPNAME), &tp->entry,
	    tp->number * tp->number);
}

static struct msct *
process_msct(struct msct *tp)
{
	int last_seen = 0;
	int proc_num = 0;
	struct msct_proximity_domain *item, *end;
	extern uint64_t plat_dr_options;

	ASSERT(tp != NULL);

	end = (void *)(tp->hdr.len + (uintptr_t)tp);
	for (item = (void *)((uintptr_t)tp + tp->proximity_domain_offset);
	    item < end;
	    item = (void *)(item->length + (uintptr_t)item)) {
		/*
		 * Sanity check according to section 5.2.19.1 of ACPI 4.0.
		 * Revision 	1
		 * Length	22
		 */
		if (item->revision != 1 || item->length != 22) {
			cmn_err(CE_CONT,
			    "?boot: unknown proximity domain structure in MSCT "
			    "with rev(%d), len(%d).\n",
			    (int)item->revision, (int)item->length);
			return (NULL);
		} else if (item->domain_min > item->domain_max) {
			cmn_err(CE_CONT,
			    "?boot: invalid proximity domain structure in MSCT "
			    "with domain_min(%u), domain_max(%u).\n",
			    item->domain_min, item->domain_max);
			return (NULL);
		} else if (item->domain_min != last_seen) {
			/*
			 * Items must be organized in ascending order of the
			 * proximity domain enumerations.
			 */
			cmn_err(CE_CONT,
			    "?boot: invalid proximity domain structure in MSCT,"
			    " items are not orginized in ascending order.\n");
			return (NULL);
		}

		/*
		 * If processor_max is 0 then there would be no CPUs in this
		 * domain.
		 */
		if (item->processor_max != 0) {
			proc_num += (item->domain_max - item->domain_min + 1) *
			    item->processor_max;
		}

		last_seen = item->domain_max - item->domain_min + 1;
		/*
		 * Break out if all proximity domains have been processed.
		 * Some BIOSes may have unused items at the end of MSCT table.
		 */
		if (last_seen > tp->maximum_proximity_domains) {
			break;
		}
	}
	if (last_seen != tp->maximum_proximity_domains + 1) {
		cmn_err(CE_CONT,
		    "?boot: invalid proximity domain structure in MSCT, "
		    "proximity domain count doesn't match.\n");
		return (NULL);
	}

	/*
	 * Set plat-max-ncpus property if it hasn't been set yet.
	 */
	if (do_bsys_getproplen(NULL, PLAT_MAX_NCPUS_NAME) < 0) {
		if (proc_num != 0) {
			bsetpropsi(PLAT_MAX_NCPUS_NAME, proc_num);
		}
	}

	/*
	 * Use Maximum Physical Address from the MSCT table as upper limit for
	 * memory hot-adding by default. It may be overridden by value from
	 * the SRAT table or the "plat-dr-physmax" boot option.
	 */
	plat_dr_physmax = btop(tp->maximum_physical_address + 1);

	/*
	 * Existence of MSCT implies CPU/memory hotplug-capability for the
	 * platform.
	 */
	plat_dr_options |= PLAT_DR_FEATURE_CPU;
	plat_dr_options |= PLAT_DR_FEATURE_MEMORY;

	return (tp);
}

#else /* __xpv */
static void
enumerate_xen_cpus()
{
	processorid_t	id, max_id;

	/*
	 * User-set boot-ncpus overrides enumeration
	 */
	if (do_bsys_getproplen(NULL, BOOT_NCPUS_NAME) >= 0)
		return;

	/*
	 * Probe every possible virtual CPU id and remember the
	 * highest id present; the count of CPUs is one greater
	 * than this.  This tacitly assumes at least cpu 0 is present.
	 */
	max_id = 0;
	for (id = 0; id < MAX_VIRT_CPUS; id++)
		if (HYPERVISOR_vcpu_op(VCPUOP_is_up, id, NULL) == 0)
			max_id = id;

	bsetpropsi(BOOT_NCPUS_NAME, max_id+1);

}
#endif /* __xpv */

static void
build_firmware_properties(void)
{
	struct table_header *tp = NULL;

#ifndef __xpv
	if ((msct_ptr = (struct msct *)find_fw_table("MSCT")) != NULL)
		msct_ptr = process_msct(msct_ptr);

	if ((tp = find_fw_table("APIC")) != NULL)
		process_madt((struct madt *)tp);

	if ((srat_ptr = (struct srat *)find_fw_table("SRAT")) != NULL)
		process_srat(srat_ptr);

	if (slit_ptr = (struct slit *)find_fw_table("SLIT"))
		process_slit(slit_ptr);

	tp = find_fw_table("MCFG");
#else /* __xpv */
	enumerate_xen_cpus();
	if (DOMAIN_IS_INITDOMAIN(xen_info))
		tp = find_fw_table("MCFG");
#endif /* __xpv */
	if (tp != NULL)
		process_mcfg((struct mcfg *)tp);
}

/*
 * fake up a boot property for deferred early console output
 * this is used by both graphical boot and the (developer only)
 * USB serial console
 */
void *
defcons_init(size_t size)
{
	static char *p = NULL;

	p = do_bsys_alloc(NULL, NULL, size, MMU_PAGESIZE);
	*p = 0;
	bsetprop("deferred-console-buf", strlen("deferred-console-buf") + 1,
	    &p, sizeof (p));
	return (p);
}

/*ARGSUSED*/
int
boot_compinfo(int fd, struct compinfo *cbp)
{
	cbp->iscmp = 0;
	cbp->blksize = MAXBSIZE;
	return (0);
}

#define	BP_MAX_STRLEN	32

/*
 * Get value for given boot property
 */
int
bootprop_getval(const char *prop_name, u_longlong_t *prop_value)
{
	int		boot_prop_len;
	char		str[BP_MAX_STRLEN];
	u_longlong_t	value;

	boot_prop_len = BOP_GETPROPLEN(bootops, prop_name);
	if (boot_prop_len < 0 || boot_prop_len > sizeof (str) ||
	    BOP_GETPROP(bootops, prop_name, str) < 0 ||
	    kobj_getvalue(str, &value) == -1)
		return (-1);

	if (prop_value)
		*prop_value = value;

	return (0);
}
