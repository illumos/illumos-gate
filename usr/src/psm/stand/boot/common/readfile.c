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

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/exechdr.h>
#include <sys/elf.h>
#include <sys/elf_notes.h>
#include <sys/bootconf.h>
#include <sys/reboot.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/link.h>
#include <sys/auxv.h>
#include <sys/salib.h>
#include <sys/bootvfs.h>
#include <sys/platnames.h>

#include "util.h"

#ifdef	BOOTAMD64
#include <amd64/amd64_page.h>
#endif	/* BOOTAMD64 */

union {
	struct exec X;
	Elf32_Ehdr Elfhdr;
	Elf64_Ehdr Elfhdr64;
} ex;

#define	x ex.X
#define	elfhdr ex.Elfhdr
#define	elfhdr64 ex.Elfhdr64

typedef int	(*func_t)();

#define	FAIL	((func_t)-1)
#define	ALIGN(x, a)	\
	((a) == 0 ? (uintptr_t)(x) : (((uintptr_t)(x) + (a) - 1) & ~((a) - 1)))

#define	__BOOT_NAUXV_IMPL	22

int 	use_align = 0;
int 	npagesize = 0;
uint_t 	icache_flush = 0;
char 	*cpulist = NULL;
char	*mmulist = NULL;
char	*module_path;		/* path for kernel modules */

/*
 * This file gets compiled in LP64 (for sun4u) and ILP32 models.
 * For LP64 compilation, the "client" file we load and run may be LP64 or ILP32,
 * and during bringup, the LP64 clients may have ELF32 headers.
 */
#ifdef	_ELF64_SUPPORT
#ifndef	BOOTAMD64
/*
 * Bootstrap vector for ELF32 LP64 client - neither supported nor needed for
 * AMD64
 */
Elf32_Boot *elfbootvecELF32_64;
#endif	/* !BOOTAMD64 */

Elf64_Boot *elfbootvecELF64;	/* ELF bootstrap vector for Elf64 LP64 */

#define	OK		((func_t)0)

#define	FAIL_READELF64	((uint64_t)0)
#define	FAIL_ILOAD64	((Elf64_Addr)-1)
#endif	/* _ELF64_SUPPORT */

/*
 * And by an ILP32 client. The non-sun4u/LP64 booters use these.
 * Also, the sun4u booter must create this for ILP32 clients.
 */
Elf32_Boot *elfbootvec;		/* ELF bootstrap vector normal ILP32 */

/*
 * Read in a Unix executable file and return its entry point.
 * Handle the various a.out formats correctly.
 * "fd" is the standalone file descriptor to read from.
 * Print informative little messages if "print" is on.
 * Returns -1 for errors.
 */

#ifdef DEBUG
static int debug = 1;
#else /* DEBUG */
static int debug = 0;
#endif /* DEBUG */

#define	dprintf		if (debug) printf

#ifdef	_ELF64_SUPPORT
typedef struct {
	uint_t	a_type;
#ifdef	BOOTAMD64
	uint_t	a_pad;	/* needed to 8-byte align uint64_ts below for AMD64 */
#endif	/* BOOTAMD64 */
	union {
		uint64_t a_val;
		uint64_t a_ptr;
#ifndef	BOOTAMD64
		void	(*a_fcn)();	/* XXX - UNUSED? */
#endif	/* !BOOTAMD64 */
	} a_un;
} auxv64_t;

#if defined(__sparcv9)
extern int client_isLP64;
#endif	/* __sparcv9 */

static uint64_t read_elf64(int, int, Elf64_Ehdr *);
static Elf64_Addr iload64(char *, Elf64_Phdr *, Elf64_Phdr *, auxv64_t **);
#endif	/* _ELF64_SUPPORT */

#if defined(i386) && !defined(_SYSCALL32)
typedef auxv_t	auxv32_t;
#endif

static func_t 	read_elf32(int, int, Elf32_Ehdr *);
static func_t	iload32(char *, Elf32_Phdr *, Elf32_Phdr *, auxv32_t **);
static caddr_t	segbrk(caddr_t *, size_t, size_t);
static int	openpath(char *, char *, int);
static char	*getmodpath(char *);
extern void	setup_aux(void);

extern void	*kmem_alloc(size_t, int);
extern void	kmem_free(void *, size_t);
extern int	cons_gets(char *, int);

#ifdef	BOOTAMD64
extern const char *amd64_getmmulist(void);

extern int amd64_elf64;
extern int is_amd64;
#endif	/* BOOTAMD64 */

#ifdef	lint
/*
 * This function is currently inlined
 */
/*ARGSUSED*/
void
sync_instruction_memory(caddr_t v, size_t len)
{}
#else	/* lint */
extern void sync_instruction_memory(caddr_t v, size_t len);
#endif	/* lint */

extern int 	verbosemode;
extern int	boothowto;
extern int	pagesize;
extern char	filename[];

/*
 * repeat reads (forever) until size of request is satisfied
 * (Thus, you don't want to use this cases where short reads are ok)
 */
ssize_t
xread(int fd, char *p, size_t nbytes)
{
	size_t bytesread = 0;
	int errorcount = 0;
	ssize_t i;

	while (bytesread < nbytes) {
		i = read(fd, p, nbytes - bytesread);
		if (i < 0) {
			++errorcount;
			if (verbosemode)
				printf("read error (0x%x times)\n", errorcount);
			continue;
		}
		bytesread += i;
		p += i;
	}
	return (bytesread);
}

func_t
readfile(int fd, int print)
{
#ifdef	_ELF64_SUPPORT
#ifdef	BOOTAMD64
	extern int bsetprop(struct bootops *, char *, void *, int);
	extern struct bootops *bop;
	extern uint64_t elf64_go2;
#else	/* !BOOTAMD64 */
	uint64_t elf64_go2;
#endif	/* BOOTAMD64 */
#endif	/* _ELF64_SUPPORT */

	ssize_t i;
	int shared = 0;

	if (verbosemode) {
		dprintf("fd = %x\n", fd);
	}

	i = xread(fd, (char *)&elfhdr, sizeof (Elf64_Ehdr));
	if (x.a_magic == ZMAGIC || x.a_magic == NMAGIC)
		shared = 1;
	if (i != sizeof (Elf64_Ehdr)) {
		printf("Error reading ELF header.\n");
		return (FAIL);
	}
	if (!shared && x.a_magic != OMAGIC) {
		if (*(int *)&elfhdr.e_ident == *(int *)(ELFMAG)) {
			if (verbosemode) {
				int is64 = (elfhdr.e_ident[EI_CLASS] ==
				    ELFCLASS64);

				dprintf("calling readelf, elfheader is:\n");
				dprintf("e_ident\t0x%x, 0x%x, 0x%x, 0x%x\n",
				    *(int *)&elfhdr.e_ident[0],
				    *(int *)&elfhdr.e_ident[4],
				    *(int *)&elfhdr.e_ident[8],
				    *(int *)&elfhdr.e_ident[12]);
				dprintf("e_machine\t0x%x\n", elfhdr.e_machine);

				dprintf("e_entry\t\t0x%llx\n", (is64 ?
				    elfhdr64.e_entry :
				    (u_longlong_t)elfhdr.e_entry));
				dprintf("e_shoff\t\t0x%llx\n", (is64 ?
				    elfhdr64.e_shoff :
				    (u_longlong_t)elfhdr.e_shoff));
				dprintf("e_shnentsize\t%d\n", (is64 ?
				    elfhdr64.e_shentsize : elfhdr.e_shentsize));
				dprintf("e_shnum\t\t%d\n", (is64 ?
				    elfhdr64.e_shnum : elfhdr.e_shnum));
				dprintf("e_shstrndx\t%d\n", (is64 ?
				    elfhdr64.e_shstrndx : elfhdr.e_shstrndx));
			}


#ifdef	_ELF64_SUPPORT
			dprintf("ELF file CLASS 0x%x 32 is %x 64 is %x\n",
			    elfhdr.e_ident[EI_CLASS], ELFCLASS32, ELFCLASS64);

			if (elfhdr.e_ident[EI_CLASS] == ELFCLASS64) {
#ifdef	BOOTAMD64
				if (elfhdr.e_machine != EM_AMD64) {
					printf("FATAL: 64-bit ELF executable "
					    "not for AMD64\n       (e_machine "
					    "= %d).\n", elfhdr.e_machine);
					return (FAIL);
				}

				/*
				 * OK, we know the executable is for an AMD64
				 * CPU.  Make sure we ARE an AMD64 CPU before
				 * proceeding.
				 */
				if (is_amd64 == 0) {
					printf("FATAL: AMD64 executables not "
					    " supported on this CPU.\n");
					return (FAIL);
				}

				amd64_elf64 = (elfhdr.e_ident[EI_CLASS] ==
				    ELFCLASS64);
#endif	/* BOOTAMD64 */

				elf64_go2 = read_elf64(fd, print,
				    (Elf64_Ehdr *)&elfhdr);

#ifdef	BOOTAMD64
				if (elf64_go2 != FAIL_READELF64)
					(void) bsetprop(bop, "mmu-modlist",
					    "mmu64", 0);

				return ((elf64_go2 == FAIL_READELF64) ? FAIL :
				    OK);
#else	/* !BOOTAMD64 */
				return ((elf64_go2 == FAIL_READELF64) ? FAIL :
				    (func_t)elf64_go2);
#endif	/* BOOTAMD64 */

			} else
#endif	/* _ELF64_SUPPORT */
				return (read_elf32(fd, print, &elfhdr));
		} else {
			printf("File not executable.\n");
			return (FAIL);
		}
	}
	return (FAIL);
}

/*
 * Macros to add attribute/values to the ELF bootstrap vector
 * and the aux vector. Use the type-cast to convert integers
 * to pointers first to suppress the gcc warning.
 */
#define	AUX(p, a, v)	{ (p)->a_type = (a); \
			((p)++)->a_un.a_val = (int32_t)(uintptr_t)(v); }

#define	EBV(p, a, v)	{ (p)->eb_tag = (a); \
			((p)++)->eb_un.eb_val = (Elf32_Word)(uintptr_t)(v); }

static func_t
read_elf32(int fd, int print, Elf32_Ehdr *elfhdrp)
{
	Elf32_Phdr *phdr;	/* program header */
	Elf32_Nhdr *nhdr;	/* note header */
	int nphdrs, phdrsize;
	caddr_t allphdrs;
	caddr_t	namep, descp;
	Elf32_Addr loadaddr, base;
	size_t offset = 0;
	size_t size;
	uintptr_t off;
	int	i;
	int	bss_seen = 0;
	int interp = 0;				/* interpreter required */
	static char dlname[MAXPATHLEN];		/* name of interpeter */
	uint_t dynamic;				/* dynamic tags array */
	Elf32_Phdr *thdr;			/* "text" program header */
	Elf32_Phdr *dhdr;			/* "data" program header */
	func_t entrypt;				/* entry point of standalone */

	/* Initialize pointers so we won't free bogus ones on elferror */
	allphdrs = NULL;
	nhdr = NULL;

#ifdef _ELF64_SUPPORT
	if (verbosemode)
		printf("Elf32 client\n");
#endif	/* _ELF64_SUPPORT */

	if (elfhdrp->e_phnum == 0 || elfhdrp->e_phoff == 0)
		goto elferror;

	/* use uintptr_t to suppress the gcc warning */
	entrypt = (func_t)(uintptr_t)elfhdrp->e_entry;
	if (verbosemode)
		dprintf("Entry point: %p\n", (void *)entrypt);

	/*
	 * Allocate and read in all the program headers.
	 */
	nphdrs = elfhdrp->e_phnum;
	phdrsize = nphdrs * elfhdrp->e_phentsize;
	allphdrs = (caddr_t)kmem_alloc(phdrsize, 0);
	if (allphdrs == NULL)
		goto elferror;
	if (verbosemode)
		dprintf("lseek: args = %x %x %x\n", fd, elfhdrp->e_phoff, 0);
	if (lseek(fd, elfhdrp->e_phoff, 0) == -1)
		goto elferror;
	if (xread(fd, allphdrs, phdrsize) != phdrsize)
		goto elferror;

	/*
	 * First look for PT_NOTE headers that tell us what pagesize to
	 * use in allocating program memory.
	 */
	npagesize = 0;
	for (i = 0; i < nphdrs; i++) {
		void *note_buf;

		phdr = (Elf32_Phdr *)(allphdrs + elfhdrp->e_phentsize * i);
		if (phdr->p_type != PT_NOTE)
			continue;
		if (verbosemode) {
			dprintf("allocating 0x%x bytes for note hdr\n",
			    phdr->p_filesz);
		}
		if ((note_buf = kmem_alloc(phdr->p_filesz, 0)) == NULL)
			goto elferror;
		if (verbosemode)
			dprintf("seeking to 0x%x\n", phdr->p_offset);
		if (lseek(fd, phdr->p_offset, 0) == -1)
			goto elferror;
		if (verbosemode) {
			dprintf("reading 0x%x bytes into %p\n",
			    phdr->p_filesz, (void *)nhdr);
		}
		nhdr = (Elf32_Nhdr *)note_buf;
		if (xread(fd, (caddr_t)nhdr, phdr->p_filesz) != phdr->p_filesz)
			goto elferror;
		if (verbosemode) {
			dprintf("p_note namesz %x descsz %x type %x\n",
			    nhdr->n_namesz, nhdr->n_descsz, nhdr->n_type);
		}

		/*
		 * Iterate through all ELF PT_NOTE elements looking for
		 * ELF_NOTE_SOLARIS which, if present, will specify the
		 * executable's preferred pagesize.
		 */
		do {
			namep = (caddr_t)(nhdr + 1);

			if (nhdr->n_namesz == strlen(ELF_NOTE_SOLARIS) + 1 &&
			    strcmp(namep, ELF_NOTE_SOLARIS) == 0 &&
			    nhdr->n_type == ELF_NOTE_PAGESIZE_HINT) {
				descp = namep + roundup(nhdr->n_namesz, 4);
				npagesize = *(int *)descp;
				if (verbosemode)
					dprintf("pagesize is %x\n", npagesize);
			}

			offset += sizeof (Elf32_Nhdr) + roundup(nhdr->n_namesz,
			    4) + roundup(nhdr->n_descsz, 4);

			nhdr = (Elf32_Nhdr *)((char *)note_buf + offset);
		} while (offset < phdr->p_filesz);

		kmem_free(note_buf, phdr->p_filesz);
		nhdr = NULL;
	}

	/*
	 * Next look for PT_LOAD headers to read in.
	 */
	if (print)
		printf("Size: ");
	for (i = 0; i < nphdrs; i++) {
		phdr = (Elf32_Phdr *)(allphdrs + elfhdrp->e_phentsize * i);
		if (verbosemode) {
			dprintf("Doing header 0x%x\n", i);
			dprintf("phdr\n");
			dprintf("\tp_offset = %x, p_vaddr = %x\n",
			    phdr->p_offset, phdr->p_vaddr);
			dprintf("\tp_memsz = %x, p_filesz = %x\n",
			    phdr->p_memsz, phdr->p_filesz);
		}
		if (phdr->p_type == PT_LOAD) {
			if (verbosemode)
				dprintf("seeking to 0x%x\n", phdr->p_offset);
			if (lseek(fd, phdr->p_offset, 0) == -1)
				goto elferror;

			if (phdr->p_flags == (PF_R | PF_W) &&
			    phdr->p_vaddr == 0) {
				/*
				 * It's a PT_LOAD segment that is RW but
				 * not executable and has a vaddr
				 * of zero.  This is relocation info that
				 * doesn't need to stick around after
				 * krtld is done with it.  We allocate boot
				 * memory for this segment, since we don't want
				 * it mapped in permanently as part of
				 * the kernel image.
				 */
				if ((loadaddr = (uintptr_t)
				    kmem_alloc(phdr->p_memsz, 0)) == 0)
					goto elferror;
				/*
				 * Save this to pass on
				 * to the interpreter.
				 */
				phdr->p_vaddr = (Elf32_Addr)loadaddr;
			} else {
				if (print)
					printf("0x%x+", phdr->p_filesz);
				/*
				 * If we found a new pagesize above, use it
				 * to adjust the memory allocation.
				 */
				loadaddr = phdr->p_vaddr;
				if (use_align && npagesize != 0) {
					off = loadaddr & (npagesize - 1);
					size = roundup(phdr->p_memsz + off,
					    npagesize);
					base = loadaddr - off;
				} else {
					npagesize = 0;
					size = phdr->p_memsz;
					base = loadaddr;
				}
				/*
				 *  Check if it's text or data.
				 */
				if (phdr->p_flags & PF_W)
					dhdr = phdr;
				else
					thdr = phdr;

				/*
				 * If memory size is zero just ignore this
				 * header.
				 */
				if (size == 0)
					continue;

				if (verbosemode)
					dprintf("allocating memory: %x %lx "
					    "%x\n", base, size, npagesize);
				/*
				 * We're all set up to read.
				 * Now let's allocate some memory.
				 */

#ifdef	i386
				/*
				 * If vaddr == paddr and npagesize is 0, that
				 * means the executable needs to be identity
				 * mapped in memory (va == pa, mapped 1:1)
				 *
				 * Otherwise load as usual.
				 */
				if ((phdr->p_vaddr == phdr->p_paddr) &&
				    (npagesize == 0)) {
					extern caddr_t idmap_mem(uint32_t,
					    size_t, int);

					uint_t n;

					n = (uint_t)base & (pagesize - 1);
					if (n) {
						base -= n;
						size += n;
					}

					if (!idmap_mem((uint32_t)base,
					    (size_t)size, pagesize))
						goto elferror;
				} else
#endif	/* i386 */
				/* use uintptr_t to suppress the gcc warning */
				if (get_progmemory((caddr_t)(uintptr_t)base,
				    size, npagesize))
					goto elferror;
			}

			if (verbosemode) {
				dprintf("reading 0x%x bytes into 0x%x\n",
				    phdr->p_filesz, loadaddr);
			}
			/* use uintptr_t to suppress the gcc warning */
			if (xread(fd, (caddr_t)(uintptr_t)loadaddr,
			    phdr->p_filesz) != phdr->p_filesz)
				goto elferror;

			/* zero out BSS */
			if (phdr->p_memsz > phdr->p_filesz) {
				loadaddr += phdr->p_filesz;
				if (verbosemode) {
					dprintf("bss from 0x%x size 0x%x\n",
					    loadaddr,
					    phdr->p_memsz - phdr->p_filesz);
				}
				/* use uintptr_t to suppress the gcc warning */
				bzero((void *)(uintptr_t)loadaddr,
				    phdr->p_memsz - phdr->p_filesz);
				bss_seen++;
				if (print)
					printf("0x%x Bytes\n",
					    phdr->p_memsz - phdr->p_filesz);
			}

			/* force instructions to be visible to icache */
			if (phdr->p_flags & PF_X) {
				sync_instruction_memory(
				    (caddr_t)(uintptr_t)phdr->p_vaddr,
				    phdr->p_memsz);
			}
		} else if (phdr->p_type == PT_INTERP) {
			/*
			 * Dynamically-linked executable.
			 */
			interp = 1;
			if (lseek(fd, phdr->p_offset, 0) == -1) {
				goto elferror;
			}
			/*
			 * Get the name of the interpreter.
			 */
			if (xread(fd, dlname, phdr->p_filesz) !=
			    phdr->p_filesz ||
			    dlname[phdr->p_filesz - 1] != '\0')
				goto elferror;
		} else if (phdr->p_type == PT_DYNAMIC) {
			dynamic = phdr->p_vaddr;
		}
	}

	if (!bss_seen && print)
		printf("0 Bytes\n");

	/*
	 * Load the interpreter
	 * if there is one.
	 */
	if (interp) {
		Elf32_Boot bootv[EB_MAX];		/* Bootstrap vector */
		auxv32_t auxv[__BOOT_NAUXV_IMPL];	/* Aux vector */
		Elf32_Boot *bv = bootv;
		auxv32_t *av = auxv;
		size_t vsize;

		/*
		 * Load it.
		 */
		if ((entrypt = iload32(dlname, thdr, dhdr, &av)) == FAIL)
			goto elferror;
		/*
		 * Build bootstrap and aux vectors.
		 */
		setup_aux();
		EBV(bv, EB_AUXV, 0); /* fill in later */
		EBV(bv, EB_PAGESIZE, pagesize);
		EBV(bv, EB_DYNAMIC, dynamic);
		EBV(bv, EB_NULL, 0);

		AUX(av, AT_BASE, entrypt);
		AUX(av, AT_ENTRY, elfhdrp->e_entry);
		AUX(av, AT_PAGESZ, pagesize);
		AUX(av, AT_PHDR, allphdrs);
		AUX(av, AT_PHNUM, elfhdrp->e_phnum);
		AUX(av, AT_PHENT, elfhdrp->e_phentsize);
		if (use_align)
			AUX(av, AT_SUN_LPAGESZ, npagesize);
		AUX(av, AT_SUN_IFLUSH, icache_flush);
		if (cpulist != NULL)
			AUX(av, AT_SUN_CPU, cpulist);
		if (mmulist != NULL)
			AUX(av, AT_SUN_MMU, mmulist);
		AUX(av, AT_NULL, 0);
		/*
		 * Realloc vectors and copy them.
		 */
		vsize = (caddr_t)bv - (caddr_t)bootv;
		if ((elfbootvec = (Elf32_Boot *)kmem_alloc(vsize, 0)) == NULL)
			goto elferror;
		bcopy((char *)bootv, (char *)elfbootvec, vsize);

		size = (caddr_t)av - (caddr_t)auxv;
		if (size > sizeof (auxv)) {
			printf("readelf: overrun of available aux vectors\n");
			kmem_free(elfbootvec, vsize);
			goto elferror;
		}
		/* use uintptr_t to suppress the gcc warning */
		if ((elfbootvec->eb_un.eb_ptr =
		    (Elf32_Addr)(uintptr_t)kmem_alloc(size, 0)) == 0) {
			kmem_free(elfbootvec, vsize);
			goto elferror;
		}
		/* use uintptr_t to suppress the gcc warning */
		bcopy(auxv,
		    (void *)(uintptr_t)(elfbootvec->eb_un.eb_ptr), size);

#if defined(_ELF64_SUPPORT) && !defined(BOOTAMD64)
		/*
		 * Make an LP64 copy of the vector for use by 64-bit standalones
		 * even if they have ELF32.
		 */
		if ((elfbootvecELF32_64 = (Elf32_Boot *)kmem_alloc(vsize, 0))
		    == NULL)
			goto elferror;
		bcopy(bootv, elfbootvecELF32_64, vsize);

		size = (av - auxv) * sizeof (auxv64_t);
		/* use uintptr_t to suppress the gcc warning */
		if ((elfbootvecELF32_64->eb_un.eb_ptr =
		    (Elf32_Addr)(uintptr_t)kmem_alloc(size, 0)) == 0) {
			kmem_free(elfbootvecELF32_64, vsize);
			goto elferror;
		} else {
			auxv64_t *a64 =
			    (auxv64_t *)(uintptr_t)
			    elfbootvecELF32_64->eb_un.eb_ptr;
			auxv32_t *a = auxv;

			for (a = auxv; a < av; a++) {
				a64->a_type = a->a_type;
				a64->a_un.a_val = a->a_un.a_val;
				a64++;
			}
		}
#endif	/* _ELF64_SUPPORT && !BOOTAMD64 */
	} else {
		kmem_free(allphdrs, phdrsize);
	}
	return (entrypt);

elferror:
	if (allphdrs != NULL)
		kmem_free(allphdrs, phdrsize);
	if (nhdr != NULL)
		kmem_free(nhdr, phdr->p_filesz);
	printf("Elf32 read error.\n");
	return (FAIL);
}

#ifdef	_ELF64_SUPPORT
/*
 * Macros to add attribute/values to the ELF bootstrap vector
 * and the aux vector.
 */
#define	AUX64(p, a, v)	{ (p)->a_type = (a); \
			((p)++)->a_un.a_val = (uint64_t)(v); }

#define	EBV64(p, a, v)	{ (p)->eb_tag = (a); \
			((p)++)->eb_un.eb_val = (Elf64_Xword)(v); }

static uint64_t
read_elf64(int fd, int print, Elf64_Ehdr *elfhdrp)
{
	Elf64_Phdr *phdr;	/* program header */
	Elf64_Nhdr *nhdr;	/* note header */
	int nphdrs, phdrsize;
	caddr_t allphdrs;
	caddr_t	namep, descp;
	Elf64_Addr loadaddr, base;
	size_t offset = 0;
	size_t size;
	int i;
	uintptr_t	off;
	int bss_seen = 0;
	int interp = 0;				/* interpreter required */
	static char dlname[MAXPATHLEN];		/* name of interpeter */
	uintptr_t dynamic;			/* dynamic tags array */
	Elf64_Phdr *thdr;			/* "text" program header */
	Elf64_Phdr *dhdr;			/* "data" program header */
	Elf64_Addr entrypt;			/* entry point of standalone */

	/* Initialize pointers so we won't free bogus ones on elf64error */
	allphdrs = NULL;
	nhdr = NULL;
#if defined(__sparcv9)
	client_isLP64 = 1;
#endif	/* __sparcv9 */

	if (verbosemode)
		printf("Elf64 client\n");

	if (elfhdrp->e_phnum == 0 || elfhdrp->e_phoff == 0)
		goto elf64error;

	entrypt = elfhdrp->e_entry;
	if (verbosemode)
		dprintf("Entry point: 0x%llx\n", (u_longlong_t)entrypt);

	/*
	 * Allocate and read in all the program headers.
	 */
	nphdrs = elfhdrp->e_phnum;
	phdrsize = nphdrs * elfhdrp->e_phentsize;
	allphdrs = (caddr_t)kmem_alloc(phdrsize, 0);
	if (allphdrs == NULL)
		goto elf64error;
	if (verbosemode)
		dprintf("lseek: args = %x %llx %x\n", fd,
		    (u_longlong_t)elfhdrp->e_phoff, 0);
	if (lseek(fd, elfhdrp->e_phoff, 0) == -1)
		goto elf64error;
	if (xread(fd, allphdrs, phdrsize) != phdrsize)
		goto elf64error;

	/*
	 * First look for PT_NOTE headers that tell us what pagesize to
	 * use in allocating program memory.
	 */
	npagesize = 0;
	for (i = 0; i < nphdrs; i++) {
		void *note_buf;

		phdr = (Elf64_Phdr *)(allphdrs + elfhdrp->e_phentsize * i);
		if (phdr->p_type != PT_NOTE)
			continue;
		if (verbosemode) {
			dprintf("allocating 0x%llx bytes for note hdr\n",
			    (u_longlong_t)phdr->p_filesz);
		}
		if ((note_buf = kmem_alloc(phdr->p_filesz, 0)) == NULL)
			goto elf64error;
		if (verbosemode)
			dprintf("seeking to 0x%llx\n",
			    (u_longlong_t)phdr->p_offset);
		if (lseek(fd, phdr->p_offset, 0) == -1)
			goto elf64error;
		if (verbosemode) {
			dprintf("reading 0x%llx bytes into 0x%p\n",
			    (u_longlong_t)phdr->p_filesz, (void *)nhdr);
		}
		nhdr = (Elf64_Nhdr *)note_buf;
		if (xread(fd, (caddr_t)nhdr, phdr->p_filesz) != phdr->p_filesz)
			goto elf64error;
		if (verbosemode) {
			dprintf("p_note namesz %x descsz %x type %x\n",
			    nhdr->n_namesz, nhdr->n_descsz, nhdr->n_type);
		}

		/*
		 * Iterate through all ELF PT_NOTE elements looking for
		 * ELF_NOTE_SOLARIS which, if present, will specify the
		 * executable's preferred pagesize.
		 */
		do {
			namep = (caddr_t)(nhdr + 1);

			if (nhdr->n_namesz == strlen(ELF_NOTE_SOLARIS) + 1 &&
			    strcmp(namep, ELF_NOTE_SOLARIS) == 0 &&
			    nhdr->n_type == ELF_NOTE_PAGESIZE_HINT) {
				descp = namep + roundup(nhdr->n_namesz, 4);
				npagesize = *(int *)descp;
				if (verbosemode)
					dprintf("pagesize is %x\n", npagesize);
			}

			offset += sizeof (Elf64_Nhdr) + roundup(nhdr->n_namesz,
			    4) + roundup(nhdr->n_descsz, 4);

			nhdr = (Elf64_Nhdr *)((char *)note_buf + offset);
		} while (offset < phdr->p_filesz);

		kmem_free(note_buf, phdr->p_filesz);
		nhdr = NULL;
	}

	/*
	 * Next look for PT_LOAD headers to read in.
	 */
	if (print)
		printf("Size: ");
	for (i = 0; i < nphdrs; i++) {
		phdr = (Elf64_Phdr *)(allphdrs + elfhdrp->e_phentsize * i);
		if (verbosemode) {
			dprintf("Doing header 0x%x\n", i);
			dprintf("phdr\n");
			dprintf("\tp_offset = %llx, p_vaddr = %llx\n",
			    (u_longlong_t)phdr->p_offset,
			    (u_longlong_t)phdr->p_vaddr);
			dprintf("\tp_memsz = %llx, p_filesz = %llx\n",
			    (u_longlong_t)phdr->p_memsz,
			    (u_longlong_t)phdr->p_filesz);
			dprintf("\tp_type = %x, p_flags = %x\n",
			    phdr->p_type, phdr->p_flags);
		}
		if (phdr->p_type == PT_LOAD) {
			if (verbosemode)
				dprintf("seeking to 0x%llx\n",
				    (u_longlong_t)phdr->p_offset);
			if (lseek(fd, phdr->p_offset, 0) == -1)
				goto elf64error;

			if (phdr->p_flags == (PF_R | PF_W) &&
			    phdr->p_vaddr == 0) {
				/*
				 * It's a PT_LOAD segment that is RW but
				 * not executable and has a vaddr
				 * of zero.  This is relocation info that
				 * doesn't need to stick around after
				 * krtld is done with it.  We allocate boot
				 * memory for this segment, since we don't want
				 * it mapped in permanently as part of
				 * the kernel image.
				 */
#ifdef	BOOTAMD64
				if ((loadaddr = (Elf64_Addr)
				    (ADDR_XTND(kmem_alloc(phdr->p_memsz, 0))))
				    == 0)
#else	/* !BOOTAMD64 */
				if ((loadaddr = (Elf64_Addr)(uintptr_t)
				    kmem_alloc(phdr->p_memsz, 0)) == 0)
#endif	/* BOOTAMD64 */
					goto elf64error;

				/*
				 * Save this to pass on
				 * to the interpreter.
				 */
				phdr->p_vaddr = loadaddr;
			} else {
				if (print)
					printf("0x%llx+",
					    (u_longlong_t)phdr->p_filesz);
				/*
				 * If we found a new pagesize above, use it
				 * to adjust the memory allocation.
				 */
				loadaddr = phdr->p_vaddr;
				if (use_align && npagesize != 0) {
					off = loadaddr & (npagesize - 1);
					size = roundup(phdr->p_memsz + off,
					    npagesize);
					base = loadaddr - off;
				} else {
					npagesize = 0;
					size = phdr->p_memsz;
					base = loadaddr;
				}
				/*
				 *  Check if it's text or data.
				 */
				if (phdr->p_flags & PF_W)
					dhdr = phdr;
				else
					thdr = phdr;

				if (verbosemode)
					dprintf(
					    "allocating memory: %llx %lx %x\n",
					    (u_longlong_t)base,
					    size, npagesize);

				/*
				 * If memory size is zero just ignore this
				 * header.
				 */
				if (size == 0)
					continue;

				/*
				 * We're all set up to read.
				 * Now let's allocate some memory.
				 */
				if (get_progmemory((caddr_t)(uintptr_t)base,
				    size, npagesize))
					goto elf64error;
			}

			if (verbosemode) {
				dprintf("reading 0x%llx bytes into 0x%llx\n",
				    (u_longlong_t)phdr->p_filesz,
				    (u_longlong_t)loadaddr);
			}
			if (xread(fd, (caddr_t)(uintptr_t)
			    loadaddr, phdr->p_filesz) != phdr->p_filesz)
				goto elf64error;

			/* zero out BSS */
			if (phdr->p_memsz > phdr->p_filesz) {
				loadaddr += phdr->p_filesz;
				if (verbosemode) {
					dprintf("bss from 0x%llx size 0x%llx\n",
					    (u_longlong_t)loadaddr,
					    (u_longlong_t)(phdr->p_memsz -
					    phdr->p_filesz));
				}

				bzero((caddr_t)(uintptr_t)loadaddr,
				    phdr->p_memsz - phdr->p_filesz);
				bss_seen++;
				if (print)
					printf("0x%llx Bytes\n",
					    (u_longlong_t)(phdr->p_memsz -
					    phdr->p_filesz));
			}

			/* force instructions to be visible to icache */
			if (phdr->p_flags & PF_X)
				sync_instruction_memory((caddr_t)(uintptr_t)
				    phdr->p_vaddr, phdr->p_memsz);

		} else if (phdr->p_type == PT_INTERP) {
			/*
			 * Dynamically-linked executable.
			 */
			interp = 1;
			if (lseek(fd, phdr->p_offset, 0) == -1) {
				goto elf64error;
			}
			/*
			 * Get the name of the interpreter.
			 */
			if (xread(fd, dlname, phdr->p_filesz) !=
			    phdr->p_filesz ||
			    dlname[phdr->p_filesz - 1] != '\0')
				goto elf64error;
		} else if (phdr->p_type == PT_DYNAMIC) {
			dynamic = phdr->p_vaddr;
		}
	}

	if (!bss_seen && print)
		printf("0 Bytes\n");

	/*
	 * Load the interpreter
	 * if there is one.
	 */
	if (interp) {
		Elf64_Boot bootv[EB_MAX];		/* Bootstrap vector */
		auxv64_t auxv[__BOOT_NAUXV_IMPL];	/* Aux vector */
		Elf64_Boot *bv = bootv;
		auxv64_t *av = auxv;
		size_t vsize;

		/*
		 * Load it.
		 */
		if ((entrypt = iload64(dlname, thdr, dhdr, &av)) ==
		    FAIL_ILOAD64)
			goto elf64error;
		/*
		 * Build bootstrap and aux vectors.
		 */
		setup_aux();
		EBV64(bv, EB_AUXV, 0); /* fill in later */
		EBV64(bv, EB_PAGESIZE, pagesize);
		EBV64(bv, EB_DYNAMIC, dynamic);
		EBV64(bv, EB_NULL, 0);

		AUX64(av, AT_BASE, entrypt);
		AUX64(av, AT_ENTRY, elfhdrp->e_entry);
		AUX64(av, AT_PAGESZ, pagesize);
		AUX64(av, AT_PHDR, (uintptr_t)allphdrs);
		AUX64(av, AT_PHNUM, elfhdrp->e_phnum);
		AUX64(av, AT_PHENT, elfhdrp->e_phentsize);
		if (npagesize)
			AUX64(av, AT_SUN_LPAGESZ, npagesize);

#ifdef	BOOTAMD64
		vsize = strlen(amd64_getmmulist()) + 1;
		if ((mmulist = kmem_alloc(vsize, 0)) == NULL)
			goto elf64error;

		bcopy(amd64_getmmulist(), mmulist, vsize);
		AUX64(av, AT_SUN_MMU, (uintptr_t)mmulist);
#endif	/* BOOTAMD64 */

		AUX64(av, AT_SUN_IFLUSH, icache_flush);
		if (cpulist != NULL)
			AUX64(av, AT_SUN_CPU, (uintptr_t)cpulist);
		AUX64(av, AT_NULL, 0);
		/*
		 * Realloc vectors and copy them.
		 */
		vsize = (caddr_t)bv - (caddr_t)bootv;
		if ((elfbootvecELF64 =
		    (Elf64_Boot *)kmem_alloc(vsize, 0)) == NULL)
			goto elf64error;
		bcopy((char *)bootv, (char *)elfbootvecELF64, vsize);

		size = (caddr_t)av - (caddr_t)auxv;
		if (size > sizeof (auxv)) {
			printf("readelf: overrun of available aux vectors\n");
			kmem_free(elfbootvecELF64, vsize);
			goto elf64error;
		}

#ifdef	BOOTAMD64
		if ((elfbootvecELF64->eb_un.eb_ptr =
		    ADDR_XTND(kmem_alloc(size, 0))) == NULL) {
			kmem_free(elfbootvecELF64, vsize);
			goto elf64error;
		}

		bcopy((char *)auxv,
		    (char *)ADDR_TRUNC((elfbootvecELF64->eb_un.eb_ptr)), size);
#else	/* !BOOTAMD64 */
		if ((elfbootvecELF64->eb_un.eb_ptr =
		    (Elf64_Addr)kmem_alloc(size, 0)) == 0) {
			kmem_free(elfbootvecELF64, vsize);
			goto elf64error;
		}

		bcopy((char *)auxv, (char *)(elfbootvecELF64->eb_un.eb_ptr),
		    size);
#endif	/* BOOTAMD64 */
	} else {
		kmem_free(allphdrs, phdrsize);
	}
	return ((uint64_t)entrypt);

elf64error:
	if (allphdrs != NULL)
		kmem_free(allphdrs, phdrsize);
	if (nhdr != NULL)
		kmem_free(nhdr, phdr->p_filesz);
	printf("Elf64 read error.\n");
	return (FAIL_READELF64);
}
#endif	/* _ELF64_SUPPORT */

/*
 * Load the interpreter.  It expects a
 * relocatable .o capable of bootstrapping
 * itself.
 */
static func_t
iload32(char *rtld, Elf32_Phdr *thdr, Elf32_Phdr *dhdr, auxv32_t **avp)
{
	Elf32_Ehdr *ehdr = NULL;
	uintptr_t dl_entry = 0;
	uint_t i;
	int fd;
	int size;
	caddr_t shdrs = NULL;
	caddr_t etext, edata;

	/* use uintptr_t to suppress the gcc warning */
	etext = (caddr_t)(uintptr_t)thdr->p_vaddr + thdr->p_memsz;
	edata = (caddr_t)(uintptr_t)dhdr->p_vaddr + dhdr->p_memsz;

	/*
	 * Get the module path.
	 */
	module_path = getmodpath(filename);

	if ((fd = openpath(module_path, rtld, O_RDONLY)) < 0) {
		printf("boot: cannot find %s\n", rtld);
		goto errorx;
	}
	dprintf("Opened %s OK\n", rtld);
	AUX(*avp, AT_SUN_LDNAME, rtld);
	/*
	 * Allocate and read the ELF header.
	 */
	if ((ehdr = (Elf32_Ehdr *)kmem_alloc(sizeof (Elf32_Ehdr), 0)) == NULL) {
		printf("boot: alloc error reading ELF header (%s).\n", rtld);
		goto error;
	}

	if (xread(fd, (char *)ehdr, sizeof (*ehdr)) != sizeof (*ehdr)) {
		printf("boot: error reading ELF header (%s).\n", rtld);
		goto error;
	}

	size = ehdr->e_shentsize * ehdr->e_shnum;
	if ((shdrs = (caddr_t)kmem_alloc(size, 0)) == NULL) {
		printf("boot: alloc error reading ELF header (%s).\n", rtld);
		goto error;
	}
	/*
	 * Read the section headers.
	 */
	if (lseek(fd, ehdr->e_shoff, 0) == -1 ||
	    xread(fd, shdrs, size) != size) {
		printf("boot: error reading section headers\n");
		goto error;
	}
	AUX(*avp, AT_SUN_LDELF, ehdr);
	AUX(*avp, AT_SUN_LDSHDR, shdrs);
	/*
	 * Load sections into the appropriate dynamic segment.
	 */
	for (i = 1; i < ehdr->e_shnum; i++) {
		Elf32_Shdr *sp;
		caddr_t *spp;
		caddr_t load;

		sp = (Elf32_Shdr *)(shdrs + (i*ehdr->e_shentsize));
		/*
		 * If it's not allocated and not required
		 * to do relocation, skip it.
		 */
		if (!(sp->sh_flags & SHF_ALLOC) &&
#ifdef i386
		    sp->sh_type != SHT_REL &&
#else
		    sp->sh_type != SHT_RELA &&
#endif
		    sp->sh_type != SHT_SYMTAB &&
		    sp->sh_type != SHT_STRTAB)
			continue;
		/*
		 * If the section is read-only,
		 * it goes in as text.
		 */
		spp = (sp->sh_flags & SHF_WRITE)? &edata: &etext;
		/*
		 * Make some room for it.
		 */
		load = segbrk(spp, sp->sh_size, sp->sh_addralign);
		if (load == NULL) {
			printf("boot: allocating memory for sections failed\n");
			goto error;
		}
		/*
		 * Compute the entry point of the linker.
		 */
		if (dl_entry == 0 &&
		    !(sp->sh_flags & SHF_WRITE) &&
		    (sp->sh_flags & SHF_EXECINSTR)) {
			dl_entry = (uintptr_t)load + ehdr->e_entry;
		}
		/*
		 * If it's bss, just zero it out.
		 */
		if (sp->sh_type == SHT_NOBITS) {
			bzero(load, sp->sh_size);
		} else {
			/*
			 * Read the section contents.
			 */
			if (lseek(fd, sp->sh_offset, 0) == -1 ||
			    xread(fd, load, sp->sh_size) != sp->sh_size) {
				printf("boot: error reading sections\n");
				goto error;
			}
		}
		/*
		 * Assign the section's virtual addr. Use uintptr_t to
		 * suppress the gcc warning.
		 */
		sp->sh_addr = (Elf32_Off)(uintptr_t)load;
		/*
		 * Force instructions to be visible to icache. Use
		 * uintptr_t to suppress the gcc warning as well.
		 */
		if (sp->sh_flags & SHF_EXECINSTR)
			sync_instruction_memory((caddr_t)(uintptr_t)sp->sh_addr,
			    sp->sh_size);
	}
	/*
	 * Update sizes of segments.
	 */
	thdr->p_memsz = (Elf32_Word)((uintptr_t)etext - thdr->p_vaddr);
	dhdr->p_memsz = (Elf32_Word)((uintptr_t)edata - dhdr->p_vaddr);

	/* load and relocate symbol tables in SAS */
	(void) close(fd);
	return ((func_t)dl_entry);

error:
	(void) close(fd);
errorx:
	if (ehdr)
		kmem_free(ehdr, sizeof (Elf32_Ehdr));
	if (shdrs)
		kmem_free(shdrs, size);
	printf("boot: error loading interpreter (%s)\n", rtld);
	return (FAIL);
}

#ifdef	_ELF64_SUPPORT
/*
 * Load the interpreter.  It expects a
 * relocatable .o capable of bootstrapping
 * itself.
 */
static Elf64_Addr
iload64(char *rtld, Elf64_Phdr *thdr, Elf64_Phdr *dhdr, auxv64_t **avp)
{
	Elf64_Ehdr *ehdr = NULL;
	Elf64_Addr dl_entry = (Elf64_Addr)0;
	Elf64_Addr etext, edata;
	uint_t i;
	int fd;
	int size;
	caddr_t shdrs = NULL;

	etext = thdr->p_vaddr + thdr->p_memsz;
	edata = dhdr->p_vaddr + dhdr->p_memsz;

	/*
	 * Get the module path.
	 */
	module_path = getmodpath(filename);

	if ((fd = openpath(module_path, rtld, O_RDONLY)) < 0) {
		printf("boot: cannot find %s\n", rtld);
		goto errorx;
	}
	dprintf("Opened %s OK\n", rtld);
	AUX64(*avp, AT_SUN_LDNAME, (uintptr_t)rtld);
	/*
	 * Allocate and read the ELF header.
	 */
#ifdef	BOOTAMD64
	if ((ehdr = (Elf64_Ehdr *)(uintptr_t)kmem_alloc(sizeof (Elf64_Ehdr),
	    0)) == NULL) {
#else	/* !BOOTAMD64 */
	if ((ehdr = (Elf64_Ehdr *)kmem_alloc(sizeof (Elf64_Ehdr), 0)) == NULL) {
#endif	/* BOOTAMD64 */
		printf("boot: alloc error reading ELF header (%s).\n", rtld);
		goto error;
	}

	if (xread(fd, (char *)ehdr, sizeof (*ehdr)) != sizeof (*ehdr)) {
		printf("boot: error reading ELF header (%s).\n", rtld);
		goto error;
	}

	size = ehdr->e_shentsize * ehdr->e_shnum;
	if ((shdrs = (caddr_t)kmem_alloc(size, 0)) == NULL) {
		printf("boot: alloc error reading ELF header (%s).\n", rtld);
		goto error;
	}
	/*
	 * Read the section headers.
	 */
	if (lseek(fd, ehdr->e_shoff, 0) == -1 ||
	    xread(fd, shdrs, size) != size) {
		printf("boot: error reading section headers\n");
		goto error;
	}

#ifdef	BOOTAMD64
	AUX64(*avp, AT_SUN_LDELF, (uintptr_t)ehdr);
	AUX64(*avp, AT_SUN_LDSHDR, (uintptr_t)shdrs);
#else	/* !BOOTAMD64 */
	AUX64(*avp, AT_SUN_LDELF, ehdr);
	AUX64(*avp, AT_SUN_LDSHDR, shdrs);
#endif	/* BOOTAMD64 */

	/*
	 * Load sections into the appropriate dynamic segment.
	 */
	for (i = 1; i < ehdr->e_shnum; i++) {
		Elf64_Shdr *sp;
		Elf64_Addr *spp, load;

		sp = (Elf64_Shdr *)(shdrs + (i*ehdr->e_shentsize));
		/*
		 * If it's not allocated and not required
		 * to do relocation, skip it.
		 */
		if (!(sp->sh_flags & SHF_ALLOC) &&
		    sp->sh_type != SHT_SYMTAB &&
		    sp->sh_type != SHT_STRTAB &&
		    sp->sh_type != SHT_RELA)
			continue;
		/*
		 * If the section is read-only,
		 * it goes in as text.
		 */
		spp = (sp->sh_flags & SHF_WRITE)? &edata: &etext;

		/*
		 * Make some room for it.
		 */
#ifdef	BOOTAMD64
		load = ADDR_XTND(segbrk((caddr_t *)spp,
		    sp->sh_size, sp->sh_addralign));
#else	/* !BOOTAMD64 */
		load = (Elf64_Addr)segbrk((caddr_t *)spp, sp->sh_size,
		    sp->sh_addralign);
#endif	/* BOOTAMD64 */

		if (load == 0) {
			printf("boot: allocating memory for section %d "
			    "failed\n", i);
			goto error;
		}

		/*
		 * Compute the entry point of the linker.
		 */
		if (dl_entry == 0 &&
		    !(sp->sh_flags & SHF_WRITE) &&
		    (sp->sh_flags & SHF_EXECINSTR)) {
			dl_entry = load + ehdr->e_entry;
			if (verbosemode)
				dprintf("boot: loading linker @ 0x%llx\n",
				    (u_longlong_t)dl_entry);
		}

		/*
		 * If it's bss, just zero it out.
		 */
		if (sp->sh_type == SHT_NOBITS) {
			bzero((caddr_t)(uintptr_t)load, sp->sh_size);
		} else {
			/*
			 * Read the section contents.
			 */
			if (lseek(fd, sp->sh_offset, 0) == -1 ||
			    xread(fd, (caddr_t)(uintptr_t)load, sp->sh_size) !=
			    sp->sh_size) {
				printf("boot: error reading section %d\n", i);
				goto error;
			}
		}
		/*
		 * Assign the section's virtual addr.
		 */

		sp->sh_addr = load;

		if (verbosemode)
			dprintf("boot: section %d, type %d, loaded @ 0x%llx, "
			    "size 0x%llx\n", i, sp->sh_type, (u_longlong_t)load,
			    (u_longlong_t)sp->sh_size);

		/* force instructions to be visible to icache */
		if (sp->sh_flags & SHF_EXECINSTR)
			sync_instruction_memory((caddr_t)(uintptr_t)sp->sh_addr,
			    sp->sh_size);
	}
	/*
	 * Update sizes of segments.
	 */
	thdr->p_memsz = etext - thdr->p_vaddr;
	dhdr->p_memsz = edata - dhdr->p_vaddr;

	/* load and relocate symbol tables in SAS */
	(void) close(fd);
	return (dl_entry);

error:
	(void) close(fd);
errorx:
	if (ehdr)
		kmem_free((caddr_t)ehdr, sizeof (Elf64_Ehdr));
	if (shdrs)
		kmem_free(shdrs, size);
	printf("boot: error loading interpreter (%s)\n", rtld);
	return (FAIL_ILOAD64);
}
#endif	/* _ELF64_SUPPORT */

/*
 * Extend the segment's "break" value by bytes.
 */
static caddr_t
segbrk(caddr_t *spp, size_t bytes, size_t align)
{
	caddr_t va, pva;
	size_t size = 0;
	unsigned int alloc_pagesize = pagesize;
	unsigned int alloc_align = 0;

	if (npagesize) {
		alloc_align = npagesize;
		alloc_pagesize = npagesize;
	}

	va = (caddr_t)ALIGN(*spp, align);
	pva = (caddr_t)roundup((uintptr_t)*spp, alloc_pagesize);
	/*
	 * Need more pages?
	 */
	if (va + bytes > pva) {
		size = roundup((bytes - (pva - va)), alloc_pagesize);

		if (get_progmemory(pva, size, alloc_align)) {
			printf("boot: segbrk allocation failed, "
			    "0x%lx bytes @ %p\n", bytes, (void *)pva);
			return (NULL);
		}
	}
	*spp = va + bytes;

	return (va);
}

/*
 * Open the file using a search path and
 * return the file descriptor (or -1 on failure).
 */
static int
openpath(path, fname, flags)
char *path;
char *fname;
int flags;
{
	register char *p, *q;
	char buf[MAXPATHLEN];
	int fd;

	/*
	 * If the file name is absolute,
	 * don't use the module search path.
	 */
	if (fname[0] == '/')
		return (open(fname, flags));

	q = NULL;
	for (p = path;  /* forever */;  p = q) {

		while (*p == ' ' || *p == '\t' || *p == ':')
			p++;
		if (*p == '\0')
			break;
		q = p;
		while (*q && *q != ' ' && *q != '\t' && *q != ':')
			q++;
		(void) strncpy(buf, p, q - p);
		if (q[-1] != '/') {
			buf[q - p] = '/';
			(void) strcpy(&buf[q - p + 1], fname);
		} else {
			/*
			 * This checks for paths that end in '/'
			 */
			(void) strcpy(&buf[q - p], fname);
		}

		if ((fd = open(buf, flags)) > 0)
			return (fd);
	}
	return (-1);
}

/*
 * Get the module search path.
 */
static char *
getmodpath(fname)
char *fname;
{
	register char *p = strrchr(fname, '/');
	static char mod_path[MOD_MAXPATH];
	size_t len;
	extern char *impl_arch_name;
#if defined(__sparcv9) || defined(BOOTAMD64)
#ifdef	__sparcv9
	char    *isastr = "/sparcv9";
#endif	/* __sparcv9 */
#ifdef	BOOTAMD64
	char	*isastr = "/amd64";
#endif	/* BOOTAMD64 */
	size_t	isalen = strlen(isastr);
#endif	/* __sparcv9 || BOOTAMD64 */

	if (p == NULL) {
		/* strchr could not find a "/" */
		printf("%s is not a legal kernel pathname", fname);
		return (NULL);
	}
	while (p > fname && *(p - 1) == '/')
		p--;		/* remove trailing "/"s */
	if (p == fname)
		p++;		/* "/" is the modpath in this case */

	len = p - fname;
	(void) strncpy(mod_path, fname, len);
	mod_path[len] = 0;

#if defined(__sparcv9) || defined(BOOTAMD64)
	len = strlen(mod_path);
	if ((len > isalen) && (strcmp(&mod_path[len - isalen], isastr) == 0)) {
		mod_path[len - isalen] = '\0';
#if defined(__sparcv9)
		if ((client_isLP64 == 0) && verbosemode)
			printf("Assuming LP64 %s client.\n", isastr);
		client_isLP64 = 1;
#endif	/* __sparcv9 */
	}
#endif	/* __sparcv9 || BOOTAMD64 */
	mod_path_uname_m(mod_path, impl_arch_name);
	(void) strcat(mod_path, " ");
	(void) strcat(mod_path, MOD_DEFPATH);

	if (boothowto & RB_ASKNAME) {
		char buf[MOD_MAXPATH];

		printf("Enter default directory for modules [%s]: ", mod_path);
		(void) cons_gets(buf, sizeof (buf));
		if (buf[0] != '\0')
			(void) strcpy(mod_path, buf);
	}
	if (verbosemode)
		printf("modpath: %s\n", mod_path);
	return (mod_path);
}
