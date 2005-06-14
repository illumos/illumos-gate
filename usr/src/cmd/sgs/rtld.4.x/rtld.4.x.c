/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Binary compatibility ld.so.  Intercepts the reference of a pre-SVR4
 * SunOS executable to the dynamic linker, and then redirects to the
 * "real" post-SVR4 SunOS ld.so.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Import data structures (N.B.: from 5.x).
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/sysconfig.h>
#include <sys/auxv.h>
#include <sys/archsystm.h>
#include <elf.h>
#include <link.h>

/*
 * Relocation manifest constants and macros.
 */
#define	ALIGN(x, a)		((int)(x) & ~((int)(a) - 1))
#define	ROUND(x, a)		(((int)(x) + ((int)(a) - 1)) & \
				    ~((int)(a) - 1))
#define	DYNAMIC_VERSION2	2
#define	RELOC_SIZE		(sizeof (struct relocation_info))
#define	RELOCOFF(x)		(x)->v2->ld_rel
#define	MASK(n)			((1<<(n))-1)
#define	IN_RANGE(v, n)		((-(1<<((n)-1))) <= (v) && (v) < (1<<((n)-1)))

void	aout_reloc_write();

/*
 * 4.x SunOS Dynamic Link Editor public definitions (much derived from
 * SunOS 4.x <link.h>.)
 */

/*
 * Dynamic linking information.  With the exception of
 * ld_loaded (determined at execution time) and ld_stab_hash (a special
 * case of relocation handled at execution time), the values in this
 * structure reflect offsets from the containing link_dynamic structure.
 */
struct link_dynamic_1 {
	struct	link_map *ld_loaded;	/* list of loaded objects */
	long	ld_need;		/* list of needed objects */
	long	ld_rules;		/* search rules for library objects */
	long	ld_got;			/* global offset table */
	long	ld_plt;			/* procedure linkage table */
	long	ld_rel;			/* relocation table */
	long	ld_hash;		/* symbol hash table */
	long	ld_stab;		/* symbol table itself */
	long	(*ld_stab_hash)();	/* "pointer" to symbol hash function */
	long	ld_buckets;		/* number of hash buckets */
	long	ld_symbols;		/* symbol strings */
	long	ld_symb_size;		/* size of symbol strings */
	long	ld_text;		/* size of text area */
};

struct link_dynamic_2 {
	struct	link_map *ld_loaded;	/* list of loaded objects */
	long	ld_need;		/* list of needed objects */
	long	ld_rules;		/* search rules for library objects */
	long	ld_got;			/* global offset table */
	long	ld_plt;			/* procedure linkage table */
	long	ld_rel;			/* relocation table */
	long	ld_hash;		/* symbol hash table */
	long	ld_stab;		/* symbol table itself */
	long	(*ld_stab_hash)();	/* "pointer" to symbol hash function */
	long	ld_buckets;		/* number of hash buckets */
	long	ld_symbols;		/* symbol strings */
	long	ld_symb_size;		/* size of symbol strings */
	long	ld_text;		/* size of text area */
	long	ld_plt_sz;		/* size of procedure linkage table */
};

/*
 * Debugger interface structure.
 */
struct 	ld_debug {
	int	ldd_version;		/* version # of interface */
	int	ldd_in_debugger;	/* a debugger is running us */
	int	ldd_sym_loaded;		/* we loaded some symbols */
	char    *ldd_bp_addr;		/* place for ld-generated bpt */
	int	ldd_bp_inst;		/* instruction which was there */
	struct rtc_symb *ldd_cp;	/* commons we built */
};

/*
 * Structure associated with each object which may be or which requires
 * execution-time link editing.  Used by the run-time linkage editor to
 * identify needed objects and symbol definitions and references.
 */
struct	link_dynamic {
	int	ld_version;
	struct 	ld_debug *ldd;
	union {
		struct link_dynamic_1 *ld_1;
		struct link_dynamic_2 *ld_2;
	} ld_un;
};

struct 	old_link_dynamic {
	int	ld_version;		/* version # of this structure */
	union {
		struct link_dynamic_1 ld_1;
	} ld_un;

	int	in_debugging;
	int	sym_loaded;
	char    *bp_addr;
	int	bp_inst;
	struct rtc_symb *cp; 		/* pointer to an array of runtime */
					/* allocated common symbols. */
};

#define	v2	ld_un.ld_2		/* short hands */
#define	v1	ld_un.ld_1

/*
 * SunOS 4.x SPARC relocation types and relocation record.  Note that
 * these, among other things, make this program not portable to things
 * other than SPARC.
 */
enum reloc_type {
	RELOC_8, RELOC_16, RELOC_32,	/* simplest relocs */
	RELOC_DISP8, RELOC_DISP16, RELOC_DISP32,
					/* Disp's (pc-rel) */
	RELOC_WDISP30, RELOC_WDISP22,	/* SR word disp's */
	RELOC_HI22, RELOC_22,		/* SR 22-bit relocs */
	RELOC_13, RELOC_LO10,		/* SR 13&10-bit relocs */
	RELOC_SFA_BASE, RELOC_SFA_OFF13, /* SR S.F.A. relocs */
	RELOC_BASE10, RELOC_BASE13, RELOC_BASE22,
					/* PIC GOT references */
	RELOC_PC10, RELOC_PC22,		/* PIC reference to GOT */
	RELOC_JMP_TBL,			/* PIC call */
	RELOC_SEGOFF16,			/* .so offset-in-segment */
	RELOC_GLOB_DAT, RELOC_JMP_SLOT, RELOC_RELATIVE,
					/* ld.so relocation types */
};

struct relocation_info {
	unsigned long int r_address;	/* relocation addr */
	unsigned int	r_index   :24;	/* segment index or symbol index */
	unsigned int	r_extern  : 1;	/* if F, r_index==SEG#; if T, SYM idx */
	int			  : 2;	/* <unused> */
	enum reloc_type r_type    : 5;	/* type of relocation to perform */
	long int	r_addend;	/* addend for relocation value */
};

/*
 * Size of relocations.
 */
#define	GETRELSZ(x)	\
	(x->ld_version < 2 ? \
	((struct old_link_dynamic *)x)->v1.ld_hash - \
		((struct old_link_dynamic *)x)->v1.ld_rel : \
	(x)->v2->ld_hash - (x)->v2->ld_rel)

/*
 * Interface between crt0 & ld.so.
 */
struct crt_i1 {
	int	crt_baseaddr;		/* Address ld.so is at */
	int	crt_dzfd;		/* /dev/zero file descriptor */
	int	crt_rlfd;		/* ld.so file descriptor */
	struct	link_dynamic *crt_udp;	/* "main_" dynamic */
	char	**crt_ep;		/* environment strings */
	caddr_t	crt_breakp;		/* place to put initial breakpoint */
};

/*
 * Structure we provide to ELF ld.so upon entry.
 */
Elf32_Boot	eb[EB_MAX];

/*
 * Global data.
 */
char *program_name;			/* used in messages */

/*
 * 4.0 ld.so main entry point.
 */
rtld(version, ip, dp, argp)
	int version;			/* interface version */
	struct crt_i1 *ip;		/* interface passed from program */
	register struct link_dynamic *dp; /* ld.so dynamic pointer */
	caddr_t	argp;			/* pointer to begining of args */
{
	char *ldso;			/* name of what we really want to be */
	int i, p;			/* working */
	int r;				/* working (# of *our* relocations */
	int page_size = 0;		/* size of a page */
	struct relocation_info *rp;	/* working pointer to our relocs */
	int fd;				/* fd assigned to ld.so */
	Elf32_Ehdr *ehdr;		/* ELF header of ld.so */
	Elf32_Phdr *phdr;		/* first Phdr in file */
	Elf32_Phdr *pptr;		/* working Phdr */
	Elf32_Phdr *lph;		/* last loadable Phdr */
	Elf32_Phdr *fph = 0;		/* first loadable Phdr */
	caddr_t maddr;			/* pointer to mapping claim */
	Elf32_Off mlen;			/* total mapping claim */
	caddr_t faddr;			/* first program mapping of ld.so */
	Elf32_Off foff;			/* file offset for segment mapping */
	Elf32_Off flen;			/* file length for segment mapping */
	caddr_t addr;			/* working mapping address */
	caddr_t zaddr;			/* /dev/zero working mapping addr */
	Elf32_Boot *ebp;		/* communication with ld.so */
	struct stat sb;			/* stat buffer for sizing */
	auxv_t *ap;			/* working aux pointer */
	void (*	wrt)();			/* address of write/iflush routine */

	/*
	 * ld.so must itself be relocated, take care of this now.
	 * We can not refer to global data before this step is
	 * complete.  Perform the relocation by stepping over all
	 * entries in the relocation table and turn them into
	 * absolute addresses.  Note that, in order to avoid invoking
	 * as yet unrelocated items, we perform the relocation count
	 * by counting rather than risk invoking subroutine calls
	 * to intrinsic .div or .mul routines.  Note also that we
	 * assume that there are no symbolic relocations to be
	 * performed here.
	 */
	dp->v2 = (struct link_dynamic_2 *)
	    ((caddr_t)dp->v2 + ip->crt_baseaddr);
	r = 0;
	i = GETRELSZ(dp);
	while (i != 0) {
		i -= RELOC_SIZE;
		r++;
	}
	rp = (struct relocation_info *)(RELOCOFF(dp) +
	    (dp->ld_version < DYNAMIC_VERSION2 ?
	    (int)dp : ip->crt_baseaddr));

	/*
	 * Determine the location of the routine that will write the relocation.
	 * This hasn't yet been relocated so determine the real address using
	 * our base address.
	 */
	wrt = (void (*)())((caddr_t)aout_reloc_write + ip->crt_baseaddr);

	/*
	 * Relocate ourselves - we only need RELOC_RELATIVE and RELOC_32.
	 * Note, if panic() was called its probable that it will barf as the
	 * corresponding plt wouldn't have been relocated yet.
	 */
	for (i = 0; i < r; i++) {
	    long *where = (long *)((caddr_t)rp->r_address + ip->crt_baseaddr);
	    long what = ip->crt_baseaddr;
	    long value;

	    switch (rp->r_type) {
	    case RELOC_RELATIVE:
		what += *where << (32-22);
		value = (*where & ~MASK(22)) | ((what >> (32-22)) & MASK(22));
		wrt(where, value);
		where++;
		what += (*where & MASK(10));
		value = (*where & ~MASK(10)) | (what & MASK(10));
		wrt(where, value);
		break;

	    case RELOC_32:
		what += *where;
		wrt(where, what);
		break;

	    default:
		panic("unknown relocation type %d\n", rp->r_type);
		break;
	    }
	    rp++;
	}

	/*
	 * We're relocated, we can now initialize things referencing
	 * static storage.
	 */
	ldso = "/usr/lib/ld.so.1";

	/*
	 * Close off the file descriptor used to get us here -- let it
	 * be available for the next (probable) use below.
	 */
	(void) close(ip->crt_rlfd);

	/*
	 * Discover things about our environment: auxiliary vector (if
	 * any), arguments, program name, and the like.
	 */
	ebp = eb;
	program_name = (char *)(argp + sizeof (int));
	if (version != 1)
		panic("bad startup interface version of %d",
		    version);
	ebp->eb_tag = EB_DYNAMIC,
	    (ebp++)->eb_un.eb_ptr = (Elf32_Addr)ip->crt_udp;
	ebp->eb_tag = EB_ARGV, (ebp++)->eb_un.eb_ptr = (Elf32_Addr)program_name;
	ebp->eb_tag = EB_ENVP, (ebp++)->eb_un.eb_ptr = (Elf32_Addr)ip->crt_ep;
	ebp->eb_tag = EB_DEVZERO,
	    (ebp++)->eb_un.eb_val = (Elf32_Word)ip->crt_dzfd;
	for (addr = (caddr_t)ip->crt_ep; *addr; addr += sizeof (char *))
		;
	addr += sizeof (char *);

	/*
	 * The kernel sends us an abbreviated aux vector with some
	 * potentially handy stuff that saves us on syscalls.
	 *
	 * Notes on 1226113
	 *
	 * The f77 compiler shipped as part of SC1.0 on 4.x creates binaries
	 * that use the _fix_libc_ feature of acc.  This makes the resulting
	 * executable object dependent on the undocumented behaviour of
	 * libc's .rem and .div routines e.g. that .div returns the
	 * remainder in %o3 (and similarly .rem returns the division in %o3).
	 *
	 * The only simple solution is to disable hardware divide for
	 * all 4.x applications so that the old software routines that have
	 * this "support" in them are used instead.  And we do that by
	 * clearing the divide-in-hardware flag from the aux vector before
	 * libc's .init routine gets to see it.  Awful isn't it.
	 */
	ebp->eb_tag = EB_AUXV, (ebp++)->eb_un.eb_ptr = (Elf32_Addr)addr;
	for (ap = (auxv_t *)addr; ap->a_type != AT_NULL; ap++)
		if (ap->a_type == AT_PAGESZ) {
			page_size = ap->a_un.a_val;
			ebp->eb_tag = EB_PAGESIZE, (ebp++)->eb_un.eb_val =
			    (Elf32_Word)page_size;
		} else if (ap->a_type == AT_SUN_HWCAP)
			ap->a_un.a_val &= ~AV_SPARC_HWDIV_32x32;

	/*
	 * If we didn't get a page size from looking in the auxiliary
	 * vector, we need to get one now.
	 */
	if (page_size == 0) {
		page_size = sysconfig(_CONFIG_PAGESIZE);
		ebp->eb_tag = EB_PAGESIZE, (ebp++)->eb_un.eb_val =
		    (Elf32_Word)page_size;
	}

	/*
	 * Map in the ELF-based ld.so.  Note that we're mapping it as
	 * an ELF database, not as a program -- we just want to walk it's
	 * data structures.  Further mappings will actually establish the
	 * program in the address space.
	 */
	if ((fd = open(ldso, O_RDONLY)) == -1)
		panic("unable to open %s", ldso);
	if (fstat(fd, &sb) == -1)
		panic("unable to find size of %s", ldso);
	ehdr = (Elf32_Ehdr *)mmap(0, sb.st_size, PROT_READ | PROT_EXEC,
	    MAP_SHARED, fd, 0);
	if (ehdr == (Elf32_Ehdr *)-1)
		panic("unable to map %s", ldso);

	/*
	 * Validate the file we're looking at, ensure it has the correct
	 * ELF structures, such as: ELF magic numbers, coded for SPARC,
	 * is a ".so", etc.
	 */
	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3)
		panic("%s is not an ELF file", ldso);
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2MSB)
		panic("%s has wrong class or data encoding", ldso);
	if (ehdr->e_type != ET_DYN)
		panic("%s is not a shared object", ldso);
	if ((ehdr->e_machine != EM_SPARC) &&
	    (ehdr->e_machine != EM_SPARC32PLUS))
		panic("%s is not a valid SPARC object: e_machine: %x",
		    ldso, ehdr->e_machine);
	if (ehdr->e_version > EV_CURRENT)
		panic("%s has bad ELF version of %d", ldso, ehdr->e_version);

	/*
	 * Point at program headers and start figuring out what to load.
	 */
	phdr = (Elf32_Phdr *)((caddr_t)ehdr + ehdr->e_phoff);
	for (p = 0, pptr = phdr; p < (int)ehdr->e_phnum; p++,
	    pptr = (Elf32_Phdr *)((caddr_t)pptr + ehdr->e_phentsize))
		if (pptr->p_type == PT_LOAD) {
			if (fph == 0) {
				fph = pptr;
			} else if (pptr->p_vaddr <= lph->p_vaddr)
				panic(
		"%s invalid program header - segments out of order", ldso);
			lph = pptr;
		}

	/*
	 * We'd better have at least one loadable segment.
	 */
	if (fph == 0)
		panic("%s has no loadable segments", ldso);

	/*
	 * Map enough address space to hold the program (as opposed to the
	 * file) represented by ld.so.  The amount to be assigned is the
	 * range between the end of the last loadable segment and the
	 * beginning of the first PLUS the alignment of the first segment.
	 * mmap() can assign us any page-aligned address, but the relocations
	 * assume the alignments included in the program header.  As an
	 * optimization, however, let's assume that mmap() will actually
	 * give us an aligned address -- since if it does, we can save
	 * an munmap() later on.  If it doesn't -- then go try it again.
	 */
	mlen = ROUND((lph->p_vaddr + lph->p_memsz) -
	    ALIGN(fph->p_vaddr, page_size), page_size);
	maddr = (caddr_t)mmap(0, mlen, PROT_READ | PROT_EXEC,
	    MAP_SHARED, fd, 0);
	if (maddr == (caddr_t)-1)
		panic("unable to reserve space for %s", ldso);
	faddr = (caddr_t)ROUND(maddr, fph->p_align);

	/*
	 * Check to see whether alignment skew was really needed.
	 */
	if (faddr != maddr) {
		(void) munmap(maddr, mlen);
		mlen = ROUND((lph->p_vaddr + lph->p_memsz) -
		    ALIGN(fph->p_vaddr, fph->p_align) + fph->p_align,
		    page_size);
		maddr = (caddr_t)mmap(0, mlen, PROT_READ | PROT_EXEC,
		    MAP_SHARED, fd, 0);
		if (maddr == (caddr_t)-1)
			panic("unable to reserve space for %s", ldso);
		faddr = (caddr_t)ROUND(maddr, fph->p_align);
	}
	ebp->eb_tag = EB_LDSO_BASE, (ebp++)->eb_un.eb_ptr = (Elf32_Addr)faddr;

	/*
	 * We have the address space reserved, so map each loadable segment.
	 */
	for (pptr = phdr; (pptr - phdr) < (int)ehdr->e_phnum; pptr++) {

		/*
		 * Skip non-loadable segments or segments that don't occupy
		 * any memory.
		 */
		if ((pptr->p_type != PT_LOAD) || (pptr->p_memsz == 0))
			continue;

		/*
		 * Determine the file offset to which the mapping will
		 * directed (must be aligned) and how much to map (might
		 * be more than the file in the case of .bss.)
		 */
		foff = ALIGN(pptr->p_offset, page_size);
		flen = pptr->p_memsz + (pptr->p_offset - foff);

		/*
		 * Set address of this segment relative to our base.
		 */
		addr = (caddr_t)ALIGN(faddr + pptr->p_vaddr, page_size);

		/*
		 * Unmap anything form the last mapping address to this
		 * one.
		 */
		if (addr - maddr) {
			(void) munmap(maddr, addr - maddr);
			mlen -= addr - maddr;
		}

		/*
		 * Determine the mapping protection from the section
		 * attributes.
		 */
		i = 0;
		if (pptr->p_flags & PF_R)
			i |= PROT_READ;
		if (pptr->p_flags & PF_W)
			i |= PROT_WRITE;
		if (pptr->p_flags & PF_X)
			i |= PROT_EXEC;
		if ((caddr_t)mmap((caddr_t)addr, flen, i,
		    MAP_FIXED | MAP_PRIVATE, fd, foff) == (caddr_t)-1)
			panic("unable to map a segment from %s", ldso);

		/*
		 * If the memory occupancy of the segment overflows the
		 * definition in the file, we need to "zero out" the
		 * end of the mapping we've established, and if necessary,
		 * map some more space from /dev/zero.
		 */
		if (pptr->p_memsz > pptr->p_filesz) {
			foff = (int)faddr + pptr->p_vaddr + pptr->p_filesz;
			zaddr = (caddr_t)ROUND(foff, page_size);
			_zero(foff, zaddr - foff);
			r = (faddr + pptr->p_vaddr + pptr->p_memsz) - zaddr;
			if (r > 0)
				if ((caddr_t)mmap((caddr_t)zaddr, r, i,
				    MAP_FIXED | MAP_PRIVATE, ip->crt_dzfd,
				    0) == (caddr_t)-1)
					panic(
					"unable to map .bss /dev/zero for %s",
					    ldso);
		}

		/*
		 * Update the mapping claim pointer.
		 */
		maddr = addr + ROUND(flen, page_size);
		mlen -= maddr - addr;
	}

	/*
	 * Unmap any final reservation.
	 */
	if (mlen > 0)
		(void) munmap(maddr, mlen);

	/*
	 * Clean up file descriptor space we've consumed.  Pass along
	 * the /dev/zero file descriptor we got -- every cycle counts.
	 */
	(void) close(fd);

	/*
	 * The call itself.  Note that we start 1 instruction word in.
	 * The ELF ld.so contains an "entry vector" of branch instructions,
	 * which, for our interest are:
	 *	+0:	ba, a	<normal startup>
	 *	+4:	ba, a	<compatibility startup>
	 * By starting at the compatibility startup, the ELF ld.so knows
	 * that a pointer to "eb" is available to it and further knows
	 * how to calculate the offset to the program's arguments and
	 * other structures.
	 */
	ebp->eb_tag = EB_NULL, ebp->eb_un.eb_val = 0;
	(*((void (*)())(ehdr->e_entry + faddr + sizeof (long))))(eb);
	return (0);
}
