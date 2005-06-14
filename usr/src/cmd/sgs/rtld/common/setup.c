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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * Run time linker common setup.
 *
 * Called from _setup to get the process going at startup.
 */
#include	"_synonyms.h"

#include	<stdlib.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mman.h>
#include	<string.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<dlfcn.h>
#include	<sys/sysconfig.h>
#include	<sys/auxv.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"_a.out.h"
#include	"msg.h"
#include	"debug.h"
#include	"conv.h"


extern int	_end, _edata, _etext;
extern void	_init(void);
extern int	_brk_unlocked(void *);

#ifndef	SGS_PRE_UNIFIED_PROCESS
/* needed for _brk_unlocked() */
void *_nd = &_end;
#endif

/*
 * Define for the executable's interpreter.
 * Usually it is ld.so.1, but for the first release of ICL binaries
 * it is libc.so.1.  We keep this information so that we don't end
 * up mapping libc twice if it is the interpreter.
 */
static Interp _interp;


static int
preload(const char *str, Rt_map *lmp)
{
	Rt_map		*clmp = lmp;
	char		*objs, *ptr, *next;
	Word		lmflags = lml_main.lm_flags;
	uint_t		flags;

	DBG_CALL(Dbg_util_nl());

	if ((objs = strdup(str)) == 0)
		return (0);

	/*
	 * Establish the flags for loading each object.  If we're called via
	 * lddstub, then the first shared object is the object being inspected
	 * by ldd(1).  This object should not be marked as an interposer, as
	 * it is intended to act like the first object of the process.
	 */
	if ((lmflags & LML_FLG_TRC_ENABLE) && (FLAGS1(lmp) & FL1_RT_LDDSTUB))
		flags = FLG_RT_PRELOAD;
	else
		flags = (FLG_RT_PRELOAD | FLG_RT_INTRPOSE);

	ptr = strtok_r(objs, MSG_ORIG(MSG_STR_DELIMIT), &next);
	do {
		Pnode	*pnp;
		Rt_map	*nlmp = 0;

		DBG_CALL(Dbg_file_preload(ptr));

		/*
		 * If this a secure application, then preload errors are
		 * reduced to warnings, as the errors are non-fatal.
		 */
		if (rtld_flags & RT_FL_SECURE)
			rtld_flags2 |= RT_FL2_FTL2WARN;
		if ((pnp = expand_paths(clmp, ptr, PN_SER_EXTLOAD, 0)) != 0)
			nlmp = load_one(&lml_main, ALO_DATA, pnp, clmp,
			MODE(lmp), flags, 0);
		if (pnp)
			remove_pnode(pnp);
		if (rtld_flags & RT_FL_SECURE)
			rtld_flags2 &= ~RT_FL2_FTL2WARN;
		if (nlmp && (bind_one(clmp, nlmp, BND_NEEDED) == 0))
			nlmp = 0;

		/*
		 * Establish state for the next preloadable object.  If no
		 * error occurred with loading this object, indicate that this
		 * link-map list contains an interposer.
		 */
		flags |= FLG_RT_INTRPOSE;
		if (nlmp == 0) {
			if ((lmflags & LML_FLG_TRC_ENABLE) ||
			    (rtld_flags & RT_FL_SECURE))
				continue;
			else
				return (0);
		}
		lml_main.lm_flags |= LML_FLG_INTRPOSE;

		/*
		 * If we're tracing shared objects via lddstub, establish a
		 * binding between the initial shared object and lddstub so that
		 * the shared object isn't called out from unused() processing.
		 * After the first object is loaded increment the caller to the
		 * initial preloaded object to provide intuitive ldd -v and -s
		 * diagnostics
		 */
		if ((lmflags & LML_FLG_TRC_ENABLE) &&
		    (FLAGS1(lmp) & FL1_RT_LDDSTUB)) {
			if ((lmp == clmp) && (lmflags &
			    (LML_FLG_TRC_UNREF | LML_FLG_TRC_UNUSED))) {
				if (bind_one(clmp, nlmp, BND_REFER) == 0)
					continue;
			}
			clmp = (Rt_map *)NEXT(lmp);
		}

	} while ((ptr = strtok_r(NULL,
	    MSG_ORIG(MSG_STR_DELIMIT), &next)) != NULL);

	free(objs);
	return (1);
}

Rt_map *
setup(ulong_t envp, ulong_t _auxv, Word _flags, char *_platform, int _syspagsz,
    char *_rt_name, Dyn *dyn_ptr, ulong_t ld_base, ulong_t interp_base, int fd,
    Phdr *phdr, char *_execname, char **_argv, int dz_fd, uid_t uid, uid_t euid,
    gid_t gid, gid_t egid, void *aoutdyn, int auxflags, uint_t hwcap_1)
{
	Rt_map		*rlmp, *mlmp, **tobj = 0;
	ulong_t		etext;
	Ehdr		*ehdr;
	struct stat	status;
	int		features = 0, _name, i, ldsoexec = 0;
	size_t		eaddr, esize;
	char		*c;
	Mmap		*mmaps;

	/*
	 * Now that ld.so has relocated itself, initialize any global variables.
	 * Initialize our own 'environ' so as to establish an address suitable
	 * for libc's hardware mul/div magic (libc/sparc/crt/hwmuldiv.o).
	 */
	_environ = (char **)((ulong_t)_auxv - sizeof (char *));
	_init();
	_environ = (char **)envp;

	at_flags = _flags;
	if (dz_fd != FD_UNAVAIL)
		dz_init(dz_fd);
	platform = _platform;

	/*
	 * If pagesize is unspecified find its value.
	 */
	if ((syspagsz = _syspagsz) == 0)
		syspagsz = _sysconfig(_CONFIG_PAGESIZE);
	fmap_setup();

	/*
	 * Add the unused portion of the last data page to the free space list.
	 * The page size must be set before doing this.  Here, _end refers to
	 * the end of the runtime linkers bss.  Note that we do not use the
	 * unused data pages from any included .so's to supplement this free
	 * space as badly behaved .os's may corrupt this data space, and in so
	 * doing ruin our data.
	 */
	eaddr = S_DROUND((size_t)&_end);
	esize = eaddr % syspagsz;
	if (esize) {
		esize = syspagsz - esize;
		addfree((void *)eaddr, esize);
	}

	/*
	 * Establish initial link-map list flags, and link-map list alists.
	 */
	if (alist_append(&lml_main.lm_lists, 0, sizeof (Lm_cntl),
	    AL_CNT_LMLISTS) == 0)
		return (0);
	lml_main.lm_flags |= LML_FLG_BASELM;

	if (alist_append(&lml_rtld.lm_lists, 0, sizeof (Lm_cntl),
	    AL_CNT_LMLISTS) == 0)
		return (0);
	lml_rtld.lm_flags |= (LML_FLG_RTLDLM | LML_FLG_NOAUDIT |
	    LML_FLG_HOLDLOCK);

	/*
	 * Determine whether we have a secure executable.
	 */
	security(uid, euid, gid, egid, auxflags);

	/*
	 * Initialize a hardware capability descriptor for use in comparing
	 * each loaded object.
	 */
#ifdef	AT_SUN_AUXFLAGS
	if (auxflags & AF_SUN_HWCAPVERIFY) {
		rtld_flags2 |= RT_FL2_HWCAP;
		hwcap = (ulong_t)hwcap_1;
	}
#endif

	/*
	 * Look for environment strings (allows things like LD_NOAUDIT to be
	 * established, although debugging isn't enabled until later).
	 */
	if ((readenv_user((const char **)envp, &(lml_main.lm_flags),
	    &(lml_main.lm_tflags), (aoutdyn != 0))) == 1)
		return (0);

	/*
	 * Create a mapping descriptor for ld.so.1.  We can determine our
	 * two segments information from known symbols.
	 */
	if ((mmaps = calloc(3, sizeof (Mmap))) == 0)
		return (0);
	mmaps[0].m_vaddr = (caddr_t)M_PTRUNC(ld_base);
	mmaps[0].m_msize = (size_t)((caddr_t)&_etext - mmaps[0].m_vaddr);
	mmaps[0].m_fsize = mmaps[0].m_msize;
	mmaps[0].m_perm = (PROT_READ | PROT_EXEC);
	mmaps[1].m_vaddr = (caddr_t)M_PTRUNC((ulong_t)&r_debug);
	mmaps[1].m_msize = (size_t)((caddr_t)&_end - mmaps[1].m_vaddr);
	mmaps[1].m_fsize = (size_t)((caddr_t)&_edata - mmaps[1].m_vaddr);
	mmaps[1].m_perm = (PROT_READ | PROT_WRITE | PROT_EXEC);

	/*
	 * Create a link map structure for ld.so.  We assign the NAME() after
	 * link-map creation to avoid fullpath() processing within elf_new_lm().
	 * This is carried out later when the true interpretor path (as defined
	 * within the application) is known.
	 */
	if ((rlmp = elf_new_lm(&lml_rtld, 0, 0, dyn_ptr, ld_base,
	    (ulong_t)&_etext, ALO_DATA, (ulong_t)(eaddr - ld_base), 0, ld_base,
	    (ulong_t)(eaddr - ld_base), mmaps, 2)) == 0) {
		return (0);
	}
	NAME(rlmp) = _rt_name;
	MODE(rlmp) |= (RTLD_LAZY | RTLD_NODELETE | RTLD_GLOBAL | RTLD_WORLD);
	FLAGS(rlmp) |= (FLG_RT_ANALYZED | FLG_RT_RELOCED | FLG_RT_INITDONE |
		FLG_RT_INITCLCT | FLG_RT_FINICLCT | FLG_RT_MODESET);
	ldso_plt_init(rlmp);

	/*
	 * If we received neither the AT_EXECFD nor the AT_PHDR aux vector,
	 * ld.so.1 must have been invoked directly from the command line.  In
	 * this case examine argv to determine what file to execute.
	 */
	if ((fd == -1) && (!phdr)) {
		/*
		 * Set pr_name now to print error messages if required. It will
		 * be reset below if an executable is found.
		 */
		rt_name = pr_name = _argv[0];
		if (rtld_getopt(_argv, &(lml_main.lm_flags),
		    &(lml_main.lm_tflags), (aoutdyn != 0)) == 1)
			return (0);
		if ((fd = open(_argv[0], O_RDONLY)) == -1) {
			int	err = errno;
			eprintf(ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), _argv[0],
			    strerror(err));
			return (0);
		}
		NAME(rlmp) = _execname;
		interp = &_interp;
		interp->i_name = NAME(rlmp);
		interp->i_faddr = (caddr_t)ADDR(rlmp);
		ldsoexec = 1;
	}

	/*
	 * Duplicate the runtime linkers name so that it is available in a core
	 * file.
	 */
	if ((NAME(rlmp) = strdup(NAME(rlmp))) == 0)
		return (0);

	/*
	 * Get the filename of the rtld for use in any diagnostics (but
	 * save the full name in the link map for future comparisons)
	 */
	rt_name = c = NAME(rlmp);
	while (*c) {
		if (*c++ == '/')
			rt_name = c;
	}

	/*
	 * Establish the applications name.  Note, if ld.so.1 was executed with
	 * the application as its argument, argv[0] will now reflect the
	 * application name.
	 */
	if (_argv[0]) {
		/*
		 * Some troublesome programs will change the value of argv[0].
		 * Dupping this string protects ourselves from such programs.
		 */
		if ((pr_name = (const char *)strdup(_argv[0])) == 0)
			return (0);
	} else
		pr_name = (const char *)MSG_INTL(MSG_STR_UNKNOWN);

	_name = 0;

	/*
	 * Map in the file, if exec has not already done so.  If it has,
	 * simply create a new link map structure for the executable.
	 */
	if (fd != -1) {
		Rej_desc	rej;
		Fct		*ftp;

		/*
		 * Find out what type of object we have.
		 */
		(void) fstat(fd, &status);
		if ((ftp = are_u_this(&rej, fd, &status, pr_name)) == 0) {
			eprintf(ERR_FATAL, MSG_INTL(err_reject[rej.rej_type]),
			    pr_name, conv_reject_str(&rej));
			return (0);
		}

		/*
		 * Map in object.
		 */
		mlmp = (ftp->fct_map_so)(&lml_main, ALO_DATA, 0, pr_name, fd);
		if (mlmp == 0)
			return (0);

		if (ldsoexec) {
			Addr	brkbase = 0;

			/*
			 * Since ld.so.1 was the primary executed object - the
			 * brk() base has not yet been initialized, we need to
			 * initialize it.  For an executable, initialize it to
			 * the end of the object.  For a shared object (ET_DYN)
			 * initialize it to the first page in memory.
			 */
			ehdr = (Ehdr *)ADDR(mlmp);

			if ((FCT(mlmp) == &elf_fct) &&
			    (ehdr->e_type == ET_EXEC)) {
				Phdr *	_phdr = (Phdr *)((uintptr_t)ADDR(mlmp) +
					ehdr->e_phoff);

				/*
				 * We scan the program headers to find the tail
				 * of the memory image.  We can't use MSIZE()
				 * since that's already been page aligned.
				 */
				for (i = 0; i < ehdr->e_phnum; i++, _phdr++) {
					if (_phdr->p_type == PT_LOAD)
						brkbase = _phdr->p_vaddr +
							_phdr->p_memsz;
				}
			}

			if (!brkbase)
				brkbase = syspagsz;

			if (_brk_unlocked((void *)brkbase) == -1) {
				int	err = errno;
				eprintf(ERR_FATAL, MSG_INTL(MSG_SYS_BRK),
				    pr_name, strerror(err));
			}
		}

		/*
		 * Object has now been mmaped in, we no longer
		 * need the file descriptor.
		 */
		(void) close(fd);

	} else {
		/*
		 * Set up function ptr and arguments according to the type
		 * of file class the executable is. (Currently only supported
		 * types are ELF and a.out format.)  Then create a link map
		 * for the executable.
		 */
		if (aoutdyn) {
#ifdef A_OUT
			if ((mlmp = aout_new_lm(&lml_main, 0, 0, aoutdyn, 0, 0,
			    ALO_DATA)) == 0) {
				return (0);
			}

			/*
			 * Set the memory size.  Note, we only know the end of
			 * text, and although we could find the _end by looking
			 * up the symbol, this may not be present.  We should
			 * set ADDR to MAIN_BASE, but presently all the a.out
			 * relocation code assumes ADDR is 0 for the dynamic
			 * executable. (these data items are only used for
			 * dladdr(3x), and there aren't many a.out dladdr(3x)
			 * users to warrant spending much time on this :-).
			 */
			MSIZE(mlmp) = MAIN_BASE + ETEXT(mlmp);

			/*
			 * Disable any object configuration cache (BCP apps
			 * bring in sbcp which can benefit from any object
			 * cache, but both the app and sbcp can't use the same
			 * objects).
			 */
			rtld_flags |= RT_FL_NOOBJALT;

			/*
			 * Make sure no-direct bindings are in effect.
			 */
			lml_main.lm_tflags |= LML_TFLG_NODIRECT;

#else
			eprintf(ERR_FATAL, MSG_INTL(MSG_ERR_REJ_UNKFILE),
			    pr_name);
			return (0);
#endif
		} else if (phdr) {
			Phdr		*pptr, *firstptr = 0, *lastptr;
			Phdr		*tlsphdr = 0;
			Phdr		*unwindphdr = 0;
			Dyn		*dyn = 0;
			Cap		*cap = 0;
			Off		i_offset;
			Addr		base = 0;
			char		*name = 0;
			ulong_t		memsize, phsize, entry;
			uint_t		mmapcnt = 0;

			/*
			 * Using the executables phdr address determine the base
			 * address of the input file.  NOTE, this assumes the
			 * program headers and elf header are part of the same
			 * mapped segment.  Although this has held for many
			 * years now, it might be more flexible if the kernel
			 * gave use the ELF headers start address, rather than
			 * the Program headers.
			 *
			 * Determine from the ELF header if we're been called
			 * from a shared object or dynamic executable.  If the
			 * latter, then any addresses within the object are used
			 * as is.  Addresses within shared objects must be added
			 * to the process's base address.
			 */
			ehdr = (Ehdr *)((Addr)phdr - phdr->p_offset);
			phsize = ehdr->e_phentsize;
			if (ehdr->e_type == ET_DYN) {
				base = (Addr)ehdr;
				name = (char *)pr_name;
				_name = 1;
			}

			/*
			 * Allocate a mapping array to retain mapped segment
			 * information.
			 */
			if ((mmaps = calloc(ehdr->e_phnum, sizeof (Mmap))) == 0)
				return (0);

			/*
			 * Extract the needed information from the segment
			 * headers.
			 */
			for (i = 0, pptr = phdr; i < ehdr->e_phnum; i++) {
				if (pptr->p_type == PT_INTERP) {
					interp = &_interp;
					i_offset = pptr->p_offset;
					interp->i_faddr =
					    (caddr_t)interp_base;
				}
				if ((pptr->p_type == PT_LOAD) &&
				    (pptr->p_filesz || pptr->p_memsz)) {
					int	perm = (PROT_READ | PROT_EXEC);
					size_t	off;

					if (!firstptr)
						firstptr = pptr;
					lastptr = pptr;
					if (!interp->i_name && pptr->p_filesz &&
					    (i_offset >= pptr->p_offset) &&
					    (i_offset <=
					    (pptr->p_memsz + pptr->p_offset))) {
						interp->i_name = (char *)
						    pptr->p_vaddr + i_offset -
						    pptr->p_offset + base;
					}
					if ((pptr->p_flags &
					    (PF_R | PF_W)) == PF_R)
						etext = pptr->p_vaddr +
						    pptr->p_memsz + base;
					else
						perm |= PROT_WRITE;

					/*
					 * Retain segments mapping info.  Round
					 * each segment to a page boundary, as
					 * this insures addresses are suitable
					 * for mprotect() if required.
					 */
					off = pptr->p_vaddr + base;
					mmaps[mmapcnt].m_vaddr =
					    (caddr_t)M_PTRUNC(off);
					off -= (size_t)mmaps[mmapcnt].m_vaddr;
					mmaps[mmapcnt].m_msize =
					    pptr->p_memsz + off;
					mmaps[mmapcnt].m_fsize =
					    pptr->p_filesz + off;
					mmaps[mmapcnt].m_perm = perm;
					mmapcnt++;

				} else if (pptr->p_type == PT_DYNAMIC)
					dyn = (Dyn *)(pptr->p_vaddr + base);
				else if (pptr->p_type == PT_TLS)
					tlsphdr = pptr;
				else if (pptr->p_type == PT_SUNW_UNWIND)
					unwindphdr = pptr;
				else if (pptr->p_type == PT_SUNWCAP)
					cap = (Cap *)(pptr->p_vaddr + base);
				pptr = (Phdr *)((ulong_t)pptr + phsize);
			}


			memsize = (lastptr->p_vaddr + lastptr->p_memsz) -
				S_ALIGN(firstptr->p_vaddr, syspagsz);

			entry = ehdr->e_entry;
			if (ehdr->e_type == ET_DYN)
				entry += (ulong_t)ehdr;

			if ((mlmp = elf_new_lm(&lml_main, name, 0, dyn,
			    (Addr)ehdr, etext, ALO_DATA, memsize, entry,
			    (ulong_t)ehdr, memsize, mmaps, mmapcnt)) == 0) {
				return (0);
			}
			if (tlsphdr) {
				PTTLS(mlmp) = tlsphdr;
				tls_assign_soffset(mlmp);
			}
			if (unwindphdr)
				PTUNWIND(mlmp) = unwindphdr;
			if (cap)
				cap_assign(cap, mlmp);
		}
	}

	/*
	 * Determine whether the kernel has supplied a AT_SUN_EXECNAME aux
	 * vector.  This vector points to the full pathname, on the stack, of
	 * the object that started the process.  If this is null, then
	 * AT_SUN_EXECNAME isn't supported (if the pathname exceeded the system
	 * limit (PATH_MAX) the exec would have failed).
	 */
	if (_execname)
		rtld_flags |= RT_FL_EXECNAME;

	/*
	 * Having mapped the executable in and created its link map, initialize
	 * the name and flags entries as necessary.
	 *
	 * Note that any object that starts the process is identified as `main',
	 * even shared objects.  This assumes that the starting object will call
	 * .init and .fini from its own crt use (this is a pretty valid
	 * assumption as the crts also provide the necessary entry point).
	 * However, newer objects may contain .initarray or .finiarray which
	 * the runtime linker must execute, and which require bindings to be
	 * established to main for proper initarray/finiarray ordering.
	 */
	if (_name == 0) {
		/*
		 * If the argv[0] name is a full path, and an AT_SUN_EXECNAME
		 * exists, and we haven't executed ld.so.1 directly, then use
		 * this name for diagnostics.  Various commands use isaexec(3C)
		 * to execute their 64-bit counterparts, however, the 64-bit
		 * application simply obtains its argv[] from the parent, and
		 * thus will contain the 32-bit application name.
		 */
		if ((*pr_name == '/') && _execname && (ldsoexec == 0))
			pr_name = _execname;
		NAME(mlmp) = (char *)pr_name;
	}

	/*
	 * Setup the PATHNAME()/ORIGNAME() for the main primary object and
	 * for ld.so.1.  If we didn't receive a AT_SUN_EXECNAME or it
	 * was ld.so.1 itself that was executed, then PATHNAME() will be
	 * based off of argv[0].  Otherwise - the PATHNAME is AT_SUN_EXECNAME.
	 */
	if ((ldsoexec) || (_execname == 0))
		PATHNAME(mlmp) = NAME(mlmp);
	else
		PATHNAME(mlmp) = _execname;

	ORIGNAME(mlmp) = PATHNAME(mlmp);

	/*
	 * If the kernel has provided hardware capabilities information, and
	 * the executable contains hardware capabilities information, make
	 * sure it's a valid object.
	 */
	if ((rtld_flags2 & RT_FL2_HWCAP) && HWCAP(mlmp)) {
		ulong_t	mhwcap;

		if ((mhwcap = (HWCAP(mlmp) & ~hwcap)) != 0) {
			if (lml_main.lm_flags & LML_FLG_TRC_ENABLE) {
				(void) printf(MSG_INTL(MSG_LDD_GEN_HWCAP_1),
				    NAME(mlmp),
				    conv_hwcap_1_str(mhwcap, M_MACH));
			} else {
				eprintf(ERR_FATAL, MSG_INTL(MSG_GEN_BADHWCAP_1),
				    conv_hwcap_1_str(mhwcap, M_MACH));
				return (0);
			}
		}
	}

	FLAGS(mlmp) |= (FLG_RT_ISMAIN | FLG_RT_MODESET);
	FLAGS1(mlmp) |= FL1_RT_USED;
	if ((INITARRAY(mlmp) == 0) && (FINIARRAY(mlmp) == 0))
		FLAGS1(mlmp) |= FL1_RT_NOINIFIN;

	/*
	 * Establish the interpretors name as that defined within the initial
	 * object (executable).  This provides for ORIGIN processing of ld.so.1
	 * dependencies.
	 */
	if (interp) {
		size_t	len;
		ORIGNAME(rlmp) = interp->i_name;
		len = strlen(interp->i_name);
		(void) expand(&interp->i_name, &len, 0, 0,
		    (PN_TKN_ISALIST | PN_TKN_HWCAP), mlmp);
		PATHNAME(rlmp) = interp->i_name;
	} else {
		ORIGNAME(rlmp) = PATHNAME(rlmp) = NAME(rlmp);
	}

	/*
	 * Far the most common application execution revolves around appending
	 * the application name to the users PATH definition, thus a full name
	 * is passed to exec() which will in turn be returned via
	 * AT_SUN_EXECNAME.  Applications may also be invoked from the current
	 * working directory, or via a relative name.
	 *
	 * When $ORIGIN was first introduced, the expansion of a relative
	 * pathname was deferred until it was required.  However now we insure
	 * a full pathname is always created - things like the analyzer wish to
	 * rely on librtld_db returning a full path.  The overhead of this is
	 * perceived to be low, providing the associated libc version of getcwd
	 * is available (see 4336878), plus it only affects execing relative
	 * paths.  Here we expand the application and ld.so.1 - see
	 * elf_new_lm() for the expansion of all other dependencies.
	 */
	if (FLAGS1(mlmp) & FL1_RT_RELATIVE)
		(void) fullpath(mlmp, 0);
	if (FLAGS1(rlmp) & FL1_RT_RELATIVE)
		(void) fullpath(rlmp, 0);

	/*
	 * Identify lddstub if necessary.
	 */
	if (lml_main.lm_flags & LML_FLG_TRC_LDDSTUB)
		FLAGS1(mlmp) |= FL1_RT_LDDSTUB;

	(void) enter();

	/*
	 * If no .initarray or .finiarray are present on the executable do not
	 * enter them into the 'sorting' mechanism for .init/.fini firing.
	 *
	 * This is to prevent them showing up during 'ldd -i ...'
	 * output when they don't do anything.
	 */
	if (INITARRAY(mlmp) == 0) {
		FLAGS(mlmp) |= (FLG_RT_INITCLCT | FLG_RT_INITCALL |
		    FLG_RT_INITDONE);
		LIST(mlmp)->lm_init--;
	}

	if (FINIARRAY(mlmp) == 0)
		FLAGS(mlmp) |= FLG_RT_FINICLCT;

	/*
	 * Add our two main link-maps to the dynlm_list
	 */
	if (list_append(&dynlm_list, &lml_main) == 0)
		return (0);

	if (list_append(&dynlm_list, &lml_rtld) == 0)
		return (0);

	/*
	 * Reset the link-map counts for both lists.  The init count is used to
	 * track how many objects have pending init sections, this gets incre-
	 * mented each time an object is relocated.  Since ld.so.1 relocates
	 * itself, it's init count will remain zero.
	 * The object count is used to track how many objects have pending fini
	 * sections, as ld.so.1 handles its own fini we can zero its count.
	 */
	lml_main.lm_obj = 1;
	lml_rtld.lm_obj = 0;

	/*
	 * Initialize debugger information structure.  Some parts of this
	 * structure were initialized statically.
	 */
	r_debug.rtd_rdebug.r_map = (Link_map *)lml_main.lm_head;
	r_debug.rtd_rdebug.r_ldsomap = (Link_map *)lml_rtld.lm_head;
	r_debug.rtd_rdebug.r_ldbase = r_debug.rtd_rdebug.r_ldsomap->l_addr;
	r_debug.rtd_dynlmlst = &dynlm_list;

	if (platform)
		platform_sz = strlen(platform);

	/*
	 * Determine the dev/inode information for the executable to complete
	 * load_so() checking for those who might dlopen(a.out).
	 */
	if ((FLAGS1(mlmp) & FL1_RT_RELATIVE) &&
	    (stat(PATHNAME(mlmp), &status) == 0)) {
		STDEV(mlmp) = status.st_dev;
		STINO(mlmp) = status.st_ino;
	}

	/*
	 * Initialize any configuration information.
	 */
	if (!(rtld_flags & RT_FL_NOCFG)) {
		if ((features = elf_config(mlmp, (aoutdyn != 0))) == -1)
			return (0);
	}

	/*
	 * Establish the modes of the initial object.  These modes are
	 * propagated to any preloaded objects and explicit shared library
	 * dependencies.
	 */
	MODE(mlmp) |= (RTLD_NODELETE | RTLD_GLOBAL | RTLD_WORLD);
	if (rtld_flags & RT_FL_CONFGEN)
		MODE(mlmp) |= RTLD_CONFGEN;
	if (rtld_flags2 & RT_FL2_BINDNOW)
		MODE(mlmp) |= RTLD_NOW;
	else
		MODE(mlmp) |= RTLD_LAZY;

	/*
	 * If debugging was requested initialize things now that any cache has
	 * been established.
	 */
	if (rpl_debug)
		dbg_mask |= dbg_setup(rpl_debug);
	if (prm_debug)
		dbg_mask |= dbg_setup(prm_debug);

	/*
	 * Now that debugging is enabled generate any diagnostics from any
	 * previous events.
	 */
	if (hwcap)
		DBG_CALL(Dbg_cap_hw_1(hwcap, M_MACH));
	if (features)
		DBG_CALL(Dbg_file_config_dis(config->c_name, features));

	if (dbg_mask) {
		DBG_CALL(Dbg_file_ldso(rt_name, (ulong_t)DYN(rlmp),
		    ADDR(rlmp), envp, _auxv));

		if (FCT(mlmp) == &elf_fct) {
			DBG_CALL(Dbg_file_elf(PATHNAME(mlmp),
			    (ulong_t)DYN(mlmp), ADDR(mlmp), MSIZE(mlmp),
			    ENTRY(mlmp), get_linkmap_id(LIST(mlmp)), ALO_DATA));
		} else {
			DBG_CALL(Dbg_file_aout(PATHNAME(mlmp),
			    (ulong_t)AOUTDYN(mlmp), (ulong_t)ADDR(mlmp),
			    (ulong_t)MSIZE(mlmp)));
		}
	}

	/*
	 * Enable auditing.
	 */
	if (rpl_audit || prm_audit || profile_lib) {
		int		ndx;
		const char	*aud[3];

		aud[0] = rpl_audit;
		aud[1] = prm_audit;
		aud[2] = profile_lib;

		/*
		 * Any global auditing (set using LD_AUDIT or LD_PROFILE) that
		 * can't be established is non-fatal.
		 */
		if ((auditors = calloc(1, sizeof (Audit_desc))) == 0)
			return (0);

		for (ndx = 0; ndx < 3; ndx++) {
			if (aud[ndx]) {
				if ((auditors->ad_name = strdup(aud[ndx])) == 0)
					return (0);
				rtld_flags2 |= RT_FL2_FTL2WARN;
				(void) audit_setup(mlmp, auditors);
				rtld_flags2 &= ~RT_FL2_FTL2WARN;
			}
		}
		lml_main.lm_tflags |= auditors->ad_flags;
	}
	if (AUDITORS(mlmp)) {
		/*
		 * Any object required auditing (set with a DT_DEPAUDIT dynamic
		 * entry) that can't be established is fatal.
		 */
		if (audit_setup(mlmp, AUDITORS(mlmp)) == 0)
			return (0);

		FLAGS1(mlmp) |= AUDITORS(mlmp)->ad_flags;
		lml_main.lm_flags |= LML_FLG_LOCAUDIT;
	}

	/*
	 * Explicitly add the initial object and ld.so.1 to those objects being
	 * audited.  Note, although the ld.so.1 link-map isn't auditable,
	 * establish a cookie for ld.so.1 as this may be bound to via the
	 * dl*() family.
	 */
	if ((lml_main.lm_tflags | FLAGS1(mlmp)) & LML_TFLG_AUD_MASK) {
		if (((audit_objopen(mlmp, mlmp) == 0) ||
		    (audit_objopen(mlmp, rlmp) == 0)) &&
		    (FLAGS1(mlmp) & LML_TFLG_AUD_MASK))
			return (0);
	}

	/*
	 * Map in any preloadable shared objects.  Note, it is valid to preload
	 * a 4.x shared object with a 5.0 executable (or visa-versa), as this
	 * functionality is required by ldd(1).
	 */
	if (rpl_preload && (preload(rpl_preload, mlmp) == 0))
		return (0);
	if (prm_preload && (preload(prm_preload, mlmp) == 0))
		return (0);

	/*
	 * Load all dependent (needed) objects.
	 */
	if (analyze_lmc(&lml_main, ALO_DATA, mlmp) == 0)
		return (0);

	/*
	 * Relocate all the dependencies we've just added.
	 *
	 * If this process has been established via crle(1), the environment
	 * variable LD_CONFGEN will have been set.  crle(1) may create this
	 * process twice.  The first time crle only needs to gather dependency
	 * information.  The second time, is to dldump() the images.
	 *
	 * If we're only gathering dependencies, relocation is unnecessary.
	 * As crle(1) may be building an arbitrary family of objects, they may
	 * not fully relocate either.  Hence the relocation phase is not carried
	 * out now, but will be called by crle(1) once all objects have been
	 * loaded.
	 */
	if ((rtld_flags & RT_FL_CONFGEN) == 0) {
		Word	lmflags;

		DBG_CALL(Dbg_file_nl());

		if (relocate_lmc(&lml_main, ALO_DATA, mlmp) == 0)
			return (0);

		/*
		 * Sort the .init sections of all objects we've added.  If
		 * we're tracing we only need to execute this under ldd(1)
		 * with the -i or -u options.
		 */
		lmflags = lml_main.lm_flags;
		if (((lmflags & LML_FLG_TRC_ENABLE) == 0) ||
		    (lmflags & (LML_FLG_TRC_INIT | LML_FLG_TRC_UNREF))) {
			if ((tobj = tsort(mlmp, LIST(mlmp)->lm_init,
			    RT_SORT_REV)) == (Rt_map **)S_ERROR)
				return (0);
		}

		/*
		 * If we are tracing we're done.  This is the one legitimate use
		 * of a direct call to rtldexit() rather than return, as we
		 * don't want to return and jump to the application.
		 */
		if (lmflags & LML_FLG_TRC_ENABLE) {
			unused(&lml_main);
			rtldexit(&lml_main, 0);
		}

		/*
		 * Inform the debuggers we're here and stable.  Newer debuggers
		 * can indicate their presence by setting the DT_DEBUG entry in
		 * the dynamic executable (see elf_new_lm()).  In this case call
		 * getpid() so the debugger can catch the system call.  This
		 * handshake allows the debugger to initialize, and consequently
		 * allows the user to set break points in .init code.
		 */
		rd_event(&lml_rtld, RD_DLACTIVITY, RT_CONSISTENT);
		rd_event(&lml_main, RD_DLACTIVITY, RT_CONSISTENT);

		if (rtld_flags & RT_FL_DEBUGGER) {
			r_debug.rtd_rdebug.r_flags |= RD_FL_ODBG;
			(void) getpid();
		}

		/*
		 * Initialize any initial TLS storage.
		 */
		if (tls_report_modules() == 0)
			return (0);
	}

	/*
	 * Call any necessary auditing routines, clean up any file descriptors
	 * and such, and then fire all dependencies .init sections.
	 */
	rtld_flags |= RT_FL_APPLIC;

	rd_event(&lml_main, RD_PREINIT, 0);

	if ((lml_main.lm_tflags | FLAGS1(mlmp)) & LML_TFLG_AUD_ACTIVITY)
		audit_activity(mlmp, LA_ACT_CONSISTENT);
	if ((lml_main.lm_tflags | FLAGS1(mlmp)) & LML_TFLG_AUD_PREINIT)
		audit_preinit(mlmp);

	call_array(PREINITARRAY(mlmp), (uint_t)PREINITARRAYSZ(mlmp), mlmp,
		SHT_PREINIT_ARRAY);

	if (tobj)
		call_init(tobj, DBG_INIT_SORT);

	rd_event(&lml_main, RD_POSTINIT, 0);

	unused(&lml_main);

	DBG_CALL(Dbg_util_call_main(NAME(mlmp)));

	leave(LIST(mlmp));

	return (mlmp);
}
