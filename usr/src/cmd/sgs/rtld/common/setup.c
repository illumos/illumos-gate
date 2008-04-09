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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"_a.out.h"
#include	"msg.h"


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

	DBG_CALL(Dbg_util_nl(&lml_main, DBG_NL_STD));

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
		flags = (FLG_RT_PRELOAD | FLG_RT_OBJINTPO);

	ptr = strtok_r(objs, MSG_ORIG(MSG_STR_DELIMIT), &next);
	do {
		Pnode	*pnp;
		Rt_map	*nlmp = 0;

		DBG_CALL(Dbg_file_preload(&lml_main, ptr));

		/*
		 * If this a secure application, then preload errors are
		 * reduced to warnings, as the errors are non-fatal.
		 */
		if (rtld_flags & RT_FL_SECURE)
			rtld_flags2 |= RT_FL2_FTL2WARN;
		if ((pnp = expand_paths(clmp, ptr, PN_FLG_EXTLOAD, 0)) != 0)
			nlmp = load_one(&lml_main, ALIST_OFF_DATA, pnp, clmp,
			    MODE(lmp), flags, 0, NULL);
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
		flags |= FLG_RT_OBJINTPO;
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
setup(char **envp, auxv_t *auxv, Word _flags, char *_platform, int _syspagsz,
    char *_rtldname, Dyn *dyn_ptr, ulong_t ld_base, ulong_t interp_base, int fd,
    Phdr *phdr, char *execname, char **argv, int dz_fd, uid_t uid,
    uid_t euid, gid_t gid, gid_t egid, void *aoutdyn, int auxflags,
    uint_t hwcap_1)
{
	Rt_map		*rlmp, *mlmp, **tobj = 0;
	Ehdr		*ehdr;
	struct stat	status;
	int		features = 0, ldsoexec = 0;
	size_t		eaddr, esize;
	char		*str, *argvname;
	Mmap		*mmaps;
	Word		lmflags;

	/*
	 * Now that ld.so has relocated itself, initialize our own 'environ' so
	 * as to establish an address suitable for libc's hardware mul/div
	 * magic (libc/sparc/crt/hwmuldiv.o).
	 */
	_environ = (char **)((ulong_t)auxv - sizeof (char *));
	_init();
	_environ = envp;

	/*
	 * Far the most common application execution revolves around appending
	 * the application name to the users PATH definition, thus a full name
	 * is passed to exec() which will in turn be returned via
	 * AT_SUN_EXECNAME.  Applications may also be invoked from the current
	 * working directory, or via a relative name.
	 *
	 * Determine whether the kernel has supplied a AT_SUN_EXECNAME aux
	 * vector.  This vector points to the full pathname, on the stack, of
	 * the object that started the process.  If this is null, then
	 * AT_SUN_EXECNAME isn't supported (if the pathname exceeded the system
	 * limit (PATH_MAX) the exec would have failed).  This flag is used to
	 * determine whether we can call resolvepath().
	 */
	if (execname)
		rtld_flags |= RT_FL_EXECNAME;

	/*
	 * Determine how ld.so.1 has been executed.
	 */
	if ((fd == -1) && (phdr == 0)) {
		/*
		 * If we received neither the AT_EXECFD nor the AT_PHDR aux
		 * vector, ld.so.1 must have been invoked directly from the
		 * command line.
		 */
		ldsoexec = 1;

		/*
		 * AT_SUN_EXECNAME provides the most precise name, if it is
		 * available, otherwise fall back to argv[0].  At this time,
		 * there is no process name.
		 */
		if (execname)
			rtldname = execname;
		else if (argv[0])
			rtldname = argv[0];
		else
			rtldname = (char *)MSG_INTL(MSG_STR_UNKNOWN);
	} else {
		/*
		 * Otherwise, we have a standard process.  AT_SUN_EXECNAME
		 * provides the most precise name, if it is available,
		 * otherwise fall back to argv[0].  Provided the application
		 * is already mapped, the process is the application, so
		 * simplify the application name for use in any diagnostics.
		 */
		if (execname)
			argvname = execname;
		else if (argv[0])
			argvname = execname = argv[0];
		else
			argvname = execname = (char *)MSG_INTL(MSG_STR_UNKNOWN);

		if (fd == -1) {
			if ((str = strrchr(argvname, '/')) != 0)
				procname = ++str;
			else
				procname = argvname;
		}

		/*
		 * At this point, we don't know the runtime linkers full path
		 * name.  The _rtldname passed to us is the SONAME of the
		 * runtime linker, which is typically /lib/ld.so.1 no matter
		 * what the full path is.   Use this for now, we'll reset the
		 * runtime linkers name once the application is analyzed.
		 */
		if (_rtldname) {
			if ((str = strrchr(_rtldname, '/')) != 0)
				rtldname = ++str;
			else
				rtldname = _rtldname;
		} else
			rtldname = (char *)MSG_INTL(MSG_STR_UNKNOWN);
	}

	/*
	 * Initialize any global variables.
	 */
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
	lml_main.lm_lmid = LM_ID_BASE;
	lml_main.lm_lmidstr = (char *)MSG_ORIG(MSG_LMID_BASE);

	if (alist_append(&lml_rtld.lm_lists, 0, sizeof (Lm_cntl),
	    AL_CNT_LMLISTS) == 0)
		return (0);
	lml_rtld.lm_flags |= (LML_FLG_RTLDLM | LML_FLG_NOAUDIT |
	    LML_FLG_HOLDLOCK);
	lml_rtld.lm_lmid = LM_ID_LDSO;
	lml_rtld.lm_lmidstr = (char *)MSG_ORIG(MSG_LMID_LDSO);

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
	 * Create a link map structure for ld.so.1.
	 */
	if ((rlmp = elf_new_lm(&lml_rtld, _rtldname, rtldname, dyn_ptr, ld_base,
	    (ulong_t)&_etext, ALIST_OFF_DATA, (ulong_t)(eaddr - ld_base), 0,
	    ld_base, (ulong_t)(eaddr - ld_base), mmaps, 2, NULL)) == 0) {
		return (0);
	}

	MODE(rlmp) |= (RTLD_LAZY | RTLD_NODELETE | RTLD_GLOBAL | RTLD_WORLD);
	FLAGS(rlmp) |= (FLG_RT_ANALYZED | FLG_RT_RELOCED | FLG_RT_INITDONE |
	    FLG_RT_INITCLCT | FLG_RT_FINICLCT | FLG_RT_MODESET);

	/*
	 * Initialize the runtime linkers information.
	 */
	interp = &_interp;
	interp->i_name = NAME(rlmp);
	interp->i_faddr = (caddr_t)ADDR(rlmp);
	ldso_plt_init(rlmp);

	/*
	 * If ld.so.1 has been invoked directly, process its arguments.
	 */
	if (ldsoexec) {
		/*
		 * Process any arguments that are specific to ld.so.1, and
		 * reorganize the process stack to effectively remove ld.so.1
		 * from it.  Reinitialize the environment pointer, as this may
		 * have been shifted after skipping ld.so.1's arguments.
		 */
		if (rtld_getopt(argv, &envp, &auxv, &(lml_main.lm_flags),
		    &(lml_main.lm_tflags), (aoutdyn != 0)) == 1) {
			eprintf(&lml_main, ERR_NONE, MSG_INTL(MSG_USG_BADOPT));
			return (0);
		}
		_environ = envp;

		/*
		 * Open the object that ld.so.1 is to execute.
		 */
		argvname = execname = argv[0];

		if ((fd = open(argvname, O_RDONLY)) == -1) {
			int	err = errno;
			eprintf(&lml_main, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN),
			    argvname, strerror(err));
			return (0);
		}
	}

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
		if ((ftp = are_u_this(&rej, fd, &status, argvname)) == 0) {
			Conv_reject_desc_buf_t rej_buf;

			eprintf(&lml_main, ERR_FATAL,
			    MSG_INTL(err_reject[rej.rej_type]), argvname,
			    conv_reject_desc(&rej, &rej_buf, M_MACH));
			return (0);
		}

		/*
		 * Map in object.
		 */
		if ((mlmp = (ftp->fct_map_so)(&lml_main, ALIST_OFF_DATA,
		    execname, argvname, fd, NULL)) == 0)
			return (0);

		/*
		 * We now have a process name for error diagnostics.
		 */
		if ((str = strrchr(argvname, '/')) != 0)
			procname = ++str;
		else
			procname = argvname;

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
				int	i;
				Phdr *_phdr = (Phdr *)((uintptr_t)ADDR(mlmp) +
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
				eprintf(&lml_main, ERR_FATAL,
				    MSG_INTL(MSG_SYS_BRK), argvname,
				    strerror(err));
			}
		}

		/*
		 * The object has now been mmaped, we no longer need the file
		 * descriptor.
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
			if ((mlmp = aout_new_lm(&lml_main, execname, argvname,
			    aoutdyn, 0, 0, ALIST_OFF_DATA)) == 0)
				return (0);

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
			eprintf(&lml_main, ERR_FATAL,
			    MSG_INTL(MSG_ERR_REJ_UNKFILE), argvname);
			return (0);
#endif
		} else if (phdr) {
			Phdr		*pptr, *firstptr = 0, *lastptr;
			Phdr		*tlsphdr = 0, *unwindphdr = 0;
			Dyn		*dyn = 0;
			Cap		*cap = 0;
			Off		i_offset = 0;
			Addr		base = 0;
			ulong_t		memsize, phsize, entry, etext;
			uint_t		mmapcnt = 0;
			int		i;

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
			if (ehdr->e_type == ET_DYN)
				base = (Addr)ehdr;

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
					if (i_offset && pptr->p_filesz &&
					    (i_offset >= pptr->p_offset) &&
					    (i_offset <=
					    (pptr->p_memsz + pptr->p_offset))) {
						interp->i_name = (char *)
						    pptr->p_vaddr + i_offset -
						    pptr->p_offset + base;
						i_offset = 0;
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

				} else if (pptr->p_type == PT_DYNAMIC) {
					dyn = (Dyn *)(pptr->p_vaddr + base);
				} else if ((pptr->p_type == PT_TLS) &&
				    pptr->p_memsz) {
					tlsphdr = pptr;
				} else if (pptr->p_type == PT_SUNW_UNWIND) {
					unwindphdr = pptr;
				} else if (pptr->p_type == PT_SUNWCAP) {
					cap = (Cap *)(pptr->p_vaddr + base);
				}
				pptr = (Phdr *)((ulong_t)pptr + phsize);
			}


			memsize = (lastptr->p_vaddr + lastptr->p_memsz) -
			    S_ALIGN(firstptr->p_vaddr, syspagsz);

			entry = ehdr->e_entry;
			if (ehdr->e_type == ET_DYN)
				entry += (ulong_t)ehdr;

			if ((mlmp = elf_new_lm(&lml_main, execname, argvname,
			    dyn, (Addr)ehdr, etext, ALIST_OFF_DATA, memsize,
			    entry, (ulong_t)ehdr, memsize, mmaps,
			    mmapcnt, NULL)) == 0) {
				return (0);
			}
			if (tlsphdr &&
			    (tls_assign(&lml_main, mlmp, tlsphdr) == 0))
				return (0);

			if (unwindphdr)
				PTUNWIND(mlmp) = unwindphdr;

			if (cap)
				cap_assign(cap, mlmp);
		}
	}

	/*
	 * Establish the interpretors name as that defined within the initial
	 * object (executable).  This provides for ORIGIN processing of ld.so.1
	 * dependencies.
	 */
	if (ldsoexec == 0) {
		size_t	len = strlen(interp->i_name);
		(void) expand(&interp->i_name, &len, 0, 0,
		    (PN_TKN_ISALIST | PN_TKN_HWCAP), rlmp);
	}
	PATHNAME(rlmp) = interp->i_name;

	if (FLAGS1(rlmp) & FL1_RT_RELATIVE)
		(void) fullpath(rlmp, 0);
	else
		ORIGNAME(rlmp) = PATHNAME(rlmp) = NAME(rlmp);

	/*
	 * Having established the true runtime linkers name, simplify the name
	 * for error diagnostics.
	 */
	if ((str = strrchr(PATHNAME(rlmp), '/')) != 0)
		rtldname = ++str;
	else
		rtldname = PATHNAME(rlmp);

	/*
	 * Expand the fullpath name of the application.  This typically occurs
	 * as a part of loading an object, but as the kernel probably mapped
	 * it in, complete this processing now.
	 */
	if (FLAGS1(mlmp) & FL1_RT_RELATIVE)
		(void) fullpath(mlmp, 0);

	/*
	 * Some troublesome programs will change the value of argv[0].  Dupping
	 * the process string protects us, and insures the string is left in
	 * any core files.
	 */
	if ((str = (char *)strdup(procname)) == 0)
		return (0);
	procname = str;

	/*
	 * If the kernel has provided hardware capabilities information, and
	 * the executable contains hardware capabilities information, make
	 * sure it's a valid object.
	 */
	if ((rtld_flags2 & RT_FL2_HWCAP) && HWCAP(mlmp)) {
		ulong_t	mhwcap;

		if ((mhwcap = (HWCAP(mlmp) & ~hwcap)) != 0) {
			Conv_cap_val_hw1_buf_t cap_val_hw1_buf;

			const char *str =
			    conv_cap_val_hw1(mhwcap, M_MACH, 0,
			    &cap_val_hw1_buf);

			if (lml_main.lm_flags & LML_FLG_TRC_ENABLE) {
				(void) printf(MSG_INTL(MSG_LDD_GEN_HWCAP_1),
				    NAME(mlmp), str);
			} else {
				eprintf(&lml_main, ERR_FATAL,
				    MSG_INTL(MSG_GEN_BADHWCAP_1), str);
				return (0);
			}
		}
	}

	FLAGS(mlmp) |= (FLG_RT_ISMAIN | FLG_RT_MODESET);
	FLAGS1(mlmp) |= FL1_RT_USED;

	/*
	 * It's the responsibility of MAIN(crt0) to call it's _init and _fini
	 * section, therefore null out any INIT/FINI so that this object isn't
	 * collected during tsort processing.  And, if the application has no
	 * initarray or finiarray we can economize on establishing bindings.
	 */
	INIT(mlmp) = FINI(mlmp) = 0;
	if ((INITARRAY(mlmp) == 0) && (FINIARRAY(mlmp) == 0))
		FLAGS1(mlmp) |= FL1_RT_NOINIFIN;

	/*
	 * Identify lddstub if necessary.
	 */
	if (lml_main.lm_flags & LML_FLG_TRC_LDDSTUB)
		FLAGS1(mlmp) |= FL1_RT_LDDSTUB;

	/*
	 * Retain our argument information for use in dlinfo.
	 */
	argsinfo.dla_argv = argv--;
	argsinfo.dla_argc = (long)*argv;
	argsinfo.dla_envp = envp;
	argsinfo.dla_auxv = auxv;

	(void) enter();

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
	 *
	 * If we're generating a configuration file using crle(1), remove
	 * any RTLD_NOW use, as we don't want to trigger any relocation proc-
	 * essing during crle(1)'s first past (this would just be unnecessary
	 * overhead).  Any filters are explicitly loaded, and thus RTLD_NOW is
	 * not required to trigger filter loading.
	 *
	 * Note, RTLD_NOW may have been established during analysis of the
	 * application had the application been built -z now.
	 */
	MODE(mlmp) |= (RTLD_NODELETE | RTLD_GLOBAL | RTLD_WORLD);

	if (rtld_flags & RT_FL_CONFGEN) {
		MODE(mlmp) |= RTLD_CONFGEN;
		MODE(mlmp) &= ~RTLD_NOW;
		rtld_flags2 &= ~RT_FL2_BINDNOW;
	}

	if ((MODE(mlmp) & RTLD_NOW) == 0) {
		if (rtld_flags2 & RT_FL2_BINDNOW)
			MODE(mlmp) |= RTLD_NOW;
		else
			MODE(mlmp) |= RTLD_LAZY;
	}

	/*
	 * If debugging was requested initialize things now that any cache has
	 * been established.  A user can specify LD_DEBUG=help to discover the
	 * list of debugging tokens available without running the application.
	 * However, don't allow this setting from a configuration file.
	 *
	 * Note, to prevent recursion issues caused by loading and binding the
	 * debugging libraries themselves, a local debugging descriptor is
	 * initialized.  Once the debugging setup has completed, this local
	 * descriptor is copied to the global descriptor which effectively
	 * enables diagnostic output.
	 */
	if (rpl_debug || prm_debug) {
		Dbg_desc	_dbg_desc = {0, 0, 0};

		if (rpl_debug) {
			uintptr_t	ret;

			if ((ret = dbg_setup(rpl_debug, &_dbg_desc)) == S_ERROR)
				return (0);
			if (ret == 0)
				rtldexit(&lml_main, 0);
		}
		if (prm_debug)
			(void) dbg_setup(prm_debug, &_dbg_desc);

		*dbg_desc = _dbg_desc;
	}

	/*
	 * Now that debugging is enabled generate any diagnostics from any
	 * previous events.
	 */
	if (hwcap)
		DBG_CALL(Dbg_cap_val_hw1(&lml_main, hwcap, M_MACH));
	if (features)
		DBG_CALL(Dbg_file_config_dis(&lml_main, config->c_name,
		    features));

	if (DBG_ENABLED) {
		DBG_CALL(Dbg_file_ldso(rlmp, envp, auxv,
		    LIST(rlmp)->lm_lmidstr, ALIST_OFF_DATA));

		if (FCT(mlmp) == &elf_fct) {
			DBG_CALL(Dbg_file_elf(&lml_main, PATHNAME(mlmp),
			    (ulong_t)DYN(mlmp), ADDR(mlmp), MSIZE(mlmp),
			    ENTRY(mlmp), LIST(mlmp)->lm_lmidstr,
			    ALIST_OFF_DATA));
		} else {
			DBG_CALL(Dbg_file_aout(&lml_main, PATHNAME(mlmp),
			    (ulong_t)AOUTDYN(mlmp), (ulong_t)ADDR(mlmp),
			    (ulong_t)MSIZE(mlmp), LIST(mlmp)->lm_lmidstr,
			    ALIST_OFF_DATA));
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
				(void) audit_setup(mlmp, auditors,
				    PN_FLG_EXTLOAD, NULL);
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
		if (FLAGS1(mlmp) & FL1_RT_GLOBAUD) {
			/*
			 * If this object requires global auditing, use the
			 * local auditing information to set the global
			 * auditing descriptor.  The effect is that a
			 * DT_DEPAUDIT act as an LD_AUDIT.
			 */
			if ((auditors == 0) &&
			    ((auditors = calloc(1, sizeof (Audit_desc))) == 0))
				return (0);

			auditors->ad_name = AUDITORS(mlmp)->ad_name;
			if (audit_setup(mlmp, auditors, 0, NULL) == 0)
				return (0);
			lml_main.lm_tflags |= auditors->ad_flags;

			/*
			 * Clear the local auditor information.
			 */
			free((void *) AUDITORS(mlmp));
			AUDITORS(mlmp) = 0;

		} else {
			/*
			 * Establish any local auditing.
			 */
			if (audit_setup(mlmp, AUDITORS(mlmp), 0, NULL) == 0)
				return (0);

			FLAGS1(mlmp) |= AUDITORS(mlmp)->ad_flags;
			lml_main.lm_flags |= LML_FLG_LOCAUDIT;
		}
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
	if (analyze_lmc(&lml_main, ALIST_OFF_DATA, mlmp, NULL) == 0)
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

		DBG_CALL(Dbg_util_nl(&lml_main, DBG_NL_STD));

		if (relocate_lmc(&lml_main, ALIST_OFF_DATA, mlmp,
		    mlmp, NULL) == 0)
			return (0);

		/*
		 * Inform the debuggers we're here and stable.  Newer debuggers
		 * can indicate their presence by setting the DT_DEBUG entry in
		 * the dynamic executable (see elf_new_lm()).  In this case call
		 * getpid() so the debugger can catch the system call.  This
		 * handshake allows the debugger to initialize, and consequently
		 * allows the user to set break points in .init code.
		 */
		rd_event(&lml_main, RD_DLACTIVITY, RT_CONSISTENT);
		rd_event(&lml_rtld, RD_DLACTIVITY, RT_CONSISTENT);

		if (rtld_flags & RT_FL_DEBUGGER) {
			r_debug.rtd_rdebug.r_flags |= RD_FL_ODBG;
			(void) getpid();
		}
	}

	/*
	 * Indicate preinit activity, and call any auditing routines.  These
	 * routines are called before initializing any threads via libc, or
	 * before collecting the complete set of .inits on the primary link-map.
	 * Although most libc interfaces are encapsulated in local routines
	 * within libc, they have been known to escape (ie. call a .plt).  As
	 * the appcert auditor uses preinit as a trigger to establish some
	 * external interfaces to the main link-maps libc, we need to activate
	 * this trigger before exercising any code within libc.  Additionally,
	 * I wouldn't put it past an auditor to add additional objects to the
	 * primary link-map.  Hence, we collect .inits after the audit call.
	 */
	rd_event(&lml_main, RD_PREINIT, 0);

	if ((lml_main.lm_tflags | FLAGS1(mlmp)) & LML_TFLG_AUD_ACTIVITY)
		audit_activity(mlmp, LA_ACT_CONSISTENT);
	if ((lml_main.lm_tflags | FLAGS1(mlmp)) & LML_TFLG_AUD_PREINIT)
		audit_preinit(mlmp);

	/*
	 * If we're creating initial configuration information, we're done
	 * now that the auditing step has been called.
	 */
	if (rtld_flags & RT_FL_CONFGEN) {
		leave(LIST(mlmp));
		return (mlmp);
	}

	/*
	 * Sort the .init sections of all objects we've added.  If we're
	 * tracing we only need to execute this under ldd(1) with the -i or -u
	 * options.
	 */
	lmflags = lml_main.lm_flags;
	if (((lmflags & LML_FLG_TRC_ENABLE) == 0) ||
	    (lmflags & (LML_FLG_TRC_INIT | LML_FLG_TRC_UNREF))) {
		if ((tobj = tsort(mlmp, LIST(mlmp)->lm_init,
		    RT_SORT_REV)) == (Rt_map **)S_ERROR)
			return (0);
	}

	/*
	 * If we are tracing we're done.  This is the one legitimate use of a
	 * direct call to rtldexit() rather than return, as we don't want to
	 * return and jump to the application.
	 */
	if (lmflags & LML_FLG_TRC_ENABLE) {
		unused(&lml_main);
		rtldexit(&lml_main, 0);
	}

#ifdef	AT_SUN_AUXFLAGS
	/*
	 * Check if this instance of the linker should have a primary link
	 * map.  This flag allows multiple copies of the -same- -version-
	 * of the linker (and libc) to run in the same address space.
	 *
	 * Without this flag we only support one copy of the linker in a
	 * process because by default the linker will always try to
	 * initialize at one primary link map  The copy of libc which is
	 * initialized on a primary link map will initalize global TLS
	 * data which can be shared with other copies of libc in the
	 * process.  The problem is that if there is more than one copy
	 * of the linker, only one copy should link libc onto a primary
	 * link map, otherwise libc will attempt to re-initialize global
	 * TLS data.  So when a copy of the linker is loaded with this
	 * flag set, it will not initialize any primary link maps since
	 * persumably another copy of the linker will do this.
	 *
	 * Note that this flag only allows multiple copies of the -same-
	 * -version- of the linker (and libc) to coexist.  This approach
	 * will not work if we are trying to load different versions of
	 * the linker and libc into the same process.  The reason for
	 * this is that the format of the global TLS data may not be
	 * the same for different versions of libc.  In this case each
	 * different version of libc must have it's own primary link map
	 * and be able to maintain it's own TLS data.  The only way this
	 * can be done is by carefully managing TLS pointers on transitions
	 * between code associated with each of the different linkers.
	 * Note that this is actually what is done for processes in lx
	 * branded zones.  Although in the lx branded zone case, the
	 * other linker and libc are actually gld and glibc.  But the
	 * same general TLS management mechanism used by the lx brand
	 * would apply to any attempts to run multiple versions of the
	 * solaris linker and libc in a single process.
	 */
	if (auxflags & AF_SUN_NOPLM)
		rtld_flags2 |= RT_FL2_NOPLM;
#endif
	/*
	 * Establish any static TLS for this primary link-map.  Note, regardless
	 * of whether TLS is available, an initial handshake occurs with libc to
	 * indicate we're processing the primary link-map.  Having identified
	 * the primary link-map, initialize threads.
	 */
	if (rt_get_extern(&lml_main, mlmp) == 0)
		return (0);

	if ((rtld_flags2 & RT_FL2_NOPLM) == 0) {
		if (tls_statmod(&lml_main, mlmp) == 0)
			return (0);
		rt_thr_init(&lml_main);
		rtld_flags2 |= RT_FL2_PLMSETUP;
	} else {
		rt_thr_init(&lml_main);
	}

	rtld_flags |= RT_FL_APPLIC;

	/*
	 * Fire all dependencies .init sections.  Identify any unused
	 * dependencies, and leave the runtime linker - effectively calling
	 * the dynamic executables entry point.
	 */
	call_array(PREINITARRAY(mlmp), (uint_t)PREINITARRAYSZ(mlmp), mlmp,
	    SHT_PREINIT_ARRAY);

	if (tobj)
		call_init(tobj, DBG_INIT_SORT);

	rd_event(&lml_main, RD_POSTINIT, 0);

	unused(&lml_main);

	DBG_CALL(Dbg_util_call_main(mlmp));

	rtld_flags |= RT_FL_OPERATION;
	leave(LIST(mlmp));

	return (mlmp);
}
