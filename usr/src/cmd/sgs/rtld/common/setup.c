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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */
/*
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * Run time linker common setup.
 *
 * Called from _setup to get the process going at startup.
 */

#include	<stdlib.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mman.h>
#include	<string.h>
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
 * Counters that are incremented every time an object is mapped/unmapped.
 *
 * Note that exec() will usually map 2 objects before we receive control,
 * but this can be 1 if ld.so.1 is executed directly. We count one of these
 * here, and add another as necessary in setup().
 */
u_longlong_t	cnt_map = 1;
u_longlong_t	cnt_unmap = 0;


/*
 * Define for the executable's interpreter.
 * Usually it is ld.so.1, but for the first release of ICL binaries
 * it is libc.so.1.  We keep this information so that we don't end
 * up mapping libc twice if it is the interpreter.
 */
static Interp _interp;

/*
 * LD_PRELOAD objects.
 */
static int
preload(const char *str, Rt_map *mlmp, Rt_map **clmp)
{
	Alist		*palp = NULL;
	char		*objs, *ptr, *next;
	Word		lmflags = lml_main.lm_flags;
	int		lddstub;

	DBG_CALL(Dbg_util_nl(&lml_main, DBG_NL_STD));

	if ((objs = strdup(str)) == NULL)
		return (0);

	/*
	 * Determine if we've been called from lddstub.
	 */
	lddstub = (lmflags & LML_FLG_TRC_ENABLE) &&
	    (FLAGS1(*clmp) & FL1_RT_LDDSTUB);


	for (ptr = strtok_r(objs, MSG_ORIG(MSG_STR_DELIMIT), &next);
	    ptr != NULL;
	    ptr = strtok_r(NULL, MSG_ORIG(MSG_STR_DELIMIT), &next)) {
		Rt_map	*nlmp = NULL;
		uint_t	flags;

		DBG_CALL(Dbg_file_preload(&lml_main, ptr));

		/*
		 * Establish the flags for loading each object.  If we're
		 * called via lddstub, then the first preloaded object is the
		 * object being inspected by ldd(1).  This object should not be
		 * marked as an interposer, as this object is intended to act
		 * as the target object of the process.
		 */
		if (lddstub)
			flags = FLG_RT_PRELOAD;
		else
			flags = (FLG_RT_PRELOAD | FLG_RT_OBJINTPO);

		/*
		 * If this a secure application, then preload errors are
		 * reduced to warnings, as the errors are non-fatal.
		 */
		if (rtld_flags & RT_FL_SECURE)
			rtld_flags2 |= RT_FL2_FTL2WARN;
		if (expand_paths(*clmp, ptr, &palp, AL_CNT_NEEDED,
		    PD_FLG_EXTLOAD, 0) != 0)
			nlmp = load_one(&lml_main, ALIST_OFF_DATA, palp, *clmp,
			    MODE(mlmp), flags, 0, NULL);
		remove_alist(&palp, 0);
		if (rtld_flags & RT_FL_SECURE)
			rtld_flags2 &= ~RT_FL2_FTL2WARN;
		if (nlmp && (bind_one(*clmp, nlmp, BND_NEEDED) == 0))
			nlmp = NULL;

		if (lddstub && nlmp) {
			lddstub = 0;

			/*
			 * Fabricate a binding between the target shared object
			 * and lddstub so that the target object isn't called
			 * out from unused() processing.
			 */
			if (lmflags &
			    (LML_FLG_TRC_UNREF | LML_FLG_TRC_UNUSED)) {
				if (bind_one(*clmp, nlmp, BND_REFER) == 0)
					nlmp = NULL;
			}

			/*
			 * By identifying lddstub as the caller, several
			 * confusing ldd() diagnostics get suppressed.  These
			 * diagnostics would reveal how the target shared object
			 * was found from lddstub.  Now that the real target is
			 * loaded, identify the target as the caller so that all
			 * ldd() diagnostics are enabled for subsequent objects.
			 */
			if (nlmp)
				*clmp = nlmp;
		}

		/*
		 * If no error occurred with loading this object, indicate that
		 * this link-map list contains an interposer.
		 */
		if (nlmp == NULL) {
			if ((lmflags & LML_FLG_TRC_ENABLE) ||
			    (rtld_flags & RT_FL_SECURE))
				continue;
			else
				return (0);
		}
		if (flags & FLG_RT_OBJINTPO)
			lml_main.lm_flags |= LML_FLG_INTRPOSE;

	}

	free(palp);
	free(objs);
	return (1);
}

Rt_map *
setup(char **envp, auxv_t *auxv, Word _flags, char *_platform, int _syspagsz,
    char *_rtldname, ulong_t ld_base, ulong_t interp_base, int fd, Phdr *phdr,
    char *execname, char **argv, uid_t uid, uid_t euid, gid_t gid, gid_t egid,
    void *aoutdyn, int auxflags, uint_t *hwcap)
{
	Rt_map			*rlmp, *mlmp, *clmp, **tobj = NULL;
	Ehdr			*ehdr;
	rtld_stat_t		status;
	int			features = 0, ldsoexec = 0;
	size_t			eaddr, esize;
	char			*str, *argvname;
	Word			lmflags;
	mmapobj_result_t	*mpp;
	Fdesc			fdr = { 0 }, fdm = { 0 };
	Rej_desc		rej = { 0 };
	APlist			*ealp = NULL;

	/*
	 * Now that ld.so has relocated itself, initialize our own 'environ' so
	 * as to establish an address suitable for any libc requirements.
	 */
	_environ = (char **)((ulong_t)auxv - sizeof (char *));
	_init();
	_environ = envp;

	/*
	 * Establish a base time.  Total time diagnostics start from entering
	 * ld.so.1 here, however the base time is reset each time the ld.so.1
	 * is re-entered.  Note also, there will be a large time associated
	 * with the first diagnostic from ld.so.1, as bootstrapping ld.so.1
	 * and establishing the liblddbg infrastructure takes some time.
	 */
	(void) gettimeofday(&DBG_TOTALTIME, NULL);
	DBG_DELTATIME = DBG_TOTALTIME;

	/*
	 * Determine how ld.so.1 has been executed.
	 */
	if ((fd == -1) && (phdr == NULL)) {
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
			if ((str = strrchr(argvname, '/')) != NULL)
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
			if ((str = strrchr(_rtldname, '/')) != NULL)
				rtldname = ++str;
			else
				rtldname = _rtldname;
		} else
			rtldname = (char *)MSG_INTL(MSG_STR_UNKNOWN);

		/* exec() brought in two objects for us. Count the second one */
		cnt_map++;
	}

	/*
	 * Initialize any global variables.
	 */
	at_flags = _flags;

	if ((org_scapset->sc_plat = _platform) != NULL)
		org_scapset->sc_platsz = strlen(_platform);

	if (org_scapset->sc_plat == NULL)
		platform_name(org_scapset);
	if (org_scapset->sc_mach == NULL)
		machine_name(org_scapset);

	/*
	 * If pagesize is unspecified find its value.
	 */
	if ((syspagsz = _syspagsz) == 0)
		syspagsz = _sysconfig(_CONFIG_PAGESIZE);

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
	if (alist_append(&lml_main.lm_lists, NULL, sizeof (Lm_cntl),
	    AL_CNT_LMLISTS) == NULL)
		return (0);
	lml_main.lm_flags |= LML_FLG_BASELM;
	lml_main.lm_lmid = LM_ID_BASE;
	lml_main.lm_lmidstr = (char *)MSG_ORIG(MSG_LMID_BASE);

	if (alist_append(&lml_rtld.lm_lists, NULL, sizeof (Lm_cntl),
	    AL_CNT_LMLISTS) == NULL)
		return (0);
	lml_rtld.lm_flags |= (LML_FLG_RTLDLM | LML_FLG_HOLDLOCK);
	lml_rtld.lm_tflags |= LML_TFLG_NOAUDIT;
	lml_rtld.lm_lmid = LM_ID_LDSO;
	lml_rtld.lm_lmidstr = (char *)MSG_ORIG(MSG_LMID_LDSO);

	/*
	 * Determine whether we have a secure executable.
	 */
	security(uid, euid, gid, egid, auxflags);

	/*
	 * Make an initial pass of environment variables to pick off those
	 * related to locale processing.  At the same time, collect and save
	 * any LD_XXXX variables for later processing.  Note that this later
	 * processing will be skipped if ld.so.1 is invoked from the command
	 * line with -e LD_NOENVIRON.
	 */
	if (envp && (readenv_user((const char **)envp, &ealp) == 1))
		return (0);

	/*
	 * If ld.so.1 has been invoked directly, process its arguments.
	 */
	if (ldsoexec) {
		/*
		 * Process any arguments that are specific to ld.so.1, and
		 * reorganize the process stack to effectively remove ld.so.1
		 * from the stack.  Reinitialize the environment pointer, as
		 * this pointer may have been shifted after skipping ld.so.1's
		 * arguments.
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
	 * Having processed any ld.so.1 command line options, return to process
	 * any LD_XXXX environment variables.
	 */
	if (ealp) {
		if (((rtld_flags & RT_FL_NOENVIRON) == 0) &&
		    (procenv_user(ealp, &(lml_main.lm_flags),
		    &(lml_main.lm_tflags), (aoutdyn != 0)) == 1))
			return (0);
		free(ealp);
	}

	/*
	 * Initialize a hardware capability descriptor for use in comparing
	 * each loaded object.  The aux vector must provide AF_SUN_HWCAPVERIFY,
	 * as prior to this setting any hardware capabilities that were found
	 * could not be relied upon.
	 */
	if (auxflags & AF_SUN_HWCAPVERIFY) {
		rtld_flags2 |= RT_FL2_HWCAP;
		org_scapset->sc_hw_1 = (Xword)hwcap[0];
		org_scapset->sc_hw_2 = (Xword)hwcap[1];
	}

	/*
	 * Create a mapping descriptor for ld.so.1.  We can determine our
	 * two segments information from known symbols.
	 */
	if ((mpp = calloc(2, sizeof (mmapobj_result_t))) == NULL)
		return (0);
	mpp[0].mr_addr = (caddr_t)M_PTRUNC(ld_base);
	mpp[0].mr_msize = (caddr_t)&_etext - mpp[0].mr_addr;
	mpp[0].mr_fsize = mpp[0].mr_msize;
	mpp[0].mr_prot = (PROT_READ | PROT_EXEC);

	mpp[1].mr_addr = (caddr_t)M_PTRUNC((uintptr_t)&r_debug);
	mpp[1].mr_msize = (caddr_t)&_end - mpp[1].mr_addr;
	mpp[1].mr_fsize = (caddr_t)&_edata - mpp[1].mr_addr;
	mpp[1].mr_prot = (PROT_READ | PROT_WRITE | PROT_EXEC);

	if ((fdr.fd_nname = stravl_insert(_rtldname, 0, 0, 0)) == NULL)
		return (0);
	if ((rlmp = elf_new_lmp(&lml_rtld, ALIST_OFF_DATA, &fdr,
	    (Addr)mpp->mr_addr, (size_t)((uintptr_t)eaddr - (uintptr_t)ld_base),
	    NULL, NULL, NULL)) == NULL)
		return (0);

	MMAPS(rlmp) = mpp;
	MMAPCNT(rlmp) = 2;
	PADSTART(rlmp) = (ulong_t)mpp[0].mr_addr;
	PADIMLEN(rlmp) = (ulong_t)mpp[0].mr_addr + (ulong_t)mpp[1].mr_addr +
	    (ulong_t)mpp[1].mr_msize;

	MODE(rlmp) |= (RTLD_LAZY | RTLD_NODELETE | RTLD_GLOBAL | RTLD_WORLD);
	FLAGS(rlmp) |= (FLG_RT_ANALYZED | FLG_RT_RELOCED | FLG_RT_INITDONE |
	    FLG_RT_INITCLCT | FLG_RT_FINICLCT | FLG_RT_MODESET);

	/*
	 * Initialize the runtime linkers information.
	 */
	interp = &_interp;
	interp->i_name = (char *)rtldname;
	interp->i_faddr = (caddr_t)ADDR(rlmp);
	ldso_plt_init(rlmp);

	/*
	 * Map in the file, if exec has not already done so, or if the file
	 * was passed as an argument to an explicit execution of ld.so.1 from
	 * the command line.
	 */
	if (fd != -1) {
		/*
		 * Map the file.  Once the object is mapped we no longer need
		 * the file descriptor.
		 */
		(void) rtld_fstat(fd, &status);
		fdm.fd_oname = argvname;
		fdm.fd_ftp = map_obj(&lml_main, &fdm, status.st_size, argvname,
		    fd, &rej);
		(void) close(fd);

		if (fdm.fd_ftp == NULL) {
			Conv_reject_desc_buf_t rej_buf;

			eprintf(&lml_main, ERR_FATAL,
			    MSG_INTL(err_reject[rej.rej_type]), argvname,
			    conv_reject_desc(&rej, &rej_buf, M_MACH));
			return (0);
		}

		/*
		 * Finish processing the loading of the file.
		 */
		if ((fdm.fd_nname = stravl_insert(argvname, 0, 0, 0)) == NULL)
			return (0);
		fdm.fd_dev = status.st_dev;
		fdm.fd_ino = status.st_ino;

		if ((mlmp = load_file(&lml_main, ALIST_OFF_DATA, NULL, &fdm,
		    NULL)) == NULL)
			return (0);

		/*
		 * We now have a process name for error diagnostics.
		 */
		if ((str = strrchr(argvname, '/')) != NULL)
			procname = ++str;
		else
			procname = argvname;

		if (ldsoexec) {
			mmapobj_result_t	*mpp = MMAPS(mlmp);
			uint_t			mnum, mapnum = MMAPCNT(mlmp);
			void			*brkbase = NULL;

			/*
			 * Since ld.so.1 was the primary executed object - the
			 * brk() base has not yet been initialized, we need to
			 * initialize it.  For an executable, initialize it to
			 * the end of the object.  For a shared object (ET_DYN)
			 * initialize it to the first page in memory.
			 */
			for (mnum = 0; mnum < mapnum; mnum++, mpp++)
				brkbase = mpp->mr_addr + mpp->mr_msize;

			if (brkbase == NULL)
				brkbase = (void *)syspagsz;

			if (_brk_unlocked(brkbase) == -1) {
				int	err = errno;

				eprintf(&lml_main, ERR_FATAL,
				    MSG_INTL(MSG_SYS_BRK), argvname,
				    strerror(err));
				return (0);
			}
		}
	} else {
		/*
		 * Set up function ptr and arguments according to the type
		 * of file class the executable is. (Currently only supported
		 * types are ELF and a.out format.)  Then create a link map
		 * for the executable.
		 */
		if (aoutdyn) {
#ifdef A_OUT
			mmapobj_result_t	*mpp;

			/*
			 * Create a mapping structure sufficient to describe
			 * a single two segments.  The ADDR() of the a.out is
			 * established as 0, which is required but the AOUT
			 * relocation code.
			 */
			if ((mpp =
			    calloc(sizeof (mmapobj_result_t), 2)) == NULL)
				return (0);

			if ((fdm.fd_nname =
			    stravl_insert(execname, 0, 0, 0)) == NULL)
				return (0);
			if ((mlmp = aout_new_lmp(&lml_main, ALIST_OFF_DATA,
			    &fdm, 0, 0, aoutdyn, NULL, NULL)) == NULL)
				return (0);

			/*
			 * Establish the true mapping information for the a.out.
			 */
			if (aout_get_mmap(&lml_main, mpp)) {
				free(mpp);
				return (0);
			}

			MSIZE(mlmp) =
			    (size_t)(mpp[1].mr_addr + mpp[1].mr_msize) -
			    S_ALIGN((size_t)mpp[0].mr_addr, syspagsz);
			MMAPS(mlmp) = mpp;
			MMAPCNT(mlmp) = 2;
			PADSTART(mlmp) = (ulong_t)mpp->mr_addr;
			PADIMLEN(mlmp) = mpp->mr_msize;

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
			Phdr			*pptr;
			Off			i_offset = 0;
			Addr			base = 0;
			ulong_t			phsize;
			mmapobj_result_t	*mpp, *fmpp, *hmpp = NULL;
			uint_t			mapnum = 0;
			int			i;
			size_t			msize;

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
			if ((fmpp = mpp = calloc(ehdr->e_phnum,
			    sizeof (mmapobj_result_t))) == NULL)
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

					if (i_offset && pptr->p_filesz &&
					    (i_offset >= pptr->p_offset) &&
					    (i_offset <=
					    (pptr->p_memsz + pptr->p_offset))) {
						interp->i_name = (char *)
						    pptr->p_vaddr + i_offset -
						    pptr->p_offset + base;
						i_offset = 0;
					}

					if (pptr->p_flags & PF_W)
						perm |= PROT_WRITE;

					/*
					 * Retain segments mapping info.  Round
					 * each segment to a page boundary, as
					 * this insures addresses are suitable
					 * for mprotect() if required.
					 */
					off = pptr->p_vaddr + base;
					if (hmpp == NULL) {
						hmpp = mpp;
						mpp->mr_addr = (caddr_t)ehdr;
					} else
						mpp->mr_addr = (caddr_t)off;

					off -= (size_t)(uintptr_t)mpp->mr_addr;
					mpp->mr_msize = pptr->p_memsz + off;
					mpp->mr_fsize = pptr->p_filesz + off;
					mpp->mr_prot = perm;

					mpp++, mapnum++;
				}

				pptr = (Phdr *)((ulong_t)pptr + phsize);
			}

			mpp--;
			msize = (size_t)(mpp->mr_addr + mpp->mr_msize) -
			    S_ALIGN((size_t)fmpp->mr_addr, syspagsz);

			if ((fdm.fd_nname =
			    stravl_insert(execname, 0, 0, 0)) == NULL)
				return (0);
			if ((mlmp = elf_new_lmp(&lml_main, ALIST_OFF_DATA,
			    &fdm, (Addr)hmpp->mr_addr, msize,
			    NULL, NULL, NULL)) == NULL)
				return (0);

			MMAPS(mlmp) = fmpp;
			MMAPCNT(mlmp) = mapnum;
			PADSTART(mlmp) = (ulong_t)fmpp->mr_addr;
			PADIMLEN(mlmp) = (ulong_t)fmpp->mr_addr +
			    (ulong_t)mpp->mr_addr + (ulong_t)mpp->mr_msize;
		}
	}

	/*
	 * Establish the interpretors name as that defined within the initial
	 * object (executable).  This provides for ORIGIN processing of ld.so.1
	 * dependencies.  Note, the NAME() of the object remains that which was
	 * passed to us as the SONAME on execution.
	 */
	if (ldsoexec == 0) {
		size_t	len = strlen(interp->i_name);

		if (expand(&interp->i_name, &len, 0, 0,
		    (PD_TKN_ISALIST | PD_TKN_CAP), rlmp) & PD_TKN_RESOLVED)
			fdr.fd_flags |= FLG_FD_RESOLVED;
	}
	fdr.fd_pname = interp->i_name;
	(void) fullpath(rlmp, &fdr);

	/*
	 * The runtime linker acts as a filtee for various dl*() functions that
	 * are defined in libc (and libdl).  Make sure this standard name for
	 * the runtime linker is also registered in the FullPathNode AVL tree.
	 */
	(void) fpavl_insert(&lml_rtld, rlmp, _rtldname, 0);

	/*
	 * Having established the true runtime linkers name, simplify the name
	 * for error diagnostics.
	 */
	if ((str = strrchr(PATHNAME(rlmp), '/')) != NULL)
		rtldname = ++str;
	else
		rtldname = PATHNAME(rlmp);

	/*
	 * Expand the fullpath name of the application.  This typically occurs
	 * as a part of loading an object, but as the kernel probably mapped
	 * it in, complete this processing now.
	 */
	(void) fullpath(mlmp, 0);

	/*
	 * Some troublesome programs will change the value of argv[0].  Dupping
	 * the process string protects us, and insures the string is left in
	 * any core files.
	 */
	if ((str = (char *)strdup(procname)) == NULL)
		return (0);
	procname = str;

	FLAGS(mlmp) |= (FLG_RT_ISMAIN | FLG_RT_MODESET);
	FLAGS1(mlmp) |= FL1_RT_USED;

	/*
	 * It's the responsibility of MAIN(crt0) to call it's _init and _fini
	 * section, therefore null out any INIT/FINI so that this object isn't
	 * collected during tsort processing.  And, if the application has no
	 * initarray or finiarray we can economize on establishing bindings.
	 */
	INIT(mlmp) = FINI(mlmp) = NULL;
	if ((INITARRAY(mlmp) == NULL) && (FINIARRAY(mlmp) == NULL))
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

	(void) enter(0);

	/*
	 * Add our two main link-maps to the dynlm_list
	 */
	if (aplist_append(&dynlm_list, &lml_main, AL_CNT_DYNLIST) == NULL)
		return (0);

	if (aplist_append(&dynlm_list, &lml_rtld, AL_CNT_DYNLIST) == NULL)
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

	/*
	 * Determine the dev/inode information for the executable to complete
	 * load_so() checking for those who might dlopen(a.out).
	 */
	if (rtld_stat(PATHNAME(mlmp), &status) == 0) {
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
	 * Initialize our toxic paths
	 */
	if (rpl_ldtoxic != NULL) {
		(void) expand_paths(mlmp, rpl_ldtoxic, &rpl_toxdirs,
		    AL_CNT_SEARCH, 0, PD_TKN_CAP);
	}

#if	defined(_ELF64)
	/*
	 * If this is a 64-bit process, determine whether this process has
	 * restricted the process address space to 32-bits.  Any dependencies
	 * that are restricted to a 32-bit address space can only be loaded if
	 * the executable has established this requirement.
	 */
	if (CAPSET(mlmp).sc_sf_1 & SF1_SUNW_ADDR32)
		rtld_flags2 |= RT_FL2_ADDR32;
#endif
	/*
	 * Establish any alternative capabilities, and validate this object
	 * if it defines it's own capabilities information.
	 */
	if (cap_alternative() == 0)
		return (0);

	if (cap_check_lmp(mlmp, &rej) == 0) {
		if (lml_main.lm_flags & LML_FLG_TRC_ENABLE) {
			/* LINTED */
			(void) printf(MSG_INTL(ldd_warn[rej.rej_type]),
			    NAME(mlmp), rej.rej_str);
		} else {
			/* LINTED */
			eprintf(&lml_main, ERR_FATAL,
			    MSG_INTL(err_reject[rej.rej_type]),
			    NAME(mlmp), rej.rej_str);
			return (0);
		}
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
	 *
	 * Ignore any debugging request if we're being monitored by a process
	 * that expects the old getpid() initialization handshake.
	 */
	if ((rpl_debug || prm_debug) && ((rtld_flags & RT_FL_DEBUGGER) == 0)) {
		Dbg_desc	_dbg_desc = {0};
		struct timeval	total = DBG_TOTALTIME;
		struct timeval	delta = DBG_DELTATIME;

		if (rpl_debug) {
			if (dbg_setup(rpl_debug, &_dbg_desc) == 0)
				return (0);
			if (_dbg_desc.d_extra & DBG_E_HELP_EXIT)
				rtldexit(&lml_main, 0);
		}
		if (prm_debug)
			(void) dbg_setup(prm_debug, &_dbg_desc);

		*dbg_desc = _dbg_desc;
		DBG_TOTALTIME = total;
		DBG_DELTATIME = delta;
	}

	/*
	 * Now that debugging is enabled generate any diagnostics from any
	 * previous events.
	 */
	if (DBG_ENABLED) {
		DBG_CALL(Dbg_cap_val(&lml_main, org_scapset, alt_scapset,
		    M_MACH));
		DBG_CALL(Dbg_file_config_dis(&lml_main, config->c_name,
		    features));

		DBG_CALL(Dbg_file_ldso(rlmp, envp, auxv,
		    LIST(rlmp)->lm_lmidstr, ALIST_OFF_DATA));

		if (THIS_IS_ELF(mlmp)) {
			DBG_CALL(Dbg_file_elf(&lml_main, PATHNAME(mlmp),
			    ADDR(mlmp), MSIZE(mlmp), LIST(mlmp)->lm_lmidstr,
			    ALIST_OFF_DATA));
		} else {
			DBG_CALL(Dbg_file_aout(&lml_main, PATHNAME(mlmp),
			    ADDR(mlmp), MSIZE(mlmp), LIST(mlmp)->lm_lmidstr,
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
		if ((auditors = calloc(1, sizeof (Audit_desc))) == NULL)
			return (0);

		for (ndx = 0; ndx < 3; ndx++) {
			if (aud[ndx]) {
				if ((auditors->ad_name =
				    strdup(aud[ndx])) == NULL)
					return (0);
				rtld_flags2 |= RT_FL2_FTL2WARN;
				(void) audit_setup(mlmp, auditors,
				    PD_FLG_EXTLOAD, NULL);
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
			if ((auditors == NULL) && ((auditors = calloc(1,
			    sizeof (Audit_desc))) == NULL))
				return (0);

			auditors->ad_name = AUDITORS(mlmp)->ad_name;
			if (audit_setup(mlmp, auditors, 0, NULL) == 0)
				return (0);
			lml_main.lm_tflags |= auditors->ad_flags;

			/*
			 * Clear the local auditor information.
			 */
			free((void *) AUDITORS(mlmp));
			AUDITORS(mlmp) = NULL;

		} else {
			/*
			 * Establish any local auditing.
			 */
			if (audit_setup(mlmp, AUDITORS(mlmp), 0, NULL) == 0)
				return (0);

			AFLAGS(mlmp) |= AUDITORS(mlmp)->ad_flags;
			lml_main.lm_flags |= LML_FLG_LOCAUDIT;
		}
	}

	/*
	 * Explicitly add the initial object and ld.so.1 to those objects being
	 * audited.  Note, although the ld.so.1 link-map isn't auditable,
	 * establish a cookie for ld.so.1 as this may be bound to via the
	 * dl*() family.
	 */
	if ((lml_main.lm_tflags | AFLAGS(mlmp)) & LML_TFLG_AUD_MASK) {
		if (((audit_objopen(mlmp, mlmp) == 0) ||
		    (audit_objopen(mlmp, rlmp) == 0)) &&
		    (AFLAGS(mlmp) & LML_TFLG_AUD_MASK))
			return (0);
	}

	/*
	 * Map in any preloadable shared objects.  Establish the caller as the
	 * head of the main link-map list.  In the case of being exercised from
	 * lddstub, the caller gets reassigned to the first target shared object
	 * so as to provide intuitive diagnostics from ldd().
	 *
	 * Note, it is valid to preload a 4.x shared object with a 5.0
	 * executable (or visa-versa), as this functionality is required by
	 * ldd(1).
	 */
	clmp = mlmp;
	if (rpl_preload && (preload(rpl_preload, mlmp, &clmp) == 0))
		return (0);
	if (prm_preload && (preload(prm_preload, mlmp, &clmp) == 0))
		return (0);

	/*
	 * Load all dependent (needed) objects.
	 */
	if (analyze_lmc(&lml_main, ALIST_OFF_DATA, mlmp, mlmp, NULL) == NULL)
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
		 * Inform the debuggers that basic process initialization is
		 * complete, and that the state of ld.so.1 (link-map lists,
		 * etc.) is stable.  This handshake enables the debugger to
		 * initialize themselves, and consequently allows the user to
		 * set break points in .init code.
		 *
		 * Most new debuggers use librtld_db to monitor activity events.
		 * Older debuggers indicated their presence by setting the
		 * DT_DEBUG entry in the dynamic executable (see elf_new_lm()).
		 * In this case, getpid() is called so that the debugger can
		 * catch the system call.  This old mechanism has some
		 * restrictions, as getpid() should not be called prior to
		 * basic process initialization being completed.  This
		 * restriction has become increasingly difficult to maintain,
		 * as the use of auditors, LD_DEBUG, and the initialization
		 * handshake with libc can result in "premature" getpid()
		 * calls.  The use of this getpid() handshake is expected to
		 * disappear at some point in the future, and there is intent
		 * to work towards that goal.
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

	if (aud_activity ||
	    ((lml_main.lm_tflags | AFLAGS(mlmp)) & LML_TFLG_AUD_ACTIVITY))
		audit_activity(mlmp, LA_ACT_CONSISTENT);
	if (aud_preinit ||
	    ((lml_main.lm_tflags | AFLAGS(mlmp)) & LML_TFLG_AUD_PREINIT))
		audit_preinit(mlmp);

	/*
	 * If we're creating initial configuration information, we're done
	 * now that the auditing step has been called.
	 */
	if (rtld_flags & RT_FL_CONFGEN) {
		leave(LIST(mlmp), 0);
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

	/*
	 * Check if this instance of the linker should have a primary link
	 * map.  This flag allows multiple copies of the -same- -version-
	 * of the linker (and libc) to run in the same address space.
	 *
	 * Without this flag we only support one copy of the linker in a
	 * process because by default the linker will always try to
	 * initialize at one primary link map  The copy of libc which is
	 * initialized on a primary link map will initialize global TLS
	 * data which can be shared with other copies of libc in the
	 * process.  The problem is that if there is more than one copy
	 * of the linker, only one copy should link libc onto a primary
	 * link map, otherwise libc will attempt to re-initialize global
	 * TLS data.  So when a copy of the linker is loaded with this
	 * flag set, it will not initialize any primary link maps since
	 * presumably another copy of the linker will do this.
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

	rtld_flags |= (RT_FL_OPERATION | RT_FL_APPLIC);

	leave(LIST(mlmp), 0);

	return (mlmp);
}
