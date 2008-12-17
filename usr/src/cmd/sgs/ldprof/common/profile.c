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
 */

/*
 * Routines to provide profiling of shared libraries required by the called
 * executable.
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <synch.h>
#include <signal.h>
#include <synch.h>
#include <link.h>
#include <libintl.h>
#include <sys/param.h>
#include <procfs.h>
#include "msg.h"
#include "sgs.h"
#include "profile.h"
#include "_rtld.h"


static char	Profile[MAXPATHLEN];	/* Profile buffer pathname */
static char	*pname = 0;		/* name of object to profile */
static L_hdr	*Hptr;			/* profile buffer header pointer */
static L_cgarc	*Cptr;			/* profile buffer call graph pointer */
static caddr_t	Hpc, Lpc;		/* Range of addresses being monitored */
static size_t	Fsize;			/* Size of mapped in profile buffer */
uintptr_t	profcookie = 0;

/*
 * When handling mutex's locally we need to mask signals.  The signal
 * mask is for everything except SIGWAITING.
 */
static const sigset_t	iset = { ~0U, ~0U, ~0U, ~0U };

static lwp_mutex_t sharedmutex = SHAREDMUTEX;

static int
prof_mutex_init(lwp_mutex_t *mp)
{
	(void) memcpy(mp, &sharedmutex, sizeof (lwp_mutex_t));
	return (0);
}

static int
prof_mutex_lock(lwp_mutex_t *mp, sigset_t *oset)
{
	if (oset)
		(void) sigprocmask(SIG_BLOCK, &iset, oset);
	(void) _lwp_mutex_lock(mp);
	return (0);
}

static int
prof_mutex_unlock(mutex_t *mp, sigset_t *oset)
{
	(void) _lwp_mutex_unlock(mp);
	if (oset)
		(void) sigprocmask(SIG_SETMASK, oset, NULL);
	return (0);
}

const char *
_ldprof_msg(Msg mid)
{
	return (dgettext(MSG_ORIG(MSG_SUNW_OST_SGS), MSG_ORIG(mid)));
}

/*
 * Determine whether a set (of arbitrary size) is in use - used to analyze proc
 * status information.
 */
static int
setisinuse(uint32_t *sp, uint_t n)
{
	while (n--)
		if (*sp++)
			return (1);
	return (0);
}

#define	prisinuse(sp) \
		setisinuse((uint32_t *)(sp), \
		    (uint_t)(sizeof (*(sp)) / sizeof (uint32_t)))

uint_t
la_version(uint_t version)
{
	int		fd;
	ssize_t		num;
	pstatus_t	status;

	if (version < LAV_CURRENT) {
		(void) fprintf(stderr, MSG_INTL(MSG_GEN_AUDITVERSION),
		    LAV_CURRENT, version);
		return (LAV_CURRENT);
	}

	/*
	 * To reduce the potential for deadlock conditions that can arise from
	 * being monitored (say by truss(1)) while setting a lock in the profile
	 * buffer, determine if someone is monitoring us.  If so silently
	 * disable profiling.
	 */
	if ((fd = open(MSG_ORIG(MSG_FMT_PROCSELF), O_RDONLY)) < 0)
		return (LAV_CURRENT);

	num = read(fd, &status, sizeof (status));
	(void) close(fd);

	if ((num != sizeof (status)) ||
	    prisinuse(&status.pr_sigtrace) || prisinuse(&status.pr_flttrace) ||
	    prisinuse(&status.pr_sysentry) || prisinuse(&status.pr_sysexit)) {
		return (LAV_CURRENT);
	}

	/*
	 * We're presently not being monitored (although there's no control of
	 * someone attaching to us later), so retrieve the profile target name.
	 */
	if (dlinfo((void *)NULL, RTLD_DI_PROFILENAME, &pname) == -1)
		(void) fprintf(stderr,  MSG_INTL(MSG_GEN_PROFNOTSET));

	return (LAV_CURRENT);
}


int
profile_open(const char *fname, Link_map *lmp)
{
	size_t		hsize;		/* struct hdr size */
	size_t		psize;		/* profile histogram size */
	size_t		csize;		/* call graph array size */
	size_t		msize;		/* size of memory being profiled */
	int		i, fd, fixed = 0;
	caddr_t		lpc;
	caddr_t		hpc;
	caddr_t		addr;
	struct stat	status;
	int		new_buffer = 0;
	sigset_t	mask;
	int		err;
	Ehdr *		ehdr;		/* ELF header for file */
	Phdr *		phdr;		/* program headers for file */
	Dyn *		dynp = 0;	/* Dynamic section */
	Word		nsym = 0;	/* no. of symtab ntries */

	if (*Profile == '\0') {
		const char	*dir, *suf;
		char		*tmp;

		/*
		 * From the basename of the specified filename generate the
		 * appropriate profile buffer name.  The profile file is created
		 * if it does not already exist.
		 */
		if (((tmp = strrchr(fname, '/')) != 0) && (*(++tmp)))
			fname = tmp;

#if	defined(_ELF64)
		suf = MSG_ORIG(MSG_SUF_PROFILE_64);
#else
		suf = MSG_ORIG(MSG_SUF_PROFILE);
#endif
		if (dlinfo((void *)NULL, RTLD_DI_PROFILEOUT, &dir) == -1)
			dir = MSG_ORIG(MSG_PTH_VARTMP);

		(void) snprintf(Profile, MAXPATHLEN, MSG_ORIG(MSG_FMT_PROFILE),
		    dir, fname, suf);
	}

	if ((fd = open(Profile, (O_RDWR | O_CREAT), 0666)) == -1) {
		err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN), Profile,
		    strerror(err));
		return (0);
	}

	/*
	 * Now we determine the valid pc range for this object.  The lpc is easy
	 * (lmp->l_addr), to determine the hpc we must examine the Phdrs.
	 */
	lpc = hpc = (caddr_t)lmp->l_addr;
	/* LINTED */
	ehdr = (Ehdr *)lpc;
	if (ehdr->e_phnum == 0) {
		(void) close(fd);
		return (0);
	}
	if (ehdr->e_type == ET_EXEC)
		fixed = 1;
	/* LINTED */
	phdr = (Phdr *)(ehdr->e_phoff + lpc);
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		caddr_t	_hpc;

		if (phdr->p_type == PT_DYNAMIC) {
			dynp = (Dyn *)phdr->p_vaddr;
			if (fixed == 0) {
				dynp = (Dyn *)((unsigned long)dynp +
				    (unsigned long)lpc);
			}
			continue;
		}

		if (phdr->p_type != PT_LOAD)
			continue;

		_hpc = (caddr_t)(phdr->p_vaddr + phdr->p_memsz);
		if (fixed == 0) {
			_hpc = (caddr_t)((unsigned long)_hpc +
			    (unsigned long)lpc);
		}
		if (_hpc > hpc)
			hpc = _hpc;
	}
	if (lpc == hpc) {
		(void) close(fd);
		return (0);
	}

	/*
	 * In order to determine the number of symbols in the object scan the
	 * dynamic section until we find the DT_HASH entry (hash[1] == symcnt).
	 */
	if (dynp) {
		for (; dynp->d_tag != DT_NULL; dynp++) {
			unsigned int	*hashp;

			if (dynp->d_tag != DT_HASH)
				continue;

			hashp = (unsigned int *)dynp->d_un.d_ptr;
			if (fixed == 0) {
				hashp = (unsigned int *)((unsigned long)hashp +
				    (unsigned long)lpc);
			}
			nsym = hashp[1];
			break;
		}
	}

	/*
	 * Determine the (minimum) size of the buffer to allocate
	 */
	Lpc = lpc = (caddr_t)PRF_ROUNDWN((long)lpc, sizeof (long));
	Hpc = hpc = (caddr_t)PRF_ROUNDUP((long)hpc, sizeof (long));

	hsize = sizeof (L_hdr);
	msize = (size_t)(hpc - lpc);
	psize = (size_t)PRF_ROUNDUP((msize / PRF_BARSIZE), sizeof (long));
	csize = (nsym + 1) * PRF_CGINIT * sizeof (L_cgarc);
	Fsize = (hsize + psize + csize);

	/*
	 * If the file size is zero (ie. we just created it), truncate it
	 * to the minimum size.
	 */
	(void) fstat(fd, &status);
	if (status.st_size == 0) {
		if (ftruncate(fd, Fsize) == -1) {
			err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_FTRUNC),
			    Profile, strerror(err));
			(void) close(fd);
			return (0);
		}
		new_buffer++;
	} else
		Fsize = status.st_size;

	/*
	 * Map the file in.
	 */
	if ((addr = (caddr_t)mmap(0, Fsize, (PROT_READ | PROT_WRITE),
	    MAP_SHARED, fd, 0)) == (char *)-1) {
		err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_MMAP), Profile,
		    strerror(err));
		(void) close(fd);
		return (0);
	}
	(void) close(fd);

	/*
	 * Initialize the remaining elements of the header.  All pc addresses
	 * that are recorded are relative to zero thus allowing the recorded
	 * entries to be correlated with the symbols in the original file,
	 * and to compensate for any differences in where the file is mapped.
	 * If the high pc address has been initialized from a previous run,
	 * and the new entry is different from the original then a new library
	 * must have been installed.  In this case bale out.
	 */
	/* LINTED */
	Hptr = (L_hdr *)addr;

	if (new_buffer)
		(void) prof_mutex_init((lwp_mutex_t *)&Hptr->hd_mutex);

	(void) prof_mutex_lock((mutex_t *)&Hptr->hd_mutex, &mask);
	if (Hptr->hd_hpc) {
		if (Hptr->hd_hpc != (caddr_t)(hpc - lpc)) {
			(void) fprintf(stderr, MSG_INTL(MSG_GEN_PROFSZCHG),
			    Profile);
			(void) prof_mutex_unlock((mutex_t *)&Hptr->
			    hd_mutex, &mask);
			(void) munmap((caddr_t)Hptr, Fsize);
			return (0);
		}
	} else {
		/*
		 * Initialize the header information as we must have just
		 * created the output file.
		 */
		Hptr->hd_magic = (unsigned int)PRF_MAGIC;
#if	defined(_ELF64)
		Hptr->hd_version = (unsigned int)PRF_VERSION_64;
#else
		Hptr->hd_version = (unsigned int)PRF_VERSION;
#endif
		Hptr->hd_hpc = (caddr_t)(hpc - lpc);
		/* LINTED */
		Hptr->hd_psize = (unsigned int)psize;
		/* LINTED */
		Hptr->hd_fsize = (unsigned int)Fsize;
		Hptr->hd_ncndx = nsym;
		Hptr->hd_lcndx = (nsym + 1) * PRF_CGINIT;
	}

	(void) prof_mutex_unlock((mutex_t *)&Hptr->hd_mutex, &mask);
	/* LINTED */
	Cptr = (L_cgarc *)(addr + hsize + psize);

	/*
	 * Turn on profiling
	 */
	/* LINTED */
	profil((unsigned short *)(addr + hsize),
	    psize, (unsigned long)lpc, (unsigned int) PRF_SCALE);

	return (1);
}


uint_t
/* ARGSUSED1 */
la_objopen(Link_map *lmp, Lmid_t lmid, uintptr_t *cookie)
{
	char	*objname;

	/*
	 * This would only occur if the getenv() in la_version() failed.
	 * at this point there is nothing for us to do.
	 */
	if (pname == 0)
		return (0);

	/*
	 * Just grab the 'basename' of the object current object for
	 * comparing against the 'profiled object name'
	 */
	if (((objname = strrchr(lmp->l_name, '/')) == 0) ||
	    (*(++objname) == 0))
		objname = lmp->l_name;

	/*
	 * Is this the object we are going to profile.  If not
	 * just set the 'BINDFROM' flag for this object.
	 */
	if ((strcmp(pname, objname) != 0) &&
	    (strcmp(pname, lmp->l_name) != 0))
		return (LA_FLG_BINDFROM);

	/*
	 * Don't even try to profile an object that does not have
	 * auditing enabled on it's link-map.  This catches 'ld.so.1'.
	 */
	if (LIST(LINKMAP_TO_RTMAP(lmp))->lm_flags & LML_FLG_NOAUDIT)
		return (LA_FLG_BINDFROM);

	if (profile_open(pname, lmp) == 0)
		return (0);

	profcookie = *cookie;

	return (LA_FLG_BINDFROM | LA_FLG_BINDTO);
}



uint_t
la_objclose(uintptr_t *cookie)
{
	if (*cookie != profcookie)
		return (0);

	profcookie = 0;
	/*
	 * Turn profil() off.
	 */
	profil(0, 0, 0, 0);
	(void) munmap((caddr_t)Hptr, Fsize);
	return (0);
}


static int
remap_profile(int fd)
{
	caddr_t		addr;
	size_t		l_fsize;

	l_fsize = Hptr->hd_fsize;

	if ((addr = (caddr_t)mmap(0, l_fsize, (PROT_READ | PROT_WRITE),
	    MAP_SHARED, fd, 0)) == (char *)-1) {
		int	err = errno;

		(void) fprintf(stderr, MSG_INTL(MSG_SYS_MMAP), Profile,
		    strerror(err));
		return (0);
	}
	(void) munmap((caddr_t)Hptr, Fsize);

	Fsize = l_fsize;
	/* LINTED */
	Hptr = (L_hdr*) addr;
	/* LINTED */
	Cptr = (L_cgarc *)(addr + sizeof (L_hdr) + Hptr->hd_psize);
	return (1);
}


/*
 * Update a call graph arc entry.  This routine can be called three ways;
 * 	o	On initialization from one of the bndr() functions.
 *		In this case the `to' address is known, and may be used to
 *		initialize the call graph entry if this function has not
 *		been entered before.
 *	o	On initial relocation (ie. LD_BIND_NOW). In this case the `to'
 *		address is known but the `from' isn't.  The call graph entry
 *		is initialized to hold this dummy `to' address, but will be
 *		re-initialized later when a function is first called.
 *	o	From an initialized plt entry.  When profiling, the plt entries
 *		are filled in with the calling functions symbol index and
 *		the plt_cg_elf interface function.  This interface function
 *		calls here to determine the `to' functions address, and in so
 *		doing increments the call count.
 */
uintptr_t
plt_cg_interp(uint_t ndx, caddr_t from, caddr_t to)
{
	L_cgarc *	cptr, cbucket;
	sigset_t	mask;

	/*
	 * If the from address is outside of the address range being profiled,
	 * simply assign it to the `outside' address.
	 */
	if (from != PRF_UNKNOWN) {
		if ((from > Hpc) || (from < Lpc))
			from = PRF_OUTADDR;
		else
			from = (caddr_t)(from - Lpc);
	}

	(void) prof_mutex_lock((mutex_t *)&Hptr->hd_mutex, &mask);
	/*
	 * Has the buffer grown since last we looked at it (another processes
	 * could have grown it...).
	 */
	/* LINTED */
	if (Hptr->hd_fsize != (unsigned int)Fsize) {
		int fd;
		fd = open(Profile, O_RDWR, 0);
		if (remap_profile(fd) == 0) {
			(void) prof_mutex_unlock((mutex_t *)&Hptr->hd_mutex,
			    &mask);
			exit(1);
		}
		(void) close(fd);
	}

	cptr = &Cptr[ndx];

	if (cptr->cg_to == 0) {
		/*
		 * If this is the first time this function has been called we
		 * got here from one of the binders or an initial relocation
		 * (ie. LD_BIND_NOW).  In this case the `to' address is
		 * provided.  Initialize this functions call graph entry with
		 * the functions address (retained as a relative offset).
		 * If we know where the function call originated from
		 * initialize the count field.
		 */
		cptr->cg_to = (caddr_t)(to - Lpc);
		cptr->cg_from = from;
		if (from != PRF_UNKNOWN)
			cptr->cg_count = 1;
	} else {
		/*
		 * If a function has been called from a previous run, but we
		 * don't know where we came from (ie. LD_BIND_NOW), then later
		 * calls through the plt will be able to obtain the required
		 * functions address, thus there is no need to proceed further.
		 */
		if (from != PRF_UNKNOWN) {
			/*
			 * If the from addresses match simply bump the count.
			 * If not scan the link list to find a match for this
			 * `from' address.  If one doesn't exit create a new
			 * entry and link it in.
			 */
			while ((cptr->cg_from != from) &&
			    (cptr->cg_from != PRF_UNKNOWN)) {
				if (cptr->cg_next != 0)
					cptr = &Cptr[cptr->cg_next];
				else {
					to = cptr->cg_to;
					cptr->cg_next = Hptr->hd_ncndx++;
					cptr = &Cptr[cptr->cg_next];
					/*
					 * If we've run out of file, extend it.
					 */
					if (Hptr->hd_ncndx == Hptr->hd_lcndx) {
						caddr_t	addr;
						int	fd;

						/* LINTED */
						Hptr->hd_fsize += (unsigned int)
						    PRF_CGNUMB *
						    sizeof (L_cgarc);
						fd = open(Profile, O_RDWR, 0);
						if (ftruncate(fd,
						    Hptr->hd_fsize) == -1) {
							int	err = errno;

							(void) fprintf(stderr,
							    MSG_INTL(
							    MSG_SYS_FTRUNC),
							    Profile,
							    strerror(err));
							(void) close(fd);
							cptr = &cbucket;
						}
						/*
						 * Since the buffer will be
						 * remapped, we need to be
						 * prepared to adjust cptr.
						 */
						addr = (caddr_t)((Addr)cptr -
						    (Addr)Cptr);
						if (remap_profile(fd) == 0) {
						    /* CSTYLED */
						    (void) prof_mutex_unlock(
							(mutex_t *)&Hptr->
							hd_mutex, &mask);
							exit(1);
						}
						cptr = (L_cgarc *)((Addr)addr +
						    (Addr)Cptr);
						(void) close(fd);
						Hptr->hd_lcndx += PRF_CGNUMB;
					}
					cptr->cg_from = from;
					cptr->cg_to = to;
				}
			}
			/*
			 * If we're updating an entry from an unknown call
			 * address initialize this element, otherwise
			 * increment the call count.
			 */
			if (cptr->cg_from == PRF_UNKNOWN) {
				cptr->cg_from = from;
				cptr->cg_count = 1;
			} else
				cptr->cg_count++;
		}
	}
	/*
	 * Return the real address of the function.
	 */
	(void) prof_mutex_unlock((mutex_t *)&Hptr->hd_mutex, &mask);

	return ((uintptr_t)((Addr)cptr->cg_to + (Addr)Lpc));
}

/* ARGSUSED2 */
#if	defined(__sparcv9)
uintptr_t
la_sparcv9_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_sparcv9_regs *regset, uint_t *sbflags,
	const char *sym_name)
#elif	defined(__sparc)
uintptr_t
la_sparcv8_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_sparcv8_regs *regset, uint_t *sbflags)
#elif	defined(__amd64)
uintptr_t
la_amd64_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_amd64_regs *regset, uint_t *sbflags,
	const char *sym_name)
#elif	defined(__i386)
uintptr_t
la_i86_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_i86_regs *regset, uint_t *sbflags)
#else
#error unexpected architecture!
#endif
{
	caddr_t		from;

	/*
	 * profiling has been disabled.
	 */
	if (profcookie == 0)
		return (symp->st_value);
#if defined(__sparc)
	/*
	 * The callers return address is currently stored in O7 (which
	 * will become I7 when the window shift occurs).
	 */
	from = (caddr_t)regset->lr_rego7;
#elif defined(__amd64)
	/*
	 * The callers return address is on the top of the stack for amd64
	 */
	from = *(caddr_t *)(regset->lr_rsp);
#elif defined(__i386)
	/*
	 * The callers return address is on the top of the stack for i386
	 */
	from = *(caddr_t *)(regset->lr_esp);
#else
#error unexpected architecture!
#endif
	return (plt_cg_interp(symndx, (caddr_t)from, (caddr_t)symp->st_value));
}
