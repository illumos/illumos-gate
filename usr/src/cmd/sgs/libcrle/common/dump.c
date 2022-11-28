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

#include	<sys/mman.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<procfs.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<string.h>
#include	<limits.h>
#include	<errno.h>
#include	<alloca.h>
#include	"rtld.h"
#include	"rtc.h"
#include	"_crle.h"
#include	"msg.h"

/*
 * Routines for dumping alternate objects under CRLE_AUD_DLDUMP mode.
 */
static Addr	membgn = 0;
static Addr	memend = 0;

/*
 * For each file in the configuration file that requires an alternate (dldump())
 * version, add the object to the processes main link-map.  The process head
 * may be an application, shared object, or lddstub.  In any case this object
 * may be augmented with other objects defined within the configuration file.
 *
 * Each file is initially loaded with RTLD_CONFGEN so that no dependency
 * analysis, relocation, or user code (.init's) is executed.  By skipping
 * analysis we save time and allow for a family of objects to be dumped that
 * may not have all relocations satisfied.  If necessary, a later call to
 * dlopen() using RTLD_NOW will force relocations to occur.
 *
 * A mapping range is maintained to span the mapping of each objects, and this
 * range is finally written back to the caller.
 */
static int
/* ARGSUSED1 */
load(const char *opath, const char *npath)
{
	Grp_hdl *	ghp;
	Rt_map *	lmp;
	Addr		_membgn, _memend;

	if ((ghp = (Grp_hdl *)dlmopen(LM_ID_BASE, opath,
	    (RTLD_LAZY | RTLD_GLOBAL | RTLD_CONFGEN))) == NULL) {
		(void) fprintf(stderr, MSG_INTL(MSG_DL_OPEN),
		    MSG_ORIG(MSG_FIL_LIBCRLE), dlerror());
		return (1);
	}
	lmp = ghp->gh_ownlmp;
	FLAGS1(lmp) |= FL1_RT_CONFSET;

	/*
	 * Establish the mapping range of the objects dumped so far.
	 */
	_membgn = ADDR(lmp);
	_memend = (ADDR(lmp) + MSIZE(lmp));

	if (membgn == 0) {
		membgn = _membgn;
		memend = _memend;
	} else {
		if (membgn > _membgn)
			membgn = _membgn;
		if (memend < _memend)
			memend = _memend;
	}
	return (0);
}

/*
 * dldump(3x) an object that is already part of the main link-map list.
 */
static int
dump(const char *opath, const char *npath)
{
	(void) unlink(npath);

	if (dldump(opath, npath, dlflag) != 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_DL_DUMP),
		    MSG_ORIG(MSG_FIL_LIBCRLE), dlerror());
		return (1);
	}
	return (0);
}

/*
 * Traverse a configuration file directory/file list.  Each file within the
 * list is maintained as both a full pathname and a simple filename - we're
 * only interested in one.
 *
 * This rutine is called twice, once to insure the appropriate objects are
 * mapped in (fptr == load()) and then once again to dldump(3x) the mapped
 * objects (fptr == dump()).
 */
static int
scanconfig(Addr addr, int (*fptr)())
{
	Rtc_head *	head = (Rtc_head *)addr;
	Rtc_obj *	obj;
	Rtc_dir *	dirtbl;
	Rtc_file *	filetbl;
	const char	*str, *strtbl;

	/* LINTED */
	strtbl = (const char *)((char *)addr + head->ch_str);

	/*
	 * Scan the directory and filename arrays looking for alternatives.
	 */
	for (dirtbl = (Rtc_dir *)(head->ch_dir + addr);
	    dirtbl->cd_obj; dirtbl++) {

		obj = (Rtc_obj *)(dirtbl->cd_obj + addr);
		str = strtbl + obj->co_name;

		if (obj->co_flags & RTC_OBJ_NOEXIST)
			continue;

		for (filetbl = (Rtc_file *)(dirtbl->cd_file + addr);
		    filetbl->cf_obj; filetbl++) {

			obj = (Rtc_obj *)(filetbl->cf_obj + addr);
			str = strtbl + obj->co_name;

			if ((obj->co_flags &
			    (RTC_OBJ_DUMP | RTC_OBJ_REALPTH | RTC_OBJ_EXEC)) ==
			    (RTC_OBJ_DUMP | RTC_OBJ_REALPTH)) {
				if ((*fptr)(str, strtbl + obj->co_alter) != 0)
					return (1);
			}
		}
	}

	/*
	 * Are we dumping a specific application.
	 */
	if (head->ch_app) {
		if (fptr == load) {
			Grp_hdl *	ghp;

			/*
			 * Obtain a handle to the application and set the
			 * FL1_RT_CONFSET flag.
			 */
			if ((ghp = dlmopen(LM_ID_BASE, 0,
			    (RTLD_NOLOAD | RTLD_CONFGEN))) == 0)
				return (1);
			FLAGS1(ghp->gh_ownlmp) |= FL1_RT_CONFSET;

		} else {
			/*
			 * If we're dumping and this configuration is for a
			 * specific application dump it also.
			 */
			/* LINTED */
			obj = (Rtc_obj *)((char *)addr + head->ch_app);
			str = strtbl + obj->co_alter;

			if (dump((const char *)0, str) != 0)
				return (1);
		}
	}

	return (0);
}

/*
 * Before loading any dependencies determine the present memory mappings being
 * used and fill any holes between these mappings.  This insures that all
 * dldump()'ed dependencies will live in a single consecutive address range.
 */
int
filladdr(void)
{
	prmap_t		*maps, *_maps;
	struct stat	status;
	int		fd = 0, err, num, _num;
	size_t		size, syspagsz;
	uintptr_t	laddr = 0, saddr;
	pstatus_t	prstatus;

	/*
	 * Open /proc/self/status to determine the virtual address of the
	 * process heap.
	 */
	if ((fd = open(MSG_ORIG(MSG_PTH_PROCSTATUS), O_RDONLY)) == -1) {
		err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
		    MSG_ORIG(MSG_FIL_LIBCRLE), MSG_ORIG(MSG_PTH_PROCSTATUS),
		    strerror(err));
		return (1);
	}
	if (read(fd, &prstatus, sizeof (pstatus_t)) != sizeof (pstatus_t)) {
		err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_READ),
		    MSG_ORIG(MSG_FIL_LIBCRLE), MSG_ORIG(MSG_PTH_PROCSTATUS),
		    strerror(err));
		(void) close(fd);
		return (1);
	}
	(void) close(fd);

	/*
	 * Round the process heap to the next page boundary so that it can be
	 * used to isolated the executable's mappings (pr_brkbase typically
	 * occurs at the end, but within, the executable's data segment).  As
	 * libcrle is used as an audit library, no process user code has run
	 * so there can't be any heap. pr_brksize is added here for
	 * completeness.
	 */
	syspagsz = sysconf(_SC_PAGESIZE);
	saddr = M_PROUND(prstatus.pr_brkbase + prstatus.pr_brksize);

	/*
	 * Open /proc/self/rmap to obtain the processes reserved mappings.
	 */
	if ((fd = open(MSG_ORIG(MSG_PTH_PROCRMAP), O_RDONLY)) == -1) {
		err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
		    MSG_ORIG(MSG_FIL_LIBCRLE), MSG_ORIG(MSG_PTH_PROCRMAP),
		    strerror(err));
		return (1);
	}
	(void) fstat(fd, &status);

	/*
	 * Determine number of mappings - use alloca so as not to perturb any
	 * mapping information by a malloc, which itself might add a mapping.
	 */
	/* LINTED */
	num = (int)(status.st_size / sizeof (prmap_t));
	size = num * sizeof (prmap_t);

	if ((maps = alloca(size)) == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_ALLOC),
		    MSG_ORIG(MSG_FIL_LIBCRLE), strerror(ENOMEM));
		(void) close(pfd);
		return (1);
	}

	if (read(fd, (void *)maps, size) < 0) {
		err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_READ),
		    MSG_ORIG(MSG_FIL_LIBCRLE), MSG_ORIG(MSG_PTH_PROCRMAP),
		    strerror(err));
		(void) close(fd);
		return (1);
	}
	(void) close(fd);

	/*
	 * Use /dev/null for filling holes.
	 */
	if ((fd = open(MSG_ORIG(MSG_PTH_DEVNULL), O_RDONLY)) == -1) {
		err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
		    MSG_ORIG(MSG_FIL_LIBCRLE), MSG_ORIG(MSG_PTH_DEVNULL),
		    strerror(err));
		return (1);
	}

	/*
	 * Scan each mapping - note it is assummed that the mappings are
	 * presented in order.  We fill holes between mappings.  On intel
	 * the last mapping is usually the data segment of ld.so.1, after
	 * this comes a red zone into which non-fixed mapping won't get
	 * place.  Thus we can simply bail from the loop after seeing the
	 * last mapping.
	 */
	for (_num = 0, _maps = maps; _num < num; _num++, _maps++) {
		/*
		 * Skip all mappings below brkbase, these represent the
		 * executable (and the stack on intel).
		 */
		if ((laddr == 0) &&
		    ((_maps->pr_vaddr + _maps->pr_size) <= saddr))
			continue;

		/*
		 * For each consecutive mapping determine the hole between each
		 * and fill it from /dev/null.
		 */
		if (laddr == 0) {
			laddr = _maps->pr_vaddr + _maps->pr_size;
			continue;
		}

		if ((size = _maps->pr_vaddr - laddr) != 0) {
			if (mmap((void *)laddr, size, PROT_NONE,
			    (MAP_FIXED | MAP_PRIVATE), fd, 0) == MAP_FAILED) {
				err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_SYS_MMAP),
				    MSG_ORIG(MSG_FIL_LIBCRLE),
				    MSG_ORIG(MSG_PTH_DEVNULL), strerror(err));
				return (1);
			}
		}
		laddr = _maps->pr_vaddr + _maps->pr_size;
	}

	/*
	 * It's been observed that there may be space between the end of the
	 * last mapping (typically ld.so.1), and the kernel base address.  As
	 * there's no interface to determine the kernel base address, keep
	 * filling in pages until we get an error.  We'll get ENOMEM once we
	 * hit the kernel base address.
	 */
	while (laddr) {
		if (mmap((void *)laddr, syspagsz, PROT_NONE,
		    (MAP_FIXED | MAP_PRIVATE), fd, 0) == MAP_FAILED) {
			err = errno;
			if (err == ENOMEM)
				break;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_MMAP),
			    MSG_ORIG(MSG_FIL_LIBCRLE),
			    MSG_ORIG(MSG_PTH_DEVNULL), strerror(err));
			return (1);
		}
		laddr += syspagsz;
	}

	/*
	 * Close /dev/null.
	 */
	(void) close(fd);
	return (0);
}

/*
 * Dump alternative objects as part of building a configuration file.  A temp
 * configuration is already built and made available to the process, and is
 * located via dlinfo().  Having load()'ed each object, and dump()'ed its image,
 * the final memory reservation infoamtion is returned to the caller.
 */
int
dumpconfig(void)
{
	char		buffer[PATH_MAX];
	Addr		config;
	Dl_info		info;

	/*
	 * Determine the configuration file and where it is mapped.
	 */
	if (dlinfo((void *)NULL, RTLD_DI_CONFIGADDR, &info) == -1) {
		(void) fprintf(stderr, MSG_INTL(MSG_DL_INFO),
		    MSG_ORIG(MSG_FIL_LIBCRLE), dlerror());
		return (1);
	}
	config = (Addr)info.dli_fbase;

	/*
	 * Scan the configuration file for alternative entries.
	 */
	if (scanconfig(config, load) != 0)
		return (1);

	/*
	 * Having mapped all objects, relocate them.  It would be nice if we
	 * could drop this step altogether, and have dldump() carry out just
	 * those relocations required, but when binding to an application we
	 * need to handle copy relocations - these can affect bindings (in the
	 * case of things like libld.so which have direct bindings) and require
	 * that the data being copied is itself relocated.
	 */
	if (dlmopen(LM_ID_BASE, 0, (RTLD_NOW | RTLD_CONFGEN)) == 0)
		return (1);

	/*
	 * Rescan the configuration dumping out each alternative file.
	 */
	if (scanconfig(config, dump) != 0)
		return (1);

	/*
	 * Having established the memory range of the dumped images and
	 * sucessfully dumped them out, report back to the caller.
	 */
	(void) sprintf(buffer, MSG_ORIG(MSG_AUD_RESBGN), EC_ADDR(membgn));
	(void) write(pfd, buffer, strlen(buffer));

	(void) sprintf(buffer, MSG_ORIG(MSG_AUD_RESEND), EC_ADDR(memend));
	(void) write(pfd, buffer, strlen(buffer));

	return (0);
}
