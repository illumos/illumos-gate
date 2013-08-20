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
 *
 * dldump(3c) creates a new file image from the specified input file.
 */

#include	<sys/param.h>
#include	<sys/procfs.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<libelf.h>
#include	<link.h>
#include	<dlfcn.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>
#include	"libld.h"
#include	"msg.h"
#include	"_librtld.h"

/*
 * Generic clean up routine
 */
static void
cleanup(Elf *ielf, Elf *oelf, Elf *melf, Cache *icache, Cache *mcache,
    int fd, const char *opath)
{
	if (icache) {
		Cache *	_icache = icache;

		for (++_icache; _icache->c_flags != FLG_C_END; _icache++) {
			if (_icache->c_info)
				(void) free(_icache->c_info);
		}
		(void) free((void *)icache);
	}
	if (mcache)
		(void) free((void *)mcache);

	if (ielf)
		(void) elf_end(ielf);
	if (oelf)
		(void) elf_end(oelf);
	if (melf)
		(void) elf_end(melf);
	if (fd)
		(void) close(fd);
	if (opath)
		(void) unlink(opath);
}

/*
 * The dldump(3x) interface directs control to the runtime linker.  The runtime
 * linker brings in librtld.so.1 to provide the underlying support for this
 * call (this is because librtld.so.1 requires libelf.so.1, and the whole wad
 * is rather expensive to drag around with ld.so.1).
 *
 * rt_dldump(Rt_map * lmp, const char * opath, int flags, Addr addr)
 *
 * lmp provides the link-map of the ipath (the input file).
 *
 * opath specifies the output file.
 *
 * flags provides a variety of options that control how the new image will be
 * relocated (if required).
 *
 * addr indicates the base address at which the associated input image is mapped
 * within the process.
 *
 * The modes of operation and the various flags provide a number of combinations
 * of images that can be created, some are useful, some maybe not.  The
 * following provide a couple of basic models for dldump(3x) use:
 *
 *  new executable -	dldump(0, outfile, RTLD_MEMORY)
 *
 *			A dynamic executable may undergo some initialization
 *			and the results of this saved in a new file for later
 *			execution.  The executable will presumable update
 *			parts of its data segment and heap (note that the heap
 *			should be acquired using malloc() so that it follows
 *			the end of the data segment for this technique to be
 *			useful).  These updated memory elements are saved to the
 *			new file, including a new .SUNW_heap section if
 *			required.
 *
 *			For greatest flexibility, no relocated information
 *			should be saved (by default any relocated information is
 *			returned to the value it had in its original file).
 *			This allows the new image to bind to new dynamic objects
 *			when executed on the same or newer upgrades of the OS.
 *
 *			Fixing relocations by applying RTLD_REL_ALL will bind
 *			the image to the dependencies presently mapped as part
 *			of the process.  Thus the new executable will only work
 *			correctly when these same dependencies map to exactly
 *			to the same locations. (note that RTLD_REL_RELATIVE will
 *			have no effect as dynamic executables commonly don't
 *			contain any relative relocations).
 *
 *  new shared object -	dldump(infile, outfile, RTLD_REL_RELATIVE)
 *
 *			A shared object can be fixed to a known address so as
 *			to reduce its relocation overhead on startup.  Because
 *			the new file is fixed to a new base address (which is
 *			the address at which the object was found mapped to the
 *			process) it is now a dynamic executable.
 *
 *			Data changes that have occurred due to the object
 *			gaining control (at the least this would be .init
 *			processing) will not be carried over to the new image.
 *
 *			By only performing relative relocations all global
 *			relocations are available for unique binding to each
 *			process - thus interposition etc. is still available.
 *
 *			Using RTLD_REL_ALL will fix all relocations in the new
 *			file, which will certainly provide for faster startup
 *			of the new image, but at the loss of interposition
 *			flexibility.
 */
int
rt_dldump(Rt_map *lmp, const char *opath, int flags, Addr addr)
{
	Elf *		ielf = 0, *oelf = 0, *melf = 0;
	Ehdr		*iehdr, *oehdr, *mehdr;
	Phdr		*iphdr, *ophdr, *data_phdr = 0;
	Cache		*icache = 0, *_icache, *mcache = 0, *_mcache;
	Cache		*data_cache = 0, *dyn_cache = 0;
	Xword		rel_null_no = 0, rel_data_no = 0, rel_func_no = 0;
	Xword		rel_entsize;
	Rel		*rel_base = 0, *rel_null, *rel_data, *rel_func;
	Elf_Scn		*scn;
	Shdr		*shdr;
	Elf_Data	*data;
	Half		endx = 1;
	int		fd = 0, err, num;
	size_t		shstr_size = 1, shndx;
	Addr		edata;
	char		*shstr, *_shstr, *ipath = NAME(lmp);
	prstatus_t	*status = 0, _status;
	Lm_list		*lml = LIST(lmp);
	Alist		*nodirect = 0;

	if (lmp == lml_main.lm_head) {
		char	proc[16];
		int	pfd;

		/*
		 * Get a /proc descriptor.
		 */
		(void) snprintf(proc, 16, MSG_ORIG(MSG_FMT_PROC),
		    (int)getpid());
		if ((pfd = open(proc, O_RDONLY)) == -1) {
			err = errno;
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), proc,
			    strerror(err));
			return (1);
		}

		/*
		 * If we've been asked to process the dynamic executable we
		 * might not know its full path (this is prior to realpath()
		 * processing becoming default), and thus use /proc to obtain a
		 * file descriptor of the input file.
		 */
		if ((fd = ioctl(pfd, PIOCOPENM, (void *)0)) == -1) {
			err = errno;
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_PROC), ipath,
			    strerror(err));
			(void) close(pfd);
			return (1);
		}

		/*
		 * Obtain the process's status structure from which we can
		 * determine the size of the process's heap.  Note, if the
		 * application is using mapmalloc then the heap size is going
		 * to be zero, and if we're dumping a data section that makes
		 * reference to the malloc'ed area we're not going to get a
		 * useful image.
		 */
		if (!(flags & RTLD_NOHEAP)) {
			if (ioctl(pfd, PIOCSTATUS, (void *)&_status) == -1) {
				err = errno;
				eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_PROC),
				    ipath, strerror(err));
				(void) close(fd);
				(void) close(pfd);
				return (1);
			}
			if ((flags & RTLD_MEMORY) && _status.pr_brksize)
				status = &_status;
		}
		(void) close(pfd);
	} else {
		/*
		 * Open the specified file.
		 */
		if ((fd = open(ipath, O_RDONLY, 0)) == -1) {
			err = errno;
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), ipath,
			    strerror(err));
			return (1);
		}
	}

	/*
	 * Initialize with the ELF library and make sure this is a suitable
	 * ELF file we're dealing with.
	 */
	(void) elf_version(EV_CURRENT);
	if ((ielf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_BEGIN), ipath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, 0);
		return (1);
	}
	(void) close(fd);

	if ((elf_kind(ielf) != ELF_K_ELF) ||
	    ((iehdr = elf_getehdr(ielf)) == NULL) ||
	    ((iehdr->e_type != ET_EXEC) && (iehdr->e_type != ET_DYN))) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_IMG_ELF), ipath);
		cleanup(ielf, oelf, melf, icache, mcache, 0, 0);
		return (1);
	}

	/*
	 * Make sure we can create the new output file.
	 */
	if ((fd = open(opath, (O_RDWR | O_CREAT | O_TRUNC), 0777)) == -1) {
		err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), opath,
		    strerror(err));
		cleanup(ielf, oelf, melf, icache, mcache, 0, 0);
		return (1);
	}
	if ((oelf = elf_begin(fd, ELF_C_WRITE, NULL)) == NULL) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_BEGIN), opath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}

	/*
	 * Obtain the input program headers.  Remember the last data segments
	 * program header entry as this will be updated later to reflect any new
	 * heap section size.
	 */
	if ((iphdr = elf_getphdr(ielf)) == NULL) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETPHDR), ipath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}

	for (num = 0, ophdr = iphdr; num != iehdr->e_phnum; num++, ophdr++) {
		/*
		 * Save the program header that contains the NOBITS section, or
		 * the last loadable program header if no NOBITS exists.  A
		 * NOBITS section translates to a memory size requirement that
		 * is greater than the file data it is mapped from.  Note that
		 * we inspect all headers just incase there only exist text
		 * segments.
		 */
		if (ophdr->p_type == PT_LOAD) {
			if (ophdr->p_filesz != ophdr->p_memsz)
				data_phdr = ophdr;
			else if (data_phdr) {
				if (data_phdr->p_vaddr < ophdr->p_vaddr)
					data_phdr = ophdr;
			} else
				data_phdr = ophdr;
		}
	}

	/*
	 * If there is no data segment, and a heap section is required,
	 * warn the user and disable the heap addition (Note that you can't
	 * simply append the heap to the last segment, as it might be a text
	 * segment, and would therefore have the wrong permissions).
	 */
	if (status && !data_phdr) {
		eprintf(lml, ERR_WARNING, MSG_INTL(MSG_IMG_DATASEG), ipath);
		status = 0;
	}

	/*
	 * Obtain the input files section header string table.
	 */

	if (elf_getshdrstrndx(ielf, &shndx) == -1) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETSHDRSTRNDX), ipath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	if ((scn = elf_getscn(ielf, shndx)) == NULL) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETSCN), ipath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	if ((data = elf_getdata(scn, NULL)) == NULL) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETDATA), ipath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	shstr = (char *)data->d_buf;

	/*
	 * Construct a cache to maintain the input files section information.
	 * Obtain an extra cache element if a heap addition is required.  Also
	 * add an additional entry (marked FLG_C_END) to make the processing of
	 * this cache easier.
	 */

	if (elf_getshdrnum(ielf, &shndx) == -1) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETSHDRNUM), opath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}

	num = shndx;

	if (status)
		num++;
	if ((icache = calloc(num + 1, sizeof (Cache))) == 0) {
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	icache[num].c_flags = FLG_C_END;

	_icache = icache;
	_icache++;

	/*
	 * Traverse each section from the input file collecting the appropriate
	 * ELF information.  Indicate how the section will be processed to
	 * generate the output image.
	 */
	for (scn = 0; scn = elf_nextscn(ielf, scn); _icache++) {

		if ((_icache->c_shdr = shdr = elf_getshdr(scn)) == NULL) {
			eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETSHDR), ipath);
			cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
			return (1);
		}

		if ((_icache->c_data = elf_getdata(scn, NULL)) == NULL) {
			eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETDATA), ipath);
			cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
			return (1);
		}
		_icache->c_name = shstr + (size_t)(shdr->sh_name);
		_icache->c_scn = scn;
		_icache->c_flags = 0;
		_icache->c_info = 0;

		/*
		 * Process any .SUNW_syminfo section.  Symbols that are tagged
		 * as NO_DIRECT are collected, as they should not be bound to.
		 */
		if ((flags & ~RTLD_REL_RELATIVE) &&
		    (shdr->sh_type == SHT_SUNW_syminfo)) {
			if (syminfo(_icache, &nodirect)) {
				cleanup(ielf, oelf, melf, icache, mcache,
				    fd, opath);
				return (1);
			}
		}

		/*
		 * If the section has no address it is not part of the mapped
		 * image, and is unlikely to require any further processing.
		 * The section header string table will be rewritten (this isn't
		 * always necessary, it's only really required when relocation
		 * sections are renamed or sections are stripped, but we do
		 * things the same way regardless).
		 */
		if (shdr->sh_addr == 0) {
			if ((shdr->sh_type == SHT_STRTAB) &&
			    ((strcmp(_icache->c_name,
			    MSG_ORIG(MSG_SCN_SHSTR))) == 0))
				_icache->c_flags = FLG_C_SHSTR;
			else if (flags & RTLD_STRIP) {
				_icache->c_flags = FLG_C_EXCLUDE;
				continue;
			}
		}

		/*
		 * Skip relocation sections for the time being, they'll be
		 * analyzed after all sections have been processed.
		 */
		if ((shdr->sh_type == M_REL_SHT_TYPE) && shdr->sh_addr)
			continue;

		/*
		 * Sections at this point will simply be passed through to the
		 * output file.  Keep track of the section header string table
		 * size.
		 */
		shstr_size += strlen(_icache->c_name) + 1;

		/*
		 * If a heap section is to be added to the output image,
		 * indicate that it will be added following the last data
		 * section.
		 */
		if (shdr->sh_addr && ((shdr->sh_addr + shdr->sh_size) ==
		    (data_phdr->p_vaddr + data_phdr->p_memsz))) {
			data_cache = _icache;

			if (status) {
				_icache++;
				_icache->c_name =
				    (char *)MSG_ORIG(MSG_SCN_HEAP);
				_icache->c_flags = FLG_C_HEAP;

				_icache->c_scn = 0;
				_icache->c_shdr = 0;
				_icache->c_data = 0;
				_icache->c_info = 0;

				shstr_size += strlen(_icache->c_name) + 1;
			}
		}
	}

	/*
	 * Now that we've processed all input sections count the relocation
	 * entries (relocation sections need to reference their symbol tables).
	 */
	_icache = icache;
	for (_icache++; _icache->c_flags != FLG_C_END; _icache++) {

		if ((shdr = _icache->c_shdr) == 0)
			continue;

		/*
		 * If any form of relocations are to be applied to the output
		 * image determine what relocation counts exist.  These will be
		 * used to reorganize (localize) the relocation records.
		 */
		if ((shdr->sh_type == M_REL_SHT_TYPE) && shdr->sh_addr) {
			rel_entsize = shdr->sh_entsize;

			if (count_reloc(icache, _icache, lmp, flags, addr,
			    &rel_null_no, &rel_data_no, &rel_func_no,
			    nodirect)) {
				cleanup(ielf, oelf, melf, icache, mcache,
				    fd, opath);
				return (1);
			}
		}
	}

	/*
	 * If any form of relocations are to be applied to the output image
	 * then we will reorganize (localize) the relocation records.  If this
	 * reorganization occurs, the relocation sections will no longer have a
	 * one-to-one relationship with the section they relocate, hence we
	 * rename them to a more generic name.
	 */
	_icache = icache;
	for (_icache++; _icache->c_flags != FLG_C_END; _icache++) {

		if ((shdr = _icache->c_shdr) == 0)
			continue;

		if ((shdr->sh_type == M_REL_SHT_TYPE) && shdr->sh_addr) {
			if (rel_null_no) {
				_icache->c_flags = FLG_C_RELOC;
				_icache->c_name =
				    (char *)MSG_ORIG(MSG_SCN_RELOC);
			}
			shstr_size += strlen(_icache->c_name) + 1;
		}
	}


	/*
	 * If there is no data section, and a heap is required, warn the user
	 * and disable the heap addition.
	 */
	if (!data_cache) {
		eprintf(lml, ERR_WARNING, MSG_INTL(MSG_IMG_DATASEC), ipath);
		status = 0;
		endx = 0;
	}

	/*
	 * Determine the value of _edata (which will also be _end) and its
	 * section index for updating the data segments phdr and symbol table
	 * information later.  If a new heap section is being added, update
	 * the values appropriately.
	 */
	edata = data_phdr->p_vaddr + data_phdr->p_memsz;
	if (status)
		edata += status->pr_brksize;

	if (endx) {
		/* LINTED */
		endx = (Half)elf_ndxscn(data_cache->c_scn);
		if (status)
			endx++;
	}

	/*
	 * We're now ready to construct the new elf image.
	 *
	 * Obtain a new elf header and initialize it with any basic information
	 * that isn't calculated as part of elf_update().
	 */
	if ((oehdr = elf_newehdr(oelf)) == NULL) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_NEWEHDR), opath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	oehdr->e_machine = iehdr->e_machine;
	oehdr->e_flags = iehdr->e_flags;
	oehdr->e_type = ET_EXEC;
	oehdr->e_entry = iehdr->e_entry;
	if (addr)
		oehdr->e_entry += addr;

	/*
	 * Obtain a new set of program headers.  Initialize these with the same
	 * information as the input program headers.  Update the virtual address
	 * and the data segments size to reflect any new heap section.
	 */
	if ((ophdr = elf_newphdr(oelf, iehdr->e_phnum)) == NULL) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_NEWPHDR), opath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	for (num = 0; num != iehdr->e_phnum; num++, iphdr++, ophdr++) {
		*ophdr = *iphdr;
		if ((ophdr->p_type != PT_INTERP) && (ophdr->p_type != PT_NOTE))
			ophdr->p_vaddr += addr;
		if (data_phdr == iphdr) {
			if (status)
				ophdr->p_memsz = edata - ophdr->p_vaddr;
			ophdr->p_filesz = ophdr->p_memsz;
		}
	}

	/*
	 * Establish a buffer for the new section header string table.  This
	 * will be filled in as each new section is created.
	 */
	if ((shstr = malloc(shstr_size)) == 0) {
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	_shstr = shstr;
	*_shstr++ = '\0';

	/*
	 * Use the input files cache information to generate new sections.
	 */
	_icache = icache;
	for (_icache++; _icache->c_flags != FLG_C_END; _icache++) {
		/*
		 * Skip any excluded sections.
		 */
		if (_icache->c_flags == FLG_C_EXCLUDE)
			continue;

		/*
		 * Create a matching section header in the output file.
		 */
		if ((scn = elf_newscn(oelf)) == NULL) {
			eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_NEWSCN), opath);
			cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
			return (1);
		}
		if ((shdr = elf_getshdr(scn)) == NULL) {
			eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_NEWSHDR), opath);
			cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
			return (1);
		}

		/*
		 * If this is the heap section initialize the appropriate
		 * entries, otherwise simply use the original section header
		 * information.
		 */
		if (_icache->c_flags == FLG_C_HEAP) {
			shdr->sh_type = SHT_PROGBITS;
			shdr->sh_flags = SHF_ALLOC | SHF_WRITE;
		} else
			*shdr = *_icache->c_shdr;

		/*
		 * Create a matching data buffer for this section.
		 */
		if ((data = elf_newdata(scn)) == NULL) {
			eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_NEWDATA), opath);
			cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
			return (1);
		}

		/*
		 * Determine what data will be used for this section.
		 */
		if (_icache->c_flags == FLG_C_SHSTR) {
			/*
			 * Reassign the shstrtab to the new data buffer we're
			 * creating.  Insure that the new elf header references
			 * this section header table.
			 */
			*data = *_icache->c_data;

			data->d_buf = (void *)shstr;
			data->d_size = shstr_size;

			_icache->c_info = shstr;

			/* LINTED */
			if (elf_ndxscn(scn) >= SHN_LORESERVE) {
				Elf_Scn	*_scn;
				Shdr	*shdr0;

				/*
				 * libelf deals with e_shnum for us, but we
				 * need to deal with e_shstrndx ourselves.
				 */
				oehdr->e_shstrndx = SHN_XINDEX;
				if ((_scn = elf_getscn(oelf, 0)) == NULL) {
					eprintf(lml, ERR_ELF,
					    MSG_ORIG(MSG_ELF_GETSCN), opath);
					cleanup(ielf, oelf, melf, icache,
					    mcache, fd, opath);
					return (1);
				}
				shdr0 = elf_getshdr(_scn);
				shdr0->sh_link = elf_ndxscn(scn);
			} else {
				oehdr->e_shstrndx = (Half)elf_ndxscn(scn);
			}

		} else if (_icache->c_flags == FLG_C_HEAP) {
			/*
			 * Assign the heap to the appropriate memory offset.
			 */
			data->d_buf = status->pr_brkbase;
			data->d_type = ELF_T_BYTE;
			data->d_size = (size_t)status->pr_brksize;
			data->d_off = 0;
			data->d_align = 1;
			data->d_version = EV_CURRENT;

			shdr->sh_addr = data_cache->c_shdr->sh_addr +
			    data_cache->c_shdr->sh_size;

		} else if (_icache->c_flags == FLG_C_RELOC) {
			/*
			 * If some relocations are to be saved in the new image
			 * then the relocation sections will be reorganized to
			 * localize their contents.  These relocation sections
			 * will no longer have a one-to-one relationship with
			 * the section they relocate, hence we rename them and
			 * remove their sh_info info.
			 */
			*data = *_icache->c_data;

			shdr->sh_info = 0;

		} else {
			/*
			 * By default simply pass the section through.  If
			 * we've been asked to use the memory image of the
			 * input file reestablish the data buffer address.
			 */
			*data = *_icache->c_data;

			if ((shdr->sh_addr) && (flags & RTLD_MEMORY))
				data->d_buf = (void *)(shdr->sh_addr + addr);

			/*
			 * Update any NOBITS section to indicate that it now
			 * contains data.  If this image is being created
			 * directly from the input file, zero out the .bss
			 * section (this saves ld.so.1 having to zero out memory
			 * or do any /dev/zero mappings).
			 */
			if (shdr->sh_type == SHT_NOBITS) {
				shdr->sh_type = SHT_PROGBITS;
				if (!(flags & RTLD_MEMORY)) {
					if ((data->d_buf = calloc(1,
					    data->d_size)) == 0) {
						cleanup(ielf, oelf, melf,
						    icache, mcache, fd, opath);
						return (1);
					}
				}
			}
		}

		/*
		 * Update the section header string table.
		 */
		/* LINTED */
		shdr->sh_name = (Word)(_shstr - shstr);
		(void) strcpy(_shstr, _icache->c_name);
		_shstr = _shstr + strlen(_icache->c_name) + 1;

		/*
		 * For each section that has a virtual address update its
		 * address to the fixed location of the new image.
		 */
		if (shdr->sh_addr)
			shdr->sh_addr += addr;

		/*
		 * If we've inserted a new section any later sections may need
		 * their sh_link fields updated (.stabs comes to mind).
		 */
		if (status && endx && (shdr->sh_link >= endx))
			shdr->sh_link++;
	}

	/*
	 * Generate the new image, and obtain a new elf descriptor that will
	 * allow us to write and update the new image.
	 */
	if (elf_update(oelf, ELF_C_WRIMAGE) == -1) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_UPDATE), opath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	if ((melf = elf_begin(0, ELF_C_IMAGE, oelf)) == NULL) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_BEGIN), opath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	if ((mehdr = elf_getehdr(melf)) == NULL) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETEHDR), opath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}

	if (elf_getshdrnum(melf, &shndx) == -1) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETSHDRNUM), opath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}

	/*
	 * Construct a cache to maintain the memory files section information.
	 */
	if ((mcache = calloc(shndx, sizeof (Cache))) == 0) {
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}
	_mcache = mcache;
	_mcache++;

	for (scn = 0; scn = elf_nextscn(melf, scn); _mcache++) {

		if ((_mcache->c_shdr = elf_getshdr(scn)) == NULL) {
			eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETSHDR), opath);
			cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
			return (1);
		}

		if ((_mcache->c_data = elf_getdata(scn, NULL)) == NULL) {
			eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_GETDATA), opath);
			cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
			return (1);
		}
	}

	/*
	 * Now that we have a complete description of the new image update any
	 * sections that are required.
	 *
	 *  o	reset any symbol table entries.
	 *
	 *  o	reset any relocation entries.
	 *
	 *  o	reset dynamic entries.
	 */
	_mcache = &mcache[0];
	for (_icache = &icache[1]; _icache->c_flags != FLG_C_END; _icache++) {

		if (_icache->c_flags == FLG_C_EXCLUDE)
			continue;

		_mcache++;
		shdr = _mcache->c_shdr;

		/*
		 * Update the symbol table entries.  _end and _edata will be
		 * changed to reflect any heap addition.  All global symbols
		 * will be updated to their new fixed address.
		 */
		if ((shdr->sh_type == SHT_SYMTAB) ||
		    (shdr->sh_type == SHT_DYNSYM) ||
		    (shdr->sh_type == SHT_SUNW_LDYNSYM)) {
			update_sym(mcache, _mcache, edata, endx, addr);
			continue;
		}

		/*
		 * Update any relocations.  All relocation requirements will
		 * have been established in count_reloc().
		 */
		if (shdr->sh_type == M_REL_SHT_TYPE) {
			if (rel_base == (Rel *)0) {
				rel_base = (Rel *)_mcache->c_data->d_buf;
				rel_null = rel_base;
				rel_data = (Rel *)((Xword)rel_null +
				    (rel_null_no * rel_entsize));
				rel_func = (Rel *)((Xword)rel_data +
				    (rel_data_no * rel_entsize));
			}

			update_reloc(mcache, icache, _icache, opath, lmp,
			    &rel_null, &rel_data, &rel_func);
			continue;
		}

		/*
		 * Perform any dynamic entry updates after all relocation
		 * processing has been carried out (as its possible the .dynamic
		 * section could occur before the .rel sections, delay this
		 * processing until last).
		 */
		if (shdr->sh_type == SHT_DYNAMIC)
			dyn_cache = _mcache;
	}

	if (dyn_cache) {
		Xword	off = (Xword)rel_base - (Xword)mehdr;

		/*
		 * If we're dumping a fixed object (typically the dynamic
		 * executable) compensate for its real base address.
		 */
		if (!addr)
			off += ADDR(lmp);

		if (update_dynamic(mcache, dyn_cache, lmp, flags, addr, off,
		    opath, rel_null_no, rel_data_no, rel_func_no, rel_entsize,
		    elf_checksum(melf))) {
			cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
			return (1);
		}
	}

	/*
	 * Having completed all section updates write the memory file out.
	 */
	if (elf_update(oelf, ELF_C_WRITE) == -1) {
		eprintf(lml, ERR_ELF, MSG_ORIG(MSG_ELF_UPDATE), opath);
		cleanup(ielf, oelf, melf, icache, mcache, fd, opath);
		return (1);
	}

	cleanup(ielf, oelf, melf, icache, mcache, fd, 0);
	return (0);
}
