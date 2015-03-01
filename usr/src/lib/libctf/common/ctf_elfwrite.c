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
/*
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * Routines for writing ctf data to elf files, originally from the ctf tools.
 */

#include <ctf_impl.h>
#include <libctf.h>
#include <gelf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <libelf.h>
#include <sys/zmod.h>

static int
ctf_write_elf(ctf_file_t *fp, Elf *src, Elf *dst, int flags)
{
	GElf_Ehdr sehdr, dehdr;
	Elf_Scn *sscn, *dscn;
	Elf_Data *sdata, *ddata;
	GElf_Shdr shdr;
	int symtab_idx = -1;
	off_t new_offset = 0;
	off_t ctfnameoff = 0;
	int compress = (flags & CTF_ELFWRITE_F_COMPRESS);
	int *secxlate;
	int srcidx, dstidx, pad, i;
	int curnmoff = 0;
	int changing = 0;
	size_t nshdr, nphdr, strndx;

	void *cdata = NULL;

	if ((flags & ~(CTF_ELFWRITE_F_COMPRESS)) != 0)
		return (ctf_set_errno(fp, EINVAL));

	if (gelf_newehdr(dst, gelf_getclass(src)) == NULL)
		return (ctf_set_errno(fp, ECTF_ELF));

	if (gelf_getehdr(src, &sehdr) == NULL)
		return (ctf_set_errno(fp, ECTF_ELF));
	(void) memcpy(&dehdr, &sehdr, sizeof (GElf_Ehdr));
	if (gelf_update_ehdr(dst, &dehdr) == 0)
		return (ctf_set_errno(fp, ECTF_ELF));

	/*
	 * Use libelf to get the number of sections and the string section to
	 * deal with ELF files that may have a large number of sections. We just
	 * always use this to make our live easier.
	 */
	if (elf_getphdrnum(src, &nphdr) != 0)
		return (ctf_set_errno(fp, ECTF_ELF));
	if (elf_getshdrnum(src, &nshdr) != 0)
		return (ctf_set_errno(fp, ECTF_ELF));
	if (elf_getshdrstrndx(src, &strndx) != 0)
		return (ctf_set_errno(fp, ECTF_ELF));

	/*
	 * Neither the existing debug sections nor the SUNW_ctf sections (new or
	 * existing) are SHF_ALLOC'd, so they won't be in areas referenced by
	 * program headers.  As such, we can just blindly copy the program
	 * headers from the existing file to the new file.
	 */
	if (nphdr != 0) {
		(void) elf_flagelf(dst, ELF_C_SET, ELF_F_LAYOUT);
		if (gelf_newphdr(dst, nphdr) == NULL)
			return (ctf_set_errno(fp, ECTF_ELF));

		for (i = 0; i < nphdr; i++) {
			GElf_Phdr phdr;

			if (gelf_getphdr(src, i, &phdr) == NULL)
				return (ctf_set_errno(fp, ECTF_ELF));
			if (gelf_update_phdr(dst, i, &phdr) == 0)
				return (ctf_set_errno(fp, ECTF_ELF));
		}
	}

	secxlate = ctf_alloc(sizeof (int) * nshdr);
	for (srcidx = dstidx = 0; srcidx < nshdr; srcidx++) {
		Elf_Scn *scn = elf_getscn(src, srcidx);
		GElf_Shdr shdr;
		char *sname;

		if (gelf_getshdr(scn, &shdr) == NULL) {
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, ECTF_ELF));
		}
		sname = elf_strptr(src, strndx, shdr.sh_name);
		if (sname == NULL) {
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, ECTF_ELF));
		}

		if (strcmp(sname, CTF_ELF_SCN_NAME) == 0) {
			secxlate[srcidx] = -1;
		} else {
			secxlate[srcidx] = dstidx++;
			curnmoff += strlen(sname) + 1;
		}

		new_offset = (off_t)dehdr.e_phoff;
	}

	for (srcidx = 1; srcidx < nshdr; srcidx++) {
		char *sname;

		sscn = elf_getscn(src, srcidx);
		if (gelf_getshdr(sscn, &shdr) == NULL) {
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, ECTF_ELF));
		}

		if (secxlate[srcidx] == -1) {
			changing = 1;
			continue;
		}

		dscn = elf_newscn(dst);
		if (dscn == NULL) {
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, ECTF_ELF));
		}

		/*
		 * If this file has program headers, we need to explicitly lay
		 * out sections.  If none of the sections prior to this one have
		 * been removed, then we can just use the existing location.  If
		 * one or more sections have been changed, then we need to
		 * adjust this one to avoid holes.
		 */
		if (changing && nphdr != 0) {
			pad = new_offset % shdr.sh_addralign;

			if (pad != 0)
				new_offset += shdr.sh_addralign - pad;
			shdr.sh_offset = new_offset;
		}

		shdr.sh_link = secxlate[shdr.sh_link];

		if (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA)
			shdr.sh_info = secxlate[shdr.sh_info];

		sname = elf_strptr(src, strndx, shdr.sh_name);
		if (sname == NULL) {
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, ECTF_ELF));
		}
		if ((sdata = elf_getdata(sscn, NULL)) == NULL) {
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, ECTF_ELF));
		}
		if ((ddata = elf_newdata(dscn)) == NULL) {
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, ECTF_ELF));
		}
		bcopy(sdata, ddata, sizeof (Elf_Data));

		if (srcidx == strndx) {
			char seclen = strlen(CTF_ELF_SCN_NAME);

			ddata->d_buf = ctf_alloc(ddata->d_size + shdr.sh_size +
			    seclen + 1);
			if (ddata->d_buf == NULL) {
				ctf_free(secxlate,
				    sizeof (int) * nshdr);
				return (ctf_set_errno(fp, ECTF_ELF));
			}
			bcopy(sdata->d_buf, ddata->d_buf, shdr.sh_size);
			(void) strcpy((caddr_t)ddata->d_buf + shdr.sh_size,
			    CTF_ELF_SCN_NAME);
			ctfnameoff = (off_t)shdr.sh_size;
			shdr.sh_size += seclen + 1;
			ddata->d_size += seclen + 1;

			if (nphdr != 0)
				changing = 1;
		}

		if (shdr.sh_type == SHT_SYMTAB && shdr.sh_entsize != 0) {
			int nsym = shdr.sh_size / shdr.sh_entsize;

			symtab_idx = secxlate[srcidx];

			ddata->d_buf = ctf_alloc(shdr.sh_size);
			if (ddata->d_buf == NULL) {
				ctf_free(secxlate,
				    sizeof (int) * nshdr);
				return (ctf_set_errno(fp, ECTF_ELF));
			}
			(void) bcopy(sdata->d_buf, ddata->d_buf, shdr.sh_size);

			for (i = 0; i < nsym; i++) {
				GElf_Sym sym;
				short newscn;

				(void) gelf_getsym(ddata, i, &sym);

				if (sym.st_shndx >= SHN_LORESERVE)
					continue;

				if ((newscn = secxlate[sym.st_shndx]) !=
				    sym.st_shndx) {
					sym.st_shndx =
					    (newscn == -1 ? 1 : newscn);

					if (gelf_update_sym(ddata, i, &sym) ==
					    0) {
						ctf_free(secxlate,
						    sizeof (int) *
						    nshdr);
						return (ctf_set_errno(fp,
						    ECTF_ELF));
					}
				}
			}
		}

		if (gelf_update_shdr(dscn, &shdr) == NULL) {
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, ECTF_ELF));
		}

		new_offset = (off_t)shdr.sh_offset;
		if (shdr.sh_type != SHT_NOBITS)
			new_offset += shdr.sh_size;
	}

	if (symtab_idx == -1) {
		ctf_free(secxlate, sizeof (int) * nshdr);
		return (ctf_set_errno(fp, ECTF_ELF));
	}

	/* Add the ctf section */
	if ((dscn = elf_newscn(dst)) == NULL) {
		ctf_free(secxlate, sizeof (int) * nshdr);
		return (ctf_set_errno(fp, ECTF_ELF));
	}
	if (gelf_getshdr(dscn, &shdr) == NULL) {
		ctf_free(secxlate, sizeof (int) * nshdr);
		return (ctf_set_errno(fp, ECTF_ELF));
	}
	shdr.sh_name = ctfnameoff;
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_size = fp->ctf_size;
	shdr.sh_link = symtab_idx;
	shdr.sh_addralign = 4;
	if (changing && nphdr != 0) {
		pad = new_offset % shdr.sh_addralign;

		if (pad)
			new_offset += shdr.sh_addralign - pad;

		shdr.sh_offset = new_offset;
		new_offset += shdr.sh_size;
	}

	if ((ddata = elf_newdata(dscn)) == NULL) {
		ctf_free(secxlate, sizeof (int) * nshdr);
		return (ctf_set_errno(fp, ECTF_ELF));
	}

	if (compress != 0) {
		size_t dlen;
		ctf_header_t *cthp;
		int err;

		if (ctf_zopen(&err) == NULL) {
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, err));
		}

		dlen = fp->ctf_size;
		cdata = ctf_data_alloc(dlen);
		bcopy(fp->ctf_base, cdata, sizeof (ctf_header_t));
		cthp = cdata;
		cthp->cth_flags  |= CTF_F_COMPRESS;
		dlen -= sizeof (ctf_header_t);
		if (z_compress((void *)((uintptr_t)cdata +
		    sizeof (ctf_header_t)), &dlen,
		    fp->ctf_base + sizeof (ctf_header_t),
		    fp->ctf_size - sizeof (ctf_header_t)) != Z_OK) {
			ctf_data_free(cdata, fp->ctf_size);
			ctf_free(secxlate, sizeof (int) * nshdr);
			return (ctf_set_errno(fp, ECTF_ZLIB));
		}
		ddata->d_buf = cdata;
		ddata->d_size = dlen + sizeof (ctf_header_t);
	} else {
		ddata->d_buf = (void *)fp->ctf_base;
		ddata->d_size = fp->ctf_size;
	}
	ddata->d_align = shdr.sh_addralign;

	if (gelf_update_shdr(dscn, &shdr) == 0) {
		if (cdata != NULL)
			ctf_data_free(cdata, fp->ctf_size);
		ctf_free(secxlate, sizeof (int) * nshdr);
		return (ctf_set_errno(fp, ECTF_ELF));
	}

	/* update the section header location */
	if (nphdr != 0) {
		size_t align = gelf_fsize(dst, ELF_T_ADDR, 1, EV_CURRENT);
		size_t r = new_offset % align;

		if (r)
			new_offset += align - r;

		dehdr.e_shoff = new_offset;
	}

	/* commit to disk */
	if (sehdr.e_shstrndx == SHN_XINDEX)
		dehdr.e_shstrndx = SHN_XINDEX;
	else
		dehdr.e_shstrndx = secxlate[sehdr.e_shstrndx];
	if (gelf_update_ehdr(dst, &dehdr) == NULL) {
		if (cdata != NULL)
			ctf_data_free(cdata, fp->ctf_size);
		ctf_free(secxlate, sizeof (int) * nshdr);
		return (ctf_set_errno(fp, ECTF_ELF));
	}
	if (elf_update(dst, ELF_C_WRITE) < 0) {
		if (cdata != NULL)
			ctf_data_free(cdata, fp->ctf_size);
		ctf_free(secxlate, sizeof (int) * nshdr);
		return (ctf_set_errno(fp, ECTF_ELF));
	}

	if (cdata != NULL)
		ctf_data_free(cdata, fp->ctf_size);
	ctf_free(secxlate, sizeof (int) * nshdr);

	return (0);
}

int
ctf_elffdwrite(ctf_file_t *fp, int ifd, int ofd, int flags)
{
	int ret;
	Elf *ielf, *oelf;

	(void) elf_version(EV_CURRENT);
	if ((ielf = elf_begin(ifd, ELF_C_READ, NULL)) == NULL)
		return (ctf_set_errno(fp, ECTF_ELF));

	if ((oelf = elf_begin(ofd, ELF_C_WRITE, NULL)) == NULL)
		return (ctf_set_errno(fp, ECTF_ELF));

	ret = ctf_write_elf(fp, ielf, oelf, flags);

	(void) elf_end(ielf);
	(void) elf_end(oelf);

	return (ret);
}

int
ctf_elfwrite(ctf_file_t *fp, const char *input, const char *output, int flags)
{
	struct stat st;
	int ifd, ofd, ret;

	if ((ifd = open(input, O_RDONLY)) < 0)
		return (ctf_set_errno(fp, errno));

	if (fstat(ifd, &st) < 0)
		return (ctf_set_errno(fp, errno));

	if ((ofd = open(output, O_RDWR | O_CREAT | O_TRUNC, st.st_mode)) < 0)
		return (ctf_set_errno(fp, errno));

	ret = ctf_elffdwrite(fp, ifd, ofd, flags);

	if (close(ifd) != 0 && ret != 0)
		ret = ctf_set_errno(fp, errno);
	if (close(ofd) != 0 && ret != 0)
		ret = ctf_set_errno(fp, errno);

	return (ret);
}
