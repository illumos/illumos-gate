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
 */
/*
 * Copyright (c) 2015, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctf_impl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <gelf.h>
#include <zlib.h>
#include <zone.h>
#include <sys/debug.h>

#ifdef _LP64
static const char *_libctf_zlib = "/usr/lib/64/libz.so.1";
#else
static const char *_libctf_zlib = "/usr/lib/libz.so.1";
#endif

static struct {
	int (*z_uncompress)(uchar_t *, ulong_t *, const uchar_t *, ulong_t);
	int (*z_initcomp)(z_stream *, int, const char *, int);
	int (*z_compress)(z_stream *, int);
	int (*z_finicomp)(z_stream *);
	const char *(*z_error)(int);
	void *z_dlp;
} zlib;

static size_t _PAGESIZE;
static size_t _PAGEMASK;

static uint64_t ctf_phase = 0;

#define	CTF_COMPRESS_CHUNK	(64*1024)

typedef struct ctf_zdata {
	void		*czd_buf;
	void		*czd_next;
	ctf_file_t	*czd_ctfp;
	size_t		czd_allocsz;
	z_stream	czd_zstr;
} ctf_zdata_t;

#pragma init(_libctf_init)
void
_libctf_init(void)
{
	const char *p = getenv("LIBCTF_DECOMPRESSOR");

	if (p != NULL)
		_libctf_zlib = p; /* use alternate decompression library */

	_libctf_debug = getenv("LIBCTF_DEBUG") != NULL;

	_PAGESIZE = getpagesize();
	_PAGEMASK = ~(_PAGESIZE - 1);
}

/*
 * Attempt to dlopen the decompression library and locate the symbols of
 * interest that we will need to call.  This information in cached so
 * that multiple calls to ctf_bufopen() do not need to reopen the library.
 */
void *
ctf_zopen(int *errp)
{
	char buf[MAXPATHLEN];
	const char *path = _libctf_zlib, *zroot;

	if (zlib.z_dlp != NULL)
		return (zlib.z_dlp); /* library is already loaded */

	/*
	 * Get the zone native root.  For the tools build, we don't need
	 * this (it seems fair to impose that we always build the system in
	 * a native zone), and we want to allow build machines that are older
	 * that the notion of the native root, so we only actually make this
	 * call if we're not the tools build.
	 */
#ifndef	CTF_TOOLS_BUILD
	zroot = zone_get_nroot();
#else
	zroot = NULL;
#endif

	if (zroot != NULL) {
		(void) snprintf(buf, MAXPATHLEN, "%s/%s", zroot, _libctf_zlib);
		path = buf;
	}

	ctf_dprintf("decompressing CTF data using %s\n", path);

	if (access(path, R_OK) == -1)
		return (ctf_set_open_errno(errp, ECTF_ZMISSING));

	if ((zlib.z_dlp = dlopen(path, RTLD_LAZY | RTLD_LOCAL)) == NULL)
		return (ctf_set_open_errno(errp, ECTF_ZINIT));

	zlib.z_uncompress = (int (*)()) dlsym(zlib.z_dlp, "uncompress");
	zlib.z_initcomp = (int (*)()) dlsym(zlib.z_dlp, "deflateInit_");
	zlib.z_compress = (int (*)()) dlsym(zlib.z_dlp, "deflate");
	zlib.z_finicomp = (int (*)()) dlsym(zlib.z_dlp, "deflateEnd");
	zlib.z_error = (const char *(*)()) dlsym(zlib.z_dlp, "zError");

	if (zlib.z_uncompress == NULL || zlib.z_error == NULL ||
	    zlib.z_initcomp == NULL|| zlib.z_compress == NULL ||
	    zlib.z_finicomp == NULL) {
		(void) dlclose(zlib.z_dlp);
		bzero(&zlib, sizeof (zlib));
		return (ctf_set_open_errno(errp, ECTF_ZINIT));
	}

	return (zlib.z_dlp);
}

/*
 * The ctf_bufopen() routine calls these subroutines, defined by <sys/zmod.h>,
 * which we then patch through to the functions in the decompression library.
 */
int
z_uncompress(void *dst, size_t *dstlen, const void *src, size_t srclen)
{
	return (zlib.z_uncompress(dst, (ulong_t *)dstlen, src, srclen));
}

const char *
z_strerror(int err)
{
	return (zlib.z_error(err));
}

static int
ctf_zdata_init(ctf_zdata_t *czd, ctf_file_t *fp)
{
	ctf_header_t *cthp;

	bzero(czd, sizeof (ctf_zdata_t));

	czd->czd_allocsz = fp->ctf_size;
	czd->czd_buf = ctf_data_alloc(czd->czd_allocsz);
	if (czd->czd_buf == MAP_FAILED)
		return (ctf_set_errno(fp, ENOMEM));

	bcopy(fp->ctf_base, czd->czd_buf, sizeof (ctf_header_t));
	czd->czd_ctfp = fp;
	cthp = czd->czd_buf;
	cthp->cth_flags |= CTF_F_COMPRESS;
	czd->czd_next = (void *)((uintptr_t)czd->czd_buf +
	    sizeof (ctf_header_t));

	if (zlib.z_initcomp(&czd->czd_zstr, Z_BEST_COMPRESSION,
	    ZLIB_VERSION, sizeof (z_stream)) != Z_OK)
		return (ctf_set_errno(fp, ECTF_ZLIB));

	return (0);
}

static int
ctf_zdata_grow(ctf_zdata_t *czd)
{
	size_t off;
	size_t newsz;
	void *ndata;

	off = (uintptr_t)czd->czd_next - (uintptr_t)czd->czd_buf;
	newsz = czd->czd_allocsz + CTF_COMPRESS_CHUNK;
	ndata = ctf_data_alloc(newsz);
	if (ndata == MAP_FAILED) {
		return (ctf_set_errno(czd->czd_ctfp, ENOMEM));
	}

	bcopy(czd->czd_buf, ndata, off);
	ctf_data_free(czd->czd_buf, czd->czd_allocsz);
	czd->czd_allocsz = newsz;
	czd->czd_buf = ndata;
	czd->czd_next = (void *)((uintptr_t)ndata + off);

	czd->czd_zstr.next_out = (Bytef *)czd->czd_next;
	czd->czd_zstr.avail_out = CTF_COMPRESS_CHUNK;
	return (0);
}

static int
ctf_zdata_compress_buffer(ctf_zdata_t *czd, const void *buf, size_t bufsize)
{
	int err;

	czd->czd_zstr.next_out = czd->czd_next;
	czd->czd_zstr.avail_out = czd->czd_allocsz -
	    ((uintptr_t)czd->czd_next - (uintptr_t)czd->czd_buf);
	czd->czd_zstr.next_in = (Bytef *)buf;
	czd->czd_zstr.avail_in = bufsize;

	while (czd->czd_zstr.avail_in != 0) {
		if (czd->czd_zstr.avail_out == 0) {
			czd->czd_next = czd->czd_zstr.next_out;
			if ((err = ctf_zdata_grow(czd)) != 0) {
				return (err);
			}
		}

		if ((err = zlib.z_compress(&czd->czd_zstr, Z_NO_FLUSH)) != Z_OK)
			return (ctf_set_errno(czd->czd_ctfp, ECTF_ZLIB));
	}
	czd->czd_next = czd->czd_zstr.next_out;

	return (0);
}

static int
ctf_zdata_flush(ctf_zdata_t *czd, boolean_t finish)
{
	int err;
	int flag = finish == B_TRUE ? Z_FINISH : Z_FULL_FLUSH;
	int bret = finish == B_TRUE ? Z_STREAM_END : Z_BUF_ERROR;

	for (;;) {
		if (czd->czd_zstr.avail_out == 0) {
			czd->czd_next = czd->czd_zstr.next_out;
			if ((err = ctf_zdata_grow(czd)) != 0) {
				return (err);
			}
		}

		err = zlib.z_compress(&czd->czd_zstr, flag);
		if (err == bret) {
			break;
		}
		if (err != Z_OK)
			return (ctf_set_errno(czd->czd_ctfp, ECTF_ZLIB));

	}

	czd->czd_next = czd->czd_zstr.next_out;

	return (0);
}

static int
ctf_zdata_end(ctf_zdata_t *czd)
{
	int ret;

	if ((ret = ctf_zdata_flush(czd, B_TRUE)) != 0)
		return (ret);

	if ((ret = zlib.z_finicomp(&czd->czd_zstr)) != 0)
		return (ctf_set_errno(czd->czd_ctfp, ECTF_ZLIB));

	return (0);
}

static void
ctf_zdata_cleanup(ctf_zdata_t *czd)
{
	ctf_data_free(czd->czd_buf, czd->czd_allocsz);
	(void) zlib.z_finicomp(&czd->czd_zstr);
}

/*
 * Compress our CTF data and return both the size of the compressed data and the
 * size of the allocation. These may be different due to the nature of
 * compression.
 *
 * In addition, we flush the compression between our two phases such that we
 * maintain a different dictionary between the CTF data and the string section.
 */
int
ctf_compress(ctf_file_t *fp, void **buf, size_t *allocsz, size_t *elfsize)
{
	int err;
	ctf_zdata_t czd;
	ctf_header_t *cthp = (ctf_header_t *)fp->ctf_base;

	if ((err = ctf_zdata_init(&czd, fp)) != 0)
		return (err);

	if ((err = ctf_zdata_compress_buffer(&czd, fp->ctf_buf,
	    cthp->cth_stroff)) != 0) {
		ctf_zdata_cleanup(&czd);
		return (err);
	}

	if ((err = ctf_zdata_flush(&czd, B_FALSE)) != 0) {
		ctf_zdata_cleanup(&czd);
		return (err);
	}

	if ((err = ctf_zdata_compress_buffer(&czd,
	    fp->ctf_buf + cthp->cth_stroff, cthp->cth_strlen)) != 0) {
		ctf_zdata_cleanup(&czd);
		return (err);
	}

	if ((err = ctf_zdata_end(&czd)) != 0) {
		ctf_zdata_cleanup(&czd);
		return (err);
	}

	*buf = czd.czd_buf;
	*allocsz = czd.czd_allocsz;
	*elfsize = (uintptr_t)czd.czd_next - (uintptr_t)czd.czd_buf;

	return (0);
}

int
z_compress(void *dst, size_t *dstlen, const void *src, size_t srclen)
{
	z_stream zs;
	int err;

	bzero(&zs, sizeof (z_stream));
	zs.next_in = (uchar_t *)src;
	zs.avail_in = srclen;
	zs.next_out = dst;
	zs.avail_out = *dstlen;

	if ((err = zlib.z_initcomp(&zs, Z_BEST_COMPRESSION, ZLIB_VERSION,
	    sizeof (z_stream))) != Z_OK)
		return (err);

	if ((err = zlib.z_compress(&zs, Z_FINISH)) != Z_STREAM_END) {
		(void) zlib.z_finicomp(&zs);
		return (err == Z_OK ? Z_BUF_ERROR : err);
	}

	*dstlen = zs.total_out;
	return (zlib.z_finicomp(&zs));
}

/*
 * Convert a 32-bit ELF file header into GElf.
 */
static void
ehdr_to_gelf(const Elf32_Ehdr *src, GElf_Ehdr *dst)
{
	bcopy(src->e_ident, dst->e_ident, EI_NIDENT);
	dst->e_type = src->e_type;
	dst->e_machine = src->e_machine;
	dst->e_version = src->e_version;
	dst->e_entry = (Elf64_Addr)src->e_entry;
	dst->e_phoff = (Elf64_Off)src->e_phoff;
	dst->e_shoff = (Elf64_Off)src->e_shoff;
	dst->e_flags = src->e_flags;
	dst->e_ehsize = src->e_ehsize;
	dst->e_phentsize = src->e_phentsize;
	dst->e_phnum = src->e_phnum;
	dst->e_shentsize = src->e_shentsize;
	dst->e_shnum = src->e_shnum;
	dst->e_shstrndx = src->e_shstrndx;
}

/*
 * Convert a 32-bit ELF section header into GElf.
 */
static void
shdr_to_gelf(const Elf32_Shdr *src, GElf_Shdr *dst)
{
	dst->sh_name = src->sh_name;
	dst->sh_type = src->sh_type;
	dst->sh_flags = src->sh_flags;
	dst->sh_addr = src->sh_addr;
	dst->sh_offset = src->sh_offset;
	dst->sh_size = src->sh_size;
	dst->sh_link = src->sh_link;
	dst->sh_info = src->sh_info;
	dst->sh_addralign = src->sh_addralign;
	dst->sh_entsize = src->sh_entsize;
}

/*
 * In order to mmap a section from the ELF file, we must round down sh_offset
 * to the previous page boundary, and mmap the surrounding page.  We store
 * the pointer to the start of the actual section data back into sp->cts_data.
 */
const void *
ctf_sect_mmap(ctf_sect_t *sp, int fd)
{
	size_t pageoff = sp->cts_offset & ~_PAGEMASK;

	caddr_t base = mmap64(NULL, sp->cts_size + pageoff, PROT_READ,
	    MAP_PRIVATE, fd, sp->cts_offset & _PAGEMASK);

	if (base != MAP_FAILED)
		sp->cts_data = base + pageoff;

	return (base);
}

/*
 * Since sp->cts_data has the adjusted offset, we have to again round down
 * to get the actual mmap address and round up to get the size.
 */
void
ctf_sect_munmap(const ctf_sect_t *sp)
{
	uintptr_t addr = (uintptr_t)sp->cts_data;
	uintptr_t pageoff = addr & ~_PAGEMASK;

	(void) munmap((void *)(addr - pageoff), sp->cts_size + pageoff);
}

/*
 * Open the specified file descriptor and return a pointer to a CTF container.
 * The file can be either an ELF file or raw CTF file.  The caller is
 * responsible for closing the file descriptor when it is no longer needed.
 */
ctf_file_t *
ctf_fdcreate_int(int fd, int *errp, ctf_sect_t *ctfp)
{
	ctf_sect_t ctfsect, symsect, strsect;
	ctf_file_t *fp = NULL;
	size_t shstrndx, shnum;

	struct stat64 st;
	ssize_t nbytes;

	union {
		ctf_preamble_t ctf;
		Elf32_Ehdr e32;
		GElf_Ehdr e64;
	} hdr;

	bzero(&ctfsect, sizeof (ctf_sect_t));
	bzero(&symsect, sizeof (ctf_sect_t));
	bzero(&strsect, sizeof (ctf_sect_t));
	bzero(&hdr.ctf, sizeof (hdr));

	if (fstat64(fd, &st) == -1)
		return (ctf_set_open_errno(errp, errno));

	if ((nbytes = pread64(fd, &hdr.ctf, sizeof (hdr), 0)) <= 0)
		return (ctf_set_open_errno(errp, nbytes < 0? errno : ECTF_FMT));

	/*
	 * If we have read enough bytes to form a CTF header and the magic
	 * string matches, attempt to interpret the file as raw CTF.
	 */
	if (nbytes >= sizeof (ctf_preamble_t) &&
	    hdr.ctf.ctp_magic == CTF_MAGIC) {
		if (ctfp != NULL)
			return (ctf_set_open_errno(errp, EINVAL));

		if (hdr.ctf.ctp_version > CTF_VERSION)
			return (ctf_set_open_errno(errp, ECTF_CTFVERS));

		ctfsect.cts_data = mmap64(NULL, st.st_size, PROT_READ,
		    MAP_PRIVATE, fd, 0);

		if (ctfsect.cts_data == MAP_FAILED)
			return (ctf_set_open_errno(errp, errno));

		ctfsect.cts_name = _CTF_SECTION;
		ctfsect.cts_type = SHT_PROGBITS;
		ctfsect.cts_flags = SHF_ALLOC;
		ctfsect.cts_size = (size_t)st.st_size;
		ctfsect.cts_entsize = 1;
		ctfsect.cts_offset = 0;

		if ((fp = ctf_bufopen(&ctfsect, NULL, NULL, errp)) == NULL)
			ctf_sect_munmap(&ctfsect);

		return (fp);
	}

	/*
	 * If we have read enough bytes to form an ELF header and the magic
	 * string matches, attempt to interpret the file as an ELF file.  We
	 * do our own largefile ELF processing, and convert everything to
	 * GElf structures so that clients can operate on any data model.
	 */
	if (nbytes >= sizeof (Elf32_Ehdr) &&
	    bcmp(&hdr.e32.e_ident[EI_MAG0], ELFMAG, SELFMAG) == 0) {
#ifdef	_BIG_ENDIAN
		uchar_t order = ELFDATA2MSB;
#else
		uchar_t order = ELFDATA2LSB;
#endif
		GElf_Shdr *sp;

		void *strs_map;
		size_t strs_mapsz, i;
		const char *strs;

		if (hdr.e32.e_ident[EI_DATA] != order)
			return (ctf_set_open_errno(errp, ECTF_ENDIAN));
		if (hdr.e32.e_version != EV_CURRENT)
			return (ctf_set_open_errno(errp, ECTF_ELFVERS));

		if (hdr.e32.e_ident[EI_CLASS] == ELFCLASS64) {
			if (nbytes < sizeof (GElf_Ehdr))
				return (ctf_set_open_errno(errp, ECTF_FMT));
		} else {
			Elf32_Ehdr e32 = hdr.e32;
			ehdr_to_gelf(&e32, &hdr.e64);
		}

		shnum = hdr.e64.e_shnum;
		shstrndx = hdr.e64.e_shstrndx;

		/* Extended ELF sections */
		if ((shstrndx == SHN_XINDEX) || (shnum == 0)) {
			if (hdr.e32.e_ident[EI_CLASS] == ELFCLASS32) {
				Elf32_Shdr x32;

				if (pread64(fd, &x32, sizeof (x32),
				    hdr.e64.e_shoff) != sizeof (x32))
					return (ctf_set_open_errno(errp,
					    errno));

				shnum = x32.sh_size;
				shstrndx = x32.sh_link;
			} else {
				Elf64_Shdr x64;

				if (pread64(fd, &x64, sizeof (x64),
				    hdr.e64.e_shoff) != sizeof (x64))
					return (ctf_set_open_errno(errp,
					    errno));

				shnum = x64.sh_size;
				shstrndx = x64.sh_link;
			}
		}

		if (shstrndx >= shnum)
			return (ctf_set_open_errno(errp, ECTF_CORRUPT));

		nbytes = sizeof (GElf_Shdr) * shnum;

		if ((sp = malloc(nbytes)) == NULL)
			return (ctf_set_open_errno(errp, errno));

		/*
		 * Read in and convert to GElf the array of Shdr structures
		 * from e_shoff so we can locate sections of interest.
		 */
		if (hdr.e32.e_ident[EI_CLASS] == ELFCLASS32) {
			Elf32_Shdr *sp32;

			nbytes = sizeof (Elf32_Shdr) * shnum;

			if ((sp32 = malloc(nbytes)) == NULL || pread64(fd,
			    sp32, nbytes, hdr.e64.e_shoff) != nbytes) {
				free(sp);
				return (ctf_set_open_errno(errp, errno));
			}

			for (i = 0; i < shnum; i++)
				shdr_to_gelf(&sp32[i], &sp[i]);

			free(sp32);

		} else if (pread64(fd, sp, nbytes, hdr.e64.e_shoff) != nbytes) {
			free(sp);
			return (ctf_set_open_errno(errp, errno));
		}

		/*
		 * Now mmap the section header strings section so that we can
		 * perform string comparison on the section names.
		 */
		strs_mapsz = sp[shstrndx].sh_size +
		    (sp[shstrndx].sh_offset & ~_PAGEMASK);

		strs_map = mmap64(NULL, strs_mapsz, PROT_READ, MAP_PRIVATE,
		    fd, sp[shstrndx].sh_offset & _PAGEMASK);

		strs = (const char *)strs_map +
		    (sp[shstrndx].sh_offset & ~_PAGEMASK);

		if (strs_map == MAP_FAILED) {
			free(sp);
			return (ctf_set_open_errno(errp, ECTF_MMAP));
		}

		/*
		 * Iterate over the section header array looking for the CTF
		 * section and symbol table.  The strtab is linked to symtab.
		 */
		for (i = 0; i < shnum; i++) {
			const GElf_Shdr *shp = &sp[i];
			const GElf_Shdr *lhp = &sp[shp->sh_link];

			if (shp->sh_link >= shnum)
				continue; /* corrupt sh_link field */

			if (shp->sh_name >= sp[shstrndx].sh_size ||
			    lhp->sh_name >= sp[shstrndx].sh_size)
				continue; /* corrupt sh_name field */

			if (shp->sh_type == SHT_PROGBITS &&
			    strcmp(strs + shp->sh_name, _CTF_SECTION) == 0 &&
			    ctfp == NULL) {
				ctfsect.cts_name = strs + shp->sh_name;
				ctfsect.cts_type = shp->sh_type;
				ctfsect.cts_flags = shp->sh_flags;
				ctfsect.cts_size = shp->sh_size;
				ctfsect.cts_entsize = shp->sh_entsize;
				ctfsect.cts_offset = (off64_t)shp->sh_offset;

			} else if (shp->sh_type == SHT_SYMTAB) {
				symsect.cts_name = strs + shp->sh_name;
				symsect.cts_type = shp->sh_type;
				symsect.cts_flags = shp->sh_flags;
				symsect.cts_size = shp->sh_size;
				symsect.cts_entsize = shp->sh_entsize;
				symsect.cts_offset = (off64_t)shp->sh_offset;

				strsect.cts_name = strs + lhp->sh_name;
				strsect.cts_type = lhp->sh_type;
				strsect.cts_flags = lhp->sh_flags;
				strsect.cts_size = lhp->sh_size;
				strsect.cts_entsize = lhp->sh_entsize;
				strsect.cts_offset = (off64_t)lhp->sh_offset;
			}
		}

		free(sp); /* free section header array */

		if (ctfp == NULL) {
			if (ctfsect.cts_type == SHT_NULL && ctfp == NULL) {
				(void) munmap(strs_map, strs_mapsz);
				return (ctf_set_open_errno(errp,
				    ECTF_NOCTFDATA));
			}

			/*
			 * Now mmap the CTF data, symtab, and strtab sections
			 * and call ctf_bufopen() to do the rest of the work.
			 */
			if (ctf_sect_mmap(&ctfsect, fd) == MAP_FAILED) {
				(void) munmap(strs_map, strs_mapsz);
				return (ctf_set_open_errno(errp, ECTF_MMAP));
			}
			ctfp = &ctfsect;
		}

		if (symsect.cts_type != SHT_NULL &&
		    strsect.cts_type != SHT_NULL) {
			if (ctf_sect_mmap(&symsect, fd) == MAP_FAILED ||
			    ctf_sect_mmap(&strsect, fd) == MAP_FAILED) {
				(void) ctf_set_open_errno(errp, ECTF_MMAP);
				goto bad; /* unmap all and abort */
			}
			fp = ctf_bufopen(ctfp, &symsect, &strsect, errp);
		} else
			fp = ctf_bufopen(ctfp, NULL, NULL, errp);
bad:
		if (fp == NULL) {
			if (ctfp == NULL)
				ctf_sect_munmap(&ctfsect);
			ctf_sect_munmap(&symsect);
			ctf_sect_munmap(&strsect);
		} else
			fp->ctf_flags |= LCTF_MMAP;

		(void) munmap(strs_map, strs_mapsz);
		return (fp);
	}

	return (ctf_set_open_errno(errp, ECTF_FMT));
}

ctf_file_t *
ctf_fdopen(int fd, int *errp)
{
	return (ctf_fdcreate_int(fd, errp, NULL));
}

/*
 * Open the specified file and return a pointer to a CTF container.  The file
 * can be either an ELF file or raw CTF file.  This is just a convenient
 * wrapper around ctf_fdopen() for callers.
 */
ctf_file_t *
ctf_open(const char *filename, int *errp)
{
	ctf_file_t *fp;
	int fd;

	if ((fd = open64(filename, O_RDONLY)) == -1) {
		if (errp != NULL)
			*errp = errno;
		return (NULL);
	}

	fp = ctf_fdopen(fd, errp);
	(void) close(fd);
	return (fp);
}

/*
 * Write the uncompressed CTF data stream to the specified file descriptor.
 * This is useful for saving the results of dynamic CTF containers.
 */
int
ctf_write(ctf_file_t *fp, int fd)
{
	const uchar_t *buf = fp->ctf_base;
	ssize_t resid = fp->ctf_size;
	ssize_t len;

	while (resid != 0) {
		if ((len = write(fd, buf, resid)) <= 0)
			return (ctf_set_errno(fp, errno));
		resid -= len;
		buf += len;
	}

	return (0);
}

/*
 * Set the CTF library client version to the specified version.  If version is
 * zero, we just return the default library version number.
 */
int
ctf_version(int version)
{
	if (version < 0) {
		errno = EINVAL;
		return (-1);
	}

	if (version > 0) {
		if (version > CTF_VERSION) {
			errno = ENOTSUP;
			return (-1);
		}
		ctf_dprintf("ctf_version: client using version %d\n", version);
		_libctf_version = version;
	}

	return (_libctf_version);
}

/*
 * A utility function for folks debugging CTF conversion and merging.
 */
void
ctf_phase_dump(ctf_file_t *fp, const char *phase)
{
	int fd;
	static char *base;
	char path[MAXPATHLEN];

	if (base == NULL && (base = getenv("LIBCTF_WRITE_PHASES")) == NULL)
		return;

	(void) snprintf(path, sizeof (path), "%s/libctf.%s.%d.ctf", base,
	    phase != NULL ? phase : "",
	    ctf_phase);
	if ((fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0777)) < 0)
		return;
	(void) ctf_write(fp, fd);
	(void) close(fd);
}
