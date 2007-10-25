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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fs/fs_subr.h>

#include <sys/elf.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/kobj.h>
#include <sys/objfs.h>
#include <sys/objfs_impl.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/vfs_opreg.h>

/*
 * /system/object/<obj>/object
 *
 * This is an ELF file that contains information about data stored in the
 * kernel.  We use a special ELF file type, ET_SUNWPSEUDO, so that we can
 * control which fields and sections have meaning.  The file contains the
 * following sections:
 *
 * 	.shstrtab	Section header string table
 * 	.SUNW_ctf	CTF data
 * 	.symtab		Symbol table
 * 	.strtab		String table
 * 	.text		Text
 * 	.data		Data
 * 	.bss		BSS
 * 	.filename	Filename of module
 * 	.info		Private module info structure
 *
 * The .text, .data, and .bss sections are all marked SHT_NOBITS, and the data
 * is not actually exported in the file for security reasons.  The section
 * headers do contain the address and size of the sections, which is needed by
 * DTrace.  The CTF data, symbol table, and string table are present only if
 * they exist in the kernel.
 */

typedef enum {
	SECT_TYPE_DATA,
	SECT_TYPE_SHSTRTAB,
	SECT_TYPE_DUMMY,
	SECT_TYPE_SYMTAB,
	SECT_TYPE_STRTAB,
	SECT_TYPE_FILENAME,
	SECT_TYPE_INFO
} sect_type_t;

typedef struct section_desc {
	sect_type_t	sect_id;
	const char	*sect_name;
	uintptr_t	sect_addr;
	size_t		sect_size;
	int		sect_type;
	int		sect_flags;
	size_t		sect_str;
	int		sect_link;
	int		sect_entsize;
	int		sect_align;
} section_desc_t;

/*
 * For data sections, 'addr' and 'size' refer to offsets within the module
 * structure where we can find the address and size of the section.
 */
#define	SECT_DATA(name, addr, size, type, flags, align) \
	{ SECT_TYPE_DATA, name, offsetof(struct module, addr), \
	offsetof(struct module, size), type, flags, 0, 0, 0, align }

/*
 * The dummy section is the initial section of the file.  It is put into this
 * array only for convenience when reading the file.
 */
#define	SECT_DUMMY	{ SECT_TYPE_DUMMY, "", 0, 0, 0, 0, 0, 0, 0, 0 }

/*
 * The size of the symbol table and string table are not immediately available
 * as an offset into the module struct, so we have to create individual types
 * for each.
 */
#ifdef _LP64
#define	SECT_SYMTAB(name, type, flags) \
	{ SECT_TYPE_SYMTAB, name, offsetof(struct module, symtbl), 0, type, \
	flags, 0, 0, sizeof (Elf64_Sym), sizeof (uint64_t) }
#else
#define	SECT_SYMTAB(name, type, flags) \
	{ SECT_TYPE_SYMTAB, name, offsetof(struct module, symtbl), 0, type, \
	flags, 0, 0, sizeof (Elf32_Sym), sizeof (uint32_t) }
#endif
#define	SECT_STRTAB(name, type, flags) \
	{ SECT_TYPE_STRTAB, name, offsetof(struct module, strings), 0, type, \
	flags, 0, 0, 0, 1 }

/*
 * The .shstrtab section is constructed when the module is first loaded.
 */
#define	SECT_SHSTRTAB(name, type, flags) \
	{ SECT_TYPE_SHSTRTAB, name, 0, 0, type, flags, 0, 0, 0, 1 }

/*
 * Generic module information (objfs_info_t)
 */
#define	SECT_INFO	\
	{ SECT_TYPE_INFO, ".info", 0, 0, SHT_PROGBITS, 0, 0, 0, 0, \
	sizeof (uint32_t) }

/*
 * Filename section.
 */
#define	SECT_FILENAME	\
	{ SECT_TYPE_FILENAME, ".filename", 0, 0, SHT_PROGBITS, 0, 0, 0, 0, 1 }

static section_desc_t data_sections[] = {
	SECT_DUMMY,
	SECT_SHSTRTAB(".shstrtab",
	    SHT_STRTAB, SHF_STRINGS),
	SECT_DATA(".SUNW_ctf", ctfdata, ctfsize,
	    SHT_PROGBITS, 0, sizeof (uint64_t)),
	SECT_SYMTAB(".symtab", SHT_SYMTAB, 0),
	SECT_STRTAB(".strtab", SHT_STRTAB, SHF_STRINGS),
	SECT_DATA(".text", text, text_size,
	    SHT_NOBITS, SHF_ALLOC | SHF_EXECINSTR, 0),
	SECT_DATA(".data", data, data_size,
	    SHT_NOBITS, SHF_WRITE | SHF_ALLOC, 0),
	SECT_DATA(".bss", bss, bss_size,
	    SHT_NOBITS, SHF_WRITE | SHF_ALLOC, 0),
	SECT_INFO,
	SECT_FILENAME
};

#define	NSECTIONS	\
	(sizeof (data_sections) / sizeof (section_desc_t))

#ifdef _LP64
#define	SECTION_OFFSET(section)	\
	(sizeof (Elf64_Ehdr) + (section) * sizeof (Elf64_Shdr))
#else
#define	SECTION_OFFSET(section)	\
	(sizeof (Elf32_Ehdr) + (section) * sizeof (Elf32_Shdr))
#endif

/*
 * Given a data node, returns the struct module appropriately locked.  If the
 * object has been unloaded, or re-loaded since the file was first opened, this
 * function will return NULL.  If successful, the caller must call
 * objfs_data_unlock().
 */
struct module *
objfs_data_lock(vnode_t *vp)
{
	objfs_datanode_t *dnode = vp->v_data;
	objfs_odirnode_t *odir = gfs_file_parent(vp)->v_data;
	struct modctl *mp = odir->objfs_odir_modctl;

	(void) mod_hold_by_modctl(mp, MOD_WAIT_FOREVER | MOD_LOCK_NOT_HELD);

	if (mp->mod_mp == NULL ||
	    dnode->objfs_data_gencount < mp->mod_gencount) {
		mod_release_mod(mp);
		return (NULL);
	}

	return (mp->mod_mp);
}

void
objfs_data_unlock(vnode_t *vp)
{
	objfs_odirnode_t *odir = gfs_file_parent(vp)->v_data;

	mod_release_mod(odir->objfs_odir_modctl);
}


/*
 * Called when the filesystem is first loaded.  Creates and initializes the
 * section header string table, and fills in the sect_str members of the section
 * descriptors.  This information could be encoded at compile-time, but this
 * way keeps the code more maintainable, as we don't have to worry about
 * duplicating information.
 */
void
objfs_data_init(void)
{
	int i, shstrtab, strtab, symtab;
	size_t len = 0;
	section_desc_t *sect;
	char *strdata;

	for (i = 0; i < NSECTIONS; i++) {
		sect = &data_sections[i];

		ASSERT(sect->sect_align == 0 || ISP2(sect->sect_align));
		ASSERT(sect->sect_align <= sizeof (uint64_t));

		len += strlen(sect->sect_name) + 1;
		if (strcmp(sect->sect_name, ".shstrtab") == 0)
			shstrtab = i;
		else if (strcmp(sect->sect_name, ".symtab") == 0)
			symtab = i;
		else if (strcmp(sect->sect_name, ".strtab") == 0)
			strtab = i;
	}

	strdata = kmem_zalloc(len, KM_SLEEP);
	sect = &data_sections[shstrtab];
	sect->sect_addr = (uintptr_t)strdata;
	sect->sect_size = len;

	len = 0;
	for (i = 0; i < NSECTIONS; i++) {
		sect = &data_sections[i];
		sect->sect_str = len;
		bcopy(sect->sect_name, strdata + len,
		    strlen(sect->sect_name) + 1);
		len += strlen(sect->sect_name) + 1;

		if (strcmp(sect->sect_name, ".SUNW_ctf") == 0)
			sect->sect_link = symtab;
		else if (strcmp(sect->sect_name, ".symtab") == 0)
			sect->sect_link = strtab;
	}
}

/*
 * Given a section descriptor and module pointer, return the address of the
 * data.
 */
static uintptr_t
sect_addr(section_desc_t *sp, struct module *mp)
{
	uintptr_t addr;

	switch (sp->sect_id) {
	case SECT_TYPE_DUMMY:
		addr = 0;
		break;

	case SECT_TYPE_SHSTRTAB:
		addr = sp->sect_addr;
		break;

	case SECT_TYPE_STRTAB:
	case SECT_TYPE_SYMTAB:
	case SECT_TYPE_DATA:
		addr = *((uintptr_t *)((char *)mp + sp->sect_addr));
		break;

	case SECT_TYPE_FILENAME:
		addr = (uintptr_t)mp->filename;
		break;

	case SECT_TYPE_INFO:
		addr = 1;	/* This can be anything nonzero */
		break;
	}

	return (addr);
}

/*
 * Given a section descriptor and module pointer, return the size of the data.
 */
static size_t
sect_size(section_desc_t *sp, struct module *mp)
{
	size_t size;

	switch (sp->sect_id) {
	case SECT_TYPE_DUMMY:
		size = 0;
		break;

	case SECT_TYPE_SHSTRTAB:
		size = sp->sect_size;
		break;

	case SECT_TYPE_DATA:
		size = *((size_t *)((char *)mp + sp->sect_size));
		break;

	case SECT_TYPE_SYMTAB:
		size = mp->symhdr->sh_size;
		break;

	case SECT_TYPE_STRTAB:
		size = mp->strhdr->sh_size;
		break;

	case SECT_TYPE_INFO:
		size = sizeof (objfs_info_t);
		break;

	case SECT_TYPE_FILENAME:
		if (mp->filename == NULL)
			size = 0;
		else
			size = strlen(mp->filename) + 1;
	}

	return (size);
}

/*
 * Given a section descriptor and module pointer, return 1 if the section has
 * valid data and should be included, 0 otherwise.
 */
static int
sect_valid(section_desc_t *sp, struct module *mp)
{
	if (sp->sect_id == SECT_TYPE_DUMMY ||
	    sect_addr(sp, mp) != 0)
		return (1);

	return (0);
}

/*
 * Given a section descriptor and module pointer, return the offset into the
 * file where the data should be placed.
 */
static size_t
data_offset(section_desc_t *sp, struct module *mp)
{
	int i;
	size_t len;
	section_desc_t *cp;

	if (sp != NULL && mp != NULL && !sect_valid(sp, mp))
		return (0);

#ifdef _LP64
	len = sizeof (Elf64_Ehdr);
#else
	len = sizeof (Elf32_Ehdr);
#endif

	/*
	 * Do a first pass to account for all the section headers.
	 */
	for (i = 0; i < NSECTIONS; i++) {
		if (sect_valid(&data_sections[i], mp)) {
#ifdef _LP64
			len += sizeof (Elf64_Shdr);
#else
			len += sizeof (Elf32_Shdr);
#endif
		}
	}

	/*
	 * Add length of each section until we find the one we're looking for.
	 */
	for (i = 0; i < NSECTIONS; i++) {
		cp = &data_sections[i];

		/*
		 * Align the section only if it's valid and contains data.  When
		 * searching for a specific section, align the section before
		 * breaking out of the loop.
		 */
		if (sect_valid(cp, mp) && cp->sect_type != SHT_NOBITS) {
			if (cp->sect_align > 1)
				len = P2ROUNDUP(len, cp->sect_align);

			if (sp != cp)
				len += sect_size(cp, mp);
		}

		if (sp == cp)
			break;
	}

	return (len);
}

/*
 * Given an index into the section table and a module pointer, returns the
 * data offset of the next section.
 */
static size_t
next_offset(int idx, struct module *mp)
{
	int i;

	for (i = idx + 1; i < NSECTIONS; i++) {
		if (sect_valid(&data_sections[i], mp))
			return (data_offset(&data_sections[i], mp));
	}

	return (data_offset(NULL, mp));
}

/*
 * Given a module pointer, return the total size needed for the file.
 */
static size_t
data_size(struct module *mp)
{
	return (data_offset(NULL, mp));
}

/*
 * Returns the size needed for all the headers in the file.
 */
static size_t
header_size(void)
{
	return (data_offset(&data_sections[0], NULL));
}

/* ARGSUSED */
vnode_t *
objfs_create_data(vnode_t *pvp)
{
	objfs_odirnode_t *onode = pvp->v_data;
	vnode_t *vp = gfs_file_create(sizeof (objfs_datanode_t), pvp,
	    objfs_ops_data);
	objfs_datanode_t *dnode = vp->v_data;

	dnode->objfs_data_gencount = onode->objfs_odir_modctl->mod_gencount;
	dnode->objfs_data_info.objfs_info_primary =
	    onode->objfs_odir_modctl->mod_prim;

	return (vp);
}

/* ARGSUSED */
static int
objfs_data_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	struct module *mp;
	timestruc_t now;

	if ((mp = objfs_data_lock(vp)) == NULL)
		return (EIO);

	vap->va_type = VREG;
	vap->va_mode = S_IRUSR | S_IRGRP | S_IROTH;
	vap->va_nodeid = gfs_file_inode(vp);
	vap->va_nlink = 1;
	vap->va_size = data_size(mp);
	gethrestime(&now);
	vap->va_atime = vap->va_ctime = vap->va_mtime = now;

	(void) objfs_common_getattr(vp, vap);

	objfs_data_unlock(vp);

	return (0);
}

/* ARGSUSED */
static int
objfs_data_access(vnode_t *vp, int mode, int flags, cred_t *cr,
	caller_context_t *ct)
{
	if (mode & (VWRITE|VEXEC))
		return (EACCES);

	return (0);
}

/* ARGSUSED */
int
objfs_data_open(vnode_t **cpp, int flag, cred_t *cr,
	caller_context_t *ct)
{
	if (flag & FWRITE)
		return (EINVAL);

	return (0);
}

/*
 * Iterate over all symbols in the table and output each one individually,
 * converting st_shndx to SHN_ABS for each symbol.
 */
static int
read_symtab(void *addr, size_t size, off_t offset, uio_t *uio)
{
#ifdef _LP64
	Elf64_Sym sym, *symtab;
#else
	Elf32_Sym sym, *symtab;
#endif
	off_t index;
	int error;

	symtab = addr;

	if (offset % sizeof (sym) != 0) {
		/*
		 * Be careful with the first symbol, as it is not
		 * symbol-aligned.
		 */
		off_t partial = offset % sizeof (sym);

		index = offset / sizeof (sym);

		sym = symtab[index];
		if (sym.st_shndx != SHN_UNDEF)
			sym.st_shndx = SHN_ABS;

		if ((error = uiomove((char *)&sym + partial,
		    sizeof (sym) - partial, UIO_READ, uio)) != 0 ||
		    uio->uio_resid <= 0)
			return (error);

		offset = (index + 1) * sizeof (sym);
	}

	ASSERT(size % sizeof (sym) == 0);

	for (index = offset / sizeof (sym); index < size / sizeof (sym);
	    index++) {

		sym = symtab[index];
		if (sym.st_shndx != SHN_UNDEF)
			sym.st_shndx = SHN_ABS;

		if ((error = uiomove((char *)&sym, sizeof (sym), UIO_READ,
		    uio)) != 0 || uio->uio_resid <= 0)
			return (error);
	}

	return (0);
}

/* ARGSUSED */
static int
objfs_data_read(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	int error = 0;
	objfs_datanode_t *dnode = vp->v_data;
	struct module *mp;
	off_t off;
#ifdef _LP64
	Elf64_Shdr shdr;
#else
	Elf32_Shdr shdr;
#endif
	int i, j;
	section_desc_t *sp;
	void *addr;
	int transidx[NSECTIONS];

	if ((mp = objfs_data_lock(vp)) == NULL)
		return (ENOENT);

	if (uio->uio_resid <= 0 || uio->uio_offset >= data_size(mp))
		goto error;

	/*
	 * Construct an array to translate from a generic section header index
	 * to an index specific for this object.
	 */
	for (i = 0, j = 0; i < NSECTIONS; i++) {
		transidx[i] = j;
		if (sect_valid(&data_sections[i], mp))
			j++;

	}

	/*
	 * Check to see if we're in the Elf header
	 */
	if (uio->uio_loffset < SECTION_OFFSET(0)) {
#ifdef _LP64
		Elf64_Ehdr ehdr;
#else
		Elf32_Ehdr ehdr;
#endif

		bzero(&ehdr, sizeof (ehdr));

		bcopy(ELFMAG, ehdr.e_ident, SELFMAG);
#ifdef _BIG_ENDIAN
		ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#else
		ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#endif
		ehdr.e_ident[EI_VERSION] = EV_CURRENT;

#ifdef _LP64
		ehdr.e_ident[EI_CLASS] = ELFCLASS64;
		ehdr.e_type = ELFCLASS64;
		ehdr.e_ehsize = sizeof (Elf64_Ehdr);
		ehdr.e_phentsize = sizeof (Elf64_Phdr);
		ehdr.e_shentsize = sizeof (Elf64_Shdr);
#else
		ehdr.e_ident[EI_CLASS] = ELFCLASS32;
		ehdr.e_type = ELFCLASS32;
		ehdr.e_ehsize = sizeof (Elf32_Ehdr);
		ehdr.e_phentsize = sizeof (Elf32_Phdr);
		ehdr.e_shentsize = sizeof (Elf32_Shdr);
#endif

#ifdef __sparc
#ifdef __sparcv9
		ehdr.e_machine = EM_SPARCV9;
#else
		ehdr.e_machine = EM_SPARC;
#endif
#elif defined(__amd64)
		ehdr.e_machine = EM_AMD64;
#else
		ehdr.e_machine = EM_386;
#endif

		ehdr.e_version = EV_CURRENT;
		ehdr.e_type = ET_SUNWPSEUDO;
		ehdr.e_shnum = 0;
		ehdr.e_shoff = SECTION_OFFSET(0);

		for (i = 0; i < NSECTIONS; i++) {
			if (strcmp(data_sections[i].sect_name,
			    ".shstrtab") == 0)
				ehdr.e_shstrndx = transidx[i];

			if (sect_valid(&data_sections[i], mp))
				ehdr.e_shnum++;
		}

		if ((error = uiomove((char *)&ehdr + uio->uio_loffset,
		    sizeof (ehdr) - uio->uio_loffset, UIO_READ, uio)) != 0 ||
		    uio->uio_resid <= 0)
			goto error;
	}

	/*
	 * Go through and construct section headers for each section.
	 */
	j = 0;
	for (i = 0; i < NSECTIONS; i++) {
		sp = &data_sections[i];

		if (!sect_valid(sp, mp))
			continue;

		if (uio->uio_loffset < SECTION_OFFSET(j+1)) {
			shdr.sh_link = transidx[sp->sect_link];
			shdr.sh_entsize = sp->sect_entsize;
			shdr.sh_info = 0;
			shdr.sh_name = sp->sect_str;
			shdr.sh_type = sp->sect_type;
			shdr.sh_flags = sp->sect_flags;
			shdr.sh_addr = sect_addr(sp, mp);
			shdr.sh_offset = data_offset(sp, mp);
			shdr.sh_size = sect_size(sp, mp);
			shdr.sh_addralign = sp->sect_align;

			off = uio->uio_loffset - SECTION_OFFSET(j);
			if ((error = uiomove((char *)&shdr + off,
			    sizeof (shdr) - off, UIO_READ, uio)) != 0 ||
			    uio->uio_resid <= 0)
				goto error;
		}

		j++;
	}

	/*
	 * Output the data for each section
	 */
	for (i = 0; i < NSECTIONS; i++) {
		size_t nextoff;
		sp = &data_sections[i];
		nextoff = next_offset(i, mp);
		if (sect_valid(sp, mp) && sp->sect_type != SHT_NOBITS &&
		    uio->uio_loffset < nextoff) {

			if (sp->sect_id == SECT_TYPE_INFO)
				addr = &dnode->objfs_data_info;
			else
				addr = (void *)sect_addr(sp, mp);
			off = uio->uio_loffset - data_offset(sp, mp);

			/*
			 * The symtab requires special processing to convert
			 * the st_shndx field to SHN_ABS.  Otherwise, simply
			 * copy the data in bulk.
			 */
			if (sp->sect_id == SECT_TYPE_SYMTAB)
				error = read_symtab(addr, sect_size(sp, mp),
				    off, uio);
			else
				error = uiomove((char *)addr + off,
				    sect_size(sp, mp) - off, UIO_READ, uio);

			if (error != 0 || uio->uio_resid <= 0)
				goto error;

			/*
			 * If the next section needs to be aligned, pad out with
			 * zeroes.
			 */
			if (uio->uio_loffset < nextoff) {
				uint64_t padding = 0;

				ASSERT(nextoff - uio->uio_loffset <
				    sizeof (uint64_t));

				if ((error = uiomove(&padding,
				    nextoff - uio->uio_loffset, UIO_READ,
				    uio)) != 0 || uio->uio_resid <= 0)
					goto error;

			}
		}
	}

error:
	objfs_data_unlock(vp);

	return (error);
}

/* ARGSUSED */
static int
objfs_data_seek(vnode_t *vp, offset_t off, offset_t *offp,
	caller_context_t *ct)
{
	return (0);
}

const fs_operation_def_t objfs_tops_data[] = {
	{ VOPNAME_OPEN,		{ .vop_open = objfs_data_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = objfs_common_close } },
	{ VOPNAME_IOCTL,	{ .error = fs_inval } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = objfs_data_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = objfs_data_access } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = gfs_vop_inactive } },
	{ VOPNAME_READ,		{ .vop_read = objfs_data_read } },
	{ VOPNAME_SEEK,		{ .vop_seek = objfs_data_seek } },
	{ VOPNAME_MAP,		{ .vop_map = gfs_vop_map } },
	{ NULL }
};
