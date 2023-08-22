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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <string.h>
#include "_libelf.h"
#include "decl.h"
#include "msg.h"


/*
 * Find elf or it's class from a pointer to an Elf_Data struct.
 * Warning:  this Assumes that the Elf_Data is part of a libelf
 * Dnode structure, which is expected to be true for any Elf_Data
 * passed into libelf *except* for the xlatetof() and xlatetom() functions.
 */
#define	EDATA_CLASS(edata) \
	(((Dnode *)(edata))->db_scn->s_elf->ed_class)

#define	EDATA_ELF(edata) \
	(((Dnode *)(edata))->db_scn->s_elf)

#define	EDATA_SCN(edata) \
	(((Dnode *)(edata))->db_scn)

#define	EDATA_READLOCKS(edata) \
	READLOCKS(EDATA_ELF((edata)), EDATA_SCN((edata)))

#define	EDATA_READUNLOCKS(edata) \
	READUNLOCKS(EDATA_ELF((edata)), EDATA_SCN((edata)))


size_t
gelf_fsize(Elf * elf, Elf_Type type, size_t count, unsigned ver)
{
	int class;

	if (elf == NULL)
		return (0);

	class = gelf_getclass(elf);
	if (class == ELFCLASS32)
		return (elf32_fsize(type, count, ver));
	else if (class == ELFCLASS64)
		return (elf64_fsize(type, count, ver));

	_elf_seterr(EREQ_CLASS, 0);
	return (0);
}


int
gelf_getclass(Elf *elf)
{
	if (elf == NULL)
		return (0);

	/*
	 * Don't rely on the idents, a new ehdr doesn't have it!
	 */
	return (elf->ed_class);
}


GElf_Ehdr *
gelf_getehdr(Elf *elf, GElf_Ehdr *dst)
{
	int class;

	if (elf == NULL)
		return (NULL);

	class = gelf_getclass(elf);
	if (class == ELFCLASS32) {
		Elf32_Ehdr * e		= elf32_getehdr(elf);

		if (e == NULL)
			return (NULL);

		ELFRLOCK(elf);
		(void) memcpy(dst->e_ident, e->e_ident, EI_NIDENT);
		dst->e_type		= e->e_type;
		dst->e_machine		= e->e_machine;
		dst->e_version		= e->e_version;
		dst->e_entry		= (Elf64_Addr)e->e_entry;
		dst->e_phoff		= (Elf64_Off)e->e_phoff;
		dst->e_shoff		= (Elf64_Off)e->e_shoff;
		dst->e_flags		= e->e_flags;
		dst->e_ehsize		= e->e_ehsize;
		dst->e_phentsize	= e->e_phentsize;
		dst->e_phnum		= e->e_phnum;
		dst->e_shentsize	= e->e_shentsize;
		dst->e_shnum		= e->e_shnum;
		dst->e_shstrndx		= e->e_shstrndx;
		ELFUNLOCK(elf);

		return (dst);
	} else if (class == ELFCLASS64) {
		Elf64_Ehdr * e		= elf64_getehdr(elf);

		if (e == NULL)
			return (NULL);

		ELFRLOCK(elf);
		*dst			= *e;
		ELFUNLOCK(elf);

		return (dst);
	}

	_elf_seterr(EREQ_CLASS, 0);
	return (NULL);
}


int
gelf_update_ehdr(Elf *elf, GElf_Ehdr *src)
{
	int class;

	if (elf == NULL)
		return (0);

	/*
	 * In case elf isn't cooked.
	 */
	class = gelf_getclass(elf);
	if (class == ELFCLASSNONE)
		class = src->e_ident[EI_CLASS];


	if (class == ELFCLASS32) {
		Elf32_Ehdr * d	= elf32_getehdr(elf);

		if (d == NULL)
			return (0);

		ELFWLOCK(elf);
		(void) memcpy(d->e_ident, src->e_ident, EI_NIDENT);
		d->e_type	= src->e_type;
		d->e_machine	= src->e_machine;
		d->e_version	= src->e_version;
		/* LINTED */
		d->e_entry	= (Elf32_Addr)src->e_entry;
		/* LINTED */
		d->e_phoff	= (Elf32_Off)src->e_phoff;
		/* LINTED */
		d->e_shoff	= (Elf32_Off)src->e_shoff;
		/* could memcpy the rest of these... */
		d->e_flags	= src->e_flags;
		d->e_ehsize	= src->e_ehsize;
		d->e_phentsize	= src->e_phentsize;
		d->e_phnum	= src->e_phnum;
		d->e_shentsize	= src->e_shentsize;
		d->e_shnum	= src->e_shnum;
		d->e_shstrndx	= src->e_shstrndx;
		ELFUNLOCK(elf);

		return (1);
	} else if (class == ELFCLASS64) {
		Elf64_Ehdr * d	= elf64_getehdr(elf);

		if (d == NULL)
			return (0);

		ELFWLOCK(elf);
		*d		= *(Elf64_Ehdr *)src;
		ELFUNLOCK(elf);

		return (1);
	}

	_elf_seterr(EREQ_CLASS, 0);
	return (0);
}


unsigned long
gelf_newehdr(Elf *elf, int class)
{
	if (elf == NULL)
		return (0);

	if (class == ELFCLASS32)
		return ((unsigned long)elf32_newehdr(elf));
	else if (class == ELFCLASS64)
		return ((unsigned long)elf64_newehdr(elf));

	_elf_seterr(EREQ_CLASS, 0);
	return (0);
}


GElf_Phdr *
gelf_getphdr(Elf *elf, int ndx, GElf_Phdr *dst)
{
	int		class;
	size_t		phnum;

	if (elf == NULL)
		return (NULL);

	if (elf_getphdrnum(elf, &phnum) == -1)
		return (NULL);

	if (phnum <= ndx) {
		_elf_seterr(EREQ_RAND, 0);
		return (NULL);
	}

	class = gelf_getclass(elf);
	if ((class != ELFCLASS32) && (class != ELFCLASS64)) {
		_elf_seterr(EREQ_CLASS, 0);
		return (NULL);
	}

	if (class == ELFCLASS32) {
		Elf32_Phdr *p	= &((Elf32_Phdr *)elf32_getphdr(elf))[ndx];

		ELFRLOCK(elf);
		dst->p_type	= p->p_type;
		dst->p_flags	= p->p_flags;
		dst->p_offset	= (Elf64_Off)p->p_offset;
		dst->p_vaddr	= (Elf64_Addr)p->p_vaddr;
		dst->p_paddr	= (Elf64_Addr)p->p_paddr;
		dst->p_filesz	= (Elf64_Xword)p->p_filesz;
		dst->p_memsz	= (Elf64_Xword)p->p_memsz;
		dst->p_align	= (Elf64_Xword)p->p_align;
		ELFUNLOCK(elf);
	} else if (class == ELFCLASS64) {
		Elf64_Phdr *phdrs = elf64_getphdr(elf);
		ELFRLOCK(elf);
		*dst = ((GElf_Phdr *)phdrs)[ndx];
		ELFUNLOCK(elf);
	}

	return (dst);
}


int
gelf_update_phdr(Elf *elf, int ndx, GElf_Phdr *src)
{
	int		class;
	size_t		phnum;

	if (elf == NULL)
		return (0);

	if (elf_getphdrnum(elf, &phnum) == -1)
		return (0);

	if (phnum < ndx) {
		_elf_seterr(EREQ_RAND, 0);
		return (0);
	}

	class = gelf_getclass(elf);
	if (class == ELFCLASS32) {
		Elf32_Phdr *dst	= &((Elf32_Phdr *)elf32_getphdr(elf))[ndx];
		ELFWLOCK(elf);
		dst->p_type	= src->p_type;
		dst->p_flags	= src->p_flags;
		/* LINTED */
		dst->p_offset	= (Elf32_Off)src->p_offset;
		/* LINTED */
		dst->p_vaddr	= (Elf32_Addr)src->p_vaddr;
		/* LINTED */
		dst->p_paddr	= (Elf32_Addr)src->p_paddr;
		/* LINTED */
		dst->p_filesz	= (Elf32_Word)src->p_filesz;
		/* LINTED */
		dst->p_memsz	= (Elf32_Word)src->p_memsz;
		/* LINTED */
		dst->p_align	= (Elf32_Word)src->p_align;
		ELFUNLOCK(elf);
	} else if (class == ELFCLASS64) {
		Elf64_Phdr *dst = elf64_getphdr(elf);
		ELFWLOCK(elf);
		dst[ndx] = *(GElf_Phdr *)src;
		ELFUNLOCK(elf);
	} else {
		_elf_seterr(EREQ_CLASS, 0);
		return (0);
	}
	return (1);
}


unsigned long
gelf_newphdr(Elf *elf, size_t phnum)
{
	int class;

	if (elf == NULL)
		return (0);

	class = gelf_getclass(elf);
	if (class == ELFCLASS32)
		return ((unsigned long)elf32_newphdr(elf, phnum));
	else if (class == ELFCLASS64)
		return ((unsigned long)elf64_newphdr(elf, phnum));

	_elf_seterr(EREQ_CLASS, 0);
	return (0);
}


GElf_Shdr *
gelf_getshdr(Elf_Scn *scn,  GElf_Shdr *dst)
{
	if (scn == NULL)
		return (NULL);

	if (scn->s_elf->ed_class == ELFCLASS32) {
		Elf32_Shdr *s		= elf32_getshdr(scn);

		if (s == NULL)
			return (NULL);

		READLOCKS(scn->s_elf, scn);
		dst->sh_name		= s->sh_name;
		dst->sh_type		= s->sh_type;
		dst->sh_flags		= (Elf64_Xword)s->sh_flags;
		dst->sh_addr		= (Elf64_Addr)s->sh_addr;
		dst->sh_offset		= (Elf64_Off)s->sh_offset;
		dst->sh_size		= (Elf64_Xword)s->sh_size;
		dst->sh_link		= s->sh_link;
		dst->sh_info		= s->sh_info;
		dst->sh_addralign	= (Elf64_Xword)s->sh_addralign;
		dst->sh_entsize		= (Elf64_Xword)s->sh_entsize;
		READUNLOCKS(scn->s_elf, scn);

		return (dst);
	} else if (scn->s_elf->ed_class == ELFCLASS64) {
		Elf64_Shdr *s		= elf64_getshdr(scn);

		if (s == NULL)
			return (NULL);

		READLOCKS(scn->s_elf, scn);
		*dst			= *(Elf64_Shdr *)s;
		READUNLOCKS(scn->s_elf, scn);

		return (dst);
	}

	_elf_seterr(EREQ_CLASS, 0);
	return (NULL);
}


int
gelf_update_shdr(Elf_Scn *scn, GElf_Shdr *src)
{
	if (scn == NULL)
		return (0);

	if (scn->s_elf->ed_class == ELFCLASS32) {
		Elf32_Shdr *dst	= elf32_getshdr(scn);

		if (dst == NULL)
			return (0);

		ELFWLOCK(scn->s_elf);
		dst->sh_name		= src->sh_name;
		dst->sh_type		= src->sh_type;
		/* LINTED */
		dst->sh_flags		= (Elf32_Word)src->sh_flags;
		/* LINTED */
		dst->sh_addr		= (Elf32_Addr)src->sh_addr;
		/* LINTED */
		dst->sh_offset		= (Elf32_Off) src->sh_offset;
		/* LINTED */
		dst->sh_size		= (Elf32_Word)src->sh_size;
		dst->sh_link		= src->sh_link;
		dst->sh_info		= src->sh_info;
		/* LINTED */
		dst->sh_addralign	= (Elf32_Word)src->sh_addralign;
		/* LINTED */
		dst->sh_entsize		= (Elf32_Word)src->sh_entsize;

		ELFUNLOCK(scn->s_elf);
		return (1);
	} else if (scn->s_elf->ed_class == ELFCLASS64) {
		Elf64_Shdr * dst	= elf64_getshdr(scn);

		if (dst == NULL)
			return (0);

		ELFWLOCK(scn->s_elf);
		*dst			= *(Elf64_Shdr *)src;
		ELFUNLOCK(scn->s_elf);
		return (1);
	}

	_elf_seterr(EREQ_CLASS, 0);
	return (0);
}


/*
 * gelf_xlatetof/gelf_xlatetom use 'elf' to find the class
 * because these are the odd case where the Elf_Data structs
 * might not have been allocated by libelf (and therefore
 * don't have Dnode's associated with them).
 */
Elf_Data *
gelf_xlatetof(Elf *elf, Elf_Data *dst, const Elf_Data *src, unsigned encode)
{
	int class;

	if ((elf == NULL) || (dst == NULL) || (src == NULL))
		return (NULL);

	class = gelf_getclass(elf);
	if (class == ELFCLASS32)
		return (elf32_xlatetof(dst, src, encode));
	else if (class == ELFCLASS64)
		return (elf64_xlatetof(dst, src, encode));

	_elf_seterr(EREQ_CLASS, 0);
	return (NULL);
}


Elf_Data *
gelf_xlatetom(Elf *elf, Elf_Data *dst, const Elf_Data *src, unsigned encode)
{
	int class;

	if ((elf == NULL) || (dst == NULL) || (src == NULL))
		return (NULL);

	class = gelf_getclass(elf);
	if (class == ELFCLASS32)
		return (elf32_xlatetom(dst, src, encode));
	else if (class == ELFCLASS64)
		return (elf64_xlatetom(dst, src, encode));

	_elf_seterr(EREQ_CLASS, 0);
	return (NULL);
}


GElf_Sym *
gelf_getsym(Elf_Data * data, int ndx, GElf_Sym * dst)
{
	int	class;
	size_t	entsize;

	if (data == NULL)
		return (NULL);

	class = EDATA_CLASS(data);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Sym);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Sym);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (NULL);
	}

	EDATA_READLOCKS(data);

	if ((entsize * ndx) >= data->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		dst = NULL;
	} else if (class == ELFCLASS32) {
		Elf32_Sym	*s;
		s		= &(((Elf32_Sym *)data->d_buf)[ndx]);
		dst->st_name	= s->st_name;
		dst->st_value	= (Elf64_Addr)s->st_value;
		dst->st_size	= (Elf64_Xword)s->st_size;
		dst->st_info	= ELF64_ST_INFO(ELF32_ST_BIND(s->st_info),
		    ELF32_ST_TYPE(s->st_info));
		dst->st_other	= s->st_other;
		dst->st_shndx	= s->st_shndx;
	} else
		*dst = ((GElf_Sym *)data->d_buf)[ndx];

	EDATA_READUNLOCKS(data);
	return (dst);
}


int
gelf_update_sym(Elf_Data *dst, int ndx, GElf_Sym *src)
{
	int	class, rc = 1;
	size_t	entsize;

	if (dst == NULL)
		return (0);

	class = EDATA_CLASS(dst);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Sym);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Sym);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (0);
	}

	ELFWLOCK(EDATA_ELF(dst));

	if ((entsize * ndx) >= dst->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		rc = 0;
	} else if (class == ELFCLASS32) {
		Elf32_Sym * d;

		d		= &(((Elf32_Sym *)dst->d_buf)[ndx]);
		d->st_name	= src->st_name;
		/* LINTED */
		d->st_value	= (Elf32_Addr)src->st_value;
		/* LINTED */
		d->st_size	= (Elf32_Word)src->st_size;
		d->st_info	= ELF32_ST_INFO(ELF64_ST_BIND(src->st_info),
		    ELF64_ST_TYPE(src->st_info));
		d->st_other	= src->st_other;
		d->st_shndx	= src->st_shndx;
	} else
		((Elf64_Sym *)dst->d_buf)[ndx] = *((Elf64_Sym *)src);

	ELFUNLOCK(EDATA_ELF(dst));
	return (rc);
}


GElf_Syminfo *
gelf_getsyminfo(Elf_Data *data, int ndx, GElf_Syminfo *dst)
{
	int	class;
	size_t	entsize;

	if (data == NULL)
		return (NULL);

	class = EDATA_CLASS(data);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Syminfo);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Syminfo);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (NULL);
	}
	EDATA_READLOCKS(data);

	if ((entsize * ndx) >= data->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		dst = NULL;
	} else if (class == ELFCLASS32) {
		Elf32_Syminfo *	si;

		si		= &(((Elf32_Syminfo *)data->d_buf)[ndx]);
		dst->si_boundto = si->si_boundto;
		dst->si_flags	= si->si_flags;
	} else
		*dst		= ((GElf_Syminfo *)data->d_buf)[ndx];

	EDATA_READUNLOCKS(data);
	return (dst);
}

int
gelf_update_syminfo(Elf_Data *dst, int ndx, GElf_Syminfo *src)
{
	int	class, rc = 1;
	size_t	entsize;

	if (dst == NULL)
		return (0);

	class = EDATA_CLASS(dst);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Syminfo);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Syminfo);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (0);
	}
	ELFWLOCK(EDATA_ELF(dst));

	if ((entsize * ndx) >= dst->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		rc = 0;
	} else if (class == ELFCLASS32) {
		Elf32_Syminfo * d	= &(((Elf32_Syminfo *)dst->d_buf)[ndx]);
		d->si_boundto		= src->si_boundto;
		d->si_flags		= src->si_flags;
	} else
		((Elf64_Syminfo *)dst->d_buf)[ndx] = *((Elf64_Syminfo *)src);

	ELFUNLOCK(EDATA_ELF(dst));
	return (rc);
}

GElf_Dyn *
gelf_getdyn(Elf_Data *data, int ndx, GElf_Dyn *dst)
{
	int	class;
	size_t	entsize;

	if (data == NULL)
		return (NULL);

	class = EDATA_CLASS(data);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Dyn);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Dyn);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (NULL);
	}
	EDATA_READLOCKS(data);

	if ((entsize * ndx) >= data->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		dst = NULL;
	} else if (class == ELFCLASS32) {
		Elf32_Dyn * d = &((Elf32_Dyn *)data->d_buf)[ndx];

		dst->d_tag	= (Elf32_Sword)d->d_tag;
		dst->d_un.d_val	= (Elf32_Word) d->d_un.d_val;
	} else
		*dst = ((Elf64_Dyn *)data->d_buf)[ndx];

	EDATA_READUNLOCKS(data);
	return (dst);
}


int
gelf_update_dyn(Elf_Data *dst, int ndx, GElf_Dyn *src)
{
	int	class, rc = 1;
	size_t	entsize;

	if (dst == NULL)
		return (0);

	class = EDATA_CLASS(dst);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Dyn);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Dyn);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (0);
	}
	ELFWLOCK(EDATA_ELF(dst));

	if ((entsize * ndx) >= dst->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		rc = 0;
	} else if (class == ELFCLASS32) {
		Elf32_Dyn * d = &((Elf32_Dyn *)dst->d_buf)[ndx];

		/* LINTED */
		d->d_tag	= (Elf32_Word)src->d_tag;
		/* LINTED */
		d->d_un.d_val	= (Elf32_Word)src->d_un.d_val;
	} else
		((Elf64_Dyn *)dst->d_buf)[ndx] = *(Elf64_Dyn*)src;

	ELFUNLOCK(EDATA_ELF(dst));
	return (rc);
}



GElf_Sym *
gelf_getsymshndx(Elf_Data *symdata, Elf_Data *shndxdata,
    int ndx, GElf_Sym *symptr, Elf32_Word *xshndx)
{
	if (gelf_getsym(symdata, ndx, symptr) == 0)
		return (NULL);
	if (shndxdata && xshndx) {
		EDATA_READLOCKS(shndxdata);
		if ((ndx * sizeof (Elf32_Word)) >= shndxdata->d_size) {
			_elf_seterr(EREQ_RAND, 0);
			EDATA_READUNLOCKS(shndxdata);
			return (NULL);
		}
		*xshndx = (((Elf32_Word *)shndxdata->d_buf)[ndx]);
		EDATA_READUNLOCKS(shndxdata);
	} else {
		*xshndx = 0;
	}
	return (symptr);
}

int
gelf_update_symshndx(Elf_Data *symdata, Elf_Data *shndxdata,
    int ndx, GElf_Sym *symptr, Elf32_Word xshndx)
{
	if (gelf_update_sym(symdata, ndx, symptr) == 0)
		return (0);
	if (shndxdata) {
		ELFWLOCK(EDATA_ELF(shndxdata));
		if ((ndx * sizeof (Elf32_Word)) >= shndxdata->d_size) {
			_elf_seterr(EREQ_RAND, 0);
			ELFUNLOCK(EDATA_ELF(shndxdata));
			return (0);
		}
		((Elf32_Word *)shndxdata->d_buf)[ndx] = xshndx;
		ELFUNLOCK(EDATA_ELF(shndxdata));
	}
	return (1);
}


GElf_Move *
gelf_getmove(Elf_Data *src, int ndx, GElf_Move *dst)
{
	int	class;
	size_t	entsize;

	if (src == NULL)
		return (NULL);

	class = EDATA_CLASS(src);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Move);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Move);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (NULL);
	}
	EDATA_READLOCKS(src);

	if ((entsize * ndx) >= src->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		dst = NULL;
	} else if (class == ELFCLASS32) {
		Elf32_Move * m = &((Elf32_Move *)src->d_buf)[ndx];

		dst->m_poffset = (Elf64_Word)m->m_poffset;
		dst->m_repeat = (Elf64_Xword)m->m_repeat;
		dst->m_stride = (Elf64_Half)m->m_stride;
		dst->m_value = (Elf64_Xword)m->m_value;
		dst->m_info = ELF64_M_INFO(ELF32_M_SYM(m->m_info),
		    ELF32_M_SIZE(m->m_info));
	} else {
		*dst = ((Elf64_Move *)src->d_buf)[ndx];
	}

	EDATA_READUNLOCKS(src);
	return (dst);
}

int
gelf_update_move(Elf_Data *dest, int ndx, GElf_Move *src)
{
	int	class, rc = 1;
	size_t	entsize;

	if (dest == NULL)
		return (0);

	class = EDATA_CLASS(dest);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Move);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Move);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (0);
	}
	ELFWLOCK(EDATA_ELF(dest));

	if ((entsize * ndx) >= dest->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		rc = 0;
	} else if (class == ELFCLASS32) {
		Elf32_Move * m = &((Elf32_Move *)dest->d_buf)[ndx];

		m->m_poffset = (Elf32_Word)src->m_poffset;
		m->m_repeat = (Elf32_Half)src->m_repeat;
		m->m_stride = (Elf32_Half)src->m_stride;
		m->m_value = (Elf32_Lword)src->m_value;
		m->m_info = (Elf32_Word)ELF32_M_INFO(ELF64_M_SYM(src->m_info),
		    ELF64_M_SIZE(src->m_info));
	} else {
		((Elf64_Move *)dest->d_buf)[ndx] = *(Elf64_Move *)src;
	}

	ELFUNLOCK(EDATA_ELF(dest));
	return (rc);
}


GElf_Rela *
gelf_getrela(Elf_Data *src, int ndx, GElf_Rela *dst)
{
	int	class;
	size_t	entsize;

	if (src == NULL)
		return (NULL);

	class = EDATA_CLASS(src);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Rela);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Rela);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (NULL);
	}
	EDATA_READLOCKS(src);

	if ((entsize * ndx) >= src->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		dst = NULL;
	} else if (class == ELFCLASS32) {
		Elf32_Rela * r = &((Elf32_Rela *)src->d_buf)[ndx];

		dst->r_offset	= (GElf_Addr)r->r_offset;
		dst->r_addend	= (GElf_Addr)r->r_addend;

		/*
		 * Elf32 will never have the extra data field that
		 * Elf64's r_info field can have, so ignore it.
		 */
		/* LINTED */
		dst->r_info	= ELF64_R_INFO(
		    ELF32_R_SYM(r->r_info),
		    ELF32_R_TYPE(r->r_info));
	} else
		*dst = ((Elf64_Rela *)src->d_buf)[ndx];

	EDATA_READUNLOCKS(src);
	return (dst);
}


int
gelf_update_rela(Elf_Data *dst, int ndx, GElf_Rela *src)
{
	int	class, rc = 1;
	size_t	entsize;

	if (dst == NULL)
		return (0);

	class = EDATA_CLASS(dst);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Rela);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Rela);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (0);
	}
	ELFWLOCK(EDATA_ELF(dst));

	if ((entsize * ndx) >= dst->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		rc = 0;
	} else if (class == ELFCLASS32) {
		Elf32_Rela * r = &((Elf32_Rela *)dst->d_buf)[ndx];

		/* LINTED */
		r->r_offset	= (Elf32_Addr) src->r_offset;
		/* LINTED */
		r->r_addend	= (Elf32_Sword)src->r_addend;

		/*
		 * Elf32 will never have the extra data field that
		 * Elf64's r_info field can have, so ignore it.
		 */
		/* LINTED */
		r->r_info	= ELF32_R_INFO(ELF64_R_SYM(src->r_info),
		    ELF64_R_TYPE(src->r_info));
	} else {
		((Elf64_Rela *)dst->d_buf)[ndx] = *(Elf64_Rela *)src;
	}

	ELFUNLOCK(EDATA_ELF(dst));

	return (rc);
}


GElf_Rel *
gelf_getrel(Elf_Data *src, int ndx, GElf_Rel *dst)
{
	int	class;
	size_t	entsize;

	if (src == NULL)
		return (NULL);

	class = EDATA_CLASS(src);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Rel);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Rel);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (NULL);
	}
	EDATA_READLOCKS(src);

	if ((entsize * ndx) >= src->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		dst = NULL;
	} else if (class == ELFCLASS32) {
		Elf32_Rel * r = &((Elf32_Rel *)src->d_buf)[ndx];

		dst->r_offset	= (GElf_Addr)r->r_offset;

		/*
		 * Elf32 will never have the extra data field that
		 * Elf64's r_info field can have, so ignore it.
		 */
		/* LINTED */
		dst->r_info	= ELF64_R_INFO(ELF32_R_SYM(r->r_info),
		    ELF32_R_TYPE(r->r_info));
	} else
		*dst = ((Elf64_Rel *)src->d_buf)[ndx];

	EDATA_READUNLOCKS(src);
	return (dst);
}


int
gelf_update_rel(Elf_Data *dst, int ndx, GElf_Rel *src)
{
	int	class, rc = 1;
	size_t	entsize;

	if (dst == NULL)
		return (0);

	class = EDATA_CLASS(dst);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Rel);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Rel);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (0);
	}
	ELFWLOCK(EDATA_ELF(dst));

	if ((entsize * ndx) >= dst->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		rc = 0;
	} else if (class == ELFCLASS32) {
		Elf32_Rel * r = &((Elf32_Rel *)dst->d_buf)[ndx];

		/* LINTED */
		r->r_offset	= (Elf32_Addr) src->r_offset;

		/*
		 * Elf32 will never have the extra data field that
		 * Elf64's r_info field can have, so ignore it.
		 */
		/* LINTED */
		r->r_info	= ELF32_R_INFO(ELF64_R_SYM(src->r_info),
		    ELF64_R_TYPE(src->r_info));

	} else {
		((Elf64_Rel *)dst->d_buf)[ndx] = *(Elf64_Rel *)src;
	}

	ELFUNLOCK(EDATA_ELF(dst));
	return (rc);
}

long
gelf_checksum(Elf *elf)
{
	int class = gelf_getclass(elf);

	if (class == ELFCLASS32)
		return (elf32_checksum(elf));
	else if (class == ELFCLASS64)
		return (elf64_checksum(elf));

	_elf_seterr(EREQ_CLASS, 0);
	return (0);
}

GElf_Cap *
gelf_getcap(Elf_Data *data, int ndx, GElf_Cap *dst)
{
	int	class;
	size_t	entsize;

	if (data == NULL)
		return (NULL);

	class = EDATA_CLASS(data);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Cap);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Cap);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (NULL);
	}

	EDATA_READLOCKS(data);

	if ((entsize * ndx) >= data->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		dst = NULL;
	} else if (class == ELFCLASS32) {
		Elf32_Cap	*c = &(((Elf32_Cap *)data->d_buf)[ndx]);

		dst->c_tag = (Elf64_Xword)c->c_tag;
		dst->c_un.c_val = (Elf64_Xword)c->c_un.c_val;
	} else
		*dst = ((GElf_Cap *)data->d_buf)[ndx];

	EDATA_READUNLOCKS(data);
	return (dst);
}

int
gelf_update_cap(Elf_Data *dst, int ndx, GElf_Cap *src)
{
	int	class, rc = 1;
	size_t	entsize;

	if (dst == NULL)
		return (0);

	class = EDATA_CLASS(dst);
	if (class == ELFCLASS32)
		entsize = sizeof (Elf32_Cap);
	else if (class == ELFCLASS64)
		entsize = sizeof (GElf_Cap);
	else {
		_elf_seterr(EREQ_CLASS, 0);
		return (0);
	}

	ELFWLOCK(EDATA_ELF(dst));

	if ((entsize * ndx) >= dst->d_size) {
		_elf_seterr(EREQ_RAND, 0);
		rc = 0;
	} else if (class == ELFCLASS32) {
		Elf32_Cap	*c = &(((Elf32_Cap *)dst->d_buf)[ndx]);

		c->c_tag = (Elf32_Word)src->c_tag;
		c->c_un.c_val = (Elf32_Word)src->c_un.c_val;
	} else
		((Elf64_Cap *)dst->d_buf)[ndx] = *((Elf64_Cap *)src);

	ELFUNLOCK(EDATA_ELF(dst));
	return (rc);
}

/*
 * If the specified object has a dynamic section, and that section
 * contains a DT_FLAGS_1 entry, then return the value of that entry.
 * Otherwise, return 0.
 */
GElf_Xword
_gelf_getdynval(Elf *elf, GElf_Sxword tag)
{
	Elf_Scn *scn = NULL;
	Elf_Data *data;
	GElf_Shdr shdr;
	GElf_Dyn dyn;
	int i, n;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) == NULL)
			break;
		if (shdr.sh_type != SHT_DYNAMIC)
			continue;
		data = elf_getdata(scn, NULL);
		if (data != NULL) {
			n = shdr.sh_size / shdr.sh_entsize;
			for (i = 0; i < n; i++) {
				(void) gelf_getdyn(data, i, &dyn);
				if (dyn.d_tag == tag) {
					return (dyn.d_un.d_val);
				}
			}
		}
		break;
	}
	return (0);
}

GElf_Xword
_gelf_getdyndtflags_1(Elf *elf)
{
	return (_gelf_getdynval(elf, DT_FLAGS_1));
}
