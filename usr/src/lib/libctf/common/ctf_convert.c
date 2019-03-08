/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Main conversion entry points. This has been designed such that there can be
 * any number of different conversion backends. Currently we only have one that
 * understands DWARFv2 (and bits of DWARFv4). Each backend should be placed in
 * the ctf_converters list and each will be tried in turn.
 */

#include <libctf_impl.h>
#include <assert.h>
#include <gelf.h>

ctf_convert_f ctf_converters[] = {
	ctf_dwarf_convert
};

#define	NCONVERTS	(sizeof (ctf_converters) / sizeof (ctf_convert_f))

ctf_hsc_ret_t
ctf_has_c_source(Elf *elf, char *errmsg, size_t errlen)
{
	ctf_hsc_ret_t ret = CHR_NO_C_SOURCE;
	Elf_Scn *scn, *strscn;
	Elf_Data *data, *strdata;
	GElf_Shdr shdr;
	ulong_t i;

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) == NULL) {
			(void) snprintf(errmsg, errlen,
			    "failed to get section header: %s",
			    elf_errmsg(elf_errno()));
			return (CHR_ERROR);
		}

		if (shdr.sh_type == SHT_SYMTAB)
			break;
	}

	if (scn == NULL)
		return (CHR_NO_C_SOURCE);

	if ((strscn = elf_getscn(elf, shdr.sh_link)) == NULL) {
		(void) snprintf(errmsg, errlen, "failed to get str section: %s",
		    elf_errmsg(elf_errno()));
		return (CHR_ERROR);
	}

	if ((data = elf_getdata(scn, NULL)) == NULL) {
		(void) snprintf(errmsg, errlen, "failed to read section: %s",
		    elf_errmsg(elf_errno()));
		return (CHR_ERROR);
	}

	if ((strdata = elf_getdata(strscn, NULL)) == NULL) {
		(void) snprintf(errmsg, errlen,
		    "failed to read string table: %s", elf_errmsg(elf_errno()));
		return (CHR_ERROR);
	}

	for (i = 0; i < shdr.sh_size / shdr.sh_entsize; i++) {
		GElf_Sym sym;
		const char *file;
		size_t len;

		if (gelf_getsym(data, i, &sym) == NULL) {
			(void) snprintf(errmsg, errlen,
			    "failed to read sym %lu: %s",
			    i, elf_errmsg(elf_errno()));
			return (CHR_ERROR);
		}

		if (GELF_ST_TYPE(sym.st_info) != STT_FILE)
			continue;

		file = (const char *)((uintptr_t)strdata->d_buf + sym.st_name);
		len = strlen(file);
		if (len >= 2 && strncmp(".c", &file[len - 2], 2) == 0) {
			ret = CHR_HAS_C_SOURCE;
			break;
		}
	}

	return (ret);
}

ctf_file_t *
ctf_elfconvert(int fd, Elf *elf, const char *label, uint_t nthrs, uint_t flags,
    int *errp, char *errbuf, size_t errlen)
{
	int err, i;
	ctf_file_t *fp = NULL;

	if (errp == NULL)
		errp = &err;

	if (elf == NULL) {
		*errp = EINVAL;
		return (NULL);
	}

	if (flags & ~CTF_ALLOW_MISSING_DEBUG) {
		*errp = EINVAL;
		return (NULL);
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		*errp = ECTF_FMT;
		return (NULL);
	}

	switch (ctf_has_c_source(elf, errbuf, errlen)) {
	case CHR_ERROR:
		*errp = ECTF_ELF;
		return (NULL);

	case CHR_NO_C_SOURCE:
		*errp = ECTF_CONVNOCSRC;
		return (NULL);

	default:
		break;
	}

	for (i = 0; i < NCONVERTS; i++) {
		fp = NULL;
		err = ctf_converters[i](fd, elf, nthrs, flags,
		    &fp, errbuf, errlen);

		if (err != ECTF_CONVNODEBUG)
			break;
	}

	if (err != 0) {
		assert(fp == NULL);
		*errp = err;
		return (NULL);
	}

	if (label != NULL) {
		if (ctf_add_label(fp, label, fp->ctf_typemax, 0) == CTF_ERR) {
			*errp = ctf_errno(fp);
			ctf_close(fp);
			return (NULL);
		}
		if (ctf_update(fp) == CTF_ERR) {
			*errp = ctf_errno(fp);
			ctf_close(fp);
			return (NULL);
		}
	}

	return (fp);
}

ctf_file_t *
ctf_fdconvert(int fd, const char *label, uint_t nthrs, uint_t flags, int *errp,
    char *errbuf, size_t errlen)
{
	int err;
	Elf *elf;
	ctf_file_t *fp;

	if (errp == NULL)
		errp = &err;

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		*errp = ECTF_FMT;
		return (NULL);
	}

	fp = ctf_elfconvert(fd, elf, label, nthrs, flags, errp, errbuf, errlen);

	(void) elf_end(elf);
	return (fp);
}
