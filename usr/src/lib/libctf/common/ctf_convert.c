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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Main conversion entry points. This has been designed such that there can be
 * any number of different conversion backends. Currently we only have one that
 * understands DWARFv2 (and bits of DWARFv4). Each backend should be placed in
 * the ctf_converters list and each will be tried in turn.
 */

#include <libctf_impl.h>
#include <gelf.h>

ctf_convert_f ctf_converters[] = {
	ctf_dwarf_convert
};

#define	NCONVERTS	(sizeof (ctf_converters) / sizeof (ctf_convert_f))

typedef enum ctf_convert_source {
	CTFCONV_SOURCE_NONE = 0x0,
	CTFCONV_SOURCE_UNKNOWN = 0x01,
	CTFCONV_SOURCE_C = 0x02,
	CTFCONV_SOURCE_S = 0x04
} ctf_convert_source_t;

static void
ctf_convert_ftypes(Elf *elf, ctf_convert_source_t *types)
{
	int i;
	Elf_Scn *scn = NULL, *strscn;
	*types = CTFCONV_SOURCE_NONE;
	GElf_Shdr shdr;
	Elf_Data *data, *strdata;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {

		if (gelf_getshdr(scn, &shdr) == NULL)
			return;

		if (shdr.sh_type == SHT_SYMTAB)
			break;
	}

	if (scn == NULL)
		return;

	if ((strscn = elf_getscn(elf, shdr.sh_link)) == NULL)
		return;

	if ((data = elf_getdata(scn, NULL)) == NULL)
		return;

	if ((strdata = elf_getdata(strscn, NULL)) == NULL)
		return;

	for (i = 0; i < shdr.sh_size / shdr.sh_entsize; i++) {
		GElf_Sym sym;
		const char *file;
		size_t len;

		if (gelf_getsym(data, i, &sym) == NULL)
			return;

		if (GELF_ST_TYPE(sym.st_info) != STT_FILE)
			continue;

		file = (const char *)((uintptr_t)strdata->d_buf + sym.st_name);
		len = strlen(file);
		if (len < 2 || file[len - 2] != '.') {
			*types |= CTFCONV_SOURCE_UNKNOWN;
			continue;
		}

		switch (file[len - 1]) {
		case 'c':
			*types |= CTFCONV_SOURCE_C;
			break;
		case 'h':
			/* We traditionally ignore header files... */
			break;
		case 's':
			*types |= CTFCONV_SOURCE_S;
			break;
		default:
			*types |= CTFCONV_SOURCE_UNKNOWN;
			break;
		}
	}
}

static ctf_file_t *
ctf_elfconvert(int fd, Elf *elf, const char *label, uint_t nthrs, uint_t flags,
    int *errp, char *errbuf, size_t errlen)
{
	int err, i;
	ctf_file_t *fp = NULL;
	boolean_t notsup = B_TRUE;
	ctf_convert_source_t type;

	if (errp == NULL)
		errp = &err;

	if (elf == NULL) {
		*errp = EINVAL;
		return (NULL);
	}

	if (flags & ~CTF_CONVERT_F_IGNNONC) {
		*errp = EINVAL;
		return (NULL);
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		*errp = ECTF_FMT;
		return (NULL);
	}

	ctf_convert_ftypes(elf, &type);
	ctf_dprintf("got types: %d\n", type);
	if (flags & CTF_CONVERT_F_IGNNONC) {
		if (type == CTFCONV_SOURCE_NONE ||
		    (type & CTFCONV_SOURCE_UNKNOWN)) {
			*errp = ECTF_CONVNOCSRC;
			return (NULL);
		}
	}

	for (i = 0; i < NCONVERTS; i++) {
		ctf_conv_status_t cs;

		fp = NULL;
		cs = ctf_converters[i](fd, elf, nthrs, errp, &fp, errbuf,
		    errlen);
		if (cs == CTF_CONV_SUCCESS) {
			notsup = B_FALSE;
			break;
		}
		if (cs == CTF_CONV_ERROR) {
			fp = NULL;
			notsup = B_FALSE;
			break;
		}
	}

	if (notsup == B_TRUE) {
		if ((flags & CTF_CONVERT_F_IGNNONC) != 0 &&
		    (type & CTFCONV_SOURCE_C) == 0) {
			*errp = ECTF_CONVNOCSRC;
			return (NULL);
		}
		*errp = ECTF_NOCONVBKEND;
		return (NULL);
	}

	/*
	 * Succsesful conversion.
	 */
	if (fp != NULL) {
		if (label == NULL)
			label = "";
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
