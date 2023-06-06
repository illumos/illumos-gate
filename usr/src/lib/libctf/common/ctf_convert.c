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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Main conversion entry points. This has been designed such that there can be
 * any number of different conversion backends. Currently we only have one that
 * understands DWARFv2 and DWARFv4. Each backend should be placed in
 * the ctf_converters list and each will be tried in turn.
 */

#include <libctf_impl.h>
#include <assert.h>
#include <gelf.h>
#include <sys/list.h>

static ctf_convert_f ctf_converters[] = {
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

	if (scn == NULL) {
		ctf_dprintf("Could not find symbol table section\n");
		return (CHR_NO_C_SOURCE);
	}

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

	ctf_dprintf("Walking string table looking for .c files\n");

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

		file = (const char *)((uintptr_t)strdata->d_buf + sym.st_name);

		if (GELF_ST_TYPE(sym.st_info) != STT_FILE) {
			ctf_dprintf("'%s'\n", file);
			continue;
		}

		ctf_dprintf("'%s'; is a file\n", file);

		len = strlen(file);
		if (len >= 2 && strncmp(".c", &file[len - 2], 2) == 0) {
			ret = CHR_HAS_C_SOURCE;
			ctf_dprintf("Found .c file - '%s'\n", file);
			break;
		}
	}

	return (ret);
}

static ctf_file_t *
ctf_elfconvert(ctf_convert_t *cch, int fd, Elf *elf, int *errp, char *errbuf,
    size_t errlen)
{
	int err, i;
	ctf_file_t *fp = NULL;
	boolean_t no_c_src = B_FALSE;

	if (errp == NULL)
		errp = &err;

	if (elf == NULL) {
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
		if ((cch->cch_flags & CTF_FORCE_CONVERSION) == 0) {
			*errp = ECTF_CONVNOCSRC;
			return (NULL);
		}
		no_c_src = B_TRUE;
		break;

	default:
		break;
	}

	for (i = 0; i < NCONVERTS; i++) {
		fp = NULL;
		err = ctf_converters[i](cch, fd, elf, &fp, errbuf, errlen);

		if (err != ECTF_CONVNODEBUG)
			break;
	}

	if (err != 0) {
		assert(fp == NULL);
		/*
		 * If no C source was found but we attempted conversion anyway
		 * due to CTF_FORCE_CONVERSION, and none of the converters
		 * was able to process the object, return ECTF_CONVNOCSRC.
		 */
		if (no_c_src && err == ECTF_CONVNODEBUG)
			*errp = ECTF_CONVNOCSRC;
		else
			*errp = err;
		return (NULL);
	}

	if (cch->cch_label != NULL) {
		if (ctf_add_label(fp, cch->cch_label, fp->ctf_typemax, 0) ==
		    CTF_ERR) {
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

ctf_convert_t *
ctf_convert_init(int *errp)
{
	struct ctf_convert_handle *cch;
	int err;

	if (errp == NULL)
		errp = &err;
	*errp = 0;

	cch = ctf_alloc(sizeof (struct ctf_convert_handle));
	if (cch == NULL) {
		*errp = ENOMEM;
		return (NULL);
	}

	cch->cch_label = NULL;
	cch->cch_flags = 0;
	cch->cch_nthreads = CTF_CONVERT_DEFAULT_NTHREADS;
	cch->cch_batchsize = CTF_CONVERT_DEFAULT_BATCHSIZE;
	cch->cch_warncb = NULL;
	cch->cch_warncb_arg = NULL;
	list_create(&cch->cch_nodebug, sizeof (ctf_convert_filelist_t),
	    offsetof(ctf_convert_filelist_t, ccf_node));

	return (cch);
}

static void
ctf_convert_fini_filelist(ctf_convert_filelist_t *ccf)
{
	ctf_strfree(ccf->ccf_basename);
	ctf_free(ccf, sizeof (ctf_convert_filelist_t));
}

void
ctf_convert_fini(ctf_convert_t *cch)
{
	ctf_convert_filelist_t *ccf;

	ctf_strfree(cch->cch_label);
	while ((ccf = list_remove_head(&cch->cch_nodebug)) != NULL)
		ctf_convert_fini_filelist(ccf);
	list_destroy(&cch->cch_nodebug);

	ctf_free(cch, sizeof (struct ctf_convert_handle));
}

int
ctf_convert_set_nthreads(ctf_convert_t *cch, uint_t nthrs)
{
	if (nthrs == 0)
		return (EINVAL);
	cch->cch_nthreads = nthrs;
	return (0);
}

int
ctf_convert_set_batchsize(ctf_convert_t *cch, uint_t bsize)
{
	if (bsize == 0)
		return (EINVAL);
	cch->cch_batchsize = bsize;
	return (0);
}

int
ctf_convert_set_flags(ctf_convert_t *cch, ctf_convert_flag_t flags)
{
	if ((flags & ~CTF_CONVERT_ALL_FLAGS) != 0)
		return (EINVAL);
	cch->cch_flags = flags;
	return (0);
}

int
ctf_convert_set_label(ctf_convert_t *cch, const char *label)
{
	char *dup;

	if (label == NULL)
		return (EINVAL);

	dup = ctf_strdup(label);
	if (dup == NULL)
		return (ENOMEM);

	ctf_strfree(cch->cch_label);
	cch->cch_label = dup;
	return (0);
}

int
ctf_convert_set_warncb(ctf_convert_t *cch, ctf_convert_warn_f cb, void *arg)
{
	cch->cch_warncb = cb;
	cch->cch_warncb_arg = arg;
	return (0);
}

int
ctf_convert_add_ignore(ctf_convert_t *cch, const char *basename)
{
	ctf_convert_filelist_t *ccf;

	if (strchr(basename, '/') != NULL)
		return (EINVAL);

	ccf = ctf_alloc(sizeof (ctf_convert_filelist_t));
	if (ccf == NULL)
		return (ENOMEM);

	ccf->ccf_basename = ctf_strdup(basename);
	if (ccf->ccf_basename == NULL) {
		ctf_free(ccf, sizeof (ctf_convert_filelist_t));
		return (ENOMEM);
	}
	list_insert_tail(&cch->cch_nodebug, ccf);

	return (0);
}

ctf_file_t *
ctf_fdconvert(ctf_convert_t *cch, int fd, int *errp,
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

	fp = ctf_elfconvert(cch, fd, elf, errp, errbuf, errlen);

	(void) elf_end(elf);
	return (fp);
}
