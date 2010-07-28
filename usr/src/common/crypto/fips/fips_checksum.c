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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */


#include <fips/fips_checksum.h>


#ifdef	_KERNEL
#define	FIPS_ALLOC(size)	kmem_alloc(size, KM_SLEEP)
#define	FIPS_FREE(buf, size)	kmem_free(buf, size)
#define	FIPS_READ_FILE		kobj_read_file
#define	ERRLOG0(str)		cmn_err(CE_NOTE, str)
#define	ERRLOG1(fmt, arg)	cmn_err(CE_NOTE, fmt, arg)
#include <sys/sunddi.h>

struct _buf *kobj_open_file(char *name);
int kobj_read_file(struct _buf *file, char *buf, uint_t size, uint_t off);
#else

#define	FIPS_ALLOC(size)	malloc(size)
#define	FIPS_FREE(buf, size)	free(buf)
#define	FIPS_READ_FILE		fips_read_file
#define	ERRLOG0(str)		(void) printf(str)
#define	ERRLOG1(fmt, arg)	(void) printf(fmt, arg)
#endif

#define	NUM_SECTIONS	(sizeof (checked_sec_names) / sizeof (char *))

static char *checked_sec_names[] = {
	".strtab",
	".dynamic",
	".compcom",
	".comment",
	".dynstr",
	".shstrtab",
	".rela.text",
	".rela.data",
	".text",
	".rodata",
	".rodata1",
	".data",
	".symtab",
	".SUNW_ctf",
	".bss"
};


static int
#ifdef	_KERNEL
process_section(SHA1_CTX *shactx, Elf64_Shdr *section, struct _buf *file,
    char *shstrtab)
#else
process_section(SHA1_CTX *shactx, Elf64_Shdr *section, int file,
    char *shstrtab)
#endif
{
	size_t		size, offs;
	char		*name;
	int		doit = 0;
	char		*buf;
	int		i;

	size = section->sh_size;
	offs = section->sh_offset;
	name = shstrtab + section->sh_name;
	for (i = 0; i < NUM_SECTIONS; i++) {
		if (strncmp(name, checked_sec_names[i],
		    strlen(checked_sec_names[i]) + 1) == 0) {
			doit++;
			break;
		}
	}

	if (!doit) {
		return (0);
	}

	/* hash the size of .bss section */
	if (strcmp(name, ".bss") == 0) {
		char	szstr[32];
		(void) snprintf(szstr, sizeof (szstr), "%ld", size);
		SHA1Update(shactx, szstr, strlen(szstr));
		return (0);
	}


	/* hash the contents of the section */
	if ((buf = FIPS_ALLOC(size)) == NULL) {
		ERRLOG1("Not enough memory for section %s\n", name);
		return (-1);
	}

	if (FIPS_READ_FILE(file, buf, size, offs) < 0) {
		FIPS_FREE(buf, size);
		return (-2);
	}

	SHA1Update(shactx, buf, size);

	FIPS_FREE(buf, size);

	return (0);
}

int
#ifdef	_KERNEL
fips_calc_checksum(struct _buf *file, Elf64_Ehdr *ehdr, char *sha1buf)
#else
fips_calc_checksum(int file, Elf64_Ehdr *ehdr, char *sha1buf)
#endif
{
	unsigned int	size, numsec;
	Elf64_Shdr	*shdrs;
	Elf64_Shdr	*section;
	SHA1_CTX	sha1ctx;
	char		*shstrtab;
	int		i;

	numsec = ehdr->e_shnum;
	size = ehdr->e_shentsize * numsec;
	if ((shdrs = (Elf64_Shdr *)FIPS_ALLOC(size)) == NULL) {
		ERRLOG0("Not enough memory for shdrs\n");
		return (FAILURE);
	}
	if (FIPS_READ_FILE(file, (char *)shdrs, size, ehdr->e_shoff) < 0) {
		return (FAILURE);
	}

	/* Obtain the .shstrtab data buffer */
	section = &(shdrs[ehdr->e_shstrndx]);
	size = section->sh_size;
	if ((shstrtab = (char *)FIPS_ALLOC(size)) == NULL) {
		ERRLOG0("Not enough memory for shstrtab\n");
		return (FAILURE);
	}
	if (FIPS_READ_FILE(file, shstrtab, size, section->sh_offset) < 0) {
		return (FAILURE);
	}

	SHA1Init(&sha1ctx);
	for (i = 0; i < numsec; i++) {
		if (process_section(&sha1ctx, &(shdrs[i]),
		    file, shstrtab) < 0) {
			return (FAILURE);
		}
	}
	SHA1Final(sha1buf, &sha1ctx);

	return (0);
}


#ifndef	_KERNEL

int
fips_read_file(int fd, char *buf, int size, int offs)
{
	int	i;

	if (lseek(fd, offs, SEEK_SET) == (off_t)(-1)) {
		(void) fprintf(stderr,
		    "lseek returned an error for file %d\n", fd);
		return (-1);
	}
	while ((i = read(fd, buf, size)) >= 0) {
		if (size == i) {
			break;
		} else {
			size -= i;
			buf += i;
		}
	}
	if (i < 0) {
		(void) fprintf(stderr, "read failed for file %d\n", fd);
		return (-2);
	}

	return (0);
}

#else

static int
get_fips_section(Elf64_Ehdr *ehdr, struct _buf *file, char *expected_checksum)
{
	unsigned int	shdrssz, shstrtabsz, numsec;
	Elf64_Shdr	*shdrs = NULL;
	Elf64_Shdr	*section;
	char		*shstrtab = NULL;
	char		*name;
	int		rv = FAILURE;
	int		i;

	numsec = ehdr->e_shnum;
	shdrssz = ehdr->e_shentsize * numsec;
	if ((shdrs = (Elf64_Shdr *)FIPS_ALLOC(shdrssz)) == NULL) {
		ERRLOG0("Not enough memory for shdrs\n");
		return (FAILURE);
	}
	if (FIPS_READ_FILE(file, (char *)shdrs, shdrssz, ehdr->e_shoff) < 0) {
		goto exit;
	}

	/* Obtain the .shstrtab data buffer */
	section = &(shdrs[ehdr->e_shstrndx]);
	shstrtabsz = section->sh_size;
	if ((shstrtab = (char *)FIPS_ALLOC(shstrtabsz)) == NULL) {
		ERRLOG0("Not enough memory for shstrtab\n");
		goto exit;
	}
	if (FIPS_READ_FILE(file, shstrtab, shstrtabsz,
	    section->sh_offset) < 0) {
		goto exit;
	}

	for (i = 0; i < numsec; i++) {
		section = &shdrs[i];
		name = shstrtab + section->sh_name;
		/* Get the checksum stored in the .SUNW_fips section */
		if (strcmp(name, ".SUNW_fips") == 0) {
			if (section->sh_size != SHA1_DIGEST_LENGTH) {
				goto exit;
			}
			if (FIPS_READ_FILE(file, expected_checksum,
			    section->sh_size, section->sh_offset) < 0) {
				goto exit;
			}
			rv = 0;
			goto exit;
		}
	}


exit:
	if (shdrs != NULL) {
		FIPS_FREE(shdrs, shdrssz);
	}
	if (shstrtab != NULL) {
		FIPS_FREE(shstrtab, shstrtabsz);
	}

	return (rv);
}


int
fips_check_module(char *modname, void *_initaddr)
{
	struct modctl	*modctlp = NULL;
	struct module	*mp = NULL;
	struct _buf	*file;
	char		*filename;
	Elf64_Ehdr	ehdr;
	unsigned int	size, i;
	char		sha1buf[SHA1_DIGEST_LENGTH];
	char		expected_checksum[SHA1_DIGEST_LENGTH];

	modctlp = mod_find_by_filename(NULL, modname);
	if (modctlp == NULL) {
		ERRLOG1("module with modname %s not found\n", modname);
		return (FAILURE);
	}
	mp = (struct module *)modctlp->mod_mp;
	if (mp != NULL && mp->filename != NULL) {
		filename = mp->filename;
	} else {
		/* filename does not exist */
		return (FAILURE);
	}
	if ((mp->text > (char *)_initaddr) ||
	    (mp->text + mp->text_size < (char *)_initaddr)) {
		ERRLOG1("_init() is not in module %s\n", modname);
		return (FAILURE);
	}

	if ((file = kobj_open_file(filename)) == (struct _buf *)-1) {
		ERRLOG1("Cannot open %s\n", filename);
		return (FAILURE);
	}
	/* Read the ELF header */
	size =  sizeof (ehdr);
	if (kobj_read_file(file, (char *)(&ehdr), size, 0) < 0) {
		goto fail_exit;
	}

	/* check if it is an ELF file */
	for (i = 0; i < SELFMAG; i++) {
		if (ehdr.e_ident[i] != ELFMAG[i]) {
			ERRLOG1("%s not an elf file\n", filename);
			goto fail_exit;
		}
	}

	/* check if it is relocatable */
	if (ehdr.e_type != ET_REL) {
		ERRLOG1("%s isn't a relocatable (ET_REL) "
		    "module\n", filename);
		goto fail_exit;
	}

	if (fips_calc_checksum(file, &ehdr, sha1buf) < 0) {
		goto fail_exit;
	}

	if (get_fips_section(&ehdr, file, expected_checksum) < 0) {
		goto fail_exit;
	}

	if (memcmp(sha1buf, expected_checksum, SHA1_DIGEST_LENGTH) != 0) {
		goto fail_exit;
	}

	kobj_close_file(file);

	return (SUCCESS);

fail_exit:

	kobj_close_file(file);

	return (FAILURE);

}

#endif
