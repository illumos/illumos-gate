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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2021 Oxide Computer Company
 */

#ifndef	_KERNEL
#include <stdlib.h>
#include <strings.h>
#include <stddef.h>
#else
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stddef.h>
#endif	/* _KERNEL */

#include <core_shstrtab.h>

const char *shstrtab_data[STR_NUM] = {
	"",
	".SUNW_ctf",
	".symtab",
	".dynsym",
	".strtab",
	".dynstr",
	".shstrtab"
};

static void *
shstrtab_alloc(void)
{
#ifdef	_KERNEL
	return (kmem_zalloc(sizeof (shstrtab_ent_t),
	    KM_NOSLEEP | KM_NORMALPRI));
#else
	return (calloc(1, sizeof (shstrtab_ent_t)));
#endif
}

static void
shstrtab_free(shstrtab_ent_t *ent)
{
#ifdef	_KERNEL
	if (ent->sste_name != NULL) {
		strfree(ent->sste_name);
	}
	kmem_free(ent, sizeof (*ent));
#else
	free(ent->sste_name);
	free(ent);
#endif
}


boolean_t
shstrtab_ndx(shstrtab_t *s, const char *name, Elf32_Word *offp)
{
	shstrtab_ent_t *ent;

	for (ent = list_head(&s->sst_names); ent != NULL;
	    ent = list_next(&s->sst_names, ent)) {
		if (strcmp(name, ent->sste_name) == 0) {
			if (offp != NULL)
				*offp = ent->sste_offset;
			return (B_TRUE);
		}
	}

	ent = shstrtab_alloc();
	if (ent == NULL) {
		return (B_FALSE);
	}

	ent->sste_name = strdup(name);
	if (ent->sste_name == NULL) {
		shstrtab_free(ent);
		return (B_FALSE);
	}
	ent->sste_len = strlen(name) + 1;
	ent->sste_offset = s->sst_len;
	s->sst_len += ent->sste_len;

	list_insert_tail(&s->sst_names, ent);

	if (offp != NULL)
		*offp = ent->sste_offset;
	return (B_TRUE);
}

boolean_t
shstrtab_init(shstrtab_t *s)
{
	bzero(s, sizeof (*s));
	list_create(&s->sst_names, sizeof (shstrtab_ent_t),
	    offsetof(shstrtab_ent_t, sste_link));

	return (shstrtab_ndx(s, shstrtab_data[STR_NONE], NULL));
}

void
shstrtab_fini(shstrtab_t *s)
{
	shstrtab_ent_t *ent;

	if (s->sst_len == 0)
		return;

	while ((ent = list_remove_head(&s->sst_names)) != NULL) {
		shstrtab_free(ent);
	}
}

size_t
shstrtab_size(const shstrtab_t *s)
{
	return (s->sst_len);
}

void
shstrtab_dump(shstrtab_t *s, void *buf)
{
	size_t off = 0;

	for (shstrtab_ent_t *ent = list_head(&s->sst_names); ent != NULL;
	    ent = list_next(&s->sst_names, ent)) {
		bcopy(ent->sste_name, buf + off, ent->sste_len);
		off += ent->sste_len;
	}
}
