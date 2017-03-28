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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

/*
 * dboot module utility functions for multiboot 2 tags processing.
 */

#include <sys/inttypes.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/multiboot2.h>
#include <sys/multiboot2_impl.h>

struct dboot_multiboot2_iterate_ctx;

typedef boolean_t (*dboot_multiboot2_iterate_cb_t)
	(int, multiboot_tag_t *, struct dboot_multiboot2_iterate_ctx *);

struct dboot_multiboot2_iterate_ctx {
	dboot_multiboot2_iterate_cb_t dboot_iter_callback;
	int dboot_iter_index;			/* item from set */
	uint32_t dboot_iter_tag;		/* tag to search */
	multiboot_tag_t *dboot_iter_tagp;	/* search result */
};

/*
 * Multiboot2 tag list elements are aligned to MULTIBOOT_TAG_ALIGN.
 * To get the next item from the list, we first add the tag's size
 * to the start of the current tag. Next, we round up that address to the
 * nearest MULTIBOOT_TAG_ALIGN address.
 */

static multiboot_tag_t *
dboot_multiboot2_first_tag(multiboot2_info_header_t *mbi)
{
	return (&mbi->mbi_tags[0]);
}

static multiboot_tag_t *
dboot_multiboot2_next_tag(multiboot_tag_t *tag)
{
	if (tag == NULL || tag->mb_type == MULTIBOOT_TAG_TYPE_END)
		return (NULL);

	return ((multiboot_tag_t *)P2ROUNDUP((uintptr_t)tag +
	    tag->mb_size, MULTIBOOT_TAG_ALIGN));
}

/*
 * Walk the tag list until we hit the first instance of a given tag or
 * the end of the list.
 * MB2_NEXT_TAG() will return NULL on end of list.
 */
static void *
dboot_multiboot2_find_tag_impl(multiboot_tag_t *tagp, uint32_t tag)
{
	while (tagp != NULL && tagp->mb_type != tag) {
		tagp = dboot_multiboot2_next_tag(tagp);
	}
	return (tagp);
}

/*
 * Walk the entire list to find the first instance of the given tag.
 */
void *
dboot_multiboot2_find_tag(multiboot2_info_header_t *mbi, uint32_t tag)
{
	multiboot_tag_t *tagp = dboot_multiboot2_first_tag(mbi);

	return (dboot_multiboot2_find_tag_impl(tagp, tag));
}

/*
 * dboot_multiboot2_iterate()
 *
 * While most tags in tag list are unique, the modules are specified
 * one module per tag and therefore we need an mechanism to process
 * tags in set.
 *
 * Arguments:
 *	mbi: multiboot info header
 *	data: callback context.
 *
 * Return value:
 *	Processed item count.
 * Callback returning B_TRUE will terminate the iteration.
 */
static int
dboot_multiboot2_iterate(multiboot2_info_header_t *mbi,
    struct dboot_multiboot2_iterate_ctx *ctx)
{
	dboot_multiboot2_iterate_cb_t callback = ctx->dboot_iter_callback;
	multiboot_tag_t *tagp;
	uint32_t tag = ctx->dboot_iter_tag;
	int index = 0;

	tagp = dboot_multiboot2_find_tag(mbi, tag);
	while (tagp != NULL) {
		if (callback != NULL) {
			if (callback(index, tagp, ctx) == B_TRUE) {
				return (index + 1);
			}
		}
		tagp = dboot_multiboot2_next_tag(tagp);
		tagp = dboot_multiboot2_find_tag_impl(tagp, tag);
		index++;
	}
	return (index);
}

char *
dboot_multiboot2_cmdline(multiboot2_info_header_t *mbi)
{
	multiboot_tag_string_t *tag;

	tag = dboot_multiboot2_find_tag(mbi, MULTIBOOT_TAG_TYPE_CMDLINE);

	if (tag != NULL)
		return (&tag->mb_string[0]);
	else
		return (NULL);
}

/*
 * Simple callback to index item in set.
 * Terminates iteration if the indexed item is found.
 */
static boolean_t
dboot_multiboot2_iterate_callback(int index, multiboot_tag_t *tagp,
    struct dboot_multiboot2_iterate_ctx *ctx)
{
	if (index == ctx->dboot_iter_index) {
		ctx->dboot_iter_tagp = tagp;
		return (B_TRUE);
	}
	return (B_FALSE);
}

int
dboot_multiboot2_modcount(multiboot2_info_header_t *mbi)
{
	struct dboot_multiboot2_iterate_ctx ctx = {
		.dboot_iter_callback = NULL,
		.dboot_iter_index = 0,
		.dboot_iter_tag = MULTIBOOT_TAG_TYPE_MODULE,
		.dboot_iter_tagp = NULL
	};

	return (dboot_multiboot2_iterate(mbi, &ctx));
}

uint32_t
dboot_multiboot2_modstart(multiboot2_info_header_t *mbi, int index)
{
	multiboot_tag_module_t *tagp;
	struct dboot_multiboot2_iterate_ctx ctx = {
		.dboot_iter_callback = dboot_multiboot2_iterate_callback,
		.dboot_iter_index = index,
		.dboot_iter_tag = MULTIBOOT_TAG_TYPE_MODULE,
		.dboot_iter_tagp = NULL
	};

	if (dboot_multiboot2_iterate(mbi, &ctx) != 0) {
		tagp = (multiboot_tag_module_t *)ctx.dboot_iter_tagp;

		if (tagp != NULL)
			return (tagp->mb_mod_start);
	}
	return (0);
}

uint32_t
dboot_multiboot2_modend(multiboot2_info_header_t *mbi, int index)
{
	multiboot_tag_module_t *tagp;
	struct dboot_multiboot2_iterate_ctx ctx = {
		.dboot_iter_callback = dboot_multiboot2_iterate_callback,
		.dboot_iter_index = index,
		.dboot_iter_tag = MULTIBOOT_TAG_TYPE_MODULE,
		.dboot_iter_tagp = NULL
	};

	if (dboot_multiboot2_iterate(mbi, &ctx) != 0) {
		tagp = (multiboot_tag_module_t *)ctx.dboot_iter_tagp;

		if (tagp != NULL)
			return (tagp->mb_mod_end);
	}
	return (0);
}

char *
dboot_multiboot2_modcmdline(multiboot2_info_header_t *mbi, int index)
{
	multiboot_tag_module_t *tagp;
	struct dboot_multiboot2_iterate_ctx ctx = {
		.dboot_iter_callback = dboot_multiboot2_iterate_callback,
		.dboot_iter_index = index,
		.dboot_iter_tag = MULTIBOOT_TAG_TYPE_MODULE,
		.dboot_iter_tagp = NULL
	};

	if (dboot_multiboot2_iterate(mbi, &ctx) != 0) {
		tagp = (multiboot_tag_module_t *)ctx.dboot_iter_tagp;

		if (tagp != NULL)
			return (&tagp->mb_cmdline[0]);
	}
	return (NULL);
}

multiboot_tag_mmap_t *
dboot_multiboot2_get_mmap_tagp(multiboot2_info_header_t *mbi)
{
	return (dboot_multiboot2_find_tag(mbi, MULTIBOOT_TAG_TYPE_MMAP));
}

boolean_t
dboot_multiboot2_basicmeminfo(multiboot2_info_header_t *mbi,
    uint32_t *lower, uint32_t *upper)
{
	multiboot_tag_basic_meminfo_t *mip;

	mip = dboot_multiboot2_find_tag(mbi, MULTIBOOT_TAG_TYPE_BASIC_MEMINFO);
	if (mip != NULL) {
		*lower = mip->mb_mem_lower;
		*upper = mip->mb_mem_upper;
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Return the type of mmap entry referenced by index.
 */
uint32_t
dboot_multiboot2_mmap_get_type(multiboot2_info_header_t *mbi,
    multiboot_tag_mmap_t *mb2_mmap_tagp, int index)
{
	multiboot_mmap_entry_t *mapentp;

	if (mb2_mmap_tagp == NULL)
		mb2_mmap_tagp = dboot_multiboot2_get_mmap_tagp(mbi);

	if (mb2_mmap_tagp == NULL)
		return (0);

	if (dboot_multiboot2_mmap_nentries(mbi, mb2_mmap_tagp) < index)
		return (0);

	mapentp = (multiboot_mmap_entry_t *)(mb2_mmap_tagp->mb_entries +
	    index * mb2_mmap_tagp->mb_entry_size);
	return (mapentp->mmap_type);
}

/*
 * Return the length of mmap entry referenced by index.
 */
uint64_t
dboot_multiboot2_mmap_get_length(multiboot2_info_header_t *mbi,
    multiboot_tag_mmap_t *mb2_mmap_tagp, int index)
{
	multiboot_mmap_entry_t *mapentp;

	if (mb2_mmap_tagp == NULL)
		mb2_mmap_tagp = dboot_multiboot2_get_mmap_tagp(mbi);

	if (mb2_mmap_tagp == NULL)
		return (0);

	if (dboot_multiboot2_mmap_nentries(mbi, mb2_mmap_tagp) < index)
		return (0);

	mapentp = (multiboot_mmap_entry_t *)(mb2_mmap_tagp->mb_entries +
	    index * mb2_mmap_tagp->mb_entry_size);
	return (mapentp->mmap_len);
}

/*
 * Return the address from mmap entry referenced by index.
 */
uint64_t
dboot_multiboot2_mmap_get_base(multiboot2_info_header_t *mbi,
    multiboot_tag_mmap_t *mb2_mmap_tagp, int index)
{
	multiboot_mmap_entry_t *mapentp;

	if (mb2_mmap_tagp == NULL)
		mb2_mmap_tagp = dboot_multiboot2_get_mmap_tagp(mbi);

	if (mb2_mmap_tagp == NULL)
		return (0);

	if (dboot_multiboot2_mmap_nentries(mbi, mb2_mmap_tagp) < index)
		return (0);

	mapentp = (multiboot_mmap_entry_t *)(mb2_mmap_tagp->mb_entries +
	    index * mb2_mmap_tagp->mb_entry_size);
	return (mapentp->mmap_addr);
}

/*
 * Count and return the number of mmap entries provided by the tag.
 */
int
dboot_multiboot2_mmap_nentries(multiboot2_info_header_t *mbi,
    multiboot_tag_mmap_t *mb2_mmap_tagp)
{
	if (mb2_mmap_tagp == NULL)
		mb2_mmap_tagp = dboot_multiboot2_get_mmap_tagp(mbi);

	if (mb2_mmap_tagp != NULL) {
		return ((mb2_mmap_tagp->mb_size -
		    offsetof(multiboot_tag_mmap_t, mb_entries)) /
		    mb2_mmap_tagp->mb_entry_size);
	}
	return (0);
}

/*
 * Return the highest address used by info header.
 */
paddr_t
dboot_multiboot2_highest_addr(multiboot2_info_header_t *mbi)
{
	return ((paddr_t)(uintptr_t)mbi + mbi->mbi_total_size);
}
