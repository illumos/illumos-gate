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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <note.h>
#include <errno.h>
#include <sys/mdesc.h>
#include <sys/mdesc_impl.h>
#include <sys/sysmacros.h>
#include "mdesc_mutable.h"

static void md_free_prop(mmd_t *mdp, md_prop_t *propp);
static void md_free_string(mmd_t *mdp, md_string_t *msp);
static void md_free_data_block(mmd_t *mdp, md_data_block_t *mdbp);

static uint32_t
md_byte_hash(uint8_t *bp, int len)
{
	uint32_t hash = 0;
	int i;

	for (i = 0; i < len; i++) {
		/* 5 bit rotation */
		hash = (hash >> 27) | (hash << 5) | bp[i];
	}

	return (hash);
}

static md_string_t *
md_find_string(mmd_t *mdp, char *strp, uint32_t *hashp)
{
	md_string_t *msp;
	uint32_t hash;

	hash = md_byte_hash((uint8_t *)strp, strlen(strp));

	if (hashp != NULL)
		*hashp = hash;

	CHAIN_ITER(mdp->string_list, msp) {
		if (msp->hash == hash && strcmp(msp->strp, strp) == 0)
			return (msp);
	}

	return (NULL);
}

static md_string_t *
md_new_string(mmd_t *mdp, char *strp)
{
	md_string_t *msp;
	uint32_t hash;

	msp = md_find_string(mdp, strp, &hash);
	if (msp == NULL) {
		msp = calloc(1, sizeof (md_string_t));
		if (msp == NULL)
			return (NULL);
		msp->strp = strdup(strp);
		if (msp->strp == NULL) {
			free(msp);
			return (NULL);
		}
		msp->size = strlen(strp) + 1;
		msp->hash = hash;
		msp->ref_cnt = 0;
		msp->build_offset = MD_OFFSET_UNDEF;
		CHAIN_ADD(mdp->string_list, msp);
	}
	msp->ref_cnt++;

	return (msp);
}

static md_data_block_t *
md_find_data_block(mmd_t *mdp, uint8_t *datap, int len, uint32_t *hashp)
{
	md_data_block_t *dbp;
	uint32_t hash;

	hash = md_byte_hash(datap, len);

	if (hashp != NULL)
		*hashp = hash;

	CHAIN_ITER(mdp->data_block_list, dbp) {
		if (dbp->size == len &&
		    dbp->hash == hash && bcmp(dbp->datap, datap, len) == 0)
			return (dbp);
	}

	return (NULL);
}

static md_data_block_t *
md_new_data_block(mmd_t *mdp, uint8_t *bufp, int len)
{
	md_data_block_t *dbp;
	uint32_t	hash;

	dbp = md_find_data_block(mdp, bufp, len, &hash);
	if (dbp == NULL) {
		dbp = calloc(1, sizeof (md_data_block_t));
		if (dbp == NULL)
			return (NULL);
		dbp->datap = malloc(len);
		if (dbp->datap == NULL) {
			free(dbp);
			return (NULL);
		}
		(void) memcpy(dbp->datap, bufp, len);
		dbp->size = len;
		dbp->hash = hash;
		dbp->ref_cnt = 0;
		dbp->build_offset = MD_OFFSET_UNDEF;
		CHAIN_ADD(mdp->data_block_list, dbp);
	}
	dbp->ref_cnt++;

	return (dbp);
}

md_node_t *
md_new_node(mmd_t *mdp, char *sp)
{
	md_node_t *nodep;

	nodep = calloc(1, sizeof (md_node_t));
	if (nodep == NULL)
		return (NULL);
	nodep->typep = md_new_string(mdp, sp);
	if (nodep->typep == NULL) {
		free(nodep);
		return (NULL);
	}
	CHAIN_ADD(mdp->node_list, nodep);

	return (nodep);
}

static md_prop_t *
md_new_property(mmd_t *mdp, md_node_t *nodep, uint8_t type, char *sp)
{
	md_prop_t *propp;

	propp = calloc(1, sizeof (md_prop_t));
	if (propp == NULL)
		return (NULL);
	propp->type = type;
	propp->sp = md_new_string(mdp, sp);
	if (propp->sp == NULL) {
		free(propp);
		return (NULL);
	}

	CHAIN_ADD(nodep->prop_list, propp);

	return (propp);
}

int
md_add_value_property(mmd_t *mdp, md_node_t *nodep, char *sp, uint64_t value)
{
	md_prop_t *propp;

	propp = md_new_property(mdp, nodep, MDET_PROP_VAL, sp);
	if (propp == NULL)
		return (ENOMEM);
	propp->d.value = value;
	return (0);
}

int
md_add_string_property(mmd_t *mdp, md_node_t *nodep, char *sp, char *bufp)
{
	md_prop_t *propp;
	md_data_block_t *dbp;

	dbp = md_new_data_block(mdp, (uint8_t *)bufp, strlen(bufp) + 1);
	if (dbp == NULL)
		return (ENOMEM);
	propp = md_new_property(mdp, nodep, MDET_PROP_STR, sp);
	if (propp == NULL) {
		md_free_data_block(mdp, dbp);
		return (ENOMEM);
	}
	propp->d.dbp = dbp;
	return (0);
}

int
md_add_data_property(mmd_t *mdp, md_node_t *nodep, char *sp, int len,
    uint8_t *bufp)
{
	md_prop_t *propp;
	md_data_block_t *dbp;

	dbp = md_new_data_block(mdp, bufp, len);
	if (dbp == NULL)
		return (ENOMEM);

	propp = md_new_property(mdp, nodep, MDET_PROP_DAT, sp);
	if (propp == NULL) {
		md_free_data_block(mdp, dbp);
		return (ENOMEM);
	}
	propp->d.dbp = dbp;
	return (0);
}

static int
md_add_arc_property(mmd_t *mdp, md_node_t *nodep, char *arcnamep,
    md_node_t *tgtnodep)
{
	md_prop_t *propp;

	propp = md_new_property(mdp, nodep, MDET_PROP_ARC, arcnamep);
	if (propp == NULL)
		return (ENOMEM);
	propp->d.arc.is_ptr = B_TRUE;
	propp->d.arc.val.nodep = tgtnodep;
	return (0);
}

md_node_t *
md_link_new_node(mmd_t *mdp, char *nodenamep, md_node_t *parentnodep,
    char *linktonewp, char *linkbackp)
{
	md_node_t *nodep;

	nodep = md_new_node(mdp, nodenamep);
	if (nodep == NULL)
		return (NULL);

	ASSERT(linktonewp != NULL);
	ASSERT(parentnodep != NULL && !parentnodep->deleted);

	if (md_add_arc_property(mdp, parentnodep, linktonewp, nodep) != 0) {
		return (NULL);
	}

	if (linkbackp != NULL) {
		if (md_add_arc_property(mdp,
		    nodep, linkbackp, parentnodep) != 0) {
			return (NULL);
		}
	}

	return (nodep);
}

void
md_destroy(mmd_t *mdp)
{
	md_node_t *nodep;

	for (nodep = CHAIN_START(mdp->node_list); nodep != NULL; ) {
		md_node_t *tmp_nodep;

		tmp_nodep = nodep->nextp;
		md_free_node(mdp, nodep);

		nodep = tmp_nodep;
	}

	/* should have deleted all the string refs by here */
	ASSERT(CHAIN_LENGTH(mdp->string_list) == 0);
	free(mdp);
}

void
md_free_node(mmd_t *mdp, md_node_t *nodep)
{
	md_prop_t *propp;

	if (nodep->typep != NULL)
		md_free_string(mdp, nodep->typep);

	for (propp = CHAIN_START(nodep->prop_list); propp != NULL; ) {
		md_prop_t *tmp_propp;

		tmp_propp = propp->nextp;
		md_free_prop(mdp, propp);

		propp = tmp_propp;
	}

	free(nodep);
}

static void
md_free_prop(mmd_t *mdp, md_prop_t *propp)
{
	if (propp->sp != NULL)
		md_free_string(mdp, propp->sp);

	switch (propp->type) {
	case MDET_PROP_VAL:
		break;

	case MDET_PROP_ARC:
		break;

	case MDET_PROP_STR:
	case MDET_PROP_DAT:
		md_free_data_block(mdp, propp->d.dbp);
		break;

	default:
		ASSERT(B_FALSE);
	}

	free(propp);
}

static void
md_free_string(mmd_t *mdp, md_string_t *msp)
{
	ASSERT(msp->ref_cnt > 0);

	msp->ref_cnt--;

	if (msp->ref_cnt == 0) {
		free(msp->strp);
		mdp->string_list.startp = msp->nextp;
		free(msp);
	}
}

static void
md_free_data_block(mmd_t *mdp, md_data_block_t *mdbp)
{
	ASSERT(mdbp->ref_cnt > 0);

	mdbp->ref_cnt--;

	if (mdbp->ref_cnt == 0) {
		free(mdbp->datap);
		mdp->data_block_list.startp = mdbp->nextp;
		free(mdbp);
	}
}

mmd_t *
md_new_md(void)
{
	return ((mmd_t *)calloc(1, sizeof (mmd_t)));
}

static void
md_fix_name(md_element_t *mdep, md_prop_t *propp)
{
	mdep->name_len = htomd8(propp->sp->size - 1);
	mdep->name_offset = htomd32(propp->sp->build_offset);
}

void
create_mde(md_element_t *mdep, int type, md_node_t *nodep, md_prop_t *propp)
{
	(void) memset(mdep, 0, MD_ELEMENT_SIZE);
	mdep->tag = htomd8(type);

	switch (type) {
	case MDET_NODE:
		mdep->d.prop_idx = htomd32(nodep->next_index);
		mdep->name_len = htomd8(nodep->typep->size - 1);
		mdep->name_offset = htomd32(nodep->typep->build_offset);
		break;

	case MDET_PROP_ARC:
		ASSERT(propp->d.arc.is_ptr);
		mdep->d.prop_idx = htomd64(propp->d.arc.val.nodep->build_index);
		md_fix_name(mdep, propp);
		break;

	case MDET_PROP_VAL:
		mdep->d.prop_val = htomd64(propp->d.value);
		md_fix_name(mdep, propp);
		break;

	case MDET_PROP_STR:
	case MDET_PROP_DAT:
		mdep->d.prop_data.offset = htomd32(propp->d.dbp->build_offset);
		mdep->d.prop_data.len = htomd32(propp->d.dbp->size);
		md_fix_name(mdep, propp);
		break;

	case MDET_NULL:
	case MDET_NODE_END:
	case MDET_LIST_END:
		break;

	default:
		ASSERT(B_FALSE);
	}
}

int
md_gen_bin(mmd_t *mdp, uint8_t **bufvalp)
{
	uint32_t offset;
	md_node_t *nodep;
	md_data_block_t *mdbp;
	md_string_t *msp;
	md_header_t *mdhp;
	md_element_t *mdep;
	uint32_t strings_size;
	uint32_t data_block_size;
	int total_size;
	uint8_t *bufferp;
	uint8_t *string_bufferp;
	uint8_t *data_block_bufferp;

	/*
	 * Skip through strings to compute offsets.
	 */
	offset = 0;
	for (msp = CHAIN_START(mdp->string_list); msp != NULL;
	    msp = msp->nextp) {
		msp->build_offset = offset;
		offset += msp->size;
	}
	strings_size = P2ROUNDUP(offset, MD_ALIGNMENT_SIZE);

	/*
	 * Skip through data blocks to compute offsets.
	 */

	offset = 0;
	for (mdbp = CHAIN_START(mdp->data_block_list); mdbp != NULL;
	    mdbp = mdbp->nextp) {
		mdbp->build_offset = offset;
		offset += mdbp->size;
		offset = P2ROUNDUP(offset, MD_ALIGNMENT_SIZE);
	}
	data_block_size = P2ROUNDUP(offset, MD_ALIGNMENT_SIZE);

	/*
	 * Compute the MD elements required to build the element list.
	 * For each node there is a node start and end, and one
	 * element for each property.
	 */

	offset = 0;
	for (nodep = CHAIN_START(mdp->node_list); nodep != NULL;
	    nodep = nodep->nextp) {
		nodep->build_index = offset;
		offset += 2 + CHAIN_LENGTH(nodep->prop_list);
		nodep->next_index = offset;
	}
	offset += 1;	/* add the LIST_END element */

	total_size = MD_HEADER_SIZE + offset * MD_ELEMENT_SIZE +
	    strings_size + data_block_size;

	/*
	 * Allocate output buffer.
	 */

	bufferp = calloc(total_size, sizeof (uint8_t));
	if (bufferp == NULL)
		return (0);

	/* LINTED */
	mdhp = (md_header_t *)bufferp;

	string_bufferp = bufferp + MD_HEADER_SIZE + offset * MD_ELEMENT_SIZE;
	data_block_bufferp = string_bufferp + strings_size;

	mdhp->transport_version = htomd32(MD_TRANSPORT_VERSION);
	mdhp->node_blk_sz = htomd32(offset * MD_ELEMENT_SIZE);
	mdhp->name_blk_sz = htomd32(strings_size);
	mdhp->data_blk_sz = htomd32(data_block_size);

	/*
	 * Build the element list.
	 * For each node there is a node start and end, and one
	 * element for each property.
	 */

	offset = 0;
	/* LINTED */
	mdep = (md_element_t *)(bufferp + MD_HEADER_SIZE);
	for (nodep = CHAIN_START(mdp->node_list); nodep != NULL;
	    nodep = nodep->nextp) {
		md_prop_t *propp;

		create_mde(mdep, MDET_NODE, nodep, NULL);
		mdep++;

		for (propp = CHAIN_START(nodep->prop_list); propp != NULL;
		    propp = propp->nextp) {
			create_mde(mdep, propp->type, nodep, propp);
			mdep++;
		}

		create_mde(mdep, MDET_NODE_END, NULL, NULL);
		mdep++;
	}

	create_mde(mdep, MDET_LIST_END, NULL, NULL);
	mdep++;

	/*
	 * Quick sanity check.
	 */

	ASSERT(((uint8_t *)mdep) == ((uint8_t *)string_bufferp));

	/*
	 * Skip through strings and stash them..
	 */

	offset = 0;
	for (msp = CHAIN_START(mdp->string_list); msp != NULL;
	    msp = msp->nextp) {
		(void) memcpy(string_bufferp + msp->build_offset, msp->strp,
		    msp->size);
	}

	/*
	 * Skip through data blocks and stash them.
	 */

	offset = 0;
	for (mdbp = CHAIN_START(mdp->data_block_list); mdbp != NULL;
	    mdbp = mdbp->nextp) {
		(void) memcpy(data_block_bufferp + mdbp->build_offset,
		    mdbp->datap, mdbp->size);
	}

	*bufvalp = bufferp;
	return (total_size);
}
