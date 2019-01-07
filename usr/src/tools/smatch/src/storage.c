/*
 * Storage - associate pseudos with "storage" that keeps them alive
 * between basic blocks.  The aim is to be able to turn as much of
 * the global storage allocation problem as possible into a local
 * per-basic-block one.
 *
 * Copyright (C) 2004 Linus Torvalds
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "symbol.h"
#include "expression.h"
#include "linearize.h"
#include "storage.h"

ALLOCATOR(storage, "storages");
ALLOCATOR(storage_hash, "storage hash");

#define MAX_STORAGE_HASH 64
static struct storage_hash_list *storage_hash_table[MAX_STORAGE_HASH];

static inline unsigned int storage_hash(struct basic_block *bb, pseudo_t pseudo, enum inout_enum inout)
{
	unsigned hash = hashval(bb) + hashval(pseudo) + hashval(inout);
	hash += hash / MAX_STORAGE_HASH;
	return hash & (MAX_STORAGE_HASH-1);
}

static int hash_list_cmp(const void *_a, const void *_b)
{
	const struct storage_hash *a = _a;
	const struct storage_hash *b = _b;
	if (a->pseudo != b->pseudo)
		return a->pseudo < b->pseudo ? -1 : 1;
	return 0;
}

static void sort_hash_list(struct storage_hash_list **listp)
{
	sort_list((struct ptr_list **)listp, hash_list_cmp);
}

struct storage_hash_list *gather_storage(struct basic_block *bb, enum inout_enum inout)
{
	int i;
	struct storage_hash *entry, *prev;
	struct storage_hash_list *list = NULL;

	for (i = 0; i < MAX_STORAGE_HASH; i++) {
		struct storage_hash *hash;
		FOR_EACH_PTR(storage_hash_table[i], hash) {
			if (hash->bb == bb && hash->inout == inout)
				add_ptr_list(&list, hash);
		} END_FOR_EACH_PTR(hash);
	}
	sort_hash_list(&list);

	prev = NULL;
	FOR_EACH_PTR(list, entry) {
		if (prev && entry->pseudo == prev->pseudo) {
			assert(entry == prev);
			DELETE_CURRENT_PTR(entry);
		}
		prev = entry;
	} END_FOR_EACH_PTR(entry);
	PACK_PTR_LIST(&list);
	return list;
}

static void name_storage(void)
{
	int i;
	int name = 0;

	for (i = 0; i < MAX_STORAGE_HASH; i++) {
		struct storage_hash *hash;
		FOR_EACH_PTR(storage_hash_table[i], hash) {
			struct storage *storage = hash->storage;
			if (storage->name)
				continue;
			storage->name = ++name;
		} END_FOR_EACH_PTR(hash);
	}
}

struct storage *lookup_storage(struct basic_block *bb, pseudo_t pseudo, enum inout_enum inout)
{
	struct storage_hash_list *list = storage_hash_table[storage_hash(bb,pseudo,inout)];
	struct storage_hash *hash;

	FOR_EACH_PTR(list, hash) {
		if (hash->bb == bb && hash->pseudo == pseudo && hash->inout == inout)
			return hash->storage;
	} END_FOR_EACH_PTR(hash);
	return NULL;
}

void add_storage(struct storage *storage, struct basic_block *bb, pseudo_t pseudo, enum inout_enum inout)
{
	struct storage_hash_list **listp = storage_hash_table + storage_hash(bb,pseudo,inout);
	struct storage_hash *hash = alloc_storage_hash(storage);

	hash->bb = bb;
	hash->pseudo = pseudo;
	hash->inout = inout;

	add_ptr_list(listp, hash);
}


static int storage_hash_cmp(const void *_a, const void *_b)
{
	const struct storage_hash *a = _a;
	const struct storage_hash *b = _b;
	struct storage *aa = a->storage;
	struct storage *bb = b->storage;

	if (a->bb != b->bb)
		return a->bb < b->bb ? -1 : 1;
	if (a->inout != b->inout)
		return a->inout < b->inout ? -1 : 1;
	if (aa->type != bb->type)
		return aa->type < bb->type ? -1 : 1;
	if (aa->regno != bb->regno)
		return aa->regno < bb->regno ? -1 : 1;
	return 0;
}

static void vrfy_storage(struct storage_hash_list **listp)
{
	struct storage_hash *entry, *last;

	sort_list((struct ptr_list **)listp, storage_hash_cmp);
	last = NULL;
	FOR_EACH_PTR(*listp, entry) {
		if (last) {
			struct storage *a = last->storage;
			struct storage *b = entry->storage;
			if (a == b)
				continue;
			if (last->bb == entry->bb
			    && last->inout == entry->inout
			    && a->type != REG_UDEF
			    && a->type == b->type
			    && a->regno == b->regno) {
				printf("\t BAD: same storage as %s in %p: %s (%s and %s)\n",
					last->inout == STOR_IN ? "input" : "output",
					last->bb,
					show_storage(a),
					show_pseudo(last->pseudo),
					show_pseudo(entry->pseudo));
			}
		}
		last = entry;
	} END_FOR_EACH_PTR(entry);
}

void free_storage(void)
{
	int i;

	for (i = 0; i < MAX_STORAGE_HASH; i++) {
		vrfy_storage(storage_hash_table + i);
		free_ptr_list(storage_hash_table + i);
	}
}

const char *show_storage(struct storage *s)
{
	static char buffer[1024];
	if (!s)
		return "none";
	switch (s->type) {
	case REG_REG:
		sprintf(buffer, "reg%d (%d)", s->regno, s->name);
		break;
	case REG_STACK:
		sprintf(buffer, "%d(SP) (%d)", s->offset, s->name);
		break;
	case REG_ARG:
		sprintf(buffer, "ARG%d (%d)", s->regno, s->name);
		break;
	default:
		sprintf(buffer, "%d:%d (%d)", s->type, s->regno, s->name);
		break;
	}
	return buffer;
}

/*
 * Combine two storage allocations into one.
 *
 * We just randomly pick one over the other, and replace
 * the other uses.
 */
static struct storage * combine_storage(struct storage *src, struct storage *dst)
{
	struct storage **usep;

	/* Remove uses of "src_storage", replace with "dst" */
	FOR_EACH_PTR(src->users, usep) {
		assert(*usep == src);
		*usep = dst;
		add_ptr_list(&dst->users, usep);
	} END_FOR_EACH_PTR(usep);

	/* Mark it unused */
	src->type = REG_BAD;
	src->users = NULL;
	return dst;
}

static void set_up_bb_storage(struct basic_block *bb)
{
	struct basic_block *child;

	FOR_EACH_PTR(bb->children, child) {
		pseudo_t pseudo;
		FOR_EACH_PTR(child->needs, pseudo) {
			struct storage *child_in, *parent_out;

			parent_out = lookup_storage(bb, pseudo, STOR_OUT);
			child_in = lookup_storage(child, pseudo, STOR_IN);

			if (parent_out) {
				if (!child_in) {
					add_storage(parent_out, child, pseudo, STOR_IN);
					continue;
				}
				if (parent_out == child_in)
					continue;
				combine_storage(parent_out, child_in);
				continue;
			}
			if (child_in) {
				add_storage(child_in, bb, pseudo, STOR_OUT);
				continue;
			}
			parent_out = alloc_storage();
			add_storage(parent_out, bb, pseudo, STOR_OUT);
			add_storage(parent_out, child, pseudo, STOR_IN);
		} END_FOR_EACH_PTR(pseudo);
	} END_FOR_EACH_PTR(child);
}

static void set_up_argument_storage(struct entrypoint *ep, struct basic_block *bb)
{
	pseudo_t arg;

	FOR_EACH_PTR(bb->needs, arg) {
		struct storage *storage = alloc_storage();

		/* FIXME! Totally made-up argument passing conventions */
		if (arg->type == PSEUDO_ARG) {
			storage->type = REG_ARG;
			storage->regno = arg->nr;
		}
		add_storage(storage, bb, arg, STOR_IN);
	} END_FOR_EACH_PTR(arg);
}

/*
 * One phi-source may feed multiple phi nodes. If so, combine
 * the storage output for this bb into one entry to reduce
 * storage pressure.
 */
static void combine_phi_storage(struct basic_block *bb)
{
	struct instruction *insn;
	FOR_EACH_PTR(bb->insns, insn) {
		struct instruction *phi;
		struct storage *last;

		if (!insn->bb || insn->opcode != OP_PHISOURCE)
			continue;
		last = NULL;
		FOR_EACH_PTR(insn->phi_users, phi) {
			struct storage *storage = lookup_storage(bb, phi->target, STOR_OUT);
			if (!storage) {
				DELETE_CURRENT_PTR(phi);
				continue;
			}
			if (last && storage != last)
				storage = combine_storage(storage, last);
			last = storage;
		} END_FOR_EACH_PTR(phi);
		PACK_PTR_LIST(&insn->phi_users);
	} END_FOR_EACH_PTR(insn);
}

void set_up_storage(struct entrypoint *ep)
{
	struct basic_block *bb;

	/* First set up storage for the incoming arguments */
	set_up_argument_storage(ep, ep->entry->bb);

	/* Then do a list of all the inter-bb storage */
	FOR_EACH_PTR(ep->bbs, bb) {
		set_up_bb_storage(bb);
		combine_phi_storage(bb);
	} END_FOR_EACH_PTR(bb);

	name_storage();
}
