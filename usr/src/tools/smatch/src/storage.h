#ifndef STORAGE_H
#define STORAGE_H

#include "allocate.h"
#include "lib.h"

/*
 * The "storage" that underlies an incoming/outgoing pseudo. It's
 * basically the backing store for a pseudo, and may be a real hardware
 * register, a stack slot or a static symbol. Or nothing at all,
 * since some pseudos can just be recalculated on the fly.
 */
enum storage_type {
	REG_UDEF,
	REG_REG,
	REG_STACK,
	REG_FRAME,
	REG_SYM,
	REG_ARG,
	REG_BAD,
};

enum inout_enum {
	STOR_IN,
	STOR_OUT
};

struct storage;
DECLARE_PTR_LIST(storage_ptr_list, struct storage *);

struct storage {
	enum storage_type type;
	int name;
	struct storage_ptr_list *users;
	union {
		int regno;
		int offset;
		struct symbol *sym;
	};
};

DECLARE_PTR_LIST(storage_list, struct storage);

struct storage_hash {
	struct basic_block *bb;
	pseudo_t pseudo;
	enum inout_enum inout;
	struct storage *storage;
	unsigned long flags;
};

DECLARE_PTR_LIST(storage_hash_list, struct storage_hash);

extern struct storage_hash_list *gather_storage(struct basic_block *, enum inout_enum);
extern void free_storage(void);
extern const char *show_storage(struct storage *);
extern void set_up_storage(struct entrypoint *);
struct storage *lookup_storage(struct basic_block *, pseudo_t, enum inout_enum);
void add_storage(struct storage *, struct basic_block *, pseudo_t, enum inout_enum);

DECLARE_ALLOCATOR(storage);
DECLARE_ALLOCATOR(storage_hash);

static inline struct storage *alloc_storage(void)
{
	return __alloc_storage(0);
}

static inline struct storage_hash *alloc_storage_hash(struct storage *s)
{
	struct storage_hash *entry = __alloc_storage_hash(0);
	struct storage **usep = &entry->storage;

	*usep = s;
	add_ptr_list(&s->users, usep);
	return entry;
}

#endif /* STORAGE_H */
