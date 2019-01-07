#include <stdio.h>
#include "allocate.h"
#include "linearize.h"
#include "storage.h"

__DECLARE_ALLOCATOR(struct ptr_list, ptrlist);


typedef void (*get_t)(struct allocator_stats*);

static void show_stats(get_t get, struct allocator_stats * tot)
{
	struct allocator_stats x;

	if (get)
		get(&x);
	else
		x = *tot;
	fprintf(stderr, "%16s: %8d, %10ld, %10ld, %6.2f%%, %8.2f\n",
		x.name, x.allocations, x.useful_bytes, x.total_bytes,
		100 * (double) x.useful_bytes / (x.total_bytes ? : 1),
		(double) x.useful_bytes / (x.allocations ? : 1));

	tot->allocations += x.allocations;
	tot->useful_bytes += x.useful_bytes;
	tot->total_bytes += x.total_bytes;
}

void show_allocation_stats(void)
{
	struct allocator_stats tot = { .name = "total", };

	fprintf(stderr, "%16s: %8s, %10s, %10s, %7s, %8s\n", "allocator", "allocs",
		"bytes", "total", "%usage", "average");
	show_stats(get_token_stats, &tot);
	show_stats(get_ident_stats, &tot);
	show_stats(get_symbol_stats, &tot);
	show_stats(get_expression_stats, &tot);
	show_stats(get_statement_stats, &tot);
	show_stats(get_scope_stats, &tot);
	show_stats(get_basic_block_stats, &tot);
	show_stats(get_instruction_stats, &tot);
	show_stats(get_pseudo_stats, &tot);
	show_stats(get_pseudo_user_stats, &tot);
	show_stats(get_ptrlist_stats, &tot);
	show_stats(get_multijmp_stats, &tot);
	show_stats(get_asm_rules_stats, &tot);
	show_stats(get_asm_constraint_stats, &tot);
	show_stats(get_context_stats, &tot);
	show_stats(get_string_stats, &tot);
	show_stats(get_bytes_stats, &tot);
	//show_stats(get_storage_stats, &tot);
	//show_stats(get_storage_hash_stats, &tot);

	show_stats(NULL, &tot);
}

void report_stats(void)
{
	if (fmem_report)
		show_allocation_stats();
}
