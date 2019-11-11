// This tests sparse "-vcompound" output.
#define NULL ((void*)0)
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

// Do not list functions.
static int do_nothing(void)
{}

// no:
static inline int zero(void)
{
	return 0 / 1;
}

// no:
struct inventory {
	unsigned char	description[64];
	unsigned char	department[64];
	uint32_t	dept_number;
	uint32_t	item_cost;
	uint64_t	stock_number;
	uint32_t	tally[12];	// per month
};

// no
static struct inventory *get_inv(uint64_t stocknum)
{
	return NULL;
}

// no
union un {
	struct inventory inv;
	unsigned char	bytes[0];
};

// yes
static union un un;

// yes
static struct inventory	inven[100];

// no
typedef struct inventory	inventory_t;

// no
static struct inventory	*invptr;

// yes
static inventory_t		invent[10];

// no
static float		floater;
static double		double_float;

// yes
static float		floats[42];
static double		doubles[84];

// no
int main(void)
{
	// no, these are not global.
	struct inventory inv[10];
	inventory_t	invt[10];
	// what about statics?
	static struct inventory invtop;
	static inventory_t inv_top;
	static uint64_t stocknums[100];

	invptr = get_inv(42000);
	return 0;
}

/*
 * check-name: compound-sizes
 * check-command: sparse -vcompound $file
 * check-assert: _Alignof(long long) == 8
 *
 * check-error-start
compound-sizes.c:39:17: union un static [toplevel] un: compound size 192, alignment 8
compound-sizes.c:42:25: struct inventory static [toplevel] inven[100]: compound size 19200, alignment 8
compound-sizes.c:51:33: struct inventory static [toplevel] [usertype] invent[10]: compound size 1920, alignment 8
compound-sizes.c:58:25: float static [toplevel] floats[42]: compound size 168, alignment 4
compound-sizes.c:59:25: double static [toplevel] doubles[84]: compound size 672, alignment 8
 * check-error-end
 */
