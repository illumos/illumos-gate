#ifndef BITMAP_H
#define BITMAP_H

#define BITS_IN_LONG	(sizeof(unsigned long)*8)
#define LONGS(x)	((x + BITS_IN_LONG - 1) & -BITS_IN_LONG)

/* Every bitmap gets its own type */
#define DECLARE_BITMAP(name, x) unsigned long name[LONGS(x)]

static inline int test_bit(unsigned int nr, unsigned long *bitmap)
{
	unsigned long offset = nr / BITS_IN_LONG;
	unsigned long bit = nr & (BITS_IN_LONG-1);
	return (bitmap[offset] >> bit) & 1;
}

static inline void set_bit(unsigned int nr, unsigned long *bitmap)
{
	unsigned long offset = nr / BITS_IN_LONG;
	unsigned long bit = nr & (BITS_IN_LONG-1);
	bitmap[offset] |= 1UL << bit;
}

static inline void clear_bit(unsigned int nr, unsigned long *bitmap)
{
	unsigned long offset = nr / BITS_IN_LONG;
	unsigned long bit = nr & (BITS_IN_LONG-1);
	bitmap[offset] &= ~(1UL << bit);
}

static inline int test_and_set_bit(unsigned int nr, unsigned long *bitmap)
{
	unsigned long offset = nr / BITS_IN_LONG;
	unsigned long bit = nr & (BITS_IN_LONG-1);
	unsigned long old = bitmap[offset];
	unsigned long mask = 1UL << bit;
	bitmap[offset] = old | mask;
	return (old & mask) != 0;
}

static inline int test_and_clear_bit(unsigned int nr, unsigned long *bitmap)
{
	unsigned long offset = nr / BITS_IN_LONG;
	unsigned long bit = nr & (BITS_IN_LONG-1);
	unsigned long old = bitmap[offset];
	unsigned long mask = 1UL << bit;
	bitmap[offset] = old & ~mask;
	return (old & mask) != 0;
}

#endif /* BITMAP_H */
