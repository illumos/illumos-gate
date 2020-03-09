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
 * Copyright 2020, The University of Queensland
 */

#ifndef _MLXCX_ENDINT_H
#define	_MLXCX_ENDINT_H

#include <sys/types.h>
#include <sys/byteorder.h>

/*
 * The inlines and structs in this file are used by mlxcx to ensure endian
 * safety when dealing with memory-mapped structures from the device, and
 * also simpler use of 24-bit integers (which Mellanox loves).
 *
 * By declaring all of these values in the memory-mapped structures as structs
 * (e.g. uint32be_t) rather than bare integers (uint32_t) we ensure that the
 * compiler will not allow them to be silently converted to integers and used
 * without doing the necessary byte-swapping work.
 *
 * The uintXbe_t structs are designed to be used inside a #pragma pack(1)
 * context only and we don't try to fix up their alignment.
 *
 * Also present in here are a number of bitsX_t types which can be used to
 * gain a little bit of type safety when dealing with endian-swapped bitfields.
 */

#pragma pack(1)
typedef struct { uint16_t be_val; } uint16be_t;
typedef struct { uint8_t be_val[3]; } uint24be_t;
typedef struct { uint32_t be_val; } uint32be_t;
typedef struct { uint64_t be_val; } uint64be_t;
#pragma pack()

static inline uint16_t
from_be16(uint16be_t v)
{
	return (BE_16(v.be_val));
}

static inline uint32_t
from_be24(uint24be_t v)
{
	return (((uint32_t)v.be_val[0] << 16) |
	    ((uint32_t)v.be_val[1] << 8) |
	    ((uint32_t)v.be_val[2]));
}

static inline uint32_t
from_be32(uint32be_t v)
{
	return (BE_32(v.be_val));
}

static inline uint64_t
from_be64(uint64be_t v)
{
	return (BE_64(v.be_val));
}

static inline uint16be_t
to_be16(uint16_t v)
{
	/* CSTYLED */
	return ((uint16be_t){ .be_val = BE_16(v) });
}

static inline uint24be_t
to_be24(uint32_t v)
{
	/* CSTYLED */
	return ((uint24be_t){ .be_val = {
	    (v & 0xFF0000) >> 16,
	    (v & 0x00FF00) >> 8,
	    (v & 0x0000FF)
	}});
}

static inline uint32be_t
to_be32(uint32_t v)
{
	/* CSTYLED */
	return ((uint32be_t){ .be_val = BE_32(v) });
}

static inline uint64be_t
to_be64(uint64_t v)
{
	/* CSTYLED */
	return ((uint64be_t){ .be_val = BE_64(v) });
}

#pragma pack(1)
typedef struct { uint8_t bit_val; } bits8_t;
typedef struct { uint16_t bit_val; } bits16_t;
typedef struct { uint32_t bit_val; } bits32_t;
typedef struct { uint24be_t bit_val; } bits24_t;
typedef struct { uint64_t bit_val; } bits64_t;
typedef struct { uint64_t bit_shift; uint64_t bit_mask; } bitdef_t;
#pragma pack()

static inline uint8_t
get_bits8(bits8_t v, bitdef_t d)
{
	return ((v.bit_val & d.bit_mask) >> d.bit_shift);
}
static inline void
set_bits8(bits8_t *v, bitdef_t d, uint8_t val)
{
	v->bit_val &= ~d.bit_mask;
	v->bit_val |= (val << d.bit_shift) & d.bit_mask;
}
static inline uint8_t
get_bit8(bits8_t v, uint8_t mask)
{
	return ((v.bit_val & mask) != 0);
}
static inline void
set_bit8(bits8_t *v, uint8_t mask)
{
	v->bit_val |= mask;
}
static inline void
clear_bit8(bits8_t *v, uint8_t mask)
{
	v->bit_val &= ~mask;
}
static inline bits8_t
new_bits8(void)
{
	/* CSTYLED */
	return ((bits8_t){ .bit_val = 0 });
}
static inline uint8_t
from_bits8(bits8_t v)
{
	return (v.bit_val);
}

static inline uint16_t
get_bits16(bits16_t v, bitdef_t d)
{
	return ((BE_16(v.bit_val) & d.bit_mask) >> d.bit_shift);
}
static inline void
set_bits16(bits16_t *v, bitdef_t d, uint16_t val)
{
	v->bit_val &= BE_16(~d.bit_mask);
	v->bit_val |= BE_16((val << d.bit_shift) & d.bit_mask);
}
static inline uint16_t
get_bit16(bits16_t v, uint16_t mask)
{
	return ((BE_16(v.bit_val) & mask) != 0);
}
static inline void
set_bit16(bits16_t *v, uint16_t mask)
{
	v->bit_val |= BE_16(mask);
}
static inline void
clear_bit16(bits16_t *v, uint16_t mask)
{
	v->bit_val &= BE_16(~mask);
}
static inline bits16_t
new_bits16(void)
{
	/* CSTYLED */
	return ((bits16_t){ .bit_val = 0 });
}
static inline uint16_t
from_bits16(bits16_t v)
{
	return (BE_16(v.bit_val));
}

static inline uint32_t
get_bits32(bits32_t v, bitdef_t d)
{
	return ((BE_32(v.bit_val) & d.bit_mask) >> d.bit_shift);
}
static inline void
set_bits32(bits32_t *v, bitdef_t d, uint32_t val)
{
	v->bit_val &= BE_32(~d.bit_mask);
	v->bit_val |= BE_32((val << d.bit_shift) & d.bit_mask);
}
static inline uint32_t
get_bit32(bits32_t v, uint32_t mask)
{
	return ((BE_32(v.bit_val) & mask) != 0);
}
static inline void
set_bit32(bits32_t *v, uint32_t mask)
{
	v->bit_val |= BE_32(mask);
}
static inline void
clear_bit32(bits32_t *v, uint32_t mask)
{
	v->bit_val &= BE_32(~mask);
}
static inline bits32_t
new_bits32(void)
{
	/* CSTYLED */
	return ((bits32_t){ .bit_val = 0 });
}
static inline uint32_t
from_bits32(bits32_t v)
{
	return (BE_32(v.bit_val));
}

static inline uint32_t
get_bits24(bits24_t v, bitdef_t d)
{
	return ((from_be24(v.bit_val) & d.bit_mask) >> d.bit_shift);
}
static inline void
set_bits24(bits24_t *v, bitdef_t d, uint32_t val)
{
	uint32_t vv = from_be24(v->bit_val);
	vv &= ~d.bit_mask;
	vv |= (val << d.bit_shift) & d.bit_mask;
	v->bit_val = to_be24(vv);
}
static inline uint32_t
get_bit24(bits24_t v, uint32_t mask)
{
	return ((from_be24(v.bit_val) & mask) != 0);
}
static inline void
set_bit24(bits24_t *v, uint32_t mask)
{
	v->bit_val = to_be24(from_be24(v->bit_val) | mask);
}
static inline void
clear_bit24(bits24_t *v, uint32_t mask)
{
	v->bit_val = to_be24(from_be24(v->bit_val) & ~mask);
}
static inline bits24_t
new_bits24(void)
{
	/* CSTYLED */
	return ((bits24_t){ .bit_val = to_be24(0) });
}
static inline uint32_t
from_bits24(bits24_t v)
{
	return (from_be24(v.bit_val));
}

static inline uint64_t
get_bits64(bits64_t v, bitdef_t d)
{
	return ((BE_64(v.bit_val) & d.bit_mask) >> d.bit_shift);
}
static inline void
set_bits64(bits64_t *v, bitdef_t d, uint64_t val)
{
	v->bit_val &= BE_64(~d.bit_mask);
	v->bit_val |= BE_64((val << d.bit_shift) & d.bit_mask);
}
static inline uint64_t
get_bit64(bits64_t v, uint64_t mask)
{
	return ((BE_64(v.bit_val) & mask) != 0);
}
static inline void
set_bit64(bits64_t *v, uint64_t mask)
{
	v->bit_val |= BE_64(mask);
}
static inline void
clear_bit64(bits64_t *v, uint64_t mask)
{
	v->bit_val &= BE_64(~mask);
}
static inline bits64_t
new_bits64(void)
{
	/* CSTYLED */
	return ((bits64_t){ .bit_val = 0 });
}
static inline uint64_t
from_bits64(bits64_t v)
{
	return (BE_64(v.bit_val));
}

#endif /* _MLXCX_ENDINT_H */
