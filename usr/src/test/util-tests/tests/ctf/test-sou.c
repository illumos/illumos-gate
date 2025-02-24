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
 * Copyright (c) 2019, Joyent, Inc.
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/types.h>
#include <complex.h>

/*
 * Test various structure and union constructs, including various things that
 * have caused regressions in the past.
 */

/*
 * Basic, simple struct.
 */
struct foo {
	int a;
	float b;
	const char *c;
};

struct foo foo;

/*
 * Self-referential structs
 */
struct node {
	struct node *prev;
	struct node *next;
};

typedef struct nlist {
	size_t size;
	size_t off;
	struct node head;
} nlist_t;

nlist_t head;

/*
 * Struct that has a forward declaration.
 */
typedef struct forward forward_t;
struct forward {
	void *past;
	void *present;
	void *future;
};

const forward_t forward;

/*
 * Here, we have a pair of structures that basically round up to different
 * sizes. As in, the size of the structure is somewhat compiler dependent.
 */
struct round_up {
	uint8_t triforce;
	uint32_t link;
	uint8_t zelda;
	uint8_t ganon;
};

#pragma pack(1)
struct fixed_up {
	uint8_t triforce;
	uint32_t link;
	uint8_t zelda;
	uint8_t ganon;
};
#pragma pack()

struct round_up oot;
struct fixed_up botw;

/*
 * Various GNU and c99 style arrays
 */
enum material {
	COPPER,
	IRON,
	STEEL,
	ADAMANTIUM,
	MYTHRIL,
	ORIHALCUM
};

struct component {
	enum material m;
	uint64_t grade;
	uint64_t count;
	const char *locations[4];
};

struct mysterious_barrel {
	const char *name;
	size_t capacity;
	struct component optional[];
};

struct dusk_barrel {
	const char *name;
	size_t opacity;
	struct component optional[0];
};

struct mysterious_barrel sophie;
struct dusk_barrel ayesha;

/*
 * Various bitfield forms.
 */

/*
 * Variant of the Intel system_desc.
 */
struct stats {
	uint64_t hp:16;
	uint64_t mp:16;
	uint64_t str:8;
	uint64_t dex:4;
	uint64_t con:1;
	uint64_t inte:2;
	uint64_t wis:1;
	uint64_t cha:4;
	uint64_t sanity:1;
	uint64_t attack:2;
	uint64_t mattack:1;
	uint64_t defense:8;
	uint64_t mdefense:32;
	uint64_t evasion:8;
	uint64_t crit:5;
	uint64_t luck:19;
};

struct stats stats;

/*
 * More odd length structures due to bitfields
 */
struct fellowship {
	uint16_t frodo:1;
	uint16_t sam:1;
	uint16_t merry:1;
	uint16_t pippin:1;
	uint16_t aragorn:1;
	uint16_t boromir:1;
	uint16_t legolas:1;
	uint16_t gimli:1;
	uint16_t gandalf:1;
};

struct fellowship ring;

struct rings {
	uint32_t elves:3;
	uint32_t dwarves:7;
	uint32_t men:9;
	uint8_t one;
	uint8_t silmarils[3];
};

struct rings rings;

/*
 * Regression, we didn't handle receiving a negative offset from DWARF with
 * this.
 */
#pragma pack(1)
struct csts {
	unsigned int rdy:7;
	unsigned int csts:32;
};

struct csts nvme;
#pragma pack()

/*
 * Onto unions
 */
union jrpg {
	int ff;
	double atelier[4];
	const char *tales;
	int (*chrono)(void);
	struct rings xeno;
};

union jrpg games;

#pragma pack(1)
struct android {
	uint32_t _2b:16;
	uint32_t _9s:16;
};

union nier {
	uint32_t automata;
	struct android android;
};
#pragma pack()

union nier nier;

union kh {
	int sora:3;
	char riku:7;
	double kairi;
	complex double namine;
};

union kh kh;

/*
 * Anonymous union in a struct, GNU extension / C11
 */

struct trigger {
	uint8_t chrono;
	uint8_t cross;
	union {
		void *lavos;
		int *crono;
		uint64_t schala[3];
	};
};

struct trigger ct;

/*
 * This is an array/union combo that failed conversion previously. Because it is
 * static, we need to have a dummy function to make sure that clang doesn't
 * optimize it away. Hopefully even with optimizations, this'll still be kept
 * even though it's a constant.
 */
static const union regress {
	unsigned int i[3];
	long double e;
} regress[9];

unsigned int
get_regress(void)
{
	return (regress[0].i[2]);
}

/*
 * Now we have a series of different anonymous unions and structures.
 */
struct anon_basic {
	int a;
	union {
		int b;
		double c;
		const char *d;
	};
	struct {
		int e;
		const char *f;
		unsigned int g[10];
	};
};

struct anon_basic anon_basic;

struct nested {
	int a;
	union {
		int b;
		struct {
			int c;
			int d;
			int e;
			union {
				int g;
				struct {
					int h;
				};
			};
			struct {
				int i;
				struct {
					int j;
					union {
						int k;
						struct {
							int l;
							int m;
						};
						union {
							int n;
							struct {
								int o;
								int p;
							};
						};
					};
				};
			};
		};
	};
};

struct nested nested;
