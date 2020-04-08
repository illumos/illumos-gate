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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

#define	MAX_MAPS	256

#define	MAP_IS_VALID		0x01

struct map_table {
	int map_flags;
	uint64_t map_add;
	size_t map_size;
	uint64_t adj_virt;
	size_t adj_length;
} map_table[MAX_MAPS];

/*
 * Originally, this code translated kernel supplied virtual addresses into
 * "memory cookies", which was a 32-bit number with ascii-M in the upper 8
 * bits, a 4-bit index and a 20-bit offset.  However, this caused two
 * problems:  1) the 20-bit offset was too small for some devices, esp. some
 * with frame-buffers;  2) if the fcode used the cookie to program the
 * hardware, there was no easy way for the software to detect that a
 * translation needed to be done.
 *
 * For that reason, "memory cookies" are now just the kernel-supplied
 * virtual address, and we now check each memory access to see if it's
 * attempting to access kernel-supplied memory.  The only important thing
 * now is that "is_mcookie" returns 1 (or true) if the tested mcookie
 * is a kernel virtual address.
 *
 * There is a potential bug if the kernel virtual address happens to
 * conflict with a user virtual address.  However, the current implementation
 * of Solaris avoids this conflict.
 */

fstack_t
mapping_to_mcookie(uint64_t req_add, size_t req_size, uint64_t adj_virt,
    size_t adj_length)
{
	int i;
	struct map_table *mp;

	for (i = 0, mp = map_table; i < MAX_MAPS; i++, mp++)
		if ((mp->map_flags & MAP_IS_VALID) == 0)
			break;
	if (i == MAX_MAPS) {
		log_message(MSG_WARN, "Warning: too many mappings\n");
		return (0);
	}
	debug_msg(DEBUG_REG_ACCESS, "Allocating mapping: %d add: 0x%llx"
	    " size: 0x%x\n", i, req_add, req_size);
	mp->map_flags |= MAP_IS_VALID;
	mp->map_add = req_add;
	mp->map_size = req_size;
	mp->adj_virt = adj_virt;
	mp->adj_length = adj_length;
	if (mp->adj_length != 0)
		return (adj_virt);
	else
		return (req_add);
}

void
delete_mapping(fstack_t mcookie)
{
	int i;
	struct map_table *mp;

	for (i = 0, mp = map_table; i < MAX_MAPS; i++, mp++) {
		if ((mp->map_flags & MAP_IS_VALID) &&
		    mcookie >= mp->map_add &&
		    mcookie < mp->map_add + mp->map_size) {
			debug_msg(DEBUG_REG_ACCESS, "Deallocating mapping: %d"
			    " add: 0x%llx size: 0x%x\n", i, mp->map_add,
			    mp->map_size);
			mp->map_flags &= ~MAP_IS_VALID;
			mp->map_add = 0;
			mp->map_size = 0;
			mp->adj_virt = 0;
			mp->adj_length = 0;
			return;
		}
	}
	log_message(MSG_WARN, "Warning: delete_mapping: invalid"
	    " mcookie: %llx\n", (uint64_t)mcookie);
}

int
is_mcookie(fstack_t mcookie)
{
	struct map_table *mp;
	int i;

	for (i = 0, mp = map_table; i < MAX_MAPS; i++, mp++)
		if ((mp->map_flags & MAP_IS_VALID) &&
		    mcookie >= mp->map_add &&
		    mcookie < mp->map_add + mp->map_size)
			return (1);
	return (0);
}

uint64_t
mcookie_to_addr(fstack_t mcookie)
{
	return (mcookie);
}

fstack_t
mcookie_to_rlen(fstack_t mcookie)
{
	int i;
	struct map_table *mp;

	for (i = 0, mp = map_table; i < MAX_MAPS; i++, mp++) {
		if ((mp->map_flags & MAP_IS_VALID) &&
		    mcookie >= mp->map_add &&
		    mcookie < mp->map_add + mp->map_size) {
			return (mp->map_size);
		}
	}
	log_message(MSG_WARN, "Warning: mcookie_to_rlen: invalid"
	    " mcookie: %llx\n", (uint64_t)mcookie);

	return (0);
}

fstack_t
mcookie_to_rvirt(fstack_t mcookie)
{
	int i;
	struct map_table *mp;

	for (i = 0, mp = map_table; i < MAX_MAPS; i++, mp++) {
		if ((mp->map_flags & MAP_IS_VALID) &&
		    mcookie >= mp->map_add &&
		    mcookie < mp->map_add + mp->map_size) {
			return (mp->map_add);
		}
	}
	log_message(MSG_WARN, "Warning: mcookie_to_rvirt: invalid"
	    " mcookie: %llx\n", (uint64_t)mcookie);

	return (0);
}

static void
dot_maps(fcode_env_t *env)
{
	int i;

	log_message(MSG_DEBUG, "idx     base-addr        size\n");
	for (i = 0; i < MAX_MAPS; i++) {
		if (map_table[i].map_flags & MAP_IS_VALID)
			log_message(MSG_DEBUG, "%3d %016llx %8x\n", i,
			    map_table[i].map_add, map_table[i].map_size);
	}
}

static void
map_qmark(fcode_env_t *env)
{
	fstack_t d = POP(DS);

	if (!is_mcookie(d))
		log_message(MSG_INFO, "%llx: not mcookie\n", (uint64_t)d);
	else
		log_message(MSG_INFO, "%llx -> %llx\n", (uint64_t)d,
		    mcookie_to_addr(d));
}

static void
add_map(fcode_env_t *env)
{
	fstack_t size, addr;

	size = POP(DS);
	addr = POP(DS);
	addr = mapping_to_mcookie(addr, size, 0, 0);
	PUSH(DS, addr);
}

static void
del_map(fcode_env_t *env)
{
	fstack_t addr;

	addr = POP(DS);
	delete_mapping(addr);
}


#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(0,	".maps",		dot_maps);
	FORTH(0,	"map?",			map_qmark);
	FORTH(0,	"add-map",		add_map);
	FORTH(0,	"del-map",		del_map);
}
