/*
 * Copyright (C) 2009 Dan Carpenter.
 * Copyright (C) 2019 Oracle.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/gpl.txt
 */

#include <ctype.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

STATE(locked);
STATE(half_locked);
STATE(start_state);
STATE(unlocked);
STATE(impossible);
STATE(restore);

enum action {
	LOCK,
	UNLOCK,
	RESTORE,
};

enum lock_type {
	spin_lock,
	read_lock,
	write_lock,
	mutex,
	bottom_half,
	irq,
	sem,
	prepare_lock,
	enable_lock,
};

const char *get_lock_name(enum lock_type type)
{
	static const char *names[] = {
		[spin_lock] = "spin_lock",
		[read_lock] = "read_lock",
		[write_lock] = "write_lock",
		[mutex] = "mutex",
		[bottom_half] = "bottom_half",
		[irq] = "irq",
		[sem] = "sem",
		[prepare_lock] = "prepare_lock",
		[enable_lock] = "enable_lock",
	};

	return names[type];
}

enum return_type {
	ret_any,
	ret_zero,
	ret_one,
	ret_negative,
	ret_positive,
	ret_valid_ptr,
};

#define RETURN_VAL -1
#define NO_ARG -2

struct lock_info {
	const char *function;
	enum action action;
	enum lock_type type;
	int arg;
	enum return_type return_type;
};

static struct lock_info lock_table[] = {
	{"spin_lock",                  LOCK,   spin_lock, 0, ret_any},
	{"spin_unlock",                UNLOCK, spin_lock, 0, ret_any},
	{"spin_lock_nested",           LOCK,   spin_lock, 0, ret_any},
	{"_spin_lock",                 LOCK,   spin_lock, 0, ret_any},
	{"_spin_unlock",               UNLOCK, spin_lock, 0, ret_any},
	{"_spin_lock_nested",          LOCK,   spin_lock, 0, ret_any},
	{"__spin_lock",                LOCK,   spin_lock, 0, ret_any},
	{"__spin_unlock",              UNLOCK, spin_lock, 0, ret_any},
	{"__spin_lock_nested",         LOCK,   spin_lock, 0, ret_any},
	{"raw_spin_lock",              LOCK,   spin_lock, 0, ret_any},
	{"raw_spin_unlock",            UNLOCK, spin_lock, 0, ret_any},
	{"_raw_spin_lock",             LOCK,   spin_lock, 0, ret_any},
	{"_raw_spin_lock_nested",      LOCK,   spin_lock, 0, ret_any},
	{"_raw_spin_unlock",           UNLOCK, spin_lock, 0, ret_any},
	{"__raw_spin_lock",            LOCK,   spin_lock, 0, ret_any},
	{"__raw_spin_unlock",          UNLOCK, spin_lock, 0, ret_any},

	{"spin_lock_irq",                 LOCK,   spin_lock, 0, ret_any},
	{"spin_unlock_irq",               UNLOCK, spin_lock, 0, ret_any},
	{"_spin_lock_irq",                LOCK,   spin_lock, 0, ret_any},
	{"_spin_unlock_irq",              UNLOCK, spin_lock, 0, ret_any},
	{"__spin_lock_irq",               LOCK,   spin_lock, 0, ret_any},
	{"__spin_unlock_irq",             UNLOCK, spin_lock, 0, ret_any},
	{"_raw_spin_lock_irq",            LOCK,   spin_lock, 0, ret_any},
	{"_raw_spin_unlock_irq",          UNLOCK, spin_lock, 0, ret_any},
	{"__raw_spin_unlock_irq",         UNLOCK, spin_lock, 0, ret_any},
	{"spin_lock_irqsave",             LOCK,   spin_lock, 0, ret_any},
	{"spin_unlock_irqrestore",        UNLOCK, spin_lock, 0, ret_any},
	{"_spin_lock_irqsave",            LOCK,   spin_lock, 0, ret_any},
	{"_spin_unlock_irqrestore",       UNLOCK, spin_lock, 0, ret_any},
	{"__spin_lock_irqsave",           LOCK,   spin_lock, 0, ret_any},
	{"__spin_unlock_irqrestore",      UNLOCK, spin_lock, 0, ret_any},
	{"_raw_spin_lock_irqsave",        LOCK,   spin_lock, 0, ret_any},
	{"_raw_spin_unlock_irqrestore",   UNLOCK, spin_lock, 0, ret_any},
	{"__raw_spin_lock_irqsave",       LOCK,   spin_lock, 0, ret_any},
	{"__raw_spin_unlock_irqrestore",  UNLOCK, spin_lock, 0, ret_any},
	{"spin_lock_irqsave_nested",      LOCK,   spin_lock, 0, ret_any},
	{"_spin_lock_irqsave_nested",     LOCK,   spin_lock, 0, ret_any},
	{"__spin_lock_irqsave_nested",    LOCK,   spin_lock, 0, ret_any},
	{"_raw_spin_lock_irqsave_nested", LOCK,   spin_lock, 0, ret_any},
	{"spin_lock_bh",                  LOCK,   spin_lock, 0, ret_any},
	{"spin_unlock_bh",                UNLOCK, spin_lock, 0, ret_any},
	{"_spin_lock_bh",                 LOCK,   spin_lock, 0, ret_any},
	{"_spin_unlock_bh",               UNLOCK, spin_lock, 0, ret_any},
	{"__spin_lock_bh",                LOCK,   spin_lock, 0, ret_any},
	{"__spin_unlock_bh",              UNLOCK, spin_lock, 0, ret_any},

	{"spin_trylock",               LOCK,   spin_lock, 0, ret_one},
	{"_spin_trylock",              LOCK,   spin_lock, 0, ret_one},
	{"__spin_trylock",             LOCK,   spin_lock, 0, ret_one},
	{"raw_spin_trylock",           LOCK,   spin_lock, 0, ret_one},
	{"_raw_spin_trylock",          LOCK,   spin_lock, 0, ret_one},
	{"spin_trylock_irq",           LOCK,   spin_lock, 0, ret_one},
	{"spin_trylock_irqsave",       LOCK,   spin_lock, 0, ret_one},
	{"spin_trylock_bh",            LOCK,   spin_lock, 0, ret_one},
	{"_spin_trylock_bh",           LOCK,   spin_lock, 0, ret_one},
	{"__spin_trylock_bh",          LOCK,   spin_lock, 0, ret_one},
	{"__raw_spin_trylock",         LOCK,   spin_lock, 0, ret_one},
	{"_atomic_dec_and_lock",       LOCK,   spin_lock, 1, ret_one},

	{"read_lock",                 LOCK,   read_lock, 0, ret_any},
	{"down_read",                 LOCK,   read_lock, 0, ret_any},
	{"down_read_nested",          LOCK,   read_lock, 0, ret_any},
	{"down_read_trylock",         LOCK,   read_lock, 0, ret_one},
	{"up_read",                   UNLOCK, read_lock, 0, ret_any},
	{"read_unlock",               UNLOCK, read_lock, 0, ret_any},
	{"_read_lock",                LOCK,   read_lock, 0, ret_any},
	{"_read_unlock",              UNLOCK, read_lock, 0, ret_any},
	{"__read_lock",               LOCK,   read_lock, 0, ret_any},
	{"__read_unlock",             UNLOCK, read_lock, 0, ret_any},
	{"_raw_read_lock",            LOCK,   read_lock, 0, ret_any},
	{"_raw_read_unlock",          UNLOCK, read_lock, 0, ret_any},
	{"__raw_read_lock",           LOCK,   read_lock, 0, ret_any},
	{"__raw_read_unlock",         UNLOCK, read_lock, 0, ret_any},
	{"read_lock_irq",             LOCK,   read_lock, 0, ret_any},
	{"read_unlock_irq" ,          UNLOCK, read_lock, 0, ret_any},
	{"_read_lock_irq",            LOCK,   read_lock, 0, ret_any},
	{"_read_unlock_irq",          UNLOCK, read_lock, 0, ret_any},
	{"__read_lock_irq",           LOCK,   read_lock, 0, ret_any},
	{"__read_unlock_irq",         UNLOCK, read_lock, 0, ret_any},
	{"_raw_read_unlock_irq",      UNLOCK, read_lock, 0, ret_any},
	{"_raw_read_lock_irq",        LOCK,   read_lock, 0, ret_any},
	{"_raw_read_lock_bh",         LOCK,   read_lock, 0, ret_any},
	{"_raw_read_unlock_bh",       UNLOCK, read_lock, 0, ret_any},
	{"read_lock_irqsave",         LOCK,   read_lock, 0, ret_any},
	{"read_unlock_irqrestore",    UNLOCK, read_lock, 0, ret_any},
	{"_read_lock_irqsave",        LOCK,   read_lock, 0, ret_any},
	{"_read_unlock_irqrestore",   UNLOCK, read_lock, 0, ret_any},
	{"__read_lock_irqsave",       LOCK,   read_lock, 0, ret_any},
	{"__read_unlock_irqrestore",  UNLOCK, read_lock, 0, ret_any},
	{"read_lock_bh",              LOCK,   read_lock, 0, ret_any},
	{"read_unlock_bh",            UNLOCK, read_lock, 0, ret_any},
	{"_read_lock_bh",             LOCK,   read_lock, 0, ret_any},
	{"_read_unlock_bh",           UNLOCK, read_lock, 0, ret_any},
	{"__read_lock_bh",            LOCK,   read_lock, 0, ret_any},
	{"__read_unlock_bh",          UNLOCK, read_lock, 0, ret_any},
	{"__raw_read_lock_bh",        LOCK,   read_lock, 0, ret_any},
	{"__raw_read_unlock_bh",      UNLOCK, read_lock, 0, ret_any},

	{"_raw_read_lock_irqsave",        LOCK,    read_lock,   0,          ret_any},
	{"_raw_read_lock_irqsave",        LOCK,    irq,	        RETURN_VAL, ret_any},
	{"_raw_read_unlock_irqrestore",   UNLOCK,  read_lock,   0,          ret_any},
	{"_raw_read_unlock_irqrestore",   RESTORE, irq,         1,          ret_any},
	{"_raw_spin_lock_bh",             LOCK,    read_lock,   0,          ret_any},
	{"_raw_spin_lock_bh",             LOCK,    bottom_half, NO_ARG,     ret_any},
	{"_raw_spin_lock_nest_lock",      LOCK,    read_lock,   0,          ret_any},
	{"_raw_spin_unlock_bh",           UNLOCK,  read_lock,   0,          ret_any},
	{"_raw_spin_unlock_bh",           UNLOCK,  bottom_half, NO_ARG,     ret_any},
	{"_raw_write_lock_irqsave",       LOCK,    write_lock,  0,          ret_any},
	{"_raw_write_lock_irqsave",       LOCK,    irq,         RETURN_VAL, ret_any},
	{"_raw_write_unlock_irqrestore",  UNLOCK,  write_lock,  0,          ret_any},
	{"_raw_write_unlock_irqrestore",  RESTORE, irq,         1,          ret_any},
	{"__raw_write_unlock_irqrestore", UNLOCK,  write_lock,  0,          ret_any},
	{"__raw_write_unlock_irqrestore", RESTORE, irq,         1,          ret_any},

	{"generic__raw_read_trylock", LOCK,   read_lock, 0, ret_one},
	{"read_trylock",              LOCK,   read_lock, 0, ret_one},
	{"_read_trylock",             LOCK,   read_lock, 0, ret_one},
	{"raw_read_trylock",          LOCK,   read_lock, 0, ret_one},
	{"_raw_read_trylock",         LOCK,   read_lock, 0, ret_one},
	{"__raw_read_trylock",        LOCK,   read_lock, 0, ret_one},
	{"__read_trylock",            LOCK,   read_lock, 0, ret_one},

	{"write_lock",                LOCK,   write_lock, 0, ret_any},
	{"down_write",                LOCK,   write_lock, 0, ret_any},
	{"down_write_nested",         LOCK,   write_lock, 0, ret_any},
	{"up_write",                  UNLOCK, write_lock, 0, ret_any},
	{"write_unlock",              UNLOCK, write_lock, 0, ret_any},
	{"_write_lock",               LOCK,   write_lock, 0, ret_any},
	{"_write_unlock",             UNLOCK, write_lock, 0, ret_any},
	{"__write_lock",              LOCK,   write_lock, 0, ret_any},
	{"__write_unlock",            UNLOCK, write_lock, 0, ret_any},
	{"write_lock_irq",            LOCK,   write_lock, 0, ret_any},
	{"write_unlock_irq",          UNLOCK, write_lock, 0, ret_any},
	{"_write_lock_irq",           LOCK,   write_lock, 0, ret_any},
	{"_write_unlock_irq",         UNLOCK, write_lock, 0, ret_any},
	{"__write_lock_irq",          LOCK,   write_lock, 0, ret_any},
	{"__write_unlock_irq",        UNLOCK, write_lock, 0, ret_any},
	{"_raw_write_unlock_irq",     UNLOCK, write_lock, 0, ret_any},
	{"write_lock_irqsave",        LOCK,   write_lock, 0, ret_any},
	{"write_unlock_irqrestore",   UNLOCK, write_lock, 0, ret_any},
	{"_write_lock_irqsave",       LOCK,   write_lock, 0, ret_any},
	{"_write_unlock_irqrestore",  UNLOCK, write_lock, 0, ret_any},
	{"__write_lock_irqsave",      LOCK,   write_lock, 0, ret_any},
	{"__write_unlock_irqrestore", UNLOCK, write_lock, 0, ret_any},
	{"write_lock_bh",             LOCK,   write_lock, 0, ret_any},
	{"write_unlock_bh",           UNLOCK, write_lock, 0, ret_any},
	{"_write_lock_bh",            LOCK,   write_lock, 0, ret_any},
	{"_write_unlock_bh",          UNLOCK, write_lock, 0, ret_any},
	{"__write_lock_bh",           LOCK,   write_lock, 0, ret_any},
	{"__write_unlock_bh",         UNLOCK, write_lock, 0, ret_any},
	{"_raw_write_lock",           LOCK,   write_lock, 0, ret_any},
	{"__raw_write_lock",          LOCK,   write_lock, 0, ret_any},
	{"_raw_write_unlock",         UNLOCK, write_lock, 0, ret_any},
	{"__raw_write_unlock",        UNLOCK, write_lock, 0, ret_any},
	{"_raw_write_lock_bh",        LOCK,   write_lock, 0, ret_any},
	{"_raw_write_unlock_bh",      UNLOCK, write_lock, 0, ret_any},
	{"_raw_write_lock_irq",       LOCK,   write_lock, 0, ret_any},

	{"write_trylock",             LOCK,   write_lock, 0, ret_one},
	{"_write_trylock",            LOCK,   write_lock, 0, ret_one},
	{"raw_write_trylock",         LOCK,   write_lock, 0, ret_one},
	{"_raw_write_trylock",        LOCK,   write_lock, 0, ret_one},
	{"__write_trylock",           LOCK,   write_lock, 0, ret_one},
	{"__raw_write_trylock",       LOCK,   write_lock, 0, ret_one},
	{"down_write_trylock",        LOCK,   write_lock, 0, ret_one},
	{"down_write_killable",       LOCK,   write_lock, 0, ret_zero},

	{"down",               LOCK,   sem, 0, ret_any},
	{"up",                 UNLOCK, sem, 0, ret_any},
	{"down_trylock",       LOCK,   sem, 0, ret_zero},
	{"down_timeout",       LOCK,   sem, 0, ret_zero},
	{"down_interruptible", LOCK,   sem, 0, ret_zero},
	{"down_killable",      LOCK,   sem, 0, ret_zero},


	{"mutex_lock",                      LOCK,   mutex, 0, ret_any},
	{"mutex_unlock",                    UNLOCK, mutex, 0, ret_any},
	{"mutex_lock_nested",               LOCK,   mutex, 0, ret_any},
	{"mutex_lock_io",                   LOCK,   mutex, 0, ret_any},
	{"mutex_lock_io_nested",            LOCK,   mutex, 0, ret_any},

	{"mutex_lock_interruptible",        LOCK,   mutex, 0, ret_zero},
	{"mutex_lock_interruptible_nested", LOCK,   mutex, 0, ret_zero},
	{"mutex_lock_killable",             LOCK,   mutex, 0, ret_zero},
	{"mutex_lock_killable_nested",      LOCK,   mutex, 0, ret_zero},

	{"mutex_trylock",                   LOCK,   mutex, 0, ret_one},

	{"ww_mutex_lock",		LOCK,   mutex, 0, ret_any},
	{"__ww_mutex_lock",		LOCK,   mutex, 0, ret_any},
	{"ww_mutex_lock_interruptible",	LOCK,   mutex, 0, ret_zero},
	{"ww_mutex_unlock",		UNLOCK, mutex, 0, ret_any},

	{"raw_local_irq_disable", LOCK,   irq, NO_ARG, ret_any},
	{"raw_local_irq_enable",  UNLOCK, irq, NO_ARG, ret_any},
	{"spin_lock_irq",         LOCK,   irq, NO_ARG, ret_any},
	{"spin_unlock_irq",       UNLOCK, irq, NO_ARG, ret_any},
	{"_spin_lock_irq",        LOCK,   irq, NO_ARG, ret_any},
	{"_spin_unlock_irq",      UNLOCK, irq, NO_ARG, ret_any},
	{"__spin_lock_irq",       LOCK,   irq, NO_ARG, ret_any},
	{"__spin_unlock_irq",     UNLOCK, irq, NO_ARG, ret_any},
	{"_raw_spin_lock_irq",    LOCK,   irq, NO_ARG, ret_any},
	{"_raw_spin_unlock_irq",  UNLOCK, irq, NO_ARG, ret_any},
	{"__raw_spin_unlock_irq", UNLOCK, irq, NO_ARG, ret_any},
	{"spin_trylock_irq",      LOCK,   irq, NO_ARG, ret_one},
	{"read_lock_irq",         LOCK,   irq, NO_ARG, ret_any},
	{"read_unlock_irq",       UNLOCK, irq, NO_ARG, ret_any},
	{"_read_lock_irq",        LOCK,   irq, NO_ARG, ret_any},
	{"_read_unlock_irq",      UNLOCK, irq, NO_ARG, ret_any},
	{"__read_lock_irq",       LOCK,   irq, NO_ARG, ret_any},
	{"_raw_read_lock_irq",    LOCK,   irq, NO_ARG, ret_any},
	{"__read_unlock_irq",     UNLOCK, irq, NO_ARG, ret_any},
	{"_raw_read_unlock_irq",  UNLOCK, irq, NO_ARG, ret_any},
	{"write_lock_irq",        LOCK,   irq, NO_ARG, ret_any},
	{"write_unlock_irq",      UNLOCK, irq, NO_ARG, ret_any},
	{"_write_lock_irq",       LOCK,   irq, NO_ARG, ret_any},
	{"_write_unlock_irq",     UNLOCK, irq, NO_ARG, ret_any},
	{"__write_lock_irq",      LOCK,   irq, NO_ARG, ret_any},
	{"__write_unlock_irq",    UNLOCK, irq, NO_ARG, ret_any},
	{"_raw_write_lock_irq",   LOCK,   irq, NO_ARG, ret_any},
	{"_raw_write_unlock_irq", UNLOCK, irq, NO_ARG, ret_any},

	{"arch_local_irq_save",        LOCK,      irq, RETURN_VAL, ret_any},
	{"arch_local_irq_restore",     RESTORE,   irq, 0,	   ret_any},
	{"__raw_local_irq_save",       LOCK,      irq, RETURN_VAL, ret_any},
	{"raw_local_irq_restore",      RESTORE,   irq, 0,	   ret_any},
	{"spin_lock_irqsave_nested",   LOCK,      irq, RETURN_VAL, ret_any},
	{"spin_lock_irqsave",          LOCK,      irq, 1,	   ret_any},
	{"spin_unlock_irqrestore",     RESTORE,   irq, 1,	   ret_any},
	{"_spin_lock_irqsave_nested",  LOCK,      irq, RETURN_VAL, ret_any},
	{"_spin_lock_irqsave",         LOCK,      irq, RETURN_VAL, ret_any},
	{"_spin_lock_irqsave",         LOCK,      irq, 1,	   ret_any},
	{"_spin_unlock_irqrestore",    RESTORE,   irq, 1,	   ret_any},
	{"__spin_lock_irqsave_nested", LOCK,      irq, 1,	   ret_any},
	{"__spin_lock_irqsave",        LOCK,      irq, 1,	   ret_any},
	{"__spin_unlock_irqrestore",   RESTORE,   irq, 1,	   ret_any},
	{"_raw_spin_lock_irqsave",     LOCK,      irq, RETURN_VAL, ret_any},
	{"_raw_spin_lock_irqsave",     LOCK,      irq, 1,	   ret_any},
	{"_raw_spin_unlock_irqrestore", RESTORE,  irq, 1,	   ret_any},
	{"__raw_spin_lock_irqsave",    LOCK,      irq, RETURN_VAL, ret_any},
	{"__raw_spin_unlock_irqrestore", RESTORE, irq, 1,	   ret_any},
	{"_raw_spin_lock_irqsave_nested", LOCK,   irq, RETURN_VAL, ret_any},
	{"spin_trylock_irqsave",       LOCK,      irq, 1,	   ret_one},
	{"read_lock_irqsave",          LOCK,      irq, RETURN_VAL, ret_any},
	{"read_lock_irqsave",          LOCK,      irq, 1,	   ret_any},
	{"read_unlock_irqrestore",     RESTORE,   irq, 1,	   ret_any},
	{"_read_lock_irqsave",         LOCK,      irq, RETURN_VAL, ret_any},
	{"_read_lock_irqsave",         LOCK,      irq, 1,	   ret_any},
	{"_read_unlock_irqrestore",    RESTORE,   irq, 1,	   ret_any},
	{"__read_lock_irqsave",        LOCK,      irq, RETURN_VAL, ret_any},
	{"__read_unlock_irqrestore",   RESTORE,   irq, 1,	   ret_any},
	{"write_lock_irqsave",         LOCK,      irq, RETURN_VAL, ret_any},
	{"write_lock_irqsave",         LOCK,      irq, 1,	   ret_any},
	{"write_unlock_irqrestore",    RESTORE,   irq, 1,	   ret_any},
	{"_write_lock_irqsave",        LOCK,      irq, RETURN_VAL, ret_any},
	{"_write_lock_irqsave",        LOCK,      irq, 1,	   ret_any},
	{"_write_unlock_irqrestore",   RESTORE,   irq, 1,	   ret_any},
	{"__write_lock_irqsave",       LOCK,      irq, RETURN_VAL, ret_any},
	{"__write_unlock_irqrestore",  RESTORE,   irq, 1,	   ret_any},

	{"local_bh_disable",	LOCK,	bottom_half, NO_ARG, ret_any},
	{"_local_bh_disable",	LOCK,	bottom_half, NO_ARG, ret_any},
	{"__local_bh_disable",	LOCK,	bottom_half, NO_ARG, ret_any},
	{"local_bh_enable",	UNLOCK,	bottom_half, NO_ARG, ret_any},
	{"_local_bh_enable",	UNLOCK,	bottom_half, NO_ARG, ret_any},
	{"__local_bh_enable",	UNLOCK,	bottom_half, NO_ARG, ret_any},
	{"spin_lock_bh",        LOCK,   bottom_half, NO_ARG, ret_any},
	{"spin_unlock_bh",      UNLOCK, bottom_half, NO_ARG, ret_any},
	{"_spin_lock_bh",       LOCK,   bottom_half, NO_ARG, ret_any},
	{"_spin_unlock_bh",     UNLOCK, bottom_half, NO_ARG, ret_any},
	{"__spin_lock_bh",      LOCK,   bottom_half, NO_ARG, ret_any},
	{"__spin_unlock_bh",    UNLOCK, bottom_half, NO_ARG, ret_any},
	{"read_lock_bh",        LOCK,   bottom_half, NO_ARG, ret_any},
	{"read_unlock_bh",      UNLOCK, bottom_half, NO_ARG, ret_any},
	{"_read_lock_bh",       LOCK,   bottom_half, NO_ARG, ret_any},
	{"_read_unlock_bh",     UNLOCK, bottom_half, NO_ARG, ret_any},
	{"__read_lock_bh",      LOCK,   bottom_half, NO_ARG, ret_any},
	{"__read_unlock_bh",    UNLOCK, bottom_half, NO_ARG, ret_any},
	{"_raw_read_lock_bh",   LOCK,   bottom_half, NO_ARG, ret_any},
	{"_raw_read_unlock_bh", UNLOCK, bottom_half, NO_ARG, ret_any},
	{"write_lock_bh",       LOCK,   bottom_half, NO_ARG, ret_any},
	{"write_unlock_bh",     UNLOCK, bottom_half, NO_ARG, ret_any},
	{"_write_lock_bh",      LOCK,   bottom_half, NO_ARG, ret_any},
	{"_write_unlock_bh",    UNLOCK, bottom_half, NO_ARG, ret_any},
	{"__write_lock_bh",     LOCK,   bottom_half, NO_ARG, ret_any},
	{"__write_unlock_bh",   UNLOCK, bottom_half, NO_ARG, ret_any},
	{"_raw_write_lock_bh",  LOCK,   bottom_half, NO_ARG, ret_any},
	{"_raw_write_unlock_bh",UNLOCK, bottom_half, NO_ARG, ret_any},
	{"spin_trylock_bh",     LOCK,   bottom_half, NO_ARG, ret_one},
	{"_spin_trylock_bh",    LOCK,   bottom_half, NO_ARG, ret_one},
	{"__spin_trylock_bh",   LOCK,   bottom_half, NO_ARG, ret_one},

	{"ffs_mutex_lock",      LOCK,   mutex, 0, ret_zero},

	{"clk_prepare_lock",    LOCK,   prepare_lock, NO_ARG, ret_any},
	{"clk_prepare_unlock",  UNLOCK, prepare_lock, NO_ARG, ret_any},
	{"clk_enable_lock",     LOCK,   enable_lock, -1, ret_any},
	{"clk_enable_unlock",   UNLOCK, enable_lock,  0, ret_any},

	{"dma_resv_lock",	        LOCK,   mutex, 0, ret_zero},
	{"dma_resv_trylock",	        LOCK,	mutex, 0, ret_one},
	{"dma_resv_lock_interruptible", LOCK,	mutex, 0, ret_zero},
	{"dma_resv_unlock",		UNLOCK, mutex, 0, ret_any},

	{"modeset_lock",			  LOCK,   mutex, 0, ret_zero},
	{"drm_ modeset_lock",			  LOCK,   mutex, 0, ret_zero},
	{"drm_modeset_lock_single_interruptible", LOCK,   mutex, 0, ret_zero},
	{"modeset_unlock",			  UNLOCK, mutex, 0, ret_any},

	{"reiserfs_write_lock_nested",	 LOCK,   mutex, 0, ret_any},
	{"reiserfs_write_unlock_nested", UNLOCK, mutex, 0, ret_any},

	{"rw_lock",                LOCK,   write_lock, 1, ret_any},
	{"rw_unlock",              UNLOCK, write_lock, 1, ret_any},

	{"sem_lock",               LOCK,   mutex, 0, ret_any},
	{"sem_unlock",             UNLOCK, mutex, 0, ret_any},

	{},
};

struct macro_info {
	const char *macro;
	enum action action;
	int param;
};

static struct macro_info macro_table[] = {
	{"genpd_lock",               LOCK,   0},
	{"genpd_lock_nested",        LOCK,   0},
	{"genpd_lock_interruptible", LOCK,   0},
	{"genpd_unlock",             UNLOCK, 0},
};

static const char *false_positives[][2] = {
	{"fs/jffs2/", "->alloc_sem"},
	{"fs/xfs/", "->b_sema"},
	{"mm/", "pvmw->ptl"},
};

static struct stree *start_states;
static struct stree_stack *saved_stack;

static struct tracker_list *locks;

static void reset(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &start_state);
}

static struct expression *remove_spinlock_check(struct expression *expr)
{
	if (expr->type != EXPR_CALL)
		return expr;
	if (expr->fn->type != EXPR_SYMBOL)
		return expr;
	if (strcmp(expr->fn->symbol_name->name, "spinlock_check"))
		return expr;
	expr = get_argument_from_call_expr(expr->args, 0);
	return expr;
}

static struct expression *filter_kernel_args(struct expression *arg)
{
	if (arg->type == EXPR_PREOP && arg->op == '&')
		return strip_expr(arg->unop);
	if (!is_pointer(arg))
		return arg;
	return deref_expression(strip_expr(arg));
}

static char *lock_to_name_sym(struct expression *expr, struct symbol **sym)
{
	expr = remove_spinlock_check(expr);
	expr = filter_kernel_args(expr);
	return expr_to_str_sym(expr, sym);
}

static char *get_full_name(struct expression *expr, int index, struct symbol **sym)
{
	struct lock_info *lock = &lock_table[index];
	struct expression *arg;

	*sym = NULL;
	if (lock->arg == RETURN_VAL) {
		return expr_to_var_sym(strip_expr(expr->left), sym);
	} else if (lock->arg == NO_ARG) {
		return alloc_string(get_lock_name(lock->type));
	} else {
		arg = get_argument_from_call_expr(expr->args, lock->arg);
		if (!arg)
			return NULL;
		return lock_to_name_sym(arg, sym);
	}
}

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	return &start_state;
}

static void pre_merge_hook(struct sm_state *cur, struct sm_state *other)
{
	if (is_impossible_path())
		set_state(my_id, cur->name, cur->sym, &impossible);
}

static struct smatch_state *merge_func(struct smatch_state *s1, struct smatch_state *s2)
{
	if (s1 == &impossible)
		return s2;
	if (s2 == &impossible)
		return s1;
	return &merged;
}

static struct smatch_state *action_to_state(enum action lock_unlock)
{
	switch (lock_unlock) {
	case LOCK:
		return &locked;
	case UNLOCK:
		return &unlocked;
	case RESTORE:
		return &restore;
	}
	return NULL;
}

static struct sm_state *get_best_match(const char *key, enum action lock_unlock)
{
	struct sm_state *sm;
	struct sm_state *match;
	int cnt = 0;
	int start_pos, state_len, key_len, chunks, i;

	if (strncmp(key, "$->", 3) == 0)
		key += 3;

	key_len = strlen(key);
	chunks = 0;
	for (i = key_len - 1; i > 0; i--) {
		if (key[i] == '>' || key[i] == '.')
			chunks++;
		if (chunks == 2) {
			key += (i + 1);
			key_len = strlen(key);
			break;
		}
	}

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (((lock_unlock == UNLOCK || lock_unlock == RESTORE) &&
		     sm->state != &locked) ||
		    (lock_unlock == LOCK && sm->state != &unlocked))
			continue;
		state_len = strlen(sm->name);
		if (state_len < key_len)
			continue;
		start_pos = state_len - key_len;
		if ((start_pos == 0 || !isalnum(sm->name[start_pos - 1])) &&
		    strcmp(sm->name + start_pos, key) == 0) {
			cnt++;
			match = sm;
		}
	} END_FOR_EACH_SM(sm);

	if (cnt == 1)
		return match;
	return NULL;
}

static void use_best_match(char *key, enum action lock_unlock)
{
	struct sm_state *match;

	match = get_best_match(key, lock_unlock);
	if (match)
		set_state(my_id, match->name, match->sym, action_to_state(lock_unlock));
	else
		set_state(my_id, key, NULL, action_to_state(lock_unlock));
}

static void set_start_state(const char *name, struct symbol *sym, struct smatch_state *start)
{
	struct smatch_state *orig;

	orig = get_state_stree(start_states, my_id, name, sym);
	if (!orig)
		set_state_stree(&start_states, my_id, name, sym, start);
	else if (orig != start)
		set_state_stree(&start_states, my_id, name, sym, &undefined);
}

static bool common_false_positive(const char *name)
{
	const char *path, *lname;
	int i, len_total, len_path, len_name, skip;

	if (!get_filename())
		return false;

	len_total = strlen(name);
	for (i = 0; i < ARRAY_SIZE(false_positives); i++) {
		path = false_positives[i][0];
		lname = false_positives[i][1];

		len_path = strlen(path);
		len_name = strlen(lname);

		if (len_name > len_total)
			continue;
		skip = len_total - len_name;

		if (strncmp(get_filename(), path, len_path) == 0 &&
		    strcmp(name + skip, lname) == 0)
			return true;
	}

	return false;
}

static void warn_on_double(struct sm_state *sm, struct smatch_state *state)
{
	struct sm_state *tmp;

	if (!sm)
		return;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (tmp->state == state)
			goto found;
	} END_FOR_EACH_PTR(tmp);

	return;
found:
	if (strcmp(sm->name, "bottom_half") == 0)
		return;
	if (common_false_positive(sm->name))
		return;
	sm_msg("error: double %s '%s' (orig line %u)",
	       state->name, sm->name, tmp->line);
}

static bool handle_macro_lock_unlock(void)
{
	struct expression *expr, *arg;
	struct macro_info *info;
	struct sm_state *sm;
	struct symbol *sym;
	const char *macro;
	char *name;
	bool ret = false;
	int i;

	expr = last_ptr_list((struct ptr_list *)big_expression_stack);
	while (expr && expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (!expr || expr->type != EXPR_CALL)
		return false;

	macro = get_macro_name(expr->pos);
	if (!macro)
		return false;

	for (i = 0; i < ARRAY_SIZE(macro_table); i++) {
		info = &macro_table[i];

		if (strcmp(macro, info->macro) != 0)
			continue;
		arg = get_argument_from_call_expr(expr->args, info->param);
		name = expr_to_str_sym(arg, &sym);
		if (!name || !sym)
			goto free;
		sm = get_sm_state(my_id, name, sym);

		if (info->action == LOCK) {
			if (!sm)
				set_start_state(name, sym, &unlocked);
			if (sm && sm->line != expr->pos.line)
				warn_on_double(sm, &locked);
			set_state(my_id, name, sym, &locked);
		} else {
			if (!sm)
				set_start_state(name, sym, &locked);
			if (sm && sm->line != expr->pos.line)
				warn_on_double(sm, &unlocked);
			set_state(my_id, name, sym, &unlocked);
		}
		ret = true;
free:
		free_string(name);
		return ret;
	}
	return false;
}

static void do_lock(const char *name, struct symbol *sym, struct lock_info *info)
{
	struct sm_state *sm;

	if (handle_macro_lock_unlock())
		return;

	add_tracker(&locks, my_id, name, sym);

	sm = get_sm_state(my_id, name, sym);
	if (!sm)
		set_start_state(name, sym, &unlocked);
	warn_on_double(sm, &locked);
	set_state(my_id, name, sym, &locked);
}

static void do_lock_failed(const char *name, struct symbol *sym)
{
	add_tracker(&locks, my_id, name, sym);
	set_state(my_id, name, sym, &unlocked);
}

static void do_unlock(const char *name, struct symbol *sym, struct lock_info *info)
{
	struct sm_state *sm;

	if (__path_is_null())
		return;

	if (handle_macro_lock_unlock())
		return;

	add_tracker(&locks, my_id, name, sym);
	sm = get_sm_state(my_id, name, sym);
	if (!sm) {
		sm = get_best_match(name, UNLOCK);
		if (sm) {
			name = sm->name;
			sym = sm->sym;
		}
	}
	if (!sm)
		set_start_state(name, sym, &locked);
	warn_on_double(sm, &unlocked);
	set_state(my_id, name, sym, &unlocked);
}

static void do_restore(const char *name, struct symbol *sym, struct lock_info *info)
{
	if (__path_is_null())
		return;

	if (!get_state(my_id, name, sym))
		set_start_state(name, sym, &locked);

	add_tracker(&locks, my_id, name, sym);
	set_state(my_id, name, sym, &restore);
}

static void match_lock_held(const char *fn, struct expression *call_expr,
			    struct expression *assign_expr, void *_index)
{
	int index = PTR_INT(_index);
	struct lock_info *lock = &lock_table[index];
	char *lock_name;
	struct symbol *sym;

	if (lock->arg == NO_ARG) {
		lock_name = get_full_name(NULL, index, &sym);
	} else if (lock->arg == RETURN_VAL) {
		if (!assign_expr)
			return;
		lock_name = get_full_name(assign_expr, index, &sym);
	} else {
		lock_name = get_full_name(call_expr, index, &sym);
	}
	if (!lock_name)
		return;
	do_lock(lock_name, sym, lock);
	free_string(lock_name);
}

static void match_lock_failed(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *_index)
{
	int index = PTR_INT(_index);
	struct lock_info *lock = &lock_table[index];
	char *lock_name;
	struct symbol *sym;

	if (lock->arg == NO_ARG) {
		lock_name = get_full_name(NULL, index, &sym);
	} else if (lock->arg == RETURN_VAL) {
		if (!assign_expr)
			return;
		lock_name = get_full_name(assign_expr, index, &sym);
	} else {
		lock_name = get_full_name(call_expr, index, &sym);
	}
	if (!lock_name)
		return;
	do_lock_failed(lock_name, sym);
	free_string(lock_name);
}

static void match_returns_locked(const char *fn, struct expression *expr,
				      void *_index)
{
	int index = PTR_INT(_index);
	struct lock_info *lock = &lock_table[index];
	char *full_name;
	struct symbol *sym;

	if (lock->arg != RETURN_VAL)
		return;
	full_name = get_full_name(expr, index, &sym);
	if (!full_name)
		return;
	do_lock(full_name, sym, lock);
}

static void match_lock_unlock(const char *fn, struct expression *expr, void *_index)
{
	int index = PTR_INT(_index);
	struct lock_info *lock = &lock_table[index];
	char *full_name;
	struct symbol *sym;

	full_name = get_full_name(expr, index, &sym);
	if (!full_name)
		return;
	switch (lock->action) {
	case LOCK:
		do_lock(full_name, sym, lock);
		break;
	case UNLOCK:
		do_unlock(full_name, sym, lock);
		break;
	case RESTORE:
		do_restore(full_name, sym, lock);
		break;
	}
	free_string(full_name);
}

static struct smatch_state *get_start_state(struct sm_state *sm)
{
	struct smatch_state *orig;

	orig = get_state_stree(start_states, my_id, sm->name, sm->sym);
	if (orig)
		return orig;
	return &undefined;
}

static int get_param_lock_name(struct sm_state *sm, struct expression *expr,
			       const char **name)
{
	char *other_name;
	struct symbol *other_sym;
	const char *param_name;
	int param;

	*name = sm->name;

	param = get_param_num_from_sym(sm->sym);
	if (param >= 0) {
		param_name = get_param_name(sm);
		if (param_name)
			*name = param_name;
		return param;
	}

	if (expr) {
		struct symbol *ret_sym;
		char *ret_str;

		ret_str = expr_to_str_sym(expr, &ret_sym);
		if (ret_str && ret_sym == sm->sym) {
			param_name = state_name_to_param_name(sm->name, ret_str);
			if (param_name) {
				free_string(ret_str);
				*name = param_name;
				return -1;
			}
		}
		free_string(ret_str);
	}

	other_name = get_other_name_sym(sm->name, sm->sym, &other_sym);
	if (!other_name)
		return -2;
	param = get_param_num_from_sym(other_sym);
	if (param < 0)
		return -2;

	param_name = get_param_name_var_sym(other_name, other_sym);
	free_string(other_name);
	if (param_name)
		*name = param_name;
	return param;
}

static int get_db_type(struct sm_state *sm)
{
	if (sm->state == get_start_state(sm)) {
		if (sm->state == &locked)
			return KNOWN_LOCKED;
		if (sm->state == &unlocked)
			return KNOWN_UNLOCKED;
	}

	if (sm->state == &locked)
		return LOCKED;
	if (sm->state == &unlocked)
		return UNLOCKED;
	if (sm->state == &restore)
		return LOCK_RESTORED;
	return LOCKED;
}

static void match_return_info(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *sm;
	const char *param_name;
	int param;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->state != &locked &&
		    sm->state != &unlocked &&
		    sm->state != &restore)
			continue;

		param = get_param_lock_name(sm, expr, &param_name);
		sql_insert_return_states(return_id, return_ranges,
					 get_db_type(sm),
					 param, param_name, "");
	} END_FOR_EACH_SM(sm);
}

enum {
	ERR_PTR, VALID_PTR, NEGATIVE, ZERO, POSITIVE, NUM_BUCKETS,
};

static bool is_EINTR(struct range_list *rl)
{
	sval_t sval;

	if (!rl_to_sval(rl, &sval))
		return false;
	return sval.value == -4;
}

static int success_fail_positive(struct range_list *rl)
{
	/* void returns are the same as success (zero in the kernel) */
	if (!rl)
		return ZERO;

	if (rl_type(rl)->type != SYM_PTR && sval_is_negative(rl_min(rl)))
		return NEGATIVE;

	if (rl_min(rl).value == 0 && rl_max(rl).value == 0)
		return ZERO;

	if (is_err_ptr(rl_min(rl)) &&
	    is_err_ptr(rl_max(rl)))
		return ERR_PTR;

	/*
	 * Trying to match ERR_PTR(ret) but without the expression struct.
	 * Ugly...
	 */
	if (type_bits(&long_ctype) == 64 &&
	    rl_type(rl)->type == SYM_PTR &&
	    rl_min(rl).value == INT_MIN)
		return ERR_PTR;

	return POSITIVE;
}

static bool sym_in_lock_table(struct symbol *sym)
{
	int i;

	if (!sym || !sym->ident)
		return false;

	for (i = 0; lock_table[i].function != NULL; i++) {
		if (strcmp(lock_table[i].function, sym->ident->name) == 0)
			return true;
	}
	return false;
}

static bool func_in_lock_table(struct expression *expr)
{
	if (expr->type != EXPR_SYMBOL)
		return false;
	return sym_in_lock_table(expr->symbol);
}

static void check_lock(char *name, struct symbol *sym)
{
	struct range_list *locked_lines = NULL;
	struct range_list *unlocked_lines = NULL;
	int locked_buckets[NUM_BUCKETS] = {};
	int unlocked_buckets[NUM_BUCKETS] = {};
	struct stree *stree, *orig;
	struct sm_state *return_sm;
	struct sm_state *sm;
	sval_t line = sval_type_val(&int_ctype, 0);
	int bucket;
	int i;

	if (sym_in_lock_table(cur_func_sym))
		return;

	FOR_EACH_PTR(get_all_return_strees(), stree) {
		orig = __swap_cur_stree(stree);

		if (is_impossible_path())
			goto swap_stree;

		return_sm = get_sm_state(RETURN_ID, "return_ranges", NULL);
		if (!return_sm)
			goto swap_stree;
		line.value = return_sm->line;

		sm = get_sm_state(my_id, name, sym);
		if (!sm)
			goto swap_stree;

		if (parent_is_gone_var_sym(sm->name, sm->sym))
			goto swap_stree;

		if (sm->state != &locked && sm->state != &unlocked)
			goto swap_stree;

		if (sm->state == &unlocked && is_EINTR(estate_rl(return_sm->state)))
			goto swap_stree;

		bucket = success_fail_positive(estate_rl(return_sm->state));
		if (sm->state == &locked) {
			add_range(&locked_lines, line, line);
			locked_buckets[bucket] = true;
		}
		if (sm->state == &unlocked) {
			add_range(&unlocked_lines, line, line);
			unlocked_buckets[bucket] = true;
		}
swap_stree:
		__swap_cur_stree(orig);
	} END_FOR_EACH_PTR(stree);


	if (!locked_lines || !unlocked_lines)
		return;

	for (i = 0; i < NUM_BUCKETS; i++) {
		if (locked_buckets[i] && unlocked_buckets[i])
			goto complain;
	}
	if (locked_buckets[NEGATIVE] &&
	    (unlocked_buckets[ZERO] || unlocked_buckets[POSITIVE]))
		goto complain;

	if (locked_buckets[ERR_PTR])
		goto complain;

	return;

complain:
	sm_msg("warn: inconsistent returns '%s'.", name);
	sm_printf("  Locked on  : %s\n", show_rl(locked_lines));
	sm_printf("  Unlocked on: %s\n", show_rl(unlocked_lines));
}

static void match_func_end(struct symbol *sym)
{
	struct tracker *tracker;

	FOR_EACH_PTR(locks, tracker) {
		check_lock(tracker->name, tracker->sym);
	} END_FOR_EACH_PTR(tracker);
}

static void register_lock(int index)
{
	struct lock_info *lock = &lock_table[index];
	void *idx = INT_PTR(index);

	if (lock->return_type == ret_one) {
		return_implies_state(lock->function, 1, 1, &match_lock_held, idx);
		return_implies_state(lock->function, 0, 0, &match_lock_failed, idx);
	} else if (lock->return_type == ret_any && lock->arg == RETURN_VAL) {
		add_function_assign_hook(lock->function, &match_returns_locked, idx);
	} else if (lock->return_type == ret_any) {
		add_function_hook(lock->function, &match_lock_unlock, idx);
	} else if (lock->return_type == ret_zero) {
		return_implies_state(lock->function, 0, 0, &match_lock_held, idx);
		return_implies_state(lock->function, -4095, -1, &match_lock_failed, idx);
	} else if (lock->return_type == ret_valid_ptr) {
		return_implies_state_sval(lock->function, valid_ptr_min_sval, valid_ptr_max_sval, &match_lock_held, idx);
	}
}

static void load_table(struct lock_info *lock_table)
{
	int i;

	for (i = 0; lock_table[i].function != NULL; i++) {
		if (lock_table[i].action == LOCK)
			register_lock(i);
		else
			add_function_hook(lock_table[i].function, &match_lock_unlock, INT_PTR(i));
	}
}

static void db_param_locked_unlocked(struct expression *expr, int param, char *key, char *value, enum action lock_unlock)
{
	struct expression *call, *arg;
	char *name;
	struct symbol *sym;

	call = expr;
	while (call->type == EXPR_ASSIGNMENT)
		call = strip_expr(call->right);
	if (call->type != EXPR_CALL)
		return;

	if (func_in_lock_table(call->fn))
		return;

	if (param == -2) {
		use_best_match(key, lock_unlock);
		return;
	}

	if (param == -1) {
		if (expr->type != EXPR_ASSIGNMENT)
			return;
		name = get_variable_from_key(expr->left, key, &sym);
	} else {
		arg = get_argument_from_call_expr(call->args, param);
		if (!arg)
			return;

		name = get_variable_from_key(arg, key, &sym);
	}
	if (!name || !sym)
		goto free;

	if (lock_unlock == LOCK)
		do_lock(name, sym, NULL);
	else if (lock_unlock == UNLOCK)
		do_unlock(name, sym, NULL);
	else if (lock_unlock == RESTORE)
		do_restore(name, sym, NULL);

free:
	free_string(name);
}

static void db_param_locked(struct expression *expr, int param, char *key, char *value)
{
	db_param_locked_unlocked(expr, param, key, value, LOCK);
}

static void db_param_unlocked(struct expression *expr, int param, char *key, char *value)
{
	db_param_locked_unlocked(expr, param, key, value, UNLOCK);
}

static void db_param_restore(struct expression *expr, int param, char *key, char *value)
{
	db_param_locked_unlocked(expr, param, key, value, RESTORE);
}

static int get_caller_param_lock_name(struct expression *call, struct sm_state *sm, const char **name)
{
	struct expression *arg;
	char *arg_name;
	int param;

	param = 0;
	FOR_EACH_PTR(call->args, arg) {
		arg_name = sm_to_arg_name(arg, sm);
		if (arg_name) {
			*name = arg_name;
			return param;
		}
		param++;
	} END_FOR_EACH_PTR(arg);

	*name = sm->name;
	return -2;
}

static void match_call_info(struct expression *expr)
{
	struct sm_state *sm;
	const char *param_name;
	int locked_type;
	int param;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		param = get_caller_param_lock_name(expr, sm, &param_name);
		if (sm->state == &locked)
			locked_type = LOCKED;
		else if (sm->state == &half_locked ||
			 slist_has_state(sm->possible, &locked))
			locked_type = HALF_LOCKED;
		else
			continue;
		sql_insert_caller_info(expr, locked_type, param, param_name, "xxx type");

	} END_FOR_EACH_SM(sm);
}

static void match_save_states(struct expression *expr)
{
	push_stree(&saved_stack, start_states);
	start_states = NULL;
}

static void match_restore_states(struct expression *expr)
{
	start_states = pop_stree(&saved_stack);
}

static void match_after_func(struct symbol *sym)
{
	free_stree(&start_states);
}

static void match_dma_resv_lock_NULL(const char *fn, struct expression *call_expr,
				     struct expression *assign_expr, void *_index)
{
	struct expression *lock, *ctx;
	char *lock_name;
	struct symbol *sym;

	lock = get_argument_from_call_expr(call_expr->args, 0);
	ctx = get_argument_from_call_expr(call_expr->args, 1);
	if (!expr_is_zero(ctx))
		return;

	lock_name = lock_to_name_sym(lock, &sym);
	if (!lock_name || !sym)
		goto free;
	do_lock(lock_name, sym, NULL);
free:
	free_string(lock_name);
}

/* print_held_locks() is used in check_call_tree.c */
void print_held_locks(void)
{
	struct stree *stree;
	struct sm_state *sm;
	int i = 0;

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(my_id, stree, sm) {
		if (sm->state != &locked)
			continue;
		if (i++)
			sm_printf(" ");
		sm_printf("'%s'", sm->name);
	} END_FOR_EACH_SM(sm);
}

void check_locking(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;

	load_table(lock_table);

	set_dynamic_states(my_id);
	add_unmatched_state_hook(my_id, &unmatched_state);
	add_pre_merge_hook(my_id, &pre_merge_hook);
	add_merge_hook(my_id, &merge_func);
	add_modification_hook(my_id, &reset);

	add_hook(&match_func_end, END_FUNC_HOOK);

	add_hook(&match_after_func, AFTER_FUNC_HOOK);
	add_hook(&match_save_states, INLINE_FN_START);
	add_hook(&match_restore_states, INLINE_FN_END);

	add_hook(&match_call_info, FUNCTION_CALL_HOOK);

	add_split_return_callback(match_return_info);
	select_return_states_hook(LOCKED, &db_param_locked);
	select_return_states_hook(UNLOCKED, &db_param_unlocked);
	select_return_states_hook(LOCK_RESTORED, &db_param_restore);

	return_implies_state("dma_resv_lock", -4095, -1, &match_dma_resv_lock_NULL, 0);
}
