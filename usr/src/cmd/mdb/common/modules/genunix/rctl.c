/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <sys/rctl.h>
#include <sys/proc.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/zone.h>

static int
print_val(uintptr_t addr, rctl_val_t *val, uintptr_t *enforced)
{
	char *priv;
	static const mdb_bitmask_t val_localflag_bits[] = {
		{ "SIGNAL", RCTL_LOCAL_SIGNAL, RCTL_LOCAL_SIGNAL },
		{ "DENY", RCTL_LOCAL_DENY, RCTL_LOCAL_DENY },
		{ "MAX", RCTL_LOCAL_MAXIMAL, RCTL_LOCAL_MAXIMAL },
		{ NULL, 0, 0 }
	};

	switch (val->rcv_privilege) {
	case (RCPRIV_BASIC):
		priv = "basic";
		break;
	case (RCPRIV_PRIVILEGED):
		priv = "privileged";
		break;
	case (RCPRIV_SYSTEM):
		priv = "system";
		break;
	default:
		priv = "???";
		break;
	};

	mdb_printf("\t%s ", addr == *enforced ? "(cur)": "     ");

	mdb_printf("%-#18llx %11s\tflags=<%b>\n",
	    val->rcv_value, priv, val->rcv_flagaction, val_localflag_bits);

	return (WALK_NEXT);
}

int
rctl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rctl_t rctl;
	rctl_dict_entry_t dict;
	char name[256];
	rctl_hndl_t hndl;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&rctl, sizeof (rctl_t), addr) == -1) {
		mdb_warn("failed to read rctl_t structure at %p", addr);
		return (DCMD_ERR);
	}

	if (argc != 0) {
		const mdb_arg_t *argp = &argv[0];

		if (argp->a_type == MDB_TYPE_IMMEDIATE)
			hndl = (rctl_hndl_t)argp->a_un.a_val;
		else
			hndl = (rctl_hndl_t)mdb_strtoull(argp->a_un.a_str);

		if (rctl.rc_id != hndl)
			return (DCMD_OK);
	}

	if (mdb_vread(&dict, sizeof (rctl_dict_entry_t),
	    (uintptr_t)rctl.rc_dict_entry) == -1) {
		mdb_warn("failed to read dict entry for rctl_t %p at %p",
		    addr, rctl.rc_dict_entry);
		return (DCMD_ERR);
	}

	if (mdb_readstr(name, 256, (uintptr_t)(dict.rcd_name)) == -1) {
		mdb_warn("failed to read name for rctl_t %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?p\t%3d : %s\n", addr, rctl.rc_id, name);

	if (mdb_pwalk("rctl_val", (mdb_walk_cb_t)print_val, &(rctl.rc_cursor),
	    addr) == -1) {
		mdb_warn("failed to walk all values for rctl_t %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

int
rctl_dict(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rctl_dict_entry_t dict;
	char name[256], *type = NULL;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("rctl_dict_list", "rctl_dict", argc,
		    argv) == -1) {
			mdb_warn("failed to walk 'rctl_dict_list'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%2s %-27s %?s %7s %s%</u>\n",
		    "ID", "NAME", "ADDR", "TYPE", "GLOBAL_FLAGS");

	if (mdb_vread(&dict, sizeof (dict), addr) == -1) {
		mdb_warn("failed to read rctl_dict at %p", addr);
		return (DCMD_ERR);
	}
	if (mdb_readstr(name, 256, (uintptr_t)(dict.rcd_name)) == -1) {
		mdb_warn("failed to read rctl_dict name for %p", addr);
		return (DCMD_ERR);
	}

	switch (dict.rcd_entity) {
	case RCENTITY_PROCESS:
		type = "process";
		break;
	case RCENTITY_TASK:
		type = "task";
		break;
	case RCENTITY_PROJECT:
		type = "project";
		break;
	case RCENTITY_ZONE:
		type = "zone";
		break;
	default:
		type = "unknown";
		break;
	}

	mdb_printf("%2d %-27s %0?p %7s 0x%08x", dict.rcd_id, name, addr,
	    type, dict.rcd_flagaction);

	return (DCMD_OK);
}

typedef struct dict_data {
	rctl_hndl_t hndl;
	uintptr_t dict_addr;
	rctl_entity_t type;
} dict_data_t;

static int
hndl2dict(uintptr_t addr, rctl_dict_entry_t *entry, dict_data_t *data)
{
	if (data->hndl == entry->rcd_id) {
		data->dict_addr = addr;
		data->type = entry->rcd_entity;
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

/*
 * Print out all project, task, and process rctls for a given process.
 * If a handle is specified, print only the rctl matching that handle
 * for the process.
 */
int
rctl_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	proc_t proc;
	uintptr_t set;
	task_t task;
	kproject_t proj;
	zone_t zone;
	dict_data_t rdict;
	int i;

	rdict.dict_addr = 0;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (argc == 0)
		rdict.hndl = 0;
	else if (argc == 1) {
		/*
		 * User specified a handle. Go find the rctl_dict_entity_t
		 * structure so we know what type of rctl to look for.
		 */
		const mdb_arg_t *argp = &argv[0];

		if (argp->a_type == MDB_TYPE_IMMEDIATE)
			rdict.hndl = (rctl_hndl_t)argp->a_un.a_val;
		else
			rdict.hndl =
			    (rctl_hndl_t)mdb_strtoull(argp->a_un.a_str);

		if (mdb_walk("rctl_dict_list", (mdb_walk_cb_t)hndl2dict,
		    &rdict) == -1) {
			mdb_warn("failed to walk rctl_dict_list");
			return (DCMD_ERR);
		}
		/* Couldn't find a rctl_dict_entry_t for this handle */
		if (rdict.dict_addr == 0)
			return (DCMD_ERR);
	} else
		return (DCMD_USAGE);


	if (mdb_vread(&proc, sizeof (proc_t), addr) == -1) {
		mdb_warn("failed to read proc at %p", addr);
		return (DCMD_ERR);
	}
	if (mdb_vread(&zone, sizeof (zone_t), (uintptr_t)proc.p_zone) == -1) {
		mdb_warn("failed to read zone at %p", proc.p_zone);
		return (DCMD_ERR);
	}
	if (mdb_vread(&task, sizeof (task_t), (uintptr_t)proc.p_task) == -1) {
		mdb_warn("failed to read task at %p", proc.p_task);
		return (DCMD_ERR);
	}
	if (mdb_vread(&proj, sizeof (kproject_t),
	    (uintptr_t)task.tk_proj) == -1) {
		mdb_warn("failed to read proj at %p", task.tk_proj);
		return (DCMD_ERR);
	}

	for (i = 0; i <= RC_MAX_ENTITY; i++) {
		/*
		 * If user didn't specify a handle, print rctls for all
		 * types. Otherwise, we can walk the rctl_set for only the
		 * entity specified by the handle.
		 */
		if (rdict.hndl != 0 && rdict.type != i)
			continue;

		switch (i) {
		case (RCENTITY_PROCESS):
			set = (uintptr_t)proc.p_rctls;
			break;
		case (RCENTITY_TASK):
			set = (uintptr_t)task.tk_rctls;
			break;
		case (RCENTITY_PROJECT):
			set = (uintptr_t)proj.kpj_rctls;
			break;
		case (RCENTITY_ZONE):
			set = (uintptr_t)zone.zone_rctls;
			break;
		default:
			mdb_warn("Unknown rctl type %d", i);
			return (DCMD_ERR);
		}

		if (mdb_pwalk_dcmd("rctl_set", "rctl", argc, argv, set) == -1) {
			mdb_warn("failed to walk rctls in set %p", set);
			return (DCMD_ERR);
		}
	}

	return (DCMD_OK);
}

typedef struct dict_walk_data {
	int num_dicts;
	int num_cur;
	rctl_dict_entry_t **curdict;
} dict_walk_data_t;

int
rctl_dict_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t ptr;
	int nlists;
	GElf_Sym sym;
	rctl_dict_entry_t **dicts;
	dict_walk_data_t *dwd;

	if (mdb_lookup_by_name("rctl_lists", &sym) == -1) {
		mdb_warn("failed to find 'rctl_lists'\n");
		return (WALK_ERR);
	}

	nlists = sym.st_size / sizeof (rctl_dict_entry_t *);
	ptr = (uintptr_t)sym.st_value;

	dicts = mdb_alloc(nlists * sizeof (rctl_dict_entry_t *), UM_SLEEP);
	mdb_vread(dicts, sym.st_size, ptr);

	dwd = mdb_alloc(sizeof (dict_walk_data_t), UM_SLEEP);
	dwd->num_dicts = nlists;
	dwd->num_cur = 0;
	dwd->curdict = dicts;

	wsp->walk_addr = 0;
	wsp->walk_data = dwd;

	return (WALK_NEXT);
}

int
rctl_dict_walk_step(mdb_walk_state_t *wsp)
{
	dict_walk_data_t *dwd = wsp->walk_data;
	uintptr_t dp;
	rctl_dict_entry_t entry;
	int status;

	dp = (uintptr_t)((dwd->curdict)[dwd->num_cur]);

	while (dp != 0) {
		if (mdb_vread(&entry, sizeof (rctl_dict_entry_t), dp) == -1) {
			mdb_warn("failed to read rctl_dict_entry_t structure "
			    "at %p", dp);
			return (WALK_ERR);
		}

		status = wsp->walk_callback(dp, &entry, wsp->walk_cbdata);
		if (status != WALK_NEXT)
			return (status);

		dp = (uintptr_t)entry.rcd_next;
	}

	dwd->num_cur++;

	if (dwd->num_cur == dwd->num_dicts)
		return (WALK_DONE);

	return (WALK_NEXT);
}

void
rctl_dict_walk_fini(mdb_walk_state_t *wsp)
{
	dict_walk_data_t *wd = wsp->walk_data;
	mdb_free(wd->curdict, wd->num_dicts * sizeof (rctl_dict_entry_t *));
	mdb_free(wd, sizeof (dict_walk_data_t));
}

typedef struct set_walk_data {
	uint_t hashsize;
	int hashcur;
	void **hashloc;
} set_walk_data_t;

int
rctl_set_walk_init(mdb_walk_state_t *wsp)
{
	rctl_set_t rset;
	uint_t hashsz;
	set_walk_data_t *swd;
	rctl_t **rctls;

	if (mdb_vread(&rset, sizeof (rctl_set_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read rset at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_readvar(&hashsz, "rctl_set_size") == -1 || hashsz == 0) {
		mdb_warn("rctl_set_size not found or invalid");
		return (WALK_ERR);
	}

	rctls = mdb_alloc(hashsz * sizeof (rctl_t *), UM_SLEEP);
	if (mdb_vread(rctls, hashsz * sizeof (rctl_t *),
	    (uintptr_t)rset.rcs_ctls) == -1) {
		mdb_warn("cannot read rctl hash at %p", rset.rcs_ctls);
		mdb_free(rctls, hashsz * sizeof (rctl_t *));
		return (WALK_ERR);
	}

	swd = mdb_alloc(sizeof (set_walk_data_t), UM_SLEEP);
	swd->hashsize = hashsz;
	swd->hashcur = 0;
	swd->hashloc = (void **)rctls;

	wsp->walk_addr = 0;
	wsp->walk_data = swd;

	return (WALK_NEXT);
}


int
rctl_set_walk_step(mdb_walk_state_t *wsp)
{
	set_walk_data_t	*swd = wsp->walk_data;
	rctl_t rctl;
	void **rhash = swd->hashloc;
	int status;

	if (swd->hashcur >= swd->hashsize)
		return (WALK_DONE);

	if (wsp->walk_addr == 0) {
		while (swd->hashcur < swd->hashsize) {
			if (rhash[swd->hashcur] != NULL) {
				break;
			}
			swd->hashcur++;
		}

		if (rhash[swd->hashcur] == NULL ||
		    swd->hashcur >= swd->hashsize)
			return (WALK_DONE);

		wsp->walk_addr = (uintptr_t)rhash[swd->hashcur];
		swd->hashcur++;
	}

	if (mdb_vread(&rctl, sizeof (rctl_t), wsp->walk_addr) == -1) {
		wsp->walk_addr = 0;
		mdb_warn("unable to read from %#p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &rctl, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)rctl.rc_next;

	return (status);
}

void
rctl_set_walk_fini(mdb_walk_state_t *wsp)
{
	set_walk_data_t *sd = wsp->walk_data;

	mdb_free(sd->hashloc, sd->hashsize * sizeof (rctl_t *));
	mdb_free(sd, sizeof (set_walk_data_t));
}

int
rctl_val_walk_init(mdb_walk_state_t *wsp)
{
	rctl_t rctl;

	if (mdb_vread(&rctl, sizeof (rctl_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read rctl at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)rctl.rc_values;
	wsp->walk_data = rctl.rc_values;
	return (WALK_NEXT);
}

int
rctl_val_walk_step(mdb_walk_state_t *wsp)
{
	rctl_val_t val;
	int status;

	if (mdb_vread(&val, sizeof (rctl_val_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read rctl_val at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, &val, wsp->walk_cbdata);

	if ((wsp->walk_addr = (uintptr_t)val.rcv_next) == 0)
		return (WALK_DONE);

	return (status);
}

typedef struct rctl_val_seen {
	uintptr_t		s_ptr;
	rctl_qty_t		s_val;
} rctl_val_seen_t;

typedef struct rctl_validate_data {
	uintptr_t		v_rctl_addr;
	rctl_val_t		*v_cursor;
	uint_t			v_flags;
	int			v_bad_rctl;
	int			v_cursor_valid;
	int			v_circularity_detected;
	uint_t			v_seen_size;
	uint_t			v_seen_cnt;
	rctl_val_seen_t		*v_seen;
} rctl_validate_data_t;

#define	RCV_VERBOSE 0x1

/*
 * rctl_val_validate()
 * Do validation on an individual rctl_val_t. This function is called
 * as part of the rctl_val walker, and helps perform the checks described
 * in the ::rctl_validate dcmd.
 */
static int
rctl_val_validate(uintptr_t addr, rctl_val_t *val, rctl_validate_data_t *data)
{
	int i;

	data->v_seen[data->v_seen_cnt].s_ptr = addr;

	if (addr == (uintptr_t)data->v_cursor)
		data->v_cursor_valid++;

	data->v_seen[data->v_seen_cnt].s_val = val->rcv_value;

	if (val->rcv_prev == (void *)0xbaddcafe ||
	    val->rcv_next == (void *)0xbaddcafe ||
	    val->rcv_prev == (void *)0xdeadbeef ||
	    val->rcv_next == (void *)0xdeadbeef) {
		if (data->v_bad_rctl++ == 0)
			mdb_printf("%p ", data->v_rctl_addr);
		if (data->v_flags & RCV_VERBOSE)
			mdb_printf("/ uninitialized or previously "
			    "freed link at %p ", addr);
	}

	if (data->v_seen_cnt == 0) {
		if (val->rcv_prev != NULL) {
			if (data->v_bad_rctl++ == 0)
				mdb_printf("%p ", data->v_rctl_addr);
			if (data->v_flags & RCV_VERBOSE)
				mdb_printf("/ bad prev pointer at "
				    "head ");
		}
	} else {
		if ((uintptr_t)val->rcv_prev !=
		    data->v_seen[data->v_seen_cnt - 1].s_ptr) {
			if (data->v_bad_rctl++ == 0)
				mdb_printf("%p ", data->v_rctl_addr);
			if (data->v_flags & RCV_VERBOSE)
				mdb_printf("/ bad prev pointer at %p ",
				    addr);
		}

		if (data->v_seen[data->v_seen_cnt].s_val <
		    data->v_seen[data->v_seen_cnt - 1].s_val) {
			if (data->v_bad_rctl++ == 0)
				mdb_printf("%p ", data->v_rctl_addr);
			if (data->v_flags & RCV_VERBOSE)
				mdb_printf("/ ordering error at %p ",
				    addr);
		}
	}

	for (i = data->v_seen_cnt; i >= 0; i--) {
		if (data->v_seen[i].s_ptr == (uintptr_t)val->rcv_next) {
			if (data->v_bad_rctl++ == 0)
				mdb_printf("%p ", data->v_rctl_addr);
			if (data->v_flags & RCV_VERBOSE)
				mdb_printf("/ circular next pointer "
				    "at %p ", addr);
			data->v_circularity_detected++;
			break;
		}
	}

	if (data->v_circularity_detected)
		return (WALK_DONE);

	data->v_seen_cnt++;
	if (data->v_seen_cnt >= data->v_seen_size) {
		uint_t new_seen_size = data->v_seen_size * 2;
		rctl_val_seen_t *tseen = mdb_zalloc(new_seen_size *
		    sizeof (rctl_val_seen_t), UM_SLEEP | UM_GC);

		bcopy(data->v_seen, tseen, data->v_seen_size *
		    sizeof (rctl_val_seen_t));

		data->v_seen = tseen;
		data->v_seen_size = new_seen_size;
	}

	return (WALK_NEXT);
}

/*
 * Validate a rctl pointer by checking:
 *   - rctl_val_t's for that rctl form an ordered, non-circular list
 *   - the cursor points to a rctl_val_t within that list
 *   - there are no more than UINT64_MAX (or # specified by -n)
 *     rctl_val_t's in the list
 */
int
rctl_validate(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rctl_validate_data_t data;

	rctl_t r;

	uint64_t long_threshold = UINT64_MAX;

	/* Initialize validate data structure */
	data.v_rctl_addr = addr;
	data.v_flags = 0;
	data.v_bad_rctl = 0;
	data.v_seen_cnt = 0;
	data.v_cursor_valid = 0;
	data.v_circularity_detected = 0;
	data.v_seen_size = 1;
	data.v_seen = mdb_zalloc(data.v_seen_size * sizeof (rctl_val_seen_t),
	    UM_SLEEP | UM_GC);

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, RCV_VERBOSE, &data.v_flags,
	    'n', MDB_OPT_UINT64, &long_threshold,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&r, sizeof (rctl_t), addr) != sizeof (rctl_t)) {
		mdb_warn("failed to read rctl structure at %p", addr);
		return (DCMD_ERR);
	}

	data.v_cursor = r.rc_cursor;

	if (data.v_cursor == NULL) {
		if (data.v_bad_rctl++ == 0)
			mdb_printf("%p ", addr);
		if (data.v_flags & RCV_VERBOSE)
			mdb_printf("/ NULL cursor seen ");
	} else if (data.v_cursor == (rctl_val_t *)0xbaddcafe) {
		if (data.v_bad_rctl++ == 0)
			mdb_printf("%p ", addr);
		if (data.v_flags & RCV_VERBOSE)
			mdb_printf("/ uninitialized cursor seen ");
	}

	/* Walk through each val in this rctl for individual validation. */
	if (mdb_pwalk("rctl_val", (mdb_walk_cb_t)rctl_val_validate, &data,
	    addr) == -1) {
		mdb_warn("failed to walk all values for rctl_t %p", addr);
		return (DCMD_ERR);
	}

	if (data.v_seen_cnt >= long_threshold) {
		if (data.v_bad_rctl++ == 0)
			mdb_printf("%p ", addr);
		if (data.v_flags & RCV_VERBOSE)
			mdb_printf("/ sequence length = %d ",
			    data.v_seen_cnt);
	}

	if (!data.v_cursor_valid) {
		if (data.v_bad_rctl++ == 0)
			mdb_printf("%p ", addr);
		if (data.v_flags & RCV_VERBOSE)
			mdb_printf("/ cursor outside sequence");
	}

	if (data.v_bad_rctl)
		mdb_printf("\n");

	if (data.v_circularity_detected)
		mdb_warn("circular list implies possible memory leak; "
		    "recommend invoking ::findleaks");

	return (DCMD_OK);
}
