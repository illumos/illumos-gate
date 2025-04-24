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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Common code to help printing stack frames in a consistent way, and with
 * options to include frame size and type data where it can be retrieved from
 * CTF data.
 */

#include <sys/types.h>

#include <mdb/mdb_string.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_isautil.h>
#include <mdb/mdb_stack.h>
#include <mdb/mdb.h>

typedef struct {
	mdb_tgt_t		*msfd_tgt;
	uint_t			msfd_arglim;
	mdb_stack_frame_flags_t	msfd_flags;
	uintptr_t		msfd_lastbp;
	boolean_t		(*msfd_callcheck)(uintptr_t);
	char			*msfd_buf;
	size_t			msfd_buflen;
} mdb_stack_frame_data_t;

mdb_stack_frame_hdl_t *
mdb_stack_frame_init(mdb_tgt_t *tgt, uint_t arglim,
    mdb_stack_frame_flags_t flags)
{
	mdb_stack_frame_data_t *data;

	data = mdb_alloc(sizeof (*data), UM_SLEEP | UM_GC);
	if (data == NULL)
		return (NULL);
	data->msfd_tgt = tgt;
	data->msfd_arglim = arglim;
	data->msfd_flags = flags;
	data->msfd_lastbp = 0;
	data->msfd_buf = NULL;
	data->msfd_buflen = 0;

	return (data);
}

uint_t
mdb_stack_frame_arglim(mdb_stack_frame_hdl_t *datap)
{
	mdb_stack_frame_data_t *data = datap;

	return (data->msfd_arglim);
}

void
mdb_stack_frame_flags_set(mdb_stack_frame_hdl_t *datap,
    mdb_stack_frame_flags_t flags)
{
	mdb_stack_frame_data_t *data = datap;

	ASSERT((flags & ~MSF_ALL) == 0);
	data->msfd_flags |= flags;
}

static char *
mdb_stack_typename(mdb_ctf_id_t id, char **bufp, size_t *lenp)
{
	char *buf = *bufp;
	size_t len = *lenp;
	ssize_t newlen;

	if (mdb_ctf_type_name(id, buf, len) != NULL)
		return (buf);

	/*
	 * Retrieve the buffer size required to store this type.
	 */
	newlen = mdb_ctf_type_lname(id, NULL, 0) + 1;
	/*
	 * To avoid reallocations in most cases, we always allocate at least
	 * space for 32 characters and the NUL terminator. This will
	 * accommodate most types.
	 */
	newlen = MAX(newlen, 33);
	if (newlen > len) {
		char *newbuf = mdb_alloc(newlen, UM_SLEEP | UM_GC);
		if (newbuf == NULL)
			return (NULL);
		mdb_free(buf, len);
		*bufp = newbuf;
		*lenp = newlen;
		return (mdb_ctf_type_name(id, newbuf, newlen));
	}

	return (NULL);
}

void
mdb_stack_frame(mdb_stack_frame_hdl_t *datap, uintptr_t pc, uintptr_t bp,
    uint_t argc, const long *argv)
{
	mdb_stack_frame_data_t *data = datap;
	uint_t nargc = MIN(argc, data->msfd_arglim);
	mdb_ctf_id_t argtypes[nargc];
	mdb_ctf_funcinfo_t mcfi;
	boolean_t ctf;
	mdb_syminfo_t msi;
	uintptr_t npc;
	GElf_Sym sym;
	uint_t i;
	int ret;

	ctf = B_FALSE;
	npc = pc;

	ret = mdb_tgt_lookup_by_addr(data->msfd_tgt, pc, MDB_TGT_SYM_FUZZY,
	    NULL, 0, &sym, &msi);

	if (ret != 0 || sym.st_value == pc) {
		/*
		 * One of two things is going on here. Either:
		 *
		 * - this address is not covered by a symbol, or
		 * - there is a symbol but our address points directly to the
		 *   start of it.
		 *
		 * Both cases can arise when the return address is from a call
		 * to a function that the compiler knows will never return. In
		 * these cases the compiler may elide the caller’s epilogue,
		 * leaving the return address pointing just past the end of the
		 * callee; either into the next function or into padding
		 * between functions.
		 *
		 * If the previous address is covered by a symbol, we use that
		 * symbol instead and mark it as approximate with a tilde (~)
		 * in the output. The platform must provide a callback that
		 * uses heuristics to to determine whether the preceding
		 * instruction could plausibly represent a function call that
		 * would result in the current return address. For example, an
		 * unconditional jump is typically not valid as it would not
		 * preserve the return address.
		 */
		if (pc > 0) {
			ret = mdb_tgt_lookup_by_addr(data->msfd_tgt, pc - 1,
			    MDB_TGT_SYM_FUZZY, NULL, 0, &sym, &msi);
			if (ret == 0 && mdb_isa_prev_callcheck(pc))
				npc = pc - 1;
		}
	}

	if (ret == 0 && (data->msfd_flags & MSF_TYPES)) {
		if (mdb_ctf_func_info(&sym, &msi, &mcfi) == 0)
			ctf = B_TRUE;
	}

	if (data->msfd_flags & MSF_SIZES) {
		if (data->msfd_lastbp != 0)
			mdb_printf("[%4lr] ", bp - data->msfd_lastbp);
		else
			mdb_printf("%7s", "");
		data->msfd_lastbp = bp;
	}

	if (data->msfd_flags & MSF_VERBOSE)
		mdb_printf("%0?lr ", bp);

	if (ctf) {
		if (mdb_stack_typename(mcfi.mtf_return,
		    &data->msfd_buf, &data->msfd_buflen) != NULL) {
			mdb_printf("%s ", data->msfd_buf);
		}
	}

	if (data->msfd_flags & MSF_ADDR) {
		mdb_printf("%0?lr(", pc);
	} else {
		if (npc != pc)
			mdb_printf("~");
		mdb_printf("%a(", npc);
	}

	if (ctf && mdb_ctf_func_args(&mcfi, nargc, argtypes) != 0)
		ctf = B_FALSE;

	for (i = 0; i < nargc; i++) {
		if (i > 0)
			mdb_printf(", ");
		if (ctf && mdb_stack_typename(argtypes[i],
		    &data->msfd_buf, &data->msfd_buflen) != NULL) {
			const char *type = data->msfd_buf;

			switch (mdb_ctf_type_kind(argtypes[i])) {
			case CTF_K_POINTER:
				if (argv[i] == 0)
					mdb_printf("(%s)NULL", type);
				else
					mdb_printf("(%s)%lr", type, argv[i]);
				break;
			case CTF_K_ENUM: {
				const char *cp;

				cp = mdb_ctf_enum_name(argtypes[i], argv[i]);
				if (cp != NULL)
					mdb_printf("(%s)%s", type, cp);
				else
					mdb_printf("(%s)%lr", type, argv[i]);
				break;
			}
			default:
				mdb_printf("(%s)%lr", type, argv[i]);
			}
		} else {
			mdb_printf("%lr", argv[i]);
		}
	}

	mdb_printf(")\n");
}
