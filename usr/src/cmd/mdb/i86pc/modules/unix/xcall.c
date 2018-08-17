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
 * Copyright 2018 Joyent, Inc.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>

typedef struct {
		uint32_t xc_work_cnt;
		struct xc_msg *xc_curmsg;
		struct xc_msg *xc_msgbox;
		xc_data_t xc_data;
} mdb_xcall_machcpu_t;

typedef struct {
	processorid_t cpu_id;
	mdb_xcall_machcpu_t cpu_m;
} mdb_xcall_cpu_t;

typedef struct {
	uint_t xd_flags;
	processorid_t xd_cpu_id;
	size_t xd_msg_index;
	struct xc_msg xd_msgs[NCPU];
} xcall_data_t;

void
xcall_help(void)
{
	mdb_printf(
	    "Print all active cross-calls where the given CPU is the master.\n"
	    "The PEND column is ->xc_work_cnt, the pending message count -\n"
	    "this includes both master and slave messages.  For each\n"
	    "cross call, the message type and the slave CPU ID are shown.\n");
}

static int
cpu_id_to_addr(processorid_t cpun, uintptr_t *addrp)
{
	uintptr_t addr;
	GElf_Sym sym;

	if (mdb_lookup_by_name("cpu", &sym) == -1) {
		mdb_warn("failed to find symbol for 'cpu'");
		return (-1);
	}

	if (cpun * sizeof (uintptr_t) > sym.st_size)
		return (-1);

	addr = (uintptr_t)sym.st_value + cpun * sizeof (uintptr_t);

	if (mdb_vread(&addr, sizeof (addr), addr) == -1) {
		mdb_warn("failed to read cpu[%lu]", cpun);
		return (-1);
	}

	if (addr != NULL) {
		*addrp = addr;
		return (0);
	}

	return (-1);
}

static int
xcall_copy_msg(struct xc_msg *msg, xcall_data_t *data, boolean_t current)
{
	if (data->xd_msg_index >= NCPU) {
		mdb_warn("ran out of msg space: %lu >= %lu\n",
		    data->xd_msg_index, NCPU);
		return (-1);
	}

	bcopy(msg, &data->xd_msgs[data->xd_msg_index], sizeof (*msg));

	/*
	 * As we don't use .xc_next, store 'current' there.
	 */
	data->xd_msgs[data->xd_msg_index].xc_next = (void *)(uintptr_t)current;
	data->xd_msg_index++;
	return (0);
}

static int
xcall_get_msgs(uintptr_t addr, const void *wdata, void *priv)
{
	_NOTE(ARGUNUSED(wdata));
	xcall_data_t *data = priv;
	mdb_xcall_cpu_t xcpu = { 0, };
	struct xc_msg msg;
	uintptr_t msgaddr;

	if (mdb_ctf_vread(&xcpu, "unix`cpu_t", "mdb_xcall_cpu_t",
	    addr, MDB_CTF_VREAD_IGNORE_ABSENT) == -1)
		return (WALK_ERR);

	if (xcpu.cpu_m.xc_curmsg != NULL) {
		msgaddr = (uintptr_t)xcpu.cpu_m.xc_curmsg;

		if (mdb_vread(&msg, sizeof (msg), msgaddr) != sizeof (msg))
			return (WALK_ERR);

		if (msg.xc_master == data->xd_cpu_id) {
			if (data->xd_flags & DCMD_PIPE_OUT)
				mdb_printf("%p\n", msgaddr);
			else if (xcall_copy_msg(&msg, data, B_TRUE) != 0)
				return (WALK_ERR);
		}
	}

	for (msgaddr = (uintptr_t)xcpu.cpu_m.xc_msgbox;
	    msgaddr != NULL; msgaddr = (uintptr_t)msg.xc_next) {
		if (mdb_vread(&msg, sizeof (msg), msgaddr) != sizeof (msg))
			return (WALK_ERR);

		if (msg.xc_master != data->xd_cpu_id)
			continue;

		if (data->xd_flags & DCMD_PIPE_OUT)
			mdb_printf("%p\n", msgaddr);
		else if (xcall_copy_msg(&msg, data, B_FALSE) != 0)
			return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
print_xcall_msg(struct xc_msg *msg)
{
	boolean_t current = (boolean_t)msg->xc_next;
	char indent[] = "        ";
	const char *cmd;

	switch (msg->xc_command) {
		case XC_MSG_ASYNC: cmd = "ASYNC"; break;
		case XC_MSG_CALL: cmd = "CALL"; break;
		case XC_MSG_SYNC: cmd = "SYNC"; break;
		case XC_MSG_FREE:cmd = "FREE"; break;
		case XC_MSG_WAITING: cmd = "WAITING"; break;
		case XC_MSG_RELEASED: cmd = "RELEASED"; break;
		case XC_MSG_DONE: cmd = "DONE"; break;
		default: cmd = "?"; break;
	}

	mdb_printf("%s %s%-*s %-6u\n", indent, current ? "*" : "",
	    9 - current, cmd, msg->xc_slave);
	return (0);
}

/*
 * Show all xcall messages where the master is the given CPU.
 *
 * As non-free messages can be on the slave's ->xc_msgbox or ->xc_curmsg, we
 * need to walk across all of them to find each message where ->xc_master
 * is our CPU ID.
 */
int
xcall_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_xcall_cpu_t xcpu = { 0, };
	xcall_data_t data = { 0, };

	if (mdb_getopts(argc, argv, NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * Yep, this will re-collect all the messages each time.  Shrug.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_pwalk_dcmd("cpu", "xcall", argc, argv, 0) == -1) {
			mdb_warn("can't walk CPUs");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (addr < NCPU && cpu_id_to_addr((processorid_t)addr, &addr) != 0) {
		mdb_warn("invalid CPU ID %lu\n", addr);
		return (DCMD_ERR);
	}

	if (mdb_ctf_vread(&xcpu, "unix`cpu_t", "mdb_xcall_cpu_t",
	    addr, MDB_CTF_VREAD_IGNORE_ABSENT) == -1) {
		mdb_warn("couldn't read cpu 0x%lx", addr);
		return (DCMD_ERR);
	}

	data.xd_cpu_id = xcpu.cpu_id;
	data.xd_flags = flags;

	if (mdb_pwalk("cpu", xcall_get_msgs, &data, NULL) == -1) {
		mdb_warn("can't walk CPUs");
		return (DCMD_ERR);
	}

	if (flags & DCMD_PIPE_OUT)
		return (DCMD_OK);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%3s %4s %s%</u>\n", "CPU", "PEND", "HANDLER");

	if (data.xd_msg_index == 0) {
		mdb_printf("%3d %4d -\n",
		    xcpu.cpu_id, xcpu.cpu_m.xc_work_cnt);
		return (DCMD_OK);
	}

	mdb_printf("%3d %4d %a(%a, %a, %a)\n",
	    xcpu.cpu_id, xcpu.cpu_m.xc_work_cnt,
	    xcpu.cpu_m.xc_data.xc_func, xcpu.cpu_m.xc_data.xc_a1,
	    xcpu.cpu_m.xc_data.xc_a2, xcpu.cpu_m.xc_data.xc_a3);

	if (!(flags & DCMD_PIPE_OUT))
		mdb_printf("         %<u>%-9s %-6s%</u>\n", "COMMAND", "SLAVE");

	for (size_t i = 0; i < data.xd_msg_index; i++) {
		if (print_xcall_msg(&data.xd_msgs[i]) != 0)
			return (DCMD_ERR);
	}

	return (DCMD_OK);
}
