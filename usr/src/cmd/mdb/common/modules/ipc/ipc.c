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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/project.h>
#include <sys/ipc_impl.h>
#include <sys/shm_impl.h>
#include <sys/sem_impl.h>
#include <sys/msg_impl.h>

#include <vm/anon.h>

#define	CMN_HDR_START	"%<u>"
#define	CMN_HDR_END	"%</u>\n"
#define	CMN_INDENT	(4)
#define	CMN_INACTIVE	"%s facility inactive.\n"

/*
 * Bitmap data for page protection flags suitable for use with %b.
 */
const mdb_bitmask_t prot_flag_bits[] = {
	{ "PROT_READ", PROT_READ, PROT_READ },
	{ "PROT_WRITE", PROT_WRITE, PROT_WRITE },
	{ "PROT_EXEC", PROT_EXEC, PROT_EXEC },
	{ "PROT_USER", PROT_USER, PROT_USER },
	{ NULL, 0, 0 }
};

static void
printtime_nice(const char *str, time_t time)
{
	if (time)
		mdb_printf("%s%Y\n", str, time);
	else
		mdb_printf("%sn/a\n", str);
}

/*
 * Print header common to all IPC types.
 */
static void
ipcperm_header()
{
	mdb_printf(CMN_HDR_START "%?s %5s %5s %8s %5s %5s %6s %5s %5s %5s %5s"
	    CMN_HDR_END, "ADDR", "REF", "ID", "KEY", "MODE", "PRJID", "ZONEID",
	    "OWNER", "GROUP", "CREAT", "CGRP");
}

/*
 * Print data common to all IPC types.
 */
static void
ipcperm_print(uintptr_t addr, kipc_perm_t *perm)
{
	kproject_t proj;
	int res;

	res = mdb_vread(&proj, sizeof (kproject_t), (uintptr_t)perm->ipc_proj);

	if (res == -1)
		mdb_warn("failed to read kproject_t at %#p", perm->ipc_proj);

	mdb_printf("%0?p %5d %5d", addr, perm->ipc_ref, perm->ipc_id);
	if (perm->ipc_key)
		mdb_printf(" %8x", perm->ipc_key);
	else
		mdb_printf(" %8s", "private");
	mdb_printf(" %5#o", perm->ipc_mode & 07777);
	if (res == -1)
		mdb_printf(" %5s %5s", "<flt>", "<flt>");
	else
		mdb_printf(" %5d %6d", proj.kpj_id, proj.kpj_zoneid);
	mdb_printf(" %5d %5d %5d %5d\n", perm->ipc_uid, perm->ipc_gid,
	    perm->ipc_cuid, perm->ipc_cgid);

}

/*ARGSUSED*/
static int
ipcperm(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kipc_perm_t perm;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		ipcperm_header();

	if (mdb_vread(&perm, sizeof (kipc_perm_t), addr) == -1) {
		mdb_warn("failed to read kipc_perm_t at %#lx", addr);
		return (DCMD_ERR);
	}

	ipcperm_print(addr, &perm);
	return (DCMD_OK);
}


#define	MSG_SND_SIZE 0x1
static int
msgq_check_for_waiters(list_t *walk_this, int min, int max,
	int copy_wait, uintptr_t addr, int flag)

{
	int found = 0;
	int ii;
	msgq_wakeup_t *walker, next;
	uintptr_t head;

	for (ii = min; ii < max; ii++) {
		head = ((ulong_t)addr) + sizeof (list_t)*ii +
		    sizeof (list_node_t);
		if (head != (uintptr_t)walk_this[ii].list_head.list_next) {
			walker =
			    (msgq_wakeup_t *)walk_this[ii].list_head.list_next;
			while (head != (uintptr_t)walker) {
				if (mdb_vread(&next, sizeof (msgq_wakeup_t),
				    (uintptr_t)walker) == -1) {
					mdb_warn(
					    "Failed to read message queue\n");
					return (found);
				}

				if (flag & MSG_SND_SIZE) {
					mdb_printf("%15lx\t%6d\t%15lx\t%15d\n",
					    next.msgw_thrd, next.msgw_type,
					    walker + (uintptr_t)
					    OFFSETOF(msgq_wakeup_t,
					    msgw_wake_cv), next.msgw_snd_size);
				} else {
					mdb_printf("%15lx\t%6d\t%15lx\t%15s\n",
					    next.msgw_thrd, next.msgw_type,
					    walker + (uintptr_t)
					    OFFSETOF(msgq_wakeup_t,
					    msgw_wake_cv),
					    (copy_wait ? "yes":"no"));
				}
				found++;
				walker =
				    (msgq_wakeup_t *)next.msgw_list.list_next;
			}
		}
	}
	return (found);
}

static void
msq_print(kmsqid_t *msqid, uintptr_t addr)
{
	int	total = 0;

	mdb_printf("&list: %-?p\n", addr + OFFSETOF(kmsqid_t, msg_list));
	mdb_printf("cbytes: 0t%lu    qnum: 0t%lu    qbytes: 0t%lu"
	    "    qmax: 0t%lu\n", msqid->msg_cbytes, msqid->msg_qnum,
	    msqid->msg_qbytes, msqid->msg_qmax);
	mdb_printf("lspid: 0t%d    lrpid: 0t%d\n",
	    (int)msqid->msg_lspid, (int)msqid->msg_lrpid);
	printtime_nice("stime: ", msqid->msg_stime);
	printtime_nice("rtime: ", msqid->msg_rtime);
	printtime_nice("ctime: ", msqid->msg_ctime);
	mdb_printf("snd_cnt: 0t%lld    snd_cv: %hd (%p)\n",
	    msqid->msg_snd_cnt, msqid->msg_snd_cv._opaque,
	    addr + (uintptr_t)OFFSETOF(kmsqid_t, msg_snd_cv));
	mdb_printf("Blocked recievers\n");
	mdb_printf("%15s\t%6s\t%15s\t%15s\n", "Thread Addr",
	    "Type", "cv addr", "copyout-wait?");
	total += msgq_check_for_waiters(&msqid->msg_cpy_block,
	    0, 1, 1, addr + OFFSETOF(kmsqid_t, msg_cpy_block), 0);
	total += msgq_check_for_waiters(msqid->msg_wait_snd_ngt,
	    0, MSG_MAX_QNUM + 1, 0,
	    addr + OFFSETOF(kmsqid_t, msg_wait_snd_ngt), 0);
	mdb_printf("Blocked senders\n");
	total += msgq_check_for_waiters(&msqid->msg_wait_rcv,
	    0, 1, 1, addr + OFFSETOF(kmsqid_t, msg_wait_rcv),
	    MSG_SND_SIZE);
	mdb_printf("%15s\t%6s\t%15s\t%15s\n", "Thread Addr",
	    "Type", "cv addr", "Msg Size");
	total += msgq_check_for_waiters(msqid->msg_wait_snd,
	    0, MSG_MAX_QNUM + 1, 0, addr + OFFSETOF(kmsqid_t,
	    msg_wait_snd), 0);
	mdb_printf("Total number of waiters: %d\n", total);
}


/*ARGSUSED1*/
static void
shm_print(kshmid_t *shmid, uintptr_t addr)
{
	shmatt_t nattch;

	nattch = shmid->shm_perm.ipc_ref - (IPC_FREE(&shmid->shm_perm) ? 0 : 1);

	mdb_printf(CMN_HDR_START "%10s %?s %5s %7s %7s %7s %7s" CMN_HDR_END,
	    "SEGSZ", "AMP", "LKCNT", "LPID", "CPID", "NATTCH", "CNATTCH");
	mdb_printf("%10#lx %?p %5u %7d %7d %7lu %7lu\n",
	    shmid->shm_segsz, shmid->shm_amp, shmid->shm_lkcnt,
	    (int)shmid->shm_lpid, (int)shmid->shm_cpid, nattch,
	    shmid->shm_ismattch);

	printtime_nice("atime: ", shmid->shm_atime);
	printtime_nice("dtime: ", shmid->shm_dtime);
	printtime_nice("ctime: ", shmid->shm_ctime);
	mdb_printf("sptinfo: %-?p    sptseg: %-?p\n",
	    shmid->shm_sptinfo, shmid->shm_sptseg);
	mdb_printf("opts: rmpend: %d prot: <%b>\n",
	    ((shmid->shm_opts & SHM_RM_PENDING) != 0),
	    (shmid->shm_opts & SHM_PROT_MASK), prot_flag_bits);
}


/*ARGSUSED1*/
static void
sem_print(ksemid_t *semid, uintptr_t addr)
{
	mdb_printf("base: %-?p    nsems: 0t%u\n",
	    semid->sem_base, semid->sem_nsems);
	printtime_nice("otime: ", semid->sem_otime);
	printtime_nice("ctime: ", semid->sem_ctime);
	mdb_printf("binary: %s\n", semid->sem_binary ? "yes" : "no");
}

typedef struct ipc_ops_vec {
	char	*iv_wcmd;	/* walker name		*/
	char	*iv_ocmd;	/* output dcmd		*/
	char	*iv_service;	/* service pointer	*/
	void	(*iv_print)(void *, uintptr_t); /* output callback */
	size_t	iv_idsize;
} ipc_ops_vec_t;

ipc_ops_vec_t msq_ops_vec = {
	"msq",
	"kmsqid",
	"msq_svc",
	(void(*)(void *, uintptr_t))msq_print,
	sizeof (kmsqid_t)
};

ipc_ops_vec_t shm_ops_vec = {
	"shm",
	"kshmid",
	"shm_svc",
	(void(*)(void *, uintptr_t))shm_print,
	sizeof (kshmid_t)
};

ipc_ops_vec_t sem_ops_vec = {
	"sem",
	"ksemid",
	"sem_svc",
	(void(*)(void *, uintptr_t))sem_print,
	sizeof (ksemid_t)
};


/*
 * Generic IPC data structure display code
 */
static int
ds_print(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    ipc_ops_vec_t *iv)
{
	void *iddata;

	if (!(flags & DCMD_ADDRSPEC)) {
		uint_t oflags = 0;

		if (mdb_getopts(argc, argv, 'l', MDB_OPT_SETBITS, 1, &oflags,
		    NULL) != argc)
			return (DCMD_USAGE);

		if (mdb_walk_dcmd(iv->iv_wcmd, oflags ? iv->iv_ocmd : "ipcperm",
		    argc, argv) == -1) {
			mdb_warn("can't walk '%s'", iv->iv_wcmd);
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	iddata = mdb_alloc(iv->iv_idsize, UM_SLEEP | UM_GC);
	if (mdb_vread(iddata, iv->iv_idsize, addr) == -1) {
		mdb_warn("failed to read %s at %#lx", iv->iv_ocmd, addr);
		return (DCMD_ERR);
	}

	if (!DCMD_HDRSPEC(flags) && iv->iv_print)
		mdb_printf("\n");

	if (DCMD_HDRSPEC(flags) || iv->iv_print)
		ipcperm_header();

	ipcperm_print(addr, (struct kipc_perm *)iddata);
	if (iv->iv_print) {
		mdb_inc_indent(CMN_INDENT);
		iv->iv_print(iddata, addr);
		mdb_dec_indent(CMN_INDENT);
	}

	return (DCMD_OK);
}


/*
 * Stubs to call ds_print with the appropriate ops vector
 */
static int
cmd_kshmid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ds_print(addr, flags, argc, argv, &shm_ops_vec));
}


static int
cmd_kmsqid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ds_print(addr, flags, argc, argv, &msq_ops_vec));
}

static int
cmd_ksemid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ds_print(addr, flags, argc, argv, &sem_ops_vec));
}

/*
 * Generic IPC walker
 */

static int
ds_walk_init(mdb_walk_state_t *wsp)
{
	ipc_ops_vec_t	*iv = wsp->walk_arg;

	if (wsp->walk_arg != NULL && wsp->walk_addr != 0)
		mdb_printf("ignoring provided address\n");

	if (wsp->walk_arg)
		if (mdb_readvar(&wsp->walk_addr, iv->iv_service) == -1) {
			mdb_printf("failed to read '%s'; module not present\n",
			    iv->iv_service);
			return (WALK_DONE);
		}
	else
		wsp->walk_addr = wsp->walk_addr +
		    OFFSETOF(ipc_service_t, ipcs_usedids);

	if (mdb_layered_walk("list", wsp) == -1)
		return (WALK_ERR);

	return (WALK_NEXT);
}


static int
ds_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * Generic IPC ID/key to pointer code
 */

static int
ipcid_impl(uintptr_t svcptr, uintptr_t id, uintptr_t *addr)
{
	ipc_service_t service;
	kipc_perm_t perm;
	ipc_slot_t slot;
	uintptr_t slotptr;
	uint_t index;

	if (id > INT_MAX) {
		mdb_warn("id out of range\n");
		return (DCMD_ERR);
	}

	if (mdb_vread(&service, sizeof (ipc_service_t), svcptr) == -1) {
		mdb_warn("failed to read ipc_service_t at %#lx", svcptr);
		return (DCMD_ERR);
	}

	index = (uint_t)id & (service.ipcs_tabsz - 1);
	slotptr = (uintptr_t)(service.ipcs_table + index);

	if (mdb_vread(&slot, sizeof (ipc_slot_t), slotptr) == -1) {
		mdb_warn("failed to read ipc_slot_t at %#lx", slotptr);
		return (DCMD_ERR);
	}

	if (slot.ipct_data == NULL)
		return (DCMD_ERR);

	if (mdb_vread(&perm, sizeof (kipc_perm_t),
	    (uintptr_t)slot.ipct_data) == -1) {
		mdb_warn("failed to read kipc_perm_t at %#p",
		    slot.ipct_data);
		return (DCMD_ERR);
	}

	if (perm.ipc_id != (uint_t)id)
		return (DCMD_ERR);

	*addr = (uintptr_t)slot.ipct_data;

	return (DCMD_OK);
}


typedef struct findkey_data {
	key_t fk_key;
	uintptr_t fk_addr;
	boolean_t fk_found;
} findkey_data_t;

static int
findkey(uintptr_t addr, kipc_perm_t *perm, findkey_data_t *arg)
{
	if (perm->ipc_key == arg->fk_key) {
		arg->fk_found = B_TRUE;
		arg->fk_addr = addr;
		return (WALK_DONE);
	}
	return (WALK_NEXT);
}

static int
ipckey_impl(uintptr_t svcptr, uintptr_t key, uintptr_t *addr)
{
	ipc_service_t	service;
	findkey_data_t	fkdata;

	if ((key == IPC_PRIVATE) || (key > INT_MAX)) {
		mdb_warn("key out of range\n");
		return (DCMD_ERR);
	}

	if (mdb_vread(&service, sizeof (ipc_service_t), svcptr) == -1) {
		mdb_warn("failed to read ipc_service_t at %#lx", svcptr);
		return (DCMD_ERR);
	}

	fkdata.fk_key = (key_t)key;
	fkdata.fk_found = B_FALSE;
	if ((mdb_pwalk("avl", (mdb_walk_cb_t)findkey, &fkdata,
	    svcptr + OFFSETOF(ipc_service_t, ipcs_keys)) == -1) ||
	    !fkdata.fk_found)
		return (DCMD_ERR);

	*addr = fkdata.fk_addr;

	return (DCMD_OK);
}

static int
ipckeyid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    int(*fp)(uintptr_t, uintptr_t, uintptr_t *))
{
	uintmax_t val;
	uintptr_t raddr;
	int result;

	if (!(flags & DCMD_ADDRSPEC) || (argc != 1))
		return (DCMD_USAGE);

	if (argv[0].a_type == MDB_TYPE_IMMEDIATE)
		val = argv[0].a_un.a_val;
	else if (argv[0].a_type == MDB_TYPE_STRING)
		val = mdb_strtoull(argv[0].a_un.a_str);
	else
		return (DCMD_USAGE);

	result = fp(addr, val, &raddr);

	if (result == DCMD_OK)
		mdb_printf("%lx", raddr);

	return (result);
}

static int
ipckey(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ipckeyid(addr, flags, argc, argv, ipckey_impl));
}

static int
ipcid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ipckeyid(addr, flags, argc, argv, ipcid_impl));
}

static int
ds_ptr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    ipc_ops_vec_t *iv)
{
	uint_t		kflag = FALSE;
	uintptr_t	svcptr, raddr;
	int		result;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'k', MDB_OPT_SETBITS, TRUE, &kflag, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&svcptr, iv->iv_service) == -1) {
		mdb_warn("failed to read '%s'; module not present\n",
		    iv->iv_service);
		return (DCMD_ERR);
	}

	result = kflag ? ipckey_impl(svcptr, addr, &raddr) :
	    ipcid_impl(svcptr, addr, &raddr);

	if (result == DCMD_OK)
		mdb_printf("%lx", raddr);

	return (result);
}

/*
 * Stubs to call ds_ptr with the appropriate ops vector
 */
static int
id2shm(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ds_ptr(addr, flags, argc, argv, &shm_ops_vec));
}

static int
id2msq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ds_ptr(addr, flags, argc, argv, &msq_ops_vec));
}

static int
id2sem(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ds_ptr(addr, flags, argc, argv, &sem_ops_vec));
}


/*
 * The message queue contents walker
 */

static int
msg_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_addr += OFFSETOF(kmsqid_t, msg_list);
	if (mdb_layered_walk("list", wsp) == -1)
		return (WALK_ERR);

	return (WALK_NEXT);
}

static int
msg_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * The "::ipcs" command itself.  Just walks each IPC type in turn.
 */

/*ARGSUSED*/
static int
ipcs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t	oflags = 0;

	if ((flags & DCMD_ADDRSPEC) || mdb_getopts(argc, argv, 'l',
	    MDB_OPT_SETBITS, 1, &oflags, NULL) != argc)
		return (DCMD_USAGE);

	mdb_printf("Message queues:\n");
	if (mdb_walk_dcmd("msq", oflags ? "kmsqid" : "ipcperm", argc, argv) ==
	    -1) {
		mdb_warn("can't walk 'msq'");
		return (DCMD_ERR);
	}

	mdb_printf("\nShared memory:\n");
	if (mdb_walk_dcmd("shm", oflags ? "kshmid" : "ipcperm", argc, argv) ==
	    -1) {
		mdb_warn("can't walk 'shm'");
		return (DCMD_ERR);
	}

	mdb_printf("\nSemaphores:\n");
	if (mdb_walk_dcmd("sem", oflags ? "ksemid" : "ipcperm", argc, argv) ==
	    -1) {
		mdb_warn("can't walk 'sem'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
msgprint(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct msg message;
	uint_t	lflag = FALSE;
	long	type = 0;
	char	*tflag = NULL;

	if (!(flags & DCMD_ADDRSPEC) || (mdb_getopts(argc, argv,
	    'l', MDB_OPT_SETBITS, TRUE, &lflag,
	    't', MDB_OPT_STR, &tflag, NULL) != argc))
		return (DCMD_USAGE);

	/*
	 * Handle negative values.
	 */
	if (tflag != NULL) {
		if (*tflag == '-') {
			tflag++;
			type = -1;
		} else {
			type = 1;
		}
		type *= mdb_strtoull(tflag);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %?s %8s %8s %8s%</u>\n",
		    "ADDR", "TEXT", "SIZE", "TYPE", "REF");

	if (mdb_vread(&message, sizeof (struct msg), addr) == -1) {
		mdb_warn("failed to read msg at %#lx", addr);
		return (DCMD_ERR);
	}

	/*
	 * If we are meeting our type contraints, display the message.
	 * If -l was specified, we will also display the message
	 * contents.
	 */
	if ((type == 0) ||
	    (type > 0 && message.msg_type == type) ||
	    (type < 0 && message.msg_type <= -type)) {

		if (lflag && !DCMD_HDRSPEC(flags))
			mdb_printf("\n");

		mdb_printf("%0?lx %?p %8ld %8ld %8ld\n", addr, message.msg_addr,
		    message.msg_size, message.msg_type, message.msg_copycnt);

		if (lflag) {
			mdb_printf("\n");
			mdb_inc_indent(CMN_INDENT);
			if (mdb_dumpptr(
			    (uintptr_t)message.msg_addr, message.msg_size,
			    MDB_DUMP_RELATIVE | MDB_DUMP_TRIM |
			    MDB_DUMP_ASCII | MDB_DUMP_HEADER |
			    MDB_DUMP_GROUP(4),
			    (mdb_dumpptr_cb_t)mdb_vread, NULL)) {
				mdb_dec_indent(CMN_INDENT);
				return (DCMD_ERR);
			}
			mdb_dec_indent(CMN_INDENT);
		}
	}

	return (DCMD_OK);
}

/*
 * MDB module linkage
 */
static const mdb_dcmd_t dcmds[] = {
	/* Generic routines */
	{ "ipcperm", ":", "display an IPC perm structure", ipcperm },
	{ "ipcid", ":id", "perform an IPC id lookup", ipcid },
	{ "ipckey", ":key", "perform an IPC key lookup", ipckey },

	/* Specific routines */
	{ "kshmid", "?[-l]", "display a struct kshmid", cmd_kshmid },
	{ "kmsqid", "?[-l]", "display a struct kmsqid", cmd_kmsqid },
	{ "ksemid", "?[-l]", "display a struct ksemid", cmd_ksemid },
	{ "msg", ":[-l] [-t type]", "display contents of a message", msgprint },

	/* Convenience routines */
	{ "id2shm", ":[-k]", "convert shared memory ID to pointer", id2shm },
	{ "id2msq", ":[-k]", "convert message queue ID to pointer", id2msq },
	{ "id2sem", ":[-k]", "convert semaphore ID to pointer", id2sem },

	{ "ipcs", "[-l]", "display System V IPC information", ipcs },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "ipcsvc", "walk a System V IPC service",
		ds_walk_init, ds_walk_step },
	{ "shm", "walk the active shmid_ds structures",
		ds_walk_init, ds_walk_step, NULL, &shm_ops_vec },
	{ "msq", "walk the active msqid_ds structures",
		ds_walk_init, ds_walk_step, NULL, &msq_ops_vec },
	{ "sem", "walk the active semid_ds structures",
		ds_walk_init, ds_walk_step, NULL, &sem_ops_vec },
	{ "msgqueue", "walk messages on a message queue",
		msg_walk_init, msg_walk_step },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
