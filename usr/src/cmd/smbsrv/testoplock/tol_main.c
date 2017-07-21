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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Test & debug program for oplocks
 *
 * This implements a simple command reader which accepts
 * commands to simulate oplock events, and prints the
 * state changes and actions that would happen after
 * each event.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_oplock.h>

#define	OPLOCK_CACHE_RWH	(READ_CACHING | HANDLE_CACHING | WRITE_CACHING)
#define	OPLOCK_TYPE	(LEVEL_TWO_OPLOCK | LEVEL_ONE_OPLOCK |\
			BATCH_OPLOCK | OPLOCK_LEVEL_GRANULAR)

#define	MAXFID 10

smb_node_t root_node, test_node;
smb_ofile_t  ofile_array[MAXFID];
smb_request_t test_sr;
uint32_t last_ind_break_level;
char cmdbuf[100];

extern const char *xlate_nt_status(uint32_t);

#define	BIT_DEF(name) { name, #name }

struct bit_defs {
	uint32_t mask;
	const char *name;
} state_bits[] = {
	BIT_DEF(NO_OPLOCK),
	BIT_DEF(BREAK_TO_NO_CACHING),
	BIT_DEF(BREAK_TO_WRITE_CACHING),
	BIT_DEF(BREAK_TO_HANDLE_CACHING),
	BIT_DEF(BREAK_TO_READ_CACHING),
	BIT_DEF(BREAK_TO_TWO_TO_NONE),
	BIT_DEF(BREAK_TO_NONE),
	BIT_DEF(BREAK_TO_TWO),
	BIT_DEF(BATCH_OPLOCK),
	BIT_DEF(LEVEL_ONE_OPLOCK),
	BIT_DEF(LEVEL_TWO_OPLOCK),
	BIT_DEF(MIXED_R_AND_RH),
	BIT_DEF(EXCLUSIVE),
	BIT_DEF(WRITE_CACHING),
	BIT_DEF(HANDLE_CACHING),
	BIT_DEF(READ_CACHING),
	{ 0, NULL }
};

/*
 * Helper to print flags fields
 */
static void
print_bits32(char *label, struct bit_defs *bit, uint32_t state)
{
	printf("%s0x%x (", label, state);
	while (bit->mask != 0) {
		if ((state & bit->mask) != 0)
			printf(" %s", bit->name);
		bit++;
	}
	printf(" )\n");
}

/*
 * Command language:
 *
 */
const char helpstr[] = "Commands:\n"
	"help\t\tList commands\n"
	"show\t\tShow OpLock state etc.\n"
	"open FID\n"
	"close FID\n"
	"req FID [OplockLevel]\n"
	"ack FID [OplockLevel]\n"
	"brk-parent FID\n"
	"brk-open [OverWrite]\n"
	"brk-handle FID\n"
	"brk-read FID\n"
	"brk-write FID\n"
	"brk-setinfo FID [InfoClass]\n"
	"move FID1 FID2\n"
	"waiters FID [count]\n";

/*
 * Command handlers
 */

static void
do_show(void)
{
	smb_node_t *node = &test_node;
	smb_oplock_t *ol = &node->n_oplock;
	uint32_t state = ol->ol_state;
	smb_ofile_t *f;

	print_bits32(" ol_state=", state_bits, state);

	if (ol->excl_open != NULL)
		printf(" Excl=Y (FID=%d)", ol->excl_open->f_fid);
	else
		printf(" Excl=n");
	printf(" cnt_II=%d cnt_R=%d cnt_RH=%d cnt_RHBQ=%d\n",
	    ol->cnt_II, ol->cnt_R, ol->cnt_RH, ol->cnt_RHBQ);

	printf(" ofile_cnt=%d\n", node->n_ofile_list.ll_count);
	FOREACH_NODE_OFILE(node, f) {
		smb_oplock_grant_t *og = &f->f_oplock;
		printf("  fid=%d Lease=%s OgState=0x%x Brk=0x%x",
		    f->f_fid,
		    f->TargetOplockKey,	/* lease */
		    f->f_oplock.og_state,
		    f->f_oplock.og_breaking);
		printf(" Excl=%s onlist: %s %s %s",
		    (ol->excl_open == f) ? "Y" : "N",
		    og->onlist_II ? "II" : "",
		    og->onlist_R  ? "R" : "",
		    og->onlist_RH ? "RH" : "");
		if (og->onlist_RHBQ) {
			printf(" RHBQ(to %s)",
			    og->BreakingToRead ?
			    "read" : "none");
		}
		printf("\n");
	}
}

static void
do_open(int fid, char *arg2)
{
	smb_node_t *node = &test_node;
	smb_ofile_t *ofile = &ofile_array[fid];

	/*
	 * Simulate an open (minimal init)
	 */
	if (ofile->f_refcnt) {
		printf("open fid %d already opened\n");
		return;
	}

	if (arg2 != NULL)
		strlcpy((char *)ofile->TargetOplockKey, arg2,
		    SMB_LEASE_KEY_SZ);

	ofile->f_refcnt++;
	node->n_open_count++;
	smb_llist_insert_tail(&node->n_ofile_list, ofile);
	printf(" open %d OK\n", fid);
}

static void
do_close(int fid)
{
	smb_node_t *node = &test_node;
	smb_ofile_t *ofile = &ofile_array[fid];

	/*
	 * Simulate an close
	 */
	if (ofile->f_refcnt <= 0) {
		printf(" close fid %d already closed\n");
		return;
	}
	smb_oplock_break_CLOSE(ofile->f_node, ofile);

	smb_llist_remove(&node->n_ofile_list, ofile);
	node->n_open_count--;
	ofile->f_refcnt--;

	bzero(ofile->TargetOplockKey, SMB_LEASE_KEY_SZ);

	printf(" close OK\n");
}

static void
do_req(int fid, char *arg2)
{
	smb_ofile_t *ofile = &ofile_array[fid];
	uint32_t oplock = BATCH_OPLOCK;
	uint32_t status;

	if (arg2 != NULL)
		oplock = strtol(arg2, NULL, 16);

	/*
	 * Request an oplock
	 */
	status = smb_oplock_request(&test_sr, ofile, &oplock);
	if (status == 0)
		ofile->f_oplock.og_state = oplock;
	printf(" req oplock fid=%d ret oplock=0x%x status=0x%x (%s)\n",
	    fid, oplock, status, xlate_nt_status(status));
}


static void
do_ack(int fid, char *arg2)
{
	smb_ofile_t *ofile = &ofile_array[fid];
	uint32_t oplock;
	uint32_t status;

	/* Default to level in last smb_oplock_ind_break() */
	oplock = last_ind_break_level;
	if (arg2 != NULL)
		oplock = strtol(arg2, NULL, 16);

	ofile->f_oplock.og_breaking = 0;
	status = smb_oplock_ack_break(&test_sr, ofile, &oplock);
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		printf(" ack: break fid=%d, break-in-progress\n", fid);
		ofile->f_oplock.og_state = oplock;
	}
	if (status == 0)
		ofile->f_oplock.og_state = oplock;

	printf(" ack: break fid=%d, newstate=0x%x, status=0x%x (%s)\n",
	    fid, oplock, status, xlate_nt_status(status));
}

static void
do_brk_parent(int fid)
{
	smb_ofile_t *ofile = &ofile_array[fid];
	uint32_t status;

	status = smb_oplock_break_PARENT(&test_node, ofile);
	printf(" brk-parent %d ret status=0x%x (%s)\n",
	    fid, status, xlate_nt_status(status));
}

static void
do_brk_open(int fid, char *arg2)
{
	smb_ofile_t *ofile = &ofile_array[fid];
	uint32_t status;
	int disp = FILE_OPEN;

	if (arg2 != NULL)
		disp = strtol(arg2, NULL, 16);

	status = smb_oplock_break_OPEN(&test_node, ofile, 7, disp);
	printf(" brk-open %d ret status=0x%x (%s)\n",
	    fid, status, xlate_nt_status(status));
}

static void
do_brk_handle(int fid)
{
	smb_ofile_t *ofile = &ofile_array[fid];
	uint32_t status;

	status = smb_oplock_break_HANDLE(&test_node, ofile);
	printf(" brk-handle %d ret status=0x%x (%s)\n",
	    fid, status, xlate_nt_status(status));

}

static void
do_brk_read(int fid)
{
	smb_ofile_t *ofile = &ofile_array[fid];
	uint32_t status;

	status = smb_oplock_break_READ(ofile->f_node, ofile);
	printf(" brk-read %d ret status=0x%x (%s)\n",
	    fid, status, xlate_nt_status(status));
}

static void
do_brk_write(int fid)
{
	smb_ofile_t *ofile = &ofile_array[fid];
	uint32_t status;

	status = smb_oplock_break_WRITE(ofile->f_node, ofile);
	printf(" brk-write %d ret status=0x%x (%s)\n",
	    fid, status, xlate_nt_status(status));
}

static void
do_brk_setinfo(int fid, char *arg2)
{
	smb_ofile_t *ofile = &ofile_array[fid];
	uint32_t status;
	int infoclass = FileEndOfFileInformation; /* 20 */

	if (arg2 != NULL)
		infoclass = strtol(arg2, NULL, 16);

	status = smb_oplock_break_SETINFO(
	    &test_node, ofile, infoclass);
	printf(" brk-setinfo %d ret status=0x%x (%s)\n",
	    fid, status, xlate_nt_status(status));

}

/*
 * Move oplock to another FD, as specified,
 * or any other available open
 */
static void
do_move(int fid, char *arg2)
{
	smb_ofile_t *ofile = &ofile_array[fid];
	smb_ofile_t *of2;
	int fid2;

	if (arg2 == NULL) {
		fprintf(stderr, "move: FID2 required\n");
		return;
	}
	fid2 = atoi(arg2);
	if (fid2 <= 0 || fid2 >= MAXFID) {
		fprintf(stderr, "move: bad FID2 %d\n", fid2);
		return;
	}
	of2 = &ofile_array[fid2];

	smb_oplock_move(&test_node, ofile, of2);
	printf(" move %d %d\n", fid, fid2);
}

/*
 * Set/clear oplock.waiters, which affects ack-break
 */
static void
do_waiters(int fid, char *arg2)
{
	smb_node_t *node = &test_node;
	smb_oplock_t *ol = &node->n_oplock;
	int old, new = 0;

	if (arg2 != NULL)
		new = atoi(arg2);

	old = ol->waiters;
	ol->waiters = new;

	printf(" waiters %d -> %d\n", old, new);
}

int
main(int argc, char *argv[])
{
	smb_node_t *node = &test_node;
	char *cmd;
	char *arg1;
	char *arg2;
	char *savep;
	char *sep = " \t\n";
	char *prompt = NULL;
	int fid;

	if (isatty(0))
		prompt = "> ";

	smb_llist_constructor(&node->n_ofile_list, sizeof (smb_ofile_t),
	    offsetof(smb_ofile_t, f_node_lnd));

	for (fid = 0; fid < MAXFID; fid++) {
		smb_ofile_t *f = &ofile_array[fid];

		f->f_magic = SMB_OFILE_MAGIC;
		mutex_init(&f->f_mutex, NULL, MUTEX_DEFAULT, NULL);
		f->f_fid = fid;
		f->f_ftype = SMB_FTYPE_DISK;
		f->f_node = &test_node;
	}

	for (;;) {
		if (prompt) {
			fputs(prompt, stdout);
			fflush(stdout);
		}

		cmd = fgets(cmdbuf, sizeof (cmdbuf), stdin);
		if (cmd == NULL)
			break;
		if (cmd[0] == '#')
			continue;

		if (prompt == NULL) {
			/* Put commands in the output too. */
			fputs(cmdbuf, stdout);
		}
		cmd = strtok_r(cmd, sep, &savep);
		if (cmd == NULL)
			continue;

		/*
		 * Commands with no args
		 */
		if (0 == strcmp(cmd, "help")) {
			fputs(helpstr, stdout);
			continue;
		}

		if (0 == strcmp(cmd, "show")) {
			do_show();
			continue;
		}

		/*
		 * Commands with one arg (the FID)
		 */
		arg1 = strtok_r(NULL, sep, &savep);
		if (arg1 == NULL) {
			fprintf(stderr, "%s missing arg1\n", cmd);
			continue;
		}
		fid = atoi(arg1);
		if (fid <= 0 || fid >= MAXFID) {
			fprintf(stderr, "%s bad FID %d\n", cmd, fid);
			continue;
		}

		if (0 == strcmp(cmd, "close")) {
			do_close(fid);
			continue;
		}
		if (0 == strcmp(cmd, "brk-parent")) {
			do_brk_parent(fid);
			continue;
		}
		if (0 == strcmp(cmd, "brk-handle")) {
			do_brk_handle(fid);
			continue;
		}
		if (0 == strcmp(cmd, "brk-read")) {
			do_brk_read(fid);
			continue;
		}
		if (0 == strcmp(cmd, "brk-write")) {
			do_brk_write(fid);
			continue;
		}

		/*
		 * Commands with an (optional) arg2.
		 */
		arg2 = strtok_r(NULL, sep, &savep);

		if (0 == strcmp(cmd, "open")) {
			do_open(fid, arg2);
			continue;
		}
		if (0 == strcmp(cmd, "req")) {
			do_req(fid, arg2);
			continue;
		}
		if (0 == strcmp(cmd, "ack")) {
			do_ack(fid, arg2);
			continue;
		}
		if (0 == strcmp(cmd, "brk-open")) {
			do_brk_open(fid, arg2);
			continue;
		}
		if (0 == strcmp(cmd, "brk-setinfo")) {
			do_brk_setinfo(fid, arg2);
			continue;
		}
		if (0 == strcmp(cmd, "move")) {
			do_move(fid, arg2);
			continue;
		}
		if (0 == strcmp(cmd, "waiters")) {
			do_waiters(fid, arg2);
			continue;
		}

		fprintf(stderr, "%s unknown command. Try help\n", cmd);
	}
	return (0);
}

/*
 * A few functions called by the oplock code
 * Stubbed out, and/or just print a message.
 */

boolean_t
smb_node_is_file(smb_node_t *node)
{
	return (B_TRUE);
}

boolean_t
smb_ofile_is_open(smb_ofile_t *ofile)
{
	return (ofile->f_refcnt != 0);
}

int
smb_lock_range_access(
    smb_request_t	*sr,
    smb_node_t		*node,
    uint64_t		start,
    uint64_t		length,
    boolean_t		will_write)
{
	return (0);
}

/*
 * Test code replacement for: smb_oplock_send_brk()
 */
static void
test_oplock_send_brk(smb_ofile_t *ofile,
    uint32_t NewLevel, boolean_t AckReq)
{
	smb_oplock_grant_t *og = &ofile->f_oplock;

	/* Skip building a message. */

	if ((og->og_state & OPLOCK_LEVEL_GRANULAR) != 0)
		NewLevel |= OPLOCK_LEVEL_GRANULAR;

	/*
	 * In a real server, we would send a break to the client,
	 * and keep track (at the SMB level) whether this oplock
	 * was obtained via a lease or an old-style oplock.
	 */
	if (AckReq) {
		uint32_t BreakTo;

		if ((og->og_state & OPLOCK_LEVEL_GRANULAR) != 0) {

			BreakTo = (NewLevel & CACHE_RWH) << BREAK_SHIFT;
			if (BreakTo == 0)
				BreakTo = BREAK_TO_NO_CACHING;
		} else {
			if ((NewLevel & LEVEL_TWO_OPLOCK) != 0)
				BreakTo = BREAK_TO_TWO;
			else
				BreakTo = BREAK_TO_NONE;
		}
		og->og_breaking = BreakTo;
		last_ind_break_level = NewLevel;
		/* Set og_state in  do_ack */
	} else {
		og->og_state = NewLevel;
		/* Clear og_breaking in do_ack */
	}
}

/*
 * Simplified version of what's in smb_srv_oplock.c
 */
void
smb_oplock_ind_break(smb_ofile_t *ofile, uint32_t NewLevel,
    boolean_t AckReq, uint32_t status)
{
	smb_oplock_grant_t *og = &ofile->f_oplock;

	printf("*smb_oplock_ind_break fid=%d NewLevel=0x%x,"
	    " AckReq=%d, ComplStatus=0x%x (%s)\n",
	    ofile->f_fid, NewLevel, AckReq,
	    status, xlate_nt_status(status));

	/*
	 * Note that the CompletionStatus from the FS level
	 * (smb_cmn_oplock.c) encodes what kind of action we
	 * need to take at the SMB level.
	 */
	switch (status) {

	case NT_STATUS_SUCCESS:
	case NT_STATUS_CANNOT_GRANT_REQUESTED_OPLOCK:
		test_oplock_send_brk(ofile, NewLevel, AckReq);
		break;

	case NT_STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE:
	case NT_STATUS_OPLOCK_HANDLE_CLOSED:
		og->og_state = OPLOCK_LEVEL_NONE;
		break;

	default:
		/* Checked by caller. */
		ASSERT(0);
		break;
	}
}

void
smb_oplock_ind_break_in_ack(smb_request_t *sr, smb_ofile_t *ofile,
    uint32_t NewLevel, boolean_t AckRequired)
{
	ASSERT(sr == &test_sr);
	smb_oplock_ind_break(ofile, NewLevel, AckRequired, STATUS_CANT_GRANT);
}

uint32_t
smb_oplock_wait_break(smb_node_t *node, int timeout)
{
	printf("*smb_oplock_wait_break (state=0x%x)\n",
	    node->n_oplock.ol_state);
	return (0);
}

/*
 * There are a couple DTRACE_PROBE* in smb_cmn_oplock.c but we're
 * not linking with the user-level dtrace support, so just
 * stub these out.
 */
void
__dtrace_fksmb___probe1(char *n, unsigned long a)
{
}
void
__dtrace_fksmb___probe2(char *n, unsigned long a, unsigned long b)
{
}
