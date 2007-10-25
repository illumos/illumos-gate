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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mdb_modapi.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/smbvar.h>

#define	SMB_DCMD_INDENT		4

static void smb_lookup_svc_state_str(smb_svcstate_t state, char *dst_str,
    int slen);

/*
 * Initialize the smb_session_t walker by reading the value of smb_info
 * object in the kernel's symbol table. Only global walk supported.
 */
static int
smb_session_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym	sym;
	uintptr_t	svcsm_addr;

	if (wsp->walk_addr == NULL) {
		if (mdb_lookup_by_name("smb_info", &sym) == -1) {
			mdb_warn("failed to find 'smb_info'");
			return (WALK_ERR);
		}
		svcsm_addr = (uintptr_t)(sym.st_value +
		    offsetof(struct smb_info, si_svc_sm_ctx));
		wsp->walk_addr = svcsm_addr +
		    offsetof(smb_svc_sm_ctx_t, ssc_active_sessions);
	} else {
		mdb_printf("smb_session walk only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("failed to walk 'list'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
smb_session_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * Initialize the smb_node_t walker by reading the value of smb_info
 * object in the kernel's symbol table. Only global walk supported.
 */
static int
smb_node_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym	sym;
	int		i;
	uintptr_t	node_hash_table_addr;

	if (wsp->walk_addr == NULL) {
		if (mdb_lookup_by_name("smb_info", &sym) == -1) {
			mdb_warn("failed to find 'smb_info'");
			return (WALK_ERR);
		}
		node_hash_table_addr = (uintptr_t)(sym.st_value +
		    offsetof(struct smb_info, node_hash_table));
	} else {
		mdb_printf("smb_node walk only supports global walks\n");
		return (WALK_ERR);
	}

	for (i = 0; i < SMBND_HASH_MASK + 1; i++) {
		wsp->walk_addr = node_hash_table_addr +
		    (i * sizeof (smb_llist_t)) +
		    offsetof(smb_llist_t, ll_list);
		if (mdb_layered_walk("list", wsp) == -1) {
			mdb_warn("failed to walk 'list'");
			return (WALK_ERR);
		}
	}

	return (WALK_NEXT);
}

static int
smb_node_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * ::smb_info
 *
 * smb_info dcmd - Print out the smb_info structure.
 */
/*ARGSUSED*/
static int
smb_information(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int print_config = FALSE;
	struct smb_info	smb_info;
	GElf_Sym smb_info_sym;
	char state_name[40];
	char last_state_name[40];

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_SETBITS, TRUE, &print_config,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (mdb_lookup_by_obj(MDB_OBJ_EVERY, "smb_info", &smb_info_sym)) {
		mdb_warn("failed to find symbol smb_info");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&smb_info, "smb_info") == -1) {
		mdb_warn("failed to read smb_info structure");
		return (DCMD_ERR);
	}

	/* Lookup state string */
	smb_lookup_svc_state_str(smb_info.si_svc_sm_ctx.ssc_state,
	    state_name, 40);
	smb_lookup_svc_state_str(smb_info.si_svc_sm_ctx.ssc_last_state,
	    last_state_name, 40);

	mdb_printf("SMB information:\n\n");
	mdb_printf("        SMB state :\t%s (%d)\n", state_name,
	    smb_info.si_svc_sm_ctx.ssc_state);
	mdb_printf("   SMB last state :\t%s (%d)\n", last_state_name,
	    smb_info.si_svc_sm_ctx.ssc_last_state);
	mdb_printf("  Active Sessions :\t%d\n",
	    smb_info.si_svc_sm_ctx.ssc_active_session_count);
	mdb_printf("Deferred Sessions :\t%d\n",
	    smb_info.si_svc_sm_ctx.ssc_deferred_session_count);
	mdb_printf("   SMB Open Files :\t%d\n", smb_info.open_files);
	mdb_printf("   SMB Open Trees :\t%d\n", smb_info.open_trees);
	mdb_printf("   SMB Open Users :\t%d\n\n", smb_info.open_users);

	if (print_config) {
		mdb_printf("Configuration:\n\n");
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		mdb_printf("Max Buffer Size %d\n",
		    smb_info.si.skc_maxbufsize);
		mdb_printf("Max Worker Thread %d\n",
		    smb_info.si.skc_maxworkers);
		mdb_printf("Max Connections %d\n",
		    smb_info.si.skc_maxconnections);
		mdb_printf("Keep Alive Timeout %d\n",
		    smb_info.si.skc_keepalive);
		mdb_printf("%sRestrict Anonymous Access\n",
		    (smb_info.si.skc_restrict_anon) ? "" : "Do Not ");
		mdb_printf("Signing %s\n",
		    (smb_info.si.skc_signing_enable) ? "Enabled" : "Disabled");
		mdb_printf("Signing %sRequired\n",
		    (smb_info.si.skc_signing_required) ? "" : "Not ");
		mdb_printf("Signing Check %s\n",
		    (smb_info.si.skc_signing_check) ? "Enabled" : "Disabled");
		mdb_printf("Oplocks %s\n",
		    (smb_info.si.skc_oplock_enable) ? "Enabled" : "Disabled");
		mdb_printf("Oplock Timeout %d millisec\n",
		    smb_info.si.skc_oplock_timeout);
		mdb_printf("Flush %sRequired\n",
		    (smb_info.si.skc_flush_required) ? "" : "Not ");
		mdb_printf("Sync %s\n",
		    (smb_info.si.skc_sync_enable) ? "Enabled" : "Disabled");
		mdb_printf("Dir Symlink %s\n",
		    (smb_info.si.skc_dirsymlink_enable) ?
		    "Enabled" : "Disabled");
		mdb_printf("%sAnnounce Quota\n",
		    (smb_info.si.skc_announce_quota) ? "" : "Do Not ");
		mdb_printf("Security Mode %d\n", smb_info.si.skc_secmode);
		mdb_printf("LM Level %d\n", smb_info.si.skc_lmlevel);
		mdb_printf("Domain %s\n", smb_info.si.skc_resource_domain);
		mdb_printf("Hostname %s\n", smb_info.si.skc_hostname);
		mdb_printf("Comment %s\n", smb_info.si.skc_system_comment);
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
		mdb_printf("\n");
	}

	return (DCMD_OK);
}

static void
smb_lookup_svc_state_str(smb_svcstate_t state, char *dst_str, int slen)
{
	GElf_Sym	smb_statename_table_sym;
	uintptr_t	statename_addr_addr, statename_addr;

	if (mdb_lookup_by_name("smb_svcstate_state_name",
	    &smb_statename_table_sym)) {
		(void) mdb_snprintf(dst_str, slen, "UNKNOWN");
		return;
	}

	/* Lookup state string */
	statename_addr_addr = smb_statename_table_sym.st_value +
	    (state * sizeof (uintptr_t));
	if (mdb_vread(&statename_addr, sizeof (uintptr_t),
	    statename_addr_addr) == -1) {
		(void) mdb_snprintf(dst_str, slen, "UNKNOWN");
		return;
	} else {
		if (mdb_readstr(dst_str, slen, statename_addr) == -1) {
			(void) mdb_snprintf(dst_str, slen, "UNKNOWN");
			return;
		}
	}
}

static void
smb_node_help(void)
{
	mdb_printf(
	    "Display the contents of smb_node_t, with optional filtering.\n\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf(
	    "-v\tDisplay verbose smb_node information\n"
	    "-p\tDisplay the full path of the vnode associated\n"
	    "-s\tDisplay the stack of the last 16 calls that modified the "
	    "reference\n\tcount\n");
}

/*
 * ::smb_node
 *
 * smb_node dcmd - Print out smb_node structure.
 */
/*ARGSUSED*/
static int
smb_node(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_node_t	node;
	int		verbose = FALSE;
	int		print_full_path = FALSE;
	int		stack_trace = FALSE;
	vnode_t		vnode;
	char		od_name[MAXNAMELEN];
	char		path_name[1024];
	uintptr_t	list_addr;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'p', MDB_OPT_SETBITS, TRUE, &print_full_path,
	    's', MDB_OPT_SETBITS, TRUE, &stack_trace,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If no smb_node address was specified on the command line, we can
	 * print out all smb nodes by invoking the smb_node walker, using
	 * this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("smb_node", "smb_node",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'smb_node'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (verbose)
			mdb_printf("SMB node information:\n\n");
		else
			mdb_printf("%<u>%?s %?s %18s %6s %5s %4s%</u>\n",
			    "SMB Nodes:", "VP", "NODE NAME",
			    "OFILES", "LOCKS", "REF");
	}

	/*
	 * For each smb_node, we just need to read the smb_node_t struct,
	 * read and then print out the following fields.
	 */
	if (mdb_vread(&node, sizeof (node), addr) == sizeof (node)) {
		(void) mdb_snprintf(od_name, MAXNAMELEN, "%s", node.od_name);
		if (print_full_path) {
			if (mdb_vread(&vnode, sizeof (vnode_t),
			    (uintptr_t)node.vp) ==
			    sizeof (vnode_t)) {
				if (mdb_readstr(path_name, 1024,
				    (uintptr_t)vnode.v_path) != 0) {
					(void) mdb_snprintf(od_name,
					    MAXNAMELEN, "N/A");
				}
			}
		}
		if (verbose) {
			mdb_printf("VP              :\t%p\n",
			    node.vp);
			mdb_printf("Name            :\t%s\n",
			    od_name);
			if (print_full_path) {
				mdb_printf("V-node Path     :\t%s\n",
				    path_name);
			}
			mdb_printf("Ofiles          :\t%u\n",
			    node.n_ofile_list.ll_count);
			mdb_printf("Range Locks     :\t%u\n",
			    node.n_lock_list.ll_count);
			if (node.n_lock_list.ll_count != 0) {
				(void) mdb_inc_indent(SMB_DCMD_INDENT);
				list_addr = addr +
				    offsetof(smb_node_t, n_lock_list) +
				    offsetof(smb_llist_t, ll_list);
				if (mdb_pwalk_dcmd("list", "smb_lock",
				    0, NULL, list_addr)) {
					mdb_warn("failed to walk node's active"
					    " locks");
				}
				(void) mdb_dec_indent(SMB_DCMD_INDENT);
			}
			mdb_printf("Reference Count :\t%u\n",
			    node.n_refcnt);
			mdb_printf("\n");
		} else {
			mdb_printf("%?p %?p %18s %5d %5d %4d\n",
			    addr, node.vp, od_name, node.n_ofile_list.ll_count,
			    node.n_lock_list.ll_count, node.n_refcnt);
			if (print_full_path) {
				if (mdb_vread(&vnode, sizeof (vnode_t),
				    (uintptr_t)node.vp) ==
				    sizeof (vnode_t)) {
					if (mdb_readstr(path_name, 1024,
					    (uintptr_t)vnode.v_path)) {
						mdb_printf("\t%s\n",
						    path_name);
					}
				}
			}
		}
		if (stack_trace && node.n_audit_buf) {
			int ctr;
			smb_audit_buf_node_t *anb;

			anb = mdb_alloc(sizeof (smb_audit_buf_node_t),
			    UM_SLEEP);

			if (mdb_vread(anb, sizeof (*anb),
			    (uintptr_t)node.n_audit_buf) != sizeof (*anb)) {
				mdb_free(anb, sizeof (smb_audit_buf_node_t));
				mdb_warn("failed to read audit buffer");
				return (DCMD_ERR);
			}
			ctr = anb->anb_max_index + 1;
			anb->anb_index--;
			anb->anb_index &= anb->anb_max_index;

			while (ctr) {
				smb_audit_record_node_t	*anr;

				anr = anb->anb_records + anb->anb_index;

				if (anr->anr_depth) {
					char c[MDB_SYM_NAMLEN];
					GElf_Sym sym;
					int i;

					mdb_printf("\nRefCnt: %u\t",
					    anr->anr_refcnt);

					for (i = 0;
					    i < anr->anr_depth;
					    i++) {
						if (mdb_lookup_by_addr(
						    anr->anr_stack[i],
						    MDB_SYM_FUZZY,
						    c, sizeof (c),
						    &sym) == -1) {
							continue;
						}
						mdb_printf("%s+0x%1x",
						    c,
						    anr->anr_stack[i] -
						    (uintptr_t)sym.st_value);
						++i;
						break;
					}

					while (i < anr->anr_depth) {
						if (mdb_lookup_by_addr(
						    anr->anr_stack[i],
						    MDB_SYM_FUZZY,
						    c, sizeof (c),
						    &sym) == -1) {
							++i;
							continue;
						}
						mdb_printf("\n\t\t%s+0x%1x",
						    c,
						    anr->anr_stack[i] -
						    (uintptr_t)sym.st_value);
						++i;
					}
					mdb_printf("\n");
				}
				anb->anb_index--;
				anb->anb_index &= anb->anb_max_index;
				ctr--;
			}
			mdb_free(anb, sizeof (smb_audit_buf_node_t));
		}
	} else {
		mdb_warn("failed to read struct smb_node at %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static void
smb_session_help(void)
{
	mdb_printf(
	    "Display the contents of smb_session_t, with optional"
	    " filtering.\n\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf(
	    "-v\tDisplay verbose smb_session information\n"
	    "-r\tDisplay the list of smb requests attached\n"
	    "-u\tDisplay the list of users attached\n");
}

/*
 * ::smb_session
 *
 * smb_session dcmd - Print out the smb_session structure.
 */
/*ARGSUSED*/
static int
smb_session(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_session_t	session;
	int		print_requests = FALSE;
	int		print_users = FALSE;
	int		verbose = FALSE;
	uintptr_t	list_addr;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'r', MDB_OPT_SETBITS, TRUE, &print_requests,
	    'u', MDB_OPT_SETBITS, TRUE, &print_users,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If no smb_session address was specified on the command line, we can
	 * print out all smb sessions by invoking the smb_session walker, using
	 * this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("smb_session", "smb_session",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'smb_session'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (verbose)
			mdb_printf("SMB session information:\n\n");
		else
			mdb_printf("%<u>%-?s %16s %16s %5s %10s%</u>\n",
			    "Sessions:", "CLIENT_IP_ADDR", "LOCAL_IP_ADDR",
			    "KID", "STATE");
	}

	/*
	 * For each smb_session, we just need to read the smb_session_t struct,
	 * read and then print out the following fields.
	 */
	if (mdb_vread(&session, sizeof (session), addr) == sizeof (session)) {
		if (verbose) {
			mdb_printf("IP address      :\t%I\n",
			    session.ipaddr);
			mdb_printf("Local IP Address:\t%I\n",
			    session.local_ipaddr);
			mdb_printf("Session KID     :\t%u\n",
			    session.s_kid);
			mdb_printf("Workstation Name:\t%s\n",
			    session.workstation);
			mdb_printf("Session state   :\t%u\n",
			    session.s_state);
			mdb_printf("users           :\t%u\n",
			    session.s_user_list.ll_count);
			mdb_printf("trees           :\t%u\n",
			    session.s_tree_cnt);
			mdb_printf("files           :\t%u\n",
			    session.s_file_cnt);
			mdb_printf("shares          :\t%u\n",
			    session.s_dir_cnt);
			mdb_printf("xa count        :\t%u\n\n",
			    session.s_xa_list.ll_count);
			mdb_printf("\n");
		} else {
			mdb_printf("%?p %16I %16I %5u %10u\n", addr,
			    session.ipaddr, session.local_ipaddr,
			    session.s_kid, session.s_state);
		}
	} else {
		mdb_warn("failed to read struct smb_session at %p", &session);
		return (DCMD_ERR);
	}

	if (print_requests) {
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		list_addr = addr + offsetof(smb_session_t, s_req_list) +
		    offsetof(smb_slist_t, sl_list);
		if (mdb_pwalk_dcmd("list", "smb_request", 0, NULL, list_addr)) {
			mdb_warn("failed to walk request list\n");
			(void) mdb_dec_indent(SMB_DCMD_INDENT);
			return (DCMD_ERR);
		}
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
	}

	if (print_users) {
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		list_addr = addr + offsetof(smb_session_t, s_user_list) +
		    offsetof(smb_llist_t, ll_list);
		if (mdb_pwalk_dcmd("list", "smb_user", 0, NULL, list_addr)) {
			mdb_warn("failed to walk user list\n");
			(void) mdb_dec_indent(SMB_DCMD_INDENT);
			return (DCMD_ERR);
		}
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
	}

	return (DCMD_OK);
}

static int
smb_request(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_request_t	request;
	int		verbose = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * An smb_requets_t address must be specified.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (verbose)
			mdb_printf("SMB request information:\n\n");
		else
			mdb_printf("%<u>%-?s %4s %6s %4s %4s %4s %4s%</u>\n",
			    "Requests: ", "COM", "STATE",
			    "TID", "PID", "UID", "MID");
	}

	if (mdb_vread(&request, sizeof (request), addr) == sizeof (request)) {
		if (verbose) {
			mdb_printf("First SMB COM    :\t%I\n",
			    request.first_smb_com);
			mdb_printf("State            :\t%I\n",
			    request.sr_state);
			mdb_printf("Tree ID          :\t%u\n",
			    request.smb_tid);
			mdb_printf("Process ID       :\t%u\n",
			    request.smb_pid);
			mdb_printf("User ID          :\t%u\n",
			    request.smb_uid);
			mdb_printf("Multiplex ID     :\t%u\n",
			    request.smb_mid);
			mdb_printf("\n");
		} else {
			mdb_printf("%?p %04x %6x %04x %04x %04x"
			    " %04x\n", addr,
			    request.first_smb_com, request.sr_state,
			    request.smb_tid, request.smb_pid,
			    request.smb_uid, request.smb_mid);
		}
	} else {
		mdb_warn("failed to read struct smb_request at %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
smb_lock(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_lock_t	lock;
	int		verbose = FALSE;
	uintptr_t	list_addr;
	char		*lock_type;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * An smb_lock_t address must be specified.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (verbose)
			mdb_printf("SMB lock information:\n\n");
		else
			mdb_printf("%<u>%-?s %4s %16s %8s %9s%</u>\n",
			    "Locks: ", "TYPE", "START", "LENGTH",
			    "CONFLICTS");
	}

	if (mdb_vread(&lock, sizeof (lock), addr) == sizeof (lock)) {
		switch (lock.l_type) {
		case SMB_LOCK_TYPE_READWRITE:
			lock_type = "RW";
			break;
		case SMB_LOCK_TYPE_READONLY:
			lock_type = "RO";
			break;
		default:
			lock_type = "N/A";
			break;
		}
		if (verbose) {
			mdb_printf("Type             :\t%s (%u)\n",
			    lock_type, lock.l_type);
			mdb_printf("Start            :\t%llx\n",
			    lock.l_start);
			mdb_printf("Length           :\t%lx\n",
			    lock.l_length);
			mdb_printf("Session          :\t%p\n",
			    lock.l_session);
			mdb_printf("File             :\t%p\n",
			    lock.l_file);
			mdb_printf("User ID          :\t%u\n",
			    lock.l_uid);
			mdb_printf("Process ID       :\t%u\n",
			    lock.l_pid);
			mdb_printf("Conflicts        :\t%u\n",
			    lock.l_conflict_list.sl_count);
			if (lock.l_conflict_list.sl_count != 0) {
				(void) mdb_inc_indent(SMB_DCMD_INDENT);
				list_addr = addr +
				    offsetof(smb_lock_t, l_conflict_list) +
				    offsetof(smb_slist_t, sl_list);
				if (mdb_pwalk_dcmd("list", "smb_lock",
				    0, NULL, list_addr)) {
					mdb_warn("failed to walk conflict "
					    "locks ");
				}
				(void) mdb_dec_indent(SMB_DCMD_INDENT);
			}
			mdb_printf("Blocked by       :\t%p\n",
			    lock.l_blocked_by);
			mdb_printf("Flags            :\t0x%x\n",
			    lock.l_flags);
			mdb_printf("\n");
		} else {
			mdb_printf("%?p %4s %16llx %08lx %9x", addr,
			    lock_type, lock.l_start, lock.l_length,
			    lock.l_conflict_list.sl_count);
		}
	} else {
		mdb_warn("failed to read struct smb_request at %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static void
smb_user_help(void)
{
	mdb_printf(
	    "Display the contents of smb_user_t, with optional filtering.\n\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf(
	    "-v\tDisplay verbose smb_user information\n"
	    "-q\tDon't Display the contents of the smb_user. This option "
	    "should be\n\tused in conjunction with -d or -f\n"
	    "-d\tDisplay the list of smb_odirs attached\n"
	    "-f\tDisplay the list of smb_ofiles attached\n"
	    "-t\tDisplay the list of smb_trees attached\n");
}

static int
smb_user(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_user_t	user;
	int		print_odir = FALSE;
	int		print_ofile = FALSE;
	int		print_tree = FALSE;
	int		verbose = FALSE;
	int		quiet = FALSE;
	uintptr_t	list_addr;
	int		new_argc;
	mdb_arg_t	new_argv[3];

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'q', MDB_OPT_SETBITS, TRUE, &quiet,
	    'd', MDB_OPT_SETBITS, TRUE, &print_odir,
	    'f', MDB_OPT_SETBITS, TRUE, &print_ofile,
	    't', MDB_OPT_SETBITS, TRUE, &print_tree,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * An smb_user address must be specified on the command line.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags) && !quiet) {
		if (verbose)
			mdb_printf("SMB user information:\n\n");
		else
			mdb_printf("%<u>%-?s %4s %6s %8s %16s %8s   %s%</u>\n",
			    "Users:", "UID", "STATE", "FLAGS", "CRED",
			    "REFCNT", "ACCOUNT");
	}

	if (mdb_vread(&user, sizeof (user), addr) !=  sizeof (user)) {
		mdb_warn("failed to read struct smb_user at %?p", addr);
		return (DCMD_ERR);
	}

	if (!quiet) {
		char domain[SMB_PI_MAX_DOMAIN];
		char account[SMB_PI_MAX_USERNAME];
		int valid_domain = 0, valid_account = 0;

		if (mdb_vread(domain, user.u_domain_len,
		    (uintptr_t)user.u_domain) == user.u_domain_len)
			valid_domain = 1;
		if (mdb_vread(account, user.u_name_len,
		    (uintptr_t)user.u_name) == user.u_name_len)
			valid_account = 1;

		if (verbose) {
			mdb_printf("User ID          :\t%04x\n",
			    user.u_uid);
			mdb_printf("State            :\t%d\n",
			    user.u_state);
			mdb_printf("Flags            :\t%08x\n",
			    user.u_flags);
			mdb_printf("Privileges       :\t%08x\n",
			    user.u_privileges);
			mdb_printf("Credential       :\t%llx\n",
			    user.u_cred);
			mdb_printf("Reference Count  :\t%d\n",
			    user.u_refcnt);
			if (valid_domain && valid_account)
				mdb_printf("User Account     :\t%s\\%s\n",
				    domain, account);
			mdb_printf("\n");
		} else {
			mdb_printf("%?p %04x %6d %08x %?p %8d   %s\\%s\n",
			    addr, user.u_uid, user.u_state, user.u_flags,
			    user.u_cred, user.u_refcnt,
			    valid_domain ? domain : "UNKNOWN",
			    valid_account ? account : "UNKNOWN");
		}
	}

	new_argc = 0;
	if (!print_tree) {
		new_argv[new_argc].a_type = MDB_TYPE_STRING;
		new_argv[new_argc].a_un.a_str = "-q";
		new_argc++;
	}
	if (print_ofile) {
		new_argv[new_argc].a_type = MDB_TYPE_STRING;
		new_argv[new_argc].a_un.a_str = "-f";
		new_argc++;
	}
	if (print_odir) {
		new_argv[new_argc].a_type = MDB_TYPE_STRING;
		new_argv[new_argc].a_un.a_str = "-d";
		new_argc++;
	}

	if (print_tree || print_ofile || print_odir) {
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		list_addr = addr + offsetof(smb_user_t, u_tree_list) +
		    offsetof(smb_llist_t, ll_list);
		if (mdb_pwalk_dcmd("list", "smb_tree", new_argc, new_argv,
		    list_addr)) {
			mdb_warn("failed to walk tree list\n");
			(void) mdb_dec_indent(SMB_DCMD_INDENT);
			return (DCMD_ERR);
		}
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
	}

	return (DCMD_OK);
}

static void
smb_tree_help(void)
{
	mdb_printf(
	    "Display the contents of smb_tree_t, with optional filtering.\n\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf(
	    "-v\tDisplay verbose smb_tree information\n"
	    "-q\tDon't Display the contents of the smb_tree. This option "
	    "should be\n\tused in conjunction with -d or -f\n"
	    "-d\tDisplay the list of smb_odirs attached\n"
	    "-f\tDisplay the list of smb_ofiles attached\n");
}

static int
smb_tree(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_tree_t	tree;
	int		print_odir = FALSE;
	int		print_ofile = FALSE;
	int		verbose = FALSE;
	int		quiet = FALSE;
	uintptr_t	list_addr;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'd', MDB_OPT_SETBITS, TRUE, &print_odir,
	    'f', MDB_OPT_SETBITS, TRUE, &print_ofile,
	    'q', MDB_OPT_SETBITS, TRUE, &quiet,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If no smb_session address was specified on the command line, we can
	 * print out all smb sessions by invoking the smb_session walker, using
	 * this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (verbose)
			mdb_printf("SMB tree information:\n\n");
		else
			mdb_printf("%<u>%-?s %4s %6s %16s %10s%</u>\n",
			    "Trees:", "TID", "STATE", "SMB NODE",
			    "SHARE NAME");
	}

	/*
	 * Read tree and print some of the fields
	 */
	if (mdb_vread(&tree, sizeof (tree), addr) != sizeof (tree)) {
		mdb_warn("failed to read struct smb_tree at %p", addr);
		return (DCMD_ERR);
	}
	if (!quiet) {
		if (verbose) {
			mdb_printf("Tree ID          :\t%04x\n",
			    tree.t_tid);
			mdb_printf("State            :\t%d\n",
			    tree.t_state);
			mdb_printf("Share name       :\t%s\n",
			    tree.t_sharename);
			mdb_printf("Resource         :\t%s\n",
			    tree.t_resource);
			mdb_printf("Umask            :\t%04x\n",
			    tree.t_umask);
			mdb_printf("Access           :\t%04x\n",
			    tree.t_access);
			mdb_printf("Flags            :\t%08x\n",
			    tree.t_flags);
			mdb_printf("SMB Node         :\t%llx\n",
			    tree.t_snode);
			mdb_printf("Reference Count  :\t%d\n",
			    tree.t_refcnt);
			mdb_printf("\n");
		} else {
			mdb_printf("%?p %04x %6d %16llx %s\n", addr,
			    tree.t_tid, tree.t_state, tree.t_snode,
			    tree.t_sharename);
		}
	}

	if (print_odir) {
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		list_addr = addr + offsetof(smb_tree_t, t_odir_list) +
		    offsetof(smb_llist_t, ll_list);
		if (mdb_pwalk_dcmd("list", "smb_odir", 0, NULL, list_addr)) {
			mdb_warn("failed to walk odir list\n");
			(void) mdb_dec_indent(SMB_DCMD_INDENT);
			return (DCMD_ERR);
		}
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
	}

	if (print_ofile) {
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		list_addr = addr + offsetof(smb_tree_t, t_ofile_list) +
		    offsetof(smb_llist_t, ll_list);
		if (mdb_pwalk_dcmd("list", "smb_ofile", 0, NULL, list_addr)) {
			mdb_warn("failed to walk ofile list\n");
			(void) mdb_dec_indent(SMB_DCMD_INDENT);
			return (DCMD_ERR);
		}
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
	}

	return (DCMD_OK);
}

static int
smb_odir(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_odir_t	odir;
	int		verbose = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If no smb_session address was specified on the command line, we can
	 * print out all smb sessions by invoking the smb_session walker, using
	 * this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (verbose)
			mdb_printf("SMB odir information:\n\n");
		else
			mdb_printf("%<u>%-?s %8s %?s %10s%</u>\n",
			    "odir:", "STATE", "SMB NODE", "PATTERN");
	}

	/*
	 * For each smb_session, we just need to read the smb_session_t struct,
	 * read and then print out the following fields.
	 */
	if (mdb_vread(&odir, sizeof (odir), addr) == sizeof (odir)) {
		if (verbose) {
			mdb_printf("State            :\t%d\n",
			    odir.d_state);
			mdb_printf("Pattern          :\t%s\n",
			    odir.d_pattern);
			mdb_printf("SMB Node         :\t%s\n",
			    odir.d_dir_snode);
			mdb_printf("\n");
		} else {
			mdb_printf("%?p %8d %16llx %s\n", addr,
			    odir.d_state, odir.d_dir_snode, odir.d_pattern);
		}
	} else {
		mdb_warn("failed to read struct smb_odir at %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
smb_ofile(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_ofile_t ofile;
	int verbose = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If no smb_session address was specified on the command line, we can
	 * print out all smb sessions by invoking the smb_session walker, using
	 * this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (verbose)
			mdb_printf("SMB ofile information:\n\n");
		else
			mdb_printf("%<u>%-?s %04s %8s %?s %8s %?s%</u>\n",
			    "ofiles:", "FID", "STATE", "SMB NODE", "FLAGS",
			    "CRED");
	}

	/*
	 * For each smb_session, we just need to read the smb_session_t struct,
	 * read and then print out the following fields.
	 */
	if (mdb_vread(&ofile, sizeof (ofile), addr) == sizeof (ofile)) {
		if (verbose) {
			mdb_printf("Ofile ID         :\t%04x\n",
			    ofile.f_fid);
			mdb_printf("State            :\t%d\n",
			    ofile.f_state);
			mdb_printf("SMB Node         :\t%llx\n",
			    ofile.f_node);
			mdb_printf("LLF Offset       :\t%llx (%s)\n",
			    ofile.f_llf_pos,
			    ((ofile.f_flags & SMB_OFLAGS_LLF_POS_VALID) ?
			    "Valid" : "Invalid"));
			mdb_printf("FLAGS            :\t%08x\n",
			    ofile.f_flags);
			mdb_printf("Credential       :\t%llx\n",
			    ofile.f_cr);
			mdb_printf("\n");
		} else {
			mdb_printf("%?p %04x %8d %16llx %08x %?\n", addr,
			    ofile.f_fid, ofile.f_state, ofile.f_node,
			    ofile.f_flags, ofile.f_cr);
		}
	} else {
		mdb_warn("failed to read struct smb_odir at %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}


/*
 * ::smb_dispatch_stats
 *
 * smb_dispatch_stats dcmd - Prints all dispatched SMB requests statistics.
 */
/*ARGSUSED*/
static int
smb_stats(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	smb_dispatch_table_t	*disp;
	GElf_Sym		sym;
	int			nstats = 0, i;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_lookup_by_obj(MDB_OBJ_EVERY, "dispatch", &sym)) {
		mdb_warn("failed to find dispatch object");
		return (DCMD_ERR);
	}

	disp = mdb_alloc(sym.st_size, UM_SLEEP | UM_GC);
	if (mdb_vread(disp, sym.st_size, sym.st_value) == -1) {
		mdb_warn("failed to read from dispatch object");
		return (DCMD_ERR);
	}

	nstats = sym.st_size / sizeof (smb_dispatch_table_t);

	mdb_printf("All dispatched SMB requests statistics:\n\n");
	for (i = 0; i < nstats; i++) {
		if (disp[i].sdt_function)
			mdb_printf("    %40s\t: %lld\n",
			    disp[i].sdt_dispatch_stats.name,
			    disp[i].sdt_dispatch_stats.value.ui64);
	}
	return (DCMD_OK);
}

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers and a function named _mdb_init to return a pointer
 * to our module information.
 */
static const mdb_dcmd_t dcmds[] = {
	{   "smb_info", "[-c]",
	    "print smb_info information", smb_information },
	{   "smb_node", "?[-vps]",
	    "print smb_node_t information", smb_node, smb_node_help },
	{   "smb_session", "?[-vru]",
	    "print smb_session_t information", smb_session, smb_session_help},
	{   "smb_request", ":[-v]",
	    "print smb_request_t information", smb_request },
	{   "smb_lock", ":[-v]",
	    "print smb_lock_t information", smb_lock },
	{   "smb_user", ":[-vdftq]",
	    "print smb_user_t information", smb_user, smb_user_help },
	{   "smb_tree", ":[-vdfq]",
	    "print smb_tree_t information", smb_tree, smb_tree_help },
	{   "smb_odir", ":[-v]",
	    "print smb_odir_t information", smb_odir },
	{   "smb_ofile", "[-v]",
	    "print smb_odir_t information", smb_ofile },
	{   "smb_stats", NULL,
	    "print all smb dispatched requests statistics",
	    smb_stats },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{  "smb_session", "walk list of smb_session_t structures",
	    smb_session_walk_init, smb_session_walk_step,
	    NULL },
	{  "smb_node", "walk list of smb_node_t structures",
	    smb_node_walk_init, smb_node_walk_step,
	    NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
