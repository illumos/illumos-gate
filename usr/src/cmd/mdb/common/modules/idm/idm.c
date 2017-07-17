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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include <sys/cpuvar.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/taskq.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>		/* networking stuff */
#include <sys/strsubr.h>	/* networking stuff */
#include <sys/nvpair.h>
#include <sys/sunldi.h>
#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>

#define	IDM_CONN_SM_STRINGS
#define	IDM_TASK_SM_STRINGS
#define	ISCSIT_TGT_SM_STRINGS
#define	ISCSIT_SESS_SM_STRINGS
#define	ISCSIT_LOGIN_SM_STRINGS
#define	ISCSI_SESS_SM_STRINGS
#define	ISCSI_CMD_SM_STRINGS
#define	ISCSI_ICS_NAMES
#define	ISCSI_LOGIN_STATE_NAMES
#define	IDM_CN_NOTIFY_STRINGS
#include <sys/idm/idm.h>
#include <iscsi.h>
#include <iscsit.h>
#include <iscsit_isns.h>
#include <sys/ib/clients/iser/iser.h>

/*
 * We want to be able to print multiple levels of object hierarchy with a
 * single dcmd information, and preferably also exclude intermediate
 * levels if desired.  For example some of the target objects have the
 * following relationship:
 *
 * target --> session --> connection --> task
 *
 * The session dcmd should allow the printing of all associated tasks for the
 * sessions without printing all the associated connections.  To accomplish
 * this the following structure contains a bit for each object type.  Dcmds
 * should invoke the functions for child objects if any bits are set
 * in iscsi_dcmd_ctrl_t but the functions for the child object should only
 * print data if their associated bit is set. Each object type should print
 * a header for its first occurrence or if it is being printed as a child
 * object for the first occurrence under each parent. For the model to follow
 * see how idc->idc_header is handled in iscsi_sess_impl.
 *
 * Each dcmd should provide an external interface with the standard MDB API
 * and an internal interface that accepts iscsi_dcmd_ctrl_t.  To display
 * child objects the dcmd calls the internal interface for the child object
 * directly.  Dcmds invoked from the command line will, of course, call the
 * external interface.  See iscsi_conn() and iscsi_conn_impl().
 */

typedef struct {
	union	{
		uint32_t	idc_children;
		struct {
			uint32_t	idc_tgt:1,
					idc_tpg:1,
					idc_tpgt:1,
					idc_portal:1,
					idc_sess:1,
					idc_conn:1,
					idc_svc:1,
					idc_print_ip:1,
					idc_task:1,
					idc_buffer:1,
					idc_states:1,
					idc_rc_audit:1,
					idc_lun:1,
					idc_hba:1,
					idc_cmd:1;
		} child;
	} u;
	boolean_t		idc_ini;
	boolean_t		idc_tgt;
	boolean_t		idc_verbose;
	boolean_t		idc_header;
	/*
	 * Our connection dcmd code works off the global connection lists
	 * in IDM since we want to know about connections even when they
	 * have not progressed to the point that they have an associated
	 * session.  If we use "::iscsi_sess [-c]" then we only want to
	 * see connections associated with particular session.  To avoid
	 * writing a separate set of code to print session-specific connection
	 * the session code should set the sessions kernel address in the
	 * following field.  The connection code will then only print
	 * connections that match.
	 */
	uintptr_t		idc_assoc_session;
} iscsi_dcmd_ctrl_t;

typedef struct idm_hba_walk_info {
	void	**array;
	int	n_elements;
	int	cur_element;
	void	*data;
} idm_hba_walk_info_t;

static int iscsi_walk_all_sess(iscsi_dcmd_ctrl_t *idc);
static int iscsi_walk_all_conn(iscsi_dcmd_ctrl_t *idc);
static int iscsi_tgt_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void);
static int iscsi_tpgt_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void);
static int iscsi_tpg_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void);
static int iscsi_portal_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void);
static int iscsi_sess_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void);
static int iscsi_conn_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void);
static int iscsi_buffer_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void);
static int iscsi_svc_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void);
static int iscsi_ini_hba_walk_cb(uintptr_t addr, const void *vhba,
    void *idc_void);
static int iscsi_ini_sess_walk_cb(uintptr_t addr, const void *vsess,
    void *idc);
static int iscsi_ini_conn_walk_cb(uintptr_t addr, const void *vconn,
    void *idc_void);
static int iscsi_ini_lun_walk_cb(uintptr_t addr, const void *vlun,
    void *idc_void);
static int iscsi_ini_cmd_walk_cb(uintptr_t addr, const void *vcmd,
    void *idc);
static int iscsi_tgt_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static int iscsi_tpgt_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static int iscsi_tpg_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static int iscsi_portal_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static int iscsi_sess_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static int iscsi_conn_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static void iscsi_print_iscsit_conn_data(idm_conn_t *ict);
static void iscsi_print_ini_conn_data(idm_conn_t *ict);
static void iscsi_print_idm_conn_data(idm_conn_t *ict);
static int iscsi_task_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static void iscsi_print_iscsit_task_data(idm_task_t *idt);
static int iscsi_buffer_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static idm_conn_type_t idm_conn_type(uintptr_t addr);
static int iscsi_i_task_impl(idm_task_t *idt, uintptr_t addr,
    iscsi_dcmd_ctrl_t *idc);
static int iscsi_refcnt_impl(uintptr_t addr);
static int iscsi_sm_audit_impl(uintptr_t addr);
static int iscsi_isns(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
static int iscsi_svc_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static int iscsi_ini_hba_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc);
static int iscsi_print_ini_sess(uintptr_t addr, iscsi_sess_t *sess,
    iscsi_dcmd_ctrl_t *idc);
static int iscsi_print_ini_lun(uintptr_t addr, const iscsi_lun_t *lun,
    iscsi_dcmd_ctrl_t *idc);
static int iscsi_print_ini_cmd(uintptr_t addr, const iscsi_cmd_t *cmd,
    iscsi_dcmd_ctrl_t *idc);
static int iscsi_ini_sess_walk_init(mdb_walk_state_t *wsp);
static int iscsi_ini_sess_step(mdb_walk_state_t *wsp);
static int iscsi_ini_conn_walk_init(mdb_walk_state_t *wsp);
static int iscsi_ini_conn_step(mdb_walk_state_t *wsp);
static int iscsi_ini_lun_walk_init(mdb_walk_state_t *wsp);
static int iscsi_ini_lun_step(mdb_walk_state_t *wsp);
static int iscsi_ini_cmd_walk_init(mdb_walk_state_t *wsp);
static int iscsi_ini_cmd_step(mdb_walk_state_t *wsp);
static const char *iscsi_idm_conn_event(unsigned int event);
static const char *iscsi_iscsit_tgt_event(unsigned int event);
static const char *iscsi_iscsit_sess_event(unsigned int event);
static const char *iscsi_iscsit_login_event(unsigned int event);
static const char *iscsi_iscsi_cmd_event(unsigned int event);
static const char *iscsi_iscsi_sess_event(unsigned int event);
static const char *iscsi_idm_conn_state(unsigned int state);
static const char *iscsi_idm_task_state(unsigned int state);
static const char *iscsi_iscsit_tgt_state(unsigned int state);
static const char *iscsi_iscsit_sess_state(unsigned int state);
static const char *iscsi_iscsit_login_state(unsigned int state);
static const char *iscsi_iscsi_cmd_state(unsigned int state);
static const char *iscsi_iscsi_sess_state(unsigned int state);
static const char *iscsi_iscsi_conn_state(unsigned int state);
static const char *iscsi_iscsi_conn_event(unsigned int event);
static const char *iscsi_iscsi_login_state(unsigned int state);

static void iscsi_format_timestamp(char *ts_str, int strlen,
    timespec_t *ts);
static char *iscsi_inet_ntop(int af, const void *addr, char *buf, int addrlen);
static void convert2ascii(char *, const in6_addr_t *);
static int sa_to_str(struct sockaddr_storage *sa, char *addr);
static int iscsi_isns_esi_cb(uintptr_t addr, const void *walker_data,
    void *data);
static int iscsi_isns_portal_cb(uintptr_t addr, const void *walker_data,
    void *data);

#define	PORTAL_STR_LEN	(INET6_ADDRSTRLEN + 7)

/*
 * ::iscsi_tgt [-scatgpbSRv]
 *
 * iscsi_tgt - Print out information associated with an iscsit target instance
 *
 * s	Print associated session information
 * c	Print associated connection information
 * a	Print IP addresses with connection information
 * t	Print associated task information
 * g	Print associated TPG information
 * p	Print portals with TPG information
 * b	Print associated buffer information
 * S	Print recent state events and transitions
 * R	Print reference count audit data
 * v	Verbose output about the connection
 */
/*ARGSUSED*/
static int
iscsi_tgt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t	idc;
	int			buffer = 0, task = 0, print_ip = 0;
	int			tpgt = 0, conn = 0, sess = 0, portal = 0;
	int			states = 0, rc_audit = 0;
	uintptr_t		iscsit_global_addr, avl_addr, list_addr;
	GElf_Sym		sym;

	bzero(&idc, sizeof (idc));
	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &print_ip,
	    'g', MDB_OPT_SETBITS, TRUE, &tpgt,
	    's', MDB_OPT_SETBITS, TRUE, &sess,
	    'c', MDB_OPT_SETBITS, TRUE, &conn,
	    't', MDB_OPT_SETBITS, TRUE, &task,
	    'b', MDB_OPT_SETBITS, TRUE, &buffer,
	    'p', MDB_OPT_SETBITS, TRUE, &portal,
	    'S', MDB_OPT_SETBITS, TRUE, &states,
	    'R', MDB_OPT_SETBITS, TRUE, &rc_audit,
	    'v', MDB_OPT_SETBITS, TRUE, &idc.idc_verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	idc.u.child.idc_tgt = 1;
	idc.u.child.idc_print_ip = print_ip;
	idc.u.child.idc_tpgt = tpgt;
	idc.u.child.idc_portal = portal;
	idc.u.child.idc_sess = sess;
	idc.u.child.idc_conn = conn;
	idc.u.child.idc_task = task;
	idc.u.child.idc_buffer = buffer;
	idc.u.child.idc_states = states;
	idc.u.child.idc_rc_audit = rc_audit;

	if (DCMD_HDRSPEC(flags))
		idc.idc_header = 1;

	/*
	 * If no address was specified on the command line, we
	 * print out all tgtions
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_lookup_by_name("iscsit_global", &sym) == -1) {
			mdb_warn("failed to find symbol 'iscsit_global'");
			return (DCMD_ERR);
		}
		iscsit_global_addr = (uintptr_t)sym.st_value;
		avl_addr = iscsit_global_addr +
		    offsetof(iscsit_global_t, global_target_list);
		if (mdb_pwalk("avl", iscsi_tgt_walk_cb, &idc, avl_addr) == -1) {
			mdb_warn("avl walk failed for global target tree");
			return (DCMD_ERR);
		}
		list_addr = iscsit_global_addr +
		    offsetof(iscsit_global_t, global_deleted_target_list);
		if (mdb_pwalk("list", iscsi_tgt_walk_cb,
		    &idc, list_addr) == -1) {
			mdb_warn("list walk failed for deleted target list");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	return (iscsi_tgt_impl(addr, &idc));
}

static int
iscsi_tpg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t	idc;
	uintptr_t		iscsit_global_addr, avl_addr;
	GElf_Sym		sym;
	int			rc_audit = 0;

	bzero(&idc, sizeof (idc));
	if (mdb_getopts(argc, argv,
	    'R', MDB_OPT_SETBITS, TRUE, &rc_audit,
	    NULL) != argc)
		return (DCMD_USAGE);

	/* Always print tpgs and portals */
	idc.u.child.idc_tpg = 1;
	idc.u.child.idc_portal = 1;
	idc.u.child.idc_rc_audit = rc_audit;
	if (DCMD_HDRSPEC(flags))
		idc.idc_header = 1;

	/*
	 * If no address was specified on the command line, we
	 * print out all tgtions
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_lookup_by_name("iscsit_global", &sym) == -1) {
			mdb_warn("failed to find symbol 'iscsit_global'");
			return (DCMD_ERR);
		}
		iscsit_global_addr = (uintptr_t)sym.st_value;
		avl_addr = iscsit_global_addr +
		    offsetof(iscsit_global_t, global_tpg_list);
		if (mdb_pwalk("avl", iscsi_tpg_walk_cb, &idc, avl_addr) == -1) {
			mdb_warn("avl walk failed for global target tree");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	return (iscsi_tpg_impl(addr, &idc));
}

/*
 * ::iscsi_tpgt [-pR]
 *
 * Print tpgt information.
 * R	Print reference count audit data
 * p	Print portal data
 */
static int
iscsi_tpgt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t	idc;
	uintptr_t		iscsit_global_addr, avl_addr, list_addr;
	GElf_Sym		sym;
	int			rc_audit = 0, portal = 0;

	bzero(&idc, sizeof (idc));
	if (mdb_getopts(argc, argv,
	    'p', MDB_OPT_SETBITS, TRUE, &portal,
	    'R', MDB_OPT_SETBITS, TRUE, &rc_audit,
	    NULL) != argc)
		return (DCMD_USAGE);

	idc.u.child.idc_tpgt = 1;
	idc.u.child.idc_portal = portal;
	idc.u.child.idc_rc_audit = rc_audit;
	if (DCMD_HDRSPEC(flags))
		idc.idc_header = 1;

	/*
	 * If no address was specified on the command line,
	 * print out all tpgts
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_lookup_by_name("iscsit_global", &sym) == -1) {
			mdb_warn("failed to find symbol 'iscsit_global'");
			return (DCMD_ERR);
		}
		iscsit_global_addr = (uintptr_t)sym.st_value;
		avl_addr = iscsit_global_addr +
		    offsetof(iscsit_global_t, global_target_list);
		if (mdb_pwalk("avl", iscsi_tgt_walk_cb, &idc, avl_addr) == -1) {
			mdb_warn("avl walk failed for global target tree");
			return (DCMD_ERR);
		}
		list_addr = iscsit_global_addr +
		    offsetof(iscsit_global_t, global_deleted_target_list);
		if (mdb_pwalk("list", iscsi_tgt_walk_cb,
		    &idc, list_addr) == -1) {
			mdb_warn("list walk failed for deleted target list");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	return (iscsi_tpgt_impl(addr, &idc));
}

/*
 * ::iscsi_sess [-ablmtvcSRIT]
 *
 * iscsi_sess - Print out information associated with an iSCSI session
 *
 * I	Print only initiator sessions
 * T	Print only target sessions
 * c	Print associated connection information
 * a	Print IP addresses with connection information
 * t	Print associated task information
 * l	Print associated lun information (with -I)
 * m	Print associated initiator command information (with -I)
 * b	Print associated buffer information
 * S	Print recent state events and transitions
 * R	Print reference count audit data
 * v	Verbose output about the connection
 */
/*ARGSUSED*/
static int
iscsi_sess(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t	idc;
	int			buffer = 0, task = 0, conn = 0, print_ip = 0;
	int			states = 0, rc_audit = 0, commands = 0;
	int			luns = 0;

	bzero(&idc, sizeof (idc));
	if (mdb_getopts(argc, argv,
	    'I', MDB_OPT_SETBITS, TRUE, &idc.idc_ini,
	    'T', MDB_OPT_SETBITS, TRUE, &idc.idc_tgt,
	    'a', MDB_OPT_SETBITS, TRUE, &print_ip,
	    'c', MDB_OPT_SETBITS, TRUE, &conn,
	    't', MDB_OPT_SETBITS, TRUE, &task,
	    'l', MDB_OPT_SETBITS, TRUE, &luns,
	    'm', MDB_OPT_SETBITS, TRUE, &commands,
	    'b', MDB_OPT_SETBITS, TRUE, &buffer,
	    'S', MDB_OPT_SETBITS, TRUE, &states,
	    'R', MDB_OPT_SETBITS, TRUE, &rc_audit,
	    'v', MDB_OPT_SETBITS, TRUE, &idc.idc_verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	idc.u.child.idc_sess = 1;
	idc.u.child.idc_print_ip = print_ip;
	idc.u.child.idc_conn = conn;
	idc.u.child.idc_task = task;
	idc.u.child.idc_cmd = commands;
	idc.u.child.idc_lun = luns;
	idc.u.child.idc_buffer = buffer;
	idc.u.child.idc_states = states;
	idc.u.child.idc_rc_audit = rc_audit;
	if (DCMD_HDRSPEC(flags))
		idc.idc_header = 1;

	/*
	 * If no address was specified on the command line, we
	 * print out all sessions
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		return (iscsi_walk_all_sess(&idc));
	}
	return (iscsi_sess_impl(addr, &idc));
}



/*
 * ::iscsi_conn [-abmtvSRIT]
 *
 * iscsi_conn - Print out information associated with an iSCSI connection
 *
 * I	Print only initiator connections
 * T	Print only target connections
 * a	Print IP addresses with connection information
 * t	Print associated task information
 * b	Print associated buffer information
 * m	Print associated initiator commands (with -I)
 * S	Print recent state events and transitions
 * R	Print reference count audit data
 * v	Verbose output about the connection
 */
/*ARGSUSED*/
static int
iscsi_conn(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t	idc;
	int			buffer = 0, task = 0, print_ip = 0;
	int			states = 0, rc_audit = 0, commands = 0;

	bzero(&idc, sizeof (idc));
	if (mdb_getopts(argc, argv,
	    'I', MDB_OPT_SETBITS, TRUE, &idc.idc_ini,
	    'T', MDB_OPT_SETBITS, TRUE, &idc.idc_tgt,
	    'a', MDB_OPT_SETBITS, TRUE, &print_ip,
	    't', MDB_OPT_SETBITS, TRUE, &task,
	    'b', MDB_OPT_SETBITS, TRUE, &buffer,
	    'm', MDB_OPT_SETBITS, TRUE, &commands,
	    'S', MDB_OPT_SETBITS, TRUE, &states,
	    'R', MDB_OPT_SETBITS, TRUE, &rc_audit,
	    'v', MDB_OPT_SETBITS, TRUE, &idc.idc_verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	idc.u.child.idc_conn = 1;
	idc.u.child.idc_print_ip = print_ip;
	idc.u.child.idc_task = task;
	idc.u.child.idc_buffer = buffer;
	idc.u.child.idc_cmd = commands;
	idc.u.child.idc_states = states;
	idc.u.child.idc_rc_audit = rc_audit;
	if (DCMD_HDRSPEC(flags))
		idc.idc_header = 1;

	/*
	 * If no address was specified on the command line, we
	 * print out all connections
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		return (iscsi_walk_all_conn(&idc));
	}
	return (iscsi_conn_impl(addr, &idc));
}


/*
 * ::iscsi_svc [-vR]
 *
 * iscsi_svc - Print out information associated with an iSCSI svc
 *
 * R	Print reference count audit data
 * v	Verbose output about the service
 */
static int
iscsi_svc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t	idc;
	GElf_Sym		sym;
	uintptr_t		idm_addr;
	uintptr_t		svc_list_addr;
	int			rc_audit = 0;

	bzero(&idc, sizeof (iscsi_dcmd_ctrl_t));

	if (mdb_getopts(argc, argv,
	    'R', MDB_OPT_SETBITS, TRUE, &rc_audit,
	    'v', MDB_OPT_SETBITS, TRUE, &idc.idc_verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	idc.u.child.idc_svc = 1;
	idc.u.child.idc_rc_audit = rc_audit;
	if (DCMD_HDRSPEC(flags)) {
		idc.idc_header = 1;
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_lookup_by_name("idm", &sym) == -1) {
			mdb_warn("failed to find symbol 'idm'");
			return (DCMD_ERR);
		}
		idm_addr = (uintptr_t)sym.st_value;
		svc_list_addr = idm_addr + offsetof(idm_global_t,
		    idm_tgt_svc_list);

		if (mdb_pwalk("list", iscsi_svc_walk_cb, &idc,
		    svc_list_addr) == -1) {
			mdb_warn("list walk failed for idm services");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	return (iscsi_svc_impl(addr, &idc));
}

/*
 * ::iscsi_portal -R
 *
 * iscsi_portal - Print out information associated with an iSCSI portal
 *
 * R	Print reference count audit data
 */
static int
iscsi_portal(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t	idc;
	GElf_Sym		sym;
	iscsit_global_t		iscsit_global;
	uintptr_t		iscsit_global_addr;
	uintptr_t		tpg_avl_addr;
	int			rc_audit = 0;

	bzero(&idc, sizeof (iscsi_dcmd_ctrl_t));

	if (mdb_getopts(argc, argv,
	    'R', MDB_OPT_SETBITS, TRUE, &rc_audit,
	    NULL) != argc)
		return (DCMD_USAGE);

	idc.u.child.idc_rc_audit = rc_audit;
	idc.u.child.idc_portal = 1;
	if (DCMD_HDRSPEC(flags)) {
		idc.idc_header = 1;
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_lookup_by_name("iscsit_global", &sym) == -1) {
			mdb_warn("failed to find symbol 'iscsit_global'");
			return (DCMD_ERR);
		}

		iscsit_global_addr = (uintptr_t)sym.st_value;

		/* get and print the global default tpg */
		if (mdb_vread(&iscsit_global, sizeof (iscsit_global_t),
		    iscsit_global_addr) != sizeof (iscsit_global_t)) {
			mdb_warn("failed to read iscsit_global_t");
			return (DCMD_ERR);
		}
		if (iscsi_tpg_impl((uintptr_t)iscsit_global.global_default_tpg,
		    &idc) != DCMD_OK) {
			return (DCMD_ERR);
		}

		/* Walk the tpgs for the rest of the portals */
		tpg_avl_addr = iscsit_global_addr + offsetof(iscsit_global_t,
		    global_tpg_list);
		if (mdb_pwalk("avl", iscsi_tpg_walk_cb, &idc,
		    tpg_avl_addr) == -1) {
			mdb_warn("list walk failed for global tpg tree");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	return (iscsi_portal_impl(addr, &idc));
}


/*
 * ::iscsi_cmd -S
 *
 * iscsi_cmd - Print out information associated with an iSCSI cmd
 *
 * S	Print state audit data
 */
static int
iscsi_cmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t	idc;
	iscsi_cmd_t		cmd;
	int			states = 0;

	bzero(&idc, sizeof (iscsi_dcmd_ctrl_t));

	if (mdb_getopts(argc, argv,
	    'S', MDB_OPT_SETBITS, TRUE, &states,
	    NULL) != argc)
		return (DCMD_USAGE);

	idc.u.child.idc_states = states;
	idc.u.child.idc_cmd = 1;
	idc.idc_ini = 1;
	if (DCMD_HDRSPEC(flags)) {
		idc.idc_header = 1;
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_pwalk("iscsi_ini_hba", iscsi_ini_hba_walk_cb,
		    &idc, NULL) == -1) {
			mdb_warn("iscsi cmd hba list walk failed");
			return (DCMD_ERR);
		}
	} else {
		if (mdb_vread(&cmd, sizeof (iscsi_cmd_t), addr) !=
		    sizeof (iscsi_cmd_t)) {
			return (DCMD_ERR);
		}
		return (iscsi_print_ini_cmd(addr, &cmd, &idc));
	}
	return (DCMD_OK);
}


static int
iscsi_ini_hba_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	iscsi_hba_t ih;

	if (mdb_vread(&ih, sizeof (ih), addr) != sizeof (ih)) {
		mdb_warn("Invalid HBA\n");
		return (DCMD_ERR);
	}

	if (idc->u.child.idc_hba) {
		mdb_printf("iscsi_hba %p sessions: \n", addr);
	}

	if (mdb_pwalk("iscsi_ini_sess", iscsi_ini_sess_walk_cb, idc,
	    (uintptr_t)ih.hba_sess_list) == -1) {
		mdb_warn("iscsi_sess_t walk failed");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

/*
 * ::iscsi_task [-bv]
 *
 * iscsi_task - Print out information associated with an iSCSI task
 *
 * b	Print associated buffer information
 * S	Print recent state events and transitions
 * R	Print reference count audit data
 * v	Verbose output about the connection
 */
/*ARGSUSED*/
static int
iscsi_task(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t	idc;
	int			buffer = 0;
	int			states = 0, rc_audit = 0;

	bzero(&idc, sizeof (idc));
	if (mdb_getopts(argc, argv,
	    'b', MDB_OPT_SETBITS, TRUE, &buffer,
	    'S', MDB_OPT_SETBITS, TRUE, &states,
	    'R', MDB_OPT_SETBITS, TRUE, &rc_audit,
	    'v', MDB_OPT_SETBITS, TRUE, &idc.idc_verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	idc.u.child.idc_conn = 0;
	idc.u.child.idc_task = 1;
	idc.u.child.idc_buffer = buffer;
	idc.u.child.idc_states = states;
	idc.u.child.idc_rc_audit = rc_audit;
	if (DCMD_HDRSPEC(flags))
		idc.idc_header = 1;

	/*
	 * If no address was specified on the command line, we
	 * print out all connections
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		return (iscsi_walk_all_conn(&idc));
	}
	return (iscsi_task_impl(addr, &idc));
}

/*
 * ::iscsi_refcnt
 *
 * iscsi_refcnt - Dump an idm_refcnt_t structure
 *
 */
/*ARGSUSED*/
static int
iscsi_refcnt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_ERR);
	}
	return (iscsi_refcnt_impl(addr));
}

/*
 * ::iscsi_states
 *
 * iscsi_states - Dump events and state transitions recoreded in an
 * idm_sm_audit_t structure
 *
 */
/*ARGSUSED*/
static int
iscsi_states(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_ERR);
	}
	return (iscsi_sm_audit_impl(addr));
}


static int
iscsi_walk_all_sess(iscsi_dcmd_ctrl_t *idc)
{
	uintptr_t	iscsit_global_addr;
	uintptr_t	avl_addr;
	uintptr_t	list_addr;
	GElf_Sym	sym;

	/* Initiator sessions */
	if (idc->idc_ini) {
		/* Always print hba info on this path */
		idc->u.child.idc_hba = 1;
		if (mdb_pwalk("iscsi_ini_hba", iscsi_ini_hba_walk_cb,
		    idc, NULL) == -1) {
			mdb_warn("iscsi cmd hba list walk failed");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/* Target sessions */
	/* Walk discovery sessions */
	if (mdb_lookup_by_name("iscsit_global", &sym) == -1) {
		mdb_warn("failed to find symbol 'iscsit_global'");
		return (DCMD_ERR);
	}
	iscsit_global_addr = (uintptr_t)sym.st_value;
	avl_addr = iscsit_global_addr +
	    offsetof(iscsit_global_t, global_discovery_sessions);
	if (mdb_pwalk("avl", iscsi_sess_walk_cb, idc, avl_addr) == -1) {
		mdb_warn("avl walk failed for discovery sessions");
		return (DCMD_ERR);
	}

	/* Walk targets printing all session info */
	avl_addr = iscsit_global_addr +
	    offsetof(iscsit_global_t, global_target_list);
	if (mdb_pwalk("avl", iscsi_tgt_walk_cb, idc, avl_addr) == -1) {
		mdb_warn("avl walk failed for target/session tree");
		return (DCMD_ERR);
	}

	/* Walk deleting targets printing all session info */
	list_addr = iscsit_global_addr +
	    offsetof(iscsit_global_t, global_deleted_target_list);
	if (mdb_pwalk("list", iscsi_tgt_walk_cb, idc, list_addr) == -1) {
		mdb_warn("list walk failed for deleted target list");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
iscsi_walk_all_conn(iscsi_dcmd_ctrl_t *idc)
{
	uintptr_t	idm_global_addr;
	uintptr_t	list_addr;
	GElf_Sym	sym;

	/* Walk initiator connections */
	if (mdb_lookup_by_name("idm", &sym) == -1) {
		mdb_warn("failed to find symbol 'idm'");
		return (DCMD_ERR);
	}
	idm_global_addr = (uintptr_t)sym.st_value;
	/* Walk connection list associated with the initiator */
	list_addr = idm_global_addr + offsetof(idm_global_t, idm_ini_conn_list);
	if (mdb_pwalk("list", iscsi_conn_walk_cb, idc, list_addr) == -1) {
		mdb_warn("list walk failed for initiator connections");
		return (DCMD_ERR);
	}

	/* Walk connection list associated with the target */
	list_addr = idm_global_addr + offsetof(idm_global_t, idm_tgt_conn_list);
	if (mdb_pwalk("list", iscsi_conn_walk_cb, idc, list_addr) == -1) {
		mdb_warn("list walk failed for target service instances");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
iscsi_tpg_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void)
{
	/* We don't particularly care about the list walker data */
	iscsi_dcmd_ctrl_t	*idc = idc_void;
	int			rc;

	rc = iscsi_tpg_impl(addr, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_tgt_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void)
{
	/* We don't particularly care about the list walker data */
	iscsi_dcmd_ctrl_t	*idc = idc_void;
	int			rc;

	rc = iscsi_tgt_impl(addr, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_tpgt_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void)
{
	/* We don't particularly care about the list walker data */
	iscsi_dcmd_ctrl_t	*idc = idc_void;
	int			rc;

	rc = iscsi_tpgt_impl(addr, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_portal_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void)
{
	/* We don't particularly care about the list walker data */
	iscsi_dcmd_ctrl_t	*idc = idc_void;
	int			rc;

	rc = iscsi_portal_impl(addr, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_sess_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void)
{
	/* We don't particularly care about the list walker data */
	iscsi_dcmd_ctrl_t	*idc = idc_void;
	int			rc;

	rc = iscsi_sess_impl(addr, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_sess_conn_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void)
{
	/* We don't particularly care about the list walker data */
	iscsi_dcmd_ctrl_t	*idc = idc_void;
	iscsit_conn_t		ict;
	int			rc;

	/*
	 * This function is different from iscsi_conn_walk_cb because
	 * we get an iscsit_conn_t instead of an idm_conn_t
	 *
	 * Read iscsit_conn_t, use to get idm_conn_t pointer
	 */
	if (mdb_vread(&ict, sizeof (iscsit_conn_t), addr) !=
	    sizeof (iscsit_conn_t)) {
		return (DCMD_ERR);
	}
	rc = iscsi_conn_impl((uintptr_t)ict.ict_ic, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_conn_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void)
{
	/* We don't particularly care about the list walker data */
	iscsi_dcmd_ctrl_t	*idc = idc_void;
	int			rc;

	rc = iscsi_conn_impl(addr, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_buffer_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void)
{
	/* We don't particularly care about the list walker data */
	iscsi_dcmd_ctrl_t	*idc = idc_void;
	int			rc;

	rc = iscsi_buffer_impl(addr, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_svc_walk_cb(uintptr_t addr, const void *list_walker_data,
    void *idc_void)
{
	iscsi_dcmd_ctrl_t	*idc = idc_void;
	int			rc;

	rc = iscsi_svc_impl(addr, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_ini_hba_walk_cb(uintptr_t addr, const void *vhba, void *idc_void)
{

	iscsi_dcmd_ctrl_t	*idc = idc_void;
	int			rc;

	rc = iscsi_ini_hba_impl(addr, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

static int
iscsi_ini_sess_walk_cb(uintptr_t addr, const void *vsess, void *idc_void)
{
	int rc;

	if (vsess == NULL) {
		return (WALK_ERR);
	}

	rc = iscsi_print_ini_sess(addr, (iscsi_sess_t *)vsess,
	    (iscsi_dcmd_ctrl_t *)idc_void);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

/*ARGSUSED*/
static int
iscsi_ini_conn_walk_cb(uintptr_t addr, const void *vconn, void *idc_void)
{
	const iscsi_conn_t	*ict = vconn;
	int			rc;

	if (vconn == NULL) {
		return (WALK_ERR);
	}

	/*
	 * Look up the idm_conn_t in the iscsi_conn_t and call the general
	 * connection handler.
	 */
	rc = iscsi_conn_impl((uintptr_t)ict->conn_ic,
	    (iscsi_dcmd_ctrl_t *)idc_void);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

static int
iscsi_ini_lun_walk_cb(uintptr_t addr, const void *vlun, void *idc_void)
{
	int			rc;

	if (vlun == NULL) {
		return (WALK_ERR);
	}

	rc = iscsi_print_ini_lun(addr, (iscsi_lun_t *)vlun,
	    (iscsi_dcmd_ctrl_t *)idc_void);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}


static int
iscsi_tgt_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	iscsit_tgt_t	tgt;
	uintptr_t	avl_addr, rc_addr, states_addr;
	char		tgt_name[MAX_ISCSI_NODENAMELEN];
	int		verbose, states, rc_audit;

	/*
	 * Read iscsit_tgt_t
	 */
	if (mdb_vread(&tgt, sizeof (iscsit_tgt_t), addr) !=
	    sizeof (iscsit_tgt_t)) {
		return (DCMD_ERR);
	}

	/*
	 * Read target name if available
	 */
	if ((tgt.target_name == NULL) ||
	    (mdb_readstr(tgt_name, sizeof (tgt_name),
	    (uintptr_t)tgt.target_name) == -1)) {
		strcpy(tgt_name, "N/A");
	}

	/*
	 * Brief output
	 *
	 * iscsit_tgt_t pointer
	 * iscsit_tgt_t.target_stmf_state
	 * iscsit_tgt_t.target_sess_list.avl_numnodes (session count)
	 * iscsit_tgt_t.target_name;
	 */

	verbose = idc->idc_verbose;
	states = idc->u.child.idc_states;
	rc_audit = idc->u.child.idc_rc_audit;

	/* For now we will ignore the verbose flag */
	if (idc->u.child.idc_tgt) {
		/* Print target data */
		if (idc->idc_header) {
			mdb_printf("%<u>%-19s %-4s  %-8s%</u>\n",
			    "iscsit_tgt_t", "Sess", "State");
		}
		mdb_printf("%-19p %-4d %-8d\n", addr,
		    tgt.target_sess_list.avl_numnodes,
		    tgt.target_state);
		mdb_printf("  %s\n", tgt_name);

		/* Indent and disable verbose for any child structures */
		mdb_inc_indent(4);
		idc->idc_verbose = 0;
	}

	/*
	 * Print states if requested
	 */
	if (idc->u.child.idc_tgt && states) {
		states_addr = addr + offsetof(iscsit_tgt_t, target_state_audit);

		mdb_printf("State History(target_state_audit):\n");
		if (iscsi_sm_audit_impl(states_addr) != DCMD_OK)
			return (DCMD_ERR);
		idc->u.child.idc_states = 0;
	}

	/*
	 * Print refcnt audit data if requested
	 */
	if (idc->u.child.idc_tgt && rc_audit) {
		mdb_printf("Reference History(target_sess_refcnt):\n");
		rc_addr = addr +
		    offsetof(iscsit_tgt_t, target_sess_refcnt);
		if (iscsi_refcnt_impl(rc_addr) != DCMD_OK)
			return (DCMD_ERR);

		mdb_printf("Reference History(target_refcnt):\n");
		rc_addr = addr +
		    offsetof(iscsit_tgt_t, target_refcnt);

		if (iscsi_refcnt_impl(rc_addr) != DCMD_OK)
			return (DCMD_ERR);
		idc->u.child.idc_rc_audit = 0;
	}

	/* Any child objects to walk? */
	if (idc->u.child.idc_tpgt || idc->u.child.idc_portal) {

		if (idc->u.child.idc_tgt) {
			idc->idc_header = 1;
		}

		/* Walk TPGT tree */
		avl_addr = addr +
		    offsetof(iscsit_tgt_t, target_tpgt_list);
		if (mdb_pwalk("avl", iscsi_tpgt_walk_cb, idc,
		    avl_addr) == -1) {
			mdb_warn("target tpgt list walk failed");
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}

	if (idc->u.child.idc_sess || idc->u.child.idc_conn ||
	    idc->u.child.idc_task || idc->u.child.idc_buffer) {

		if (idc->u.child.idc_tgt || idc->u.child.idc_tpgt ||
		    idc->u.child.idc_portal) {
			idc->idc_header = 1;
		}

		/* Walk sess tree */
		avl_addr = addr + offsetof(iscsit_tgt_t, target_sess_list);
		if (mdb_pwalk("avl", iscsi_sess_walk_cb, idc,
		    avl_addr) == -1) {
			mdb_warn("target sess list walk failed");
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}

	/* If tgts were handled decrease indent and reset header */
	if (idc->u.child.idc_tgt) {
		idc->idc_header = 0;
		mdb_dec_indent(4);
	}

	idc->idc_verbose = verbose;
	idc->u.child.idc_states = states;
	idc->u.child.idc_rc_audit = rc_audit;
	return (DCMD_OK);
}

static int
iscsi_tpgt_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	iscsit_tpgt_t	tpgt;
	iscsit_tpg_t	tpg;
	uintptr_t	avl_addr, tpg_addr, rc_addr;
	int		rc_audit;

	/*
	 * Read iscsit_tpgt_t
	 */
	if (mdb_vread(&tpgt, sizeof (iscsit_tpgt_t), addr) !=
	    sizeof (iscsit_tpgt_t)) {
		return (DCMD_ERR);
	}

	tpg_addr = (uintptr_t)tpgt.tpgt_tpg;

	/*
	 * Read iscsit_tpg_t
	 */
	if (mdb_vread(&tpg, sizeof (iscsit_tpg_t), tpg_addr) !=
	    sizeof (iscsit_tpg_t)) {
		return (DCMD_ERR);
	}

	rc_audit = idc->u.child.idc_rc_audit;

	/*
	 * Brief output
	 *
	 * iscsit_tpgt_t pointer
	 * iscsit_tpg_t pointer
	 * iscsit_tpg_t.tpg_name
	 * iscsit_tpgt_t.tpgt_tag;
	 */

	/* For now we will ignore the verbose flag */
	if (idc->u.child.idc_tpgt) {
		/* Print target data */
		if (idc->idc_header) {
			mdb_printf("%<u>%-?s %-?s %-18s %-6s%</u>\n",
			    "iscsit_tpgt_t", "iscsit_tpg_t", "Name", "Tag");
		}
		mdb_printf("%?p %?p %-18s 0x%04x\n", addr, tpgt.tpgt_tpg,
		    tpg.tpg_name, tpgt.tpgt_tag);

		if (rc_audit) {
			(void) mdb_inc_indent(4);

			mdb_printf("Reference History(tpgt_refcnt):\n");
			rc_addr = addr + offsetof(iscsit_tpgt_t, tpgt_refcnt);
			if (iscsi_refcnt_impl(rc_addr) != DCMD_OK)
				return (DCMD_ERR);

			idc->u.child.idc_rc_audit = 0;
			(void) mdb_dec_indent(4);
		}
	}

	/*
	 * Assume for now that anyone interested in TPGT wants to see the
	 * portals as well. Enable idc_header for the portals.
	 */
	idc->idc_header = 1;
	(void) mdb_inc_indent(4);
	avl_addr = tpg_addr + offsetof(iscsit_tpg_t, tpg_portal_list);
	if (mdb_pwalk("avl", iscsi_portal_walk_cb, idc, avl_addr) == -1) {
		mdb_warn("portal list walk failed");
		(void) mdb_dec_indent(4);
		return (DCMD_ERR);
	}
	(void) mdb_dec_indent(4);
	idc->idc_header = 0;

	idc->u.child.idc_rc_audit = rc_audit;
	return (DCMD_OK);
}

static int
iscsi_tpg_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	iscsit_tpg_t	tpg;
	uintptr_t	avl_addr, rc_addr;
	int		rc_audit = 0;

	rc_audit = idc->u.child.idc_rc_audit;

	/*
	 * Read iscsit_tpg_t
	 */
	if (mdb_vread(&tpg, sizeof (iscsit_tpg_t), addr) !=
	    sizeof (iscsit_tpg_t)) {
		return (DCMD_ERR);
	}

	/*
	 * Brief output
	 *
	 * iscsit_tpgt_t pointer
	 * iscsit_tpg_t pointer
	 * iscsit_tpg_t.tpg_name
	 * iscsit_tpgt_t.tpgt_tag;
	 */

	/* Print tpg data */
	if (idc->u.child.idc_tpg) {
		if (idc->idc_header) {
			mdb_printf("%<u>%-?s %-18s%</u>\n",
			    "iscsit_tpg_t", "Name");
		}
		mdb_printf("%?p %-18s\n", addr, tpg.tpg_name);

		(void) mdb_inc_indent(4);

		if (rc_audit) {
			mdb_printf("Reference History(tpg_refcnt):\n");
			rc_addr = addr + offsetof(iscsit_tpg_t, tpg_refcnt);
			if (iscsi_refcnt_impl(rc_addr) != DCMD_OK) {
				return (DCMD_ERR);
			}
			idc->u.child.idc_rc_audit = 0;
		}
	}

	if (idc->u.child.idc_portal) {
		if (idc->u.child.idc_tpg) {
			idc->idc_header = 1;
		}

		avl_addr = addr + offsetof(iscsit_tpg_t, tpg_portal_list);
		if (mdb_pwalk("avl", iscsi_portal_walk_cb, idc,
		    avl_addr) == -1) {
			mdb_warn("portal list walk failed");
			if (idc->u.child.idc_tpg) {
				(void) mdb_dec_indent(4);
			}
			return (DCMD_ERR);
		}
	}

	if (idc->u.child.idc_tpg) {
		(void) mdb_dec_indent(4);
		idc->idc_header = 0;
	}

	idc->u.child.idc_rc_audit = rc_audit;
	return (DCMD_OK);
}

static int
iscsi_portal_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	iscsit_portal_t	portal;
	char		portal_addr[PORTAL_STR_LEN];
	uintptr_t	rc_addr;

	if (idc->u.child.idc_portal) {
		/*
		 * Read iscsit_portal_t
		 */
		if (mdb_vread(&portal, sizeof (iscsit_portal_t), addr) !=
		    sizeof (iscsit_portal_t)) {
			return (DCMD_ERR);
		}

		/* Print portal data */
		if (idc->idc_header) {
			mdb_printf("%<u>%-?s %-?s %-30s%</u>\n",
			    "iscsit_portal_t", "idm_svc_t", "IP:Port");
			idc->idc_header = 0;
		}
		sa_to_str(&portal.portal_addr, portal_addr);
		mdb_printf("%?p %?p %s\n", addr, portal.portal_svc,
		    portal.portal_default ? "(Default)" : portal_addr);

		if (idc->u.child.idc_rc_audit) {
			(void) mdb_inc_indent(4);
			mdb_printf("Reference History(portal_refcnt):\n");
			rc_addr = addr + offsetof(iscsit_portal_t,
			    portal_refcnt);
			if (iscsi_refcnt_impl(rc_addr) != DCMD_OK) {
				return (DCMD_ERR);
			}
			(void) mdb_dec_indent(4);
		}
	}

	return (DCMD_OK);
}

static int
iscsi_sess_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	iscsit_sess_t	ist;
	iscsi_sess_t	ini_sess;
	uintptr_t	list_addr, states_addr, rc_addr;
	char		ini_name[80];
	char		tgt_name[80];
	int		verbose, states, rc_audit;

	if (idc->idc_ini) {
		if ((mdb_vread(&ini_sess, sizeof (iscsi_sess_t),
		    (uintptr_t)addr)) != sizeof (iscsi_sess_t)) {
			mdb_warn("Failed to read initiator session\n");
			return (DCMD_ERR);
		}
		if (iscsi_print_ini_sess(addr, &ini_sess, idc) != DCMD_OK) {
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	/*
	 * Read iscsit_sess_t
	 */
	if (mdb_vread(&ist, sizeof (iscsit_sess_t), addr) !=
	    sizeof (iscsit_sess_t)) {
		return (DCMD_ERR);
	}

	/*
	 * Brief output
	 *
	 * iscsit_sess_t pointer
	 * iscsit_sess_t.ist_state/iscsit_sess_t.ist_ffp_conn_count
	 * iscsit_sess_t.ist_tsih
	 * iscsit_sess_t.ist_initiator_name
	 */

	verbose = idc->idc_verbose;
	states = idc->u.child.idc_states;
	rc_audit = idc->u.child.idc_rc_audit;

	if (idc->u.child.idc_sess) {
		if (verbose) {
			/*
			 * Read initiator name if available
			 */
			if ((ist.ist_initiator_name == NULL) ||
			    (mdb_readstr(ini_name, sizeof (ini_name),
			    (uintptr_t)ist.ist_initiator_name) == -1)) {
				strcpy(ini_name, "N/A");
			}

			/*
			 * Read target name if available
			 */
			if ((ist.ist_target_name == NULL) ||
			    (mdb_readstr(tgt_name, sizeof (tgt_name),
			    (uintptr_t)ist.ist_target_name) == -1)) {
				strcpy(tgt_name, "N/A");
			}

			mdb_printf("Session %p\n", addr);
			mdb_printf("%16s: %d\n", "State",
			    ist.ist_state);
			mdb_printf("%16s: %d\n", "Last State",
			    ist.ist_last_state);
			mdb_printf("%16s: %d\n", "FFP Connections",
			    ist.ist_ffp_conn_count);
			mdb_printf("%16s: %02x%02x%02x%02x%02x%02x\n", "ISID",
			    ist.ist_isid[0], ist.ist_isid[1], ist.ist_isid[2],
			    ist.ist_isid[3], ist.ist_isid[4], ist.ist_isid[5]);
			mdb_printf("%16s: 0x%04x\n", "TSIH",
			    ist.ist_tsih);
			mdb_printf("%16s: %s\n", "Initiator IQN",
			    ini_name);
			mdb_printf("%16s: %s\n", "Target IQN",
			    tgt_name);
			mdb_printf("%16s: %08x\n", "ExpCmdSN",
			    ist.ist_expcmdsn);
			mdb_printf("%16s: %08x\n", "MaxCmdSN",
			    ist.ist_maxcmdsn);

			idc->idc_verbose = 0;
		} else {
			/* Print session data */
			if (idc->idc_header) {
				mdb_printf("%<u>%-?s %10s %-12s %-6s%</u>\n",
				    "iscsit_sess_t", "State/Conn", "ISID",
				    "TSIH");
			}
			mdb_printf("%?p  %4d/%-4d %02x%02x%02x%02x%02x%02x "
			    "0x%04x\n", addr,
			    ist.ist_state, ist.ist_ffp_conn_count,
			    ist.ist_isid[0], ist.ist_isid[1], ist.ist_isid[2],
			    ist.ist_isid[3], ist.ist_isid[4], ist.ist_isid[5],
			    ist.ist_tsih);
		}

		/*
		 * Indent for any child structures
		 */
		(void) mdb_inc_indent(4);
	}

	/*
	 * Print states if requested
	 */
	if (idc->u.child.idc_sess && states) {
		states_addr = addr + offsetof(iscsit_sess_t, ist_state_audit);

		mdb_printf("State History(ist_state_audit):\n");
		if (iscsi_sm_audit_impl(states_addr) != DCMD_OK)
			return (DCMD_ERR);

		/* Don't print state history for child objects */
		idc->u.child.idc_states = 0;
	}

	/*
	 * Print refcnt audit data if requested
	 */
	if (idc->u.child.idc_sess && rc_audit) {
		mdb_printf("Reference History(ist_refcnt):\n");
		rc_addr = addr +
		    offsetof(iscsit_sess_t, ist_refcnt);
		if (iscsi_refcnt_impl(rc_addr) != DCMD_OK)
			return (DCMD_ERR);

		/* Don't print audit data for child objects */
		idc->u.child.idc_rc_audit = 0;
	}

	/* Any child objects to walk? */
	if (idc->u.child.idc_conn || idc->u.child.idc_task ||
	    idc->u.child.idc_buffer) {
		/*
		 * If a session has been printed enable headers for
		 * any child structs.
		 */
		if (idc->u.child.idc_sess) {
			idc->idc_header = 1;
		}

		/* Walk conn list */
		list_addr = addr + offsetof(iscsit_sess_t, ist_conn_list);
		if (mdb_pwalk("list", iscsi_sess_conn_walk_cb, idc,
		    list_addr) == -1) {
			mdb_warn("session conn list walk failed");
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}

	/* If a session was handled decrease indent and reset header. */
	if (idc->u.child.idc_sess) {
		idc->idc_header = 0;
		mdb_dec_indent(4);
	}

	idc->idc_verbose = verbose;
	idc->u.child.idc_states = states;
	idc->u.child.idc_rc_audit = rc_audit;

	return (DCMD_OK);
}

static int
iscsi_print_ini_sess(uintptr_t addr, iscsi_sess_t *sess,
    iscsi_dcmd_ctrl_t *idc)
{

	int verbose, states;
	uintptr_t states_addr;

	verbose = idc->idc_verbose;
	states = idc->u.child.idc_states;


	if (idc->u.child.idc_sess) {
		if (!idc->idc_verbose) {
			if (idc->idc_header) {
				mdb_printf("%<u>%-?s %-4s  %-8s%</u>\n",
				    "iscsi_sess_t", "Type", "State");
			}
			mdb_printf("%-19p %-4d %-8d\n", addr,
			    sess->sess_type, sess->sess_state);
		} else {
			mdb_printf("Session %p\n", addr);
			mdb_printf("%22s: %d\n", "State",
			    sess->sess_state);
			mdb_printf("%22s: %d\n", "Last State",
			    sess->sess_prev_state);
			mdb_printf("%22s: %s\n", "Session Name",
			    sess->sess_name);
			mdb_printf("%22s: %s\n", "Alias",
			    sess->sess_alias);
			mdb_printf("%22s: %08x\n", "CmdSN",
			    sess->sess_cmdsn);
			mdb_printf("%22s: %08x\n", "ExpCmdSN",
			    sess->sess_expcmdsn);
			mdb_printf("%22s: %08x\n", "MaxCmdSN",
			    sess->sess_maxcmdsn);
			mdb_printf("%22s: %p\n", "Pending Queue Head",
			    sess->sess_queue_pending.head);
			mdb_printf("%22s: %p\n", "Completion Queue Head",
			    sess->sess_queue_completion.head);
			mdb_printf("%22s: %p\n", "Connnection List Head",
			    sess->sess_conn_list);

			idc->idc_verbose = 0;
		}

		/* Indent for any child structures */
		mdb_inc_indent(4);

		if (idc->u.child.idc_states) {
			states_addr = (uintptr_t)addr +
			    offsetof(iscsi_sess_t, sess_state_audit);

			mdb_printf("State History(sess_state_audit):\n");
			if (iscsi_sm_audit_impl(states_addr) != DCMD_OK) {
				(void) mdb_dec_indent(4);
				return (DCMD_ERR);
			}
			idc->u.child.idc_states = 0;
		}
	}

	if (idc->u.child.idc_lun && sess->sess_lun_list) {
		if (idc->u.child.idc_sess) {
			idc->idc_header = 1;
		}

		if (mdb_pwalk("iscsi_ini_lun", iscsi_ini_lun_walk_cb, idc,
		    (uintptr_t)sess->sess_lun_list) == -1) {
			mdb_warn("iscsi_ini_lun walk failed");
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}


	/* If requested print the cmds in the session queue */
	if (idc->u.child.idc_cmd) {

		/* If any other structs printed enable header */
		if (idc->u.child.idc_sess || idc->u.child.idc_lun) {
			idc->idc_header = 1;
		}

		if (sess->sess_queue_pending.head) {
			if (mdb_pwalk("iscsi_ini_cmd", iscsi_ini_cmd_walk_cb,
			    idc, (uintptr_t)sess->sess_queue_pending.head)
			    == -1) {
				mdb_warn("list walk failed for iscsi cmds");
			}
		}
		if (sess->sess_queue_completion.head) {
			if (mdb_pwalk("iscsi_ini_cmd", iscsi_ini_cmd_walk_cb,
			    idc, (uintptr_t)sess->sess_queue_completion.head)
			    == -1) {
				mdb_warn("list walk failed for iscsi cmds");
			}
		}
	}

	/* If connections or cmds requested walk the connections */
	if (idc->u.child.idc_conn || idc->u.child.idc_cmd) {
		/*
		 * If idc_conn is not set don't enable header or the
		 * commands may get extraneous headers.
		 */
		if (idc->u.child.idc_conn) {
			idc->idc_header = 1;
		}
		if (mdb_pwalk("iscsi_ini_conn", iscsi_ini_conn_walk_cb, idc,
		    (uintptr_t)sess->sess_conn_list) == -1) {
			mdb_warn("iscsi_ini_conn walk failed");
			return (DCMD_ERR);
		}
	}

	/* If sessions were handled decrease indent and reset header */
	if (idc->u.child.idc_sess) {
		idc->idc_header = 0;
		mdb_dec_indent(4);
	}

	idc->u.child.idc_states = states;
	idc->idc_verbose = verbose;
	return (DCMD_OK);
}


static int
iscsi_conn_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	uintptr_t	idm_global_addr, states_addr, rc_addr;
	uintptr_t	task_addr, task_ptr;
	GElf_Sym	sym;
	idm_task_t	idt;
	idm_conn_t	ic;
	iscsit_conn_t	ict;
	iscsi_conn_t	ini_conn;
	char		*conn_type;
	int		task_idx;
	char		laddr[PORTAL_STR_LEN];
	char		raddr[PORTAL_STR_LEN];
	int		verbose, states, rc_audit;

	/*
	 * Get pointer to task table
	 */

	if (mdb_lookup_by_name("idm", &sym) == -1) {
		mdb_warn("failed to find symbol 'idm'");
		return (DCMD_ERR);
	}

	idm_global_addr = (uintptr_t)sym.st_value;

	if (mdb_vread(&task_ptr, sizeof (uintptr_t),
	    idm_global_addr + offsetof(idm_global_t, idm_taskid_table)) !=
	    sizeof (uintptr_t)) {
		mdb_warn("Failed to read address of task table");
		return (DCMD_ERR);
	}

	/*
	 * Read idm_conn_t
	 */
	if (mdb_vread(&ic, sizeof (idm_conn_t), addr) != sizeof (idm_conn_t)) {
		return (DCMD_ERR);
	}

	/*
	 * If filter bits are set to only print targets or only initiators
	 * skip entries of the other type.
	 */
	if (!(idc->idc_ini && idc->idc_tgt) &&
	    ((idc->idc_ini && (ic.ic_conn_type != CONN_TYPE_INI)) ||
	    (idc->idc_tgt && (ic.ic_conn_type != CONN_TYPE_TGT)))) {
		return (DCMD_OK);
	}


	conn_type = (ic.ic_conn_type == CONN_TYPE_INI) ? "Ini" :
	    (ic.ic_conn_type == CONN_TYPE_TGT) ? "Tgt" : "Unk";

	/*
	 * Brief output
	 *
	 * idm_conn_t pointer
	 * idm_conn_t.ic_conn_type
	 * idm_conn_t.ic_statet+idm_conn_t.ic_ffp
	 */

	verbose = idc->idc_verbose;
	states = idc->u.child.idc_states;
	rc_audit = idc->u.child.idc_rc_audit;

	/*
	 * If targets(-T) and/or initiators (-I) are specifically requested,
	 * fetch the iscsit_conn_t and/or iscsi_conn_t struct as a sanity
	 * check and for use below.
	 */
	if (idc->idc_tgt && IDM_CONN_ISTGT(&ic)) {
		if (mdb_vread(&ict, sizeof (iscsit_conn_t),
		    (uintptr_t)ic.ic_handle) !=
		    sizeof (iscsit_conn_t)) {
			mdb_printf("Failed to read target connection "
			    "handle data\n");
			return (DCMD_ERR);
		}
	}

	if (idc->idc_ini && IDM_CONN_ISINI(&ic)) {
		if (mdb_vread(&ini_conn, sizeof (iscsi_conn_t),
		    (uintptr_t)ic.ic_handle) !=
		    sizeof (iscsi_conn_t)) {
			mdb_printf("Failed to read initiator "
			    "connection handle data\n");
			return (DCMD_ERR);
		}
	}

	if (idc->u.child.idc_conn) {
		if (idc->idc_verbose) {
			mdb_printf("IDM Conn %p\n", addr);
			if (ic.ic_conn_type == CONN_TYPE_TGT) {
				iscsi_print_iscsit_conn_data(&ic);
			} else {
				iscsi_print_ini_conn_data(&ic);
			}
			idc->idc_verbose = 0;
		} else {
			/* Print connection data */
			if (idc->idc_header) {
				mdb_printf("%<u>%-?s %-6s %-10s %12s%</u>\n",
				    "idm_conn_t", "Type", "Transport",
				    "State/FFP");
			}
			mdb_printf("%?p %-6s %-10s %6d/%-6d\n", addr, conn_type,
			    (ic.ic_transport_type ==
			    IDM_TRANSPORT_TYPE_ISER) ? "ISER_IB" :
			    (ic.ic_transport_type ==
			    IDM_TRANSPORT_TYPE_SOCKETS) ? "SOCKETS" :
			    "N/A",
			    ic.ic_state, ic.ic_ffp);
			if (idc->u.child.idc_print_ip) {
				sa_to_str(&ic.ic_laddr, laddr);
				sa_to_str(&ic.ic_raddr, raddr);
				mdb_printf("  L%s  R%s\n",
				    laddr, raddr);
			}
		}

		/* Indent for any child structs */
		mdb_inc_indent(4);
	}

	/*
	 * Print states if requested
	 */
	if (idc->u.child.idc_conn && states) {
		states_addr = addr + offsetof(idm_conn_t, ic_state_audit);

		mdb_printf("State History(ic_state_audit):\n");
		if (iscsi_sm_audit_impl(states_addr) != DCMD_OK)
			return (DCMD_ERR);

		/*
		 * If targets are specifically requested show the
		 * state audit for the target specific connection struct
		 */
		if (idc->idc_tgt && IDM_CONN_ISTGT(&ic)) {
			states_addr = (uintptr_t)ic.ic_handle +
			    offsetof(iscsit_conn_t, ict_login_sm) +
			    offsetof(iscsit_conn_login_t, icl_state_audit);

			mdb_printf("State History(icl_state_audit):\n");
			if (iscsi_sm_audit_impl(states_addr) != DCMD_OK) {
				return (DCMD_ERR);
			}
		}

		/*
		 * If initiators are specifically requested show the
		 * state audit for the initiator specific connection struct
		 */
		if (idc->idc_ini && IDM_CONN_ISINI(&ic)) {
			states_addr = (uintptr_t)ic.ic_handle +
			    offsetof(iscsi_conn_t, conn_state_audit);

			mdb_printf("State History(iscsi_conn_t "
			    "conn_state_audit):\n");
			if (iscsi_sm_audit_impl(states_addr) != DCMD_OK) {
				return (DCMD_ERR);
			}
		}

		/* Don't print state history for child objects */
		idc->u.child.idc_states = 0;
	}

	/*
	 * Print refcnt audit data for the connection struct if requested.
	 */
	if (idc->u.child.idc_conn && rc_audit) {
		mdb_printf("Reference History(ic_refcnt):\n");
		rc_addr = addr + offsetof(idm_conn_t, ic_refcnt);
		if (iscsi_refcnt_impl(rc_addr) != DCMD_OK)
			return (DCMD_ERR);

		/*
		 * If targets are specifically requested show the
		 * Refcounts for the target specific connection struct
		 */
		if (idc->idc_tgt && IDM_CONN_ISTGT(&ic)) {
			mdb_printf("Reference History(ict_refcnt):\n");
			rc_addr = (uintptr_t)ic.ic_handle +
			    offsetof(iscsit_conn_t, ict_refcnt);
			if (iscsi_refcnt_impl(rc_addr) != DCMD_OK) {
				return (DCMD_ERR);
			}

			mdb_printf("Reference History(ict_dispatch_refcnt):\n");
			rc_addr = (uintptr_t)ic.ic_handle +
			    offsetof(iscsit_conn_t, ict_dispatch_refcnt);
			if (iscsi_refcnt_impl(rc_addr) != DCMD_OK) {
				return (DCMD_ERR);
			}
		}

		/* Don't print audit data for child objects */
		idc->u.child.idc_rc_audit = 0;
	}

	task_idx = 0;

	if (idc->u.child.idc_task || idc->u.child.idc_buffer) {

		if (idc->u.child.idc_conn) {
			idc->idc_header = 1;
		}

		while (task_idx < IDM_TASKIDS_MAX) {
			/*
			 * Read the next idm_task_t
			 */
			if (mdb_vread(&task_addr, sizeof (uintptr_t),
			    task_ptr) != sizeof (uintptr_t)) {
				mdb_warn("Failed to read task pointer");
				return (DCMD_ERR);
			}

			if (task_addr == NULL) {
				task_ptr += sizeof (uintptr_t);
				task_idx++;
				continue;
			}

			if (mdb_vread(&idt, sizeof (idm_task_t), task_addr)
			    != sizeof (idm_task_t)) {
				mdb_warn("Failed to read task pointer");
				return (DCMD_ERR);
			}

			if (((uintptr_t)idt.idt_ic == addr) &&
			    (idt.idt_state != TASK_IDLE)) {
				if (iscsi_i_task_impl(&idt, task_addr, idc)
				    == -1) {
					mdb_warn("Failed to walk connection "
					    "task tree");
					return (DCMD_ERR);
				}
			}

			task_ptr += sizeof (uintptr_t);
			task_idx++;
		}
	}

	if (idc->idc_ini && IDM_CONN_ISINI(&ic) && idc->u.child.idc_cmd) {
		if (idc->u.child.idc_conn || idc->u.child.idc_task) {
			idc->idc_header = 1;
		}
		if (ini_conn.conn_queue_active.head &&
		    (mdb_pwalk("iscsi_ini_cmd", iscsi_ini_cmd_walk_cb, idc,
		    (uintptr_t)ini_conn.conn_queue_active.head) == -1)) {
			mdb_warn("list walk failed for iscsi cmds");
		}
		if (ini_conn.conn_queue_idm_aborting.head &&
		    (mdb_pwalk("iscsi_ini_cmd", iscsi_ini_cmd_walk_cb, idc,
		    (uintptr_t)ini_conn.conn_queue_idm_aborting.head) == -1)) {
			mdb_warn("list walk failed for iscsi cmds");
		}
	}

	/*
	 * If connection information was handled unset header and
	 * decrease indent
	 */
	if (idc->u.child.idc_conn) {
		idc->idc_header = 0;
		mdb_dec_indent(4);
	}

	idc->idc_verbose = verbose;
	idc->u.child.idc_states = states;
	idc->u.child.idc_rc_audit = rc_audit;

	return (DCMD_OK);
}

static int
iscsi_svc_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	idm_svc_t	svc;
	iser_svc_t	iser_svc;
	uintptr_t	rc_addr;

	if (mdb_vread(&svc, sizeof (idm_svc_t), addr) !=
	    sizeof (idm_svc_t)) {
		return (DCMD_ERR);
	}

	if (idc->u.child.idc_svc) {
		if (idc->idc_verbose) {
			mdb_printf("Service %p\n", addr);
			mdb_printf("%20s: %d\n", "Port",
			    svc.is_svc_req.sr_port);
			mdb_printf("%20s: %d\n", "Online",
			    svc.is_online);
			mdb_printf("%20s: %p\n", "Socket Service",
			    svc.is_so_svc);
			mdb_printf("%20s: %p\n", "iSER Service",
			    svc.is_iser_svc);
		} else {
			if (idc->idc_header) {
				mdb_printf("%<u>%-?s %-8s %-8s%</u>\n",
				    "idm_svc_t", "Port", "Online");
				idc->idc_header = 0;
			}

			mdb_printf("%?p %-8d %-8d\n", addr,
			    svc.is_svc_req.sr_port, svc.is_online);
		}

		if (idc->u.child.idc_rc_audit) {
			(void) mdb_inc_indent(4);
			mdb_printf("Reference History(is_refcnt):\n");
			rc_addr = addr + offsetof(idm_svc_t, is_refcnt);
			if (iscsi_refcnt_impl(rc_addr) != DCMD_OK) {
				(void) mdb_dec_indent(4);
				return (DCMD_ERR);
			}

			if (svc.is_iser_svc != NULL) {
				mdb_printf("Reference History"
				    "(iser_svc is_refcnt):\n");

				/* Sanity check the iser svc struct */
				if (mdb_vread(&iser_svc, sizeof (iser_svc_t),
				    (uintptr_t)svc.is_iser_svc) !=
				    sizeof (iser_svc_t)) {
					return (DCMD_ERR);
				}

				rc_addr = (uintptr_t)svc.is_iser_svc +
				    offsetof(iser_svc_t, is_refcnt);

				if (iscsi_refcnt_impl(rc_addr) != DCMD_OK) {
					return (DCMD_ERR);
				}
			}
			(void) mdb_dec_indent(4);
		}
	}
	return (DCMD_OK);
}

static void
iscsi_print_iscsit_conn_data(idm_conn_t *ic)
{
	iscsit_conn_t	ict;
	char		*csg;
	char		*nsg;

	iscsi_print_idm_conn_data(ic);

	if (mdb_vread(&ict, sizeof (iscsit_conn_t),
	    (uintptr_t)ic->ic_handle) != sizeof (iscsit_conn_t)) {
		mdb_printf("**Failed to read conn private data\n");
		return;
	}

	mdb_printf("%20s: %p\n", "iSCSIT TGT Conn",
	    ic->ic_handle);

	if (ict.ict_login_sm.icl_login_state != ILS_LOGIN_DONE) {
		switch (ict.ict_login_sm.icl_login_csg) {
		case ISCSI_SECURITY_NEGOTIATION_STAGE:
			csg = "Security";
			break;
		case ISCSI_OP_PARMS_NEGOTIATION_STAGE:
			csg = "Operational";
			break;
		case ISCSI_FULL_FEATURE_PHASE:
			csg = "FFP";
			break;
		default:
			csg = "Unknown";
		}
		switch (ict.ict_login_sm.icl_login_nsg) {
		case ISCSI_SECURITY_NEGOTIATION_STAGE:
			nsg = "Security";
			break;
		case ISCSI_OP_PARMS_NEGOTIATION_STAGE:
			nsg = "Operational";
			break;
		case ISCSI_FULL_FEATURE_PHASE:
			nsg = "FFP";
			break;
		default:
			nsg = "Unknown";
		}
		mdb_printf("%20s: %d\n", "Login State",
		    ict.ict_login_sm.icl_login_state);
		mdb_printf("%20s: %d\n", "Login Last State",
		    ict.ict_login_sm.icl_login_last_state);
		mdb_printf("%20s: %s\n", "CSG", csg);
		mdb_printf("%20s: %s\n", "NSG", nsg);
		mdb_printf("%20s: %d\n", "Transit",
		    ict.ict_login_sm.icl_login_transit >> 7);
		mdb_printf("%20s: %p\n", "Request nvlist",
		    ict.ict_login_sm.icl_request_nvlist);
		mdb_printf("%20s: %p\n", "Response nvlist",
		    ict.ict_login_sm.icl_response_nvlist);
		mdb_printf("%20s: %p\n", "Negotiated nvlist",
		    ict.ict_login_sm.icl_negotiated_values);
		if (ict.ict_login_sm.icl_login_state == ILS_LOGIN_ERROR) {
			mdb_printf("%20s: 0x%02x\n", "Error Class",
			    ict.ict_login_sm.icl_login_resp_err_class);
			mdb_printf("%20s: 0x%02x\n", "Error Detail",
			    ict.ict_login_sm.icl_login_resp_err_detail);
		}
	}
	mdb_printf("%20s: 0x%04x\n", "CID", ict.ict_cid);
	mdb_printf("%20s: 0x%08x\n", "StatSN", ict.ict_statsn);
}

static void
iscsi_print_ini_conn_data(idm_conn_t *ic)
{
	iscsi_conn_t	ini_conn;

	iscsi_print_idm_conn_data(ic);

	if (mdb_vread(&ini_conn, sizeof (iscsi_conn_t),
	    (uintptr_t)ic->ic_handle) != sizeof (iscsi_conn_t)) {
		mdb_printf("Failed to read conn private data\n");
		return;
	}

	mdb_printf("%20s: %p\n", "iSCSI Ini Conn",
	    ic->ic_handle);
	mdb_printf("%20s: %p\n", "Parent Session",
	    ini_conn.conn_sess);
	mdb_printf("%20s: %d\n", "Conn State",
	    ini_conn.conn_state);
	mdb_printf("%20s: %d\n", "Last Conn State",
	    ini_conn.conn_prev_state);

	mdb_printf("%20s: %d\n", "Login Stage",
	    ini_conn.conn_current_stage);
	mdb_printf("%20s: %d\n", "Next Login Stage",
	    ini_conn.conn_next_stage);

	mdb_printf("%20s: 0x%08x\n", "Expected StatSN",
	    ini_conn.conn_expstatsn);
	mdb_printf("%20s: %p\n", "Active Queue Head",
	    ini_conn.conn_queue_active.head);
	mdb_printf("%20s: %d\n", "Abort Queue Head",
	    ini_conn.conn_queue_idm_aborting.head);
}

static void
iscsi_print_idm_conn_data(idm_conn_t *ic)
{
	char		laddr[PORTAL_STR_LEN];
	char		raddr[PORTAL_STR_LEN];

	sa_to_str(&ic->ic_laddr, laddr);
	sa_to_str(&ic->ic_raddr, raddr);

	mdb_printf("%20s: %s\n", "Conn Type",
	    ((ic->ic_conn_type == CONN_TYPE_TGT) ? "Target" :
	    ((ic->ic_conn_type == CONN_TYPE_INI) ? "Initiator" :
	    "Unknown")));
	if (ic->ic_conn_type == CONN_TYPE_TGT) {
		mdb_printf("%20s: %p\n", "Svc. Binding",
		    ic->ic_svc_binding);
	}
	mdb_printf("%20s: %s\n", "Transport",
	    (ic->ic_transport_type == IDM_TRANSPORT_TYPE_ISER) ? "ISER_IB" :
	    (ic->ic_transport_type == IDM_TRANSPORT_TYPE_SOCKETS) ? "SOCKETS" :
	    "N/A");

	mdb_printf("%20s: %s\n", "Local IP", laddr);
	mdb_printf("%20s: %s\n", "Remote IP", raddr);
	mdb_printf("%20s: %d\n", "State",
	    ic->ic_state);
	mdb_printf("%20s: %d\n", "Last State",
	    ic->ic_last_state);
	mdb_printf("%20s: %d %s\n", "Refcount",
	    ic->ic_refcnt.ir_refcnt,
	    (ic->ic_refcnt.ir_waiting == REF_NOWAIT) ? "" :
	    ((ic->ic_refcnt.ir_waiting == REF_WAIT_SYNC) ? "REF_WAIT_SYNC" :
	    ((ic->ic_refcnt.ir_waiting == REF_WAIT_ASYNC) ? "REF_WAIT_ASYNC" :
	    "UNKNOWN")));
}

static int
iscsi_i_task_impl(idm_task_t *idt, uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	uintptr_t	list_addr, rc_addr;
	idm_conn_type_t	conn_type;
	int		verbose, states, rc_audit;

	conn_type = idm_conn_type((uintptr_t)idt->idt_ic);

	verbose = idc->idc_verbose;
	states = idc->u.child.idc_states;
	rc_audit = idc->u.child.idc_rc_audit;

	if (idc->u.child.idc_task) {
		if (verbose) {
			mdb_printf("Task %p\n", addr);
			(void) mdb_inc_indent(2);
			if (conn_type == CONN_TYPE_TGT) {
				iscsi_print_iscsit_task_data(idt);
			}
			(void) mdb_dec_indent(2);
		} else {
			/* Print task data */
			if (idc->idc_header) {
				mdb_printf(
				    "%<u>%-?s %-16s %-4s %-8s %-8s%</u>\n",
				    "Tasks:", "State", "Ref",
				    (conn_type == CONN_TYPE_TGT ? "TTT" :
				    (conn_type == CONN_TYPE_INI ? "ITT" :
				    "TT")), "Handle");
			}
			mdb_printf("%?p %-16s %04x %08x %08x\n", addr,
			    idm_ts_name[idt->idt_state],
			    idt->idt_refcnt.ir_refcnt,
			    idt->idt_tt, idt->idt_client_handle);
		}
	}
	idc->idc_header = 0;
	idc->idc_verbose = 0;

	/*
	 * Print states if requested
	 */
#if 0
	if (states) {
		states_addr = addr + offsetof(idm_task_t, idt_state_audit);

		(void) mdb_inc_indent(4);
		mdb_printf("State History(idt_state_audit):\n");
		if (iscsi_sm_audit_impl(states_addr) != DCMD_OK)
			return (DCMD_ERR);

		/* Don't print state history for child objects */
		idc->u.child.idc_states = 0;
		(void) mdb_dec_indent(4);
	}
#endif

	/*
	 * Print refcnt audit data if requested
	 */
	if (rc_audit) {
		(void) mdb_inc_indent(4);
		mdb_printf("Reference History(idt_refcnt):\n");
		rc_addr = addr +
		    offsetof(idm_task_t, idt_refcnt);
		if (iscsi_refcnt_impl(rc_addr) != DCMD_OK)
			return (DCMD_ERR);

		/* Don't print audit data for child objects */
		idc->u.child.idc_rc_audit = 0;
		(void) mdb_dec_indent(4);
	}


	/*
	 * Buffers are leaf objects and always get headers so the
	 * user can discern between in and out buffers.
	 */
	if (idc->u.child.idc_buffer) {
		/* Walk in buffer list */
		(void) mdb_inc_indent(2);
		mdb_printf("In buffers:\n");
		idc->idc_header = 1;
		(void) mdb_inc_indent(2);
		list_addr = addr + offsetof(idm_task_t, idt_inbufv);
		if (mdb_pwalk("list", iscsi_buffer_walk_cb, idc, list_addr) ==
		    -1) {
			mdb_warn("list walk failed for task in buffers");
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
		(void) mdb_dec_indent(2);
		/* Walk out buffer list */
		mdb_printf("Out buffers:\n");
		idc->idc_header = 1;
		(void) mdb_inc_indent(2);
		list_addr = addr + offsetof(idm_task_t, idt_outbufv);
		if (mdb_pwalk("list", iscsi_buffer_walk_cb, idc, list_addr) ==
		    -1) {
			mdb_warn("list walk failed for task out buffers\n");
			(void) mdb_dec_indent(2);
			return (DCMD_ERR);
		}
		(void) mdb_dec_indent(4);
	}

	idc->idc_verbose = verbose;
	idc->u.child.idc_states = states;
	idc->u.child.idc_rc_audit = rc_audit;

	return (DCMD_OK);
}

static int
iscsi_task_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	idm_task_t	idt;

	/*
	 * Read idm_conn_t
	 */
	if (mdb_vread(&idt, sizeof (idm_task_t), addr) != sizeof (idm_task_t)) {
		return (DCMD_ERR);
	}

	return (iscsi_i_task_impl(&idt, addr, idc));
}

#define	ISCSI_CDB_INDENT	16

static void
iscsi_print_iscsit_task_data(idm_task_t *idt)
{
	iscsit_task_t	itask;
	boolean_t	good_scsi_task = B_TRUE;
	scsi_task_t	scsi_task;

	if (mdb_vread(&itask, sizeof (iscsit_task_t),
	    (uintptr_t)idt->idt_private) != sizeof (iscsit_task_t)) {
		mdb_printf("**Failed to read idt_private data\n");
		return;
	}

	if (mdb_vread(&scsi_task, sizeof (scsi_task_t),
	    (uintptr_t)itask.it_stmf_task) != sizeof (scsi_task_t)) {
		good_scsi_task = B_FALSE;
	}

	mdb_printf("%20s: %s(%d)\n", "State",
	    idt->idt_state > TASK_MAX_STATE ?
	    "UNKNOWN" : idm_ts_name[idt->idt_state],
	    idt->idt_state);
	mdb_printf("%20s: %d/%d\n", "STMF abort/IDM aborted",
	    itask.it_stmf_abort, itask.it_aborted);
	mdb_printf("%20s: %p/%p/%p%s\n",
	    "iscsit/STMF/LU", idt->idt_private,
	    itask.it_stmf_task, good_scsi_task ? scsi_task.task_lu_private : 0,
	    good_scsi_task ? "" : "**");
	if (good_scsi_task) {
		mdb_printf("%20s: %08x/%08x\n", "ITT/TTT",
		    itask.it_itt, itask.it_ttt);
		mdb_printf("%20s: %08x\n", "CmdSN",
		    itask.it_cmdsn);
		mdb_printf("%20s: %02x %02x %02x %02x %02x %02x %02x %02x\n",
		    "LU number",
		    scsi_task.task_lun_no[0], scsi_task.task_lun_no[1],
		    scsi_task.task_lun_no[2], scsi_task.task_lun_no[3],
		    scsi_task.task_lun_no[4], scsi_task.task_lun_no[5],
		    scsi_task.task_lun_no[6], scsi_task.task_lun_no[7]);
		mdb_printf("     CDB (%d bytes):\n",
		    scsi_task.task_cdb_length);
		(void) mdb_inc_indent(ISCSI_CDB_INDENT);
		if (mdb_dumpptr((uintptr_t)scsi_task.task_cdb,
		    scsi_task.task_cdb_length,
		    MDB_DUMP_RELATIVE | MDB_DUMP_TRIM |
		    MDB_DUMP_GROUP(1),
		    (mdb_dumpptr_cb_t)mdb_vread, NULL)) {
			mdb_printf("** Invalid CDB addr (%p)\n",
			    scsi_task.task_cdb);
		}
		(void) mdb_dec_indent(ISCSI_CDB_INDENT);
		mdb_printf("%20s: %d/%d\n", "STMF cur/max bufs",
		    scsi_task.task_cur_nbufs,
		    scsi_task.task_max_nbufs);
		mdb_printf("%20s: 0x%08x/0x%08x/0x%08x\n", "Bytes Exp/Cmd/Done",
		    scsi_task.task_expected_xfer_length,
		    scsi_task.task_cmd_xfer_length,
		    scsi_task.task_nbytes_transferred);
		mdb_printf("%20s: 0x%x/0x%x\n", "TX-ini start/done",
		    idt->idt_tx_to_ini_start,
		    idt->idt_tx_to_ini_done);
		mdb_printf("%20s: 0x%x/0x%x\n", "RX-ini start/done",
		    idt->idt_rx_from_ini_start,
		    idt->idt_rx_from_ini_done);
	}
}

static int
iscsi_print_ini_lun(uintptr_t addr, const iscsi_lun_t *lun,
    iscsi_dcmd_ctrl_t *idc)
{

	if (idc->u.child.idc_lun) {
		if (idc->idc_header) {
			mdb_printf("%<u>%-?s %-5s %-10s%</u>\n",
			    "iscsi_lun_t", "State", "Lun Number");
			idc->idc_header = 0;
		}
		mdb_printf("%?p %-5d %-10d\n", addr,
		    lun->lun_state, lun->lun_num);
	}
	return (DCMD_OK);
}

static int
iscsi_print_ini_cmd(uintptr_t addr, const iscsi_cmd_t *cmd,
    iscsi_dcmd_ctrl_t *idc)
{

	uintptr_t states_addr;

	if (idc->idc_header) {
		mdb_printf("%<u>%-?s %-?s %4s %6s/%-6s %-?s%</u>\n",
		    "iscsi_cmd_t", "idm_task_t", "Type",
		    "State", "Prev", "iscsi_lun_t");
		idc->idc_header = 0;
	}

	mdb_printf("%?p %?p %4d %6d/%-6d %?p\n",
	    addr, cmd->cmd_itp, cmd->cmd_type, cmd->cmd_state,
	    cmd->cmd_prev_state, cmd->cmd_lun);

	/*
	 * Print states if requested
	 */
	if (idc->u.child.idc_states) {
		states_addr = addr + offsetof(iscsi_cmd_t, cmd_state_audit);

		(void) mdb_inc_indent(4);
		mdb_printf("State History(cmd_state_audit):\n");
		if (iscsi_sm_audit_impl(states_addr) != DCMD_OK)
			return (DCMD_ERR);
		idc->u.child.idc_states = 0;
		(void) mdb_dec_indent(4);
	}
	return (DCMD_OK);
}

static int
iscsi_buffer_impl(uintptr_t addr, iscsi_dcmd_ctrl_t *idc)
{
	idm_buf_t	idb;

	/*
	 * Read idm_buf_t
	 */
	if (mdb_vread(&idb, sizeof (idm_buf_t), addr) != sizeof (idm_buf_t)) {
		return (DCMD_ERR);
	}


	if (idc->idc_header) {
		mdb_printf("%<u>%-?s %?s/%-8s %8s %8s %8s%</u>\n",
		    "idm_buf_t", "Mem Rgn", "Length",
		    "Rel Off", "Xfer Len", "Exp. Off");
		idc->idc_header = 0;
	}

	/* Print buffer data */
	mdb_printf("%?p %?p/%08x %8x %8x %08x\n", addr,
	    idb.idb_buf, idb.idb_buflen,
	    idb.idb_bufoffset, idb.idb_xfer_len,
	    idb.idb_exp_offset);


	/* Buffers are leaf objects */

	return (DCMD_OK);
}

static int
iscsi_refcnt_impl(uintptr_t addr)
{
	idm_refcnt_t		refcnt;
	refcnt_audit_buf_t	*anb;
	int			ctr;

	/*
	 * Print refcnt info
	 */
	if (mdb_vread(&refcnt, sizeof (idm_refcnt_t), addr) !=
	    sizeof (idm_refcnt_t)) {
		mdb_warn("read refcnt failed");
		return (DCMD_ERR);
	}

	anb = &refcnt.ir_audit_buf;

	ctr = anb->anb_max_index + 1;
	anb->anb_index--;
	anb->anb_index &= anb->anb_max_index;

	while (ctr) {
		refcnt_audit_record_t	*anr;

		anr = anb->anb_records + anb->anb_index;

		if (anr->anr_depth) {
			char c[MDB_SYM_NAMLEN];
			GElf_Sym sym;
			int i;

			mdb_printf("\nRefCnt: %u\t", anr->anr_refcnt);

			for (i = 0; i < anr->anr_depth; i++) {
				if (mdb_lookup_by_addr(anr->anr_stack[i],
				    MDB_SYM_FUZZY, c, sizeof (c),
				    &sym) == -1) {
					continue;
				}
				mdb_printf("%s+0x%1x", c,
				    anr->anr_stack[i] -
				    (uintptr_t)sym.st_value);
				++i;
				break;
			}

			while (i < anr->anr_depth) {
				if (mdb_lookup_by_addr(anr->anr_stack[i],
				    MDB_SYM_FUZZY, c, sizeof (c),
				    &sym) == -1) {
					++i;
					continue;
				}
				mdb_printf("\n\t\t%s+0x%1x", c,
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

	return (DCMD_OK);
}

static int
iscsi_sm_audit_impl(uintptr_t addr)
{
	sm_audit_buf_t		audit_buf;
	int			ctr;
	const char		*event_name;
	const char		*state_name;
	const char		*new_state_name;
	char			ts_string[40];
	/*
	 * Print refcnt info
	 */
	if (mdb_vread(&audit_buf, sizeof (sm_audit_buf_t), addr) !=
	    sizeof (sm_audit_buf_t)) {
		mdb_warn("failed to read audit buf");
		return (DCMD_ERR);
	}

	ctr = audit_buf.sab_max_index + 1;
	audit_buf.sab_index++;
	audit_buf.sab_index &= audit_buf.sab_max_index;

	while (ctr) {
		sm_audit_record_t	*sar;

		sar = audit_buf.sab_records + audit_buf.sab_index;

		iscsi_format_timestamp(ts_string, 40, &sar->sar_timestamp);

		switch (sar->sar_type) {
		case SAR_STATE_EVENT:
			switch (sar->sar_sm_type) {
			case SAS_IDM_CONN:
				state_name =
				    iscsi_idm_conn_state(sar->sar_state);
				event_name =
				    iscsi_idm_conn_event(sar->sar_event);
				break;
			case SAS_ISCSIT_TGT:
				state_name =
				    iscsi_iscsit_tgt_state(sar->sar_state);
				event_name =
				    iscsi_iscsit_tgt_event(sar->sar_event);
				break;
			case SAS_ISCSIT_SESS:
				state_name =
				    iscsi_iscsit_sess_state(sar->sar_state);
				event_name =
				    iscsi_iscsit_sess_event(sar->sar_event);
				break;
			case SAS_ISCSIT_LOGIN:
				state_name =
				    iscsi_iscsit_login_state(sar->sar_state);
				event_name =
				    iscsi_iscsit_login_event(sar->sar_event);
				break;
			case SAS_ISCSI_CMD:
				state_name =
				    iscsi_iscsi_cmd_state(sar->sar_state);
				event_name=
				    iscsi_iscsi_cmd_event(sar->sar_event);
				break;
			case SAS_ISCSI_SESS:
				state_name =
				    iscsi_iscsi_sess_state(sar->sar_state);
				event_name=
				    iscsi_iscsi_sess_event(sar->sar_event);
				break;
			case SAS_ISCSI_CONN:
				state_name =
				    iscsi_iscsi_conn_state(sar->sar_state);
				event_name=
				    iscsi_iscsi_conn_event(sar->sar_event);
				break;
			default:
				state_name = event_name = "N/A";
				break;
			}
			mdb_printf("%s|%s (%d)\n\t%9s %s (%d) %p\n",
			    ts_string, state_name, sar->sar_state,
			    "Event", event_name,
			    sar->sar_event, sar->sar_event_info);

			break;
		case SAR_STATE_CHANGE:
			switch (sar->sar_sm_type) {
			case SAS_IDM_CONN:
				state_name =
				    iscsi_idm_conn_state(sar->sar_state);
				new_state_name =
				    iscsi_idm_conn_state(sar->sar_new_state);
				break;
			case SAS_IDM_TASK:
				state_name =
				    iscsi_idm_task_state(sar->sar_state);
				new_state_name =
				    iscsi_idm_task_state(sar->sar_new_state);
				break;
			case SAS_ISCSIT_TGT:
				state_name =
				    iscsi_iscsit_tgt_state(sar->sar_state);
				new_state_name =
				    iscsi_iscsit_tgt_state(sar->sar_new_state);
				break;
			case SAS_ISCSIT_SESS:
				state_name =
				    iscsi_iscsit_sess_state(sar->sar_state);
				new_state_name =
				    iscsi_iscsit_sess_state(sar->sar_new_state);
				break;
			case SAS_ISCSIT_LOGIN:
				state_name =
				    iscsi_iscsit_login_state(sar->sar_state);
				new_state_name =
				    iscsi_iscsit_login_state(
				    sar->sar_new_state);
				break;
			case SAS_ISCSI_CMD:
				state_name =
				    iscsi_iscsi_cmd_state(sar->sar_state);
				new_state_name=
				    iscsi_iscsi_cmd_state(sar->sar_new_state);
				break;
			case SAS_ISCSI_SESS:
				state_name =
				    iscsi_iscsi_sess_state(sar->sar_state);
				new_state_name=
				    iscsi_iscsi_sess_state(sar->sar_new_state);
				break;
			case SAS_ISCSI_CONN:
				state_name =
				    iscsi_iscsi_conn_state(sar->sar_state);
				new_state_name=
				    iscsi_iscsi_conn_state(sar->sar_new_state);
				break;
			case SAS_ISCSI_LOGIN:
				state_name =
				    iscsi_iscsi_login_state(sar->sar_state);
				new_state_name=
				    iscsi_iscsi_login_state(sar->sar_new_state);
				break;
			default:
				state_name = new_state_name = "N/A";
				break;
			}
			mdb_printf("%s|%s (%d)\n\t%9s %s (%d)\n",
			    ts_string, state_name, sar->sar_state,
			    "New State", new_state_name, sar->sar_new_state);

			break;
		default:
			break;
		}

		audit_buf.sab_index++;
		audit_buf.sab_index &= audit_buf.sab_max_index;
		ctr--;
	}

	return (DCMD_OK);
}

static const char *
iscsi_idm_conn_event(unsigned int event)
{
	return ((event < CE_MAX_EVENT) ? idm_ce_name[event] : "N/A");
}

static const char *
iscsi_iscsit_tgt_event(unsigned int event)
{
	return ((event < TE_MAX_EVENT) ? iscsit_te_name[event] : "N/A");
}

static const char *
iscsi_iscsit_sess_event(unsigned int event)
{
	return ((event < SE_MAX_EVENT) ? iscsit_se_name[event] : "N/A");
}

static const char *
iscsi_iscsit_login_event(unsigned int event)
{
	return ((event < ILE_MAX_EVENT) ? iscsit_ile_name[event] : "N/A");
}

static const char *
iscsi_iscsi_cmd_event(unsigned int event)
{
	return ((event < ISCSI_CMD_EVENT_MAX) ?
	    iscsi_cmd_event_names[event] : "N/A");
}

static const char *
iscsi_iscsi_sess_event(unsigned int event)
{

	return ((event < ISCSI_SESS_EVENT_MAX) ?
	    iscsi_sess_event_names[event] : "N/A");
}

static const char *
iscsi_idm_conn_state(unsigned int state)
{
	return ((state < CS_MAX_STATE) ? idm_cs_name[state] : "N/A");
}

static const char *
iscsi_iscsi_conn_event(unsigned int event)
{

	return ((event < CN_MAX) ? idm_cn_strings[event] : "N/A");
}

/*ARGSUSED*/
static const char *
iscsi_idm_task_state(unsigned int state)
{
	return ("N/A");
}

static const char *
iscsi_iscsit_tgt_state(unsigned int state)
{
	return ((state < TS_MAX_STATE) ? iscsit_ts_name[state] : "N/A");
}

static const char *
iscsi_iscsit_sess_state(unsigned int state)
{
	return ((state < SS_MAX_STATE) ? iscsit_ss_name[state] : "N/A");
}

static const char *
iscsi_iscsit_login_state(unsigned int state)
{
	return ((state < ILS_MAX_STATE) ? iscsit_ils_name[state] : "N/A");
}

static const char *
iscsi_iscsi_cmd_state(unsigned int state)
{
	return ((state < ISCSI_CMD_STATE_MAX) ?
	    iscsi_cmd_state_names[state] : "N/A");
}

static const char *
iscsi_iscsi_sess_state(unsigned int state)
{
	return ((state < ISCSI_SESS_STATE_MAX) ?
	    iscsi_sess_state_names[state] : "N/A");
}

static const char *
iscsi_iscsi_conn_state(unsigned int state)
{
	return ((state < ISCSI_CONN_STATE_MAX) ? iscsi_ics_name[state] : "N/A");
}

static const char *
iscsi_iscsi_login_state(unsigned int state)
{
	return ((state < LOGIN_MAX) ? iscsi_login_state_names[state] : "N/A");
}


/*
 * Retrieve connection type given a kernel address
 */
static idm_conn_type_t
idm_conn_type(uintptr_t addr)
{
	idm_conn_type_t result = 0; /* Unknown */
	uintptr_t idm_conn_type_addr;

	idm_conn_type_addr = addr + offsetof(idm_conn_t, ic_conn_type);
	(void) mdb_vread(&result, sizeof (result), idm_conn_type_addr);

	return (result);
}

/*
 * Convert a sockaddr to the string representation, suitable for
 * storing in an nvlist or printing out in a list.
 */
static int
sa_to_str(struct sockaddr_storage *sa, char *buf)
{
	char			pbuf[7];
	const char		*bufp;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	uint16_t		port;

	if (!sa || !buf) {
		return (EINVAL);
	}

	buf[0] = '\0';

	if (sa->ss_family == AF_INET) {
		sin = (struct sockaddr_in *)sa;
		bufp = iscsi_inet_ntop(AF_INET,
		    (const void *)&(sin->sin_addr.s_addr),
		    buf, PORTAL_STR_LEN);
		if (bufp == NULL) {
			return (-1);
		}
		mdb_nhconvert(&port, &sin->sin_port, sizeof (uint16_t));
	} else if (sa->ss_family == AF_INET6) {
		strlcat(buf, "[", sizeof (buf));
		sin6 = (struct sockaddr_in6 *)sa;
		bufp = iscsi_inet_ntop(AF_INET6,
		    (const void *)&sin6->sin6_addr.s6_addr,
		    &buf[1], PORTAL_STR_LEN - 1);
		if (bufp == NULL) {
			return (-1);
		}
		strlcat(buf, "]", PORTAL_STR_LEN);
		mdb_nhconvert(&port, &sin6->sin6_port, sizeof (uint16_t));
	} else {
		return (EINVAL);
	}


	mdb_snprintf(pbuf, sizeof (pbuf), ":%u", port);
	strlcat(buf, pbuf, PORTAL_STR_LEN);

	return (0);
}


static void
iscsi_format_timestamp(char *ts_str, int strlen, timespec_t *ts)
{
	mdb_snprintf(ts_str, strlen, "%Y:%03d:%03d:%03d", ts->tv_sec,
	    (ts->tv_nsec / 1000000) % 1000, (ts->tv_nsec / 1000) % 1000,
	    ts->tv_nsec % 1000);
}

/*
 * Help information for the iscsi_isns dcmd
 */
static void
iscsi_isns_help(void)
{
	mdb_printf("iscsi_isns:\n");
	mdb_inc_indent(4);
	mdb_printf("-e: Print ESI information\n");
	mdb_printf("-p: Print portal information\n");
	mdb_printf("-s: Print iSNS server information\n");
	mdb_printf("-t: Print target information\n");
	mdb_printf("-v: Add verbosity to the other options' output\n");
	mdb_printf("-R: Add Refcount information to '-t' output\n");
	mdb_dec_indent(4);
}

/* ARGSUSED */
static int
iscsi_isns_esi_cb(uintptr_t addr, const void *walker_data, void *data)
{
	isns_esi_tinfo_t tinfo;

	if (mdb_vread(&tinfo, sizeof (isns_esi_tinfo_t), addr) !=
	    sizeof (isns_esi_tinfo_t)) {
		return (WALK_ERR);
	}

	mdb_printf("ESI thread/thr did : 0x%p / %d\n", tinfo.esi_thread,
	    tinfo.esi_thread_did);
	mdb_printf("ESI sonode         : 0x%p\n", tinfo.esi_so);
	mdb_printf("ESI port           : %d\n", tinfo.esi_port);
	mdb_printf("ESI thread running : %s\n",
	    (tinfo.esi_thread_running) ? "Yes" : "No");

	return (WALK_NEXT);
}

static int
iscsi_isns_esi(iscsi_dcmd_ctrl_t *idc)
{
	GElf_Sym		sym;
	uintptr_t		addr;

	if (mdb_lookup_by_name("esi", &sym) == -1) {
		mdb_warn("failed to find symbol 'esi_list'");
		return (DCMD_ERR);
	}
	addr = (uintptr_t)sym.st_value;

	idc->idc_header = 1;
	(void) iscsi_isns_esi_cb(addr, NULL, idc);

	return (0);
}

/* ARGSUSED */
static int
iscsi_isns_portal_cb(uintptr_t addr, const void *walker_data, void *data)
{
	iscsi_dcmd_ctrl_t *idc = (iscsi_dcmd_ctrl_t *)data;
	isns_portal_t portal;
	char portal_addr[PORTAL_STR_LEN];
	struct sockaddr_storage *ss;
	char			ts_string[40];

	if (mdb_vread(&portal, sizeof (isns_portal_t), addr) !=
	    sizeof (isns_portal_t)) {
		return (WALK_ERR);
	}

	ss = &portal.portal_addr;
	sa_to_str(ss, portal_addr);
	mdb_printf("Portal IP address ");

	if (ss->ss_family == AF_INET) {
		mdb_printf("(v4): %s", portal_addr);
	} else {
		mdb_printf("(v6): %s", portal_addr);
	}

	if (portal.portal_default == B_TRUE) {
		mdb_printf(" (Default portal)\n");
	} else {
		mdb_printf("\n");
	}
	if (portal.portal_iscsit != NULL) {
		mdb_printf("(Part of TPG: 0x%p)\n", portal.portal_iscsit);
	}

	iscsi_format_timestamp(ts_string, 40, &portal.portal_esi_timestamp);
	mdb_printf("Portal ESI timestamp: %s\n\n", ts_string);

	if ((portal.portal_iscsit != NULL) && (idc->idc_verbose)) {
		mdb_inc_indent(4);
		iscsi_portal_impl((uintptr_t)portal.portal_iscsit, idc);
		mdb_dec_indent(4);
	}


	return (WALK_NEXT);
}

static int
iscsi_isns_portals(iscsi_dcmd_ctrl_t *idc)
{
	GElf_Sym sym;
	uintptr_t portal_list;

	mdb_printf("All Active Portals:\n");

	if (mdb_lookup_by_name("isns_all_portals", &sym) == -1) {
		mdb_warn("failed to find symbol 'isns_all_portals'");
		return (DCMD_ERR);
	}

	portal_list = (uintptr_t)sym.st_value;
	idc->idc_header = 1;

	if (mdb_pwalk("avl", iscsi_isns_portal_cb, idc, portal_list) == -1) {
		mdb_warn("avl walk failed for isns_all_portals");
		return (DCMD_ERR);
	}
	mdb_printf("\nPortals from TPGs:\n");

	if (mdb_lookup_by_name("isns_tpg_portals", &sym) == -1) {
		mdb_warn("failed to find symbol 'isns_tpg_portals'");
		return (DCMD_ERR);
	}

	portal_list = (uintptr_t)sym.st_value;
	idc->idc_header = 1;

	if (mdb_pwalk("avl", iscsi_isns_portal_cb, idc, portal_list) == -1) {
		mdb_warn("avl walk failed for isns_tpg_portals");
		return (DCMD_ERR);
	}


	return (0);
}

/* ARGSUSED */
static int
iscsi_isns_targets_cb(uintptr_t addr, const void *walker_data, void *data)
{
	iscsi_dcmd_ctrl_t	*idc = (iscsi_dcmd_ctrl_t *)data;
	isns_target_t		itarget;
	int			rc = 0;
	int			rc_audit = 0;
	uintptr_t		rc_addr;

	if (mdb_vread(&itarget, sizeof (isns_target_t), addr) !=
	    sizeof (isns_target_t)) {
		return (WALK_ERR);
	}

	idc->idc_header = 1;
	rc_audit = idc->u.child.idc_rc_audit;

	mdb_printf("Target: %p\n", addr);
	mdb_inc_indent(4);
	mdb_printf("Registered: %s\n",
	    (itarget.target_registered) ? "Yes" : "No");
	mdb_printf("Update needed: %s\n",
	    (itarget.target_update_needed) ? "Yes" : "No");
	mdb_printf("Target Info: %p\n", itarget.target_info);

	/* Prevent target refcounts from showing through this path */
	idc->u.child.idc_rc_audit = 0;
	rc = iscsi_tgt_impl((uintptr_t)itarget.target, idc);

	idc->u.child.idc_rc_audit = rc_audit;
	if (idc->u.child.idc_rc_audit) {
		rc_addr = (uintptr_t)itarget.target_info +
		    offsetof(isns_target_info_t, ti_refcnt);

		mdb_printf("Reference History(isns_target_info ti_refcnt):\n");
		if (iscsi_refcnt_impl(rc_addr) != 0) {
			return (WALK_ERR);
		}
	}

	mdb_dec_indent(4);

	if (rc == DCMD_OK) {
		return (WALK_NEXT);
	}

	return (WALK_ERR);
}

static int
iscsi_isns_targets(iscsi_dcmd_ctrl_t *idc)
{
	GElf_Sym sym;
	uintptr_t isns_target_list;

	if (mdb_lookup_by_name("isns_target_list", &sym) == -1) {
		mdb_warn("failed to find symbol 'isns_target_list'");
		return (DCMD_ERR);
	}

	isns_target_list = (uintptr_t)sym.st_value;
	idc->idc_header = 1;
	idc->u.child.idc_tgt = 1;

	if (mdb_pwalk("avl", iscsi_isns_targets_cb, idc,
	    isns_target_list) == -1) {
		mdb_warn("avl walk failed for isns_target_list");
		return (DCMD_ERR);
	}

	return (0);
}

/* ARGSUSED */
static int
iscsi_isns_servers_cb(uintptr_t addr, const void *walker_data, void *data)
{
	iscsit_isns_svr_t	server;
	char			server_addr[PORTAL_STR_LEN];
	struct sockaddr_storage *ss;
	clock_t			lbolt;
	iscsi_dcmd_ctrl_t	*idc = (iscsi_dcmd_ctrl_t *)data;
	uintptr_t		avl_addr;

	if (mdb_vread(&server, sizeof (iscsit_isns_svr_t), addr) !=
	    sizeof (iscsit_isns_svr_t)) {
		return (WALK_ERR);
	}

	if ((lbolt = (clock_t)mdb_get_lbolt()) == -1)
		return (WALK_ERR);

	mdb_printf("iSNS server %p:\n", addr);
	mdb_inc_indent(4);
	ss = &server.svr_sa;
	sa_to_str(ss, server_addr);

	mdb_printf("IP address ");
	if (ss->ss_family == AF_INET) {
		mdb_printf("(v4): %s\n", server_addr);
	} else {
		mdb_printf("(v6): %s\n", server_addr);
	}

	mdb_printf("ESI Interval: %d seconds\n",
	    server.svr_esi_interval);
	mdb_printf("Last message: %d seconds ago\n",
	    ((lbolt - server.svr_last_msg) / 100));
	mdb_printf("Client registered: %s\n",
	    (server.svr_registered) ? "Yes" : "No");
	mdb_printf("Retry Count: %d\n",
	    server.svr_retry_count);
	mdb_printf("Targets Changes Pending: %s\n",
	    (server.svr_targets_changed) ? "Yes" : "No");
	mdb_printf("Delete Pending: %s\n",
	    (server.svr_delete_needed) ? "Yes" : "No");
	mdb_printf("Replace-All Needed: %s\n",
	    (server.svr_reset_needed) ? "Yes" : "No");

	if (idc->idc_verbose) {
		idc->idc_header = 1;
		idc->u.child.idc_tgt = 1;

		mdb_inc_indent(2);
		avl_addr = addr + offsetof(iscsit_isns_svr_t,
		    svr_target_list);
		if (mdb_pwalk("avl", iscsi_isns_targets_cb, idc,
		    avl_addr) == -1) {
			mdb_warn("avl walk failed for svr_target_list");
			return (WALK_ERR);
		}
		mdb_dec_indent(2);
	}

	mdb_dec_indent(4);

	return (WALK_NEXT);
}

static int
iscsi_isns_servers(iscsi_dcmd_ctrl_t *idc)
{
	uintptr_t	iscsit_global_addr;
	uintptr_t	list_addr;
	GElf_Sym	sym;

	if (mdb_lookup_by_name("iscsit_global", &sym) == -1) {
		mdb_warn("failed to find symbol 'iscsit_global'");
		return (DCMD_ERR);
	}

	iscsit_global_addr = (uintptr_t)sym.st_value;
	idc->idc_header = 1;
	list_addr = iscsit_global_addr +
	    offsetof(iscsit_global_t, global_isns_cfg.isns_svrs);

	if (mdb_pwalk("list", iscsi_isns_servers_cb, idc, list_addr) == -1) {
		mdb_warn("list walk failed for iSNS servers");
		return (DCMD_ERR);
	}

	return (0);
}

/* ARGSUSED */
static int
iscsi_isns(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iscsi_dcmd_ctrl_t idc;
	int portals = 0, esi = 0, targets = 0, verbose = 0, servers = 0;
	int rc_audit = 0;

	if (flags & DCMD_ADDRSPEC) {
		mdb_warn("iscsi_isns is only a global dcmd.");
		return (DCMD_ERR);
	}

	bzero(&idc, sizeof (idc));
	if (mdb_getopts(argc, argv,
	    'e', MDB_OPT_SETBITS, TRUE, &esi,
	    'p', MDB_OPT_SETBITS, TRUE, &portals,
	    's', MDB_OPT_SETBITS, TRUE, &servers,
	    't', MDB_OPT_SETBITS, TRUE, &targets,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'R', MDB_OPT_SETBITS, TRUE, &rc_audit,
	    NULL) != argc)
		return (DCMD_USAGE);

	if ((esi + portals + targets + servers) > 1) {
		mdb_printf("Only one of e, p, s, and t must be provided");
		return (DCMD_ERR);
	}

	if ((esi | portals | targets | servers) == 0) {
		mdb_printf("Exactly one of e, p, s, or t must be provided");
		return (DCMD_ERR);
	}

	idc.idc_verbose = verbose;
	idc.u.child.idc_rc_audit = rc_audit;

	if (esi) {
		return (iscsi_isns_esi(&idc));
	}

	if (portals) {
		return (iscsi_isns_portals(&idc));
	}

	if (servers) {
		return (iscsi_isns_servers(&idc));
	}

	return (iscsi_isns_targets(&idc));
}

static int
iscsi_ini_sess_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("<iscsi_sess_t addr>::walk iscsi_ini_sess");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (iscsi_sess_t), UM_SLEEP|UM_GC);
	if (!wsp->walk_data) {
		mdb_warn("iscsi_ini_sess walk failed");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
iscsi_ini_sess_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (iscsi_sess_t), wsp->walk_addr)
	    != sizeof (iscsi_sess_t)) {
		mdb_warn("failed to read iscsi_sess_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((iscsi_sess_t *)wsp->walk_data)->sess_next);

	return (status);
}

static int
iscsi_ini_conn_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("<iscsi_conn_t addr>::walk iscsi_ini_conn");
		return (WALK_DONE);
	}

	wsp->walk_data = mdb_alloc(sizeof (iscsi_conn_t), UM_SLEEP|UM_GC);
	if (!wsp->walk_data) {
		mdb_warn("iscsi_ini_conn walk failed");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
iscsi_ini_conn_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (iscsi_conn_t), wsp->walk_addr)
	    != sizeof (iscsi_conn_t)) {
		mdb_warn("failed to read iscsi_conn_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}


	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((iscsi_conn_t *)wsp->walk_data)->conn_next);

	return (status);
}

static int
iscsi_ini_lun_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("<iscsi_lun_t addr>::walk iscsi_ini_lun");
		return (WALK_DONE);
	}

	wsp->walk_data = mdb_alloc(sizeof (iscsi_lun_t), UM_SLEEP|UM_GC);
	if (!wsp->walk_data) {
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
iscsi_ini_lun_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (iscsi_lun_t), wsp->walk_addr)
	    != sizeof (iscsi_lun_t)) {
		mdb_warn("failed to read iscsi_lun_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((iscsi_lun_t *)wsp->walk_data)->lun_next);

	return (status);
}

static int
iscsi_ini_cmd_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("<iscsi_cmd_t addr>::walk iscsi_ini_cmd");
		return (WALK_DONE);
	}

	wsp->walk_data = mdb_alloc(sizeof (iscsi_cmd_t), UM_SLEEP|UM_GC);
	if (!wsp->walk_data) {
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
iscsi_ini_cmd_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (iscsi_cmd_t), wsp->walk_addr)
	    != sizeof (iscsi_cmd_t)) {
		mdb_warn("failed to read iscsi_cmd_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((iscsi_cmd_t *)wsp->walk_data)->cmd_next);

	return (status);
}

static int
iscsi_ini_cmd_walk_cb(uintptr_t addr, const void *vcmd, void *vidc)
{
	const iscsi_cmd_t	*cmd = vcmd;
	iscsi_dcmd_ctrl_t	*idc = vidc;
	int			rc;

	if (cmd == NULL) {
		mdb_warn("list walk failed. Null cmd");
		return (WALK_ERR);
	}

	rc = iscsi_print_ini_cmd(addr, cmd, idc);

	return ((rc == DCMD_OK) ? WALK_NEXT : WALK_ERR);
}

static int
iscsi_ini_hba_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t state_addr, array_addr;
	int array_size;
	struct i_ddi_soft_state *ss;
	idm_hba_walk_info_t *hwi;


	hwi = (idm_hba_walk_info_t *)mdb_zalloc(
	    sizeof (idm_hba_walk_info_t), UM_SLEEP|UM_GC);

	if (!hwi) {
		mdb_warn("unable to allocate storage for iscsi_ini_hba walk");
		return (WALK_ERR);
	}

	if (wsp->walk_addr != NULL) {
		mdb_warn("iscsi_ini_hba only supports global walk");
		return (WALK_ERR);
	} else {

		/*
		 * Read in the array and setup the walk struct.
		 */
		if (mdb_readvar(&state_addr, "iscsi_state") == -1) {
			mdb_warn("state variable iscsi_state not found.\n");
			mdb_warn("Is the driver loaded ?\n");
			return (WALK_ERR);
		}

		ss = (struct i_ddi_soft_state *)mdb_alloc(sizeof (*ss),
		    UM_SLEEP|UM_GC);
		if (mdb_vread(ss, sizeof (*ss), state_addr) != sizeof (*ss)) {
			mdb_warn("Cannot read softstate struct "
			    "(Invalid pointer?).\n");
			return (WALK_ERR);
		}

		/* Where to get the data */
		array_size = ss->n_items * (sizeof (void *));
		array_addr = (uintptr_t)ss->array;

		/* Where to put the data */
		hwi->n_elements = ss->n_items;
		hwi->array = mdb_alloc(array_size, UM_SLEEP|UM_GC);
		if (!hwi->array) {
			mdb_warn("list walk failed");
			return (WALK_ERR);
		}
		if (mdb_vread(hwi->array, array_size, array_addr) !=
		    array_size) {
			mdb_warn("Corrupted softstate struct.\n");
			return (WALK_ERR);
		}
		hwi->cur_element = 0;
		wsp->walk_data =  hwi;
	}

	return (WALK_NEXT);
}

static int
iscsi_ini_hba_step(mdb_walk_state_t *wsp)
{
	int status;
	idm_hba_walk_info_t *hwi = (idm_hba_walk_info_t *)wsp->walk_data;

	for (; hwi->cur_element < hwi->n_elements; hwi->cur_element++) {
		if (hwi->array[hwi->cur_element] != NULL) {
			break;
		}
	}
	if (hwi->cur_element >= hwi->n_elements) {
		return (WALK_DONE);
	}

	hwi->data = (iscsi_hba_t *)mdb_alloc(sizeof (iscsi_hba_t),
	    UM_SLEEP|UM_GC);
	if (mdb_vread(hwi->data, sizeof (iscsi_hba_t),
	    (uintptr_t)hwi->array[hwi->cur_element]) != sizeof (iscsi_hba_t)) {
		mdb_warn("failed to read iscsi_sess_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}


	status = wsp->walk_callback((uintptr_t)hwi->array[hwi->cur_element],
	    hwi->data, wsp->walk_cbdata);

	/* Increment cur_element for next iteration */
	hwi->cur_element++;

	return (status);
}

/*
 * iscsi_inet_ntop -- Convert an IPv4 or IPv6 address in binary form into
 * printable form, and return a pointer to that string. Caller should
 * provide a buffer of correct length to store string into.
 * Note: this routine is kernel version of inet_ntop. It has similar
 * format as iscsi_inet_ntop() defined in rfc2553. But it does not do
 * error handling operations exactly as rfc2553 defines. This function
 * is used by kernel inet directory routines only for debugging.
 * This iscsi_inet_ntop() function, does not return NULL if third argument
 * is NULL. The reason is simple that we don't want kernel to panic
 * as the output of this function is directly fed to ip<n>dbg macro.
 * Instead it uses a local buffer for destination address for
 * those calls which purposely pass NULL ptr for the destination
 * buffer. This function is thread-safe when the caller passes a non-
 * null buffer with the third argument.
 */
/* ARGSUSED */

#define	OK_16PTR(p)	(!((uintptr_t)(p) & 0x1))
#if defined(__x86)
#define	OK_32PTR(p)	OK_16PTR(p)
#else
#define	OK_32PTR(p)	(!((uintptr_t)(p) & 0x3))
#endif

char *
iscsi_inet_ntop(int af, const void *addr, char *buf, int addrlen)
{
	static char local_buf[PORTAL_STR_LEN];
	static char *err_buf1 = "<badaddr>";
	static char *err_buf2 = "<badfamily>";
	in6_addr_t	*v6addr;
	uchar_t		*v4addr;
	char		*caddr;

	/*
	 * We don't allow thread unsafe iscsi_inet_ntop calls, they
	 * must pass a non-null buffer pointer. For DEBUG mode
	 * we use the ASSERT() and for non-debug kernel it will
	 * silently allow it for now. Someday we should remove
	 * the static buffer from this function.
	 */

	ASSERT(buf != NULL);
	if (buf == NULL)
		buf = local_buf;
	buf[0] = '\0';

	/* Let user know politely not to send NULL or unaligned addr */
	if (addr == NULL || !(OK_32PTR(addr))) {
		return (err_buf1);
	}


#define	UC(b)	(((int)b) & 0xff)
	switch (af) {
	case AF_INET:
		ASSERT(addrlen >= INET_ADDRSTRLEN);
		v4addr = (uchar_t *)addr;
		(void) mdb_snprintf(buf, INET6_ADDRSTRLEN,
		    "%03d.%03d.%03d.%03d",
		    UC(v4addr[0]), UC(v4addr[1]), UC(v4addr[2]), UC(v4addr[3]));
		return (buf);

	case AF_INET6:
		ASSERT(addrlen >= INET6_ADDRSTRLEN);
		v6addr = (in6_addr_t *)addr;
		if (IN6_IS_ADDR_V4MAPPED(v6addr)) {
			caddr = (char *)addr;
			(void) mdb_snprintf(buf, INET6_ADDRSTRLEN,
			    "::ffff:%d.%d.%d.%d",
			    UC(caddr[12]), UC(caddr[13]),
			    UC(caddr[14]), UC(caddr[15]));
		} else if (IN6_IS_ADDR_V4COMPAT(v6addr)) {
			caddr = (char *)addr;
			(void) mdb_snprintf(buf, INET6_ADDRSTRLEN,
			    "::%d.%d.%d.%d",
			    UC(caddr[12]), UC(caddr[13]), UC(caddr[14]),
			    UC(caddr[15]));
		} else if (IN6_IS_ADDR_UNSPECIFIED(v6addr)) {
			(void) mdb_snprintf(buf, INET6_ADDRSTRLEN, "::");
		} else {
			convert2ascii(buf, v6addr);
		}
		return (buf);

	default:
		return (err_buf2);
	}
#undef UC
}

/*
 *
 * v6 formats supported
 * General format xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
 * The short hand notation :: is used for COMPAT addr
 * Other forms : fe80::xxxx:xxxx:xxxx:xxxx
 */
static void
convert2ascii(char *buf, const in6_addr_t *addr)
{
	int		hexdigits;
	int		head_zero = 0;
	int		tail_zero = 0;
	/* tempbuf must be big enough to hold ffff:\0 */
	char		tempbuf[6];
	char		*ptr;
	uint16_t	out_addr_component;
	uint16_t	*addr_component;
	size_t		len;
	boolean_t	first = B_FALSE;
	boolean_t	med_zero = B_FALSE;
	boolean_t	end_zero = B_FALSE;

	addr_component = (uint16_t *)addr;
	ptr = buf;

	/* First count if trailing zeroes higher in number */
	for (hexdigits = 0; hexdigits < 8; hexdigits++) {
		if (*addr_component == 0) {
			if (hexdigits < 4)
				head_zero++;
			else
				tail_zero++;
		}
		addr_component++;
	}
	addr_component = (uint16_t *)addr;
	if (tail_zero > head_zero && (head_zero + tail_zero) != 7)
		end_zero = B_TRUE;

	for (hexdigits = 0; hexdigits < 8; hexdigits++) {

		/* if entry is a 0 */

		if (*addr_component == 0) {
			if (!first && *(addr_component + 1) == 0) {
				if (end_zero && (hexdigits < 4)) {
					*ptr++ = '0';
					*ptr++ = ':';
				} else {
					/*
					 * address starts with 0s ..
					 * stick in leading ':' of pair
					 */
					if (hexdigits == 0)
						*ptr++ = ':';
					/* add another */
					*ptr++ = ':';
					first = B_TRUE;
					med_zero = B_TRUE;
				}
			} else if (first && med_zero) {
				if (hexdigits == 7)
					*ptr++ = ':';
				addr_component++;
				continue;
			} else {
				*ptr++ = '0';
				*ptr++ = ':';
			}
			addr_component++;
			continue;
		}
		if (med_zero)
			med_zero = B_FALSE;

		tempbuf[0] = '\0';
		mdb_nhconvert(&out_addr_component, addr_component,
		    sizeof (uint16_t));
		(void) mdb_snprintf(tempbuf, 6, "%x:", out_addr_component);
		len = strlen(tempbuf);
		bcopy(tempbuf, ptr, len);
		ptr = ptr + len;
		addr_component++;
	}
	*--ptr = '\0';
}

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers and a function named _mdb_init to return a pointer
 * to our module information.
 */
static const mdb_dcmd_t dcmds[] = {
	{   "iscsi_tgt", "[-agscptbSRv]",
	    "iSCSI target information", iscsi_tgt },
	{   "iscsi_tpgt", "[-R]",
	    "iSCSI target portal group tag information", iscsi_tpgt },
	{   "iscsi_tpg", "[-R]",
	    "iSCSI target portal group information", iscsi_tpg },
	{   "iscsi_sess", "[-ablmtvcSRIT]",
	    "iSCSI session information", iscsi_sess },
	{   "iscsi_conn", "[-abmtvSRIT]",
	    "iSCSI connection information", iscsi_conn },
	{   "iscsi_task", "[-bSRv]",
	    "iSCSI task information", iscsi_task },
	{   "iscsi_refcnt", "",
	    "print audit informtion for idm_refcnt_t", iscsi_refcnt },
	{   "iscsi_states", "",
	    "dump events and state transitions recorded in an\t"
	    "\t\tidm_sm_audit_t structure", iscsi_states },
	{   "iscsi_isns", "[-epstvR]",
	    "print iscsit iSNS information", iscsi_isns, iscsi_isns_help },
	{   "iscsi_svc", "[-vR]",
	    "iSCSI service information", iscsi_svc },
	{   "iscsi_portal", "[-R]",
	    "iSCSI portal information", iscsi_portal },
	{   "iscsi_cmd", "[-S]",
	    "iSCSI command information (initiator only)", iscsi_cmd },
	{ NULL }
};

/*
 * Basic walkers for the initiator linked lists
 */
static const mdb_walker_t walkers[] = {
	{ "iscsi_ini_hba", "global walk of the initiator iscsi_hba_t "
	    "list", iscsi_ini_hba_walk_init, iscsi_ini_hba_step, NULL},
	{ "iscsi_ini_sess", "walk list of initiator iscsi_sess_t structures",
	    iscsi_ini_sess_walk_init, iscsi_ini_sess_step, NULL },
	{ "iscsi_ini_conn", "walk list of initiator iscsi_conn_t structures",
	    iscsi_ini_conn_walk_init, iscsi_ini_conn_step, NULL },
	{ "iscsi_ini_lun", "walk list of initiator iscsi_lun_t structures",
	    iscsi_ini_lun_walk_init, iscsi_ini_lun_step, NULL },
	{ "iscsi_ini_cmd", "walk list of initiator iscsi_cmd_t structures",
	    iscsi_ini_cmd_walk_init, iscsi_ini_cmd_step, NULL },
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
