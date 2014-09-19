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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * The BrandZ Linux thunking server.
 *
 * The interfaces defined in this file form the server side of a bridge
 * to allow native solaris process to access Linux services.  Currently
 * the Linux services that is made accessible by these interfaces here
 * are:
 *	- Linux host <-> address naming services
 *	- Linux service <-> port naming services
 *	- Linux syslog
 *
 * Access to all these services is provided through a doors server.
 * Currently the only client of these interfaces and the process that
 * initially starts up the doors server is lx_thunk.so.
 *
 * lx_thunk.so is a native solaris library that is loaded into native
 * solaris process that need to run inside a Linux zone and have access
 * to Linux services.  When lx_thunk.so receives a request that requires
 * accessing Linux services it creates a "thunk server" process by
 * forking and executing the following shell script (which runs as
 * a branded /bin/sh Linux process):
 * 	/native/usr/lib/brand/lx/lx_thunk
 *
 * The first and only thing this shell script attempts to do is re-exec
 * itself.  The brand library will detect when this script attempts to
 * re-exec itself and take control of the process.  The exec() system
 * call made by the Linux shell will never return.
 *
 * At this point the process becomes a "thunk server" process.
 * The first thing it does is a bunch of initialization:
 *
 * - Sanity check that a file descriptor based communication mechanism
 *   needed talk to the parent process is correctly initialized.
 *
 * - Verify that two predetermined file descriptors are FIFOs.
 *   These FIFOs will be used to establish communications with
 *   the client program that spawned us and which will be sending
 *   us requests.
 *
 * - Use existing debugging libraries (libproc.so, librtld_db.so,
 *   and the BrandZ lx plug-in to librtld_db.so) and /native/proc to
 *   walk the Linux link maps in our own address space to determine
 *   the address of the Linux dlsym() function.
 *
 * - Use the native Linux dlsym() function to look up other symbols
 *   (for both functions and variables) that we will need access
 *   to service thunking requests.
 *
 * - Create a doors server and notify the parent process that we
 *   are ready to service requests.
 *
 * - Enter a service loop and wait for requests.
 *
 * At this point the lx_thunk process is ready to service door
 * based requests.  When door service request is received the
 * following happens inside the lx_thunk process:
 *
 * - The doors server function is is invoked on a new solaris thread
 *   that the kernel injects into the lx_thunk process.  We sanity
 *   check the incoming request, place it on a service queue, and
 *   wait for notification that the request has been completed.
 *
 * - A Linux thread takes this request off the service queue
 *   and dispatches it to a service function that will:
 *	- Decode the request.
 *	- Handle the request by invoking native Linux interfaces.
 *	- Encode the results for the request.
 *
 * - The Linux thread then notifies the requesting doors server
 *   thread that the  request has been completed and goes to sleep
 *   until it receives another request.
 *
 * - the solaris door server thread returns the results of the
 *   operation to the caller.
 *
 * Notes:
 *
 * - The service request hand off operation from the solaris doors thread to
 *   the "Linux thread" is required because only "Linux threads" can call
 *   into Linux code.  In this context a "Linux thread" is a thread that
 *   is either the initial thread of a Linux process or a thread that was
 *   created by calling the Linux version of thread_create().  The reason
 *   for this restriction is that any thread that invokes Linux code needs
 *   to have been initialized in the Linux threading libraries and have
 *   things like Linux thread local storage properly setup.
 *
 *   But under solaris all door server threads are created and destroyed
 *   dynamically.  This means that when a doors server function is invoked,
 *   it is invoked via a thread that hasn't been initialized in the Linux
 *   environment and there for can't call directly into Linux code.
 *
 * - Currently when a thunk server process is starting up, it communicated
 *   with it's parent via two FIFOs.  These FIFOs are setup by the
 *   lx_thunk.so library.  After creating the FIFOs and starting the lx_thunk
 *   server, lx_thunk.so writes the name of the file that the door should
 *   be attached to to the first pipe.  The lx_thunk server reads in this
 *   value, initialized the server, fattach()s it to the file request by
 *   lx_thunk.so and does a write to the second FIFO to let lx_thunk.so
 *   know that the server is ready to take requests.
 *
 *   This negotiation could be simplified to use only use one FIFO.
 *   lx_thunk.so would attempt to read from the FIFO and the lx_thunk
 *   server process could send the new door server file descriptor
 *   to this process via an I_SENDFD ioctl (see streamio.7I).
 *
 * - The lx_thunk server process will exit when the client process
 *   that it's handling requests for exists.  (ie, when there are no
 *   more open file handles to the doors server.)
 */

#include <assert.h>
#include <door.h>
#include <errno.h>
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/lx_debug.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>
#include <sys/lx_thread.h>
#include <sys/lx_thunk_server.h>
#include <sys/varargs.h>
#include <thread.h>
#include <unistd.h>

/*
 * Generic interfaces used for looking up and calling Linux functions.
 */
typedef struct __lx_handle_dlsym	*lx_handle_dlsym_t;
typedef struct __lx_handle_sym		*lx_handle_sym_t;

uintptr_t lx_call0(lx_handle_sym_t);
uintptr_t lx_call1(lx_handle_sym_t, uintptr_t);
uintptr_t lx_call2(lx_handle_sym_t, uintptr_t, uintptr_t);
uintptr_t lx_call3(lx_handle_sym_t, uintptr_t, uintptr_t, uintptr_t);
uintptr_t lx_call4(lx_handle_sym_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t);
uintptr_t lx_call5(lx_handle_sym_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t);
uintptr_t lx_call6(lx_handle_sym_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t);
uintptr_t lx_call7(lx_handle_sym_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t);
uintptr_t lx_call8(lx_handle_sym_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

/*
 * Flag indicating if this process is destined to become a thunking
 * server process.
 */
static int lxt_server_processes = 0;

/*
 * Linux function call defines and handles.
 */
static lx_handle_dlsym_t	lxh_init = NULL;

#define	LXTH_GETHOSTBYNAME_R	0
#define	LXTH_GETHOSTBYADDR_R	1
#define	LXTH_GETSERVBYNAME_R	2
#define	LXTH_GETSERVBYPORT_R	3
#define	LXTH_OPENLOG		4
#define	LXTH_SYSLOG		5
#define	LXTH_CLOSELOG		6
#define	LXTH_PROGNAME		7

static struct lxt_handles {
	int		lxth_index;
	char		*lxth_name;
	lx_handle_sym_t	lxth_handle;
} lxt_handles[] = {
	{ LXTH_GETHOSTBYNAME_R,	"gethostbyname_r",	NULL },
	{ LXTH_GETHOSTBYADDR_R,	"gethostbyaddr_r",	NULL },
	{ LXTH_GETSERVBYNAME_R,	"getservbyname_r",	NULL },
	{ LXTH_GETSERVBYPORT_R,	"getservbyport_r",	NULL },
	{ LXTH_OPENLOG,		"openlog",		NULL },
	{ LXTH_SYSLOG,		"syslog",		NULL },
	{ LXTH_CLOSELOG,	"closelog",		NULL },
	{ LXTH_PROGNAME,	"__progname",		NULL },
	{ -1,			NULL, 			NULL },
};

/*
 * Door server operations dispatch functions and table.
 *
 * When the doors server get's a request for a particlar operation
 * this dispatch table controls what function will be invoked to
 * service the request.  The function is invoked via Linux thread
 * so that it can call into native Linux code if necessary.
 */
static void lxt_server_gethost(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size);
static void lxt_server_getserv(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size);
static void lxt_server_openlog(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size);
static void lxt_server_syslog(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size);
static void lxt_server_closelog(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size);

typedef void (*lxt_op_func_t)(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size);

static struct lxt_operations {
	int		lxto_index;
	lxt_op_func_t	lxto_fp;
} lxt_operations[] = {
	{ LXT_SERVER_OP_PING,		NULL },
	{ LXT_SERVER_OP_NAME2HOST,	lxt_server_gethost },
	{ LXT_SERVER_OP_ADDR2HOST,	lxt_server_gethost },
	{ LXT_SERVER_OP_NAME2SERV,	lxt_server_getserv },
	{ LXT_SERVER_OP_PORT2SERV,	lxt_server_getserv },
	{ LXT_SERVER_OP_OPENLOG,	lxt_server_openlog },
	{ LXT_SERVER_OP_SYSLOG,		lxt_server_syslog },
	{ LXT_SERVER_OP_CLOSELOG,	lxt_server_closelog },
};

/*
 * Structures for passing off requests from doors threads (which are
 * solaris threads) to a Linux thread that that can handle them.
 */
typedef struct lxt_req {
	lxt_server_arg_t	*lxtr_request;
	size_t			lxtr_request_size;
	char			*lxtr_result;
	size_t			lxtr_result_size;
	int			lxtr_complete;
	cond_t			lxtr_complete_cv;
} lxt_req_t;

static mutex_t		lxt_req_lock = DEFAULTMUTEX;
static cond_t		lxt_req_cv = DEFAULTCV;
static lxt_req_t	*lxt_req_ptr = NULL;

static mutex_t		lxt_pid_lock = DEFAULTMUTEX;
static pid_t		lxt_pid = NULL;

/*
 * Interfaces used to call from lx_brand.so into Linux code.
 */
typedef struct lookup_cb_arg {
	struct ps_prochandle	*lca_ph;
	caddr_t			lca_ptr;
} lookup_cb_arg_t;

static int
/*ARGSUSED*/
lookup_cb(void *data, const prmap_t *pmp, const char *object)
{
	lookup_cb_arg_t		*lcap = (lookup_cb_arg_t *)data;
	prsyminfo_t		si;
	GElf_Sym		sym;

	if (Pxlookup_by_name(lcap->lca_ph,
	    LM_ID_BASE, object, "dlsym", &sym, &si) != 0)
		return (0);

	if (sym.st_shndx == SHN_UNDEF)
		return (0);

	/*
	 * XXX: we should be more paranoid and verify that the symbol
	 * we just looked up is libdl.so.2`dlsym
	 */
	lcap->lca_ptr = (caddr_t)(uintptr_t)sym.st_value;
	return (1);
}

lx_handle_dlsym_t
lx_call_init(void)
{
	struct ps_prochandle	*ph;
	lookup_cb_arg_t		lca;
	extern int 		__libc_threaded;
	int			err;

	lx_debug("lx_call_init(): looking up Linux dlsym");

	/*
	 * The handle is really the address of the Linux "dlsym" function.
	 * Once we have this address we can call into the Linux "dlsym"
	 * function to lookup other functions.  It's the initial lookup
	 * of "dlsym" that's difficult.  To do this we'll leverage the
	 * brand support that we added to librtld_db.  We're going
	 * to fire up a seperate native solaris process that will
	 * attach to us via libproc/librtld_db and lookup the symbol
	 * for us.
	 */

	/* Make sure we're single threaded. */
	if (__libc_threaded) {
		lx_debug("lx_call_init() fail: "
		    "process must be single threaded");
		return (NULL);
	}

	/* Tell libproc.so where the real procfs is mounted. */
	Pset_procfs_path("/native/proc");

	/* Tell librtld_db.so where the real /native is */
	(void) rd_ctl(RD_CTL_SET_HELPPATH, "/native");

	/* Grab ourselves but don't stop ourselves. */
	if ((ph = Pgrab(getpid(),
	    PGRAB_FORCE | PGRAB_RDONLY | PGRAB_NOSTOP, &err)) == NULL) {
		lx_debug("lx_call_init() fail: Pgrab failed: %s",
		    Pgrab_error(err));
		return (NULL);
	}

	lca.lca_ph = ph;
	lca.lca_ptr = NULL;
	if (Pobject_iter(ph, lookup_cb, &lca) == -1) {
		lx_debug("lx_call_init() fail: couldn't find Linux dlsym");
		return (NULL);
	}

	lx_debug("lx_call_init(): Linux dlsym = 0x%p", lca.lca_ptr);
	return ((lx_handle_dlsym_t)lca.lca_ptr);
}

#define	LX_RTLD_DEFAULT		((void *)0)
#define	LX_RTLD_NEXT		((void *) -1l)

lx_handle_sym_t
lx_call_dlsym(lx_handle_dlsym_t lxh_dlsym, const char *str)
{
	lx_handle_sym_t result;
	lx_debug("lx_call_dlsym: calling Linux dlsym for: %s", str);
	result = (lx_handle_sym_t)lx_call2((lx_handle_sym_t)lxh_dlsym,
	    (uintptr_t)LX_RTLD_DEFAULT, (uintptr_t)str);
	lx_debug("lx_call_dlsym: Linux sym: \"%s\" = 0x%p", str, result);
	return (result);
}

static uintptr_t
/*ARGSUSED*/
lx_call(lx_handle_sym_t lx_ch, uintptr_t p1, uintptr_t p2,
    uintptr_t p3, uintptr_t p4, uintptr_t p5, uintptr_t p6, uintptr_t p7,
    uintptr_t p8)
{
	typedef uintptr_t	(*fp8_t)(uintptr_t, uintptr_t, uintptr_t,
	    uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
	lx_regs_t		*rp;
	uintptr_t		ret;
	fp8_t			lx_funcp = (fp8_t)lx_ch;
#if defined(_ILP32)
	long			cur_gs;
#endif

	rp = lx_syscall_regs();

	lx_debug("lx_call: calling to Linux code at 0x%p", lx_ch);
	lx_debug("lx_call: loading Linux gs, rp = 0x%p, gs = 0x%p",
	    rp, rp->lxr_gs);

#if defined(_ILP32)
	lx_swap_gs(rp->lxr_gs, &cur_gs);
#endif
	ret = lx_funcp(p1, p2, p3, p4, p5, p6, p7, p8);
#if defined(_ILP32)
	lx_swap_gs(cur_gs, &rp->lxr_gs);
#endif

	lx_debug("lx_call: returned from Linux code at 0x%p (%p)", lx_ch, ret);
	return (ret);
}

uintptr_t
lx_call0(lx_handle_sym_t lx_ch)
{
	return (lx_call(lx_ch, 0, 0, 0, 0, 0, 0, 0, 0));
}

uintptr_t
lx_call1(lx_handle_sym_t lx_ch, uintptr_t p1)
{
	return (lx_call(lx_ch, p1, 0, 0, 0, 0, 0, 0, 0));
}

uintptr_t
lx_call2(lx_handle_sym_t lx_ch, uintptr_t p1, uintptr_t p2)
{
	return (lx_call(lx_ch, p1, p2, 0, 0, 0, 0, 0, 0));
}

uintptr_t
lx_call3(lx_handle_sym_t lx_ch, uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	return (lx_call(lx_ch, p1, p2, p3, 0, 0, 0, 0, 0));
}

uintptr_t
lx_call4(lx_handle_sym_t lx_ch, uintptr_t p1, uintptr_t p2, uintptr_t p3,
    uintptr_t p4)
{
	return (lx_call(lx_ch, p1, p2, p3, p4, 0, 0, 0, 0));
}

uintptr_t
lx_call5(lx_handle_sym_t lx_ch, uintptr_t p1, uintptr_t p2, uintptr_t p3,
    uintptr_t p4, uintptr_t p5)
{
	return (lx_call(lx_ch, p1, p2, p3, p4, p5, 0, 0, 0));
}

uintptr_t
lx_call6(lx_handle_sym_t lx_ch, uintptr_t p1, uintptr_t p2, uintptr_t p3,
    uintptr_t p4, uintptr_t p5, uintptr_t p6)
{
	return (lx_call(lx_ch, p1, p2, p3, p4, p5, p6, 0, 0));
}

uintptr_t
lx_call7(lx_handle_sym_t lx_ch, uintptr_t p1, uintptr_t p2, uintptr_t p3,
    uintptr_t p4, uintptr_t p5, uintptr_t p6, uintptr_t p7)
{
	return (lx_call(lx_ch, p1, p2, p3, p4, p5, p6, p7, 0));
}

uintptr_t
lx_call8(lx_handle_sym_t lx_ch, uintptr_t p1, uintptr_t p2, uintptr_t p3,
    uintptr_t p4, uintptr_t p5, uintptr_t p6, uintptr_t p7, uintptr_t p8)
{
	return (lx_call(lx_ch, p1, p2, p3, p4, p5, p6, p7, p8));
}

/*
 * Linux Thunking Interfaces - Server Side
 */
static int
lxt_gethost_arg_check(lxt_gethost_arg_t *x, int x_size)
{
	if (x_size != sizeof (*x) + x->lxt_gh_buf_len - 1)
		return (-1);

	if ((x->lxt_gh_token_len < 0) || (x->lxt_gh_buf_len < 0))
		return (-1);

	/* Token and buf should use up all the storage. */
	if ((x->lxt_gh_token_len + x->lxt_gh_buf_len) != x->lxt_gh_storage_len)
		return (-1);

	return (0);
}

static void
lxt_server_gethost(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size)
{
	lxt_gethost_arg_t	*data;
	struct hostent		*result, *rv;
	int			token_len, buf_len, type, data_size, i;
	char			*token, *buf;
	int			h_errnop;

	assert((request->lxt_sa_op == LXT_SERVER_OP_NAME2HOST) ||
	    (request->lxt_sa_op == LXT_SERVER_OP_ADDR2HOST));

	/*LINTED*/
	data = (lxt_gethost_arg_t *)&request->lxt_sa_data[0];
	data_size = request_size - sizeof (*request) - 1;

	if (!lxt_gethost_arg_check(data, data_size)) {
		lx_debug("lxt_server_gethost: invalid request");
		*door_result = NULL;
		*door_result_size = 0;
		return;
	}

	/* Unpack the arguments. */
	type = data->lxt_gh_type;
	token = &data->lxt_gh_storage[0];
	token_len = data->lxt_gh_token_len;
	result = &data->lxt_gh_result;
	buf = &data->lxt_gh_storage[data->lxt_gh_token_len];
	buf_len = data->lxt_gh_buf_len - data->lxt_gh_token_len;

	if (request->lxt_sa_op == LXT_SERVER_OP_NAME2HOST) {
		(void) lx_call6(lxt_handles[LXTH_GETHOSTBYNAME_R].lxth_handle,
		    (uintptr_t)token, (uintptr_t)result,
		    (uintptr_t)buf, buf_len, (uintptr_t)&rv,
		    (uintptr_t)&h_errnop);
	} else {
		(void) lx_call8(lxt_handles[LXTH_GETHOSTBYADDR_R].lxth_handle,
		    (uintptr_t)token, token_len, type, (uintptr_t)result,
		    (uintptr_t)buf, buf_len, (uintptr_t)&rv,
		    (uintptr_t)&h_errnop);
	}

	if (rv == NULL) {
		/* the lookup failed */
		request->lxt_sa_success = 0;
		request->lxt_sa_errno = errno;
		data->lxt_gh_h_errno = h_errnop;
		*door_result = (char *)request;
		*door_result_size = request_size;
		return;
	}
	request->lxt_sa_success = 1;
	request->lxt_sa_errno = 0;
	data->lxt_gh_h_errno = 0;

	/*
	 * The result structure that we would normally return contains a
	 * bunch of pointers, but those pointers are useless to our caller
	 * since they are in a different address space.  So before returning
	 * we'll convert all the result pointers into offsets.  The caller
	 * can then map the offsets back into pointers.
	 */
	for (i = 0; result->h_aliases[i] != NULL; i++) {
		result->h_aliases[i] =
		    LXT_PTR_TO_OFFSET(result->h_aliases[i], buf);
	}
	for (i = 0; result->h_addr_list[i] != NULL; i++) {
		result->h_addr_list[i] =
		    LXT_PTR_TO_OFFSET(result->h_addr_list[i], buf);
	}
	result->h_name = LXT_PTR_TO_OFFSET(result->h_name, buf);
	result->h_aliases = LXT_PTR_TO_OFFSET(result->h_aliases, buf);
	result->h_addr_list = LXT_PTR_TO_OFFSET(result->h_addr_list, buf);

	*door_result = (char *)request;
	*door_result_size = request_size;
}

static int
lxt_getserv_arg_check(lxt_getserv_arg_t *x, int x_size)
{
	if (x_size != sizeof (*x) + x->lxt_gs_buf_len - 1)
		return (-1);

	if ((x->lxt_gs_token_len < 0) || (x->lxt_gs_buf_len < 0))
		return (-1);

	/* Token and buf should use up all the storage. */
	if ((x->lxt_gs_token_len + x->lxt_gs_buf_len) != x->lxt_gs_storage_len)
		return (-1);

	return (0);
}

static void
lxt_server_getserv(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size)
{
	lxt_getserv_arg_t	*data;
	struct servent		*result, *rv;
	int			token_len, buf_len, data_size, i, port;
	char			*token, *buf, *proto = NULL;

	assert((request->lxt_sa_op == LXT_SERVER_OP_NAME2SERV) ||
	    (request->lxt_sa_op == LXT_SERVER_OP_PORT2SERV));

	/*LINTED*/
	data = (lxt_getserv_arg_t *)&request->lxt_sa_data[0];
	data_size = request_size - sizeof (*request) - 1;

	if (!lxt_getserv_arg_check(data, data_size)) {
		lx_debug("lxt_server_getserv: invalid request");
		*door_result = NULL;
		*door_result_size = 0;
		return;
	}

	/* Unpack the arguments. */
	token = &data->lxt_gs_storage[0];
	token_len = data->lxt_gs_token_len;
	result = &data->lxt_gs_result;
	buf = &data->lxt_gs_storage[data->lxt_gs_token_len];
	buf_len = data->lxt_gs_buf_len - data->lxt_gs_token_len;
	if (strlen(data->lxt_gs_proto) > 0)
		proto = data->lxt_gs_proto;

	/* Do more sanity checks */
	if ((request->lxt_sa_op == LXT_SERVER_OP_PORT2SERV) &&
	    (token_len != sizeof (int))) {
		lx_debug("lxt_server_getserv: invalid request");
		*door_result = NULL;
		*door_result_size = 0;
		return;
	}

	if (request->lxt_sa_op == LXT_SERVER_OP_NAME2SERV) {
		(void) lx_call6(lxt_handles[LXTH_GETSERVBYNAME_R].lxth_handle,
		    (uintptr_t)token, (uintptr_t)proto, (uintptr_t)result,
		    (uintptr_t)buf, buf_len, (uintptr_t)&rv);
	} else {
		bcopy(token, &port, sizeof (int));
		(void) lx_call6(lxt_handles[LXTH_GETSERVBYPORT_R].lxth_handle,
		    port, (uintptr_t)proto, (uintptr_t)result,
		    (uintptr_t)buf, buf_len, (uintptr_t)&rv);
	}

	if (rv == NULL) {
		/* the lookup failed */
		request->lxt_sa_success = 0;
		request->lxt_sa_errno = errno;
		*door_result = (char *)request;
		*door_result_size = request_size;
		return;
	}
	request->lxt_sa_success = 1;
	request->lxt_sa_errno = 0;

	/*
	 * The result structure that we would normally return contains a
	 * bunch of pointers, but those pointers are useless to our caller
	 * since they are in a different address space.  So before returning
	 * we'll convert all the result pointers into offsets.  The caller
	 * can then map the offsets back into pointers.
	 */
	for (i = 0; result->s_aliases[i] != NULL; i++) {
		result->s_aliases[i] =
		    LXT_PTR_TO_OFFSET(result->s_aliases[i], buf);
	}
	result->s_proto = LXT_PTR_TO_OFFSET(result->s_proto, buf);
	result->s_aliases = LXT_PTR_TO_OFFSET(result->s_aliases, buf);
	result->s_name = LXT_PTR_TO_OFFSET(result->s_name, buf);

	*door_result = (char *)request;
	*door_result_size = request_size;
}

static void
/*ARGSUSED*/
lxt_server_openlog(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size)
{
	lxt_openlog_arg_t	*data;
	int			data_size;
	static char		ident[128];

	assert(request->lxt_sa_op == LXT_SERVER_OP_OPENLOG);

	/*LINTED*/
	data = (lxt_openlog_arg_t *)&request->lxt_sa_data[0];
	data_size = request_size - sizeof (*request);

	if (data_size != sizeof (*data)) {
		lx_debug("lxt_server_openlog: invalid request");
		*door_result = NULL;
		*door_result_size = 0;
		return;
	}

	/*
	 * Linux expects that the ident pointer passed to openlog()
	 * points to a static string that won't go away.  Linux
	 * saves the pointer and references with syslog() is called.
	 * Hence we'll make a local copy of the ident string here.
	 */
	(void) mutex_lock(&lxt_pid_lock);
	(void) strlcpy(ident, data->lxt_ol_ident, sizeof (ident));
	(void) mutex_unlock(&lxt_pid_lock);

	/* Call Linx openlog(). */
	(void) lx_call3(lxt_handles[LXTH_OPENLOG].lxth_handle,
	    (uintptr_t)ident, data->lxt_ol_logopt, data->lxt_ol_facility);

	request->lxt_sa_success = 1;
	request->lxt_sa_errno = 0;
	*door_result = (char *)request;
	*door_result_size = request_size;
}

static void
/*ARGSUSED*/
lxt_server_syslog(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size)
{
	lxt_syslog_arg_t	*data;
	int			data_size;
	char			*progname_ptr_new;
	char			*progname_ptr_old;

	assert(request->lxt_sa_op == LXT_SERVER_OP_SYSLOG);

	/*LINTED*/
	data = (lxt_syslog_arg_t *)&request->lxt_sa_data[0];
	data_size = request_size - sizeof (*request);

	if (data_size != sizeof (*data)) {
		lx_debug("lxt_server_openlog: invalid request");
		*door_result = NULL;
		*door_result_size = 0;
		return;
	}
	progname_ptr_new = data->lxt_sl_progname;

	(void) mutex_lock(&lxt_pid_lock);

	/*
	 * Ensure the message has the correct pid.
	 * We do this by telling our getpid() system call to return a
	 * different value.
	 */
	lxt_pid = data->lxt_sl_pid;

	/*
	 * Ensure the message has the correct program name.
	 * Normally instead of a program name an "ident" string is
	 * used, this is the string passed to openlog().  But if
	 * openlog() wasn't called before syslog() then Linux
	 * syslog() will attempt to use the program name as
	 * the ident string, and the program name is determined
	 * by looking at the __progname variable.  So we'll just
	 * update the Linux __progname variable while we do the
	 * call.
	 */
	(void) uucopy(lxt_handles[LXTH_PROGNAME].lxth_handle,
	    &progname_ptr_old, sizeof (char *));
	(void) uucopy(&progname_ptr_new,
	    lxt_handles[LXTH_PROGNAME].lxth_handle, sizeof (char *));

	/* Call Linux syslog(). */
	(void) lx_call2(lxt_handles[LXTH_SYSLOG].lxth_handle,
	    data->lxt_sl_priority, (uintptr_t)data->lxt_sl_message);

	/* Restore pid and program name. */
	(void) uucopy(&progname_ptr_old,
	    lxt_handles[LXTH_PROGNAME].lxth_handle, sizeof (char *));
	lxt_pid = NULL;

	(void) mutex_unlock(&lxt_pid_lock);

	request->lxt_sa_success = 1;
	request->lxt_sa_errno = 0;
	*door_result = (char *)request;
	*door_result_size = request_size;
}

static void
/*ARGSUSED*/
lxt_server_closelog(lxt_server_arg_t *request, size_t request_size,
    char **door_result, size_t *door_result_size)
{
	int			data_size;

	assert(request->lxt_sa_op == LXT_SERVER_OP_CLOSELOG);

	data_size = request_size - sizeof (*request);
	if (data_size != 0) {
		lx_debug("lxt_server_closelog: invalid request");
		*door_result = NULL;
		*door_result_size = 0;
		return;
	}

	/* Call Linux closelog(). */
	(void) lx_call0(lxt_handles[LXTH_CLOSELOG].lxth_handle);

	request->lxt_sa_success = 1;
	request->lxt_sa_errno = 0;
	*door_result = (char *)request;
	*door_result_size = request_size;
}

static void
/*ARGSUSED*/
lxt_server(void *cookie, char *argp, size_t request_size,
    door_desc_t *dp, uint_t n_desc)
{
	/*LINTED*/
	lxt_server_arg_t	*request = (lxt_server_arg_t *)argp;
	lxt_req_t		lxt_req;
	char			*door_path = cookie;

	/* Check if there's no callers left */
	if (argp == DOOR_UNREF_DATA) {
		(void) fdetach(door_path);
		(void) unlink(door_path);
		lx_debug("lxt_thunk_server: no clients, exiting");
		exit(0);
	}

	/* Sanity check the incomming request. */
	if (request_size < sizeof (*request)) {
		/* the lookup failed */
		lx_debug("lxt_thunk_server: invalid request size");
		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	if ((request->lxt_sa_op < LXT_SERVER_OP_MIN) ||
	    (request->lxt_sa_op > LXT_SERVER_OP_MAX)) {
		lx_debug("lxt_thunk_server: invalid request op");
		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	/* Handle ping requests immediatly, return here. */
	if (request->lxt_sa_op == LXT_SERVER_OP_PING) {
		lx_debug("lxt_thunk_server: handling ping request");
		request->lxt_sa_success = 1;
		(void) door_return((char *)request, request_size, NULL, 0);
		return;
	}

	lx_debug("lxt_thunk_server: hand off request to Linux thread, "
	    "request = 0x%p", request);

	/* Pack the request up so we can pass it to a Linux thread. */
	lxt_req.lxtr_request = request;
	lxt_req.lxtr_request_size = request_size;
	lxt_req.lxtr_result = NULL;
	lxt_req.lxtr_result_size = 0;
	lxt_req.lxtr_complete = 0;
	(void) cond_init(&lxt_req.lxtr_complete_cv, USYNC_THREAD, NULL);

	/* Pass the request onto a Linux thread. */
	(void) mutex_lock(&lxt_req_lock);
	while (lxt_req_ptr != NULL)
		(void) cond_wait(&lxt_req_cv, &lxt_req_lock);
	lxt_req_ptr = &lxt_req;
	(void) cond_broadcast(&lxt_req_cv);

	/* Wait for the request to be completed. */
	while (lxt_req.lxtr_complete == 0)
		(void) cond_wait(&lxt_req.lxtr_complete_cv, &lxt_req_lock);
	assert(lxt_req_ptr != &lxt_req);
	(void) mutex_unlock(&lxt_req_lock);

	lx_debug("lxt_thunk_server: hand off request completed, "
	    "request = 0x%p", request);

	/*
	 * If door_return() is successfull it never returns, so if we made
	 * it here there was some kind of error, but there's nothing we can
	 * really do about it.
	 */
	(void) door_return(
	    lxt_req.lxtr_result, lxt_req.lxtr_result_size, NULL, 0);
}

static void
lxt_server_loop(void)
{
	lxt_req_t		*lxt_req;
	lxt_server_arg_t	*request;
	size_t			request_size;
	char			*door_result;
	size_t			door_result_size;

	for (;;) {
		/* Wait for a request from a doors server thread. */
		(void) mutex_lock(&lxt_req_lock);
		while (lxt_req_ptr == NULL)
			(void) cond_wait(&lxt_req_cv, &lxt_req_lock);

		/* We got a request, get a local pointer to it. */
		lxt_req = lxt_req_ptr;
		lxt_req_ptr = NULL;
		(void) cond_broadcast(&lxt_req_cv);
		(void) mutex_unlock(&lxt_req_lock);

		/* Get a pointer to the request. */
		request = lxt_req->lxtr_request;
		request_size = lxt_req->lxtr_request_size;

		lx_debug("lxt_server_loop: Linux thread request recieved, "
		    "request = %p", request);

		/* Dispatch the request. */
		assert((request->lxt_sa_op > LXT_SERVER_OP_PING) ||
		    (request->lxt_sa_op < LXT_SERVER_OP_MAX));
		lxt_operations[request->lxt_sa_op].lxto_fp(
		    request, request_size, &door_result, &door_result_size);

		lx_debug("lxt_server_loop: Linux thread request completed, "
		    "request = %p", request);

		(void) mutex_lock(&lxt_req_lock);

		/* Set the result pointers for the calling door thread. */
		lxt_req->lxtr_result = door_result;
		lxt_req->lxtr_result_size = door_result_size;

		/* Let the door thread know we're done. */
		lxt_req->lxtr_complete = 1;
		(void) cond_signal(&lxt_req->lxtr_complete_cv);

		(void) mutex_unlock(&lxt_req_lock);
	}
	/*NOTREACHED*/
}

static void
lxt_server_enter(int fifo1_wr, int fifo2_rd)
{
	struct stat	stat;
	char		door_path[MAXPATHLEN];
	int		i, dfd, junk = 0;

	/*
	 * Do some sanity checks.  Make sure we've got the fifos
	 * we need passed to us on the correct file descriptors.
	 */
	if ((fstat(fifo1_wr, &stat) != 0) ||
	    ((stat.st_mode & S_IFMT) != S_IFIFO) ||
	    (fstat(fifo2_rd, &stat) != 0) ||
	    ((stat.st_mode & S_IFMT) != S_IFIFO)) {
		lx_err("lx_thunk server aborting, can't contact parent");
		exit(-1);
	}

	/*
	 * Get the initial Linux call handle so we can invoke other
	 * Linux calls.
	 */
	lxh_init = lx_call_init();
	if (lxh_init == NULL) {
		lx_err("lx_thunk server aborting, failed Linux call init");
		exit(-1);
	}

	/* Now lookup other Linux symbols we'll need access to. */
	for (i = 0; lxt_handles[i].lxth_name != NULL; i++) {
		assert(lxt_handles[i].lxth_index == i);
		if ((lxt_handles[i].lxth_handle = lx_call_dlsym(lxh_init,
		    lxt_handles[i].lxth_name)) == NULL) {
			lx_err("lx_thunk server aborting, "
			    "failed Linux symbol lookup: %s",
			    lxt_handles[i].lxth_name);
			exit(-1);
		}
	}

	/* get the path to the door server */
	if (read(fifo2_rd, door_path, sizeof (door_path)) < 0) {
		lx_err("lxt_server_enter: failed to get door path");
		exit(-1);
	}
	(void) close(fifo2_rd);

	/* Create the door server. */
	if ((dfd = door_create(lxt_server, door_path,
	    DOOR_UNREF | DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) < 0) {
		lx_err("lxt_server_enter: door_create() failed");
		exit(-1);
	}

	/* Attach the door to a file system path. */
	(void) fdetach(door_path);
	if (fattach(dfd, door_path) < 0) {
		lx_err("lxt_server_enter: fattach() failed");
		exit(-1);
	}

	/* The door server is ready, signal this via a fifo write */
	(void) write(fifo1_wr, &junk, 1);
	(void) close(fifo1_wr);

	lx_debug("lxt_server_enter: doors server initialized");
	lxt_server_loop();
	/*NOTREACHED*/
}

void
lxt_server_exec_check(void)
{
	if (lxt_server_processes == 0)
		return;

	/*
	 * We're a thunk server process, so we take over control of
	 * the current Linux process here.
	 */
	lx_debug("lx_thunk server initalization starting");
	lxt_server_enter(LXT_SERVER_FIFO_WR_FD, LXT_SERVER_FIFO_RD_FD);
	/*NOTREACHED*/
}

void
lxt_server_init(int argc, char *argv[])
{
	/*
	 * The thunk server process is a shell script named LXT_SERVER_BINARY.
	 * It is executed without any parameters.  Since it's a shell script
	 * the arguments passed to the shell's main entry point are:
	 *	1) the name of the shell
	 *	2) the name of the script to execute
	 *
	 * So to check if we're the thunk server process we first check
	 * for the expected number of arduments and then we'll look at
	 * the second parameter to see if it's LXT_SERVER_BINARY.
	 */
	if ((argc != 2) ||
	    (strcmp(argv[1], LXT_SERVER_BINARY) != 0))
		return;

	lxt_server_processes = 1;
	lx_debug("lx_thunk server detected, delaying initalization");
}

int
lxt_server_pid(int *pid)
{
	if (lxt_server_processes == 0)
		return (0);
	*pid = lxt_pid;
	return (1);
}
