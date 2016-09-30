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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>

#include <pthread.h>
#include <stddef.h>
#include <dlfcn.h>
#include <link.h>
#include <libproc.h>

#include <Python.h>
#include <frameobject.h>

/*
 * Decoding Python Stack Frames
 * ============================
 *
 * Python2 uses a variety of objects to construct its call chain.  An address
 * space may have one or more PyInterpreterState objects, which are the base
 * object in the interpreter's state.  These objects are kept in a linked list
 * with a head pointer named interp_head.  This makes it possible for the
 * debugger to get a toehold on data structures necessary to understand the
 * interpreter.  Since most of these structures are linked out of the
 * InterpreterState, traversals generally start here.
 *
 * In order to decode a frame, the debugger needs to walk from
 * PyInterpreterState down to a PyCodeObject.  The diagram below shows the
 * the objects that must be examined in order to reach a leaf PyCodeObject.
 *
 *                +--------------------+ next   +--------------------+ next
 * interp_head -> | PyInterpreterState | ---->  | PyInterpreterState | ---> ...
 *                +--------------------+        +--------------------+
 *                  |                            | tstate_head
 *                  | tstate_head                V
 *                  |                 +---------------+  frame
 *                  V                 | PyThreadState | -----> ...
 *  +---------------+  frame          +---------------+
 *  | PyThreadState |  ---> ...
 *  +---------------+
 *          | next
 *          V
 *  +---------------+  frame    +---------------+ f_back +---------------+
 *  | PyThreadState |  ------>  | PyFrameObject | -----> | PyFrameObject |
 *  +---------------+           +---------------+        +---------------+
 *                                      |                       |
 *                                      | f_code                | f_code
 *                                      V                       V
 *                              +--------------+               ...
 *                              | PyCodeObject |
 *                              +--------------+
 *                 co_filename   |      |     | co_lnotab
 *                 +-------------+      |     +-------------+
 *                 |           co_name  |                   |
 *                 V                    V                   V
 * +----------------+          +----------------+         +----------------+
 * | PyStringObject |          | PyStringObject |         | PyStringObject |
 * +----------------+          +----------------+         +----------------+
 *
 * The interp_head pointer is a list of one or more PyInterpreterState
 * objects.  Each of these objects can contain one or more PyThreadState
 * objects.  The PyInterpreterState object keeps a pointer to the head of the
 * list of PyThreadState objects as tstate_head.
 *
 * Each thread keeps ahold of its stack frames.  The PyThreadState object
 * has a pointer to the topmost PyFrameObject, kept in frame.  The
 * successive frames on the stack are kept linked in the PyFrameObject's
 * f_back pointer, with each frame pointing to its caller.
 *
 * In order to decode each call frame, our code needs to look at the
 * PyCodeObject for each frame.  Essentially, this is the code that is
 * being executed in the frame.  The PyFrameObject keeps a pointer to this
 * code object in f_code.  In order to print meaningful debug information,
 * it's necessary to extract the Python filename (co_filename), the
 * function name (co_name), and the line number within the file
 * (co_lnotab).  The filename and function are stored as strings, but the
 * line number is a mapping of bytecode offsets to line numbers.  The
 * description of the lnotab algorithm lives here:
 *
 * http://svn.python.org/projects/python/trunk/Objects/lnotab_notes.txt
 *
 * In order to decode the frame, the debugger needs to walk each
 * InterpreterState object.  For each InterpreterState, every PyThreadState
 * must be traversed.  The PyThreadState objects point to the
 * PyFrameObjects.  For every thread, we must walk the frames backwards and
 * decode the strings that are in the PyCodeObjects.
 */

/*
 * The Python-dependent debugging functionality lives in its own helper
 * library.  The helper agent is provided by libpython2.[67]_db.so, which
 * is also used by pstack(1) for debugging Python processes.
 *
 * Define needed prototypes here.
 */

#define	PYDB_VERSION	1
typedef struct pydb_agent pydb_agent_t;
typedef struct pydb_iter pydb_iter_t;

typedef pydb_agent_t *(*pydb_agent_create_f)(struct ps_prochandle *P, int vers);
typedef void (*pydb_agent_destroy_f)(pydb_agent_t *py);
typedef int (*pydb_get_frameinfo_f)(pydb_agent_t *py, uintptr_t frame_addr,
    char *fbuf, size_t bufsz, int verbose);
typedef pydb_iter_t *(*pydb_iter_init_f)(pydb_agent_t *py, uintptr_t addr);
typedef uintptr_t (*pydb_iter_next_f)(pydb_iter_t *iter);
typedef void (*pydb_iter_fini_f)(pydb_iter_t *iter);

static pydb_agent_create_f pydb_agent_create;
static pydb_agent_destroy_f pydb_agent_destroy;
static pydb_get_frameinfo_f pydb_get_frameinfo;
static pydb_iter_init_f pydb_frame_iter_init;
static pydb_iter_init_f pydb_interp_iter_init;
static pydb_iter_init_f pydb_thread_iter_init;
static pydb_iter_next_f pydb_iter_next;
static pydb_iter_fini_f pydb_iter_fini;

static pydb_agent_t *pydb_hdl = NULL;
static void *pydb_dlhdl = NULL;

/*ARGSUSED*/
static int
py_frame(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char buf[1024];
	int verbose = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (flags & DCMD_PIPE_OUT) {
		mdb_warn("py_stack cannot output into a pipe\n");
		return (DCMD_ERR);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("no address");
		return (DCMD_USAGE);
	}

	if (pydb_get_frameinfo(pydb_hdl, addr, buf, sizeof (buf),
	    verbose) < 0) {
		mdb_warn("Unable to find frame at address %p\n", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%s", buf);

	return (DCMD_OK);
}

int
py_interp_walk_init(mdb_walk_state_t *wsp)
{
	pydb_iter_t *pdi;

	pdi = pydb_interp_iter_init(pydb_hdl, wsp->walk_addr);

	if (pdi == NULL) {
		mdb_warn("unable to create interpreter iterator\n");
		return (DCMD_ERR);
	}

	wsp->walk_data = pdi;

	return (WALK_NEXT);
}

int
py_walk_step(mdb_walk_state_t *wsp)
{
	pydb_iter_t *pdi = wsp->walk_data;
	uintptr_t addr;
	int status;

	addr = pydb_iter_next(pdi);

	if (addr == NULL) {
		return (WALK_DONE);
	}

	status = wsp->walk_callback(addr, 0, wsp->walk_cbdata);

	return (status);
}

void
py_walk_fini(mdb_walk_state_t *wsp)
{
	pydb_iter_t *pdi = wsp->walk_data;
	pydb_iter_fini(pdi);
}

int
py_thread_walk_init(mdb_walk_state_t *wsp)
{
	pydb_iter_t *pdi;

	pdi = pydb_thread_iter_init(pydb_hdl, wsp->walk_addr);
	if (pdi == NULL) {
		mdb_warn("unable to create thread iterator\n");
		return (DCMD_ERR);
	}

	wsp->walk_data = pdi;

	return (WALK_NEXT);
}

int
py_frame_walk_init(mdb_walk_state_t *wsp)
{
	pydb_iter_t *pdi;

	pdi = pydb_frame_iter_init(pydb_hdl, wsp->walk_addr);
	if (pdi == NULL) {
		mdb_warn("unable to create frame iterator\n");
		return (DCMD_ERR);
	}

	wsp->walk_data = pdi;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
python_stack(uintptr_t addr, const PyThreadState *ts, uint_t *verbose)
{
	mdb_arg_t nargv;
	uint_t nargc = (verbose != NULL && *verbose) ? 1 : 0;
	/*
	 * Pass the ThreadState to the frame walker. Have frame walker
	 * call frame dcmd.
	 */
	mdb_printf("PyThreadState: %0?p\n", addr);

	nargv.a_type = MDB_TYPE_STRING;
	nargv.a_un.a_str = "-v";

	if (mdb_pwalk_dcmd("pyframe", "pyframe", nargc, &nargv, addr) == -1) {
		mdb_warn("can't walk 'pyframe'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
python_thread(uintptr_t addr, const PyInterpreterState *is, uint_t *verbose)
{
	/*
	 * Pass the InterpreterState to the threadstate walker.
	 */
	if (mdb_pwalk("pythread", (mdb_walk_cb_t)python_stack, verbose,
	    addr) == -1) {
		mdb_warn("can't walk 'pythread'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
py_stack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (flags & DCMD_PIPE_OUT) {
		mdb_warn("py_stack cannot output into a pipe\n");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC) {
		mdb_arg_t nargv;
		uint_t nargc = verbose ? 1 : 0;

		nargv.a_type = MDB_TYPE_STRING;
		nargv.a_un.a_str = "-v";

		if (mdb_pwalk_dcmd("pyframe", "pyframe", nargc, &nargv, addr)
		    == -1) {
			mdb_warn("can't walk 'pyframe'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_walk("pyinterp", (mdb_walk_cb_t)python_thread,
	    &verbose) == -1) {
		mdb_warn("can't walk 'pyinterp'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "pystack", "[-v]", "print python stacks", py_stack },
	{ "pyframe", "[-v]", "print python frames", py_frame },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "pyinterp", "walk python interpreter structures",
		py_interp_walk_init, py_walk_step, py_walk_fini },
	{ "pythread", "given an interpreter, walk the list of python threads",
		py_thread_walk_init, py_walk_step, py_walk_fini },
	{ "pyframe", "given a thread state, walk the list of frame objects",
		py_frame_walk_init, py_walk_step, py_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

/*ARGSUSED*/
static int
python_object_iter(void *cd, const prmap_t *pmp, const char *obj)
{
	char path[PATH_MAX];
	char *name;
	char *s1, *s2;
	struct ps_prochandle *Pr = cd;

	name = strstr(obj, "/libpython");

	if (name) {
		(void) strcpy(path, obj);
		if (Pstatus(Pr)->pr_dmodel != PR_MODEL_NATIVE) {
			s1 = name;
			s2 = path + (s1 - obj);
			(void) strcpy(s2, "/64");
			s2 += 3;
			(void) strcpy(s2, s1);
		}

		s1 = strstr(obj, ".so");
		s2 = strstr(path, ".so");
		(void) strcpy(s2, "_db");
		s2 += 3;
		(void) strcpy(s2, s1);

		if ((pydb_dlhdl = dlopen(path, RTLD_LAZY|RTLD_GLOBAL)) != NULL)
			return (1);
	}

	return (0);
}

static int
python_db_init(void)
{
	struct ps_prochandle *Ph;

	if (mdb_get_xdata("pshandle", &Ph, sizeof (Ph)) == -1) {
		mdb_warn("couldn't read pshandle xdata\n");
		dlclose(pydb_dlhdl);
		pydb_dlhdl = NULL;
		return (-1);
	}

	(void) Pobject_iter(Ph, python_object_iter, Ph);

	pydb_agent_create = (pydb_agent_create_f)
	    dlsym(pydb_dlhdl, "pydb_agent_create");
	pydb_agent_destroy = (pydb_agent_destroy_f)
	    dlsym(pydb_dlhdl, "pydb_agent_destroy");
	pydb_get_frameinfo = (pydb_get_frameinfo_f)
	    dlsym(pydb_dlhdl, "pydb_get_frameinfo");

	pydb_frame_iter_init = (pydb_iter_init_f)
	    dlsym(pydb_dlhdl, "pydb_frame_iter_init");
	pydb_interp_iter_init = (pydb_iter_init_f)
	    dlsym(pydb_dlhdl, "pydb_interp_iter_init");
	pydb_thread_iter_init = (pydb_iter_init_f)
	    dlsym(pydb_dlhdl, "pydb_thread_iter_init");
	pydb_iter_next = (pydb_iter_next_f)dlsym(pydb_dlhdl, "pydb_iter_next");
	pydb_iter_fini = (pydb_iter_fini_f)dlsym(pydb_dlhdl, "pydb_iter_fini");


	if (pydb_agent_create == NULL || pydb_agent_destroy == NULL ||
	    pydb_get_frameinfo == NULL || pydb_frame_iter_init == NULL ||
	    pydb_interp_iter_init == NULL || pydb_thread_iter_init == NULL ||
	    pydb_iter_next == NULL || pydb_iter_fini == NULL) {
		mdb_warn("couldn't load pydb functions");
		dlclose(pydb_dlhdl);
		pydb_dlhdl = NULL;
		return (-1);
	}

	pydb_hdl = pydb_agent_create(Ph, PYDB_VERSION);
	if (pydb_hdl == NULL) {
		mdb_warn("unable to create pydb_agent");
		dlclose(pydb_dlhdl);
		pydb_dlhdl = NULL;
		return (-1);
	}

	return (0);
}

static void
python_db_fini(void)
{
	if (pydb_dlhdl) {
		pydb_agent_destroy(pydb_hdl);
		pydb_hdl = NULL;

		dlclose(pydb_dlhdl);
		pydb_dlhdl = NULL;
	}
}

const mdb_modinfo_t *
_mdb_init(void)
{
	if (python_db_init() != 0)
		return (NULL);

	return (&modinfo);
}

void
_mdb_fini(void)
{
	python_db_fini();
}
