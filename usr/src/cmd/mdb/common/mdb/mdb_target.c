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
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * MDB Target Layer
 *
 * The *target* is the program being inspected by the debugger.  The MDB target
 * layer provides a set of functions that insulate common debugger code,
 * including the MDB Module API, from the implementation details of how the
 * debugger accesses information from a given target.  Each target exports a
 * standard set of properties, including one or more address  spaces, one or
 * more symbol tables, a set of load objects, and a set of threads that can be
 * examined using the interfaces in <mdb/mdb_target.h>.  This technique has
 * been employed successfully in other debuggers, including [1], primarily
 * to improve portability, although the term "target" often refers to the
 * encapsulation of architectural or operating system-specific details.  The
 * target abstraction is useful for MDB because it allows us to easily extend
 * the debugger to examine a variety of different program forms.  Primarily,
 * the target functions validate input arguments and then call an appropriate
 * function in the target ops vector, defined in <mdb/mdb_target_impl.h>.
 * However, this interface layer provides a very high level of flexibility for
 * separating the debugger interface from instrumentation details.  Experience
 * has shown this kind of design can facilitate separating out debugger
 * instrumentation into an external agent [2] and enable the development of
 * advanced instrumentation frameworks [3].  We want MDB to be an ideal
 * extensible framework for the development of such applications.
 *
 * Aside from a set of wrapper functions, the target layer also provides event
 * management for targets that represent live executing programs.  Our model of
 * events is also extensible, and is based upon work in [3] and [4].  We define
 * a *software event* as a state transition in the target program (for example,
 * the transition of the program counter to a location of interest) that is
 * observed by the debugger or its agent.  A *software event specifier* is a
 * description of a class of software events that is used by the debugger to
 * instrument the target so that the corresponding software events can be
 * observed.  In MDB, software event specifiers are represented by the
 * mdb_sespec_t structure, defined in <mdb/mdb_target_impl.h>.  As the user,
 * the internal debugger code, and MDB modules may all wish to observe software
 * events and receive appropriate notification and callbacks, we do not expose
 * software event specifiers directly as part of the user interface.  Instead,
 * clients of the target layer request that events be observed by creating
 * new *virtual event specifiers*.  Each virtual specifier is named by a unique
 * non-zero integer (the VID), and is represented by a mdb_vespec_t structure.
 * One or more virtual specifiers are then associated with each underlying
 * software event specifier.  This design enforces the constraint that the
 * target must only insert one set of instrumentation, regardless of how many
 * times the target layer was asked to trace a given event.  For example, if
 * multiple clients request a breakpoint at a particular address, the virtual
 * specifiers will map to the same sespec, ensuring that only one breakpoint
 * trap instruction is actually planted at the given target address.  When no
 * virtual specifiers refer to an sespec, it is no longer needed and can be
 * removed, along with the corresponding instrumentation.
 *
 * The following state transition diagram illustrates the life cycle of a
 * software event specifier and example transitions:
 *
 *                                         cont/
 *     +--------+   delete   +--------+    stop    +-------+
 *    (|( DEAD )|) <------- (  ACTIVE  ) <------> (  ARMED  )
 *     +--------+            +--------+            +-------+
 *          ^   load/unload  ^        ^   failure/     |
 *   delete |        object /          \  reset        | failure
 *          |              v            v              |
 *          |      +--------+          +-------+       |
 *          +---- (   IDLE   )        (   ERR   ) <----+
 *          |      +--------+          +-------+
 *          |                              |
 *          +------------------------------+
 *
 * The MDB execution control model is based upon the synchronous debugging
 * model exported by Solaris proc(4).  A target program is set running or the
 * debugger is attached to a running target.  On ISTOP (stop on event of
 * interest), one target thread is selected as the representative.  The
 * algorithm for selecting the representative is target-specific, but we assume
 * that if an observed software event has occurred, the target will select the
 * thread that triggered the state transition of interest.  The other threads
 * are stopped in sympathy with the representative as soon as possible.  Prior
 * to continuing the target, we plant our instrumentation, transitioning event
 * specifiers from the ACTIVE to the ARMED state, and then back again when the
 * target stops.  We then query each active event specifier to learn which ones
 * are matched, and then invoke the callbacks associated with their vespecs.
 * If an OS error occurs while attempting to arm or disarm a specifier, the
 * specifier is transitioned to the ERROR state; we will attempt to arm it
 * again at the next continue.  If no target process is under our control or
 * if an event is not currently applicable (e.g. a deferred breakpoint on an
 * object that is not yet loaded), it remains in the IDLE state.  The target
 * implementation should intercept object load events and then transition the
 * specifier to the ACTIVE state when the corresponding object is loaded.
 *
 * To simplify the debugger implementation and allow targets to easily provide
 * new types of observable events, most of the event specifier management is
 * done by the target layer.  Each software event specifier provides an ops
 * vector of subroutines that the target layer can call to perform the
 * various state transitions described above.  The target maintains two lists
 * of mdb_sespec_t's: the t_idle list (IDLE state) and the t_active list
 * (ACTIVE, ARMED, and ERROR states).  Each mdb_sespec_t maintains a list of
 * associated mdb_vespec_t's.  If an sespec is IDLE or ERROR, its se_errno
 * field will have an errno value specifying the reason for its inactivity.
 * The vespec stores the client's callback function and private data, and the
 * arguments used to construct the sespec.  All objects are reference counted
 * so we can destroy an object when it is no longer needed.  The mdb_sespec_t
 * invariants for the respective states are as follows:
 *
 *   IDLE: on t_idle list, se_data == NULL, se_errno != 0, se_ctor not called
 * ACTIVE: on t_active list, se_data valid, se_errno == 0, se_ctor called
 *  ARMED: on t_active list, se_data valid, se_errno == 0, se_ctor called
 *  ERROR: on t_active list, se_data valid, se_errno != 0, se_ctor called
 *
 * Additional commentary on specific state transitions and issues involving
 * event management can be found below near the target layer functions.
 *
 * References
 *
 * [1] John Gilmore, "Working in GDB", Technical Report, Cygnus Support,
 *     1.84 edition, 1994.
 *
 * [2] David R. Hanson and Mukund Raghavachari, "A Machine-Independent
 *     Debugger", Software--Practice and Experience, 26(11), 1277-1299(1996).
 *
 * [3] Michael W. Shapiro, "RDB: A System for Incremental Replay Debugging",
 *     Technical Report CS-97-12, Department of Computer Science,
 *     Brown University.
 *
 * [4] Daniel B. Price, "New Techniques for Replay Debugging", Technical
 *     Report CS-98-05, Department of Computer Science, Brown University.
 */

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_callb.h>
#include <mdb/mdb_gelf.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_signal.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>

/*
 * Define convenience macros for referencing the set of vespec flag bits that
 * are preserved by the target implementation, and the set of bits that
 * determine automatic ve_hits == ve_limit behavior.
 */
#define	T_IMPL_BITS	\
	(MDB_TGT_SPEC_INTERNAL | MDB_TGT_SPEC_SILENT | MDB_TGT_SPEC_MATCHED | \
	MDB_TGT_SPEC_DELETED)

#define	T_AUTO_BITS	\
	(MDB_TGT_SPEC_AUTOSTOP | MDB_TGT_SPEC_AUTODEL | MDB_TGT_SPEC_AUTODIS)

/*
 * Define convenience macro for referencing target flag pending continue bits.
 */
#define	T_CONT_BITS	\
	(MDB_TGT_F_STEP | MDB_TGT_F_STEP_OUT | MDB_TGT_F_NEXT | MDB_TGT_F_CONT)

mdb_tgt_t *
mdb_tgt_create(mdb_tgt_ctor_f *ctor, int flags, int argc, const char *argv[])
{
	mdb_module_t *mp;
	mdb_tgt_t *t;

	if (flags & ~MDB_TGT_F_ALL) {
		(void) set_errno(EINVAL);
		return (NULL);
	}

	t = mdb_zalloc(sizeof (mdb_tgt_t), UM_SLEEP);
	mdb_list_append(&mdb.m_tgtlist, t);

	t->t_module = &mdb.m_rmod;
	t->t_matched = T_SE_END;
	t->t_flags = flags;
	t->t_vepos = 1;
	t->t_veneg = 1;

	for (mp = mdb.m_mhead; mp != NULL; mp = mp->mod_next) {
		if (ctor == mp->mod_tgt_ctor) {
			t->t_module = mp;
			break;
		}
	}

	if (ctor(t, argc, argv) != 0) {
		mdb_list_delete(&mdb.m_tgtlist, t);
		mdb_free(t, sizeof (mdb_tgt_t));
		return (NULL);
	}

	mdb_dprintf(MDB_DBG_TGT, "t_create %s (%p)\n",
	    t->t_module->mod_name, (void *)t);

	(void) t->t_ops->t_status(t, &t->t_status);
	return (t);
}

int
mdb_tgt_getflags(mdb_tgt_t *t)
{
	return (t->t_flags);
}

int
mdb_tgt_setflags(mdb_tgt_t *t, int flags)
{
	if (flags & ~MDB_TGT_F_ALL)
		return (set_errno(EINVAL));

	return (t->t_ops->t_setflags(t, flags));
}

int
mdb_tgt_setcontext(mdb_tgt_t *t, void *context)
{
	return (t->t_ops->t_setcontext(t, context));
}

/*ARGSUSED*/
static int
tgt_delete_vespec(mdb_tgt_t *t, void *private, int vid, void *data)
{
	(void) mdb_tgt_vespec_delete(t, vid);
	return (0);
}

void
mdb_tgt_destroy(mdb_tgt_t *t)
{
	mdb_xdata_t *xdp, *nxdp;

	if (mdb.m_target == t) {
		mdb_dprintf(MDB_DBG_TGT, "t_deactivate %s (%p)\n",
		    t->t_module->mod_name, (void *)t);
		t->t_ops->t_deactivate(t);
		mdb.m_target = NULL;
	}

	mdb_dprintf(MDB_DBG_TGT, "t_destroy %s (%p)\n",
	    t->t_module->mod_name, (void *)t);

	for (xdp = mdb_list_next(&t->t_xdlist); xdp != NULL; xdp = nxdp) {
		nxdp = mdb_list_next(xdp);
		mdb_list_delete(&t->t_xdlist, xdp);
		mdb_free(xdp, sizeof (mdb_xdata_t));
	}

	mdb_tgt_sespec_idle_all(t, EBUSY, TRUE);
	(void) mdb_tgt_vespec_iter(t, tgt_delete_vespec, NULL);
	t->t_ops->t_destroy(t);

	mdb_list_delete(&mdb.m_tgtlist, t);
	mdb_free(t, sizeof (mdb_tgt_t));

	if (mdb.m_target == NULL)
		mdb_tgt_activate(mdb_list_prev(&mdb.m_tgtlist));
}

void
mdb_tgt_activate(mdb_tgt_t *t)
{
	mdb_tgt_t *otgt = mdb.m_target;

	if (mdb.m_target != NULL) {
		mdb_dprintf(MDB_DBG_TGT, "t_deactivate %s (%p)\n",
		    mdb.m_target->t_module->mod_name, (void *)mdb.m_target);
		mdb.m_target->t_ops->t_deactivate(mdb.m_target);
	}

	if ((mdb.m_target = t) != NULL) {
		const char *v = strstr(mdb.m_root, "%V");

		mdb_dprintf(MDB_DBG_TGT, "t_activate %s (%p)\n",
		    t->t_module->mod_name, (void *)t);

		/*
		 * If the root was explicitly set with -R and contains %V,
		 * expand it like a path.  If the resulting directory is
		 * not present, then replace %V with "latest" and re-evaluate.
		 */
		if (v != NULL) {
			char old_root[MAXPATHLEN];
			const char **p;
#ifndef _KMDB
			struct stat s;
#endif
			size_t len;

			p = mdb_path_alloc(mdb.m_root, &len);
			(void) strcpy(old_root, mdb.m_root);
			(void) strncpy(mdb.m_root, p[0], MAXPATHLEN);
			mdb.m_root[MAXPATHLEN - 1] = '\0';
			mdb_path_free(p, len);

#ifndef _KMDB
			if (stat(mdb.m_root, &s) == -1 && errno == ENOENT) {
				mdb.m_flags |= MDB_FL_LATEST;
				p = mdb_path_alloc(old_root, &len);
				(void) strncpy(mdb.m_root, p[0], MAXPATHLEN);
				mdb.m_root[MAXPATHLEN - 1] = '\0';
				mdb_path_free(p, len);
			}
#endif
		}

		/*
		 * Re-evaluate the macro and dmod paths now that we have the
		 * new target set and m_root figured out.
		 */
		if (otgt == NULL) {
			mdb_set_ipath(mdb.m_ipathstr);
			mdb_set_lpath(mdb.m_lpathstr);
		}

		t->t_ops->t_activate(t);
	}
}

void
mdb_tgt_periodic(mdb_tgt_t *t)
{
	t->t_ops->t_periodic(t);
}

const char *
mdb_tgt_name(mdb_tgt_t *t)
{
	return (t->t_ops->t_name(t));
}

const char *
mdb_tgt_isa(mdb_tgt_t *t)
{
	return (t->t_ops->t_isa(t));
}

const char *
mdb_tgt_platform(mdb_tgt_t *t)
{
	return (t->t_ops->t_platform(t));
}

int
mdb_tgt_uname(mdb_tgt_t *t, struct utsname *utsp)
{
	return (t->t_ops->t_uname(t, utsp));
}

int
mdb_tgt_dmodel(mdb_tgt_t *t)
{
	return (t->t_ops->t_dmodel(t));
}

int
mdb_tgt_auxv(mdb_tgt_t *t, const auxv_t **auxvp)
{
	return (t->t_ops->t_auxv(t, auxvp));
}

ssize_t
mdb_tgt_aread(mdb_tgt_t *t, mdb_tgt_as_t as,
    void *buf, size_t n, mdb_tgt_addr_t addr)
{
	if (t->t_flags & MDB_TGT_F_ASIO)
		return (t->t_ops->t_aread(t, as, buf, n, addr));

	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_VIRT:
		return (t->t_ops->t_vread(t, buf, n, addr));
	case (uintptr_t)MDB_TGT_AS_PHYS:
		return (t->t_ops->t_pread(t, buf, n, addr));
	case (uintptr_t)MDB_TGT_AS_FILE:
		return (t->t_ops->t_fread(t, buf, n, addr));
	case (uintptr_t)MDB_TGT_AS_IO:
		return (t->t_ops->t_ioread(t, buf, n, addr));
	}
	return (t->t_ops->t_aread(t, as, buf, n, addr));
}

ssize_t
mdb_tgt_awrite(mdb_tgt_t *t, mdb_tgt_as_t as,
    const void *buf, size_t n, mdb_tgt_addr_t addr)
{
	if (!(t->t_flags & MDB_TGT_F_RDWR))
		return (set_errno(EMDB_TGTRDONLY));

	if (t->t_flags & MDB_TGT_F_ASIO)
		return (t->t_ops->t_awrite(t, as, buf, n, addr));

	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_VIRT:
		return (t->t_ops->t_vwrite(t, buf, n, addr));
	case (uintptr_t)MDB_TGT_AS_PHYS:
		return (t->t_ops->t_pwrite(t, buf, n, addr));
	case (uintptr_t)MDB_TGT_AS_FILE:
		return (t->t_ops->t_fwrite(t, buf, n, addr));
	case (uintptr_t)MDB_TGT_AS_IO:
		return (t->t_ops->t_iowrite(t, buf, n, addr));
	}
	return (t->t_ops->t_awrite(t, as, buf, n, addr));
}

ssize_t
mdb_tgt_vread(mdb_tgt_t *t, void *buf, size_t n, uintptr_t addr)
{
	return (t->t_ops->t_vread(t, buf, n, addr));
}

ssize_t
mdb_tgt_vwrite(mdb_tgt_t *t, const void *buf, size_t n, uintptr_t addr)
{
	if (t->t_flags & MDB_TGT_F_RDWR)
		return (t->t_ops->t_vwrite(t, buf, n, addr));

	return (set_errno(EMDB_TGTRDONLY));
}

ssize_t
mdb_tgt_pread(mdb_tgt_t *t, void *buf, size_t n, physaddr_t addr)
{
	return (t->t_ops->t_pread(t, buf, n, addr));
}

ssize_t
mdb_tgt_pwrite(mdb_tgt_t *t, const void *buf, size_t n, physaddr_t addr)
{
	if (t->t_flags & MDB_TGT_F_RDWR)
		return (t->t_ops->t_pwrite(t, buf, n, addr));

	return (set_errno(EMDB_TGTRDONLY));
}

ssize_t
mdb_tgt_fread(mdb_tgt_t *t, void *buf, size_t n, uintptr_t addr)
{
	return (t->t_ops->t_fread(t, buf, n, addr));
}

ssize_t
mdb_tgt_fwrite(mdb_tgt_t *t, const void *buf, size_t n, uintptr_t addr)
{
	if (t->t_flags & MDB_TGT_F_RDWR)
		return (t->t_ops->t_fwrite(t, buf, n, addr));

	return (set_errno(EMDB_TGTRDONLY));
}

ssize_t
mdb_tgt_ioread(mdb_tgt_t *t, void *buf, size_t n, uintptr_t addr)
{
	return (t->t_ops->t_ioread(t, buf, n, addr));
}

ssize_t
mdb_tgt_iowrite(mdb_tgt_t *t, const void *buf, size_t n, uintptr_t addr)
{
	if (t->t_flags & MDB_TGT_F_RDWR)
		return (t->t_ops->t_iowrite(t, buf, n, addr));

	return (set_errno(EMDB_TGTRDONLY));
}

int
mdb_tgt_vtop(mdb_tgt_t *t, mdb_tgt_as_t as, uintptr_t va, physaddr_t *pap)
{
	return (t->t_ops->t_vtop(t, as, va, pap));
}

ssize_t
mdb_tgt_readstr(mdb_tgt_t *t, mdb_tgt_as_t as, char *buf,
    size_t nbytes, mdb_tgt_addr_t addr)
{
	ssize_t n, nread = mdb_tgt_aread(t, as, buf, nbytes, addr);
	char *p;

	if (nread >= 0) {
		if ((p = memchr(buf, '\0', nread)) != NULL)
			nread = (size_t)(p - buf);
		goto done;
	}

	nread = 0;
	p = &buf[0];

	while (nread < nbytes && (n = mdb_tgt_aread(t, as, p, 1, addr)) == 1) {
		if (*p == '\0')
			return (nread);
		nread++;
		addr++;
		p++;
	}

	if (nread == 0 && n == -1)
		return (-1); /* If we can't even read a byte, return -1 */

done:
	if (nbytes != 0)
		buf[MIN(nread, nbytes - 1)] = '\0';

	return (nread);
}

ssize_t
mdb_tgt_writestr(mdb_tgt_t *t, mdb_tgt_as_t as,
    const char *buf, mdb_tgt_addr_t addr)
{
	ssize_t nwritten = mdb_tgt_awrite(t, as, buf, strlen(buf) + 1, addr);
	return (nwritten > 0 ? nwritten - 1 : nwritten);
}

int
mdb_tgt_lookup_by_name(mdb_tgt_t *t, const char *obj,
    const char *name, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	mdb_syminfo_t info;
	GElf_Sym sym;
	uint_t id;

	if (name == NULL || t == NULL)
		return (set_errno(EINVAL));

	if (obj == MDB_TGT_OBJ_EVERY &&
	    mdb_gelf_symtab_lookup_by_name(mdb.m_prsym, name, &sym, &id) == 0) {
		info.sym_table = MDB_TGT_PRVSYM;
		info.sym_id = id;
		goto found;
	}

	if (t->t_ops->t_lookup_by_name(t, obj, name, &sym, &info) == 0)
		goto found;

	return (-1);

found:
	if (symp != NULL)
		*symp = sym;
	if (sip != NULL)
		*sip = info;
	return (0);
}

int
mdb_tgt_lookup_by_addr(mdb_tgt_t *t, uintptr_t addr, uint_t flags,
    char *buf, size_t len, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	mdb_syminfo_t info;
	GElf_Sym sym;

	if (t == NULL)
		return (set_errno(EINVAL));

	if (t->t_ops->t_lookup_by_addr(t, addr, flags,
	    buf, len, &sym, &info) == 0) {
		if (symp != NULL)
			*symp = sym;
		if (sip != NULL)
			*sip = info;
		return (0);
	}

	return (-1);
}

/*
 * The mdb_tgt_lookup_by_scope function is a convenience routine for code that
 * wants to look up a scoped symbol name such as "object`symbol".  It is
 * implemented as a simple wrapper around mdb_tgt_lookup_by_name.  Note that
 * we split on the *last* occurrence of "`", so the object name itself may
 * contain additional scopes whose evaluation is left to the target.  This
 * allows targets to implement additional scopes, such as source files,
 * function names, link map identifiers, etc.
 */
int
mdb_tgt_lookup_by_scope(mdb_tgt_t *t, const char *s, GElf_Sym *symp,
    mdb_syminfo_t *sip)
{
	const char *object = MDB_TGT_OBJ_EVERY;
	const char *name = s;
	char buf[MDB_TGT_SYM_NAMLEN];

	if (t == NULL)
		return (set_errno(EINVAL));

	if (strchr(name, '`') != NULL) {

		(void) strncpy(buf, s, sizeof (buf));
		buf[sizeof (buf) - 1] = '\0';
		name = buf;

		if ((s = strrsplit(buf, '`')) != NULL) {
			object = buf;
			name = s;
			if (*object == '\0')
				return (set_errno(EMDB_NOOBJ));
			if (*name == '\0')
				return (set_errno(EMDB_NOSYM));
		}
	}

	return (mdb_tgt_lookup_by_name(t, object, name, symp, sip));
}

int
mdb_tgt_symbol_iter(mdb_tgt_t *t, const char *obj, uint_t which,
    uint_t type, mdb_tgt_sym_f *cb, void *p)
{
	if ((which != MDB_TGT_SYMTAB && which != MDB_TGT_DYNSYM) ||
	    (type & ~(MDB_TGT_BIND_ANY | MDB_TGT_TYPE_ANY)) != 0)
		return (set_errno(EINVAL));

	return (t->t_ops->t_symbol_iter(t, obj, which, type, cb, p));
}

ssize_t
mdb_tgt_readsym(mdb_tgt_t *t, mdb_tgt_as_t as, void *buf, size_t nbytes,
    const char *obj, const char *name)
{
	GElf_Sym sym;

	if (mdb_tgt_lookup_by_name(t, obj, name, &sym, NULL) == 0)
		return (mdb_tgt_aread(t, as, buf, nbytes, sym.st_value));

	return (-1);
}

ssize_t
mdb_tgt_writesym(mdb_tgt_t *t, mdb_tgt_as_t as, const void *buf,
    size_t nbytes, const char *obj, const char *name)
{
	GElf_Sym sym;

	if (mdb_tgt_lookup_by_name(t, obj, name, &sym, NULL) == 0)
		return (mdb_tgt_awrite(t, as, buf, nbytes, sym.st_value));

	return (-1);
}

int
mdb_tgt_mapping_iter(mdb_tgt_t *t, mdb_tgt_map_f *cb, void *p)
{
	return (t->t_ops->t_mapping_iter(t, cb, p));
}

int
mdb_tgt_object_iter(mdb_tgt_t *t, mdb_tgt_map_f *cb, void *p)
{
	return (t->t_ops->t_object_iter(t, cb, p));
}

const mdb_map_t *
mdb_tgt_addr_to_map(mdb_tgt_t *t, uintptr_t addr)
{
	return (t->t_ops->t_addr_to_map(t, addr));
}

const mdb_map_t *
mdb_tgt_name_to_map(mdb_tgt_t *t, const char *name)
{
	return (t->t_ops->t_name_to_map(t, name));
}

struct ctf_file *
mdb_tgt_addr_to_ctf(mdb_tgt_t *t, uintptr_t addr)
{
	return (t->t_ops->t_addr_to_ctf(t, addr));
}

struct ctf_file *
mdb_tgt_name_to_ctf(mdb_tgt_t *t, const char *name)
{
	return (t->t_ops->t_name_to_ctf(t, name));
}

/*
 * Return the latest target status.  We just copy out our cached copy.  The
 * status only needs to change when the target is run, stepped, or continued.
 */
int
mdb_tgt_status(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	uint_t dstop = (t->t_status.st_flags & MDB_TGT_DSTOP);
	uint_t istop = (t->t_status.st_flags & MDB_TGT_ISTOP);
	uint_t state = t->t_status.st_state;

	if (tsp == NULL)
		return (set_errno(EINVAL));

	/*
	 * If we're called with the address of the target's internal status,
	 * then call down to update it; otherwise copy out the saved status.
	 */
	if (tsp == &t->t_status && t->t_ops->t_status(t, &t->t_status) != 0)
		return (-1); /* errno is set for us */

	/*
	 * Assert that our state is valid before returning it.  The state must
	 * be valid, and DSTOP and ISTOP cannot be set simultaneously.  ISTOP
	 * is only valid when stopped.  DSTOP is only valid when running or
	 * stopped.  If any test fails, abort the debugger.
	 */
	if (state > MDB_TGT_LOST)
		fail("invalid target state (%u)\n", state);
	if (state != MDB_TGT_STOPPED && istop)
		fail("target state is (%u) and ISTOP is set\n", state);
	if (state != MDB_TGT_STOPPED && state != MDB_TGT_RUNNING && dstop)
		fail("target state is (%u) and DSTOP is set\n", state);
	if (istop && dstop)
		fail("target has ISTOP and DSTOP set simultaneously\n");

	if (tsp != &t->t_status)
		bcopy(&t->t_status, tsp, sizeof (mdb_tgt_status_t));

	return (0);
}

/*
 * For the given sespec, scan its list of vespecs for ones that are marked
 * temporary and delete them.  We use the same method as vespec_delete below.
 */
/*ARGSUSED*/
void
mdb_tgt_sespec_prune_one(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	mdb_vespec_t *vep, *nvep;

	for (vep = mdb_list_next(&sep->se_velist); vep; vep = nvep) {
		nvep = mdb_list_next(vep);

		if ((vep->ve_flags & (MDB_TGT_SPEC_DELETED |
		    MDB_TGT_SPEC_TEMPORARY)) == MDB_TGT_SPEC_TEMPORARY) {
			vep->ve_flags |= MDB_TGT_SPEC_DELETED;
			mdb_tgt_vespec_rele(t, vep);
		}
	}
}

/*
 * Prune each sespec on the active list of temporary vespecs.  This function
 * is called, for example, after the target finishes a continue operation.
 */
void
mdb_tgt_sespec_prune_all(mdb_tgt_t *t)
{
	mdb_sespec_t *sep, *nsep;

	for (sep = mdb_list_next(&t->t_active); sep != NULL; sep = nsep) {
		nsep = mdb_list_next(sep);
		mdb_tgt_sespec_prune_one(t, sep);
	}
}

/*
 * Transition the given sespec to the IDLE state.  We invoke the destructor,
 * and then move the sespec from the active list to the idle list.
 */
void
mdb_tgt_sespec_idle_one(mdb_tgt_t *t, mdb_sespec_t *sep, int reason)
{
	ASSERT(sep->se_state != MDB_TGT_SPEC_IDLE);

	if (sep->se_state == MDB_TGT_SPEC_ARMED)
		(void) sep->se_ops->se_disarm(t, sep);

	sep->se_ops->se_dtor(t, sep);
	sep->se_data = NULL;

	sep->se_state = MDB_TGT_SPEC_IDLE;
	sep->se_errno = reason;

	mdb_list_delete(&t->t_active, sep);
	mdb_list_append(&t->t_idle, sep);

	mdb_tgt_sespec_prune_one(t, sep);
}

/*
 * Transition each sespec on the active list to the IDLE state.  This function
 * is called, for example, after the target terminates execution.
 */
void
mdb_tgt_sespec_idle_all(mdb_tgt_t *t, int reason, int clear_matched)
{
	mdb_sespec_t *sep, *nsep;
	mdb_vespec_t *vep;

	while ((sep = t->t_matched) != T_SE_END && clear_matched) {
		for (vep = mdb_list_next(&sep->se_velist); vep != NULL; ) {
			vep->ve_flags &= ~MDB_TGT_SPEC_MATCHED;
			vep = mdb_list_next(vep);
		}

		t->t_matched = sep->se_matched;
		sep->se_matched = NULL;
		mdb_tgt_sespec_rele(t, sep);
	}

	for (sep = mdb_list_next(&t->t_active); sep != NULL; sep = nsep) {
		nsep = mdb_list_next(sep);
		mdb_tgt_sespec_idle_one(t, sep, reason);
	}
}

/*
 * Attempt to transition the given sespec from the IDLE to ACTIVE state.  We
 * do this by invoking se_ctor -- if this fails, we save the reason in se_errno
 * and return -1 with errno set.  One strange case we need to deal with here is
 * the possibility that a given vespec is sitting on the idle list with its
 * corresponding sespec, but it is actually a duplicate of another sespec on the
 * active list.  This can happen if the sespec is associated with a
 * MDB_TGT_SPEC_DISABLED vespec that was just enabled, and is now ready to be
 * activated.  A more interesting reason this situation might arise is the case
 * where a virtual address breakpoint is set at an address just mmap'ed by
 * dlmopen.  Since no symbol table information is available for this mapping
 * yet, a pre-existing deferred symbolic breakpoint may already exist for this
 * address, but it is on the idle list.  When the symbol table is ready and the
 * DLACTIVITY event occurs, we now discover that the virtual address obtained by
 * evaluating the symbolic breakpoint matches the explicit virtual address of
 * the active virtual breakpoint.  To resolve this conflict in either case, we
 * destroy the idle sespec, and attach its list of vespecs to the existing
 * active sespec.
 */
int
mdb_tgt_sespec_activate_one(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	mdb_vespec_t *vep = mdb_list_next(&sep->se_velist);

	mdb_vespec_t *nvep;
	mdb_sespec_t *dup;

	ASSERT(sep->se_state == MDB_TGT_SPEC_IDLE);
	ASSERT(vep != NULL);

	if (vep->ve_flags & MDB_TGT_SPEC_DISABLED)
		return (0); /* cannot be activated while disabled bit set */

	/*
	 * First search the active list for an existing, duplicate sespec to
	 * handle the special case described above.
	 */
	for (dup = mdb_list_next(&t->t_active); dup; dup = mdb_list_next(dup)) {
		if (dup->se_ops == sep->se_ops &&
		    dup->se_ops->se_secmp(t, dup, vep->ve_args)) {
			ASSERT(dup != sep);
			break;
		}
	}

	/*
	 * If a duplicate is found, destroy the existing, idle sespec, and
	 * attach all of its vespecs to the duplicate sespec.
	 */
	if (dup != NULL) {
		for (vep = mdb_list_next(&sep->se_velist); vep; vep = nvep) {
			mdb_dprintf(MDB_DBG_TGT, "merge [ %d ] to sespec %p\n",
			    vep->ve_id, (void *)dup);

			if (dup->se_matched != NULL)
				vep->ve_flags |= MDB_TGT_SPEC_MATCHED;

			nvep = mdb_list_next(vep);
			vep->ve_hits = 0;

			mdb_list_delete(&sep->se_velist, vep);
			mdb_tgt_sespec_rele(t, sep);

			mdb_list_append(&dup->se_velist, vep);
			mdb_tgt_sespec_hold(t, dup);
			vep->ve_se = dup;
		}

		mdb_dprintf(MDB_DBG_TGT, "merged idle sespec %p with %p\n",
		    (void *)sep, (void *)dup);
		return (0);
	}

	/*
	 * If no duplicate is found, call the sespec's constructor.  If this
	 * is successful, move the sespec to the active list.
	 */
	if (sep->se_ops->se_ctor(t, sep, vep->ve_args) < 0) {
		sep->se_errno = errno;
		sep->se_data = NULL;

		return (-1);
	}

	for (vep = mdb_list_next(&sep->se_velist); vep; vep = nvep) {
		nvep = mdb_list_next(vep);
		vep->ve_hits = 0;
	}
	mdb_list_delete(&t->t_idle, sep);
	mdb_list_append(&t->t_active, sep);
	sep->se_state = MDB_TGT_SPEC_ACTIVE;
	sep->se_errno = 0;

	return (0);
}

/*
 * Transition each sespec on the idle list to the ACTIVE state.  This function
 * is called, for example, after the target's t_run() function returns.  If
 * the se_ctor() function fails, the specifier is not yet applicable; it will
 * remain on the idle list and can be activated later.
 *
 * Returns 1 if there weren't any unexpected activation failures; 0 if there
 * were.
 */
int
mdb_tgt_sespec_activate_all(mdb_tgt_t *t)
{
	mdb_sespec_t *sep, *nsep;
	int rc = 1;

	for (sep = mdb_list_next(&t->t_idle); sep != NULL; sep = nsep) {
		nsep = mdb_list_next(sep);

		if (mdb_tgt_sespec_activate_one(t, sep) < 0 &&
		    sep->se_errno != EMDB_NOOBJ)
			rc = 0;
	}

	return (rc);
}

/*
 * Transition the given sespec to the ARMED state.  Note that we attempt to
 * re-arm sespecs previously in the ERROR state.  If se_arm() fails the sespec
 * transitions to the ERROR state but stays on the active list.
 */
void
mdb_tgt_sespec_arm_one(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	ASSERT(sep->se_state != MDB_TGT_SPEC_IDLE);

	if (sep->se_state == MDB_TGT_SPEC_ARMED)
		return; /* do not arm sespecs more than once */

	if (sep->se_ops->se_arm(t, sep) == -1) {
		sep->se_state = MDB_TGT_SPEC_ERROR;
		sep->se_errno = errno;
	} else {
		sep->se_state = MDB_TGT_SPEC_ARMED;
		sep->se_errno = 0;
	}
}

/*
 * Transition each sespec on the active list (except matched specs) to the
 * ARMED state.  This function is called prior to continuing the target.
 */
void
mdb_tgt_sespec_arm_all(mdb_tgt_t *t)
{
	mdb_sespec_t *sep, *nsep;

	for (sep = mdb_list_next(&t->t_active); sep != NULL; sep = nsep) {
		nsep = mdb_list_next(sep);
		if (sep->se_matched == NULL)
			mdb_tgt_sespec_arm_one(t, sep);
	}
}

/*
 * Transition each sespec on the active list that is in the ARMED state to
 * the ACTIVE state.  If se_disarm() fails, the sespec is transitioned to
 * the ERROR state instead, but left on the active list.
 */
static void
tgt_disarm_sespecs(mdb_tgt_t *t)
{
	mdb_sespec_t *sep;

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		if (sep->se_state != MDB_TGT_SPEC_ARMED)
			continue; /* do not disarm if in ERROR state */

		if (sep->se_ops->se_disarm(t, sep) == -1) {
			sep->se_state = MDB_TGT_SPEC_ERROR;
			sep->se_errno = errno;
		} else {
			sep->se_state = MDB_TGT_SPEC_ACTIVE;
			sep->se_errno = 0;
		}
	}
}

/*
 * Determine if the software event that triggered the most recent stop matches
 * any of the active event specifiers.  If 'all' is TRUE, we consider all
 * sespecs in our search.   If 'all' is FALSE, we only consider ARMED sespecs.
 * If we successfully match an event, we add it to the t_matched list and
 * place an additional hold on it.
 */
static mdb_sespec_t *
tgt_match_sespecs(mdb_tgt_t *t, int all)
{
	mdb_sespec_t *sep;

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		if (all == FALSE && sep->se_state != MDB_TGT_SPEC_ARMED)
			continue; /* restrict search to ARMED sespecs */

		if (sep->se_state != MDB_TGT_SPEC_ERROR &&
		    sep->se_ops->se_match(t, sep, &t->t_status)) {
			mdb_dprintf(MDB_DBG_TGT, "match se %p\n", (void *)sep);
			mdb_tgt_sespec_hold(t, sep);
			sep->se_matched = t->t_matched;
			t->t_matched = sep;
		}
	}

	return (t->t_matched);
}

/*
 * This function provides the low-level target continue algorithm.  We proceed
 * in three phases: (1) we arm the active sespecs, except the specs matched at
 * the time we last stopped, (2) we call se_cont() on any matched sespecs to
 * step over these event transitions, and then arm the corresponding sespecs,
 * and (3) we call the appropriate low-level continue routine.  Once the
 * target stops again, we determine which sespecs were matched, and invoke the
 * appropriate vespec callbacks and perform other vespec maintenance.
 */
static int
tgt_continue(mdb_tgt_t *t, mdb_tgt_status_t *tsp,
    int (*t_cont)(mdb_tgt_t *, mdb_tgt_status_t *))
{
	mdb_var_t *hitv = mdb_nv_lookup(&mdb.m_nv, "hits");
	uintptr_t pc = t->t_status.st_pc;
	int error = 0;

	mdb_sespec_t *sep, *nsep, *matched;
	mdb_vespec_t *vep, *nvep;
	uintptr_t addr;

	uint_t cbits = 0;	/* union of pending continue bits */
	uint_t ncont = 0;	/* # of callbacks that requested cont */
	uint_t n = 0;		/* # of callbacks */

	/*
	 * If the target is undead, dead, or lost, we no longer allow continue.
	 * This effectively forces the user to use ::kill or ::run after death.
	 */
	if (t->t_status.st_state == MDB_TGT_UNDEAD)
		return (set_errno(EMDB_TGTZOMB));
	if (t->t_status.st_state == MDB_TGT_DEAD)
		return (set_errno(EMDB_TGTCORE));
	if (t->t_status.st_state == MDB_TGT_LOST)
		return (set_errno(EMDB_TGTLOST));

	/*
	 * If any of single-step, step-over, or step-out is pending, it takes
	 * precedence over an explicit or pending continue, because these are
	 * all different specialized forms of continue.
	 */
	if (t->t_flags & MDB_TGT_F_STEP)
		t_cont = t->t_ops->t_step;
	else if (t->t_flags & MDB_TGT_F_NEXT)
		t_cont = t->t_ops->t_step;
	else if (t->t_flags & MDB_TGT_F_STEP_OUT)
		t_cont = t->t_ops->t_cont;

	/*
	 * To handle step-over, we ask the target to find the address past the
	 * next control transfer instruction.  If an address is found, we plant
	 * a temporary breakpoint there and continue; otherwise just step.
	 */
	if ((t->t_flags & MDB_TGT_F_NEXT) && !(t->t_flags & MDB_TGT_F_STEP)) {
		if (t->t_ops->t_next(t, &addr) == -1 || mdb_tgt_add_vbrkpt(t,
		    addr, MDB_TGT_SPEC_HIDDEN | MDB_TGT_SPEC_TEMPORARY,
		    no_se_f, NULL) == 0) {
			mdb_dprintf(MDB_DBG_TGT, "next falling back to step: "
			    "%s\n", mdb_strerror(errno));
		} else
			t_cont = t->t_ops->t_cont;
	}

	/*
	 * To handle step-out, we ask the target to find the return address of
	 * the current frame, plant a temporary breakpoint there, and continue.
	 */
	if (t->t_flags & MDB_TGT_F_STEP_OUT) {
		if (t->t_ops->t_step_out(t, &addr) == -1)
			return (-1); /* errno is set for us */

		if (mdb_tgt_add_vbrkpt(t, addr, MDB_TGT_SPEC_HIDDEN |
		    MDB_TGT_SPEC_TEMPORARY, no_se_f, NULL) == 0)
			return (-1); /* errno is set for us */
	}

	(void) mdb_signal_block(SIGHUP);
	(void) mdb_signal_block(SIGTERM);
	mdb_intr_disable();

	t->t_flags &= ~T_CONT_BITS;
	t->t_flags |= MDB_TGT_F_BUSY;
	mdb_tgt_sespec_arm_all(t);

	ASSERT(t->t_matched != NULL);
	matched = t->t_matched;
	t->t_matched = T_SE_END;

	if (mdb.m_term != NULL)
		IOP_SUSPEND(mdb.m_term);

	/*
	 * Iterate over the matched sespec list, performing autostop processing
	 * and clearing the matched bit for each associated vespec.  We then
	 * invoke each sespec's se_cont callback in order to continue past
	 * the corresponding event.  If the matched list has more than one
	 * sespec, we assume that the se_cont callbacks are non-interfering.
	 */
	for (sep = matched; sep != T_SE_END; sep = sep->se_matched) {
		for (vep = mdb_list_next(&sep->se_velist); vep != NULL; ) {
			if ((vep->ve_flags & MDB_TGT_SPEC_AUTOSTOP) &&
			    (vep->ve_limit && vep->ve_hits == vep->ve_limit))
				vep->ve_hits = 0;

			vep->ve_flags &= ~MDB_TGT_SPEC_MATCHED;
			vep = mdb_list_next(vep);
		}

		if (sep->se_ops->se_cont(t, sep, &t->t_status) == -1) {
			error = errno ? errno : -1;
			tgt_disarm_sespecs(t);
			break;
		}

		if (!(t->t_status.st_flags & MDB_TGT_ISTOP)) {
			tgt_disarm_sespecs(t);
			if (t->t_status.st_state == MDB_TGT_UNDEAD)
				mdb_tgt_sespec_idle_all(t, EMDB_TGTZOMB, TRUE);
			else if (t->t_status.st_state == MDB_TGT_LOST)
				mdb_tgt_sespec_idle_all(t, EMDB_TGTLOST, TRUE);
			break;
		}
	}

	/*
	 * Clear the se_matched field for each matched sespec, and drop the
	 * reference count since the sespec is no longer on the matched list.
	 */
	for (sep = matched; sep != T_SE_END; sep = nsep) {
		nsep = sep->se_matched;
		sep->se_matched = NULL;
		mdb_tgt_sespec_rele(t, sep);
	}

	/*
	 * If the matched list was non-empty, see if we hit another event while
	 * performing se_cont() processing.  If so, don't bother continuing any
	 * further.  If not, arm the sespecs on the old matched list by calling
	 * mdb_tgt_sespec_arm_all() again and then continue by calling t_cont.
	 */
	if (matched != T_SE_END) {
		if (error != 0 || !(t->t_status.st_flags & MDB_TGT_ISTOP))
			goto out; /* abort now if se_cont() failed */

		if ((t->t_matched = tgt_match_sespecs(t, FALSE)) != T_SE_END) {
			tgt_disarm_sespecs(t);
			goto out;
		}

		mdb_tgt_sespec_arm_all(t);
	}

	if (t_cont != t->t_ops->t_step || pc == t->t_status.st_pc) {
		if (t_cont(t, &t->t_status) != 0)
			error = errno ? errno : -1;
	}

	tgt_disarm_sespecs(t);

	if (t->t_flags & MDB_TGT_F_UNLOAD)
		longjmp(mdb.m_frame->f_pcb, MDB_ERR_QUIT);

	if (t->t_status.st_state == MDB_TGT_UNDEAD)
		mdb_tgt_sespec_idle_all(t, EMDB_TGTZOMB, TRUE);
	else if (t->t_status.st_state == MDB_TGT_LOST)
		mdb_tgt_sespec_idle_all(t, EMDB_TGTLOST, TRUE);
	else if (t->t_status.st_flags & MDB_TGT_ISTOP)
		t->t_matched = tgt_match_sespecs(t, TRUE);
out:
	if (mdb.m_term != NULL)
		IOP_RESUME(mdb.m_term);

	(void) mdb_signal_unblock(SIGTERM);
	(void) mdb_signal_unblock(SIGHUP);
	mdb_intr_enable();

	for (sep = t->t_matched; sep != T_SE_END; sep = sep->se_matched) {
		/*
		 * When we invoke a ve_callback, it may in turn request that the
		 * target continue immediately after callback processing is
		 * complete.  We only allow this to occur if *all* callbacks
		 * agree to continue.  To implement this behavior, we keep a
		 * count (ncont) of such requests, and only apply the cumulative
		 * continue bits (cbits) to the target if ncont is equal to the
		 * total number of callbacks that are invoked (n).
		 */
		for (vep = mdb_list_next(&sep->se_velist);
		    vep != NULL; vep = nvep, n++) {
			/*
			 * Place an extra hold on the current vespec and pick
			 * up the next pointer before invoking the callback: we
			 * must be prepared for the vespec to be deleted or
			 * moved to a different list by the callback.
			 */
			mdb_tgt_vespec_hold(t, vep);
			nvep = mdb_list_next(vep);

			vep->ve_flags |= MDB_TGT_SPEC_MATCHED;
			vep->ve_hits++;

			mdb_nv_set_value(mdb.m_dot, t->t_status.st_pc);
			mdb_nv_set_value(hitv, vep->ve_hits);

			ASSERT((t->t_flags & T_CONT_BITS) == 0);
			vep->ve_callback(t, vep->ve_id, vep->ve_data);

			ncont += (t->t_flags & T_CONT_BITS) != 0;
			cbits |= (t->t_flags & T_CONT_BITS);
			t->t_flags &= ~T_CONT_BITS;

			if (vep->ve_limit && vep->ve_hits == vep->ve_limit) {
				if (vep->ve_flags & MDB_TGT_SPEC_AUTODEL)
					(void) mdb_tgt_vespec_delete(t,
					    vep->ve_id);
				else if (vep->ve_flags & MDB_TGT_SPEC_AUTODIS)
					(void) mdb_tgt_vespec_disable(t,
					    vep->ve_id);
			}

			if (vep->ve_limit && vep->ve_hits < vep->ve_limit) {
				if (vep->ve_flags & MDB_TGT_SPEC_AUTOSTOP)
					(void) mdb_tgt_continue(t, NULL);
			}

			mdb_tgt_vespec_rele(t, vep);
		}
	}

	if (t->t_matched != T_SE_END && ncont == n)
		t->t_flags |= cbits; /* apply continues (see above) */

	mdb_tgt_sespec_prune_all(t);

	t->t_status.st_flags &= ~MDB_TGT_BUSY;
	t->t_flags &= ~MDB_TGT_F_BUSY;

	if (tsp != NULL)
		bcopy(&t->t_status, tsp, sizeof (mdb_tgt_status_t));

	if (error != 0)
		return (set_errno(error));

	return (0);
}

/*
 * This function is the common glue that connects the high-level target layer
 * continue functions (e.g. step and cont below) with the low-level
 * tgt_continue() function above.  Since vespec callbacks may perform any
 * actions, including attempting to continue the target itself, we must be
 * prepared to be called while the target is still marked F_BUSY.  In this
 * case, we just set a pending bit and return.  When we return from the call
 * to tgt_continue() that made us busy into the tgt_request_continue() call
 * that is still on the stack, we will loop around and call tgt_continue()
 * again.  This allows vespecs to continue the target without recursion.
 */
static int
tgt_request_continue(mdb_tgt_t *t, mdb_tgt_status_t *tsp, uint_t tflag,
    int (*t_cont)(mdb_tgt_t *, mdb_tgt_status_t *))
{
	mdb_tgt_spec_desc_t desc;
	mdb_sespec_t *sep;
	char buf[BUFSIZ];
	int status;

	if (t->t_flags & MDB_TGT_F_BUSY) {
		t->t_flags |= tflag;
		return (0);
	}

	do {
		status = tgt_continue(t, tsp, t_cont);
	} while (status == 0 && (t->t_flags & T_CONT_BITS));

	if (status == 0) {
		for (sep = t->t_matched; sep != T_SE_END;
		    sep = sep->se_matched) {
			mdb_vespec_t *vep;

			for (vep = mdb_list_next(&sep->se_velist); vep;
			    vep = mdb_list_next(vep)) {
				if (vep->ve_flags & MDB_TGT_SPEC_SILENT)
					continue;
				warn("%s\n", sep->se_ops->se_info(t, sep,
				    vep, &desc, buf, sizeof (buf)));
			}
		}

		mdb_callb_fire(MDB_CALLB_STCHG);
	}

	t->t_flags &= ~T_CONT_BITS;
	return (status);
}

/*
 * Restart target execution: we rely upon the underlying target implementation
 * to do most of the work for us.  In particular, we assume it will properly
 * preserve the state of our event lists if the run fails for some reason,
 * and that it will reset all events to the IDLE state if the run succeeds.
 * If it is successful, we attempt to activate all of the idle sespecs.  The
 * t_run() operation is defined to leave the target stopped at the earliest
 * possible point in execution, and then return control to the debugger,
 * awaiting a step or continue operation to set it running again.
 */
int
mdb_tgt_run(mdb_tgt_t *t, int argc, const mdb_arg_t *argv)
{
	int i;

	for (i = 0; i < argc; i++) {
		if (argv->a_type != MDB_TYPE_STRING)
			return (set_errno(EINVAL));
	}

	if (t->t_ops->t_run(t, argc, argv) == -1)
		return (-1); /* errno is set for us */

	t->t_flags &= ~T_CONT_BITS;
	(void) mdb_tgt_sespec_activate_all(t);

	if (mdb.m_term != NULL)
		IOP_CTL(mdb.m_term, MDB_IOC_CTTY, NULL);

	return (0);
}

int
mdb_tgt_step(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	return (tgt_request_continue(t, tsp, MDB_TGT_F_STEP, t->t_ops->t_step));
}

int
mdb_tgt_step_out(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	t->t_flags |= MDB_TGT_F_STEP_OUT; /* set flag even if tgt not busy */
	return (tgt_request_continue(t, tsp, 0, t->t_ops->t_cont));
}

int
mdb_tgt_next(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	t->t_flags |= MDB_TGT_F_NEXT; /* set flag even if tgt not busy */
	return (tgt_request_continue(t, tsp, 0, t->t_ops->t_step));
}

int
mdb_tgt_continue(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	return (tgt_request_continue(t, tsp, MDB_TGT_F_CONT, t->t_ops->t_cont));
}

int
mdb_tgt_signal(mdb_tgt_t *t, int sig)
{
	return (t->t_ops->t_signal(t, sig));
}

void *
mdb_tgt_vespec_data(mdb_tgt_t *t, int vid)
{
	mdb_vespec_t *vep = mdb_tgt_vespec_lookup(t, vid);

	if (vep == NULL) {
		(void) set_errno(EMDB_NOSESPEC);
		return (NULL);
	}

	return (vep->ve_data);
}

/*
 * Return a structured description and comment string for the given vespec.
 * We fill in the common information from the vespec, and then call down to
 * the underlying sespec to provide the comment string and modify any
 * event type-specific information.
 */
char *
mdb_tgt_vespec_info(mdb_tgt_t *t, int vid, mdb_tgt_spec_desc_t *sp,
    char *buf, size_t nbytes)
{
	mdb_vespec_t *vep = mdb_tgt_vespec_lookup(t, vid);

	mdb_tgt_spec_desc_t desc;
	mdb_sespec_t *sep;

	if (vep == NULL) {
		if (sp != NULL)
			bzero(sp, sizeof (mdb_tgt_spec_desc_t));
		(void) set_errno(EMDB_NOSESPEC);
		return (NULL);
	}

	if (sp == NULL)
		sp = &desc;

	sep = vep->ve_se;

	sp->spec_id = vep->ve_id;
	sp->spec_flags = vep->ve_flags;
	sp->spec_hits = vep->ve_hits;
	sp->spec_limit = vep->ve_limit;
	sp->spec_state = sep->se_state;
	sp->spec_errno = sep->se_errno;
	sp->spec_base = NULL;
	sp->spec_size = 0;
	sp->spec_data = vep->ve_data;

	return (sep->se_ops->se_info(t, sep, vep, sp, buf, nbytes));
}

/*
 * Qsort callback for sorting vespecs by VID, used below.
 */
static int
tgt_vespec_compare(const mdb_vespec_t **lp, const mdb_vespec_t **rp)
{
	return ((*lp)->ve_id - (*rp)->ve_id);
}

/*
 * Iterate over all vespecs and call the specified callback function with the
 * corresponding VID and caller data pointer.  We want the callback function
 * to see a consistent, sorted snapshot of the vespecs, and allow the callback
 * to take actions such as deleting the vespec itself, so we cannot simply
 * iterate over the lists.  Instead, we pre-allocate an array of vespec
 * pointers, fill it in and place an additional hold on each vespec, and then
 * sort it.  After the callback has been executed on each vespec in the
 * sorted array, we remove our hold and free the temporary array.
 */
int
mdb_tgt_vespec_iter(mdb_tgt_t *t, mdb_tgt_vespec_f *func, void *p)
{
	mdb_vespec_t **veps, **vepp, **vend;
	mdb_vespec_t *vep, *nvep;
	mdb_sespec_t *sep;

	uint_t vecnt = t->t_vecnt;

	veps = mdb_alloc(sizeof (mdb_vespec_t *) * vecnt, UM_SLEEP);
	vend = veps + vecnt;
	vepp = veps;

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		for (vep = mdb_list_next(&sep->se_velist); vep; vep = nvep) {
			mdb_tgt_vespec_hold(t, vep);
			nvep = mdb_list_next(vep);
			*vepp++ = vep;
		}
	}

	for (sep = mdb_list_next(&t->t_idle); sep; sep = mdb_list_next(sep)) {
		for (vep = mdb_list_next(&sep->se_velist); vep; vep = nvep) {
			mdb_tgt_vespec_hold(t, vep);
			nvep = mdb_list_next(vep);
			*vepp++ = vep;
		}
	}

	if (vepp != vend) {
		fail("target has %u vespecs on list but vecnt shows %u\n",
		    (uint_t)(vepp - veps), vecnt);
	}

	qsort(veps, vecnt, sizeof (mdb_vespec_t *),
	    (int (*)(const void *, const void *))tgt_vespec_compare);

	for (vepp = veps; vepp < vend; vepp++) {
		if (func(t, p, (*vepp)->ve_id, (*vepp)->ve_data) != 0)
			break;
	}

	for (vepp = veps; vepp < vend; vepp++)
		mdb_tgt_vespec_rele(t, *vepp);

	mdb_free(veps, sizeof (mdb_vespec_t *) * vecnt);
	return (0);
}

/*
 * Reset the vespec flags, match limit, and callback data to the specified
 * values.  We silently correct invalid parameters, except for the VID.
 * The caller is required to query the existing properties and pass back
 * the existing values for any properties that should not be modified.
 * If the callback data is modified, the caller is responsible for cleaning
 * up any state associated with the previous value.
 */
int
mdb_tgt_vespec_modify(mdb_tgt_t *t, int id, uint_t flags,
    uint_t limit, void *data)
{
	mdb_vespec_t *vep = mdb_tgt_vespec_lookup(t, id);

	if (vep == NULL)
		return (set_errno(EMDB_NOSESPEC));

	/*
	 * If the value of the MDB_TGT_SPEC_DISABLED bit is changing, call the
	 * appropriate vespec function to do the enable/disable work.
	 */
	if ((flags & MDB_TGT_SPEC_DISABLED) !=
	    (vep->ve_flags & MDB_TGT_SPEC_DISABLED)) {
		if (flags & MDB_TGT_SPEC_DISABLED)
			(void) mdb_tgt_vespec_disable(t, id);
		else
			(void) mdb_tgt_vespec_enable(t, id);
	}

	/*
	 * Make that only one MDB_TGT_SPEC_AUTO* bit is set in the new flags
	 * value: extra bits are cleared according to order of precedence.
	 */
	if (flags & MDB_TGT_SPEC_AUTOSTOP)
		flags &= ~(MDB_TGT_SPEC_AUTODEL | MDB_TGT_SPEC_AUTODIS);
	else if (flags & MDB_TGT_SPEC_AUTODEL)
		flags &= ~MDB_TGT_SPEC_AUTODIS;

	/*
	 * The TEMPORARY property always takes precedence over STICKY.
	 */
	if (flags & MDB_TGT_SPEC_TEMPORARY)
		flags &= ~MDB_TGT_SPEC_STICKY;

	/*
	 * If any MDB_TGT_SPEC_AUTO* bits are changing, reset the hit count
	 * back to zero and clear all of the old auto bits.
	 */
	if ((flags & T_AUTO_BITS) != (vep->ve_flags & T_AUTO_BITS)) {
		vep->ve_flags &= ~T_AUTO_BITS;
		vep->ve_hits = 0;
	}

	vep->ve_flags = (vep->ve_flags & T_IMPL_BITS) | (flags & ~T_IMPL_BITS);
	vep->ve_data = data;

	/*
	 * If any MDB_TGT_SPEC_AUTO* flags are set, make sure the limit is at
	 * least one.  If none are set, reset it back to zero.
	 */
	if (vep->ve_flags & T_AUTO_BITS)
		vep->ve_limit = MAX(limit, 1);
	else
		vep->ve_limit = 0;

	/*
	 * As a convenience, we allow the caller to specify SPEC_DELETED in
	 * the flags field as indication that the event should be deleted.
	 */
	if (flags & MDB_TGT_SPEC_DELETED)
		(void) mdb_tgt_vespec_delete(t, id);

	return (0);
}

/*
 * Remove the user disabled bit from the specified vespec, and attempt to
 * activate the underlying sespec and move it to the active list if possible.
 */
int
mdb_tgt_vespec_enable(mdb_tgt_t *t, int id)
{
	mdb_vespec_t *vep = mdb_tgt_vespec_lookup(t, id);

	if (vep == NULL)
		return (set_errno(EMDB_NOSESPEC));

	if (vep->ve_flags & MDB_TGT_SPEC_DISABLED) {
		ASSERT(mdb_list_next(vep) == NULL);
		vep->ve_flags &= ~MDB_TGT_SPEC_DISABLED;
		if (mdb_tgt_sespec_activate_one(t, vep->ve_se) < 0)
			return (-1); /* errno is set for us */
	}

	return (0);
}

/*
 * Set the user disabled bit on the specified vespec, and move it to the idle
 * list.  If the vespec is not alone with its sespec or if it is a currently
 * matched event, we must always create a new idle sespec and move the vespec
 * there.  If the vespec was alone and active, we can simply idle the sespec.
 */
int
mdb_tgt_vespec_disable(mdb_tgt_t *t, int id)
{
	mdb_vespec_t *vep = mdb_tgt_vespec_lookup(t, id);
	mdb_sespec_t *sep;

	if (vep == NULL)
		return (set_errno(EMDB_NOSESPEC));

	if (vep->ve_flags & MDB_TGT_SPEC_DISABLED)
		return (0); /* already disabled */

	if (mdb_list_prev(vep) != NULL || mdb_list_next(vep) != NULL ||
	    vep->ve_se->se_matched != NULL) {

		sep = mdb_tgt_sespec_insert(t, vep->ve_se->se_ops, &t->t_idle);

		mdb_list_delete(&vep->ve_se->se_velist, vep);
		mdb_tgt_sespec_rele(t, vep->ve_se);

		mdb_list_append(&sep->se_velist, vep);
		mdb_tgt_sespec_hold(t, sep);

		vep->ve_flags &= ~MDB_TGT_SPEC_MATCHED;
		vep->ve_se = sep;

	} else if (vep->ve_se->se_state != MDB_TGT_SPEC_IDLE)
		mdb_tgt_sespec_idle_one(t, vep->ve_se, EMDB_SPECDIS);

	vep->ve_flags |= MDB_TGT_SPEC_DISABLED;
	return (0);
}

/*
 * Delete the given vespec.  We use the MDB_TGT_SPEC_DELETED flag to ensure that
 * multiple calls to mdb_tgt_vespec_delete to not attempt to decrement the
 * reference count on the vespec more than once.  This is because the vespec
 * may remain referenced if it is currently held by another routine (e.g.
 * vespec_iter), and so the user could attempt to delete it more than once
 * since it reference count will be >= 2 prior to the first delete call.
 */
int
mdb_tgt_vespec_delete(mdb_tgt_t *t, int id)
{
	mdb_vespec_t *vep = mdb_tgt_vespec_lookup(t, id);

	if (vep == NULL)
		return (set_errno(EMDB_NOSESPEC));

	if (vep->ve_flags & MDB_TGT_SPEC_DELETED)
		return (set_errno(EBUSY));

	vep->ve_flags |= MDB_TGT_SPEC_DELETED;
	mdb_tgt_vespec_rele(t, vep);
	return (0);
}

int
mdb_tgt_add_vbrkpt(mdb_tgt_t *t, uintptr_t addr,
    int spec_flags, mdb_tgt_se_f *func, void *p)
{
	return (t->t_ops->t_add_vbrkpt(t, addr, spec_flags, func, p));
}

int
mdb_tgt_add_sbrkpt(mdb_tgt_t *t, const char *symbol,
    int spec_flags, mdb_tgt_se_f *func, void *p)
{
	return (t->t_ops->t_add_sbrkpt(t, symbol, spec_flags, func, p));
}

int
mdb_tgt_add_pwapt(mdb_tgt_t *t, physaddr_t pa, size_t n, uint_t flags,
    int spec_flags, mdb_tgt_se_f *func, void *p)
{
	if ((flags & ~MDB_TGT_WA_RWX) || flags == 0) {
		(void) set_errno(EINVAL);
		return (0);
	}

	if (pa + n < pa) {
		(void) set_errno(EMDB_WPRANGE);
		return (0);
	}

	return (t->t_ops->t_add_pwapt(t, pa, n, flags, spec_flags, func, p));
}

int
mdb_tgt_add_vwapt(mdb_tgt_t *t, uintptr_t va, size_t n, uint_t flags,
    int spec_flags, mdb_tgt_se_f *func, void *p)
{
	if ((flags & ~MDB_TGT_WA_RWX) || flags == 0) {
		(void) set_errno(EINVAL);
		return (0);
	}

	if (va + n < va) {
		(void) set_errno(EMDB_WPRANGE);
		return (0);
	}

	return (t->t_ops->t_add_vwapt(t, va, n, flags, spec_flags, func, p));
}

int
mdb_tgt_add_iowapt(mdb_tgt_t *t, uintptr_t addr, size_t n, uint_t flags,
    int spec_flags, mdb_tgt_se_f *func, void *p)
{
	if ((flags & ~MDB_TGT_WA_RWX) || flags == 0) {
		(void) set_errno(EINVAL);
		return (0);
	}

	if (addr + n < addr) {
		(void) set_errno(EMDB_WPRANGE);
		return (0);
	}

	return (t->t_ops->t_add_iowapt(t, addr, n, flags, spec_flags, func, p));
}

int
mdb_tgt_add_sysenter(mdb_tgt_t *t, int sysnum,
    int spec_flags, mdb_tgt_se_f *func, void *p)
{
	return (t->t_ops->t_add_sysenter(t, sysnum, spec_flags, func, p));
}

int
mdb_tgt_add_sysexit(mdb_tgt_t *t, int sysnum,
    int spec_flags, mdb_tgt_se_f *func, void *p)
{
	return (t->t_ops->t_add_sysexit(t, sysnum, spec_flags, func, p));
}

int
mdb_tgt_add_signal(mdb_tgt_t *t, int sig,
    int spec_flags, mdb_tgt_se_f *func, void *p)
{
	return (t->t_ops->t_add_signal(t, sig, spec_flags, func, p));
}

int
mdb_tgt_add_fault(mdb_tgt_t *t, int flt,
    int spec_flags, mdb_tgt_se_f *func, void *p)
{
	return (t->t_ops->t_add_fault(t, flt, spec_flags, func, p));
}

int
mdb_tgt_getareg(mdb_tgt_t *t, mdb_tgt_tid_t tid,
    const char *rname, mdb_tgt_reg_t *rp)
{
	return (t->t_ops->t_getareg(t, tid, rname, rp));
}

int
mdb_tgt_putareg(mdb_tgt_t *t, mdb_tgt_tid_t tid,
    const char *rname, mdb_tgt_reg_t r)
{
	return (t->t_ops->t_putareg(t, tid, rname, r));
}

int
mdb_tgt_stack_iter(mdb_tgt_t *t, const mdb_tgt_gregset_t *gregs,
    mdb_tgt_stack_f *cb, void *p)
{
	return (t->t_ops->t_stack_iter(t, gregs, cb, p));
}

int
mdb_tgt_xdata_iter(mdb_tgt_t *t, mdb_tgt_xdata_f *func, void *private)
{
	mdb_xdata_t *xdp;

	for (xdp = mdb_list_next(&t->t_xdlist); xdp; xdp = mdb_list_next(xdp)) {
		if (func(private, xdp->xd_name, xdp->xd_desc,
		    xdp->xd_copy(t, NULL, 0)) != 0)
			break;
	}

	return (0);
}

ssize_t
mdb_tgt_getxdata(mdb_tgt_t *t, const char *name, void *buf, size_t nbytes)
{
	mdb_xdata_t *xdp;

	for (xdp = mdb_list_next(&t->t_xdlist); xdp; xdp = mdb_list_next(xdp)) {
		if (strcmp(xdp->xd_name, name) == 0)
			return (xdp->xd_copy(t, buf, nbytes));
	}

	return (set_errno(ENODATA));
}

long
mdb_tgt_notsup()
{
	return (set_errno(EMDB_TGTNOTSUP));
}

void *
mdb_tgt_null()
{
	(void) set_errno(EMDB_TGTNOTSUP);
	return (NULL);
}

long
mdb_tgt_nop()
{
	return (0L);
}

int
mdb_tgt_xdata_insert(mdb_tgt_t *t, const char *name, const char *desc,
    ssize_t (*copy)(mdb_tgt_t *, void *, size_t))
{
	mdb_xdata_t *xdp;

	for (xdp = mdb_list_next(&t->t_xdlist); xdp; xdp = mdb_list_next(xdp)) {
		if (strcmp(xdp->xd_name, name) == 0)
			return (set_errno(EMDB_XDEXISTS));
	}

	xdp = mdb_alloc(sizeof (mdb_xdata_t), UM_SLEEP);
	mdb_list_append(&t->t_xdlist, xdp);

	xdp->xd_name = name;
	xdp->xd_desc = desc;
	xdp->xd_copy = copy;

	return (0);
}

int
mdb_tgt_xdata_delete(mdb_tgt_t *t, const char *name)
{
	mdb_xdata_t *xdp;

	for (xdp = mdb_list_next(&t->t_xdlist); xdp; xdp = mdb_list_next(xdp)) {
		if (strcmp(xdp->xd_name, name) == 0) {
			mdb_list_delete(&t->t_xdlist, xdp);
			mdb_free(xdp, sizeof (mdb_xdata_t));
			return (0);
		}
	}

	return (set_errno(EMDB_NOXD));
}

int
mdb_tgt_sym_match(const GElf_Sym *sym, uint_t mask)
{
#if STT_NUM != (STT_TLS + 1)
#error "STT_NUM has grown. update mdb_tgt_sym_match()"
#endif

	uchar_t s_bind = GELF_ST_BIND(sym->st_info);
	uchar_t s_type = GELF_ST_TYPE(sym->st_info);

	/*
	 * In case you haven't already guessed, this relies on the bitmask
	 * used by <mdb/mdb_target.h> and <libproc.h> for encoding symbol
	 * type and binding matching the order of STB and STT constants
	 * in <sys/elf.h>.  Changes to ELF must maintain binary
	 * compatibility, so I think this is reasonably fair game.
	 */
	if (s_bind < STB_NUM && s_type < STT_NUM) {
		uint_t type = (1 << (s_type + 8)) | (1 << s_bind);
		return ((type & ~mask) == 0);
	}

	return (0); /* Unknown binding or type; fail to match */
}

void
mdb_tgt_elf_export(mdb_gelf_file_t *gf)
{
	GElf_Xword d = 0, t = 0;
	GElf_Addr b = 0, e = 0;
	uint32_t m = 0;
	mdb_var_t *v;

	/*
	 * Reset legacy adb variables based on the specified ELF object file
	 * provided by the target.  We define these variables:
	 *
	 * b - the address of the data segment (first writeable Phdr)
	 * d - the size of the data segment
	 * e - the address of the entry point
	 * m - the magic number identifying the file
	 * t - the address of the text segment (first executable Phdr)
	 */
	if (gf != NULL) {
		const GElf_Phdr *text = NULL, *data = NULL;
		size_t i;

		e = gf->gf_ehdr.e_entry;
		bcopy(&gf->gf_ehdr.e_ident[EI_MAG0], &m, sizeof (m));

		for (i = 0; i < gf->gf_npload; i++) {
			if (text == NULL && (gf->gf_phdrs[i].p_flags & PF_X))
				text = &gf->gf_phdrs[i];
			if (data == NULL && (gf->gf_phdrs[i].p_flags & PF_W))
				data = &gf->gf_phdrs[i];
		}

		if (text != NULL)
			t = text->p_memsz;
		if (data != NULL) {
			b = data->p_vaddr;
			d = data->p_memsz;
		}
	}

	if ((v = mdb_nv_lookup(&mdb.m_nv, "b")) != NULL)
		mdb_nv_set_value(v, b);
	if ((v = mdb_nv_lookup(&mdb.m_nv, "d")) != NULL)
		mdb_nv_set_value(v, d);
	if ((v = mdb_nv_lookup(&mdb.m_nv, "e")) != NULL)
		mdb_nv_set_value(v, e);
	if ((v = mdb_nv_lookup(&mdb.m_nv, "m")) != NULL)
		mdb_nv_set_value(v, m);
	if ((v = mdb_nv_lookup(&mdb.m_nv, "t")) != NULL)
		mdb_nv_set_value(v, t);
}

/*ARGSUSED*/
void
mdb_tgt_sespec_hold(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	sep->se_refs++;
	ASSERT(sep->se_refs != 0);
}

void
mdb_tgt_sespec_rele(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	ASSERT(sep->se_refs != 0);

	if (--sep->se_refs == 0) {
		mdb_dprintf(MDB_DBG_TGT, "destroying sespec %p\n", (void *)sep);
		ASSERT(mdb_list_next(&sep->se_velist) == NULL);

		if (sep->se_state != MDB_TGT_SPEC_IDLE) {
			sep->se_ops->se_dtor(t, sep);
			mdb_list_delete(&t->t_active, sep);
		} else
			mdb_list_delete(&t->t_idle, sep);

		mdb_free(sep, sizeof (mdb_sespec_t));
	}
}

mdb_sespec_t *
mdb_tgt_sespec_insert(mdb_tgt_t *t, const mdb_se_ops_t *ops, mdb_list_t *list)
{
	mdb_sespec_t *sep = mdb_zalloc(sizeof (mdb_sespec_t), UM_SLEEP);

	if (list == &t->t_active)
		sep->se_state = MDB_TGT_SPEC_ACTIVE;
	else
		sep->se_state = MDB_TGT_SPEC_IDLE;

	mdb_list_append(list, sep);
	sep->se_ops = ops;
	return (sep);
}

mdb_sespec_t *
mdb_tgt_sespec_lookup_active(mdb_tgt_t *t, const mdb_se_ops_t *ops, void *args)
{
	mdb_sespec_t *sep;

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		if (sep->se_ops == ops && sep->se_ops->se_secmp(t, sep, args))
			break;
	}

	return (sep);
}

mdb_sespec_t *
mdb_tgt_sespec_lookup_idle(mdb_tgt_t *t, const mdb_se_ops_t *ops, void *args)
{
	mdb_sespec_t *sep;

	for (sep = mdb_list_next(&t->t_idle); sep; sep = mdb_list_next(sep)) {
		if (sep->se_ops == ops && sep->se_ops->se_vecmp(t,
		    mdb_list_next(&sep->se_velist), args))
			break;
	}

	return (sep);
}

/*ARGSUSED*/
void
mdb_tgt_vespec_hold(mdb_tgt_t *t, mdb_vespec_t *vep)
{
	vep->ve_refs++;
	ASSERT(vep->ve_refs != 0);
}

void
mdb_tgt_vespec_rele(mdb_tgt_t *t, mdb_vespec_t *vep)
{
	ASSERT(vep->ve_refs != 0);

	if (--vep->ve_refs == 0) {
		/*
		 * Remove this vespec from the sespec's velist and decrement
		 * the reference count on the sespec.
		 */
		mdb_list_delete(&vep->ve_se->se_velist, vep);
		mdb_tgt_sespec_rele(t, vep->ve_se);

		/*
		 * If we are deleting the most recently assigned VID, reset
		 * t_vepos or t_veneg as appropriate to re-use that number.
		 * This could be enhanced to re-use any free number by
		 * maintaining a bitmap or hash of the allocated IDs.
		 */
		if (vep->ve_id > 0 && t->t_vepos == vep->ve_id + 1)
			t->t_vepos = vep->ve_id;
		else if (vep->ve_id < 0 && t->t_veneg == -vep->ve_id + 1)
			t->t_veneg = -vep->ve_id;

		/*
		 * Call the destructor to clean up ve_args, and then free
		 * the actual vespec structure.
		 */
		vep->ve_dtor(vep);
		mdb_free(vep, sizeof (mdb_vespec_t));

		ASSERT(t->t_vecnt != 0);
		t->t_vecnt--;
	}
}

int
mdb_tgt_vespec_insert(mdb_tgt_t *t, const mdb_se_ops_t *ops, int flags,
    mdb_tgt_se_f *func, void *data, void *args, void (*dtor)(mdb_vespec_t *))
{
	mdb_vespec_t *vep = mdb_zalloc(sizeof (mdb_vespec_t), UM_SLEEP);

	int id, mult, *seqp;
	mdb_sespec_t *sep;

	/*
	 * Make that only one MDB_TGT_SPEC_AUTO* bit is set in the new flags
	 * value: extra bits are cleared according to order of precedence.
	 */
	if (flags & MDB_TGT_SPEC_AUTOSTOP)
		flags &= ~(MDB_TGT_SPEC_AUTODEL | MDB_TGT_SPEC_AUTODIS);
	else if (flags & MDB_TGT_SPEC_AUTODEL)
		flags &= ~MDB_TGT_SPEC_AUTODIS;

	/*
	 * The TEMPORARY property always takes precedence over STICKY.
	 */
	if (flags & MDB_TGT_SPEC_TEMPORARY)
		flags &= ~MDB_TGT_SPEC_STICKY;

	/*
	 * Find a matching sespec or create a new one on the appropriate list.
	 * We always create a new sespec if the vespec is created disabled.
	 */
	if (flags & MDB_TGT_SPEC_DISABLED)
		sep = mdb_tgt_sespec_insert(t, ops, &t->t_idle);
	else if ((sep = mdb_tgt_sespec_lookup_active(t, ops, args)) == NULL &&
	    (sep = mdb_tgt_sespec_lookup_idle(t, ops, args)) == NULL)
		sep = mdb_tgt_sespec_insert(t, ops, &t->t_active);

	/*
	 * Generate a new ID for the vespec.  Increasing positive integers are
	 * assigned to visible vespecs; decreasing negative integers are
	 * assigned to hidden vespecs.  The target saves our most recent choice.
	 */
	if (flags & MDB_TGT_SPEC_INTERNAL) {
		seqp = &t->t_veneg;
		mult = -1;
	} else {
		seqp = &t->t_vepos;
		mult = 1;
	}

	id = *seqp;

	while (mdb_tgt_vespec_lookup(t, id * mult) != NULL)
		id = MAX(id + 1, 1);

	*seqp = MAX(id + 1, 1);

	vep->ve_id = id * mult;
	vep->ve_flags = flags & ~(MDB_TGT_SPEC_MATCHED | MDB_TGT_SPEC_DELETED);
	vep->ve_se = sep;
	vep->ve_callback = func;
	vep->ve_data = data;
	vep->ve_args = args;
	vep->ve_dtor = dtor;

	mdb_list_append(&sep->se_velist, vep);
	mdb_tgt_sespec_hold(t, sep);

	mdb_tgt_vespec_hold(t, vep);
	t->t_vecnt++;

	/*
	 * If this vespec is the first reference to the sespec and it's active,
	 * then it is newly created and we should attempt to initialize it.
	 * If se_ctor fails, then move the sespec back to the idle list.
	 */
	if (sep->se_refs == 1 && sep->se_state == MDB_TGT_SPEC_ACTIVE &&
	    sep->se_ops->se_ctor(t, sep, vep->ve_args) == -1) {

		mdb_list_delete(&t->t_active, sep);
		mdb_list_append(&t->t_idle, sep);

		sep->se_state = MDB_TGT_SPEC_IDLE;
		sep->se_errno = errno;
		sep->se_data = NULL;
	}

	/*
	 * If the sespec is active and the target is currently running (because
	 * we grabbed it using PGRAB_NOSTOP), then go ahead and attempt to arm
	 * the sespec so it will take effect immediately.
	 */
	if (sep->se_state == MDB_TGT_SPEC_ACTIVE &&
	    t->t_status.st_state == MDB_TGT_RUNNING)
		mdb_tgt_sespec_arm_one(t, sep);

	mdb_dprintf(MDB_DBG_TGT, "inserted [ %d ] sep=%p refs=%u state=%d\n",
	    vep->ve_id, (void *)sep, sep->se_refs, sep->se_state);

	return (vep->ve_id);
}

/*
 * Search the target's active, idle, and disabled lists for the vespec matching
 * the specified VID, and return a pointer to it, or NULL if no match is found.
 */
mdb_vespec_t *
mdb_tgt_vespec_lookup(mdb_tgt_t *t, int vid)
{
	mdb_sespec_t *sep;
	mdb_vespec_t *vep;

	if (vid == 0)
		return (NULL); /* 0 is never a valid VID */

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		for (vep = mdb_list_next(&sep->se_velist); vep;
		    vep = mdb_list_next(vep)) {
			if (vep->ve_id == vid)
				return (vep);
		}
	}

	for (sep = mdb_list_next(&t->t_idle); sep; sep = mdb_list_next(sep)) {
		for (vep = mdb_list_next(&sep->se_velist); vep;
		    vep = mdb_list_next(vep)) {
			if (vep->ve_id == vid)
				return (vep);
		}
	}

	return (NULL);
}

/*ARGSUSED*/
void
no_ve_dtor(mdb_vespec_t *vep)
{
	/* default destructor does nothing */
}

/*ARGSUSED*/
void
no_se_f(mdb_tgt_t *t, int vid, void *data)
{
	/* default callback does nothing */
}

/*ARGSUSED*/
void
no_se_dtor(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	/* default destructor does nothing */
}

/*ARGSUSED*/
int
no_se_secmp(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	return (sep->se_data == args);
}

/*ARGSUSED*/
int
no_se_vecmp(mdb_tgt_t *t, mdb_vespec_t *vep, void *args)
{
	return (vep->ve_args == args);
}

/*ARGSUSED*/
int
no_se_arm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	return (0); /* return success */
}

/*ARGSUSED*/
int
no_se_disarm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	return (0); /* return success */
}

/*ARGSUSED*/
int
no_se_cont(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	if (tsp != &t->t_status)
		bcopy(&t->t_status, tsp, sizeof (mdb_tgt_status_t));

	return (0); /* return success */
}

int
mdb_tgt_register_dcmds(mdb_tgt_t *t, const mdb_dcmd_t *dcp, int flags)
{
	int fail = 0;

	for (; dcp->dc_name != NULL; dcp++) {
		if (mdb_module_add_dcmd(t->t_module, dcp, flags) == -1) {
			warn("failed to add dcmd %s", dcp->dc_name);
			fail++;
		}
	}

	return (fail > 0 ? -1 : 0);
}

int
mdb_tgt_register_walkers(mdb_tgt_t *t, const mdb_walker_t *wp, int flags)
{
	int fail = 0;

	for (; wp->walk_name != NULL; wp++) {
		if (mdb_module_add_walker(t->t_module, wp, flags) == -1) {
			warn("failed to add walk %s", wp->walk_name);
			fail++;
		}
	}

	return (fail > 0 ? -1 : 0);
}

void
mdb_tgt_register_regvars(mdb_tgt_t *t, const mdb_tgt_regdesc_t *rdp,
    const mdb_nv_disc_t *disc, int flags)
{
	for (; rdp->rd_name != NULL; rdp++) {
		if (!(rdp->rd_flags & MDB_TGT_R_EXPORT))
			continue; /* Don't export register as a variable */

		if (rdp->rd_flags & MDB_TGT_R_RDONLY)
			flags |= MDB_NV_RDONLY;

		(void) mdb_nv_insert(&mdb.m_nv, rdp->rd_name, disc,
		    (uintptr_t)t, MDB_NV_PERSIST | flags);
	}
}
