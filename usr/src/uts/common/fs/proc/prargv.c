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
 * Copyright 2015, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/proc.h>
#include <sys/procfs.h>
#include <sys/sysmacros.h>
#include <vm/as.h>

/*
 * Safely read a contiguous region of memory from 'addr' in the address space
 * of a particular process into the supplied kernel buffer (*buf, sz).
 * Partially mapped regions will result in a partial read terminating at the
 * first hole in the address space.  The number of bytes actually read is
 * returned to the caller via 'rdsz'.
 */
static int
prreadbuf(proc_t *p, uintptr_t addr, uint8_t *buf, size_t sz, size_t *rdsz)
{
	int error = 0;
	size_t rem = sz;
	off_t pos = 0;

	if (rdsz != NULL)
		*rdsz = 0;

	while (rem != 0) {
		size_t len = MIN(rem, PAGESIZE - (addr & PAGEOFFSET));

		if ((error = uread(p, buf + pos, len, addr + pos)) != 0) {
			if (error == ENXIO) {
				/*
				 * ENXIO from uread() indicates that the page
				 * does not exist.  This will simply be a
				 * partial read.
				 */
				error = 0;
			}
			break;
		}

		rem -= len;
		pos += len;
	}

	if (rdsz != NULL)
		*rdsz = pos;

	return (error);
}

/*
 * Attempt to read the argument vector (argv) from this process.  The caller
 * must hold the p_lock mutex, and have marked the process P_PR_LOCK (e.g. via
 * prlock or lx_prlock).
 *
 * The caller must provide a buffer (buf, buflen).  We will concatenate each
 * argument string (including the NUL terminator) into this buffer.  The number
 * of characters written to this buffer (including the final NUL terminator)
 * will be stored in 'slen'.
 */
int
prreadargv(proc_t *p, char *buf, size_t bufsz, size_t *slen)
{
	int error;
	user_t *up;
	struct as *as;
	size_t pos = 0;
	caddr_t *argv = NULL;
	size_t argvsz = 0;
	int i;

	VERIFY(MUTEX_HELD(&p->p_lock));
	VERIFY(p->p_proc_flag & P_PR_LOCK);

	up = PTOU(p);
	as = p->p_as;

	if ((p->p_flag & SSYS) || as == &kas || up->u_argv == NULL) {
		/*
		 * Return the regular psargs string to the caller.
		 */
		bcopy(up->u_psargs, buf, MIN(bufsz, sizeof (up->u_psargs)));
		buf[bufsz - 1] = '\0';
		*slen = strlen(buf) + 1;

		return (0);
	}

	/*
	 * Allocate space to store argv array.
	 */
	argvsz = up->u_argc * (p->p_model == DATAMODEL_ILP32 ?
	    sizeof (caddr32_t) : sizeof (caddr_t));
	argv = kmem_alloc(argvsz, KM_SLEEP);

	/*
	 * Extract the argv array from the target process.  Drop p_lock
	 * while we do I/O to avoid deadlock with the clock thread.
	 */
	mutex_exit(&p->p_lock);
	if ((error = prreadbuf(p, up->u_argv, (uint8_t *)argv, argvsz,
	    NULL)) != 0) {
		kmem_free(argv, argvsz);
		mutex_enter(&p->p_lock);
		VERIFY(p->p_proc_flag & P_PR_LOCK);
		return (-1);
	}

	/*
	 * Read each argument string from the pointers in the argv array.
	 */
	pos = 0;
	for (i = 0; i < up->u_argc; i++) {
		size_t rdsz, trysz;
		uintptr_t arg;
		off_t j;
		boolean_t found_nul;
		boolean_t do_retry = B_TRUE;

#ifdef	_SYSCALL32_IMPL
		if (p->p_model == DATAMODEL_ILP32) {
			arg = (uintptr_t)((caddr32_t *)argv)[i];
		} else {
			arg = (uintptr_t)argv[i];
		}
#else
		arg = (uintptr_t)argv[i];
#endif

		/*
		 * Stop trying to read arguments if we reach a NULL
		 * pointer in the vector.
		 */
		if (arg == NULL)
			break;

		/*
		 * Stop reading if we have read the maximum length
		 * we can return to the user.
		 */
		if (pos >= bufsz)
			break;

		/*
		 * Initially we try a short read, on the assumption that
		 * most individual argument strings are less than 80
		 * characters long.
		 */
		if ((trysz = MIN(80, bufsz - pos - 1)) < 80) {
			/*
			 * We don't have room in the target buffer for even
			 * an entire short read, so there is no need to retry
			 * with a longer read.
			 */
			do_retry = B_FALSE;
		}

retry:
		/*
		 * Read string data for this argument.  Leave room
		 * in the buffer for a final NUL terminator.
		 */
		if ((error = prreadbuf(p, arg, (uint8_t *)&buf[pos], trysz,
		    &rdsz)) != 0) {
			/*
			 * There was a problem reading this string
			 * from the process.  Give up.
			 */
			break;
		}

		/*
		 * Find the NUL terminator.
		 */
		found_nul = B_FALSE;
		for (j = 0; j < rdsz; j++) {
			if (buf[pos + j] == '\0') {
				found_nul = B_TRUE;
				break;
			}
		}

		if (!found_nul && do_retry) {
			/*
			 * We did not find a NUL terminator, but this
			 * was a first pass short read.  Try once more
			 * with feeling.
			 */
			trysz = bufsz - pos - 1;
			do_retry = B_FALSE;
			goto retry;
		}

		/*
		 * Commit the string we read to the buffer.
		 */
		pos += j + 1;
		if (!found_nul) {
			/*
			 * A NUL terminator was not found; add one.
			 */
			buf[pos++] = '\0';
		}
	}

	/*
	 * Ensure the entire string is NUL-terminated.
	 */
	buf[bufsz - 1] = '\0';

	mutex_enter(&p->p_lock);
	VERIFY(p->p_proc_flag & P_PR_LOCK);
	kmem_free(argv, argvsz);

	/*
	 * If the operation was a success, return the copied string length
	 * to the caller.
	 */
	*slen = (error == 0) ? pos : 0;

	return (error);
}
