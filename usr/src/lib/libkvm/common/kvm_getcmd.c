/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <kvm.h>
#include <strings.h>
#include <sys/types32.h>

#define	_SYSCALL32

/*
 * VERSION FOR MACHINES WITH STACKS GROWING DOWNWARD IN MEMORY
 *
 * On program entry, the top of the stack frame looks like this:
 *
 * hi:	|-----------------------|
 *	|	unspecified	|
 *	|-----------------------|+
 *	|	   :		| \
 *	|  arg and env strings	|  > no more than NCARGS bytes
 *	|	   :		| /
 *	|-----------------------|+
 *	|	unspecified	|
 *	|-----------------------|
 *	| null auxiliary vector	|
 *	|-----------------------|
 *	|   auxiliary vector	|
 *	|   (2-word entries)	|
 *	|	   :		|
 *	|-----------------------|
 *	|	(char *)0	|
 *	|-----------------------|
 *	|  ptrs to env strings	|
 *	|	   :		|
 *	|-----------------------|
 *	|	(char *)0	|
 *	|-----------------------|
 *	|  ptrs to arg strings	|
 *	|   (argc = # of ptrs)	|
 *	|	   :		|
 *	|-----------------------|
 *	|	  argc		|
 * low:	|-----------------------|
 */

#define	RoundUp(v, t)	(((v) + sizeof (t) - 1) & ~(sizeof (t) - 1))

static int
kvm_getcmd32(kvm_t *kd,
    struct proc *p, struct user *u, char ***arg, char ***env)
{
#if defined(_LP64) || defined(lint)
	size_t size32;
	void *stack32;
	int i, argc, envc;
	int auxc = 0;
	size_t asize, esize;
	char **argv = NULL;
	char **envp = NULL;
	size_t strpoolsz;
	int aptrcount;
	int eptrcount;
	caddr_t stackp;
	ptrdiff_t reloc;
	char *str;

	/*
	 * Bring the entire stack into memory first, size it
	 * as an LP64 user stack, then allocate and copy into
	 * the buffer(s) to be returned to the caller.
	 */
	size32 = (size_t)p->p_usrstack - (size_t)u->u_argv;
	if ((stack32 = malloc(size32)) == NULL)
		return (-1);
	if (kvm_uread(kd, (uintptr_t)u->u_argv, stack32, size32) != size32) {
		free(stack32);
		return (-1);
	}

	/*
	 * Find the interesting sizes of a 32-bit stack.
	 */
	argc = u->u_argc;
	stackp = (caddr_t)stack32 + ((1 + argc) * sizeof (caddr32_t));

	for (envc = 0; *(caddr32_t *)stackp; envc++) {
		stackp += sizeof (caddr32_t);
		if ((stackp - (caddr_t)stack32) >= size32) {
			free(stack32);
			return (-1);
		}
	}

	if (u->u_auxv[0].a_type != AT_NULL) {
		stackp += sizeof (caddr32_t);
		for (auxc = 0; *(int32_t *)stackp; auxc++) {
			stackp += 2 * sizeof (caddr32_t);
			if ((stackp - (caddr_t)stack32) >= size32) {
				free(stack32);
				return (-1);
			}
		}
		auxc++;		/* terminating AT_NULL record */
	}

	/*
	 * Compute the sizes of the stuff we're going to allocate or copy.
	 */
	eptrcount = (envc + 1) + 2 * auxc;
	aptrcount = (argc + 1) + eptrcount;
	strpoolsz = size32 - aptrcount * sizeof (caddr32_t);

	asize = aptrcount * sizeof (uintptr_t) + RoundUp(strpoolsz, uintptr_t);
	if (arg && (argv = calloc(1, asize + sizeof (uintptr_t))) == NULL) {
		free(stack32);
		return (-1);
	}

	esize = eptrcount * sizeof (uintptr_t) + RoundUp(strpoolsz, uintptr_t);
	if (env && (envp = calloc(1, esize + sizeof (uintptr_t))) == NULL) {
		if (argv)
			free(argv);
		free(stack32);
		return (-1);
	}

	/*
	 * Walk up the 32-bit stack, filling in the 64-bit argv and envp
	 * as we go.
	 */
	stackp = (caddr_t)stack32;

	/*
	 * argument vector
	 */
	if (argv) {
		for (i = 0; i < argc; i++) {
			argv[i] = (char *)(uintptr_t)(*(caddr32_t *)stackp);
			stackp += sizeof (caddr32_t);
		}
		argv[argc] = 0;
		stackp += sizeof (caddr32_t);
	} else
		stackp += (1 + argc) * sizeof (caddr32_t);

	/*
	 * environment
	 */
	if (envp) {
		for (i = 0; i < envc; i++) {
			envp[i] = (char *)(uintptr_t)(*(caddr32_t *)stackp);
			stackp += sizeof (caddr32_t);
		}
		envp[envc] = 0;
		stackp += sizeof (caddr32_t);
	} else
		stackp += (1 + envc) * sizeof (caddr32_t);

	/*
	 * auxiliary vector (skip it..)
	 */
	stackp += auxc * (sizeof (int32_t) + sizeof (uint32_t));

	/*
	 * Copy the string pool, untranslated
	 */
	if (argv)
		(void) memcpy(argv + aptrcount, (void *)stackp, strpoolsz);
	if (envp)
		(void) memcpy(envp + eptrcount, (void *)stackp, strpoolsz);

	free(stack32);

	/*
	 * Relocate the pointers to point at the newly allocated space.
	 * Use the same algorithms as kvm_getcmd to handle naughty
	 * changes to the argv and envp arrays.
	 */
	if (argv) {
		char *argv_null = (char *)argv + asize;

		reloc = (char *)(argv + aptrcount) - (char *)
		    ((caddr_t)u->u_argv + aptrcount * sizeof (caddr32_t));

		for (i = 0; i < argc; i++)
			if (argv[i] != NULL) {
				str = (argv[i] += reloc);
				if (str < (char *)argv ||
				    str >= (char *)argv + asize)
					argv[i] = argv_null;
			}

		*arg = argv;
	}

	if (envp) {
		char *envp_null = (char *)envp + esize;
		char *last_str;

		reloc = (char *)(envp + eptrcount) - (char *)
		    ((caddr_t)u->u_envp + eptrcount * sizeof (caddr32_t));

		last_str = (char *)((size_t)u->u_argv +
		    (1 + argc) * sizeof (caddr32_t) + reloc);
		if (last_str < (char *)envp ||
		    last_str >= (char *)envp + esize)
			last_str = envp_null;

		for (i = 0; i < envc; i++) {
			str = (envp[i] += reloc);
			if (str < (char *)envp ||
			    str >= (char *)envp + esize) {
				if (last_str != envp_null)
					envp[i] = (char *)((size_t)last_str +
					    strlen(last_str) + 1);
				else
					envp[i] = envp_null;
			}
			last_str = envp[i];
		}
		*env = envp;
	}
#endif	/* _LP64 || lint */
	return (0);
}

/*
 * reconstruct an argv-like argument list from the target process
 */
int
kvm_getcmd(kvm_t *kd,
    struct proc *proc, struct user *u, char ***arg, char ***env)
{
	size_t asize;
	size_t esize;
	size_t offset;
	int i;
	int argc;
	char **argv = NULL;
	char **envp = NULL;
	char *str;
	char *last_str;
	char *argv_null;	/* Known null in the returned argv */
	char *envp_null;	/* Known null in the returned envp */

	if (proc->p_flag & SSYS)	/* system process */
		return (-1);

	/*
	 * Protect against proc structs found by kvm_nextproc()
	 * while the kernel was doing a fork(). Such a proc struct
	 * may have p_usrstack set but a still zeroed uarea.
	 * We wouldn't want to unecessarily allocate 4GB memory ...
	 */
	if (u->u_argv == (uintptr_t)NULL || u->u_envp == (uintptr_t)NULL)
		return (-1);

	/*
	 * If this is a 32-bit process running on a 64-bit system,
	 * then the stack is laid out using ILP32 pointers, not LP64.
	 * To minimize potential confusion, we blow it up to "LP64
	 * shaped" right here.
	 */
	if (proc->p_model != DATAMODEL_NATIVE &&
	    proc->p_model == DATAMODEL_ILP32)
		return (kvm_getcmd32(kd, proc, u, arg, env));

	/*
	 * Space for the stack, from the argument vector.  An additional
	 * word is added to guarantee a NULL word terminates the buffer.
	 */
	if (arg) {
		asize = (size_t)proc->p_usrstack - (size_t)u->u_argv;
		if ((argv = malloc(asize + sizeof (uintptr_t))) == NULL)
			return (-1);
		argv_null = (char *)argv + asize;
		*(uintptr_t *)argv_null = 0;
	}

	/*
	 * Space for the stack, from the environment vector.  An additional
	 * word is added to guarantee a NULL word terminates the buffer.
	 */
	if (env) {
		esize = (size_t)proc->p_usrstack - (size_t)u->u_envp;
		if ((envp = malloc(esize + sizeof (uintptr_t))) == NULL) {
			if (argv)
				free(argv);
			return (-1);
		}
		envp_null = (char *)envp + esize;
		*(uintptr_t *)envp_null = 0;
	}

	argc = u->u_argc;

	if (argv) {
		/* read the whole initial stack */
		if (kvm_uread(kd,
		    (uintptr_t)u->u_argv, argv, asize) != asize) {
			free(argv);
			if (envp)
				free(envp);
			return (-1);
		}
		argv[argc] = 0;
		if (envp) {
			/*
			 * Copy it to the malloc()d space for the envp array
			 */
			(void) memcpy(envp, &argv[argc + 1], esize);
		}
	} else if (envp) {
		/* read most of the initial stack (excluding argv) */
		if (kvm_uread(kd,
		    (uintptr_t)u->u_envp, envp, esize) != esize) {
			free(envp);
			return (-1);
		}
	}

	/*
	 * Relocate and sanity check the argv array.  Entries which have
	 * been explicity nulled are left that way.  Entries which have
	 * been replaced are pointed to a null string.  Well behaved apps
	 * don't do any of this.
	 */
	if (argv) {
		/* relocate the argv[] addresses */
		offset = (char *)argv - (char *)u->u_argv;
		for (i = 0; i < argc; i++) {
			if (argv[i] != NULL) {
				str = (argv[i] += offset);
				if (str < (char *)argv ||
				    str >= (char *)argv + asize)
					argv[i] = argv_null;
			}
		}
		argv[i] = NULL;
		*arg = argv;
	}

	/*
	 * Relocate and sanity check the envp array.  A null entry indicates
	 * the end of the environment.  Entries which point outside of the
	 * initial stack are replaced with what must have been the initial
	 * value based on the known ordering of the string table by the
	 * kernel.  If stack corruption prevents the calculation of the
	 * location of an initial string value, a pointer to a null string
	 * is returned.  To return a null pointer would prematurely terminate
	 * the list.  Well behaved apps do set pointers outside of the
	 * initial stack via the putenv(3C) library routine.
	 */
	if (envp) {

		/*
		 * Determine the start of the environment strings as one
		 * past the last argument string.
		 */
		offset = (char *)envp - (char *)u->u_envp;

		if (kvm_uread(kd,
		    (uintptr_t)u->u_argv + (argc - 1) * sizeof (char **),
		    &last_str, sizeof (last_str)) != sizeof (last_str))
			last_str = envp_null;
		else {
			last_str += offset;
			if (last_str < (char *)envp ||
			    last_str >= (char *)envp + esize)
				last_str = envp_null;
		}

		/*
		 * Relocate the envp[] addresses, while ensuring that we
		 * don't return bad addresses.
		 */
		for (i = 0; envp[i] != NULL; i++) {
			str = (envp[i] += offset);
			if (str < (char *)envp || str >= (char *)envp + esize) {
				if (last_str != envp_null)
					envp[i] = last_str +
					    strlen(last_str) + 1;
				else
					envp[i] = envp_null;
			}
			last_str = envp[i];
		}
		envp[i] = NULL;
		*env = envp;
	}

	return (0);
}
