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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include 	<errno.h>
#include 	<priv.h>
#include 	<sys/tsol/priv.h>
#include 	<sys/varargs.h>

/*
 * set_effective_priv(op, num_priv, priv_id1, priv_id2, ... )
 *
 * Library routine to enable a user process to set its effective
 * privilege set appropriately using a single call.  User is
 * required to specify the number of privilege ids that follow as
 * arguments, rather than depending on the compiler to terminate
 * the argument list with a NULL, which may be compiler-dependent.
 */
int
set_effective_priv(priv_op_t op, int num_priv, ...)
{
	priv_set_t *priv_set;
	priv_t priv_id;
	va_list ap;
	int	status;

	priv_set = priv_allocset();
	PRIV_EMPTY(priv_set);

	va_start(ap, num_priv);
	while (num_priv--) {
		char	*priv_name;
		/*
		 * Do sanity checking on priv_id's here to assure
		 * valid inputs to privilege macros.  This checks
		 * num_priv argument as well.
		 */
		priv_id = va_arg(ap, priv_t);
		priv_name = (char *)priv_getbynum((int)(uintptr_t)priv_id);
		if (priv_name == NULL) {
			errno = EINVAL;
			priv_freeset(priv_set);
			return (-1);
		}
		(void) priv_addset(priv_set, priv_name);
	}
	va_end(ap);

	/*
	 * Depend on system call to do sanity checking on "op"
	 */
	status = setppriv(op, PRIV_EFFECTIVE, priv_set);
	priv_freeset(priv_set);
	return (status);

} /* set_effective_priv() */




/*
 * set_inheritable_priv(op, num_priv, priv_id1, priv_id2, ... )
 *
 * Library routine to enable a user process to set its inheritable
 * privilege set appropriately using a single call.  User is
 * required to specify the number of privilege ids that follow as
 * arguments, rather than depending on the compiler to terminate
 * the argument list with a NULL, which may be compiler-dependent.
 */
int
set_inheritable_priv(priv_op_t op, int num_priv, ...)
{
	priv_set_t *priv_set;
	priv_t priv_id;
	va_list ap;
	int	status;

	priv_set = priv_allocset();

	PRIV_EMPTY(priv_set);

	va_start(ap, num_priv);
	while (num_priv--) {
		/*
		 * Do sanity checking on priv_id's here to assure
		 * valid inputs to privilege macros.  This checks
		 * num_priv argument as well.
		 */
		priv_id = va_arg(ap, priv_t);
		if ((char *)priv_getbynum((int)(uintptr_t)priv_id) == NULL) {
			errno = EINVAL;
			priv_freeset(priv_set);
			return (-1);
		}
		(void) PRIV_ASSERT(priv_set, priv_id);
	}
	va_end(ap);

	/*
	 * Depend on system call to do sanity checking on "op"
	 */
	status = setppriv(op, PRIV_INHERITABLE, priv_set);
	priv_freeset(priv_set);
	return (status);

} /* set_inheritable_priv() */




/*
 * set_permitted_priv(op, num_priv, priv_id1, priv_id2, ... )
 *
 * Library routine to enable a user process to set its permitted
 * privilege set appropriately using a single call.  User is
 * required to specify the number of privilege ids that follow as
 * arguments, rather than depending on the compiler to terminate
 * the argument list with a NULL, which may be compiler-dependent.
 */
int
set_permitted_priv(priv_op_t op, int num_priv, ...)
{
	priv_set_t *priv_set;
	priv_t priv_id;
	va_list ap;
	int	status;

	priv_set = priv_allocset();

	PRIV_EMPTY(priv_set);

	va_start(ap, num_priv);
	while (num_priv--) {
		/*
		 * Do sanity checking on priv_id's here to assure
		 * valid inputs to privilege macros.  This checks
		 * num_priv argument as well.
		 */
		priv_id = va_arg(ap, priv_t);
		if ((char *)priv_getbynum((int)(uintptr_t)priv_id) == NULL) {
			errno = EINVAL;
			priv_freeset(priv_set);
			return (-1);
		}
		(void) PRIV_ASSERT(priv_set, priv_id);
	}
	va_end(ap);

	/*
	 * Depend on system call to do sanity checking on "op"
	 */
	status = setppriv(op, PRIV_PERMITTED, priv_set);
	priv_freeset(priv_set);
	return (status);

} /* set_permitted_priv() */
