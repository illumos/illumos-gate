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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SPCS_S_K_H
#define	_SPCS_S_K_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Public SPCS uniform status details
 */

/*
 *	KERNEL level status support utilities
 */


/*
 *	Create and initialize local status. Call this at entry to topmost
 *	operation (e.g. the start of ioctl service)
 *      @return The allocated and initialized status info or NULL if no memory
 *	available
 */
spcs_s_info_t
spcs_s_kcreate();

/*
 *	Initialize existing status. Call this at entry to topmost operation
 *      (e.g. the start of ioctl service)
 *      @param kstatus The status info.
 */
void
spcs_s_kinit(spcs_s_info_t kstatus);

/*
 *	Add a status code and optional support information to status
 *      @param kstatus  The status info pointer
 *      @param stcode    The status code to be added (.e.g. DSW_EEMPTY)
 *      <BR>Supplemental value parameters may be supplied as needed. There
 *	should be one supplemental info parameter corresponding
 *      to each edit specification (e.g. %s) in the message text for a
 *      given code.
 *      <BR>If there is no additional room to insert everything the code
 *      SPCS_EOVERFLOW is inserted instead of stcode, possibly replacing an
 *	a previously inserted status code.
 */
void
spcs_s_add(spcs_s_info_t kstatus, spcs_s_status_t stcode, ...);

/*
 *	Copy status info to userspace
 *      @param kstatus_a is The address of the local (kernel) status info
 *      @param ustatus The userspace status info
 */
void
spcs_s_copyout(spcs_s_info_t *kstatus_a, spcs_s_info_t ustatus);

/*
 *	Copy status info to userspace and free status info storage
 *      @param kstatus_a is The address of the local (kernel) status info
 *      @param ustatus The userspace status info
 */
void
spcs_s_copyoutf(spcs_s_info_t *kstatus_a, spcs_s_info_t ustatus);

/*
 *	Return the oldest status code from the status info or SPCS_S_OK if
 *      there is none. This is the status code that was inserted first (i.e.
 *      LIFO).
 *      @param kstatus The local (kernel level) status info
 *      @return The oldest status code value
 */

spcs_s_status_t
spcs_s_oldest_status(spcs_s_info_t kstatus);

/*
 *	Return the youngest status code from the status info or SPCS_S_OK if
 *      there is none. This is the status code that was inserted last (i.e.
 *      LIFO).
 *      @param kstatus The local (kernel level) status info
 *      @return The youngest status code value
 */

spcs_s_status_t
spcs_s_youngest_status(spcs_s_info_t kstatus);

/*
 *      Copy status info to userspace and provide return value.
 *      <BR>This is a one-step means of returning from a kernel function. It is
 *      identical to spcs_s_fcopyout except that the kernel status storage is
 *	not released.
 *      @param kstatus_a The address of the local kernel status info.
 *      @param ustatus The user status info
 *      @param stcode A status code. If the status code is NULL it is ignored.
 *      <BR>Supplemental value parameters may be supplied as needed. There
 *	should be one supplemental info parameter corresponding
 *      to each edit specification (e.g. %s) in the message text for a
 *      given code.
 *      <BR>If there is no additional room to insert everything the code
 *      SPCS_EOVERFLOW is inserted instead of stcode, possibly replacing an
 *	a previously inserted status code.
 *      @return If stcode is NULL and there is no status info present,
 *      SPCS_S_OK, else SPCS_S_ERROR.
 */
spcs_s_status_t
spcs_s_ocopyout(spcs_s_info_t *kstatus_a,
			spcs_s_info_t ustatus, spcs_s_status_t stcode, ...);

/*
 *	Copy status info to userspace, free it and provide a return value
 *      <BR>This is a one-step means of returning from a kernel function. It is
 *      identical to spcs_s_fcopyout except that the kernel status storage is
 *	released.
 *      <BR>Return a value to use as a function result (SPCS_S_OK or ERROR)
 *      <BR>This is a one-step means of returning from an operation. It is
 *      identical to spcs_s_copyout except that the kernel status information
 *      storage is released.
 *      @param kstatus_a The address of the local kernel status info.
 *      @param ustatus The user status info
 *      @param stcode A status code. If the status code is NULL it is ignored.
 *      @param stcode A status code. If the status code is NULL it is ignored.
 *      <BR>Supplemental value parameters may be supplied as needed. There
 *	should be one supplemental info parameter corresponding
 *      to each edit specification (e.g. %s) in the message text for a
 *      <BR>If there is no additional room to insert everything the code
 *      SPCS_EOVERFLOW is inserted instead of stcode, possibly replacing an
 *	a previously inserted status code.
 *      @return If stcode is NULL and there is no status info present,
 *      SPCS_S_OK, else SPCS_S_ERROR.
 */
spcs_s_status_t
spcs_s_ocopyoutf(spcs_s_info_t *kstatus_a,
		spcs_s_info_t ustatus, spcs_s_status_t stcode, ...);

/*
 *	Release (free) status storage.
 *	@param status The status information to release (kmem_free)
 */
void
spcs_s_kfree(spcs_s_info_t status);

/*
 *	Test a status code and return true if it is a Solaris error code
 *	@return B_TRUE if the code is a Solaris code (module == 0), else
 *	B_FALSE
 */
boolean_t
spcs_s_is_solaris(spcs_s_status_t error);

/*
 *
 *	Edit an value into a decimal or hexidecimal string.
 *	Note that if multiple calls to this function are used to develop the
 *	parameters for spcs_s_add() the character arrays must be distinct.
 *      @param val    The value to edit
 *      @param buf    Pointer to the start of a char array for conversion
 *      @param buflen The size of the char array (minimum 2)
 *      @param hex    If nonzero "0x" is prepended to generated string and
 *		      it is edited as hexidecimal.
 *      @return       The numeric string or "***" if an error is detected
 */

char *
spcs_s_inttostring(int val, char *buf, int buflen, int hex);

/*
 *	Initialize the bytestream mechanism.
 *
 *	This function initializes the Unistat mechanism for transporting
 *	status information with or without bytestream data to userspace.
 *
 *	@return   SPCS_S_OK for normal completion, SPCS_S_ERROR otherwise
 *
 *	Specification TBD. Not in 10/22 commitment
 */

int
spcs_s_start_bytestream();

/*
 *	Stop (shut off) the bytestream mechanism.
 *
 *	This function terminates the Unistat mechanism for transporting
 *	status information with or without bytestream data to userspace.
 *
 *	@return   SPCS_S_OK for normal completion, SPCS_S_ERROR otherwise
 *
 *	Specification TBD. Not in 10/22 commitment
 */

int
spcs_s_stop_bytestream();

/*
 *	Add a status code and the address and length of arbitrary binary
 *	data to be held (possibly with other status) for later transmission to
 *	userspace via a pipe facility (i.e. NOT via ioctl return). This is a
 *	means of getting arbitrary information with or without other status
 *	info shipped out as an alternative to cmn_err and/or trace file
 *	mechanisms.
 *      @param kstatus  The status info pointer
 *      @param stcode   The status code to annotate the data
 *      @param data     The starting address of the data
 *      @param size     The byte length of the data
 *	Specification TBD. Not in the 10/22/98 unistat commitment
 */

void
spcs_s_add_bytestream(spcs_s_info_t kstatus, spcs_s_status_t stcode,
	spcs_s_bytestream_ptr_t data, int size);

/*
 *	Asynchronously output unistat info and possibly bytestreams to
 *	userspace. The bytestream mechanism must have been initialized.
 *      @param kstatus  The status info pointer
 *      @return SPCS_S_OK for normal completion, SPCS_S_ERROR otherwise
 *	Specification TBD. Not in the 10/22/98 unistat commitment
 */

int
spcs_s_asynch_status(spcs_s_info_t kstatus);

#ifdef __cplusplus
}
#endif

#endif /* _SPCS_S_K_H */
