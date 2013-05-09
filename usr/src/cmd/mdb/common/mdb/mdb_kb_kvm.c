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

/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

/*
 * The default KVM backend, which simply calls directly into libkvm for all
 * operations.
 */

#include <mdb/mdb_kb.h>
#include <mdb/mdb_target_impl.h>

#include <fcntl.h>
#include <dlfcn.h>
#include <kvm.h>

/*ARGSUSED*/
static mdb_io_t *
libkvm_sym_io(void *kvm, const char *ignored)
{
	mdb_io_t *io;
	const char *symfile = kvm_namelist(kvm);

	if ((io = mdb_fdio_create_path(NULL, symfile, O_RDONLY, 0)) == NULL)
		mdb_warn("failed to open %s", symfile);

	return (io);
}

mdb_kb_ops_t *
libkvm_kb_ops(void)
{
	static mdb_kb_ops_t ops = {
		.kb_open = (void *(*)())kvm_open,
		.kb_close = (int (*)())kvm_close,
		.kb_sym_io = libkvm_sym_io,
		.kb_kread = (ssize_t (*)())kvm_kread,
		.kb_kwrite = (ssize_t (*)())kvm_kwrite,
		.kb_aread = (ssize_t (*)())kvm_aread,
		.kb_awrite = (ssize_t (*)())kvm_awrite,
		.kb_pread = (ssize_t (*)())kvm_pread,
		.kb_pwrite = (ssize_t (*)())kvm_pwrite,
		.kb_getmregs = (int (*)())mdb_tgt_notsup,
		.kb_vtop = (uint64_t (*)())kvm_physaddr,
	};
	return (&ops);
}
