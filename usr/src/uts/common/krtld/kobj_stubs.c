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

#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/errno.h>

/*
 * Stubs for entry points into
 * the stand-alone linker/loader.
 */

int
kobj_load_module(struct modctl *modp __unused, int use_path __unused)
{
	return (EINVAL);
}

int
kobj_load_primary_module(struct modctl *modp __unused)
{
	return (-1);
}

void
kobj_unload_module(struct modctl *modp __unused)
{
}

int
kobj_path_exists(char *name __unused, int use_path __unused)
{
	return (0);
}

struct _buf *
kobj_open_path(char *name __unused, int use_path __unused,
    int use_moddir_suffix __unused)
{
	return (NULL);
}

struct _buf *
kobj_open_file(char *name __unused)
{
	return (NULL);
}

int
kobj_read_file(struct _buf *file __unused, char *buf __unused,
    unsigned size __unused, unsigned off __unused)
{
	return (-1);
}

void
kobj_close_file(struct _buf *file __unused)
{
}

intptr_t
kobj_open(char *filename __unused)
{
	return (-1L);
}

int
kobj_read(intptr_t descr __unused, char *buf __unused, unsigned size __unused,
    unsigned offset __unused)
{
	return (-1);
}

void
kobj_close(intptr_t descr __unused)
{
}

int
kobj_fstat(intptr_t descr __unused, struct bootstat *buf __unused)
{
	return (-1);
}

int
kobj_get_filesize(struct _buf *file __unused, uint64_t *size __unused)
{
	return (-1);
}

int
kobj_filbuf(struct _buf *f __unused)
{
	return (-1);
}

int
kobj_addrcheck(void *xmp __unused, caddr_t adr __unused)
{
	return (1);
}

uintptr_t
kobj_getelfsym(char *name __unused, void *mp __unused, int *size __unused)
{
	return (0);
}

void
kobj_getmodinfo(void *xmp __unused, struct modinfo *modinfo __unused)
{
}

void
kobj_getpagesize(void)
{
}

char *
kobj_getsymname(uintptr_t value __unused, ulong_t *offset __unused)
{
	return (NULL);
}

uintptr_t
kobj_getsymvalue(char *name __unused, int kernelonly __unused)
{
	return (0);
}

char *
kobj_searchsym(struct module *mp __unused, uintptr_t value __unused,
    ulong_t *offset __unused)
{
	return (NULL);
}

uintptr_t
kobj_lookup(struct module *mod __unused, const char *name __unused)
{
	return (0);
}

Sym *
kobj_lookup_all(struct module *mp __unused, char *name __unused,
    int include_self __unused)
{
	return (NULL);
}

void *
kobj_alloc(size_t size __unused, int flag __unused)
{
	return (NULL);
}

void *
kobj_zalloc(size_t size __unused, int flag __unused)
{
	return (NULL);
}

void
kobj_free(void *address __unused, size_t size __unused)
{
}

void
kobj_sync(void)
{
}

void
kobj_stat_get(kobj_stat_t *kp __unused)
{
}

void
kobj_sync_instruction_memory(caddr_t addr __unused, size_t size __unused)
{
}

int
kobj_notify_add(kobj_notify_list_t *knp __unused)
{
	return (-1);
}

int
kobj_notify_remove(kobj_notify_list_t *knp __unused)
{
	return (-1);
}

void
kobj_export_module(struct module *mp __unused)
{
}

#ifndef sparc
void
kobj_boot_unmountroot(void)
{
}
#endif

/*
 * Dummy declarations for variables in
 * the stand-alone linker/loader.
 */
char *boot_cpu_compatible_list;
