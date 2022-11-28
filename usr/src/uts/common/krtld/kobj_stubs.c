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

/*ARGSUSED*/
int
kobj_load_module(struct modctl *modp, int use_path)
{
	return (EINVAL);
}

/*ARGSUSED*/
int
kobj_load_primary_module(struct modctl *modp)
{
	return (-1);
}

/*ARGSUSED*/
void
kobj_unload_module(struct modctl *modp)
{}

/*ARGSUSED*/
int
kobj_path_exists(char *name, int use_path)
{
	return (0);
}

/*ARGSUSED*/
struct _buf *
kobj_open_path(char *name, int use_path, int use_moddir_suffix)
{
	return (NULL);
}

/*ARGSUSED*/
struct _buf *
kobj_open_file(char *name)
{
	return (NULL);
}

/*ARGSUSED*/
int
kobj_read_file(struct _buf *file, char *buf, unsigned size, unsigned off)
{
	return (-1);
}

/*ARGSUSED*/
void
kobj_close_file(struct _buf *file)
{}

/*ARGSUSED*/
intptr_t
kobj_open(char *filename)
{
	return (-1L);
}

/*ARGSUSED*/
int
kobj_read(intptr_t descr, char *buf, unsigned size, unsigned offset)
{
	return (-1);
}

/*ARGSUSED*/
void
kobj_close(intptr_t descr)
{}

/*ARGSUSED*/
int
kobj_fstat(intptr_t descr, struct bootstat *buf)
{
	return (-1);
}

/*ARGSUSED*/
int
kobj_get_filesize(struct _buf *file, uint64_t *size)
{
	return (-1);
}

/*ARGSUSED*/
int
kobj_filbuf(struct _buf *f)
{
	return (-1);
}

/*ARGSUSED*/
int
kobj_addrcheck(void *xmp, caddr_t adr)
{
	return (1);
}

/*ARGSUSED*/
uintptr_t
kobj_getelfsym(char *name, void *mp, int *size)
{
	return (0);
}

/*ARGSUSED*/
void
kobj_getmodinfo(void *xmp, struct modinfo *modinfo)
{}

void
kobj_getpagesize()
{}

/*ARGSUSED*/
char *
kobj_getsymname(uintptr_t value, ulong_t *offset)
{
	return (NULL);
}

/*ARGSUSED*/
uintptr_t
kobj_getsymvalue(char *name, int kernelonly)
{
	return (0);
}

/*ARGSUSED*/
char *
kobj_searchsym(struct module *mp, uintptr_t value, ulong_t *offset)
{
	return (NULL);
}

/*ARGSUSED*/
uintptr_t
kobj_lookup(struct module *mod, const char *name)
{
	return (0);
}

/*ARGSUSED*/
Sym *
kobj_lookup_all(struct module *mp, char *name, int include_self)
{
	return (NULL);
}

/*ARGSUSED*/
void *
kobj_alloc(size_t size, int flag)
{
	return (NULL);
}

/*ARGSUSED*/
void *
kobj_zalloc(size_t size, int flag)
{
	return (NULL);
}

/*ARGSUSED*/
void
kobj_free(void *address, size_t size)
{}

/*ARGSUSED*/
void
kobj_sync(void)
{}

/*ARGSUSED*/
void
kobj_stat_get(kobj_stat_t *kp)
{}

/*ARGSUSED*/
void
kobj_sync_instruction_memory(caddr_t addr, size_t size)
{
}

/*ARGSUSED*/
int
kobj_notify_add(kobj_notify_list_t *knp)
{
	return (-1);
}

/*ARGSUSED*/
int
kobj_notify_remove(kobj_notify_list_t *knp)
{
	return (-1);
}

/*ARGSUSED*/
void
kobj_export_module(struct module *mp)
{
}

#ifndef sparc
void
kobj_boot_unmountroot(void)
{}
#endif

/*
 * Dummy declarations for variables in
 * the stand-alone linker/loader.
 */
char *boot_cpu_compatible_list;
