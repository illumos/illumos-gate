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

#include <limits.h>
#include <strings.h>
#include <unistd.h>
#include <libnvpair.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/objfs.h>
#include <sys/modctl.h>
#include <libelf.h>
#include <gelf.h>

#include <topo_error.h>

static int mod_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *);
static void mod_release(topo_mod_t *, tnode_t *);
static int mod_fmri_create_meth(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

#define	MOD_VERSION	TOPO_VERSION

static const topo_method_t mod_methods[] = {
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, mod_fmri_create_meth },
	{ NULL }
};

static const topo_modinfo_t mod_info =
	{ "mod", MOD_VERSION, mod_enum, mod_release };

void
mod_init(topo_mod_t *mod)
{
	topo_mod_setdebug(mod, TOPO_DBG_ALL);
	topo_mod_dprintf(mod, "initializing mod builtin\n");

	if (topo_mod_register(mod, &mod_info, NULL) != 0) {
		topo_mod_dprintf(mod, "failed to register mod_info: "
		    "%s\n", topo_mod_errmsg(mod));
		return;
	}
}

void
mod_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

/*ARGSUSED*/
static int
mod_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg)
{
	(void) topo_method_register(mod, pnode, mod_methods);
	return (0);
}

static void
mod_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

static char *
mod_binary_path_get(topo_mod_t *mp, char *objpath)
{
	static char Pathbuf[PATH_MAX];
	Elf *elf = NULL;
	Elf_Scn *scn = NULL;
	Elf_Data *edata;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	int fd;

	if ((fd = open(objpath, O_RDONLY)) < 0) {
		topo_mod_dprintf(mp, "failed to open %s", objpath);
		goto mbpg_bail;
	}
	if (elf_version(EV_CURRENT) == EV_NONE) {
		topo_mod_dprintf(mp, "Elf version out of whack\n");
		goto mbpg_bail;
	}
	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		topo_mod_dprintf(mp, "elf_begin failed\n");
		goto mbpg_bail;
	}
	if ((gelf_getehdr(elf, &ehdr)) == NULL) {
		topo_mod_dprintf(mp, "gelf_getehdr failed\n");
		goto mbpg_bail;
	}
	scn = elf_getscn(elf, 0);	/* "seek" to start of sections */
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		const char *sh_name;
		if (gelf_getshdr(scn, &shdr) == NULL) {
			topo_mod_dprintf(mp, "gelf_getshdr failed\n");
			goto mbpg_bail;
		}
		if (shdr.sh_type != SHT_PROGBITS)
			continue;
		sh_name = elf_strptr(elf,
		    ehdr.e_shstrndx, (size_t)shdr.sh_name);
		if (strcmp(sh_name, ".filename") != 0)
			continue;
		if ((edata = elf_getdata(scn, NULL)) == NULL) {
			topo_mod_dprintf(mp, "no filename data");
			break;
		}
		(void) strlcpy(Pathbuf, edata->d_buf, PATH_MAX);
		break;
	}
	elf_end(elf);
	(void) close(fd);
	return (Pathbuf);

mbpg_bail:
	if (elf != NULL)
		elf_end(elf);
	if (fd >= 0)
		(void) close(fd);
	(void) topo_mod_seterrno(mp, EMOD_METHOD_INVAL);
	return (NULL);
}

static int
mod_nvl_data(topo_mod_t *mp, nvlist_t *out, const char *path)
{
	struct modinfo mi;
	struct stat64 s;
	int id, e;

	if (stat64(path, &s) < 0) {
		topo_mod_dprintf(mp,
		    "No system object file for driver %s", path);
		return (topo_mod_seterrno(mp, EMOD_METHOD_INVAL));
	}

	id = OBJFS_MODID(s.st_ino);
	mi.mi_id = mi.mi_nextid = id;
	mi.mi_info = MI_INFO_ONE | MI_INFO_NOBASE;
	if (modctl(MODINFO, id, &mi) < 0) {
		topo_mod_dprintf(mp, "failed to get modinfo for %s", path);
		return (topo_mod_seterrno(mp, EMOD_METHOD_INVAL));
	}
	mi.mi_name[MODMAXNAMELEN - 1] = '\0';
	mi.mi_msinfo[0].msi_linkinfo[MODMAXNAMELEN - 1] = '\0';
	e = nvlist_add_string(out, FM_FMRI_SCHEME, FM_FMRI_SCHEME_MOD);
	e |= nvlist_add_uint8(out, FM_VERSION, FM_MOD_SCHEME_VERSION);
	e |= nvlist_add_int32(out, FM_FMRI_MOD_ID, id);
	e |= nvlist_add_string(out, FM_FMRI_MOD_NAME, mi.mi_name);
	e |= nvlist_add_string(out,
	    FM_FMRI_MOD_DESC, mi.mi_msinfo[0].msi_linkinfo);
	if (e != 0)
		return (topo_mod_seterrno(mp, EMOD_FMRI_NVL));

	return (0);
}

static nvlist_t *
mod_fmri_create(topo_mod_t *mp, const char *driver)
{
	topo_hdl_t *thp;
	nvlist_t *arg = NULL;
	nvlist_t *out = NULL;
	nvlist_t *pkg = NULL;
	char objpath[PATH_MAX];
	char *path = NULL;
	int err;

	if (topo_mod_nvalloc(mp, &arg, NV_UNIQUE_NAME) != 0 ||
	    topo_mod_nvalloc(mp, &out, NV_UNIQUE_NAME) != 0) {
		(void) topo_mod_seterrno(mp, EMOD_FMRI_NVL);
		goto mfc_bail;
	}

	(void) snprintf(objpath, PATH_MAX, "%s/%s/object", OBJFS_ROOT, driver);

	if ((path = mod_binary_path_get(mp, objpath)) == NULL)
		goto mfc_bail;
	if (nvlist_add_string(arg, "path", path) != 0) {
		(void) topo_mod_seterrno(mp, EMOD_FMRI_NVL);
		goto mfc_bail;
	}

	if (mod_nvl_data(mp, out, objpath) < 0)
		goto mfc_bail;

	thp = topo_mod_handle(mp);
	pkg = topo_fmri_create(thp,
	    FM_FMRI_SCHEME_PKG, FM_FMRI_SCHEME_PKG, 0, arg, &err);
	if (pkg == NULL) {
		(void) topo_mod_seterrno(mp, err);
		goto mfc_bail;
	}
	nvlist_free(arg);
	arg = NULL;

	if (nvlist_add_nvlist(out, FM_FMRI_MOD_PKG, pkg) != 0) {
		(void) topo_mod_seterrno(mp, EMOD_FMRI_NVL);
		goto mfc_bail;
	}
	nvlist_free(pkg);

	return (out);

mfc_bail:
	nvlist_free(pkg);
	nvlist_free(out);
	nvlist_free(arg);
	return (NULL);
}

/*ARGSUSED*/
static int
mod_fmri_create_meth(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *args;
	nvlist_t *modnvl;
	char *driver;

	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));

	if (nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_NVL, &args) != 0 ||
	    nvlist_lookup_string(args, "DRIVER", &driver) != 0) {
		topo_mod_dprintf(mp, "no DRIVER string in method argument\n");
		return (topo_mod_seterrno(mp, EMOD_METHOD_INVAL));
	}

	modnvl = mod_fmri_create(mp, driver);
	if (modnvl == NULL) {
		*out = NULL;
		topo_mod_dprintf(mp, "failed to create contained mod FMRI\n");
		return (topo_mod_seterrno(mp, EMOD_FMRI_NVL));
	}
	*out = modnvl;
	return (0);
}
