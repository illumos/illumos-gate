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
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mdb_modapi.h>
#include <sys/smbios_impl.h>
#include <unistd.h>

/*
 * Unfortunately, we're in a bit of a bind. Because of the situation we're in,
 * we cannot use string.h directly as it declares ffs() which is also declared
 * in sys/systm.h. sys/systm.h is being pulled in because mdb is building with
 * _KERNEL. Therefore we have to manually declare an extern delaration for
 * strerror().
 */
extern const char *strerror(int);

/*
 * Take an existing smbios_hdl_t from a dump and slurp out its memory so we can
 * open up a new smbios handle to perform operations on.
 */
static int
smbios_mdb_write(const char *path, uintptr_t addr)
{
	smbios_hdl_t shp, *hdl;
	void *buf;
	int err, fd = -1;
	int ret = DCMD_ERR;

	if (mdb_vread(&shp, sizeof (shp), addr) != sizeof (shp)) {
		mdb_warn("failed to read smbios_hdl_t at %p", addr);
		return (DCMD_ERR);
	}

	buf = mdb_alloc(shp.sh_buflen, UM_NOSLEEP | UM_GC);
	if (buf == NULL) {
		mdb_warn("failed to allocate %zu bytes for the smbios "
		    "data buffer", shp.sh_buflen);
		return (DCMD_ERR);
	}

	if (mdb_vread(buf, shp.sh_buflen, (uintptr_t)shp.sh_buf) !=
	    shp.sh_buflen) {
		mdb_warn("failed to copy smbios data at %p", shp.sh_buf);
		return (DCMD_ERR);
	}

	hdl = smbios_bufopen(&shp.sh_ent, buf, shp.sh_buflen, SMB_VERSION, 0,
	    &err);
	if (hdl == NULL) {
		mdb_warn("failed to load smbios data: %s\n",
		    smbios_errmsg(err));
		return (DCMD_ERR);
	}

	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
		mdb_warn("failed to open output file %s: %s\n", path,
		    strerror(errno));
		goto out;
	}

	if (smbios_write(hdl, fd) != 0) {
		mdb_warn("failed to write smbios data to %s: %s\n", path,
		    smbios_errmsg(smbios_errno(hdl)));
		ret = DCMD_ERR;
	} else {
		ret = DCMD_OK;
	}
out:
	if (fd != -1) {
		(void) close(fd);
	}
	smbios_close(hdl);
	return (ret);
}

static int
smbios_mdb_smbios(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	const char *wpath = NULL;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("missing required smbios_hdl_t\n");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv, 'w', MDB_OPT_STR, &wpath, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (wpath != NULL) {
		return (smbios_mdb_write(wpath, addr));
	}

	return (DCMD_USAGE);
}

static void
smbios_mdb_help(void)
{
	mdb_printf("Given a pointer to an smbios_hdl_t take the following "
	    "actions:\n\n"
	    "\t-w path\t\tWrite SMBIOS data out to path\n");
}

static const mdb_dcmd_t smbios_dcmds[] = {
	{ "smbios", ":[-w path]", "Manipulate an smbios handle",
	    smbios_mdb_smbios, smbios_mdb_help },
	{ NULL }
};

static const mdb_modinfo_t smbios_modinfo = {
	MDB_API_VERSION, smbios_dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&smbios_modinfo);
}
