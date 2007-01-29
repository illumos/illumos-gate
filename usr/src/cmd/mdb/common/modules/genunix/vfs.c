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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/door.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/procfs.h>
#include <sys/proc/prdata.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/fs/snode.h>
#include <sys/fs/fifonode.h>
#include <sys/fs/namenode.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <sys/socketvar.h>
#include <sys/strsubr.h>
#include <sys/un.h>

int
vfs_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "rootvfs") == -1) {
		mdb_warn("failed to read 'rootvfs'");
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)wsp->walk_addr;
	return (WALK_NEXT);
}

int
vfs_walk_step(mdb_walk_state_t *wsp)
{
	vfs_t vfs;
	int status;

	if (mdb_vread(&vfs, sizeof (vfs), wsp->walk_addr) == -1) {
		mdb_warn("failed to read vfs_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, &vfs, wsp->walk_cbdata);

	if (vfs.vfs_next == wsp->walk_data)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)vfs.vfs_next;

	return (status);
}

/*
 * Utility routine to read in a filesystem name given a vfs pointer.  If
 * no vfssw entry for the vfs is available (as is the case with some pseudo-
 * filesystems), we check against some known problem fs's: doorfs and
 * portfs.  If that fails, we try to guess the filesystem name using
 * symbol names.  fsname should be a buffer of size _ST_FSTYPSZ.
 */
static int
read_fsname(uintptr_t vfsp, char *fsname)
{
	vfs_t vfs;
	struct vfssw vfssw_entry;
	GElf_Sym vfssw_sym, test_sym;
	char testname[MDB_SYM_NAMLEN];

	if (mdb_vread(&vfs, sizeof (vfs), vfsp) == -1) {
		mdb_warn("failed to read vfs %p", vfsp);
		return (-1);
	}

	if (mdb_lookup_by_name("vfssw", &vfssw_sym) == -1) {
		mdb_warn("failed to find vfssw");
		return (-1);
	}

	/*
	 * vfssw is an array; we need vfssw[vfs.vfs_fstype].
	 */
	if (mdb_vread(&vfssw_entry, sizeof (vfssw_entry),
	    vfssw_sym.st_value + (sizeof (struct vfssw) * vfs.vfs_fstype))
	    == -1) {
		mdb_warn("failed to read vfssw index %d", vfs.vfs_fstype);
		return (-1);
	}

	if (vfs.vfs_fstype != 0) {
		if (mdb_readstr(fsname, _ST_FSTYPSZ,
		    (uintptr_t)vfssw_entry.vsw_name) == -1) {
			mdb_warn("failed to find fs name %p",
			    vfssw_entry.vsw_name);
			return (-1);
		}
		return (0);
	}

	/*
	 * Do precise detection for certain filesystem types that we
	 * know do not appear in vfssw[], and that we depend upon in other
	 * parts of the code: doorfs and portfs.
	 */
	if (mdb_lookup_by_name("door_vfs", &test_sym) != -1) {
		if (test_sym.st_value == vfsp) {
			strcpy(fsname, "doorfs");
			return (0);
		}
	}
	if (mdb_lookup_by_name("port_vfs", &test_sym) != -1) {
		if (test_sym.st_value == vfsp) {
			strcpy(fsname, "portfs");
			return (0);
		}
	}

	/*
	 * Heuristic detection for other filesystems that don't have a
	 * vfssw[] entry.  These tend to be named <fsname>_vfs, so we do a
	 * lookup_by_addr and see if we find a symbol of that name.
	 */
	if (mdb_lookup_by_addr(vfsp, MDB_SYM_EXACT, testname, sizeof (testname),
	    &test_sym) != -1) {
		if ((strlen(testname) > 4) &&
		    (strcmp(testname + strlen(testname) - 4, "_vfs") == 0)) {
			testname[strlen(testname) - 4] = '\0';
			strncpy(fsname, testname, _ST_FSTYPSZ);
			return (0);
		}
	}

	mdb_warn("unknown filesystem type for vfs %p", vfsp);
	return (-1);
}

/*
 * Column widths for mount point display in ::fsinfo output.
 */
#ifdef _LP64
#define	FSINFO_MNTLEN	48
#else
#define	FSINFO_MNTLEN	56
#endif

/*ARGSUSED*/
int
fsinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	vfs_t vfs;
	int len;
	int opt_v = 0;
	char buf[MAXPATHLEN];
	char fsname[_ST_FSTYPSZ];
	mntopt_t *mntopts;
	size_t size;
	int i;
	int first = 1;
	char opt[MAX_MNTOPT_STR];
	uintptr_t global_zone;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("vfs", "fsinfo", argc, argv) == -1) {
			mdb_warn("failed to walk file system list");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %-15s %s%</u>\n",
		    "VFSP", "FS", "MOUNT");

	if (mdb_vread(&vfs, sizeof (vfs), addr) == -1) {
		mdb_warn("failed to read vfs_t %p", addr);
		return (DCMD_ERR);
	}

	if ((len = mdb_read_refstr((uintptr_t)vfs.vfs_mntpt, buf,
	    sizeof (buf))) <= 0)
		strcpy(buf, "??");

	else if (!opt_v && (len >= FSINFO_MNTLEN))
		/*
		 * In normal mode, we truncate the path to keep the output
		 * clean.  In -v mode, we just print the full path.
		 */
		strcpy(&buf[FSINFO_MNTLEN - 4], "...");

	if (read_fsname(addr, fsname) == -1)
		return (DCMD_ERR);

	mdb_printf("%0?p %-15s %s\n", addr, fsname, buf);

	if (!opt_v)
		return (DCMD_OK);

	/*
	 * Print 'resource' string; this shows what we're mounted upon.
	 */
	if (mdb_read_refstr((uintptr_t)vfs.vfs_resource, buf,
	    MAXPATHLEN) <= 0)
		strcpy(buf, "??");

	mdb_printf("%?s %s\n", "R:", buf);

	/*
	 * Print mount options array; it sucks to be a mimic, but we copy
	 * the same logic as in mntvnops.c for adding zone= tags, and we
	 * don't bother with the obsolete dev= option.
	 */
	size = vfs.vfs_mntopts.mo_count * sizeof (mntopt_t);
	mntopts = mdb_alloc(size, UM_SLEEP | UM_GC);

	if (mdb_vread(mntopts, size,
	    (uintptr_t)vfs.vfs_mntopts.mo_list) == -1) {
		mdb_warn("failed to read mntopts %p", vfs.vfs_mntopts.mo_list);
		return (DCMD_ERR);
	}

	for (i = 0; i < vfs.vfs_mntopts.mo_count; i++) {
		if (mntopts[i].mo_flags & MO_SET) {
			if (mdb_readstr(opt, sizeof (opt),
			    (uintptr_t)mntopts[i].mo_name) == -1) {
				mdb_warn("failed to read mntopt name %p",
				    mntopts[i].mo_name);
				return (DCMD_ERR);
			}
			if (first) {
				mdb_printf("%?s ", "O:");
				first = 0;
			} else {
				mdb_printf(",");
			}
			mdb_printf("%s", opt);
			if (mntopts[i].mo_flags & MO_HASVALUE) {
				if (mdb_readstr(opt, sizeof (opt),
				    (uintptr_t)mntopts[i].mo_arg) == -1) {
					mdb_warn("failed to read mntopt "
					    "value %p", mntopts[i].mo_arg);
					return (DCMD_ERR);
				}
				mdb_printf("=%s", opt);
			}
		}
	}

	if (mdb_readvar(&global_zone, "global_zone") == -1) {
		mdb_warn("failed to locate global_zone");
		return (DCMD_ERR);
	}

	if ((vfs.vfs_zone != NULL) &&
	    ((uintptr_t)vfs.vfs_zone != global_zone)) {
		zone_t z;

		if (mdb_vread(&z, sizeof (z), (uintptr_t)vfs.vfs_zone) == -1) {
			mdb_warn("failed to read zone");
			return (DCMD_ERR);
		}
		/*
		 * zone names are much shorter than MAX_MNTOPT_STR
		 */
		if (mdb_readstr(opt, sizeof (opt),
		    (uintptr_t)z.zone_name) == -1) {
			mdb_warn("failed to read zone name");
			return (DCMD_ERR);
		}
		if (first) {
			mdb_printf("%?s ", "O:");
		} else {
			mdb_printf(",");
		}
		mdb_printf("zone=%s", opt);
	}
	return (DCMD_OK);
}


#define	REALVP_DONE	0
#define	REALVP_ERR	1
#define	REALVP_CONTINUE	2

static int
next_realvp(uintptr_t invp, struct vnode *outvn, uintptr_t *outvp)
{
	char fsname[_ST_FSTYPSZ];

	*outvp = invp;
	if (mdb_vread(outvn, sizeof (struct vnode), invp) == -1) {
		mdb_warn("failed to read vnode at %p", invp);
		return (REALVP_ERR);
	}

	if (read_fsname((uintptr_t)outvn->v_vfsp, fsname) == -1)
		return (REALVP_ERR);

	/*
	 * We know how to do 'realvp' for as many filesystems as possible;
	 * for all other filesystems, we assume that the vp we are given
	 * is the realvp.  In the kernel, a realvp operation will sometimes
	 * dig through multiple layers.  Here, we only fetch the pointer
	 * to the next layer down.  This allows dcmds to print out the
	 * various layers.
	 */
	if (strcmp(fsname, "fifofs") == 0) {
		fifonode_t fn;
		if (mdb_vread(&fn, sizeof (fn),
		    (uintptr_t)outvn->v_data) == -1) {
			mdb_warn("failed to read fifonode");
			return (REALVP_ERR);
		}
		*outvp = (uintptr_t)fn.fn_realvp;

	} else if (strcmp(fsname, "namefs") == 0) {
		struct namenode nn;
		if (mdb_vread(&nn, sizeof (nn),
		    (uintptr_t)outvn->v_data) == -1) {
			mdb_warn("failed to read namenode");
			return (REALVP_ERR);
		}
		*outvp = (uintptr_t)nn.nm_filevp;

	} else if (outvn->v_type == VSOCK && outvn->v_stream != NULL) {
		struct stdata stream;

		/*
		 * Sockets have a strange and different layering scheme; we
		 * hop over into the sockfs vnode (accessible via the stream
		 * head) if possible.
		 */
		if (mdb_vread(&stream, sizeof (stream),
		    (uintptr_t)outvn->v_stream) == -1) {
			mdb_warn("failed to read stream data");
			return (REALVP_ERR);
		}
		*outvp = (uintptr_t)stream.sd_vnode;
	}

	if (*outvp == invp || *outvp == NULL)
		return (REALVP_DONE);

	return (REALVP_CONTINUE);
}

static void
pfiles_print_addr(struct sockaddr *addr)
{
	struct sockaddr_in *s_in;
	struct sockaddr_un *s_un;
	struct sockaddr_in6 *s_in6;
	in_port_t port;

	switch (addr->sa_family) {
	case AF_INET:
		/*LINTED: alignment*/
		s_in = (struct sockaddr_in *)addr;
		mdb_nhconvert(&port, &s_in->sin_port, sizeof (port));
		mdb_printf("AF_INET %I %d ", s_in->sin_addr.s_addr, port);
		break;

	case AF_INET6:
		/*LINTED: alignment*/
		s_in6 = (struct sockaddr_in6 *)addr;
		mdb_nhconvert(&port, &s_in6->sin6_port, sizeof (port));
		mdb_printf("AF_INET6 %N %d ", &(s_in6->sin6_addr), port);
		break;

	case AF_UNIX:
		s_un = (struct sockaddr_un *)addr;
		mdb_printf("AF_UNIX %s ", s_un->sun_path);
		break;
	default:
		mdb_printf("AF_?? (%d) ", addr->sa_family);
		break;
	}
}


static int
pfiles_get_sonode(uintptr_t vp, struct sonode *sonode)
{
	vnode_t v;
	struct stdata stream;

	if (mdb_vread(&v, sizeof (v), vp) == -1) {
		mdb_warn("failed to read socket vnode");
		return (-1);
	}

	if (mdb_vread(&stream, sizeof (stream), (uintptr_t)v.v_stream) == -1) {
		mdb_warn("failed to read stream data");
		return (-1);
	}

	if (mdb_vread(&v, sizeof (v), (uintptr_t)stream.sd_vnode) == -1) {
		mdb_warn("failed to read stream vnode");
		return (-1);
	}

	if (mdb_vread(sonode, sizeof (struct sonode),
	    (uintptr_t)v.v_data) == -1) {
		mdb_warn("failed to read sonode");
		return (-1);
	}

	return (0);
}

/*
 * Do some digging to get a reasonable pathname for this vnode. 'path'
 * should point at a buffer of MAXPATHLEN in size.
 */
static int
pfiles_dig_pathname(uintptr_t vp, char *path)
{
	vnode_t v;

	bzero(path, MAXPATHLEN);

	if (mdb_vread(&v, sizeof (v), vp) == -1) {
		mdb_warn("failed to read vnode");
		return (-1);
	}

	if (v.v_path == NULL) {
		/*
		 * fifo's and doors are special.   Some have pathnames, and
		 * some do not.  And for these, it is pointless to go off to
		 * mdb_vnode2path, which is very slow.
		 *
		 * Event ports never have a pathname.
		 */
		if (v.v_type == VFIFO || v.v_type == VDOOR || v.v_type == VPORT)
			return (0);

		/*
		 * For sockets, we won't find a path unless we print the path
		 * associated with the accessvp.
		 */
		if (v.v_type == VSOCK) {
			struct sonode sonode;

			if (pfiles_get_sonode(vp, &sonode) == -1) {
				return (-1);
			}

			vp = (uintptr_t)sonode.so_accessvp;
		}
	}


	/*
	 * mdb_vnode2path will print an error for us as needed, but not
	 * finding a pathname is not really an error, so we plow on.
	 */
	(void) mdb_vnode2path(vp, path, MAXPATHLEN);

	/*
	 * A common problem is that device pathnames are prefixed with
	 * /dev/../devices/.  We just clean those up slightly:
	 * 	/dev/../devices/<mumble> --> /devices/<mumble>
	 * 	/dev/pts/../../devices/<mumble> --> /devices/<mumble>
	 */
	if (strncmp("/dev/../devices/", path, strlen("/dev/../devices/")) == 0)
		strcpy(path, path + 7);

	if (strncmp("/dev/pts/../../devices/", path,
	    strlen("/dev/pts/../../devices/")) == 0)
		strcpy(path, path + 14);

	return (0);
}

const struct fs_type {
	int type;
	const char *name;
} fs_types[] = {
	{ VNON,   "NON" },
	{ VREG,   "REG" },
	{ VDIR,   "DIR" },
	{ VBLK,   "BLK" },
	{ VCHR,   "CHR" },
	{ VLNK,   "LNK" },
	{ VFIFO,  "FIFO" },
	{ VDOOR,  "DOOR" },
	{ VPROC,  "PROC" },
	{ VSOCK,  "SOCK" },
	{ VPORT,  "PORT" },
	{ VBAD,   "BAD" }
};

#define	NUM_FS_TYPES (sizeof (fs_types) / sizeof (struct fs_type))

struct pfiles_cbdata {
	int opt_p;
	int fd;
};

static int
pfile_callback(uintptr_t addr, const struct file *f, struct pfiles_cbdata *cb)
{
	vnode_t v, layer_vn;
	int myfd = cb->fd;
	const char *type;
	char path[MAXPATHLEN];
	uintptr_t top_vnodep, realvpp;
	char fsname[_ST_FSTYPSZ];
	int err, i;

	cb->fd++;

	if (addr == NULL) {
		return (WALK_NEXT);
	}

	top_vnodep = realvpp = (uintptr_t)f->f_vnode;

	if (mdb_vread(&v, sizeof (v), realvpp) == -1) {
		mdb_warn("failed to read vnode");
		return (DCMD_ERR);
	}

	type = "?";
	for (i = 0; i <= NUM_FS_TYPES; i++) {
		if (fs_types[i].type == v.v_type)
			type = fs_types[i].name;
	}

	do {
		uintptr_t next_realvpp;

		err = next_realvp(realvpp, &layer_vn, &next_realvpp);
		if (next_realvpp != NULL)
			realvpp = next_realvpp;

	} while (err == REALVP_CONTINUE);

	if (err == REALVP_ERR) {
		mdb_warn("failed to do realvp() for %p", realvpp);
		return (DCMD_ERR);
	}

	if (read_fsname((uintptr_t)layer_vn.v_vfsp, fsname) == -1)
		return (DCMD_ERR);

	mdb_printf("%4d %4s %?0p ", myfd, type, top_vnodep);

	if (cb->opt_p) {
		if (pfiles_dig_pathname(top_vnodep, path) == -1)
			return (DCMD_ERR);

		mdb_printf("%s\n", path);
		return (DCMD_OK);
	}

	/*
	 * Sockets generally don't have interesting pathnames; we only
	 * show those in the '-p' view.
	 */
	path[0] = '\0';
	if (v.v_type != VSOCK) {
		if (pfiles_dig_pathname(top_vnodep, path) == -1)
			return (DCMD_ERR);
	}
	mdb_printf("%s%s", path, path[0] == '\0' ? "" : " ");

	switch (v.v_type) {
	case VDOOR:
	{
		door_node_t doornode;
		proc_t pr;

		if (mdb_vread(&doornode, sizeof (doornode),
		    (uintptr_t)layer_vn.v_data) == -1) {
			mdb_warn("failed to read door_node");
			return (DCMD_ERR);
		}

		if (mdb_vread(&pr, sizeof (pr),
		    (uintptr_t)doornode.door_target) == -1) {
			mdb_warn("failed to read door server process %p",
			    doornode.door_target);
			return (DCMD_ERR);
		}
		mdb_printf("[door to '%s' (proc=%p)]", pr.p_user.u_comm,
		    doornode.door_target);
		break;
	}

	case VSOCK:
	{
		struct sonode sonode;

		if (pfiles_get_sonode(realvpp, &sonode) == -1)
			return (DCMD_ERR);

		/*
		 * If the address is cached in the sonode, use it; otherwise,
		 * we print nothing.
		 */
		if (sonode.so_state & SS_LADDR_VALID) {
			struct sockaddr *laddr =
			    mdb_alloc(sonode.so_laddr_len, UM_SLEEP);
			if (mdb_vread(laddr, sonode.so_laddr_len,
			    (uintptr_t)sonode.so_laddr_sa) == -1) {
				mdb_warn("failed to read sonode socket addr");
				return (DCMD_ERR);
			}

			mdb_printf("socket: ");
			pfiles_print_addr(laddr);
		}

		if (sonode.so_state & SS_FADDR_VALID) {
			struct sockaddr *faddr =
			    mdb_alloc(sonode.so_faddr_len, UM_SLEEP);
			if (mdb_vread(faddr, sonode.so_faddr_len,
			    (uintptr_t)sonode.so_faddr_sa) == -1) {
				mdb_warn("failed to read sonode remote addr");
				return (DCMD_ERR);
			}

			mdb_printf("remote: ");
			pfiles_print_addr(faddr);
		}
		break;
	}

	case VPORT:
		mdb_printf("[event port (port=%p)]", v.v_data);
		break;

	case VPROC:
	{
		prnode_t prnode;
		prcommon_t prcommon;

		if (mdb_vread(&prnode, sizeof (prnode),
		    (uintptr_t)layer_vn.v_data) == -1) {
			mdb_warn("failed to read prnode");
			return (DCMD_ERR);
		}

		if (mdb_vread(&prcommon, sizeof (prcommon),
		    (uintptr_t)prnode.pr_common) == -1) {
			mdb_warn("failed to read prcommon %p",
			    prnode.pr_common);
			return (DCMD_ERR);
		}

		mdb_printf("(proc=%p)", prcommon.prc_proc);
		break;
	}

	default:
		break;
	}


	mdb_printf("\n");

	return (WALK_NEXT);
}

static int
file_t_callback(uintptr_t addr, const struct file *f, struct pfiles_cbdata *cb)
{
	int myfd = cb->fd;

	cb->fd++;

	if (addr == NULL) {
		return (WALK_NEXT);
	}

	/*
	 * We really need 20 digits to print a 64-bit offset_t, but this
	 * is exceedingly rare, so we cheat and assume a column width of 10
	 * digits, in order to fit everything cleanly into 80 columns.
	 */
	mdb_printf("%?0p %4d %8x %?0p %10lld %?0p %4d\n",
	    addr, myfd, f->f_flag, f->f_vnode, f->f_offset, f->f_cred,
	    f->f_count);

	return (WALK_NEXT);
}

int
pfiles(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int opt_f = 0;

	struct pfiles_cbdata cb;

	bzero(&cb, sizeof (cb));

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'p', MDB_OPT_SETBITS, TRUE, &cb.opt_p,
	    'f', MDB_OPT_SETBITS, TRUE, &opt_f, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_f) {
		mdb_printf("%<u>%?s %4s %8s %?s %10s %?s %4s%</u>\n", "FILE",
		    "FD", "FLAG", "VNODE", "OFFSET", "CRED", "CNT");
		if (mdb_pwalk("allfile", (mdb_walk_cb_t)file_t_callback, &cb,
		    addr) == -1) {
			mdb_warn("failed to walk 'allfile'");
			return (DCMD_ERR);
		}
	} else {
		mdb_printf("%<u>%-4s %4s %?s ", "FD", "TYPE", "VNODE");
		if (cb.opt_p)
			mdb_printf("PATH");
		else
			mdb_printf("INFO");
		mdb_printf("%</u>\n");

		if (mdb_pwalk("allfile", (mdb_walk_cb_t)pfile_callback, &cb,
		    addr) == -1) {
			mdb_warn("failed to walk 'allfile'");
			return (DCMD_ERR);
		}
	}


	return (DCMD_OK);
}

void
pfiles_help(void)
{
	mdb_printf(
	    "Given the address of a process, print information about files\n"
	    "which the process has open.  By default, this includes decoded\n"
	    "information about the file depending on file and filesystem type\n"
	    "\n"
	    "\t-p\tPathnames; omit decoded information.  Only display "
	    "pathnames\n"
	    "\t-f\tfile_t view; show the file_t structure corresponding to "
	    "the fd\n");
}
