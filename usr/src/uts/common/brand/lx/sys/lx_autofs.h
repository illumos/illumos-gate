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
/*
 * Copyright 2015 Joyent, Inc.
 */

#ifndef	_LX_AUTOFS_H
#define	_LX_AUTOFS_H

/*
 * The lxautofs filesystem exists to emulate the Linux autofs filesystem
 * and provide support for the Linux "automount" automounter.
 *
 *
 *
 * +++ Linux automounter background.
 *
 * Linux has two automounters: "amd" and "automount"
 *
 * 1) "amd" is a userland NFS server.  It basically mounts an NFS filesystem
 * at an automount point, and it acts as the NFS server for the mount.  When
 * an access is done to that NFS filesystem, the access is redirected by the
 * kernel to the "amd" process via rpc.  "amd" then looks up any information
 * required to resolve the requests, mounts real NFS filesystems if
 * necessary, and returns.  "amd" has it's own strange configuration
 * mechanism that doesn't seem to be very compatabile with Illumos's network
 * based automounter map support.
 *
 * 2) "automount" is the other Linux automounter.  It utilizes a kernel
 * filesystem (autofs) to provide it's functionality.  Basically, it mounts
 * the autofs filesystem at any automounter controlled mount point.  This
 * filesystem then intercepts and redirects lookup operations (and only
 * lookup ops) to the userland automounter process via a pipe.  (The
 * pipe to the automounter is establised via mount options when the autofs
 * filesystem is mounted.)  When the automounter recieves a request via this
 * pipe, it does lookups to whatever backing store it's configured to use,
 * does mkdir operations on the autofs filesystem, mounts remote NFS
 * filesystems on any leaf directories it just created, and signals the
 * autofs filesystem via an ioctl to let it know that the lookup can
 * continue.
 *
 *
 *
 * +++ Linux autofs (and automount daemon) notes
 *
 * Since we're mimicking the behavior of the Linux autofs filesystem it's
 * important to document some of it's observed behavior here. There are
 * multiple versions if the autofs kernel API protocol and most modern
 * implemenations of the user-land automount daemon depend on v5, but these
 * comments start by describing the general behavior available with v2.
 * The mounting behavior is similar for v2 vs. v5 although the ioctl and
 * protocol format is different.
 *
 * A) Autofs allows root owned, non-automounter processes to create
 * directories in the autofs filesystem.  The autofs filesystem treats the
 * automounter's process group as special, but it doesn't prevent root
 * processes outside of the automounter's process group from creating new
 * directories in the autofs filesystem.
 *
 * B) Autofs doesn't allow creation of any non-directory entries in the
 * autofs filesystem.  No entity can create files (e.g. /bin/touch or
 * VOP_CREATE/VOP_SYMLINK/etc.)  The only entries that can exist within
 * the autofs filesystem are directories.
 *
 * C) Autofs only intercepts vop lookup operations.  Notably, it does _not_
 * intercept and re-direct vop readdir operations.  This means that the
 * observed behavior of the Linux automounter can be considerably different
 * from that of the Illumos automounter.  Specifically, on Illumos if autofs
 * mount point is mounted _without_ the -nobrowse option then if a user does
 * an ls operation (which translates into a vop readdir operation) then the
 * automounter will intercept that operation and list all the possible
 * directories and mount points without actually mounting any filesystems.
 * Essentially, all automounter managed mount points on Linux will behave
 * like "-nobrowse" mount points on Illumos.  Here's an example to
 * illustrate this.  If /ws was mounted on Illumos without the -nobrowse
 * option and an auto_ws yp map was setup as the backing store for this
 * mount point, then an "ls /ws" would list all the keys in the map as
 * valid directories, but an "ls /ws" on Linux would list an emptry
 * directory.
 *
 * D) NFS mounts are performed by the automount process.  When the automount
 * process gets a redirected lookup request, it determines _all_ the
 * possible remote mount points for that request, creates directory paths
 * via mkdir, and mounts the remote filesystems on the newly created paths.
 * So for example, if a machine called mcescher exported /var/crash and
 * /var/core, an "ls /net/mcescher" would result in the following actions
 * being done by the automounter:
 * 	mkdir /net/mcescher
 * 	mkdir /net/mcescher/var
 * 	mkdir /net/mcescher/var/crash
 * 	mkdir /net/mcescher/var/core
 * 	mount mcescher:/var/crash /var/crash
 * 	mount mcescher:/var/crash /var/core
 * once the automounter completed the work above it would signal the autofs
 * filesystem (via an ioctl) that the lookup could continue.
 *
 * E.1) Autofs only redirects vop lookup operations for path entries that
 * don't already exist in the autofs filesystem.  So for the example above,
 * an initial (after the start of the automounter) "ls /net/mcescher" would
 * result in a request to the automounter.  A subsequest "ls /net/mcescher"
 * would not result in a request to the automounter.  Even if
 * /net/mcescher/var/crash and /net/mcescher/var/core were manually unmounted
 * after the initial "ls /net/mcescher", a subsequest "ls /net/mcescher"
 * would not result in a new request to the automounter.
 *
 * E.2) Autofs lookup requests that are sent to the automounter only include
 * the root directory path component.  So for example, after starting up
 * the automounter if a user were to do a "ls /net/mcescher/var/crash", the
 * lookup request actually sent to the automounter would just be for
 * "mcescher".  (The same request as if the user had done "ls /net/mcescher".)
 *
 * E.3) The two statements above aren't entirely entirely true.  The Linux
 * autofs filesystem will also redirect lookup operations for leaf
 * directories that don't have a filesystem mounted on them.  Using the
 * example above, if a user did a "ls /net/mcescher", then manually
 * unmounted /net/mcescher/var/crash, and then did an "ls
 * /net/mcescher/var/crash", this would result in a request for
 * "mcescher/var/crash" being sent to the automounter.  The strange thing
 * (a Linux bug perhaps) is that the automounter won't do anything with this
 * request and the lookup will fail.
 *
 * F) The autofs filesystem communication protocol (what ioctls it supports
 * and what data it passes to the automount process) are versioned. The
 * userland automount daemon (as of version v5.0.7) expects v5 of the protocol
 * (by running the AUTOFS_IOC_PROTOSUBVER ioctl), and exits if that is not
 * supported. For v2-v5 the structure passed through the pipe always begins
 * with a common header followed by different fields depending on the packet
 * type. In addition the different versions support additional ioctls.
 *
 * v2 - basic mount request
 * v3 - adds expiring (umounting)
 * v4 - adds expire multi
 * v5 - adds missing indirect, expire indirect, missing direct & expire direct.
 *      Defines a new protocol structure layout.
 *      The v5 'missing indirect' and 'missing direct' ioctls are analogous to
 *      the v2 'missing' ioctl. These ioctls are used to initiate a mount.
 *
 * +++ lxautofs notes
 *
 * 1) In general, the lxautofs filesystem tries to mimic the behavior of the
 * Linux autofs filesystem with the following exceptions:
 *
 * 	1.1) We don't bother to implement the E.3 functionality listed above
 * 	since it doesn't appear to be of any use.
 *
 * 	1.2) We only fully implement v2 of the autofs protocol and only
 *	implement the mount ioctls from v5. Fully implementing v3-v5 would take
 *	a _lot_ more work (this is primarily around unmounting). If this proves
 *	to be a problem we can re-visit this decision later. (More details
 *	about post-v2 support are included in comments below.)
 *
 * 2) In general, the approach taken for lxautofs is to keep it as simple
 * as possible and to minimize it's memory usage.  To do this all information
 * about the contents of the lxautofs filesystem are mirrored in the
 * underlying filesystem that lxautofs is mounted on and most vop operations
 * are simply passed onto this underlying filesystem.  This means we don't
 * have to implement most the complex operations that a full filesystem
 * normally has to implement.  It also means that most of our filesystem state
 * (wrt the contents of the filesystem) doesn't actually have to be stored
 * in memory, we can simply go to the underlying filesystem to get it when
 * it's requested.  For the purposes of discussion, we'll call the underlying
 * filesystem the "backing store."
 *
 * The backing store is actually directory called ".lxautofs" which is created
 * in the directory where the lxautofs filesystem is mounted. When the
 * lxautofs filesystem is unmounted this backing store directory is deleted.
 * If this directory exists at mount time (perhaps the system crashed while a
 * previous lxautofs instance was mounted at the same location) it will be
 * deleted. There are a few implications of using a backing store worth
 * mentioning.
 *
 * 	2.1) lxautofs can't be mounted on a read only filesystem.  If this
 * 	proves to be a problem we can probably move the location of the
 * 	backing store.
 *
 * 	2.2) If the backing store filesystem runs out of space then the
 * 	automounter process won't be able to create more directories and mount
 * 	new filesystems.  Of course, strange failures usually happen when
 * 	filesystems run out of space.
 *
 * 3) Why aren't we using gfs?  gfs has two different usage models.
 *
 * 	3.1) I'm my own filesystem but i'm using gfs to help with managing
 * 	readdir operations.
 *
 * 	3.2) I'm a gfs filesystem and gfs is managing all my vnodes
 *
 * We're not using the 3.1 interfaces because we don't implement readdir
 * ourselves.  We pass all readdir operations onto the backing store
 * filesystem and utilize its readdir implementation.
 *
 * We're not using the 3.2 interfaces because they are really designed for
 * in memory filesystems where all of the filesystem state is stored in
 * memory.  They don't lend themselves to filesystems where part of the
 * state is in memory and part of the state is on disk.
 *
 * For more information on gfs take a look at the block comments in the
 * top of gfs.c
 *
 * 4) v3-v5 protocol.
 *
 * Initially we only supported v2 of the Linux kernel autofs protocol.
 * Modern automount daemons depend on v5 so we minimally have to support the
 * "missing" and "version" ioctls, as well as the packet format, for v5.
 *
 * For v3 and later the automounter can be started with a timeout option. It
 * will notify the filesystem of this timeout and, if any automounter
 * filesystem root directory entry is not in use, it will notify autofs
 * via one of the LX_AUTOFS_IOC_EXPIRE* ioctls, depending on which protocol is
 * in use.
 *
 * For example, if the timeout is 60 seconds, the Linux automounter will use
 * the LX_AUTOFS_IOC_EXPIRE ioctl to query for timeouts more often than that
 * (v3.1.7 of the automount daemon would perform this ioctl every <timeout>/4
 * seconds). Then, the autofs filesystem will report top level directories that
 * aren't in use to the automounter via this ioctl. If /net was managed by the
 * automounter and there were the following mount points:
 *	/net/jurassic/var/crash
 *	/net/mcescher/var/crash
 * and no one was looking at any crash dumps on mcescher but someone
 * was analyzing a crash dump on jurassic, then after <timeout> seconds
 * had passed the autofs filesystem would let the automounter know that
 * "mcescher" could be unmounted.  (Note the granularity of notification
 * is directories in the root of the autofs filesystem.)
 *
 * Here's two ideas for how this functionality could be implemented on Illumos:
 *
 * 4.1) The easy incomplete way.  Don't do any in-use detection.  Simply
 * tell the automounter it can try to unmount the filesystem every time
 * the specified timeout passes.  If the filesystem is in use then the
 * unmount will fail.  This would break down for remote hosts with multiple
 * mounts.  For example, if the automounter had mounted the following
 * filesystems:
 *	/net/jurassic/var/crash
 *	/net/jurassic/var/core
 * and the user was looking at a core file, and the timeout expired, the
 * automounter would recieve notification to unmount "jurassic".  Then
 * it would unmount crash (which would succeed) and then to try unmount
 * core (which would fail).  After that (since the automounter only
 * performs mounts for failed lookups in the root autofs directory)
 * future access to /net/jurassic/var/crash would result to access
 * to an empty autofs directory.  We might be able to work around
 * this by caching which root autofs directories we've timed out,
 * then any access to paths that contain those directories could be
 * stalled and we could resend another request to the automounter.
 * This could work if the automounter ignores mount failures.
 *
 * 4.2) The hard correct way.  The real difficulty here is detecting
 * files in use on other filesystems (say NFS) that have been mounted
 * on top of autofs.  (Detecting in use autofs vnodes should be easy.)
 * to do this we would probably have to create a new brand op to intercept
 * mount/umount filesystem operations.  Then using this entry point we
 * could detect mounts of other filesystems on top of lxautofs.  When
 * a successful mount finishes we would use the FEM (file event
 * monitoring) framework to push a module onto that filesystem and
 * intercept VOP operations that allocate/free vnodes in that filesystem.
 * (We would also then have to track mount operations on top of that
 * filesystem, etc.)  this would allow us to properly detect any
 * usage of subdirectories of an autofs directory.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Note that the name of the actual file system is lxautofs, not lx_autofs, but
 * the code uses lx_autofs to prefix the various names. This is because file
 * system names are limited to 8 characters.
 */
#define	LX_AUTOFS_NAME			"lxautofs"

/*
 * Mount options supported.
 */
#define	LX_MNTOPT_FD			"fd"
#define	LX_MNTOPT_PGRP			"pgrp"
#define	LX_MNTOPT_MINPROTO		"minproto"
#define	LX_MNTOPT_MAXPROTO		"maxproto"
#define	LX_MNTOPT_INDIRECT		"indirect"
#define	LX_MNTOPT_DIRECT		"direct"

/*
 * Version/subversion of the Linux kernel automount protocol we support.
 *
 * We only fully support v2, but we also support the v5 mount requests. We'll
 * return ENOTSUP for all of the v3-v5 ioctls we don't yet handle.
 */
#define	LX_AUTOFS_PROTO_VERS5		5
#define	LX_AUTOFS_PROTO_SUBVERSION	2
#define	LX_AUTOFS_PROTO_VERS2		2

/* packet types */
typedef enum laph_ptype {
	LX_AUTOFS_PTYPE_MISSING,	/* 0 */
	LX_AUTOFS_PTYPE_EXPIRE,		/* 1 */
	LX_AUTOFS_PTYPE_EXPIRE_MULTI,	/* 2 */
	LX_AUTOFS_PTYPE_MISSING_INDIR,	/* 3 */
	LX_AUTOFS_PTYPE_EXPIRE_INDIR,	/* 4 */
	LX_AUTOFS_PTYPE_MISSING_DIRECT,	/* 5 */
	LX_AUTOFS_PTYPE_EXPIRE_DIRECT	/* 6 */
} laph_ptype_t;

/*
 * Common header for all versions of the protocol.
 */
typedef struct lx_autofs_pkt_hdr {
	int		laph_protover;	/* protocol version number */
	laph_ptype_t	laph_type;
	int		laph_id;	/* every pkt must have a unique id */
} lx_autofs_pkt_hdr_t;

/*
 * Command structure sent to automount process from lxautofs via a pipe.
 * This structure is the same for v2-v4 of the automount protocol
 * (the communication pipe is established at mount time).
 */
typedef struct lx_autofs_v2_pkt {
	lx_autofs_pkt_hdr_t lap_hdr;
	int	lap_name_len;	/* don't include newline or NULL */
	char	lap_name[256];	/* path component to lookup */
} lx_autofs_v2_pkt_t;

/* v5 */
typedef struct lx_autofs_v5_pkt {
	lx_autofs_pkt_hdr_t lap_hdr;
	uint32_t lap_dev;
	uint64_t lap_ino;
	uint32_t lap_uid;
	uint32_t lap_gid;
	uint32_t lap_pid;
	uint32_t lap_tgid;
	uint32_t lap_name_len;
	char	lap_name[256];
} lx_autofs_v5_pkt_t;

union lx_autofs_pkt {
	lx_autofs_v2_pkt_t	lap_v2;
	lx_autofs_v5_pkt_t	lap_v5;
};

#define	lap_protover	lap_v2.lap_hdr.laph_protover
#define	lap_type	lap_v2.lap_hdr.laph_type
#define	lap_id		lap_v2.lap_hdr.laph_id

/*
 * Ioctls fully supported (v2 protocol).
 */
#define	LX_AUTOFS_IOC_READY		0x00009360 /* arg: int */
#define	LX_AUTOFS_IOC_FAIL		0x00009361 /* arg: int */
#define	LX_AUTOFS_IOC_CATATONIC		0x00009362 /* arg: <none> */

/*
 * Ioctls supported (v3 protocol).
 */
#define	LX_AUTOFS_IOC_PROTOVER		0x80049363 /* arg: int */

/*
 * Ioctls not supported (v3 protocol).
 */
#define	LX_AUTOFS_IOC_SETTIMEOUT	0xc0049364 /* arg: ulong_t */
#define	LX_AUTOFS_IOC_EXPIRE		0x81109365 /* arg: lx_autofs_expire * */

/*
 * Ioctls supported (v5 protocol).
 */
#define	LX_AUTOFS_IOC_PROTOSUBVER	0x80049367 /* arg: int */
#define	LX_AUTOFS_IOC_ASKUMOUNT		0x80049370 /* arg: int */

/*
 * Ioctls not supported (v5 protocol).
 */
#define	LX_AUTOFS_IOC_EXPIRE_MULTI	0x40049366 /* arg: int */
#define	LX_AUTOFS_IOC_EXPIRE_INDIRECT	LX_AUTOFS_IOC_EXPIRE_MULTI
#define	LX_AUTOFS_IOC_EXPIRE_DIRECT	LX_AUTOFS_IOC_EXPIRE_MULTI

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_AUTOFS_H */
