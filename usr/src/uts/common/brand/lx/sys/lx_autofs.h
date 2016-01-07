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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_LX_AUTOFS_H
#define	_LX_AUTOFS_H

/*
 * The lxautofs filesystem exists to emulate the Linux autofs filesystem
 * and provide support for the Linux "automount" automounter.
 *
 * We emulate parts of the Linux autofs v4 file system (which confusingly uses
 * the v5 autofs protocol to user-land).
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
 * mechanism that doesn't seem to be very compatabile with illumos's network
 * based automounter map support.
 *
 * 2) "automount" is the other Linux automounter.  It utilizes a kernel
 * filesystem (autofs) to provide it's functionality.  Basically, it mounts
 * the autofs filesystem at any automounter controlled mountpoint.  This
 * filesystem then intercepts and redirects lookup operations (or expire ops)
 * to the userland automounter process via a pipe. The pipe to the automounter
 * is established via mount options when the autofs filesystem is mounted. When
 * the automounter recieves a request via this pipe, it does lookups (or
 * unmounts) to whatever backing store it's configured to use, does mkdir
 * operations on the autofs filesystem, mounts remote NFS filesystems on any
 * leaf directories it just created, and signals the autofs filesystem via an
 * ioctl to let it know that the lookup (or expire) can continue.
 *
 *
 * +++ Linux autofs documentation.
 *
 * Within the Linux src tree, see the file:
 * Documentation/filesystems/autofs4-mount-control.txt. This documents some
 * of the autofs behavior and the dev ioctls (which we currently do not
 * support). The dev ioctls are used for recovery if the automounter dies, or
 * is killed, and restarted.
 *
 * The following URL (https://lwn.net/Articles/606960/) documents autofs in
 * general. This patch was targeted for Documentation/filesystems/autofs4.txt,
 * but seems to have never integrated into the Linux src tree.
 *
 *
 * +++ Linux autofs (and automount daemon) notes
 *
 * Since we're mimicking the behavior of the Linux autofs filesystem it's
 * important to document some of it's observed behavior here. There are
 * multiple versions if the autofs kernel API protocol and most modern
 * implemenations of the user-land automount daemon depend on v5, but these
 * comments start by describing the general behavior available with v2.
 * The lookup/mounting behavior is similar for v2 vs. v5 although the ioctl and
 * protocol format is different. The key enhancement is the v5 protocol has
 * support for the automounter to determine when it can unmount file systems.
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
 * from that of the illumos automounter.  Specifically, on illumos if an autofs
 * mountpoint is mounted _without_ the -nobrowse option then if a user does
 * an ls operation (which translates into a vop readdir operation) then the
 * automounter will intercept that operation and list all the possible
 * directories and mountpoints without actually mounting any filesystems.
 * Essentially, all automounter managed mountpoints on Linux will behave
 * like "-nobrowse" mountpoints on illumos.  Here's an example to illustrate
 * this.  If /ws was mounted on illumos without the -nobrowse option and an
 * auto_ws yp map was setup as the backing store for this mountpoint, then an
 * "ls /ws" would list all the keys in the map as valid directories, but an
 * "ls /ws" on Linux would list an emptry directory.
 *
 * D) NFS mounts are performed by the automount process.  When the automount
 * process gets a redirected lookup request, it determines _all_ the
 * possible remote mountpoints for that request, creates directory paths
 * via mkdir, and mounts the remote filesystems on the newly created paths.
 * So for example (for an offset mount), if a machine called mcescher exported
 * /var/crash and /var/core, an "ls /net/mcescher" would result in the
 * following actions being done by the automounter:
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
 * and what data it passes to the automount process) is versioned. The
 * userland automount daemon (as of version v5.0.7) expects v5 of the protocol
 * (by running the AUTOFS_IOC_PROTOSUBVER ioctl), and exits if that is not
 * supported. For v2-v5 the structure passed through the pipe always begins
 * with a common header followed by different fields depending on the packet
 * type. In addition the different versions support additional ioctls.
 *
 * v2 - basic lookup request
 * v3 - adds expiring (umounting)
 * v4 - adds expire multi
 * v5 - adds missing indirect, expire indirect, missing direct & expire direct.
 *      Defines a new protocol structure layout.
 *      The v5 'missing indirect' and 'missing direct' ioctls are analogous to
 *      the v2 'missing' ioctl. These ioctls are used to initiate a mount via
 *	a lookup. The 'expire' ioctls are used by the automounter to query if
 *	it is possible to unmount the filesystem. 'direct' and 'indirect'
 *	refer to the mount option type that the automounter performed and
 *	correlate to an automounter direct or indirect map mointpoint.
 *
 * G) The automounter can also do an 'offset' mount instead of a 'direct' or
 * 'indirect' mount. An offset mount is used in cases such as the /net/{host}
 * map to mount all exported file systems under the /net/{host} entry. Offset
 * mounts are similar to 'direct' mounts, except that unmount support is more
 * complex and discussed below.
 *
 * +++ lxautofs notes
 *
 * 1) In general, the lxautofs filesystem tries to mimic the behavior of the
 * Linux autofs filesystem with the following exceptions:
 *
 * 	1.1) We don't bother to implement the E.3 functionality listed above
 * 	since it doesn't appear to be of any use.
 *
 * 	1.2) We only fully implement v2 and partially implement v5 of the
 *	autofs protocol. The partial v5 support is around the 'expire' ioctls
 *	and discussed below under "v5 expire protocol".
 *
 *	1.3) We currently do not support 'offset' mounts and expiration
 *	(since this is a variation on direct mounts).
 *
 *	1.4) We currently do not implement the dev ioctls for automounter
 *	restart recovery.
 *
 * 2) In general, the approach taken for lxautofs is to keep it as simple
 * as possible and to minimize it's memory usage.  To do this all information
 * about the contents of the lxautofs filesystem are mirrored in the
 * underlying filesystem that lxautofs is mounted on and most vop operations
 * are simply passed onto this underlying filesystem.  This means we don't
 * have to implement most of the complex operations that a full filesystem
 * normally has to implement.  It also means that most of our filesystem state
 * (wrt the contents of the filesystem) doesn't actually have to be stored
 * in memory, we can simply go to the underlying filesystem to get it when
 * it's requested.  For the purposes of discussion, we'll call the underlying
 * filesystem the "backing store."
 *
 * The backing store is actually a directory called ".lxautofs" which is created
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
 * 4) v5 protocol expire handling.
 *
 * The automounter has a timeout associated with each mount. It informs autofs
 * of this timeout using the LX_AUTOFS_IOC_SETTIMEOUT ioctl after autofs has
 * been mounted on the mountpoint.
 *
 * Periodically (<timeout>/4 seconds) the automounter will issue the
 * LX_AUTOFS_IOC_EXPIRE_MULTI ioctl on the autofs mount. autofs is expected to
 * respond with one or more underlying mountpoint entries which are candidates
 * for unmounting. The automounter will attempt to unmount the filesystem
 * (which may fail if it is busy, since this is obviously racy) and then
 * acknowledge the expire ioctl. The successful acknowledgement is independent
 * of the success of unmounting the underlying filesystem.
 *
 * To support 'indirect' mount expiration, the autofs vfs keeps track of the
 * filesystems mounted immediately under the autofs mountpoint (in
 * lav_mnt_list) after a lookup has completed successfully. Upon receipt of the
 * LX_AUTOFS_IOC_EXPIRE_MULTI ioctl, autofs removes the first element from the
 * list, attempts to check if it is busy and if not, returns that mountpoint
 * as the ioctl response (if busy the entry is added to the end of the list).
 * When the ioctl is acknowledged, if the mountpoint still exists, that
 * means the unmount failed and the entry is added at the back of the list. If
 * there are no elements or the first one is busy, EAGAIN is returned for the
 * 'expire' ioctl and the autoumounter will check again in <timeout>/4 seconds.
 *
 * For example, if /home is an autofs indirect mount, then there are typically
 * many different {username}-specific NFS mounts under that /home autofs mount.
 * autofs uses the lav_mnt_list to respond to 'expire' ioctls in a round-robin
 * fashion so that the automounter can unmount user file systems that aren't in
 * use.
 *
 * Expiring 'direct' mounts is similar, but since there is only a single mount,
 * the lav_mnt_list only will have at most one entry if there is a filesystem
 * mounted overtop of the autofs mount.
 *
 * Expiring 'offset' mounts is also more complicated and offset mounts do not
 * currently work correctly (because each lower-level offset mount is like a
 * direct mount).
 *
 * For example, if /net was an autofs 'offset' mount and the host 'jurassic'
 * had two exported file systems (/var/crash and /var/core) then accessing
 * /net/jurassic would cause the lookup to the automounter to create the
 * following two autofs mounts (these are like direct autofs mounts):
 *	/net/jurassic/var/crash
 *	/net/jurassic/var/core
 *
 * For expiration the automounter will issue the LX_AUTOFS_IOC_EXPIRE_MULTI
 * ioctl on /net but because there are no immediate mountpoints under /net
 * (the underlying autofs mountpoints are jurassic/var/crash and
 * jurassic/var/core) the indirect technique described above will fail.
 *
 * Here's one possibility for how this functionality could be implemented,
 * although the details will depend on how direct mount expiration is
 * implemented:
 *
 * Coalesce underlying mountpoints to a common ancester and don't do any in-use
 * detection. Simply tell the automounter we expired the ancestor every time
 * its turn comes around. If one of the underlying filesystems is in use then
 * that unmount will fail. This technique can break down for a remote host with
 * multiple mounts. For example, if the automounter had mounted the following
 * autofs filesystems, and then NFS mounted over those:
 *	/net/jurassic/var/crash
 *	/net/jurassic/var/core
 * and the user was looking at a core file when the timeout expired, the
 * automounter would receive notification to expire 'jurassic'. It would
 * unmount jurassic/var/crash (which would succeed) and then to try unmount
 * jurassic/var/core (which would fail). After that, since the automounter only
 * performs mounts for failed lookups in the root autofs directory, future
 * access to /net/jurassic/var/crash would result in access to an empty autofs
 * directory. We might be able to work around this by resending lookups to the
 * automounter, assuming it ignores mount failures.
 *
 * There are likely other solutions to expiring offset mounts and one of these
 * might be the eventual solution.
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
#define	LX_MNTOPT_OFFSET		"offset"

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

/* v4 multi-expire */
typedef struct lx_autofs_v4_exp_pkt {
	lx_autofs_pkt_hdr_t lape_hdr;
	int lape_len;
	char lape_name[MAXNAMELEN];
} lx_autofs_v4_exp_pkt_t;

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
 * Ioctls supported (v3/v4 protocol).
 */
#define	LX_AUTOFS_IOC_PROTOVER		0x80049363 /* arg: int */
#define	LX_AUTOFS_IOC_SETTIMEOUT	0xc0089364 /* arg: ulong_t */

/*
 * Ioctls not supported (v3/v4 protocol).
 */
					/* arg: lx_autofs_v3_exp_pkt_t * */
#define	LX_AUTOFS_IOC_EXPIRE		0x81109365

/*
 * Ioctls supported (v5 protocol).
 */
#define	LX_AUTOFS_IOC_PROTOSUBVER	0x80049367 /* arg: int */
#define	LX_AUTOFS_IOC_ASKUMOUNT		0x80049370 /* arg: int */
#define	LX_AUTOFS_IOC_EXPIRE_MULTI	0x40049366 /* arg: int */
#define	LX_AUTOFS_IOC_EXPIRE_INDIRECT	LX_AUTOFS_IOC_EXPIRE_MULTI
#define	LX_AUTOFS_IOC_EXPIRE_DIRECT	LX_AUTOFS_IOC_EXPIRE_MULTI

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_AUTOFS_H */
