/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MDB_ERRNO_H
#define	_MDB_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MDB

#define	EMDB_BASE	1000			/* Base value for mdb errnos */

enum {
	EMDB_NOSYM = EMDB_BASE,			/* Symbol not found */
	EMDB_NOOBJ,				/* Object file not found */
	EMDB_NOMAP,				/* No mapping for address */
	EMDB_NODCMD,				/* Dcmd not found */
	EMDB_NOWALK,				/* Walk not found */
	EMDB_DCMDEXISTS,			/* Dcmd already exists */
	EMDB_WALKEXISTS,			/* Walk already exists */
	EMDB_NOPLAT,				/* No platform support */
	EMDB_NOPROC,				/* No process created yet */
	EMDB_NAME2BIG,				/* Name is too long */
	EMDB_NAMEBAD,				/* Name is invalid */
	EMDB_ALLOC,				/* Failed to allocate memory */
	EMDB_NOMOD,				/* Module not found */
	EMDB_BUILTINMOD,			/* Cannot unload builtin mod */
	EMDB_NOWCB,				/* No walk is active */
	EMDB_BADWCB,				/* Invalid walk state */
	EMDB_NOWALKLOC,				/* Walker doesn't accept addr */
	EMDB_NOWALKGLOB,			/* Walker requires addr */
	EMDB_WALKINIT,				/* Walker init failed */
	EMDB_WALKLOOP,				/* Walker layering loop */
	EMDB_IORO,				/* I/O stream is read-only */
	EMDB_IOWO,				/* I/O stream is write-only */
	EMDB_NOSYMADDR,				/* No symbol for address */
	EMDB_NODIS,				/* Disassembler not found */
	EMDB_DISEXISTS,				/* Disassembler exists */
	EMDB_NOSESPEC,				/* No software event spec */
	EMDB_NOXD,				/* No such xdata */
	EMDB_XDEXISTS,				/* Xdata name already exists */
	EMDB_TGTNOTSUP,				/* Op not supported by tgt */
	EMDB_TGTRDONLY,				/* Tgt not open for writing */
	EMDB_BADREG,				/* Invalid register name */
	EMDB_NOREGS,				/* No registers for thread */
	EMDB_STKALIGN,				/* Bad stack pointer align */
	EMDB_NOEXEC,				/* No executable file open */
	EMDB_EVAL,				/* Failed to mdb_eval() */
	EMDB_CANCEL,				/* Command cancelled by user */
	EMDB_PARTIAL,				/* Partial read occurred */
	EMDB_DCFAIL,				/* Dcmd failed */
	EMDB_DCUSAGE, 				/* Dcmd usage error */
	EMDB_TGT,				/* Internal target error */
	EMDB_BADSYSNUM,				/* Invalid system call code */
	EMDB_BADSIGNUM,				/* Invalid signal number */
	EMDB_BADFLTNUM,				/* Invalid fault number */
	EMDB_TGTBUSY,				/* Target is busy executing */
	EMDB_TGTZOMB,				/* Target is a zombie */
	EMDB_TGTCORE,				/* Target is a core file */
	EMDB_TGTLOST,				/* Target is lost to mdb */
	EMDB_TDB,				/* libthread_db error */
	EMDB_RTLD,				/* libdl error */
	EMDB_RTLD_DB,				/* librtld_db error */
	EMDB_NORTLD,				/* no librtld_db */
	EMDB_NOTHREAD,				/* Invalid thread identifier */
	EMDB_SPECDIS,				/* Event specifier disabled */
	EMDB_NOLMID,				/* Link map not found */
	EMDB_NORETADDR,				/* No return address found */
	EMDB_WPRANGE,				/* Watchpoint size overflow */
	EMDB_WPDUP,				/* Watchpoint duplicate */
	EMDB_BPALIGN,				/* Breakpoint alignment err */
	EMDB_NODEM,				/* Bad demangler library */
	EMDB_EOF,				/* Read failed at EOF */
	EMDB_NOCTF,				/* No CTF data for module */
	EMDB_CTF,				/* libctf error */
	EMDB_TLS,				/* TLS not allocated */
	EMDB_NOTLS,				/* TLS not supported in obj */
	EMDB_CTFNOMEMB,				/* No CTF member of type */
	EMDB_CTX,				/* Action in invalid context */
	EMDB_INCOMPAT,				/* Mod incompat. w/ target */
	EMDB_TGTHWNOTSUP,			/* Not sup by tgt on this h/w */
	EMDB_KINACTIVE,				/* kmdb is not loaded */
	EMDB_KACTIVATING,			/* kmdb is loading */
	EMDB_KACTIVE,				/* kmdb is already loaded */
	EMDB_KDEACTIVATING,			/* kmdb is unloading */
	EMDB_KNOLOAD,				/* kmdb could not be loaded */
	EMDB_KNOUNLOAD,				/* kmdb cannot be unloaded */
	EMDB_WPTOOMANY,				/* Too many watchpoints */
	EMDB_DTACTIVE,				/* DTrace is active */
	EMDB_KMODNOUNLOAD,			/* module can't be unloaded */
	EMDB_STKFRAME,				/* Bad stack frame pointer */
	EMDB_SHORTWRITE				/* unexpected short write */
};

#endif /* _MDB */

#ifdef __cplusplus
}
#endif

#endif /* _MDB_ERRNO_H */
