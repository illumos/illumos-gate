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
 * Copyright (c) 1996 Sun Microsystems, Inc.  All Rights Reserved
 *
 * module:
 *	messages.h
 *
 * purpose:
 *	contins defines for all localizable messages
 *
 * notes:
 *	unless otherwise specified, all %s arguments can be assumed
 * 	to be file names.  Non-obvious arguments are explained in
 *	comments.
 */

#ifndef	_MESSAGES_H
#define	_MESSAGES_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <libintl.h>

/*
 * summary output messages
 */
#define	SUM_hd		"RECONCILE %s and %s (%d files)\n"
#define	SUM_dst		"\t-> %4d copies, %4d deletes, %4d ownership\n"
#define	SUM_src		"\t<- %4d copies, %4d deletes, %4d ownership\n"
#define	SUM_unresolved	"\tUNRESOLVED CONFLICTS: %d\n"

/*
 * verbose mode analysis commentary
 */
#define	V_nomore	"# file %s no longer exists\n"
#define	V_deleted	"# file %s deleted from %s\n"	/* src/dst */
#define	V_created	"# file %s created on %s\n"	/* src/dst */
#define	V_delconf	"# file %s has been deleted and changed\n"
#define	V_trunconf	"# file %s has been truncated and changed\n"
#define	V_unchanged	"# file %s has two identical versions\n"
#define	V_different	"# file %s has two different versions\n"
#define	V_modes		"# file %s has changed modes/ownership\n"
#define	V_changed	"# file %s has been modified\n"
#define	V_renamed	"# file %s has been renamed to %s\n"
#define	V_prunes	"# %d stale entries pruned from baseline\n"
#define	V_nostat	"# WARNING: unable to stat file %s\n"
#define	V_change	"# WARNING: file %s on %s, was <%ld,%ld>#%ld, now <%ld,%ld>#%ld\n"
#define	V_suppressed	"# file %s not reconciled due to halt-on-error\n"

/*
 * usage messages
 */
#define	ERR_usage	"Usage:"
#define	USE_a		"always check for Access Control Lists"
#define	USE_e		"everything must agree (modes, owner, group)"
#define	USE_h		"halt immediately after a file propagation error"
#define	USE_m		"modification times should be preserved"
#define	USE_n		"no touch (do not change any files)"
#define	USE_q		"quiet    (do not list reconciliation commands)"
#define	USE_v		"verbose  (commentary on each changed file)"
#define	USE_y		"yes      (do not prompt for confirmations)"
#define	USE_s		"source directory for new rules"
#define	USE_d		"destination directory for new rules"
#define	USE_r		"restrict reconciliation to specified directories"
#define	USE_f		"force conflicts to resolve in favor of src/dst/old/new"
#define	USE_o		"one-way: only propagate changes from src/dst"

/*
 * These are the basic usage scenario line, and in most cases should not
 * be translated.
 */
#define	USE_simple	"[-mnqv] -s dir -d dir file ..."
#define	USE_all		"[-aehmnqvy] [-r dir] [-f src/dst/old/new] [-o src/dst]"

/*
 * error messages
 */
#define	ERR_open	"ERROR: cannot open %s file %s\n"
#define	ERR_creat	"ERROR: unable to create %s file %s\n"
#define	ERR_write	"ERROR: write error in %s file %s\n"
#define	ERR_fclose	"ERROR: error in flushing and closing %s file %s\n"
#define	ERR_chdir	"ERROR: unable to chdir to %s\n"
#define	ERR_rename	"ERROR: unable to rename %s file %s to %s\n"
#define	ERR_lock	"ERROR: unable to lock %s file %s\n"
			/*
			 * first %s argument is "rules" or "baseline"
			 */
#define	ERR_badinput	"ERROR: invalid input at line %d, %s in %s\n"
			/*
			 * first %s argument is a the name of the offending
			 * field (e.g. "mode" or "major dev").  The last
			 * %s argument is the name of the file being
			 * processed.
			 */
#define	ERR_badver	"ERROR: bad version (%d.%d) found in %s file %s\n"
			/*
			 * second %s is "rules" or "baseline"
			 * last %s is file name
			 */


#define	ERR_nocwd	"ERROR: unable to get working directory for %s\n"
#define	ERR_longname	"ERROR: excessively long name %s\n"
#define	ERR_undef	"ERROR: undefined variable %s\n"
#define	ERR_deep	"ERROR: directory tree is too deep at directory %s\n"

#define	ERR_badopt	"ERROR: unrecognized option -%c %s\n"
			/*
			 * the %c argument is the offending flag
			 * (e.g. -f or -o) and the %s is the argument
			 * that followed it.
			 */

#define	ERR_nofsync	"ERROR: unable to find rule and baseline files\n"
#define	ERR_badbase	"ERROR: invalid BASE directory %s\n"
#define	ERR_nosrc	"ERROR: no source directory specified\n"
#define	ERR_nodst	"ERROR: no destination directory specified\n"
#define	ERR_nonames	"ERROR: no file/directory names specified and no rules file found\n"
#define	ERR_tomany	"ERROR: only %d -r arguments allowed\n"
#define	ERR_rdwri	"ERROR: cannot read/write file %s\n"
#define	ERR_dirwac	"ERROR: cannot create files in directory %s\n"
#define	ERR_nomem	"ERROR: unable to allocate memory for %s\n"
			/*
			 * the %s argument is the name of a data structure
			 * that could not be allocated.  It is only useful
			 * for telling the support person over the phone.
			 */

#define	ERR_badrun	"ERROR: bad exit code from %s\n"
			/*
			 * argument is a command from the rules file
			 */

#define	ERR_cannot	"ERROR: %s %s\n"
			/*
			 * The first %s argument will be a PROB_ string.
			 * The second %s argument is the file we were
			 * trying to do it to.
			 */

#define	ERR_abort_h	"ERROR: aborting because of propagation failure\n"

#define	WARN_ignore	"WARNING: ignoring LIST rule for %s (illegal '.', '..', or '/')\n"
#define	WARN_noacls	"WARNING: ACLs are not supported for file %s\n"
#define	WARN_deletes	"WARNING: this operation might delete %d files\n"
#define	WARN_rmdirs	"WARNING: operation might delete %d non-empty directories\n"
#define	WARN_ichange	"WARNING: %d listed directories have changed Inode #s\n"
#define	WARN_proceed	"Press Enter to confirm, or interrupt to abort\n"
#define	WARN_super	"NOTE: there are ownership and protection conflicts that can only be\n      resolved by the super user\n"

/*
 * descriptions of problems in unreconcilable files
 */
#define	PROB_del_change	"deleted and changed"
#define	PROB_different	"two different versions"
#define	PROB_ownership	"different owners"
#define	PROB_protection	"different protections"
#define	PROB_prohibited	"blocked by -o switch"
#define	PROB_aborted	"aborted by -h switch"

#define	PROB_chown	"unable to chown"
#define	PROB_chgrp	"unable to chgrp"
#define	PROB_chmod	"unable to chmod"
#define	PROB_chacl	"unable to setfacl"
#define	PROB_link	"unable to link"
#define	PROB_unlink	"unable to unlink"
#define	PROB_rmdir	"unable to rmdir"
#define	PROB_copy	"unable to copy"
#define	PROB_mknod	"unable to mknod"
#define	PROB_mkdir	"unable to mkdir"
#define	PROB_readlink	"unable to read symlink"
#define	PROB_symlink	"unable to create symlink"
#define	PROB_restat	"unable to stat/restat"
#define	PROB_deal	"unable to deal with"
#define	PROB_copyin	"unable to open changed file"
#define	PROB_copyout	"unable to create new file"
#define	PROB_botch	"unable to safely setfacl"
#define	PROB_rename	"unable to rename"
#define	PROB_rename2	"unable to rename/create"
#define	PROB_read	"read error"
#define	PROB_write	"write error"
#define	PROB_space	"insufficient space to copy"


/*
 * text snippets
 */
#define	TXT_src		"source"			/* for WARN_change   */
#define	TXT_dst		"destination"			/* for WARN_change   */
#define	TXT_srcdst	"missing source/destination"	/* for ERR_bad_input */
#define	TXT_noargs	"missing arguments"		/* for ERR_bad_input */
#define	TXT_badver	"invalid version number"	/* for ERR_bad_input */
#define	TXT_nobase	"LIST without a BASE"		/* for ERR_bad_input */
#define	TXT_rules	"rules"				/* for ERR_bad_ver   */
#define	TXT_base	"baseline"			/* for ERR_bad_ver   */

#ifdef	__cplusplus
}
#endif

#endif	/* _MESSAGES_H */
