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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PKGADM_MSGS_H
#define	_PKGADM_MSGS_H


#include <libintl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	lint
#define	gettext(x)	x
#endif

/* generic messages */
#define	MSG_BAD_SUB		gettext(\
	"\"%s\" is not a valid subcommand")

#define	MSG_MISSING_OPERAND	gettext(\
	"-%c requires an operand")

#define	MSG_USAGE		gettext(\
"usage:\n" \
"\n" \
"pkgadm dbstatus [-R rootpath]\n" \
"\n" \
"\t- Returns 'text' - the text install database in use since Solaris 2.0\n" \
"\t  is the current install database in use.\n" \
"\n" \
"pkgadm sync [-R rootpath] [-q]\n" \
"\n" \
"\t- Writes the contents file and rolls the contents log file.\n" \
"\t- Optionally forces the contents file server to quit [-q].\n" \
"\n" \
"pkgadm -V\n" \
"\t- Displays packaging tools version\n" \
"\n" \
"pkgadm -?\n" \
"\t- Shows this help message\n")

#define	MSG_WARNING		gettext(\
	"WARNING")

#define	MSG_ERROR		gettext(\
	"ERROR")

#define	MSG_T_OPTION_ARGS	gettext(\
	"-t option takes 2 or 3 arguments, not %d!\n")

#define	MSG_T_RESULT_TWO	gettext(\
	"result <%d>: <%s> ~= <%s>\n")

#define	MSG_T_RESULT_THREE	gettext(\
	"required <%d> actual <%d> <%30s> ~- <%30s>\n")

#define	MSG_ERROR		gettext(\
	"ERROR")

/* warnings */

#define	CREATE_PKGDIR_WARN	gettext(\
	"Creating directory <%s>\n")

#define	MSG_VALID_STALE		gettext(\
	"Removing stale lock on <%s> pid <%ld> zid <%ld>")

/* errors */

#define	MSG_INTERNAL			gettext(\
	"Intenal Error <%s>")

#define	MSG_OPEN			gettext(\
	"Cannot open <%s> for reading")

#define	MSG_OPEN_WRITE			gettext(\
	"Cannot open <%s> for writing")

#define	ERR_LOG_FAIL			gettext(\
	"Failed to log message using format <%s>")

#define	MSG_ZONES_MISSING_REQUEST	gettext(\
	"Must specify operation to perform\n")

#define	MSG_LOCK_ALTROOT_CANTCREATE	gettext(\
	"lock: cannot create alternative root directory <%s>: %s\n")

#define	MSG_LOCK_ALTROOT_NONEXIST	gettext(\
	"lock: argument to -R <%s> is not a directory: %s\n")

#define	MSG_LOCK_ROOTDIR_INVALID	gettext(\
	"lock: lock file base directory <%s> not valid: %s\n")

#define	MSG_LOCK_WFLAG_BADINT	gettext(\
	"The integer value <%s> given to the -W option includes an " \
	"invalid character: \"%c\"\n")

#define	MSG_LOCK_pFLAG_BADINT	gettext(\
	"The integer value <%s> given to the -p option includes an " \
	"invalid character: \"%c\"\n")

#define	MSG_LOCK_zFLAG_BADINT	gettext(\
	"The integer value <%s> given to the -z option includes an " \
	"invalid character: \"%c\"\n")

#define	MSG_LOCK_nFLAG_BADINT	gettext(\
	"The integer value <%s> given to the -n option includes an " \
	"invalid character: \"%c\"\n")

#define	MSG_LOCK_ar_TOGETHER	gettext(\
	"lock: The -a and -r options cannot be used together: "\
	"specify only one.\n")

#define	MSG_LOCK_kARG_TOOLONG	gettext(\
	"Argument to -k is <%d> characters: may not exceed <%d> characters\n")

#define	MSG_LOCK_oARG_TOOLONG	gettext(\
	"Argument to -o is <%d> characters: may not exceed <%d> characters\n")

#define	MSG_LOCK_RARG_NOT_ABSOLUTE	gettext(\
	"Argument to -R must be absolute path: %s")

#define	MSG_LOCK_WFLAG_ERROR	gettext(\
	"Argument to -W has problem with wait interval <%s>: %s")

#define	MSG_LOCK_pFLAG_ERROR	gettext(\
	"Argument to -p has problem with process i.d. value <%s>: %s")

#define	MSG_LOCK_zFLAG_ERROR	gettext(\
	"Argument to -p has problem with zone i.d. value <%s>: %s")

#define	MSG_LOCK_nFLAG_ERROR	gettext(\
	"Argument to -n has problem with maximum number of retries " \
	"value <%s>: %s")

#define	MSG_LOCK_es_TOGETHER	gettext(\
	"lock: The -e and -s options cannot be used together: "\
	"specify only one.\n")

#define	MSG_LOCK_ak_TOGETHER	gettext(\
	"lock: The -k option cannot be used with the -a option.\n")

#define	MSG_LOCK_e_without_a	gettext(\
	"lock: The -e option can only be used with the -a option.\n")

#define	MSG_LOCK_s_without_a	gettext(\
	"lock: The -s option can only be used with the -a option.\n")

#define	MSG_LOCK_ACQUIRE_KEYMISMATCH	gettext(\
	"cannot acquire %s lock on <%s>: object locked and specified key " \
	"does not match")

#define	MSG_LOCK_ACQUIRE_ERROR	gettext(\
	"cannot determine if object <%s> key <%s> is locked: %s")

#define	MSG_LOCK_ACQUIRE_TIMEDOUT	gettext(\
	"cannot acquire %s lock on <%s> key <%s>: object locked, no key " \
	"was specified, and the wait timed out")

#define	MSG_LOCK_ACQUIRE_WAITING	gettext(\
	"object <%s> is locked: waiting for object to become available")

#define	MSG_LOCK_ACQUIRE_REOPEN_FAILED	gettext(\
	"cannot reopen lock file after waiting for lock on object " \
	"<%s> to be released")

#define	MSG_LOCK_RELEASE_NOTLOCKED	gettext(\
	"cannot release lock on <%s> key <%s>: object not locked and " \
	"a key was specified")

#define	MSG_LOCK_RELEASE_LOCKED		gettext(\
	"cannot release lock on <%s> key <%s>: object locked but no " \
	"key was specified")

#define	MSG_LOCK_RELEASE_NOTFOUND	gettext(\
	"cannot release lock on <%s> key <%s>: object is not locked")

#define	MSG_LOCK_RELEASE_KEYMISMATCH	gettext(\
	"cannot release lock on <%s>: object locked and specified key " \
	"does not match")

#define	MSG_LOCK_RELEASE_ERROR		gettext(\
	"cannot determine if object <%s> key <%s> is locked")

#define	MSG_LOCK_EXEC_ACCESS	gettext(\
	"cannot execute command <%s>: %s")

#define	MSG_LOCK_EXEC_NOINPUT	gettext(\
	"cannot open input file <%s>: %s")

#define	MSG_LOCK_EXEC_NOPIPE	gettext(\
	"cannot create pipe: %s")

#define	MSG_LOCK_FINDLOCK_LSEEK_FAILURE	gettext(\
	"cannot find lock <%s> key <%s>: lseek failure: %s")

#define	MSG_LOCK_ADDLOCK_PWRITE_FAILURE	gettext(\
	"cannot create %s lock for object <%s>: pwrite failure: %s")

#define	MSG_LOCK_ADDLOCK_LSEEK_FAILURE	gettext(\
	"cannot create %s lock for object <%s>: lseek failure: %s")

#define	MSG_LOCK_INCLOCK_PWRITE_FAILURE	gettext(\
	"cannot increment %s lock for object <%s>: pwrite failure: %s")

#define	MSG_LOCK_DECLOCK_PWRITE_FAILURE	gettext(\
	"cannot decrement %s lock for object <%s>: pwrite failure: %s")

#define	MSG_LOCK_DECLOCK_PREAD_FAILURE	gettext(\
	"cannot decrement %s lock for object <%s>: pread failure: %s")

#define	MSG_LOCK_DECLOCK_LSEEK_FAILURE	gettext(\
	"cannot decrement %s lock for object <%s>: lseek failure: %s")

#define	MSG_LOCK_DECLOCK_FTRUNCATE_FAILURE	gettext(\
	"cannot decrement %s lock for object <%s>: ftruncate failure: %s")

/*
 * i18n:
 * next two messages grouped together
 */

#define	MSG_LOCK_ACQUIRE_BUSY_QUASI	gettext(\
	"cannot acquire %s lock on <%s> key <%s>: object matches wildcard " \
	"<%s> lock%s")
#define	MSG_LOCK_ACQUIRE_BUSY_FIRST	gettext(\
	"cannot acquire %s lock on <%s> key <%s>: object <%s> is locked <%s>%s")

/*
 * i18n: note this message may be appended to the previous message
 * by supplying it to the final "%s" at the end of the line above;
 * that is either:
 *  cannot acquire %s lock on <%s> key <%s>: object is locked <%s>
 * or:
 *  cannot acquire %s lock on <%s> [...] is locked <%s> and no key specified
 */

#define	MSG_LOCK_ACQUIRE_BUSY_ADDITIONAL	gettext(\
	" and no key specified")

/*
 * i18n: note these two "messages" are inserted into other
 * messages, such as:
 * 	cannot acquire %s lock on <%s>
 * will be either:
 *	cannot acquire shared lock on <%s>
 * or
 *	cannot acquire exclusive lock on <%s>
 */

#define	MSG_LOCK_EXC	gettext(\
	"exclusive")

#define	MSG_LOCK_SHR		gettext(\
	"shared")

/*
 * i18n: note these messages are "debugging" messages and will normally
 * not be seen unless debugging has been enabled for problem root causing
 * so they are not meant to be perfectly "human readable"
 */

#define	MSG_VALID_NOPID		gettext(\
	"validate lock <%s>: VALID (no pid)")

#define	MSG_VALID_BADZID	gettext(\
	"validate lock <%s>: VALID (lock zid <%ld> this zid <%ld>)")

#define	MSG_VALID_ZIDOK	gettext(\
	"validate lock <%s>: zone i.d.s match (lock zid <%ld> this zid <%ld>)")

#define	MSG_VALID_OK		gettext(\
	"validate lock <%s> pid <%ld> path <%s>: VALID")

#define	MSG_VALID_NOTOK		gettext(\
	"validate lock <%s> pid <%ld> path <%s>: NOT VALID")

#define	MSG_LCKMCH_ENTRY	gettext(\
	"lockMatch: *** BEGIN *** compare objects <%s> <%s>")

#define	MSG_LCKMCH_FSTNODE	gettext(\
	"lockMatch: first lock node (%d) <%s>")

#define	MSG_LCKMCH_SCNDNODE	gettext(\
	"lockMatch: second lock node (%d) <%s>")

#define	MSG_LCKMCH_NODES	gettext(\
	"lockMatch: first lock node <%s> prefix <%s> (%d) second lock " \
	" node <%s> prefix <%s> (%d)")

#define	MSG_LCKMCH_DIRMCH	gettext(\
	"lockMatch: no prefix direct comparison: match: <%s> <%s>")

#define	MSG_LCKMCH_DIRNOMCH	gettext(\
	"lockMatch: no prefix direct comparison: NO MATCH: <%s> <%s>")

#define	MSG_LCKMCH_PFXMCH	gettext(\
	"lockMatch: prefix comparison: match: <%s> <%s>")

#define	MSG_LCKMCH_PFXNOMCH	gettext(\
	"lockMatch: prefix comparison: NO MATCH: <%s> <%s>")

#define	MSG_LCKMCH_FSTLCK	gettext(\
	"lockMatch: first lock index (%d) last scanned node <%s> prefix " \
	"<%s> (%d)")

#define	MSG_LCKMCH_SCNDLCK	gettext(\
	"lockMatch: second lock index (%d) last scanned node <%s> prefix " \
	"<%s> (%d)")

#define	MSG_LCKMCH_ABSNOMCH	gettext(\
	"lockMatch: absolute locks: NO MATCH: <%s> <%s>")

#define	MSG_LCKMCH_OBJMCH	gettext(\
	"lockMatch: object locks: match: <%s> <%s>")

#define	MSG_LCKMCH_OVLPNOMCH	gettext(\
	"lockMatch: nonmatching overlapping objects: <%s> <%s> before " \
	"(%d) <%s>")

#define	MSG_LCKMCH_SAME	gettext(\
	"lockMatch: locks begin with same node - compare: <%s> <%s> at <%s>")

#define	MSG_LCKMCH_SCNDSUB	gettext(\
	"lockMatch: second lock <%s> subset of <%s> at (%d) <%s>")

#define	MSG_LCKMCH_FRSTSUB	gettext(\
	"lockMatch: first lock <%s> subset of <%s> at (%d) <%s>")

#define	MSG_LCKMCH_DONTKNOW	gettext(\
	"lockMatch: unable to determine how to compare locks: <%s> <%s>: " \
	"using direct comparision")

#define	MSG_LCKMCH_READY	gettext(\
	"lockMatch: comparing nodes locks <%s> <%s>")

#define	MSG_LCKMCH_NODEFAIL	gettext(\
	"lockMatch: node (%d) comparison: NO MATCH: <%s> != <%s>")

#define	MSG_LCKMCH_NODEOK	gettext(\
	"lockMatch: node (%d) comparision: match: <%s> == <%s>")

#define	MSG_LCKMCH_MATCHOK	gettext(\
	"lockMatch: locks match: <%s> == <%s>")

#define	MSG_LOCK_EXEC_RESULTS	gettext(\
	"command <%s> executed: pid <%d> errno <0x%04x> status <0x%04x> " \
	"final status <0x%04x> output <%s>")

#define	MSG_LOCK_GENUID_INTERNAL	gettext(\
	"generated new unique key using date: %s")

#define	MSG_LOCK_DECLOCK_DECING	gettext(\
	"decrement <%s> lock count record <%d> count <%d>")

#define	MSG_LOCK_DECLOCK_DONE	gettext(\
	"decrement lock record <%d> count <%d> object <%s> key <%s>")

#define	MSG_LOCK_DECLOCK_REMOVE	gettext(\
	"decrement lock remove record lastPos %ld last record %d " \
	"current record %d")

#define	MSG_LOCK_DECLOCK_LASTONE	gettext(\
	"decrement lock removing <%s> lock last record <%d> " \
	"truncating to <%ld>")

#define	MSG_LOCK_DECLOCK_REMOVING	gettext(\
	"decrement lock removing record <%d> last record <%d> " \
	"truncating to <%ld>")

#define	MSG_LOCK_INCLOCK_ENTRY	gettext(\
	"increment <%s> lock count record <%d> count <%d>")

#define	MSG_LOCK_INCLOCK_DONE	gettext(\
	"increment lock record <%d> count <%d> object <%s> key <%s>")

#define	MSG_LOCK_ADDLOCK_ADDING	gettext(\
	"adding %s lock pos <%d> object <%s> key <%s> pid <%ld> zid <%ld>")

#define	MSG_LOCK_FINDLOCK_ENTRY	gettext(\
	"find lock object <%s> key <%s>")

#define	MSG_LOCK_FINDLOCK_READRECORD	gettext(\
	"find lock read record <%d>: count <%d> object <%s> key <%s> pid " \
	"<%ld> zid <%ld>")

#define	MSG_LOCK_FINDLOCK_FOUND	gettext(\
	"find lock record found")

#define	MSG_LOCK_FINDLOCK_NOTFOUND	gettext(\
	"find lock record not found")

#define	MSG_LOCK_OPENFILE_ENTRY	gettext(\
	"open lock file root <%s> file <%s>")

#define	MSG_LOCK_OPENFILE_SLEEPING	gettext(\
	"open lock file busy <%s>: sleeping <%d>")

#define	MSG_LOCK_OPENFILE_FAILURE	gettext(\
	"open lock file could not be opened: %s")

#define	MSG_LOCK_OPENFILE_SLEEP2	gettext(\
	"open lock file cannot obtain record lock <%s>: sleeping <%d>")

#define	MSG_LOCK_OPENFILE_FAIL2	gettext(\
	"open lock file could not obtain record lock: <%s>")

#define	MSG_LOCK_OPENFILE_SUCCESS	gettext(\
	"open lock file: opened and locked fd <%d>")

#define	MSG_LOCK_STATUS_READRECORD	gettext(\
	"status read record <%d>: count <%d> object <%s> key <%s> pid <%ld> " \
	"zid <%ld>")

#define	MSG_LOCK_STATUS_ENTRY	gettext(\
	"status key=<%s> object=<%s>")

#define	MSG_LOCK_RELEASE_FOUND		gettext(\
	"object <%s> key <%s> is locked: decrementing lock count")

#define	MSG_LOCK_RELEASE_ENTRY	gettext(\
	"release lock key=<%s> object=<%s> quiet=<%d>")

#define	MSG_LOCK_RELEASE_FINDRESULT	gettext(\
	"release lock result <%d> record <%d>")

#define	MSG_LOCK_ACQUIRE_FOUND_INC	gettext(\
	"object <%s> key <%s> is locked: incrementing <%s> lock count")

#define	MSG_LOCK_ACQUIRE_ENTRY	gettext(\
	"acquire lock key=<%s> object=<%s> quiet=<%d> exclusive=<%d>")

#define	MSG_LOCK_ACQUIRE_FINDRESULT	gettext(\
	"acquire %s lock result <%d> record <%d>")

#define	MSG_LOCK_ACQUIRE_LOCKED_SHARED	gettext(\
	"object <%s> key <%s> is locked but shared: incrementing lock count")

#define	MSG_LOCK_ACQUIRE_NOTLOCKED	gettext(\
	"cannot acquire %s lock on <%s> key <%s>: object not locked " \
	"and non-matching key specified")

#define	MSG_LOCK_ACQUIRE_NOTFOUND	gettext(\
	"acquiring %s lock on object <%s>")

#ifdef	__cplusplus
}
#endif

#endif /* _PKGADM_MSGS_H */
