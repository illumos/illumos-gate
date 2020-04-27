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

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <locale.h>
#include <errno.h>
#include <assert.h>
#include <sys/dditypes.h>
#include <sys/param.h>
#include <sys/obpdefs.h>
#include <sys/fhc.h>
#include <sys/sysctrl.h>
#include <sys/ac.h>
#include <sys/spitregs.h>
#include <config_admin.h>
#include "mema_util.h"
#include "mema_test.h"
#include "mema_prom.h"

#ifdef	DEBUG
#define	DBG	(void) printf
#define	DBG1	(void) printf
#define	DBG3	(void) printf
#define	DBG4	(void) printf
#else
#define	DBG(a, b)
#define	DBG1(a)
#define	DBG3(a, b, c)
#define	DBG4(a, b, c, d)
#endif

#ifndef P_DER_UE
/*
 * <sys/spitregs.h> has these defines inside 'ifdef _KERNEL' at the
 * time of writing.  Re-define here if that is still the case.
 */

#define	P_DER_UE	0x00000000000000200ULL	/* UE has occurred */
#define	P_DER_CE	0x00000000000000100ULL	/* CE has occurred */
#define	P_DER_E_SYND	0x000000000000000FFULL	/* SYND<7:0>: ECC syndrome */
#endif /* ! P_DER_UE */

#define	DEV_DEBUG
#ifdef DEV_DEBUG
#include <stdio.h>
#include <stdlib.h>

static FILE *debug_fp;
static int debugging(void);
static void dump_ioctl(int, void *);
static void dump_ioctl_res(int, void *, int, int);
#else /* DEV_DEBUG */
#define	dump_ioctl(CMD, ARG)
#define	dump_ioctl_res(CMD, ARG, RET, ERRNO)
#endif /* DEV_DEBUG */

typedef struct {
	uint_t   board;
	uint_t   bank;
} mema_bank_t;

static char *mema_opts[] = {
#define	OPT_BOOT_DISABLE	0
	"disable-at-boot",
#define	OPT_BOOT_ENABLE		1
	"enable-at-boot",
#define	OPT_TIMEOUT		2
	"timeout",
	NULL
};

#define	OPT_NEEDS_VALUE(O)	((O) == OPT_TIMEOUT)

#define	MAX_OPT_LENGTH		(sizeof ("disable-at-boot"))

/*
 * For each function there is an array of opt_control structures giving
 * the valid options.  The array is terminated by an element with the
 * subopt field set to -1.  The group field is used to identify
 * mutually exclusive options, with zero meaning no grouping.
 */
struct opt_control {
	int		subopt;
	int		group;
};

/*
 * Returned set of options.
 * If the option takes a value, it will be set in 'val'
 * if the corresponding bit is set in 'bits' is set,
 * otherwise the pointer in 'val' is undefined.
 */
#define	OPT_VAL_ARRAY_SIZE	32	/* # bits in 'bits' */
typedef struct {
	unsigned int	bits;
	char		*val[OPT_VAL_ARRAY_SIZE];
} option_set_t;

#define	OPTSET_INIT(S)		((S).bits = 0)
#define	_OPT_TO_BIT(O)		(1 << (O))
#define	OPTSET_SET_VAL(S, O, V)	((S).bits |= _OPT_TO_BIT(O), \
				(S).val[(O)] = (V))
#define	OPTSET_TEST(S, O)	(((S).bits & _OPT_TO_BIT(O)) != 0)
#define	OPTSET_VAL(S, O)	((S).val[(O)])
#define	OPTSET_IS_EMPTY(S)	((S).bits == 0)

static option_set_t process_options(const char *, struct opt_control *,
	int *, char **);

static struct opt_control add_opts[] = {
	{OPT_BOOT_ENABLE, 1},
	{OPT_BOOT_DISABLE, 1},
	{-1, 0}
};

static struct opt_control del_opts[] = {
	{OPT_BOOT_ENABLE, 1},
	{OPT_BOOT_DISABLE, 1},
	{OPT_TIMEOUT, 2},
	{-1, 0}
};

static struct opt_control stat_opts[] = {
	{OPT_BOOT_ENABLE, 1},
	{OPT_BOOT_DISABLE, 1},
	{-1, 0}
};

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

static const char still_testing[] = "bank %s being tested by process %d";
static const char no_value[] = "sub-option \"%s\" does not take a value";
static const char missing_value[] = "sub-option \"%s\" needs a value";
static const char conflict_opt[] = "sub-option \"%s\" conflicts with \"%s\"";
static const char unk_subopt[] = "sub-option \"%s\" unknown\n"
	"choose from: %s";
static const char not_valid[] =
	"sub-option \"%s\" not valid for this operation\n"
	"choose from: %s";
static const char timeout_notnum[] =
	"timeout value not a positive integer \"%s\"";
static const char calloc_fail[] = "memory allocation failed (%d*%d bytes)";
static const char unk_test[] = "test \"%s\" unknown\n"
	"choose from: %s";
static const char dup_test[] = "more than one test type specified (\"%s\")";
static const char dup_num[] = "option specified more than once (\"%s\")";
static const char no_num[] = "invalid number specified for max_errors(\"%s\")";
static const char mtest_rw_error[] = "memory test read/write error";
static const char mtest_lib_error[] = "memory test library error";
static const char dlist_invalid[] = "invalid disabled-memory-list";
static const char dlist_write_failed[] = "disabled-memory-list write failed";
static const char mtest_unknown_error[] = "unknown memory test error";
static const char ap_invalid[] = "invalid attachment point: %s";
static const char trans_illegal[] = "illegal transition";
static const char open_failed[] = "open failed: %s: %s";
static const char mema_help[] =	"\nAc specific options:\n";
static const char disable_opts[] = "\t-o disable-at-boot\n";
static const char enable_opts[] = "\t-o enable-at-boot\n";
static const char timeout_opts[] = "\t-o timeout=# (seconds)\n";
static const char test_opts[] =
	"\t-o {quick, normal, extended},[max_errors=#] -t ap_id [ap_id...]\n";
static const char private_funcs[] = "\t-x relocate-test ap_id [ap_id...]\n";
static const char add_is_disabled[] = "memory is disabled at boot";
static const char add_willbe_disabled[] =
	"memory will be disabled at boot";
static const char add_disab_err[] = "cannot get memory disabled status";
static const char pfunc_unknown[] = "private function \"%s\" unknown";


#define	mema_eid(a, b)		(((a) << 8) + (b))
#define	mema_str(i)		mema_strs[(i)]

#define	AC_BK_BUSY		0
#define	AC_BK_ID		1
#define	AC_BD_ID		2
#define	AC_BD_TYPE		3
#define	AC_BD_STATE		4
#define	AC_MEM_TEST_ID		5
#define	AC_MEM_TEST_PAR		6
#define	AC_MEM_PERM		7
#define	AC_KPM_CANCELLED	8
#define	AC_KPM_REFUSED		9
#define	AC_KPM_SPAN		10
#define	AC_KPM_DUP		11
#define	AC_KPM_FAULT		12
#define	AC_KPM_RESOURCE		13
#define	AC_KPM_NOTSUP		14
#define	AC_KPM_NOHANDLES	15
#define	AC_KPM_NONRELOC		16
#define	AC_KPM_HANDLE		17
#define	AC_KPM_BUSY		18
#define	AC_KPM_NOTVIABLE	19
#define	AC_KPM_SEQUENCE		20
#define	AC_KPM_NOWORK		21
#define	AC_KPM_NOTFINISHED	22
#define	AC_KPM_NOTRUNNING	23
#define	AC_VMEM			24
#define	CMD_MEM_STAT		25
#define	CMD_MEM_ADD		26
#define	CMD_MEM_DEL		27
#define	CMD_MEM_TEST_START	28
#define	CMD_MEM_TEST_STOP	29
#define	AC_UNKNOWN		30
#define	AC_INTR			31
#define	AC_TIMEOUT		32
#define	CMD_MEM_RELOCTEST	33
#define	AC_DEINTLV		34

static char *
mema_strs[] = {
	"memory bank busy",
	"invalid memory bank",
	"invalid board id",
	"invalid board type",
	"invalid board state",
	"invalid memory test id",
	"invalid memory test parameter(s)",
	"no write permission",
	"memory operation cancelled",
	"memory operation refused",
	"memory already in use (add)",
	"memory span duplicate (delete)",
	"memory access test failed (add)",
	"some resource was not available",
	"operation not supported",
	"cannot allocate any more handles",
	"non-relocatable pages in span",
	"bad handle supplied",
	"memory in span is being deleted",
	"VM viability test failed",
	"function called out of sequence",
	"no memory to delete",
	"delete processing not finished",
	"delete processing not running",
	"insufficient virtual memory",
	"memory stat failed: %s",
	"memory add failed: %s",
	"memory delete failed: %s",
	"memory test start failed: %s",
	"memory test stop failed: %s",
	"unknown error",
	"memory delete killed",
	"memory delete timeout",
	"memory relocate-test failed: %s",
	"memory cannot be de-interleaved"
};

/*
 *	AC_MEM_PERM,		EBADF,   AC_ERR_MEM_PERM
 *	AC_BK_BUSY,		EBUSY,   AC_ERR_MEM_BK
 *	AC_KPM_CANCELLED,	EINTR,   AC_ERR_KPM_CANCELLED
 *	AC_KPM_REFUSED,		EINTR,   AC_ERR_KPM_REFUSED
 *	AC_BK_ID,		EINVAL,  AC_ERR_MEM_BK
 *	AC_BD_ID,		EINVAL,  AC_ERR_BD
 *	AC_BD_TYPE,		EINVAL,  AC_ERR_BD_TYPE
 *	AC_BD_STATE,		EINVAL,  AC_ERR_BD_STATE
 *	AC_MEM_TEST_ID,		EINVAL,  AC_ERR_MEM_TEST
 *	AC_MEM_TEST_PAR,	EINVAL,  AC_ERR_MEM_TEST_PAR
 *	AC_KPM_SPAN,		EINVAL,  AC_ERR_KPM_SPAN
 *	AC_KPM_DUP,		EINVAL,  AC_ERR_KPM_DUP?
 *	AC_KPM_FAULT,		EINVAL,  AC_ERR_KPM_FAULT
 *	AC_KPM_RESOURCE,	EINVAL,  AC_ERR_KPM_RESOURCE
 *	AC_KPM_NOTSUP,		EINVAL,  AC_ERR_KPM_NOTSUP
 *	AC_KPM_NOHANDLES,	EINVAL,  AC_ERR_KPM_NOHANDLES
 *	AC_KPM_NONRELOC,	EINVAL,  AC_ERR_KPM_NONRELOC
 *	AC_KPM_HANDLE,		EINVAL,  AC_ERR_KPM_HANDLE
 *	AC_KPM_BUSY,		EINVAL,  AC_ERR_KPM_BUSY
 *	AC_KPM_NOTVIABLE,	EINVAL,  AC_ERR_KPM_NOTVIABLE
 *	AC_KPM_SEQUENCE,	EINVAL,  AC_ERR_KPM_SEQUENCE
 *	AC_KPM_NOWORK,		EINVAL,  AC_ERR_KPM_NOWORK
 *	AC_KPM_NOTFINISHED,	EINVAL,  AC_ERR_KPM_NOTFINISHED
 *	AC_KPM_NOTRUNNING,	EINVAL,  AC_ERR_KPM_NOTRUNNING
 *	AC_VMEM,		ENOMEM,  AC_ERR_VMEM
 *	AC_INTR,		EINTR,   AC_ERR_INTR
 *	AC_TIMEOUT,		EINTR,   AC_ERR_TIMEOUT
 *	AC_DEINTLV,		EINVAL,  AC_ERR_MEM_DEINTLV
 */
static int
mema_sid(int err, int acerr)
{
	if (acerr == AC_ERR_DEFAULT)
		return (AC_UNKNOWN);

	switch (mema_eid(err, acerr)) {
	case mema_eid(EBADF, AC_ERR_MEM_PERM):
		return (AC_MEM_PERM);
	case mema_eid(EBUSY, AC_ERR_MEM_BK):
		return (AC_BK_BUSY);
	case mema_eid(EINTR, AC_ERR_KPM_CANCELLED):
		return (AC_KPM_CANCELLED);
	case mema_eid(EINTR, AC_ERR_KPM_REFUSED):
		return (AC_KPM_REFUSED);
	case mema_eid(EINVAL, AC_ERR_MEM_BK):
		return (AC_BK_ID);
	case mema_eid(EINVAL, AC_ERR_BD):
		return (AC_BD_ID);
	case mema_eid(EINVAL, AC_ERR_BD_TYPE):
		return (AC_BD_TYPE);
	case mema_eid(EINVAL, AC_ERR_BD_STATE):
		return (AC_BD_STATE);
	case mema_eid(EINVAL, AC_ERR_MEM_TEST):
		return (AC_MEM_TEST_ID);
	case mema_eid(EINVAL, AC_ERR_MEM_TEST_PAR):
		return (AC_MEM_TEST_PAR);
	case mema_eid(EINVAL, AC_ERR_KPM_SPAN):
		return (AC_KPM_SPAN);
	case mema_eid(EINVAL, AC_ERR_KPM_DUP):
		return (AC_KPM_DUP);
	case mema_eid(EINVAL, AC_ERR_KPM_FAULT):
		return (AC_KPM_FAULT);
	case mema_eid(EINVAL, AC_ERR_KPM_RESOURCE):
		return (AC_KPM_RESOURCE);
	case mema_eid(EINVAL, AC_ERR_KPM_NOTSUP):
		return (AC_KPM_NOTSUP);
	case mema_eid(EINVAL, AC_ERR_KPM_NOHANDLES):
		return (AC_KPM_NOHANDLES);
	case mema_eid(EINVAL, AC_ERR_KPM_NONRELOC):
		return (AC_KPM_NONRELOC);
	case mema_eid(EINVAL, AC_ERR_KPM_HANDLE):
		return (AC_KPM_HANDLE);
	case mema_eid(EINVAL, AC_ERR_KPM_BUSY):
		return (AC_KPM_BUSY);
	case mema_eid(EINVAL, AC_ERR_KPM_NOTVIABLE):
		return (AC_KPM_NOTVIABLE);
	case mema_eid(EINVAL, AC_ERR_KPM_SEQUENCE):
		return (AC_KPM_SEQUENCE);
	case mema_eid(EINVAL, AC_ERR_KPM_NOWORK):
		return (AC_KPM_NOWORK);
	case mema_eid(EINVAL, AC_ERR_KPM_NOTFINISHED):
		return (AC_KPM_NOTFINISHED);
	case mema_eid(EINVAL, AC_ERR_KPM_NOTRUNNING):
		return (AC_KPM_NOTRUNNING);
	case mema_eid(ENOMEM, AC_ERR_VMEM):
		return (AC_VMEM);
	case mema_eid(EINTR, AC_ERR_INTR):
		return (AC_INTR);
	case mema_eid(EINTR, AC_ERR_TIMEOUT):
		return (AC_TIMEOUT);
	case mema_eid(EINVAL, AC_ERR_MEM_DEINTLV):
		return (AC_DEINTLV);
	default:
		break;
	}

	return (AC_UNKNOWN);
}

static void
mema_err(ac_cfga_cmd_t *ac, int ret_errno, char **errstring, int cmd)
{
	char *cname = mema_str(cmd);
	char *syserr;
	char syserr_num[20];

	if (ac) {
		syserr = mema_str(mema_sid(ret_errno, ac->errtype));
		syserr = dgettext(TEXT_DOMAIN, syserr);
	} else {
		syserr = strerror(ret_errno);
		/* strerror() does its own gettext(). */
		if (syserr == NULL) {
			(void) sprintf(syserr_num, "errno=%d", errno);
			syserr = syserr_num;
		}
	}

	__fmt_errstring(errstring, strlen(syserr),
	    dgettext(TEXT_DOMAIN, cname), syserr);
}

static void
mema_cmd_init(ac_cfga_cmd_t *ac, void *cmd, char *outputstr, int force)
{
	(void) memset((void *)ac, 0, sizeof (*ac));

	ac->errtype = AC_ERR_DEFAULT;
	ac->private = cmd;
	ac->force = force;
	ac->outputstr = outputstr;

	(void) memset((void *)outputstr, 0, AC_OUTPUT_LEN);
}

static int
ap_bk_idx(const char *ap_id)
{
	int id;
	char *s;
	static char *bank = "bank";

	DBG("ap_bk_idx(%s)\n", ap_id);

	if ((s = strstr(ap_id, bank)) == NULL)
		return (-1);
	else {
		int n;

		s += strlen(bank);
		n = strlen(s);

		DBG3("ap_bk_idx: s=%s, n=%d\n", s, n);

		if ((n != 1) || !isdigit(s[0]))
			return (-1);
	}

	id = atoi(s);

	if (id < 0 || id > 1)
		return (-1);

	DBG3("ap_bk_idx(%s)=%d\n", s, id);

	return (id);
}

static cfga_err_t
ap_stat(
	const char *bank_spec,
	int *fdp,
	mema_bank_t *bkp,
	ac_stat_t *stp,
	char **errstring)
{
	int fd;
	int ret, ret_errno;
	int bank;
	mema_bank_t bk;
	ac_stat_t stat;
	ac_cfga_cmd_t cmd;
	char outputstr[AC_OUTPUT_LEN];

	if ((bank = ap_bk_idx(bank_spec)) == -1) {
		__fmt_errstring(errstring, strlen(bank_spec),
		    dgettext(TEXT_DOMAIN, ap_invalid), bank_spec);
		return (CFGA_ERROR);
	}

	bk.bank = bank;

	if ((fd = open(bank_spec, ((fdp != NULL) ? O_RDWR : O_RDONLY), 0)) ==
	    -1) {
		char *syserr;
		char syserr_num[20];

		syserr = strerror(errno);
		if (syserr == NULL) {
			(void) sprintf(syserr_num, "errno=%d", errno);
			syserr = syserr_num;
		}
		__fmt_errstring(errstring, strlen(syserr) +
		    strlen(bank_spec),
		    dgettext(TEXT_DOMAIN, open_failed), bank_spec, syserr);
		return (CFGA_ERROR);
	}

	mema_cmd_init(&cmd, &stat, outputstr, 0);
	dump_ioctl(AC_MEM_STAT, NULL);
	ret = ioctl(fd, AC_MEM_STAT, &cmd);
	ret_errno = errno;
	dump_ioctl_res(AC_MEM_STAT, &stat, ret, ret_errno);

	if (ret == -1) {
		mema_err(&cmd, ret_errno, errstring, CMD_MEM_STAT);
		(void) close(fd);
		return (CFGA_ERROR);
	}

	if (fdp)
		*fdp = fd;
	else
		(void) close(fd);

	if (stp)
		*stp = stat;

	if (bkp) {
		bkp->bank = bk.bank;
		bkp->board = stat.board;
	}

	return (CFGA_OK);
}

static void
set_disabled_bits(mema_disabled_t *dp, int value)
{
	if (value == 0)
		*dp &= ~PROM_MEMORY_DISABLED;
	else
		*dp |= PROM_MEMORY_DISABLED;
}

static void
set_present_bits(mema_disabled_t *dp, ac_stat_t *asp)
{
	if (asp->ostate == SYSC_CFGA_OSTATE_CONFIGURED)
		*dp |= PROM_MEMORY_PRESENT;
	else
		*dp &= ~PROM_MEMORY_DISABLED;
}

static cfga_err_t
prom_do_options(
	option_set_t do_option,
	int board,
	ac_stat_t *asp,
	char **errstring)
{
	cfga_err_t ret;
	mema_disabled_t disab;

	if (!prom_read_disabled_list(&disab, board))
		return (CFGA_ERROR);

	set_present_bits(&disab, asp);

	ret = CFGA_OK;

	if (OPTSET_TEST(do_option, OPT_BOOT_ENABLE)) {
		set_disabled_bits(&disab, 0);
		if (!prom_viable_disabled_list(&disab)) {
			__fmt_errstring(errstring, 0,
			    dgettext(TEXT_DOMAIN, dlist_invalid));
			ret = CFGA_ERROR;
		} else if (!prom_write_disabled_list(&disab, board)) {
			__fmt_errstring(errstring, 0,
			    dgettext(TEXT_DOMAIN, dlist_write_failed));
			ret = CFGA_ERROR;
		}
	} else if (OPTSET_TEST(do_option, OPT_BOOT_DISABLE)) {
		set_disabled_bits(&disab, 1);
		if (!prom_viable_disabled_list(&disab)) {
			__fmt_errstring(errstring, 0,
			    dgettext(TEXT_DOMAIN, dlist_invalid));
			ret = CFGA_ERROR;
		} else if (!prom_write_disabled_list(&disab, board)) {
			__fmt_errstring(errstring, 0,
			    dgettext(TEXT_DOMAIN, dlist_write_failed));
			ret = CFGA_ERROR;
		}
	}

	return (ret);
}

static cfga_err_t
mema_add(
	const char *bank_spec,
	const char *options,
	char **errstring,
	int force)
{
	mema_bank_t bk;
	int fd, ret, ret_errno;
	option_set_t do_option;
	ac_cfga_cmd_t cmd;
	ac_stat_t stat;
	char outputstr[AC_OUTPUT_LEN];

	ret = 0;
	do_option = process_options(options, add_opts, &ret, errstring);
	if (ret != 0) {
		return (ret);
	}

	ret = ap_stat(bank_spec, &fd, &bk, &stat, errstring);
	if (ret != CFGA_OK)
		return (ret);


	if (stat.rstate != SYSC_CFGA_RSTATE_CONNECTED ||
	    stat.ostate != SYSC_CFGA_OSTATE_UNCONFIGURED) {
		__fmt_errstring(errstring, 0,
		    dgettext(TEXT_DOMAIN, trans_illegal));
		(void) close(fd);
		return (CFGA_ERROR);
	}

	if (!force) {
		mema_disabled_t disab;

		if (prom_read_disabled_list(&disab, bk.board)) {
			if (disab != 0 &&
			    !OPTSET_TEST(do_option, OPT_BOOT_ENABLE)) {
				__fmt_errstring(errstring, 0,
				    dgettext(TEXT_DOMAIN, add_is_disabled));
				(void) close(fd);
				return (CFGA_ERROR);
			}
			if (disab == 0 &&
			    OPTSET_TEST(do_option, OPT_BOOT_DISABLE)) {
				__fmt_errstring(errstring, 0,
				    dgettext(TEXT_DOMAIN, add_willbe_disabled));
				(void) close(fd);
				return (CFGA_ERROR);
			}
		} else {
			__fmt_errstring(errstring, 0,
			    dgettext(TEXT_DOMAIN, add_disab_err));
			(void) close(fd);
			return (CFGA_ERROR);
		}
	}

	mema_cmd_init(&cmd, NULL, outputstr, force);
	dump_ioctl(AC_MEM_CONFIGURE, NULL);
	ret = ioctl(fd, AC_MEM_CONFIGURE, &cmd);
	ret_errno = errno;
	dump_ioctl_res(AC_MEM_CONFIGURE, NULL, ret, ret_errno);
	(void) close(fd);

	if (ret == -1) {
		mema_err(&cmd, ret_errno, errstring, CMD_MEM_ADD);
		return (CFGA_ERROR);
	}

	ret = prom_do_options(do_option, bk.board, &stat, errstring);

	return (ret);
}

static cfga_err_t
mema_delete(
	const char *bank_spec,
	const char *options,
	char **errstring,
	int force)
{
	mema_bank_t bk;
	int fd, ret, ret_errno;
	option_set_t do_option;
	ac_cfga_cmd_t cmd;
	ac_stat_t stat;
	char outputstr[AC_OUTPUT_LEN];
	int timeout_secs = -1;	/* Init to 'use default'. */

	ret = 0;
	do_option = process_options(options, del_opts, &ret, errstring);
	if (ret != 0) {
		return (ret);
	}

	if (OPTSET_TEST(do_option, OPT_TIMEOUT)) {
		char *to_val;
		char *ep;

		to_val = OPTSET_VAL(do_option, OPT_TIMEOUT);
		timeout_secs = (int)strtol(to_val, &ep, 10);
		if (*ep != '\0' || ep == to_val || timeout_secs < 0) {
			__fmt_errstring(errstring, strlen(to_val),
			    dgettext(TEXT_DOMAIN, timeout_notnum), to_val);
			return (CFGA_ERROR);
		}
	}

	ret = ap_stat(bank_spec, &fd, &bk, &stat, errstring);
	if (ret != CFGA_OK)
		return (ret);

	if (stat.rstate != SYSC_CFGA_RSTATE_CONNECTED ||
	    stat.ostate != SYSC_CFGA_OSTATE_CONFIGURED) {
		__fmt_errstring(errstring, 0,
		    dgettext(TEXT_DOMAIN, trans_illegal));
		(void) close(fd);
		return (CFGA_ERROR);
	}

	mema_cmd_init(&cmd, NULL, outputstr, force);
	cmd.arg = timeout_secs;
	dump_ioctl(AC_MEM_UNCONFIGURE, NULL);
	ret = ioctl(fd, AC_MEM_UNCONFIGURE, &cmd);
	ret_errno = errno;
	dump_ioctl_res(AC_MEM_UNCONFIGURE, NULL, ret, ret_errno);
	(void) close(fd);

	if (ret == -1) {
		mema_err(&cmd, ret_errno, errstring, CMD_MEM_DEL);
		return (CFGA_ERROR);
	}

	ret = prom_do_options(do_option, bk.board, &stat, errstring);

	return (ret);
}

/*ARGSUSED*/
cfga_err_t
cfga_change_state(
	cfga_cmd_t state_change_cmd,
	const char *ap_id,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	int force;
	cfga_err_t rc;

	if (errstring != NULL)
		*errstring = NULL;

	force = flags & CFGA_FLAG_FORCE;

	switch (state_change_cmd) {
	case CFGA_CMD_CONFIGURE:
		rc =  mema_add(ap_id, options, errstring, force);
		break;

	case CFGA_CMD_UNCONFIGURE:
		rc =  mema_delete(ap_id, options, errstring, force);
		break;

	default:
		rc = CFGA_OPNOTSUPP;
		break;
	}

	return (rc);
}

/*ARGSUSED*/
cfga_err_t
cfga_private_func(
	const char *function,
	const char *ap_id,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	mema_bank_t bk;
	ac_stat_t stat;
	int fd, ret, ret_errno;
	ac_cfga_cmd_t cmd;
	char outputstr[AC_OUTPUT_LEN];

	if (errstring != NULL)
		*errstring = NULL;

	ret = ap_stat(ap_id, &fd, &bk, &stat, errstring);
	if (ret != CFGA_OK)
		return (ret);

	if (strcmp(function, "relocate-test") == 0) {
		struct ac_memx_relocate_stats rstat;

		mema_cmd_init(&cmd, NULL, outputstr,
		    (flags & CFGA_FLAG_FORCE));
		cmd.arg = AC_MEMX_RELOCATE_ALL;
		cmd.private = &rstat;
		(void) memset((void *)&rstat, 0, sizeof (rstat));
		dump_ioctl(AC_MEM_EXERCISE, &cmd);
		ret = ioctl(fd, AC_MEM_EXERCISE, &cmd);
		ret_errno = errno;
		dump_ioctl_res(AC_MEM_EXERCISE, &cmd, ret, ret_errno);
		(void) close(fd);

		if (ret == -1) {
			mema_err(&cmd, ret_errno, errstring, CMD_MEM_RELOCTEST);
			return (CFGA_ERROR);
		}
		return (CFGA_OK);
	}

	__fmt_errstring(errstring, strlen(function),
	    dgettext(TEXT_DOMAIN, pfunc_unknown), function);

	return (CFGA_ERROR);
}

static int
mtest_run(
	int fd,
	int test_fun,
	mema_bank_t *abkp,
	struct cfga_msg *msgp,
	char **errstring,
	ulong_t max_errors)
{
	ac_mem_test_start_t test_start;
	ac_mem_test_stop_t test_stop;
	struct mtest_handle handle;
	int ret, ret_errno;
	int res;
	ac_cfga_cmd_t cmd;
	char outputstr[AC_OUTPUT_LEN];

	(void) memset((void *)&test_start, 0, sizeof (test_start));
	mema_cmd_init(&cmd, &test_start, outputstr, 0);
	dump_ioctl(AC_MEM_TEST_START, &test_start);
	ret = ioctl(fd, AC_MEM_TEST_START, &cmd);
	ret_errno = errno;
	dump_ioctl_res(AC_MEM_TEST_START, &test_start, ret, ret_errno);

	if (ret == -1) {
		if (ret_errno == ENOTSUP) {
			mema_err(&cmd, ret_errno, errstring,
			    CMD_MEM_TEST_START);
			return (CFGA_OPNOTSUPP);
		}
		if (ret_errno == EBUSY && test_start.tester_pid > 0) {
			/*
			 * Bank appears to be being tested.  Check that
			 * process 'tester_pid' is still running.
			 */
			if (kill(test_start.tester_pid, 0) != -1 ||
			    errno != ESRCH) {
				cfga_ap_log_id_t bname;

				/* Process still exists. */
				(void) sprintf(bname, "board %d bank%d",
				    abkp->board, abkp->bank);
				__fmt_errstring(errstring, strlen(bname),
				    dgettext(TEXT_DOMAIN, still_testing),
				    bname, test_start.tester_pid);
				return (CFGA_ERROR);
			}
			/*
			 * Do a test stop and re-try the start.
			 */
			(void) memset((void *)&test_stop, 0,
			    sizeof (test_stop));
			test_stop.handle = test_start.handle;
			test_stop.condition = SYSC_CFGA_COND_UNKNOWN;
			mema_cmd_init(&cmd, &test_stop, outputstr, 0);
			dump_ioctl(AC_MEM_TEST_STOP, &test_stop);
			ret = ioctl(fd, AC_MEM_TEST_STOP, &cmd);
			ret_errno = errno;
			dump_ioctl_res(AC_MEM_TEST_STOP, &test_stop,
			    ret, ret_errno);
			/*
			 * Ignore test stop error processing and re-try the
			 * start.  The error return will be derived from the
			 * result of start.
			 */
			(void) memset((void *)&test_start, 0,
			    sizeof (test_start));
			mema_cmd_init(&cmd, &test_start, outputstr, 0);
			dump_ioctl(AC_MEM_TEST_START, &test_start);
			ret = ioctl(fd, AC_MEM_TEST_START, &cmd);
			ret_errno = errno;
			dump_ioctl_res(AC_MEM_TEST_START, &test_start,
			    ret, ret_errno);
		}
		/* Test return code again to cover the case of a re-try. */
		if (ret == -1) {
			mema_err(&cmd, ret_errno, errstring,
			    CMD_MEM_TEST_START);
			return (CFGA_ERROR);
		}
	}
	(void) memset((void *)&handle, 0, sizeof (handle));
	handle.fd = fd;
	handle.drvhandle = (void *)&test_start;
	handle.msgp = msgp;
	handle.bank_size = test_start.bank_size;
	handle.page_size = test_start.page_size;
	handle.line_size = test_start.line_size;
	handle.lines_per_page = test_start.page_size / test_start.line_size;
	handle.condition = CFGA_COND_UNKNOWN;
	handle.max_errors = max_errors;

	res = (*mtest_table[test_fun].test_func)(&handle);

	mtest_deallocate_buf_all(&handle);

	/*
	 * Convert memory test code to MEMA_ code.
	 */
	switch (res) {
	case MTEST_DONE:
		res = CFGA_OK;
		break;
	case MTEST_LIB_ERROR:
		__fmt_errstring(errstring, 0, dgettext(TEXT_DOMAIN,
		    mtest_lib_error));
		res = CFGA_ERROR;
		break;
	case MTEST_DEV_ERROR:
		__fmt_errstring(errstring, 0, dgettext(TEXT_DOMAIN,
		    mtest_rw_error));
		res = CFGA_ERROR;
		break;
	default:
		__fmt_errstring(errstring, 0, dgettext(TEXT_DOMAIN,
		    mtest_unknown_error));
		res = CFGA_ERROR;
		assert(0);
		break;
	}

	(void) memset((void *)&test_stop, 0, sizeof (test_stop));
	test_stop.handle = test_start.handle;
	switch (handle.condition) {
	case CFGA_COND_OK:
		test_stop.condition = SYSC_CFGA_COND_OK;
		break;
	case CFGA_COND_FAILING:
		test_stop.condition = SYSC_CFGA_COND_FAILING;
		break;
	case CFGA_COND_FAILED:
		test_stop.condition = SYSC_CFGA_COND_FAILED;
		break;
	case CFGA_COND_UNKNOWN:
		test_stop.condition = SYSC_CFGA_COND_UNKNOWN;
		break;
	default:
		test_stop.condition = SYSC_CFGA_COND_UNKNOWN;
		assert(0);
		break;
	}

	mema_cmd_init(&cmd, &test_stop, outputstr, 0);
	dump_ioctl(AC_MEM_TEST_STOP, &test_stop);
	ret = ioctl(fd, AC_MEM_TEST_STOP, &cmd);
	ret_errno = errno;
	dump_ioctl_res(AC_MEM_TEST_STOP, &test_stop, ret, ret_errno);
	if (ret == -1) {
		mema_err(&cmd, ret_errno, errstring,
		    CMD_MEM_TEST_STOP);
		return (CFGA_ERROR);
	}
	return (res);
}

#define	DRVHANDLE(H)	(((ac_mem_test_start_t *)(H)->drvhandle)->handle)

int
mtest_write(
	mtest_handle_t handle,
	void *page_buf,
	u_longlong_t page_no,
	uint_t line_offset,
	uint_t line_count)
{
	ac_mem_test_write_t test_write;
	int fd, ret, ret_errno;
	ac_cfga_cmd_t cmd;
	char outputstr[AC_OUTPUT_LEN];

	(void) memset((void *)&test_write, 0, sizeof (test_write));
	fd = handle->fd;
	test_write.handle = DRVHANDLE(handle);
	test_write.page_buf = page_buf;
	test_write.address.page_num = page_no;
	test_write.address.line_offset = line_offset;
	if (line_count == 0)
		test_write.address.line_count = handle->lines_per_page;
	else
		test_write.address.line_count = line_count;

	mema_cmd_init(&cmd, &test_write, outputstr, 0);
	dump_ioctl(AC_MEM_TEST_WRITE, &test_write);
	ret = ioctl(fd, AC_MEM_TEST_WRITE, &cmd);
	ret_errno = errno;
	dump_ioctl_res(AC_MEM_TEST_WRITE, &test_write, ret, ret_errno);

	if (ret == -1)
		return (-1);
	return (0);
}

int
mtest_read(
	mtest_handle_t handle,
	void *page_buf,
	u_longlong_t page_no,
	uint_t line_offset,
	uint_t line_count,
	struct mtest_error *errp)
{
	ac_mem_test_read_t test_read;
	sunfire_processor_error_regs_t errbuf;
	int fd, ret, ret_errno;
	ac_cfga_cmd_t cmd;
	char outputstr[AC_OUTPUT_LEN];

	(void) memset((void *)&test_read, 0, sizeof (test_read));
	(void) memset((void *)&errbuf, 0, sizeof (errbuf));
	fd = handle->fd;
	test_read.handle = DRVHANDLE(handle);
	test_read.page_buf = page_buf;
	test_read.address.page_num = page_no;
	test_read.address.line_offset = line_offset;
	test_read.error_buf =  &errbuf;
	if (line_count == 0)
		test_read.address.line_count = handle->lines_per_page;
	else
		test_read.address.line_count = line_count;

	mema_cmd_init(&cmd, &test_read, outputstr, 0);
	dump_ioctl(AC_MEM_TEST_READ, &test_read);
	ret = ioctl(fd, AC_MEM_TEST_READ, &cmd);
	ret_errno = errno;
	dump_ioctl_res(AC_MEM_TEST_READ, &test_read, ret, ret_errno);

	if (ret == -1) {
		if (ret_errno == EIO) {
			/*
			 * Special case indicating CE or UE.
			 */
			if (((errbuf.udbh_error_reg | errbuf.udbl_error_reg) &
			    P_DER_UE) != 0)
				errp->error_type = MTEST_ERR_UE;
			else
				errp->error_type = MTEST_ERR_CE;
		} else {
			return (-1);
		}
	} else {
		errp->error_type = MTEST_ERR_NONE;
	}
	return (0);
}

static char *
subopt_help_str(char *opts[])
{
	char *str;
	const char *sep;
	int len;
	int i, n;
	static const char help_sep[] = ", ";
	static const char help_nil[] = "???";

	len = 0;
	n = 0;
	for (i = 0; opts[i] != NULL; i++) {
		n++;
		len += strlen(opts[i]);
	}
	if (n == 0)
		return (strdup(help_nil));
	len += (n - 1) * strlen(help_sep);
	len++;
	str = (char *)malloc(len);
	if (str == NULL)
		return (NULL);
	*str = '\0';
	sep = "";
	for (i = 0; opts[i] != NULL; i++) {
		(void) strcat(str, sep);
		(void) strcat(str, opts[i]);
		sep = help_sep;
	}
	return (str);
}

/*ARGSUSED*/
cfga_err_t
cfga_test(
	const char *ap_id,
	const char *options,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	mema_bank_t bk;
	ac_stat_t stat;
	int test_fun = -1;
	int fd, ret;
	int maxerr_idx;
	long max_errors = -1;
	char *ret_p;

	if (errstring != NULL)
		*errstring = NULL;

	/*
	 * Decode test level and max error number.
	 */
	if (options != NULL && *options != '\0') {
		char **opts;
		char *value;
		char *cp, *free_cp;
		int subopt;

		/* getsubopt() modifies the input string, so copy it. */
		cp = strdup(options);
		if (cp == NULL) {
			return (CFGA_LIB_ERROR);
		}
		free_cp = cp;
		opts = mtest_build_opts(&maxerr_idx);
		if (opts == NULL) {
			free((void *)free_cp);
			return (CFGA_LIB_ERROR);
		}

		while (*cp != '\0') {
			subopt = getsubopt(&cp, opts, &value);
			if (subopt == -1) {
				char *hlp;

				hlp = subopt_help_str(opts);
				if (hlp != NULL) {
					__fmt_errstring(errstring,
					    strlen(value) + strlen(hlp),
					    dgettext(TEXT_DOMAIN, unk_test),
					    value, hlp);
					free((void *)hlp);
				} else {
					__fmt_errstring(errstring, 20,
					    dgettext(TEXT_DOMAIN, calloc_fail),
					    strlen(options) + 1, 1);
				}
				/* Free after printing value. */
				free((void *)free_cp);
				return (CFGA_ERROR);
			}

			if (test_fun != -1 && subopt != test_fun &&
			    subopt != maxerr_idx) {
				__fmt_errstring(errstring,
				    strlen(opts[subopt]),
				    dgettext(TEXT_DOMAIN, dup_test),
				    opts[subopt]);
				free((void *)free_cp);
				return (CFGA_ERROR);
			}

			if (subopt < maxerr_idx)
				test_fun = subopt;
			else {

				if (max_errors != -1 && subopt == maxerr_idx) {
					__fmt_errstring(errstring,
					    strlen(opts[subopt]),
					    dgettext(TEXT_DOMAIN, dup_num),
					    opts[subopt]);
					free((void *)free_cp);
					return (CFGA_ERROR);
				}

				if (value == NULL) {
					__fmt_errstring(errstring,
					    0,
					    dgettext(TEXT_DOMAIN, no_num),
					    "");
					free((void *)free_cp);
					return (CFGA_ERROR);
				}

				max_errors = strtol(value, &ret_p, 10);
				if ((ret_p == value) || (*ret_p != '\0') ||
				    (max_errors < 0)) {
					__fmt_errstring(errstring,
					    strlen(value),
					    dgettext(TEXT_DOMAIN, no_num),
					    value);
					free((void *)free_cp);
					return (CFGA_ERROR);
				}
			}
		}
		free((void *)free_cp);
	}

	if (test_fun == -1)
		test_fun = MTEST_DEFAULT_TEST;
	if (max_errors == -1)
		max_errors = MAX_ERRORS;

	ret = ap_stat(ap_id, &fd, &bk, &stat, errstring);
	if (ret != CFGA_OK)
		return (ret);

	if (stat.rstate != SYSC_CFGA_RSTATE_CONNECTED ||
	    stat.ostate != SYSC_CFGA_OSTATE_UNCONFIGURED) {
		__fmt_errstring(errstring, 0,
		    dgettext(TEXT_DOMAIN, trans_illegal));
		(void) close(fd);
		return (CFGA_ERROR);
	}

	ret = mtest_run(fd, test_fun, &bk,
	    ((flags & CFGA_FLAG_VERBOSE) != 0) ? msgp : NULL, errstring,
	    (ulong_t)max_errors);

	(void) close(fd);

	return (ret);
}

static cfga_stat_t
rstate_cvt(sysc_cfga_rstate_t rs)
{
	cfga_stat_t cs;

	switch (rs) {
	case SYSC_CFGA_RSTATE_EMPTY:
		cs = CFGA_STAT_EMPTY;
		break;
	case SYSC_CFGA_RSTATE_DISCONNECTED:
		cs = CFGA_STAT_DISCONNECTED;
		break;
	case SYSC_CFGA_RSTATE_CONNECTED:
		cs = CFGA_STAT_CONNECTED;
		break;
	default:
		cs = CFGA_STAT_NONE;
		break;
	}

	return (cs);
}

static cfga_stat_t
ostate_cvt(sysc_cfga_ostate_t os)
{
	cfga_stat_t cs;

	switch (os) {
	case SYSC_CFGA_OSTATE_UNCONFIGURED:
		cs = CFGA_STAT_UNCONFIGURED;
		break;
	case SYSC_CFGA_OSTATE_CONFIGURED:
		cs = CFGA_STAT_CONFIGURED;
		break;
	default:
		cs = CFGA_STAT_NONE;
		break;
	}

	return (cs);
}

static cfga_cond_t
cond_cvt(sysc_cfga_cond_t sc)
{
	cfga_cond_t cc;

	switch (sc) {
	case SYSC_CFGA_COND_OK:
		cc = CFGA_COND_OK;
		break;
	case SYSC_CFGA_COND_FAILING:
		cc = CFGA_COND_FAILING;
		break;
	case SYSC_CFGA_COND_FAILED:
		cc = CFGA_COND_FAILED;
		break;
	case SYSC_CFGA_COND_UNUSABLE:
		cc = CFGA_COND_UNUSABLE;
		break;
	case SYSC_CFGA_COND_UNKNOWN:
	default:
		cc = CFGA_COND_UNKNOWN;
		break;
	}

	return (cc);
}

static void
info_set(ac_stat_t *asp, mema_bank_t *bkp, cfga_info_t info)
{
	mema_disabled_t disab;
	uint_t board;
	uint_t n;
	u_longlong_t decode;
	uint_t intlv;
	char *f;
	char *end;

	end = &info[sizeof (cfga_info_t)];
	*info = '\0';

	board = bkp->board;

	/* Print the board number in a way that matches the sysctrl AP. */
	info += snprintf(info, end - info, "slot%d", board);

	if (asp->real_size == 0) {
		info += snprintf(info, end - info, " empty");
		return;
	}

	if ((n = asp->real_size) >= 1024) {
		n /= 1024;
		f = "Gb";
	} else
		f = "Mb";
	info += snprintf(info, end - info, " %d%s", n, f);

	if (asp->rstate == SYSC_CFGA_RSTATE_CONNECTED &&
	    asp->ostate == SYSC_CFGA_OSTATE_CONFIGURED &&
	    asp->use_size != asp->real_size) {
		if ((n = asp->use_size) >= 1024) {
			n /= 1024;
			f = "Gb";
		} else
			f = "Mb";
		info += snprintf(info, end - info, " (%d%s used)", n, f);
	}

	if (bkp->bank == 0)
		decode = asp->ac_decode0;
	else
		decode = asp->ac_decode1;

	info += snprintf(info, end - info, " base 0x%llx",
	    GRP_REALBASE(decode));

	if (bkp->bank == 0)
		intlv = INTLV0(asp->ac_memctl);
	else
		intlv = INTLV1(asp->ac_memctl);

	if (intlv != 1)
		info += snprintf(info, end - info, " interleaved %u-way",
		    intlv);

	if (prom_read_disabled_list(&disab, board)) {
		if (disab != 0) {
			info += snprintf(info, end - info, " disabled at boot");
		}

	}

	if (asp->rstate == SYSC_CFGA_RSTATE_CONNECTED &&
	    asp->ostate == SYSC_CFGA_OSTATE_CONFIGURED &&
	    asp->nonrelocatable)
		info += snprintf(info, end - info, " permanent");
}

static void
mema_cvt(ac_stat_t *ac, mema_bank_t *bkp, cfga_stat_data_t *cs)
{
	(void) strcpy(cs->ap_type, "memory");
	cs->ap_r_state = rstate_cvt(ac->rstate);
	cs->ap_o_state = ostate_cvt(ac->ostate);
	cs->ap_cond = cond_cvt(ac->condition);
	cs->ap_busy = (cfga_busy_t)ac->busy;
	cs->ap_status_time = ac->status_time;
	info_set(ac, bkp, cs->ap_info);
	cs->ap_log_id[0] = '\0';
	cs->ap_phys_id[0] = '\0';
}

/*ARGSUSED*/
cfga_err_t
cfga_stat(
	const char *ap_id,
	struct cfga_stat_data *cs,
	const char *options,
	char **errstring)
{
	int ret;
	mema_bank_t bk;
	ac_stat_t stat;
	option_set_t do_option;

	if (errstring != NULL)
		*errstring = NULL;

	ret = 0;
	do_option = process_options(options, stat_opts, &ret, errstring);
	if (ret != 0)
		return (ret);

	ret = ap_stat(ap_id, NULL, &bk, &stat, errstring);
	if (ret != CFGA_OK)
		return (ret);

	mema_cvt(&stat, &bk, cs);

	ret = prom_do_options(do_option, bk.board, &stat, errstring);

	return (ret);
}

/*ARGSUSED*/
cfga_err_t
cfga_list(
	const char *ap_id,
	cfga_stat_data_t **ap_list,
	int *nlist,
	const char *options,
	char **errstring)
{
	if (errstring != NULL)
		*errstring = NULL;

	return (CFGA_NOTSUPP);
}

/*
 * cfga_ap_id_cmp -- use default_ap_id_cmp() in libcfgadm
 */

/*ARGSUSED*/
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{


	(*msgp->message_routine)(msgp->appdata_ptr, mema_help);
	(*msgp->message_routine)(msgp->appdata_ptr, disable_opts);
	(*msgp->message_routine)(msgp->appdata_ptr, enable_opts);
	(*msgp->message_routine)(msgp->appdata_ptr, timeout_opts);
	(*msgp->message_routine)(msgp->appdata_ptr, test_opts);
	(*msgp->message_routine)(msgp->appdata_ptr, private_funcs);

	return (CFGA_OK);
}

#if 0
static ac_mem_version_t
get_version(int fd)
{
	ac_mem_version_t ver;
	int ret, ret_errno;

	ver = 0;
	dump_ioctl(AC_MEM_ADMIN_VER, &ver);
	ret = ioctl(fd, AC_MEM_ADMIN_VER, &ver);
	ret_errno = errno;
	dump_ioctl_res(AC_MEM_ADMIN_VER, &ver, ret, ret_errno);
	return (ver);
}
#endif

static char *
opt_help_str(struct opt_control *opts)
{
	char *str;
	const char *sep;
	int len;
	int i, n;
	static const char help_sep[] = ", ";
	static const char help_nil[] = "???";

	len = 0;
	n = 0;
	for (i = 0; opts[i].subopt != -1; i++) {
		n++;
		len += strlen(mema_opts[opts[i].subopt]);
	}
	if (n == 0)
		return (strdup(help_nil));
	len += (n - 1) * strlen(help_sep);
	len++;
	str = (char *)malloc(len);
	if (str == NULL)
		return (NULL);
	*str = '\0';
	sep = "";
	for (i = 0; opts[i].subopt != -1; i++) {
		(void) strcat(str, sep);
		(void) strcat(str, mema_opts[opts[i].subopt]);
		sep = help_sep;
	}
	return (str);
}

static option_set_t
process_options(
	const char *options,
	struct opt_control *opts,
	int *retp,
	char **errstring)
{
	option_set_t opt_set;
	char *optcopy, *optcopy_alloc;
	char *value;
	int subopt;
	int subopt_err;
	int i;
	int group;
	int need_value;

	OPTSET_INIT(opt_set);

	if (options == NULL || *options == '\0') {
		return (opt_set);
	}

	optcopy = optcopy_alloc = strdup(options);
	if (optcopy_alloc == NULL) {
		__fmt_errstring(errstring, 20,
		    dgettext(TEXT_DOMAIN, calloc_fail), strlen(options) + 1, 1);
		*retp = CFGA_LIB_ERROR;
		return (opt_set);
	}

	subopt_err = 0;
	while (*optcopy != '\0' && subopt_err == 0) {
		subopt = getsubopt(&optcopy, mema_opts, &value);
		if (subopt == -1) {
			char *hlp;

			hlp = opt_help_str(opts);
			__fmt_errstring(errstring, strlen(value) + strlen(hlp),
			    dgettext(TEXT_DOMAIN, unk_subopt), value, hlp);
			free((void *)hlp);
			subopt_err = 1;
			break;
		}
		for (i = 0; opts[i].subopt != -1; i++) {
			if (opts[i].subopt == subopt) {
				group = opts[i].group;
				break;
			}
		}
		if (opts[i].subopt == -1) {
			char *hlp;

			hlp = opt_help_str(opts);
			__fmt_errstring(errstring,
			    MAX_OPT_LENGTH + strlen(hlp),
			    dgettext(TEXT_DOMAIN, not_valid),
			    mema_opts[subopt], hlp);
			free((void *)hlp);
			subopt_err = 1;
			break;
		}
		need_value = OPT_NEEDS_VALUE(subopt);
		if (!need_value && value != NULL) {
			__fmt_errstring(errstring, MAX_OPT_LENGTH,
			    dgettext(TEXT_DOMAIN, no_value),
			    mema_opts[subopt]);
			subopt_err = 1;
			break;
		}
		if (need_value && value == NULL) {
			__fmt_errstring(errstring, MAX_OPT_LENGTH,
			    dgettext(TEXT_DOMAIN, missing_value),
			    mema_opts[subopt]);
			subopt_err = 1;
			break;
		}
		if (OPTSET_TEST(opt_set, subopt)) {
			/* Ignore repeated options. */
			continue;
		}
		if (group != 0 && !OPTSET_IS_EMPTY(opt_set)) {
			for (i = 0; opts[i].subopt != -1; i++) {
				if (i == subopt)
					continue;
				if (opts[i].group == group &&
				    OPTSET_TEST(opt_set, opts[i].subopt))
					break;
			}
			if (opts[i].subopt != -1) {
				__fmt_errstring(errstring, MAX_OPT_LENGTH * 2,
				    dgettext(TEXT_DOMAIN, conflict_opt),
				    mema_opts[subopt],
				    mema_opts[opts[i].subopt]);
				subopt_err = 1;
				break;
			}
		}
		OPTSET_SET_VAL(opt_set, subopt, value);
	}
	free((void *)optcopy_alloc);
	if (subopt_err) {
		*retp = CFGA_ERROR;
	}

	return (opt_set);
}

#ifdef DEV_DEBUG

static int
debugging(void)
{
	char *ep;
	static int inited;

	if (inited)
		return (debug_fp != NULL);
	inited = 1;

	if ((ep = getenv("MEMADM_DEBUG")) == NULL) {
		return (0);
	}
	if (*ep == '\0')
		debug_fp = stderr;
	else {
		if ((debug_fp = fopen(ep, "a")) == NULL)
			return (0);
	}
	(void) fprintf(debug_fp, "\nDebug started, pid=%d\n", (int)getpid());
	return (1);
}

static void
dump_ioctl(
	int cmd,
	void *arg)
{
	if (!debugging())
		return;

	switch (cmd) {
	case AC_MEM_CONFIGURE:
		(void) fprintf(debug_fp, "IOCTL: AC_MEM_CONFIGURE\n");
		break;

	case AC_MEM_UNCONFIGURE:
		(void) fprintf(debug_fp, "IOCTL: AC_MEM_UNCONFIGURE\n");
		break;

	case AC_MEM_TEST_START:
		(void) fprintf(debug_fp, "IOCTL: AC_MEM_TEST_START\n");
		break;

	case AC_MEM_TEST_STOP: {
		ac_mem_test_stop_t *tstop;

		tstop = (ac_mem_test_stop_t *)arg;
		(void) fprintf(debug_fp, "IOCTL: AC_MEM_TEST_STOP handle=%#x "
		    "condition=%d\n", tstop->handle, tstop->condition);
	}
		break;
	case AC_MEM_TEST_READ: {
		ac_mem_test_read_t *tread;

		tread = (ac_mem_test_read_t *)arg;
		(void) fprintf(debug_fp, "IOCTL: AC_MEM_TEST_READ handle=%#x "
		    "buf=%#p page=%#llx off=%#x count=%#x\n",
		    tread->handle, tread->page_buf,
		    tread->address.page_num,
		    tread->address.line_offset, tread->address.line_count);
	}
		break;
	case AC_MEM_TEST_WRITE: {
		ac_mem_test_write_t *twrite;

		twrite = (ac_mem_test_write_t *)arg;
		(void) fprintf(debug_fp, "IOCTL: AC_MEM_TEST_WRITE handle=%#x "
		    "buf=%#p page=%#llx off=%#x count=%#x\n",
		    twrite->handle, twrite->page_buf,
		    twrite->address.page_num,
		    twrite->address.line_offset, twrite->address.line_count);
	}
		break;
	case AC_MEM_ADMIN_VER:
		(void) fprintf(debug_fp, "IOCTL: AC_MEM_ADMIN_VER:\n");
		break;
	case AC_MEM_STAT:
		(void) fprintf(debug_fp, "IOCTL: AC_MEM_STAT\n");
		break;
	case AC_MEM_EXERCISE: {
		ac_cfga_cmd_t *cmdp;

		cmdp = arg;
		(void) fprintf(debug_fp, "IOCTL: AC_MEM_EXERCISE arg=%d\n",
		    cmdp->arg);
		break;
	}
	default:
		(void) fprintf(debug_fp, "IOCTL: unknown (%#x)\n", cmd);
		break;
	}
	(void) fflush(debug_fp);
}

static void
dump_ioctl_res(
	int cmd,
	void *arg,
	int ret,
	int ret_errno)
{
	if (!debugging())
		return;

	if (ret == -1) {
		(void) fprintf(debug_fp, "IOCTL failed, \"%s\" (errno=%d)\n",
		    strerror(ret_errno), ret_errno);
		(void) fflush(debug_fp);
		return;
	} else {
		(void) fprintf(debug_fp, "IOCTL succeeded, ret=%d\n", ret);
	}

	switch (cmd) {
	case AC_MEM_CONFIGURE:
	case AC_MEM_UNCONFIGURE:
		break;
	case AC_MEM_TEST_START: {
		ac_mem_test_start_t *tstart;

		tstart = (ac_mem_test_start_t *)arg;
		(void) fprintf(debug_fp, "    handle=%#x tester_pid=%d "
		    "prev_condition=%d bank_size=%#llx "
		    "page_size=%#x line_size=%#x afar_base=%#llx\n",
		    tstart->handle, (int)tstart->tester_pid,
		    tstart->prev_condition,
		    tstart->bank_size, tstart->page_size,
		    tstart->line_size, tstart->afar_base);
	}
		break;
	case AC_MEM_TEST_STOP:
		break;
	case AC_MEM_TEST_READ: {
		ac_mem_test_read_t *tread;
		sunfire_processor_error_regs_t *err;

		tread = (ac_mem_test_read_t *)arg;
		err = tread->error_buf;
		if (ret_errno == EIO) {
			(void) fprintf(debug_fp, "module_id=%#llx afsr=%#llx "
			    "afar=%#llx udbh_error_reg=%#llx "
			    "udbl_error_reg=%#llx\n",
			    (longlong_t)err->module_id, (longlong_t)err->afsr,
			    (longlong_t)err->afar,
			    (longlong_t)err->udbh_error_reg,
			    (longlong_t)err->udbl_error_reg);
		} else {
			(void) fprintf(debug_fp, "\n");
		}
	}
		break;
	case AC_MEM_TEST_WRITE:
		break;
	case AC_MEM_ADMIN_VER: {
		ac_mem_version_t *ver;

		ver = (ac_mem_version_t *)arg;
		(void) fprintf(debug_fp, "    version %d\n", *ver);
	}
		break;
	case AC_MEM_STAT: {
		ac_stat_t *tstat;

		tstat = (ac_stat_t *)arg;
		(void) fprintf(debug_fp, "    rstate=%u ostate=%u "
		    "condition=%u status_time=%#lx board=%u\n",
		    (uint_t)tstat->rstate, (uint_t)tstat->ostate,
		    (uint_t)tstat->condition, (ulong_t)tstat->status_time,
		    tstat->board);
		(void) fprintf(debug_fp, "    real_size=%u use_size=%u "
		    "busy=%u\n",
		    tstat->real_size, tstat->use_size, tstat->busy);
		(void) fprintf(debug_fp, "    page_size=%#x "
		    "phys_pages=%#llx managed=%#llx nonrelocatable=%#llx\n",
		    tstat->page_size, (longlong_t)tstat->phys_pages,
		    (longlong_t)tstat->managed,
		    (longlong_t)tstat->nonrelocatable);
		(void) fprintf(debug_fp, "    memctl=%#llx "
		    "decode0=%#llx decode1=%#llx\n",
		    (longlong_t)tstat->ac_memctl, (longlong_t)tstat->ac_decode0,
		    (longlong_t)tstat->ac_decode1);
	}
		break;
	case AC_MEM_EXERCISE: {
		ac_cfga_cmd_t *cmdp;

		cmdp = arg;
		switch (cmdp->arg) {
		case AC_MEMX_RELOCATE_ALL: {
			struct ac_memx_relocate_stats *stp;

			if ((stp = cmdp->private) != NULL) {
				(void) fprintf(debug_fp, "    base=%u npgs=%u"
				    " nopaget=%u nolock=%u isfree=%u reloc=%u"
				    " noreloc=%u\n",
				    stp->base, stp->npgs, stp->nopaget,
				    stp->nolock, stp->isfree, stp->reloc,
				    stp->noreloc);
			}
			break;
		}
		default:
			break;
		}
		break;
	}
	default:
		break;
	}
	(void) fflush(debug_fp);
}
#endif /* DEV_DEBUG */
