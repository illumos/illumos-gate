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

#include <sys/time_impl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <libdevinfo.h>
#define	_KERNEL
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/bofi.h>

#define	BOFI_DEV	"/devices/pseudo/bofi@0:bofi,ctl"

#define	GETSTRUCT(s, num)	\
	((s *) memalign(sizeof (void*), (num) * sizeof (s)))

#define	MAXEDEFS	(0x64)		/* controls max no of concurent edefs */
#define	DFLTLOGSZ	(0x4000)	/* default size of an access log */
#define	DFLT_NONPIO_LOGSZ	(0x400)	/* default size of a log */
#define	MAXALRMCALL	(0x1000ull)	/* alarm does not permit big values */
#define	MIN_REPORT_TIME	(5)		/* min time to wait for edef status */
#define	DISTRIB_CUTOFF	(3)		/* useful when reducing a log */
#define	myLLMAX		(0x7fffffffffffffffll)
#define	myULLMAX	(0xffffffffffffffffull)

/*
 * default interval to wait between kicking off workload and injecting fault
 */
#define	DEFAULT_EDEF_SLEEP 3
/*
 * when generating dma corruptions, it is best to corrupt each double word
 * individually for control areas - however for data areas this can be
 * excessive and would generate so many cases we would never finish the run.
 * So set a cut-off value where we switch from corrupting each double word
 * separately to corrupting th elot in one go. 0x100 bytes seems a good value
 * on the drivers we have seen so far.
 */
#define	DMA_INDIVIDUAL_CORRUPT_CUTOFF 0x100

struct collector_def {
	struct bofi_errdef ed;		/* definition of the log criteria */
	struct bofi_errstate es;	/* the current status of the log */
	struct acc_log_elem *lp;	/* array of logged accesses */
	pid_t pid;
};

static uint16_t policy;

#define	BYTEPOLICY	(0xf)
#define	MULTIPOLICY	(0x10)
#define	SIZEPOLICY	(BYTEPOLICY|MULTIPOLICY)
#define	UNBIASEDPOLICY	0x20
#define	UNCOMMONPOLICY	0x40
#define	COMMONPOLICY	0x80
#define	MEDIANPOLICY	0x100
#define	MAXIMALPOLICY	0x200
#define	OPERATORSPOLICY	0x400
#define	VALIDPOLICY	(0x7ff)

typedef
struct coding {
	char	*str;
	uint_t	code;
} coding_t;

static coding_t ptypes[] = {
	{"onebyte", 0x1}, {"twobyte", 0x2},
	{"fourbyte", 0x4}, {"eightbyte", 0x8},
	{"multibyte", 0x10}, {"unbiased", 0x20}, {"uncommon", 0x40},
	{"common", 0x80}, {"median", 0x100}, {"maximal", 0x200},
	{"operators", 0x400},  {0, 0}
};
static coding_t atypes[] = {
	{"pio_r", BOFI_PIO_R}, {"pio_w", BOFI_PIO_W},
	{"dma_r", BOFI_DMA_R}, {"dma_w", BOFI_DMA_W},
	{"pio", BOFI_PIO_RW}, {"dma", BOFI_DMA_RW},
	{"log", BOFI_LOG}, {"intr", BOFI_INTR},
	{"PIO_R", BOFI_PIO_R}, {"PIO_W", BOFI_PIO_W},
	{"DMA_R", BOFI_DMA_R}, {"DMA_W", BOFI_DMA_W},
	{"PIO", BOFI_PIO_RW}, {"DMA", BOFI_DMA_RW},
	{"LOG", BOFI_LOG}, {"INTR", BOFI_INTR}, {0, 0}
};
static coding_t optypes[] = {
	{"EQ", BOFI_EQUAL}, {"AND", BOFI_AND}, {"OR", BOFI_OR},
	{"XOR", BOFI_XOR}, {"NO", BOFI_NO_TRANSFER},
	{"DELAY", BOFI_DELAY_INTR}, {"LOSE", BOFI_LOSE_INTR},
	{"EXTRA", BOFI_EXTRA_INTR}, {0, 0}
};
static coding_t doptypes[] = {
	{"EQ", BOFI_EQUAL}, {"AND", BOFI_AND}, {"OR", BOFI_OR},
	{"XOR", BOFI_XOR}, {0, 0}
};
static coding_t ioptypes[] = {
	{"DELAY", BOFI_DELAY_INTR}, {"LOSE", BOFI_LOSE_INTR},
	{"EXTRA", BOFI_EXTRA_INTR}, {0, 0}
};

static const unsigned long long	DFLTLOGTIME	= -1ull; /* log forever */

/*
 * This global controls the generation of errdefs for PIO_W. The default should
 * be to only perform an access check errdef but not to corrupt writes - this
 * may trash non-FT platforms.
 */
static uint_t atype_is_default;	/* do not corrupt PIO_W by default */
static uint_t lsize_is_default;	/* set when the user has not given a size */

static uint64_t random_operand = 0xdeadbeafdeadbeafull;
#define	NPIO_DEFAULTS	(3)	/* number of default corruption values */
static longlong_t pio_default_values[NPIO_DEFAULTS] = {
	0x0ull,			/* corresponds to a line going high/low */
	0x32f1f03232f1f032ull,	/* the value returned when the fake ta is set */
	(longlong_t)(~0)	/* corresponds to a line going high/low */
};

static uint_t dbglvl		= 0;	/* debug this program */
static int alarmed		= 0;
static int killed		= 0;

/*
 * name of a script to call before offlining a driver being tested
 */
static char **fixup_script = 0;
static int	scriptargs = 0;
static char **pargv;
static int	pargc;

static int	max_edef_wait = 0;
static int	edef_sleep = 0;
static int	do_status = 0;	/* report edef status in parsable format */
static char *user_comment = 0;

static char *Progname;
static FILE *errfile;
static FILE *outfile;

/*
 * The th_define utility provides an interface to the bus_ops fault injection
 * bofi device driver for defining error injection specifications (referred to
 * as errdefs). An errdef corresponds to a specification of how to corrupt a
 * device driver's accesses to its hardware. The command line arguments
 * determine the precise nature of the fault to be injected. If the supplied
 * arguments define a consistent errdef, the th_define process will store the
 * errdef with the bofi driver and suspend itself until the criteria given by
 * the errdef become satisfied (in practice, this will occur when the access
 * counts go to zero).
 *
 * When the resulting errdef is activated using the th_manage(1M) user command
 * utility, the bofi driver will act upon the errdef by matching the number of
 * hardware accesses - specified in count, that are of the type specified in
 * acc_types, made by instance number instance - of the driver whose name is
 * name, (or by the driver instance specified by * path ) to the register set
 * (or DMA handle) specified by rnumber, that lie within the range offset to
 * offset + length from the beginning of the register set or DMA handle. It then
 * applies operator and operand to the next failcount matching accesses.
 *
 * If acc_types includes LOG, th_define runs in automatic test script generation
 * mode, and a set of test scripts (written in the Korn shell) is created and
 * placed in a sub-directory of the current directory with the name
 * driver.test.<id>. A separate, executable script is generated for each access
 * handle that matches the logging criteria. The log of accesses is placed at
 * the top of each script as a record of the session. If the current directory
 * is not writable, file output is written to standard output. The base name of
 * each test file is the driver name, and the extension is a number that
 * discriminates between different access handles. A control script (with the
 * same name as the created test directory) is generated that will run all the
 * test scripts sequentially.
 *
 * Executing the scripts will install, and then activate, the resulting error
 * definitions. Error definitions are activated sequentially and the driver
 * instance under test is taken offline and brought back online before each test
 * (refer to the -e option for more information). By default, logging will apply
 * to all PIO accesses, interrupts and DMA accesses to and from areas mapped
 * for both reading and writing, but it can be constrained by specifying
 * additional acc_types, rnumber, offset and length. Logging will continue for
 * count matching accesses, with an optional time limit of collect_time seconds.
 *
 * Either the -n or -P option must be provided. The other options are optional.
 * If an option (other than the -a option) is specified multiple times, only
 * the final value for the option is used. If an option is not specified, its
 * associated value is set to an appropriate default, which will provide
 * maximal error coverage as described below.
 */

/*PRINTFLIKE2*/
static void
msg(uint_t lvl, char *msg, ...)
{
#define	BUFSZ	128

	if (lvl <= dbglvl) {
		int count;
		va_list args;
		char buf[BUFSZ];
		int	pos = 0;

		va_start(args, msg);
		count = vsnprintf(buf, BUFSZ, msg, args);
		va_end(args);
		if (count > 0) {
			count += pos;
			if (count >= sizeof (buf))
				count = BUFSZ - 1;
			buf[count] = '\0';
			(void) fprintf(errfile, "%s", buf);
		}
	}
}

static void
kill_sighandler(int sig)
{
	switch (sig) {
		case SIGALRM:
			alarmed = 1;
			break;
		default:
			killed = 1;
			break;
	}
}

static void
set_handler(int sig)
{
	struct sigaction sa;

	(void) sigfillset(&(sa.sa_mask));
	sa.sa_flags = 0;
	sa.sa_handler = kill_sighandler;
	if (sigaction(sig, &sa, NULL) != 0)
		/* install handler */
		msg(0, "bad sigaction: %s\n", strerror(errno));
}

/*
 * Compare two driver access handles
 */
static int
hdl_cmp(const void *p1, const void *p2)
{
	struct handle_info *e1 = (struct handle_info *)p1;
	struct handle_info *e2 = (struct handle_info *)p2;

	if (e1->instance < e2->instance)
		return (-1);
	else if (e1->instance > e2->instance)
		return (1);
	else if (e1->access_type < e2->access_type)
		return (-1);
	else if (e1->access_type > e2->access_type)
		return (1);
	else if (e1->rnumber < e2->rnumber)
		return (-1);
	else if (e1->rnumber > e2->rnumber)
		return (1);
	else if (e1->len < e2->len)
		return (-1);
	else if (e1->len > e2->len)
		return (1);
	else if (e1->offset < e2->offset)
		return (-1);
	else if (e1->offset > e2->offset)
		return (1);
	else if (e1->addr_cookie < e2->addr_cookie)
		return (-1);
	else if (e1->addr_cookie > e2->addr_cookie)
		return (1);
	else
		return (0);
}

/*
 * Compare two hardware accesses.
 */
static int
elem_cmp(const void *p1, const void *p2)
{
	struct acc_log_elem *e1 = (struct acc_log_elem *)p1;
	struct acc_log_elem *e2 = (struct acc_log_elem *)p2;

	if (e1->access_type < e2->access_type)
		return (-1);
	else if (e1->access_type > e2->access_type)
		return (1);
	else if (e1->offset < e2->offset)
		return (-1);
	else if (e1->offset > e2->offset)
		return (1);
	else if (e1->size < e2->size)
		return (-1);
	else if (e1->size > e2->size)
		return (1);
	else
		return (0);
}

/*
 * Another way of comparing two hardware accesses.
 */
static int
log_cmp(const void *p1, const void *p2)
{
	struct acc_log_elem *e1 = (struct acc_log_elem *)p1;
	struct acc_log_elem *e2 = (struct acc_log_elem *)p2;

	int rval = elem_cmp(p1, p2);

	if (rval == 0)
		if (e1->repcount < e2->repcount)
			return (-1);
		else if (e1->repcount > e2->repcount)
			return (1);
		else
			return (0);
	else
		return (rval);
}

/*
 * And a final way of sorting a log (by access type followed by repcount).
 */
static int
log_cmp2(const void *p1, const void *p2)
{
	struct acc_log_elem *e1 = (struct acc_log_elem *)p1;
	struct acc_log_elem *e2 = (struct acc_log_elem *)p2;

	if (e1->access_type < e2->access_type)
		return (-1);
	else if (e1->access_type > e2->access_type)
		return (1);
	else if (e1->repcount < e2->repcount)
		return (-1);
	else if (e1->repcount > e2->repcount)
		return (1);
	else
		return (0);
}

static void
dump_log(uint_t lvl, FILE *fp, struct acc_log_elem *items,
    size_t nitems, uint_t logflags)
{
	if (lvl <= dbglvl) {
		int i;
		uint_t offset, allthesame = 1;

		if (logflags & BOFI_LOG_TIMESTAMP &&
		    getenv("DUMP_FULL_LOG") != 0)
			allthesame = 0;
		else
			for (i = 1; i < nitems; i++)
				if (elem_cmp(items+i, items) != 0)
					allthesame = 0;
		if (fp != 0)
			(void) fprintf(fp,
			    "# Logged Accesses:\n# %-4s\t%-12s\t%-4s\t%-18s"
			    " (%-1s)\t%-10s\n\n", "type",
			    (items->access_type & BOFI_DMA_RW) ?
			    "address" : "offset",
			    "size", "value", "repcnt", "time");

		for (i = 0; i < nitems; i++, items++) {
			offset = items->offset;
			if (fp != 0) {
				(void) fprintf(fp,
				    "# 0x%-2x\t0x%-10x\t%-4d\t0x%-16llx"
				    " (0x%-1x)\t%-8llu\n",
				    items->access_type, offset, items->size,
				    items->value, items->repcount,
				    (logflags & BOFI_LOG_TIMESTAMP) ?
				    items->access_time : 0ull);

				if (allthesame) {
					(void) fprintf(fp,
					    "# Access duplicated %d times\n",
					    nitems);
					break;
				}
			} else
				msg(lvl, "# 0x%x 0x%x %d 0x%llx(0x%x) %llu\n",
				    items->access_type, offset, items->size,
				    items->value, items->repcount,
				    (logflags & BOFI_LOG_TIMESTAMP) ?
				    items->access_time : 0ull);
		}
	}
}

static int
str_to_bm(char *optarg, coding_t *c, uint_t *bm)
{
	char *str;
	char *s = "\t\n ";
	int err = EINVAL;

	msg(2, "str_to_bm: optarg %s\n", optarg);
	if (optarg != NULL && (str = strtok(optarg, s))) {
		msg(2, "str_to_bm: str %s\n", str);
		do {
			for (; c->str != 0; c++)
				if (strcmp(str, c->str) == 0) {
					*bm |= c->code;
					msg(2, "str_to_bm: %s matches\n",
					    c->str);
					err = 0;
					break;
				}
		} while ((str = strtok(NULL, s)));
	} else
		return (EINVAL);
	msg(2, "str_to_bm: done 0x%x\n", *bm);
	return (err);
}


/*
 * Generic routine for commands that apply to a particular instance of
 * a driver under test (e.g. activate all errdefs defined on an instance).
 */
static int
manage_instance(int fd, char *namep, int instance, int cmd)
{
	struct bofi_errctl errctl;

	errctl.namesize = strlen(namep);
	(void) strncpy(errctl.name, namep, MAXNAMELEN);
	errctl.instance = instance;

	msg(8, "manage_instance: %s %d\n", namep, instance);
	if (ioctl(fd, cmd, &errctl) == -1) {
		msg(0, "bofi ioctl %d failed: %s\n", cmd, strerror(errno));
		return (-1);
	}
	return (0);
}


static int
define_one_error(
	FILE *fp,
	struct bofi_errdef *edp,
	struct acc_log_elem *item,
	ulong_t	nttime,
	ulong_t interval,
	char	*type,
	int fon,	/* corrupt after this many accesses */
	size_t fcnt,	/* and then fail it fcnt times */
	uint_t	acc_chk,
	char	*opname,
	uint64_t	operand)
{
	(void) fprintf(fp,
	    "-n %s -i %d -r %d -l 0x%llx 0x%x -a %s -c %d %d -f %d"
	    " -o %s 0x%llx",
	    (char *)edp->name,
	    edp->instance,
	    edp->rnumber,
	    edp->offset + item->offset,	/* offset into the regset */
	    item->size,	/* corrupt addrs from offset to offset+size */
	    type,
	    fon,	/* corrupt after this many accesses */
	    fcnt,	/* and then fail it fcnt times */
	    acc_chk,
	    opname,
	    operand);

	(void) fprintf(fp, " -w %lu %lu\n", nttime, interval);
	return (0);
}

static void
define_op_err(FILE *fp, int *ecnt, struct bofi_errdef *edp,
    struct acc_log_elem *item, ulong_t nttime, ulong_t interval, char *type,
    int fon, size_t fcnt)
{
	coding_t *ct;
	char	*opname;
	uint_t	op;
	uint64_t	operand;
	int k, save_size;
	uint64_t save_offset;

	if (item->access_type & BOFI_INTR)
		ct = &ioptypes[0];
	else
		ct = &doptypes[0];

	/*
	 * errdefs for dma accesses are too numerous so assume that dma writes
	 * (DDI_DMA_SYNC_FORDEV) create less exposure to potential errors than
	 * do dma reads (DDI_DMA_SYNC_FORCPU).
	 *
	 * also by default do not corrupt PIO_W - it may hang a non-FT platform.
	 */
	if (item->access_type != BOFI_DMA_W &&
	    ((item->access_type & BOFI_PIO_W) == 0 || !atype_is_default)) {
		/*
		 * user has asked for PIO_W
		 */
		for (; ct->str != 0; ct++) {
			op = ct->code;
			opname = ct->str;
			switch (op) {
			case BOFI_EQUAL:
				operand = random_operand; /* a random value */
				random_operand = lrand48() | ((uint64_t)
				    (lrand48()) << 32);
				break;
			case BOFI_AND:
				operand = 0xaddedabadb00bull;
				break;
			case BOFI_OR:
				operand = 0x1;
				break;
			case BOFI_XOR:
			default:
				operand = myULLMAX;
				break;
			case BOFI_DELAY_INTR: /* delay for 1 msec */
				operand = 1000000;
				break;
			case BOFI_LOSE_INTR: /* op not applicable */
				operand = 0;
				break;
			case BOFI_EXTRA_INTR: /* extra intrs */
				operand = 0xfff;
				break;
			}
			*ecnt = *ecnt + 1;

			if ((item->access_type == BOFI_DMA_W ||
			    item->access_type == BOFI_DMA_R) &&
			    item->size > sizeof (uint64_t) && item->size <
			    DMA_INDIVIDUAL_CORRUPT_CUTOFF) {
				save_size = item->size;
				save_offset = item->offset;
				for (k = (item->size +
				    sizeof (uint64_t) - 1) &
				    ~(sizeof (uint64_t) - 1);
				    k > 0; k -= sizeof (uint64_t)) {
					item->size = sizeof (uint64_t);
					(void) define_one_error(fp, edp,
					    item, nttime, interval, type, fon,
					    fcnt, edp->acc_chk, opname,
					    operand);
					item->offset += sizeof (uint64_t);
				}
				item->size = save_size;
				item->offset = save_offset;
			} else {
				(void) define_one_error(fp, edp, item,
				    nttime, interval, type, fon, fcnt,
				    edp->acc_chk, opname, operand);
			}

			if (op == BOFI_EQUAL) {
				uint_t cnt;
				for (cnt = 0; cnt < NPIO_DEFAULTS;
				    cnt++, *ecnt = *ecnt + 1) {
					if ((item->access_type == BOFI_DMA_W ||
					    item->access_type == BOFI_DMA_R) &&
					    item->size > sizeof (uint64_t) &&
					    item->size <
					    DMA_INDIVIDUAL_CORRUPT_CUTOFF) {
						save_size = item->size;
						save_offset = item->offset;
						for (k = (item->size +
						    sizeof (uint64_t) - 1) &
						    ~(sizeof (uint64_t) - 1);
						    k > 0;
						    k -= sizeof (uint64_t)) {
							item->size =
							    sizeof (uint64_t);
							(void) define_one_error(
							    fp, edp, item,
							    nttime, interval,
							    type, fon, fcnt,
							    edp->acc_chk,
							    opname,
							    pio_default_values
							    [cnt]);
							item->offset +=
							    sizeof (uint64_t);
						}
						item->size = save_size;
						item->offset = save_offset;
					} else {
						(void) define_one_error(fp,
						    edp, item, nttime, interval,
						    type, fon, fcnt,
						    edp->acc_chk, opname,
						    pio_default_values[cnt]);
					}
				}
			}
		}
	}

	if ((item->access_type & BOFI_PIO_W) && !atype_is_default) {
		/*
		 * user has asked for PIO_W
		 */
		(void) define_one_error(fp, edp, item, nttime, interval,
		    type, fon, fcnt, edp->acc_chk, "NO", 0);
		*ecnt = *ecnt + 1;
	}

	/*
	 * and finally an access check errdef
	 */
	if (item->access_type & BOFI_PIO_RW)
		(void) define_one_error(fp, edp, item, nttime, interval,
		    type, fon, fcnt, 1, "OR", 0);

	if (item->access_type & BOFI_DMA_RW)
		(void) define_one_error(fp, edp, item, nttime, interval,
		    type, fon, fcnt, 2, "OR", 0);

}

/*
 * Convert a collection of log entries into error definitions.
 */
/* ARGSUSED */
static int
define_nerrs(int fd, FILE *fp, int *ecnt, struct bofi_errdef *edp,
    struct acc_log_elem *items, size_t nitems, uint_t naccess, uint_t minac,
    uint_t maxac, ulong_t logtime, ulong_t logsize)
{
	char	*type;
	uint_t	at;
	int	i;
	struct acc_log_elem	*item;
	char	*opname;
	uint_t	op;
	uint64_t	operand;
	int	cycleiops, cycledops;
	int	intrs = 0;
	ulong_t	ttime, nttime, interval;

	op = edp->optype;
	operand = edp->operand;
	msg(3, "define_nerrs: nitems %d (ac %d at 0x%x): (%d %d)"
	    " (op 0x%x 0x%llx)\n\n", nitems, naccess, items->access_type,
	    minac, maxac, op, operand);

	/*
	 * all items are guaranteed have values in the two element set {0, at}
	 * where at is a valid access type (so find the value of at)
	 */
	for (i = 0, item = items, at = 0; i < nitems; i++, item++)
		if (item->access_type != 0) {
			at = item->access_type;
			break;
		}
	if (at == 0)
		return (-1);

	/*
	 * find the string form of the access type
	 */
	for (i = 0, type = 0; atypes[i].str != 0; i++) {
		if (atypes[i].code == at) {
			type = atypes[i].str;
			break;
		}
	}
	if (type == 0) {
		msg(0, "Unknown access type returned from bofi\n\t");
		dump_log(0, 0, item, 1, BOFI_LOG_TIMESTAMP);
		msg(1, "0x%x 0x%x 0x%x 0x%x\n", BOFI_LOG, BOFI_INTR,
		    BOFI_DMA_RW, BOFI_PIO_RW);
		return (-1);
	}

	msg(1, "define_n: at = 0x%d (%s)\n", at, type == 0 ? "null" : type);
	/*
	 * find the string form of the operator
	 */
	for (i = 0, opname = 0; optypes[i].str != 0; i++) {
		if (op == optypes[i].code) {
			opname = optypes[i].str;
			break;
		}
	}

	/*
	 * if not found or inconsistent default to XOR
	 */
	if (opname == 0 ||
	    (op == BOFI_NO_TRANSFER &&
	    (at & (BOFI_DMA_RW|BOFI_PIO_R))) ||
	    (op >= BOFI_DELAY_INTR && (at & BOFI_INTR) == 0)) {
		opname = optypes[3].str;	/* "XOR" */
		operand = myULLMAX;
		op = optypes[3].code;
	}

	/*
	 * if operator and access type are inconsistent choose a sensible
	 * default
	 */
	cycleiops = 0;
	if (at & BOFI_INTR)
		if (op < BOFI_DELAY_INTR)
			cycleiops = 1;
		else if (op == BOFI_LOSE_INTR)
			operand = 0;

	cycledops = 0;
	if (nitems == 1 && (at & BOFI_DMA_RW))
		cycledops = 1;
	/*
	 * for each access in the list define one or more error definitions
	 */
	for (i = 0, item = items; i < nitems; i++, item++) {
		size_t acnt, fcnt;
		int j, fon;

		if (item->access_type == 0)
			continue;

		/*
		 * base number of errors to inject on 3% of number of
		 * similar accesses seen during LOG phase
		 */
		acnt = item->repcount / 10 + 1; /* 10% */
		fcnt = (acnt >= 3) ? acnt / 3 : 1; /* 3% */

		/*
		 * wait for twice the time it took during LOG phase
		 */
		if ((ttime = (item->access_time * 2)) < MIN_REPORT_TIME)
			ttime = MIN_REPORT_TIME;
		else if (max_edef_wait != 0 && ttime > max_edef_wait)
			ttime = max_edef_wait;
		/*
		 * if edef_sleep set (-w) the use that, otherwise use default
		 */
		interval = edef_sleep ? edef_sleep : DEFAULT_EDEF_SLEEP;

		msg(10,
		    "define_n: item %d limit %d step %d (intr %d) tt(%lu)\n",
		    i, item->repcount, acnt, intrs, ttime);

		for (j = 0, fon = 1, nttime = ttime; j < item->repcount;
		    j += acnt) {
			if (policy & OPERATORSPOLICY) {
				define_op_err(fp, ecnt, edp, item,
				    nttime, interval, type, fon, fcnt);
			} else {
				if (cycleiops) {
					op = ioptypes[intrs].code;
					opname = ioptypes[intrs++].str;
					switch (op) {
					case BOFI_DELAY_INTR:
						/* delay for 1 sec */
						operand = 1000000;
						break;
					case BOFI_LOSE_INTR:
						/* op not applicable */
						operand = 0;
						break;
					case BOFI_EXTRA_INTR:
					default:
						/* generate 2 extra intrs */
						operand = 0xfff;
						break;
					}
					intrs %= 3;
				} else if (cycledops) {
					op = doptypes[intrs].code;
					opname = doptypes[intrs++].str;
					switch (op) {
					case BOFI_EQUAL:
						random_operand = lrand48() |
						    ((uint64_t)
						    (lrand48()) << 32);
						break; /* a random value */
					case BOFI_AND:
						operand = 0xaddedabadb00bull;
						break;
					case BOFI_OR:
						operand = 0xd1ab011c0af1a5c0ull;
						break;
					case BOFI_XOR:
					default:
						operand = myULLMAX;
						break;
					}
					intrs %= 4;
				}
				(void) define_one_error(fp, edp, item,
				    nttime, interval, type, fon,
				    fcnt, edp->acc_chk, opname, operand);
				*ecnt = *ecnt + 1;
				if (op == BOFI_EQUAL) {
					uint_t cnt;
					for (cnt = 0; cnt < NPIO_DEFAULTS;
					    cnt++, *ecnt = *ecnt + 1)
						(void) define_one_error(fp,
						    edp, item, nttime,
						    interval, type, fon, fcnt,
						    edp->acc_chk, opname,
						    pio_default_values[cnt]);
				}
			}

			/*
			 * all non maximal policies should only generate
			 * a single error definition set per access.
			 */
			if (!(policy & MAXIMALPOLICY))
				break;

			nttime = (logtime - item->access_time) *
			    (j + acnt + fcnt - 1) / logsize;
			if (nttime < MIN_REPORT_TIME)
				nttime = MIN_REPORT_TIME;
			else if (nttime > max_edef_wait)
				nttime = max_edef_wait;

			msg(11, "define_nerrs: %lu %d %d %d %llu\n", nttime,
			    max_edef_wait, fon, fcnt, item->access_time);

			if (item->access_type != BOFI_INTR)
				fon += j;
		}
	}

	return (0);
}

static int
reduce_log(uint16_t pol, struct acc_log *log,		/* input args */
    struct acc_log_elem **llp, size_t *cntp)		/* output args */
{
	ulong_t logtime;
	struct acc_log_elem *items, *item, *elem;
	int cnt, nitems, acnt;
	int i, j, k, lb, ub, mina, maxa, cutoff[2], mean;

	if (llp == 0 || cntp == 0)	/* subroutine interface violated */
		return (-1);

	if (*llp == 0) {
		items = (void *)log->logbase;
		nitems = log->entries;
	} else {
		items = *llp;	/* outputs double up as inputs */
		nitems = *cntp;
	}
	/* has the utc time wrapped over ULMAX - unlikely so fix it at 10 */
	logtime = (log->stop_time >= log->start_time) ?
	    log->stop_time - log->start_time : 10ul;

	msg(1, "reduce %d: logtime %lu\n", nitems, logtime);
	/*
	 * Sort the log by access type - do not remove duplicates yet (but do
	 * remove access that do not match the requested log -> errdef policy
	 * (defined by union pu pol). Set the repcount field of each entry to a
	 * unique value (in the control statement of the for loop) - this
	 * ensures that the qsort (following the for loop) will not remove any
	 * entries.
	 */
	for (i = 0, cnt = 0, elem = items; i < nitems;
	    elem->repcount = i, i++, elem++) {
		/*
		 * If interested in the I/O transfer size and this access
		 * does not match the requested size then ignore the access
		 */
		if ((pol & SIZEPOLICY) &&
		    (!(pol & MULTIPOLICY) || elem->repcount == 1) &&
		    /* req for DMA / ddi_rep */
		    (pol & elem->size) == 0)
			elem->access_type = 0;
			/* these will end up sorted at the head */
		else {
			cnt += 1;
			elem->size *= elem->repcount;
			if (log->flags & BOFI_LOG_TIMESTAMP)
				/* real access time */
				elem->access_time -= log->start_time;
			else
				/* linear fit */
				elem->access_time = logtime * (i + 1) / nitems;
		}
	}

	qsort((void *)items, nitems, sizeof (*items), log_cmp);

	msg(5, "qsorted log raw (nitems %d cnt %d:\n", nitems, cnt);
	dump_log(14, 0, items, nitems, log->flags);

	if (cnt != nitems) {	/* some items should be ignored */
		items += (nitems - cnt);	/* ignore these ones */
		if ((nitems = cnt) == 0) {
			*cntp = 0;
			*llp = 0;
			return (0);
			/* the chosen policy has ignored everything */
		}

	}
	/*
	 * Now remove duplicate entries based on access type, address and size.
	 * Reuse the repcount field to store the no. of duplicate accesses.
	 * Store the average access time in the single remaining
	 * representative of the duplicate set.
	 */

	for (i = 1, cnt = 1, elem = items, elem->repcount = 1, item = elem + 1;
	    i < nitems; i++, item++) {
		if (elem_cmp(elem, item) == 0) {
			elem->access_time += item->access_time;
			elem->repcount++;
		} else {	/* not a duplicate */
			elem->access_time = logtime / elem->repcount;
			elem++;
			*elem = *item;
			cnt++;
			elem->repcount = 1;
		}
	}
	elem->access_time = logtime / elem->repcount;

	/*
	 * The log is sorted by access type - now resort to order by frequency
	 * of accesses (ie for a given access type uncommon access will come
	 * first.
	 */

	qsort((void *)items, cnt, sizeof (*items), log_cmp2);
	msg(4, "qsorted log2: cnt is %d\n", cnt);
	dump_log(4, 0, items, cnt, log->flags);

	for (i = 0; i < cnt; i = j) {

		/*
		 * Pick out the set [i, j) consisting of elements with the same
		 * access type
		 */
		for (j = i + 1, acnt = items[i].repcount; j < cnt &&
		    items[j].access_type == items[i].access_type; j++)
			acnt += items[j].repcount;

		if (j - i == 1)	/* never ignore solo accesses of a given type */
			continue;
		/*
		 * Now determine what constitutes uncommon and common accesses:
		 */
		mina = items[i].repcount;
		maxa = items[j-1].repcount;
		mean = acnt / (j - i); /* mean value */

		if (pol & (UNCOMMONPOLICY|MEDIANPOLICY)) {
			cutoff[0] = (mean - mina) / DISTRIB_CUTOFF + mina;

			for (ub = i; ub < j; ub++)
				if (items[ub].repcount > cutoff[0])
					break;
			lb = j - 1;
		} else {
			lb = i;
			ub = j-1;
		}

		if (pol & (COMMONPOLICY|MEDIANPOLICY)) {
			cutoff[1] = maxa - (maxa - mean) / DISTRIB_CUTOFF;
			for (lb = j - 1; lb >= i; lb--)
				if (items[lb].repcount < cutoff[1])
					break;
			if (!(pol & (UNCOMMONPOLICY|MEDIANPOLICY)))
				ub = i;
		}

		msg(3, "reduce_log: p 0x%x at %d:0x%x %d:0x%x acnt mina maxa"
		    " (%d %d %d)"
		    " mean %d cutoffs(%d %d) bnds(%d, %d)\n",
		    pol, i, items[i].access_type, j, items[j].access_type,
		    acnt, mina, maxa, mean, cutoff[0], cutoff[1], lb, ub);

		if (ub <= lb)
			if (!(pol & MEDIANPOLICY))
				/* delete all the mid accesses */
				for (k = ub; k <= lb; k++)
					items[k].access_type = 0;
			else {
				if (!(pol & UNCOMMONPOLICY))
					/* delete uncommon accesses */
					for (k = i; k < ub; k++)
						items[k].access_type = 0;
				if (!(pol & COMMONPOLICY))
					/* delete common accesses */
					for (k = lb+1; k < j; k++)
						items[k].access_type = 0;
			}
	}
	msg(4, "reduce_log: returning %d items\n", cnt);
	dump_log(5, 0, items, cnt, log->flags);
	*cntp = cnt;
	*llp = items;
	return (0);
}

static void
log2errdefs(int fd, struct bofi_errdef *edp, struct acc_log *log,
    char *devpath)
{
	struct acc_log_elem	*items;
	size_t			nitems;
	int			i, j;
	uint_t			acc_cnt;
	char			fname[_POSIX_PATH_MAX];
	FILE			*fp = 0;
	time_t			utc = time(NULL);
	int			ecnt = 0;
	int			err;
	ulong_t			logtime;
	char			*buffer;
	struct stat		statbuf;

	items = (void *)log->logbase;
	nitems = log->entries;
	logtime = (log->stop_time >= log->start_time) ?
	    log->stop_time - log->start_time : 10ul;

	if (nitems == 0)
		return;

	/* ensure that generated errdefs complete in bounded time */
	if (max_edef_wait == 0)
		max_edef_wait =
		    logtime > MIN_REPORT_TIME ? logtime : MIN_REPORT_TIME * 2;

	msg(4, "log2errdefs(0x%p, 0x%p, %d, 0x%x):\n",
	    (void *) edp, (void *) items, nitems, policy);

	(void) snprintf(fname, sizeof (fname), "%s.%d", (char *)edp->name,
	    (int)getpid());
	if ((fp = fopen(fname, "w")) == 0)
		fp = outfile;

	(void) fprintf(fp, "#!/bin/ksh -p\n\n");
	(void) fprintf(fp, "# %-24s%s\n", "Script creation time:", ctime(&utc));
	(void) fprintf(fp, "# %-24s%llu\n",
	    "Activation time:", log->start_time);
	(void) fprintf(fp, "# %-24s%llu\n",
	    "Deactivation time:", log->stop_time);
	(void) fprintf(fp, "# %-24s%d\n", "Log size:", nitems);
	(void) fprintf(fp, "# %-24s", "Errdef policy:");
	for (i = 0; ptypes[i].str != 0; i++)
		if (policy & ptypes[i].code)
			(void) fprintf(fp, "%s ", ptypes[i].str);
	(void) fprintf(fp, "\n");
	(void) fprintf(fp, "# %-24s%s\n", "Driver:", (char *)edp->name);
	(void) fprintf(fp, "# %-24s%d\n", "Instance:", edp->instance);
	if (edp->access_type & BOFI_PIO_RW) {
		(void) fprintf(fp, "# %-24s%d\n",
		    "Register set:", edp->rnumber);
		(void) fprintf(fp, "# %-24s0x%llx\n", "Offset:", edp->offset);
		(void) fprintf(fp, "# %-24s0x%llx\n", "Length:", edp->len);
	} else if (edp->access_type & BOFI_DMA_RW) {
		(void) fprintf(fp, "# %-24s%d\n", "DMA handle:", edp->rnumber);
		(void) fprintf(fp, "# %-24s0x%llx\n", "Offset:", edp->offset);
		(void) fprintf(fp, "# %-24s0x%llx\n", "Length:", edp->len);
	} else if ((edp->access_type & BOFI_INTR) == 0) {
		(void) fprintf(fp, "# %-24s%d\n",
		    "Unknown Handle Type:", edp->rnumber);
	}

	(void) fprintf(fp, "# %-24s0x%x ( ", "Access type:",
	    (edp->access_type & ~BOFI_LOG));
	if (edp->access_type & BOFI_PIO_R)
		(void) fprintf(fp, "%s ", "pio_r");
	if (edp->access_type & BOFI_PIO_W)
		(void) fprintf(fp, "%s ", "pio_w");
	if (edp->access_type & BOFI_DMA_W)
		(void) fprintf(fp, "%s ", "dma_w");
	if (edp->access_type & BOFI_DMA_R)
		(void) fprintf(fp, "%s ", "dma_r");
	if (edp->access_type & BOFI_INTR)
		(void) fprintf(fp, "%s ", "intr");
	(void) fprintf(fp, ")\n\n");
	if (user_comment)
		(void) fprintf(fp, "# %-24s%s\n\n",
		    "Test Comment:", user_comment);

	dump_log(0, fp, items, nitems, log->flags);

	items = 0;
	if ((err = reduce_log(policy, log, &items, &nitems)) < 0 ||
	    nitems == 0) {
		msg(4, "log2errdefs: reduce_log err %d nitems %d\n",
		    err, nitems);
		return;
	}
	(void) fprintf(fp, "\nerror() { echo \""
	    "${0##*/}: $@\""
	    " >&2; exit 2; }\n");
	(void) fprintf(fp,
	    "trap ' ' 16\t# ignore - it is trapped by abort monitor_edef\n");

	(void) fprintf(fp, "\nfixup_script()\n{\n");
	if (scriptargs > 0) {
		(void) fprintf(fp, "\tif [[ $1 -eq 1 ]]\n\tthen\n");
		(void) fprintf(fp, "\t\t# Call a user defined workload\n");
		(void) fprintf(fp, "\t\t# while injecting errors\n\t\t");
		for (i = 0; i < scriptargs; i++)
			(void) fprintf(fp, "%s ", fixup_script[i]);
		(void) fprintf(fp, "\n\tfi\n");
		(void) fprintf(fp, "\treturn 0\n");
	} else {
		(void) fprintf(fp, "\tif [[ $1 -eq 0 ]]\n\tthen\n");
		(void) fprintf(fp,
		    "\t\t# terminate any outstanding workload\n");
		(void) fprintf(fp, "\t\tif [ $script_pid -gt 0 ]; then\n");
		(void) fprintf(fp, "\t\t\tkill $script_pid\n");
		(void) fprintf(fp, "\t\t\tscript_pid=0\n");
		(void) fprintf(fp, "\t\tfi\n");
		(void) fprintf(fp, "\tfi\n");
		(void) fprintf(fp, "\treturn -1\n");
	}
	(void) fprintf(fp, "}\n\n");
	(void) fprintf(fp, "devpath=/devices%s\n\n", devpath);
	(void) fprintf(fp, "#\n");
	(void) fprintf(fp, "# following text extracted from th_script\n");
	(void) fprintf(fp, "#\n");
	if (stat("/usr/lib/th_script", &statbuf) == -1) {
		msg(0, "log2errdefs: stat of /usr/lib/th_script failed\n");
		return;
	}
	fd = open("/usr/lib/th_script", O_RDONLY);
	if (fd == -1) {
		msg(0, "log2errdefs: open of /usr/lib/th_script failed\n");
		return;
	}
	buffer = malloc(statbuf.st_size);
	if (!buffer) {
		msg(0, "log2errdefs: malloc for /usr/lib/th_script failed\n");
		return;
	}
	if (read(fd, buffer, statbuf.st_size) != statbuf.st_size) {
		msg(0, "log2errdefs: read of /usr/lib/th_script failed\n");
		return;
	}
	(void) fwrite(buffer, statbuf.st_size, 1, fp);
	(void) close(fd);
	(void) fprintf(fp, "#\n");
	(void) fprintf(fp, "# end of extracted text\n");
	(void) fprintf(fp, "#\n");
	(void) fprintf(fp, "run_subtest %s %d <<ERRDEFS\n",
	    (char *)edp->name, edp->instance);

	for (i = 0; i < nitems; i = j) {

		acc_cnt = items[i].repcount;
		for (j = i + 1;
		    j < nitems && items[j].access_type == items[i].access_type;
		    j++)
			acc_cnt += items[j].repcount;
		msg(1, "l2e: nitems %d i %d j %d at 0x%x\n",
		    nitems, i, j, items[i].access_type);
		if (items[i].access_type != 0)
			(void) define_nerrs(fd, fp, &ecnt, edp, items+i, j-i,
			    acc_cnt, items[i].repcount, items[j-1].repcount,
			    logtime, log->entries);
	}

	(void) fprintf(fp, "ERRDEFS\n");
	(void) fprintf(fp, "exit 0\n");

	if (fp != stdout && fp != stderr) {
		if (fchmod(fileno(fp), S_IRWXU|S_IRGRP|S_IROTH))
			msg(0, "fchmod failed: %s\n", strerror(errno));
		if (fclose(fp) != 0)
			msg(0, "close of %s failed: %s\n", fname,
			    strerror(errno));
	}
	msg(10, "log2errdefs: done\n");
}

#define	LLSZMASK (sizeof (longlong_t) -1)

static int
add_edef(
	int fd,
	struct bofi_errdef *errdef,	/* returned access criteria */
	struct bofi_errstate *errstate,
	struct handle_info *hdl,	/* handle to match against request */
	struct bofi_errdef *edp)	/* requested access criteria */
{
	*errdef = *edp;
	errdef->instance = hdl->instance;


	if (hdl->access_type == 0)
		return (EINVAL);

	errdef->access_type =
	    errdef->access_type & (hdl->access_type|BOFI_LOG);

	/* use a big log for PIO and a small one otherwise */
	if (lsize_is_default &&
	    (errdef->access_type & BOFI_PIO_RW) == 0) {
		errdef->access_count = DFLT_NONPIO_LOGSZ;
		errdef->fail_count = 0;
	}
	errdef->log.logsize = errstate->log.logsize =
	    errdef->access_count + errdef->fail_count - 1;
	if (errdef->log.logsize == -1U) {
		errdef->log.logsize = errstate->log.logsize = 0;
	}
	errdef->log.logbase = errstate->log.logbase =
	    (caddr_t)GETSTRUCT(struct acc_log_elem, errdef->log.logsize);

	if (errdef->log.logbase == 0)
		return (EAGAIN);

	errdef->rnumber = hdl->rnumber;
	errdef->offset = hdl->offset;
	errdef->len = hdl->len;

	msg(4, "creating errdef: %d %s %d %d 0x%llx 0x%llx 0x%x 0x%x 0x%x"
	    " 0x%x 0x%x 0x%llx\n",
	    errdef->namesize, (char *)errdef->name,
	    errdef->instance, errdef->rnumber,
	    errdef->offset, errdef->len,
	    errdef->access_type,
	    errdef->access_count, errdef->fail_count,
	    errdef->acc_chk, errdef->optype, errdef->operand);
	if (ioctl(fd, BOFI_ADD_DEF, errdef) == -1) {
		perror("th_define - adding errdef failed");
		return (errno);
	}
	errdef->optype = edp->optype; /* driver clears it if fcnt is zero */
	errstate->errdef_handle = errdef->errdef_handle;
	return (0);
}

static void
collect_state(int fd, int cmd, struct bofi_errstate *errstate,
    struct bofi_errdef *errdef, char *devpath)
{
	int rval;
	size_t ls = errstate->log.logsize;

	msg(2, "collect_state: pre: edp->access_type 0x%x (logsize %d)\n",
	    errdef->access_type, errdef->log.logsize);

	do {
		errstate->log.logsize = 0; /* only copy the driver log once */

		msg(10, "collecting state (lsize %d) ...\n",
		    errstate->log.logsize);
		errno = 0;

		if (ioctl(fd, cmd, errstate) == -1 && errno != EINTR) {
			perror("th_define (collect) -"
			    " waiting for error report failed");
			break;
		}

		(void) fprintf(outfile, "Logged %d out of %d accesses"
		    " (%s %d %d 0x%x %d).\n",
		    errstate->log.entries, ls,
		    (char *)errdef->name, errdef->instance, errdef->rnumber,
		    errdef->access_type, errstate->log.wrapcnt);

		(void) msg(1, "\t(ac %d fc %d lf 0x%x wc %d).\n",
		    errstate->access_count, errstate->fail_count,
		    errstate->log.flags, errstate->log.wrapcnt);

		rval = errno;
		if ((errstate->log.flags & BOFI_LOG_WRAP) &&
		    errstate->access_count > 0)
			continue;
		if (errstate->access_count <= 1 &&
		    errstate->fail_count == 0 &&
		    errstate->acc_chk == 0) {
			msg(3, "collecting state complete entries %d\n",
			    errstate->log.entries);
			break;
		}

		msg(5, "still collecting state: %d, %d, %d\n",
		    errstate->access_count, errstate->fail_count,
		    errstate->acc_chk);
		(void) msg(2, "Log: errno %d size %d entries %d "
		    "(off 0x%llx len 0x%llx) ac %d\n", errno,
		    errstate->log.logsize, errstate->log.entries,
		    errdef->offset, errdef->len, errstate->access_count);

	} while (rval == 0 && errstate->log.entries < ls);

	/* now grab the log itself */
	errstate->log.logsize = ls;
	if (errstate->log.entries != 0) {
		if (ioctl(fd, BOFI_CHK_STATE, errstate) == -1) {
			msg(0,
			    "%s: errorwhile retrieving %d log entries: %s\n",
			    Progname, errstate->log.entries, strerror(errno));
		} else {
			msg(2, "collect_state: post: edp->access_type 0x%x"
			    " (log entries %d %d) (%llu - %llu)\n",
			    errdef->access_type,
			    errstate->log.entries, errstate->access_count,
			    errstate->log.start_time, errstate->log.stop_time);

			log2errdefs(fd, errdef, &(errstate->log), devpath);
		}
	}
}

static void
print_err_reports(FILE *fp, struct bofi_errstate *esp,
    char *fname, char *cmt, int id)
{
	if (fname != 0 && *fname != 0)
		(void) fprintf(fp, "%sErrdef file %s definition %d:",
		    cmt, fname, id);
	else
		(void) fprintf(fp, "%s", cmt);

	if (esp->access_count != 0) {
		(void) fprintf(fp, " (access count %d).\n", esp->access_count);
	} else {
		(void) fprintf(fp, "\n%s\tremaining fail count %d acc_chk %d\n",
		    cmt, esp->fail_count, esp->acc_chk);
		(void) fprintf(fp, "%s\tfail time 0x%llx error reported time"
		    " 0x%llx errors reported %d\n", cmt,
		    esp->fail_time, esp->msg_time,
		    esp->errmsg_count);
		if (esp->msg_time)
			(void) fprintf(fp, "%s\tmessage \"%s\" severity 0x%x\n",
			    cmt, esp->buffer, (uint_t)esp->severity);
	}
}

static void
thr_collect(void *arg, char *devpath)
{
	int fd;
	struct collector_def *hi = (struct collector_def *)arg;

	msg(4, "thr_collect: collecting %s inst %d rn %d at = 0x%x.\n",
	    hi->ed.name, hi->ed.instance,
	    hi->ed.rnumber, hi->ed.access_type);

	if ((fd = open(BOFI_DEV, O_RDWR)) == -1) {
		if (errno == EAGAIN)
			msg(0, "Too many instances of bofi currently open\n");
		else
			msg(0, "Error while opening bofi driver: %s",
			    strerror(errno));
	} else {
		/*
		 * Activate the logging errdefs - then collect the results.
		 */
		(void) manage_instance(fd, hi->ed.name,
		    hi->ed.instance, BOFI_START);
		collect_state(fd, BOFI_CHK_STATE_W, &hi->es, &hi->ed, devpath);
	}

	/*
	 * there is no more work to do on this access handle so clean up / exit.
	 */
	msg(3, "thr_collect: closing and broadcasting.\n");
	exit(0);
}

/*
 * Given an access handle known to the bofi driver see if the user has
 * specified access criteria that match that handle. Note: this matching
 * algorithm should be kept consistent with the drivers alogorithm.
 */
static int
match_hinfo(struct handle_info *hp, int instance, uint_t access_type,
    int rnumber, offset_t offset, offset_t len)
{

	msg(9, "matching (%d %d) 0x%x %d offset (%llx, %llx) len (%llx %llx)\n",
	    hp->instance, instance, access_type, rnumber,
	    hp->offset, offset, hp->len, len);

	if (instance != -1 && hp->instance != instance)
		return (0);
	if ((access_type & BOFI_DMA_RW) &&
	    (hp->access_type & BOFI_DMA_RW) &&
	    (rnumber == -1 || hp->rnumber == rnumber))
		return (1);
	else if ((access_type & BOFI_INTR) &&
	    (hp->access_type & BOFI_INTR))
		return (1);
	else if ((access_type & BOFI_PIO_RW) &&
	    (hp->access_type & BOFI_PIO_RW) &&
	    (rnumber == -1 || hp->rnumber == rnumber) &&
	    (len == 0 || hp->offset < offset + len) &&
	    (hp->len == 0 || hp->offset + hp->len > offset))
		return (1);
	else
		return (0);
}

/*
 * Obtain all the handles created by the driver specified by the name parameter
 * that match the remaining arguments. The output parameter nhdls indicates how
 * many of the structures pointed to by the output parameter hip match the
 * specification.
 *
 * It is the responsibility of the caller to free *hip when *nhdls != 0.
 */
static int
get_hinfo(int fd, char *name, struct handle_info **hip, size_t *nhdls,
    int instance, int atype, int rset, offset_t offset, offset_t len,
    int new_semantics)
{
	struct bofi_get_hdl_info hdli;
	int command;

	command = BOFI_GET_HANDLE_INFO;
	hdli.namesize = strlen(name);
	(void) strncpy(hdli.name, name, MAXNAMELEN);
	/*
	 * Initially ask for the number of access handles (not the structures)
	 * in order to allocate memory
	 */
	hdli.hdli = 0;
	*hip = 0;
	hdli.count = 0;

	/*
	 * Ask the bofi driver for all handles created by the driver under test.
	 */
	if (ioctl(fd, command, &hdli) == -1) {
		*nhdls = 0;
		msg(0, "driver failed to return handles: %s\n",
		    strerror(errno));
		return (errno);
	} else if ((*nhdls = hdli.count) == 0) {
		msg(1, "get_hinfo: no registered handles\n");
		return (0);	/* no handles */
	} else if ((*hip = GETSTRUCT(struct handle_info, *nhdls)) == 0) {
		return (EAGAIN);
	} else {
		struct handle_info *hp, **chosen;
		int i;

		/* Ask for *nhdls handles */
		hdli.hdli = (caddr_t)*hip;
		if (ioctl(fd, command, &hdli) == -1) {
			int err = errno;

			msg(0, "BOFI_GET_HANDLE_INFO ioctl returned error %d\n",
			    err);
			free(*hip);
			return (err);
		}

		if (hdli.count < *nhdls)
			*nhdls = hdli.count; /* some handles have gone away */

		msg(4, "qsorting %d handles\n", *nhdls);
		if (*nhdls > 1)
			/* sort them naturally (NB ordering is not mandatory) */
			qsort((void *)*hip, *nhdls, sizeof (**hip), hdl_cmp);

		if ((chosen = malloc(sizeof (hp) * *nhdls)) != NULL) {
			struct handle_info **ip;
			/* the selected handles */
			struct handle_info *prev = 0;
			int scnt = 0;

			for (i = 0, hp = *hip, ip = chosen; i < *nhdls;
			    i++, hp++) {
				/*
				 * Remark: unbound handles never match
				 * (access_type == 0)
				 */
				if (match_hinfo(hp, instance, atype, rset,
				    offset&0x7fffffff, len&0x7fffffff)) {
					msg(3, "match: 0x%x 0x%llx 0x%llx"
					    " 0x%llx (0x%llx)\n",
					    hp->access_type, hp->addr_cookie,
					    hp->offset, hp->len,
					    (hp->len & 0x7fffffff));
					if (prev &&
					    (prev->access_type & BOFI_DMA_RW) &&
					    (hp->access_type & BOFI_DMA_RW) &&
					    hp->instance == prev->instance &&
					    hp->len == prev->len &&
					    hp->addr_cookie ==
					    prev->addr_cookie)
						continue;

					if ((hp->access_type & BOFI_DMA_RW) &&
					    (atype & BOFI_DMA_RW) !=
					    hp->access_type)
						if (new_semantics)
							continue;

					if (prev)
						msg(3, "match_hinfo: match:"
						    " 0x%llx (%d %d) (%d %d)"
						    " (0x%x 0x%x) (0x%llx,"
						    " 0x%llx)\n",
						    hp->addr_cookie,
						    prev->instance,
						    hp->instance, prev->rnumber,
						    hp->rnumber,
						    prev->access_type,
						    hp->access_type, prev->len,
						    hp->len);

					/* it matches so remember it */
					prev = *ip++ = hp;
					scnt += 1;
				}
			}

			if (*nhdls != scnt) {
				/*
				 * Reuse the alloc'ed memory to return
				 * only those handles the user has asked for.
				 * But first prune the handles to get rid of
				 * overlapping ranges (they are ordered by
				 * offset and length).
				 */
				*nhdls = scnt;
				for (i = 0, hp = *hip, ip = chosen; i < scnt;
				    i++, ip++, hp++)
					if (hp != *ip)
						(void) memcpy(hp, *ip,
						    sizeof (*hp));
			}
			free(chosen);
		}

		for (i = 0, hp = *hip; i < *nhdls; i++, hp++) {
			msg(4, "\t%d 0x%x %d 0x%llx 0x%llx 0x%llx\n",
			    hp->instance, hp->access_type, hp->rnumber,
			    hp->len, hp->offset, hp->addr_cookie);
		}
	}
	if (*nhdls == 0 && *hip)
		free(*hip);

	msg(4, "get_info: %s got %d handles\n", name, *nhdls);
	return (0);
}

static void
init_sigs()
{
	struct sigaction sa;
	int *ip, sigs[] = {SIGINT, SIGTERM, 0};

	sa.sa_handler = kill_sighandler;
	(void) sigemptyset(&sa.sa_mask);
	for (ip = sigs; *ip; ip++)
		(void) sigaddset(&sa.sa_mask, *ip);
	sa.sa_flags = 0;
	for (ip = sigs; *ip; ip++)
		(void) sigaction(*ip, &sa, NULL);
}

static void
up_resources()
{
	struct rlimit rl;

	/* Potentially hungry on resources so up them all to their maximums */
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		msg(0, "failed to obtain RLIMIT_NOFILE: %s\n", strerror(errno));
	else {
		msg(12, "RLIMIT_NOFILE\t %lu (%lu)\n",
		    rl.rlim_cur, rl.rlim_max);
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
			msg(0, "failed to set RLIMIT_NOFILE: %s\n",
			    strerror(errno));
		(void) enable_extended_FILE_stdio(-1, -1);
	}
	if (getrlimit(RLIMIT_DATA, &rl) < 0)
		msg(0, "failed to obtain RLIMIT_DATA: %s\n", strerror(errno));
	else {
		msg(12, "RLIMIT_DATA\t %lu (%lu)\n", rl.rlim_cur, rl.rlim_max);
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_DATA, &rl) < 0)
			msg(0, "failed to set RLIMIT_DATA: %s\n",
			    strerror(errno));
	}
	if (getrlimit(RLIMIT_FSIZE, &rl) < 0)
		msg(0, "failed to obtain RLIMIT_FSIZE: %s\n", strerror(errno));
	else {
		msg(12, "RLIMIT_FSIZE\t %lu (%lu)\n", rl.rlim_cur, rl.rlim_max);
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_FSIZE, &rl) < 0)
			msg(0, "failed to set RLIMIT_FSIZE: %s\n",
			    strerror(errno));
	}
}

static FILE *
create_test_file(char *drvname)
{
	char dirname[_POSIX_PATH_MAX];
	char testname[_POSIX_PATH_MAX];
	FILE *fp = 0;
	time_t utc = time(NULL);

	if (snprintf(dirname, sizeof (dirname), "%s.test.%lu",
	    drvname, utc) == -1 ||
	    snprintf(testname, sizeof (testname), "%s.test.%lu",
	    drvname, utc) == -1)
		return (0);

	if (mkdir(dirname, S_IRWXU|S_IRGRP|S_IROTH)) {
		msg(0, "Error creating %s: %s\n", dirname, strerror(errno));
		return (0);
	}
	if (chdir(dirname)) {
		(void) rmdir(dirname);
		return (0);
	}
	if ((fp = fopen(testname, "w")) == 0)
		return (0);	/* leave created directory intact */

	return (fp);
}

struct walk_arg {
	char *path;
	int instance;
	char name[MAXPATHLEN];
	int pathlen;
};

static int
walk_callback(di_node_t node, void *arg)
{
	struct walk_arg *warg = (struct walk_arg *)arg;
	char *driver_name;
	char *path;

	driver_name = di_driver_name(node);
	if (driver_name != NULL) {
		if (strcmp(driver_name, warg->name) == 0 &&
		    di_instance(node) == warg->instance) {
			path = di_devfs_path(node);
			if (path == NULL)
				warg->path = NULL;
			else
				(void) strncpy(warg->path, path, warg->pathlen);
			return (DI_WALK_TERMINATE);
		}
	}
	return (DI_WALK_CONTINUE);
}

static int
getpath(char *path, int instance, char *name, int pathlen)
{
	di_node_t node;
	struct walk_arg warg;

	warg.instance = instance;
	(void) strncpy(warg.name, name, MAXPATHLEN);
	warg.path = path;
	warg.pathlen = pathlen;
	if ((node = di_init("/", DINFOSUBTREE)) == DI_NODE_NIL)
		return (-1);
	if (di_walk_node(node, DI_WALK_CLDFIRST, &warg, walk_callback) == -1) {
		di_fini(node);
		return (-1);
	}
	if (warg.path == NULL) {
		di_fini(node);
		return (-1);
	}
	di_fini(node);
	return (0);
}

/*
 * Record logsize h/w accesses of type 'edp->access_type' made by instance
 * 'edp->instance' of driver 'edp->name' to the register set (or dma handle)
 * 'edp->rnumber' that lie within the range 'edp->offset' to
 * 'edp->offset' + 'edp->len'.
 * Access criteria may be mixed and matched:
 * -	access types may be combined (PIO read/write, DMA read write or intrs);
 * -	if 'edp->instance' is -1 all instances are checked for the criteria;
 * -	if 'edp->rnumber' is -1 all register sets and dma handles are matched;
 * -	'offset' and 'len' indicate that only PIO and DMA accesses within the
 *	range 'edp->offset' to 'edp->len' will be logged. Putting 'edp->offset'
 *      to zero and 'edp->len' to -1ull gives maximal coverage.
 *
 * 'collecttime' is the number of seconds used to log accesses
 *		(default is infinity).
 */
static void
test_driver(struct bofi_errdef *edp,
    unsigned long long collecttime)
{
	pid_t pid;
	int statloc;
	struct collector_def *cdefs, *cdp;
	struct handle_info *hdls, *hdl;
	int i, fd;
	size_t cnt;
	size_t nchildren;
	unsigned long long timechunk;
	FILE *sfp;	/* generated control test file */
	char buf[MAXPATHLEN];
	char devpath[MAXPATHLEN];
	char *devpathp = "NULL";
	int drv_inst;
	int got_it = 0;

	char *name = (char *)edp->name;
	uint_t logsize = edp->access_count + edp->fail_count - 1;
	int inst = edp->instance;
	uint_t atype = edp->access_type;
	int rset = edp->rnumber;
	offset_t offset = edp->offset;
	offset_t len = edp->len;

	msg(4, "test_driver: %s %d inst %d 0x%x rset %d %llx %llx\n",
	    name, logsize, inst, atype, rset, offset, len);

	drv_inst = inst;
	if (getpath(devpath, inst, name, MAXPATHLEN) != -1) {
		devpathp = devpath;
		got_it = 1;
	}
	if (logsize == -1U)
		logsize = 0;
	fd = open(BOFI_DEV, O_RDWR);
	if (fd == -1) {
		perror("get_hdl_info - bad open of bofi driver");
		return;
	}
	if (got_it) {
		(void) snprintf(buf, sizeof (buf),
		    "th_manage /devices%s offline", devpathp);
		(void) system(buf);
		(void) snprintf(buf, sizeof (buf),
		    "th_manage /devices%s online", devpathp);
		(void) system(buf);
		(void) snprintf(buf, sizeof (buf),
		    "th_manage /devices%s getstate >/dev/null", devpathp);
		(void) system(buf);
	}
	if (get_hinfo(fd, name, &hdls, &cnt,
	    inst, atype, rset, offset, len, 1) != 0) {
		msg(0, "driver_test: bad get_info for %d hdls\n", cnt);
		return;
	} else if (logsize == 0 || collecttime == 0 || cnt == 0) {
		if (cnt == 0)
			msg(1, "No matching handles.\n");
		return;
	}
	if ((cdefs = GETSTRUCT(struct collector_def, cnt)) == 0) {
		msg(0, "driver_test: can't get memory for %d cdefs\n", cnt);
		return;
	}
	up_resources();
	if (got_it) {
		if (scriptargs > 0) {
			(void) snprintf(buf, sizeof (buf),
			    "DRIVER_PATH=/devices%s DRIVER_INSTANCE=%d"
			    " DRIVER_UNCONFIGURE=0 DRIVER_CONFIGURE=1",
			    devpathp, drv_inst);
			for (i = 0; i < scriptargs; i++) {
				(void) strcat(buf, " ");
				(void) strcat(buf, fixup_script[i]);
			}
			(void) strcat(buf, " &");
		} else {
			(void) snprintf(buf, sizeof (buf),
			    "while : ; do th_manage /devices%s online;"
			    " th_manage /devices%s getstate >/dev/null;"
			    " th_manage /devices%s offline;done &"
			    " echo $! >/tmp/bofi.pid",
			    devpathp, devpathp, devpathp);
		}
		(void) system(buf);
		(void) snprintf(buf, sizeof (buf), "sleep %d",
		    edef_sleep ? edef_sleep : DEFAULT_EDEF_SLEEP);
		(void) system(buf);
	}

	(void) fprintf(outfile,
	    "Logging accesses to instances ");
	for (i = 0, inst = -1, hdl = hdls; i < cnt;
	    i++, hdl++) {
		if (inst != hdl->instance) {
			inst = hdl->instance;
			(void) fprintf(outfile, "%d ", inst);
		}
	}
	(void) fprintf(outfile, " (%d logs of size 0x%x).\n\t"
	    "(Use th_manage ... clear_errdefs to terminate"
	    " logging)\n", cnt, logsize);

	sfp = create_test_file(name);
	/*
	 * Install a logging errdef for each matching handle,
	 * and then create a child to collect the log.
	 * The child is responsible for activating the log.
	 */
	for (i = 0, cdp = cdefs, hdl = hdls, nchildren = 0;
	    i < cnt; i++, cdp++, hdl++) {
		if (add_edef(fd, &cdp->ed, &cdp->es, hdl, edp) != 0) {
			cdp->lp = 0;
			cdp->pid = 0;
		} else {
			cdp->lp = (void *)cdp->ed.log.logbase;
			msg(1, "test_driver: thr_create:"
			    " lsize 0x%x 0x%x at 0x%x\n",
			    cdp->es.log.logsize,
			    cdp->ed.log.logsize,
			    cdp->ed.access_type);
			if ((pid = fork()) == -1) {
				msg(0, "fork failed for handle"
				    " %d: %s\n", i, strerror(errno));
				cdp->pid = 0;	/* ignore */
			} else if (pid == 0) {
				thr_collect(cdp, devpathp);
			} else {
				cdp->pid = pid;
				nchildren += 1;
			}
		}
	}

	if (nchildren != 0) {
		if (sfp) {
			(void) fprintf(sfp, "#!/bin/ksh -p\n\n");
			(void) fprintf(sfp,
			    "\n# Test control script generated using:\n#");
			for (i = 0; i < pargc; i++)
				(void) fprintf(sfp, " %s", pargv[i]);
			(void) fprintf(sfp, "\n\n");
			(void) fprintf(sfp, "\nrun_tests()\n{\n");
			for (i = 0, cdp = cdefs; i < cnt; i++, cdp++)
				if (cdp->pid) {
					(void) fprintf(sfp,
					    "\tif [ -x ./%s.%d ]\n\tthen\n",
					    name, (int)cdp->pid);
					(void) fprintf(sfp,
					    "\t\techo \"Starting test"
					    " %d (id %d)\"\n",
					    i, (int)cdp->pid);
					(void) fprintf(sfp, "\t\t./%s.%d\n",
					    name, (int)cdp->pid);
					(void) fprintf(sfp, "\t\techo \""
					    "Test %d (id %d) complete\"\n",
					    i, (int)cdp->pid);
					(void) fprintf(sfp, "\tfi\n");
				}
			(void) fprintf(sfp, "}\n\nrun_tests\n");
			if (fchmod(fileno(sfp), S_IRWXU|S_IRGRP|S_IROTH))
				msg(0, "fchmod on control script failed: %s\n",
				    strerror(errno));
			if (fclose(sfp) != 0)
				msg(0, "Error closing control script: %s\n",
				    strerror(errno));
		}

		set_handler(SIGALRM);	/* handle it */
		/*
		 * The user may want to terminate logging before the log fills
		 * so use a timer to signal the logging children to handle this
		 * case.
		 */
		timechunk = collecttime / MAXALRMCALL;
		collecttime = collecttime - timechunk * MAXALRMCALL;

		msg(2, "logging for (0x%llx 0x%llx)\n", timechunk, collecttime);

		(void) alarm(collecttime); /* odd bit of collect time */

		/* wait for the log to fill or deadline satisfied */
		for (;;) {
			pid = wait(&statloc);
			for (i = 0, nchildren = 0, cdp = cdefs;
			    i < cnt; i++, cdp++)
				if (cdp->pid == pid)
					cdp->pid = 0;
			for (i = 0, nchildren = 0, cdp = cdefs;
			    i < cnt; i++, cdp++)
				if (cdp->pid)
					nchildren++;
			if (nchildren == 0)
				break;
			if (killed)
				break;
			if (alarmed) {
				if (timechunk-- > 0) {
					/*
					 * prepare for the next timeslice by
					 * rearming the clock
					 */
					if (alarm(MAXALRMCALL) == 0)
						alarmed = 0;
					else {
						/*
						 * must have been a user abort
						 * (via SIGALRM)
						 */
						(void) alarm(0);
						break;
					}
				} else
					break;
			}
		}

		(void) fprintf(outfile, "Logging complete.\n");
	}
	if (got_it) {
		if (scriptargs > 0) {
			(void) snprintf(buf, sizeof (buf),
			    "DRIVER_PATH=/devices%s DRIVER_INSTANCE=%d"
			    " DRIVER_UNCONFIGURE=1 DRIVER_CONFIGURE=0",
			    devpathp, drv_inst);
			for (i = 0; i < scriptargs; i++) {
				(void) strcat(buf, " ");
				(void) strcat(buf, fixup_script[i]);
			}
			(void) system(buf);
		} else {
			(void) system("kill `cat /tmp/bofi.pid`");
		}
	}
	msg(2, "test_driver: terminating\n");
}

static int
getnameinst(char *orig_path, int *instance, char *name, int namelen)
{
	di_node_t node;
	char *binding_name;

	if ((node = di_init(&orig_path[8], DINFOSUBTREE|DINFOMINOR)) ==
	    DI_NODE_NIL)
		return (-1);
	if ((binding_name = di_driver_name(node)) == NULL)
		return (-1);
	*instance = di_instance(node);
	(void) strncpy(name, binding_name, namelen);
	di_fini(node);
	return (0);
}

static char syntax[] =
	"          [ -n name [ -i instance ] | -P path ]\n"
	"          [ -a acc_types ] [ -r rnumber ]\n"
	"          [ -l offset [ length ] ] [ -c count [ failcount ] ]\n"
	"          [ -o operator [ operand ] ] [ -f acc_chk  ]\n"
	"          [ -w max_wait_period [ report_interval ] ]\n"
	"     or\n"
	"          [ -n name [ -i instance ] | -P path ]\n"
	"          -a  LOG  [  acc_types ]  [ -r rnumber]\n"
	"          [ -l offset [ length ] ] [ -c count [ failcount ] ]\n"
	"          [ -s collect_time ] [ -p policy ] [ -x flags ]\n"
	"          [ -C ] [-e fixup_script ]\n"
	"     or\n"
	"          -h";

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;

	char	c;		/* for parsing getopts */
	int	nopts = 0;	/* for backward compatibility */
	int	err = 0;

	/* use a maximal set of defaults for logging or injecting */
	struct bofi_errdef errdef = {
		0,		/* length of driver name */
		{0},		/* driver name */
		-1,		/* monitor all instances */
		-1,		/* monitor all register sets and DMA handles */
		(offset_t)0,	/* monitor from start of reg. set or DMA hd */
		myLLMAX,	/* monitor whole reg set or DMA hdl(no LLMAX) */
		0,		/* qualify all */
		DFLTLOGSZ,	/* default no. of accesses before corrupting */
		0u,		/* default no. of accesses to corrupt */
		0u,		/* no check access corruption */
		BOFI_NOP,	/* no corruption operator by default */
		myULLMAX,	/* default operand */
		{0, 0, BOFI_LOG_TIMESTAMP, /* timestamp by default */
		0, 0, 0, 0},	/* no logging by default */
		0};


	/* specify the default no of seconds for which to monitor */
	unsigned long long	collecttime = DFLTLOGTIME;

	char	*str;	/* temporary variable */
	long	tmpl;	/* another one */
	int		i;
	uint_t	tmpui;

	char buf[MAXPATHLEN];

	Progname = (char *)strrchr(*argv, '/');
	Progname = (Progname == NULL) ? *argv : Progname + 1;

	errfile = stderr;
	outfile = stdout;
	policy = 0;
	lsize_is_default = 1;
	pargv = argv;
	pargc = argc;

	while ((c = getopt(argc, argv, "a:c:C:dD:e:f:h:i:l:n:o:p:P:r:s:tw:x"))
	    != EOF) {
		nopts++;
		switch (c) {
		case 'a':
			msg(2, "option a: optarg %s optind %d argc %d\n",
			    optarg, optind, argc);
			if ((err = str_to_bm(optarg, atypes,
			    &errdef.access_type)) == 0)
				while (optind < argc && *argv[optind] != '-') {
					if ((err = str_to_bm(argv[optind++],
					    atypes, &errdef.access_type)))
						break;
				}
			break;
		case 'c':
			lsize_is_default = 0;
			/* zero is valid */
			errdef.access_count = strtoul(optarg, &str, 0);
			if (str == optarg)
				err = EINVAL;
			else if (optind < argc && (argv[optind][0] != '-' ||
			    (strlen(argv[optind]) > 1 &&
			    isdigit(argv[optind][1]))))
				errdef.fail_count =
				    strtoull(argv[optind++], 0, 0);
			break;
		case 'C':
			user_comment = optarg;
			if (optind < argc && argv[optind][0] != '-')
				err = EINVAL;
			break;
		case 'D':
			dbglvl = strtoul(optarg, &str, 0);
			break;
		case 'e':
			fixup_script = 0;
			scriptargs = 0;
			fixup_script = &argv[optind - 1];
			scriptargs += 1;
			while (optind < argc) {
				optind += 1;
				scriptargs += 1;
			}
			break;
		case 'f':
			tmpl = strtol(optarg, &str, 0);

			if (str != optarg)
				errdef.acc_chk = tmpl;
			else if (strcmp(optarg, "PIO") == 0)
				errdef.acc_chk = 1;
			else if (strcmp(optarg, "DMA") == 0)
				errdef.acc_chk = 2;
			else if (strcmp(optarg, "U4FT_ACC_NO_PIO") == 0)
				errdef.acc_chk = 1;
			else if (strcmp(optarg, "U4FT_ACC_NO_DMA") == 0)
				errdef.acc_chk = 2;
			else
				err = EINVAL;
			break;
		case 'i':
			if ((errdef.instance = strtol(optarg, &str, 0)) < 0)
				errdef.instance = -1;
			else if (str == optarg)
				err = EINVAL;
			break;
		case 'l':
			errdef.offset = strtoull(optarg, &str, 0);
			if (str == optarg)
				err = EINVAL;
			else if (optind < argc &&
			    (argv[optind][0] != '-' ||
			    (strlen(argv[optind]) > 1 &&
			    isdigit(argv[optind][1])))) {
				/* -1 indicates the rest of register set */
				errdef.len = strtoull(argv[optind++], 0, 0);
			}
			break;
		case 'n':
			(void) strncpy(errdef.name, optarg, MAXNAMELEN);
			if ((errdef.namesize = strlen(errdef.name)) == 0)
				err = EINVAL;
			break;
		case 'o':
			for (i = 0; optypes[i].str != 0; i++)
				if (strcmp(optarg, optypes[i].str) == 0) {
					errdef.optype = optypes[i].code;
					break;
				}
			if (optypes[i].str == 0)
				err = EINVAL;
			else if (optind < argc &&
			    (argv[optind][0] != '-' ||
			    (strlen(argv[optind]) > 1 &&
			    isdigit(argv[optind][1]))))
				errdef.operand =
				    strtoull(argv[optind++], 0, 0);
			break;
		case 'p':
			tmpui = 0x0u;
			if ((err = str_to_bm(optarg, ptypes, &tmpui)) == 0) {
				while (optind < argc && *argv[optind] != '-')
					if ((err = str_to_bm(argv[optind++],
					    ptypes, &tmpui)))
						break;
				policy = (uint16_t)tmpui;
			}
			if (err == 0 && (policy & BYTEPOLICY))
				errdef.log.flags |= BOFI_LOG_REPIO;
			break;
		case 'P':
			if (getnameinst(optarg, &errdef.instance, buf,
			    MAXPATHLEN) == -1)
				err = EINVAL;
			else
				(void) strncpy(errdef.name, buf, MAXNAMELEN);
			break;
		case 'r':
			if ((errdef.rnumber = strtol(optarg, &str, 0)) < 0)
				errdef.rnumber = -1;
			if (str == optarg) err = EINVAL;
			break;
		case 's':
			collecttime = strtoull(optarg, &str, 0);
			if (str == optarg)
				err = EINVAL;	/* zero is valid */
			break;
		case 'w':
			do_status = 1;
			max_edef_wait = strtoul(optarg, &str, 0);
			/* zero is valid */
			if (str == optarg)
				err = EINVAL;
			else if (optind < argc &&
			    (argv[optind][0] != '-' ||
			    (strlen(argv[optind]) > 1 &&
			    isdigit(argv[optind][1]))))
				edef_sleep = strtoull(argv[optind++], 0, 0);

			break;
		case 'x':
			if ((optind < argc && *argv[optind] == '-') ||
			    optind == argc)
				errdef.log.flags |= BOFI_LOG_WRAP;
			else {
				if (strchr(argv[optind], 'w') != 0)
					errdef.log.flags |= BOFI_LOG_WRAP;
				if (strchr(argv[optind], 'r') != 0)
					errdef.log.flags |= BOFI_LOG_REPIO;
				if (strchr(argv[optind], 't') != 0)
					errdef.log.flags |= BOFI_LOG_TIMESTAMP;
				if (strstr(argv[optind], "~t") != 0)
					errdef.log.flags &= ~BOFI_LOG_TIMESTAMP;
				optind++;
			}
			break;
		case 'h':
			(void) fprintf(errfile, "usage: %s %s\n",
			    Progname, syntax);
			exit(0);
			break;
		case '?':	/* also picks up missing parameters */
		default:
			(void) fprintf(errfile, "usage: %s %s\n",
			    Progname, syntax);
			exit(2);
		}

		if (err) {
			(void) fprintf(errfile, "usage: %s %s\n",
			    Progname, syntax);
			exit(2);
		}
		if (c == 'e')
			break;	/* the -e option must be the final option */
	}


	if (errdef.name[0] == 0) {
		msg(0, "%s - invalid name parameter\n", Progname);
		exit(1);
	}
	errdef.namesize = strlen(errdef.name);

	if (policy == 0) {
		policy |= UNBIASEDPOLICY;
		policy |= OPERATORSPOLICY;
	}

	if (errdef.optype == BOFI_NOP)
		errdef.optype = BOFI_XOR;
	if (errdef.access_type == BOFI_LOG) { /* qualify all accesses */
		errdef.access_type =
		    (BOFI_LOG|BOFI_DMA_RW|BOFI_PIO_RW|BOFI_INTR);
		atype_is_default = 1;
	} else if (errdef.access_type == 0) { /* qualify all accesses */
		errdef.access_type =
		    (BOFI_DMA_RW|BOFI_PIO_RW|BOFI_INTR);
		atype_is_default = 1;
	} else
		atype_is_default = 0;

	init_sigs();
	if ((errdef.access_type & BOFI_LOG) == 0) {
		int fd, i, instance;
		size_t cnt;
		struct handle_info *hdls, *hp;

		if ((fd = open(BOFI_DEV, O_RDWR)) == -1) {
			msg(0, "%s: error opening bofi driver: %s\n",
			    Progname, strerror(errno));
			exit(1);
		}
		if ((err = get_hinfo(fd, errdef.name, &hdls, &cnt,
		    errdef.instance, errdef.access_type, errdef.rnumber,
		    errdef.offset, errdef.len, 0)) != 0) {
			msg(0, "%s: Bad lookup on bofi driver.\n", Progname);
			(void) close(fd);
			exit(1);
		} else if (cnt == 0) {
			msg(0,
			    "%s: No handles match request access criteria.\n",
			    Progname);
			(void) close(fd);
			exit(1);
		}
		if (errdef.instance == -1)
			instance = -1;
		else {
			instance = hdls->instance;
			for (i = 0, hp = hdls; i < cnt; i++, hp++) {
				if (instance != hp->instance) {
					instance = -1;
					break;
				}
			}
		}
		if (instance == -1) {
			msg(0, "Multiple instances match access criteria"
			    " (only allowed when logging):\n");
			msg(0, "\tinst\taccess\trnumber\toffset\tlength\n");
			for (i = 0, hp = hdls; i < cnt; i++, hp++)
				msg(0, "\t%d\t0x%x\t%d\t0x%llx\t0x%llx\n",
				    hp->instance, hp->access_type,
				    hp->rnumber, hp->offset, hp->len);
		} else {
			struct bofi_errstate es;
			int timeleft = max_edef_wait;

			if (ioctl(fd, BOFI_ADD_DEF, &errdef) == -1) {
				perror("th_define - adding errdef failed");
			} else {
				es.errdef_handle = errdef.errdef_handle;
				msg(4, "waiting for edef:"
				    " %d %s %d %d 0x%llx 0x%llx 0x%x 0x%x"
				    " 0x%x 0x%x 0x%x 0x%llx\n",
				    errdef.namesize, errdef.name,
				    errdef.instance, errdef.rnumber,
				    errdef.offset, errdef.len,
				    errdef.access_type, errdef.access_count,
				    errdef.fail_count, errdef.acc_chk,
				    errdef.optype, errdef.operand);

				set_handler(SIGALRM);	/* handle it */

				do {
					if (do_status)
						(void) alarm(edef_sleep);
					if (ioctl(fd, BOFI_CHK_STATE_W,
					    &es) == -1) {
						if (errno != EINTR) {
							perror("bad"
							    " BOFI_CHK_STATE");
							break;
						} else if (!do_status) {
							break;
						}
					}
					if (do_status)
						(void) fprintf(outfile,
						    "%llu:%llu:%u:%u:%u:"
						    "%u:%d:\"%s\"\n",
						    es.fail_time, es.msg_time,
						    es.access_count,
						    es.fail_count,
						    es.acc_chk, es.errmsg_count,
						    (uint_t)es.severity,
						    (es.msg_time) ?
						    es.buffer : "");
					if (es.acc_chk == 0 &&
					    es.fail_count == 0 && !do_status)
						print_err_reports(outfile,
						    &es, "", "", -1);
					else if (alarmed) {
						alarmed = 0;
						if ((timeleft -= edef_sleep) <=
						    0) {
							if (do_status)
								break;
							print_err_reports(
							    outfile, &es, "",
							    "", -1);
							break;
						}
					} else if (!do_status)
						print_err_reports(outfile,
						    &es, "", "", -1);
				} while (es.acc_chk != 0 || es.fail_count != 0);

				msg(2, "done: acc_chk 0x%x fcnt %d\n",
				    es.acc_chk, es.fail_count);
			}

			(void) close(fd);
		}
		free(hdls);
		return (0);
	}
	test_driver(&errdef, collecttime);
	return (0);
}
