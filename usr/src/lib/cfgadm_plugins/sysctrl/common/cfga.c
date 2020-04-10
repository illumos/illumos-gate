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
#include <locale.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <langinfo.h>
#include <time.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/dditypes.h>
#include <sys/modctl.h>
#include <sys/obpdefs.h>
#include <sys/fhc.h>
#include <sys/sysctrl.h>
#include <sys/openpromio.h>
#ifdef	SIM
#include <sys/stat.h>
#endif
#define	CFGA_PLUGIN_LIB
#include <config_admin.h>

#ifdef	DEBUG
#define	DBG	printf
#define	DBG1	printf
#define	DBG3	printf
#define	DBG4	printf
#else
#define	DBG(a, b)
#define	DBG1(a)
#define	DBG3(a, b, c)
#define	DBG4(a, b, c, d)
#endif

#define	BD_CPU			1
#define	BD_MEM			2
#define	BD_IO_2SBUS		3
#define	BD_IO_SBUS_FFB		4
#define	BD_IO_PCI		5
#define	BD_DISK			6
#define	BD_IO_2SBUS_SOCPLUS	7
#define	BD_IO_SBUS_FFB_SOCPLUS	8
#define	BD_UNKNOWN		9
#define	CMD_GETSTAT		10
#define	CMD_LIST		11
#define	CMD_CONNECT		12
#define	CMD_DISCONNECT		13
#define	CMD_CONFIGURE		14
#define	CMD_UNCONFIGURE		15
#define	CMD_QUIESCE		16
#define	CMD_INSERT		17
#define	CMD_REMOVE		18
#define	CMD_SET_COND		19
#define	OPT_ENABLE		20
#define	OPT_DISABLE		21
#define	ERR_PROM_OPEN		22
#define	ERR_PROM_GETPROP	23
#define	ERR_PROM_SETPROP	24
#define	ERR_TRANS		25
#define	ERR_CMD_INVAL		26
#define	ERR_OPT_INVAL		27
#define	ERR_AP_INVAL		28
#define	ERR_DISABLED		29
#define	DIAG_FORCE		30
#define	DIAG_TRANS_OK		31
#define	DIAG_FAILED		32
#define	DIAG_WAS_ENABLED	33
#define	DIAG_WAS_DISABLED	34
#define	DIAG_WILL_ENABLE	35
#define	DIAG_WILL_DISABLE	36
#define	HELP_HEADER		37
#define	HELP_QUIESCE		38
#define	HELP_INSERT		39
#define	HELP_REMOVE		40
#define	HELP_SET_COND		41
#define	HELP_ENABLE		42
#define	HELP_DISABLE		43
#define	HELP_UNKNOWN		44
#define	ASK_CONNECT		45
#define	STR_BD			46
#define	STR_COL			47
#define	COND_UNKNOWN		48
#define	COND_OK			49
#define	COND_FAILING		50
#define	COND_FAILED		51
#define	COND_UNUSABLE		52
#define	SYSC_COOLING		53
#define	SYSC_POWER		54
#define	SYSC_PRECHARGE		55
#define	SYSC_INTRANS		56
#define	SYSC_UTHREAD		57
#define	SYSC_KTHREAD		58
#define	SYSC_DEV_ATTACH		59
#define	SYSC_DEV_DETACH		60
#define	SYSC_NDI_ATTACH		61
#define	SYSC_NDI_DETACH		62
#define	SYSC_CORE_RESOURCE	63
#define	SYSC_OSTATE		64
#define	SYSC_RSTATE		65
#define	SYSC_COND		66
#define	SYSC_PROM		67
#define	SYSC_NOMEM		68
#define	SYSC_HOTPLUG		69
#define	SYSC_HW_COMPAT		70
#define	SYSC_NON_DR_PROM	71
#define	SYSC_SUSPEND		72
#define	SYSC_RESUME		73
#define	SYSC_UNKNOWN		74
#define	SYSC_DEVSTR		75

/*
 * The string table contains all the strings used by the platform
 * library.  The comment next to each string specifies whether the
 * string should be internationalized (y) or not (n).
 * Note that there are calls to dgettext() with strings other than
 * the ones below, they are marked by the li18 symbol.
 */
static char *
cfga_strs[] = {
	/*   */ NULL,
	/* n */ "cpu/mem   ",
	/* n */ "mem       ",
	/* n */ "dual-sbus ",
	/* n */ "sbus-upa  ",
	/* n */ "dual-pci  ",
	/* n */ "disk      ",
	/* n */ "soc+sbus  ",
	/* n */ "soc+upa   ",
	/* n */ "unknown   ",
	/* n */ "get-status",
	/* n */ "list",
	/* n */ "connect",
	/* n */ "disconnect",
	/* n */ "configure",
	/* n */ "unconfigure",
	/* n */ "quiesce-test",
	/* n */ "insert-test",
	/* n */ "remove-test",
	/* n */ "set-condition-test",
	/* n */ "enable-at-boot",
	/* n */ "disable-at-boot",
	/* n */ "prom open",
	/* n */ "prom getprop",
	/* n */ "prom setprop",
	/* y */ "invalid transition",
	/* y */ "invalid command: ",
	/* y */ "invalid option: ",
	/* y */ "invalid attachment point: ",
	/* y */ "board is disabled: must override with ",
	/* n */ "[-f][-o enable-at-boot]",
	/* y */ "transition succeeded but ",
	/* y */ " failed: ",
	/* y */ "was already enabled at boot time",
	/* y */ "was already disabled at boot time",
	/* y */ "will be enabled at boot time",
	/* y */ "will be disabled at boot time",
	/* y */ "\nSysctrl specific commands/options:",
	/* n */ "\t-x quiesce-test ap_id [ap_id...]",
	/* n */ "\t-x insert-test  ap_id [ap_id...]",
	/* n */ "\t-x remove-test  ap_id [ap_id...]",
	/* n */ "\t-x set-condition-test=<condition>",
	/* n */ "\t-o enable-at-boot",
	/* n */ "\t-o disable-at-boot",
	/* y */ "\tunknown command or option: ",
	/* y */
	"system will be temporarily suspended to connect a board: proceed",
	/* y */ "board ",
	/* y */ ": ",
	/* n */ "unknown",
	/* n */ "ok",
	/* n */ "failing",
	/* n */ "failed",
	/* n */ "unusable",
	/* y */ "not enough cooling for a new board",
	/* y */ "not enough power for a new board",
	/* y */ "not enough precharge power for a new board",
	/* y */ "configuration operation already in progress on this board",
	/* y */ "could not suspend user process: ",
	/* y */ "could not suspend system processes",
	/* y */ "device did not attach",
	/* y */ "device did not detach",
	/* y */ "nexus error during attach",
	/* y */ "nexus error during detach",
	/* y */ "attempt to remove core system resource",
	/* y */ "invalid occupant state",
	/* y */ "invalid receptacle state",
	/* y */ "insufficient condition",
	/* y */ "firmware operation error",
	/* y */ "not enough memory",
	/* y */ "hotplug feature unavailable on this machine",
	/* y */ "board does not support dynamic reconfiguration",
	/* y */ "firmware does not support dynamic reconfiguration",
	/* y */ "system suspend error",
	/* y */ "system resume error",
	/* y */ "unknown system error",
	/*   */ NULL
};

#define	cfga_str(i)		cfga_strs[(i)]

#define	cfga_eid(a, b)		(((a) << 8) + (b))

/*
 *
 *	Translation table for mapping from an <errno,sysc_err>
 *	pair to an error string.
 *
 *
 *	SYSC_COOLING,		EAGAIN,  SYSC_ERR_COOLING
 *	SYSC_POWER,		EAGAIN,  SYSC_ERR_POWER
 *	SYSC_PRECHARGE,		EAGAIN,  SYSC_ERR_PRECHARGE
 *	SYSC_INTRANS,		EBUSY,   SYSC_ERR_INTRANS
 *	SYSC_KTHREAD,		EBUSY,   SYSC_ERR_KTHREAD
 *	SYSC_DEV_ATTACH,	EBUSY,   SYSC_ERR_NDI_ATTACH
 *	SYSC_DEV_DETACH,	EBUSY,   SYSC_ERR_NDI_DETACH
 *	SYSC_NDI_ATTACH,	EFAULT,  SYSC_ERR_NDI_ATTACH
 *	SYSC_NDI_DETACH,	EFAULT,  SYSC_ERR_NDI_DETACH
 *	SYSC_CORE_RESOURCE,	EINVAL,  SYSC_ERR_CORE_RESOURCE
 *	SYSC_OSTATE,		EINVAL,  SYSC_ERR_OSTATE
 *	SYSC_RSTATE,		EINVAL,  SYSC_ERR_RSTATE
 *	SYSC_COND,		EINVAL,  SYSC_ERR_COND
 *	SYSC_PROM,		EIO,     SYSC_ERR_PROM
 *	SYSC_NOMEM,		ENOMEM,  SYSC_ERR_DR_INIT
 *	SYSC_NOMEM,		ENOMEM,  SYSC_ERR_NDI_ATTACH
 *	SYSC_NOMEM,		ENOMEM,  SYSC_ERR_NDI_DETACH
 *	SYSC_HOTPLUG,		ENOTSUP, SYSC_ERR_HOTPLUG
 *	SYSC_HW_COMPAT,		ENOTSUP, SYSC_ERR_HW_COMPAT
 *	SYSC_NON_DR_PROM,	ENOTSUP, SYSC_ERR_NON_DR_PROM
 *	SYSC_SUSPEND,		ENXIO,   SYSC_ERR_SUSPEND
 *	SYSC_RESUME,		ENXIO,   SYSC_ERR_RESUME
 *	SYSC_UTHREAD,		ESRCH,   SYSC_ERR_UTHREAD
 */
static int
cfga_sid(int err, int scerr)
{
	if (scerr == SYSC_ERR_DEFAULT)
		return (SYSC_UNKNOWN);

	switch (cfga_eid(err, scerr)) {
	case cfga_eid(EAGAIN, SYSC_ERR_COOLING):
		return (SYSC_COOLING);
	case cfga_eid(EAGAIN, SYSC_ERR_POWER):
		return (SYSC_POWER);
	case cfga_eid(EAGAIN, SYSC_ERR_PRECHARGE):
		return (SYSC_PRECHARGE);
	case cfga_eid(EBUSY, SYSC_ERR_INTRANS):
		return (SYSC_INTRANS);
	case cfga_eid(EBUSY, SYSC_ERR_KTHREAD):
		return (SYSC_KTHREAD);
	case cfga_eid(EBUSY, SYSC_ERR_NDI_ATTACH):
		return (SYSC_DEV_ATTACH);
	case cfga_eid(EBUSY, SYSC_ERR_NDI_DETACH):
		return (SYSC_DEV_DETACH);
	case cfga_eid(EFAULT, SYSC_ERR_NDI_ATTACH):
		return (SYSC_NDI_ATTACH);
	case cfga_eid(EFAULT, SYSC_ERR_NDI_DETACH):
		return (SYSC_NDI_DETACH);
	case cfga_eid(EINVAL, SYSC_ERR_CORE_RESOURCE):
		return (SYSC_CORE_RESOURCE);
	case cfga_eid(EINVAL, SYSC_ERR_OSTATE):
		return (SYSC_OSTATE);
	case cfga_eid(EINVAL, SYSC_ERR_RSTATE):
		return (SYSC_RSTATE);
	case cfga_eid(EINVAL, SYSC_ERR_COND):
		return (SYSC_COND);
	case cfga_eid(EIO, SYSC_ERR_PROM):
		return (SYSC_PROM);
	case cfga_eid(ENOMEM, SYSC_ERR_DR_INIT):
		return (SYSC_NOMEM);
	case cfga_eid(ENOMEM, SYSC_ERR_NDI_ATTACH):
		return (SYSC_NOMEM);
	case cfga_eid(ENOMEM, SYSC_ERR_NDI_DETACH):
		return (SYSC_NOMEM);
	case cfga_eid(ENOTSUP, SYSC_ERR_HOTPLUG):
		return (SYSC_HOTPLUG);
	case cfga_eid(ENOTSUP, SYSC_ERR_HW_COMPAT):
		return (SYSC_HW_COMPAT);
	case cfga_eid(ENOTSUP, SYSC_ERR_NON_DR_PROM):
		return (SYSC_NON_DR_PROM);
	case cfga_eid(ENXIO, SYSC_ERR_SUSPEND):
		return (SYSC_SUSPEND);
	case cfga_eid(ENXIO, SYSC_ERR_RESUME):
		return (SYSC_RESUME);
	case cfga_eid(ESRCH, SYSC_ERR_UTHREAD):
		return (SYSC_UTHREAD);
	default:
		break;
	}

	return (SYSC_UNKNOWN);
}

static void
sysc_cmd_init(sysc_cfga_cmd_t *sc, char *outputstr, int force)
{
	sc->force = force;
	sc->outputstr = outputstr;
	sc->errtype = SYSC_ERR_DEFAULT;

	(void) memset((void *)outputstr, 0, sizeof (outputstr));

	cfga_str(SYSC_DEVSTR) = outputstr;
}

/*
 * cfga_err() accepts a variable number of message IDs and constructs
 * a corresponding error string which is returned via the errstring argument.
 * cfga_err() calls dgettext() to internationalize proper messages.
 */
static void
cfga_err(sysc_cfga_cmd_t *sc, char **errstring, ...)
{
	int a;
	int i;
	int n;
	int len;
	int flen;
	char *p;
	char *q;
	char *s[32];
	char *failed;
	va_list ap;
	char syserr_num[20];

	/*
	 * If errstring is null it means user in not interested in getting
	 * error status. So we don't do all the work
	 */
	if (errstring == NULL) {
		return;
	}
	va_start(ap, errstring);

	failed = dgettext(TEXT_DOMAIN, cfga_str(DIAG_FAILED));
	flen = strlen(failed);

	for (n = len = 0; (a = va_arg(ap, int)) != 0; n++) {

		switch (a) {
		case ERR_PROM_OPEN:
		case ERR_PROM_GETPROP:
		case ERR_PROM_SETPROP:
		case CMD_GETSTAT:
		case CMD_LIST:
		case CMD_CONNECT:
		case CMD_DISCONNECT:
		case CMD_CONFIGURE:
		case CMD_UNCONFIGURE:
		case CMD_QUIESCE:
		case CMD_INSERT:
		case CMD_REMOVE:
		case CMD_SET_COND:
			p =  cfga_str(a);
			len += (strlen(p) + flen);
			s[n] = p;
			s[++n] = failed;

			DBG("<%s>", p);
			DBG("<%s>", failed);
			break;

		case OPT_ENABLE:
		case OPT_DISABLE:
			p = dgettext(TEXT_DOMAIN, cfga_str(DIAG_TRANS_OK));
			q = cfga_str(a);
			len += (strlen(p) + strlen(q) + flen);
			s[n] = p;
			s[++n] = q;
			s[++n] = failed;

			DBG("<%s>", p);
			DBG("<%s>", q);
			DBG("<%s>", failed);
			break;

		case ERR_CMD_INVAL:
		case ERR_AP_INVAL:
		case ERR_OPT_INVAL:
			p =  dgettext(TEXT_DOMAIN, cfga_str(a));
			q = va_arg(ap, char *);
			len += (strlen(p) + strlen(q));
			s[n] = p;
			s[++n] = q;

			DBG("<%s>", p);
			DBG("<%s>", q);
			break;

		case ERR_TRANS:
		case ERR_DISABLED:
			p =  dgettext(TEXT_DOMAIN, cfga_str(a));
			len += strlen(p);
			s[n] = p;

			DBG("<%s>", p);
			break;

		case DIAG_FORCE:
		default:
			p =  cfga_str(a);
			len += strlen(p);
			s[n] = p;

			DBG("<%s>", p);
			break;
		}
	}

	DBG1("\n");
	va_end(ap);

	if (errno) {
		if (sc)
			i = cfga_sid(errno, (int)sc->errtype);
		else
			i = SYSC_UNKNOWN;

		DBG4("cfga_sid(%d,%d)=%d\n", errno, sc->errtype, i);

		if (i == SYSC_UNKNOWN) {
			p = strerror(errno);
			if (p == NULL) {
				(void) sprintf(syserr_num, "errno=%d", errno);
				p = syserr_num;
			}
		} else
			p = dgettext(TEXT_DOMAIN, cfga_str(i));

		len += strlen(p);
		s[n++] = p;
		p = cfga_str(SYSC_DEVSTR);
		if (p && p[0]) {
			q = cfga_str(STR_COL);

			len += strlen(q);
			s[n++] = q;
			len += strlen(p);
			s[n++] = p;
		}
	}

	if ((p = (char *)calloc(len, 1)) == NULL)
		return;

	for (i = 0; i < n; i++)
		(void) strcat(p, s[i]);

	*errstring = p;
#ifdef	SIM_MSG
	printf("%s\n", *errstring);
#endif
}

/*
 * This routine accepts a variable number of message IDs and constructs
 * a corresponding error string which is printed via the message print routine
 * argument.  The HELP_UNKNOWN message ID has an argument string (the unknown
 * help topic) that follows.
 */
static void
cfga_msg(struct cfga_msg *msgp, ...)
{
	int a;
	int i;
	int n;
	int len;
	char *p;
	char *s[32];
	va_list ap;

	va_start(ap, msgp);

	for (n = len = 0; (a = va_arg(ap, int)) != 0; n++) {
		DBG("<%d>", a);
		p =  dgettext(TEXT_DOMAIN, cfga_str(a));
		len += strlen(p);
		s[n] = p;
		if (a == HELP_UNKNOWN) {
			p = va_arg(ap, char *);
			len += strlen(p);
			s[++n] = p;
		}
	}

	va_end(ap);

	if ((p = (char *)calloc(len + 1, 1)) == NULL)
		return;

	for (i = 0; i < n; i++)
		(void) strcat(p, s[i]);
	(void) strcat(p, "\n");

#ifdef	SIM_MSG
	printf("%s", p);
#else
	(*msgp->message_routine)(msgp->appdata_ptr, p);
#endif
	free(p);
}

static sysc_cfga_stat_t *
sysc_stat(const char *ap_id, int *fdp)
{
	int fd;
	static sysc_cfga_stat_t sc_list[MAX_BOARDS];


	if ((fd = open(ap_id, O_RDWR, 0)) == -1)
		return (NULL);
	else if (ioctl(fd, SYSC_CFGA_CMD_GETSTATUS, sc_list) == -1) {
		(void) close(fd);
		return (NULL);
	} else if (fdp)
		*fdp = fd;
	else
		(void) close(fd);

	return (sc_list);
}

/*
 * This code implementes the simulation of the ioctls that transition state.
 * The GETSTAT ioctl is not simulated.  In this way a snapshot of the system
 * state is read and manipulated by the simulation routines.  It is basically
 * a useful debugging tool.
 */
#ifdef	SIM
static int sim_idx;
static int sim_fd = -1;
static int sim_size = MAX_BOARDS * sizeof (sysc_cfga_stat_t);
static sysc_cfga_stat_t sim_sc_list[MAX_BOARDS];

static sysc_cfga_stat_t *
sim_sysc_stat(const char *ap_id, int *fdp)
{
	int fd;
	struct stat buf;

	if (sim_fd != -1)
		return (sim_sc_list);

	if ((sim_fd = open("/tmp/cfga_simdata", O_RDWR|O_CREAT)) == -1) {
		perror("sim_open");
		exit(1);
	} else if (fstat(sim_fd, &buf) == -1) {
		perror("sim_stat");
		exit(1);
	}

	if (buf.st_size) {
		if (buf.st_size != sim_size) {
			perror("sim_size");
			exit(1);
		} else if (read(sim_fd, sim_sc_list, sim_size) == -1) {
			perror("sim_read");
			exit(1);
		}
	} else if ((fd = open(ap_id, O_RDWR, 0)) == -1)
		return (NULL);
	else if (ioctl(fd, SYSC_CFGA_CMD_GETSTATUS, sim_sc_list) == -1) {
		(void) close(fd);
		return (NULL);
	} else if (fdp)
		*fdp = fd;

	return (sim_sc_list);
}

static int
sim_open(char *a, int b, int c)
{
	printf("sim_open(%s)\n", a);

	if (strcmp(a, "/dev/openprom") == 0)
		return (open(a, b, c));
	return (0);
}

static int
sim_close(int a)
{
	return (0);
}

static int
sim_ioctl(int fd, int cmd, void *a)
{
	printf("sim_ioctl(%d)\n", sim_idx);

	switch (cmd) {
	case SYSC_CFGA_CMD_CONNECT:
		sim_sc_list[sim_idx].rstate = SYSC_CFGA_RSTATE_CONNECTED;
		break;
	case SYSC_CFGA_CMD_CONFIGURE:
		sim_sc_list[sim_idx].ostate = SYSC_CFGA_OSTATE_CONFIGURED;
		break;
	case SYSC_CFGA_CMD_UNCONFIGURE:
		sim_sc_list[sim_idx].ostate = SYSC_CFGA_OSTATE_UNCONFIGURED;
		break;
	case SYSC_CFGA_CMD_DISCONNECT:
		sim_sc_list[sim_idx].rstate = SYSC_CFGA_RSTATE_DISCONNECTED;
		break;
	case SYSC_CFGA_CMD_QUIESCE_TEST:
	case SYSC_CFGA_CMD_TEST:
		return (0);
	case OPROMGETOPT:
		return (ioctl(fd, OPROMGETOPT, a));
	case OPROMSETOPT:
		return (ioctl(fd, OPROMSETOPT, a));
	}

	if (lseek(sim_fd, SEEK_SET, 0) == -1) {
		perror("sim_seek");
		exit(1);
	}
	if (write(sim_fd, sim_sc_list, sim_size) == -1) {
		perror("sim_write");
		exit(1);
	}

	return (0);
}

#define	open(a, b, c)	sim_open((char *)(a), (int)(b), (int)(c))
#define	close(a)	sim_close(a)
#define	ioctl(a, b, c)	sim_ioctl((int)(a), (int)(b), (void *)(c))
#define	sysc_stat(a, b)	sim_sysc_stat(a, b)
#endif	/* SIM */

static char *promdev = "/dev/openprom";
static char *dlprop = "disabled-board-list";

#define	BUFSIZE		128

typedef union {
	char buf[BUFSIZE];
	struct openpromio opp;
} oppbuf_t;

static int
prom_get_prop(int prom_fd, char *var, char **val)
{
	static oppbuf_t oppbuf;
	struct openpromio *opp = &(oppbuf.opp);

	(void) strncpy(opp->oprom_array, var, OBP_MAXPROPNAME);
	opp->oprom_array[OBP_MAXPROPNAME + 1] = '\0';
	opp->oprom_size = BUFSIZE;

	DBG3("getprop(%s, %d)\n", opp->oprom_array, opp->oprom_size);

	if (ioctl(prom_fd, OPROMGETOPT, opp) < 0)
		return (ERR_PROM_GETPROP);
	else if (opp->oprom_size > 0)
		*val = opp->oprom_array;
	else
		*val = NULL;

	return (0);
}

static cfga_err_t
prom_set_prop(int prom_fd, char *var, char *val)
{
	oppbuf_t oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	int varlen = strlen(var) + 1;
	int vallen = strlen(val);

	DBG("prom_set_prop(%s)\n", val);

	(void) strcpy(opp->oprom_array, var);
	(void) strcpy(opp->oprom_array + varlen, val);
	opp->oprom_size = varlen + vallen;

	if (ioctl(prom_fd, OPROMSETOPT, opp) < 0)
		return (ERR_PROM_SETPROP);

	return (0);
}

static int
dlist_find(int board, char **dlist, int *disabled)
{
	int i;
	int err;
	int prom_fd;
	char *p;
	char *dl;
	char b[2];

	if ((prom_fd = open(promdev, O_RDWR, 0)) < 0)
		return (ERR_PROM_OPEN);
	else if (err = prom_get_prop(prom_fd, dlprop, dlist)) {
		(void) close(prom_fd);
		return (err);
	} else
		(void) close(prom_fd);

	b[1] = 0;
	*disabled = 0;

	if ((dl = *dlist) != NULL) {
		int len = strlen(dl);

		for (i = 0; i < len; i++) {
			int bd;

			b[0] = dl[i];
			bd = strtol(b, &p, 16);

			if (p != b && bd == board)
				(*disabled)++;
		}
	}

	return (0);
}

static int
dlist_update(int board, int disable, char *dlist, struct cfga_msg *msgp,
    int verbose)
{
	int i, j, n;
	int err;
	int found;
	int update;
	int prom_fd;
	char *p;
	char b[2];
	char ndlist[64];

	b[1] = 0;
	ndlist[0] = 0;
	j = 0;
	found = 0;
	update = 0;

	if ((prom_fd = open(promdev, O_RDWR, 0)) < 0)
		return (ERR_PROM_OPEN);

	if (dlist) {
		int len = strlen(dlist);

		for (i = 0; i < len; i++) {
			int bd;

			b[0] = dlist[i];
			bd = strtol(b, &p, 16);

			if (p != b && bd == board) {

				found++;
				if (disable) {
					if (verbose)
						cfga_msg(msgp, STR_BD,
						    DIAG_WAS_DISABLED, 0);
				} else {
					if (verbose)
						cfga_msg(msgp, STR_BD,
						    DIAG_WILL_ENABLE, 0);
					update++;
					continue;
				}
			}
			ndlist[j++] = dlist[i];
		}
		ndlist[j] = 0;
	}

	if (!found)
		if (disable) {
			if (verbose)
				cfga_msg(msgp, STR_BD, DIAG_WILL_DISABLE, 0);
			p = &ndlist[j];
			n = sprintf(p, "%x", board);
			p[n] = 0;
			update++;
		} else {
			if (verbose)
				cfga_msg(msgp, STR_BD, DIAG_WAS_ENABLED, 0);
		}

	if (update)
		err = prom_set_prop(prom_fd, dlprop, ndlist);
	else
		err = 0;

	(void) close(prom_fd);

	return (err);
}

static int
ap_idx(const char *ap_id)
{
	int id;
	char *s;
	static char *slot = "slot";

	DBG("ap_idx(%s)\n", ap_id);

	if ((s = strstr(ap_id, slot)) == NULL)
		return (-1);
	else {
		int n;

		s += strlen(slot);
		n = strlen(s);

		DBG3("ap_idx: s=%s, n=%d\n", s, n);

		switch (n) {
		case 2:
			if (!isdigit(s[1]))
				return (-1);
		/* FALLTHROUGH */
		case 1:
			if (!isdigit(s[0]))
				return (-1);
			break;
		default:
			return (-1);
		}
	}

	if ((id = atoi(s)) > MAX_BOARDS)
		return (-1);

	DBG3("ap_idx(%s)=%d\n", s, id);

	return (id);
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
	int fd;
	int idx;
	int err;
	int force;
	int verbose;
	int opterr;
	int disable;
	int disabled;
	cfga_err_t rc;
	sysc_cfga_stat_t *ss;
	sysc_cfga_cmd_t *sc, sysc_cmd;
	sysc_cfga_rstate_t rs;
	sysc_cfga_ostate_t os;
	char *dlist;
	char outputstr[SYSC_OUTPUT_LEN];

	if (errstring != NULL)
		*errstring = NULL;

	rc = CFGA_ERROR;

	if (options) {
		disable = 0;
		if (strcmp(options, cfga_str(OPT_DISABLE)) == 0)
			disable++;
		else if (strcmp(options, cfga_str(OPT_ENABLE))) {
			cfga_err(NULL, errstring, ERR_OPT_INVAL, options, 0);
			return (rc);
		}
	}

	if ((idx = ap_idx(ap_id)) == -1) {
		cfga_err(NULL, errstring, ERR_AP_INVAL, ap_id, 0);
		return (rc);
	} else if ((ss = sysc_stat(ap_id, &fd)) == NULL) {
		cfga_err(NULL, errstring, CMD_GETSTAT, 0);
		return (rc);
	}
#ifdef	SIM
	sim_idx = idx;
#endif
	/*
	 * We disallow connecting on the disabled list unless
	 * either the FORCE flag or the enable-at-boot option
	 * is set. The check is made further below
	 */
	if (opterr = dlist_find(idx, &dlist, &disabled)) {
		err = disable ? OPT_DISABLE : OPT_ENABLE;
		cfga_err(NULL, errstring, err, opterr, 0);
		(void) close(fd);
		return (rc);
	} else
		force = flags & CFGA_FLAG_FORCE;

	rs = ss[idx].rstate;
	os = ss[idx].ostate;

	sc = &sysc_cmd;
	sysc_cmd_init(sc, outputstr, force);
	verbose = flags & CFGA_FLAG_VERBOSE;

	switch (state_change_cmd) {
	case CFGA_CMD_CONNECT:
		if (rs != SYSC_CFGA_RSTATE_DISCONNECTED)
			cfga_err(NULL, errstring, ERR_TRANS, 0);
		else if (disabled && !(force || (options && !disable)))
			cfga_err(NULL, errstring, CMD_CONNECT,
			    ERR_DISABLED, DIAG_FORCE, 0);
		else if (!(*confp->confirm)(confp->appdata_ptr,
		    cfga_str(ASK_CONNECT))) {
			(void) close(fd);
			return (CFGA_NACK);
		} else if (ioctl(fd, SYSC_CFGA_CMD_CONNECT, sc) == -1)
			cfga_err(sc, errstring, CMD_CONNECT, 0);
		else if (options && (opterr = dlist_update(idx, disable,
		    dlist, msgp, verbose))) {
			err = disable ? OPT_DISABLE : OPT_ENABLE;
			cfga_err(NULL, errstring, err, opterr, 0);
		} else
			rc = CFGA_OK;
		break;

	case CFGA_CMD_DISCONNECT:
		if ((os == SYSC_CFGA_OSTATE_CONFIGURED) &&
		    (ioctl(fd, SYSC_CFGA_CMD_UNCONFIGURE, sc) == -1)) {
			cfga_err(sc, errstring, CMD_UNCONFIGURE, 0);
			(void) close(fd);
			return (CFGA_ERROR);
		} else
			sysc_cmd_init(sc, outputstr, force);

		if (rs == SYSC_CFGA_RSTATE_CONNECTED) {
			if (ioctl(fd, SYSC_CFGA_CMD_DISCONNECT, sc) == -1)
				cfga_err(sc, errstring, CMD_DISCONNECT, 0);
			else if (options && (opterr = dlist_update(idx, disable,
			    dlist, msgp, verbose))) {
				err = disable ? OPT_DISABLE : OPT_ENABLE;
				cfga_err(NULL, errstring, err, opterr, 0);
			} else
				rc = CFGA_OK;
		} else
			cfga_err(NULL, errstring, ERR_TRANS, 0);
		break;

	case CFGA_CMD_CONFIGURE:
		if (rs == SYSC_CFGA_RSTATE_DISCONNECTED)
			if (disabled && !(force || (options && !disable))) {
				cfga_err(NULL, errstring, CMD_CONFIGURE,
				    ERR_DISABLED, DIAG_FORCE, 0);
				(void) close(fd);
				return (CFGA_ERROR);
			} else if (!(*confp->confirm)(confp->appdata_ptr,
			    cfga_str(ASK_CONNECT))) {
				(void) close(fd);
				return (CFGA_NACK);
			} else if (ioctl(fd, SYSC_CFGA_CMD_CONNECT, sc) == -1) {
				cfga_err(sc, errstring, CMD_CONNECT, 0);
				(void) close(fd);
				return (CFGA_ERROR);
			} else
				sysc_cmd_init(sc, outputstr, force);

		if (os == SYSC_CFGA_OSTATE_UNCONFIGURED) {
			if (ioctl(fd, SYSC_CFGA_CMD_CONFIGURE, sc) == -1)
				cfga_err(sc, errstring, CMD_CONFIGURE, 0);
			else if (options && (opterr = dlist_update(idx,
			    disable, dlist, msgp, verbose))) {
				err = disable ? OPT_DISABLE : OPT_ENABLE;
				cfga_err(NULL, errstring, err, opterr, 0);
			} else
				rc = CFGA_OK;
		} else
			cfga_err(NULL, errstring, ERR_TRANS, 0);
		break;

	case CFGA_CMD_UNCONFIGURE:
		if (os != SYSC_CFGA_OSTATE_CONFIGURED)
			cfga_err(NULL, errstring, ERR_TRANS, 0);
		else if (ioctl(fd, SYSC_CFGA_CMD_UNCONFIGURE, sc) == -1)
			cfga_err(sc, errstring, CMD_UNCONFIGURE, 0);
		else if (options && (opterr = dlist_update(idx, disable,
		    dlist, msgp, verbose))) {
			err = disable ? OPT_DISABLE : OPT_ENABLE;
			cfga_err(NULL, errstring, err, opterr, 0);
		} else
			rc = CFGA_OK;
		break;

	default:
		rc = CFGA_OPNOTSUPP;
		break;
	}

	(void) close(fd);
	return (rc);
}

static int
str2cond(const char *cond)
{
	int c;

	if (strcmp(cond, cfga_str(COND_UNKNOWN)) == 0)
		c =  SYSC_CFGA_COND_UNKNOWN;
	else if (strcmp(cond, cfga_str(COND_OK)) == 0)
		c =  SYSC_CFGA_COND_OK;
	else if (strcmp(cond, cfga_str(COND_FAILING)) == 0)
		c =  SYSC_CFGA_COND_FAILING;
	else if (strcmp(cond, cfga_str(COND_FAILED)) == 0)
		c =  SYSC_CFGA_COND_FAILED;
	else if (strcmp(cond, cfga_str(COND_UNUSABLE)) == 0)
		c =  SYSC_CFGA_COND_UNUSABLE;
	else
		c = -1;

	return (c);
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
	int fd;
	int idx;
	int len;
	int cmd;
	int cond;
	int err;
	int opterr;
	int verbose;
	int disable;
	int disabled;
	cfga_err_t rc;
	char *str;
	char *dlist;
	char outputstr[SYSC_OUTPUT_LEN];
	sysc_cfga_cmd_t *sc, sysc_cmd;

	if (errstring != NULL)
		*errstring = NULL;

	verbose = flags & CFGA_FLAG_VERBOSE;

	rc = CFGA_ERROR;

	if (options) {
		disable = 0;
		if (strcmp(options, cfga_str(OPT_DISABLE)) == 0)
			disable++;
		else if (strcmp(options, cfga_str(OPT_ENABLE))) {
			cfga_err(NULL, errstring, ERR_OPT_INVAL, options, 0);
			return (rc);
		}
	}

	sc = &sysc_cmd;
	str = cfga_str(CMD_SET_COND);
	len = strlen(str);

	if ((strncmp(function, str, len) == 0) && (function[len++] == '=') &&
	    ((cond = (str2cond(&function[len]))) != -1)) {
		cmd = SYSC_CFGA_CMD_TEST_SET_COND;
		err = CMD_SET_COND;
		sc->arg = cond;
	} else if (strcmp(function, cfga_str(CMD_QUIESCE)) == 0) {
		cmd = SYSC_CFGA_CMD_QUIESCE_TEST;
		err = CMD_QUIESCE;
	} else if (strcmp(function, cfga_str(CMD_INSERT)) == 0) {
		cmd = SYSC_CFGA_CMD_TEST;
		err = CMD_INSERT;
	} else if (strcmp(function, cfga_str(CMD_REMOVE)) == 0) {
		cmd = SYSC_CFGA_CMD_TEST;
		err = CMD_REMOVE;
	} else {
		cfga_err(NULL, errstring, ERR_CMD_INVAL, (char *)function, 0);
		return (rc);
	}

	sysc_cmd_init(sc, outputstr, 0);

	if ((idx = ap_idx(ap_id)) == -1)
		cfga_err(NULL, errstring, ERR_AP_INVAL, ap_id, 0);
	else if (((fd = open(ap_id, O_RDWR, 0)) == -1) ||
	    (ioctl(fd, cmd, sc) == -1))
		cfga_err(NULL, errstring, err, 0);
	else
		rc = CFGA_OK;

	if (options) {
		opterr = (dlist_find(idx, &dlist, &disabled) ||
		    dlist_update(idx, disable, dlist, msgp, verbose));
		if (opterr) {
			err = disable ? OPT_DISABLE : OPT_ENABLE;
			if (verbose)
				cfga_msg(msgp, err, opterr, 0);
		}
	}

	(void) close(fd);
	return (rc);
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
	if (errstring != NULL)
		*errstring = NULL;

	return (CFGA_OPNOTSUPP);
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

static char *
type_str(enum board_type type)
{
	char *type_str;

	switch (type) {
	case MEM_BOARD:
		type_str = cfga_str(BD_MEM);
		break;
	case CPU_BOARD:
		type_str = cfga_str(BD_CPU);
		break;
	case IO_2SBUS_BOARD:
		type_str = cfga_str(BD_IO_2SBUS);
		break;
	case IO_SBUS_FFB_BOARD:
		type_str = cfga_str(BD_IO_SBUS_FFB);
		break;
	case IO_PCI_BOARD:
		type_str = cfga_str(BD_IO_PCI);
		break;
	case DISK_BOARD:
		type_str = cfga_str(BD_DISK);
		break;
	case IO_2SBUS_SOCPLUS_BOARD:
		type_str = cfga_str(BD_IO_2SBUS_SOCPLUS);
		break;
	case IO_SBUS_FFB_SOCPLUS_BOARD:
		type_str = cfga_str(BD_IO_SBUS_FFB_SOCPLUS);
		break;
	case UNKNOWN_BOARD:
	default:
		type_str = cfga_str(BD_UNKNOWN);
		break;
	}
	return (type_str);
}

static void
info_set(sysc_cfga_stat_t *sc, cfga_info_t info, int disabled)
{
	int i;
	struct cpu_info *cpu;
	union bd_un *bd = &sc->bd;

	*info = '\0';

	switch (sc->type) {
	case CPU_BOARD:
		for (i = 0, cpu = bd->cpu; i < 2; i++, cpu++) {
			if (cpu->cpu_speed > 1) {
				info += sprintf(info, "cpu %d: ", i);
				info += sprintf(info, "%3d MHz ",
				    cpu->cpu_speed);
				if (cpu->cache_size)
					info += sprintf(info, "%0.1fM ",
					    (float)cpu->cache_size /
					    (float)(1024 * 1024));
			}
		}
		break;
	case IO_SBUS_FFB_BOARD:
		switch (bd->io2.ffb_size) {
		case FFB_SINGLE:
			info += sprintf(info, "single buffered ffb   ");
			break;
		case FFB_DOUBLE:
			info += sprintf(info, "double buffered ffb   ");
			break;
		case FFB_NOT_FOUND:
#ifdef FFB_DR_SUPPORT
			info += sprintf(info, "no ffb installed   ");
#endif
			break;
		default:
			info += sprintf(info, "illegal ffb size   ");
			break;
		}
		break;
	case DISK_BOARD:
		for (i = 0; i < 2; i++)
			if (bd->dsk.disk_pres[i])
				info += sprintf(info, "target: %2d ",
				    bd->dsk.disk_id[i]);
			else
				info += sprintf(info, "no disk   ");
		break;
	}

	if (disabled)
		info += sprintf(info, "disabled at boot   ");

	if (sc->no_detach)
		info += sprintf(info, "non-detachable   ");

	if (sc->plus_board)
		info += sprintf(info, "100 MHz capable   ");
}

static void
sysc_cvt(sysc_cfga_stat_t *sc, cfga_stat_data_t *cs, int disabled)
{
	(void) strcpy(cs->ap_type, type_str(sc->type));
	cs->ap_r_state = rstate_cvt(sc->rstate);
	cs->ap_o_state = ostate_cvt(sc->ostate);
	cs->ap_cond = cond_cvt(sc->condition);
	cs->ap_busy = (cfga_busy_t)sc->in_transition;
	cs->ap_status_time = sc->last_change;
	info_set(sc, cs->ap_info, disabled);
	cs->ap_log_id[0] = '\0';
	cs->ap_phys_id[0] = '\0';
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
	int i;
	cfga_err_t rc;
	sysc_cfga_stat_t *sc;
	cfga_stat_data_t *cs;

	if (errstring != NULL)
		*errstring = NULL;

	rc = CFGA_ERROR;

	if (ap_idx(ap_id) == -1)
		cfga_err(NULL, errstring, ERR_AP_INVAL, ap_id, 0);
	else if ((sc = sysc_stat(ap_id, NULL)) == NULL)
		cfga_err(NULL, errstring, CMD_LIST, 0);
	else if (!(cs = (cfga_stat_data_t *)malloc(MAX_BOARDS * sizeof (*cs))))
		cfga_err(NULL, errstring, CMD_LIST, 0);
	else {
		*ap_list = cs;

		for (*nlist = 0, i = 0; i < MAX_BOARDS; i++, sc++) {
			if (sc->board == -1)
				continue;
			sysc_cvt(sc, cs++, 0); /* XXX - disable */
			(*nlist)++;
		}

		rc = CFGA_OK;
	}

	return (rc);
}

/*ARGSUSED*/
cfga_err_t
cfga_stat(
	const char *ap_id,
	struct cfga_stat_data *cs,
	const char *options,
	char **errstring)
{
	cfga_err_t rc;
	int idx;
	int err;
	int opterr;
	int disable;
	int disabled;
	char *dlist;
	sysc_cfga_stat_t *sc;

	if (errstring != NULL)
		*errstring = NULL;

	rc = CFGA_ERROR;

	if (options && options[0]) {
		disable = 0;
		if (strcmp(options, cfga_str(OPT_DISABLE)) == 0)
			disable++;
		else if (strcmp(options, cfga_str(OPT_ENABLE))) {
			cfga_err(NULL, errstring, ERR_OPT_INVAL, options, 0);
			return (rc);
		}
	}

	if ((idx = ap_idx(ap_id)) == -1)
		cfga_err(NULL, errstring, ERR_AP_INVAL, ap_id, 0);
	else if ((sc = sysc_stat(ap_id, NULL)) == NULL)
		cfga_err(NULL, errstring, CMD_GETSTAT, 0);
	else {
		opterr = dlist_find(idx, &dlist, &disabled);
		sysc_cvt(sc + idx, cs, disabled);

		rc = CFGA_OK;

		if (options && options[0] && ((opterr != 0) ||
		    ((opterr = dlist_update(idx, disable, dlist, NULL, 0))
		    != 0))) {
				err = disable ? OPT_DISABLE : OPT_ENABLE;
				cfga_err(NULL, errstring, err, opterr, 0);
		}
	}

	return (rc);
}

/*ARGSUSED*/
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	int help = 0;

	if (options) {
		if (strcmp(options, cfga_str(OPT_DISABLE)) == 0)
			help = HELP_DISABLE;
		else if (strcmp(options, cfga_str(OPT_ENABLE)) == 0)
			help = HELP_ENABLE;
		else if (strcmp(options, cfga_str(CMD_INSERT)) == 0)
			help = HELP_INSERT;
		else if (strcmp(options, cfga_str(CMD_REMOVE)) == 0)
			help = HELP_REMOVE;
		else if (strcmp(options, cfga_str(CMD_QUIESCE)) == 0)
			help = HELP_QUIESCE;
		else
			help = HELP_UNKNOWN;
	}

	if (help)  {
		if (help == HELP_UNKNOWN)
			cfga_msg(msgp, help, options, 0);
		else
			cfga_msg(msgp, help, 0);
	} else {
		cfga_msg(msgp, HELP_HEADER, 0);
		cfga_msg(msgp, HELP_DISABLE, 0);
		cfga_msg(msgp, HELP_ENABLE, 0);
		cfga_msg(msgp, HELP_INSERT, 0);
		cfga_msg(msgp, HELP_REMOVE, 0);
		cfga_msg(msgp, HELP_QUIESCE, 0);
		cfga_msg(msgp, HELP_SET_COND, 0);
	}

	return (CFGA_OK);
}

/*
 * cfga_ap_id_cmp -- use default_ap_id_cmp() in libcfgadm
 */
