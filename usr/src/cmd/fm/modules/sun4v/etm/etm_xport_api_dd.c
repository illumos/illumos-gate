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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * etm_xport_api_dd.c	FMA ETM-to-Transport API implementation
 *			for sun4v/Ontario
 *
 * library for establishing connections and transporting FMA events
 * between ETMs (event transport modules) in separate fault domain,
 * ie, between domain and service processor in same chassis, using
 * a character device driver based transport
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * --------------------------------- includes --------------------------------
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>

#include <pthread.h>
#include <stdio.h>
#include <stropts.h>
#include <locale.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <sys/ldc.h>
#include <sys/vldc.h>

#include "etm_xport_api.h"
#include "etm_etm_proto.h"
#include "etm_impl.h"

/*
 * ----------------------- private consts and defns --------------------------
 */

/* magic numbers (32 bits) for transport address and connection handle */

#define	ETM_XPORT_DD_MAGIC_ADDR	(0x45544D41)
#define	ETM_XPORT_DD_MAGIC_CONN	(0x45544D43)

/* flags to use in opening transport device */

#define	ETM_XPORT_OPEN_FLAGS		(O_RDWR | O_NOCTTY)

/*
 * transport address and connection handle structures overload fn and fd
 * fields to include state information:
 *
 *	fn	file name		NULL means unused or closed
 *	fd	file descriptor		-1 means unused or closed
 */

typedef struct _etm_xport_addr {
	uint32_t		magic_num;	/* magic number */
	char			*fn;		/* fullpath to device node */
} _etm_xport_addr_t;

typedef struct _etm_xport_conn {
	uint32_t		magic_num;	/* magic number */
	int			fd;		/* open dev file descriptor */
	_etm_xport_addr_t	*addr;		/* associated transport addr */
} _etm_xport_conn_t;

/*
 * filename of device node to reach SP from domain.  one of these two
 * device nodes will be used:
 *   ETM_XPORT_DEV_FN_SP - the Ontario glvc
 *   ETM_XPORT_DEV_VLDC  - the more recent LDOMS 1.0 (a.k.a. Ontario+) vldc
 * When the latter is in use, use_vldc is set to 1.
 *
 * filenames of device nodes to reach domains from SP
 * are NA because SP runs ALOM vs Solaris or Linux
 * and ETM is for Unix based OSes
 */
#define	ETM_XPORT_DEV_FN_SP	"/dev/spfma"

#define	ETM_XPORT_DEV_VLDC	\
	"/devices/virtual-devices@100/channel-devices@200" \
	"/virtual-channel-client@2:spfma"

/*
 * -------------------------- global variables -------------------------------
 */

static int use_vldc = 0;

static struct stats {

	/* address handle failures */

	fmd_stat_t xport_addr_magicnum_bad;
	fmd_stat_t xport_addr_fn_bad;

	/* connection handle failures */

	fmd_stat_t xport_conn_magicnum_bad;
	fmd_stat_t xport_conn_fd_bad;

	/* internal read/peek failures */

	fmd_stat_t xport_buffread_badargs;
	fmd_stat_t xport_rawpeek_badargs;

	/* xport API failures */

	fmd_stat_t xport_accept_badargs;
	fmd_stat_t xport_get_addr_conn_badargs;
	fmd_stat_t xport_free_addr_badargs;
	fmd_stat_t xport_free_addrv_badargs;
	fmd_stat_t xport_get_any_lcc_badargs;

	/* system and library failures */

	fmd_stat_t xport_os_open_fail;
	fmd_stat_t xport_os_close_fail;
	fmd_stat_t xport_os_read_fail;
	fmd_stat_t xport_os_write_fail;
	fmd_stat_t xport_os_peek_fail;
	fmd_stat_t xport_os_ioctl_fail;

} etm_xport_stats = {

	/* address handle failures */

	{ "xport_addr_magicnum_bad", FMD_TYPE_UINT64,
		"invalid address handle magic number" },
	{ "xport_addr_fn_bad", FMD_TYPE_UINT64,
		"invalid address handle file name" },

	/* connection handle failures */

	{ "xport_conn_magicnum_bad", FMD_TYPE_UINT64,
		"invalid connection handle magic number" },
	{ "xport_conn_fd_bad", FMD_TYPE_UINT64,
		"invalid connection handle file descriptor" },

	/* internal read/peek failures */

	{ "xport_buffread_badargs", FMD_TYPE_UINT64,
		"bad arguments in etm_xport_buffered_read" },
	{ "xport_rawpeek_badargs", FMD_TYPE_UINT64,
		"bad arguments in etm_xport_raw_peek" },

	/* xport API failures */

	{ "xport_accept_badargs", FMD_TYPE_UINT64,
		"bad arguments in etm_xport_accept" },
	{ "xport_get_addr_conn_badargs", FMD_TYPE_UINT64,
		"bad arguments in etm_xport_get_addr_conn" },
	{ "xport_free_addr_badargs", FMD_TYPE_UINT64,
		"bad arguments in etm_xport_free_addr" },
	{ "xport_free_addrv_badargs", FMD_TYPE_UINT64,
		"bad arguments in etm_xport_free_addrv" },
	{ "xport_get_any_lcc_badargs", FMD_TYPE_UINT64,
		"bad arguments in etm_xport_get_any_lcc" },

	/* system and library failures */

	{ "xport_os_open_fail", FMD_TYPE_UINT64,
		"open system call failures" },
	{ "xport_os_close_fail", FMD_TYPE_UINT64,
		"close system call failures" },
	{ "xport_os_read_fail", FMD_TYPE_UINT64,
		"read system call failures" },
	{ "xport_os_write_fail", FMD_TYPE_UINT64,
		"write system call failures" },
	{ "xport_os_peek_fail", FMD_TYPE_UINT64,
		"peek (ioctl) failures" },
	{ "xport_os_ioctl_fail", FMD_TYPE_UINT64,
		"ioctl system call failures" }
};

/* intermediate read buffer to [partially] emulate byte stream semantics */

static uint8_t	*etm_xport_irb_area = NULL;	/* buffered read area */
static uint8_t	*etm_xport_irb_head = NULL;	/* read head (dequeue) */
static uint8_t	*etm_xport_irb_tail = NULL;	/* read tail (enqueue) */
static size_t	etm_xport_irb_mtu_sz = 0;	/* MTU size (in bytes) */

/*
 * -------------------------- private variables ------------------------------
 */

static _etm_xport_conn_t *
etm_xport_vldc_conn = NULL;	/* single connection handle for VLDC */

static pthread_mutex_t
etm_xport_vldc_lock = PTHREAD_MUTEX_INITIALIZER;
				/* lock for open()/close() VLDC */

static int
etm_xport_debug_lvl = 0;	/* debug level: 0 off, 1 on, 2 more, ... */

static char *
etm_xport_addrs = "";		/* spec str for transport addrs to use */

static int
etm_xport_should_fake_dd = 0;	/* bool for whether to fake device driver */

/*
 * -------------------------- private functions ------------------------------
 */

/*
 * etm_fake_ioctl - fake/simulate transport driver's ioctl() behavior
 *			[for unit testing with device driver absent or
 *			for alternative directory entry based transports],
 *			return 0 for success
 *			or -1 and set errno
 * caveats:
 *		simulation may be incomplete, especially wrt peek()
 *
 * Design_Note:	To avoid interfering with FMD's signal mask (SIGALRM)
 *		do not use [Solaris] sleep(3C) and instead use
 *		pthread_cond_wait() or nanosleep(), both of which
 *		are POSIX spec-ed to leave signal masks alone.
 *		This is needed for Solaris and Linux (domain and SP).
 */

static int
etm_fake_ioctl(int fd, int op, void *buf)
{
	int			rv;		/* ret val */
	etm_xport_opt_op_t	*op_ctl_ptr;	/* ptr for option ops */
	etm_xport_msg_peek_t	*peek_ctl_ptr;	/* ptr for peeking */
	struct stat		stat_buf;	/* file stat struct */
	ssize_t			n;		/* gen use */
	struct timespec		tms;		/* for nanosleep() */

	tms.tv_sec = 0;
	tms.tv_nsec = 0;

	rv = 0; /* default is success */

	if (op == ETM_XPORT_IOCTL_DATA_PEEK) {
		peek_ctl_ptr = buf;
		/* sleep until some data avail, potentially forever */
		for (;;) {
			if (fstat(fd, &stat_buf) < 0) {
				rv = -1;
				goto func_ret;
			}
			if (stat_buf.st_size > 0) {
				n = MIN(peek_ctl_ptr->pk_buflen,
				    stat_buf.st_size);
				peek_ctl_ptr->pk_buflen = n;
				/* return bogus data assuming content unused */
				(void) memset(peek_ctl_ptr->pk_buf, 0xA5, n);
				goto func_ret;
			}
			tms.tv_sec = ETM_SLEEP_QUIK;
			tms.tv_nsec = 0;
			if ((n = nanosleep(&tms, NULL)) < 0) {
				rv = -1;
				goto func_ret;
			}
		} /* forever awaiting data */
	} else if (op == ETM_XPORT_IOCTL_OPT_OP) {
		op_ctl_ptr = buf;
		/* default near MTU_SZ gets and agree with everything else */
		if ((op_ctl_ptr->oo_op  == ETM_XPORT_OPT_GET) &&
		    (op_ctl_ptr->oo_opt == ETM_XPORT_OPT_MTU_SZ)) {
			op_ctl_ptr->oo_val = 7 * ETM_XPORT_MTU_SZ_DEF / 8;
		}
		goto func_ret;
	} /* whether ioctl op is handled */

	rv = -1;
	errno = EINVAL;

func_ret:

	return (rv);

} /* etm_fake_ioctl() */

/*
 * etm_xport_get_fn - return a cached read-only copy
 *			of the device node name to use
 *			for the given I/O operation
 */

static char *
etm_xport_get_fn(fmd_hdl_t *hdl, int io_op)
{
	static char	fn_wr[PATH_MAX] = {0};		/* fn for write */
	static char	fn_rd[PATH_MAX] = {0};		/* fn for read/peek */
	char		*rv;				/* ret val */
	char		*prop_str;			/* property string */
	char		*cp;				/* char ptr */

	rv = NULL;

	/* use cached copies if avail */

	if ((io_op == ETM_IO_OP_WR) && (fn_wr[0] != '\0')) {
		return (fn_wr);
	}
	if (((io_op == ETM_IO_OP_RD) || (io_op == ETM_IO_OP_PK)) &&
	    (fn_rd[0] != '\0')) {
		return (fn_rd);
	}

	/* create cached copies if empty "" property string */

	prop_str = fmd_prop_get_string(hdl, ETM_PROP_NM_XPORT_ADDRS);
	if (etm_xport_debug_lvl >= 2) {
		fmd_hdl_debug(hdl, "info: etm_xport_get_fn prop_str %s\n",
		    prop_str);
	}

	if (strlen(prop_str) == 0) {
		struct stat buf;
		char *fname;

		if (stat(ETM_XPORT_DEV_VLDC, &buf) == 0) {
			use_vldc = 1;
			fname = ETM_XPORT_DEV_VLDC;
		} else {
			use_vldc = 0;
			fname = ETM_XPORT_DEV_FN_SP;
		}

		(void) strncpy(fn_wr, fname, PATH_MAX - 1);
		(void) strncpy(fn_rd, fname, PATH_MAX - 1);
		rv = fn_rd;
		if (io_op == ETM_IO_OP_WR) {
			rv = fn_wr;
		}
		goto func_ret;
	} /* if no/empty property set */

	/* create cached copies if "write[|read]" property string */

	if (io_op == ETM_IO_OP_WR) {
		(void) strncpy(fn_wr, prop_str, PATH_MAX - 1);
		if ((cp = strchr(fn_wr, '|')) != NULL) {
			*cp = '\0';
		}
		rv = fn_wr;
	} else {
		if ((cp = strchr(prop_str, '|')) != NULL) {
			cp++;
		} else {
			cp = prop_str;
		}
		(void) strncpy(fn_rd, cp, PATH_MAX - 1);
		rv = fn_rd;
	} /* whether io op is write/read/peek */

func_ret:

	if (etm_xport_debug_lvl >= 2) {
		fmd_hdl_debug(hdl, "info: etm_xport_get_fn fn_wr %s fn_rd %s\n",
		    fn_wr, fn_rd);
	}
	fmd_prop_free_string(hdl, prop_str);
	return (rv);

} /* etm_xport_get_fn() */

/*
 * etm_xport_valid_addr - validate the given transport address,
 *			return 0 if valid
 *			or -errno value if not
 */

static int
etm_xport_valid_addr(etm_xport_addr_t addr)
{
	_etm_xport_addr_t	*_addr;		/* transport address */
	struct stat		stat_buf;	/* buffer for stat() results */

	_addr = addr;

	if (_addr == NULL) {
		return (-EINVAL);
	}

	if (_addr->magic_num != ETM_XPORT_DD_MAGIC_ADDR) {
		etm_xport_stats.xport_addr_magicnum_bad.fmds_value.ui64++;
		return (-EFAULT);
	}

	if (stat(_addr->fn, &stat_buf) < 0) {
		/* errno assumed set by above call */
		etm_xport_stats.xport_addr_fn_bad.fmds_value.ui64++;
		return (-errno);
	}

	return (0);

} /* etm_xport_valid_addr() */

/*
 * etm_xport_valid_conn - validate the given connection handle,
 *			return 0 if valid
 *			or -errno value if not
 */

static int
etm_xport_valid_conn(etm_xport_conn_t conn)
{
	_etm_xport_conn_t	*_conn;		/* connection handle */

	_conn = conn;

	if (_conn == NULL) {
		return (-EINVAL);
	}

	if (_conn->magic_num != ETM_XPORT_DD_MAGIC_CONN) {
		etm_xport_stats.xport_conn_magicnum_bad.fmds_value.ui64++;
		return (-EFAULT);
	}

	if (_conn->fd <= -1) {
		etm_xport_stats.xport_conn_fd_bad.fmds_value.ui64++;
		return (-EBADF);
	}

	return (0);

} /* etm_xport_valid_conn() */

/*
 * etm_xport_free_addr -  free the given transport address
 */

static void
etm_xport_free_addr(fmd_hdl_t *hdl, etm_xport_addr_t addr)
{
	if (addr == NULL) {
		etm_xport_stats.xport_free_addr_badargs.fmds_value.ui64++;
		return;
	}

	fmd_hdl_free(hdl, addr, sizeof (_etm_xport_addr_t));

} /* etm_xport_free_addr() */

/*
 * etm_xport_dup_addr - duplicate the given transport address,
 *			which is to be freed separately,
 *			return the newly allocated transport address
 *			pending until possible to do so
 */

static etm_xport_addr_t
etm_xport_dup_addr(fmd_hdl_t *hdl, etm_xport_addr_t addr)
{
	etm_xport_addr_t new_addr;	/* new transport address */

	new_addr = fmd_hdl_zalloc(hdl, sizeof (_etm_xport_addr_t), FMD_SLEEP);
	(void) memcpy(new_addr, addr, sizeof (_etm_xport_addr_t));
	return (new_addr);

} /* etm_xport_dup_addr() */

/*
 * etm_xport_raw_peek - try to peek N <= MTU bytes from the connection
 *			into the caller's given buffer,
 *			return how many bytes actually peeked
 *			or -errno value
 * caveats:
 *		peeked data is NOT guaranteed by all platform transports
 *		to remain enqueued if this process/thread crashes;
 *		this casts some doubt on the utility of this func
 *
 *		transport does NOT support peek sizes > MTU
 */

static ssize_t
etm_xport_raw_peek(fmd_hdl_t *hdl, _etm_xport_conn_t *_conn,
			void *buf, size_t byte_cnt)
{
	ssize_t			rv;		/* ret val */
	ssize_t			n;		/* gen use */
	etm_xport_msg_peek_t	peek_ctl;	/* struct for peeking */

	rv = 0;

	/* sanity check args */

	if ((hdl == NULL) || (_conn == NULL) || (buf == NULL)) {
		etm_xport_stats.xport_rawpeek_badargs.fmds_value.ui64++;
		return (-EINVAL);
	}

	if ((etm_xport_irb_mtu_sz > 0) && (byte_cnt > etm_xport_irb_mtu_sz)) {
		etm_xport_stats.xport_rawpeek_badargs.fmds_value.ui64++;
		return (-EINVAL);
	}

	/* try to peek requested amt of data */

	peek_ctl.pk_buf = buf;
	peek_ctl.pk_buflen = byte_cnt;
	peek_ctl.pk_flags = 0;
	peek_ctl.pk_rsvd = 0;

	if (etm_xport_should_fake_dd) {
		n = etm_fake_ioctl(_conn->fd, ETM_XPORT_IOCTL_DATA_PEEK,
		    &peek_ctl);
	} else {
		n = ioctl(_conn->fd, ETM_XPORT_IOCTL_DATA_PEEK, &peek_ctl);
	}
	if (n < 0) {
		/* errno assumed set by above call */
		etm_xport_stats.xport_os_peek_fail.fmds_value.ui64++;
		rv = (-errno);
	} else {
		rv = peek_ctl.pk_buflen;
	}

	if (etm_xport_debug_lvl >= 3) {
		fmd_hdl_debug(hdl, "info: [fake] ioctl(_PEEK) ~= %d bytes\n",
		    rv);
	}
	return (rv);

} /* etm_xport_raw_peek() */

/*
 * Design_Note:
 *
 * The transport device driver did not implement byte stream semantics
 * per the spec; its behavior is closer to that of a block device.
 * Consequently, ETM within its Transport API attempts to make the device
 * look like a byte stream by using an intermediate buffer in user space
 * and maintaining progress pointers within that buffer which is populated
 * in near-MTU sized reads. We think it's OK to leave the write side
 * implementation as it was originally written for byte stream semantics
 * because we were told subsequent write()s will pend until the earlier
 * content is read() at the remote end -- essentially each write() must be
 * paired with a single read() -- the device driver does not buffer any I/O.
 *
 * The early driver bugs of returning more data than requested (thus
 * causing buffer overrun corruptions/crashes) and requiring user buffers
 * to be stack based vs heap based, have both been corrected.
 */

/*
 * etm_xport_buffered_read - try to read N <= MTU bytes from the connection
 *			or from an privately maintained intermediate buffer,
 *			into the caller's given buffer,
 *			return how many bytes actually read
 *			or -errno value
 *
 * caveats:
 *		simple buffer scheme consumes 2x MTU bytes of memory and
 *		may do unnecesssary memory copies for ease of coding
 */

static ssize_t
etm_xport_buffered_read(fmd_hdl_t *hdl, _etm_xport_conn_t *_conn,
			void *buf, size_t byte_cnt)
{
	ssize_t		i, n;		/* gen use */

	/* perform one-time initializations */

	/*
	 * Design_Note:
	 *
	 * These initializations are not done in etm_xport_init() because
	 * the connection/device is not yet open and hence the MTU size
	 * is not yet known. However, the corresponding cleanup is done
	 * in etm_xport_fini(). The buffering for byte stream semantics
	 * should be done on a per device vs per connection basis; the
	 * MTU size is assumed to remain constant across all connections.
	 */

	if (etm_xport_irb_mtu_sz == 0) {
		if ((n = etm_xport_get_opt(hdl, _conn,
		    ETM_XPORT_OPT_MTU_SZ)) < 0) {
			etm_xport_irb_mtu_sz = ETM_XPORT_MTU_SZ_DEF;
		} else {
			etm_xport_irb_mtu_sz = n;
		}
	}
	if (etm_xport_irb_area == NULL) {
		etm_xport_irb_area = fmd_hdl_zalloc(hdl,
		    2 * etm_xport_irb_mtu_sz, FMD_SLEEP);
		etm_xport_irb_head = etm_xport_irb_area;
		etm_xport_irb_tail = etm_xport_irb_head;
	}

	/* sanity check the byte count after have MTU */

	if (byte_cnt > etm_xport_irb_mtu_sz) {
		etm_xport_stats.xport_buffread_badargs.fmds_value.ui64++;
		return (-EINVAL);
	}

	/* if intermediate buffer can satisfy request do so w/out xport read */

	if (byte_cnt <= (etm_xport_irb_tail - etm_xport_irb_head)) {
		(void) memcpy(buf, etm_xport_irb_head, byte_cnt);
		etm_xport_irb_head += byte_cnt;
		if (etm_xport_debug_lvl >= 2) {
			fmd_hdl_debug(hdl, "info: quik buffered read == %d\n",
			    byte_cnt);
		}
		return (byte_cnt);
	}

	/* slide buffer contents to front to make room for [MTU] more bytes */

	n = etm_xport_irb_tail - etm_xport_irb_head;
	(void) memmove(etm_xport_irb_area, etm_xport_irb_head, n);
	etm_xport_irb_head = etm_xport_irb_area;
	etm_xport_irb_tail = etm_xport_irb_head + n;

	/*
	 * peek to see how much data is avail and read all of it;
	 * there is no race condition between peeking and reading
	 * due to unbuffered design of the device driver
	 */
	if (use_vldc) {
		pollfd_t pollfd;

		pollfd.events = POLLIN;
		pollfd.revents = 0;
		pollfd.fd = _conn->fd;

		if ((n = poll(&pollfd, 1, -1)) < 1) {
			if (n == 0)
				return (-EIO);
			else
				return (-errno);
		}

		/*
		 * set i to the maximum size --- read(..., i) below will
		 * pull in n bytes (n <= i) anyway
		 */
		i = etm_xport_irb_mtu_sz;
	} else {
		if ((i = etm_xport_raw_peek(hdl, _conn, etm_xport_irb_tail,
		    etm_xport_irb_mtu_sz)) < 0) {
			return (i);
		}
	}
	if ((n = read(_conn->fd, etm_xport_irb_tail, i)) < 0) {
		/* errno assumed set by above call */
		etm_xport_stats.xport_os_read_fail.fmds_value.ui64++;
		return (-errno);
	}
	etm_xport_irb_tail += n;

	/* satisfy request as best we can with what we now have */

	n = MIN(byte_cnt, (etm_xport_irb_tail - etm_xport_irb_head));
	(void) memcpy(buf, etm_xport_irb_head, n);
	etm_xport_irb_head += n;
	if (etm_xport_debug_lvl >= 2) {
		fmd_hdl_debug(hdl, "info: slow buffered read == %d\n", n);
	}
	return (n);

} /* etm_xport_buffered_read() */

/*
 * ------------------ connection establishment functions ---------------------
 */

/*
 * etm_xport_init - initialize/setup any transport infrastructure
 *			before any connections are opened,
 *			return 0 or -errno value if initialization failed
 */

int
etm_xport_init(fmd_hdl_t *hdl)
{
	_etm_xport_addr_t	**_addrv;	/* address vector */
	int			i;		/* vector index */
	ssize_t			n;		/* gen use */
	int			rv;		/* ret val */
	struct stat		stat_buf;	/* file stat struct */
	char			*fn;		/* filename of dev node */

	rv = 0;	/* assume good */

	_addrv = NULL;

	if (hdl == NULL) {
		rv = (-EINVAL);
		goto func_ret;
	}

	fmd_hdl_debug(hdl, "info: xport initializing\n");

	/* setup statistics and properties from FMD */

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (etm_xport_stats) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&etm_xport_stats);

	etm_xport_debug_lvl = fmd_prop_get_int32(hdl, ETM_PROP_NM_DEBUG_LVL);
	etm_xport_addrs = fmd_prop_get_string(hdl, ETM_PROP_NM_XPORT_ADDRS);
	fmd_hdl_debug(hdl, "info: etm_xport_debug_lvl %d\n",
	    etm_xport_debug_lvl);
	fmd_hdl_debug(hdl, "info: etm_xport_addrs %s\n", etm_xport_addrs);

	/* decide whether to fake [some of] the device driver behavior */

	etm_xport_should_fake_dd = 0;	/* default to false */

	fn = etm_xport_get_fn(hdl, ETM_IO_OP_RD);
	if (stat(fn, &stat_buf) < 0) {
		/* errno assumed set by above call */
		fmd_hdl_error(hdl, "error: bad device node %s errno %d\n",
		    fn, errno);
		rv = (-errno);
		goto func_ret;
	}
	if (!S_ISCHR(stat_buf.st_mode) && use_vldc == 0) {
		etm_xport_should_fake_dd = 1;	/* not a char driver */
	}
	fmd_hdl_debug(hdl, "info: etm_xport_should_fake_dd %d\n",
	    etm_xport_should_fake_dd);

	/* validate each default dst transport address */

	if ((_addrv = (void *)etm_xport_get_ev_addrv(hdl, NULL)) == NULL) {
		/* errno assumed set by above call */
		rv = (-errno);
		goto func_ret;
	}

	for (i = 0; _addrv[i] != NULL; i++) {
		if ((n = etm_xport_valid_addr(_addrv[i])) < 0) {
			fmd_hdl_error(hdl, "error: bad xport addr %p\n",
			    _addrv[i]);
			rv = n;
			goto func_ret;
		}
	} /* foreach dst addr */

	if (use_vldc) {
		etm_xport_vldc_conn = etm_xport_open(hdl, _addrv[0]);
		if (etm_xport_vldc_conn == NULL) {
			fmd_hdl_debug(hdl, "info: etm_xport_open() failed\n");
		}
	}

func_ret:

	if (_addrv != NULL) {
		etm_xport_free_addrv(hdl, (void *)_addrv);
	}
	if (rv >= 0) {
		fmd_hdl_debug(hdl, "info: xport initialized ok\n");
	}
	return (rv);

} /* etm_xport_init() */

/*
 * etm_xport_open - open a connection with the given endpoint,
 *			return the connection handle,
 *			or NULL and set errno if open failed
 *
 * Design_Note: The current transport device driver's open()
 *		call will succeed even if the SP is down;
 *		hence there's currently no need for a retry
 *		mechanism.
 */

etm_xport_conn_t
etm_xport_open(fmd_hdl_t *hdl, etm_xport_addr_t addr)
{
	_etm_xport_addr_t	*_addr;		/* address handle */
	_etm_xport_conn_t	*_conn;		/* connection handle */
	ssize_t			n;		/* gen use */

	if ((n = etm_xport_valid_addr(addr)) < 0) {
		errno = (-n);
		return (NULL);
	}

	_addr = etm_xport_dup_addr(hdl, addr);

	/* allocate a connection handle and start populating it */

	_conn = fmd_hdl_zalloc(hdl, sizeof (_etm_xport_conn_t), FMD_SLEEP);

	(void) pthread_mutex_lock(&etm_xport_vldc_lock);

	if (use_vldc == 0 || etm_xport_vldc_conn == NULL) {
		if ((_conn->fd = open(_addr->fn,
		    ETM_XPORT_OPEN_FLAGS, 0)) == -1) {
			/* errno assumed set by above call */
			etm_xport_free_addr(hdl, _addr);
			fmd_hdl_free(hdl, _conn, sizeof (_etm_xport_conn_t));
			etm_xport_stats.xport_os_open_fail.fmds_value.ui64++;
			(void) pthread_mutex_unlock(&etm_xport_vldc_lock);
			return (NULL);
		}
	}

	if (use_vldc && etm_xport_vldc_conn == NULL) {
		vldc_opt_op_t op;

		/* Set the channel to reliable mode */
		op.op_sel = VLDC_OP_SET;
		op.opt_sel = VLDC_OPT_MODE;
		op.opt_val = LDC_MODE_RELIABLE;

		if (ioctl(_conn->fd, VLDC_IOCTL_OPT_OP, &op) != 0) {
			/* errno assumed set by above call */
			(void) close(_conn->fd);
			etm_xport_free_addr(hdl, _addr);
			fmd_hdl_free(hdl, _conn, sizeof (_etm_xport_conn_t));
			etm_xport_stats.xport_os_ioctl_fail.fmds_value.ui64++;
			(void) pthread_mutex_unlock(&etm_xport_vldc_lock);
			return (NULL);
		}

		etm_xport_vldc_conn = _conn;
	} else if (use_vldc && etm_xport_vldc_conn != NULL) {
		_conn->fd = dup(etm_xport_vldc_conn->fd);
	}

	(void) pthread_mutex_unlock(&etm_xport_vldc_lock);

	/* return the fully formed connection handle */

	_conn->magic_num = ETM_XPORT_DD_MAGIC_CONN;
	_conn->addr = _addr;

	return (_conn);

} /* etm_xport_open() */

/*
 * etm_xport_accept - accept a request to open a connection,
 *			pending until a remote endpoint opens a
 *			a new connection to us [and sends an ETM msg],
 *			per non-NULL addrp optionally indicate the
 *			remote address if known/avail (NULL if not),
 *			return the connection handle,
 *			or NULL and set errno on failure
 *
 * caveats:
 *		any returned transport address is valid only for
 *		as long as the associated connection remains open;
 *		callers should not try to free the transport address
 *
 *		if new connections are rapid relative to how
 *		frequently this function is called, fairness will
 *		be provided among which connections are accepted
 *
 *		this function may maintain state to recognize [new]
 *		connections and/or to provide fairness
 */

etm_xport_conn_t
etm_xport_accept(fmd_hdl_t *hdl, etm_xport_addr_t *addrp)
{
	_etm_xport_addr_t	*_addr;	/* address handle */
	_etm_xport_addr_t	**_addrv; /* vector of addresses */
	_etm_xport_conn_t	*_conn;	/* connection handle */
	_etm_xport_conn_t	*rv;	/* ret val */
	uint8_t			buf[4];	/* buffer for peeking */
	int			n;	/* byte cnt */
	struct timespec		tms;	/* for nanosleep() */

	rv = NULL;	/* default is failure */

	_conn = NULL;
	_addrv = NULL;

	tms.tv_sec = ETM_SLEEP_QUIK;
	tms.tv_nsec = 0;

	/*
	 * get the default dst transport address and open a connection to it;
	 * there is only 1 default addr
	 */

	if ((_addrv = (void*)etm_xport_get_ev_addrv(hdl, NULL)) == NULL) {
		/* errno assumed set by above call */
		goto func_ret;
	}

	if (_addrv[0] == NULL) {
		errno = ENXIO;	/* missing addr */
		etm_xport_stats.xport_accept_badargs.fmds_value.ui64++;
		goto func_ret;
	}

	if (_addrv[1] != NULL) {
		errno = E2BIG;	/* too many addrs */
		etm_xport_stats.xport_accept_badargs.fmds_value.ui64++;
		goto func_ret;
	}

	_addr = _addrv[0];
	_addr->fn = etm_xport_get_fn(hdl, ETM_IO_OP_RD);

	if ((_conn = etm_xport_open(hdl, _addr)) == NULL) {
		/* errno assumed set by above call */
		goto func_ret;
	}

	if (etm_xport_should_fake_dd) {
		(void) nanosleep(&tms, NULL);	/* delay [for resp capture] */
		(void) ftruncate(_conn->fd, 0); /* act like socket/queue/pipe */
	}

	/*
	 * peek from the connection to simulate an accept() system call
	 * behavior; this will pend until some ETM message is written
	 * from the other end
	 */

	if (use_vldc) {
		pollfd_t pollfd;

		pollfd.events = POLLIN;
		pollfd.revents = 0;
		pollfd.fd = _conn->fd;

		if ((n = poll(&pollfd, 1, -1)) < 1) {
			if (n == 0) {
				errno = EIO;
			}
			goto func_ret;
		}
	} else {
		if ((n = etm_xport_raw_peek(hdl, _conn, buf, 1)) < 0) {
			errno = (-n);
			goto func_ret;
		}
	}

	rv = _conn;	/* success, return the open connection */

func_ret:

	/* cleanup the connection if failed */

	if (rv == NULL) {
		if (_conn != NULL) {
			(void) etm_xport_close(hdl, _conn);
		}
	} else {
		if (addrp != NULL) {
			*addrp = _conn->addr;
		}
	}

	/* free _addrv and all its transport addresses */

	if (_addrv != NULL) {
		etm_xport_free_addrv(hdl, (void *)_addrv);
	}

	if (etm_xport_debug_lvl >= 2) {
		fmd_hdl_debug(hdl, "info: accept conn %p w/ *addrp %p\n",
		    rv, (addrp != NULL ? *addrp : NULL));
	}

	return (rv);

} /* etm_xport_accept() */

/*
 * etm_xport_close - close a connection from either endpoint,
 *			return the original connection handle,
 *			or NULL and set errno if close failed
 */

etm_xport_conn_t
etm_xport_close(fmd_hdl_t *hdl, etm_xport_conn_t conn)
{
	etm_xport_conn_t	rv;	/* ret val */
	_etm_xport_conn_t	*_conn;	/* connection handle */
	int			nev;	/* -errno val */

	_conn = conn;

	rv = _conn;	/* assume success */

	if ((nev = etm_xport_valid_conn(_conn)) < 0) {
		_conn = NULL;
		rv = NULL;
		goto func_ret;
	}

	/* close the device node */

	(void) pthread_mutex_lock(&etm_xport_vldc_lock);

	if (close(_conn->fd) < 0) {
		/* errno assumed set by above call */
		etm_xport_stats.xport_os_close_fail.fmds_value.ui64++;
		nev = (-errno);
		rv = NULL;
	}

	if (use_vldc && (_conn == etm_xport_vldc_conn)) {
		etm_xport_vldc_conn = NULL;
	}

	(void) pthread_mutex_unlock(&etm_xport_vldc_lock);

func_ret:

	/* cleanup the connection */

	if (_conn != NULL) {
		etm_xport_free_addr(hdl, _conn->addr);
		_conn->addr = NULL;
		_conn->magic_num = 0;
		_conn->fd = -1;
		fmd_hdl_free(hdl, _conn, sizeof (_etm_xport_conn_t));
	}

	if (rv == NULL) {
		errno = (-nev);
	}
	return (rv);

} /* etm_xport_close() */

/*
 * etm_xport_get_ev_addrv - indicate which transport addresses
 *				are implied as destinations by the
 *				given FMA event, if given no FMA event
 *				(NULL) indicate default or policy
 *				driven dst transport addresses,
 *				return an allocated NULL terminated
 *				vector of allocated transport addresses,
 *				or NULL and set errno if none
 * caveats:
 *		callers should never try to individually free an addr
 *		within the returned vector
 */

etm_xport_addr_t *
etm_xport_get_ev_addrv(fmd_hdl_t *hdl, nvlist_t *evp)
{
	_etm_xport_addr_t	*_addr;		/* address handle */
	_etm_xport_addr_t	**_addrv;	/* vector of addresses */

	if (evp == NULL) {

		/*
		 * allocate address handles for default/policy destinations
		 *
		 * in reality we have just 1 dst transport addr
		 */

		_addr = fmd_hdl_zalloc(hdl, sizeof (_etm_xport_addr_t),
		    FMD_SLEEP);
	} else {

		/*
		 * allocate address handles per FMA event content
		 *
		 * in reality we have just 1 dst transport addr
		 */

		_addr = fmd_hdl_zalloc(hdl, sizeof (_etm_xport_addr_t),
		    FMD_SLEEP);
	} /* whether caller passed in a FMA event */

	/* allocate vector with 1 non-NULL transport addr */

	_addrv = fmd_hdl_zalloc(hdl, 2 * sizeof (_etm_xport_addr_t *),
	    FMD_SLEEP);

	_addr->fn = etm_xport_get_fn(hdl, ETM_IO_OP_WR);
	_addr->magic_num = ETM_XPORT_DD_MAGIC_ADDR;
	_addrv[0] = _addr;
	_addrv[1] = NULL;

	return ((void *) _addrv);

} /* etm_xport_get_ev_addrv() */

/*
 * etm_xport_free_addrv - free the given vector of transport addresses,
 *				including each transport address
 */

void
etm_xport_free_addrv(fmd_hdl_t *hdl, etm_xport_addr_t *addrv)
{
	_etm_xport_addr_t	**_addrv;	/* vector of addrs */
	int			i;		/* vector index */

	if (addrv == NULL) {
		etm_xport_stats.xport_free_addrv_badargs.fmds_value.ui64++;
		return;
	}

	_addrv = (void*)addrv;

	for (i = 0; _addrv[i] != NULL; i++) {
		etm_xport_free_addr(hdl, _addrv[i]);
		_addrv[i] = NULL;
	}
	fmd_hdl_free(hdl, _addrv, (i + 1) * sizeof (_etm_xport_addr_t *));

} /* etm_xport_free_addrv() */

/*
 * etm_xport_get_addr_conn - indicate which connections in a NULL
 *				terminated vector of connection
 *				handles are associated with the
 *				given transport address,
 *				return an allocated NULL terminated
 *				vector of those connection handles,
 *				or NULL and set errno if none
 */

etm_xport_conn_t *
etm_xport_get_addr_conn(fmd_hdl_t *hdl, etm_xport_conn_t *connv,
			    etm_xport_addr_t addr)
{
	_etm_xport_conn_t	**_connv; /* vector of connections */
	_etm_xport_conn_t	**_mcv;	/* matching connections vector */
	_etm_xport_addr_t	*_addr;	/* transport addr to match */
	int			n;	/* matching transport addr cnt */
	int			i;	/* vector index */

	if ((connv == NULL) || (addr == NULL)) {
		errno = EINVAL;
		etm_xport_stats.xport_get_addr_conn_badargs.fmds_value.ui64++;
		return (NULL);
	}

	_connv = (void*)connv;
	_addr = (void*)addr;

	/* count, allocate space for, and copy, all matching addrs */

	n = 0;
	for (i = 0; _connv[i] != NULL; i++) {
		if ((_connv[i]->addr == _addr) ||
		    ((_connv[i]->addr != NULL) &&
		    (_connv[i]->addr->fn == _addr->fn))) {
			n++;
		}
	} /* for counting how many addresses match */

	_mcv = fmd_hdl_zalloc(hdl, (n + 1) * sizeof (_etm_xport_conn_t *),
	    FMD_SLEEP);
	n = 0;
	for (i = 0; _connv[i] != NULL; i++) {
		if ((_connv[i]->addr == _addr) ||
		    ((_connv[i]->addr != NULL) &&
		    (_connv[i]->addr->fn == _addr->fn))) {
			_mcv[n] = _connv[i];
			n++;
		}
	} /* for copying matching address pointers */
	_mcv[n] = NULL;

	return ((void *) _mcv);

} /* etm_xport_get_addr_conn() */

/*
 * etm_xport_get_any_lcc - indicate which endpoint has undergone
 *			a life cycle change and what that change
 *			was (ex: came up), pending until a change
 *			has occured for some/any endpoint,
 *			return the appropriate address handle,
 *			or NULL and set errno if problem
 *
 * caveats:
 *		this function maintains or accesses state/history
 *		regarding life cycle changes of endpoints
 *
 *		if life cycle changes are rapid relative to how
 *		frequently this function is called, fairness will
 *		be provided among which endpoints are reported
 */

etm_xport_addr_t
etm_xport_get_any_lcc(fmd_hdl_t *hdl, etm_xport_lcc_t *lccp)
{
	if ((hdl == NULL) || (lccp == NULL)) {
		etm_xport_stats.xport_get_any_lcc_badargs.fmds_value.ui64++;
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * function not needed in FMA Phase 1 for sun4v/Ontario
	 */

	errno = ENOTSUP;
	return (NULL);

} /* etm_xport_get_any_lcc() */

/*
 * etm_xport_fini - finish/teardown any transport infrastructure
 *			after all connections are closed,
 *			return 0 or -errno value if teardown failed
 */

int
etm_xport_fini(fmd_hdl_t *hdl)
{
	fmd_hdl_debug(hdl, "info: xport finalizing\n");

	if (use_vldc && (etm_xport_vldc_conn != NULL)) {
		(void) etm_xport_close(hdl, etm_xport_vldc_conn);
		etm_xport_vldc_conn = NULL;
	}

	/* free any long standing properties from FMD */

	fmd_prop_free_string(hdl, etm_xport_addrs);

	/* cleanup the intermediate read buffer */

	if (etm_xport_irb_tail != etm_xport_irb_head) {
		fmd_hdl_debug(hdl, "warning: xport %d bytes stale data\n",
		    (int)(etm_xport_irb_tail - etm_xport_irb_head));
	}
	fmd_hdl_free(hdl, etm_xport_irb_area, 2 * etm_xport_irb_mtu_sz);
	etm_xport_irb_area = NULL;
	etm_xport_irb_head = NULL;
	etm_xport_irb_tail = NULL;
	etm_xport_irb_mtu_sz = 0;

	/* cleanup statistics from FMD */

	(void) fmd_stat_destroy(hdl,
	    sizeof (etm_xport_stats) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&etm_xport_stats);

	fmd_hdl_debug(hdl, "info: xport finalized ok\n");
	return (0);

} /* etm_xport_fini() */

/*
 * ------------------------ input/output functions ---------------------------
 */

/*
 * etm_xport_read - try to read N bytes from the connection
 *			into the given buffer,
 *			return how many bytes actually read
 *			or -errno value
 */

ssize_t
etm_xport_read(fmd_hdl_t *hdl, etm_xport_conn_t conn, void *buf,
							size_t byte_cnt)
{
	return (etm_xport_buffered_read(hdl, conn, buf, byte_cnt));

} /* etm_xport_read() */

/*
 * etm_xport_write - try to write N bytes to the connection
 *			from the given buffer,
 *			return how many bytes actually written
 *			or -errno value
 */

ssize_t
etm_xport_write(fmd_hdl_t *hdl, etm_xport_conn_t conn, void *buf,
							size_t byte_cnt)
{
	_etm_xport_conn_t	*_conn;		/* connection handle */
	int			n;		/* byte cnt */

	_conn = conn;

	if (hdl == NULL) {		/* appease lint */
		return (-EINVAL);
	}
	if ((n = etm_xport_valid_conn(_conn)) < 0) {
		return (n);
	}

	/* write to the connection device's open file descriptor */

	if ((n = write(_conn->fd, buf, byte_cnt)) < 0) {
		/* errno assumed set by above call */
		etm_xport_stats.xport_os_write_fail.fmds_value.ui64++;
		n = (-errno);
	}

	return (n);

} /* etm_xport_write() */

/*
 * ------------------------ miscellaneous functions --------------------------
 */

/*
 * etm_xport_get_opt - get a connection's transport option value,
 *			return the current value
 *			or -errno value (ex: -ENOTSUP)
 */

ssize_t
etm_xport_get_opt(fmd_hdl_t *hdl, etm_xport_conn_t conn, etm_xport_opt_t opt)
{
	ssize_t			rv;		/* ret val */
	_etm_xport_conn_t	*_conn;		/* connection handle */
	etm_xport_opt_op_t	op_ctl;		/* struct for option ops */
	ssize_t			n;		/* gen use */

	rv = 0;
	_conn = conn;

	if (hdl == NULL) {		/* appease lint */
		return (-EINVAL);
	}
	if ((n = etm_xport_valid_conn(_conn)) < 0) {
		return (n);
	}

	op_ctl.oo_op = ETM_XPORT_OPT_GET;
	op_ctl.oo_opt = opt;

	if (etm_xport_should_fake_dd) {
		n = etm_fake_ioctl(_conn->fd, ETM_XPORT_IOCTL_OPT_OP, &op_ctl);
	} else if (use_vldc) {
		if (opt == ETM_XPORT_OPT_MTU_SZ) {
			vldc_opt_op_t operation;

			operation.op_sel = VLDC_OP_GET;
			operation.opt_sel = VLDC_OPT_MTU_SZ;

			n = ioctl(_conn->fd, VLDC_IOCTL_OPT_OP, &operation);

			op_ctl.oo_val = operation.opt_val;
		} else {
			return (-EINVAL);
		}
	} else {
		n = ioctl(_conn->fd, ETM_XPORT_IOCTL_OPT_OP, &op_ctl);
	}
	if (n < 0) {
		/* errno assumed set by above call */
		rv = (-errno);
		etm_xport_stats.xport_os_ioctl_fail.fmds_value.ui64++;
	} else {
		rv = (int)op_ctl.oo_val;
	}

	return (rv);

} /* etm_xport_get_opt() */
