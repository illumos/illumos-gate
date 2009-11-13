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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * NCA mdb module.  Provides a collection of dcmds and walkers that
 * operate on core NCA data structures.  Dependencies on NCA internals
 * are described in $SRC/uts/common/inet/nca/nca.h.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include <ctype.h>
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/processor.h>
#include <netinet/in.h>
#include <netinet/ip6.h>	/* must come before common.h */
#include <inet/common.h>	/* must come before led.h */
#include <inet/led.h>		/* must come before ip.h */
#include <inet/ip.h>		/* must come before tcp.h */
#include <inet/tcp.h>		/* must come before nca/nca.h */
#include <inet/nca/nca.h>
#include <inet/nca/ncadoorhdr.h>

#define	NCA_WALK_PLRU	(void *)1
#define	NCA_WALK_VLRU	(void *)2
#define	NCA_ADDR_WIDTH	11	/* kernel addresses *shouldn't* be wider */
#define	YESNO(bool)	((bool) ? 'Y' : 'n')

/*
 * Structure for assigning a name to a region of memory.
 */
typedef struct {
	const char	*nm_name;	/* name of region */
	int		nm_len;		/* length to region */
	uintptr_t	nm_addr;	/* starting address of region */
} namedmem_t;

/*
 * Structure for giving a name to a constant.
 */
typedef struct {
	const char *const_name;  /* name of constant */
	int	    const_value; /* constant itself */
} constname_t;

/*
 * Structure for mapping a bit to a name and a description.  Instances
 * of this datatype should always be arrays which decode bits in a
 * number, and the index into the array should contain the description
 * of a bit at position "index" in the number being decoded.  The list
 * must be terminated by an entry with a NULL `bit_name'.
 */
typedef struct {
	const char *bit_name;	/* name of bit */
	const char *bit_descr;	/* description of bit's purpose */
} bitname_t;

/*
 * Note: These should be defined in upside down order to their
 * definitions in nca.h
 * (Assumes that current ordering convention in nca.h will
 * prevail for future additions)
 */
static const bitname_t node_refs[] = {
	{ "REF_UNUSED",		"0x00000001" },
	{ "REF_UNUSED",		"0x00000002" },
	{ "REF_UNUSED",		"0x00000004" },
	{ "REF_UNUSED",		"0x00000008" },
	{ "REF_UNUSED",		"0x00000010" },
	{ "REF_UNUSED",		"0x00000020" },
	{ "REF_UNUSED",		"0x00000040" },
	{ "REF_UNUSED",		"0x00000080" },
	{ "REF_UNUSED",		"0x00000100" },
	{ "REF_UNUSED",		"0x00000200" },
	{ "REF_UNUSED",		"0x00000400" },
	{ "REF_SEGMAP",		"segmapped (PHYS|VIRT)" },
	{ "REF_NCAFS",		"NCAfs required" },
	{ "REF_VNODE",		"vnode hashed" },
	{ "REF_ERROR",		"errored" },
	{ "REF_OWNED",		"owned (won't be freed)" },
	{ "REF_UPCALL",		"upcall not completed yet" },
	{ "REF_CTAG",		"CTAG hashed" },
	{ "REF_PREEMPT",	"processing preempted" },
	{ "REF_ONVLRU",		"on virtual memory LRU list" },
	{ "REF_ONPLRU",		"on physical memory LRU list" },
	{ "REF_MISS",		"in miss processing" },
	{ "REF_NOLRU",		"not safe for LRU reclaim" },
	{ "REF_RESP",		"done parsing response header" },
	{ "REF_FILE",		"reachable through filename hash" },
	{ "REF_SAFED",		"not safe for use" },
	{ "REF_DONE",		"done with miss processing" },
	{ "REF_KMEM",		"content-backed via kmem_alloc()" },
	{ "REF_CKSUM",		"checksum mapping in-use" },
	{ "REF_VIRT",		"virtually mapped (data valid)" },
	{ "REF_PHYS",		"physically mapped (pp valid)" },
	{ "REF_URI",		"reachable through URI hash" },
	{ NULL }
};

static const bitname_t advise_types[] = {
	{ "ADVISE",		"" },
	{ "ADVISE_REPLACE",	"replace cached object with provided object" },
	{ "ADVISE_FLUSH",	"flush cached object" },
	{ "ADVISE_TEMP",	"return this object; keep cached object" },
	{ NULL }
};

/*
 * Print `len' bytes of buffer `buf'.  Handle nonprintable characters
 * specially.
 */
static void
printbuf(uint8_t *buf, size_t len)
{
	size_t	i;

	/*
	 * TODO: display octal form of unprintable characters in dim mode
	 *	 once mdb pager bug is fixed.
	 */
	for (i = 0; i < len; i++)
		mdb_printf(isgraph(buf[i]) ? "%c" : "\\%#o", buf[i]);

	mdb_printf("\n");
}

/*
 * Convert HTTP method operation `method' to a name.
 */
static const char *
method2name(unsigned int method)
{
	unsigned int i;
	static constname_t http_methods[] = {
		{ "NCA_UNKNOWN", NCA_UNKNOWN	},
		{ "NCA_OPTIONS", NCA_OPTIONS	},
		{ "NCA_GET",	 NCA_GET	},
		{ "NCA_HEAD",	 NCA_HEAD	},
		{ "NCA_POST",	 NCA_POST	},
		{ "NCA_PUT",	 NCA_PUT	},
		{ "NCA_DELETE",  NCA_DELETE	},
		{ "NCA_TRACE",	 NCA_TRACE	},
		{ "NCA_RAW",	 NCA_RAW	},
		{ NULL }
	};

	for (i = 0; http_methods[i].const_name != NULL; i++) {
		if (method == http_methods[i].const_value)
			return (http_methods[i].const_name);
	}

	return ("<unknown>");
}

/*
 * Convert TCP state `state' to a name.
 */
static const char *
state2name(int state)
{
	unsigned int i;
	static constname_t tcp_states[] = {
		{ "CLOSED",	 TCPS_CLOSED		},
		{ "IDLE",	 TCPS_IDLE		},
		{ "BOUND",	 TCPS_BOUND		},
		{ "LISTEN",	 TCPS_LISTEN		},
		{ "SYN_SENT",	 TCPS_SYN_SENT		},
		{ "SYN_RCVD",	 TCPS_SYN_RCVD		},
		{ "ESTABLISHED", TCPS_ESTABLISHED 	},
		{ "CLOSE_WAIT",	 TCPS_CLOSE_WAIT	},
		{ "FIN_WAIT1",	 TCPS_FIN_WAIT_1	},
		{ "FIN_WAIT2",	 TCPS_FIN_WAIT_2	},
		{ "CLOSING",	 TCPS_CLOSING		},
		{ "LAST_ACK",	 TCPS_LAST_ACK 		},
		{ "TIME_WAIT",	 TCPS_TIME_WAIT		},
		{ NULL }
	};

	for (i = 0; tcp_states[i].const_name != NULL; i++) {
		if (state == tcp_states[i].const_value)
			return (tcp_states[i].const_name);
	}

	return ("<unknown>");
}

/*
 * Convert an nca_io2_t direct_type into a name.
 */
static const char *
direct2name(unsigned int type)
{
	unsigned int i;
	static const constname_t direct_types[] = {
		{ "DIRECT_NONE",	NCA_IO_DIRECT_NONE	},
		{ "DIRECT_FILENAME",	NCA_IO_DIRECT_FILENAME	},
		{ "DIRECT_SHMSEG",	NCA_IO_DIRECT_SHMSEG	},
		{ "DIRECT_FILEDESC",	NCA_IO_DIRECT_FILEDESC	},
		{ "DIRECT_CTAG",	NCA_IO_DIRECT_CTAG	},
		{ "DIRECT_SPLICE",	NCA_IO_DIRECT_SPLICE	},
		{ "DIRECT_TEE",		NCA_IO_DIRECT_TEE 	},
		{ "DIRECT_FILE_FD",	NCA_IO_DIRECT_FILE_FD 	},
		{ NULL,			0			}
	};

	for (i = 0; direct_types[i].const_name != NULL; i++) {
		if (type == direct_types[i].const_value)
			return (direct_types[i].const_name);
	}

	return ("<unknown>");
}

/*
 * Convert an nca_io2_t operation into a name.
 */
static const char *
op2name(nca_op_t op)
{
	unsigned int i;
	static const constname_t op_types[] = {
		{ "http",		http_op		},
		{ "error",		error_op	},
		{ "error_retry",	error_retry_op	},
		{ "resource",		resource_op	},
		{ "timeout",		timeout_op	},
		{ "door_attach",	door_attach_op	},

		{ "log",		log_op		},
		{ "log_ok",		log_ok_op	},
		{ "log_error",		log_error_op	},
		{ "log_op_fiov",	log_op_fiov	},

		{ NULL,			0		}
	};

	for (i = 0; op_types[i].const_name != NULL; i++) {
		if (op == op_types[i].const_value)
			return (op_types[i].const_name);
	}

	return ("<unknown>");
}

/*
 * Convert from ticks to milliseconds.
 */
static uint64_t
tick2msec(uint64_t tick)
{
	static int tick_per_msec;
	static int msec_per_tick;
	static int once;

	if (once == 0) {
		if (mdb_readvar(&tick_per_msec, "tick_per_msec") == -1) {
			mdb_warn("cannot read symbol tick_per_msec");
			return (0);
		}
		if (mdb_readvar(&msec_per_tick, "msec_per_tick") == -1) {
			mdb_warn("cannot read symbol msec_per_tick");
			return (0);
		}
		once++;
	}

	return (tick_per_msec ? tick / tick_per_msec : tick * msec_per_tick);
}

/*
 * Print the core fields in an nca_io2_t.  With the "-v" argument,
 * provide more verbose output.  With the "-p" argument, print payload
 * information.
 */
static int
nca_io2(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	unsigned int	i;
	unsigned int	payload_len;
	uint64_t	payload_output_max = 0;
	unsigned int	verbose = FALSE;
	const int	IO2_ADVDELT = NCA_ADDR_WIDTH + 1;
	boolean_t	arm;
	nca_io2_t	io2;
	uint8_t		*buf;
	namedmem_t	area[3];

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'p', MDB_OPT_UINT64, &payload_output_max, NULL) != argc)
		return (DCMD_USAGE);

	if (!DCMD_HDRSPEC(flags) && verbose)
		mdb_printf("\n\n");

	if (DCMD_HDRSPEC(flags) || verbose) {
		mdb_printf("%<u>%-*s %2s %4s %8s %*s %8s %16s %-12s%</u>\n",
		    NCA_ADDR_WIDTH, "ADDR", "AV", "MFNP", "TID",
		    NCA_ADDR_WIDTH, "CONN", "CONN_TAG", "CACHE_TAG",
		    "OPERATION");
	}

	if (mdb_vread(&io2, sizeof (nca_io2_t), addr) == -1) {
		mdb_warn("cannot read nca_io2_t at %p", addr);
		return (DCMD_ERR);
	}

	if (io2.version != NCA_HTTP_VERSION2)
		mdb_warn("nca_io2_t at %p has incorrect version `%u'\n", addr,
		    io2.version);

	mdb_printf("%0*p %02x %c%c%c%c %08x %0*llx %08x %016llx %s\n",
	    NCA_ADDR_WIDTH, addr, io2.advisory, YESNO(io2.more),
	    YESNO(io2.first), YESNO(io2.nocache), YESNO(io2.preempt),
	    (uint32_t)io2.tid, NCA_ADDR_WIDTH, io2.cid, io2.tag, io2.ctag,
	    op2name(io2.op));

	if (verbose) {
		arm = B_TRUE;
		for (i = 0; advise_types[i].bit_name != NULL; i++) {
			if ((io2.advisory & (1 << i)) == 0)
				continue;

			if (arm) {
				mdb_printf("%*s|\n", IO2_ADVDELT, "");
				mdb_printf("%*s+-->  ", IO2_ADVDELT, "");
				arm = B_FALSE;
			} else
				mdb_printf("%*s      ", IO2_ADVDELT, "");

			mdb_printf("%-15s %s\n", advise_types[i].bit_name,
			    advise_types[i].bit_descr);
		}
	}

	payload_len = io2.data_len + io2.direct_len + io2.trailer_len;

	if (payload_output_max == 0 || payload_len == 0)
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf("\n%u byte payload consists of:\n", payload_len);
	mdb_inc_indent(4);

	buf = mdb_alloc(payload_output_max, UM_SLEEP);

	area[0].nm_name = "data";
	area[0].nm_addr = addr + io2.data;
	area[0].nm_len  = io2.data_len;

	area[1].nm_name = direct2name(io2.direct_type);
	area[1].nm_addr = addr + io2.direct;
	area[1].nm_len  = io2.direct_len;

	area[2].nm_name = "trailer";
	area[2].nm_addr = addr + io2.trailer;
	area[2].nm_len  = io2.trailer_len;

	for (i = 0; i < sizeof (area) / sizeof (area[0]); i++) {
		if (area[i].nm_len <= 0)
			continue;

		mdb_printf("%d byte %s area at %p (", area[i].nm_len,
		    area[i].nm_name, area[i].nm_addr);

		if (area[i].nm_len > payload_output_max) {
			mdb_printf("first");
			area[i].nm_len = (int)payload_output_max;
		} else
			mdb_printf("all");

		mdb_printf(" %u bytes follow):\n", area[i].nm_len);
		if (mdb_vread(buf, area[i].nm_len, area[i].nm_addr) == -1)
			mdb_warn("cannot read %s area at %p", area[i].nm_name,
			    area[i].nm_addr);
		else {
			mdb_inc_indent(4);
			printbuf(buf, area[i].nm_len);
			mdb_dec_indent(4);
		}
	}
	mdb_dec_indent(4);
	mdb_dec_indent(4);

	mdb_free(buf, payload_output_max);

	return (DCMD_OK);
}

static void
nca_io2_help(void)
{
	mdb_printf("Print the core information for a given NCA nca_io2_t.\n");
	mdb_printf("Options:\n");
	mdb_printf("\t-p N\tshow up to N bytes of payload information from\n");
	mdb_printf("\t\teach payload area\n");
	mdb_printf("\t\t(reminder: default radix is %<b>hex%</b>)\n");
	mdb_printf("\t-v\tbe verbose (more descriptive)\n");
}

/*
 * Print the core fields for one or all NCA timers.  If no address is
 * specified, all NCA timers are printed; otherwise the specified timer
 * list is printed.  With the "-e" argument, the "encapsulated" pointer
 * for each te_t in a given tb_t is shown in parentheses.
 */
static int
nca_timer(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	unsigned int	show_encap = FALSE;
	void		*tb_addr, *te_addr;
	clock_t		lbolt, first_exec = 0;
	ti_t		ti;
	tb_t		tb;
	te_t		te;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("nca_timer", "nca_timer", argc, argv) == -1) {
			mdb_warn("cannot walk timer list");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv, 'e', MDB_OPT_SETBITS, TRUE, &show_encap,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-*s %-*s %-55s%</u>\n", NCA_ADDR_WIDTH, "TI",
		    NCA_ADDR_WIDTH, "SQUEUE", "FIRELIST +MSEC");
	}

	if (mdb_vread(&ti, sizeof (ti_t), addr) == -1) {
		mdb_warn("cannot read ti_t at %p", addr);
		return (DCMD_ERR);
	}

	if ((lbolt = (clock_t)mdb_get_lbolt()) == -1)
		return (DCMD_ERR);

	mdb_printf("%0*p %0*p", NCA_ADDR_WIDTH, addr, NCA_ADDR_WIDTH, ti.ep);
	mdb_inc_indent(24);
	for (tb_addr = ti.head; tb_addr != NULL; tb_addr = tb.next) {
		if (mdb_vread(&tb, sizeof (tb_t), (uintptr_t)tb_addr) == -1) {
			mdb_warn("cannot read tb_t at %p", tb_addr);
			return (DCMD_ERR);
		}
		if (first_exec == 0) {
			mdb_printf(" %ld", tick2msec(tb.exec - lbolt));
			first_exec = tb.exec;
		} else
			mdb_printf(" %+lld", tick2msec(tb.exec - first_exec));

		if (!show_encap || tb.head == NULL)
			continue;

		mdb_printf("(");
		for (te_addr = tb.head; te_addr != NULL; te_addr = te.next) {
			if (mdb_vread(&te, sizeof (te_t), (uintptr_t)te_addr)
			    == -1) {
				mdb_warn("cannot read te_t at %p", te_addr);
				return (DCMD_ERR);
			}
			mdb_printf("%0p%s", te.ep, te.next == NULL ? "" : " ");
		}
		mdb_printf(")");
	}
	mdb_printf("\n");
	mdb_dec_indent(24);

	return (DCMD_OK);
}

static void
nca_timer_help(void)
{
	mdb_printf("Print the core information for one or all NCA timer\n");
	mdb_printf("lists.  If no timer list is given, then all timer lists\n");
	mdb_printf("are shown.  For each timer list, the list of timers to\n");
	mdb_printf("fire on that list are shown, the first in absolute\n");
	mdb_printf("ticks and the rest in ticks relative to the first.\n\n");
	mdb_printf("Options:\n");
	mdb_printf("\t-e\tshow the encapsulating pointer for each event ");
	mdb_printf("at each fire time\n");
}

/*
 * Print the core fields in an NCA node_t.  With the "-r" argument,
 * provide additional information about the request; with "-v",
 * provide more verbose output.
 */
static int
nca_node(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	unsigned int	i, max;
	unsigned int	verbose = FALSE;
	unsigned int	request = FALSE;
	const int	NODE_REFDELT = NCA_ADDR_WIDTH + 4 + 2;
	boolean_t	arm;
	node_t		node;
	char		*buf;
	namedmem_t	hdr[4];

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'r', MDB_OPT_SETBITS, TRUE, &request, 'p', NULL) != argc)
		return (DCMD_USAGE);

	if (!DCMD_HDRSPEC(flags) && verbose)
		mdb_printf("\n\n");

	if (DCMD_HDRSPEC(flags) || verbose) {
		mdb_printf("%<u>%-*s %4s %5s %8s %-*s %-*s %-*s %-*s%</u>\n",
		    NCA_ADDR_WIDTH, "ADDR", "REF", "STATE", "DATASIZE",
		    NCA_ADDR_WIDTH, "SQUEUE", NCA_ADDR_WIDTH, "REQUEST",
		    NCA_ADDR_WIDTH, "PLRUN", NCA_ADDR_WIDTH, "VLRUN");
	}

	if (mdb_vread(&node, sizeof (node_t), addr) == -1) {
		mdb_warn("cannot read node_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0*p %4d %05x %8d %0*p %0*p %0*p %0*p\n",
	    NCA_ADDR_WIDTH, addr, node.cnt, node.ref,
	    node.datasz, NCA_ADDR_WIDTH, node.sqp, NCA_ADDR_WIDTH,
	    node.req, NCA_ADDR_WIDTH, node.plrunn, NCA_ADDR_WIDTH, node.vlrunn);

	if (verbose) {
		arm = B_TRUE;
		for (i = 0; node_refs[i].bit_name != NULL; i++) {
			if ((node.ref & (1 << i)) == 0)
				continue;

			if (arm) {
				mdb_printf("%*s|\n", NODE_REFDELT, "");
				mdb_printf("%*s+-->  ", NODE_REFDELT, "");
				arm = B_FALSE;
			} else
				mdb_printf("%*s      ", NODE_REFDELT, "");

			mdb_printf("%-12s %s\n", node_refs[i].bit_name,
			    node_refs[i].bit_descr);
		}
	}

	if (!request || node.req == NULL)
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf("\n%u byte HTTP/%u.%u %s request (%u bytes in header, "
	    "%u in content)\n", node.reqsz, node.version >> 16,
	    node.version & 0xff, method2name(node.method), node.reqhdrsz,
	    node.reqcontl);

	hdr[0].nm_name = "URI";
	hdr[0].nm_addr = (uintptr_t)node.path;
	hdr[0].nm_len  = node.pathsz;

	hdr[1].nm_name = "Accept";
	hdr[1].nm_addr = (uintptr_t)node.reqaccept;
	hdr[1].nm_len  = node.reqacceptsz;

	hdr[2].nm_name = "Accept-Language";
	hdr[2].nm_addr = (uintptr_t)node.reqacceptl;
	hdr[2].nm_len  = node.reqacceptlsz;

	hdr[3].nm_name = "Host";
	hdr[3].nm_addr = (uintptr_t)node.reqhost;
	hdr[3].nm_len  = node.reqhostsz;

	/*
	 * A little optimization.  Allocate all of the necessary memory here,
	 * so we don't have to allocate on each loop iteration.
	 */

	max = node.reqhdrsz;
	for (i = 0; i < 4; i++)
		max = MAX(max, hdr[i].nm_len);
	max++;

	buf = mdb_alloc(max, UM_SLEEP);

	mdb_inc_indent(4);
	for (i = 0; i < sizeof (hdr) / sizeof (hdr[0]); i++) {
		if (hdr[i].nm_len <= 0)
			continue;

		if (mdb_vread(buf, hdr[i].nm_len, hdr[i].nm_addr) == -1) {
			mdb_warn("cannot read \"%s\" header field at %p",
			    hdr[i].nm_name, hdr[i].nm_addr);
			continue;
		}
		buf[hdr[i].nm_len] = '\0';

		mdb_printf("%s: ", hdr[i].nm_name);
		mdb_inc_indent(4);
		mdb_printf("%s\n", buf);
		mdb_dec_indent(4);
	}

	if (node.reqhdrsz > 0 && verbose) {
		if (mdb_vread(buf, node.reqhdrsz, (uintptr_t)node.reqhdr) == -1)
			mdb_warn("cannot read header at %p", node.reqhdr);
		else {
			mdb_printf("Raw header: ");
			mdb_inc_indent(4);
			printbuf((uint8_t *)buf, node.reqhdrsz);
			mdb_dec_indent(4);
		}
	}
	mdb_dec_indent(4);
	mdb_dec_indent(4);

	mdb_free(buf, max);

	return (DCMD_OK);
}

static void
nca_node_help(void)
{
	mdb_printf("Print the core information for a given NCA node_t.\n\n");
	mdb_printf("Options:\n");
	mdb_printf("\t-r\tdisplay HTTP request information\n");
	mdb_printf("\t-v\tbe verbose (more descriptive)\n");
}

/*
 * Print the core fields in an NCA nca_conn_t.  With the "-t" argument, skip
 * all nca_conn_t's that are in the TIME_WAIT state.  With the "-x" argument,
 * show the xmit data.
 */
static int
nca_conn(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	unsigned int	i;
	nca_conn_t 		conn;
	unsigned int	show_timewait = TRUE;
	unsigned int	show_xmit = FALSE;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv, 'x', MDB_OPT_SETBITS, TRUE, &show_xmit,
	    't', MDB_OPT_CLRBITS, TRUE, &show_timewait, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-*s %3s %8s %15s %15s %-*s %-10s%</u>\n",
		    NCA_ADDR_WIDTH, "ADDR", "REF", "CREATE", "LOCAL_ADDR",
		    "REMOTE_ADDR", NCA_ADDR_WIDTH,  "NODE", "STATE");
	}

	if (mdb_vread(&conn, sizeof (nca_conn_t), addr) == -1) {
		mdb_warn("cannot read nca_conn_t at %p", addr);
		return (DCMD_ERR);
	}

	if (!show_timewait && conn.tcp_state == TCPS_TIME_WAIT)
		return (DCMD_OK);

	mdb_printf("%0*p %3d %8lx %15I %15I %0*p %s\n", NCA_ADDR_WIDTH, addr,
	    conn.ref, conn.create, conn.laddr, conn.faddr, NCA_ADDR_WIDTH,
	    conn.req_np, state2name(conn.tcp_state));

	if (show_xmit) {
		mdb_inc_indent(4);

		for (i = 0; i < TCP_XMIT_MAX_IX; i++) {
			mdb_printf("xmit[%d]\n", i);
			mdb_printf("\tref pointer\t\t%p\n", conn.xmit[i].np);
			mdb_printf("\tdata pointer\t\t%p\n", conn.xmit[i].dp);
			mdb_printf("\tcksum array\t\t%p\n", conn.xmit[i].cp);
			mdb_printf("\tremaining xmit data\t%d\n",
			    conn.xmit[i].sz);
			mdb_printf("\tref to node_t\t\t%p\n",
			    conn.xmit[i].refed);
			mdb_printf("\tremaining segment data\t%d\n",
			    conn.xmit[i].dsz);
			mdb_printf("\tvirtual pointer\t\t%p\n",
			    conn.xmit[i].dvp);
		}

		mdb_dec_indent(4);
	}

	return (DCMD_OK);
}

static void
nca_conn_help(void)
{
	mdb_printf("Print the core information for a given NCA "
	    "nca_conn_t.\n\n");
	mdb_printf("Options:\n");
	mdb_printf("\t-t\tskip connections in the TIME_WAIT state\n");
	mdb_printf("\t-x\tshow TCP XMIT information\n");
}

/*
 * Print the core TCP-related fields in an NCA nca_conn_t.  With the "-t"
 * argument, skips all nca_conn_t's that are in the TIME_WAIT state.
 */
static int
nca_tcpconn(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nca_conn_t		conn;
	unsigned int	show_timewait = TRUE;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv, 't', MDB_OPT_CLRBITS, TRUE, &show_timewait,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-*s %21s %5s %8s %5s %8s %5s %-9s%</u>\n",
		    NCA_ADDR_WIDTH, "ADDR", "REMOTE_ADDR", "SWIND", "SUNASEQ",
		    "SNSEQ", "RACKSEQ", "RNSEQ", "STATE");
	}

	if (mdb_vread(&conn, sizeof (nca_conn_t), addr) == -1) {
		mdb_warn("cannot read nca_conn_t at %p", addr);
		return (DCMD_ERR);
	}

	if (!show_timewait && conn.tcp_state == TCPS_TIME_WAIT)
		return (DCMD_OK);

	mdb_nhconvert(&conn.conn_fport, &conn.conn_fport, sizeof (in_port_t));

	mdb_printf("%0*p %15I:%05hu %5u %08x %+5d %08x %+5d %-9s\n",
	    NCA_ADDR_WIDTH, addr, conn.faddr, conn.conn_fport, conn.tcp_swnd,
	    conn.tcp_suna, conn.tcp_snxt - conn.tcp_suna, conn.tcp_rack,
	    conn.tcp_rnxt - conn.tcp_rack, state2name(conn.tcp_state));

	return (DCMD_OK);
}

static void
nca_tcpconn_help(void)
{
	mdb_printf("Print the core TCP-related information for a given ");
	mdb_printf("NCA nca_conn_t.\n\n");
	mdb_printf("Options:\n");
	mdb_printf("\t-t\tskip connections in the TIME_WAIT state\n");
}

/*
 * Initialize a walk for the NCA connection fanout table.  Note that
 * local walks are not supported since they're more trouble than
 * they're worth.
 */
static int
nca_connf_walk_init(mdb_walk_state_t *wsp)
{
	int	fanout_size;

	if (wsp->walk_addr != 0) {
		mdb_warn("nca_connf_walk does not support local walks\n");
		return (WALK_DONE);
	}

	if (mdb_readvar(&wsp->walk_addr, "nca_conn_fanout") == -1) {
		mdb_warn("cannot read symbol nca_conn_fanout");
		return (WALK_ERR);
	}

	if (mdb_readvar(&fanout_size, "nca_conn_fanout_size") == -1) {
		mdb_warn("cannot read symbol nca_conn_fanout_size");
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)(uintptr_t)fanout_size;

	return (WALK_NEXT);
}

/*
 * Walk the NCA connection fanout table; `wsp->walk_data' is used to keep
 * track of the number of indicies that are left to walk so we know when
 * to stop.
 */
static int
nca_connf_walk_step(mdb_walk_state_t *wsp)
{
	connf_t		connf;
	nca_conn_t		conn;
	int		status;
	intptr_t	i = (intptr_t)wsp->walk_data;

	if (i-- <= 0)
		return (WALK_DONE);

	if (mdb_vread(&connf, sizeof (connf_t), wsp->walk_addr) == -1) {
		mdb_warn("cannot read connf_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	/*
	 * No point in walking the fanout if there are no
	 * connections in it.
	 */
	if (connf.head != NULL) {
		/*
		 * Point to the nca_conn_t instead of the connf_t so that output
		 * can be piped to ::nca_conn dcmd.
		 */
		if (mdb_vread(&conn, sizeof (nca_conn_t),
		    (uintptr_t)connf.head) == -1) {
			mdb_warn("cannot read nca_conn_t at %p", connf.head);
			return (WALK_ERR);
		}
		status = wsp->walk_callback((uintptr_t)connf.head, &conn,
		    wsp->walk_cbdata);
	} else {
		status = WALK_NEXT;
	}

	wsp->walk_data = (void *)i;
	wsp->walk_addr += sizeof (connf_t);

	return (status);
}

/*
 * Initialize a walk for the NCA node fanout tables.  Note that local
 * walks are not supported since they're more trouble than they're
 * worth.
 */
static int
nca_nodef_walk_init(mdb_walk_state_t *wsp)
{
	char		varname[256];
	uint32_t	size;

	if (wsp->walk_addr != 0) {
		mdb_warn("nca_nodef_walk does not support local walks\n");
		return (WALK_DONE);
	}

	if (mdb_readvar(&wsp->walk_addr, wsp->walk_arg) == -1) {
		mdb_warn("cannot read symbol %s", wsp->walk_arg);
		return (WALK_ERR);
	}

	mdb_snprintf(varname, sizeof (varname), "%s_sz", wsp->walk_arg);

	if (mdb_readvar(&size, varname) == -1) {
		mdb_warn("cannot read symbol %s", varname);
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)(uintptr_t)size;

	return (WALK_NEXT);
}

/*
 * Walk the NCA node fanout table; `wsp->walk_data' is used to keep
 * track of the number of indicies that are left to walk so we know
 * when to stop.
 */
static int
nca_nodef_walk_step(mdb_walk_state_t *wsp)
{
	nodef_t		nodef;
	node_t		node;
	int		status;
	intptr_t	i = (intptr_t)wsp->walk_data;

	if (i-- <= 0)
		return (WALK_DONE);

	if (mdb_vread(&nodef, sizeof (nodef_t), wsp->walk_addr) == -1) {
		mdb_warn("cannot read nodef_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &nodef, wsp->walk_cbdata);

	wsp->walk_data = (void *)i;
	wsp->walk_addr += sizeof (nodef_t);

	if (nodef.head != NULL) {
		/*
		 * Point to the node_t instead of the nodef_t so that output
		 * can be piped to ::nca_node dcmd.
		 */
		if (mdb_vread(&node, sizeof (node),
		    (uintptr_t)nodef.head) == -1) {
			mdb_warn("cannot read node_t at %p", nodef.head);
			return (WALK_ERR);
		}

		status = wsp->walk_callback((uintptr_t)nodef.head,
		    &node, wsp->walk_cbdata);
	} else {
		status = WALK_NEXT;
	}

	return (status);
}

/*
 * Initialize a walk for the NCA CPU table.  Note that local walks
 * are not supported since they're more trouble than they're worth.
 */
static int
nca_cpu_walk_init(mdb_walk_state_t *wsp)
{
	int	ncpus;

	if (wsp->walk_addr != 0) {
		mdb_warn("nca_cpu_walk does not support local walks\n");
		return (WALK_DONE);
	}

	if (mdb_readvar(&wsp->walk_addr, "nca_gv") == -1) {
		mdb_warn("cannot read symbol nca_gv");
		return (WALK_ERR);
	}

	if (mdb_readvar(&ncpus, "ncpus") == -1) {
		mdb_warn("cannot read symbol ncpus");
		return (WALK_ERR);
	}
	wsp->walk_data = (void *)(uintptr_t)ncpus;

	return (WALK_NEXT);
}

/*
 * Walk the NCA CPU table; `wsp->walk_data' is used to keep track of the
 * number of CPUs that are left to walk so we know when to stop.
 */
static int
nca_cpu_walk_step(mdb_walk_state_t *wsp)
{
	nca_cpu_t	cpu;
	int		status;
	intptr_t	curcpu = (intptr_t)wsp->walk_data;

	if (curcpu-- <= 0)
		return (WALK_DONE);

	if (mdb_vread(&cpu, sizeof (nca_cpu_t), wsp->walk_addr) == -1) {
		mdb_warn("cannot read nca_cpu_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &cpu, wsp->walk_cbdata);

	wsp->walk_data = (void *)curcpu;
	wsp->walk_addr += sizeof (nca_cpu_t);

	return (status);
}

/*
 * Initialize a walk for the NCA timer list.  Note that local walks
 * are not supported since this walk is layered on top of "nca_cpu"
 * which doesn't support them (and they're not too useful here anyway).
 */
static int
nca_timer_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != 0) {
		mdb_warn("nca_timer_walk does not support local walks\n");
		return (WALK_DONE);
	}

	if (mdb_layered_walk("nca_cpu", wsp) == -1) {
		mdb_warn("cannot walk nca_cpu");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/*
 * Walk the NCA timer list; done as a layered walk on top of "nca_cpu".
 */
static int
nca_timer_walk_step(mdb_walk_state_t *wsp)
{
	const nca_cpu_t	*nca_cpu = wsp->walk_layer;
	ti_t		ti;

	/*
	 * Just skip CPUs that don't have any timers running.
	 */
	if (nca_cpu->tcp_ti == NULL)
		return (WALK_NEXT);

	if (mdb_vread(&ti, sizeof (ti_t), (uintptr_t)nca_cpu->tcp_ti) == -1) {
		mdb_warn("cannot read ti_t at %p", nca_cpu->tcp_ti);
		return (WALK_ERR);
	}

	return (wsp->walk_callback((uintptr_t)nca_cpu->tcp_ti, &ti,
	    wsp->walk_cbdata));
}

/*
 * Initialize a walk for NCA node LRUs; the type of LRU to walk should
 * be specified through `wsp->walk_arg'.  If no starting location for
 * the walk is given, `wsp->walk_addr' is set to the head of the
 * appropriate LRU.
 */
static int
nca_node_lru_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym	sym;
	lru_t		lru;

	if (wsp->walk_addr != 0)
		return (WALK_NEXT);

	/*
	 * We do this instead of mdb_readvar() so that we catch changes
	 * in the size of the lru_t structure.
	 */
	if (mdb_lookup_by_name("nca_lru", &sym) == -1) {
		mdb_warn("cannot lookup symbol nca_lru");
		return (WALK_ERR);
	}

	if (sym.st_size != sizeof (lru)) {
		mdb_warn("nca_lru object size mismatch\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&lru, sym.st_size, (uintptr_t)sym.st_value) == -1) {
		mdb_warn("cannot read nca_lru at %p", sym.st_value);
		return (WALK_ERR);
	}

	if (wsp->walk_arg == NCA_WALK_PLRU)
		wsp->walk_addr = (uintptr_t)lru.phead;
	else
		wsp->walk_addr = (uintptr_t)lru.vhead;

	return (WALK_NEXT);
}

/*
 * Walk the NCA node LRUs; the type of LRU to walk should be specified
 * through `wsp->walk_arg'.
 */
static int
nca_node_lru_walk_step(mdb_walk_state_t *wsp)
{
	node_t		node;
	int		status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&node, sizeof (node_t), wsp->walk_addr) == -1) {
		mdb_warn("cannot read node_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &node, wsp->walk_cbdata);

	if (wsp->walk_arg == NCA_WALK_PLRU)
		wsp->walk_addr = (uintptr_t)node.plrunn;
	else
		wsp->walk_addr = (uintptr_t)node.vlrunn;

	return (status);
}

/*
 * Walk the NCA node structures; follows node_t next pointers from a
 * given offset, specified through `wsp->walk_arg'.
 */
static int
nca_node_walk_step(mdb_walk_state_t *wsp)
{
	node_t		node;
	int		status;

	if (wsp->walk_addr == 0) {
		mdb_warn("nca_node_walk does not support global walks\n");
		return (WALK_DONE);
	}

	if (mdb_vread(&node, sizeof (node_t), wsp->walk_addr) == -1) {
		mdb_warn("cannot read node_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &node, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	/* LINTED */
	wsp->walk_addr = *(uintptr_t *)((caddr_t)&node +
	    (uint_t)(uintptr_t)wsp->walk_arg);

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	return (WALK_NEXT);
}

/*
 * Walk the NCA connection structures; follows nca_conn_t next pointers
 * from a given offset, specified through `wsp->walk_arg'.
 */
static int
nca_conn_walk_step(mdb_walk_state_t *wsp)
{
	nca_conn_t		conn;
	int		status;

	if (wsp->walk_addr == 0) {
		mdb_warn("nca_conn_walk does not support global walks\n");
		return (WALK_DONE);
	}

	if (mdb_vread(&conn, sizeof (nca_conn_t), wsp->walk_addr) == -1) {
		mdb_warn("cannot read nca_conn_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &conn, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	/* LINTED */
	wsp->walk_addr = *(uintptr_t *)((caddr_t)&conn +
	    (uint_t)(uintptr_t)wsp->walk_arg);

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	return (WALK_NEXT);
}

static const mdb_dcmd_t dcmds[] = {
	{ "nca_conn",	":[-tx]", "print core NCA nca_conn_t info",   nca_conn,
	    nca_conn_help },
	{ "nca_tcpconn", ":[-t]", "print TCP NCA nca_conn_t info",
	    nca_tcpconn, nca_tcpconn_help },
	{ "nca_io2",	":[-pv]", "print core NCA io2_t info",    nca_io2,
	    nca_io2_help },
	{ "nca_node",	":[-rv]", "print core NCA node_t info",   nca_node,
	    nca_node_help },
	{ "nca_timer",	"?[-e]",  "print core NCA timer info",    nca_timer,
	    nca_timer_help },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "nca_conn_hash",	"walk the NCA connection hash chain", 0,
	    nca_conn_walk_step, 0, (void *)OFFSETOF(nca_conn_t, hashnext) },
	{ "nca_conn_bind",	"walk the NCA connection bind chain", 0,
	    nca_conn_walk_step, 0, (void *)OFFSETOF(nca_conn_t, bindnext) },
	{ "nca_conn_miss",	"walk the NCA connection miss chain", 0,
	    nca_conn_walk_step, 0, (void *)OFFSETOF(nca_conn_t, nodenext) },
	{ "nca_conn_tw",	"walk the NCA connection TIME_WAIT chain", 0,
	    nca_conn_walk_step, 0, (void *)OFFSETOF(nca_conn_t, twnext) },

	{ "nca_node_file",	"walk the NCA node file chain", 0,
	    nca_node_walk_step, 0, (void *)OFFSETOF(node_t, filenext) },
	{ "nca_node_hash",	"walk the NCA node hash chain", 0,
	    nca_node_walk_step, 0, (void *)OFFSETOF(node_t, hashnext) },
	{ "nca_node_chunk",	"walk the NCA node chunk chain", 0,
	    nca_node_walk_step, 0, (void *)OFFSETOF(node_t, next) },
	{ "nca_node_ctag",	"walk the NCA node ctag chain", 0,
	    nca_node_walk_step, 0, (void *)OFFSETOF(node_t, ctagnext) },

	{ "nca_node_plru",	"walk the NCA node physical LRU chain",
	    nca_node_lru_walk_init, nca_node_lru_walk_step, 0, NCA_WALK_PLRU },
	{ "nca_node_vlru",	"walk the NCA node virtual LRU chain",
	    nca_node_lru_walk_init, nca_node_lru_walk_step, 0, NCA_WALK_VLRU },

	{ "nca_uri_hash",	"walk the NCA URI node hash table",
	    nca_nodef_walk_init, nca_nodef_walk_step, 0, "ncaurihash" },
	{ "nca_file_hash",	"walk the NCA file node hash table",
	    nca_nodef_walk_init, nca_nodef_walk_step, 0, "ncafilehash" },
	{ "nca_ctag_hash",	"walk the NCA ctag node hash table",
	    nca_nodef_walk_init, nca_nodef_walk_step, 0, "ncactaghash" },
	{ "nca_vnode_hash",	"walk the NCA vnode node hash table",
	    nca_nodef_walk_init, nca_nodef_walk_step, 0, "ncavnodehash" },

	{ "nca_cpu",		"walk the NCA CPU table",
	    nca_cpu_walk_init,   nca_cpu_walk_step },
	{ "nca_timer",		"walk the NCA timer table",
	    nca_timer_walk_init, nca_timer_walk_step },
	{ "nca_connf",		"walk the NCA connection fanout",
	    nca_connf_walk_init, nca_connf_walk_step },

	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
