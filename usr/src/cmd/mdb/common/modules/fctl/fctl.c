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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/mdb_modapi.h>
#include <sys/mutex.h>
#include <sys/modctl.h>
#include <time.h>
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fctl_private.h>
#include <sys/fibre-channel/impl/fc_ulpif.h>
#include <sys/fibre-channel/impl/fc_portif.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>


/*
 * If we #include <string.h> then other definitions fail. This is
 * the easiest way of getting access to the function
 */
extern char *strtok(char *string, const char *sepset);

/* we need 26 bytes for the cftime() call */
#define	TIMESTAMPSIZE	26 * sizeof (char)

/* for backward compatibility */
typedef struct fc_trace_dmsgv1 {
	int			id_size;
	int			id_flag;
	time_t			id_time;
	caddr_t			id_buf;
	struct fc_trace_dmsgv1	*id_next;
} fc_trace_dmsgv1_t;

static struct pwwn_hash *fp_pwwn_table;
static struct d_id_hash *fp_did_table;
static uint32_t pd_hash_index;
struct fc_local_port port;

/*
 * Leadville port walker/dcmd code
 */

/*
 * Initialize the fc_fca_port_t walker by either using the given starting
 * address, or reading the value of the kernel's fctl_fca_portlist pointer.
 * We also allocate a fc_fca_port_t for storage, and save this using the
 * walk_data pointer.
 */
static int
port_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "fctl_fca_portlist") == -1) {
		mdb_warn("failed to read 'fctl_fca_portlist'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (fc_fca_port_t), UM_SLEEP);
	return (WALK_NEXT);
}

/*
 * At each step, read a fc_fca_port_t into our private storage, and then invoke
 * the callback function.  We terminate when we reach a NULL p_next pointer.
 */
static int
port_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (fc_fca_port_t), wsp->walk_addr)
	    == -1) {
		mdb_warn("failed to read fc_fca_port_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((fc_fca_port_t *)wsp->walk_data)->port_next);

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.  Since we
 * dynamically allocated a fc_fca_port_t in port_walk_i, we must free it now.
 */
static void
port_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (fc_fca_port_t));
}


static int
ports(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fc_fca_port_t	portlist;
	fc_local_port_t port;
	int		longlist = FALSE;

	if (argc > 1) {
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'l', MDB_OPT_SETBITS, TRUE, &longlist) != argc) {
		return (DCMD_USAGE);
	}


	if (!(flags & DCMD_ADDRSPEC)) {
		if (longlist == 0) {
			if (mdb_walk_dcmd("ports", "ports",
			    argc, argv) == -1) {
				mdb_warn("failed to walk 'fctl_fca_portlist'");
				return (DCMD_ERR);
			}
		} else {
			if (mdb_walk_dcmd("ports", "fcport",
			    argc, argv) == -1) {
				mdb_warn("failed to walk 'fctl_fca_portlist'");
				return (DCMD_ERR);
			}
		}

		return (DCMD_OK);
	}

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags))
		mdb_printf("%16s %-2s %4s %-4s%16s %16s %16s\n",
		    "Port", "I#", "State", "Soft", "FCA Handle",
		    "Port DIP", "FCA Port DIP");

	/*
	 * For each port, we just need to read the fc_fca_port_t struct, read
	 * the port_handle
	 */
	if (mdb_vread(&portlist, sizeof (fc_fca_port_t), addr) ==
	    sizeof (fc_fca_port_t)) {
		/*
		 * Now read that port in
		 */

		if (mdb_vread(&port, sizeof (fc_local_port_t), (uintptr_t)
		    portlist.port_handle) == sizeof (fc_local_port_t)) {
			mdb_printf("%16p %2d %4x %4x %16p %16p %16p\n",
			    portlist.port_handle, port.fp_instance,
			    port.fp_state, port.fp_soft_state,
			    port.fp_fca_handle, port.fp_port_dip,
			    port.fp_fca_dip);
		} else
			mdb_warn("failed to read port at %p",
			    portlist.port_handle);

	} else
		mdb_warn("failed to read port info at %p", addr);

	return (DCMD_OK);
}


/*
 * Leadville ULP walker/dcmd code
 */

static int
ulp_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "fctl_ulp_list") == -1) {
		mdb_warn("failed to read 'fctl_ulp_list'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (fc_ulp_list_t), UM_SLEEP);
	return (WALK_NEXT);
}



static int
ulp_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (fc_ulp_list_t), wsp->walk_addr)
	    == -1) {
		mdb_warn("failed to read fctl_ulp_list %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((fc_ulp_list_t *)wsp->walk_data)->ulp_next);

	return (status);
}


static void
ulp_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (fc_ulp_list_t));
}


static int
ulps(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fc_ulp_list_t		ulplist;
	fc_ulp_modinfo_t	ulp;
	char			ulp_name[30];

	if (argc != 0) {
		return (DCMD_USAGE);
	}

	/*
	 * If no fc_ulp_list_t address was specified on the command line, we can
	 * print out all processes by invoking the walker, using this
	 * dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("ulps", "ulps", argc, argv) == -1) {
			mdb_warn("failed to walk 'fc_ulp_list_t'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags))
		mdb_printf("%30s %4s %8s\n", "ULP Name", "Type", "Revision");

	/*
	 * For each port, we just need to read the fc_fca_port_t struct, read
	 * the port_handle
	 */
	if (mdb_vread(&ulplist, sizeof (fc_ulp_list_t), addr) ==
	    sizeof (fc_ulp_list_t)) {
		/*
		 * Now read that port in
		 */

		if (mdb_vread(&ulp, sizeof (fc_ulp_modinfo_t),
		    (uintptr_t)ulplist.ulp_info) == sizeof (fc_ulp_modinfo_t)) {
			if (mdb_vread(&ulp_name, 30,
			    (uintptr_t)ulp.ulp_name) > 0) {
				mdb_printf("%30s %4x %8x\n",
				    ulp_name, ulp.ulp_type, ulp.ulp_rev);
			}
		} else
			mdb_warn("failed to read ulp at %p",
			    ulplist.ulp_info);

	} else
		mdb_warn("failed to read ulplist at %p", addr);

	return (DCMD_OK);
}



/*
 * Leadville ULP module walker/dcmd code
 */

static int
ulpmod_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "fctl_ulp_modules") == -1) {
		mdb_warn("failed to read 'fctl_ulp_modules'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (fc_ulp_module_t), UM_SLEEP);
	return (WALK_NEXT);
}



static int
ulpmod_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (fc_ulp_module_t), wsp->walk_addr)
	    == -1) {
		mdb_warn("failed to read fctl_ulp_modules %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((fc_ulp_module_t *)wsp->walk_data)->mod_next);

	return (status);
}


static void
ulpmod_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (fc_ulp_module_t));
}


static int
ulpmods(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fc_ulp_module_t		modlist;
	fc_ulp_modinfo_t	modinfo;
	fc_ulp_ports_t		ulp_port;

	if (argc != 0) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("ulpmods", "ulpmods", argc, argv)
		    == -1) {
			mdb_warn("failed to walk 'fc_ulp_module_t'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags))
		mdb_printf("%4s %16s %8s %8s\n",
		    "Type", "Port Handle", "dstate", "statec");

	/*
	 * For each port, we just need to read the fc_fca_port_t struct, read
	 * the port_handle
	 */
	if (mdb_vread(&modlist, sizeof (fc_ulp_module_t), addr) ==
	    sizeof (fc_ulp_module_t)) {
		/*
		 * Now read that module info in
		 */

		if (mdb_vread(&modinfo, sizeof (fc_ulp_modinfo_t),
		    (uintptr_t)modlist.mod_info) == sizeof (fc_ulp_modinfo_t)) {
			/* Now read all the ports for this module */
			if (mdb_vread(&ulp_port, sizeof (fc_ulp_ports_t),
			    (uintptr_t)modlist.mod_ports) ==
			    sizeof (fc_ulp_ports_t)) {
				while (ulp_port.port_handle != NULL) {
					mdb_printf("%4x %16p %8x %8x\n",
					    modinfo.ulp_type,
					    ulp_port.port_handle,
					    ulp_port.port_dstate,
					    ulp_port.port_statec);

					if (ulp_port.port_next == NULL)
						break;

					mdb_vread(&ulp_port,
					    sizeof (fc_ulp_ports_t),
					    (uintptr_t)ulp_port.port_next);
				}
			}
		} else
			mdb_warn("failed to read modinfo at %p",
			    modlist.mod_info);

	} else
		mdb_warn("failed to read modlist at %p", addr);

	return (DCMD_OK);
}


/*
 * Display an fc_local_port_t struct
 */
static int
fcport(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fc_fca_port_t	portlist;
	fc_local_port_t	port;
	int		idx;
	int		first = 1;
	int		walking_fc_fca_portlist = 0;

	if (argc != 0) {
		int result;

		if (argc != 1)
			return (DCMD_USAGE);

		if (argv->a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		walking_fc_fca_portlist = 1;
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_printf("Sorry, you must provide an address\n");
		return (DCMD_ERR);
	}

	if (walking_fc_fca_portlist) {
		/*
		 * Must read the fc_fca_portlist to get the fc_local_port addr
		 */
		if (mdb_vread(&portlist, sizeof (fc_fca_port_t), addr) ==
		    sizeof (fc_fca_port_t)) {
			addr = (uintptr_t)portlist.port_handle;
		}
	}

	mdb_printf("Reading fc_local_port_t at %p:\n", addr);

	/*
	 * For each port, we just need to read the fc_local_port_t struct
	 */

	if (mdb_vread(&port, sizeof (fc_local_port_t),
	    addr) == sizeof (fc_local_port_t)) {
		mdb_printf("  fp_mutex          : 0x%p\n", port.fp_mutex);
		mdb_printf("  fp_state          : 0x%-8x\n", port.fp_state);
		mdb_printf("  fp_port_id        : 0x%-06x\n",
		    port.fp_port_id.port_id);
		mdb_printf("  fp_fca_handle     : 0x%p\n", port.fp_fca_handle);
		mdb_printf("  fp_fca_tran       : 0x%p\n", port.fp_fca_tran);
		mdb_printf("  fp_job_head       : 0x%p\n", port.fp_job_head);
		mdb_printf("  fp_job_tail       : 0x%p\n", port.fp_job_tail);
		mdb_printf("  fp_wait_head      : 0x%p\n", port.fp_wait_head);
		mdb_printf("  fp_wait_tail      : 0x%p\n", port.fp_wait_tail);
		mdb_printf("  fp_topology       : %u\n", port.fp_topology);
		mdb_printf("  fp_task           : %d\n", port.fp_task);
		mdb_printf("  fp_last_task      : %d\n", port.fp_last_task);
		mdb_printf("  fp_soft_state     : 0x%-4x\n",
		    port.fp_soft_state);
		mdb_printf("  fp_flag           : 0x%-2x\n", port.fp_flag);
		mdb_printf("  fp_statec_busy    : 0x%-8x\n",
		    port.fp_statec_busy);
		mdb_printf("  fp_port_num       : %d\n", port.fp_port_num);
		mdb_printf("  fp_instance       : %d\n", port.fp_instance);
		mdb_printf("  fp_ulp_attach     : %d\n", port.fp_ulp_attach);
		mdb_printf("  fp_dev_count      : %d\n", port.fp_dev_count);
		mdb_printf("  fp_total_devices  : %d\n", port.fp_total_devices);
		mdb_printf("  fp_bind_state     : 0x%-8x\n",
		    port.fp_bind_state);
		mdb_printf("  fp_options        : 0x%-8x\n", port.fp_options);
		mdb_printf("  fp_port_type      : 0x%-2x\n",
		    port.fp_port_type.port_type);
		mdb_printf("  fp_ub_count       : %d\n", port.fp_ub_count);
		mdb_printf("  fp_active_ubs     : %d\n", port.fp_active_ubs);
		mdb_printf("  fp_port_dip       : 0x%p\n", port.fp_port_dip);
		mdb_printf("  fp_fca_dip        : 0x%p\n", port.fp_fca_dip);

		for (idx = 0; idx < 16; idx++) {
			if (port.fp_ip_addr[idx] != 0)
				break;
		}

		if (idx != 16) {
			mdb_printf("  fp_ip_addr        : %-2x:%-2x:%-2x:%-2x:"
			    "%-2x:%-2x:%-2x:%-2x:%-2x:%-2x:%-2x:%-2x:%-2x:%-2x"
			    ":%-2x:%-2x\n",
			    port.fp_ip_addr[0], port.fp_ip_addr[1],
			    port.fp_ip_addr[2], port.fp_ip_addr[3],
			    port.fp_ip_addr[4], port.fp_ip_addr[5],
			    port.fp_ip_addr[6], port.fp_ip_addr[7],
			    port.fp_ip_addr[8], port.fp_ip_addr[9],
			    port.fp_ip_addr[10], port.fp_ip_addr[11],
			    port.fp_ip_addr[12], port.fp_ip_addr[13],
			    port.fp_ip_addr[14], port.fp_ip_addr[15]);
		} else {
			mdb_printf("  fp_ip_addr        : N/A\n");
		}

		mdb_printf("  fp_fc4_types      : ");

		for (idx = 0; idx < 8; idx++) {
			if (port.fp_fc4_types[idx] != 0) {
				if (first) {
					mdb_printf("%d",
					    port.fp_fc4_types[idx]);
					first = 0;
				} else {
					mdb_printf(", %d",
					    port.fp_fc4_types[idx]);
				}
			}
		}

		if (first) {
			mdb_printf("None\n");
		} else {
			mdb_printf("\n");
		}

		mdb_printf("  fp_pm_level       : %d\n", port.fp_pm_level);
		mdb_printf("  fp_pm_busy        : %d\n", port.fp_pm_busy);
		mdb_printf("  fp_pm_busy_nocomp : 0x%-8x\n",
		    port.fp_pm_busy_nocomp);
		mdb_printf("  fp_hard_addr      : 0x%-6x\n",
		    port.fp_hard_addr.hard_addr);
		mdb_printf("  fp_sym_port_name  : \"%s\"\n",
		    port.fp_sym_port_name);
		mdb_printf("  fp_sym_node_name  : \"%s\"\n",
		    port.fp_sym_node_name);
		mdb_printf("  fp_rscn_count     : %d\n", port.fp_rscn_count);
	} else {
		mdb_warn("failed to read fc_local_port_t at 0x%p", addr);
	}

	mdb_printf("\n");

	return (DCMD_OK);
}


/*
 * Leadville remote_port walker/dcmd code
 */

/*
 * We need to be given the address of a port structure in order to start
 * walking.  From that, we can read the pwwn table.
 */
static int
pd_by_pwwn_walk_i(mdb_walk_state_t *wsp)
{
	fc_local_port_t port;

	if (wsp->walk_addr == NULL) {
		mdb_warn("pd_by_pwwn walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	/*
	 * Allocate space for the pwwn_hash table
	 */

	fp_pwwn_table = mdb_alloc(sizeof (struct pwwn_hash) *
	    PWWN_HASH_TABLE_SIZE, UM_SLEEP);

	/*
	 * Input should be an fc_local_port_t, so read it to get the pwwn
	 * table's head
	 */

	if (mdb_vread(&port, sizeof (fc_local_port_t), wsp->walk_addr) !=
	    sizeof (fc_local_port_t)) {
		mdb_warn("Unable to read in the port structure address\n");
		return (WALK_ERR);
	}

	if (mdb_vread(fp_pwwn_table, sizeof (struct pwwn_hash) *
	    PWWN_HASH_TABLE_SIZE, (uintptr_t)port.fp_pwwn_table) == -1) {
		mdb_warn("Unable to read in the pwwn hash table\n");
		return (WALK_ERR);
	}

	pd_hash_index = 0;

	while ((fp_pwwn_table[pd_hash_index].pwwn_head == NULL) &&
	    (pd_hash_index < PWWN_HASH_TABLE_SIZE)) {
		pd_hash_index++;
	}

	wsp->walk_addr = (uintptr_t)fp_pwwn_table[pd_hash_index].pwwn_head;

	wsp->walk_data = mdb_alloc(sizeof (fc_remote_port_t), UM_SLEEP);
	return (WALK_NEXT);
}

/*
 * At each step, read a fc_remote_port_t into our private storage, and then
 * invoke the callback function.  We terminate when we reach a NULL p_next
 * pointer.
 */
static int
pd_by_pwwn_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if ((wsp->walk_addr == NULL) &&
	    (pd_hash_index >= (PWWN_HASH_TABLE_SIZE - 1))) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (fc_remote_port_t), wsp->walk_addr)
	    == -1) {
		mdb_warn("failed to read fc_remote_port at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((fc_remote_port_t *)wsp->walk_data)->pd_wwn_hnext);

	if (wsp->walk_addr == NULL) {
		/*
		 * Try the next hash list, if there is one.
		 */

		pd_hash_index++;

		while ((fp_pwwn_table[pd_hash_index].pwwn_head == NULL) &&
		    (pd_hash_index < PWWN_HASH_TABLE_SIZE)) {
			pd_hash_index++;
		}

		if (pd_hash_index == PWWN_HASH_TABLE_SIZE) {
			/* We're done */
			return (status);
		}

		wsp->walk_addr =
		    (uintptr_t)fp_pwwn_table[pd_hash_index].pwwn_head;
	}

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
pd_by_pwwn_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (fc_remote_port_t));
	mdb_free(fp_pwwn_table, sizeof (struct pwwn_hash) *
	    PWWN_HASH_TABLE_SIZE);
	fp_pwwn_table = NULL;
}

/*
 * This is the same walker as pd_by_pwwn, but we walk the D_ID hash table
 */

static int
pd_by_did_walk_i(mdb_walk_state_t *wsp)
{
	fc_local_port_t port;

	if (wsp->walk_addr == NULL) {
		mdb_warn("pd_by_did walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	/*
	 * Allocate space for the did_hash table
	 */

	fp_did_table = mdb_alloc(sizeof (struct d_id_hash) *
	    D_ID_HASH_TABLE_SIZE, UM_SLEEP);

	/*
	 * Input should be an fc_local_port_t, so read it to get the d_id
	 * table's head
	 */

	if (mdb_vread(&port, sizeof (fc_local_port_t), wsp->walk_addr) !=
	    sizeof (fc_local_port_t)) {
		mdb_warn("Unable to read in the port structure address\n");
		return (WALK_ERR);
	}

	if (mdb_vread(fp_did_table, sizeof (struct d_id_hash) *
	    D_ID_HASH_TABLE_SIZE, (uintptr_t)port.fp_did_table) == -1) {
		mdb_warn("Unable to read in the D_ID hash table\n");
		return (WALK_ERR);
	}
	pd_hash_index = 0;

	while ((fp_did_table[pd_hash_index].d_id_head == NULL) &&
	    (pd_hash_index < D_ID_HASH_TABLE_SIZE)) {
		pd_hash_index++;
	}

	wsp->walk_addr = (uintptr_t)fp_did_table[pd_hash_index].d_id_head;

	wsp->walk_data = mdb_alloc(sizeof (fc_remote_port_t), UM_SLEEP);
	return (WALK_NEXT);
}

/*
 * At each step, read a fc_remote_port_t into our private storage, and then
 * invoke the callback function.  We terminate when we reach a NULL p_next
 * pointer.
 */
static int
pd_by_did_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if ((wsp->walk_addr == NULL) &&
	    (pd_hash_index >= (D_ID_HASH_TABLE_SIZE - 1))) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (fc_remote_port_t), wsp->walk_addr)
	    == -1) {
		mdb_warn("failed to read fc_remote_port at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((fc_remote_port_t *)wsp->walk_data)->pd_did_hnext);

	if (wsp->walk_addr == NULL) {
		/*
		 * Try the next hash list, if there is one.
		 */

		pd_hash_index++;

		while ((fp_did_table[pd_hash_index].d_id_head == NULL) &&
		    (pd_hash_index < D_ID_HASH_TABLE_SIZE)) {
			pd_hash_index++;
		}

		if (pd_hash_index == D_ID_HASH_TABLE_SIZE) {
			/* We're done */
			return (status);
		}

		wsp->walk_addr =
		    (uintptr_t)fp_did_table[pd_hash_index].d_id_head;
	}

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
pd_by_did_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (fc_remote_port_t));
	mdb_free(fp_did_table, sizeof (struct d_id_hash) *
	    D_ID_HASH_TABLE_SIZE);
	fp_did_table = NULL;
}


/*
 * Display a remote_port structure
 */
static int
remote_port(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fc_remote_port_t	pd;
	int			idx;
	int			first = 1;

	if (argc > 0) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_printf("Sorry, you must provide an address\n");
		return (DCMD_ERR);
	}

	if (mdb_vread(&pd, sizeof (fc_remote_port_t), addr) !=
	    sizeof (fc_remote_port_t)) {
		mdb_warn("Error reading pd at 0x%x\n", addr);
		return (DCMD_ERR);
	}

	mdb_printf("Reading remote_port at 0x%p\n", addr);
	mdb_printf("  mutex          : 0x%p\n", pd.pd_mutex);
	mdb_printf("  port_id        : 0x%-8x\n", pd.pd_port_id);
	mdb_printf("  port_name      : 0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	    pd.pd_port_name.raw_wwn[0], pd.pd_port_name.raw_wwn[1],
	    pd.pd_port_name.raw_wwn[2], pd.pd_port_name.raw_wwn[3],
	    pd.pd_port_name.raw_wwn[4], pd.pd_port_name.raw_wwn[5],
	    pd.pd_port_name.raw_wwn[6], pd.pd_port_name.raw_wwn[7]);
	mdb_printf("  login_count    : %d\n", pd.pd_login_count);
	mdb_printf("  state          : 0x%x ", pd.pd_state);

	switch (pd.pd_state) {
	case PORT_DEVICE_INVALID:
		mdb_printf("(invalid)\n");
		break;
	case PORT_DEVICE_VALID:
		mdb_printf("(valid)\n");
		break;
	case PORT_DEVICE_LOGGED_IN:
		mdb_printf("(logged in)\n");
		break;
	default:
		mdb_printf("(Unknown state)\n");
	}

	mdb_printf("  remote node    : 0x%p\n", pd.pd_remote_nodep);
	mdb_printf("  hard_addr      : 0x%x\n", pd.pd_hard_addr);
	mdb_printf("  local port     : 0x%p\n", pd.pd_port);
	mdb_printf("  type           : %d ", pd.pd_type);

	switch (pd.pd_type) {
	case PORT_DEVICE_NOCHANGE:
		mdb_printf("(No change)\n");
		break;
	case PORT_DEVICE_NEW:
		mdb_printf("(New)\n");
		break;
	case PORT_DEVICE_OLD:
		mdb_printf("(Old)\n");
		break;
	case PORT_DEVICE_CHANGED:
		mdb_printf("(Changed)\n");
		break;
	case PORT_DEVICE_DELETE:
		mdb_printf("(Delete)\n");
		break;
	case PORT_DEVICE_USER_LOGIN:
		mdb_printf("(User login)\n");
		break;
	case PORT_DEVICE_USER_LOGOUT:
		mdb_printf("(User logout)\n");
		break;
	case PORT_DEVICE_USER_CREATE:
		mdb_printf("(User create)\n");
		break;
	case PORT_DEVICE_USER_DELETE:
		mdb_printf("(User delete)\n");
		break;
	default:
		mdb_printf("(Unknown type)\n");
	}

	mdb_printf("  flags          : 0x%x ", pd.pd_flags);

	switch (pd.pd_flags) {
	case PD_IDLE:
		mdb_printf("(Idle)\n");
		break;
	case PD_ELS_IN_PROGRESS:
		mdb_printf("(ELS in progress)\n");
		break;
	case PD_ELS_MARK:
		mdb_printf("(Mark)\n");
		break;
	default:
		mdb_printf("(Unknown flag value)\n");
	}

	mdb_printf("  login_class    : 0x%x\n", pd.pd_login_class);
	mdb_printf("  recipient      : %d\n", pd.pd_recepient);
	mdb_printf("  ref_count      : %d\n", pd.pd_ref_count);
	mdb_printf("  aux_flags      : 0x%x ", pd.pd_aux_flags);

	first = 1;
	if (pd.pd_aux_flags & PD_IN_DID_QUEUE) {
		mdb_printf("(IN_DID_QUEUE");
		first = 0;
	}

	if (pd.pd_aux_flags & PD_DISABLE_RELOGIN) {
		if (first) {
			mdb_printf("(DISABLE_RELOGIN");
		} else {
			mdb_printf(", DISABLE_RELOGIN");
		}
		first = 0;
	}

	if (pd.pd_aux_flags & PD_NEEDS_REMOVAL) {
		if (first) {
			mdb_printf("(NEEDS_REMOVAL");
		} else {
			mdb_printf(", NEEDS_REMOVAL");
		}
		first = 0;
	}

	if (pd.pd_aux_flags & PD_LOGGED_OUT) {
		if (first) {
			mdb_printf("(LOGGED_OUT");
		} else {
			mdb_printf(", LOGGED_OUT");
		}
		first = 0;
	}

	if (pd.pd_aux_flags & PD_GIVEN_TO_ULPS) {
		if (first) {
			mdb_printf("(GIVEN_TO_ULPS");
		} else {
			mdb_printf(", GIVEN_TO_ULPS");
		}
		first = 0;
	}

	if (first == 0) {
		mdb_printf(")\n");
	} else {
		mdb_printf("\n");
	}

	mdb_printf("  sig            : %p\n", pd.pd_logo_tc.sig);
	mdb_printf("  active         : %d\n", pd.pd_logo_tc.active);
	mdb_printf("  counter        : %d\n", pd.pd_logo_tc.counter);
	mdb_printf("  max_value      : %d\n", pd.pd_logo_tc.max_value);
	mdb_printf("  timer          : %d\n", pd.pd_logo_tc.timer);
	mdb_printf("\n");

	return (DCMD_OK);
}

int
fc_dump_logmsg(fc_trace_dmsg_t *addr, uint_t pktstart, uint_t pktend,
    uint_t *printed)
{
	fc_trace_dmsg_t	msg;
	caddr_t		buf;
	char		merge[1024];
	caddr_t		tmppkt;
	char		*tmpbuf; /* for tokenising the buffer */
	uint_t		pktnum = 0;

	while (addr != NULL) {
		if (mdb_vread(&msg, sizeof (msg), (uintptr_t)addr) !=
		    sizeof (msg)) {
			mdb_warn("failed to read message pointer in kernel");
			return (DCMD_ERR);
		}

		if (msg.id_size) {

			buf = mdb_alloc(msg.id_size + 1, UM_SLEEP);
			tmppkt = mdb_alloc(msg.id_size + 1, UM_SLEEP);

			if (mdb_vread(buf, msg.id_size,
			    (uintptr_t)msg.id_buf) != msg.id_size) {
				mdb_warn("failed to read buffer contents"
				    " in kernel");
				mdb_free(buf, msg.id_size + 1);
				return (DCMD_ERR);
			}

			if (buf[0] == '\n') {
				mdb_printf("There is a problem in"
				    "the buffer\n");
			}
			/* funky packet processing stuff */
			bcopy(buf, tmppkt, msg.id_size + 1);

			/* find the equals sign, and put a null there */
			tmpbuf = strchr(tmppkt, '=');
			*tmpbuf = 0;
			pktnum = (uint_t)mdb_strtoull(tmppkt);

			if ((pktnum >= pktstart) && (pktnum <= pktend)) {
				(void) mdb_snprintf(merge, sizeof (merge),
				    "[%Y:%03d:%03d:%03d] %s",
				    msg.id_time.tv_sec,
				    (int)msg.id_time.tv_nsec/1000000,
				    (int)(msg.id_time.tv_nsec/1000)%1000,
				    (int)msg.id_time.tv_nsec%1000, buf);
				mdb_printf("%s", merge);
				if (printed != NULL)
					(*printed) ++;
			}
			mdb_free(buf, msg.id_size + 1);
			mdb_free(tmppkt, msg.id_size + 1);
		}
		addr = msg.id_next;
	}

	return (DCMD_OK);
}

int
fc_dump_old_logmsg(fc_trace_dmsgv1_t *addr, uint_t pktstart, uint_t pktend,
    uint_t *printed)
{
	fc_trace_dmsgv1_t	msg;
	caddr_t			buf;
	char			merge[1024];
	caddr_t			tmppkt;
	char			*tmpbuf; /* for tokenising the buffer */
	uint_t			pktnum = 0;

	while (addr != NULL) {
		if (mdb_vread(&msg, sizeof (msg), (uintptr_t)addr) !=
		    sizeof (msg)) {
			mdb_warn("failed to read message pointer in kernel");
			return (DCMD_ERR);
		}

		if (msg.id_size) {

			buf = mdb_alloc(msg.id_size + 1, UM_SLEEP);
			tmppkt = mdb_alloc(msg.id_size + 1, UM_SLEEP);

			if (mdb_vread(buf, msg.id_size,
			    (uintptr_t)msg.id_buf) != msg.id_size) {
				mdb_warn("failed to read buffer contents"
				    " in kernel");
				mdb_free(buf, msg.id_size + 1);
				return (DCMD_ERR);
			}

			if (buf[0] == '\n') {
				mdb_printf("There is a problem in"
				    "the buffer\n");
			}
			/* funky packet processing stuff */
			bcopy(buf, tmppkt, msg.id_size + 1);

			tmpbuf = strchr(tmppkt, '=');
			*tmpbuf = 0;
			pktnum = (uint_t)mdb_strtoull(tmppkt);

			if ((pktnum >= pktstart) && (pktnum <= pktend)) {
				(void) mdb_snprintf(merge, sizeof (merge),
				    "[%Y] %s", msg.id_time, buf);
				mdb_printf("%s", merge);
				if (printed != NULL)
					(*printed) ++;
			}
			mdb_free(buf, msg.id_size + 1);
			mdb_free(tmppkt, msg.id_size + 1);
		}
		addr = msg.id_next;
	}

	return (DCMD_OK);
}

int
fc_trace_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fc_trace_logq_t logq;
	uint_t		pktnum = 0;
	uint_t		printed = 0; /* have we printed anything? */

	uintptr_t	pktstart = 0;
	uintptr_t	pktend = UINT_MAX;
	int		rval = DCMD_OK;

	if (mdb_vread(&logq, sizeof (logq), addr) != sizeof (logq)) {
		mdb_warn("Failed to read log queue in kernel");
		return (DCMD_ERR);
	}

	if (mdb_getopts(argc, argv,
	    's', MDB_OPT_UINTPTR, &pktstart,
	    'e', MDB_OPT_UINTPTR, &pktend) != argc) {
		return (DCMD_USAGE);
	}

	if (pktstart > pktend) {
		return (DCMD_USAGE);
	}

	if ((logq.il_flags & FC_TRACE_LOGQ_V2) != 0) {
		rval = fc_dump_logmsg((fc_trace_dmsg_t *)logq.il_msgh, pktstart,
		    pktend, &printed);
	} else {
		rval = fc_dump_old_logmsg((fc_trace_dmsgv1_t *)logq.il_msgh,
		    pktstart, pktend, &printed);
	}

	if (rval != DCMD_OK) {
		return (rval);
	}

	if (printed == 0) {
		mdb_printf("No packets in the buffer match the"
		    " criteria given");
	}

	return (rval);
}

int
fp_trace_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (mdb_readvar(&addr, "fp_logq") == -1) {
		mdb_warn("failed to read fp_logq");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("fp trace buffer contents\n");
	}

	return (fc_trace_dump(addr, flags, argc, argv));
}


int
fcp_trace_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (mdb_readvar(&addr, "fcp_logq") == -1) {
		mdb_warn("failed to read fcp_logq");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("fcp trace buffer contents\n");
	}

	return (fc_trace_dump(addr, flags, argc, argv));
}

/*
 * Leadville job_request walker/dcmd code
 */

/*
 * We need to be given the address of a local port structure in order to start
 * walking.  From that, we can read the job_request list.
 */

static int
job_request_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("The address of a fc_local_port"
		    " structure must be given\n");
		return (WALK_ERR);
	}

	/*
	 * Input should be a fc_local_port_t, so read it to get the job_request
	 * lists's head
	 */

	if (mdb_vread(&port, sizeof (fc_local_port_t), wsp->walk_addr) !=
	    sizeof (fc_local_port_t)) {
		mdb_warn("Failed to read in the fc_local_port"
		    " at 0x%p\n", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)(port.fp_job_head);
	wsp->walk_data = mdb_alloc(sizeof (struct job_request), UM_SLEEP);

	return (WALK_NEXT);
}

static int
job_request_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (struct job_request),
	    wsp->walk_addr) == -1) {
		mdb_warn("Failed to read in the job_request at 0x%p\n",
		    wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((struct job_request *)wsp->walk_data)->job_next);

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
job_request_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct job_request));
}


/*
 * Leadville fc_orphan walker/dcmd code
 */

/*
 * We need to be given the address of a port structure in order to start
 * walking.  From that, we can read the orphan list.
 */

static int
orphan_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("The address of a fc_local_port"
		    " structure must be given\n");
		return (WALK_ERR);
	}

	/*
	 * Input should be a fc_local_port_t, so read it to get the orphan
	 * lists's head
	 */

	if (mdb_vread(&port, sizeof (fc_local_port_t), wsp->walk_addr) !=
	    sizeof (fc_local_port_t)) {
		mdb_warn("Failed to read in the fc_local_port"
		    " at 0x%p\n", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)(port.fp_orphan_list);
	wsp->walk_data = mdb_alloc(sizeof (struct fc_orphan), UM_SLEEP);

	return (WALK_NEXT);
}

static int
orphan_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (struct fc_orphan),
	    wsp->walk_addr) == -1) {
		mdb_warn("Failed to read in the fc_orphan at 0x%p\n",
		    wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((struct fc_orphan *)wsp->walk_data)->orp_next);

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
orphan_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct fc_orphan));
}


/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers, and a function named _mdb_init to return a pointer
 * to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "ports", "[-l]", "Leadville port list", ports },
	{ "ulps", NULL, "Leadville ULP list", ulps },
	{ "ulpmods", NULL, "Leadville ULP module list", ulpmods },
	{ "fcport", NULL, "Display a Leadville fc_local_port structure",
	    fcport },
	{ "remote_port", NULL, "Display fc_remote_port structures",
	    remote_port },
	{ "fcptrace", "[-s m][-e n] (m < n)", "Dump the fcp trace buffer, "
	    "optionally supplying starting and ending packet numbers.",
	    fcp_trace_dump, NULL },
	{ "fptrace", "[-s m][-e n] (m < n)", "Dump the fp trace buffer, "
	    "optionally supplying starting and ending packet numbers.",
	    fp_trace_dump, NULL },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "ports", "walk list of Leadville port structures",
	    port_walk_i, port_walk_s, port_walk_f },
	{ "ulps", "walk list of Leadville ULP structures",
	    ulp_walk_i, ulp_walk_s, ulp_walk_f },
	{ "ulpmods", "walk list of Leadville ULP module structures",
	    ulpmod_walk_i, ulpmod_walk_s, ulpmod_walk_f },
	{ "pd_by_pwwn", "walk list of fc_remote_port structures hashed by PWWN",
	    pd_by_pwwn_walk_i, pd_by_pwwn_walk_s, pd_by_pwwn_walk_f },
	{ "pd_by_did", "walk list of fc_remote_port structures hashed by D_ID",
	    pd_by_did_walk_i, pd_by_did_walk_s, pd_by_did_walk_f },
	{ "job_request", "walk list of job_request structures for a local port",
	    job_request_walk_i, job_request_walk_s, job_request_walk_f },
	{ "orphan", "walk list of orphan structures for a local port",
	    orphan_walk_i, orphan_walk_s, orphan_walk_f },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
