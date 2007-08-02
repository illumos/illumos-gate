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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif_impl.h>
#include <sys/machsystm.h>
#include <sys/lpad.h>
#include <sys/vmsystm.h>
#include <sys/prom_plat.h>
#include <sys/ldoms.h>
#include <sys/kobj.h>
#include <sys/reboot.h>
#include <sys/hypervisor_api.h>
#include <sys/mdesc.h>
#include <sys/mach_descrip.h>

#ifndef _KMDB
static processorid_t cif_cpu;
static struct translation *cif_prom_trans;
static size_t cif_prom_ntrans;

int cif_cpu_mp_ready;
int (*prom_cif_handler)(void *) = NULL;
#endif

#ifdef DEBUG
uint_t cif_debug;
#endif /* DEBUG */

extern int (*cif_handler)(void *);

typedef struct {
	char		*name;
	cif_func_t	func;
} cif_callback_t;

static cif_callback_t cb_table[] = {
	{ "getprop",			promif_getprop		    },
	{ "getproplen",			promif_getproplen	    },
	{ "nextprop",			promif_nextprop		    },
	{ "peer",			promif_nextnode		    },
	{ "child",			promif_childnode	    },
	{ "parent",			promif_parentnode	    },
	{ "enter",			promif_enter_mon	    },
	{ "exit",			promif_exit_to_mon	    },
	{ "boot",			promif_reboot		    },
	{ "write",			promif_write		    },
	{ "read",			promif_read		    },
	{ "interpret",			promif_interpret	    },
	{ "finddevice",			promif_finddevice	    },
	{ "instance-to-package",	promif_instance_to_package  },
#ifndef _KMDB
	{ "setprop",			promif_setprop		    },
	{ "test",			promif_test		    },
	{ "instance-to-path",		promif_instance_to_path	    },
	{ "SUNW,power-off",		promif_power_off	    },
	{ "SUNW,asr-list-keys-len",	promif_asr_list_keys_len    },
	{ "SUNW,asr-list-keys",		promif_asr_list_keys	    },
	{ "SUNW,asr-export-len",	promif_asr_export_len	    },
	{ "SUNW,asr-export",		promif_asr_export	    },
	{ "SUNW,set-security-key",	promif_set_security_key	    },
	{ "SUNW,get-security-key",	promif_get_security_key	    },
	{ "SUNW,start-cpu-by-cpuid",	promif_start_cpu	    },
	{ "SUNW,set-trap-table",	promif_set_mmfsa_traptable  },
	{ "SUNW,set-sun4v-api-version",	promif_set_sun4v_api_version },
	{ "SUNW,get-sun4v-api-version",	promif_get_sun4v_api_version },
#endif
	{ NULL,				NULL			    }
};

cif_func_t
promif_find_cif_callback(char *opname)
{
	cif_callback_t	*cb;

	if (opname == NULL)
		return (NULL);

	for (cb = cb_table; cb->name; cb++) {
		if (prom_strcmp(cb->name, opname) == 0)
			break;
	}

	return (cb->func);
}

static int
kern_cif_handler(void *p)
{
	cell_t		*ci = (cell_t *)p;
	char		*opname;
	cif_func_t	func;
	int		rv;

	ASSERT(cif_handler == kern_cif_handler);

#ifndef _KMDB
	cif_cpu = getprocessorid();
#endif

	opname = p1275_cell2ptr(ci[0]);

	/* lookup the callback for the desired operation */
	func = promif_find_cif_callback(opname);

	if (func == NULL) {
#ifdef _KMDB
		prom_fatal_error("sun4v unsupported CIFs\n");
#else
		cmn_err(CE_CONT, "!sun4v unsupported CIF: %s\n", opname);
		return (-1);
#endif
	}

	/* callback found, execute it */
	rv = func(p);

#ifndef _KMDB
	cif_cpu = -1;
#endif

	return (rv);
}

#ifdef _KMDB

void
cif_init(char *pgmname, caddr_t root, ihandle_t in, ihandle_t out,
    phandle_t pin, phandle_t pout, pnode_t chosen, pnode_t options)
{
	/* initialize pointer to a copy of OBP device tree */
	promif_stree_setroot(root);

	promif_set_nodes(chosen, options);

	/* initialize io parameters */
	promif_io_init(in, out, pin, pout);

	/*
	 * Switch CIF handler to the kernel.
	 */
	if (pgmname != NULL)
		prom_init(pgmname, (void *)kern_cif_handler);
	else
		cif_handler = kern_cif_handler;
}

#else

static void cache_prom_data(void);

/*
 * This function returns 1 if the current thread is executing in
 * the CIF and 0 otherwise. This is useful information to know
 * since code that implements CIF handlers can assume that it has
 * gone through the kern_preprom() entry point, implying it is
 * running single threaded, has preemption disabled, etc.
 */
int
promif_in_cif(void)
{
	int	mycpuid = getprocessorid();

	return ((cif_cpu == mycpuid) ? 1 : 0);
}

/*
 * Check that all cpus in the MD are within range (< NCPU).  Attempt
 * to stop any that aren't.
 */
static void
cif_check_cpus(void)
{
	md_t		*mdp;
	mde_cookie_t	rootnode;
	size_t		listsz;
	int		i;
	mde_cookie_t	*listp = NULL;
	int		num_nodes;
	uint64_t	cpuid;
	int		status;

	mdp = md_get_handle();
	ASSERT(mdp);

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);

	num_nodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, "cpu"),
	    md_find_name(mdp, "fwd"), listp);

	if (num_nodes <= 0)
		goto done;

	for (i = 0; i < num_nodes; i++) {
		if (md_get_prop_val(mdp, listp[i], "id", &cpuid)) {
			cmn_err(CE_WARN, "cif_check_cpus: "
			    "CPU instance %d has no 'id' property", i);
			continue;
		}

		mutex_enter(&cpu_lock);

		if (cpuid >= NCPU) {
			status = stopcpu_bycpuid(cpuid);
			if (status != 0 && status != ENOTSUP)
				cmn_err(CE_PANIC, "failed to stop cpu %lu (%d)",
				    cpuid, status);
		}

		mutex_exit(&cpu_lock);
	}

done:
	kmem_free(listp, listsz);
	(void) md_fini_handle(mdp);
}

void
cif_init(void)
{
	void (*kmdb_cb)(void);
	uint64_t rtba;
	uint64_t rv;

	/*
	 * Check if domaining is enabled. If not, do not
	 * initialize the kernel CIF handler.
	 */
	if (!domaining_enabled())
		return;

	/*
	 * Cache PROM data that is needed later, e.g. a shadow
	 * copy of the device tree, IO mappings, etc.
	 */
	cache_prom_data();

	/*
	 * Prepare to take over the get/set of environmental variables.
	 */
	promif_prop_init();

	/*
	 * Switch CIF handler to the kernel.
	 */
	prom_cif_handler = cif_handler;

	promif_preprom();
	cif_handler = kern_cif_handler;

	/*
	 * Take over rtba for the boot CPU. The rtba for
	 * all other CPUs are set as they enter the system.
	 */
	rtba = va_to_pa(&trap_table);
	if ((rv = hv_cpu_set_rtba(&rtba)) != H_EOK)
		panic("hv_cpu_set_rtba failed: %ld\n", rv);

	promif_postprom();

	/*
	 * If the system has been booted with kmdb we need kmdb to
	 * use the kernel cif handler instead of the PROM cif handler.
	 */
	if (boothowto & RB_KMDB) {
		kmdb_cb = (void (*)(void))modlookup("misc/kmdbmod",
		    "kctl_switch_promif");
		ASSERT(kmdb_cb != NULL);
		(*kmdb_cb)();
	}

	cif_check_cpus();
}

static void
cache_prom_data(void)
{
	/* initialize copy of OBP device tree */
	promif_stree_init();

	/* initialize io parameters */
	promif_io_init();
}

#endif	/* _KMDB */
