/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

/*
 * This implements psrinfo(1M), a utility to report various information
 * about processors, cores, and threads (virtual cpus).  This is mostly
 * intended for human consumption - this utility doesn't do much more than
 * simply process kstats for human readability.
 *
 * All the relevant kstats are in the cpu_info kstat module.
 */

#include <sys/sysmacros.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <kstat.h>
#include <libintl.h>
#include <locale.h>
#include <libgen.h>
#include <ctype.h>
#include <errno.h>
#include <err.h>

#include <libdevinfo.h>

#define	_(x)	gettext(x)
#if XGETTEXT
	/* These CPU states are here for benefit of xgettext */
	_("on-line")
	_("off-line")
	_("faulted")
	_("powered-off")
	_("no-intr")
	_("spare")
	_("unknown")
	_("disabled")
#endif

/*
 * We deal with sorted linked lists, where the sort key is usually the
 * cpu id, core id, or chip id.  We generalize this with simple node.
 */
struct link {
	long		l_id;
	struct link	*l_next;
	void		*l_ptr;
};

/*
 * A physical chip.  A chip can contain multiple cores and virtual cpus.
 */
struct pchip {
	struct link	p_link;
	int		p_ncore;
	int		p_nvcpu;
	struct link	*p_cores;
	struct link	*p_vcpus;
	int		p_doit;
};

struct core {
	struct link	c_link;
	struct link	c_link_pchip;

	int		c_nvcpu;
	int		c_doit;

	struct pchip	*c_pchip;
	struct link	*c_vcpus;
};

struct vcpu {
	struct link	v_link;

	struct link	v_link_core;
	struct link	v_link_pchip;

	int		v_doit;

	struct pchip	*v_pchip;
	struct core	*v_core;

	char		*v_state;
	long		v_state_begin;
	char		*v_cpu_type;
	char		*v_fpu_type;
	long		v_clock_mhz;
	long		v_pchip_id;	/* 1 per socket */
	char		*v_impl;
	char		*v_brand;
	char		*v_socket;
	long		v_core_id;	/* n per chip_id */
};

static struct link *pchips = NULL;
static struct link *cores = NULL;
static struct link *vcpus = NULL;

static uint_t nr_cpus;
static uint_t nr_cores;
static uint_t nr_chips;

static const char *cmdname;

static void
usage(char *msg)
{
	if (msg != NULL)
		(void) fprintf(stderr, "%s: %s\n", cmdname, msg);
	(void) fprintf(stderr, _("usage: \n"
	    "\t%s -r propname\n"
	    "\t%s [-v] [-p] [processor_id ...]\n"
	    "\t%s -s [-p] processor_id\n"
	    "\t%s -t [-S <state> | -c | -p]\n"),
	    cmdname, cmdname, cmdname, cmdname);
	exit(2);
}

/* like perror, but includes the command name */
static void
die(const char *msg)
{
	(void) fprintf(stderr, "%s: %s: %s\n", cmdname, msg, strerror(errno));
	exit(2);
}

static char *
mystrdup(const char *src)
{
	char *dst;

	if ((dst = strdup(src)) == NULL)
		die(_("strdup() failed"));
	return (dst);
}

static void *
zalloc(size_t size)
{
	void *ptr;

	if ((ptr = calloc(1, size)) == NULL)
		die(_("calloc() failed"));
	return (ptr);
}

/*
 * Insert a new node on a list, at the insertion point given.
 */
static void
ins_link(struct link **ins, struct link *item)
{
	item->l_next = *ins;
	*ins = item;
}

/*
 * Find an id on a sorted list.  If the requested id is not found,
 * then the insertpt will be set (if not null) to the location where
 * a new node should be inserted with ins_link (see above).
 */
static void *
find_link(void *list, int id, struct link ***insertpt)
{
	struct link **ins = list;
	struct link *l;

	while ((l = *ins) != NULL) {
		if (l->l_id == id)
			return (l->l_ptr);
		if (l->l_id > id)
			break;
		ins = &l->l_next;
	}
	if (insertpt != NULL)
		*insertpt = ins;
	return (NULL);
}

/*
 * Print the linked list of ids in parens, taking care to collapse
 * ranges, so instead of (0 1 2 3) it should print (0-3).
 */
static void
print_links(struct link *l)
{
	int	start = -1;
	int	end = 0;

	(void) printf(" (");
	while (l != NULL) {
		if (start < 0) {
			start = l->l_id;
		}
		end = l->l_id;
		if ((l->l_next == NULL) ||
		    (l->l_next->l_id > (l->l_id + 1))) {
			/* end of the contiguous group */
			if (start == end) {
				(void) printf("%d", start);
			} else {
				(void) printf("%d-%d", start, end);
			}
			if (l->l_next)
				(void) printf(" ");
			start = -1;
		}
		l = l->l_next;
	}
	(void) printf(")");
}

static const char *
timestr(long t)
{
	static char buffer[256];
	(void) strftime(buffer, sizeof (buffer), _("%m/%d/%Y %T"),
	    localtime(&t));
	return (buffer);
}

static void
print_vp(int nspec)
{
	struct pchip *chip;
	struct core *core;
	struct vcpu *vcpu;
	struct link *l1, *l2;
	int len;
	for (l1 = pchips; l1; l1 = l1->l_next) {

		chip = l1->l_ptr;

		if ((nspec != 0) && (chip->p_doit == 0))
			continue;

		vcpu = chip->p_vcpus->l_ptr;

		/*
		 * Note that some of the way these strings are broken up are
		 * to accommodate the legacy translations so that we won't
		 * have to retranslate for this utility.
		 */
		if ((chip->p_ncore == 1) || (chip->p_ncore == chip->p_nvcpu)) {
			(void) printf(_("%s has %d virtual %s"),
			    _("The physical processor"),
			    chip->p_nvcpu,
			    chip->p_nvcpu > 1 ?
			    _("processors") :
			    _("processor"));
		} else {
			(void) printf(_("%s has %d %s and %d virtual %s"),
			    _("The physical processor"),
			    chip->p_ncore, _("cores"),
			    chip->p_nvcpu,
			    chip->p_nvcpu > 1 ?
			    _("processors") : _("processor"));
		}

		print_links(chip->p_vcpus);
		(void) putchar('\n');

		if ((chip->p_ncore == 1) || (chip->p_ncore == chip->p_nvcpu)) {
			if (strlen(vcpu->v_impl)) {
				(void) printf("  %s\n", vcpu->v_impl);
			}
			if (((len = strlen(vcpu->v_brand)) != 0) &&
			    (strncmp(vcpu->v_brand, vcpu->v_impl, len) != 0))
				(void) printf("\t%s", vcpu->v_brand);
			if (strcmp(vcpu->v_socket, "Unknown") != 0)
				(void) printf("\t[ %s: %s ]", _("Socket"),
				    vcpu->v_socket);
			(void) putchar('\n');
		} else {
			for (l2 = chip->p_cores; l2; l2 = l2->l_next) {
				core = l2->l_ptr;
				(void) printf(_("  %s has %d virtual %s"),
				    _("The core"),
				    core->c_nvcpu,
				    chip->p_nvcpu > 1 ?
				    _("processors") : _("processor"));
				print_links(core->c_vcpus);
				(void) putchar('\n');
			}
			if (strlen(vcpu->v_impl)) {
				(void) printf("    %s\n", vcpu->v_impl);
			}
			if (((len = strlen(vcpu->v_brand)) != 0) &&
			    (strncmp(vcpu->v_brand, vcpu->v_impl, len) != 0))
				(void) printf("      %s\n", vcpu->v_brand);
		}
	}
}

static void
print_ps(void)
{
	int online = 1;
	struct pchip *p = NULL;
	struct vcpu *v;
	struct link *l;

	/*
	 * Report "1" if all cpus colocated on the same chip are online.
	 */
	for (l = pchips; l != NULL; l = l->l_next) {
		p = l->l_ptr;
		if (p->p_doit)
			break;
	}
	if (p == NULL)
		return;	/* should never happen! */
	for (l = p->p_vcpus; l != NULL; l = l->l_next) {
		v = l->l_ptr;
		if (strcmp(v->v_state, "on-line") != 0) {
			online = 0;
			break;
		}
	}

	(void) printf("%d\n", online);
}

static void
print_s(void)
{
	struct link *l;

	/*
	 * Find the processor (there will be only one) that we selected,
	 * and report whether or not it is online.
	 */
	for (l = vcpus; l != NULL; l = l->l_next) {
		struct vcpu *v = l->l_ptr;
		if (v->v_doit) {
			(void) printf("%d\n",
			    strcmp(v->v_state, "on-line") == 0 ? 1 : 0);
			return;
		}
	}
}

static void
print_p(int nspec)
{
	struct		link *l1, *l2;
	int		online = 0;

	/*
	 * Print the number of physical packages with at least one processor
	 * online.
	 */
	for (l1 = pchips; l1 != NULL; l1 = l1->l_next) {
		struct pchip *p = l1->l_ptr;
		if ((nspec == 0) || (p->p_doit)) {

			for (l2 = p->p_vcpus; l2 != NULL; l2 = l2->l_next) {
				struct vcpu *v = l2->l_ptr;
				if (strcmp(v->v_state, "on-line") == 0) {
					online++;
					break;
				}
			}
		}
	}
	(void) printf("%d\n", online);
}

static void
print_v(int nspec)
{
	struct link	*l;

	for (l = vcpus; l != NULL; l = l->l_next) {
		struct vcpu *v = l->l_ptr;

		if ((nspec != 0) && (!v->v_doit))
			continue;
		(void) printf(_("Status of virtual processor %d as of: "),
		    l->l_id);
		(void) printf("%s\n", timestr(time(NULL)));
		(void) printf(_("  %s since %s.\n"),
		    _(v->v_state), timestr(v->v_state_begin));
		if (v->v_clock_mhz) {
			(void) printf(
			    _("  The %s processor operates at %llu MHz,\n"),
			    v->v_cpu_type, (unsigned long long)v->v_clock_mhz);
		} else {
			(void) printf(
			    _("  The %s processor operates at " \
			    "an unknown frequency,\n"), v->v_cpu_type);
		}
		switch (*v->v_fpu_type) {
		case '\0':
			(void) printf(
			    _("\tand has no floating point processor.\n"));
			break;
		case 'a': case 'A':
		case 'e': case 'E':
		case 'i': case 'I':
		case 'o': case 'O':
		case 'u': case 'U':
		case 'y': case 'Y':
			(void) printf(
			    _("\tand has an %s floating point processor.\n"),
			    v->v_fpu_type);
			break;
		default:
			(void) printf(
			    _("\tand has a %s floating point processor.\n"),
			    v->v_fpu_type);
			break;
		}
	}
}

static void
print_normal(int nspec)
{
	struct link	*l;
	struct vcpu	*v;

	for (l = vcpus; l != NULL; l = l->l_next) {
		v = l->l_ptr;
		if ((nspec == 0) || (v->v_doit)) {
			(void) printf(_("%d\t%-8s  since %s\n"),
			    l->l_id, _(v->v_state), timestr(v->v_state_begin));
		}
	}
}

static bool
valid_propname(const char *propname)
{
	size_t i;

	const char *props[] = {
		"smt_enabled",
	};

	for (i = 0; i < ARRAY_SIZE(props); i++) {
		if (strcmp(propname, props[i]) == 0)
			break;
	}

	return (i != ARRAY_SIZE(props));
}

static void
read_property(const char *propname)
{
	di_prop_t prop = DI_PROP_NIL;
	di_node_t root_node;
	bool show_all = strcmp(propname, "all") == 0;

	if (!show_all && !valid_propname(propname))
		errx(EXIT_FAILURE, _("unknown CPU property %s"), propname);

	if ((root_node = di_init("/", DINFOPROP)) == NULL)
		err(EXIT_FAILURE, _("failed to read root node"));

	while ((prop = di_prop_sys_next(root_node, prop)) != DI_PROP_NIL) {
		const char *name = di_prop_name(prop);
		char *val;
		int nr_vals;

		if (!valid_propname(name))
			continue;

		if (!show_all && strcmp(di_prop_name(prop), propname) != 0)
			continue;

		if ((nr_vals = di_prop_strings(prop, &val)) < 1) {
			err(EXIT_FAILURE,
			    _("error reading property %s"), name);
		} else if (nr_vals != 1) {
			errx(EXIT_FAILURE, _("invalid property %s"), name);
		}

		printf("%s=%s\n", name, val);

		if (!show_all)
			exit(EXIT_SUCCESS);
	}

	if (!show_all)
		errx(EXIT_FAILURE, _("property %s was not found"), propname);

	di_fini(root_node);
}

static void
print_total(int opt_c, int opt_p, const char *opt_S)
{
	uint_t count = 0;

	if (opt_c) {
		printf("%u\n", nr_cores);
		return;
	} else if (opt_p) {
		printf("%u\n", nr_chips);
		return;
	} else if (opt_S == NULL || strcmp(opt_S, "all") == 0) {
		printf("%u\n", nr_cpus);
		return;
	}


	for (struct link *l = vcpus; l != NULL; l = l->l_next) {
		struct vcpu *v = l->l_ptr;
		if (strcmp(opt_S, v->v_state) == 0)
			count++;
	}

	printf("%u\n", count);
}

int
main(int argc, char **argv)
{
	kstat_ctl_t	*kc;
	kstat_t		*ksp;
	kstat_named_t	*knp;
	struct vcpu	*vc;
	struct core	*core;
	struct pchip	*chip;
	struct link	**ins;
	char		*s;
	int		nspec;
	int		optc;
	int		opt_c = 0;
	int		opt_p = 0;
	const char	*opt_r = NULL;
	const char	*opt_S = NULL;
	int		opt_s = 0;
	int		opt_t = 0;
	int		opt_v = 0;
	int		ex = 0;

	cmdname = basename(argv[0]);


	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* collect the kstats */
	if ((kc = kstat_open()) == NULL)
		die(_("kstat_open() failed"));

	if ((ksp = kstat_lookup(kc, "cpu_info", -1, NULL)) == NULL)
		die(_("kstat_lookup() failed"));

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {

		if (strcmp(ksp->ks_module, "cpu_info") != 0)
			continue;
		if (kstat_read(kc, ksp, NULL) == NULL)
			die(_("kstat_read() failed"));

		vc = find_link(&vcpus, ksp->ks_instance, &ins);
		if (vc == NULL) {
			vc = zalloc(sizeof (struct vcpu));
			vc->v_link.l_id = ksp->ks_instance;
			vc->v_link_core.l_id = ksp->ks_instance;
			vc->v_link_pchip.l_id = ksp->ks_instance;
			vc->v_link.l_ptr = vc;
			vc->v_link_core.l_ptr = vc;
			vc->v_link_pchip.l_ptr = vc;
			ins_link(ins, &vc->v_link);
			nr_cpus++;
		}

		if ((knp = kstat_data_lookup(ksp, "state")) != NULL) {
			vc->v_state = mystrdup(knp->value.c);
		} else {
			vc->v_state = "unknown";
		}

		if ((knp = kstat_data_lookup(ksp, "cpu_type")) != NULL) {
			vc->v_cpu_type = mystrdup(knp->value.c);
		}
		if ((knp = kstat_data_lookup(ksp, "fpu_type")) != NULL) {
			vc->v_fpu_type = mystrdup(knp->value.c);
		}

		if ((knp = kstat_data_lookup(ksp, "state_begin")) != NULL) {
			vc->v_state_begin = knp->value.l;
		}

		if ((knp = kstat_data_lookup(ksp, "clock_MHz")) != NULL) {
			vc->v_clock_mhz = knp->value.l;
		}

		if ((knp = kstat_data_lookup(ksp, "brand")) == NULL) {
			vc->v_brand = _("(unknown)");
		} else {
			vc->v_brand = mystrdup(knp->value.str.addr.ptr);
		}

		if ((knp = kstat_data_lookup(ksp, "socket_type")) == NULL) {
			vc->v_socket = "Unknown";
		} else {
			vc->v_socket = mystrdup(knp->value.str.addr.ptr);
		}

		if ((knp = kstat_data_lookup(ksp, "implementation")) == NULL) {
			vc->v_impl = _("(unknown)");
		} else {
			vc->v_impl = mystrdup(knp->value.str.addr.ptr);
		}
		/*
		 * Legacy code removed the chipid and cpuid fields... we
		 * do the same for compatibility.  Note that the original
		 * pattern is a bit strange, and we have to emulate this because
		 * on SPARC we *do* emit these.  The original pattern we are
		 * emulating is: $impl =~ s/(cpuid|chipid)\s*\w+\s+//;
		 */
		if ((s = strstr(vc->v_impl, "chipid")) != NULL) {
			char *x = s + strlen("chipid");
			while (isspace(*x))
				x++;
			if ((!isalnum(*x)) && (*x != '_'))
				goto nochipid;
			while (isalnum(*x) || (*x == '_'))
				x++;
			if (!isspace(*x))
				goto nochipid;
			while (isspace(*x))
				x++;
			(void) strcpy(s, x);
		}
nochipid:
		if ((s = strstr(vc->v_impl, "cpuid")) != NULL) {
			char *x = s + strlen("cpuid");
			while (isspace(*x))
				x++;
			if ((!isalnum(*x)) && (*x != '_'))
				goto nocpuid;
			while (isalnum(*x) || (*x == '_'))
				x++;
			if (!isspace(*x))
				goto nocpuid;
			while (isspace(*x))
				x++;
			(void) strcpy(s, x);
		}
nocpuid:

		if ((knp = kstat_data_lookup(ksp, "chip_id")) != NULL)
			vc->v_pchip_id = knp->value.l;
		chip = find_link(&pchips, vc->v_pchip_id, &ins);
		if (chip == NULL) {
			chip = zalloc(sizeof (struct pchip));
			chip->p_link.l_id = vc->v_pchip_id;
			chip->p_link.l_ptr = chip;
			ins_link(ins, &chip->p_link);
			nr_chips++;
		}
		vc->v_pchip = chip;

		if ((knp = kstat_data_lookup(ksp, "core_id")) != NULL)
			vc->v_core_id = knp->value.l;
		core = find_link(&cores, vc->v_core_id, &ins);
		if (core == NULL) {
			core = zalloc(sizeof (struct core));
			core->c_link.l_id = vc->v_core_id;
			core->c_link.l_ptr = core;
			core->c_link_pchip.l_id = vc->v_core_id;
			core->c_link_pchip.l_ptr = core;
			core->c_pchip = chip;
			ins_link(ins, &core->c_link);
			chip->p_ncore++;
			(void) find_link(&chip->p_cores, core->c_link.l_id,
			    &ins);
			ins_link(ins, &core->c_link_pchip);
			nr_cores++;
		}
		vc->v_core = core;



		/* now put other linkages in place */
		(void) find_link(&chip->p_vcpus, vc->v_link.l_id, &ins);
		ins_link(ins, &vc->v_link_pchip);
		chip->p_nvcpu++;

		(void) find_link(&core->c_vcpus, vc->v_link.l_id, &ins);
		ins_link(ins, &vc->v_link_core);
		core->c_nvcpu++;
	}

	(void) kstat_close(kc);

	nspec = 0;

	while ((optc = getopt(argc, argv, "cpr:S:stv")) != EOF) {
		switch (optc) {
		case 'c':
			opt_c = 1;
			break;
		case 'p':
			opt_p = 1;
			break;
		case 'r':
			opt_r = optarg;
			break;
		case 'S':
			opt_S = optarg;
			break;
		case 's':
			opt_s = 1;
			break;
		case 't':
			opt_t = 1;
			break;
		case 'v':
			opt_v = 1;
			break;
		default:
			usage(NULL);
		}
	}

	if (opt_r != NULL) {
		if (optind != argc)
			usage(_("cannot specify CPUs with -r"));
		if (opt_c || opt_p || opt_S != NULL || opt_s || opt_t || opt_v)
			usage(_("cannot specify other arguments with -r"));

		read_property(opt_r);
		return (EXIT_SUCCESS);
	}

	if (opt_t != 0) {
		if (optind != argc)
			usage(_("cannot specify CPUs with -t"));
		if (opt_s || opt_v)
			usage(_("cannot specify -s or -v with -t"));
		if (opt_S != NULL && (opt_c || opt_p))
			usage(_("cannot specify CPU state with -c or -p"));
		if (opt_c && opt_p)
			usage(_("cannot specify -c and -p"));

		print_total(opt_c, opt_p, opt_S);
		return (EXIT_SUCCESS);
	}

	if (opt_S != NULL || opt_c)
		usage(_("cannot specify -S or -c without -t"));

	while (optind < argc) {
		long id;
		char *eptr;
		struct link *l;
		id = strtol(argv[optind], &eptr, 10);
		l = find_link(&vcpus, id, NULL);
		if ((*eptr != '\0') || (l == NULL)) {
			(void) fprintf(stderr,
			    _("%s: processor %s: Invalid argument\n"),
			    cmdname, argv[optind]);
			ex = 2;
		} else {
			((struct vcpu *)l->l_ptr)->v_doit = 1;
			((struct vcpu *)l->l_ptr)->v_pchip->p_doit = 1;
			((struct vcpu *)l->l_ptr)->v_core->c_doit = 1;
		}
		nspec++;
		optind++;
	}

	if (opt_s && opt_v) {
		usage(_("options -s and -v are mutually exclusive"));
	}
	if (opt_s && nspec != 1) {
		usage(_("must specify exactly one processor if -s used"));
	}
	if (opt_v && opt_p) {
		print_vp(nspec);
	} else if (opt_s && opt_p) {
		print_ps();
	} else if (opt_p) {
		print_p(nspec);
	} else if (opt_v) {
		print_v(nspec);
	} else if (opt_s) {
		print_s();
	} else {
		print_normal(nspec);
	}

	return (ex);
}
