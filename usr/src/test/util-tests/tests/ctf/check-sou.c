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
 * Copyright (c) 2019, Joyent, Inc.
 */

/*
 * Check that we properly handle structures and unions.
 */

#include "check-common.h"

static check_number_t check_bitfields[] = {
#ifdef	TARGET_LP64
	{ "unsigned long:1", CTF_K_INTEGER, 0, 0, 1 },
	{ "unsigned long:2", CTF_K_INTEGER,  0, 0, 2 },
	{ "unsigned long:4", CTF_K_INTEGER,  0, 0, 4 },
	{ "unsigned long:5", CTF_K_INTEGER,  0, 0, 5 },
	{ "unsigned long:8", CTF_K_INTEGER,  0, 0, 8 },
	{ "unsigned long:16", CTF_K_INTEGER,  0, 0, 16 },
	{ "unsigned long:19", CTF_K_INTEGER,  0, 0, 19 },
	{ "unsigned long:32", CTF_K_INTEGER,  0, 0, 32 },
#else
	{ "unsigned long long:1", CTF_K_INTEGER, 0, 0, 1 },
	{ "unsigned long long:2", CTF_K_INTEGER,  0, 0, 2 },
	{ "unsigned long long:4", CTF_K_INTEGER,  0, 0, 4 },
	{ "unsigned long long:5", CTF_K_INTEGER,  0, 0, 5 },
	{ "unsigned long long:8", CTF_K_INTEGER,  0, 0, 8 },
	{ "unsigned long long:16", CTF_K_INTEGER,  0, 0, 16 },
	{ "unsigned long long:19", CTF_K_INTEGER,  0, 0, 19 },
	{ "unsigned long long:32", CTF_K_INTEGER,  0, 0, 32 },
#endif
	{ "unsigned short:1", CTF_K_INTEGER, 0, 0, 1 },
	{ "unsigned int:7", CTF_K_INTEGER, 0, 0, 7 },
	{ "unsigned int:32", CTF_K_INTEGER, 0, 0, 32 },
	{ "int:3", CTF_K_INTEGER, CTF_INT_SIGNED, 0, 3 },
	{ NULL }
};

static check_symbol_t check_syms[] = {
	{ "foo", "struct foo" },
	{ "head", "nlist_t" },
	{ "forward", "const forward_t" },
	{ "oot", "struct round_up" },
	{ "botw", "struct fixed_up" },
	{ "sophie", "struct mysterious_barrel" },
	{ "ayesha", "struct dusk_barrel" },
	{ "stats", "struct stats" },
	{ "ring", "struct fellowship" },
	{ "rings", "struct rings" },
	{ "nvme", "struct csts" },
	{ "games", "union jrpg" },
	{ "nier", "union nier" },
	{ "kh", "union kh" },
	{ "ct", "struct trigger" },
	{ "regress", "const union regress [9]" },
	{ NULL }
};

static check_member_t check_member_foo[] = {
	{ "a", "int", 0 },
	{ "b", "float", 4 * NBBY },
	{ "c", "const char *", 8 * NBBY },
	{ NULL }
};

static check_member_t check_member_node[] = {
	{ "prev", "struct node *", 0 },
#ifdef	TARGET_LP64
	{ "next", "struct node *", 8 * NBBY },
#else
	{ "next", "struct node *", 4 * NBBY },
#endif
	{ NULL }
};

static check_member_t check_member_nlist[] = {
	{ "size", "size_t", 0 },
#ifdef	TARGET_LP64
	{ "off", "size_t", 8 * NBBY },
	{ "head", "struct node", 16 * NBBY },
#else
	{ "off", "size_t", 4 * NBBY },
	{ "head", "struct node", 8 * NBBY },
#endif
	{ NULL }
};

static check_member_t check_member_forward[] = {
	{ "past", "void *", 0 },
#ifdef	TARGET_LP64
	{ "present", "void *", 8 * NBBY },
	{ "future", "void *", 16 * NBBY },
#else
	{ "present", "void *", 4 * NBBY },
	{ "future", "void *", 8 * NBBY },
#endif
	{ NULL }
};

static check_member_t check_member_round_up[] = {
	{ "triforce", "uint8_t", 0 },
	{ "link", "uint32_t", 4 * NBBY },
	{ "zelda", "uint8_t", 8 * NBBY },
	{ "ganon", "uint8_t", 9 * NBBY },
	{ NULL }
};

static check_member_t check_member_fixed_up[] = {
	{ "triforce", "uint8_t", 0 },
	{ "link", "uint32_t", 1 * NBBY },
	{ "zelda", "uint8_t", 5 * NBBY },
	{ "ganon", "uint8_t", 6 * NBBY },
	{ NULL }
};

#ifdef	TARGET_LP64
static check_member_t check_member_component[] = {
	{ "m", "enum material", 0 },
	{ "grade", "uint64_t", 8 * NBBY },
	{ "count", "uint64_t", 16 * NBBY },
	{ "locations", "const char *[4]", 24 * NBBY },
	{ NULL }
};

static check_member_t check_member_mysterious[] = {
	{ "name", "const char *", 0 },
	{ "capacity", "size_t", 8 * NBBY },
	{ "optional", "struct component [0]", 16 * NBBY },
	{ NULL }
};

static check_member_t check_member_dusk[] = {
	{ "name", "const char *", 0 },
	{ "opacity", "size_t", 8 * NBBY },
	{ "optional", "struct component [0]", 16 * NBBY },
	{ NULL }
};


static check_member_t check_member_stats[] = {
	{ "hp", "unsigned long:16", 0 },
	{ "mp", "unsigned long:16", 16 },
	{ "str", "unsigned long:8", 32 },
	{ "dex", "unsigned long:4", 40 },
	{ "con", "unsigned long:1", 44 },
	{ "inte", "unsigned long:2", 45 },
	{ "wis", "unsigned long:1", 47 },
	{ "cha", "unsigned long:4", 48 },
	{ "sanity", "unsigned long:1", 52 },
	{ "attack", "unsigned long:2", 53 },
	{ "mattack", "unsigned long:1", 55 },
	{ "defense", "unsigned long:8", 56 },
	{ "mdefense", "unsigned long:32", 64 },
	{ "evasion", "unsigned long:8", 96 },
	{ "crit", "unsigned long:5", 104 },
	{ "luck", "unsigned long:19", 109 },
	{ NULL }
};
#else
static check_member_t check_member_component[] = {
	{ "m", "enum material", 0 },
	{ "grade", "uint64_t", 4 * NBBY },
	{ "count", "uint64_t", 12 * NBBY },
	{ "locations", "const char *[4]", 20 * NBBY },
	{ NULL }
};

static check_member_t check_member_mysterious[] = {
	{ "name", "const char *", 0 },
	{ "capacity", "size_t", 4 * NBBY },
	{ "optional", "struct component [0]", 8 * NBBY },
	{ NULL }
};

static check_member_t check_member_dusk[] = {
	{ "name", "const char *", 0 },
	{ "opacity", "size_t", 4 * NBBY },
	{ "optional", "struct component [0]", 8 * NBBY },
	{ NULL }
};


static check_member_t check_member_stats[] = {
	{ "hp", "unsigned long long:16", 0 },
	{ "mp", "unsigned long long:16", 16 },
	{ "str", "unsigned long long:8", 32 },
	{ "dex", "unsigned long long:4", 40 },
	{ "con", "unsigned long long:1", 44 },
	{ "inte", "unsigned long long:2", 45 },
	{ "wis", "unsigned long long:1", 47 },
	{ "cha", "unsigned long long:4", 48 },
	{ "sanity", "unsigned long long:1", 52 },
	{ "attack", "unsigned long long:2", 53 },
	{ "mattack", "unsigned long long:1", 55 },
	{ "defense", "unsigned long long:8", 56 },
	{ "mdefense", "unsigned long long:32", 64 },
	{ "evasion", "unsigned long long:8", 96 },
	{ "crit", "unsigned long long:5", 104 },
	{ "luck", "unsigned long long:19", 109 },
	{ NULL }
};
#endif

static check_member_t check_member_fellowship[] = {
	{ "frodo", "unsigned short:1", 0 },
	{ "sam", "unsigned short:1", 1 },
	{ "merry", "unsigned short:1", 2 },
	{ "pippin", "unsigned short:1", 3 },
	{ "aragorn", "unsigned short:1", 4 },
	{ "boromir", "unsigned short:1", 5 },
	{ "legolas", "unsigned short:1", 6 },
	{ "gimli", "unsigned short:1", 7 },
	{ "gandalf", "unsigned short:1", 8 },
	{ NULL }
};

static check_member_t check_member_rings[] = {
	{ "elves", "unsigned int:3", 0 },
	{ "dwarves", "unsigned int:7", 3 },
	{ "men", "unsigned int:9", 10 },
	{ "one", "uint8_t", 3 * NBBY },
	{ "silmarils", "uint8_t [3]", 4 * NBBY },
	{ NULL }
};

static check_member_t check_member_csts[] = {
	{ "rdy", "unsigned int:7", 0 },
	{ "csts", "unsigned int:32", 7 },
	{ NULL }
};

static check_member_t check_member_jrpg[] = {
	{ "ff", "int", 0 },
	{ "atelier", "double [4]", 0 },
	{ "tales", "const char *", 0 },
	{ "chrono", "int (*)()", 0 },
	{ "xeno", "struct rings", 0 },
	{ NULL }
};

static check_member_t check_member_android[] = {
	{ "_2b", "unsigned int:16", 0 },
	{ "_9s", "unsigned int:16", 16 },
	{ NULL }
};

static check_member_t check_member_nier[] = {
	{ "automata", "uint32_t", 0 },
	{ "android", "struct android", 0 },
	{ NULL }
};

static check_member_t check_member_kh[] = {
	{ "sora", "int:3", 0 },
	{ "riku", "char:7", 0 },
	{ "kairi", "double", 0 },
	{ "namine", "complex double", 0 },
	{ NULL }
};

static check_member_t check_member_trigger[] = {
	{ "chrono", "uint8_t", 0 },
	{ "cross", "uint8_t", 8 },
	/*
	 * This test has an anonymous union. Unfortunately, there's not a great
	 * way to distinguish between various anonymous unions in this form.
	 */
#ifdef	TARGET_LP64
	{ "", "union ", 64 },
#else
	{ "", "union ", 32 },
#endif
	{ NULL }
};

static check_member_t check_member_regress[] = {
	{ "i", "unsigned int [3]", 0 },
	{ "e", "long double", 0 },
	{ NULL }
};

static check_member_test_t members[] = {
#ifdef	TARGET_LP64
	{ "struct foo", CTF_K_STRUCT, 16, check_member_foo },
	{ "struct node", CTF_K_STRUCT, 16, check_member_node },
	{ "struct nlist", CTF_K_STRUCT, 32, check_member_nlist },
	{ "struct forward", CTF_K_STRUCT, 24, check_member_forward },
#else
	{ "struct foo", CTF_K_STRUCT, 12, check_member_foo },
	{ "struct node", CTF_K_STRUCT, 8, check_member_node },
	{ "struct nlist", CTF_K_STRUCT, 16, check_member_nlist },
	{ "struct forward", CTF_K_STRUCT, 12, check_member_forward },
#endif
	{ "struct round_up", CTF_K_STRUCT, 12, check_member_round_up },
	{ "struct fixed_up", CTF_K_STRUCT, 7, check_member_fixed_up },
#ifdef	TARGET_LP64
	{ "struct component", CTF_K_STRUCT, 56, check_member_component },
	{ "struct mysterious_barrel", CTF_K_STRUCT, 16,
	    check_member_mysterious },
	{ "struct dusk_barrel", CTF_K_STRUCT, 16, check_member_dusk },
#else
	{ "struct component", CTF_K_STRUCT, 36, check_member_component },
	{ "struct mysterious_barrel", CTF_K_STRUCT, 8,
	    check_member_mysterious },
	{ "struct dusk_barrel", CTF_K_STRUCT, 8, check_member_dusk },
#endif
	{ "struct stats", CTF_K_STRUCT, 16, check_member_stats },
	{ "struct fellowship", CTF_K_STRUCT, 2, check_member_fellowship },
	{ "struct rings", CTF_K_STRUCT, 8, check_member_rings },
	{ "struct csts", CTF_K_STRUCT, 5, check_member_csts },
	{ "union jrpg", CTF_K_UNION, 32, check_member_jrpg },
	{ "struct android", CTF_K_STRUCT, 4, check_member_android },
	{ "union nier", CTF_K_UNION, 4, check_member_nier },
	{ "union kh", CTF_K_UNION, 16, check_member_kh },
#ifdef	TARGET_LP64
	{ "struct trigger", CTF_K_STRUCT, 32, check_member_trigger },
	{ "union regress", CTF_K_UNION, 16, check_member_regress },
#else
	{ "struct trigger", CTF_K_STRUCT, 28, check_member_trigger },
	{ "union regress", CTF_K_UNION, 12, check_member_regress },
#endif
	{ NULL }
};

static check_descent_t check_descent_head[] = {
	{ "nlist_t", CTF_K_TYPEDEF },
	{ "struct nlist", CTF_K_STRUCT },
	{ NULL }
};

static check_descent_t check_descent_forward[] = {
	{ "const forward_t", CTF_K_CONST },
	{ "forward_t", CTF_K_TYPEDEF },
	{ "struct forward", CTF_K_STRUCT },
	{ NULL }
};

static check_descent_t check_descent_regress[] = {
	{ "const union regress [9]", CTF_K_CONST },
	{ "union regress [9]", CTF_K_ARRAY, "union regress", 9 },
	{ "union regress", CTF_K_UNION },
	{ NULL }
};

static check_descent_test_t descents[] = {
	{ "head", check_descent_head },
	{ "forward", check_descent_forward },
	{ "regress", check_descent_regress },
	{ NULL }
};

int
main(int argc, char *argv[])
{
	int i, ret = 0;

	if (argc < 2) {
		errx(EXIT_FAILURE, "missing test files");
	}

	for (i = 1; i < argc; i++) {
		ctf_file_t *fp;
		uint_t j;

		if ((fp = ctf_open(argv[i], &ret)) == NULL) {
			warnx("failed to open %s: %s", argv[i],
			    ctf_errmsg(ret));
			ret = EXIT_FAILURE;
			continue;
		}

		if (!ctftest_check_numbers(fp, check_bitfields))
			ret = EXIT_FAILURE;
		if (!ctftest_check_symbols(fp, check_syms))
			ret = EXIT_FAILURE;
		for (j = 0; descents[j].cdt_sym != NULL; j++) {
			if (!ctftest_check_descent(descents[j].cdt_sym, fp,
			    descents[j].cdt_tests)) {
				ret = EXIT_FAILURE;
			}
		}

		for (j = 0; members[j].cmt_type != NULL; j++) {
			if (!ctftest_check_members(members[j].cmt_type, fp,
			    members[j].cmt_kind, members[j].cmt_size,
			    members[j].cmt_members)) {
				ret = EXIT_FAILURE;
			}
		}

		ctf_close(fp);
	}

	return (ret);
}
