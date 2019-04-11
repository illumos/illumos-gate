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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * Check qualifier encoding. Note that the needed_qualifier() workaround applies
 * to most of these.
 */

#include "check-common.h"

static check_descent_t check_descent_const_union_array_gcc4[] = {
	{ "const union const_union [5]", CTF_K_CONST },
	{ "union const_union [5]", CTF_K_ARRAY, "union const_union", 5 },
	{ "union const_union", CTF_K_UNION },
	{ NULL }
};

static check_descent_t check_descent_const_union_array_gcc7[] = {
	{ "const union const_union [5]", CTF_K_ARRAY,
	    "const union const_union", 5 },
	{ "const union const_union", CTF_K_CONST },
	{ "union const_union", CTF_K_UNION },
	{ NULL }
};

static check_descent_test_t alt_descents_const_union_array[] = {
	{ "const_union_array", check_descent_const_union_array_gcc4 },
	{ "const_union_array", check_descent_const_union_array_gcc7 },
	{ NULL }
};

static check_descent_t check_descent_const_struct_array_gcc4[] = {
	{ "const struct const_struct [7]", CTF_K_CONST },
	{ "struct const_struct [7]", CTF_K_ARRAY, "struct const_struct", 7 },
	{ "struct const_struct", CTF_K_STRUCT },
	{ NULL }
};

static check_descent_t check_descent_const_struct_array_gcc7[] = {
	{ "const struct const_struct [7]", CTF_K_ARRAY,
	    "const struct const_struct", 7 },
	{ "const struct const_struct", CTF_K_CONST },
	{ "struct const_struct", CTF_K_STRUCT },
	{ NULL }
};

static check_descent_test_t alt_descents_const_struct_array[] = {
	{ "const_struct_array", check_descent_const_struct_array_gcc4 },
	{ "const_struct_array", check_descent_const_struct_array_gcc7 },
	{ NULL }
};

static check_descent_t check_descent_volatile_struct_array_gcc4[] = {
	{ "volatile struct volatile_struct [9]", CTF_K_VOLATILE },
	{ "struct volatile_struct [9]", CTF_K_ARRAY,
	    "struct volatile_struct", 9 },
	{ "struct volatile_struct", CTF_K_STRUCT },
	{ NULL }
};

static check_descent_t check_descent_volatile_struct_array_gcc7[] = {
	{ "volatile struct volatile_struct [9]", CTF_K_ARRAY,
	    "volatile struct volatile_struct", 9 },
	{ "volatile struct volatile_struct", CTF_K_VOLATILE },
	{ "struct volatile_struct", CTF_K_STRUCT },
	{ NULL }
};

static check_descent_test_t alt_descents_volatile_struct_array[] = {
	{ "volatile_struct_array", check_descent_volatile_struct_array_gcc4 },
	{ "volatile_struct_array", check_descent_volatile_struct_array_gcc7 },
	{ NULL }
};

static check_descent_t check_descent_c_int_array_gcc4[] = {
	{ "const int [11]", CTF_K_CONST },
	{ "int [11]", CTF_K_ARRAY, "int", 11 },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_c_int_array_gcc7[] = {
	{ "const int [11]", CTF_K_ARRAY, "const int", 11 },
	{ "const int", CTF_K_CONST },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t alt_descents_c_int_array[] = {
	{ "c_int_array", check_descent_c_int_array_gcc4 },
	{ "c_int_array", check_descent_c_int_array_gcc7 },
	{ NULL }
};

static check_descent_t check_descent_cv_int_array_gcc4[] = {
	{ "const volatile int [13]", CTF_K_CONST },
	{ "volatile int [13]", CTF_K_VOLATILE },
	{ "int [13]", CTF_K_ARRAY, "int", 13 },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_cv_int_array_gcc7[] = {
	{ "volatile const int [13]", CTF_K_ARRAY, "volatile const int", 13 },
	{ "volatile const int", CTF_K_VOLATILE },
	{ "const int", CTF_K_CONST },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t alt_descents_cv_int_array[] = {
	{ "cv_int_array", check_descent_cv_int_array_gcc4 },
	{ "cv_int_array", check_descent_cv_int_array_gcc7 },
	{ NULL }
};

static check_descent_t check_descent_vc_int_array_gcc4[] = {
	{ "const volatile int [15]", CTF_K_CONST },
	{ "volatile int [15]", CTF_K_VOLATILE },
	{ "int [15]", CTF_K_ARRAY, "int", 15 },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_vc_int_array_gcc7[] = {
	{ "volatile const int [15]", CTF_K_ARRAY, "volatile const int", 15 },
	{ "volatile const int", CTF_K_VOLATILE },
	{ "const int", CTF_K_CONST },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t alt_descents_vc_int_array[] = {
	{ "vc_int_array", check_descent_vc_int_array_gcc4 },
	{ "vc_int_array", check_descent_vc_int_array_gcc7 },
	{ NULL }
};

static check_descent_t check_descent_vc_int_array2_gcc4[] = {
	{ "const volatile int [17]", CTF_K_CONST },
	{ "volatile int [17]", CTF_K_VOLATILE },
	{ "int [17]", CTF_K_ARRAY, "int", 17 },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_vc_int_array2_gcc7[] = {
	{ "volatile const int [17]", CTF_K_ARRAY, "volatile const int", 17 },
	{ "volatile const int", CTF_K_VOLATILE },
	{ "const int", CTF_K_CONST },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t alt_descents_vc_int_array2[] = {
	{ "vc_int_array2", check_descent_vc_int_array2_gcc4 },
	{ "vc_int_array2", check_descent_vc_int_array2_gcc7 },
	{ NULL }
};

static check_descent_t check_descent_c_2d_array_gcc4[] = {
	{ "const int [4][2]", CTF_K_CONST },
	{ "int [4][2]", CTF_K_ARRAY, "int [2]", 4 },
	{ "int [2]", CTF_K_ARRAY, "int", 2 },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_c_2d_array_gcc7[] = {
	{ "const int [4][2]", CTF_K_ARRAY, "const int [2]", 4 },
	{ "const int [2]", CTF_K_ARRAY, "const int", 2 },
	{ "const int", CTF_K_CONST },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t alt_descents_c_2d_array[] = {
	{ "c_2d_array", check_descent_c_2d_array_gcc4 },
	{ "c_2d_array", check_descent_c_2d_array_gcc7 },
	{ NULL }
};

static check_descent_t check_descent_cv_3d_array_gcc4[] = {
	{ "const volatile int [3][2][1]", CTF_K_CONST },
	{ "volatile int [3][2][1]", CTF_K_VOLATILE },
	{ "int [3][2][1]", CTF_K_ARRAY, "int [2][1]", 3 },
	{ "int [2][1]", CTF_K_ARRAY, "int [1]", 2 },
	{ "int [1]", CTF_K_ARRAY, "int", 1 },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_cv_3d_array_gcc7[] = {
	{ "volatile const int [3][2][1]", CTF_K_ARRAY,
	    "volatile const int [2][1]", 3 },
	{ "volatile const int [2][1]", CTF_K_ARRAY,
	    "volatile const int [1]", 2 },
	{ "volatile const int [1]", CTF_K_ARRAY, "volatile const int", 1 },
	{ "volatile const int", CTF_K_VOLATILE },
	{ "const int", CTF_K_CONST },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t alt_descents_cv_3d_array[] = {
	{ "cv_3d_array", check_descent_cv_3d_array_gcc4 },
	{ "cv_3d_array", check_descent_cv_3d_array_gcc7 },
	{ NULL }
};

static check_descent_t check_descent_ptr_to_const_int[] = {
	{ "const int *", CTF_K_POINTER },
	{ "const int", CTF_K_CONST },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t alt_descents_ptr_to_const_int[] = {
	{ "ptr_to_const_int", check_descent_ptr_to_const_int },
	{ NULL }
};

static check_descent_t check_descent_const_ptr_to_int[] = {
	{ "int *const", CTF_K_CONST },
	{ "int *", CTF_K_POINTER },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t alt_descents_const_ptr_to_int[] = {
	{ "const_ptr_to_int", check_descent_const_ptr_to_int },
	{ NULL }
};

static check_descent_t check_descent_const_ptr_to_const_int[] = {
	{ "const int *const", CTF_K_CONST },
	{ "const int *", CTF_K_POINTER },
	{ "const int", CTF_K_CONST },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t alt_descents_const_ptr_to_const_int[] = {
	{ "const_ptr_to_const_int", check_descent_const_ptr_to_const_int },
	{ NULL }
};

static check_descent_test_t *alt_descents[] = {
	alt_descents_const_union_array,
	alt_descents_const_struct_array,
	alt_descents_volatile_struct_array,
	alt_descents_c_int_array,
	alt_descents_cv_int_array,
	alt_descents_vc_int_array,
	alt_descents_vc_int_array2,
	alt_descents_c_2d_array,
	alt_descents_cv_3d_array,
	alt_descents_ptr_to_const_int,
	alt_descents_const_ptr_to_int,
	alt_descents_const_ptr_to_const_int,
	NULL
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

		if ((fp = ctf_open(argv[i], &ret)) == NULL) {
			warnx("failed to open %s: %s", argv[i],
			    ctf_errmsg(ret));
			ret = EXIT_FAILURE;
			continue;
		}

		for (uint_t j = 0; alt_descents[j] != NULL; j++) {
			check_descent_test_t *descents = alt_descents[j];
			int alt_ok = 0;

			for (uint_t k = 0; descents[k].cdt_sym != NULL; k++) {
				if (ctftest_check_descent(descents[k].cdt_sym,
				    fp, descents[k].cdt_tests, B_TRUE)) {
					alt_ok = 1;
					break;
				}
			}

			if (!alt_ok) {
				warnx("all descents failed for %s",
				    descents[0].cdt_sym);
				ret = EXIT_FAILURE;
			}
		}

		ctf_close(fp);
	}

	return (ret);
}
