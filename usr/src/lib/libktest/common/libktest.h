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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _LIBKTEST_H
#define	_LIBKTEST_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ktest_hdl ktest_hdl_t;
typedef struct ktest_list_iter ktest_list_iter_t;

typedef struct ktest_entry {
	const char	*ke_module;
	const char	*ke_suite;
	const char	*ke_test;
	bool		ke_requires_input;
} ktest_entry_t;

typedef struct ktest_run_req {
	const char	*krq_module;
	const char	*krq_suite;
	const char	*krq_test;
	uchar_t		*krq_input;
	size_t		krq_input_len;
} ktest_run_req_t;

typedef enum ktest_code {
	KTEST_CODE_NONE,
	KTEST_CODE_PASS,
	KTEST_CODE_FAIL,
	KTEST_CODE_SKIP,
	KTEST_CODE_ERROR
} ktest_code_t;

typedef struct ktest_run_result {
	ktest_code_t	krr_code;
	char		*krr_msg;
	uint_t		krr_line;
} ktest_run_result_t;

extern ktest_hdl_t *ktest_init(void);
extern void ktest_fini(ktest_hdl_t *);

extern ktest_list_iter_t *ktest_list(ktest_hdl_t *);
extern void ktest_list_free(ktest_list_iter_t *);
extern bool ktest_list_next(ktest_list_iter_t *, ktest_entry_t *);
extern void ktest_list_reset(ktest_list_iter_t *);

extern bool ktest_run(ktest_hdl_t *, const ktest_run_req_t *,
    ktest_run_result_t *);

extern const char *ktest_code_name(ktest_code_t);

extern bool ktest_mod_load(const char *);
extern bool ktest_mod_load_all(void);
extern void ktest_mod_unload(const char *);
extern bool ktest_mod_unload_all(void);

extern size_t ktest_max_input_size(void);


#ifdef __cplusplus
}
#endif

#endif /* _LIBKTEST_H */
