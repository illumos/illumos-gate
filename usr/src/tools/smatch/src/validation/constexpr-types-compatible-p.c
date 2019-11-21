static int a[] = {[__builtin_types_compatible_p(int, int)] = 0};

/*
 * check-name: constness of __builtin_types_compatible_p()
 *
 * check-error-start
 * check-error-end
 */
