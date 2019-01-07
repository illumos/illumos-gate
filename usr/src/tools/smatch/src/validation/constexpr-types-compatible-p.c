static int a[] = {[__builtin_types_compatible_p(int, int)] = 0};

/*
 * check-name: __builtin_types_compatible_p() constness verification.
 *
 * check-error-start
 * check-error-end
 */
