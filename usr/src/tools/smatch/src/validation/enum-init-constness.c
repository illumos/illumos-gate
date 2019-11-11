extern int invalid;

enum e {
	E = 1 ? 1 : invalid
};

/*
 * check-name: enum-init-constness
 */
