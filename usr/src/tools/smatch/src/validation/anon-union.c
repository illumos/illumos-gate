struct s {
        union {
                int val;
        };
};

static struct s foo = { .val = 5, };
/*
 * check-name: test anonymous union initializer
 */

