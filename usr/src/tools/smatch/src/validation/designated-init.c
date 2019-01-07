struct s1 {
	int x;
	int y;
};

struct s2 {
	int x;
	int y;
} __attribute__((designated_init));

struct nest1 {
	struct s1 s1;
	struct s2 s2;
};

struct nest2 {
	struct s1 s1;
	struct s2 s2;
} __attribute__((designated_init));

static struct s1 s1_positional = { 5, 10 };
static struct s1 s1_designated = { .x = 5, .y = 10 };
static struct s2 s2_positional = { 5, 10 };
static struct s2 s2_designated = { .x = 5, .y = 10 };
static struct nest1 nest1_positional = {
	{ 5, 10 },
	{ 5, 10 },
};
static struct nest1 nest1_designated_outer = {
	.s1 = { 5, 10 },
	.s2 = { 5, 10 },
};
static struct nest1 nest1_designated_inner = {
	{ .x = 5, .y = 10 },
	{ .x = 5, .y = 10 },
};
static struct nest1 nest1_designated_both = {
	.s1 = { .x = 5, .y = 10 },
	.s2 = { .x = 5, .y = 10 },
};
static struct nest2 nest2_positional = {
	{ 5, 10 },
	{ 5, 10 },
};
static struct nest2 nest2_designated_outer = {
	.s1 = { 5, 10 },
	.s2 = { 5, 10 },
};
static struct nest2 nest2_designated_inner = {
	{ .x = 5, .y = 10 },
	{ .x = 5, .y = 10 },
};
static struct nest2 nest2_designated_both = {
	.s1 = { .x = 5, .y = 10 },
	.s2 = { .x = 5, .y = 10 },
};

static struct {
	int x;
	int y;
} __attribute__((designated_init))
	anon_positional = { 5, 10 },
	anon_designated = { .x = 5, .y = 10};

static struct s1 s1_array[] = {
	{ 5, 10 },
	{ .x = 5, .y = 10 },
};

static struct s2 s2_array[] = {
	{ 5, 10 },
	{ .x = 5, .y = 10 },
};

static struct s1 ret_s1_positional(void)
{
	return ((struct s1){ 5, 10 });
}

static struct s1 ret_s1_designated(void)
{
	return ((struct s1){ .x = 5, .y = 10 });
}

static struct s2 ret_s2_positional(void)
{
	return ((struct s2){ 5, 10 });
}

static struct s2 ret_s2_designated(void)
{
	return ((struct s2){ .x = 5, .y = 10 });
}

static struct nest1 ret_nest1_positional(void)
{
	return ((struct nest1){
			{ 5, 10 },
			{ 5, 10 },
		});
}

static struct nest1 ret_nest1_designated_outer(void)
{
	return ((struct nest1){
			.s1 = { 5, 10 },
			.s2 = { 5, 10 },
		});
}

static struct nest1 ret_nest1_designated_inner(void)
{
	return ((struct nest1){
			{ .x = 5, .y = 10 },
			{ .x = 5, .y = 10 },
		});
}

static struct nest1 ret_nest1_designated_both(void)
{
	return ((struct nest1){
			.s1 = { .x = 5, .y = 10 },
			.s2 = { .x = 5, .y = 10 },
		});
}

static struct nest2 ret_nest2_positional(void)
{
	return ((struct nest2){
			{ 5, 10 },
			{ 5, 10 },
		});
}

static struct nest2 ret_nest2_designated_outer(void)
{
	return ((struct nest2){
			.s1 = { 5, 10 },
			.s2 = { 5, 10 },
		});
}

static struct nest2 ret_nest2_designated_inner(void)
{
	return ((struct nest2){
			{ .x = 5, .y = 10 },
			{ .x = 5, .y = 10 },
		});
}

static struct nest2 ret_nest2_designated_both(void)
{
	return ((struct nest2){
			.s1 = { .x = 5, .y = 10 },
			.s2 = { .x = 5, .y = 10 },
		});
}
/*
 * check-name: designated_init attribute
 *
 * check-error-start
designated-init.c:23:36: warning: in initializer for s2_positional: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:23:39: warning: in initializer for s2_positional: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:27:11: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:27:14: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:31:17: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:31:20: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:42:9: warning: in initializer for nest2_positional: positional init of field in struct nest2, declared with attribute designated_init
designated-init.c:43:9: warning: in initializer for nest2_positional: positional init of field in struct nest2, declared with attribute designated_init
designated-init.c:43:11: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:43:14: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:47:17: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:47:20: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:50:9: warning: in initializer for nest2_designated_inner: positional init of field in struct nest2, declared with attribute designated_init
designated-init.c:51:9: warning: in initializer for nest2_designated_inner: positional init of field in struct nest2, declared with attribute designated_init
designated-init.c:62:29: warning: in initializer for anon_positional: positional init of field in struct <noident>, declared with attribute designated_init
designated-init.c:62:32: warning: in initializer for anon_positional: positional init of field in struct <noident>, declared with attribute designated_init
designated-init.c:71:11: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:71:14: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:87:30: warning: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:87:33: warning: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:99:27: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:99:30: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:107:33: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:107:36: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:130:25: warning: positional init of field in struct nest2, declared with attribute designated_init
designated-init.c:131:25: warning: positional init of field in struct nest2, declared with attribute designated_init
designated-init.c:131:27: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:131:30: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:139:33: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:139:36: warning: in initializer for s2: positional init of field in struct s2, declared with attribute designated_init
designated-init.c:146:25: warning: positional init of field in struct nest2, declared with attribute designated_init
designated-init.c:147:25: warning: positional init of field in struct nest2, declared with attribute designated_init
 * check-error-end
 */
