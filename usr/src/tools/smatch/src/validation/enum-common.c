static enum ENUM_TYPE_A { VALUE_A } var_a;
static enum ENUM_TYPE_B { VALUE_B } var_b;
static enum /* anon. */ { VALUE_C } anon_enum_var;
static int i;

static void take_enum_of_type_a(enum ENUM_TYPE_A arg_enum)
{
	(void) arg_enum;
}

static void take_int(int arg_int)
{
	(void) arg_int;
}

static void always_ok(void)
{
	var_a ++;
	var_a = VALUE_A;
	var_a = (enum ENUM_TYPE_A) VALUE_B;
	var_b = (enum ENUM_TYPE_B) i;
	i = (int) VALUE_A;
	anon_enum_var = VALUE_C;
	i = VALUE_C;
	i = anon_enum_var;
	i = 7;
	var_a = (enum ENUM_TYPE_A) 0;
	anon_enum_var = (__typeof__(anon_enum_var)) 0;
	anon_enum_var = (__typeof__(anon_enum_var)) VALUE_A;

	switch (var_a) {
		case VALUE_A:
		default:
			take_enum_of_type_a(var_a);
			take_enum_of_type_a(VALUE_A);
	}

	switch (anon_enum_var) {
		case VALUE_C:
		default:
			take_int(anon_enum_var);
	}

	switch (i) {
		case VALUE_C:
		default:
			take_int(VALUE_C);
	}
}

static void trigger_enum_mismatch(void)
{
	switch (var_a) {
		case VALUE_B:
		case VALUE_C:
		default:
			take_enum_of_type_a(var_b);
			take_enum_of_type_a(VALUE_B);
	}

	switch (anon_enum_var) {
		case VALUE_A:
		default:
			take_enum_of_type_a(anon_enum_var);
			take_enum_of_type_a(VALUE_C);
	}

	// this has been already working in sparse 0.4.1
	var_a = var_b;
	var_b = anon_enum_var;
	anon_enum_var = var_a;

	// implemented after sparse 0.4.1
	var_a = VALUE_B;
	var_b = VALUE_C;
	anon_enum_var = VALUE_A;
}

static void trigger_int_to_enum_conversion(void)
{
	switch (var_a) {
		case 0:
		default:
			take_enum_of_type_a(i);
			take_enum_of_type_a(7);
	}
	var_a = 0;
	var_b = i;
	anon_enum_var = 0;
	anon_enum_var = i;
	var_a = (int) VALUE_A;
	var_a = (int) VALUE_B;
}

static void trigger_enum_to_int_conversion(void)
{
	i = var_a;
	i = VALUE_B;
	switch (i) {
		case VALUE_A:
		case VALUE_B:
		default:
			take_int(var_a);
			take_int(VALUE_B);
	}
}

/*
 * check-name: enum-common
 * check-description: common part of the test for -Wenum-mismatch, -Wenum-to-int and -Wint-to-enum
 * check-command: sparse -Wno-enum-mismatch -Wno-int-to-enum $file
 */
