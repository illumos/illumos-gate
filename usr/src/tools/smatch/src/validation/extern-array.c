extern const char *v4l2_type_names[];
const char *v4l2_type_names[] = {
        "test"
};
extern const char *v4l2_type_names[];

static void test(void)
{
        unsigned sz = sizeof(v4l2_type_names);
}
/*
 * check-name: duplicate extern array
 */

