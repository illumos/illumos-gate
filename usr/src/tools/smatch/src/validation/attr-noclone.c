#define noclone		__attribute__((__noclone__))

static void noclone bar(void)
{
}

/*
 * check-name: attribute noclone
 */
