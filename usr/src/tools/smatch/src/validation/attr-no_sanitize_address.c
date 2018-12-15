#define __no_sanitize_address __attribute__((no_sanitize_address))

static void __no_sanitize_address bar(void)
{
}

/*
 * check-name: attribute no_sanitize_address
 */
