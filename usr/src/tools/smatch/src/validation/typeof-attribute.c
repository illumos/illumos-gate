#define __percpu __attribute__((noderef, address_space(3)))

/* Turn v back into a normal var. */
#define convert(v) \
       (*(typeof(v) __attribute__((address_space(0), force)) *)(&v))

int main(int argc, char *argv)
{
       unsigned int __percpu x;

       convert(x) = 0;
       return 0;
}
/*
 * check-name: Rusty Russell's typeof attribute casting.
 */
