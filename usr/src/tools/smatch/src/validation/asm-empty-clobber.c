
# define __ASM_FORM(x)  " " #x " "
# define JUMP_LABEL_INITIAL_NOP ".byte 0xe9 \n\t .long 0\n\t"
# define __ASM_SEL(a,b) __ASM_FORM(b)
#define _ASM_PTR        __ASM_SEL(.long, .quad)

# define JUMP_LABEL(key, label)                                 \
       do {                                                    \
               asm goto("1:"                                   \
                       JUMP_LABEL_INITIAL_NOP                  \
                       ".pushsection __jump_table,  \"a\" \n\t"\
                       _ASM_PTR "1b, %l[" #label "], %c0 \n\t" \
                       ".popsection \n\t"                      \
                       : :  "i" (key) :  : label);             \
       } while (0)

int main(int argc, char *argv[])
{
       JUMP_LABEL("1", do_trace );
       return 1;
do_trace:
       return 0;
}

/*
 *  check-name: Asm with goto labels.
 */

