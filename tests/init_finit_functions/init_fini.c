#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// define the init and fini functions
static void before_main(void) __attribute__((constructor));
static void after_main(void) __attribute__((destructor));

static void before_main(void)
{
    puts("I'm executing before main, don't I?");
}

static void after_main(void)
{
    puts("I'm executing after main, don't I?");
}

int 
main(void)
{
    const char *string = "this is a string";
    size_t len_string;

    len_string = strlen(string);

    printf("I'm main, this string '%s' has %ld characters\n", string, len_string);

    return 0;
}
