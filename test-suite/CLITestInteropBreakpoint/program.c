#include <stdio.h>

extern "C" void test_native_function()                          // Func break
{
    printf("<stdout_marker>test_native_function\n");
}

extern "C" void native_method()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("<stdout_marker>Native: Start\n");
    test_native_function();
    printf("<stdout_marker>Native: End\n");                     // BREAK2
}
