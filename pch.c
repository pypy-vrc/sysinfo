#pragma comment(linker, "/RELEASE")
#pragma comment(linker, "/OPT:NOWIN98")
#pragma comment(lib, "ws2_32.lib")
#include "pch.h"

int main(int argc, const char **argv)
{
    return app_main(argc, argv);
}
