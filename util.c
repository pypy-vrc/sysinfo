#include "pch.h"

void dump(const void *buf, size_t len)
{
    static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    unsigned char *begin, *end, c;
    char line[64 + 1];
    size_t i;

    begin = (unsigned char *)buf;
    end = begin + len;

    while (begin < end) {
        line[64] = 0;
        memset(line, ' ', 64);
        i = (size_t)(end - begin);
        if (i > 16)
            i = 16;
        do {
            c = begin[--i];
            line[i * 3] = hex[c >> 4];
            line[i * 3 + 1] = hex[c & 15];
            line[i + 48] = (c > 31 && c < 127) ? c : '.';
        } while (i);
        begin += 16;
        printf("%.*s\n", 64, line);
    }   
}
