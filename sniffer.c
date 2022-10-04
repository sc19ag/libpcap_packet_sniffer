#include <stdio.h>
#include "sniffer.h"

void sniffToCli(int argc, char *argv[]) {
    printf("sniffToCli() called\n");
}

void sniffToFile(int argc, char *argv[], char *path) {
    printf("sniffToFile() called with filepath %s\n", path);
}