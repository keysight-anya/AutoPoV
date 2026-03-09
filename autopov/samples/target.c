#include <stdio.h>
#include <string.h>

void vulnerable_function(char *str) {
    char buffer[10];
    // DANGEROUS: strcpy does not check the size of the buffer!
    strcpy(buffer, str);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
