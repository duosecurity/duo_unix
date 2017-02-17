#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "util.h"

int success()
{
    printf("OK\n");
    return EXIT_SUCCESS;
}

int failure()
{
    printf("FAIL\n");
    return EXIT_FAILURE;
}

int main (int argc, char *argv[])
{
    if (argc != 5) {
        printf("Format: %s <string|NULL> <delimiter> <position> <expected|NULL>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *s = argv[1];
    char *delimiter = argv[2];
    int position = atoi(argv[3]);
    char *expected = argv[4];

    if (strcmp(s, "NULL") == 0) {
        s = NULL;
    }

    char *result = duo_split_at(s, *delimiter, position);

    if ((result == NULL && strcmp(expected, "NULL") == 0) ||
            (result != NULL && strcmp(result, expected) == 0)) {
        return success();
    }

    return failure();
}
