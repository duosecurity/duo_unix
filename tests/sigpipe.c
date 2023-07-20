/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * sigpipe.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>

#include <sys/wait.h>

void usage(int argc, char *argv[]) {
    fprintf(stderr, "usage: %s (run argv... | test)\n", argc ? argv[0] : "sigpipe");
    exit(2);
}

int main(int argc, char *argv[]) {
    pid_t pid;
    int status;

    if (argc < 2) {
        usage(argc, argv);
    }

    if (strcmp(argv[1], "run") == 0) {
        if (argc < 3) {
            fprintf(stderr, "error: no program provided\n");
            usage(argc, argv);
        }
        signal(SIGPIPE, SIG_DFL);
        execvp(argv[2], argv + 2);
        perror("execvp");
        exit(1);
    } else if (strcmp(argv[1], "test") == 0) {
        if ((pid = fork()) < 0) {
            perror("fork");
            exit(1);
        } else if (pid == 0) {
            raise(SIGPIPE);
        } else if (wait(&status) < 0) {
            perror("wait");
            exit(1);
        } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE) {
            printf("Success!\n");
            exit(0);
        } else {
            printf("Failure\n");
            exit(1);
        }
    }
}
