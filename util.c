// ############## LLM Generated Code Begins ##############
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

char *read_input_line(const char *prompt) {
    printf("%s", prompt);
    fflush(stdout);
    char *line = NULL;
    size_t n = 0;
    ssize_t r = getline(&line, &n, stdin);
    if (r == -1) {
        free(line);
        return NULL;
    }
    if (r > 0 && line[r - 1] == '\n')
        line[r - 1] = '\0';
    return line;
}

// ############## LLM Generated Code Ends ################
