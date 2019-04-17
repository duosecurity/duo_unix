#include "pam_duo_private.h"

int
parse_argv(const char **config, int argc, const char *argv[])
{
    int i;
    for (i = 0; i < argc; i++) {
        if ((strncmp("conf=", argv[i], 5) == 0) && (*config != NULL)) {
            *config = argv[i] + 5;
        } else if (strcmp("debug", argv[i]) == 0) {
            /* duo_debug is a global variable defined in util.h */
            duo_debug = 1;
        } else {
            duo_syslog(LOG_ERR, "Invalid pam_duo option: '%s'",
                argv[i]);
            return 0; 
        }
    }
    return 1;
}
