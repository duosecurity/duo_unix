#ifndef PAM_EXTRA_H
#define PAM_EXTRA_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_PAM_VPROMPT
int pam_vprompt(
    pam_handle_t *pamh,
    int style,
    char **response,
    const char *fmt,
    va_list args
);

int pam_prompt(
    pam_handle_t *pamh,
    int style,
    char **response,
    const char *fmt,
    ...
);

#define pam_info(pamh, fmt...) pam_prompt(pamh, PAM_TEXT_INFO, NULL, fmt)
#endif

#endif /* PAM_EXTRA_H */
