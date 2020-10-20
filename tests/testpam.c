
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
#else
# include <security/pam_appl.h>
#endif

#ifdef LINUX_PAM    /* XXX: and OpenPAM? */
# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)
#else
# define PAM_MSG_MEMBER(msg, n, member) ((*(msg))[(n)].member)
#endif

int
my_conv(int n, const struct pam_message **msg,
    struct pam_response **resp, void *data)
{
    struct pam_response *aresp;
    char buf[PAM_MAX_RESP_SIZE];
    const char *p;
    int i;

    if (n <= 0 || n > PAM_MAX_NUM_MSG)
        return (PAM_CONV_ERR);

    if ((aresp = calloc(n, sizeof *aresp)) == NULL)
        return (PAM_BUF_ERR);

    for (i = 0; i < n; ++i) {
        aresp[i].resp_retcode = 0;
        aresp[i].resp = NULL;
        p = PAM_MSG_MEMBER(msg, i, msg);

        switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
        case PAM_PROMPT_ECHO_OFF:
            aresp[i].resp = strdup(getpass(p));
            if (aresp[i].resp == NULL)
                goto fail;
            break;
        case PAM_PROMPT_ECHO_ON:
            fputs(p, stderr);
            if (fgets(buf, sizeof(buf), stdin) == NULL)
                goto fail;
            aresp[i].resp = strdup(buf);
            if (aresp[i].resp == NULL)
                goto fail;
            break;
        case PAM_ERROR_MSG:
            fputs(p, stderr);
            if (strlen(p) > 0 && p[strlen(p) - 1] != '\n')
                fputc('\n', stderr);
            break;
        case PAM_TEXT_INFO:
            fputs(p, stdout);
            if (strlen(p) > 0 && p[strlen(p) - 1] != '\n')
                fputc('\n', stdout);
            break;
        default:
            goto fail;
        }
    }
    *resp = aresp;
    return (PAM_SUCCESS);
fail:
    for (i = 0; i < n; ++i) {
        if (aresp[i].resp != NULL)
            free(aresp[i].resp);
    }
    *resp = NULL;
    return (PAM_CONV_ERR);
}

static struct pam_conv conv = { my_conv, NULL };

static void
die(pam_handle_t *pamh, int errnum)
{
        //fprintf(stderr, "%s\n", pam_strerror(pamh, errnum));
        exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
    pam_handle_t *pamh = NULL;
    char *user, *host = NULL;
    int ret;

    if (argc < 2) {
        fprintf(stderr, "Usage: testpam <user> [host]\n");
        exit(EXIT_FAILURE);
    }
    user = argv[1];
    if (argc > 2)
        host = argv[2];

    if ((ret = pam_start("testpam", user, &conv, &pamh)) != PAM_SUCCESS) {
                die(pamh, ret);
    }
    if (host != NULL) {
        if ((ret = pam_set_item(pamh, PAM_RHOST, host)) != PAM_SUCCESS) {
            die(pamh, ret);
        }
    }
    if ((ret = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
        if (ret != PAM_MAXTRIES) {
            die(pamh, ret);
        }
    }
    if ((ret = pam_end(pamh, ret)) != PAM_SUCCESS) {
                die(pamh, ret);
    }
    exit(EXIT_SUCCESS);
}
